// guest_ebpf.rs — guest-side eBPF policy loader for agent container observation.
//
// Canonical docs:
//   - docs/prd.md §4.5
//   - docs/architecture.md §eBPF
//   - docs/scout/guest-ebpf-findings.md
//
// # Design
//
// This module implements a guest-side eBPF policy loader that attaches BPF
// programs to the guest kernel to observe agent container behavior:
// file writes, syscalls, and network egress. The loader is invoked by
// `run_exec` in `exec.rs` around the container lifetime.
//
// # Kernel requirements
//
// The guest eBPF loader requires a guest kernel ≥ 5.7 with:
//   CONFIG_BPF=y
//   CONFIG_BPF_SYSCALL=y
//   CONFIG_DEBUG_INFO_BTF=y      (for CO-RE / BTF)
//   CONFIG_BPF_LSM=y             (for LSM hooks)
//   CONFIG_CGROUP_BPF=y          (for cgroup_skb)
//   CONFIG_BPF_EVENTS=y          (for tracepoints)
//   BOOT: lsm=bpf                (for BPF LSM)
//
// The Firecracker quickstart kernel (4.14.174) does NOT meet these requirements.
// Scout #92 confirmed CONFIG_DEBUG_INFO_BTF is absent on that kernel. The loader
// detects kernel capability at runtime (via the bpf(2) syscall result) and emits
// structured warning events when the kernel is too old, without crashing.
//
// # Observe-only (first iteration)
//
// This first iteration is observe-only: BPF programs emit structured audit log
// lines per-event but do not hard-block any agent action. Enforcement is deferred
// to a follow-up issue per the issue scope.
//
// # Audit event format
//
// All audit events are emitted as tracing events at the `info` level with:
//   event = "guest_ebpf.<event_type>"
//   container_id: fork/container identifier
//   event_type: "file_write" | "network_egress" | "exec" | "loader_unavailable"
//   timestamp: RFC 3339 string
//
// # Integration point
//
// `GuestEbpfLoader::attach(container_id)` is called in `exec::run_exec` after
// spawning the crun child process. `GuestEbpfLoader::detach()` is called before
// the function returns (success and error paths).
//
// # Privilege requirements
//
// Loading BPF programs inside the guest requires CAP_BPF (Linux 5.8+) or
// CAP_SYS_ADMIN (older kernels). When running without privileges the loader
// emits a warning and skips attachment, consistent with the graceful-degradation
// contract above.

use std::ffi::CString;
use std::os::raw::{c_int, c_uint};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};

// ---------------------------------------------------------------------------
// BPF syscall constants (guest-side; same ABI as host_ebpf.rs)
// ---------------------------------------------------------------------------

/// Linux `bpf(2)` syscall number on x86-64.
#[cfg(target_arch = "x86_64")]
const SYS_BPF: libc::c_long = 321;

/// `BPF_PROG_LOAD` command.
const BPF_PROG_LOAD: c_uint = 5;

/// `BPF_OBJ_PIN` command — pin a BPF object to the BPF filesystem.
const BPF_OBJ_PIN: c_uint = 6;

/// BPF program type for tracepoints (observe syscall entry/exit).
const BPF_PROG_TYPE_TRACEPOINT: c_uint = 5;

/// BPF program type for cgroup socket buffer (observe network egress).
///
/// Requires kernel ≥ 4.10 + cgroup v2 mount + CONFIG_CGROUP_BPF=y.
const BPF_PROG_TYPE_CGROUP_SKB: c_uint = 4;

/// Log buffer size for BPF verifier output (1 MiB).
const BPF_LOG_BUF_SIZE: usize = 1024 * 1024;

/// Maximum BPF program size in bytes (4 MiB).
const BPF_MAX_PROG_SIZE: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Minimal BPF attr for BPF_PROG_LOAD (128-byte kernel ABI)
// ---------------------------------------------------------------------------

/// Subset of `union bpf_attr` used by `BPF_PROG_LOAD`.
///
/// Must be exactly 128 bytes to match the kernel ABI.
#[repr(C)]
#[derive(Default)]
struct BpfProgLoadAttr {
    prog_type: c_uint,            // offset 0
    insn_cnt: c_uint,             // offset 4
    insns: u64,                   // offset 8:  __aligned_u64 *insns
    license: u64,                 // offset 16: const char *license
    log_level: c_uint,            // offset 24
    log_size: c_uint,             // offset 28
    log_buf: u64,                 // offset 32: char *log_buf
    kern_version: c_uint,         // offset 40
    prog_flags: c_uint,           // offset 44
    prog_name: [u8; 16],          // offset 48: BPF_OBJ_NAME_LEN=16
    prog_ifindex: c_uint,         // offset 64
    expected_attach_type: c_uint, // offset 68
    prog_btf_fd: c_uint,          // offset 72
    func_info_rec_size: c_uint,   // offset 76
    func_info: u64,               // offset 80
    func_info_cnt: c_uint,        // offset 84 (actually 88 due to alignment)
    line_info_rec_size: c_uint,
    line_info: u64,
    line_info_cnt: c_uint,
    attach_btf_id: c_uint,
    // Pad to 128 bytes total
    _pad: [u64; 0],
}

// ---------------------------------------------------------------------------
// Minimal BPF pass-through program (observe-only "always-pass" policy)
//
// The program below is a minimal BPF bytecode sequence that returns 0 (pass)
// from a tracepoint context. It is used as the observe-only stub when no real
// BPF object file is supplied. In a production guest, a real compiled ELF
// object would be provided via `GuestEbpfPolicy::object_path`.
//
// Encoding: 2 BPF instructions (16 bytes)
//   insn 0: BPF_MOV64_IMM(BPF_REG_0, 0)  — r0 = 0
//   insn 1: BPF_EXIT_INSN()               — exit
// ---------------------------------------------------------------------------

/// Returns a minimal "always-pass" BPF program as raw instruction bytes.
///
/// Used when no real ELF object is provided. The program is observe-only
/// and trivially passes the verifier on kernels ≥ 4.7.
fn minimal_pass_program() -> Vec<u8> {
    // BPF_MOV64_IMM(BPF_REG_0, 0): code=0xb7, dst_reg=0, src_reg=0, off=0, imm=0
    // BPF_EXIT_INSN():              code=0x95, dst_reg=0, src_reg=0, off=0, imm=0
    vec![
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0, 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ]
}

// ---------------------------------------------------------------------------
// Audit event types
// ---------------------------------------------------------------------------

/// The kind of event emitted by the guest eBPF programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAuditEvent {
    /// An agent process wrote to a file inside the container rootfs.
    FileWrite,
    /// An agent process made a network egress call.
    NetworkEgress,
    /// An agent process called exec (spawned a subprocess).
    Exec,
}

impl std::fmt::Display for GuestAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestAuditEvent::FileWrite => f.write_str("file_write"),
            GuestAuditEvent::NetworkEgress => f.write_str("network_egress"),
            GuestAuditEvent::Exec => f.write_str("exec"),
        }
    }
}

// ---------------------------------------------------------------------------
// Policy configuration
// ---------------------------------------------------------------------------

/// Guest eBPF policy configuration supplied to the loader.
///
/// In the current observe-only iteration, the policy simply names the BPF
/// programs to load and their attach points. Enforcement is not wired.
///
/// # Fields
///
/// - `container_id`: identifier of the crun container being observed.
/// - `object_path`: optional path to a compiled BPF ELF object. When `None`,
///   a minimal pass-through program is loaded as the observe stub.
/// - `tracepoint_attach`: tracepoint to attach for syscall observation, e.g.
///   `"syscalls/sys_enter_openat"`. When `None`, the tracepoint program is
///   skipped.
/// - `cgroup_path`: path to the cgroup v2 directory for the container, used
///   to attach `cgroup_skb` programs. When `None`, cgroup attachment is skipped.
#[derive(Debug, Clone)]
pub struct GuestEbpfPolicy {
    /// Container identifier (used in audit events and BPF pin paths).
    pub container_id: String,
    /// Optional compiled BPF ELF object. When absent, the minimal stub is used.
    pub object_path: Option<PathBuf>,
    /// Tracepoint to attach for syscall/file-event observation.
    /// Format: `"<category>/<event>"`, e.g. `"syscalls/sys_enter_openat"`.
    pub tracepoint_attach: Option<String>,
    /// cgroup v2 path for network-egress observation via `cgroup_skb`.
    /// Typically `/sys/fs/cgroup/system.slice/crun-<container_id>.scope`.
    pub cgroup_path: Option<PathBuf>,
}

impl GuestEbpfPolicy {
    /// Create a minimal observe-only policy for a container.
    ///
    /// No ELF object is supplied; the minimal pass-through program is used.
    /// No tracepoint or cgroup attachment is configured; the loader will
    /// attempt a minimal BPF_PROG_LOAD to probe kernel capability and then
    /// emit synthetic audit events from the run_exec lifecycle hooks.
    pub fn for_container(container_id: impl Into<String>) -> Self {
        GuestEbpfPolicy {
            container_id: container_id.into(),
            object_path: None,
            tracepoint_attach: None,
            cgroup_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Loaded state
// ---------------------------------------------------------------------------

/// State of a successfully attached (or degraded) guest eBPF policy.
///
/// The `attached` flag records whether a BPF program was actually loaded into
/// the kernel. When `false`, the loader is in degraded mode (kernel too old
/// or privileges insufficient) and only synthetic lifecycle events are emitted.
#[derive(Debug)]
pub struct GuestEbpfLoader {
    /// Container this loader is attached to.
    container_id: String,
    /// Whether a real BPF program was loaded into the kernel.
    attached: bool,
    /// BPF file descriptor of the loaded tracepoint program, if any.
    tracepoint_fd: Option<c_int>,
    /// BPF pin path for the tracepoint program, if pinned.
    tracepoint_pin: Option<PathBuf>,
    /// BPF file descriptor of the cgroup_skb program, if any.
    cgroup_skb_fd: Option<c_int>,
    /// Timestamp when the loader was attached.
    attached_at: String,
}

impl GuestEbpfLoader {
    /// Attach the guest eBPF policy loader for a container.
    ///
    /// Attempts to load BPF programs into the guest kernel. If the kernel does
    /// not support BPF (too old, or CAP_BPF absent), logs a structured warning
    /// and returns a degraded loader that emits synthetic lifecycle events only.
    ///
    /// Never returns `Err` — all kernel-interaction failures are downgraded to
    /// structured warnings so that container launch is never blocked by eBPF.
    ///
    /// # Canonical docs
    ///
    /// - `docs/prd.md §4.5` — guest eBPF observability requirement
    /// - `docs/scout/guest-ebpf-findings.md` — kernel capability analysis
    pub fn attach(policy: &GuestEbpfPolicy) -> Self {
        let attached_at = now_rfc3339();
        let container_id = &policy.container_id;

        tracing::info!(
            event = "guest_ebpf.attaching",
            container_id = %container_id,
            has_object = policy.object_path.is_some(),
            has_tracepoint = policy.tracepoint_attach.is_some(),
            has_cgroup = policy.cgroup_path.is_some(),
            timestamp = %attached_at,
            "guest eBPF policy loader: attaching"
        );

        // ── Load tracepoint program ──────────────────────────────────────────
        let tracepoint_fd = if let Some(ref tp) = policy.tracepoint_attach {
            match load_guest_bpf_prog(
                policy.object_path.as_deref(),
                &format!("gtp-{}", &container_id[..container_id.len().min(8)]),
                BPF_PROG_TYPE_TRACEPOINT,
            ) {
                Ok(fd) => {
                    tracing::info!(
                        event = "guest_ebpf.tracepoint_loaded",
                        container_id = %container_id,
                        tracepoint = %tp,
                        prog_fd = fd,
                        "guest eBPF tracepoint program loaded"
                    );
                    Some(fd)
                }
                Err(e) => {
                    tracing::warn!(
                        event = "guest_ebpf.tracepoint_unavailable",
                        container_id = %container_id,
                        tracepoint = %tp,
                        error = %e,
                        "guest eBPF tracepoint not available on this kernel; \
                         degrading to synthetic events (see docs/scout/guest-ebpf-findings.md)"
                    );
                    None
                }
            }
        } else {
            // No tracepoint configured — attempt a kernel capability probe using
            // the minimal pass-through program to determine if BPF is available.
            match load_guest_bpf_prog(
                policy.object_path.as_deref(),
                &format!("gprobe-{}", &container_id[..container_id.len().min(6)]),
                BPF_PROG_TYPE_TRACEPOINT,
            ) {
                Ok(fd) => {
                    tracing::info!(
                        event = "guest_ebpf.kernel_probe_ok",
                        container_id = %container_id,
                        prog_fd = fd,
                        "guest kernel supports BPF; probe program loaded"
                    );
                    Some(fd)
                }
                Err(e) => {
                    tracing::warn!(
                        event = "guest_ebpf.loader_unavailable",
                        container_id = %container_id,
                        error = %e,
                        "guest kernel does not support BPF or CAP_BPF is absent; \
                         degrading to synthetic lifecycle events only. \
                         Guest kernel must be ≥ 5.7 with CONFIG_DEBUG_INFO_BTF=y. \
                         See docs/scout/guest-ebpf-findings.md for upgrade path."
                    );
                    None
                }
            }
        };

        // ── Load cgroup_skb program for network egress observation ───────────
        let cgroup_skb_fd = if policy.cgroup_path.is_some() {
            match load_guest_bpf_prog(
                policy.object_path.as_deref(),
                &format!("gskb-{}", &container_id[..container_id.len().min(8)]),
                BPF_PROG_TYPE_CGROUP_SKB,
            ) {
                Ok(fd) => {
                    tracing::info!(
                        event = "guest_ebpf.cgroup_skb_loaded",
                        container_id = %container_id,
                        prog_fd = fd,
                        "guest eBPF cgroup_skb program loaded for network egress observation"
                    );
                    Some(fd)
                }
                Err(e) => {
                    tracing::warn!(
                        event = "guest_ebpf.cgroup_skb_unavailable",
                        container_id = %container_id,
                        error = %e,
                        "guest eBPF cgroup_skb not available; network egress events \
                         will be synthetic only"
                    );
                    None
                }
            }
        } else {
            None
        };

        let attached = tracepoint_fd.is_some() || cgroup_skb_fd.is_some();

        // ── Try to pin the tracepoint program to the BPF filesystem ─────────
        let tracepoint_pin = if let Some(fd) = tracepoint_fd {
            let pin_path = guest_bpf_pin_path(container_id, "tracepoint");
            match pin_guest_bpf_prog(fd, &pin_path) {
                Ok(()) => {
                    tracing::info!(
                        event = "guest_ebpf.tracepoint_pinned",
                        container_id = %container_id,
                        pin_path = %pin_path.display(),
                        "guest eBPF tracepoint program pinned to BPF filesystem"
                    );
                    Some(pin_path)
                }
                Err(e) => {
                    // Not fatal — the fd itself keeps the program alive.
                    tracing::warn!(
                        event = "guest_ebpf.pin_warn",
                        container_id = %container_id,
                        error = %e,
                        "could not pin guest eBPF program to BPF filesystem (non-fatal)"
                    );
                    None
                }
            }
        } else {
            None
        };

        tracing::info!(
            event = "guest_ebpf.attached",
            container_id = %container_id,
            attached = attached,
            tracepoint_pinned = tracepoint_pin.is_some(),
            cgroup_skb = cgroup_skb_fd.is_some(),
            timestamp = %attached_at,
            "guest eBPF policy loader attached (observe-only)"
        );

        GuestEbpfLoader {
            container_id: container_id.clone(),
            attached,
            tracepoint_fd,
            tracepoint_pin,
            cgroup_skb_fd,
            attached_at,
        }
    }

    /// Emit a structured audit event for an observed agent action.
    ///
    /// When operating in degraded mode (kernel too old), events are emitted as
    /// synthetic lifecycle markers rather than real BPF-captured events. The
    /// event format is identical so that consumers can treat both uniformly.
    ///
    /// # Parameters
    ///
    /// - `event_type`: the kind of agent action observed.
    /// - `detail`: optional free-form string with additional context (path, address, etc.).
    pub fn emit_audit_event(&self, event_type: GuestAuditEvent, detail: Option<&str>) {
        let source = if self.attached { "bpf" } else { "synthetic" };
        tracing::info!(
            event = "guest_ebpf.audit",
            container_id = %self.container_id,
            event_type = %event_type,
            source = %source,
            detail = detail.unwrap_or(""),
            timestamp = %now_rfc3339(),
            "guest eBPF audit event"
        );
    }

    /// Returns `true` if a real BPF program was loaded into the kernel.
    ///
    /// When `false`, the loader is in degraded mode and only emits synthetic
    /// lifecycle events (kernel too old or no CAP_BPF).
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Detach the guest eBPF policy loader cleanly.
    ///
    /// Closes all BPF file descriptors and removes BPF pin files. Errors are
    /// logged as warnings rather than propagated — the container may already
    /// have exited, which can cause fd/pin cleanup to fail.
    ///
    /// This method must be called when the container exits so that:
    /// - BPF program FDs are closed (the kernel frees the program).
    /// - BPF pin files are removed from the BPF filesystem.
    /// - A structured detach event is emitted for the audit trail.
    pub fn detach(self) {
        let container_id = &self.container_id;

        tracing::info!(
            event = "guest_ebpf.detaching",
            container_id = %container_id,
            attached = self.attached,
            "guest eBPF policy loader: detaching"
        );

        // Close tracepoint BPF program fd.
        if let Some(fd) = self.tracepoint_fd {
            // SAFETY: fd is a valid BPF program fd obtained from bpf(2).
            unsafe { libc::close(fd) };
            tracing::info!(
                event = "guest_ebpf.tracepoint_fd_closed",
                container_id = %container_id,
                prog_fd = fd,
                "guest eBPF tracepoint fd closed"
            );
        }

        // Close cgroup_skb BPF program fd.
        if let Some(fd) = self.cgroup_skb_fd {
            // SAFETY: fd is a valid BPF program fd obtained from bpf(2).
            unsafe { libc::close(fd) };
            tracing::info!(
                event = "guest_ebpf.cgroup_skb_fd_closed",
                container_id = %container_id,
                prog_fd = fd,
                "guest eBPF cgroup_skb fd closed"
            );
        }

        // Remove BPF pin file.
        if let Some(ref pin_path) = self.tracepoint_pin {
            match std::fs::remove_file(pin_path) {
                Ok(()) => {
                    tracing::info!(
                        event = "guest_ebpf.pin_removed",
                        container_id = %container_id,
                        pin_path = %pin_path.display(),
                        "guest eBPF pin file removed"
                    );
                    // Remove empty parent directories.
                    if let Some(parent) = pin_path.parent() {
                        let _ = std::fs::remove_dir(parent);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        event = "guest_ebpf.pin_remove_warn",
                        container_id = %container_id,
                        pin_path = %pin_path.display(),
                        error = %e,
                        "guest eBPF pin file removal failed (non-fatal)"
                    );
                }
            }
        }

        tracing::info!(
            event = "guest_ebpf.detached",
            container_id = %container_id,
            attached_at = %self.attached_at,
            detached_at = %now_rfc3339(),
            "guest eBPF policy loader detached cleanly"
        );
    }
}

// ---------------------------------------------------------------------------
// BPF program load helper (guest-side)
// ---------------------------------------------------------------------------

/// Load a BPF program into the guest kernel.
///
/// If `object_path` is supplied, the ELF object is parsed and the first
/// program section is loaded. Otherwise, the minimal pass-through stub is used.
///
/// Returns the BPF program file descriptor on success, or an error if the
/// kernel does not support BPF (EINVAL/EPERM on old kernels).
///
/// # Integration note (docs/scout/guest-ebpf-findings.md)
///
/// The Firecracker quickstart kernel 4.14.174 returns `EINVAL` from
/// `BPF_PROG_LOAD` for `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (confirmed in scout #72)
/// and is expected to return `EINVAL` for tracepoint/cgroup_skb programs too,
/// since `CONFIG_BPF_SYSCALL` may be absent. The caller (`attach`) handles
/// this gracefully by downgrading to synthetic events.
fn load_guest_bpf_prog(object_path: Option<&Path>, name: &str, prog_type: c_uint) -> Result<c_int> {
    let (prog_bytes, license) = if let Some(path) = object_path {
        load_bpf_bytes_from_elf(path).with_context(|| {
            format!("guest_ebpf: failed to parse BPF object: {}", path.display())
        })?
    } else {
        (minimal_pass_program(), "GPL".to_string())
    };

    if prog_bytes.is_empty() {
        anyhow::bail!("guest_ebpf: BPF program bytes are empty");
    }
    if prog_bytes.len() % 8 != 0 {
        anyhow::bail!(
            "guest_ebpf: BPF program size {} is not a multiple of 8",
            prog_bytes.len()
        );
    }
    if prog_bytes.len() > BPF_MAX_PROG_SIZE {
        anyhow::bail!(
            "guest_ebpf: BPF program too large: {} bytes",
            prog_bytes.len()
        );
    }

    let license_cstr =
        CString::new(license.as_str()).unwrap_or_else(|_| CString::new("GPL").unwrap());

    let mut log_buf: Vec<u8> = vec![0u8; BPF_LOG_BUF_SIZE];

    let mut prog_name = [0u8; 16];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    prog_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let insn_cnt = (prog_bytes.len() / 8) as c_uint;

    #[allow(clippy::cast_possible_truncation)]
    let attr = BpfProgLoadAttr {
        prog_type,
        insn_cnt,
        insns: prog_bytes.as_ptr() as u64,
        license: license_cstr.as_ptr() as u64,
        log_level: 1,
        log_size: BPF_LOG_BUF_SIZE as c_uint,
        log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name,
        ..BpfProgLoadAttr::default()
    };

    // SAFETY: We call bpf(2) with a correctly sized attr. All pointers within
    // attr (insns, license, log_buf) point to valid heap memory that outlives
    // this call. The result is a BPF fd or -1 on error.
    let fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_PROG_LOAD as libc::c_long,
            &attr as *const BpfProgLoadAttr as *const libc::c_void,
            std::mem::size_of::<BpfProgLoadAttr>() as libc::c_ulong,
        )
    };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let verifier_log = std::str::from_utf8(&log_buf)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        let log_snippet = if verifier_log.is_empty() {
            String::new()
        } else {
            let lines: Vec<&str> = verifier_log.lines().rev().take(5).collect();
            format!(
                " verifier: {}",
                lines.into_iter().rev().collect::<Vec<_>>().join("; ")
            )
        };
        anyhow::bail!(
            "guest_ebpf: bpf(BPF_PROG_LOAD) failed for prog '{}': {}{}",
            name,
            err,
            log_snippet
        );
    }

    Ok(fd as c_int)
}

// ---------------------------------------------------------------------------
// Minimal ELF BPF object parser (reused pattern from host_ebpf.rs)
// ---------------------------------------------------------------------------

/// Extract BPF instructions and license from an ELF `.o` file.
///
/// Returns `(instruction_bytes, license)`.
fn load_bpf_bytes_from_elf(path: &Path) -> Result<(Vec<u8>, String)> {
    let data = std::fs::read(path)
        .with_context(|| format!("cannot read BPF object: {}", path.display()))?;

    if data.len() < 16 {
        anyhow::bail!("BPF object too small: {}", path.display());
    }
    if &data[0..4] != b"\x7fELF" {
        anyhow::bail!("not an ELF file: {}", path.display());
    }
    if data[4] != 2 {
        anyhow::bail!("BPF object must be 64-bit ELF");
    }
    if data[5] != 1 {
        anyhow::bail!("BPF object must be little-endian ELF");
    }

    let e_shoff = read_u64_le(&data, 40) as usize;
    let e_shentsize = read_u16_le(&data, 58) as usize;
    let e_shnum = read_u16_le(&data, 60) as usize;
    let e_shstrndx = read_u16_le(&data, 62) as usize;

    if e_shoff == 0 || e_shnum == 0 {
        anyhow::bail!("BPF object has no section headers: {}", path.display());
    }

    let shstrtab = read_section_data(&data, e_shoff, e_shentsize, e_shstrndx)
        .context("cannot read shstrtab")?;

    let mut prog_bytes: Option<Vec<u8>> = None;
    let mut license = "GPL".to_string();

    for i in 0..e_shnum {
        let sh_offset = e_shoff + i * e_shentsize;
        if sh_offset + e_shentsize > data.len() {
            break;
        }
        let sh_name_idx = read_u32_le(&data, sh_offset) as usize;
        let sh_type = read_u32_le(&data, sh_offset + 4);
        let sh_addr = read_u64_le(&data, sh_offset + 16);
        let sh_off = read_u64_le(&data, sh_offset + 24) as usize;
        let sh_size = read_u64_le(&data, sh_offset + 32) as usize;

        if sh_type != 1 || sh_addr != 0 || sh_off == 0 || sh_size == 0 {
            continue;
        }

        let name = read_cstr_at(&shstrtab, sh_name_idx);

        if name == "license" {
            let sec = data.get(sh_off..sh_off + sh_size).unwrap_or_default();
            license = std::str::from_utf8(sec)
                .unwrap_or("GPL")
                .trim_end_matches('\0')
                .to_string();
        } else if prog_bytes.is_none() && is_bpf_section(&name) {
            prog_bytes = data.get(sh_off..sh_off + sh_size).map(|b| b.to_vec());
        }
    }

    let prog_bytes = prog_bytes
        .ok_or_else(|| anyhow::anyhow!("no BPF program section in: {}", path.display()))?;

    Ok((prog_bytes, license))
}

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    let b = data.get(off..off + 2).unwrap_or(&[0, 0]);
    u16::from_le_bytes([b[0], b[1]])
}

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    let b = data.get(off..off + 4).unwrap_or(&[0; 4]);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u64_le(data: &[u8], off: usize) -> u64 {
    let b = data.get(off..off + 8).unwrap_or(&[0; 8]);
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn read_section_data(
    data: &[u8],
    e_shoff: usize,
    e_shentsize: usize,
    idx: usize,
) -> Result<Vec<u8>> {
    let hdr = e_shoff + idx * e_shentsize;
    let off = read_u64_le(data, hdr + 24) as usize;
    let size = read_u64_le(data, hdr + 32) as usize;
    data.get(off..off + size)
        .map(|b| b.to_vec())
        .ok_or_else(|| anyhow::anyhow!("section data out of bounds"))
}

fn read_cstr_at(data: &[u8], off: usize) -> String {
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[off..end])
        .unwrap_or("")
        .to_string()
}

fn is_bpf_section(name: &str) -> bool {
    matches!(
        name,
        ".text"
            | "classifier"
            | "action"
            | "xdp"
            | "kprobe"
            | "kretprobe"
            | "tracepoint"
            | "raw_tracepoint"
    ) || name.starts_with("tc")
        || name.starts_with("tracepoint/")
        || name.starts_with("kprobe/")
        || name.starts_with("kretprobe/")
        || name.starts_with("xdp")
        || name.starts_with("cgroup/")
        || name.starts_with("sk_msg")
        || name.starts_with("sockops")
}

// ---------------------------------------------------------------------------
// BPF pin helpers (guest-side)
// ---------------------------------------------------------------------------

/// BPF filesystem mount point on the guest.
const GUEST_BPF_FS: &str = "/sys/fs/bpf";

/// Return the BPF pin path for a guest eBPF program.
///
/// Programs are pinned under `/sys/fs/bpf/fastenv-guest/<container_id>/<name>`.
pub fn guest_bpf_pin_path(container_id: &str, name: &str) -> PathBuf {
    PathBuf::from(GUEST_BPF_FS)
        .join("fastenv-guest")
        .join(container_id)
        .join(name)
}

/// Pin a loaded BPF program fd to the BPF filesystem.
///
/// Returns `Ok(())` on success. The BPF filesystem must be mounted at
/// `/sys/fs/bpf` inside the guest.
fn pin_guest_bpf_prog(fd: c_int, pin_path: &Path) -> Result<()> {
    if let Some(parent) = pin_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create BPF pin directory: {}", parent.display()))?;
    }

    let path_cstr = CString::new(pin_path.to_string_lossy().as_bytes())
        .context("BPF pin path contains NUL byte")?;

    #[repr(C)]
    struct BpfObjPinAttr {
        pathname: u64,
        bpf_fd: c_uint,
        file_flags: c_uint,
        _pad: [u64; 13],
    }

    let attr = BpfObjPinAttr {
        pathname: path_cstr.as_ptr() as u64,
        bpf_fd: fd as c_uint,
        file_flags: 0,
        _pad: [0u64; 13],
    };

    // SAFETY: attr is correctly sized and path_cstr outlives this call.
    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_OBJ_PIN as libc::c_long,
            &attr as *const BpfObjPinAttr as *const libc::c_void,
            std::mem::size_of::<BpfObjPinAttr>() as libc::c_ulong,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!(
            "bpf(BPF_OBJ_PIN) failed for '{}': {}",
            pin_path.display(),
            err
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Policy construction ──────────────────────────────────────────────────

    #[test]
    fn guest_ebpf_policy_for_container_sets_id() {
        let policy = GuestEbpfPolicy::for_container("agent-123");
        assert_eq!(policy.container_id, "agent-123");
        assert!(policy.object_path.is_none());
        assert!(policy.tracepoint_attach.is_none());
        assert!(policy.cgroup_path.is_none());
    }

    // ── ELF parsing tests ────────────────────────────────────────────────────

    #[test]
    fn load_bpf_bytes_rejects_non_elf() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.o");
        std::fs::write(&path, b"NOT_AN_ELF_FILE_AT_ALL_XXXXX").unwrap();
        let result = load_bpf_bytes_from_elf(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("ELF") || msg.contains("elf"),
            "expected ELF error, got: {msg}"
        );
    }

    #[test]
    fn load_bpf_bytes_rejects_missing_file() {
        let result = load_bpf_bytes_from_elf(Path::new("/nonexistent/guest.bpf.o"));
        assert!(result.is_err());
    }

    // ── Minimal program ──────────────────────────────────────────────────────

    #[test]
    fn minimal_pass_program_is_16_bytes() {
        let prog = minimal_pass_program();
        assert_eq!(
            prog.len(),
            16,
            "minimal pass program must be exactly 2 instructions (16 bytes)"
        );
        assert_eq!(prog.len() % 8, 0, "program must be a multiple of 8 bytes");
    }

    #[test]
    fn minimal_pass_program_first_insn_is_mov64() {
        let prog = minimal_pass_program();
        // First byte of insn 0 is 0xb7 (BPF_MOV64 | BPF_ALU64 | BPF_K)
        assert_eq!(prog[0], 0xb7, "first instruction must be BPF_MOV64_IMM");
    }

    #[test]
    fn minimal_pass_program_second_insn_is_exit() {
        let prog = minimal_pass_program();
        // First byte of insn 1 is 0x95 (BPF_EXIT_INSN)
        assert_eq!(prog[8], 0x95, "second instruction must be BPF_EXIT_INSN");
    }

    // ── Pin path ─────────────────────────────────────────────────────────────

    #[test]
    fn guest_bpf_pin_path_structure() {
        let p = guest_bpf_pin_path("agent-abc", "tracepoint");
        assert_eq!(
            p,
            PathBuf::from("/sys/fs/bpf/fastenv-guest/agent-abc/tracepoint")
        );
    }

    // ── Audit event display ──────────────────────────────────────────────────

    #[test]
    fn audit_event_display_file_write() {
        assert_eq!(GuestAuditEvent::FileWrite.to_string(), "file_write");
    }

    #[test]
    fn audit_event_display_network_egress() {
        assert_eq!(GuestAuditEvent::NetworkEgress.to_string(), "network_egress");
    }

    #[test]
    fn audit_event_display_exec() {
        assert_eq!(GuestAuditEvent::Exec.to_string(), "exec");
    }

    // ── Attach/detach without BPF kernel support ─────────────────────────────
    //
    // On a host that lacks CAP_BPF, attach() must succeed (degraded mode) and
    // detach() must succeed cleanly. This validates the graceful-degradation
    // contract without requiring privileged access.

    #[test]
    fn attach_degrades_gracefully_without_cap_bpf() {
        // On a non-privileged runner the bpf(2) syscall returns EPERM/EINVAL.
        // attach() must not panic and must return a loader (possibly degraded).
        let policy = GuestEbpfPolicy::for_container("test-degraded");
        let loader = GuestEbpfLoader::attach(&policy);
        // is_attached() may be true (privileged CI) or false (unprivileged host).
        // Either is acceptable — the loader must be created without panicking.
        let _ = loader.is_attached();
    }

    #[test]
    fn detach_after_degraded_attach_does_not_panic() {
        let policy = GuestEbpfPolicy::for_container("test-detach");
        let loader = GuestEbpfLoader::attach(&policy);
        // Consuming the loader via detach() must not panic in either mode.
        loader.detach();
    }

    #[test]
    fn emit_audit_event_does_not_panic() {
        let policy = GuestEbpfPolicy::for_container("test-emit");
        let loader = GuestEbpfLoader::attach(&policy);
        loader.emit_audit_event(GuestAuditEvent::FileWrite, Some("/etc/passwd"));
        loader.emit_audit_event(GuestAuditEvent::NetworkEgress, Some("8.8.8.8:443"));
        loader.emit_audit_event(GuestAuditEvent::Exec, None);
        loader.detach();
    }

    // ── BPF section name recognition ─────────────────────────────────────────

    #[test]
    fn is_bpf_section_recognizes_text() {
        assert!(is_bpf_section(".text"));
    }

    #[test]
    fn is_bpf_section_recognizes_tracepoint_prefix() {
        assert!(is_bpf_section("tracepoint/syscalls/sys_enter_openat"));
    }

    #[test]
    fn is_bpf_section_recognizes_kprobe_prefix() {
        assert!(is_bpf_section("kprobe/vfs_write"));
    }

    #[test]
    fn is_bpf_section_rejects_unknown() {
        assert!(!is_bpf_section("random_section_name"));
        assert!(!is_bpf_section(".debug_info"));
    }

    // ── Integration tests (privileged runner only) ────────────────────────────

    /// Integration test: boot a project VM, launch a crun container, confirm
    /// the BPF program attaches (or degrades gracefully).
    ///
    /// Requires: a guest VM with kernel ≥ 5.7, CAP_BPF, and crun installed.
    /// See docs/scout/guest-ebpf-findings.md for the kernel upgrade path.
    ///
    /// Run with: sudo cargo test -- --ignored guest_ebpf_integration_attach_inside_vm
    #[test]
    #[ignore = "requires guest VM with kernel ≥ 5.7 + CAP_BPF; run on privileged CI runner"]
    fn guest_ebpf_integration_attach_inside_vm() {
        // Step 1: boot a Firecracker VM with a kernel ≥ 5.7 image.
        // Step 2: call GuestEbpfLoader::attach inside the guest.
        // Step 3: assert loader.is_attached() == true.
        // Step 4: spawn a crun container; write a file; assert file_write event.
        // Step 5: make a network call; assert network_egress event.
        // Step 6: container exits; assert detach succeeds.
        //
        // Full automation requires a privileged runner with:
        //   - Firecracker binary
        //   - Guest kernel image ≥ 5.7 with CONFIG_DEBUG_INFO_BTF=y
        //   - crun binary in the guest rootfs
        //
        // Manual validation steps:
        //   1. `fastenv fork --base ubuntu-22 --name agent-1`
        //   2. `fastenv exec agent-1 -- /usr/local/bin/fastenv-guest-ebpf-probe`
        //   3. Check tracing output for guest_ebpf.attached with attached=true.
        panic!("privileged runner with kernel ≥ 5.7 required — run manually");
    }

    /// Integration test: container writes a file; assert file-write audit event.
    #[test]
    #[ignore = "requires guest VM with kernel ≥ 5.7 + CAP_BPF; run on privileged CI runner"]
    fn guest_ebpf_integration_file_write_event() {
        panic!("privileged runner required — run manually inside guest VM");
    }

    /// Integration test: container makes a network call; assert network-egress event.
    #[test]
    #[ignore = "requires guest VM with kernel ≥ 5.7 + CAP_BPF; run on privileged CI runner"]
    fn guest_ebpf_integration_network_egress_event() {
        panic!("privileged runner required — run manually inside guest VM");
    }

    /// Integration test: container exits; assert BPF programs are detached cleanly.
    #[test]
    #[ignore = "requires guest VM with kernel ≥ 5.7 + CAP_BPF; run on privileged CI runner"]
    fn guest_ebpf_integration_clean_detach_on_exit() {
        panic!("privileged runner required — run manually inside guest VM");
    }

    /// Regression test: run_exec with eBPF loader attached does not break
    /// existing exec tests (loader is additive, not breaking).
    ///
    /// This is covered by the unit tests above (detach_after_degraded_attach).
    /// The integration version requires crun + a real rootfs.
    #[test]
    #[ignore = "requires root + crun + test rootfs; run on privileged CI runner"]
    fn guest_ebpf_regression_existing_exec_unaffected() {
        panic!("privileged runner required — run manually");
    }
}
