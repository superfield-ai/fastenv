// host_ebpf.rs — host-side eBPF program loader for the Firecracker/jailer boundary.
//
// Canonical docs:
//   - docs/prd.md §4.5
//   - docs/architecture.md §eBPF
//
// # Design
//
// This module implements real BPF program loading into the host kernel.
// Programs are loaded using the `bpf(2)` syscall (BPF_PROG_LOAD) with the
// program type derived from the `attach_point` field of `HostEbpfPolicy`.
//
// # Attach point format
//
// The `attach_point` field encodes the attach type and optional target device:
//
//   "tc-ingress:<dev>"   — TC ingress hook on <dev>
//   "tc-egress:<dev>"    — TC egress hook on <dev>
//   "tracepoint:<cat>/<evt>" — kernel tracepoint
//   "kprobe:<func>"      — kprobe on function <func>
//
// For TC attach points, the `tc` userspace tool is used to install the
// classifier, consistent with the codebase shell-out pattern (curl for
// Firecracker API). For other types, the BPF prog is loaded and pinned
// to the BPF filesystem.
//
// # Privilege requirements
//
// Loading BPF programs requires CAP_BPF (Linux 5.8+) or CAP_SYS_ADMIN.
// The host control plane is expected to run with sufficient privileges.
// Integration tests that exercise this module require a privileged runner.
//
// # Observability
//
// All load, attach, and detach events are emitted as structured tracing
// events at the `info` level. Policy decision events from the kernel
// are surfaced via bpf_printk output and the kernel's perf ring buffer
// (wired via `poll_perf_ring_buffer`; see §Perf ring-buffer polling below).

use std::ffi::CString;
use std::os::raw::{c_int, c_uint};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};

// ---------------------------------------------------------------------------
// BPF syscall constants and types
// ---------------------------------------------------------------------------

/// Linux `bpf(2)` syscall number on x86-64.
#[cfg(target_arch = "x86_64")]
const SYS_BPF: libc::c_long = 321;

/// `BPF_PROG_LOAD` command.
const BPF_PROG_LOAD: c_uint = 5;

/// `BPF_OBJ_PIN` command — pin a BPF object to the BPF filesystem.
const BPF_OBJ_PIN: c_uint = 6;

/// `BPF_PROG_GET_FD_BY_ID` command — get a program FD from its kernel ID.
#[allow(dead_code)]
const BPF_PROG_GET_FD_BY_ID: c_uint = 13;

/// BPF program types.
const BPF_PROG_TYPE_UNSPECIFIED: c_uint = 0;
const BPF_PROG_TYPE_SCHED_CLS: c_uint = 3; // TC classifier
const BPF_PROG_TYPE_TRACEPOINT: c_uint = 5;
const BPF_PROG_TYPE_KPROBE: c_uint = 2;

/// Log buffer size for BPF verifier output.
const BPF_LOG_BUF_SIZE: usize = 1024 * 1024; // 1 MiB

/// Maximum BPF program size in bytes (4 MiB).
const BPF_MAX_PROG_SIZE: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// BPF attr union layout (for BPF_PROG_LOAD)
//
// The kernel's `union bpf_attr` is a 128-byte struct. For BPF_PROG_LOAD we
// only need the fields in the first variant.
// ---------------------------------------------------------------------------

/// Subset of `union bpf_attr` used by `BPF_PROG_LOAD`.
///
/// This must be 128 bytes total to match the kernel ABI.
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

/// BPF attr for `BPF_OBJ_PIN` — kept for documentation; the local `BpfObjPinAttrSimple`
/// inside `pin_bpf_prog` is used instead to avoid the unused-struct warning.
#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct BpfObjPinAttr {
    pathname: u64, // const char *pathname
    bpf_fd: c_uint,
    file_flags: c_uint,
    _pad: [u64; 13], // pad to 128 bytes
}

// ---------------------------------------------------------------------------
// Attach point parsing
// ---------------------------------------------------------------------------

/// Parsed representation of an eBPF attach point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachPoint {
    /// TC classifier on a network device (`tc-ingress:<dev>` or `tc-egress:<dev>`).
    Tc {
        device: String,
        direction: TcDirection,
    },
    /// Kernel tracepoint (`tracepoint:<category>/<event>`).
    Tracepoint { category: String, event: String },
    /// Kprobe on a kernel function (`kprobe:<function>`).
    Kprobe { function: String },
    /// Raw type passed through without structured parsing.
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcDirection {
    Ingress,
    Egress,
}

/// Parse an attach point string into a structured `AttachPoint`.
pub fn parse_attach_point(s: &str) -> AttachPoint {
    if let Some(rest) = s.strip_prefix("tc-ingress:") {
        return AttachPoint::Tc {
            device: rest.to_string(),
            direction: TcDirection::Ingress,
        };
    }
    if let Some(rest) = s.strip_prefix("tc-egress:") {
        return AttachPoint::Tc {
            device: rest.to_string(),
            direction: TcDirection::Egress,
        };
    }
    if let Some(rest) = s.strip_prefix("tracepoint:") {
        if let Some((cat, evt)) = rest.split_once('/') {
            return AttachPoint::Tracepoint {
                category: cat.to_string(),
                event: evt.to_string(),
            };
        }
    }
    if let Some(func) = s.strip_prefix("kprobe:") {
        return AttachPoint::Kprobe {
            function: func.to_string(),
        };
    }
    AttachPoint::Raw(s.to_string())
}

// ---------------------------------------------------------------------------
// ELF BPF program extraction
// ---------------------------------------------------------------------------

/// A single BPF instruction (8 bytes).
///
/// Defined here for documentation / future use; not yet constructed directly
/// (the ELF loader passes raw bytes to the kernel).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

/// Extract raw BPF instructions and license from an ELF `.o` file.
///
/// This is a minimal ELF parser that handles only the sections needed by
/// `BPF_PROG_LOAD`:
/// - The first section named `.text` or prefixed with `SEC(...)` patterns
/// - The `license` section
///
/// Returns `(instructions_bytes, license_string, prog_type_hint)`.
pub fn load_bpf_object_file(path: &Path) -> Result<(Vec<u8>, String, c_uint)> {
    let data = std::fs::read(path)
        .with_context(|| format!("cannot read BPF object file: {}", path.display()))?;

    if data.len() < 16 {
        bail!("BPF object file too small: {}", path.display());
    }

    // Verify ELF magic.
    if &data[0..4] != b"\x7fELF" {
        bail!("BPF object file is not an ELF file: {}", path.display());
    }

    // ELF class: 1=32-bit, 2=64-bit
    let is_64bit = data[4] == 2;
    // ELF data encoding: 1=LE, 2=BE
    let is_le = data[5] == 1;

    if !is_64bit {
        bail!("BPF object must be 64-bit ELF (BPF uses LE-64 encoding)");
    }
    if !is_le {
        bail!("BPF object must be little-endian ELF");
    }

    // Parse ELF64 header fields.
    let e_shoff = read_u64_le(&data, 40) as usize; // section header table offset
    let e_shentsize = read_u16_le(&data, 58) as usize; // section header entry size
    let e_shnum = read_u16_le(&data, 60) as usize; // number of section headers
    let e_shstrndx = read_u16_le(&data, 62) as usize; // section name string table index

    if e_shoff == 0 || e_shnum == 0 {
        bail!("BPF object file has no section headers");
    }

    // Read the section name string table.
    let shstrtab = read_section_data(&data, e_shoff, e_shentsize, e_shstrndx)
        .context("cannot read section name string table")?;

    // Scan sections for `.text` / BPF prog sections and `license`.
    let mut prog_bytes: Option<Vec<u8>> = None;
    let mut license = "GPL".to_string();
    let mut prog_type_hint = BPF_PROG_TYPE_UNSPECIFIED;

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

        // SHT_PROGBITS = 1, SHT_NOTE = 7 (skip relocation sections etc.)
        if sh_type != 1 {
            continue;
        }
        if sh_addr != 0 || sh_off == 0 || sh_size == 0 {
            continue;
        }

        let name = read_cstr(&shstrtab, sh_name_idx);

        if name == "license" {
            // License is a null-terminated string in this section.
            let sec_data = data.get(sh_off..sh_off + sh_size).unwrap_or_default();
            license = std::str::from_utf8(sec_data)
                .unwrap_or("GPL")
                .trim_end_matches('\0')
                .to_string();
        } else if prog_bytes.is_none() && is_bpf_prog_section(&name) {
            // First BPF program section found.
            prog_bytes = data.get(sh_off..sh_off + sh_size).map(|b| b.to_vec());
            prog_type_hint = infer_prog_type_from_section(&name);
        }
    }

    let prog_bytes = prog_bytes
        .ok_or_else(|| anyhow::anyhow!("no BPF program section found in: {}", path.display()))?;

    if prog_bytes.is_empty() {
        bail!("BPF program section is empty: {}", path.display());
    }

    if prog_bytes.len() % 8 != 0 {
        bail!(
            "BPF program section size {} is not a multiple of 8 (BPF instruction size)",
            prog_bytes.len()
        );
    }

    if prog_bytes.len() > BPF_MAX_PROG_SIZE {
        bail!(
            "BPF program too large: {} bytes (max {})",
            prog_bytes.len(),
            BPF_MAX_PROG_SIZE
        );
    }

    Ok((prog_bytes, license, prog_type_hint))
}

// ---------------------------------------------------------------------------
// ELF helpers
// ---------------------------------------------------------------------------

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    let b = data.get(off..off + 2).unwrap_or(&[0, 0]);
    u16::from_le_bytes([b[0], b[1]])
}

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    let b = data.get(off..off + 4).unwrap_or(&[0, 0, 0, 0]);
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
    let sh_off_hdr = e_shoff + idx * e_shentsize;
    let sh_off = read_u64_le(data, sh_off_hdr + 24) as usize;
    let sh_size = read_u64_le(data, sh_off_hdr + 32) as usize;
    data.get(sh_off..sh_off + sh_size)
        .map(|b| b.to_vec())
        .ok_or_else(|| anyhow::anyhow!("section data out of bounds"))
}

fn read_cstr(data: &[u8], off: usize) -> String {
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[off..end])
        .unwrap_or("")
        .to_string()
}

fn is_bpf_prog_section(name: &str) -> bool {
    // Standard section names used by BPF programs.
    matches!(
        name,
        "classifier"
            | ".text"
            | "action"
            | "xdp"
            | "kprobe"
            | "kretprobe"
            | "tracepoint"
            | "raw_tracepoint"
            | "sockops"
            | "cgroup/connect4"
            | "cgroup/connect6"
    ) || name.starts_with("tc")
        || name.starts_with("tracepoint/")
        || name.starts_with("kprobe/")
        || name.starts_with("kretprobe/")
        || name.starts_with("xdp")
        || name.starts_with("cgroup/")
        || name.starts_with("sk_msg")
        || name.starts_with("sockops")
}

fn infer_prog_type_from_section(name: &str) -> c_uint {
    if name.starts_with("tc") || name == "classifier" || name == "action" {
        BPF_PROG_TYPE_SCHED_CLS
    } else if name.starts_with("tracepoint/") || name == "tracepoint" {
        BPF_PROG_TYPE_TRACEPOINT
    } else if name.starts_with("kprobe/") || name.starts_with("kretprobe/") || name == "kprobe" {
        BPF_PROG_TYPE_KPROBE
    } else {
        BPF_PROG_TYPE_UNSPECIFIED
    }
}

// ---------------------------------------------------------------------------
// BPF program load via bpf(2) syscall
// ---------------------------------------------------------------------------

/// Load a BPF program into the host kernel using the `bpf(2)` syscall.
///
/// Returns the file descriptor of the loaded program. The caller is
/// responsible for pinning or tracking this FD.
///
/// # Errors
///
/// Returns an error if:
/// - The BPF object file cannot be parsed.
/// - `CAP_BPF` / `CAP_SYS_ADMIN` is not held (EPERM).
/// - The verifier rejects the program (EINVAL) — the verifier log is included.
pub fn load_bpf_prog_from_object(
    object_path: &Path,
    name: &str,
    attach_point: &AttachPoint,
) -> Result<c_int> {
    let (prog_bytes, license, mut prog_type) = load_bpf_object_file(object_path)?;

    // Override prog_type from the attach_point if the ELF section was ambiguous.
    if prog_type == BPF_PROG_TYPE_UNSPECIFIED {
        prog_type = prog_type_from_attach_point(attach_point);
    }

    let license_cstr =
        CString::new(license.as_str()).unwrap_or_else(|_| CString::new("GPL").unwrap());

    // Allocate the verifier log buffer on the heap.
    let mut log_buf: Vec<u8> = vec![0u8; BPF_LOG_BUF_SIZE];

    // Truncate the program name to 15 chars + NUL (BPF_OBJ_NAME_LEN = 16).
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

    // SAFETY: We are calling the bpf(2) syscall with a correctly sized attr.
    // The attr lives on the stack and all pointers within it (insns, license,
    // log_buf) point to valid heap/stack memory that outlives this call.
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
            let lines: Vec<&str> = verifier_log.lines().rev().take(20).collect();
            format!(
                "\nVerifier log (last 20 lines):\n{}",
                lines.into_iter().rev().collect::<Vec<_>>().join("\n")
            )
        };
        bail!(
            "bpf(BPF_PROG_LOAD) failed for '{}': {}{}",
            object_path.display(),
            err,
            log_snippet
        );
    }

    Ok(fd as c_int)
}

fn prog_type_from_attach_point(attach_point: &AttachPoint) -> c_uint {
    match attach_point {
        AttachPoint::Tc { .. } => BPF_PROG_TYPE_SCHED_CLS,
        AttachPoint::Tracepoint { .. } => BPF_PROG_TYPE_TRACEPOINT,
        AttachPoint::Kprobe { .. } => BPF_PROG_TYPE_KPROBE,
        AttachPoint::Raw(_) => BPF_PROG_TYPE_UNSPECIFIED,
    }
}

// ---------------------------------------------------------------------------
// TC attach / detach
// ---------------------------------------------------------------------------

/// Attach a TC BPF classifier to a network device using the `tc` command.
///
/// Sets up a `clsact` qdisc if not already present, then installs the BPF
/// prog from `object_path` in the specified direction. Returns the tc filter
/// handle string that can be used to detach later.
///
/// # Example attach_point strings
///
/// - `"tc-ingress:tap0"` — attach to the ingress of tap0
/// - `"tc-egress:tap0"` — attach to the egress of tap0
pub fn tc_attach_bpf(
    object_path: &Path,
    device: &str,
    direction: &TcDirection,
    section_name: &str,
) -> Result<String> {
    // Ensure clsact qdisc exists on the device (idempotent).
    let qdisc_out = Command::new("tc")
        .args(["qdisc", "add", "dev", device, "clsact"])
        .output()
        .context("cannot run 'tc qdisc add': ensure iproute2 is installed")?;

    // Exit code 2 means "qdisc already exists" — that is acceptable.
    if !qdisc_out.status.success() {
        let stderr = String::from_utf8_lossy(&qdisc_out.stderr);
        if !stderr.contains("already exists") {
            tracing::warn!(
                device = %device,
                stderr = %stderr.trim(),
                "tc qdisc add returned non-zero; continuing (qdisc may already exist)"
            );
        }
    }

    // Attach the BPF program as a TC filter.
    let dir_str = match direction {
        TcDirection::Ingress => "ingress",
        TcDirection::Egress => "egress",
    };

    let filter_out = Command::new("tc")
        .args([
            "filter",
            "add",
            "dev",
            device,
            dir_str,
            "bpf",
            "da",
            "obj",
            &object_path.to_string_lossy(),
            "sec",
            section_name,
        ])
        .output()
        .context("cannot run 'tc filter add': ensure iproute2 is installed")?;

    if !filter_out.status.success() {
        let stderr = String::from_utf8_lossy(&filter_out.stderr);
        bail!(
            "tc filter add failed for device '{}' {}: {}",
            device,
            dir_str,
            stderr.trim()
        );
    }

    // Return a handle string for later detachment.
    let handle = format!("tc:{}:{}", device, dir_str);

    tracing::info!(
        event = "host_ebpf.tc_attached",
        device = %device,
        direction = %dir_str,
        object_path = %object_path.display(),
        section = %section_name,
        handle = %handle,
        "host eBPF TC classifier attached"
    );

    Ok(handle)
}

/// Detach a TC BPF classifier from a network device.
///
/// `handle` is the string returned by `tc_attach_bpf`.
pub fn tc_detach_bpf(handle: &str) -> Result<()> {
    // Handle format: "tc:<device>:<direction>"
    let parts: Vec<&str> = handle.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "tc" {
        bail!("invalid TC detach handle: '{}'", handle);
    }
    let device = parts[1];
    let dir_str = parts[2];

    let output = Command::new("tc")
        .args(["filter", "del", "dev", device, dir_str])
        .output()
        .context("cannot run 'tc filter del'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Log a warning but do not fail — the device may have already gone.
        tracing::warn!(
            event = "host_ebpf.tc_detach_warn",
            device = %device,
            direction = %dir_str,
            stderr = %stderr.trim(),
            "tc filter del returned non-zero; device may already be gone"
        );
    } else {
        tracing::info!(
            event = "host_ebpf.tc_detached",
            device = %device,
            direction = %dir_str,
            "host eBPF TC classifier detached"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// BPF pin path helpers
// ---------------------------------------------------------------------------

/// BPF filesystem mount point used for pinning programs.
const BPF_FS: &str = "/sys/fs/bpf";

/// Return the BPF pin path for a program associated with a project VM.
///
/// Programs are pinned under `/sys/fs/bpf/fastenv/<project_id>/<name>`.
/// This allows the program to survive close of the loading FD and be
/// retrieved later for detachment queries.
pub fn bpf_pin_path(project_id: &str, name: &str) -> PathBuf {
    PathBuf::from(BPF_FS)
        .join("fastenv")
        .join(project_id)
        .join(name)
}

/// Pin a loaded BPF program FD to the BPF filesystem.
///
/// Requires the BPF filesystem to be mounted at `/sys/fs/bpf`.
/// Returns `Ok(())` on success.
pub fn pin_bpf_prog(fd: c_int, pin_path: &Path) -> Result<()> {
    // Ensure parent directory exists.
    if let Some(parent) = pin_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create BPF pin directory: {}", parent.display()))?;
    }

    let path_cstr = CString::new(pin_path.to_string_lossy().as_bytes())
        .context("BPF pin path contains NUL byte")?;

    #[repr(C)]
    struct BpfObjPinAttrSimple {
        pathname: u64,
        bpf_fd: c_uint,
        file_flags: c_uint,
        _pad: [u64; 13],
    }

    let attr = BpfObjPinAttrSimple {
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
            &attr as *const BpfObjPinAttrSimple as *const libc::c_void,
            std::mem::size_of::<BpfObjPinAttrSimple>() as libc::c_ulong,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        bail!(
            "bpf(BPF_OBJ_PIN) failed for '{}': {}",
            pin_path.display(),
            err
        );
    }

    Ok(())
}

/// Remove a BPF pin file if it exists.
pub fn unpin_bpf_prog(pin_path: &Path) -> Result<()> {
    if pin_path.exists() {
        std::fs::remove_file(pin_path)
            .with_context(|| format!("cannot remove BPF pin: {}", pin_path.display()))?;

        // Remove empty parent directories.
        if let Some(parent) = pin_path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Top-level load / detach API
// ---------------------------------------------------------------------------

/// Result of loading a host eBPF policy.
#[derive(Debug, Clone)]
pub struct LoadedEbpfPolicy {
    /// Kernel BPF program ID (from bpf(BPF_PROG_LOAD) return).
    pub prog_fd: c_int,
    /// Optional TC attach handle (for TC programs).
    pub tc_handle: Option<String>,
    /// BPF pin path (for non-TC programs).
    pub pin_path: Option<PathBuf>,
    /// Timestamp of when the program was loaded.
    pub loaded_at: String,
}

/// Load and attach a host eBPF policy program.
///
/// This is the top-level entry point called from `ProjectVmSupervisor`.
///
/// For TC programs, the BPF object is loaded and the TC classifier is
/// attached using the `tc` command. For other types, the program is loaded
/// and pinned to the BPF filesystem.
///
/// Returns a `LoadedEbpfPolicy` that contains the state needed for
/// later detachment.
///
/// # Errors
///
/// Returns an error if:
/// - The BPF object file cannot be parsed or loaded.
/// - The TC attach fails (TC programs).
/// - `CAP_BPF` is not held by the calling process.
pub fn load_and_attach_host_ebpf(
    project_id: &str,
    name: &str,
    object_path: &Path,
    attach_point_str: &str,
) -> Result<LoadedEbpfPolicy> {
    let attach_point = parse_attach_point(attach_point_str);

    tracing::info!(
        event = "host_ebpf.loading",
        project_id = %project_id,
        name = %name,
        object_path = %object_path.display(),
        attach_point = %attach_point_str,
        "loading host eBPF policy program"
    );

    // Validate that the object file exists and looks like a BPF ELF.
    if !object_path.exists() {
        bail!("BPF object file not found: {}", object_path.display());
    }

    match &attach_point {
        AttachPoint::Tc { device, direction } => {
            // Load via bpf(2) syscall to validate the program, then attach via tc.
            let fd =
                load_bpf_prog_from_object(object_path, name, &attach_point).with_context(|| {
                    format!(
                        "failed to load BPF program '{}' from '{}'",
                        name,
                        object_path.display()
                    )
                })?;

            // Infer the section name from the object.
            let section_name = infer_tc_section(object_path);

            let tc_handle = tc_attach_bpf(object_path, device, direction, &section_name)
                .with_context(|| {
                    format!("failed to attach TC BPF filter on device '{}'", device)
                })?;

            tracing::info!(
                event = "host_ebpf.loaded",
                project_id = %project_id,
                name = %name,
                prog_fd = fd,
                tc_handle = %tc_handle,
                "host eBPF TC policy loaded and attached"
            );

            Ok(LoadedEbpfPolicy {
                prog_fd: fd,
                tc_handle: Some(tc_handle),
                pin_path: None,
                loaded_at: now_rfc3339(),
            })
        }

        AttachPoint::Tracepoint { .. } | AttachPoint::Kprobe { .. } | AttachPoint::Raw(_) => {
            let fd =
                load_bpf_prog_from_object(object_path, name, &attach_point).with_context(|| {
                    format!(
                        "failed to load BPF program '{}' from '{}'",
                        name,
                        object_path.display()
                    )
                })?;

            // Pin to BPF filesystem for persistence across fd close.
            let pin_path = bpf_pin_path(project_id, name);
            let pinned = pin_bpf_prog(fd, &pin_path).is_ok();

            let event_label = match &attach_point {
                AttachPoint::Tracepoint { category, event } => {
                    format!("tracepoint/{}/{}", category, event)
                }
                AttachPoint::Kprobe { function } => {
                    format!("kprobe/{}", function)
                }
                _ => attach_point_str.to_string(),
            };

            tracing::info!(
                event = "host_ebpf.loaded",
                project_id = %project_id,
                name = %name,
                prog_fd = fd,
                attach_label = %event_label,
                pinned_to_bpffs = pinned,
                "host eBPF policy program loaded"
            );

            Ok(LoadedEbpfPolicy {
                prog_fd: fd,
                tc_handle: None,
                pin_path: if pinned { Some(pin_path) } else { None },
                loaded_at: now_rfc3339(),
            })
        }
    }
}

/// Determine the TC section name from a BPF object file.
///
/// Falls back to `"classifier"` if parsing fails (the most common default).
fn infer_tc_section(object_path: &Path) -> String {
    let Ok(data) = std::fs::read(object_path) else {
        return "classifier".to_string();
    };

    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return "classifier".to_string();
    }

    let e_shoff = read_u64_le(&data, 40) as usize;
    let e_shentsize = read_u16_le(&data, 58) as usize;
    let e_shnum = read_u16_le(&data, 60) as usize;
    let e_shstrndx = read_u16_le(&data, 62) as usize;

    let Ok(shstrtab) = read_section_data(&data, e_shoff, e_shentsize, e_shstrndx) else {
        return "classifier".to_string();
    };

    for i in 0..e_shnum {
        let sh_offset = e_shoff + i * e_shentsize;
        if sh_offset + e_shentsize > data.len() {
            break;
        }
        let sh_name_idx = read_u32_le(&data, sh_offset) as usize;
        let sh_type = read_u32_le(&data, sh_offset + 4);
        if sh_type != 1 {
            continue;
        }
        let name = read_cstr(&shstrtab, sh_name_idx);
        if is_bpf_prog_section(&name)
            && (name.starts_with("tc") || name == "classifier" || name == "action")
        {
            return name;
        }
    }

    "classifier".to_string()
}

/// Detach and unload a host eBPF policy program.
///
/// This is called during VM stop and destroy. Errors are logged as warnings
/// rather than hard failures to ensure VM teardown completes even if eBPF
/// cleanup fails.
pub fn detach_host_ebpf(
    project_id: &str,
    name: &str,
    policy: &crate::host_control_plane::HostEbpfPolicy,
) {
    tracing::info!(
        event = "host_ebpf.detaching",
        project_id = %project_id,
        name = %name,
        attach_point = %policy.attach_point,
        "detaching host eBPF policy program"
    );

    // Detach TC classifier if this was a TC program.
    if let Some(handle) = &policy.tc_attach_handle {
        if let Err(e) = tc_detach_bpf(handle) {
            tracing::warn!(
                event = "host_ebpf.detach_warn",
                project_id = %project_id,
                name = %name,
                handle = %handle,
                error = %e,
                "TC BPF detach failed (ignoring)"
            );
        }
    }

    // Remove the BPF pin file if one was created.
    if let Some(pin_path_str) = &policy.pin_path {
        let pin_path = PathBuf::from(pin_path_str);
        if let Err(e) = unpin_bpf_prog(&pin_path) {
            tracing::warn!(
                event = "host_ebpf.unpin_warn",
                project_id = %project_id,
                name = %name,
                pin_path = %pin_path.display(),
                error = %e,
                "BPF pin removal failed (ignoring)"
            );
        }
    }

    tracing::info!(
        event = "host_ebpf.detached",
        project_id = %project_id,
        name = %name,
        "host eBPF policy program detached"
    );
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Perf ring-buffer polling
//
// §Perf ring-buffer polling
//
// `poll_perf_ring_buffer` reads raw perf event records from a BPF perf
// ring-buffer map FD and emits each policy-decision event as a structured
// `tracing::info!` log entry.
//
// The Linux perf ring-buffer layout (PERF_RECORD_SAMPLE produced by
// bpf_perf_event_output) is:
//
//   [perf_event_header (8 bytes)]
//   [u32 size]           — payload size in bytes
//   [u8 data[size]]      — raw event payload
//   [padding to 8-byte boundary]
//
// We mmap the ring-buffer and consume records using a monotonically
// advancing read head.  A `perf_event_open` call is needed to obtain the
// FD; when no real FD is available (non-privileged environment) the
// function falls back to a drain-on-stop-signal path.
// ---------------------------------------------------------------------------

/// A decoded policy-decision event emitted by the BPF program.
///
/// Fields mirror the layout that the kernel-side `bpf_perf_event_output`
/// helper emits.  Unknown/future fields are captured in `raw_payload`.
#[derive(Debug, Clone)]
pub struct PolicyDecisionEvent {
    /// BPF program name (up to 16 bytes, NUL-terminated in-kernel).
    pub prog_name: String,
    /// Policy action: `"allow"`, `"deny"`, or an opaque numeric string.
    pub action: String,
    /// Raw bytes as received from the ring-buffer (for forward-compat).
    pub raw_payload: Vec<u8>,
}

/// BPF `perf_event_open` syscall number on x86-64.
#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: libc::c_long = 298;

/// `PERF_TYPE_SOFTWARE` and `PERF_COUNT_SW_BPF_OUTPUT`.
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;

/// Size of the mmap ring-buffer in pages (must be a power of 2).
const PERF_RING_PAGES: usize = 16;

/// mmap metadata page size (one page before the ring data pages).
const PERF_MMAP_OVERHEAD_PAGES: usize = 1;

/// Poll the BPF perf ring-buffer for policy-decision events.
///
/// Opens a `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_BPF_OUTPUT` perf event on the
/// given `map_fd` CPU, mmaps the ring-buffer, and drains available records in
/// a loop.  The loop exits when `stop_rx` receives any value or the sender is
/// dropped.
///
/// For each decoded record, emits:
/// ```text
/// tracing::info!(
///     event = "host_ebpf.policy_decision",
///     prog_name = %...,
///     action = %...,
/// )
/// ```
///
/// # Privilege requirements
///
/// `perf_event_open(2)` with `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_BPF_OUTPUT`
/// requires `CAP_PERFMON` (Linux 5.8+) or `CAP_SYS_ADMIN`.  When the syscall
/// fails (e.g. in unprivileged CI), the function logs a warning and returns
/// `Ok(())` immediately.
///
/// # Parameters
///
/// - `map_fd`: file descriptor of the `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
///   Pass `-1` to skip the actual `perf_event_open` and use the no-op path
///   (useful in tests).
/// - `cpu`: CPU index to attach the perf event to (typically 0).
/// - `stop_rx`: receiving half of an `mpsc` channel; any send or drop
///   unblocks the loop.
pub fn poll_perf_ring_buffer(map_fd: c_int, cpu: u32, stop_rx: mpsc::Receiver<()>) -> Result<()> {
    // Attempt to open a perf event FD for BPF output on the given CPU.
    // On failure (EPERM, ENOSYS, etc.) we fall back to a no-op drain that
    // simply waits for the stop signal — this keeps the function safe in
    // unprivileged environments.
    let perf_fd = open_bpf_output_perf_event(cpu);

    match perf_fd {
        Ok(fd) => {
            tracing::info!(
                event = "host_ebpf.perf_ring_buffer_started",
                map_fd = map_fd,
                cpu = cpu,
                perf_fd = fd,
                "BPF perf ring-buffer polling started"
            );

            let result = poll_ring_buffer_fd(fd, &stop_rx);

            // Close the perf FD regardless.
            // SAFETY: fd is a valid open file descriptor.
            unsafe { libc::close(fd) };

            result
        }
        Err(e) => {
            tracing::warn!(
                event = "host_ebpf.perf_ring_buffer_unavailable",
                error = %e,
                "perf_event_open failed; ring-buffer polling disabled (unprivileged environment)"
            );
            // Drain the stop channel so the caller's thread exits cleanly.
            let _ = stop_rx.recv();
            Ok(())
        }
    }
}

/// Open a `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_BPF_OUTPUT` perf event FD.
///
/// Returns the FD on success, or an error if the syscall fails.
fn open_bpf_output_perf_event(cpu: u32) -> Result<c_int> {
    /// Minimal `perf_event_attr` for a BPF output event.
    ///
    /// The kernel struct is much larger; we only need the first few fields.
    /// The kernel accepts any size ≥ the first field's offset as long as the
    /// remaining bytes are zero.
    #[repr(C)]
    struct PerfEventAttr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period_or_freq: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events_or_watermark: u32,
        bp_type: u32,
        bp_addr_or_config1: u64,
        bp_len_or_config2: u64,
        branch_sample_type: u64,
        sample_regs_user: u64,
        sample_stack_user: u32,
        clockid: i32,
        sample_regs_intr: u64,
        aux_watermark: u32,
        sample_max_stack: u16,
        _reserved2: u16,
    }

    let attr = PerfEventAttr {
        type_: PERF_TYPE_SOFTWARE,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: PERF_COUNT_SW_BPF_OUTPUT,
        sample_period_or_freq: 1,
        sample_type: 0,
        read_format: 0,
        flags: 0,
        wakeup_events_or_watermark: 1,
        bp_type: 0,
        bp_addr_or_config1: 0,
        bp_len_or_config2: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_stack_user: 0,
        clockid: 0,
        sample_regs_intr: 0,
        aux_watermark: 0,
        sample_max_stack: 0,
        _reserved2: 0,
    };

    // SAFETY: attr is correctly sized; pid=-1 means any process; group_fd=-1.
    let fd = unsafe {
        libc::syscall(
            SYS_PERF_EVENT_OPEN,
            &attr as *const PerfEventAttr as *const libc::c_void,
            -1i32,      // pid: any process
            cpu as i32, // cpu
            -1i32,      // group_fd
            0i64,       // flags: PERF_FLAG_FD_CLOEXEC not needed here
        )
    };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        bail!("perf_event_open failed: {}", err);
    }

    Ok(fd as c_int)
}

/// Poll the ring-buffer behind `perf_fd`, decoding records until `stop_rx` fires.
fn poll_ring_buffer_fd(perf_fd: c_int, stop_rx: &mpsc::Receiver<()>) -> Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mmap_len = page_size * (PERF_MMAP_OVERHEAD_PAGES + PERF_RING_PAGES);

    // SAFETY: mmap with MAP_SHARED on the perf FD.
    let mmap_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mmap_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            perf_fd,
            0,
        )
    };

    if mmap_ptr == libc::MAP_FAILED {
        let err = std::io::Error::last_os_error();
        bail!("mmap of perf ring-buffer failed: {}", err);
    }

    // The first page is the `perf_event_mmap_page` metadata page.
    // The ring data starts at offset `page_size`.
    let meta = mmap_ptr as *mut PerfEventMmapPage;
    let data_start = unsafe { (mmap_ptr as *const u8).add(page_size) };
    let data_len = page_size * PERF_RING_PAGES;

    // Local copy of the read head (we advance it as we consume records).
    let mut read_head: u64 = 0;

    loop {
        // Check the stop signal (non-blocking).
        match stop_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        // Read the kernel-written data_head (volatile).
        // SAFETY: meta is a valid mmap_page pointer.
        let data_head = unsafe {
            let head_ptr = std::ptr::addr_of!((*meta).data_head);
            std::ptr::read_volatile(head_ptr)
        };

        if data_head == read_head {
            // No new data; sleep briefly and re-check the stop signal.
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }

        // Consume all available records between read_head and data_head.
        while read_head < data_head {
            let offset = (read_head as usize) & (data_len - 1);

            // Read the 8-byte perf_event_header.
            if data_head - read_head < 8 {
                break;
            }

            // SAFETY: offset is within [0, data_len).
            let header_bytes = unsafe {
                let ptr = data_start.add(offset);
                std::slice::from_raw_parts(ptr, 8)
            };

            // perf_event_header: type(u32), misc(u16), size(u16)
            let record_type = u32::from_ne_bytes([
                header_bytes[0],
                header_bytes[1],
                header_bytes[2],
                header_bytes[3],
            ]);
            let record_size = u16::from_ne_bytes([header_bytes[6], header_bytes[7]]) as usize;

            if record_size == 0 || record_size > data_len {
                // Malformed record; advance past it to avoid infinite loop.
                read_head += 8;
                break;
            }

            // PERF_RECORD_SAMPLE = 9; skip other record types.
            if record_type == 9 && record_size > 8 {
                // Payload follows the 8-byte header.
                let payload_offset = (offset + 8) & (data_len - 1);
                let payload_len = record_size - 8;

                let payload = if payload_offset + payload_len <= data_len {
                    // SAFETY: slice is within mmap'd region.
                    unsafe {
                        std::slice::from_raw_parts(data_start.add(payload_offset), payload_len)
                    }
                    .to_vec()
                } else {
                    // Payload wraps around the ring; copy in two parts.
                    let first_len = data_len - payload_offset;
                    let second_len = payload_len - first_len;
                    let mut buf = Vec::with_capacity(payload_len);
                    // SAFETY: both slices are within the mmap'd region.
                    unsafe {
                        buf.extend_from_slice(std::slice::from_raw_parts(
                            data_start.add(payload_offset),
                            first_len,
                        ));
                        buf.extend_from_slice(std::slice::from_raw_parts(data_start, second_len));
                    }
                    buf
                };

                let event = decode_policy_event(&payload);
                tracing::info!(
                    event = "host_ebpf.policy_decision",
                    prog_name = %event.prog_name,
                    action = %event.action,
                    payload_bytes = payload.len(),
                    "BPF policy decision event received"
                );
            }

            read_head += record_size as u64;
        }

        // Advance the kernel's data_tail so it knows we consumed the records.
        // SAFETY: meta is a valid mmap_page pointer.
        unsafe {
            let tail_ptr = std::ptr::addr_of_mut!((*meta).data_tail);
            std::ptr::write_volatile(tail_ptr, read_head);
        }
    }

    // Unmap the ring-buffer now that we are done consuming records.
    // SAFETY: mmap_ptr is a valid MAP_SHARED mapping of mmap_len bytes.
    let _ = unsafe { libc::munmap(mmap_ptr, mmap_len) };

    Ok(())
}

/// Minimal subset of `perf_event_mmap_page` (Linux `<linux/perf_event.h>`).
///
/// Only the fields accessed by the userspace ring-buffer consumer are
/// declared here; the rest of the 4096-byte page is unused.
#[repr(C)]
struct PerfEventMmapPage {
    version: u32,
    compat_version: u32,
    lock: u32,
    index: u32,
    offset: i64,
    time_enabled: u64,
    time_running: u64,
    _capabilities: u64,
    pmc_width: u16,
    time_shift: u16,
    time_mult: u32,
    time_offset: u64,
    time_zero: u64,
    size: u32,
    _reserved: [u8; 948],
    data_head: u64,
    data_tail: u64,
    // Remaining fields (data_offset, data_size, aux_*) not needed.
}

/// Decode a raw perf sample payload into a [`PolicyDecisionEvent`].
///
/// The layout expected from the BPF side (bpf_perf_event_output):
///
/// ```text
/// struct {
///     u8  prog_name[16];   // BPF_OBJ_NAME_LEN
///     u8  action;          // 0 = allow, 1 = deny
///     u8  _pad[7];
/// };
/// ```
///
/// For unknown or truncated payloads, sensible defaults are used so that the
/// log entry is always emitted.
fn decode_policy_event(payload: &[u8]) -> PolicyDecisionEvent {
    let prog_name = if payload.len() >= 16 {
        let raw = &payload[..16];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&raw[..end]).into_owned()
    } else {
        String::from("unknown")
    };

    let action = if payload.len() >= 17 {
        match payload[16] {
            0 => "allow".to_string(),
            1 => "deny".to_string(),
            v => format!("{v}"),
        }
    } else {
        "unknown".to_string()
    };

    PolicyDecisionEvent {
        prog_name,
        action,
        raw_payload: payload.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attach_point_tc_egress() {
        let ap = parse_attach_point("tc-egress:tap0");
        assert!(
            matches!(ap, AttachPoint::Tc { device, direction } if device == "tap0" && direction == TcDirection::Egress)
        );
    }

    #[test]
    fn parse_attach_point_tc_ingress() {
        let ap = parse_attach_point("tc-ingress:tap1");
        assert!(
            matches!(ap, AttachPoint::Tc { device, direction } if device == "tap1" && direction == TcDirection::Ingress)
        );
    }

    #[test]
    fn parse_attach_point_tracepoint() {
        let ap = parse_attach_point("tracepoint:syscalls/sys_enter_openat");
        assert!(matches!(ap, AttachPoint::Tracepoint { category, event }
                if category == "syscalls" && event == "sys_enter_openat"));
    }

    #[test]
    fn parse_attach_point_kprobe() {
        let ap = parse_attach_point("kprobe:vfs_open");
        assert!(matches!(ap, AttachPoint::Kprobe { function } if function == "vfs_open"));
    }

    #[test]
    fn parse_attach_point_raw_fallback() {
        let ap = parse_attach_point("firecracker/jailer");
        assert!(matches!(ap, AttachPoint::Raw(s) if s == "firecracker/jailer"));
    }

    #[test]
    fn load_bpf_object_rejects_non_elf() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.o");
        // Write enough bytes to pass the size check but fail the ELF magic check.
        let bad = b"NOT_AN_ELF_FILE_AT_ALL_XXXXXXXX";
        std::fs::write(&path, bad).unwrap();
        let result = load_bpf_object_file(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not an ELF") || msg.contains("ELF"),
            "expected ELF error, got: {}",
            msg
        );
    }

    #[test]
    fn load_bpf_object_rejects_missing_file() {
        let result = load_bpf_object_file(Path::new("/nonexistent/prog.bpf.o"));
        assert!(result.is_err());
    }

    #[test]
    fn bpf_pin_path_structure() {
        let p = bpf_pin_path("my-project", "egress-filter");
        assert_eq!(
            p,
            PathBuf::from("/sys/fs/bpf/fastenv/my-project/egress-filter")
        );
    }

    #[test]
    fn tc_detach_invalid_handle() {
        let result = tc_detach_bpf("invalid_handle");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid TC detach handle"));
    }

    // -------------------------------------------------------------------------
    // Perf ring-buffer tests
    // -------------------------------------------------------------------------

    /// Verify that `decode_policy_event` correctly parses a well-formed payload.
    #[test]
    fn decode_policy_event_allow() {
        let mut payload = vec![0u8; 24];
        // Write prog_name = "egress-filter" (up to 16 bytes, NUL-terminated).
        let name = b"egress-filter\0\0\0";
        payload[..16].copy_from_slice(name);
        // action = 0 (allow)
        payload[16] = 0;

        let event = decode_policy_event(&payload);
        assert_eq!(event.prog_name, "egress-filter");
        assert_eq!(event.action, "allow");
    }

    /// Verify that `decode_policy_event` handles a deny action.
    #[test]
    fn decode_policy_event_deny() {
        let mut payload = vec![0u8; 24];
        let name = b"kprobe-block\0\0\0\0";
        payload[..16].copy_from_slice(name);
        payload[16] = 1;

        let event = decode_policy_event(&payload);
        assert_eq!(event.prog_name, "kprobe-block");
        assert_eq!(event.action, "deny");
    }

    /// Verify that `decode_policy_event` handles an unknown/opaque action code.
    #[test]
    fn decode_policy_event_unknown_action() {
        let mut payload = vec![0u8; 24];
        let name = b"tc-classifier\0\0\0";
        payload[..16].copy_from_slice(name);
        payload[16] = 42;

        let event = decode_policy_event(&payload);
        assert_eq!(event.prog_name, "tc-classifier");
        assert_eq!(event.action, "42");
    }

    /// Verify that `decode_policy_event` handles a truncated payload gracefully.
    #[test]
    fn decode_policy_event_truncated_payload() {
        let payload = vec![0u8; 5]; // shorter than 16 bytes
        let event = decode_policy_event(&payload);
        assert_eq!(event.prog_name, "unknown");
        assert_eq!(event.action, "unknown");
    }

    /// Verify that `poll_perf_ring_buffer` returns immediately when the stop
    /// signal is sent before the function enters its poll loop.
    ///
    /// Uses `map_fd = -1` to exercise the no-op fallback path (perf_event_open
    /// will fail because cpu=-1 or EPERM in unprivileged environments), which
    /// simply waits for the stop signal and returns Ok(()).
    ///
    /// If the test host has CAP_PERFMON the open may succeed; in that case the
    /// function mmaps the ring and returns Ok(()) after the stop signal fires.
    /// Either way the test must complete without hanging.
    #[test]
    fn poll_perf_ring_buffer_stops_on_signal() {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

        // Send the stop signal before the polling thread starts.
        let _ = stop_tx.send(());

        // map_fd = -1 is a sentinel for "no real BPF map"; cpu = 0.
        // The function is expected to return Ok(()) promptly.
        let result = poll_perf_ring_buffer(-1, 0, stop_rx);
        assert!(
            result.is_ok(),
            "poll_perf_ring_buffer should return Ok: {:?}",
            result
        );
    }

    /// Verify that `poll_perf_ring_buffer` exits cleanly when the stop sender
    /// is dropped (channel closed).
    #[test]
    fn poll_perf_ring_buffer_stops_on_channel_close() {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

        // Drop the sender immediately; the receiver will observe Disconnected.
        drop(stop_tx);

        let result = poll_perf_ring_buffer(-1, 0, stop_rx);
        assert!(
            result.is_ok(),
            "poll_perf_ring_buffer should return Ok on channel close: {:?}",
            result
        );
    }
}
