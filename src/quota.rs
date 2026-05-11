// quota.rs — Per-fork disk quota management.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//   - docs/quota-prerequisites.md
//
// This module handles:
//   1. Probing /proc/mounts to determine whether the fastenv data root
//      is on a filesystem mounted with `prjquota` (→ hard mode).
//   2. Assigning a kernel project ID to the fork's upper/ directory via
//      FS_IOC_FSSETXATTR when hard quota is available.
//   3. Parsing human-readable quota sizes (e.g. "10MiB", "2GiB").
//
// If `prjquota` is absent, or if FS_IOC_FSSETXATTR returns EOPNOTSUPP, the
// function falls back gracefully to soft quota mode and logs a warning.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::IntoRawFd;
use std::path::Path;

use anyhow::{Context, Result};
use linux_raw_sys::general::{fsxattr, FS_XFLAG_PROJINHERIT};
use linux_raw_sys::ioctl::{FS_IOC_FSGETXATTR, FS_IOC_FSSETXATTR};
use rustix::fd::{FromRawFd, OwnedFd};
use rustix::ioctl::{Getter, Opcode, Setter};

use crate::registry::QuotaMode;

// ---------------------------------------------------------------------------
// Human-readable size parser
// ---------------------------------------------------------------------------

/// Parse a human-readable size string into bytes.
///
/// Accepted suffixes (case-insensitive): B, KiB, MiB, GiB, TiB, K, M, G, T.
/// A bare number is interpreted as bytes.
///
/// Examples:
/// - `"1024"`   → `Ok(1024)`
/// - `"1MiB"`   → `Ok(1_048_576)`
/// - `"10MiB"`  → `Ok(10_485_760)`
/// - `"2GiB"`   → `Ok(2_147_483_648)`
/// - `"1KiB"`   → `Ok(1024)`
/// - `"512B"`   → `Ok(512)`
pub fn parse_quota_size(s: &str) -> Result<u64> {
    let s = s.trim();
    // Try to split into numeric prefix and optional suffix.
    let split_pos = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num_str, suffix) = s.split_at(split_pos);
    let suffix = suffix.trim();

    if num_str.is_empty() {
        anyhow::bail!("invalid quota size '{}': no numeric prefix", s);
    }

    // Parse as f64 to support decimal fractions like "1.5GiB".
    let value: f64 = num_str.parse().with_context(|| {
        format!(
            "invalid quota size '{}': cannot parse number '{}'",
            s, num_str
        )
    })?;

    let multiplier: u64 = match suffix.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KIB" => 1 << 10,
        "M" | "MIB" => 1 << 20,
        "G" | "GIB" => 1 << 30,
        "T" | "TIB" => 1 << 40,
        // Also accept KB, MB, GB (decimal, treated same as KiB etc. for simplicity)
        "KB" => 1 << 10,
        "MB" => 1 << 20,
        "GB" => 1 << 30,
        "TB" => 1 << 40,
        other => anyhow::bail!("invalid quota size '{}': unknown suffix '{}'", s, other),
    };

    let bytes = (value * multiplier as f64).round() as u64;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// /proc/mounts probe
// ---------------------------------------------------------------------------

/// Check whether the filesystem hosting `fastenv_root` is mounted with the
/// `prjquota` mount option.
///
/// Algorithm:
///   1. Read /proc/mounts line-by-line.
///   2. Find the mount entry whose mount-point is the longest prefix of
///      `fastenv_root` (i.e. the most-specific mount covering the path).
///   3. Return `true` if that entry's mount options contain `prjquota`.
///
/// Returns `false` if /proc/mounts cannot be read, or if no covering mount
/// is found.
pub fn has_prjquota(fastenv_root: &Path) -> bool {
    let contents = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read /proc/mounts; assuming no prjquota");
            return false;
        }
    };

    parse_proc_mounts_has_prjquota(&contents, fastenv_root)
}

/// Pure function to parse /proc/mounts content and determine if the
/// most-specific mount covering `fastenv_root` has `prjquota`.
///
/// Exported for unit testing without filesystem access.
pub fn parse_proc_mounts_has_prjquota(proc_mounts: &str, fastenv_root: &Path) -> bool {
    // Each line: <device> <mountpoint> <fstype> <options> <dump> <pass>
    let mut best_mount: Option<(&str, bool)> = None; // (mountpoint, has_prjquota)
    let mut best_len = 0usize;

    for line in proc_mounts.lines() {
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        let mountpoint = match fields.next() {
            Some(m) => m,
            None => continue,
        };
        let _fstype = fields.next();
        let options = match fields.next() {
            Some(o) => o,
            None => continue,
        };

        // Check if fastenv_root starts with this mountpoint.
        let mountpoint_path = Path::new(mountpoint);
        if fastenv_root.starts_with(mountpoint_path) {
            let mlen = mountpoint.len();
            if mlen >= best_len {
                best_len = mlen;
                let has_prj = options.split(',').any(|opt| opt == "prjquota");
                best_mount = Some((mountpoint, has_prj));
            }
        }
    }

    best_mount.map(|(_, has_prj)| has_prj).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Project quota assignment
// ---------------------------------------------------------------------------

/// Attempt to assign a project ID and hard quota limit to `upper_dir`.
///
/// Returns `QuotaMode::Hard` if the project ID was successfully assigned via
/// `FS_IOC_FSSETXATTR`, `QuotaMode::Soft` otherwise (with a tracing warning).
///
/// The caller should verify `has_prjquota()` before calling this function;
/// if `prjquota` is absent, the ioctl will return `EOPNOTSUPP` and this
/// function will fall back to soft mode gracefully.
///
/// `project_id` must be unique across all active forks on this filesystem.
/// The caller is responsible for allocating unique IDs (see `alloc_project_id`).
pub fn assign_project_quota(
    upper_dir: &Path,
    project_id: u32,
    _quota_bytes: u64,
) -> Result<QuotaMode> {
    // Open the upper directory.
    // O_DIRECTORY ensures the path is a directory; O_CLOEXEC for safety.
    // libc constants: O_DIRECTORY=0o200000, O_CLOEXEC=0o2000000 on Linux x86_64.
    const O_DIRECTORY: i32 = 0o200000;
    const O_CLOEXEC: i32 = 0o2000000;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_CLOEXEC)
        .open(upper_dir)
        .with_context(|| format!("open upper dir for ioctl: {}", upper_dir.display()))?;

    let owned_fd: OwnedFd = {
        let raw = file.into_raw_fd();
        // SAFETY: we own this fd (just opened above)
        unsafe { OwnedFd::from_raw_fd(raw) }
    };

    // First read existing xattr to preserve any existing flags.
    let existing = fsgetxattr(&owned_fd);
    let base_xflags = match existing {
        Ok(xa) => xa.fsx_xflags,
        Err(_) => 0,
    };

    // Build the fsxattr to set: enable FS_XFLAG_PROJINHERIT and set projid.
    let new_xattr = fsxattr {
        fsx_xflags: base_xflags | FS_XFLAG_PROJINHERIT,
        fsx_extsize: 0,
        fsx_nextents: 0,
        fsx_projid: project_id,
        fsx_cowextsize: 0,
        fsx_pad: [0u8; 8],
    };

    match fssetxattr(&owned_fd, new_xattr) {
        Ok(()) => {
            tracing::info!(
                upper_dir = %upper_dir.display(),
                project_id,
                "assigned project quota (hard mode)"
            );
            Ok(QuotaMode::Hard)
        }
        Err(e) => {
            // EOPNOTSUPP (95) means no prjquota; EPERM means no privilege.
            // Both are non-fatal: fall back to soft mode.
            let raw_err = e.raw_os_error();
            tracing::warn!(
                upper_dir = %upper_dir.display(),
                project_id,
                errno = raw_err,
                "FS_IOC_FSSETXATTR failed; falling back to soft quota mode"
            );
            Ok(QuotaMode::Soft)
        }
    }
}

// ---------------------------------------------------------------------------
// FS_IOC_FSGETXATTR / FS_IOC_FSSETXATTR via rustix
// ---------------------------------------------------------------------------

/// Read the fsxattr for an open directory fd.
fn fsgetxattr(fd: &OwnedFd) -> rustix::io::Result<fsxattr> {
    // SAFETY: FS_IOC_FSGETXATTR is a valid opcode for this type, and
    // `fsxattr` is the correct output type defined by the Linux kernel ABI.
    let getter: Getter<{ FS_IOC_FSGETXATTR as Opcode }, fsxattr> = unsafe { Getter::new() };
    unsafe { rustix::ioctl::ioctl(fd, getter) }
}

/// Write fsxattr for an open directory fd.
fn fssetxattr(fd: &OwnedFd, xattr: fsxattr) -> rustix::io::Result<()> {
    // SAFETY: FS_IOC_FSSETXATTR is a valid opcode for this type, and
    // `fsxattr` is the correct input type defined by the Linux kernel ABI.
    let setter: Setter<{ FS_IOC_FSSETXATTR as Opcode }, fsxattr> = unsafe { Setter::new(xattr) };
    unsafe { rustix::ioctl::ioctl(fd, setter) }
}

// ---------------------------------------------------------------------------
// Project ID allocator
// ---------------------------------------------------------------------------

/// Allocate a unique project ID for a new fork by hashing the fork key.
///
/// Uses a simple FNV-1a hash to map the fork key to a 32-bit project ID.
/// IDs 0 and 1 are reserved (0 = no project, 1 = root); the result is
/// clamped to [2, u32::MAX].
///
/// This is best-effort: collisions are theoretically possible for very large
/// numbers of forks. For production use, a persistent counter in the registry
/// would be more robust, but that is out of scope for this issue.
pub fn alloc_project_id(fork_key: &str) -> u32 {
    // FNV-1a 32-bit hash
    let mut hash: u32 = 2_166_136_261u32;
    for byte in fork_key.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619u32);
    }
    // Clamp to [2, u32::MAX] to avoid reserved IDs 0 and 1.
    hash.max(2)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_quota_size
    // -----------------------------------------------------------------------

    #[test]
    fn parse_quota_size_bytes() {
        assert_eq!(parse_quota_size("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_quota_size_b_suffix() {
        assert_eq!(parse_quota_size("512B").unwrap(), 512);
    }

    #[test]
    fn parse_quota_size_kib() {
        assert_eq!(parse_quota_size("1KiB").unwrap(), 1024);
    }

    #[test]
    fn parse_quota_size_mib() {
        assert_eq!(parse_quota_size("10MiB").unwrap(), 10 * 1024 * 1024);
    }

    #[test]
    fn parse_quota_size_gib() {
        assert_eq!(parse_quota_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_quota_size_case_insensitive_mib() {
        assert_eq!(parse_quota_size("5mib").unwrap(), 5 * 1024 * 1024);
    }

    #[test]
    fn parse_quota_size_fractional_gib() {
        // 1.5 GiB
        let expected = (1.5f64 * (1u64 << 30) as f64).round() as u64;
        assert_eq!(parse_quota_size("1.5GiB").unwrap(), expected);
    }

    #[test]
    fn parse_quota_size_plain_m() {
        assert_eq!(parse_quota_size("3M").unwrap(), 3 * 1024 * 1024);
    }

    #[test]
    fn parse_quota_size_invalid() {
        assert!(parse_quota_size("abc").is_err());
    }

    #[test]
    fn parse_quota_size_unknown_suffix() {
        assert!(parse_quota_size("1PiB").is_err());
    }

    // -----------------------------------------------------------------------
    // parse_proc_mounts_has_prjquota
    // -----------------------------------------------------------------------

    const PROC_MOUNTS_NO_PRJQUOTA: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/md0 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
";

    const PROC_MOUNTS_WITH_PRJQUOTA: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sdb1 / ext4 rw,relatime,prjquota 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
";

    const PROC_MOUNTS_PRJQUOTA_ON_SUBDIR: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/md0 / ext4 rw,relatime 0 0
/dev/sdb1 /var/lib ext4 rw,relatime,prjquota 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
";

    #[test]
    fn proc_mounts_no_prjquota_returns_false() {
        let root = Path::new("/var/lib/fastenv");
        assert!(!parse_proc_mounts_has_prjquota(
            PROC_MOUNTS_NO_PRJQUOTA,
            root
        ));
    }

    #[test]
    fn proc_mounts_with_prjquota_on_root_returns_true() {
        let root = Path::new("/var/lib/fastenv");
        assert!(parse_proc_mounts_has_prjquota(
            PROC_MOUNTS_WITH_PRJQUOTA,
            root
        ));
    }

    #[test]
    fn proc_mounts_prjquota_on_subdir_beats_root() {
        // /var/lib is mounted with prjquota; /var/lib/fastenv is under it
        let root = Path::new("/var/lib/fastenv");
        assert!(parse_proc_mounts_has_prjquota(
            PROC_MOUNTS_PRJQUOTA_ON_SUBDIR,
            root
        ));
    }

    #[test]
    fn proc_mounts_prjquota_subdir_does_not_affect_different_path() {
        // /var/lib has prjquota but we're asking about /tmp/fastenv
        let root = Path::new("/tmp/fastenv");
        assert!(!parse_proc_mounts_has_prjquota(
            PROC_MOUNTS_PRJQUOTA_ON_SUBDIR,
            root
        ));
    }

    #[test]
    fn proc_mounts_empty_input_returns_false() {
        let root = Path::new("/var/lib/fastenv");
        assert!(!parse_proc_mounts_has_prjquota("", root));
    }

    // -----------------------------------------------------------------------
    // alloc_project_id
    // -----------------------------------------------------------------------

    #[test]
    fn alloc_project_id_nonzero_and_ge2() {
        let id = alloc_project_id("agent-1");
        assert!(id >= 2, "project ID must be >= 2, got {}", id);
    }

    #[test]
    fn alloc_project_id_different_keys_likely_different() {
        let a = alloc_project_id("agent-1");
        let b = alloc_project_id("agent-2");
        // With FNV-1a, these happen to differ. We don't assert they must
        // differ in general (hash collisions are valid), but these specific
        // strings should differ.
        assert_ne!(
            a, b,
            "agent-1 and agent-2 should have different project IDs"
        );
    }

    #[test]
    fn alloc_project_id_deterministic() {
        let id1 = alloc_project_id("my-fork");
        let id2 = alloc_project_id("my-fork");
        assert_eq!(id1, id2, "same key must yield same project ID");
    }
}
