# Phase 4 Dev-Scout Findings: quota ioctl, multi-lower overlayfs, and MS_BIND bind-mount

**Issue:** #50
**Scout date:** 2026-05-11
**Canonical docs:** docs/architecture.md, docs/implementation-plan.md, docs/quota-prerequisites.md
**Downstream issues:** #44 (per-fork disk quotas), #45 (shared cache mounts), #46 (GC), #47 (mount-path/unmount), #48 (bench)

---

## Host environment

```
Kernel:  Linux 5.15.0-173-generic (Ubuntu 22.04)
Arch:    x86_64
User:    lucas (uid=1003, groups: sudo, docker)
Rust:    rustc 1.92.0 / cargo 1.92.0 (stable-x86_64-unknown-linux-gnu)
rustix:  1.1.4
Root FS: /dev/md0 (ext4 RAID) — rw,relatime, no prjquota mount option
```

---

## 1. prjquota probe — /proc/mounts analysis

### What was probed

`/proc/mounts` on the self-hosted runner (Linux 5.15.0-173-generic, Ubuntu 22.04)
was inspected for the `prjquota` mount option on the device hosting the fastenv
data root (`/var/lib/fastenv`). The root device is `/dev/md0` mounted at `/`.

### Result

```
/dev/md0 / ext4 rw,relatime 0 0
```

**`prjquota` is NOT present** on the root device. The ext4 filesystem is mounted
with `rw,relatime` only. No XFS filesystems are present.

### Implication for #44

`fastenv fork` will always select **soft quota mode** on this runner. Hard
quota enforcement (kernel-level `EDQUOT` rejection) requires the target
partition to be remounted with `prjquota`. The quota probe in #44 must
implement the `/proc/mounts` scan and fall back to soft mode gracefully, which
matches the existing `docs/quota-prerequisites.md` specification.

The `parse_proc_mounts()` function planned for #44 should:
1. Locate the `/var/lib/fastenv` path (or its first ancestor present in mounts)
2. Check if the mount options string contains `prjquota`
3. Return `QuotaMode::Hard` if found, `QuotaMode::Soft` otherwise

---

## 2. FS_IOC_FSSETXATTR — project quota ioctl via rustix

### rustix 1.1.4 API assessment

rustix 1.1.4 does **not** expose `FS_IOC_FSSETXATTR` or `FS_IOC_FSGETXATTR` as
first-class functions. The `rustix::fs::ioctl` module provides:

- `ioctl_getflags` / `ioctl_setflags` — `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS`
- `ioctl_blksszget` / `ioctl_blkpbszget` — block size queries
- `ioctl_ficlone` — reflink copy
- `ext4_ioc_resize_fs` — ext4 resize

**`FS_IOC_FSSETXATTR` (opcode `0x401c5820`) is absent from rustix 1.1.4.**

The underlying ioctl and struct are defined in `linux-raw-sys` 0.4.15:

```rust
// linux-raw-sys 0.4.15, src/x86_64/ioctl.rs
pub const FS_IOC_FSSETXATTR: u32 = 1075599392; // 0x401c5820
pub const FS_IOC_FSGETXATTR: u32 = 2149598239; // 0x801c581f

// linux-raw-sys 0.4.15, src/x86_64/general.rs
pub struct fsxattr {
    pub fsx_xflags:    __u32,  // extended flags (FS_XFLAG_PROJINHERIT = 0x0020)
    pub fsx_extsize:   __u32,  // extent size hint (ignore for quotas)
    pub fsx_nextents:  __u32,  // read-only nextents
    pub fsx_projid:    __u32,  // project ID to assign
    pub fsx_cowextsize: __u32,
    pub fsx_pad:       [u8; 8],
}
```

### Kernel-level result on this host

`FS_IOC_FSGETXATTR` succeeds on ext4 directories (returns projid=0, xflags=0).
`FS_IOC_FSSETXATTR` fails with **errno 95 (EOPNOTSUPP)** on ext4 without
`prjquota` mounted. This is expected: ext4 requires the quota subsystem active
(`quotaon -P`) before project IDs can be assigned.

```
FS_IOC_FSGETXATTR OK: projid=0, xflags=0x0
FS_IOC_FSSETXATTR FAILED: errno=95 (Operation not supported)
Reason: ext4 requires prjquota mount option + quotaon -P
```

### Recommended approach for #44

Use a raw `rustix::ioctl::Ioctl` implementation or `unsafe` libc `ioctl(2)`
call, since rustix does not wrap this ioctl. The recommended pattern is a
custom `Ioctl` impl using the `linux-raw-sys` constants already available as
a transitive dependency:

```rust
use rustix::ioctl::{self, Ioctl, IoctlOutput, Opcode};
use linux_raw_sys::general::{fsxattr, FS_IOC_FSSETXATTR};

struct SetFsXattr(fsxattr);

unsafe impl Ioctl for SetFsXattr {
    type Output = ();
    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        FS_IOC_FSSETXATTR as Opcode
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        &mut self.0 as *mut _ as *mut _
    }

    unsafe fn output_from_ptr(
        _: IoctlOutput,
        _: *mut std::ffi::c_void,
    ) -> rustix::io::Result<()> {
        Ok(())
    }
}

// Usage:
fn assign_project_id(fd: BorrowedFd, project_id: u32) -> rustix::io::Result<()> {
    let attrs = fsxattr {
        fsx_xflags: 0x0020, // FS_XFLAG_PROJINHERIT
        fsx_projid: project_id,
        ..unsafe { std::mem::zeroed() }
    };
    unsafe { ioctl::ioctl(fd, SetFsXattr(attrs)) }
}
```

**Important:** When `prjquota` is absent (soft mode), the ioctl returns
`EOPNOTSUPP`. #44 must detect this and fall back to soft mode instead of
propagating the error.

---

## 3. Multi-lower overlayfs — colon-separated lowerdir=

### Validation result

Two lower directories were created; overlayfs was mounted with
`lowerdir=lower1:lower2`. Both are visible in `merged/`:

```
Setup:
  lower1/file-from-lower1.txt  → "content-in-lower1"
  lower2/file-from-lower2.txt  → "content-in-lower2"

Mount:
  mount -t overlay overlay \
    -o lowerdir=/tmp/scout/lower1:/tmp/scout/lower2,upperdir=upper,workdir=work \
    merged/

  exit: 0

merged/ contents:
  file-from-lower1.txt  → "content-in-lower1"  ✓
  file-from-lower2.txt  → "content-in-lower2"  ✓

/proc/mounts entry:
  overlay merged overlay rw,relatime,lowerdir=lower1:lower2,upperdir=upper,workdir=work 0 0
```

**Multi-lower overlayfs works on kernel 5.15.0.** (Support added in Linux 3.19.)

Write-through was also verified: writing to `merged/new-file.txt` created the
file in `upper/new-file.txt` as expected.

### Rust API for #45

`rustix::mount::mount` accepts the `lowerdir=a:b:c` data string directly as
the `data` parameter. The existing `fork.rs` pattern extends naturally:

```rust
// existing (single lower):
let data = format!("lowerdir={lower},upperdir={upper},workdir={work}");
rustix::mount::mount("overlay", &merged, "overlay", MountFlags::empty(),
    Some(CStr::from_bytes_with_nul_unchecked(&format!("{data}\0").into_bytes())))?;

// multi-lower (#45):
let lower_dirs = cache_layers.join(":");
let data = format!("lowerdir={lower_dirs}:{base_lower},upperdir={upper},workdir={work}");
// same mount call — colon separator is passed verbatim to the kernel
```

**Ordering:** the kernel stacks lower directories left-to-right; the leftmost
path wins name conflicts. For #45 (shared caches), put the base lower last so
per-fork writable upper/ shadowing works correctly:
`lowerdir=<cache_npm>:<cache_pip>:<base_lower>`.

---

## 4. MS_BIND bind-mount — rustix::mount::mount_bind

### Validation result

`mount --bind` of an overlayfs `merged/` directory to a second path succeeded:

```
source: /tmp/scout/merged/     (overlayfs with lowerdir=lower1:lower2)
target: /tmp/scout/bind-target/

mount --bind exit: 0

bind-target/ contents:
  file-from-lower1.txt  → "content-in-lower1"  ✓
  file-from-lower2.txt  → "content-in-lower2"  ✓

/proc/mounts entry:
  overlay /tmp/scout/bind-target overlay rw,relatime,lowerdir=lower1:lower2,... 0 0
```

Note: `/proc/mounts` shows the bind target with the same overlay type and
options as the source — the kernel propagates the mount attributes.

`umount -l` (MNT_DETACH) on the bind target also succeeded (exit 0).

### rustix API for #47

`rustix::mount::mount_bind` (available since rustix 1.1.4) is the correct
function — it emits `mount(source, target, NULL, MS_BIND, NULL)` exactly:

```rust
use rustix::mount::mount_bind;

fn bind_mount_merged(merged: &Path, target: &Path) -> rustix::io::Result<()> {
    mount_bind(merged, target)
}
```

For unmount, `rustix::mount::unmount` with `UnmountFlags::DETACH` (MNT_DETACH)
is safe and matches the pattern already used by `src/discard.rs`:

```rust
use rustix::mount::{unmount, UnmountFlags};

fn unbind(target: &Path) -> rustix::io::Result<()> {
    unmount(target, UnmountFlags::DETACH)
}
```

**Ordering for #47:** the bind mount must be unmounted before the underlying
overlayfs is unmounted, otherwise the overlayfs unmount returns `EBUSY`.

---

## 5. Integration risks for downstream issues

### #44 (per-fork disk quotas)

| Risk | Severity | Mitigation |
|---|---|---|
| `FS_IOC_FSSETXATTR` not in rustix 1.1.4 | High | Use custom `Ioctl` impl with `linux-raw-sys` constants (§2 above) |
| `EOPNOTSUPP` when prjquota absent | Medium | Detect errno=95 and set `quota_mode=soft`; never error out |
| prjquota requires `quotaon -P` + remount | Medium | Document in quota-prerequisites.md; do not attempt in soft mode |
| Self-hosted runner has no prjquota on / | Confirmed | CI tests must not assert hard quota behavior; test soft mode only |

### #45 (shared cache mounts)

| Risk | Severity | Mitigation |
|---|---|---|
| lowerdir= ordering affects shadowing | Medium | Put base lower last; caches leftmost (§3 above) |
| Stale mounts if cache layer evicted while overlay active | High | GC (#46) must check for active mounts (via /proc/mounts) before removing cache dirs |
| Maximum lowerdir count | Low | Kernel 5.15 supports at least 500 lower layers; practical limit is inode lookup depth |

### #46 (GC — TTL/LRU fork eviction)

| Risk | Severity | Mitigation |
|---|---|---|
| Stale overlay mounts orphaned after crash | Medium | GC must scan /proc/mounts for all overlay entries, cross-reference registry, and unmount (MNT_DETACH) any orphans |
| Bind mounts outliving their overlay source | Medium | GC should unmount bind mounts before their base overlay |

### #47 (mount-path and unmount)

| Risk | Severity | Mitigation |
|---|---|---|
| Unbind before overlay unmount | High | Always unmount bind target first; see §4 above |
| bind target left mounted if fastenv crashes | Medium | GC (#46) must detect bind mounts on forks/*/merged/ paths and clean up |

### #48 (bench)

No new kernel capability risks. The latency measurement from fork.rs (mount
syscall entry to return) is the appropriate baseline. Bench should be gated on
#44 and #45 being stable, not on this scout's findings.

---

## 6. Additional finding: MNT_DETACH confirmed

Per the note from issue #39's integration handoff: `rustix::mount::unmount`
with `UnmountFlags::DETACH` was tested by `src/discard.rs`. This scout
independently confirms that `umount -l` (kernel MNT_DETACH) succeeds on this
kernel for both regular overlay mounts and bind mounts. The flag is present in
rustix 1.1.4 as `UnmountFlags::DETACH`.

---

## Summary

| Capability | Status on kernel 5.15.0 + ext4 (no prjquota) | rustix 1.1.4 API |
|---|---|---|
| prjquota mount option | **ABSENT** — soft mode only on this runner | n/a — parse /proc/mounts in Rust |
| FS_IOC_FSSETXATTR (project ID) | **EOPNOTSUPP** without prjquota; syscall itself available | Custom `Ioctl` impl needed; not in rustix |
| Multi-lower overlayfs (lowerdir=a:b) | **PASS** — both files visible in merged/ | `rustix::mount::mount` with colon-separated data string |
| MS_BIND bind-mount | **PASS** — content visible at bind target | `rustix::mount::mount_bind` |
| MNT_DETACH unmount | **PASS** — bind and overlay both cleanly detach | `rustix::mount::unmount` with `UnmountFlags::DETACH` |

No production code was changed in this scout.
