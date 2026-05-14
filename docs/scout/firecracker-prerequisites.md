# Firecracker Prerequisites: Findings and Go/No-Go

**Issue:** #86
**Scout date:** 2026-05-14
**Canonical docs:** docs/prd.md, docs/architecture.md
**Downstream issues:** Real Firecracker Integration phase (VM boot implementation)

---

## Host environment

```
Kernel:  Linux 5.15.0-173-generic (Ubuntu 22.04)
Arch:    x86_64
User:    lucas (uid=1003, gid=1004, groups: sudo, docker)
Cgroup:  cgroup v2 only (/sys/fs/cgroup, nsdelegate,memory_recursiveprot)
/srv:    /srv/jailer does not exist (must be created before jailer runs)
```

---

## 1. Firecracker Binary Version and Location

### Finding

Neither `firecracker` nor `jailer` is installed on the target runner.

```
which firecracker  → not found
which jailer       → not found
/usr/local/bin/firecracker → does not exist
/usr/bin/firecracker       → does not exist
apt-cache search firecracker → no Firecracker package in Ubuntu 22.04 APT
```

The latest upstream release (as of scout date) is **v1.15.1** (verified via
GitHub releases API). Firecracker is distributed as a statically-linked musl
binary. It is not available in the Ubuntu APT repository; it must be downloaded
from GitHub releases or built from source.

Upstream release URL pattern:
```
https://github.com/firecracker-microvm/firecracker/releases/download/v<version>/
  firecracker-v<version>-x86_64.tgz  (contains firecracker + jailer)
```

### Decision

**BLOCK — Firecracker binary is not present on the runner.**

The VM boot implementation must install Firecracker and jailer as a prerequisite
step. Options:

1. Download the `firecracker-v1.15.1-x86_64.tgz` release binary from GitHub
   Releases during runner setup or in a dedicated bootstrap phase.
2. Mount it from a pre-built host image layer if the environment supports that.

The jailer binary must always match the Firecracker binary version exactly
(both statically linked with the same musl toolchain, same version number).

---

## 2. KVM Device Access

### Finding

`/dev/kvm` is present on the host:

```
crw-rw---- 1 root kvm 10, 232 May 13 19:56 /dev/kvm
```

The `kvm` group has GID 108:

```
kvm:x:108:
```

The runner user `lucas` (uid=1003, gid=1004) is **not a member of the `kvm`
group**:

```
groups: lucas sudo docker   (kvm is absent)
```

A direct Python `open('/dev/kvm', os.O_RDWR)` call returns:

```
FAILED: [Errno 13] Permission denied
```

KVM is therefore **not accessible to the runner user in its current group
membership**. The jailer runs as root (or a user with `CAP_SYS_ADMIN`) and uses
`mknod` to create a `/dev/kvm` node inside the chroot jail, then `chown`s it to
the specified `--uid`/`--gid`. This means the runner itself must be able to
invoke the jailer as root or via `sudo`, not that the runner user needs direct
`/dev/kvm` access.

However, a CI environment running Firecracker directly (without jailer, for smoke
tests) would require the test process to be in the `kvm` group or have `sudo`
access.

### Decision

**BLOCK — Runner user cannot open /dev/kvm directly.**

For the VM boot implementation:

- The jailer must be invoked with sufficient privilege (root or `CAP_SYS_ADMIN`)
  to call `mknod /dev/kvm` inside the chroot. This is the standard Firecracker
  production path and does not require the runner user to be in the `kvm` group.
- CI smoke tests that invoke Firecracker directly (without jailer) will fail
  unless the CI runner is added to the `kvm` group or `sudo` is used.
- Adding `lucas` to the `kvm` group (`sudo usermod -aG kvm lucas`) and
  re-logging in would unblock direct KVM access for testing. This is a
  prerequisite for the bare-metal Firecracker boot smoke tests planned in
  Phase 5.

---

## 3. Jailer uid/gid Requirements and Cgroup Hierarchy Compatibility

### Finding

**Jailer invocation model (from upstream docs):**

```bash
jailer --id <vm-uuid> \
       --exec-file /usr/bin/firecracker \
       --uid <uid> \
       --gid <gid> \
       [--cgroup-version 2] \
       [--cgroup <controller>=<value>] \
       [--chroot-base-dir /srv/jailer] \
       [--daemonize] \
       [--new-pid-ns]
```

The jailer:
1. Creates a chroot jail at `<chroot-base-dir>/firecracker/<id>/root/`.
2. Copies the Firecracker binary into the jail root.
3. Uses `mknod` to create `/dev/net/tun` and `/dev/kvm` inside the jail.
4. `chown`s the jail root and devices to `--uid`/`--gid`.
5. Drops privileges to the specified uid/gid.
6. Execs Firecracker inside the jail.

**Cgroup hierarchy on this host:** Cgroup v2 only.

```
/proc/mounts:
  cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0

Available cgroup controllers:
  cpuset cpu io memory hugetlb pids rdma misc
```

The host uses **cgroup v2 exclusively** (no cgroup v1 hierarchy). The jailer
defaults to `--cgroup-version 1`, so the real VM boot implementation must always
pass `--cgroup-version 2` explicitly.

**Compatibility with `ProjectVmSupervisor` design (`src/host_control_plane.rs`):**

The `ProjectVmSupervisor` currently stores `firecracker_sock` as
`<vm_dir>/firecracker.sock` (`/var/lib/fastenv/vms/<project-id>/firecracker.sock`).
When jailer is used, the socket is created *inside* the chroot jail at
`<chroot-base-dir>/firecracker/<id>/root/<api-sock>` (default: `run/firecracker.socket`).
These paths do not match — the supervisor design must be updated to either:

- Not use jailer (run Firecracker directly as a non-root user with kvm group
  membership), or
- Pass `--api-sock` to Firecracker via the jailer `--` argument separator,
  pointing to a path inside the chroot that is also accessible from the host
  side through a bind mount or symlink.

**Recommended uid/gid mapping:** Create a dedicated non-root user for
Firecracker:

```bash
sudo useradd -r -M -s /usr/sbin/nologin -G kvm fc-worker
# Jailer invocation: --uid $(id -u fc-worker) --gid $(id -g fc-worker)
```

No dedicated `firecracker` user or group exists on this runner currently.

### Decision

**BLOCK — Cgroup v2 only; jailer defaults to cgroup v1.**

The VM boot implementation must:
- Pass `--cgroup-version 2` to jailer explicitly.
- Reconcile the socket path convention between `ProjectVmSupervisor` and the
  jailer chroot layout (the two paths do not match today).
- Create a dedicated non-root `fc-worker` user and group as a setup prerequisite.
- The jailer must be invoked as root (or with `CAP_SYS_ADMIN` + `CAP_MKNOD`).

No cgroup v1 controllers exist on this runner, so the jailer's default behavior
(`--cgroup-version 1`) would fail at runtime.

---

## 4. Firecracker API Socket Path and Request/Response Format

### Finding

**API version in use:** v1.15.1 (latest upstream release as of scout date).

**Transport:** Unix Domain Socket (HTTP/1.1 over UDS). Content-Type: `application/json`.

**Default socket path (no jailer):** `/run/firecracker.socket`

**Socket path via jailer:** Created inside the chroot jail. From the host:
```
/srv/jailer/firecracker/<id>/root/run/firecracker.socket
```

The `host_control_plane.rs` supervisor records:
```
firecracker_sock: <vm_dir>/firecracker.sock
```
This does not match the jailer path convention. The socket path must be
reconciled during the VM boot implementation.

**Key API endpoints (HTTP over Unix socket):**

```
GET  /               → InstanceInfo (describe instance)
PUT  /boot-source    → configure kernel image path and boot args (pre-boot only)
PUT  /drives/{id}    → configure block device (rootfs, workspace) (pre-boot only)
PUT  /machine-config → set vcpu_count and mem_size_mib (pre-boot only)
PUT  /network-interfaces/{id} → configure TAP network (pre-boot only)
PUT  /actions        → InstanceStart ("InstanceStart" action to boot)
DELETE /             → send CtrlAltDel / power off
```

**InstanceInfo response format (GET /):**
```json
{
  "app_name": "Firecracker",
  "id": "<vm-id>",
  "state": "Not started",
  "vmm_version": "1.15.1"
}
```
`state` enum values: `"Not started"`, `"Running"`, `"Paused"`.

**Minimal boot sequence over the API socket:**

```bash
# 1. Configure kernel
curl --unix-socket <sock> -X PUT http://localhost/boot-source \
  -H "Content-Type: application/json" \
  -d '{"kernel_image_path": "/kernel", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"}'

# 2. Configure rootfs block device
curl --unix-socket <sock> -X PUT http://localhost/drives/rootfs \
  -H "Content-Type: application/json" \
  -d '{"drive_id": "rootfs", "path_on_host": "/rootfs.img", "is_root_device": true, "is_read_only": false}'

# 3. Configure machine (vcpus, memory)
curl --unix-socket <sock> -X PUT http://localhost/machine-config \
  -H "Content-Type: application/json" \
  -d '{"vcpu_count": 1, "mem_size_mib": 128}'

# 4. Boot
curl --unix-socket <sock> -X PUT http://localhost/actions \
  -H "Content-Type: application/json" \
  -d '{"action_type": "InstanceStart"}'
```

All pre-boot `PUT` calls return `204 No Content` on success, or `400 Bad Request`
with a JSON error body on failure.

**Note on paths inside the jail:** When Firecracker runs under the jailer, paths
in API calls (`kernel_image_path`, `path_on_host`) are relative to the chroot
root. The supervisor must hard-link or copy kernel and rootfs images into the
chroot directory before starting the VM.

### Decision

**GO — The API socket format is well-specified and straightforward.**

The HTTP/JSON protocol over Unix Domain Socket is stable and has been consistent
across Firecracker versions. The Rust `hyper` crate with a `tokio::net::UnixStream`
connector, or the `firecracker-http-api` crate, can drive the API from the
supervisor. A minimal implementation can use `std::process::Command` to call
`curl --unix-socket` for initial testing.

The socket path mismatch with the current `ProjectVmRecord.firecracker_sock`
field is a known integration point that must be resolved in the VM boot
implementation issue.

---

## 5. Integration Risks and Downstream Impact

### Summary table

| Finding | Status | Decision |
|---|---|---|
| Firecracker binary | **Not installed** | BLOCK — must download from GitHub Releases before VM boot impl |
| KVM access (runner user) | **Permission denied** | BLOCK — runner needs kvm group or jailer must be invoked as root |
| Cgroup v2 only | **v1 absent** | BLOCK — jailer must receive `--cgroup-version 2` explicitly |
| Socket path mismatch | **supervisor != jailer** | BLOCK — `ProjectVmRecord.firecracker_sock` path convention must be reconciled |
| Firecracker API format | **Well-specified, v1.15.1** | GO — HTTP/JSON over UDS, minimal boot sequence documented above |
| Jailer uid/gid mapping | **No fc-worker user** | BLOCK — dedicated non-root user must be created |

### Risks for the VM boot implementation issue

| Risk | Severity | Mitigation |
|---|---|---|
| Firecracker binary not present | Critical | Add binary download step (GitHub Releases v1.15.1) to runner setup |
| kvm group membership | High | Add runner user to `kvm` group, or document that jailer invocation requires root |
| cgroup v2 only / jailer default v1 | High | Always pass `--cgroup-version 2` to jailer; add assertion |
| Socket path inside chroot vs supervisor field | High | Update `ProjectVmRecord.firecracker_sock` to reflect the jailer chroot path; or pass `--api-sock` via jailer to a fixed host-accessible path |
| Kernel and rootfs must be inside chroot | High | Supervisor must hard-link or copy images to `<chroot-dir>/` before starting VM |
| No jailer chroot base dir | Medium | Create `/srv/jailer` or configure `--chroot-base-dir` to `/var/lib/fastenv/jails` and ensure it exists |
| No dedicated fc user/group | Medium | Create `fc-worker` user and group as part of host provisioning |
| CI smoke tests need direct KVM access | Medium | Add runner to `kvm` group, or use `sudo` wrapper in CI; gate bare-metal tests on Phase 5 |

### Newly discovered integration points in `src/host_control_plane.rs`

1. `ProjectVmRecord.firecracker_sock` — currently set to `<vm_dir>/firecracker.sock`.
   Must change to `<chroot_base>/firecracker/<project_id>/root/run/firecracker.socket`
   when jailer is used, or to a configurable path passed via `--api-sock`.

2. `ProjectVmRecord.kernel_path` / `rootfs_path` / `workspace_path` — these are
   currently host-side paths. When jailer is used, the supervisor must hard-link
   these files into the chroot root before starting the VM.

3. `ProjectVmSupervisor::transition_vm_state` — must be driven by the API socket
   response (`GET /` returns `"state": "Running"`) rather than by a local state
   file write.

4. `ProjectVmSpec.network_policy` — the `NetworkPolicy::None` and
   `NetworkPolicy::PackageMirrorOnly` modes require no TAP device; `Allowlist`
   and `AuditedEgress` require a TAP device configured via `PUT /network-interfaces/{id}`.

---

## 6. No production code was changed in this scout.

All findings are documentation-only. The existing `ProjectVmSupervisor` stubs
in `src/host_control_plane.rs` are untouched.
