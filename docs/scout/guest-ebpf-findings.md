# Dev-Scout Findings: Guest eBPF Loader and CO-RE Support

**Issue:** #92
**Scout date:** 2026-05-14
**Canonical docs:** docs/prd.md §4.5, docs/architecture.md §2 (Project boundary)
**Downstream issues:** #93 (guest eBPF policy loader implementation), #97 (benchmark harness)

---

## Host environment

```text
Host kernel:  Linux 5.15.0-173-generic (Ubuntu 22.04)
Arch:         x86_64
Firecracker:  v1.15.1 x86_64
Prior scout:  #72 (host/guest eBPF boundary — see docs/scout/issue-72-findings.md)
```

---

## Context from prior scout (#72)

Issue #72 established that the Firecracker quickstart guest kernel (`Linux 4.14.174`) is
**too old** for guest eBPF policy: `BPF_PROG_LOAD` returned `EINVAL` for
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`. This scout (#92) focuses on what a suitable
guest kernel must provide and which loader toolchain (Aya vs libbpf) is
appropriate for the fastenv guest runtime.

No guest VM was booted during this scout; findings are derived from kernel
configuration requirements, published CO-RE support timelines, and toolchain
constraints assessed against the host environment.

---

## 1. Guest kernel version and BPF CO-RE support

### What was probed

CO-RE (Compile Once – Run Everywhere) requires `CONFIG_DEBUG_INFO_BTF=y` in the
guest kernel. BTF (BPF Type Format) encodes kernel struct layouts in the kernel
image itself. Aya and libbpf both depend on BTF for type-relocation at load
time.

### Kernel version requirements

| Feature | Minimum kernel | Notes |
|---|---|---|
| `CONFIG_DEBUG_INFO_BTF` | 5.2 | First release with in-kernel BTF |
| `BPF_PROG_TYPE_TRACEPOINT` | 4.7 | Available but not CO-RE-ready without BTF |
| `BPF_PROG_TYPE_LSM` | 5.7 | Requires `CONFIG_BPF_LSM=y` + `lsm=bpf` boot param |
| `BPF_PROG_TYPE_CGROUP_SKB` | 4.10 | cgroup v2 required; must be mounted |
| CO-RE type relocation (libbpf) | 5.2 + BTF | `BPF_BTF_LOAD` syscall present |
| Aya CO-RE relocation | 5.2 + BTF | Same requirement as libbpf CO-RE |
| BTF-aware verifier | 5.2 | `bpftool prog dump` requires this |

**Minimum viable guest kernel for this scout's requirements: Linux 5.7**
(covers LSM, CO-RE, tracepoint, cgroup_skb in one baseline).

The quickstart kernel (4.14.174) used in #72 satisfies **none** of these.

### Go/no-go decision

| Capability | Decision | Condition |
|---|---|---|
| CO-RE / BTF support | **GO — conditional** | Guest kernel must be ≥ 5.2 with `CONFIG_DEBUG_INFO_BTF=y` |
| Quickstart kernel (4.14.174) | **BLOCK** | Too old; must be replaced before #93 can proceed |
| Host kernel (5.15) BTF | **GO** | `CONFIG_DEBUG_INFO_BTF=y` confirmed on host; serves as reference |

**Finding:** The project VM must ship a custom guest kernel ≥ 5.7 with
`CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_LSM=y`, and cgroup v2 enabled.
The Firecracker quickstart image is **not** a valid baseline for #93.

---

## 2. Available BPF program types

### What was probed

Three program types are required per the issue scope:

- `BPF_PROG_TYPE_TRACEPOINT` — observe syscall entry/exit from crun-spawned processes
- `BPF_PROG_TYPE_LSM` — enforce security policy at LSM hook points
- `BPF_PROG_TYPE_CGROUP_SKB` — observe or filter network packets at the cgroup boundary

### Kernel configuration requirements

```text
CONFIG_BPF=y                   # core BPF support
CONFIG_BPF_SYSCALL=y           # BPF syscall accessible from user space
CONFIG_DEBUG_INFO_BTF=y        # CO-RE type metadata in the kernel
CONFIG_BPF_LSM=y               # LSM program type
CONFIG_CGROUPS=y               # cgroup subsystem
CONFIG_CGROUP_BPF=y            # BPF at cgroup attach points
CONFIG_BPF_EVENTS=y            # perf events for tracepoints
BOOT: lsm=bpf (or lsm=...,bpf)  # BPF LSM must be listed in the LSM chain
BOOT: cgroup_no_v1=all         # optional: force cgroup v2 only
```

### Go/no-go per program type

| Program type | Decision | Notes |
|---|---|---|
| `BPF_PROG_TYPE_TRACEPOINT` | **GO** | Available ≥ kernel 4.7; CO-RE requires 5.2+ BTF |
| `BPF_PROG_TYPE_LSM` | **GO — conditional** | Requires `CONFIG_BPF_LSM=y` + `lsm=bpf` boot param; ≥ kernel 5.7 |
| `BPF_PROG_TYPE_CGROUP_SKB` | **GO — conditional** | Requires `CONFIG_CGROUP_BPF=y` + cgroup v2 mount in guest |
| CO-RE type relocation for all | **GO — conditional** | All three require `CONFIG_DEBUG_INFO_BTF=y` in guest kernel |

**Finding for #93:** Guest kernel image for the project VM must be compiled
with all four `CONFIG_` options set to `y`. The boot parameter `lsm=bpf` must
be passed to the Firecracker guest in the `boot_args` field of the VM config.
cgroup v2 must be mounted in the guest rootfs (`/sys/fs/cgroup` as cgroup2).

---

## 3. Loader toolchain: Aya (Rust) vs libbpf (C)

### Assessment criteria

| Criterion | Aya | libbpf |
|---|---|---|
| Language | Rust (aligns with fastenv codebase) | C (foreign dependency) |
| CO-RE support | Yes — via `aya` crate ≥ 0.13 | Yes — reference implementation |
| Cargo integration | Yes (`aya`, `aya-bpf`, `aya-log`) | No — requires build.rs + bindgen |
| No libc linking required | Yes | No — links against libc |
| Binary size in guest | Smaller (no C runtime overhead) | Larger |
| Maturity | Production use at major companies | Reference implementation, stable API |
| BPF skeleton / CO-RE maps | `aya::maps` API | `BPF_MAP_TYPE_*` via libbpf skeleton |
| LSM program support | Yes (≥ aya 0.13) | Yes |
| tracepoint support | Yes | Yes |
| cgroup_skb support | Yes | Yes |
| Guest cross-compile complexity | Moderate (Rust cross-target: `x86_64-unknown-linux-musl`) | High (C cross-compile + sysroot) |

### Go/no-go decision

**Decision: GO — Aya (Rust)**

Rationale:
1. fastenv is an all-Rust codebase. Adding libbpf would require a C toolchain
   in the build environment, bindgen, and a libc dependency in the guest image.
2. Aya supports all three required program types (tracepoint, LSM, cgroup_skb)
   as of aya 0.13.
3. Aya's CO-RE support uses the same kernel BTF interface as libbpf; there is no
   correctness advantage to libbpf on a kernel ≥ 5.7.
4. A musl-linked Aya binary can be embedded in a minimal guest rootfs without
   glibc. This is important for the Firecracker guest image size constraint.
5. The `aya-bpf` crate compiles the BPF bytecode side with `cargo bpf build`,
   producing an ELF that Aya loads at runtime — the same pattern as libbpf
   skeletons but in pure Rust.

**Risk:** Aya is younger than libbpf. Edge cases in CO-RE map relocation have
been reported for complex programs. #93 must use simple, flat BPF maps and
avoid complex CO-RE struct rewrites initially.

---

## 4. Guest eBPF vs host eBPF conflict analysis

### What was assessed

PRD §4.5 requires that host eBPF and guest eBPF operate as **separate
kernel-local policy planes**. The architecture doc (§eBPF) states:

> host eBPF is loaded by the host kernel and only sees host-side state;
> guest eBPF is loaded by the guest kernel and only sees guest-side state.

Firecracker provides full VM-level isolation: the guest kernel has its own BPF
verifier, map namespace, and program table. Host and guest BPF programs **cannot
directly observe each other's maps or programs**.

### Potential conflict surfaces

| Surface | Risk | Mitigation |
|---|---|---|
| Host and guest both load tracepoint programs | None — separate kernel BPF tables | No action needed |
| Host eBPF policy rejects guest BPF syscall from Firecracker | Low | Host policy must allow `BPF_PROG_LOAD` from the `firecracker` or `jailer` process group |
| cgroup hierarchy overlap (host cgroup v2 path for Firecracker vs guest cgroup v2 path) | Medium | Firecracker mounts its own cgroup namespace; guest cgroup v2 is separate |
| Host bpf prog list grows due to guest programs | None — guest BPF lives in guest kernel memory | Verified in #72: host `bpftool prog list` does not show guest programs |

### Go/no-go decision

**Decision: GO — no conflict**

Guest eBPF programs loaded inside the Firecracker VM are fully isolated from
host eBPF. The only operational consideration is ensuring the host eBPF policy
(#94, #105) permits `BPF_PROG_LOAD` syscalls from the Firecracker/jailer
process. This is a host-side policy concern, not a guest-side constraint.

**Finding for #93:** Guest eBPF loader code can be developed and tested
independently of the host eBPF layer. The guest loader should be gated on
the guest kernel version check (finding §1) at startup and must not assume
a specific cgroup path — it should discover the cgroup v2 mount dynamically
from `/proc/mounts`.

---

## 5. Integration risks for downstream issues

### #93 (guest eBPF policy loader)

| Risk | Severity | Mitigation |
|---|---|---|
| Guest kernel lacks `CONFIG_DEBUG_INFO_BTF` | **High** | Probe BTF at loader startup; return `GuestEbpfError::NoBtf` if absent |
| `lsm=bpf` not in guest boot args | **High** | Detect by attempting `BPF_PROG_TYPE_LSM` load; fall back to tracepoint-only mode |
| cgroup v2 not mounted in guest rootfs | **Medium** | Check `/proc/mounts` for `cgroup2` type before attaching `cgroup_skb` |
| Aya CO-RE relocation fails for complex maps | **Medium** | Use flat `HashMap` BPF maps; avoid nested struct rewrites in initial implementation |
| Guest kernel < 5.7 shipped in production image | **High** | Guest kernel version check must gate the entire loader; fail fast with clear error |
| musl cross-compile target not in CI | **Low** | Add `x86_64-unknown-linux-musl` to rustup targets in CI; already supported by Rust toolchain |

### #96 (guest harness)

| Risk | Severity | Mitigation |
|---|---|---|
| Guest harness boots quickstart kernel (4.14) | **High** | Guest harness must use the upgraded guest kernel with BTF; block #96 on kernel image availability |
| BTF probe step missing from guest harness | **Medium** | Add kernel config check (`/proc/config.gz` or `/boot/config`) as first step in guest harness |

### #97 (benchmark harness)

| Risk | Severity | Mitigation |
|---|---|---|
| eBPF overhead measured on non-BTF guest kernel | **High** | Benchmark must gate eBPF overhead measurement on guest BTF availability |
| Aya loader startup latency not measured separately | **Low** | Benchmark should time loader init separately from program attach |

---

## 6. Recommended stub entrypoints for #93

The following Rust module structure is the recommended seam for #93. No
implementation code should be added in this scout — these are discovery
notes only.

```text
src/guest_ebpf.rs          — top-level guest eBPF loader module (new file)
  pub struct GuestEbpfLoader   — owns loaded Aya programs and maps
  pub enum GuestEbpfError      — NoBtf, NoLsmSupport, NoCgroupV2, LoadFailed(String)
  pub fn probe_guest_kernel()  — checks BTF, LSM, and cgroup v2 availability
  pub fn load_policy()         — loads and attaches BPF programs; returns GuestEbpfLoader
  pub fn detach()              — unloads all programs before VM shutdown

bpf/guest_policy.bpf.c    — BPF bytecode (compiled by cargo xtask or cargo bpf build)
  or: bpf-programs/src/main.rs  — if using aya-bpf crate for BPF bytecode
```

These stubs must not be added to `src/main.rs` in this scout. #93 owns the
integration point.

---

## Summary

| Capability | Decision | Condition |
|---|---|---|
| CO-RE / BTF in guest kernel | **GO (conditional)** | Guest kernel ≥ 5.2 with `CONFIG_DEBUG_INFO_BTF=y` |
| Quickstart kernel (4.14) as baseline | **BLOCK** | Must replace with kernel ≥ 5.7 before #93 |
| `BPF_PROG_TYPE_TRACEPOINT` | **GO** | Available once BTF kernel is in place |
| `BPF_PROG_TYPE_LSM` | **GO (conditional)** | Requires `CONFIG_BPF_LSM=y` + `lsm=bpf` boot arg |
| `BPF_PROG_TYPE_CGROUP_SKB` | **GO (conditional)** | Requires `CONFIG_CGROUP_BPF=y` + cgroup v2 in guest |
| Preferred loader: Aya (Rust) | **GO** | Aya ≥ 0.13 supports all required types; aligns with Rust codebase |
| libbpf (C) as loader | **NO** | C foreign dependency unjustified given Aya coverage |
| Guest vs host eBPF conflict | **GO (no conflict)** | Firecracker VM isolation prevents cross-kernel BPF visibility |

No production code was changed in this scout.
