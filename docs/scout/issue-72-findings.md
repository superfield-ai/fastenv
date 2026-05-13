# Issue 72 Dev-Scout Findings: Firecracker host/guest eBPF boundary

**Issue:** #72
**Scout date:** 2026-05-13
**Canonical docs:** [docs/prd.md](/home/lucas/tmp/superfield-worktrees/fastenv/feat-72-dev-scout-validate-firecracker-host-guest-ebpf-b/docs/prd.md), [docs/architecture.md](/home/lucas/tmp/superfield-worktrees/fastenv/feat-72-dev-scout-validate-firecracker-host-guest-ebpf-b/docs/architecture.md), [docs/implementation-plan.md](/home/lucas/tmp/superfield-worktrees/fastenv/feat-72-dev-scout-validate-firecracker-host-guest-ebpf-b/docs/implementation-plan.md)
**Firecracker release:** v1.15.1 x86_64
**Guest image:** `hello-rootfs.ext4` + `vmlinux.bin` from the Firecracker quickstart assets

## Host environment

```text
Host kernel: Linux 5.15.0-173-generic
Host binary: Firecracker v1.15.1
Host BPF tooling: raw tracepoint loader via libbpf on the host
```

## Host eBPF placement

Result: PASS

I loaded a host-side raw tracepoint program on `sys_enter` and booted a Firecracker VM. The program counted `852` syscalls from the `firecracker` process during the boot window.

That is enough to confirm:

- the host kernel can load and attach policy at the Firecracker boundary
- Firecracker activity is observable from host eBPF before the guest is started
- the host control plane can place policy in the host kernel without involving the guest

## Guest eBPF placement

Result: FAIL on the quickstart guest kernel

The guest kernel reported by the Firecracker boot log was `Linux 4.14.174`. A minimal guest init attempted to load a `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` policy with `BPF_PROG_LOAD`, but the kernel rejected it with `EINVAL` before any attach.

Observed guest-side outcome:

- `BPF_PROG_LOAD failed: Invalid argument`
- guest init exited
- the guest kernel panicked because PID 1 exited

This means the quickstart guest image is not a valid baseline for the intended guest policy plane. The planned guest eBPF boundary needs a newer guest kernel and/or a different guest image with the required cgroup-BPF support enabled.

## Runtime constraints captured

- Host eBPF at the Firecracker boundary is feasible on the current host kernel.
- The guest kernel shipped in the Firecracker quickstart assets is too old for the desired agent-policy hook.
- The scout should not assume `crun`-level guest policy is available until the guest kernel baseline is upgraded and the policy attach type is revalidated.
- The refactor should treat host and guest kernel capability as separate prerequisites, not one shared eBPF plane.

## Scout conclusion

The host side of the boundary is validated. The guest side is not validated on the current quickstart kernel; the report should be treated as a negative finding that constrains the refactor assumptions.
