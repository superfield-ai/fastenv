# Disk Quota Prerequisites

`fastenv fork --quota` supports two enforcement modes:

| Mode | Host requirement | Behaviour |
|------|-----------------|-----------|
| **soft** | none (default) | Usage is measured. `fastenv du` emits a warning when usage exceeds the limit. Writes are never rejected. |
| **hard** | ext4 or xfs with `prjquota` | Writes exceeding the quota fail immediately with `EDQUOT` (errno 122). Enforced by the kernel. |

## How mode is selected

At `fastenv fork` time, fastenv probes `/proc/mounts` for the `prjquota` mount
option on the device that hosts the containerd snapshot root
(`/var/lib/containerd` by default). If `prjquota` is found, **hard** mode is
selected and recorded in the JSON output. Otherwise **soft** mode is used.

The mode is logged as a structured field:

```json
{"fork_id":"agent-1","base_image":"my-workspace","snapshot_key":"agent-1",
 "creation_latency":"3.2ms","quota_bytes":10485760,"quota_mode":"hard"}
```

## Enabling hard quota enforcement (ext4)

1. Ensure your containerd data partition is formatted as ext4. Check with:

   ```bash
   df -T /var/lib/containerd
   ```

2. Add the `prjquota` option to `/etc/fstab` for that partition:

   ```
   /dev/sdX  /var/lib/containerd  ext4  defaults,prjquota  0 2
   ```

3. Remount the filesystem:

   ```bash
   sudo mount -o remount,prjquota /var/lib/containerd
   ```

4. Initialise quota accounting:

   ```bash
   sudo quotacheck -Pug /var/lib/containerd
   sudo quotaon -P /var/lib/containerd
   ```

5. Verify:

   ```bash
   sudo repquota -Ps /var/lib/containerd
   ```

## Enabling hard quota enforcement (xfs)

XFS includes project quota support in its default kernel module. Mount with
`prjquota`:

```
/dev/sdX  /var/lib/containerd  xfs  defaults,prjquota  0 2
```

Then remount:

```bash
sudo mount -o remount,prjquota /var/lib/containerd
```

## Soft mode — no host changes needed

If the prerequisites above are not met, fastenv operates in **soft mode**
transparently. Writes are never rejected. Run `fastenv du <fork-id>` after
each operation to check whether the quota has been exceeded:

```bash
fastenv fork --base my-workspace --name agent-1 --quota 10MiB
# ... agent writes files ...
fastenv du agent-1
# → {"fork_id":"agent-1","usage_bytes":12582912,"usage_human":"12.0 MiB"}
# stderr: {"level":"warn","fork_id":"agent-1","usage_bytes":12582912,"quota_bytes":10485760,"overage_bytes":2097152}
```

## Canonical docs

- [Architecture §5 OD-4](architecture.md)
- [PRD](prd.md)
- [Implementation plan Phase 5](implementation-plan.md)
