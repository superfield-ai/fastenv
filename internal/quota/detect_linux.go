// detect_linux.go — Linux-specific project quota detection via /proc/mounts.
//
// Project quota detection reads /proc/mounts to find the mount entry for the
// given device number and checks whether the mount options include "prjquota"
// or "quota" (the equivalent option on some kernels/tools). This avoids the
// quotactl syscall which requires CAP_SYS_ADMIN and is not portable across
// filesystem types.
//
// # Canonical docs
//
//   - docs/quota-prerequisites.md (host filesystem prerequisites)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
package quota

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// hasProjectQuotas returns true if the block device identified by devNum is
// mounted with the "prjquota" or "grpquota" option in /proc/mounts.
//
// devNum is the st_dev field from syscall.Stat_t (major:minor encoded as uint64).
func hasProjectQuotas(devNum uint64) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// /proc/mounts format: device mountpoint fstype options dump pass
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device := fields[0]
		opts := fields[3]

		// Resolve the device path to its dev number.
		mountDevNum, err := deviceNumber(device)
		if err != nil {
			continue
		}
		if mountDevNum != devNum {
			continue
		}

		// Check for prjquota in the mount options.
		for _, opt := range strings.Split(opts, ",") {
			if opt == "prjquota" {
				return true
			}
		}
	}
	return false
}

// deviceNumber returns the st_dev value for a block device path.
// It follows symlinks and returns the device number of the actual file.
func deviceNumber(device string) (uint64, error) {
	// For non-device entries like "tmpfs", "proc", etc. stat will fail.
	var st syscall.Stat_t
	if err := syscall.Stat(device, &st); err != nil {
		// Try interpreting as major:minor (e.g. "8:1")
		if idx := strings.IndexByte(device, ':'); idx >= 0 {
			major, err1 := strconv.ParseUint(device[:idx], 10, 32)
			minor, err2 := strconv.ParseUint(device[idx+1:], 10, 32)
			if err1 == nil && err2 == nil {
				return mkdev(uint32(major), uint32(minor)), nil
			}
		}
		return 0, fmt.Errorf("stat %q: %w", device, err)
	}
	// For block device files, Rdev is the device they represent.
	// For regular files (bind mounts, loop devices), Dev is the host device.
	if st.Mode&syscall.S_IFMT == syscall.S_IFBLK {
		return st.Rdev, nil
	}
	return st.Dev, nil
}

// mkdev builds a Linux device number from major and minor components.
// Matches the kernel's MKDEV macro: ((major << 8) | minor) for simple cases.
func mkdev(major, minor uint32) uint64 {
	return (uint64(major) << 8) | uint64(minor)
}
