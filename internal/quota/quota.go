// Package quota implements per-fork disk quota detection and management.
//
// # Quota modes
//
// fastenv supports two quota modes:
//
//   - Soft (all configurations): the --quota flag is accepted by `fastenv fork`
//     and stored as a label on the snapshot. `fastenv du` reads the label, reports
//     current usage, and logs a warning when usage exceeds the quota. No writes are
//     rejected.
//
//   - Hard (ext4/xfs with project quotas): when the host filesystem backing the
//     containerd snapshot root has project quota support enabled, the quota is
//     enforced at the kernel level. Writes that would exceed the quota fail with
//     EDQUOT (errno 122). fastenv detects this capability at fork time and logs the
//     enforcement mode as a structured JSON field.
//
// # Host prerequisites for hard enforcement
//
// Hard enforcement requires the host filesystem to be formatted with project quota
// support and mounted with the prjquota option. See docs/quota-prerequisites.md for
// setup instructions.
//
// # Canonical docs
//
//   - docs/prd.md
//   - docs/architecture.md §5 OD-4 (quota enforcement)
//   - docs/implementation-plan.md Phase 5 (per-fork disk quotas)
//   - docs/quota-prerequisites.md (host filesystem prerequisites)
package quota

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// Mode describes how the quota is enforced for a fork.
type Mode string

const (
	// ModeSoft means quota is measured and a warning is emitted when exceeded,
	// but writes are never rejected. Available on all configurations.
	ModeSoft Mode = "soft"

	// ModeHard means quota is enforced at the kernel level via project quotas.
	// Writes exceeding the quota fail with EDQUOT. Requires ext4 or xfs with
	// prjquota enabled on the filesystem hosting the containerd snapshot root.
	ModeHard Mode = "hard"
)

// LabelKey is the snapshot label used to persist the per-fork quota limit.
// The value is stored as a byte count string (e.g. "10485760" for 10 MiB).
const LabelKey = "fastenv.fork.quota"

// Parse parses a human-readable size string into bytes.
//
// Supported suffixes (case-insensitive): B, KiB, MiB, GiB, TiB, KB, MB, GB, TB.
// A plain integer is interpreted as bytes.
//
//	Parse("10MiB")  // → 10485760, nil
//	Parse("1GiB")   // → 1073741824, nil
//	Parse("512")    // → 512, nil
func Parse(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("quota: empty size string")
	}

	// Table of suffixes in descending length order so "MiB" is matched before "M".
	suffixes := []struct {
		suffix string
		factor int64
	}{
		{"TiB", 1 << 40},
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"TB", 1_000_000_000_000},
		{"GB", 1_000_000_000},
		{"MB", 1_000_000},
		{"KB", 1_000},
		{"B", 1},
	}

	upper := strings.ToUpper(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, strings.ToUpper(sf.suffix)) {
			numStr := s[:len(s)-len(sf.suffix)]
			n, err := strconv.ParseFloat(strings.TrimSpace(numStr), 64)
			if err != nil {
				return 0, fmt.Errorf("quota: invalid size %q: %w", s, err)
			}
			if n < 0 {
				return 0, fmt.Errorf("quota: size must be non-negative, got %q", s)
			}
			return int64(n * float64(sf.factor)), nil
		}
	}

	// Plain integer (bytes).
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("quota: invalid size %q: expected a number with optional suffix (B, KiB, MiB, GiB, TiB)", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("quota: size must be non-negative, got %q", s)
	}
	return n, nil
}

// Format renders bytes as a human-readable string using binary prefixes.
//
//	Format(10485760)   // → "10.0 MiB"
//	Format(1536)       // → "1.5 KiB"
//	Format(42)         // → "42 B"
func Format(bytes int64) string {
	switch {
	case bytes >= 1<<40:
		return fmt.Sprintf("%.1f TiB", float64(bytes)/float64(1<<40))
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// DetectMode probes the filesystem at the given path to determine whether
// project quota enforcement is available.
//
// It performs a QCMD_GETQUOTA quota control syscall. If the filesystem supports
// project quotas and they are enabled, ModeHard is returned. Otherwise ModeSoft
// is returned (no error is returned in the soft case — it is the expected mode
// for most configurations).
//
// path should be a directory on the filesystem to probe (e.g. the containerd
// snapshot root). If path is empty, "/var/lib/containerd" is used.
func DetectMode(path string) Mode {
	if path == "" {
		path = "/var/lib/containerd"
	}

	// Stat the path to get the device number.
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return ModeSoft
	}

	// Check /proc/mounts for the prjquota or usrjquota mount option on this device.
	// This is more portable than the quotactl syscall and works across filesystems.
	if hasProjectQuotas(st.Dev) {
		return ModeHard
	}
	return ModeSoft
}
