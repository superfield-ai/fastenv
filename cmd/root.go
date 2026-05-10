// Package cmd implements the fastenv CLI using cobra.
//
// Root command registers all subcommands and wires global flags including the
// containerd socket path, namespace, snapshotter driver, GC policy flags,
// and log level.
// Subcommand implementations live in their own files within this package.
//
// Structured JSON logging is emitted to stderr for every CLI operation.
// The --log-level flag (default: "info") controls verbosity.
//
// Canonical docs:
//   - docs/architecture.md §2 (cobra as CLI framework)
//   - docs/architecture.md §5 OD-1 (observability tooling)
//   - docs/implementation-plan.md Phase 1 (scaffold), Phase 2 (snapshotter)
//   - docs/implementation-plan.md Phase 6 (GC flags and Observability)
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	// Blank-import driver packages so their init() functions register the
	// drivers with the snapshotter registry before any subcommand runs.
	// New drivers only need to be added here and in their own file.
	_ "github.com/superfield-ai/fastenv/internal/snapshotter"

	"github.com/superfield-ai/fastenv/internal/logger"
)

// Global flags shared across all subcommands.
var (
	// containerdSocket is the path to the containerd gRPC Unix socket.
	// Default matches the standard containerd installation path.
	// Override via --socket flag or CONTAINERD_SOCKET env var.
	containerdSocket string

	// containerdNamespace is the containerd namespace fastenv operates in.
	// Using a dedicated namespace avoids collisions with Docker / CRI containers.
	// See docs/scout/phase1-findings.md §7 (integration point: namespace isolation).
	containerdNamespace string

	// snapshotterName selects the snapshot driver used for all fork and base
	// operations. Must be a driver registered in the snapshotter package.
	// Supported values: overlayfs (default), stargz, nydus.
	// Selecting an unimplemented driver returns a clear error on first use
	// rather than panicking.
	//
	// Canonical docs:
	//   - docs/architecture.md §2 (pluggable snapshotter)
	//   - docs/implementation-plan.md Phase 2 (--snapshotter flag)
	snapshotterName string

	// gcTTL is the maximum age of a fork before it is eligible for TTL-based
	// GC eviction. Applied on every `fastenv fork`, `fastenv discard`, and
	// `fastenv gc` invocation. Default: 24h.
	//
	// Canonical docs:
	//   - docs/architecture.md §5 OD-3 (fork GC scheduling)
	//   - docs/implementation-plan.md Phase 6 (GC)
	gcTTL time.Duration

	// gcMaxDisk is the total writable-layer disk budget in bytes. When total
	// usage across all forks exceeds this threshold, LRU eviction kicks in.
	// Default: 10 GiB (10737418240 bytes).
	//
	// Canonical docs:
	//   - docs/architecture.md §5 OD-3 (fork GC scheduling)
	//   - docs/implementation-plan.md Phase 6 (GC)
	gcMaxDisk int64

	// logLevelStr is the raw --log-level flag value (debug|info|warn|error).
	// Parsed in rootCmd.PersistentPreRunE and stored as the global log instance.
	logLevelStr string

	// log is the process-wide structured JSON logger, initialized by
	// rootCmd.PersistentPreRunE from the --log-level flag.
	// Subcommands call log.Info / log.Debug / log.Warn / log.Error as needed.
	log *logger.Logger
)

// rootCmd is the base command that all subcommands are attached to.
var rootCmd = &cobra.Command{
	Use:   "fastenv",
	Short: "OCI-native copy-on-write workspace forking for AI agents",
	Long: `fastenv creates isolated writable snapshot layers on top of a shared
immutable base image using containerd's snapshot API. Agent workspaces
(forks) are created in ≤100ms p95 with near-zero marginal disk cost.

Complete documentation: https://github.com/superfield-ai/fastenv`,
	// PersistentPreRunE parses the --log-level flag and initialises the global
	// JSON logger before any subcommand's RunE is called.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		lvl, err := logger.ParseLevel(logLevelStr)
		if err != nil {
			return err
		}
		log = logger.New(lvl, cmd.ErrOrStderr())
		return nil
	},
}

// Execute runs the root command. Called from main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// --socket / CONTAINERD_SOCKET: path to containerd's Unix domain socket.
	// The containerd client dials this socket for all snapshot and image operations.
	// See docs/scout/phase1-findings.md §7 (integration point: socket path).
	rootCmd.PersistentFlags().StringVar(
		&containerdSocket,
		"socket",
		"/run/containerd/containerd.sock",
		"containerd gRPC socket path (env: CONTAINERD_SOCKET)",
	)

	// --namespace: containerd namespace for all fastenv resources.
	// Isolation from Docker/CRI containers requires a separate namespace.
	// See docs/scout/phase1-findings.md §7 (integration point: namespace isolation).
	rootCmd.PersistentFlags().StringVar(
		&containerdNamespace,
		"namespace",
		"fastenv",
		"containerd namespace (env: CONTAINERD_NAMESPACE)",
	)

	// --snapshotter: selects the snapshot driver for fork and base operations.
	// Defaults to "overlayfs" (the only fully implemented driver in v1).
	// Choosing "stargz" or "nydus" will surface a clear ErrNotImplemented
	// error rather than panicking. This satisfies the acceptance criterion:
	//   "Swapping --snapshotter to an unimplemented value returns a clear
	//    error rather than a panic."
	rootCmd.PersistentFlags().StringVar(
		&snapshotterName,
		"snapshotter",
		"overlayfs",
		"snapshot driver to use (overlayfs|stargz|nydus)",
	)

	// --gc-ttl: maximum age of a fork before TTL-based GC eviction.
	// Applied lazily on every fork/discard invocation and explicitly by
	// `fastenv gc`. Zero disables TTL eviction (use DefaultTTL as documented).
	// See docs/architecture.md §5 OD-3 and docs/implementation-plan.md Phase 6.
	rootCmd.PersistentFlags().DurationVar(
		&gcTTL,
		"gc-ttl",
		24*time.Hour,
		"fork TTL: evict forks older than this duration (0 = disabled)",
	)

	// --gc-max-disk: total writable-layer disk budget in bytes. When total
	// usage exceeds this, LRU eviction removes oldest forks until under budget.
	// Default: 10 GiB. See docs/architecture.md §5 OD-3.
	rootCmd.PersistentFlags().Int64Var(
		&gcMaxDisk,
		"gc-max-disk",
		10*1024*1024*1024,
		"LRU disk budget in bytes: evict oldest forks when total usage exceeds this (default 10GiB)",
	)

	// --log-level: controls the minimum severity of structured JSON log lines
	// emitted to stderr. Levels: debug, info (default), warn, error.
	// Each CLI operation emits at least one info-level line on success.
	// See docs/architecture.md §5 OD-1 (observability tooling).
	rootCmd.PersistentFlags().StringVar(
		&logLevelStr,
		"log-level",
		"info",
		"minimum log level for structured JSON stderr output (debug|info|warn|error)",
	)

	// Register all subcommands.
	rootCmd.AddCommand(
		newBuildBaseCmd(),
		newForkCmd(),
		newExecCmd(),
		newDiffCmd(),
		newDuCmd(),
		newExportPatchCmd(),
		newDiscardCmd(),
		newGCCmd(),
		newBenchCmd(),
	)
}
