// Package cmd implements the fastenv CLI using cobra.
//
// Root command registers all subcommands and wires global flags including the
// containerd socket path and namespace. Subcommand implementations live in
// their own files within this package.
//
// Canonical docs:
//   - docs/architecture.md §2 (cobra as CLI framework)
//   - docs/implementation-plan.md Phase 1 (scaffold)
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
)

// rootCmd is the base command that all subcommands are attached to.
var rootCmd = &cobra.Command{
	Use:   "fastenv",
	Short: "OCI-native copy-on-write workspace forking for AI agents",
	Long: `fastenv creates isolated writable snapshot layers on top of a shared
immutable base image using containerd's snapshot API. Agent workspaces
(forks) are created in ≤100ms p95 with near-zero marginal disk cost.

Complete documentation: https://github.com/superfield-ai/fastenv`,
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
