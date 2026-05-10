// exec.go — cobra command for `fastenv exec`.
//
// exec runs a user-supplied command inside an existing fork's isolated mount
// and PID namespaces using containerd's task API and crun as the OCI runtime.
// All heavy lifting is delegated to [internal/execer.Exec], which handles
// container creation, task lifecycle, stdio streaming, and cleanup. This file
// handles CLI argument parsing, flag wiring, structured JSON output, and exit
// code propagation.
//
// # Usage
//
//	fastenv exec <fork-id> -- <cmd> [args...]
//
// # Design
//
// The fork identified by <fork-id> must already exist (created by
// `fastenv fork`). The command runs as PID 1 inside isolated mount and PID
// namespaces; writes land in the fork's overlayfs upper layer and are visible
// via `fastenv diff`. The base image is not affected.
//
// Network isolation is controlled by --network:
//   - --network=none (default): a new network namespace with only loopback is
//     created. No CNI plugin or external binary is required.
//   - --network=host: shares the host network namespace.
//
// On completion a structured JSON log line is written to stdout:
//
//	{"fork_id":"...","command":[...],"exit_code":0,"duration":"...","network_mode":"none"}
//
// The process exits with the same exit code as the inner command.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 3 (exec)
//   - docs/architecture.md §2 (containerd task API)
//   - docs/scout/phase1-findings.md §2 (crun integration path)
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/execer"
)

// newExecCmd returns the cobra command for the exec subcommand.
//
// exec runs a command inside a fork with isolated mount and PID namespaces
// and configurable CPU/memory limits via crun through containerd's task API.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 3 (exec)
//   - docs/scout/phase1-findings.md §2 (crun integration path)
func newExecCmd() *cobra.Command {
	var (
		cpuShares   uint64
		memoryLimit string
		crunPath    string
		workDir     string
		envVars     []string
		networkMode string
	)

	cmd := &cobra.Command{
		Use:   "exec <fork-id> -- <command> [args...]",
		Short: "Run a command inside a fork with namespace isolation",
		Long: `Execute a command inside a named fork using containerd's task API and crun
as the OCI container runtime. The command runs inside isolated mount and
PID namespaces with the fork's writable overlay as the root filesystem.

Writes made by the command appear in 'fastenv diff <fork-id>' output and
do not affect the base image.

CPU and memory limits are configurable via --cpu and --memory flags.
See docs/scout/phase1-findings.md §2 for crun shim compatibility notes.

On completion a structured JSON log line is written to stdout:
  {"fork_id":"...","command":[...],"exit_code":0,"duration":"..."}

The process exits with the same exit code as the inner command.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkID := args[0]
			command := args[1:]

			// Parse memory limit string (e.g. "512m", "1g", "1073741824").
			memBytes, err := parseMemory(memoryLimit)
			if err != nil {
				return fmt.Errorf("exec: --memory: %w", err)
			}

			result, err := execer.Exec(cmd.Context(), forkID, command, execer.Options{
				SocketPath:       containerdSocket,
				Namespace:        containerdNamespace,
				CrunPath:         crunPath,
				CPUShares:        cpuShares,
				MemoryLimitBytes: uint64(memBytes),
				WorkDir:          workDir,
				Env:              envVars,
				Network:          execer.NetworkMode(networkMode),
			})
			if err != nil {
				return fmt.Errorf("exec: %w", err)
			}

			// Emit structured JSON log line to stdout per acceptance criteria.
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			if err := enc.Encode(result); err != nil {
				return fmt.Errorf("encode result: %w", err)
			}

			// Propagate the inner command's exit code.
			if result.ExitCode != 0 {
				os.Exit(result.ExitCode)
			}
			return nil
		},
	}

	cmd.Flags().Uint64Var(&cpuShares, "cpu", 0,
		"CPU shares (relative weight, 0 = unlimited)")
	cmd.Flags().StringVar(&memoryLimit, "memory", "",
		"memory limit (e.g. 512m, 1g, or bytes; empty = unlimited)")
	cmd.Flags().StringVar(&crunPath, "crun-path", "/usr/bin/crun",
		"absolute path to the crun binary")
	cmd.Flags().StringVar(&workDir, "workdir", "/",
		"working directory inside the container")
	cmd.Flags().StringArrayVarP(&envVars, "env", "e", nil,
		"set environment variable KEY=VALUE (can be repeated)")
	cmd.Flags().StringVar(&networkMode, "network", string(execer.NetworkNone),
		`network mode: "none" (isolated loopback-only netns, default) or "host" (share host network)`)

	return cmd
}

// parseMemory converts a human-readable memory string to bytes.
//
// Supported suffixes: b/B, k/K, m/M, g/G (binary: ×1024).
// An empty string returns 0 (no limit).
// A plain integer string is treated as bytes.
func parseMemory(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	multiplier := int64(1)
	digits := s
	if len(s) > 0 {
		suffix := s[len(s)-1]
		switch suffix {
		case 'b', 'B':
			digits = s[:len(s)-1]
		case 'k', 'K':
			multiplier = 1024
			digits = s[:len(s)-1]
		case 'm', 'M':
			multiplier = 1024 * 1024
			digits = s[:len(s)-1]
		case 'g', 'G':
			multiplier = 1024 * 1024 * 1024
			digits = s[:len(s)-1]
		}
	}

	var n int64
	if _, err := fmt.Sscanf(digits, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid memory value %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("memory value must be non-negative, got %q", s)
	}
	return n * multiplier, nil
}
