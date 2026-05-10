package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	cmd := &cobra.Command{
		Use:   "exec <fork-id> <command> [args...]",
		Short: "Run a command inside a fork with namespace isolation",
		Long: `Execute a command inside a named fork using containerd's task API and crun
as the OCI container runtime. The command runs inside isolated mount and
PID namespaces. Network isolation is optional.

CPU and memory limits are configurable via the OCI spec resource fields.
See docs/scout/phase1-findings.md §2 for crun shim compatibility notes.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "exec: not yet implemented (Phase 3)")
			return nil
		},
	}
	return cmd
}
