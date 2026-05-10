// Package execer runs a command inside a fork's isolated namespace via
// containerd's task API and crun as the OCI runtime.
//
// # Design
//
// The exec lifecycle follows the containerd task API:
//  1. Dial containerd and scope to the fastenv namespace.
//  2. Create a container object that references the fork's writable overlayfs
//     snapshot. This does not start a process.
//  3. Build an OCI spec: isolated mount and PID namespaces, the user's command
//     as the process args, and optional CPU/memory resource limits.
//  4. Create a task (shim fork + crun init) and stream stdio to the caller's
//     terminal via cio.NewCreator(cio.WithStdio).
//  5. Start the task — crun execs the user command as PID 1 in the namespace.
//  6. Wait for the task to exit; capture the exit status.
//  7. Delete the task (cleans up the shim and cgroups; the snapshot is NOT
//     removed — snapshot lifetime is managed separately via fastenv discard).
//  8. Delete the container object.
//  9. Emit a structured JSON log line: fork ID, command, exit code, duration.
//
// The container object and task are ephemeral; they exist only for the
// duration of the exec invocation. The fork's snapshot is preserved so
// subsequent writes (diff, export-patch) remain accessible.
//
// # Resource limits
//
// CPU limits are expressed as CPU shares (relative weight) when --cpu is given
// as an integer, or as a cpuset string (e.g. "0-1") when it contains a hyphen
// or comma. Memory limits are in bytes passed via --memory.
//
// # crun path
//
// The default crun binary path is /usr/bin/crun. Override via --crun-path.
// See docs/scout/phase1-findings.md §2 for crun/shim compatibility notes.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md Phase 3 (exec)
//   - docs/scout/phase1-findings.md §2 (crun integration path)
package execer

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	runcOptions "github.com/containerd/containerd/api/types/runc/options"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second

	// defaultCrunPath is the standard crun binary path on most Linux distros.
	// Override via Options.CrunPath.
	defaultCrunPath = "/usr/bin/crun"
)

// Options controls Exec behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
	// CrunPath is the absolute path to the crun binary.
	// Defaults to /usr/bin/crun if empty.
	CrunPath string
	// CPUShares sets the OCI spec linux.resources.cpu.shares.
	// Zero means no limit.
	CPUShares uint64
	// MemoryLimitBytes sets the OCI spec linux.resources.memory.limit.
	// Zero means no limit.
	MemoryLimitBytes uint64
	// WorkDir is the working directory inside the container.
	// Defaults to "/" if empty.
	WorkDir string
	// Env is a list of additional environment variables (KEY=VALUE) to pass.
	Env []string
}

// ExecResult holds metadata about the completed exec, emitted as a structured
// JSON log line upon completion.
type ExecResult struct {
	// ForkID is the fork that the command ran inside.
	ForkID string `json:"fork_id"`
	// Command is the command and arguments that were executed.
	Command []string `json:"command"`
	// ExitCode is the exit code of the inner command.
	ExitCode int `json:"exit_code"`
	// Duration is the wall-clock time from task start to exit.
	Duration string `json:"duration"`
}

// Exec runs cmd inside the named fork's isolated mount and PID namespaces.
//
// The fork snapshot identified by forkID must already exist (created by
// fastenv fork). The function streams the command's stdout and stderr directly
// to os.Stdout / os.Stderr. It returns an ExecResult with the exit code and
// duration on success (including non-zero exit codes from the inner command).
//
// The fork's snapshot is NOT removed — it remains available for diff, gc, etc.
func Exec(ctx context.Context, forkID string, cmd []string, opts Options) (*ExecResult, error) {
	if opts.SocketPath == "" {
		opts.SocketPath = "/run/containerd/containerd.sock"
	}
	if opts.Namespace == "" {
		opts.Namespace = "fastenv"
	}
	if opts.CrunPath == "" {
		opts.CrunPath = defaultCrunPath
	}
	if opts.WorkDir == "" {
		opts.WorkDir = "/"
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("exec: command must not be empty")
	}

	client, err := containerd.New(opts.SocketPath,
		containerd.WithDefaultNamespace(opts.Namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("exec: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)

	// Container ID must be unique per invocation.  We derive it from the fork
	// ID and a nanosecond timestamp to avoid collisions when the same fork is
	// exec'd concurrently.
	containerID := fmt.Sprintf("%s-exec-%d", forkID, time.Now().UnixNano())

	// Build OCI spec options.
	specOpts := buildSpecOpts(cmd, opts)

	// Step 1: Create the container object.  This is a lightweight metadata
	// record in containerd; it references the fork's active snapshot and the
	// OCI spec.  No process is started yet.
	container, err := client.NewContainer(ctx, containerID,
		containerd.WithSnapshotter("overlayfs"),
		containerd.WithSnapshot(forkID),
		containerd.WithRuntime(defaults.DefaultRuntime,
			&runcOptions.Options{BinaryName: opts.CrunPath},
		),
		containerd.WithNewSpec(specOpts...),
	)
	if err != nil {
		return nil, fmt.Errorf("exec: create container for fork %q: %w", forkID, err)
	}
	defer func() {
		// Best-effort cleanup: remove the ephemeral container metadata record.
		// The snapshot (forkID) is preserved.
		_ = container.Delete(ctx)
	}()

	// Step 2: Create a task.  This forks the containerd shim and crun binary,
	// sets up namespaces and cgroups, but does NOT exec the user command yet.
	// cio.NewCreator(cio.WithStdio) wires the container's stdio to the current
	// process's stdin/stdout/stderr, satisfying the "stream to terminal" req.
	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return nil, fmt.Errorf("exec: create task for fork %q: %w", forkID, err)
	}

	// Register a Wait channel before Start to avoid a race where the task
	// exits before we call Wait.
	exitCh, err := task.Wait(ctx)
	if err != nil {
		_, _ = task.Delete(ctx)
		return nil, fmt.Errorf("exec: register wait for fork %q: %w", forkID, err)
	}

	// Step 3: Start the task — crun execs the user command as PID 1.
	start := time.Now()
	if err := task.Start(ctx); err != nil {
		_, _ = task.Delete(ctx)
		return nil, fmt.Errorf("exec: start task for fork %q: %w", forkID, err)
	}

	// Step 4: Block until the command exits.
	exitStatus := <-exitCh
	duration := time.Since(start)

	// Step 5: Delete the task to clean up the shim and cgroup resources.
	// This is separate from snapshot cleanup.
	if _, delErr := task.Delete(ctx); delErr != nil {
		// Log but do not fail — the task has already exited.
		fmt.Fprintf(os.Stderr, "exec: warning: task delete for fork %q: %v\n", forkID, delErr)
	}

	// exitStatus.Error() is non-nil only for infrastructure errors, not for
	// non-zero exit codes from the process itself.
	if err := exitStatus.Error(); err != nil {
		return nil, fmt.Errorf("exec: wait error for fork %q: %w", forkID, err)
	}

	return &ExecResult{
		ForkID:   forkID,
		Command:  cmd,
		ExitCode: int(exitStatus.ExitCode()),
		Duration: duration.Round(time.Millisecond).String(),
	}, nil
}

// buildSpecOpts constructs the OCI SpecOpts slice from cmd and Options.
//
// The spec uses isolated mount and PID namespaces as required by the issue.
// Network is shared with the host (no --network=none flag in v1) to allow
// the exec'd command to reach the network as an AI agent would expect.
// User namespace is omitted to keep v1 simple (requires root / CAP_SYS_ADMIN).
func buildSpecOpts(cmd []string, opts Options) []oci.SpecOpts {
	sopts := []oci.SpecOpts{
		// Isolated mount namespace: the fork's overlayfs is the rootfs.
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.MountNamespace}),
		// Isolated PID namespace: the exec'd command is PID 1 inside.
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.PIDNamespace}),
		// Process args: the user command.
		oci.WithProcessArgs(cmd...),
		// Working directory inside the container.
		oci.WithProcessCwd(opts.WorkDir),
	}

	// Default PATH so simple commands (pytest, bash, python) resolve without
	// a fully-qualified path.
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	env = append(env, opts.Env...)
	sopts = append(sopts, oci.WithEnv(env))

	// Resource limits — only add the spec option when a limit is set.
	if opts.MemoryLimitBytes > 0 {
		sopts = append(sopts, oci.WithMemoryLimit(opts.MemoryLimitBytes))
	}
	if opts.CPUShares > 0 {
		cpuStr := fmt.Sprintf("%d", opts.CPUShares)
		if strings.ContainsAny(cpuStr, "-,") {
			// Treat as cpuset if it contains hyphen or comma (e.g. "0-3").
			sopts = append(sopts, oci.WithCPUs(cpuStr))
		} else {
			sopts = append(sopts, oci.WithCPUShares(opts.CPUShares))
		}
	}

	return sopts
}
