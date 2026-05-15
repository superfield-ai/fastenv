// fastenv — OCI-native copy-on-write workspace forking for AI agent orchestration.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md

// parity_check references crate::Cli so it must be declared in main.rs.
pub mod parity_check;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fastenv::{bench, boundary, exec, gc, quota};
use std::path::PathBuf;

use boundary::{GuestRuntime, HostControlPlane, LocalHostControlPlane};
use exec::GuestNetworkMode;

/// OCI-native copy-on-write workspace forking for AI agent orchestration.
#[derive(Parser)]
#[command(name = "fastenv", version, about, long_about = None)]
struct Cli {
    /// fastenv data root directory (default: /var/lib/fastenv).
    #[arg(long, global = true, default_value = "/var/lib/fastenv")]
    root: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and register a base snapshot from a local directory.
    BuildBase {
        /// Path to the source directory to package as a base.
        dir: PathBuf,
        /// Registry key for the new base (e.g. "ubuntu-22").
        #[arg(long)]
        name: String,
    },
    /// Fork a new writable workspace from the named base snapshot.
    Fork {
        /// Name of the base snapshot to fork from.
        #[arg(long)]
        base: String,
        /// Unique identifier for the new fork.
        #[arg(long)]
        name: String,
        /// Maximum writable disk quota for this fork's upper layer.
        /// Accepts human-readable sizes: 512B, 10KiB, 1MiB, 2GiB, etc.
        /// On prjquota filesystems, hard quota is enforced by the kernel.
        /// On other filesystems, quota is tracked in soft mode (warn-only via `du`).
        #[arg(long)]
        quota: Option<String>,
    },
    /// Discard a fork and release its snapshot resources.
    Discard {
        /// Fork identifier to discard
        fork_id: String,
    },
    /// Execute a command inside a fork's container environment.
    Exec {
        /// Fork identifier to run inside
        fork_id: String,
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, num_args = 1..)]
        command: Vec<String>,
        /// Path to the crun binary
        #[arg(long, default_value = "/usr/bin/crun")]
        crun_path: String,
        /// CPU constraint: integer → cpu_shares, string with '-' or ',' → cpuset
        #[arg(long)]
        cpu: Option<String>,
        /// Memory limit in bytes (e.g. 67108864 for 64 MiB)
        #[arg(long)]
        memory: Option<u64>,
        /// Guest network mode inside the VM.
        #[arg(long, value_enum, default_value_t = GuestNetworkMode::Host)]
        network: GuestNetworkMode,
    },
    /// Show a unified diff of changes made inside a fork.
    Diff {
        /// Fork identifier to diff
        fork_id: String,
    },
    /// Report disk usage of a fork's upper (writable) layer.
    Du {
        /// Fork identifier to inspect
        fork_id: String,
    },
    /// Export a fork's changes as a patch archive.
    ExportPatch {
        /// Fork identifier to export
        fork_id: String,
        /// Write tar to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Garbage-collect stale or orphaned forks and snapshots.
    Gc {
        /// Maximum age of a fork before it is evicted (e.g. "24h", "30m", "0s").
        /// Forks older than this value are eviction candidates.
        /// Default: "24h".
        #[arg(long, default_value = "24h")]
        max_age: String,
        /// Maximum number of forks to retain.  When the live count exceeds this,
        /// the oldest forks are evicted first.
        #[arg(long)]
        max_forks: Option<usize>,
        /// Print eviction candidates without performing any removals.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Print the host mount path for an active fork's overlayfs.
    MountPath {
        /// Fork identifier
        fork_id: String,
    },
    /// Unmount the overlayfs for an active fork.
    Unmount {
        /// Fork identifier to unmount
        fork_id: String,
    },
    /// Run a performance benchmark against core fastenv operations.
    Bench {
        /// Base snapshot name to fork from (required).
        #[arg(long)]
        base: String,
        /// Number of fork+discard iterations to run.
        #[arg(long, default_value = "100")]
        iterations: u32,
        /// Also measure exec start latency (runs exec /bin/true for each iteration).
        #[arg(long)]
        exec: bool,
        /// Measure VM-tier latencies: Firecracker boot time, crun container
        /// startup inside the VM, and eBPF overhead per layer.
        /// Requires KVM access (/dev/kvm); VM tiers are skipped gracefully
        /// when KVM is unavailable.
        /// Also enabled by setting the environment variable FASTENV_BENCH_VM=1.
        #[arg(long)]
        vm: bool,
    },
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let host = LocalHostControlPlane::new();
    let guest = host.guest();

    match cli.command {
        Commands::BuildBase { dir, name } => {
            guest.build_base(&dir, &name, &cli.root)?;
        }
        Commands::Fork { base, name, quota } => {
            let quota_bytes = quota.as_deref().map(quota::parse_quota_size).transpose()?;
            guest.fork_base(&base, &name, &cli.root, quota_bytes)?;
        }
        Commands::Discard { fork_id } => {
            guest.discard_fork(&fork_id, &cli.root)?;
        }
        Commands::Exec {
            fork_id,
            command,
            crun_path,
            cpu,
            memory,
            network,
        } => {
            let cpu_spec = cpu.as_deref().map(exec::parse_cpu_spec).transpose()?;
            let opts = exec::ExecOptions {
                crun_path,
                cpu: cpu_spec,
                memory,
                network,
                secret_leases: Vec::new(),
            };
            let exit_code = guest.run_exec(&fork_id, &command, &cli.root, &opts)?;
            std::process::exit(exit_code);
        }
        Commands::Diff { fork_id } => {
            guest.diff_fork(&fork_id, &cli.root)?;
        }
        Commands::Du { fork_id } => {
            guest.du_fork(&fork_id, &cli.root)?;
        }
        Commands::ExportPatch { fork_id, output } => {
            guest.export_patch(&fork_id, &cli.root, output.as_deref())?;
        }
        Commands::Gc {
            max_age,
            max_forks,
            dry_run,
        } => {
            let max_age_duration = gc::parse_duration(&max_age)
                .with_context(|| format!("invalid --max-age value: '{}'", max_age))?;
            let opts = gc::GcOptions {
                max_age: Some(max_age_duration),
                max_forks,
                dry_run,
            };
            guest.run_gc(&cli.root, &opts)?;
        }
        Commands::MountPath { fork_id } => {
            tracing::warn!(
                command = "mount-path",
                fork_id = %fork_id,
                boundary = "boundary::GuestRuntime",
                "deprecated CLI entrypoint; use the explicit host/guest boundary"
            );
            guest.mount_path(&fork_id, &cli.root)?;
        }
        Commands::Unmount { fork_id } => {
            tracing::warn!(
                command = "unmount",
                fork_id = %fork_id,
                boundary = "boundary::GuestRuntime",
                "deprecated CLI entrypoint; use the explicit host/guest boundary"
            );
            guest.unmount_fork(&fork_id, &cli.root)?;
        }
        Commands::Bench {
            base,
            iterations,
            exec,
            vm,
        } => {
            let result = guest.run_bench(
                &base,
                &cli.root,
                &bench::BenchOptions {
                    iterations,
                    measure_exec: exec,
                    measure_vm: vm,
                },
            )?;
            let json = serde_json::to_string_pretty(&result).context("serialize bench result")?;
            println!("{json}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli_build_base() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn all_subcommands_present() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let subcommands: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        let expected = [
            "build-base",
            "fork",
            "discard",
            "exec",
            "diff",
            "du",
            "export-patch",
            "gc",
            "mount-path",
            "unmount",
            "bench",
        ];
        for name in &expected {
            assert!(
                subcommands.contains(name),
                "subcommand '{}' is missing from CLI",
                name
            );
        }
        assert_eq!(
            subcommands.len(),
            expected.len(),
            "unexpected number of subcommands: {:?}",
            subcommands
        );
    }
}
