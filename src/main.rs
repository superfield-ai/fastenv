// fastenv — OCI-native copy-on-write workspace forking for AI agent orchestration.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md

pub mod build_base;
pub mod diff;
pub mod discard;
pub mod du;
pub mod exec;
pub mod fork;
pub mod registry;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
        /// Network mode: 'none' for isolated, 'host' for host networking
        #[arg(long)]
        network: Option<String>,
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
        /// Output path for the patch archive
        output: String,
    },
    /// Garbage-collect stale or orphaned forks and snapshots.
    Gc,
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
        /// Number of iterations
        #[arg(long, default_value = "10")]
        iterations: u32,
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

    match cli.command {
        Commands::BuildBase { dir, name } => {
            build_base::build_base(&dir, &name, &cli.root)?;
        }
        Commands::Fork { base, name } => {
            fork::fork_base(&base, &name, &cli.root)?;
        }
        Commands::Discard { fork_id } => {
            discard::discard_fork(&fork_id, &cli.root)?;
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
            };
            let exit_code = exec::run_exec(&fork_id, &command, &cli.root, &opts)?;
            std::process::exit(exit_code);
        }
        Commands::Diff { fork_id } => {
            diff::diff_fork(&fork_id, &cli.root)?;
        }
        Commands::Du { fork_id } => {
            du::du_fork(&fork_id, &cli.root)?;
        }
        Commands::ExportPatch { fork_id, output } => {
            tracing::info!(command = "export-patch", fork_id = %fork_id, output = %output, "not yet implemented");
        }
        Commands::Gc => {
            tracing::info!(command = "gc", "not yet implemented");
        }
        Commands::MountPath { fork_id } => {
            tracing::info!(command = "mount-path", fork_id = %fork_id, "not yet implemented");
        }
        Commands::Unmount { fork_id } => {
            tracing::info!(command = "unmount", fork_id = %fork_id, "not yet implemented");
        }
        Commands::Bench { iterations } => {
            tracing::info!(command = "bench", iterations, "not yet implemented");
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
