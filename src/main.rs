// fastenv — OCI-native copy-on-write workspace forking for AI agent orchestration.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// This binary provides the Rust CLI skeleton. All subcommand handlers are stubs
// that emit a structured JSON log line and exit 0. Business logic is added in
// subsequent implementation issues.

use anyhow::Result;
use clap::{Parser, Subcommand};

/// OCI-native copy-on-write workspace forking for AI agent orchestration.
#[derive(Parser)]
#[command(name = "fastenv", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and register a base OCI snapshot from an image reference.
    BuildBase {
        /// Image reference (e.g. docker.io/library/ubuntu:22.04)
        image: String,
    },
    /// Fork a new writable workspace from the named base snapshot.
    Fork {
        /// Name of the base snapshot to fork from
        base: String,
        /// Unique identifier for the new fork
        fork_id: String,
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
        Commands::BuildBase { image } => {
            tracing::info!(command = "build-base", image = %image, "not yet implemented");
        }
        Commands::Fork { base, fork_id } => {
            tracing::info!(command = "fork", base = %base, fork_id = %fork_id, "not yet implemented");
        }
        Commands::Discard { fork_id } => {
            tracing::info!(command = "discard", fork_id = %fork_id, "not yet implemented");
        }
        Commands::Exec { fork_id, command } => {
            tracing::info!(command = "exec", fork_id = %fork_id, exec_command = ?command, "not yet implemented");
        }
        Commands::Diff { fork_id } => {
            tracing::info!(command = "diff", fork_id = %fork_id, "not yet implemented");
        }
        Commands::Du { fork_id } => {
            tracing::info!(command = "du", fork_id = %fork_id, "not yet implemented");
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
