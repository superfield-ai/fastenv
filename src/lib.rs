// lib.rs — Library entry point for fastenv.
//
// Exposes internal modules for benchmarks and integration tests.
// The binary entry point is src/main.rs.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md

pub mod bench;
pub mod boundary;
pub mod build_base;
pub mod container_runtime;
pub mod diff;
pub mod discard;
pub mod du;
pub mod e2e_smoke;
pub mod exec;
pub mod export_patch;
pub mod fork;
pub mod gc;
pub mod guest_ebpf;
pub mod guest_harness;
pub mod host_control_plane;
pub mod host_ebpf;
pub mod mount_path;
pub mod privileged_harness;
pub mod quota;
pub mod registry;
pub mod security_regression;

// parity_check is declared in main.rs only because it references crate::Cli.
// It cannot be part of the library crate without moving the Cli struct here.
// See src/parity_check.rs for the Phase 6 parity table.
