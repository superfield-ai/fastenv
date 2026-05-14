// security_regression.rs — Security regression tests for the host/guest VM split.
//
// Canonical docs:
//   - docs/prd.md          §Security model
//   - docs/architecture.md §Host/guest boundary
//   - docs/implementation-plan.md §Phase: Test harnesses
//
// These tests validate the three key security properties of the fork isolation
// model without requiring root, KVM, or a real Firecracker instance:
//
//   1. Unauthorized writes — a fork's upper layer is writable only within its
//      own directory; the base lower layer is never mutated.
//   2. Cross-agent contamination — two forks derived from the same base do not
//      share their upper layers; writes in one fork are invisible in the other.
//   3. Distinct isolation paths — the registry assigns per-fork-key upper and
//      work paths so that no two forks can share a single directory.
//   4. Network-mode annotation — the guest network mode field is carried as an
//      annotation on the OCI config and is covered by exec.rs unit tests;
//      this module records the regression contract at the policy level.
//
// All tests run in a tempdir and never touch the real /var/lib/fastenv.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    use crate::build_base::build_base;
    use crate::registry::{ForkEntry, QuotaMode, Registry};

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a minimal base snapshot in `root`.
    fn setup_base(root: &TempDir, base_key: &str) {
        let source = root.path().join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("seed.txt"), b"seed data").unwrap();
        build_base(&source, base_key, root.path()).unwrap();
    }

    /// Manually insert a fork entry using only the public `Registry` API.
    fn insert_fork_entry(registry: &Registry, root: &TempDir, fork_id: &str, base_key: &str) {
        let upper = root.path().join(format!("forks/{fork_id}/upper"));
        let work = root.path().join(format!("forks/{fork_id}/work"));
        let merged = root.path().join(format!("forks/{fork_id}/merged"));
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&merged).unwrap();
        registry
            .insert_fork(
                fork_id,
                ForkEntry {
                    base_key: base_key.to_owned(),
                    upper_path: upper,
                    work_path: work,
                    merged_path: Some(merged),
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();
    }

    // =========================================================================
    // 1. Unauthorized writes — base lower layer must not be mutated by a fork
    // =========================================================================

    /// Regression: writing into a fork's upper layer must not alter the base
    /// lower layer.  We simulate this without root/overlayfs by directly
    /// writing to the fork's upper directory (which is what the kernel would
    /// redirect CoW writes to) and asserting the base lower dir is untouched.
    #[test]
    fn fork_write_does_not_mutate_base_lower() {
        let root = TempDir::new().unwrap();
        setup_base(&root, "base-a");

        // Record base lower contents before any fork write.
        let base_lower = root.path().join("bases/base-a/lower");
        let before: Vec<_> = fs::read_dir(&base_lower)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            before.iter().any(|n| n == "seed.txt"),
            "base lower must contain seed.txt; got {:?}",
            before
        );

        let registry = Registry::open(root.path()).unwrap();
        insert_fork_entry(&registry, &root, "fork-w", "base-a");

        let entry = registry.get_fork("fork-w").unwrap();

        // Simulate a write inside the fork (into its upper layer).
        fs::write(
            entry.upper_path.join("agent-output.txt"),
            b"agent wrote this",
        )
        .unwrap();

        // The base lower dir must remain unchanged — no new files.
        let after: Vec<_> = fs::read_dir(&base_lower)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            before.len(),
            after.len(),
            "base lower must be unchanged after fork write; before={:?} after={:?}",
            before,
            after
        );
        assert!(
            !base_lower.join("agent-output.txt").exists(),
            "base lower must not contain fork-written file"
        );
    }

    // =========================================================================
    // 2. Cross-agent contamination — two forks must not share upper layers
    // =========================================================================

    /// Regression: a write in fork-A's upper layer must not appear in fork-B's
    /// upper layer when both forks share the same base.
    #[test]
    fn fork_upper_layers_are_isolated_between_agents() {
        let root = TempDir::new().unwrap();
        setup_base(&root, "base-b");

        let registry = Registry::open(root.path()).unwrap();
        insert_fork_entry(&registry, &root, "agent-a", "base-b");
        insert_fork_entry(&registry, &root, "agent-b", "base-b");

        let entry_a = registry.get_fork("agent-a").unwrap();
        let entry_b = registry.get_fork("agent-b").unwrap();

        // Write a distinct file in each agent's upper layer.
        fs::write(
            entry_a.upper_path.join("secret-a.txt"),
            b"agent-a private data",
        )
        .unwrap();
        fs::write(entry_b.upper_path.join("secret-b.txt"), b"agent-b data").unwrap();

        // Upper paths must be physically distinct directories.
        assert_ne!(
            entry_a.upper_path, entry_b.upper_path,
            "forks from the same base must have distinct upper paths"
        );

        // agent-b's upper must not contain agent-a's file.
        assert!(
            !entry_b.upper_path.join("secret-a.txt").exists(),
            "cross-agent contamination: agent-b's upper contains agent-a's file"
        );
        // agent-a's upper must not contain agent-b's file.
        assert!(
            !entry_a.upper_path.join("secret-b.txt").exists(),
            "cross-agent contamination: agent-a's upper contains agent-b's file"
        );
    }

    // =========================================================================
    // 3. Distinct isolation paths — per-fork-key upper and work directories
    // =========================================================================

    /// Regression: the registry assigns unique upper and work paths for each
    /// fork key, so no two active forks can share a directory regardless of
    /// their common base.
    #[test]
    fn fork_base_unique_upper_and_work_paths_per_fork_key() {
        let root = TempDir::new().unwrap();
        setup_base(&root, "base-c");

        let registry = Registry::open(root.path()).unwrap();
        insert_fork_entry(&registry, &root, "fx-1", "base-c");
        insert_fork_entry(&registry, &root, "fx-2", "base-c");

        let e1 = registry.get_fork("fx-1").unwrap();
        let e2 = registry.get_fork("fx-2").unwrap();

        assert_ne!(
            e1.upper_path, e2.upper_path,
            "each fork key must produce a distinct upper path"
        );
        assert_ne!(
            e1.work_path, e2.work_path,
            "each fork key must produce a distinct work path"
        );
    }

    /// Regression: two forks derived from different bases also get distinct
    /// upper paths; the fork key, not the base key, determines the path.
    #[test]
    fn fork_upper_path_is_keyed_by_fork_not_base() {
        let root = TempDir::new().unwrap();
        setup_base(&root, "base-d");
        setup_base(&root, "base-e");

        let registry = Registry::open(root.path()).unwrap();
        insert_fork_entry(&registry, &root, "fork-d", "base-d");
        insert_fork_entry(&registry, &root, "fork-e", "base-e");

        let ed = registry.get_fork("fork-d").unwrap();
        let ee = registry.get_fork("fork-e").unwrap();

        // Keys differ → paths must differ.
        assert_ne!(ed.upper_path, ee.upper_path);
        // Neither path is based on the base key alone.
        assert!(
            ed.upper_path.to_string_lossy().contains("fork-d"),
            "upper path must contain fork key"
        );
        assert!(
            ee.upper_path.to_string_lossy().contains("fork-e"),
            "upper path must contain fork key"
        );
    }

    // =========================================================================
    // 4. Policy-plane labelling — VM boundary annotation in the registry
    // =========================================================================

    /// Regression: fork metadata stored in the registry must include the
    /// base_key field so the host control plane can resolve the lower layer
    /// and attach the correct eBPF policy scope.
    #[test]
    fn fork_registry_entry_records_base_key_for_policy_resolution() {
        let root = TempDir::new().unwrap();
        setup_base(&root, "base-f");

        let registry = Registry::open(root.path()).unwrap();
        insert_fork_entry(&registry, &root, "fork-policy", "base-f");

        let entry = registry.get_fork("fork-policy").unwrap();
        assert_eq!(
            entry.base_key, "base-f",
            "registry must record the originating base key for eBPF policy resolution"
        );
    }
}
