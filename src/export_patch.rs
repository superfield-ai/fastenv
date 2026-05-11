// export_patch.rs — `fastenv export-patch <fork-id>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Look up fork_key in the registry (NotFound → non-zero exit).
//  2. Walk forks/<fork-key>/upper/ recursively.
//  3. Append each entry to an uncompressed tar archive, preserving overlayfs
//     whiteout files (char-device 0:0 and ".wh." prefixed files).
//  4. Write the archive to stdout, or to --output <file> if provided.
//  5. Emit one JSON log line on completion: fork_id, patch_size_bytes.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result};

use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Domain errors for the export-patch command.
#[derive(Debug, thiserror::Error)]
pub enum ExportPatchError {
    /// The named fork does not exist in the registry.
    #[error("fork not found: {0}")]
    NotFound(String),
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `export-patch` pipeline.
///
/// * `fork_key`    — key of an existing fork in the registry.
/// * `root`        — fastenv data root (e.g. `/var/lib/fastenv`).
/// * `output_path` — if `Some`, write tar to this file; otherwise write to stdout.
///
/// Writes an uncompressed tar of the fork's `upper/` layer, preserving
/// overlayfs whiteout entries.
pub fn export_patch(fork_key: &str, root: &Path, output_path: Option<&Path>) -> Result<()> {
    let registry = Registry::open(root)?;

    // ── 1. Validate fork exists ───────────────────────────────────────────────
    let fork_entry = registry.get_fork(fork_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", ExportPatchError::NotFound(fork_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    let upper_path = &fork_entry.upper_path;

    // ── 2. Build tar archive ──────────────────────────────────────────────────
    let patch_size_bytes: u64 = match output_path {
        Some(out_file) => {
            let file = fs::File::create(out_file)
                .with_context(|| format!("cannot create output file: {}", out_file.display()))?;
            let mut counter = CountingWriter::new(file);
            append_upper_to_tar(upper_path, &mut counter)?;
            counter.bytes_written()
        }
        None => {
            let stdout = io::stdout();
            let mut counter = CountingWriter::new(stdout.lock());
            append_upper_to_tar(upper_path, &mut counter)?;
            counter.bytes_written()
        }
    };

    // ── 3. Emit completion log line ───────────────────────────────────────────
    tracing::info!(
        command = "export-patch",
        fork_id = fork_key,
        patch_size_bytes = patch_size_bytes,
        "export-patch complete"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tar builder
// ---------------------------------------------------------------------------

/// Append all entries in `upper_path` to an uncompressed tar archive written
/// to `writer`.
///
/// Whiteout files (char-device 0:0 and ".wh."-prefixed files) are included
/// verbatim so the archive carries the full overlayfs delta.
fn append_upper_to_tar<W: io::Write>(upper_path: &Path, writer: W) -> Result<()> {
    let mut archive = tar::Builder::new(writer);
    // Follow symlinks when reading the overlayfs upper layer; this matches
    // the semantics of the merged view visible to processes inside the fork.
    archive.follow_symlinks(false);

    if !upper_path.exists() {
        // upper/ was never created → empty archive.
        archive.finish().context("cannot finalise tar archive")?;
        return Ok(());
    }

    append_dir_recursive(&mut archive, upper_path, upper_path)?;

    archive.finish().context("cannot finalise tar archive")?;
    Ok(())
}

/// Recursively append entries under `dir` to `archive`, computing paths
/// relative to `upper_root`.
fn append_dir_recursive<W: io::Write>(
    archive: &mut tar::Builder<W>,
    dir: &Path,
    upper_root: &Path,
) -> Result<()> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("cannot read directory: {}", dir.display()))?;

    let mut sorted: Vec<_> = entries
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("cannot list directory entries in: {}", dir.display()))?;

    // Deterministic archive order.
    sorted.sort_by_key(|e| e.file_name());

    for entry in sorted {
        let entry_path = entry.path();

        // Relative path from upper root (no leading slash).
        let rel = entry_path
            .strip_prefix(upper_root)
            .expect("entry must be under upper_root");

        let meta = entry
            .metadata()
            .with_context(|| format!("cannot stat: {}", entry_path.display()))?;

        if is_char_whiteout_meta(&meta) {
            // Character-device whiteout: append as a regular tar entry.
            // We cannot use append_file() for a char device, so we build a
            // Header manually and write zero bytes of data.
            let mut header = tar::Header::new_gnu();
            header
                .set_path(rel)
                .with_context(|| format!("cannot set tar path for whiteout: {}", rel.display()))?;
            header.set_size(0);
            header.set_mode(0o000);
            header.set_entry_type(tar::EntryType::Char);
            header.set_device_major(0).context("set device major")?;
            header.set_device_minor(0).context("set device minor")?;
            header.set_cksum();
            archive
                .append(&header, io::empty())
                .with_context(|| format!("cannot append whiteout to tar: {}", rel.display()))?;
        } else if meta.is_dir() {
            // Append the directory entry, then recurse.
            let mut header = tar::Header::new_gnu();
            header
                .set_path(rel)
                .with_context(|| format!("cannot set tar path for dir: {}", rel.display()))?;
            header.set_size(0);
            header.set_mode(if meta.permissions().readonly() {
                0o555
            } else {
                0o755
            });
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            archive
                .append(&header, io::empty())
                .with_context(|| format!("cannot append dir to tar: {}", rel.display()))?;

            append_dir_recursive(archive, &entry_path, upper_root)?;
        } else {
            // Regular file (includes ".wh." prefixed whiteout-marker files).
            archive
                .append_path_with_name(&entry_path, rel)
                .with_context(|| format!("cannot append file to tar: {}", rel.display()))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true when the metadata describes an overlayfs char-device whiteout
/// (major=0, minor=0).
fn is_char_whiteout_meta(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::MetadataExt as _;
    meta.file_type().is_char_device() && meta.rdev() == 0
}

// ---------------------------------------------------------------------------
// CountingWriter
// ---------------------------------------------------------------------------

/// Wraps any `io::Write` and tracks the number of bytes written.
struct CountingWriter<W: io::Write> {
    inner: W,
    count: u64,
}

impl<W: io::Write> CountingWriter<W> {
    fn new(inner: W) -> Self {
        CountingWriter { inner, count: 0 }
    }

    fn bytes_written(&self) -> u64 {
        self.count
    }
}

impl<W: io::Write> io::Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    use crate::registry::{BaseEntry, ForkEntry, QuotaMode, Registry};

    // -----------------------------------------------------------------------
    // Test helper: set up a registry with one base and one fork
    // -----------------------------------------------------------------------

    fn setup_fork(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let registry = Registry::open(root).unwrap();

        let lower = root.join("bases/mybase/lower");
        fs::create_dir_all(&lower).unwrap();

        registry
            .insert_base(
                "mybase",
                BaseEntry {
                    lower_path: lower.clone(),
                    meta_path: root.join("bases/mybase/meta.json"),
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    cache_lower_paths: vec![],
                },
            )
            .unwrap();

        let upper = root.join("forks/agent-1/upper");
        fs::create_dir_all(&upper).unwrap();

        registry
            .insert_fork(
                "agent-1",
                ForkEntry {
                    base_key: "mybase".to_owned(),
                    upper_path: upper.clone(),
                    work_path: root.join("forks/agent-1/work"),
                    merged_path: None,
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        (lower, upper)
    }

    // -----------------------------------------------------------------------
    // Unknown fork → NotFound error
    // -----------------------------------------------------------------------

    #[test]
    fn export_patch_unknown_fork_returns_not_found() {
        let root = TempDir::new().unwrap();
        let out = root.path().join("patch.tar");
        let err = export_patch("nonexistent-fork", root.path(), Some(&out))
            .expect_err("expected error for unknown fork");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("nonexistent-fork"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Two new files → both present in the extracted tar
    // -----------------------------------------------------------------------

    #[test]
    fn export_patch_two_files_present_in_tar() {
        let root = TempDir::new().unwrap();
        let (_lower, upper) = setup_fork(root.path());

        fs::write(upper.join("alpha.txt"), b"hello").unwrap();
        fs::write(upper.join("beta.txt"), b"world").unwrap();

        let tar_path = root.path().join("patch.tar");
        export_patch("agent-1", root.path(), Some(&tar_path)).unwrap();

        // Extract to a temp dir and assert both files are present.
        let extract_dir = TempDir::new().unwrap();
        let tar_file = fs::File::open(&tar_path).unwrap();
        let mut archive = tar::Archive::new(tar_file);
        archive.unpack(extract_dir.path()).unwrap();

        assert!(
            extract_dir.path().join("alpha.txt").exists(),
            "alpha.txt not found after extraction"
        );
        assert!(
            extract_dir.path().join("beta.txt").exists(),
            "beta.txt not found after extraction"
        );
    }

    // -----------------------------------------------------------------------
    // Whiteout entry (.wh. prefix) is preserved in tar
    // -----------------------------------------------------------------------

    #[test]
    fn export_patch_whiteout_entry_in_tar() {
        let root = TempDir::new().unwrap();
        let (_lower, upper) = setup_fork(root.path());

        // Simulate a file deletion inside the fork: overlayfs creates a .wh.
        // prefixed marker file.
        fs::write(upper.join(".wh.deleted.txt"), b"").unwrap();

        let tar_path = root.path().join("patch.tar");
        export_patch("agent-1", root.path(), Some(&tar_path)).unwrap();

        // Read the tar and check that the whiteout entry is present.
        let tar_file = fs::File::open(&tar_path).unwrap();
        let mut archive = tar::Archive::new(tar_file);
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(
            entries.iter().any(|p| p.contains(".wh.deleted.txt")),
            "whiteout entry not found in tar; entries: {:?}",
            entries
        );
    }

    // -----------------------------------------------------------------------
    // --output writes to file, not stdout
    // -----------------------------------------------------------------------

    #[test]
    fn export_patch_output_flag_writes_file() {
        let root = TempDir::new().unwrap();
        let (_lower, upper) = setup_fork(root.path());
        fs::write(upper.join("readme.md"), b"# readme").unwrap();

        let out_path = root.path().join("output.tar");
        export_patch("agent-1", root.path(), Some(&out_path)).unwrap();

        let meta = fs::metadata(&out_path).unwrap();
        assert!(
            meta.len() > 0,
            "output tar file is empty — expected content"
        );
    }

    // -----------------------------------------------------------------------
    // patch_size_bytes is non-zero for a non-empty upper
    // -----------------------------------------------------------------------

    #[test]
    fn export_patch_size_nonzero_for_nonempty_upper() {
        let root = TempDir::new().unwrap();
        let (_lower, upper) = setup_fork(root.path());
        fs::write(upper.join("data.bin"), b"binary content").unwrap();

        let out_path = root.path().join("size_test.tar");
        export_patch("agent-1", root.path(), Some(&out_path)).unwrap();

        let size = fs::metadata(&out_path).unwrap().len();
        assert!(size > 0, "expected non-zero patch size");
    }
}
