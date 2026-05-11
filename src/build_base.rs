// build_base.rs — `fastenv build-base <dir> --name <key>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Deterministic (sorted) directory walk produces a gzip tar blob in memory.
//  2. SHA-256 digest of the compressed bytes is computed.
//  3. Blob is written to `<root>/content/blobs/sha256/<digest>` (skipped if
//     the file already exists — content-addressed deduplication).
//  4. Tar is extracted into `bases/<key>/lower/`.
//  5. `bases/<key>/meta.json` is written with layer_digest, source_path, and
//     created_at.
//  6. Cache subdirs (`cache/npm`, `cache/pip`, `cache/cargo`) in the source are
//     detected and each extracted into `bases/<key>/cache/<name>/` as separate
//     read-only lower dirs; their paths are stored in the registry entry as
//     `cache_lower_paths`.
//  7. `registry.insert_base` registers the base in registry.json.
//  8. Idempotent: if the base key already exists in the registry, the command
//     returns Ok(()) immediately without re-extracting.

use std::fs;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use flate2::{write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::registry::{BaseEntry, Registry};

// ---------------------------------------------------------------------------
// meta.json schema
// ---------------------------------------------------------------------------

/// Written to `bases/<key>/meta.json` after successful extraction.
#[derive(Debug, Serialize, Deserialize)]
pub struct BaseMeta {
    /// `sha256:<hex>` digest of the gzip tar blob.
    pub layer_digest: String,
    /// Absolute path of the source directory used to build this base.
    pub source_path: String,
    /// RFC 3339 creation timestamp (UTC, second precision).
    pub created_at: String,
    /// Names of detected cache subdirectories (e.g. `["npm", "pip"]`).
    /// Each is extracted as a separate lower dir under `bases/<key>/cache/<name>/`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_names: Vec<String>,
}

/// Known cache subdirectory names detected inside `cache/` of the source dir.
const KNOWN_CACHE_NAMES: &[&str] = &["npm", "pip", "cargo"];

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `build-base` pipeline.
///
/// * `source_dir` — directory tree to package.
/// * `base_key`   — registry key (used as the `bases/<key>/` directory name).
/// * `root`       — fastenv data root (e.g. `/var/lib/fastenv`).
pub fn build_base(source_dir: &Path, base_key: &str, root: &Path) -> Result<()> {
    let started_at = Instant::now();

    // Canonicalise so that meta.json always contains an absolute path.
    let source_dir = source_dir
        .canonicalize()
        .with_context(|| format!("cannot canonicalize source dir: {}", source_dir.display()))?;

    // ── 0. Idempotency guard ─────────────────────────────────────────────────
    let registry = Registry::open(root)?;
    if registry.get_base(base_key).is_ok() {
        tracing::info!(
            command = "build-base",
            base_key = base_key,
            "base already exists — skipping re-extraction"
        );
        return Ok(());
    }

    // ── 1. Build deterministic gzip tar blob ─────────────────────────────────
    let blob = build_gzip_tar(&source_dir)
        .with_context(|| format!("failed to build tar from {}", source_dir.display()))?;

    // ── 2. SHA-256 digest ────────────────────────────────────────────────────
    let mut hasher = Sha256::new();
    hasher.update(&blob);
    let digest_hex = hex::encode(hasher.finalize());
    let layer_digest = format!("sha256:{}", digest_hex);

    // ── 3. Write blob to content store ───────────────────────────────────────
    let blobs_dir = root.join("content").join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)
        .with_context(|| format!("cannot create blobs dir: {}", blobs_dir.display()))?;
    let blob_path = blobs_dir.join(&digest_hex);
    if !blob_path.exists() {
        write_atomic(&blob_path, &blob)
            .with_context(|| format!("cannot write blob to {}", blob_path.display()))?;
    }

    // ── 4. Extract tar into bases/<key>/lower/ ───────────────────────────────
    let lower_dir = root.join("bases").join(base_key).join("lower");
    fs::create_dir_all(&lower_dir)
        .with_context(|| format!("cannot create lower dir: {}", lower_dir.display()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(&blob)));
    archive
        .unpack(&lower_dir)
        .with_context(|| format!("cannot unpack tar into {}", lower_dir.display()))?;

    // ── 5. Write bases/<key>/meta.json ───────────────────────────────────────
    let created_at = rfc3339_now();

    // ── 6. Detect and extract cache subdirs ──────────────────────────────────
    // Scan for cache/<name>/ subdirs in source_dir where <name> is one of
    // KNOWN_CACHE_NAMES.  Each found cache subdir is extracted into
    // bases/<key>/cache/<name>/ and its path is appended to cache_lower_paths.
    let mut cache_lower_paths: Vec<PathBuf> = Vec::new();
    let mut cache_names: Vec<String> = Vec::new();
    let cache_source_root = source_dir.join("cache");
    for &name in KNOWN_CACHE_NAMES {
        let cache_source_dir = cache_source_root.join(name);
        if cache_source_dir.is_dir() {
            let cache_lower_dir = root.join("bases").join(base_key).join("cache").join(name);
            fs::create_dir_all(&cache_lower_dir).with_context(|| {
                format!(
                    "cannot create cache lower dir: {}",
                    cache_lower_dir.display()
                )
            })?;
            let cache_blob = build_gzip_tar(&cache_source_dir).with_context(|| {
                format!(
                    "failed to build tar from cache/{} at {}",
                    name,
                    cache_source_dir.display()
                )
            })?;
            let mut archive =
                tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(&cache_blob)));
            archive.unpack(&cache_lower_dir).with_context(|| {
                format!(
                    "cannot unpack cache/{} tar into {}",
                    name,
                    cache_lower_dir.display()
                )
            })?;
            cache_lower_paths.push(cache_lower_dir);
            cache_names.push(name.to_owned());
            tracing::info!(
                command = "build-base",
                base_key = base_key,
                cache = name,
                "cache subdir detected and extracted"
            );
        }
    }

    let meta = BaseMeta {
        layer_digest: layer_digest.clone(),
        source_path: source_dir.to_string_lossy().into_owned(),
        created_at: created_at.clone(),
        cache_names: cache_names.clone(),
    };
    let meta_path = root.join("bases").join(base_key).join("meta.json");
    let meta_bytes = serde_json::to_vec_pretty(&meta)?;
    write_atomic(&meta_path, &meta_bytes)
        .with_context(|| format!("cannot write meta.json to {}", meta_path.display()))?;

    // ── 7. Register base ─────────────────────────────────────────────────────
    registry.insert_base(
        base_key,
        BaseEntry {
            lower_path: lower_dir.clone(),
            meta_path: meta_path.clone(),
            created_at,
            cache_lower_paths: cache_lower_paths.clone(),
        },
    )?;

    // ── 8. Structured JSON log ───────────────────────────────────────────────
    let elapsed_ms = started_at.elapsed().as_millis();
    tracing::info!(
        command      = "build-base",
        base_key     = base_key,
        layer_digest = %layer_digest,
        cache_count  = cache_lower_paths.len(),
        elapsed_ms   = elapsed_ms,
        "build-base complete"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic gzip tar builder
// ---------------------------------------------------------------------------

/// Walk `dir` in sorted order and return a gzip-compressed tar archive as a
/// `Vec<u8>`.  Paths inside the archive are relative to `dir`.
fn build_gzip_tar(dir: &Path) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let gz = GzEncoder::new(buf, Compression::default());
    let mut tar = tar::Builder::new(gz);
    // Preserve mtime from the source files (not normalising timestamps here;
    // timestamp normalisation is noted as a future enhancement in the issue).
    tar.follow_symlinks(false);

    // Collect all paths first so we can sort them for determinism.
    let mut entries = collect_entries(dir, dir)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (rel_path, abs_path) in entries {
        let metadata = fs::metadata(&abs_path)
            .with_context(|| format!("stat failed for {}", abs_path.display()))?;
        if metadata.is_dir() {
            tar.append_dir(&rel_path, &abs_path)
                .with_context(|| format!("tar append_dir failed for {}", rel_path.display()))?;
        } else {
            let mut file = fs::File::open(&abs_path)
                .with_context(|| format!("cannot open {}", abs_path.display()))?;
            tar.append_file(&rel_path, &mut file)
                .with_context(|| format!("tar append_file failed for {}", rel_path.display()))?;
        }
    }

    let gz = tar.into_inner()?;
    let bytes = gz.finish()?;
    Ok(bytes)
}

/// Recursively collect `(relative_path, absolute_path)` pairs under `root`.
/// Directories themselves are also included so that empty dirs are preserved.
fn collect_entries(root: &Path, current: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut result = Vec::new();
    for entry in
        fs::read_dir(current).with_context(|| format!("cannot read dir {}", current.display()))?
    {
        let entry = entry?;
        let abs = entry.path();
        let rel = abs
            .strip_prefix(root)
            .expect("abs path is always under root")
            .to_path_buf();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            result.push((rel, abs.clone()));
            result.extend(collect_entries(root, &abs)?);
        } else {
            result.push((rel, abs));
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write `data` atomically to `dest` via a sibling temp file + rename.
fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
    let parent = dest.parent().context("dest has no parent directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.persist(dest)
        .map_err(|e| anyhow::anyhow!("persist failed: {}", e))?;
    Ok(())
}

/// Return the current UTC time as an RFC 3339 string (second precision).
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format manually to avoid pulling in a large date/time library just for
    // this single use.  chrono is listed as a dependency but we keep it simple.
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_source_tree(dir: &Path) {
        fs::write(dir.join("a.txt"), b"hello from a").unwrap();
        fs::write(dir.join("b.txt"), b"hello from b").unwrap();
        let sub = dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("c.txt"), b"hello from c").unwrap();
    }

    /// Create a temp source dir with 3 files; run build_base; assert lower/
    /// contains all 3 files.
    #[test]
    fn build_base_populates_lower_dir() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let lower = root.path().join("bases").join("mybase").join("lower");
        assert!(lower.join("a.txt").exists(), "a.txt missing from lower/");
        assert!(lower.join("b.txt").exists(), "b.txt missing from lower/");
        assert!(
            lower.join("subdir").join("c.txt").exists(),
            "subdir/c.txt missing from lower/"
        );
    }

    /// meta.json layer_digest must match sha256sum of the blob in the content
    /// store.
    #[test]
    fn meta_json_digest_matches_blob() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let meta_path = root.path().join("bases").join("mybase").join("meta.json");
        let meta: BaseMeta = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();

        // Digest is "sha256:<hex>".
        let hex_part = meta.layer_digest.strip_prefix("sha256:").unwrap();
        let blob_path = root
            .path()
            .join("content")
            .join("blobs")
            .join("sha256")
            .join(hex_part);
        assert!(blob_path.exists(), "blob file missing");

        let blob_bytes = fs::read(&blob_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&blob_bytes);
        let actual = hex::encode(hasher.finalize());
        assert_eq!(
            hex_part, actual,
            "layer_digest does not match sha256 of blob"
        );
    }

    /// Running build_base twice on the same dir+key must not re-extract (lower/
    /// mtime must not change on the second run).
    #[test]
    fn build_base_idempotent() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("first build_base failed");

        let lower = root.path().join("bases").join("mybase").join("lower");
        let mtime_before = fs::metadata(lower.join("a.txt"))
            .unwrap()
            .modified()
            .unwrap();

        // Second invocation — should return Ok immediately without re-extracting.
        build_base(src.path(), "mybase", root.path()).expect("second build_base failed");

        let mtime_after = fs::metadata(lower.join("a.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "lower/ was re-extracted on second build_base run"
        );
    }

    /// The blob at content/blobs/sha256/<digest> must be a valid gzip tar that
    /// unpacks to match the source directory.
    #[test]
    fn blob_is_valid_gzip_tar_of_source() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let meta_path = root.path().join("bases").join("mybase").join("meta.json");
        let meta: BaseMeta = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
        let hex_part = meta.layer_digest.strip_prefix("sha256:").unwrap();
        let blob_path = root
            .path()
            .join("content")
            .join("blobs")
            .join("sha256")
            .join(hex_part);

        let blob_bytes = fs::read(&blob_path).unwrap();
        let extract_dir = TempDir::new().unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(blob_bytes)));
        archive.unpack(extract_dir.path()).unwrap();

        assert!(
            extract_dir.path().join("a.txt").exists(),
            "a.txt missing after independent blob extraction"
        );
        assert!(
            extract_dir.path().join("subdir").join("c.txt").exists(),
            "subdir/c.txt missing after independent blob extraction"
        );
    }

    /// registry.list_bases includes the key after a successful build_base.
    #[test]
    fn registry_contains_base_after_build() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let registry = Registry::open(root.path()).unwrap();
        let bases = registry.list_bases().unwrap();
        assert!(
            bases.contains_key("mybase"),
            "registry does not contain 'mybase' after build_base"
        );
    }

    // -----------------------------------------------------------------------
    // Cache subdir detection
    // -----------------------------------------------------------------------

    fn make_source_tree_with_npm_cache(dir: &Path) {
        // Regular files
        fs::write(dir.join("a.txt"), b"hello from a").unwrap();
        // cache/npm subdir with a package file
        let npm = dir.join("cache").join("npm");
        fs::create_dir_all(&npm).unwrap();
        fs::write(npm.join("lodash-4.17.21.tgz"), b"fake npm package").unwrap();
    }

    /// build-base on a dir with cache/npm registers a cache entry in the
    /// registry and creates bases/<key>/cache/npm/ on disk.
    #[test]
    fn build_base_detects_npm_cache_dir() {
        let src = TempDir::new().unwrap();
        make_source_tree_with_npm_cache(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        // Registry entry must have one cache_lower_path ending in /cache/npm.
        let registry = Registry::open(root.path()).unwrap();
        let entry = registry.get_base("mybase").unwrap();
        assert_eq!(
            entry.cache_lower_paths.len(),
            1,
            "expected exactly one cache lower path"
        );
        assert!(
            entry.cache_lower_paths[0]
                .to_string_lossy()
                .ends_with("cache/npm"),
            "cache lower path should end with cache/npm, got: {}",
            entry.cache_lower_paths[0].display()
        );

        // The extracted cache lower dir must contain the npm package file.
        let cache_lower = root
            .path()
            .join("bases")
            .join("mybase")
            .join("cache")
            .join("npm");
        assert!(
            cache_lower.join("lodash-4.17.21.tgz").exists(),
            "npm cache file missing from cache lower dir"
        );
    }

    /// meta.json must record cache_names when cache subdirs are detected.
    #[test]
    fn meta_json_records_cache_names() {
        let src = TempDir::new().unwrap();
        make_source_tree_with_npm_cache(src.path());

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let meta_path = root.path().join("bases").join("mybase").join("meta.json");
        let meta: BaseMeta = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
        assert_eq!(meta.cache_names, vec!["npm"], "cache_names mismatch");
    }

    /// build-base without cache dirs must have empty cache_lower_paths in
    /// the registry — existing bases are unaffected by the new feature.
    #[test]
    fn build_base_without_cache_dirs_has_empty_cache_lower_paths() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path()); // no cache/ subdir

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let registry = Registry::open(root.path()).unwrap();
        let entry = registry.get_base("mybase").unwrap();
        assert!(
            entry.cache_lower_paths.is_empty(),
            "cache_lower_paths should be empty when no cache dirs are present"
        );
    }

    /// build-base with all three cache types (npm, pip, cargo) registers all
    /// three in order.
    #[test]
    fn build_base_detects_all_three_cache_dirs() {
        let src = TempDir::new().unwrap();
        make_source_tree(src.path());
        for name in &["npm", "pip", "cargo"] {
            let cache_dir = src.path().join("cache").join(name);
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(
                cache_dir.join(format!("{}-pkg.txt", name)),
                format!("fake {} package", name).as_bytes(),
            )
            .unwrap();
        }

        let root = TempDir::new().unwrap();
        build_base(src.path(), "mybase", root.path()).expect("build_base failed");

        let registry = Registry::open(root.path()).unwrap();
        let entry = registry.get_base("mybase").unwrap();
        assert_eq!(
            entry.cache_lower_paths.len(),
            3,
            "expected 3 cache lower paths"
        );

        // Verify each cache dir was extracted.
        for name in &["npm", "pip", "cargo"] {
            let cache_lower = root
                .path()
                .join("bases")
                .join("mybase")
                .join("cache")
                .join(name);
            assert!(
                cache_lower.join(format!("{}-pkg.txt", name)).exists(),
                "{} cache file missing from cache lower dir",
                name
            );
        }
    }
}
