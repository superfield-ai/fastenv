// builder_test.go — unit and integration tests for the builder package.
//
// Unit tests use a local on-disk content store (containerd's local store backed
// by a temp directory) and do not require a running containerd daemon.
//
// Integration tests (TestBuildBaseIntegration) require a live containerd daemon
// and are skipped automatically when one is not available, following the
// pattern established in internal/snapshotter for CI environments.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (build-base, test plan)
package builder

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestCreateLayerProducesGzipBlob verifies that createLayer writes a valid
// gzip-compressed tar blob to the content store for a small source directory.
func TestCreateLayerProducesGzipBlob(t *testing.T) {
	ctx := context.Background()

	// Create a small source directory with a couple of files.
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(srcDir, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "data.json"), []byte(`{"key":"value"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Use a local content store backed by a temp directory.
	csDir := t.TempDir()
	cs, err := local.NewStore(csDir)
	if err != nil {
		t.Fatalf("create content store: %v", err)
	}

	layerDesc, diffID, err := createLayer(ctx, cs, srcDir)
	if err != nil {
		t.Fatalf("createLayer: %v", err)
	}

	// Verify the layer descriptor has the correct media type.
	if layerDesc.MediaType != ocispec.MediaTypeImageLayerGzip {
		t.Errorf("layer media type: got %q, want %q", layerDesc.MediaType, ocispec.MediaTypeImageLayerGzip)
	}

	// Verify the digest is non-empty and follows sha256 format.
	if layerDesc.Digest == "" {
		t.Error("layer digest is empty")
	}
	if !strings.HasPrefix(layerDesc.Digest.String(), "sha256:") {
		t.Errorf("layer digest should be sha256, got %q", layerDesc.Digest.String())
	}

	// Verify the DiffID is distinct from the layer digest (one is uncompressed,
	// one is compressed).
	if diffID == layerDesc.Digest {
		t.Error("DiffID should differ from the compressed layer digest")
	}
	if !strings.HasPrefix(diffID.String(), "sha256:") {
		t.Errorf("DiffID should be sha256, got %q", diffID.String())
	}

	// Verify the blob exists in the content store and is valid gzip.
	info, err := cs.Info(ctx, layerDesc.Digest)
	if err != nil {
		t.Fatalf("blob not found in content store after createLayer: %v", err)
	}
	if info.Digest != layerDesc.Digest {
		t.Errorf("content store info digest mismatch: got %q, want %q", info.Digest, layerDesc.Digest)
	}

	// Read the blob back and verify it decompresses cleanly.
	ra, err := cs.ReaderAt(ctx, layerDesc)
	if err != nil {
		t.Fatalf("open blob for reading: %v", err)
	}
	defer ra.Close()

	gr, err := gzip.NewReader(io.NewSectionReader(ra, 0, layerDesc.Size))
	if err != nil {
		t.Fatalf("open gzip reader: %v", err)
	}
	defer gr.Close()

	if _, err := io.Copy(io.Discard, gr); err != nil {
		t.Fatalf("decompress layer: %v", err)
	}
}

// TestCreateLayerIsContentAddressed verifies that building the same source tree
// twice produces identical layer and DiffID digests (content-addressed property).
func TestCreateLayerIsContentAddressed(t *testing.T) {
	ctx := context.Background()

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "file.txt"), []byte("stable content"), 0o644); err != nil {
		t.Fatal(err)
	}

	csDir := t.TempDir()
	cs, err := local.NewStore(csDir)
	if err != nil {
		t.Fatalf("create content store: %v", err)
	}

	desc1, diffID1, err := createLayer(ctx, cs, srcDir)
	if err != nil {
		t.Fatalf("first createLayer: %v", err)
	}
	desc2, diffID2, err := createLayer(ctx, cs, srcDir)
	if err != nil {
		t.Fatalf("second createLayer: %v", err)
	}

	if desc1.Digest != desc2.Digest {
		t.Errorf("layer digest is not stable: first=%q second=%q", desc1.Digest, desc2.Digest)
	}
	if diffID1 != diffID2 {
		t.Errorf("DiffID is not stable: first=%q second=%q", diffID1, diffID2)
	}
}

// TestWriteConfigProducesValidOCIConfig verifies that writeConfig produces a
// blob that deserialises back to a valid OCI Image struct.
func TestWriteConfigProducesValidOCIConfig(t *testing.T) {
	ctx := context.Background()

	csDir := t.TempDir()
	cs, err := local.NewStore(csDir)
	if err != nil {
		t.Fatalf("create content store: %v", err)
	}

	fakeLayerDiffID := digest.SHA256.FromString("fake-layer-content")
	configDesc, err := writeConfig(ctx, cs, fakeLayerDiffID)
	if err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	// Read the config blob back.
	ra, err := cs.ReaderAt(ctx, configDesc)
	if err != nil {
		t.Fatalf("open config blob: %v", err)
	}
	defer ra.Close()

	data := make([]byte, configDesc.Size)
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatalf("read config blob: %v", err)
	}

	var cfg ocispec.Image
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	if cfg.RootFS.Type != "layers" {
		t.Errorf("config RootFS.Type: got %q, want %q", cfg.RootFS.Type, "layers")
	}
	if len(cfg.RootFS.DiffIDs) != 1 || cfg.RootFS.DiffIDs[0] != fakeLayerDiffID {
		t.Errorf("config RootFS.DiffIDs: got %v, want [%q]", cfg.RootFS.DiffIDs, fakeLayerDiffID)
	}
	if cfg.OS == "" {
		t.Error("config OS field should not be empty")
	}
	if cfg.Architecture == "" {
		t.Error("config Architecture field should not be empty")
	}
}

// TestWriteManifestReferencesLayerAndConfig verifies that writeManifest
// produces a valid OCI manifest that references the given config and layer.
func TestWriteManifestReferencesLayerAndConfig(t *testing.T) {
	ctx := context.Background()

	csDir := t.TempDir()
	cs, err := local.NewStore(csDir)
	if err != nil {
		t.Fatalf("create content store: %v", err)
	}

	configDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.SHA256.FromString("fake-config"),
		Size:      12,
	}
	layerDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.SHA256.FromString("fake-layer"),
		Size:      99,
	}

	manifestDesc, err := writeManifest(ctx, cs, configDesc, layerDesc)
	if err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	if manifestDesc.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("manifest media type: got %q, want %q", manifestDesc.MediaType, ocispec.MediaTypeImageManifest)
	}

	// Read the manifest blob back.
	ra, err := cs.ReaderAt(ctx, manifestDesc)
	if err != nil {
		t.Fatalf("open manifest blob: %v", err)
	}
	defer ra.Close()

	data := make([]byte, manifestDesc.Size)
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatalf("read manifest blob: %v", err)
	}

	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if m.SchemaVersion != 2 {
		t.Errorf("manifest SchemaVersion: got %d, want 2", m.SchemaVersion)
	}
	if m.Config.Digest != configDesc.Digest {
		t.Errorf("manifest config digest: got %q, want %q", m.Config.Digest, configDesc.Digest)
	}
	if len(m.Layers) != 1 || m.Layers[0].Digest != layerDesc.Digest {
		t.Errorf("manifest layers: got %v, want [%q]", m.Layers, layerDesc.Digest)
	}
}

// TestBuildBaseIntegration is an integration test that runs build-base against
// a live containerd daemon.  It is skipped automatically when containerd is not
// reachable or when permission is denied, following the pattern in
// internal/snapshotter for CI environments.
func TestBuildBaseIntegration(t *testing.T) {
	const socketPath = "/run/containerd/containerd.sock"
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Skipf("containerd socket not found at %s; skipping integration test", socketPath)
	}

	// Create a small representative source directory.
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module example.com/test\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	imageName := "fastenv-test/build-base-integration:latest"
	opts := Options{
		SocketPath: socketPath,
		Namespace:  "fastenv-test",
	}

	ctx := context.Background()
	result, err := BuildBase(ctx, srcDir, imageName, opts)
	if err != nil {
		// Skip on permission / connection errors (containerd not accessible).
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such file or directory") {
			t.Skipf("containerd not accessible at %s: %v", socketPath, err)
		}
		t.Fatalf("BuildBase: %v", err)
	}

	if result.ImageName != imageName {
		t.Errorf("result.ImageName: got %q, want %q", result.ImageName, imageName)
	}
	if !strings.HasPrefix(result.ManifestDigest, "sha256:") {
		t.Errorf("result.ManifestDigest should be sha256, got %q", result.ManifestDigest)
	}
	if result.TotalSize <= 0 {
		t.Errorf("result.TotalSize should be > 0, got %d", result.TotalSize)
	}
	if result.BuildDuration == "" {
		t.Error("result.BuildDuration should not be empty")
	}

	// Re-run with same name — should overwrite without error (idempotent).
	result2, err := BuildBase(ctx, srcDir, imageName, opts)
	if err != nil {
		t.Fatalf("BuildBase (second run): %v", err)
	}
	// Second build on unchanged source should produce the same manifest digest
	// (content-addressed guarantee — acceptance criterion #2).
	if result.ManifestDigest != result2.ManifestDigest {
		t.Errorf("manifest digest is not stable across runs: first=%q second=%q",
			result.ManifestDigest, result2.ManifestDigest)
	}
}
