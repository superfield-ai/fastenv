// Package builder implements the build-base command logic: ingesting a local
// directory into a content-addressed OCI image stored in containerd's image
// and content stores.
//
// # Algorithm
//
//  1. Walk the source directory and stream an uncompressed tar snapshot using
//     containerd's archive.Diff("", sourceDir) helper.
//  2. Simultaneously pipe the tar bytes through a SHA-256 hasher (for the OCI
//     DiffID) and a gzip writer (for the actual layer blob stored in the
//     content store).
//  3. Compute the SHA-256 of the compressed layer blob — this is the layer
//     descriptor digest used in the manifest.
//  4. Write the compressed layer to containerd's content store.
//  5. Build an OCI Image Config JSON that references the layer via its DiffID.
//  6. Build an OCI Image Manifest JSON that references the config and layer.
//  7. Write the config and manifest blobs to the content store.
//  8. Register (or update) the image in containerd's image service under the
//     caller-supplied tag name.
//
// # Content-addressed stability
//
// Stability requires a deterministic tar stream.  archive.Diff produces a
// consistent ordering for the same tree on the same filesystem.  The
// [WithSourceDateEpoch] option normalises modification timestamps; passing the
// zero time pins all mtimes to the Unix epoch for maximum reproducibility.
// Note that ACLs, xattrs, and inode-level metadata that vary across machines
// will cause digest divergence.  Treat the digest as stable-on-the-same-host
// for the same source tree.
//
// # Canonical docs
//
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md Phase 2 (build-base)
//   - docs/scout/phase1-findings.md §1 Phase A (layer ingest sequence)
package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// gcRootLabel pins a committed image so containerd GC does not reclaim it.
	// The value is an RFC 3339 timestamp (convention used by containerd tooling).
	// See docs/scout/phase1-findings.md §1 for GC label rationale.
	gcRootLabel = "containerd.io/gc.root"

	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second
)

// BuildResult holds metadata about the built image, emitted as a structured
// JSON log line upon successful completion.
type BuildResult struct {
	// ImageName is the tag under which the image was registered.
	ImageName string `json:"image_name"`
	// ManifestDigest is the OCI manifest digest (sha256:…) identifying the image.
	ManifestDigest string `json:"manifest_digest"`
	// TotalSize is the total on-disk size of all content blobs written (bytes).
	TotalSize int64 `json:"total_size_bytes"`
	// BuildDuration is the wall-clock time taken to build the image.
	BuildDuration string `json:"build_duration"`
}

// Options controls the behaviour of BuildBase.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
}

// BuildBase ingests the directory at sourceDir into containerd as an OCI
// image tagged with imageName.  If an image with that name already exists it
// is overwritten (the manifest target is replaced; unreferenced blobs are
// eligible for containerd's background GC).
//
// On success it returns a [BuildResult] suitable for JSON output.
func BuildBase(ctx context.Context, sourceDir, imageName string, opts Options) (*BuildResult, error) {
	start := time.Now()

	if opts.SocketPath == "" {
		opts.SocketPath = "/run/containerd/containerd.sock"
	}
	if opts.Namespace == "" {
		opts.Namespace = "fastenv"
	}

	// Dial containerd.
	client, err := containerd.New(opts.SocketPath,
		containerd.WithDefaultNamespace(opts.Namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("build-base: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)
	cs := client.ContentStore()

	// --- Step 1–3: create gzip layer from directory, compute DiffID ----------

	layerDesc, diffID, err := createLayer(ctx, cs, sourceDir)
	if err != nil {
		return nil, fmt.Errorf("build-base: create layer: %w", err)
	}

	// --- Step 4: write the OCI Image Config -----------------------------------

	configDesc, err := writeConfig(ctx, cs, diffID)
	if err != nil {
		return nil, fmt.Errorf("build-base: write image config: %w", err)
	}

	// --- Step 5: write the OCI Image Manifest --------------------------------

	manifestDesc, err := writeManifest(ctx, cs, configDesc, layerDesc)
	if err != nil {
		return nil, fmt.Errorf("build-base: write manifest: %w", err)
	}

	// --- Step 6: register (or update) the image in containerd ---------------

	if err := registerImage(ctx, client, imageName, manifestDesc); err != nil {
		return nil, fmt.Errorf("build-base: register image: %w", err)
	}

	totalSize := layerDesc.Size + configDesc.Size + manifestDesc.Size
	return &BuildResult{
		ImageName:      imageName,
		ManifestDigest: manifestDesc.Digest.String(),
		TotalSize:      totalSize,
		BuildDuration:  time.Since(start).Round(time.Millisecond).String(),
	}, nil
}

// createLayer streams the source directory as an OCI tar+gzip layer, writes it
// to the content store, and returns the layer descriptor and DiffID.
//
// DiffID = sha256 of the uncompressed tar stream (OCI spec §4.6.2).
// Layer descriptor digest = sha256 of the gzip-compressed blob stored in the
// content store.
func createLayer(ctx context.Context, cs content.Store, sourceDir string) (ocispec.Descriptor, digest.Digest, error) {
	// Pin modification times to the Unix epoch so that re-running build-base
	// on an identical source tree produces the same digest.
	epoch := time.Unix(0, 0).UTC()

	// archive.Diff("", sourceDir) streams the full directory as an OCI-style
	// uncompressed tar.  Passing a zero-value SourceDateEpoch normalises mtimes.
	diffRC := archive.Diff(ctx, "", sourceDir,
		archive.WithSourceDateEpoch(&epoch),
	)
	defer diffRC.Close()

	// Pipe the uncompressed tar stream through two destinations simultaneously:
	//   - a SHA-256 digester to compute the DiffID (sha256 of uncompressed tar)
	//   - a gzip writer to produce the compressed layer blob stored in the
	//     content store
	// Strategy: TeeReader copies uncompressed bytes to the diffHash digester
	// while the primary reader (gzip writer) processes them.
	// The gzip writer's output accumulates in buf; the layer digest is
	// computed from buf after the stream is fully consumed.
	diffDigester := digest.SHA256.Digester()

	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("create gzip writer: %w", err)
	}

	// TeeReader: reading from tarTee sends uncompressed bytes to diffDigester.Hash()
	// AND to the gzip writer (via io.Copy destination).
	tarTee := io.TeeReader(diffRC, diffDigester.Hash())
	if _, err := io.Copy(gw, tarTee); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("stream tar to gzip: %w", err)
	}
	if err := gw.Close(); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("close gzip writer: %w", err)
	}

	diffID := diffDigester.Digest()
	layerBytes := buf.Bytes()
	layerDigest := digest.SHA256.FromBytes(layerBytes)
	layerSize := int64(len(layerBytes))

	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    layerDigest,
		Size:      layerSize,
	}

	if err := writeBlob(ctx, cs, desc, bytes.NewReader(layerBytes)); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("write layer blob: %w", err)
	}

	return desc, diffID, nil
}

// writeConfig builds and persists the OCI Image Config for the given layer.
//
// The Created timestamp is pinned to the Unix epoch (1970-01-01T00:00:00Z) so
// that the config digest — and therefore the manifest digest — is stable for
// identical input directories.  This satisfies acceptance criterion #2:
// "Image digest is stable for identical input directories (content-addressed)."
func writeConfig(ctx context.Context, cs content.Store, diffID digest.Digest) (ocispec.Descriptor, error) {
	// Pin to epoch for deterministic config digest.
	epoch := time.Unix(0, 0).UTC()
	cfg := ocispec.Image{
		Created: &epoch,
		Author:  "fastenv build-base",
		Platform: ocispec.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		},
		RootFS: ocispec.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{diffID},
		},
		History: []ocispec.History{
			{
				Created:   &epoch,
				CreatedBy: "fastenv build-base",
				Comment:   "ingested from local directory",
			},
		},
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal image config: %w", err)
	}

	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.SHA256.FromBytes(cfgJSON),
		Size:      int64(len(cfgJSON)),
	}
	if err := writeBlob(ctx, cs, desc, bytes.NewReader(cfgJSON)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("write config blob: %w", err)
	}
	return desc, nil
}

// writeManifest builds and persists the OCI Image Manifest referencing the
// given config and layer descriptors.
func writeManifest(ctx context.Context, cs content.Store, configDesc, layerDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}

	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.SHA256.FromBytes(manifestJSON),
		Size:      int64(len(manifestJSON)),
	}
	if err := writeBlob(ctx, cs, desc, bytes.NewReader(manifestJSON)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("write manifest blob: %w", err)
	}
	return desc, nil
}

// registerImage creates or updates the named image in containerd's image store.
// The image is pinned with a gc.root label so containerd's background GC does
// not reclaim the underlying blobs while the image tag is live.
//
// Re-running with the same imageName overwrites the existing manifest pointer,
// satisfying the acceptance criterion: "Re-running build-base with the same
// name overwrites the tag; the old image is garbage-collected."
func registerImage(ctx context.Context, client *containerd.Client, name string, manifestDesc ocispec.Descriptor) error {
	is := client.ImageService()
	now := time.Now().UTC().Format(time.RFC3339)

	img := images.Image{
		Name:   name,
		Target: manifestDesc,
		Labels: map[string]string{
			gcRootLabel: now,
		},
	}

	// Try to update an existing image first (idempotent for repeated builds).
	if existing, err := is.Get(ctx, name); err == nil {
		// Preserve any existing labels; update gc.root timestamp and target.
		if existing.Labels != nil {
			for k, v := range existing.Labels {
				if _, ok := img.Labels[k]; !ok {
					img.Labels[k] = v
				}
			}
		}
		img.Labels[gcRootLabel] = now
		if _, err := is.Update(ctx, img); err != nil {
			return fmt.Errorf("update image %q: %w", name, err)
		}
		return nil
	}

	// Image does not yet exist — create it.
	if _, err := is.Create(ctx, img); err != nil {
		return fmt.Errorf("create image %q: %w", name, err)
	}
	return nil
}

// writeBlob writes the bytes from r to the content store under desc.
// If a blob with the same digest already exists the write is a no-op,
// providing idempotency for repeated build-base invocations on the same tree.
func writeBlob(ctx context.Context, cs content.Store, desc ocispec.Descriptor, r io.Reader) error {
	// Check existence first to avoid redundant writes.
	if _, err := cs.Info(ctx, desc.Digest); err == nil {
		return nil
	}

	ref := fmt.Sprintf("fastenv-ingest-%s", desc.Digest.Encoded()[:16])
	cw, err := cs.Writer(ctx,
		content.WithRef(ref),
		content.WithDescriptor(desc),
	)
	if err != nil {
		return fmt.Errorf("open content writer (ref=%s): %w", ref, err)
	}
	defer cw.Close()

	if _, err := io.Copy(cw, r); err != nil {
		return fmt.Errorf("copy blob bytes: %w", err)
	}
	if err := cw.Commit(ctx, desc.Size, desc.Digest); err != nil {
		return fmt.Errorf("commit blob: %w", err)
	}
	return nil
}
