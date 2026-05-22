package image

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// SourceType indicates where the image comes from.
type SourceType int

const (
	SourceRemote  SourceType = iota // Docker Hub or other registry
	SourceTarball                   // docker save tarball (.tar)
	SourceOCILayout                 // OCI image layout directory
)

// DetectSource determines the image source type from the reference string.
func DetectSource(ref string) SourceType {
	// Check if it's a tarball file
	if strings.HasSuffix(ref, ".tar") || strings.HasSuffix(ref, ".tar.gz") || strings.HasSuffix(ref, ".tgz") {
		if _, err := os.Stat(ref); err == nil {
			return SourceTarball
		}
	}

	// Check if it's an OCI layout directory
	if info, err := os.Stat(ref); err == nil && info.IsDir() {
		indexFile := filepath.Join(ref, "index.json")
		if _, err := os.Stat(indexFile); err == nil {
			return SourceOCILayout
		}
	}

	return SourceRemote
}

// Fetch retrieves an image from any supported source.
func Fetch(ctx context.Context, ref string) (v1.Image, error) {
	switch DetectSource(ref) {
	case SourceTarball:
		return fetchTarball(ref)
	case SourceOCILayout:
		return fetchOCILayout(ref)
	default:
		return fetchRemote(ctx, ref)
	}
}

// fetchRemote pulls image metadata from a remote registry.
func fetchRemote(ctx context.Context, ref string) (v1.Image, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %q: %w", ref, err)
	}

	img, err := remote.Image(parsedRef,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image %q: %w", ref, err)
	}

	return img, nil
}

// fetchTarball loads an image from a docker-save tarball file.
func fetchTarball(path string) (v1.Image, error) {
	// Try to get the tag from the tarball; use empty tag as fallback
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load tarball %q: %w", path, err)
	}
	return img, nil
}

// fetchOCILayout loads the first image from an OCI image layout directory.
func fetchOCILayout(dir string) (v1.Image, error) {
	p, err := layout.ImageIndexFromPath(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCI layout %q: %w", dir, err)
	}

	manifest, err := p.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to read OCI index manifest: %w", err)
	}

	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("no images found in OCI layout %q", dir)
	}

	// Prefer the first manifest (could be multi-arch; pick first for MVP)
	for _, desc := range manifest.Manifests {
		if desc.MediaType.IsImage() {
			img, err := p.Image(desc.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to read OCI image %s: %w", desc.Digest, err)
			}
			return img, nil
		}
	}

	// Fallback: try first manifest regardless of type
	img, err := p.Image(manifest.Manifests[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCI image: %w", err)
	}
	return img, nil
}
