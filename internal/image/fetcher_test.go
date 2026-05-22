package image

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectSource(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want SourceType
	}{
		{name: "remote ref", ref: "nginx:latest", want: SourceRemote},
		{name: "remote with registry", ref: "gcr.io/distroless/static:latest", want: SourceRemote},
		{name: "remote digest", ref: "nginx@sha256:abc123", want: SourceRemote},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectSource(tt.ref); got != tt.want {
				t.Errorf("DetectSource(%q) = %d, want %d", tt.ref, got, tt.want)
			}
		})
	}
}

func TestDetectSourceTarball(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "test.tar")
	if err := os.WriteFile(tarPath, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}

	if got := DetectSource(tarPath); got != SourceTarball {
		t.Errorf("DetectSource(%q) = %d, want SourceTarball", tarPath, got)
	}
}

func TestDetectSourceOCILayout(t *testing.T) {
	dir := t.TempDir()
	indexFile := filepath.Join(dir, "index.json")
	if err := os.WriteFile(indexFile, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	if got := DetectSource(dir); got != SourceOCILayout {
		t.Errorf("DetectSource(%q) = %d, want SourceOCILayout", dir, got)
	}
}

func TestDetectSourceNonexistentFile(t *testing.T) {
	// A .tar path that doesn't exist should fall back to remote
	if got := DetectSource("/nonexistent/path.tar"); got != SourceRemote {
		t.Errorf("DetectSource for nonexistent tar = %d, want SourceRemote", got)
	}
}
