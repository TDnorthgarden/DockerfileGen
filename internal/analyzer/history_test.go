package analyzer

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"

	"github.com/TDnorthgarden/DockerfileGen/internal/model"
)

func TestParseCreatedBy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType model.InstructionType
		wantBody string
	}{
		{
			name:     "RUN instruction",
			input:    "/bin/sh -c apt-get update && apt-get install -y curl",
			wantType: model.InstRUN,
			wantBody: "apt-get update && apt-get install -y curl",
		},
		{
			name:     "RUN without shell prefix",
			input:    "apt-get update",
			wantType: model.InstRUN,
			wantBody: "apt-get update",
		},
		{
			name:     "WORKDIR via nop",
			input:    "/bin/sh -c #(nop) WORKDIR /app",
			wantType: model.InstWORKDIR,
			wantBody: "/app",
		},
		{
			name:     "ENV via nop",
			input:    "/bin/sh -c #(nop) ENV PATH=/usr/local/bin:/usr/bin:/bin",
			wantType: model.InstENV,
		},
		{
			name:     "EXPOSE via nop",
			input:    "/bin/sh -c #(nop) EXPOSE 80",
			wantType: model.InstEXPOSE,
			wantBody: "80",
		},
		{
			name:     "CMD via nop with JSON",
			input:    `/bin/sh -c #(nop) CMD ["nginx" "-g" "daemon off;"]`,
			wantType: model.InstCMD,
		},
		{
			name:     "ENTRYPOINT via nop",
			input:    `/bin/sh -c #(nop) ENTRYPOINT ["/docker-entrypoint.sh"]`,
			wantType: model.InstENTRYPOINT,
		},
		{
			name:     "COPY via nop",
			input:    "/bin/sh -c #(nop) COPY file:abc123 in /etc/nginx/nginx.conf",
			wantType: model.InstCOPY,
			wantBody: "file:abc123 /etc/nginx/nginx.conf",
		},
		{
			name:     "ADD via nop",
			input:    "/bin/sh -c #(nop) ADD file:def456 in /tmp/",
			wantType: model.InstADD,
			wantBody: "file:def456 /tmp/",
		},
		{
			name:     "USER via nop",
			input:    "/bin/sh -c #(nop) USER nginx",
			wantType: model.InstUSER,
			wantBody: "nginx",
		},
		{
			name:     "LABEL via nop",
			input:    "/bin/sh -c #(nop) LABEL maintainer=test@example.com",
			wantType: model.InstLABEL,
		},
		{
			name:     "empty string",
			input:    "",
			wantType: "",
		},
		{
			name:     "BuildKit RUN format",
			input:    "RUN apt-get update",
			wantType: model.InstRUN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCreatedBy(tt.input)
			if tt.input == "" {
				if result != nil {
					t.Fatalf("expected nil for empty input, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Type != tt.wantType {
				t.Errorf("type = %q, want %q", result.Type, tt.wantType)
			}
			if tt.wantBody != "" && result.Content != tt.wantBody {
				t.Errorf("content = %q, want %q", result.Content, tt.wantBody)
			}
		})
	}
}

func TestParseHistory(t *testing.T) {
	history := []v1.History{
		{CreatedBy: "/bin/sh -c apk add --no-cache curl", EmptyLayer: false},
		{CreatedBy: "/bin/sh -c #(nop) WORKDIR /app", EmptyLayer: true},
		{CreatedBy: "/bin/sh -c #(nop) COPY file:abc123 in /app/main.go", EmptyLayer: false},
		{CreatedBy: "", EmptyLayer: true}, // should be skipped
	}

	result := ParseHistory(history)
	if len(result) != 3 {
		t.Fatalf("expected 3 instructions, got %d", len(result))
	}

	if result[0].Type != model.InstRUN {
		t.Errorf("instruction[0] type = %q, want RUN", result[0].Type)
	}
	if result[1].Type != model.InstWORKDIR {
		t.Errorf("instruction[1] type = %q, want WORKDIR", result[1].Type)
	}
	if result[2].Type != model.InstCOPY {
		t.Errorf("instruction[2] type = %q, want COPY", result[2].Type)
	}
}

func TestExtractMetadata(t *testing.T) {
	cfg := &v1.ConfigFile{
		Config: v1.Config{
			Env: []string{"PATH=/usr/bin:/bin", "NGINX_VERSION=1.21.0"},
			ExposedPorts: map[string]struct{}{
				"80/tcp": {},
				"443/tcp": {},
			},
			Cmd:        []string{"nginx", "-g", "daemon off;"},
			Entrypoint: []string{"/docker-entrypoint.sh"},
			WorkingDir: "/app",
			User:       "nginx",
		},
	}

	img := empty.Image
	meta := ExtractMetadata(cfg, "nginx:1.21-alpine", img)

	if meta.BaseImageRef == "" {
		t.Error("BaseImageRef should not be empty")
	}
	if len(meta.EnvVars) != 2 {
		t.Errorf("EnvVars count = %d, want 2", len(meta.EnvVars))
	}
	if meta.EnvVars["NGINX_VERSION"] != "1.21.0" {
		t.Errorf("EnvVars[NGINX_VERSION] = %q, want 1.21.0", meta.EnvVars["NGINX_VERSION"])
	}
	if len(meta.ExposedPorts) != 2 {
		t.Errorf("ExposedPorts count = %d, want 2", len(meta.ExposedPorts))
	}
	if meta.WorkingDir != "/app" {
		t.Errorf("WorkingDir = %q, want /app", meta.WorkingDir)
	}
	if meta.User != "nginx" {
		t.Errorf("User = %q, want nginx", meta.User)
	}
}

func TestIsScratchImage_Explicit(t *testing.T) {
	cfg := &v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "FROM scratch", EmptyLayer: true},
			{CreatedBy: "COPY myapp /usr/local/bin/myapp", EmptyLayer: false},
			{CreatedBy: "CMD [\"myapp\"]", EmptyLayer: true},
		},
	}
	if !isScratchImage(cfg) {
		t.Error("expected isScratchImage=true for explicit FROM scratch")
	}
}

func TestIsScratchImage_CopyFirst(t *testing.T) {
	cfg := &v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "COPY myapp /usr/local/bin/myapp", EmptyLayer: false},
			{CreatedBy: "EXPOSE 8080", EmptyLayer: true},
		},
	}
	if !isScratchImage(cfg) {
		t.Error("expected isScratchImage=true when first entry is COPY")
	}
}

func TestIsScratchImage_NormalBase(t *testing.T) {
	cfg := &v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "/bin/sh -c #(nop) ENV PATH=/usr/bin:/bin", EmptyLayer: true},
			{CreatedBy: "/bin/sh -c #(nop) LABEL maintainer=test", EmptyLayer: true},
			{CreatedBy: "/bin/sh -c apk add --no-cache curl", EmptyLayer: false},
		},
	}
	if isScratchImage(cfg) {
		t.Error("expected isScratchImage=false for normal base image")
	}
}

func TestExtractMetadata_Scratch(t *testing.T) {
	cfg := &v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: "FROM scratch", EmptyLayer: true},
			{CreatedBy: "COPY myapp /", EmptyLayer: false},
		},
		Config: v1.Config{
			Cmd: []string{"/myapp"},
		},
	}
	img := empty.Image
	meta := ExtractMetadata(cfg, "myapp:v1", img)

	if meta.BaseImageRef != "scratch" {
		t.Errorf("BaseImageRef = %q, want scratch", meta.BaseImageRef)
	}
}
