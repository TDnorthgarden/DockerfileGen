package analyzer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/TDnorthgarden/DockerfileGen/internal/model"
)

var shellPrefixRe = regexp.MustCompile(`^/bin/sh -c\s+`)
var buildkitSuffix = regexp.MustCompile(`\s+#\s*buildkit\s*$`)

// knownKeywords are instruction keywords that can appear at the start of a BuildKit CreatedBy.
var knownKeywords = []string{
	"HEALTHCHECK ", "ENTRYPOINT ", "STOPSIGNAL ", "ONBUILD ",
	"WORKDIR ", "VOLUME ", "EXPOSE ", "SHELL ",
	"COPY ", "CMD ", "ENV ", "ADD ", "RUN ", "ARG ", "LABEL ", "USER ",
}

// ExtractMetadata pulls top-level config directives from the image config.
func ExtractMetadata(cfg *v1.ConfigFile, imageRef string, img v1.Image) model.ImageMetadata {
	meta := model.ImageMetadata{
		BaseImageRef: imageRef,
	}

	// Detect FROM scratch: check if history explicitly contains "FROM scratch"
	// or if the image has no base image indicators
	if isScratchImage(cfg) {
		meta.BaseImageRef = "scratch"
	} else if digest, err := img.Digest(); err == nil {
		meta.BaseImageRef = fmt.Sprintf("%s@%s", imageRef, digest.String())
	}

	meta.EnvVars = make(map[string]string)
	for _, e := range cfg.Config.Env {
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			meta.EnvVars[e[:idx]] = e[idx+1:]
		}
	}

	for port := range cfg.Config.ExposedPorts {
		meta.ExposedPorts = append(meta.ExposedPorts, port)
	}
	sort.Strings(meta.ExposedPorts)

	meta.Cmd = cfg.Config.Cmd
	meta.Entrypoint = cfg.Config.Entrypoint
	meta.WorkingDir = cfg.Config.WorkingDir
	meta.User = cfg.Config.User
	meta.StopSignal = cfg.Config.StopSignal

	meta.Labels = make(map[string]string)
	for k, v := range cfg.Config.Labels {
		meta.Labels[k] = v
	}

	for vol := range cfg.Config.Volumes {
		meta.Volumes = append(meta.Volumes, vol)
	}
	sort.Strings(meta.Volumes)

	return meta
}

// isScratchImage checks if the image was built FROM scratch.
// Detection: history contains explicit "FROM scratch", or the first real history
// entry is a filesystem operation (COPY/ADD/RUN) with no prior base image metadata.
func isScratchImage(cfg *v1.ConfigFile) bool {
	if len(cfg.History) == 0 {
		return false
	}

	// Check for explicit "FROM scratch" in history
	for _, h := range cfg.History {
		created := strings.TrimSpace(h.CreatedBy)
		upper := strings.ToUpper(created)
		if upper == "FROM SCRATCH" || strings.HasPrefix(upper, "FROM SCRATCH") {
			return true
		}
	}

	// Heuristic: if the first non-empty history entry is a filesystem operation
	// (COPY, ADD, RUN) rather than metadata from a base image, it's likely scratch.
	// Base images typically start with ENV/LABEL entries inherited from their parent.
	for _, h := range cfg.History {
		if h.CreatedBy == "" {
			continue
		}
		inst := parseCreatedBy(h.CreatedBy)
		if inst == nil {
			continue
		}
		// First real instruction is a filesystem op — likely scratch
		switch inst.Type {
		case model.InstCOPY, model.InstADD, model.InstRUN:
			return true
		default:
			return false
		}
	}

	return false
}

// ParseHistory converts image history entries into ordered instructions.
func ParseHistory(history []v1.History) []model.Instruction {
	var instructions []model.Instruction
	for _, h := range history {
		if h.EmptyLayer && h.CreatedBy == "" {
			continue
		}
		inst := parseCreatedBy(h.CreatedBy)
		if inst != nil {
			instructions = append(instructions, *inst)
		}
	}
	return instructions
}

// classifyByKeyword tries to match the payload against known Dockerfile instruction keywords
// and returns the appropriate instruction. Returns nil if no keyword matches (treat as RUN).
func classifyByKeyword(raw, payload string) *model.Instruction {
	upper := strings.ToUpper(payload)

	for _, kw := range knownKeywords {
		if strings.HasPrefix(upper, kw) {
			kwLen := len(kw)
			arg := strings.TrimSpace(payload[kwLen:])
			keyword := upper[:kwLen-1] // strip trailing space

			switch keyword {
			case "COPY":
				return parseCopyAdd(raw, model.InstCOPY, arg)
			case "ADD":
				return parseCopyAdd(raw, model.InstADD, arg)
			case "WORKDIR":
				return &model.Instruction{Type: model.InstWORKDIR, Raw: raw, Content: arg}
			case "ENV":
				return parseEnv(raw, arg)
			case "EXPOSE":
				return &model.Instruction{Type: model.InstEXPOSE, Raw: raw, Content: cleanExpose(arg)}
			case "CMD":
				return parseCmdEntrypoint(raw, model.InstCMD, arg)
			case "ENTRYPOINT":
				return parseCmdEntrypoint(raw, model.InstENTRYPOINT, arg)
			case "LABEL":
				return parseLabel(raw, arg)
			case "USER":
				return &model.Instruction{Type: model.InstUSER, Raw: raw, Content: arg}
			case "STOPSIGNAL":
				return &model.Instruction{Type: model.InstSTOPSIGNAL, Raw: raw, Content: arg}
			case "VOLUME":
				return parseCmdEntrypoint(raw, model.InstVOLUME, arg)
			case "ARG":
				return &model.Instruction{Type: model.InstARG, Raw: raw, Content: arg}
			case "SHELL":
				return parseCmdEntrypoint(raw, model.InstSHELL, arg)
			case "HEALTHCHECK":
				return &model.Instruction{Type: model.InstHEALTHCHECK, Raw: raw, Content: arg}
			case "ONBUILD":
				return &model.Instruction{Type: model.InstONBUILD, Raw: raw, Content: arg}
			case "RUN":
				// "RUN /bin/sh -c ..." — strip the "RUN " prefix and re-parse as RUN
				return &model.Instruction{Type: model.InstRUN, Raw: raw, Content: arg}
			}
		}
	}
	return nil
}

// parseCreatedBy classifies a single History.CreatedBy string into an Instruction.
func parseCreatedBy(createdBy string) *model.Instruction {
	if createdBy == "" {
		return nil
	}

	raw := createdBy
	payload := createdBy

	// Strip "/bin/sh -c " prefix (classic Docker format)
	if m := shellPrefixRe.FindString(payload); m != "" {
		payload = payload[len(m):]
	}

	// Strip "# buildkit" suffix (BuildKit format)
	payload = buildkitSuffix.ReplaceAllString(payload, "")
	payload = strings.TrimSpace(payload)

	// Classic Docker: check for #(nop) marker
	if strings.HasPrefix(payload, "#(nop)") {
		remainder := strings.TrimPrefix(payload, "#(nop)")
		remainder = strings.TrimSpace(remainder)
		return parseNopInstruction(raw, remainder)
	}

	// BuildKit format: try to match known instruction keywords directly
	if inst := classifyByKeyword(raw, payload); inst != nil {
		return inst
	}

	// Fallback: treat as RUN instruction
	return &model.Instruction{
		Type:    model.InstRUN,
		Raw:     raw,
		Content: payload,
	}
}

// parseNopInstruction handles classic Docker entries with the #(nop) marker.
func parseNopInstruction(raw, remainder string) *model.Instruction {
	return classifyByKeyword(raw, remainder)
}

// cleanExpose normalizes EXPOSE arguments.
// BuildKit may output "map[80/tcp:{}]" — extract just the port.
func cleanExpose(arg string) string {
	if strings.HasPrefix(arg, "map[") && strings.HasSuffix(arg, ":{}]") {
		return strings.TrimPrefix(strings.TrimSuffix(arg, ":{}]"), "map[")
	}
	return arg
}

// parseCopyAdd handles COPY/ADD instructions.
func parseCopyAdd(raw string, instType model.InstructionType, arg string) *model.Instruction {
	// Classic format: "file:<hash> in /path"
	parts := strings.SplitN(arg, " in ", 2)
	if len(parts) == 2 {
		return &model.Instruction{
			Type:    instType,
			Raw:     raw,
			Content: fmt.Sprintf("%s %s", parts[0], parts[1]),
		}
	}
	// BuildKit format: "source dest [flags]"
	return &model.Instruction{Type: instType, Raw: raw, Content: arg}
}

// parseEnv handles ENV instructions.
func parseEnv(raw, arg string) *model.Instruction {
	kvp := make(map[string]string)
	if idx := strings.IndexByte(arg, '='); idx >= 0 {
		kvp[arg[:idx]] = arg[idx+1:]
	} else {
		parts := strings.SplitN(arg, " ", 2)
		if len(parts) == 2 {
			kvp[parts[0]] = parts[1]
		} else {
			kvp[arg] = ""
		}
	}
	return &model.Instruction{Type: model.InstENV, Raw: raw, KVPairs: kvp}
}

// parseCmdEntrypoint handles CMD/ENTRYPOINT/SHELL/VOLUME.
func parseCmdEntrypoint(raw string, instType model.InstructionType, arg string) *model.Instruction {
	var args []string
	if err := json.Unmarshal([]byte(arg), &args); err == nil {
		return &model.Instruction{Type: instType, Raw: raw, Args: args}
	}
	return &model.Instruction{Type: instType, Raw: raw, Content: arg}
}

// parseLabel handles LABEL instructions.
func parseLabel(raw, arg string) *model.Instruction {
	kvp := make(map[string]string)
	if idx := strings.IndexByte(arg, '='); idx >= 0 {
		kvp[arg[:idx]] = arg[idx+1:]
	}
	return &model.Instruction{Type: model.InstLABEL, Raw: raw, KVPairs: kvp}
}
