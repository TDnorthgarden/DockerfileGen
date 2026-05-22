package model

// InstructionType enumerates the Dockerfile instructions we can reconstruct.
type InstructionType string

const (
	InstFROM       InstructionType = "FROM"
	InstRUN        InstructionType = "RUN"
	InstCOPY       InstructionType = "COPY"
	InstADD        InstructionType = "ADD"
	InstWORKDIR    InstructionType = "WORKDIR"
	InstENV        InstructionType = "ENV"
	InstEXPOSE     InstructionType = "EXPOSE"
	InstCMD        InstructionType = "CMD"
	InstENTRYPOINT InstructionType = "ENTRYPOINT"
	InstLABEL      InstructionType = "LABEL"
	InstUSER       InstructionType = "USER"
	InstCOMMENT    InstructionType = "COMMENT"
	InstSTOPSIGNAL InstructionType = "STOPSIGNAL"
	InstARG        InstructionType = "ARG"
	InstSHELL      InstructionType = "SHELL"
	InstVOLUME     InstructionType = "VOLUME"
	InstONBUILD    InstructionType = "ONBUILD"
	InstHEALTHCHECK InstructionType = "HEALTHCHECK"
)

// Instruction represents a single reconstructed Dockerfile line.
type Instruction struct {
	Type    InstructionType
	Raw     string            // original CreatedBy string from history
	Content string            // instruction body (e.g., "apt-get update && apt-get install -y curl")
	Args    []string          // structured args for CMD, ENTRYPOINT
	KVPairs map[string]string // for ENV, LABEL
}

// ImageMetadata holds top-level image config fields that map to Dockerfile directives.
type ImageMetadata struct {
	BaseImageRef string            // resolved FROM reference (tag + optional @sha256:...)
	EnvVars      map[string]string // from Config.Env
	ExposedPorts []string          // from Config.ExposedPorts
	Cmd          []string          // from Config.Cmd
	Entrypoint   []string          // from Config.Entrypoint
	WorkingDir   string            // from Config.WorkingDir
	Labels       map[string]string // from Config.Labels
	User         string            // from Config.User
	StopSignal   string            // from Config.StopSignal
	Volumes      []string          // from Config.Volumes
}

// Dockerfile represents the complete reconstructed Dockerfile.
type Dockerfile struct {
	Meta         ImageMetadata
	Instructions []Instruction // ordered, from History
}
