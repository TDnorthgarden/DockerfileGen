package generator

import (
	"fmt"
	"strings"

	"github.com/TDnorthgarden/DockerfileGen/internal/model"
)

// MergeRuns combines consecutive RUN instructions into a single RUN joined by "&&".
func MergeRuns(instructions []model.Instruction) []model.Instruction {
	if len(instructions) == 0 {
		return instructions
	}

	var result []model.Instruction
	var runBatch []string

	flush := func() {
		if len(runBatch) == 0 {
			return
		}
		merged := strings.Join(runBatch, " && \\\n    ")
		result = append(result, model.Instruction{
			Type:    model.InstRUN,
			Content: merged,
		})
		runBatch = nil
	}

	for _, inst := range instructions {
		if inst.Type == model.InstRUN {
			runBatch = append(runBatch, inst.Content)
		} else {
			flush()
			result = append(result, inst)
		}
	}
	flush()

	// Preserve raw field for merged instructions
	for i := range result {
		if result[i].Raw == "" {
			result[i].Raw = fmt.Sprintf("RUN %s", result[i].Content)
		}
	}

	return result
}
