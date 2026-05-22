package main

import (
	"os"

	"github.com/TDnorthgarden/DockerfileGen/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
