package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dockerfilegen",
	Short: "Reverse-engineer Dockerfiles from Docker images",
	Long:  "DockerfileGen scans Docker Hub images and automatically generates Dockerfiles by analyzing image layers and metadata.",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
