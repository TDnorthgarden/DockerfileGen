package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/TDnorthgarden/DockerfileGen/internal/analyzer"
	"github.com/TDnorthgarden/DockerfileGen/internal/generator"
	"github.com/TDnorthgarden/DockerfileGen/internal/image"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Docker image and generate a Dockerfile",
	Long: `Pulls image metadata from a registry or local file and reverse-engineers
a Dockerfile from the image history and configuration.

Supports three image sources:
  - Remote registry:  nginx:1.21-alpine, gcr.io/distroless/static:latest
  - Docker tarball:   ./image.tar (from docker save)
  - OCI layout dir:   ./oci-images/ (OCI image layout with index.json)

Source type is auto-detected from the reference format.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("image", "i", "", "Image reference: remote ref, .tar file, or OCI layout directory (required)")
	scanCmd.MarkFlagRequired("image")
	scanCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	scanCmd.Flags().Bool("merge-runs", false, "Merge consecutive RUN instructions")
}

func runScan(cmd *cobra.Command, args []string) error {
	imageRef, _ := cmd.Flags().GetString("image")
	outputPath, _ := cmd.Flags().GetString("output")
	mergeRuns, _ := cmd.Flags().GetBool("merge-runs")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Fetch image (auto-detects source type)
	sourceType := image.DetectSource(imageRef)
	sourceLabel := map[image.SourceType]string{
		image.SourceRemote:  "remote registry",
		image.SourceTarball: "tarball",
		image.SourceOCILayout: "OCI layout",
	}
	fmt.Fprintf(os.Stderr, "Fetching image %s (source: %s)...\n", imageRef, sourceLabel[sourceType])

	img, err := image.Fetch(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}

	// 2. Get config
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to read image config: %w", err)
	}

	// 3. Analyze
	meta := analyzer.ExtractMetadata(cfg, imageRef, img)
	instructions := analyzer.ParseHistory(cfg.History)

	fmt.Fprintf(os.Stderr, "Parsed %d history entries into %d instructions\n", len(cfg.History), len(instructions))

	// 4. Generate
	dockerfile := generator.Render(meta, instructions, mergeRuns)

	// 5. Output
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(dockerfile), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Dockerfile written to %s\n", outputPath)
	} else {
		fmt.Print(dockerfile)
	}

	return nil
}
