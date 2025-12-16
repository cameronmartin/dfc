/*
Copyright 2025 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DockerBuildResult represents the result of a docker build
type DockerBuildResult struct {
	Success        bool   `json:"success"`
	ExitCode       int    `json:"exit_code"`
	Output         string `json:"output,omitempty"`
	Error          string `json:"error,omitempty"`
	Duration       string `json:"duration"`
	ImageID        string `json:"image_id,omitempty"`
	TailLines      int    `json:"tail_lines,omitempty"`
	DockerfilePath string `json:"dockerfile_path"`
}

// BuildDockerfile builds a Dockerfile from a path and returns the result
func BuildDockerfile(ctx context.Context, dockerfilePath string, tailLines int) (*DockerBuildResult, error) {
	if dockerfilePath == "" {
		return nil, fmt.Errorf("dockerfile path cannot be empty")
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(dockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("dockerfile not found: %s", absPath)
	}

	if tailLines <= 0 {
		tailLines = 50
	}

	// Check if docker is available
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("docker not found in PATH: %w", err)
	}

	// Use the directory containing the Dockerfile as the build context
	contextDir := filepath.Dir(absPath)

	// Create context with timeout (10 minutes for build)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Run docker build with -f to specify the Dockerfile
	startTime := time.Now()
	cmd := exec.CommandContext(ctx, dockerPath, "build", "--progress=plain", "-f", absPath, contextDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	duration := time.Since(startTime)

	result := &DockerBuildResult{
		Duration:       duration.Round(time.Millisecond).String(),
		TailLines:      tailLines,
		DockerfilePath: absPath,
	}

	// Combine stdout and stderr for output
	combinedOutput := stdout.String() + stderr.String()

	if err != nil {
		result.Success = false

		// Get exit code
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			result.Error = "build timed out after 10 minutes"
			result.ExitCode = -1
		} else {
			result.ExitCode = -1
		}

		// Get the last N lines of output for error context
		result.Output = getLastNLines(combinedOutput, tailLines)
		if result.Error == "" {
			result.Error = fmt.Sprintf("docker build failed with exit code %d", result.ExitCode)
		}
	} else {
		result.Success = true
		result.ExitCode = 0

		// Try to extract the image ID from the output
		result.ImageID = extractImageID(combinedOutput)

		// For successful builds, just return a summary
		result.Output = "Build completed successfully"
	}

	return result, nil
}

// getLastNLines returns the last n lines of a string
func getLastNLines(s string, n int) string {
	lines := strings.Split(s, "\n")

	// Remove empty trailing line if present
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}

	return strings.Join(lines[len(lines)-n:], "\n")
}

// extractImageID tries to extract the image ID from docker build output
func extractImageID(output string) string {
	lines := strings.Split(output, "\n")

	// Look for patterns like "writing image sha256:..." or "Successfully built ..."
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])

		// BuildKit format: "writing image sha256:abc123..."
		if strings.Contains(line, "writing image sha256:") {
			parts := strings.Split(line, "sha256:")
			if len(parts) >= 2 {
				// Get the hash, which might have additional text after it
				hash := strings.Fields(parts[1])[0]
				if len(hash) >= 12 {
					return "sha256:" + hash[:12]
				}
			}
		}

		// Legacy format: "Successfully built abc123"
		if strings.HasPrefix(line, "Successfully built ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}

	return ""
}
