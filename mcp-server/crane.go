/*
Copyright 2025 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// ImageConfig represents the configuration details of a container image
type ImageConfig struct {
	Image      string   `json:"image"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	User       string   `json:"user,omitempty"`
	WorkingDir string   `json:"working_dir,omitempty"`
	Env        []string `json:"env,omitempty"`
}

// craneConfigOutput represents the JSON output from crane config
type craneConfigOutput struct {
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		User       string   `json:"User"`
		WorkingDir string   `json:"WorkingDir"`
		Env        []string `json:"Env"`
	} `json:"config"`
}

// GetImageConfig uses crane to get the configuration of a container image
func GetImageConfig(ctx context.Context, imageRef string) (*ImageConfig, error) {
	// Validate image reference
	if imageRef == "" {
		return nil, fmt.Errorf("image reference cannot be empty")
	}

	// Check if crane is available
	cranePath, err := exec.LookPath("crane")
	if err != nil {
		return nil, fmt.Errorf("crane not found in PATH: %w (install from https://github.com/google/go-containerregistry/tree/main/cmd/crane)", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Run crane config to get the image configuration
	cmd := exec.CommandContext(ctx, cranePath, "config", imageRef)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("crane timed out after 2 minutes")
		}
		return nil, fmt.Errorf("crane failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse crane JSON output
	var craneOutput craneConfigOutput
	if err := json.Unmarshal(stdout.Bytes(), &craneOutput); err != nil {
		return nil, fmt.Errorf("failed to parse crane output: %w", err)
	}

	result := &ImageConfig{
		Image:      imageRef,
		Entrypoint: craneOutput.Config.Entrypoint,
		Cmd:        craneOutput.Config.Cmd,
		User:       craneOutput.Config.User,
		WorkingDir: craneOutput.Config.WorkingDir,
		Env:        craneOutput.Config.Env,
	}

	return result, nil
}
