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

// SyftPackage represents a package found by Syft
type SyftPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SyftBinary represents a binary/executable found in the image
type SyftBinary struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// ImageAnalysisResult contains the analysis results from Syft
type ImageAnalysisResult struct {
	Image    string        `json:"image"`
	Packages []SyftPackage `json:"packages"`
	Binaries []SyftBinary  `json:"binaries"`
}

// ImageInfo contains comprehensive information about a container image
type ImageInfo struct {
	Image      string        `json:"image"`
	Packages   []SyftPackage `json:"packages"`
	Binaries   []SyftBinary  `json:"binaries"`
	Entrypoint []string      `json:"entrypoint,omitempty"`
	Cmd        []string      `json:"cmd,omitempty"`
	User       string        `json:"user,omitempty"`
	WorkingDir string        `json:"working_dir,omitempty"`
	Env        []string      `json:"env,omitempty"`
}

// syftJSONOutput represents the JSON output format from syft
type syftJSONOutput struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftLicense struct {
	Value string `json:"value"`
}

type syftArtifact struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Type      string        `json:"type"`
	Licenses  []syftLicense `json:"licenses,omitempty"`
	Locations []struct {
		Path string `json:"path"`
	} `json:"locations,omitempty"`
}

// AnalyzeImage uses Syft to analyze a container image and extract packages and binaries
func AnalyzeImage(ctx context.Context, imageRef string) (*ImageAnalysisResult, error) {
	// Validate image reference
	if imageRef == "" {
		return nil, fmt.Errorf("image reference cannot be empty")
	}

	// Check if syft is available
	syftPath, err := exec.LookPath("syft")
	if err != nil {
		return nil, fmt.Errorf("syft not found in PATH: %w (install from https://github.com/anchore/syft)", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Run syft with JSON output
	cmd := exec.CommandContext(ctx, syftPath, imageRef, "-o", "json", "--quiet")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("syft timed out after 5 minutes")
		}
		return nil, fmt.Errorf("syft failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse syft JSON output
	var syftOutput syftJSONOutput
	if err := json.Unmarshal(stdout.Bytes(), &syftOutput); err != nil {
		return nil, fmt.Errorf("failed to parse syft output: %w", err)
	}

	result := &ImageAnalysisResult{
		Image:    imageRef,
		Packages: []SyftPackage{},
		Binaries: []SyftBinary{},
	}

	// Process artifacts
	seenBinaries := make(map[string]bool)

	for _, artifact := range syftOutput.Artifacts {
		// Handle binary type separately
		if artifact.Type == "binary" {
			for _, loc := range artifact.Locations {
				if !seenBinaries[loc.Path] {
					seenBinaries[loc.Path] = true
					result.Binaries = append(result.Binaries, SyftBinary{
						Path: loc.Path,
						Name: artifact.Name,
					})
				}
			}
			continue
		}

		result.Packages = append(result.Packages, SyftPackage{
			Name:    artifact.Name,
			Version: artifact.Version,
		})
	}

	return result, nil
}

// GetImageInfo retrieves comprehensive image information including packages, binaries, and config
func GetImageInfo(ctx context.Context, imageRef string) (*ImageInfo, error) {
	if imageRef == "" {
		return nil, fmt.Errorf("image reference cannot be empty")
	}

	result := &ImageInfo{
		Image:    imageRef,
		Packages: []SyftPackage{},
		Binaries: []SyftBinary{},
	}

	// Get packages and binaries from Syft
	analysis, err := AnalyzeImage(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze image: %w", err)
	}
	result.Packages = analysis.Packages
	result.Binaries = analysis.Binaries

	// Get config from Crane
	config, err := GetImageConfig(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get image config: %w", err)
	}
	result.Entrypoint = config.Entrypoint
	result.Cmd = config.Cmd
	result.User = config.User
	result.WorkingDir = config.WorkingDir
	result.Env = config.Env

	return result, nil
}
