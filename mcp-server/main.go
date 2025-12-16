/*
Copyright 2025 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chainguard-dev/dfc/pkg/dfc"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Version information
const (
	Version = "dev"
)

func main() {
	// Set up logging to stderr for diagnostics
	logger := log.New(os.Stderr, "[dfc-mcp] ", log.LstdFlags)
	logger.Printf("Starting dfc MCP Server v%s", Version)

	// Create a context that listens for termination signals
	_, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create an MCP server instance
	s := server.NewMCPServer(
		"dfc - Dockerfile Converter",
		Version,
		server.WithLogging(),
		server.WithRecovery(),
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithInstructions(getConversionWorkflowInstructions()),
	)

	// Define the Dockerfile converter tool
	dockerfileConverterTool := mcp.NewTool("convert_dockerfile",
		mcp.WithDescription("Convert a Dockerfile to use Chainguard Images and APKs in FROM and RUN lines"),
		mcp.WithString("dockerfile_content",
			mcp.Required(),
			mcp.Description("The content of the Dockerfile to convert"),
		),
		mcp.WithString("organization",
			mcp.Description("The Chainguard organization to use (defaults to 'ORG')"),
		),
		mcp.WithString("registry",
			mcp.Description("Alternative registry to use instead of cgr.dev"),
		),
	)

	// Add a healthcheck tool for diagnostics
	healthcheckTool := mcp.NewTool("healthcheck",
		mcp.WithDescription("Check if the dfc MCP server is running correctly"),
	)

	// Add the handler for the Dockerfile converter tool
	s.AddTool(dockerfileConverterTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received convert_dockerfile request")

		// Extract parameters
		dockerfileContent, ok := request.Params.Arguments["dockerfile_content"].(string)
		if !ok || dockerfileContent == "" {
			logger.Printf("Error: Empty dockerfile content in request")
			return mcp.NewToolResultError("Dockerfile content cannot be empty"), nil
		}

		// Log a sample of the Dockerfile content (first 50 chars)
		contentPreview := dockerfileContent
		if len(contentPreview) > 50 {
			contentPreview = contentPreview[:50] + "..."
		}
		logger.Printf("Processing Dockerfile (preview): %s", contentPreview)

		// Extract optional parameters with defaults
		organization := "ORG"
		if org, ok := request.Params.Arguments["organization"].(string); ok && org != "" {
			organization = org
			logger.Printf("Using custom organization: %s", organization)
		}

		var registry string
		if reg, ok := request.Params.Arguments["registry"].(string); ok && reg != "" {
			registry = reg
			logger.Printf("Using custom registry: %s", registry)
		}

		// Convert the Dockerfile
		convertedDockerfile, err := convertDockerfile(ctx, dockerfileContent, organization, registry)
		if err != nil {
			logger.Printf("Error converting Dockerfile: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Error converting Dockerfile: %v", err)), nil
		}

		// Log success
		logger.Printf("Successfully converted Dockerfile (length: %d bytes)", len(convertedDockerfile))

		// Return the result
		return mcp.NewToolResultText(convertedDockerfile), nil
	})

	// Add the healthcheck handler
	s.AddTool(healthcheckTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received healthcheck request")

		// Create test Dockerfile content
		testDockerfile := "FROM alpine\nRUN apk add --no-cache curl"

		// Try a test conversion to ensure dfc package is working
		_, err := convertDockerfile(ctx, testDockerfile, "ORG", "")
		if err != nil {
			logger.Printf("Healthcheck failed: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Healthcheck failed: %v", err)), nil
		}

		// If we get here, all systems are operational
		statusInfo := map[string]interface{}{
			"status":      "ok",
			"version":     Version,
			"dfc_package": "operational",
		}

		statusJSON, _ := json.Marshal(statusInfo)
		return mcp.NewToolResultText(fmt.Sprintf("Healthcheck passed: %s", string(statusJSON))), nil
	})

	// Add a tool that analyzes a Dockerfile
	analyzeDockerfileTool := mcp.NewTool("analyze_dockerfile",
		mcp.WithDescription("Analyze a Dockerfile and provide information about its structure"),
		mcp.WithString("dockerfile_content",
			mcp.Required(),
			mcp.Description("The content of the Dockerfile to analyze"),
		),
	)

	// Add the analyzer handler
	s.AddTool(analyzeDockerfileTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received analyze_dockerfile request")

		// Extract parameters
		dockerfileContent, ok := request.Params.Arguments["dockerfile_content"].(string)
		if !ok || dockerfileContent == "" {
			logger.Printf("Error: Empty dockerfile content in analyze request")
			return mcp.NewToolResultError("Dockerfile content cannot be empty"), nil
		}

		// Parse the Dockerfile
		dockerfile, err := dfc.ParseDockerfile(ctx, []byte(dockerfileContent))
		if err != nil {
			logger.Printf("Error parsing Dockerfile for analysis: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Failed to parse Dockerfile: %v", err)), nil
		}

		// Analyze the Dockerfile
		stageCount := 0
		baseImages := []string{}
		packageManagers := map[string]bool{}

		for _, line := range dockerfile.Lines {
			if line.From != nil {
				stageCount++
				if line.From.Orig != "" {
					baseImages = append(baseImages, line.From.Orig)
				} else {
					baseImg := line.From.Base
					if line.From.Tag != "" {
						baseImg += ":" + line.From.Tag
					}
					baseImages = append(baseImages, baseImg)
				}
			}
			if line.Run != nil && line.Run.Manager != "" {
				packageManagers[string(line.Run.Manager)] = true
			}
		}

		// Build package manager list
		// TODO: something seems to be off here, returning "No package managers detected"
		packageManagerList := []string{}
		for pm := range packageManagers {
			packageManagerList = append(packageManagerList, pm)
		}

		// Build analysis text
		analysis := "Dockerfile Analysis:\n\n"
		analysis += fmt.Sprintf("- Total stages: %d\n", stageCount)
		analysis += fmt.Sprintf("- Base images: %s\n", strings.Join(baseImages, ", "))
		if len(packageManagerList) > 0 {
			analysis += fmt.Sprintf("- Package managers: %s\n", strings.Join(packageManagerList, ", "))
		} else {
			analysis += "- No package managers detected\n"
		}

		logger.Printf("Successfully analyzed Dockerfile: %d stages, %d base images",
			stageCount, len(baseImages))

		// Return the result
		return mcp.NewToolResultText(analysis), nil
	})

	// Define the Wolfi package search tool
	searchWolfiTool := mcp.NewTool("search_wolfi_packages",
		mcp.WithDescription("Search for Wolfi packages by name with fuzzy matching"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Search term to find packages"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of results to return (default 10)"),
		),
		mcp.WithBoolean("search_description",
			mcp.Description("Also search in package descriptions (default false)"),
		),
	)

	// Add the search handler
	s.AddTool(searchWolfiTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received search_wolfi_packages request")

		// Extract query (required)
		query, ok := request.Params.Arguments["query"].(string)
		if !ok || query == "" {
			return mcp.NewToolResultError("query parameter is required"), nil
		}

		// Extract limit (optional, default 10)
		limit := 10
		if l, ok := request.Params.Arguments["limit"].(float64); ok {
			limit = int(l)
		}

		// Extract search_description (optional, default false)
		searchDescription := false
		if sd, ok := request.Params.Arguments["search_description"].(bool); ok {
			searchDescription = sd
		}

		logger.Printf("Searching for %q (limit=%d, search_description=%v)", query, limit, searchDescription)

		// Perform search
		response, err := SearchPackages(ctx, query, limit, searchDescription)
		if err != nil {
			logger.Printf("Error searching packages: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Search failed: %v", err)), nil
		}

		// Convert to JSON
		jsonResult, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			logger.Printf("Error marshaling search results: %v", err)
			return mcp.NewToolResultError("Failed to format results"), nil
		}

		logger.Printf("Found %d matches (returning %d)", response.TotalMatches, len(response.Results))

		return mcp.NewToolResultText(string(jsonResult)), nil
	})

	// Define the consolidated image info tool
	imageInfoTool := mcp.NewTool("get_image_info",
		mcp.WithDescription("Get comprehensive container image information: packages, binaries, and config (entrypoint, cmd, user, workdir, env)"),
		mcp.WithString("image",
			mcp.Required(),
			mcp.Description("Container image reference (e.g., 'nginx:latest', 'cgr.dev/chainguard/go:latest')"),
		),
	)

	// Add the image info handler
	s.AddTool(imageInfoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received get_image_info request")

		// Extract image reference
		imageRef, ok := request.Params.Arguments["image"].(string)
		if !ok || imageRef == "" {
			return mcp.NewToolResultError("image parameter is required"), nil
		}

		logger.Printf("Getting info for image: %s", imageRef)

		// Get comprehensive image info
		result, err := GetImageInfo(ctx, imageRef)
		if err != nil {
			logger.Printf("Error getting image info: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get image info: %v", err)), nil
		}

		// Convert to JSON
		jsonResult, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			logger.Printf("Error marshaling image info: %v", err)
			return mcp.NewToolResultError("Failed to format results"), nil
		}

		logger.Printf("Found %d packages, %d binaries for %s",
			len(result.Packages), len(result.Binaries), imageRef)

		return mcp.NewToolResultText(string(jsonResult)), nil
	})

	// Define the Dockerfile build tool
	buildDockerfileTool := mcp.NewTool("build_dockerfile",
		mcp.WithDescription("Build a Dockerfile from a path and return success/failure status with output"),
		mcp.WithString("dockerfile_path",
			mcp.Required(),
			mcp.Description("The path to the Dockerfile to build"),
		),
		mcp.WithNumber("tail_lines",
			mcp.Description("Number of output lines to return on failure (default 50)"),
		),
	)

	// Add the build handler
	s.AddTool(buildDockerfileTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received build_dockerfile request")

		// Extract dockerfile path
		dockerfilePath, ok := request.Params.Arguments["dockerfile_path"].(string)
		if !ok || dockerfilePath == "" {
			return mcp.NewToolResultError("dockerfile_path parameter is required"), nil
		}

		// Extract tail_lines (optional, default 50)
		tailLines := 50
		if tl, ok := request.Params.Arguments["tail_lines"].(float64); ok {
			tailLines = int(tl)
		}

		logger.Printf("Building Dockerfile: %s", dockerfilePath)

		// Build the Dockerfile
		result, err := BuildDockerfile(ctx, dockerfilePath, tailLines)
		if err != nil {
			logger.Printf("Error building Dockerfile: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Build setup failed: %v", err)), nil
		}

		// Convert to JSON
		jsonResult, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			logger.Printf("Error marshaling build results: %v", err)
			return mcp.NewToolResultError("Failed to format results"), nil
		}

		if result.Success {
			logger.Printf("Build succeeded in %s", result.Duration)
		} else {
			logger.Printf("Build failed with exit code %d in %s", result.ExitCode, result.Duration)
		}

		return mcp.NewToolResultText(string(jsonResult)), nil
	})

	// Define the Chainguard image search tool
	searchChainguardTool := mcp.NewTool("search_chainguard_images",
		mcp.WithDescription("Search for Chainguard images by mapped name or direct name, optionally including recommended tags"),
		mcp.WithString("organization",
			mcp.Required(),
			mcp.Description("Chainguard organization name"),
		),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Search term to find images"),
		),
		mcp.WithString("search_type",
			mcp.Required(),
			mcp.Description("Search type: 'mapped' (search by alias) or 'chainguard' (search by image name)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of results to return (default 10)"),
		),
		mcp.WithBoolean("include_tags",
			mcp.Description("Include recommended tags for each result (default false, slower but more useful)"),
		),
		mcp.WithNumber("max_tags",
			mcp.Description("Maximum number of recommended tags per image (default 10)"),
		),
	)

	// Add the Chainguard search handler
	s.AddTool(searchChainguardTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received search_chainguard_images request")

		// Extract organization (required)
		organization, ok := request.Params.Arguments["organization"].(string)
		if !ok || organization == "" {
			return mcp.NewToolResultError("organization parameter is required"), nil
		}

		// Extract query (required)
		query, ok := request.Params.Arguments["query"].(string)
		if !ok || query == "" {
			return mcp.NewToolResultError("query parameter is required"), nil
		}

		// Extract search_type (required)
		searchType, ok := request.Params.Arguments["search_type"].(string)
		if !ok || searchType == "" {
			return mcp.NewToolResultError("search_type parameter is required"), nil
		}
		if searchType != "mapped" && searchType != "chainguard" {
			return mcp.NewToolResultError("search_type must be 'mapped' or 'chainguard'"), nil
		}

		// Extract limit (optional, default 10)
		limit := 10
		if l, ok := request.Params.Arguments["limit"].(float64); ok {
			limit = int(l)
		}

		// Extract include_tags (optional, default false)
		includeTags := false
		if it, ok := request.Params.Arguments["include_tags"].(bool); ok {
			includeTags = it
		}

		// Extract max_tags (optional, default 10)
		maxTags := 10
		if mt, ok := request.Params.Arguments["max_tags"].(float64); ok {
			maxTags = int(mt)
		}

		logger.Printf("Searching Chainguard images for %q in org %q (type=%s, limit=%d, include_tags=%v)", query, organization, searchType, limit, includeTags)

		// Perform search
		response, err := SearchChainguardImages(ctx, organization, query, searchType, limit)
		if err != nil {
			logger.Printf("Error searching Chainguard images: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Search failed: %v", err)), nil
		}

		// Optionally fetch tags for each result
		if includeTags {
			// Extract tag from query if present (e.g., "python:3.12" -> "3.12")
			queryTag := ""
			if idx := strings.Index(query, ":"); idx != -1 {
				queryTag = query[idx+1:]
			}

			for i := range response.Results {
				tags, err := fetchImageTags(ctx, organization, response.Results[i].ChainguardImage)
				if err != nil {
					logger.Printf("Warning: failed to fetch tags for %s: %v", response.Results[i].ChainguardImage, err)
					continue
				}
				response.Results[i].RecommendedTags = filterRecommendedTags(tags, maxTags, queryTag)
			}
		}

		// Convert to JSON
		jsonResult, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			logger.Printf("Error marshaling search results: %v", err)
			return mcp.NewToolResultError("Failed to format results"), nil
		}

		logger.Printf("Found %d matches (returning %d)", response.TotalMatches, len(response.Results))

		return mcp.NewToolResultText(string(jsonResult)), nil
	})

	// Define the Chainguard image tags tool
	chainguardTagsTool := mcp.NewTool("get_chainguard_image_tags",
		mcp.WithDescription("Get available tags for a Chainguard image"),
		mcp.WithString("organization",
			mcp.Required(),
			mcp.Description("Chainguard organization name"),
		),
		mcp.WithString("image",
			mcp.Required(),
			mcp.Description("Chainguard image name"),
		),
	)

	// Add the Chainguard tags handler
	s.AddTool(chainguardTagsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Printf("Received get_chainguard_image_tags request")

		// Extract organization (required)
		organization, ok := request.Params.Arguments["organization"].(string)
		if !ok || organization == "" {
			return mcp.NewToolResultError("organization parameter is required"), nil
		}

		// Extract image (required)
		image, ok := request.Params.Arguments["image"].(string)
		if !ok || image == "" {
			return mcp.NewToolResultError("image parameter is required"), nil
		}

		logger.Printf("Getting tags for %s/%s", organization, image)

		// Get tags
		response, err := GetChainguardImageTags(ctx, organization, image)
		if err != nil {
			logger.Printf("Error getting Chainguard image tags: %v", err)
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get tags: %v", err)), nil
		}

		// Convert to JSON
		jsonResult, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			logger.Printf("Error marshaling tags results: %v", err)
			return mcp.NewToolResultError("Failed to format results"), nil
		}

		logger.Printf("Found %d tags for %s", len(response.Tags), image)

		return mcp.NewToolResultText(string(jsonResult)), nil
	})

	// Define the Wolfi package resource template
	wolfiPackageTemplate := mcp.NewResourceTemplate(
		"wolfi://package/{name}",
		"Wolfi Package",
		mcp.WithTemplateDescription("Get metadata for a Wolfi package by name"),
		mcp.WithTemplateMIMEType("application/json"),
	)

	// Add the Wolfi package resource handler
	s.AddResourceTemplate(wolfiPackageTemplate, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		logger.Printf("Received wolfi package resource request: %s", request.Params.URI)

		// Extract package name from URI: wolfi://package/{name}
		uri := request.Params.URI
		const prefix = "wolfi://package/"
		if !strings.HasPrefix(uri, prefix) {
			return nil, fmt.Errorf("invalid URI format: %s", uri)
		}
		packageName := strings.TrimPrefix(uri, prefix)
		if packageName == "" {
			return nil, fmt.Errorf("package name cannot be empty")
		}

		// Look up the package
		pkg, err := LookupPackage(ctx, packageName)
		if err != nil {
			logger.Printf("Error looking up package %q: %v", packageName, err)
			return nil, err
		}

		// Convert to JSON
		jsonContent, err := PackageToJSON(pkg)
		if err != nil {
			logger.Printf("Error converting package to JSON: %v", err)
			return nil, err
		}

		logger.Printf("Successfully retrieved package %q", packageName)

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      uri,
				MIMEType: "application/json",
				Text:     jsonContent,
			},
		}, nil
	})

	// Define the Chainguard organizations resource
	chainguardOrgsResource := mcp.NewResource(
		"chainguard://organizations",
		"Chainguard Organizations",
		mcp.WithResourceDescription("List Chainguard organizations the user has access to"),
		mcp.WithMIMEType("application/json"),
	)

	// Add the Chainguard organizations resource handler
	s.AddResource(chainguardOrgsResource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		logger.Printf("Received chainguard organizations resource request")

		// Get the list of organizations using chainctl
		orgs, err := ListChainguardOrganizations(ctx)
		if err != nil {
			logger.Printf("Error listing Chainguard organizations: %v", err)
			return nil, err
		}

		// Convert to JSON
		jsonContent, err := json.MarshalIndent(orgs, "", "  ")
		if err != nil {
			logger.Printf("Error marshaling organizations: %v", err)
			return nil, err
		}

		logger.Printf("Successfully retrieved %d Chainguard organizations", len(orgs))

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "chainguard://organizations",
				MIMEType: "application/json",
				Text:     string(jsonContent),
			},
		}, nil
	})

	// Announce that we're ready to serve
	logger.Printf("MCP server initialization complete, ready to handle requests")

	// Start the server
	if err := server.ServeStdio(s); err != nil {
		logger.Printf("Server error: %v", err)
		os.Exit(1)
	}
}

// getConversionWorkflowInstructions returns the instructions for the Dockerfile conversion workflow
// These instructions are provided to the LLM when the MCP server is connected
func getConversionWorkflowInstructions() string {
	return `# Dockerfile Conversion Workflow

When the user asks to "convert" a Dockerfile to use Chainguard Images, follow this workflow:

## Available Tools:
- build_dockerfile: Build a Dockerfile and get success/failure with output
- convert_dockerfile: Convert Dockerfile to use Chainguard Images
- get_image_info: Get packages, binaries, entrypoint, cmd, user, env for an image
- search_wolfi_packages: Find Wolfi package names (different from apt/yum)
- search_chainguard_images: Search for Chainguard images by name or alias
- get_chainguard_image_tags: Get available tags for a Chainguard image

## Available Resources:
- chainguard://organizations: List Chainguard organizations the user has access to (returns org names and IDs)

## Workflow:

### Phase 1: Setup
1. **Identify Dockerfile**: Use IDE context or ask user for path
2. **Build original**: Call build_dockerfile on the Dockerfile - this validates the original works
3. **Analyze original image**: Once built successfully, use get_image_info on the built image to understand its packages, binaries, entrypoint, cmd, user, and environment. Save this for comparison.
4. **Get organization**: Read the chainguard://organizations resource to get the list of organizations the user has access to. Present the list and ask: "Which Chainguard organization would you like to use for the conversion?" If the user only has one organization, you can suggest using that one.
5. **Convert**: Read the Dockerfile, call convert_dockerfile with content and organization
6. **Save**: Write converted content to {dockerfile_path}.converted
7. **Build converted**: Call build_dockerfile on the converted file

### Phase 2: Iterative Error Resolution
If build fails:

1. **Analyze base image**: Use get_image_info on the Chainguard base image being used (e.g., cgr.dev/{org}/python:latest-dev) to understand what packages, binaries, and config it provides. Compare with the original image analysis from Phase 1. Only add missing binaries if the Dockerfile explicitly references them or the build fails due to their absence - do not speculatively add packages.

2. **Identify error type and fix**:

| Error Type | Symptoms | Solution |
|------------|----------|----------|
| Permission | "permission denied", "operation not permitted" | Check USER with get_image_info. Chainguard images run as non-root. Add USER root before apk add, then USER nonroot after to restore least privilege |
| Missing package | "package not found", "unable to locate" | Use search_wolfi_packages - names differ (python3 -> python-3). Compare packages between original and base image. |
| Missing binary | "not found", "no such file" | Compare binaries between original and base image using get_image_info. Use search_wolfi_packages to find provider package. |
| Shell issues | "/bin/bash: not found" | Use /bin/sh or add bash. Consider -dev variant |
| Entrypoint issues | App doesn't start | Compare entrypoints with get_image_info between original and converted |
| COPY ownership | Files copied with wrong owner | Use get_image_info to check target image's USER, then set USER before COPY or use --chown flag (e.g., COPY --chown=nonroot:nonroot) |
| COPY destination | Files copied to wrong location | Chainguard images may have different directory structures. Use get_image_info to check WORKDIR and env vars like $HOME. Verify destination paths exist and are appropriate for the new base image |

3. After each fix, rebuild and verify. Continue until successful.

### Phase 3: Variant Optimization
Once build succeeds:

**If final stage uses -dev variant:**
1. Use get_chainguard_image_tags to check what variants are available for the image
2. Only offer variants that actually exist as tags
3. If you want to describe whether a variant has a shell, use get_image_info to inspect the image first

Example prompt (adjust based on available tags):
"Your Dockerfile builds with the -dev variant. Would you like to optimize with a multi-stage build?
- **slim**: Smaller image (only offer if slim tag exists)
- **latest** (distroless): Base variant (use get_image_info to check if it has a shell)
- **keep -dev**: Keep current (has package manager for runtime installs)"

Note: slim variants are typically smaller than distroless/latest variants.

If user chooses an alternative variant:
1. Create multi-stage: build stage with -dev, runtime stage with chosen variant
2. Save to {dockerfile_path}.converted.{variant}
3. Build and verify

**If using chainguard-base:**
Analyze Dockerfile to identify application type (Python, Node, Go, etc.)
Ask: "You're using chainguard-base. Based on your Dockerfile, {specific-image} might be more appropriate. Would you like to try it?"

### Phase 4: Summary
Report:
- Original image capabilities (packages, binaries, config)
- Converted image capabilities
- Changes made during conversion
- Errors fixed and how
- Final image location
- Recommendation for production use`
}

// convertDockerfile converts a Dockerfile to use Chainguard Images and APKs
func convertDockerfile(ctx context.Context, dockerfileContent, organization, registry string) (string, error) {
	// Parse the Dockerfile
	dockerfile, err := dfc.ParseDockerfile(ctx, []byte(dockerfileContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse Dockerfile: %w", err)
	}

	// Create options for conversion
	opts := dfc.Options{
		Organization: organization,
	}

	// If registry is provided, set it in options
	if registry != "" {
		opts.Registry = registry
	}

	// Convert the Dockerfile
	converted, err := dockerfile.Convert(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("failed to convert Dockerfile: %w", err)
	}

	// Return the converted Dockerfile as a string
	return converted.String(), nil
}
