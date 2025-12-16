# dfc MCP Server

This is a Go implementation of an MCP (Model Context Protocol) server for `dfc`. It provides a standardized interface that allows AI assistants and other clients to convert Dockerfiles to use Chainguard Images and APKs through the stdio protocol.

![dfc MCP Server](demo-cursor.png)

## Features

- Full MCP protocol implementation with tools and resources
- Converts Dockerfiles to use Chainguard Images and Wolfi APKs
- Builds Dockerfiles and reports success/failure with detailed output
- Inspects container images for packages, binaries, and configuration
- Searches Wolfi packages with fuzzy matching
- Searches Chainguard images by name or alias with optional tag recommendations
- Lists available Chainguard organizations
- Provides guided workflow instructions for AI assistants
- Configurable organization and registry

## Tools

This MCP server provides the following tools:

### Dockerfile Conversion
- `convert_dockerfile` - Converts a Dockerfile to use Chainguard Images and APKs
- `analyze_dockerfile` - Analyzes a Dockerfile and provides information about its structure
- `build_dockerfile` - Builds a Dockerfile and returns success/failure status with output

### Image Inspection
- `get_image_info` - Get comprehensive container image information: packages, binaries, and config (entrypoint, cmd, user, workdir, env)

### Package Search
- `search_wolfi_packages` - Search for Wolfi packages by name with fuzzy matching

### Chainguard Registry
- `search_chainguard_images` - Search for Chainguard images by mapped name or direct name, optionally including recommended tags
- `get_chainguard_image_tags` - Get available tags for a Chainguard image

### Diagnostics
- `healthcheck` - Checks if the server is running correctly

## Resources

The MCP server also provides the following resources:

- `chainguard://organizations` - List Chainguard organizations the user has access to (returns org names and IDs)
- `wolfi://package/{name}` - Get metadata for a Wolfi package by name (resource template)

## Directory Structure

```
├── main.go           # Main MCP server implementation and tool handlers
├── apkindex.go       # Wolfi APKINDEX parsing and package search
├── chainguard.go     # Chainguard image search and organization listing
├── crane.go          # Container image tag fetching via crane
├── docker.go         # Dockerfile building functionality
├── syft.go           # Image inspection using syft (packages, binaries, config)
├── go.mod/go.sum     # Go module dependencies
├── Dockerfile        # Container definition
├── README.md         # Documentation
```

## Prerequisites

- Go 1.20 or higher

## Installation

Clone the repository:

```bash
git clone https://github.com/chainguard-dev/dfc.git
cd dfc/mcp-server
```

Build the server:

```bash
go build -o mcp-server .
```

Run the server:

```bash
./mcp-server
```

## Docker

You can also run the server in a Docker container:

```bash
docker build -t dfc-mcp-server .
docker run -p 3000:3000 dfc-mcp-server
```

## Configuring with AI Assistants

### Configuring in Claude Code

To use this server with Claude Code, run the following:

```
claude mcp add dfc -- /path/to/dfc/mcp-server/mcp-server
```

Then you can invoke the server by asking to convert a Dockerfile:

```
Can you convert the following Dockerfile to use Chainguard Images? https://raw.githubusercontent.com/django/djangoproject.com/refs/heads/main/Dockerfile
```

### Configuring in Cursor

To configure this MCP server in Cursor, add the following configuration to your Cursor settings:

```json
{
  "mcp.servers": [
    {
      "name": "Dockerfile Converter",
      "command": "path/to/dfc/mcp-server/mcp-server",
      "transport": "stdio"
    }
  ]
}
```

You can then invoke the Dockerfile converter tool from Cursor with commands like:

```
@dfc convert my Dockerfile to use Chainguard Images
```

### Configuring in Claude Desktop

To use this server with Claude Desktop, add the following to your `claude_desktop_config.json` file (typically found in your home directory):

```json
{
  "mcpServers": {
    "dfc": {
      "command": "/path/to/dfc/mcp-server/mcp-server",
      "transport": "stdio"
    }
  }
}
```

Then you can invoke the server in Claude Desktop using:

```
@dfc analyze this Dockerfile
```

### Configuring in Windsurf

To add this MCP server to Windsurf, follow these steps:

1. Open Windsurf and navigate to Settings
2. Find the "MCP Servers" section
3. Click "Add New Server"
4. Fill in the following details:
   - Name: `Dockerfile Converter`
   - Command: `/path/to/dfc/mcp-server/mcp-server`
   - Transport Type: `stdio`
5. Click "Save"

You can then invoke the tool in Windsurf using:

```
@dfc convert this Dockerfile
```

### Configuring with General MCP Clients

For other MCP clients or custom implementations, you'll need:

1. The path to the built `mcp-server` executable
2. Configuration for stdio transport
3. Tool names to invoke:
   - `convert_dockerfile` - Convert Dockerfiles to Chainguard
   - `analyze_dockerfile` - Analyze Dockerfile structure
   - `build_dockerfile` - Build and test Dockerfiles
   - `get_image_info` - Inspect container images
   - `search_wolfi_packages` - Find Wolfi packages
   - `search_chainguard_images` - Search Chainguard registry
   - `get_chainguard_image_tags` - Get image tags
   - `healthcheck` - Server health check

General configuration format for most MCP clients:

```json
{
  "servers": {
    "dfc": {
      "command": "/path/to/dfc/mcp-server/mcp-server",
      "transport": "stdio"
    }
  }
}
```

## API Usage

### Convert a Dockerfile

To convert a Dockerfile, provide the following parameters:

- `dockerfile_content` (required) - The content of the Dockerfile to convert
- `organization` (optional) - The Chainguard organization to use (defaults to 'ORG')
- `registry` (optional) - Alternative registry to use instead of cgr.dev

Example request:

```json
{
  "name": "convert_dockerfile",
  "arguments": {
    "dockerfile_content": "FROM alpine\nRUN apk add --no-cache curl",
    "organization": "mycorp",
    "registry": "registry.mycorp.com"
  }
}
```

### Analyze a Dockerfile

To analyze a Dockerfile, provide the following parameter:

- `dockerfile_content` (required) - The content of the Dockerfile to analyze

Example request:

```json
{
  "name": "analyze_dockerfile",
  "arguments": {
    "dockerfile_content": "FROM alpine\nRUN apk add --no-cache curl"
  }
}
```

### Build a Dockerfile

To build a Dockerfile and get the result:

- `dockerfile_path` (required) - The path to the Dockerfile to build
- `tail_lines` (optional) - Number of output lines to return on failure (default 50)

Example request:

```json
{
  "name": "build_dockerfile",
  "arguments": {
    "dockerfile_path": "/path/to/Dockerfile",
    "tail_lines": 100
  }
}
```

### Get Image Info

To get comprehensive information about a container image:

- `image` (required) - Container image reference (e.g., 'nginx:latest', 'cgr.dev/chainguard/python:latest')

Example request:

```json
{
  "name": "get_image_info",
  "arguments": {
    "image": "cgr.dev/chainguard/python:latest-dev"
  }
}
```

Returns packages, binaries, entrypoint, cmd, user, workdir, and environment variables.

### Search Wolfi Packages

To search for Wolfi packages:

- `query` (required) - Search term to find packages
- `limit` (optional) - Maximum number of results (default 10)
- `search_description` (optional) - Also search in package descriptions (default false)

Example request:

```json
{
  "name": "search_wolfi_packages",
  "arguments": {
    "query": "python",
    "limit": 5
  }
}
```

### Search Chainguard Images

To search for Chainguard images:

- `organization` (required) - Chainguard organization name
- `query` (required) - Search term to find images
- `search_type` (required) - 'mapped' (search by alias) or 'chainguard' (search by image name)
- `limit` (optional) - Maximum number of results (default 10)
- `include_tags` (optional) - Include recommended tags (default false, slower)
- `max_tags` (optional) - Maximum tags per image (default 10)

Example request:

```json
{
  "name": "search_chainguard_images",
  "arguments": {
    "organization": "mycorp",
    "query": "python",
    "search_type": "mapped",
    "include_tags": true
  }
}
```

### Get Chainguard Image Tags

To get available tags for a Chainguard image:

- `organization` (required) - Chainguard organization name
- `image` (required) - Chainguard image name

Example request:

```json
{
  "name": "get_chainguard_image_tags",
  "arguments": {
    "organization": "mycorp",
    "image": "python"
  }
}
```

## Development

When making changes, ensure the server follows the MCP protocol specification correctly. The server uses stdio for communication with clients.
