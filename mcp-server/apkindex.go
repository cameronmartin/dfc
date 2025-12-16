/*
Copyright 2025 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
)

const (
	// wolfiAPKINDEXURLTemplate is the URL template for Wolfi's APKINDEX
	wolfiAPKINDEXURLTemplate = "https://packages.wolfi.dev/os/%s/APKINDEX.tar.gz"

	// cacheTTL is how long the cached APKINDEX is considered fresh
	cacheTTL = 24 * time.Hour

	// cacheSubdir is the subdirectory within XDG cache for APKINDEX data
	cacheSubdir = "dev.chainguard.dfc/apkindex"
)

// WolfiPackage represents metadata for a Wolfi package
type WolfiPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Origin      string `json:"origin"`
	URL         string `json:"url"`
}

// apkindexCache manages the cached APKINDEX data
type apkindexCache struct {
	mu           sync.RWMutex
	packages     map[string]*WolfiPackage
	lastUpdated  time.Time
	cacheDir     string
	architecture string
}

// globalCache is the singleton cache instance
var globalCache *apkindexCache
var cacheOnce sync.Once

// getCache returns the singleton cache instance
func getCache() *apkindexCache {
	cacheOnce.Do(func() {
		arch := runtime.GOARCH
		// Map Go arch names to Alpine/Wolfi arch names
		switch arch {
		case "amd64":
			arch = "x86_64"
		case "arm64":
			arch = "aarch64"
		}

		globalCache = &apkindexCache{
			packages:     make(map[string]*WolfiPackage),
			cacheDir:     filepath.Join(xdg.CacheHome, cacheSubdir),
			architecture: arch,
		}
	})
	return globalCache
}

// getCacheFilePath returns the path to the cached APKINDEX file
func (c *apkindexCache) getCacheFilePath() string {
	return filepath.Join(c.cacheDir, fmt.Sprintf("APKINDEX-%s.txt", c.architecture))
}

// getTimestampFilePath returns the path to the timestamp file
func (c *apkindexCache) getTimestampFilePath() string {
	return filepath.Join(c.cacheDir, fmt.Sprintf("APKINDEX-%s.timestamp", c.architecture))
}

// isCacheFresh checks if the cache is within TTL
func (c *apkindexCache) isCacheFresh() bool {
	c.mu.RLock()
	lastUpdated := c.lastUpdated
	c.mu.RUnlock()

	if lastUpdated.IsZero() {
		// Try to load timestamp from disk
		timestampFile := c.getTimestampFilePath()
		data, err := os.ReadFile(timestampFile)
		if err != nil {
			return false
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
		if err != nil {
			return false
		}
		c.mu.Lock()
		c.lastUpdated = t
		lastUpdated = t
		c.mu.Unlock()
	}

	return time.Since(lastUpdated) < cacheTTL
}

// loadFromDisk loads the cached APKINDEX from disk
func (c *apkindexCache) loadFromDisk() error {
	cacheFile := c.getCacheFilePath()
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("reading cache file: %w", err)
	}

	packages, err := parseAPKINDEXContent(string(data))
	if err != nil {
		return fmt.Errorf("parsing cached APKINDEX: %w", err)
	}

	c.mu.Lock()
	c.packages = packages
	c.mu.Unlock()

	// Load timestamp
	timestampFile := c.getTimestampFilePath()
	timestampData, err := os.ReadFile(timestampFile)
	if err == nil {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(timestampData)))
		if err == nil {
			c.mu.Lock()
			c.lastUpdated = t
			c.mu.Unlock()
		}
	}

	return nil
}

// saveToDisk saves the APKINDEX content to disk
func (c *apkindexCache) saveToDisk(content string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	// Write APKINDEX content
	cacheFile := c.getCacheFilePath()
	if err := os.WriteFile(cacheFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("writing cache file: %w", err)
	}

	// Write timestamp
	timestampFile := c.getTimestampFilePath()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	if err := os.WriteFile(timestampFile, []byte(timestamp), 0600); err != nil {
		return fmt.Errorf("writing timestamp file: %w", err)
	}

	return nil
}

// downloadAPKINDEX downloads the APKINDEX from Wolfi's repository
func (c *apkindexCache) downloadAPKINDEX(ctx context.Context) (string, error) {
	url := fmt.Sprintf(wolfiAPKINDEXURLTemplate, c.architecture)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "dfc-mcp/"+Version)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching APKINDEX: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// The response is a tar.gz file, we need to extract the APKINDEX file
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tar: %w", err)
		}

		if header.Name == "APKINDEX" {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return "", fmt.Errorf("reading APKINDEX: %w", err)
			}
			return string(content), nil
		}
	}

	return "", fmt.Errorf("APKINDEX not found in archive")
}

// refresh updates the cache from the network or loads from disk
func (c *apkindexCache) refresh(ctx context.Context) error {
	// If cache is fresh and loaded in memory, nothing to do
	if c.isCacheFresh() && len(c.packages) > 0 {
		return nil
	}

	// Try to download fresh data
	content, err := c.downloadAPKINDEX(ctx)
	if err != nil {
		// Network failed, try to use local cache regardless of TTL
		if loadErr := c.loadFromDisk(); loadErr != nil {
			return fmt.Errorf("network error (%v) and no local cache available: %w", err, loadErr)
		}
		return nil // Using stale cache
	}

	// Parse the downloaded content
	packages, err := parseAPKINDEXContent(content)
	if err != nil {
		return fmt.Errorf("parsing APKINDEX: %w", err)
	}

	// Update in-memory cache
	c.mu.Lock()
	c.packages = packages
	c.lastUpdated = time.Now()
	c.mu.Unlock()

	// Save to disk
	if err := c.saveToDisk(content); err != nil {
		// Log but don't fail - we have the data in memory
		fmt.Fprintf(os.Stderr, "[dfc-mcp] Warning: failed to save cache to disk: %v\n", err)
	}

	return nil
}

// parseAPKINDEXContent parses the APKINDEX text format
func parseAPKINDEXContent(content string) (map[string]*WolfiPackage, error) {
	packages := make(map[string]*WolfiPackage)
	scanner := bufio.NewScanner(strings.NewReader(content))

	var current *WolfiPackage
	for scanner.Scan() {
		line := scanner.Text()

		// Blank line means end of package record
		if line == "" {
			if current != nil && current.Name != "" {
				packages[current.Name] = current
			}
			current = nil
			continue
		}

		// Start new package if needed
		if current == nil {
			current = &WolfiPackage{}
		}

		// Parse field: format is "X:value" where X is a single letter
		if len(line) >= 2 && line[1] == ':' {
			key := line[0]
			value := line[2:]

			switch key {
			case 'P':
				current.Name = value
			case 'V':
				current.Version = value
			case 'T':
				current.Description = value
			case 'o':
				current.Origin = value
			case 'U':
				current.URL = value
			}
		}
	}

	// Don't forget the last package if file doesn't end with blank line
	if current != nil && current.Name != "" {
		packages[current.Name] = current
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning APKINDEX: %w", err)
	}

	return packages, nil
}

// LookupPackage looks up a package by name
func LookupPackage(ctx context.Context, name string) (*WolfiPackage, error) {
	cache := getCache()

	if err := cache.refresh(ctx); err != nil {
		return nil, err
	}

	cache.mu.RLock()
	pkg, ok := cache.packages[name]
	cache.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("package %q not found", name)
	}

	return pkg, nil
}

// PackageToJSON converts a WolfiPackage to JSON string
func PackageToJSON(pkg *WolfiPackage) (string, error) {
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling package to JSON: %w", err)
	}
	return string(data), nil
}

// SearchResult represents a search match with scoring information
type SearchResult struct {
	Package   *WolfiPackage `json:"package"`
	MatchType string        `json:"match_type"` // "exact", "prefix", "contains", "fuzzy", "description"
	Score     int           `json:"score"`      // lower is better
}

// SearchResponse is the response structure for search results
type SearchResponse struct {
	Results      []SearchResult `json:"results"`
	TotalMatches int            `json:"total_matches"`
}

// levenshteinDistance calculates the edit distance between two strings
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

// SearchPackages searches for packages matching the query
func SearchPackages(ctx context.Context, query string, limit int, searchDescription bool) (*SearchResponse, error) {
	cache := getCache()

	if err := cache.refresh(ctx); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 10
	}

	query = strings.ToLower(query)
	var results []SearchResult

	cache.mu.RLock()
	for _, pkg := range cache.packages {
		nameLower := strings.ToLower(pkg.Name)
		descLower := strings.ToLower(pkg.Description)

		var matchType string
		var score int

		// Check match types in priority order
		if nameLower == query {
			// Exact match - highest priority
			matchType = "exact"
			score = 0
		} else if strings.HasPrefix(nameLower, query) {
			// Prefix match
			matchType = "prefix"
			score = 100 + len(nameLower) - len(query) // shorter names score better
		} else if strings.Contains(nameLower, query) {
			// Contains match
			matchType = "contains"
			score = 200 + strings.Index(nameLower, query) // earlier position scores better
		} else {
			// Fuzzy match - only if query is reasonably close
			distance := levenshteinDistance(nameLower, query)
			maxDistance := len(query) / 2 // allow up to 50% edit distance
			if maxDistance < 2 {
				maxDistance = 2
			}
			if distance <= maxDistance {
				matchType = "fuzzy"
				score = 300 + distance*10
			}
		}

		// Check description if enabled and no name match found
		if matchType == "" && searchDescription && descLower != "" {
			if strings.Contains(descLower, query) {
				matchType = "description"
				score = 400 + strings.Index(descLower, query)
			}
		}

		if matchType != "" {
			results = append(results, SearchResult{
				Package:   pkg,
				MatchType: matchType,
				Score:     score,
			})
		}
	}
	cache.mu.RUnlock()

	// Sort by score (lower is better)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score < results[j].Score
		}
		// Tie-breaker: alphabetical by name
		return results[i].Package.Name < results[j].Package.Name
	})

	totalMatches := len(results)

	// Apply limit
	if len(results) > limit {
		results = results[:limit]
	}

	return &SearchResponse{
		Results:      results,
		TotalMatches: totalMatches,
	}, nil
}
