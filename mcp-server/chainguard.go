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
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
)

const (
	chainguardCacheTTL    = 24 * time.Hour
	chainguardCacheSubdir = "dev.chainguard.dfc/chainguard"
	chainguardAPIEndpoint = "https://data.chainguard.dev/query?id=PrivateImageCatalog"
)

// ChainguardImage represents an image from the Chainguard catalog
type ChainguardImage struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

// ChainguardImageSearchResult represents a search result for Chainguard images
type ChainguardImageSearchResult struct {
	ChainguardImage string   `json:"chainguard_image"`
	MappedFrom      string   `json:"mapped_from,omitempty"` // only for mapped search
	Aliases         []string `json:"aliases,omitempty"`
	MatchType       string   `json:"match_type"`
	Score           int      `json:"score"`
	RecommendedTags []string `json:"recommended_tags,omitempty"`
}

// ChainguardSearchResponse is the response structure for image search results
type ChainguardSearchResponse struct {
	Results      []ChainguardImageSearchResult `json:"results"`
	TotalMatches int                           `json:"total_matches"`
}

// ChainguardTagsResponse is the response structure for image tags
type ChainguardTagsResponse struct {
	Image string   `json:"image"`
	Tags  []string `json:"tags"`
}

// chainguardCache holds the cached image catalog for an organization
type chainguardCache struct {
	mu           sync.RWMutex
	images       map[string]*ChainguardImage // keyed by image name
	lastFetch    time.Time
	organization string
	orgID        string // resolved UIDP
}

// Global cache map keyed by org name
var (
	orgCaches   = make(map[string]*chainguardCache)
	orgCachesMu sync.RWMutex
)

// getOrCreateCache returns or creates a cache for the given organization
func getOrCreateCache(orgName string) *chainguardCache {
	orgCachesMu.Lock()
	defer orgCachesMu.Unlock()

	if cache, exists := orgCaches[orgName]; exists {
		return cache
	}

	cache := &chainguardCache{
		images:       make(map[string]*ChainguardImage),
		organization: orgName,
	}
	orgCaches[orgName] = cache
	return cache
}

// getChainctlToken retrieves an auth token using chainctl
func getChainctlToken(ctx context.Context) (string, error) {
	chainctlPath, err := exec.LookPath("chainctl")
	if err != nil {
		return "", fmt.Errorf("chainctl not found in PATH: %w (install from https://edu.chainguard.dev/chainguard/administration/how-to-install-chainctl/)", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, chainctlPath, "auth", "token")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("chainctl auth token timed out after 30 seconds")
		}
		return "", fmt.Errorf("chainctl auth token failed: %w (stderr: %s)", err, stderr.String())
	}

	// The token is returned as "Authorization: Bearer <token>"
	token := strings.TrimSpace(stdout.String())
	if token == "" {
		return "", fmt.Errorf("chainctl returned empty token")
	}

	return token, nil
}

// chainctlOrg represents an organization from chainctl output
type chainctlOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// chainctlOrgListResponse represents the response from chainctl iam organizations list
type chainctlOrgListResponse struct {
	Items []chainctlOrg `json:"items"`
}

// ChainguardOrganization represents a Chainguard organization
type ChainguardOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListChainguardOrganizations lists all Chainguard organizations the user has access to
func ListChainguardOrganizations(ctx context.Context) ([]ChainguardOrganization, error) {
	chainctlPath, err := exec.LookPath("chainctl")
	if err != nil {
		return nil, fmt.Errorf("chainctl not found in PATH: %w (install from https://edu.chainguard.dev/chainguard/administration/how-to-install-chainctl/)", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, chainctlPath, "iam", "organizations", "list", "-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("chainctl timed out after 30 seconds")
		}
		return nil, fmt.Errorf("chainctl iam organizations list failed: %w (stderr: %s)", err, stderr.String())
	}

	var response chainctlOrgListResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("failed to parse chainctl output: %w", err)
	}

	orgs := make([]ChainguardOrganization, len(response.Items))
	for i, item := range response.Items {
		orgs[i] = ChainguardOrganization{
			ID:   item.ID,
			Name: item.Name,
		}
	}

	return orgs, nil
}

// resolveOrgID resolves an organization name to its UIDP
func resolveOrgID(ctx context.Context, orgName string) (string, error) {
	chainctlPath, err := exec.LookPath("chainctl")
	if err != nil {
		return "", fmt.Errorf("chainctl not found in PATH: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, chainctlPath, "iam", "organizations", "list", "-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("chainctl timed out after 30 seconds")
		}
		return "", fmt.Errorf("chainctl iam organizations list failed: %w (stderr: %s)", err, stderr.String())
	}

	var response chainctlOrgListResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return "", fmt.Errorf("failed to parse chainctl output: %w", err)
	}

	for _, org := range response.Items {
		if strings.EqualFold(org.Name, orgName) {
			return org.ID, nil
		}
	}

	return "", fmt.Errorf("organization %q not found", orgName)
}

// graphQLRequest represents a GraphQL request body
type graphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

// graphQLResponse represents the response from the Chainguard API
type graphQLResponse struct {
	Data struct {
		Repos []struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"repos"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// fetchImageCatalog fetches the image catalog from the Chainguard API
func fetchImageCatalog(ctx context.Context, orgID string, token string) (map[string]*ChainguardImage, error) {
	query := `query OrganizationImageCatalog($organization: ID!) {
  repos(filter: {uidp: {childrenOf: $organization}}) {
    name
    aliases
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"organization":  orgID,
			"excludeDates":  true,
			"excludeEpochs": true,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", chainguardAPIEndpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var gqlResp graphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	images := make(map[string]*ChainguardImage)
	for _, repo := range gqlResp.Data.Repos {
		images[repo.Name] = &ChainguardImage{
			Name:    repo.Name,
			Aliases: repo.Aliases,
		}
	}

	return images, nil
}

// getCacheDir returns the cache directory for an organization
func (c *chainguardCache) getCacheDir() string {
	return filepath.Join(xdg.CacheHome, chainguardCacheSubdir, c.organization)
}

// getCacheFilePath returns the path to the catalog cache file
func (c *chainguardCache) getCacheFilePath() string {
	return filepath.Join(c.getCacheDir(), "catalog.json")
}

// getTimestampFilePath returns the path to the timestamp file
func (c *chainguardCache) getTimestampFilePath() string {
	return filepath.Join(c.getCacheDir(), "catalog.timestamp")
}

// diskCacheData represents the data stored on disk
type diskCacheData struct {
	Images map[string]*ChainguardImage `json:"images"`
	OrgID  string                      `json:"org_id"`
}

// loadFromDisk loads the cache from disk
func (c *chainguardCache) loadFromDisk() error {
	cacheFile := c.getCacheFilePath()
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return err
	}

	var cacheData diskCacheData
	if err := json.Unmarshal(data, &cacheData); err != nil {
		return err
	}

	// Load timestamp
	timestampFile := c.getTimestampFilePath()
	timestampData, err := os.ReadFile(timestampFile)
	if err != nil {
		return err
	}

	timestamp, err := time.Parse(time.RFC3339, strings.TrimSpace(string(timestampData)))
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.images = cacheData.Images
	c.orgID = cacheData.OrgID
	c.lastFetch = timestamp
	c.mu.Unlock()

	return nil
}

// saveToDisk saves the cache to disk
func (c *chainguardCache) saveToDisk() error {
	cacheDir := c.getCacheDir()
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}

	c.mu.RLock()
	cacheData := diskCacheData{
		Images: c.images,
		OrgID:  c.orgID,
	}
	timestamp := c.lastFetch
	c.mu.RUnlock()

	data, err := json.MarshalIndent(cacheData, "", "  ")
	if err != nil {
		return err
	}

	cacheFile := c.getCacheFilePath()
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return err
	}

	timestampFile := c.getTimestampFilePath()
	return os.WriteFile(timestampFile, []byte(timestamp.Format(time.RFC3339)), 0644)
}

// isCacheFresh checks if the cache is fresh
func (c *chainguardCache) isCacheFresh() bool {
	c.mu.RLock()
	lastFetch := c.lastFetch
	hasImages := len(c.images) > 0
	c.mu.RUnlock()

	if hasImages && time.Since(lastFetch) < chainguardCacheTTL {
		return true
	}

	// Try loading from disk
	if err := c.loadFromDisk(); err == nil {
		c.mu.RLock()
		fresh := time.Since(c.lastFetch) < chainguardCacheTTL
		c.mu.RUnlock()
		return fresh
	}

	return false
}

// refresh refreshes the cache if needed
func (c *chainguardCache) refresh(ctx context.Context) error {
	if c.isCacheFresh() {
		return nil
	}

	// Get auth token
	token, err := getChainctlToken(ctx)
	if err != nil {
		// Try to use disk cache on auth failure
		if loadErr := c.loadFromDisk(); loadErr == nil {
			return nil
		}
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Resolve org ID if not cached
	c.mu.RLock()
	orgID := c.orgID
	c.mu.RUnlock()

	if orgID == "" {
		resolvedID, err := resolveOrgID(ctx, c.organization)
		if err != nil {
			// Try to use disk cache
			if loadErr := c.loadFromDisk(); loadErr == nil {
				return nil
			}
			return fmt.Errorf("failed to resolve organization: %w", err)
		}
		orgID = resolvedID
	}

	// Fetch catalog
	images, err := fetchImageCatalog(ctx, orgID, token)
	if err != nil {
		// Try to use disk cache on fetch failure
		if loadErr := c.loadFromDisk(); loadErr == nil {
			return nil
		}
		return fmt.Errorf("failed to fetch catalog: %w", err)
	}

	// Update cache
	c.mu.Lock()
	c.images = images
	c.orgID = orgID
	c.lastFetch = time.Now()
	c.mu.Unlock()

	// Save to disk (non-fatal if this fails)
	if err := c.saveToDisk(); err != nil {
		// Log but don't fail
		fmt.Fprintf(os.Stderr, "[dfc-mcp] Warning: failed to save cache to disk: %v\n", err)
	}

	return nil
}

// SearchChainguardImages searches for images in the Chainguard catalog
func SearchChainguardImages(ctx context.Context, org, query, searchType string, limit int) (*ChainguardSearchResponse, error) {
	cache := getOrCreateCache(org)

	if err := cache.refresh(ctx); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 10
	}

	query = strings.ToLower(query)
	var results []ChainguardImageSearchResult

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	if searchType == "mapped" {
		// Search by aliases
		for _, img := range cache.images {
			for _, alias := range img.Aliases {
				aliasLower := strings.ToLower(alias)

				var matchType string
				var score int

				if aliasLower == query {
					matchType = "exact"
					score = 0
				} else if strings.HasPrefix(aliasLower, query) {
					matchType = "prefix"
					score = 100 + len(aliasLower) - len(query)
				} else if strings.Contains(aliasLower, query) {
					matchType = "contains"
					score = 200 + strings.Index(aliasLower, query)
				} else {
					distance := levenshteinDistance(aliasLower, query)
					maxDistance := len(query) / 2
					if maxDistance < 2 {
						maxDistance = 2
					}
					if distance <= maxDistance {
						matchType = "fuzzy"
						score = 300 + distance*10
					}
				}

				if matchType != "" {
					results = append(results, ChainguardImageSearchResult{
						ChainguardImage: img.Name,
						MappedFrom:      alias,
						Aliases:         img.Aliases,
						MatchType:       matchType,
						Score:           score,
					})
					break // Only one match per image
				}
			}
		}
	} else {
		// Search by Chainguard image name
		for _, img := range cache.images {
			nameLower := strings.ToLower(img.Name)

			var matchType string
			var score int

			if nameLower == query {
				matchType = "exact"
				score = 0
			} else if strings.HasPrefix(nameLower, query) {
				matchType = "prefix"
				score = 100 + len(nameLower) - len(query)
			} else if strings.Contains(nameLower, query) {
				matchType = "contains"
				score = 200 + strings.Index(nameLower, query)
			} else {
				distance := levenshteinDistance(nameLower, query)
				maxDistance := len(query) / 2
				if maxDistance < 2 {
					maxDistance = 2
				}
				if distance <= maxDistance {
					matchType = "fuzzy"
					score = 300 + distance*10
				}
			}

			if matchType != "" {
				results = append(results, ChainguardImageSearchResult{
					ChainguardImage: img.Name,
					Aliases:         img.Aliases,
					MatchType:       matchType,
					Score:           score,
				})
			}
		}
	}

	// Sort by score (lower is better)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score < results[j].Score
		}
		return results[i].ChainguardImage < results[j].ChainguardImage
	})

	totalMatches := len(results)

	if len(results) > limit {
		results = results[:limit]
	}

	return &ChainguardSearchResponse{
		Results:      results,
		TotalMatches: totalMatches,
	}, nil
}

// filterRecommendedTags filters tags to return only useful ones (excludes signatures, attestations, SBOMs)
// If queryTag is provided, tags are sorted by semantic similarity to it
// If queryTag is empty, "latest" tags are prioritized
func filterRecommendedTags(tags []string, limit int, queryTag string) []string {
	var filtered []string

	for _, tag := range tags {
		// Skip sha256 digest tags
		if strings.HasPrefix(tag, "sha256-") {
			continue
		}

		// Skip attestation/signature/SBOM tags
		if strings.HasSuffix(tag, ".att") || strings.HasSuffix(tag, ".sbom") || strings.HasSuffix(tag, ".sig") {
			continue
		}

		// Skip tags that look like signatures (contain sig or attestation markers)
		tagLower := strings.ToLower(tag)
		if strings.Contains(tagLower, ".sig") || strings.Contains(tagLower, ".att") {
			continue
		}

		filtered = append(filtered, tag)
	}

	// Sort tags based on query
	if queryTag == "" {
		// No tag in query - prioritize latest, then by length
		sort.Slice(filtered, func(i, j int) bool {
			iIsLatest := strings.HasPrefix(filtered[i], "latest")
			jIsLatest := strings.HasPrefix(filtered[j], "latest")
			if iIsLatest && !jIsLatest {
				return true
			}
			if !iIsLatest && jIsLatest {
				return false
			}

			// Prioritize shorter tags (usually more significant versions)
			if len(filtered[i]) != len(filtered[j]) {
				return len(filtered[i]) < len(filtered[j])
			}

			return filtered[i] < filtered[j]
		})
	} else {
		// Tag in query - sort by semantic similarity
		sort.Slice(filtered, func(i, j int) bool {
			scoreI := tagSimilarityScore(filtered[i], queryTag)
			scoreJ := tagSimilarityScore(filtered[j], queryTag)
			if scoreI != scoreJ {
				return scoreI < scoreJ // lower score is better
			}
			// Tie-breaker: shorter tags first, then alphabetical
			if len(filtered[i]) != len(filtered[j]) {
				return len(filtered[i]) < len(filtered[j])
			}
			return filtered[i] < filtered[j]
		})
	}

	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return filtered
}

// tagSimilarityScore calculates how similar a tag is to the query tag
// Lower score = more similar
func tagSimilarityScore(tag, queryTag string) int {
	// Exact match
	if tag == queryTag {
		return 0
	}

	// Extract version components for comparison
	queryParts := parseVersionParts(queryTag)
	tagParts := parseVersionParts(tag)

	// If query has version parts, match on them
	if len(queryParts) > 0 && len(tagParts) > 0 {
		// Check if major version matches
		if queryParts[0] == tagParts[0] {
			// Major matches - check minor
			if len(queryParts) > 1 && len(tagParts) > 1 {
				if queryParts[1] == tagParts[1] {
					// Major.minor matches - check patch
					if len(queryParts) > 2 && len(tagParts) > 2 {
						if queryParts[2] == tagParts[2] {
							return 10 // exact version match
						}
						return 20 // same major.minor, different patch
					}
					return 15 // same major.minor
				}
				return 30 // same major, different minor
			}
			return 25 // same major only
		}
		return 100 // different major version
	}

	// Check for prefix match (e.g., "3.12" matches "3.12.1")
	if strings.HasPrefix(tag, queryTag) {
		return 5 + len(tag) - len(queryTag)
	}

	// Check for common prefix
	commonPrefix := 0
	minLen := len(tag)
	if len(queryTag) < minLen {
		minLen = len(queryTag)
	}
	for i := 0; i < minLen; i++ {
		if tag[i] == queryTag[i] {
			commonPrefix++
		} else {
			break
		}
	}
	if commonPrefix > 0 {
		return 50 + (len(queryTag) - commonPrefix)
	}

	// Fallback to levenshtein distance
	return 200 + levenshteinDistance(tag, queryTag)
}

// parseVersionParts extracts numeric version parts from a tag
// e.g., "3.12.1-alpine" -> ["3", "12", "1"]
func parseVersionParts(tag string) []string {
	var parts []string
	var current strings.Builder

	for _, c := range tag {
		if c >= '0' && c <= '9' {
			current.WriteRune(c)
		} else if current.Len() > 0 {
			parts = append(parts, current.String())
			current.Reset()
			// Stop at first non-numeric separator after getting some parts
			// This handles cases like "3.12-alpine" where we want ["3", "12"]
			if c != '.' && len(parts) > 0 {
				break
			}
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// fetchImageTags fetches tags for an image using crane (internal helper)
func fetchImageTags(ctx context.Context, org, image string) ([]string, error) {
	cranePath, err := exec.LookPath("crane")
	if err != nil {
		return nil, fmt.Errorf("crane not found in PATH: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	imageRef := fmt.Sprintf("cgr.dev/%s/%s", org, image)
	cmd := exec.CommandContext(ctx, cranePath, "ls", imageRef)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("crane timed out")
		}
		return nil, fmt.Errorf("crane ls failed: %w", err)
	}

	tagsOutput := strings.TrimSpace(stdout.String())
	if tagsOutput == "" {
		return []string{}, nil
	}

	return strings.Split(tagsOutput, "\n"), nil
}

// GetChainguardImageTags gets the available tags for a Chainguard image
func GetChainguardImageTags(ctx context.Context, org, image string) (*ChainguardTagsResponse, error) {
	cache := getOrCreateCache(org)

	// We need the org name for crane, but let's verify the image exists
	if err := cache.refresh(ctx); err != nil {
		return nil, err
	}

	cache.mu.RLock()
	_, exists := cache.images[image]
	cache.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("image %q not found in organization %q", image, org)
	}

	// Use crane to list tags
	cranePath, err := exec.LookPath("crane")
	if err != nil {
		return nil, fmt.Errorf("crane not found in PATH: %w (install from https://github.com/google/go-containerregistry/tree/main/cmd/crane)", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	imageRef := fmt.Sprintf("cgr.dev/%s/%s", org, image)
	cmd := exec.CommandContext(ctx, cranePath, "ls", imageRef)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("crane timed out after 2 minutes")
		}
		return nil, fmt.Errorf("crane ls failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse tags (one per line)
	tagsOutput := strings.TrimSpace(stdout.String())
	var tags []string
	if tagsOutput != "" {
		tags = strings.Split(tagsOutput, "\n")
	}

	return &ChainguardTagsResponse{
		Image: image,
		Tags:  tags,
	}, nil
}
