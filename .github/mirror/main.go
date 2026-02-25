package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	baseURL      = "https://detections.ai"
	authPath     = "/bff/api/v1/auth/refresh"
	discoverPath = "/bff/api/v1/detections/v2/discover"
	maxPageSize  = 500
	envToken     = "UPSTREAM_REFRESH_TOKEN"
)

// API response types

type authResponse struct {
	Data struct {
		AccessToken string `json:"access_token"`
	} `json:"data"`
}

type discoverRequest struct {
	Filters discoverFilters `json:"filters"`
	Options discoverOptions `json:"options"`
}

type discoverFilters struct {
	RuleTypes []string `json:"rule_types"`
}

type discoverOptions struct {
	Page int `json:"page"`
	Size int `json:"size"`
}

type discoverResponse struct {
	Data []apiRule `json:"data"`
}

type apiRule struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Content     string      `json:"content"`
	RuleType    string      `json:"rule_type"`
	Author      string      `json:"author"`
	Version     any         `json:"version"` // can be int or string
	Tags        []string    `json:"tags"`
	Metadata    apiMetadata `json:"metadata"`
	Contributor json.RawMessage `json:"contributor"`
}

type apiMetadata struct {
	Severity    string           `json:"severity"`
	MitreAttack []mitreReference `json:"mitre_attack"`
	References  []string         `json:"references"`
	DataSources []string         `json:"data_sources"`
}

type mitreReference struct {
	Type    string `json:"type"`    // "tactic", "technique", "subtechnique"
	MitreID string `json:"mitre_id"`
}

// Library YAML output types

type libraryEntry struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Query       string   `yaml:"query,omitempty"`
	QueryType   string   `yaml:"query_type"`
	Severity    string   `yaml:"severity,omitempty"`
	Tactics     []string `yaml:"tactics,omitempty"`
	Techniques  []string `yaml:"techniques,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Author      string   `yaml:"author,omitempty"`
	Version     string   `yaml:"version,omitempty"`
	References  []string `yaml:"references,omitempty"`
	DataSources []string `yaml:"data_sources,omitempty"`
	File        string   `yaml:"file,omitempty"`
}

type libraryIndex struct {
	Entries []libraryEntry `yaml:"entries"`
}

func main() {
	outputDir := flag.String("output-dir", "./output", "Output directory for library files")
	ruleTypes := flag.String("rule-types", "SIGMA,SPL,KQL", "Comma-separated rule types to fetch")
	excludeContributors := flag.String("exclude-contributors", "yamatosecurityhayabusa,sigmahq,splunksecurity,azuresentinel", "Comma-separated contributor slugs to exclude")
	includeAll := flag.Bool("include-all", false, "Include all contributors (override exclude list)")
	flag.Parse()

	refreshToken := os.Getenv(envToken)
	if refreshToken == "" {
		log.Fatalf("%s environment variable is required", envToken)
	}

	// Parse flags
	types := strings.Split(*ruleTypes, ",")
	for i := range types {
		types[i] = strings.TrimSpace(types[i])
	}

	excludeSet := make(map[string]bool)
	if !*includeAll {
		for _, slug := range strings.Split(*excludeContributors, ",") {
			slug = strings.TrimSpace(slug)
			if slug != "" {
				excludeSet[strings.ToLower(slug)] = true
			}
		}
	}

	// Authenticate
	log.Println("Authenticating...")
	accessToken, newRefreshToken, err := authenticate(refreshToken)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	log.Println("Authentication successful")

	// Save new refresh token if changed
	if newRefreshToken != "" && newRefreshToken != refreshToken {
		log.Printf("New refresh token received — update %s secret", envToken)
		// Write to a file so CI can pick it up
		_ = os.WriteFile(filepath.Join(*outputDir, ".new-refresh-token"), []byte(newRefreshToken), 0600)
	}

	// Fetch all detections
	log.Printf("Fetching detections (types: %s)...", strings.Join(types, ", "))
	rules, err := fetchAllRules(accessToken, types)
	if err != nil {
		log.Printf("Failed to fetch detections: %v", err)
		os.Exit(1)
	}
	log.Printf("Fetched %d total detections", len(rules))

	// Filter out excluded contributors
	var filtered []apiRule
	excluded := 0
	for _, r := range rules {
		if slug := contributorSlug(r); slug != "" && excludeSet[strings.ToLower(slug)] {
			excluded++
			continue
		}
		filtered = append(filtered, r)
	}
	log.Printf("After filtering: %d detections (%d excluded from known sources)", len(filtered), excluded)

	// Convert and write
	if err := writeOutput(*outputDir, filtered); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
	log.Printf("Done! Output written to %s", *outputDir)
}

func authenticate(refreshToken string) (accessToken, newRefreshToken string, err error) {
	req, err := http.NewRequest("POST", baseURL+authPath, nil)
	if err != nil {
		return "", "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Cookie", "refresh_token="+refreshToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("auth returned status %d: %s", resp.StatusCode, string(body))
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", "", fmt.Errorf("decoding response: %w", err)
	}

	if authResp.Data.AccessToken == "" {
		return "", "", fmt.Errorf("no access token in response")
	}

	// Extract new refresh token from Set-Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "refresh_token" {
			newRefreshToken = cookie.Value
			break
		}
	}

	return authResp.Data.AccessToken, newRefreshToken, nil
}

func fetchAllRules(accessToken string, ruleTypes []string) ([]apiRule, error) {
	var allRules []apiRule
	page := 1

	for {
		rules, err := fetchPage(accessToken, ruleTypes, page, maxPageSize)
		if err != nil {
			return nil, fmt.Errorf("fetching page %d: %w", page, err)
		}

		allRules = append(allRules, rules...)
		log.Printf("  Page %d: got %d rules (total so far: %d)", page, len(rules), len(allRules))

		if len(rules) < maxPageSize {
			break
		}
		page++

		// Rate limiting courtesy
		time.Sleep(200 * time.Millisecond)
	}

	return allRules, nil
}

func fetchPage(accessToken string, ruleTypes []string, page, size int) ([]apiRule, error) {
	body := discoverRequest{
		Filters: discoverFilters{RuleTypes: ruleTypes},
		Options: discoverOptions{Page: page, Size: size},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", baseURL+discoverPath, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discover returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var discoverResp discoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
		return nil, err
	}

	return discoverResp.Data, nil
}

func contributorSlug(r apiRule) string {
	if len(r.Contributor) == 0 || string(r.Contributor) == "null" {
		return ""
	}
	// Try object: {"slug": "..."}
	var obj struct {
		Slug string `json:"slug"`
	}
	if json.Unmarshal(r.Contributor, &obj) == nil && obj.Slug != "" {
		return obj.Slug
	}
	// Try plain string: "some-slug"
	var s string
	if json.Unmarshal(r.Contributor, &s) == nil {
		return s
	}
	return ""
}

func convertRule(r apiRule) libraryEntry {
	queryType := strings.ToLower(r.RuleType)

	var tactics, techniques []string
	for _, m := range r.Metadata.MitreAttack {
		switch m.Type {
		case "tactic":
			tactics = append(tactics, m.MitreID)
		case "technique", "subtechnique":
			techniques = append(techniques, m.MitreID)
		}
	}

	version := ""
	switch v := r.Version.(type) {
	case float64:
		version = strconv.Itoa(int(v))
	case string:
		version = v
	}

	return libraryEntry{
		ID:          r.ID,
		Name:        r.Title,
		Description: r.Description,
		Query:       r.Content,
		QueryType:   queryType,
		Severity:    r.Metadata.Severity,
		Tactics:     tactics,
		Techniques:  techniques,
		Tags:        r.Tags,
		Author:      r.Author,
		Version:     version,
		References:  r.Metadata.References,
		DataSources: r.Metadata.DataSources,
	}
}

func writeOutput(outputDir string, rules []apiRule) error {
	// Create directories
	entriesDir := filepath.Join(outputDir, "entries")
	for _, subdir := range []string{"sigma", "spl", "kql"} {
		if err := os.MkdirAll(filepath.Join(entriesDir, subdir), 0755); err != nil {
			return fmt.Errorf("creating directory: %w", err)
		}
	}

	var indexEntries []libraryEntry

	for _, r := range rules {
		entry := convertRule(r)
		queryType := entry.QueryType

		// Ensure subdirectory exists for this query type
		subDir := filepath.Join(entriesDir, queryType)
		if err := os.MkdirAll(subDir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", subDir, err)
		}

		// Write individual entry file
		entryPath := filepath.Join("entries", queryType, entry.ID+".yaml")
		fullPath := filepath.Join(outputDir, entryPath)

		data, err := yaml.Marshal(entry)
		if err != nil {
			log.Printf("Warning: failed to marshal entry %s: %v", entry.ID, err)
			continue
		}
		if err := os.WriteFile(fullPath, data, 0644); err != nil {
			return fmt.Errorf("writing entry file: %w", err)
		}

		// Add to index (without query content)
		indexEntry := entry
		indexEntry.Query = ""
		indexEntry.File = entryPath
		indexEntries = append(indexEntries, indexEntry)
	}

	// Sort index entries by ID for deterministic output
	sort.Slice(indexEntries, func(i, j int) bool {
		return indexEntries[i].ID < indexEntries[j].ID
	})

	// Write index file
	index := libraryIndex{Entries: indexEntries}
	indexData, err := yaml.Marshal(index)
	if err != nil {
		return fmt.Errorf("marshaling index: %w", err)
	}
	indexPath := filepath.Join(outputDir, "library.index.yaml")
	if err := os.WriteFile(indexPath, indexData, 0644); err != nil {
		return fmt.Errorf("writing index file: %w", err)
	}

	log.Printf("Wrote %d entries and index to %s", len(indexEntries), outputDir)
	return nil
}
