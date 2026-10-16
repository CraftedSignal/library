package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var includedTrees = map[string]string{
	"rules":                  "detection",
	"rules-emerging-threats": "emerging_threat",
	"rules-threat-hunting":   "threat_hunt",
	"rules-compliance":       "compliance",
}

type sigmaRule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Author         string         `yaml:"author"`
	Date           string         `yaml:"date"`
	Level          string         `yaml:"level"`
	Tags           []string       `yaml:"tags"`
	References     []string       `yaml:"references"`
	FalsePositives []string       `yaml:"falsepositives"`
	LogSource      map[string]any `yaml:"logsource"`
	Detection      map[string]any `yaml:"detection"`
}

type libraryEntry struct {
	ID               string   `yaml:"id"`
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description,omitempty"`
	Query            string   `yaml:"query,omitempty"`
	QueryType        string   `yaml:"query_type"`
	Severity         string   `yaml:"severity,omitempty"`
	Tactics          []string `yaml:"tactics,omitempty"`
	Techniques       []string `yaml:"techniques,omitempty"`
	Tags             []string `yaml:"tags,omitempty"`
	Date             string   `yaml:"date,omitempty"`
	Author           string   `yaml:"author,omitempty"`
	Version          string   `yaml:"version,omitempty"`
	References       []string `yaml:"references,omitempty"`
	DataSources      []string `yaml:"data_sources,omitempty"`
	File             string   `yaml:"file,omitempty"`
	Source           string   `yaml:"source,omitempty"`
	SourceRepository string   `yaml:"source_repository,omitempty"`
	SourcePath       string   `yaml:"source_path,omitempty"`
	SourceCommit     string   `yaml:"source_commit,omitempty"`
	SourceCategory   string   `yaml:"source_category,omitempty"`
	UpstreamID       string   `yaml:"upstream_id,omitempty"`
	UpstreamStatus   string   `yaml:"upstream_status,omitempty"`
	License          string   `yaml:"license,omitempty"`
	QualityScore     int      `yaml:"quality_score,omitempty"`
}

type libraryIndex struct {
	Entries []libraryEntry `yaml:"entries"`
}

type rejection struct {
	Path    string   `yaml:"path"`
	Title   string   `yaml:"title,omitempty"`
	ID      string   `yaml:"id,omitempty"`
	Score   int      `yaml:"score"`
	Reasons []string `yaml:"reasons"`
}

type syncManifest struct {
	SourceRepository string         `yaml:"source_repository"`
	SourceCommit     string         `yaml:"source_commit"`
	SyncedAt         string         `yaml:"synced_at"`
	Accepted         int            `yaml:"accepted"`
	Rejected         int            `yaml:"rejected"`
	ByCategory       map[string]int `yaml:"by_category"`
	Rejections       []rejection    `yaml:"rejections,omitempty"`
}

func main() {
	outputDir := flag.String("output-dir", ".", "CraftedSignal library repository root")
	sigmaDir := flag.String("sigma-dir", "", "SigmaHQ/sigma checkout root")
	flag.Parse()

	if strings.TrimSpace(*sigmaDir) == "" {
		log.Fatal("--sigma-dir is required")
	}
	commit, err := gitCommit(*sigmaDir)
	if err != nil {
		log.Fatalf("resolve SigmaHQ commit: %v", err)
	}

	entries, rejections, byCategory, err := collectRules(*sigmaDir, commit)
	if err != nil {
		log.Fatalf("collect SigmaHQ rules: %v", err)
	}
	if err := mergeLibrary(*outputDir, entries); err != nil {
		log.Fatalf("merge SigmaHQ rules: %v", err)
	}
	manifest := syncManifest{
		SourceRepository: "https://github.com/SigmaHQ/sigma",
		SourceCommit:     commit,
		SyncedAt:         time.Now().UTC().Format(time.RFC3339),
		Accepted:         len(entries),
		Rejected:         len(rejections),
		ByCategory:       byCategory,
		Rejections:       rejections,
	}
	if err := writeYAML(filepath.Join(*outputDir, "sigmahq.sync.yaml"), manifest); err != nil {
		log.Fatalf("write sync manifest: %v", err)
	}
	log.Printf("SigmaHQ sync complete: accepted=%d rejected=%d commit=%s", len(entries), len(rejections), commit)
}

func gitCommit(root string) (string, error) {
	command := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func collectRules(root, commit string) ([]libraryEntry, []rejection, map[string]int, error) {
	var entries []libraryEntry
	var rejections []rejection
	byCategory := make(map[string]int)

	for tree, category := range includedTrees {
		treeRoot := filepath.Join(root, tree)
		err := filepath.WalkDir(treeRoot, func(path string, directoryEntry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if directoryEntry.IsDir() || filepath.Ext(path) != ".yml" {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var rule sigmaRule
			if err := yaml.Unmarshal(raw, &rule); err != nil {
				rejections = append(rejections, rejection{Path: relativePath(root, path), Reasons: []string{"invalid_yaml"}})
				return nil
			}
			score, reasons := qualityScore(rule, category)
			if len(reasons) > 0 {
				rejections = append(rejections, rejection{Path: relativePath(root, path), Title: rule.Title, ID: rule.ID, Score: score, Reasons: reasons})
				return nil
			}
			entry := convertSigmaRule(rule, string(raw), relativePath(root, path), commit, category, score)
			entries = append(entries, entry)
			byCategory[category]++
			return nil
		})
		if err != nil {
			return nil, nil, nil, err
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	sort.Slice(rejections, func(i, j int) bool { return rejections[i].Path < rejections[j].Path })
	return entries, rejections, byCategory, nil
}

func qualityScore(rule sigmaRule, category string) (int, []string) {
	score := 0
	var reasons []string
	required := []struct {
		missing bool
		reason  string
	}{
		{strings.TrimSpace(rule.ID) == "", "missing_id"},
		{strings.TrimSpace(rule.Title) == "", "missing_title"},
		{len(rule.LogSource) == 0, "missing_logsource"},
		{len(rule.Detection) == 0, "missing_detection"},
		{rule.Detection["condition"] == nil, "missing_condition"},
	}
	for _, check := range required {
		if check.missing {
			reasons = append(reasons, check.reason)
		}
	}
	if len(reasons) > 0 {
		return score, reasons
	}
	score = 50
	status := strings.ToLower(strings.TrimSpace(rule.Status))
	if status == "deprecated" || status == "unsupported" {
		return score, []string{"inactive_status"}
	}
	if status == "stable" || status == "test" {
		score += 10
	} else if status == "experimental" {
		score += 5
	}
	if strings.TrimSpace(rule.Author) != "" {
		score += 10
	}
	if strings.TrimSpace(rule.Level) != "" {
		score += 10
	}
	if len(rule.References) > 0 {
		score += 10
	}
	if len(rule.FalsePositives) > 0 {
		score += 5
	}
	if len(rule.Tags) > 0 {
		score += 5
	}
	minimum := 70
	if category == "threat_hunt" {
		minimum = 65
	}
	if score < minimum {
		reasons = append(reasons, fmt.Sprintf("quality_score_below_%d", minimum))
	}
	return score, reasons
}

func convertSigmaRule(rule sigmaRule, raw, path, commit, category string, score int) libraryEntry {
	var tactics []string
	var techniques []string
	for _, tag := range rule.Tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.ta") {
			tactics = append(tactics, strings.ToUpper(strings.TrimPrefix(lower, "attack.")))
		} else if strings.HasPrefix(lower, "attack.t") {
			techniques = append(techniques, strings.ToUpper(strings.TrimPrefix(lower, "attack.")))
		}
	}
	dataSources := make([]string, 0, 3)
	for _, key := range []string{"product", "category", "service"} {
		if value := strings.TrimSpace(fmt.Sprintf("%v", rule.LogSource[key])); value != "" && value != "<nil>" {
			dataSources = append(dataSources, value)
		}
	}
	return libraryEntry{
		ID:               strings.ToLower(rule.ID),
		Name:             rule.Title,
		Description:      rule.Description,
		Query:            raw,
		QueryType:        "sigma",
		Severity:         rule.Level,
		Tactics:          uniqueStrings(tactics),
		Techniques:       uniqueStrings(techniques),
		Tags:             rule.Tags,
		Date:             sigmaRuleDate(rule.Date),
		Author:           rule.Author,
		References:       rule.References,
		DataSources:      uniqueStrings(dataSources),
		Source:           "sigmahq",
		SourceRepository: "https://github.com/SigmaHQ/sigma",
		SourcePath:       path,
		SourceCommit:     commit,
		SourceCategory:   category,
		UpstreamID:       rule.ID,
		UpstreamStatus:   rule.Status,
		License:          "DRL-1.1",
		QualityScore:     score,
	}
}

func mergeLibrary(outputDir string, sigmaEntries []libraryEntry) error {
	indexPath := filepath.Join(outputDir, "library.index.yaml")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return err
	}
	var index libraryIndex
	if err := yaml.Unmarshal(indexData, &index); err != nil {
		return err
	}

	retained := make([]libraryEntry, 0, len(index.Entries)+len(sigmaEntries))
	for _, entry := range index.Entries {
		if entry.Source == "sigmahq" {
			if entry.File != "" {
				_ = os.Remove(filepath.Join(outputDir, filepath.FromSlash(entry.File)))
			}
			continue
		}
		if entry.Date == "" && entry.QueryType == "sigma" {
			entry.Date = sigmaEntryFileDate(outputDir, entry.File)
		}
		retained = append(retained, entry)
	}

	entriesDir := filepath.Join(outputDir, "entries", "sigma")
	if err := os.MkdirAll(entriesDir, 0755); err != nil {
		return err
	}
	for _, entry := range sigmaEntries {
		entryPath := filepath.Join("entries", "sigma", entry.ID+".yaml")
		entry.File = filepath.ToSlash(entryPath)
		if err := writeYAML(filepath.Join(outputDir, entryPath), entry); err != nil {
			return err
		}
		indexEntry := entry
		indexEntry.Query = ""
		retained = append(retained, indexEntry)
	}
	sort.Slice(retained, func(i, j int) bool { return retained[i].ID < retained[j].ID })
	return writeYAML(indexPath, libraryIndex{Entries: retained})
}

// sigmaRuleDate returns a Sigma rule's date as YYYY-MM-DD, or "" when the rule
// has none or it can't be read. Rules write it as 2023-01-15 or 2023/01/15.
func sigmaRuleDate(raw string) string {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "/", "-")
	if date, err := time.Parse("2006-1-2", raw); err == nil {
		return date.Format("2006-01-02")
	}
	return ""
}

// sigmaEntryFileDate reads the date from the Sigma rule in a library entry
// file, for Sigma entries other sources added without one.
func sigmaEntryFileDate(outputDir, file string) string {
	if file == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(outputDir, filepath.FromSlash(file)))
	if err != nil {
		return ""
	}
	var entry libraryEntry
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return ""
	}
	var rule sigmaRule
	if err := yaml.Unmarshal([]byte(entry.Query), &rule); err != nil {
		return ""
	}
	return sigmaRuleDate(rule.Date)
}

func writeYAML(path string, value any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
