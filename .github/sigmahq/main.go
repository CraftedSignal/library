package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type upstreamSource struct {
	Name       string
	Repository string
	License    string
	Trees      map[string]string
}

var sigmaHQSource = upstreamSource{
	Name:       "sigmahq",
	Repository: "https://github.com/SigmaHQ/sigma",
	License:    "DRL-1.1",
	Trees: map[string]string{
		"rules":                  "detection",
		"rules-emerging-threats": "emerging_threat",
		"rules-threat-hunting":   "threat_hunt",
		"rules-compliance":       "compliance",
	},
}

var huntressSource = upstreamSource{
	Name:       "huntresslabs-threat-intel",
	Repository: "https://github.com/huntresslabs/threat-intel",
	License:    "MIT",
	Trees:      map[string]string{".": "threat_intel"},
}

const craftedSignalSource = "craftedsignal"

var sigmaIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
	Fields         []string       `yaml:"fields"`
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
	SourceRepository  string         `yaml:"source_repository"`
	SourceCommit      string         `yaml:"source_commit"`
	SyncedAt          string         `yaml:"synced_at"`
	Accepted          int            `yaml:"accepted"`
	Imported          int            `yaml:"imported"`
	Rejected          int            `yaml:"rejected"`
	DuplicatesSkipped int            `yaml:"duplicates_skipped,omitempty"`
	ByCategory        map[string]int `yaml:"by_category"`
	Rejections        []rejection    `yaml:"rejections,omitempty"`
}

type sourceBatch struct {
	source       upstreamSource
	commit       string
	entries      []libraryEntry
	rejections   []rejection
	byCategory   map[string]int
	manifestPath string
}

func main() {
	outputDir := flag.String("output-dir", ".", "CraftedSignal library repository root")
	sigmaDir := flag.String("sigma-dir", "", "SigmaHQ/sigma checkout root")
	huntressDir := flag.String("huntress-dir", "", "huntresslabs/threat-intel checkout root")
	flag.Parse()

	var batches []sourceBatch
	if strings.TrimSpace(*sigmaDir) != "" {
		batch, err := collectSourceBatch(*sigmaDir, sigmaHQSource, "sigmahq.sync.yaml")
		if err != nil {
			log.Fatalf("collect SigmaHQ rules: %v", err)
		}
		batches = append(batches, batch)
	}
	if strings.TrimSpace(*huntressDir) != "" {
		batch, err := collectSourceBatch(*huntressDir, huntressSource, "huntress.sync.yaml")
		if err != nil {
			log.Fatalf("collect Huntress rules: %v", err)
		}
		batches = append(batches, batch)
	}
	if len(batches) == 0 {
		log.Fatal("at least one of --sigma-dir or --huntress-dir is required")
	}
	if err := mergeAndWriteManifests(*outputDir, batches, time.Now().UTC()); err != nil {
		log.Fatalf("sync Sigma upstreams: %v", err)
	}
	for _, batch := range batches {
		log.Printf("%s sync complete: accepted=%d rejected=%d commit=%s", batch.source.Name, len(batch.entries), len(batch.rejections), batch.commit)
	}
}

func collectSourceBatch(root string, source upstreamSource, manifestPath string) (sourceBatch, error) {
	commit, err := gitCommit(root)
	if err != nil {
		return sourceBatch{}, fmt.Errorf("resolve %s commit: %w", source.Name, err)
	}
	entries, rejections, byCategory, err := collectRules(root, commit, source)
	if err != nil {
		return sourceBatch{}, err
	}
	return sourceBatch{
		source:       source,
		commit:       commit,
		entries:      entries,
		rejections:   rejections,
		byCategory:   byCategory,
		manifestPath: manifestPath,
	}, nil
}

func mergeAndWriteManifests(outputDir string, batches []sourceBatch, syncedAt time.Time) error {
	refreshedSources := make(map[string]bool, len(batches))
	var entries []libraryEntry
	for _, batch := range batches {
		refreshedSources[batch.source.Name] = true
		entries = append(entries, batch.entries...)
	}
	imported, err := mergeLibrary(outputDir, refreshedSources, entries)
	if err != nil {
		return err
	}
	for _, batch := range batches {
		manifest := syncManifest{
			SourceRepository:  batch.source.Repository,
			SourceCommit:      batch.commit,
			SyncedAt:          syncedAt.Format(time.RFC3339),
			Accepted:          len(batch.entries),
			Imported:          imported[batch.source.Name],
			Rejected:          len(batch.rejections),
			DuplicatesSkipped: len(batch.entries) - imported[batch.source.Name],
			ByCategory:        batch.byCategory,
			Rejections:        batch.rejections,
		}
		if err := writeYAML(filepath.Join(outputDir, batch.manifestPath), manifest); err != nil {
			return err
		}
	}
	return nil
}

func gitCommit(root string) (string, error) {
	command := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func collectRules(root, commit string, source upstreamSource) ([]libraryEntry, []rejection, map[string]int, error) {
	var entries []libraryEntry
	var rejections []rejection
	byCategory := make(map[string]int)

	for tree, category := range source.Trees {
		treeRoot := filepath.Join(root, tree)
		err := filepath.WalkDir(treeRoot, func(path string, directoryEntry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if directoryEntry.IsDir() {
				if directoryEntry.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			extension := strings.ToLower(filepath.Ext(path))
			if extension != ".yml" && extension != ".yaml" {
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
			entry := convertSigmaRule(rule, string(raw), relativePath(root, path), commit, category, score, source)
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
		{strings.TrimSpace(rule.ID) != "" && !sigmaIDPattern.MatchString(rule.ID), "invalid_id"},
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

func convertSigmaRule(rule sigmaRule, raw, path, commit, category string, score int, source upstreamSource) libraryEntry {
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
		Source:           source.Name,
		SourceRepository: source.Repository,
		SourcePath:       path,
		SourceCommit:     commit,
		SourceCategory:   category,
		UpstreamID:       rule.ID,
		UpstreamStatus:   rule.Status,
		License:          source.License,
		QualityScore:     score,
	}
}

type mergeCandidate struct {
	entry    libraryEntry
	incoming bool
}

func mergeLibrary(outputDir string, refreshedSources map[string]bool, newEntries []libraryEntry) (map[string]int, error) {
	indexPath := filepath.Join(outputDir, "library.index.yaml")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, err
	}
	var index libraryIndex
	if err := yaml.Unmarshal(indexData, &index); err != nil {
		return nil, err
	}

	candidates := make([]mergeCandidate, 0, len(index.Entries)+len(newEntries))
	removed := make([]libraryEntry, 0)
	for _, entry := range index.Entries {
		if refreshedSources[entry.Source] {
			removed = append(removed, entry)
			continue
		}
		if entry.Date == "" && entry.QueryType == "sigma" {
			entry.Date = sigmaEntryFileDate(outputDir, entry.File)
		}
		candidates = append(candidates, mergeCandidate{entry: entry})
	}
	for _, entry := range newEntries {
		candidates = append(candidates, mergeCandidate{entry: entry, incoming: true})
	}

	winners := make(map[string]mergeCandidate, len(candidates))
	for _, candidate := range candidates {
		winner, exists := winners[candidate.entry.ID]
		if !exists || sourcePriority(candidate.entry.Source) > sourcePriority(winner.entry.Source) {
			winners[candidate.entry.ID] = candidate
		}
	}

	winnerFiles := make(map[string]mergeCandidate, len(winners))
	for id, winner := range winners {
		if winner.incoming {
			winner.entry.File = filepath.ToSlash(filepath.Join("entries", "sigma", id+".yaml"))
			winners[id] = winner
		}
		if winner.entry.File != "" {
			winnerFiles[winner.entry.File] = winner
		}
	}
	for _, entry := range removed {
		if entry.File == "" {
			continue
		}
		winner, retained := winnerFiles[entry.File]
		if retained && !winner.incoming {
			continue
		}
		if err := os.Remove(filepath.Join(outputDir, filepath.FromSlash(entry.File))); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}

	entriesDir := filepath.Join(outputDir, "entries", "sigma")
	if err := os.MkdirAll(entriesDir, 0755); err != nil {
		return nil, err
	}
	imported := make(map[string]int, len(refreshedSources))
	merged := make([]libraryEntry, 0, len(winners))
	for _, winner := range winners {
		entry := winner.entry
		if winner.incoming {
			if err := writeYAML(filepath.Join(outputDir, filepath.FromSlash(entry.File)), entry); err != nil {
				return nil, err
			}
			imported[entry.Source]++
		}
		indexEntry := entry
		indexEntry.Query = ""
		merged = append(merged, indexEntry)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].ID < merged[j].ID })
	return imported, writeYAML(indexPath, libraryIndex{Entries: merged})
}

func sourcePriority(source string) int {
	switch source {
	case craftedSignalSource:
		return 300
	case sigmaHQSource.Name:
		return 200
	case huntressSource.Name:
		return 100
	default:
		return 0
	}
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
