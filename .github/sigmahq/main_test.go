package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestCollectRulesUsesSourceConfigAndRecurses(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "2026", "incident", "rule.yaml")
	if err := os.MkdirAll(filepath.Dir(validPath), 0755); err != nil {
		t.Fatal(err)
	}
	valid := `title: Huntress rule
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects a thing.
author: Huntress
date: 2026/10/21
references:
  - https://example.invalid/advisory
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
falsepositives:
  - Administrative activity
level: high
tags:
  - attack.execution
  - attack.t1059.003
`
	if err := os.WriteFile(validPath, []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}

	nonSigmaPath := filepath.Join(dir, "2026", "incident", "chainsaw.yml")
	if err := os.WriteFile(nonSigmaPath, []byte("title: Chainsaw rule\nkind: evtx\nfilter:\n  condition: selection\n"), 0644); err != nil {
		t.Fatal(err)
	}

	gitPath := filepath.Join(dir, ".git", "ignored.yml")
	if err := os.MkdirAll(filepath.Dir(gitPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gitPath, []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}

	source := upstreamSource{
		Name:       "huntresslabs-threat-intel",
		Repository: "https://github.com/huntresslabs/threat-intel",
		License:    "MIT",
		Trees:      map[string]string{".": "threat_intel"},
	}
	entries, rejections, byCategory, err := collectRules(dir, "abc123", source)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if len(rejections) != 1 {
		t.Fatalf("rejections = %d, want 1", len(rejections))
	}
	entry := entries[0]
	if entry.Source != source.Name || entry.SourceRepository != source.Repository || entry.License != source.License {
		t.Fatalf("source provenance = %#v, want %#v", entry, source)
	}
	if entry.SourcePath != "2026/incident/rule.yaml" || entry.SourceCategory != "threat_intel" || entry.SourceCommit != "abc123" {
		t.Fatalf("source location = %#v", entry)
	}
	if entry.Date != "2026-10-21" {
		t.Fatalf("entry date = %q, want 2026-10-21", entry.Date)
	}
	if !slices.Contains(rejections[0].Reasons, "missing_id") {
		t.Fatalf("rejection reasons = %v, want missing_id", rejections[0].Reasons)
	}
	if byCategory["threat_intel"] != 1 {
		t.Fatalf("byCategory = %v, want threat_intel=1", byCategory)
	}
}

func TestQualityScoreRejectsStructurallyIncompleteRules(t *testing.T) {
	_, reasons := qualityScore(sigmaRule{Title: "Incomplete"}, "detection")
	if len(reasons) == 0 {
		t.Fatal("expected incomplete rule to be rejected")
	}
}

func TestQualityScoreAcceptsCuratedExperimentalRule(t *testing.T) {
	rule := sigmaRule{
		Title:          "Curated rule",
		ID:             "11111111-1111-1111-1111-111111111111",
		Status:         "experimental",
		Author:         "SigmaHQ",
		Level:          "high",
		References:     []string{"https://example.invalid/reference"},
		FalsePositives: []string{"Administrative activity"},
		Tags:           []string{"attack.t1059"},
		LogSource:      map[string]any{"category": "process_creation"},
		Detection:      map[string]any{"condition": "selection", "selection": map[string]any{"Image": "cmd.exe"}},
	}
	score, reasons := qualityScore(rule, "detection")
	if len(reasons) != 0 {
		t.Fatalf("expected rule to pass, score=%d reasons=%v", score, reasons)
	}
}

func TestQualityScoreRejectsInactiveRule(t *testing.T) {
	rule := sigmaRule{
		Title:     "Deprecated rule",
		ID:        "11111111-1111-1111-1111-111111111111",
		Status:    "deprecated",
		LogSource: map[string]any{"category": "process_creation"},
		Detection: map[string]any{"condition": "selection"},
	}
	_, reasons := qualityScore(rule, "detection")
	if len(reasons) != 1 || reasons[0] != "inactive_status" {
		t.Fatalf("expected inactive_status, got %v", reasons)
	}
}

func TestQualityScoreRejectsUnsafeOrMalformedIDs(t *testing.T) {
	for _, id := range []string{
		"../../outside",
		"11b8251d3-6267-4817-8d70-f001b6952c4b",
	} {
		rule := sigmaRule{
			Title:          "Unsafe ID",
			ID:             id,
			Status:         "experimental",
			Author:         "Huntress",
			Level:          "high",
			References:     []string{"https://example.invalid/reference"},
			FalsePositives: []string{"Administrative activity"},
			Tags:           []string{"attack.t1059"},
			LogSource:      map[string]any{"category": "process_creation"},
			Detection:      map[string]any{"condition": "selection"},
		}
		_, reasons := qualityScore(rule, "threat_intel")
		if !slices.Contains(reasons, "invalid_id") {
			t.Errorf("qualityScore ID %q reasons = %v, want invalid_id", id, reasons)
		}
	}
}

func TestSigmaRuleDateNormalizes(t *testing.T) {
	for raw, want := range map[string]string{
		"2023/01/15":   "2023-01-15",
		"2023-01-15":   "2023-01-15",
		"2023/1/5":     "2023-01-05",
		" 2021-03-04 ": "2021-03-04",
		"":             "",
		"not a date":   "",
	} {
		if got := sigmaRuleDate(raw); got != want {
			t.Errorf("sigmaRuleDate(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestConvertSigmaRuleKeepsSourceDate(t *testing.T) {
	raw := "title: Dated rule\nid: 22222222-2222-2222-2222-222222222222\ndate: 2021-03-04\n"
	var rule sigmaRule
	if err := yaml.Unmarshal([]byte(raw), &rule); err != nil {
		t.Fatal(err)
	}
	entry := convertSigmaRule(rule, raw, "rules/dated.yml", "commit", "detection", 90, sigmaHQSource)
	if entry.Date != "2021-03-04" {
		t.Fatalf("entry date = %q, want 2021-03-04", entry.Date)
	}
}

// Sigma entries from other sources get their date from the rule body, so
// every Sigma template carries its source date.
func TestMergeLibraryFillsDatesForOtherSigmaEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "entries", "sigma"), 0755); err != nil {
		t.Fatal(err)
	}
	ruleFile := libraryEntry{ID: "aaa", Name: "Mirrored", QueryType: "sigma", Query: "title: Mirrored\ndate: 2020/05/06\n", File: "entries/sigma/aaa.yaml"}
	if err := writeYAML(filepath.Join(dir, "entries", "sigma", "aaa.yaml"), ruleFile); err != nil {
		t.Fatal(err)
	}
	index := libraryIndex{Entries: []libraryEntry{
		{ID: "aaa", Name: "Mirrored", QueryType: "sigma", File: "entries/sigma/aaa.yaml"},
		{ID: "bbb", Name: "KQL rule", QueryType: "kql", File: "entries/kql/bbb.yaml"},
	}}
	if err := writeYAML(filepath.Join(dir, "library.index.yaml"), index); err != nil {
		t.Fatal(err)
	}

	if _, err := mergeLibrary(dir, nil, nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "library.index.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var merged libraryIndex
	if err := yaml.Unmarshal(data, &merged); err != nil {
		t.Fatal(err)
	}
	dates := map[string]string{}
	for _, entry := range merged.Entries {
		dates[entry.ID] = entry.Date
	}
	if dates["aaa"] != "2020-05-06" || dates["bbb"] != "" {
		t.Fatalf("dates = %v, want aaa=2020-05-06 and no date for the KQL entry", dates)
	}
}

func TestMergeLibraryPrefersSigmaHQForDuplicateID(t *testing.T) {
	dir := t.TempDir()
	if err := writeYAML(filepath.Join(dir, "library.index.yaml"), libraryIndex{}); err != nil {
		t.Fatal(err)
	}
	sigma := libraryEntry{ID: "same-id", Name: "SigmaHQ", QueryType: "sigma", Query: "title: SigmaHQ\n", Source: sigmaHQSource.Name}
	huntress := libraryEntry{ID: "same-id", Name: "Huntress", QueryType: "sigma", Query: "title: Huntress\n", Source: huntressSource.Name}

	imported, err := mergeLibrary(dir, map[string]bool{
		sigmaHQSource.Name:  true,
		huntressSource.Name: true,
	}, []libraryEntry{huntress, sigma})
	if err != nil {
		t.Fatal(err)
	}
	if imported[sigmaHQSource.Name] != 1 || imported[huntressSource.Name] != 0 {
		t.Fatalf("imported = %v, want sigmahq=1 and huntress=0", imported)
	}

	index := readLibraryIndex(t, filepath.Join(dir, "library.index.yaml"))
	if len(index.Entries) != 1 || index.Entries[0].Source != sigmaHQSource.Name {
		t.Fatalf("entries = %#v, want one SigmaHQ winner", index.Entries)
	}
	entry := readLibraryEntry(t, filepath.Join(dir, "entries", "sigma", "same-id.yaml"))
	if entry.Source != sigmaHQSource.Name || entry.Name != "SigmaHQ" {
		t.Fatalf("written entry = %#v, want SigmaHQ winner", entry)
	}
}

func TestIndependentHuntressRefreshKeepsExistingSigmaHQWinner(t *testing.T) {
	dir := t.TempDir()
	entriesDir := filepath.Join(dir, "entries", "sigma")
	if err := os.MkdirAll(entriesDir, 0755); err != nil {
		t.Fatal(err)
	}
	existingSigma := libraryEntry{ID: "same-id", Name: "SigmaHQ", QueryType: "sigma", Query: "title: SigmaHQ\n", File: "entries/sigma/same-id.yaml", Source: sigmaHQSource.Name}
	staleHuntress := libraryEntry{ID: "stale-id", Name: "Stale", QueryType: "sigma", Query: "title: Stale\n", File: "entries/sigma/stale-id.yaml", Source: huntressSource.Name}
	if err := writeYAML(filepath.Join(entriesDir, "same-id.yaml"), existingSigma); err != nil {
		t.Fatal(err)
	}
	if err := writeYAML(filepath.Join(entriesDir, "stale-id.yaml"), staleHuntress); err != nil {
		t.Fatal(err)
	}
	if err := writeYAML(filepath.Join(dir, "library.index.yaml"), libraryIndex{Entries: []libraryEntry{existingSigma, staleHuntress}}); err != nil {
		t.Fatal(err)
	}

	incoming := []libraryEntry{
		{ID: "same-id", Name: "Huntress duplicate", QueryType: "sigma", Query: "title: Huntress duplicate\n", Source: huntressSource.Name},
		{ID: "new-id", Name: "Huntress new", QueryType: "sigma", Query: "title: Huntress new\n", Source: huntressSource.Name},
	}
	imported, err := mergeLibrary(dir, map[string]bool{huntressSource.Name: true}, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if imported[huntressSource.Name] != 1 {
		t.Fatalf("imported = %v, want one Huntress rule", imported)
	}

	index := readLibraryIndex(t, filepath.Join(dir, "library.index.yaml"))
	if len(index.Entries) != 2 {
		t.Fatalf("entries = %#v, want SigmaHQ winner plus new Huntress rule", index.Entries)
	}
	byID := map[string]libraryEntry{}
	for _, entry := range index.Entries {
		byID[entry.ID] = entry
	}
	if byID["same-id"].Source != sigmaHQSource.Name || byID["new-id"].Source != huntressSource.Name {
		t.Fatalf("entries by ID = %#v", byID)
	}
	if _, err := os.Stat(filepath.Join(entriesDir, "stale-id.yaml")); !os.IsNotExist(err) {
		t.Fatalf("stale Huntress file still exists, stat error = %v", err)
	}
	entry := readLibraryEntry(t, filepath.Join(entriesDir, "same-id.yaml"))
	if entry.Source != sigmaHQSource.Name {
		t.Fatalf("duplicate overwrote SigmaHQ file: %#v", entry)
	}
}

func TestMergeAndWriteManifestsReportsImportedAndDuplicateCounts(t *testing.T) {
	dir := t.TempDir()
	if err := writeYAML(filepath.Join(dir, "library.index.yaml"), libraryIndex{}); err != nil {
		t.Fatal(err)
	}
	batches := []sourceBatch{
		{
			source:       sigmaHQSource,
			commit:       "sigma-commit",
			entries:      []libraryEntry{{ID: "same-id", Name: "SigmaHQ", QueryType: "sigma", Query: "title: SigmaHQ\n", Source: sigmaHQSource.Name}},
			byCategory:   map[string]int{"detection": 1},
			manifestPath: "sigmahq.sync.yaml",
		},
		{
			source: huntressSource,
			commit: "huntress-commit",
			entries: []libraryEntry{
				{ID: "same-id", Name: "Huntress duplicate", QueryType: "sigma", Query: "title: duplicate\n", Source: huntressSource.Name},
				{ID: "huntress-id", Name: "Huntress unique", QueryType: "sigma", Query: "title: unique\n", Source: huntressSource.Name},
			},
			rejections:   []rejection{{Path: "not-sigma.yml", Reasons: []string{"missing_id"}}},
			byCategory:   map[string]int{"threat_intel": 2},
			manifestPath: "huntress.sync.yaml",
		},
	}
	syncedAt := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	if err := mergeAndWriteManifests(dir, batches, syncedAt); err != nil {
		t.Fatal(err)
	}

	sigmaManifest := readSyncManifest(t, filepath.Join(dir, "sigmahq.sync.yaml"))
	if sigmaManifest.Accepted != 1 || sigmaManifest.Imported != 1 || sigmaManifest.DuplicatesSkipped != 0 {
		t.Fatalf("SigmaHQ manifest = %#v", sigmaManifest)
	}
	huntressManifest := readSyncManifest(t, filepath.Join(dir, "huntress.sync.yaml"))
	if huntressManifest.SourceRepository != huntressSource.Repository || huntressManifest.SourceCommit != "huntress-commit" {
		t.Fatalf("Huntress provenance = %#v", huntressManifest)
	}
	if huntressManifest.Accepted != 2 || huntressManifest.Imported != 1 || huntressManifest.Rejected != 1 || huntressManifest.DuplicatesSkipped != 1 {
		t.Fatalf("Huntress counts = %#v", huntressManifest)
	}
	if huntressManifest.SyncedAt != "2026-10-21T12:00:00Z" {
		t.Fatalf("synced_at = %q", huntressManifest.SyncedAt)
	}
}

func readLibraryIndex(t *testing.T, path string) libraryIndex {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index libraryIndex
	if err := yaml.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	return index
}

func readLibraryEntry(t *testing.T, path string) libraryEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry libraryEntry
	if err := yaml.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func readSyncManifest(t *testing.T, path string) syncManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest syncManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}
