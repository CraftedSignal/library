package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
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

func TestMergeLibraryPrefersCraftedSignalForDuplicateID(t *testing.T) {
	for _, incomingSource := range []upstreamSource{sigmaHQSource, huntressSource} {
		t.Run(incomingSource.Name, func(t *testing.T) {
			dir := t.TempDir()
			entriesDir := filepath.Join(dir, "entries", "sigma")
			if err := os.MkdirAll(entriesDir, 0755); err != nil {
				t.Fatal(err)
			}
			local := libraryEntry{
				ID:        "same-id",
				Name:      "CraftedSignal",
				QueryType: "sigma",
				Query:     "title: CraftedSignal\n",
				File:      "entries/sigma/same-id.yaml",
				Source:    "craftedsignal",
			}
			if err := writeYAML(filepath.Join(entriesDir, "same-id.yaml"), local); err != nil {
				t.Fatal(err)
			}
			if err := writeYAML(filepath.Join(dir, "library.index.yaml"), libraryIndex{Entries: []libraryEntry{local}}); err != nil {
				t.Fatal(err)
			}
			incoming := libraryEntry{
				ID:        "same-id",
				Name:      incomingSource.Name,
				QueryType: "sigma",
				Query:     "title: upstream duplicate\n",
				Source:    incomingSource.Name,
			}

			imported, err := mergeLibrary(dir, map[string]bool{incomingSource.Name: true}, []libraryEntry{incoming})
			if err != nil {
				t.Fatal(err)
			}
			if imported[incomingSource.Name] != 0 {
				t.Fatalf("imported = %v, want duplicate skipped", imported)
			}
			index := readLibraryIndex(t, filepath.Join(dir, "library.index.yaml"))
			if len(index.Entries) != 1 || index.Entries[0].Source != "craftedsignal" {
				t.Fatalf("duplicate winner = %#v, want CraftedSignal", index.Entries)
			}
			entry := readLibraryEntry(t, filepath.Join(entriesDir, "same-id.yaml"))
			if entry.Source != "craftedsignal" || entry.Name != "CraftedSignal" {
				t.Fatalf("first-party file was overwritten: %#v", entry)
			}
		})
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

func TestCraftedSignalSigmaEntriesAreIndexedAndMeetQualityGate(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	index := readLibraryIndex(t, filepath.Join(repositoryRoot, "library.index.yaml"))
	indexed := make(map[string]libraryEntry)
	for _, entry := range index.Entries {
		if entry.Source == "craftedsignal" && entry.QueryType == "sigma" {
			indexed[entry.ID] = entry
		}
	}
	if len(indexed) == 0 {
		t.Fatal("no craftedsignal entries found in library index")
	}

	paths, err := filepath.Glob(filepath.Join(repositoryRoot, "entries", "sigma", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		entry := readLibraryEntry(t, path)
		if entry.Source != "craftedsignal" || entry.QueryType != "sigma" {
			continue
		}
		seen[entry.ID] = true
		indexEntry, exists := indexed[entry.ID]
		if !exists {
			t.Errorf("first-party entry %s is missing from library.index.yaml", entry.ID)
			continue
		}
		relativePath, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			t.Fatal(err)
		}
		relativePath = filepath.ToSlash(relativePath)
		if indexEntry.File != relativePath || entry.SourcePath != relativePath {
			t.Errorf("%s paths: index=%q source=%q want %q", entry.ID, indexEntry.File, entry.SourcePath, relativePath)
		}
		expectedIndexEntry := entry
		expectedIndexEntry.Query = ""
		expectedIndexEntry.File = relativePath
		if !reflect.DeepEqual(indexEntry, expectedIndexEntry) {
			t.Errorf("%s index metadata does not match its entry file", entry.ID)
		}
		if entry.ID != strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) {
			t.Errorf("%s does not match filename %s", entry.ID, filepath.Base(path))
		}

		var rule sigmaRule
		if err := yaml.Unmarshal([]byte(entry.Query), &rule); err != nil {
			t.Errorf("%s has invalid Sigma YAML: %v", entry.ID, err)
			continue
		}
		if rule.ID != entry.ID || rule.Title != entry.Name || rule.Level != entry.Severity {
			t.Errorf("%s wrapper does not match Sigma rule metadata", entry.ID)
		}
		score, reasons := qualityScore(rule, entry.SourceCategory)
		if len(reasons) > 0 {
			t.Errorf("%s fails quality gate: score=%d reasons=%v", entry.ID, score, reasons)
		}
		if entry.QualityScore != score || indexEntry.QualityScore != score {
			t.Errorf("%s quality score: entry=%d index=%d want=%d", entry.ID, entry.QualityScore, indexEntry.QualityScore, score)
		}
		if entry.Date != sigmaRuleDate(rule.Date) || indexEntry.Date != entry.Date {
			t.Errorf("%s dates: rule=%q entry=%q index=%q", entry.ID, rule.Date, entry.Date, indexEntry.Date)
		}
		converted := convertSigmaRule(rule, entry.Query, relativePath, "", entry.SourceCategory, score, upstreamSource{})
		if entry.Description != converted.Description || entry.Author != converted.Author ||
			!slices.Equal(entry.Tags, converted.Tags) || !slices.Equal(entry.Techniques, converted.Techniques) ||
			!slices.Equal(entry.Tactics, converted.Tactics) || !slices.Equal(entry.References, converted.References) ||
			!slices.Equal(entry.DataSources, converted.DataSources) {
			t.Errorf("%s wrapper fields do not match converted Sigma metadata", entry.ID)
		}
	}
	for id := range indexed {
		if !seen[id] {
			t.Errorf("indexed first-party entry %s has no corresponding file", id)
		}
	}
}

func TestPHPDetectionRuleSemantics(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))

	t.Run("upload progress field follows PHP multipart parsing", func(t *testing.T) {
		entry := readLibraryEntry(t, filepath.Join(repositoryRoot, "entries", "sigma", "ce41b180-c21d-49a1-8848-dff5cce2a069.yaml"))
		var rule sigmaRule
		if err := yaml.Unmarshal([]byte(entry.Query), &rule); err != nil {
			t.Fatal(err)
		}
		selection, ok := rule.Detection["selection_progress_field"].(map[string]any)
		if !ok {
			t.Fatalf("selection_progress_field = %#v", rule.Detection["selection_progress_field"])
		}
		pattern, ok := selection["RequestBody|re|m"].(string)
		if !ok {
			t.Fatalf("RequestBody|re|m = %#v", selection["RequestBody|re|m"])
		}
		if strings.Contains(pattern, "(?:") || strings.Contains(pattern, "(?m)") {
			t.Fatalf("progress-field regex uses non-portable Sigma constructs: %q", pattern)
		}
		expression, err := regexp.Compile("(?m)" + pattern)
		if err != nil {
			t.Fatalf("invalid progress-field regex: %v", err)
		}
		for _, body := range []string{
			`Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"`,
			`Content-Disposition: form-data; Name='PHP_SESSION_UPLOAD_PROGRESS'; filename="x"`,
			"Content-Disposition: form-data; NAME=PHP_SESSION_UPLOAD_PROGRESS\r\n",
		} {
			if !expression.MatchString(body) {
				t.Errorf("progress-field regex did not match %q", body)
			}
		}
		for _, body := range []string{
			`Content-Disposition: form-data; name="php_session_upload_progress"`,
			`Content-Disposition: form-data; filename="PHP_SESSION_UPLOAD_PROGRESS"`,
		} {
			if expression.MatchString(body) {
				t.Errorf("progress-field regex unexpectedly matched %q", body)
			}
		}
		if rule.Level != "low" {
			t.Errorf("level = %q, want low", rule.Level)
		}
		assertNoExploitTags(t, rule)
		assertPHPMultipartContentType(t, rule)
	})

	t.Run("generic anomalies do not claim exploit attribution", func(t *testing.T) {
		for _, id := range []string{
			"8088567b-0125-43db-9d81-6f37f34fd4c7",
			"61d30385-719e-46df-878c-2280d08992fa",
		} {
			entry := readLibraryEntry(t, filepath.Join(repositoryRoot, "entries", "sigma", id+".yaml"))
			var rule sigmaRule
			if err := yaml.Unmarshal([]byte(entry.Query), &rule); err != nil {
				t.Fatal(err)
			}
			assertNoExploitTags(t, rule)
			if id == "8088567b-0125-43db-9d81-6f37f34fd4c7" {
				assertPHPMultipartContentType(t, rule)
			}
		}
	})

	t.Run("mixed child process signal does not claim interpreter technique", func(t *testing.T) {
		entry := readLibraryEntry(t, filepath.Join(repositoryRoot, "entries", "sigma", "c2a21046-4958-4690-83f2-d4cc10fdbf4a.yaml"))
		var rule sigmaRule
		if err := yaml.Unmarshal([]byte(entry.Query), &rule); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(rule.Tags, "attack.t1059") {
			t.Error("mixed shell/network-utility rule must not claim T1059 for every match")
		}
	})

	t.Run("session content evidence is included in analyst fields", func(t *testing.T) {
		entry := readLibraryEntry(t, filepath.Join(repositoryRoot, "entries", "sigma", "4d82642b-19c6-4934-8401-5f933b21ffe9.yaml"))
		var rule sigmaRule
		if err := yaml.Unmarshal([]byte(entry.Query), &rule); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(rule.Fields, "FileContent") {
			t.Errorf("fields = %v, want FileContent", rule.Fields)
		}
	})
}

func assertNoExploitTags(t *testing.T, rule sigmaRule) {
	t.Helper()
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "attack.") || strings.HasPrefix(tag, "cve.") {
			t.Errorf("generic signal has exploit-attribution tag %q", tag)
		}
	}
}

func assertPHPMultipartContentType(t *testing.T, rule sigmaRule) {
	t.Helper()
	selection, ok := rule.Detection["selection_content_type"].(map[string]any)
	if !ok {
		t.Fatalf("selection_content_type = %#v", rule.Detection["selection_content_type"])
	}
	pattern, ok := selection["RequestContentType|re|i"].(string)
	if !ok {
		t.Fatalf("RequestContentType|re|i = %#v", selection["RequestContentType|re|i"])
	}
	if strings.Contains(pattern, "(?:") || strings.Contains(pattern, "(?i)") {
		t.Fatalf("content-type regex uses non-portable Sigma constructs: %q", pattern)
	}
	expression, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		t.Fatalf("invalid content-type regex: %v", err)
	}
	for _, contentType := range []string{
		"multipart/form-data",
		"MULTIPART/FORM-DATA; boundary=x",
		"multipart/form-data ; boundary=x",
		"multipart/form-data,boundary=x",
	} {
		if !expression.MatchString(contentType) {
			t.Errorf("content-type regex did not match %q", contentType)
		}
	}
	if expression.MatchString("multipart/form-dataevil") {
		t.Error("content-type regex matched a non-delimited prefix")
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
