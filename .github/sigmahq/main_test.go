package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

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
	entry := convertSigmaRule(rule, raw, "rules/dated.yml", "commit", "detection", 90)
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

	if err := mergeLibrary(dir, nil); err != nil {
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
