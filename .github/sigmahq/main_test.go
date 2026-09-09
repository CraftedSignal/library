package main

import "testing"

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
