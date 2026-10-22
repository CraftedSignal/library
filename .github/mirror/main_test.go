package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	localEntryID   = "ce41b180-c21d-49a1-8848-dff5cce2a069"
	localEntryPath = "entries/sigma/ce41b180-c21d-49a1-8848-dff5cce2a069.yaml"
)

type testIndex struct {
	Entries []struct {
		ID           string `yaml:"id"`
		Name         string `yaml:"name"`
		Date         string `yaml:"date"`
		File         string `yaml:"file"`
		Source       string `yaml:"source"`
		QualityScore int    `yaml:"quality_score"`
	} `yaml:"entries"`
}

func TestWriteOutputPreservesCraftedSignalEntries(t *testing.T) {
	dir := t.TempDir()
	writeLocalFixture(t, dir)

	if err := writeOutput(dir, nil); err != nil {
		t.Fatal(err)
	}

	index := readTestIndex(t, filepath.Join(dir, "library.index.yaml"))
	if len(index.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(index.Entries))
	}
	entry := index.Entries[0]
	if entry.ID != localEntryID || entry.Name != "Local rule" || entry.Source != "craftedsignal" {
		t.Fatalf("preserved entry = %#v", entry)
	}
	if entry.Date != "2026-10-21" || entry.QualityScore != 95 || entry.File != localEntryPath {
		t.Fatalf("preserved metadata = %#v", entry)
	}
}

func TestWriteOutputDoesNotOverwriteCraftedSignalEntryOnAPIDuplicate(t *testing.T) {
	dir := t.TempDir()
	wantFile := writeLocalFixture(t, dir)
	rules := []apiRule{{
		ID:       localEntryID,
		Title:    "API duplicate",
		Content:  "title: API duplicate\n",
		RuleType: "SIGMA",
	}}

	if err := writeOutput(dir, rules); err != nil {
		t.Fatal(err)
	}

	gotFile, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(localEntryPath)))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotFile) != wantFile {
		t.Fatalf("local entry file was overwritten:\n%s", gotFile)
	}
	index := readTestIndex(t, filepath.Join(dir, "library.index.yaml"))
	if len(index.Entries) != 1 || index.Entries[0].Name != "Local rule" {
		t.Fatalf("duplicate winner = %#v, want Local rule", index.Entries)
	}
}

func writeLocalFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(localEntryPath))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	fileContent := "id: " + localEntryID + "\nname: Local rule\nquery_type: sigma\nsource: craftedsignal\n"
	if err := os.WriteFile(path, []byte(fileContent), 0644); err != nil {
		t.Fatal(err)
	}
	indexContent := "entries:\n" +
		"    - id: " + localEntryID + "\n" +
		"      name: Local rule\n" +
		"      query_type: sigma\n" +
		"      date: '2026-10-21'\n" +
		"      file: " + localEntryPath + "\n" +
		"      source: craftedsignal\n" +
		"      quality_score: 95\n"
	if err := os.WriteFile(filepath.Join(dir, "library.index.yaml"), []byte(indexContent), 0644); err != nil {
		t.Fatal(err)
	}
	return fileContent
}

func readTestIndex(t *testing.T, path string) testIndex {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index testIndex
	if err := yaml.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	return index
}
