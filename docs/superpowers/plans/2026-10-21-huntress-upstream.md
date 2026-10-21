# Huntress Threat Intel Upstream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add quality-gated, commit-pinned ingestion of Huntress Sigma detections alongside SigmaHQ.

**Architecture:** Generalize the existing SigmaHQ importer around explicit upstream specifications, then collect and merge both repositories in one deterministic pass. The same merge routine supports an independent local refresh and resolves duplicate IDs by source priority.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, GitHub Actions, YAML corpus files

**Spec:** `docs/superpowers/specs/2026-10-21-huntress-upstream-design.md`

## Global Constraints

- Keep existing SigmaHQ behavior and metadata compatible.
- Import only structurally valid, quality-gated Sigma rules.
- Prefer SigmaHQ over Huntress for duplicate Sigma IDs.
- Attribute Huntress entries to the MIT-licensed source repository and exact commit.
- Do not ingest IOC CSV, YARA, PowerShell, or Chainsaw artifacts.

## Review Focus

- Recursive discovery must skip `.git` and non-YAML artifacts while accepting `.yml` and `.yaml` Sigma files.
- A non-Sigma YAML document must be reported as rejected, not abort the entire sync.
- A duplicate Huntress ID must not replace the SigmaHQ entry or produce a duplicate index row.
- An independent Huntress refresh must respect an existing higher-priority SigmaHQ entry.
- Refreshing a managed source must remove stale managed entries without deleting a retained winner's file.

---

### Task 1: Source-aware collection and conversion

**Files:**
- Modify: `.github/sigmahq/main.go`
- Modify: `.github/sigmahq/main_test.go`

**Interfaces:**
- Consumes: checkout roots and exact Git commits for configured Sigma upstreams
- Produces: `collectRules(root, commit string, source upstreamSource) ([]libraryEntry, []rejection, map[string]int, error)`

- [ ] Write failing tests for recursive Huntress collection, non-Sigma rejection, and source-specific provenance.
- [ ] Run `go test ./...` in `.github/sigmahq` and confirm the tests fail for missing source-aware behavior.
- [ ] Introduce `upstreamSource` configuration and generalize collection and conversion.
- [ ] Run `gofmt` and `go test ./...` in `.github/sigmahq`.

### Task 2: Deterministic multi-source merge

**Files:**
- Modify: `.github/sigmahq/main.go`
- Modify: `.github/sigmahq/main_test.go`

**Interfaces:**
- Consumes: existing index, refreshed source set, newly collected entries
- Produces: a deduplicated index and per-source imported counts

- [ ] Write failing tests proving SigmaHQ wins duplicate IDs and independent Huntress refreshes respect that winner.
- [ ] Run `go test ./...` and confirm the duplicate tests fail for the expected reason.
- [ ] Implement priority-aware merging, safe stale-file cleanup, and imported counts.
- [ ] Run `gofmt` and the full `.github/sigmahq` test suite.

### Task 3: CI wiring and manifests

**Files:**
- Modify: `.github/workflows/mirror.yml`
- Modify: `.github/sigmahq/main.go`
- Modify: `README.md`
- Create: `huntress.sync.yaml`

**Interfaces:**
- Consumes: `.upstream/sigma` and `.upstream/huntress-threat-intel` checkouts
- Produces: refreshed library entries plus `sigmahq.sync.yaml` and `huntress.sync.yaml`

- [ ] Add the pinned-action Huntress checkout and pass both roots to the importer.
- [ ] Generate separate manifests with accepted, imported, rejected, and duplicate counts.
- [ ] Document the two direct curated upstreams and the supported artifact scope.
- [ ] Run the importer against the live Huntress checkout to materialize current accepted rules.

### Task 4: Full verification

**Files:**
- Verify all modified and generated files

**Interfaces:**
- Consumes: completed implementation and generated corpus
- Produces: evidence that tests, generation, metadata, and index invariants hold

- [ ] Run `go test ./...` in both `.github/sigmahq` and `.github/mirror`.
- [ ] Run `go vet ./...` in `.github/sigmahq`.
- [ ] Verify no duplicate IDs exist in `library.index.yaml`.
- [ ] Verify every Huntress index entry has a corresponding file, exact repository provenance, commit, and MIT license.
- [ ] Review `git diff --check`, `git status --short`, and the final diff summary.
