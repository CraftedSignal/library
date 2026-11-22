# Structural Library Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make library generation deterministic and prevent failed source refreshes from publishing partial snapshots.

**Architecture:** Remove wall-clock state from generated sync manifests so the existing tree comparison can correctly identify no-op runs. Let detections.ai refresh failures propagate through GitHub Actions, preserving the workflow's atomic publication boundary.

**Tech Stack:** Go, Python unittest, Bash, GitHub Actions YAML

**Spec:** `docs/superpowers/specs/2026-11-22-structural-library-sync-design.md`

## Global Constraints

- Add no dependencies.
- Preserve source precedence, quality gates, and entry serialization.
- Keep token rotation eligible after refresh failure.
- Do not publish any generated snapshot after a configured source fails.

## Review Focus

- Repeated identical batches must produce byte-identical manifests.
- A changed upstream commit must still change the manifest through `source_commit`.
- Missing manifests must still be created with counts, categories, and rejections.
- A detections.ai failure must leave publication success-gated while token cleanup remains eligible.
- Existing publisher behavior for a truly unchanged tree must remain intact.

---

### Task 1: Deterministic sync manifests

**Files:**
- Modify: `.github/sigmahq/main.go`
- Modify: `.github/sigmahq/main_test.go`
- Modify: `sigmahq.sync.yaml`
- Modify: `huntress.sync.yaml`
- Modify: `ai-dfir-toolkit.sync.yaml`

**Interfaces:**
- Consumes: existing `sourceBatch` values and `mergeLibrary` results.
- Produces: `mergeAndWriteManifests(outputDir string, batches []sourceBatch) error` with deterministic YAML output.

- [ ] **Step 1: Write the failing regression test**

Add `TestMergeAndWriteManifestsProducesStableManifestForUnchangedSnapshot`. Run the generator twice with identical batches and distinct times through the current interface, then assert literal byte equality and absence of a changed snapshot.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `GOWORK=off go test -run TestMergeAndWriteManifestsProducesStableManifestForUnchangedSnapshot ./...`

Expected: FAIL because `synced_at` differs.

- [ ] **Step 3: Remove wall-clock manifest state**

Remove `syncManifest.SyncedAt`, remove the time argument from `mergeAndWriteManifests`, update callers, and remove existing `synced_at` keys from all three generated manifests.

- [ ] **Step 4: Run focused and module tests**

Run: `GOWORK=off go test -race -timeout=5m ./... && GOWORK=off go vet ./...`

Expected: PASS.

### Task 2: Atomic workflow failure

**Files:**
- Modify: `.github/workflows/mirror.yml`

**Interfaces:**
- Consumes: exit status from the detections.ai Go helper.
- Produces: a failed workflow job with no generated publication when refresh fails.

- [ ] **Step 1: Remove failure masking**

Delete `continue-on-error: true` from the detections.ai refresh step. Retain `if: always()` on token rotation and leave publication under the default success condition.

- [ ] **Step 2: Validate workflow syntax and behavior ordering**

Run the available workflow linter, then inspect the diff to confirm refresh precedes generation/publication and only token rotation has unconditional execution.

### Task 3: Full verification

**Files:**
- Verify all modified files.

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: a reviewable branch with repository CI commands passing.

- [ ] **Step 1: Run Python publisher tests**

Run: `python3 -m unittest discover -s .github/tests -p 'test_*.py'`

Expected: 6 tests, PASS.

- [ ] **Step 2: Run Go test, race, and vet in both modules**

Run the CI loop with `GOWORK=off` for `.github/mirror` and `.github/sigmahq`.

Expected: PASS.

- [ ] **Step 3: Run vulnerability scans**

Run `govulncheck ./...` in both modules with `GOWORK=off`.

Expected: no reachable vulnerabilities.

- [ ] **Step 4: Review the final diff against the spec**

Confirm no generated entries, quality rules, or publisher behavior changed.
