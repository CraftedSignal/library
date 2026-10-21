# Huntress Threat Intel Upstream Design

## Intent

Ingest the Sigma detections published in `huntresslabs/threat-intel` as a first-class, periodically refreshed upstream, following the provenance and quality model already used for `SigmaHQ/sigma`.

## Goals

- Checkout Huntress directly in the six-hour sync workflow.
- Discover Sigma YAML recursively because Huntress organizes content by year and incident rather than under one fixed rules directory.
- Apply the existing structural and quality gates before publishing a rule.
- Record Huntress repository, commit, path, status, category, quality score, and MIT license on every imported entry.
- Write a separate `huntress.sync.yaml` manifest with accepted, imported, rejected, and duplicate counts.
- Keep source precedence deterministic: a current SigmaHQ rule wins when both repositories publish the same Sigma ID.
- Make the importer source-aware so another curated Sigma repository can be added without copying the ingestion program.

## Non-goals

- Do not ingest Huntress CSV indicators, YARA signatures, PowerShell tools, or Chainsaw rules. The library currently has no first-class schemas for those artifact types.
- Do not discover or add unrelated repositories in this change.
- Do not weaken the existing Sigma quality threshold to increase the Huntress acceptance count.

## Constraints and decisions

- Continue writing accepted detections under `entries/sigma/<lowercase-id>.yaml`.
- Continue using the existing Sigma conversion and scoring logic.
- Treat the whole Huntress repository as category `threat_intel`; non-Sigma YAML is rejected by the structural gates and reported in the manifest.
- Support refreshing either source independently for local maintenance, while CI refreshes both together.
- Preserve existing non-managed library entries unless a higher-priority managed source publishes the same ID.
