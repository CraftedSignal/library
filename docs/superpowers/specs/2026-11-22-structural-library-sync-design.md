# Structural Library Sync Design

## Intent

Make scheduled library generation deterministic and honest: a run with no material source changes must not create a commit or pull request, and a failed source refresh must not be reported as a successful sync.

## Goals

- Keep generated manifests byte-stable when their upstream snapshot is unchanged.
- Retain durable provenance through each manifest's `source_commit`.
- Keep operational check times in GitHub Actions and commit metadata, not generated source files.
- Stop publication when the detections.ai community source cannot refresh.
- Prove no-op generation is deterministic with a regression test.

## Non-goals

- Replace or reverse-engineer the removed detections.ai API contract.
- Change source quality gates, precedence, or generated library entry content.
- Redesign the automation branch or pull-request publisher.

## Constraints

- Preserve the current atomic generated snapshot: all configured sources must refresh before publication.
- Use only the existing Go and Python toolchains and add no dependencies.
- Keep token rotation cleanup eligible to run after a failed refresh.

## Approaches

1. **Remove `synced_at` from committed manifests (selected).** The manifest becomes a deterministic description of the imported snapshot. GitHub already records run and commit time. This removes the volatile input at its source.
2. Preserve the old timestamp when all other manifest fields match. This keeps the field but adds stateful read/compare/write behavior and ambiguous semantics when generator code changes.
3. Teach the publisher to ignore timestamp-only diffs. This masks nondeterminism late in the pipeline and leaves local generation dirty on every run.

## Design

`mergeAndWriteManifests` will no longer accept a wall-clock argument or emit `synced_at`. Existing generated manifests will drop that field once. Re-running the same batches must produce identical manifest bytes. The scheduled workflow will remove `continue-on-error` from the detections.ai refresh. The existing `if: always()` token-rotation cleanup remains, while normal GitHub Actions success gating prevents the curated merge and publication steps from running after a failed community refresh.

## Success Criteria

- Two identical generator runs produce byte-identical sync manifests.
- A no-op scheduled run leaves the generated Git tree equal to `main`, so the publisher exits without a branch or PR update.
- A detections.ai refresh error makes the sync job fail and prevents publication.

