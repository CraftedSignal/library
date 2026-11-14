#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?A token that can push the automation branch and open its PR is required}"
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_RUN_ID:?}"

cd "$(git rev-parse --show-toplevel)"
base_sha=$(git rev-parse HEAD)
branch=automation/upstream-sync
branch_ref="refs/heads/$branch"

# These are the only outputs the trusted main-branch generators may publish.
# Never stage refresh tokens, upstream checkouts, or source/workflow changes.
git add -A -- entries library.index.yaml sigmahq.sync.yaml huntress.sync.yaml ai-dfir-toolkit.sync.yaml
while IFS= read -r -d '' path; do
  case "$path" in
    entries/*|library.index.yaml|sigmahq.sync.yaml|huntress.sync.yaml|ai-dfir-toolkit.sync.yaml) ;;
    *) echo "Refusing publication outside generated mirror paths: $path" >&2; exit 1 ;;
  esac
done < <(git diff --cached --name-only -z "$base_sha")
tree=$(git write-tree)

previous=""
if git ls-remote --exit-code --heads origin "$branch_ref" > /dev/null; then
  git fetch --no-tags --depth=1 origin "$branch_ref"
  previous=$(git rev-parse FETCH_HEAD)
else
  status=$?
  if [ "$status" -ne 2 ]; then
    exit "$status"
  fi
fi

changed=true
if git diff --quiet "$base_sha" "$tree"; then
  changed=false
  if [ -z "$previous" ]; then
    echo "No generated mirror changes to publish"
    exit 0
  fi
fi

if [ -z "$previous" ] || [ "$(git rev-parse "$previous^{tree}")" != "$tree" ]; then
  parents=(-p "$base_sha")
  if [ -n "$previous" ] && [ "$previous" != "$base_sha" ]; then
    # Retain both the pending snapshot's history and the reviewed main source.
    # The resulting snapshot advances the automation branch without a force push.
    parents=(-p "$previous" -p "$base_sha")
  fi
  commit=$(git -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit-tree "$tree" "${parents[@]}" <<EOF
sync: update community detections

Source-Commit: $base_sha
Workflow-Run: ${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID
EOF
  )
  # GH_PAT causes PR/synchronize events to run CI. A concurrent branch update
  # rejects this ordinary push rather than overwriting someone else's commit.
  git -c credential.helper='!gh auth git-credential' push origin "$commit:$branch_ref"
fi

if [ "$changed" = false ]; then
  echo "Automation branch matches main; no new PR is needed"
  exit 0
fi

pr=$(gh pr list --repo "$GITHUB_REPOSITORY" --state open --base main --head "$branch" --json number --jq '.[0].number // empty')
body_file=$(mktemp)
trap 'rm -f "$body_file"' EXIT
cat > "$body_file" <<EOF
Updates the generated community detection mirror from the configured upstream sources.

The generated entries and sync manifests retain their upstream source commit identifiers.
Generation used reviewed main commit $base_sha.

Run: ${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID

Merge after the required Mirror tests check passes. This workflow does not approve or merge this PR.
EOF
if [ -z "$pr" ]; then
  gh pr create --repo "$GITHUB_REPOSITORY" --base main --head "$branch" \
    --title 'sync: update community detections' --body-file "$body_file"
else
  # gh pr edit also queries organization/team metadata and requires read:org.
  # Updating only the body through REST keeps the token scoped to this repo.
  gh api --method PATCH "repos/$GITHUB_REPOSITORY/pulls/$pr" --field "body=@$body_file" --silent
  echo "Updated existing mirror PR #$pr"
fi
