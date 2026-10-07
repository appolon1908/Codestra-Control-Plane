#!/usr/bin/env bash
set -euo pipefail
wt="$1"
parent="$2"
branch="$3"
actual=$(git -C "$wt" branch --show-current)
[ "$actual" = "$branch" ] || { echo "EXPECTED_BRANCH=FAIL actual=$actual expected=$branch"; exit 1; }
echo EXPECTED_BRANCH=PASS
[ -z "$(git -C "$wt" status --porcelain)" ] || { echo TREE_CLEAN=FAIL; exit 1; }
echo TREE_CLEAN=PASS
git -C "$wt" fetch --prune origin >/dev/null
git -C "$wt" rev-parse --verify "origin/$parent" >/dev/null
echo PARENT_EXISTS=PASS
echo HEAD_SHA=$(git -C "$wt" rev-parse HEAD)
echo AHEAD=$(git -C "$wt" rev-list --count "origin/$parent..HEAD")
echo BEHIND=$(git -C "$wt" rev-list --count "HEAD..origin/$parent")
echo PRODUCTION_EFFECTS=OFF
echo PREFLIGHT=PASS
