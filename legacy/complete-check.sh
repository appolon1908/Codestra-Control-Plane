#!/usr/bin/env bash
set -euo pipefail
wt="$1"
branch="$2"
[ -z "$(git -C "$wt" status --porcelain)" ] || { echo TREE_CLEAN=NO; exit 1; }
echo TREE_CLEAN=YES
local_sha=$(git -C "$wt" rev-parse HEAD)
remote_sha=$(git -C "$wt" ls-remote origin "refs/heads/$branch" | awk "{print \$1}")
[ -n "$remote_sha" ] || { echo REMOTE_BRANCH=NO; exit 1; }
[ "$local_sha" = "$remote_sha" ] || { echo "LOCAL_REMOTE_SHA_MATCH=NO local=$local_sha remote=$remote_sha"; exit 1; }
echo LOCAL_REMOTE_SHA_MATCH=YES
git -C "$wt" diff --check
echo DIFF_CHECK=PASS
echo STATUS=COMPLETE_CANDIDATE
