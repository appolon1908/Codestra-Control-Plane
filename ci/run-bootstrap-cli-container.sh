#!/usr/bin/env bash
# Run fixed-path broker integration only in an offline disposable container.
set -euo pipefail

image_id="${1:-}"
if [[ $# -ne 1 || ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo 'Usage: run-bootstrap-cli-container.sh sha256:<reviewed-local-image-id>' >&2
  exit 2
fi
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$repo_root" == *','* || "$repo_root" == *$'\n'* ]]; then
  echo 'Source path cannot be encoded safely as a Docker bind mount' >&2
  exit 2
fi
actual_id="$(docker image inspect --format '{{.Id}}' "$image_id")"
if [[ "$actual_id" != "$image_id" ]]; then
  echo 'Reviewed local image identity mismatch' >&2
  exit 2
fi

exec docker run --rm --init --network none --read-only --user 0:0 \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 512m --cpus 1 \
  --mount "type=bind,src=$repo_root,dst=/source,readonly" \
  --tmpfs /etc/codestra:rw,nosuid,nodev,noexec,mode=755 \
  --tmpfs /var/lib/codestra:rw,nosuid,nodev,noexec,mode=755 \
  --tmpfs /staging:rw,nosuid,nodev,noexec,mode=755 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 \
  -e CODESTRA_DISPOSABLE_BOOTSTRAP_TEST=1 -e PYTHONDONTWRITEBYTECODE=1 \
  -e PRODUCTION_GO=NO -e LIVE_CAPABILITIES_ENABLED=NO -e EXTERNAL_EFFECTS=false \
  --entrypoint python3 "$image_id" /source/tests/integration/bootstrap_cli.py
