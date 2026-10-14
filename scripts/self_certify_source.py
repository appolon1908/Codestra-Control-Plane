#!/usr/bin/env python3
"""Fail-closed, source-only self-certification (not a GitHub required check).

Run on an exact clean Git commit. Confirm the authenticated remote branch SHA,
exercise the full no-effects offline suite with site packages disabled and
produce an immutable local JSON evidence record outside the Git checkout.
This does NOT grant independent reviewer approval or production authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
SUITE = ("-S", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v")
LIMIT_SECONDS = 180
APPROVED_ORIGINS = frozenset({
    "https://github.com/appolon1908/Codestra-Control-Plane.git",
    "git@github.com:appolon1908/Codestra-Control-Plane.git",
    "ssh://git@github.com/appolon1908/Codestra-Control-Plane.git",
})


class CertificationError(RuntimeError):
    pass


def run(args: list[str], root: Path, *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args, cwd=root, env=env, text=True, capture_output=True,
        timeout=LIMIT_SECONDS, check=False,
    )
    if result.returncode:
        raise CertificationError(
            f"{args[0]} returned {result.returncode}: "
            + (result.stdout + "\n" + result.stderr)[-2000:]
        )
    return result.stdout + result.stderr


def assert_destination(root: Path, output: Path) -> Path:
    path = output.expanduser().resolve()
    if path == root or path.is_relative_to(root):
        raise CertificationError("evidence must be outside the checkout")
    if path.exists():
        raise CertificationError("evidence file already exists; never overwrite evidence")
    if not path.parent.is_dir():
        raise CertificationError("evidence directory does not exist")
    return path


def validate_ref(ref: str) -> None:
    if not REF.fullmatch(ref) or ".." in ref or ref.startswith("-") or ref.endswith("/"):
        raise CertificationError("invalid source branch")
    if ref.startswith("/") or "//" in ref:
        raise CertificationError("invalid source branch")


def certify(
    root: Path, *, expected_sha: str, branch: str, output: Path
) -> dict[str, object]:
    root = root.resolve(strict=True)
    target = assert_destination(root, output)
    if not HEX40.fullmatch(expected_sha):
        raise CertificationError("expected commit must be a full SHA-1 hex")
    validate_ref(branch)
    if run(["git", "rev-parse", "--show-toplevel"], root).strip() != str(root):
        raise CertificationError("source directory is not the checkout root")
    head = run(["git", "rev-parse", "HEAD"], root).strip()
    if head != expected_sha:
        raise CertificationError("HEAD differs from requested exact SHA")
    if run(["git", "status", "--porcelain", "--untracked-files=all"], root).strip():
        raise CertificationError("checkout has local edits or untracked files")
    if run(["git", "diff", "HEAD^", "HEAD", "--check"], root).strip():
        raise CertificationError("commit violates git diff --check")

    remote_url = run(["git", "remote", "get-url", "origin"], root).strip()
    if remote_url not in APPROVED_ORIGINS:
        raise CertificationError("origin is not the expected canonical source repository")
    remote_ref = "refs/heads/" + branch
    response = run(["git", "ls-remote", "--exit-code", "origin", remote_ref], root)
    lines = [line.split() for line in response.splitlines()]
    if len(lines) != 1 or len(lines[0]) != 2 or lines[0][1] != remote_ref:
        raise CertificationError("remote branch response not exact")
    if lines[0][0] != head:
        raise CertificationError("remote branch HEAD does not match the tested commit")

    tree = run(["git", "rev-parse", "HEAD^{tree}"], root).strip()
    # -S disables imports from third-party site packages. The test suite mocks
    # all live PostgreSQL/HTTP publication boundaries. Do not use live effects.
    env = os.environ.copy()
    env.update({
        "PRODUCTION_GO": "NO",
        "LIVE_CAPABILITIES_ENABLED": "NO",
        "EXTERNAL_EFFECTS": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    })
    output_text = run([sys.executable, *SUITE], root, env=env)
    match = re.search(r"Ran (\d+) tests? in [\d.]+s", output_text)
    if match is None or int(match.group(1)) < 9:
        raise CertificationError("offline suite count is missing or incomplete")
    if not re.search(r"^OK\s*$", output_text, re.MULTILINE):
        raise CertificationError("offline suite did not report success")
    if run(["git", "status", "--porcelain", "--untracked-files=all"], root).strip():
        raise CertificationError("tests dirtied the checkout")

    evidence: dict[str, object] = {
        "schema": "codestra.self-certification.source.v1",
        "level": "LOCAL_EXACT_SHA_SOURCE_TESTS_PASSED",
        "repository": "appolon1908/Codestra-Control-Plane",
        "branch": branch,
        "head_sha": head,
        "tree_sha": tree,
        "remote_sha": lines[0][0],
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "host_platform": platform.system(),
        "tests_run": int(match.group(1)),
        "test_command": "python3 -S -m unittest discover -s tests -p test_*.py -v",
        "test_output_sha256": hashlib.sha256(output_text.encode()).hexdigest(),
        "checked_clean_before_and_after": True,
        "production_go": "NO",
        "live_capabilities_enabled": "NO",
        "external_effects": "false",
        "github_ci_certified": False,
        "independent_codeowner_approved": False,
        "merge_or_promotion_authorized": False,
    }
    # Exclusive creation prevents evidence overwrites or misleading reuse.
    with target.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        evidence = certify(
            args.root, expected_sha=args.expected_sha,
            branch=args.branch, output=args.output,
        )
    except (CertificationError, OSError, subprocess.TimeoutExpired) as exc:
        print("SELF_CERTIFICATION=FAIL " + str(exc), file=sys.stderr)
        return 1
    print("SELF_CERTIFICATION=LOCAL_SOURCE_PASS")
    print("HEAD_SHA=" + str(evidence["head_sha"]))
    print("REMOTE_SHA=" + str(evidence["remote_sha"]))
    print("TESTS=" + str(evidence["tests_run"]))
    print("EVIDENCE=" + str(args.output.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
