#!/usr/bin/env python3
"""Read-only, exact SHA, offline *scoped source* evidence; never release authority."""
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys

OWNER = "appolon1908"
IMAGE = "codestra-middleware-ci:4d83aa9a11f21acba04337a2027e35d66191297f"
IMAGE_ID = "sha256:da5804b4d68ca099affa16ab8e47b142d040ef33e99587558ab30dd765d3474e"
PROFILES = {
    "Kong": ["tests/test_gateway_release_boundaries.py", "tests/test_kong_v3_identity_security.py", "tests/test_kong_cross_repo_parity.py"],
    "Caddy": ["tests/test_pas141_private_boundaries.py", "tests/test_caddy_readonly_validator.py", "tests/test_caddy_staging_candidate.py"],
    "Keycloak": ["tests/test_keycloak_token_scope_and_plan_errors.py", "tests/test_production_certification_contract.py", "tests/test_openbao_workload_identity.py"],
    "Codestra-OpenBao": ["tests/test_mcr_contract.py"],
}


def call(args, root):
    p = subprocess.run(args, cwd=root, capture_output=True, text=True, timeout=180, check=False)
    if p.returncode:
        raise RuntimeError(f"execution failed {p.returncode}: {(p.stdout+p.stderr)[-1000:]}")
    return p.stdout + p.stderr


def certify(name, root, expected, outfile):
    if name not in PROFILES or not re.fullmatch("[a-f0-9]{40}", expected):
        raise ValueError("unsupported repository or invalid full SHA")
    root = Path(root).resolve(strict=True)
    outfile = Path(outfile).resolve()
    if outfile.exists() or outfile.is_relative_to(root) or not outfile.parent.is_dir():
        raise ValueError("evidence must be new and outside the checkout")
    if call(["git", "rev-parse", "--show-toplevel"], root).strip() != str(root):
        raise ValueError("not the canonical checkout root")
    head = call(["git", "rev-parse", "HEAD"], root).strip()
    if head != expected or call(["git", "status", "--porcelain", "--untracked-files=all"], root).strip():
        raise ValueError("source has wrong SHA or is dirty")
    origin = call(["git", "remote", "get-url", "origin"], root).strip()
    allowed = {f"https://github.com/{OWNER}/{name}.git", f"git@github.com:{OWNER}/{name}.git"}
    if origin not in allowed:
        raise ValueError("source origin is not trusted")
    if call(["git", "ls-remote", "origin", "refs/heads/main"], root).split() != [head, "refs/heads/main"]:
        raise ValueError("source HEAD does not match remote main")
    tree = call(["git", "rev-parse", "HEAD^{tree}"], root).strip()
    image_id = call(["sudo", "-n", "docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], root).strip()
    if image_id != IMAGE_ID:
        raise ValueError("local offline-test image digest differs from review")
    for file in PROFILES[name]:
        path = root / file
        if not path.is_file() or path.is_symlink():
            raise ValueError("reviewed test path invalid: " + file)
    target = (["-S", "-m", "unittest", "discover", "-s", "tests", "-p", "test_mcr_contract.py", "-v"]
              if name == "Codestra-OpenBao" else
              ["-m", "pytest", "-q", "-p", "no:cacheprovider", *PROFILES[name]])
    args = ["sudo", "-n", "docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--entrypoint", "python", "-e", "PYTHONPATH=/review",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PRODUCTION_GO=NO",
            "-e", "LIVE_CAPABILITIES_ENABLED=NO", "-e", "EXTERNAL_EFFECTS=false",
            "-v", f"{root}:/review:ro", "--workdir", "/review", IMAGE, *target]
    output = call(args, root)
    if name == "Codestra-OpenBao":
        count = re.search(r"Ran ([0-9]+) tests?", output)
        if not count or "OK" not in output.splitlines():
            raise ValueError("test success evidence absent")
        passed, skipped = int(count[1]), 0
    else:
        count = re.search(r"([0-9]+) passed(?:, ([0-9]+) skipped)?", output)
        if not count:
            raise ValueError("test success evidence absent")
        passed, skipped = int(count[1]), int(count[2] or 0)
    if not passed or call(["git", "status", "--porcelain", "--untracked-files=all"], root).strip():
        raise ValueError("insufficient tests or checkout modified")
    result = {
        "schema": "codestra.self-certification.scoped-source.v1",
        "level": "LOCAL_EXACT_SHA_SCOPED_SOURCE_TESTS_PASSED",
        "repository": f"{OWNER}/{name}", "ref": "refs/heads/main",
        "head_sha": head, "remote_sha": head, "tree_sha": tree,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "container_image_id": image_id, "network": "none", "source_mount": "read_only",
        "test_files": PROFILES[name], "tests_passed": passed, "tests_skipped": skipped,
        "test_output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "source_verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_clean_before_after": True, "production_go": "NO",
        "external_effects": "false", "live_capabilities_enabled": "NO",
        "scope": "selected source tests only; no live/runtime certification",
        "github_ci_certified": False, "independent_codeowner_approved": False,
        "runtime_deployment_certified": False, "merge_or_promotion_authorized": False,
    }
    with outfile.open("x") as fp:
        json.dump(result, fp, sort_keys=True, indent=2)
        fp.write(chr(10))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, choices=PROFILES)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--output", required=True)
    a = parser.parse_args()
    try:
        record = certify(a.repository, a.source, a.expected_sha, a.output)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"SELF_CERTIFICATION=FAIL {exc}", file=sys.stderr)
        sys.exit(1)
    print("SELF_CERTIFICATION=LOCAL_SCOPED_SOURCE_PASS")
    print("SHA", record["head_sha"], "TESTS", record["tests_passed"], "SKIPS", record["tests_skipped"])
    print("EVIDENCE", a.output)
