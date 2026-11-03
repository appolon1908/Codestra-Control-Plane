"""Retired CLI entrypoints must stop before dependencies or external effects."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PYTHON_COMMANDS = (
    "codestra-apply-required-ruleset",
    "codestra-github-check",
    "codestra-promotion-check",
    "codestra-promote",
    "codestra-install-family-governance",
    "codestra-rollout-v3-clean-prs",
    "codestra-github-statusd",
)
SHELL_COMMAND = "codestra-rollout-standalone-governance"
OLD_ARGUMENTS = {
    "codestra-apply-required-ruleset": ["--apply"],
    "codestra-github-check": ["--product", "middleware", "--repo-path", "/unused",
                             "--head-ref", "section/fixture", "--base-ref", "development",
                             "--head-sha", "a" * 40],
    "codestra-promotion-check": ["--product", "middleware", "--source-level", "section",
                                "--source-ref", "section/fixture", "--target-level", "development",
                                "--target-ref", "development", "--sha", "a" * 40],
    "codestra-promote": ["--repo", "/unused", "--product", "middleware",
                        "--head", "section/fixture", "--base", "development", "--open-pr"],
    "codestra-install-family-governance": ["Middleware-", "--apply"],
    "codestra-rollout-v3-clean-prs": [],
    "codestra-github-statusd": [],
}
GUIDANCE = "GitHub Actions and repository protections"
DESIGN = "docs/superpowers/specs/2026-11-02-native-github-governance-design.md"

# Execute the actual CLI in a fresh interpreter, including its __main__ guard.
# The audit hook prevents writes/processes/network even when testing old code.
PYTHON_SANDBOX = r'''
import contextlib, importlib.abc, io, json, os, pathlib, runpy, sys
entry, *arguments = sys.argv[1:]
attempts = []
class NoRuntimeDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'psycopg2', 'requests', 'cryptography'}:
            attempts.append('dependency:' + fullname)
            raise ImportError('runtime dependencies deliberately unavailable')
sys.meta_path.insert(0, NoRuntimeDependencies())
def audit(event, args):
    forbidden = event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn', 'os.fork'))
    forbidden |= event in {'os.system', 'os.mkdir', 'os.remove', 'os.rename', 'os.rmdir',
                          'os.chmod', 'os.chown', 'os.truncate', 'os.link', 'os.symlink'}
    if event == 'open':
        mode, flags = args[1:3]
        forbidden |= isinstance(mode, str) and any(c in mode for c in 'wax+')
        forbidden |= isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    if forbidden:
        attempts.append(event)
        raise RuntimeError('external effect forbidden: ' + event)
sys.addaudithook(audit)
sys.argv = [entry, *arguments]
out, err = io.StringIO(), io.StringIO()
code, error = 0, None
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    try:
        runpy.run_path(entry, run_name='__main__')
    except SystemExit as exc:
        code = exc.code
    except BaseException as exc:
        code, error = 99, type(exc).__name__ + ': ' + str(exc)
print(json.dumps({'code': code, 'stdout': out.getvalue(), 'stderr': err.getvalue(),
                  'attempts': attempts, 'error': error}))
'''

# No command from the historical shell body is allowed to execute. DEBUG traps
# run before commands, and the only accepted operations are shell builtins used
# by the retirement header. Any redirection except stderr also fails closed.
SHELL_SANDBOX = r'''
set -T
trap 'case "$BASH_COMMAND" in
  "source \"\$1\"") ;;
  "set -euo pipefail") ;;
  "printf "*)
    candidate=${BASH_COMMAND//>&2/}
    case "$candidate" in *\>*|*\<*) printf "SANDBOX_BLOCKED:redirection\n" >&2; exit 97;; esac ;;
  "exit 2") ;;
  *) printf "SANDBOX_BLOCKED:%s\n" "$BASH_COMMAND" >&2; exit 97 ;;
esac' DEBUG
source "$1"
'''


class RetiredSourceGateTests(unittest.TestCase):
    def assert_refusal(self, result):
        self.assertEqual(result["code"], 2, result)
        self.assertEqual(result["stdout"], "", result)
        self.assertIn("RETIRED_SOURCE_GATE", result["stderr"], result)
        self.assertIn(GUIDANCE, result["stderr"], result)
        self.assertIn(DESIGN, result["stderr"], result)
        self.assertNotRegex(result["stderr"], r"\b(?:PASS|CERTIFIED|success)\b")

    def test_python_commands_refuse_before_missing_dependencies_or_effects(self):
        for command in PYTHON_COMMANDS:
            for arguments in (["--help"], ["--apply"], OLD_ARGUMENTS[command]):
                with self.subTest(command=command, arguments=arguments):
                    child = subprocess.run(
                        [sys.executable, "-I", "-S", "-c", PYTHON_SANDBOX,
                         str(ROOT / "bin" / command), *arguments],
                        capture_output=True, text=True, check=True, timeout=15,
                    )
                    result = json.loads(child.stdout)
                    self.assertEqual(result["attempts"], [], result)
                    self.assertIsNone(result["error"], result)
                    self.assert_refusal(result)

    def test_shell_command_refuses_before_any_external_command(self):
        bash = shutil.which("bash")
        if os.name == "nt":
            git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
            if git_bash.exists():
                bash = str(git_bash)
        self.assertIsNotNone(bash, "Bash is required to verify the retired shell entrypoint")
        environment = {k: v for k, v in os.environ.items() if k not in {"BASH_ENV", "ENV"}}
        for arguments in ([], ["--apply"], ["Middleware-", "--apply"]):
            with self.subTest(arguments=arguments):
                child = subprocess.run(
                    [bash, "--noprofile", "--norc", "-c", SHELL_SANDBOX, "sandbox",
                     (ROOT / "bin" / SHELL_COMMAND).as_posix(), *arguments],
                    env=environment, capture_output=True, text=True, timeout=15,
                )
                self.assertNotIn("SANDBOX_BLOCKED", child.stderr, child.stderr)
                self.assert_refusal({"code": child.returncode,
                                     "stdout": child.stdout, "stderr": child.stderr})


if __name__ == "__main__":
    unittest.main()
