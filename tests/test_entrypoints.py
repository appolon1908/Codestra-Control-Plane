"""Parse imported entry points without running their live-effect code."""

import ast
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


def entrypoints():
    return sorted(
        list((ROOT / "bin").glob("*"))
        + list((ROOT / "legacy" / "bin").glob("*"))
        + list((ROOT / "legacy").glob("*.sh"))
    )


class EntrypointSyntaxTests(unittest.TestCase):
    def test_all_python_entrypoints_parse_without_execution(self):
        checked = []
        for path in entrypoints():
            if not path.is_file():
                continue
            source = path.read_text(encoding="utf-8")
            if "python" not in source.splitlines()[0]:
                continue
            checked.append(path)
            with self.subTest(path=str(path.relative_to(ROOT))):
                try:
                    ast.parse(source, filename=str(path))
                except SyntaxError as exc:
                    self.fail(f"Entry point cannot start: {exc}")
        self.assertTrue(checked, "No Python entry points found")

    def test_shell_entrypoints_parse_without_execution(self):
        checked = []
        for path in entrypoints():
            if not path.is_file():
                continue
            first_line = path.read_text(encoding="utf-8").splitlines()[0]
            if "bash" not in first_line and not first_line.endswith("/sh"):
                continue
            checked.append(path)
            with self.subTest(path=str(path.relative_to(ROOT))):
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-n", str(path)],
                    capture_output=True, text=True, timeout=10, check=False,
                    env={"PATH": "/usr/bin:/bin"},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(checked, "No shell entry points found")
