"""Side-effect-free refusal for superseded source-governance commands."""
import sys


GUIDANCE = (
    "RETIRED_SOURCE_GATE: Use GitHub Actions and repository protections for "
    "source publication and merging. Keep required CI, verified signatures, "
    "independent review and resolved threads; deployment needs separate approval.\n"
    "See docs/superpowers/specs/2026-11-02-native-github-governance-design.md"
)


def refuse():
    """Do not translate an obsolete controller invocation into approval."""
    print(GUIDANCE, file=sys.stderr)
    return 2
