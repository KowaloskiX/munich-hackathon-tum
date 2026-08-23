"""Structural guards for the rules that keep verification honest.

AGENTS.md rule 5 ("the oracle is authoritative, never let a component
self-report a pass") is only true while the agent cannot reach the verifier or
the held-out fixtures. These tests read the import graph instead of trusting a
sentence, so wiring them together fails `make check` rather than the demo.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# module -> (modules it must not import, why)
FORBIDDEN: dict[str, tuple[set[str], str]] = {
    "agent_stub": (
        {"oracle", "orchestrator", "state"},
        "the agent side must not reach the verifier or the live fleet state",
    ),
    "link_scout": (
        {"oracle", "orchestrator", "state"},
        "the web-domain scout is an agent: no reach to the verifier or fleet state",
    ),
    "link_agent_devin": (
        {"oracle", "orchestrator", "state"},
        "the devin scout is an agent: no reach to the verifier or fleet state",
    ),
    "oracle": (
        {"agent_stub", "orchestrator", "state"},
        "the oracle stays independent of what it judges",
    ),
    "models": (
        {"agent_stub", "main", "mockgen", "oracle", "orchestrator", "state"},
        "the frozen contracts are a leaf: everything imports them, they import nothing",
    ),
}


def _local_imports(path: Path) -> set[str]:
    """Sibling `app.*` modules imported by `path`, relative or absolute."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom):
            if node.level and node.module:  # from .oracle import run_oracle
                names.add(node.module.split(".")[0])
            elif node.level:  # from . import mockgen
                names.update(alias.name for alias in node.names)
            elif node.module and node.module.startswith("app."):
                names.add(node.module.split(".")[1])
        elif isinstance(node, ast.Import):
            names.update(a.name.split(".")[1] for a in node.names if a.name.startswith("app."))
    return names


def _code_strings(path: Path) -> list[str]:
    """String literals that are actually used, i.e. excluding docstrings."""
    tree = ast.parse(path.read_text())
    docstrings = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


@pytest.mark.parametrize("module", sorted(FORBIDDEN))
def test_forbidden_imports(module: str) -> None:
    forbidden, why = FORBIDDEN[module]
    leaked = _local_imports(APP / f"{module}.py") & forbidden
    assert not leaked, f"{module}.py imports {sorted(leaked)} — {why}"


def test_only_the_oracle_names_the_held_out_fixtures() -> None:
    """The fixtures are the answer key. A filter author that can read them wins for free."""
    for path in sorted(APP.glob("*.py")):
        if path.name == "oracle.py":
            continue
        offenders = [s for s in _code_strings(path) if "fixture" in s.lower()]
        assert not offenders, f"{path.name} references the held-out fixtures: {offenders}"
