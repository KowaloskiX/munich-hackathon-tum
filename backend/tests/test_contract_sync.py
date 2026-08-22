"""The frozen contracts are mirrored on both sides — enforced, not described.

AGENTS.md rule 4 says a contract change updates `backend/app/models.py`,
`dashboard/src/types.ts` and the mock generator in one change. Prose does not
fail a build, so these tests parse the TypeScript mirror and compare it against
the pydantic models. A field added on one side only turns `make check` red.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel

from app.models import (
    Counters,
    EventType,
    FleetSnapshot,
    LiveEvent,
    NodeState,
    NodeView,
)

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboard" / "src"
TYPES_TS = DASHBOARD / "types.ts"
REDUCER_TS = DASHBOARD / "reducer.ts"

# Every pydantic model that crosses the WS/HTTP boundary to the dashboard.
# A new one goes here in the same change that adds its TS interface.
MIRRORED: dict[str, type[BaseModel]] = {
    "NodeView": NodeView,
    "Counters": Counters,
    "FleetSnapshot": FleetSnapshot,
    "LiveEvent": LiveEvent,
}


def _ts_source(path: Path) -> str:
    assert path.exists(), f"missing TS mirror: {path}"
    return path.read_text()


def _ts_string_union(name: str) -> set[str]:
    """Members of `export type <name> = "A" | "B";` (single- or multi-line)."""
    src = _ts_source(TYPES_TS)
    match = re.search(rf"export type {name}\s*=(.*?);", src, re.DOTALL)
    assert match, f"{name} is not declared in {TYPES_TS.name}"
    return set(re.findall(r'"([A-Z_]+)"', match.group(1)))


def _ts_interface_fields() -> dict[str, set[str]]:
    """Field names per `export interface X { ... }`, keyed by interface name."""
    src = _ts_source(TYPES_TS)
    out: dict[str, set[str]] = {}
    for match in re.finditer(r"export interface (\w+) \{(.*?)\n\}", src, re.DOTALL):
        body = match.group(2)
        out[match.group(1)] = set(re.findall(r"^\s*(\w+)\??:", body, re.MULTILINE))
    return out


def test_node_state_enum_is_mirrored() -> None:
    assert _ts_string_union("NodeState") == {m.value for m in NodeState}


def test_event_type_enum_is_mirrored() -> None:
    assert _ts_string_union("EventType") == {m.value for m in EventType}


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_model_fields_are_mirrored(name: str) -> None:
    interfaces = _ts_interface_fields()
    assert name in interfaces, f"{name} has no `export interface {name}` in types.ts"
    assert set(MIRRORED[name].model_fields) == interfaces[name]


def test_reducer_handles_every_event_type() -> None:
    """An unhandled event falls through to the raw type string in the timeline."""
    handled = set(re.findall(r'case "([A-Z_]+)":', _ts_source(REDUCER_TS)))
    missing = {m.value for m in EventType} - handled
    assert not missing, f"reducer.ts describe() does not handle: {sorted(missing)}"
