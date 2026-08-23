"""Per-node filter store: which compiled filter each node is enforcing."""

from __future__ import annotations

from .filter_runtime import FilterRuntime


class FilterStore:
    """One FilterRuntime per node. Missing / unloaded node -> pass-through."""

    def __init__(self) -> None:
        self._by_node: dict[str, FilterRuntime] = {}

    def get(self, node_id: str) -> FilterRuntime | None:
        return self._by_node.get(node_id)

    def runtime(self, node_id: str) -> FilterRuntime:
        """Get-or-create the runtime for a node."""
        rt = self._by_node.get(node_id)
        if rt is None:
            rt = FilterRuntime()
            self._by_node[node_id] = rt
        return rt

    def partition(self, node_id: str, frames: list[str]) -> tuple[list[str], list[str]]:
        """(kept, dropped). Pass everything through when no filter is loaded."""
        rt = self._by_node.get(node_id)
        if rt is None or not rt.loaded:
            return list(frames), []
        return rt.partition(frames)

    def version(self, node_id: str) -> str | None:
        rt = self._by_node.get(node_id)
        return rt.version if rt else None

    def clear(self) -> None:
        """Unload every demo filter and release its temporary artifacts."""
        for runtime in self._by_node.values():
            runtime.close()
        self._by_node.clear()
