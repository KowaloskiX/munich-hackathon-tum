"""Platform-safe compiler arguments for native filter shared libraries."""

from __future__ import annotations

import os


def shared_library_clang_args(os_name: str | None = None) -> list[str]:
    """Return clang flags accepted by the active platform toolchain."""
    platform = os.name if os_name is None else os_name
    platform_flags = ["-Wl,/export:block_frame"] if platform == "nt" else ["-fPIC"]
    return ["clang", "-shared", *platform_flags, "-O2"]
