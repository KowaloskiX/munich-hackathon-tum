"""Compiled-filter runtime — the part that actually drops frames.

The backend writes a C filter and its independent oracle verifies it on held-out
captures. This runtime then *enforces* the verified filter in the traffic path:
it compiles the C to a native shared object (`clang -shared -fPIC`), loads it via
ctypes (`dlopen`), and runs every frame through the real `block_frame()`. The
`.so` is genuine machine code; a dropped frame provably never leaves the process.

`FilterRuntime` owns one compiled filter and swaps it atomically on reload. A
filter that will not compile raises `CompileError` and leaves the previous one
running — enforcement never silently degrades to "pass everything".
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from ctypes import CDLL, POINTER, c_bool, c_size_t, c_uint8
from pathlib import Path
from typing import Any

COMPILE_TIMEOUT_S = 20
CLANG_ARGS = ["clang", "-shared", "-fPIC", "-O2"]


class CompileError(RuntimeError):
    """The filter would not compile or load — keep the previous one."""


def parse_hex(line: str) -> bytes | None:
    """Decode one frame line to bytes; None for blank/comment/garbage.

    Strips inline `# ...` comments, whitespace, and separators `_ : -`.
    """
    body = line.split("#", 1)[0]
    cleaned = "".join(c for c in body if c not in " \t\r\n_:-")
    if not cleaned:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _compile_shared(filter_c_code: str, workdir: Path) -> Path:
    src = workdir / "filter.c"
    src.write_text(filter_c_code)
    so = workdir / "filter.so"
    try:
        proc = subprocess.run(
            [*CLANG_ARGS, str(src), "-o", str(so)],
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT_S,
            cwd=workdir,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise CompileError(f"compile error: {exc}") from exc
    if proc.returncode != 0:
        raise CompileError(f"compile failed:\n{proc.stderr.strip()}")
    return so


def _load_block_frame(so: Path) -> Any:
    """dlopen the shared object and return its block_frame function pointer.

    Contract: `bool block_frame(const uint8_t *f, size_t n)`. Typed Any as
    ctypes exposes no clean public type for a function pointer.
    """
    lib = CDLL(str(so))
    fn = lib.block_frame
    fn.restype = c_bool
    fn.argtypes = [POINTER(c_uint8), c_size_t]
    return fn


class FilterRuntime:
    """Holds one compiled filter for a node and enforces it on frames."""

    def __init__(self) -> None:
        self._fn: Any = None
        self._workdir: Path | None = None
        self.version: str | None = None
        self.attack_class: str = ""
        self.code: str = ""  # C source currently enforced (for status/persist)
        self.evaluated: int = 0  # frames the native filter has run on
        # Proof of native compilation, populated on reload:
        self.so_path: str | None = None
        self.so_sha: str = ""
        self.so_bytes: int = 0

    @property
    def loaded(self) -> bool:
        return self._fn is not None

    def reload(self, filter_c_code: str, version: str, attack_class: str = "") -> str:
        """Compile + dlopen a new filter, swapping atomically. Raises on bad C."""
        workdir = Path(tempfile.mkdtemp(prefix="edge-filter-"))
        try:
            so = _compile_shared(filter_c_code, workdir)
            fn = _load_block_frame(so)
        except CompileError:
            shutil.rmtree(workdir, ignore_errors=True)
            raise  # previous filter stays live
        so_bytes = so.read_bytes()
        old = self._workdir
        self._fn = fn
        self.version = version
        self.attack_class = attack_class
        self.code = filter_c_code
        self.so_path = str(so)
        self.so_sha = hashlib.sha256(so_bytes).hexdigest()[:12]
        self.so_bytes = len(so_bytes)
        self._workdir = workdir
        if old is not None:
            shutil.rmtree(old, ignore_errors=True)
        return version

    def blocks(self, frame_hex: str) -> bool:
        """True if the loaded filter drops this frame. Undecodable -> pass."""
        if self._fn is None:
            return False
        frame = parse_hex(frame_hex)
        if frame is None:
            return False
        buf = (c_uint8 * len(frame)).from_buffer_copy(frame)
        return bool(self._fn(buf, len(frame)))

    def partition(self, frames: list[str]) -> tuple[list[str], list[str]]:
        """Split frames into (kept, dropped) by running the real native filter."""
        kept: list[str] = []
        dropped: list[str] = []
        for frame_hex in frames:
            if self._fn is not None:
                self.evaluated += 1
            (dropped if self.blocks(frame_hex) else kept).append(frame_hex)
        return kept, dropped
