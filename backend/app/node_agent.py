"""Software enforcement runtime — the part that makes "blocked" real.

Devin writes a C filter; the independent oracle proves it on held-out captures.
This module then does what a real protected node would do: it **compiles that
exact filter and runs frames through the compiled machine code**, counting what
the filter actually drops. The numbers on the dashboard are measured here, not
invented.

Two ways it runs, one shared core:

- Inline (default): the orchestrator calls `run_enforcement(...)` right after a
  deploy, so the demo is real out of the box with no extra process.
- Standalone: `python -m app.node_agent --backend URL --node esp-sw-01` is a real
  distributed node — it heartbeats, pulls the filter over OTA (`GET /firmware`),
  compiles + replays it, and reports real counts (`POST /enforcement`).

The oracle stays the authoritative verdict on held-out captures. Enforcement is a
*second, independent* real signal (runtime measurement on live/attack traffic),
never a replacement — so nothing here touches the held-out set.
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
import time
from collections.abc import Sequence
from ctypes import CDLL, POINTER, c_bool, c_size_t, c_uint8
from pathlib import Path
from typing import Any

from .models import EnforcementResult
from .prompts import SAMPLE_BENIGN

COMPILE_TIMEOUT_S = 20


class EnforcementError(RuntimeError):
    """The filter would not compile or load — enforcement cannot run."""


def parse_hex(line: str) -> bytes | None:
    """Decode one capture line to bytes; None for blank/comment/garbage.

    Mirrors the oracle harness decoder: strip inline `# ...` comments,
    whitespace, and the readability separators `_ : -`.
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
            ["clang", "-shared", "-fPIC", "-O2", str(src), "-o", str(so)],
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT_S,
            cwd=workdir,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise EnforcementError(f"compile error: {exc}") from exc
    if proc.returncode != 0:
        raise EnforcementError(f"compile failed:\n{proc.stderr.strip()}")
    return so


def _load_block_frame(so: Path) -> Any:
    """Load the compiled filter and return its block_frame function pointer.

    Contract: `bool block_frame(const uint8_t *f, size_t n)` (see the oracle
    harness). Returns a ctypes function pointer; typed Any as ctypes exposes no
    clean public type for it.
    """
    lib = CDLL(str(so))
    fn = lib.block_frame
    fn.restype = c_bool
    fn.argtypes = [POINTER(c_uint8), c_size_t]
    return fn


def _blocks(fn: Any, frame: bytes) -> bool:
    buf = (c_uint8 * len(frame)).from_buffer_copy(frame)
    return bool(fn(buf, len(frame)))


def _tally(fn: Any, frames: Sequence[str]) -> tuple[int, int]:
    """Return (blocked, total) over the decodable frames in the stream."""
    blocked = 0
    total = 0
    for line in frames:
        frame = parse_hex(line)
        if frame is None:
            continue
        total += 1
        if _blocks(fn, frame):
            blocked += 1
    return blocked, total


def run_enforcement(
    filter_c_code: str,
    attack_frames: Sequence[str],
    benign_frames: Sequence[str] | None = None,
) -> EnforcementResult:
    """Compile the filter, run every frame through it, and count for real.

    `attack_frames` are the captured malicious frames from the incident;
    `benign_frames` is a legitimate-traffic baseline (defaults to the shared
    sample baseline) used to measure false positives. Raises EnforcementError
    if the filter will not compile or load.
    """
    benign = list(SAMPLE_BENIGN) if benign_frames is None else list(benign_frames)
    with tempfile.TemporaryDirectory(prefix="enforce-") as tmp:
        workdir = Path(tmp)
        so = _compile_shared(filter_c_code, workdir)
        fn = _load_block_frame(so)
        atk_blocked, atk_total = _tally(fn, list(attack_frames))
        ben_blocked, ben_total = _tally(fn, benign)
    blocked = atk_blocked + ben_blocked
    total = atk_total + ben_total
    return EnforcementResult(
        blocked=blocked,
        passed=total - blocked,
        attack_total=atk_total,
        benign_total=ben_total,
        false_positives=ben_blocked,
    )


# --- standalone distributed node (real OTA pull over the wire) -----------
def run_node(backend: str, node_id: str, interval: float = 3.0, once: bool = False) -> None:
    """A real software node: heartbeat, pull the filter, enforce, report.

    Reports its cumulative blocked count in each heartbeat so the fleet's
    per-node counter stays consistent with the FRAME_BLOCKED events emitted by
    /enforcement (both track the same deltas this node produces).
    """
    import httpx  # local import: only the standalone path needs an HTTP client

    client = httpx.Client(base_url=backend.rstrip("/"), timeout=10.0)
    last_version: str | None = None
    cumulative = 0
    print(f"[node] {node_id} -> {backend} (poll {interval}s)")
    try:
        while True:
            try:
                client.post(
                    "/heartbeat",
                    json={
                        "node_id": node_id,
                        "timestamp": time.time(),
                        "stats": {"blocked": cumulative, "fw_version": last_version or "v1"},
                    },
                )
                fw = client.get(f"/firmware/{node_id}").json()
                version = str(fw.get("fw_version") or "v1")
                code = str(fw.get("filter_c_code") or "")
                if code and version != last_version:
                    frames = list(fw.get("sample_frames") or [])
                    # The node treats its whole captured stream as input; the
                    # backend already proved correctness on held-out captures.
                    result = run_enforcement(code, frames, benign_frames=[])
                    cumulative += result.blocked
                    client.post(
                        "/enforcement",
                        json={
                            "node_id": node_id,
                            "fw_version": version,
                            "blocked": result.blocked,
                            "passed": result.passed,
                        },
                    )
                    last_version = version
                    print(
                        f"[node] loaded {version}: "
                        f"blocked {result.blocked}/{result.blocked + result.passed} frames"
                    )
            except Exception as exc:  # a flaky link must never kill the node
                print(f"[node] transient error: {exc}")
            if once:
                break
            time.sleep(interval)
    finally:
        client.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Software enforcement node (real OTA pull).")
    ap.add_argument("--backend", default="http://localhost:8000")
    ap.add_argument("--node", default="esp-sw-01")
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--once", action="store_true", help="one poll cycle then exit")
    args = ap.parse_args()
    run_node(args.backend, args.node, interval=args.interval, once=args.once)


if __name__ == "__main__":
    main()
