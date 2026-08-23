"""Independent oracle: compile the agent's C filter and replay-test it.

Authoritative verification. The backend owns this and runs it on held-out
fixtures the agent never sees, so a filter cannot be gamed by self-reporting.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import OracleOut

ORACLE_DIR = Path(__file__).resolve().parent.parent / "oracle"
HARNESS = ORACLE_DIR / "harness.c"
FIXTURES = ORACLE_DIR / "fixtures"

COMPILE_TIMEOUT_S = 20
RUN_TIMEOUT_S = 10

# Real ESP keyboard demo stages: t=deauth, y=authentication, u=association.
# Until a stage is observed, its representative frame is a must-pass probe so
# an earlier patch cannot hide the next attack from the edge/backend pipeline.
STAGED_MGMT_PROBES = (
    "c0003a01ffffffffffff00112233445500112233445500700700",
    "b0003a01ffffffffffff00112233445500112233445500700700",
    "00003a01ffffffffffff00112233445500112233445500700700",
)

_RESULT_RE = re.compile(
    r"TPR=(?P<tpr>[\d.]+)\s+FPR=(?P<fpr>[\d.]+)\s+"
    r"PASSED=(?P<passed>\d+)\s+TOTAL=(?P<total>\d+)"
)


def _fail(log: str) -> OracleOut:
    return OracleOut(passed=False, tpr=0.0, fpr=1.0, tests_total=0, tests_passed=0, log=log)


def _management_subtype(frame_hex: str) -> int | None:
    body = frame_hex.split("#", 1)[0]
    cleaned = "".join(char for char in body if char not in " \t\r\n_:-")
    if len(cleaned) < 2:
        return None
    try:
        frame_control = int(cleaned[:2], 16)
    except ValueError:
        return None
    if ((frame_control >> 2) & 0x3) != 0:
        return None
    return (frame_control >> 4) & 0xF


def unseen_staged_mgmt_frames(observed_frames: list[str]) -> list[str]:
    """Return real demo stages that a cumulative filter must still pass."""
    observed = {
        subtype for frame in observed_frames if (subtype := _management_subtype(frame)) is not None
    }
    return [frame for frame in STAGED_MGMT_PROBES if _management_subtype(frame) not in observed]


def run_oracle(
    filter_c_code: str,
    attack: Path | None = None,
    benign: Path | None = None,
    *,
    attack_frames: list[str] | None = None,
    must_pass_frames: list[str] | None = None,
) -> OracleOut:
    """Compile `filter_c_code`, replay both captures, return the verdict.

    Compile failure -> passed=False with the compiler stderr in `log`, so the
    orchestrator can feed it straight back to the agent for another attempt.
    """
    attack = attack or (FIXTURES / "attack.hex")
    benign = benign or (FIXTURES / "benign.hex")

    with tempfile.TemporaryDirectory(prefix="oracle-") as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "filter.c").write_text(filter_c_code)
        shutil.copy(HARNESS, tmpdir / "harness.c")
        binary = tmpdir / "test"
        if attack_frames:
            staged_attack = tmpdir / "attack.hex"
            staged_attack.write_text(
                attack.read_text()
                + "\n# Current independently observed incident\n"
                + "\n".join(attack_frames)
                + "\n"
            )
            attack = staged_attack
        if must_pass_frames:
            staged_benign = tmpdir / "benign.hex"
            staged_benign.write_text(
                benign.read_text()
                + "\n# Unseen staged subtypes must remain observable\n"
                + "\n".join(must_pass_frames)
                + "\n"
            )
            benign = staged_benign

        try:
            compile_proc = subprocess.run(
                ["clang", "-Wall", "-std=c11", str(tmpdir / "harness.c"), "-o", str(binary)],
                capture_output=True,
                text=True,
                timeout=COMPILE_TIMEOUT_S,
                cwd=tmpdir,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return _fail(f"compile error: {exc}")

        if compile_proc.returncode != 0:
            return _fail(f"compile failed:\n{compile_proc.stderr.strip()}")

        try:
            run_proc = subprocess.run(
                [str(binary), str(attack), str(benign)],
                capture_output=True,
                text=True,
                timeout=RUN_TIMEOUT_S,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired:
            return _fail("filter timed out during replay (possible infinite loop)")

        stdout = run_proc.stdout.strip()
        if must_pass_frames:
            subtypes = sorted(
                {
                    subtype
                    for frame in must_pass_frames
                    if (subtype := _management_subtype(frame)) is not None
                }
            )
            stdout += f"\nMUST_PASS_UNSEEN_SUBTYPES={','.join(map(str, subtypes))}"
        match = _RESULT_RE.search(stdout)
        if not match:
            return _fail(f"unparseable oracle output:\n{stdout}\n{run_proc.stderr.strip()}")

        total = int(match["total"])
        passed_count = int(match["passed"])
        return OracleOut(
            passed="RESULT=PASS" in stdout,
            tpr=float(match["tpr"]),
            fpr=float(match["fpr"]),
            tests_total=total,
            tests_passed=passed_count,
            log=stdout,
        )
