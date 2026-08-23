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

_RESULT_RE = re.compile(
    r"TPR=(?P<tpr>[\d.]+)\s+FPR=(?P<fpr>[\d.]+)\s+"
    r"PASSED=(?P<passed>\d+)\s+TOTAL=(?P<total>\d+)"
)


def _fail(log: str) -> OracleOut:
    return OracleOut(passed=False, tpr=0.0, fpr=1.0, tests_total=0, tests_passed=0, log=log)


def run_oracle(
    filter_c_code: str,
    attack: Path | None = None,
    benign: Path | None = None,
    *,
    attack_frames: list[str] | None = None,
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
