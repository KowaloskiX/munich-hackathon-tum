"""Fake 'Devin' agent — canned filters behind the real AgentIn->AgentOut contract.

Swapped for a real Devin/LLM call at integration (see ARCHITECTURE.md §5 step 2).
The orchestrator does not care which one it talks to.

To exercise the real fail->retry->pass loop, the first attempt over-blocks
(catches every management frame, so beacons get dropped -> FPR>0 -> oracle FAIL)
and the retry, once handed the failure log, narrows to deauth/disassoc only.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .models import AgentIn, AgentOut

StepFn = Callable[[str], None]

_GOOD_FILTER = (Path(__file__).resolve().parent.parent / "oracle/filters/deauth.c").read_text()

_OVERBROAD_FILTER = """\
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* First guess: block ALL management frames. Too aggressive — drops beacons. */
bool block_frame(const uint8_t *f, size_t n) {
    if (n < 1) return false;
    uint8_t type = (f[0] >> 2) & 0x3;
    return type == 0x0;
}
"""


def call_agent(payload: AgentIn, on_step: StepFn | None = None) -> AgentOut:
    def step(msg: str) -> None:
        if on_step is not None:
            on_step(msg)

    retrying = bool(payload.failure_log or payload.prev_filter)
    if retrying:
        step("re-reading failure log; narrowing the filter")
        step("recompiled filter.c, re-ran harness: TPR=1.000 FPR=0.000")
        return AgentOut(
            attack_class="deauth_flood",
            confidence=0.94,
            filter_c_code=_GOOD_FILTER,
            explanation=(
                "Narrowed to 802.11 mgmt subtypes 0xC (deauth) and 0xA (disassoc); "
                "beacons and data frames now pass."
            ),
            iterations=2,
            compiled=True,
            self_tpr=1.0,
            self_fpr=0.0,
        )
    step("wrote filter.c, compiled with gcc -Wall")
    step("ran harness: over-blocks beacons (FPR>0) — needs a fix")
    return AgentOut(
        attack_class="deauth_flood",
        confidence=0.71,
        filter_c_code=_OVERBROAD_FILTER,
        explanation="Initial guess: high volume of management frames — block all mgmt.",
        iterations=1,
        compiled=True,
        self_tpr=1.0,
        self_fpr=0.5,
    )
