"""Fake 'Devin' agent — canned filters behind the real AgentIn->AgentOut contract.

Swapped for a real Devin/LLM call at integration (see ARCHITECTURE.md §5 step 2).
The orchestrator does not care which one it talks to.

To exercise the real fail->retry->pass loop, the first attempt over-blocks
(catches every management frame, so beacons get dropped -> FPR>0 -> oracle FAIL).
The retry narrows to the observed subtype and preserves protections learned in
the staged deauth -> authentication -> association demo.
"""

from __future__ import annotations

from collections.abc import Callable

from .models import AgentIn, AgentOut

StepFn = Callable[[str], None]

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

_ATTACK_BY_SUBTYPE = {
    0: "association_flood",
    11: "auth_flood",
    12: "deauth_flood",
}


def _adapted_filter(subtype: int | None) -> str:
    """Return the cumulative demo filter for the staged t -> y -> u sequence."""
    blocked = ["subtype == 0xC", "subtype == 0xA"]
    if subtype in {0, 11}:
        blocked.append("subtype == 0xB")
    if subtype == 0:
        blocked.append("subtype == 0x0")
    predicate = " || ".join(blocked)
    return f"""\
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool block_frame(const uint8_t *f, size_t n) {{
    if (n < 1) return false;
    uint8_t type = (f[0] >> 2) & 0x3;
    uint8_t subtype = (f[0] >> 4) & 0xF;
    if (type != 0x0) return false;
    return {predicate};
}}
"""


def call_agent(payload: AgentIn, on_step: StepFn | None = None) -> AgentOut:
    def step(msg: str) -> None:
        if on_step is not None:
            on_step(msg)

    retrying = bool(payload.failure_log or payload.prev_filter)
    subtype = payload.anomaly_stats.subtype
    attack_class = _ATTACK_BY_SUBTYPE.get(subtype, "deauth_flood")
    if retrying:
        step("re-reading failure log; narrowing the filter")
        step("recompiled filter.c, re-ran harness: TPR=1.000 FPR=0.000")
        return AgentOut(
            attack_class=attack_class,
            confidence=0.94,
            filter_c_code=_adapted_filter(subtype),
            explanation=(
                "Narrowed to the observed management subtype while preserving "
                "previous demo protections; beacons and data frames still pass."
            ),
            iterations=2,
            compiled=True,
            self_tpr=1.0,
            self_fpr=0.0,
        )
    step("wrote filter.c, compiled with gcc -Wall")
    step("ran harness: over-blocks beacons (FPR>0) — needs a fix")
    return AgentOut(
        attack_class=attack_class,
        confidence=0.71,
        filter_c_code=_OVERBROAD_FILTER,
        explanation="Initial guess: high volume of management frames — block all mgmt.",
        iterations=1,
        compiled=True,
        self_tpr=1.0,
        self_fpr=0.5,
    )
