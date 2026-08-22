"""Devin prompt construction for the anomaly-defense agent.

The agent is handed raw captured frames and must return a C predicate that
blocks the attack and nothing legitimate. We give it a SMALL sample of labeled
frames to reason and self-test against — never the held-out fixtures the oracle
scores it on (kept in backend/oracle/fixtures/).
"""

from __future__ import annotations

from .models import AgentIn

# Small, illustrative labeled sample for Devin to self-test against.
# Deliberately NOT the held-out set the oracle uses.
SAMPLE_ATTACK = [
    "c0003a01ffffffffffff00112233445500112233445500700700",  # deauth
    "a0003a01ffffffffffff00112233445500112233445500900800",  # disassoc
]
SAMPLE_BENIGN = [
    "8000000000ffffffffffffaabbccddeeffaabbccddeeffc0006400",  # beacon
    "08422c00112233445566aabbccddeeff1122334455660010dead",  # data
]

STRUCTURED_OUTPUT_SPEC = (
    "Return a JSON object with exactly these keys: "
    '"attack_class" (string, e.g. "deauth_flood"), '
    '"confidence" (number 0..1), '
    '"filter_c_code" (string: the full contents of filter.c), '
    '"explanation" (string: one short paragraph on the attack and the filter).'
)

# JSON Schema passed to Devin v3 (structured_output_schema) to enforce the shape.
STRUCTURED_OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "attack_class": {"type": "string"},
        "confidence": {"type": "number"},
        "filter_c_code": {"type": "string"},
        "explanation": {"type": "string"},
    },
    "required": ["attack_class", "filter_c_code"],
}

_SIGNATURE = "bool block_frame(const uint8_t *f, size_t n)"


def build_devin_prompt(payload: AgentIn) -> str:
    """Build the task prompt for a Devin session from an anomaly."""
    frames = "\n".join(payload.frame_hex) or "(none provided)"
    stats = payload.anomaly_stats
    sample_attack = "\n".join(SAMPLE_ATTACK)
    sample_benign = "\n".join(SAMPLE_BENIGN)

    base = f"""\
You are a defensive network-security engineer for industrial (OT/ICS) equipment.
A passive sniffer flagged an anomaly and captured raw 802.11 frames (hex, one per
line). Identify the attack and write a C filter that blocks it.

## Captured anomaly
frame_type={stats.frame_type} subtype={stats.subtype} \
count_in_window={stats.count_in_window} window_ms={stats.window_ms}

Raw frames (hex):
{frames}

## Your task
Write a single C source file `filter.c` that defines exactly this function:

    #include <stdbool.h>
    #include <stddef.h>
    #include <stdint.h>
    {_SIGNATURE};

`block_frame` returns true for a frame that is part of the attack and must be
dropped, and false for legitimate traffic that must pass. The first byte of an
802.11 frame is the Frame Control field (bits [3:2]=type, bits [7:4]=subtype).

## How it will be tested (self-test before finishing)
Your filter is compiled with `clang -Wall` and replayed over two capture files:
every attack frame MUST return true, every benign frame MUST return false. It
passes only at 100% detection with zero false positives.

Sample attack frames (must be blocked):
{sample_attack}

Sample benign frames (must pass):
{sample_benign}

## Hard rules
- Edit only `filter.c`; keep the exact signature above.
- Must compile clean with `clang -Wall` (no warnings, C11).
- Match on frame structure (type/subtype), not on exact byte-for-byte frames.
- Self-verify against the samples before you finish.

## Output
{STRUCTURED_OUTPUT_SPEC}
"""

    if payload.failure_log:
        base += f"""

## Previous attempt FAILED independent verification
Your last filter did not pass the held-out replay test. Fix it.

Previous filter.c:
{payload.prev_filter or "(unavailable)"}

Failure log:
{payload.failure_log}
"""
    return base
