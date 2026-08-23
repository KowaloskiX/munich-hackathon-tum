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
    '"explanation" (string: one short paragraph on the attack and the filter), '
    '"iterations" (integer: how many compile+test cycles you ran in your VM), '
    '"compiled" (boolean: did the final filter.c compile cleanly), '
    '"self_tpr" (number: your harness detection rate on the samples, 0..1), '
    '"self_fpr" (number: your harness false-positive rate on the samples, 0..1).'
)

# JSON Schema passed to Devin v3 (structured_output_schema) to enforce the shape.
STRUCTURED_OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "attack_class": {"type": "string"},
        "confidence": {"type": "number"},
        "filter_c_code": {"type": "string"},
        "explanation": {"type": "string"},
        "iterations": {"type": "integer"},
        "compiled": {"type": "boolean"},
        "self_tpr": {"type": "number"},
        "self_fpr": {"type": "number"},
    },
    "required": ["attack_class", "filter_c_code"],
}

_SIGNATURE = "bool block_frame(const uint8_t *f, size_t n)"

# Compact test harness Devin recreates and runs in its VM. Reads two hex-frame
# files (one frame per line) and prints the detection / false-positive rates.
HARNESS_C = r"""#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "filter.c"

static int parse_hex(const char *line, uint8_t *out, int cap) {
    int n = 0, hi = -1;
    for (const char *p = line; *p; ++p) {
        char c = *p;
        int v;
        if (c == '#') break;
        if (isspace((unsigned char)c) || c == '_' || c == ':' || c == '-') continue;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (hi < 0) hi = v;
        else { if (n < cap) out[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    return n ? n : -1;
}

static void score(const char *path, bool expect, int *ok, int *tot) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return; }
    char line[8192];
    uint8_t fr[4096];
    while (fgets(line, sizeof line, f)) {
        int len = parse_hex(line, fr, sizeof fr);
        if (len < 0) continue;
        (*tot)++;
        if (block_frame(fr, (size_t)len) == expect) (*ok)++;
    }
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s attack benign\n", argv[0]); return 2; }
    int tp = 0, at = 0, tn = 0, bt = 0;
    score(argv[1], true, &tp, &at);
    score(argv[2], false, &tn, &bt);
    double tpr = at ? (double)tp / at : 0;
    double fpr = bt ? (double)(bt - tn) / bt : 0;
    printf("TPR=%.3f FPR=%.3f\n", tpr, fpr);
    return (tp == at && tn == bt && at > 0) ? 0 : 1;
}
"""


def build_devin_prompt(payload: AgentIn) -> str:
    """Build the task prompt for a Devin session from an anomaly."""
    frames = "\n".join(payload.frame_hex) or "(none provided)"
    stats = payload.anomaly_stats
    current_attack = "\n".join(payload.frame_hex) or "# no captured frame provided"
    regression_attacks = "\n".join(SAMPLE_ATTACK)
    sample_benign = "\n".join(SAMPLE_BENIGN)
    harness = HARNESS_C

    base = f"""\
You are a defensive network-security engineer for industrial (OT/ICS) equipment.
A passive sniffer flagged an anomaly and captured raw 802.11 frames (hex, one per
line). Identify the attack and write a C filter that blocks it.

## Captured anomaly
frame_type={stats.frame_type} subtype={stats.subtype} \
count_in_window={stats.count_in_window} window_ms={stats.window_ms}

Raw frames (hex):
{frames}

## Your task — actually build and test this in your VM
Do the real engineering loop in your sandbox, do not just write code:

1. Create `filter.c` defining exactly this function:

       #include <stdbool.h>
       #include <stddef.h>
       #include <stdint.h>
       {_SIGNATURE};

   It returns true for an attack frame (drop it) and false for legitimate
   traffic (pass). The first byte of an 802.11 frame is the Frame Control field
   (bits [3:2]=type, bits [7:4]=subtype).

2. Create `attack.hex` and `benign.hex`, one hex frame per line:

   attack.hex:
   # Current captured anomaly — classify from this section only
   {current_attack}
   # Regression attacks — preserve protection; not evidence of the current attack
   {regression_attacks}

   benign.hex:
   {sample_benign}

3. Create `harness.c` with EXACTLY this content (it #includes your filter.c):

   ```c
   {harness}
   ```

4. Compile and run in your VM, and ITERATE until it passes:

       gcc -Wall -std=c11 harness.c -o test    # apt-get install gcc if missing
       ./test attack.hex benign.hex            # prints TPR=.. FPR=..

   Every attack frame must be blocked (TPR=1.000) and no benign frame may be
   blocked (FPR=0.000). If not, fix `filter.c` and recompile/rerun. Count how
   many compile+run cycles you needed.

## Hard rules
- Edit only `filter.c`; keep the exact signature. Do not edit harness.c.
- Must compile clean with `gcc -Wall` (no warnings, C11).
- Match on frame structure (type/subtype), not exact byte-for-byte frames.
- Use only the current captured anomaly to classify the attack. The regression
  samples exist only to prevent earlier protections from regressing.
- Block the current captured subtype and subtypes already blocked by the existing
  deployed filter. Do not proactively block any other management subtype.
- Keep unseen management subtypes observable as legitimate must-pass traffic;
  one can become a future attack stage and must still reach anomaly detection.
- You MUST have actually run ./test and seen TPR=1.000 FPR=0.000 before finishing.

## Output
{STRUCTURED_OUTPUT_SPEC}
Report `iterations` as the real number of compile+run cycles you performed, and
`self_tpr`/`self_fpr` as the final numbers your harness printed.
"""

    if payload.prev_filter and not payload.failure_log:
        base += f"""

## Existing deployed protection
Extend the currently deployed filter below. Preserve every attack subtype it
already blocks while adding protection for the new captured anomaly. Independent
verification will replay both earlier and current attack frames.

Existing filter.c:
{payload.prev_filter}
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
