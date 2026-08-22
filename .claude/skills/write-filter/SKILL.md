---
name: write-filter
description: Write or debug a C packet filter that the oracle must accept — the artifact the agent generates. Use when authoring a filter, changing backend/oracle/harness.c, adding fixtures, or diagnosing why the oracle returned FAIL.
---

# Write a filter the oracle accepts

The filter is the whole product: the agent emits C, the oracle replay-tests it,
and it deploys OTA with no human in the loop. The contract below is what
`backend/oracle/harness.c` actually enforces — get it wrong and the oracle
reports a compile failure, which the orchestrator treats as a failed attempt.

## The one required symbol

```c
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool block_frame(const uint8_t *f, size_t n) { ... }   /* true = drop the frame */
```

Reference implementation: `backend/oracle/filters/deauth.c`.

- The harness does `#include "filter.c"`, so the file must be **self-contained**
  and must define **no `main`**. Include what you use; nothing is included for you.
- Compiled with `clang -Wall -Werror -std=c11`. **A warning is a build failure** —
  unused parameter, implicit conversion, missing include, all fatal.
- `n` can be as small as 1. Guard every index: `if (n < 1) return false;`.
- No allocation, no I/O, no globals with state. This runs per frame on an ESP32.

## What "pass" means

The harness replays two labeled captures — `fixtures/attack.hex` (every frame
*should* be blocked) and `fixtures/benign.hex` (every frame *must* pass) — and
prints two machine-parseable lines that `backend/app/oracle.py` regex-parses:

```
TPR=1.000 FPR=0.000 PASSED=8 TOTAL=8
RESULT=PASS
```

Pass requires **`fn == 0` and `fp == 0`** (`harness.c:102`): catch every attack
frame *and* block nothing legitimate. There is no partial credit and no
threshold to relax (AGENTS.md rule 3).

## The failure mode that always happens first

Over-blocking. "High volume of management frames → block all management frames"
catches the deauth flood *and* kills every beacon and probe response, so
`FPR > 0` and the oracle fails. Narrow to the subtype:
`fc >> 4 == 0xC` (deauth) or `0xA` (disassoc), with `(fc >> 2) & 0x3 == 0`
selecting management. `agent_stub.py` deliberately makes this mistake on the
first attempt so the retry path is exercised in every demo run.

## Fixture format

One frame per line, hex. `_`, `:` and `-` are stripped for readability, `#`
starts a comment, blank lines are skipped, junk characters skip the line
silently — a typo'd fixture line disappears instead of erroring.

## The fixtures are the answer key

`backend/oracle/fixtures/` is held out: the agent sees the anomaly's `frame_hex`
and never the fixtures. Nothing on the agent side may read that directory —
`backend/tests/test_layering.py` fails the build if it tries. Add fixtures by
hand; never generate them from a filter you are trying to pass.

## Check it

```bash
make oracle-build                                   # harness + the sample filter
cd backend && uv run pytest tests/test_oracle.py    # good / over-broad / non-compiling
```
