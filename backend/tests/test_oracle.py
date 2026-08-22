"""The independent oracle passes a correct filter and fails broken ones."""

from pathlib import Path

from app.oracle import run_oracle

GOOD = (Path(__file__).resolve().parent.parent / "oracle/filters/deauth.c").read_text()

OVERBROAD = """\
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
bool block_frame(const uint8_t *f, size_t n) {
    if (n < 1) return false;
    return ((f[0] >> 2) & 0x3) == 0x0;  /* blocks all mgmt incl. beacons */
}
"""

WONT_COMPILE = "this is not C code {{{"


def test_good_filter_passes():
    out = run_oracle(GOOD)
    assert out.passed is True
    assert out.tpr == 1.0
    assert out.fpr == 0.0
    assert out.tests_passed == out.tests_total > 0


def test_overbroad_filter_fails_on_false_positives():
    out = run_oracle(OVERBROAD)
    assert out.passed is False
    assert out.fpr > 0.0  # beacons/probes wrongly blocked


def test_compile_error_is_a_failure_not_a_crash():
    out = run_oracle(WONT_COMPILE)
    assert out.passed is False
    assert "compile failed" in out.log
