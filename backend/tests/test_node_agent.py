"""Enforcement is real: the deployed filter is compiled and run on frames."""

from pathlib import Path

import pytest

from app.node_agent import EnforcementError, parse_hex, run_enforcement
from app.prompts import SAMPLE_ATTACK, SAMPLE_BENIGN

# The reference filter Devin's stub converges to (deauth/disassoc only).
DEAUTH_C = (Path(__file__).resolve().parent.parent / "oracle/filters/deauth.c").read_text()


def test_parse_hex_strips_comments_and_separators():
    assert parse_hex("# just a comment") is None
    assert parse_hex("   ") is None
    assert parse_hex("c0_00 3a:01") == bytes([0xC0, 0x00, 0x3A, 0x01])
    assert parse_hex("nothex") is None


def test_enforcement_blocks_attack_and_passes_benign():
    result = run_enforcement(DEAUTH_C, SAMPLE_ATTACK, SAMPLE_BENIGN)
    # Every attack frame (deauth + disassoc) is actually dropped by the filter.
    assert result.attack_total == len(SAMPLE_ATTACK)
    assert result.blocked == len(SAMPLE_ATTACK)
    # No benign frame is wrongly dropped, so they all pass through.
    assert result.false_positives == 0
    assert result.benign_total == len(SAMPLE_BENIGN)
    assert result.passed == len(SAMPLE_BENIGN)


def test_enforcement_default_benign_baseline():
    # benign_frames omitted -> uses the shared sample baseline internally.
    result = run_enforcement(DEAUTH_C, SAMPLE_ATTACK)
    assert result.benign_total == len(SAMPLE_BENIGN)
    assert result.false_positives == 0


def test_bad_c_raises_enforcement_error():
    with pytest.raises(EnforcementError):
        run_enforcement("this is not valid C", ["c0003a01"])
