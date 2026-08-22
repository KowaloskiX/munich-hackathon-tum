"""The edge filter really compiles to native code and really drops frames."""

import pytest

from app.edge.filter_runtime import CompileError, FilterRuntime, parse_hex

# Reference deauth/disassoc filter (the shape the backend agent converges to).
DEAUTH_C = """\
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool block_frame(const uint8_t *f, size_t n) {
    if (n < 1) return false;
    uint8_t type = (f[0] >> 2) & 0x3;
    uint8_t subtype = (f[0] >> 4) & 0xF;
    if (type != 0x0) return false;
    return subtype == 0xC || subtype == 0xA;
}
"""

ATTACK = [
    "c0003a01ffffffffffff00112233445500112233445500700700",  # deauth
    "a0003a01ffffffffffff00112233445500112233445500900800",  # disassoc
]
BENIGN = [
    "8000000000ffffffffffffaabbccddeeffaabbccddeeffc0006400",  # beacon
    "08422c00112233445566aabbccddeeff1122334455660010dead",  # data
]


def test_parse_hex():
    assert parse_hex("# comment") is None
    assert parse_hex("  ") is None
    assert parse_hex("c0_00 3a:01") == bytes([0xC0, 0x00, 0x3A, 0x01])
    assert parse_hex("zz") is None


def test_partition_drops_attack_keeps_benign_and_records_native_proof():
    rt = FilterRuntime()
    rt.reload(DEAUTH_C, "v2", "deauth_flood")
    kept, dropped = rt.partition(ATTACK + BENIGN)
    assert dropped == ATTACK  # every attack frame actually dropped
    assert kept == BENIGN  # benign frames pass untouched
    assert rt.evaluated == 4  # ran the native filter on every frame
    # Proof it built + loaded a real native shared object.
    assert rt.so_path and rt.so_path.endswith("filter.so")
    assert rt.so_bytes > 0 and len(rt.so_sha) == 12


def test_bad_c_raises_and_keeps_previous_filter():
    rt = FilterRuntime()
    rt.reload(DEAUTH_C, "v2")
    with pytest.raises(CompileError):
        rt.reload("this is not valid C", "v3")
    assert rt.version == "v2"  # never degrades to "pass all"
    _, dropped = rt.partition(ATTACK)
    assert dropped == ATTACK


def test_unloaded_runtime_passes_everything():
    rt = FilterRuntime()
    assert rt.loaded is False
    assert rt.blocks(ATTACK[0]) is False
