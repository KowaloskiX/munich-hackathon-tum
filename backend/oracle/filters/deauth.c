/*
 * Sample filter — the shape the agent (Devin) is expected to emit.
 *
 * Blocks 802.11 management deauthentication / disassociation frames, the
 * payload of a deauth/disassoc flood. The first byte of an 802.11 frame is
 * the Frame Control field: bits [7:4] = subtype, bits [3:2] = type.
 *
 *   type 00 = management
 *   subtype 1100 (0xC) = deauthentication  -> FC = 0xC0
 *   subtype 1010 (0xA) = disassociation    -> FC = 0xA0
 *
 * Data (0x08) and beacon (0x80) frames pass untouched.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool block_frame(const uint8_t *f, size_t n) {
    if (n < 1) return false;
    uint8_t fc = f[0];
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    if (type != 0x0) return false;                 /* only management frames */
    return subtype == 0xC || subtype == 0xA;       /* deauth or disassoc     */
}
