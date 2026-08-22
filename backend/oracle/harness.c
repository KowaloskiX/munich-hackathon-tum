/*
 * Independent oracle harness.
 *
 * Replays two labeled capture files through the agent-written filter and
 * scores it. This is the authoritative verification — the backend runs it
 * on human-prepared, held-out fixtures the agent never sees.
 *
 *   argv[1] = attack capture  (every frame SHOULD be blocked -> expect true)
 *   argv[2] = benign capture   (every frame should PASS       -> expect false)
 *
 * Fixture format: one frame per line as hex (e.g. "c000...").
 * Blank lines and lines starting with '#' are ignored.
 *
 * The agent's filter is dropped next to this file as filter.c and must define:
 *   bool block_frame(const uint8_t *f, size_t n);
 *
 * Output (machine-parseable, last line is authoritative):
 *   TPR=1.000 FPR=0.000 PASSED=8 TOTAL=8
 *   RESULT=PASS
 */
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "filter.c"

#define MAX_LINE 8192
#define MAX_FRAME 4096

/* Parse one hex line into bytes. Returns frame length, or -1 to skip. */
static int parse_hex(const char *line, uint8_t *out, size_t cap) {
    size_t n = 0;
    int hi = -1;
    for (const char *p = line; *p; ++p) {
        char c = *p;
        if (c == '#') break;              /* inline comment */
        if (isspace((unsigned char)c)) continue;
        if (c == '_' || c == ':' || c == '-') continue;  /* readability seps */
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;                   /* junk -> skip line */
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= cap) return (int)n;
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (n == 0) return -1;                 /* blank/comment line */
    return (int)n;
}

/* Run the filter over a file. expect_block=true for attack, false for benign.
 * Increments *correct for each frame classified as expected, *total per frame. */
static int score_file(const char *path, bool expect_block, int *correct, int *total) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "oracle: cannot open %s\n", path);
        return -1;
    }
    char line[MAX_LINE];
    uint8_t frame[MAX_FRAME];
    while (fgets(line, sizeof line, fp)) {
        int len = parse_hex(line, frame, sizeof frame);
        if (len < 0) continue;
        bool blocked = block_frame(frame, (size_t)len);
        *total += 1;
        if (blocked == expect_block) *correct += 1;
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <attack.hex> <benign.hex>\n", argv[0]);
        return 2;
    }

    int tp = 0, attack_total = 0;   /* attack frames correctly blocked */
    int tn = 0, benign_total = 0;   /* benign frames correctly passed  */

    if (score_file(argv[1], true, &tp, &attack_total) < 0) return 2;
    if (score_file(argv[2], false, &tn, &benign_total) < 0) return 2;

    int fn = attack_total - tp;     /* attacks that slipped through */
    int fp = benign_total - tn;     /* legit frames wrongly blocked */

    double tpr = attack_total ? (double)tp / attack_total : 0.0;
    double fpr = benign_total ? (double)fp / benign_total : 0.0;

    int total = attack_total + benign_total;
    int passed = tp + tn;

    /* Pass = catches every attack AND blocks nothing legit. */
    bool ok = (fn == 0) && (fp == 0) && (attack_total > 0);

    printf("TPR=%.3f FPR=%.3f PASSED=%d TOTAL=%d\n", tpr, fpr, passed, total);
    printf("RESULT=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
