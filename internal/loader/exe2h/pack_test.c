/* Focused packer regression fixture. Run by extractor_test.go with Zig cc. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pack.h"

static void check(int condition, const char *message) {
    if(!condition) {
        fprintf(stderr, "pack fixture: %s\n", message);
        exit(1);
    }
}

int main(void) {
    uint8_t image[80] = {0};
    pack_sec_t sections[3] = {0};
    pack_ref_t *refs = NULL;
    uint32_t blob_size = 0;
    int n_refs = 0;

    /* .text RVA 0x1000: LEA rax,[RIP+.rdata], CALL .hot, RET. */
    const uint8_t text[] = {
        0x48, 0x8d, 0x05, 0xf9, 0x4f, 0x00, 0x00,
        0xe8, 0xf4, 0x1f, 0x00, 0x00, 0xc3,
    };
    memcpy(image, text, sizeof(text));
    image[32] = 0xc3; /* .hot RVA 0x3000: RET */
    image[64] = 0x11;
    image[65] = 0x22;
    image[66] = 0x33;
    image[67] = 0x44;

    strcpy(sections[0].name, ".text");
    sections[0].vaddr = 0x1000;
    sections[0].vsize = sizeof(text);
    sections[0].copy_size = sizeof(text);
    strcpy(sections[1].name, ".hot");
    sections[1].vaddr = 0x3000;
    sections[1].vsize = 1;
    sections[1].file_off = 32;
    sections[1].copy_size = 1;
    sections[1].single_page = 1;
    strcpy(sections[2].name, ".rdata");
    sections[2].vaddr = 0x6000;
    sections[2].vsize = 4;
    sections[2].file_off = 64;
    sections[2].copy_size = 4;

    uint8_t *blob = pack_extract(image, sections, 2, 3,
                                 &blob_size, &refs, &n_refs);
    check(blob != NULL, "valid code and read-only data did not pack");
    check(blob_size == 0x1004 && sections[2].new_offset == 0x1000,
          "read-only data was not page-aligned after code");
    check(memcmp(blob + 0x1000, image + 64, 4) == 0,
          "read-only data contents were lost");

    int32_t data_disp, code_disp;
    memcpy(&data_disp, blob + 3, 4);
    memcpy(&code_disp, blob + 8, 4);
    check(data_disp == 0x1000 - 7, "RIP-relative data target was not rewritten");
    check(code_disp == 1, "CALL target was not rewritten");
    check(n_refs == 1 && refs != NULL && refs[0].src_sec == 0 &&
          refs[0].src_offset == 7 && refs[0].target_sec == 1,
          "read-only data incorrectly entered the dispatch reference table");
    free(refs);
    free(blob);

    /* A present but unreferenced .rdata section must not inflate the shim
       past a page boundary merely because the PE carries unwind data. */
    const uint8_t local_disp[4] = {0x05, 0x00, 0x00, 0x00};
    memcpy(image + 3, local_disp, sizeof(local_disp));
    blob = pack_extract(image, sections, 2, 3, &blob_size, &refs, &n_refs);
    check(blob != NULL && blob_size == sizeof(text) + 1 && n_refs == 1,
          "unreferenced read-only data was copied into the blob");
    free(refs);
    free(blob);
    memcpy(image + 3, text + 3, 4);

    /* Omitting .rdata must fail instead of leaving the PE RVA in the blob. */
    blob = pack_extract(image, sections, 2, 2, &blob_size, &refs, &n_refs);
    check(blob == NULL, "unpacked read-only data target was accepted");

    /* A protected section cannot be entered with JMP semantics. */
    image[7] = 0xe9;
    blob = pack_extract(image, sections, 2, 3, &blob_size, &refs, &n_refs);
    check(blob == NULL, "cross-section JMP into protected code was accepted");

    return 0;
}
