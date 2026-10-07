/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#include <shlwapi.h>
#include "mmap.h"
#pragma comment(lib, "shlwapi.lib")
#else
#define NIX
#include <libgen.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pe.h>
#endif

#include "pack.h"

// return pointer to DOS header
PIMAGE_DOS_HEADER DosHdr(void *map) {
    return (PIMAGE_DOS_HEADER)map;
}

// return pointer to NT header
PIMAGE_NT_HEADERS NtHdr (void *map) {
    return (PIMAGE_NT_HEADERS) ((uint8_t*)map + DosHdr(map)->e_lfanew);
}

// return pointer to File header
PIMAGE_FILE_HEADER FileHdr (void *map) {
    return &NtHdr(map)->FileHeader;
}

// determines CPU architecture of binary
int is32 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_I386;
}

// determines CPU architecture of binary
int is64 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_AMD64;
}

// return pointer to Optional header
void* OptHdr (void *map) {
    return (void*)&NtHdr(map)->OptionalHeader;
}

// return pointer to first section header
PIMAGE_SECTION_HEADER SecHdr (void *map) {
    PIMAGE_NT_HEADERS nt = NtHdr(map);

    return (PIMAGE_SECTION_HEADER)((uint8_t*)&nt->OptionalHeader +
    nt->FileHeader.SizeOfOptionalHeader);
}

uint32_t DirSize (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->NumberOfRvaAndSizes;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->NumberOfRvaAndSizes;
    }
}

uint32_t SecSize (void *map) {
    return NtHdr(map)->FileHeader.NumberOfSections;
}

PIMAGE_DATA_DIRECTORY Dirs (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->DataDirectory;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->DataDirectory;
    }
}

uint64_t ImgBase (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->ImageBase;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->ImageBase;
    }
}

// valid dos header?
int valid_dos_hdr (void *map) {
    PIMAGE_DOS_HEADER dos = DosHdr(map);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void *map) {
    return NtHdr(map)->Signature == IMAGE_NT_SIGNATURE;
}

uint32_t rva2ofs (void *map, uint32_t rva) {
    int i;

    PIMAGE_SECTION_HEADER sh = SecHdr(map);

    for (i=0; i<SecSize(map); i++) {
      if (rva >= sh[i].VirtualAddress && rva < sh[i].VirtualAddress + sh[i].SizeOfRawData)
      return sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
    }
    return -1;
}

void bin2h(void *map, char *fname, void *bin, uint32_t len) {
    char      label[32], file[32], *str;
    uint32_t  i;
    uint8_t   *p=(uint8_t*)bin;
    FILE      *fd;

    memset(label, 0, sizeof(label));
    memset(file,  0, sizeof(file));

#if defined(WINDOWS)
    str = PathFindFileName(fname);
#else
    str = basename(fname);
#endif
    for(i=0; str[i] != 0 && i < 24;i++) {
      if(str[i] == '.') {
        file[i] = label[i] = '_';
      } else {
        label[i] = toupper(str[i]);
        file[i]  = tolower(str[i]);
      }
    }
    if(map != NULL) {
      strcat(label, is32(map) ? "_X86" : "_X64");
      strcat(file,  is32(map) ? "_x86" : "_x64");
    }
    strcat(file, ".h");

    fd = fopen(file, "wb");

    if(fd != NULL) {
      fprintf(fd, "\nunsigned char %s[] = {", label);

      for(i=0;i<len;i++) {
        if(!(i % 12)) fprintf(fd, "\n  ");
        fprintf(fd, "0x%02x", p[i]);
        if((i+1) != len) {
          fprintf(fd, ((i+1) % 12) ? ", " : ",");
        }
      }
      fprintf(fd, "\n};\n");
      fclose(fd);
      printf("  [ saved code to %s\n", file);
    } else printf("  [ unable to create file : %s\n", file);
}

void bin2go(void* map, char* fname, void* bin, uint32_t len) {
	char      label[32], file[32], * str;
	uint32_t  i;
	uint8_t* p = (uint8_t*)bin;
	FILE* fd;

	memset(label, 0, sizeof(label));
	memset(file, 0, sizeof(file));

#if defined(WINDOWS)
	str = PathFindFileName(fname);
#else
	str = basename(fname);
#endif
	for (i = 0; str[i] != 0 && i < 24; i++) {
		if (str[i] == '.') {
			file[i] = label[i] = '_';
		}
		else {
			label[i] = toupper(str[i]);
			file[i] = tolower(str[i]);
		}
	}
	if (map != NULL) {
		strcat(label, is32(map) ? "_X86" : "_X64");
		strcat(file, is32(map) ? "_x86" : "_x64");
	}
	strcat(file, ".go");

	fd = fopen(file, "wb");

	if (fd != NULL) {
		fprintf(fd, "package fritter\n\n// %s - stub for EXE PE files\nvar %s = []byte{\n", label, label);

		for (i = 0; i < len; i++) {
			if (!(i % 12)) fprintf(fd, "\n  ");
			fprintf(fd, "0x%02x,", p[i]);
			if ((i + 1) != len && (i + 1) % 12) {
				fprintf(fd, " ");
			}
		}
		fprintf(fd, "\n};\n");
		fclose(fd);
		printf("  [ saved code to %s\n", file);
	}
	else printf("  [ unable to create file : %s\n", file);
}


/* Derive a base name from an input path like "loader_peb1.exe":
     out_lower gets "loader_peb1"  (lowercase, '.' -> '_' stripped)
     out_upper gets "LOADER_PEB1"  (uppercase equivalent)
   Bounded by 24 chars, matching bin2h's cap. */
static void exe2h_base_names(const char *fname, char *out_lower, char *out_upper) {
    const char *str;
    int i;
#if defined(WINDOWS)
    str = PathFindFileName((LPSTR)fname);
#else
    str = basename((char*)fname);
#endif
    for(i = 0; str[i] != 0 && i < 24; i++) {
        /* Strip at the extension dot so "loader_peb1.exe" -> "loader_peb1" */
        if(str[i] == '.') break;
        out_lower[i] = (char)tolower((unsigned char)str[i]);
        out_upper[i] = (char)toupper((unsigned char)str[i]);
    }
    out_lower[i] = 0;
    out_upper[i] = 0;
}

/* Emit companion header: fn_table describes each protected code section
   in blob-offset terms. Consumed by fritter's build_loader to populate
   the shim's fn_table_area and to XOR each protected slab with a random
   per-fn key. */
static void emit_fn_table_h(void *map, const char *fname,
                            const pack_sec_t *sections, int n_sec) {
    char base_lower[32], base_upper[32], out_file[64];
    FILE *fd;
    int i;

    exe2h_base_names(fname, base_lower, base_upper);
    snprintf(out_file, sizeof(out_file), "%s_fn_table_x64.h", base_lower);

    fd = fopen(out_file, "wb");
    if(fd == NULL) {
        printf("  [ unable to create file : %s\n", out_file);
        return;
    }

    fprintf(fd, "/* Auto-generated by exe2h. Do not edit. */\n");
    fprintf(fd, "#ifndef %s_FN_TABLE_X64_H\n", base_upper);
    fprintf(fd, "#define %s_FN_TABLE_X64_H\n\n", base_upper);
    fprintf(fd, "#include <stdint.h>\n\n");
    fprintf(fd, "#ifndef FRITTER_FN_META_T_DEFINED\n");
    fprintf(fd, "#define FRITTER_FN_META_T_DEFINED\n");
    fprintf(fd, "typedef struct {\n");
    fprintf(fd, "    uint32_t offset;     /* blob-relative start */\n");
    fprintf(fd, "    uint32_t size;       /* section VirtualSize */\n");
    fprintf(fd, "    uint8_t  single_page;/* section fits within one 4K page */\n");
    fprintf(fd, "    uint8_t  _pad[3];\n");
    fprintf(fd, "    char     name[16];   /* PE section name, NUL-padded */\n");
    fprintf(fd, "} fn_meta_t;\n");
    fprintf(fd, "#endif\n\n");
    fprintf(fd, "#define %s_FN_COUNT %d\n\n", base_upper, n_sec);
    fprintf(fd, "static const fn_meta_t %s_FNS[%s_FN_COUNT] = {\n",
            base_upper, base_upper);
    for(i = 0; i < n_sec; i++) {
        const pack_sec_t *s = &sections[i];
        fprintf(fd, "  { 0x%08x, 0x%08x, %u, {0,0,0}, \"%.8s\" },\n",
                s->new_offset, s->vsize, (unsigned)s->single_page, s->name);
    }
    fprintf(fd, "};\n\n");
    fprintf(fd, "#endif\n");
    fclose(fd);
    printf("  [ saved fn table to %s (%d sections)\n", out_file, n_sec);
    (void)map;
}

/* Emit companion header: ref_table describes each cross-section
   fixup already applied to the blob. Used by fritter to redirect
   those disp32 patches at generated thunks instead of the raw
   callee bytes (so a call from .text into .cipher becomes a call
   into a thunk that enters the dispatcher). Coordinates are in
   blob-absolute offsets so fritter doesn't need to know section
   geometry. */
static void emit_ref_table_h(void *map, const char *fname,
                             const pack_ref_t *refs, int n_refs,
                             const pack_sec_t *sections, int n_sec) {
    char base_lower[32], base_upper[32], out_file[64];
    FILE *fd;
    int i;

    exe2h_base_names(fname, base_lower, base_upper);
    snprintf(out_file, sizeof(out_file), "%s_ref_table_x64.h", base_lower);

    fd = fopen(out_file, "wb");
    if(fd == NULL) {
        printf("  [ unable to create file : %s\n", out_file);
        return;
    }

    fprintf(fd, "/* Auto-generated by exe2h. Do not edit. */\n");
    fprintf(fd, "#ifndef %s_REF_TABLE_X64_H\n", base_upper);
    fprintf(fd, "#define %s_REF_TABLE_X64_H\n\n", base_upper);
    fprintf(fd, "#include <stdint.h>\n\n");
    fprintf(fd, "#ifndef FRITTER_REF_T_DEFINED\n");
    fprintf(fd, "#define FRITTER_REF_T_DEFINED\n");
    fprintf(fd, "typedef struct {\n");
    fprintf(fd, "    uint32_t src_blob_off; /* start of source instruction */\n");
    fprintf(fd, "    uint16_t inst_length;  /* full instruction length */\n");
    fprintf(fd, "    uint16_t disp_offset;  /* offset of disp32 within inst */\n");
    fprintf(fd, "    uint16_t src_fn;       /* index into FNS[] (caller) */\n");
    fprintf(fd, "    uint16_t target_fn;    /* index into FNS[] (callee) */\n");
    fprintf(fd, "} ref_t;\n");
    fprintf(fd, "#endif\n\n");
    fprintf(fd, "#define %s_REF_COUNT %d\n\n", base_upper, n_refs);
    fprintf(fd, "static const ref_t %s_REFS[%s_REF_COUNT + 1] = {\n",
            base_upper, base_upper);
    for(i = 0; i < n_refs; i++) {
        const pack_ref_t *r = &refs[i];
        uint32_t blob_off = sections[r->src_sec].new_offset + r->src_offset;
        fprintf(fd, "  { 0x%08x, %u, %u, %u, %u },\n",
                blob_off, r->inst_length, r->disp_offset,
                r->src_sec, r->target_sec);
    }
    /* Trailing sentinel so the [+1] sizing keeps a valid element even
       when REF_COUNT is 0 (dispatch_shim.exe case). */
    fprintf(fd, "  { 0, 0, 0, 0, 0 }\n};\n\n");
    fprintf(fd, "#endif\n");
    fclose(fd);
    printf("  [ saved ref table to %s (%d refs)\n", out_file, n_refs);
    (void)map;
    (void)n_sec;
}

/**
void bin2array(void *map, char *fname, void *bin, uint32_t len) {
    char      label[32], file[32], *str;
    uint32_t  i;
    uint32_t  *p=(uint32_t*)bin;
    FILE      *fd;

    memset(label, 0, sizeof(label));
    memset(file,  0, sizeof(file));

#if defined(WINDOWS)
    str = PathFindFileName(fname);
#else
    str = basename(fname);
#endif
    for(i=0; str[i] != 0 && i < 24;i++) {
      if(str[i] == '.') {
        file[i] = label[i] = '_';
      } else {
        label[i] = toupper(str[i]);
        file[i]  = tolower(str[i]);
      }
    }

    strcat(file, ".h");

    fd = fopen(file, "wb");

    if(fd != NULL) {
      // align up by 4
      len = (len & -4) + 4;
      len >>= 2;

      // declare the array
      fprintf(fd, "\nunsigned int %s[%i];\n\n", label, len);

      // initialize array
      for(i=0; i<len; i++) {
        fprintf(fd, "%s[%i] = 0x%08" PRIX32 ";\n", label, i, p[i]);
      }
      fclose(fd);
      printf("  [ Saved array to %s\n", file);
    } else printf("  [ unable to create file : %s\n", file);
}
*/
/* Copy a PE section descriptor into the packer's bounded representation. */
static int pack_section_from_pe(pack_sec_t *out, const IMAGE_SECTION_HEADER *in,
                                size_t file_size, int single_page) {
    uint32_t copy_size = in->Misc.VirtualSize;
    if(copy_size > in->SizeOfRawData) copy_size = in->SizeOfRawData;
    if(in->Misc.VirtualSize == 0 || copy_size == 0 ||
       (uint64_t)in->VirtualAddress + in->Misc.VirtualSize > UINT32_MAX ||
       (uint64_t)in->PointerToRawData + copy_size > file_size ||
       (single_page && in->Misc.VirtualSize > PACK_PAGE)) {
        printf("  [ invalid or oversized PE section '%.8s'\n", in->Name);
        return 0;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->name, in->Name, sizeof(in->Name));
    out->vaddr = in->VirtualAddress;
    out->vsize = in->Misc.VirtualSize;
    out->file_off = in->PointerToRawData;
    out->copy_size = copy_size;
    out->single_page = single_page;
    return 1;
}

/* PE base relocations are needed only when a copied section contains an
   absolute image address. The shellcode has no PE loader to apply them.
   Relocations in omitted unwind/debug sections do not affect the blob. */
static int packed_base_relocs(const uint8_t *map, size_t file_size,
                              const pack_sec_t *sections, int n_sec) {
    const IMAGE_DATA_DIRECTORY *dir =
        &Dirs((void*)map)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(dir->Size == 0) return 0;
    uint32_t off = rva2ofs((void*)map, dir->VirtualAddress);
    if(off == UINT32_MAX || (uint64_t)off + dir->Size > file_size) return -1;
    uint32_t cursor = off;
    uint32_t end = off + dir->Size;
    while(cursor < end) {
        uint32_t page, block_size;
        if(end - cursor < 8) return -1;
        memcpy(&page, map + cursor, 4);
        memcpy(&block_size, map + cursor + 4, 4);
        if(block_size < 8 || block_size > end - cursor || (block_size & 1))
            return -1;
        for(uint32_t entry_off = cursor + 8;
            entry_off < cursor + block_size; entry_off += 2) {
            uint16_t entry;
            memcpy(&entry, map + entry_off, 2);
            if((entry >> 12) != 0) {
                uint64_t site = (uint64_t)page + (entry & 0x0fff);
                if(site > UINT32_MAX) return -1;
                if(pack_find_section(sections, n_sec, (uint32_t)site) >= 0)
                    return 1;
            }
        }
        cursor += block_size;
    }
    return 0;
}

// structure of COFF (.obj) file

//--------------------------//
// IMAGE_FILE_HEADER        //
//--------------------------//
// IMAGE_SECTION_HEADER     //
//  * num sections          //
//--------------------------//
//                          //
//                          //
//                          //
// section data             //
//  * num sections          //
//                          //
//                          //
//--------------------------//
// IMAGE_SYMBOL             //
//  * num symbols           //
//--------------------------//
// string table             //
//--------------------------//

int main (int argc, char *argv[]) {
    int                        i;
    FILE                       *fp;
    struct stat                fs;
    uint8_t                    *map;
    PIMAGE_SECTION_HEADER      sh;
    int                        failed = 0;

    if (argc != 2) {
      printf ("\n  [ usage: file2h <file.exe | file.bin>\n");
      return 2;
    }

    printf("  [ Opening file for reading: %s\n", argv[1]);

    // open file for reading
    fp = fopen(argv[1], "rb");

    if(fp == NULL) {
      printf("  [ Unable to open %s\n", argv[1]);
      return 1;
    } else {
      printf("  [ File opened.\n");
    }

    // get file info
    if(fstat(fileno(fp), &fs) != 0 || fs.st_size <= 0 ||
       (uint64_t)fs.st_size > UINT32_MAX) {
      printf("  [ invalid input file size\n");
      fclose(fp);
      return 1;
    }

    // if file has some data
    if(fs.st_size > 0) {
      printf("  [ Reading file: %s\n", argv[1]);
      // map into memory
      map = (uint8_t*)mmap(NULL, fs.st_size,
        PROT_READ, MAP_PRIVATE, fileno(fp), 0);
      if(map != MAP_FAILED) {
        int looks_pe = (uint64_t)fs.st_size >= sizeof(IMAGE_DOS_HEADER) &&
                       valid_dos_hdr(map);
        if(looks_pe && ((uint64_t)DosHdr(map)->e_lfanew +
                        sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > (uint64_t)fs.st_size ||
                        DosHdr(map)->e_lfanew < 0)) {
          printf("  [ truncated PE headers\n");
          failed = 1;
        } else if(looks_pe && valid_nt_hdr(map)) {
          printf("  [ Found valid DOS and NT header.\n");
          sh = SecHdr(map);
          if(!is64(map) ||
             FileHdr(map)->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
             (uint8_t*)OptHdr(map) +
                 (uint64_t)FileHdr(map)->SizeOfOptionalHeader > map + fs.st_size ||
             (uint8_t*)sh + (uint64_t)SecSize(map)*sizeof(*sh) >
                 map + fs.st_size || DirSize(map) > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
            printf("  [ invalid or unsupported PE section table\n");
            failed = 1;
          } else if((DirSize(map) > IMAGE_DIRECTORY_ENTRY_IMPORT &&
                     Dirs(map)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) ||
                    (DirSize(map) > IMAGE_DIRECTORY_ENTRY_IAT &&
                     Dirs(map)[IMAGE_DIRECTORY_ENTRY_IAT].Size != 0) ||
                    (DirSize(map) > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT &&
                     Dirs(map)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size != 0)) {
            printf("  [ PE contains external imports; standalone loader required\n");
            failed = 1;
          } else {
            pack_sec_t psecs[PACK_MAX_SECTIONS];
            int code_count = 0, section_count;
            int default_text_idx = -1;

            printf("  [ Scanning for code sections (IMAGE_SCN_CNT_CODE).\n");
            for(i=0; i<SecSize(map); i++) {
              if(sh[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                int is_text = strncmp((char*)sh[i].Name, ".text", 5) == 0;
                if(code_count == PACK_MAX_SECTIONS ||
                   !pack_section_from_pe(&psecs[code_count], &sh[i],
                                         (size_t)fs.st_size, !is_text)) {
                  failed = 1;
                  break;
                }
                /* Default ".text" stays at offset 0 (it contains the
                   PE entry, e.g. FritterLoader pinned at .text$a, which
                   must be at blob+0). Other sections may be reordered. */
                if(is_text && default_text_idx < 0) {
                  default_text_idx = code_count;
                }
                code_count++;
                printf("  [   section '%.8s' rva=0x%x size=0x%x\n",
                    sh[i].Name, sh[i].VirtualAddress, sh[i].Misc.VirtualSize);
              }
            }
            section_count = code_count;
            /* Zig/Clang can place constants in .rdata. It is copied into
               the blob but deliberately omitted from the function table:
               the dispatcher must leave data resident and unencrypted. */
            for(i=0; i<SecSize(map) && !failed; i++) {
              if(strncmp((char*)sh[i].Name, ".rdata", 6) == 0 &&
                 !(sh[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
                if((sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) ||
                   section_count == PACK_MAX_SECTIONS ||
                   !pack_section_from_pe(&psecs[section_count], &sh[i],
                                         (size_t)fs.st_size, 0)) {
                  printf("  [ unsupported .rdata section\n");
                  failed = 1;
                  break;
                }
                section_count++;
              }
            }

            if(!failed && (code_count == 0 || default_text_idx < 0)) {
              printf("  [ entry .text code section is missing\n");
              failed = 1;
            }
            if(!failed && DirSize(map) > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
              int reloc_state = packed_base_relocs(map, (size_t)fs.st_size,
                                                    psecs, section_count);
              if(reloc_state != 0) {
                printf("  [ PE has %s base relocations\n",
                       reloc_state < 0 ? "invalid" : "unsupported packed");
                failed = 1;
              }
            }
            if(!failed) {
              uint32_t blob_size = 0;
              uint8_t  *blob = NULL;
              pack_ref_t *refs = NULL;
              int n_refs = 0;

              /* Ensure .text (entry-point section) is at index 0 for the
                 packer's "first section fixed at offset 0" convention. */
              if(default_text_idx > 0) {
                pack_sec_t tmp = psecs[0];
                psecs[0] = psecs[default_text_idx];
                psecs[default_text_idx] = tmp;
              }
              if(((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->AddressOfEntryPoint !=
                 psecs[0].vaddr) {
                printf("  [ PE entry is not at .text+0\n");
                failed = 1;
              } else {
                blob = pack_extract(map, psecs, code_count, section_count,
                                    &blob_size, &refs, &n_refs);
              }

              if(blob != NULL) {
                bin2h(map, argv[1], blob, blob_size);
                bin2go(map, argv[1], blob, blob_size);
                /* Only executable sections enter the dispatch metadata. */
                emit_fn_table_h(map, argv[1], psecs, code_count);
                emit_ref_table_h(map, argv[1], refs, n_refs, psecs, code_count);
                free(blob);
                if(refs) free(refs);
              } else {
                printf("  [ unable to extract PE loader\n");
                failed = 1;
                if(refs) free(refs);
              }
            }
          }
        } else if(!failed) {
          printf("  [ No valid DOS or NT header found.\n");
          // treat file as binary
          bin2h(NULL, argv[1], map, fs.st_size);
		  bin2go(NULL, argv[1], map, fs.st_size);
          //bin2array(NULL, argv[1], map, fs.st_size);
        }
        munmap(map, fs.st_size);
      } else {
        printf("  [ unable to map input file\n");
        failed = 1;
      }
    }
    fclose(fp);
    return failed ? 1 : 0;
}
