/*
 * Copyright 2025 Jacob Cherry
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbit.h>
#include <stdint.h>
#include <stdarg.h>
#include <endian.h>
#include <string.h>
#include <sys/stat.h>

#define MAKE_MAGIC16(b0, b1) ((b1 << 8) | b0)
#define MAKE_MAGIC32(b0, b1, b2, b3) ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0)

#define PE_SIGNATURE_PTR_ADDR                   0x3c

#define COFF_HEADER_OFFSET                          4 // From PE Signature
#define COFF_HEADER_NUMSECTIONS_OFFSET              2
#define COFF_HEADER_OPTIONAL_HEADER_SIZE_OFFSET    16
#define COFF_HEADER_LENGTH                         20

#define SECTION_TABLE_ENTRY_NAME_OFFSET             0
#define SECTION_TABLE_ENTRY_VIRTUAL_SIZE_OFFSET     8
#define SECTION_TABLE_ENTRY_VIRTUAL_ADDR_OFFSET    12
#define SECTION_TABLE_ENTRY_DATA_SIZE_OFFSET       16
#define SECTION_TABLE_ENTRY_DATA_PTR_OFFSET        20
#define SECTION_TABLE_ENTRY_LENGTH                 40

#define RESOURCE_DIRECTORY_NAME_ENTRY_CNT_OFFSET   12
#define RESOURCE_DIRECTORY_ID_ENTRY_CNT_OFFSET     14
#define RESOURCE_DIRECTORY_LENGTH                  16

#define RESOURCE_DIRECTORY_ENTRY_NAME_OFFSET        0
#define RESOURCE_DIRECTORY_ENTRY_ID_OFFSET          0
#define RESOURCE_DIRECTORY_ENTRY_DATA_PTR_OFFSET    4
#define RESOURCE_DIRECTORY_ENTRY_SUBDIR_PTR_OFFSET  4
#define RESOURCE_DIRECTORY_ENTRY_LENGTH             8

#define RESOURCE_DATA_ENTRY_DATA_PTR_OFFSET         0
#define RESOURCE_DATA_ENTRY_DATA_LEN_OFFSET         4
#define RESOURCE_DATA_ENTRY_LENGTH                 16

#define GROUP_ICON_DIRECTORY_TYPE_OFFSET            2
#define GROUP_ICON_DIRECTORY_COUNT_OFFSET           4
#define GROUP_ICON_DIRECTORY_LENGTH                 6

#define GROUP_ICON_ENTRY_WIDTH_OFFSET               0
#define GROUP_ICON_ENTRY_HEIGHT_OFFSET              1
#define GROUP_ICON_ENTRY_COLOR_COUNT_OFFSET         2
#define GROUP_ICON_ENTRY_PLANES_OFFSET              4
#define GROUP_ICON_ENTRY_BIT_COUNT_OFFSET           6
#define GROUP_ICON_ENTRY_BYTES_IN_RES_OFFSET        8
#define GROUP_ICON_ENTRY_ID_OFFSET                 12
#define GROUP_ICON_ENTRY_LENGTH                    14

#define ICO_HEADER_DIRECTORY_LENGTH GROUP_ICON_DIRECTORY_LENGTH
#define ICO_HEADER_ENTRY_LENGTH (GROUP_ICON_ENTRY_LENGTH + 2)

#define RT_ACCELERATOR   9
#define RT_ANICURSOR    21
#define RT_ANIICON      22
#define RT_BITMAP        2
#define RT_CURSOR        1
#define RT_DIALOG        5
#define RT_DLGINCLUDE   17
#define RT_FONT          8
#define RT_FONTDIR       7
#define RT_GROUP_CURSOR 12
#define RT_GROUP_ICON   14
#define RT_HTML         23
#define RT_ICON          3
#define RT_MANIFEST     24
#define RT_MENU          4
#define RT_MESSAGETABLE 11
#define RT_PLUGPLAY     19
#define RT_RCDATA       10
#define RT_STRING        6
#define RT_VERSION      16
#define RT_VXD          20

const uint16_t EXE_MAGIC = MAKE_MAGIC16('M', 'Z');
const uint32_t PE_MAGIC  = MAKE_MAGIC32('P', 'E', '\0', '\0');

#define SPRINTF(...) ({ \
    size_t _size = snprintf(NULL, 0, __VA_ARGS__); \
    char *_out = malloc((_size + 1) * sizeof(*_out)); \
    snprintf(_out, _size + 1, __VA_ARGS__); \
    _out; \
})

uint8_t read_u8(FILE *stream, uint64_t offset)
{
    fseek(stream, offset, SEEK_SET);
    return fgetc(stream);
}

void write_u8(FILE *stream, uint8_t val)
{
    fputc(val, stream);
}

uint16_t read_u16(FILE *stream, uint64_t offset)
{
    uint16_t ret = 0;

    fseek(stream, offset, SEEK_SET);
    fread(&ret, sizeof(uint16_t), 1, stream);

    return le16toh(ret);
}

void write_u16(FILE *stream, uint16_t val)
{
    uint16_t wval = htole16(val);

    fwrite(&wval, sizeof(uint16_t), 1, stream);
}

uint32_t read_u32(FILE *stream, uint64_t offset)
{
    uint32_t ret = 0;

    fseek(stream, offset, SEEK_SET);
    fread(&ret, sizeof(uint32_t), 1, stream);

    return le32toh(ret);
}

void write_u32(FILE *stream, uint32_t val)
{
    uint32_t wval = htole32(val);

    fwrite(&wval, sizeof(uint32_t), 1, stream);
}

uint64_t read_u64(FILE *stream, uint64_t offset)
{
    uint64_t ret = 0;

    fseek(stream, offset, SEEK_SET);
    fread(&ret, sizeof(uint64_t), 1, stream);

    return le64toh(ret);
}

void write_u64(FILE * stream, uint64_t val)
{
    uint64_t wval = htole64(val);
    
    fwrite(&wval, sizeof(uint64_t), 1, stream);
}

void copy_block(FILE *in, FILE* out, uint64_t offset, uint64_t length)
{
    fseek(in, offset, SEEK_SET);
    for (uint64_t i = 0; i < length; i++) {
        fputc(fgetc(in), out);
    }
}

char *read_wstr(FILE *stream, uint64_t offset, uint64_t wchars)
{
    uint16_t *utf16 = malloc(wchars * sizeof(*utf16));
    char *utf8 = malloc ((3 * wchars + 1) * sizeof(*utf8));

    fseek(stream, offset, SEEK_SET);
    fread(utf16, sizeof(*utf16), wchars, stream);

    uint64_t u8idx = 0;
    for (uint64_t i = 0; i < wchars; i++) {
        uint32_t codepoint = utf16[i];
        if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
            // handle surrogate pairs
            if (i + 1 >= wchars) {
                // unpaired surrogate at end of text
                codepoint = 0xfffd; // error replacement character
            } else if (utf16[i + 1] < 0xd800 || utf16[i + 1] > 0xdfff) {
                // unpaired surrogate in middle of text
                codepoint = 0xfffd;
            } else {
                uint32_t lowhalf = utf16[++i];

                codepoint -= 0xd800;
                lowhalf -= 0xdc00;
                codepoint = 0x10000 + (codepoint << 10) + lowhalf;
            }
        }

        if (codepoint > 0x10ffff) {
            // invalid codepoint - should be impossible with utf16
            codepoint = 0xfffd;
        }
        if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
            // surrogates are invalid utf8
            codepoint = 0xfffd;
        }

        if (codepoint <= 0x7f) {
            utf8[u8idx++] = (char)codepoint;
        } else if (codepoint <= 0x7ff) {
            utf8[u8idx++] = ((codepoint >> 6) & 0x1f) | 0xc0;
            utf8[u8idx++] = (codepoint & 0x3f) | 0x80;
        } else if (codepoint <= 0xffff) {
            utf8[u8idx++] = ((codepoint >> 12) & 0xf) | 0xe0;
            utf8[u8idx++] = ((codepoint >> 6) & 0x3f) | 0x80;
            utf8[u8idx++] = (codepoint & 0x3f) | 0x80;
        } else { // codepoint <= 0x10ffff
            utf8[u8idx++] = ((codepoint >> 18) & 0x7) | 0xf0;
            utf8[u8idx++] = ((codepoint >> 12) & 0x3f) | 0x80;
            utf8[u8idx++] = ((codepoint >> 6) & 0x3f) | 0x80;
            utf8[u8idx++] = (codepoint & 0x3f) | 0x80;
        }
    }

    utf8[u8idx++] = 0;
    free(utf16);

    return utf8;
}

typedef struct {
    FILE *exe;
    uint32_t section_faddr;
    uint32_t section_vaddr;
} rsrcctx;

typedef struct {
    bool isname;
    union {
        uint32_t id;
        char *name;
    };
} entryid;

typedef struct {
    bool issubdir;
    uint32_t offset;
} entrychild;

typedef struct {
    entryid id;
    entrychild child;
} rdentry;

#define ID(_id) ((entryid) { .isname = false, .id = (_id) })
#define NAME(_name) ((entryid) { .isname = true, .name = (_name) })
#define PRINT_ID(_id) do { \
    if ((_id).isname) { \
        printf("%s", (_id).name); \
    } else { \
        printf("%x", (_id).id); \
    } \
} while (0)

void read_rdentry(rsrcctx *ctx, uint32_t entry_addr, bool isname, rdentry *out)
{
    out->id.isname = isname,
    out->id.id = read_u32(ctx->exe, entry_addr + RESOURCE_DIRECTORY_ENTRY_ID_OFFSET);
    out->child.issubdir = false;
    out->child.offset = read_u32(ctx->exe, entry_addr + RESOURCE_DIRECTORY_ENTRY_SUBDIR_PTR_OFFSET);

    if (isname) {
        uint32_t naddr = ctx->section_faddr + (out->id.id & 0x7fffffff);
        uint16_t nlen = read_u16(ctx->exe, naddr);
        out->id.name = read_wstr(ctx->exe, naddr + 2, nlen);
    }

    if ((out->child.offset & 0x80000000) != 0) {
        out->child.issubdir = true;
        out->child.offset &= 0x7fffffff;
    }
}

bool search_resource_directory(rsrcctx *ctx, uint32_t directory_offset, entryid id, rdentry *out)
{
    uint32_t directory_addr = ctx->section_faddr + directory_offset;
    uint16_t name_entries = read_u16(ctx->exe, directory_addr + RESOURCE_DIRECTORY_NAME_ENTRY_CNT_OFFSET);
    uint16_t id_entries   = read_u16(ctx->exe, directory_addr + RESOURCE_DIRECTORY_ID_ENTRY_CNT_OFFSET);
    uint32_t entries_addr = directory_addr + RESOURCE_DIRECTORY_LENGTH +
        (id.isname ? 0 : (name_entries * RESOURCE_DIRECTORY_ENTRY_LENGTH));

    uint16_t low = 0;
    uint16_t high = (id.isname ? name_entries : id_entries) - 1;

    while (low <= high) {
        uint16_t entry = (low + high) / 2;
        uint32_t entry_addr = entries_addr + (entry * RESOURCE_DIRECTORY_ENTRY_LENGTH);
        uint32_t entry_id = read_u32(ctx->exe, entry_addr + RESOURCE_DIRECTORY_ENTRY_ID_OFFSET);

        if (id.isname) {
            uint32_t naddr = ctx->section_faddr + (entry_id & 0x7fffffff);
            uint16_t nlen = read_u16(ctx->exe, naddr);
            char *entry_name = read_wstr(ctx->exe, naddr + 2, nlen);
            int cmp = strcmp(entry_name, id.name);

            free(entry_name);

            if (cmp > 0) {
                high = entry - 1;
            } else if (cmp < 0) {
                low = entry + 1;
            } else {
                read_rdentry(ctx, entry_addr, true, out);
                return true;
            }
        } else {
            if (entry_id > id.id) {
                high = entry - 1;
            } else if (entry_id < id.id) {
                low = entry + 1;
            } else {
                read_rdentry(ctx, entry_addr, false, out);
                return true;
            }
        }
    }

    return false;
}

#define FOR_EACH_RESDIR_ENTRY(ctx, dir_offset, entry) { \
    uint32_t _diraddr = (ctx)->section_faddr + (dir_offset); \
    uint16_t _names = read_u16((ctx)->exe, _diraddr + RESOURCE_DIRECTORY_NAME_ENTRY_CNT_OFFSET); \
    uint16_t _ids   = read_u16((ctx)->exe, _diraddr + RESOURCE_DIRECTORY_ID_ENTRY_CNT_OFFSET); \
    \
    for (uint16_t _i = 0; _i < _names + _ids; _i++) { \
        uint32_t _eaddr = _diraddr + RESOURCE_DIRECTORY_LENGTH + (_i * RESOURCE_DIRECTORY_ENTRY_LENGTH); \
        read_rdentry((ctx), _eaddr, (_i < _names), (entry));

#define FOR_EACH_RESDIR_ENTRY_END(entry) \
        if ((entry)->id.isname) { \
            free((entry)->id.name); \
            (entry)->id.name = NULL; \
        } \
    } \
}

void dump_ico(rsrcctx *ctx, uint32_t data_entry_offset, const char *name, uint32_t lang)
{
    char *fname = SPRINTF("%s.%x.ico", name, lang);
    FILE *ico = fopen(fname, "wb");

    uint32_t data_entry_addr = ctx->section_faddr + data_entry_offset;
    uint32_t igroup_vaddr = read_u32(ctx->exe, data_entry_addr + RESOURCE_DATA_ENTRY_DATA_PTR_OFFSET);

    uint32_t igroup_addr = igroup_vaddr - ctx->section_vaddr + ctx->section_faddr;
    uint32_t igroup_len = read_u32(ctx->exe, data_entry_addr + RESOURCE_DATA_ENTRY_DATA_LEN_OFFSET);

    uint16_t igroup_type = read_u16(ctx->exe, igroup_addr + GROUP_ICON_DIRECTORY_TYPE_OFFSET);
    if (igroup_type != 1) {
        fprintf(stderr, "RT_GROUP_ICON.%s.%x: type should be 1 but is %u\n", name, lang, igroup_type);
        goto cleanup;
    }
    uint16_t igroup_count = read_u16(ctx->exe, igroup_addr + GROUP_ICON_DIRECTORY_COUNT_OFFSET);
    if (igroup_count == 0) {
        fprintf(stderr, "RT_GROUP_ICON.%s.%x: icon has no images\n", name, lang);
        goto cleanup;
    }

    if ((((uint32_t)igroup_count * GROUP_ICON_ENTRY_LENGTH) + GROUP_ICON_DIRECTORY_LENGTH) > igroup_len) {
        fprintf(stderr, "RT_GROUP_ICON.%s.%x: icon count too large for data\n", name, lang);
        goto cleanup;
    }

    struct {
        uint16_t id;
        uint32_t size;
    } *icon_info = calloc(igroup_count, sizeof(*icon_info));

    write_u16(ico, 0); // reserved
    write_u16(ico, igroup_type);
    write_u16(ico, igroup_count);

    uint32_t icon_ptr = ICO_HEADER_DIRECTORY_LENGTH + (igroup_count * ICO_HEADER_ENTRY_LENGTH);

    for (uint16_t igentry = 0; igentry < igroup_count; igentry++) {
        uint32_t igentry_addr = igroup_addr + GROUP_ICON_DIRECTORY_LENGTH + (igentry * GROUP_ICON_ENTRY_LENGTH);
        icon_info[igentry].id = read_u16(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_ID_OFFSET);
        icon_info[igentry].size = read_u32(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_BYTES_IN_RES_OFFSET);

        write_u8(ico, read_u8(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_WIDTH_OFFSET));
        write_u8(ico, read_u8(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_HEIGHT_OFFSET));
        write_u8(ico, read_u8(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_COLOR_COUNT_OFFSET));
        write_u8(ico, 0); // reserved
        write_u16(ico, read_u16(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_PLANES_OFFSET));
        write_u16(ico, read_u16(ctx->exe, igentry_addr + GROUP_ICON_ENTRY_BIT_COUNT_OFFSET));
        write_u32(ico, icon_info[igentry].size);
        write_u32(ico, icon_ptr);

        icon_ptr += icon_info[igentry].size;
    }

    rdentry type_entry = { 0 };
    rdentry icon_entry = { 0 };

    if (!search_resource_directory(ctx, 0, ID(RT_ICON), &type_entry)) {
        fprintf(stderr, "RT_GROUP_ICO.%s.%u: No RT_ICON resources!\n", name, lang);
        goto cleanup;
    }

    if (!type_entry.child.issubdir) {
        fprintf(stderr, "RT_GROUP_ICON.%s.%x: RT_ICON does not have children\n",
                name, lang);
        goto cleanup;
    }


    for (uint16_t igentry = 0; igentry < igroup_count; igentry++) {
        if (!search_resource_directory(ctx, type_entry.child.offset, ID(icon_info[igentry].id), &icon_entry)) {
            fprintf(stderr, "RT_GROUP_ICON.%s.%x: Couldn't find RT_ICON resource with ID %x\n",
                    name, lang, icon_info[igentry].id);
            goto cleanup;
        }

        if (icon_entry.child.issubdir) {
            if (!search_resource_directory(ctx, icon_entry.child.offset, ID(lang), &icon_entry)) {
                fprintf(stderr, "RT_GROUP_ICON.%s.%x: Couldn't find RT_ICON resource with ID %x, language %u\n",
                        name, lang, icon_info[igentry].id, lang);
                goto cleanup;
            }

            if (icon_entry.id.isname) {
                fprintf(stderr, "RT_GROUP_ICON.%s.%x: Language should be an ID\n", name, lang);
                goto cleanup;
            }

            if (icon_entry.child.issubdir) {
                fprintf(stderr, "RT_GROUP_ICON.%s.%x: Language %x doesn't point to a data entry\n",
                        name, lang, icon_entry.id.id);
                goto cleanup;
            }
        }

        uint32_t icon_entry_addr = ctx->section_faddr + icon_entry.child.offset;
        uint32_t icon_vaddr = read_u32(ctx->exe, icon_entry_addr + RESOURCE_DATA_ENTRY_DATA_PTR_OFFSET);

        uint32_t icon_addr = icon_vaddr - ctx->section_vaddr + ctx->section_faddr;
        uint32_t icon_len = read_u32(ctx->exe, icon_entry_addr + RESOURCE_DATA_ENTRY_DATA_LEN_OFFSET);

        if (icon_len < icon_info[igentry].size) {
            fprintf(stderr, "RT_GROUP_ICON.%s.%x: RT_ICON with ID %x too small (%u < %u)\n",
                    name, lang, icon_info[igentry].id, icon_len, icon_info[igentry].size);
            goto cleanup;
        }

        copy_block(ctx->exe, ico, icon_addr, icon_info[igentry].size);
    }

cleanup:
    if (type_entry.id.isname) {
        free(type_entry.id.name);
    }
    if (icon_entry.id.isname) {
        free(icon_entry.id.name);
    }
    if (icon_entry.id.isname) {
        free(icon_entry.id.name);
    }
    fclose(ico);
    free(fname);
}

int main(int argc, char **argv)
{
    int ret = 1;

    if (argc <= 1) {
        fprintf(stderr, "Usage: %s exe_file", argv[0]);
    }

    FILE *exe = fopen(argv[1], "rb");

    // Verify the EXE magic number
    uint16_t exe_magic = read_u16(exe, 0);
    if (exe_magic != EXE_MAGIC) {
        fprintf(stderr, "ERROR: %s is not a windows executable\n", argv[1]);
        goto cleanup;
    }

    printf("EXE Magic number matches\n");

    uint32_t pe_signature_addr = read_u32(exe, PE_SIGNATURE_PTR_ADDR);
    printf("PE Signature @ 0x%x\n", pe_signature_addr);

    uint32_t pe_magic = read_u32(exe, pe_signature_addr);
    if (pe_magic != PE_MAGIC) {
        fprintf(stderr, "ERROR: %s is not a PE windows executable\n", argv[1]);
        goto cleanup;
    }
    printf("PE Signature matches\n");

    uint32_t coff_header_addr = pe_signature_addr + COFF_HEADER_OFFSET;
    printf("COFF Header @ 0x%x\n", coff_header_addr);

    uint16_t section_count   = read_u16(exe, coff_header_addr + COFF_HEADER_NUMSECTIONS_OFFSET);
    uint16_t opt_header_len = read_u16(exe, coff_header_addr + COFF_HEADER_OPTIONAL_HEADER_SIZE_OFFSET);
    printf("Optional Header Length - %u bytes\n", opt_header_len);

    uint32_t section_table_addr = coff_header_addr + COFF_HEADER_LENGTH + opt_header_len;
    printf("Section Table with %u entries @ 0x%x\n", section_count, section_table_addr);

    uint32_t rsrc_header_addr = 0;
    for (uint16_t entry = 0; entry < section_count; entry++) {
        char namebuf[8];
        uint32_t entry_addr = section_table_addr + (entry * SECTION_TABLE_ENTRY_LENGTH);

        fseek(exe, entry_addr + SECTION_TABLE_ENTRY_NAME_OFFSET, SEEK_SET);
        fread(namebuf, sizeof(char), 8, exe);
        printf("Section %u: %.8s\n", entry, namebuf);

        if (strncmp(namebuf, ".rsrc", 5) == 0) {
            rsrc_header_addr = entry_addr;
            break;
        }

    }

    if (rsrc_header_addr == 0) {
        fprintf(stderr, "ERROR: .rsrc section header not found\n");
        goto cleanup;
    }

    printf("Found .rsrc section header @ 0x%x\n", rsrc_header_addr);
    uint32_t rsrc_section_vaddr = read_u32(exe, rsrc_header_addr + SECTION_TABLE_ENTRY_VIRTUAL_ADDR_OFFSET);
    uint32_t rsrc_section_addr  = read_u32(exe, rsrc_header_addr + SECTION_TABLE_ENTRY_DATA_PTR_OFFSET);
    printf(".rsrc section @ 0x%x -> 0x%x\n", rsrc_section_addr, rsrc_section_vaddr);

    rsrcctx ctx = {
        exe,
        rsrc_section_addr,
        rsrc_section_vaddr,
    };

    rdentry type_entry = { 0 };
    rdentry name_entry = { 0 };
    rdentry lang_entry = { 0 };
    if(!search_resource_directory(&ctx, 0, ID(RT_GROUP_ICON), &type_entry)) {
        fprintf(stderr, "No RT_GROUP_ICON resources found!\n");
        goto cleanup;
    }

    if (!type_entry.child.issubdir) {
        fprintf(stderr, "Type RT_GROUP_ICON doesn't point to a subdir\n");
        goto cleanup;
    }

    FOR_EACH_RESDIR_ENTRY(&ctx, type_entry.child.offset, &name_entry) {
        printf("Handling icon group: ");
        PRINT_ID(name_entry.id);
        printf("\n");

        if (name_entry.child.issubdir) {
            FOR_EACH_RESDIR_ENTRY(&ctx, name_entry.child.offset, &lang_entry) {
                if (lang_entry.id.isname) {
                    fprintf(stderr, "Language should be an ID\n");
                    goto cleanup;
                }

                printf("Handling language: %x\n", lang_entry.id.id);

                if (lang_entry.child.issubdir) {
                    fprintf(stderr, "Language %x doesn't point to a data entry\n", lang_entry.id.id);
                    goto cleanup;
                }

                dump_ico(&ctx, lang_entry.child.offset, name_entry.id.name, lang_entry.id.id);
            } FOR_EACH_RESDIR_ENTRY_END(&lang_entry);
        } else {
            dump_ico(&ctx, name_entry.child.offset, name_entry.id.name, 0);
        }
    } FOR_EACH_RESDIR_ENTRY_END(&name_entry);

    ret = 0;
cleanup:
    // Typically unnecessary, but are important if we break out of the for loops early
    if (lang_entry.id.isname) {
        free(lang_entry.id.name);
    }
    if (name_entry.id.isname) {
        free(name_entry.id.name);
    }
    if (type_entry.id.isname) {
        free(type_entry.id.name);
    }
    fclose(exe);
    return ret;
}
