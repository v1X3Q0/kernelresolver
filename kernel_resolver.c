/*
 * kernel_resolver.c
 * by snare (snare@ho.ax)
 * updates and aslr support by nervegas
 *
 * This is a simple example of how to resolve private symbols in the kernel
 * from within a kernel extension. There are much more efficient ways to
 * do this, but this should serve as a good starting point.
 *
 * See the following URL for more info:
 *     http://ho.ax/posts/2012/02/resolving-kernel-symbols/
 */

#include <stdio.h>
#include <string.h>
#include <mach-o/nlist.h>

#include <drv_share.h>
#include <krw_util.h>
#include <localUtil.h>
#include <localUtil_xnu.h>

#include "kernel_resolver.h"
// #include <IOKit/IOLib.h>

#define KERNEL_BASE MAC_KERNBASE
#define IOLog printf

struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd);
int find_symbol(struct mach_header_64 *mh, const char *name, void** symaddr_out);

int lookup_symbol(const char *symbol, void** symbol_out)
{
    int64_t slide = 0;
    vm_offset_t slide_address = 0;
    size_t kernBase = 0;
    int result = -1;
    void* symTarg = 0;

    // vm_kernel_unslide_or_perm_external((unsigned long long)(void *)printf, &slide_address);
    // slide = (unsigned long long)(void *)printf - slide_address;
    // int64_t base_address = slide + KERNEL_BASE;

    SAFE_BAIL(kBase(&kernBase) == -1);
    slide = kernBase - KERNEL_BASE;

    IOLog("%s: aslr slide: 0x%0llx\n", __func__, slide);
    IOLog("%s: base address: 0x%0llx\n", __func__, kernBase);

    SAFE_BAIL(find_symbol((struct mach_header_64 *)kernBase, symbol, symTarg) == -1);

    result = 0;
    if (symbol_out != 0)
    {
        *symbol_out = symTarg;
    }
fail:
    return result;
}

struct segment_command_64* find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *seg, *foundseg = NULL;

    /* first load command begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds)
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            /* evaluate segment */
            seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segname) == 0)
            {
                foundseg = seg;
                break;
            }
        }

        /* next load command */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }

    return foundseg;
}

struct load_command* find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc = NULL;

    /* first load command begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds)
    {
        if (lc->cmd == cmd)
        {
            foundlc = (struct load_command *)lc;
            break;
        }

        /* next load command*/
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }

    return foundlc;
}

#define REBASE_LOCAL(MH, KERN_BASE, TARG_ADDR) \
    TARG_ADDR - KERN_BASE + (size_t)MH

int find_symbol(struct mach_header_64 *mh, const char *name, void** symaddr_out)
{
#define KERNBASE_FS(TARG_ADDR) \
    REBASE_LOCAL(mh, MAC_KERNBASE, TARG_ADDR)

    int result = -1;
    struct symtab_command *symtab = NULL;
    struct segment_command_64 *linkedit = NULL;
    struct nlist_64 *nl = NULL;
    void *strtab = NULL;
    void *addr = NULL;
    char *str = 0;
    uint64_t i;
    int64_t strtab_addr = 0;
    int64_t symtab_addr = 0;

    /* check header (0xfeedfccf) */
    SAFE_PAIL(mh->magic != MH_MAGIC_64, "%s: magic number doesn't match - 0x%x\n", __func__, mh->magic);

    /* find the __LINKEDIT segment and LC_SYMTAB command */
    linkedit = find_segment_64(mh, SEG_LINKEDIT);
    SAFE_PAIL(!linkedit, "%s: couldn't find __LINKEDIT\n", __func__);

    symtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    SAFE_PAIL(!symtab, "%s: couldn't find LC_SYMTAB\n", __func__);

    /* walk the symbol table until we find a match */
//    strtab_addr = (int64_t)(KERNBASE_FS(linkedit->vmaddr) - linkedit->fileoff) + symtab->stroff;
//    symtab_addr = (int64_t)(KERNBASE_FS(linkedit->vmaddr) - linkedit->fileoff) + symtab->symoff;

    strtab_addr = (int64_t)mh + symtab->stroff;
    symtab_addr = (int64_t)mh + symtab->symoff;

    strtab = (void *)strtab_addr;
    for (i = 0, nl = (struct nlist_64 *)symtab_addr;
         i < symtab->nsyms;
         i++, nl = (struct nlist_64 *)((int64_t)nl + sizeof(struct nlist_64)))
    {
        str = (char *)strtab + nl->n_un.n_strx;

        FINISH_IF(strcmp(str, name) == 0);
    }

    goto fail;
finish:
    result = 0;
    addr = (void *)nl->n_value;
    if (symaddr_out != 0)
    {
        *symaddr_out = addr;
    }

fail:
    return result;
}

int resolve_live_symbol(struct mach_header_64* mach_static, struct mach_header_64* mach_dyn, const char *symbol, void** symbol_out)
{
    int result = -1;
    void* symTmp = 0;
    struct section_64* section_64_static = 0;
    struct section_64* section_64_live = 0;

    // on the read file
    SAFE_BAIL(find_symbol(mach_static, symbol, &symTmp) == -1);
    SAFE_BAIL(section_with_sym(mach_static, (size_t)symTmp, &section_64_static) == -1);

    // on the live kernel header
    section_64_live = getsectbynamefromheader_64(mach_dyn, section_64_static->segname, section_64_static->sectname);
    SAFE_BAIL(section_64_live == 0);

    result = 0;
    if (symbol_out != 0)
    {
        *symbol_out = symTmp - section_64_static->addr + section_64_live->addr;
    }
fail:
    return result;
}
