/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: load_aout.c,v 1.9 1998/10/09 23:15:39 peter Exp $
 */

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/imgact_aout.h>
#include <sys/reboot.h>
#include <sys/linker.h>
#include <string.h>
#include <machine/bootinfo.h>
#include <stand.h>
#include <a.out.h>
#define FREEBSD_AOUT
#include <link.h>

#include "bootstrap.h"

static int		aout_loadimage(struct loaded_module *mp, int fd, vm_offset_t loadaddr, struct exec *ehdr, int kernel);

#if 0
static vm_offset_t	aout_findkldident(struct loaded_module *mp, struct exec *ehdr);
static int		aout_fixupkldmod(struct loaded_module *mp, struct exec *ehdr);
#endif

char	*aout_kerneltype = "a.out kernel";
char	*aout_moduletype = "a.out module";

/*
 * Attempt to load the file (file) as an a.out module.  It will be stored at
 * (dest), and a pointer to a module structure describing the loaded object
 * will be saved in (result).
 */
int
aout_loadmodule(char *filename, vm_offset_t dest, struct loaded_module **result)
{
    struct loaded_module	*mp, *kmp;
    struct exec			ehdr;
    int				fd;
    vm_offset_t			addr;
    int				err, kernel;
    u_int			pad;
    char			*s;

    mp = NULL;
    
    /*
     * Open the image, read and validate the a.out header 
     */
    if (filename == NULL)	/* can't handle nameless */
	return(EFTYPE);
    if ((fd = open(filename, O_RDONLY)) == -1)
	return(errno);
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
	err = EFTYPE;		/* could be EIO, but may be small file */
	goto oerr;
    }
    if (N_BADMAG(ehdr)) {
	err = EFTYPE;
	goto oerr;
    }

    /*
     * Check to see what sort of module we are.
     *
     * XXX should check N_GETMID()
     */
    kmp = mod_findmodule(NULL, NULL);
    if ((N_GETFLAG(ehdr)) & EX_DYNAMIC) {
	/* Looks like a kld module */
	if (kmp == NULL) {
	    printf("aout_loadmodule: can't load module before kernel\n");
	    err = EPERM;
	    goto oerr;
	}
	if (strcmp(aout_kerneltype, kmp->m_type)) {
	    printf("aout_loadmodule: can't load module with kernel type '%s'\n", kmp->m_type);
	    err = EPERM;
	    goto oerr;
	}
	/* Looks OK, got ahead */
	kernel = 0;

    } else if (N_GETFLAG(ehdr) == 0) {
	/* Looks like a kernel */
	if (kmp != NULL) {
	    printf("aout_loadmodule: kernel already loaded\n");
	    err = EPERM;
	    goto oerr;
	}
	/* 
	 * Calculate destination address based on kernel entrypoint 	
	 * XXX this is i386-freebsd-aout specific
	 */
	dest = ehdr.a_entry & 0x100000;
	if (dest == 0) {
	    printf("aout_loadmodule: not a kernel (maybe static binary?)\n");
	    err = EPERM;
	    goto oerr;
	}
	kernel = 1;
    } else {
	err = EFTYPE;
	goto oerr;
    }

    /* 
     * Ok, we think we should handle this.
     */
    mp = mod_allocmodule();
    if (kernel)
	setenv("kernelname", filename, 1);
    s = strrchr(filename, '/');
    if (s)
	mp->m_name = strdup(s + 1); 
    else
	mp->m_name = strdup(filename);
    mp->m_type = strdup(kernel ? aout_kerneltype : aout_moduletype);

    /* Page-align the load address */
    addr = dest;
    pad = (u_int)addr & PAGE_MASK;
    if (pad != 0) {
	pad = PAGE_SIZE - pad;
	addr += pad;
    }
    mp->m_addr = addr;					/* save the aligned load address */
    if (kernel)
	printf("%s at %p\n", filename, (void *) addr);

    mp->m_size = aout_loadimage(mp, fd, addr, &ehdr, kernel);
    if (mp->m_size == 0)
	goto ioerr;

#if 0
    /* Handle KLD module data */
    if (!kernel && ((err = aout_fixupkldmod(mp, &ehdr)) != 0))
	goto oerr;
#endif

    /* save exec header as metadata */
    mod_addmetadata(mp, MODINFOMD_AOUTEXEC, sizeof(struct exec), &ehdr);

    /* Load OK, return module pointer */
    *result = (struct loaded_module *)mp;
    err = 0;
    goto out;
    
 ioerr:
    err = EIO;
 oerr:
    mod_discard(mp);
    free(mp);
 out:
    close(fd);
    return(err);
}

/*
 * With the file (fd) open on the image, and (ehdr) containing
 * the exec header, load the image at (addr)
 *
 * Fixup the a_bss field in (ehdr) to reflect the padding added to
 * align the symbol table.
 */
static int
aout_loadimage(struct loaded_module *mp, int fd, vm_offset_t loadaddr, struct exec *ehdr, int kernel)
{
    u_int		pad;
    vm_offset_t		addr;
    int			ss;
    vm_offset_t		ssym, esym;
    
    addr = loadaddr;
    lseek(fd, N_TXTOFF(*ehdr), SEEK_SET);

    /* text segment */
    printf("  text=0x%lx ", ehdr->a_text);
    if (archsw.arch_readin(fd, addr, ehdr->a_text) != ehdr->a_text)
	return(0);
    addr += ehdr->a_text;

    /* data segment */
    printf("data=0x%lx ", ehdr->a_data);
    if (archsw.arch_readin(fd, addr, ehdr->a_data) != ehdr->a_data)
	return(0);
    addr += ehdr->a_data;

    /* For kernels, we pad the BSS to a page boundary */
    if (kernel) {
	pad = (u_int)ehdr->a_bss & PAGE_MASK;
	if (pad != 0) {
	    pad = PAGE_SIZE - pad;
	    ehdr->a_bss += pad;
	}
    }
    printf("bss=0x%lx ", ehdr->a_bss);
    addr += ehdr->a_bss;

    /* symbol table size */
    ssym = addr;
    archsw.arch_copyin(&ehdr->a_syms, addr, sizeof(ehdr->a_syms));
    addr += sizeof(ehdr->a_syms);

    /* symbol table */
    printf("symbols=[0x%x+0x%lx", sizeof(ehdr->a_syms), ehdr->a_syms);
    if (archsw.arch_readin(fd, addr, ehdr->a_syms) != ehdr->a_syms)
	return(0);
    addr += ehdr->a_syms;

    /* string table */
    read(fd, &ss, sizeof(ss));
    archsw.arch_copyin(&ss, addr, sizeof(ss));
    addr += sizeof(ss);
    ss -= sizeof(ss);
    printf("+0x%x+0x%x]", sizeof(ss), ss);
    if (archsw.arch_readin(fd, addr, ss) != ss)
	return(0);
    printf(" \n");
    addr += ss;
    esym = addr;

    mod_addmetadata(mp, MODINFOMD_SSYM, sizeof(ssym), &ssym);
    mod_addmetadata(mp, MODINFOMD_ESYM, sizeof(esym), &esym);

    return(addr - loadaddr);
}


#if 0
#define AOUT_RELOC(mp, off) ((mp)->m_addr + (vm_offset_t)(off))

/*
 * The goal here is to find the one symbol in the loaded object
 * which fits the format "kld_identifier_<something>.  If there's
 * more than one, we fail.
 */
static vm_offset_t
aout_findkldident(struct loaded_module *mp, struct exec *ehdr)
{
    /* XXX much of this can go when we can address the load area directly */
    vm_offset_t				sp, ep, cand, stringbase, result;
    struct _dynamic			dynamic;
    struct section_dispatch_table	sdt;
    struct nzlist			nzl;
    char				*np;
    int					match;

    /* Get the _DYNAMIC object, which we assume is first in the data segment */
    archsw.arch_copyout(AOUT_RELOC(mp, ehdr->a_text), &dynamic, sizeof(dynamic));
    archsw.arch_copyout(AOUT_RELOC(mp, dynamic.d_un.d_sdt), &sdt, sizeof(struct section_dispatch_table));
    dynamic.d_un.d_sdt = &sdt;			/* fix up SDT pointer */
    if (dynamic.d_version != LD_VERSION_BSD)
	return(0);
    stringbase = AOUT_RELOC(mp, LD_STRINGS(&dynamic));
    
    /* start pointer */
    sp = AOUT_RELOC(mp, LD_SYMBOL(&dynamic));
    /* end pointer */
    ep = sp + LD_STABSZ(&dynamic);

    /*
     * Walk the entire table comparing names.
     */
    match = 0;
    result = 0;
    for (cand = sp; cand < ep; cand += sizeof(struct nzlist)) {
	/* get the entry, check for a name */
	archsw.arch_copyout(cand, &nzl, sizeof(struct nzlist));
	/* is this symbol worth looking at? */
	if ((nzl.nz_strx == 0)			||		/* no name */
	    (nzl.nz_value == 0)			||		/* not a definition */
	    ((nzl.nz_type == N_UNDF+N_EXT) && 
	     (nzl.nz_value != 0)           && 
	     (nzl.nz_other == AUX_FUNC)))			/* weak function */
	    continue;

	np = strdupout(stringbase + nzl.nz_strx);
	match = (np[0] == '_') && !strncmp(KLD_IDENT_SYMNAME, np + 1, strlen(KLD_IDENT_SYMNAME));
	free(np);
	if (match) {
	    /* duplicates? */
	    if (result)
		return(0);
	    result = AOUT_RELOC(mp, nzl.nz_value);
	}
    }
    return(result);
}

/*
 * Perform extra housekeeping associated with loading a KLD module.
 *
 * XXX if this returns an error, it seems the heap becomes corrupted.
 */
static int
aout_fixupkldmod(struct loaded_module *mp, struct exec *ehdr)
{
    struct kld_module_identifier	kident;
    struct kld_module_dependancy	*kdeps;
    vm_offset_t				vp;
    size_t				dsize;

    /* Find the KLD identifier */
    if ((vp = aout_findkldident(mp, ehdr)) == 0) {
	printf("bad a.out module format\n");
	return(EFTYPE);
    }
    archsw.arch_copyout(vp, &kident, sizeof(struct kld_module_identifier));
    
    /* Name the module using the name from the KLD data */
    if (mod_findmodule(kident.ki_name, NULL) != NULL) {
	printf("module '%s' already loaded\n", kident.ki_name);
	return(EPERM);
    }
    mp->m_name = strdup(kident.ki_name);

    /* Save the module identifier */
    mod_addmetadata(mp, MODINFOMD_KLDIDENT, sizeof(struct kld_module_identifier), &kident);
    
    /* Look for dependancy data, add to metadata list */
    if (kident.ki_ndeps > 0) {
	dsize = kident.ki_ndeps * kident.ki_depsize;
	kdeps = malloc(dsize);
	archsw.arch_copyout(AOUT_RELOC(mp, kident.ki_deps), kdeps, dsize);
	mod_addmetadata(mp, MODINFOMD_KLDDEP, dsize, kdeps);
	free(kdeps);
    }
    return(0);
}
#endif
