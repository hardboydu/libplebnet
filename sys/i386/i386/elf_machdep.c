/*-
 * Copyright 1996-1998 John D. Polstra.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *      $Id: elf_machdep.c,v 1.1 1998/09/11 08:47:02 dfr Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/linker.h>
#include <machine/elf.h>

/* Process one elf relocation with addend. (!) */
int
elf_reloc(linker_file_t lf, const Elf_Rela *rela, const char *sym)
{
	Elf_Addr relocbase = (Elf_Addr) lf->address;
	Elf_Addr *where = (Elf_Addr *) (relocbase + rela->r_offset);
	Elf_Addr addr, tmp_value;

	switch (ELF_R_TYPE(rela->r_info)) {

		case R_386_NONE:
			break;

		case R_386_32:
			addr = (Elf_Addr)linker_file_lookup_symbol(lf, sym, 1);
			if (addr == NULL)
				return -1;

			addr += rela->r_addend;
			if (*where != addr)
				*where = addr;
			break;

		case R_386_PC32:
			addr = (Elf_Addr)linker_file_lookup_symbol(lf, sym, 1);
			if (addr == NULL)
				return -1;

			addr += *where - (Elf_Addr)where + rela->r_addend;
			if (*where != addr)
				*where = addr;
			break;

		case R_386_COPY:
			/*
			 * There shouldn't be copy relocations in kernel
			 * objects.
			 */
			printf("kldload: unexpected R_COPY relocation\n");
			return -1;
			break;

		case R_386_GLOB_DAT:
			addr = (Elf_Addr)linker_file_lookup_symbol(lf, sym, 1);
			if (addr == NULL)
				return -1;

			if (*where != addr)
				*where = addr;
			break;

		case R_386_RELATIVE:
			*where += relocbase;
			break;

		default:
			printf("kldload: unexpected relocation type %d\n",
			       ELF_R_TYPE(rela->r_info));
			return -1;
	}
	return(0);
}
