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
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/linker.h>
#include <sys/sysent.h>
#include <sys/imgact_elf.h>
#include <sys/syscall.h>
#include <sys/signalvar.h>

#include <vm/vm.h>
#include <vm/vm_param.h>

#include <machine/elf.h>
#include <machine/frame.h>
#include <machine/md_var.h>
#include <machine/unwind.h>

static int ia64_coredump(struct thread *, struct vnode *, off_t);

struct sysentvec elf64_freebsd_sysvec = {
	SYS_MAXSYSCALL,
	sysent,
	0,
	0,
	NULL,
	0,
	NULL,
	NULL,
	__elfN(freebsd_fixup),
	sendsig,
	NULL,		/* sigcode */
	NULL,		/* &szsigcode */
	NULL,
	"FreeBSD ELF64",
	ia64_coredump,
	NULL,
	MINSIGSTKSZ,
	PAGE_SIZE,
	VM_MIN_ADDRESS,
	VM_MAXUSER_ADDRESS,
	USRSTACK,
	PS_STRINGS,
	VM_PROT_ALL,
	exec_copyout_strings,
	exec_setregs,
	NULL
};

static Elf64_Brandinfo freebsd_brand_info = {
						ELFOSABI_FREEBSD,
						EM_IA_64,
						"FreeBSD",
						NULL,
						"/libexec/ld-elf.so.1",
						&elf64_freebsd_sysvec,
						NULL,
					  };

SYSINIT(elf64, SI_SUB_EXEC, SI_ORDER_ANY,
	(sysinit_cfunc_t) elf64_insert_brand_entry,
	&freebsd_brand_info);

static Elf64_Brandinfo freebsd_brand_oinfo = {
						ELFOSABI_FREEBSD,
						EM_IA_64,
						"FreeBSD",
						NULL,
						"/usr/libexec/ld-elf.so.1",
						&elf64_freebsd_sysvec,
						NULL,
					  };

SYSINIT(oelf64, SI_SUB_EXEC, SI_ORDER_ANY,
	(sysinit_cfunc_t) elf64_insert_brand_entry,
	&freebsd_brand_oinfo);

Elf_Addr link_elf_get_gp(linker_file_t);

extern Elf_Addr fptr_storage[];

static int
ia64_coredump(struct thread *td, struct vnode *vp, off_t limit)
{
	struct trapframe *tf;
	uint64_t bspst, kstk, ndirty, rnat;

	tf = td->td_frame;
	ndirty = tf->tf_special.ndirty;
	if (ndirty != 0) {
		kstk = td->td_kstack + (tf->tf_special.bspstore & 0x1ffUL);
		__asm __volatile("mov	ar.rsc=0;;");
		__asm __volatile("mov	%0=ar.bspstore" : "=r"(bspst));
		/* Make sure we have all the user registers written out. */
		if (bspst - kstk < ndirty) {
			__asm __volatile("flushrs;;");
			__asm __volatile("mov	%0=ar.bspstore" : "=r"(bspst));
		}
		__asm __volatile("mov	%0=ar.rnat;;" : "=r"(rnat));
		__asm __volatile("mov	ar.rsc=3");
		copyout((void*)kstk, (void*)tf->tf_special.bspstore, ndirty);
		kstk += ndirty;
		tf->tf_special.bspstore += ndirty;
		tf->tf_special.ndirty = 0;
		tf->tf_special.rnat =
		    (bspst > kstk && (bspst & 0x1ffUL) < (kstk & 0x1ffUL))
		    ? *(uint64_t*)(kstk | 0x1f8UL) : rnat;
	}
	return (elf64_coredump(td, vp, limit));
}

static Elf_Addr
lookup_fdesc(linker_file_t lf, Elf_Word symidx)
{
	linker_file_t top;
	Elf_Addr addr;
	const char *symname;
	int i;
	static int eot = 0;

	addr = elf_lookup(lf, symidx, 0);
	if (addr == 0) {
		top = lf;
		symname = elf_get_symname(top, symidx);
		for (i = 0; i < top->ndeps; i++) {
			lf = top->deps[i];
			addr = (Elf_Addr)linker_file_lookup_symbol(lf,
			    symname, 0);
			if (addr != 0)
				break;
		}
		if (addr == 0)
			return (0);
	}

	if (eot)
		return (0);

	/*
	 * Lookup and/or construct OPD
	 */
	for (i = 0; i < 8192; i += 2) {
		if (fptr_storage[i] == addr)
			return (Elf_Addr)(fptr_storage + i);

		if (fptr_storage[i] == 0) {
			fptr_storage[i] = addr;
			fptr_storage[i+1] = link_elf_get_gp(lf);
			return (Elf_Addr)(fptr_storage + i);
		}
	}

	printf("%s: fptr table full\n", __func__);
	eot = 1;

	return (0);
}

/* Process one elf relocation with addend. */
static int
elf_reloc_internal(linker_file_t lf, const void *data, int type, int local)
{
	Elf_Addr relocbase = (Elf_Addr)lf->address;
	Elf_Addr *where;
	Elf_Addr addend, addr;
	Elf_Word rtype, symidx;
	const Elf_Rel *rel;
	const Elf_Rela *rela;

	switch (type) {
	case ELF_RELOC_REL:
		rel = (const Elf_Rel *)data;
		where = (Elf_Addr *)(relocbase + rel->r_offset);
		rtype = ELF_R_TYPE(rel->r_info);
		symidx = ELF_R_SYM(rel->r_info);
		switch (rtype) {
		case R_IA64_DIR64LSB:
		case R_IA64_FPTR64LSB:
		case R_IA64_REL64LSB:
			addend = *where;
			break;
		default:
			addend = 0;
			break;
		}
		break;
	case ELF_RELOC_RELA:
		rela = (const Elf_Rela *)data;
		where = (Elf_Addr *)(relocbase + rela->r_offset);
		rtype = ELF_R_TYPE(rela->r_info);
		symidx = ELF_R_SYM(rela->r_info);
		addend = rela->r_addend;
		break;
	default:
		panic("%s: invalid ELF relocation (0x%x)\n", __func__, type);
	}

	if (local) {
		if (rtype == R_IA64_REL64LSB)
			*where = relocbase + addend;
		return (0);
	}

	switch (rtype) {
	case R_IA64_NONE:
		break;
	case R_IA64_DIR64LSB:	/* word64 LSB	S + A */
		addr = elf_lookup(lf, symidx, 1);
		if (addr == 0)
			return (-1);
		*where = addr + addend;
		break;
	case R_IA64_FPTR64LSB:	/* word64 LSB	@fptr(S + A) */
		if (addend != 0) {
			printf("%s: addend ignored for OPD relocation\n",
			    __func__);
		}
		addr = lookup_fdesc(lf, symidx);
		if (addr == 0)
			return (-1);
		*where = addr;
		break;
	case R_IA64_REL64LSB:	/* word64 LSB	BD + A */
		break;
	case R_IA64_IPLTLSB:
		addr = lookup_fdesc(lf, symidx);
		if (addr == 0)
			return (-1);
		where[0] = *((Elf_Addr*)addr) + addend;
		where[1] = *((Elf_Addr*)addr + 1);
		break;
	default:
		printf("%s: unknown relocation (0x%x)\n", __func__,
		    (int)rtype);
		return -1;
	}

	return (0);
}

int
elf_reloc(linker_file_t lf, const void *data, int type)
{

	return (elf_reloc_internal(lf, data, type, 0));
}

int
elf_reloc_local(linker_file_t lf, const void *data, int type)
{

	return (elf_reloc_internal(lf, data, type, 1));
}

int
elf_cpu_load_file(linker_file_t lf)
{
	Elf_Ehdr *hdr;
	Elf_Phdr *ph, *phlim;
	Elf_Addr reloc, vaddr;

	hdr = (Elf_Ehdr *)(lf->address);
	if (!IS_ELF(*hdr)) {
		printf("Missing or corrupted ELF header at %p\n", hdr);
		return (EFTYPE);
	}

	/*
	 * Iterate over the segments and register the unwind table if
	 * we come across it.
	 */
	ph = (Elf_Phdr *)(lf->address + hdr->e_phoff);
	phlim = ph + hdr->e_phnum;
	reloc = ~0ULL;
	while (ph < phlim) {
		if (ph->p_type == PT_LOAD && reloc == ~0ULL)
			reloc = (Elf_Addr)lf->address - ph->p_vaddr;

		if (ph->p_type == PT_IA_64_UNWIND) {
			vaddr = ph->p_vaddr + reloc;
			unw_table_add((vm_offset_t)lf->address, vaddr,
			    vaddr + ph->p_memsz);
		}
		++ph;
	}

	return (0);
}

int
elf_cpu_unload_file(linker_file_t lf)
{

	unw_table_remove((vm_offset_t)lf->address);
	return (0);
}
