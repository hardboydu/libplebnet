/*-
 * Copyright (c) 2001 Jake Burkholder.
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	_MACHINE_ELF_H_
#define	_MACHINE_ELF_H_

#include <sys/elf64.h>

#define	__ELF_WORD_SIZE	64
#include <sys/elf_generic.h>

#define	ELF_ARCH	EM_SPARCV9

#define	ELF_TARG_CLASS	ELFCLASS64
#define	ELF_TARG_DATA	ELFDATA2MSB
#define	ELF_TARG_MACH	ELF_ARCH
#define	ELF_TARG_VER	1

#define	ELF_MACHINE_OK(m)	((m) == ELF_ARCH)
#define	ELF_RTLD_ADDR(vm)	(0)

/*
 * Auxiliary vector entries for passing information to the interpreter.
 */

typedef	struct {
	long	a_type;
	union {
		long	a_val;
		void	*a_ptr;
		void	(*a_fcn)(void);
	} a_un;
} Elf64_Auxinfo;

__ElfType(Auxinfo);

/*
 * Values for a_type.
 */

#define AT_NULL		0	/* Terminates the vector. */
#define AT_IGNORE	1	/* Ignored entry. */
#define AT_EXECFD	2	/* File descriptor of program to load. */
#define AT_PHDR		3	/* Program header of program already loaded. */
#define AT_PHENT	4	/* Size of each program header entry. */
#define AT_PHNUM	5	/* Number of program header entries. */
#define AT_PAGESZ	6	/* Page size in bytes. */
#define AT_BASE		7	/* Interpreter's base address. */
#define AT_FLAGS	8	/* Flags (unused). */
#define AT_ENTRY	9	/* Where interpreter should transfer control. */

/*
 * The following non-standard values are used for passing information
 * from John Polstra's testbed program to the dynamic linker.  These
 * are expected to go away soon.
 *
 * Unfortunately, these overlap the Linux non-standard values, so they
 * must not be used in the same context.
 */
#define AT_BRK		10	/* Starting point for sbrk and brk. */
#define AT_DEBUG	11	/* Debugging level. */

#define	AT_COUNT	15	/* Count of defined aux entry types. */

#endif /* !_MACHINE_ELF_H_ */
