/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *	from: @(#)DEFS.h	5.1 (Berkeley) 4/23/90
 * $FreeBSD$
 */

#ifndef _MACHINE_ASM_H_
#define	_MACHINE_ASM_H_

#include <sys/cdefs.h>

#ifdef PIC
#define	PIC_PLT(x)	x@PLT
#define	PIC_GOT(x)	x@GOTPCREL(%rip)
#else
#define	PIC_PLT(x)	x
#define	PIC_GOT(x)	x
#endif

/*
 * CNAME and HIDENAME manage the relationship between symbol names in C
 * and the equivalent assembly language names.  CNAME is given a name as
 * it would be used in a C program.  It expands to the equivalent assembly
 * language name.  HIDENAME is given an assembly-language name, and expands
 * to a possibly-modified form that will be invisible to C programs.
 */
#define CNAME(csym)		csym
#define HIDENAME(asmsym)	__CONCAT(.,asmsym)

/* XXX should use .p2align 4,0x90 for -m486. */
#define _START_ENTRY	.text; .p2align 2,0x90

#define _ENTRY(x)	_START_ENTRY; \
			.globl CNAME(x); .type CNAME(x),@function; CNAME(x):

#ifdef PROF
#define	ALTENTRY(x)	_ENTRY(x); \
			pushl %rbp; movl %rsp,%rbp; \
			call PIC_PLT(HIDENAME(mcount)); \
			popl %rbp; \
			jmp 9f
#define	ENTRY(x)	_ENTRY(x); \
			pushl %rbp; movl %rsp,%rbp; \
			call PIC_PLT(HIDENAME(mcount)); \
			popl %rbp; \
			9:
#else
#define	ALTENTRY(x)	_ENTRY(x)
#define	ENTRY(x)	_ENTRY(x)
#endif

#define RCSID(x)	.text; .asciz x

#undef __FBSDID
#if !defined(lint) && !defined(STRIP_FBSDID)
#define __FBSDID(s)	.ident s
#else
#define __FBSDID(s)	/* nothing */
#endif /* not lint and not STRIP_FBSDID */

#ifdef _ARCH_INDIRECT
/*
 * Generate code to select between the generic functions and _ARCH_INDIRECT
 * specific ones.
 * XXX nested __CONCATs don't work with non-ANSI cpp's.
 */
#define	ANAME(x)	CNAME(__CONCAT(__CONCAT(__,_ARCH_INDIRECT),x))
#define	ASELNAME(x)	CNAME(__CONCAT(__arch_select_,x))
#define	AVECNAME(x)	CNAME(__CONCAT(__arch_,x))
#define	GNAME(x)	CNAME(__CONCAT(__generic_,x))

/* Don't bother profiling this. */
#ifdef PIC
#define	ARCH_DISPATCH(x) \
			_START_ENTRY; \
			.globl CNAME(x); .type CNAME(x),@function; CNAME(x): ; \
			movq PIC_GOT(AVECNAME(x)),%rax; \
			jmpq *(%rax)

#define	ARCH_SELECT(x)	_START_ENTRY; \
			.type ASELNAME(x),@function; \
			ASELNAME(x): \
			call PIC_PLT(CNAME(__get_hw_float)); \
			testq %rax,%rax; \
			movq PIC_GOT(ANAME(x)),%rax; \
			jne 8f; \
			movq PIC_GOT(GNAME(x)),%rax; \
			8: \
			movq PIC_GOT(AVECNAME(x)),%rdx; \
			movq %rax,(%rdx); \
			jmpq *%rax
#else /* !PIC */
#define	ARCH_DISPATCH(x) \
			_START_ENTRY; \
			.globl CNAME(x); .type CNAME(x),@function; CNAME(x): ; \
			jmpw *AVECNAME(x)

#define	ARCH_SELECT(x)	_START_ENTRY; \
			.type ASELNAME(x),@function; \
			ASELNAME(x): \
			call CNAME(__get_hw_float); \
			testw %rax,%rax; \
			movw $ANAME(x),%rax; \
			jne 8f; \
			movw $GNAME(x),%rax; \
			8: \
			movw %rax,AVECNAME(x); \
			jmpw *%rax
#endif /* PIC */

#define	ARCH_VECTOR(x)	.data; .p2align 2; \
			.globl AVECNAME(x); \
			.type AVECNAME(x),@object; \
			.size AVECNAME(x),4; \
			AVECNAME(x): .long ASELNAME(x)

#undef _ENTRY
#define	_ENTRY(x)	ARCH_VECTOR(x); ARCH_SELECT(x); ARCH_DISPATCH(x); \
			_START_ENTRY; \
			.globl ANAME(x); .type ANAME(x),@function; ANAME(x):

#endif /* _ARCH_INDIRECT */

#endif /* !_MACHINE_ASM_H_ */
