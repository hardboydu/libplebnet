/*-
 * Copyright (c) Peter Wemm <peter@netplex.com.au>
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
 * $FreeBSD$
 */

#ifndef _MACHINE_GLOBALDATA_H_
#define _MACHINE_GLOBALDATA_H_

#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/pmap.h>
#include <machine/segments.h>
#include <machine/tss.h>

/* XXX */
#ifdef KTR_PERCPU
#include <sys/ktr.h>
#endif

/*
 * This structure maps out the global data that needs to be kept on a
 * per-cpu basis.  genassym uses this to generate offsets for the assembler
 * code, which also provides external symbols so that C can get at them as
 * though they were really globals.
 *
 * The SMP parts are setup in pmap.c and locore.s for the BSP, and
 * mp_machdep.c sets up the data for the AP's to "see" when they awake.
 * The reason for doing it via a struct is so that an array of pointers
 * to each CPU's data can be set up for things like "check curproc on all
 * other processors"
 */
struct globaldata {
	struct globaldata *gd_prvspace;		/* self-reference */
	struct proc	*gd_curproc;
	struct proc	*gd_npxproc;
	struct pcb	*gd_curpcb;
	struct proc	*gd_idleproc;
	struct timeval	gd_switchtime;
	struct i386tss	gd_common_tss;
	int		gd_switchticks;
	u_char		gd_intr_nesting_level;
	u_char		gd_pad0[3];
	struct segment_descriptor gd_common_tssd;
	struct segment_descriptor *gd_tss_gdt;
	int		gd_currentldt;		/* only used for USER_LDT */
	u_int		gd_cpuid;
	u_int		gd_cpu_lockid;
	u_int		gd_other_cpus;
	pt_entry_t	*gd_prv_CMAP1;
	pt_entry_t	*gd_prv_CMAP2;
	pt_entry_t	*gd_prv_CMAP3;
	pt_entry_t	*gd_prv_PMAP1;
	caddr_t		gd_prv_CADDR1;
	caddr_t		gd_prv_CADDR2;
	caddr_t		gd_prv_CADDR3;
	unsigned	*gd_prv_PADDR1;
	u_int		gd_astpending;
	SLIST_ENTRY(globaldata) gd_allcpu;
	int		gd_witness_spin_check;
#ifdef KTR_PERCPU
#ifdef KTR
	volatile int	gd_ktr_idx;
	char		*gd_ktr_buf;
	char		gd_ktr_buf_data[KTR_SIZE];
#endif
#endif
};

SLIST_HEAD(cpuhead, globaldata);
extern struct cpuhead cpuhead;

#ifdef SMP
/*
 * This is the upper (0xff800000) address space layout that is per-cpu.
 * It is setup in locore.s and pmap.c for the BSP and in mp_machdep.c for
 * each AP.  genassym helps export this to the assembler code.
 */
struct privatespace {
	/* page 0 - data page */
	struct globaldata globaldata;
	char		__filler0[PAGE_SIZE - sizeof(struct globaldata)];

	/* page 1..4 - CPAGE1,CPAGE2,CPAGE3,PPAGE1 */
	char		CPAGE1[PAGE_SIZE];
	char		CPAGE2[PAGE_SIZE];
	char		CPAGE3[PAGE_SIZE];
	char		PPAGE1[PAGE_SIZE];

	/* page 5..4+UPAGES - idle stack (UPAGES pages) */
	char		idlestack[UPAGES * PAGE_SIZE];
};

extern struct privatespace SMP_prvspace[];

#endif

#endif	/* ! _MACHINE_GLOBALDATA_H_ */
