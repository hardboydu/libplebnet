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

#ifdef _KERNEL

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
	struct	globaldata *gd_prvspace;	/* Self-reference */
	struct	thread *gd_curthread;
	struct	thread *gd_npxthread;
	struct	pcb *gd_curpcb;
	struct	thread *gd_idlethread;
	struct	timeval gd_switchtime;
	struct	i386tss gd_common_tss;
	int	gd_switchticks;
	struct	segment_descriptor gd_common_tssd;
	struct	segment_descriptor *gd_tss_gdt;
	int	gd_currentldt;
	u_int	gd_cpuid;
	u_int	gd_other_cpus;
	SLIST_ENTRY(globaldata) gd_allcpu;
	struct	lock_list_entry *gd_spinlocks;
#ifdef KTR_PERCPU
	int	gd_ktr_idx;			/* Index into trace table */
	char	*gd_ktr_buf;
	char	gd_ktr_buf_data[KTR_SIZE];
#endif
};

#endif	/* _KERNEL */

#endif	/* ! _MACHINE_GLOBALDATA_H_ */
