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

#ifndef	_MACHINE_PCB_H_
#define	_MACHINE_PCB_H_

#include <machine/fp.h>
#include <machine/frame.h>

/*
 * XXX: MAXWIN should probably be done dynamically, pcb_wscratch is therefore
 * at the end of the pcb.
 */
#define	MAXWIN		8

/* Used in pcb_fcwp to mark the wscratch stack as empty. */
#define	PCB_CWP_EMPTY	0xff

/* NOTE: pcb_fpstate must be aligned on a 64 byte boundary. */
struct	pcb {
	struct	fpstate	pcb_fpstate;
	u_long	pcb_cwp;
	u_long	pcb_fp;
	u_long	pcb_pc;
	u_long	pcb_y;
	caddr_t	pcb_onfault;
	u_long	pcb_nsaved;
	u_long	pcb_rwsp[MAXWIN];
	struct	rwindow pcb_rw[MAXWIN];
};

struct	md_coredump {
};

#ifdef _KERNEL
int	savectx(struct pcb *pcb);
#endif

#endif /* !_MACHINE_PCB_H_ */
