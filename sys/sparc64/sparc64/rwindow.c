/*-
 * Copyright (c) 1997 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: BSDI: trap.c,v 1.17.2.9 1999/10/19 15:29:52 cp Exp
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ktr.h>
#include <sys/proc.h>
#include <sys/user.h>

#include <machine/frame.h>

int
rwindow_load(struct proc *p, struct trapframe *tf, int n)
{
	struct rwindow rw;
	u_long usp;
	int error;
	int i;

	/*
	 * In case current window is still only on-chip, push it out;
	 * if it cannot get all the way out, we cannot continue either.
	 */
	if ((error = rwindow_save(p)) != 0)
		return (error);
	usp = tf->tf_out[6];
	CTR3(KTR_TRAP, "rwindow_load: p=%p (%s) n=%d",
	    p, p->p_comm, n);
	for (i = 0; i < n; i++) {
		CTR1(KTR_TRAP, "rwindow_load: usp=%#lx", usp);
		usp += SPOFF;
		error = copyin((void *)usp, &rw, sizeof rw);
		usp = rw.rw_in[6];
	}
	CTR1(KTR_TRAP, "rwindow_load: error=%d", error);
	return (error);
}

int
rwindow_save(struct proc *p)
{
	struct rwindow *rw;
	struct pcb *pcb;
	u_long *ausp;
	u_long usp;
	int error;
	int i;

	flushw();
	pcb = &p->p_addr->u_pcb;
	i = pcb->pcb_nsaved;
	CTR3(KTR_TRAP, "rwindow_save: p=%p (%s) nsaved=%d", p, p->p_comm, i);
	if (i == 0)
		return (0);
	ausp = pcb->pcb_rwsp;
	rw = pcb->pcb_rw;
	error = 0;
	do {
		usp = *ausp;
		CTR1(KTR_TRAP, "rwindow_save: usp=%#lx", usp);
		usp += SPOFF;
		error = copyout(rw, (void *)usp, sizeof *rw);
		if (error)
			break;
		ausp++;
		rw++;
	} while (--i > 0);
	CTR1(KTR_TRAP, "rwindow_save: error=%d", error);
	if (error == 0)
		pcb->pcb_nsaved = 0;
	return (error);
}
