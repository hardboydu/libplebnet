/*-
 * Copyright (c) 1989, 1990 William F. Jolitz.
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
 *	@(#)ipl.s
 *
 *	$Id: ipl.s,v 1.24 1998/08/11 17:01:32 bde Exp $
 */


/*
 * AT/386
 * Vector interrupt control section
 */

	.data
	ALIGN_DATA

/* current priority (all off) */
	.globl	_cpl
_cpl:	.long	HWI_MASK | SWI_MASK

	.globl	_tty_imask
_tty_imask:	.long	SWI_TTY_MASK
	.globl	_bio_imask
_bio_imask:	.long	SWI_CLOCK_MASK | SWI_CAMBIO_MASK
	.globl	_net_imask
_net_imask:	.long	SWI_NET_MASK | SWI_CAMNET_MASK
	.globl	_cam_imask
_cam_imask:	.long	SWI_CAMBIO_MASK | SWI_CAMNET_MASK
	.globl	_soft_imask
_soft_imask:	.long	SWI_MASK
	.globl	_softnet_imask
_softnet_imask:	.long	SWI_NET_MASK
	.globl	_softtty_imask
_softtty_imask:	.long	SWI_TTY_MASK


/* pending interrupts blocked by splxxx() */
	.globl	_ipending
_ipending:	.long	0

/* set with bits for which queue to service */
	.globl	_netisr
_netisr:	.long	0

	.globl _netisrs
_netisrs:
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr
	.long	dummynetisr, dummynetisr, dummynetisr, dummynetisr

	.text

#ifdef SMP
#ifdef notnow
#define TEST_CIL			\
	cmpl	$0x0100, _cil ;		\
	jne	1f ;			\
	cmpl	$0, _inside_intr ;	\
	jne	1f ;			\
	int	$3 ;			\
1:
#else
#define TEST_CIL
#endif
#endif

/*
 * Handle return from interrupts, traps and syscalls.
 */
	SUPERALIGN_TEXT
_doreti:
#ifdef SMP
	TEST_CIL
#endif
	FAKE_MCOUNT(_bintr)		/* init "from" _bintr -> _doreti */
	addl	$4,%esp			/* discard unit number */
	popl	%eax			/* cpl or cml to restore */
doreti_next:
	/*
	 * Check for pending HWIs and SWIs atomically with restoring cpl
	 * and exiting.  The check has to be atomic with exiting to stop
	 * (ipending & ~cpl) changing from zero to nonzero while we're
	 * looking at it (this wouldn't be fatal but it would increase
	 * interrupt latency).  Restoring cpl has to be atomic with exiting
	 * so that the stack cannot pile up (the nesting level of interrupt
	 * handlers is limited by the number of bits in cpl).
	 */
#ifdef SMP
	TEST_CIL
	cli				/* early to prevent INT deadlock */
	pushl	%eax			/* preserve cpl while getting lock */
	ICPL_LOCK
	popl	%eax
doreti_next2:
#endif
	movl	%eax,%ecx
#ifdef CPL_AND_CML
	orl	_cpl, %ecx		/* add cpl to cml */
#endif
	notl	%ecx			/* set bit = unmasked level */
#ifndef SMP
	cli
#endif
	andl	_ipending,%ecx		/* set bit = unmasked pending INT */
	jne	doreti_unpend
doreti_exit:
#ifdef SMP
	TEST_CIL
#endif
#ifdef CPL_AND_CML
	movl	%eax, _cml
#else
	movl	%eax,_cpl
#endif
	FAST_ICPL_UNLOCK		/* preserves %eax */
	MPLOCKED decb _intr_nesting_level
	MEXITCOUNT
#ifdef VM86
#ifdef CPL_AND_CML
	/* XXX CPL_AND_CML needs work */
#error not ready for vm86
#endif
	cmpl	$1,_in_vm86call
	je	1f			/* want cpl == SWI_AST_PENDING */
	/*
	 * XXX
	 * Sometimes when attempting to return to vm86 mode, cpl is not
	 * being reset to 0, so here we force it to 0 before returning to
	 * vm86 mode.  doreti_stop is a convenient place to set a breakpoint.
	 * When the cpl problem is solved, this code can disappear.
	 */
	ICPL_LOCK
	cmpl	$0,_cpl				/* cpl == 0, skip it */
	je	1f
	testl	$PSL_VM,TF_EFLAGS(%esp)		/* going to VM86 mode? */
	jne	doreti_stop
	testb	$SEL_RPL_MASK,TRAPF_CS_OFF(%esp)	/* to user mode? */
	je	1f
doreti_stop:
	movl	$0,_cpl
	nop
1:
	FAST_ICPL_UNLOCK		/* preserves %eax */
#endif /* VM86 */

#ifdef SMP
#ifdef INTR_SIMPLELOCK
#error code needed here to decide which lock to release, INTR or giant
#endif
	/* release the kernel lock */
	pushl	$_mp_lock		/* GIANT_LOCK */
	call	_MPrellock
	add	$4, %esp
#endif /* SMP */

	.globl	doreti_popl_es
doreti_popl_es:
	popl	%es
	.globl	doreti_popl_ds
doreti_popl_ds:
	popl	%ds
	popal
	addl	$8,%esp
	.globl	doreti_iret
doreti_iret:
	iret

	ALIGN_TEXT
	.globl	doreti_iret_fault
doreti_iret_fault:
	subl	$8,%esp
	pushal
	pushl	%ds
	.globl	doreti_popl_ds_fault
doreti_popl_ds_fault:
	pushl	%es
	.globl	doreti_popl_es_fault
doreti_popl_es_fault:
	movl	$0,4+4+32+4(%esp)	/* XXX should be the error code */
	movl	$T_PROTFLT,4+4+32+0(%esp)
	jmp	alltraps_with_regs_pushed

	ALIGN_TEXT
doreti_unpend:
	/*
	 * Enabling interrupts is safe because we haven't restored cpl yet.
	 * The locking from the "btrl" test is probably no longer necessary.
	 * We won't miss any new pending interrupts because we will check
	 * for them again.
	 */
#ifdef SMP
	TEST_CIL
	/* we enter with cpl locked */
	bsfl	%ecx, %ecx		/* slow, but not worth optimizing */
	btrl	%ecx, _ipending
	jnc	doreti_next2		/* some intr cleared memory copy */
	cmpl	$NHWI, %ecx
	jae	1f
	btsl	%ecx, _cil
1:	
	FAST_ICPL_UNLOCK		/* preserves %eax */
	sti				/* late to prevent INT deadlock */
#else
	sti
	bsfl	%ecx,%ecx		/* slow, but not worth optimizing */
	btrl	%ecx,_ipending
	jnc	doreti_next		/* some intr cleared memory copy */
#endif /* SMP */

	/*
	 * Set up JUMP to _ihandlers[%ecx] for HWIs.
	 * Set up CALL of _ihandlers[%ecx] for SWIs.
	 * This is a bit early for the SMP case - we have to push %ecx and
	 * %edx, but could push only %ecx and load %edx later.
	 */
	movl	_ihandlers(,%ecx,4),%edx
	cmpl	$NHWI,%ecx
	jae	doreti_swi
	cli
#ifdef SMP
	pushl	%edx			/* preserve %edx */
#ifdef APIC_INTR_DIAGNOSTIC
	pushl	%ecx
#endif
	pushl	%eax			/* preserve %eax */
	ICPL_LOCK
#ifdef CPL_AND_CML
	popl	_cml
#else
	popl	_cpl
#endif
	FAST_ICPL_UNLOCK
#ifdef APIC_INTR_DIAGNOSTIC
	popl	%ecx
#endif
	popl	%edx
#else
	movl	%eax,_cpl
#endif
	MEXITCOUNT
#ifdef APIC_INTR_DIAGNOSTIC
	lock
	incl	CNAME(apic_itrace_doreti)(,%ecx,4)
#ifdef APIC_INTR_DIAGNOSTIC_IRQ	
	cmpl	$APIC_INTR_DIAGNOSTIC_IRQ,%ecx
	jne	9f
	pushl	%eax
	pushl	%ecx
	pushl	%edx
	pushl	$APIC_ITRACE_DORETI
	call	log_intr_event
	addl	$4,%esp
	popl	%edx
	popl	%ecx
	popl	%eax
9:	
#endif
#endif
	jmp	%edx

	ALIGN_TEXT
doreti_swi:
#ifdef SMP
	TEST_CIL
#endif
	pushl	%eax
	/*
	 * The SWI_AST handler has to run at cpl = SWI_AST_MASK and the
	 * SWI_CLOCK handler at cpl = SWI_CLOCK_MASK, so we have to restore
	 * all the h/w bits in cpl now and have to worry about stack growth.
	 * The worst case is currently (30 Jan 1994) 2 SWI handlers nested
	 * in dying interrupt frames and about 12 HWIs nested in active
	 * interrupt frames.  There are only 4 different SWIs and the HWI
	 * and SWI masks limit the nesting further.
	 */
#ifdef SMP
	orl imasks(,%ecx,4), %eax
	pushl	%ecx			/* preserve for use by _swi_generic */
	pushl	%edx			/* save handler entry point */
	cli				/* prevent INT deadlock */
	pushl	%eax			/* save cpl|cml */
	ICPL_LOCK
#ifdef CPL_AND_CML
	popl	_cml			/* restore cml */
#else
	popl	_cpl			/* restore cpl */
#endif
	FAST_ICPL_UNLOCK
	sti
	popl	%edx			/* restore handler entry point */
	popl	%ecx
#else
	orl	imasks(,%ecx,4),%eax
	movl	%eax,_cpl
#endif
	call	%edx
	popl	%eax
	jmp	doreti_next

	ALIGN_TEXT
swi_ast:
	addl	$8,%esp			/* discard raddr & cpl to get trap frame */
#ifdef VM86
	cmpl	$1,_in_vm86call
	je	1f			/* stay in kernel mode */
#endif
	testb	$SEL_RPL_MASK,TRAPF_CS_OFF(%esp)
	je	swi_ast_phantom
swi_ast_user:
	movl	$T_ASTFLT,(2+8+0)*4(%esp)
	movb	$0,_intr_nesting_level	/* finish becoming a trap handler */
	call	_trap
	subl	%eax,%eax		/* recover cpl|cml */
#ifdef CPL_AND_CML
	movl	%eax, _cpl
#endif
	movb	$1,_intr_nesting_level	/* for doreti_next to decrement */
	jmp	doreti_next

	ALIGN_TEXT
swi_ast_phantom:
#ifdef VM86
	/*
	 * check for ast from vm86 mode.  Placed down here so the jumps do
	 * not get taken for mainline code.
	 */
	testl	$PSL_VM,TF_EFLAGS(%esp)
	jne	swi_ast_user
1:
#endif /* VM86 */
	/*
	 * These happen when there is an interrupt in a trap handler before
	 * ASTs can be masked or in an lcall handler before they can be
	 * masked or after they are unmasked.  They could be avoided for
	 * trap entries by using interrupt gates, and for lcall exits by
	 * using by using cli, but they are unavoidable for lcall entries.
	 */
	cli
	ICPL_LOCK
	orl $SWI_AST_PENDING, _ipending
	/* cpl is unlocked in doreti_exit */
	subl	%eax,%eax
#ifdef CPL_AND_CML
	movl	%eax, _cpl
#endif
	jmp	doreti_exit	/* SWI_AST is highest so we must be done */


	ALIGN_TEXT
swi_net:
	MCOUNT
	bsfl	_netisr,%eax
	je	swi_net_done
swi_net_more:
	btrl	%eax,_netisr
	jnc	swi_net_next
	call	*_netisrs(,%eax,4)
swi_net_next:
	bsfl	_netisr,%eax
	jne	swi_net_more
swi_net_done:
	ret

	ALIGN_TEXT
dummynetisr:
	MCOUNT
	ret	

/*
 * The arg is in a nonstandard place, so swi_dispatcher() can't be called
 * directly and swi_generic() can't use ENTRY() or MCOUNT.
 */
	ALIGN_TEXT
	.globl	_swi_generic
_swi_generic:
	pushl	%ecx
	FAKE_MCOUNT(4(%esp))
	call	_swi_dispatcher
	popl	%ecx
	ret

ENTRY(swi_null)
	ret

#ifdef APIC_IO
#include "i386/isa/apic_ipl.s"
#else
#include "i386/isa/icu_ipl.s"
#endif /* APIC_IO */
