/*
 * Copyright (c) 1997, by Steve Passe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the developer may NOT be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 *	$Id: lock.h,v 1.2 1997/08/30 07:51:10 smp Exp smp $
 */


#ifndef _MACHINE_LOCK_H_
#define _MACHINE_LOCK_H_

/*
 * XXX some temp debug control of cpl locks
 */
#define REAL_ECPL	/* exception.s:		SCPL_LOCK/SCPL_UNLOCK */
#define REAL_ICPL	/* ipl.s:		CPL_LOCK/CPL_UNLOCK/FAST */
#define REAL_AICPL	/* apic_ipl.s:		SCPL_LOCK/SCPL_UNLOCK */
#define REAL_AVCPL	/* apic_vector.s:	CPL_LOCK/CPL_UNLOCK */

#define REAL_IFCPL	/* ipl_funcs.c:		SCPL_LOCK/SCPL_UNLOCK */

#define REAL_MCPL_NOT	/* microtime.s:		CPL_LOCK/movl $0,_cpl_lock */


#ifdef LOCORE

#ifdef SMP

#define	MPLOCKED	lock ;

/*
 * Some handy macros to allow logical organization and
 * convenient reassignment of various locks.
 */

#define FPU_LOCK	call	_get_fpu_lock
#define ALIGN_LOCK	call	_get_align_lock
#define SYSCALL_LOCK	call	_get_syscall_lock
#define ALTSYSCALL_LOCK	call	_get_altsyscall_lock

/*
 * Protects INTR() ISRs.
 */
#define ISR_TRYLOCK							\
	pushl	$_mp_lock ;			/* GIANT_LOCK */	\
	call	_MPtrylock ;			/* try to get lock */	\
	add	$4, %esp

#define ISR_RELLOCK							\
	pushl	$_mp_lock ;			/* GIANT_LOCK */	\
	call	_MPrellock ;						\
	add	$4, %esp

/*
 * Protects the IO APIC and apic_imen as a critical region.
 */
#define IMASK_LOCK							\
	pushl	$_imen_lock ;			/* address of lock */	\
	call	_s_lock ;			/* MP-safe */		\
	addl	$4, %esp

#define IMASK_UNLOCK							\
	pushl	$_imen_lock ;			/* address of lock */	\
	call	_s_unlock ;			/* MP-safe */		\
	addl	$4, %esp

/*
 * Variations of CPL_LOCK protect spl updates as a critical region.
 * Items within this 'region' include:
 *  cpl
 *  cil
 *  ipending
 *  ???
 */

/*
 * Botom half routines, ie. those already protected from INTs.
 *
 * Used in:
 *  sys/i386/i386/microtime.s (XXX currently NOT used, possible race?)
 *  sys/i386/isa/ipl.s:		_doreti
 *  sys/i386/isa/apic_vector.s:	_Xintr0, ..., _Xintr23
 */
#define CPL_LOCK							\
	pushl	$_cpl_lock ;			/* address of lock */	\
	call	_s_lock ;			/* MP-safe */		\
	addl	$4, %esp

#define CPL_UNLOCK							\
	pushl	$_cpl_lock ;			/* address of lock */	\
	call	_s_unlock ;			/* MP-safe */		\
	addl	$4, %esp

/*
 * INT safe version for top half of kernel.
 *
 * Used in:
 *  sys/i386/i386/exception.s:	_Xfpu, _Xalign, _Xsyscall, _Xint0x80_syscall
 *  sys/i386/isa/apic_ipl.s:	splz()
 */
#define SCPL_LOCK 							\
	pushl	$_cpl_lock ;						\
	call	_ss_lock ;						\
	addl	$4, %esp

#define SCPL_UNLOCK							\
	pushl	$_cpl_lock ;						\
	call	_ss_unlock ;						\
	addl	$4, %esp

#else  /* SMP */

#define	MPLOCKED				/* NOP */

#define FPU_LOCK				/* NOP */
#define ALIGN_LOCK				/* NOP */
#define SYSCALL_LOCK				/* NOP */
#define ALTSYSCALL_LOCK				/* NOP */

#endif /* SMP */

#else /* LOCORE */

#ifdef SMP

#include <machine/smptests.h>			/** XXX_MPINTR_LOCK */

/*
 * Protects cpl/cml/cil/ipending data as a critical region.
 *
 * Used in:
 *  sys/i386/isa/ipl_funcs.c:	DO_SETBITS, softclockpending(), GENSPL,
 *				spl0(), splx(), splq()
 */

/* Bottom half */
#define CPL_LOCK() 	s_lock(&cpl_lock)
#define CPL_UNLOCK() 	s_unlock(&cpl_lock)

/* INT safe version for top half of kernel */
#define SCPL_LOCK() 	ss_lock(&cpl_lock)
#define SCPL_UNLOCK() 	ss_unlock(&cpl_lock)

/* lock regions protected in UP kernel via cli/sti */
#if defined(SIMPLE_MPINTRLOCK)
#define MPINTR_LOCK() 	s_lock(&mpintr_lock)
#define MPINTR_UNLOCK() s_unlock(&mpintr_lock)
#elif defined(RECURSIVE_MPINTRLOCK)
#define MPINTR_LOCK() 	get_mpintrlock()
#define MPINTR_UNLOCK() rel_mpintrlock();
#else
#error whats up doc?
#endif /* _MPINTRLOCK */

#else /* SMP */

#define CPL_LOCK()
#define CPL_UNLOCK()
#define SCPL_LOCK()
#define SCPL_UNLOCK()
#define MPINTR_LOCK() 	
#define MPINTR_UNLOCK() 

#endif /* SMP */

/*
 * Simple spin lock.
 * It is an error to hold one of these locks while a process is sleeping.
 */
struct simplelock {
	volatile int	lock_data;
};

/* functions in simplelock.s */
void	s_lock_init		__P((struct simplelock *));
void	s_lock			__P((struct simplelock *));
int	s_lock_try		__P((struct simplelock *));
void	s_unlock		__P((struct simplelock *));
void	ss_lock			__P((struct simplelock *));
void	ss_unlock		__P((struct simplelock *));

/* global data in mp_machdep.c */
extern struct simplelock	imen_lock;
extern struct simplelock	cpl_lock;
extern struct simplelock	fast_intr_lock;
extern struct simplelock	intr_lock;

#ifdef SIMPLE_MPINTRLOCK
extern struct simplelock	mpintr_lock;
extern struct simplelock	clock_lock;
#endif/* SIMPLE_MPINTRLOCK */

#if !defined(SIMPLELOCK_DEBUG) && NCPUS > 1
/*
 * This set of defines turns on the real functions in i386/isa/apic_ipl.s.
 */
#define	simple_lock_init(alp)	s_lock_init(alp)
#define	simple_lock(alp)	s_lock(alp)
#define	simple_lock_try(alp)	s_lock_try(alp)
#define	simple_unlock(alp)	s_unlock(alp)

#endif /* !SIMPLELOCK_DEBUG && NCPUS > 1 */

#endif /* LOCORE */

#endif /* !_MACHINE_LOCK_H_ */
