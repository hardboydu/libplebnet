/*
 * Copyright (c) 1996, by Steve Passe
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
 * $FreeBSD$
 */

#ifndef _MACHINE_SMPTESTS_H_
#define _MACHINE_SMPTESTS_H_


/*
 * Various 'tests in progress' and configuration parameters.
 */


/*
 * Tor's clock improvements.
 *
 *  When the giant kernel lock disappears, a different strategy should
 *  probably be used, thus this patch can only be considered a temporary
 *  measure.
 *
 *  This patch causes (NCPU-1)*(128+100) extra IPIs per second.
 *  During profiling, the number is (NCPU-1)*(1024+100) extra IPIs/s
 *  in addition to extra IPIs due to forwarding ASTs to other CPUs.
 *
 *  Having a shared AST flag in an SMP configuration is wrong, and I've
 *  just kludged around it, based upon the kernel lock blocking other
 *  processors from entering the kernel while handling an AST for one
 *  processor. When the giant kernel lock disappers, this kludge breaks.
 *
 *  -- Tor
 */
#define BETTER_CLOCK


/*
 * Control the "giant lock" pushdown by logical steps.
 */
#define PUSHDOWN_LEVEL_1
#define PUSHDOWN_LEVEL_2

/*
 * Debug version of simple_lock.  This will store the CPU id of the
 * holding CPU along with the lock.  When a CPU fails to get the lock
 * it compares its own id to the holder id.  If they are the same it
 * panic()s, as simple locks are binary, and this would cause a deadlock.
 *
 */
#define SL_DEBUG


/*
 * Put FAST_INTR() ISRs at an APIC priority above the regular INTs.
 * Allow the mp_lock() routines to handle FAST interrupts while spinning.
 */
#ifdef PUSHDOWN_LEVEL_1
#define FAST_HI
#endif


/*
 * These defines enable critical region locking of areas that were
 * protected via cli/sti in the UP kernel.
 *
 * COMLOCK protects the sio/cy drivers.
 * known to be incomplete:
 *	joystick lkm
 *	?
 */
#ifdef PUSHDOWN_LEVEL_1
#define USE_COMLOCK
#endif


/*
 * Portions of the old TEST_LOPRIO code, back from the grave!
 */
#define GRAB_LOPRIO


/*
 * Send CPUSTOP IPI for stop/restart of other CPUs on DDB break.
 */
#define VERBOSE_CPUSTOP_ON_DDBBREAK
#define CPUSTOP_ON_DDBBREAK


/*
 * Bracket code/comments relevant to the current 'giant lock' model.
 * Everything is now the 'giant lock' model, but we will use this as
 * we start to "push down" the lock.
 */
#define GIANT_LOCK

#ifdef APIC_IO
/*
 * Don't assume that slow interrupt handler X is called from vector
 * X + ICU_OFFSET.
 */
#define APIC_INTR_REORDER

/*
 * Redirect clock interrupts to a higher priority (fast intr) vector,
 * while still using the slow interrupt handler. Only effective when 
 * APIC_INTR_REORDER is defined.
 */
#define APIC_INTR_HIGHPRI_CLOCK

#endif /* APIC_IO */

/*
 * Misc. counters.
 *
#define COUNT_XINVLTLB_HITS
 */


/**
 * Hack to "fake-out" kernel into thinking it is running on a 'default config'.
 *
 * value == default type
#define TEST_DEFAULT_CONFIG	6
 */


/*
 * Simple test code for IPI interaction, save for future...
 *
#define TEST_TEST1
#define IPI_TARGET_TEST1	1
 */


/*
 * Address of POST hardware port.
 * Defining this enables POSTCODE macros.
 *
#define POST_ADDR		0x80
 */


/*
 * POST hardware macros.
 */
#ifdef POST_ADDR
#define ASMPOSTCODE_INC				\
	pushl	%eax ;				\
	movl	_current_postcode, %eax ;	\
	incl	%eax ;				\
	andl	$0xff, %eax ;			\
	movl	%eax, _current_postcode ;	\
	outb	%al, $POST_ADDR ;		\
	popl	%eax

/*
 * Overwrite the current_postcode value.
 */
#define ASMPOSTCODE(X)				\
	pushl	%eax ;				\
	movl	$X, %eax ;			\
	movl	%eax, _current_postcode ;	\
	outb	%al, $POST_ADDR ;		\
	popl	%eax

/*
 * Overwrite the current_postcode low nibble.
 */
#define ASMPOSTCODE_LO(X)			\
	pushl	%eax ;				\
	movl	_current_postcode, %eax ;	\
	andl	$0xf0, %eax ;			\
	orl	$X, %eax ;			\
	movl	%eax, _current_postcode ;	\
	outb	%al, $POST_ADDR ;		\
	popl	%eax

/*
 * Overwrite the current_postcode high nibble.
 */
#define ASMPOSTCODE_HI(X)			\
	pushl	%eax ;				\
	movl	_current_postcode, %eax ;	\
	andl	$0x0f, %eax ;			\
	orl	$(X<<4), %eax ;			\
	movl	%eax, _current_postcode ;	\
	outb	%al, $POST_ADDR ;		\
	popl	%eax
#else
#define ASMPOSTCODE_INC
#define ASMPOSTCODE(X)
#define ASMPOSTCODE_LO(X)
#define ASMPOSTCODE_HI(X)
#endif /* POST_ADDR */


#endif /* _MACHINE_SMPTESTS_H_ */
