/*-
 * Copyright (c) 1998 Doug Rabson
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
/*
 * Copyright (c) 1994, 1995, 1996 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Chris G. Demetriou
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

#include <machine/asm.h>
#include <machine/ia64_cpu.h>
#include <machine/fpu.h>
#include <machine/pte.h>
#include <sys/syscall.h>
#include <assym.s>

#ifndef EVCNT_COUNTERS
#define _LOCORE
#include <machine/intrcnt.h>
#endif

	.section .data.proc0,"aw"
	.global	kstack
	.align	PAGE_SIZE
kstack:	.space KSTACK_PAGES * PAGE_SIZE

	.text

/*
 * Not really a leaf but we can't return.
 * The EFI loader passes the physical address of the bootinfo block in
 * register r8.
 */
ENTRY(__start, 1)
	movl	r16=ia64_vector_table	// set up IVT early
	;;
	mov	cr.iva=r16
	movl	r16=ia64_vhpt+(1<<8)+(15<<2)+1	// and VHPT
	;;
	mov	cr.pta=r16
	movl	r16=kstack
	;;
	srlz.i
	;;
	mov	r17=KSTACK_PAGES*PAGE_SIZE-SIZEOF_PCB-SIZEOF_TRAPFRAME-16
	movl	gp=__gp			// find kernel globals
	;;
	add	sp=r16,r17		// proc0's stack
	mov	ar.rsc=0		// turn off rse
	;;
	mov	ar.bspstore=r16		// switch backing store
	movl	r16=pa_bootinfo
	;;
	st8	[r16]=r8		// save the PA of the bootinfo block
	loadrs				// invalidate regs
	;;
	mov	ar.rsc=3		// turn rse back on
	;;
	alloc	r16=ar.pfs,0,0,1,0
	;;
	movl	out0=0			// we are linked at the right address 
	;;				// we just need to process fptrs
	br.call.sptk.many rp=_reloc
	;;
	br.call.sptk.many rp=ia64_init

	/*
	 * switch to thread0 and then initialise the rest of the kernel.
	 */
	alloc	r16=ar.pfs,0,0,1,0
	;; 
	movl	out0=thread0
	;;
	add	out0=TD_PCB,out0
	;;
	ld8	out0=[out0]
	;; 
	add	r16=PCB_B0,out0		// return to mi_startup_trampoline
	movl	r17=mi_startup_trampoline
	;;
	st8	[r16]=r17
	;;
	br.call.sptk.many rp=restorectx

	/* NOTREACHED */	
	
END(__start)


ENTRY(mi_startup_trampoline, 0)
	.prologue
	.save	rp,r0
	.body
	
	br.call.sptk.many rp=mi_startup

	// Should never happen
1:	br.cond.sptk.few 1b

END(mi_startup_trampoline)

#ifdef SMP
/*
 * AP wake-up entry point. The handoff state is similar as for the BSP,
 * as described on page 3-9 of the IPF SAL Specification. The difference
 * lies in the contents of register b0. For APs this register holds the
 * return address into the SAL rendezvous routine.
 *
 * Note that we're responsible for clearing the IRR bit by reading cr.ivr
 * and issuing the EOI to the local SAPIC.
 */
	.align	32
ENTRY(os_boot_rendez,0)
	mov	r16=cr.ivr	// clear IRR bit
	;;
	srlz.d
	mov	cr.eoi=r0	// ACK the wake-up
	;;
	srlz.d
	rsm	IA64_PSR_IC|IA64_PSR_I
	;;
	mov	r16 = (5<<8)|(PAGE_SHIFT<<2)|1
	movl	r17 = 5<<61
	;;
	mov	rr[r17] = r16
	;;
	srlz.d
	mov	r16 = (6<<8)|(28<<2)
	movl	r17 = 6<<61
	;;
	mov	rr[r17] = r16
	;;
	srlz.d
	mov	r16 = (7<<8)|(28<<2)
	movl	r17 = 7<<61
	;;
	mov	rr[r17] = r16
	;;
	srlz.d
	mov	r16 = (PTE_P|PTE_MA_WB|PTE_A|PTE_D|PTE_PL_KERN|PTE_AR_RWX)
	mov	r18 = 28<<2
	;;

	mov	cr.ifa = r17
	mov	cr.itir = r18
	ptr.d	r17, r18
	ptr.i	r17, r18
	;;
	srlz.i
	;;
	itr.d	dtr[r0] = r16
	;;
	itr.i	itr[r0] = r16
	;;
	srlz.i
	;;
1:	mov	r16 = ip
	add	r17 = 2f-1b, r17
	movl	r18 = (IA64_PSR_AC|IA64_PSR_DT|IA64_PSR_RT|IA64_PSR_IT|IA64_PSR_BN)
	;;
	add	r17 = r17, r16
	mov	cr.ipsr = r18
	mov	cr.ifs = r0
	;;
	mov	cr.iip = r17
	;;
	rfi

	.align	32
2:	movl	r16 = ia64_vector_table			// set up IVT early
	;;
	mov	cr.iva = r16
	;;
	srlz.i
	;;
	movl	r16 = ap_stack
	movl	r17 = ap_pcpu
	mov	ar.rsc = 0
	movl	gp = __gp
	;;
	ld8	r16 = [r16]
	ld8	r17 = [r17]
	mov	r18 = KSTACK_PAGES*PAGE_SIZE-SIZEOF_PCB-SIZEOF_TRAPFRAME-16
	;;
	add	sp = r18, r16
	mov	ar.bspstore = r16
	mov	ar.k4 = r17
	mov	r13 = r17	/* gas doesn't know tp as an alias for r13 */
	;;
	loadrs
	movl	r16 = ia64_pal_base
	;;
	mov	ar.rsc = 3
	ld8	r16 = [r16]
	;;
	cmp.eq	p1, p0 = 0, r16
(p1)	br.cond.spnt	1f
	;;
	mov	r18 = 28<<2
	movl	r17 = 7<<61
	;;
	mov	cr.itir = r18
	or	r17 = r17, r16
	mov	r16 = (PTE_P|PTE_MA_WB|PTE_A|PTE_D|PTE_PL_KERN|PTE_AR_RWX)
	;;
	mov	cr.ifa = r17
	extr.u  r18 = r17, 12, 38
	;;
	srlz.i
	shl	r18 = r18, 12
	;;
	add	r17 = 1, r0
	or	r16 = r16, r18
	;;
	itr.i	itr[r17] = r16
	;;
	srlz.i
	;;
1:	alloc	r16 = ar.pfs, 0, 0, 0, 0
	;;
	br.call.sptk.few rp = ia64_ap_startup
	/* NOT REACHED */
9:	br	9b
END(os_boot_rendez)

#endif /* !SMP */

/**************************************************************************/

/*
 * Signal "trampoline" code. Invoked from RTE setup by sendsig().
 *
 * On entry, registers look like:
 *
 *      r14	signal number
 *      r15	pointer to siginfo_t
 *	r16	pointer to signal context frame (scp)
 *      r17	address of handler function descriptor
 *	r18	address of new backing store (if any)
 *      sp+16	pointer to sigframe
 */

ENTRY(sigcode,0)
	ld8	r8=[r17],8		// function address
	;;
	ld8	gp=[r17]		// function's gp value
	mov	b6=r8			// transfer to a branch register
	cover
	;;
	add	r8=UC_MCONTEXT_MC_AR_BSP,r16 // address or mc_ar_bsp
	mov	r9=ar.bsp		// save ar.bsp
	;;
	st8	[r8]=r9
	cmp.eq	p1,p2=r0,r18		// check for new bs
(p1)	br.cond.sptk.few 1f		// branch if not switching
	flushrs				// flush out to old bs
	mov	ar.rsc=0		// switch off RSE
	add	r8=UC_MCONTEXT_MC_AR_RNAT,r16 // address of mc_ar_rnat
	;;
	mov	r9=ar.rnat		// value of ar.rnat after flush
	mov	ar.bspstore=r18		// point at new bs
	;;
	st8	[r8]=r9			// remember ar.rnat
	mov	ar.rsc=15		// XXX bogus value - check
	invala
	;; 
1:	alloc	r5=ar.pfs,0,0,3,0	// register frame for call
	;;
	mov	out0=r14		// signal number
	mov	out1=r15		// siginfo
	mov	out2=r16		// ucontext
	mov	r4=r16			// save from call
	br.call.sptk.few rp=b6		// call the signal handler
	;; 
	alloc	r14=ar.pfs,0,0,0,0	// discard call frame
	;; 
	flushrs
	;; 
(p1)	br.cond.sptk.few 2f		// note: p1 is preserved
	mov	ar.rsc=0
	add	r8=UC_MCONTEXT_MC_AR_RNAT,r4 // address of mc_ar_rnat
	;;
	ld8	r9=[r8]
	;; 
	add	r8=UC_MCONTEXT_MC_AR_BSP,r4 // address of mc_ar_bsp
	;;
	ld8	r10=[r8]
	;;
	mov	ar.bspstore=r10
	;;
	mov	ar.rnat=r9
	mov	ar.rsc=15
	;; 
2:	CALLSYS_NOERROR(sigreturn)	// call sigreturn()
	alloc	r14=ar.pfs,0,0,1,0 ;;
	mov	out0=ret0		// if that failed, get error code
	CALLSYS_NOERROR(exit)		// and call exit() with it.
XENTRY(esigcode)
	END(sigcode)

	.data
	EXPORT(szsigcode)
	.quad	esigcode-sigcode
	.text
	
/* XXX: make systat/vmstat happy */
	.data
EXPORT(intrnames)
	.asciz	"clock"
intr_n = 0
.rept INTRCNT_COUNT
	.ascii "intr "
	.byte intr_n / 10 + '0, intr_n % 10 + '0
	.asciz "     "		/* space for platform-specific rewrite */
	intr_n = intr_n + 1
.endr
EXPORT(eintrnames)
	.align 8
EXPORT(intrcnt)
	.fill INTRCNT_COUNT + 1, 8, 0
EXPORT(eintrcnt)
	.text
	
	// in0:	image base
STATIC_ENTRY(_reloc, 1)
	alloc	loc0=ar.pfs,1,2,0,0
	mov	loc1=rp
	;; 
	movl	r15=@gprel(_DYNAMIC)	// find _DYNAMIC etc.
	movl	r2=@gprel(fptr_storage)
	movl	r3=@gprel(fptr_storage_end)
	;;
	add	r15=r15,gp		// relocate _DYNAMIC etc.
	add	r2=r2,gp
	add	r3=r3,gp
	;;
1:	ld8	r16=[r15],8		// read r15->d_tag
	;;
	ld8	r17=[r15],8		// and r15->d_val
	;;
	cmp.eq	p6,p0=DT_NULL,r16	// done?
(p6)	br.cond.dpnt.few 2f
	;; 
	cmp.eq	p6,p0=DT_RELA,r16
	;; 
(p6)	add	r18=r17,in0		// found rela section
	;; 
	cmp.eq	p6,p0=DT_RELASZ,r16
	;; 
(p6)	mov	r19=r17			// found rela size
	;; 
	cmp.eq	p6,p0=DT_SYMTAB,r16
	;; 
(p6)	add	r20=r17,in0		// found symbol table
	;; 
(p6)	setf.sig f8=r20
	;; 
	cmp.eq	p6,p0=DT_SYMENT,r16
	;; 
(p6)	setf.sig f9=r17			// found symbol entry size
	;; 
	cmp.eq	p6,p0=DT_RELAENT,r16
	;; 
(p6)	mov	r22=r17			// found rela entry size
	;;
	br.sptk.few 1b
	
2:	
	ld8	r15=[r18],8		// read r_offset
	;; 
	ld8	r16=[r18],8		// read r_info
	add	r15=r15,in0		// relocate r_offset
	;;
	ld8	r17=[r18],8		// read r_addend
	sub	r19=r19,r22		// update relasz

	extr.u	r23=r16,0,32		// ELF64_R_TYPE(r16)
	;;
	cmp.eq	p6,p0=R_IA64_NONE,r23
(p6)	br.cond.dpnt.few 3f
	;;
	cmp.eq	p6,p0=R_IA64_REL64LSB,r23
(p6)	br.cond.dptk.few 4f
	;;

	extr.u	r16=r16,32,32		// ELF64_R_SYM(r16)
	;; 
	setf.sig f10=r16		// so we can multiply
	;;
	xma.lu	f10=f10,f9,f8		// f10=symtab + r_sym*syment
	;;
	getf.sig r16=f10
	;;
	add	r16=8,r16		// address of st_value
	;;
	ld8	r16=[r16]		// read symbol value
	;;
	add	r16=r16,in0		// relocate symbol value
	;;

	cmp.eq	p6,p0=R_IA64_DIR64LSB,r23
(p6)	br.cond.dptk.few 5f
	;;
	cmp.eq	p6,p0=R_IA64_FPTR64LSB,r23
(p6)	br.cond.dptk.few 6f
	;;

3:
	cmp.ltu	p6,p0=0,r19		// more?
(p6)	br.cond.dptk.few 2b		// loop
	mov	r8=0			// success return value
	br.cond.sptk.few 9f		// done

4:
	add	r16=in0,r17		// BD + A
	;;
	st8	[r15]=r16		// word64 (LSB)
	br.cond.sptk.few 3b

5:
	add	r16=r16,r17		// S + A
	;;
	st8	[r15]=r16		// word64 (LSB)
	br.cond.sptk.few 3b

6:
	movl	r17=@gprel(fptr_storage)
	;;
	add	r17=r17,gp		// start of fptrs
	;;
7:	cmp.geu	p6,p0=r17,r2		// end of fptrs?
(p6)	br.cond.dpnt.few 8f		// can't find existing fptr
	ld8	r20=[r17]		// read function from fptr
	;;
	cmp.eq	p6,p0=r16,r20		// same function?
	;;
(p6)	st8	[r15]=r17		// reuse fptr
(p6)	br.cond.sptk.few 3b		// done
	add	r17=16,r17		// next fptr
	br.cond.sptk.few 7b

8:					// allocate new fptr
	mov	r8=1			// failure return value
	cmp.geu	p6,p0=r2,r3		// space left?
(p6)	br.cond.dpnt.few 9f		// bail out

	st8	[r15]=r2		// install fptr
	st8	[r2]=r16,8		// write fptr address
	;;
	st8	[r2]=gp,8		// write fptr gp
	br.cond.sptk.few 3b

9:
	mov	ar.pfs=loc0
	mov	rp=loc1
	;;
	br.ret.sptk.few rp

END(_reloc)

	.data
	.align	16
	.global fptr_storage
fptr_storage:
	.space	4096*16			// XXX
fptr_storage_end:
