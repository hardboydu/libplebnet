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
 *	from BSDI: locore.s,v 1.36.2.15 1999/08/23 22:34:41 cp Exp
 */
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

#include "opt_ddb.h"

#include <machine/asi.h>
#include <machine/asmacros.h>
#include <machine/ktr.h>
#include <machine/pstate.h>
#include <machine/trap.h>
#include <machine/tstate.h>
#include <machine/wstate.h>

#include "assym.s"

	.register %g2,#ignore
	.register %g3,#ignore
	.register %g6,#ignore
	.register %g7,#ignore

/*
 * Atomically set the reference bit in a tte.
 */
#define	TTE_SET_BIT(r1, r2, r3, bit) \
	add	r1, TTE_DATA, r1 ; \
	ldx	[r1], r2 ; \
9:	or	r2, bit, r3 ; \
	casxa	[r1] ASI_N, r2, r3 ; \
	cmp	r2, r3 ; \
	bne,pn	%xcc, 9b ; \
	 mov	r3, r2

#define	TTE_SET_REF(r1, r2, r3)		TTE_SET_BIT(r1, r2, r3, TD_REF)
#define	TTE_SET_W(r1, r2, r3)		TTE_SET_BIT(r1, r2, r3, TD_W)

/*
 * Macros for spilling and filling live windows.
 *
 * NOTE: These macros use exactly 16 instructions, and it is assumed that the
 * handler will not use more than 24 instructions total, to leave room for
 * resume vectors which occupy the last 8 instructions.
 */

#define	SPILL(storer, base, size, asi) \
	storer	%l0, [base + (0 * size)] asi ; \
	storer	%l1, [base + (1 * size)] asi ; \
	storer	%l2, [base + (2 * size)] asi ; \
	storer	%l3, [base + (3 * size)] asi ; \
	storer	%l4, [base + (4 * size)] asi ; \
	storer	%l5, [base + (5 * size)] asi ; \
	storer	%l6, [base + (6 * size)] asi ; \
	storer	%l7, [base + (7 * size)] asi ; \
	storer	%i0, [base + (8 * size)] asi ; \
	storer	%i1, [base + (9 * size)] asi ; \
	storer	%i2, [base + (10 * size)] asi ; \
	storer	%i3, [base + (11 * size)] asi ; \
	storer	%i4, [base + (12 * size)] asi ; \
	storer	%i5, [base + (13 * size)] asi ; \
	storer	%i6, [base + (14 * size)] asi ; \
	storer	%i7, [base + (15 * size)] asi

#define	FILL(loader, base, size, asi) \
	loader	[base + (0 * size)] asi, %l0 ; \
	loader	[base + (1 * size)] asi, %l1 ; \
	loader	[base + (2 * size)] asi, %l2 ; \
	loader	[base + (3 * size)] asi, %l3 ; \
	loader	[base + (4 * size)] asi, %l4 ; \
	loader	[base + (5 * size)] asi, %l5 ; \
	loader	[base + (6 * size)] asi, %l6 ; \
	loader	[base + (7 * size)] asi, %l7 ; \
	loader	[base + (8 * size)] asi, %i0 ; \
	loader	[base + (9 * size)] asi, %i1 ; \
	loader	[base + (10 * size)] asi, %i2 ; \
	loader	[base + (11 * size)] asi, %i3 ; \
	loader	[base + (12 * size)] asi, %i4 ; \
	loader	[base + (13 * size)] asi, %i5 ; \
	loader	[base + (14 * size)] asi, %i6 ; \
	loader	[base + (15 * size)] asi, %i7

#define	ERRATUM50(reg)	mov reg, reg

#define	KSTACK_SLOP	1024

/*
 * Sanity check the kernel stack and bail out if its wrong.
 * XXX: doesn't handle being on the panic stack.
 */
#define	KSTACK_CHECK \
	dec	16, ASP_REG ; \
	stx	%g1, [ASP_REG + 0] ; \
	stx	%g2, [ASP_REG + 8] ; \
	add	%sp, SPOFF, %g1 ; \
	andcc	%g1, (1 << PTR_SHIFT) - 1, %g0 ; \
	bnz,a	%xcc, tl1_kstack_fault ; \
	 inc	16, ASP_REG ; \
	ldx	[PCPU(CURTHREAD)], %g2 ; \
	ldx	[%g2 + TD_KSTACK], %g2 ; \
	add	%g2, KSTACK_SLOP, %g2 ; \
	subcc	%g1, %g2, %g1 ; \
	ble,a	%xcc, tl1_kstack_fault ; \
	 inc	16, ASP_REG ; \
	set	KSTACK_PAGES * PAGE_SIZE, %g2 ; \
	cmp	%g1, %g2 ; \
	bgt,a	%xcc, tl1_kstack_fault ; \
	 inc	16, ASP_REG ; \
	ldx	[ASP_REG + 8], %g2 ; \
	ldx	[ASP_REG + 0], %g1 ; \
	inc	16, ASP_REG

ENTRY(tl1_kstack_fault)
	rdpr	%tl, %g1
1:	cmp	%g1, 2
	be,a	2f
	 nop

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl1_kstack_fault: tl=%#lx tpc=%#lx tnpc=%#lx"
	    , %g2, %g3, %g4, 7, 8, 9)
	rdpr	%tl, %g3
	stx	%g3, [%g2 + KTR_PARM1]
	rdpr	%tpc, %g3
	stx	%g3, [%g2 + KTR_PARM1]
	rdpr	%tnpc, %g3
	stx	%g3, [%g2 + KTR_PARM1]
9:
#endif

	sub	%g1, 1, %g1
	wrpr	%g1, 0, %tl
	ba,a	%xcc, 1b
	 nop

2:
#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP,
	    "tl1_kstack_fault: sp=%#lx ks=%#lx cr=%#lx cs=%#lx ow=%#lx ws=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	add	%sp, SPOFF, %g2
	stx	%g2, [%g1 + KTR_PARM1]
	ldx	[PCPU(CURTHREAD)], %g2
	ldx	[%g2 + TD_KSTACK], %g2
	stx	%g2, [%g1 + KTR_PARM2]
	rdpr	%canrestore, %g2
	stx	%g2, [%g1 + KTR_PARM3]
	rdpr	%cansave, %g2
	stx	%g2, [%g1 + KTR_PARM4]
	rdpr	%otherwin, %g2
	stx	%g2, [%g1 + KTR_PARM5]
	rdpr	%wstate, %g2
	stx	%g2, [%g1 + KTR_PARM6]
9:
#endif

	wrpr	%g0, 0, %canrestore
	wrpr	%g0, 6, %cansave
	wrpr	%g0, 0, %otherwin
	wrpr	%g0, WSTATE_KERNEL, %wstate

	sub	ASP_REG, SPOFF + CCFSZ, %sp
	clr	%fp

	b	%xcc, tl1_trap
	 mov	T_KSTACK_FAULT | T_KERNEL, %o0
END(tl1_kstack_fault)

/*
 * Magic to resume from a spill or fill trap.  If we get an alignment or an
 * mmu fault during a spill or a fill, this macro will detect the fault and
 * resume at a set instruction offset in the trap handler.
 *
 * To check if the previous trap was a spill/fill we convert the trapped pc
 * to a trap type and verify that it is in the range of spill/fill vectors.
 * The spill/fill vectors are types 0x80-0xff and 0x280-0x2ff, masking off the
 * tl bit allows us to detect both ranges with one test.
 *
 * This is:
 *	0x80 <= (((%tpc - %tba) >> 5) & ~0x200) < 0x100
 *
 * To calculate the new pc we take advantage of the xor feature of wrpr.
 * Forcing all the low bits of the trapped pc on we can produce any offset
 * into the spill/fill vector.  The size of a spill/fill trap vector is 0x80.
 *
 *	0x7f ^ 0x1f == 0x60
 *	0x1f == (0x80 - 0x60) - 1
 *
 * Which are the offset and xor value used to resume from alignment faults.
 */

/*
 * Determine if we have trapped inside of a spill/fill vector, and if so resume
 * at a fixed instruction offset in the trap vector.  Must be called on
 * alternate globals.
 */
#define	RESUME_SPILLFILL_MAGIC(stxa_g0_sfsr, xor) \
	dec	16, ASP_REG ; \
	stx	%g1, [ASP_REG + 0] ; \
	stx	%g2, [ASP_REG + 8] ; \
	rdpr	%tpc, %g1 ; \
	ERRATUM50(%g1) ; \
	rdpr	%tba, %g2 ; \
	sub	%g1, %g2, %g2 ; \
	srlx	%g2, 5, %g2 ; \
	andn	%g2, 0x200, %g2 ; \
	cmp	%g2, 0x80 ; \
	blu,pt	%xcc, 9f ; \
	 cmp	%g2, 0x100 ; \
	bgeu,pt	%xcc, 9f ; \
	 or	%g1, 0x7f, %g1 ; \
	wrpr	%g1, xor, %tnpc ; \
	stxa_g0_sfsr ; \
	ldx	[ASP_REG + 8], %g2 ; \
	ldx	[ASP_REG + 0], %g1 ; \
	inc	16, ASP_REG ; \
	done ; \
9:	ldx	[ASP_REG + 8], %g2 ; \
	ldx	[ASP_REG + 0], %g1 ; \
	inc	16, ASP_REG

/*
 * For certain faults we need to clear the sfsr mmu register before returning.
 */
#define	RSF_CLR_SFSR \
	wr	%g0, ASI_DMMU, %asi ; \
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi

#define	RSF_XOR(off)	((0x80 - off) - 1)

/*
 * Instruction offsets in spill and fill trap handlers for handling certain
 * nested traps, and corresponding xor constants for wrpr.
 */
#define	RSF_OFF_ALIGN	0x60
#define	RSF_OFF_MMU	0x70

#define	RESUME_SPILLFILL_ALIGN \
	RESUME_SPILLFILL_MAGIC(RSF_CLR_SFSR, RSF_XOR(RSF_OFF_ALIGN))
#define	RESUME_SPILLFILL_MMU \
	RESUME_SPILLFILL_MAGIC(EMPTY, RSF_XOR(RSF_OFF_MMU))
#define	RESUME_SPILLFILL_MMU_CLR_SFSR \
	RESUME_SPILLFILL_MAGIC(RSF_CLR_SFSR, RSF_XOR(RSF_OFF_MMU))

/*
 * Constant to add to %tnpc when taking a fill trap just before returning to
 * user mode.
 */
#define	RSF_FILL_INC	tl0_ret_fill_end - tl0_ret_fill

/*
 * Retry a spill or fill with a different wstate due to an alignment fault.
 * We may just be using the wrong stack offset.
 */
#define	RSF_ALIGN_RETRY(ws) \
	wrpr	%g0, (ws), %wstate ; \
	retry ; \
	.align	16

/*
 * Generate a T_SPILL or T_FILL trap if the window operation fails.
 */
#define	RSF_TRAP(type) \
	b	%xcc, tl0_sftrap ; \
	 mov	type, %g2 ; \
	.align	16

/*
 * Game over if the window operation fails.
 */
#define	RSF_FATAL(type) \
	b	%xcc, rsf_fatal ; \
	 mov	type, %g2 ; \
	.align	16

/*
 * Magic to resume from a failed fill a few instructions after the corrsponding
 * restore.  This is used on return from the kernel to usermode.
 */
#define	RSF_FILL_MAGIC \
	rdpr	%tnpc, %g1 ; \
	add	%g1, RSF_FILL_INC, %g1 ; \
	wrpr	%g1, 0, %tnpc ; \
	done ; \
	.align	16

/*
 * Spill to the pcb if a spill to the user stack in kernel mode fails.
 */
#define	RSF_SPILL_TOPCB \
	b,a	%xcc, tl1_spill_topcb ; \
	 nop ; \
	.align	16

ENTRY(rsf_fatal)
#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "rsf_fatal: bad window trap tt=%#lx type=%#lx"
	    , %g1, %g3, %g4, 7, 8, 9)
	rdpr	%tt, %g3
	stx	%g3, [%g1 + KTR_PARM1]
	stx	%g2, [%g1 + KTR_PARM2]
9:
#endif

	KSTACK_CHECK

	sir
END(rsf_fatal)

	.comm	intrnames, IV_MAX * 8
	.comm	eintrnames, 0

	.comm	intrcnt, IV_MAX * 8
	.comm	eintrcnt, 0

/*
 * Trap table and associated macros
 *
 * Due to its size a trap table is an inherently hard thing to represent in
 * code in a clean way.  There are approximately 1024 vectors, of 8 or 32
 * instructions each, many of which are identical.  The way that this is
 * layed out is the instructions (8 or 32) for the actual trap vector appear
 * as an AS macro.  In general this code branches to tl0_trap or tl1_trap,
 * but if not supporting code can be placed just after the definition of the
 * macro.  The macros are then instantiated in a different section (.trap),
 * which is setup to be placed by the linker at the beginning of .text, and the
 * code around the macros is moved to the end of trap table.  In this way the
 * code that must be sequential in memory can be split up, and located near
 * its supporting code so that it is easier to follow.
 */

	/*
	 * Clean window traps occur when %cleanwin is zero to ensure that data
	 * is not leaked between address spaces in registers.
	 */
	.macro	clean_window
	clr	%o0
	clr	%o1
	clr	%o2
	clr	%o3
	clr	%o4
	clr	%o5
	clr	%o6
	clr	%o7
	clr	%l0
	clr	%l1
	clr	%l2
	clr	%l3
	clr	%l4
	clr	%l5
	clr	%l6
	rdpr	%cleanwin, %l7
	inc	%l7
	wrpr	%l7, 0, %cleanwin
	clr	%l7
	retry
	.align	128
	.endm

	/*
	 * Stack fixups for entry from user mode.  We are still running on the
	 * user stack, and with its live registers, so we must save soon.  We
	 * are on alternate globals so we do have some registers.  Set the
	 * transitional window state, and do the save.  If this traps we
	 * we attempt to spill a window to the user stack.  If this fails,
	 * we spill the window to the pcb and continue.  Spilling to the pcb
	 * must not fail.
	 *
	 * NOTE: Must be called with alternate globals and clobbers %g1.
	 */

	.macro	tl0_split
	rdpr	%wstate, %g1
	wrpr	%g1, WSTATE_TRANSITION, %wstate
	save
	.endm

	.macro	tl0_setup	type
	tl0_split
	b	%xcc, tl0_trap
	 mov	\type, %o0
	.endm

	/*
	 * Generic trap type.  Call trap() with the specified type.
	 */
	.macro	tl0_gen		type
	tl0_setup \type
	.align	32
	.endm

	/*
	 * This is used to suck up the massive swaths of reserved trap types.
	 * Generates count "reserved" trap vectors.
	 */
	.macro	tl0_reserved	count
	.rept	\count
	tl0_gen	T_RESERVED
	.endr
	.endm

	.macro	tl0_fp_restore
	wr	%g0, FPRS_FEF, %fprs
	wr	%g0, ASI_BLK_S, %asi
	ldda	[PCB_REG + PCB_FPSTATE + FP_FB0] %asi, %f0
	ldda	[PCB_REG + PCB_FPSTATE + FP_FB1] %asi, %f16
	ldda	[PCB_REG + PCB_FPSTATE + FP_FB2] %asi, %f32
	ldda	[PCB_REG + PCB_FPSTATE + FP_FB3] %asi, %f48
	membar	#Sync
	done
	.align	32
	.endm

	.macro	tl0_insn_excptn
	wr	%g0, ASI_IMMU, %asi
	rdpr	%tpc, %g3
	ldxa	[%g0 + AA_IMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_IMMU_SFSR] %asi
	membar	#Sync
	b	%xcc, tl0_sfsr_trap
	 mov	T_INSTRUCTION_EXCEPTION, %g2
	.align	32
	.endm

	.macro	tl0_data_excptn
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync
	b	%xcc, tl0_sfsr_trap
	 mov	T_DATA_EXCEPTION, %g2
	.align	32
	.endm

	.macro	tl0_align
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync
	b	%xcc, tl0_sfsr_trap
	 mov	T_MEM_ADDRESS_NOT_ALIGNED, %g2
	.align	32
	.endm

ENTRY(tl0_sfsr_trap)
	tl0_split
	mov	%g3, %o4
	mov	%g4, %o5
	b	%xcc, tl0_trap
	 mov	%g2, %o0
END(tl0_sfsr_trap)

	.macro	tl0_intr level, mask
	tl0_split
	set	\mask, %o1
	b	%xcc, tl0_intr
	 mov	\level, %o0
	.align	32
	.endm

#define	INTR(level, traplvl)						\
	tl ## traplvl ## _intr	level, 1 << level

#define	TICK(traplvl) \
	tl ## traplvl ## _intr	PIL_TICK, 1

#define	INTR_LEVEL(tl)							\
	INTR(1, tl) ;							\
	INTR(2, tl) ;							\
	INTR(3, tl) ;							\
	INTR(4, tl) ;							\
	INTR(5, tl) ;							\
	INTR(6, tl) ;							\
	INTR(7, tl) ;							\
	INTR(8, tl) ;							\
	INTR(9, tl) ;							\
	INTR(10, tl) ;							\
	INTR(11, tl) ;							\
	INTR(12, tl) ;							\
	INTR(13, tl) ;							\
	TICK(tl) ;							\
	INTR(15, tl) ;

	.macro	tl0_intr_level
	INTR_LEVEL(0)
	.endm

	.macro	intr_vector
	ldxa	[%g0] ASI_INTR_RECEIVE, %g1
	andcc	%g1, IRSR_BUSY, %g0
	bnz,a,pt %xcc, intr_enqueue
	 nop
	sir
	.align	32
	.endm

	.macro	immu_miss_user
	/*
	 * Extract the virtual page number from the contents of the tag
	 * access register.
	 */
	srlx	%g2, TAR_VPN_SHIFT, %g3

	/*
	 * Compute the tte bucket address.
	 */
	set	(1 << TSB_BUCKET_ADDRESS_BITS) - 1, %g1
	and	%g1, %g3, %g1
	sllx	%g1, TSB_BUCKET_SHIFT + TTE_SHIFT, %g1
	add	%g1, TSB_REG, %g1

	/*
	 * Loop over the ttes in this bucket
	 */

	/*
	 * Load the tte.  Note that this instruction may fault, clobbering
	 * the context of the tag access register (at least), and the contents
	 * of %g3, %g4, %g5, and %g6.  Luckily we can recover %g3, and we do
	 * not use %g4 or %g5 until this instruction completes successfully.
	 */
1:	ldda	[%g1] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */

	/*
	 * Recover the virtual page number, which may have been clobbered.
	 */
	srlx	%g2, TAR_VPN_SHIFT, %g3

	/*
	 * Check that its valid and executable and that the virtual page
	 * numbers match.
	 */
	brgez,pn %g5, 2f
	 andcc	%g5, TD_EXEC, %g0
	bz,pn	%xcc, 2f
	 cmp	%g3, %g4
	bne,pn %xcc, 2f
	 EMPTY

	/*
	 * We matched a tte, load the tlb.
	 */

	/*
	 * Set the reference bit, if it's currently clear.
	 */
	 andcc	%g5, TD_REF, %g0
	bz,a,pn	%xcc, tl0_immu_miss_set_ref
	 nop

	/*
	 * Load the tte tag and data into the tlb and retry the instruction.
	 */
	stxa	%g2, [%g0 + AA_IMMU_TAR] %asi
	stxa	%g5, [%g0] ASI_ITLB_DATA_IN_REG
	retry

	/*
	 * Check the low bits to see if we've finished the bucket.
	 */
2:	add	%g1, 1 << TTE_SHIFT, %g1
	andcc	%g1, (1 << (TSB_BUCKET_SHIFT + TTE_SHIFT)) - 1, %g0
	bnz,a,pt %xcc, 1b
	 nop
	.endm

	.macro	tl0_immu_miss
	/*
	 * Force kernel store order.
	 */
	wrpr	%g0, PSTATE_MMU, %pstate

	/*
	 * Load the virtual page number and context from the tag access
	 * register.  We ignore the context.
	 */
	wr	%g0, ASI_IMMU, %asi
	ldxa	[%g0 + AA_IMMU_TAR] %asi, %g2

	immu_miss_user

	b,a	%xcc, tl0_immu_miss_trap
	 nop
	.align	128
	.endm

ENTRY(tl0_immu_miss_set_ref)
	/*
	 * Set the reference bit.
	 */
	TTE_SET_REF(%g1, %g4, %g5)

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g4, 1f
	 or	%g4, TD_REF, %g4

	/*
	 * Load the tte tag and data into the tlb and retry the instruction.
	 */
	stxa	%g2, [%g0 + AA_IMMU_TAR] %asi
	stxa	%g4, [%g0] ASI_ITLB_DATA_IN_REG
1:	retry
END(tl0_immu_miss_set_ref)

ENTRY(tl0_immu_miss_trap)
	/*
	 * Put back the contents of the tag access register, in case we
	 * faulted.
	 */
	stxa	%g2, [%g0 + AA_IMMU_TAR] %asi
	membar	#Sync

	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	/*
	 * Reload the tag access register.
	 */
	ldxa	[%g0 + AA_IMMU_TAR] %asi, %g2

	/*
	 * Save the tag access register, and call common trap code.
	 */
	tl0_split
	mov	%g2, %o3
	b	%xcc, tl0_trap
	 mov	T_INSTRUCTION_MISS, %o0
END(tl0_immu_miss_trap)

	.macro	dmmu_miss_user
	/*
	 * Extract the virtual page number from the contents of the tag
	 * access register.
	 */
	srlx	%g2, TAR_VPN_SHIFT, %g3

	/*
	 * Compute the tte bucket address.
	 */
	set	(1 << TSB_BUCKET_ADDRESS_BITS) - 1, %g1
	and	%g1, %g3, %g1
	sllx	%g1, TSB_BUCKET_SHIFT + TTE_SHIFT, %g1
	add	%g1, TSB_REG, %g1

	/*
	 * Loop over the ttes in this bucket
	 */

	/*
	 * Load the tte.  Note that this instruction may fault, clobbering
	 * the contents of the tag access register (at least), and the contents
	 * of %g3, %g4, %g5, and %g6.  Luckily we can recover %g3, and we do
	 * not use %g4 or %g5 until this instruction completes successfully.
	 */
1:	ldda	[%g1] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */

	/*
	 * Recover the virtual page number, which may have been clobbered.
	 */
	srlx	%g2, TAR_VPN_SHIFT, %g3

	/*
	 * Check that its valid and that the virtual page numbers match.
	 */
	brgez,pn %g5, 2f
	 cmp	%g3, %g4
	bne,pn %xcc, 2f
	 EMPTY

	/*
	 * We matched a tte, load the tlb.
	 */

	/*
	 * Set the reference bit, if it's currently clear.
	 */
	 andcc	%g5, TD_REF, %g0
	bz,a,pn	%xcc, dmmu_miss_user_set_ref
	 nop

	/*
	 * Load the tte tag and data into the tlb and retry the instruction.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	stxa	%g5, [%g0] ASI_DTLB_DATA_IN_REG
	retry

	/*
	 * Check the low bits to see if we've finished the bucket.
	 */
2:	add	%g1, 1 << TTE_SHIFT, %g1
	andcc	%g1, (1 << (TSB_BUCKET_SHIFT + TTE_SHIFT)) - 1, %g0
	bnz,a,pt %xcc, 1b
	 nop
	.endm

ENTRY(dmmu_miss_user_set_ref)
	/*
	 * Set the reference bit.
	 */
	TTE_SET_REF(%g1, %g4, %g5)

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g4, 1f
	 or	%g4, TD_REF, %g4

	/*
	 * Load the tte tag and data into the tlb and retry the instruction.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	stxa	%g4, [%g0] ASI_DTLB_DATA_IN_REG
1:	retry
END(dmmu_miss_user_set_ref)

	.macro	tl0_dmmu_miss
	/*
	 * Force kernel store order.
	 */
	wrpr	%g0, PSTATE_MMU, %pstate

	/*
	 * Load the virtual page number and context from the tag access
	 * register.  We ignore the context.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2

	/*
	 * Try a fast inline lookup of the primary tsb.
	 */
	dmmu_miss_user

	/*
	 * Not in primary tsb, call c code.  Not much else fits inline.
	 */
	b,a	%xcc, tl0_dmmu_miss_trap
	 nop
	.align	128
	.endm

ENTRY(tl0_dmmu_miss_trap)
	/*
	 * Put back the contents of the tag access register, in case we
	 * faulted.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	membar	#Sync

	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	/*
	 * Reload the tag access register.
	 */
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2

	/*
	 * Save the tag access register and call common trap code.
	 */
	tl0_split
	mov	%g2, %o3
	b	%xcc, tl0_trap
	 mov	T_DATA_MISS, %o0
END(tl0_dmmu_miss_trap)

	.macro	dmmu_prot_user
	/*
	 * Extract the virtual page number from the contents of the tag
	 * access register.
	 */
	srlx	%g2, TAR_VPN_SHIFT, %g3

	/*
	 * Compute the tte bucket address.
	 */
	set	(1 << TSB_BUCKET_ADDRESS_BITS) - 1, %g1
	and	%g1, %g3, %g1
	sllx	%g1, TSB_BUCKET_SHIFT + TTE_SHIFT, %g1
	add	%g1, TSB_REG, %g1

	/*
	 * Loop over the ttes in this bucket
	 */

	/*
	 * Load the tte.  Note that this instruction may fault, clobbering
	 * the context of the tag access register (at least), and the contents
	 * of %g3, %g4, %g5, and %g6.  Luckily we can recover %g3, and we do
	 * not use %g4 or %g5 until this instruction completes successfully.
	 */
1:	ldda	[%g1] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */

	/*
	 * Recover the virtual page number, which may have been clobbered.
	 */
	srlx	%g2, TAR_VPN_SHIFT, %g3

	/*
	 * Check that its valid and writable and that the virtual page
	 * numbers match.
	 */
	brgez,pn %g5, 2f
	 andcc	%g5, TD_SW, %g0
	bz,pn	%xcc, 2f
	 cmp	%g3, %g4
	bne,pn %xcc, 2f
	 nop

	/*
	 * Set the hardware write bit.
	 */
	b,a	%xcc, dmmu_prot_set_w
	 nop

	/*
	 * Check the low bits to see if we've finished the bucket.
	 */
2:	add	%g1, 1 << TTE_SHIFT, %g1
	andcc	%g1, (1 << (TSB_BUCKET_SHIFT + TTE_SHIFT)) - 1, %g0
	bnz,a,pt %xcc, 1b
	 nop
	.endm

	.macro	tl0_dmmu_prot
	/*
	 * Force kernel store order.
	 */
	wrpr	%g0, PSTATE_MMU, %pstate

	/*
	 * Load the virtual page number and context from the tag access
	 * register.  We ignore the context.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2

	/*
	 * Try a fast inline lookup of the tsb.
	 */
	dmmu_prot_user

	/*
	 * Not in tsb.  Call c code.
	 */
	b,a	%xcc, tl0_dmmu_prot_trap
	 nop
	.align	128
	.endm

ENTRY(dmmu_prot_set_w)
	/*
	 * Set the hardware write bit in the tte.
	 */
	TTE_SET_W(%g1, %g4, %g5)

	/*
	 * Delete the old TLB entry and clear the sfsr.
	 */
	sllx	%g3, TAR_VPN_SHIFT, %g3
	stxa	%g0, [%g3] ASI_DMMU_DEMAP
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	/*
	 * May have become invalid in which case start over.
	 */
	brgez,pn %g4, 1f
	 or	%g4, TD_W, %g4

	/*
	 * Load the tte data into the tlb and retry the instruction.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	stxa	%g4, [%g0] ASI_DTLB_DATA_IN_REG
1:	retry
END(dmmu_prot_set_w)

ENTRY(tl0_dmmu_prot_trap)
	/*
	 * Put back the contents of the tag access register, in case we
	 * faulted.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	membar	#Sync

	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	/*
	 * Load the tar, sfar and sfsr.
	 */
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2

	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	/*
	 * Save the mmu registers and call common trap code.
	 */
	tl0_split
	mov	%g2, %o3
	mov	%g3, %o4
	mov	%g4, %o5
	b	%xcc, tl0_trap
	 mov	T_DATA_PROTECTION, %o0
END(tl0_dmmu_prot_trap)

	.macro	tl0_spill_0_n
	wr	%g0, ASI_AIUP, %asi
	SPILL(stxa, %sp + SPOFF, 8, %asi)
	saved
	retry
	.align	32
	RSF_TRAP(T_SPILL)
	RSF_TRAP(T_SPILL)
	.endm

	.macro	tl0_spill_1_n
	wr	%g0, ASI_AIUP, %asi
	SPILL(stwa, %sp, 4, %asi)
	saved
	retry
	.align	32
	RSF_TRAP(T_SPILL)
	RSF_TRAP(T_SPILL)
	.endm

	.macro	tl0_fill_0_n
	wr	%g0, ASI_AIUP, %asi
	FILL(ldxa, %sp + SPOFF, 8, %asi)
	restored
	retry
	.align	32
	RSF_TRAP(T_FILL)
	RSF_TRAP(T_FILL)
	.endm

	.macro	tl0_fill_1_n
	wr	%g0, ASI_AIUP, %asi
	FILL(lduwa, %sp, 4, %asi)
	restored
	retry
	.align	32
	RSF_TRAP(T_FILL)
	RSF_TRAP(T_FILL)
	.endm

ENTRY(tl0_sftrap)
	rdpr	%tstate, %g1
	and	%g1, TSTATE_CWP_MASK, %g1
	wrpr	%g1, 0, %cwp
	tl0_split
	b	%xcc, tl0_trap
	 mov	%g2, %o0
END(tl0_sftrap)

	.macro	tl0_spill_bad	count
	.rept	\count
	sir
	.align	128
	.endr
	.endm

	.macro	tl0_fill_bad	count
	.rept	\count
	sir
	.align	128
	.endr
	.endm

	.macro	tl0_syscall
	tl0_split
	b	%xcc, tl0_syscall
	 mov	T_SYSCALL, %o0
	.align	32
	.endm

	.macro	tl0_soft	count
	.rept	\count
	tl0_gen	T_SOFT
	.endr
	.endm

	.macro	tl1_split
	rdpr	%wstate, %g1
	wrpr	%g1, WSTATE_NESTED, %wstate
	save	%sp, -CCFSZ, %sp
	.endm

	.macro	tl1_setup	type
	tl1_split
	b	%xcc, tl1_trap
	 mov	\type | T_KERNEL, %o0
	.endm

	.macro	tl1_gen		type
	tl1_setup \type
	.align	32
	.endm

	.macro	tl1_reserved	count
	.rept	\count
	tl1_gen	T_RESERVED
	.endr
	.endm

	.macro	tl1_insn_excptn
	wr	%g0, ASI_IMMU, %asi
	rdpr	%tpc, %g3
	ldxa	[%g0 + AA_IMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_IMMU_SFSR] %asi
	membar	#Sync
	b	%xcc, tl1_insn_exceptn_trap
	 mov	T_INSTRUCTION_EXCEPTION | T_KERNEL, %g2
	.align	32
	.endm

ENTRY(tl1_insn_exceptn_trap)
	tl1_split
	mov	%g3, %o4
	mov	%g4, %o5
	b	%xcc, tl1_trap
	 mov	%g2, %o0
END(tl1_insn_exceptn_trap)

	.macro	tl1_data_excptn
	b,a	%xcc, tl1_data_excptn_trap
	 nop
	.align	32
	.endm

ENTRY(tl1_data_excptn_trap)
	wrpr	%g0, PSTATE_ALT, %pstate
	RESUME_SPILLFILL_MMU_CLR_SFSR
	b	%xcc, tl1_sfsr_trap
	 mov	T_DATA_EXCEPTION | T_KERNEL, %g2
END(tl1_data_excptn_trap)

	.macro	tl1_align
	b,a	%xcc, tl1_align_trap
	 nop
	.align	32
	.endm

ENTRY(tl1_align_trap)
	wrpr	%g0, PSTATE_ALT, %pstate
	RESUME_SPILLFILL_ALIGN
	b	%xcc, tl1_sfsr_trap
	 mov	T_MEM_ADDRESS_NOT_ALIGNED | T_KERNEL, %g2
END(tl1_data_excptn_trap)

ENTRY(tl1_sfsr_trap)
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	tl1_split
	mov	%g3, %o4
	mov	%g4, %o5
	b	%xcc, tl1_trap
	 mov	%g2, %o0
END(tl1_sfsr_trap)

	.macro	tl1_intr level, mask
	tl1_split
	set	\mask, %o1
	b	%xcc, tl1_intr
	 mov	\level, %o0
	.align	32
	.endm

	.macro	tl1_intr_level
	INTR_LEVEL(1)
	.endm

ENTRY(intr_dequeue)
	save	%sp, -CCFSZ, %sp

1:	ldx	[PCPU(IRHEAD)], %l0
	brnz,a,pt %l0, 2f
	 nop

	ret
	 restore

2:	wrpr	%g0, PSTATE_NORMAL, %pstate

	ldx	[%l0 + IR_NEXT], %l1
	brnz,pt	%l1, 3f
	 stx	%l1, [PCPU(IRHEAD)]
	PCPU_ADDR(IRHEAD, %l1)
	stx	%l1, [PCPU(IRTAIL)]

3:	ldx	[%l0 + IR_FUNC], %o0
	ldx	[%l0 + IR_ARG], %o1
	ldx	[%l0 + IR_VEC], %o2

	ldx	[PCPU(IRFREE)], %l1
	stx	%l1, [%l0 + IR_NEXT]
	stx	%l0, [PCPU(IRFREE)]

	wrpr	%g0, PSTATE_KERNEL, %pstate

	call	%o0
	 mov	%o1, %o0
	ba,a	%xcc, 1b
	 nop
END(intr_dequeue)

/*
 * Handle a vectored interrupt.
 *
 * This is either a data bearing mondo vector interrupt, or a cross trap
 * request from another cpu.  In either case the hardware supplies an
 * interrupt packet, in the form of 3 data words which are read from internal
 * registers.  A data bearing mondo vector packet consists of an interrupt
 * number in the first data word, and zero in 2nd and 3rd.  We use the
 * interrupt number to find the function, argument and priority from the
 * intr_vector table, allocate and fill in an intr_request from the per-cpu
 * free list, link it onto the per-cpu active list and finally post a softint
 * at the desired priority.  Cross trap requests come in 2 forms, direct
 * and queued.  Direct requests are distinguished by the first data word
 * being zero.  The 2nd data word carries a function to call and the 3rd
 * an argument to pass.  The function is jumped to directly.  It executes
 * in nucleus context on interrupt globals and with all interrupts disabled,
 * therefore it must be fast, and the things that it can do are limited.
 * Queued cross trap requests are handled much like mondo vectors, except
 * that the function, argument and priority are contained in the interrupt
 * packet itself.  They are distinguished by the upper 4 bits of the data
 * word being non-zero, which specifies the priority of the softint to
 * deliver.
 *
 * Register usage:
 *	%g1 - pointer to intr_request
 *	%g2 - pointer to intr_vector, temp once required data is loaded
 *	%g3 - interrupt number for mondo vectors, unused otherwise
 *	%g4 - function, from the interrupt packet for cross traps, or
 *	      loaded from the interrupt registers for mondo vecors
 *	%g5 - argument, as above for %g4
 *	%g6 - softint priority
 */
ENTRY(intr_enqueue)
	/*
	 * Load the interrupt packet from the hardware.
	 */
	wr	%g0, ASI_SDB_INTR_R, %asi
	ldxa	[%g0 + AA_SDB_INTR_D0] %asi, %g3
	ldxa	[%g0 + AA_SDB_INTR_D1] %asi, %g4
	ldxa	[%g0 + AA_SDB_INTR_D2] %asi, %g5
	stxa	%g0, [%g0] ASI_INTR_RECEIVE
	membar	#Sync

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR, "intr_enqueue: data=%#lx %#lx %#lx"
	    , %g1, %g2, %g6, 7, 8, 9)
	stx	%g3, [%g1 + KTR_PARM1]
	stx	%g4, [%g1 + KTR_PARM2]
	stx	%g5, [%g1 + KTR_PARM3]
9:
#endif

	/*
	 * If the first data word is zero this is a direct cross trap request.
	 * The 2nd word points to code to execute and the 3rd is an argument
	 * to pass.  Jump to it.
	 */
	brnz,a,pt %g3, 1f
	 nop

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR, "intr_enqueue: direct ipi func=%#lx arg=%#lx"
	    , %g1, %g2, %g6, 7, 8, 9)
	stx	%g4, [%g1 + KTR_PARM1]
	stx	%g5, [%g1 + KTR_PARM2]
9:
#endif

	jmpl	%g4, %g0
	 nop
	/* NOTREACHED */

	/*
	 * If the high 4 bits of the 1st data word are non-zero, this is a
	 * queued cross trap request to be delivered as a softint.  The high
	 * 4 bits of the 1st data word specify a priority, and the 2nd and
	 * 3rd a function and argument.
	 */
1:	srlx	%g3, 60, %g6
	brnz,a,pn %g6, 2f
	 clr	%g3

	/*
	 * Find the function, argument and desired priority from the
	 * intr_vector table.
	 */
	SET(intr_vectors, %g4, %g2)
	sllx	%g3, IV_SHIFT, %g4
	add	%g2, %g4, %g2

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR, "intr_enqueue: mondo vector func=%#lx arg=%#lx pri=%#lx"
	    , %g4, %g5, %g6, 7, 8, 9)
	ldx	[%g2 + IV_FUNC], %g5
	stx	%g5, [%g4 + KTR_PARM1]
	ldx	[%g2 + IV_ARG], %g5
	stx	%g5, [%g4 + KTR_PARM2]
	ldx	[%g2 + IV_PRI], %g5
	stx	%g5, [%g4 + KTR_PARM3]
9:
#endif

	ldx	[%g2 + IV_FUNC], %g4
	ldx	[%g2 + IV_ARG], %g5
	lduw	[%g2 + IV_PRI], %g6

	ba,a	%xcc, 3f
	 nop

	/*
	 * Get a intr_request from the free list.  There should always be one
	 * unless we are getting an interrupt storm from stray interrupts, in
	 * which case the we will deference a NULL pointer and panic.
	 */
2:
#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR, "intr_enqueue: queued ipi func=%#lx arg=%#lx pri=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	stx	%g4, [%g1 + KTR_PARM1]
	stx	%g5, [%g1 + KTR_PARM2]
	stx	%g6, [%g1 + KTR_PARM3]
9:
	clr	%g3
#endif

3:
	ldx	[PCPU(IRFREE)], %g1
	ldx	[%g1 + IR_NEXT], %g2
	stx	%g2, [PCPU(IRFREE)]

	/*
	 * Store the vector number, function, argument and priority.
	 */
	stw	%g3, [%g1 + IR_VEC]
	stx	%g4, [%g1 + IR_FUNC]
	stx	%g5, [%g1 + IR_ARG]
	stw	%g6, [%g1 + IR_PRI]

	/*
	 * Link it onto the end of the active list.
	 */
	stx	%g0, [%g1 + IR_NEXT]
	ldx	[PCPU(IRTAIL)], %g4
	stx	%g1, [%g4]
	add	%g1, IR_NEXT, %g1
	stx	%g1, [PCPU(IRTAIL)]

	/*
	 * Trigger a softint at the level indicated by the priority.
	 */
	mov	1, %g1
	sllx	%g1, %g6, %g1

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR, "intr_enqueue: softint pil=%#lx pri=%#lx mask=%#lx"
	    , %g2, %g3, %g4, 7, 8, 9)
	rdpr	%pil, %g3
	stx	%g3, [%g2 + KTR_PARM1]
	stx	%g6, [%g2 + KTR_PARM2]
	stx	%g1, [%g2 + KTR_PARM3]
9:
#endif

	wr	%g1, 0, %asr20

	/*
	 * Done, retry the instruction.
	 */
	retry
END(intr_enqueue)

	.macro	tl1_immu_miss
	/*
	 * Load the context and the virtual page number from the tag access
	 * register.  We ignore the context.
	 */
	wr	%g0, ASI_IMMU, %asi
	ldxa	[%g0 + AA_IMMU_TAR] %asi, %g6

	/*
	 * Extract the virtual page number from the contents of the tag access
	 * register.
	 */
	srlx	%g6, TAR_VPN_SHIFT, %g6

	/*
	 * Find the index into the kernel tsb.
	 */
	set	TSB_KERNEL_MASK, %g4
	and	%g6, %g4, %g3

	/*
	 * Compute the tte address.
	 */
	ldxa	[%g0 + AA_IMMU_TSB] %asi, %g4
	sllx	%g3, TTE_SHIFT, %g3
	add	%g3, %g4, %g3

	/*
	 * Load the tte.
	 */
	ldda	[%g3] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */

	/*
	 * Check that its valid and executable and that the virtual page
	 * numbers match.
	 */
	brgez,pn %g5, tl1_immu_miss_trap
	 andcc	%g5, TD_EXEC, %g0
	bz,pn	%xcc, tl1_immu_miss_trap
	 cmp	%g4, %g6
	bne,pn	%xcc, tl1_immu_miss_trap
	 EMPTY

	/*
	 * Set the reference bit if its currently clear.
	 */
	 andcc	%g5, TD_REF, %g0
	bnz,a,pt %xcc, 1f
	 nop
	TTE_SET_REF(%g3, %g5, %g4)

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g5, 2f
	 or	%g5, TD_REF, %g5

	/*
	 * Load the tte data into the TLB and retry the instruction.
	 */
1:	stxa	%g5, [%g0] ASI_ITLB_DATA_IN_REG
2:	retry
	.align	128
	.endm

ENTRY(tl1_immu_miss_trap)
	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	ldxa	[%g0 + AA_IMMU_TAR] %asi, %g2

	tl1_split
	mov	%g2, %o3
	b	%xcc, tl1_trap
	 mov	T_INSTRUCTION_MISS | T_KERNEL, %o0
END(tl1_immu_miss_trap)

	.macro	tl1_dmmu_miss
	/*
	 * Load the context and the virtual page number from the tag access
	 * register.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g6

	/*
	 * Extract the context from the contents of the tag access register.
	 * If its non-zero this is a fault on a user address, otherwise get
	 * the virtual page number.
	 */
	sllx	%g6, 64 - TAR_VPN_SHIFT, %g5
	brnz,a,pn %g5, tl1_dmmu_miss_user
	 mov	%g6, %g2

	/*
	 * Find the index into the kernel tsb.
	 */
	set	TSB_KERNEL_MASK, %g4
	srlx	%g6, TAR_VPN_SHIFT, %g6
	and	%g6, %g4, %g3

	/*
	 * Compute the tte address.
	 */
	ldxa	[%g0 + AA_DMMU_TSB] %asi, %g4
	sllx	%g3, TTE_SHIFT, %g3
	add	%g3, %g4, %g3

	/*
	 * Load the tte.
	 */
	ldda	[%g3] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */

	/*
	 * Check that its valid and that the virtual page numbers match.
	 */
	brgez,pn %g5, tl1_dmmu_miss_trap
	 cmp	%g4, %g6
	bne,pn %xcc, tl1_dmmu_miss_trap
	 EMPTY

	/*
	 * Set the reference bit if its currently clear.
	 */
	 andcc	%g5, TD_REF, %g0
	bnz,a,pt %xcc, 1f
	 nop
	TTE_SET_REF(%g3, %g5, %g4)

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g5, 2f
	 or	%g5, TD_REF, %g5

	/*
	 * Load the tte data into the TLB and retry the instruction.
	 */
1:	stxa	%g5, [%g0] ASI_DTLB_DATA_IN_REG
2:	retry
	.align	128
	.endm

ENTRY(tl1_dmmu_miss_trap)
	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	KSTACK_CHECK

	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2

	tl1_split
	mov	%g2, %o3
	b	%xcc, tl1_trap
	 mov	T_DATA_MISS | T_KERNEL, %o0
END(tl1_dmmu_miss_trap)

ENTRY(tl1_dmmu_miss_user)
	/*
	 * Try a fast inline lookup of the user tsb.
	 */
	dmmu_miss_user

	/*
	 * Put back the contents of the tag access register, in case we
	 * faulted.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	membar	#Sync

	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	/*
	 * Handle faults during window spill/fill.
	 */
	RESUME_SPILLFILL_MMU

	/*
	 * Reload the tag access register.
	 */
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2

	tl1_split
	mov	%g2, %o3
	b	%xcc, tl1_trap
	 mov	T_DATA_MISS | T_KERNEL, %o0
END(tl1_dmmu_miss_user)

	.macro	tl1_dmmu_prot
	/*
	 * Load the context and the virtual page number from the tag access
	 * register.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g6

	/*
	 * Extract the context from the contents of the tag access register.
	 * If its non-zero this is a fault on a user address, otherwise get
	 * the virtual page number.
	 */
	sllx	%g6, 64 - TAR_VPN_SHIFT, %g5
	brnz,a,pn %g5, tl1_dmmu_prot_user
	 mov	%g6, %g2

	/*
	 * Find the index into the kernel tsb.
	 */
	set	TSB_KERNEL_MASK, %g4
	srlx	%g6, TAR_VPN_SHIFT, %g6
	and	%g6, %g4, %g5

	/*
	 * Compute the tte address.
	 */
	ldxa	[%g0 + AA_DMMU_TSB] %asi, %g4
	sllx	%g5, TTE_SHIFT, %g5
	add	%g4, %g5, %g3

	/*
	 * Load the tte.
	 */
	ldda	[%g3] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */

	/*
	 * Check that its valid and writeable and that the virtual page
	 * numbers match.
	 */
	brgez,pn %g5, tl1_dmmu_prot_trap
	 andcc	%g5, TD_SW, %g0
	bz,pn	%xcc, tl1_dmmu_prot_trap
	 cmp	%g4, %g6
	bne,pn	%xcc, tl1_dmmu_prot_trap
	 EMPTY

	/*
	 * Delete the old TLB entry and clear the sfsr.
	 */
	 sllx	%g6, TAR_VPN_SHIFT, %g6
	or	%g6, TLB_DEMAP_NUCLEUS, %g6
	stxa	%g0, [%g6] ASI_DMMU_DEMAP
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	ba,a	%xcc, tl1_dmmu_prot_cont
	 nop
	.align	128
	.endm

ENTRY(tl1_dmmu_prot_cont)
	/*
	 * Set the hardware write bit.
	 */
	TTE_SET_W(%g3, %g5, %g6)

	/*
	 * Load the tte data into the TLB and retry the instruction.
	 */
	or	%g5, TD_W, %g5
	stxa	%g5, [%g0] ASI_DTLB_DATA_IN_REG
	retry
END(tl1_dmmu_prot_cont)

ENTRY(tl1_dmmu_prot_user)
	/*
	 * Try a fast inline lookup of the user tsb.
	 */
	dmmu_prot_user

	/*
	 * Put back the contents of the tag access register, in case we
	 * faulted.
	 */
	stxa	%g2, [%g0 + AA_DMMU_TAR] %asi
	membar	#Sync

	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	/* Handle faults during window spill/fill. */
	RESUME_SPILLFILL_MMU_CLR_SFSR

	b,a	%xcc, tl1_dmmu_prot_trap
	 nop
END(tl1_dmmu_prot_user)

ENTRY(tl1_dmmu_prot_trap)
	/*
	 * Switch to alternate globals.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	/*
	 * Load the sfar, sfsr and tar.  Clear the sfsr.
	 */
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g2
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g4
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	tl1_split
	mov	%g2, %o3
	mov	%g3, %o4
	mov	%g4, %o5
	b	%xcc, tl1_trap
	 mov	T_DATA_PROTECTION | T_KERNEL, %o0
END(tl1_dmmu_prot_trap)

	.macro	tl1_spill_0_n
	SPILL(stx, %sp + SPOFF, 8, EMPTY)
	saved
	retry
	.align	32
	RSF_FATAL(T_SPILL)
	RSF_FATAL(T_SPILL)
	.endm

	.macro	tl1_spill_2_n
	wr	%g0, ASI_AIUP, %asi
	SPILL(stxa, %sp + SPOFF, 8, %asi)
	saved
	retry
	.align	32
	RSF_SPILL_TOPCB
	RSF_SPILL_TOPCB
	.endm

	.macro	tl1_spill_3_n
	wr	%g0, ASI_AIUP, %asi
	SPILL(stwa, %sp, 4, %asi)
	saved
	retry
	.align	32
	RSF_SPILL_TOPCB
	RSF_SPILL_TOPCB
	.endm

	.macro	tl1_spill_0_o
	wr	%g0, ASI_AIUP, %asi
	SPILL(stxa, %sp + SPOFF, 8, %asi)
	saved
	retry
	.align	32
	RSF_SPILL_TOPCB
	RSF_SPILL_TOPCB
	.endm

	.macro	tl1_spill_1_o
	wr	%g0, ASI_AIUP, %asi
	SPILL(stwa, %sp, 4, %asi)
	saved
	retry
	.align	32
	RSF_SPILL_TOPCB
	RSF_SPILL_TOPCB
	.endm

	.macro	tl1_spill_2_o
	RSF_SPILL_TOPCB
	.align	128
	.endm

	.macro	tl1_fill_0_n
	FILL(ldx, %sp + SPOFF, 8, EMPTY)
	restored
	retry
	.align	32
	RSF_FATAL(T_FILL)
	RSF_FATAL(T_FILL)
	.endm

	.macro	tl1_fill_2_n
	wr	%g0, ASI_AIUP, %asi
	FILL(ldxa, %sp + SPOFF, 8, %asi)
	restored
	retry
	.align 32
	RSF_FILL_MAGIC
	RSF_FILL_MAGIC
	.endm

	.macro	tl1_fill_3_n
	wr	%g0, ASI_AIUP, %asi
	FILL(lduwa, %sp, 4, %asi)
	restored
	retry
	.align 32
	RSF_FILL_MAGIC
	RSF_FILL_MAGIC
	.endm

/*
 * This is used to spill windows that are still occupied with user
 * data on kernel entry to the pcb.
 */
ENTRY(tl1_spill_topcb)
	wrpr	%g0, PSTATE_ALT, %pstate

	/* Free some globals for our use. */
	dec	24, ASP_REG
	stx	%g1, [ASP_REG + 0]
	stx	%g2, [ASP_REG + 8]
	stx	%g3, [ASP_REG + 16]

	ldx	[PCB_REG + PCB_NSAVED], %g1

	sllx	%g1, PTR_SHIFT, %g2
	add	%g2, PCB_REG, %g2
	stx	%sp, [%g2 + PCB_RWSP]

	sllx	%g1, RW_SHIFT, %g2
	add	%g2, PCB_REG, %g2
	SPILL(stx, %g2 + PCB_RW, 8, EMPTY)

	inc	%g1
	stx	%g1, [PCB_REG + PCB_NSAVED]

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl1_spill_topcb: pc=%#lx npc=%#lx sp=%#lx nsaved=%d"
	   , %g1, %g2, %g3, 7, 8, 9)
	rdpr	%tpc, %g2
	stx	%g2, [%g1 + KTR_PARM1]
	rdpr	%tnpc, %g2
	stx	%g2, [%g1 + KTR_PARM2]
	stx	%sp, [%g1 + KTR_PARM3]
	ldx	[PCB_REG + PCB_NSAVED], %g2
	stx	%g2, [%g1 + KTR_PARM4]
9:
#endif

	saved

	ldx	[ASP_REG + 16], %g3
	ldx	[ASP_REG + 8], %g2
	ldx	[ASP_REG + 0], %g1
	inc	24, ASP_REG
	retry
END(tl1_spill_topcb)

	.macro	tl1_spill_bad	count
	.rept	\count
	sir
	.align	128
	.endr
	.endm

	.macro	tl1_fill_bad	count
	.rept	\count
	sir
	.align	128
	.endr
	.endm

	.macro	tl1_soft	count
	.rept	\count
	tl1_gen	T_SOFT | T_KERNEL
	.endr
	.endm

	.sect	.trap
	.align	0x8000
	.globl	tl0_base

tl0_base:
	tl0_reserved	8				! 0x0-0x7
tl0_insn_excptn:
	tl0_insn_excptn					! 0x8
	tl0_reserved	1				! 0x9
tl0_insn_error:
	tl0_gen		T_INSTRUCTION_ERROR		! 0xa
	tl0_reserved	5				! 0xb-0xf
tl0_insn_illegal:
	tl0_gen		T_ILLEGAL_INSTRUCTION		! 0x10
tl0_priv_opcode:
	tl0_gen		T_PRIVILEGED_OPCODE		! 0x11
	tl0_reserved	14				! 0x12-0x1f
tl0_fp_disabled:
	tl0_gen		T_FP_DISABLED			! 0x20
tl0_fp_ieee:
	tl0_gen		T_FP_EXCEPTION_IEEE_754		! 0x21
tl0_fp_other:
	tl0_gen		T_FP_EXCEPTION_OTHER		! 0x22
tl0_tag_ovflw:
	tl0_gen		T_TAG_OFERFLOW			! 0x23
tl0_clean_window:
	clean_window					! 0x24
tl0_divide:
	tl0_gen		T_DIVISION_BY_ZERO		! 0x28
	tl0_reserved	7				! 0x29-0x2f
tl0_data_excptn:
	tl0_data_excptn					! 0x30
	tl0_reserved	1				! 0x31
tl0_data_error:
	tl0_gen		T_DATA_ERROR			! 0x32
	tl0_reserved	1				! 0x33
tl0_align:
	tl0_align					! 0x34
tl0_align_lddf:
	tl0_gen		T_RESERVED			! 0x35
tl0_align_stdf:
	tl0_gen		T_RESERVED			! 0x36
tl0_priv_action:
	tl0_gen		T_PRIVILEGED_ACTION		! 0x37
	tl0_reserved	9				! 0x38-0x40
tl0_intr_level:
	tl0_intr_level					! 0x41-0x4f
	tl0_reserved	16				! 0x50-0x5f
tl0_intr_vector:
	intr_vector					! 0x60
tl0_watch_phys:
	tl0_gen		T_PA_WATCHPOINT			! 0x61
tl0_watch_virt:
	tl0_gen		T_VA_WATCHPOINT			! 0x62
tl0_ecc:
	tl0_gen		T_CORRECTED_ECC_ERROR		! 0x63
tl0_immu_miss:
	tl0_immu_miss					! 0x64
tl0_dmmu_miss:
	tl0_dmmu_miss					! 0x68
tl0_dmmu_prot:
	tl0_dmmu_prot					! 0x6c
	tl0_reserved	16				! 0x70-0x7f
tl0_spill_0_n:
	tl0_spill_0_n					! 0x80
tl0_spill_1_n:
	tl0_spill_1_n					! 0x84
	tl0_spill_bad	14				! 0x88-0xbf
tl0_fill_0_n:
	tl0_fill_0_n					! 0xc0
tl0_fill_1_n:
	tl0_fill_1_n					! 0xc4
	tl0_fill_bad	14				! 0xc8-0xff
tl0_soft:
	tl0_reserved	1				! 0x100
	tl0_gen		T_BREAKPOINT			! 0x101
	tl0_gen		T_DIVISION_BY_ZERO		! 0x102
	tl0_reserved	1				! 0x103
	tl0_gen		T_CLEAN_WINDOW			! 0x104
	tl0_gen		T_RANGE_CHECK			! 0x105
	tl0_gen		T_FIX_ALIGNMENT			! 0x106
	tl0_gen		T_INTEGER_OVERFLOW		! 0x107
	tl0_reserved	1				! 0x108
	tl0_syscall					! 0x109
	tl0_fp_restore					! 0x10a
	tl0_reserved	5				! 0x10b-0x10f
	tl0_gen		T_TRAP_INSTRUCTION_16		! 0x110
	tl0_gen		T_TRAP_INSTRUCTION_17		! 0x111
	tl0_gen		T_TRAP_INSTRUCTION_18		! 0x112
	tl0_gen		T_TRAP_INSTRUCTION_19		! 0x113
	tl0_gen		T_TRAP_INSTRUCTION_20		! 0x114
	tl0_gen		T_TRAP_INSTRUCTION_21		! 0x115
	tl0_gen		T_TRAP_INSTRUCTION_22		! 0x116
	tl0_gen		T_TRAP_INSTRUCTION_23		! 0x117
	tl0_gen		T_TRAP_INSTRUCTION_24		! 0x118
	tl0_gen		T_TRAP_INSTRUCTION_25		! 0x119
	tl0_gen		T_TRAP_INSTRUCTION_26		! 0x11a
	tl0_gen		T_TRAP_INSTRUCTION_27		! 0x11b
	tl0_gen		T_TRAP_INSTRUCTION_28		! 0x11c
	tl0_gen		T_TRAP_INSTRUCTION_29		! 0x11d
	tl0_gen		T_TRAP_INSTRUCTION_30		! 0x11e
	tl0_gen		T_TRAP_INSTRUCTION_31		! 0x11f
	tl0_reserved	224				! 0x120-0x1ff

tl1_base:
	tl1_reserved	8				! 0x200-0x207
tl1_insn_excptn:
	tl1_insn_excptn					! 0x208
	tl1_reserved	1				! 0x209
tl1_insn_error:
	tl1_gen		T_INSTRUCTION_ERROR		! 0x20a
	tl1_reserved	5				! 0x20b-0x20f
tl1_insn_illegal:
	tl1_gen		T_ILLEGAL_INSTRUCTION		! 0x210
tl1_priv_opcode:
	tl1_gen		T_PRIVILEGED_OPCODE		! 0x211
	tl1_reserved	14				! 0x212-0x21f
tl1_fp_disabled:
	tl1_gen		T_FP_DISABLED			! 0x220
tl1_fp_ieee:
	tl1_gen		T_FP_EXCEPTION_IEEE_754		! 0x221
tl1_fp_other:
	tl1_gen		T_FP_EXCEPTION_OTHER		! 0x222
tl1_tag_ovflw:
	tl1_gen		T_TAG_OFERFLOW			! 0x223
tl1_clean_window:
	clean_window					! 0x224
tl1_divide:
	tl1_gen		T_DIVISION_BY_ZERO		! 0x228
	tl1_reserved	7				! 0x229-0x22f
tl1_data_excptn:
	tl1_data_excptn					! 0x230
	tl1_reserved	1				! 0x231
tl1_data_error:
	tl1_gen		T_DATA_ERROR			! 0x232
	tl1_reserved	1				! 0x233
tl1_align:
	tl1_align					! 0x234
tl1_align_lddf:
	tl1_gen		T_RESERVED			! 0x235
tl1_align_stdf:
	tl1_gen		T_RESERVED			! 0x236
tl1_priv_action:
	tl1_gen		T_PRIVILEGED_ACTION		! 0x237
	tl1_reserved	9				! 0x238-0x240
tl1_intr_level:
	tl1_intr_level					! 0x241-0x24f
	tl1_reserved	16				! 0x250-0x25f
tl1_intr_vector:
	intr_vector					! 0x260
tl1_watch_phys:
	tl1_gen		T_PA_WATCHPOINT			! 0x261
tl1_watch_virt:
	tl1_gen		T_VA_WATCHPOINT			! 0x262
tl1_ecc:
	tl1_gen		T_CORRECTED_ECC_ERROR		! 0x263
tl1_immu_miss:
	tl1_immu_miss					! 0x264
tl1_dmmu_miss:
	tl1_dmmu_miss					! 0x268
tl1_dmmu_prot:
	tl1_dmmu_prot					! 0x26c
	tl1_reserved	16				! 0x270-0x27f
tl1_spill_0_n:
	tl1_spill_0_n					! 0x280
	tl1_spill_bad	1				! 0x284
tl1_spill_2_n:
	tl1_spill_2_n					! 0x288
tl1_spill_3_n:
	tl1_spill_3_n					! 0x29c
	tl1_spill_bad	4				! 0x290-0x29f
tl1_spill_0_o:
	tl1_spill_0_o					! 0x2a0
tl1_spill_1_o:
	tl1_spill_1_o					! 0x2a4
tl1_spill_2_o:
	tl1_spill_2_o					! 0x2a8
	tl1_spill_bad	5				! 0x2ac-0x2bf
tl1_fill_0_n:
	tl1_fill_0_n					! 0x2c0
	tl1_fill_bad	1				! 0x2c4
tl1_fill_2_n:
	tl1_fill_2_n					! 0x2d0
tl1_fill_3_n:
	tl1_fill_3_n					! 0x2d4
	tl1_fill_bad	12				! 0x2d8-0x2ff
	tl1_reserved	1				! 0x300
tl1_breakpoint:
	tl1_gen		T_BREAKPOINT			! 0x301
	tl1_gen		T_RSTRWP_PHYS			! 0x302
	tl1_gen		T_RSTRWP_VIRT			! 0x303
	tl1_reserved	252				! 0x304-0x3ff

/*
 * User trap entry point.
 *
 * void tl0_trap(u_int type, u_long o1, u_long o2, u_long tar, u_long sfar,
 *		 u_int sfsr)
 *
 * The following setup has been performed:
 *	- the windows have been split and the active user window has been saved
 *	  (maybe just to the pcb)
 *	- we are on alternate globals and interrupts are disabled
 *
 * We switch to the kernel stack, build a trapframe, switch to normal
 * globals, enable interrupts and call trap.
 *
 * NOTE: We must be very careful setting up the per-cpu pointer.  We know that
 * it has been pre-set in alternate globals, so we read it from there and setup
 * the normal %g7 *before* enabling interrupts.  This avoids any possibility
 * of cpu migration and using the wrong pcpup.
 */
ENTRY(tl0_trap)
	/*
	 * Force kernel store order.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	rdpr	%tstate, %l0
	rdpr	%tpc, %l1
	rdpr	%tnpc, %l2
	rd	%y, %l3
	rd	%fprs, %l4
	rdpr	%wstate, %l5

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP,
	    "tl0_trap: td=%p type=%#x pil=%#lx pc=%#lx npc=%#lx sp=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	stx	%o0, [%g1 + KTR_PARM2]
	rdpr	%pil, %g2
	stx	%g2, [%g1 + KTR_PARM3]
	stx	%l1, [%g1 + KTR_PARM4]
	stx	%l2, [%g1 + KTR_PARM5]
	stx	%i6, [%g1 + KTR_PARM6]
9:
#endif

	and	%l5, WSTATE_NORMAL_MASK, %l5

	cmp	%o0, UT_MAX
	bge,a,pt %xcc, 2f
	 nop

	ldx	[PCPU(CURTHREAD)], %l6
	ldx	[%l6 + TD_PROC], %l6
	ldx	[%l6 + P_MD + MD_UTRAP], %l6
	brz,pt	%l6, 2f
	 sllx	%o0, PTR_SHIFT, %l7
	ldx	[%l6 + %l7], %l6
	brz,pt	%l6, 2f
	 andn	%l0, TSTATE_CWP_MASK, %l7

	ldx	[PCB_REG + PCB_NSAVED], %g1
	brnz,a,pn %g1, 1f
	 mov	T_SPILL, %o0

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl0_trap: user trap npc=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	stx	%l6, [%g1 + KTR_PARM1]
9:
#endif

	wrpr	%l5, %wstate
	wrpr	%l6, %tnpc
	rdpr	%cwp, %l6
	wrpr	%l6, %l7, %tstate

	sub	%fp, CCFSZ, %sp

	/*
	 * Need to store %fsr to pass it to the user trap handler. Otherwise,
	 * the ftt field might be zeoed out in a store in another trap or
	 * interrupt. Use the temporary stack for that.
	 */
	rd	%fprs, %l3
	or	%l3, FPRS_FEF, %l4
	wr	%l4, 0, %fprs
	dec	8, ASP_REG
	stx	%fsr, [ASP_REG]
	ldx	[ASP_REG], %l4
	inc	8, ASP_REG
	wr	%l3, 0, %fprs

	mov	%l0, %l5
	mov	%l1, %l6
	mov	%l2, %l7

	done

1:
#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl0_trap: defer user trap npc=%#lx nsaved=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	stx	%l6, [%g1 + KTR_PARM1]
	ldx	[PCB_REG + PCB_NSAVED], %g2
	stx	%g2, [%g1 + KTR_PARM2]
9:
#endif

2:	sllx	%l5, WSTATE_OTHER_SHIFT, %l5
	wrpr	%l5, WSTATE_KERNEL, %wstate
	rdpr	%canrestore, %l6
	wrpr	%l6, 0, %otherwin
	wrpr	%g0, 0, %canrestore

	sub	PCB_REG, SPOFF + CCFSZ + TF_SIZEOF, %sp

	stx	%o3, [%sp + SPOFF + CCFSZ + TF_TAR]
	stx	%o4, [%sp + SPOFF + CCFSZ + TF_SFAR]
	stw	%o5, [%sp + SPOFF + CCFSZ + TF_SFSR]

	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]
	stw	%l3, [%sp + SPOFF + CCFSZ + TF_Y]
	stb	%l4, [%sp + SPOFF + CCFSZ + TF_FPRS]
	stb	%l5, [%sp + SPOFF + CCFSZ + TF_WSTATE]

	wr	%g0, FPRS_FEF, %fprs
	stx	%fsr, [%sp + SPOFF + CCFSZ + TF_FSR]
	wr	%g0, 0, %fprs

	mov	PCB_REG, %l0
	mov	PCPU_REG, %l1
	wrpr	%g0, PSTATE_NORMAL, %pstate

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]
	stx	%g6, [%sp + SPOFF + CCFSZ + TF_G6]
	stx	%g7, [%sp + SPOFF + CCFSZ + TF_G7]

	mov	%l0, PCB_REG
	mov	%l1, PCPU_REG
	wrpr	%g0, PSTATE_KERNEL, %pstate

	stx	%i0, [%sp + SPOFF + CCFSZ + TF_O0]
	stx	%i1, [%sp + SPOFF + CCFSZ + TF_O1]
	stx	%i2, [%sp + SPOFF + CCFSZ + TF_O2]
	stx	%i3, [%sp + SPOFF + CCFSZ + TF_O3]
	stx	%i4, [%sp + SPOFF + CCFSZ + TF_O4]
	stx	%i5, [%sp + SPOFF + CCFSZ + TF_O5]
	stx	%i6, [%sp + SPOFF + CCFSZ + TF_O6]
	stx	%i7, [%sp + SPOFF + CCFSZ + TF_O7]

.Ltl0_trap_reenter:
	stw	%o0, [%sp + SPOFF + CCFSZ + TF_TYPE]
	call	trap
	 add	%sp, CCFSZ + SPOFF, %o0
	b,a	%xcc, tl0_ret
	 nop
END(tl0_trap)

/*
 * void tl0_syscall(u_int type)
 */
ENTRY(tl0_syscall)
	/*
	 * Force kernel store order.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	rdpr	%tstate, %l0
	rdpr	%tpc, %l1
	rdpr	%tnpc, %l2
	rd	%y, %l3
	rd	%fprs, %l4
	rdpr	%wstate, %l5

#if KTR_COMPILE & KTR_SYSC
	CATR(KTR_SYSC,
	    "tl0_syscall: td=%p type=%#x pil=%#lx pc=%#lx npc=%#lx sp=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	stx	%o0, [%g1 + KTR_PARM2]
	rdpr	%pil, %g2
	stx	%g2, [%g1 + KTR_PARM3]
	stx	%l1, [%g1 + KTR_PARM4]
	stx	%l2, [%g1 + KTR_PARM5]
	stx	%i6, [%g1 + KTR_PARM6]
9:
#endif

	and	%l5, WSTATE_NORMAL_MASK, %l5
	sllx	%l5, WSTATE_OTHER_SHIFT, %l5
	wrpr	%l5, WSTATE_KERNEL, %wstate
	rdpr	%canrestore, %l6
	wrpr	%l6, 0, %otherwin
	wrpr	%g0, 0, %canrestore

	sub	PCB_REG, SPOFF + CCFSZ + TF_SIZEOF, %sp

	stw	%o0, [%sp + SPOFF + CCFSZ + TF_TYPE]

	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]
	stw	%l3, [%sp + SPOFF + CCFSZ + TF_Y]
	stb	%l4, [%sp + SPOFF + CCFSZ + TF_FPRS]
	stb	%l5, [%sp + SPOFF + CCFSZ + TF_WSTATE]

	wr	%g0, FPRS_FEF, %fprs
	stx	%fsr, [%sp + SPOFF + CCFSZ + TF_FSR]
	wr	%g0, 0, %fprs

	mov	PCB_REG, %l0
	mov	PCPU_REG, %l1
	wrpr	%g0, PSTATE_NORMAL, %pstate

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]
	stx	%g6, [%sp + SPOFF + CCFSZ + TF_G6]
	stx	%g7, [%sp + SPOFF + CCFSZ + TF_G7]

	mov	%l0, PCB_REG
	mov	%l1, PCPU_REG
	wrpr	%g0, PSTATE_KERNEL, %pstate

	stx	%i0, [%sp + SPOFF + CCFSZ + TF_O0]
	stx	%i1, [%sp + SPOFF + CCFSZ + TF_O1]
	stx	%i2, [%sp + SPOFF + CCFSZ + TF_O2]
	stx	%i3, [%sp + SPOFF + CCFSZ + TF_O3]
	stx	%i4, [%sp + SPOFF + CCFSZ + TF_O4]
	stx	%i5, [%sp + SPOFF + CCFSZ + TF_O5]
	stx	%i6, [%sp + SPOFF + CCFSZ + TF_O6]
	stx	%i7, [%sp + SPOFF + CCFSZ + TF_O7]

	call	syscall
	 add	%sp, CCFSZ + SPOFF, %o0
	b,a	%xcc, tl0_ret
	 nop
END(tl0_syscall)

/*
 * void tl0_intr(u_int level, u_int mask)
 */
ENTRY(tl0_intr)
	/*
	 * Force kernel store order.
	 */
	wrpr	%g0, PSTATE_ALT, %pstate

	rdpr	%tstate, %l0
	rdpr	%tpc, %l1
	rdpr	%tnpc, %l2
	rd	%y, %l3
	rd	%fprs, %l4
	rdpr	%wstate, %l5

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR,
	    "tl0_intr: td=%p level=%#x pil=%#lx pc=%#lx npc=%#lx sp=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	stx	%o0, [%g1 + KTR_PARM2]
	rdpr	%pil, %g2
	stx	%g2, [%g1 + KTR_PARM3]
	stx	%l1, [%g1 + KTR_PARM4]
	stx	%l2, [%g1 + KTR_PARM5]
	stx	%i6, [%g1 + KTR_PARM6]
9:
#endif

	wrpr	%o0, 0, %pil
	wr	%o1, 0, %asr21

	and	%l5, WSTATE_NORMAL_MASK, %l5
	sllx	%l5, WSTATE_OTHER_SHIFT, %l5
	wrpr	%l5, WSTATE_KERNEL, %wstate
	rdpr	%canrestore, %l6
	wrpr	%l6, 0, %otherwin
	wrpr	%g0, 0, %canrestore

	sub	PCB_REG, SPOFF + CCFSZ + TF_SIZEOF, %sp

	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]
	stw	%l3, [%sp + SPOFF + CCFSZ + TF_Y]
	stb	%l4, [%sp + SPOFF + CCFSZ + TF_FPRS]
	stb	%l5, [%sp + SPOFF + CCFSZ + TF_WSTATE]

	wr	%g0, FPRS_FEF, %fprs
	stx	%fsr, [%sp + SPOFF + CCFSZ + TF_FSR]
	wr	%g0, 0, %fprs

	mov	%o0, %l3
	mov	T_INTERRUPT, %o1

	stw	%o0, [%sp + SPOFF + CCFSZ + TF_LEVEL]
	stw	%o1, [%sp + SPOFF + CCFSZ + TF_TYPE]

	mov	PCB_REG, %l0
	mov	PCPU_REG, %l1
	wrpr	%g0, PSTATE_NORMAL, %pstate

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]
	stx	%g6, [%sp + SPOFF + CCFSZ + TF_G6]
	stx	%g7, [%sp + SPOFF + CCFSZ + TF_G7]

	mov	%l0, PCB_REG
	mov	%l1, PCPU_REG
	wrpr	%g0, PSTATE_KERNEL, %pstate

	stx	%i0, [%sp + SPOFF + CCFSZ + TF_O0]
	stx	%i1, [%sp + SPOFF + CCFSZ + TF_O1]
	stx	%i2, [%sp + SPOFF + CCFSZ + TF_O2]
	stx	%i3, [%sp + SPOFF + CCFSZ + TF_O3]
	stx	%i4, [%sp + SPOFF + CCFSZ + TF_O4]
	stx	%i5, [%sp + SPOFF + CCFSZ + TF_O5]
	stx	%i6, [%sp + SPOFF + CCFSZ + TF_O6]
	stx	%i7, [%sp + SPOFF + CCFSZ + TF_O7]

	call	critical_enter
	 nop

	SET(cnt+V_INTR, %l1, %l0)
	ATOMIC_INC_INT(%l0, %l1, %l2)

	SET(intr_handlers, %l1, %l0)
	sllx	%l3, IH_SHIFT, %l1
	ldx	[%l0 + %l1], %l1
	KASSERT(%l1, "tl0_intr: ih null")
	call	%l1
	 add	%sp, CCFSZ + SPOFF, %o0

	call	critical_exit
	 nop

	b,a	%xcc, tl0_ret
	 nop
END(tl0_intr)

ENTRY(tl0_ret)
#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl0_ret: check ast td=%p (%s) pil=%#lx sflag=%#x"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	ldx	[%g2 + TD_PROC], %g2
	add	%g2, P_COMM, %g3
	stx	%g3, [%g1 + KTR_PARM2]
	rdpr	%pil, %g3
	stx	%g3, [%g1 + KTR_PARM3]
	lduw	[%g2 + P_SFLAG], %g3
	stx	%g3, [%g1 + KTR_PARM4]
9:
#endif

	/*
	 * Check for pending asts atomically with returning.  We must raise
	 * the pil before checking, and if no asts are found the pil must
	 * remain raised until the retry is executed, or we risk missing asts
	 * caused by interrupts occuring after the test.  If the pil is lowered,
	 * as it is when we call ast, the check must be re-executed.
	 */
1:	wrpr	%g0, PIL_TICK, %pil
	ldx	[PCPU(CURTHREAD)], %l0
	ldx	[%l0 + TD_KSE], %l1
	lduw	[%l1 + KE_FLAGS], %l2
	and	%l2, KEF_ASTPENDING | KEF_NEEDRESCHED, %l2
	brz,a,pt %l2, 2f
	 nop
	wrpr	%g0, 0, %pil
	call	ast
	 add	%sp, CCFSZ + SPOFF, %o0
	ba,a	%xcc, 1b
	 nop

	/*
	 * Check for windows that were spilled to the pcb and need to be
	 * copied out.  This must be the last thing that is done before the
	 * return to usermode.  If there are still user windows in the cpu
	 * and we call a nested function after this, which causes them to be
	 * spilled to the pcb, they will not be copied out and the stack will
	 * be inconsistent.
	 */
2:	ldx	[PCB_REG + PCB_NSAVED], %l1
	mov	T_SPILL, %o0
	brnz,a,pn %l1, .Ltl0_trap_reenter
	 wrpr	%g0, 0, %pil

	ldx	[%sp + SPOFF + CCFSZ + TF_O0], %i0
	ldx	[%sp + SPOFF + CCFSZ + TF_O1], %i1
	ldx	[%sp + SPOFF + CCFSZ + TF_O2], %i2
	ldx	[%sp + SPOFF + CCFSZ + TF_O3], %i3
	ldx	[%sp + SPOFF + CCFSZ + TF_O4], %i4
	ldx	[%sp + SPOFF + CCFSZ + TF_O5], %i5
	ldx	[%sp + SPOFF + CCFSZ + TF_O6], %i6
	ldx	[%sp + SPOFF + CCFSZ + TF_O7], %i7

	ldx	[%sp + SPOFF + CCFSZ + TF_TSTATE], %l0
	ldx	[%sp + SPOFF + CCFSZ + TF_TPC], %l1
	ldx	[%sp + SPOFF + CCFSZ + TF_TNPC], %l2
	lduw	[%sp + SPOFF + CCFSZ + TF_Y], %l3
	ldub	[%sp + SPOFF + CCFSZ + TF_FPRS], %l4
	ldub	[%sp + SPOFF + CCFSZ + TF_WSTATE], %l5

	wrpr	%g0, PSTATE_NORMAL, %pstate

	ldx	[%sp + SPOFF + CCFSZ + TF_G1], %g1
	ldx	[%sp + SPOFF + CCFSZ + TF_G2], %g2
	ldx	[%sp + SPOFF + CCFSZ + TF_G3], %g3
	ldx	[%sp + SPOFF + CCFSZ + TF_G4], %g4
	ldx	[%sp + SPOFF + CCFSZ + TF_G5], %g5
	ldx	[%sp + SPOFF + CCFSZ + TF_G6], %g6
	ldx	[%sp + SPOFF + CCFSZ + TF_G7], %g7

	wrpr	%g0, PSTATE_ALT, %pstate

	wrpr	%g0, 0, %pil
	wrpr	%l1, 0, %tpc
	wrpr	%l2, 0, %tnpc
	wr	%l3, 0, %y

	andn	%l0, TSTATE_CWP_MASK, %g1
	mov	%l4, %g2

	srlx	%l5, WSTATE_OTHER_SHIFT, %g3
	wrpr	%g3, WSTATE_TRANSITION, %wstate
	rdpr	%otherwin, %o0
	wrpr	%o0, 0, %canrestore
	wrpr	%g0, 0, %otherwin
	wrpr	%o0, 0, %cleanwin

	/*
	 * If this instruction causes a fill trap which fails to fill a window
	 * from the user stack, we will resume at tl0_ret_fill_end and call
	 * back into the kernel.
	 */
	restore
tl0_ret_fill:

	rdpr	%cwp, %g4
	wrpr	%g1, %g4, %tstate
	wr	%g2, 0, %fprs
	wrpr	%g3, 0, %wstate

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl0_ret: td=%#lx pil=%#lx pc=%#lx npc=%#lx sp=%#lx"
	    , %g2, %g3, %g4, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g3
	stx	%g3, [%g2 + KTR_PARM1]
	rdpr	%pil, %g3
	stx	%g3, [%g2 + KTR_PARM2]
	rdpr	%tpc, %g3
	stx	%g3, [%g2 + KTR_PARM3]
	rdpr	%tnpc, %g3
	stx	%g3, [%g2 + KTR_PARM4]
	stx	%sp, [%g2 + KTR_PARM5]
9:
#endif

	retry
tl0_ret_fill_end:

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl0_ret: fill magic ps=%#lx ws=%#lx sp=%#lx"
	    , %l0, %l1, %l2, 7, 8, 9)
	rdpr	%pstate, %l1
	stx	%l1, [%l0 + KTR_PARM1]
	stx	%l5, [%l0 + KTR_PARM2]
	stx	%sp, [%l0 + KTR_PARM3]
9:
#endif

	/*
	 * The fill failed and magic has been performed.  Call trap again,
	 * which will copyin the window on the user's behalf.
	 */
	wrpr	%l5, 0, %wstate
	wrpr	%g0, PSTATE_ALT, %pstate
	mov	PCB_REG, %o0
	mov	PCPU_REG, %o1
	wrpr	%g0, PSTATE_NORMAL, %pstate
	mov	%o0, PCB_REG
	mov	%o1, PCPU_REG
	wrpr	%g0, PSTATE_KERNEL, %pstate
	b	%xcc, .Ltl0_trap_reenter
	 mov	T_FILL_RET, %o0
END(tl0_ret)

/*
 * Kernel trap entry point
 *
 * void tl1_trap(u_int type, u_long o1, u_long o2, u_long tar, u_long sfar,
 *		 u_int sfsr)
 *
 * This is easy because the stack is already setup and the windows don't need
 * to be split.  We build a trapframe and call trap(), the same as above, but
 * the outs don't need to be saved.
 */
ENTRY(tl1_trap)
	sub	%sp, TF_SIZEOF, %sp

	rdpr	%tstate, %l0
	rdpr	%tpc, %l1
	rdpr	%tnpc, %l2
	rdpr	%pil, %l3
	rd	%y, %l4
	rdpr	%wstate, %l5

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl1_trap: td=%p type=%#lx pil=%#lx pc=%#lx sp=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	stx	%o0, [%g1 + KTR_PARM2]
	stx	%l3, [%g1 + KTR_PARM3]
	stx	%l1, [%g1 + KTR_PARM4]
	stx	%i6, [%g1 + KTR_PARM5]
9:
#endif

	wrpr	%g0, 1, %tl

	and	%l5, WSTATE_OTHER_MASK, %l5
	wrpr	%l5, WSTATE_KERNEL, %wstate

	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]
	stb	%l3, [%sp + SPOFF + CCFSZ + TF_PIL]
	stw	%l4, [%sp + SPOFF + CCFSZ + TF_Y]

	stw	%o0, [%sp + SPOFF + CCFSZ + TF_TYPE]
	stx	%o3, [%sp + SPOFF + CCFSZ + TF_TAR]
	stx	%o4, [%sp + SPOFF + CCFSZ + TF_SFAR]
	stw	%o5, [%sp + SPOFF + CCFSZ + TF_SFSR]

	stx	%i6, [%sp + SPOFF + CCFSZ + TF_O6]
	stx	%i7, [%sp + SPOFF + CCFSZ + TF_O7]

	mov	PCB_REG, %l4
	mov	PCPU_REG, %l5
	wrpr	%g0, PSTATE_NORMAL, %pstate

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]

	mov	%l4, PCB_REG
	mov	%l5, PCPU_REG
	wrpr	%g0, PSTATE_KERNEL, %pstate

	call	trap
	 add	%sp, CCFSZ + SPOFF, %o0

	ldx	[%sp + SPOFF + CCFSZ + TF_TSTATE], %l0
	ldx	[%sp + SPOFF + CCFSZ + TF_TPC], %l1
	ldx	[%sp + SPOFF + CCFSZ + TF_TNPC], %l2
	ldub	[%sp + SPOFF + CCFSZ + TF_PIL], %l3
	lduw	[%sp + SPOFF + CCFSZ + TF_Y], %l4

	ldx	[%sp + SPOFF + CCFSZ + TF_G1], %g1
	ldx	[%sp + SPOFF + CCFSZ + TF_G2], %g2
	ldx	[%sp + SPOFF + CCFSZ + TF_G3], %g3
	ldx	[%sp + SPOFF + CCFSZ + TF_G4], %g4
	ldx	[%sp + SPOFF + CCFSZ + TF_G5], %g5

	wrpr	%g0, PSTATE_ALT, %pstate

	andn	%l0, TSTATE_CWP_MASK, %g1
	mov	%l1, %g2
	mov	%l2, %g3

	wrpr	%l3, 0, %pil
	wr	%l4, 0, %y

	restore

	wrpr	%g0, 2, %tl

	rdpr	%cwp, %g4
	wrpr	%g1, %g4, %tstate
	wrpr	%g2, 0, %tpc
	wrpr	%g3, 0, %tnpc

#if KTR_COMPILE & KTR_TRAP
	CATR(KTR_TRAP, "tl1_trap: td=%#lx pil=%#lx ts=%#lx pc=%#lx sp=%#lx"
	    , %g2, %g3, %g4, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g3
	stx	%g3, [%g2 + KTR_PARM1]
	rdpr	%pil, %g3
	stx	%g3, [%g2 + KTR_PARM2]
	rdpr	%tstate, %g3
	stx	%g3, [%g2 + KTR_PARM3]
	rdpr	%tpc, %g3
	stx	%g3, [%g2 + KTR_PARM4]
	stx	%sp, [%g2 + KTR_PARM5]
9:
#endif

	retry
END(tl1_trap)

/*
 * void tl1_intr(u_int level, u_int mask)
 */
ENTRY(tl1_intr)
	sub	%sp, TF_SIZEOF, %sp

	rdpr	%tstate, %l0
	rdpr	%tpc, %l1
	rdpr	%tnpc, %l2
	rdpr	%pil, %l3
	rd	%y, %l4
	rdpr	%wstate, %l5

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR,
	    "tl1_intr: td=%p level=%#lx pil=%#lx pc=%#lx sp=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	stx	%o0, [%g1 + KTR_PARM2]
	stx	%l3, [%g1 + KTR_PARM3]
	stx	%l1, [%g1 + KTR_PARM4]
	stx	%i6, [%g1 + KTR_PARM5]
9:
#endif

	wrpr	%o0, 0, %pil
	wr	%o1, 0, %asr21

	wrpr	%g0, 1, %tl

	and	%l5, WSTATE_OTHER_MASK, %l5
	wrpr	%l5, WSTATE_KERNEL, %wstate

	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]
	stb	%l3, [%sp + SPOFF + CCFSZ + TF_PIL]
	stw	%l4, [%sp + SPOFF + CCFSZ + TF_Y]

	mov	%o0, %l7
	mov	T_INTERRUPT | T_KERNEL, %o1

	stw	%o0, [%sp + SPOFF + CCFSZ + TF_LEVEL]
	stw	%o1, [%sp + SPOFF + CCFSZ + TF_TYPE]

	stx	%i6, [%sp + SPOFF + CCFSZ + TF_O6]
	stx	%i7, [%sp + SPOFF + CCFSZ + TF_O7]

	mov	PCB_REG, %l4
	mov	PCPU_REG, %l5
	wrpr	%g0, PSTATE_NORMAL, %pstate

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]

	mov	%l4, PCB_REG
	mov	%l5, PCPU_REG
	wrpr	%g0, PSTATE_KERNEL, %pstate

	call	critical_enter
	 nop

	SET(cnt+V_INTR, %l5, %l4)
	ATOMIC_INC_INT(%l4, %l5, %l6)

	SET(intr_handlers, %l5, %l4)
	sllx	%l7, IH_SHIFT, %l5
	ldx	[%l4 + %l5], %l5
	KASSERT(%l5, "tl1_intr: ih null")
	call	%l5
	 add	%sp, CCFSZ + SPOFF, %o0

	call	critical_exit
	 nop

	lduw	[%sp + SPOFF + CCFSZ + TF_Y], %l4

	ldx	[%sp + SPOFF + CCFSZ + TF_G1], %g1
	ldx	[%sp + SPOFF + CCFSZ + TF_G2], %g2
	ldx	[%sp + SPOFF + CCFSZ + TF_G3], %g3
	ldx	[%sp + SPOFF + CCFSZ + TF_G4], %g4
	ldx	[%sp + SPOFF + CCFSZ + TF_G5], %g5

	wrpr	%g0, PSTATE_ALT, %pstate

	andn	%l0, TSTATE_CWP_MASK, %g1
	mov	%l1, %g2
	mov	%l2, %g3
	wrpr	%l3, 0, %pil
	wr	%l4, 0, %y

	restore

	wrpr	%g0, 2, %tl

	rdpr	%cwp, %g4
	wrpr	%g1, %g4, %tstate
	wrpr	%g2, 0, %tpc
	wrpr	%g3, 0, %tnpc

#if KTR_COMPILE & KTR_INTR
	CATR(KTR_INTR, "tl1_intr: td=%#lx pil=%#lx ts=%#lx pc=%#lx sp=%#lx"
	    , %g2, %g3, %g4, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g3
	stx	%g3, [%g2 + KTR_PARM1]
	rdpr	%pil, %g3
	stx	%g3, [%g2 + KTR_PARM2]
	rdpr	%tstate, %g3
	stx	%g3, [%g2 + KTR_PARM3]
	rdpr	%tpc, %g3
	stx	%g3, [%g2 + KTR_PARM4]
	stx	%sp, [%g2 + KTR_PARM5]
9:
#endif

	retry
END(tl1_intr)

/*
 * Freshly forked processes come here when switched to for the first time.
 * The arguments to fork_exit() have been setup in the locals, we must move
 * them to the outs.
 */
ENTRY(fork_trampoline)
#if KTR_COMPILE & KTR_PROC
	CATR(KTR_PROC, "fork_trampoline: td=%p (%s) cwp=%#lx"
	    , %g1, %g2, %g3, 7, 8, 9)
	ldx	[PCPU(CURTHREAD)], %g2
	stx	%g2, [%g1 + KTR_PARM1]
	ldx	[%g2 + TD_PROC], %g2
	add	%g2, P_COMM, %g2
	stx	%g2, [%g1 + KTR_PARM2]
	rdpr	%cwp, %g2
	stx	%g2, [%g1 + KTR_PARM3]
9:
#endif
	mov	%l0, %o0
	mov	%l1, %o1
	call	fork_exit
	 mov	%l2, %o2
	b,a	%xcc, tl0_ret
	 nop
END(fork_trampoline)
