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
#include <machine/trap.h>

#include "assym.s"

/*
 * This is more or less relatively straight forward, except for the register
 * window handling, which can get ugly.
 * There are two situations where this can happen:
 * - a normal (non spill/fill) trap from user space, where the windows are
 *   still filled with user data
 * - a trap in a spill/fill trap handler that spills/fills userland windows
 * In both cases, the spills of the user data may fault in a way that requires
 * the C fault handler to be invoked, which needs a register window, so we would
 * try to spill again... ad infinitum.
 * The traps in question are dmmu_miss, dmmu_prot (both possibly fatal),
 * data_access and alignment (fatal).
 * So, on entry from user space, we set up a special %wstate (to handle a
 * possible spill triggered by the first save), and later set %otherwin to
 * split the window between kernel windows and user windows.
 * The spill handler that is called with this %wstate or %otherwin != 0 spills
 * to pcb_wscratch, indexed by %cwp, and notes the number of spilled registers
 * in pcb_ws_inuse. Elements of pcb_wstate that are in use are marked by setting
 * the wsf_inuse field. When the trap has completed, %otherwin is set so that
 * user space spills/fills for windows that are still stored in pcb_wscratch are
 * handled by directly filling from pcb_wscratch or spilling from pcb_wscratch
 * to user space.
 */

#define	SPILL(storer, base, asi, struct) \
	storer	%l0, [base + struct ## _L0] asi ; \
	storer	%l1, [base + struct ## _L1] asi ; \
	storer	%l2, [base + struct ## _L2] asi ; \
	storer	%l3, [base + struct ## _L3] asi ; \
	storer	%l4, [base + struct ## _L4] asi ; \
	storer	%l5, [base + struct ## _L5] asi ; \
	storer	%l6, [base + struct ## _L6] asi ; \
	storer	%l7, [base + struct ## _L7] asi ; \
	storer	%i0, [base + struct ## _I0] asi ; \
	storer	%i1, [base + struct ## _I1] asi ; \
	storer	%i2, [base + struct ## _I2] asi ; \
	storer	%i3, [base + struct ## _I3] asi ; \
	storer	%i4, [base + struct ## _I4] asi ; \
	storer	%i5, [base + struct ## _I5] asi ; \
	storer	%i6, [base + struct ## _I6] asi ; \
	storer	%i7, [base + struct ## _I7] asi

#define	FILL(loader, base, asi, struct) \
	loader	[base + struct ## _L0] asi, %l0 ; \
	loader	[base + struct ## _L1] asi, %l1 ; \
	loader	[base + struct ## _L2] asi, %l2 ; \
	loader	[base + struct ## _L3] asi, %l3 ; \
	loader	[base + struct ## _L4] asi, %l4 ; \
	loader	[base + struct ## _L5] asi, %l5 ; \
	loader	[base + struct ## _L6] asi, %l6 ; \
	loader	[base + struct ## _L7] asi, %l7 ; \
	loader	[base + struct ## _I0] asi, %i0 ; \
	loader	[base + struct ## _I1] asi, %i1 ; \
	loader	[base + struct ## _I2] asi, %i2 ; \
	loader	[base + struct ## _I3] asi, %i3 ; \
	loader	[base + struct ## _I4] asi, %i4 ; \
	loader	[base + struct ## _I5] asi, %i5 ; \
	loader	[base + struct ## _I6] asi, %i6 ; \
	loader	[base + struct ## _I7] asi, %i7

DATA(intrnames)
	.asciz	"foo"
DATA(eintrnames)

DATA(intrcnt)
	.long	0
DATA(eintrcnt)

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

	/* Fixups for kernel entry from tl0. */

	/*
	 * Split the register window using %otherwin. This is an optimization
	 * to not have to flush all the register windows on kernel entry.
	 * Set %wstate so that spills go to the pcb; this is valid because there
	 * is always at least one frame.
	 * A spill with %wstate == 1 will invoke the same spill handler
	 * regardless of %otherwin (tl1_spill_1_n and tl1_spill_0_o are the
	 * same).
	 * Before the next save (that is, in tl0_trap_*), we finish the
	 * splitting setup and set %otherwin correctly.
	 * Note that the alternate %g7 must always be valid in places where we
	 * could spill.
	 */
	.macro	tl0_split_save
	wrpr	%g0, 1, %wstate
	save
	.endm

	/*
	 * Flush out all but one of the user windows to the pcb register
	 * window scratch space. At the end of the trap, the windows are
	 * restored.
	 */
	.macro	tl0_flush_save
	wrpr	%g0, 1, %wstate
	save
	flushw
	wrpr	%g0, 0, %wstate
	.endm

	/*
	 * Setup the kernel stack when faulting from user space.
	 */
	.macro	tl0_setup_stack	tmp1, sz
	/* Set up the kernel stack. */
	setx	UPAGES * PAGE_SIZE - SPOFF - CCFSZ - TF_SIZEOF - \sz, \tmp1, %sp
	ldx	[PCPU(CURPCB)], \tmp1
	add	%sp, \tmp1, %sp
	.endm	

	.macro	tl0_gen		type
	tl0_split_save
	rdpr	%pil, %o0
	b	%xcc, tl0_trap
	 mov	\type, %o1
	.align	32
	.endm

	.macro	tl0_wide	type
	tl0_split_save
	rdpr	%pil, %o0
	b	%xcc, tl0_trap
	 mov	\type, %o1
	.align	128
	.endm

	.macro	tl0_reserved	count
	.rept	\count
	tl0_gen	T_RESERVED
	.endr
	.endm

	.macro	tl0_align
	rdpr	%pstate, %g1
	wrpr	%g1, PSTATE_MG | PSTATE_AG, %pstate
	b	%xcc, tl0_sfsr_trap
	 mov	T_ALIGN, %g4
	.align	32
	.endm

/*
 * This must be called with MMU globals active, otherwise the spill handler
 * might clobber the globals we use to transfer the sfar and sfsr.
 */
ENTRY(tl0_sfsr_trap)
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g1
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g2
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	tl0_split_save
	mov	%g1, %l1
	mov	%g2, %l2
	mov	%g4, %o1
	rdpr	%pstate, %l3
	wrpr	%l3, PSTATE_MG | PSTATE_AG, %pstate
	tl0_setup_stack	%l0, MF_SIZEOF
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_SFAR]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_SFSR]
	rdpr	%pil, %o0
	b	%xcc, tl0_trap_withstack
	 add	%sp, SPOFF + CCFSZ + TF_SIZEOF, %o2
END(tl0_sfsr_trap)

	.macro	tl0_intr level, mask, type
	tl0_split_save
	set	\level, %o3
	set	\mask, %o2
	b	%xcc, tl0_intr_call_trap
	 mov	\type, %o1
	.align	32
	.endm

/*
 * Actually call tl0_trap, and do some work that cannot be done in tl0_intr
 * because of space constraints.
 */
ENTRY(tl0_intr_call_trap)
	rdpr	%pil, %o0
	wrpr	%g0, %o3, %pil
	b	%xcc, tl0_trap
	 wr	%o2, 0, %asr21
END(tl0_intr_call_trap)

#define	INTR(level, traplvl)						\
	tl ## traplvl ## _intr	level, 1 << level,			\
	    T_INTR | (level << T_LEVEL_SHIFT)

#define	TICK(traplvl) \
	tl ## traplvl ## _intr	14, 1, T_INTR | (14 << T_LEVEL_SHIFT)

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

	.macro	tl0_intr_vector
	b,a	intr_enqueue
	.align	32
	.endm

	.macro	tl0_immu_miss
	/*
	 * Extract the 8KB pointer and convert to an index.
	 */
	ldxa	[%g0] ASI_IMMU_TSB_8KB_PTR_REG, %g1	
	srax	%g1, TTE_SHIFT, %g1

	/*
	 * Compute the stte address in the primary used tsb.
	 */
	and	%g1, (1 << TSB_PRIMARY_MASK_WIDTH) - 1, %g2
	sllx	%g2, TSB_PRIMARY_STTE_SHIFT, %g2
	setx	TSB_USER_MIN_ADDRESS, %g4, %g3
	add	%g2, %g3, %g2

	/*
	 * Preload the tte tag target.
	 */
	ldxa	[%g0] ASI_IMMU_TAG_TARGET_REG, %g3

	/*
	 * Preload tte data bits to check inside the bucket loop.
	 */
	and	%g1, TD_VA_LOW_MASK >> TD_VA_LOW_SHIFT, %g4
	sllx	%g4, TD_VA_LOW_SHIFT, %g4
	or	%g4, TD_EXEC, %g4

	/*
	 * Preload mask for tte data check.
	 */
	setx	TD_VA_LOW_MASK, %g5, %g1
	or	%g1, TD_EXEC, %g1

	/*
	 * Loop over the sttes in this bucket
	 */

	/*
	 * Load the tte.
	 */
1:	ldda	[%g2] ASI_NUCLEUS_QUAD_LDD, %g6

	/*
	 * Compare the tag.
	 */
	cmp	%g6, %g3
	bne,pn	%xcc, 2f

	/*
	 * Compare the data.
	 */
	 xor	%g7, %g4, %g5
	brgez,pn %g7, 2f
	 andcc	%g5, %g1, %g0
	bnz,pn	%xcc, 2f

	/*
	 * We matched a tte, load the tlb.
	 */

	/*
	 * Set the reference bit, if it's currently clear.
	 */
	 andcc	%g7, TD_REF, %g0
	bz,a,pn	%xcc, immu_miss_user_set_ref
	 nop

	/*
	 * Load the tte data into the tlb and retry the instruction.
	 */
	stxa	%g7, [%g0] ASI_ITLB_DATA_IN_REG
	retry

	/*
	 * Check the low bits to see if we've finished the bucket.
	 */
2:	add	%g2, STTE_SIZEOF, %g2
	andcc	%g2, TSB_PRIMARY_STTE_MASK, %g0
	bnz	%xcc, 1b
	 nop
	b,a	%xcc, immu_miss_user_call_trap
	.align	128
	.endm

ENTRY(immu_miss_user_set_ref)
	/*
	 * Set the reference bit.
	 */
	add	%g2, TTE_DATA, %g2
1:	or	%g7, TD_REF, %g1
	casxa	[%g2] ASI_N, %g7, %g1
	cmp	%g1, %g7
	bne,a,pn %xcc, 1b
	 mov	%g1, %g7

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g1, 2f
	 nop

	/*
	 * Load the tte data into the tlb and retry the instruction.
	 */
	stxa	%g1, [%g0] ASI_ITLB_DATA_IN_REG
2:	retry
END(immu_miss_user_set_ref)

ENTRY(immu_miss_user_call_trap)
	/*
	 * Load the tar, sfar and sfsr aren't valid.
	 */
	mov	AA_IMMU_TAR, %g1
	ldxa	[%g1] ASI_IMMU, %g1

	/*
	 * Save the mmu registers on the stack, switch to alternate globals,
	 * and call common trap code.
	 */
	tl0_split_save
	mov	%g1, %l1
	rdpr	%pstate, %l3
	wrpr	%l3, PSTATE_AG | PSTATE_MG, %pstate
	tl0_setup_stack	%l0, MF_SIZEOF
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_TAR]
	rdpr	%pil, %o0
	mov	T_IMMU_MISS, %o1
	b	%xcc, tl0_trap_withstack
	 add	%sp, SPOFF + CCFSZ + TF_SIZEOF, %o2
END(immu_miss_user_call_trap)

	.macro	dmmu_miss_user
	/*
	 * Extract the 8KB pointer and convert to an index.
	 */
	ldxa	[%g0] ASI_DMMU_TSB_8KB_PTR_REG, %g1	
	srax	%g1, TTE_SHIFT, %g1

	/*
	 * Compute the stte address in the primary used tsb.
	 */
	and	%g1, (1 << TSB_PRIMARY_MASK_WIDTH) - 1, %g2
	sllx	%g2, TSB_PRIMARY_STTE_SHIFT, %g2
	setx	TSB_USER_MIN_ADDRESS, %g4, %g3
	add	%g2, %g3, %g2

	/*
	 * Preload the tte tag target.
	 */
	ldxa	[%g0] ASI_DMMU_TAG_TARGET_REG, %g3

	/*
	 * Preload tte data bits to check inside the bucket loop.
	 */
	and	%g1, TD_VA_LOW_MASK >> TD_VA_LOW_SHIFT, %g4
	sllx	%g4, TD_VA_LOW_SHIFT, %g4

	/*
	 * Preload mask for tte data check.
	 */
	setx	TD_VA_LOW_MASK, %g5, %g1

	/*
	 * Loop over the sttes in this bucket
	 */

	/*
	 * Load the tte.
	 */
1:	ldda	[%g2] ASI_NUCLEUS_QUAD_LDD, %g6

	/*
	 * Compare the tag.
	 */
	cmp	%g6, %g3
	bne,pn	%xcc, 2f

	/*
	 * Compare the data.
	 */
	 xor	%g7, %g4, %g5
	brgez,pn %g7, 2f
	 andcc	%g5, %g1, %g0
	bnz,pn	%xcc, 2f

	/*
	 * We matched a tte, load the tlb.
	 */

	/*
	 * Set the reference bit, if it's currently clear.
	 */
	 andcc	%g7, TD_REF, %g0
	bz,a,pn	%xcc, dmmu_miss_user_set_ref
	 nop

	/*
	 * If the mod bit is clear, clear the write bit too.
	 */
	andcc	%g7, TD_MOD, %g1
	movz	%xcc, TD_W, %g1
	andn	%g7, %g1, %g7

	/*
	 * Load the tte data into the tlb and retry the instruction.
	 */
	stxa	%g7, [%g0] ASI_DTLB_DATA_IN_REG
	retry

	/*
	 * Check the low bits to see if we've finished the bucket.
	 */
2:	add	%g2, STTE_SIZEOF, %g2
	andcc	%g2, TSB_PRIMARY_STTE_MASK, %g0
	bnz	%xcc, 1b
	 nop
	.endm

ENTRY(dmmu_miss_user_set_ref)
	/*
	 * Set the reference bit.
	 */
	add	%g2, TTE_DATA, %g2
1:	or	%g7, TD_REF, %g1
	casxa	[%g2] ASI_N, %g7, %g1
	cmp	%g1, %g7
	bne,a,pn %xcc, 1b
	 mov	%g1, %g7

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g1, 2f
	 nop

	/*
	 * If the mod bit is clear, clear the write bit too.
	 */
	andcc	%g1, TD_MOD, %g2
	movz	%xcc, TD_W, %g2
	andn	%g1, %g2, %g1

	/*
	 * Load the tte data into the tlb and retry the instruction.
	 */
	stxa	%g1, [%g0] ASI_DTLB_DATA_IN_REG
2:	retry
END(dmmu_miss_user_set_ref)

	.macro	tl0_dmmu_miss
	/*
	 * Try a fast inline lookup of the primary tsb.
	 */
	dmmu_miss_user

	/*
	 * Not in primary tsb, call c code.  Nothing else fits inline.
	 */
	b,a	tl0_dmmu_miss_trap
	.align	128
	.endm

ENTRY(tl0_dmmu_miss_trap)
	/*
	 * Load the tar, sfar and sfsr aren't valid.
	 */
	mov	AA_DMMU_TAR, %g1
	ldxa	[%g1] ASI_DMMU, %g1

	/*
	 * Save the mmu registers on the stack, switch to alternate globals,
	 * and call common trap code.
	 */
	tl0_split_save
	mov	%g1, %l1
	rdpr	%pstate, %l3
	wrpr	%l3, PSTATE_AG | PSTATE_MG, %pstate
	tl0_setup_stack	%l0, MF_SIZEOF
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_TAR]
	rdpr	%pil, %o0
	mov	T_DMMU_MISS, %o1
	b	%xcc, tl0_trap_withstack
	 add	%sp, SPOFF + CCFSZ + TF_SIZEOF, %o2
END(tl0_dmmu_miss_trap)

	.macro	dmmu_prot_user
	/*
	 * Extract the 8KB pointer and convert to an index.
	 */
	ldxa	[%g0] ASI_DMMU_TSB_8KB_PTR_REG, %g1	
	srax	%g1, TTE_SHIFT, %g1

	/*
	 * Compute the stte address in the primary used tsb.
	 */
	and	%g1, (1 << TSB_PRIMARY_MASK_WIDTH) - 1, %g2
	sllx	%g2, TSB_PRIMARY_STTE_SHIFT, %g2
	setx	TSB_USER_MIN_ADDRESS, %g4, %g3
	add	%g2, %g3, %g2

	/*
	 * Preload the tte tag target.
	 */
	ldxa	[%g0] ASI_DMMU_TAG_TARGET_REG, %g3

	/*
	 * Preload tte data bits to check inside the bucket loop.
	 */
	and	%g1, TD_VA_LOW_MASK >> TD_VA_LOW_SHIFT, %g4
	sllx	%g4, TD_VA_LOW_SHIFT, %g4

	/*
	 * Preload mask for tte data check.
	 */
	setx	TD_VA_LOW_MASK, %g5, %g1
	or	%g1, TD_W, %g1

	/*
	 * Loop over the sttes in this bucket
	 */

	/*
	 * Load the tte.
	 */
1:	ldda	[%g2] ASI_NUCLEUS_QUAD_LDD, %g6

	/*
	 * Compare the tag.
	 */
	cmp	%g6, %g3
	bne,pn	%xcc, 2f

	/*
	 * Compare the data.
	 */
	 xor	%g7, %g4, %g5
	brgez,pn %g7, 2f
	 andcc	%g5, %g1, %g0

	/*
	 * On a match, jump to code to finish up.
	 */
	bz,pn	%xcc, dmmu_prot_user_set_mod
	 nop

	/*
	 * Check the low bits to see if we've finished the bucket.
	 */
2:	add	%g2, STTE_SIZEOF, %g2
	andcc	%g2, TSB_PRIMARY_STTE_MASK, %g0
	bnz	%xcc, 1b
	 nop
	.endm

ENTRY(dmmu_prot_user_set_mod)
	/*
	 * Set the modify bit.
	 */
	add	%g2, TTE_DATA, %g2
1:	or	%g7, TD_MOD, %g1
	casxa	[%g2] ASI_N, %g7, %g1
	cmp	%g1, %g7
	bne,a,pn %xcc, 1b
	 mov	%g1, %g7

	/*
	 * Delete the old tsb entry.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g3
	andn	%g3, PAGE_MASK, %g3
	stxa	%g0, [%g3] ASI_DMMU_DEMAP

	/*
	 * May have become invalid, in which case start over.
	 */
	brgez,pn %g1, 2f
	 nop

	/*
	 * Load the tte data into the tlb, clear the sfsr and retry the
	 * instruction.
	 */
	stxa	%g1, [%g0] ASI_DTLB_DATA_IN_REG
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
2:	retry
END(dmmu_prot_user_set_mod)

	.macro	tl0_dmmu_prot
	/*
	 * Try a fast inline lookup of the primary tsb.
	 */
	dmmu_prot_user

	/*
	 * Not in primary tsb, call c code.  Nothing else fits inline.
	 */
	b,a	tl0_dmmu_prot_trap
	.align	128
	.endm

ENTRY(tl0_dmmu_prot_trap)
	/*
	 * Load the tar, sfar and sfsr.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g2
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g1
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	/*
	 * Save the mmu registers on the stack, switch to alternate globals,
	 * and call common trap code.
	 */
	tl0_split_save
	mov	%g1, %l1
	mov	%g2, %l2
	mov	%g3, %l3
	rdpr	%pstate, %l4
	wrpr	%l4, PSTATE_AG | PSTATE_MG, %pstate
	tl0_setup_stack	%l0, MF_SIZEOF
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_TAR]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_SFAR]
	stx	%l3, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_SFSR]
	rdpr	%pil, %o0
	mov	T_DMMU_PROT, %o1
	b	%xcc, tl0_trap_withstack
	 add	%sp, SPOFF + CCFSZ + TF_SIZEOF, %o2
END(tl0_dmmu_prot_trap)

	.macro	tl0_spill_0_n
	ldx	[PCPU(CURPCB)], %g1
	stx	%g1, [%g1 + PCB_INWINOP]	! something != 0
	wr	%g0, ASI_AIUP, %asi
	SPILL(stxa, %sp + SPOFF, %asi, F)
	stx	%g0, [%g1 + PCB_INWINOP]
	saved
	retry
	.align	128
	.endm

	.macro	tl0_spill_0_o
	b,a	tl0_spill_frompcb
	.align	128
	.endm	

#define LDSTA(tmp, from, to)						\
	ldx	[from], tmp ;						\
	stxa	tmp, [to] %asi

/*
 * A window that was spilled to the pcb during the last trap, was marked with
 * %otherwin, but was not filled back in again yet. In this case, we need to
 * spill the data from the pcb directly to user space. Traps while writing to
 * user space are handled as normally.
 */
ENTRY(tl0_spill_frompcb)
	ldx	[PCPU(CURPCB)], %g1
	/* We may fault while spilling to user space, prepare for that. */
	stx	%g1, [%g1 + PCB_INWINOP]	! something != 0
	rdpr	%cwp, %g2
	mulx	%g2, WSF_SIZEOF, %g3
	add	%g1, %g3, %g3
	ldx	[%g3 + PCB_WSCRATCH + WSF_SP], %g4
	wr	%g0, ASI_AIUP, %asi
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I0, %g4 + SPOFF + F_I0)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I1, %g4 + SPOFF + F_I1)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I2, %g4 + SPOFF + F_I2)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I3, %g4 + SPOFF + F_I3)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I4, %g4 + SPOFF + F_I4)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I5, %g4 + SPOFF + F_I5)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I6, %g4 + SPOFF + F_I6)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_I7, %g4 + SPOFF + F_I7)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L0, %g4 + SPOFF + F_L0)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L1, %g4 + SPOFF + F_L1)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L2, %g4 + SPOFF + F_L2)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L3, %g4 + SPOFF + F_L3)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L4, %g4 + SPOFF + F_L4)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L5, %g4 + SPOFF + F_L5)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L6, %g4 + SPOFF + F_L6)
	LDSTA(%g2, %g3 + PCB_WSCRATCH + WSF_L7, %g4 + SPOFF + F_L7)
	stx	%g0, [%g1 + PCB_INWINOP]
	/* wscratch window becomes unused. */
	stx	%g0, [%g3 + WSF_INUSE] 
	rdpr	%otherwin, %g4
	sub	%g4, 1, %g4
	stx	%g4, [%g1 + PCB_WS_INUSE]
	saved
	retry
END(tl0_spill_frompcb)

	.macro	tl0_spill_bad	count
	.rept	\count
	tl0_wide T_SPILL
	.endr
	.endm

	.macro	tl0_fill_0_n
	ldx	[PCPU(CURPCB)], %g1
	stx	%g1, [%g1 + PCB_INWINOP]	! something != 0
	wr	%g0, ASI_AIUP, %asi
	FILL(ldxa, %sp + SPOFF, %asi, F)
	stx	%g0, [%g1 + PCB_INWINOP]
	restored
	retry
	.align	128
	.endm

	.macro	tl0_fill_0_o
	ldx	[PCPU(CURPCB)], %g1
	rdpr	%cwp, %g2
	mulx	%g2, WSF_SIZEOF, %g3
	add	%g1, %g3, %g3
	FILL(ldx, %g3 + PCB_WSCRATCH, EMPTY, WSF)
	/* wscratch window becomes unused. */
	stx	%g0, [%g3 + PCB_WSCRATCH + WSF_INUSE] 
	rdpr	%otherwin, %g4
	sub	%g4, 1, %g4
	stx	%g4, [%g1 + PCB_WS_INUSE]
	restored
	retry
	.align	128
	.endm	

	.macro	tl0_fill_bad	count
	.rept	\count
	tl0_wide T_FILL
	.endr
	.endm

	.macro	tl0_soft	count
	tl0_reserved \count
	.endm

	.macro	tl1_gen		type
	save	%sp, -CCFSZ, %sp
	rdpr	%pil, %o0
	b	%xcc, tl1_trap
	 mov	\type | T_KERNEL, %o1
	.align	32
	.endm

	.macro	tl1_wide	type
	save	%sp, -CCFSZ, %sp
	rdpr	%pil, %o0
	b	%xcc, tl1_trap
	 mov	\type | T_KERNEL, %o1
	.align	128
	.endm

	.macro	tl1_reserved	count
	.rept	\count
	tl1_gen	T_RESERVED
	.endr
	.endm

	.macro	tl1_insn_excptn
	save	%sp, -CCFSZ, %sp
	rdpr	%pstate, %o0
	wrpr	%o0, PSTATE_MG | PSTATE_AG, %pstate
	rdpr	%pil, %o0
	b	%xcc, tl1_trap
	 mov	T_INSN_EXCPTN | T_KERNEL, %o1
	.align	32
	.endm

	.macro	tl1_data_excptn
	b	%xcc, tl1_sfsr_trap
	 mov	T_DATA_EXCPTN, %g4
	.align	32
	.endm

	.macro	tl1_align
	rdpr	%pstate, %g1
	wrpr	%g1, PSTATE_MG | PSTATE_AG, %pstate	
	b	%xcc, tl1_sfsr_trap
	 mov	T_ALIGN, %g4
	.align	32
	.endm

/*
 * Handle traps that require only sfsr and sfar to be saved. %g4 holds the trap
 * type to be used (T_KERNEL is set if appropriate).
 * Call with memory globals active.
 */
ENTRY(tl1_sfsr_trap)
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g2
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g3
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync
	/* Fall through. */
END(tl1_sfsr_trap)

/*
 * Handle traps that require MMU frames to be written. The values for TAR, SFAR
 * and SFSR are passed in %g1, %g2 and %g3, respectively.
 * All traps that may happen during spill/fill for user processes should be
 * handled here.
 * %g4 contains the trap type, T_KERNEL is set if appropriate.
 */
ENTRY(tl1_mmu_trap)
	/* Handle faults during window spill/fill. */
	mov	%o1, %g5
	mov	%o2, %g6
	rdpr	%pstate, %o1
	wrpr	%o1, PSTATE_MG | PSTATE_AG, %pstate
	ldx	[PCPU(CURPCB)], %o2
	ldx	[%o2 + PCB_INWINOP], %o2
	rdpr	%pstate, %o1
	wrpr	%o1, PSTATE_MG | PSTATE_AG, %pstate
	mov	%g5, %o1
	brz,pt	%o2, 1f
	 mov	%g6, %o2

	wrpr	1, %tl		! go to tl 1
	 rdpr	%tstate, %g5
	and	%g5, TSTATE_CWP_MASK, %g5
	wrpr	%g5, %cwp
	tl0_split_save
	mov	%g1, %l1
	mov	%g2, %l2
	mov	%g3, %l3
	mov	%g4, %o1
	rdpr	%pstate, %l4
	wrpr	%l4, PSTATE_MG | PSTATE_AG, %pstate
	tl0_setup_stack	%l0, MF_SIZEOF
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_TAR]
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_SFAR]
	stx	%l3, [%sp + SPOFF + CCFSZ + TF_SIZEOF + MF_SFSR]
	rdpr	%pil, %o0
	b	%xcc, tl0_trap_withstack
	 add	%sp, SPOFF + CCFSZ + TF_SIZEOF, %o2

1:	save	%sp, -(CCFSZ + MF_SIZEOF), %sp
	stx	%g1, [%sp + SPOFF + CCFSZ + MF_TAR]
	stx	%g2, [%sp + SPOFF + CCFSZ + MF_SFAR]
	stx	%g3, [%sp + SPOFF + CCFSZ + MF_SFSR]
	or	%g4, T_KERNEL, %o1
	rdpr	%pstate, %g1
	wrpr	%g1, PSTATE_MG | PSTATE_AG, %pstate
	rdpr	%pil, %o0
	b	%xcc, tl1_trap
	 add	%sp, SPOFF + CCFSZ, %o2
END(tl1_mmu_trap)

	.macro	tl1_intr level, mask, type
	save	%sp, -CCFSZ, %sp
	rdpr	%pil, %o0
	wrpr	%g0, \level, %pil
	set	\mask, %o2
	wr	%o2, 0, %asr21
	b	%xcc, tl1_trap
	 mov	\type | T_KERNEL, %o1
	.align	32
	.endm

	.macro	tl1_intr_level
	INTR_LEVEL(1)
	.endm

	.macro	tl1_intr_vector
	b,a	intr_enqueue
	.align	32
	.endm

ENTRY(intr_enqueue)
	/*
	 * Find the head of the queue and advance it.
	 */
	ldx	[PCPU(IQ)], %g1
	ldx	[%g1 + IQ_HEAD], %g2
	add	%g2, 1, %g3
	and	%g3, IQ_MASK, %g3
	stx	%g3, [%g1 + IQ_HEAD]

	/*
	 * If the new head is the same as the tail, the next interrupt will
	 * overwrite unserviced packets.  This is bad.
	 */
	ldx	[%g1 + IQ_TAIL], %g4
	cmp	%g4, %g3
	be	%xcc, 3f
	 nop

	/*
	 * Load the interrupt packet from the hardware.
	 */
	wr	%g0, ASI_SDB_INTR_R, %asi
	ldxa	[%g0] ASI_INTR_RECEIVE, %g3
	ldxa	[%g0 + AA_SDB_INTR_D0] %asi, %g4
	ldxa	[%g0 + AA_SDB_INTR_D1] %asi, %g5
	ldxa	[%g0 + AA_SDB_INTR_D2] %asi, %g6
	stxa	%g0, [%g0] ASI_INTR_RECEIVE
	membar	#Sync

	/*
	 * Store the tag and first data word in the iqe.  These are always
	 * valid.
	 */
	sllx	%g2, IQE_SHIFT, %g2
	add	%g2, %g1, %g2
	stw	%g3, [%g2 + IQE_TAG]
	stx	%g4, [%g2 + IQE_VEC]

	/*
	 * Find the interrupt vector associated with this source.
	 */
	ldx	[PCPU(IVT)], %g3
	sllx	%g4, IV_SHIFT, %g4

	/*
	 * If the 2nd data word, the function, is zero the actual function
	 * and argument are in the interrupt vector table, so retrieve them.
	 * The function is used as a lock on the vector data.  If it can be
	 * read atomically as non-zero, the argument and priority are valid.
	 * Otherwise this is either a true stray interrupt, or someone is
	 * trying to deregister the source as we speak.  In either case,
	 * bail and log a stray.
	 */
	brnz,pn %g5, 1f
	 add	%g3, %g4, %g3
	casxa	[%g3] ASI_N, %g0, %g5
	brz,pn	%g5, 2f
	 ldx	[%g3 + IV_ARG], %g6

	/*
	 * Save the priority and the two remaining data words in the iqe.
	 */
1:	lduw	[%g3 + IV_PRI], %g4
	stw	%g4, [%g2 + IQE_PRI]
	stx	%g5, [%g2 + IQE_FUNC]
	stx	%g6, [%g2 + IQE_ARG]

	/*
	 * Trigger a softint at the level indicated by the priority.
	 */
	mov	1, %g3
	sllx	%g3, %g4, %g3
	wr	%g3, 0, %asr20
	retry

	/*
	 * Either this is a true stray interrupt, or an interrupt occured
	 * while the source was being deregistered.  In either case, just
	 * log the stray and return.  XXX
	 */
2:	DEBUGGER()

	/*
	 * The interrupt queue is about to overflow.  We are in big trouble.
	 */
3:	DEBUGGER()
END(intr_enqueue)

	.macro	tl1_immu_miss
	save	%sp, -CCFSZ, %sp
	rdpr	%pstate, %o0
	wrpr	%o0, PSTATE_MG | PSTATE_AG, %pstate
	rdpr	%pil, %o0
	b	%xcc, tl1_trap
	 mov	T_IMMU_MISS | T_KERNEL, %o1
	.align	128
	.endm

	.macro	tl1_dmmu_miss
	/*
	 * Load the target tte tag, and extract the context.  If the context
	 * is non-zero handle as user space access.  In either case, load the
	 * tsb 8k pointer.
	 */
	ldxa	[%g0] ASI_DMMU_TAG_TARGET_REG, %g1
	srlx	%g1, TT_CTX_SHIFT, %g2
	brnz,pn	%g2, tl1_dmmu_miss_user
	 ldxa	[%g0] ASI_DMMU_TSB_8KB_PTR_REG, %g2

	/*
	 * Convert the tte pointer to an stte pointer, and add extra bits to
	 * accomodate for large tsb.
	 */
	sllx	%g2, STTE_SHIFT - TTE_SHIFT, %g2
#ifdef notyet
	mov	AA_DMMU_TAR, %g3
	ldxa	[%g3] ASI_DMMU, %g3
	srlx	%g3, TSB_1M_STTE_SHIFT, %g3
	and	%g3, TSB_KERNEL_MASK >> TSB_1M_STTE_SHIFT, %g3
	sllx	%g3, TSB_1M_STTE_SHIFT, %g3
	add	%g2, %g3, %g2
#endif

	/*
	 * Load the tte, check that it's valid and that the tags match.
	 */
	ldda	[%g2] ASI_NUCLEUS_QUAD_LDD, %g4 /*, %g5 */
	brgez,pn %g5, 2f
	 cmp	%g4, %g1
	bne	%xcc, 2f
	 EMPTY

	/*
	 * Set the refence bit, if its currently clear.
	 */
	andcc	%g5, TD_REF, %g0
	bnz	%xcc, 1f
	 or	%g5, TD_REF, %g1
	stx	%g1, [%g2 + ST_TTE + TTE_DATA]

	/*
	 * If the mod bit is clear, clear the write bit too.
	 */
1:	andcc	%g5, TD_MOD, %g1
	movz	%xcc, TD_W, %g1
	andn	%g5, %g1, %g5

	/*
	 * Load the tte data into the TLB and retry the instruction.
	 */
	stxa	%g5, [%g0] ASI_DTLB_DATA_IN_REG
	retry

2:	b,a	%xcc, tl1_dmmu_miss_trap
	.align	128
	.endm

ENTRY(tl1_dmmu_miss_user)
	/*
	 * Try a fast inline lookup of the primary tsb.
	 */
	dmmu_miss_user

	/* Fallthrough. */
END(tl1_dmmu_miss_user)

ENTRY(tl1_dmmu_miss_trap)
	/*
	 * Not in primary tsb, call c code.
	 * Load the tar, sfar and sfsr aren't valid.
	 */
	mov	AA_DMMU_TAR, %g1
	ldxa	[%g1] ASI_DMMU, %g1
	b	%xcc, tl1_mmu_trap
	 mov	T_DMMU_MISS, %g4
END(tl1_dmmu_miss_user)

	.macro	tl1_dmmu_prot
	/*
	 * Load the target tte tag, and extract the context.  If the context
	 * is non-zero handle as user space access.  In either case, load the
	 * tsb 8k pointer.
	 */
	ldxa	[%g0] ASI_DMMU_TAG_TARGET_REG, %g1
	srlx	%g1, TT_CTX_SHIFT, %g2
	brnz,pn	%g2, tl1_dmmu_prot_user
	 ldxa	[%g0] ASI_DMMU_TSB_8KB_PTR_REG, %g2

	/*
	 * Convert the tte pointer to an stte pointer, and add extra bits to
	 * accomodate for large tsb.
	 */
	sllx	%g2, STTE_SHIFT - TTE_SHIFT, %g2
#ifdef notyet
	mov	AA_DMMU_TAR, %g3
	ldxa	[%g3] ASI_DMMU, %g3
	srlx	%g3, TSB_1M_STTE_SHIFT, %g3
	and	%g3, TSB_KERNEL_MASK >> TSB_1M_STTE_SHIFT, %g3
	sllx	%g3, TSB_1M_STTE_SHIFT, %g3
	add	%g2, %g3, %g2
#endif

	/*
	 * Load the tte, check that it's valid, writeable, and that the
	 * tags match.
	 */
	ldda	[%g2] ASI_NUCLEUS_QUAD_LDD, %g4
	brgez,pn %g5, 2f
	 andcc	%g5, TD_W, %g0
	bz,pn	%xcc, 2f
	 cmp	%g4, %g1
	bne	%xcc, 2f
	 EMPTY

	/*
	 * Set the mod bit in the tte.
	 */
	or	%g5, TD_MOD, %g5
	stx	%g5, [%g2 + TTE_DATA]

	/*
	 * Delete the old tlb entry.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g6
	or	%g6, TLB_DEMAP_NUCLEUS, %g6
	stxa	%g0, [%g6] ASI_DMMU_DEMAP

	/*
	 * Load the tte data into the tlb, clear the sfsr and retry the
	 * instruction.
	 */
	stxa	%g5, [%g0] ASI_DTLB_DATA_IN_REG
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	retry

	/*
	 * For now just bail.  This might cause a red state exception,
	 * but oh well.
	 */
2:	DEBUGGER()
	.align	128
	.endm

ENTRY(tl1_dmmu_prot_user)
	/*
	 * Try a fast inline lookup of the primary tsb.
	 */
	dmmu_prot_user

	/*
	 * Not in primary tsb, call c code.
	 * Load the sfar, sfsr and tar.  Clear the sfsr.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[%g0 + AA_DMMU_SFAR] %asi, %g2
	ldxa	[%g0 + AA_DMMU_SFSR] %asi, %g3
	ldxa	[%g0 + AA_DMMU_TAR] %asi, %g1
	stxa	%g0, [%g0 + AA_DMMU_SFSR] %asi
	membar	#Sync

	b	%xcc, tl1_mmu_trap
	 mov	T_DMMU_PROT, %g4
END(tl1_dmmu_prot_user)

	.macro	tl1_spill_0_n
	SPILL(stx, %sp + SPOFF, EMPTY, F)
	saved
	retry
	.align	128
	.endm

	.macro	tl1_spill_1_n
	b,a	tl1_spill_topcb
	.align	128
	.endm

	/*
	 * The following is equivalent to tl1_spill_1_n and is used for
	 * splitting.
	 */
	.macro	tl1_spill_0_o
	tl1_spill_1_n
	.endm
	
/*
 * This is used to spill windows that are still occupied with user
 * data on kernel entry to the pcb using tl0_flush_save.
 */
ENTRY(tl1_spill_topcb)
	/* Free some globals for our use. */
	sub	%g6, 32, %g6
	stx	%g1, [%g6]
	stx	%g2, [%g6 + 8]
	stx	%g3, [%g6 + 16]
	stx	%g4, [%g6 + 24]
	ldx	[PCPU(CURPCB)], %g1
	rdpr	%cwp, %g2
	mulx	%g2, WSF_SIZEOF, %g3
	add	%g1, %g3, %g3
	ldx	[%g3 + PCB_WSCRATCH + WSF_INUSE], %g4
	brnz,pn	%g4, 1f			! window was already spilled to pcb
	 stx	%g1, [%g3 + PCB_WSCRATCH + WSF_INUSE]	! just write sth. != 0
	stx	%sp, [%g3 + PCB_WSCRATCH + WSF_SP]
	SPILL(stx, %g3 + PCB_WSCRATCH, EMPTY, WSF)
	ldx	[%g1 + PCB_WS_INUSE], %g4
	add	%g4, 1, %g4
	stx	%g4, [%g1 + PCB_WS_INUSE]
1:	ldx	[%g6], %g1
	ldx	[%g6 + 8], %g2
	ldx	[%g6 + 16], %g3
	ldx	[%g6 + 24], %g4
	add	%g6, 32, %g6
	saved
	retry
END(tl1_spill_topcb)

	.macro	tl1_spill_bad	count
	.rept	\count
	tl1_wide T_SPILL
	.endr
	.endm

	.macro	tl1_fill_0_n
	FILL(ldx, %sp + SPOFF, EMPTY, F)
	restored
	retry
	.align	128
	.endm

	.macro	tl1_fill_1_n
	b,a	tl1_fill_frompcb
	.align	128
	.endm

	/* Same as tl1_fill_1_n, used for splitting. */
	.macro	tl1_fill_0_o
	tl1_fill_1_n
	.endm

/*
 * This is invoked only once when a user process is in the kernel:
 * to restore the topmost window on user return. We just look up whether
 * the window at %cwp was already spilled to the pcb (as inducated by the
 * wsf_inuse flag). If so, we indeed need to fill from the pcb, otherwise the
 * window is valid and we can just return.
 */
ENTRY(tl1_fill_frompcb)
	/* Free some globals for our use. */
	sub	%g6, 32, %g6
	stx	%g1, [%g6]
	stx	%g2, [%g6 + 8]
	stx	%g3, [%g6 + 16]
	stx	%g4, [%g6 + 24]
	ldx	[PCPU(CURPCB)], %g1
	rdpr	%cwp, %g2
	mulx	%g2, WSF_SIZEOF, %g3
	add	%g1, %g3, %g3
	ldx	[%g3 + PCB_WSCRATCH + WSF_INUSE], %g4
	brz,pn	%g4, 1f			! window not spilled and is valid
	 stx	%g0, [%g3 + PCB_WSCRATCH + WSF_INUSE]
	FILL(ldx, %g3 + PCB_WSCRATCH, EMPTY, WSF)
	ldx	[%g1 + PCB_WS_INUSE], %g4
	sub	%g4, 1, %g4
	stx	%g4, [%g1 + PCB_WS_INUSE]
	/* Restore the registers. */
1:	ldx	[%g6], %g1
	ldx	[%g6 + 8], %g2
	ldx	[%g6 + 16], %g3
	ldx	[%g6 + 24], %g4
	add	%g6, 32, %g6
	restored
	retry
END(tl1_fill_frompcb)

	.macro	tl1_fill_bad	count
	.rept	\count
	tl1_wide T_FILL
	.endr
	.endm

	.macro	tl1_breakpoint
	b,a	%xcc, tl1_breakpoint_trap
	.align	32
	.endm

ENTRY(tl1_breakpoint_trap)
	save	%sp, -(CCFSZ + KF_SIZEOF), %sp
	flushw
	stx	%fp, [%sp + SPOFF + CCFSZ + KF_FP]
	rdpr	%pil, %o0
	mov	T_BREAKPOINT | T_KERNEL, %o1
	b	%xcc, tl1_trap
	 add	%sp, SPOFF + CCFSZ, %o2
END(tl1_breakpoint_trap)

	.macro	tl1_soft	count
	tl1_reserved \count
	.endm

	.sect	.trap
	.align	0x8000
	.globl	tl0_base

tl0_base:
	tl0_reserved	1		! 0x0 unused
tl0_power_on:
	tl0_gen		T_POWER_ON	! 0x1 power on reset
tl0_watchdog:
	tl0_gen		T_WATCHDOG	! 0x2 watchdog rest
tl0_reset_ext:
	tl0_gen		T_RESET_EXT	! 0x3 externally initiated reset
tl0_reset_soft:
	tl0_gen		T_RESET_SOFT	! 0x4 software initiated reset
tl0_red_state:
	tl0_gen		T_RED_STATE	! 0x5 red state exception
	tl0_reserved	2		! 0x6-0x7 reserved
tl0_insn_excptn:
	tl0_gen		T_INSN_EXCPTN	! 0x8 instruction access exception
	tl0_reserved	1		! 0x9 reserved
tl0_insn_error:
	tl0_gen		T_INSN_ERROR	! 0xa instruction access error
	tl0_reserved	5		! 0xb-0xf reserved
tl0_insn_illegal:
	tl0_gen		T_INSN_ILLEGAL	! 0x10 illegal instruction
tl0_priv_opcode:
	tl0_gen		T_PRIV_OPCODE	! 0x11 privileged opcode
	tl0_reserved	14		! 0x12-0x1f reserved
tl0_fp_disabled:
	tl0_gen		T_FP_DISABLED	! 0x20 floating point disabled
tl0_fp_ieee:
	tl0_gen		T_FP_IEEE	! 0x21 floating point exception ieee
tl0_fp_other:
	tl0_gen		T_FP_OTHER	! 0x22 floating point exception other
tl0_tag_ovflw:
	tl0_gen		T_TAG_OVFLW	! 0x23 tag overflow
tl0_clean_window:
	clean_window			! 0x24 clean window
tl0_divide:
	tl0_gen		T_DIVIDE	! 0x28 division by zero
	tl0_reserved	7		! 0x29-0x2f reserved
tl0_data_excptn:
	tl0_gen		T_DATA_EXCPTN	! 0x30 data access exception
	tl0_reserved	1		! 0x31 reserved
tl0_data_error:
	tl0_gen		T_DATA_ERROR	! 0x32 data access error
	tl0_reserved	1		! 0x33 reserved
tl0_align:
	tl0_align			! 0x34 memory address not aligned
tl0_align_lddf:
	tl0_gen		T_ALIGN_LDDF	! 0x35 lddf memory address not aligned
tl0_align_stdf:
	tl0_gen		T_ALIGN_STDF	! 0x36 stdf memory address not aligned
tl0_priv_action:
	tl0_gen		T_PRIV_ACTION	! 0x37 privileged action
	tl0_reserved	9		! 0x38-0x40 reserved
tl0_intr_level:
	tl0_intr_level			! 0x41-0x4f interrupt level 1 to 15
	tl0_reserved	16		! 0x50-0x5f reserved
tl0_intr_vector:
	tl0_intr_vector			! 0x60 interrupt vector
tl0_watch_phys:
	tl0_gen		T_WATCH_PHYS	! 0x61 physical address watchpoint
tl0_watch_virt:
	tl0_gen		T_WATCH_VIRT	! 0x62 virtual address watchpoint
tl0_ecc:
	tl0_gen		T_ECC		! 0x63 corrected ecc error
tl0_immu_miss:
	tl0_immu_miss			! 0x64 fast instruction access mmu miss
tl0_dmmu_miss:
	tl0_dmmu_miss			! 0x68 fast data access mmu miss
tl0_dmmu_prot:
	tl0_dmmu_prot			! 0x6c fast data access protection
	tl0_reserved	16		! 0x70-0x7f reserved
tl0_spill_0_n:
	tl0_spill_0_n			! 0x80 spill 0 normal
tl0_spill_bad_n:
	tl0_spill_bad	7		! 0x84-0x9f spill normal, other
tl0_spill_0_o:
	tl0_spill_0_o			! 0xa0 spill 0 other
tl0_spill_bad_o:
	tl0_spill_bad	7		! 0xa4-0xbf spill normal, other
tl0_fill_0_n:
	tl0_fill_0_n			! 0xc0 fill 0 normal
tl0_fill_bad_n:
	tl0_fill_bad	7		! 0xc4-0xdf fill normal
tl0_fill_0_o:
	tl0_fill_0_o			! 0xe0 fill 0 normal
tl0_fill_bad_o:
	tl0_fill_bad	7		! 0xe4-0xff fill other
tl0_sun_syscall:
	tl0_reserved	1		! 0x100 sun system call
tl0_breakpoint:
	tl0_gen		T_BREAKPOINT	! 0x101 breakpoint
	tl0_soft	7		! 0x102-0x107 trap instruction
	tl0_reserved			! 0x109 SVr4 syscall
	tl0_gen		T_SYSCALL	! 0x109 BSD syscall
	tl0_soft	118		! 0x110-0x17f trap instruction
	tl0_reserved	128		! 0x180-0x1ff reserved

tl1_base:
	tl1_reserved	1		! 0x200 unused
tl1_power_on:
	tl1_gen		T_POWER_ON	! 0x201 power on reset
tl1_watchdog:
	tl1_gen		T_WATCHDOG	! 0x202 watchdog rest
tl1_reset_ext:
	tl1_gen		T_RESET_EXT	! 0x203 externally initiated reset
tl1_reset_soft:
	tl1_gen		T_RESET_SOFT	! 0x204 software initiated reset
tl1_red_state:
	tl1_gen		T_RED_STATE	! 0x205 red state exception
	tl1_reserved	2		! 0x206-0x207 reserved
tl1_insn_excptn:
	tl1_insn_excptn			! 0x208 instruction access exception
	tl1_reserved	1		! 0x209 reserved
tl1_insn_error:
	tl1_gen		T_INSN_ERROR	! 0x20a instruction access error
	tl1_reserved	5		! 0x20b-0x20f reserved
tl1_insn_illegal:
	tl1_gen		T_INSN_ILLEGAL	! 0x210 illegal instruction
tl1_priv_opcode:
	tl1_gen		T_PRIV_OPCODE	! 0x211 privileged opcode
	tl1_reserved	14		! 0x212-0x21f reserved
tl1_fp_disabled:
	tl1_gen		T_FP_DISABLED	! 0x220 floating point disabled
tl1_fp_ieee:
	tl1_gen		T_FP_IEEE	! 0x221 floating point exception ieee
tl1_fp_other:
	tl1_gen		T_FP_OTHER	! 0x222 floating point exception other
tl1_tag_ovflw:
	tl1_gen		T_TAG_OVFLW	! 0x223 tag overflow
tl1_clean_window:
	clean_window			! 0x224 clean window
tl1_divide:
	tl1_gen		T_DIVIDE	! 0x228 division by zero
	tl1_reserved	7		! 0x229-0x22f reserved
tl1_data_excptn:
	tl1_data_excptn			! 0x230 data access exception
	tl1_reserved	1		! 0x231 reserved
tl1_data_error:
	tl1_gen		T_DATA_ERROR	! 0x232 data access error
	tl1_reserved	1		! 0x233 reserved
tl1_align:
	tl1_align			! 0x234 memory address not aligned
tl1_align_lddf:
	tl1_gen		T_ALIGN_LDDF	! 0x235 lddf memory address not aligned
tl1_align_stdf:
	tl1_gen		T_ALIGN_STDF	! 0x236 stdf memory address not aligned
tl1_priv_action:
	tl1_gen		T_PRIV_ACTION	! 0x237 privileged action
	tl1_reserved	9		! 0x238-0x240 reserved
tl1_intr_level:
	tl1_intr_level			! 0x241-0x24f interrupt level 1 to 15
	tl1_reserved	16		! 0x250-0x25f reserved
tl1_intr_vector:
	tl1_intr_vector			! 0x260 interrupt vector
tl1_watch_phys:
	tl1_gen		T_WATCH_PHYS	! 0x261 physical address watchpoint
tl1_watch_virt:
	tl1_gen		T_WATCH_VIRT	! 0x262 virtual address watchpoint
tl1_ecc:
	tl1_gen		T_ECC		! 0x263 corrected ecc error
tl1_immu_miss:
	tl1_immu_miss			! 0x264 fast instruction access mmu miss
tl1_dmmu_miss:
	tl1_dmmu_miss			! 0x268 fast data access mmu miss
tl1_dmmu_prot:
	tl1_dmmu_prot			! 0x26c fast data access protection
	tl1_reserved	16		! 0x270-0x27f reserved
tl1_spill_0_n:
	tl1_spill_0_n			! 0x280 spill 0 normal
tl1_spill_1_n:
	tl1_spill_1_n			! 0x284 spill 1 normal
tl1_spill_bad_n:
	tl1_spill_bad	6		! 0x288-0x29f spill normal
tl1_spill_0_o:
	tl1_spill_0_o			! 0x2a0 spill 0 other
tl1_spill_bad_o:
	tl1_spill_bad	7		! 0x2a8-0x2bf spill other
tl1_fill_0_n:
	tl1_fill_0_n			! 0x2c0 fill 0 normal
tl1_fill_1_n:
	tl1_fill_1_n			! 0x2c4 fill 1 normal
tl1_fill_bad_n:
	tl1_fill_bad	6		! 0x2c8-0x2df fill normal, other
tl1_fill_0_o:
	tl1_fill_0_o			! 0x2e0 fill 0 other
tl1_fill_bad_o:
	tl1_fill_bad	7		! 0x2e4-0x2ff fill other
	tl1_reserved	1		! 0x300 trap instruction
tl1_breakpoint:
	tl1_breakpoint			! 0x301 breakpoint
	tl1_gen		T_RESTOREWP	! 0x302 restore watchpoint (debug)
	tl1_soft	126		! 0x303-0x37f trap instruction
	tl1_reserved	128		! 0x380-0x3ff reserved

/*
 * void tl0_trap(u_long o0, u_long o1, u_long o2, u_long type)
 */
ENTRY(tl0_trap)
	tl0_setup_stack	%l0, 0
	/* Fallthrough */
END(tl0_trap)

ENTRY(tl0_trap_withstack)
	ldx	[PCPU(CURPCB)], %l1
	rdpr	%cwp, %l2
	stx	%l2, [%l1 + PCB_CWP]
	/* Finish setting up splitted windows. */
	wrpr	%g0, 0, %wstate
	rdpr	%canrestore, %l0
	rdpr	%otherwin, %l1
	add	%l0, %l1, %l0
	wrpr	%g0, 0, %canrestore
	wrpr	%l0, %otherwin
	
	rdpr	%tstate, %l0
	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	rdpr	%tpc, %l1
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	rdpr	%tnpc, %l2
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]

	mov	%g7, %l0
	rdpr	%pstate, %l1
	wrpr	%l1, PSTATE_AG, %pstate

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]
	stx	%g6, [%sp + SPOFF + CCFSZ + TF_G6]
	stx	%g7, [%sp + SPOFF + CCFSZ + TF_G7]

	mov	%l0, %g7	/* set up the normal %g7 */

	rdpr	%pstate, %l1
	wrpr	%l1, PSTATE_IE, %pstate

	stx	%i0, [%sp + SPOFF + CCFSZ + TF_O0]
	stx	%i1, [%sp + SPOFF + CCFSZ + TF_O1]
	stx	%i2, [%sp + SPOFF + CCFSZ + TF_O2]
	stx	%i3, [%sp + SPOFF + CCFSZ + TF_O3]
	stx	%i4, [%sp + SPOFF + CCFSZ + TF_O4]
	stx	%i5, [%sp + SPOFF + CCFSZ + TF_O5]
	stx	%i6, [%sp + SPOFF + CCFSZ + TF_O6]
	stx	%i7, [%sp + SPOFF + CCFSZ + TF_O7]

	stx	%o0, [%sp + SPOFF + CCFSZ + TF_PIL]
	stx	%o1, [%sp + SPOFF + CCFSZ + TF_TYPE]
	stx	%o2, [%sp + SPOFF + CCFSZ + TF_ARG]

	call	trap
	 add	%sp, CCFSZ + SPOFF, %o0
	
	/* Fallthough. */
END(tl0_trap_withstack)

/* Return to tl0 (user process). */
ENTRY(tl0_ret)
	ldx	[%sp + SPOFF + CCFSZ + TF_G1], %g1
	ldx	[%sp + SPOFF + CCFSZ + TF_G2], %g2
	ldx	[%sp + SPOFF + CCFSZ + TF_G3], %g3
	ldx	[%sp + SPOFF + CCFSZ + TF_G4], %g4
	ldx	[%sp + SPOFF + CCFSZ + TF_G5], %g5
	ldx	[%sp + SPOFF + CCFSZ + TF_G6], %g6
	ldx	[%sp + SPOFF + CCFSZ + TF_G7], %g7

	rdpr	%pstate, %o0
	wrpr	%o0, PSTATE_IE | PSTATE_AG, %pstate
	mov	%sp, %g1

	/*
	 * Restore the user window state.
	 * Note: whenever we come here, it should be with %canrestore = 0.
	 */
	ldx	[PCPU(CURPCB)], %g4
	ldx	[%g4 + PCB_CWP], %g2
	wrpr	%g2, %cwp

	/*
	 * Set up window state for restore. If all windows were spilled,
	 * %otherwin may be 0, so just set %wstate to 1 to invoke a
	 * special fill handler (fill traps with %wstate == 1 invoke the
	 * same handler regardless of %otherwin).
	 */
	wrpr	%g0, 1, %wstate
	restore		! This will invoke the otherwin fill handler.
	wrpr	%g0, 0, %wstate

	/* Set up window state for return. */
	ldx	[%g4 + PCB_WS_INUSE], %g2
	rdpr	%otherwin, %g3
	sub	%g3, %g2, %g3
	wrpr	%g2, 0, %otherwin
	movrlz	%g3, %g0, %g3
	wrpr	%g3, %canrestore
	add	%g2, %g3, %g2
	rdpr	%ver, %g3
	and	%g3, VER_MAXWIN_MASK, %g3
	sub	%g3, 1, %g3	! VER.MAXWIN is NWINDOWS - 1.
	sub	%g3, %g2, %g3
	wrpr	%g3, %cansave
	
	ldx	[%g1 + SPOFF + CCFSZ + TF_O0], %o0
	ldx	[%g1 + SPOFF + CCFSZ + TF_O1], %o1
	ldx	[%g1 + SPOFF + CCFSZ + TF_O2], %o2
	ldx	[%g1 + SPOFF + CCFSZ + TF_O3], %o3
	ldx	[%g1 + SPOFF + CCFSZ + TF_O4], %o4
	ldx	[%g1 + SPOFF + CCFSZ + TF_O5], %o5
	ldx	[%g1 + SPOFF + CCFSZ + TF_O6], %o6
	ldx	[%g1 + SPOFF + CCFSZ + TF_O7], %o7

	ldx	[%g1 + SPOFF + CCFSZ + TF_PIL], %g2
	wrpr	%g2, 0, %pil
	ldx	[%g1 + SPOFF + CCFSZ + TF_TSTATE], %g2
	andn	%g2, TSTATE_CWP_MASK, %g2
	rdpr	%cwp, %g3
	or	%g2, %g3, %g2
	wrpr	%g2, %tstate
	ldx	[%g1 + SPOFF + CCFSZ + TF_TPC], %g2
	wrpr	%g2, 0, %tpc
	ldx	[%g1 + SPOFF + CCFSZ + TF_TNPC], %g2
	wrpr	%g2, 0, %tnpc

	retry
END(tl0_ret)

/*
 * void tl1_trap(u_long o0, u_long o1, u_long o2, u_long type)
 */
ENTRY(tl1_trap)
	sub	%sp, TF_SIZEOF, %sp
	rdpr	%tstate, %l0
	stx	%l0, [%sp + SPOFF + CCFSZ + TF_TSTATE]
	rdpr	%tpc, %l1
	stx	%l1, [%sp + SPOFF + CCFSZ + TF_TPC]
	rdpr	%tnpc, %l2
	stx	%l2, [%sp + SPOFF + CCFSZ + TF_TNPC]

	wrpr	%g0, 1, %tl
	/* We may have trapped before %g7 was set up correctly. */
	mov	%g7, %l3
	rdpr	%pstate, %l0
	wrpr	%l0, PSTATE_AG, %pstate

	stx	%o0, [%sp + SPOFF + CCFSZ + TF_PIL]
	stx	%o1, [%sp + SPOFF + CCFSZ + TF_TYPE]
	stx	%o2, [%sp + SPOFF + CCFSZ + TF_ARG]

	stx	%g1, [%sp + SPOFF + CCFSZ + TF_G1]
	stx	%g2, [%sp + SPOFF + CCFSZ + TF_G2]
	stx	%g3, [%sp + SPOFF + CCFSZ + TF_G3]
	stx	%g4, [%sp + SPOFF + CCFSZ + TF_G4]
	stx	%g5, [%sp + SPOFF + CCFSZ + TF_G5]
	stx	%g6, [%sp + SPOFF + CCFSZ + TF_G6]
	stx	%g7, [%sp + SPOFF + CCFSZ + TF_G7]

	mov	%l3, %g7
	rdpr	%pstate, %l0
	wrpr	%l0, PSTATE_IE, %pstate
	
	call	trap
	 add	%sp, CCFSZ + SPOFF, %o0

	ldx	[%sp + SPOFF + CCFSZ + TF_G1], %g1
	ldx	[%sp + SPOFF + CCFSZ + TF_G2], %g2
	ldx	[%sp + SPOFF + CCFSZ + TF_G3], %g3
	ldx	[%sp + SPOFF + CCFSZ + TF_G4], %g4
	ldx	[%sp + SPOFF + CCFSZ + TF_G5], %g5
	ldx	[%sp + SPOFF + CCFSZ + TF_G6], %g6
	ldx	[%sp + SPOFF + CCFSZ + TF_G7], %g7

	ldx	[%sp + SPOFF + CCFSZ + TF_PIL], %l0
	ldx	[%sp + SPOFF + CCFSZ + TF_TSTATE], %l1
	ldx	[%sp + SPOFF + CCFSZ + TF_TPC], %l2
	ldx	[%sp + SPOFF + CCFSZ + TF_TNPC], %l3

	rdpr	%pstate, %o0
	andn	%o0, PSTATE_IE, %o0
	wrpr	%o0, 0, %pstate

	wrpr	%l0, 0, %pil

	wrpr	%g0, 2, %tl
	wrpr	%l1, 0, %tstate
	wrpr	%l2, 0, %tpc
	wrpr	%l3, 0, %tnpc

	restore
	retry
END(tl1_trap)

ENTRY(fork_trampoline)
	mov	%l0, %o0
	mov	%l1, %o1
	mov	%l2, %o2
	call	fork_exit
	 nop
	b,a	%xcc, tl0_ret
END(fork_trampoline)
