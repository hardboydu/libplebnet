/*-
 * Copyright (c) 1982, 1990 The Regents of the University of California.
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
 *	from: @(#)genassym.c	5.11 (Berkeley) 5/10/91
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <machine/frame.h>
#include <machine/chipset.h>
#include <sys/vmmeter.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#define _KERNEL	/* Avoid userland compatability headers */
#include <sys/user.h>
#undef _KERNEL
#include <net/if.h>
#include <netinet/in.h>
#include <nfs/nfsv2.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/nfsdiskless.h>

int	main __P((void));
int	printf __P((const char *, ...));

#define BIG(val)	((val) > 999LL || (val) < -999LL)

#define P(name, val) \
	printf(BIG(val) ? "#define\t%s 0x%llx\n" : "#define\t%s %lld\n", name, val)

#define OFF(name, type, elem)	P(#name, (long long) &((type*)0)->elem)
#define CONST2(name, val)	P(#name, (long long) val)
#define CONST1(name)		P(#name, (long long) name)

int
main()
{
	OFF(P_ADDR,		struct proc,	p_addr);
	OFF(P_MD_FLAGS,		struct proc,	p_md.md_flags);
	OFF(P_MD_PCBPADDR,	struct proc,	p_md.md_pcbpaddr);
	OFF(P_MD_HAE,		struct proc,	p_md.md_hae);
	CONST1(MDP_HAEUSED);

	OFF(CHIPSET_WRITE_HAE,	struct alpha_chipset, write_hae);

	CONST1(VM_MAXUSER_ADDRESS);
	CONST1(PTLEV1I);
	CONST1(PTESIZE);

	OFF(U_PCB_ONFAULT,	struct user,	u_pcb.pcb_onfault);
	OFF(U_PCB_HWPCB_KSP,	struct user,	u_pcb.pcb_hw.apcb_ksp);
	OFF(U_PCB_CONTEXT,	struct user,	u_pcb.pcb_context);

	OFF(PCB_HW,		struct pcb,	pcb_hw);

	OFF(FPREG_FPR_REGS,	struct fpreg,	fpr_regs);
	OFF(FPREG_FPR_CR,	struct fpreg,	fpr_cr);

	CONST1(EFAULT);
	CONST1(ENAMETOOLONG);

	/* Register offsets, for stack frames. */
	CONST1(FRAME_V0),
	CONST1(FRAME_T0),
	CONST1(FRAME_T1),
	CONST1(FRAME_T2),
	CONST1(FRAME_T3),
	CONST1(FRAME_T4),
	CONST1(FRAME_T5),
	CONST1(FRAME_T6),
	CONST1(FRAME_T7),
	CONST1(FRAME_S0),
	CONST1(FRAME_S1),
	CONST1(FRAME_S2),
	CONST1(FRAME_S3),
	CONST1(FRAME_S4),
	CONST1(FRAME_S5),
	CONST1(FRAME_S6),
	CONST1(FRAME_A3),
	CONST1(FRAME_A4),
	CONST1(FRAME_A5),
	CONST1(FRAME_T8),
	CONST1(FRAME_T9),
	CONST1(FRAME_T10),
	CONST1(FRAME_T11),
	CONST1(FRAME_RA),
	CONST1(FRAME_T12),
	CONST1(FRAME_AT),
	CONST1(FRAME_SP),

	CONST1(FRAME_SW_SIZE),

	CONST1(FRAME_PS),
	CONST1(FRAME_PC),
	CONST1(FRAME_GP),
	CONST1(FRAME_A0),
	CONST1(FRAME_A1),
	CONST1(FRAME_A2),

	CONST1(FRAME_SIZE),

	/* bits of the PS register */
	CONST1(ALPHA_PSL_USERMODE);
	CONST1(ALPHA_PSL_IPL_MASK);
	CONST1(ALPHA_PSL_IPL_0);
	CONST1(ALPHA_PSL_IPL_SOFT);
	CONST1(ALPHA_PSL_IPL_HIGH);

	/* pte bits */
	CONST1(ALPHA_L1SHIFT);
	CONST1(ALPHA_L2SHIFT);
	CONST1(ALPHA_L3SHIFT);
	CONST1(ALPHA_K1SEG_BASE);
	CONST1(ALPHA_PTE_VALID);
	CONST1(ALPHA_PTE_ASM);
	CONST1(ALPHA_PTE_KR);
	CONST1(ALPHA_PTE_KW);

	/* Kernel entries */
	CONST1(ALPHA_KENTRY_ARITH);
	CONST1(ALPHA_KENTRY_MM);

	CONST1(ALPHA_KENTRY_IF);
	CONST1(ALPHA_KENTRY_UNA);

	CONST1(VPTBASE);

	return (0);
}
