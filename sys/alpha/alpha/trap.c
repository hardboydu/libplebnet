/* $Id: trap.c,v 1.10 1998/12/30 10:38:58 dfr Exp $ */
/* $NetBSD: trap.c,v 1.31 1998/03/26 02:21:46 thorpej Exp $ */

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

/* #include "opt_fix_unaligned_vax_fp.h" */
#include "opt_ddb.h"
#include "opt_simos.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/vmmeter.h>
#include <sys/buf.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/pioctl.h>
#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_prot.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <machine/clock.h>
#include <machine/md_var.h>
#include <machine/reg.h>
#include <machine/pal.h>
#include <machine/fpu.h>

#ifdef DDB
#include <ddb/ddb.h>
#endif

struct proc *fpcurproc;		/* current user of the FPU */

void		userret __P((struct proc *, u_int64_t, u_quad_t));

unsigned long	Sfloat_to_reg __P((unsigned int));
unsigned int	reg_to_Sfloat __P((unsigned long));
unsigned long	Tfloat_reg_cvt __P((unsigned long));
#ifdef FIX_UNALIGNED_VAX_FP
unsigned long	Ffloat_to_reg __P((unsigned int));
unsigned int	reg_to_Ffloat __P((unsigned long));
unsigned long	Gfloat_reg_cvt __P((unsigned long));
#endif

int		unaligned_fixup __P((unsigned long, unsigned long,
		    unsigned long, struct proc *));

static void printtrap __P((const unsigned long, const unsigned long,
      const unsigned long, const unsigned long, struct trapframe *, int, int));
/*
 * Define the code needed before returning to user mode, for
 * trap and syscall.
 */
void
userret(p, pc, oticks)
	register struct proc *p;
	u_int64_t pc;
	u_quad_t oticks;
{
	int sig, s;

	/* take pending signals */
	while ((sig = CURSIG(p)) != 0)
		postsig(sig);
	p->p_priority = p->p_usrpri;
	if (want_resched) {
		/*
		 * Since we are curproc, a clock interrupt could
		 * change our priority without changing run queues
		 * (the running process is not kept on a run queue).
		 * If this happened after we setrunqueue ourselves but
		 * before we switch()'ed, we might not be on the queue
		 * indicated by our priority.
		 */
		s = splstatclock();
		setrunqueue(p);
		p->p_stats->p_ru.ru_nivcsw++;
		mi_switch();
		splx(s);
		while ((sig = CURSIG(p)) != 0)
			postsig(sig);
	}

	/*
	 * If profiling, charge recent system time to the trapped pc.
	 */
	if (p->p_flag & P_PROFIL) {
		addupc_task(p, pc, (int)(p->p_sticks - oticks) * psratio);
	}

	curpriority = p->p_priority;
}

static void
printtrap(a0, a1, a2, entry, framep, isfatal, user)
	const unsigned long a0, a1, a2, entry;
	struct trapframe *framep;
	int isfatal, user;
{
	char ubuf[64];
	const char *entryname;

	switch (entry) {
	case ALPHA_KENTRY_INT:
		entryname = "interrupt";
		break;
	case ALPHA_KENTRY_ARITH:
		entryname = "arithmetic trap";
		break;
	case ALPHA_KENTRY_MM:
		entryname = "memory management fault";
		break;
	case ALPHA_KENTRY_IF:
		entryname = "instruction fault";
		break;
	case ALPHA_KENTRY_UNA:
		entryname = "unaligned access fault";
		break;
	case ALPHA_KENTRY_SYS:
		entryname = "system call";
		break;
	default:
		snprintf(ubuf, sizeof(ubuf), "type %lx", entry);
		entryname = (const char *) ubuf;
		break;
	}

	printf("\n");
	printf("%s %s trap:\n", isfatal? "fatal" : "handled",
	       user ? "user" : "kernel");
	printf("\n");
	printf("    trap entry = 0x%lx (%s)\n", entry, entryname);
	printf("    a0         = 0x%lx\n", a0);
	printf("    a1         = 0x%lx\n", a1);
	printf("    a2         = 0x%lx\n", a2);
	printf("    pc         = 0x%lx\n", framep->tf_regs[FRAME_PC]);
	printf("    ra         = 0x%lx\n", framep->tf_regs[FRAME_RA]);
	printf("    curproc    = %p\n", curproc);
	if (curproc != NULL)
		printf("        pid = %d, comm = %s\n", curproc->p_pid,
		       curproc->p_comm);
	printf("\n");
}

/*
 * Trap is called from locore to handle most types of processor traps.
 * System calls are broken out for efficiency and ASTs are broken out
 * to make the code a bit cleaner and more representative of the
 * Alpha architecture.
 */
/*ARGSUSED*/
void
trap(a0, a1, a2, entry, framep)
	const unsigned long a0, a1, a2, entry;
	struct trapframe *framep;
{
	register struct proc *p;
	register int i;
	u_int64_t ucode;
	u_quad_t sticks;
	int user;

	cnt.v_trap++;
	p = curproc;
	ucode = 0;
	user = (framep->tf_regs[FRAME_PS] & ALPHA_PSL_USERMODE) != 0;
	if (user)  {
		sticks = p->p_sticks;
		p->p_md.md_tf = framep;
#if	0
/* This is to catch some wierd stuff on the UDB (mj) */
		if (framep->tf_regs[FRAME_PC] > 0 && 
		    framep->tf_regs[FRAME_PC] < 0x120000000) {
			printf("PC Out of Whack\n");
			printtrap(a0, a1, a2, entry, framep, 1, user);
		}
#endif
	} else {
		sticks = 0;		/* XXX bogus -Wuninitialized warning */
	}

	switch (entry) {
	case ALPHA_KENTRY_UNA:
		/*
		 * If user-land, do whatever fixups, printing, and
		 * signalling is appropriate (based on system-wide
		 * and per-process unaligned-access-handling flags).
		 */
		if (user) {
			if ((i = unaligned_fixup(a0, a1, a2, p)) == 0)
				goto out;

			ucode = a0;		/* VA */
			break;
		}

		/*
		 * Unaligned access from kernel mode is always an error,
		 * EVEN IF A COPY FAULT HANDLER IS SET!
		 *
		 * It's an error if a copy fault handler is set because
		 * the various routines which do user-initiated copies
		 * do so in a bcopy-like manner.  In other words, the
		 * kernel never assumes that pointers provided by the
		 * user are properly aligned, and so if the kernel
		 * does cause an unaligned access it's a kernel bug.
		 */
		goto dopanic;

	case ALPHA_KENTRY_ARITH:
		/* 
		 * If user-land, give a SIGFPE if software completion
		 * is not requested or if the completion fails.
		 */
		if (user) {
			if (a0 & EXCSUM_SWC)
				if (fp_software_completion(a1, p))
					goto out;
			i = SIGFPE;
			ucode =  a0;		/* exception summary */
			break;
		}

		/* Always fatal in kernel.  Should never happen. */
		goto dopanic;

	case ALPHA_KENTRY_IF:
		/*
		 * These are always fatal in kernel, and should never
		 * happen.
		 */
		if (!user) {
#ifdef DDB
			/*
			 * ...unless, of course, DDB is configured; BUGCHK
			 * is used to invoke the kernel debugger, and we
			 * might have set a breakpoint.
			 */
			if (a0 == ALPHA_IF_CODE_BUGCHK ||
			    a0 == ALPHA_IF_CODE_BPT
#ifdef SIMOS
			    || a0 == ALPHA_IF_CODE_GENTRAP
#endif
			    ) {
				if (kdb_trap(a0, a1, a2, entry, framep))
					goto out;
			}

			/*
			 * If we get here, DDB did _not_ handle the
			 * trap, and we need to PANIC!
			 */
#endif
			goto dopanic;
		}
		i = 0;
		switch (a0) {
		case ALPHA_IF_CODE_GENTRAP:
			if (framep->tf_regs[FRAME_A0] == -2) { /* weird! */
				i = SIGFPE;
				ucode =  a0;	/* exception summary */
				break;
			}
			/* FALLTHROUTH */
		case ALPHA_IF_CODE_BPT:
		case ALPHA_IF_CODE_BUGCHK:
			if (p->p_md.md_flags & (MDP_STEP1|MDP_STEP2)) {
				ptrace_clear_single_step(p);
				p->p_md.md_tf->tf_regs[FRAME_PC] -= 4;
			}
			ucode = a0;		/* trap type */
			i = SIGTRAP;
			break;

		case ALPHA_IF_CODE_OPDEC:
			ucode = a0;		/* trap type */
			i = SIGILL;
			break;

		case ALPHA_IF_CODE_FEN:
			/*
			 * on exit from the kernel, if proc == fpcurproc,
			 * FP is enabled.
			 */
			if (fpcurproc == p) {
				printf("trap: fp disabled for fpcurproc == %p",
				    p);
				goto dopanic;
			}
	
			alpha_pal_wrfen(1);
			if (fpcurproc)
				savefpstate(&fpcurproc->p_addr->u_pcb.pcb_fp);
			fpcurproc = p;
			restorefpstate(&fpcurproc->p_addr->u_pcb.pcb_fp);
			alpha_pal_wrfen(0);

			p->p_md.md_flags |= MDP_FPUSED;
			goto out;

		default:
			printf("trap: unknown IF type 0x%lx\n", a0);
			goto dopanic;
		}
		break;

	case ALPHA_KENTRY_MM:
		switch (a1) {
		case ALPHA_MMCSR_FOR:
		case ALPHA_MMCSR_FOE:
			pmap_emulate_reference(p, a0, user, 0);
			goto out;

		case ALPHA_MMCSR_FOW:
			pmap_emulate_reference(p, a0, user, 1);
			goto out;

		case ALPHA_MMCSR_INVALTRANS:
		case ALPHA_MMCSR_ACCESS:
	    	{
			register vm_offset_t va;
			register struct vmspace *vm = NULL;
			register vm_map_t map;
			vm_prot_t ftype = 0;
			int rv;

			/*
			 * If it was caused by fuswintr or suswintr,
			 * just punt.  Note that we check the faulting
			 * address against the address accessed by
			 * [fs]uswintr, in case another fault happens
			 * when they are running.
			 */
			if (!user &&
			    p != NULL &&
			    p->p_addr->u_pcb.pcb_onfault ==
			      (unsigned long)fswintrberr &&
			    p->p_addr->u_pcb.pcb_accessaddr == a0) {
				framep->tf_regs[FRAME_PC] =
				    p->p_addr->u_pcb.pcb_onfault;
				p->p_addr->u_pcb.pcb_onfault = 0;
				goto out;
			}

			/*
			 * It is only a kernel address space fault iff:
			 *	1. !user and
			 *	2. pcb_onfault not set or
			 *	3. pcb_onfault set but kernel space data fault
			 * The last can occur during an exec() copyin where the
			 * argument space is lazy-allocated.
			 */
			if (!user && (a0 >= VM_MIN_KERNEL_ADDRESS ||
			    p == NULL || p->p_addr->u_pcb.pcb_onfault == 0))
				map = kernel_map;
			else {
				vm = p->p_vmspace;
				map = &vm->vm_map;
			}
	
			switch (a2) {
			case -1:		/* instruction fetch fault */
			case 0:			/* load instruction */
				ftype = VM_PROT_READ;
				break;
			case 1:			/* store instruction */
				ftype = VM_PROT_WRITE;
				break;
#ifdef DIAGNOSTIC
			default:		/* XXX gcc -Wuninitialized */
				goto dopanic;
#endif
			}
	
			va = trunc_page((vm_offset_t)a0);

			if (map != kernel_map) {
				/*
				 * Keep swapout from messing with us
				 * during thiscritical time.
				 */
				++p->p_lock;

				/*
				 * Grow the stack if necessary
				 */
#ifndef VM_STACK
				if ((caddr_t)va > vm->vm_maxsaddr
				    && va < USRSTACK) {
					if (!grow(p, va)) {
						rv = KERN_FAILURE;
						--p->p_lock;
						goto nogo;
					}
				}
#else
				/* grow_stack returns false only if va falls into
				 * a growable stack region and the stack growth
				 * fails.  It returns true if va was not within
				 * a growable stack region, or if the stack 
				 * growth succeeded.
				 */
				if (!grow_stack (p, va)) {
				  rv = KERN_FAILURE;
				  --p->p_lock;
				  goto nogo;
				}
#endif


				/* Fault in the user page: */
				rv = vm_fault(map, va, ftype,
					      (ftype & VM_PROT_WRITE)
					      ? VM_FAULT_DIRTY : 0);

				--p->p_lock;
			} else {
				/*
				 * Don't have to worry about process
				 * locking or stacks in the kernel.
				 */
				rv = vm_fault(map, va, ftype, FALSE);
			}
				
		nogo:;
			/*
			 * If this was a stack access we keep track of the
			 * maximum accessed stack size.  Also, if vm_fault
			 * gets a protection failure it is due to accessing
			 * the stack region outside the current limit and
			 * we need to reflect that as an access error.
			 */
			if (map != kernel_map &&
			    (caddr_t)va >= vm->vm_maxsaddr
			    && (caddr_t)va < (caddr_t)USRSTACK) {
				if (rv == KERN_SUCCESS) {
					unsigned nss;
	
					nss = alpha_btop(round_page(USRSTACK - va));
					if (nss > vm->vm_ssize)
						vm->vm_ssize = nss;
				} else if (rv == KERN_PROTECTION_FAILURE)
					rv = KERN_INVALID_ADDRESS;
			}
			if (rv == KERN_SUCCESS) {
				goto out;
			}

			if (!user) {
				/* Check for copyin/copyout fault */
				if (p != NULL &&
				    p->p_addr->u_pcb.pcb_onfault != 0) {
					framep->tf_regs[FRAME_PC] =
					    p->p_addr->u_pcb.pcb_onfault;
					p->p_addr->u_pcb.pcb_onfault = 0;
					goto out;
				}
				goto dopanic;
			}
			ucode = a0;
			i = SIGSEGV;
#ifdef DEBUG
			printtrap(a0, a1, a2, entry, framep, 1, user);
#endif
			break;
		    }

		default:
			printf("trap: unknown MMCSR value 0x%lx\n", a1);
			goto dopanic;
		}
		break;

	default:
		goto dopanic;
	}

#ifdef DEBUG
	printtrap(a0, a1, a2, entry, framep, 1, user);
#endif
	framep->tf_regs[FRAME_TRAPARG_A0] = a0;
	framep->tf_regs[FRAME_TRAPARG_A1] = a1;
	framep->tf_regs[FRAME_TRAPARG_A2] = a2;
	trapsignal(p, i, ucode);
out:
	if (user) {
		framep->tf_regs[FRAME_SP] = alpha_pal_rdusp();
		userret(p, framep->tf_regs[FRAME_PC], sticks);
	}
	return;

dopanic:
	printtrap(a0, a1, a2, entry, framep, 1, user);

	/* XXX dump registers */

#ifdef DDB
	kdb_trap(a0, a1, a2, entry, framep);
#endif

	panic("trap");
}

/*
 * Process a system call.
 *
 * System calls are strange beasts.  They are passed the syscall number
 * in v0, and the arguments in the registers (as normal).  They return
 * an error flag in a3 (if a3 != 0 on return, the syscall had an error),
 * and the return value (if any) in v0.
 *
 * The assembly stub takes care of moving the call number into a register
 * we can get to, and moves all of the argument registers into their places
 * in the trap frame.  On return, it restores the callee-saved registers,
 * a3, and v0 from the frame before returning to the user process.
 */
void
syscall(code, framep)
	u_int64_t code;
	struct trapframe *framep;
{
	struct sysent *callp;
	struct proc *p;
	int error = 0, numsys;
	u_int64_t opc;
	u_quad_t sticks;
	u_int64_t args[10];					/* XXX */
	u_int hidden = 0, nargs;

	framep->tf_regs[FRAME_TRAPARG_A0] = 0;
	framep->tf_regs[FRAME_TRAPARG_A1] = 0;
	framep->tf_regs[FRAME_TRAPARG_A2] = 0;
#if notdef				/* can't happen, ever. */
	if ((framep->tf_regs[FRAME_PS] & ALPHA_PSL_USERMODE) == 0)
		panic("syscall");
#endif

	cnt.v_syscall++;
	p = curproc;
	p->p_md.md_tf = framep;
	opc = framep->tf_regs[FRAME_PC] - 4;
	sticks = p->p_sticks;

	if (p->p_sysent->sv_prepsyscall) {
		/* (*p->p_sysent->sv_prepsyscall)(framep, args, &code, &params); */
		panic("prepsyscall");
	} else {
		/*
		 * syscall() and __syscall() are handled the same on
		 * the alpha, as everything is 64-bit aligned, anyway.
		 */
		if (code == SYS_syscall || code == SYS___syscall) {
			/*
			 * Code is first argument, followed by actual args.
			 */
			code = framep->tf_regs[FRAME_A0];
			hidden = 1;
		}
	}

 	if (p->p_sysent->sv_mask)
 		code &= p->p_sysent->sv_mask;

 	if (code >= p->p_sysent->sv_size)
 		callp = &p->p_sysent->sv_table[0];
  	else
 		callp = &p->p_sysent->sv_table[code];

	nargs = callp->sy_narg + hidden;
	switch (nargs) {
	default:
		if (nargs > 10)		/* XXX */
			panic("syscall: too many args (%d)", nargs);
		error = copyin((caddr_t)(alpha_pal_rdusp()), &args[6],
		    (nargs - 6) * sizeof(u_int64_t));
	case 6:	
		args[5] = framep->tf_regs[FRAME_A5];
	case 5:	
		args[4] = framep->tf_regs[FRAME_A4];
	case 4:	
		args[3] = framep->tf_regs[FRAME_A3];
	case 3:	
		args[2] = framep->tf_regs[FRAME_A2];
	case 2:	
		args[1] = framep->tf_regs[FRAME_A1];
	case 1:	
		args[0] = framep->tf_regs[FRAME_A0];
	case 0:
		break;
	}
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSCALL))
		ktrsyscall(p->p_tracep, code, callp->sy_narg, args + hidden);
#endif
	if (error == 0) {
		p->p_retval[0] = 0;
		p->p_retval[1] = 0;

		STOPEVENT(p, S_SCE, callp->sy_narg);

		error = (*callp->sy_call)(p, args + hidden);
	}


	switch (error) {
	case 0:
		framep->tf_regs[FRAME_V0] = p->p_retval[0];
		framep->tf_regs[FRAME_A4] = p->p_retval[1];
		framep->tf_regs[FRAME_A3] = 0;
		break;
	case ERESTART:
		framep->tf_regs[FRAME_PC] = opc;
		break;
	case EJUSTRETURN:
		break;
	default:
		if (p->p_sysent->sv_errsize)
			if (error >= p->p_sysent->sv_errsize)
				error = -1; /* XXX */
			else
				error = p->p_sysent->sv_errtbl[error];
		framep->tf_regs[FRAME_V0] = error;
		framep->tf_regs[FRAME_A3] = 1;
		break;
	}

        /*
         * Reinitialize proc pointer `p' as it may be different
         * if this is a child returning from fork syscall.
         */
	p = curproc;

	userret(p, framep->tf_regs[FRAME_PC], sticks);
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSRET))
		ktrsysret(p->p_tracep, code, error, rval[0]);
#endif

	/*
	 * This works because errno is findable through the
	 * register set.  If we ever support an emulation where this
	 * is not the case, this code will need to be revisited.
	 */
	STOPEVENT(p, S_SCX, code);
}

/*
 * Process the tail end of a fork() for the child.
 */
void
child_return(p)
	struct proc *p;
{

	/*
	 * Return values in the frame set by cpu_fork().
	 */

	userret(p, p->p_md.md_tf->tf_regs[FRAME_PC], 0);
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSRET))
		ktrsysret(p->p_tracep, SYS_fork, 0, 0);
#endif
}

/*
 * Process an asynchronous software trap.
 * This is relatively easy.
 */
void
ast(framep)
	struct trapframe *framep;
{
	register struct proc *p;
	u_quad_t sticks;

	p = curproc;
	sticks = p->p_sticks;
	p->p_md.md_tf = framep;

	if ((framep->tf_regs[FRAME_PS] & ALPHA_PSL_USERMODE) == 0)
		panic("ast and not user");

	cnt.v_soft++;

	astpending = 0;
	if (p->p_flag & P_OWEUPC) {
		p->p_flag &= ~P_OWEUPC;
		addupc_task(p, p->p_stats->p_prof.pr_addr,
			    p->p_stats->p_prof.pr_ticks);
	}

	userret(p, framep->tf_regs[FRAME_PC], sticks);
}

/*
 * Unaligned access handler.  It's not clear that this can get much slower...
 *
 */
const static int reg_to_framereg[32] = {
	FRAME_V0,	FRAME_T0,	FRAME_T1,	FRAME_T2,
	FRAME_T3,	FRAME_T4,	FRAME_T5,	FRAME_T6,
	FRAME_T7,	FRAME_S0,	FRAME_S1,	FRAME_S2,
	FRAME_S3,	FRAME_S4,	FRAME_S5,	FRAME_S6,
	FRAME_A0,	FRAME_A1,	FRAME_A2,	FRAME_A3,
	FRAME_A4,	FRAME_A5,	FRAME_T8,	FRAME_T9,
	FRAME_T10,	FRAME_T11,	FRAME_RA,	FRAME_T12,
	FRAME_AT,	FRAME_GP,	FRAME_SP,	-1,
};

#define	irp(p, reg)							\
	((reg_to_framereg[(reg)] == -1) ? NULL :			\
	    &(p)->p_md.md_tf->tf_regs[reg_to_framereg[(reg)]])

#define	frp(p, reg)							\
	(&(p)->p_addr->u_pcb.pcb_fp.fpr_regs[(reg)])

#define	dump_fp_regs()							\
	if (p == fpcurproc) {						\
		alpha_pal_wrfen(1);					\
		savefpstate(&fpcurproc->p_addr->u_pcb.pcb_fp);		\
		alpha_pal_wrfen(0);					\
		fpcurproc = NULL;					\
	}

#define	unaligned_load(storage, ptrf, mod)				\
	if (copyin((caddr_t)va, &(storage), sizeof (storage)) == 0 &&	\
	    (regptr = ptrf(p, reg)) != NULL)				\
		signal = 0;						\
	else								\
		break;							\
	*regptr = mod (storage);

#define	unaligned_store(storage, ptrf, mod)				\
	if ((regptr = ptrf(p, reg)) == NULL)				\
		break;							\
	(storage) = mod (*regptr);					\
	if (copyout(&(storage), (caddr_t)va, sizeof (storage)) == 0)	\
		signal = 0;						\
	else								\
		break;

#define	unaligned_load_integer(storage)					\
	unaligned_load(storage, irp, )

#define	unaligned_store_integer(storage)				\
	unaligned_store(storage, irp, )

#define	unaligned_load_floating(storage, mod)				\
	dump_fp_regs();							\
	unaligned_load(storage, frp, mod)

#define	unaligned_store_floating(storage, mod)				\
	dump_fp_regs();							\
	unaligned_store(storage, frp, mod)

unsigned long
Sfloat_to_reg(s)
	unsigned int s;
{
	unsigned long sign, expn, frac;
	unsigned long result;

	sign = (s & 0x80000000) >> 31;
	expn = (s & 0x7f800000) >> 23;
	frac = (s & 0x007fffff) >>  0;

	/* map exponent part, as appropriate. */
	if (expn == 0xff)
		expn = 0x7ff;
	else if ((expn & 0x80) != 0)
		expn = (0x400 | (expn & ~0x80));
	else if ((expn & 0x80) == 0 && expn != 0)
		expn = (0x380 | (expn & ~0x80));

	result = (sign << 63) | (expn << 52) | (frac << 29);
	return (result);
}

unsigned int
reg_to_Sfloat(r)
	unsigned long r;
{
	unsigned long sign, expn, frac;
	unsigned int result;

	sign = (r & 0x8000000000000000) >> 63;
	expn = (r & 0x7ff0000000000000) >> 52;
	frac = (r & 0x000fffffe0000000) >> 29;

	/* map exponent part, as appropriate. */
	expn = (expn & 0x7f) | ((expn & 0x400) != 0 ? 0x80 : 0x00);

	result = (sign << 31) | (expn << 23) | (frac << 0);
	return (result);
}

/*
 * Conversion of T floating datums to and from register format
 * requires no bit reordering whatsoever.
 */
unsigned long
Tfloat_reg_cvt(input)
	unsigned long input;
{

	return (input);
}

#ifdef FIX_UNALIGNED_VAX_FP
unsigned long
Ffloat_to_reg(f)
	unsigned int f;
{
	unsigned long sign, expn, frlo, frhi;
	unsigned long result;

	sign = (f & 0x00008000) >> 15;
	expn = (f & 0x00007f80) >>  7;
	frhi = (f & 0x0000007f) >>  0;
	frlo = (f & 0xffff0000) >> 16;

	/* map exponent part, as appropriate. */
	if ((expn & 0x80) != 0)
		expn = (0x400 | (expn & ~0x80));
	else if ((expn & 0x80) == 0 && expn != 0)
		expn = (0x380 | (expn & ~0x80));

	result = (sign << 63) | (expn << 52) | (frhi << 45) | (frlo << 29);
	return (result);
}

unsigned int
reg_to_Ffloat(r)
	unsigned long r;
{
	unsigned long sign, expn, frhi, frlo;
	unsigned int result;

	sign = (r & 0x8000000000000000) >> 63;
	expn = (r & 0x7ff0000000000000) >> 52;
	frhi = (r & 0x000fe00000000000) >> 45;
	frlo = (r & 0x00001fffe0000000) >> 29;

	/* map exponent part, as appropriate. */
	expn = (expn & 0x7f) | ((expn & 0x400) != 0 ? 0x80 : 0x00);

	result = (sign << 15) | (expn << 7) | (frhi << 0) | (frlo << 16);
	return (result);
}

/*
 * Conversion of G floating datums to and from register format is
 * symmetrical.  Just swap shorts in the quad...
 */
unsigned long
Gfloat_reg_cvt(input)
	unsigned long input;
{
	unsigned long a, b, c, d;
	unsigned long result;

	a = (input & 0x000000000000ffff) >> 0;
	b = (input & 0x00000000ffff0000) >> 16;
	c = (input & 0x0000ffff00000000) >> 32;
	d = (input & 0xffff000000000000) >> 48;

	result = (a << 48) | (b << 32) | (c << 16) | (d << 0);
	return (result);
}
#endif /* FIX_UNALIGNED_VAX_FP */

extern int	alpha_unaligned_print, alpha_unaligned_fix;
extern int	alpha_unaligned_sigbus;

int
unaligned_fixup(va, opcode, reg, p)
	unsigned long va, opcode, reg;
	struct proc *p;
{
	int doprint, dofix, dosigbus;
	int signal, size;
	const char *type;
	unsigned long *regptr, longdata;
	int intdata;		/* signed to get extension when storing */
	struct {
		const char *type;	/* opcode name */
		int size;		/* size, 0 if fixup not supported */
	} tab[0x10] = {
#ifdef FIX_UNALIGNED_VAX_FP
		{ "ldf",	4 },	{ "ldg",	8 },
#else
		{ "ldf",	0 },	{ "ldg",	0 },
#endif
		{ "lds",	4 },	{ "ldt",	8 },
#ifdef FIX_UNALIGNED_VAX_FP
		{ "stf",	4 },	{ "stg",	8 },
#else
		{ "stf",	0 },	{ "stg",	0 },
#endif
		{ "sts",	4 },	{ "stt",	8 },
		{ "ldl",	4 },	{ "ldq",	8 },
		{ "ldl_l",	0 },	{ "ldq_l",	0 },	/* can't fix */
		{ "stl",	4 },	{ "stq",	8 },
		{ "stl_c",	0 },	{ "stq_c",	0 },	/* can't fix */
	};

	/*
	 * Figure out what actions to take.
	 *
	 * XXX In the future, this should have a per-process component
	 * as well.
	 */
	doprint = alpha_unaligned_print;
	dofix = alpha_unaligned_fix;
	dosigbus = alpha_unaligned_sigbus;

	/*
	 * Find out which opcode it is.  Arrange to have the opcode
	 * printed if it's an unknown opcode.
	 */
	if (opcode >= 0x20 && opcode <= 0x2f) {
		type = tab[opcode - 0x20].type;
		size = tab[opcode - 0x20].size;
	} else {
		type = "0x%lx";
		size = 0;
	}

	/*
	 * See if the user can access the memory in question.
	 * Even if it's an unknown opcode, SEGV if the access
	 * should have failed.
	 */
	if (!useracc((caddr_t)va, size ? size : 1, B_WRITE)) {
		signal = SIGSEGV;
		goto out;
	}

	/*
	 * If we're supposed to be noisy, squawk now.
	 */
	if (doprint) {
		uprintf(
		"pid %d (%s): unaligned access: va=0x%lx pc=0x%lx ra=0x%lx op=",
		    p->p_pid, p->p_comm, va, p->p_md.md_tf->tf_regs[FRAME_PC],
		    p->p_md.md_tf->tf_regs[FRAME_RA]);
		uprintf(type,opcode);
		uprintf("\n");
	}

	/*
	 * If we should try to fix it and know how, give it a shot.
	 *
	 * We never allow bad data to be unknowingly used by the
	 * user process.  That is, if we decide not to fix up an
	 * access we cause a SIGBUS rather than letting the user
	 * process go on without warning.
	 *
	 * If we're trying to do a fixup, we assume that things
	 * will be botched.  If everything works out OK, 
	 * unaligned_{load,store}_* clears the signal flag.
	 */
	signal = SIGBUS;
	if (dofix && size != 0) {
		switch (opcode) {
#ifdef FIX_UNALIGNED_VAX_FP
		case 0x20:			/* ldf */
			unaligned_load_floating(intdata, Ffloat_to_reg);
			break;

		case 0x21:			/* ldg */
			unaligned_load_floating(longdata, Gfloat_reg_cvt);
			break;
#endif

		case 0x22:			/* lds */
			unaligned_load_floating(intdata, Sfloat_to_reg);
			break;

		case 0x23:			/* ldt */
			unaligned_load_floating(longdata, Tfloat_reg_cvt);
			break;

#ifdef FIX_UNALIGNED_VAX_FP
		case 0x24:			/* stf */
			unaligned_store_floating(intdata, reg_to_Ffloat);
			break;

		case 0x25:			/* stg */
			unaligned_store_floating(longdata, Gfloat_reg_cvt);
			break;
#endif

		case 0x26:			/* sts */
			unaligned_store_floating(intdata, reg_to_Sfloat);
			break;

		case 0x27:			/* stt */
			unaligned_store_floating(longdata, Tfloat_reg_cvt);
			break;

		case 0x28:			/* ldl */
			unaligned_load_integer(intdata);
			break;

		case 0x29:			/* ldq */
			unaligned_load_integer(longdata);
			break;

		case 0x2c:			/* stl */
			unaligned_store_integer(intdata);
			break;

		case 0x2d:			/* stq */
			unaligned_store_integer(longdata);
			break;

#ifdef DIAGNOSTIC
		default:
			panic("unaligned_fixup: can't get here");
#endif
		}
	} 

	/*
	 * Force SIGBUS if requested.
	 */
	if (dosigbus)
		signal = SIGBUS;

out:
	return (signal);
}
