/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * Interface to new debugger.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/reboot.h>
#include <sys/cons.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>

#include <machine/cpu.h>
#ifdef SMP
#include <machine/smptests.h>	/** CPUSTOP_ON_DDBBREAK */
#endif

#include <vm/vm.h>
#include <vm/pmap.h>

#include <ddb/ddb.h>

#include <machine/setjmp.h>

static jmp_buf *db_nofault = 0;
extern jmp_buf	db_jmpbuf;

extern void	gdb_handle_exception(db_regs_t *, int, int);

int	db_active;
db_regs_t ddb_regs;

static jmp_buf	db_global_jmpbuf;

static __inline u_short
rss(void)
{
	u_short ss;
#ifdef __GNUC__
	__asm __volatile("mov %%ss,%0" : "=r" (ss));
#else
	ss = 0; /* XXXX Fix for other compilers. */
#endif
	return ss;
}

/*
 *  kdb_trap - field a TRACE or BPT trap
 */
int
kdb_trap(int type, int code, struct i386_saved_state *regs)
{
	u_int ef;
	volatile int ddb_mode = !(boothowto & RB_GDB);

	/*
	 * XXX try to do nothing if the console is in graphics mode.
	 * Handle trace traps (and hardware breakpoints...) by ignoring
	 * them except for forgetting about them.  Return 0 for other
	 * traps to say that we haven't done anything.  The trap handler
	 * will usually panic.  We should handle breakpoint traps for
	 * our breakpoints by disarming our breakpoints and fixing up
	 * %eip.
	 */
	if (cnunavailable() != 0 && ddb_mode) {
	    if (type == T_TRCTRAP) {
		regs->tf_eflags &= ~PSL_T;
		return (1);
	    }
	    return (0);
	}

	ef = read_eflags();
	disable_intr();

#ifdef SMP
#ifdef CPUSTOP_ON_DDBBREAK

#if defined(VERBOSE_CPUSTOP_ON_DDBBREAK)
	db_printf("\nCPU%d stopping CPUs: 0x%08x...", PCPU_GET(cpuid),
	    PCPU_GET(other_cpus));
#endif /* VERBOSE_CPUSTOP_ON_DDBBREAK */

	/* We stop all CPUs except ourselves (obviously) */
	stop_cpus(PCPU_GET(other_cpus));

#if defined(VERBOSE_CPUSTOP_ON_DDBBREAK)
	db_printf(" stopped.\n");
#endif /* VERBOSE_CPUSTOP_ON_DDBBREAK */

#endif /* CPUSTOP_ON_DDBBREAK */
#endif /* SMP */

	switch (type) {
	    case T_BPTFLT:	/* breakpoint */
	    case T_TRCTRAP:	/* debug exception */
		break;

	    default:
		/*
		 * XXX this is almost useless now.  In most cases,
		 * trap_fatal() has already printed a much more verbose
		 * message.  However, it is dangerous to print things in
		 * trap_fatal() - printf() might be reentered and trap.
		 * The debugger should be given control first.
		 */
		if (ddb_mode)
		    db_printf("kernel: type %d trap, code=%x\n", type, code);

		if (db_nofault) {
		    jmp_buf *no_fault = db_nofault;
		    db_nofault = 0;
		    longjmp(*no_fault, 1);
		}
	}

	/*
	 * This handles unexpected traps in ddb commands, including calls to
	 * non-ddb functions.  db_nofault only applies to memory accesses by
	 * internal ddb commands.
	 */
	if (db_active)
	    longjmp(db_global_jmpbuf, 1);

	/*
	 * XXX We really should switch to a local stack here.
	 */
	ddb_regs = *regs;

	/*
	 * If in kernel mode, esp and ss are not saved, so dummy them up.
	 */
	if (ISPL(regs->tf_cs) == 0) {
	    ddb_regs.tf_esp = (int)&regs->tf_esp;
	    ddb_regs.tf_ss = rss();
	}

	(void) setjmp(db_global_jmpbuf);
	if (ddb_mode) {
	    if (!db_active)
		cndbctl(TRUE);
	    db_active = 1;
	    db_trap(type, code);
	    cndbctl(FALSE);
	} else {
	    db_active = 1;
	    gdb_handle_exception(&ddb_regs, type, code);
	}
	db_active = 0;

	regs->tf_eip    = ddb_regs.tf_eip;
	regs->tf_eflags = ddb_regs.tf_eflags;
	regs->tf_eax    = ddb_regs.tf_eax;
	regs->tf_ecx    = ddb_regs.tf_ecx;
	regs->tf_edx    = ddb_regs.tf_edx;
	regs->tf_ebx    = ddb_regs.tf_ebx;

	/*
	 * If in user mode, the saved ESP and SS were valid, restore them.
	 */
	if (ISPL(regs->tf_cs)) {
	    regs->tf_esp = ddb_regs.tf_esp;
	    regs->tf_ss  = ddb_regs.tf_ss & 0xffff;
	}

	regs->tf_ebp    = ddb_regs.tf_ebp;
	regs->tf_esi    = ddb_regs.tf_esi;
	regs->tf_edi    = ddb_regs.tf_edi;
	regs->tf_es     = ddb_regs.tf_es & 0xffff;
	regs->tf_fs     = ddb_regs.tf_fs & 0xffff;
	regs->tf_cs     = ddb_regs.tf_cs & 0xffff;
	regs->tf_ds     = ddb_regs.tf_ds & 0xffff;

#ifdef SMP
#ifdef CPUSTOP_ON_DDBBREAK

#if defined(VERBOSE_CPUSTOP_ON_DDBBREAK)
	db_printf("\nCPU%d restarting CPUs: 0x%08x...", PCPU_GET(cpuid),
	    stopped_cpus);
#endif /* VERBOSE_CPUSTOP_ON_DDBBREAK */

	/* Restart all the CPUs we previously stopped */
	if (stopped_cpus != PCPU_GET(other_cpus) && smp_started != 0) {
		db_printf("whoa, other_cpus: 0x%08x, stopped_cpus: 0x%08x\n",
			  PCPU_GET(other_cpus), stopped_cpus);
		panic("stop_cpus() failed");
	}
	restart_cpus(stopped_cpus);

#if defined(VERBOSE_CPUSTOP_ON_DDBBREAK)
	db_printf(" restarted.\n");
#endif /* VERBOSE_CPUSTOP_ON_DDBBREAK */

#endif /* CPUSTOP_ON_DDBBREAK */
#endif /* SMP */

	write_eflags(ef);

	return (1);
}

/*
 * Read bytes from kernel address space for debugger.
 */
void
db_read_bytes(vm_offset_t addr, size_t size, char *data)
{
	char	*src;

	db_nofault = &db_jmpbuf;

	src = (char *)addr;
	while (size-- > 0)
	    *data++ = *src++;

	db_nofault = 0;
}

/*
 * Write bytes to kernel address space for debugger.
 */
void
db_write_bytes(vm_offset_t addr, size_t size, char *data)
{
	char	*dst;

	pt_entry_t	*ptep0 = NULL;
	pt_entry_t	oldmap0 = 0;
	vm_offset_t	addr1;
	pt_entry_t	*ptep1 = NULL;
	pt_entry_t	oldmap1 = 0;

	db_nofault = &db_jmpbuf;

	if (addr > trunc_page((vm_offset_t)btext) - size &&
	    addr < round_page((vm_offset_t)etext)) {

	    ptep0 = pmap_pte(kernel_pmap, addr);
	    oldmap0 = *ptep0;
	    *ptep0 |= PG_RW;

	    /* Map another page if the data crosses a page boundary. */
	    if ((*ptep0 & PG_PS) == 0) {
	    	addr1 = trunc_page(addr + size - 1);
	    	if (trunc_page(addr) != addr1) {
		    ptep1 = pmap_pte(kernel_pmap, addr1);
		    oldmap1 = *ptep1;
		    *ptep1 |= PG_RW;
	    	}
	    } else {
		addr1 = trunc_4mpage(addr + size - 1);
		if (trunc_4mpage(addr) != addr1) {
		    ptep1 = pmap_pte(kernel_pmap, addr1);
		    oldmap1 = *ptep1;
		    *ptep1 |= PG_RW;
		}
	    }

	    invltlb();
	}

	dst = (char *)addr;

	while (size-- > 0)
	    *dst++ = *data++;

	db_nofault = 0;

	if (ptep0) {
	    *ptep0 = oldmap0;

	    if (ptep1)
		*ptep1 = oldmap1;

	    invltlb();
	}
}

/*
 * XXX
 * Move this to machdep.c and allow it to be called if any debugger is
 * installed.
 */
void
Debugger(const char *msg)
{
	static volatile u_int in_Debugger;

	/*
	 * XXX
	 * Do nothing if the console is in graphics mode.  This is
	 * OK if the call is for the debugger hotkey but not if the call
	 * is a weak form of panicing.
	 */
	if (cnunavailable() != 0 && !(boothowto & RB_GDB))
	    return;

	if (atomic_cmpset_acq_int(&in_Debugger, 0, 1)) {
	    db_printf("Debugger(\"%s\")\n", msg);
	    breakpoint();
	    atomic_store_rel_int(&in_Debugger, 0);
	}
}

void
db_show_mdpcpu(struct pcpu *pc)
{

	db_printf("APIC ID      = %d\n", pc->pc_apic_id);
	db_printf("currentldt   = 0x%x\n", pc->pc_currentldt);
}
