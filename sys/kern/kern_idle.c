/*-
 * Copyright (c) 2000, All rights reserved.  See /usr/src/COPYRIGHT
 *
 * $FreeBSD$
 */

#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/vmmeter.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/ipl.h>
#include <sys/kthread.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/eventhandler.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#ifdef KTRACE
#include <sys/uio.h>
#include <sys/ktrace.h>
#endif

#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/smp.h>

#include <machine/globaldata.h>
#include <machine/globals.h>

static void idle_setup(void *dummy);
SYSINIT(idle_setup, SI_SUB_SCHED_IDLE, SI_ORDER_FIRST, idle_setup, NULL)

static void idle_proc(void *dummy);

/*
 * setup per-cpu idle process contexts
 */
static void
idle_setup(void *dummy)
{
	struct globaldata *gd;
	int error;

	SLIST_FOREACH(gd, &cpuhead, gd_allcpu) {
#ifdef SMP
		error = kthread_create(idle_proc, NULL, &gd->gd_idleproc,
				       RFSTOPPED|RFHIGHPID, "idle: cpu%d",
				       gd->gd_cpuid);
#else
		error = kthread_create(idle_proc, NULL, &gd->gd_idleproc,
				       RFSTOPPED|RFHIGHPID, "idle");
#endif
		if (error)
			panic("idle_setup: kthread_create error %d\n", error);

		gd->gd_idleproc->p_flag |= P_NOLOAD;
		gd->gd_idleproc->p_stat = SRUN;
	}
}

/*
 * idle process context
 */
static void
idle_proc(void *dummy)
{
#ifdef DIAGNOSTIC
	int count;
#endif

	for (;;) {
		mtx_assert(&Giant, MA_NOTOWNED);

#ifdef DIAGNOSTIC
		count = 0;

		while (count >= 0 && procrunnable() == 0) {
#else
		while (procrunnable() == 0) {
#endif
		/*
		 * This is a good place to put things to be done in
		 * the background, including sanity checks.
		 */

#ifdef DIAGNOSTIC
			if (count++ < 0)
				CTR0(KTR_PROC, "idle_proc: timed out waiting"
				    " for a process");
#endif

			if (vm_page_zero_idle() != 0)
				continue;

#ifdef __i386__
			cpu_idle();
#endif
		}

		mtx_lock_spin(&sched_lock);
		mi_switch();
		mtx_unlock_spin(&sched_lock);
	}
}
