/*-
 * Copyright (c) 1982, 1986, 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)kern_synch.c	8.9 (Berkeley) 5/19/95
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/vmmeter.h>
#ifdef DDB
#include <ddb/ddb.h>
#endif
#ifdef KTRACE
#include <sys/uio.h>
#include <sys/ktrace.h>
#endif

#include <machine/cpu.h>

static void synch_setup(void *dummy);
SYSINIT(synch_setup, SI_SUB_KICK_SCHEDULER, SI_ORDER_FIRST, synch_setup, NULL)

int	hogticks;
int	lbolt;

static struct callout loadav_callout;
static struct callout lbolt_callout;

struct loadavg averunnable =
	{ {0, 0, 0}, FSCALE };	/* load average, of runnable procs */
/*
 * Constants for averages over 1, 5, and 15 minutes
 * when sampling at 5 second intervals.
 */
static fixpt_t cexp[3] = {
	0.9200444146293232 * FSCALE,	/* exp(-1/12) */
	0.9834714538216174 * FSCALE,	/* exp(-1/60) */
	0.9944598480048967 * FSCALE,	/* exp(-1/180) */
};

/* kernel uses `FSCALE', userland (SHOULD) use kern.fscale */
static int      fscale __unused = FSCALE;
SYSCTL_INT(_kern, OID_AUTO, fscale, CTLFLAG_RD, 0, FSCALE, "");

static void	loadav(void *arg);
static void	lboltcb(void *arg);

/*
 * We're only looking at 7 bits of the address; everything is
 * aligned to 4, lots of things are aligned to greater powers
 * of 2.  Shift right by 8, i.e. drop the bottom 256 worth.
 */
#define TABLESIZE	128
static TAILQ_HEAD(slpquehead, thread) slpque[TABLESIZE];
#define LOOKUP(x)	(((intptr_t)(x) >> 8) & (TABLESIZE - 1))

void
sleepinit(void)
{
	int i;

	hogticks = (hz / 10) * 2;	/* Default only. */
	for (i = 0; i < TABLESIZE; i++)
		TAILQ_INIT(&slpque[i]);
	init_sleepqueues();
}

/*
 * General sleep call.  Suspends the current process until a wakeup is
 * performed on the specified identifier.  The process will then be made
 * runnable with the specified priority.  Sleeps at most timo/hz seconds
 * (0 means no timeout).  If pri includes PCATCH flag, signals are checked
 * before and after sleeping, else signals are not checked.  Returns 0 if
 * awakened, EWOULDBLOCK if the timeout expires.  If PCATCH is set and a
 * signal needs to be delivered, ERESTART is returned if the current system
 * call should be restarted if possible, and EINTR is returned if the system
 * call should be interrupted by the signal (return EINTR).
 *
 * The mutex argument is exited before the caller is suspended, and
 * entered before msleep returns.  If priority includes the PDROP
 * flag the mutex is not entered before returning.
 */

int
msleep(ident, mtx, priority, wmesg, timo)
	void *ident;
	struct mtx *mtx;
	int priority, timo;
	const char *wmesg;
{
	struct sleepqueue *sq;
	struct thread *td;
	struct proc *p;
	int catch, rval, sig;
	WITNESS_SAVE_DECL(mtx);

	td = curthread;
	p = td->td_proc;
#ifdef KTRACE
	if (KTRPOINT(td, KTR_CSW))
		ktrcsw(1, 0);
#endif
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, mtx == NULL ? NULL :
	    &mtx->mtx_object, "Sleeping on \"%s\"", wmesg);
	KASSERT(timo != 0 || mtx_owned(&Giant) || mtx != NULL,
	    ("sleeping without a mutex"));
	KASSERT(p != NULL, ("msleep1"));
	KASSERT(ident != NULL && TD_IS_RUNNING(td), ("msleep"));

	if (cold) {
		/*
		 * During autoconfiguration, just return;
		 * don't run any other procs or panic below,
		 * in case this is the idle process and already asleep.
		 * XXX: this used to do "s = splhigh(); splx(safepri);
		 * splx(s);" to give interrupts a chance, but there is
		 * no way to give interrupts a chance now.
		 */
		if (mtx != NULL && priority & PDROP)
			mtx_unlock(mtx);
		return (0);
	}
	catch = priority & PCATCH;
	rval = 0;

	/*
	 * If we are already on a sleep queue, then remove us from that
	 * sleep queue first.  We have to do this to handle recursive
	 * sleeps.
	 */
	if (TD_ON_SLEEPQ(td))
		sleepq_remove(td, td->td_wchan);

	sq = sleepq_lookup(ident);
	mtx_lock_spin(&sched_lock);

	/*
	 * If we are capable of async syscalls and there isn't already
	 * another one ready to return, start a new thread
	 * and queue it as ready to run. Note that there is danger here
	 * because we need to make sure that we don't sleep allocating
	 * the thread (recursion here might be bad).
	 */
	if (p->p_flag & P_SA || p->p_numthreads > 1) {
		/*
		 * Just don't bother if we are exiting
		 * and not the exiting thread or thread was marked as
		 * interrupted.
		 */
		if (catch) {
			if ((p->p_flag & P_WEXIT) && p->p_singlethread != td) {
				mtx_unlock_spin(&sched_lock);
				sleepq_release(ident);
				return (EINTR);
			}
			if (td->td_flags & TDF_INTERRUPT) {
				mtx_unlock_spin(&sched_lock);
				sleepq_release(ident);
				return (td->td_intrval);
			}
		}
	}
	mtx_unlock_spin(&sched_lock);
	CTR5(KTR_PROC, "msleep: thread %p (pid %d, %s) on %s (%p)",
	    td, p->p_pid, p->p_comm, wmesg, ident);

	DROP_GIANT();
	if (mtx != NULL) {
		mtx_assert(mtx, MA_OWNED | MA_NOTRECURSED);
		WITNESS_SAVE(&mtx->mtx_object, mtx);
		mtx_unlock(mtx);
	}

	/*
	 * We put ourselves on the sleep queue and start our timeout
	 * before calling thread_suspend_check, as we could stop there,
	 * and a wakeup or a SIGCONT (or both) could occur while we were
	 * stopped without resuming us.  Thus, we must be ready for sleep
	 * when cursig() is called.  If the wakeup happens while we're
	 * stopped, then td will no longer be on a sleep queue upon
	 * return from cursig().
	 */
	sleepq_add(sq, ident, mtx, wmesg, 0);
	if (timo)
		sleepq_set_timeout(sq, ident, timo);
	if (catch) {
		sig = sleepq_catch_signals(ident);
		if (sig == 0 && !TD_ON_SLEEPQ(td)) {
			mtx_lock_spin(&sched_lock);
			td->td_flags &= ~TDF_SINTR;
			mtx_unlock_spin(&sched_lock);
			catch = 0;
		}
	} else
		sig = 0;

	/*
	 * Adjust this threads priority.
	 *
	 * XXX: Do we need to save priority in td_base_pri?
	 */
	mtx_lock_spin(&sched_lock);
	sched_prio(td, priority & PRIMASK);
	mtx_unlock_spin(&sched_lock);

	if (timo && catch)
		rval = sleepq_timedwait_sig(ident, sig != 0);
	else if (timo)
		rval = sleepq_timedwait(ident, sig != 0);
	else if (catch)
		rval = sleepq_wait_sig(ident);
	else {
		sleepq_wait(ident);
		rval = 0;
	}

	/*
	 * We're awake from voluntary sleep.
	 */
	if (rval == 0 && catch)
		rval = sleepq_calc_signal_retval(sig);
#ifdef KTRACE
	if (KTRPOINT(td, KTR_CSW))
		ktrcsw(0, 0);
#endif
	PICKUP_GIANT();
	if (mtx != NULL && !(priority & PDROP)) {
		mtx_lock(mtx);
		WITNESS_RESTORE(&mtx->mtx_object, mtx);
	}
	return (rval);
}

/*
 * Make all processes sleeping on the specified identifier runnable.
 */
void
wakeup(ident)
	register void *ident;
{

	sleepq_broadcast(ident, 0, -1);
}

/*
 * Make a process sleeping on the specified identifier runnable.
 * May wake more than one process if a target process is currently
 * swapped out.
 */
void
wakeup_one(ident)
	register void *ident;
{

	sleepq_signal(ident, 0, -1);
}

/*
 * The machine independent parts of mi_switch().
 */
void
mi_switch(int flags)
{
	struct bintime new_switchtime;
	struct thread *td;
	struct proc *p;

	mtx_assert(&sched_lock, MA_OWNED | MA_NOTRECURSED);
	td = curthread;			/* XXX */
	p = td->td_proc;		/* XXX */
	KASSERT(!TD_ON_RUNQ(td), ("mi_switch: called by old code"));
#ifdef INVARIANTS
	if (!TD_ON_LOCK(td) && !TD_IS_RUNNING(td))
		mtx_assert(&Giant, MA_NOTOWNED);
#endif
	KASSERT(td->td_critnest == 1,
	    ("mi_switch: switch in a critical section"));
	KASSERT((flags & (SW_INVOL | SW_VOL)) != 0,
	    ("mi_switch: switch must be voluntary or involuntary"));

	if (flags & SW_VOL)
		p->p_stats->p_ru.ru_nvcsw++;
	else
		p->p_stats->p_ru.ru_nivcsw++;
	/*
	 * Compute the amount of time during which the current
	 * process was running, and add that to its total so far.
	 */
	binuptime(&new_switchtime);
	bintime_add(&p->p_runtime, &new_switchtime);
	bintime_sub(&p->p_runtime, PCPU_PTR(switchtime));

	td->td_generation++;	/* bump preempt-detect counter */

#ifdef DDB
	/*
	 * Don't perform context switches from the debugger.
	 */
	if (db_active) {
		mtx_unlock_spin(&sched_lock);
		db_print_backtrace();
		db_error("Context switches not allowed in the debugger");
	}
#endif

	/*
	 * Check if the process exceeds its cpu resource allocation.  If
	 * over max, arrange to kill the process in ast().
	 */
	if (p->p_cpulimit != RLIM_INFINITY &&
	    p->p_runtime.sec > p->p_cpulimit) {
		p->p_sflag |= PS_XCPU;
		td->td_flags |= TDF_ASTPENDING;
	}

	/*
	 * Finish up stats for outgoing thread.
	 */
	cnt.v_swtch++;
	PCPU_SET(switchtime, new_switchtime);
	PCPU_SET(switchticks, ticks);
	CTR3(KTR_PROC, "mi_switch: old thread %p (pid %d, %s)", td, p->p_pid,
	    p->p_comm);
	if (td->td_proc->p_flag & P_SA)
		thread_switchout(td);
	sched_switch(td);

	CTR3(KTR_PROC, "mi_switch: new thread %p (pid %d, %s)", td, p->p_pid,
	    p->p_comm);

	/* 
	 * If the last thread was exiting, finish cleaning it up.
	 */
	if ((td = PCPU_GET(deadthread))) {
		PCPU_SET(deadthread, NULL);
		thread_stash(td);
	}
}

/*
 * Change process state to be runnable,
 * placing it on the run queue if it is in memory,
 * and awakening the swapper if it isn't in memory.
 */
void
setrunnable(struct thread *td)
{
	struct proc *p;

	p = td->td_proc;
	mtx_assert(&sched_lock, MA_OWNED);
	switch (p->p_state) {
	case PRS_ZOMBIE:
		panic("setrunnable(1)");
	default:
		break;
	}
	switch (td->td_state) {
	case TDS_RUNNING:
	case TDS_RUNQ:
		return;
	case TDS_INHIBITED:
		/*
		 * If we are only inhibited because we are swapped out
		 * then arange to swap in this process. Otherwise just return.
		 */
		if (td->td_inhibitors != TDI_SWAPPED)
			return;
		/* XXX: intentional fall-through ? */
	case TDS_CAN_RUN:
		break;
	default:
		printf("state is 0x%x", td->td_state);
		panic("setrunnable(2)");
	}
	if ((p->p_sflag & PS_INMEM) == 0) {
		if ((p->p_sflag & PS_SWAPPINGIN) == 0) {
			p->p_sflag |= PS_SWAPINREQ;
			wakeup(&proc0);
		}
	} else
		sched_wakeup(td);
}

/*
 * Compute a tenex style load average of a quantity on
 * 1, 5 and 15 minute intervals.
 * XXXKSE   Needs complete rewrite when correct info is available.
 * Completely Bogus.. only works with 1:1 (but compiles ok now :-)
 */
static void
loadav(void *arg)
{
	int i, nrun;
	struct loadavg *avg;

	nrun = sched_load();
	avg = &averunnable;

	for (i = 0; i < 3; i++)
		avg->ldavg[i] = (cexp[i] * avg->ldavg[i] +
		    nrun * FSCALE * (FSCALE - cexp[i])) >> FSHIFT;

	/*
	 * Schedule the next update to occur after 5 seconds, but add a
	 * random variation to avoid synchronisation with processes that
	 * run at regular intervals.
	 */
	callout_reset(&loadav_callout, hz * 4 + (int)(random() % (hz * 2 + 1)),
	    loadav, NULL);
}

static void
lboltcb(void *arg)
{
	wakeup(&lbolt);
	callout_reset(&lbolt_callout, hz, lboltcb, NULL);
}

/* ARGSUSED */
static void
synch_setup(dummy)
	void *dummy;
{
	callout_init(&loadav_callout, 0);
	callout_init(&lbolt_callout, CALLOUT_MPSAFE);

	/* Kick off timeout driven events by calling first time. */
	loadav(NULL);
	lboltcb(NULL);
}

/*
 * General purpose yield system call
 */
int
yield(struct thread *td, struct yield_args *uap)
{
	struct ksegrp *kg;

	kg = td->td_ksegrp;
	mtx_assert(&Giant, MA_NOTOWNED);
	mtx_lock_spin(&sched_lock);
	sched_prio(td, PRI_MAX_TIMESHARE);
	mi_switch(SW_VOL);
	mtx_unlock_spin(&sched_lock);
	td->td_retval[0] = 0;
	return (0);
}
