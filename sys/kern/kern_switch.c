/*
 * Copyright (c) 2001 Jake Burkholder <jake@FreeBSD.org>
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
 */

/***
Here is the logic..

If there are N processors, then there are at most N KSEs (kernel
schedulable entities) working to process threads that belong to a
KSEGROUP (kg). If there are X of these KSEs actually running at the
moment in question, then there are at most M (N-X) of these KSEs on
the run queue, as running KSEs are not on the queue.

Runnable threads are queued off the KSEGROUP in priority order.
If there are M or more threads runnable, the top M threads
(by priority) are 'preassigned' to the M KSEs not running. The KSEs take
their priority from those threads and are put on the run queue.

The last thread that had a priority high enough to have a KSE associated
with it, AND IS ON THE RUN QUEUE is pointed to by
kg->kg_last_assigned. If no threads queued off the KSEGROUP have KSEs
assigned as all the available KSEs are activly running, or because there
are no threads queued, that pointer is NULL.

When a KSE is removed from the run queue to become runnable, we know
it was associated with the highest priority thread in the queue (at the head
of the queue). If it is also the last assigned we know M was 1 and must
now be 0. Since the thread is no longer queued that pointer must be
removed from it. Since we know there were no more KSEs available,
(M was 1 and is now 0) and since we are not FREEING our KSE
but using it, we know there are STILL no more KSEs available, we can prove
that the next thread in the ksegrp list will not have a KSE to assign to
it, so we can show that the pointer must be made 'invalid' (NULL).

The pointer exists so that when a new thread is made runnable, it can
have its priority compared with the last assigned thread to see if
it should 'steal' its KSE or not.. i.e. is it 'earlier'
on the list than that thread or later.. If it's earlier, then the KSE is
removed from the last assigned (which is now not assigned a KSE)
and reassigned to the new thread, which is placed earlier in the list.
The pointer is then backed up to the previous thread (which may or may not
be the new thread).

When a thread sleeps or is removed, the KSE becomes available and if there 
are queued threads that are not assigned KSEs, the highest priority one of
them is assigned the KSE, which is then placed back on the run queue at
the approipriate place, and the kg->kg_last_assigned pointer is adjusted down
to point to it.

The following diagram shows 2 KSEs and 3 threads from a single process.

 RUNQ: --->KSE---KSE--...    (KSEs queued at priorities from threads)
              \    \____   
               \        \
    KSEGROUP---thread--thread--thread    (queued in priority order)
        \                 / 
         \_______________/
          (last_assigned)

The result of this scheme is that the M available KSEs are always
queued at the priorities they have inherrited from the M highest priority
threads for that KSEGROUP. If this situation changes, the KSEs are 
reassigned to keep this true.
***/

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_sched.h"

#ifndef KERN_SWITCH_INCLUDE
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sched.h>
#else  /* KERN_SWITCH_INCLUDE */
#if defined(SMP) && (defined(__i386__) || defined(__amd64__))
#include <sys/smp.h>
#endif
#include <machine/critical.h>
#if defined(SMP) && defined(SCHED_4BSD)
#include <sys/sysctl.h>
#endif

#ifdef FULL_PREEMPTION
#ifndef PREEMPTION
#error "The FULL_PREEMPTION option requires the PREEMPTION option"
#endif
#endif

CTASSERT((RQB_BPW * RQB_LEN) == RQ_NQS);

#define td_kse td_sched

/************************************************************************
 * Functions that manipulate runnability from a thread perspective.	*
 ************************************************************************/
/*
 * Select the KSE that will be run next.  From that find the thread, and
 * remove it from the KSEGRP's run queue.  If there is thread clustering,
 * this will be what does it.
 */
struct thread *
choosethread(void)
{
	struct kse *ke;
	struct thread *td;
	struct ksegrp *kg;

#if defined(SMP) && (defined(__i386__) || defined(__amd64__))
	if (smp_active == 0 && PCPU_GET(cpuid) != 0) {
		/* Shutting down, run idlethread on AP's */
		td = PCPU_GET(idlethread);
		ke = td->td_kse;
		CTR1(KTR_RUNQ, "choosethread: td=%p (idle)", td);
		ke->ke_flags |= KEF_DIDRUN;
		TD_SET_RUNNING(td);
		return (td);
	}
#endif

retry:
	ke = sched_choose();
	if (ke) {
		td = ke->ke_thread;
		KASSERT((td->td_kse == ke), ("kse/thread mismatch"));
		kg = ke->ke_ksegrp;
		if (td->td_proc->p_flag & P_HADTHREADS) {
			if (kg->kg_last_assigned == td) {
				kg->kg_last_assigned = TAILQ_PREV(td,
				    threadqueue, td_runq);
			}
			TAILQ_REMOVE(&kg->kg_runq, td, td_runq);
			kg->kg_runnable--;
		}
		CTR2(KTR_RUNQ, "choosethread: td=%p pri=%d",
		    td, td->td_priority);
	} else {
		/* Simulate runq_choose() having returned the idle thread */
		td = PCPU_GET(idlethread);
		ke = td->td_kse;
		CTR1(KTR_RUNQ, "choosethread: td=%p (idle)", td);
	}
	ke->ke_flags |= KEF_DIDRUN;

	/*
	 * If we are in panic, only allow system threads,
	 * plus the one we are running in, to be run.
	 */
	if (panicstr && ((td->td_proc->p_flag & P_SYSTEM) == 0 &&
	    (td->td_flags & TDF_INPANIC) == 0)) {
		/* note that it is no longer on the run queue */
		TD_SET_CAN_RUN(td);
		goto retry;
	}

	TD_SET_RUNNING(td);
	return (td);
}

/*
 * Given a surplus system slot, try assign a new runnable thread to it.
 * Called from:
 *  sched_thread_exit()  (local)
 *  sched_switch()  (local)
 *  sched_thread_exit()  (local)
 *  remrunqueue()  (local) 
 */
static void
slot_fill(struct ksegrp *kg)
{
	struct thread *td;

	mtx_assert(&sched_lock, MA_OWNED);
	while (kg->kg_avail_opennings > 0) {
		/*
		 * Find the first unassigned thread
		 */
		if ((td = kg->kg_last_assigned) != NULL)
			td = TAILQ_NEXT(td, td_runq);
		else
			td = TAILQ_FIRST(&kg->kg_runq);

		/*
		 * If we found one, send it to the system scheduler.
		 */
		if (td) {
			kg->kg_last_assigned = td;
			kg->kg_avail_opennings--;
			sched_add(td, SRQ_BORING);
			CTR2(KTR_RUNQ, "slot_fill: td%p -> kg%p", td, kg);
		} else {
			/* no threads to use up the slots. quit now */
			break;
		}
	}
}

/*
 * Remove a thread from its KSEGRP's run queue.
 * This in turn may remove it from a KSE if it was already assigned
 * to one, possibly causing a new thread to be assigned to the KSE
 * and the KSE getting a new priority.
 */
static void
remrunqueue(struct thread *td)
{
	struct thread *td2, *td3;
	struct ksegrp *kg;
	struct kse *ke;

	mtx_assert(&sched_lock, MA_OWNED);
	KASSERT((TD_ON_RUNQ(td)), ("remrunqueue: Bad state on run queue"));
	kg = td->td_ksegrp;
	ke = td->td_kse;
	CTR1(KTR_RUNQ, "remrunqueue: td%p", td);
	TD_SET_CAN_RUN(td);
	/*
	 * If it is not a threaded process, take the shortcut.
	 */
	if ((td->td_proc->p_flag & P_HADTHREADS) == 0) {
		/* remve from sys run queue and free up a slot */
		sched_rem(td);
		kg->kg_avail_opennings++;
		ke->ke_state = KES_THREAD; 
		return;
	}
   	td3 = TAILQ_PREV(td, threadqueue, td_runq);
	TAILQ_REMOVE(&kg->kg_runq, td, td_runq);
	kg->kg_runnable--;
	if (ke->ke_state == KES_ONRUNQ) {
		/*
		 * This thread has been assigned to the system run queue.
		 * We need to dissociate it and try assign the
		 * KSE to the next available thread. Then, we should
		 * see if we need to move the KSE in the run queues.
		 */
		sched_rem(td);
		kg->kg_avail_opennings++;
		ke->ke_state = KES_THREAD; 
		td2 = kg->kg_last_assigned;
		KASSERT((td2 != NULL), ("last assigned has wrong value"));
		if (td2 == td) 
			kg->kg_last_assigned = td3;
		/* slot_fill(kg); */ /* will replace it with another */
	}
}

/*
 * Change the priority of a thread that is on the run queue.
 */
void
adjustrunqueue( struct thread *td, int newpri) 
{
	struct ksegrp *kg;
	struct kse *ke;

	mtx_assert(&sched_lock, MA_OWNED);
	KASSERT((TD_ON_RUNQ(td)), ("adjustrunqueue: Bad state on run queue"));

	ke = td->td_kse;
	CTR1(KTR_RUNQ, "adjustrunqueue: td%p", td);
	/*
	 * If it is not a threaded process, take the shortcut.
	 */
	if ((td->td_proc->p_flag & P_HADTHREADS) == 0) {
		/* We only care about the kse in the run queue. */
		td->td_priority = newpri;
		if (ke->ke_rqindex != (newpri / RQ_PPQ)) {
			sched_rem(td);
			sched_add(td, SRQ_BORING);
		}
		return;
	}

	/* It is a threaded process */
	kg = td->td_ksegrp;
	TD_SET_CAN_RUN(td);
	if (ke->ke_state == KES_ONRUNQ) {
		if (kg->kg_last_assigned == td) {
			kg->kg_last_assigned =
			    TAILQ_PREV(td, threadqueue, td_runq);
		}
		sched_rem(td);
		kg->kg_avail_opennings++;
	}
	TAILQ_REMOVE(&kg->kg_runq, td, td_runq);
	kg->kg_runnable--;
	td->td_priority = newpri;
	setrunqueue(td, SRQ_BORING);
}
int limitcount;
void
setrunqueue(struct thread *td, int flags)
{
	struct ksegrp *kg;
	struct thread *td2;
	struct thread *tda;
	int count;

	CTR3(KTR_RUNQ, "setrunqueue: td:%p kg:%p pid:%d",
	    td, td->td_ksegrp, td->td_proc->p_pid);
	mtx_assert(&sched_lock, MA_OWNED);
	KASSERT((td->td_inhibitors == 0),
			("setrunqueue: trying to run inhibitted thread"));
	KASSERT((TD_CAN_RUN(td) || TD_IS_RUNNING(td)),
	    ("setrunqueue: bad thread state"));
	TD_SET_RUNQ(td);
	kg = td->td_ksegrp;
	if ((td->td_proc->p_flag & P_HADTHREADS) == 0) {
		/*
		 * Common path optimisation: Only one of everything
		 * and the KSE is always already attached.
		 * Totally ignore the ksegrp run queue.
		 */
		if (kg->kg_avail_opennings != 1) {
			if (limitcount < 1) {
				limitcount++;
				printf("pid %d: corrected slot count (%d->1)\n",
				    td->td_proc->p_pid, kg->kg_avail_opennings);

			}
			kg->kg_avail_opennings = 1;
		}
		kg->kg_avail_opennings--;
		sched_add(td, flags);
		return;
	}

	tda = kg->kg_last_assigned;
	if ((kg->kg_avail_opennings <= 0) &&
	(tda && (tda->td_priority > td->td_priority))) {
		/*
		 * None free, but there is one we can commandeer.
		 */
		CTR2(KTR_RUNQ,
		    "setrunqueue: kg:%p: take slot from td: %p", kg, tda);
		sched_rem(tda);
		tda = kg->kg_last_assigned =
		    TAILQ_PREV(tda, threadqueue, td_runq);
		kg->kg_avail_opennings++;
	}

	/*
	 * Add the thread to the ksegrp's run queue at
	 * the appropriate place.
	 */
	count = 0;
	TAILQ_FOREACH(td2, &kg->kg_runq, td_runq) {
		if (td2->td_priority > td->td_priority) {
			kg->kg_runnable++;
			TAILQ_INSERT_BEFORE(td2, td, td_runq);
			break;
		}
		/* XXX Debugging hack */
		if (++count > 10000) {
			printf("setrunqueue(): corrupt kq_runq, td= %p\n", td);
			panic("deadlock in setrunqueue");
		}
	}
	if (td2 == NULL) {
		/* We ran off the end of the TAILQ or it was empty. */
		kg->kg_runnable++;
		TAILQ_INSERT_TAIL(&kg->kg_runq, td, td_runq);
	}

	/*
	 * If we have a slot to use, then put the thread on the system
	 * run queue and if needed, readjust the last_assigned pointer.
	 */
	if (kg->kg_avail_opennings > 0) {
		if (tda == NULL) {
			/*
			 * No pre-existing last assigned so whoever is first
			 * gets the KSE we brought in.. (maybe us)
			 */
			td2 = TAILQ_FIRST(&kg->kg_runq);
			kg->kg_last_assigned = td2;
		} else if (tda->td_priority > td->td_priority) {
			td2 = td;
		} else {
			/* 
			 * We are past last_assigned, so 
			 * gave the next slot to whatever is next,
			 * which may or may not be us.
			 */
			td2 = TAILQ_NEXT(tda, td_runq);
			kg->kg_last_assigned = td2;
		}
		kg->kg_avail_opennings--;
		sched_add(td2, flags);
	} else {
		CTR3(KTR_RUNQ, "setrunqueue: held: td%p kg%p pid%d",
			td, td->td_ksegrp, td->td_proc->p_pid);
	}
}

/*
 * Kernel thread preemption implementation.  Critical sections mark
 * regions of code in which preemptions are not allowed.
 */
void
critical_enter(void)
{
	struct thread *td;

	td = curthread;
	if (td->td_critnest == 0)
		cpu_critical_enter(td);
	td->td_critnest++;
}

void
critical_exit(void)
{
	struct thread *td;

	td = curthread;
	KASSERT(td->td_critnest != 0,
	    ("critical_exit: td_critnest == 0"));
	if (td->td_critnest == 1) {
#ifdef PREEMPTION
		mtx_assert(&sched_lock, MA_NOTOWNED);
		if (td->td_pflags & TDP_OWEPREEMPT) {
			mtx_lock_spin(&sched_lock);
			mi_switch(SW_INVOL, NULL);
			mtx_unlock_spin(&sched_lock);
		}
#endif
		td->td_critnest = 0;
		cpu_critical_exit(td);
	} else {
		td->td_critnest--;
	}
}

/*
 * This function is called when a thread is about to be put on run queue
 * because it has been made runnable or its priority has been adjusted.  It
 * determines if the new thread should be immediately preempted to.  If so,
 * it switches to it and eventually returns true.  If not, it returns false
 * so that the caller may place the thread on an appropriate run queue.
 */
int
maybe_preempt(struct thread *td)
{
#ifdef PREEMPTION
	struct thread *ctd;
	int cpri, pri;
#endif

	mtx_assert(&sched_lock, MA_OWNED);
#ifdef PREEMPTION
	/*
	 * The new thread should not preempt the current thread if any of the
	 * following conditions are true:
	 *
	 *  - The current thread has a higher (numerically lower) or
	 *    equivalent priority.  Note that this prevents curthread from
	 *    trying to preempt to itself.
	 *  - It is too early in the boot for context switches (cold is set).
	 *  - The current thread has an inhibitor set or is in the process of
	 *    exiting.  In this case, the current thread is about to switch
	 *    out anyways, so there's no point in preempting.  If we did,
	 *    the current thread would not be properly resumed as well, so
	 *    just avoid that whole landmine.
	 *  - If the new thread's priority is not a realtime priority and
	 *    the current thread's priority is not an idle priority and
	 *    FULL_PREEMPTION is disabled.
	 *
	 * If all of these conditions are false, but the current thread is in
	 * a nested critical section, then we have to defer the preemption
	 * until we exit the critical section.  Otherwise, switch immediately
	 * to the new thread.
	 */
	ctd = curthread;
	KASSERT ((ctd->td_kse != NULL && ctd->td_kse->ke_thread == ctd),
	  ("thread has no (or wrong) sched-private part."));
	KASSERT((td->td_inhibitors == 0),
			("maybe_preempt: trying to run inhibitted thread"));
	pri = td->td_priority;
	cpri = ctd->td_priority;
	if (pri >= cpri || cold /* || dumping */ || TD_IS_INHIBITED(ctd) ||
	    td->td_kse->ke_state != KES_THREAD)
		return (0);
#ifndef FULL_PREEMPTION
	if (!(pri >= PRI_MIN_ITHD && pri <= PRI_MAX_ITHD) &&
	    !(cpri >= PRI_MIN_IDLE))
		return (0);
#endif
	if (ctd->td_critnest > 1) {
		CTR1(KTR_PROC, "maybe_preempt: in critical section %d",
		    ctd->td_critnest);
		ctd->td_pflags |= TDP_OWEPREEMPT;
		return (0);
	}

	/*
	 * Our thread state says that we are already on a run queue, so
	 * update our state as if we had been dequeued by choosethread().
	 * However we must not actually be on the system run queue yet.
	 */
	MPASS(TD_ON_RUNQ(td));
	MPASS(td->td_sched->ke_state != KES_ONRUNQ);
	if (td->td_proc->p_flag & P_HADTHREADS) {
		/*
		 * If this is a threaded process we actually ARE on the
		 * ksegrp run queue so take it off that first.
		 */
		remrunqueue(td); /* maybe use a simpler version */
	}
		
	TD_SET_RUNNING(td);
	CTR3(KTR_PROC, "preempting to thread %p (pid %d, %s)\n", td,
	    td->td_proc->p_pid, td->td_proc->p_comm);
	mi_switch(SW_INVOL, td);
	return (1);
#else
	return (0);
#endif
}

#if 0
#ifndef PREEMPTION
/* XXX: There should be a non-static version of this. */
static void
printf_caddr_t(void *data)
{
	printf("%s", (char *)data);
}
static char preempt_warning[] =
    "WARNING: Kernel preemption is disabled, expect reduced performance.\n";
SYSINIT(preempt_warning, SI_SUB_COPYRIGHT, SI_ORDER_ANY, printf_caddr_t,
    preempt_warning)
#endif
#endif

/************************************************************************
 * SYSTEM RUN QUEUE manipulations and tests				*
 ************************************************************************/
/*
 * Initialize a run structure.
 */
void
runq_init(struct runq *rq)
{
	int i;

	bzero(rq, sizeof *rq);
	for (i = 0; i < RQ_NQS; i++)
		TAILQ_INIT(&rq->rq_queues[i]);
}

/*
 * Clear the status bit of the queue corresponding to priority level pri,
 * indicating that it is empty.
 */
static __inline void
runq_clrbit(struct runq *rq, int pri)
{
	struct rqbits *rqb;

	rqb = &rq->rq_status;
	CTR4(KTR_RUNQ, "runq_clrbit: bits=%#x %#x bit=%#x word=%d",
	    rqb->rqb_bits[RQB_WORD(pri)],
	    rqb->rqb_bits[RQB_WORD(pri)] & ~RQB_BIT(pri),
	    RQB_BIT(pri), RQB_WORD(pri));
	rqb->rqb_bits[RQB_WORD(pri)] &= ~RQB_BIT(pri);
}

/*
 * Find the index of the first non-empty run queue.  This is done by
 * scanning the status bits, a set bit indicates a non-empty queue.
 */
static __inline int
runq_findbit(struct runq *rq)
{
	struct rqbits *rqb;
	int pri;
	int i;

	rqb = &rq->rq_status;
	for (i = 0; i < RQB_LEN; i++)
		if (rqb->rqb_bits[i]) {
			pri = RQB_FFS(rqb->rqb_bits[i]) + (i << RQB_L2BPW);
			CTR3(KTR_RUNQ, "runq_findbit: bits=%#x i=%d pri=%d",
			    rqb->rqb_bits[i], i, pri);
			return (pri);
		}

	return (-1);
}

/*
 * Set the status bit of the queue corresponding to priority level pri,
 * indicating that it is non-empty.
 */
static __inline void
runq_setbit(struct runq *rq, int pri)
{
	struct rqbits *rqb;

	rqb = &rq->rq_status;
	CTR4(KTR_RUNQ, "runq_setbit: bits=%#x %#x bit=%#x word=%d",
	    rqb->rqb_bits[RQB_WORD(pri)],
	    rqb->rqb_bits[RQB_WORD(pri)] | RQB_BIT(pri),
	    RQB_BIT(pri), RQB_WORD(pri));
	rqb->rqb_bits[RQB_WORD(pri)] |= RQB_BIT(pri);
}

/*
 * Add the KSE to the queue specified by its priority, and set the
 * corresponding status bit.
 */
void
runq_add(struct runq *rq, struct kse *ke)
{
	struct rqhead *rqh;
	int pri;

	pri = ke->ke_thread->td_priority / RQ_PPQ;
	ke->ke_rqindex = pri;
	runq_setbit(rq, pri);
	rqh = &rq->rq_queues[pri];
	CTR5(KTR_RUNQ, "runq_add: td=%p ke=%p pri=%d %d rqh=%p",
	    ke->ke_thread, ke, ke->ke_thread->td_priority, pri, rqh);
	TAILQ_INSERT_TAIL(rqh, ke, ke_procq);
}

/*
 * Return true if there are runnable processes of any priority on the run
 * queue, false otherwise.  Has no side effects, does not modify the run
 * queue structure.
 */
int
runq_check(struct runq *rq)
{
	struct rqbits *rqb;
	int i;

	rqb = &rq->rq_status;
	for (i = 0; i < RQB_LEN; i++)
		if (rqb->rqb_bits[i]) {
			CTR2(KTR_RUNQ, "runq_check: bits=%#x i=%d",
			    rqb->rqb_bits[i], i);
			return (1);
		}
	CTR0(KTR_RUNQ, "runq_check: empty");

	return (0);
}

#if defined(SMP) && defined(SCHED_4BSD)
int runq_fuzz = 1;
SYSCTL_INT(_kern_sched, OID_AUTO, runq_fuzz, CTLFLAG_RW, &runq_fuzz, 0, "");
#endif

/*
 * Find the highest priority process on the run queue.
 */
struct kse *
runq_choose(struct runq *rq)
{
	struct rqhead *rqh;
	struct kse *ke;
	int pri;

	mtx_assert(&sched_lock, MA_OWNED);
	while ((pri = runq_findbit(rq)) != -1) {
		rqh = &rq->rq_queues[pri];
#if defined(SMP) && defined(SCHED_4BSD)
		/* fuzz == 1 is normal.. 0 or less are ignored */
		if (runq_fuzz > 1) {
			/*
			 * In the first couple of entries, check if
			 * there is one for our CPU as a preference.
			 */
			int count = runq_fuzz;
			int cpu = PCPU_GET(cpuid);
			struct kse *ke2;
			ke2 = ke = TAILQ_FIRST(rqh);

			while (count-- && ke2) {
				if (ke->ke_thread->td_lastcpu == cpu) {
					ke = ke2;
					break;
				}
				ke2 = TAILQ_NEXT(ke2, ke_procq);
			}
		} else 
#endif
			ke = TAILQ_FIRST(rqh);
		KASSERT(ke != NULL, ("runq_choose: no proc on busy queue"));
		CTR3(KTR_RUNQ,
		    "runq_choose: pri=%d kse=%p rqh=%p", pri, ke, rqh);
		return (ke);
	}
	CTR1(KTR_RUNQ, "runq_choose: idleproc pri=%d", pri);

	return (NULL);
}

/*
 * Remove the KSE from the queue specified by its priority, and clear the
 * corresponding status bit if the queue becomes empty.
 * Caller must set ke->ke_state afterwards.
 */
void
runq_remove(struct runq *rq, struct kse *ke)
{
	struct rqhead *rqh;
	int pri;

	KASSERT(ke->ke_proc->p_sflag & PS_INMEM,
		("runq_remove: process swapped out"));
	pri = ke->ke_rqindex;
	rqh = &rq->rq_queues[pri];
	CTR5(KTR_RUNQ, "runq_remove: td=%p, ke=%p pri=%d %d rqh=%p",
	    ke->ke_thread, ke, ke->ke_thread->td_priority, pri, rqh);
	KASSERT(ke != NULL, ("runq_remove: no proc on busy queue"));
	TAILQ_REMOVE(rqh, ke, ke_procq);
	if (TAILQ_EMPTY(rqh)) {
		CTR0(KTR_RUNQ, "runq_remove: empty");
		runq_clrbit(rq, pri);
	}
}

/****** functions that are temporarily here ***********/
#include <vm/uma.h>
#define RANGEOF(type, start, end) (offsetof(type, end) - offsetof(type, start))
extern struct mtx kse_zombie_lock;

/*
 *  Allocate scheduler specific per-process resources.
 * The thread and ksegrp have already been linked in.
 * In this case just set the default concurrency value.
 *
 * Called from:
 *  proc_init() (UMA init method)
 */
void
sched_newproc(struct proc *p, struct ksegrp *kg, struct thread *td)
{

	/* This can go in sched_fork */
	sched_init_concurrency(kg);
}

/*
 * Called by the uma process fini routine..
 * undo anything we may have done in the uma_init method.
 * Panic if it's not all 1:1:1:1
 * Called from:
 *  proc_fini() (UMA method)
 */
void
sched_destroyproc(struct proc *p)
{

	/* this function slated for destruction */
	KASSERT((p->p_numthreads == 1), ("Cached proc with > 1 thread "));
	KASSERT((p->p_numksegrps == 1), ("Cached proc with > 1 ksegrp "));
}

#define RANGEOF(type, start, end) (offsetof(type, end) - offsetof(type, start))
/*
 * thread is being either created or recycled.
 * Fix up the per-scheduler resources associated with it.
 * Called from:
 *  sched_fork_thread()
 *  thread_dtor()  (*may go away)
 *  thread_init()  (*may go away)
 */
void
sched_newthread(struct thread *td)
{
	struct td_sched *ke;

	ke = (struct td_sched *) (td + 1);
	bzero(ke, sizeof(*ke));
	td->td_sched     = ke;
	ke->ke_thread	= td;
	ke->ke_oncpu	= NOCPU;
	ke->ke_state	= KES_THREAD;
}

/*
 * Set up an initial concurrency of 1
 * and set the given thread (if given) to be using that
 * concurrency slot.
 * May be used "offline"..before the ksegrp is attached to the world
 * and thus wouldn't need schedlock in that case.
 * Called from:
 *  thr_create()
 *  proc_init() (UMA) via sched_newproc()
 */
void
sched_init_concurrency(struct ksegrp *kg)
{

	kg->kg_concurrency = 1;
	kg->kg_avail_opennings = 1;
}

/*
 * Change the concurrency of an existing ksegrp to N
 * Called from:
 *  kse_create()
 *  kse_exit()
 *  thread_exit()
 *  thread_single()
 */
void
sched_set_concurrency(struct ksegrp *kg, int concurrency)
{

	/* Handle the case for a declining concurrency */
	kg->kg_avail_opennings += (concurrency - kg->kg_concurrency);
	kg->kg_concurrency = concurrency;
}

/*
 * Called from thread_exit() for all exiting thread
 *
 * Not to be confused with sched_exit_thread()
 * that is only called from thread_exit() for threads exiting
 * without the rest of the process exiting because it is also called from
 * sched_exit() and we wouldn't want to call it twice.
 * XXX This can probably be fixed.
 */
void
sched_thread_exit(struct thread *td)
{

	td->td_ksegrp->kg_avail_opennings++;
	slot_fill(td->td_ksegrp);
}

#endif /* KERN_SWITCH_INCLUDE */
