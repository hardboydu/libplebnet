/*-
 * Copyright (c) 1998 Berkeley Software Design, Inc. All rights reserved.
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
 *	from BSDI $Id: mutex_witness.c,v 1.1.2.20 2000/04/27 03:10:27 cp Exp $
 *	and BSDI $Id: synch_machdep.c,v 2.3.2.39 2000/04/27 03:10:25 cp Exp $
 * $FreeBSD$
 */

/*
 * Machine independent bits of mutex implementation and implementation of
 * `witness' structure & related debugging routines.
 */

/*
 *	Main Entry: witness
 *	Pronunciation: 'wit-n&s
 *	Function: noun
 *	Etymology: Middle English witnesse, from Old English witnes knowledge,
 *	    testimony, witness, from 2wit
 *	Date: before 12th century
 *	1 : attestation of a fact or event : TESTIMONY
 *	2 : one that gives evidence; specifically : one who testifies in
 *	    a cause or before a judicial tribunal
 *	3 : one asked to be present at a transaction so as to be able to
 *	    testify to its having taken place
 *	4 : one who has personal knowledge of something
 *	5 a : something serving as evidence or proof : SIGN
 *	  b : public affirmation by word or example of usually
 *	      religious faith or conviction <the heroic witness to divine
 *	      life -- Pilot>
 *	6 capitalized : a member of the Jehovah's Witnesses 
 */

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/vmmeter.h>
#include <sys/ktr.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/clock.h>
#include <machine/cpu.h>

#include <ddb/ddb.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>

/*
 * Internal utility macros.
 */
#define mtx_unowned(m)	((m)->mtx_lock == MTX_UNOWNED)

#define mtx_owner(m)	(mtx_unowned((m)) ? NULL \
	: (struct thread *)((m)->mtx_lock & MTX_FLAGMASK))

#define SET_PRIO(td, pri)	(td)->td_ksegrp->kg_pri.pri_level = (pri)

/*
 * Lock classes for sleep and spin mutexes.
 */
struct lock_class lock_class_mtx_sleep = {
	"sleep mutex",
	LC_SLEEPLOCK | LC_RECURSABLE
};
struct lock_class lock_class_mtx_spin = {
	"spin mutex",
	LC_SPINLOCK | LC_RECURSABLE
};

/*
 * Prototypes for non-exported routines.
 */
static void	propagate_priority(struct thread *);

static void
propagate_priority(struct thread *td)
{
	struct ksegrp *kg = td->td_ksegrp;
	int pri = kg->kg_pri.pri_level;
	struct mtx *m = td->td_blocked;

	mtx_assert(&sched_lock, MA_OWNED);
	for (;;) {
		struct thread *td1;

		td = mtx_owner(m);

		if (td == NULL) {
			/*
			 * This really isn't quite right. Really
			 * ought to bump priority of thread that
			 * next acquires the mutex.
			 */
			MPASS(m->mtx_lock == MTX_CONTESTED);
			return;
		}
		kg = td->td_ksegrp;

		MPASS(td->td_proc->p_magic == P_MAGIC);
		KASSERT(td->td_proc->p_stat != SSLEEP, ("sleeping thread owns a mutex"));
		if (kg->kg_pri.pri_level <= pri) /* lower is higher priority */
			return;

		/*
		 * Bump this thread's priority.
		 */
		SET_PRIO(td, pri);

		/*
		 * If lock holder is actually running, just bump priority.
		 */
		 /* XXXKSE this test is not sufficient */
		if (td->td_kse && (td->td_kse->ke_oncpu != NOCPU)) { 
			MPASS(td->td_proc->p_stat == SRUN
			|| td->td_proc->p_stat == SZOMB
			|| td->td_proc->p_stat == SSTOP);
			return;
		}

#ifndef SMP
		/*
		 * For UP, we check to see if td is curthread (this shouldn't
		 * ever happen however as it would mean we are in a deadlock.)
		 */
		KASSERT(td != curthread, ("Deadlock detected"));
#endif

		/*
		 * If on run queue move to new run queue, and quit.
		 * XXXKSE this gets a lot more complicated under threads
		 * but try anyhow.
		 */
		if (td->td_proc->p_stat == SRUN) {
			MPASS(td->td_blocked == NULL);
			remrunqueue(td);
			setrunqueue(td);
			return;
		}

		/*
		 * If we aren't blocked on a mutex, we should be.
		 */
		KASSERT(td->td_proc->p_stat == SMTX, (
		    "process %d(%s):%d holds %s but isn't blocked on a mutex\n",
		    td->td_proc->p_pid, td->td_proc->p_comm, td->td_proc->p_stat,
		    m->mtx_object.lo_name));

		/*
		 * Pick up the mutex that td is blocked on.
		 */
		m = td->td_blocked;
		MPASS(m != NULL);

		/*
		 * Check if the thread needs to be moved up on
		 * the blocked chain
		 */
		if (td == TAILQ_FIRST(&m->mtx_blocked)) {
			continue;
		}

		td1 = TAILQ_PREV(td, threadqueue, td_blkq);
		if (td1->td_ksegrp->kg_pri.pri_level <= pri) {
			continue;
		}

		/*
		 * Remove thread from blocked chain and determine where
		 * it should be moved up to.  Since we know that td1 has
		 * a lower priority than td, we know that at least one
		 * thread in the chain has a lower priority and that
		 * td1 will thus not be NULL after the loop.
		 */
		TAILQ_REMOVE(&m->mtx_blocked, td, td_blkq);
		TAILQ_FOREACH(td1, &m->mtx_blocked, td_blkq) {
			MPASS(td1->td_proc->p_magic == P_MAGIC);
			if (td1->td_ksegrp->kg_pri.pri_level > pri)
				break;
		}

		MPASS(td1 != NULL);
		TAILQ_INSERT_BEFORE(td1, td, td_blkq);
		CTR4(KTR_LOCK,
		    "propagate_priority: p %p moved before %p on [%p] %s",
		    td, td1, m, m->mtx_object.lo_name);
	}
}

/*
 * Function versions of the inlined __mtx_* macros.  These are used by
 * modules and can also be called from assembly language if needed.
 */
void
_mtx_lock_flags(struct mtx *m, int opts, const char *file, int line)
{

	MPASS(curthread != NULL);
	KASSERT((opts & MTX_NOSWITCH) == 0,
	    ("MTX_NOSWITCH used at %s:%d", file, line));
	_get_sleep_lock(m, curthread, opts, file, line);
	LOCK_LOG_LOCK("LOCK", &m->mtx_object, opts, m->mtx_recurse, file,
	    line);
	WITNESS_LOCK(&m->mtx_object, opts | LOP_EXCLUSIVE, file, line);
}

void
_mtx_unlock_flags(struct mtx *m, int opts, const char *file, int line)
{

	MPASS(curthread != NULL);
	mtx_assert((m), MA_OWNED);
 	WITNESS_UNLOCK(&m->mtx_object, opts | LOP_EXCLUSIVE, file, line);
	LOCK_LOG_LOCK("UNLOCK", &m->mtx_object, opts, m->mtx_recurse, file,
	    line);
	_rel_sleep_lock(m, curthread, opts, file, line);
}

void
_mtx_lock_spin_flags(struct mtx *m, int opts, const char *file, int line)
{

	MPASS(curthread != NULL);
	_get_spin_lock(m, curthread, opts, file, line);
	LOCK_LOG_LOCK("LOCK", &m->mtx_object, opts, m->mtx_recurse, file,
	    line);
	WITNESS_LOCK(&m->mtx_object, opts | LOP_EXCLUSIVE, file, line);
}

void
_mtx_unlock_spin_flags(struct mtx *m, int opts, const char *file, int line)
{

	MPASS(curthread != NULL);
	mtx_assert((m), MA_OWNED);
 	WITNESS_UNLOCK(&m->mtx_object, opts | LOP_EXCLUSIVE, file, line);
	LOCK_LOG_LOCK("UNLOCK", &m->mtx_object, opts, m->mtx_recurse, file,
	    line);
	_rel_spin_lock(m);
}

/*
 * The important part of mtx_trylock{,_flags}()
 * Tries to acquire lock `m.' We do NOT handle recursion here; we assume that
 * if we're called, it's because we know we don't already own this lock.
 */
int
_mtx_trylock(struct mtx *m, int opts, const char *file, int line)
{
	int rval;

	MPASS(curthread != NULL);

	/*
	 * _mtx_trylock does not accept MTX_NOSWITCH option.
	 */
	KASSERT((opts & MTX_NOSWITCH) == 0,
	    ("mtx_trylock() called with invalid option flag(s) %d", opts));

	rval = _obtain_lock(m, curthread);

	LOCK_LOG_TRY("LOCK", &m->mtx_object, opts, rval, file, line);
	if (rval) {
		/*
		 * We do not handle recursion in _mtx_trylock; see the
		 * note at the top of the routine.
		 */
		KASSERT(!mtx_recursed(m),
		    ("mtx_trylock() called on a recursed mutex"));
		WITNESS_LOCK(&m->mtx_object, opts | LOP_EXCLUSIVE | LOP_TRYLOCK,
		    file, line);
	}

	return (rval);
}

/*
 * _mtx_lock_sleep: the tougher part of acquiring an MTX_DEF lock.
 *
 * We call this if the lock is either contested (i.e. we need to go to
 * sleep waiting for it), or if we need to recurse on it.
 */
void
_mtx_lock_sleep(struct mtx *m, int opts, const char *file, int line)
{
	struct thread *td = curthread;
	struct ksegrp *kg = td->td_ksegrp;

	if ((m->mtx_lock & MTX_FLAGMASK) == (uintptr_t)td) {
		m->mtx_recurse++;
		atomic_set_ptr(&m->mtx_lock, MTX_RECURSED);
		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR1(KTR_LOCK, "_mtx_lock_sleep: %p recursing", m);
		return;
	}

	if (LOCK_LOG_TEST(&m->mtx_object, opts))
		CTR4(KTR_LOCK,
		    "_mtx_lock_sleep: %s contested (lock=%p) at %s:%d",
		    m->mtx_object.lo_name, (void *)m->mtx_lock, file, line);

	while (!_obtain_lock(m, td)) {
		uintptr_t v;
		struct thread *td1;

		mtx_lock_spin(&sched_lock);
		/*
		 * Check if the lock has been released while spinning for
		 * the sched_lock.
		 */
		if ((v = m->mtx_lock) == MTX_UNOWNED) {
			mtx_unlock_spin(&sched_lock);
			continue;
		}

		/*
		 * The mutex was marked contested on release. This means that
		 * there are threads blocked on it.
		 */
		if (v == MTX_CONTESTED) {
			td1 = TAILQ_FIRST(&m->mtx_blocked);
			MPASS(td1 != NULL);
			m->mtx_lock = (uintptr_t)td | MTX_CONTESTED;

			if (td1->td_ksegrp->kg_pri.pri_level < kg->kg_pri.pri_level)
				SET_PRIO(td, td1->td_ksegrp->kg_pri.pri_level); 
			mtx_unlock_spin(&sched_lock);
			return;
		}

		/*
		 * If the mutex isn't already contested and a failure occurs
		 * setting the contested bit, the mutex was either released
		 * or the state of the MTX_RECURSED bit changed.
		 */
		if ((v & MTX_CONTESTED) == 0 &&
		    !atomic_cmpset_ptr(&m->mtx_lock, (void *)v,
			(void *)(v | MTX_CONTESTED))) {
			mtx_unlock_spin(&sched_lock);
			continue;
		}

		/*
		 * We deffinately must sleep for this lock.
		 */
		mtx_assert(m, MA_NOTOWNED);

#ifdef notyet
		/*
		 * If we're borrowing an interrupted thread's VM context, we
		 * must clean up before going to sleep.
		 */
		if (td->td_ithd != NULL) {
			struct ithd *it = td->td_ithd;

			if (it->it_interrupted) {
				if (LOCK_LOG_TEST(&m->mtx_object, opts))
					CTR2(KTR_LOCK,
				    "_mtx_lock_sleep: %p interrupted %p",
					    it, it->it_interrupted);
				intr_thd_fixup(it);
			}
		}
#endif

		/*
		 * Put us on the list of threads blocked on this mutex.
		 */
		if (TAILQ_EMPTY(&m->mtx_blocked)) {
			td1 = (struct thread *)(m->mtx_lock & MTX_FLAGMASK);
			LIST_INSERT_HEAD(&td1->td_contested, m, mtx_contested);
			TAILQ_INSERT_TAIL(&m->mtx_blocked, td, td_blkq);
		} else {
			TAILQ_FOREACH(td1, &m->mtx_blocked, td_blkq)
				if (td1->td_ksegrp->kg_pri.pri_level > kg->kg_pri.pri_level)
					break;
			if (td1)
				TAILQ_INSERT_BEFORE(td1, td, td_blkq);
			else
				TAILQ_INSERT_TAIL(&m->mtx_blocked, td, td_blkq);
		}

		/*
		 * Save who we're blocked on.
		 */
		td->td_blocked = m;
		td->td_mtxname = m->mtx_object.lo_name;
		td->td_proc->p_stat = SMTX;
		propagate_priority(td);

		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR3(KTR_LOCK,
			    "_mtx_lock_sleep: p %p blocked on [%p] %s", td, m,
			    m->mtx_object.lo_name);

		td->td_proc->p_stats->p_ru.ru_nvcsw++;
		mi_switch();

		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR3(KTR_LOCK,
			  "_mtx_lock_sleep: p %p free from blocked on [%p] %s",
			  td, m, m->mtx_object.lo_name);

		mtx_unlock_spin(&sched_lock);
	}

	return;
}

/*
 * _mtx_lock_spin: the tougher part of acquiring an MTX_SPIN lock.
 *
 * This is only called if we need to actually spin for the lock. Recursion
 * is handled inline.
 */
void
_mtx_lock_spin(struct mtx *m, int opts, critical_t mtx_crit, const char *file,
	       int line)
{
	int i = 0;

	if (LOCK_LOG_TEST(&m->mtx_object, opts))
		CTR1(KTR_LOCK, "_mtx_lock_spin: %p spinning", m);

	for (;;) {
		if (_obtain_lock(m, curthread))
			break;

		/* Give interrupts a chance while we spin. */
		critical_exit(mtx_crit);
		while (m->mtx_lock != MTX_UNOWNED) {
			if (i++ < 1000000)
				continue;
			if (i++ < 6000000)
				DELAY(1);
#ifdef DDB
			else if (!db_active)
#else
			else
#endif
			panic("spin lock %s held by %p for > 5 seconds",
			    m->mtx_object.lo_name, (void *)m->mtx_lock);
		}
		mtx_crit = critical_enter();
	}

	m->mtx_savecrit = mtx_crit;
	if (LOCK_LOG_TEST(&m->mtx_object, opts))
		CTR1(KTR_LOCK, "_mtx_lock_spin: %p spin done", m);

	return;
}

/*
 * _mtx_unlock_sleep: the tougher part of releasing an MTX_DEF lock.
 *
 * We are only called here if the lock is recursed or contested (i.e. we
 * need to wake up a blocked thread).
 */
void
_mtx_unlock_sleep(struct mtx *m, int opts, const char *file, int line)
{
	struct thread *td, *td1;
	struct mtx *m1;
	int pri;
	struct ksegrp *kg;

	td = curthread;
	kg = td->td_ksegrp;

	if (mtx_recursed(m)) {
		if (--(m->mtx_recurse) == 0)
			atomic_clear_ptr(&m->mtx_lock, MTX_RECURSED);
		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR1(KTR_LOCK, "_mtx_unlock_sleep: %p unrecurse", m);
		return;
	}

	mtx_lock_spin(&sched_lock);
	if (LOCK_LOG_TEST(&m->mtx_object, opts))
		CTR1(KTR_LOCK, "_mtx_unlock_sleep: %p contested", m);

	td1 = TAILQ_FIRST(&m->mtx_blocked);
	MPASS(td->td_proc->p_magic == P_MAGIC);
	MPASS(td1->td_proc->p_magic == P_MAGIC);

	TAILQ_REMOVE(&m->mtx_blocked, td1, td_blkq);

	if (TAILQ_EMPTY(&m->mtx_blocked)) {
		LIST_REMOVE(m, mtx_contested);
		_release_lock_quick(m);
		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR1(KTR_LOCK, "_mtx_unlock_sleep: %p not held", m);
	} else
		atomic_store_rel_ptr(&m->mtx_lock, (void *)MTX_CONTESTED);

	pri = PRI_MAX;
	LIST_FOREACH(m1, &td->td_contested, mtx_contested) {
		int cp = TAILQ_FIRST(&m1->mtx_blocked)->td_ksegrp->kg_pri.pri_level;
		if (cp < pri)
			pri = cp;
	}

	if (pri > kg->kg_pri.pri_native)
		pri = kg->kg_pri.pri_native;
	SET_PRIO(td, pri);

	if (LOCK_LOG_TEST(&m->mtx_object, opts))
		CTR2(KTR_LOCK, "_mtx_unlock_sleep: %p contested setrunqueue %p",
		    m, td1);

	td1->td_blocked = NULL;
	td1->td_proc->p_stat = SRUN;
	setrunqueue(td1);

	if ((opts & MTX_NOSWITCH) == 0 && td1->td_ksegrp->kg_pri.pri_level < pri) {
#ifdef notyet
		if (td->td_ithd != NULL) {
			struct ithd *it = td->td_ithd;

			if (it->it_interrupted) {
				if (LOCK_LOG_TEST(&m->mtx_object, opts))
					CTR2(KTR_LOCK,
				    "_mtx_unlock_sleep: %p interrupted %p",
					    it, it->it_interrupted);
				intr_thd_fixup(it);
			}
		}
#endif
		setrunqueue(td);
		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR2(KTR_LOCK,
			    "_mtx_unlock_sleep: %p switching out lock=%p", m,
			    (void *)m->mtx_lock);

		td->td_proc->p_stats->p_ru.ru_nivcsw++;
		mi_switch();
		if (LOCK_LOG_TEST(&m->mtx_object, opts))
			CTR2(KTR_LOCK, "_mtx_unlock_sleep: %p resuming lock=%p",
			    m, (void *)m->mtx_lock);
	}

	mtx_unlock_spin(&sched_lock);

	return;
}

/*
 * All the unlocking of MTX_SPIN locks is done inline.
 * See the _rel_spin_lock() macro for the details. 
 */

/*
 * The backing function for the INVARIANTS-enabled mtx_assert()
 */
#ifdef INVARIANT_SUPPORT
void
_mtx_assert(struct mtx *m, int what, const char *file, int line)
{

	if (panicstr != NULL)
		return;
	switch (what) {
	case MA_OWNED:
	case MA_OWNED | MA_RECURSED:
	case MA_OWNED | MA_NOTRECURSED:
		if (!mtx_owned(m))
			panic("mutex %s not owned at %s:%d",
			    m->mtx_object.lo_name, file, line);
		if (mtx_recursed(m)) {
			if ((what & MA_NOTRECURSED) != 0)
				panic("mutex %s recursed at %s:%d",
				    m->mtx_object.lo_name, file, line);
		} else if ((what & MA_RECURSED) != 0) {
			panic("mutex %s unrecursed at %s:%d",
			    m->mtx_object.lo_name, file, line);
		}
		break;
	case MA_NOTOWNED:
		if (mtx_owned(m))
			panic("mutex %s owned at %s:%d",
			    m->mtx_object.lo_name, file, line);
		break;
	default:
		panic("unknown mtx_assert at %s:%d", file, line);
	}
}
#endif

/*
 * The MUTEX_DEBUG-enabled mtx_validate()
 *
 * Most of these checks have been moved off into the LO_INITIALIZED flag
 * maintained by the witness code.
 */
#ifdef MUTEX_DEBUG

void	mtx_validate __P((struct mtx *));

void
mtx_validate(struct mtx *m)
{

/*
 * XXX - When kernacc() is fixed on the alpha to handle K0_SEG memory properly
 * we can re-enable the kernacc() checks.
 */
#ifndef __alpha__
	/*
	 * Can't call kernacc() from early init386(), especially when
	 * initializing Giant mutex, because some stuff in kernacc()
	 * requires Giant itself.
	 */ 
	if (!cold)
		if (!kernacc((caddr_t)m, sizeof(m),
		    VM_PROT_READ | VM_PROT_WRITE))
			panic("Can't read and write to mutex %p", m);
#endif
}
#endif

/*
 * Mutex initialization routine; initialize lock `m' of type contained in
 * `opts' with options contained in `opts' and description `description.'
 */ 
void
mtx_init(struct mtx *m, const char *description, int opts)
{
	struct lock_object *lock;

	MPASS((opts & ~(MTX_SPIN | MTX_QUIET | MTX_RECURSE |
	    MTX_SLEEPABLE | MTX_NOWITNESS)) == 0);

#ifdef MUTEX_DEBUG
	/* Diagnostic and error correction */
	mtx_validate(m);
#endif

	bzero(m, sizeof(*m));
	lock = &m->mtx_object;
	if (opts & MTX_SPIN)
		lock->lo_class = &lock_class_mtx_spin;
	else
		lock->lo_class = &lock_class_mtx_sleep;
	lock->lo_name = description;
	if (opts & MTX_QUIET)
		lock->lo_flags = LO_QUIET;
	if (opts & MTX_RECURSE)
		lock->lo_flags |= LO_RECURSABLE;
	if (opts & MTX_SLEEPABLE)
		lock->lo_flags |= LO_SLEEPABLE;
	if ((opts & MTX_NOWITNESS) == 0)
		lock->lo_flags |= LO_WITNESS;

	m->mtx_lock = MTX_UNOWNED;
	TAILQ_INIT(&m->mtx_blocked);

	LOCK_LOG_INIT(lock, opts);

	WITNESS_INIT(lock);
}

/*
 * Remove lock `m' from all_mtx queue.  We don't allow MTX_QUIET to be
 * passed in as a flag here because if the corresponding mtx_init() was
 * called with MTX_QUIET set, then it will already be set in the mutex's
 * flags.
 */
void
mtx_destroy(struct mtx *m)
{

	LOCK_LOG_DESTROY(&m->mtx_object, 0);

	if (!mtx_owned(m))
		MPASS(mtx_unowned(m));
	else {
		MPASS((m->mtx_lock & (MTX_RECURSED|MTX_CONTESTED)) == 0);

		/* Tell witness this isn't locked to make it happy. */
		WITNESS_UNLOCK(&m->mtx_object, LOP_EXCLUSIVE | LOP_NOSWITCH,
		    __FILE__, __LINE__);
	}

	WITNESS_DESTROY(&m->mtx_object);
}
