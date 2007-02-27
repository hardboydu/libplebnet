/*-
 * Copyright (c) 2006 John Baldwin <jhb@FreeBSD.org>
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
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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

/*
 * Machine independent bits of reader/writer lock implementation.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/systm.h>
#include <sys/turnstile.h>
#include <sys/lock_profile.h>
#include <machine/cpu.h>

#ifdef DDB
#include <ddb/ddb.h>

static void	db_show_rwlock(struct lock_object *lock);
#endif

struct lock_class lock_class_rw = {
	"rw",
	LC_SLEEPLOCK | LC_RECURSABLE | LC_UPGRADABLE,
#ifdef DDB
	db_show_rwlock
#endif
};

/*
 * Return a pointer to the owning thread if the lock is write-locked or
 * NULL if the lock is unlocked or read-locked.
 */
#define	rw_wowner(rw)							\
	((rw)->rw_lock & RW_LOCK_READ ? NULL :				\
	    (struct thread *)RW_OWNER((rw)->rw_lock))

/*
 * Return a pointer to the owning thread for this lock who should receive
 * any priority lent by threads that block on this lock.  Currently this
 * is identical to rw_wowner().
 */
#define	rw_owner(rw)		rw_wowner(rw)

#ifndef INVARIANTS
#define	_rw_assert(rw, what, file, line)
#endif

void
rw_init(struct rwlock *rw, const char *name)
{

	rw->rw_lock = RW_UNLOCKED;

	lock_profile_object_init(&rw->rw_object, &lock_class_rw, name);
	lock_init(&rw->rw_object, &lock_class_rw, name, NULL, LO_WITNESS |
	    LO_RECURSABLE | LO_UPGRADABLE);
}

void
rw_destroy(struct rwlock *rw)
{

	KASSERT(rw->rw_lock == RW_UNLOCKED, ("rw lock not unlocked"));
	lock_profile_object_destroy(&rw->rw_object);
	lock_destroy(&rw->rw_object);
}

void
rw_sysinit(void *arg)
{
	struct rw_args *args = arg;

	rw_init(args->ra_rw, args->ra_desc);
}

int
rw_wowned(struct rwlock *rw)
{

	return (rw_wowner(rw) == curthread);
}

void
_rw_wlock(struct rwlock *rw, const char *file, int line)
{

	MPASS(curthread != NULL);
	KASSERT(rw_wowner(rw) != curthread,
	    ("%s (%s): wlock already held @ %s:%d", __func__,
	    rw->rw_object.lo_name, file, line));
	WITNESS_CHECKORDER(&rw->rw_object, LOP_NEWORDER | LOP_EXCLUSIVE, file,
	    line);
	__rw_wlock(rw, curthread, file, line);
	LOCK_LOG_LOCK("WLOCK", &rw->rw_object, 0, 0, file, line);
	WITNESS_LOCK(&rw->rw_object, LOP_EXCLUSIVE, file, line);
	curthread->td_locks++;
}

void
_rw_wunlock(struct rwlock *rw, const char *file, int line)
{

	MPASS(curthread != NULL);
	_rw_assert(rw, RA_WLOCKED, file, line);
	curthread->td_locks--;
	WITNESS_UNLOCK(&rw->rw_object, LOP_EXCLUSIVE, file, line);
	LOCK_LOG_LOCK("WUNLOCK", &rw->rw_object, 0, 0, file, line);
	lock_profile_release_lock(&rw->rw_object);
	__rw_wunlock(rw, curthread, file, line);
}

void
_rw_rlock(struct rwlock *rw, const char *file, int line)
{
#ifdef SMP
	volatile struct thread *owner;
#endif
	uint64_t waitstart = 0;
	int contested = 0;
	uintptr_t x;

	KASSERT(rw_wowner(rw) != curthread,
	    ("%s (%s): wlock already held @ %s:%d", __func__,
	    rw->rw_object.lo_name, file, line));
	WITNESS_CHECKORDER(&rw->rw_object, LOP_NEWORDER, file, line);

	/*
	 * Note that we don't make any attempt to try to block read
	 * locks once a writer has blocked on the lock.  The reason is
	 * that we currently allow for read locks to recurse and we
	 * don't keep track of all the holders of read locks.  Thus, if
	 * we were to block readers once a writer blocked and a reader
	 * tried to recurse on their reader lock after a writer had
	 * blocked we would end up in a deadlock since the reader would
	 * be blocked on the writer, and the writer would be blocked
	 * waiting for the reader to release its original read lock.
	 */
	for (;;) {
		/*
		 * Handle the easy case.  If no other thread has a write
		 * lock, then try to bump up the count of read locks.  Note
		 * that we have to preserve the current state of the
		 * RW_LOCK_WRITE_WAITERS flag.  If we fail to acquire a
		 * read lock, then rw_lock must have changed, so restart
		 * the loop.  Note that this handles the case of a
		 * completely unlocked rwlock since such a lock is encoded
		 * as a read lock with no waiters.
		 */
		x = rw->rw_lock;
		if (x & RW_LOCK_READ) {

			/*
			 * The RW_LOCK_READ_WAITERS flag should only be set
			 * if another thread currently holds a write lock,
			 * and in that case RW_LOCK_READ should be clear.
			 */
			MPASS((x & RW_LOCK_READ_WAITERS) == 0);
			if (atomic_cmpset_acq_ptr(&rw->rw_lock, x,
			    x + RW_ONE_READER)) {
				lock_profile_obtain_lock_success(&rw->rw_object, contested, waitstart, file, line);
				if (LOCK_LOG_TEST(&rw->rw_object, 0))
					CTR4(KTR_LOCK,
					    "%s: %p succeed %p -> %p", __func__,
					    rw, (void *)x,
					    (void *)(x + RW_ONE_READER));
				break;
			}
			lock_profile_obtain_lock_failed(&rw->rw_object, &contested, &waitstart);
			cpu_spinwait();
			continue;
		}

		/*
		 * Okay, now it's the hard case.  Some other thread already
		 * has a write lock, so acquire the turnstile lock so we can
		 * begin the process of blocking.
		 */
		turnstile_lock(&rw->rw_object);

		/*
		 * The lock might have been released while we spun, so
		 * recheck its state and restart the loop if there is no
		 * longer a write lock.
		 */
		x = rw->rw_lock;
		if (x & RW_LOCK_READ) {
			turnstile_release(&rw->rw_object);
			cpu_spinwait();
			continue;
		}

		/*
		 * Ok, it's still a write lock.  If the RW_LOCK_READ_WAITERS
		 * flag is already set, then we can go ahead and block.  If
		 * it is not set then try to set it.  If we fail to set it
		 * drop the turnstile lock and restart the loop.
		 */
		if (!(x & RW_LOCK_READ_WAITERS)) {
			if (!atomic_cmpset_ptr(&rw->rw_lock, x,
			    x | RW_LOCK_READ_WAITERS)) {
				turnstile_release(&rw->rw_object);
				cpu_spinwait();
				continue;
			}
			if (LOCK_LOG_TEST(&rw->rw_object, 0))
				CTR2(KTR_LOCK, "%s: %p set read waiters flag",
				    __func__, rw);
		}

#ifdef SMP
		/*
		 * If the owner is running on another CPU, spin until
		 * the owner stops running or the state of the lock
		 * changes.
		 */
		owner = (struct thread *)RW_OWNER(x);
		if (TD_IS_RUNNING(owner)) {
			lock_profile_obtain_lock_failed(&rw->rw_object, &contested, &waitstart);
			turnstile_release(&rw->rw_object);
			if (LOCK_LOG_TEST(&rw->rw_object, 0))
				CTR3(KTR_LOCK, "%s: spinning on %p held by %p",
				    __func__, rw, owner);
			while ((struct thread*)RW_OWNER(rw->rw_lock)== owner &&
			    TD_IS_RUNNING(owner))
				cpu_spinwait();
			continue;
		}
#endif

		/*
		 * We were unable to acquire the lock and the read waiters
		 * flag is set, so we must block on the turnstile.
		 */
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p blocking on turnstile", __func__,
			    rw);
		turnstile_wait(&rw->rw_object, rw_owner(rw), TS_SHARED_QUEUE);
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p resuming from turnstile",
			    __func__, rw);
	}

	/*
	 * TODO: acquire "owner of record" here.  Here be turnstile dragons
	 * however.  turnstiles don't like owners changing between calls to
	 * turnstile_wait() currently.
	 */

	LOCK_LOG_LOCK("RLOCK", &rw->rw_object, 0, 0, file, line);
	WITNESS_LOCK(&rw->rw_object, 0, file, line);
	curthread->td_locks++;
}

void
_rw_runlock(struct rwlock *rw, const char *file, int line)
{
	struct turnstile *ts;
	uintptr_t x;

	_rw_assert(rw, RA_RLOCKED, file, line);
	curthread->td_locks--;
	WITNESS_UNLOCK(&rw->rw_object, 0, file, line);
	LOCK_LOG_LOCK("RUNLOCK", &rw->rw_object, 0, 0, file, line);

	/* TODO: drop "owner of record" here. */

	for (;;) {
		/*
		 * See if there is more than one read lock held.  If so,
		 * just drop one and return.
		 */
		x = rw->rw_lock;
		if (RW_READERS(x) > 1) {
			if (atomic_cmpset_ptr(&rw->rw_lock, x,
			    x - RW_ONE_READER)) {
				if (LOCK_LOG_TEST(&rw->rw_object, 0))
					CTR4(KTR_LOCK,
					    "%s: %p succeeded %p -> %p",
					    __func__, rw, (void *)x,
					    (void *)(x - RW_ONE_READER));
				break;
			}
			continue;
		} else 
			lock_profile_release_lock(&rw->rw_object);


		/*
		 * We should never have read waiters while at least one
		 * thread holds a read lock.  (See note above)
		 */
		KASSERT(!(x & RW_LOCK_READ_WAITERS),
		    ("%s: waiting readers", __func__));

		/*
		 * If there aren't any waiters for a write lock, then try
		 * to drop it quickly.
		 */
		if (!(x & RW_LOCK_WRITE_WAITERS)) {

			/*
			 * There shouldn't be any flags set and we should
			 * be the only read lock.  If we fail to release
			 * the single read lock, then another thread might
			 * have just acquired a read lock, so go back up
			 * to the multiple read locks case.
			 */
			MPASS(x == RW_READERS_LOCK(1));
			if (atomic_cmpset_ptr(&rw->rw_lock, RW_READERS_LOCK(1),
			    RW_UNLOCKED)) {
				if (LOCK_LOG_TEST(&rw->rw_object, 0))
					CTR2(KTR_LOCK, "%s: %p last succeeded",
					    __func__, rw);
				break;
			}
			continue;
		}

		/*
		 * There should just be one reader with one or more
		 * writers waiting.
		 */
		MPASS(x == (RW_READERS_LOCK(1) | RW_LOCK_WRITE_WAITERS));

		/*
		 * Ok, we know we have a waiting writer and we think we
		 * are the last reader, so grab the turnstile lock.
		 */
		turnstile_lock(&rw->rw_object);

		/*
		 * Try to drop our lock leaving the lock in a unlocked
		 * state.
		 *
		 * If you wanted to do explicit lock handoff you'd have to
		 * do it here.  You'd also want to use turnstile_signal()
		 * and you'd have to handle the race where a higher
		 * priority thread blocks on the write lock before the
		 * thread you wakeup actually runs and have the new thread
		 * "steal" the lock.  For now it's a lot simpler to just
		 * wakeup all of the waiters.
		 *
		 * As above, if we fail, then another thread might have
		 * acquired a read lock, so drop the turnstile lock and
		 * restart.
		 */
		if (!atomic_cmpset_ptr(&rw->rw_lock,
		    RW_READERS_LOCK(1) | RW_LOCK_WRITE_WAITERS, RW_UNLOCKED)) {
			turnstile_release(&rw->rw_object);
			continue;
		}
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p last succeeded with waiters",
			    __func__, rw);

		/*
		 * Ok.  The lock is released and all that's left is to
		 * wake up the waiters.  Note that the lock might not be
		 * free anymore, but in that case the writers will just
		 * block again if they run before the new lock holder(s)
		 * release the lock.
		 */
		ts = turnstile_lookup(&rw->rw_object);
		MPASS(ts != NULL);
		turnstile_broadcast(ts, TS_EXCLUSIVE_QUEUE);
		turnstile_unpend(ts, TS_SHARED_LOCK);
		break;
	}
}

/*
 * This function is called when we are unable to obtain a write lock on the
 * first try.  This means that at least one other thread holds either a
 * read or write lock.
 */
void
_rw_wlock_hard(struct rwlock *rw, uintptr_t tid, const char *file, int line)
{
#ifdef SMP
	volatile struct thread *owner;
#endif
	uintptr_t v;

	if (LOCK_LOG_TEST(&rw->rw_object, 0))
		CTR5(KTR_LOCK, "%s: %s contested (lock=%p) at %s:%d", __func__,
		    rw->rw_object.lo_name, (void *)rw->rw_lock, file, line);

	while (!_rw_write_lock(rw, tid)) {
		turnstile_lock(&rw->rw_object);
		v = rw->rw_lock;

		/*
		 * If the lock was released while spinning on the
		 * turnstile chain lock, try again.
		 */
		if (v == RW_UNLOCKED) {
			turnstile_release(&rw->rw_object);
			cpu_spinwait();
			continue;
		}

		/*
		 * If the lock was released by a writer with both readers
		 * and writers waiting and a reader hasn't woken up and
		 * acquired the lock yet, rw_lock will be set to the
		 * value RW_UNLOCKED | RW_LOCK_WRITE_WAITERS.  If we see
		 * that value, try to acquire it once.  Note that we have
		 * to preserve the RW_LOCK_WRITE_WAITERS flag as there are
		 * other writers waiting still. If we fail, restart the
		 * loop.
		 */
		if (v == (RW_UNLOCKED | RW_LOCK_WRITE_WAITERS)) {
			if (atomic_cmpset_acq_ptr(&rw->rw_lock,
			    RW_UNLOCKED | RW_LOCK_WRITE_WAITERS,
			    tid | RW_LOCK_WRITE_WAITERS)) {
				turnstile_claim(&rw->rw_object);
				CTR2(KTR_LOCK, "%s: %p claimed by new writer",
				    __func__, rw);
				break;
			}
			turnstile_release(&rw->rw_object);
			cpu_spinwait();
			continue;
		}

		/*
		 * If the RW_LOCK_WRITE_WAITERS flag isn't set, then try to
		 * set it.  If we fail to set it, then loop back and try
		 * again.
		 */
		if (!(v & RW_LOCK_WRITE_WAITERS)) {
			if (!atomic_cmpset_ptr(&rw->rw_lock, v,
			    v | RW_LOCK_WRITE_WAITERS)) {
				turnstile_release(&rw->rw_object);
				cpu_spinwait();
				continue;
			}
			if (LOCK_LOG_TEST(&rw->rw_object, 0))
				CTR2(KTR_LOCK, "%s: %p set write waiters flag",
				    __func__, rw);
		}

#ifdef SMP
		/*
		 * If the lock is write locked and the owner is
		 * running on another CPU, spin until the owner stops
		 * running or the state of the lock changes.
		 */
		owner = (struct thread *)RW_OWNER(v);
		if (!(v & RW_LOCK_READ) && TD_IS_RUNNING(owner)) {
			turnstile_release(&rw->rw_object);
			if (LOCK_LOG_TEST(&rw->rw_object, 0))
				CTR3(KTR_LOCK, "%s: spinning on %p held by %p",
				    __func__, rw, owner);
			while ((struct thread*)RW_OWNER(rw->rw_lock)== owner &&
			    TD_IS_RUNNING(owner))
				cpu_spinwait();
			continue;
		}
#endif

		/*
		 * We were unable to acquire the lock and the write waiters
		 * flag is set, so we must block on the turnstile.
		 */
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p blocking on turnstile", __func__,
			    rw);
		turnstile_wait(&rw->rw_object, rw_owner(rw),
		    TS_EXCLUSIVE_QUEUE);
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p resuming from turnstile",
			    __func__, rw);
	}
}

/*
 * This function is called if the first try at releasing a write lock failed.
 * This means that one of the 2 waiter bits must be set indicating that at
 * least one thread is waiting on this lock.
 */
void
_rw_wunlock_hard(struct rwlock *rw, uintptr_t tid, const char *file, int line)
{
	struct turnstile *ts;
	uintptr_t v;
	int queue;

	KASSERT(rw->rw_lock & (RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS),
	    ("%s: neither of the waiter flags are set", __func__));

	if (LOCK_LOG_TEST(&rw->rw_object, 0))
		CTR2(KTR_LOCK, "%s: %p contested", __func__, rw);

	turnstile_lock(&rw->rw_object);
	ts = turnstile_lookup(&rw->rw_object);

#ifdef SMP
	/*
	 * There might not be a turnstile for this lock if all of
	 * the waiters are adaptively spinning.  In that case, just
	 * reset the lock to the unlocked state and return.
	 */
	if (ts == NULL) {
		atomic_store_rel_ptr(&rw->rw_lock, RW_UNLOCKED);
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p no sleepers", __func__, rw);
		turnstile_release(&rw->rw_object);
		return;
	}
#else
	MPASS(ts != NULL);
#endif

	/*
	 * Use the same algo as sx locks for now.  Prefer waking up shared
	 * waiters if we have any over writers.  This is probably not ideal.
	 *
	 * 'v' is the value we are going to write back to rw_lock.  If we
	 * have waiters on both queues, we need to preserve the state of
	 * the waiter flag for the queue we don't wake up.  For now this is
	 * hardcoded for the algorithm mentioned above.
	 *
	 * In the case of both readers and writers waiting we wakeup the
	 * readers but leave the RW_LOCK_WRITE_WAITERS flag set.  If a
	 * new writer comes in before a reader it will claim the lock up
	 * above.  There is probably a potential priority inversion in
	 * there that could be worked around either by waking both queues
	 * of waiters or doing some complicated lock handoff gymnastics.
	 *
	 * Note that in the SMP case, if both flags are set, there might
	 * not be any actual writers on the turnstile as they might all
	 * be spinning.  In that case, we don't want to preserve the
	 * RW_LOCK_WRITE_WAITERS flag as the turnstile is going to go
	 * away once we wakeup all the readers.
	 */
	v = RW_UNLOCKED;
	if (rw->rw_lock & RW_LOCK_READ_WAITERS) {
		queue = TS_SHARED_QUEUE;
#ifdef SMP
		if (rw->rw_lock & RW_LOCK_WRITE_WAITERS &&
		    !turnstile_empty(ts, TS_EXCLUSIVE_QUEUE))
			v |= RW_LOCK_WRITE_WAITERS;
#else
		v |= (rw->rw_lock & RW_LOCK_WRITE_WAITERS);
#endif
	} else
		queue = TS_EXCLUSIVE_QUEUE;

#ifdef SMP
	/*
	 * We have to make sure that we actually have waiters to
	 * wakeup.  If they are all spinning, then we just need to
	 * disown the turnstile and return.
	 */
	if (turnstile_empty(ts, queue)) {
		if (LOCK_LOG_TEST(&rw->rw_object, 0))
			CTR2(KTR_LOCK, "%s: %p no sleepers 2", __func__, rw);
		atomic_store_rel_ptr(&rw->rw_lock, v);
		turnstile_disown(ts);
		return;
	}
#endif

	/* Wake up all waiters for the specific queue. */
	if (LOCK_LOG_TEST(&rw->rw_object, 0))
		CTR3(KTR_LOCK, "%s: %p waking up %s waiters", __func__, rw,
		    queue == TS_SHARED_QUEUE ? "read" : "write");
	turnstile_broadcast(ts, queue);
	atomic_store_rel_ptr(&rw->rw_lock, v);
	turnstile_unpend(ts, TS_EXCLUSIVE_LOCK);
}

/*
 * Attempt to do a non-blocking upgrade from a read lock to a write
 * lock.  This will only succeed if this thread holds a single read
 * lock.  Returns true if the upgrade succeeded and false otherwise.
 */
int
_rw_try_upgrade(struct rwlock *rw, const char *file, int line)
{
	uintptr_t v, tid;
	int success;

	_rw_assert(rw, RA_RLOCKED, file, line);

	/*
	 * Attempt to switch from one reader to a writer.  If there
	 * are any write waiters, then we will have to lock the
	 * turnstile first to prevent races with another writer
	 * calling turnstile_wait() before we have claimed this
	 * turnstile.  So, do the simple case of no waiters first.
	 */
	tid = (uintptr_t)curthread;
	if (!(rw->rw_lock & RW_LOCK_WRITE_WAITERS)) {
		success = atomic_cmpset_acq_ptr(&rw->rw_lock,
		    RW_READERS_LOCK(1), tid);
		goto out;
	}

	/*
	 * Ok, we think we have write waiters, so lock the
	 * turnstile.
	 */
	turnstile_lock(&rw->rw_object);

	/*
	 * Try to switch from one reader to a writer again.  This time
	 * we honor the current state of the RW_LOCK_WRITE_WAITERS
	 * flag.  If we obtain the lock with the flag set, then claim
	 * ownership of the turnstile.  In the SMP case it is possible
	 * for there to not be an associated turnstile even though there
	 * are waiters if all of the waiters are spinning.
	 */
	v = rw->rw_lock & RW_LOCK_WRITE_WAITERS;
	success = atomic_cmpset_acq_ptr(&rw->rw_lock, RW_READERS_LOCK(1) | v,
	    tid | v);
#ifdef SMP
	if (success && v && turnstile_lookup(&rw->rw_object) != NULL)
#else
	if (success && v)
#endif
		turnstile_claim(&rw->rw_object);
	else
		turnstile_release(&rw->rw_object);
out:
	LOCK_LOG_TRY("WUPGRADE", &rw->rw_object, 0, success, file, line);
	if (success)
		WITNESS_UPGRADE(&rw->rw_object, LOP_EXCLUSIVE | LOP_TRYLOCK,
		    file, line);
	return (success);
}

/*
 * Downgrade a write lock into a single read lock.
 */
void
_rw_downgrade(struct rwlock *rw, const char *file, int line)
{
	struct turnstile *ts;
	uintptr_t tid, v;

	_rw_assert(rw, RA_WLOCKED, file, line);

	WITNESS_DOWNGRADE(&rw->rw_object, 0, file, line);

	/*
	 * Convert from a writer to a single reader.  First we handle
	 * the easy case with no waiters.  If there are any waiters, we
	 * lock the turnstile, "disown" the lock, and awaken any read
	 * waiters.
	 */
	tid = (uintptr_t)curthread;
	if (atomic_cmpset_rel_ptr(&rw->rw_lock, tid, RW_READERS_LOCK(1)))
		goto out;

	/*
	 * Ok, we think we have waiters, so lock the turnstile so we can
	 * read the waiter flags without any races.
	 */
	turnstile_lock(&rw->rw_object);
	v = rw->rw_lock;
	MPASS(v & (RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS));

	/*
	 * Downgrade from a write lock while preserving
	 * RW_LOCK_WRITE_WAITERS and give up ownership of the
	 * turnstile.  If there are any read waiters, wake them up.
	 *
	 * For SMP, we have to allow for the fact that all of the
	 * read waiters might be spinning.  In that case, act as if
	 * RW_LOCK_READ_WAITERS is not set.  Also, only preserve
	 * the RW_LOCK_WRITE_WAITERS flag if at least one writer is
	 * blocked on the turnstile.
	 */
	ts = turnstile_lookup(&rw->rw_object);
#ifdef SMP
	if (ts == NULL)
		v &= ~(RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS);
	else if (v & RW_LOCK_READ_WAITERS &&
	    turnstile_empty(ts, TS_SHARED_QUEUE))
		v &= ~RW_LOCK_READ_WAITERS;
	else if (v & RW_LOCK_WRITE_WAITERS &&
	    turnstile_empty(ts, TS_EXCLUSIVE_QUEUE))
		v &= ~RW_LOCK_WRITE_WAITERS;
#else
	MPASS(ts != NULL);
#endif
	if (v & RW_LOCK_READ_WAITERS)
		turnstile_broadcast(ts, TS_SHARED_QUEUE);
	atomic_store_rel_ptr(&rw->rw_lock, RW_READERS_LOCK(1) |
	    (v & RW_LOCK_WRITE_WAITERS));
	if (v & RW_LOCK_READ_WAITERS)
		turnstile_unpend(ts, TS_EXCLUSIVE_LOCK);
#ifdef SMP
	else if (ts == NULL)
		turnstile_release(&rw->rw_object);
#endif
	else
		turnstile_disown(ts);
out:
	LOCK_LOG_LOCK("WDOWNGRADE", &rw->rw_object, 0, 0, file, line);
}

#ifdef INVARIANT_SUPPORT
#ifndef INVARIANTS
#undef _rw_assert
#endif

/*
 * In the non-WITNESS case, rw_assert() can only detect that at least
 * *some* thread owns an rlock, but it cannot guarantee that *this*
 * thread owns an rlock.
 */
void
_rw_assert(struct rwlock *rw, int what, const char *file, int line)
{

	if (panicstr != NULL)
		return;
	switch (what) {
	case RA_LOCKED:
	case RA_RLOCKED:
#ifdef WITNESS
		witness_assert(&rw->rw_object, what, file, line);
#else
		/*
		 * If some other thread has a write lock or we have one
		 * and are asserting a read lock, fail.  Also, if no one
		 * has a lock at all, fail.
		 */
		if (rw->rw_lock == RW_UNLOCKED ||
		    (!(rw->rw_lock & RW_LOCK_READ) && (what == RA_RLOCKED ||
		    rw_wowner(rw) != curthread)))
			panic("Lock %s not %slocked @ %s:%d\n",
			    rw->rw_object.lo_name, (what == RA_RLOCKED) ?
			    "read " : "", file, line);
#endif
		break;
	case RA_WLOCKED:
		if (rw_wowner(rw) != curthread)
			panic("Lock %s not exclusively locked @ %s:%d\n",
			    rw->rw_object.lo_name, file, line);
		break;
	case RA_UNLOCKED:
#ifdef WITNESS
		witness_assert(&rw->rw_object, what, file, line);
#else
		/*
		 * If we hold a write lock fail.  We can't reliably check
		 * to see if we hold a read lock or not.
		 */
		if (rw_wowner(rw) == curthread)
			panic("Lock %s exclusively locked @ %s:%d\n",
			    rw->rw_object.lo_name, file, line);
#endif
		break;
	default:
		panic("Unknown rw lock assertion: %d @ %s:%d", what, file,
		    line);
	}
}
#endif /* INVARIANT_SUPPORT */

#ifdef DDB
void
db_show_rwlock(struct lock_object *lock)
{
	struct rwlock *rw;
	struct thread *td;

	rw = (struct rwlock *)lock;

	db_printf(" state: ");
	if (rw->rw_lock == RW_UNLOCKED)
		db_printf("UNLOCKED\n");
	else if (rw->rw_lock & RW_LOCK_READ)
		db_printf("RLOCK: %jd locks\n",
		    (intmax_t)(RW_READERS(rw->rw_lock)));
	else {
		td = rw_wowner(rw);
		db_printf("WLOCK: %p (tid %d, pid %d, \"%s\")\n", td,
		    td->td_tid, td->td_proc->p_pid, td->td_proc->p_comm);
	}
	db_printf(" waiters: ");
	switch (rw->rw_lock & (RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS)) {
	case RW_LOCK_READ_WAITERS:
		db_printf("readers\n");
		break;
	case RW_LOCK_WRITE_WAITERS:
		db_printf("writers\n");
		break;
	case RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS:
		db_printf("readers and waiters\n");
		break;
	default:
		db_printf("none\n");
		break;
	}
}

#endif
