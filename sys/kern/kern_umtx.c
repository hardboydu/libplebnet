/*
 * Copyright (c) 2002, Jeffrey Roberson <jeff@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/thr.h>
#include <sys/umtx.h>

int
_umtx_lock(struct thread *td, struct _umtx_lock_args *uap)
    /* struct umtx *umtx */
{
	struct umtx *umtx;
	struct thread *blocked;
	intptr_t owner;
	int error;

	error = 0;

	/*
	 * Care must be exercised when dealing with this structure.  It
	 * can fault on any access.
	 */
	umtx = uap->umtx;	

	PROC_LOCK(td->td_proc);

	for (;;) {
		/*
		 * Try the uncontested case.  This should be done in userland.
		 */
		owner = casuptr((intptr_t *)&umtx->u_owner,
		    UMTX_UNOWNED, (intptr_t)td);

		/* The acquire succeeded. */
		if (owner == (intptr_t)td) {
			error = 0;
			goto out;
		}

		/* The address was invalid. */
		if (owner == -1) {
			error = EFAULT;
			goto out;
		}

		if (owner & UMTX_CONTESTED)
			break;

		/*
		 * Set the contested bit so that a release in user space
		 * knows to use the system call for unlock.  If this fails
		 * either some one else has acquired the lock or it has been
		 * released.
		 */
		owner = casuptr((intptr_t *)&umtx->u_owner, owner, owner | UMTX_CONTESTED);

		/* The contested bit was set. */
		if (owner & UMTX_CONTESTED)
			break;

		/* The address was invalid. */
		if (owner == -1) {
			error = EFAULT;
			goto out;
		}
		/* We didn't set the contested bit, try again. */
	}

	/*
	 * We are now protected from further races via the proc lock.
	 * If userland messes with their mutex without using cmpset
	 * they will deadlock themselves but they will still be
	 * killable via signals.
	 */

	if ((owner = fuword(&umtx->u_blocked)) == -1) {
		error = EFAULT;
		goto out;
	}

	if (owner == UMTX_UNOWNED) {
		if (suword(&umtx->u_blocked, (long)td) == -1) {
			error = EFAULT;
			goto out;
		}
		/*
		 * Other blocked threads will reside here.
		 */
		STAILQ_INIT(&td->td_umtxq);
	} else {
		FOREACH_THREAD_IN_PROC(td->td_proc, blocked)
			if (blocked == (struct thread *)(owner))
				break;

		if (blocked == NULL) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Insert us onto the end of the TAILQ.
		 */
		STAILQ_INSERT_TAIL(&blocked->td_umtxq, td, td_umtx);
	}

	for (;;) {
		/*
		 * Sleep until we can acquire the lock.  We must still deliver
		 * signals so that they are not deferred until we acquire the
		 * lock which may be never.  The threads actual priority is
		 * used to maintain proper ordering.
		 */

		error = msleep(&td->td_umtx, &td->td_proc->p_mtx,
		    td->td_priority | PCATCH, "umtx", 0);

		/*
		 * When we are woken up we need to see if we now own the lock
		 * even if a signal was delivered.
		 */
		if ((owner = fuword(&umtx->u_owner)) == -1) {
			error = EFAULT;
			break;
		}
		owner &= ~UMTX_CONTESTED;
		if ((struct thread *)owner == td) {
			error = 0;
			break;
		}

		/*
		 * We may have signals to deliver.
		 */
		if (error)
			break;
	}

out:
	PROC_UNLOCK(td->td_proc);

	return (error);
}

int
_umtx_unlock(struct thread *td, struct _umtx_unlock_args *uap)
    /* struct umtx *umtx */
{
	struct thread *td0;
	struct umtx *umtx;
	intptr_t owner;
	intptr_t blocked;
	int error;

	error = 0;
	umtx = uap->umtx;

	PROC_LOCK(td->td_proc);

	/*
	 * Make sure we own this mtx.
	 *
	 * XXX Need a {fu,su}ptr this is not correct on arch where
	 * sizeof(intptr_t) != sizeof(long).
	 */
	if ((owner = fuword(&umtx->u_owner)) == -1) {
		error = EFAULT;
		goto out;
	}
	if ((struct thread *)(owner & ~UMTX_CONTESTED) != td) {
		error = EPERM;
		goto out;
	}
	/*
	 * If we own it but it isn't contested then we can just release and
	 * return.
	 */
	if ((owner & UMTX_CONTESTED) == 0) {
		owner = casuptr((intptr_t *)&umtx->u_owner,
		    (intptr_t)td, UMTX_UNOWNED);

		if (owner == -1)
			error = EFAULT;
		/*
		 * If this failed someone modified the memory without going
		 * through this api.
		 */
		else if (owner != UMTX_UNOWNED)
			error = EINVAL;
		else
			error = 0;

		goto out;
	}

	/*
	 * Since we own the mutex and the proc lock we are free to inspect
	 * the blocked queue.  It must have one valid entry since the
	 * CONTESTED bit was set.
	 */
	blocked = fuword(&umtx->u_blocked);
	if (blocked == -1){ 
		error = EFAULT;
		goto out;
	}
	if (blocked == 0) {
		error = EINVAL;
		goto out;
	}

	FOREACH_THREAD_IN_PROC(td->td_proc, td0)
		if (td0 == (struct thread *)blocked)
			break;

	if (td0 == NULL) {
		error = EINVAL;
		goto out;
	}

	if (!STAILQ_EMPTY(&td0->td_umtxq)) {
		struct thread *next;

		blocked |= UMTX_CONTESTED;
		next = STAILQ_FIRST(&td0->td_umtxq);
		if (suword(&umtx->u_blocked, (long)next) == -1) {
			error = EFAULT;
			goto out;
		}
		STAILQ_REMOVE_HEAD(&td0->td_umtxq, td_umtx);

		/*
		 * Switch the queue over to the next blocked thread.
		 */
		if (!STAILQ_EMPTY(&td0->td_umtxq)) {
			next->td_umtxq = td0->td_umtxq;
			STAILQ_INIT(&td0->td_umtxq);
		} else
			STAILQ_INIT(&next->td_umtxq);
	} else {
		if (suword(&umtx->u_blocked, UMTX_UNOWNED) == -1) {
			error = EFAULT;
			goto out;
		}
	}
	/*
	 * Now directly assign this mutex to the first thread that was
	 * blocked on it.
	 */
	owner = casuptr((intptr_t *)&umtx->u_owner, owner, blocked);

	/*
	 * This will only happen if someone modifies the lock without going
	 * through this api.
	 */
	if (owner != blocked) {
		error = EINVAL;
		goto out;
	}
	if (owner == -1) {
		error = EFAULT;
		goto out;
	}
	/* Success. */
	error = 0;
	wakeup(&td0->td_umtx);

out:
	PROC_UNLOCK(td->td_proc);

	return (error);
}
