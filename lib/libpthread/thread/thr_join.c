/*
 * Copyright (c) 1995 John Birrell <jb@cimlogic.com.au>.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by John Birrell.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN BIRRELL AND CONTRIBUTORS ``AS IS'' AND
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
#include <errno.h>
#include <pthread.h>
#include "thr_private.h"

__weak_reference(_pthread_join, pthread_join);

int
_pthread_join(pthread_t pthread, void **thread_return)
{
	struct pthread	*curthread = _get_curthread();
	int		ret = 0;
 
	_thr_enter_cancellation_point(curthread);

	/* Check if the caller has specified an invalid thread: */
	if (pthread == NULL || pthread->magic != THR_MAGIC) {
		/* Invalid thread: */
		_thr_leave_cancellation_point(curthread);
		return (EINVAL);
	}

	/* Check if the caller has specified itself: */
	if (pthread == curthread) {
		/* Avoid a deadlock condition: */
		_thr_leave_cancellation_point(curthread);
		return (EDEADLK);
	}

	/*
	 * Find the thread in the list of active threads or in the
	 * list of dead threads:
	 */
	if ((ret = _thr_ref_add(curthread, pthread, /*include dead*/1)) != 0) {
		/* Return an error: */
		_thr_leave_cancellation_point(curthread);
		return (ESRCH);
	}

	/* Check if this thread has been detached: */
	if ((pthread->attr.flags & PTHREAD_DETACHED) != 0) {
		/* Remove the reference and return an error: */
		_thr_ref_delete(curthread, pthread);
		ret = ESRCH;
	} else {
		/* Lock the target thread while checking its state. */
		THR_SCHED_LOCK(curthread, pthread);
		if ((pthread->state == PS_DEAD) ||
		    ((pthread->flags & THR_FLAGS_EXITING) != 0)) {
			if (thread_return != NULL)
				/* Return the thread's return value: */
				*thread_return = pthread->ret;

			/* Unlock the thread and remove the reference. */
			THR_SCHED_UNLOCK(curthread, pthread);
			_thr_ref_delete(curthread, pthread);
		}
		else if (pthread->joiner != NULL) {
			/* Unlock the thread and remove the reference. */
			THR_SCHED_UNLOCK(curthread, pthread);
			_thr_ref_delete(curthread, pthread);

			/* Multiple joiners are not supported. */
			ret = ENOTSUP;
		}
		else {
			/* Set the running thread to be the joiner: */
			pthread->joiner = curthread;

			/* Keep track of which thread we're joining to: */
			curthread->join_status.thread = pthread;

			/* Unlock the thread and remove the reference. */
			THR_SCHED_UNLOCK(curthread, pthread);
			_thr_ref_delete(curthread, pthread);

			THR_SCHED_LOCK(curthread, curthread);
			if (curthread->join_status.thread == pthread)
				THR_SET_STATE(curthread, PS_JOIN);
			THR_SCHED_UNLOCK(curthread, curthread);

			while (curthread->join_status.thread == pthread) {
				/* Schedule the next thread: */
				_thr_sched_switch(curthread);
			}

			/*
			 * The thread return value and error are set by the
			 * thread we're joining to when it exits or detaches:
			 */
			ret = curthread->join_status.error;
			if ((ret == 0) && (thread_return != NULL))
				*thread_return = curthread->join_status.ret;
		}
	}
	_thr_leave_cancellation_point(curthread);

	/* Return the completion status: */
	return (ret);
}
