/*
 * Copyright (c) 1995-1998 John Birrell <jb@cimlogic.com.au>
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
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "thr_private.h"

__weak_reference(_pthread_exit, pthread_exit);

/* thr_exit() */
extern int _thr_exit(void);

void
_thread_exit(char *fname, int lineno, char *string)
{
	char            s[256];

	/* Prepare an error message string: */
	snprintf(s, sizeof(s),
	    "Fatal error '%s' at line %d in file %s (errno = %d)\n",
	    string, lineno, fname, errno);

	/* Write the string to the standard error file descriptor: */
	__sys_write(2, s, strlen(s));

	/* Force this process to exit: */
	/* XXX - Do we want abort to be conditional on _PTHREADS_INVARIANTS? */
#if defined(_PTHREADS_INVARIANTS)
	abort();
#else
	__sys_exit(1);
#endif
}

/*
 * Only called when a thread is cancelled.  It may be more useful
 * to call it from pthread_exit() if other ways of asynchronous or
 * abnormal thread termination can be found.
 */
void
_thread_exit_cleanup(void)
{
	/*
	 * POSIX states that cancellation/termination of a thread should
	 * not release any visible resources (such as mutexes) and that
	 * it is the applications responsibility.  Resources that are
	 * internal to the threads library, including file and fd locks,
	 * are not visible to the application and need to be released.
	 */
	/* Unlock all private mutexes: */
	_mutex_unlock_private(curthread);

	/*
	 * This still isn't quite correct because we don't account
	 * for held spinlocks (see libc/stdlib/malloc.c).
	 */
}

void
_pthread_exit(void *status)
{
	pthread_t pthread, joiner;
	int exitNow = 0;

	/* Check if this thread is already in the process of exiting: */
	if ((curthread->flags & PTHREAD_EXITING) != 0) {
		char msg[128];
		snprintf(msg, sizeof(msg), "Thread %p has called pthread_exit() from a destructor. POSIX 1003.1 1996 s16.2.5.2 does not allow this!",curthread);
		PANIC(msg);
	}

	/* Flag this thread as exiting: */
	curthread->flags |= PTHREAD_EXITING;

	/* Save the return value: */
	curthread->ret = status;

	while (curthread->cleanup != NULL) {
		pthread_cleanup_pop(1);
	}
	if (curthread->attr.cleanup_attr != NULL) {
		curthread->attr.cleanup_attr(curthread->attr.arg_attr);
	}
	/* Check if there is thread specific data: */
	if (curthread->specific != NULL) {
		/* Run the thread-specific data destructors: */
		_thread_cleanupspecific();
	}

retry:
	/*
	 * Proper lock order, to minimize deadlocks, between joining
	 * and exiting threads is: DEAD_LIST, THREAD_LIST, exiting, joiner.
	 * In order to do this *and* protect from races, we must resort
	 * this test-and-retry loop.
	 */
	joiner = curthread->joiner;

	/* Lock the dead list first to maintain correct lock order */
	DEAD_LIST_LOCK;
	THREAD_LIST_LOCK;
	_thread_critical_enter(curthread);

	if (joiner != curthread->joiner) {
		_thread_critical_exit(curthread);
		THREAD_LIST_UNLOCK;
		DEAD_LIST_UNLOCK;
		goto retry;
	}

	/* Check if there is a thread joining this one: */
	if (curthread->joiner != NULL) {
		pthread = curthread->joiner;
		UMTX_LOCK(&pthread->lock);
		curthread->joiner = NULL;

		/* Make the joining thread runnable: */
		PTHREAD_NEW_STATE(pthread, PS_RUNNING);

		/* Set the return value for the joining thread: */
		pthread->join_status.ret = curthread->ret;
		pthread->join_status.error = 0;
		pthread->join_status.thread = NULL;
		UMTX_UNLOCK(&pthread->lock);

		/* Make this thread collectable by the garbage collector. */
		PTHREAD_ASSERT(((curthread->attr.flags & PTHREAD_DETACHED) ==
		    0), "Cannot join a detached thread");
		curthread->attr.flags |= PTHREAD_DETACHED;
	}

	/*
	 * Add this thread to the list of dead threads, and
	 * also remove it from the active threads list.
	 */
	TAILQ_INSERT_HEAD(&_dead_list, curthread, dle);
	TAILQ_REMOVE(&_thread_list, curthread, tle);
	PTHREAD_SET_STATE(curthread, PS_DEAD);
	_thread_critical_exit(curthread);
	
	/* If we're the last thread, call it quits */
	if (TAILQ_EMPTY(&_thread_list))
		exitNow = 1;

	THREAD_LIST_UNLOCK;

	/*
	 * Signal the garbage collector thread that there is something
	 * to clean up. But don't allow it to free the memory until after
	 * it is retired by holding on to the dead list lock.
	 */
	if (pthread_cond_signal(&_gc_cond) != 0)
		PANIC("Cannot signal gc cond");

	if (exitNow)
		exit(0);

	DEAD_LIST_UNLOCK;

	/*
	 * This function will not return unless we are the last
	 * thread, which we can't be because we've already checked
	 * for that.
	 */
	_thr_exit();

	/* This point should not be reached. */
	PANIC("Dead thread has resumed");
}
