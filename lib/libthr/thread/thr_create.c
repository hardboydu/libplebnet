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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/time.h>
#include <machine/reg.h>
#include <pthread.h>
#include "thr_private.h"
#include "libc_private.h"

static u_int64_t next_uniqueid = 1;

#define OFF(f)	offsetof(struct pthread, f)
int _thread_next_offset			= OFF(tle.tqe_next);
int _thread_uniqueid_offset		= OFF(uniqueid);
int _thread_state_offset		= OFF(state);
int _thread_name_offset			= OFF(name);
int _thread_ctx_offset			= OFF(ctx);
#undef OFF

int _thread_PS_RUNNING_value		= PS_RUNNING;
int _thread_PS_DEAD_value		= PS_DEAD;

__weak_reference(_pthread_create, pthread_create);

int
_pthread_create(pthread_t * thread, const pthread_attr_t * attr,
	       void *(*start_routine) (void *), void *arg)
{
	int		f_gc = 0;
	int             ret = 0;
	pthread_t       gc_thread;
	pthread_t       new_thread;
	pthread_attr_t	pattr;
	int		flags;
	void           *stack;

	/*
	 * Locking functions in libc are required when there are
	 * threads other than the initial thread.
	 */
	__isthreaded = 1;

	/* Allocate memory for the thread structure: */
	if ((new_thread = (pthread_t) malloc(sizeof(struct pthread))) == NULL)
		return (EAGAIN);

	/* Check if default thread attributes are required: */
	if (attr == NULL || *attr == NULL) 
		pattr = &pthread_attr_default;
	else 
		pattr = *attr;
	
	/* Check if a stack was specified in the thread attributes: */
	if ((stack = pattr->stackaddr_attr) == NULL) {
		stack = _thread_stack_alloc(pattr->stacksize_attr,
		    pattr->guardsize_attr);
		if (stack == NULL) {
			free(new_thread);
			return (EAGAIN);
		}
	}

	/* Initialise the thread structure: */
	memset(new_thread, 0, sizeof(struct pthread));
	new_thread->stack = stack;
	new_thread->start_routine = start_routine;
	new_thread->arg = arg;

	new_thread->cancelflags = PTHREAD_CANCEL_ENABLE |
	    PTHREAD_CANCEL_DEFERRED;

	/*
	 * Write a magic value to the thread structure
	 * to help identify valid ones:
	 */
	new_thread->magic = PTHREAD_MAGIC;

	/* Initialise the machine context: */
	getcontext(&new_thread->ctx);
	new_thread->ctx.uc_stack.ss_sp = new_thread->stack;
	new_thread->ctx.uc_stack.ss_size = pattr->stacksize_attr;
	makecontext(&new_thread->ctx, _thread_start, 0);
	new_thread->arch_id = _set_curthread(&new_thread->ctx, new_thread);

	/* Copy the thread attributes: */
	memcpy(&new_thread->attr, pattr, sizeof(struct pthread_attr));

	/*
	 * Check if this thread is to inherit the scheduling
	 * attributes from its parent:
	 */
	if (new_thread->attr.flags & PTHREAD_INHERIT_SCHED) {
		/* Copy the scheduling attributes: */
		new_thread->base_priority = curthread->base_priority &
		    ~PTHREAD_SIGNAL_PRIORITY;
		new_thread->attr.prio = curthread->base_priority &
		    ~PTHREAD_SIGNAL_PRIORITY;
		new_thread->attr.sched_policy = curthread->attr.sched_policy;
	} else {
		/*
		 * Use just the thread priority, leaving the
		 * other scheduling attributes as their
		 * default values:
		 */
		new_thread->base_priority = new_thread->attr.prio;
	}
	new_thread->active_priority = new_thread->base_priority;
	new_thread->inherited_priority = 0;

	/* Initialize joiner to NULL (no joiner): */
	new_thread->joiner = NULL;

	/* Initialize the mutex queue: */
	TAILQ_INIT(&new_thread->mutexq);

	/* Initialise hooks in the thread structure: */
	new_thread->specific = NULL;
	new_thread->cleanup = NULL;
	new_thread->flags = 0;

	/*
	 * Initialise the unique id which GDB uses to
	 * track threads.
	 */
	new_thread->uniqueid = next_uniqueid++;

	THREAD_LIST_LOCK;
	_thread_critical_enter(new_thread);

	/*
	 * Check if the garbage collector thread
	 * needs to be started.
	 */
	f_gc = (TAILQ_FIRST(&_thread_list) == _thread_initial);

	/* Add the thread to the linked list of all threads: */
	TAILQ_INSERT_HEAD(&_thread_list, new_thread, tle);

	THREAD_LIST_UNLOCK;

	/*
	 * Create the thread.
	 *
	 */
	if (pattr->suspend == PTHREAD_FLAGS_SUSPENDED)
		flags = THR_SUSPENDED;
	else
		flags = 0;

	ret = thr_create(&new_thread->ctx, &new_thread->thr_id, flags);
	    
	if (ret != 0) {
		_thread_printf(STDERR_FILENO, "thr_create() == %d\n", ret);
		PANIC("thr_create");
	}

	/* Return a pointer to the thread structure: */
	(*thread) = new_thread;

	_thread_critical_exit(new_thread);

	/*
	 * Start a garbage collector thread
	 * if necessary.
	 */
	if (f_gc && pthread_create(&gc_thread,NULL, _thread_gc,NULL) != 0)
		PANIC("Can't create gc thread");

	return (0);
}

void
_thread_start(void)
{

	/* Run the current thread's start routine with argument: */
	pthread_exit(curthread->start_routine(curthread->arg));

	/* This point should never be reached. */
	PANIC("Thread has resumed after exit");
}
