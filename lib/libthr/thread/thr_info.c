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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include "thr_private.h"

#ifndef NELEMENTS
#define NELEMENTS(arr)	(sizeof(arr) / sizeof(arr[0]))
#endif

static void	dump_thread(int fd, pthread_t pthread, int long_version);

__weak_reference(_pthread_set_name_np, pthread_set_name_np);

struct s_thread_info {
	enum pthread_state state;
	char           *name;
};

/* Static variables: */
static const struct s_thread_info thread_info[] = {
	{PS_RUNNING	, "Running"},
	{PS_MUTEX_WAIT	, "Waiting on a mutex"},
	{PS_COND_WAIT	, "Waiting on a condition variable"},
	{PS_SLEEP_WAIT	, "Sleeping"},
	{PS_WAIT_WAIT	, "Waiting process"},
	{PS_JOIN	, "Waiting to join"},
	{PS_DEAD	, "Dead"},
	{PS_DEADLOCK	, "Deadlocked"},
	{PS_STATE_MAX	, "Not a real state!"}
};

void
_thread_dump_info(void)
{
	char            s[512];
	int             fd;
	int             i;
	pthread_t       pthread;
	char		tmpfile[128];

	for (i = 0; i < 100000; i++) {
		snprintf(tmpfile, sizeof(tmpfile), "/tmp/uthread.dump.%u.%i",
			getpid(), i);
		/* Open the dump file for append and create it if necessary: */
		if ((fd = __sys_open(tmpfile, O_RDWR | O_CREAT | O_EXCL,
			0666)) < 0) {
				/* Can't open the dump file. */
				if (errno == EEXIST)
					continue;
				/*
				 * We only need to continue in case of
				 * EEXIT error. Most other error
				 * codes means that we will fail all
				 * the times.
				 */
				return;
		} else {
			break;
		}
	}
	if (i==100000) {
		/* all 100000 possibilities are in use :( */
		return;
	} else {
		/* Output a header for active threads: */
		strcpy(s, "\n\n=============\nACTIVE THREADS\n\n");
		__sys_write(fd, s, strlen(s));

		/* Enter a loop to report each thread in the global list: */
		TAILQ_FOREACH(pthread, &_thread_list, tle) {
			dump_thread(fd, pthread, /*long_verson*/ 1);
		}

		/* Check if there are no dead threads: */
		if (TAILQ_FIRST(&_dead_list) == NULL) {
			/* Output a record: */
			strcpy(s, "\n\nTHERE ARE NO DEAD THREADS\n");
			__sys_write(fd, s, strlen(s));
		} else {
			/* Output a header for dead threads: */
			strcpy(s, "\n\nDEAD THREADS\n\n");
			__sys_write(fd, s, strlen(s));

			/*
			 * Enter a loop to report each thread in the global
			 * dead thread list:
			 */
			TAILQ_FOREACH(pthread, &_dead_list, dle) {
				dump_thread(fd, pthread, /*long_version*/ 0);
			}
		}

		/* Close the dump file: */
		__sys_close(fd);
	}
}

static void
dump_thread(int fd, pthread_t pthread, int long_version)
{
	struct pthread	*curthread = _get_curthread();
	char		s[512];
	int		i;

	/* Find the state: */
	for (i = 0; i < NELEMENTS(thread_info) - 1; i++)
		if (thread_info[i].state == pthread->state)
			break;

	/* Output a record for the thread: */
	snprintf(s, sizeof(s),
	    "--------------------\nThread %p (%s) prio %3d state %s [%s:%d]\n",
	    pthread, (pthread->name == NULL) ? "" : pthread->name,
	    pthread->active_priority, thread_info[i].name, pthread->fname,
	    pthread->lineno);
	__sys_write(fd, s, strlen(s));

	if (long_version != 0) {
		/* Check if this is the running thread: */
		if (pthread == curthread) {
			/* Output a record for the running thread: */
			strcpy(s, "This is the running thread\n");
			__sys_write(fd, s, strlen(s));
		}
		/* Check if this is the initial thread: */
		if (pthread == _thread_initial) {
			/* Output a record for the initial thread: */
			strcpy(s, "This is the initial thread\n");
			__sys_write(fd, s, strlen(s));
		}
		/* Process according to thread state: */
		switch (pthread->state) {
		/*
		 * Trap other states that are not explicitly
		 * coded to dump information:
		 */
		default:
			/* Nothing to do here. */
			break;
		}
	}
}

/* Set the thread name for debug: */
void
_pthread_set_name_np(pthread_t thread, const char *name)
{
	/* Check if the caller has specified a valid thread: */
	if (thread != NULL && thread->magic == PTHREAD_MAGIC) {
		if (thread->name != NULL) {
			/* Free space for previous name. */
			free(thread->name);
		}
		thread->name = strdup(name);
	}
}
