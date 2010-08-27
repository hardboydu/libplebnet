/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
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

#ifndef	_SYNCH_H_
#define	_SYNCH_H_

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <time.h>

static __inline void
mtx_init(pthread_mutex_t *lock)
{
	int error;

	error = pthread_mutex_init(lock, NULL);
	assert(error == 0);
}
static __inline void
mtx_lock(pthread_mutex_t *lock)
{
	int error;

	error = pthread_mutex_lock(lock);
	assert(error == 0);
}
static __inline bool
mtx_trylock(pthread_mutex_t *lock)
{
	int error;

	error = pthread_mutex_trylock(lock);
	assert(error == 0 || error == EBUSY);
	return (error == 0);
}
static __inline void
mtx_unlock(pthread_mutex_t *lock)
{
	int error;

	error = pthread_mutex_unlock(lock);
	assert(error == 0);
}
static __inline bool
mtx_owned(pthread_mutex_t *lock)
{

	return (pthread_mutex_isowned_np(lock) != 0);
}

static __inline void
rw_init(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_init(lock, NULL);
	assert(error == 0);
}
static __inline void
rw_rlock(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_rdlock(lock);
	assert(error == 0);
}
static __inline void
rw_wlock(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_wrlock(lock);
	assert(error == 0);
}
static __inline void
rw_unlock(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_unlock(lock);
	assert(error == 0);
}

static __inline void
cv_init(pthread_cond_t *cv)
{
	pthread_condattr_t attr;
	int error;

	error = pthread_condattr_init(&attr);
	assert(error == 0);
	error = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	assert(error == 0);
	error = pthread_cond_init(cv, &attr);
	assert(error == 0);
}
static __inline void
cv_wait(pthread_cond_t *cv, pthread_mutex_t *lock)
{
	int error;

	error = pthread_cond_wait(cv, lock);
	assert(error == 0);
}
static __inline bool
cv_timedwait(pthread_cond_t *cv, pthread_mutex_t *lock, int timeout)
{
	struct timespec ts;
	int error;

	if (timeout == 0) {
		cv_wait(cv, lock);
		return (false);
	}

        error = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(error == 0);
	ts.tv_sec += timeout;
	error = pthread_cond_timedwait(cv, lock, &ts);
	assert(error == 0 || error == ETIMEDOUT);
	return (error == ETIMEDOUT);
}
static __inline void
cv_signal(pthread_cond_t *cv)
{
	int error;

	error = pthread_cond_signal(cv);
	assert(error == 0);
}
static __inline void
cv_broadcast(pthread_cond_t *cv)
{
	int error;

	error = pthread_cond_broadcast(cv);
	assert(error == 0);
}
#endif	/* !_SYNCH_H_ */
