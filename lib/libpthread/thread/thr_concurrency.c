/*
 * Copyright (c) 2003 Daniel M. Eischen <deischen@freebsd.org>
 * Copyright (c) 2003 Sergey Osokin <osa@freebsd.org.ru>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
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

/*#define DEBUG_CONCURRENCY */
#ifdef DEBUG_CONCURRENCY
#define DBG_MSG		stdout_debug
#else
#define	DBG_MSG(x...)
#endif

static int level = 0;

__weak_reference(_pthread_getconcurrency, pthread_getconcurrency);
__weak_reference(_pthread_setconcurrency, pthread_setconcurrency);

int
_pthread_getconcurrency(void)
{
	return (level);
}

int
_pthread_setconcurrency(int new_level)
{
	struct pthread *curthread;
	struct kse *newkse;
	kse_critical_t crit;
	int kse_count;
	int i;
	int ret;


	if (new_level < 0)
		ret = EINVAL;
	else if (new_level == level)
		ret = 0;
	else if (new_level == 0) {
		level = 0;
		ret = 0;
	} else if ((_kse_isthreaded() == 0) && (_kse_setthreaded(1) != 0)) {
		DBG_MSG("Can't enable threading.\n");
		ret = EAGAIN;
	} else {
		ret = 0;
		curthread = _get_curthread();
		/* Race condition, but so what. */
		kse_count = _kse_initial->k_kseg->kg_ksecount;
		for (i = kse_count; i < new_level; i++) {
			newkse = _kse_alloc(curthread);
			if (newkse == NULL) {
				DBG_MSG("Can't alloc new KSE.\n");
				ret = EAGAIN;
				break;
			}
			newkse->k_kseg = _kse_initial->k_kseg;
			newkse->k_schedq = _kse_initial->k_schedq;
			newkse->k_curthread = NULL;
			crit = _kse_critical_enter();
			KSE_SCHED_LOCK(curthread->kse, newkse->k_kseg);
			TAILQ_INSERT_TAIL(&newkse->k_kseg->kg_kseq,
			    newkse, k_kgqe);
			newkse->k_kseg->kg_ksecount++;
			KSE_SCHED_UNLOCK(curthread->kse, newkse->k_kseg);
			if (_ksd_setprivate(&_kse_initial->k_ksd) != 0) {
				/* This should never happen. */
				PANIC("pthread_setconcurrency: Unable to "
				    "set KSE specific data");
			}
			newkse->k_flags |= KF_INITIALIZED;
			if (kse_create(&newkse->k_mbx, 0) != 0) {
				_ksd_setprivate(&curthread->kse->k_ksd);
				KSE_SCHED_LOCK(curthread->kse, newkse->k_kseg);
				TAILQ_REMOVE(&newkse->k_kseg->kg_kseq,
				    newkse, k_kgqe);
				newkse->k_kseg->kg_ksecount--;
				KSE_SCHED_UNLOCK(curthread->kse, newkse->k_kseg);
				_kse_critical_leave(crit);
				_kse_free(curthread, newkse);
				DBG_MSG("kse_create syscall failed.\n");
				ret = EAGAIN;
				break;
			}
			_ksd_setprivate(&curthread->kse->k_ksd);
			_kse_critical_leave(crit);
		}
		if (ret == 0)
			level = new_level;
	}
	return (ret);
}
