/*
 * Copyright (C) 2001 Jason Evans <jasone@freebsd.org>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible 
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Shared/exclusive locks.  This implementation assures deterministic lock
 * granting behavior, so that slocks and xlocks are interleaved.
 *
 * Priority propagation will not generally raise the priority of lock holders,
 * so should not be relied upon in combination with sx locks.
 *
 * The witness code can not detect lock cycles (yet).
 *
 * XXX: When witness is made to function with sx locks, it will need to
 * XXX: be taught to deal with these situations, as they are more involved:
 *   slock --> xlock (deadlock)
 *   slock --> slock (slock recursion, not fatal)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ktr.h>
#include <sys/condvar.h>
#include <sys/mutex.h>
#include <sys/sx.h>

void
sx_init(struct sx *sx, const char *description)
{

	mtx_init(&sx->sx_lock, description, MTX_DEF);
	sx->sx_cnt = 0;
	cv_init(&sx->sx_shrd_cv, description);
	sx->sx_shrd_wcnt = 0;
	cv_init(&sx->sx_excl_cv, description);
	sx->sx_descr = description;
	sx->sx_excl_wcnt = 0;
	sx->sx_xholder = NULL;
}

void
sx_destroy(struct sx *sx)
{

	KASSERT((sx->sx_cnt == 0 && sx->sx_shrd_wcnt == 0 && sx->sx_excl_wcnt ==
	    0), ("%s (%s): holders or waiters\n", __FUNCTION__, sx->sx_descr));

	mtx_destroy(&sx->sx_lock);
	cv_destroy(&sx->sx_shrd_cv);
	cv_destroy(&sx->sx_excl_cv);
}

void
sx_slock(struct sx *sx)
{

	mtx_lock(&sx->sx_lock);
	KASSERT(sx->sx_xholder != curproc,
	    ("%s (%s): trying to get slock while xlock is held\n", __FUNCTION__,
	    sx->sx_descr));

	/*
	 * Loop in case we lose the race for lock acquisition.
	 */
	while (sx->sx_cnt < 0) {
		sx->sx_shrd_wcnt++;
		cv_wait(&sx->sx_shrd_cv, &sx->sx_lock);
		sx->sx_shrd_wcnt--;
	}

	/* Acquire a shared lock. */
	sx->sx_cnt++;

	mtx_unlock(&sx->sx_lock);
}

void
sx_xlock(struct sx *sx)
{

	mtx_lock(&sx->sx_lock);

	/*
	 * With sx locks, we're absolutely not permitted to recurse on
	 * xlocks, as it is fatal (deadlock). Normally, recursion is handled
	 * by WITNESS, but as it is not semantically correct to hold the
	 * xlock while in here, we consider it API abuse and put it under
	 * INVARIANTS.
	 */
	KASSERT(sx->sx_xholder != curproc,
	    ("%s (%s): xlock already held", __FUNCTION__, sx->sx_descr));

	/* Loop in case we lose the race for lock acquisition. */
	while (sx->sx_cnt != 0) {
		sx->sx_excl_wcnt++;
		cv_wait(&sx->sx_excl_cv, &sx->sx_lock);
		sx->sx_excl_wcnt--;
	}

	MPASS(sx->sx_cnt == 0);

	/* Acquire an exclusive lock. */
	sx->sx_cnt--;
	sx->sx_xholder = curproc;

	mtx_unlock(&sx->sx_lock);
}

void
sx_sunlock(struct sx *sx)
{

	mtx_lock(&sx->sx_lock);
	SX_ASSERT_SLOCKED(sx);

	/* Release. */
	sx->sx_cnt--;

	/*
	 * If we just released the last shared lock, wake any waiters up, giving
	 * exclusive lockers precedence.  In order to make sure that exclusive
	 * lockers won't be blocked forever, don't wake shared lock waiters if
	 * there are exclusive lock waiters.
	 */
	if (sx->sx_excl_wcnt > 0) {
		if (sx->sx_cnt == 0)
			cv_signal(&sx->sx_excl_cv);
	} else if (sx->sx_shrd_wcnt > 0)
		cv_broadcast(&sx->sx_shrd_cv);

	mtx_unlock(&sx->sx_lock);
}

void
sx_xunlock(struct sx *sx)
{

	mtx_lock(&sx->sx_lock);
	SX_ASSERT_XLOCKED(sx);
	MPASS(sx->sx_cnt == -1);

	/* Release. */
	sx->sx_cnt++;
	sx->sx_xholder = NULL;

	/*
	 * Wake up waiters if there are any.  Give precedence to slock waiters.
	 */
	if (sx->sx_shrd_wcnt > 0)
		cv_broadcast(&sx->sx_shrd_cv);
	else if (sx->sx_excl_wcnt > 0)
		cv_signal(&sx->sx_excl_cv);

	mtx_unlock(&sx->sx_lock);
}
