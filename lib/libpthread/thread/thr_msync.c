/*
 * David Leonard <d@openbsd.org>, 1999. Public Domain.
 *
 * $OpenBSD: uthread_msync.c,v 1.2 1999/06/09 07:16:17 d Exp $
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/mman.h>
#ifdef _THREAD_SAFE
#include <pthread.h>
#include "pthread_private.h"

int
_libc_msync(addr, len, flags)
	void *addr;
	size_t len;
	int flags;
{
	int ret;

	/*
	 * XXX This is quite pointless unless we know how to get the
	 * file descriptor associated with the memory, and lock it for
	 * write. The only real use of this wrapper is to guarantee
	 * a cancellation point, as per the standard. sigh.
	 */

	/* This is a cancellation point: */
	_thread_enter_cancellation_point();

	ret = _thread_sys_msync(addr, len, flags);

	/* No longer in a cancellation point: */
	_thread_leave_cancellation_point();

	return (ret);
}

__weak_reference(_libc_msync, msync);
#endif
