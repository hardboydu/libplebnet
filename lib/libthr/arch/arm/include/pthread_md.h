/*-
 * Copyright (c) 2005 David Xu <davidxu@freebsd.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
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
 */

/*
 * Machine-dependent thread prototypes/definitions.
 */
#ifndef _PTHREAD_MD_H_
#define	_PTHREAD_MD_H_

#include <sys/types.h>
#include <machine/sysarch.h>
#include <stddef.h>
#include <errno.h>

static __inline int atomic_cmpset_32(volatile uint32_t *, uint32_t, uint32_t);

#include <sys/umtx.h>

#define	DTV_OFFSET		offsetof(struct tcb, tcb_dtv)

/*
 * Variant II tcb, first two members are required by rtld.
 */
struct tcb {
	struct tcb              *tcb_self;	/* required by rtld */
	void                    *tcb_dtv;	/* required by rtld */
	struct pthread          *tcb_thread;	/* our hook */
	void			*tcb_spare[1];
};

/*
 * The tcb constructors.
 */
struct tcb	*_tcb_ctor(struct pthread *, int);
void		_tcb_dtor(struct tcb *);

/* Called from the thread to set its private data. */
static __inline void
_tcb_set(struct tcb *tcb)
{
	*((struct tcb **)ARM_TP_ADDRESS) = tcb;
}

/*
 * Get the current tcb.
 */
static __inline struct tcb *
_tcb_get(void)
{
	return (*((struct tcb **)ARM_TP_ADDRESS));
}

extern struct pthread *_thr_initial;

static __inline struct pthread *
_get_curthread(void)
{
	if (_thr_initial)
		return (_tcb_get()->tcb_thread);
	return (NULL);
}

extern struct umtx arm_umtx;

static __inline int
atomic_cmpset_32(volatile uint32_t *dst, uint32_t old, uint32_t newval)
{						
	int ret;				

	_umtx_lock(&arm_umtx);
	arm_umtx.u_owner = (void*)((uint32_t)arm_umtx.u_owner | UMTX_CONTESTED);
	if (*dst == old) {
		*dst = newval;
		ret = 1;
	} else
		ret = 0;
	_umtx_unlock(&arm_umtx);
	return (ret);
}

#endif /* _PTHREAD_MD_H_ */
