/*
 * Copyright (C) 2001 Julian Elischer <julian@freebsd.org>
 * for the FreeBSD Foundation.
 *
 *  All rights reserved.
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

#ifndef SYS_KSE_H
#define SYS_KSE_H

#include <machine/kse.h>
#include <sys/ucontext.h>

/*
 * This file defines the structures needed for communication between
 * the userland and the kernel when running a KSE-based threading system.
 * The only programs that should see this file are the UTS and the kernel.
 */
struct kse_mailbox;
typedef void kse_fn_t(struct kse_mailbox *mbx);

/*
 * Thread mailbox.
 *
 * This describes a user thread to the kernel scheduler.
 */
struct thread_mailbox {
	ucontext_t		tm_context;	/* User and machine context */
	unsigned int		tm_flags;	/* Thread flags */
	struct thread_mailbox	*tm_next;	/* Next thread in list */
	void			*tm_udata;	/* For use by the UTS */
	int			tm_spare[8];
};

/*
 * KSE mailbox.
 *
 * Cummunication path between the UTS and the kernel scheduler specific to
 * a single KSE.
 */
struct kse_mailbox {
	struct thread_mailbox	*km_curthread;	/* Currently running thread */
	struct thread_mailbox	*km_completed;	/* Threads back from kernel */
	sigset_t		km_sigscaught;	/* Caught signals */
	unsigned int		km_flags;	/* KSE flags */
	void			*km_func;	/* UTS function */
	stack_t			km_stack;	/* UTS context */
	void			*km_udata;	/* For use by the UTS */
	int			tm_spare[8];
};

#ifndef _KERNEL
int	kse_exit(void);
int	kse_wakeup(void);
int	kse_new(struct kse_mailbox *, int);
int	kse_yield(void);
#endif

#endif
