/*
 * Copyright (c) 1999 Peter Wemm <peter@FreeBSD.org>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/unistd.h>
#include <sys/wait.h>

#include <machine/stdarg.h>

/*
 * Start a kernel process.  This is called after a fork() call in
 * mi_startup() in the file kern/init_main.c.
 *
 * This function is used to start "internal" daemons and intended
 * to be called from SYSINIT().
 */
void
kproc_start(udata)
	const void *udata;
{
	const struct kproc_desc	*kp = udata;
	int error;

	error = kthread_create((void (*)(void *))kp->func, NULL,
		    kp->global_procpp, 0, kp->arg0);
	if (error)
		panic("kproc_start: %s: error %d", kp->arg0, error);
}

/*
 * Create a kernel process/thread/whatever.  It shares its address space
 * with proc0 - ie: kernel only.
 *
 * func is the function to start.
 * arg is the parameter to pass to function on first startup.
 * newpp is the return value pointing to the thread's struct proc.
 * flags are flags to fork1 (in unistd.h)
 * fmt and following will be *printf'd into (*newpp)->p_comm (for ps, etc.).
 */
int
kthread_create(void (*func)(void *), void *arg,
    struct proc **newpp, int flags, const char *fmt, ...)
{
	int error;
	va_list ap;
	struct proc *p2;

	if (!proc0.p_stats /* || proc0.p_stats->p_start.tv_sec == 0 */)
		panic("kthread_create called too soon");

	error = fork1(&proc0, RFMEM | RFFDG | RFPROC | RFSTOPPED | flags, &p2);
	if (error)
		return error;

	/* save a global descriptor, if desired */
	if (newpp != NULL)
		*newpp = p2;

	/* this is a non-swapped system process */
	PROC_LOCK(p2);
	p2->p_flag |= P_SYSTEM | P_KTHREAD;
	p2->p_procsig->ps_flag |= PS_NOCLDWAIT;
	PROC_UNLOCK(p2);
	PHOLD(p2);

	/* set up arg0 for 'ps', et al */
	va_start(ap, fmt);
	vsnprintf(p2->p_comm, sizeof(p2->p_comm), fmt, ap);
	va_end(ap);

	/* call the processes' main()... */
	cpu_set_fork_handler(p2, func, arg);

	/* Delay putting it on the run queue until now. */
	mtx_enter(&sched_lock, MTX_SPIN);
	p2->p_sflag |= PS_INMEM;
	if (!(flags & RFSTOPPED)) {
		p2->p_stat = SRUN;
		setrunqueue(p2);
	}
	mtx_exit(&sched_lock, MTX_SPIN);

	return 0;
}

void
kthread_exit(int ecode)
{

	PROCTREE_LOCK(PT_EXCLUSIVE);
	proc_reparent(curproc, initproc);
	PROCTREE_LOCK(PT_RELEASE);
	exit1(curproc, W_EXITCODE(ecode, 0));
}

/*
 * Advise a kernel process to suspend (or resume) in its main loop.
 * Participation is voluntary.
 */
int
kthread_suspend(struct proc *p, int timo)
{
	/*
	 * Make sure this is indeed a system process and we can safely
	 * use the p_siglist field.
	 */
	if ((p->p_flag & P_SYSTEM) == 0)
		return (EINVAL);
	SIGADDSET(p->p_siglist, SIGSTOP);
	return tsleep((caddr_t)&p->p_siglist, PPAUSE, "suspkt", timo);
}

int
kthread_resume(struct proc *p)
{
	/*
	 * Make sure this is indeed a system process and we can safely
	 * use the p_siglist field.
	 */
	if ((p->p_flag & P_SYSTEM) == 0)
		return (EINVAL);
	SIGDELSET(p->p_siglist, SIGSTOP);
	wakeup((caddr_t)&p->p_siglist);
	return (0);
}

void
kthread_suspend_check(struct proc *p)
{
	while (SIGISMEMBER(p->p_siglist, SIGSTOP)) {
		wakeup((caddr_t)&p->p_siglist);
		tsleep((caddr_t)&p->p_siglist, PPAUSE, "ktsusp", 0);
	}
}
