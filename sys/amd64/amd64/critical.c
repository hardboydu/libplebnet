/*-
 * Copyright (c) 2001 Matthew Dillon.  This code is distributed under
 * the BSD copyright, /usr/src/COPYRIGHT.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/ucontext.h>
#include <machine/clock.h>
#include <machine/critical.h>

/*
 * cpu_critical_fork_exit() - cleanup after fork
 */
void
cpu_critical_fork_exit(void)
{
	struct thread *td;

	td = curthread;
	td->td_md.md_savecrit = read_rflags() | PSL_I;
}
