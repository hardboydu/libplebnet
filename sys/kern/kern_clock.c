/*-
 * Copyright (c) 1997, 1998 Poul-Henning Kamp <phk@FreeBSD.org>
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_clock.c	8.5 (Berkeley) 1/21/94
 * $Id: kern_clock.c,v 1.80 1998/10/06 23:17:44 alex Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dkstat.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/timex.h>
#include <vm/vm.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/sysctl.h>

#include <machine/cpu.h>
#include <machine/limits.h>

#ifdef GPROF
#include <sys/gmon.h>
#endif

#if defined(SMP) && defined(BETTER_CLOCK)
#include <machine/smp.h>
#endif

/*
 * Number of timecounters used to implement stable storage
 */
#ifndef NTIMECOUNTER
#define NTIMECOUNTER	2
#endif

static MALLOC_DEFINE(M_TIMECOUNTER, "timecounter", 
	"Timecounter stable storage");

static void initclocks __P((void *dummy));
SYSINIT(clocks, SI_SUB_CLOCKS, SI_ORDER_FIRST, initclocks, NULL)

static void tco_forward __P((void));
static void tco_setscales __P((struct timecounter *tc));
static __inline unsigned tco_delta __P((struct timecounter *tc));

/* Some of these don't belong here, but it's easiest to concentrate them. */
#if defined(SMP) && defined(BETTER_CLOCK)
long cp_time[CPUSTATES];
#else
static long cp_time[CPUSTATES];
#endif

long tk_cancc;
long tk_nin;
long tk_nout;
long tk_rawcc;

time_t time_second;

/*
 * Implement a dummy timecounter which we can use until we get a real one
 * in the air.  This allows the console and other early stuff to use
 * timeservices.
 */

static unsigned 
dummy_get_timecount(struct timecounter *tc)
{
	static unsigned now;
	return (++now);
}

static struct timecounter dummy_timecounter = {
	dummy_get_timecount,
	0,
	~0u,
	1000000,
	"dummy"
};

struct timecounter *timecounter = &dummy_timecounter;

/*
 * Clock handling routines.
 *
 * This code is written to operate with two timers that run independently of
 * each other.
 *
 * The main timer, running hz times per second, is used to trigger interval
 * timers, timeouts and rescheduling as needed.
 *
 * The second timer handles kernel and user profiling,
 * and does resource use estimation.  If the second timer is programmable,
 * it is randomized to avoid aliasing between the two clocks.  For example,
 * the randomization prevents an adversary from always giving up the cpu
 * just before its quantum expires.  Otherwise, it would never accumulate
 * cpu ticks.  The mean frequency of the second timer is stathz.
 *
 * If no second timer exists, stathz will be zero; in this case we drive
 * profiling and statistics off the main clock.  This WILL NOT be accurate;
 * do not do it unless absolutely necessary.
 *
 * The statistics clock may (or may not) be run at a higher rate while
 * profiling.  This profile clock runs at profhz.  We require that profhz
 * be an integral multiple of stathz.
 *
 * If the statistics clock is running fast, it must be divided by the ratio
 * profhz/stathz for statistics.  (For profiling, every tick counts.)
 *
 * Time-of-day is maintained using a "timecounter", which may or may
 * not be related to the hardware generating the above mentioned
 * interrupts.
 */

int	stathz;
int	profhz;
static int profprocs;
int	ticks;
static int psdiv, pscnt;		/* prof => stat divider */
int	psratio;			/* ratio: prof / stat */

/*
 * Initialize clock frequencies and start both clocks running.
 */
/* ARGSUSED*/
static void
initclocks(dummy)
	void *dummy;
{
	register int i;

	/*
	 * Set divisors to 1 (normal case) and let the machine-specific
	 * code do its bit.
	 */
	psdiv = pscnt = 1;
	cpu_initclocks();

	/*
	 * Compute profhz/stathz, and fix profhz if needed.
	 */
	i = stathz ? stathz : hz;
	if (profhz == 0)
		profhz = i;
	psratio = profhz / i;
}

/*
 * The real-time timer, interrupting hz times per second.
 */
void
hardclock(frame)
	register struct clockframe *frame;
{
	register struct proc *p;

	p = curproc;
	if (p) {
		register struct pstats *pstats;

		/*
		 * Run current process's virtual and profile time, as needed.
		 */
		pstats = p->p_stats;
		if (CLKF_USERMODE(frame) &&
		    timevalisset(&pstats->p_timer[ITIMER_VIRTUAL].it_value) &&
		    itimerdecr(&pstats->p_timer[ITIMER_VIRTUAL], tick) == 0)
			psignal(p, SIGVTALRM);
		if (timevalisset(&pstats->p_timer[ITIMER_PROF].it_value) &&
		    itimerdecr(&pstats->p_timer[ITIMER_PROF], tick) == 0)
			psignal(p, SIGPROF);
	}

#if defined(SMP) && defined(BETTER_CLOCK)
	forward_hardclock(pscnt);
#endif

	/*
	 * If no separate statistics clock is available, run it from here.
	 */
	if (stathz == 0)
		statclock(frame);

	tco_forward();
	ticks++;

	/*
	 * Process callouts at a very low cpu priority, so we don't keep the
	 * relatively high clock interrupt priority any longer than necessary.
	 */
	if (TAILQ_FIRST(&callwheel[ticks & callwheelmask]) != NULL) {
		if (CLKF_BASEPRI(frame)) {
			/*
			 * Save the overhead of a software interrupt;
			 * it will happen as soon as we return, so do it now.
			 */
			(void)splsoftclock();
			softclock();
		} else
			setsoftclock();
	} else if (softticks + 1 == ticks)
		++softticks;
}

/*
 * Compute number of ticks in the specified amount of time.
 */
int
tvtohz(tv)
	struct timeval *tv;
{
	register unsigned long ticks;
	register long sec, usec;

	/*
	 * If the number of usecs in the whole seconds part of the time
	 * difference fits in a long, then the total number of usecs will
	 * fit in an unsigned long.  Compute the total and convert it to
	 * ticks, rounding up and adding 1 to allow for the current tick
	 * to expire.  Rounding also depends on unsigned long arithmetic
	 * to avoid overflow.
	 *
	 * Otherwise, if the number of ticks in the whole seconds part of
	 * the time difference fits in a long, then convert the parts to
	 * ticks separately and add, using similar rounding methods and
	 * overflow avoidance.  This method would work in the previous
	 * case but it is slightly slower and assumes that hz is integral.
	 *
	 * Otherwise, round the time difference down to the maximum
	 * representable value.
	 *
	 * If ints have 32 bits, then the maximum value for any timeout in
	 * 10ms ticks is 248 days.
	 */
	sec = tv->tv_sec;
	usec = tv->tv_usec;
	if (usec < 0) {
		sec--;
		usec += 1000000;
	}
	if (sec < 0) {
#ifdef DIAGNOSTIC
		if (usec > 0) {
			sec++;
			usec -= 1000000;
		}
		printf("tvotohz: negative time difference %ld sec %ld usec\n",
		       sec, usec);
#endif
		ticks = 1;
	} else if (sec <= LONG_MAX / 1000000)
		ticks = (sec * 1000000 + (unsigned long)usec + (tick - 1))
			/ tick + 1;
	else if (sec <= LONG_MAX / hz)
		ticks = sec * hz
			+ ((unsigned long)usec + (tick - 1)) / tick + 1;
	else
		ticks = LONG_MAX;
	if (ticks > INT_MAX)
		ticks = INT_MAX;
	return ((int)ticks);
}

/*
 * Start profiling on a process.
 *
 * Kernel profiling passes proc0 which never exits and hence
 * keeps the profile clock running constantly.
 */
void
startprofclock(p)
	register struct proc *p;
{
	int s;

	if ((p->p_flag & P_PROFIL) == 0) {
		p->p_flag |= P_PROFIL;
		if (++profprocs == 1 && stathz != 0) {
			s = splstatclock();
			psdiv = pscnt = psratio;
			setstatclockrate(profhz);
			splx(s);
		}
	}
}

/*
 * Stop profiling on a process.
 */
void
stopprofclock(p)
	register struct proc *p;
{
	int s;

	if (p->p_flag & P_PROFIL) {
		p->p_flag &= ~P_PROFIL;
		if (--profprocs == 0 && stathz != 0) {
			s = splstatclock();
			psdiv = pscnt = 1;
			setstatclockrate(stathz);
			splx(s);
		}
	}
}

/*
 * Statistics clock.  Grab profile sample, and if divider reaches 0,
 * do process and kernel statistics.
 */
void
statclock(frame)
	register struct clockframe *frame;
{
#ifdef GPROF
	register struct gmonparam *g;
#endif
	register struct proc *p;
	register int i;
	struct pstats *pstats;
	long rss;
	struct rusage *ru;
	struct vmspace *vm;

	if (CLKF_USERMODE(frame)) {
		p = curproc;
		if (p->p_flag & P_PROFIL)
			addupc_intr(p, CLKF_PC(frame), 1);
#if defined(SMP) && defined(BETTER_CLOCK)
		if (stathz != 0)
			forward_statclock(pscnt);
#endif
		if (--pscnt > 0)
			return;
		/*
		 * Came from user mode; CPU was in user state.
		 * If this process is being profiled record the tick.
		 */
		p->p_uticks++;
		if (p->p_nice > NZERO)
			cp_time[CP_NICE]++;
		else
			cp_time[CP_USER]++;
	} else {
#ifdef GPROF
		/*
		 * Kernel statistics are just like addupc_intr, only easier.
		 */
		g = &_gmonparam;
		if (g->state == GMON_PROF_ON) {
			i = CLKF_PC(frame) - g->lowpc;
			if (i < g->textsize) {
				i /= HISTFRACTION * sizeof(*g->kcount);
				g->kcount[i]++;
			}
		}
#endif
#if defined(SMP) && defined(BETTER_CLOCK)
		if (stathz != 0)
			forward_statclock(pscnt);
#endif
		if (--pscnt > 0)
			return;
		/*
		 * Came from kernel mode, so we were:
		 * - handling an interrupt,
		 * - doing syscall or trap work on behalf of the current
		 *   user process, or
		 * - spinning in the idle loop.
		 * Whichever it is, charge the time as appropriate.
		 * Note that we charge interrupts to the current process,
		 * regardless of whether they are ``for'' that process,
		 * so that we know how much of its real time was spent
		 * in ``non-process'' (i.e., interrupt) work.
		 */
		p = curproc;
		if (CLKF_INTR(frame)) {
			if (p != NULL)
				p->p_iticks++;
			cp_time[CP_INTR]++;
		} else if (p != NULL) {
			p->p_sticks++;
			cp_time[CP_SYS]++;
		} else
			cp_time[CP_IDLE]++;
	}
	pscnt = psdiv;

	/*
	 * We maintain statistics shown by user-level statistics
	 * programs:  the amount of time in each cpu state.
	 */

	/*
	 * We adjust the priority of the current process.  The priority of
	 * a process gets worse as it accumulates CPU time.  The cpu usage
	 * estimator (p_estcpu) is increased here.  The formula for computing
	 * priorities (in kern_synch.c) will compute a different value each
	 * time p_estcpu increases by 4.  The cpu usage estimator ramps up
	 * quite quickly when the process is running (linearly), and decays
	 * away exponentially, at a rate which is proportionally slower when
	 * the system is busy.  The basic principal is that the system will
	 * 90% forget that the process used a lot of CPU time in 5 * loadav
	 * seconds.  This causes the system to favor processes which haven't
	 * run much recently, and to round-robin among other processes.
	 */
	if (p != NULL) {
		p->p_cpticks++;
		if (++p->p_estcpu == 0)
			p->p_estcpu--;
		if ((p->p_estcpu & 3) == 0) {
			resetpriority(p);
			if (p->p_priority >= PUSER)
				p->p_priority = p->p_usrpri;
		}

		/* Update resource usage integrals and maximums. */
		if ((pstats = p->p_stats) != NULL &&
		    (ru = &pstats->p_ru) != NULL &&
		    (vm = p->p_vmspace) != NULL) {
			ru->ru_ixrss += vm->vm_tsize * PAGE_SIZE / 1024;
			ru->ru_idrss += vm->vm_dsize * PAGE_SIZE / 1024;
			ru->ru_isrss += vm->vm_ssize * PAGE_SIZE / 1024;
			rss = vm->vm_pmap.pm_stats.resident_count *
			      PAGE_SIZE / 1024;
			if (ru->ru_maxrss < rss)
				ru->ru_maxrss = rss;
        	}
	}
}

/*
 * Return information about system clocks.
 */
static int
sysctl_kern_clockrate SYSCTL_HANDLER_ARGS
{
	struct clockinfo clkinfo;
	/*
	 * Construct clockinfo structure.
	 */
	clkinfo.hz = hz;
	clkinfo.tick = tick;
	clkinfo.tickadj = tickadj;
	clkinfo.profhz = profhz;
	clkinfo.stathz = stathz ? stathz : hz;
	return (sysctl_handle_opaque(oidp, &clkinfo, sizeof clkinfo, req));
}

SYSCTL_PROC(_kern, KERN_CLOCKRATE, clockrate, CTLTYPE_STRUCT|CTLFLAG_RD,
	0, 0, sysctl_kern_clockrate, "S,clockinfo","");

static __inline unsigned
tco_delta(struct timecounter *tc)
{

	return ((tc->tc_get_timecount(tc) - tc->tc_offset_count) & 
	    tc->tc_counter_mask);
}

/*
 * We have four functions for looking at the clock, two for microseconds
 * and two for nanoseconds.  For each there is fast but less precise
 * version "get{nano|micro}time" which will return a time which is up
 * to 1/HZ previous to the call, whereas the raw version "{nano|micro}time"
 * will return a timestamp which is as precise as possible.
 */

void
getmicrotime(struct timeval *tvp)
{
	struct timecounter *tc;

	tc = timecounter;
	*tvp = tc->tc_microtime;
}

void
getnanotime(struct timespec *tsp)
{
	struct timecounter *tc;

	tc = timecounter;
	*tsp = tc->tc_nanotime;
}

void
microtime(struct timeval *tv)
{
	struct timecounter *tc;

	tc = (struct timecounter *)timecounter;
	tv->tv_sec = tc->tc_offset_sec;
	tv->tv_usec = tc->tc_offset_micro;
	tv->tv_usec += ((u_int64_t)tco_delta(tc) * tc->tc_scale_micro) >> 32;
	tv->tv_usec += boottime.tv_usec;
	tv->tv_sec += boottime.tv_sec;
	while (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
}

void
nanotime(struct timespec *ts)
{
	unsigned count;
	u_int64_t delta;
	struct timecounter *tc;

	tc = (struct timecounter *)timecounter;
	ts->tv_sec = tc->tc_offset_sec;
	count = tco_delta(tc);
	delta = tc->tc_offset_nano;
	delta += ((u_int64_t)count * tc->tc_scale_nano_f);
	delta >>= 32;
	delta += ((u_int64_t)count * tc->tc_scale_nano_i);
	delta += boottime.tv_usec * 1000;
	ts->tv_sec += boottime.tv_sec;
	while (delta >= 1000000000) {
		delta -= 1000000000;
		ts->tv_sec++;
	}
	ts->tv_nsec = delta;
}

void
timecounter_timespec(unsigned count, struct timespec *ts)
{
	u_int64_t delta;
	struct timecounter *tc;

	tc = (struct timecounter *)timecounter;
	ts->tv_sec = tc->tc_offset_sec;
	count -= tc->tc_offset_count;
	count &= tc->tc_counter_mask;
	delta = tc->tc_offset_nano;
	delta += ((u_int64_t)count * tc->tc_scale_nano_f);
	delta >>= 32;
	delta += ((u_int64_t)count * tc->tc_scale_nano_i);
	delta += boottime.tv_usec * 1000;
	ts->tv_sec += boottime.tv_sec;
	while (delta >= 1000000000) {
		delta -= 1000000000;
		ts->tv_sec++;
	}
	ts->tv_nsec = delta;
}

void
getmicrouptime(struct timeval *tvp)
{
	struct timecounter *tc;

	tc = timecounter;
	tvp->tv_sec = tc->tc_offset_sec;
	tvp->tv_usec = tc->tc_offset_micro;
}

void
getnanouptime(struct timespec *tsp)
{
	struct timecounter *tc;

	tc = timecounter;
	tsp->tv_sec = tc->tc_offset_sec;
	tsp->tv_nsec = tc->tc_offset_nano >> 32;
}

void
microuptime(struct timeval *tv)
{
	struct timecounter *tc;

	tc = (struct timecounter *)timecounter;
	tv->tv_sec = tc->tc_offset_sec;
	tv->tv_usec = tc->tc_offset_micro;
	tv->tv_usec += ((u_int64_t)tco_delta(tc) * tc->tc_scale_micro) >> 32;
	if (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
}

void
nanouptime(struct timespec *tv)
{
	unsigned count;
	u_int64_t delta;
	struct timecounter *tc;

	tc = (struct timecounter *)timecounter;
	tv->tv_sec = tc->tc_offset_sec;
	count = tco_delta(tc);
	delta = tc->tc_offset_nano;
	delta += ((u_int64_t)count * tc->tc_scale_nano_f);
	delta >>= 32;
	delta += ((u_int64_t)count * tc->tc_scale_nano_i);
	if (delta >= 1000000000) {
		delta -= 1000000000;
		tv->tv_sec++;
	}
	tv->tv_nsec = delta;
}

static void
tco_setscales(struct timecounter *tc)
{
	u_int64_t scale;

	scale = 1000000000LL << 32;
	if (tc->tc_adjustment > 0)
		scale += (tc->tc_adjustment * 1000LL) << 10;
	else
		scale -= (-tc->tc_adjustment * 1000LL) << 10;
	scale /= tc->tc_frequency;
	tc->tc_scale_micro = scale / 1000;
	tc->tc_scale_nano_f = scale & 0xffffffff;
	tc->tc_scale_nano_i = scale >> 32;
}

void
init_timecounter(struct timecounter *tc)
{
	struct timespec ts0, ts1;
	struct timecounter *t1, *t2, *t3;
	int i;

	tc->tc_adjustment = 0;
	tco_setscales(tc);
	tc->tc_offset_count = tc->tc_get_timecount(tc);
	tc->tc_tweak = tc;
	MALLOC(t1, struct timecounter *, sizeof *t1, M_TIMECOUNTER, M_WAITOK);
	*t1 = *tc;
	t2 = t1;
	for (i = 1; i < NTIMECOUNTER; i++) {
		MALLOC(t3, struct timecounter *, sizeof *t3,
		    M_TIMECOUNTER, M_WAITOK);
		*t3 = *tc;
		t3->tc_other = t2;
		t2 = t3;
	}
	t1->tc_other = t3;
	tc = t1;

	printf("Timecounter \"%s\"  frequency %lu Hz\n", 
	    tc->tc_name, (u_long)tc->tc_frequency);

	/* XXX: For now always start using the counter. */
	tc->tc_offset_count = tc->tc_get_timecount(tc);
	nanouptime(&ts1);
	tc->tc_offset_nano = (u_int64_t)ts1.tv_nsec << 32;
	tc->tc_offset_micro = ts1.tv_nsec / 1000;
	tc->tc_offset_sec = ts1.tv_sec;
	timecounter = tc;
}

void
set_timecounter(struct timespec *ts)
{
	struct timespec ts2;

	nanouptime(&ts2);
	boottime.tv_sec = ts->tv_sec - ts2.tv_sec;
	boottime.tv_usec = (ts->tv_nsec - ts2.tv_nsec) / 1000;
	if (boottime.tv_usec < 0) {
		boottime.tv_usec += 1000000;
		boottime.tv_sec--;
	}
	/* fiddle all the little crinkly bits around the fiords... */
	tco_forward();
}


#if 0 /* Currently unused */
void
switch_timecounter(struct timecounter *newtc)
{
	int s;
	struct timecounter *tc;
	struct timespec ts;

	s = splclock();
	tc = timecounter;
	if (newtc == tc || newtc == tc->tc_other) {
		splx(s);
		return;
	}
	nanouptime(&ts);
	newtc->tc_offset_sec = ts.tv_sec;
	newtc->tc_offset_nano = (u_int64_t)ts.tv_nsec << 32;
	newtc->tc_offset_micro = ts.tv_nsec / 1000;
	newtc->tc_offset_count = newtc->tc_get_timecount(newtc);
	timecounter = newtc;
	splx(s);
}
#endif

static struct timecounter *
sync_other_counter(void)
{
	struct timecounter *tc, *tcn, *tco;
	unsigned delta;

	tco = timecounter;
	tc = tco->tc_other;
	tcn = tc->tc_other;
	*tc = *tco;
	tc->tc_other = tcn;
	delta = tco_delta(tc);
	tc->tc_offset_count += delta;
	tc->tc_offset_count &= tc->tc_counter_mask;
	tc->tc_offset_nano += (u_int64_t)delta * tc->tc_scale_nano_f;
	tc->tc_offset_nano += (u_int64_t)delta * tc->tc_scale_nano_i << 32;
	return (tc);
}

static void
tco_forward(void)
{
	struct timecounter *tc, *tco;

	tco = timecounter;
	tc = sync_other_counter();
	/*
	 * We may be inducing a tiny error here, the tc_poll_pps() may
	 * process a latched count which happens after the tco_delta()
	 * in sync_other_counter(), which would extend the previous
	 * counters parameters into the domain of this new one.
	 * Since the timewindow is very small for this, the error is
	 * going to be only a few weenieseconds (as Dave Mills would
	 * say), so lets just not talk more about it, OK ?
	 */
	if (tco->tc_poll_pps) 
		tco->tc_poll_pps(tco);
	if (timedelta != 0) {
		tc->tc_offset_nano += (u_int64_t)(tickdelta * 1000) << 32;
		timedelta -= tickdelta;
	}

	while (tc->tc_offset_nano >= 1000000000ULL << 32) {
		tc->tc_offset_nano -= 1000000000ULL << 32;
		tc->tc_offset_sec++;
		tc->tc_frequency = tc->tc_tweak->tc_frequency;
		tc->tc_adjustment = tc->tc_tweak->tc_adjustment;
		ntp_update_second(tc);	/* XXX only needed if xntpd runs */
		tco_setscales(tc);
	}

	tc->tc_offset_micro = (tc->tc_offset_nano / 1000) >> 32;

	/* Figure out the wall-clock time */
	tc->tc_nanotime.tv_sec = tc->tc_offset_sec + boottime.tv_sec;
	tc->tc_nanotime.tv_nsec = 
	    (tc->tc_offset_nano >> 32) + boottime.tv_usec * 1000;
	tc->tc_microtime.tv_usec = tc->tc_offset_micro + boottime.tv_usec;
	if (tc->tc_nanotime.tv_nsec >= 1000000000) {
		tc->tc_nanotime.tv_nsec -= 1000000000;
		tc->tc_microtime.tv_usec -= 1000000;
		tc->tc_nanotime.tv_sec++;
	}
	time_second = tc->tc_microtime.tv_sec = tc->tc_nanotime.tv_sec;

	timecounter = tc;
}

static int
sysctl_kern_timecounter_frequency SYSCTL_HANDLER_ARGS
{

	return (sysctl_handle_opaque(oidp, 
	    &timecounter->tc_tweak->tc_frequency,
	    sizeof(timecounter->tc_tweak->tc_frequency), req));
}

static int
sysctl_kern_timecounter_adjustment SYSCTL_HANDLER_ARGS
{

	return (sysctl_handle_opaque(oidp, 
	    &timecounter->tc_tweak->tc_adjustment,
	    sizeof(timecounter->tc_tweak->tc_adjustment), req));
}

SYSCTL_NODE(_kern, OID_AUTO, timecounter, CTLFLAG_RW, 0, "");

SYSCTL_PROC(_kern_timecounter, OID_AUTO, frequency, CTLTYPE_INT | CTLFLAG_RW,
    0, sizeof(u_int), sysctl_kern_timecounter_frequency, "I", "");

SYSCTL_PROC(_kern_timecounter, OID_AUTO, adjustment, CTLTYPE_INT | CTLFLAG_RW,
    0, sizeof(int), sysctl_kern_timecounter_adjustment, "I", "");
