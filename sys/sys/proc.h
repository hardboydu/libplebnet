/*-
 * Copyright (c) 1986, 1989, 1991, 1993
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
 *	@(#)proc.h	8.15 (Berkeley) 5/19/95
 * $FreeBSD$
 */

#ifndef _SYS_PROC_H_
#define	_SYS_PROC_H_

#include <machine/proc.h>		/* Machine-dependent proc substruct. */
#include <sys/callout.h>		/* For struct callout. */
#include <sys/event.h>			/* For struct klist. */
#include <sys/filedesc.h>
#include <sys/queue.h>
#include <sys/rtprio.h>			/* For struct rtprio. */
#include <sys/signal.h>
#ifndef _KERNEL
#include <sys/time.h>			/* For structs itimerval, timeval. */
#endif
#include <sys/ucred.h>

/*
 * One structure allocated per session.
 */
struct	session {
	int	s_count;		/* Ref cnt; pgrps in session. */
	struct	proc *s_leader;		/* Session leader. */
	struct	vnode *s_ttyvp;		/* Vnode of controlling terminal. */
	struct	tty *s_ttyp;		/* Controlling terminal. */
	pid_t	s_sid;			/* Session ID. */
					/* Setlogin() name: */
	char	s_login[roundup(MAXLOGNAME, sizeof(long))];
};

/*
 * One structure allocated per process group.
 */
struct	pgrp {
	LIST_ENTRY(pgrp) pg_hash;	/* Hash chain. */
	LIST_HEAD(, proc) pg_members;	/* Pointer to pgrp members. */
	struct	session *pg_session;	/* Pointer to session. */
	struct  sigiolst pg_sigiolst;	/* List of sigio sources. */
	pid_t	pg_id;			/* Pgrp id. */
	int	pg_jobc;	/* # procs qualifying pgrp for job control */
};

struct	procsig {
	sigset_t ps_sigignore;	/* Signals being ignored. */
	sigset_t ps_sigcatch;	/* Signals being caught by user. */
	int	 ps_flag;
	struct	 sigacts *ps_sigacts;	/* Signal actions, state. */
	int	 ps_refcnt;
};

#define	PS_NOCLDWAIT	0x0001	/* No zombies if child dies */
#define	PS_NOCLDSTOP	0x0002	/* No SIGCHLD when children stop. */

/*
 * pasleep structure, used by asleep() syscall to hold requested priority
 * and timeout values for await().
 */
struct	pasleep {
	int	as_priority;	/* Async priority. */
	int	as_timo;	/* Async timeout. */
};

/*
 * pargs, used to hold a copy of the command line, if it had a sane length.
 */
struct	pargs {
	u_int	ar_ref;		/* Reference count. */
	u_int	ar_length;	/* Length. */
	u_char	ar_args[0];	/* Arguments. */
};

/*-
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressable except for those marked "(CPU)" below,
 * which might be addressable only on a processor on which the process
 * is running.
 *
 * Below is a key of locks used to protect each member of struct proc.  The
 * lock is indicated by a reference to a specific character in parens in the
 * associated comment.
 *      * - not yet protected
 *      a - only touched by curproc or parent during fork/wait
 *      b - created at fork, never chagnes 
 *      c - locked by proc mtx
 *      d - locked by allproc_lock lock
 *      e - locked by proc tree lock
 *      f - session mtx
 *      g - process group mtx
 *      h - callout_lock mtx
 *      i - by curproc or the master session mtx
 *      j - locked by sched_lock mtx
 *      k - either by curproc or a lock which prevents the lock from
 *          going away, such as (d,e)
 *      l - the attaching proc or attaching proc parent
 *      m - Giant
 *      n - not locked, lazy
 */
struct	proc {
	TAILQ_ENTRY(proc) p_procq;	/* (j) Run/mutex queue. */
	TAILQ_ENTRY(proc) p_slpq;	/* (j) Sleep queue. */
	LIST_ENTRY(proc) p_list;	/* (d) List of all processes. */

	/* substructures: */
	struct	pcred *p_cred;		/* (b) Process owner's identity. */
	struct	filedesc *p_fd;		/* (b) Ptr to open files structure. */
	struct	pstats *p_stats;	/* (b) Accounting/statistics (CPU). */
	struct	plimit *p_limit;	/* (m) Process limits. */
	struct	vm_object *p_upages_obj;/* (c) Upages object. */
	struct	procsig *p_procsig;	/* (c) Signal actions, state (CPU). */
#define	p_sigacts	p_procsig->ps_sigacts
#define	p_sigignore	p_procsig->ps_sigignore
#define	p_sigcatch	p_procsig->ps_sigcatch

#define	p_ucred		p_cred->pc_ucred
#define	p_rlimit	p_limit->pl_rlimit

	int	p_flag;			/* (c/j) P_* flags. */
	char	p_stat;			/* (j) S* process status. */
	char	p_pad1[3];

	pid_t	p_pid;			/* (b) Process identifier. */
	LIST_ENTRY(proc) p_hash;	/* (d) Hash chain. */
	LIST_ENTRY(proc) p_pglist;	/* (c) List of processes in pgrp. */
	struct	proc *p_pptr;		/* (e) Pointer to parent process. */
	LIST_ENTRY(proc) p_sibling;	/* (e) List of sibling processes. */
	LIST_HEAD(, proc) p_children;	/* (e) Pointer to list of children. */

/* The following fields are all zeroed upon creation in fork. */
#define	p_startzero	p_oppid

	pid_t	p_oppid;	 /* (c) Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* (c) Sideways ret value from fdopen. XXX */
	struct	vmspace *p_vmspace;	/* (b) Address space. */

	/* scheduling */
	u_int	p_estcpu;	 /* (j) Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* (j) Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* (j) %cpu during p_swtime. */
	struct	callout p_slpcallout;	/* (h) Callout for sleep. */
	void	*p_wchan;	 /* (j) Sleep address. */
	const char *p_wmesg;	 /* (j) Reason for sleep. */
	u_int	p_swtime;	 /* (j) Time swapped in or out. */
	u_int	p_slptime;	 /* (j) Time since last blocked. */

	struct	callout p_itcallout;	/* (h) Interval timer callout. */
	struct	itimerval p_realtimer;	/* (h?/k?) Alarm timer. */
	u_int64_t p_runtime;	/* (c) Real time in microsec. */
	u_int64_t p_uu;		/* (c) Previous user time in microsec. */
	u_int64_t p_su;		/* (c) Previous system time in microsec. */
	u_int64_t p_iu;		/* (c) Previous interrupt time in microsec. */
	u_int64_t p_uticks;	/* (j) Statclock hits in user mode. */
	u_int64_t p_sticks;	/* (j) Statclock hits in system mode. */
	u_int64_t p_iticks;	/* (j) Statclock hits processing intr. */

	int	p_traceflag;		/* (j?) Kernel trace points. */
	struct	vnode *p_tracep;	/* (j?) Trace to vnode. */

	sigset_t p_siglist;	/* (c) Signals arrived but not delivered. */

	struct	vnode *p_textvp;	/* (b) Vnode of executable. */

	char	p_lock;		/* (c) Process lock (prevent swap) count. */
	struct	mtx p_mtx;		/* (k) Lock for this struct. */
	u_char	p_oncpu;		/* (j) Which cpu we are on. */
	u_char	p_lastcpu;		/* (j) Last cpu we were on. */
	char	p_rqindex;		/* (j) Run queue index. */

	short	p_locks;	/* (*) DEBUG: lockmgr count of held locks */
	short	p_simple_locks;	/* (*) DEBUG: count of held simple locks */
	u_int	p_stops;		/* (c) Procfs event bitmask. */
	u_int	p_stype;		/* (c) Procfs stop event type. */
	char	p_step;			/* (c) Procfs stop *once* flag. */
	u_char	p_pfsflags;		/* (c) Procfs flags. */
	char	p_pad3[2];		/* Alignment. */
	register_t p_retval[2];		/* (k) Syscall aux returns. */
	struct	sigiolst p_sigiolst;	/* (c) List of sigio sources. */
	int	p_sigparent;		/* (c) Signal to parent on exit. */
	sigset_t p_oldsigmask;	/* (c) Saved mask from before sigpause. */
	int	p_sig;			/* (n) For core dump/debugger XXX. */
	u_long	p_code;			/* (n) For core dump/debugger XXX. */
	struct	klist p_klist;	/* (c?) Knotes attached to this process. */
	LIST_HEAD(, mtx) p_heldmtx;	/* (j) For debugging code. */
	struct mtx *p_blocked;		/* (j) Mutex process is blocked on. */
	const char *p_mtxname;		/* (j) Name of mutex blocked on. */
	LIST_HEAD(, mtx) p_contested;	/* (j) Contested locks. */

/* End area that is zeroed on creation. */
#define	p_endzero	p_startcopy

/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_sigmask

	sigset_t p_sigmask;	/* (c) Current signal mask. */
	stack_t	p_sigstk;	/* (c) Stack pointer and on-stack flag. */

	int	p_magic;	/* (b) Magic number. */
	u_char	p_priority;	/* (j) Process priority. */
	u_char	p_usrpri; /* (j) User priority based on p_cpu and p_nice. */
	u_char	p_nativepri;	/* (j) Priority before propagation. */
	char	p_nice;		/* (j/k?) Process "nice" value. */
	char	p_comm[MAXCOMLEN + 1];	/* (b) Process name. */

	struct 	pgrp *p_pgrp;	/* (e?/c?) Pointer to process group. */
	struct 	sysentvec *p_sysent; /* (b) System call dispatch information. */
	struct	rtprio p_rtprio;	/* (j) Realtime priority. */
	struct	prison *p_prison;	/* (b?) jail(4). */
	struct	pargs *p_args;		/* (b?) Process arguments. */

/* End area that is copied on creation. */
#define	p_endcopy	p_addr

	struct	user *p_addr;	/* (k) Kernel virtual addr of u-area (CPU). */
	struct	mdproc p_md;	/* (k) Any machine-dependent fields. */

	u_short	p_xstat;	/* (c) Exit status for wait; also stop sig. */
	u_short	p_acflag;	/* (c) Accounting flags. */
	struct	rusage *p_ru;	/* (a) Exit information. XXX */

	void	*p_aioinfo;	/* (c) ASYNC I/O info. */
	struct proc *p_peers;	/* (c) */
	struct proc *p_leader;	/* (c) */
	struct	pasleep p_asleep;	/* (k) Used by asleep()/await(). */
	void	*p_emuldata;	/* (c) Emulator state data. */
	struct	ithd *p_ithd;	/* (b) For interrupt threads only. */
};

#define	p_session	p_pgrp->pg_session
#define	p_pgid		p_pgrp->pg_id

/* Status values (p_stat). */
#define	SIDL	1		/* Process being created by fork. */
#define	SRUN	2		/* Currently runnable. */
#define	SSLEEP	3		/* Sleeping on an address. */
#define	SSTOP	4		/* Process debugging or suspension. */
#define	SZOMB	5		/* Awaiting collection by parent. */
#define	SWAIT	6		/* Waiting for interrupt. */
#define	SMTX	7		/* Blocked on a mutex. */

/* These flags are kept in p_flag. */
#define	P_ADVLOCK	0x00001	/* Process may hold a POSIX advisory lock. */
#define	P_CONTROLT	0x00002	/* Has a controlling terminal. */
#define	P_INMEM		0x00004	/* Loaded into memory. */
#define	P_NOLOAD	0x00008	/* Ignore during load avg calculations. */
#define	P_PPWAIT	0x00010	/* Parent is waiting for child to exec/exit. */
#define	P_PROFIL	0x00020	/* Has started profiling. */
#define	P_SELECT	0x00040	/* Selecting; wakeup/waiting danger. */
#define	P_SINTR		0x00080	/* Sleep is interruptible. */
#define	P_SUGID		0x00100	/* Had set id privileges since last exec. */
#define	P_SYSTEM	0x00200	/* System proc: no sigs, stats or swapping. */
#define	P_TIMEOUT	0x00400	/* Timing out during sleep. */
#define	P_TRACED	0x00800	/* Debugged process being traced. */
#define	P_WAITED	0x01000	/* Debugging process has waited for child. */
#define	P_WEXIT		0x02000	/* Working on exiting. */
#define	P_EXEC		0x04000	/* Process called exec. */
#define	P_ALRMPEND	0x08000 /* Pending SIGVTALRM needs to be posted. */
#define	P_PROFPEND	0x10000 /* Pending SIGPROF needs to be posted. */

/* Should be moved to machine-dependent areas. */
#define	P_OWEUPC	0x20000	/* Owe process an addupc() call at next ast. */

#define	P_SWAPPING	0x40000	/* Process is being swapped. */
#define	P_SWAPINREQ	0x80000	/* Swapin request due to wakeup. */
#define	P_BUFEXHAUST	0x100000 /* Dirty buffers flush is in progress. */
#define	P_COWINPROGRESS	0x400000 /* Snapshot copy-on-write in progress. */

#define	P_DEADLKTREAT	0x800000 /* Lock aquisition - deadlock treatment. */

#define	P_JAILED	0x1000000 /* Process is in jail. */
#define	P_OLDMASK	0x2000000 /* Need to restore mask after suspend. */
#define	P_ALTSTACK	0x4000000 /* Have alternate signal stack. */

#define	P_MAGIC		0xbeefface

#define	P_CAN_SEE	1
#define	P_CAN_KILL	2
#define	P_CAN_SCHED	3
#define	P_CAN_DEBUG	4

/*
 * MOVE TO ucred.h?
 *
 * Shareable process credentials (always resident).  This includes a reference
 * to the current user credentials as well as real and saved ids that may be
 * used to change ids.
 */
struct	pcred {
	struct	ucred *pc_ucred;	/* Current credentials. */
	uid_t	p_ruid;			/* Real user id. */
	uid_t	p_svuid;		/* Saved effective user id. */
	gid_t	p_rgid;			/* Real group id. */
	gid_t	p_svgid;		/* Saved effective group id. */
	int	p_refcnt;		/* Number of references. */
	struct	uidinfo *p_uidinfo;	/* Per uid resource consumption. */
};

/*
 * Describe an interrupt thread.  There is one of these per irq.  BSD/OS makes
 * this a superset of struct proc, i.e. it_proc is the struct itself and not a
 * pointer.  We point in both directions, because it feels good that way.
 */
struct	ithd {
	struct	proc *it_proc;		/* Interrupt process. */
	LIST_ENTRY(ithd) it_list;	/* All interrupt threads. */
	int	it_need;		/* Needs service. */
	int	irq;			/* Vector. */
	struct	intrhand *it_ih;	/* Interrupt handlers. */
	struct	ithd *it_interrupted;	/* Who we interrupted. */
	void	*it_md;			/* Hook for MD interrupt code. */
};

#ifdef _KERNEL

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_PARGS);
MALLOC_DECLARE(M_SESSION);
MALLOC_DECLARE(M_SUBPROC);
MALLOC_DECLARE(M_ZOMBIE);
#endif

static __inline int
sigonstack(size_t sp)
{
	register struct proc *p = curproc;

	return ((p->p_flag & P_ALTSTACK) ?
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	    ((p->p_sigstk.ss_size == 0) ? (p->p_sigstk.ss_flags & SS_ONSTACK) :
		((sp - (size_t)p->p_sigstk.ss_sp) < p->p_sigstk.ss_size))
#else
	    ((sp - (size_t)p->p_sigstk.ss_sp) < p->p_sigstk.ss_size)
#endif
	    : 0);
}

/* Handy macro to determine if p1 can mangle p2. */
#define	PRISON_CHECK(p1, p2) \
	((p1)->p_prison == NULL || (p1)->p_prison == (p2)->p_prison)

/*
 * We use process IDs <= PID_MAX; PID_MAX + 1 must also fit in a pid_t,
 * as it is used to represent "no process group".
 */
#define	PID_MAX		99999
#define	NO_PID		100000

#define SESS_LEADER(p)	((p)->p_session->s_leader == (p))
#define	SESSHOLD(s)	((s)->s_count++)
#define	SESSRELE(s) {							\
	if (--(s)->s_count == 0)					\
		FREE(s, M_SESSION);					\
}

/* STOPEVENT() is MP safe. */
#define	STOPEVENT(p, e, v) do {						\
	if ((p)->p_stops & (e)) {					\
		mtx_enter(&Giant, MTX_DEF);				\
		stopevent((p), (e), (v));				\
		mtx_exit(&Giant, MTX_DEF);				\
	}								\
} while (0)

/* Lock and unlock a process. */
#define PROC_LOCK(p)	mtx_enter(&(p)->p_mtx, MTX_DEF)
#define PROC_UNLOCK(p)	mtx_exit(&(p)->p_mtx, MTX_DEF)

/* Lock and unlock the proc lists. */
#define	ALLPROC_LOCK(how)						\
	lockmgr(&allproc_lock, (how), NULL, CURPROC)

#define	AP_SHARED	LK_SHARED
#define	AP_EXCLUSIVE	LK_EXCLUSIVE
#define	AP_RELEASE	LK_RELEASE

/* Hold process U-area in memory, normally for ptrace/procfs work. */
#define PHOLD(p) do {							\
	PROC_LOCK(p);							\
	if ((p)->p_lock++ == 0 && ((p)->p_flag & P_INMEM) == 0) {	\
		PROC_UNLOCK(p);						\
		faultin(p);						\
	} else								\
		PROC_UNLOCK(p);						\
} while (0)
#define	PRELE(p) do {							\
	PROC_LOCK(p);							\
	(--(p)->p_lock);						\
	PROC_UNLOCK(p);							\
} while (0)

#define	PIDHASH(pid)	(&pidhashtbl[(pid) & pidhash])
extern LIST_HEAD(pidhashhead, proc) *pidhashtbl;
extern u_long pidhash;

#define	PGRPHASH(pgid)	(&pgrphashtbl[(pgid) & pgrphash])
extern LIST_HEAD(pgrphashhead, pgrp) *pgrphashtbl;
extern u_long pgrphash;

extern struct lock allproc_lock;
extern struct proc proc0;		/* Process slot for swapper. */
extern int hogticks;			/* Limit on kernel cpu hogs. */
extern int nprocs, maxproc;		/* Current and max number of procs. */
extern int maxprocperuid;		/* Max procs per uid. */
extern u_long ps_arg_cache_limit;
extern int ps_argsopen;
extern int ps_showallprocs;
extern int sched_quantum;		/* Scheduling quantum in ticks. */

LIST_HEAD(proclist, proc);
extern struct proclist allproc;		/* List of all processes. */
extern struct proclist zombproc;	/* List of zombie processes. */
extern struct proc *initproc, *pageproc; /* Process slots for init, pager. */
extern struct proc *updateproc;		/* Process slot for syncer (sic). */

#define	NQS	32			/* 32 run queues. */

TAILQ_HEAD(rq, proc);
extern struct rq itqueues[];
extern struct rq rtqueues[];
extern struct rq queues[];
extern struct rq idqueues[];
extern struct vm_zone *proc_zone;

/*
 * XXX macros for scheduler.  Shouldn't be here, but currently needed for
 * bounding the dubious p_estcpu inheritance in wait1().
 * INVERSE_ESTCPU_WEIGHT is only suitable for statclock() frequencies in
 * the range 100-256 Hz (approximately).
 */
#define	ESTCPULIM(e) \
    min((e), INVERSE_ESTCPU_WEIGHT * (NICE_WEIGHT * (PRIO_MAX - PRIO_MIN) - \
	     PPQ) + INVERSE_ESTCPU_WEIGHT - 1)
#define	INVERSE_ESTCPU_WEIGHT	8	/* 1 / (priorities per estcpu level). */
#define	NICE_WEIGHT	1		/* Priorities per nice level. */
#define	PPQ		(128 / NQS)	/* Priorities per queue. */

struct mtx;

struct	proc *pfind __P((pid_t));	/* Find process by id. */
struct	pgrp *pgfind __P((pid_t));	/* Find process group by id. */

struct	proc *chooseproc __P((void));
int	enterpgrp __P((struct proc *p, pid_t pgid, int mksess));
void	faultin __P((struct proc *p));
void	fixjobc __P((struct proc *p, struct pgrp *pgrp, int entering));
int	fork1 __P((struct proc *, int, struct proc **));
int	inferior __P((struct proc *p));
int	leavepgrp __P((struct proc *p));
void	mi_switch __P((void));
int	p_can __P((const struct proc *p1, const struct proc *p2, int operation,
	    int *privused));
int	p_trespass __P((struct proc *p1, struct proc *p2));
void	procinit __P((void));
void	proc_reparent __P((struct proc *child, struct proc *newparent));
u_int32_t procrunnable __P((void));
void	remrunqueue __P((struct proc *));
void	resetpriority __P((struct proc *));
int	roundrobin_interval __P((void));
void	schedclock __P((struct proc *));
void	setrunnable __P((struct proc *));
void	setrunqueue __P((struct proc *));
void	setsugid __P((struct proc *p));
void	sleepinit __P((void));
void	stopevent __P((struct proc *, u_int, u_int));
void	cpu_idle __P((void));
void	cpu_switch __P((void));
void	cpu_throw __P((void)) __dead2;
void	unsleep __P((struct proc *));

void	cpu_exit __P((struct proc *)) __dead2;
void	exit1 __P((struct proc *, int)) __dead2;
void	cpu_fork __P((struct proc *, struct proc *, int));
void	cpu_set_fork_handler __P((struct proc *, void (*)(void *), void *));
int	trace_req __P((struct proc *));
void	cpu_wait __P((struct proc *));
int	cpu_coredump __P((struct proc *, struct vnode *, struct ucred *));
#endif	/* _KERNEL */

#endif	/* !_SYS_PROC_H_ */
