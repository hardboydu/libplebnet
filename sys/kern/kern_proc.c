/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)kern_proc.c	8.7 (Berkeley) 2/14/95
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/tty.h>
#include <sys/signalvar.h>
#include <vm/vm.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/user.h>
#include <vm/vm_zone.h>
#include <sys/jail.h>

static MALLOC_DEFINE(M_PGRP, "pgrp", "process group header");
MALLOC_DEFINE(M_SESSION, "session", "session header");
static MALLOC_DEFINE(M_PROC, "proc", "Proc structures");
MALLOC_DEFINE(M_SUBPROC, "subproc", "Proc sub-structures");

int ps_showallprocs = 1;
SYSCTL_INT(_kern, OID_AUTO, ps_showallprocs, CTLFLAG_RW,
    &ps_showallprocs, 0, "");

static void pgdelete	__P((struct pgrp *));

static void	orphanpg __P((struct pgrp *pg));

/*
 * Other process lists
 */
struct pidhashhead *pidhashtbl;
u_long pidhash;
struct pgrphashhead *pgrphashtbl;
u_long pgrphash;
struct proclist allproc;
struct proclist zombproc;
struct lock allproc_lock;
struct lock proctree_lock;
vm_zone_t proc_zone;
vm_zone_t ithread_zone;

/*
 * Initialize global process hashing structures.
 */
void
procinit()
{

	lockinit(&allproc_lock, PZERO, "allproc", 0, 0);
	lockinit(&proctree_lock, PZERO, "proctree", 0, 0);
	LIST_INIT(&allproc);
	LIST_INIT(&zombproc);
	pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);
	pgrphashtbl = hashinit(maxproc / 4, M_PROC, &pgrphash);
	proc_zone = zinit("PROC", sizeof (struct proc), 0, 0, 5);
	uihashinit();
	/*
	 * This should really be a compile time warning, but I do
	 * not know of any way to do that...
	 */
	if (sizeof(struct kinfo_proc) != KINFO_PROC_SIZE)
		printf("WARNING: size of kinfo_proc (%ld) should be %d!!!\n",
			(long)sizeof(struct kinfo_proc), KINFO_PROC_SIZE);
}

/*
 * Is p an inferior of the current process?
 */
int
inferior(p)
	register struct proc *p;
{
	int rval = 1;

	PROCTREE_LOCK(PT_SHARED);
	for (; p != curproc; p = p->p_pptr)
		if (p->p_pid == 0) {
			rval = 0;
			break;
		}
	PROCTREE_LOCK(PT_RELEASE);
	return (rval);
}

/*
 * Locate a process by number
 */
struct proc *
pfind(pid)
	register pid_t pid;
{
	register struct proc *p;

	ALLPROC_LOCK(AP_SHARED);
	LIST_FOREACH(p, PIDHASH(pid), p_hash)
		if (p->p_pid == pid)
			break;
	ALLPROC_LOCK(AP_RELEASE);
	return (p);
}

/*
 * Locate a process group by number
 */
struct pgrp *
pgfind(pgid)
	register pid_t pgid;
{
	register struct pgrp *pgrp;

	LIST_FOREACH(pgrp, PGRPHASH(pgid), pg_hash)
		if (pgrp->pg_id == pgid)
			return (pgrp);
	return (NULL);
}

/*
 * Move p to a new or existing process group (and session)
 */
int
enterpgrp(p, pgid, mksess)
	register struct proc *p;
	pid_t pgid;
	int mksess;
{
	register struct pgrp *pgrp = pgfind(pgid);
	struct pgrp *savegrp;

	KASSERT(pgrp == NULL || !mksess,
	    ("enterpgrp: setsid into non-empty pgrp"));
	KASSERT(!SESS_LEADER(p),
	    ("enterpgrp: session leader attempted setpgrp"));

	if (pgrp == NULL) {
		pid_t savepid = p->p_pid;
		struct proc *np;
		/*
		 * new process group
		 */
		KASSERT(p->p_pid == pgid,
		    ("enterpgrp: new pgrp and pid != pgid"));
		MALLOC(pgrp, struct pgrp *, sizeof(struct pgrp), M_PGRP,
		    M_WAITOK);
		if ((np = pfind(savepid)) == NULL || np != p)
			return (ESRCH);
		if (mksess) {
			register struct session *sess;

			/*
			 * new session
			 */
			MALLOC(sess, struct session *, sizeof(struct session),
			    M_SESSION, M_WAITOK);
			sess->s_leader = p;
			sess->s_sid = p->p_pid;
			sess->s_count = 1;
			sess->s_ttyvp = NULL;
			sess->s_ttyp = NULL;
			bcopy(p->p_session->s_login, sess->s_login,
			    sizeof(sess->s_login));
			PROC_LOCK(p);
			p->p_flag &= ~P_CONTROLT;
			PROC_UNLOCK(p);
			pgrp->pg_session = sess;
			KASSERT(p == curproc,
			    ("enterpgrp: mksession and p != curproc"));
		} else {
			pgrp->pg_session = p->p_session;
			pgrp->pg_session->s_count++;
		}
		pgrp->pg_id = pgid;
		LIST_INIT(&pgrp->pg_members);
		LIST_INSERT_HEAD(PGRPHASH(pgid), pgrp, pg_hash);
		pgrp->pg_jobc = 0;
		SLIST_INIT(&pgrp->pg_sigiolst);
	} else if (pgrp == p->p_pgrp)
		return (0);

	/*
	 * Adjust eligibility of affected pgrps to participate in job control.
	 * Increment eligibility counts before decrementing, otherwise we
	 * could reach 0 spuriously during the first call.
	 */
	fixjobc(p, pgrp, 1);
	fixjobc(p, p->p_pgrp, 0);

	PROC_LOCK(p);
	LIST_REMOVE(p, p_pglist);
	savegrp = p->p_pgrp;
	p->p_pgrp = pgrp;
	LIST_INSERT_HEAD(&pgrp->pg_members, p, p_pglist);
	PROC_UNLOCK(p);
	if (LIST_EMPTY(&savegrp->pg_members))
		pgdelete(savegrp);
	return (0);
}

/*
 * remove process from process group
 */
int
leavepgrp(p)
	register struct proc *p;
{
	struct pgrp *savegrp;

	PROC_LOCK(p);
	LIST_REMOVE(p, p_pglist);
	savegrp = p->p_pgrp;
	p->p_pgrp = NULL;
	PROC_UNLOCK(p);
	if (LIST_EMPTY(&savegrp->pg_members))
		pgdelete(savegrp);
	return (0);
}

/*
 * delete a process group
 */
static void
pgdelete(pgrp)
	register struct pgrp *pgrp;
{

	/*
	 * Reset any sigio structures pointing to us as a result of
	 * F_SETOWN with our pgid.
	 */
	funsetownlst(&pgrp->pg_sigiolst);

	if (pgrp->pg_session->s_ttyp != NULL &&
	    pgrp->pg_session->s_ttyp->t_pgrp == pgrp)
		pgrp->pg_session->s_ttyp->t_pgrp = NULL;
	LIST_REMOVE(pgrp, pg_hash);
	if (--pgrp->pg_session->s_count == 0)
		FREE(pgrp->pg_session, M_SESSION);
	FREE(pgrp, M_PGRP);
}

/*
 * Adjust pgrp jobc counters when specified process changes process group.
 * We count the number of processes in each process group that "qualify"
 * the group for terminal job control (those with a parent in a different
 * process group of the same session).  If that count reaches zero, the
 * process group becomes orphaned.  Check both the specified process'
 * process group and that of its children.
 * entering == 0 => p is leaving specified group.
 * entering == 1 => p is entering specified group.
 */
void
fixjobc(p, pgrp, entering)
	register struct proc *p;
	register struct pgrp *pgrp;
	int entering;
{
	register struct pgrp *hispgrp;
	register struct session *mysession = pgrp->pg_session;

	/*
	 * Check p's parent to see whether p qualifies its own process
	 * group; if so, adjust count for p's process group.
	 */
	PROCTREE_LOCK(PT_SHARED);
	if ((hispgrp = p->p_pptr->p_pgrp) != pgrp &&
	    hispgrp->pg_session == mysession) {
		if (entering)
			pgrp->pg_jobc++;
		else if (--pgrp->pg_jobc == 0)
			orphanpg(pgrp);
	}

	/*
	 * Check this process' children to see whether they qualify
	 * their process groups; if so, adjust counts for children's
	 * process groups.
	 */
	LIST_FOREACH(p, &p->p_children, p_sibling)
		if ((hispgrp = p->p_pgrp) != pgrp &&
		    hispgrp->pg_session == mysession &&
		    p->p_stat != SZOMB) {
			if (entering)
				hispgrp->pg_jobc++;
			else if (--hispgrp->pg_jobc == 0)
				orphanpg(hispgrp);
		}
	PROCTREE_LOCK(PT_RELEASE);
}

/*
 * A process group has become orphaned;
 * if there are any stopped processes in the group,
 * hang-up all process in that group.
 */
static void
orphanpg(pg)
	struct pgrp *pg;
{
	register struct proc *p;

	mtx_lock_spin(&sched_lock);
	LIST_FOREACH(p, &pg->pg_members, p_pglist) {
		if (p->p_stat == SSTOP) {
			mtx_unlock_spin(&sched_lock);
			LIST_FOREACH(p, &pg->pg_members, p_pglist) {
				PROC_LOCK(p);
				psignal(p, SIGHUP);
				psignal(p, SIGCONT);
				PROC_UNLOCK(p);
			}
			return;
		}
	}
	mtx_unlock_spin(&sched_lock);
}

#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>

DB_SHOW_COMMAND(pgrpdump, pgrpdump)
{
	register struct pgrp *pgrp;
	register struct proc *p;
	register int i;

	for (i = 0; i <= pgrphash; i++) {
		if (!LIST_EMPTY(&pgrphashtbl[i])) {
			printf("\tindx %d\n", i);
			LIST_FOREACH(pgrp, &pgrphashtbl[i], pg_hash) {
				printf(
			"\tpgrp %p, pgid %ld, sess %p, sesscnt %d, mem %p\n",
				    (void *)pgrp, (long)pgrp->pg_id,
				    (void *)pgrp->pg_session,
				    pgrp->pg_session->s_count,
				    (void *)LIST_FIRST(&pgrp->pg_members));
				LIST_FOREACH(p, &pgrp->pg_members, p_pglist) {
					printf("\t\tpid %ld addr %p pgrp %p\n", 
					    (long)p->p_pid, (void *)p,
					    (void *)p->p_pgrp);
				}
			}
		}
	}
}
#endif /* DDB */

/*
 * Fill in an kinfo_proc structure for the specified process.
 */
void
fill_kinfo_proc(p, kp)
	struct proc *p;
	struct kinfo_proc *kp;
{
	struct tty *tp;
	struct session *sp;

	bzero(kp, sizeof(*kp));

	kp->ki_structsize = sizeof(*kp);
	kp->ki_paddr = p;
	PROC_LOCK(p);
	kp->ki_addr = p->p_addr;
	kp->ki_args = p->p_args;
	kp->ki_tracep = p->p_tracep;
	kp->ki_textvp = p->p_textvp;
	kp->ki_fd = p->p_fd;
	kp->ki_vmspace = p->p_vmspace;
	if (p->p_cred) {
		kp->ki_uid = p->p_cred->pc_ucred->cr_uid;
		kp->ki_ruid = p->p_cred->p_ruid;
		kp->ki_svuid = p->p_cred->p_svuid;
		kp->ki_ngroups = p->p_cred->pc_ucred->cr_ngroups;
		bcopy(p->p_cred->pc_ucred->cr_groups, kp->ki_groups,
		    NGROUPS * sizeof(gid_t));
		kp->ki_rgid = p->p_cred->p_rgid;
		kp->ki_svgid = p->p_cred->p_svgid;
	}
	if (p->p_procsig) {
		kp->ki_sigignore = p->p_procsig->ps_sigignore;
		kp->ki_sigcatch = p->p_procsig->ps_sigcatch;
	}
	mtx_lock_spin(&sched_lock);
	if (p->p_stat != SIDL && p->p_stat != SZOMB && p->p_vmspace != NULL) {
		struct vmspace *vm = p->p_vmspace;

		kp->ki_size = vm->vm_map.size;
		kp->ki_rssize = vmspace_resident_count(vm); /*XXX*/
		kp->ki_swrss = vm->vm_swrss;
		kp->ki_tsize = vm->vm_tsize;
		kp->ki_dsize = vm->vm_dsize;
		kp->ki_ssize = vm->vm_ssize;
	}
	if ((p->p_sflag & PS_INMEM) && p->p_stats) {
		kp->ki_start = p->p_stats->p_start;
		kp->ki_rusage = p->p_stats->p_ru;
		kp->ki_childtime.tv_sec = p->p_stats->p_cru.ru_utime.tv_sec +
		    p->p_stats->p_cru.ru_stime.tv_sec;
		kp->ki_childtime.tv_usec = p->p_stats->p_cru.ru_utime.tv_usec +
		    p->p_stats->p_cru.ru_stime.tv_usec;
	}
	if (p->p_wmesg) {
		strncpy(kp->ki_wmesg, p->p_wmesg, WMESGLEN);
		kp->ki_wmesg[WMESGLEN] = 0;
	}
	if (p->p_stat == SMTX) {
		kp->ki_kiflag |= KI_MTXBLOCK;
		strncpy(kp->ki_mtxname, p->p_mtxname, MTXNAMELEN);
		kp->ki_mtxname[MTXNAMELEN] = 0;
	}
	kp->ki_stat = p->p_stat;
	kp->ki_sflag = p->p_sflag;
	kp->ki_pctcpu = p->p_pctcpu;
	kp->ki_estcpu = p->p_estcpu;
	kp->ki_slptime = p->p_slptime;
	kp->ki_swtime = p->p_swtime;
	kp->ki_wchan = p->p_wchan;
	kp->ki_traceflag = p->p_traceflag;
	kp->ki_pri = p->p_pri;
	kp->ki_nice = p->p_nice;
	kp->ki_runtime = p->p_runtime;
	kp->ki_pid = p->p_pid;
	kp->ki_rqindex = p->p_rqindex;
	kp->ki_oncpu = p->p_oncpu;
	kp->ki_lastcpu = p->p_lastcpu;
	mtx_unlock_spin(&sched_lock);
	sp = NULL;
	if (p->p_pgrp) {
		kp->ki_pgid = p->p_pgrp->pg_id;
		kp->ki_jobc = p->p_pgrp->pg_jobc;
		sp = p->p_pgrp->pg_session;

		if (sp != NULL) {
			kp->ki_sid = sp->s_sid;
			bcopy(sp->s_login, kp->ki_login, sizeof(kp->ki_login));
			if (sp->s_ttyvp)
				kp->ki_kiflag = KI_CTTY;
			if (SESS_LEADER(p))
				kp->ki_kiflag |= KI_SLEADER;
		}
	}
	if ((p->p_flag & P_CONTROLT) && sp && ((tp = sp->s_ttyp) != NULL)) {
		kp->ki_tdev = dev2udev(tp->t_dev);
		kp->ki_tpgid = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		if (tp->t_session)
			kp->ki_tsid = tp->t_session->s_sid;
	} else
		kp->ki_tdev = NOUDEV;
	if (p->p_comm[0] != 0) {
		strncpy(kp->ki_comm, p->p_comm, MAXCOMLEN);
		kp->ki_comm[MAXCOMLEN] = 0;
	}
	kp->ki_siglist = p->p_siglist;
	kp->ki_sigmask = p->p_sigmask;
	kp->ki_xstat = p->p_xstat;
	kp->ki_acflag = p->p_acflag;
	kp->ki_flag = p->p_flag;
	/* If jailed(p->p_ucred), emulate the old P_JAILED flag. */
	if (jailed(p->p_ucred))
		kp->ki_flag |= P_JAILED;
	kp->ki_lock = p->p_lock;
	if (p->p_pptr)
		kp->ki_ppid = p->p_pptr->p_pid;
	PROC_UNLOCK(p);
}

/*
 * Locate a zombie process by number
 */
struct proc *
zpfind(pid_t pid)
{
	struct proc *p;

	ALLPROC_LOCK(AP_SHARED);
	LIST_FOREACH(p, &zombproc, p_list)
		if (p->p_pid == pid)
			break;
	ALLPROC_LOCK(AP_RELEASE);
	return (p);
}


static int
sysctl_out_proc(struct proc *p, struct sysctl_req *req, int doingzomb)
{
	struct kinfo_proc kinfo_proc;
	int error;
	pid_t pid = p->p_pid;

	fill_kinfo_proc(p, &kinfo_proc);
	error = SYSCTL_OUT(req, (caddr_t)&kinfo_proc, sizeof(kinfo_proc));
	if (error)
		return (error);
	if (!doingzomb && pid && (pfind(pid) != p))
		return EAGAIN;
	if (doingzomb && zpfind(pid) != p)
		return EAGAIN;
	return (0);
}

static int
sysctl_kern_proc(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	u_int namelen = arg2;
	struct proc *p;
	int doingzomb;
	int error = 0;

	if (oidp->oid_number == KERN_PROC_PID) {
		if (namelen != 1) 
			return (EINVAL);
		p = pfind((pid_t)name[0]);
		if (!p)
			return (0);
		if (p_can(curproc, p, P_CAN_SEE, NULL))
			return (0);
		error = sysctl_out_proc(p, req, 0);
		return (error);
	}
	if (oidp->oid_number == KERN_PROC_ALL && !namelen)
		;
	else if (oidp->oid_number != KERN_PROC_ALL && namelen == 1)
		;
	else
		return (EINVAL);
	
	if (!req->oldptr) {
		/* overestimate by 5 procs */
		error = SYSCTL_OUT(req, 0, sizeof (struct kinfo_proc) * 5);
		if (error)
			return (error);
	}
	ALLPROC_LOCK(AP_SHARED);
	for (doingzomb=0 ; doingzomb < 2 ; doingzomb++) {
		if (!doingzomb)
			p = LIST_FIRST(&allproc);
		else
			p = LIST_FIRST(&zombproc);
		for (; p != 0; p = LIST_NEXT(p, p_list)) {
			/*
			 * Show a user only appropriate processes.
			 */
			if (p_can(curproc, p, P_CAN_SEE, NULL))
				continue;
			/*
			 * Skip embryonic processes.
			 */
			if (p->p_stat == SIDL)
				continue;
			/*
			 * TODO - make more efficient (see notes below).
			 * do by session.
			 */
			switch (oidp->oid_number) {

			case KERN_PROC_PGRP:
				/* could do this by traversing pgrp */
				if (p->p_pgrp == NULL || 
				    p->p_pgrp->pg_id != (pid_t)name[0])
					continue;
				break;

			case KERN_PROC_TTY:
				if ((p->p_flag & P_CONTROLT) == 0 ||
				    p->p_session == NULL ||
				    p->p_session->s_ttyp == NULL ||
				    dev2udev(p->p_session->s_ttyp->t_dev) != 
					(udev_t)name[0])
					continue;
				break;

			case KERN_PROC_UID:
				if (p->p_ucred == NULL || 
				    p->p_ucred->cr_uid != (uid_t)name[0])
					continue;
				break;

			case KERN_PROC_RUID:
				if (p->p_ucred == NULL || 
				    p->p_cred->p_ruid != (uid_t)name[0])
					continue;
				break;
			}

			if (p_can(curproc, p, P_CAN_SEE, NULL))
				continue;

			error = sysctl_out_proc(p, req, doingzomb);
			if (error) {
				ALLPROC_LOCK(AP_RELEASE);
				return (error);
			}
		}
	}
	ALLPROC_LOCK(AP_RELEASE);
	return (0);
}

/*
 * This sysctl allows a process to retrieve the argument list or process
 * title for another process without groping around in the address space
 * of the other process.  It also allow a process to set its own "process 
 * title to a string of its own choice.
 */
static int
sysctl_kern_proc_args(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	u_int namelen = arg2;
	struct proc *p;
	struct pargs *pa;
	int error = 0;

	if (namelen != 1) 
		return (EINVAL);

	p = pfind((pid_t)name[0]);
	if (!p)
		return (0);

	if ((!ps_argsopen) && p_can(curproc, p, P_CAN_SEE, NULL))
		return (0);

	if (req->newptr && curproc != p)
		return (EPERM);

	if (req->oldptr && p->p_args != NULL)
		error = SYSCTL_OUT(req, p->p_args->ar_args, p->p_args->ar_length);
	if (req->newptr == NULL)
		return (error);

	if (p->p_args && --p->p_args->ar_ref == 0) 
		FREE(p->p_args, M_PARGS);
	PROC_LOCK(p);
	p->p_args = NULL;
	PROC_UNLOCK(p);

	if (req->newlen + sizeof(struct pargs) > ps_arg_cache_limit)
		return (error);

	MALLOC(pa, struct pargs *, sizeof(struct pargs) + req->newlen, 
	    M_PARGS, M_WAITOK);
	pa->ar_ref = 1;
	pa->ar_length = req->newlen;
	error = SYSCTL_IN(req, pa->ar_args, req->newlen);
	if (!error) {
		PROC_LOCK(p);
		p->p_args = pa;
		PROC_UNLOCK(p);
	} else
		FREE(pa, M_PARGS);
	return (error);
}

SYSCTL_NODE(_kern, KERN_PROC, proc, CTLFLAG_RD,  0, "Process table");

SYSCTL_PROC(_kern_proc, KERN_PROC_ALL, all, CTLFLAG_RD|CTLTYPE_STRUCT,
	0, 0, sysctl_kern_proc, "S,proc", "Return entire process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_PGRP, pgrp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_TTY, tty, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_UID, uid, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_RUID, ruid, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_PID, pid, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_ARGS, args, CTLFLAG_RW | CTLFLAG_ANYBODY,
	sysctl_kern_proc_args, "Process argument list");
