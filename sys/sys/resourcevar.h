/*
 * Copyright (c) 1991, 1993
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
 *	@(#)resourcevar.h	8.4 (Berkeley) 1/9/95
 * $FreeBSD$
 */

#ifndef	_SYS_RESOURCEVAR_H_
#define	_SYS_RESOURCEVAR_H_

#include <sys/resource.h>
#include <sys/queue.h>
#ifdef _KERNEL
#include <sys/_lock.h>
#include <sys/_mutex.h>
#endif

/*
 * Kernel per-process accounting / statistics
 * (not necessarily resident except when running).
 */
struct pstats {
#define	pstat_startzero	p_ru
	struct	rusage p_ru;		/* stats for this proc */
	struct	rusage p_cru;		/* sum of stats for reaped children */
	struct	itimerval p_timer[3];	/* virtual-time timers */
#define	pstat_endzero	pstat_startcopy

#define	pstat_startcopy	p_prof
	struct uprof {			/* profile arguments */
		caddr_t	pr_base;	/* buffer base */
		u_long	pr_size;	/* buffer size */
		u_long	pr_off;		/* pc offset */
		u_long	pr_scale;	/* pc scaling */
		u_long	pr_addr;	/* temp storage for addr until AST */
		u_int	pr_ticks;	/* temp storage for ticks until AST */
	} p_prof;
#define	pstat_endcopy	p_start
	struct	timeval p_start;	/* starting time */
};

#ifdef _KERNEL

/*
 * Kernel shareable process resource limits.  Because this structure
 * is moderately large but changes infrequently, it is normally
 * shared copy-on-write after forks.
 */
struct plimit {
	struct	rlimit pl_rlimit[RLIM_NLIMITS];
	int	pl_refcnt;		/* number of references */
	struct	mtx *pl_mtx;
};

#define	LIM_LOCK(lim)		mtx_lock((lim)->pl_mtx)
#define	LIM_UNLOCK(lim)		mtx_unlock((lim)->pl_mtx)
#define	LIM_LOCK_ASSERT(lim, f)	mtx_assert((lim)->pl_mtx, (f))

/*
 * Per uid resource consumption
 */
struct uidinfo {
	LIST_ENTRY(uidinfo) ui_hash;
	rlim_t	ui_sbsize;		/* socket buffer space consumed */
	long	ui_proccnt;		/* number of processes */
	uid_t	ui_uid;			/* uid */
	u_int	ui_ref;			/* reference count */
	struct mtx *ui_mtxp;		/* protect all counts/limits */
};

#define	UIDINFO_LOCK(ui)	mtx_lock((ui)->ui_mtxp)
#define	UIDINFO_UNLOCK(ui)	mtx_unlock((ui)->ui_mtxp)

struct proc;
struct thread;

void	 addupc_intr(struct thread *td, uintptr_t pc, u_int ticks);
void	 addupc_task(struct thread *td, uintptr_t pc, u_int ticks);
void	 calcru(struct proc *p, struct timeval *up, struct timeval *sp,
	    struct timeval *ip);
int	 chgproccnt(struct uidinfo *uip, int diff, int max);
int	 chgsbsize(struct uidinfo *uip, u_int *hiwat, u_int to,
	    rlim_t max);
int	 fuswintr(void *base);
struct plimit
	*lim_alloc(void);
void	 lim_copy(struct plimit *dst, struct plimit *src);
rlim_t	 lim_cur(struct proc *p, int which);
void	 lim_free(struct plimit *limp);
struct plimit
	*lim_hold(struct plimit *limp);
rlim_t	 lim_max(struct proc *p, int which);
void	 lim_rlimit(struct proc *p, int which, struct rlimit *rlp);
void	 ruadd(struct rusage *ru, struct rusage *ru2);
int	 suswintr(void *base, int word);
struct uidinfo
	*uifind(uid_t uid);
void	 uifree(struct uidinfo *uip);
void	 uihashinit(void);
void	 uihold(struct uidinfo *uip);

#endif /* _KERNEL */
#endif /* !_SYS_RESOURCEVAR_H_ */
