/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)kern_descrip.c	8.6 (Berkeley) 4/19/94
 * $FreeBSD$
 */

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/conf.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/resourcevar.h>
#include <sys/event.h>
#include <sys/sx.h>
#include <sys/socketvar.h>

#include <machine/limits.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

static MALLOC_DEFINE(M_FILEDESC, "file desc", "Open file descriptor table");
static MALLOC_DEFINE(M_SIGIO, "sigio", "sigio structures");

uma_zone_t file_zone;

static	 d_open_t  fdopen;
#define NUMFDESC 64

#define CDEV_MAJOR 22
static struct cdevsw fildesc_cdevsw = {
	/* open */	fdopen,
	/* close */	noclose,
	/* read */	noread,
	/* write */	nowrite,
	/* ioctl */	noioctl,
	/* poll */	nopoll,
	/* mmap */	nommap,
	/* strategy */	nostrategy,
	/* name */	"FD",
	/* maj */	CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	0,
};

static int do_dup(struct filedesc *fdp, int old, int new, register_t *retval, struct thread *td);
static int badfo_readwrite(struct file *fp, struct uio *uio,
    struct ucred *cred, int flags, struct thread *td);
static int badfo_ioctl(struct file *fp, u_long com, caddr_t data,
    struct thread *td);
static int badfo_poll(struct file *fp, int events,
    struct ucred *cred, struct thread *td);
static int badfo_kqfilter(struct file *fp, struct knote *kn);
static int badfo_stat(struct file *fp, struct stat *sb, struct thread *td);
static int badfo_close(struct file *fp, struct thread *td);

/*
 * Descriptor management.
 */
struct filelist filehead;	/* head of list of open files */
int nfiles;			/* actual number of open files */
extern int cmask;	
struct sx filelist_lock;	/* sx to protect filelist */
struct sx sigio_lock;		/* sx to protect pointers to sigio */

/*
 * System calls on descriptors.
 */
#ifndef _SYS_SYSPROTO_H_
struct getdtablesize_args {
	int	dummy;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
getdtablesize(td, uap)
	struct thread *td;
	struct getdtablesize_args *uap;
{
	struct proc *p = td->td_proc;

	mtx_lock(&Giant);
	td->td_retval[0] = 
	    min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfilesperproc);
	mtx_unlock(&Giant);
	return (0);
}

/*
 * Duplicate a file descriptor to a particular value.
 *
 * note: keep in mind that a potential race condition exists when closing
 * descriptors from a shared descriptor table (via rfork).
 */
#ifndef _SYS_SYSPROTO_H_
struct dup2_args {
	u_int	from;
	u_int	to;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
dup2(td, uap)
	struct thread *td;
	struct dup2_args *uap;
{
	struct proc *p = td->td_proc;
	register struct filedesc *fdp = td->td_proc->p_fd;
	register u_int old = uap->from, new = uap->to;
	int i, error;

	FILEDESC_LOCK(fdp);
retry:
	if (old >= fdp->fd_nfiles ||
	    fdp->fd_ofiles[old] == NULL ||
	    new >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
	    new >= maxfilesperproc) {
		FILEDESC_UNLOCK(fdp);
		return (EBADF);
	}
	if (old == new) {
		td->td_retval[0] = new;
		FILEDESC_UNLOCK(fdp);
		return (0);
	}
	if (new >= fdp->fd_nfiles) {
		if ((error = fdalloc(td, new, &i))) {
			FILEDESC_UNLOCK(fdp);
			return (error);
		}
		/*
		 * fdalloc() may block, retest everything.
		 */
		goto retry;
	}
	error = do_dup(fdp, (int)old, (int)new, td->td_retval, td);
	return(error);
}

/*
 * Duplicate a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct dup_args {
	u_int	fd;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
dup(td, uap)
	struct thread *td;
	struct dup_args *uap;
{
	register struct filedesc *fdp;
	u_int old;
	int new, error;

	old = uap->fd;
	fdp = td->td_proc->p_fd;
	FILEDESC_LOCK(fdp);
	if (old >= fdp->fd_nfiles || fdp->fd_ofiles[old] == NULL) {
		FILEDESC_UNLOCK(fdp);
		return (EBADF);
	}
	if ((error = fdalloc(td, 0, &new))) {
		FILEDESC_UNLOCK(fdp);
		return (error);
	}
	error = do_dup(fdp, (int)old, new, td->td_retval, td);
	return (error);
}

/*
 * The file control system call.
 */
#ifndef _SYS_SYSPROTO_H_
struct fcntl_args {
	int	fd;
	int	cmd;
	long	arg;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
fcntl(td, uap)
	struct thread *td;
	register struct fcntl_args *uap;
{
	register struct proc *p = td->td_proc;
	register struct filedesc *fdp;
	register struct file *fp;
	register char *pop;
	struct vnode *vp;
	int i, tmp, error = 0, flg = F_POSIX;
	struct flock fl;
	u_int newmin;
	struct proc *leaderp;

	mtx_lock(&Giant);

	fdp = p->p_fd;
	FILEDESC_LOCK(fdp);
	if ((unsigned)uap->fd >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[uap->fd]) == NULL) {
		FILEDESC_UNLOCK(fdp);
		error = EBADF;
		goto done2;
	}
	pop = &fdp->fd_ofileflags[uap->fd];

	switch (uap->cmd) {
	case F_DUPFD:
		newmin = uap->arg;
		if (newmin >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
		    newmin >= maxfilesperproc) {
			FILEDESC_UNLOCK(fdp);
			error = EINVAL;
			break;
		}
		if ((error = fdalloc(td, newmin, &i))) {
			FILEDESC_UNLOCK(fdp);
			break;
		}
		error = do_dup(fdp, uap->fd, i, td->td_retval, td);
		break;

	case F_GETFD:
		td->td_retval[0] = (*pop & UF_EXCLOSE) ? FD_CLOEXEC : 0;
		FILEDESC_UNLOCK(fdp);
		break;

	case F_SETFD:
		*pop = (*pop &~ UF_EXCLOSE) |
		    (uap->arg & FD_CLOEXEC ? UF_EXCLOSE : 0);
		FILEDESC_UNLOCK(fdp);
		break;

	case F_GETFL:
		FILE_LOCK(fp);
		FILEDESC_UNLOCK(fdp);
		td->td_retval[0] = OFLAGS(fp->f_flag);
		FILE_UNLOCK(fp);
		break;

	case F_SETFL:
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		fp->f_flag &= ~FCNTLFLAGS;
		fp->f_flag |= FFLAGS(uap->arg & ~O_ACCMODE) & FCNTLFLAGS;
		tmp = fp->f_flag & FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, td);
		if (error) {
			fdrop(fp, td);
			break;
		}
		tmp = fp->f_flag & FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, td);
		if (!error) {
			fdrop(fp, td);
			break;
		}
		fp->f_flag &= ~FNONBLOCK;
		tmp = 0;
		(void)fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, td);
		fdrop(fp, td);
		break;

	case F_GETOWN:
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		error = fo_ioctl(fp, FIOGETOWN, (caddr_t)td->td_retval, td);
		fdrop(fp, td);
		break;

	case F_SETOWN:
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		error = fo_ioctl(fp, FIOSETOWN, (caddr_t)&uap->arg, td);
		fdrop(fp, td);
		break;

	case F_SETLKW:
		flg |= F_WAIT;
		/* Fall into F_SETLK */

	case F_SETLK:
		if (fp->f_type != DTYPE_VNODE) {
			FILEDESC_UNLOCK(fdp);
			error = EBADF;
			break;
		}
		vp = (struct vnode *)fp->f_data;
		/*
		 * copyin/lockop may block
		 */
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		vp = (struct vnode *)fp->f_data;

		/* Copy in the lock structure */
		error = copyin((caddr_t)(intptr_t)uap->arg, (caddr_t)&fl,
		    sizeof(fl));
		if (error) {
			fdrop(fp, td);
			break;
		}
		if (fl.l_whence == SEEK_CUR) {
			if (fp->f_offset < 0 ||
			    (fl.l_start > 0 &&
			     fp->f_offset > OFF_MAX - fl.l_start)) {
				fdrop(fp, td);
				error = EOVERFLOW;
				break;
			}
			fl.l_start += fp->f_offset;
		}

		switch (fl.l_type) {
		case F_RDLCK:
			if ((fp->f_flag & FREAD) == 0) {
				error = EBADF;
				break;
			}
			PROC_LOCK(p);
			p->p_flag |= P_ADVLOCK;
			leaderp = p->p_leader;
			PROC_UNLOCK(p);
			error = VOP_ADVLOCK(vp, (caddr_t)leaderp, F_SETLK,
			    &fl, flg);
			break;
		case F_WRLCK:
			if ((fp->f_flag & FWRITE) == 0) {
				error = EBADF;
				break;
			}
			PROC_LOCK(p);
			p->p_flag |= P_ADVLOCK;
			leaderp = p->p_leader;
			PROC_UNLOCK(p);
			error = VOP_ADVLOCK(vp, (caddr_t)leaderp, F_SETLK,
			    &fl, flg);
			break;
		case F_UNLCK:
			PROC_LOCK(p);
			leaderp = p->p_leader;
			PROC_UNLOCK(p);
			error = VOP_ADVLOCK(vp, (caddr_t)leaderp, F_UNLCK,
				&fl, F_POSIX);
			break;
		default:
			error = EINVAL;
			break;
		}
		fdrop(fp, td);
		break;

	case F_GETLK:
		if (fp->f_type != DTYPE_VNODE) {
			FILEDESC_UNLOCK(fdp);
			error = EBADF;
			break;
		}
		vp = (struct vnode *)fp->f_data;
		/*
		 * copyin/lockop may block
		 */
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		vp = (struct vnode *)fp->f_data;

		/* Copy in the lock structure */
		error = copyin((caddr_t)(intptr_t)uap->arg, (caddr_t)&fl,
		    sizeof(fl));
		if (error) {
			fdrop(fp, td);
			break;
		}
		if (fl.l_type != F_RDLCK && fl.l_type != F_WRLCK &&
		    fl.l_type != F_UNLCK) {
			fdrop(fp, td);
			error = EINVAL;
			break;
		}
		if (fl.l_whence == SEEK_CUR) {
			if ((fl.l_start > 0 &&
			     fp->f_offset > OFF_MAX - fl.l_start) ||
			    (fl.l_start < 0 &&
			     fp->f_offset < OFF_MIN - fl.l_start)) {
				fdrop(fp, td);
				error = EOVERFLOW;
				break;
			}
			fl.l_start += fp->f_offset;
		}
		error = VOP_ADVLOCK(vp, (caddr_t)p->p_leader, F_GETLK,
			    &fl, F_POSIX);
		fdrop(fp, td);
		if (error == 0) {
			error = copyout((caddr_t)&fl,
				    (caddr_t)(intptr_t)uap->arg, sizeof(fl));
		}
		break;
	default:
		FILEDESC_UNLOCK(fdp);
		error = EINVAL;
		break;
	}
done2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * Common code for dup, dup2, and fcntl(F_DUPFD).
 * filedesc must be locked, but will be unlocked as a side effect.
 */
static int
do_dup(fdp, old, new, retval, td)
	register struct filedesc *fdp;
	register int old, new;
	register_t *retval;
	struct thread *td;
{
	struct file *fp;
	struct file *delfp;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	/*
	 * Save info on the descriptor being overwritten.  We have
	 * to do the unmap now, but we cannot close it without
	 * introducing an ownership race for the slot.
	 */
	delfp = fdp->fd_ofiles[new];
#if 0
	if (delfp && (fdp->fd_ofileflags[new] & UF_MAPPED))
		(void) munmapfd(td, new);
#endif

	/*
	 * Duplicate the source descriptor, update lastfile
	 */
	fp = fdp->fd_ofiles[old];
	fdp->fd_ofiles[new] = fp;
	fdp->fd_ofileflags[new] = fdp->fd_ofileflags[old] &~ UF_EXCLOSE;
	fhold(fp);
	if (new > fdp->fd_lastfile)
		fdp->fd_lastfile = new;
	*retval = new;

	FILEDESC_UNLOCK(fdp);

	/*
	 * If we dup'd over a valid file, we now own the reference to it
	 * and must dispose of it using closef() semantics (as if a
	 * close() were performed on it).
	 */
	if (delfp) {
		mtx_lock(&Giant);
		(void) closef(delfp, td);
		mtx_unlock(&Giant);
	}
	return (0);
}

/*
 * If sigio is on the list associated with a process or process group,
 * disable signalling from the device, remove sigio from the list and
 * free sigio.
 */
void
funsetown(sigio)
	struct sigio *sigio;
{
	int s;

	if (sigio == NULL)
		return;

	s = splhigh();
	*(sigio->sio_myref) = NULL;
	splx(s);
	if ((sigio)->sio_pgid < 0) {
		struct pgrp *pg = (sigio)->sio_pgrp;
		PGRP_LOCK(pg);
		SLIST_REMOVE(&sigio->sio_pgrp->pg_sigiolst, sigio,
			     sigio, sio_pgsigio);
		PGRP_UNLOCK(pg);
	} else {
		struct proc *p = (sigio)->sio_proc;
		PROC_LOCK(p);
		SLIST_REMOVE(&sigio->sio_proc->p_sigiolst, sigio,
			     sigio, sio_pgsigio);
		PROC_UNLOCK(p);
	}
	crfree(sigio->sio_ucred);
	FREE(sigio, M_SIGIO);
}

/* Free a list of sigio structures. */
void
funsetownlst(sigiolst)
	struct sigiolst *sigiolst;
{
	int s;
	struct sigio *sigio;
	struct proc *p;
	struct pgrp *pg;

	sigio = SLIST_FIRST(sigiolst);
	if (sigio == NULL)
		return;

	p = NULL;
	pg = NULL;

	/*
	 * Every entry of the list should belong
	 * to a single proc or pgrp.
	 */
	if (sigio->sio_pgid < 0) {
		pg = sigio->sio_pgrp;
		PGRP_LOCK_ASSERT(pg, MA_OWNED);
	} else /* if (sigio->sio_pgid > 0) */ {
		p = sigio->sio_proc;
		PROC_LOCK_ASSERT(p, MA_OWNED);
	}

	while ((sigio = SLIST_FIRST(sigiolst)) != NULL) {
		s = splhigh();
		*(sigio->sio_myref) = NULL;
		splx(s);
		if (pg != NULL) {
			KASSERT(sigio->sio_pgid < 0, ("Proc sigio in pgrp sigio list"));
			KASSERT(sigio->sio_pgrp == pg, ("Bogus pgrp in sigio list"));
			SLIST_REMOVE(&pg->pg_sigiolst, sigio, sigio, sio_pgsigio);
			PGRP_UNLOCK(pg);
			crfree(sigio->sio_ucred);
			mtx_lock(&Giant);
			FREE(sigio, M_SIGIO);
			mtx_unlock(&Giant);
			PGRP_LOCK(pg);
		} else /* if (p != NULL) */ {
			KASSERT(sigio->sio_pgid > 0, ("Pgrp sigio in proc sigio list"));
			KASSERT(sigio->sio_proc == p, ("Bogus proc in sigio list"));
			SLIST_REMOVE(&p->p_sigiolst, sigio, sigio, sio_pgsigio);
			PROC_UNLOCK(p);
			crfree(sigio->sio_ucred);
			mtx_lock(&Giant);
			FREE(sigio, M_SIGIO);
			mtx_unlock(&Giant);
			PROC_LOCK(p);
		}
	}
}

/*
 * This is common code for FIOSETOWN ioctl called by fcntl(fd, F_SETOWN, arg).
 *
 * After permission checking, add a sigio structure to the sigio list for
 * the process or process group.
 */
int
fsetown(pgid, sigiop)
	pid_t pgid;
	struct sigio **sigiop;
{
	struct proc *proc;
	struct pgrp *pgrp;
	struct sigio *sigio;
	int s, ret;

	if (pgid == 0) {
		funsetown(*sigiop);
		return (0);
	}

	ret = 0;

	/* Allocate and fill in the new sigio out of locks. */
	MALLOC(sigio, struct sigio *, sizeof(struct sigio), M_SIGIO, M_WAITOK);
	sigio->sio_pgid = pgid;
	sigio->sio_ucred = crhold(curthread->td_ucred);
	sigio->sio_myref = sigiop;

	sx_slock(&proctree_lock);
	if (pgid > 0) {
		proc = pfind(pgid);
		if (proc == NULL) {
			ret = ESRCH;
			goto fail;
		}

		/*
		 * Policy - Don't allow a process to FSETOWN a process
		 * in another session.
		 *
		 * Remove this test to allow maximum flexibility or
		 * restrict FSETOWN to the current process or process
		 * group for maximum safety.
		 */
		PROC_UNLOCK(proc);
		if (proc->p_session != curthread->td_proc->p_session) {
			ret = EPERM;
			goto fail;
		}

		pgrp = NULL;
	} else /* if (pgid < 0) */ {
		pgrp = pgfind(-pgid);
		if (pgrp == NULL) {
			ret = ESRCH;
			goto fail;
		}
		PGRP_UNLOCK(pgrp);

		/*
		 * Policy - Don't allow a process to FSETOWN a process
		 * in another session.
		 *
		 * Remove this test to allow maximum flexibility or
		 * restrict FSETOWN to the current process or process
		 * group for maximum safety.
		 */
		if (pgrp->pg_session != curthread->td_proc->p_session) {
			ret = EPERM;
			goto fail;
		}

		proc = NULL;
	}
	funsetown(*sigiop);
	if (pgid > 0) {
		PROC_LOCK(proc);
		SLIST_INSERT_HEAD(&proc->p_sigiolst, sigio, sio_pgsigio);
		sigio->sio_proc = proc;
		PROC_UNLOCK(proc);
	} else {
		PGRP_LOCK(pgrp);
		SLIST_INSERT_HEAD(&pgrp->pg_sigiolst, sigio, sio_pgsigio);
		sigio->sio_pgrp = pgrp;
		PGRP_UNLOCK(pgrp);
	}
	sx_sunlock(&proctree_lock);
	s = splhigh();
	*sigiop = sigio;
	splx(s);
	return (0);

fail:
	sx_sunlock(&proctree_lock);
	crfree(sigio->sio_ucred);
	FREE(sigio, M_SIGIO);
	return (ret);
}

/*
 * This is common code for FIOGETOWN ioctl called by fcntl(fd, F_GETOWN, arg).
 */
pid_t
fgetown(sigio)
	struct sigio *sigio;
{
	return (sigio != NULL ? sigio->sio_pgid : 0);
}

/*
 * Close a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct close_args {
        int     fd;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
close(td, uap)
	struct thread *td;
	struct close_args *uap;
{
	register struct filedesc *fdp;
	register struct file *fp;
	register int fd = uap->fd;
	int error = 0;

	mtx_lock(&Giant);
	fdp = td->td_proc->p_fd;
	FILEDESC_LOCK(fdp);
	if ((unsigned)fd >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[fd]) == NULL) {
		FILEDESC_UNLOCK(fdp);
		error = EBADF;
		goto done2;
	}
#if 0
	if (fdp->fd_ofileflags[fd] & UF_MAPPED)
		(void) munmapfd(td, fd);
#endif
	fdp->fd_ofiles[fd] = NULL;
	fdp->fd_ofileflags[fd] = 0;

	/*
	 * we now hold the fp reference that used to be owned by the descriptor
	 * array.
	 */
	while (fdp->fd_lastfile > 0 && fdp->fd_ofiles[fdp->fd_lastfile] == NULL)
		fdp->fd_lastfile--;
	if (fd < fdp->fd_freefile)
		fdp->fd_freefile = fd;
	if (fd < fdp->fd_knlistsize) {
		FILEDESC_UNLOCK(fdp);
		knote_fdclose(td, fd);
	} else
		FILEDESC_UNLOCK(fdp);

	error = closef(fp, td);
done2:
	mtx_unlock(&Giant);
	return(error);
}

#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
/*
 * Return status information about a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct ofstat_args {
	int	fd;
	struct	ostat *sb;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
ofstat(td, uap)
	struct thread *td;
	register struct ofstat_args *uap;
{
	struct file *fp;
	struct stat ub;
	struct ostat oub;
	int error;

	mtx_lock(&Giant);
	if ((error = fget(td, uap->fd, &fp)) != 0)
		goto done2;
	error = fo_stat(fp, &ub, td);
	if (error == 0) {
		cvtstat(&ub, &oub);
		error = copyout((caddr_t)&oub, (caddr_t)uap->sb, sizeof (oub));
	}
	fdrop(fp, td);
done2:
	mtx_unlock(&Giant);
	return (error);
}
#endif /* COMPAT_43 || COMPAT_SUNOS */

/*
 * Return status information about a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fstat_args {
	int	fd;
	struct	stat *sb;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
fstat(td, uap)
	struct thread *td;
	struct fstat_args *uap;
{
	struct file *fp;
	struct stat ub;
	int error;

	mtx_lock(&Giant);
	if ((error = fget(td, uap->fd, &fp)) != 0)
		goto done2;
	error = fo_stat(fp, &ub, td);
	if (error == 0)
		error = copyout((caddr_t)&ub, (caddr_t)uap->sb, sizeof (ub));
	fdrop(fp, td);
done2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * Return status information about a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct nfstat_args {
	int	fd;
	struct	nstat *sb;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
nfstat(td, uap)
	struct thread *td;
	register struct nfstat_args *uap;
{
	struct file *fp;
	struct stat ub;
	struct nstat nub;
	int error;

	mtx_lock(&Giant);
	if ((error = fget(td, uap->fd, &fp)) != 0)
		goto done2;
	error = fo_stat(fp, &ub, td);
	if (error == 0) {
		cvtnstat(&ub, &nub);
		error = copyout((caddr_t)&nub, (caddr_t)uap->sb, sizeof (nub));
	}
	fdrop(fp, td);
done2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * Return pathconf information about a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fpathconf_args {
	int	fd;
	int	name;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
fpathconf(td, uap)
	struct thread *td;
	register struct fpathconf_args *uap;
{
	struct file *fp;
	struct vnode *vp;
	int error;

	if ((error = fget(td, uap->fd, &fp)) != 0)
		return (error);

	switch (fp->f_type) {
	case DTYPE_PIPE:
	case DTYPE_SOCKET:
		if (uap->name != _PC_PIPE_BUF) {
			error = EINVAL;
		} else {
			td->td_retval[0] = PIPE_BUF;
			error = 0;
		}
		break;
	case DTYPE_FIFO:
	case DTYPE_VNODE:
		vp = (struct vnode *)fp->f_data;
		mtx_lock(&Giant);
		error = VOP_PATHCONF(vp, uap->name, td->td_retval);
		mtx_unlock(&Giant);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	fdrop(fp, td);
	return(error);
}

/*
 * Allocate a file descriptor for the process.
 */
static int fdexpand;
SYSCTL_INT(_debug, OID_AUTO, fdexpand, CTLFLAG_RD, &fdexpand, 0, "");

int
fdalloc(td, want, result)
	struct thread *td;
	int want;
	int *result;
{
	struct proc *p = td->td_proc;
	register struct filedesc *fdp = td->td_proc->p_fd;
	register int i;
	int lim, last, nfiles;
	struct file **newofile, **oldofile;
	char *newofileflags;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	/*
	 * Search for a free descriptor starting at the higher
	 * of want or fd_freefile.  If that fails, consider
	 * expanding the ofile array.
	 */
	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfilesperproc);
	for (;;) {
		last = min(fdp->fd_nfiles, lim);
		if ((i = want) < fdp->fd_freefile)
			i = fdp->fd_freefile;
		for (; i < last; i++) {
			if (fdp->fd_ofiles[i] == NULL) {
				fdp->fd_ofileflags[i] = 0;
				if (i > fdp->fd_lastfile)
					fdp->fd_lastfile = i;
				if (want <= fdp->fd_freefile)
					fdp->fd_freefile = i;
				*result = i;
				return (0);
			}
		}

		/*
		 * No space in current array.  Expand?
		 */
		if (fdp->fd_nfiles >= lim)
			return (EMFILE);
		if (fdp->fd_nfiles < NDEXTENT)
			nfiles = NDEXTENT;
		else
			nfiles = 2 * fdp->fd_nfiles;
		FILEDESC_UNLOCK(fdp);
		mtx_lock(&Giant);
		MALLOC(newofile, struct file **, nfiles * OFILESIZE,
		    M_FILEDESC, M_WAITOK);
		mtx_unlock(&Giant);
		FILEDESC_LOCK(fdp);

		/*
		 * deal with file-table extend race that might have occured
		 * when malloc was blocked.
		 */
		if (fdp->fd_nfiles >= nfiles) {
			FILEDESC_UNLOCK(fdp);
			mtx_lock(&Giant);
			FREE(newofile, M_FILEDESC);
			mtx_unlock(&Giant);
			FILEDESC_LOCK(fdp);
			continue;
		}
		newofileflags = (char *) &newofile[nfiles];
		/*
		 * Copy the existing ofile and ofileflags arrays
		 * and zero the new portion of each array.
		 */
		bcopy(fdp->fd_ofiles, newofile,
			(i = sizeof(struct file *) * fdp->fd_nfiles));
		bzero((char *)newofile + i, nfiles * sizeof(struct file *) - i);
		bcopy(fdp->fd_ofileflags, newofileflags,
			(i = sizeof(char) * fdp->fd_nfiles));
		bzero(newofileflags + i, nfiles * sizeof(char) - i);
		if (fdp->fd_nfiles > NDFILE)
			oldofile = fdp->fd_ofiles;
		else
			oldofile = NULL;
		fdp->fd_ofiles = newofile;
		fdp->fd_ofileflags = newofileflags;
		fdp->fd_nfiles = nfiles;
		fdexpand++;
		if (oldofile != NULL) {
			FILEDESC_UNLOCK(fdp);
			mtx_lock(&Giant);
			FREE(oldofile, M_FILEDESC);
			mtx_unlock(&Giant);
			FILEDESC_LOCK(fdp);
		}
	}
	return (0);
}

/*
 * Check to see whether n user file descriptors
 * are available to the process p.
 */
int
fdavail(td, n)
	struct thread *td;
	register int n;
{
	struct proc *p = td->td_proc;
	register struct filedesc *fdp = td->td_proc->p_fd;
	register struct file **fpp;
	register int i, lim, last;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfilesperproc);
	if ((i = lim - fdp->fd_nfiles) > 0 && (n -= i) <= 0)
		return (1);

	last = min(fdp->fd_nfiles, lim);
	fpp = &fdp->fd_ofiles[fdp->fd_freefile];
	for (i = last - fdp->fd_freefile; --i >= 0; fpp++) {
		if (*fpp == NULL && --n <= 0)
			return (1);
	}
	return (0);
}

/*
 * Create a new open file structure and allocate
 * a file decriptor for the process that refers to it.
 */
int
falloc(td, resultfp, resultfd)
	register struct thread *td;
	struct file **resultfp;
	int *resultfd;
{
	struct proc *p = td->td_proc;
	register struct file *fp, *fq;
	int error, i;

	sx_xlock(&filelist_lock);
	if (nfiles >= maxfiles) {
		sx_xunlock(&filelist_lock);
		tablefull("file");
		return (ENFILE);
	}
	nfiles++;
	sx_xunlock(&filelist_lock);
	/*
	 * Allocate a new file descriptor.
	 * If the process has file descriptor zero open, add to the list
	 * of open files at that point, otherwise put it at the front of
	 * the list of open files.
	 */
	fp = uma_zalloc(file_zone, M_WAITOK);
	bzero(fp, sizeof(*fp));

	/*
	 * wait until after malloc (which may have blocked) returns before
	 * allocating the slot, else a race might have shrunk it if we had
	 * allocated it before the malloc.
	 */
	FILEDESC_LOCK(p->p_fd);
	if ((error = fdalloc(td, 0, &i))) {
		FILEDESC_UNLOCK(p->p_fd);
		sx_xlock(&filelist_lock);
		nfiles--;
		sx_xunlock(&filelist_lock);
		uma_zfree(file_zone, fp);
		return (error);
	}
	fp->f_mtxp = mtx_pool_alloc();
	fp->f_gcflag = 0;
	fp->f_count = 1;
	fp->f_cred = crhold(td->td_ucred);
	fp->f_ops = &badfileops;
	fp->f_seqcount = 1;
	FILEDESC_UNLOCK(p->p_fd);
	sx_xlock(&filelist_lock);
	FILEDESC_LOCK(p->p_fd);
	if ((fq = p->p_fd->fd_ofiles[0])) {
		LIST_INSERT_AFTER(fq, fp, f_list);
	} else {
		LIST_INSERT_HEAD(&filehead, fp, f_list);
	}
	p->p_fd->fd_ofiles[i] = fp;
	FILEDESC_UNLOCK(p->p_fd);
	sx_xunlock(&filelist_lock);
	if (resultfp)
		*resultfp = fp;
	if (resultfd)
		*resultfd = i;
	return (0);
}

/*
 * Free a file descriptor.
 */
void
ffree(fp)
	register struct file *fp;
{

	KASSERT((fp->f_count == 0), ("ffree: fp_fcount not 0!"));
	sx_xlock(&filelist_lock);
	LIST_REMOVE(fp, f_list);
	nfiles--;
	sx_xunlock(&filelist_lock);
	crfree(fp->f_cred);
	uma_zfree(file_zone, fp);
}

/*
 * Build a new filedesc structure.
 */
struct filedesc *
fdinit(td)
	struct thread *td;
{
	register struct filedesc0 *newfdp;
	register struct filedesc *fdp = td->td_proc->p_fd;

	MALLOC(newfdp, struct filedesc0 *, sizeof(struct filedesc0),
	    M_FILEDESC, M_WAITOK | M_ZERO);
	mtx_init(&newfdp->fd_fd.fd_mtx, FILEDESC_LOCK_DESC, NULL, MTX_DEF);
	FILEDESC_LOCK(&newfdp->fd_fd);
	newfdp->fd_fd.fd_cdir = fdp->fd_cdir;
	if (newfdp->fd_fd.fd_cdir)
		VREF(newfdp->fd_fd.fd_cdir);
	newfdp->fd_fd.fd_rdir = fdp->fd_rdir;
	if (newfdp->fd_fd.fd_rdir)
		VREF(newfdp->fd_fd.fd_rdir);
	newfdp->fd_fd.fd_jdir = fdp->fd_jdir;
	if (newfdp->fd_fd.fd_jdir)
		VREF(newfdp->fd_fd.fd_jdir);

	/* Create the file descriptor table. */
	newfdp->fd_fd.fd_refcnt = 1;
	newfdp->fd_fd.fd_cmask = cmask;
	newfdp->fd_fd.fd_ofiles = newfdp->fd_dfiles;
	newfdp->fd_fd.fd_ofileflags = newfdp->fd_dfileflags;
	newfdp->fd_fd.fd_nfiles = NDFILE;
	newfdp->fd_fd.fd_knlistsize = -1;
	FILEDESC_UNLOCK(&newfdp->fd_fd);

	return (&newfdp->fd_fd);
}

/*
 * Share a filedesc structure.
 */
struct filedesc *
fdshare(p)
	struct proc *p;
{
	FILEDESC_LOCK(p->p_fd);
	p->p_fd->fd_refcnt++;
	FILEDESC_UNLOCK(p->p_fd);
	return (p->p_fd);
}

/*
 * Copy a filedesc structure.
 */
struct filedesc *
fdcopy(td)
	struct thread *td;
{
	register struct filedesc *newfdp, *fdp = td->td_proc->p_fd;
	register struct file **fpp;
	register int i, j;

	/* Certain daemons might not have file descriptors. */
	if (fdp == NULL)
		return (NULL);

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	FILEDESC_UNLOCK(fdp);
	MALLOC(newfdp, struct filedesc *, sizeof(struct filedesc0),
	    M_FILEDESC, M_WAITOK);
	FILEDESC_LOCK(fdp);
	bcopy(fdp, newfdp, sizeof(struct filedesc));
	FILEDESC_UNLOCK(fdp);
	bzero(&newfdp->fd_mtx, sizeof(newfdp->fd_mtx));
	mtx_init(&newfdp->fd_mtx, FILEDESC_LOCK_DESC, NULL, MTX_DEF);
	if (newfdp->fd_cdir)
		VREF(newfdp->fd_cdir);
	if (newfdp->fd_rdir)
		VREF(newfdp->fd_rdir);
	if (newfdp->fd_jdir)
		VREF(newfdp->fd_jdir);
	newfdp->fd_refcnt = 1;

	/*
	 * If the number of open files fits in the internal arrays
	 * of the open file structure, use them, otherwise allocate
	 * additional memory for the number of descriptors currently
	 * in use.
	 */
	FILEDESC_LOCK(fdp);
	newfdp->fd_lastfile = fdp->fd_lastfile;
	newfdp->fd_nfiles = fdp->fd_nfiles;
	if (newfdp->fd_lastfile < NDFILE) {
		newfdp->fd_ofiles = ((struct filedesc0 *) newfdp)->fd_dfiles;
		newfdp->fd_ofileflags =
		    ((struct filedesc0 *) newfdp)->fd_dfileflags;
		i = NDFILE;
	} else {
		/*
		 * Compute the smallest multiple of NDEXTENT needed
		 * for the file descriptors currently in use,
		 * allowing the table to shrink.
		 */
retry:
		i = newfdp->fd_nfiles;
		while (i > 2 * NDEXTENT && i > newfdp->fd_lastfile * 2)
			i /= 2;
		FILEDESC_UNLOCK(fdp);
		MALLOC(newfdp->fd_ofiles, struct file **, i * OFILESIZE,
		    M_FILEDESC, M_WAITOK);
		FILEDESC_LOCK(fdp);
		newfdp->fd_lastfile = fdp->fd_lastfile;
		newfdp->fd_nfiles = fdp->fd_nfiles;
		j = newfdp->fd_nfiles;
		while (j > 2 * NDEXTENT && j > newfdp->fd_lastfile * 2)
			j /= 2;
		if (i != j) {
			/*
			 * The size of the original table has changed.
			 * Go over once again.
			 */
			FILEDESC_UNLOCK(fdp);
			FREE(newfdp->fd_ofiles, M_FILEDESC);
			FILEDESC_LOCK(fdp);
			newfdp->fd_lastfile = fdp->fd_lastfile;
			newfdp->fd_nfiles = fdp->fd_nfiles;
			goto retry;
		}
		newfdp->fd_ofileflags = (char *) &newfdp->fd_ofiles[i];
	}
	newfdp->fd_nfiles = i;
	bcopy(fdp->fd_ofiles, newfdp->fd_ofiles, i * sizeof(struct file **));
	bcopy(fdp->fd_ofileflags, newfdp->fd_ofileflags, i * sizeof(char));

	/*
	 * kq descriptors cannot be copied.
	 */
	if (newfdp->fd_knlistsize != -1) {
		fpp = &newfdp->fd_ofiles[newfdp->fd_lastfile];
		for (i = newfdp->fd_lastfile; i >= 0; i--, fpp--) {
			if (*fpp != NULL && (*fpp)->f_type == DTYPE_KQUEUE) {
				*fpp = NULL;
				if (i < newfdp->fd_freefile)
					newfdp->fd_freefile = i;
			}
			if (*fpp == NULL && i == newfdp->fd_lastfile && i > 0)
				newfdp->fd_lastfile--;
		}
		newfdp->fd_knlist = NULL;
		newfdp->fd_knlistsize = -1;
		newfdp->fd_knhash = NULL;
		newfdp->fd_knhashmask = 0;
	}

	fpp = newfdp->fd_ofiles;
	for (i = newfdp->fd_lastfile; i-- >= 0; fpp++) {
		if (*fpp != NULL) {
			fhold(*fpp);
		}
	}
	return (newfdp);
}

/*
 * Release a filedesc structure.
 */
void
fdfree(td)
	struct thread *td;
{
	register struct filedesc *fdp;
	struct file **fpp;
	register int i;

	fdp = td->td_proc->p_fd;
	/* Certain daemons might not have file descriptors. */
	if (fdp == NULL)
		return;

	FILEDESC_LOCK(fdp);
	if (--fdp->fd_refcnt > 0) {
		FILEDESC_UNLOCK(fdp);
		return;
	}
	/*
	 * we are the last reference to the structure, we can
	 * safely assume it will not change out from under us.
	 */
	FILEDESC_UNLOCK(fdp);
	fpp = fdp->fd_ofiles;
	for (i = fdp->fd_lastfile; i-- >= 0; fpp++) {
		if (*fpp)
			(void) closef(*fpp, td);
	}

	PROC_LOCK(td->td_proc);
	td->td_proc->p_fd = NULL;
	PROC_UNLOCK(td->td_proc);

	if (fdp->fd_nfiles > NDFILE)
		FREE(fdp->fd_ofiles, M_FILEDESC);
	if (fdp->fd_cdir)
		vrele(fdp->fd_cdir);
	if (fdp->fd_rdir)
		vrele(fdp->fd_rdir);
	if (fdp->fd_jdir)
		vrele(fdp->fd_jdir);
	if (fdp->fd_knlist)
		FREE(fdp->fd_knlist, M_KQUEUE);
	if (fdp->fd_knhash)
		FREE(fdp->fd_knhash, M_KQUEUE);
	mtx_destroy(&fdp->fd_mtx);
	FREE(fdp, M_FILEDESC);
}

/*
 * For setugid programs, we don't want to people to use that setugidness
 * to generate error messages which write to a file which otherwise would
 * otherwise be off-limits to the process.
 *
 * This is a gross hack to plug the hole.  A better solution would involve
 * a special vop or other form of generalized access control mechanism.  We
 * go ahead and just reject all procfs file systems accesses as dangerous.
 *
 * Since setugidsafety calls this only for fd 0, 1 and 2, this check is
 * sufficient.  We also don't for check setugidness since we know we are.
 */
static int
is_unsafe(struct file *fp)
{
	if (fp->f_type == DTYPE_VNODE && 
	    ((struct vnode *)(fp->f_data))->v_tag == VT_PROCFS)
		return (1);
	return (0);
}

/*
 * Make this setguid thing safe, if at all possible.
 */
void
setugidsafety(td)
	struct thread *td;
{
	struct filedesc *fdp = td->td_proc->p_fd;
	register int i;

	/* Certain daemons might not have file descriptors. */
	if (fdp == NULL)
		return;

	/*
	 * note: fdp->fd_ofiles may be reallocated out from under us while
	 * we are blocked in a close.  Be careful!
	 */
	FILEDESC_LOCK(fdp);
	for (i = 0; i <= fdp->fd_lastfile; i++) {
		if (i > 2)
			break;
		if (fdp->fd_ofiles[i] && is_unsafe(fdp->fd_ofiles[i])) {
			struct file *fp;

#if 0
			if ((fdp->fd_ofileflags[i] & UF_MAPPED) != 0)
				(void) munmapfd(td, i);
#endif
			if (i < fdp->fd_knlistsize) {
				FILEDESC_UNLOCK(fdp);
				knote_fdclose(td, i);
				FILEDESC_LOCK(fdp);
			}
			/*
			 * NULL-out descriptor prior to close to avoid
			 * a race while close blocks.
			 */
			fp = fdp->fd_ofiles[i];
			fdp->fd_ofiles[i] = NULL;
			fdp->fd_ofileflags[i] = 0;
			if (i < fdp->fd_freefile)
				fdp->fd_freefile = i;
			FILEDESC_UNLOCK(fdp);
			(void) closef(fp, td);
			FILEDESC_LOCK(fdp);
		}
	}
	while (fdp->fd_lastfile > 0 && fdp->fd_ofiles[fdp->fd_lastfile] == NULL)
		fdp->fd_lastfile--;
	FILEDESC_UNLOCK(fdp);
}

/*
 * Close any files on exec?
 */
void
fdcloseexec(td)
	struct thread *td;
{
	struct filedesc *fdp = td->td_proc->p_fd;
	register int i;

	/* Certain daemons might not have file descriptors. */
	if (fdp == NULL)
		return;

	FILEDESC_LOCK(fdp);

	/*
	 * We cannot cache fd_ofiles or fd_ofileflags since operations
	 * may block and rip them out from under us.
	 */
	for (i = 0; i <= fdp->fd_lastfile; i++) {
		if (fdp->fd_ofiles[i] != NULL &&
		    (fdp->fd_ofileflags[i] & UF_EXCLOSE)) {
			struct file *fp;

#if 0
			if (fdp->fd_ofileflags[i] & UF_MAPPED)
				(void) munmapfd(td, i);
#endif
			if (i < fdp->fd_knlistsize) {
				FILEDESC_UNLOCK(fdp);
				knote_fdclose(td, i);
				FILEDESC_LOCK(fdp);
			}
			/*
			 * NULL-out descriptor prior to close to avoid
			 * a race while close blocks.
			 */
			fp = fdp->fd_ofiles[i];
			fdp->fd_ofiles[i] = NULL;
			fdp->fd_ofileflags[i] = 0;
			if (i < fdp->fd_freefile)
				fdp->fd_freefile = i;
			FILEDESC_UNLOCK(fdp);
			(void) closef(fp, td);
			FILEDESC_LOCK(fdp);
		}
	}
	while (fdp->fd_lastfile > 0 && fdp->fd_ofiles[fdp->fd_lastfile] == NULL)
		fdp->fd_lastfile--;
	FILEDESC_UNLOCK(fdp);
}

/*
 * It is unsafe for set[ug]id processes to be started with file
 * descriptors 0..2 closed, as these descriptors are given implicit
 * significance in the Standard C library.  fdcheckstd() will create a
 * descriptor referencing /dev/null for each of stdin, stdout, and
 * stderr that is not already open.
 */
int
fdcheckstd(td)
	struct thread *td;
{
	struct nameidata nd;
	struct filedesc *fdp;
	struct file *fp;
	register_t retval;
	int fd, i, error, flags, devnull;

	fdp = td->td_proc->p_fd;
	if (fdp == NULL)
		return (0);
	devnull = -1;
	error = 0;
	for (i = 0; i < 3; i++) {
		if (fdp->fd_ofiles[i] != NULL)
			continue;
		if (devnull < 0) {
			error = falloc(td, &fp, &fd);
			if (error != 0)
				break;
			NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, "/dev/null",
			    td);
			flags = FREAD | FWRITE;
			error = vn_open(&nd, &flags, 0);
			if (error != 0) {
				FILEDESC_LOCK(fdp);
				fdp->fd_ofiles[i] = NULL;
				FILEDESC_UNLOCK(fdp);
				fdrop(fp, td);
				break;
			}
			NDFREE(&nd, NDF_ONLY_PNBUF);
			fp->f_data = (caddr_t)nd.ni_vp;
			fp->f_flag = flags;
			fp->f_ops = &vnops;
			fp->f_type = DTYPE_VNODE;
			VOP_UNLOCK(nd.ni_vp, 0, td);
			devnull = fd;
		} else {
			FILEDESC_LOCK(fdp);
			error = fdalloc(td, 0, &fd);
			if (error != 0) {
				FILEDESC_UNLOCK(fdp);
				break;
			}
			error = do_dup(fdp, devnull, fd, &retval, td);
			if (error != 0)
				break;
		}
	}
	return (error);
}

/*
 * Internal form of close.
 * Decrement reference count on file structure.
 * Note: td may be NULL when closing a file
 * that was being passed in a message.
 */
int
closef(fp, td)
	register struct file *fp;
	register struct thread *td;
{
	struct vnode *vp;
	struct flock lf;

	if (fp == NULL)
		return (0);
	/*
	 * POSIX record locking dictates that any close releases ALL
	 * locks owned by this process.  This is handled by setting
	 * a flag in the unlock to free ONLY locks obeying POSIX
	 * semantics, and not to free BSD-style file locks.
	 * If the descriptor was in a message, POSIX-style locks
	 * aren't passed with the descriptor.
	 */
	if (td && (td->td_proc->p_flag & P_ADVLOCK) &&
	    fp->f_type == DTYPE_VNODE) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fp->f_data;
		(void) VOP_ADVLOCK(vp, (caddr_t)td->td_proc->p_leader,
		    F_UNLCK, &lf, F_POSIX);
	}
	return (fdrop(fp, td));
}

/*
 * Drop reference on struct file passed in, may call closef if the
 * reference hits zero.
 */
int
fdrop(fp, td)
	struct file *fp;
	struct thread *td;
{

	FILE_LOCK(fp);
	return (fdrop_locked(fp, td));
}

/*
 * Extract the file pointer associated with the specified descriptor for
 * the current user process.
 *
 * If the descriptor doesn't exist, EBADF is returned.
 *
 * If the descriptor exists but doesn't match 'flags' then
 * return EBADF for read attempts and EINVAL for write attempts.
 *
 * If 'hold' is set (non-zero) the file's refcount will be bumped on return.
 * It should be droped with fdrop().
 * If it is not set, then the refcount will not be bumped however the
 * thread's filedesc struct will be returned locked (for fgetsock).
 *
 * If an error occured the non-zero error is returned and *fpp is set to NULL.
 * Otherwise *fpp is set and zero is returned.
 */
static __inline
int
_fget(struct thread *td, int fd, struct file **fpp, int flags, int hold)
{
	struct filedesc *fdp;
	struct file *fp;

	*fpp = NULL;
	if (td == NULL || (fdp = td->td_proc->p_fd) == NULL)
		return(EBADF);
	FILEDESC_LOCK(fdp);
	if ((fp = fget_locked(fdp, fd)) == NULL || fp->f_ops == &badfileops) {
		FILEDESC_UNLOCK(fdp);
		return(EBADF);
	}

	/*
	 * Note: FREAD failures returns EBADF to maintain backwards
	 * compatibility with what routines returned before.
	 *
	 * Only one flag, or 0, may be specified.
	 */
	if (flags == FREAD && (fp->f_flag & FREAD) == 0) {
		FILEDESC_UNLOCK(fdp);
		return(EBADF);
	}
	if (flags == FWRITE && (fp->f_flag & FWRITE) == 0) {
		FILEDESC_UNLOCK(fdp);
		return(EINVAL);
	}
	if (hold) {
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
	}
	*fpp = fp;
	return(0);
}

int
fget(struct thread *td, int fd, struct file **fpp)
{
    return(_fget(td, fd, fpp, 0, 1));
}

int
fget_read(struct thread *td, int fd, struct file **fpp)
{
    return(_fget(td, fd, fpp, FREAD, 1));
}

int
fget_write(struct thread *td, int fd, struct file **fpp)
{
    return(_fget(td, fd, fpp, FWRITE, 1));
}

/*
 * Like fget() but loads the underlying vnode, or returns an error if
 * the descriptor does not represent a vnode.  Note that pipes use vnodes
 * but never have VM objects (so VOP_GETVOBJECT() calls will return an
 * error).  The returned vnode will be vref()d.
 */

static __inline
int
_fgetvp(struct thread *td, int fd, struct vnode **vpp, int flags)
{
	struct file *fp;
	int error;

	*vpp = NULL;
	if ((error = _fget(td, fd, &fp, 0, 0)) != 0)
		return (error);
	if (fp->f_type != DTYPE_VNODE && fp->f_type != DTYPE_FIFO) {
		error = EINVAL;
	} else {
		*vpp = (struct vnode *)fp->f_data;
		vref(*vpp);
	}
	FILEDESC_UNLOCK(td->td_proc->p_fd);
	return (error);
}

int
fgetvp(struct thread *td, int fd, struct vnode **vpp)
{
	return(_fgetvp(td, fd, vpp, 0));
}

int
fgetvp_read(struct thread *td, int fd, struct vnode **vpp)
{
	return(_fgetvp(td, fd, vpp, FREAD));
}

int
fgetvp_write(struct thread *td, int fd, struct vnode **vpp)
{
	return(_fgetvp(td, fd, vpp, FWRITE));
}

/*
 * Like fget() but loads the underlying socket, or returns an error if
 * the descriptor does not represent a socket.
 *
 * We bump the ref count on the returned socket.  XXX Also obtain the SX lock in
 * the future.
 */
int
fgetsock(struct thread *td, int fd, struct socket **spp, u_int *fflagp)
{
	struct file *fp;
	int error;

	*spp = NULL;
	if (fflagp)
		*fflagp = 0;
	if ((error = _fget(td, fd, &fp, 0, 0)) != 0)
		return (error);
	if (fp->f_type != DTYPE_SOCKET) {
		error = ENOTSOCK;
	} else {
		*spp = (struct socket *)fp->f_data;
		if (fflagp)
			*fflagp = fp->f_flag;
		soref(*spp);
	}
	FILEDESC_UNLOCK(td->td_proc->p_fd);
	return(error);
}

/*
 * Drop the reference count on the the socket and XXX release the SX lock in
 * the future.  The last reference closes the socket.
 */
void
fputsock(struct socket *so)
{
	sorele(so);
}

/*
 * Drop reference on struct file passed in, may call closef if the
 * reference hits zero.
 * Expects struct file locked, and will unlock it.
 */
int
fdrop_locked(fp, td)
	struct file *fp;
	struct thread *td;
{
	struct flock lf;
	struct vnode *vp;
	int error;

	FILE_LOCK_ASSERT(fp, MA_OWNED);

	if (--fp->f_count > 0) {
		FILE_UNLOCK(fp);
		return (0);
	}
	mtx_lock(&Giant);
	if (fp->f_count < 0)
		panic("fdrop: count < 0");
	if ((fp->f_flag & FHASLOCK) && fp->f_type == DTYPE_VNODE) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fp->f_data;
		FILE_UNLOCK(fp);
		(void) VOP_ADVLOCK(vp, (caddr_t)fp, F_UNLCK, &lf, F_FLOCK);
	} else
		FILE_UNLOCK(fp);
	if (fp->f_ops != &badfileops)
		error = fo_close(fp, td);
	else
		error = 0;
	ffree(fp);
	mtx_unlock(&Giant);
	return (error);
}

/*
 * Apply an advisory lock on a file descriptor.
 *
 * Just attempt to get a record lock of the requested type on
 * the entire file (l_whence = SEEK_SET, l_start = 0, l_len = 0).
 */
#ifndef _SYS_SYSPROTO_H_
struct flock_args {
	int	fd;
	int	how;
};
#endif
/*
 * MPSAFE
 */
/* ARGSUSED */
int
flock(td, uap)
	struct thread *td;
	register struct flock_args *uap;
{
	struct file *fp;
	struct vnode *vp;
	struct flock lf;
	int error;

	if ((error = fget(td, uap->fd, &fp)) != 0)
		return (error);
	if (fp->f_type != DTYPE_VNODE) {
		fdrop(fp, td);
		return (EOPNOTSUPP);
	}

	mtx_lock(&Giant);
	vp = (struct vnode *)fp->f_data;
	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	if (uap->how & LOCK_UN) {
		lf.l_type = F_UNLCK;
		FILE_LOCK(fp);
		fp->f_flag &= ~FHASLOCK;
		FILE_UNLOCK(fp);
		error = VOP_ADVLOCK(vp, (caddr_t)fp, F_UNLCK, &lf, F_FLOCK);
		goto done2;
	}
	if (uap->how & LOCK_EX)
		lf.l_type = F_WRLCK;
	else if (uap->how & LOCK_SH)
		lf.l_type = F_RDLCK;
	else {
		error = EBADF;
		goto done2;
	}
	FILE_LOCK(fp);
	fp->f_flag |= FHASLOCK;
	FILE_UNLOCK(fp);
	error = VOP_ADVLOCK(vp, (caddr_t)fp, F_SETLK, &lf,
	    (uap->how & LOCK_NB) ? F_FLOCK : F_FLOCK | F_WAIT);
done2:
	fdrop(fp, td);
	mtx_unlock(&Giant);
	return (error);
}

/*
 * File Descriptor pseudo-device driver (/dev/fd/).
 *
 * Opening minor device N dup()s the file (if any) connected to file
 * descriptor N belonging to the calling process.  Note that this driver
 * consists of only the ``open()'' routine, because all subsequent
 * references to this file will be direct to the other driver.
 */
/* ARGSUSED */
static int
fdopen(dev, mode, type, td)
	dev_t dev;
	int mode, type;
	struct thread *td;
{

	/*
	 * XXX Kludge: set curthread->td_dupfd to contain the value of the
	 * the file descriptor being sought for duplication. The error
	 * return ensures that the vnode for this device will be released
	 * by vn_open. Open will detect this special error and take the
	 * actions in dupfdopen below. Other callers of vn_open or VOP_OPEN
	 * will simply report the error.
	 */
	td->td_dupfd = dev2unit(dev);
	return (ENODEV);
}

/*
 * Duplicate the specified descriptor to a free descriptor.
 */
int
dupfdopen(td, fdp, indx, dfd, mode, error)
	struct thread *td;
	struct filedesc *fdp;
	int indx, dfd;
	int mode;
	int error;
{
	register struct file *wfp;
	struct file *fp;

	/*
	 * If the to-be-dup'd fd number is greater than the allowed number
	 * of file descriptors, or the fd to be dup'd has already been
	 * closed, then reject.
	 */
	FILEDESC_LOCK(fdp);
	if ((u_int)dfd >= fdp->fd_nfiles ||
	    (wfp = fdp->fd_ofiles[dfd]) == NULL) {
		FILEDESC_UNLOCK(fdp);
		return (EBADF);
	}

	/*
	 * There are two cases of interest here.
	 *
	 * For ENODEV simply dup (dfd) to file descriptor
	 * (indx) and return.
	 *
	 * For ENXIO steal away the file structure from (dfd) and
	 * store it in (indx).  (dfd) is effectively closed by
	 * this operation.
	 *
	 * Any other error code is just returned.
	 */
	switch (error) {
	case ENODEV:
		/*
		 * Check that the mode the file is being opened for is a
		 * subset of the mode of the existing descriptor.
		 */
		FILE_LOCK(wfp);
		if (((mode & (FREAD|FWRITE)) | wfp->f_flag) != wfp->f_flag) {
			FILE_UNLOCK(wfp);
			FILEDESC_UNLOCK(fdp);
			return (EACCES);
		}
		fp = fdp->fd_ofiles[indx];
#if 0
		if (fp && fdp->fd_ofileflags[indx] & UF_MAPPED)
			(void) munmapfd(td, indx);
#endif
		fdp->fd_ofiles[indx] = wfp;
		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		fhold_locked(wfp);
		FILE_UNLOCK(wfp);
		if (indx > fdp->fd_lastfile)
			fdp->fd_lastfile = indx;
		if (fp != NULL)
			FILE_LOCK(fp);
		FILEDESC_UNLOCK(fdp);
		/*
		 * we now own the reference to fp that the ofiles[] array
		 * used to own.  Release it.
		 */
		if (fp != NULL)
			fdrop_locked(fp, td);
		return (0);

	case ENXIO:
		/*
		 * Steal away the file pointer from dfd, and stuff it into indx.
		 */
		fp = fdp->fd_ofiles[indx];
#if 0
		if (fp && fdp->fd_ofileflags[indx] & UF_MAPPED)
			(void) munmapfd(td, indx);
#endif
		fdp->fd_ofiles[indx] = fdp->fd_ofiles[dfd];
		fdp->fd_ofiles[dfd] = NULL;
		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		fdp->fd_ofileflags[dfd] = 0;

		/*
		 * Complete the clean up of the filedesc structure by
		 * recomputing the various hints.
		 */
		if (indx > fdp->fd_lastfile) {
			fdp->fd_lastfile = indx;
		} else {
			while (fdp->fd_lastfile > 0 &&
			   fdp->fd_ofiles[fdp->fd_lastfile] == NULL) {
				fdp->fd_lastfile--;
			}
			if (dfd < fdp->fd_freefile)
				fdp->fd_freefile = dfd;
		}
		if (fp != NULL)
			FILE_LOCK(fp);
		FILEDESC_UNLOCK(fdp);

		/*
		 * we now own the reference to fp that the ofiles[] array
		 * used to own.  Release it.
		 */
		if (fp != NULL)
			fdrop_locked(fp, td);
		return (0);

	default:
		FILEDESC_UNLOCK(fdp);
		return (error);
	}
	/* NOTREACHED */
}

/*
 * Get file structures.
 */
static int
sysctl_kern_file(SYSCTL_HANDLER_ARGS)
{
	int error;
	struct file *fp;

	sx_slock(&filelist_lock);
	if (!req->oldptr) {
		/*
		 * overestimate by 10 files
		 */
		error = SYSCTL_OUT(req, 0, sizeof(filehead) + 
				   (nfiles + 10) * sizeof(struct file));
		sx_sunlock(&filelist_lock);
		return (error);
	}

	error = SYSCTL_OUT(req, (caddr_t)&filehead, sizeof(filehead));
	if (error) {
		sx_sunlock(&filelist_lock);
		return (error);
	}

	/*
	 * followed by an array of file structures
	 */
	LIST_FOREACH(fp, &filehead, f_list) {
		error = SYSCTL_OUT(req, (caddr_t)fp, sizeof (struct file));
		if (error) {
			sx_sunlock(&filelist_lock);
			return (error);
		}
	}
	sx_sunlock(&filelist_lock);
	return (0);
}

SYSCTL_PROC(_kern, KERN_FILE, file, CTLTYPE_OPAQUE|CTLFLAG_RD,
    0, 0, sysctl_kern_file, "S,file", "Entire file table");

SYSCTL_INT(_kern, KERN_MAXFILESPERPROC, maxfilesperproc, CTLFLAG_RW, 
    &maxfilesperproc, 0, "Maximum files allowed open per process");

SYSCTL_INT(_kern, KERN_MAXFILES, maxfiles, CTLFLAG_RW, 
    &maxfiles, 0, "Maximum number of files");

SYSCTL_INT(_kern, OID_AUTO, openfiles, CTLFLAG_RD, 
    &nfiles, 0, "System-wide number of open files");

static void
fildesc_drvinit(void *unused)
{
	dev_t dev;

	dev = make_dev(&fildesc_cdevsw, 0, UID_BIN, GID_BIN, 0666, "fd/0");
	make_dev_alias(dev, "stdin");
	dev = make_dev(&fildesc_cdevsw, 1, UID_BIN, GID_BIN, 0666, "fd/1");
	make_dev_alias(dev, "stdout");
	dev = make_dev(&fildesc_cdevsw, 2, UID_BIN, GID_BIN, 0666, "fd/2");
	make_dev_alias(dev, "stderr");
	if (!devfs_present) {
		int fd;

		for (fd = 3; fd < NUMFDESC; fd++)
			make_dev(&fildesc_cdevsw, fd, UID_BIN, GID_BIN, 0666,
			    "fd/%d", fd);
	}
}

struct fileops badfileops = {
	badfo_readwrite,
	badfo_readwrite,
	badfo_ioctl,
	badfo_poll,
	badfo_kqfilter,
	badfo_stat,
	badfo_close
};

static int
badfo_readwrite(fp, uio, cred, flags, td)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	struct thread *td;
	int flags;
{

	return (EBADF);
}

static int
badfo_ioctl(fp, com, data, td)
	struct file *fp;
	u_long com;
	caddr_t data;
	struct thread *td;
{

	return (EBADF);
}

static int
badfo_poll(fp, events, cred, td)
	struct file *fp;
	int events;
	struct ucred *cred;
	struct thread *td;
{

	return (0);
}

static int
badfo_kqfilter(fp, kn)
	struct file *fp;
	struct knote *kn;
{

	return (0);
}

static int
badfo_stat(fp, sb, td)
	struct file *fp;
	struct stat *sb;
	struct thread *td;
{

	return (EBADF);
}

static int
badfo_close(fp, td)
	struct file *fp;
	struct thread *td;
{

	return (EBADF);
}

SYSINIT(fildescdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,
					fildesc_drvinit,NULL)

static void filelistinit(void *);
SYSINIT(select, SI_SUB_LOCK, SI_ORDER_FIRST, filelistinit, NULL)

/* ARGSUSED*/
static void
filelistinit(dummy)
	void *dummy;
{
	file_zone = uma_zcreate("Files", sizeof(struct file), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, 0);

	sx_init(&filelist_lock, "filelist lock");
	sx_init(&sigio_lock, "sigio lock");
}
