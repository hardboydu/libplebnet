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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/systm.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/conf.h>
#include <sys/filedesc.h>
#include <sys/lock.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/mount.h>
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
#include <sys/signalvar.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

static MALLOC_DEFINE(M_FILEDESC, "file desc", "Open file descriptor table");
static MALLOC_DEFINE(M_FILEDESC_TO_LEADER, "file desc to leader",
		     "file desc to leader structures");
static MALLOC_DEFINE(M_SIGIO, "sigio", "sigio structures");

static uma_zone_t file_zone;

static	 d_open_t  fdopen;
#define	NUMFDESC 64

#define	CDEV_MAJOR 22
static struct cdevsw fildesc_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_NEEDGIANT,
	.d_open =	fdopen,
	.d_name =	"FD",
	.d_maj =	CDEV_MAJOR,
};

/* How to treat 'new' parameter when allocating a fd for do_dup(). */
enum dup_type { DUP_VARIABLE, DUP_FIXED };

static int do_dup(struct thread *td, enum dup_type type, int old, int new,
    register_t *retval);
static int	fd_first_free(struct filedesc *, int, int);
static int	fd_last_used(struct filedesc *, int, int);
static void	fdgrowtable(struct filedesc *, int);

/*
 * Descriptor management.
 */
struct filelist filehead;	/* head of list of open files */
int nfiles;			/* actual number of open files */
struct sx filelist_lock;	/* sx to protect filelist */
struct mtx sigio_lock;		/* mtx to protect pointers to sigio */

/*
 * Find the first zero bit in the given bitmap, starting at low and not
 * exceeding size - 1.
 */
static int
fd_first_free(struct filedesc *fdp, int low, int size)
{
	NDSLOTTYPE *map = fdp->fd_map;
	NDSLOTTYPE mask;
	int off, maxoff;

	if (low >= size)
		return (low);

	off = NDSLOT(low);
	if (low % NDENTRIES) {
		mask = ~(~(NDSLOTTYPE)0 >> (NDENTRIES - (low % NDENTRIES)));
		if ((mask &= ~map[off]) != 0UL)
			return (off * NDENTRIES + ffsl(mask) - 1);
		++off;
	}
	for (maxoff = NDSLOTS(size); off < maxoff; ++off)
		if (map[off] != ~0UL)
			return (off * NDENTRIES + ffsl(~map[off]) - 1);
	return (size);
}

/*
 * Find the highest non-zero bit in the given bitmap, starting at low and
 * not exceeding size - 1.
 */
static int
fd_last_used(struct filedesc *fdp, int low, int size)
{
	NDSLOTTYPE *map = fdp->fd_map;
	NDSLOTTYPE mask;
	int off, minoff;

	if (low >= size)
		return (-1);

	off = NDSLOT(size);
	if (size % NDENTRIES) {
		mask = ~(~(NDSLOTTYPE)0 << (size % NDENTRIES));
		if ((mask &= map[off]) != 0)
			return (off * NDENTRIES + flsl(mask) - 1);
		--off;
	}
	for (minoff = NDSLOT(low); off >= minoff; --off)
		if (map[off] != 0)
			return (off * NDENTRIES + flsl(map[off]) - 1);
	return (size - 1);
}

static int
fdisused(struct filedesc *fdp, int fd)
{
        KASSERT(fd >= 0 && fd < fdp->fd_nfiles,
            ("file descriptor %d out of range (0, %d)", fd, fdp->fd_nfiles));
	return ((fdp->fd_map[NDSLOT(fd)] & NDBIT(fd)) != 0);
}

/*
 * Mark a file descriptor as used.
 */
void
fdused(struct filedesc *fdp, int fd)
{
	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);
	KASSERT(!fdisused(fdp, fd),
	    ("fd already used"));
	fdp->fd_map[NDSLOT(fd)] |= NDBIT(fd);
	if (fd > fdp->fd_lastfile)
		fdp->fd_lastfile = fd;
	if (fd == fdp->fd_freefile)
		fdp->fd_freefile = fd_first_free(fdp, fd, fdp->fd_nfiles);
}

/*
 * Mark a file descriptor as unused.
 */
void
fdunused(struct filedesc *fdp, int fd)
{
	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);
	KASSERT(fdisused(fdp, fd),
	    ("fd is already unused"));
	KASSERT(fdp->fd_ofiles[fd] == NULL,
	    ("fd is still in use"));
	fdp->fd_map[NDSLOT(fd)] &= ~NDBIT(fd);
	if (fd < fdp->fd_freefile)
		fdp->fd_freefile = fd;
	if (fd == fdp->fd_lastfile)
		fdp->fd_lastfile = fd_last_used(fdp, 0, fd);
}

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

	PROC_LOCK(p);
	td->td_retval[0] =
	    min((int)lim_cur(p, RLIMIT_NOFILE), maxfilesperproc);
	PROC_UNLOCK(p);
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

	return (do_dup(td, DUP_FIXED, (int)uap->from, (int)uap->to,
		    td->td_retval));
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

	return (do_dup(td, DUP_VARIABLE, (int)uap->fd, 0, td->td_retval));
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
	struct fcntl_args *uap;
{
	struct flock fl;
	intptr_t arg;
	int error;

	error = 0;
	switch (uap->cmd) {
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		error = copyin((void *)(intptr_t)uap->arg, &fl, sizeof(fl));
		arg = (intptr_t)&fl;
		break;
	default:
		arg = uap->arg;
		break;
	}
	if (error)
		return (error);
	error = kern_fcntl(td, uap->fd, uap->cmd, arg);
	if (error)
		return (error);
	if (uap->cmd == F_GETLK)
		error = copyout(&fl, (void *)(intptr_t)uap->arg, sizeof(fl));
	return (error);
}

int
kern_fcntl(struct thread *td, int fd, int cmd, intptr_t arg)
{
	struct filedesc *fdp;
	struct flock *flp;
	struct file *fp;
	struct proc *p;
	char *pop;
	struct vnode *vp;
	u_int newmin;
	int error, flg, tmp;

	error = 0;
	flg = F_POSIX;
	p = td->td_proc;
	fdp = p->p_fd;
	mtx_lock(&Giant);
	FILEDESC_LOCK(fdp);
	if ((unsigned)fd >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[fd]) == NULL) {
		FILEDESC_UNLOCK(fdp);
		error = EBADF;
		goto done2;
	}
	pop = &fdp->fd_ofileflags[fd];

	switch (cmd) {
	case F_DUPFD:
		FILEDESC_UNLOCK(fdp);
		newmin = arg;
		PROC_LOCK(p);
		if (newmin >= lim_cur(p, RLIMIT_NOFILE) ||
		    newmin >= maxfilesperproc) {
			PROC_UNLOCK(p);
			error = EINVAL;
			break;
		}
		PROC_UNLOCK(p);
		error = do_dup(td, DUP_VARIABLE, fd, newmin, td->td_retval);
		break;

	case F_GETFD:
		td->td_retval[0] = (*pop & UF_EXCLOSE) ? FD_CLOEXEC : 0;
		FILEDESC_UNLOCK(fdp);
		break;

	case F_SETFD:
		*pop = (*pop &~ UF_EXCLOSE) |
		    (arg & FD_CLOEXEC ? UF_EXCLOSE : 0);
		FILEDESC_UNLOCK(fdp);
		break;

	case F_GETFL:
		FILE_LOCK(fp);
		FILEDESC_UNLOCK(fdp);
		td->td_retval[0] = OFLAGS(fp->f_flag);
		FILE_UNLOCK(fp);
		break;

	case F_SETFL:
		FILE_LOCK(fp);
		FILEDESC_UNLOCK(fdp);
		fhold_locked(fp);
		fp->f_flag &= ~FCNTLFLAGS;
		fp->f_flag |= FFLAGS(arg & ~O_ACCMODE) & FCNTLFLAGS;
		FILE_UNLOCK(fp);
		tmp = fp->f_flag & FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, &tmp, td->td_ucred, td);
		if (error) {
			fdrop(fp, td);
			break;
		}
		tmp = fp->f_flag & FASYNC;
		error = fo_ioctl(fp, FIOASYNC, &tmp, td->td_ucred, td);
		if (error == 0) {
			fdrop(fp, td);
			break;
		}
		FILE_LOCK(fp);
		fp->f_flag &= ~FNONBLOCK;
		FILE_UNLOCK(fp);
		tmp = 0;
		(void)fo_ioctl(fp, FIONBIO, &tmp, td->td_ucred, td);
		fdrop(fp, td);
		break;

	case F_GETOWN:
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		error = fo_ioctl(fp, FIOGETOWN, &tmp, td->td_ucred, td);
		if (error == 0)
			td->td_retval[0] = tmp;
		fdrop(fp, td);
		break;

	case F_SETOWN:
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		tmp = arg;
		error = fo_ioctl(fp, FIOSETOWN, &tmp, td->td_ucred, td);
		fdrop(fp, td);
		break;

	case F_SETLKW:
		flg |= F_WAIT;
		/* FALLTHROUGH F_SETLK */

	case F_SETLK:
		if (fp->f_type != DTYPE_VNODE) {
			FILEDESC_UNLOCK(fdp);
			error = EBADF;
			break;
		}

		flp = (struct flock *)arg;
		if (flp->l_whence == SEEK_CUR) {
			if (fp->f_offset < 0 ||
			    (flp->l_start > 0 &&
			     fp->f_offset > OFF_MAX - flp->l_start)) {
				FILEDESC_UNLOCK(fdp);
				error = EOVERFLOW;
				break;
			}
			flp->l_start += fp->f_offset;
		}

		/*
		 * VOP_ADVLOCK() may block.
		 */
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		vp = fp->f_vnode;

		switch (flp->l_type) {
		case F_RDLCK:
			if ((fp->f_flag & FREAD) == 0) {
				error = EBADF;
				break;
			}
			PROC_LOCK(p->p_leader);
			p->p_leader->p_flag |= P_ADVLOCK;
			PROC_UNLOCK(p->p_leader);
			error = VOP_ADVLOCK(vp, (caddr_t)p->p_leader, F_SETLK,
			    flp, flg);
			break;
		case F_WRLCK:
			if ((fp->f_flag & FWRITE) == 0) {
				error = EBADF;
				break;
			}
			PROC_LOCK(p->p_leader);
			p->p_leader->p_flag |= P_ADVLOCK;
			PROC_UNLOCK(p->p_leader);
			error = VOP_ADVLOCK(vp, (caddr_t)p->p_leader, F_SETLK,
			    flp, flg);
			break;
		case F_UNLCK:
			error = VOP_ADVLOCK(vp, (caddr_t)p->p_leader, F_UNLCK,
			    flp, F_POSIX);
			break;
		default:
			error = EINVAL;
			break;
		}
		/* Check for race with close */
		FILEDESC_LOCK(fdp);
		if ((unsigned) fd >= fdp->fd_nfiles ||
		    fp != fdp->fd_ofiles[fd]) {
			FILEDESC_UNLOCK(fdp);
			flp->l_whence = SEEK_SET;
			flp->l_start = 0;
			flp->l_len = 0;
			flp->l_type = F_UNLCK;
			(void) VOP_ADVLOCK(vp, (caddr_t)p->p_leader,
					   F_UNLCK, flp, F_POSIX);
		} else
			FILEDESC_UNLOCK(fdp);
		fdrop(fp, td);
		break;

	case F_GETLK:
		if (fp->f_type != DTYPE_VNODE) {
			FILEDESC_UNLOCK(fdp);
			error = EBADF;
			break;
		}
		flp = (struct flock *)arg;
		if (flp->l_type != F_RDLCK && flp->l_type != F_WRLCK &&
		    flp->l_type != F_UNLCK) {
			FILEDESC_UNLOCK(fdp);
			error = EINVAL;
			break;
		}
		if (flp->l_whence == SEEK_CUR) {
			if ((flp->l_start > 0 &&
			    fp->f_offset > OFF_MAX - flp->l_start) ||
			    (flp->l_start < 0 &&
			     fp->f_offset < OFF_MIN - flp->l_start)) {
				FILEDESC_UNLOCK(fdp);
				error = EOVERFLOW;
				break;
			}
			flp->l_start += fp->f_offset;
		}
		/*
		 * VOP_ADVLOCK() may block.
		 */
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
		vp = fp->f_vnode;
		error = VOP_ADVLOCK(vp, (caddr_t)p->p_leader, F_GETLK, flp,
		    F_POSIX);
		fdrop(fp, td);
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
 */
static int
do_dup(td, type, old, new, retval)
	enum dup_type type;
	int old, new;
	register_t *retval;
	struct thread *td;
{
	struct filedesc *fdp;
	struct proc *p;
	struct file *fp;
	struct file *delfp;
	int error, holdleaders, maxfd;

	KASSERT((type == DUP_VARIABLE || type == DUP_FIXED),
	    ("invalid dup type %d", type));

	p = td->td_proc;
	fdp = p->p_fd;

	/*
	 * Verify we have a valid descriptor to dup from and possibly to
	 * dup to.
	 */
	if (old < 0 || new < 0)
		return (EBADF);
	PROC_LOCK(p);
	maxfd = min((int)lim_cur(p, RLIMIT_NOFILE), maxfilesperproc);
	PROC_UNLOCK(p);
	if (new >= maxfd)
		return (EMFILE);

	FILEDESC_LOCK(fdp);
	if (old >= fdp->fd_nfiles || fdp->fd_ofiles[old] == NULL) {
		FILEDESC_UNLOCK(fdp);
		return (EBADF);
	}
	if (type == DUP_FIXED && old == new) {
		*retval = new;
		FILEDESC_UNLOCK(fdp);
		return (0);
	}
	fp = fdp->fd_ofiles[old];
	fhold(fp);

	/*
	 * If the caller specified a file descriptor, make sure the file
	 * table is large enough to hold it, and grab it.  Otherwise, just
	 * allocate a new descriptor the usual way.  Since the filedesc
	 * lock may be temporarily dropped in the process, we have to look
	 * out for a race.
	 */
	if (type == DUP_FIXED) {
		if (new >= fdp->fd_nfiles)
			fdgrowtable(fdp, new + 1);
		if (fdp->fd_ofiles[new] == NULL)
			fdused(fdp, new);
	} else {
		if ((error = fdalloc(td, new, &new)) != 0) {
			FILEDESC_UNLOCK(fdp);
			fdrop(fp, td);
			return (error);
		}
	}

	/*
	 * If the old file changed out from under us then treat it as a
	 * bad file descriptor.  Userland should do its own locking to
	 * avoid this case.
	 */
	if (fdp->fd_ofiles[old] != fp) {
		/* we've allocated a descriptor which we won't use */
		if (fdp->fd_ofiles[new] == NULL)
			fdunused(fdp, new);
		FILEDESC_UNLOCK(fdp);
		fdrop(fp, td);
		return (EBADF);
	}
	KASSERT(old != new,
	    ("new fd is same as old"));

	/*
	 * Save info on the descriptor being overwritten.  We cannot close
	 * it without introducing an ownership race for the slot, since we
	 * need to drop the filedesc lock to call closef().
	 *
	 * XXX this duplicates parts of close().
	 */
	delfp = fdp->fd_ofiles[new];
	holdleaders = 0;
	if (delfp != NULL) {
		if (td->td_proc->p_fdtol != NULL) {
			/*
			 * Ask fdfree() to sleep to ensure that all relevant
			 * process leaders can be traversed in closef().
			 */
			fdp->fd_holdleaderscount++;
			holdleaders = 1;
		}
	}

	/*
	 * Duplicate the source descriptor
	 */
	fdp->fd_ofiles[new] = fp;
	fdp->fd_ofileflags[new] = fdp->fd_ofileflags[old] &~ UF_EXCLOSE;
	if (new > fdp->fd_lastfile)
		fdp->fd_lastfile = new;
	FILEDESC_UNLOCK(fdp);
	*retval = new;

	/*
	 * If we dup'd over a valid file, we now own the reference to it
	 * and must dispose of it using closef() semantics (as if a
	 * close() were performed on it).
	 *
	 * XXX this duplicates parts of close().
	 */
	if (delfp != NULL) {
		/* XXX need to call knote_fdclose() */
		mtx_lock(&Giant);
		(void) closef(delfp, td);
		mtx_unlock(&Giant);
		if (holdleaders) {
			FILEDESC_LOCK(fdp);
			fdp->fd_holdleaderscount--;
			if (fdp->fd_holdleaderscount == 0 &&
			    fdp->fd_holdleaderswakeup != 0) {
				fdp->fd_holdleaderswakeup = 0;
				wakeup(&fdp->fd_holdleaderscount);
			}
			FILEDESC_UNLOCK(fdp);
		}
	}
	return (0);
}

/*
 * If sigio is on the list associated with a process or process group,
 * disable signalling from the device, remove sigio from the list and
 * free sigio.
 */
void
funsetown(sigiop)
	struct sigio **sigiop;
{
	struct sigio *sigio;

	SIGIO_LOCK();
	sigio = *sigiop;
	if (sigio == NULL) {
		SIGIO_UNLOCK();
		return;
	}
	*(sigio->sio_myref) = NULL;
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
	SIGIO_UNLOCK();
	crfree(sigio->sio_ucred);
	FREE(sigio, M_SIGIO);
}

/*
 * Free a list of sigio structures.
 * We only need to lock the SIGIO_LOCK because we have made ourselves
 * inaccessable to callers of fsetown and therefore do not need to lock
 * the proc or pgrp struct for the list manipulation.
 */
void
funsetownlst(sigiolst)
	struct sigiolst *sigiolst;
{
	struct proc *p;
	struct pgrp *pg;
	struct sigio *sigio;

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
		PGRP_LOCK_ASSERT(pg, MA_NOTOWNED);
	} else /* if (sigio->sio_pgid > 0) */ {
		p = sigio->sio_proc;
		PROC_LOCK_ASSERT(p, MA_NOTOWNED);
	}

	SIGIO_LOCK();
	while ((sigio = SLIST_FIRST(sigiolst)) != NULL) {
		*(sigio->sio_myref) = NULL;
		if (pg != NULL) {
			KASSERT(sigio->sio_pgid < 0,
			    ("Proc sigio in pgrp sigio list"));
			KASSERT(sigio->sio_pgrp == pg,
			    ("Bogus pgrp in sigio list"));
			PGRP_LOCK(pg);
			SLIST_REMOVE(&pg->pg_sigiolst, sigio, sigio,
			    sio_pgsigio);
			PGRP_UNLOCK(pg);
		} else /* if (p != NULL) */ {
			KASSERT(sigio->sio_pgid > 0,
			    ("Pgrp sigio in proc sigio list"));
			KASSERT(sigio->sio_proc == p,
			    ("Bogus proc in sigio list"));
			PROC_LOCK(p);
			SLIST_REMOVE(&p->p_sigiolst, sigio, sigio,
			    sio_pgsigio);
			PROC_UNLOCK(p);
		}
		SIGIO_UNLOCK();
		crfree(sigio->sio_ucred);
		FREE(sigio, M_SIGIO);
		SIGIO_LOCK();
	}
	SIGIO_UNLOCK();
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
	int ret;

	if (pgid == 0) {
		funsetown(sigiop);
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
	funsetown(sigiop);
	if (pgid > 0) {
		PROC_LOCK(proc);
		/*
		 * Since funsetownlst() is called without the proctree
		 * locked, we need to check for P_WEXIT.
		 * XXX: is ESRCH correct?
		 */
		if ((proc->p_flag & P_WEXIT) != 0) {
			PROC_UNLOCK(proc);
			ret = ESRCH;
			goto fail;
		}
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
	SIGIO_LOCK();
	*sigiop = sigio;
	SIGIO_UNLOCK();
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
fgetown(sigiop)
	struct sigio **sigiop;
{
	pid_t pgid;

	SIGIO_LOCK();
	pgid = (*sigiop != NULL) ? (*sigiop)->sio_pgid : 0;
	SIGIO_UNLOCK();
	return (pgid);
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
	struct filedesc *fdp;
	struct file *fp;
	int fd, error;
	int holdleaders;

	fd = uap->fd;
	error = 0;
	holdleaders = 0;
	fdp = td->td_proc->p_fd;
	mtx_lock(&Giant);
	FILEDESC_LOCK(fdp);
	if ((unsigned)fd >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[fd]) == NULL) {
		FILEDESC_UNLOCK(fdp);
		mtx_unlock(&Giant);
		return (EBADF);
	}
	fdp->fd_ofiles[fd] = NULL;
	fdp->fd_ofileflags[fd] = 0;
	fdunused(fdp, fd);
	if (td->td_proc->p_fdtol != NULL) {
		/*
		 * Ask fdfree() to sleep to ensure that all relevant
		 * process leaders can be traversed in closef().
		 */
		fdp->fd_holdleaderscount++;
		holdleaders = 1;
	}

	/*
	 * we now hold the fp reference that used to be owned by the descriptor
	 * array.
	 */
	if (fd < fdp->fd_knlistsize) {
		FILEDESC_UNLOCK(fdp);
		knote_fdclose(td, fd);
	} else
		FILEDESC_UNLOCK(fdp);

	error = closef(fp, td);
	mtx_unlock(&Giant);
	if (holdleaders) {
		FILEDESC_LOCK(fdp);
		fdp->fd_holdleaderscount--;
		if (fdp->fd_holdleaderscount == 0 &&
		    fdp->fd_holdleaderswakeup != 0) {
			fdp->fd_holdleaderswakeup = 0;
			wakeup(&fdp->fd_holdleaderscount);
		}
		FILEDESC_UNLOCK(fdp);
	}
	return (error);
}

#if defined(COMPAT_43)
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
	struct ofstat_args *uap;
{
	struct file *fp;
	struct stat ub;
	struct ostat oub;
	int error;

	if ((error = fget(td, uap->fd, &fp)) != 0)
		goto done2;
	mtx_lock(&Giant);
	error = fo_stat(fp, &ub, td->td_ucred, td);
	mtx_unlock(&Giant);
	if (error == 0) {
		cvtstat(&ub, &oub);
		error = copyout(&oub, uap->sb, sizeof(oub));
	}
	fdrop(fp, td);
done2:
	return (error);
}
#endif /* COMPAT_43 */

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

	if ((error = fget(td, uap->fd, &fp)) != 0)
		goto done2;
	mtx_lock(&Giant);
	error = fo_stat(fp, &ub, td->td_ucred, td);
	mtx_unlock(&Giant);
	if (error == 0)
		error = copyout(&ub, uap->sb, sizeof(ub));
	fdrop(fp, td);
done2:
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
	struct nfstat_args *uap;
{
	struct file *fp;
	struct stat ub;
	struct nstat nub;
	int error;

	if ((error = fget(td, uap->fd, &fp)) != 0)
		goto done2;
	mtx_lock(&Giant);
	error = fo_stat(fp, &ub, td->td_ucred, td);
	mtx_unlock(&Giant);
	if (error == 0) {
		cvtnstat(&ub, &nub);
		error = copyout(&nub, uap->sb, sizeof(nub));
	}
	fdrop(fp, td);
done2:
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
	struct fpathconf_args *uap;
{
	struct file *fp;
	struct vnode *vp;
	int error;

	if ((error = fget(td, uap->fd, &fp)) != 0)
		return (error);

	/* If asynchronous I/O is available, it works for all descriptors. */
	if (uap->name == _PC_ASYNC_IO) {
		td->td_retval[0] = async_io_version;
		goto out;
	}
	vp = fp->f_vnode;
	if (vp != NULL) {
		mtx_lock(&Giant);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, td);
		error = VOP_PATHCONF(vp, uap->name, td->td_retval);
		VOP_UNLOCK(vp, 0, td);
		mtx_unlock(&Giant);
	} else if (fp->f_type == DTYPE_PIPE || fp->f_type == DTYPE_SOCKET) {
		if (uap->name != _PC_PIPE_BUF) {
			error = EINVAL;
		} else {
			td->td_retval[0] = PIPE_BUF;
		error = 0;
		}
	} else {
		error = EOPNOTSUPP;
	}
out:
	fdrop(fp, td);
	return (error);
}

/*
 * Grow the file table to accomodate (at least) nfd descriptors.  This may
 * block and drop the filedesc lock, but it will reacquire it before
 * returing.
 */
static void
fdgrowtable(struct filedesc *fdp, int nfd)
{
	struct file **ntable;
	char *nfileflags;
	int nnfiles, onfiles;
	NDSLOTTYPE *nmap;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	KASSERT(fdp->fd_nfiles > 0,
	    ("zero-length file table"));

	/* compute the size of the new table */
	onfiles = fdp->fd_nfiles;
	nnfiles = NDSLOTS(nfd) * NDENTRIES; /* round up */
	if (nnfiles <= onfiles)
		/* the table is already large enough */
		return;

	/* allocate a new table and (if required) new bitmaps */
	FILEDESC_UNLOCK(fdp);
	MALLOC(ntable, struct file **, nnfiles * OFILESIZE,
	    M_FILEDESC, M_ZERO | M_WAITOK);
	nfileflags = (char *)&ntable[nnfiles];
	if (NDSLOTS(nnfiles) > NDSLOTS(onfiles))
		MALLOC(nmap, NDSLOTTYPE *, NDSLOTS(nnfiles) * NDSLOTSIZE,
		    M_FILEDESC, M_ZERO | M_WAITOK);
	else
		nmap = NULL;
	FILEDESC_LOCK(fdp);

	/*
	 * We now have new tables ready to go.  Since we dropped the
	 * filedesc lock to call malloc(), watch out for a race.
	 */
	onfiles = fdp->fd_nfiles;
	if (onfiles >= nnfiles) {
		/* we lost the race, but that's OK */
		free(ntable, M_FILEDESC);
		if (nmap != NULL)
			free(nmap, M_FILEDESC);
		return;
	}
	bcopy(fdp->fd_ofiles, ntable, onfiles * sizeof(*ntable));
	bcopy(fdp->fd_ofileflags, nfileflags, onfiles);
	if (onfiles > NDFILE)
		free(fdp->fd_ofiles, M_FILEDESC);
	fdp->fd_ofiles = ntable;
	fdp->fd_ofileflags = nfileflags;
	if (NDSLOTS(nnfiles) > NDSLOTS(onfiles)) {
		bcopy(fdp->fd_map, nmap, NDSLOTS(onfiles) * sizeof(*nmap));
		if (NDSLOTS(onfiles) > NDSLOTS(NDFILE))
			free(fdp->fd_map, M_FILEDESC);
		fdp->fd_map = nmap;
	}
	fdp->fd_nfiles = nnfiles;
}

/*
 * Allocate a file descriptor for the process.
 */
int
fdalloc(struct thread *td, int minfd, int *result)
{
	struct proc *p = td->td_proc;
	struct filedesc *fdp = p->p_fd;
	int fd = -1, maxfd;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	PROC_LOCK(p);
	maxfd = min((int)lim_cur(p, RLIMIT_NOFILE), maxfilesperproc);
	PROC_UNLOCK(p);

	/*
	 * Search the bitmap for a free descriptor.  If none is found, try
	 * to grow the file table.  Keep at it until we either get a file
	 * descriptor or run into process or system limits; fdgrowtable()
	 * may drop the filedesc lock, so we're in a race.
	 */
	for (;;) {
		fd = fd_first_free(fdp, minfd, fdp->fd_nfiles);
		if (fd >= maxfd)
			return (EMFILE);
		if (fd < fdp->fd_nfiles)
			break;
		fdgrowtable(fdp, min(fdp->fd_nfiles * 2, maxfd));
	}

	/*
	 * Perform some sanity checks, then mark the file descriptor as
	 * used and return it to the caller.
	 */
	KASSERT(!fdisused(fdp, fd),
	    ("fd_first_free() returned non-free descriptor"));
	KASSERT(fdp->fd_ofiles[fd] == NULL,
	    ("free descriptor isn't"));
	fdp->fd_ofileflags[fd] = 0; /* XXX needed? */
	fdused(fdp, fd);
	fdp->fd_freefile = fd_first_free(fdp, fd, fdp->fd_nfiles);
	*result = fd;
	return (0);
}

/*
 * Check to see whether n user file descriptors
 * are available to the process p.
 */
int
fdavail(td, n)
	struct thread *td;
	int n;
{
	struct proc *p = td->td_proc;
	struct filedesc *fdp = td->td_proc->p_fd;
	struct file **fpp;
	int i, lim, last;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	PROC_LOCK(p);
	lim = min((int)lim_cur(p, RLIMIT_NOFILE), maxfilesperproc);
	PROC_UNLOCK(p);
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
 * We add one reference to the file for the descriptor table
 * and one reference for resultfp. This is to prevent us being
 * prempted and the entry in the descriptor table closed after
 * we release the FILEDESC lock.
 */
int
falloc(td, resultfp, resultfd)
	struct thread *td;
	struct file **resultfp;
	int *resultfd;
{
	struct proc *p = td->td_proc;
	struct file *fp, *fq;
	int error, i;
	int maxuserfiles = maxfiles - (maxfiles / 20);
	static struct timeval lastfail;
	static int curfail;

	fp = uma_zalloc(file_zone, M_WAITOK | M_ZERO);
	sx_xlock(&filelist_lock);
	if ((nfiles >= maxuserfiles && td->td_ucred->cr_ruid != 0)
	   || nfiles >= maxfiles) {
		if (ppsratecheck(&lastfail, &curfail, 1)) {
			printf("kern.maxfiles limit exceeded by uid %i, please see tuning(7).\n",
				td->td_ucred->cr_ruid);
		}
		sx_xunlock(&filelist_lock);
		uma_zfree(file_zone, fp);
		return (ENFILE);
	}
	nfiles++;

	/*
	 * If the process has file descriptor zero open, add the new file
	 * descriptor to the list of open files at that point, otherwise
	 * put it at the front of the list of open files.
	 */
	fp->f_mtxp = mtx_pool_alloc(mtxpool_sleep);
	fp->f_count = 1;
	if (resultfp)
		fp->f_count++;
	fp->f_cred = crhold(td->td_ucred);
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	fp->f_vnode = NULL;
	FILEDESC_LOCK(p->p_fd);
	if ((fq = p->p_fd->fd_ofiles[0])) {
		LIST_INSERT_AFTER(fq, fp, f_list);
	} else {
		LIST_INSERT_HEAD(&filehead, fp, f_list);
	}
	sx_xunlock(&filelist_lock);
	if ((error = fdalloc(td, 0, &i))) {
		FILEDESC_UNLOCK(p->p_fd);
		fdrop(fp, td);
		if (resultfp)
			fdrop(fp, td);
		return (error);
	}
	p->p_fd->fd_ofiles[i] = fp;
	FILEDESC_UNLOCK(p->p_fd);
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
	struct file *fp;
{

	KASSERT(fp->f_count == 0, ("ffree: fp_fcount not 0!"));
	sx_xlock(&filelist_lock);
	LIST_REMOVE(fp, f_list);
	nfiles--;
	sx_xunlock(&filelist_lock);
	crfree(fp->f_cred);
	uma_zfree(file_zone, fp);
}

/*
 * Build a new filedesc structure from another.
 * Copy the current, root, and jail root vnode references.
 */
struct filedesc *
fdinit(fdp)
	struct filedesc *fdp;
{
	struct filedesc0 *newfdp;

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);

	FILEDESC_UNLOCK(fdp);
	MALLOC(newfdp, struct filedesc0 *, sizeof(struct filedesc0),
	    M_FILEDESC, M_WAITOK | M_ZERO);
	FILEDESC_LOCK(fdp);
	mtx_init(&newfdp->fd_fd.fd_mtx, FILEDESC_LOCK_DESC, NULL, MTX_DEF);
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
	newfdp->fd_fd.fd_cmask = CMASK;
	newfdp->fd_fd.fd_ofiles = newfdp->fd_dfiles;
	newfdp->fd_fd.fd_ofileflags = newfdp->fd_dfileflags;
	newfdp->fd_fd.fd_nfiles = NDFILE;
	newfdp->fd_fd.fd_knlistsize = -1;
	newfdp->fd_fd.fd_map = newfdp->fd_dmap;
	return (&newfdp->fd_fd);
}

/*
 * Share a filedesc structure.
 */
struct filedesc *
fdshare(fdp)
	struct filedesc *fdp;
{
	FILEDESC_LOCK(fdp);
	fdp->fd_refcnt++;
	FILEDESC_UNLOCK(fdp);
	return (fdp);
}

/*
 * Copy a filedesc structure.
 * A NULL pointer in returns a NULL reference, this is to ease callers,
 * not catch errors.
 */
struct filedesc *
fdcopy(fdp)
	struct filedesc *fdp;
{
	struct filedesc *newfdp;
	int i;

	/* Certain daemons might not have file descriptors. */
	if (fdp == NULL)
		return (NULL);

	FILEDESC_LOCK_ASSERT(fdp, MA_OWNED);
	newfdp = fdinit(fdp);
	while (fdp->fd_lastfile >= newfdp->fd_nfiles) {
		FILEDESC_UNLOCK(fdp);
		FILEDESC_LOCK(newfdp);
		fdgrowtable(newfdp, fdp->fd_lastfile + 1);
		FILEDESC_UNLOCK(newfdp);
		FILEDESC_LOCK(fdp);
	}
	/* copy everything except kqueue descriptors */
	newfdp->fd_freefile = -1;
	for (i = 0; i <= fdp->fd_lastfile; ++i) {
		if (fdisused(fdp, i) &&
		    fdp->fd_ofiles[i]->f_type != DTYPE_KQUEUE) {
			newfdp->fd_ofiles[i] = fdp->fd_ofiles[i];
			newfdp->fd_ofileflags[i] = fdp->fd_ofileflags[i];
			fhold(newfdp->fd_ofiles[i]);
			newfdp->fd_lastfile = i;
		} else {
			if (newfdp->fd_freefile == -1)
				newfdp->fd_freefile = i;
		}
	}
	FILEDESC_UNLOCK(fdp);
	FILEDESC_LOCK(newfdp);
	for (i = 0; i <= newfdp->fd_lastfile; ++i)
		if (newfdp->fd_ofiles[i] != NULL)
			fdused(newfdp, i);
	FILEDESC_UNLOCK(newfdp);
	FILEDESC_LOCK(fdp);
	if (newfdp->fd_freefile == -1)
		newfdp->fd_freefile = i;
	newfdp->fd_cmask = fdp->fd_cmask;
	return (newfdp);
}

/* A mutex to protect the association between a proc and filedesc. */
struct mtx	fdesc_mtx;
MTX_SYSINIT(fdesc, &fdesc_mtx, "fdesc", MTX_DEF);

/*
 * Release a filedesc structure.
 */
void
fdfree(td)
	struct thread *td;
{
	struct filedesc *fdp;
	struct file **fpp;
	int i;
	struct filedesc_to_leader *fdtol;
	struct file *fp;
	struct vnode *vp;
	struct flock lf;

	/* Certain daemons might not have file descriptors. */
	fdp = td->td_proc->p_fd;
	if (fdp == NULL)
		return;

	/* Check for special need to clear POSIX style locks */
	fdtol = td->td_proc->p_fdtol;
	if (fdtol != NULL) {
		FILEDESC_LOCK(fdp);
		KASSERT(fdtol->fdl_refcount > 0,
			("filedesc_to_refcount botch: fdl_refcount=%d",
			 fdtol->fdl_refcount));
		if (fdtol->fdl_refcount == 1 &&
		    (td->td_proc->p_leader->p_flag & P_ADVLOCK) != 0) {
			i = 0;
			fpp = fdp->fd_ofiles;
			for (i = 0, fpp = fdp->fd_ofiles;
			     i <= fdp->fd_lastfile;
			     i++, fpp++) {
				if (*fpp == NULL ||
				    (*fpp)->f_type != DTYPE_VNODE)
					continue;
				fp = *fpp;
				fhold(fp);
				FILEDESC_UNLOCK(fdp);
				lf.l_whence = SEEK_SET;
				lf.l_start = 0;
				lf.l_len = 0;
				lf.l_type = F_UNLCK;
				vp = fp->f_vnode;
				(void) VOP_ADVLOCK(vp,
						   (caddr_t)td->td_proc->
						   p_leader,
						   F_UNLCK,
						   &lf,
						   F_POSIX);
				FILEDESC_LOCK(fdp);
				fdrop(fp, td);
				fpp = fdp->fd_ofiles + i;
			}
		}
	retry:
		if (fdtol->fdl_refcount == 1) {
			if (fdp->fd_holdleaderscount > 0 &&
			    (td->td_proc->p_leader->p_flag & P_ADVLOCK) != 0) {
				/*
				 * close() or do_dup() has cleared a reference
				 * in a shared file descriptor table.
				 */
				fdp->fd_holdleaderswakeup = 1;
				msleep(&fdp->fd_holdleaderscount, &fdp->fd_mtx,
				       PLOCK, "fdlhold", 0);
				goto retry;
			}
			if (fdtol->fdl_holdcount > 0) {
				/*
				 * Ensure that fdtol->fdl_leader
				 * remains valid in closef().
				 */
				fdtol->fdl_wakeup = 1;
				msleep(fdtol, &fdp->fd_mtx,
				       PLOCK, "fdlhold", 0);
				goto retry;
			}
		}
		fdtol->fdl_refcount--;
		if (fdtol->fdl_refcount == 0 &&
		    fdtol->fdl_holdcount == 0) {
			fdtol->fdl_next->fdl_prev = fdtol->fdl_prev;
			fdtol->fdl_prev->fdl_next = fdtol->fdl_next;
		} else
			fdtol = NULL;
		td->td_proc->p_fdtol = NULL;
		FILEDESC_UNLOCK(fdp);
		if (fdtol != NULL)
			FREE(fdtol, M_FILEDESC_TO_LEADER);
	}
	FILEDESC_LOCK(fdp);
	if (--fdp->fd_refcnt > 0) {
		FILEDESC_UNLOCK(fdp);
		return;
	}

	/*
	 * We are the last reference to the structure, so we can
	 * safely assume it will not change out from under us.
	 */
	FILEDESC_UNLOCK(fdp);
	fpp = fdp->fd_ofiles;
	for (i = fdp->fd_lastfile; i-- >= 0; fpp++) {
		if (*fpp)
			(void) closef(*fpp, td);
	}

	/* XXX This should happen earlier. */
	mtx_lock(&fdesc_mtx);
	td->td_proc->p_fd = NULL;
	mtx_unlock(&fdesc_mtx);

	if (fdp->fd_nfiles > NDFILE)
		FREE(fdp->fd_ofiles, M_FILEDESC);
	if (NDSLOTS(fdp->fd_nfiles) > NDSLOTS(NDFILE))
		FREE(fdp->fd_map, M_FILEDESC);
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
 * otherwise be off-limits to the process.  We check for filesystems where
 * the vnode can change out from under us after execve (like [lin]procfs).
 *
 * Since setugidsafety calls this only for fd 0, 1 and 2, this check is
 * sufficient.  We also don't for check setugidness since we know we are.
 */
static int
is_unsafe(struct file *fp)
{
	if (fp->f_type == DTYPE_VNODE) {
		struct vnode *vp = fp->f_vnode;

		if ((vp->v_vflag & VV_PROCDEP) != 0)
			return (1);
	}
	return (0);
}

/*
 * Make this setguid thing safe, if at all possible.
 */
void
setugidsafety(td)
	struct thread *td;
{
	struct filedesc *fdp;
	int i;

	/* Certain daemons might not have file descriptors. */
	fdp = td->td_proc->p_fd;
	if (fdp == NULL)
		return;

	/*
	 * Note: fdp->fd_ofiles may be reallocated out from under us while
	 * we are blocked in a close.  Be careful!
	 */
	FILEDESC_LOCK(fdp);
	for (i = 0; i <= fdp->fd_lastfile; i++) {
		if (i > 2)
			break;
		if (fdp->fd_ofiles[i] && is_unsafe(fdp->fd_ofiles[i])) {
			struct file *fp;

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
			fdunused(fdp, i);
			FILEDESC_UNLOCK(fdp);
			(void) closef(fp, td);
			FILEDESC_LOCK(fdp);
		}
	}
	FILEDESC_UNLOCK(fdp);
}

/*
 * Close any files on exec?
 */
void
fdcloseexec(td)
	struct thread *td;
{
	struct filedesc *fdp;
	int i;

	/* Certain daemons might not have file descriptors. */
	fdp = td->td_proc->p_fd;
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
			fdunused(fdp, i);
			FILEDESC_UNLOCK(fdp);
			(void) closef(fp, td);
			FILEDESC_LOCK(fdp);
		}
	}
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
	KASSERT(fdp->fd_refcnt == 1, ("the fdtable should not be shared"));
	devnull = -1;
	error = 0;
	for (i = 0; i < 3; i++) {
		if (fdp->fd_ofiles[i] != NULL)
			continue;
		if (devnull < 0) {
			error = falloc(td, &fp, &fd);
			if (error != 0)
				break;
			/* Note extra ref on `fp' held for us by falloc(). */
			KASSERT(fd == i, ("oof, we didn't get our fd"));
			NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, "/dev/null",
			    td);
			flags = FREAD | FWRITE;
			error = vn_open(&nd, &flags, 0, -1);
			if (error != 0) {
				/*
				 * Someone may have closed the entry in the
				 * file descriptor table, so check it hasn't
				 * changed before dropping the reference count.
				 */
				FILEDESC_LOCK(fdp);
				KASSERT(fdp->fd_ofiles[fd] == fp,
				    ("table not shared, how did it change?"));
				fdp->fd_ofiles[fd] = NULL;
				fdunused(fdp, fd);
				FILEDESC_UNLOCK(fdp);
				fdrop(fp, td);
				fdrop(fp, td);
				break;
			}
			NDFREE(&nd, NDF_ONLY_PNBUF);
			fp->f_vnode = nd.ni_vp;
			fp->f_data = nd.ni_vp;
			fp->f_flag = flags;
			fp->f_ops = &vnops;
			fp->f_type = DTYPE_VNODE;
			VOP_UNLOCK(nd.ni_vp, 0, td);
			devnull = fd;
			fdrop(fp, td);
		} else {
			error = do_dup(td, DUP_FIXED, devnull, i, &retval);
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
	struct file *fp;
	struct thread *td;
{
	struct vnode *vp;
	struct flock lf;
	struct filedesc_to_leader *fdtol;
	struct filedesc *fdp;

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
	if (td != NULL &&
	    fp->f_type == DTYPE_VNODE) {
		if ((td->td_proc->p_leader->p_flag & P_ADVLOCK) != 0) {
			lf.l_whence = SEEK_SET;
			lf.l_start = 0;
			lf.l_len = 0;
			lf.l_type = F_UNLCK;
			vp = fp->f_vnode;
			(void) VOP_ADVLOCK(vp, (caddr_t)td->td_proc->p_leader,
					   F_UNLCK, &lf, F_POSIX);
		}
		fdtol = td->td_proc->p_fdtol;
		if (fdtol != NULL) {
			/*
			 * Handle special case where file descriptor table
			 * is shared between multiple process leaders.
			 */
			fdp = td->td_proc->p_fd;
			FILEDESC_LOCK(fdp);
			for (fdtol = fdtol->fdl_next;
			     fdtol != td->td_proc->p_fdtol;
			     fdtol = fdtol->fdl_next) {
				if ((fdtol->fdl_leader->p_flag &
				     P_ADVLOCK) == 0)
					continue;
				fdtol->fdl_holdcount++;
				FILEDESC_UNLOCK(fdp);
				lf.l_whence = SEEK_SET;
				lf.l_start = 0;
				lf.l_len = 0;
				lf.l_type = F_UNLCK;
				vp = fp->f_vnode;
				(void) VOP_ADVLOCK(vp,
						   (caddr_t)fdtol->fdl_leader,
						   F_UNLCK, &lf, F_POSIX);
				FILEDESC_LOCK(fdp);
				fdtol->fdl_holdcount--;
				if (fdtol->fdl_holdcount == 0 &&
				    fdtol->fdl_wakeup != 0) {
					fdtol->fdl_wakeup = 0;
					wakeup(fdtol);
				}
			}
			FILEDESC_UNLOCK(fdp);
		}
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
static __inline int
_fget(struct thread *td, int fd, struct file **fpp, int flags, int hold)
{
	struct filedesc *fdp;
	struct file *fp;

	*fpp = NULL;
	if (td == NULL || (fdp = td->td_proc->p_fd) == NULL)
		return (EBADF);
	FILEDESC_LOCK(fdp);
	if ((fp = fget_locked(fdp, fd)) == NULL || fp->f_ops == &badfileops) {
		FILEDESC_UNLOCK(fdp);
		return (EBADF);
	}

	/*
	 * Note: FREAD failures returns EBADF to maintain backwards
	 * compatibility with what routines returned before.
	 *
	 * Only one flag, or 0, may be specified.
	 */
	if (flags == FREAD && (fp->f_flag & FREAD) == 0) {
		FILEDESC_UNLOCK(fdp);
		return (EBADF);
	}
	if (flags == FWRITE && (fp->f_flag & FWRITE) == 0) {
		FILEDESC_UNLOCK(fdp);
		return (EINVAL);
	}
	if (hold) {
		fhold(fp);
		FILEDESC_UNLOCK(fdp);
	}
	*fpp = fp;
	return (0);
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
static __inline int
_fgetvp(struct thread *td, int fd, struct vnode **vpp, int flags)
{
	struct file *fp;
	int error;

	*vpp = NULL;
	if ((error = _fget(td, fd, &fp, 0, 0)) != 0)
		return (error);
	if (fp->f_vnode == NULL) {
		error = EINVAL;
	} else {
		*vpp = fp->f_vnode;
		vref(*vpp);
	}
	FILEDESC_UNLOCK(td->td_proc->p_fd);
	return (error);
}

int
fgetvp(struct thread *td, int fd, struct vnode **vpp)
{

	return (_fgetvp(td, fd, vpp, 0));
}

int
fgetvp_read(struct thread *td, int fd, struct vnode **vpp)
{

	return (_fgetvp(td, fd, vpp, FREAD));
}

int
fgetvp_write(struct thread *td, int fd, struct vnode **vpp)
{

	return (_fgetvp(td, fd, vpp, FWRITE));
}

/*
 * Like fget() but loads the underlying socket, or returns an error if
 * the descriptor does not represent a socket.
 *
 * We bump the ref count on the returned socket.  XXX Also obtain the SX
 * lock in the future.
 */
int
fgetsock(struct thread *td, int fd, struct socket **spp, u_int *fflagp)
{
	struct file *fp;
	int error;

	*spp = NULL;
	if (fflagp != NULL)
		*fflagp = 0;
	if ((error = _fget(td, fd, &fp, 0, 0)) != 0)
		return (error);
	if (fp->f_type != DTYPE_SOCKET) {
		error = ENOTSOCK;
	} else {
		*spp = fp->f_data;
		if (fflagp)
			*fflagp = fp->f_flag;
		SOCK_LOCK(*spp);
		soref(*spp);
		SOCK_UNLOCK(*spp);
	}
	FILEDESC_UNLOCK(td->td_proc->p_fd);
	return (error);
}

/*
 * Drop the reference count on the the socket and XXX release the SX lock in
 * the future.  The last reference closes the socket.
 */
void
fputsock(struct socket *so)
{

	NET_ASSERT_GIANT();
	SOCK_LOCK(so);
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
	int error;

	FILE_LOCK_ASSERT(fp, MA_OWNED);

	if (--fp->f_count > 0) {
		FILE_UNLOCK(fp);
		return (0);
	}
	/* We have the last ref so we can proceed without the file lock. */
	FILE_UNLOCK(fp);
	if (fp->f_count < 0)
		panic("fdrop: count < 0");
	mtx_lock(&Giant);
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
	struct flock_args *uap;
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
	vp = fp->f_vnode;
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
	struct cdev *dev;
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
	struct file *wfp;
	struct file *fp;

	/*
	 * If the to-be-dup'd fd number is greater than the allowed number
	 * of file descriptors, or the fd to be dup'd has already been
	 * closed, then reject.
	 */
	FILEDESC_LOCK(fdp);
	if (dfd < 0 || dfd >= fdp->fd_nfiles ||
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
		fdp->fd_ofiles[indx] = wfp;
		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		if (fp == NULL)
			fdused(fdp, indx);
		fhold_locked(wfp);
		FILE_UNLOCK(wfp);
		if (fp != NULL)
			FILE_LOCK(fp);
		FILEDESC_UNLOCK(fdp);
		/*
		 * We now own the reference to fp that the ofiles[] array
		 * used to own.  Release it.
		 */
		if (fp != NULL)
			fdrop_locked(fp, td);
		return (0);

	case ENXIO:
		/*
		 * Steal away the file pointer from dfd and stuff it into indx.
		 */
		fp = fdp->fd_ofiles[indx];
		fdp->fd_ofiles[indx] = fdp->fd_ofiles[dfd];
		fdp->fd_ofiles[dfd] = NULL;
		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		fdp->fd_ofileflags[dfd] = 0;
		fdunused(fdp, dfd);
		if (fp == NULL)
			fdused(fdp, indx);
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

struct filedesc_to_leader *
filedesc_to_leader_alloc(struct filedesc_to_leader *old,
			 struct filedesc *fdp,
			 struct proc *leader)
{
	struct filedesc_to_leader *fdtol;

	MALLOC(fdtol, struct filedesc_to_leader *,
	       sizeof(struct filedesc_to_leader),
	       M_FILEDESC_TO_LEADER,
	       M_WAITOK);
	fdtol->fdl_refcount = 1;
	fdtol->fdl_holdcount = 0;
	fdtol->fdl_wakeup = 0;
	fdtol->fdl_leader = leader;
	if (old != NULL) {
		FILEDESC_LOCK(fdp);
		fdtol->fdl_next = old->fdl_next;
		fdtol->fdl_prev = old;
		old->fdl_next = fdtol;
		fdtol->fdl_next->fdl_prev = fdtol;
		FILEDESC_UNLOCK(fdp);
	} else {
		fdtol->fdl_next = fdtol;
		fdtol->fdl_prev = fdtol;
	}
	return (fdtol);
}

/*
 * Get file structures.
 */
static int
sysctl_kern_file(SYSCTL_HANDLER_ARGS)
{
	struct xfile xf;
	struct filedesc *fdp;
	struct file *fp;
	struct proc *p;
	int error, n;

	/*
	 * Note: because the number of file descriptors is calculated
	 * in different ways for sizing vs returning the data,
	 * there is information leakage from the first loop.  However,
	 * it is of a similar order of magnitude to the leakage from
	 * global system statistics such as kern.openfiles.
	 */
	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	if (req->oldptr == NULL) {
		n = 16;		/* A slight overestimate. */
		sx_slock(&filelist_lock);
		LIST_FOREACH(fp, &filehead, f_list) {
			/*
			 * We should grab the lock, but this is an
			 * estimate, so does it really matter?
			 */
			/* mtx_lock(fp->f_mtxp); */
			n += fp->f_count;
			/* mtx_unlock(f->f_mtxp); */
		}
		sx_sunlock(&filelist_lock);
		return (SYSCTL_OUT(req, 0, n * sizeof(xf)));
	}
	error = 0;
	bzero(&xf, sizeof(xf));
	xf.xf_size = sizeof(xf);
	sx_slock(&allproc_lock);
	LIST_FOREACH(p, &allproc, p_list) {
		PROC_LOCK(p);
		if (p_cansee(req->td, p) != 0) {
			PROC_UNLOCK(p);
			continue;
		}
		xf.xf_pid = p->p_pid;
		xf.xf_uid = p->p_ucred->cr_uid;
		PROC_UNLOCK(p);
		mtx_lock(&fdesc_mtx);
		if ((fdp = p->p_fd) == NULL) {
			mtx_unlock(&fdesc_mtx);
			continue;
		}
		FILEDESC_LOCK(fdp);
		for (n = 0; n < fdp->fd_nfiles; ++n) {
			if ((fp = fdp->fd_ofiles[n]) == NULL)
				continue;
			xf.xf_fd = n;
			xf.xf_file = fp;
			xf.xf_data = fp->f_data;
			xf.xf_vnode = fp->f_vnode;
			xf.xf_type = fp->f_type;
			xf.xf_count = fp->f_count;
			xf.xf_msgcount = fp->f_msgcount;
			xf.xf_offset = fp->f_offset;
			xf.xf_flag = fp->f_flag;
			error = SYSCTL_OUT(req, &xf, sizeof(xf));
			if (error)
				break;
		}
		FILEDESC_UNLOCK(fdp);
		mtx_unlock(&fdesc_mtx);
		if (error)
			break;
	}
	sx_sunlock(&allproc_lock);
	return (error);
}

SYSCTL_PROC(_kern, KERN_FILE, file, CTLTYPE_OPAQUE|CTLFLAG_RD,
    0, 0, sysctl_kern_file, "S,xfile", "Entire file table");

SYSCTL_INT(_kern, KERN_MAXFILESPERPROC, maxfilesperproc, CTLFLAG_RW,
    &maxfilesperproc, 0, "Maximum files allowed open per process");

SYSCTL_INT(_kern, KERN_MAXFILES, maxfiles, CTLFLAG_RW,
    &maxfiles, 0, "Maximum number of files");

SYSCTL_INT(_kern, OID_AUTO, openfiles, CTLFLAG_RD,
    &nfiles, 0, "System-wide number of open files");

static void
fildesc_drvinit(void *unused)
{
	struct cdev *dev;

	dev = make_dev(&fildesc_cdevsw, 0, UID_ROOT, GID_WHEEL, 0666, "fd/0");
	make_dev_alias(dev, "stdin");
	dev = make_dev(&fildesc_cdevsw, 1, UID_ROOT, GID_WHEEL, 0666, "fd/1");
	make_dev_alias(dev, "stdout");
	dev = make_dev(&fildesc_cdevsw, 2, UID_ROOT, GID_WHEEL, 0666, "fd/2");
	make_dev_alias(dev, "stderr");
}

static fo_rdwr_t	badfo_readwrite;
static fo_ioctl_t	badfo_ioctl;
static fo_poll_t	badfo_poll;
static fo_kqfilter_t	badfo_kqfilter;
static fo_stat_t	badfo_stat;
static fo_close_t	badfo_close;

struct fileops badfileops = {
	.fo_read = badfo_readwrite,
	.fo_write = badfo_readwrite,
	.fo_ioctl = badfo_ioctl,
	.fo_poll = badfo_poll,
	.fo_kqfilter = badfo_kqfilter,
	.fo_stat = badfo_stat,
	.fo_close = badfo_close,
};

static int
badfo_readwrite(fp, uio, active_cred, flags, td)
	struct file *fp;
	struct uio *uio;
	struct ucred *active_cred;
	struct thread *td;
	int flags;
{

	return (EBADF);
}

static int
badfo_ioctl(fp, com, data, active_cred, td)
	struct file *fp;
	u_long com;
	void *data;
	struct ucred *active_cred;
	struct thread *td;
{

	return (EBADF);
}

static int
badfo_poll(fp, events, active_cred, td)
	struct file *fp;
	int events;
	struct ucred *active_cred;
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
badfo_stat(fp, sb, active_cred, td)
	struct file *fp;
	struct stat *sb;
	struct ucred *active_cred;
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
	mtx_init(&sigio_lock, "sigio lock", NULL, MTX_DEF);
}
