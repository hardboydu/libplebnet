/*
 * Copyright (c) 1989, 1993, 1995
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
 *	@(#)spec_vnops.c	8.14 (Berkeley) 5/21/95
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/conf.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/vmmeter.h>
#include <sys/sysctl.h>
#include <sys/tty.h>
#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

static int	spec_advlock(struct vop_advlock_args *);
static int	spec_close(struct vop_close_args *);
static int	spec_fsync(struct  vop_fsync_args *);
static int	spec_ioctl(struct vop_ioctl_args *);
static int	spec_kqfilter(struct vop_kqfilter_args *);
static int	spec_open(struct vop_open_args *);
static int	spec_poll(struct vop_poll_args *);
static int	spec_print(struct vop_print_args *);
static int	spec_read(struct vop_read_args *);
static int	spec_specstrategy(struct vop_specstrategy_args *);
static int	spec_write(struct vop_write_args *);

vop_t **spec_vnodeop_p;
static struct vnodeopv_entry_desc spec_vnodeop_entries[] = {
	{ &vop_default_desc,		(vop_t *) vop_defaultop },
	{ &vop_access_desc,		(vop_t *) vop_ebadf },
	{ &vop_advlock_desc,		(vop_t *) spec_advlock },
	{ &vop_bmap_desc,		(vop_t *) vop_panic },
	{ &vop_close_desc,		(vop_t *) spec_close },
	{ &vop_create_desc,		(vop_t *) vop_panic },
	{ &vop_fsync_desc,		(vop_t *) spec_fsync },
	{ &vop_getwritemount_desc, 	(vop_t *) vop_stdgetwritemount },
	{ &vop_ioctl_desc,		(vop_t *) spec_ioctl },
	{ &vop_kqfilter_desc,		(vop_t *) spec_kqfilter },
	{ &vop_lease_desc,		(vop_t *) vop_null },
	{ &vop_link_desc,		(vop_t *) vop_panic },
	{ &vop_mkdir_desc,		(vop_t *) vop_panic },
	{ &vop_mknod_desc,		(vop_t *) vop_panic },
	{ &vop_open_desc,		(vop_t *) spec_open },
	{ &vop_pathconf_desc,		(vop_t *) vop_stdpathconf },
	{ &vop_poll_desc,		(vop_t *) spec_poll },
	{ &vop_print_desc,		(vop_t *) spec_print },
	{ &vop_read_desc,		(vop_t *) spec_read },
	{ &vop_readdir_desc,		(vop_t *) vop_panic },
	{ &vop_readlink_desc,		(vop_t *) vop_panic },
	{ &vop_reallocblks_desc,	(vop_t *) vop_panic },
	{ &vop_reclaim_desc,		(vop_t *) vop_null },
	{ &vop_remove_desc,		(vop_t *) vop_panic },
	{ &vop_rename_desc,		(vop_t *) vop_panic },
	{ &vop_rmdir_desc,		(vop_t *) vop_panic },
	{ &vop_setattr_desc,		(vop_t *) vop_ebadf },
	{ &vop_specstrategy_desc,	(vop_t *) spec_specstrategy },
	{ &vop_strategy_desc,		(vop_t *) vop_panic },
	{ &vop_symlink_desc,		(vop_t *) vop_panic },
	{ &vop_write_desc,		(vop_t *) spec_write },
	{ NULL, NULL }
};
static struct vnodeopv_desc spec_vnodeop_opv_desc =
	{ &spec_vnodeop_p, spec_vnodeop_entries };

VNODEOP_SET(spec_vnodeop_opv_desc);

int
spec_vnoperate(ap)
	struct vop_generic_args /* {
		struct vnodeop_desc *a_desc;
		<other random data follows, presumably>
	} */ *ap;
{
	return (VOCALL(spec_vnodeop_p, ap->a_desc->vdesc_offset, ap));
}

/*
 * Open a special file.
 */
/* ARGSUSED */
static int
spec_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	struct thread *td = ap->a_td;
	struct vnode *vp = ap->a_vp;
	struct cdev *dev = vp->v_rdev;
	int error;
	struct cdevsw *dsw;

	if (vp->v_type == VBLK)
		return (ENXIO);

	/* Don't allow open if fs is mounted -nodev. */
	if (vp->v_mount && (vp->v_mount->mnt_flag & MNT_NODEV))
		return (ENXIO);

	if (dev == NULL)
		return (ENXIO);

	/* Make this field valid before any I/O in d_open. */
	if (dev->si_iosize_max == 0)
		dev->si_iosize_max = DFLTPHYS;

	/*
	 * XXX: Disks get special billing here, but it is mostly wrong.
	 * XXX: Disk partitions can overlap and the real checks should
	 * XXX: take this into account, and consequently they need to
	 * XXX: live in the disk slice code.  Some checks do.
	 */
	if (vn_isdisk(vp, NULL) && ap->a_cred != FSCRED &&
	    (ap->a_mode & FWRITE)) {
		/*
		 * Never allow opens for write if the disk is mounted R/W.
		 */
		if (vp->v_rdev->si_mountpoint != NULL &&
		    !(vp->v_rdev->si_mountpoint->mnt_flag & MNT_RDONLY))
			return (EBUSY);

		/*
		 * When running in secure mode, do not allow opens
		 * for writing if the disk is mounted.
		 */
		error = securelevel_ge(td->td_ucred, 1);
		if (error && vfs_mountedon(vp))
			return (error);

		/*
		 * When running in very secure mode, do not allow
		 * opens for writing of any disks.
		 */
		error = securelevel_ge(td->td_ucred, 2);
		if (error)
			return (error);
	}

	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return (ENXIO);

	/* XXX: Special casing of ttys for deadfs.  Probably redundant. */
	if (dsw->d_flags & D_TTY)
		vp->v_vflag |= VV_ISTTY;

	VOP_UNLOCK(vp, 0, td);

	if(!(dsw->d_flags & D_NEEDGIANT)) {
		DROP_GIANT();
		if (dsw->d_fdopen != NULL)
			error = dsw->d_fdopen(dev, ap->a_mode, td, ap->a_fdidx);
		else
			error = dsw->d_open(dev, ap->a_mode, S_IFCHR, td);
		PICKUP_GIANT();
	} else if (dsw->d_fdopen != NULL)
		error = dsw->d_fdopen(dev, ap->a_mode, td, ap->a_fdidx);
	else
		error = dsw->d_open(dev, ap->a_mode, S_IFCHR, td);

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, td);

	dev_relthread(dev);

	if (error)
		return (error);

	if (vn_isdisk(vp, NULL)) {
		if (!dev->si_bsize_phys)
			dev->si_bsize_phys = DEV_BSIZE;
	}
	return (error);
}

/*
 * Vnode op for read
 */
/* ARGSUSED */
static int
spec_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp;
	struct thread *td;
	struct uio *uio;
	struct cdev *dev;
	int error, resid;
	struct cdevsw *dsw;

	vp = ap->a_vp;
	dev = vp->v_rdev;
	uio = ap->a_uio;
	td = uio->uio_td;
	resid = uio->uio_resid;

	if (resid == 0)
		return (0);

	KASSERT(dev->si_refcount > 0,
	    ("specread() on un-referenced struct cdev *(%s)", devtoname(dev)));
	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return (ENXIO);
	VOP_UNLOCK(vp, 0, td);
	if (!(dsw->d_flags & D_NEEDGIANT)) {
		DROP_GIANT();
		error = dsw->d_read(dev, uio, ap->a_ioflag);
		PICKUP_GIANT();
	} else
		error = dsw->d_read(dev, uio, ap->a_ioflag);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, td);
	dev_relthread(dev);
	if (uio->uio_resid != resid || (error == 0 && resid != 0))
		vfs_timestamp(&dev->si_atime);
	return (error);
}

/*
 * Vnode op for write
 */
/* ARGSUSED */
static int
spec_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp;
	struct thread *td;
	struct uio *uio;
	struct cdev *dev;
	int error, resid;
	struct cdevsw *dsw;

	vp = ap->a_vp;
	dev = vp->v_rdev;
	uio = ap->a_uio;
	td = uio->uio_td;
	resid = uio->uio_resid;

	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return (ENXIO);
	VOP_UNLOCK(vp, 0, td);
	KASSERT(dev->si_refcount > 0,
	    ("spec_write() on un-referenced struct cdev *(%s)", devtoname(dev)));
	if (!(dsw->d_flags & D_NEEDGIANT)) {
		DROP_GIANT();
		error = dsw->d_write(dev, uio, ap->a_ioflag);
		PICKUP_GIANT();
	} else
		error = dsw->d_write(dev, uio, ap->a_ioflag);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, td);
	dev_relthread(dev);
	if (uio->uio_resid != resid || (error == 0 && resid != 0)) {
		vfs_timestamp(&dev->si_ctime);
		dev->si_mtime = dev->si_ctime;
	}
	return (error);
}

/*
 * Device ioctl operation.
 */
/* ARGSUSED */
static int
spec_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long  a_command;
		caddr_t  a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	struct cdev *dev;
	int error;
	struct cdevsw *dsw;

	dev = ap->a_vp->v_rdev;
	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return (ENXIO);
	KASSERT(dev->si_refcount > 0,
	    ("spec_ioctl() on un-referenced struct cdev *(%s)", devtoname(dev)));
	if (!(dsw->d_flags & D_NEEDGIANT)) {
		DROP_GIANT();
		error = dsw->d_ioctl(dev, ap->a_command,
		    ap->a_data, ap->a_fflag, ap->a_td);
		PICKUP_GIANT();
	} else 
		error = dsw->d_ioctl(dev, ap->a_command,
		    ap->a_data, ap->a_fflag, ap->a_td);
	dev_relthread(dev);
	if (error == ENOIOCTL)
		error = ENOTTY;
	return (error);
}

/* ARGSUSED */
static int
spec_poll(ap)
	struct vop_poll_args /* {
		struct vnode *a_vp;
		int  a_events;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	struct cdev *dev;
	struct cdevsw *dsw;
	int error;

	dev = ap->a_vp->v_rdev;
	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return(0);
	KASSERT(dev->si_refcount > 0,
	    ("spec_poll() on un-referenced struct cdev *(%s)", devtoname(dev)));
	if (!(dsw->d_flags & D_NEEDGIANT)) {
		/* XXX: not yet DROP_GIANT(); */
		error = dsw->d_poll(dev, ap->a_events, ap->a_td);
		/* XXX: not yet PICKUP_GIANT(); */
	} else
		error = dsw->d_poll(dev, ap->a_events, ap->a_td);
	dev_relthread(dev);
	return(error);
}

/* ARGSUSED */
static int
spec_kqfilter(ap)
	struct vop_kqfilter_args /* {
		struct vnode *a_vp;
		struct knote *a_kn;
	} */ *ap;
{
	struct cdev *dev;
	struct cdevsw *dsw;
	int error;

	dev = ap->a_vp->v_rdev;
	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return(0);
	KASSERT(dev->si_refcount > 0,
	    ("spec_kqfilter() on un-referenced struct cdev *(%s)", devtoname(dev)));
	if (!(dsw->d_flags & D_NEEDGIANT)) {
		DROP_GIANT();
		error = dsw->d_kqfilter(dev, ap->a_kn);
		PICKUP_GIANT();
	} else
		error = dsw->d_kqfilter(dev, ap->a_kn);
	dev_relthread(dev);
	return (error);
}

/*
 * Synch buffers associated with a block device
 */
/* ARGSUSED */
static int
spec_fsync(ap)
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		struct ucred *a_cred;
		int  a_waitfor;
		struct thread *a_td;
	} */ *ap;
{
	if (!vn_isdisk(ap->a_vp, NULL))
		return (0);

	return (vop_stdfsync(ap));
}

static int doslowdown = 0;
SYSCTL_INT(_debug, OID_AUTO, doslowdown, CTLFLAG_RW, &doslowdown, 0, "");

/*
 * Just call the device strategy routine
 */
static int
spec_specstrategy(ap)
	struct vop_specstrategy_args /* {
		struct vnode *a_vp;
		struct buf *a_bp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;
	struct mount *mp;
	struct thread *td = curthread;
	
	KASSERT(ap->a_vp->v_rdev == ap->a_bp->b_dev,
	    ("%s, dev %s != %s", __func__,
	    devtoname(ap->a_vp->v_rdev),
	    devtoname(ap->a_bp->b_dev)));
	KASSERT(bp->b_iocmd == BIO_READ || bp->b_iocmd == BIO_WRITE,
	    ("Wrong b_iocmd buf=%p cmd=%d", bp, bp->b_iocmd));

	/*
	 * Slow down disk requests for niced processes.
	 */
	if (doslowdown && td && td->td_proc->p_nice > 0) {
		msleep(td, NULL, PPAUSE | PCATCH, "ioslow",
		    td->td_proc->p_nice);
	}
	/*
	 * Collect statistics on synchronous and asynchronous read
	 * and write counts for disks that have associated filesystems.
	 */
	if (vn_isdisk(vp, NULL) && (mp = vp->v_rdev->si_mountpoint) != NULL) {
		if (bp->b_iocmd == BIO_WRITE) {
			if (bp->b_lock.lk_lockholder == LK_KERNPROC)
				mp->mnt_stat.f_asyncwrites++;
			else
				mp->mnt_stat.f_syncwrites++;
		} else {
			if (bp->b_lock.lk_lockholder == LK_KERNPROC)
				mp->mnt_stat.f_asyncreads++;
			else
				mp->mnt_stat.f_syncreads++;
		}
	}

	dev_strategy(bp);	
		
	return (0);
}

/*
 * Device close routine
 */
/* ARGSUSED */
static int
spec_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp, *oldvp;
	struct thread *td = ap->a_td;
	struct cdev *dev = vp->v_rdev;
	struct cdevsw *dsw;
	int error;

	/*
	 * Hack: a tty device that is a controlling terminal
	 * has a reference from the session structure.
	 * We cannot easily tell that a character device is
	 * a controlling terminal, unless it is the closing
	 * process' controlling terminal.  In that case,
	 * if the reference count is 2 (this last descriptor
	 * plus the session), release the reference from the session.
	 */

	/*
	 * This needs to be rewritten to take the vp interlock into
	 * consideration.
	 */

	oldvp = NULL;
	sx_xlock(&proctree_lock);
	if (td && vp == td->td_proc->p_session->s_ttyvp) {
		SESS_LOCK(td->td_proc->p_session);
		VI_LOCK(vp);
		if (count_dev(dev) == 2 && (vp->v_iflag & VI_XLOCK) == 0) {
			td->td_proc->p_session->s_ttyvp = NULL;
			oldvp = vp;
		}
		VI_UNLOCK(vp);
		SESS_UNLOCK(td->td_proc->p_session);
	}
	sx_xunlock(&proctree_lock);
	if (oldvp != NULL)
		vrele(oldvp);
	/*
	 * We do not want to really close the device if it
	 * is still in use unless we are trying to close it
	 * forcibly. Since every use (buffer, vnode, swap, cmap)
	 * holds a reference to the vnode, and because we mark
	 * any other vnodes that alias this device, when the
	 * sum of the reference counts on all the aliased
	 * vnodes descends to one, we are on last close.
	 */
	dsw = dev_refthread(dev);
	if (dsw == NULL)
		return (ENXIO);
	VI_LOCK(vp);
	if (vp->v_iflag & VI_XLOCK) {
		/* Forced close. */
	} else if (dsw->d_flags & D_TRACKCLOSE) {
		/* Keep device updated on status. */
	} else if (count_dev(dev) > 1) {
		VI_UNLOCK(vp);
		dev_relthread(dev);
		return (0);
	}
	VI_UNLOCK(vp);
	KASSERT(dev->si_refcount > 0,
	    ("spec_close() on un-referenced struct cdev *(%s)", devtoname(dev)));
	if (!(dsw->d_flags & D_NEEDGIANT)) {
		DROP_GIANT();
		error = dsw->d_close(dev, ap->a_fflag, S_IFCHR, td);
		PICKUP_GIANT();
	} else
		error = dsw->d_close(dev, ap->a_fflag, S_IFCHR, td);
	dev_relthread(dev);
	return (error);
}

/*
 * Print out the contents of a special device vnode.
 */
static int
spec_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("\tdev %s\n", devtoname(ap->a_vp->v_rdev));
	return (0);
}

/*
 * Special device advisory byte-level locks.
 */
/* ARGSUSED */
static int
spec_advlock(ap)
	struct vop_advlock_args /* {
		struct vnode *a_vp;
		caddr_t  a_id;
		int  a_op;
		struct flock *a_fl;
		int  a_flags;
	} */ *ap;
{

	return (ap->a_flags & F_FLOCK ? EOPNOTSUPP : EINVAL);
}
