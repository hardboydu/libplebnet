/*
 * Copyright (c) 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2000
 *	Poul-Henning Kamp.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Neither the name of the University nor the names of its contributors
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
 *	@(#)kernfs_vfsops.c	8.10 (Berkeley) 5/14/95
 * From: FreeBSD: src/sys/miscfs/kernfs/kernfs_vfsops.c 1.36
 *
 * $FreeBSD$
 */

#include "opt_devfs.h"
#ifndef NODEVFS

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <fs/devfs/devfs.h>

MALLOC_DEFINE(M_DEVFS, "DEVFS", "DEVFS data");

static int	devfs_mount(struct mount *mp, struct nameidata *ndp,
				  struct thread *td);
static int	devfs_unmount(struct mount *mp, int mntflags,
				  struct thread *td);
static int	devfs_root(struct mount *mp, struct vnode **vpp);
static int	devfs_statfs(struct mount *mp, struct statfs *sbp,
				   struct thread *td);

/*
 * Mount the filesystem
 */
static int
devfs_mount(mp, ndp, td)
	struct mount *mp;
	struct nameidata *ndp;
	struct thread *td;
{
	int error;
	struct devfs_mount *fmp;
	struct vnode *rvp;

	error = 0;
	/*
	 * XXX: flag changes.
	 */
	if (mp->mnt_flag & MNT_UPDATE)
		return (EOPNOTSUPP);

	MALLOC(fmp, struct devfs_mount *, sizeof(struct devfs_mount),
	    M_DEVFS, M_WAITOK | M_ZERO);
	lockinit(&fmp->dm_lock, PVFS, "devfs", 0, LK_NOPAUSE);

	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_data = (qaddr_t) fmp;
	vfs_getnewfsid(mp);

	fmp->dm_inode = DEVFSINOMOUNT;

	fmp->dm_rootdir = devfs_vmkdir("(root)", 6, NULL);
	fmp->dm_rootdir->de_inode = 2;
	fmp->dm_basedir = fmp->dm_rootdir;

	error = devfs_root(mp, &rvp);
	if (error) {
		lockdestroy(&fmp->dm_lock);
		FREE(fmp, M_DEVFS);
		return (error);
	}
	VOP_UNLOCK(rvp, 0, td);

	bzero(mp->mnt_stat.f_mntfromname, MNAMELEN);
	bcopy("devfs", mp->mnt_stat.f_mntfromname, sizeof("devfs"));
	(void)devfs_statfs(mp, &mp->mnt_stat, td);

	return (0);
}

static int
devfs_unmount(mp, mntflags, td)
	struct mount *mp;
	int mntflags;
	struct thread *td;
{
	int error;
	int flags = 0;
	struct devfs_mount *fmp;

	fmp = VFSTODEVFS(mp);
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
	/* There is 1 extra root vnode reference from devfs_mount(). */
	error = vflush(mp, 1, flags);
	if (error)
		return (error);
	devfs_purge(fmp->dm_rootdir);
	mp->mnt_data = 0;
	lockdestroy(&fmp->dm_lock);
	free(fmp, M_DEVFS);
	return 0;
}

/* Return locked reference to root.  */

static int
devfs_root(mp, vpp)
	struct mount *mp;
	struct vnode **vpp;
{
	int error;
	struct thread *td;
	struct vnode *vp;
	struct devfs_mount *dmp;

	td = curthread;					/* XXX */
	dmp = VFSTODEVFS(mp);
	error = devfs_allocv(dmp->dm_rootdir, mp, &vp, td);
	if (error)
		return (error);
	vp->v_flag |= VROOT;
	*vpp = vp;
	return (0);
}

static int
devfs_statfs(mp, sbp, td)
	struct mount *mp;
	struct statfs *sbp;
	struct thread *td;
{

	sbp->f_flags = 0;
	sbp->f_bsize = DEV_BSIZE;
	sbp->f_iosize = DEV_BSIZE;
	sbp->f_blocks = 2;		/* 1K to keep df happy */
	sbp->f_bfree = 0;
	sbp->f_bavail = 0;
	sbp->f_files = 0;
	sbp->f_ffree = 0;
	if (sbp != &mp->mnt_stat) {
		sbp->f_type = mp->mnt_vfc->vfc_typenum;
		bcopy(&mp->mnt_stat.f_fsid, &sbp->f_fsid, sizeof(sbp->f_fsid));
		bcopy(mp->mnt_stat.f_mntonname, sbp->f_mntonname, MNAMELEN);
		bcopy(mp->mnt_stat.f_mntfromname, sbp->f_mntfromname, MNAMELEN);
	}
	return (0);
}

static struct vfsops devfs_vfsops = {
	NULL,
	vfs_stdstart,
	devfs_unmount,
	devfs_root,
	vfs_stdquotactl,
	devfs_statfs,
	vfs_stdsync,
	vfs_stdvget,
	vfs_stdfhtovp,
	vfs_stdcheckexp,
	vfs_stdvptofh,
	vfs_stdinit,
	vfs_stduninit,
	vfs_stdextattrctl,
	devfs_mount,
};

VFS_SET(devfs_vfsops, devfs, VFCF_SYNTHETIC);
#endif
