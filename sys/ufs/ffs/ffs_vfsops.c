/*
 * Copyright (c) 1989, 1991, 1993, 1994
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
 *	@(#)ffs_vfsops.c	8.31 (Berkeley) 5/20/95
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_mac.h"
#include "opt_quota.h"
#include "opt_ufs.h"
#include "opt_ffs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/disk.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <ufs/ufs/extattr.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

#include <vm/vm.h>
#include <vm/uma.h>
#include <vm/vm_page.h>

uma_zone_t uma_inode, uma_ufs1, uma_ufs2;

static int	ffs_sbupdate(struct ufsmount *, int);
static int	ffs_reload(struct mount *, struct thread *);
static int	ffs_mountfs(struct vnode *, struct mount *, struct thread *);
static void	ffs_oldfscompat_read(struct fs *, struct ufsmount *,
		    ufs2_daddr_t);
static void	ffs_oldfscompat_write(struct fs *, struct ufsmount *);
static void	ffs_ifree(struct ufsmount *ump, struct inode *ip);
static vfs_init_t ffs_init;
static vfs_uninit_t ffs_uninit;
static vfs_extattrctl_t ffs_extattrctl;
static vfs_omount_t ffs_omount;

static struct vfsops ufs_vfsops = {
	.vfs_extattrctl =	ffs_extattrctl,
	.vfs_fhtovp =		ffs_fhtovp,
	.vfs_init =		ffs_init,
	.vfs_omount =		ffs_omount,
	.vfs_quotactl =		ufs_quotactl,
	.vfs_root =		ufs_root,
	.vfs_start =		ufs_start,
	.vfs_statfs =		ffs_statfs,
	.vfs_sync =		ffs_sync,
	.vfs_uninit =		ffs_uninit,
	.vfs_unmount =		ffs_unmount,
	.vfs_vget =		ffs_vget,
	.vfs_vptofh =		ffs_vptofh,
};

VFS_SET(ufs_vfsops, ufs, 0);

static b_strategy_t ffs_geom_strategy;

static struct buf_ops ffs_ops = {
	.bop_name =	"FFS",
	.bop_write =	bufwrite,
	.bop_strategy =	ffs_geom_strategy,
};

/*
 * ffs_omount
 *
 * Called when mounting local physical media
 *
 * PARAMETERS:
 *		mountroot
 *			mp	mount point structure
 *			path	NULL (flag for root mount!!!)
 *			data	<unused>
 *			ndp	<unused>
 *			p	process (user credentials check [statfs])
 *
 *		mount
 *			mp	mount point structure
 *			path	path to mount point
 *			data	pointer to argument struct in user space
 *			ndp	mount point namei() return (used for
 *				credentials on reload), reused to look
 *				up block device.
 *			p	process (user credentials check)
 *
 * RETURNS:	0	Success
 *		!0	error number (errno.h)
 *
 * LOCK STATE:
 *
 *		ENTRY
 *			mount point is locked
 *		EXIT
 *			mount point is locked
 *
 * NOTES:
 *		A NULL path can be used for a flag since the mount
 *		system call will fail with EFAULT in copyinstr in
 *		namei() if it is a genuine NULL from the user.
 */
static int
ffs_omount(struct mount *mp, char *path, caddr_t data, struct thread *td)
{
	size_t size;
	struct vnode *devvp, *rootvp;
	struct ufs_args args;
	struct ufsmount *ump = 0;
	struct fs *fs;
	int error, flags;
	mode_t accessmode;
	struct nameidata ndp;

	if (uma_inode == NULL) {
		uma_inode = uma_zcreate("FFS inode",
		    sizeof(struct inode), NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, 0);
		uma_ufs1 = uma_zcreate("FFS1 dinode",
		    sizeof(struct ufs1_dinode), NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, 0);
		uma_ufs2 = uma_zcreate("FFS2 dinode",
		    sizeof(struct ufs2_dinode), NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, 0);
	}
	/*
	 * Use NULL path to indicate we are mounting the root filesystem.
	 */
	if (path == NULL) {
		if ((error = bdevvp(rootdev, &rootvp))) {
			printf("ffs_mountroot: can't find rootvp\n");
			return (error);
		}

		if ((error = ffs_mountfs(rootvp, mp, td)) != 0)
			return (error);
		return (0);
	}

	/*
	 * Mounting non-root filesystem or updating a filesystem
	 */
	if ((error = copyin(data, (caddr_t)&args, sizeof(struct ufs_args)))!= 0)
		return (error);

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		ump = VFSTOUFS(mp);
		fs = ump->um_fs;
		devvp = ump->um_devvp;
		if (fs->fs_ronly == 0 && (mp->mnt_flag & MNT_RDONLY)) {
			if ((error = vn_start_write(NULL, &mp, V_WAIT)) != 0)
				return (error);
			/*
			 * Flush any dirty data.
			 */
			if ((error = VFS_SYNC(mp, MNT_WAIT,
			    td->td_ucred, td)) != 0) {
				vn_finished_write(mp);
				return (error);
			}
			/*
			 * Check for and optionally get rid of files open
			 * for writing.
			 */
			flags = WRITECLOSE;
			if (mp->mnt_flag & MNT_FORCE)
				flags |= FORCECLOSE;
			if (mp->mnt_flag & MNT_SOFTDEP) {
				error = softdep_flushfiles(mp, flags, td);
			} else {
				error = ffs_flushfiles(mp, flags, td);
			}
			if (error) {
				vn_finished_write(mp);
				return (error);
			}
			if (fs->fs_pendingblocks != 0 ||
			    fs->fs_pendinginodes != 0) {
				printf("%s: %s: blocks %jd files %d\n",
				    fs->fs_fsmnt, "update error",
				    (intmax_t)fs->fs_pendingblocks,
				    fs->fs_pendinginodes);
				fs->fs_pendingblocks = 0;
				fs->fs_pendinginodes = 0;
			}
			fs->fs_ronly = 1;
			if ((fs->fs_flags & (FS_UNCLEAN | FS_NEEDSFSCK)) == 0)
				fs->fs_clean = 1;
			if ((error = ffs_sbupdate(ump, MNT_WAIT)) != 0) {
				fs->fs_ronly = 0;
				fs->fs_clean = 0;
				vn_finished_write(mp);
				return (error);
			}
			vn_finished_write(mp);
		}
		if ((mp->mnt_flag & MNT_RELOAD) &&
		    (error = ffs_reload(mp, td)) != 0)
			return (error);
		if (fs->fs_ronly && (mp->mnt_kern_flag & MNTK_WANTRDWR)) {
			/*
			 * If upgrade to read-write by non-root, then verify
			 * that user has necessary permissions on the device.
			 */
			if (suser(td)) {
				vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, td);
				if ((error = VOP_ACCESS(devvp, VREAD | VWRITE,
				    td->td_ucred, td)) != 0) {
					VOP_UNLOCK(devvp, 0, td);
					return (error);
				}
				VOP_UNLOCK(devvp, 0, td);
			}
			fs->fs_flags &= ~FS_UNCLEAN;
			if (fs->fs_clean == 0) {
				fs->fs_flags |= FS_UNCLEAN;
				if ((mp->mnt_flag & MNT_FORCE) ||
				    ((fs->fs_flags & FS_NEEDSFSCK) == 0 &&
				     (fs->fs_flags & FS_DOSOFTDEP))) {
					printf("WARNING: %s was not %s\n",
					   fs->fs_fsmnt, "properly dismounted");
				} else {
					printf(
"WARNING: R/W mount of %s denied.  Filesystem is not clean - run fsck\n",
					    fs->fs_fsmnt);
					return (EPERM);
				}
			}
			if ((error = vn_start_write(NULL, &mp, V_WAIT)) != 0)
				return (error);
			fs->fs_ronly = 0;
			fs->fs_clean = 0;
			if ((error = ffs_sbupdate(ump, MNT_WAIT)) != 0) {
				vn_finished_write(mp);
				return (error);
			}
			/* check to see if we need to start softdep */
			if ((fs->fs_flags & FS_DOSOFTDEP) &&
			    (error = softdep_mount(devvp, mp, fs, td->td_ucred))){
				vn_finished_write(mp);
				return (error);
			}
			if (fs->fs_snapinum[0] != 0)
				ffs_snapshot_mount(mp);
			vn_finished_write(mp);
		}
		/*
		 * Soft updates is incompatible with "async",
		 * so if we are doing softupdates stop the user
		 * from setting the async flag in an update.
		 * Softdep_mount() clears it in an initial mount 
		 * or ro->rw remount.
		 */
		if (mp->mnt_flag & MNT_SOFTDEP)
			mp->mnt_flag &= ~MNT_ASYNC;
		/*
		 * If not updating name, process export requests.
		 */
		if (args.fspec == 0)
			return (vfs_export(mp, &args.export));
		/*
		 * If this is a snapshot request, take the snapshot.
		 */
		if (mp->mnt_flag & MNT_SNAPSHOT)
			return (ffs_snapshot(mp, args.fspec));
	}

	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible disk device.
	 */
	NDINIT(&ndp, LOOKUP, FOLLOW, UIO_USERSPACE, args.fspec, td);
	if ((error = namei(&ndp)) != 0)
		return (error);
	NDFREE(&ndp, NDF_ONLY_PNBUF);
	devvp = ndp.ni_vp;
	if (!vn_isdisk(devvp, &error)) {
		vrele(devvp);
		return (error);
	}

	/*
	 * If mount by non-root, then verify that user has necessary
	 * permissions on the device.
	 */
	if (suser(td)) {
		accessmode = VREAD;
		if ((mp->mnt_flag & MNT_RDONLY) == 0)
			accessmode |= VWRITE;
		vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, td);
		if ((error = VOP_ACCESS(devvp, accessmode, td->td_ucred, td))!= 0){
			vput(devvp);
			return (error);
		}
		VOP_UNLOCK(devvp, 0, td);
	}

	if (mp->mnt_flag & MNT_UPDATE) {
		/*
		 * Update only
		 *
		 * If it's not the same vnode, or at least the same device
		 * then it's not correct.
		 */

		if (devvp != ump->um_devvp &&
		    devvp->v_rdev != ump->um_devvp->v_rdev)
			error = EINVAL;	/* needs translation */
		vrele(devvp);
		if (error)
			return (error);
	} else {
		/*
		 * New mount
		 *
		 * We need the name for the mount point (also used for
		 * "last mounted on") copied in. If an error occurs,
		 * the mount point is discarded by the upper level code.
		 * Note that vfs_mount() populates f_mntonname for us.
		 */
		if ((error = ffs_mountfs(devvp, mp, td)) != 0) {
			vrele(devvp);
			return (error);
		}
	}
	/*
	 * Save "mounted from" device name info for mount point (NULL pad).
	 */
	copyinstr(args.fspec, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, &size);
	bzero( mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	return (0);
}

/*
 * Reload all incore data for a filesystem (used after running fsck on
 * the root filesystem and finding things to fix). The filesystem must
 * be mounted read-only.
 *
 * Things to do to update the mount:
 *	1) invalidate all cached meta-data.
 *	2) re-read superblock from disk.
 *	3) re-read summary information from disk.
 *	4) invalidate all inactive vnodes.
 *	5) invalidate all cached file data.
 *	6) re-read inode data for all active vnodes.
 */
static int
ffs_reload(struct mount *mp, struct thread *td)
{
	struct vnode *vp, *nvp, *devvp;
	struct inode *ip;
	void *space;
	struct buf *bp;
	struct fs *fs, *newfs;
	ufs2_daddr_t sblockloc;
	int i, blks, size, error;
	int32_t *lp;

	if ((mp->mnt_flag & MNT_RDONLY) == 0)
		return (EINVAL);
	/*
	 * Step 1: invalidate all cached meta-data.
	 */
	devvp = VFSTOUFS(mp)->um_devvp;
	vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, td);
	if (vinvalbuf(devvp, 0, td->td_ucred, td, 0, 0) != 0)
		panic("ffs_reload: dirty1");
	
	vfs_object_create(devvp, td, td->td_ucred);
	VOP_UNLOCK(devvp, 0, td);

	/*
	 * Step 2: re-read superblock from disk.
	 */
	fs = VFSTOUFS(mp)->um_fs;
	if ((error = bread(devvp, btodb(fs->fs_sblockloc), fs->fs_sbsize,
	    NOCRED, &bp)) != 0)
		return (error);
	newfs = (struct fs *)bp->b_data;
	if ((newfs->fs_magic != FS_UFS1_MAGIC &&
	     newfs->fs_magic != FS_UFS2_MAGIC) ||
	    newfs->fs_bsize > MAXBSIZE ||
	    newfs->fs_bsize < sizeof(struct fs)) {
			brelse(bp);
			return (EIO);		/* XXX needs translation */
	}
	/*
	 * Copy pointer fields back into superblock before copying in	XXX
	 * new superblock. These should really be in the ufsmount.	XXX
	 * Note that important parameters (eg fs_ncg) are unchanged.
	 */
	newfs->fs_csp = fs->fs_csp;
	newfs->fs_maxcluster = fs->fs_maxcluster;
	newfs->fs_contigdirs = fs->fs_contigdirs;
	newfs->fs_active = fs->fs_active;
	/* The file system is still read-only. */
	newfs->fs_ronly = 1;
	sblockloc = fs->fs_sblockloc;
	bcopy(newfs, fs, (u_int)fs->fs_sbsize);
	brelse(bp);
	mp->mnt_maxsymlinklen = fs->fs_maxsymlinklen;
	ffs_oldfscompat_read(fs, VFSTOUFS(mp), sblockloc);
	if (fs->fs_pendingblocks != 0 || fs->fs_pendinginodes != 0) {
		printf("%s: reload pending error: blocks %jd files %d\n",
		    fs->fs_fsmnt, (intmax_t)fs->fs_pendingblocks,
		    fs->fs_pendinginodes);
		fs->fs_pendingblocks = 0;
		fs->fs_pendinginodes = 0;
	}

	/*
	 * Step 3: re-read summary information from disk.
	 */
	blks = howmany(fs->fs_cssize, fs->fs_fsize);
	space = fs->fs_csp;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		error = bread(devvp, fsbtodb(fs, fs->fs_csaddr + i), size,
		    NOCRED, &bp);
		if (error)
			return (error);
		bcopy(bp->b_data, space, (u_int)size);
		space = (char *)space + size;
		brelse(bp);
	}
	/*
	 * We no longer know anything about clusters per cylinder group.
	 */
	if (fs->fs_contigsumsize > 0) {
		lp = fs->fs_maxcluster;
		for (i = 0; i < fs->fs_ncg; i++)
			*lp++ = fs->fs_contigsumsize;
	}

loop:
	MNT_ILOCK(mp);
	MNT_VNODE_FOREACH(vp, mp, nvp) {
		VI_LOCK(vp);
		if (vp->v_iflag & VI_XLOCK) {
			VI_UNLOCK(vp);
			continue;
		}
		MNT_IUNLOCK(mp);
		/*
		 * Step 4: invalidate all inactive vnodes.
		 */
		if (vp->v_usecount == 0) {
			vgonel(vp, td);
			goto loop;
		}
		/*
		 * Step 5: invalidate all cached file data.
		 */
		if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, td)) {
			goto loop;
		}
		if (vinvalbuf(vp, 0, td->td_ucred, td, 0, 0))
			panic("ffs_reload: dirty2");
		/*
		 * Step 6: re-read inode data for all active vnodes.
		 */
		ip = VTOI(vp);
		error =
		    bread(devvp, fsbtodb(fs, ino_to_fsba(fs, ip->i_number)),
		    (int)fs->fs_bsize, NOCRED, &bp);
		if (error) {
			VOP_UNLOCK(vp, 0, td);
			vrele(vp);
			return (error);
		}
		ffs_load_inode(bp, ip, fs, ip->i_number);
		ip->i_effnlink = ip->i_nlink;
		brelse(bp);
		VOP_UNLOCK(vp, 0, td);
		vrele(vp);
		MNT_ILOCK(mp);
	}
	MNT_IUNLOCK(mp);
	return (0);
}

/*
 * Possible superblock locations ordered from most to least likely.
 */
static int sblock_try[] = SBLOCKSEARCH;

/*
 * Common code for mount and mountroot
 */
static int
ffs_mountfs(devvp, mp, td)
	struct vnode *devvp;
	struct mount *mp;
	struct thread *td;
{
	struct ufsmount *ump;
	struct buf *bp;
	struct fs *fs;
	struct cdev *dev;
	void *space;
	ufs2_daddr_t sblockloc;
	int error, i, blks, size, ronly;
	int32_t *lp;
	struct ucred *cred;
	size_t strsize;

	dev = devvp->v_rdev;
	cred = td ? td->td_ucred : NOCRED;
	/*
	 * Disallow multiple mounts of the same device.
	 * Disallow mounting of a device that is currently in use
	 * (except for root, which might share swap device for miniroot).
	 * Flush out any old buffers remaining from a previous use.
	 */
	error = vfs_mountedon(devvp);
	if (error)
		return (error);
	if (vcount(devvp) > 1)
		return (EBUSY);
	vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, td);
	error = vinvalbuf(devvp, V_SAVE, cred, td, 0, 0);
	if (error) {
		VOP_UNLOCK(devvp, 0, td);
		return (error);
	}

	/*
	 * Note that it is optional that the backing device be VMIOed.  This
	 * increases the opportunity for metadata caching.
	 */
	vfs_object_create(devvp, td, cred);

	ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
	/*
	 * XXX: open the device with read and write access even if only
	 * read access is needed now.  Write access is needed if the
	 * filesystem is ever mounted read/write, and we don't change the
	 * access mode for remounts.
	 */
#ifdef notyet
	error = VOP_OPEN(devvp, ronly ? FREAD : FREAD | FWRITE, FSCRED, td, -1);
#else
	error = VOP_OPEN(devvp, FREAD | FWRITE, FSCRED, td, -1);
#endif
	VOP_UNLOCK(devvp, 0, td);
	if (error)
		return (error);
	if (devvp->v_rdev->si_iosize_max != 0)
		mp->mnt_iosize_max = devvp->v_rdev->si_iosize_max;
	if (mp->mnt_iosize_max > MAXPHYS)
		mp->mnt_iosize_max = MAXPHYS;

	devvp->v_bufobj.bo_ops = &ffs_ops;

	bp = NULL;
	ump = NULL;
	fs = NULL;
	sblockloc = 0;
	/*
	 * Try reading the superblock in each of its possible locations.
	 */
	for (i = 0; sblock_try[i] != -1; i++) {
		if ((error = bread(devvp, sblock_try[i] / DEV_BSIZE, SBLOCKSIZE,
		    cred, &bp)) != 0)
			goto out;
		fs = (struct fs *)bp->b_data;
		sblockloc = sblock_try[i];
		if ((fs->fs_magic == FS_UFS1_MAGIC ||
		     (fs->fs_magic == FS_UFS2_MAGIC &&
		      (fs->fs_sblockloc == sblockloc ||
		       (fs->fs_old_flags & FS_FLAGS_UPDATED) == 0))) &&
		    fs->fs_bsize <= MAXBSIZE &&
		    fs->fs_bsize >= sizeof(struct fs))
			break;
		brelse(bp);
		bp = NULL;
	}
	if (sblock_try[i] == -1) {
		error = EINVAL;		/* XXX needs translation */
		goto out;
	}
	fs->fs_fmod = 0;
	fs->fs_flags &= ~FS_INDEXDIRS;	/* no support for directory indicies */
	fs->fs_flags &= ~FS_UNCLEAN;
	if (fs->fs_clean == 0) {
		fs->fs_flags |= FS_UNCLEAN;
		if (ronly || (mp->mnt_flag & MNT_FORCE) ||
		    ((fs->fs_flags & FS_NEEDSFSCK) == 0 &&
		     (fs->fs_flags & FS_DOSOFTDEP))) {
			printf(
"WARNING: %s was not properly dismounted\n",
			    fs->fs_fsmnt);
		} else {
			printf(
"WARNING: R/W mount of %s denied.  Filesystem is not clean - run fsck\n",
			    fs->fs_fsmnt);
			error = EPERM;
			goto out;
		}
		if ((fs->fs_pendingblocks != 0 || fs->fs_pendinginodes != 0) &&
		    (mp->mnt_flag & MNT_FORCE)) {
			printf("%s: lost blocks %jd files %d\n", fs->fs_fsmnt,
			    (intmax_t)fs->fs_pendingblocks,
			    fs->fs_pendinginodes);
			fs->fs_pendingblocks = 0;
			fs->fs_pendinginodes = 0;
		}
	}
	if (fs->fs_pendingblocks != 0 || fs->fs_pendinginodes != 0) {
		printf("%s: mount pending error: blocks %jd files %d\n",
		    fs->fs_fsmnt, (intmax_t)fs->fs_pendingblocks,
		    fs->fs_pendinginodes);
		fs->fs_pendingblocks = 0;
		fs->fs_pendinginodes = 0;
	}
	ump = malloc(sizeof *ump, M_UFSMNT, M_WAITOK | M_ZERO);
	ump->um_fs = malloc((u_long)fs->fs_sbsize, M_UFSMNT, M_WAITOK);
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		ump->um_fstype = UFS1;
		ump->um_balloc = ffs_balloc_ufs1;
	} else {
		ump->um_fstype = UFS2;
		ump->um_balloc = ffs_balloc_ufs2;
	}
	ump->um_blkatoff = ffs_blkatoff;
	ump->um_truncate = ffs_truncate;
	ump->um_update = ffs_update;
	ump->um_valloc = ffs_valloc;
	ump->um_vfree = ffs_vfree;
	ump->um_ifree = ffs_ifree;
	bcopy(bp->b_data, ump->um_fs, (u_int)fs->fs_sbsize);
	if (fs->fs_sbsize < SBLOCKSIZE)
		bp->b_flags |= B_INVAL | B_NOCACHE;
	brelse(bp);
	bp = NULL;
	fs = ump->um_fs;
	ffs_oldfscompat_read(fs, ump, sblockloc);
	fs->fs_ronly = ronly;
	size = fs->fs_cssize;
	blks = howmany(size, fs->fs_fsize);
	if (fs->fs_contigsumsize > 0)
		size += fs->fs_ncg * sizeof(int32_t);
	size += fs->fs_ncg * sizeof(u_int8_t);
	space = malloc((u_long)size, M_UFSMNT, M_WAITOK);
	fs->fs_csp = space;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		if ((error = bread(devvp, fsbtodb(fs, fs->fs_csaddr + i), size,
		    cred, &bp)) != 0) {
			free(fs->fs_csp, M_UFSMNT);
			goto out;
		}
		bcopy(bp->b_data, space, (u_int)size);
		space = (char *)space + size;
		brelse(bp);
		bp = NULL;
	}
	if (fs->fs_contigsumsize > 0) {
		fs->fs_maxcluster = lp = space;
		for (i = 0; i < fs->fs_ncg; i++)
			*lp++ = fs->fs_contigsumsize;
		space = lp;
	}
	size = fs->fs_ncg * sizeof(u_int8_t);
	fs->fs_contigdirs = (u_int8_t *)space;
	bzero(fs->fs_contigdirs, size);
	fs->fs_active = NULL;
	mp->mnt_data = (qaddr_t)ump;
	mp->mnt_stat.f_fsid.val[0] = fs->fs_id[0];
	mp->mnt_stat.f_fsid.val[1] = fs->fs_id[1];
	if (fs->fs_id[0] == 0 || fs->fs_id[1] == 0 || 
	    vfs_getvfs(&mp->mnt_stat.f_fsid)) 
		vfs_getnewfsid(mp);
	mp->mnt_maxsymlinklen = fs->fs_maxsymlinklen;
	mp->mnt_flag |= MNT_LOCAL;
	if ((fs->fs_flags & FS_MULTILABEL) != 0)
#ifdef MAC
		mp->mnt_flag |= MNT_MULTILABEL;
#else
		printf(
"WARNING: %s: multilabel flag on fs but no MAC support\n",
		    fs->fs_fsmnt);
#endif
	if ((fs->fs_flags & FS_ACLS) != 0)
#ifdef UFS_ACL
		mp->mnt_flag |= MNT_ACLS;
#else
		printf(
"WARNING: %s: ACLs flag on fs but no ACLs support\n",
		    fs->fs_fsmnt);
#endif
	ump->um_mountp = mp;
	ump->um_dev = dev;
	ump->um_devvp = devvp;
	ump->um_nindir = fs->fs_nindir;
	ump->um_bptrtodb = fs->fs_fsbtodb;
	ump->um_seqinc = fs->fs_frag;
	for (i = 0; i < MAXQUOTAS; i++)
		ump->um_quotas[i] = NULLVP;
#ifdef UFS_EXTATTR
	ufs_extattr_uepm_init(&ump->um_extattr);
#endif
	devvp->v_rdev->si_mountpoint = mp;

	/*
	 * Set FS local "last mounted on" information (NULL pad)
	 */
	copystr(	mp->mnt_stat.f_mntonname,	/* mount point*/
			fs->fs_fsmnt,			/* copy area*/
			sizeof(fs->fs_fsmnt) - 1,	/* max size*/
			&strsize);			/* real size*/
	bzero( fs->fs_fsmnt + strsize, sizeof(fs->fs_fsmnt) - strsize);

	if( mp->mnt_flag & MNT_ROOTFS) {
		/*
		 * Root mount; update timestamp in mount structure.
		 * this will be used by the common root mount code
		 * to update the system clock.
		 */
		mp->mnt_time = fs->fs_time;
	}

	if (ronly == 0) {
		if ((fs->fs_flags & FS_DOSOFTDEP) &&
		    (error = softdep_mount(devvp, mp, fs, cred)) != 0) {
			free(fs->fs_csp, M_UFSMNT);
			goto out;
		}
		if (fs->fs_snapinum[0] != 0)
			ffs_snapshot_mount(mp);
		fs->fs_fmod = 1;
		fs->fs_clean = 0;
		(void) ffs_sbupdate(ump, MNT_WAIT);
	}
	/*
	 * Initialize filesystem stat information in mount struct.
	 */
	(void)VFS_STATFS(mp, &mp->mnt_stat, td);
#ifdef UFS_EXTATTR
#ifdef UFS_EXTATTR_AUTOSTART
	/*
	 *
	 * Auto-starting does the following:
	 *	- check for /.attribute in the fs, and extattr_start if so
	 *	- for each file in .attribute, enable that file with
	 * 	  an attribute of the same name.
	 * Not clear how to report errors -- probably eat them.
	 * This would all happen while the filesystem was busy/not
	 * available, so would effectively be "atomic".
	 */
	(void) ufs_extattr_autostart(mp, td);
#endif /* !UFS_EXTATTR_AUTOSTART */
#endif /* !UFS_EXTATTR */
	return (0);
out:
	devvp->v_rdev->si_mountpoint = NULL;
	if (bp)
		brelse(bp);
	/* XXX: see comment above VOP_OPEN. */
#ifdef notyet
	(void)VOP_CLOSE(devvp, ronly ? FREAD : FREAD | FWRITE, cred, td);
#else
	(void)VOP_CLOSE(devvp, FREAD | FWRITE, cred, td);
#endif
	if (ump) {
		free(ump->um_fs, M_UFSMNT);
		free(ump, M_UFSMNT);
		mp->mnt_data = (qaddr_t)0;
	}
	return (error);
}

#include <sys/sysctl.h>
int bigcgs = 0;
SYSCTL_INT(_debug, OID_AUTO, bigcgs, CTLFLAG_RW, &bigcgs, 0, "");

/*
 * Sanity checks for loading old filesystem superblocks.
 * See ffs_oldfscompat_write below for unwound actions.
 *
 * XXX - Parts get retired eventually.
 * Unfortunately new bits get added.
 */
static void
ffs_oldfscompat_read(fs, ump, sblockloc)
	struct fs *fs;
	struct ufsmount *ump;
	ufs2_daddr_t sblockloc;
{
	off_t maxfilesize;

	/*
	 * If not yet done, update fs_flags location and value of fs_sblockloc.
	 */
	if ((fs->fs_old_flags & FS_FLAGS_UPDATED) == 0) {
		fs->fs_flags = fs->fs_old_flags;
		fs->fs_old_flags |= FS_FLAGS_UPDATED;
		fs->fs_sblockloc = sblockloc;
	}
	/*
	 * If not yet done, update UFS1 superblock with new wider fields.
	 */
	if (fs->fs_magic == FS_UFS1_MAGIC && fs->fs_maxbsize != fs->fs_bsize) {
		fs->fs_maxbsize = fs->fs_bsize;
		fs->fs_time = fs->fs_old_time;
		fs->fs_size = fs->fs_old_size;
		fs->fs_dsize = fs->fs_old_dsize;
		fs->fs_csaddr = fs->fs_old_csaddr;
		fs->fs_cstotal.cs_ndir = fs->fs_old_cstotal.cs_ndir;
		fs->fs_cstotal.cs_nbfree = fs->fs_old_cstotal.cs_nbfree;
		fs->fs_cstotal.cs_nifree = fs->fs_old_cstotal.cs_nifree;
		fs->fs_cstotal.cs_nffree = fs->fs_old_cstotal.cs_nffree;
	}
	if (fs->fs_magic == FS_UFS1_MAGIC &&
	    fs->fs_old_inodefmt < FS_44INODEFMT) {
		fs->fs_maxfilesize = (u_quad_t) 1LL << 39;
		fs->fs_qbmask = ~fs->fs_bmask;
		fs->fs_qfmask = ~fs->fs_fmask;
	}
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		ump->um_savedmaxfilesize = fs->fs_maxfilesize;
		maxfilesize = (u_int64_t)0x40000000 * fs->fs_bsize - 1;
		if (fs->fs_maxfilesize > maxfilesize)
			fs->fs_maxfilesize = maxfilesize;
	}
	/* Compatibility for old filesystems */
	if (fs->fs_avgfilesize <= 0)
		fs->fs_avgfilesize = AVFILESIZ;
	if (fs->fs_avgfpdir <= 0)
		fs->fs_avgfpdir = AFPDIR;
	if (bigcgs) {
		fs->fs_save_cgsize = fs->fs_cgsize;
		fs->fs_cgsize = fs->fs_bsize;
	}
}

/*
 * Unwinding superblock updates for old filesystems.
 * See ffs_oldfscompat_read above for details.
 *
 * XXX - Parts get retired eventually.
 * Unfortunately new bits get added.
 */
static void
ffs_oldfscompat_write(fs, ump)
	struct fs *fs;
	struct ufsmount *ump;
{

	/*
	 * Copy back UFS2 updated fields that UFS1 inspects.
	 */
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		fs->fs_old_time = fs->fs_time;
		fs->fs_old_cstotal.cs_ndir = fs->fs_cstotal.cs_ndir;
		fs->fs_old_cstotal.cs_nbfree = fs->fs_cstotal.cs_nbfree;
		fs->fs_old_cstotal.cs_nifree = fs->fs_cstotal.cs_nifree;
		fs->fs_old_cstotal.cs_nffree = fs->fs_cstotal.cs_nffree;
		fs->fs_maxfilesize = ump->um_savedmaxfilesize;
	}
	if (bigcgs) {
		fs->fs_cgsize = fs->fs_save_cgsize;
		fs->fs_save_cgsize = 0;
	}
}

/*
 * unmount system call
 */
int
ffs_unmount(mp, mntflags, td)
	struct mount *mp;
	int mntflags;
	struct thread *td;
{
	struct ufsmount *ump = VFSTOUFS(mp);
	struct fs *fs;
	int error, flags;

	flags = 0;
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
	}
#ifdef UFS_EXTATTR
	if ((error = ufs_extattr_stop(mp, td))) {
		if (error != EOPNOTSUPP)
			printf("ffs_unmount: ufs_extattr_stop returned %d\n",
			    error);
	} else {
		ufs_extattr_uepm_destroy(&ump->um_extattr);
	}
#endif
	if (mp->mnt_flag & MNT_SOFTDEP) {
		if ((error = softdep_flushfiles(mp, flags, td)) != 0)
			return (error);
	} else {
		if ((error = ffs_flushfiles(mp, flags, td)) != 0)
			return (error);
	}
	fs = ump->um_fs;
	if (fs->fs_pendingblocks != 0 || fs->fs_pendinginodes != 0) {
		printf("%s: unmount pending error: blocks %jd files %d\n",
		    fs->fs_fsmnt, (intmax_t)fs->fs_pendingblocks,
		    fs->fs_pendinginodes);
		fs->fs_pendingblocks = 0;
		fs->fs_pendinginodes = 0;
	}
	if (fs->fs_ronly == 0) {
		fs->fs_clean = fs->fs_flags & (FS_UNCLEAN|FS_NEEDSFSCK) ? 0 : 1;
		error = ffs_sbupdate(ump, MNT_WAIT);
		if (error) {
			fs->fs_clean = 0;
			return (error);
		}
	}
	ump->um_devvp->v_rdev->si_mountpoint = NULL;

	vinvalbuf(ump->um_devvp, V_SAVE, NOCRED, td, 0, 0);
	/* XXX: see comment above VOP_OPEN. */
#ifdef notyet
	error = VOP_CLOSE(ump->um_devvp, fs->fs_ronly ? FREAD : FREAD | FWRITE,
	    NOCRED, td);
#else
	error = VOP_CLOSE(ump->um_devvp, FREAD | FWRITE, NOCRED, td);
#endif
	vrele(ump->um_devvp);
	free(fs->fs_csp, M_UFSMNT);
	free(fs, M_UFSMNT);
	free(ump, M_UFSMNT);
	mp->mnt_data = (qaddr_t)0;
	mp->mnt_flag &= ~MNT_LOCAL;
	return (error);
}

/*
 * Flush out all the files in a filesystem.
 */
int
ffs_flushfiles(mp, flags, td)
	struct mount *mp;
	int flags;
	struct thread *td;
{
	struct ufsmount *ump;
	int error;

	ump = VFSTOUFS(mp);
#ifdef QUOTA
	if (mp->mnt_flag & MNT_QUOTA) {
		int i;
		error = vflush(mp, 0, SKIPSYSTEM|flags, td);
		if (error)
			return (error);
		for (i = 0; i < MAXQUOTAS; i++) {
			if (ump->um_quotas[i] == NULLVP)
				continue;
			quotaoff(td, mp, i);
		}
		/*
		 * Here we fall through to vflush again to ensure
		 * that we have gotten rid of all the system vnodes.
		 */
	}
#endif
	ASSERT_VOP_LOCKED(ump->um_devvp, "ffs_flushfiles");
	if (ump->um_devvp->v_vflag & VV_COPYONWRITE) {
		if ((error = vflush(mp, 0, SKIPSYSTEM | flags, td)) != 0)
			return (error);
		ffs_snapshot_unmount(mp);
		/*
		 * Here we fall through to vflush again to ensure
		 * that we have gotten rid of all the system vnodes.
		 */
	}
        /*
	 * Flush all the files.
	 */
	if ((error = vflush(mp, 0, flags, td)) != 0)
		return (error);
	/*
	 * Flush filesystem metadata.
	 */
	vn_lock(ump->um_devvp, LK_EXCLUSIVE | LK_RETRY, td);
	error = VOP_FSYNC(ump->um_devvp, td->td_ucred, MNT_WAIT, td);
	VOP_UNLOCK(ump->um_devvp, 0, td);
	return (error);
}

/*
 * Get filesystem statistics.
 */
int
ffs_statfs(mp, sbp, td)
	struct mount *mp;
	struct statfs *sbp;
	struct thread *td;
{
	struct ufsmount *ump;
	struct fs *fs;

	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	if (fs->fs_magic != FS_UFS1_MAGIC && fs->fs_magic != FS_UFS2_MAGIC)
		panic("ffs_statfs");
	sbp->f_version = STATFS_VERSION;
	sbp->f_bsize = fs->fs_fsize;
	sbp->f_iosize = fs->fs_bsize;
	sbp->f_blocks = fs->fs_dsize;
	sbp->f_bfree = fs->fs_cstotal.cs_nbfree * fs->fs_frag +
	    fs->fs_cstotal.cs_nffree + dbtofsb(fs, fs->fs_pendingblocks);
	sbp->f_bavail = freespace(fs, fs->fs_minfree) +
	    dbtofsb(fs, fs->fs_pendingblocks);
	sbp->f_files =  fs->fs_ncg * fs->fs_ipg - ROOTINO;
	sbp->f_ffree = fs->fs_cstotal.cs_nifree + fs->fs_pendinginodes;
	sbp->f_namemax = NAME_MAX;
	if (sbp != &mp->mnt_stat) {
		sbp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
		sbp->f_type = mp->mnt_vfc->vfc_typenum;
		sbp->f_syncwrites = mp->mnt_stat.f_syncwrites;
		sbp->f_asyncwrites = mp->mnt_stat.f_asyncwrites;
		sbp->f_syncreads = mp->mnt_stat.f_syncreads;
		sbp->f_asyncreads = mp->mnt_stat.f_asyncreads;
		sbp->f_owner = mp->mnt_stat.f_owner;
		sbp->f_fsid = mp->mnt_stat.f_fsid;
		bcopy((caddr_t)mp->mnt_stat.f_fstypename,
			(caddr_t)&sbp->f_fstypename[0], MFSNAMELEN);
		bcopy((caddr_t)mp->mnt_stat.f_mntonname,
			(caddr_t)&sbp->f_mntonname[0], MNAMELEN);
		bcopy((caddr_t)mp->mnt_stat.f_mntfromname,
			(caddr_t)&sbp->f_mntfromname[0], MNAMELEN);
	}
	return (0);
}

/*
 * Go through the disk queues to initiate sandbagged IO;
 * go through the inodes to write those that have been modified;
 * initiate the writing of the super block if it has been modified.
 *
 * Note: we are always called with the filesystem marked `MPBUSY'.
 */
int
ffs_sync(mp, waitfor, cred, td)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct thread *td;
{
	struct vnode *nvp, *vp, *devvp;
	struct inode *ip;
	struct ufsmount *ump = VFSTOUFS(mp);
	struct fs *fs;
	int error, count, wait, lockreq, allerror = 0;
	struct bufobj *bo;

	fs = ump->um_fs;
	if (fs->fs_fmod != 0 && fs->fs_ronly != 0) {		/* XXX */
		printf("fs = %s\n", fs->fs_fsmnt);
		panic("ffs_sync: rofs mod");
	}
	/*
	 * Write back each (modified) inode.
	 */
	wait = 0;
	lockreq = LK_EXCLUSIVE | LK_NOWAIT;
	if (waitfor == MNT_WAIT) {
		wait = 1;
		lockreq = LK_EXCLUSIVE;
	}
	lockreq |= LK_INTERLOCK;
	MNT_ILOCK(mp);
loop:
	MNT_VNODE_FOREACH(vp, mp, nvp) {
		/*
		 * Depend on the mntvnode_slock to keep things stable enough
		 * for a quick test.  Since there might be hundreds of
		 * thousands of vnodes, we cannot afford even a subroutine
		 * call unless there's a good chance that we have work to do.
		 */
		VI_LOCK(vp);
		if (vp->v_iflag & VI_XLOCK) {
			VI_UNLOCK(vp);
			continue;
		}
		ip = VTOI(vp);
		if (vp->v_type == VNON || ((ip->i_flag &
		    (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) == 0 &&
		    vp->v_bufobj.bo_dirty.bv_cnt == 0)) {
			VI_UNLOCK(vp);
			continue;
		}
		MNT_IUNLOCK(mp);
		if ((error = vget(vp, lockreq, td)) != 0) {
			MNT_ILOCK(mp);
			if (error == ENOENT)
				goto loop;
			continue;
		}
		if ((error = VOP_FSYNC(vp, cred, waitfor, td)) != 0)
			allerror = error;
		VOP_UNLOCK(vp, 0, td);
		vrele(vp);
		MNT_ILOCK(mp);
	}
	MNT_IUNLOCK(mp);
	/*
	 * Force stale filesystem control information to be flushed.
	 */
	if (waitfor == MNT_WAIT) {
		if ((error = softdep_flushworklist(ump->um_mountp, &count, td)))
			allerror = error;
		/* Flushed work items may create new vnodes to clean */
		if (allerror == 0 && count) {
			MNT_ILOCK(mp);
			goto loop;
		}
	}
#ifdef QUOTA
	qsync(mp);
#endif
	devvp = ump->um_devvp;
	VI_LOCK(devvp);
	bo = &devvp->v_bufobj;
	if (waitfor != MNT_LAZY &&
	    (bo->bo_numoutput > 0 || bo->bo_dirty.bv_cnt > 0)) {
		vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY | LK_INTERLOCK, td);
		if ((error = VOP_FSYNC(devvp, cred, waitfor, td)) != 0)
			allerror = error;
		VOP_UNLOCK(devvp, 0, td);
		if (allerror == 0 && waitfor == MNT_WAIT) {
			MNT_ILOCK(mp);
			goto loop;
		}
	} else
		VI_UNLOCK(devvp);
	/*
	 * Write back modified superblock.
	 */
	if (fs->fs_fmod != 0 && (error = ffs_sbupdate(ump, waitfor)) != 0)
		allerror = error;
	return (allerror);
}

int
ffs_vget(mp, ino, flags, vpp)
	struct mount *mp;
	ino_t ino;
	int flags;
	struct vnode **vpp;
{
	struct thread *td = curthread; 		/* XXX */
	struct fs *fs;
	struct inode *ip;
	struct ufsmount *ump;
	struct buf *bp;
	struct vnode *vp;
	struct cdev *dev;
	int error;

	ump = VFSTOUFS(mp);
	dev = ump->um_dev;

	/*
	 * We do not lock vnode creation as it is believed to be too
	 * expensive for such rare case as simultaneous creation of vnode
	 * for same ino by different processes. We just allow them to race
	 * and check later to decide who wins. Let the race begin!
	 */
	if ((error = ufs_ihashget(dev, ino, flags, vpp)) != 0)
		return (error);
	if (*vpp != NULL)
		return (0);

	/*
	 * If this MALLOC() is performed after the getnewvnode()
	 * it might block, leaving a vnode with a NULL v_data to be
	 * found by ffs_sync() if a sync happens to fire right then,
	 * which will cause a panic because ffs_sync() blindly
	 * dereferences vp->v_data (as well it should).
	 */
	ip = uma_zalloc(uma_inode, M_WAITOK);

	/* Allocate a new vnode/inode. */
	error = getnewvnode("ufs", mp, ffs_vnodeop_p, &vp);
	if (error) {
		*vpp = NULL;
		uma_zfree(uma_inode, ip);
		return (error);
	}
	bzero((caddr_t)ip, sizeof(struct inode));
	/*
	 * FFS supports recursive locking.
	 */
	fs = ump->um_fs;
	vp->v_vnlock->lk_flags |= LK_CANRECURSE;
	vp->v_data = ip;
	vp->v_bufobj.bo_bsize = fs->fs_bsize;
	ip->i_vnode = vp;
	ip->i_ump = ump;
	ip->i_fs = fs;
	ip->i_dev = dev;
	ip->i_number = ino;
#ifdef QUOTA
	{
		int i;
		for (i = 0; i < MAXQUOTAS; i++)
			ip->i_dquot[i] = NODQUOT;
	}
#endif
	/*
	 * Exclusively lock the vnode before adding to hash. Note, that we
	 * must not release nor downgrade the lock (despite flags argument
	 * says) till it is fully initialized.
	 */
	lockmgr(vp->v_vnlock, LK_EXCLUSIVE, (struct mtx *)0, td);

	/*
	 * Atomicaly (in terms of ufs_hash operations) check the hash for
	 * duplicate of vnode being created and add it to the hash. If a
	 * duplicate vnode was found, it will be vget()ed from hash for us.
	 */
	if ((error = ufs_ihashins(ip, flags, vpp)) != 0) {
		vput(vp);
		*vpp = NULL;
		return (error);
	}

	/* We lost the race, then throw away our vnode and return existing */
	if (*vpp != NULL) {
		vput(vp);
		return (0);
	}

	/* Read in the disk contents for the inode, copy into the inode. */
	error = bread(ump->um_devvp, fsbtodb(fs, ino_to_fsba(fs, ino)),
	    (int)fs->fs_bsize, NOCRED, &bp);
	if (error) {
		/*
		 * The inode does not contain anything useful, so it would
		 * be misleading to leave it on its hash chain. With mode
		 * still zero, it will be unlinked and returned to the free
		 * list by vput().
		 */
		brelse(bp);
		vput(vp);
		*vpp = NULL;
		return (error);
	}
	if (ip->i_ump->um_fstype == UFS1)
		ip->i_din1 = uma_zalloc(uma_ufs1, M_WAITOK);
	else
		ip->i_din2 = uma_zalloc(uma_ufs2, M_WAITOK);
	ffs_load_inode(bp, ip, fs, ino);
	if (DOINGSOFTDEP(vp))
		softdep_load_inodeblock(ip);
	else
		ip->i_effnlink = ip->i_nlink;
	bqrelse(bp);

	/*
	 * Initialize the vnode from the inode, check for aliases.
	 * Note that the underlying vnode may have changed.
	 */
	error = ufs_vinit(mp, ffs_fifoop_p, &vp);
	if (error) {
		vput(vp);
		*vpp = NULL;
		return (error);
	}
	/*
	 * Finish inode initialization.
	 */
	VREF(ip->i_devvp);
	/*
	 * Set up a generation number for this inode if it does not
	 * already have one. This should only happen on old filesystems.
	 */
	if (ip->i_gen == 0) {
		ip->i_gen = arc4random() / 2 + 1;
		if ((vp->v_mount->mnt_flag & MNT_RDONLY) == 0) {
			ip->i_flag |= IN_MODIFIED;
			DIP_SET(ip, i_gen, ip->i_gen);
		}
	}
	/*
	 * Ensure that uid and gid are correct. This is a temporary
	 * fix until fsck has been changed to do the update.
	 */
	if (fs->fs_magic == FS_UFS1_MAGIC &&		/* XXX */
	    fs->fs_old_inodefmt < FS_44INODEFMT) {	/* XXX */
		ip->i_uid = ip->i_din1->di_ouid;	/* XXX */
		ip->i_gid = ip->i_din1->di_ogid;	/* XXX */
	}						/* XXX */

#ifdef MAC
	if ((mp->mnt_flag & MNT_MULTILABEL) && ip->i_mode) {
		/*
		 * If this vnode is already allocated, and we're running
		 * multi-label, attempt to perform a label association
		 * from the extended attributes on the inode.
		 */
		error = mac_associate_vnode_extattr(mp, vp);
		if (error) {
			/* ufs_inactive will release ip->i_devvp ref. */
			vput(vp);
			*vpp = NULL;
			return (error);
		}
	}
#endif

	*vpp = vp;
	return (0);
}

/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is valid
 * - call ffs_vget() to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 * - check that the given client host has export rights and return
 *   those rights via. exflagsp and credanonp
 */
int
ffs_fhtovp(mp, fhp, vpp)
	struct mount *mp;
	struct fid *fhp;
	struct vnode **vpp;
{
	struct ufid *ufhp;
	struct fs *fs;

	ufhp = (struct ufid *)fhp;
	fs = VFSTOUFS(mp)->um_fs;
	if (ufhp->ufid_ino < ROOTINO ||
	    ufhp->ufid_ino >= fs->fs_ncg * fs->fs_ipg)
		return (ESTALE);
	return (ufs_fhtovp(mp, ufhp, vpp));
}

/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
ffs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	struct inode *ip;
	struct ufid *ufhp;

	ip = VTOI(vp);
	ufhp = (struct ufid *)fhp;
	ufhp->ufid_len = sizeof(struct ufid);
	ufhp->ufid_ino = ip->i_number;
	ufhp->ufid_gen = ip->i_gen;
	return (0);
}

/*
 * Initialize the filesystem.
 */
static int
ffs_init(vfsp)
	struct vfsconf *vfsp;
{

	softdep_initialize();
	return (ufs_init(vfsp));
}

/*
 * Undo the work of ffs_init().
 */
static int
ffs_uninit(vfsp)
	struct vfsconf *vfsp;
{
	int ret;

	ret = ufs_uninit(vfsp);
	softdep_uninitialize();
	return (ret);
}

/*
 * Write a superblock and associated information back to disk.
 */
static int
ffs_sbupdate(mp, waitfor)
	struct ufsmount *mp;
	int waitfor;
{
	struct fs *fs = mp->um_fs;
	struct buf *bp;
	int blks;
	void *space;
	int i, size, error, allerror = 0;

	if (fs->fs_ronly == 1 &&
	    (mp->um_mountp->mnt_flag & (MNT_RDONLY | MNT_UPDATE)) != 
	    (MNT_RDONLY | MNT_UPDATE))
		panic("ffs_sbupdate: write read-only filesystem");
	/*
	 * First write back the summary information.
	 */
	blks = howmany(fs->fs_cssize, fs->fs_fsize);
	space = fs->fs_csp;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		bp = getblk(mp->um_devvp, fsbtodb(fs, fs->fs_csaddr + i),
		    size, 0, 0, 0);
		bcopy(space, bp->b_data, (u_int)size);
		space = (char *)space + size;
		if (waitfor != MNT_WAIT)
			bawrite(bp);
		else if ((error = bwrite(bp)) != 0)
			allerror = error;
	}
	/*
	 * Now write back the superblock itself. If any errors occurred
	 * up to this point, then fail so that the superblock avoids
	 * being written out as clean.
	 */
	if (allerror)
		return (allerror);
	if (fs->fs_magic == FS_UFS1_MAGIC && fs->fs_sblockloc != SBLOCK_UFS1 &&
	    (fs->fs_flags & FS_FLAGS_UPDATED) == 0) {
		printf("%s: correcting fs_sblockloc from %jd to %d\n",
		    fs->fs_fsmnt, fs->fs_sblockloc, SBLOCK_UFS1);
		fs->fs_sblockloc = SBLOCK_UFS1;
	}
	if (fs->fs_magic == FS_UFS2_MAGIC && fs->fs_sblockloc != SBLOCK_UFS2 &&
	    (fs->fs_flags & FS_FLAGS_UPDATED) == 0) {
		printf("%s: correcting fs_sblockloc from %jd to %d\n",
		    fs->fs_fsmnt, fs->fs_sblockloc, SBLOCK_UFS2);
		fs->fs_sblockloc = SBLOCK_UFS2;
	}
	bp = getblk(mp->um_devvp, btodb(fs->fs_sblockloc), (int)fs->fs_sbsize,
	    0, 0, 0);
	fs->fs_fmod = 0;
	fs->fs_time = time_second;
	bcopy((caddr_t)fs, bp->b_data, (u_int)fs->fs_sbsize);
	ffs_oldfscompat_write((struct fs *)bp->b_data, mp);
	if (waitfor != MNT_WAIT)
		bawrite(bp);
	else if ((error = bwrite(bp)) != 0)
		allerror = error;
	return (allerror);
}

static int
ffs_extattrctl(struct mount *mp, int cmd, struct vnode *filename_vp,
	int attrnamespace, const char *attrname, struct thread *td)
{

#ifdef UFS_EXTATTR
	return (ufs_extattrctl(mp, cmd, filename_vp, attrnamespace,
	    attrname, td));
#else
	return (vfs_stdextattrctl(mp, cmd, filename_vp, attrnamespace,
	    attrname, td));
#endif
}

static void
ffs_ifree(struct ufsmount *ump, struct inode *ip)
{

	if (ump->um_fstype == UFS1 && ip->i_din1 != NULL)
		uma_zfree(uma_ufs1, ip->i_din1);
	else if (ip->i_din2 != NULL)
		uma_zfree(uma_ufs2, ip->i_din2);
	uma_zfree(uma_inode, ip);
}

static void
ffs_geom_strategy(struct bufobj *bo, struct buf *bp)
{
	int i = 0;
	struct vnode *vp;

	vp = bp->b_vp;
#if 0
	KASSERT(vp == bo->bo_vnode, ("Inconsistent vnode bufstrategy"));
	KASSERT(vp->v_type != VCHR && vp->v_type != VBLK,
	    ("Wrong vnode in bufstrategy(bp=%p, vp=%p)", bp, vp));
#endif
	if (vp->v_type == VCHR) {
#ifdef SOFTUPDATES
		if (bp->b_iocmd == BIO_WRITE && softdep_disk_prewrite(bp->b_vp, bp))
			return;
#endif
		i = VOP_SPECSTRATEGY(vp, bp);
	} else {
		i = VOP_STRATEGY(vp, bp);
	}
	KASSERT(i == 0, ("VOP_STRATEGY failed bp=%p vp=%p", bp, bp->b_vp));
}

