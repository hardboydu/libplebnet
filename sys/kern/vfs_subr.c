/*
 * Copyright (c) 1989, 1993
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
 *	@(#)vfs_subr.c	8.31 (Berkeley) 5/26/95
 * $Id: vfs_subr.c,v 1.163 1998/09/14 19:56:40 sos Exp $
 */

/*
 * External virtual filesystem routines
 */
#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/domain.h>
#include <sys/dirent.h>
#include <sys/vmmeter.h>

#include <machine/limits.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>
#include <vm/vm_zone.h>
#include <sys/sysctl.h>

#include <miscfs/specfs/specdev.h>

static MALLOC_DEFINE(M_NETADDR, "Export Host", "Export host address structure");

static void	insmntque __P((struct vnode *vp, struct mount *mp));
#ifdef DDB
static void	printlockedvnodes __P((void));
#endif
static void	vclean __P((struct vnode *vp, int flags, struct proc *p));
static void	vfree __P((struct vnode *));
static void	vgonel __P((struct vnode *vp, struct proc *p));
static __inline void	vfs_object_destroy __P((struct vnode *));
static unsigned long	numvnodes;
SYSCTL_INT(_debug, OID_AUTO, numvnodes, CTLFLAG_RD, &numvnodes, 0, "");

enum vtype iftovt_tab[16] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};
int vttoif_tab[9] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK,
	S_IFSOCK, S_IFIFO, S_IFMT,
};

/*
 * Insq/Remq for the vnode usage lists.
 */
#define	bufinsvn(bp, dp)	LIST_INSERT_HEAD(dp, bp, b_vnbufs)
#define	bufremvn(bp) {							\
	LIST_REMOVE(bp, b_vnbufs);					\
	(bp)->b_vnbufs.le_next = NOLIST;				\
}

static TAILQ_HEAD(freelst, vnode) vnode_free_list;	/* vnode free list */
struct tobefreelist vnode_tobefree_list;	/* vnode free list */

static u_long wantfreevnodes = 25;
SYSCTL_INT(_debug, OID_AUTO, wantfreevnodes, CTLFLAG_RW, &wantfreevnodes, 0, "");
static u_long freevnodes = 0;
SYSCTL_INT(_debug, OID_AUTO, freevnodes, CTLFLAG_RD, &freevnodes, 0, "");

int vfs_ioopt = 0;
#ifdef ENABLE_VFS_IOOPT
SYSCTL_INT(_vfs, OID_AUTO, ioopt, CTLFLAG_RW, &vfs_ioopt, 0, "");
#endif

struct mntlist mountlist;	/* mounted filesystem list */
struct simplelock mountlist_slock;
static struct simplelock mntid_slock;
struct simplelock mntvnode_slock;
int	nfs_mount_type = -1;
static struct simplelock vnode_free_list_slock;
static struct simplelock spechash_slock;
struct nfs_public nfs_pub;	/* publicly exported FS */
static vm_zone_t vnode_zone;

/*
 * The workitem queue.
 */
#define SYNCER_MAXDELAY		32
int syncer_maxdelay =		SYNCER_MAXDELAY;	/* maximum delay time */
time_t syncdelay =		30;
int rushjob;				/* number of slots to run ASAP */

static int syncer_delayno = 0;
static long syncer_mask; 
LIST_HEAD(synclist, vnode);
static struct synclist *syncer_workitem_pending;

int desiredvnodes;
SYSCTL_INT(_kern, KERN_MAXVNODES, maxvnodes, CTLFLAG_RW, &desiredvnodes, 0, "");

static void	vfs_free_addrlist __P((struct netexport *nep));
static int	vfs_free_netcred __P((struct radix_node *rn, void *w));
static int	vfs_hang_addrlist __P((struct mount *mp, struct netexport *nep,
				       struct export_args *argp));

/*
 * Initialize the vnode management data structures.
 */
void
vntblinit()
{

	desiredvnodes = maxproc + cnt.v_page_count / 4;
	simple_lock_init(&mntvnode_slock);
	simple_lock_init(&mntid_slock);
	simple_lock_init(&spechash_slock);
	TAILQ_INIT(&vnode_free_list);
	TAILQ_INIT(&vnode_tobefree_list);
	simple_lock_init(&vnode_free_list_slock);
	CIRCLEQ_INIT(&mountlist);
	vnode_zone = zinit("VNODE", sizeof (struct vnode), 0, 0, 5);
	/*
	 * Initialize the filesystem syncer.
	 */     
	syncer_workitem_pending = hashinit(syncer_maxdelay, M_VNODE, 
		&syncer_mask);
	syncer_maxdelay = syncer_mask + 1;
}

/*
 * Mark a mount point as busy. Used to synchronize access and to delay
 * unmounting. Interlock is not released on failure.
 */
int
vfs_busy(mp, flags, interlkp, p)
	struct mount *mp;
	int flags;
	struct simplelock *interlkp;
	struct proc *p;
{
	int lkflags;

	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		if (flags & LK_NOWAIT)
			return (ENOENT);
		mp->mnt_kern_flag |= MNTK_MWAIT;
		if (interlkp) {
			simple_unlock(interlkp);
		}
		/*
		 * Since all busy locks are shared except the exclusive
		 * lock granted when unmounting, the only place that a
		 * wakeup needs to be done is at the release of the
		 * exclusive lock at the end of dounmount.
		 */
		tsleep((caddr_t)mp, PVFS, "vfs_busy", 0);
		if (interlkp) {
			simple_lock(interlkp);
		}
		return (ENOENT);
	}
	lkflags = LK_SHARED | LK_NOPAUSE;
	if (interlkp)
		lkflags |= LK_INTERLOCK;
	if (lockmgr(&mp->mnt_lock, lkflags, interlkp, p))
		panic("vfs_busy: unexpected lock failure");
	return (0);
}

/*
 * Free a busy filesystem.
 */
void
vfs_unbusy(mp, p)
	struct mount *mp;
	struct proc *p;
{

	lockmgr(&mp->mnt_lock, LK_RELEASE, NULL, p);
}

/*
 * Lookup a filesystem type, and if found allocate and initialize
 * a mount structure for it.
 *
 * Devname is usually updated by mount(8) after booting.
 */
int
vfs_rootmountalloc(fstypename, devname, mpp)
	char *fstypename;
	char *devname;
	struct mount **mpp;
{
	struct proc *p = curproc;	/* XXX */
	struct vfsconf *vfsp;
	struct mount *mp;

	if (fstypename == NULL)
		return (ENODEV);
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strcmp(vfsp->vfc_name, fstypename))
			break;
	if (vfsp == NULL)
		return (ENODEV);
	mp = malloc((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));
	lockinit(&mp->mnt_lock, PVFS, "vfslock", 0, LK_NOPAUSE);
	(void)vfs_busy(mp, LK_NOWAIT, 0, p);
	LIST_INIT(&mp->mnt_vnodelist);
	mp->mnt_vfc = vfsp;
	mp->mnt_op = vfsp->vfc_vfsops;
	mp->mnt_flag = MNT_RDONLY;
	mp->mnt_vnodecovered = NULLVP;
	vfsp->vfc_refcount++;
	mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_stat.f_fstypename, vfsp->vfc_name, MFSNAMELEN);
	mp->mnt_stat.f_mntonname[0] = '/';
	mp->mnt_stat.f_mntonname[1] = 0;
	(void) copystr(devname, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, 0);
	*mpp = mp;
	return (0);
}

/*
 * Find an appropriate filesystem to use for the root. If a filesystem
 * has not been preselected, walk through the list of known filesystems
 * trying those that have mountroot routines, and try them until one
 * works or we have tried them all.
 */
#ifdef notdef	/* XXX JH */
int
lite2_vfs_mountroot()
{
	struct vfsconf *vfsp;
	extern int (*lite2_mountroot) __P((void));
	int error;

	if (lite2_mountroot != NULL)
		return ((*lite2_mountroot)());
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next) {
		if (vfsp->vfc_mountroot == NULL)
			continue;
		if ((error = (*vfsp->vfc_mountroot)()) == 0)
			return (0);
		printf("%s_mountroot failed: %d\n", vfsp->vfc_name, error);
	}
	return (ENODEV);
}
#endif

/*
 * Lookup a mount point by filesystem identifier.
 */
struct mount *
vfs_getvfs(fsid)
	fsid_t *fsid;
{
	register struct mount *mp;

	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist;
	    mp = mp->mnt_list.cqe_next) {
		if (mp->mnt_stat.f_fsid.val[0] == fsid->val[0] &&
		    mp->mnt_stat.f_fsid.val[1] == fsid->val[1]) {
			simple_unlock(&mountlist_slock);
			return (mp);
	    }
	}
	simple_unlock(&mountlist_slock);
	return ((struct mount *) 0);
}

/*
 * Get a new unique fsid
 */
void
vfs_getnewfsid(mp)
	struct mount *mp;
{
	static u_short xxxfs_mntid;

	fsid_t tfsid;
	int mtype;

	simple_lock(&mntid_slock); 
	mtype = mp->mnt_vfc->vfc_typenum;
	mp->mnt_stat.f_fsid.val[0] = makedev(nblkdev + mtype, 0);
	mp->mnt_stat.f_fsid.val[1] = mtype;
	if (xxxfs_mntid == 0)
		++xxxfs_mntid;
	tfsid.val[0] = makedev(nblkdev + mtype, xxxfs_mntid);
	tfsid.val[1] = mtype;
	if (mountlist.cqh_first != (void *)&mountlist) {
		while (vfs_getvfs(&tfsid)) {
			tfsid.val[0]++;
			xxxfs_mntid++;
		}
	}
	mp->mnt_stat.f_fsid.val[0] = tfsid.val[0];
	simple_unlock(&mntid_slock);
}

/*
 * Set vnode attributes to VNOVAL
 */
void
vattr_null(vap)
	register struct vattr *vap;
{

	vap->va_type = VNON;
	vap->va_size = VNOVAL;
	vap->va_bytes = VNOVAL;
	vap->va_mode = VNOVAL;
	vap->va_nlink = VNOVAL;
	vap->va_uid = VNOVAL;
	vap->va_gid = VNOVAL;
	vap->va_fsid = VNOVAL;
	vap->va_fileid = VNOVAL;
	vap->va_blocksize = VNOVAL;
	vap->va_rdev = VNOVAL;
	vap->va_atime.tv_sec = VNOVAL;
	vap->va_atime.tv_nsec = VNOVAL;
	vap->va_mtime.tv_sec = VNOVAL;
	vap->va_mtime.tv_nsec = VNOVAL;
	vap->va_ctime.tv_sec = VNOVAL;
	vap->va_ctime.tv_nsec = VNOVAL;
	vap->va_flags = VNOVAL;
	vap->va_gen = VNOVAL;
	vap->va_vaflags = 0;
}

/*
 * Routines having to do with the management of the vnode table.
 */
extern vop_t **dead_vnodeop_p;

/*
 * Return the next vnode from the free list.
 */
int
getnewvnode(tag, mp, vops, vpp)
	enum vtagtype tag;
	struct mount *mp;
	vop_t **vops;
	struct vnode **vpp;
{
	int s;
	struct proc *p = curproc;	/* XXX */
	struct vnode *vp, *tvp, *nvp;
	vm_object_t object;
	TAILQ_HEAD(freelst, vnode) vnode_tmp_list;

	/*
	 * We take the least recently used vnode from the freelist
	 * if we can get it and it has no cached pages, and no
	 * namecache entries are relative to it.
	 * Otherwise we allocate a new vnode
	 */

	s = splbio();
	simple_lock(&vnode_free_list_slock);
	TAILQ_INIT(&vnode_tmp_list);

	for (vp = TAILQ_FIRST(&vnode_tobefree_list); vp; vp = nvp) {
		nvp = TAILQ_NEXT(vp, v_freelist);
		TAILQ_REMOVE(&vnode_tobefree_list, vp, v_freelist);
		if (vp->v_flag & VAGE) {
			TAILQ_INSERT_HEAD(&vnode_free_list, vp, v_freelist);
		} else {
			TAILQ_INSERT_TAIL(&vnode_free_list, vp, v_freelist);
		}
		vp->v_flag &= ~(VTBFREE|VAGE);
		vp->v_flag |= VFREE;
		if (vp->v_usecount)
			panic("tobe free vnode isn't");
		freevnodes++;
	}

	if (wantfreevnodes && freevnodes < wantfreevnodes) {
		vp = NULL;
	} else if (!wantfreevnodes && freevnodes <= desiredvnodes) {
		/* 
		 * XXX: this is only here to be backwards compatible
		 */
		vp = NULL;
	} else {
		for (vp = TAILQ_FIRST(&vnode_free_list); vp; vp = nvp) {

			nvp = TAILQ_NEXT(vp, v_freelist);

			if (!simple_lock_try(&vp->v_interlock)) 
				continue;
			if (vp->v_usecount)
				panic("free vnode isn't");

			object = vp->v_object;
			if (object && (object->resident_page_count || object->ref_count)) {
				printf("object inconsistant state: RPC: %d, RC: %d\n",
					object->resident_page_count, object->ref_count);
				/* Don't recycle if it's caching some pages */
				TAILQ_REMOVE(&vnode_free_list, vp, v_freelist);
				TAILQ_INSERT_TAIL(&vnode_tmp_list, vp, v_freelist);
				continue;
			} else if (LIST_FIRST(&vp->v_cache_src)) {
				/* Don't recycle if active in the namecache */
				simple_unlock(&vp->v_interlock);
				continue;
			} else {
				break;
			}
		}
	}

	for (tvp = TAILQ_FIRST(&vnode_tmp_list); tvp; tvp = nvp) {
		nvp = TAILQ_NEXT(tvp, v_freelist);
		TAILQ_REMOVE(&vnode_tmp_list, tvp, v_freelist);
		TAILQ_INSERT_TAIL(&vnode_free_list, tvp, v_freelist);
		simple_unlock(&tvp->v_interlock);
	}

	if (vp) {
		vp->v_flag |= VDOOMED;
		TAILQ_REMOVE(&vnode_free_list, vp, v_freelist);
		freevnodes--;
		simple_unlock(&vnode_free_list_slock);
		cache_purge(vp);
		vp->v_lease = NULL;
		if (vp->v_type != VBAD) {
			vgonel(vp, p);
		} else {
			simple_unlock(&vp->v_interlock);
		}

#ifdef DIAGNOSTIC
		{
			int s;

			if (vp->v_data)
				panic("cleaned vnode isn't");
			s = splbio();
			if (vp->v_numoutput)
				panic("Clean vnode has pending I/O's");
			splx(s);
		}
#endif
		vp->v_flag = 0;
		vp->v_lastr = 0;
		vp->v_lastw = 0;
		vp->v_lasta = 0;
		vp->v_cstart = 0;
		vp->v_clen = 0;
		vp->v_socket = 0;
		vp->v_writecount = 0;	/* XXX */
		vp->v_maxio = 0;
	} else {
		simple_unlock(&vnode_free_list_slock);
		vp = (struct vnode *) zalloc(vnode_zone);
		bzero((char *) vp, sizeof *vp);
		simple_lock_init(&vp->v_interlock);
		vp->v_dd = vp;
		cache_purge(vp);
		LIST_INIT(&vp->v_cache_src);
		TAILQ_INIT(&vp->v_cache_dst);
		numvnodes++;
	}

	vp->v_type = VNON;
	vp->v_tag = tag;
	vp->v_op = vops;
	insmntque(vp, mp);
	*vpp = vp;
	vp->v_usecount = 1;
	vp->v_data = 0;
	splx(s);

	vfs_object_create(vp, p, p->p_ucred, TRUE);
	return (0);
}

/*
 * Move a vnode from one mount queue to another.
 */
static void
insmntque(vp, mp)
	register struct vnode *vp;
	register struct mount *mp;
{

	simple_lock(&mntvnode_slock);
	/*
	 * Delete from old mount point vnode list, if on one.
	 */
	if (vp->v_mount != NULL)
		LIST_REMOVE(vp, v_mntvnodes);
	/*
	 * Insert into list of vnodes for the new mount point, if available.
	 */
	if ((vp->v_mount = mp) == NULL) {
		simple_unlock(&mntvnode_slock);
		return;
	}
	LIST_INSERT_HEAD(&mp->mnt_vnodelist, vp, v_mntvnodes);
	simple_unlock(&mntvnode_slock);
}

/*
 * Update outstanding I/O count and do wakeup if requested.
 */
void
vwakeup(bp)
	register struct buf *bp;
{
	register struct vnode *vp;

	bp->b_flags &= ~B_WRITEINPROG;
	if ((vp = bp->b_vp)) {
		vp->v_numoutput--;
		if (vp->v_numoutput < 0)
			panic("vwakeup: neg numoutput");
		if ((vp->v_numoutput == 0) && (vp->v_flag & VBWAIT)) {
			vp->v_flag &= ~VBWAIT;
			wakeup((caddr_t) &vp->v_numoutput);
		}
	}
}

/*
 * Flush out and invalidate all buffers associated with a vnode.
 * Called with the underlying object locked.
 */
int
vinvalbuf(vp, flags, cred, p, slpflag, slptimeo)
	register struct vnode *vp;
	int flags;
	struct ucred *cred;
	struct proc *p;
	int slpflag, slptimeo;
{
	register struct buf *bp;
	struct buf *nbp, *blist;
	int s, error;
	vm_object_t object;

	if (flags & V_SAVE) {
		s = splbio();
		while (vp->v_numoutput) {
			vp->v_flag |= VBWAIT;
			tsleep((caddr_t)&vp->v_numoutput,
				slpflag | (PRIBIO + 1),
				"vinvlbuf", slptimeo);
		}
		if (vp->v_dirtyblkhd.lh_first != NULL) {
			splx(s);
			if ((error = VOP_FSYNC(vp, cred, MNT_WAIT, p)) != 0)
				return (error);
			s = splbio();
			if (vp->v_numoutput > 0 ||
			    vp->v_dirtyblkhd.lh_first != NULL)
				panic("vinvalbuf: dirty bufs");
		}
		splx(s);
  	}
	s = splbio();
	for (;;) {
		if ((blist = vp->v_cleanblkhd.lh_first) && (flags & V_SAVEMETA))
			while (blist && blist->b_lblkno < 0)
				blist = blist->b_vnbufs.le_next;
		if (!blist && (blist = vp->v_dirtyblkhd.lh_first) &&
		    (flags & V_SAVEMETA))
			while (blist && blist->b_lblkno < 0)
				blist = blist->b_vnbufs.le_next;
		if (!blist)
			break;

		for (bp = blist; bp; bp = nbp) {
			nbp = bp->b_vnbufs.le_next;
			if ((flags & V_SAVEMETA) && bp->b_lblkno < 0)
				continue;
			if (bp->b_flags & B_BUSY) {
				bp->b_flags |= B_WANTED;
				error = tsleep((caddr_t) bp,
				    slpflag | (PRIBIO + 4), "vinvalbuf",
				    slptimeo);
				if (error) {
					splx(s);
					return (error);
				}
				break;
			}
			/*
			 * XXX Since there are no node locks for NFS, I
			 * believe there is a slight chance that a delayed
			 * write will occur while sleeping just above, so
			 * check for it.  Note that vfs_bio_awrite expects
			 * buffers to reside on a queue, while VOP_BWRITE and
			 * brelse do not.
			 */
			if (((bp->b_flags & (B_DELWRI | B_INVAL)) == B_DELWRI) &&
				(flags & V_SAVE)) {

				if (bp->b_vp == vp) {
					if (bp->b_flags & B_CLUSTEROK) {
						vfs_bio_awrite(bp);
					} else {
						bremfree(bp);
						bp->b_flags |= (B_BUSY | B_ASYNC);
						VOP_BWRITE(bp);
					}
				} else {
					bremfree(bp);
					bp->b_flags |= B_BUSY;
					(void) VOP_BWRITE(bp);
				}
				break;
			}
			bremfree(bp);
			bp->b_flags |= (B_INVAL | B_NOCACHE | B_RELBUF | B_BUSY);
			bp->b_flags &= ~B_ASYNC;
			brelse(bp);
		}
	}

	while (vp->v_numoutput > 0) {
		vp->v_flag |= VBWAIT;
		tsleep(&vp->v_numoutput, PVM, "vnvlbv", 0);
	}

	splx(s);

	/*
	 * Destroy the copy in the VM cache, too.
	 */
	simple_lock(&vp->v_interlock);
	object = vp->v_object;
	if (object != NULL) {
		if (flags & V_SAVEMETA)
			vm_object_page_remove(object, 0, object->size,
				(flags & V_SAVE) ? TRUE : FALSE);
		else
			vm_object_page_remove(object, 0, 0,
				(flags & V_SAVE) ? TRUE : FALSE);
	}
	simple_unlock(&vp->v_interlock);

	if (!(flags & V_SAVEMETA) &&
	    (vp->v_dirtyblkhd.lh_first || vp->v_cleanblkhd.lh_first))
		panic("vinvalbuf: flush failed");
	return (0);
}

/*
 * Truncate a file's buffer and pages to a specified length.  This
 * is in lieu of the old vinvalbuf mechanism, which performed unneeded
 * sync activity.
 */
int
vtruncbuf(vp, cred, p, length, blksize)
	register struct vnode *vp;
	struct ucred *cred;
	struct proc *p;
	off_t length;
	int blksize;
{
	register struct buf *bp;
	struct buf *nbp, *blist;
	int s, error, anyfreed;
	vm_object_t object;
	int trunclbn;

	/*
	 * Round up to the *next* lbn.
	 */
	trunclbn = (length + blksize - 1) / blksize;

	s = splbio();
restart:
	anyfreed = 1;
	for (;anyfreed;) {
		anyfreed = 0;
		for ( bp = LIST_FIRST(&vp->v_cleanblkhd); bp; bp = nbp) {

			nbp = LIST_NEXT(bp, b_vnbufs);

			if (bp->b_lblkno >= trunclbn) {
				if (bp->b_flags & B_BUSY) {
					bp->b_flags |= B_WANTED;
					tsleep(bp, PRIBIO + 4, "vtrb1", 0);
					goto restart;
				} else {
					bremfree(bp);
					bp->b_flags |= (B_BUSY | B_INVAL | B_RELBUF);
					bp->b_flags &= ~B_ASYNC;
					brelse(bp);
					anyfreed = 1;
				}
				if (nbp && 
					((LIST_NEXT(nbp, b_vnbufs) == NOLIST) ||
					 (nbp->b_vp != vp) ||
					 (nbp->b_flags & B_DELWRI))) {
					goto restart;
				}
			}
		}

		for (bp = LIST_FIRST(&vp->v_dirtyblkhd); bp; bp = nbp) {

			nbp = LIST_NEXT(bp, b_vnbufs);

			if (bp->b_lblkno >= trunclbn) {
				if (bp->b_flags & B_BUSY) {
					bp->b_flags |= B_WANTED;
					tsleep(bp, PRIBIO + 4, "vtrb2", 0);
					goto restart;
				} else {
					bremfree(bp);
					bp->b_flags |= (B_BUSY | B_INVAL | B_RELBUF);
					bp->b_flags &= ~B_ASYNC;
					brelse(bp);
					anyfreed = 1;
				}
				if (nbp && 
					((LIST_NEXT(nbp, b_vnbufs) == NOLIST) ||
					 (nbp->b_vp != vp) ||
					 (nbp->b_flags & B_DELWRI) == 0)) {
					goto restart;
				}
			}
		}
	}

	if (length > 0) {
restartsync:
		for (bp = LIST_FIRST(&vp->v_dirtyblkhd); bp; bp = nbp) {

			nbp = LIST_NEXT(bp, b_vnbufs);

			if ((bp->b_flags & B_DELWRI) && (bp->b_lblkno < 0)) {
				if (bp->b_flags & B_BUSY) {
					bp->b_flags |= B_WANTED;
					tsleep(bp, PRIBIO, "vtrb3", 0);
				} else {
					bremfree(bp);
					bp->b_flags |= B_BUSY;
					if (bp->b_vp == vp) {
						bp->b_flags |= B_ASYNC;
					} else {
						bp->b_flags &= ~B_ASYNC;
					}
					VOP_BWRITE(bp);
				}
				goto restartsync;
			}

		}
	}

	while (vp->v_numoutput > 0) {
		vp->v_flag |= VBWAIT;
		tsleep(&vp->v_numoutput, PVM, "vbtrunc", 0);
	}

	splx(s);

	vnode_pager_setsize(vp, length);

	return (0);
}

/*
 * Associate a buffer with a vnode.
 */
void
bgetvp(vp, bp)
	register struct vnode *vp;
	register struct buf *bp;
{
	int s;

#if defined(DIAGNOSTIC)
	if (bp->b_vp)
		panic("bgetvp: not free");
#endif
	vhold(vp);
	bp->b_vp = vp;
	if (vp->v_type == VBLK || vp->v_type == VCHR)
		bp->b_dev = vp->v_rdev;
	else
		bp->b_dev = NODEV;
	/*
	 * Insert onto list for new vnode.
	 */
	s = splbio();
	bufinsvn(bp, &vp->v_cleanblkhd);
	splx(s);
}

/*
 * Disassociate a buffer from a vnode.
 */
void
brelvp(bp)
	register struct buf *bp;
{
	struct vnode *vp;
	int s;

#if defined(DIAGNOSTIC)
	if (bp->b_vp == (struct vnode *) 0)
		panic("brelvp: NULL");
#endif

	/*
	 * Delete from old vnode list, if on one.
	 */
	vp = bp->b_vp;
	s = splbio();
	if (bp->b_vnbufs.le_next != NOLIST)
		bufremvn(bp);
	if ((vp->v_flag & VONWORKLST) && (LIST_FIRST(&vp->v_dirtyblkhd) == NULL)) {
		vp->v_flag &= ~VONWORKLST;
		LIST_REMOVE(vp, v_synclist);
	}
	splx(s);
	bp->b_vp = (struct vnode *) 0;
	vdrop(vp);
}

/*
 * The workitem queue.
 * 
 * It is useful to delay writes of file data and filesystem metadata
 * for tens of seconds so that quickly created and deleted files need
 * not waste disk bandwidth being created and removed. To realize this,
 * we append vnodes to a "workitem" queue. When running with a soft
 * updates implementation, most pending metadata dependencies should
 * not wait for more than a few seconds. Thus, mounted on block devices
 * are delayed only about a half the time that file data is delayed.
 * Similarly, directory updates are more critical, so are only delayed
 * about a third the time that file data is delayed. Thus, there are
 * SYNCER_MAXDELAY queues that are processed round-robin at a rate of
 * one each second (driven off the filesystem syner process). The
 * syncer_delayno variable indicates the next queue that is to be processed.
 * Items that need to be processed soon are placed in this queue:
 *
 *	syncer_workitem_pending[syncer_delayno]
 *
 * A delay of fifteen seconds is done by placing the request fifteen
 * entries later in the queue:
 *
 *	syncer_workitem_pending[(syncer_delayno + 15) & syncer_mask]
 *
 */

/*
 * Add an item to the syncer work queue.
 */
void
vn_syncer_add_to_worklist(vp, delay)
	struct vnode *vp;
	int delay;
{
	int s, slot;

	s = splbio();

	if (vp->v_flag & VONWORKLST) {
		LIST_REMOVE(vp, v_synclist);
	}

	if (delay > syncer_maxdelay - 2)
		delay = syncer_maxdelay - 2;
	slot = (syncer_delayno + delay) & syncer_mask;

	LIST_INSERT_HEAD(&syncer_workitem_pending[slot], vp, v_synclist);
	vp->v_flag |= VONWORKLST;
	splx(s);
}

static void sched_sync __P((void));
static struct	proc *updateproc;
static struct kproc_desc up_kp = {
	"syncer",
	sched_sync,
	&updateproc
};
SYSINIT_KT(syncer, SI_SUB_KTHREAD_UPDATE, SI_ORDER_FIRST, kproc_start, &up_kp)

/*
 * System filesystem synchronizer daemon.
 */
void 
sched_sync(void)
{
	struct synclist *slp;
	struct vnode *vp;
	long starttime;
	int s;
	struct proc *p = updateproc;

	for (;;) {
		starttime = time_second;

		/*
		 * Push files whose dirty time has expired.
		 */
		s = splbio();
		slp = &syncer_workitem_pending[syncer_delayno];
		syncer_delayno += 1;
		if (syncer_delayno == syncer_maxdelay)
			syncer_delayno = 0;
		splx(s);

		while ((vp = LIST_FIRST(slp)) != NULL) {
			vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
			(void) VOP_FSYNC(vp, p->p_ucred, MNT_LAZY, p);
			VOP_UNLOCK(vp, 0, p);
			if (LIST_FIRST(slp) == vp) {
				if (LIST_FIRST(&vp->v_dirtyblkhd) == NULL &&
				    vp->v_type != VBLK)
					panic("sched_sync: fsync failed");
				/*
				 * Move ourselves to the back of the sync list.
				 */
				LIST_REMOVE(vp, v_synclist);
				vn_syncer_add_to_worklist(vp, syncdelay);
			}
		}

		/*
		 * Do soft update processing.
		 */
		if (bioops.io_sync)
			(*bioops.io_sync)(NULL);

		/*
		 * The variable rushjob allows the kernel to speed up the
		 * processing of the filesystem syncer process. A rushjob
		 * value of N tells the filesystem syncer to process the next
		 * N seconds worth of work on its queue ASAP. Currently rushjob
		 * is used by the soft update code to speed up the filesystem
		 * syncer process when the incore state is getting so far
		 * ahead of the disk that the kernel memory pool is being
		 * threatened with exhaustion.
		 */
		if (rushjob > 0) {
			rushjob -= 1;
			continue;
		}
		/*
		 * If it has taken us less than a second to process the
		 * current work, then wait. Otherwise start right over
		 * again. We can still lose time if any single round
		 * takes more than two seconds, but it does not really
		 * matter as we are just trying to generally pace the
		 * filesystem activity.
		 */
		if (time_second == starttime)
			tsleep(&lbolt, PPAUSE, "syncer", 0);
	}
}

/*
 * Associate a p-buffer with a vnode.
 */
void
pbgetvp(vp, bp)
	register struct vnode *vp;
	register struct buf *bp;
{
#if defined(DIAGNOSTIC)
	if (bp->b_vp)
		panic("pbgetvp: not free");
#endif
	bp->b_vp = vp;
	if (vp->v_type == VBLK || vp->v_type == VCHR)
		bp->b_dev = vp->v_rdev;
	else
		bp->b_dev = NODEV;
}

/*
 * Disassociate a p-buffer from a vnode.
 */
void
pbrelvp(bp)
	register struct buf *bp;
{

#if defined(DIAGNOSTIC)
	if (bp->b_vp == (struct vnode *) 0)
		panic("pbrelvp: NULL");
#endif

	bp->b_vp = (struct vnode *) 0;
}

/*
 * Reassign a buffer from one vnode to another.
 * Used to assign file specific control information
 * (indirect blocks) to the vnode to which they belong.
 */
void
reassignbuf(bp, newvp)
	register struct buf *bp;
	register struct vnode *newvp;
{
	struct buflists *listheadp;
	int delay;
	int s;

	if (newvp == NULL) {
		printf("reassignbuf: NULL");
		return;
	}

	s = splbio();
	/*
	 * Delete from old vnode list, if on one.
	 */
	if (bp->b_vnbufs.le_next != NOLIST) {
		bufremvn(bp);
		vdrop(bp->b_vp);
	}
	/*
	 * If dirty, put on list of dirty buffers; otherwise insert onto list
	 * of clean buffers.
	 */
	if (bp->b_flags & B_DELWRI) {
		struct buf *tbp;

		listheadp = &newvp->v_dirtyblkhd;
		if ((newvp->v_flag & VONWORKLST) == 0) {
			switch (newvp->v_type) {
			case VDIR:
				delay = syncdelay / 3;
				break;
			case VBLK:
				if (newvp->v_specmountpoint != NULL) {
					delay = syncdelay / 2;
					break;
				}
				/* fall through */
			default:
				delay = syncdelay;
			}
			vn_syncer_add_to_worklist(newvp, delay);
		}
		tbp = listheadp->lh_first;
		if (!tbp || (tbp->b_lblkno > bp->b_lblkno)) {
			bufinsvn(bp, listheadp);
		} else {
			while (tbp->b_vnbufs.le_next &&
			    (tbp->b_vnbufs.le_next->b_lblkno < bp->b_lblkno)) {
				tbp = tbp->b_vnbufs.le_next;
			}
			LIST_INSERT_AFTER(tbp, bp, b_vnbufs);
		}
	} else {
		bufinsvn(bp, &newvp->v_cleanblkhd);
		if ((newvp->v_flag & VONWORKLST) &&
			LIST_FIRST(&newvp->v_dirtyblkhd) == NULL) {
			newvp->v_flag &= ~VONWORKLST;
			LIST_REMOVE(newvp, v_synclist);
		}
	}
	bp->b_vp = newvp;
	vhold(bp->b_vp);
	splx(s);
}

/*
 * Create a vnode for a block device.
 * Used for mounting the root file system.
 */
int
bdevvp(dev, vpp)
	dev_t dev;
	struct vnode **vpp;
{
	register struct vnode *vp;
	struct vnode *nvp;
	int error;

	if (dev == NODEV)
		return (0);
	error = getnewvnode(VT_NON, (struct mount *) 0, spec_vnodeop_p, &nvp);
	if (error) {
		*vpp = 0;
		return (error);
	}
	vp = nvp;
	vp->v_type = VBLK;
	if ((nvp = checkalias(vp, dev, (struct mount *) 0))) {
		vput(vp);
		vp = nvp;
	}
	*vpp = vp;
	return (0);
}

/*
 * Check to see if the new vnode represents a special device
 * for which we already have a vnode (either because of
 * bdevvp() or because of a different vnode representing
 * the same block device). If such an alias exists, deallocate
 * the existing contents and return the aliased vnode. The
 * caller is responsible for filling it with its new contents.
 */
struct vnode *
checkalias(nvp, nvp_rdev, mp)
	register struct vnode *nvp;
	dev_t nvp_rdev;
	struct mount *mp;
{
	struct proc *p = curproc;	/* XXX */
	struct vnode *vp;
	struct vnode **vpp;

	if (nvp->v_type != VBLK && nvp->v_type != VCHR)
		return (NULLVP);

	vpp = &speclisth[SPECHASH(nvp_rdev)];
loop:
	simple_lock(&spechash_slock);
	for (vp = *vpp; vp; vp = vp->v_specnext) {
		if (nvp_rdev != vp->v_rdev || nvp->v_type != vp->v_type)
			continue;
		/*
		 * Alias, but not in use, so flush it out.
		 * Only alias active device nodes.
		 * Not sure why we don't re-use this like we do below.
		 */
		simple_lock(&vp->v_interlock);
		if (vp->v_usecount == 0) {
			simple_unlock(&spechash_slock);
			vgonel(vp, p);
			goto loop;
		}
		if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p)) {
			/*
			 * It dissappeared, and we may have slept.
			 * Restart from the beginning
			 */
			simple_unlock(&spechash_slock);
			goto loop;
		}
		break;
	}
	/*
	 * It would be a lot clearer what is going on here if
	 * this had been expressed as:
	 * if ( vp && (vp->v_tag == VT_NULL))
	 * and the clauses had been swapped.
	 */
	if (vp == NULL || vp->v_tag != VT_NON) {
		/*
		 * Put the new vnode into the hash chain.
		 * and if there was an alias, connect them.
		 */
		MALLOC(nvp->v_specinfo, struct specinfo *,
		    sizeof(struct specinfo), M_VNODE, M_WAITOK);
		nvp->v_rdev = nvp_rdev;
		nvp->v_hashchain = vpp;
		nvp->v_specnext = *vpp;
		nvp->v_specmountpoint = NULL;
		simple_unlock(&spechash_slock);
		*vpp = nvp;
		if (vp != NULLVP) {
			nvp->v_flag |= VALIASED;
			vp->v_flag |= VALIASED;
			vput(vp);
		}
		return (NULLVP);
	}
	/*
	 * if ( vp && (vp->v_tag == VT_NULL))
	 * We have a vnode alias, but it is a trashed.
	 * Make it look like it's newley allocated. (by getnewvnode())
	 * The caller should use this instead.
	 */
	simple_unlock(&spechash_slock);
	VOP_UNLOCK(vp, 0, p);
	simple_lock(&vp->v_interlock);
	vclean(vp, 0, p);
	vp->v_op = nvp->v_op;
	vp->v_tag = nvp->v_tag;
	nvp->v_type = VNON;
	insmntque(vp, mp);
	return (vp);
}

/*
 * Grab a particular vnode from the free list, increment its
 * reference count and lock it. The vnode lock bit is set the
 * vnode is being eliminated in vgone. The process is awakened
 * when the transition is completed, and an error returned to
 * indicate that the vnode is no longer usable (possibly having
 * been changed to a new file system type).
 */
int
vget(vp, flags, p)
	register struct vnode *vp;
	int flags;
	struct proc *p;
{
	int error;

	/*
	 * If the vnode is in the process of being cleaned out for
	 * another use, we wait for the cleaning to finish and then
	 * return failure. Cleaning is determined by checking that
	 * the VXLOCK flag is set.
	 */
	if ((flags & LK_INTERLOCK) == 0) {
		simple_lock(&vp->v_interlock);
	}
	if (vp->v_flag & VXLOCK) {
		vp->v_flag |= VXWANT;
		simple_unlock(&vp->v_interlock);
		tsleep((caddr_t)vp, PINOD, "vget", 0);
		return (ENOENT);
	}

	vp->v_usecount++;

	if (VSHOULDBUSY(vp))
		vbusy(vp);
	if (flags & LK_TYPE_MASK) {
		if ((error = vn_lock(vp, flags | LK_INTERLOCK, p)) != 0) {
			/*
			 * must expand vrele here because we do not want
			 * to call VOP_INACTIVE if the reference count
			 * drops back to zero since it was never really
			 * active. We must remove it from the free list
			 * before sleeping so that multiple processes do
			 * not try to recycle it.
			 */
			simple_lock(&vp->v_interlock);
			vp->v_usecount--;
			if (VSHOULDFREE(vp))
				vfree(vp);
			simple_unlock(&vp->v_interlock);
		}
		return (error);
	}
	simple_unlock(&vp->v_interlock);
	return (0);
}

void
vref(struct vnode *vp)
{
	simple_lock(&vp->v_interlock);
	vp->v_usecount++;
	simple_unlock(&vp->v_interlock);
}

static __inline void
vfs_object_destroy(vp)
	struct vnode* vp;
{
	if (vp->v_type == VBLK && vp->v_object != NULL &&
	    vp->v_object->ref_count == 0)
		vm_object_terminate(vp->v_object);
}

/*
 * Vnode put/release.
 * If count drops to zero, call inactive routine and return to freelist.
 */
void
vrele(vp)
	struct vnode *vp;
{
	struct proc *p = curproc;	/* XXX */

#ifdef DIAGNOSTIC
	if (vp == NULL)
		panic("vrele: null vp");
#endif
	simple_lock(&vp->v_interlock);

	if (vp->v_usecount > 1) {

		vp->v_usecount--;
		simple_unlock(&vp->v_interlock);

		return;
	}

	if (vp->v_usecount == 1) {

		vfs_object_destroy(vp);
		vp->v_usecount--;
		if (VSHOULDFREE(vp))
			vfree(vp);
	/*
	 * If we are doing a vput, the node is already locked, and we must
	 * call VOP_INACTIVE with the node locked.  So, in the case of
	 * vrele, we explicitly lock the vnode before calling VOP_INACTIVE.
	 */
		if (vn_lock(vp, LK_EXCLUSIVE | LK_INTERLOCK, p) == 0) {
			VOP_INACTIVE(vp, p);
		}

	} else {
#ifdef DIAGNOSTIC
		vprint("vrele: negative ref count", vp);
		simple_unlock(&vp->v_interlock);
#endif
		panic("vrele: negative ref cnt");
	}
}

void
vput(vp)
	struct vnode *vp;
{
	struct proc *p = curproc;	/* XXX */

#ifdef DIAGNOSTIC
	if (vp == NULL)
		panic("vput: null vp");
#endif

	simple_lock(&vp->v_interlock);

	if (vp->v_usecount > 1) {

		vp->v_usecount--;
		VOP_UNLOCK(vp, LK_INTERLOCK, p);
		return;

	}

	if (vp->v_usecount == 1) {

		vfs_object_destroy(vp);
		vp->v_usecount--;
		if (VSHOULDFREE(vp))
			vfree(vp);
	/*
	 * If we are doing a vput, the node is already locked, and we must
	 * call VOP_INACTIVE with the node locked.  So, in the case of
	 * vrele, we explicitly lock the vnode before calling VOP_INACTIVE.
	 */
		simple_unlock(&vp->v_interlock);
		VOP_INACTIVE(vp, p);

	} else {
#ifdef DIAGNOSTIC
		vprint("vput: negative ref count", vp);
#endif
		panic("vput: negative ref cnt");
	}
}

/*
 * Somebody doesn't want the vnode recycled.
 */
void
vhold(vp)
	register struct vnode *vp;
{
	int s;

  	s = splbio();
	vp->v_holdcnt++;
	if (VSHOULDBUSY(vp))
		vbusy(vp);
	splx(s);
}

/*
 * One less who cares about this vnode.
 */
void
vdrop(vp)
	register struct vnode *vp;
{
	int s;

	s = splbio();
	if (vp->v_holdcnt <= 0)
		panic("vdrop: holdcnt");
	vp->v_holdcnt--;
	if (VSHOULDFREE(vp))
		vfree(vp);
	splx(s);
}

/*
 * Remove any vnodes in the vnode table belonging to mount point mp.
 *
 * If MNT_NOFORCE is specified, there should not be any active ones,
 * return error if any are found (nb: this is a user error, not a
 * system error). If MNT_FORCE is specified, detach any active vnodes
 * that are found.
 */
#ifdef DIAGNOSTIC
static int busyprt = 0;		/* print out busy vnodes */
SYSCTL_INT(_debug, OID_AUTO, busyprt, CTLFLAG_RW, &busyprt, 0, "");
#endif

int
vflush(mp, skipvp, flags)
	struct mount *mp;
	struct vnode *skipvp;
	int flags;
{
	struct proc *p = curproc;	/* XXX */
	struct vnode *vp, *nvp;
	int busy = 0;

	simple_lock(&mntvnode_slock);
loop:
	for (vp = mp->mnt_vnodelist.lh_first; vp; vp = nvp) {
		/*
		 * Make sure this vnode wasn't reclaimed in getnewvnode().
		 * Start over if it has (it won't be on the list anymore).
		 */
		if (vp->v_mount != mp)
			goto loop;
		nvp = vp->v_mntvnodes.le_next;
		/*
		 * Skip over a selected vnode.
		 */
		if (vp == skipvp)
			continue;

		simple_lock(&vp->v_interlock);
		/*
		 * Skip over a vnodes marked VSYSTEM.
		 */
		if ((flags & SKIPSYSTEM) && (vp->v_flag & VSYSTEM)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}
		/*
		 * If WRITECLOSE is set, only flush out regular file vnodes
		 * open for writing.
		 */
		if ((flags & WRITECLOSE) &&
		    (vp->v_writecount == 0 || vp->v_type != VREG)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}

		/*
		 * With v_usecount == 0, all we need to do is clear out the
		 * vnode data structures and we are done.
		 */
		if (vp->v_usecount == 0) {
			simple_unlock(&mntvnode_slock);
			vgonel(vp, p);
			simple_lock(&mntvnode_slock);
			continue;
		}

		/*
		 * If FORCECLOSE is set, forcibly close the vnode. For block
		 * or character devices, revert to an anonymous device. For
		 * all other files, just kill them.
		 */
		if (flags & FORCECLOSE) {
			simple_unlock(&mntvnode_slock);
			if (vp->v_type != VBLK && vp->v_type != VCHR) {
				vgonel(vp, p);
			} else {
				vclean(vp, 0, p);
				vp->v_op = spec_vnodeop_p;
				insmntque(vp, (struct mount *) 0);
			}
			simple_lock(&mntvnode_slock);
			continue;
		}
#ifdef DIAGNOSTIC
		if (busyprt)
			vprint("vflush: busy vnode", vp);
#endif
		simple_unlock(&vp->v_interlock);
		busy++;
	}
	simple_unlock(&mntvnode_slock);
	if (busy)
		return (EBUSY);
	return (0);
}

/*
 * Disassociate the underlying file system from a vnode.
 */
static void
vclean(vp, flags, p)
	struct vnode *vp;
	int flags;
	struct proc *p;
{
	int active;
	vm_object_t obj;

	/*
	 * Check to see if the vnode is in use. If so we have to reference it
	 * before we clean it out so that its count cannot fall to zero and
	 * generate a race against ourselves to recycle it.
	 */
	if ((active = vp->v_usecount))
		vp->v_usecount++;

	/*
	 * Prevent the vnode from being recycled or brought into use while we
	 * clean it out.
	 */
	if (vp->v_flag & VXLOCK)
		panic("vclean: deadlock");
	vp->v_flag |= VXLOCK;
	/*
	 * Even if the count is zero, the VOP_INACTIVE routine may still
	 * have the object locked while it cleans it out. The VOP_LOCK
	 * ensures that the VOP_INACTIVE routine is done with its work.
	 * For active vnodes, it ensures that no other activity can
	 * occur while the underlying object is being cleaned out.
	 */
	VOP_LOCK(vp, LK_DRAIN | LK_INTERLOCK, p);

	/*
	 * Clean out any buffers associated with the vnode.
	 */
	vinvalbuf(vp, V_SAVE, NOCRED, p, 0, 0);
	if (obj = vp->v_object) {
		if (obj->ref_count == 0) {
			/*
			 * This is a normal way of shutting down the object/vnode
			 * association.
			 */
			vm_object_terminate(obj);
		} else {
			/*
			 * Woe to the process that tries to page now :-).
			 */
			vm_pager_deallocate(obj);
		}
	}

	/*
	 * If purging an active vnode, it must be closed and
	 * deactivated before being reclaimed. Note that the
	 * VOP_INACTIVE will unlock the vnode.
	 */
	if (active) {
		if (flags & DOCLOSE)
			VOP_CLOSE(vp, IO_NDELAY, NOCRED, p);
		VOP_INACTIVE(vp, p);
	} else {
		/*
		 * Any other processes trying to obtain this lock must first
		 * wait for VXLOCK to clear, then call the new lock operation.
		 */
		VOP_UNLOCK(vp, 0, p);
	}
	/*
	 * Reclaim the vnode.
	 */
	if (VOP_RECLAIM(vp, p))
		panic("vclean: cannot reclaim");

	if (active)
		vrele(vp);

	cache_purge(vp);
	if (vp->v_vnlock) {
#if 0 /* This is the only place we have LK_DRAINED in the entire kernel ??? */
#ifdef DIAGNOSTIC
		if ((vp->v_vnlock->lk_flags & LK_DRAINED) == 0)
			vprint("vclean: lock not drained", vp);
#endif
#endif
		FREE(vp->v_vnlock, M_VNODE);
		vp->v_vnlock = NULL;
	}

	if (VSHOULDFREE(vp))
		vfree(vp);

	/*
	 * Done with purge, notify sleepers of the grim news.
	 */
	vp->v_op = dead_vnodeop_p;
	vn_pollgone(vp);
	vp->v_tag = VT_NON;
	vp->v_flag &= ~VXLOCK;
	if (vp->v_flag & VXWANT) {
		vp->v_flag &= ~VXWANT;
		wakeup((caddr_t) vp);
	}
}

/*
 * Eliminate all activity associated with the requested vnode
 * and with all vnodes aliased to the requested vnode.
 */
int
vop_revoke(ap)
	struct vop_revoke_args /* {
		struct vnode *a_vp;
		int a_flags;
	} */ *ap;
{
	struct vnode *vp, *vq;
	struct proc *p = curproc;	/* XXX */

#ifdef DIAGNOSTIC
	if ((ap->a_flags & REVOKEALL) == 0)
		panic("vop_revoke");
#endif

	vp = ap->a_vp;
	simple_lock(&vp->v_interlock);

	if (vp->v_flag & VALIASED) {
		/*
		 * If a vgone (or vclean) is already in progress,
		 * wait until it is done and return.
		 */
		if (vp->v_flag & VXLOCK) {
			vp->v_flag |= VXWANT;
			simple_unlock(&vp->v_interlock);
			tsleep((caddr_t)vp, PINOD, "vop_revokeall", 0);
			return (0);
		}
		/*
		 * Ensure that vp will not be vgone'd while we
		 * are eliminating its aliases.
		 */
		vp->v_flag |= VXLOCK;
		simple_unlock(&vp->v_interlock);
		while (vp->v_flag & VALIASED) {
			simple_lock(&spechash_slock);
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_rdev != vp->v_rdev ||
				    vq->v_type != vp->v_type || vp == vq)
					continue;
				simple_unlock(&spechash_slock);
				vgone(vq);
				break;
			}
			if (vq == NULLVP) {
				simple_unlock(&spechash_slock);
			}
		}
		/*
		 * Remove the lock so that vgone below will
		 * really eliminate the vnode after which time
		 * vgone will awaken any sleepers.
		 */
		simple_lock(&vp->v_interlock);
		vp->v_flag &= ~VXLOCK;
		if (vp->v_flag & VXWANT) {
			vp->v_flag &= ~VXWANT;
			wakeup(vp);
		}
	}
	vgonel(vp, p);
	return (0);
}

/*
 * Recycle an unused vnode to the front of the free list.
 * Release the passed interlock if the vnode will be recycled.
 */
int
vrecycle(vp, inter_lkp, p)
	struct vnode *vp;
	struct simplelock *inter_lkp;
	struct proc *p;
{

	simple_lock(&vp->v_interlock);
	if (vp->v_usecount == 0) {
		if (inter_lkp) {
			simple_unlock(inter_lkp);
		}
		vgonel(vp, p);
		return (1);
	}
	simple_unlock(&vp->v_interlock);
	return (0);
}

/*
 * Eliminate all activity associated with a vnode
 * in preparation for reuse.
 */
void
vgone(vp)
	register struct vnode *vp;
{
	struct proc *p = curproc;	/* XXX */

	simple_lock(&vp->v_interlock);
	vgonel(vp, p);
}

/*
 * vgone, with the vp interlock held.
 */
static void
vgonel(vp, p)
	struct vnode *vp;
	struct proc *p;
{
	int s;
	struct vnode *vq;
	struct vnode *vx;

	/*
	 * If a vgone (or vclean) is already in progress,
	 * wait until it is done and return.
	 */
	if (vp->v_flag & VXLOCK) {
		vp->v_flag |= VXWANT;
		simple_unlock(&vp->v_interlock);
		tsleep((caddr_t)vp, PINOD, "vgone", 0);
		return;
	}

	/*
	 * Clean out the filesystem specific data.
	 */
	vclean(vp, DOCLOSE, p);
	simple_lock(&vp->v_interlock);

	/*
	 * Delete from old mount point vnode list, if on one.
	 */
	if (vp->v_mount != NULL)
		insmntque(vp, (struct mount *)0);
	/*
	 * If special device, remove it from special device alias list
	 * if it is on one.
	 */
	if ((vp->v_type == VBLK || vp->v_type == VCHR) && vp->v_specinfo != 0) {
		simple_lock(&spechash_slock);
		if (*vp->v_hashchain == vp) {
			*vp->v_hashchain = vp->v_specnext;
		} else {
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_specnext != vp)
					continue;
				vq->v_specnext = vp->v_specnext;
				break;
			}
			if (vq == NULL)
				panic("missing bdev");
		}
		if (vp->v_flag & VALIASED) {
			vx = NULL;
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_rdev != vp->v_rdev ||
				    vq->v_type != vp->v_type)
					continue;
				if (vx)
					break;
				vx = vq;
			}
			if (vx == NULL)
				panic("missing alias");
			if (vq == NULL)
				vx->v_flag &= ~VALIASED;
			vp->v_flag &= ~VALIASED;
		}
		simple_unlock(&spechash_slock);
		FREE(vp->v_specinfo, M_VNODE);
		vp->v_specinfo = NULL;
	}

	/*
	 * If it is on the freelist and not already at the head,
	 * move it to the head of the list. The test of the back
	 * pointer and the reference count of zero is because
	 * it will be removed from the free list by getnewvnode,
	 * but will not have its reference count incremented until
	 * after calling vgone. If the reference count were
	 * incremented first, vgone would (incorrectly) try to
	 * close the previous instance of the underlying object.
	 */
	if (vp->v_usecount == 0 && !(vp->v_flag & VDOOMED)) {
		s = splbio();
		simple_lock(&vnode_free_list_slock);
		if (vp->v_flag & VFREE) {
			TAILQ_REMOVE(&vnode_free_list, vp, v_freelist);
		} else if (vp->v_flag & VTBFREE) {
			TAILQ_REMOVE(&vnode_tobefree_list, vp, v_freelist);
			vp->v_flag &= ~VTBFREE;
			freevnodes++;
		} else
			freevnodes++;
		vp->v_flag |= VFREE;
		TAILQ_INSERT_HEAD(&vnode_free_list, vp, v_freelist);
		simple_unlock(&vnode_free_list_slock);
		splx(s);
	}

	vp->v_type = VBAD;
	simple_unlock(&vp->v_interlock);
}

/*
 * Lookup a vnode by device number.
 */
int
vfinddev(dev, type, vpp)
	dev_t dev;
	enum vtype type;
	struct vnode **vpp;
{
	register struct vnode *vp;
	int rc = 0;

	simple_lock(&spechash_slock);
	for (vp = speclisth[SPECHASH(dev)]; vp; vp = vp->v_specnext) {
		if (dev != vp->v_rdev || type != vp->v_type)
			continue;
		*vpp = vp;
		rc = 1;
		break;
	}
	simple_unlock(&spechash_slock);
	return (rc);
}

/*
 * Calculate the total number of references to a special device.
 */
int
vcount(vp)
	register struct vnode *vp;
{
	struct vnode *vq, *vnext;
	int count;

loop:
	if ((vp->v_flag & VALIASED) == 0)
		return (vp->v_usecount);
	simple_lock(&spechash_slock);
	for (count = 0, vq = *vp->v_hashchain; vq; vq = vnext) {
		vnext = vq->v_specnext;
		if (vq->v_rdev != vp->v_rdev || vq->v_type != vp->v_type)
			continue;
		/*
		 * Alias, but not in use, so flush it out.
		 */
		if (vq->v_usecount == 0 && vq != vp) {
			simple_unlock(&spechash_slock);
			vgone(vq);
			goto loop;
		}
		count += vq->v_usecount;
	}
	simple_unlock(&spechash_slock);
	return (count);
}
/*
 * Print out a description of a vnode.
 */
static char *typename[] =
{"VNON", "VREG", "VDIR", "VBLK", "VCHR", "VLNK", "VSOCK", "VFIFO", "VBAD"};

void
vprint(label, vp)
	char *label;
	register struct vnode *vp;
{
	char buf[64];

	if (label != NULL)
		printf("%s: %p: ", label, (void *)vp);
	else
		printf("%p: ", (void *)vp);
	printf("type %s, usecount %d, writecount %d, refcount %d,",
	    typename[vp->v_type], vp->v_usecount, vp->v_writecount,
	    vp->v_holdcnt);
	buf[0] = '\0';
	if (vp->v_flag & VROOT)
		strcat(buf, "|VROOT");
	if (vp->v_flag & VTEXT)
		strcat(buf, "|VTEXT");
	if (vp->v_flag & VSYSTEM)
		strcat(buf, "|VSYSTEM");
	if (vp->v_flag & VXLOCK)
		strcat(buf, "|VXLOCK");
	if (vp->v_flag & VXWANT)
		strcat(buf, "|VXWANT");
	if (vp->v_flag & VBWAIT)
		strcat(buf, "|VBWAIT");
	if (vp->v_flag & VALIASED)
		strcat(buf, "|VALIASED");
	if (vp->v_flag & VDOOMED)
		strcat(buf, "|VDOOMED");
	if (vp->v_flag & VFREE)
		strcat(buf, "|VFREE");
	if (vp->v_flag & VOBJBUF)
		strcat(buf, "|VOBJBUF");
	if (buf[0] != '\0')
		printf(" flags (%s)", &buf[1]);
	if (vp->v_data == NULL) {
		printf("\n");
	} else {
		printf("\n\t");
		VOP_PRINT(vp);
	}
}

#ifdef DDB
/*
 * List all of the locked vnodes in the system.
 * Called when debugging the kernel.
 */
static void
printlockedvnodes()
{
	struct proc *p = curproc;	/* XXX */
	struct mount *mp, *nmp;
	struct vnode *vp;

	printf("Locked vnodes\n");
	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		for (vp = mp->mnt_vnodelist.lh_first;
		     vp != NULL;
		     vp = vp->v_mntvnodes.le_next) {
			if (VOP_ISLOCKED(vp))
				vprint((char *)0, vp);
		}
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);
}
#endif

/*
 * Top level filesystem related information gathering.
 */
static int	sysctl_ovfs_conf __P(SYSCTL_HANDLER_ARGS);

static int
vfs_sysctl SYSCTL_HANDLER_ARGS
{
	int *name = (int *)arg1 - 1;	/* XXX */
	u_int namelen = arg2 + 1;	/* XXX */
	struct vfsconf *vfsp;

#if 1 || defined(COMPAT_PRELITE2)
	/* Resolve ambiguity between VFS_VFSCONF and VFS_GENERIC. */
	if (namelen == 1)
		return (sysctl_ovfs_conf(oidp, arg1, arg2, req));
#endif

#ifdef notyet
	/* all sysctl names at this level are at least name and field */
	if (namelen < 2)
		return (ENOTDIR);		/* overloaded */
	if (name[0] != VFS_GENERIC) {
		for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
			if (vfsp->vfc_typenum == name[0])
				break;
		if (vfsp == NULL)
			return (EOPNOTSUPP);
		return ((*vfsp->vfc_vfsops->vfs_sysctl)(&name[1], namelen - 1,
		    oldp, oldlenp, newp, newlen, p));
	}
#endif
	switch (name[1]) {
	case VFS_MAXTYPENUM:
		if (namelen != 2)
			return (ENOTDIR);
		return (SYSCTL_OUT(req, &maxvfsconf, sizeof(int)));
	case VFS_CONF:
		if (namelen != 3)
			return (ENOTDIR);	/* overloaded */
		for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
			if (vfsp->vfc_typenum == name[2])
				break;
		if (vfsp == NULL)
			return (EOPNOTSUPP);
		return (SYSCTL_OUT(req, vfsp, sizeof *vfsp));
	}
	return (EOPNOTSUPP);
}

SYSCTL_NODE(_vfs, VFS_GENERIC, generic, CTLFLAG_RD, vfs_sysctl,
	"Generic filesystem");

#if 1 || defined(COMPAT_PRELITE2)

static int
sysctl_ovfs_conf SYSCTL_HANDLER_ARGS
{
	int error;
	struct vfsconf *vfsp;
	struct ovfsconf ovfs;

	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next) {
		ovfs.vfc_vfsops = vfsp->vfc_vfsops;	/* XXX used as flag */
		strcpy(ovfs.vfc_name, vfsp->vfc_name);
		ovfs.vfc_index = vfsp->vfc_typenum;
		ovfs.vfc_refcount = vfsp->vfc_refcount;
		ovfs.vfc_flags = vfsp->vfc_flags;
		error = SYSCTL_OUT(req, &ovfs, sizeof ovfs);
		if (error)
			return error;
	}
	return 0;
}

#endif /* 1 || COMPAT_PRELITE2 */

static volatile int kinfo_vdebug = 1;

#if 0
#define KINFO_VNODESLOP	10
/*
 * Dump vnode list (via sysctl).
 * Copyout address of vnode followed by vnode.
 */
/* ARGSUSED */
static int
sysctl_vnode SYSCTL_HANDLER_ARGS
{
	struct proc *p = curproc;	/* XXX */
	struct mount *mp, *nmp;
	struct vnode *nvp, *vp;
	int error;

#define VPTRSZ	sizeof (struct vnode *)
#define VNODESZ	sizeof (struct vnode)

	req->lock = 0;
	if (!req->oldptr) /* Make an estimate */
		return (SYSCTL_OUT(req, 0,
			(numvnodes + KINFO_VNODESLOP) * (VPTRSZ + VNODESZ)));

	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
again:
		simple_lock(&mntvnode_slock);
		for (vp = mp->mnt_vnodelist.lh_first;
		     vp != NULL;
		     vp = nvp) {
			/*
			 * Check that the vp is still associated with
			 * this filesystem.  RACE: could have been
			 * recycled onto the same filesystem.
			 */
			if (vp->v_mount != mp) {
				simple_unlock(&mntvnode_slock);
				if (kinfo_vdebug)
					printf("kinfo: vp changed\n");
				goto again;
			}
			nvp = vp->v_mntvnodes.le_next;
			simple_unlock(&mntvnode_slock);
			if ((error = SYSCTL_OUT(req, &vp, VPTRSZ)) ||
			    (error = SYSCTL_OUT(req, vp, VNODESZ)))
				return (error);
			simple_lock(&mntvnode_slock);
		}
		simple_unlock(&mntvnode_slock);
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);

	return (0);
}
#endif

/*
 * XXX
 * Exporting the vnode list on large systems causes them to crash.
 * Exporting the vnode list on medium systems causes sysctl to coredump.
 */
#if 0
SYSCTL_PROC(_kern, KERN_VNODE, vnode, CTLTYPE_OPAQUE|CTLFLAG_RD,
	0, 0, sysctl_vnode, "S,vnode", "");
#endif

/*
 * Check to see if a filesystem is mounted on a block device.
 */
int
vfs_mountedon(vp)
	struct vnode *vp;
{
	struct vnode *vq;
	int error = 0;

	if (vp->v_specmountpoint != NULL)
		return (EBUSY);
	if (vp->v_flag & VALIASED) {
		simple_lock(&spechash_slock);
		for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
			if (vq->v_rdev != vp->v_rdev ||
			    vq->v_type != vp->v_type)
				continue;
			if (vq->v_specmountpoint != NULL) {
				error = EBUSY;
				break;
			}
		}
		simple_unlock(&spechash_slock);
	}
	return (error);
}

/*
 * Unmount all filesystems. The list is traversed in reverse order
 * of mounting to avoid dependencies.
 */
void
vfs_unmountall()
{
	struct mount *mp, *nmp;
	struct proc *p;
	int error;

	if (curproc != NULL)
		p = curproc;
	else
		p = initproc;	/* XXX XXX should this be proc0? */
	/*
	 * Since this only runs when rebooting, it is not interlocked.
	 */
	for (mp = mountlist.cqh_last; mp != (void *)&mountlist; mp = nmp) {
		nmp = mp->mnt_list.cqe_prev;
		error = dounmount(mp, MNT_FORCE, p);
		if (error) {
			printf("unmount of %s failed (",
			    mp->mnt_stat.f_mntonname);
			if (error == EBUSY)
				printf("BUSY)\n");
			else
				printf("%d)\n", error);
		}
	}
}

/*
 * Build hash lists of net addresses and hang them off the mount point.
 * Called by ufs_mount() to set up the lists of export addresses.
 */
static int
vfs_hang_addrlist(mp, nep, argp)
	struct mount *mp;
	struct netexport *nep;
	struct export_args *argp;
{
	register struct netcred *np;
	register struct radix_node_head *rnh;
	register int i;
	struct radix_node *rn;
	struct sockaddr *saddr, *smask = 0;
	struct domain *dom;
	int error;

	if (argp->ex_addrlen == 0) {
		if (mp->mnt_flag & MNT_DEFEXPORTED)
			return (EPERM);
		np = &nep->ne_defexported;
		np->netc_exflags = argp->ex_flags;
		np->netc_anon = argp->ex_anon;
		np->netc_anon.cr_ref = 1;
		mp->mnt_flag |= MNT_DEFEXPORTED;
		return (0);
	}
	i = sizeof(struct netcred) + argp->ex_addrlen + argp->ex_masklen;
	np = (struct netcred *) malloc(i, M_NETADDR, M_WAITOK);
	bzero((caddr_t) np, i);
	saddr = (struct sockaddr *) (np + 1);
	if ((error = copyin(argp->ex_addr, (caddr_t) saddr, argp->ex_addrlen)))
		goto out;
	if (saddr->sa_len > argp->ex_addrlen)
		saddr->sa_len = argp->ex_addrlen;
	if (argp->ex_masklen) {
		smask = (struct sockaddr *) ((caddr_t) saddr + argp->ex_addrlen);
		error = copyin(argp->ex_mask, (caddr_t) smask, argp->ex_masklen);
		if (error)
			goto out;
		if (smask->sa_len > argp->ex_masklen)
			smask->sa_len = argp->ex_masklen;
	}
	i = saddr->sa_family;
	if ((rnh = nep->ne_rtable[i]) == 0) {
		/*
		 * Seems silly to initialize every AF when most are not used,
		 * do so on demand here
		 */
		for (dom = domains; dom; dom = dom->dom_next)
			if (dom->dom_family == i && dom->dom_rtattach) {
				dom->dom_rtattach((void **) &nep->ne_rtable[i],
				    dom->dom_rtoffset);
				break;
			}
		if ((rnh = nep->ne_rtable[i]) == 0) {
			error = ENOBUFS;
			goto out;
		}
	}
	rn = (*rnh->rnh_addaddr) ((caddr_t) saddr, (caddr_t) smask, rnh,
	    np->netc_rnodes);
	if (rn == 0 || np != (struct netcred *) rn) {	/* already exists */
		error = EPERM;
		goto out;
	}
	np->netc_exflags = argp->ex_flags;
	np->netc_anon = argp->ex_anon;
	np->netc_anon.cr_ref = 1;
	return (0);
out:
	free(np, M_NETADDR);
	return (error);
}

/* ARGSUSED */
static int
vfs_free_netcred(rn, w)
	struct radix_node *rn;
	void *w;
{
	register struct radix_node_head *rnh = (struct radix_node_head *) w;

	(*rnh->rnh_deladdr) (rn->rn_key, rn->rn_mask, rnh);
	free((caddr_t) rn, M_NETADDR);
	return (0);
}

/*
 * Free the net address hash lists that are hanging off the mount points.
 */
static void
vfs_free_addrlist(nep)
	struct netexport *nep;
{
	register int i;
	register struct radix_node_head *rnh;

	for (i = 0; i <= AF_MAX; i++)
		if ((rnh = nep->ne_rtable[i])) {
			(*rnh->rnh_walktree) (rnh, vfs_free_netcred,
			    (caddr_t) rnh);
			free((caddr_t) rnh, M_RTABLE);
			nep->ne_rtable[i] = 0;
		}
}

int
vfs_export(mp, nep, argp)
	struct mount *mp;
	struct netexport *nep;
	struct export_args *argp;
{
	int error;

	if (argp->ex_flags & MNT_DELEXPORT) {
		if (mp->mnt_flag & MNT_EXPUBLIC) {
			vfs_setpublicfs(NULL, NULL, NULL);
			mp->mnt_flag &= ~MNT_EXPUBLIC;
		}
		vfs_free_addrlist(nep);
		mp->mnt_flag &= ~(MNT_EXPORTED | MNT_DEFEXPORTED);
	}
	if (argp->ex_flags & MNT_EXPORTED) {
		if (argp->ex_flags & MNT_EXPUBLIC) {
			if ((error = vfs_setpublicfs(mp, nep, argp)) != 0)
				return (error);
			mp->mnt_flag |= MNT_EXPUBLIC;
		}
		if ((error = vfs_hang_addrlist(mp, nep, argp)))
			return (error);
		mp->mnt_flag |= MNT_EXPORTED;
	}
	return (0);
}


/*
 * Set the publicly exported filesystem (WebNFS). Currently, only
 * one public filesystem is possible in the spec (RFC 2054 and 2055)
 */
int
vfs_setpublicfs(mp, nep, argp)
	struct mount *mp;
	struct netexport *nep;
	struct export_args *argp;
{
	int error;
	struct vnode *rvp;
	char *cp;

	/*
	 * mp == NULL -> invalidate the current info, the FS is
	 * no longer exported. May be called from either vfs_export
	 * or unmount, so check if it hasn't already been done.
	 */
	if (mp == NULL) {
		if (nfs_pub.np_valid) {
			nfs_pub.np_valid = 0;
			if (nfs_pub.np_index != NULL) {
				FREE(nfs_pub.np_index, M_TEMP);
				nfs_pub.np_index = NULL;
			}
		}
		return (0);
	}

	/*
	 * Only one allowed at a time.
	 */
	if (nfs_pub.np_valid != 0 && mp != nfs_pub.np_mount)
		return (EBUSY);

	/*
	 * Get real filehandle for root of exported FS.
	 */
	bzero((caddr_t)&nfs_pub.np_handle, sizeof(nfs_pub.np_handle));
	nfs_pub.np_handle.fh_fsid = mp->mnt_stat.f_fsid;

	if ((error = VFS_ROOT(mp, &rvp)))
		return (error);

	if ((error = VFS_VPTOFH(rvp, &nfs_pub.np_handle.fh_fid)))
		return (error);

	vput(rvp);

	/*
	 * If an indexfile was specified, pull it in.
	 */
	if (argp->ex_indexfile != NULL) {
		MALLOC(nfs_pub.np_index, char *, MAXNAMLEN + 1, M_TEMP,
		    M_WAITOK);
		error = copyinstr(argp->ex_indexfile, nfs_pub.np_index,
		    MAXNAMLEN, (size_t *)0);
		if (!error) {
			/*
			 * Check for illegal filenames.
			 */
			for (cp = nfs_pub.np_index; *cp; cp++) {
				if (*cp == '/') {
					error = EINVAL;
					break;
				}
			}
		}
		if (error) {
			FREE(nfs_pub.np_index, M_TEMP);
			return (error);
		}
	}

	nfs_pub.np_mount = mp;
	nfs_pub.np_valid = 1;
	return (0);
}

struct netcred *
vfs_export_lookup(mp, nep, nam)
	register struct mount *mp;
	struct netexport *nep;
	struct sockaddr *nam;
{
	register struct netcred *np;
	register struct radix_node_head *rnh;
	struct sockaddr *saddr;

	np = NULL;
	if (mp->mnt_flag & MNT_EXPORTED) {
		/*
		 * Lookup in the export list first.
		 */
		if (nam != NULL) {
			saddr = nam;
			rnh = nep->ne_rtable[saddr->sa_family];
			if (rnh != NULL) {
				np = (struct netcred *)
					(*rnh->rnh_matchaddr)((caddr_t)saddr,
							      rnh);
				if (np && np->netc_rnodes->rn_flags & RNF_ROOT)
					np = NULL;
			}
		}
		/*
		 * If no address match, use the default if it exists.
		 */
		if (np == NULL && mp->mnt_flag & MNT_DEFEXPORTED)
			np = &nep->ne_defexported;
	}
	return (np);
}

/*
 * perform msync on all vnodes under a mount point
 * the mount point must be locked.
 */
void
vfs_msync(struct mount *mp, int flags) {
	struct vnode *vp, *nvp;
	struct vm_object *obj;
	int anyio, tries;

	tries = 5;
loop:
	anyio = 0;
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nvp) {

		nvp = vp->v_mntvnodes.le_next;

		if (vp->v_mount != mp) {
			goto loop;
		}

		if (vp->v_flag & VXLOCK)	/* XXX: what if MNT_WAIT? */
			continue;

		if (flags != MNT_WAIT) {
			obj = vp->v_object;
			if (obj == NULL || (obj->flags & OBJ_MIGHTBEDIRTY) == 0)
				continue;
			if (VOP_ISLOCKED(vp))
				continue;
		}

		simple_lock(&vp->v_interlock);
		if (vp->v_object &&
		   (vp->v_object->flags & OBJ_MIGHTBEDIRTY)) {
			if (!vget(vp,
				LK_INTERLOCK | LK_EXCLUSIVE | LK_RETRY | LK_NOOBJ, curproc)) {
				if (vp->v_object) {
					vm_object_page_clean(vp->v_object, 0, 0, TRUE);
					anyio = 1;
				}
				vput(vp);
			}
		} else {
			simple_unlock(&vp->v_interlock);
		}
	}
	if (anyio && (--tries > 0))
		goto loop;
}

/*
 * Create the VM object needed for VMIO and mmap support.  This
 * is done for all VREG files in the system.  Some filesystems might
 * afford the additional metadata buffering capability of the
 * VMIO code by making the device node be VMIO mode also.
 *
 * If !waslocked, must be called with interlock.
 */
int
vfs_object_create(vp, p, cred, waslocked)
	struct vnode *vp;
	struct proc *p;
	struct ucred *cred;
	int waslocked;
{
	struct vattr vat;
	vm_object_t object;
	int error = 0;

	if ((vp->v_type != VREG) && (vp->v_type != VBLK)) {
		if (!waslocked)
			simple_unlock(&vp->v_interlock);
		return 0;
	}

	if (!waslocked) 
		vn_lock(vp, LK_EXCLUSIVE | LK_INTERLOCK | LK_RETRY, p);

retry:
	if ((object = vp->v_object) == NULL) {
		if (vp->v_type == VREG) {
			if ((error = VOP_GETATTR(vp, &vat, cred, p)) != 0)
				goto retn;
			object = vnode_pager_alloc(vp,
				OFF_TO_IDX(round_page(vat.va_size)), 0, 0);
		} else if (major(vp->v_rdev) < nblkdev) {
			/*
			 * This simply allocates the biggest object possible
			 * for a VBLK vnode.  This should be fixed, but doesn't
			 * cause any problems (yet).
			 */
			object = vnode_pager_alloc(vp, INT_MAX, 0, 0);
		}
		object->ref_count--;
		vp->v_usecount--;
	} else {
		if (object->flags & OBJ_DEAD) {
			VOP_UNLOCK(vp, 0, p);
			tsleep(object, PVM, "vodead", 0);
			vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
			goto retry;
		}
	}

	if (vp->v_object) {
		vp->v_flag |= VOBJBUF;
	}

retn:
	if (!waslocked) {
		simple_lock(&vp->v_interlock);
		VOP_UNLOCK(vp, LK_INTERLOCK, p);
	}

	return error;
}

static void
vfree(vp)
	struct vnode *vp;
{
	int s;

	s = splbio();
	simple_lock(&vnode_free_list_slock);
	if (vp->v_flag & VTBFREE) {
		TAILQ_REMOVE(&vnode_tobefree_list, vp, v_freelist);
		vp->v_flag &= ~VTBFREE;
	}
	if (vp->v_flag & VAGE) {
		TAILQ_INSERT_HEAD(&vnode_free_list, vp, v_freelist);
	} else {
		TAILQ_INSERT_TAIL(&vnode_free_list, vp, v_freelist);
	}
	freevnodes++;
	simple_unlock(&vnode_free_list_slock);
	vp->v_flag &= ~VAGE;
	vp->v_flag |= VFREE;
	splx(s);
}

void
vbusy(vp)
	struct vnode *vp;
{
	int s;

	s = splbio();
	simple_lock(&vnode_free_list_slock);
	if (vp->v_flag & VTBFREE) {
		TAILQ_REMOVE(&vnode_tobefree_list, vp, v_freelist);
		vp->v_flag &= ~VTBFREE;
	} else {
		TAILQ_REMOVE(&vnode_free_list, vp, v_freelist);
		freevnodes--;
	}
	simple_unlock(&vnode_free_list_slock);
	vp->v_flag &= ~(VFREE|VAGE);
	splx(s);
}

/*
 * Record a process's interest in events which might happen to
 * a vnode.  Because poll uses the historic select-style interface
 * internally, this routine serves as both the ``check for any
 * pending events'' and the ``record my interest in future events''
 * functions.  (These are done together, while the lock is held,
 * to avoid race conditions.)
 */
int
vn_pollrecord(vp, p, events)
	struct vnode *vp;
	struct proc *p;
	short events;
{
	simple_lock(&vp->v_pollinfo.vpi_lock);
	if (vp->v_pollinfo.vpi_revents & events) {
		/*
		 * This leaves events we are not interested
		 * in available for the other process which
		 * which presumably had requested them
		 * (otherwise they would never have been
		 * recorded).
		 */
		events &= vp->v_pollinfo.vpi_revents;
		vp->v_pollinfo.vpi_revents &= ~events;

		simple_unlock(&vp->v_pollinfo.vpi_lock);
		return events;
	}
	vp->v_pollinfo.vpi_events |= events;
	selrecord(p, &vp->v_pollinfo.vpi_selinfo);
	simple_unlock(&vp->v_pollinfo.vpi_lock);
	return 0;
}

/*
 * Note the occurrence of an event.  If the VN_POLLEVENT macro is used,
 * it is possible for us to miss an event due to race conditions, but
 * that condition is expected to be rare, so for the moment it is the
 * preferred interface.
 */
void
vn_pollevent(vp, events)
	struct vnode *vp;
	short events;
{
	simple_lock(&vp->v_pollinfo.vpi_lock);
	if (vp->v_pollinfo.vpi_events & events) {
		/*
		 * We clear vpi_events so that we don't
		 * call selwakeup() twice if two events are
		 * posted before the polling process(es) is
		 * awakened.  This also ensures that we take at
		 * most one selwakeup() if the polling process
		 * is no longer interested.  However, it does
		 * mean that only one event can be noticed at
		 * a time.  (Perhaps we should only clear those
		 * event bits which we note?) XXX
		 */
		vp->v_pollinfo.vpi_events = 0;	/* &= ~events ??? */
		vp->v_pollinfo.vpi_revents |= events;
		selwakeup(&vp->v_pollinfo.vpi_selinfo);
	}
	simple_unlock(&vp->v_pollinfo.vpi_lock);
}

/*
 * Wake up anyone polling on vp because it is being revoked.
 * This depends on dead_poll() returning POLLHUP for correct
 * behavior.
 */
void
vn_pollgone(vp)
	struct vnode *vp;
{
	simple_lock(&vp->v_pollinfo.vpi_lock);
	if (vp->v_pollinfo.vpi_events) {
		vp->v_pollinfo.vpi_events = 0;
		selwakeup(&vp->v_pollinfo.vpi_selinfo);
	}
	simple_unlock(&vp->v_pollinfo.vpi_lock);
}



/*
 * Routine to create and manage a filesystem syncer vnode.
 */
#define sync_close ((int (*) __P((struct  vop_close_args *)))nullop)
int	sync_fsync __P((struct  vop_fsync_args *));
int	sync_inactive __P((struct  vop_inactive_args *));
int	sync_reclaim  __P((struct  vop_reclaim_args *));
#define sync_lock ((int (*) __P((struct  vop_lock_args *)))vop_nolock)
#define sync_unlock ((int (*) __P((struct  vop_unlock_args *)))vop_nounlock)
int	sync_print __P((struct vop_print_args *));
#define sync_islocked ((int(*) __P((struct vop_islocked_args *)))vop_noislocked)

vop_t **sync_vnodeop_p;
struct vnodeopv_entry_desc sync_vnodeop_entries[] = {
	{ &vop_default_desc,	(vop_t *) vop_eopnotsupp },
	{ &vop_close_desc,	(vop_t *) sync_close },		/* close */
	{ &vop_fsync_desc,	(vop_t *) sync_fsync },		/* fsync */
	{ &vop_inactive_desc,	(vop_t *) sync_inactive },	/* inactive */
	{ &vop_reclaim_desc,	(vop_t *) sync_reclaim },	/* reclaim */
	{ &vop_lock_desc,	(vop_t *) sync_lock },		/* lock */
	{ &vop_unlock_desc,	(vop_t *) sync_unlock },	/* unlock */
	{ &vop_print_desc,	(vop_t *) sync_print },		/* print */
	{ &vop_islocked_desc,	(vop_t *) sync_islocked },	/* islocked */
	{ NULL, NULL }
};
struct vnodeopv_desc sync_vnodeop_opv_desc =
	{ &sync_vnodeop_p, sync_vnodeop_entries };

VNODEOP_SET(sync_vnodeop_opv_desc);

/*
 * Create a new filesystem syncer vnode for the specified mount point.
 */
int
vfs_allocate_syncvnode(mp)
	struct mount *mp;
{
	struct vnode *vp;
	static long start, incr, next;
	int error;

	/* Allocate a new vnode */
	if ((error = getnewvnode(VT_VFS, mp, sync_vnodeop_p, &vp)) != 0) {
		mp->mnt_syncer = NULL;
		return (error);
	}
	vp->v_type = VNON;
	/*
	 * Place the vnode onto the syncer worklist. We attempt to
	 * scatter them about on the list so that they will go off
	 * at evenly distributed times even if all the filesystems
	 * are mounted at once.
	 */
	next += incr;
	if (next == 0 || next > syncer_maxdelay) {
		start /= 2;
		incr /= 2;
		if (start == 0) {
			start = syncer_maxdelay / 2;
			incr = syncer_maxdelay;
		}
		next = start;
	}
	vn_syncer_add_to_worklist(vp, syncdelay > 0 ? next % syncdelay : 0);
	mp->mnt_syncer = vp;
	return (0);
}

/*
 * Do a lazy sync of the filesystem.
 */
int
sync_fsync(ap)
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		struct ucred *a_cred;
		int a_waitfor;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *syncvp = ap->a_vp;
	struct mount *mp = syncvp->v_mount;
	struct proc *p = ap->a_p;
	int asyncflag;

	/*
	 * We only need to do something if this is a lazy evaluation.
	 */
	if (ap->a_waitfor != MNT_LAZY)
		return (0);

	/*
	 * Move ourselves to the back of the sync list.
	 */
	vn_syncer_add_to_worklist(syncvp, syncdelay);

	/*
	 * Walk the list of vnodes pushing all that are dirty and
	 * not already on the sync list.
	 */
	simple_lock(&mountlist_slock);
	if (vfs_busy(mp, LK_EXCLUSIVE | LK_NOWAIT, &mountlist_slock, p) != 0) {
		simple_unlock(&mountlist_slock);
		return (0);
	}
	asyncflag = mp->mnt_flag & MNT_ASYNC;
	mp->mnt_flag &= ~MNT_ASYNC;
	vfs_msync(mp, MNT_NOWAIT);
	VFS_SYNC(mp, MNT_LAZY, ap->a_cred, p);
	if (asyncflag)
		mp->mnt_flag |= MNT_ASYNC;
	vfs_unbusy(mp, p);
	return (0);
}

/*
 * The syncer vnode is no referenced.
 */
int
sync_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap;
{

	vgone(ap->a_vp);
	return (0);
}

/*
 * The syncer vnode is no longer needed and is being decommissioned.
 */
int
sync_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	vp->v_mount->mnt_syncer = NULL;
	if (vp->v_flag & VONWORKLST) {
		LIST_REMOVE(vp, v_synclist);
		vp->v_flag &= ~VONWORKLST;
	}

	return (0);
}

/*
 * Print out a syncer vnode.
 */
int
sync_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	printf("syncer vnode");
	if (vp->v_vnlock != NULL)
		lockmgr_printinfo(vp->v_vnlock);
	printf("\n");
	return (0);
}
