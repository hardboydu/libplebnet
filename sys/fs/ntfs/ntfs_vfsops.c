/*	$NetBSD: ntfs_vfsops.c,v 1.23 1999/11/15 19:38:14 jdolecek Exp $	*/

/*-
 * Copyright (c) 1998, 1999 Semen Ustimenko
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>

/*#define NTFS_DEBUG 1*/
#include <fs/ntfs/ntfs.h>
#include <fs/ntfs/ntfs_inode.h>
#include <fs/ntfs/ntfs_subr.h>
#include <fs/ntfs/ntfs_vfsops.h>
#include <fs/ntfs/ntfs_ihash.h>
#include <fs/ntfs/ntfsmount.h>

MALLOC_DEFINE(M_NTFSMNT, "NTFS mount", "NTFS mount structure");
MALLOC_DEFINE(M_NTFSNTNODE,"NTFS ntnode",  "NTFS ntnode information");
MALLOC_DEFINE(M_NTFSFNODE,"NTFS fnode",  "NTFS fnode information");
MALLOC_DEFINE(M_NTFSDIR,"NTFS dir",  "NTFS dir buffer");

struct sockaddr;

static int	ntfs_mountfs(register struct vnode *, struct mount *, 
				  struct ntfs_args *, struct thread *);

static vfs_init_t       ntfs_init;
static vfs_uninit_t     ntfs_uninit;
static vfs_vget_t       ntfs_vget;
static vfs_fhtovp_t     ntfs_fhtovp;
static vfs_mount_t      ntfs_mount;
static vfs_root_t       ntfs_root;
static vfs_statfs_t     ntfs_statfs;
static vfs_unmount_t    ntfs_unmount;
static vfs_vptofh_t     ntfs_vptofh;

static int
ntfs_init (
	struct vfsconf *vcp )
{
	ntfs_nthashinit();
	ntfs_toupper_init();
	return 0;
}

static int
ntfs_uninit (
	struct vfsconf *vcp )
{
	ntfs_toupper_destroy();
	ntfs_nthashdestroy();
	return 0;
}

static int
ntfs_mount ( 
	struct mount *mp,
	char *path,
	caddr_t data,
	struct nameidata *ndp,
	struct thread *td )
{
	size_t		size;
	int		err = 0;
	struct vnode	*devvp;
	struct ntfs_args args;

	/*
	 * Use NULL path to flag a root mount
	 */
	if( path == NULL) {
		/*
		 ***
		 * Mounting root filesystem
		 ***
		 */
	
		/* Get vnode for root device*/
		if( bdevvp( rootdev, &rootvp))
			panic("ntfs_mountroot: can't setup bdevvp for root");

		/*
		 * FS specific handling
		 */
		mp->mnt_flag |= MNT_RDONLY;	/* XXX globally applicable?*/

		/*
		 * Attempt mount
		 */
		if( ( err = ntfs_mountfs(rootvp, mp, &args, td)) != 0) {
			/* fs specific cleanup (if any)*/
			goto error_1;
		}

		goto dostatfs;		/* success*/

	}

	/*
	 ***
	 * Mounting non-root filesystem or updating a filesystem
	 ***
	 */

	/* copy in user arguments*/
	err = copyin(data, (caddr_t)&args, sizeof (struct ntfs_args));
	if (err)
		goto error_1;		/* can't get arguments*/

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		/* if not updating name...*/
		if (args.fspec == 0) {
			/*
			 * Process export requests.  Jumping to "success"
			 * will return the vfs_export() error code.
			 */
			err = vfs_export(mp, &args.export);
			goto success;
		}

		printf("ntfs_mount(): MNT_UPDATE not supported\n");
		err = EINVAL;
		goto error_1;
	}

	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible block device.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW, UIO_USERSPACE, args.fspec, td);
	err = namei(ndp);
	if (err) {
		/* can't get devvp!*/
		goto error_1;
	}
	NDFREE(ndp, NDF_ONLY_PNBUF);
	devvp = ndp->ni_vp;

	if (!vn_isdisk(devvp, &err)) 
		goto error_2;
	if (mp->mnt_flag & MNT_UPDATE) {
#if 0
		/*
		 ********************
		 * UPDATE
		 ********************
		 */

		if (devvp != ntmp->um_devvp)
			err = EINVAL;	/* needs translation */
		else
			vrele(devvp);
		/*
		 * Update device name only on success
		 */
		if( !err) {
			/* Save "mounted from" info for mount point (NULL pad)*/
			copyinstr(	args.fspec,
					mp->mnt_stat.f_mntfromname,
					MNAMELEN - 1,
					&size);
			bzero( mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
		}
#endif
	} else {
		/*
		 ********************
		 * NEW MOUNT
		 ********************
		 */

		/*
		 * Since this is a new mount, we want the names for
		 * the device and the mount point copied in.  If an
		 * error occurs, the mountpoint is discarded by the
		 * upper level code.  Note that vfs_mount() handles
		 * copying the mountpoint f_mntonname for us, so we
		 * don't have to do it here unless we want to set it
		 * to something other than "path" for some rason.
		 */
		/* Save "mounted from" info for mount point (NULL pad)*/
		copyinstr(	args.fspec,			/* device name*/
				mp->mnt_stat.f_mntfromname,	/* save area*/
				MNAMELEN - 1,			/* max size*/
				&size);				/* real size*/
		bzero( mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);

		err = ntfs_mountfs(devvp, mp, &args, td);
	}
	if (err) {
		goto error_2;
	}

dostatfs:
	/*
	 * Initialize FS stat information in mount struct; uses both
	 * mp->mnt_stat.f_mntonname and mp->mnt_stat.f_mntfromname
	 *
	 * This code is common to root and non-root mounts
	 */
	(void)VFS_STATFS(mp, &mp->mnt_stat, td);

	goto success;


error_2:	/* error with devvp held*/

	/* release devvp before failing*/
	vrele(devvp);

error_1:	/* no state to back out*/

success:
	return(err);
}

/*
 * Common code for mount and mountroot
 */
int
ntfs_mountfs(devvp, mp, argsp, td)
	register struct vnode *devvp;
	struct mount *mp;
	struct ntfs_args *argsp;
	struct thread *td;
{
	struct buf *bp;
	struct ntfsmount *ntmp;
	struct cdev *dev = devvp->v_rdev;
	int error, ronly, ncount, i;
	struct vnode *vp;

	/*
	 * Disallow multiple mounts of the same device.
	 * Disallow mounting of a device that is currently in use
	 * (except for root, which might share swap device for miniroot).
	 * Flush out any old buffers remaining from a previous use.
	 */
	error = vfs_mountedon(devvp);
	if (error)
		return (error);
	ncount = vcount(devvp);
	if (devvp->v_object)
		ncount -= 1;
	if (ncount > 1 && devvp != rootvp)
		return (EBUSY);
	vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, td);
	error = vinvalbuf(devvp, V_SAVE, td->td_ucred, td, 0, 0);
	VOP_UNLOCK(devvp, 0, td);
	if (error)
		return (error);

	ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
	vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, td);
	error = VOP_OPEN(devvp, ronly ? FREAD : FREAD|FWRITE, FSCRED, td, -1);
	VOP_UNLOCK(devvp, 0, td);
	if (error)
		return (error);

	bp = NULL;

	error = bread(devvp, BBLOCK, BBSIZE, NOCRED, &bp);
	if (error)
		goto out;
	ntmp = malloc( sizeof *ntmp, M_NTFSMNT, M_WAITOK | M_ZERO);
	bcopy( bp->b_data, &ntmp->ntm_bootfile, sizeof(struct bootfile) );
	/*
	 * We must not cache the boot block if its size is not exactly
	 * one cluster in order to avoid confusing the buffer cache when
	 * the boot file is read later by ntfs_readntvattr_plain(), which
	 * reads a cluster at a time.
	 */
	if (ntfs_cntob(1) != BBSIZE)
		bp->b_flags |= B_NOCACHE;
	brelse( bp );
	bp = NULL;

	if (strncmp(ntmp->ntm_bootfile.bf_sysid, NTFS_BBID, NTFS_BBIDLEN)) {
		error = EINVAL;
		dprintf(("ntfs_mountfs: invalid boot block\n"));
		goto out;
	}

	{
		int8_t cpr = ntmp->ntm_mftrecsz;
		if( cpr > 0 )
			ntmp->ntm_bpmftrec = ntmp->ntm_spc * cpr;
		else
			ntmp->ntm_bpmftrec = (1 << (-cpr)) / ntmp->ntm_bps;
	}
	dprintf(("ntfs_mountfs(): bps: %d, spc: %d, media: %x, mftrecsz: %d (%d sects)\n",
		ntmp->ntm_bps,ntmp->ntm_spc,ntmp->ntm_bootfile.bf_media,
		ntmp->ntm_mftrecsz,ntmp->ntm_bpmftrec));
	dprintf(("ntfs_mountfs(): mftcn: 0x%x|0x%x\n",
		(u_int32_t)ntmp->ntm_mftcn,(u_int32_t)ntmp->ntm_mftmirrcn));

	ntmp->ntm_mountp = mp;
	ntmp->ntm_dev = dev;
	ntmp->ntm_devvp = devvp;
	ntmp->ntm_uid = argsp->uid;
	ntmp->ntm_gid = argsp->gid;
	ntmp->ntm_mode = argsp->mode;
	ntmp->ntm_flag = argsp->flag;

	/* Copy in the 8-bit to Unicode conversion table */
	/* Initialize Unicode to 8-bit table from 8toU table */
	if (argsp->flag & NTFS_MFLAG_KICONV) {
		ntfs_82u_init(ntmp, argsp->cs_local, argsp->cs_ntfs);
		ntfs_u28_init(ntmp, NULL, argsp->cs_local, argsp->cs_ntfs);
	} else {
		ntfs_82u_init(ntmp, NULL, NULL);
		ntfs_u28_init(ntmp, ntmp->ntm_82u, NULL, NULL);
	}

	mp->mnt_data = (qaddr_t)ntmp;

	dprintf(("ntfs_mountfs(): case-%s,%s uid: %d, gid: %d, mode: %o\n",
		(ntmp->ntm_flag & NTFS_MFLAG_CASEINS)?"insens.":"sens.",
		(ntmp->ntm_flag & NTFS_MFLAG_ALLNAMES)?" allnames,":"",
		ntmp->ntm_uid, ntmp->ntm_gid, ntmp->ntm_mode));

	/*
	 * We read in some system nodes to do not allow 
	 * reclaim them and to have everytime access to them.
	 */ 
	{
		int pi[3] = { NTFS_MFTINO, NTFS_ROOTINO, NTFS_BITMAPINO };
		for (i=0; i<3; i++) {
			error = VFS_VGET(mp, pi[i], LK_EXCLUSIVE,
					 &(ntmp->ntm_sysvn[pi[i]]));
			if(error)
				goto out1;
			ntmp->ntm_sysvn[pi[i]]->v_vflag |= VV_SYSTEM;
			VREF(ntmp->ntm_sysvn[pi[i]]);
			vput(ntmp->ntm_sysvn[pi[i]]);
		}
	}

	/* read the Unicode lowercase --> uppercase translation table,
	 * if necessary */
	if ((error = ntfs_toupper_use(mp, ntmp)))
		goto out1;

	/*
	 * Scan $BitMap and count free clusters
	 */
	error = ntfs_calccfree(ntmp, &ntmp->ntm_cfree);
	if(error)
		goto out1;

	/*
	 * Read and translate to internal format attribute
	 * definition file. 
	 */
	{
		int num,j;
		struct attrdef ad;

		/* Open $AttrDef */
		error = VFS_VGET(mp, NTFS_ATTRDEFINO, LK_EXCLUSIVE, &vp );
		if(error) 
			goto out1;

		/* Count valid entries */
		for(num=0;;num++) {
			error = ntfs_readattr(ntmp, VTONT(vp),
					NTFS_A_DATA, NULL,
					num * sizeof(ad), sizeof(ad),
					&ad, NULL);
			if (error)
				goto out1;
			if (ad.ad_name[0] == 0)
				break;
		}

		/* Alloc memory for attribute definitions */
		MALLOC(ntmp->ntm_ad, struct ntvattrdef *,
			num * sizeof(struct ntvattrdef),
			M_NTFSMNT, M_WAITOK);

		ntmp->ntm_adnum = num;

		/* Read them and translate */
		for(i=0;i<num;i++){
			error = ntfs_readattr(ntmp, VTONT(vp),
					NTFS_A_DATA, NULL,
					i * sizeof(ad), sizeof(ad),
					&ad, NULL);
			if (error)
				goto out1;
			j = 0;
			do {
				ntmp->ntm_ad[i].ad_name[j] = ad.ad_name[j];
			} while(ad.ad_name[j++]);
			ntmp->ntm_ad[i].ad_namelen = j - 1;
			ntmp->ntm_ad[i].ad_type = ad.ad_type;
		}

		vput(vp);
	}

	mp->mnt_stat.f_fsid.val[0] = dev2udev(dev);
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_maxsymlinklen = 0;
	mp->mnt_flag |= MNT_LOCAL;
	devvp->v_rdev->si_mountpoint = mp;
	return (0);

out1:
	for(i=0;i<NTFS_SYSNODESNUM;i++)
		if(ntmp->ntm_sysvn[i]) vrele(ntmp->ntm_sysvn[i]);

	if (vflush(mp, 0, 0, td))
		dprintf(("ntfs_mountfs: vflush failed\n"));

out:
	devvp->v_rdev->si_mountpoint = NULL;
	if (bp)
		brelse(bp);

	(void)VOP_CLOSE(devvp, ronly ? FREAD : FREAD|FWRITE, NOCRED, td);
	
	return (error);
}

static int
ntfs_unmount( 
	struct mount *mp,
	int mntflags,
	struct thread *td)
{
	struct ntfsmount *ntmp;
	int error, ronly, flags, i;

	dprintf(("ntfs_unmount: unmounting...\n"));
	ntmp = VFSTONTFS(mp);

	flags = 0;
	if(mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	dprintf(("ntfs_unmount: vflushing...\n"));
	error = vflush(mp, 0, flags | SKIPSYSTEM, td);
	if (error) {
		printf("ntfs_unmount: vflush failed: %d\n",error);
		return (error);
	}

	/* Check if only system vnodes are rest */
	for(i=0;i<NTFS_SYSNODESNUM;i++)
		 if((ntmp->ntm_sysvn[i]) && 
		    (vrefcnt(ntmp->ntm_sysvn[i]) > 1)) return (EBUSY);

	/* Dereference all system vnodes */
	for(i=0;i<NTFS_SYSNODESNUM;i++)
		 if(ntmp->ntm_sysvn[i]) vrele(ntmp->ntm_sysvn[i]);

	/* vflush system vnodes */
	error = vflush(mp, 0, flags, td);
	if (error)
		printf("ntfs_unmount: vflush failed(sysnodes): %d\n",error);

	/* Check if the type of device node isn't VBAD before
	 * touching v_cdev.  If the device vnode is revoked, the
	 * field is NULL and touching it causes null pointer derefercence.
	 */
	if (ntmp->ntm_devvp->v_type != VBAD)
		ntmp->ntm_devvp->v_rdev->si_mountpoint = NULL;

	vinvalbuf(ntmp->ntm_devvp, V_SAVE, NOCRED, td, 0, 0);

	ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
	error = VOP_CLOSE(ntmp->ntm_devvp, ronly ? FREAD : FREAD|FWRITE,
		NOCRED, td);

	vrele(ntmp->ntm_devvp);

	/* free the toupper table, if this has been last mounted ntfs volume */
	ntfs_toupper_unuse();

	dprintf(("ntfs_umount: freeing memory...\n"));
	ntfs_u28_uninit(ntmp);
	ntfs_82u_uninit(ntmp);
	mp->mnt_data = (qaddr_t)0;
	mp->mnt_flag &= ~MNT_LOCAL;
	FREE(ntmp->ntm_ad, M_NTFSMNT);
	FREE(ntmp, M_NTFSMNT);
	return (error);
}

static int
ntfs_root(
	struct mount *mp,
	struct vnode **vpp,
	struct thread *td )
{
	struct vnode *nvp;
	int error = 0;

	dprintf(("ntfs_root(): sysvn: %p\n",
		VFSTONTFS(mp)->ntm_sysvn[NTFS_ROOTINO]));
	error = VFS_VGET(mp, (ino_t)NTFS_ROOTINO, LK_EXCLUSIVE, &nvp);
	if(error) {
		printf("ntfs_root: VFS_VGET failed: %d\n",error);
		return (error);
	}

	*vpp = nvp;
	return (0);
}

int
ntfs_calccfree(
	struct ntfsmount *ntmp,
	cn_t *cfreep)
{
	struct vnode *vp;
	u_int8_t *tmp;
	int j, error;
	long cfree = 0;
	size_t bmsize, i;

	vp = ntmp->ntm_sysvn[NTFS_BITMAPINO];

	bmsize = VTOF(vp)->f_size;

	MALLOC(tmp, u_int8_t *, bmsize, M_TEMP, M_WAITOK);

	error = ntfs_readattr(ntmp, VTONT(vp), NTFS_A_DATA, NULL,
			       0, bmsize, tmp, NULL);
	if (error)
		goto out;

	for(i=0;i<bmsize;i++)
		for(j=0;j<8;j++)
			if(~tmp[i] & (1 << j)) cfree++;
	*cfreep = cfree;

    out:
	FREE(tmp, M_TEMP);
	return(error);
}

static int
ntfs_statfs(
	struct mount *mp,
	struct statfs *sbp,
	struct thread *td)
{
	struct ntfsmount *ntmp = VFSTONTFS(mp);
	u_int64_t mftsize,mftallocated;

	dprintf(("ntfs_statfs():\n"));

	mftsize = VTOF(ntmp->ntm_sysvn[NTFS_MFTINO])->f_size;
	mftallocated = VTOF(ntmp->ntm_sysvn[NTFS_MFTINO])->f_allocated;

	sbp->f_type = mp->mnt_vfc->vfc_typenum;
	sbp->f_bsize = ntmp->ntm_bps;
	sbp->f_iosize = ntmp->ntm_bps * ntmp->ntm_spc;
	sbp->f_blocks = ntmp->ntm_bootfile.bf_spv;
	sbp->f_bfree = sbp->f_bavail = ntfs_cntobn(ntmp->ntm_cfree);
	sbp->f_ffree = sbp->f_bfree / ntmp->ntm_bpmftrec;
	sbp->f_files = mftallocated / ntfs_bntob(ntmp->ntm_bpmftrec) +
		       sbp->f_ffree;
	if (sbp != &mp->mnt_stat) {
		bcopy((caddr_t)mp->mnt_stat.f_mntonname,
			(caddr_t)&sbp->f_mntonname[0], MNAMELEN);
		bcopy((caddr_t)mp->mnt_stat.f_mntfromname,
			(caddr_t)&sbp->f_mntfromname[0], MNAMELEN);
	}
	sbp->f_flags = mp->mnt_flag;

	return (0);
}

/*ARGSUSED*/
static int
ntfs_fhtovp(
	struct mount *mp,
	struct fid *fhp,
	struct vnode **vpp)
{
	struct vnode *nvp;
	struct ntfid *ntfhp = (struct ntfid *)fhp;
	int error;

	ddprintf(("ntfs_fhtovp(): %d\n", ntfhp->ntfid_ino));

	if ((error = VFS_VGET(mp, ntfhp->ntfid_ino, LK_EXCLUSIVE, &nvp)) != 0) {
		*vpp = NULLVP;
		return (error);
	}
	/* XXX as unlink/rmdir/mkdir/creat are not currently possible
	 * with NTFS, we don't need to check anything else for now */
	*vpp = nvp;

	return (0);
}

static int
ntfs_vptofh(
	struct vnode *vp,
	struct fid *fhp)
{
	register struct ntnode *ntp;
	register struct ntfid *ntfhp;

	ddprintf(("ntfs_fhtovp(): %p\n", vp));

	ntp = VTONT(vp);
	ntfhp = (struct ntfid *)fhp;
	ntfhp->ntfid_len = sizeof(struct ntfid);
	ntfhp->ntfid_ino = ntp->i_number;
	/* ntfhp->ntfid_gen = ntp->i_gen; */
	return (0);
}

int
ntfs_vgetex(
	struct mount *mp,
	ino_t ino,
	u_int32_t attrtype,
	char *attrname,
	u_long lkflags,
	u_long flags,
	struct thread *td,
	struct vnode **vpp) 
{
	int error;
	register struct ntfsmount *ntmp;
	struct ntnode *ip;
	struct fnode *fp;
	struct vnode *vp;
	enum vtype f_type;

	dprintf(("ntfs_vgetex: ino: %d, attr: 0x%x:%s, lkf: 0x%lx, f: 0x%lx\n",
		ino, attrtype, attrname?attrname:"", (u_long)lkflags,
		(u_long)flags ));

	ntmp = VFSTONTFS(mp);
	*vpp = NULL;

	/* Get ntnode */
	error = ntfs_ntlookup(ntmp, ino, &ip);
	if (error) {
		printf("ntfs_vget: ntfs_ntget failed\n");
		return (error);
	}

	/* It may be not initialized fully, so force load it */
	if (!(flags & VG_DONTLOADIN) && !(ip->i_flag & IN_LOADED)) {
		error = ntfs_loadntnode(ntmp, ip);
		if(error) {
			printf("ntfs_vget: CAN'T LOAD ATTRIBUTES FOR INO: %d\n",
			       ip->i_number);
			ntfs_ntput(ip);
			return (error);
		}
	}

	error = ntfs_fget(ntmp, ip, attrtype, attrname, &fp);
	if (error) {
		printf("ntfs_vget: ntfs_fget failed\n");
		ntfs_ntput(ip);
		return (error);
	}

	f_type = VNON;
	if (!(flags & VG_DONTVALIDFN) && !(fp->f_flag & FN_VALID)) {
		if ((ip->i_frflag & NTFS_FRFLAG_DIR) &&
		    (fp->f_attrtype == NTFS_A_DATA && fp->f_attrname == NULL)) {
			f_type = VDIR;
		} else if (flags & VG_EXT) {
			f_type = VNON;
			fp->f_size = fp->f_allocated = 0;
		} else {
			f_type = VREG;	

			error = ntfs_filesize(ntmp, fp, 
					      &fp->f_size, &fp->f_allocated);
			if (error) {
				ntfs_ntput(ip);
				return (error);
			}
		}

		fp->f_flag |= FN_VALID;
	}

	if (FTOV(fp)) {
		vget(FTOV(fp), lkflags, td);
		*vpp = FTOV(fp);
		ntfs_ntput(ip);
		return (0);
	}

	error = getnewvnode("ntfs", ntmp->ntm_mountp, ntfs_vnodeop_p, &vp);
	if(error) {
		ntfs_frele(fp);
		ntfs_ntput(ip);
		return (error);
	}
	dprintf(("ntfs_vget: vnode: %p for ntnode: %d\n", vp,ino));

	fp->f_vp = vp;
	vp->v_data = fp;
	vp->v_type = f_type;

	if (ino == NTFS_ROOTINO)
		vp->v_vflag |= VV_ROOT;

	ntfs_ntput(ip);

	if (lkflags & LK_TYPE_MASK) {
		error = vn_lock(vp, lkflags, td);
		if (error) {
			vput(vp);
			return (error);
		}
	}

	*vpp = vp;
	return (0);
	
}

static int
ntfs_vget(
	struct mount *mp,
	ino_t ino,
	int lkflags,
	struct vnode **vpp) 
{
	return ntfs_vgetex(mp, ino, NTFS_A_DATA, NULL, lkflags, 0,
	    curthread, vpp);
}

static struct vfsops ntfs_vfsops = {
	.vfs_fhtovp =	ntfs_fhtovp,
	.vfs_init =	ntfs_init,
	.vfs_mount =	ntfs_mount,
	.vfs_root =	ntfs_root,
	.vfs_statfs =	ntfs_statfs,
	.vfs_uninit =	ntfs_uninit,
	.vfs_unmount =	ntfs_unmount,
	.vfs_vget =	ntfs_vget,
	.vfs_vptofh =	ntfs_vptofh,
};
VFS_SET(ntfs_vfsops, ntfs, 0);
MODULE_VERSION(ntfs, 1);
