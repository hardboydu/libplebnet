/*
 *  Written by Julian Elischer (julian@DIALix.oz.au)
 *
 *	$Header: /home/ncvs/src/sys/miscfs/devfs/devfs_vnops.c,v 1.4 1995/05/03 23:04:26 julian Exp $
 *
 * symlinks can wait 'til later.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>	/* defines plimit structure in proc struct */
#include <sys/kernel.h>
#include <sys/file.h>		/* define FWRITE ... */
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
/*#include <miscfs/specfs/specdev.h>*/ /* plimit structure in the proc struct */
#include <sys/malloc.h>
#include <sys/dir.h>		/* defines dirent structure		*/
/*#include "vnode_if.h"*/ /* must be included elsewhere (vnode.h?)*/
#include "devfsdefs.h"

/*extern struct timeval time,boottime;*/
/*
 * Insert description here
 */


/*
 * Convert a component of a pathname into a pointer to a locked devfs_front.
 * This is a very central and rather complicated routine.
 * If the file system is not maintained in a strict tree hierarchy,
 * this can result in a deadlock situation (see comments in code below).
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it and the target of the pathname
 * exists, lookup returns both the target and its parent directory locked.
 * When creating or renaming and LOCKPARENT is specified, the target may
 * not be ".".  When deleting and LOCKPARENT is specified, the target may
 * be "."., but the caller must check to ensure it does an vrele and DNUNLOCK
 * instead of two DNUNLOCKs.
 *
 * Overall outline of devfs_lookup:
 *
 *	check accessibility of directory
 *	null terminate the component (lookup leaves the whole string alone)
 *	look for name in cache, if found, then if at end of path
 *	  and deleting or creating, drop it, else return name
 *	search for name in directory, to found or notfound
 * notfound:
 *	if creating, return locked directory,
 *	else return error
 * found:
 *	if at end of path and deleting, return information to allow delete
 *	if at end of path and rewriting (RENAME and LOCKPARENT), lock target
 *	  devfs_front and return info to allow rewrite
 *	if not at end, add name to cache; if at end and neither creating
 *	  nor deleting, add name to cache
 * On return to lookup, remove the null termination we put in at the start.
 *
 * NOTE: (LOOKUP | LOCKPARENT) currently returns the parent devfs_front unlocked.
 */
int devfs_lookup(ap)
        struct vop_lookup_args /* {
                struct vnode * a_dvp; directory vnode ptr
                struct vnode ** a_vpp; where to put the result
                struct componentname * a_cnp; the name we want
        } */ *ap;
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dir_vnode = ap->a_dvp;
	struct vnode **result_vnode = ap->a_vpp;
        dn_p   dir_node;       /* the directory we are searching */
        dn_p   new_node;       /* the node we are searching for */
	int flags = cnp->cn_flags;
        int op = cnp->cn_nameiop;       /* LOOKUP, CREATE, RENAME, or DELETE */
        int lockparent = flags & LOCKPARENT;
        int wantparent = flags & (LOCKPARENT|WANTPARENT);
        int error = 0;
	struct proc *p = cnp->cn_proc;
	char	heldchar;	/* the char at the end of the name componet */

	*result_vnode = NULL; /* safe not sorry */ /*XXX*/

DBPRINT(("lookup\n"));

	if(devfs_vntodn(dir_vnode,&dir_node))
	{
		printf("vnode has changed?\n");
		vprint("=",dir_vnode);
		return(EINVAL);
	}

	/*
	 * Check accessiblity of directory.
	 */
	if (dir_node->type != DEV_DIR)
	{
		return (ENOTDIR);
	}
	if (error = VOP_ACCESS(dir_vnode, VEXEC, cnp->cn_cred, cnp->cn_proc))
	{
		return (error);
	}

	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 * Before tediously performing a linear scan of the directory,
	 * check the name cache to see if the directory/name pair
	 * we are looking for is known already.
	 */

#ifdef NOT_AT_THE_MOMENT
	if (error = cache_lookup(dir_vnode, result_vnode, cnp)) {
		int vpid;	/* capability number of vnode */

		if (error == ENOENT)
			return (error);
DBPRINT(("cached "));
		/*
		 * Claim the next vnode in the path.
		 * See comment below starting `Step through' for
		 * an explaination of the locking protocol.
		 */
		if(devfs_vntodn(*result_vnode,&new_node))
		{
			printf("vnode has changed!?\n");
			vprint("=",*result_vnode);
			return(EINVAL);
		}
		vpid = (*result_vnode)->v_id;
		if (dir_node == new_node) {	/* is "." */
			VREF(*result_vnode); /* not a full vget() */
			error = 0;
		} else if (flags & ISDOTDOT) {/* do a locking dance */
			VOP_UNLOCK(dir_vnode);
			error = vget(*result_vnode,1);
			if (!error && lockparent && (flags & ISLASTCN))
				VOP_LOCK(dir_vnode);
		} else {
			error = vget(*result_vnode,1);
			if (!lockparent || error || !(flags & ISLASTCN))
				VOP_UNLOCK(dir_vnode);
		}
		/*
		 * Check that the capability number did not change
		 * while we were waiting for the lock.
		 */
		if (!error) {
			if (vpid == (*result_vnode)->v_id)
				return (0);	/* SUCCCESS, return! */
			vput((*result_vnode));	/* pretend we failed */
			if (lockparent
			&& (dir_node != new_node)
			&& (flags & ISLASTCN))
				VOP_UNLOCK(dir_vnode);
		}
		if( error = VOP_LOCK(dir_vnode))
			return error;
		*result_vnode = NULL; /* safe not sorry */
DBPRINT(("errr, maybe not cached "));
	}
#endif
/***********************************************************************\
* SEARCH FOR NAME							*
* while making sure the component is null terminated for the strcmp 	*
\***********************************************************************/

	heldchar = cnp->cn_nameptr[cnp->cn_namelen];
	cnp->cn_nameptr[cnp->cn_namelen] = '\0';
	new_node = dev_findfront(dir_node,cnp->cn_nameptr);
	cnp->cn_nameptr[cnp->cn_namelen] = heldchar;
	if(new_node)
	{
		goto found;
	}
/***********************************************************************\
* Failed to find it.. (That may be good)				*
\***********************************************************************/
/* notfound: */
/*XXX*/ /* possibly release some resources here */
	/*
	 * If creating, and at end of pathname
	 * then can consider
	 * allowing file to be created.
	 * XXX original code (ufs_lookup) checked for . being deleted
	 */
        if ((op == CREATE || op == RENAME) && (flags & ISLASTCN)) {

		/*
		 * Access for write is interpreted as allowing
		 * creation of files in the directory.
		 */
		if (error = VOP_ACCESS(dir_vnode, VWRITE,
				cnp->cn_cred, cnp->cn_proc))
		{
DBPRINT(("MKACCESS "));
			return (error);
		}
		dir_node->flags |= IUPD|ICHG;/*XXX*/
		/*
		 * We return with the directory locked, so that
		 * the parameters we set up above will still be
		 * valid if we actually decide to do a direnter().
		 * We return ni_vp == NULL to indicate that the entry
		 * does not currently exist; we leave a pointer to
		 * the (locked) directory devfs_front in namei_data->ni_dvp.
		 * The pathname buffer is saved so that the name
		 * can be obtained later.
		 *
		 * NB - if the directory is unlocked, then this
		 * information cannot be used.
		 */
		cnp->cn_flags |= SAVENAME;
		if (!lockparent)
			VOP_UNLOCK(dir_vnode);
		/* DON't make a cache entry... status changing */
		return (EJUSTRETURN);
	}
	/*
	 * Insert name into cache (as non-existent) if appropriate.
	 */
	if ((cnp->cn_flags & MAKEENTRY) && op != CREATE)
		cache_enter(dir_vnode, *result_vnode, cnp);
DBPRINT(("NOT\n"));
	return (ENOENT);

/***********************************************************************\
* Found it.. this is not always a good thing..				*
\***********************************************************************/
found:
/*XXX*/ /* possibly release some resources here */


	/*
	 * If deleting, and at end of pathname, return
	 * parameters which can be used to remove file.
	 * If the wantparent flag isn't set, we return only
	 * the directory (in namei_data->ni_dvp), otherwise we go
	 * on and lock the devfs_front, being careful with ".".
	 */
	if (op == DELETE && (flags & ISLASTCN)) {
		/*
		 * Write access to directory required to delete files.
		 */
		if (error = VOP_ACCESS(dir_vnode, VWRITE,
				cnp->cn_cred, cnp->cn_proc))
			return (error);
		/*
		 */
		if (dir_node == new_node) {
			VREF(dir_vnode);
			*result_vnode = dir_vnode;
			return (0);
		}
		/*
		 * If directory is "sticky", then user must own
		 * the directory, or the file in it, else she
		 * may not delete it (unless she's root). This
		 * implements append-only directories.
		 */
		devfs_dntovn(new_node,result_vnode);
		VOP_LOCK((*result_vnode));
#ifdef NOTYET
		if ((dir_node->mode & ISVTX) &&
		    cnp->cn_cred->cr_uid != 0 &&
		    cnp->cn_cred->cr_uid != dir_node->uid &&
		    new_node->uid != cnp->cn_cred->cr_uid) {
			VOP_UNLOCK((*result_vnode));
			return (EPERM);
		}
#endif
		if (!lockparent)
			VOP_UNLOCK(dir_vnode);
		return (0);
	}

	/*
	 * If rewriting (RENAME), return the devfs_front and the
	 * information required to rewrite the present directory
	 * Must get devfs_front of directory entry to verify it's a
	 * regular file, or empty directory.
	 */
	if (op == RENAME && wantparent && (flags & ISLASTCN)) {
		if (error = VOP_ACCESS(dir_vnode, VWRITE,
				cnp->cn_cred, cnp->cn_proc))
			return (error);
		/*
		 * Careful about locking second devfs_front.
		 * This can only occur if the target is ".".
		 */
		if (dir_node == new_node)
			return (EISDIR);
		devfs_dntovn(new_node,result_vnode);
		VOP_LOCK(*result_vnode);
		cnp->cn_flags |= SAVENAME;
		if (!lockparent)
			VOP_UNLOCK(dir_vnode);
		return (0);
	}

	/*
	 * Step through the translation in the name.  We do not `DNUNLOCK' the
	 * directory because we may need it again if a symbolic link
	 * is relative to the current directory.  Instead we save it
	 * unlocked as "saved_dir_node" XXX.  We must get the target
	 * devfs_front before unlocking
	 * the directory to insure that the devfs_front will not be removed
	 * before we get it.  We prevent deadlock by always fetching
	 * devfs_fronts from the root, moving down the directory tree. Thus
	 * when following backward pointers ".." we must unlock the
	 * parent directory before getting the requested directory.
	 * There is a potential race condition here if both the current
	 * and parent directories are removed before the `DNLOCK' for the
	 * devfs_front associated with ".." returns.  We hope that this occurs
	 * infrequently since we cannot avoid this race condition without
	 * implementing a sophisticated deadlock detection algorithm.
	 * Note also that this simple deadlock detection scheme will not
	 * work if the file system has any hard links other than ".."
	 * that point backwards in the directory structure.
	 */
	if (flags & ISDOTDOT) {
		VOP_UNLOCK(dir_vnode);	/* race to get the devfs_front */
		devfs_dntovn(new_node,result_vnode);
		VOP_LOCK(*result_vnode);
		if (lockparent && (flags & ISLASTCN))
			VOP_LOCK(dir_vnode);
	} else if (dir_node == new_node) {
		VREF(dir_vnode);	/* we want ourself, ie "." */
		*result_vnode = dir_vnode;
	} else {
		devfs_dntovn(new_node,result_vnode);
		VOP_LOCK(*result_vnode);
		if (!lockparent || (flags & ISLASTCN))
			VOP_UNLOCK(dir_vnode);
	}

	/*
	 * Insert name into cache if appropriate.
	 */
	if (cnp->cn_flags & MAKEENTRY)
		cache_enter(dir_vnode, *result_vnode, cnp);
DBPRINT(("GOT\n"));
	return (0);
}




/*
 *  Create a regular file.
 *  We must also free the pathname buffer pointed at
 *  by ndp->ni_pnbuf, always on error, or only if the
 *  SAVESTART bit in ni_nameiop is clear on success.
 * <still true in 4.4?>
 *
 *  Always  error... no such thing in this FS
 */
int devfs_create(ap)
        struct vop_mknod_args /* {
                struct vnode *a_dvp;
                struct vnode **a_vpp;
                struct componentname *a_cnp;
                struct vattr *a_vap;
        } */ *ap;
{
DBPRINT(("create\n"));
        return EINVAL;
}

int devfs_mknod(ap)
        struct vop_mknod_args /* {
                struct vnode *a_dvp;
                struct vnode **a_vpp;
                struct componentname *a_cnp;
                struct vattr *a_vap;
        } */ *ap;
{
        int error;


DBPRINT(("mknod\n"));
	switch (ap->a_vap->va_type) {
	case VDIR:
#ifdef VNSLEAZE
		return devfs_mkdir(ap);
		/*XXX check for WILLRELE settings (different)*/
#else
		error = VOP_MKDIR(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap);
#endif
		break;

/*
 *  devfs_create() sets ndp->ni_vp.
 */
	case VREG:
#ifdef VNSLEAZE
		return devfs_create(ap);
		/*XXX check for WILLRELE settings (different)*/
#else
		error = VOP_CREATE(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap);
#endif
		break;

	default:
		return EINVAL;
		break;
	}
	return error;
}

int devfs_open(ap)
        struct vop_open_args /* {
                struct vnode *a_vp;
                int  a_mode;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
DBPRINT(("open\n"));
	return 0;
}

int devfs_close(ap)
        struct vop_close_args /* {
                struct vnode *a_vp;
                int  a_fflag;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
DBPRINT(("close\n"));
	return 0;
}

int devfs_access(ap)
        struct vop_access_args /* {
                struct vnode *a_vp;
                int  a_mode;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
	/*
 	 *  mode is filled with a combination of VREAD, VWRITE,
 	 *  and/or VEXEC bits turned on.  In an octal number these
 	 *  are the Y in 0Y00.
 	 */
	struct vnode *vp = ap->a_vp;
	int mode = ap->a_mode;
	struct ucred *cred = ap->a_cred;
	struct proc *p = ap->a_p;
	dn_p	file_node;
	int	error;
	gid_t	*gp;
	int 	i;

DBPRINT(("access\n"));
	if (error = devfs_vntodn(vp,&file_node))
	{
		printf("devfs_vntodn returned %d ",error);
		return error;
	}
	/*
	 *  Root gets to do anything.
	 */
	if (cred->cr_uid == 0)
		return 0;

	/*
	 * Access check is based on only one of owner, group, public.
	 * If not owner, then check group. If not a member of the
	 * group, then check public access.
	 */
	if (cred->cr_uid != file_node->uid)
	{
		/* failing that.. try groups */
		mode >>= 3;
		gp = cred->cr_groups;
		for (i = 0; i < cred->cr_ngroups; i++, gp++)
		{
			if (file_node->gid == *gp)
			{
				goto found;
			}
		}
		/* failing that.. try general access */
		mode >>= 3;
found:
		;
	}
	if ((file_node->mode & mode) == mode)
		return (0);
	return (EACCES);
}

int devfs_getattr(ap)
        struct vop_getattr_args /* {
                struct vnode *a_vp;
                struct vattr *a_vap;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct proc *p = ap->a_p;
	dn_p	file_node;
	int	error;

DBPRINT(("getattr\n"));
	if (error = devfs_vntodn(vp,&file_node))
	{
		printf("devfs_vntodn returned %d ",error);
		return error;
	}
	vap->va_rdev = 0;/* default value only */
	vap->va_mode = file_node->mode;
	switch (file_node->type)
	{
	case 	DEV_DIR:
		vap->va_rdev = (dev_t)file_node->dvm;
		vap->va_mode |= (S_IFDIR);
		break;
	case	DEV_CDEV:
		vap->va_rdev = file_node->by.Cdev.dev;
		vap->va_mode |= (S_IFCHR);
		break;
	case	DEV_BDEV:
		vap->va_rdev = file_node->by.Bdev.dev;
		vap->va_mode |= (S_IFBLK);
		break;
	case	DEV_SLNK:
		break;
	}
	vap->va_type = vp->v_type;
	vap->va_nlink = file_node->links;
	vap->va_uid = file_node->uid;
	vap->va_gid = file_node->gid;
	vap->va_fsid = (long)file_node->dvm;
	vap->va_fileid = (long)file_node;
	vap->va_size = file_node->len; /* now a u_quad_t */
	vap->va_blocksize = 512;
	if(file_node->ctime.tv_sec)
	{
		vap->va_ctime = file_node->ctime;
	}
	else
	{
		TIMEVAL_TO_TIMESPEC(&boottime,&(vap->va_ctime));
	}
	if(file_node->mtime.tv_sec)
	{
		vap->va_mtime = file_node->mtime;
	}
	else
	{
		TIMEVAL_TO_TIMESPEC(&boottime,&(vap->va_mtime));
	}
	if(file_node->atime.tv_sec)
	{
		vap->va_atime = file_node->atime;
	}
	else
	{
		TIMEVAL_TO_TIMESPEC(&boottime,&(vap->va_atime));
	}
	vap->va_gen = 0;
	vap->va_flags = 0;
	vap->va_bytes = file_node->len;	/* u_quad_t */
	vap->va_filerev = 0; /* XXX */		/* u_quad_t */
	vap->va_vaflags = 0; /* XXX */
	return 0;
}

int devfs_setattr(ap)
        struct vop_setattr_args /* {
                struct vnode *a_vp;
                struct vattr *a_vap;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct proc *p = ap->a_p;
	int error = 0;
	dn_p	file_node;

	if (error = devfs_vntodn(vp,&file_node))
	{
		printf("devfs_vntodn returned %d ",error);
		return error;
	}
DBPRINT(("setattr\n"));
	if ((vap->va_type != VNON)  ||
	    (vap->va_nlink != VNOVAL)  ||
	    (vap->va_fsid != VNOVAL)  ||
	    (vap->va_fileid != VNOVAL)  ||
	    (vap->va_blocksize != VNOVAL)  ||
	    (vap->va_rdev != VNOVAL)  ||
	    (vap->va_bytes != VNOVAL)  ||
	    (vap->va_gen != VNOVAL)  ||
	    (vap->va_atime.ts_sec != VNOVAL))
	{
		return EINVAL;
	}

	if (vap->va_size != VNOVAL) {
			return error;	/*XXX (?) */
	}
	if (vap->va_atime.ts_sec != VNOVAL)
	{
		file_node->atime = vap->va_atime;
	}

	if (vap->va_mtime.ts_sec != VNOVAL)
	{
		file_node->mtime = vap->va_mtime;
	}

	if (vap->va_ctime.ts_sec != VNOVAL)
	{
		file_node->ctime = vap->va_ctime;
	}

	if (vap->va_mode != (u_short)VNOVAL)
	{
		/* set drwxwxrwx stuff */
		file_node->mode &= ~07777;
		file_node->mode |= vap->va_mode & 07777;
	}

	if (vap->va_uid != (uid_t)VNOVAL)
	{
		file_node->uid = vap->va_uid;
	}
	if (vap->va_gid != (gid_t)VNOVAL)
	{
		file_node->gid = vap->va_gid;
	}
	if (vap->va_flags != VNOVAL) {
		if (error = suser(cred, &p->p_acflag))
			return error;
		if (cred->cr_uid == 0)
		;
		else {
		}
	}
	return error;
}


int devfs_read(ap)
        struct vop_read_args /* {
                struct vnode *a_vp;
                struct uio *a_uio;
                int  a_ioflag;
                struct ucred *a_cred;
        } */ *ap;
{
	int	eof;
	int	error = 0;
	dn_p	file_node;

DBPRINT(("read\n"));
	if (error = devfs_vntodn(ap->a_vp,&file_node))
	{
		printf("devfs_vntodn returned %d ",error);
		return error;
	}


	switch (ap->a_vp->v_type) {
	case VREG:
		return(EINVAL);
	case VDIR:
		return VOP_READDIR(ap->a_vp,ap->a_uio,ap->a_cred);
	case VCHR:
	case VBLK:
		error = spec_read(ap);
		TIMEVAL_TO_TIMESPEC(&time,&(file_node->atime))
		return(error);

	default:
		panic("devfs_read(): bad file type");
		break;
	}
}

/*
 *  Write data to a file or directory.
 */
int devfs_write(ap)
        struct vop_write_args /* {
                struct vnode *a_vp;
                struct uio *a_uio;
                int  a_ioflag;
                struct ucred *a_cred;
        } */ *ap;
{
	dn_p	file_node;
	int	error;

	if (error = devfs_vntodn(ap->a_vp,&file_node))
	{
		printf("devfs_vntodn returned %d ",error);
		return error;
	}


DBPRINT(("write\n"));
	switch (ap->a_vp->v_type) {
	case VREG:
		return(EINVAL);
	case VDIR:
		return(EISDIR);
	case VCHR:
	case VBLK:
		error = spec_write(ap);
		TIMEVAL_TO_TIMESPEC(&time,&(file_node->mtime))
		return(error);

	default:
		panic("devfs_write(): bad file type");
		break;
	}
}

int devfs_ioctl(ap)
        struct vop_ioctl_args /* {
                struct vnode *a_vp;
                int  a_command;
                caddr_t  a_data;
                int  a_fflag;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
DBPRINT(("ioctl\n"));
	return ENOTTY;
}

int devfs_select(ap)
        struct vop_select_args /* {
                struct vnode *a_vp;
                int  a_which;
                int  a_fflags;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
DBPRINT(("select\n"));
	return 1;		/* DOS filesystems never block? */
}

int devfs_mmap(ap)
        struct vop_mmap_args /* {
                struct vnode *a_vp;
                int  a_fflags;
                struct ucred *a_cred;
                struct proc *a_p;
        } */ *ap;
{
DBPRINT(("mmap\n"));
	return EINVAL;
}

/*
 *  Flush the blocks of a file to disk.
 */
int devfs_fsync(ap)
        struct vop_fsync_args /* {
                struct vnode *a_vp;
                struct ucred *a_cred;
                int  a_waitfor;
                struct proc *a_p;
        } */ *ap;
{
DBPRINT(("fsync\n"));
	return(0);
}

int devfs_seek(ap)
        struct vop_seek_args /* {
                struct vnode *a_vp;
                off_t  a_oldoff;
                off_t  a_newoff;
                struct ucred *a_cred;
        } */ *ap;
{
	int error = 0;
DBPRINT(("seek\n"));
	return 0;
}

int devfs_remove(ap)
        struct vop_remove_args /* {
                struct vnode *a_dvp;
                struct vnode *a_vp;
                struct componentname *a_cnp;
        } */ *ap;
{
	int error = 0;
	/*vrele(DETOV(dep));*/
DBPRINT(("remove\n"));
	return error;
}

/*
 */
int devfs_link(ap)
        struct vop_link_args /* {
                struct vnode *a_vp;
                struct vnode *a_tdvp;
                struct componentname *a_cnp;
        } */ *ap;
{
DBPRINT(("link\n"));
	return 0;
}

int devfs_rename(ap)
        struct vop_rename_args  /* {
                struct vnode *a_fdvp;
                struct vnode *a_fvp;
                struct componentname *a_fcnp;
                struct vnode *a_tdvp;
                struct vnode *a_tvp;
                struct componentname *a_tcnp;
        } */ *ap;
{
DBPRINT(("rename\n"));
	return 0;
}


int devfs_mkdir(ap)
        struct vop_mkdir_args /* {
                struct vnode *a_dvp;
                struct vnode **a_vpp;
                struct componentname *a_cnp;
                struct vattr *a_vap;
        } */ *ap;
{
DBPRINT(("mkdir\n"));
	return EINVAL;
}

int devfs_rmdir(ap)
        struct vop_rmdir_args /* {
                struct vnode *a_dvp;
                struct vnode *a_vp;
                struct componentname *a_cnp;
        } */ *ap;
{
DBPRINT(("rmdir\n"));
	return 0;
}

int devfs_symlink(ap)
        struct vop_symlink_args /* {
                struct vnode *a_dvp;
                struct vnode **a_vpp;
                struct componentname *a_cnp;
                struct vattr *a_vap;
                char *a_target;
        } */ *ap;
{
	return EINVAL;
DBPRINT(("symlink\n"));
}

/*
 * Vnode op for readdir
 */
int devfs_readdir(ap)
        struct vop_readdir_args /* {
                struct vnode *a_vp;
                struct uio *a_uio;
                struct ucred *a_cred;
        } */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct ucred *cred = ap->a_cred;
	struct dirent dirent;
	dn_p dir_node;
	devnm_p	name_node;
	char	*name;
	int error = 0;
	int reclen;
	int nodenumber;
	int	startpos,pos;

DBPRINT(("readdir\n"));

/*  set up refs to dir */
	if (error = devfs_vntodn(vp,&dir_node))
		return error;
	if(dir_node->type != DEV_DIR)
		return(ENOTDIR);

	pos = 0;
	startpos = uio->uio_offset;
	name_node = dir_node->by.Dir.dirlist;
	nodenumber = 0;
	TIMEVAL_TO_TIMESPEC(&time,&(dir_node->atime))

	while ((name_node || (nodenumber < 2)) && (uio->uio_resid > 0))
	{
		switch(nodenumber)
		{
		case	0:
			dirent.d_fileno = (unsigned long int)dir_node;
			name = ".";
			dirent.d_namlen = 1;
			dirent.d_type = DT_DIR;
			break;
		case	1:
			if(dir_node->by.Dir.parent)
				dirent.d_fileno
				 = (unsigned long int)dir_node->by.Dir.parent;
			else
				dirent.d_fileno = (unsigned long int)dir_node;
			name = "..";
			dirent.d_namlen = 2;
			dirent.d_type = DT_DIR;
			break;
		default:
			dirent.d_fileno =
				(unsigned long int)name_node->dnp;
			dirent.d_namlen = strlen(name_node->name);
			name = name_node->name;
			switch(name_node->dnp->type) {
			case DEV_BDEV:
				dirent.d_type = DT_BLK;
				break;
			case DEV_CDEV:
				dirent.d_type = DT_CHR;
				break;
			case DEV_DDEV:
				dirent.d_type = DT_SOCK; /*XXX*/
				break;
			case DEV_DIR:
				dirent.d_type = DT_DIR;
				break;
			case DEV_SLNK:
				dirent.d_type = DT_LNK;
				break;
			default:
				dirent.d_type = DT_UNKNOWN;
			}
		}

		reclen = dirent.d_reclen = DIRSIZ (&dirent);

		if(pos >= startpos)	/* made it to the offset yet? */
		{
			if (uio->uio_resid < reclen) /* will it fit? */
				break;
			strcpy( dirent.d_name,name);
			if (error = uiomove ((caddr_t)&dirent,
					dirent.d_reclen, uio))
				break;
		}
		pos += reclen;
		if((nodenumber >1) && name_node)
			name_node = name_node->next;
		nodenumber++;
	}
	uio->uio_offset = pos;

	return (error);
}


/*
 */
int devfs_readlink(ap)
        struct vop_readlink_args /* {
                struct vnode *a_vp;
                struct uio *a_uio;
                struct ucred *a_cred;
        } */ *ap;
{
DBPRINT(("readlink\n"));
	return 0;
}

int devfs_abortop(ap)
        struct vop_abortop_args /* {
                struct vnode *a_dvp;
                struct componentname *a_cnp;
        } */ *ap;
{
DBPRINT(("abortop\n"));
	return 0;
}

int devfs_inactive(ap)
        struct vop_inactive_args /* {
                struct vnode *a_vp;
        } */ *ap;
{
DBPRINT(("inactive\n"));
	return 0;
}
int devfs_lock(ap)
        struct vop_lock_args *ap;
{
DBPRINT(("lock\n"));
	return 0;
}

int devfs_unlock(ap)
        struct vop_unlock_args *ap;
{
DBPRINT(("unlock\n"));
	return 0;
}

int devfs_islocked(ap)
        struct vop_islocked_args /* {
                struct vnode *a_vp;
        } */ *ap;
{
DBPRINT(("islocked\n"));
	return 0;
}

int devfs_bmap(ap)
        struct vop_bmap_args /* {
                struct vnode *a_vp;
                daddr_t  a_bn;
                struct vnode **a_vpp;
                daddr_t *a_bnp;
                int *a_runp;
        } */ *ap;
{
DBPRINT(("bmap\n"));
		return 0;
}

int devfs_strategy(ap)
        struct vop_strategy_args /* {
                struct buf *a_bp;
        } */ *ap;
{
	struct vnode *vp;
	int error;
DBPRINT(("strategy\n"));

	if (ap->a_bp->b_vp->v_type == VBLK  ||  ap->a_bp->b_vp->v_type == VCHR)
		printf("devfs_strategy: spec");
	return 0;
}


int devfs_advlock(ap)
        struct vop_advlock_args /* {
                struct vnode *a_vp;
                caddr_t  a_id;
                int  a_op;
                struct flock *a_fl;
                int  a_flags;
        } */ *ap;
{
DBPRINT(("advlock\n"));
	return EINVAL;		/* we don't do locking yet		*/
}

int	devfs_reclaim(ap)
        struct vop_reclaim_args /* {
		struct vnode *a_vp;
        } */ *ap;
{
	dn_p	file_node;
	int	error;

DBPRINT(("reclaim\n"));
	if (error = devfs_vntodn(ap->a_vp,&file_node))
	{
		printf("devfs_vntodn returned %d ",error);
		return error;
	}

	file_node->vn = 0;
	file_node->vn_id = 0;
	return(0);
}

/*
 * Return POSIX pathconf information applicable to special devices.
 */
int
devfs_pathconf(ap)
        struct vop_pathconf_args /* {
                struct vnode *a_vp;
                int a_name;
                int *a_retval;
        } */ *ap;
{

        switch (ap->a_name) {
        case _PC_LINK_MAX:
                *ap->a_retval = LINK_MAX;
                return (0);
        case _PC_MAX_CANON:
                *ap->a_retval = MAX_CANON;
                return (0);
        case _PC_MAX_INPUT:
                *ap->a_retval = MAX_INPUT;
                return (0);
        case _PC_PIPE_BUF:
                *ap->a_retval = PIPE_BUF;
                return (0);
        case _PC_CHOWN_RESTRICTED:
                *ap->a_retval = 1;
                return (0);
        case _PC_VDISABLE:
                *ap->a_retval = _POSIX_VDISABLE;
                return (0);
        default:
                return (EINVAL);
        }
        /* NOTREACHED */
}


/*
 * Print out the contents of a /devfs vnode.
 */
/* ARGSUSED */
int
devfs_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("tag VT_DEVFS, devfs vnode\n");
	return (0);
}

/*void*/
int
devfs_vfree(ap)
	struct vop_vfree_args /* {
		struct vnode *a_pvp;
		ino_t a_ino;
		int a_mode;
	} */ *ap;
{

	return (0);
}

/**************************************************************************\
* pseudo ops *
\**************************************************************************/

/*
 * /devfs vnode unsupported operation
 */
int
devfs_enotsupp()
{

	return (EOPNOTSUPP);
}

/*
 * /devfs "should never get here" operation
 */
int
devfs_badop()
{

	panic("devfs: bad op");
	/* NOTREACHED */
}

/*
 * devfs vnode null operation
 */
int
devfs_nullop()
{

	return (0);
}


void	devfs_dropvnode(dn_p dnp) /*proto*/
{
	struct vnode *vn_p;

	if(!dnp)
	{
		printf("devfs: dn count dropped too early\n");
	}
	vn_p = dnp->vn;
	if(!vn_p)
	{
		printf("devfs: vn count dropped too early\n");
	}
	/*
	 * check if we have a vnode.......
	 */
	if((vn_p) && ( dnp->vn_id == vn_p->v_id) && (dnp == (dn_p)vn_p->v_data))
	{
		vgoneall(vn_p);
	}
	dnp->vn = NULL; /* be pedantic about this */
}

#define devfs_create ((int (*) __P((struct  vop_create_args *)))devfs_enotsupp)
#define devfs_mknod ((int (*) __P((struct  vop_mknod_args *)))devfs_enotsupp)
#define devfs_close ((int (*) __P((struct  vop_close_args *)))nullop)
#define devfs_ioctl ((int (*) __P((struct  vop_ioctl_args *)))devfs_enotsupp)
#define devfs_select ((int (*) __P((struct  vop_select_args *)))devfs_enotsupp)
#define devfs_mmap ((int (*) __P((struct  vop_mmap_args *)))devfs_enotsupp)
#define devfs_fsync ((int (*) __P((struct  vop_fsync_args *)))nullop)
#define devfs_seek ((int (*) __P((struct  vop_seek_args *)))nullop)
#define devfs_remove ((int (*) __P((struct  vop_remove_args *)))devfs_enotsupp)
#define devfs_link ((int (*) __P((struct  vop_link_args *)))devfs_enotsupp)
#define devfs_rename ((int (*) __P((struct  vop_rename_args *)))devfs_enotsupp)
#define devfs_mkdir ((int (*) __P((struct  vop_mkdir_args *)))devfs_enotsupp)
#define devfs_rmdir ((int (*) __P((struct  vop_rmdir_args *)))devfs_enotsupp)
#define devfs_symlink ((int (*) __P((struct vop_symlink_args *)))devfs_enotsupp)
#define devfs_readlink \
	((int (*) __P((struct  vop_readlink_args *)))devfs_enotsupp)
#define devfs_abortop ((int (*) __P((struct  vop_abortop_args *)))nullop)
#define devfs_lock ((int (*) __P((struct  vop_lock_args *)))nullop)
#define devfs_unlock ((int (*) __P((struct  vop_unlock_args *)))nullop)
#define devfs_bmap ((int (*) __P((struct  vop_bmap_args *)))devfs_badop)
#define devfs_strategy ((int (*) __P((struct  vop_strategy_args *)))devfs_badop)
#define devfs_islocked ((int (*) __P((struct  vop_islocked_args *)))nullop)
#define devfs_advlock ((int (*) __P((struct vop_advlock_args *)))devfs_enotsupp)
#define devfs_blkatoff \
	((int (*) __P((struct  vop_blkatoff_args *)))devfs_enotsupp)
#define devfs_valloc ((int(*) __P(( \
		struct vnode *pvp, \
		int mode, \
		struct ucred *cred, \
		struct vnode **vpp))) devfs_enotsupp)
#define devfs_truncate \
	((int (*) __P((struct  vop_truncate_args *)))devfs_enotsupp)
#define devfs_update ((int (*) __P((struct  vop_update_args *)))devfs_enotsupp)
#define devfs_bwrite ((int (*) __P((struct  vop_bwrite_args *)))devfs_enotsupp)

/* These are the operations used by directories etc in a devfs */

int (**devfs_vnodeop_p)();
struct vnodeopv_entry_desc devfs_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_lookup_desc, devfs_lookup },	/* lookup */
	{ &vop_create_desc, devfs_create },	/* create */
	{ &vop_mknod_desc, devfs_mknod },	/* mknod */
	{ &vop_open_desc, devfs_open },		/* open */
	{ &vop_close_desc, devfs_close },	/* close */
	{ &vop_access_desc, devfs_access },	/* access */
	{ &vop_getattr_desc, devfs_getattr },	/* getattr */
	{ &vop_setattr_desc, devfs_setattr },	/* setattr */
	{ &vop_read_desc, devfs_read },		/* read */
	{ &vop_write_desc, devfs_write },	/* write */
	{ &vop_ioctl_desc, devfs_ioctl },	/* ioctl */
	{ &vop_select_desc, devfs_select },	/* select */
	{ &vop_mmap_desc, devfs_mmap },		/* mmap */
	{ &vop_fsync_desc, devfs_fsync },	/* fsync */
	{ &vop_seek_desc, devfs_seek },		/* seek */
	{ &vop_remove_desc, devfs_remove },	/* remove */
	{ &vop_link_desc, devfs_link },		/* link */
	{ &vop_rename_desc, devfs_rename },	/* rename */
	{ &vop_mkdir_desc, devfs_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, devfs_rmdir },	/* rmdir */
	{ &vop_symlink_desc, devfs_symlink },	/* symlink */
	{ &vop_readdir_desc, devfs_readdir },	/* readdir */
	{ &vop_readlink_desc, devfs_readlink },	/* readlink */
	{ &vop_abortop_desc, devfs_abortop },	/* abortop */
	{ &vop_inactive_desc, devfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, devfs_reclaim },	/* reclaim */
	{ &vop_lock_desc, devfs_lock },		/* lock */
	{ &vop_unlock_desc, devfs_unlock },	/* unlock */
	{ &vop_bmap_desc, devfs_bmap },		/* bmap */
	{ &vop_strategy_desc, devfs_strategy },	/* strategy */
	{ &vop_print_desc, devfs_print },	/* print */
	{ &vop_islocked_desc, devfs_islocked },	/* islocked */
	{ &vop_pathconf_desc, devfs_pathconf },	/* pathconf */
	{ &vop_advlock_desc, devfs_advlock },	/* advlock */
	{ &vop_blkatoff_desc, devfs_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, devfs_valloc },	/* valloc */
	{ &vop_vfree_desc, devfs_vfree },	/* vfree */
	{ &vop_truncate_desc, devfs_truncate },	/* truncate */
	{ &vop_update_desc, devfs_update },	/* update */
	{ &vop_bwrite_desc, devfs_bwrite },	/* bwrite */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc devfs_vnodeop_opv_desc =
	{ &devfs_vnodeop_p, devfs_vnodeop_entries };

VNODEOP_SET(devfs_vnodeop_opv_desc);


/*copied in from specfs/spec_vnops.c.. (spot the changes )*/
/* These are the operations used by special devices in a devfs */
/*
 * Copyright (c) 1989, 1993
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
 *	@(#)spec_vnops.c	8.6 (Berkeley) 4/9/94
 * spec_vnops.c,v 1.9 1994/11/14 13:22:52 bde Exp
 */

#include "../specfs/specdev.h"	/* for all the definitions and prototypes */

int (**dev_spec_vnodeop_p)();
struct vnodeopv_entry_desc dev_spec_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_lookup_desc, spec_lookup },		/* lookup */
	{ &vop_create_desc, spec_create },		/* create */
	{ &vop_mknod_desc, spec_mknod },		/* mknod */
	{ &vop_open_desc, spec_open },			/* open */
	{ &vop_close_desc, spec_close },		/* close */
	{ &vop_access_desc, devfs_access },		/* access */
	{ &vop_getattr_desc, devfs_getattr },		/* getattr */
	{ &vop_setattr_desc, devfs_setattr },		/* setattr */
	{ &vop_read_desc, spec_read },			/* read */
	{ &vop_write_desc, spec_write },		/* write */
	{ &vop_ioctl_desc, spec_ioctl },		/* ioctl */
	{ &vop_select_desc, spec_select },		/* select */
	{ &vop_mmap_desc, spec_mmap },			/* mmap */
	{ &vop_fsync_desc, spec_fsync },		/* fsync */
	{ &vop_seek_desc, spec_seek },			/* seek */
	{ &vop_remove_desc, spec_remove },		/* remove */
	{ &vop_link_desc, spec_link },			/* link */
	{ &vop_rename_desc, spec_rename },		/* rename */
	{ &vop_mkdir_desc, spec_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, spec_rmdir },		/* rmdir */
	{ &vop_symlink_desc, spec_symlink },		/* symlink */
	{ &vop_readdir_desc, spec_readdir },		/* readdir */
	{ &vop_readlink_desc, spec_readlink },		/* readlink */
	{ &vop_abortop_desc, spec_abortop },		/* abortop */
	{ &vop_inactive_desc, spec_inactive },		/* inactive */
	{ &vop_reclaim_desc, spec_reclaim },		/* reclaim */
	{ &vop_lock_desc, spec_lock },			/* lock */
	{ &vop_unlock_desc, spec_unlock },		/* unlock */
	{ &vop_bmap_desc, spec_bmap },			/* bmap */
	{ &vop_strategy_desc, spec_strategy },		/* strategy */
	{ &vop_print_desc, spec_print },		/* print */
	{ &vop_islocked_desc, spec_islocked },		/* islocked */
	{ &vop_pathconf_desc, spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, spec_advlock },		/* advlock */
	{ &vop_blkatoff_desc, spec_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, spec_valloc },		/* valloc */
	{ &vop_vfree_desc, spec_vfree },		/* vfree */
	{ &vop_truncate_desc, spec_truncate },		/* truncate */
	{ &vop_update_desc, spec_update },		/* update */
	{ &vop_bwrite_desc, spec_bwrite },		/* bwrite */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc dev_spec_vnodeop_opv_desc =
	{ &dev_spec_vnodeop_p, dev_spec_vnodeop_entries };

VNODEOP_SET(dev_spec_vnodeop_opv_desc);

