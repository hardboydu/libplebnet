/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
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
 *	@(#)fdesc_vnops.c	8.9 (Berkeley) 1/21/94
 *
 * $FreeBSD$
 */

/*
 * /dev/fd Filesystem
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kernel.h>	/* boottime */
#include <sys/filedesc.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <sys/conf.h>
#include <sys/socketvar.h>
#include <miscfs/fdesc/fdesc.h>

#define FDL_WANT	0x01
#define FDL_LOCKED	0x02
static int fdcache_lock;

static vop_t **fdesc_vnodeop_p;

#define	NFDCACHE 4
#define FD_NHASH(ix) \
	(&fdhashtbl[(ix) & fdhash])
static LIST_HEAD(fdhashhead, fdescnode) *fdhashtbl;
static u_long fdhash;

static int	fdesc_badop __P((void));
static int	fdesc_getattr __P((struct vop_getattr_args *ap));
static int	fdesc_inactive __P((struct vop_inactive_args *ap));
static int	fdesc_lookup __P((struct vop_lookup_args *ap));
static int	fdesc_open __P((struct vop_open_args *ap));
static int	fdesc_print __P((struct vop_print_args *ap));
static int	fdesc_readdir __P((struct vop_readdir_args *ap));
static int	fdesc_reclaim __P((struct vop_reclaim_args *ap));
static int	fdesc_poll __P((struct vop_poll_args *ap));
static int	fdesc_setattr __P((struct vop_setattr_args *ap));

/*
 * Initialise cache headers
 */
int
fdesc_init(vfsp)
	struct vfsconf *vfsp;
{

	fdhashtbl = hashinit(NFDCACHE, M_CACHE, &fdhash);
	return (0);
}

int
fdesc_allocvp(ftype, ix, mp, vpp)
	fdntype ftype;
	int ix;
	struct mount *mp;
	struct vnode **vpp;
{
	struct proc *p = curproc;	/* XXX */
	struct fdhashhead *fc;
	struct fdescnode *fd;
	int error = 0;

	fc = FD_NHASH(ix);
loop:
	for (fd = fc->lh_first; fd != 0; fd = fd->fd_hash.le_next) {
		if (fd->fd_ix == ix && fd->fd_vnode->v_mount == mp) {
			if (vget(fd->fd_vnode, 0, p))
				goto loop;
			*vpp = fd->fd_vnode;
			return (error);
		}
	}

	/*
	 * otherwise lock the array while we call getnewvnode
	 * since that can block.
	 */
	if (fdcache_lock & FDL_LOCKED) {
		fdcache_lock |= FDL_WANT;
		(void) tsleep((caddr_t) &fdcache_lock, PINOD, "fdalvp", 0);
		goto loop;
	}
	fdcache_lock |= FDL_LOCKED;

	/*
	 * Do the MALLOC before the getnewvnode since doing so afterward
	 * might cause a bogus v_data pointer to get dereferenced
	 * elsewhere if MALLOC should block.
	 */
	MALLOC(fd, struct fdescnode *, sizeof(struct fdescnode), M_TEMP, M_WAITOK);

	error = getnewvnode(VT_FDESC, mp, fdesc_vnodeop_p, vpp);
	if (error) {
		FREE(fd, M_TEMP);
		goto out;
	}
	(*vpp)->v_data = fd;
	fd->fd_vnode = *vpp;
	fd->fd_type = ftype;
	fd->fd_fd = -1;
	fd->fd_link = 0;
	fd->fd_ix = ix;
	LIST_INSERT_HEAD(fc, fd, fd_hash);

out:
	fdcache_lock &= ~FDL_LOCKED;

	if (fdcache_lock & FDL_WANT) {
		fdcache_lock &= ~FDL_WANT;
		wakeup((caddr_t) &fdcache_lock);
	}

	return (error);
}

/*
 * vp is the current namei directory
 * ndp is the name to locate in that directory...
 */
static int
fdesc_lookup(ap)
	struct vop_lookup_args /* {
		struct vnode * a_dvp;
		struct vnode ** a_vpp;
		struct componentname * a_cnp;
	} */ *ap;
{
	struct vnode **vpp = ap->a_vpp;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	char *pname = cnp->cn_nameptr;
	struct proc *p = cnp->cn_proc;
	int nlen = cnp->cn_namelen;
	int nfiles = p->p_fd->fd_nfiles;
	u_int fd;
	int error;
	struct vnode *fvp;

	if (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME) {
		error = EROFS;
		goto bad;
	}

	VOP_UNLOCK(dvp, 0, p);
	if (cnp->cn_namelen == 1 && *pname == '.') {
		*vpp = dvp;
		VREF(dvp);	
		vn_lock(dvp, LK_SHARED | LK_RETRY, p);
		return (0);
	}

	if (VTOFDESC(dvp)->fd_type != Froot) {
		error = ENOTDIR;
		goto bad;
	}

	fd = 0;
	while (nlen--) {
		if (*pname < '0' || *pname > '9') {
			error = ENOENT;
			goto bad;
		}
		fd = 10 * fd + *pname++ - '0';
	}

	if (fd >= nfiles || p->p_fd->fd_ofiles[fd] == NULL) {
		error = EBADF;
		goto bad;
	}

	error = fdesc_allocvp(Fdesc, FD_DESC+fd, dvp->v_mount, &fvp);
	if (error)
		goto bad;
	VTOFDESC(fvp)->fd_fd = fd;
	vn_lock(fvp, LK_SHARED | LK_RETRY, p);
	*vpp = fvp;
	return (0);

bad:
	vn_lock(dvp, LK_SHARED | LK_RETRY, p);
	*vpp = NULL;
	return (error);
}

static int
fdesc_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	if (VTOFDESC(vp)->fd_type == Froot)
		return (0);

	/*
	 * XXX Kludge: set p->p_dupfd to contain the value of the the file
	 * descriptor being sought for duplication. The error return ensures
	 * that the vnode for this device will be released by vn_open. Open
	 * will detect this special error and take the actions in dupfdopen.
	 * Other callers of vn_open or VOP_OPEN will simply report the
	 * error.
	 */
	ap->a_p->p_dupfd = VTOFDESC(vp)->fd_fd;	/* XXX */
	return (ENODEV);
}

static int
fdesc_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct filedesc *fdp = ap->a_p->p_fd;
	struct file *fp;
	struct stat stb;
	u_int fd;
	int error = 0;

	switch (VTOFDESC(vp)->fd_type) {
	case Froot:
		bzero((caddr_t) vap, sizeof(*vap));
		vattr_null(vap);

		vap->va_mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
		vap->va_type = VDIR;
		vap->va_nlink = 2;
		vap->va_size = DEV_BSIZE;
		vap->va_fileid = VTOFDESC(vp)->fd_ix;
		vap->va_uid = 0;
		vap->va_gid = 0;
		vap->va_blocksize = DEV_BSIZE;
		vap->va_atime.tv_sec = boottime.tv_sec;
		vap->va_atime.tv_nsec = 0;
		vap->va_mtime = vap->va_atime;
		vap->va_ctime = vap->va_mtime;
		vap->va_gen = 0;
		vap->va_flags = 0;
		vap->va_rdev = 0;
		vap->va_bytes = 0;
		break;

	case Fdesc:
		fd = VTOFDESC(vp)->fd_fd;

		if (fd >= fdp->fd_nfiles || (fp = fdp->fd_ofiles[fd]) == NULL)
			return (EBADF);

		switch (fp->f_type) {
		case DTYPE_FIFO:
		case DTYPE_VNODE:
			error = VOP_GETATTR((struct vnode *) fp->f_data, vap,
			    ap->a_cred, ap->a_p);
			if (error == 0 && vap->va_type == VDIR) {
				/*
				 * directories can cause loops in the namespace,
				 * so turn off the 'r' and 'x' bits to avoid
				 * trouble.
				 */
#define VRXEC (VREAD|VEXEC)
				vap->va_mode &= ~((VRXEC)|(VRXEC>>3)|(VRXEC>>6));
#undef VRXEC
			}
			/*
			 * Make sure these nodes reflect data as it pertains
			 * to fdesc and not the original file system.
			 */
			vap->va_fileid = VTOFDESC(vp)->fd_ix;
			vap->va_fsid = VNOVAL;
			break;
	
		case DTYPE_PIPE:
		case DTYPE_SOCKET:
		case DTYPE_KQUEUE:
			error = fo_stat(fp, &stb, ap->a_p);
			if (error == 0) {
				vattr_null(vap);
				if (fp->f_type == DTYPE_KQUEUE)
					vap->va_type = VFIFO;
				else
					vap->va_type = IFTOVT(stb.st_mode);

				vap->va_mode = S_IRUSR | S_IWUSR | S_IRGRP |
				    S_IWGRP | S_IROTH | S_IWOTH;
				vap->va_nlink = 1;
				vap->va_flags = 0;
				vap->va_bytes = stb.st_blocks * stb.st_blksize;
				vap->va_fsid = VNOVAL;
				vap->va_fileid = VTOFDESC(vp)->fd_ix;
				vap->va_size = stb.st_size;
				vap->va_blocksize = stb.st_blksize;

				/*
				 * XXX Sockets and kqueues don't have any
				 * mtime/atime/ctime data.
				 */
				if (fp->f_type == DTYPE_SOCKET ||
				    fp->f_type == DTYPE_KQUEUE) {
					nanotime(&stb.st_atimespec);
					stb.st_mtimespec = stb.st_atimespec;
					stb.st_ctimespec = stb.st_mtimespec;
				}
				vap->va_atime = stb.st_atimespec;
				vap->va_mtime = stb.st_mtimespec;
				vap->va_ctime = stb.st_ctimespec;
				vap->va_uid = stb.st_uid;
				vap->va_gid = stb.st_gid;
			}
			break;
		default:
			panic("fdesc_getattr: Unknown fp->f_type encountered");
			break;
		}
		break;

	default:
		panic("fdesc_getattr");
		break;
	}

	if (error == 0)
		vp->v_type = vap->va_type;
	return (error);
}

static int
fdesc_setattr(ap)
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct filedesc *fdp = ap->a_p->p_fd;
	struct vattr *vap = ap->a_vap;
	struct file *fp;
	unsigned fd;
	int error;

	/*
	 * Can't mess with the root vnode
	 */
	if (VTOFDESC(ap->a_vp)->fd_type == Froot)
		return (EACCES);

	fd = VTOFDESC(ap->a_vp)->fd_fd;
	if (fd >= fdp->fd_nfiles || (fp = fdp->fd_ofiles[fd]) == NULL)
		return (EBADF);

	/*
	 * Can setattr the underlying vnode, but not sockets!
	 */
	switch (fp->f_type) {
	case DTYPE_FIFO:
	case DTYPE_PIPE:
	case DTYPE_VNODE:
		error = VOP_SETATTR((struct vnode *) fp->f_data, ap->a_vap,
		    ap->a_cred, ap->a_p);
		break;

	case DTYPE_SOCKET:
	case DTYPE_KQUEUE:
		if (vap->va_flags != VNOVAL)
			error = EOPNOTSUPP;
		else
			error = 0;
		break;

	default:
		error = EBADF;
		break;
	}

	return (error);
}

#define UIO_MX 16

static int
fdesc_readdir(ap)
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
		int *a_eofflag;
		u_long *a_cookies;
		int a_ncookies;
	} */ *ap;
{
	struct uio *uio = ap->a_uio;
	struct filedesc *fdp;
	struct dirent d;
	struct dirent *dp = &d;
	int error, i, off, fcnt;

	/*
	 * We don't allow exporting fdesc mounts, and currently local
	 * requests do not need cookies.
	 */
	if (ap->a_ncookies)
		panic("fdesc_readdir: not hungry");

	if (VTOFDESC(ap->a_vp)->fd_type != Froot)
		panic("fdesc_readdir: not dir");

	off = (int)uio->uio_offset;
	if (off != uio->uio_offset || off < 0 || (u_int)off % UIO_MX != 0 ||
	    uio->uio_resid < UIO_MX)
		return (EINVAL);
	i = (u_int)off / UIO_MX;
	fdp = uio->uio_procp->p_fd;
	error = 0;

	fcnt = i - 2;		/* The first two nodes are `.' and `..' */

	while (i < fdp->fd_nfiles + 2 && uio->uio_resid >= UIO_MX) {
		switch (i) {
		case 0:	/* `.' */
		case 1: /* `..' */
			bzero((caddr_t)dp, UIO_MX);

			dp->d_fileno = i + FD_ROOT;
			dp->d_namlen = i + 1;
			dp->d_reclen = UIO_MX;
			bcopy("..", dp->d_name, dp->d_namlen);
			dp->d_name[i + 1] = '\0';
			dp->d_type = DT_DIR;
			break;
		default:
			if (fdp->fd_ofiles[fcnt] == NULL)
				goto done;

			bzero((caddr_t) dp, UIO_MX);
			dp->d_namlen = sprintf(dp->d_name, "%d", fcnt);
			dp->d_reclen = UIO_MX;
			dp->d_type = DT_UNKNOWN;
			dp->d_fileno = i + FD_DESC;
			break;
		}
		/*
		 * And ship to userland
		 */
		error = uiomove((caddr_t) dp, UIO_MX, uio);
		if (error)
			break;
		i++;
		fcnt++;
	}

done:
	uio->uio_offset = i * UIO_MX;
	return (error);
}

static int
fdesc_poll(ap)
	struct vop_poll_args /* {
		struct vnode *a_vp;
		int  a_events;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	return seltrue(0, ap->a_events, ap->a_p);
}

static int
fdesc_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	/*
	 * Clear out the v_type field to avoid
	 * nasty things happening in vgone().
	 */
	VOP_UNLOCK(vp, 0, ap->a_p);
	vp->v_type = VNON;
	return (0);
}

static int
fdesc_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct fdescnode *fd = VTOFDESC(vp);

	LIST_REMOVE(fd, fd_hash);
	FREE(vp->v_data, M_TEMP);
	vp->v_data = 0;

	return (0);
}

/*
 * Print out the contents of a /dev/fd vnode.
 */
/* ARGSUSED */
static int
fdesc_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("tag VT_NON, fdesc vnode\n");
	return (0);
}

/*
 * /dev/fd "should never get here" operation
 */
static int
fdesc_badop()
{

	panic("fdesc: bad op");
	/* NOTREACHED */
}

static struct vnodeopv_entry_desc fdesc_vnodeop_entries[] = {
	{ &vop_default_desc,		(vop_t *) vop_defaultop },
	{ &vop_access_desc,		(vop_t *) vop_null },
	{ &vop_bmap_desc,		(vop_t *) fdesc_badop },
	{ &vop_getattr_desc,		(vop_t *) fdesc_getattr },
	{ &vop_inactive_desc,		(vop_t *) fdesc_inactive },
	{ &vop_lookup_desc,		(vop_t *) fdesc_lookup },
	{ &vop_open_desc,		(vop_t *) fdesc_open },
	{ &vop_pathconf_desc,		(vop_t *) vop_stdpathconf },
	{ &vop_poll_desc,		(vop_t *) fdesc_poll },
	{ &vop_print_desc,		(vop_t *) fdesc_print },
	{ &vop_readdir_desc,		(vop_t *) fdesc_readdir },
	{ &vop_reclaim_desc,		(vop_t *) fdesc_reclaim },
	{ &vop_setattr_desc,		(vop_t *) fdesc_setattr },
	{ NULL, NULL }
};
static struct vnodeopv_desc fdesc_vnodeop_opv_desc =
	{ &fdesc_vnodeop_p, fdesc_vnodeop_entries };

VNODEOP_SET(fdesc_vnodeop_opv_desc);
