/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 * from: Utah Hdr: vn.c 1.13 94/04/02
 *
 *	from: @(#)vn.c	8.6 (Berkeley) 4/1/94
 *	$Id: vn.c,v 1.85 1999/08/23 09:35:12 phk Exp $
 */

/*
 * Vnode disk driver.
 *
 * Block/character interface to a vnode.  Allows one to treat a file
 * as a disk (e.g. build a filesystem in it, mount it, etc.).
 *
 * NOTE 1: This uses the VOP_BMAP/VOP_STRATEGY interface to the vnode
 * instead of a simple VOP_RDWR.  We do this to avoid distorting the
 * local buffer cache.
 *
 * NOTE 2: There is a security issue involved with this driver.
 * Once mounted all access to the contents of the "mapped" file via
 * the special file is controlled by the permissions on the special
 * file, the protection of the mapped file is ignored (effectively,
 * by using root credentials in all transactions).
 *
 * NOTE 3: Doesn't interact with leases, should it?
 */
#include "vn.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/vnioctl.h>

#include <vm/vm.h>
#include <vm/vm_prot.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/swap_pager.h>
#include <vm/vm_extern.h>
#include <vm/vm_zone.h>

static	d_ioctl_t	vnioctl;
static	d_open_t	vnopen;
static	d_close_t	vnclose;
static	d_psize_t	vnsize;
static	d_strategy_t	vnstrategy;

#define CDEV_MAJOR 43
#define BDEV_MAJOR 15

/*
 * cdevsw
 *	D_DISK		we want to look like a disk
 *	( D_NOCLUSTERRW	 removed - clustering should be ok )
 *	D_CANFREE	We support B_FREEBUF
 */

static struct cdevsw vn_cdevsw = {
	/* open */	vnopen,
	/* close */	vnclose,
	/* read */	physread,
	/* write */	physwrite,
	/* ioctl */	vnioctl,
	/* stop */	nostop,
	/* reset */	noreset,
	/* devtotty */	nodevtotty,
	/* poll */	nopoll,
	/* mmap */	nommap,
	/* strategy */	vnstrategy,
	/* name */	"vn",
	/* parms */	noparms,
	/* maj */	CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	vnsize,
	/* flags */	D_DISK|D_CANFREE,
	/* maxio */	0,
	/* bmaj */	BDEV_MAJOR
};

#define	getvnbuf()	\
	((struct buf *)malloc(sizeof(struct buf), M_DEVBUF, M_WAITOK))

#define putvnbuf(bp)	\
	free((caddr_t)(bp), M_DEVBUF)

struct vn_softc {
	int		sc_unit;
	int		sc_flags;	/* flags 			*/
	int		sc_size;	/* size of vn, sc_secsize scale	*/
	int		sc_secsize;	/* sector size			*/
	struct diskslices *sc_slices;
	struct vnode	*sc_vp;		/* vnode if not NULL		*/
	vm_object_t	sc_object;	/* backing object if not NULL	*/
	struct ucred	*sc_cred;	/* credentials 			*/
	int		 sc_maxactive;	/* max # of active requests 	*/
	struct buf	 sc_tab;	/* transfer queue 		*/
	u_long		 sc_options;	/* options 			*/
	SLIST_ENTRY(vn_softc) sc_list;
};

static SLIST_HEAD(, vn_softc) vn_list;

/* sc_flags */
#define VNF_INITED	0x01

static u_long	vn_options;

#define IFOPT(vn,opt) if (((vn)->sc_options|vn_options) & (opt))

static int	vnsetcred (struct vn_softc *vn, struct ucred *cred);
static void	vnclear (struct vn_softc *vn);
static int	vn_modevent (module_t, int, void *);
static int 	vniocattach_file (struct vn_softc *, struct vn_ioctl *, dev_t dev, int flag, struct proc *p);
static int 	vniocattach_swap (struct vn_softc *, struct vn_ioctl *, dev_t dev, int flag, struct proc *p);

static	int
vnclose(dev_t dev, int flags, int mode, struct proc *p)
{
	struct vn_softc *vn = dev->si_drv1;

	IFOPT(vn, VN_LABELS)
		if (vn->sc_slices != NULL)
			dsclose(dev, mode, vn->sc_slices);
	return (0);
}

static struct vn_softc *
vnfindvn(dev_t dev)
{
	int unit;
	struct vn_softc *vn;

	unit = dkunit(dev);
	vn = dev->si_drv1;
	if (!vn) {
		SLIST_FOREACH(vn, &vn_list, sc_list) {
			if (vn->sc_unit == unit) {
				dev->si_drv1 = vn;
				break;
			}
		}
	}
	if (!vn) {
		vn = malloc(sizeof *vn, M_DEVBUF, M_WAITOK);
		if (!vn)
			return (NULL);
		bzero(vn, sizeof *vn);
		vn->sc_unit = unit;
		dev->si_drv1 = vn;
		make_dev(&vn_cdevsw, 0, 
		    UID_ROOT, GID_OPERATOR, 0640, "vn%d", unit);
		SLIST_INSERT_HEAD(&vn_list, vn, sc_list);
	}
	return (vn);
}

static	int
vnopen(dev_t dev, int flags, int mode, struct proc *p)
{
	int unit;
	struct vn_softc *vn;

	unit = dkunit(dev);
	vn = dev->si_drv1;
	if (!vn)
		vn = vnfindvn(dev);

	IFOPT(vn, VN_FOLLOW)
		printf("vnopen(%s, 0x%x, 0x%x, %p)\n",
		    devtoname(dev), flags, mode, (void *)p);

	IFOPT(vn, VN_LABELS) {
		if (vn->sc_flags & VNF_INITED) {
			struct disklabel label;

			/* Build label for whole disk. */
			bzero(&label, sizeof label);
			label.d_secsize = vn->sc_secsize;
			label.d_nsectors = 32;
			label.d_ntracks = 64 / (vn->sc_secsize / DEV_BSIZE);
			label.d_secpercyl = label.d_nsectors * label.d_ntracks;
			label.d_ncylinders = vn->sc_size / label.d_secpercyl;
			label.d_secperunit = vn->sc_size;
			label.d_partitions[RAW_PART].p_size = vn->sc_size;

			return (dsopen("vn", dev, mode, 0, &vn->sc_slices,
			    &label));
		}
		if (dkslice(dev) != WHOLE_DISK_SLICE ||
		    dkpart(dev) != RAW_PART ||
		    mode != S_IFCHR)
			return (ENXIO);
	}
	return(0);
}

/*
 *	vnstrategy:
 *
 *	Run strategy routine for VN device.  We use VOP_READ/VOP_WRITE calls
 *	for vnode-backed vn's, and the new vm_pager_strategy() call for
 *	vm_object-backed vn's.
 *
 *	Currently B_ASYNC is only partially handled - for OBJT_SWAP I/O only.
 *
 *	NOTE: bp->b_blkno is DEV_BSIZE'd.  We must generate bp->b_pblkno for
 *	our uio or vn_pager_strategy() call that is vn->sc_secsize'd
 */

static	void
vnstrategy(struct buf *bp)
{
	int unit;
	struct vn_softc *vn;
	int error;
	int isvplocked = 0;
	long sz;
	struct uio auio;
	struct iovec aiov;

	unit = dkunit(bp->b_dev);
	vn = bp->b_dev->si_drv1;
	if (!vn)
		vn = vnfindvn(bp->b_dev);

	IFOPT(vn, VN_DEBUG)
		printf("vnstrategy(%p): unit %d\n", bp, unit);

	if ((vn->sc_flags & VNF_INITED) == 0) {
		bp->b_error = ENXIO;
		bp->b_flags |= B_ERROR;
		biodone(bp);
		return;
	}

	bp->b_resid = bp->b_bcount;

	IFOPT(vn, VN_LABELS) {
		if (vn->sc_slices != NULL && dscheck(bp, vn->sc_slices) <= 0) {
			bp->b_flags |= B_INVAL;
			biodone(bp);
			return;
		}
	} else {
		int pbn;

		pbn = bp->b_blkno * (vn->sc_secsize / DEV_BSIZE);
		sz = howmany(bp->b_bcount, vn->sc_secsize);

		if (pbn < 0 || pbn + sz > vn->sc_size) {
			if (pbn != vn->sc_size) {
				bp->b_error = EINVAL;
				bp->b_flags |= B_ERROR | B_INVAL;
			}
			biodone(bp);
			return;
		}
		bp->b_pblkno = pbn;
	}

	if (vn->sc_vp && (bp->b_flags & B_FREEBUF)) {
		/*
		 * Not handled for vnode-backed element yet.
		 */
		biodone(bp);
	} else if (vn->sc_vp) {
		/*
		 * VNODE I/O
		 */
		aiov.iov_base = bp->b_data;
		aiov.iov_len = bp->b_bcount;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = (vm_ooffset_t)bp->b_pblkno * vn->sc_secsize;
		auio.uio_segflg = UIO_SYSSPACE;
		if( bp->b_flags & B_READ)
			auio.uio_rw = UIO_READ;
		else
			auio.uio_rw = UIO_WRITE;
		auio.uio_resid = bp->b_bcount;
		auio.uio_procp = curproc;
		if (!VOP_ISLOCKED(vn->sc_vp)) {
			isvplocked = 1;
			vn_lock(vn->sc_vp, LK_EXCLUSIVE | LK_RETRY, curproc);
		}
		if( bp->b_flags & B_READ)
			error = VOP_READ(vn->sc_vp, &auio, 0, vn->sc_cred);
		else
			error = VOP_WRITE(vn->sc_vp, &auio, 0, vn->sc_cred);
		if (isvplocked) {
			VOP_UNLOCK(vn->sc_vp, 0, curproc);
			isvplocked = 0;
		}
		bp->b_resid = auio.uio_resid;

		if( error ) {
			bp->b_error = error;
			bp->b_flags |= B_ERROR;
		}
		biodone(bp);
	} else if (vn->sc_object) {
		/*
		 * OBJT_SWAP I/O
		 *
		 * ( handles read, write, freebuf )
		 */
		vm_pager_strategy(vn->sc_object, bp);
	} else {
		bp->b_flags |= B_ERROR;
		bp->b_error = EINVAL;
		biodone(bp);
	}
}

/* ARGSUSED */
static	int
vnioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	struct vn_softc *vn;
	struct vn_ioctl *vio;
	int error;
	u_long *f;

	vn = dev->si_drv1;
	IFOPT(vn,VN_FOLLOW)
		printf("vnioctl(%s, 0x%lx, %p, 0x%x, %p): unit %d\n",
		    devtoname(dev), cmd, (void *)data, flag, (void *)p,
		    dkunit(dev));

	switch (cmd) {
	case VNIOCATTACH:
	case VNIOCDETACH:
	case VNIOCGSET:
	case VNIOCGCLEAR:
	case VNIOCUSET:
	case VNIOCUCLEAR:
		goto vn_specific;
	}

	IFOPT(vn,VN_LABELS) {
		if (vn->sc_slices != NULL) {
			error = dsioctl("vn", dev, cmd, data, flag,
					&vn->sc_slices);
			if (error != ENOIOCTL)
				return (error);
		}
		if (dkslice(dev) != WHOLE_DISK_SLICE ||
		    dkpart(dev) != RAW_PART)
			return (ENOTTY);
	}

    vn_specific:

	error = suser(p);
	if (error)
		return (error);

	vio = (struct vn_ioctl *)data;
	f = (u_long*)data;
	switch (cmd) {

	case VNIOCATTACH:
		if (vn->sc_flags & VNF_INITED)
			return(EBUSY);

		if (vio->vn_file == NULL)
			error = vniocattach_swap(vn, vio, dev, flag, p);
		else
			error = vniocattach_file(vn, vio, dev, flag, p);
		break;

	case VNIOCDETACH:
		if ((vn->sc_flags & VNF_INITED) == 0)
			return(ENXIO);
		/*
		 * XXX handle i/o in progress.  Return EBUSY, or wait, or
		 * flush the i/o.
		 * XXX handle multiple opens of the device.  Return EBUSY,
		 * or revoke the fd's.
		 * How are these problems handled for removable and failing
		 * hardware devices? (Hint: They are not)
		 */
		vnclear(vn);
		IFOPT(vn, VN_FOLLOW)
			printf("vnioctl: CLRed\n");
		break;

	case VNIOCGSET:
		vn_options |= *f;
		*f = vn_options;
		break;

	case VNIOCGCLEAR:
		vn_options &= ~(*f);
		*f = vn_options;
		break;

	case VNIOCUSET:
		vn->sc_options |= *f;
		*f = vn->sc_options;
		break;

	case VNIOCUCLEAR:
		vn->sc_options &= ~(*f);
		*f = vn->sc_options;
		break;

	default:
		error = ENOTTY;
		break;
	}
	return(error);
}

/*
 *	vniocattach_file:
 *
 *	Attach a file to a VN partition.  Return the size in the vn_size
 *	field.
 */

static int
vniocattach_file(vn, vio, dev, flag, p)
	struct vn_softc *vn;
	struct vn_ioctl *vio;
	dev_t dev;
	int flag;
	struct proc *p;
{
	struct vattr vattr;
	struct nameidata nd;
	int error;

	/*
	 * Always open for read and write.
	 * This is probably bogus, but it lets vn_open()
	 * weed out directories, sockets, etc. so we don't
	 * have to worry about them.
	 */
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, vio->vn_file, p);
	error = vn_open(&nd, FREAD|FWRITE, 0);
	if (error)
		return(error);
	error = VOP_GETATTR(nd.ni_vp, &vattr, p->p_ucred, p);
	if (error) {
		VOP_UNLOCK(nd.ni_vp, 0, p);
		(void) vn_close(nd.ni_vp, FREAD|FWRITE, p->p_ucred, p);
		return(error);
	}
	VOP_UNLOCK(nd.ni_vp, 0, p);
	vn->sc_secsize = DEV_BSIZE;
	vn->sc_vp = nd.ni_vp;
	vn->sc_size = vattr.va_size / vn->sc_secsize;	/* note truncation */
	error = vnsetcred(vn, p->p_ucred);
	if (error) {
		(void) vn_close(nd.ni_vp, FREAD|FWRITE, p->p_ucred, p);
		return(error);
	}
	if (dev->si_bsize_phys < vn->sc_secsize)
		dev->si_bsize_phys = vn->sc_secsize;
	if (dev->si_bsize_best < vn->sc_secsize)
		dev->si_bsize_best = vn->sc_secsize;
	vn->sc_flags |= VNF_INITED;
	IFOPT(vn, VN_LABELS) {
		/*
		 * Reopen so that `ds' knows which devices are open.
		 * If this is the first VNIOCSET, then we've
		 * guaranteed that the device is the cdev and that
		 * no other slices or labels are open.  Otherwise,
		 * we rely on VNIOCCLR not being abused.
		 */
		error = vnopen(dev, flag, S_IFCHR, p);
		if (error)
			vnclear(vn);
	}
	IFOPT(vn, VN_FOLLOW)
		printf("vnioctl: SET vp %p size %x blks\n",
		       vn->sc_vp, vn->sc_size);
	return(0);
}

/*
 *	vniocattach_swap:
 *
 *	Attach swap backing store to a VN partition of the size specified
 *	in vn_size.
 */

static int
vniocattach_swap(vn, vio, dev, flag, p)
	struct vn_softc *vn;
	struct vn_ioctl *vio;
	dev_t dev;
	int flag;
	struct proc *p;
{
	int error;

	/*
	 * Range check.  Disallow negative sizes or any size less then the
	 * size of a page.  Then round to a page.
	 */

	if (vio->vn_size <= 0)
		return(EDOM);

	/*
	 * Allocate an OBJT_SWAP object.
	 *
	 * sc_secsize is PAGE_SIZE'd
	 *
	 * vio->vn_size is in PAGE_SIZE'd chunks.
	 * sc_size must be in PAGE_SIZE'd chunks.  
	 * Note the truncation.
	 */

	vn->sc_secsize = PAGE_SIZE;
	vn->sc_size = vio->vn_size;
	vn->sc_object = 
	 vm_pager_allocate(OBJT_SWAP, NULL, vn->sc_secsize * (vm_ooffset_t)vio->vn_size, VM_PROT_DEFAULT, 0);
	vn->sc_flags |= VNF_INITED;

	error = vnsetcred(vn, p->p_ucred);
	if (error == 0) {
		IFOPT(vn, VN_LABELS) {
			/*
			 * Reopen so that `ds' knows which devices are open.
			 * If this is the first VNIOCSET, then we've
			 * guaranteed that the device is the cdev and that
			 * no other slices or labels are open.  Otherwise,
			 * we rely on VNIOCCLR not being abused.
			 */
			error = vnopen(dev, flag, S_IFCHR, p);
		}
	}
	if (error == 0) {
		IFOPT(vn, VN_FOLLOW) {
			printf("vnioctl: SET vp %p size %x\n",
			       vn->sc_vp, vn->sc_size);
		}
	}
	if (error)
		vnclear(vn);
	return(error);
}

/*
 * Duplicate the current processes' credentials.  Since we are called only
 * as the result of a SET ioctl and only root can do that, any future access
 * to this "disk" is essentially as root.  Note that credentials may change
 * if some other uid can write directly to the mapped file (NFS).
 */
int
vnsetcred(struct vn_softc *vn, struct ucred *cred)
{
	struct uio auio;
	struct iovec aiov;
	char *tmpbuf;
	int error = 0;

	/*
	 * Set credits in our softc
	 */

	if (vn->sc_cred)
		crfree(vn->sc_cred);
	vn->sc_cred = crdup(cred);

	/*
	 * Horrible kludge to establish credentials for NFS  XXX.
	 */

	if (vn->sc_vp) {
		tmpbuf = malloc(vn->sc_secsize, M_TEMP, M_WAITOK);

		aiov.iov_base = tmpbuf;
		aiov.iov_len = vn->sc_secsize;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_resid = aiov.iov_len;
		vn_lock(vn->sc_vp, LK_EXCLUSIVE | LK_RETRY, curproc);
		error = VOP_READ(vn->sc_vp, &auio, 0, vn->sc_cred);
		VOP_UNLOCK(vn->sc_vp, 0, curproc);
		free(tmpbuf, M_TEMP);
	}
	return (error);
}

void
vnclear(struct vn_softc *vn)
{
	struct proc *p = curproc;		/* XXX */

	IFOPT(vn, VN_FOLLOW)
		printf("vnclear(%p): vp=%p\n", vn, vn->sc_vp);
	if (vn->sc_slices != NULL)
		dsgone(&vn->sc_slices);
	vn->sc_flags &= ~VNF_INITED;
	if (vn->sc_vp != NULL) {
		(void)vn_close(vn->sc_vp, FREAD|FWRITE, vn->sc_cred, p);
		vn->sc_vp = NULL;
	}
	if (vn->sc_cred) {
		crfree(vn->sc_cred);
		vn->sc_cred = NULL;
	}
	if (vn->sc_object != NULL) {
		vm_pager_deallocate(vn->sc_object);
		vn->sc_object = NULL;
	}
	vn->sc_size = 0;
}

static	int
vnsize(dev_t dev)
{
	struct vn_softc *vn;

	vn = dev->si_drv1;
	if (!vn)
		return(-1);
	if ((vn->sc_flags & VNF_INITED) == 0)
		return(-1);

	return(vn->sc_size);
}

static int 
vn_modevent(module_t mod, int type, void *data)
{
	struct vn_softc *vn;

	switch (type) {
	case MOD_LOAD:
		break;

	case MOD_UNLOAD:
		/* fall through */
	case MOD_SHUTDOWN:
		for (;;) {
			vn = SLIST_FIRST(&vn_list);
			if (!vn)
				break;
			SLIST_REMOVE_HEAD(&vn_list, sc_list);
			if (vn->sc_flags & VNF_INITED)
				vnclear(vn);
			free(vn, M_DEVBUF);
		}
		break;
	default:
		break;
	}
	return 0;
}

DEV_MODULE(vn, CDEV_MAJOR, BDEV_MAJOR, vn_cdevsw, vn_modevent, 0);
