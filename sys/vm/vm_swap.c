/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)vm_swap.c	8.5 (Berkeley) 2/17/94
 * $Id: vm_swap.c,v 1.15 1995/03/16 18:17:33 bde Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/dmap.h>		/* XXX */
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/rlist.h>

#include <vm/vm.h>

#include <miscfs/specfs/specdev.h>

/*
 * Indirect driver for multi-controller paging.
 */

int nswap, nswdev;
int vm_swap_size;
int bswneeded;
vm_offset_t swapbkva;		/* swap buffers kva */

/*
 * Set up swap devices.
 * Initialize linked list of free swap
 * headers. These do not actually point
 * to buffers, but rather to pages that
 * are being swapped in and out.
 */
void
swapinit()
{
	register struct proc *p = &proc0;	/* XXX */
	struct swdevt *swp;
	int error;

	/*
	 * Count swap devices, and adjust total swap space available. Some of
	 * the space will not be countable until later (dynamically
	 * configurable devices) and some of the counted space will not be
	 * available until a swapon() system call is issued, both usually
	 * happen when the system goes multi-user.
	 * 
	 * If using NFS for swap, swdevt[0] will already be bdevvp'd.	XXX
	 */
	nswdev = 0;
	nswap = 0;
	for (swp = swdevt; swp->sw_dev != NODEV || swp->sw_vp != NULL; swp++) {
		nswdev++;
		if (swp->sw_nblks > nswap)
			nswap = swp->sw_nblks;
	}
	if (nswdev == 0)
		panic("swapinit");
	if (nswdev > 1)
		nswap = ((nswap + dmmax - 1) / dmmax) * dmmax;
	nswap *= nswdev;
	if (swdevt[0].sw_vp == NULL &&
	    bdevvp(swdevt[0].sw_dev, &swdevt[0].sw_vp))
		panic("swapvp");
	/*
	 * If there is no swap configured, tell the user. We don't
	 * automatically activate any swapspaces in the kernel; the user must
	 * explicitly use swapon to enable swaping on a device.
	 */
	if (nswap == 0)
		printf("WARNING: no swap space found\n");
	for (swp = swdevt;; swp++) {
		if (swp->sw_dev == NODEV) {
			if (swp->sw_vp == NULL)
				break;

			/* We DO enable NFS swapspaces */
			error = swfree(p, swp - swdevt);
			if (error) {
				printf(
				    "Couldn't enable swapspace %d, error = %d",
				    swp - swdevt, error);
			}
		}
	}
}

void
swstrategy(bp)
	register struct buf *bp;
{
	int sz, off, seg, index;
	register struct swdevt *sp;
	struct vnode *vp;

	sz = howmany(bp->b_bcount, DEV_BSIZE);
	if (bp->b_blkno + sz > nswap) {
		bp->b_error = EINVAL;
		bp->b_flags |= B_ERROR;
		biodone(bp);
		return;
	}
	if (nswdev > 1) {
		off = bp->b_blkno % dmmax;
		if (off + sz > dmmax) {
			bp->b_error = EINVAL;
			bp->b_flags |= B_ERROR;
			biodone(bp);
			return;
		}
		seg = bp->b_blkno / dmmax;
		index = seg % nswdev;
		seg /= nswdev;
		bp->b_blkno = seg * dmmax + off;
	} else
		index = 0;
	sp = &swdevt[index];
	if ((bp->b_dev = sp->sw_dev) == NODEV)
		panic("swstrategy");
	if (sp->sw_vp == NULL) {
		bp->b_error = ENODEV;
		bp->b_flags |= B_ERROR;
		biodone(bp);
		return;
	}
	VHOLD(sp->sw_vp);
	if ((bp->b_flags & B_READ) == 0) {
		vp = bp->b_vp;
		if (vp) {
			vp->v_numoutput--;
			if ((vp->v_flag & VBWAIT) && vp->v_numoutput <= 0) {
				vp->v_flag &= ~VBWAIT;
				wakeup((caddr_t) &vp->v_numoutput);
			}
		}
		sp->sw_vp->v_numoutput++;
	}
	if (bp->b_vp != NULL)
		pbrelvp(bp);
	bp->b_vp = sp->sw_vp;
	VOP_STRATEGY(bp);
}

/*
 * System call swapon(name) enables swapping on device name,
 * which must be in the swdevsw.  Return EBUSY
 * if already swapping on this device.
 */
struct swapon_args {
	char *name;
};

/* ARGSUSED */
int
swapon(p, uap, retval)
	struct proc *p;
	struct swapon_args *uap;
	int *retval;
{
	register struct vnode *vp;
	register struct swdevt *sp;
	dev_t dev;
	int error;
	struct nameidata nd;

	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->name, p);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	if (vp->v_type != VBLK) {
		vrele(vp);
		return (ENOTBLK);
	}
	dev = (dev_t) vp->v_rdev;
	if (major(dev) >= nblkdev) {
		vrele(vp);
		return (ENXIO);
	}
	for (sp = &swdevt[0]; sp->sw_dev != NODEV; sp++) {
		if (sp->sw_dev == dev) {
			if (sp->sw_flags & SW_FREED) {
				vrele(vp);
				return (EBUSY);
			}
			sp->sw_vp = vp;
			error = swfree(p, sp - swdevt);
			if (error) {
				vrele(vp);
				return (error);
			}
			return (0);
		}
	}
	vrele(vp);
	return (EINVAL);
}

/*
 * Swfree(index) frees the index'th portion of the swap map.
 * Each of the nswdev devices provides 1/nswdev'th of the swap
 * space, which is laid out with blocks of dmmax pages circularly
 * among the devices.
 */
int
swfree(p, index)
	struct proc *p;
	int index;
{
	register struct swdevt *sp;
	register swblk_t vsbase;
	register long blk;
	struct vnode *vp;
	register swblk_t dvbase;
	register int nblks;
	int error;

	sp = &swdevt[index];
	vp = sp->sw_vp;
	error = VOP_OPEN(vp, FREAD | FWRITE, p->p_ucred, p);
	if (error)
		return (error);
	sp->sw_flags |= SW_FREED;
	nblks = sp->sw_nblks;
	/*
	 * Some devices may not exist til after boot time. If so, their nblk
	 * count will be 0.
	 */
	if (nblks <= 0) {
		int perdev;
		dev_t dev = sp->sw_dev;

		if (bdevsw[major(dev)].d_psize == 0 ||
		    (nblks = (*bdevsw[major(dev)].d_psize) (dev)) == -1) {
			(void) VOP_CLOSE(vp, FREAD | FWRITE, p->p_ucred, p);
			sp->sw_flags &= ~SW_FREED;
			return (ENXIO);
		}
		perdev = nswap / nswdev;
		if (nblks > perdev)
			nblks = perdev;
		sp->sw_nblks = nblks;
	}
	if (nblks == 0) {
		(void) VOP_CLOSE(vp, FREAD | FWRITE, p->p_ucred, p);
		sp->sw_flags &= ~SW_FREED;
		return (0);	/* XXX error? */
	}
	for (dvbase = dmmax; dvbase < nblks; dvbase += dmmax) {
		blk = nblks - dvbase;

		if ((vsbase = index * dmmax + dvbase * nswdev) >= nswap)
			panic("swfree");
		if (blk > dmmax)
			blk = dmmax;
		/* XXX -- we need to exclude the first cluster as above */
		/* but for now, this will work fine... */
		rlist_free(&swaplist, vsbase, vsbase + blk - 1);
		vm_swap_size += blk;
	}
	return (0);
}
