/*
 * Copyright (c) 1990 University of Utah.
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1993,1994 John S. Dyson
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
 *	from: @(#)vnode_pager.c	7.5 (Berkeley) 4/20/91
 *	$Id: vnode_pager.c,v 1.6 1994/08/07 13:10:43 davidg Exp $
 */

/*
 * Page to/from files (vnodes).
 *
 * TODO:
 *	pageouts
 *	fix credential use (uses current process credentials now)
 */

/*
 * MODIFICATIONS:
 * John S. Dyson  08 Dec 93
 *
 * This file in conjunction with some vm_fault mods, eliminate the performance
 * advantage for using the buffer cache and minimize memory copies.
 *
 * 1) Supports multiple - block reads
 * 2) Bypasses buffer cache for reads
 *
 * TODO:
 *
 * 1) Totally bypass buffer cache for reads
 *    (Currently will still sometimes use buffer cache for reads)
 * 2) Bypass buffer cache for writes
 *    (Code does not support it, but mods are simple)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/mount.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vnode_pager.h>

#include <sys/buf.h>
#include <miscfs/specfs/specdev.h>

int     vnode_pager_putmulti();

void    vnode_pager_init();
vm_pager_t vnode_pager_alloc(caddr_t, vm_offset_t, vm_prot_t, vm_offset_t);
void    vnode_pager_dealloc();
int     vnode_pager_getpage();
int     vnode_pager_getmulti();
int     vnode_pager_putpage();
boolean_t vnode_pager_haspage();

struct pagerops vnodepagerops = {
	vnode_pager_init,
	vnode_pager_alloc,
	vnode_pager_dealloc,
	vnode_pager_getpage,
	vnode_pager_getmulti,
	vnode_pager_putpage,
	vnode_pager_putmulti,
	vnode_pager_haspage
};



static int vnode_pager_input(vn_pager_t vnp, vm_page_t * m, int count, int reqpage);
static int vnode_pager_output(vn_pager_t vnp, vm_page_t * m, int count, int *rtvals);
struct buf * getpbuf();
void relpbuf(struct buf * bp);

extern vm_map_t pager_map;

struct pagerlst vnode_pager_list;	/* list of managed vnodes */

#define MAXBP (PAGE_SIZE/DEV_BSIZE);

void
vnode_pager_init()
{
	TAILQ_INIT(&vnode_pager_list);
}

/*
 * Allocate (or lookup) pager for a vnode.
 * Handle is a vnode pointer.
 */
vm_pager_t
vnode_pager_alloc(handle, size, prot, offset)
	caddr_t handle;
	vm_size_t size;
	vm_prot_t prot;
	vm_offset_t offset;
{
	register vm_pager_t pager;
	register vn_pager_t vnp;
	vm_object_t object;
	struct vattr vattr;
	struct vnode *vp;
	struct proc *p = curproc;	/* XXX */

	/*
	 * Pageout to vnode, no can do yet.
	 */
	if (handle == NULL)
		return (NULL);

	/*
	 * Vnodes keep a pointer to any associated pager so no need to lookup
	 * with vm_pager_lookup.
	 */
	vp = (struct vnode *) handle;
	pager = (vm_pager_t) vp->v_vmdata;
	if (pager == NULL) {

		/*
		 * Allocate pager structures
		 */
		pager = (vm_pager_t) malloc(sizeof *pager, M_VMPAGER, M_WAITOK);
		if (pager == NULL)
			return (NULL);
		vnp = (vn_pager_t) malloc(sizeof *vnp, M_VMPGDATA, M_WAITOK);
		if (vnp == NULL) {
			free((caddr_t) pager, M_VMPAGER);
			return (NULL);
		}

		/*
		 * And an object of the appropriate size
		 */
		if (VOP_GETATTR(vp, &vattr, p->p_ucred, p) == 0) {
			object = vm_object_allocate(round_page(vattr.va_size));
			vm_object_enter(object, pager);
			vm_object_setpager(object, pager, 0, TRUE);
		} else {
			free((caddr_t) vnp, M_VMPGDATA);
			free((caddr_t) pager, M_VMPAGER);
			return (NULL);
		}

		/*
		 * Hold a reference to the vnode and initialize pager data.
		 */
		VREF(vp);
		vnp->vnp_flags = 0;
		vnp->vnp_vp = vp;
		vnp->vnp_size = vattr.va_size;

		TAILQ_INSERT_TAIL(&vnode_pager_list, pager, pg_list);
		pager->pg_handle = handle;
		pager->pg_type = PG_VNODE;
		pager->pg_ops = &vnodepagerops;
		pager->pg_data = (caddr_t) vnp;
		vp->v_vmdata = (caddr_t) pager;
	} else {

		/*
		 * vm_object_lookup() will remove the object from the cache if
		 * found and also gain a reference to the object.
		 */
		object = vm_object_lookup(pager);
	}
	return (pager);
}

void
vnode_pager_dealloc(pager)
	vm_pager_t pager;
{
	register vn_pager_t vnp = (vn_pager_t) pager->pg_data;
	register struct vnode *vp;
	struct proc *p = curproc;	/* XXX */

	if (vp = vnp->vnp_vp) {
		vp->v_vmdata = NULL;
		vp->v_flag &= ~VTEXT;
#if 0
		/* can hang if done at reboot on NFS FS */
		(void) VOP_FSYNC(vp, p->p_ucred, p);
#endif
		vrele(vp);
	}
	TAILQ_REMOVE(&vnode_pager_list, pager, pg_list);
	free((caddr_t) vnp, M_VMPGDATA);
	free((caddr_t) pager, M_VMPAGER);
}

int
vnode_pager_getmulti(pager, m, count, reqpage, sync)
	vm_pager_t pager;
	vm_page_t *m;
	int     count;
	int     reqpage;
	boolean_t sync;
{

	return vnode_pager_input((vn_pager_t) pager->pg_data, m, count, reqpage);
}

int
vnode_pager_getpage(pager, m, sync)
	vm_pager_t pager;
	vm_page_t m;
	boolean_t sync;
{

	int     err;
	vm_page_t marray[1];

	if (pager == NULL)
		return FALSE;
	marray[0] = m;

	return vnode_pager_input((vn_pager_t) pager->pg_data, marray, 1, 0);
}

boolean_t
vnode_pager_putpage(pager, m, sync)
	vm_pager_t pager;
	vm_page_t m;
	boolean_t sync;
{
	int     err;
	vm_page_t marray[1];
	int     rtvals[1];

	if (pager == NULL)
		return FALSE;
	marray[0] = m;
	vnode_pager_output((vn_pager_t) pager->pg_data, marray, 1, rtvals);
	return rtvals[0];
}

int
vnode_pager_putmulti(pager, m, c, sync, rtvals)
	vm_pager_t pager;
	vm_page_t *m;
	int     c;
	boolean_t sync;
	int    *rtvals;
{
	return vnode_pager_output((vn_pager_t) pager->pg_data, m, c, rtvals);
}


boolean_t
vnode_pager_haspage(pager, offset)
	vm_pager_t pager;
	vm_offset_t offset;
{
	register vn_pager_t vnp = (vn_pager_t) pager->pg_data;
	daddr_t bn;
	int     err;

	/*
	 * Offset beyond end of file, do not have the page
	 */
	if (offset >= vnp->vnp_size) {
		return (FALSE);
	}

	/*
	 * Read the index to find the disk block to read from.  If there is no
	 * block, report that we don't have this data.
	 * 
	 * Assumes that the vnode has whole page or nothing.
	 */
	err = VOP_BMAP(vnp->vnp_vp,
		       offset / vnp->vnp_vp->v_mount->mnt_stat.f_iosize,
		       (struct vnode **) 0, &bn, 0);
	if (err) {
		return (TRUE);
	}
	return ((long) bn < 0 ? FALSE : TRUE);
}

/*
 * Lets the VM system know about a change in size for a file.
 * If this vnode is mapped into some address space (i.e. we have a pager
 * for it) we adjust our own internal size and flush any cached pages in
 * the associated object that are affected by the size change.
 *
 * Note: this routine may be invoked as a result of a pager put
 * operation (possibly at object termination time), so we must be careful.
 */
void
vnode_pager_setsize(vp, nsize)
	struct vnode *vp;
	u_long  nsize;
{
	register vn_pager_t vnp;
	register vm_object_t object;
	vm_pager_t pager;

	/*
	 * Not a mapped vnode
	 */
	if (vp == NULL || vp->v_type != VREG || vp->v_vmdata == NULL)
		return;

	/*
	 * Hasn't changed size
	 */
	pager = (vm_pager_t) vp->v_vmdata;
	vnp = (vn_pager_t) pager->pg_data;
	if (nsize == vnp->vnp_size)
		return;

	/*
	 * No object. This can happen during object termination since
	 * vm_object_page_clean is called after the object has been removed
	 * from the hash table, and clean may cause vnode write operations
	 * which can wind up back here.
	 */
	object = vm_object_lookup(pager);
	if (object == NULL)
		return;

	/*
	 * File has shrunk. Toss any cached pages beyond the new EOF.
	 */
	if (nsize < vnp->vnp_size) {
		vm_object_lock(object);
		vm_object_page_remove(object,
			     round_page((vm_offset_t) nsize), vnp->vnp_size);
		vm_object_unlock(object);

		/*
		 * this gets rid of garbage at the end of a page that is now
		 * only partially backed by the vnode...
		 */
		if (nsize & PAGE_MASK) {
			vm_offset_t kva;
			vm_page_t m;

			m = vm_page_lookup(object, trunc_page((vm_offset_t) nsize));
			if (m) {
				kva = vm_pager_map_page(m);
				bzero((caddr_t) kva + (nsize & PAGE_MASK),
				      round_page(nsize) - nsize);
				vm_pager_unmap_page(kva);
			}
		}
	} else {

		/*
		 * this allows the filesystem and VM cache to stay in sync if
		 * the VM page hasn't been modified...  After the page is
		 * removed -- it will be faulted back in from the filesystem
		 * cache.
		 */
		if (vnp->vnp_size & PAGE_MASK) {
			vm_page_t m;

			m = vm_page_lookup(object, trunc_page(vnp->vnp_size));
			if (m && (m->flags & PG_CLEAN)) {
				vm_object_lock(object);
				vm_object_page_remove(object,
					       vnp->vnp_size, vnp->vnp_size);
				vm_object_unlock(object);
			}
		}
	}
	vnp->vnp_size = (vm_offset_t) nsize;
	object->size = round_page(nsize);

	vm_object_deallocate(object);
}

void
vnode_pager_umount(mp)
	register struct mount *mp;
{
	register vm_pager_t pager, npager;
	struct vnode *vp;

	pager = vnode_pager_list.tqh_first;
	while (pager) {

		/*
		 * Save the next pointer now since uncaching may terminate the
		 * object and render pager invalid
		 */
		vp = ((vn_pager_t) pager->pg_data)->vnp_vp;
		npager = pager->pg_list.tqe_next;
		if (mp == (struct mount *) 0 || vp->v_mount == mp)
			(void) vnode_pager_uncache(vp);
		pager = npager;
	}
}

/*
 * Remove vnode associated object from the object cache.
 *
 * Note: this routine may be invoked as a result of a pager put
 * operation (possibly at object termination time), so we must be careful.
 */
boolean_t
vnode_pager_uncache(vp)
	register struct vnode *vp;
{
	register vm_object_t object;
	boolean_t uncached, locked;
	vm_pager_t pager;

	/*
	 * Not a mapped vnode
	 */
	pager = (vm_pager_t) vp->v_vmdata;
	if (pager == NULL)
		return (TRUE);

	/*
	 * Unlock the vnode if it is currently locked. We do this since
	 * uncaching the object may result in its destruction which may
	 * initiate paging activity which may necessitate locking the vnode.
	 */
	locked = VOP_ISLOCKED(vp);
	if (locked)
		VOP_UNLOCK(vp);

	/*
	 * Must use vm_object_lookup() as it actually removes the object from
	 * the cache list.
	 */
	object = vm_object_lookup(pager);
	if (object) {
		uncached = (object->ref_count <= 1);
		pager_cache(object, FALSE);
	} else
		uncached = TRUE;
	if (locked)
		VOP_LOCK(vp);
	return (uncached);
}


void
vnode_pager_freepage(m)
	vm_page_t m;
{
	PAGE_WAKEUP(m);
	vm_page_free(m);
}

/*
 * calculate the linear (byte) disk address of specified virtual
 * file address
 */
vm_offset_t
vnode_pager_addr(vp, address)
	struct vnode *vp;
	vm_offset_t address;
{
	int     rtaddress;
	int     bsize;
	vm_offset_t block;
	struct vnode *rtvp;
	int     err;
	int     vblock, voffset;

	bsize = vp->v_mount->mnt_stat.f_iosize;
	vblock = address / bsize;
	voffset = address % bsize;

	err = VOP_BMAP(vp, vblock, &rtvp, &block, 0);

	if (err)
		rtaddress = -1;
	else
		rtaddress = block * DEV_BSIZE + voffset;

	return rtaddress;
}

/*
 * interrupt routine for I/O completion
 */
void
vnode_pager_iodone(bp)
	struct buf *bp;
{
	bp->b_flags |= B_DONE;
	wakeup((caddr_t) bp);
	if( bp->b_flags & B_ASYNC) {
		vm_offset_t paddr;
		vm_page_t m;
		vm_object_t obj = 0;
		int i;
		int npages;

		paddr = (vm_offset_t) bp->b_data;
		if( bp->b_bufsize != bp->b_bcount)
			bzero( bp->b_data + bp->b_bcount,
				bp->b_bufsize - bp->b_bcount);

		npages = (bp->b_bufsize + PAGE_SIZE - 1) / PAGE_SIZE;
/*
		printf("bcount: %d, bufsize: %d, npages: %d\n",
			bp->b_bcount, bp->b_bufsize, npages);
*/
		for( i = 0; i < npages; i++) {
			m = PHYS_TO_VM_PAGE(pmap_kextract(paddr + i * PAGE_SIZE));
			obj = m->object;
			if( m) {
				m->flags |= PG_CLEAN;
				m->flags &= ~(PG_LAUNDRY|PG_FAKE);
				PAGE_WAKEUP(m);
			} else {
				panic("vnode_pager_iodone: page is gone!!!");
			}
		}
		pmap_qremove( paddr, npages);
		if( obj) {
			--obj->paging_in_progress;
			if( obj->paging_in_progress == 0)
				wakeup((caddr_t) obj);
		} else {
			panic("vnode_pager_iodone: object is gone???");
		}
		HOLDRELE(bp->b_vp);
		relpbuf(bp);
	}
}

/*
 * small block file system vnode pager input
 */
int
vnode_pager_input_smlfs(vnp, m)
	vn_pager_t vnp;
	vm_page_t m;
{
	int     i;
	int     s;
	vm_offset_t paging_offset;
	struct vnode *dp, *vp;
	struct buf *bp;
	vm_offset_t foff;
	vm_offset_t kva;
	int     fileaddr;
	int     block;
	vm_offset_t bsize;
	int     error = 0;

	paging_offset = m->object->paging_offset;
	vp = vnp->vnp_vp;
	bsize = vp->v_mount->mnt_stat.f_iosize;
	foff = m->offset + paging_offset;

	VOP_BMAP(vp, foff, &dp, 0, 0);

	kva = vm_pager_map_page(m);

	for (i = 0; i < PAGE_SIZE / bsize; i++) {

		/*
		 * calculate logical block and offset
		 */
		block = foff / bsize + i;
		s = splbio();
		while (bp = incore(vp, block)) {
			int     amount;

			/*
			 * wait until the buffer is avail or gone
			 */
			if (bp->b_flags & B_BUSY) {
				bp->b_flags |= B_WANTED;
				tsleep((caddr_t) bp, PVM, "vnwblk", 0);
				continue;
			}
			amount = bsize;
			if ((foff + bsize) > vnp->vnp_size)
				amount = vnp->vnp_size - foff;

			/*
			 * make sure that this page is in the buffer
			 */
			if ((amount > 0) && amount <= bp->b_bcount) {
				bp->b_flags |= B_BUSY;
				splx(s);

				/*
				 * copy the data from the buffer
				 */
				bcopy(bp->b_un.b_addr, (caddr_t) kva + i * bsize, amount);
				if (amount < bsize) {
					bzero((caddr_t) kva + amount, bsize - amount);
				}
				bp->b_flags &= ~B_BUSY;
				wakeup((caddr_t) bp);
				goto nextblock;
			}
			break;
		}
		splx(s);
		fileaddr = vnode_pager_addr(vp, foff + i * bsize);
		if (fileaddr != -1) {
			bp = getpbuf();
			VHOLD(vp);

			/* build a minimal buffer header */
			bp->b_flags = B_BUSY | B_READ | B_CALL;
			bp->b_iodone = vnode_pager_iodone;
			bp->b_proc = curproc;
			bp->b_rcred = bp->b_wcred = bp->b_proc->p_ucred;
			if (bp->b_rcred != NOCRED)
				crhold(bp->b_rcred);
			if (bp->b_wcred != NOCRED)
				crhold(bp->b_wcred);
			bp->b_un.b_addr = (caddr_t) kva + i * bsize;
			bp->b_blkno = fileaddr / DEV_BSIZE;
			bgetvp(dp, bp);
			bp->b_bcount = bsize;
			bp->b_bufsize = bsize;

			/* do the input */
			VOP_STRATEGY(bp);

			/* we definitely need to be at splbio here */

			s = splbio();
			while ((bp->b_flags & B_DONE) == 0) {
				tsleep((caddr_t) bp, PVM, "vnsrd", 0);
			}
			splx(s);
			if ((bp->b_flags & B_ERROR) != 0)
				error = EIO;

			/*
			 * free the buffer header back to the swap buffer pool
			 */
			relpbuf(bp);
			HOLDRELE(vp);
			if (error)
				break;
		} else {
			bzero((caddr_t) kva + i * bsize, bsize);
		}
nextblock:
	}
	vm_pager_unmap_page(kva);
	if (error) {
		return VM_PAGER_FAIL;
	}
	pmap_clear_modify(VM_PAGE_TO_PHYS(m));
	m->flags |= PG_CLEAN;
	m->flags &= ~PG_LAUNDRY;
	return VM_PAGER_OK;

}


/*
 * old style vnode pager output routine
 */
int
vnode_pager_input_old(vnp, m)
	vn_pager_t vnp;
	vm_page_t m;
{
	int     i;
	struct uio auio;
	struct iovec aiov;
	int     error;
	int     size;
	vm_offset_t foff;
	vm_offset_t kva;

	error = 0;
	foff = m->offset + m->object->paging_offset;

	/*
	 * Return failure if beyond current EOF
	 */
	if (foff >= vnp->vnp_size) {
		return VM_PAGER_BAD;
	} else {
		size = PAGE_SIZE;
		if (foff + size > vnp->vnp_size)
			size = vnp->vnp_size - foff;
/*
 * Allocate a kernel virtual address and initialize so that
 * we can use VOP_READ/WRITE routines.
 */
		kva = vm_pager_map_page(m);
		aiov.iov_base = (caddr_t) kva;
		aiov.iov_len = size;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = foff;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_READ;
		auio.uio_resid = size;
		auio.uio_procp = (struct proc *) 0;

		error = VOP_READ(vnp->vnp_vp, &auio, 0, curproc->p_ucred);
		if (!error) {
			register int count = size - auio.uio_resid;

			if (count == 0)
				error = EINVAL;
			else if (count != PAGE_SIZE)
				bzero((caddr_t) kva + count, PAGE_SIZE - count);
		}
		vm_pager_unmap_page(kva);
	}
	pmap_clear_modify(VM_PAGE_TO_PHYS(m));
	m->flags |= PG_CLEAN;
	m->flags &= ~PG_LAUNDRY;
	return error ? VM_PAGER_FAIL : VM_PAGER_OK;
}

/*
 * generic vnode pager input routine
 */
int
vnode_pager_input(vnp, m, count, reqpage)
	register vn_pager_t vnp;
	vm_page_t *m;
	int     count, reqpage;
{
	int     i, j;
	vm_offset_t kva, foff;
	int     size, sizea;
	struct proc *p = curproc;	/* XXX */
	vm_object_t object;
	vm_offset_t paging_offset;
	struct vnode *dp, *vp;
	int     bsize;

	int     first, last;
	int     reqaddr, firstaddr;
	int     block, offset;

	int     nbp;
	struct buf *bp, *bpa;
	int	counta;
	int     s;
	int     failflag;

	int     errtype = 0;	/* 0 is file type otherwise vm type */
	int     error = 0;

	object = m[reqpage]->object;	/* all vm_page_t items are in same
					 * object */
	paging_offset = object->paging_offset;

	vp = vnp->vnp_vp;
	bsize = vp->v_mount->mnt_stat.f_iosize;

	/* get the UNDERLYING device for the file with VOP_BMAP() */

	/*
	 * originally, we did not check for an error return value -- assuming
	 * an fs always has a bmap entry point -- that assumption is wrong!!!
	 */
	foff = m[reqpage]->offset + paging_offset;

	/*
	 * if we can't bmap, use old VOP code
	 */
	if (VOP_BMAP(vp, foff, &dp, 0, 0)) {
		for (i = 0; i < count; i++) {
			if (i != reqpage) {
				vnode_pager_freepage(m[i]);
			}
		}
		return vnode_pager_input_old(vnp, m[reqpage]);

		/*
		 * if the blocksize is smaller than a page size, then use
		 * special small filesystem code.  NFS sometimes has a small
		 * blocksize, but it can handle large reads itself.
		 */
	} else if ((PAGE_SIZE / bsize) > 1 &&
		   (vp->v_mount->mnt_stat.f_type != MOUNT_NFS)) {

		for (i = 0; i < count; i++) {
			if (i != reqpage) {
				vnode_pager_freepage(m[i]);
			}
		}
		return vnode_pager_input_smlfs(vnp, m[reqpage]);
	}
/*
 * here on direct device I/O
 */


	/*
	 * This pathetic hack gets data from the buffer cache, if it's there.
	 * I believe that this is not really necessary, and the ends can be
	 * gotten by defaulting to the normal vfs read behavior, but this
	 * might be more efficient, because the will NOT invoke read-aheads
	 * and one of the purposes of this code is to bypass the buffer cache
	 * and keep from flushing it by reading in a program.
	 */

	/*
	 * calculate logical block and offset
	 */
	block = foff / bsize;
	offset = foff % bsize;
	s = splbio();

	/*
	 * if we have a buffer in core, then try to use it
	 */
	while (bp = incore(vp, block)) {
		int     amount;

		/*
		 * wait until the buffer is avail or gone
		 */
		if (bp->b_flags & B_BUSY) {
			bp->b_flags |= B_WANTED;
			tsleep((caddr_t) bp, PVM, "vnwblk", 0);
			continue;
		}
		amount = PAGE_SIZE;
		if ((foff + amount) > vnp->vnp_size)
			amount = vnp->vnp_size - foff;

		/*
		 * make sure that this page is in the buffer
		 */
		if ((amount > 0) && (offset + amount) <= bp->b_bcount) {
			bp->b_flags |= B_BUSY;
			splx(s);
			kva = kmem_alloc_pageable( pager_map, PAGE_SIZE);

			/*
			 * map the requested page
			 */
			pmap_qenter(kva, &m[reqpage], 1);

			/*
			 * copy the data from the buffer
			 */
			bcopy(bp->b_un.b_addr + offset, (caddr_t) kva, amount);
			if (amount < PAGE_SIZE) {
				bzero((caddr_t) kva + amount, PAGE_SIZE - amount);
			}

			/*
			 * unmap the page and free the kva
			 */
			pmap_qremove( kva, 1);
			kmem_free_wakeup(pager_map, kva, PAGE_SIZE);

			/*
			 * release the buffer back to the block subsystem
			 */
			bp->b_flags &= ~B_BUSY;
			wakeup((caddr_t) bp);

			/*
			 * we did not have to do any work to get the requested
			 * page, the read behind/ahead does not justify a read
			 */
			for (i = 0; i < count; i++) {
				if (i != reqpage) {
					vnode_pager_freepage(m[i]);
				}
			}
			count = 1;
			reqpage = 0;
			m[0] = m[reqpage];

			/*
			 * sorry for the goto
			 */
			goto finishup;
		}

		/*
		 * buffer is nowhere to be found, read from the disk
		 */
		break;
	}
	splx(s);

	reqaddr = vnode_pager_addr(vp, foff);
	s = splbio();

	/*
	 * Make sure that our I/O request is contiguous. Scan backward and
	 * stop for the first discontiguous entry or stop for a page being in
	 * buffer cache.
	 */
	failflag = 0;
	first = reqpage;
	for (i = reqpage - 1; i >= 0; --i) {
		if (failflag ||
		    incore(vp, (foff + (i - reqpage) * PAGE_SIZE) / bsize) ||
		    (vnode_pager_addr(vp, m[i]->offset + paging_offset))
		    != reqaddr + (i - reqpage) * PAGE_SIZE) {
			vnode_pager_freepage(m[i]);
			failflag = 1;
		} else {
			first = i;
		}
	}

	/*
	 * Scan forward and stop for the first non-contiguous entry or stop
	 * for a page being in buffer cache.
	 */
	failflag = 0;
	last = reqpage + 1;
	for (i = reqpage + 1; i < count; i++) {
		if (failflag ||
		    incore(vp, (foff + (i - reqpage) * PAGE_SIZE) / bsize) ||
		    (vnode_pager_addr(vp, m[i]->offset + paging_offset))
		    != reqaddr + (i - reqpage) * PAGE_SIZE) {
			vnode_pager_freepage(m[i]);
			failflag = 1;
		} else {
			last = i + 1;
		}
	}
	splx(s);

	/*
	 * the first and last page have been calculated now, move input pages
	 * to be zero based...
	 */
	count = last;
	if (first != 0) {
		for (i = first; i < count; i++) {
			m[i - first] = m[i];
		}
		count -= first;
		reqpage -= first;
	}

	/*
	 * calculate the file virtual address for the transfer
	 */
	foff = m[0]->offset + paging_offset;

	/*
	 * and get the disk physical address (in bytes)
	 */
	firstaddr = vnode_pager_addr(vp, foff);

	/*
	 * calculate the size of the transfer
	 */
	size = count * PAGE_SIZE;
	if ((foff + size) > vnp->vnp_size)
		size = vnp->vnp_size - foff;

	/*
	 * round up physical size for real devices
	 */
	if (dp->v_type == VBLK || dp->v_type == VCHR)
		size = (size + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);

	counta = 0;
	if( count*PAGE_SIZE > bsize)
		counta = (count - reqpage) - 1;
	bpa = 0;
	sizea = 0;
	if( counta) {
		bpa = getpbuf();
		count -= counta;
		sizea = size - count*PAGE_SIZE;
		size = count * PAGE_SIZE;
	}

	bp = getpbuf();
	kva = (vm_offset_t)bp->b_data;

	/*
	 * and map the pages to be read into the kva
	 */
	pmap_qenter(kva, m, count);
	VHOLD(vp);

	/* build a minimal buffer header */
	bp->b_flags = B_BUSY | B_READ | B_CALL;
	bp->b_iodone = vnode_pager_iodone;
	/* B_PHYS is not set, but it is nice to fill this in */
	bp->b_proc = curproc;
	bp->b_rcred = bp->b_wcred = bp->b_proc->p_ucred;
	if (bp->b_rcred != NOCRED)
		crhold(bp->b_rcred);
	if (bp->b_wcred != NOCRED)
		crhold(bp->b_wcred);
	bp->b_blkno = firstaddr / DEV_BSIZE;
	bgetvp(dp, bp);
	bp->b_bcount = size;
	bp->b_bufsize = size;

	/* do the input */
	VOP_STRATEGY(bp);
	if( counta) {
		for(i=0;i<counta;i++) {
			vm_page_deactivate(m[count+i]);
		}
		pmap_qenter((vm_offset_t)bpa->b_data, &m[count], counta);
		++m[count]->object->paging_in_progress;
		VHOLD(vp);
		bpa->b_flags = B_BUSY | B_READ | B_CALL | B_ASYNC;
		bpa->b_iodone = vnode_pager_iodone;
		/* B_PHYS is not set, but it is nice to fill this in */
		bpa->b_proc = curproc;
		bpa->b_rcred = bpa->b_wcred = bpa->b_proc->p_ucred;
		if (bpa->b_rcred != NOCRED)
			crhold(bpa->b_rcred);
		if (bpa->b_wcred != NOCRED)
			crhold(bpa->b_wcred);
		bpa->b_blkno = (firstaddr + count * PAGE_SIZE) / DEV_BSIZE;
		bgetvp(dp, bpa);
		bpa->b_bcount = sizea;
		bpa->b_bufsize = counta*PAGE_SIZE;

		VOP_STRATEGY(bpa);
	}

	s = splbio();
	/* we definitely need to be at splbio here */

	while ((bp->b_flags & B_DONE) == 0) {
		tsleep((caddr_t) bp, PVM, "vnread", 0);
	}
	splx(s);
	if ((bp->b_flags & B_ERROR) != 0)
		error = EIO;

	if (!error) {
		if (size != count * PAGE_SIZE)
			bzero((caddr_t) kva + size, PAGE_SIZE * count - size);
	}
	pmap_qremove( kva, count);

	/*
	 * free the buffer header back to the swap buffer pool
	 */
	relpbuf(bp);
	HOLDRELE(vp);

finishup:
	for (i = 0; i < count; i++) {
		pmap_clear_modify(VM_PAGE_TO_PHYS(m[i]));
		m[i]->flags |= PG_CLEAN;
		m[i]->flags &= ~PG_LAUNDRY;
		if (i != reqpage) {

			/*
			 * whether or not to leave the page activated is up in
			 * the air, but we should put the page on a page queue
			 * somewhere. (it already is in the object). Result:
			 * It appears that emperical results show that
			 * deactivating pages is best.
			 */

			/*
			 * just in case someone was asking for this page we
			 * now tell them that it is ok to use
			 */
			if (!error) {
				vm_page_deactivate(m[i]);
				PAGE_WAKEUP(m[i]);
				m[i]->flags &= ~PG_FAKE;
			} else {
				vnode_pager_freepage(m[i]);
			}
		}
	}
	if (error) {
		printf("vnode pager read error: %d\n", error);
	}
	if (errtype)
		return error;
	return (error ? VM_PAGER_FAIL : VM_PAGER_OK);
}

/*
 * old-style vnode pager output routine
 */
int
vnode_pager_output_old(vnp, m)
	register vn_pager_t vnp;
	vm_page_t m;
{
	vm_offset_t foff;
	vm_offset_t kva;
	vm_offset_t size;
	struct iovec aiov;
	struct uio auio;
	struct vnode *vp;
	int     error;

	vp = vnp->vnp_vp;
	foff = m->offset + m->object->paging_offset;

	/*
	 * Return failure if beyond current EOF
	 */
	if (foff >= vnp->vnp_size) {
		return VM_PAGER_BAD;
	} else {
		size = PAGE_SIZE;
		if (foff + size > vnp->vnp_size)
			size = vnp->vnp_size - foff;
/*
 * Allocate a kernel virtual address and initialize so that
 * we can use VOP_WRITE routines.
 */
		kva = vm_pager_map_page(m);
		aiov.iov_base = (caddr_t) kva;
		aiov.iov_len = size;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = foff;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_WRITE;
		auio.uio_resid = size;
		auio.uio_procp = (struct proc *) 0;

		error = VOP_WRITE(vp, &auio, 0, curproc->p_ucred);

		if (!error) {
			if ((size - auio.uio_resid) == 0) {
				error = EINVAL;
			}
		}
		vm_pager_unmap_page(kva);
		return error ? VM_PAGER_FAIL : VM_PAGER_OK;
	}
}

/*
 * vnode pager output on a small-block file system
 */
int
vnode_pager_output_smlfs(vnp, m)
	vn_pager_t vnp;
	vm_page_t m;
{
	int     i;
	int     s;
	vm_offset_t paging_offset;
	struct vnode *dp, *vp;
	struct buf *bp;
	vm_offset_t foff;
	vm_offset_t kva;
	int     fileaddr;
	int     block;
	vm_offset_t bsize;
	int     error = 0;

	paging_offset = m->object->paging_offset;
	vp = vnp->vnp_vp;
	bsize = vp->v_mount->mnt_stat.f_iosize;
	foff = m->offset + paging_offset;

	VOP_BMAP(vp, foff, &dp, 0, 0);
	kva = vm_pager_map_page(m);
	for (i = 0; !error && i < (PAGE_SIZE / bsize); i++) {

		/*
		 * calculate logical block and offset
		 */
		fileaddr = vnode_pager_addr(vp, foff + i * bsize);
		if (fileaddr != -1) {
			s = splbio();
			if (bp = incore(vp, (foff / bsize) + i)) {
				bp = getblk(vp, (foff / bsize) + i, bp->b_bufsize, 0, 0);
				bp->b_flags |= B_INVAL;
				brelse(bp);
			}
			splx(s);

			bp = getpbuf();
			VHOLD(vp);

			/* build a minimal buffer header */
			bp->b_flags = B_BUSY | B_CALL | B_WRITE;
			bp->b_iodone = vnode_pager_iodone;
			bp->b_proc = curproc;
			bp->b_rcred = bp->b_wcred = bp->b_proc->p_ucred;
			if (bp->b_rcred != NOCRED)
				crhold(bp->b_rcred);
			if (bp->b_wcred != NOCRED)
				crhold(bp->b_wcred);
			bp->b_un.b_addr = (caddr_t) kva + i * bsize;
			bp->b_blkno = fileaddr / DEV_BSIZE;
			bgetvp(dp, bp);
			++dp->v_numoutput;
			/* for NFS */
			bp->b_dirtyoff = 0;
			bp->b_dirtyend = bsize;
			bp->b_bcount = bsize;
			bp->b_bufsize = bsize;

			/* do the input */
			VOP_STRATEGY(bp);

			/* we definitely need to be at splbio here */

			s = splbio();
			while ((bp->b_flags & B_DONE) == 0) {
				tsleep((caddr_t) bp, PVM, "vnswrt", 0);
			}
			splx(s);
			if ((bp->b_flags & B_ERROR) != 0)
				error = EIO;

			/*
			 * free the buffer header back to the swap buffer pool
			 */
			relpbuf(bp);
			HOLDRELE(vp);
		}
	}
	vm_pager_unmap_page(kva);
	if (error)
		return VM_PAGER_FAIL;
	else
		return VM_PAGER_OK;
}

/*
 * generic vnode pager output routine
 */
int
vnode_pager_output(vnp, m, count, rtvals)
	vn_pager_t vnp;
	vm_page_t *m;
	int     count;
	int    *rtvals;
{
	int     i, j;
	vm_offset_t kva, foff;
	int     size;
	struct proc *p = curproc;	/* XXX */
	vm_object_t object;
	vm_offset_t paging_offset;
	struct vnode *dp, *vp;
	struct buf *bp;
	vm_offset_t reqaddr;
	int     bsize;
	int     s;

	int     error = 0;

retryoutput:
	object = m[0]->object;	/* all vm_page_t items are in same object */
	paging_offset = object->paging_offset;

	vp = vnp->vnp_vp;
	bsize = vp->v_mount->mnt_stat.f_iosize;

	for (i = 0; i < count; i++)
		rtvals[i] = VM_PAGER_AGAIN;

	/*
	 * if the filesystem does not have a bmap, then use the old code
	 */
	if (VOP_BMAP(vp, m[0]->offset + paging_offset, &dp, 0, 0)) {

		rtvals[0] = vnode_pager_output_old(vnp, m[0]);

		pmap_clear_modify(VM_PAGE_TO_PHYS(m[0]));
		m[0]->flags |= PG_CLEAN;
		m[0]->flags &= ~PG_LAUNDRY;
		return rtvals[0];
	}

	/*
	 * if the filesystem has a small blocksize, then use the small block
	 * filesystem output code
	 */
	if ((bsize < PAGE_SIZE) &&
	    (vp->v_mount->mnt_stat.f_type != MOUNT_NFS)) {

		for (i = 0; i < count; i++) {
			rtvals[i] = vnode_pager_output_smlfs(vnp, m[i]);
			if (rtvals[i] == VM_PAGER_OK) {
				pmap_clear_modify(VM_PAGE_TO_PHYS(m[i]));
				m[i]->flags |= PG_CLEAN;
				m[i]->flags &= ~PG_LAUNDRY;
			}
		}
		return rtvals[0];
	}

	for (i = 0; i < count; i++) {
		foff = m[i]->offset + paging_offset;
		if (foff >= vnp->vnp_size) {
			for (j = i; j < count; j++)
				rtvals[j] = VM_PAGER_BAD;
			count = i;
			break;
		}
	}
	if (count == 0) {
		return rtvals[0];
	}
	foff = m[0]->offset + paging_offset;
	reqaddr = vnode_pager_addr(vp, foff);

	/*
	 * Scan forward and stop for the first non-contiguous entry or stop
	 * for a page being in buffer cache.
	 */
	for (i = 1; i < count; i++) {
		if (vnode_pager_addr(vp, m[i]->offset + paging_offset)
		    != reqaddr + i * PAGE_SIZE) {
			count = i;
			break;
		}
	}

	/*
	 * calculate the size of the transfer
	 */
	size = count * PAGE_SIZE;
	if ((foff + size) > vnp->vnp_size)
		size = vnp->vnp_size - foff;

	/*
	 * round up physical size for real devices
	 */
	if (dp->v_type == VBLK || dp->v_type == VCHR)
		size = (size + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);

	bp = getpbuf();
	kva = (vm_offset_t)bp->b_data;
	/*
	 * and map the pages to be read into the kva
	 */
	pmap_qenter(kva, m, count);
	printf("vnode: writing foff: %d, devoff: %d, size: %d\n",
		foff, reqaddr, size);

	/*
	 * next invalidate the incore vfs_bio data
	 */
	for (i = 0; i < count; i++) {
		int     filblock = (foff + i * PAGE_SIZE) / bsize;
		struct buf *fbp;

		s = splbio();
		if (fbp = incore(vp, filblock)) {
			fbp = getblk(vp, filblock, fbp->b_bufsize, 0, 0);
			if (fbp->b_flags & B_DELWRI) {
				if (fbp->b_bufsize <= PAGE_SIZE)
					fbp->b_flags &= ~B_DELWRI;
				else {
					bwrite(fbp);
					fbp = getblk(vp, filblock,
						     fbp->b_bufsize, 0, 0);
				}
			}
			fbp->b_flags |= B_INVAL;
			brelse(fbp);
		}
		splx(s);
	}


	VHOLD(vp);
	/* build a minimal buffer header */
	bp->b_flags = B_BUSY | B_WRITE | B_CALL;
	bp->b_iodone = vnode_pager_iodone;
	/* B_PHYS is not set, but it is nice to fill this in */
	bp->b_proc = curproc;
	bp->b_rcred = bp->b_wcred = bp->b_proc->p_ucred;

	if (bp->b_rcred != NOCRED)
		crhold(bp->b_rcred);
	if (bp->b_wcred != NOCRED)
		crhold(bp->b_wcred);
	bp->b_blkno = reqaddr / DEV_BSIZE;
	bgetvp(dp, bp);
	++dp->v_numoutput;

	/* for NFS */
	bp->b_dirtyoff = 0;
	bp->b_dirtyend = size;

	bp->b_bcount = size;
	bp->b_bufsize = size;

	/* do the output */
	VOP_STRATEGY(bp);

	s = splbio();

	/* we definitely need to be at splbio here */

	while ((bp->b_flags & B_DONE) == 0) {
		tsleep((caddr_t) bp, PVM, "vnwrite", 0);
	}
	splx(s);

	if ((bp->b_flags & B_ERROR) != 0)
		error = EIO;

	pmap_qremove( kva, count);

	/*
	 * free the buffer header back to the swap buffer pool
	 */
	relpbuf(bp);
	HOLDRELE(vp);

	if (!error) {
		for (i = 0; i < count; i++) {
			pmap_clear_modify(VM_PAGE_TO_PHYS(m[i]));
			m[i]->flags |= PG_CLEAN;
			m[i]->flags &= ~PG_LAUNDRY;
			rtvals[i] = VM_PAGER_OK;
		}
	} else if (count != 1) {
		error = 0;
		count = 1;
		goto retryoutput;
	}
	if (error) {
		printf("vnode pager write error: %d\n", error);
	}
	return (error ? VM_PAGER_FAIL : VM_PAGER_OK);
}
