/*
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Absolutely no warranty of function or purpose is made by the author
 *    John S. Dyson.
 * 4. This work was done expressly for inclusion into FreeBSD.  Other use
 *    is allowed if this notation is included.
 * 5. Modifications may be freely made to this file if the above conditions
 *    are met.
 *
 * $Id: vfs_bio.c,v 1.56 1995/07/29 11:40:18 bde Exp $
 */

/*
 * this file contains a new buffer I/O scheme implementing a coherent
 * VM object and buffer cache scheme.  Pains have been taken to make
 * sure that the performance degradation associated with schemes such
 * as this is not realized.
 *
 * Author:  John S. Dyson
 * Significant help during the development and debugging phases
 * had been provided by David Greenman, also of the FreeBSD core team.
 */

#define VMIO
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/proc.h>

#include <miscfs/specfs/specdev.h>

struct buf *buf;		/* buffer header pool */
struct swqueue bswlist;

void vm_hold_free_pages(struct buf * bp, vm_offset_t from, vm_offset_t to);
void vm_hold_load_pages(struct buf * bp, vm_offset_t from, vm_offset_t to);
void vfs_clean_pages(struct buf * bp);
static void vfs_setdirty(struct buf *bp);

int needsbuffer;

/*
 * Internal update daemon, process 3
 *	The variable vfs_update_wakeup allows for internal syncs.
 */
int vfs_update_wakeup;


/*
 * buffers base kva
 */
caddr_t buffers_kva;

/*
 * bogus page -- for I/O to/from partially complete buffers
 * this is a temporary solution to the problem, but it is not
 * really that bad.  it would be better to split the buffer
 * for input in the case of buffers partially already in memory,
 * but the code is intricate enough already.
 */
vm_page_t bogus_page;
vm_offset_t bogus_offset;

int bufspace, maxbufspace;

/*
 * advisory minimum for size of LRU queue or VMIO queue
 */
int minbuf;

struct bufhashhdr bufhashtbl[BUFHSZ], invalhash;
struct bqueues bufqueues[BUFFER_QUEUES];

/*
 * Initialize buffer headers and related structures.
 */
void
bufinit()
{
	struct buf *bp;
	int i;

	TAILQ_INIT(&bswlist);
	LIST_INIT(&invalhash);

	/* first, make a null hash table */
	for (i = 0; i < BUFHSZ; i++)
		LIST_INIT(&bufhashtbl[i]);

	/* next, make a null set of free lists */
	for (i = 0; i < BUFFER_QUEUES; i++)
		TAILQ_INIT(&bufqueues[i]);

	buffers_kva = (caddr_t) kmem_alloc_pageable(buffer_map, MAXBSIZE * nbuf);
	/* finally, initialize each buffer header and stick on empty q */
	for (i = 0; i < nbuf; i++) {
		bp = &buf[i];
		bzero(bp, sizeof *bp);
		bp->b_flags = B_INVAL;	/* we're just an empty header */
		bp->b_dev = NODEV;
		bp->b_rcred = NOCRED;
		bp->b_wcred = NOCRED;
		bp->b_qindex = QUEUE_EMPTY;
		bp->b_vnbufs.le_next = NOLIST;
		bp->b_data = buffers_kva + i * MAXBSIZE;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_EMPTY], bp, b_freelist);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
	}
/*
 * maxbufspace is currently calculated to support all filesystem blocks
 * to be 8K.  If you happen to use a 16K filesystem, the size of the buffer
 * cache is still the same as it would be for 8K filesystems.  This
 * keeps the size of the buffer cache "in check" for big block filesystems.
 */
	minbuf = nbuf / 3;
	maxbufspace = 2 * (nbuf + 8) * PAGE_SIZE;

	bogus_offset = kmem_alloc_pageable(kernel_map, PAGE_SIZE);
	bogus_page = vm_page_alloc(kernel_object,
			bogus_offset - VM_MIN_KERNEL_ADDRESS, VM_ALLOC_NORMAL);

}

/*
 * remove the buffer from the appropriate free list
 */
void
bremfree(struct buf * bp)
{
	int s = splbio();

	if (bp->b_qindex != QUEUE_NONE) {
		TAILQ_REMOVE(&bufqueues[bp->b_qindex], bp, b_freelist);
		bp->b_qindex = QUEUE_NONE;
	} else {
		panic("bremfree: removing a buffer when not on a queue");
	}
	splx(s);
}

/*
 * Get a buffer with the specified data.  Look in the cache first.
 */
int
bread(struct vnode * vp, daddr_t blkno, int size, struct ucred * cred,
    struct buf ** bpp)
{
	struct buf *bp;

	bp = getblk(vp, blkno, size, 0, 0);
	*bpp = bp;

	/* if not found in cache, do some I/O */
	if ((bp->b_flags & B_CACHE) == 0) {
		if (curproc != NULL)
			curproc->p_stats->p_ru.ru_inblock++;
		bp->b_flags |= B_READ;
		bp->b_flags &= ~(B_DONE | B_ERROR | B_INVAL);
		if (bp->b_rcred == NOCRED) {
			if (cred != NOCRED)
				crhold(cred);
			bp->b_rcred = cred;
		}
		vfs_busy_pages(bp, 0);
		VOP_STRATEGY(bp);
		return (biowait(bp));
	}
	return (0);
}

/*
 * Operates like bread, but also starts asynchronous I/O on
 * read-ahead blocks.
 */
int
breadn(struct vnode * vp, daddr_t blkno, int size,
    daddr_t * rablkno, int *rabsize,
    int cnt, struct ucred * cred, struct buf ** bpp)
{
	struct buf *bp, *rabp;
	int i;
	int rv = 0, readwait = 0;

	*bpp = bp = getblk(vp, blkno, size, 0, 0);

	/* if not found in cache, do some I/O */
	if ((bp->b_flags & B_CACHE) == 0) {
		if (curproc != NULL)
			curproc->p_stats->p_ru.ru_inblock++;
		bp->b_flags |= B_READ;
		bp->b_flags &= ~(B_DONE | B_ERROR | B_INVAL);
		if (bp->b_rcred == NOCRED) {
			if (cred != NOCRED)
				crhold(cred);
			bp->b_rcred = cred;
		}
		vfs_busy_pages(bp, 0);
		VOP_STRATEGY(bp);
		++readwait;
	}
	for (i = 0; i < cnt; i++, rablkno++, rabsize++) {
		if (inmem(vp, *rablkno))
			continue;
		rabp = getblk(vp, *rablkno, *rabsize, 0, 0);

		if ((rabp->b_flags & B_CACHE) == 0) {
			if (curproc != NULL)
				curproc->p_stats->p_ru.ru_inblock++;
			rabp->b_flags |= B_READ | B_ASYNC;
			rabp->b_flags &= ~(B_DONE | B_ERROR | B_INVAL);
			if (rabp->b_rcred == NOCRED) {
				if (cred != NOCRED)
					crhold(cred);
				rabp->b_rcred = cred;
			}
			vfs_busy_pages(rabp, 0);
			VOP_STRATEGY(rabp);
		} else {
			brelse(rabp);
		}
	}

	if (readwait) {
		rv = biowait(bp);
	}
	return (rv);
}

/*
 * Write, release buffer on completion.  (Done by iodone
 * if async.)
 */
int
bwrite(struct buf * bp)
{
	int oldflags = bp->b_flags;

	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return (0);
	}
	if (!(bp->b_flags & B_BUSY))
		panic("bwrite: buffer is not busy???");

	bp->b_flags &= ~(B_READ | B_DONE | B_ERROR | B_DELWRI);
	bp->b_flags |= B_WRITEINPROG;

	if ((oldflags & (B_ASYNC|B_DELWRI)) == (B_ASYNC|B_DELWRI)) {
		reassignbuf(bp, bp->b_vp);
	}

	bp->b_vp->v_numoutput++;
	vfs_busy_pages(bp, 1);
	if (curproc != NULL)
		curproc->p_stats->p_ru.ru_oublock++;
	VOP_STRATEGY(bp);

	if ((oldflags & B_ASYNC) == 0) {
		int rtval = biowait(bp);

		if (oldflags & B_DELWRI) {
			reassignbuf(bp, bp->b_vp);
		}
		brelse(bp);
		return (rtval);
	}
	return (0);
}

int
vn_bwrite(ap)
	struct vop_bwrite_args *ap;
{
	return (bwrite(ap->a_bp));
}

/*
 * Delayed write. (Buffer is marked dirty).
 */
void
bdwrite(struct buf * bp)
{

	if ((bp->b_flags & B_BUSY) == 0) {
		panic("bdwrite: buffer is not busy");
	}
	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return;
	}
	if (bp->b_flags & B_TAPE) {
		bawrite(bp);
		return;
	}
	bp->b_flags &= ~(B_READ|B_RELBUF);
	if ((bp->b_flags & B_DELWRI) == 0) {
		bp->b_flags |= B_DONE | B_DELWRI;
		reassignbuf(bp, bp->b_vp);
	}

	/*
	 * This bmap keeps the system from needing to do the bmap later,
	 * perhaps when the system is attempting to do a sync.  Since it
	 * is likely that the indirect block -- or whatever other datastructure
	 * that the filesystem needs is still in memory now, it is a good
	 * thing to do this.  Note also, that if the pageout daemon is
	 * requesting a sync -- there might not be enough memory to do
	 * the bmap then...  So, this is important to do.
	 */
	if( bp->b_lblkno == bp->b_blkno) {
		VOP_BMAP(bp->b_vp, bp->b_lblkno, NULL, &bp->b_blkno, NULL);
	}

	/*
	 * Set the *dirty* buffer range based upon the VM system dirty pages.
	 */
	vfs_setdirty(bp);

	/*
	 * We need to do this here to satisfy the vnode_pager and the
	 * pageout daemon, so that it thinks that the pages have been
	 * "cleaned".  Note that since the pages are in a delayed write
	 * buffer -- the VFS layer "will" see that the pages get written
	 * out on the next sync, or perhaps the cluster will be completed.
	 */
	vfs_clean_pages(bp);
	brelse(bp);
	return;
}

/*
 * Asynchronous write.
 * Start output on a buffer, but do not wait for it to complete.
 * The buffer is released when the output completes.
 */
void
bawrite(struct buf * bp)
{
	bp->b_flags |= B_ASYNC;
	(void) VOP_BWRITE(bp);
}

/*
 * Release a buffer.
 */
void
brelse(struct buf * bp)
{
	int s;

	if (bp->b_flags & B_CLUSTER) {
		relpbuf(bp);
		return;
	}
	/* anyone need a "free" block? */
	s = splbio();

	if (needsbuffer) {
		needsbuffer = 0;
		wakeup(&needsbuffer);
	}

	/* anyone need this block? */
	if (bp->b_flags & B_WANTED) {
		bp->b_flags &= ~(B_WANTED | B_AGE);
		wakeup(bp);
	} else if (bp->b_flags & B_VMIO) {
		bp->b_flags &= ~B_WANTED;
		wakeup(bp);
	}
	if (bp->b_flags & B_LOCKED)
		bp->b_flags &= ~B_ERROR;

	if ((bp->b_flags & (B_NOCACHE | B_INVAL | B_ERROR)) ||
	    (bp->b_bufsize <= 0)) {
		bp->b_flags |= B_INVAL;
		bp->b_flags &= ~(B_DELWRI | B_CACHE);
		if (((bp->b_flags & B_VMIO) == 0) && bp->b_vp)
			brelvp(bp);
	}

	/*
	 * VMIO buffer rundown.  It is not very necessary to keep a VMIO buffer
	 * constituted, so the B_INVAL flag is used to *invalidate* the buffer,
	 * but the VM object is kept around.  The B_NOCACHE flag is used to
	 * invalidate the pages in the VM object.
	 */
	if (bp->b_flags & B_VMIO) {
		vm_offset_t foff;
		vm_object_t obj;
		int i, resid;
		vm_page_t m;
		int iototal = bp->b_bufsize;

		foff = 0;
		obj = 0;
		if (bp->b_npages) {
			if (bp->b_vp && bp->b_vp->v_mount) {
				foff = bp->b_vp->v_mount->mnt_stat.f_iosize * bp->b_lblkno;
			} else {
				/*
				 * vnode pointer has been ripped away --
				 * probably file gone...
				 */
				foff = bp->b_pages[0]->offset;
			}
		}
		for (i = 0; i < bp->b_npages; i++) {
			m = bp->b_pages[i];
			if (m == bogus_page) {
				m = vm_page_lookup(obj, foff);
				if (!m) {
					panic("brelse: page missing\n");
				}
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page(bp->b_data), bp->b_pages, bp->b_npages);
			}
			resid = (m->offset + PAGE_SIZE) - foff;
			if (resid > iototal)
				resid = iototal;
			if (resid > 0) {
				/*
				 * Don't invalidate the page if the local machine has already
				 * modified it.  This is the lesser of two evils, and should
				 * be fixed.
				 */
				if (bp->b_flags & (B_NOCACHE | B_ERROR)) {
					vm_page_test_dirty(m);
					if (m->dirty == 0) {
						vm_page_set_invalid(m, foff, resid);
						if (m->valid == 0)
							vm_page_protect(m, VM_PROT_NONE);
					}
				}
			}
			foff += resid;
			iototal -= resid;
		}

		if (bp->b_flags & (B_INVAL | B_RELBUF)) {
			for(i=0;i<bp->b_npages;i++) {
				m = bp->b_pages[i];
				--m->bmapped;
				if (m->bmapped == 0) {
					if (m->flags & PG_WANTED) {
						wakeup(m);
						m->flags &= ~PG_WANTED;
					}
					vm_page_test_dirty(m);
					if ((m->dirty & m->valid) == 0 &&
						(m->flags & PG_REFERENCED) == 0 &&
							!pmap_is_referenced(VM_PAGE_TO_PHYS(m))) {
						vm_page_cache(m);
					} else if ((m->flags & PG_ACTIVE) == 0) {
						vm_page_activate(m);
						m->act_count = 0;
					}
				}
			}
			bufspace -= bp->b_bufsize;
			pmap_qremove(trunc_page((vm_offset_t) bp->b_data), bp->b_npages);
			bp->b_npages = 0;
			bp->b_bufsize = 0;
			bp->b_flags &= ~B_VMIO;
			if (bp->b_vp)
				brelvp(bp);
		}
	}
	if (bp->b_qindex != QUEUE_NONE)
		panic("brelse: free buffer onto another queue???");

	/* enqueue */
	/* buffers with no memory */
	if (bp->b_bufsize == 0) {
		bp->b_qindex = QUEUE_EMPTY;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_EMPTY], bp, b_freelist);
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
		bp->b_dev = NODEV;
		/* buffers with junk contents */
	} else if (bp->b_flags & (B_ERROR | B_INVAL | B_NOCACHE | B_RELBUF)) {
		bp->b_qindex = QUEUE_AGE;
		TAILQ_INSERT_HEAD(&bufqueues[QUEUE_AGE], bp, b_freelist);
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
		bp->b_dev = NODEV;
		/* buffers that are locked */
	} else if (bp->b_flags & B_LOCKED) {
		bp->b_qindex = QUEUE_LOCKED;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LOCKED], bp, b_freelist);
		/* buffers with stale but valid contents */
	} else if (bp->b_flags & B_AGE) {
		bp->b_qindex = QUEUE_AGE;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_AGE], bp, b_freelist);
		/* buffers with valid and quite potentially reuseable contents */
	} else {
		bp->b_qindex = QUEUE_LRU;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LRU], bp, b_freelist);
	}

	/* unlock */
	bp->b_flags &= ~(B_WANTED | B_BUSY | B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF);
	splx(s);
}

/*
 * this routine implements clustered async writes for
 * clearing out B_DELWRI buffers...  This is much better
 * than the old way of writing only one buffer at a time.
 */
void
vfs_bio_awrite(struct buf * bp)
{
	int i;
	daddr_t lblkno = bp->b_lblkno;
	struct vnode *vp = bp->b_vp;
	int s;
	int ncl;
	struct buf *bpa;

	s = splbio();
	if( vp->v_mount && (vp->v_flag & VVMIO) &&
	    	(bp->b_flags & (B_CLUSTEROK | B_INVAL)) == B_CLUSTEROK) {
		int size = vp->v_mount->mnt_stat.f_iosize;

		for (i = 1; i < MAXPHYS / size; i++) {
			if ((bpa = incore(vp, lblkno + i)) &&
			    ((bpa->b_flags & (B_BUSY | B_DELWRI | B_CLUSTEROK | B_INVAL)) ==
			    (B_DELWRI | B_CLUSTEROK)) &&
			    (bpa->b_bufsize == size)) {
				if ((bpa->b_blkno == bpa->b_lblkno) ||
				    (bpa->b_blkno != bp->b_blkno + (i * size) / DEV_BSIZE))
					break;
			} else {
				break;
			}
		}
		ncl = i;
		/*
		 * this is a possible cluster write
		 */
		if (ncl != 1) {
			bremfree(bp);
			cluster_wbuild(vp, bp, size, lblkno, ncl, -1);
			splx(s);
			return;
		}
	}
	/*
	 * default (old) behavior, writing out only one block
	 */
	bremfree(bp);
	bp->b_flags |= B_BUSY | B_ASYNC;
	(void) VOP_BWRITE(bp);
	splx(s);
}


/*
 * Find a buffer header which is available for use.
 */
static struct buf *
getnewbuf(int slpflag, int slptimeo, int doingvmio)
{
	struct buf *bp;
	int s;
	int firstbp = 1;

	s = splbio();
start:
	if (bufspace >= maxbufspace)
		goto trytofreespace;

	/* can we constitute a new buffer? */
	if ((bp = bufqueues[QUEUE_EMPTY].tqh_first)) {
		if (bp->b_qindex != QUEUE_EMPTY)
			panic("getnewbuf: inconsistent EMPTY queue");
		bremfree(bp);
		goto fillbuf;
	}
trytofreespace:
	/*
	 * We keep the file I/O from hogging metadata I/O
	 * This is desirable because file data is cached in the
	 * VM/Buffer cache even if a buffer is freed.
	 */
	if ((bp = bufqueues[QUEUE_AGE].tqh_first)) {
		if (bp->b_qindex != QUEUE_AGE)
			panic("getnewbuf: inconsistent AGE queue");
	} else if ((bp = bufqueues[QUEUE_LRU].tqh_first)) {
		if (bp->b_qindex != QUEUE_LRU)
			panic("getnewbuf: inconsistent LRU queue");
	}
	if (!bp) {
		/* wait for a free buffer of any kind */
		needsbuffer = 1;
		tsleep(&needsbuffer, PRIBIO | slpflag, "newbuf", slptimeo);
		splx(s);
		return (0);
	}

	/* if we are a delayed write, convert to an async write */
	if ((bp->b_flags & (B_DELWRI | B_INVAL)) == B_DELWRI) {
		vfs_bio_awrite(bp);
		if (!slpflag && !slptimeo) {
			splx(s);
			return (0);
		}
		goto start;
	}

	if (bp->b_flags & B_WANTED) {
		bp->b_flags &= ~B_WANTED;
		wakeup(bp);
	}
	bremfree(bp);

	if (bp->b_flags & B_VMIO) {
		bp->b_flags |= B_RELBUF | B_BUSY | B_DONE;
		brelse(bp);
		bremfree(bp);
	}

	if (bp->b_vp)
		brelvp(bp);

	/* we are not free, nor do we contain interesting data */
	if (bp->b_rcred != NOCRED)
		crfree(bp->b_rcred);
	if (bp->b_wcred != NOCRED)
		crfree(bp->b_wcred);
fillbuf:
	bp->b_flags |= B_BUSY;
	LIST_REMOVE(bp, b_hash);
	LIST_INSERT_HEAD(&invalhash, bp, b_hash);
	splx(s);
	if (bp->b_bufsize) {
		allocbuf(bp, 0);
	}
	bp->b_flags = B_BUSY;
	bp->b_dev = NODEV;
	bp->b_vp = NULL;
	bp->b_blkno = bp->b_lblkno = 0;
	bp->b_iodone = 0;
	bp->b_error = 0;
	bp->b_resid = 0;
	bp->b_bcount = 0;
	bp->b_npages = 0;
	bp->b_wcred = bp->b_rcred = NOCRED;
	bp->b_data = buffers_kva + (bp - buf) * MAXBSIZE;
	bp->b_dirtyoff = bp->b_dirtyend = 0;
	bp->b_validoff = bp->b_validend = 0;
	if (bufspace >= maxbufspace) {
		s = splbio();
		bp->b_flags |= B_INVAL;
		brelse(bp);
		goto trytofreespace;
	}
	return (bp);
}

/*
 * Check to see if a block is currently memory resident.
 */
struct buf *
incore(struct vnode * vp, daddr_t blkno)
{
	struct buf *bp;
	struct bufhashhdr *bh;

	int s = splbio();

	bh = BUFHASH(vp, blkno);
	bp = bh->lh_first;

	/* Search hash chain */
	while (bp) {
		/* hit */
		if (bp->b_lblkno == blkno && bp->b_vp == vp &&
		    (bp->b_flags & B_INVAL) == 0) {
			splx(s);
			return (bp);
		}
		bp = bp->b_hash.le_next;
	}
	splx(s);

	return (0);
}

/*
 * Returns true if no I/O is needed to access the
 * associated VM object.  This is like incore except
 * it also hunts around in the VM system for the data.
 */

int
inmem(struct vnode * vp, daddr_t blkno)
{
	vm_object_t obj;
	vm_offset_t off, toff, tinc;
	vm_page_t m;

	if (incore(vp, blkno))
		return 1;
	if (vp->v_mount == 0)
		return 0;
	if ((vp->v_object == 0) || (vp->v_flag & VVMIO) == 0)
		return 0;

	obj = vp->v_object;
	tinc = PAGE_SIZE;
	if (tinc > vp->v_mount->mnt_stat.f_iosize)
		tinc = vp->v_mount->mnt_stat.f_iosize;
	off = blkno * vp->v_mount->mnt_stat.f_iosize;

	for (toff = 0; toff < vp->v_mount->mnt_stat.f_iosize; toff += tinc) {
		int mask;

		m = vm_page_lookup(obj, trunc_page(toff + off));
		if (!m)
			return 0;
		if (vm_page_is_valid(m, toff + off, tinc) == 0)
			return 0;
	}
	return 1;
}

/*
 * now we set the dirty range for the buffer --
 * for NFS -- if the file is mapped and pages have
 * been written to, let it know.  We want the
 * entire range of the buffer to be marked dirty if
 * any of the pages have been written to for consistancy
 * with the b_validoff, b_validend set in the nfs write
 * code, and used by the nfs read code.
 */
static void
vfs_setdirty(struct buf *bp) {
	int i;
	vm_object_t object;
	vm_offset_t boffset, offset;
	/*
	 * We qualify the scan for modified pages on whether the
	 * object has been flushed yet.  The OBJ_WRITEABLE flag
	 * is not cleared simply by protecting pages off.
	 */
	if ((bp->b_flags & B_VMIO) &&
		((object = bp->b_pages[0]->object)->flags & OBJ_WRITEABLE)) {
		/*
		 * test the pages to see if they have been modified directly
		 * by users through the VM system.
		 */
		for (i = 0; i < bp->b_npages; i++)
			vm_page_test_dirty(bp->b_pages[i]);

		/*
		 * scan forwards for the first page modified
		 */
		for (i = 0; i < bp->b_npages; i++) {
			if (bp->b_pages[i]->dirty) {
				break;
			}
		}
		boffset = i * PAGE_SIZE;
		if (boffset < bp->b_dirtyoff) {
			bp->b_dirtyoff = boffset;
		}

		/*
		 * scan backwards for the last page modified
		 */
		for (i = bp->b_npages - 1; i >= 0; --i) {
			if (bp->b_pages[i]->dirty) {
				break;
			}
		}
		boffset = (i + 1) * PAGE_SIZE;
		offset = boffset + bp->b_pages[0]->offset;
		if (offset >= object->size) {
			boffset = object->size - bp->b_pages[0]->offset;
		}
		if (bp->b_dirtyend < boffset) {
			bp->b_dirtyend = boffset;
		}
	}
}

/*
 * Get a block given a specified block and offset into a file/device.
 */
struct buf *
getblk(struct vnode * vp, daddr_t blkno, int size, int slpflag, int slptimeo)
{
	struct buf *bp;
	int s;
	struct bufhashhdr *bh;
	vm_offset_t off;
	int nleft;

	s = splbio();
loop:
	if (bp = incore(vp, blkno)) {
		if (bp->b_flags & B_BUSY) {
			bp->b_flags |= B_WANTED;
			if (!tsleep(bp, PRIBIO | slpflag, "getblk", slptimeo))
				goto loop;

			splx(s);
			return (struct buf *) NULL;
		}
		bp->b_flags |= B_BUSY | B_CACHE;
		bremfree(bp);
		/*
		 * check for size inconsistancies
		 */
		if (bp->b_bcount != size) {
			allocbuf(bp, size);
		}
		splx(s);
		return (bp);
	} else {
		vm_object_t obj;
		int doingvmio;

		if ((obj = vp->v_object) && (vp->v_flag & VVMIO)) {
			doingvmio = 1;
		} else {
			doingvmio = 0;
		}
		if ((bp = getnewbuf(slpflag, slptimeo, doingvmio)) == 0) {
			if (slpflag || slptimeo)
				return NULL;
			goto loop;
		}

		/*
		 * This code is used to make sure that a buffer is not
		 * created while the getnewbuf routine is blocked.
		 * Normally the vnode is locked so this isn't a problem.
		 * VBLK type I/O requests, however, don't lock the vnode.
		 */
		if (!VOP_ISLOCKED(vp) && incore(vp, blkno)) {
			bp->b_flags |= B_INVAL;
			brelse(bp);
			goto loop;
		}

		/*
		 * Insert the buffer into the hash, so that it can
		 * be found by incore.
		 */
		bp->b_blkno = bp->b_lblkno = blkno;
		bgetvp(vp, bp);
		LIST_REMOVE(bp, b_hash);
		bh = BUFHASH(vp, blkno);
		LIST_INSERT_HEAD(bh, bp, b_hash);

		if (doingvmio) {
			bp->b_flags |= (B_VMIO | B_CACHE);
#if defined(VFS_BIO_DEBUG)
			if (vp->v_type != VREG)
				printf("getblk: vmioing file type %d???\n", vp->v_type);
#endif
		} else {
			bp->b_flags &= ~B_VMIO;
		}
		splx(s);

		allocbuf(bp, size);
		return (bp);
	}
}

/*
 * Get an empty, disassociated buffer of given size.
 */
struct buf *
geteblk(int size)
{
	struct buf *bp;

	while ((bp = getnewbuf(0, 0, 0)) == 0);
	allocbuf(bp, size);
	bp->b_flags |= B_INVAL;
	return (bp);
}

/*
 * This code constitutes the buffer memory from either anonymous system
 * memory (in the case of non-VMIO operations) or from an associated
 * VM object (in the case of VMIO operations).
 *
 * Note that this code is tricky, and has many complications to resolve
 * deadlock or inconsistant data situations.  Tread lightly!!!
 *
 * Modify the length of a buffer's underlying buffer storage without
 * destroying information (unless, of course the buffer is shrinking).
 */
int
allocbuf(struct buf * bp, int size)
{

	int s;
	int newbsize, mbsize;
	int i;

	if (!(bp->b_flags & B_BUSY))
		panic("allocbuf: buffer not busy");

	if ((bp->b_flags & B_VMIO) == 0) {
		/*
		 * Just get anonymous memory from the kernel
		 */
		mbsize = ((size + DEV_BSIZE - 1) / DEV_BSIZE) * DEV_BSIZE;
		newbsize = round_page(size);

		if (newbsize < bp->b_bufsize) {
			vm_hold_free_pages(
			    bp,
			    (vm_offset_t) bp->b_data + newbsize,
			    (vm_offset_t) bp->b_data + bp->b_bufsize);
		} else if (newbsize > bp->b_bufsize) {
			vm_hold_load_pages(
			    bp,
			    (vm_offset_t) bp->b_data + bp->b_bufsize,
			    (vm_offset_t) bp->b_data + newbsize);
		}
	} else {
		vm_page_t m;
		int desiredpages;

		newbsize = ((size + DEV_BSIZE - 1) / DEV_BSIZE) * DEV_BSIZE;
		desiredpages = round_page(newbsize) / PAGE_SIZE;

		if (newbsize < bp->b_bufsize) {
			if (desiredpages < bp->b_npages) {
				pmap_qremove((vm_offset_t) trunc_page(bp->b_data) +
				    desiredpages * PAGE_SIZE, (bp->b_npages - desiredpages));
				for (i = desiredpages; i < bp->b_npages; i++) {
					m = bp->b_pages[i];
					s = splhigh();
					while ((m->flags & PG_BUSY) || (m->busy != 0)) {
						m->flags |= PG_WANTED;
						tsleep(m, PVM, "biodep", 0);
					}
					splx(s);

					if (m->bmapped == 0) {
						printf("allocbuf: bmapped is zero for page %d\n", i);
						panic("allocbuf: error");
					}
					--m->bmapped;
					if (m->bmapped == 0) {
						vm_page_protect(m, VM_PROT_NONE);
						vm_page_free(m);
					}
					bp->b_pages[i] = NULL;
				}
				bp->b_npages = desiredpages;
			}
		} else if (newbsize > bp->b_bufsize) {
			vm_object_t obj;
			vm_offset_t tinc, off, toff, objoff;
			int pageindex, curbpnpages;
			struct vnode *vp;
			int bsize;

			vp = bp->b_vp;
			bsize = vp->v_mount->mnt_stat.f_iosize;

			if (bp->b_npages < desiredpages) {
				obj = vp->v_object;
				tinc = PAGE_SIZE;
				if (tinc > bsize)
					tinc = bsize;
				off = bp->b_lblkno * bsize;
		doretry:
				curbpnpages = bp->b_npages;
				bp->b_flags |= B_CACHE;
				for (toff = 0; toff < newbsize; toff += tinc) {
					int mask;
					int bytesinpage;

					pageindex = toff / PAGE_SIZE;
					objoff = trunc_page(toff + off);
					if (pageindex < curbpnpages) {
						int pb;

						m = bp->b_pages[pageindex];
						if (m->offset != objoff)
							panic("allocbuf: page changed offset??!!!?");
						bytesinpage = tinc;
						if (tinc > (newbsize - toff))
							bytesinpage = newbsize - toff;
						if (!vm_page_is_valid(m, toff + off, bytesinpage)) {
							bp->b_flags &= ~B_CACHE;
						}
						if ((m->flags & PG_ACTIVE) == 0) {
							vm_page_activate(m);
							m->act_count = 0;
						}
						continue;
					}
					m = vm_page_lookup(obj, objoff);
					if (!m) {
						m = vm_page_alloc(obj, objoff, VM_ALLOC_NORMAL);
						if (!m) {
							int j;

							for (j = bp->b_npages; j < pageindex; j++) {
								PAGE_WAKEUP(bp->b_pages[j]);
							}
							VM_WAIT;
							goto doretry;
						}
						vm_page_activate(m);
						m->act_count = 0;
						m->valid = 0;
						bp->b_flags &= ~B_CACHE;
					} else if (m->flags & PG_BUSY) {
						int j;

						for (j = bp->b_npages; j < pageindex; j++) {
							PAGE_WAKEUP(bp->b_pages[j]);
						}

						s = splbio();
						m->flags |= PG_WANTED;
						tsleep(m, PRIBIO, "pgtblk", 0);
						splx(s);

						goto doretry;
					} else {
						int pb;
						if ((curproc != pageproc) &&
							(m->flags & PG_CACHE) &&
						    (cnt.v_free_count + cnt.v_cache_count) < cnt.v_free_min) {
							pagedaemon_wakeup();
						}
						bytesinpage = tinc;
						if (tinc > (newbsize - toff))
							bytesinpage = newbsize - toff;
						if (!vm_page_is_valid(m, toff + off, bytesinpage)) {
							bp->b_flags &= ~B_CACHE;
						}
						if ((m->flags & PG_ACTIVE) == 0) {
							vm_page_activate(m);
							m->act_count = 0;
						}
						m->flags |= PG_BUSY;
					}
					bp->b_pages[pageindex] = m;
					curbpnpages = pageindex + 1;
				}
				for (i = bp->b_npages; i < curbpnpages; i++) {
					m = bp->b_pages[i];
					m->bmapped++;
					PAGE_WAKEUP(m);
				}
				bp->b_npages = curbpnpages;
				bp->b_data = buffers_kva + (bp - buf) * MAXBSIZE;
				pmap_qenter((vm_offset_t) bp->b_data, bp->b_pages, bp->b_npages);
				bp->b_data += off % PAGE_SIZE;
			}
		}
	}
	bufspace += (newbsize - bp->b_bufsize);
	bp->b_bufsize = newbsize;
	bp->b_bcount = size;
	return 1;
}

/*
 * Wait for buffer I/O completion, returning error status.
 */
int
biowait(register struct buf * bp)
{
	int s;

	s = splbio();
	while ((bp->b_flags & B_DONE) == 0)
		tsleep(bp, PRIBIO, "biowait", 0);
	splx(s);
	if (bp->b_flags & B_EINTR) {
		bp->b_flags &= ~B_EINTR;
		return (EINTR);
	}
	if (bp->b_flags & B_ERROR) {
		return (bp->b_error ? bp->b_error : EIO);
	} else {
		return (0);
	}
}

/*
 * Finish I/O on a buffer, calling an optional function.
 * This is usually called from interrupt level, so process blocking
 * is not *a good idea*.
 */
void
biodone(register struct buf * bp)
{
	int s;

	s = splbio();
	if (!(bp->b_flags & B_BUSY))
		panic("biodone: buffer not busy");

	if (bp->b_flags & B_DONE) {
		splx(s);
		printf("biodone: buffer already done\n");
		return;
	}
	bp->b_flags |= B_DONE;

	if ((bp->b_flags & B_READ) == 0) {
		struct vnode *vp = bp->b_vp;
		vwakeup(bp);
	}
#ifdef BOUNCE_BUFFERS
	if (bp->b_flags & B_BOUNCE)
		vm_bounce_free(bp);
#endif

	/* call optional completion function if requested */
	if (bp->b_flags & B_CALL) {
		bp->b_flags &= ~B_CALL;
		(*bp->b_iodone) (bp);
		splx(s);
		return;
	}
	if (bp->b_flags & B_VMIO) {
		int i, resid;
		vm_offset_t foff;
		vm_page_t m;
		vm_object_t obj;
		int iosize;
		struct vnode *vp = bp->b_vp;

		foff = vp->v_mount->mnt_stat.f_iosize * bp->b_lblkno;
		obj = vp->v_object;
		if (!obj) {
			panic("biodone: no object");
		}
#if defined(VFS_BIO_DEBUG)
		if (obj->paging_in_progress < bp->b_npages) {
			printf("biodone: paging in progress(%d) < bp->b_npages(%d)\n",
			    obj->paging_in_progress, bp->b_npages);
		}
#endif
		iosize = bp->b_bufsize;
		for (i = 0; i < bp->b_npages; i++) {
			int bogusflag = 0;
			m = bp->b_pages[i];
			if (m == bogus_page) {
				bogusflag = 1;
				m = vm_page_lookup(obj, foff);
				if (!m) {
#if defined(VFS_BIO_DEBUG)
					printf("biodone: page disappeared\n");
#endif
					--obj->paging_in_progress;
					continue;
				}
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page(bp->b_data), bp->b_pages, bp->b_npages);
			}
#if defined(VFS_BIO_DEBUG)
			if (trunc_page(foff) != m->offset) {
				printf("biodone: foff(%d)/m->offset(%d) mismatch\n", foff, m->offset);
			}
#endif
			resid = (m->offset + PAGE_SIZE) - foff;
			if (resid > iosize)
				resid = iosize;
			/*
			 * In the write case, the valid and clean bits are
			 * already changed correctly, so we only need to do this
			 * here in the read case.
			 */
			if ((bp->b_flags & B_READ) && !bogusflag && resid > 0) {
				vm_page_set_valid(m, foff & (PAGE_SIZE-1), resid);
				vm_page_set_clean(m, foff & (PAGE_SIZE-1), resid);
			}

			/*
			 * when debugging new filesystems or buffer I/O methods, this
			 * is the most common error that pops up.  if you see this, you
			 * have not set the page busy flag correctly!!!
			 */
			if (m->busy == 0) {
				printf("biodone: page busy < 0, "
				    "off: %ld, foff: %ld, "
				    "resid: %d, index: %d\n",
				    m->offset, foff, resid, i);
				printf(" iosize: %ld, lblkno: %ld, flags: 0x%x, npages: %d\n",
				    bp->b_vp->v_mount->mnt_stat.f_iosize,
				    bp->b_lblkno, bp->b_flags, bp->b_npages);
				printf(" valid: 0x%x, dirty: 0x%x, mapped: %d\n",
				    m->valid, m->dirty, m->bmapped);
				panic("biodone: page busy < 0\n");
			}
			--m->busy;
			if ((m->busy == 0) && (m->flags & PG_WANTED)) {
				m->flags &= ~PG_WANTED;
				wakeup(m);
			}
			--obj->paging_in_progress;
			foff += resid;
			iosize -= resid;
		}
		if (obj && obj->paging_in_progress == 0 &&
		    (obj->flags & OBJ_PIPWNT)) {
			obj->flags &= ~OBJ_PIPWNT;
			wakeup(obj);
		}
	}
	/*
	 * For asynchronous completions, release the buffer now. The brelse
	 * checks for B_WANTED and will do the wakeup there if necessary - so
	 * no need to do a wakeup here in the async case.
	 */

	if (bp->b_flags & B_ASYNC) {
		brelse(bp);
	} else {
		bp->b_flags &= ~B_WANTED;
		wakeup(bp);
	}
	splx(s);
}

int
count_lock_queue()
{
	int count;
	struct buf *bp;

	count = 0;
	for (bp = bufqueues[QUEUE_LOCKED].tqh_first;
	    bp != NULL;
	    bp = bp->b_freelist.tqe_next)
		count++;
	return (count);
}

int vfs_update_interval = 30;

void
vfs_update()
{
	(void) spl0();
	while (1) {
		tsleep(&vfs_update_wakeup, PRIBIO, "update",
		    hz * vfs_update_interval);
		vfs_update_wakeup = 0;
		sync(curproc, NULL, NULL);
	}
}

/*
 * This routine is called in lieu of iodone in the case of
 * incomplete I/O.  This keeps the busy status for pages
 * consistant.
 */
void
vfs_unbusy_pages(struct buf * bp)
{
	int i;

	if (bp->b_flags & B_VMIO) {
		struct vnode *vp = bp->b_vp;
		vm_object_t obj = vp->v_object;
		vm_offset_t foff;

		foff = trunc_page(vp->v_mount->mnt_stat.f_iosize * bp->b_lblkno);

		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];

			if (m == bogus_page) {
				m = vm_page_lookup(obj, foff + i * PAGE_SIZE);
				if (!m) {
					panic("vfs_unbusy_pages: page missing\n");
				}
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page(bp->b_data), bp->b_pages, bp->b_npages);
			}
			--obj->paging_in_progress;
			--m->busy;
			if ((m->busy == 0) && (m->flags & PG_WANTED)) {
				m->flags &= ~PG_WANTED;
				wakeup(m);
			}
		}
		if (obj->paging_in_progress == 0 &&
		    (obj->flags & OBJ_PIPWNT)) {
			obj->flags &= ~OBJ_PIPWNT;
			wakeup(obj);
		}
	}
}

/*
 * This routine is called before a device strategy routine.
 * It is used to tell the VM system that paging I/O is in
 * progress, and treat the pages associated with the buffer
 * almost as being PG_BUSY.  Also the object paging_in_progress
 * flag is handled to make sure that the object doesn't become
 * inconsistant.
 */
void
vfs_busy_pages(struct buf * bp, int clear_modify)
{
	int i;

	if (bp->b_flags & B_VMIO) {
		vm_object_t obj = bp->b_vp->v_object;
		vm_offset_t foff = bp->b_vp->v_mount->mnt_stat.f_iosize * bp->b_lblkno;
		int iocount = bp->b_bufsize;

		vfs_setdirty(bp);
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];
			int resid = (m->offset + PAGE_SIZE) - foff;

			if (resid > iocount)
				resid = iocount;
			obj->paging_in_progress++;
			m->busy++;
			if (clear_modify) {
				vm_page_protect(m, VM_PROT_READ);
				vm_page_set_valid(m,
					foff & (PAGE_SIZE-1), resid);
				vm_page_set_clean(m,
					foff & (PAGE_SIZE-1), resid);
			} else if (bp->b_bcount >= PAGE_SIZE) {
				if (m->valid && (bp->b_flags & B_CACHE) == 0) {
					bp->b_pages[i] = bogus_page;
					pmap_qenter(trunc_page(bp->b_data), bp->b_pages, bp->b_npages);
				}
			}
			foff += resid;
			iocount -= resid;
		}
	}
}

/*
 * Tell the VM system that the pages associated with this buffer
 * are clean.  This is used for delayed writes where the data is
 * going to go to disk eventually without additional VM intevention.
 */
void
vfs_clean_pages(struct buf * bp)
{
	int i;

	if (bp->b_flags & B_VMIO) {
		vm_offset_t foff =
			bp->b_vp->v_mount->mnt_stat.f_iosize * bp->b_lblkno;
		int iocount = bp->b_bufsize;

		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];
			int resid = (m->offset + PAGE_SIZE) - foff;

			if (resid > iocount)
				resid = iocount;
			if (resid > 0) {
				vm_page_set_valid(m,
					foff & (PAGE_SIZE-1), resid);
				vm_page_set_clean(m,
					foff & (PAGE_SIZE-1), resid);
			}
			foff += resid;
			iocount -= resid;
		}
	}
}

void
vfs_bio_clrbuf(struct buf *bp) {
	int i;
	if( bp->b_flags & B_VMIO) {
		if( (bp->b_npages == 1) && (bp->b_bufsize < PAGE_SIZE)) {
			int j;
			if( bp->b_pages[0]->valid != VM_PAGE_BITS_ALL) {
				for(j=0; j < bp->b_bufsize / DEV_BSIZE;j++) {
					bzero(bp->b_data + j * DEV_BSIZE, DEV_BSIZE);
				}
			}
			bp->b_resid = 0;
			return;
		}
		for(i=0;i<bp->b_npages;i++) {
			if( bp->b_pages[i]->valid == VM_PAGE_BITS_ALL)
				continue;
			if( bp->b_pages[i]->valid == 0) {
				bzero(bp->b_data + i * PAGE_SIZE, PAGE_SIZE);
			} else {
				int j;
				for(j=0;j<PAGE_SIZE/DEV_BSIZE;j++) {
					if( (bp->b_pages[i]->valid & (1<<j)) == 0)
						bzero(bp->b_data + i * PAGE_SIZE + j * DEV_BSIZE, DEV_BSIZE);
				}
			}
			bp->b_pages[i]->valid = VM_PAGE_BITS_ALL;
		}
		bp->b_resid = 0;
	} else {
		clrbuf(bp);
	}
}

/*
 * vm_hold_load_pages and vm_hold_unload pages get pages into
 * a buffers address space.  The pages are anonymous and are
 * not associated with a file object.
 */
void
vm_hold_load_pages(struct buf * bp, vm_offset_t froma, vm_offset_t toa)
{
	vm_offset_t pg;
	vm_page_t p;
	vm_offset_t from = round_page(froma);
	vm_offset_t to = round_page(toa);

	for (pg = from; pg < to; pg += PAGE_SIZE) {

tryagain:

		p = vm_page_alloc(kernel_object, pg - VM_MIN_KERNEL_ADDRESS,
		    VM_ALLOC_NORMAL);
		if (!p) {
			VM_WAIT;
			goto tryagain;
		}
		vm_page_wire(p);
		pmap_kenter(pg, VM_PAGE_TO_PHYS(p));
		bp->b_pages[((caddr_t) pg - bp->b_data) / PAGE_SIZE] = p;
		PAGE_WAKEUP(p);
		bp->b_npages++;
	}
}

void
vm_hold_free_pages(struct buf * bp, vm_offset_t froma, vm_offset_t toa)
{
	vm_offset_t pg;
	vm_page_t p;
	vm_offset_t from = round_page(froma);
	vm_offset_t to = round_page(toa);

	for (pg = from; pg < to; pg += PAGE_SIZE) {
		p = bp->b_pages[((caddr_t) pg - bp->b_data) / PAGE_SIZE];
		bp->b_pages[((caddr_t) pg - bp->b_data) / PAGE_SIZE] = 0;
		pmap_kremove(pg);
		vm_page_free(p);
		--bp->b_npages;
	}
}
