/*
 * Copyright (c) 1994,1997 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Absolutely no warranty of function or purpose is made by the author
 *		John S. Dyson.
 *
 * $Id: vfs_bio.c,v 1.201 1999/03/02 21:23:38 julian Exp $
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
 *
 * see man buf(9) for more info.
 */

#define VMIO
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vmmeter.h>
#include <sys/lock.h>
#include <miscfs/specfs/specdev.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_prot.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>

static MALLOC_DEFINE(M_BIOBUF, "BIO buffer", "BIO buffer");

struct	bio_ops bioops;		/* I/O operation notification */

#if 0 	/* replaced bu sched_sync */
static void vfs_update __P((void));
static struct	proc *updateproc;
static struct kproc_desc up_kp = {
	"update",
	vfs_update,
	&updateproc
};
SYSINIT_KT(update, SI_SUB_KTHREAD_UPDATE, SI_ORDER_FIRST, kproc_start, &up_kp)
#endif

struct buf *buf;		/* buffer header pool */
struct swqueue bswlist;

static void vm_hold_free_pages(struct buf * bp, vm_offset_t from,
		vm_offset_t to);
static void vm_hold_load_pages(struct buf * bp, vm_offset_t from,
		vm_offset_t to);
static void vfs_buf_set_valid(struct buf *bp, vm_ooffset_t foff,
			      vm_offset_t off, vm_offset_t size,
			      vm_page_t m);
static void vfs_page_set_valid(struct buf *bp, vm_ooffset_t off,
			       int pageno, vm_page_t m);
static void vfs_clean_pages(struct buf * bp);
static void vfs_setdirty(struct buf *bp);
static void vfs_vmio_release(struct buf *bp);
static void flushdirtybuffers(int slpflag, int slptimeo);
static int flushbufqueues(void);

/*
 * Internal update daemon, process 3
 *	The variable vfs_update_wakeup allows for internal syncs.
 */
int vfs_update_wakeup;

/*
 * bogus page -- for I/O to/from partially complete buffers
 * this is a temporary solution to the problem, but it is not
 * really that bad.  it would be better to split the buffer
 * for input in the case of buffers partially already in memory,
 * but the code is intricate enough already.
 */
vm_page_t bogus_page;
int runningbufspace;
static vm_offset_t bogus_offset;

static int bufspace, maxbufspace, vmiospace, maxvmiobufspace,
	bufmallocspace, maxbufmallocspace, hibufspace;
static int needsbuffer;
static int numdirtybuffers, lodirtybuffers, hidirtybuffers;
static int numfreebuffers, lofreebuffers, hifreebuffers;
static int kvafreespace;

SYSCTL_INT(_vfs, OID_AUTO, numdirtybuffers, CTLFLAG_RD,
	&numdirtybuffers, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, lodirtybuffers, CTLFLAG_RW,
	&lodirtybuffers, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, hidirtybuffers, CTLFLAG_RW,
	&hidirtybuffers, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, numfreebuffers, CTLFLAG_RD,
	&numfreebuffers, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, lofreebuffers, CTLFLAG_RW,
	&lofreebuffers, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, hifreebuffers, CTLFLAG_RW,
	&hifreebuffers, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, runningbufspace, CTLFLAG_RD,
	&runningbufspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, maxbufspace, CTLFLAG_RW,
	&maxbufspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, hibufspace, CTLFLAG_RD,
	&hibufspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, bufspace, CTLFLAG_RD,
	&bufspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, maxvmiobufspace, CTLFLAG_RW,
	&maxvmiobufspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, vmiospace, CTLFLAG_RD,
	&vmiospace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, maxmallocbufspace, CTLFLAG_RW,
	&maxbufmallocspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, bufmallocspace, CTLFLAG_RD,
	&bufmallocspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, kvafreespace, CTLFLAG_RD,
	&kvafreespace, 0, "");

static LIST_HEAD(bufhashhdr, buf) bufhashtbl[BUFHSZ], invalhash;
struct bqueues bufqueues[BUFFER_QUEUES] = { { 0 } };

extern int vm_swap_size;

#define BUF_MAXUSE		24

#define VFS_BIO_NEED_ANY	0x01	/* any freeable buffer */
#define VFS_BIO_NEED_RESERVED02	0x02	/* unused */
#define VFS_BIO_NEED_FREE	0x04	/* wait for free bufs, hi hysteresis */
#define VFS_BIO_NEED_BUFSPACE	0x08	/* wait for buf space, lo hysteresis */
#define VFS_BIO_NEED_KVASPACE	0x10	/* wait for buffer_map space, emerg  */

/*
 *	kvaspacewakeup:
 *
 *	Called when kva space is potential available for recovery or when
 *	kva space is recovered in the buffer_map.  This function wakes up
 *	anyone waiting for buffer_map kva space.  Even though the buffer_map
 *	is larger then maxbufspace, this situation will typically occur 
 *	when the buffer_map gets fragmented.
 */

static __inline void
kvaspacewakeup(void)
{
	/*
	 * If someone is waiting for KVA space, wake them up.  Even
	 * though we haven't freed the kva space yet, the waiting
	 * process will be able to now.
	 */
	if (needsbuffer & VFS_BIO_NEED_KVASPACE) {
		needsbuffer &= ~VFS_BIO_NEED_KVASPACE;
		wakeup(&needsbuffer);
	}
}

/*
 *	bufspacewakeup:
 *
 *	Called when buffer space is potentially available for recovery or when
 *	buffer space is recovered.  getnewbuf() will block on this flag when
 *	it is unable to free sufficient buffer space.  Buffer space becomes
 *	recoverable when bp's get placed back in the queues.
 */

static __inline void
bufspacewakeup(void)
{
	/*
	 * If someone is waiting for BUF space, wake them up.  Even
	 * though we haven't freed the kva space yet, the waiting
	 * process will be able to now.
	 */
	if (needsbuffer & VFS_BIO_NEED_BUFSPACE) {
		needsbuffer &= ~VFS_BIO_NEED_BUFSPACE;
		wakeup(&needsbuffer);
	}
}

/*
 *	bufcountwakeup:
 *
 *	Called when a buffer has been added to one of the free queues to
 *	account for the buffer and to wakeup anyone waiting for free buffers.
 *	This typically occurs when large amounts of metadata are being handled
 *	by the buffer cache ( else buffer space runs out first, usually ).
 */

static __inline void
bufcountwakeup(void) 
{
	++numfreebuffers;
	if (needsbuffer) {
		needsbuffer &= ~VFS_BIO_NEED_ANY;
		if (numfreebuffers >= hifreebuffers)
			needsbuffer &= ~VFS_BIO_NEED_FREE;
		wakeup(&needsbuffer);
	}
}

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

	/* finally, initialize each buffer header and stick on empty q */
	for (i = 0; i < nbuf; i++) {
		bp = &buf[i];
		bzero(bp, sizeof *bp);
		bp->b_flags = B_INVAL;	/* we're just an empty header */
		bp->b_dev = NODEV;
		bp->b_rcred = NOCRED;
		bp->b_wcred = NOCRED;
		bp->b_qindex = QUEUE_EMPTY;
		bp->b_xflags = 0;
		LIST_INIT(&bp->b_dep);
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_EMPTY], bp, b_freelist);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
	}

	/*
	 * maxbufspace is currently calculated to support all filesystem 
	 * blocks to be 8K.  If you happen to use a 16K filesystem, the size
	 * of the buffer cache is still the same as it would be for 8K 
	 * filesystems.  This keeps the size of the buffer cache "in check" 
	 * for big block filesystems.
	 *
	 * maxbufspace is calculated as around 50% of the KVA available in
	 * the buffer_map ( DFLTSIZE vs BKVASIZE ), I presume to reduce the 
	 * effect of fragmentation.
	 */
	maxbufspace = (nbuf + 8) * DFLTBSIZE;
	if ((hibufspace = maxbufspace - MAXBSIZE * 5) <= MAXBSIZE)
		hibufspace = 3 * maxbufspace / 4;
/*
 * reserve 1/3 of the buffers for metadata (VDIR) which might not be VMIO'ed
 */
	maxvmiobufspace = 2 * hibufspace / 3;
/*
 * Limit the amount of malloc memory since it is wired permanently into
 * the kernel space.  Even though this is accounted for in the buffer
 * allocation, we don't want the malloced region to grow uncontrolled.
 * The malloc scheme improves memory utilization significantly on average
 * (small) directories.
 */
	maxbufmallocspace = hibufspace / 20;

/*
 * Reduce the chance of a deadlock occuring by limiting the number
 * of delayed-write dirty buffers we allow to stack up.
 */
	lodirtybuffers = nbuf / 16 + 10;
	hidirtybuffers = nbuf / 8 + 20;
	numdirtybuffers = 0;

/*
 * Try to keep the number of free buffers in the specified range,
 * and give the syncer access to an emergency reserve.
 */
	lofreebuffers = nbuf / 18 + 5;
	hifreebuffers = 2 * lofreebuffers;
	numfreebuffers = nbuf;

	kvafreespace = 0;

	bogus_offset = kmem_alloc_pageable(kernel_map, PAGE_SIZE);
	bogus_page = vm_page_alloc(kernel_object,
			((bogus_offset - VM_MIN_KERNEL_ADDRESS) >> PAGE_SHIFT),
			VM_ALLOC_NORMAL);

}

/*
 * Free the kva allocation for a buffer
 * Must be called only at splbio or higher,
 *  as this is the only locking for buffer_map.
 */
static void
bfreekva(struct buf * bp)
{
	if (bp->b_kvasize) {
		vm_map_delete(buffer_map,
		    (vm_offset_t) bp->b_kvabase,
		    (vm_offset_t) bp->b_kvabase + bp->b_kvasize
		);
		bp->b_kvasize = 0;
		kvaspacewakeup();
	}
}

/*
 *	bremfree:
 *
 *	Remove the buffer from the appropriate free list.
 */
void
bremfree(struct buf * bp)
{
	int s = splbio();
	int old_qindex = bp->b_qindex;

	if (bp->b_qindex != QUEUE_NONE) {
		if (bp->b_qindex == QUEUE_EMPTY) {
			kvafreespace -= bp->b_kvasize;
		}
		TAILQ_REMOVE(&bufqueues[bp->b_qindex], bp, b_freelist);
		bp->b_qindex = QUEUE_NONE;
		runningbufspace += bp->b_bufsize;
	} else {
#if !defined(MAX_PERF)
		panic("bremfree: removing a buffer when not on a queue");
#endif
	}

	/*
	 * Fixup numfreebuffers count.  If the buffer is invalid or not
	 * delayed-write, and it was on the EMPTY, LRU, or AGE queues,
	 * the buffer was free and we must decrement numfreebuffers.
	 */
	if ((bp->b_flags & B_INVAL) || (bp->b_flags & B_DELWRI) == 0) {
		switch(old_qindex) {
		case QUEUE_EMPTY:
		case QUEUE_LRU:
		case QUEUE_AGE:
			--numfreebuffers;
			break;
		default:
			break;
		}
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
		KASSERT(!(bp->b_flags & B_ASYNC), ("bread: illegal async bp %p", bp));
		bp->b_flags |= B_READ;
		bp->b_flags &= ~(B_DONE | B_ERROR | B_INVAL);
		if (bp->b_rcred == NOCRED) {
			if (cred != NOCRED)
				crhold(cred);
			bp->b_rcred = cred;
		}
		vfs_busy_pages(bp, 0);
		VOP_STRATEGY(vp, bp);
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
		VOP_STRATEGY(vp, bp);
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
			VOP_STRATEGY(vp, rabp);
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
	int oldflags, s;
	struct vnode *vp;
	struct mount *mp;

	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return (0);
	}

	oldflags = bp->b_flags;

#if !defined(MAX_PERF)
	if ((bp->b_flags & B_BUSY) == 0)
		panic("bwrite: buffer is not busy???");
#endif
	s = splbio();
	bundirty(bp);

	bp->b_flags &= ~(B_READ | B_DONE | B_ERROR);
	bp->b_flags |= B_WRITEINPROG;

	bp->b_vp->v_numoutput++;
	vfs_busy_pages(bp, 1);
	if (curproc != NULL)
		curproc->p_stats->p_ru.ru_oublock++;
	splx(s);
	VOP_STRATEGY(bp->b_vp, bp);

	/*
	 * Collect statistics on synchronous and asynchronous writes.
	 * Writes to block devices are charged to their associated
	 * filesystem (if any).
	 */
	if ((vp = bp->b_vp) != NULL) {
		if (vp->v_type == VBLK)
			mp = vp->v_specmountpoint;
		else
			mp = vp->v_mount;
		if (mp != NULL)
			if ((oldflags & B_ASYNC) == 0)
				mp->mnt_stat.f_syncwrites++;
			else
				mp->mnt_stat.f_asyncwrites++;
	}

	if ((oldflags & B_ASYNC) == 0) {
		int rtval = biowait(bp);
		brelse(bp);
		return (rtval);
	}

	return (0);
}

/*
 * Delayed write. (Buffer is marked dirty).
 */
void
bdwrite(struct buf * bp)
{
	struct vnode *vp;

#if !defined(MAX_PERF)
	if ((bp->b_flags & B_BUSY) == 0) {
		panic("bdwrite: buffer is not busy");
	}
#endif

	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return;
	}
	bdirty(bp);

	/*
	 * This bmap keeps the system from needing to do the bmap later,
	 * perhaps when the system is attempting to do a sync.  Since it
	 * is likely that the indirect block -- or whatever other datastructure
	 * that the filesystem needs is still in memory now, it is a good
	 * thing to do this.  Note also, that if the pageout daemon is
	 * requesting a sync -- there might not be enough memory to do
	 * the bmap then...  So, this is important to do.
	 */
	if (bp->b_lblkno == bp->b_blkno) {
		VOP_BMAP(bp->b_vp, bp->b_lblkno, NULL, &bp->b_blkno, NULL, NULL);
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
	bqrelse(bp);

	/*
	 * XXX The soft dependency code is not prepared to
	 * have I/O done when a bdwrite is requested. For
	 * now we just let the write be delayed if it is
	 * requested by the soft dependency code.
	 */
	if ((vp = bp->b_vp) &&
	    ((vp->v_type == VBLK && vp->v_specmountpoint &&
		  (vp->v_specmountpoint->mnt_flag & MNT_SOFTDEP)) ||
		 (vp->v_mount && (vp->v_mount->mnt_flag & MNT_SOFTDEP))))
		return;

	if (numdirtybuffers >= hidirtybuffers)
		flushdirtybuffers(0, 0);
}

/*
 *	bdirty:
 *
 *	Turn buffer into delayed write request.  We must clear B_READ and
 *	B_RELBUF, and we must set B_DELWRI.  We reassign the buffer to 
 *	itself to properly update it in the dirty/clean lists.  We mark it
 *	B_DONE to ensure that any asynchronization of the buffer properly
 *	clears B_DONE ( else a panic will occur later ).  Note that B_INVALID 
 *	buffers are not considered dirty even if B_DELWRI is set.	
 *
 *	Since the buffer is not on a queue, we do not update the numfreebuffers
 *	count.
 *
 *	Must be called at splbio().
 *	The buffer must be on QUEUE_NONE.
 */
void
bdirty(bp)
	struct buf *bp;
{
	KASSERT(bp->b_qindex == QUEUE_NONE, ("bdirty: buffer %p still on queue %d", bp, bp->b_qindex));
	bp->b_flags &= ~(B_READ|B_RELBUF);

	if ((bp->b_flags & B_DELWRI) == 0) {
		bp->b_flags |= B_DONE | B_DELWRI;
		reassignbuf(bp, bp->b_vp);
		++numdirtybuffers;
	}
}

/*
 *	bundirty:
 *
 *	Clear B_DELWRI for buffer.
 *
 *	Since the buffer is not on a queue, we do not update the numfreebuffers
 *	count.
 *	
 *	Must be called at splbio().
 *	The buffer must be on QUEUE_NONE.
 */

void
bundirty(bp)
	struct buf *bp;
{
	KASSERT(bp->b_qindex == QUEUE_NONE, ("bundirty: buffer %p still on queue %d", bp, bp->b_qindex));

	if (bp->b_flags & B_DELWRI) {
		bp->b_flags &= ~B_DELWRI;
		reassignbuf(bp, bp->b_vp);
		--numdirtybuffers;
	}
}

/*
 *	bawrite:
 *
 *	Asynchronous write.  Start output on a buffer, but do not wait for
 *	it to complete.  The buffer is released when the output completes.
 */
void
bawrite(struct buf * bp)
{
	bp->b_flags |= B_ASYNC;
	(void) VOP_BWRITE(bp);
}

/*
 *	bowrite:
 *
 *	Ordered write.  Start output on a buffer, and flag it so that the 
 *	device will write it in the order it was queued.  The buffer is 
 *	released when the output completes.
 */
int
bowrite(struct buf * bp)
{
	bp->b_flags |= B_ORDERED | B_ASYNC;
	return (VOP_BWRITE(bp));
}

/*
 *	brelse:
 *
 *	Release a busy buffer and, if requested, free its resources.  The
 *	buffer will be stashed in the appropriate bufqueue[] allowing it
 *	to be accessed later as a cache entity or reused for other purposes.
 */
void
brelse(struct buf * bp)
{
	int s;

	KASSERT(!(bp->b_flags & (B_CLUSTER|B_PAGING)), ("brelse: inappropriate B_PAGING or B_CLUSTER bp %p", bp));

#if 0
	if (bp->b_flags & B_CLUSTER) {
		relpbuf(bp, NULL);
		return;
	}
#endif

	s = splbio();

	if (bp->b_flags & B_LOCKED)
		bp->b_flags &= ~B_ERROR;

	if ((bp->b_flags & (B_READ | B_ERROR)) == B_ERROR) {
		bp->b_flags &= ~B_ERROR;
		bdirty(bp);
	} else if ((bp->b_flags & (B_NOCACHE | B_INVAL | B_ERROR | B_FREEBUF)) ||
	    (bp->b_bufsize <= 0)) {
		bp->b_flags |= B_INVAL;
		if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_deallocate)
			(*bioops.io_deallocate)(bp);
		if (bp->b_flags & B_DELWRI)
			--numdirtybuffers;
		bp->b_flags &= ~(B_DELWRI | B_CACHE | B_FREEBUF);
		if ((bp->b_flags & B_VMIO) == 0) {
			if (bp->b_bufsize)
				allocbuf(bp, 0);
			if (bp->b_vp)
				brelvp(bp);
		}
	}

	/*
	 * We must clear B_RELBUF if B_DELWRI is set.  If vfs_vmio_release() 
	 * is called with B_DELWRI set, the underlying pages may wind up
	 * getting freed causing a previous write (bdwrite()) to get 'lost'
	 * because pages associated with a B_DELWRI bp are marked clean.
	 * 
	 * We still allow the B_INVAL case to call vfs_vmio_release(), even
	 * if B_DELWRI is set.
	 */

	if (bp->b_flags & B_DELWRI)
		bp->b_flags &= ~B_RELBUF;

	/*
	 * VMIO buffer rundown.  It is not very necessary to keep a VMIO buffer
	 * constituted, so the B_INVAL flag is used to *invalidate* the buffer,
	 * but the VM object is kept around.  The B_NOCACHE flag is used to
	 * invalidate the pages in the VM object.
	 *
	 * The b_{validoff,validend,dirtyoff,dirtyend} values are relative 
	 * to b_offset and currently have byte granularity, whereas the
	 * valid flags in the vm_pages have only DEV_BSIZE resolution.
	 * The byte resolution fields are used to avoid unnecessary re-reads
	 * of the buffer but the code really needs to be genericized so
	 * other filesystem modules can take advantage of these fields.
	 *
	 * XXX this seems to cause performance problems.
	 */
	if ((bp->b_flags & B_VMIO)
	    && !(bp->b_vp->v_tag == VT_NFS &&
		 bp->b_vp->v_type != VBLK &&
		 (bp->b_flags & B_DELWRI) != 0)
#ifdef notdef
	    && (bp->b_vp->v_tag != VT_NFS
		|| bp->b_vp->v_type == VBLK
		|| (bp->b_flags & (B_NOCACHE | B_INVAL | B_ERROR))
		|| bp->b_validend == 0
		|| (bp->b_validoff == 0
		    && bp->b_validend == bp->b_bufsize))
#endif
	    ) {

		int i, j, resid;
		vm_page_t m;
		off_t foff;
		vm_pindex_t poff;
		vm_object_t obj;
		struct vnode *vp;

		vp = bp->b_vp;

		/*
		 * Get the base offset and length of the buffer.  Note that 
		 * for block sizes that are less then PAGE_SIZE, the b_data
		 * base of the buffer does not represent exactly b_offset and
		 * neither b_offset nor b_size are necessarily page aligned.
		 * Instead, the starting position of b_offset is:
		 *
		 * 	b_data + (b_offset & PAGE_MASK)
		 *
		 * block sizes less then DEV_BSIZE (usually 512) are not 
		 * supported due to the page granularity bits (m->valid,
		 * m->dirty, etc...). 
		 *
		 * See man buf(9) for more information
		 */

		resid = bp->b_bufsize;
		foff = bp->b_offset;

		for (i = 0; i < bp->b_npages; i++) {
			m = bp->b_pages[i];
			vm_page_flag_clear(m, PG_ZERO);
			if (m == bogus_page) {

				obj = (vm_object_t) vp->v_object;
				poff = OFF_TO_IDX(bp->b_offset);

				for (j = i; j < bp->b_npages; j++) {
					m = bp->b_pages[j];
					if (m == bogus_page) {
						m = vm_page_lookup(obj, poff + j);
#if !defined(MAX_PERF)
						if (!m) {
							panic("brelse: page missing\n");
						}
#endif
						bp->b_pages[j] = m;
					}
				}

				if ((bp->b_flags & B_INVAL) == 0) {
					pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
				}
			}
			if (bp->b_flags & (B_NOCACHE|B_ERROR)) {
				int poffset = foff & PAGE_MASK;
				int presid = resid > (PAGE_SIZE - poffset) ?
					(PAGE_SIZE - poffset) : resid;

				KASSERT(presid >= 0, ("brelse: extra page"));
				vm_page_set_invalid(m, poffset, presid);
			}
			resid -= PAGE_SIZE - (foff & PAGE_MASK);
			foff = (foff + PAGE_SIZE) & ~PAGE_MASK;
		}

		if (bp->b_flags & (B_INVAL | B_RELBUF))
			vfs_vmio_release(bp);

	} else if (bp->b_flags & B_VMIO) {

		if (bp->b_flags & (B_INVAL | B_RELBUF))
			vfs_vmio_release(bp);

	}
			
#if !defined(MAX_PERF)
	if (bp->b_qindex != QUEUE_NONE)
		panic("brelse: free buffer onto another queue???");
#endif
	/* enqueue */

	/* buffers with no memory */
	if (bp->b_bufsize == 0) {
		bp->b_flags |= B_INVAL;
		bp->b_qindex = QUEUE_EMPTY;
		TAILQ_INSERT_HEAD(&bufqueues[QUEUE_EMPTY], bp, b_freelist);
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
		bp->b_dev = NODEV;
		kvafreespace += bp->b_kvasize;
		if (bp->b_kvasize)
			kvaspacewakeup();
	/* buffers with junk contents */
	} else if (bp->b_flags & (B_ERROR | B_INVAL | B_NOCACHE | B_RELBUF)) {
		bp->b_flags |= B_INVAL;
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

	/*
	 * If B_INVAL, clear B_DELWRI.
	 */
	if ((bp->b_flags & (B_INVAL|B_DELWRI)) == (B_INVAL|B_DELWRI)) {
		bp->b_flags &= ~B_DELWRI;
		--numdirtybuffers;
	}

	runningbufspace -= bp->b_bufsize;

	/*
	 * Fixup numfreebuffers count.  The bp is on an appropriate queue
	 * unless locked.  We then bump numfreebuffers if it is not B_DELWRI.
	 * We've already handled the B_INVAL case ( B_DELWRI will be clear
	 * if B_INVAL is set ).
	 */

	if ((bp->b_flags & B_LOCKED) == 0 && !(bp->b_flags & B_DELWRI))
		bufcountwakeup();

	/*
	 * Something we can maybe free.
	 */

	if (bp->b_bufsize)
		bufspacewakeup();

	if (bp->b_flags & B_WANTED) {
		bp->b_flags &= ~(B_WANTED | B_AGE);
		wakeup(bp);
	} 

	/* unlock */
	bp->b_flags &= ~(B_ORDERED | B_WANTED | B_BUSY |
		B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF);
	splx(s);
}

/*
 * Release a buffer back to the appropriate queue but do not try to free
 * it.
 */
void
bqrelse(struct buf * bp)
{
	int s;

	s = splbio();

	KASSERT(!(bp->b_flags & (B_CLUSTER|B_PAGING)), ("bqrelse: inappropriate B_PAGING or B_CLUSTER bp %p", bp));

#if !defined(MAX_PERF)
	if (bp->b_qindex != QUEUE_NONE)
		panic("bqrelse: free buffer onto another queue???");
#endif
	if (bp->b_flags & B_LOCKED) {
		bp->b_flags &= ~B_ERROR;
		bp->b_qindex = QUEUE_LOCKED;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LOCKED], bp, b_freelist);
		/* buffers with stale but valid contents */
	} else {
		bp->b_qindex = QUEUE_LRU;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LRU], bp, b_freelist);
	}

	runningbufspace -= bp->b_bufsize;

	if ((bp->b_flags & B_LOCKED) == 0 &&
	    ((bp->b_flags & B_INVAL) || !(bp->b_flags & B_DELWRI))
	) {
		bufcountwakeup();
	}

	/*
	 * Something we can maybe wakeup
	 */
	if (bp->b_bufsize)
		bufspacewakeup();

	/* anyone need this block? */
	if (bp->b_flags & B_WANTED) {
		bp->b_flags &= ~(B_WANTED | B_AGE);
		wakeup(bp);
	} 

	/* unlock */
	bp->b_flags &= ~(B_ORDERED | B_WANTED | B_BUSY |
		B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF);
	splx(s);
}

static void
vfs_vmio_release(bp)
	struct buf *bp;
{
	int i, s;
	vm_page_t m;

	s = splvm();
	for (i = 0; i < bp->b_npages; i++) {
		m = bp->b_pages[i];
		bp->b_pages[i] = NULL;
		/*
		 * In order to keep page LRU ordering consistent, put
		 * everything on the inactive queue.
		 */
		vm_page_unwire(m, 0);
		/*
		 * We don't mess with busy pages, it is
		 * the responsibility of the process that
		 * busied the pages to deal with them.
		 */
		if ((m->flags & PG_BUSY) || (m->busy != 0))
			continue;
			
		if (m->wire_count == 0) {
			vm_page_flag_clear(m, PG_ZERO);
			/*
			 * Might as well free the page if we can and it has
			 * no valid data.
			 */
			if ((bp->b_flags & B_ASYNC) == 0 && !m->valid && m->hold_count == 0) {
				vm_page_busy(m);
				vm_page_protect(m, VM_PROT_NONE);
				vm_page_free(m);
			}
		}
	}
	bufspace -= bp->b_bufsize;
	vmiospace -= bp->b_bufsize;
	runningbufspace -= bp->b_bufsize;
	splx(s);
	pmap_qremove(trunc_page((vm_offset_t) bp->b_data), bp->b_npages);
	if (bp->b_bufsize)
		bufspacewakeup();
	bp->b_npages = 0;
	bp->b_bufsize = 0;
	bp->b_flags &= ~B_VMIO;
	if (bp->b_vp)
		brelvp(bp);
}

/*
 * Check to see if a block is currently memory resident.
 */
struct buf *
gbincore(struct vnode * vp, daddr_t blkno)
{
	struct buf *bp;
	struct bufhashhdr *bh;

	bh = BUFHASH(vp, blkno);
	bp = bh->lh_first;

	/* Search hash chain */
	while (bp != NULL) {
		/* hit */
		if (bp->b_vp == vp && bp->b_lblkno == blkno &&
		    (bp->b_flags & B_INVAL) == 0) {
			break;
		}
		bp = bp->b_hash.le_next;
	}
	return (bp);
}

/*
 * this routine implements clustered async writes for
 * clearing out B_DELWRI buffers...  This is much better
 * than the old way of writing only one buffer at a time.
 */
int
vfs_bio_awrite(struct buf * bp)
{
	int i;
	daddr_t lblkno = bp->b_lblkno;
	struct vnode *vp = bp->b_vp;
	int s;
	int ncl;
	struct buf *bpa;
	int nwritten;
	int size;
	int maxcl;

	s = splbio();
	/*
	 * right now we support clustered writing only to regular files, and
	 * then only if our I/O system is not saturated.
	 */
	if ((vp->v_type == VREG) && 
	    (vp->v_mount != 0) && /* Only on nodes that have the size info */
	    (bp->b_flags & (B_CLUSTEROK | B_INVAL)) == B_CLUSTEROK) {

		size = vp->v_mount->mnt_stat.f_iosize;
		maxcl = MAXPHYS / size;

		for (i = 1; i < maxcl; i++) {
			if ((bpa = gbincore(vp, lblkno + i)) &&
			    ((bpa->b_flags & (B_BUSY | B_DELWRI | B_CLUSTEROK | B_INVAL)) ==
			    (B_DELWRI | B_CLUSTEROK)) &&
			    (bpa->b_bufsize == size)) {
				if ((bpa->b_blkno == bpa->b_lblkno) ||
				    (bpa->b_blkno != bp->b_blkno + ((i * size) >> DEV_BSHIFT)))
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
			nwritten = cluster_wbuild(vp, size, lblkno, ncl);
			splx(s);
			return nwritten;
		}
	}

	bremfree(bp);
	bp->b_flags |= B_BUSY | B_ASYNC;

	splx(s);
	/*
	 * default (old) behavior, writing out only one block
	 */
	nwritten = bp->b_bufsize;
	(void) VOP_BWRITE(bp);

	return nwritten;
}

/*
 *	getnewbuf:
 *
 *	Find and initialize a new buffer header, freeing up existing buffers 
 *	in the bufqueues as necessary.
 *
 *	We block if:
 *		We have insufficient buffer headers
 *		We have insufficient buffer space
 *		buffer_map is too fragmented ( space reservation fails )
 *
 *	We do *not* attempt to flush dirty buffers more then one level deep.
 *	I.e., if P_FLSINPROG is set we do not flush dirty buffers at all.
 *
 *	If P_FLSINPROG is set, we are allowed to dip into our emergency 
 *	reserve.
 */
static struct buf *
getnewbuf(struct vnode *vp, daddr_t blkno,
	int slpflag, int slptimeo, int size, int maxsize)
{
	struct buf *bp;
	struct buf *nbp;
	int outofspace;
	int nqindex;
	int defrag = 0;
	int countawrites = 0;
	
restart:

	/*
	 * Setup for scan.  If we do not have enough free buffers,
	 * we setup a degenerate case that falls through the while.
	 *
	 * If we are in the middle of a flush, we can dip into the
	 * emergency reserve.
	 */

	if ((curproc->p_flag & P_FLSINPROG) == 0 &&
	    numfreebuffers < lofreebuffers
	) {
		nqindex = QUEUE_LRU;
		nbp = NULL;
	} else {
		nqindex = QUEUE_EMPTY;
		if ((nbp = TAILQ_FIRST(&bufqueues[QUEUE_EMPTY])) == NULL) {
			nqindex = QUEUE_AGE;
			nbp = TAILQ_FIRST(&bufqueues[QUEUE_AGE]);
			if (nbp == NULL) {
				nqindex = QUEUE_LRU;
				nbp = TAILQ_FIRST(&bufqueues[QUEUE_LRU]);
			}
		}
	}

	/*
	 * Calculate whether we are out of buffer space.  This state is
	 * recalculated on every restart.  If we are out of space, we
	 * have to turn off defragmentation.  The outofspace code will
	 * defragment too, but the looping conditionals will be messed up
	 * if both outofspace and defrag are on.
	 */

	outofspace = 0;
	if (bufspace >= hibufspace) {
		if ((curproc->p_flag & P_FLSINPROG) == 0 ||
		    bufspace >= maxbufspace
		) {
			outofspace = 1;
			defrag = 0;
		}
	}

	/*
	 * defrag state is semi-persistant.  1 means we are flagged for
	 * defragging.  -1 means we actually defragged something.
	 */
	/* nop */

	/*
	 * Run scan, possibly freeing data and/or kva mappings on the fly
	 * depending.
	 */

	while ((bp = nbp) != NULL) {
		int qindex = nqindex;
		/*
		 * Calculate next bp ( we can only use it if we do not block
		 * or do other fancy things ).
		 */
		if ((nbp = TAILQ_NEXT(bp, b_freelist)) == NULL) {
			switch(qindex) {
			case QUEUE_EMPTY:
				nqindex = QUEUE_AGE;
				if ((nbp = TAILQ_FIRST(&bufqueues[QUEUE_AGE])))
					break;
				/* fall through */
			case QUEUE_AGE:
				nqindex = QUEUE_LRU;
				if ((nbp = TAILQ_FIRST(&bufqueues[QUEUE_LRU])))
					break;
				/* fall through */
			case QUEUE_LRU:
				/*
				 * nbp is NULL. 
				 */
				break;
			}
		}

		/*
		 * Sanity Checks
		 */
		KASSERT(!(bp->b_flags & B_BUSY), ("getnewbuf: busy buffer %p on free list", bp));
		KASSERT(bp->b_qindex == qindex, ("getnewbuf: inconsistant queue %d bp %p", qindex, bp));

		/*
		 * Here we try to move NON VMIO buffers to the end of the 
		 * LRU queue in order to make VMIO buffers more readily 
		 * freeable.  We also try to move buffers with a positive
		 * usecount to the end.
		 *
		 * Note that by moving the bp to the end, we setup a following
		 * loop.  Since we continue to decrement b_usecount this
		 * is ok and, in fact, desireable.
		 *
		 * If we are at the end of the list, we move ourself to the
		 * same place and need to fixup nbp and nqindex to handle
		 * the following case.
		 */

		if ((qindex == QUEUE_LRU) && bp->b_usecount > 0) {
			if ((bp->b_flags & B_VMIO) == 0 ||
			    (vmiospace < maxvmiobufspace)
			) {
				--bp->b_usecount;
				TAILQ_REMOVE(&bufqueues[QUEUE_LRU], bp, b_freelist);
				TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LRU], bp, b_freelist);
				if (nbp == NULL) {
					nqindex = qindex;
					nbp = bp;
				}
				continue;
			}
		}

		/*
		 * If we come across a delayed write and numdirtybuffers should
		 * be flushed, try to write it out.  Only if P_FLSINPROG is
		 * not set.  We can't afford to recursively stack more then
		 * one deep due to the possibility of having deep VFS call
		 * stacks.
		 *
		 * Limit the number of dirty buffers we are willing to try
		 * to recover since it really isn't our job here.
		 */
		if ((bp->b_flags & (B_DELWRI | B_INVAL)) == B_DELWRI) {
			if ((curproc->p_flag & P_FLSINPROG) || 
			    numdirtybuffers < hidirtybuffers ||
			    countawrites > 16
			) {
				continue;
			}
			curproc->p_flag |= P_FLSINPROG;
			vfs_bio_awrite(bp);
			curproc->p_flag &= ~P_FLSINPROG;
			++countawrites;
			goto restart;
		}

		if (defrag > 0 && bp->b_kvasize == 0)
			continue;
		if (outofspace > 0 && bp->b_bufsize == 0)
			continue;

		/*
		 * Start freeing the bp.  This is somewhat involved.  nbp
		 * remains valid only for QUEUE_EMPTY bp's.
		 */

		bremfree(bp);
		bp->b_flags |= B_BUSY;

		if (qindex == QUEUE_LRU || qindex == QUEUE_AGE) {
			if (bp->b_flags & B_VMIO) {
				bp->b_flags &= ~B_ASYNC;
				vfs_vmio_release(bp);
			}
			if (bp->b_vp)
				brelvp(bp);
		}

		if (bp->b_flags & B_WANTED) {
			bp->b_flags &= ~B_WANTED;
			wakeup(bp);
		}

		/*
		 * NOTE:  nbp is now entirely invalid.  We can only restart
		 * the scan from this point on.
		 *
		 * Get the rest of the buffer freed up.  b_kva* is still
		 * valid after this operation.
		 */

		if (bp->b_rcred != NOCRED) {
			crfree(bp->b_rcred);
			bp->b_rcred = NOCRED;
		}
		if (bp->b_wcred != NOCRED) {
			crfree(bp->b_wcred);
			bp->b_wcred = NOCRED;
		}
		if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_deallocate)
			(*bioops.io_deallocate)(bp);

		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);

		if (bp->b_bufsize)
			allocbuf(bp, 0);

		bp->b_flags = B_BUSY;
		bp->b_dev = NODEV;
		bp->b_vp = NULL;
		bp->b_blkno = bp->b_lblkno = 0;
		bp->b_offset = NOOFFSET;
		bp->b_iodone = 0;
		bp->b_error = 0;
		bp->b_resid = 0;
		bp->b_bcount = 0;
		bp->b_npages = 0;
		bp->b_dirtyoff = bp->b_dirtyend = 0;
		bp->b_validoff = bp->b_validend = 0;
		bp->b_usecount = 5;

		LIST_INIT(&bp->b_dep);

		/*
		 * Ok, now that we have a free buffer, if we are defragging
		 * we have to recover the kvaspace.
		 */

		if (defrag > 0) {
			defrag = -1;
			bp->b_flags |= B_INVAL;
			bfreekva(bp);
			brelse(bp);
			goto restart;
		}

		if (outofspace > 0) {
			outofspace = -1;
			bp->b_flags |= B_INVAL;
			bfreekva(bp);
			brelse(bp);
			goto restart;
		}

		/*
		 * We are done
		 */
		break;
	}

	/*
	 * If we exhausted our list, sleep as appropriate.
	 */

	if (bp == NULL) {
		int flags;

dosleep:
		if (defrag > 0)
			flags = VFS_BIO_NEED_KVASPACE;
		else if (outofspace > 0)
			flags = VFS_BIO_NEED_BUFSPACE;
		else
			flags = VFS_BIO_NEED_ANY;

		if (rushjob < syncdelay / 2)
			++rushjob;
		needsbuffer |= flags;
		while (needsbuffer & flags) {
			tsleep(
			    &needsbuffer, 
			    (PRIBIO + 4) | slpflag, 
			    "newbuf",
			    slptimeo
			);
		}
	} else {
		/*
		 * We finally have a valid bp.  We aren't quite out of the
		 * woods, we still have to reserve kva space.
		 */
		vm_offset_t addr = 0;

		maxsize = (maxsize + PAGE_MASK) & ~PAGE_MASK;

		if (maxsize != bp->b_kvasize) {
			bfreekva(bp);

			if (vm_map_findspace(buffer_map,
				vm_map_min(buffer_map), maxsize, &addr)
			) {
				/*
				 * Uh oh.  Buffer map is to fragmented.  Try
				 * to defragment.
				 */
				if (defrag <= 0) {
					defrag = 1;
					bp->b_flags |= B_INVAL;
					brelse(bp);
					goto restart;
				}
				/*
				 * Uh oh.  We couldn't seem to defragment
				 */
				bp = NULL;
				goto dosleep;
			}
		}
		if (addr) {
			vm_map_insert(buffer_map, NULL, 0,
				addr, addr + maxsize,
				VM_PROT_ALL, VM_PROT_ALL, MAP_NOFAULT);

			bp->b_kvabase = (caddr_t) addr;
			bp->b_kvasize = maxsize;
			bp->b_data = bp->b_kvabase;
		}
	}
	
	return (bp);
}

/*
 *	waitfreebuffers:
 *
 *	Wait for sufficient free buffers.  This routine is not called if
 *	curproc is the update process so we do not have to do anything 
 *	fancy.
 */

static void
waitfreebuffers(int slpflag, int slptimeo) 
{
	while (numfreebuffers < hifreebuffers) {
		flushdirtybuffers(slpflag, slptimeo);
		if (numfreebuffers < hifreebuffers)
			break;
		needsbuffer |= VFS_BIO_NEED_FREE;
		if (tsleep(&needsbuffer, (PRIBIO + 4)|slpflag, "biofre", slptimeo))
			break;
	}
}

/*
 *	flushdirtybuffers:
 *
 *	This routine is called when we get too many dirty buffers.  
 *
 *	We have to protect ourselves from recursion, but we also do not want
 *	other process's flushdirtybuffers() to interfere with the syncer if
 *	it decides to flushdirtybuffers().
 *
 *	In order to maximize operations, we allow any process to flush
 *	dirty buffers and use P_FLSINPROG to prevent recursion.  
 */

static void
flushdirtybuffers(int slpflag, int slptimeo) 
{
	int s;

	s = splbio();

	if (curproc->p_flag & P_FLSINPROG) {
		splx(s);
		return;
	}
	curproc->p_flag |= P_FLSINPROG;

	while (numdirtybuffers > lodirtybuffers) {
		if (flushbufqueues() == 0)
			break;
	}

	curproc->p_flag &= ~P_FLSINPROG;

	splx(s);
}

static int
flushbufqueues(void)
{
	struct buf *bp;
	int qindex;
	int r = 0;

	qindex = QUEUE_AGE;
	bp = TAILQ_FIRST(&bufqueues[QUEUE_AGE]);

	for (;;) {
		if (bp == NULL) {
			if (qindex == QUEUE_LRU)
				break;
			qindex = QUEUE_LRU;
			if ((bp = TAILQ_FIRST(&bufqueues[QUEUE_LRU])) == NULL)
				break;
		}

		/*
		 * XXX NFS does weird things with B_INVAL bps if we bwrite
		 * them ( vfs_bio_awrite/bawrite/bdwrite/etc )  Why?
		 *
		 */
		if ((bp->b_flags & B_DELWRI) != 0) {
			if (bp->b_flags & B_INVAL) {
				bremfree(bp);
				bp->b_flags |= B_BUSY;
				brelse(bp);
			} else {
				vfs_bio_awrite(bp);
			}
			++r;
			break;
		}
		bp = TAILQ_NEXT(bp, b_freelist);
	}
	return(r);
}

/*
 * Check to see if a block is currently memory resident.
 */
struct buf *
incore(struct vnode * vp, daddr_t blkno)
{
	struct buf *bp;

	int s = splbio();
	bp = gbincore(vp, blkno);
	splx(s);
	return (bp);
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
	vm_offset_t toff, tinc, size;
	vm_page_t m;
	vm_ooffset_t off;

	if (incore(vp, blkno))
		return 1;
	if (vp->v_mount == NULL)
		return 0;
	if ((vp->v_object == NULL) || (vp->v_flag & VOBJBUF) == 0)
		return 0;

	obj = vp->v_object;
	size = PAGE_SIZE;
	if (size > vp->v_mount->mnt_stat.f_iosize)
		size = vp->v_mount->mnt_stat.f_iosize;
	off = (vm_ooffset_t)blkno * (vm_ooffset_t)vp->v_mount->mnt_stat.f_iosize;

	for (toff = 0; toff < vp->v_mount->mnt_stat.f_iosize; toff += tinc) {
		m = vm_page_lookup(obj, OFF_TO_IDX(off + toff));
		if (!m)
			return 0;
		tinc = size;
		if (tinc > PAGE_SIZE - ((toff + off) & PAGE_MASK))
			tinc = PAGE_SIZE - ((toff + off) & PAGE_MASK);
		if (vm_page_is_valid(m,
		    (vm_offset_t) ((toff + off) & PAGE_MASK), tinc) == 0)
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
vfs_setdirty(struct buf *bp) 
{
	int i;
	vm_object_t object;
	vm_offset_t boffset;

	/*
	 * We qualify the scan for modified pages on whether the
	 * object has been flushed yet.  The OBJ_WRITEABLE flag
	 * is not cleared simply by protecting pages off.
	 */

	if ((bp->b_flags & B_VMIO) == 0)
		return;

	object = bp->b_pages[0]->object;

	if ((object->flags & OBJ_WRITEABLE) && !(object->flags & OBJ_MIGHTBEDIRTY))
		printf("Warning: object %p writeable but not mightbedirty\n", object);
	if (!(object->flags & OBJ_WRITEABLE) && (object->flags & OBJ_MIGHTBEDIRTY))
		printf("Warning: object %p mightbedirty but not writeable\n", object);

	if (object->flags & (OBJ_MIGHTBEDIRTY|OBJ_CLEANING)) {
		/*
		 * test the pages to see if they have been modified directly
		 * by users through the VM system.
		 */
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_flag_clear(bp->b_pages[i], PG_ZERO);
			vm_page_test_dirty(bp->b_pages[i]);
		}

		/*
		 * scan forwards for the first page modified
		 */
		for (i = 0; i < bp->b_npages; i++) {
			if (bp->b_pages[i]->dirty) {
				break;
			}
		}

		boffset = (i << PAGE_SHIFT) - (bp->b_offset & PAGE_MASK);
		if (boffset < bp->b_dirtyoff) {
			bp->b_dirtyoff = max(boffset, 0);
		}

		/*
		 * scan backwards for the last page modified
		 */
		for (i = bp->b_npages - 1; i >= 0; --i) {
			if (bp->b_pages[i]->dirty) {
				break;
			}
		}
		boffset = (i + 1);
#if 0
		offset = boffset + bp->b_pages[0]->pindex;
		if (offset >= object->size)
			boffset = object->size - bp->b_pages[0]->pindex;
#endif
		boffset = (boffset << PAGE_SHIFT) - (bp->b_offset & PAGE_MASK);
		if (bp->b_dirtyend < boffset)
			bp->b_dirtyend = min(boffset, bp->b_bufsize);
	}
}

/*
 * Get a block given a specified block and offset into a file/device.
 */
struct buf *
getblk(struct vnode * vp, daddr_t blkno, int size, int slpflag, int slptimeo)
{
	struct buf *bp;
	int i, s;
	struct bufhashhdr *bh;

#if !defined(MAX_PERF)
	if (size > MAXBSIZE)
		panic("getblk: size(%d) > MAXBSIZE(%d)\n", size, MAXBSIZE);
#endif

	s = splbio();
loop:
	/*
	 * Block if we are low on buffers.  The syncer is allowed more
	 * buffers in order to avoid a deadlock.
	 */
	if (curproc == updateproc && numfreebuffers == 0) {
		needsbuffer |= VFS_BIO_NEED_ANY;
		tsleep(&needsbuffer, (PRIBIO + 4) | slpflag, "newbuf",
		    slptimeo);
	} else if (curproc != updateproc && numfreebuffers < lofreebuffers) {
		waitfreebuffers(slpflag, slptimeo);
	}

	if ((bp = gbincore(vp, blkno))) {
		if (bp->b_flags & B_BUSY) {
			bp->b_flags |= B_WANTED;
			if (bp->b_usecount < BUF_MAXUSE)
				++bp->b_usecount;

			if (!tsleep(bp,
				(PRIBIO + 4) | slpflag, "getblk", slptimeo)) {
				goto loop;
			}

			splx(s);
			return (struct buf *) NULL;
		}
		bp->b_flags |= B_BUSY | B_CACHE;
		bremfree(bp);

		/*
		 * check for size inconsistancies for non-VMIO case.
		 */

		if (bp->b_bcount != size) {
			if ((bp->b_flags & B_VMIO) == 0 ||
			    (size > bp->b_kvasize)
			) {
				if (bp->b_flags & B_DELWRI) {
					bp->b_flags |= B_NOCACHE;
					VOP_BWRITE(bp);
				} else {
					if ((bp->b_flags & B_VMIO) &&
					   (LIST_FIRST(&bp->b_dep) == NULL)) {
						bp->b_flags |= B_RELBUF;
						brelse(bp);
					} else {
						bp->b_flags |= B_NOCACHE;
						VOP_BWRITE(bp);
					}
				}
				goto loop;
			}
		}

		/*
		 * If the size is inconsistant in the VMIO case, we can resize
		 * the buffer.  This might lead to B_CACHE getting cleared.
		 */

		if (bp->b_bcount != size)
			allocbuf(bp, size);

		KASSERT(bp->b_offset != NOOFFSET, 
		    ("getblk: no buffer offset"));

		/*
		 * Check that the constituted buffer really deserves for the
		 * B_CACHE bit to be set.  B_VMIO type buffers might not
		 * contain fully valid pages.  Normal (old-style) buffers
		 * should be fully valid.  This might also lead to B_CACHE
		 * getting clear.
		 *
		 * If B_CACHE is already clear, don't bother checking to see 
		 * if we have to clear it again.
		 *
		 * XXX this code should not be necessary unless the B_CACHE
		 * handling is broken elsewhere in the kernel.  We need to
		 * check the cases and then turn the clearing part of this
		 * code into a panic.
		 */
		if (
		    (bp->b_flags & (B_VMIO|B_CACHE)) == (B_VMIO|B_CACHE) &&
		    (bp->b_vp->v_tag != VT_NFS || bp->b_validend <= 0)
		) {
			int checksize = bp->b_bufsize;
			int poffset = bp->b_offset & PAGE_MASK;
			int resid;
			for (i = 0; i < bp->b_npages; i++) {
				resid = (checksize > (PAGE_SIZE - poffset)) ?
					(PAGE_SIZE - poffset) : checksize;
				if (!vm_page_is_valid(bp->b_pages[i], poffset, resid)) {
					bp->b_flags &= ~(B_CACHE | B_DONE);
					break;
				}
				checksize -= resid;
				poffset = 0;
			}
		}

		/*
		 * If B_DELWRI is set and B_CACHE got cleared ( or was
		 * already clear ), we have to commit the write and
		 * retry.  The NFS code absolutely depends on this,
		 * and so might the FFS code.  In anycase, it formalizes
		 * the B_CACHE rules.  See sys/buf.h.
		 */

		if ((bp->b_flags & (B_CACHE|B_DELWRI)) == B_DELWRI) {
			VOP_BWRITE(bp);
			goto loop;
		}

		if (bp->b_usecount < BUF_MAXUSE)
			++bp->b_usecount;
		splx(s);
		return (bp);
	} else {
		int bsize, maxsize, vmio;
		off_t offset;

		if (vp->v_type == VBLK)
			bsize = DEV_BSIZE;
		else if (vp->v_mountedhere)
			bsize = vp->v_mountedhere->mnt_stat.f_iosize;
		else if (vp->v_mount)
			bsize = vp->v_mount->mnt_stat.f_iosize;
		else
			bsize = size;

		offset = (off_t)blkno * bsize;
		vmio = (vp->v_object != 0) && (vp->v_flag & VOBJBUF);
		maxsize = vmio ? size + (offset & PAGE_MASK) : size;
		maxsize = imax(maxsize, bsize);

		if ((bp = getnewbuf(vp, blkno,
			slpflag, slptimeo, size, maxsize)) == 0) {
			if (slpflag || slptimeo) {
				splx(s);
				return NULL;
			}
			goto loop;
		}

		/*
		 * This code is used to make sure that a buffer is not
		 * created while the getnewbuf routine is blocked.
		 * This can be a problem whether the vnode is locked or not.
		 */
		if (gbincore(vp, blkno)) {
			bp->b_flags |= B_INVAL;
			brelse(bp);
			goto loop;
		}

		/*
		 * Insert the buffer into the hash, so that it can
		 * be found by incore.
		 */
		bp->b_blkno = bp->b_lblkno = blkno;
		bp->b_offset = offset;

		bgetvp(vp, bp);
		LIST_REMOVE(bp, b_hash);
		bh = BUFHASH(vp, blkno);
		LIST_INSERT_HEAD(bh, bp, b_hash);

		if (vmio) {
			bp->b_flags |= (B_VMIO | B_CACHE);
#if defined(VFS_BIO_DEBUG)
			if (vp->v_type != VREG && vp->v_type != VBLK)
				printf("getblk: vmioing file type %d???\n", vp->v_type);
#endif
		} else {
			bp->b_flags &= ~B_VMIO;
		}

		allocbuf(bp, size);

		splx(s);
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
	int s;

	s = splbio();
	while ((bp = getnewbuf(0, (daddr_t) 0, 0, 0, size, MAXBSIZE)) == 0);
	splx(s);
	allocbuf(bp, size);
	bp->b_flags |= B_INVAL; /* b_dep cleared by getnewbuf() */
	return (bp);
}


/*
 * This code constitutes the buffer memory from either anonymous system
 * memory (in the case of non-VMIO operations) or from an associated
 * VM object (in the case of VMIO operations).  This code is able to
 * resize a buffer up or down.
 *
 * Note that this code is tricky, and has many complications to resolve
 * deadlock or inconsistant data situations.  Tread lightly!!! 
 * There are B_CACHE and B_DELWRI interactions that must be dealt with by 
 * the caller.  Calling this code willy nilly can result in the loss of data.
 */

int
allocbuf(struct buf *bp, int size)
{
	int newbsize, mbsize;
	int i;

#if !defined(MAX_PERF)
	if (!(bp->b_flags & B_BUSY))
		panic("allocbuf: buffer not busy");

	if (bp->b_kvasize < size)
		panic("allocbuf: buffer too small");
#endif

	if ((bp->b_flags & B_VMIO) == 0) {
		caddr_t origbuf;
		int origbufsize;
		/*
		 * Just get anonymous memory from the kernel
		 */
		mbsize = (size + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
#if !defined(NO_B_MALLOC)
		if (bp->b_flags & B_MALLOC)
			newbsize = mbsize;
		else
#endif
			newbsize = round_page(size);

		if (newbsize < bp->b_bufsize) {
#if !defined(NO_B_MALLOC)
			/*
			 * malloced buffers are not shrunk
			 */
			if (bp->b_flags & B_MALLOC) {
				if (newbsize) {
					bp->b_bcount = size;
				} else {
					free(bp->b_data, M_BIOBUF);
					bufspace -= bp->b_bufsize;
					bufmallocspace -= bp->b_bufsize;
					runningbufspace -= bp->b_bufsize;
					if (bp->b_bufsize)
						bufspacewakeup();
					bp->b_data = bp->b_kvabase;
					bp->b_bufsize = 0;
					bp->b_bcount = 0;
					bp->b_flags &= ~B_MALLOC;
				}
				return 1;
			}		
#endif
			vm_hold_free_pages(
			    bp,
			    (vm_offset_t) bp->b_data + newbsize,
			    (vm_offset_t) bp->b_data + bp->b_bufsize);
		} else if (newbsize > bp->b_bufsize) {
#if !defined(NO_B_MALLOC)
			/*
			 * We only use malloced memory on the first allocation.
			 * and revert to page-allocated memory when the buffer grows.
			 */
			if ( (bufmallocspace < maxbufmallocspace) &&
				(bp->b_bufsize == 0) &&
				(mbsize <= PAGE_SIZE/2)) {

				bp->b_data = malloc(mbsize, M_BIOBUF, M_WAITOK);
				bp->b_bufsize = mbsize;
				bp->b_bcount = size;
				bp->b_flags |= B_MALLOC;
				bufspace += mbsize;
				bufmallocspace += mbsize;
				runningbufspace += bp->b_bufsize;
				return 1;
			}
#endif
			origbuf = NULL;
			origbufsize = 0;
#if !defined(NO_B_MALLOC)
			/*
			 * If the buffer is growing on its other-than-first allocation,
			 * then we revert to the page-allocation scheme.
			 */
			if (bp->b_flags & B_MALLOC) {
				origbuf = bp->b_data;
				origbufsize = bp->b_bufsize;
				bp->b_data = bp->b_kvabase;
				bufspace -= bp->b_bufsize;
				bufmallocspace -= bp->b_bufsize;
				runningbufspace -= bp->b_bufsize;
				if (bp->b_bufsize)
					bufspacewakeup();
				bp->b_bufsize = 0;
				bp->b_flags &= ~B_MALLOC;
				newbsize = round_page(newbsize);
			}
#endif
			vm_hold_load_pages(
			    bp,
			    (vm_offset_t) bp->b_data + bp->b_bufsize,
			    (vm_offset_t) bp->b_data + newbsize);
#if !defined(NO_B_MALLOC)
			if (origbuf) {
				bcopy(origbuf, bp->b_data, origbufsize);
				free(origbuf, M_BIOBUF);
			}
#endif
		}
	} else {
		vm_page_t m;
		int desiredpages;

		newbsize = (size + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
		desiredpages = (size == 0) ? 0 :
			num_pages((bp->b_offset & PAGE_MASK) + newbsize);

#if !defined(NO_B_MALLOC)
		if (bp->b_flags & B_MALLOC)
			panic("allocbuf: VMIO buffer can't be malloced");
#endif

		if (newbsize < bp->b_bufsize) {
			if (desiredpages < bp->b_npages) {
				for (i = desiredpages; i < bp->b_npages; i++) {
					/*
					 * the page is not freed here -- it
					 * is the responsibility of vnode_pager_setsize
					 */
					m = bp->b_pages[i];
					KASSERT(m != bogus_page,
					    ("allocbuf: bogus page found"));
					while (vm_page_sleep_busy(m, TRUE, "biodep"))
						;

					bp->b_pages[i] = NULL;
					vm_page_unwire(m, 0);
				}
				pmap_qremove((vm_offset_t) trunc_page((vm_offset_t)bp->b_data) +
				    (desiredpages << PAGE_SHIFT), (bp->b_npages - desiredpages));
				bp->b_npages = desiredpages;
			}
		} else if (newbsize > bp->b_bufsize) {
			vm_object_t obj;
			vm_offset_t tinc, toff;
			vm_ooffset_t off;
			vm_pindex_t objoff;
			int pageindex, curbpnpages;
			struct vnode *vp;
			int bsize;
			int orig_validoff = bp->b_validoff;
			int orig_validend = bp->b_validend;

			vp = bp->b_vp;

			if (vp->v_type == VBLK)
				bsize = DEV_BSIZE;
			else
				bsize = vp->v_mount->mnt_stat.f_iosize;

			if (bp->b_npages < desiredpages) {
				obj = vp->v_object;
				tinc = PAGE_SIZE;

				off = bp->b_offset;
				KASSERT(bp->b_offset != NOOFFSET,
				    ("allocbuf: no buffer offset"));
				curbpnpages = bp->b_npages;
		doretry:
				bp->b_validoff = orig_validoff;
				bp->b_validend = orig_validend;
				bp->b_flags |= B_CACHE;
				for (toff = 0; toff < newbsize; toff += tinc) {
					objoff = OFF_TO_IDX(off + toff);
					pageindex = objoff - OFF_TO_IDX(off);
					tinc = PAGE_SIZE - ((off + toff) & PAGE_MASK);
					if (pageindex < curbpnpages) {

						m = bp->b_pages[pageindex];
#ifdef VFS_BIO_DIAG
						if (m->pindex != objoff)
							panic("allocbuf: page changed offset?!!!?");
#endif
						if (tinc > (newbsize - toff))
							tinc = newbsize - toff;
						if (bp->b_flags & B_CACHE)
							vfs_buf_set_valid(bp, off, toff, tinc, m);
						continue;
					}
					m = vm_page_lookup(obj, objoff);
					if (!m) {
						m = vm_page_alloc(obj, objoff, VM_ALLOC_NORMAL);
						if (!m) {
							VM_WAIT;
							vm_pageout_deficit += (desiredpages - curbpnpages);
							goto doretry;
						}

						vm_page_wire(m);
						vm_page_wakeup(m);
						bp->b_flags &= ~B_CACHE;

					} else if (vm_page_sleep_busy(m, FALSE, "pgtblk")) {
						/*
						 *  If we had to sleep, retry.
						 *
						 *  Also note that we only test
						 *  PG_BUSY here, not m->busy.
						 *  
						 *  We cannot sleep on m->busy
						 *  here because a vm_fault ->
						 *  getpages -> cluster-read ->
						 *  ...-> allocbuf sequence 
						 *  will convert PG_BUSY to
						 *  m->busy so we have to let 
						 *  m->busy through if we do 
						 *  not want to deadlock.
						 */
						goto doretry;
					} else {
						if ((curproc != pageproc) &&
							((m->queue - m->pc) == PQ_CACHE) &&
						    ((cnt.v_free_count + cnt.v_cache_count) <
								(cnt.v_free_min + cnt.v_cache_min))) {
							pagedaemon_wakeup();
						}
						if (tinc > (newbsize - toff))
							tinc = newbsize - toff;
						if (bp->b_flags & B_CACHE)
							vfs_buf_set_valid(bp, off, toff, tinc, m);
						vm_page_flag_clear(m, PG_ZERO);
						vm_page_wire(m);
					}
					bp->b_pages[pageindex] = m;
					curbpnpages = pageindex + 1;
				}
				if (vp->v_tag == VT_NFS && 
				    vp->v_type != VBLK) {
					if (bp->b_dirtyend > 0) {
						bp->b_validoff = min(bp->b_validoff, bp->b_dirtyoff);
						bp->b_validend = max(bp->b_validend, bp->b_dirtyend);
					}
					if (bp->b_validend == 0)
						bp->b_flags &= ~B_CACHE;
				}
				bp->b_data = (caddr_t) trunc_page((vm_offset_t)bp->b_data);
				bp->b_npages = curbpnpages;
				pmap_qenter((vm_offset_t) bp->b_data,
					bp->b_pages, bp->b_npages);
				((vm_offset_t) bp->b_data) |= off & PAGE_MASK;
			}
		}
	}
	if (bp->b_flags & B_VMIO)
		vmiospace += (newbsize - bp->b_bufsize);
	bufspace += (newbsize - bp->b_bufsize);
	runningbufspace += (newbsize - bp->b_bufsize);
	if (newbsize < bp->b_bufsize)
		bufspacewakeup();
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
#if defined(NO_SCHEDULE_MODS)
		tsleep(bp, PRIBIO, "biowait", 0);
#else
		if (bp->b_flags & B_READ)
			tsleep(bp, PRIBIO, "biord", 0);
		else
			tsleep(bp, PRIBIO, "biowr", 0);
#endif
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

	KASSERT((bp->b_flags & B_BUSY), ("biodone: bp %p not busy", bp));
	KASSERT(!(bp->b_flags & B_DONE), ("biodone: bp %p already done", bp));

	bp->b_flags |= B_DONE;

	if (bp->b_flags & B_FREEBUF) {
		brelse(bp);
		splx(s);
		return;
	}

	if ((bp->b_flags & B_READ) == 0) {
		vwakeup(bp);
	}

	/* call optional completion function if requested */
	if (bp->b_flags & B_CALL) {
		bp->b_flags &= ~B_CALL;
		(*bp->b_iodone) (bp);
		splx(s);
		return;
	}
	if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_complete)
		(*bioops.io_complete)(bp);

	if (bp->b_flags & B_VMIO) {
		int i, resid;
		vm_ooffset_t foff;
		vm_page_t m;
		vm_object_t obj;
		int iosize;
		struct vnode *vp = bp->b_vp;

		obj = vp->v_object;

#if defined(VFS_BIO_DEBUG)
		if (vp->v_usecount == 0) {
			panic("biodone: zero vnode ref count");
		}

		if (vp->v_object == NULL) {
			panic("biodone: missing VM object");
		}

		if ((vp->v_flag & VOBJBUF) == 0) {
			panic("biodone: vnode is not setup for merged cache");
		}
#endif

		foff = bp->b_offset;
		KASSERT(bp->b_offset != NOOFFSET,
		    ("biodone: no buffer offset"));

#if !defined(MAX_PERF)
		if (!obj) {
			panic("biodone: no object");
		}
#endif
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
				m = vm_page_lookup(obj, OFF_TO_IDX(foff));
				if (!m) {
#if defined(VFS_BIO_DEBUG)
					printf("biodone: page disappeared\n");
#endif
					vm_object_pip_subtract(obj, 1);
					continue;
				}
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
			}
#if defined(VFS_BIO_DEBUG)
			if (OFF_TO_IDX(foff) != m->pindex) {
				printf(
"biodone: foff(%lu)/m->pindex(%d) mismatch\n",
				    (unsigned long)foff, m->pindex);
			}
#endif
			resid = IDX_TO_OFF(m->pindex + 1) - foff;
			if (resid > iosize)
				resid = iosize;

			/*
			 * In the write case, the valid and clean bits are
			 * already changed correctly, so we only need to do this
			 * here in the read case.
			 */
			if ((bp->b_flags & B_READ) && !bogusflag && resid > 0) {
				vfs_page_set_valid(bp, foff, i, m);
			}
			vm_page_flag_clear(m, PG_ZERO);

			/*
			 * when debugging new filesystems or buffer I/O methods, this
			 * is the most common error that pops up.  if you see this, you
			 * have not set the page busy flag correctly!!!
			 */
			if (m->busy == 0) {
#if !defined(MAX_PERF)
				printf("biodone: page busy < 0, "
				    "pindex: %d, foff: 0x(%x,%x), "
				    "resid: %d, index: %d\n",
				    (int) m->pindex, (int)(foff >> 32),
						(int) foff & 0xffffffff, resid, i);
#endif
				if (vp->v_type != VBLK)
#if !defined(MAX_PERF)
					printf(" iosize: %ld, lblkno: %d, flags: 0x%lx, npages: %d\n",
					    bp->b_vp->v_mount->mnt_stat.f_iosize,
					    (int) bp->b_lblkno,
					    bp->b_flags, bp->b_npages);
				else
					printf(" VDEV, lblkno: %d, flags: 0x%lx, npages: %d\n",
					    (int) bp->b_lblkno,
					    bp->b_flags, bp->b_npages);
				printf(" valid: 0x%x, dirty: 0x%x, wired: %d\n",
				    m->valid, m->dirty, m->wire_count);
#endif
				panic("biodone: page busy < 0\n");
			}
			vm_page_io_finish(m);
			vm_object_pip_subtract(obj, 1);
			foff += resid;
			iosize -= resid;
		}
		if (obj)
			vm_object_pip_wakeupn(obj, 0);
	}
	/*
	 * For asynchronous completions, release the buffer now. The brelse
	 * checks for B_WANTED and will do the wakeup there if necessary - so
	 * no need to do a wakeup here in the async case.
	 */

	if (bp->b_flags & B_ASYNC) {
		if ((bp->b_flags & (B_NOCACHE | B_INVAL | B_ERROR | B_RELBUF)) != 0)
			brelse(bp);
		else
			bqrelse(bp);
	} else {
		bp->b_flags &= ~B_WANTED;
		wakeup(bp);
	}
	splx(s);
}

#if 0	/* not with kirks code */
static int vfs_update_interval = 30;

static void
vfs_update()
{
	while (1) {
		tsleep(&vfs_update_wakeup, PUSER, "update",
		    hz * vfs_update_interval);
		vfs_update_wakeup = 0;
		sync(curproc, NULL);
	}
}

static int
sysctl_kern_updateinterval SYSCTL_HANDLER_ARGS
{
	int error = sysctl_handle_int(oidp,
		oidp->oid_arg1, oidp->oid_arg2, req);
	if (!error)
		wakeup(&vfs_update_wakeup);
	return error;
}

SYSCTL_PROC(_kern, KERN_UPDATEINTERVAL, update, CTLTYPE_INT|CTLFLAG_RW,
	&vfs_update_interval, 0, sysctl_kern_updateinterval, "I", "");

#endif


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

		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];

			if (m == bogus_page) {
				m = vm_page_lookup(obj, OFF_TO_IDX(bp->b_offset) + i);
#if !defined(MAX_PERF)
				if (!m) {
					panic("vfs_unbusy_pages: page missing\n");
				}
#endif
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
			}
			vm_object_pip_subtract(obj, 1);
			vm_page_flag_clear(m, PG_ZERO);
			vm_page_io_finish(m);
		}
		vm_object_pip_wakeupn(obj, 0);
	}
}

/*
 * Set NFS' b_validoff and b_validend fields from the valid bits
 * of a page.  If the consumer is not NFS, and the page is not
 * valid for the entire range, clear the B_CACHE flag to force
 * the consumer to re-read the page.
 *
 * B_CACHE interaction is especially tricky.
 */
static void
vfs_buf_set_valid(struct buf *bp,
		  vm_ooffset_t foff, vm_offset_t off, vm_offset_t size,
		  vm_page_t m)
{
	if (bp->b_vp->v_tag == VT_NFS && bp->b_vp->v_type != VBLK) {
		vm_offset_t svalid, evalid;
		int validbits = m->valid >> (((foff+off)&PAGE_MASK)/DEV_BSIZE);

		/*
		 * This only bothers with the first valid range in the
		 * page.
		 */
		svalid = off;
		while (validbits && !(validbits & 1)) {
			svalid += DEV_BSIZE;
			validbits >>= 1;
		}
		evalid = svalid;
		while (validbits & 1) {
			evalid += DEV_BSIZE;
			validbits >>= 1;
		}
		evalid = min(evalid, off + size);
		/*
		 * We can only set b_validoff/end if this range is contiguous
		 * with the range built up already.  If we cannot set
		 * b_validoff/end, we must clear B_CACHE to force an update
		 * to clean the bp up.
		 */
		if (svalid == bp->b_validend) {
			bp->b_validoff = min(bp->b_validoff, svalid);
			bp->b_validend = max(bp->b_validend, evalid);
		} else {
			bp->b_flags &= ~B_CACHE;
		}
	} else if (!vm_page_is_valid(m,
				     (vm_offset_t) ((foff + off) & PAGE_MASK),
				     size)) {
		bp->b_flags &= ~B_CACHE;
	}
}

/*
 * Set the valid bits in a page, taking care of the b_validoff,
 * b_validend fields which NFS uses to optimise small reads.  Off is
 * the offset within the file and pageno is the page index within the buf.
 *
 * XXX we have to set the valid & clean bits for all page fragments 
 * touched by b_validoff/validend, even if the page fragment goes somewhat
 * beyond b_validoff/validend due to alignment.
 */
static void
vfs_page_set_valid(struct buf *bp, vm_ooffset_t off, int pageno, vm_page_t m)
{
	struct vnode *vp = bp->b_vp;
	vm_ooffset_t soff, eoff;

	soff = off;
	eoff = (off + PAGE_SIZE) & ~PAGE_MASK;
	if (eoff > bp->b_offset + bp->b_bufsize)
		eoff = bp->b_offset + bp->b_bufsize;
	if (vp->v_tag == VT_NFS && vp->v_type != VBLK) {
		vm_ooffset_t sv, ev;
		vm_page_set_invalid(m,
		    (vm_offset_t) (soff & PAGE_MASK),
		    (vm_offset_t) (eoff - soff));
		sv = (bp->b_offset + bp->b_validoff + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
		ev = (bp->b_offset + bp->b_validend + (DEV_BSIZE - 1)) & 
		    ~(DEV_BSIZE - 1);
		soff = qmax(sv, soff);
		eoff = qmin(ev, eoff);
	}
	if (eoff > soff)
		vm_page_set_validclean(m,
	       (vm_offset_t) (soff & PAGE_MASK),
	       (vm_offset_t) (eoff - soff));
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
	int i, bogus;

	if (bp->b_flags & B_VMIO) {
		struct vnode *vp = bp->b_vp;
		vm_object_t obj = vp->v_object;
		vm_ooffset_t foff;

		foff = bp->b_offset;
		KASSERT(bp->b_offset != NOOFFSET,
		    ("vfs_busy_pages: no buffer offset"));
		vfs_setdirty(bp);

retry:
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];
			if (vm_page_sleep_busy(m, FALSE, "vbpage"))
				goto retry;
		}

		bogus = 0;
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];

			vm_page_flag_clear(m, PG_ZERO);
			if ((bp->b_flags & B_CLUSTER) == 0) {
				vm_object_pip_add(obj, 1);
				vm_page_io_start(m);
			}

			vm_page_protect(m, VM_PROT_NONE);
			if (clear_modify)
				vfs_page_set_valid(bp, foff, i, m);
			else if (m->valid == VM_PAGE_BITS_ALL &&
				(bp->b_flags & B_CACHE) == 0) {
				bp->b_pages[i] = bogus_page;
				bogus++;
			}
			foff = (foff + PAGE_SIZE) & ~PAGE_MASK;
		}
		if (bogus)
			pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
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
		vm_ooffset_t foff;
		foff = bp->b_offset;
		KASSERT(bp->b_offset != NOOFFSET,
		    ("vfs_clean_pages: no buffer offset"));
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];
			vfs_page_set_valid(bp, foff, i, m);
			foff = (foff + PAGE_SIZE) & ~PAGE_MASK;
		}
	}
}

void
vfs_bio_clrbuf(struct buf *bp) {
	int i, mask = 0;
	caddr_t sa, ea;
	if ((bp->b_flags & (B_VMIO | B_MALLOC)) == B_VMIO) {
		if( (bp->b_npages == 1) && (bp->b_bufsize < PAGE_SIZE) &&
		    (bp->b_offset & PAGE_MASK) == 0) {
			mask = (1 << (bp->b_bufsize / DEV_BSIZE)) - 1;
			if (((bp->b_pages[0]->flags & PG_ZERO) == 0) &&
			    ((bp->b_pages[0]->valid & mask) != mask)) {
				bzero(bp->b_data, bp->b_bufsize);
			}
			bp->b_pages[0]->valid |= mask;
			bp->b_resid = 0;
			return;
		}
		ea = sa = bp->b_data;
		for(i=0;i<bp->b_npages;i++,sa=ea) {
			int j = ((u_long)sa & PAGE_MASK) / DEV_BSIZE;
			ea = (caddr_t)trunc_page((vm_offset_t)sa + PAGE_SIZE);
			ea = (caddr_t)ulmin((u_long)ea,
				(u_long)bp->b_data + bp->b_bufsize);
			mask = ((1 << ((ea - sa) / DEV_BSIZE)) - 1) << j;
			if ((bp->b_pages[i]->valid & mask) == mask)
				continue;
			if ((bp->b_pages[i]->valid & mask) == 0) {
				if ((bp->b_pages[i]->flags & PG_ZERO) == 0) {
					bzero(sa, ea - sa);
				}
			} else {
				for (; sa < ea; sa += DEV_BSIZE, j++) {
					if (((bp->b_pages[i]->flags & PG_ZERO) == 0) &&
						(bp->b_pages[i]->valid & (1<<j)) == 0)
						bzero(sa, DEV_BSIZE);
				}
			}
			bp->b_pages[i]->valid |= mask;
			vm_page_flag_clear(bp->b_pages[i], PG_ZERO);
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
vm_hold_load_pages(struct buf * bp, vm_offset_t from, vm_offset_t to)
{
	vm_offset_t pg;
	vm_page_t p;
	int index;

	to = round_page(to);
	from = round_page(from);
	index = (from - trunc_page((vm_offset_t)bp->b_data)) >> PAGE_SHIFT;

	for (pg = from; pg < to; pg += PAGE_SIZE, index++) {

tryagain:

		p = vm_page_alloc(kernel_object,
			((pg - VM_MIN_KERNEL_ADDRESS) >> PAGE_SHIFT),
		    VM_ALLOC_NORMAL);
		if (!p) {
			vm_pageout_deficit += (to - from) >> PAGE_SHIFT;
			VM_WAIT;
			goto tryagain;
		}
		vm_page_wire(p);
		p->valid = VM_PAGE_BITS_ALL;
		vm_page_flag_clear(p, PG_ZERO);
		pmap_kenter(pg, VM_PAGE_TO_PHYS(p));
		bp->b_pages[index] = p;
		vm_page_wakeup(p);
	}
	bp->b_npages = index;
}

void
vm_hold_free_pages(struct buf * bp, vm_offset_t from, vm_offset_t to)
{
	vm_offset_t pg;
	vm_page_t p;
	int index, newnpages;

	from = round_page(from);
	to = round_page(to);
	newnpages = index = (from - trunc_page((vm_offset_t)bp->b_data)) >> PAGE_SHIFT;

	for (pg = from; pg < to; pg += PAGE_SIZE, index++) {
		p = bp->b_pages[index];
		if (p && (index < bp->b_npages)) {
#if !defined(MAX_PERF)
			if (p->busy) {
				printf("vm_hold_free_pages: blkno: %d, lblkno: %d\n",
					bp->b_blkno, bp->b_lblkno);
			}
#endif
			bp->b_pages[index] = NULL;
			pmap_kremove(pg);
			vm_page_busy(p);
			vm_page_unwire(p, 0);
			vm_page_free(p);
		}
	}
	bp->b_npages = newnpages;
}


#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>

DB_SHOW_COMMAND(buffer, db_show_buffer)
{
	/* get args */
	struct buf *bp = (struct buf *)addr;

	if (!have_addr) {
		db_printf("usage: show buffer <addr>\n");
		return;
	}

	db_printf("b_proc = %p,\nb_flags = 0x%b\n", (void *)bp->b_proc,
		  (u_int)bp->b_flags, PRINT_BUF_FLAGS);
	db_printf("b_error = %d, b_bufsize = %ld, b_bcount = %ld, "
		  "b_resid = %ld\nb_dev = 0x%x, b_data = %p, "
		  "b_blkno = %d, b_pblkno = %d\n",
		  bp->b_error, bp->b_bufsize, bp->b_bcount, bp->b_resid,
		  bp->b_dev, bp->b_data, bp->b_blkno, bp->b_pblkno);
	if (bp->b_npages) {
		int i;
		db_printf("b_npages = %d, pages(OBJ, IDX, PA): ", bp->b_npages);
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m;
			m = bp->b_pages[i];
			db_printf("(%p, 0x%lx, 0x%lx)", (void *)m->object,
			    (u_long)m->pindex, (u_long)VM_PAGE_TO_PHYS(m));
			if ((i + 1) < bp->b_npages)
				db_printf(",");
		}
		db_printf("\n");
	}
}
#endif /* DDB */
