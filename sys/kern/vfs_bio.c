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
 * $FreeBSD$
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/resourcevar.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>

static MALLOC_DEFINE(M_BIOBUF, "BIO buffer", "BIO buffer");

struct	bio_ops bioops;		/* I/O operation notification */

struct buf *buf;		/* buffer header pool */
struct swqueue bswlist;

static void vm_hold_free_pages(struct buf * bp, vm_offset_t from,
		vm_offset_t to);
static void vm_hold_load_pages(struct buf * bp, vm_offset_t from,
		vm_offset_t to);
static void vfs_page_set_valid(struct buf *bp, vm_ooffset_t off,
			       int pageno, vm_page_t m);
static void vfs_clean_pages(struct buf * bp);
static void vfs_setdirty(struct buf *bp);
static void vfs_vmio_release(struct buf *bp);
static void vfs_backgroundwritedone(struct buf *bp);
static int flushbufqueues(void);

static int bd_request;

static void buf_daemon __P((void));
/*
 * bogus page -- for I/O to/from partially complete buffers
 * this is a temporary solution to the problem, but it is not
 * really that bad.  it would be better to split the buffer
 * for input in the case of buffers partially already in memory,
 * but the code is intricate enough already.
 */
vm_page_t bogus_page;
int runningbufspace;
int vmiodirenable = FALSE;
int buf_maxio = DFLTPHYS;
static vm_offset_t bogus_offset;

static int bufspace, maxbufspace, vmiospace, 
	bufmallocspace, maxbufmallocspace, hibufspace;
static int maxbdrun;
static int needsbuffer;
static int numdirtybuffers, hidirtybuffers;
static int numfreebuffers, lofreebuffers, hifreebuffers;
static int getnewbufcalls;
static int getnewbufrestarts;
static int kvafreespace;

SYSCTL_INT(_vfs, OID_AUTO, numdirtybuffers, CTLFLAG_RD,
	&numdirtybuffers, 0, "");
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
SYSCTL_INT(_vfs, OID_AUTO, maxbdrun, CTLFLAG_RW,
	&maxbdrun, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, vmiospace, CTLFLAG_RD,
	&vmiospace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, maxmallocbufspace, CTLFLAG_RW,
	&maxbufmallocspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, bufmallocspace, CTLFLAG_RD,
	&bufmallocspace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, kvafreespace, CTLFLAG_RD,
	&kvafreespace, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, getnewbufcalls, CTLFLAG_RW,
	&getnewbufcalls, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, getnewbufrestarts, CTLFLAG_RW,
	&getnewbufrestarts, 0, "");
SYSCTL_INT(_vfs, OID_AUTO, vmiodirenable, CTLFLAG_RW,
	&vmiodirenable, 0, "");


static int bufhashmask;
static LIST_HEAD(bufhashhdr, buf) *bufhashtbl, invalhash;
struct bqueues bufqueues[BUFFER_QUEUES] = { { 0 } };
char *buf_wmesg = BUF_WMESG;

extern int vm_swap_size;

#define BUF_MAXUSE		24

#define VFS_BIO_NEED_ANY	0x01	/* any freeable buffer */
#define VFS_BIO_NEED_DIRTYFLUSH	0x02	/* waiting for dirty buffer flush */
#define VFS_BIO_NEED_FREE	0x04	/* wait for free bufs, hi hysteresis */
#define VFS_BIO_NEED_BUFSPACE	0x08	/* wait for buf space, lo hysteresis */
#define VFS_BIO_NEED_KVASPACE	0x10	/* wait for buffer_map space, emerg  */

/*
 * Buffer hash table code.  Note that the logical block scans linearly, which
 * gives us some L1 cache locality.
 */

static __inline 
struct bufhashhdr *
bufhash(struct vnode *vnp, daddr_t bn)
{
	return(&bufhashtbl[(((uintptr_t)(vnp) >> 7) + (int)bn) & bufhashmask]);
}

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
 *	numdirtywakeup:
 *
 *	If someone is blocked due to there being too many dirty buffers,
 *	and numdirtybuffers is now reasonable, wake them up.
 */

static __inline void
numdirtywakeup(void)
{
	if (numdirtybuffers < hidirtybuffers) {
		if (needsbuffer & VFS_BIO_NEED_DIRTYFLUSH) {
			needsbuffer &= ~VFS_BIO_NEED_DIRTYFLUSH;
			wakeup(&needsbuffer);
		}
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
 *	vfs_buf_test_cache:
 *
 *	Called when a buffer is extended.  This function clears the B_CACHE
 *	bit if the newly extended portion of the buffer does not contain
 *	valid data.
 */
static __inline__
void
vfs_buf_test_cache(struct buf *bp,
		  vm_ooffset_t foff, vm_offset_t off, vm_offset_t size,
		  vm_page_t m)
{
	if (bp->b_flags & B_CACHE) {
		int base = (foff + off) & PAGE_MASK;
		if (vm_page_is_valid(m, base, size) == 0)
			bp->b_flags &= ~B_CACHE;
	}
}

static __inline__
void
bd_wakeup(int dirtybuflevel)
{
	if (numdirtybuffers >= dirtybuflevel && bd_request == 0) {
		bd_request = 1;
		wakeup(&bd_request);
	}
}

/*
 * bd_speedup - speedup the buffer cache flushing code
 */

static __inline__
void
bd_speedup(void)
{
	bd_wakeup(1);
}

/*
 * Initialize buffer headers and related structures. 
 */

caddr_t
bufhashinit(caddr_t vaddr)
{
	/* first, make a null hash table */
	for (bufhashmask = 8; bufhashmask < nbuf / 4; bufhashmask <<= 1)
		;
	bufhashtbl = (void *)vaddr;
	vaddr = vaddr + sizeof(*bufhashtbl) * bufhashmask;
	--bufhashmask;
	return(vaddr);
}

void
bufinit(void)
{
	struct buf *bp;
	int i;

	TAILQ_INIT(&bswlist);
	LIST_INIT(&invalhash);
	simple_lock_init(&buftimelock);

	for (i = 0; i <= bufhashmask; i++)
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
		BUF_LOCKINIT(bp);
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_EMPTY], bp, b_freelist);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
	}

	/*
	 * maxbufspace is currently calculated to be maximally efficient
	 * when the filesystem block size is DFLTBSIZE or DFLTBSIZE*2
	 * (4K or 8K).  To reduce the number of stall points our calculation
	 * is based on DFLTBSIZE which should reduce the chances of actually
	 * running out of buffer headers.  The maxbufspace calculation is also
	 * based on DFLTBSIZE (4K) instead of BKVASIZE (8K) in order to
	 * reduce the chance that a KVA allocation will fail due to
	 * fragmentation.  While this does not usually create a stall,
	 * the KVA map allocation/free functions are O(N) rather then O(1)
	 * so running them constantly would result in inefficient O(N*M)
	 * buffer cache operation.
	 */
	maxbufspace = (nbuf + 8) * DFLTBSIZE;
	hibufspace = imax(3 * maxbufspace / 4, maxbufspace - MAXBSIZE * 10);
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
	hidirtybuffers = nbuf / 4 + 20;
	numdirtybuffers = 0;
/*
 * To support extreme low-memory systems, make sure hidirtybuffers cannot
 * eat up all available buffer space.  This occurs when our minimum cannot
 * be met.  We try to size hidirtybuffers to 3/4 our buffer space assuming
 * BKVASIZE'd (8K) buffers.  We also reduce buf_maxio in this case (used
 * by the clustering code) in an attempt to further reduce the load on
 * the buffer cache.
 */
	while (hidirtybuffers * BKVASIZE > 3 * hibufspace / 4) {
		hidirtybuffers >>= 1;
		buf_maxio >>= 1;
	}

	/*
	 * Temporary, BKVASIZE may be manipulated soon, make sure we don't
	 * do something illegal. XXX
	 */
#if BKVASIZE < MAXBSIZE
	if (buf_maxio < BKVASIZE * 2)
		buf_maxio = BKVASIZE * 2;
#else
	if (buf_maxio < MAXBSIZE)
		buf_maxio = MAXBSIZE;
#endif

/*
 * Try to keep the number of free buffers in the specified range,
 * and give the syncer access to an emergency reserve.
 */
	lofreebuffers = nbuf / 18 + 5;
	hifreebuffers = 2 * lofreebuffers;
	numfreebuffers = nbuf;

/*
 * Maximum number of async ops initiated per buf_daemon loop.  This is
 * somewhat of a hack at the moment, we really need to limit ourselves
 * based on the number of bytes of I/O in-transit that were initiated
 * from buf_daemon.
 */
	if ((maxbdrun = nswbuf / 4) < 4)
		maxbdrun = 4;

	kvafreespace = 0;

	bogus_offset = kmem_alloc_pageable(kernel_map, PAGE_SIZE);
	bogus_page = vm_page_alloc(kernel_object,
			((bogus_offset - VM_MIN_KERNEL_ADDRESS) >> PAGE_SHIFT),
			VM_ALLOC_NORMAL);
	cnt.v_wire_count++;

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
		if (bp->b_qindex == QUEUE_EMPTYKVA) {
			kvafreespace -= bp->b_kvasize;
		}
		KASSERT(BUF_REFCNT(bp) == 1, ("bremfree: bp %p not locked",bp));
		TAILQ_REMOVE(&bufqueues[bp->b_qindex], bp, b_freelist);
		bp->b_qindex = QUEUE_NONE;
		runningbufspace += bp->b_bufsize;
	} else {
#if !defined(MAX_PERF)
		if (BUF_REFCNT(bp) <= 1)
			panic("bremfree: removing a buffer not on a queue");
#endif
	}

	/*
	 * Fixup numfreebuffers count.  If the buffer is invalid or not
	 * delayed-write, and it was on the EMPTY, LRU, or AGE queues,
	 * the buffer was free and we must decrement numfreebuffers.
	 */
	if ((bp->b_flags & B_INVAL) || (bp->b_flags & B_DELWRI) == 0) {
		switch(old_qindex) {
		case QUEUE_DIRTY:
		case QUEUE_CLEAN:
		case QUEUE_EMPTY:
		case QUEUE_EMPTYKVA:
			--numfreebuffers;
			break;
		default:
			break;
		}
	}
	splx(s);
}


/*
 * Get a buffer with the specified data.  Look in the cache first.  We
 * must clear B_ERROR and B_INVAL prior to initiating I/O.  If B_CACHE
 * is set, the buffer is valid and we do not have to do anything ( see
 * getblk() ).
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
		bp->b_flags &= ~(B_ERROR | B_INVAL);
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
 * read-ahead blocks.  We must clear B_ERROR and B_INVAL prior
 * to initiating I/O . If B_CACHE is set, the buffer is valid 
 * and we do not have to do anything.
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
		bp->b_flags &= ~(B_ERROR | B_INVAL);
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
			rabp->b_flags &= ~(B_ERROR | B_INVAL);
			if (rabp->b_rcred == NOCRED) {
				if (cred != NOCRED)
					crhold(cred);
				rabp->b_rcred = cred;
			}
			vfs_busy_pages(rabp, 0);
			BUF_KERNPROC(rabp);
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
 * if async).  Do not bother writing anything if the buffer
 * is invalid.
 *
 * Note that we set B_CACHE here, indicating that buffer is
 * fully valid and thus cacheable.  This is true even of NFS
 * now so we set it generally.  This could be set either here 
 * or in biodone() since the I/O is synchronous.  We put it
 * here.
 */
int
bwrite(struct buf * bp)
{
	int oldflags, s;
	struct buf *newbp;

	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return (0);
	}

	oldflags = bp->b_flags;

#if !defined(MAX_PERF)
	if (BUF_REFCNT(bp) == 0)
		panic("bwrite: buffer is not busy???");
#endif
	s = splbio();
	/*
	 * If a background write is already in progress, delay
	 * writing this block if it is asynchronous. Otherwise
	 * wait for the background write to complete.
	 */
	if (bp->b_xflags & BX_BKGRDINPROG) {
		if (bp->b_flags & B_ASYNC) {
			splx(s);
			bdwrite(bp);
			return (0);
		}
		bp->b_xflags |= BX_BKGRDWAIT;
		tsleep(&bp->b_xflags, PRIBIO, "biord", 0);
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("bwrite: still writing");
	}

	/* Mark the buffer clean */
	bundirty(bp);

	/*
	 * If this buffer is marked for background writing and we
	 * do not have to wait for it, make a copy and write the
	 * copy so as to leave this buffer ready for further use.
	 */
	if ((bp->b_xflags & BX_BKGRDWRITE) && (bp->b_flags & B_ASYNC)) {
		if (bp->b_flags & B_CALL)
			panic("bwrite: need chained iodone");

		/* get a new block */
		newbp = geteblk(bp->b_bufsize);

		/* set it to be identical to the old block */
		memcpy(newbp->b_data, bp->b_data, bp->b_bufsize);
		bgetvp(bp->b_vp, newbp);
		newbp->b_lblkno = bp->b_lblkno;
		newbp->b_blkno = bp->b_blkno;
		newbp->b_offset = bp->b_offset;
		newbp->b_iodone = vfs_backgroundwritedone;
		newbp->b_flags |= B_ASYNC | B_CALL;
		newbp->b_flags &= ~B_INVAL;

		/* move over the dependencies */
		if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_movedeps)
			(*bioops.io_movedeps)(bp, newbp);

		/*
		 * Initiate write on the copy, release the original to
		 * the B_LOCKED queue so that it cannot go away until
		 * the background write completes. If not locked it could go
		 * away and then be reconstituted while it was being written.
		 * If the reconstituted buffer were written, we could end up
		 * with two background copies being written at the same time.
		 */
		bp->b_xflags |= BX_BKGRDINPROG;
		bp->b_flags |= B_LOCKED;
		bqrelse(bp);
		bp = newbp;
	}

	bp->b_flags &= ~(B_READ | B_DONE | B_ERROR);
	bp->b_flags |= B_WRITEINPROG | B_CACHE;

	bp->b_vp->v_numoutput++;
	vfs_busy_pages(bp, 1);
	if (curproc != NULL)
		curproc->p_stats->p_ru.ru_oublock++;
	splx(s);
	if (oldflags & B_ASYNC)
		BUF_KERNPROC(bp);
	VOP_STRATEGY(bp->b_vp, bp);

	if ((oldflags & B_ASYNC) == 0) {
		int rtval = biowait(bp);
		brelse(bp);
		return (rtval);
	}

	return (0);
}

/*
 * Complete a background write started from bwrite.
 */
static void
vfs_backgroundwritedone(bp)
	struct buf *bp;
{
	struct buf *origbp;

	/*
	 * Find the original buffer that we are writing.
	 */
	if ((origbp = gbincore(bp->b_vp, bp->b_lblkno)) == NULL)
		panic("backgroundwritedone: lost buffer");
	/*
	 * Process dependencies then return any unfinished ones.
	 */
	if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_complete)
		(*bioops.io_complete)(bp);
	if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_movedeps)
		(*bioops.io_movedeps)(bp, origbp);
	/*
	 * Clear the BX_BKGRDINPROG flag in the original buffer
	 * and awaken it if it is waiting for the write to complete.
	 */
	origbp->b_xflags &= ~BX_BKGRDINPROG;
	if (origbp->b_xflags & BX_BKGRDWAIT) {
		origbp->b_xflags &= ~BX_BKGRDWAIT;
		wakeup(&origbp->b_xflags);
	}
	/*
	 * Clear the B_LOCKED flag and remove it from the locked
	 * queue if it currently resides there.
	 */
	origbp->b_flags &= ~B_LOCKED;
	if (BUF_LOCK(origbp, LK_EXCLUSIVE | LK_NOWAIT) == 0) {
		bremfree(origbp);
		bqrelse(origbp);
	}
	/*
	 * This buffer is marked B_NOCACHE, so when it is released
	 * by biodone, it will be tossed. We mark it with B_READ
	 * to avoid biodone doing a second vwakeup.
	 */
	bp->b_flags |= B_NOCACHE | B_READ;
	bp->b_flags &= ~(B_CACHE | B_CALL | B_DONE);
	bp->b_iodone = 0;
	biodone(bp);
}

/*
 * Delayed write. (Buffer is marked dirty).  Do not bother writing
 * anything if the buffer is marked invalid.
 *
 * Note that since the buffer must be completely valid, we can safely
 * set B_CACHE.  In fact, we have to set B_CACHE here rather then in
 * biodone() in order to prevent getblk from writing the buffer
 * out synchronously.
 */
void
bdwrite(struct buf * bp)
{
#if !defined(MAX_PERF)
	if (BUF_REFCNT(bp) == 0)
		panic("bdwrite: buffer is not busy");
#endif

	if (bp->b_flags & B_INVAL) {
		brelse(bp);
		return;
	}
	bdirty(bp);

	/*
	 * Set B_CACHE, indicating that the buffer is fully valid.  This is
	 * true even of NFS now.
	 */
	bp->b_flags |= B_CACHE;

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
	 * Wakeup the buffer flushing daemon if we have saturated the
	 * buffer cache.
	 */

	bd_wakeup(hidirtybuffers);

	/*
	 * note: we cannot initiate I/O from a bdwrite even if we wanted to,
	 * due to the softdep code.
	 */
}

/*
 *	bdirty:
 *
 *	Turn buffer into delayed write request.  We must clear B_READ and
 *	B_RELBUF, and we must set B_DELWRI.  We reassign the buffer to 
 *	itself to properly update it in the dirty/clean lists.  We mark it
 *	B_DONE to ensure that any asynchronization of the buffer properly
 *	clears B_DONE ( else a panic will occur later ).  
 *
 *	bdirty() is kinda like bdwrite() - we have to clear B_INVAL which
 *	might have been set pre-getblk().  Unlike bwrite/bdwrite, bdirty()
 *	should only be called if the buffer is known-good.
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
		bd_wakeup(hidirtybuffers);
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
		numdirtywakeup();
	}
	/*
	 * Since it is now being written, we can clear its deferred write flag.
	 */
	bp->b_flags &= ~B_DEFERRED;
}

/*
 *	bawrite:
 *
 *	Asynchronous write.  Start output on a buffer, but do not wait for
 *	it to complete.  The buffer is released when the output completes.
 *
 *	bwrite() ( or the VOP routine anyway ) is responsible for handling 
 *	B_INVAL buffers.  Not us.
 */
void
bawrite(struct buf * bp)
{
	bp->b_flags |= B_ASYNC;
	(void) VOP_BWRITE(bp->b_vp, bp);
}

/*
 *	bowrite:
 *
 *	Ordered write.  Start output on a buffer, and flag it so that the 
 *	device will write it in the order it was queued.  The buffer is 
 *	released when the output completes.  bwrite() ( or the VOP routine
 *	anyway ) is responsible for handling B_INVAL buffers.
 */
int
bowrite(struct buf * bp)
{
	bp->b_flags |= B_ORDERED | B_ASYNC;
	return (VOP_BWRITE(bp->b_vp, bp));
}

/*
 *	bwillwrite:
 *
 *	Called prior to the locking of any vnodes when we are expecting to
 *	write.  We do not want to starve the buffer cache with too many
 *	dirty buffers so we block here.  By blocking prior to the locking
 *	of any vnodes we attempt to avoid the situation where a locked vnode
 *	prevents the various system daemons from flushing related buffers.
 */

void
bwillwrite(void)
{
	int slop = hidirtybuffers / 10;

	if (numdirtybuffers > hidirtybuffers + slop) {
		int s;

		s = splbio();
		while (numdirtybuffers > hidirtybuffers) {
			bd_wakeup(hidirtybuffers);
			needsbuffer |= VFS_BIO_NEED_DIRTYFLUSH;
			tsleep(&needsbuffer, (PRIBIO + 4), "flswai", 0);
		}
		splx(s);
	}
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
	int kvawakeup = 0;

	KASSERT(!(bp->b_flags & (B_CLUSTER|B_PAGING)), ("brelse: inappropriate B_PAGING or B_CLUSTER bp %p", bp));

	s = splbio();

	if (bp->b_flags & B_LOCKED)
		bp->b_flags &= ~B_ERROR;

	if ((bp->b_flags & (B_READ | B_ERROR | B_INVAL)) == B_ERROR) {
		/*
		 * Failed write, redirty.  Must clear B_ERROR to prevent
		 * pages from being scrapped.  If B_INVAL is set then
		 * this case is not run and the next case is run to 
		 * destroy the buffer.  B_INVAL can occur if the buffer
		 * is outside the range supported by the underlying device.
		 */
		bp->b_flags &= ~B_ERROR;
		bdirty(bp);
	} else if ((bp->b_flags & (B_NOCACHE | B_INVAL | B_ERROR | B_FREEBUF)) ||
	    (bp->b_bufsize <= 0)) {
		/*
		 * Either a failed I/O or we were asked to free or not
		 * cache the buffer.
		 */
		bp->b_flags |= B_INVAL;
		if (LIST_FIRST(&bp->b_dep) != NULL && bioops.io_deallocate)
			(*bioops.io_deallocate)(bp);
		if (bp->b_flags & B_DELWRI) {
			--numdirtybuffers;
			numdirtywakeup();
		}
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
	 * constituted, not even NFS buffers now.  Two flags effect this.  If
	 * B_INVAL, the struct buf is invalidated but the VM object is kept
	 * around ( i.e. so it is trivial to reconstitute the buffer later ).
	 *
	 * If B_ERROR or B_NOCACHE is set, pages in the VM object will be
	 * invalidated.  B_ERROR cannot be set for a failed write unless the
	 * buffer is also B_INVAL because it hits the re-dirtying code above.
	 *
	 * Normally we can do this whether a buffer is B_DELWRI or not.  If
	 * the buffer is an NFS buffer, it is tracking piecemeal writes or
	 * the commit state and we cannot afford to lose the buffer. If the
	 * buffer has a background write in progress, we need to keep it
	 * around to prevent it from being reconstituted and starting a second
	 * background write.
	 */
	if ((bp->b_flags & B_VMIO)
	    && !(bp->b_vp->v_tag == VT_NFS &&
		 !vn_isdisk(bp->b_vp, NULL) &&
		 (bp->b_flags & B_DELWRI) &&
		 (bp->b_xflags & BX_BKGRDINPROG))
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
	if (BUF_REFCNT(bp) > 1) {
		/* Temporary panic to verify exclusive locking */
		/* This panic goes away when we allow shared refs */
		panic("brelse: multiple refs");
		/* do not release to free list */
		BUF_UNLOCK(bp);
		splx(s);
		return;
	}

	/* enqueue */

	/* buffers with no memory */
	if (bp->b_bufsize == 0) {
		bp->b_flags |= B_INVAL;
		bp->b_xflags &= ~BX_BKGRDWRITE;
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("losing buffer 1");
		if (bp->b_kvasize) {
			bp->b_qindex = QUEUE_EMPTYKVA;
			kvawakeup = 1;
		} else {
			bp->b_qindex = QUEUE_EMPTY;
		}
		TAILQ_INSERT_HEAD(&bufqueues[bp->b_qindex], bp, b_freelist);
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
		bp->b_dev = NODEV;
		kvafreespace += bp->b_kvasize;
	/* buffers with junk contents */
	} else if (bp->b_flags & (B_ERROR | B_INVAL | B_NOCACHE | B_RELBUF)) {
		bp->b_flags |= B_INVAL;
		bp->b_xflags &= ~BX_BKGRDWRITE;
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("losing buffer 2");
		bp->b_qindex = QUEUE_CLEAN;
		if (bp->b_kvasize)
			kvawakeup = 1;
		TAILQ_INSERT_HEAD(&bufqueues[QUEUE_CLEAN], bp, b_freelist);
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
		bp->b_dev = NODEV;

	/* buffers that are locked */
	} else if (bp->b_flags & B_LOCKED) {
		bp->b_qindex = QUEUE_LOCKED;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LOCKED], bp, b_freelist);

	/* remaining buffers */
	} else {
		switch(bp->b_flags & (B_DELWRI|B_AGE)) {
		case B_DELWRI | B_AGE:
		    bp->b_qindex = QUEUE_DIRTY;
		    TAILQ_INSERT_HEAD(&bufqueues[QUEUE_DIRTY], bp, b_freelist);
		    break;
		case B_DELWRI:
		    bp->b_qindex = QUEUE_DIRTY;
		    TAILQ_INSERT_TAIL(&bufqueues[QUEUE_DIRTY], bp, b_freelist);
		    break;
		case B_AGE:
		    bp->b_qindex = QUEUE_CLEAN;
		    TAILQ_INSERT_HEAD(&bufqueues[QUEUE_CLEAN], bp, b_freelist);
		    if (bp->b_kvasize)
			    kvawakeup = 1;
		    break;
		default:
		    bp->b_qindex = QUEUE_CLEAN;
		    TAILQ_INSERT_TAIL(&bufqueues[QUEUE_CLEAN], bp, b_freelist);
		    if (bp->b_kvasize)
			    kvawakeup = 1;
		    break;
		}
	}

	/*
	 * If B_INVAL, clear B_DELWRI.  We've already placed the buffer
	 * on the correct queue.
	 */
	if ((bp->b_flags & (B_INVAL|B_DELWRI)) == (B_INVAL|B_DELWRI)) {
		bp->b_flags &= ~B_DELWRI;
		--numdirtybuffers;
		numdirtywakeup();
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
	if (kvawakeup)
		kvaspacewakeup();

	/* unlock */
	BUF_UNLOCK(bp);
	bp->b_flags &= ~(B_ORDERED | B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF);
	splx(s);
}

/*
 * Release a buffer back to the appropriate queue but do not try to free
 * it.
 *
 * bqrelse() is used by bdwrite() to requeue a delayed write, and used by
 * biodone() to requeue an async I/O on completion.  It is also used when
 * known good buffers need to be requeued but we think we may need the data
 * again soon.
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
	if (BUF_REFCNT(bp) > 1) {
		/* do not release to free list */
		panic("bqrelse: multiple refs");
		BUF_UNLOCK(bp);
		splx(s);
		return;
	}
	if (bp->b_flags & B_LOCKED) {
		bp->b_flags &= ~B_ERROR;
		bp->b_qindex = QUEUE_LOCKED;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LOCKED], bp, b_freelist);
		/* buffers with stale but valid contents */
	} else if (bp->b_flags & B_DELWRI) {
		bp->b_qindex = QUEUE_DIRTY;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_DIRTY], bp, b_freelist);
	} else {
		bp->b_qindex = QUEUE_CLEAN;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_CLEAN], bp, b_freelist);
	}

	runningbufspace -= bp->b_bufsize;

	if ((bp->b_flags & B_LOCKED) == 0 &&
	    ((bp->b_flags & B_INVAL) || !(bp->b_flags & B_DELWRI))) {
		bufcountwakeup();
	}

	/*
	 * Something we can maybe wakeup
	 */
	if (bp->b_bufsize && !(bp->b_flags & B_DELWRI))
		bufspacewakeup();

	/* unlock */
	BUF_UNLOCK(bp);
	bp->b_flags &= ~(B_ORDERED | B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF);
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

	bh = bufhash(vp, blkno);

	/* Search hash chain */
	LIST_FOREACH(bp, bh, b_hash) {
		/* hit */
		if (bp->b_vp == vp && bp->b_lblkno == blkno &&
		    (bp->b_flags & B_INVAL) == 0) {
			break;
		}
	}
	return (bp);
}

/*
 *	vfs_bio_awrite:
 *
 *	Implement clustered async writes for clearing out B_DELWRI buffers.
 *	This is much better then the old way of writing only one buffer at
 *	a time.  Note that we may not be presented with the buffers in the 
 *	correct order, so we search for the cluster in both directions.
 */
int
vfs_bio_awrite(struct buf * bp)
{
	int i;
	int j;
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
	 * right now we support clustered writing only to regular files.  If
	 * we find a clusterable block we could be in the middle of a cluster
	 * rather then at the beginning.
	 */
	if ((vp->v_type == VREG) && 
	    (vp->v_mount != 0) && /* Only on nodes that have the size info */
	    (bp->b_flags & (B_CLUSTEROK | B_INVAL)) == B_CLUSTEROK) {

		size = vp->v_mount->mnt_stat.f_iosize;
		maxcl = MAXPHYS / size;

		for (i = 1; i < maxcl; i++) {
			if ((bpa = gbincore(vp, lblkno + i)) &&
			    BUF_REFCNT(bpa) == 0 &&
			    ((bpa->b_flags & (B_DELWRI | B_CLUSTEROK | B_INVAL)) ==
			    (B_DELWRI | B_CLUSTEROK)) &&
			    (bpa->b_bufsize == size)) {
				if ((bpa->b_blkno == bpa->b_lblkno) ||
				    (bpa->b_blkno !=
				     bp->b_blkno + ((i * size) >> DEV_BSHIFT)))
					break;
			} else {
				break;
			}
		}
		for (j = 1; i + j <= maxcl && j <= lblkno; j++) {
			if ((bpa = gbincore(vp, lblkno - j)) &&
			    BUF_REFCNT(bpa) == 0 &&
			    ((bpa->b_flags & (B_DELWRI | B_CLUSTEROK | B_INVAL)) ==
			    (B_DELWRI | B_CLUSTEROK)) &&
			    (bpa->b_bufsize == size)) {
				if ((bpa->b_blkno == bpa->b_lblkno) ||
				    (bpa->b_blkno !=
				     bp->b_blkno - ((j * size) >> DEV_BSHIFT)))
					break;
			} else {
				break;
			}
		}
		--j;
		ncl = i + j;
		/*
		 * this is a possible cluster write
		 */
		if (ncl != 1) {
			nwritten = cluster_wbuild(vp, size, lblkno - j, ncl);
			splx(s);
			return nwritten;
		}
	}

	BUF_LOCK(bp, LK_EXCLUSIVE);
	bremfree(bp);
	bp->b_flags |= B_ASYNC;

	splx(s);
	/*
	 * default (old) behavior, writing out only one block
	 *
	 * XXX returns b_bufsize instead of b_bcount for nwritten?
	 */
	nwritten = bp->b_bufsize;
	(void) VOP_BWRITE(bp->b_vp, bp);

	return nwritten;
}

/*
 *	getnewbuf:
 *
 *	Find and initialize a new buffer header, freeing up existing buffers 
 *	in the bufqueues as necessary.  The new buffer is returned locked.
 *
 *	Important:  B_INVAL is not set.  If the caller wishes to throw the
 *	buffer away, the caller must set B_INVAL prior to calling brelse().
 *
 *	We block if:
 *		We have insufficient buffer headers
 *		We have insufficient buffer space
 *		buffer_map is too fragmented ( space reservation fails )
 *		If we have to flush dirty buffers ( but we try to avoid this )
 *
 *	To avoid VFS layer recursion we do not flush dirty buffers ourselves.
 *	Instead we ask the buf daemon to do it for us.  We attempt to
 *	avoid piecemeal wakeups of the pageout daemon.
 */

static struct buf *
getnewbuf(int slpflag, int slptimeo, int size, int maxsize)
{
	struct buf *bp;
	struct buf *nbp;
	struct buf *dbp;
	int outofspace;
	int nqindex;
	int defrag = 0;
	
	++getnewbufcalls;
	--getnewbufrestarts;
restart:
	++getnewbufrestarts;

	/*
	 * Calculate whether we are out of buffer space.  This state is
	 * recalculated on every restart.  If we are out of space, we
	 * have to turn off defragmentation.  Setting defrag to -1 when
	 * outofspace is positive means "defrag while freeing buffers".
	 * The looping conditional will be muffed up if defrag is left
	 * positive when outofspace is positive.
	 */

	dbp = NULL;
	outofspace = 0;
	if (bufspace >= hibufspace) {
		if ((curproc && (curproc->p_flag & P_BUFEXHAUST) == 0) ||
		    bufspace >= maxbufspace) {
			outofspace = 1;
			if (defrag > 0)
				defrag = -1;
		}
	}

	/*
	 * defrag state is semi-persistant.  1 means we are flagged for
	 * defragging.  -1 means we actually defragged something.
	 */
	/* nop */

	/*
	 * Setup for scan.  If we do not have enough free buffers,
	 * we setup a degenerate case that immediately fails.  Note
	 * that if we are specially marked process, we are allowed to
	 * dip into our reserves.
	 *
	 * Normally we want to find an EMPTYKVA buffer.  That is, a
	 * buffer with kva already allocated.  If there are no EMPTYKVA
	 * buffers we back up to the truely EMPTY buffers.  When defragging
	 * we do not bother backing up since we have to locate buffers with
	 * kva to defrag.  If we are out of space we skip both EMPTY and
	 * EMPTYKVA and dig right into the CLEAN queue.
	 *
	 * In this manner we avoid scanning unnecessary buffers.  It is very
	 * important for us to do this because the buffer cache is almost
	 * constantly out of space or in need of defragmentation.
	 */

	if (curproc && (curproc->p_flag & P_BUFEXHAUST) == 0 &&
	    numfreebuffers < lofreebuffers) {
		nqindex = QUEUE_CLEAN;
		nbp = NULL;
	} else {
		nqindex = QUEUE_EMPTYKVA;
		nbp = TAILQ_FIRST(&bufqueues[QUEUE_EMPTYKVA]);
		if (nbp == NULL) {
			if (defrag <= 0) {
				nqindex = QUEUE_EMPTY;
				nbp = TAILQ_FIRST(&bufqueues[QUEUE_EMPTY]);
			}
		}
		if (outofspace || nbp == NULL) {
			nqindex = QUEUE_CLEAN;
			nbp = TAILQ_FIRST(&bufqueues[QUEUE_CLEAN]);
		}
	}

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
				nqindex = QUEUE_EMPTYKVA;
				if ((nbp = TAILQ_FIRST(&bufqueues[QUEUE_EMPTYKVA])))
					break;
				/* fall through */
			case QUEUE_EMPTYKVA:
				nqindex = QUEUE_CLEAN;
				if ((nbp = TAILQ_FIRST(&bufqueues[QUEUE_CLEAN])))
					break;
				/* fall through */
			case QUEUE_CLEAN:
				/*
				 * nbp is NULL. 
				 */
				break;
			}
		}

		/*
		 * Sanity Checks
		 */
		KASSERT(bp->b_qindex == qindex, ("getnewbuf: inconsistant queue %d bp %p", qindex, bp));

		/*
		 * Note: we no longer distinguish between VMIO and non-VMIO
		 * buffers.
		 */

		KASSERT((bp->b_flags & B_DELWRI) == 0, ("delwri buffer %p found in queue %d", bp, qindex));

		/*
		 * If we are defragging and the buffer isn't useful for fixing
		 * that problem we continue.  If we are out of space and the
		 * buffer isn't useful for fixing that problem we continue.
		 */

		if (defrag > 0 && bp->b_kvasize == 0)
			continue;
		if (outofspace > 0 && bp->b_bufsize == 0)
			continue;

		/*
		 * Start freeing the bp.  This is somewhat involved.  nbp
		 * remains valid only for QUEUE_EMPTY[KVA] bp's.
		 */

		if (BUF_LOCK(bp, LK_EXCLUSIVE | LK_NOWAIT) != 0)
			panic("getnewbuf: locked buf");
		bremfree(bp);

		if (qindex == QUEUE_CLEAN) {
			if (bp->b_flags & B_VMIO) {
				bp->b_flags &= ~B_ASYNC;
				vfs_vmio_release(bp);
			}
			if (bp->b_vp)
				brelvp(bp);
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
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("losing buffer 3");
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);

		if (bp->b_bufsize)
			allocbuf(bp, 0);

		bp->b_flags = 0;
		bp->b_xflags = 0;
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

		LIST_INIT(&bp->b_dep);

		/*
		 * Ok, now that we have a free buffer, if we are defragging
		 * we have to recover the kvaspace.  If we are out of space
		 * we have to free the buffer (which we just did), but we
		 * do not have to recover kva space unless we hit a defrag
		 * hicup.  Being able to avoid freeing the kva space leads
		 * to a significant reduction in overhead.
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
			if (defrag < 0)
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
	 * If we exhausted our list, sleep as appropriate.  We may have to
	 * wakeup various daemons and write out some dirty buffers.
	 *
	 * Generally we are sleeping due to insufficient buffer space.
	 */

	if (bp == NULL) {
		int flags;
		char *waitmsg;

		if (defrag > 0) {
			flags = VFS_BIO_NEED_KVASPACE;
			waitmsg = "nbufkv";
		} else if (outofspace > 0) {
			waitmsg = "nbufbs";
			flags = VFS_BIO_NEED_BUFSPACE;
		} else {
			waitmsg = "newbuf";
			flags = VFS_BIO_NEED_ANY;
		}

		bd_speedup();	/* heeeelp */

		needsbuffer |= flags;
		while (needsbuffer & flags) {
			if (tsleep(&needsbuffer, (PRIBIO + 4) | slpflag,
			    waitmsg, slptimeo))
				return (NULL);
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
				vm_map_min(buffer_map), maxsize, &addr)) {
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
				panic("getnewbuf: unreachable code reached");
			}
		}
		if (addr) {
			vm_map_insert(buffer_map, NULL, 0,
				addr, addr + maxsize,
				VM_PROT_ALL, VM_PROT_ALL, MAP_NOFAULT);

			bp->b_kvabase = (caddr_t) addr;
			bp->b_kvasize = maxsize;
		}
		bp->b_data = bp->b_kvabase;
	}
	return(bp);
}

/*
 *	waitfreebuffers:
 *
 *	Wait for sufficient free buffers.  Only called from normal processes.
 */

static void
waitfreebuffers(int slpflag, int slptimeo) 
{
	while (numfreebuffers < hifreebuffers) {
		if (numfreebuffers >= hifreebuffers)
			break;
		needsbuffer |= VFS_BIO_NEED_FREE;
		if (tsleep(&needsbuffer, (PRIBIO + 4)|slpflag, "biofre", slptimeo))
			break;
	}
}

/*
 *	buf_daemon:
 *
 *	buffer flushing daemon.  Buffers are normally flushed by the
 *	update daemon but if it cannot keep up this process starts to
 *	take the load in an attempt to prevent getnewbuf() from blocking.
 */

static struct proc *bufdaemonproc;
static int bd_interval;
static int bd_flushto;
static int bd_flushinc;

static struct kproc_desc buf_kp = {
	"bufdaemon",
	buf_daemon,
	&bufdaemonproc
};
SYSINIT(bufdaemon, SI_SUB_KTHREAD_BUF, SI_ORDER_FIRST, kproc_start, &buf_kp)

static void
buf_daemon()
{
	int s;

	/*
	 * This process needs to be suspended prior to shutdown sync.
	 */
	EVENTHANDLER_REGISTER(shutdown_pre_sync, shutdown_kproc, bufdaemonproc,
	    SHUTDOWN_PRI_LAST);

	/*
	 * This process is allowed to take the buffer cache to the limit
	 */
	curproc->p_flag |= P_BUFEXHAUST;
	s = splbio();

	bd_interval = 5 * hz;	/* dynamically adjusted */
	bd_flushto = hidirtybuffers;	/* dynamically adjusted */
	bd_flushinc = 1;

	for (;;) {
		kproc_suspend_loop(bufdaemonproc);

		bd_request = 0;

		/*
		 * Do the flush.  Limit the number of buffers we flush in one
		 * go.  The failure condition occurs when processes are writing
		 * buffers faster then we can dispose of them.  In this case
		 * we may be flushing so often that the previous set of flushes
		 * have not had time to complete, causing us to run out of
		 * physical buffers and block.
		 */
		{
			int runcount = maxbdrun;

			while (numdirtybuffers > bd_flushto && runcount) {
				--runcount;
				if (flushbufqueues() == 0)
					break;
			}
		}

		if (bd_request || 
		    tsleep(&bd_request, PVM, "psleep", bd_interval) == 0) {
			/*
			 * Another request is pending or we were woken up
			 * without timing out.  Flush more.
			 */
			--bd_flushto;
			if (bd_flushto >= numdirtybuffers - 5) {
				bd_flushto = numdirtybuffers - 10;
				bd_flushinc = 1;
			}
			if (bd_flushto < 2)
				bd_flushto = 2;
		} else {
			/*
			 * We slept and timed out, we can slow down.
			 */
			bd_flushto += bd_flushinc;
			if (bd_flushto > hidirtybuffers)
				bd_flushto = hidirtybuffers;
			++bd_flushinc;
			if (bd_flushinc > hidirtybuffers / 20 + 1)
				bd_flushinc = hidirtybuffers / 20 + 1;
		}

		/*
		 * Set the interval on a linear scale based on hidirtybuffers
		 * with a maximum frequency of 1/10 second.
		 */
		bd_interval = bd_flushto * 5 * hz / hidirtybuffers;
		if (bd_interval < hz / 10)
			bd_interval = hz / 10;
	}
}

/*
 *	flushbufqueues:
 *
 *	Try to flush a buffer in the dirty queue.  We must be careful to
 *	free up B_INVAL buffers instead of write them, which NFS is 
 *	particularly sensitive to.
 */

static int
flushbufqueues(void)
{
	struct buf *bp;
	int r = 0;

	bp = TAILQ_FIRST(&bufqueues[QUEUE_DIRTY]);

	while (bp) {
		KASSERT((bp->b_flags & B_DELWRI), ("unexpected clean buffer %p", bp));
		if ((bp->b_flags & B_DELWRI) != 0 &&
		    (bp->b_xflags & BX_BKGRDINPROG) == 0) {
			if (bp->b_flags & B_INVAL) {
				if (BUF_LOCK(bp, LK_EXCLUSIVE | LK_NOWAIT) != 0)
					panic("flushbufqueues: locked buf");
				bremfree(bp);
				brelse(bp);
				++r;
				break;
			}
			if (LIST_FIRST(&bp->b_dep) != NULL &&
			    bioops.io_countdeps &&
			    (bp->b_flags & B_DEFERRED) == 0 &&
			    (*bioops.io_countdeps)(bp, 0)) {
				TAILQ_REMOVE(&bufqueues[QUEUE_DIRTY],
				    bp, b_freelist);
				TAILQ_INSERT_TAIL(&bufqueues[QUEUE_DIRTY],
				    bp, b_freelist);
				bp->b_flags |= B_DEFERRED;
				continue;
			}
			vfs_bio_awrite(bp);
			++r;
			break;
		}
		bp = TAILQ_NEXT(bp, b_freelist);
	}
	return (r);
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
 *	vfs_setdirty:
 *
 *	Sets the dirty range for a buffer based on the status of the dirty
 *	bits in the pages comprising the buffer.
 *
 *	The range is limited to the size of the buffer.
 *
 *	This routine is primarily used by NFS, but is generalized for the
 *	B_VMIO case.
 */
static void
vfs_setdirty(struct buf *bp) 
{
	int i;
	vm_object_t object;

	/*
	 * Degenerate case - empty buffer
	 */

	if (bp->b_bufsize == 0)
		return;

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
		vm_offset_t boffset;
		vm_offset_t eoffset;

		/*
		 * test the pages to see if they have been modified directly
		 * by users through the VM system.
		 */
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_flag_clear(bp->b_pages[i], PG_ZERO);
			vm_page_test_dirty(bp->b_pages[i]);
		}

		/*
		 * Calculate the encompassing dirty range, boffset and eoffset,
		 * (eoffset - boffset) bytes.
		 */

		for (i = 0; i < bp->b_npages; i++) {
			if (bp->b_pages[i]->dirty)
				break;
		}
		boffset = (i << PAGE_SHIFT) - (bp->b_offset & PAGE_MASK);

		for (i = bp->b_npages - 1; i >= 0; --i) {
			if (bp->b_pages[i]->dirty) {
				break;
			}
		}
		eoffset = ((i + 1) << PAGE_SHIFT) - (bp->b_offset & PAGE_MASK);

		/*
		 * Fit it to the buffer.
		 */

		if (eoffset > bp->b_bcount)
			eoffset = bp->b_bcount;

		/*
		 * If we have a good dirty range, merge with the existing
		 * dirty range.
		 */

		if (boffset < eoffset) {
			if (bp->b_dirtyoff > boffset)
				bp->b_dirtyoff = boffset;
			if (bp->b_dirtyend < eoffset)
				bp->b_dirtyend = eoffset;
		}
	}
}

/*
 *	getblk:
 *
 *	Get a block given a specified block and offset into a file/device.
 *	The buffers B_DONE bit will be cleared on return, making it almost
 * 	ready for an I/O initiation.  B_INVAL may or may not be set on 
 *	return.  The caller should clear B_INVAL prior to initiating a
 *	READ.
 *
 *	For a non-VMIO buffer, B_CACHE is set to the opposite of B_INVAL for
 *	an existing buffer.
 *
 *	For a VMIO buffer, B_CACHE is modified according to the backing VM.
 *	If getblk()ing a previously 0-sized invalid buffer, B_CACHE is set
 *	and then cleared based on the backing VM.  If the previous buffer is
 *	non-0-sized but invalid, B_CACHE will be cleared.
 *
 *	If getblk() must create a new buffer, the new buffer is returned with
 *	both B_INVAL and B_CACHE clear unless it is a VMIO buffer, in which
 *	case it is returned with B_INVAL clear and B_CACHE set based on the
 *	backing VM.
 *
 *	getblk() also forces a VOP_BWRITE() for any B_DELWRI buffer whos
 *	B_CACHE bit is clear.
 *	
 *	What this means, basically, is that the caller should use B_CACHE to
 *	determine whether the buffer is fully valid or not and should clear
 *	B_INVAL prior to issuing a read.  If the caller intends to validate
 *	the buffer by loading its data area with something, the caller needs
 *	to clear B_INVAL.  If the caller does this without issuing an I/O, 
 *	the caller should set B_CACHE ( as an optimization ), else the caller
 *	should issue the I/O and biodone() will set B_CACHE if the I/O was
 *	a write attempt or if it was a successfull read.  If the caller 
 *	intends to issue a READ, the caller must clear B_INVAL and B_ERROR
 *	prior to issuing the READ.  biodone() will *not* clear B_INVAL.
 */
struct buf *
getblk(struct vnode * vp, daddr_t blkno, int size, int slpflag, int slptimeo)
{
	struct buf *bp;
	int s;
	struct bufhashhdr *bh;

#if !defined(MAX_PERF)
	if (size > MAXBSIZE)
		panic("getblk: size(%d) > MAXBSIZE(%d)\n", size, MAXBSIZE);
#endif

	s = splbio();
loop:
	/*
	 * Block if we are low on buffers.   Certain processes are allowed
	 * to completely exhaust the buffer cache.
         *
         * If this check ever becomes a bottleneck it may be better to
         * move it into the else, when gbincore() fails.  At the moment
         * it isn't a problem.
         */
	if (!curproc || (curproc->p_flag & P_BUFEXHAUST)) {
		if (numfreebuffers == 0) {
			if (!curproc)
				return NULL;
			needsbuffer |= VFS_BIO_NEED_ANY;
			tsleep(&needsbuffer, (PRIBIO + 4) | slpflag, "newbuf",
			    slptimeo);
		}
	} else if (numfreebuffers < lofreebuffers) {
		waitfreebuffers(slpflag, slptimeo);
	}

	if ((bp = gbincore(vp, blkno))) {
		/*
		 * Buffer is in-core.  If the buffer is not busy, it must
		 * be on a queue.
		 */

		if (BUF_LOCK(bp, LK_EXCLUSIVE | LK_NOWAIT)) {
			if (BUF_TIMELOCK(bp, LK_EXCLUSIVE | LK_SLEEPFAIL,
			    "getblk", slpflag, slptimeo) == ENOLCK)
				goto loop;
			splx(s);
			return (struct buf *) NULL;
		}

		/*
		 * The buffer is locked.  B_CACHE is cleared if the buffer is 
		 * invalid.  Ohterwise, for a non-VMIO buffer, B_CACHE is set
		 * and for a VMIO buffer B_CACHE is adjusted according to the
		 * backing VM cache.
		 */
		if (bp->b_flags & B_INVAL)
			bp->b_flags &= ~B_CACHE;
		else if ((bp->b_flags & (B_VMIO | B_INVAL)) == 0)
			bp->b_flags |= B_CACHE;
		bremfree(bp);

		/*
		 * check for size inconsistancies for non-VMIO case.
		 */

		if (bp->b_bcount != size) {
			if ((bp->b_flags & B_VMIO) == 0 ||
			    (size > bp->b_kvasize)) {
				if (bp->b_flags & B_DELWRI) {
					bp->b_flags |= B_NOCACHE;
					VOP_BWRITE(bp->b_vp, bp);
				} else {
					if ((bp->b_flags & B_VMIO) &&
					   (LIST_FIRST(&bp->b_dep) == NULL)) {
						bp->b_flags |= B_RELBUF;
						brelse(bp);
					} else {
						bp->b_flags |= B_NOCACHE;
						VOP_BWRITE(bp->b_vp, bp);
					}
				}
				goto loop;
			}
		}

		/*
		 * If the size is inconsistant in the VMIO case, we can resize
		 * the buffer.  This might lead to B_CACHE getting set or
		 * cleared.  If the size has not changed, B_CACHE remains
		 * unchanged from its previous state.
		 */

		if (bp->b_bcount != size)
			allocbuf(bp, size);

		KASSERT(bp->b_offset != NOOFFSET, 
		    ("getblk: no buffer offset"));

		/*
		 * A buffer with B_DELWRI set and B_CACHE clear must
		 * be committed before we can return the buffer in
		 * order to prevent the caller from issuing a read
		 * ( due to B_CACHE not being set ) and overwriting
		 * it.
		 *
		 * Most callers, including NFS and FFS, need this to
		 * operate properly either because they assume they
		 * can issue a read if B_CACHE is not set, or because
		 * ( for example ) an uncached B_DELWRI might loop due 
		 * to softupdates re-dirtying the buffer.  In the latter
		 * case, B_CACHE is set after the first write completes,
		 * preventing further loops.
		 */

		if ((bp->b_flags & (B_CACHE|B_DELWRI)) == B_DELWRI) {
			VOP_BWRITE(bp->b_vp, bp);
			goto loop;
		}

		splx(s);
		bp->b_flags &= ~B_DONE;
	} else {
		/*
		 * Buffer is not in-core, create new buffer.  The buffer
		 * returned by getnewbuf() is locked.  Note that the returned
		 * buffer is also considered valid (not marked B_INVAL).
		 */
		int bsize, maxsize, vmio;
		off_t offset;

		if (vn_isdisk(vp, NULL))
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

		if ((bp = getnewbuf(slpflag, slptimeo, size, maxsize)) == NULL) {
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
		 * If the buffer is created out from under us, we have to
		 * throw away the one we just created.  There is now window
		 * race because we are safely running at splbio() from the
		 * point of the duplicate buffer creation through to here,
		 * and we've locked the buffer.
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
		bh = bufhash(vp, blkno);
		LIST_INSERT_HEAD(bh, bp, b_hash);

		/*
		 * set B_VMIO bit.  allocbuf() the buffer bigger.  Since the
		 * buffer size starts out as 0, B_CACHE will be set by
		 * allocbuf() for the VMIO case prior to it testing the
		 * backing store for validity.
		 */

		if (vmio) {
			bp->b_flags |= B_VMIO;
#if defined(VFS_BIO_DEBUG)
			if (vp->v_type != VREG && vp->v_type != VBLK)
				printf("getblk: vmioing file type %d???\n", vp->v_type);
#endif
		} else {
			bp->b_flags &= ~B_VMIO;
		}

		allocbuf(bp, size);

		splx(s);
		bp->b_flags &= ~B_DONE;
	}
	return (bp);
}

/*
 * Get an empty, disassociated buffer of given size.  The buffer is initially
 * set to B_INVAL.
 */
struct buf *
geteblk(int size)
{
	struct buf *bp;
	int s;

	s = splbio();
	while ((bp = getnewbuf(0, 0, size, MAXBSIZE)) == 0);
	splx(s);
	allocbuf(bp, size);
	bp->b_flags |= B_INVAL;	/* b_dep cleared by getnewbuf() */
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
 *
 * allocbuf() only adjusts B_CACHE for VMIO buffers.  getblk() deals with
 * B_CACHE for the non-VMIO case.
 */

int
allocbuf(struct buf *bp, int size)
{
	int newbsize, mbsize;
	int i;

#if !defined(MAX_PERF)
	if (BUF_REFCNT(bp) == 0)
		panic("allocbuf: buffer not busy");

	if (bp->b_kvasize < size)
		panic("allocbuf: buffer too small");
#endif

	if ((bp->b_flags & B_VMIO) == 0) {
		caddr_t origbuf;
		int origbufsize;
		/*
		 * Just get anonymous memory from the kernel.  Don't
		 * mess with B_CACHE.
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
			 * and revert to page-allocated memory when the buffer
			 * grows.
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
		/*
		 * Set B_CACHE initially if buffer is 0 length or will become
		 * 0-length.
		 */
		if (size == 0 || bp->b_bufsize == 0)
			bp->b_flags |= B_CACHE;

		if (newbsize < bp->b_bufsize) {
			/*
			 * DEV_BSIZE aligned new buffer size is less then the
			 * DEV_BSIZE aligned existing buffer size.  Figure out
			 * if we have to remove any pages.
			 */
			if (desiredpages < bp->b_npages) {
				for (i = desiredpages; i < bp->b_npages; i++) {
					/*
					 * the page is not freed here -- it
					 * is the responsibility of 
					 * vnode_pager_setsize
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
		} else if (size > bp->b_bcount) {
			/*
			 * We are growing the buffer, possibly in a 
			 * byte-granular fashion.
			 */
			struct vnode *vp;
			vm_object_t obj;
			vm_offset_t toff;
			vm_offset_t tinc;

			/*
			 * Step 1, bring in the VM pages from the object, 
			 * allocating them if necessary.  We must clear
			 * B_CACHE if these pages are not valid for the 
			 * range covered by the buffer.
			 */

			vp = bp->b_vp;
			obj = vp->v_object;

			while (bp->b_npages < desiredpages) {
				vm_page_t m;
				vm_pindex_t pi;

				pi = OFF_TO_IDX(bp->b_offset) + bp->b_npages;
				if ((m = vm_page_lookup(obj, pi)) == NULL) {
					m = vm_page_alloc(obj, pi, VM_ALLOC_NORMAL);
					if (m == NULL) {
						VM_WAIT;
						vm_pageout_deficit += desiredpages - bp->b_npages;
					} else {
						vm_page_wire(m);
						vm_page_wakeup(m);
						bp->b_flags &= ~B_CACHE;
						bp->b_pages[bp->b_npages] = m;
						++bp->b_npages;
					}
					continue;
				}

				/*
				 * We found a page.  If we have to sleep on it,
				 * retry because it might have gotten freed out
				 * from under us.
				 *
				 * We can only test PG_BUSY here.  Blocking on
				 * m->busy might lead to a deadlock:
				 *
				 *  vm_fault->getpages->cluster_read->allocbuf
				 *
				 */

				if (vm_page_sleep_busy(m, FALSE, "pgtblk"))
					continue;

				/*
				 * We have a good page.  Should we wakeup the
				 * page daemon?
				 */
				if ((curproc != pageproc) &&
				    ((m->queue - m->pc) == PQ_CACHE) &&
				    ((cnt.v_free_count + cnt.v_cache_count) <
					(cnt.v_free_min + cnt.v_cache_min))) {
					pagedaemon_wakeup();
				}
				vm_page_flag_clear(m, PG_ZERO);
				vm_page_wire(m);
				bp->b_pages[bp->b_npages] = m;
				++bp->b_npages;
			}

			/*
			 * Step 2.  We've loaded the pages into the buffer,
			 * we have to figure out if we can still have B_CACHE
			 * set.  Note that B_CACHE is set according to the
			 * byte-granular range ( bcount and size ), new the
			 * aligned range ( newbsize ).
			 *
			 * The VM test is against m->valid, which is DEV_BSIZE
			 * aligned.  Needless to say, the validity of the data
			 * needs to also be DEV_BSIZE aligned.  Note that this
			 * fails with NFS if the server or some other client
			 * extends the file's EOF.  If our buffer is resized, 
			 * B_CACHE may remain set! XXX
			 */

			toff = bp->b_bcount;
			tinc = PAGE_SIZE - ((bp->b_offset + toff) & PAGE_MASK);

			while ((bp->b_flags & B_CACHE) && toff < size) {
				vm_pindex_t pi;

				if (tinc > (size - toff))
					tinc = size - toff;

				pi = ((bp->b_offset & PAGE_MASK) + toff) >> 
				    PAGE_SHIFT;

				vfs_buf_test_cache(
				    bp, 
				    bp->b_offset,
				    toff, 
				    tinc, 
				    bp->b_pages[pi]
				);
				toff += tinc;
				tinc = PAGE_SIZE;
			}

			/*
			 * Step 3, fixup the KVM pmap.  Remember that
			 * bp->b_data is relative to bp->b_offset, but 
			 * bp->b_offset may be offset into the first page.
			 */

			bp->b_data = (caddr_t)
			    trunc_page((vm_offset_t)bp->b_data);
			pmap_qenter(
			    (vm_offset_t)bp->b_data,
			    bp->b_pages, 
			    bp->b_npages
			);
			bp->b_data = (caddr_t)((vm_offset_t)bp->b_data | 
			    (vm_offset_t)(bp->b_offset & PAGE_MASK));
		}
	}
	if (bp->b_flags & B_VMIO)
		vmiospace += (newbsize - bp->b_bufsize);
	bufspace += (newbsize - bp->b_bufsize);
	runningbufspace += (newbsize - bp->b_bufsize);
	if (newbsize < bp->b_bufsize)
		bufspacewakeup();
	bp->b_bufsize = newbsize;	/* actual buffer allocation	*/
	bp->b_bcount = size;		/* requested buffer size	*/
	return 1;
}

/*
 *	biowait:
 *
 *	Wait for buffer I/O completion, returning error status.  The buffer
 *	is left locked and B_DONE on return.  B_EINTR is converted into a EINTR
 *	error and cleared.
 */
int
biowait(register struct buf * bp)
{
	int s;

	s = splbio();
	while ((bp->b_flags & B_DONE) == 0) {
#if defined(NO_SCHEDULE_MODS)
		tsleep(bp, PRIBIO, "biowait", 0);
#else
		if (bp->b_flags & B_READ)
			tsleep(bp, PRIBIO, "biord", 0);
		else
			tsleep(bp, PRIBIO, "biowr", 0);
#endif
	}
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
 *	biodone:
 *
 *	Finish I/O on a buffer, optionally calling a completion function.
 *	This is usually called from an interrupt so process blocking is
 *	not allowed.
 *
 *	biodone is also responsible for setting B_CACHE in a B_VMIO bp.
 *	In a non-VMIO bp, B_CACHE will be set on the next getblk() 
 *	assuming B_INVAL is clear.
 *
 *	For the VMIO case, we set B_CACHE if the op was a read and no
 *	read error occured, or if the op was a write.  B_CACHE is never
 *	set if the buffer is invalid or otherwise uncacheable.
 *
 *	biodone does not mess with B_INVAL, allowing the I/O routine or the
 *	initiator to leave B_INVAL set to brelse the buffer out of existance
 *	in the biodone routine.
 */
void
biodone(register struct buf * bp)
{
	int s;

	s = splbio();

	KASSERT(BUF_REFCNT(bp) > 0, ("biodone: bp %p not busy %d", bp, BUF_REFCNT(bp)));
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

		/*
		 * Set B_CACHE if the op was a normal read and no error
		 * occured.  B_CACHE is set for writes in the b*write()
		 * routines.
		 */
		iosize = bp->b_bcount - bp->b_resid;
		if ((bp->b_flags & (B_READ|B_FREEBUF|B_INVAL|B_NOCACHE|B_ERROR)) == B_READ) {
			bp->b_flags |= B_CACHE;
		}

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
					bp->b_flags &= ~B_CACHE;
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
			 * already changed correctly ( see bdwrite() ), so we 
			 * only need to do this here in the read case.
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
				if (!vn_isdisk(vp, NULL))
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
	 * will do a wakeup there if necessary - so no need to do a wakeup
	 * here in the async case. The sync case always needs to do a wakeup.
	 */

	if (bp->b_flags & B_ASYNC) {
		if ((bp->b_flags & (B_NOCACHE | B_INVAL | B_ERROR | B_RELBUF)) != 0)
			brelse(bp);
		else
			bqrelse(bp);
	} else {
		wakeup(bp);
	}
	splx(s);
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
 * vfs_page_set_valid:
 *
 *	Set the valid bits in a page based on the supplied offset.   The
 *	range is restricted to the buffer's size.
 *
 *	This routine is typically called after a read completes.
 */
static void
vfs_page_set_valid(struct buf *bp, vm_ooffset_t off, int pageno, vm_page_t m)
{
	vm_ooffset_t soff, eoff;

	/*
	 * Start and end offsets in buffer.  eoff - soff may not cross a
	 * page boundry or cross the end of the buffer.  The end of the
	 * buffer, in this case, is our file EOF, not the allocation size
	 * of the buffer.
	 */
	soff = off;
	eoff = (off + PAGE_SIZE) & ~PAGE_MASK;
	if (eoff > bp->b_offset + bp->b_bcount)
		eoff = bp->b_offset + bp->b_bcount;

	/*
	 * Set valid range.  This is typically the entire buffer and thus the
	 * entire page.
	 */
	if (eoff > soff) {
		vm_page_set_validclean(
		    m,
		   (vm_offset_t) (soff & PAGE_MASK),
		   (vm_offset_t) (eoff - soff)
		);
	}
}

/*
 * This routine is called before a device strategy routine.
 * It is used to tell the VM system that paging I/O is in
 * progress, and treat the pages associated with the buffer
 * almost as being PG_BUSY.  Also the object paging_in_progress
 * flag is handled to make sure that the object doesn't become
 * inconsistant.
 *
 * Since I/O has not been initiated yet, certain buffer flags
 * such as B_ERROR or B_INVAL may be in an inconsistant state
 * and should be ignored.
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

			/*
			 * When readying a buffer for a read ( i.e
			 * clear_modify == 0 ), it is important to do
			 * bogus_page replacement for valid pages in 
			 * partially instantiated buffers.  Partially 
			 * instantiated buffers can, in turn, occur when
			 * reconstituting a buffer from its VM backing store
			 * base.  We only have to do this if B_CACHE is
			 * clear ( which causes the I/O to occur in the
			 * first place ).  The replacement prevents the read
			 * I/O from overwriting potentially dirty VM-backed
			 * pages.  XXX bogus page replacement is, uh, bogus.
			 * It may not work properly with small-block devices.
			 * We need to find a better way.
			 */

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
 *
 * Note that while we only really need to clean through to b_bcount, we
 * just go ahead and clean through to b_bufsize.
 */
static void
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
			vm_ooffset_t noff = (foff + PAGE_SIZE) & ~PAGE_MASK;
			vm_ooffset_t eoff = noff;

			if (eoff > bp->b_offset + bp->b_bufsize)
				eoff = bp->b_offset + bp->b_bufsize;
			vfs_page_set_valid(bp, foff, i, m);
			/* vm_page_clear_dirty(m, foff & PAGE_MASK, eoff - foff); */
			foff = noff;
		}
	}
}

/*
 *	vfs_bio_set_validclean:
 *
 *	Set the range within the buffer to valid and clean.  The range is 
 *	relative to the beginning of the buffer, b_offset.  Note that b_offset
 *	itself may be offset from the beginning of the first page.
 */

void   
vfs_bio_set_validclean(struct buf *bp, int base, int size)
{
	if (bp->b_flags & B_VMIO) {
		int i;
		int n;

		/*
		 * Fixup base to be relative to beginning of first page.
		 * Set initial n to be the maximum number of bytes in the
		 * first page that can be validated.
		 */

		base += (bp->b_offset & PAGE_MASK);
		n = PAGE_SIZE - (base & PAGE_MASK);

		for (i = base / PAGE_SIZE; size > 0 && i < bp->b_npages; ++i) {
			vm_page_t m = bp->b_pages[i];

			if (n > size)
				n = size;

			vm_page_set_validclean(m, base & PAGE_MASK, n);
			base += n;
			size -= n;
			n = PAGE_SIZE;
		}
	}
}

/*
 *	vfs_bio_clrbuf:
 *
 *	clear a buffer.  This routine essentially fakes an I/O, so we need
 *	to clear B_ERROR and B_INVAL.
 *
 *	Note that while we only theoretically need to clear through b_bcount,
 *	we go ahead and clear through b_bufsize.
 */

void
vfs_bio_clrbuf(struct buf *bp) {
	int i, mask = 0;
	caddr_t sa, ea;
	if ((bp->b_flags & (B_VMIO | B_MALLOC)) == B_VMIO) {
		bp->b_flags &= ~(B_INVAL|B_ERROR);
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
			int j = ((vm_offset_t)sa & PAGE_MASK) / DEV_BSIZE;
			ea = (caddr_t)trunc_page((vm_offset_t)sa + PAGE_SIZE);
			ea = (caddr_t)(vm_offset_t)ulmin(
			    (u_long)(vm_offset_t)ea,
			    (u_long)(vm_offset_t)bp->b_data + bp->b_bufsize);
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

	db_printf("b_flags = 0x%b\n", (u_int)bp->b_flags, PRINT_BUF_FLAGS);
	db_printf("b_error = %d, b_bufsize = %ld, b_bcount = %ld, "
		  "b_resid = %ld\nb_dev = (%d,%d), b_data = %p, "
		  "b_blkno = %d, b_pblkno = %d\n",
		  bp->b_error, bp->b_bufsize, bp->b_bcount, bp->b_resid,
		  major(bp->b_dev), minor(bp->b_dev),
		  bp->b_data, bp->b_blkno, bp->b_pblkno);
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
