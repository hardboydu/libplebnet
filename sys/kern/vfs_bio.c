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
#include <sys/stdint.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/devicestat.h>
#include <sys/eventhandler.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/proc.h>
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

struct	buf_ops buf_ops_bio = {
	"buf_ops_bio",
	bwrite
};

/*
 * XXX buf is global because kern_shutdown.c and ffs_checkoverlap has
 * carnal knowledge of buffers.  This knowledge should be moved to vfs_bio.c.
 */
struct buf *buf;		/* buffer header pool */
struct mtx buftimelock;		/* Interlock on setting prio and timo */

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
static void buf_daemon(void);

int vmiodirenable = TRUE;
SYSCTL_INT(_vfs, OID_AUTO, vmiodirenable, CTLFLAG_RW, &vmiodirenable, 0,
    "Use the VM system for directory writes");
int runningbufspace;
SYSCTL_INT(_vfs, OID_AUTO, runningbufspace, CTLFLAG_RD, &runningbufspace, 0,
    "Amount of presently outstanding async buffer io");
static int bufspace;
SYSCTL_INT(_vfs, OID_AUTO, bufspace, CTLFLAG_RD, &bufspace, 0,
    "KVA memory used for bufs");
static int maxbufspace;
SYSCTL_INT(_vfs, OID_AUTO, maxbufspace, CTLFLAG_RD, &maxbufspace, 0,
    "Maximum allowed value of bufspace (including buf_daemon)");
static int bufmallocspace;
SYSCTL_INT(_vfs, OID_AUTO, bufmallocspace, CTLFLAG_RD, &bufmallocspace, 0,
    "Amount of malloced memory for buffers");
static int maxbufmallocspace;
SYSCTL_INT(_vfs, OID_AUTO, maxmallocbufspace, CTLFLAG_RW, &maxbufmallocspace, 0,
    "Maximum amount of malloced memory for buffers");
static int lobufspace;
SYSCTL_INT(_vfs, OID_AUTO, lobufspace, CTLFLAG_RD, &lobufspace, 0,
    "Minimum amount of buffers we want to have");
static int hibufspace;
SYSCTL_INT(_vfs, OID_AUTO, hibufspace, CTLFLAG_RD, &hibufspace, 0,
    "Maximum allowed value of bufspace (excluding buf_daemon)");
static int bufreusecnt;
SYSCTL_INT(_vfs, OID_AUTO, bufreusecnt, CTLFLAG_RW, &bufreusecnt, 0,
    "Number of times we have reused a buffer");
static int buffreekvacnt;
SYSCTL_INT(_vfs, OID_AUTO, buffreekvacnt, CTLFLAG_RW, &buffreekvacnt, 0,
    "Number of times we have freed the KVA space from some buffer");
static int bufdefragcnt;
SYSCTL_INT(_vfs, OID_AUTO, bufdefragcnt, CTLFLAG_RW, &bufdefragcnt, 0,
    "Number of times we have had to repeat buffer allocation to defragment");
static int lorunningspace;
SYSCTL_INT(_vfs, OID_AUTO, lorunningspace, CTLFLAG_RW, &lorunningspace, 0,
    "Minimum preferred space used for in-progress I/O");
static int hirunningspace;
SYSCTL_INT(_vfs, OID_AUTO, hirunningspace, CTLFLAG_RW, &hirunningspace, 0,
    "Maximum amount of space to use for in-progress I/O");
static int numdirtybuffers;
SYSCTL_INT(_vfs, OID_AUTO, numdirtybuffers, CTLFLAG_RD, &numdirtybuffers, 0,
    "Number of buffers that are dirty (has unwritten changes) at the moment");
static int lodirtybuffers;
SYSCTL_INT(_vfs, OID_AUTO, lodirtybuffers, CTLFLAG_RW, &lodirtybuffers, 0,
    "How many buffers we want to have free before bufdaemon can sleep");
static int hidirtybuffers;
SYSCTL_INT(_vfs, OID_AUTO, hidirtybuffers, CTLFLAG_RW, &hidirtybuffers, 0,
    "When the number of dirty buffers is considered severe");
static int numfreebuffers;
SYSCTL_INT(_vfs, OID_AUTO, numfreebuffers, CTLFLAG_RD, &numfreebuffers, 0,
    "Number of free buffers");
static int lofreebuffers;
SYSCTL_INT(_vfs, OID_AUTO, lofreebuffers, CTLFLAG_RW, &lofreebuffers, 0,
   "XXX Unused");
static int hifreebuffers;
SYSCTL_INT(_vfs, OID_AUTO, hifreebuffers, CTLFLAG_RW, &hifreebuffers, 0,
   "XXX Complicatedly unused");
static int getnewbufcalls;
SYSCTL_INT(_vfs, OID_AUTO, getnewbufcalls, CTLFLAG_RW, &getnewbufcalls, 0,
   "Number of calls to getnewbuf");
static int getnewbufrestarts;
SYSCTL_INT(_vfs, OID_AUTO, getnewbufrestarts, CTLFLAG_RW, &getnewbufrestarts, 0,
    "Number of times getnewbuf has had to restart a buffer aquisition");
static int dobkgrdwrite = 1;
SYSCTL_INT(_debug, OID_AUTO, dobkgrdwrite, CTLFLAG_RW, &dobkgrdwrite, 0,
    "Do background writes (honoring the BX_BKGRDWRITE flag)?");

/*
 * Wakeup point for bufdaemon, as well as indicator of whether it is already
 * active.  Set to 1 when the bufdaemon is already "on" the queue, 0 when it
 * is idling.
 */
static int bd_request;

/*
 * bogus page -- for I/O to/from partially complete buffers
 * this is a temporary solution to the problem, but it is not
 * really that bad.  it would be better to split the buffer
 * for input in the case of buffers partially already in memory,
 * but the code is intricate enough already.
 */
vm_page_t bogus_page;

/*
 * Offset for bogus_page.
 * XXX bogus_offset should be local to bufinit
 */
static vm_offset_t bogus_offset;

/*
 * Synchronization (sleep/wakeup) variable for active buffer space requests.
 * Set when wait starts, cleared prior to wakeup().
 * Used in runningbufwakeup() and waitrunningbufspace().
 */
static int runningbufreq;

/* 
 * Synchronization (sleep/wakeup) variable for buffer requests.
 * Can contain the VFS_BIO_NEED flags defined below; setting/clearing is done
 * by and/or.
 * Used in numdirtywakeup(), bufspacewakeup(), bufcountwakeup(), bwillwrite(),
 * getnewbuf(), and getblk().
 */
static int needsbuffer;

#ifdef USE_BUFHASH
/*
 * Mask for index into the buffer hash table, which needs to be power of 2 in
 * size.  Set in kern_vfs_bio_buffer_alloc.
 */
static int bufhashmask;

/*
 * Hash table for all buffers, with a linked list hanging from each table
 * entry.  Set in kern_vfs_bio_buffer_alloc, initialized in buf_init.
 */
static LIST_HEAD(bufhashhdr, buf) *bufhashtbl;

/*
 * Somewhere to store buffers when they are not in another list, to always
 * have them in a list (and thus being able to use the same set of operations
 * on them.)
 */
static struct bufhashhdr invalhash;

#endif

/*
 * Definitions for the buffer free lists.
 */
#define BUFFER_QUEUES	6	/* number of free buffer queues */

#define QUEUE_NONE	0	/* on no queue */
#define QUEUE_LOCKED	1	/* locked buffers */
#define QUEUE_CLEAN	2	/* non-B_DELWRI buffers */
#define QUEUE_DIRTY	3	/* B_DELWRI buffers */
#define QUEUE_EMPTYKVA	4	/* empty buffer headers w/KVA assignment */
#define QUEUE_EMPTY	5	/* empty buffer headers */

/* Queues for free buffers with various properties */
static TAILQ_HEAD(bqueues, buf) bufqueues[BUFFER_QUEUES] = { { 0 } };
/*
 * Single global constant for BUF_WMESG, to avoid getting multiple references.
 * buf_wmesg is referred from macros.
 */
const char *buf_wmesg = BUF_WMESG;

#define VFS_BIO_NEED_ANY	0x01	/* any freeable buffer */
#define VFS_BIO_NEED_DIRTYFLUSH	0x02	/* waiting for dirty buffer flush */
#define VFS_BIO_NEED_FREE	0x04	/* wait for free bufs, hi hysteresis */
#define VFS_BIO_NEED_BUFSPACE	0x08	/* wait for buf space, lo hysteresis */

#ifdef USE_BUFHASH
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

#endif

/*
 *	numdirtywakeup:
 *
 *	If someone is blocked due to there being too many dirty buffers,
 *	and numdirtybuffers is now reasonable, wake them up.
 */

static __inline void
numdirtywakeup(int level)
{
	if (numdirtybuffers <= level) {
		if (needsbuffer & VFS_BIO_NEED_DIRTYFLUSH) {
			needsbuffer &= ~VFS_BIO_NEED_DIRTYFLUSH;
			wakeup(&needsbuffer);
		}
	}
}

/*
 *	bufspacewakeup:
 *
 *	Called when buffer space is potentially available for recovery.
 *	getnewbuf() will block on this flag when it is unable to free 
 *	sufficient buffer space.  Buffer space becomes recoverable when 
 *	bp's get placed back in the queues.
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
 * runningbufwakeup() - in-progress I/O accounting.
 *
 */
static __inline void
runningbufwakeup(struct buf *bp)
{
	if (bp->b_runningbufspace) {
		runningbufspace -= bp->b_runningbufspace;
		bp->b_runningbufspace = 0;
		if (runningbufreq && runningbufspace <= lorunningspace) {
			runningbufreq = 0;
			wakeup(&runningbufreq);
		}
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
 *	waitrunningbufspace()
 *
 *	runningbufspace is a measure of the amount of I/O currently
 *	running.  This routine is used in async-write situations to
 *	prevent creating huge backups of pending writes to a device.
 *	Only asynchronous writes are governed by this function.
 *
 *	Reads will adjust runningbufspace, but will not block based on it.
 *	The read load has a side effect of reducing the allowed write load.
 *
 *	This does NOT turn an async write into a sync write.  It waits  
 *	for earlier writes to complete and generally returns before the
 *	caller's write has reached the device.
 */
static __inline void
waitrunningbufspace(void)
{
	/*
	 * XXX race against wakeup interrupt, currently
	 * protected by Giant.  FIXME!
	 */
	while (runningbufspace > hirunningspace) {
		++runningbufreq;
		tsleep(&runningbufreq, PVM, "wdrain", 0);
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
	GIANT_REQUIRED;

	if (bp->b_flags & B_CACHE) {
		int base = (foff + off) & PAGE_MASK;
		if (vm_page_is_valid(m, base, size) == 0)
			bp->b_flags &= ~B_CACHE;
	}
}

/* Wake up the buffer deamon if necessary */
static __inline__
void
bd_wakeup(int dirtybuflevel)
{
	if (bd_request == 0 && numdirtybuffers >= dirtybuflevel) {
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
 * Calculating buffer cache scaling values and reserve space for buffer
 * headers.  This is called during low level kernel initialization and
 * may be called more then once.  We CANNOT write to the memory area
 * being reserved at this time.
 */
caddr_t
kern_vfs_bio_buffer_alloc(caddr_t v, long physmem_est)
{
	/*
	 * physmem_est is in pages.  Convert it to kilobytes (assumes
	 * PAGE_SIZE is >= 1K)
	 */
	physmem_est = physmem_est * (PAGE_SIZE / 1024);

	/*
	 * The nominal buffer size (and minimum KVA allocation) is BKVASIZE.
	 * For the first 64MB of ram nominally allocate sufficient buffers to
	 * cover 1/4 of our ram.  Beyond the first 64MB allocate additional
	 * buffers to cover 1/20 of our ram over 64MB.  When auto-sizing
	 * the buffer cache we limit the eventual kva reservation to
	 * maxbcache bytes.
	 *
	 * factor represents the 1/4 x ram conversion.
	 */
	if (nbuf == 0) {
		int factor = 4 * BKVASIZE / 1024;

		nbuf = 50;
		if (physmem_est > 4096)
			nbuf += min((physmem_est - 4096) / factor,
			    65536 / factor);
		if (physmem_est > 65536)
			nbuf += (physmem_est - 65536) * 2 / (factor * 5);

		if (maxbcache && nbuf > maxbcache / BKVASIZE)
			nbuf = maxbcache / BKVASIZE;
	}

#if 0
	/*
	 * Do not allow the buffer_map to be more then 1/2 the size of the
	 * kernel_map.
	 */
	if (nbuf > (kernel_map->max_offset - kernel_map->min_offset) / 
	    (BKVASIZE * 2)) {
		nbuf = (kernel_map->max_offset - kernel_map->min_offset) / 
		    (BKVASIZE * 2);
		printf("Warning: nbufs capped at %d\n", nbuf);
	}
#endif

	/*
	 * swbufs are used as temporary holders for I/O, such as paging I/O.
	 * We have no less then 16 and no more then 256.
	 */
	nswbuf = max(min(nbuf/4, 256), 16);

	/*
	 * Reserve space for the buffer cache buffers
	 */
	swbuf = (void *)v;
	v = (caddr_t)(swbuf + nswbuf);
	buf = (void *)v;
	v = (caddr_t)(buf + nbuf);

#ifdef USE_BUFHASH
	/*
	 * Calculate the hash table size and reserve space
	 */
	for (bufhashmask = 8; bufhashmask < nbuf / 4; bufhashmask <<= 1)
		;
	bufhashtbl = (void *)v;
	v = (caddr_t)(bufhashtbl + bufhashmask);
	--bufhashmask;
#endif
	return(v);
}

/* Initialize the buffer subsystem.  Called before use of any buffers. */
void
bufinit(void)
{
	struct buf *bp;
	int i;

	GIANT_REQUIRED;

#ifdef USE_BUFHASH
	LIST_INIT(&invalhash);
#endif
	mtx_init(&buftimelock, "buftime lock", NULL, MTX_DEF);

#ifdef USE_BUFHASH
	for (i = 0; i <= bufhashmask; i++)
		LIST_INIT(&bufhashtbl[i]);
#endif

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
#ifdef USE_BUFHASH
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
#endif
	}

	/*
	 * maxbufspace is the absolute maximum amount of buffer space we are 
	 * allowed to reserve in KVM and in real terms.  The absolute maximum
	 * is nominally used by buf_daemon.  hibufspace is the nominal maximum
	 * used by most other processes.  The differential is required to 
	 * ensure that buf_daemon is able to run when other processes might 
	 * be blocked waiting for buffer space.
	 *
	 * maxbufspace is based on BKVASIZE.  Allocating buffers larger then
	 * this may result in KVM fragmentation which is not handled optimally
	 * by the system.
	 */
	maxbufspace = nbuf * BKVASIZE;
	hibufspace = imax(3 * maxbufspace / 4, maxbufspace - MAXBSIZE * 10);
	lobufspace = hibufspace - MAXBSIZE;

	lorunningspace = 512 * 1024;
	hirunningspace = 1024 * 1024;

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
 * BKVASIZE'd (8K) buffers.
 */
	while (hidirtybuffers * BKVASIZE > 3 * hibufspace / 4) {
		hidirtybuffers >>= 1;
	}
	lodirtybuffers = hidirtybuffers / 2;

/*
 * Try to keep the number of free buffers in the specified range,
 * and give special processes (e.g. like buf_daemon) access to an 
 * emergency reserve.
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

	bogus_offset = kmem_alloc_pageable(kernel_map, PAGE_SIZE);
	vm_object_lock(kernel_object);
	bogus_page = vm_page_alloc(kernel_object,
			((bogus_offset - VM_MIN_KERNEL_ADDRESS) >> PAGE_SHIFT),
			VM_ALLOC_NORMAL);
	vm_object_unlock(kernel_object);
	cnt.v_wire_count++;
}

/*
 * bfreekva() - free the kva allocation for a buffer.
 *
 *	Must be called at splbio() or higher as this is the only locking for
 *	buffer_map.
 *
 *	Since this call frees up buffer space, we call bufspacewakeup().
 */
static void
bfreekva(struct buf * bp)
{
	GIANT_REQUIRED;

	if (bp->b_kvasize) {
		++buffreekvacnt;
		bufspace -= bp->b_kvasize;
		vm_map_delete(buffer_map,
		    (vm_offset_t) bp->b_kvabase,
		    (vm_offset_t) bp->b_kvabase + bp->b_kvasize
		);
		bp->b_kvasize = 0;
		bufspacewakeup();
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

	GIANT_REQUIRED;

	if (bp->b_qindex != QUEUE_NONE) {
		KASSERT(BUF_REFCNT(bp) == 1, ("bremfree: bp %p not locked",bp));
		TAILQ_REMOVE(&bufqueues[bp->b_qindex], bp, b_freelist);
		bp->b_qindex = QUEUE_NONE;
	} else {
		if (BUF_REFCNT(bp) <= 1)
			panic("bremfree: removing a buffer not on a queue");
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
 * must clear BIO_ERROR and B_INVAL prior to initiating I/O.  If B_CACHE
 * is set, the buffer is valid and we do not have to do anything ( see
 * getblk() ).  This is really just a special case of breadn().
 */
int
bread(struct vnode * vp, daddr_t blkno, int size, struct ucred * cred,
    struct buf ** bpp)
{

	return (breadn(vp, blkno, size, 0, 0, 0, cred, bpp));
}

/*
 * Operates like bread, but also starts asynchronous I/O on
 * read-ahead blocks.  We must clear BIO_ERROR and B_INVAL prior
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
		if (curthread != PCPU_GET(idlethread))
			curthread->td_proc->p_stats->p_ru.ru_inblock++;
		bp->b_iocmd = BIO_READ;
		bp->b_flags &= ~B_INVAL;
		bp->b_ioflags &= ~BIO_ERROR;
		if (bp->b_rcred == NOCRED && cred != NOCRED)
			bp->b_rcred = crhold(cred);
		vfs_busy_pages(bp, 0);
		if (vp->v_type == VCHR)
			VOP_SPECSTRATEGY(vp, bp);
		else
			VOP_STRATEGY(vp, bp);
		++readwait;
	}

	for (i = 0; i < cnt; i++, rablkno++, rabsize++) {
		if (inmem(vp, *rablkno))
			continue;
		rabp = getblk(vp, *rablkno, *rabsize, 0, 0);

		if ((rabp->b_flags & B_CACHE) == 0) {
			if (curthread != PCPU_GET(idlethread))
				curthread->td_proc->p_stats->p_ru.ru_inblock++;
			rabp->b_flags |= B_ASYNC;
			rabp->b_flags &= ~B_INVAL;
			rabp->b_ioflags &= ~BIO_ERROR;
			rabp->b_iocmd = BIO_READ;
			if (rabp->b_rcred == NOCRED && cred != NOCRED)
				rabp->b_rcred = crhold(cred);
			vfs_busy_pages(rabp, 0);
			BUF_KERNPROC(rabp);
			if (vp->v_type == VCHR)
				VOP_SPECSTRATEGY(vp, bp);
			else
				VOP_STRATEGY(vp, bp);
		} else {
			brelse(rabp);
		}
	}

	if (readwait) {
		rv = bufwait(bp);
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

	if (BUF_REFCNT(bp) == 0)
		panic("bwrite: buffer is not busy???");
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
		tsleep(&bp->b_xflags, PRIBIO, "bwrbg", 0);
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("bwrite: still writing");
	}

	/* Mark the buffer clean */
	bundirty(bp);

	/*
	 * If this buffer is marked for background writing and we
	 * do not have to wait for it, make a copy and write the
	 * copy so as to leave this buffer ready for further use.
	 *
	 * This optimization eats a lot of memory.  If we have a page
	 * or buffer shortfall we can't do it.
	 */
	if (dobkgrdwrite && (bp->b_xflags & BX_BKGRDWRITE) && 
	    (bp->b_flags & B_ASYNC) &&
	    !vm_page_count_severe() &&
	    !buf_dirty_count_severe()) {
		if (bp->b_iodone != NULL) {
			printf("bp->b_iodone = %p\n", bp->b_iodone);
			panic("bwrite: need chained iodone");
		}

		/* get a new block */
		newbp = geteblk(bp->b_bufsize);

		/*
		 * set it to be identical to the old block.  We have to
		 * set b_lblkno and BKGRDMARKER before calling bgetvp()
		 * to avoid confusing the splay tree and gbincore().
		 */
		memcpy(newbp->b_data, bp->b_data, bp->b_bufsize);
		newbp->b_lblkno = bp->b_lblkno;
		newbp->b_xflags |= BX_BKGRDMARKER;
		bgetvp(bp->b_vp, newbp);
		newbp->b_blkno = bp->b_blkno;
		newbp->b_offset = bp->b_offset;
		newbp->b_iodone = vfs_backgroundwritedone;
		newbp->b_flags |= B_ASYNC;
		newbp->b_flags &= ~B_INVAL;

		/* move over the dependencies */
		if (LIST_FIRST(&bp->b_dep) != NULL)
			buf_movedeps(bp, newbp);

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

	bp->b_flags &= ~B_DONE;
	bp->b_ioflags &= ~BIO_ERROR;
	bp->b_flags |= B_WRITEINPROG | B_CACHE;
	bp->b_iocmd = BIO_WRITE;

	VI_LOCK(bp->b_vp);
	bp->b_vp->v_numoutput++;
	VI_UNLOCK(bp->b_vp);
	vfs_busy_pages(bp, 1);

	/*
	 * Normal bwrites pipeline writes
	 */
	bp->b_runningbufspace = bp->b_bufsize;
	runningbufspace += bp->b_runningbufspace;

	if (curthread != PCPU_GET(idlethread))
		curthread->td_proc->p_stats->p_ru.ru_oublock++;
	splx(s);
	if (oldflags & B_ASYNC)
		BUF_KERNPROC(bp);
	if (bp->b_vp->v_type == VCHR)
		VOP_SPECSTRATEGY(bp->b_vp, bp);
	else
		VOP_STRATEGY(bp->b_vp, bp);

	if ((oldflags & B_ASYNC) == 0) {
		int rtval = bufwait(bp);
		brelse(bp);
		return (rtval);
	} else if ((oldflags & B_NOWDRAIN) == 0) {
		/*
		 * don't allow the async write to saturate the I/O
		 * system.  Deadlocks can occur only if a device strategy
		 * routine (like in MD) turns around and issues another
		 * high-level write, in which case B_NOWDRAIN is expected
		 * to be set.  Otherwise we will not deadlock here because
		 * we are blocking waiting for I/O that is already in-progress
		 * to complete.
		 */
		waitrunningbufspace();
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
	VI_LOCK(bp->b_vp);
	if ((origbp = gbincore(bp->b_vp, bp->b_lblkno)) == NULL)
		panic("backgroundwritedone: lost buffer");
	VI_UNLOCK(bp->b_vp);
	/*
	 * Process dependencies then return any unfinished ones.
	 */
	if (LIST_FIRST(&bp->b_dep) != NULL)
		buf_complete(bp);
	if (LIST_FIRST(&bp->b_dep) != NULL)
		buf_movedeps(bp, origbp);
	/*
	 * Clear the BX_BKGRDINPROG flag in the original buffer
	 * and awaken it if it is waiting for the write to complete.
	 * If BX_BKGRDINPROG is not set in the original buffer it must
	 * have been released and re-instantiated - which is not legal.
	 */
	KASSERT((origbp->b_xflags & BX_BKGRDINPROG),
	    ("backgroundwritedone: lost buffer2"));
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
	 * by biodone, it will be tossed. We mark it with BIO_READ
	 * to avoid biodone doing a second vwakeup.
	 */
	bp->b_flags |= B_NOCACHE;
	bp->b_iocmd = BIO_READ;
	bp->b_flags &= ~(B_CACHE | B_DONE);
	bp->b_iodone = 0;
	bufdone(bp);
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
	GIANT_REQUIRED;

	if (BUF_REFCNT(bp) == 0)
		panic("bdwrite: buffer is not busy");

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
	if (bp->b_vp->v_type != VCHR && bp->b_lblkno == bp->b_blkno) {
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
	 * Wakeup the buffer flushing daemon if we have a lot of dirty
	 * buffers (midpoint between our recovery point and our stall
	 * point).
	 */
	bd_wakeup((lodirtybuffers + hidirtybuffers) / 2);

	/*
	 * note: we cannot initiate I/O from a bdwrite even if we wanted to,
	 * due to the softdep code.
	 */
}

/*
 *	bdirty:
 *
 *	Turn buffer into delayed write request.  We must clear BIO_READ and
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
	KASSERT(bp->b_qindex == QUEUE_NONE,
	    ("bdirty: buffer %p still on queue %d", bp, bp->b_qindex));
	bp->b_flags &= ~(B_RELBUF);
	bp->b_iocmd = BIO_WRITE;

	if ((bp->b_flags & B_DELWRI) == 0) {
		bp->b_flags |= B_DONE | B_DELWRI;
		reassignbuf(bp, bp->b_vp);
		++numdirtybuffers;
		bd_wakeup((lodirtybuffers + hidirtybuffers) / 2);
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
	KASSERT(bp->b_qindex == QUEUE_NONE,
	    ("bundirty: buffer %p still on queue %d", bp, bp->b_qindex));

	if (bp->b_flags & B_DELWRI) {
		bp->b_flags &= ~B_DELWRI;
		reassignbuf(bp, bp->b_vp);
		--numdirtybuffers;
		numdirtywakeup(lodirtybuffers);
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
	(void) BUF_WRITE(bp);
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
	if (numdirtybuffers >= hidirtybuffers) {
		int s;

		mtx_lock(&Giant);
		s = splbio();
		while (numdirtybuffers >= hidirtybuffers) {
			bd_wakeup(1);
			needsbuffer |= VFS_BIO_NEED_DIRTYFLUSH;
			tsleep(&needsbuffer, (PRIBIO + 4), "flswai", 0);
		}
		splx(s);
		mtx_unlock(&Giant);
	}
}

/*
 * Return true if we have too many dirty buffers.
 */
int
buf_dirty_count_severe(void)
{
	return(numdirtybuffers >= hidirtybuffers);
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

	GIANT_REQUIRED;

	KASSERT(!(bp->b_flags & (B_CLUSTER|B_PAGING)),
	    ("brelse: inappropriate B_PAGING or B_CLUSTER bp %p", bp));

	s = splbio();

	if (bp->b_flags & B_LOCKED)
		bp->b_ioflags &= ~BIO_ERROR;

	if (bp->b_iocmd == BIO_WRITE &&
	    (bp->b_ioflags & BIO_ERROR) &&
	    !(bp->b_flags & B_INVAL)) {
		/*
		 * Failed write, redirty.  Must clear BIO_ERROR to prevent
		 * pages from being scrapped.  If B_INVAL is set then
		 * this case is not run and the next case is run to 
		 * destroy the buffer.  B_INVAL can occur if the buffer
		 * is outside the range supported by the underlying device.
		 */
		bp->b_ioflags &= ~BIO_ERROR;
		bdirty(bp);
	} else if ((bp->b_flags & (B_NOCACHE | B_INVAL)) ||
	    (bp->b_ioflags & BIO_ERROR) ||
	    bp->b_iocmd == BIO_DELETE || (bp->b_bufsize <= 0)) {
		/*
		 * Either a failed I/O or we were asked to free or not
		 * cache the buffer.
		 */
		bp->b_flags |= B_INVAL;
		if (LIST_FIRST(&bp->b_dep) != NULL)
			buf_deallocate(bp);
		if (bp->b_flags & B_DELWRI) {
			--numdirtybuffers;
			numdirtywakeup(lodirtybuffers);
		}
		bp->b_flags &= ~(B_DELWRI | B_CACHE);
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
	 *
	 * If B_DELWRI is not set we may have to set B_RELBUF if we are low
	 * on pages to return pages to the VM page queues.
	 */
	if (bp->b_flags & B_DELWRI)
		bp->b_flags &= ~B_RELBUF;
	else if (vm_page_count_severe() && !(bp->b_xflags & BX_BKGRDINPROG))
		bp->b_flags |= B_RELBUF;

	/*
	 * VMIO buffer rundown.  It is not very necessary to keep a VMIO buffer
	 * constituted, not even NFS buffers now.  Two flags effect this.  If
	 * B_INVAL, the struct buf is invalidated but the VM object is kept
	 * around ( i.e. so it is trivial to reconstitute the buffer later ).
	 *
	 * If BIO_ERROR or B_NOCACHE is set, pages in the VM object will be
	 * invalidated.  BIO_ERROR cannot be set for a failed write unless the
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
	    && !(bp->b_vp->v_mount != NULL &&
		 (bp->b_vp->v_mount->mnt_vfc->vfc_flags & VFCF_NETWORK) != 0 &&
		 !vn_isdisk(bp->b_vp, NULL) &&
		 (bp->b_flags & B_DELWRI))
	    ) {

		int i, j, resid;
		vm_page_t m;
		off_t foff;
		vm_pindex_t poff;
		vm_object_t obj;
		struct vnode *vp;

		vp = bp->b_vp;
		obj = bp->b_object;

		/*
		 * Get the base offset and length of the buffer.  Note that 
		 * in the VMIO case if the buffer block size is not
		 * page-aligned then b_data pointer may not be page-aligned.
		 * But our b_pages[] array *IS* page aligned.
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
			int had_bogus = 0;

			m = bp->b_pages[i];
			vm_page_lock_queues();
			vm_page_flag_clear(m, PG_ZERO);
			vm_page_unlock_queues();

			/*
			 * If we hit a bogus page, fixup *all* the bogus pages
			 * now.
			 */
			if (m == bogus_page) {
				poff = OFF_TO_IDX(bp->b_offset);
				had_bogus = 1;

				for (j = i; j < bp->b_npages; j++) {
					vm_page_t mtmp;
					mtmp = bp->b_pages[j];
					if (mtmp == bogus_page) {
						mtmp = vm_page_lookup(obj, poff + j);
						if (!mtmp) {
							panic("brelse: page missing\n");
						}
						bp->b_pages[j] = mtmp;
					}
				}

				if ((bp->b_flags & B_INVAL) == 0) {
					pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
				}
				m = bp->b_pages[i];
			}
			if ((bp->b_flags & B_NOCACHE) || (bp->b_ioflags & BIO_ERROR)) {
				int poffset = foff & PAGE_MASK;
				int presid = resid > (PAGE_SIZE - poffset) ?
					(PAGE_SIZE - poffset) : resid;

				KASSERT(presid >= 0, ("brelse: extra page"));
				vm_page_set_invalid(m, poffset, presid);
				if (had_bogus)
					printf("avoided corruption bug in bogus_page/brelse code\n");
			}
			resid -= PAGE_SIZE - (foff & PAGE_MASK);
			foff = (foff + PAGE_SIZE) & ~(off_t)PAGE_MASK;
		}

		if (bp->b_flags & (B_INVAL | B_RELBUF))
			vfs_vmio_release(bp);

	} else if (bp->b_flags & B_VMIO) {

		if (bp->b_flags & (B_INVAL | B_RELBUF)) {
			vfs_vmio_release(bp);
		}

	}
			
	if (bp->b_qindex != QUEUE_NONE)
		panic("brelse: free buffer onto another queue???");
	if (BUF_REFCNT(bp) > 1) {
		/* do not release to free list */
		BUF_UNLOCK(bp);
		splx(s);
		return;
	}

	/* enqueue */

	/* buffers with no memory */
	if (bp->b_bufsize == 0) {
		bp->b_flags |= B_INVAL;
		bp->b_xflags &= ~(BX_BKGRDWRITE | BX_ALTDATA);
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("losing buffer 1");
		if (bp->b_kvasize) {
			bp->b_qindex = QUEUE_EMPTYKVA;
		} else {
			bp->b_qindex = QUEUE_EMPTY;
		}
		TAILQ_INSERT_HEAD(&bufqueues[bp->b_qindex], bp, b_freelist);
#ifdef USE_BUFHASH
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
#endif
		bp->b_dev = NODEV;
	/* buffers with junk contents */
	} else if (bp->b_flags & (B_INVAL | B_NOCACHE | B_RELBUF) ||
	    (bp->b_ioflags & BIO_ERROR)) {
		bp->b_flags |= B_INVAL;
		bp->b_xflags &= ~(BX_BKGRDWRITE | BX_ALTDATA);
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("losing buffer 2");
		bp->b_qindex = QUEUE_CLEAN;
		TAILQ_INSERT_HEAD(&bufqueues[QUEUE_CLEAN], bp, b_freelist);
#ifdef USE_BUFHASH
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
#endif
		bp->b_dev = NODEV;

	/* buffers that are locked */
	} else if (bp->b_flags & B_LOCKED) {
		bp->b_qindex = QUEUE_LOCKED;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LOCKED], bp, b_freelist);

	/* remaining buffers */
	} else {
		if (bp->b_flags & B_DELWRI)
			bp->b_qindex = QUEUE_DIRTY;
		else
			bp->b_qindex = QUEUE_CLEAN;
		if (bp->b_flags & B_AGE)
			TAILQ_INSERT_HEAD(&bufqueues[bp->b_qindex], bp, b_freelist);
		else
			TAILQ_INSERT_TAIL(&bufqueues[bp->b_qindex], bp, b_freelist);
	}

	/*
	 * If B_INVAL and B_DELWRI is set, clear B_DELWRI.  We have already
	 * placed the buffer on the correct queue.  We must also disassociate
	 * the device and vnode for a B_INVAL buffer so gbincore() doesn't
	 * find it.
	 */
	if (bp->b_flags & B_INVAL) {
		if (bp->b_flags & B_DELWRI)
			bundirty(bp);
		if (bp->b_vp)
			brelvp(bp);
	}

	/*
	 * Fixup numfreebuffers count.  The bp is on an appropriate queue
	 * unless locked.  We then bump numfreebuffers if it is not B_DELWRI.
	 * We've already handled the B_INVAL case ( B_DELWRI will be clear
	 * if B_INVAL is set ).
	 */

	if ((bp->b_flags & B_LOCKED) == 0 && !(bp->b_flags & B_DELWRI))
		bufcountwakeup();

	/*
	 * Something we can maybe free or reuse
	 */
	if (bp->b_bufsize || bp->b_kvasize)
		bufspacewakeup();

	/* unlock */
	BUF_UNLOCK(bp);
	bp->b_flags &= ~(B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF | 
			B_DIRECT | B_NOWDRAIN);
	if ((bp->b_flags & B_DELWRI) == 0 && (bp->b_xflags & BX_VNDIRTY))
		panic("brelse: not dirty");
	splx(s);
}

/*
 * Release a buffer back to the appropriate queue but do not try to free
 * it.  The buffer is expected to be used again soon.
 *
 * bqrelse() is used by bdwrite() to requeue a delayed write, and used by
 * biodone() to requeue an async I/O on completion.  It is also used when
 * known good buffers need to be requeued but we think we may need the data
 * again soon.
 *
 * XXX we should be able to leave the B_RELBUF hint set on completion.
 */
void
bqrelse(struct buf * bp)
{
	int s;

	s = splbio();

	KASSERT(!(bp->b_flags & (B_CLUSTER|B_PAGING)), ("bqrelse: inappropriate B_PAGING or B_CLUSTER bp %p", bp));

	if (bp->b_qindex != QUEUE_NONE)
		panic("bqrelse: free buffer onto another queue???");
	if (BUF_REFCNT(bp) > 1) {
		/* do not release to free list */
		BUF_UNLOCK(bp);
		splx(s);
		return;
	}
	if (bp->b_flags & B_LOCKED) {
		bp->b_ioflags &= ~BIO_ERROR;
		bp->b_qindex = QUEUE_LOCKED;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_LOCKED], bp, b_freelist);
		/* buffers with stale but valid contents */
	} else if (bp->b_flags & B_DELWRI) {
		bp->b_qindex = QUEUE_DIRTY;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_DIRTY], bp, b_freelist);
	} else if (vm_page_count_severe()) {
		/*
		 * We are too low on memory, we have to try to free the
		 * buffer (most importantly: the wired pages making up its
		 * backing store) *now*.
		 */
		splx(s);
		brelse(bp);
		return;
	} else {
		bp->b_qindex = QUEUE_CLEAN;
		TAILQ_INSERT_TAIL(&bufqueues[QUEUE_CLEAN], bp, b_freelist);
	}

	if ((bp->b_flags & B_LOCKED) == 0 &&
	    ((bp->b_flags & B_INVAL) || !(bp->b_flags & B_DELWRI))) {
		bufcountwakeup();
	}

	/*
	 * Something we can maybe free or reuse.
	 */
	if (bp->b_bufsize && !(bp->b_flags & B_DELWRI))
		bufspacewakeup();

	/* unlock */
	BUF_UNLOCK(bp);
	bp->b_flags &= ~(B_ASYNC | B_NOCACHE | B_AGE | B_RELBUF);
	if ((bp->b_flags & B_DELWRI) == 0 && (bp->b_xflags & BX_VNDIRTY))
		panic("bqrelse: not dirty");
	splx(s);
}

/* Give pages used by the bp back to the VM system (where possible) */
static void
vfs_vmio_release(bp)
	struct buf *bp;
{
	int i;
	vm_page_t m;

	GIANT_REQUIRED;
	vm_page_lock_queues();
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
			 * no valid data.  We also free the page if the
			 * buffer was used for direct I/O
			 */
			if ((bp->b_flags & B_ASYNC) == 0 && !m->valid &&
			    m->hold_count == 0) {
				vm_page_busy(m);
				pmap_remove_all(m);
				vm_page_free(m);
			} else if (bp->b_flags & B_DIRECT) {
				vm_page_try_to_free(m);
			} else if (vm_page_count_severe()) {
				vm_page_try_to_cache(m);
			}
		}
	}
	vm_page_unlock_queues();
	pmap_qremove(trunc_page((vm_offset_t) bp->b_data), bp->b_npages);
	
	if (bp->b_bufsize) {
		bufspacewakeup();
		bp->b_bufsize = 0;
	}
	bp->b_npages = 0;
	bp->b_flags &= ~B_VMIO;
	if (bp->b_vp)
		brelvp(bp);
}

#ifdef USE_BUFHASH
/*
 * XXX MOVED TO VFS_SUBR.C
 *
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
#endif

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

		VI_LOCK(vp);
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
		VI_UNLOCK(vp);
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
	(void) BUF_WRITE(bp);

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
	int defrag = 0;
	int nqindex;
	static int flushingbufs;

	GIANT_REQUIRED;

	/*
	 * We can't afford to block since we might be holding a vnode lock,
	 * which may prevent system daemons from running.  We deal with
	 * low-memory situations by proactively returning memory and running
	 * async I/O rather then sync I/O.
	 */

	++getnewbufcalls;
	--getnewbufrestarts;
restart:
	++getnewbufrestarts;

	/*
	 * Setup for scan.  If we do not have enough free buffers,
	 * we setup a degenerate case that immediately fails.  Note
	 * that if we are specially marked process, we are allowed to
	 * dip into our reserves.
	 *
	 * The scanning sequence is nominally:  EMPTY->EMPTYKVA->CLEAN
	 *
	 * We start with EMPTYKVA.  If the list is empty we backup to EMPTY.
	 * However, there are a number of cases (defragging, reusing, ...)
	 * where we cannot backup.
	 */
	nqindex = QUEUE_EMPTYKVA;
	nbp = TAILQ_FIRST(&bufqueues[QUEUE_EMPTYKVA]);

	if (nbp == NULL) {
		/*
		 * If no EMPTYKVA buffers and we are either
		 * defragging or reusing, locate a CLEAN buffer
		 * to free or reuse.  If bufspace useage is low
		 * skip this step so we can allocate a new buffer.
		 */
		if (defrag || bufspace >= lobufspace) {
			nqindex = QUEUE_CLEAN;
			nbp = TAILQ_FIRST(&bufqueues[QUEUE_CLEAN]);
		}

		/*
		 * If we could not find or were not allowed to reuse a
		 * CLEAN buffer, check to see if it is ok to use an EMPTY
		 * buffer.  We can only use an EMPTY buffer if allocating
		 * its KVA would not otherwise run us out of buffer space.
		 */
		if (nbp == NULL && defrag == 0 &&
		    bufspace + maxsize < hibufspace) {
			nqindex = QUEUE_EMPTY;
			nbp = TAILQ_FIRST(&bufqueues[QUEUE_EMPTY]);
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
				/* FALLTHROUGH */
			case QUEUE_EMPTYKVA:
				nqindex = QUEUE_CLEAN;
				if ((nbp = TAILQ_FIRST(&bufqueues[QUEUE_CLEAN])))
					break;
				/* FALLTHROUGH */
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
		 * If we are defragging then we need a buffer with 
		 * b_kvasize != 0.  XXX this situation should no longer
		 * occur, if defrag is non-zero the buffer's b_kvasize
		 * should also be non-zero at this point.  XXX
		 */
		if (defrag && bp->b_kvasize == 0) {
			printf("Warning: defrag empty buffer %p\n", bp);
			continue;
		}

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
		if (LIST_FIRST(&bp->b_dep) != NULL)
			buf_deallocate(bp);
		if (bp->b_xflags & BX_BKGRDINPROG)
			panic("losing buffer 3");
#ifdef USE_BUFHASH
		LIST_REMOVE(bp, b_hash);
		LIST_INSERT_HEAD(&invalhash, bp, b_hash);
#endif

		if (bp->b_bufsize)
			allocbuf(bp, 0);

		bp->b_flags = 0;
		bp->b_ioflags = 0;
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
		bp->b_magic = B_MAGIC_BIO;
		bp->b_op = &buf_ops_bio;
		bp->b_object = NULL;

		LIST_INIT(&bp->b_dep);

		/*
		 * If we are defragging then free the buffer.
		 */
		if (defrag) {
			bp->b_flags |= B_INVAL;
			bfreekva(bp);
			brelse(bp);
			defrag = 0;
			goto restart;
		}

		/*
		 * If we are overcomitted then recover the buffer and its
		 * KVM space.  This occurs in rare situations when multiple
		 * processes are blocked in getnewbuf() or allocbuf().
		 */
		if (bufspace >= hibufspace)
			flushingbufs = 1;
		if (flushingbufs && bp->b_kvasize != 0) {
			bp->b_flags |= B_INVAL;
			bfreekva(bp);
			brelse(bp);
			goto restart;
		}
		if (bufspace < lobufspace)
			flushingbufs = 0;
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

		if (defrag) {
			flags = VFS_BIO_NEED_BUFSPACE;
			waitmsg = "nbufkv";
		} else if (bufspace >= hibufspace) {
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
		 * woods, we still have to reserve kva space.  In order
		 * to keep fragmentation sane we only allocate kva in
		 * BKVASIZE chunks.
		 */
		maxsize = (maxsize + BKVAMASK) & ~BKVAMASK;

		if (maxsize != bp->b_kvasize) {
			vm_offset_t addr = 0;

			bfreekva(bp);

			if (vm_map_findspace(buffer_map,
				vm_map_min(buffer_map), maxsize, &addr)) {
				/*
				 * Uh oh.  Buffer map is to fragmented.  We
				 * must defragment the map.
				 */
				++bufdefragcnt;
				defrag = 1;
				bp->b_flags |= B_INVAL;
				brelse(bp);
				goto restart;
			}
			if (addr) {
				vm_map_insert(buffer_map, NULL, 0,
					addr, addr + maxsize,
					VM_PROT_ALL, VM_PROT_ALL, MAP_NOFAULT);

				bp->b_kvabase = (caddr_t) addr;
				bp->b_kvasize = maxsize;
				bufspace += bp->b_kvasize;
				++bufreusecnt;
			}
		}
		bp->b_data = bp->b_kvabase;
	}
	return(bp);
}

/*
 *	buf_daemon:
 *
 *	buffer flushing daemon.  Buffers are normally flushed by the
 *	update daemon but if it cannot keep up this process starts to
 *	take the load in an attempt to prevent getnewbuf() from blocking.
 */

static struct proc *bufdaemonproc;

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

	mtx_lock(&Giant);

	/*
	 * This process needs to be suspended prior to shutdown sync.
	 */
	EVENTHANDLER_REGISTER(shutdown_pre_sync, kproc_shutdown, bufdaemonproc,
	    SHUTDOWN_PRI_LAST);

	/*
	 * This process is allowed to take the buffer cache to the limit
	 */
	s = splbio();

	for (;;) {
		kthread_suspend_check(bufdaemonproc);

		bd_request = 0;

		/*
		 * Do the flush.  Limit the amount of in-transit I/O we
		 * allow to build up, otherwise we would completely saturate
		 * the I/O system.  Wakeup any waiting processes before we
		 * normally would so they can run in parallel with our drain.
		 */
		while (numdirtybuffers > lodirtybuffers) {
			if (flushbufqueues() == 0)
				break;
			waitrunningbufspace();
			numdirtywakeup((lodirtybuffers + hidirtybuffers) / 2);
		}

		/*
		 * Only clear bd_request if we have reached our low water
		 * mark.  The buf_daemon normally waits 1 second and
		 * then incrementally flushes any dirty buffers that have
		 * built up, within reason.
		 *
		 * If we were unable to hit our low water mark and couldn't
		 * find any flushable buffers, we sleep half a second.
		 * Otherwise we loop immediately.
		 */
		if (numdirtybuffers <= lodirtybuffers) {
			/*
			 * We reached our low water mark, reset the
			 * request and sleep until we are needed again.
			 * The sleep is just so the suspend code works.
			 */
			bd_request = 0;
			tsleep(&bd_request, PVM, "psleep", hz);
		} else {
			/*
			 * We couldn't find any flushable dirty buffers but
			 * still have too many dirty buffers, we
			 * have to sleep and try again.  (rare)
			 */
			tsleep(&bd_request, PVM, "qsleep", hz / 10);
		}
	}
}

/*
 *	flushbufqueues:
 *
 *	Try to flush a buffer in the dirty queue.  We must be careful to
 *	free up B_INVAL buffers instead of write them, which NFS is 
 *	particularly sensitive to.
 */
int flushwithdeps = 0;
SYSCTL_INT(_vfs, OID_AUTO, flushwithdeps, CTLFLAG_RW, &flushwithdeps,
    0, "Number of buffers flushed with dependecies that require rollbacks");
static int
flushbufqueues(void)
{
	struct thread *td = curthread;
	struct vnode *vp;
	struct buf *bp;

	TAILQ_FOREACH(bp, &bufqueues[QUEUE_DIRTY], b_freelist) {
		KASSERT((bp->b_flags & B_DELWRI),
		    ("unexpected clean buffer %p", bp));
		if ((bp->b_xflags & BX_BKGRDINPROG) != 0)
			continue;
		if (bp->b_flags & B_INVAL) {
			if (BUF_LOCK(bp, LK_EXCLUSIVE) != 0)
				panic("flushbufqueues: locked buf");
			bremfree(bp);
			brelse(bp);
			return (1);
		}
		if (LIST_FIRST(&bp->b_dep) != NULL && buf_countdeps(bp, 0))
			continue;
		/*
		 * We must hold the lock on a vnode before writing
		 * one of its buffers. Otherwise we may confuse, or
		 * in the case of a snapshot vnode, deadlock the
		 * system.
		 */
		if ((vp = bp->b_vp) == NULL ||
		    vn_lock(vp, LK_EXCLUSIVE | LK_NOWAIT, td) == 0) {
			vfs_bio_awrite(bp);
			if (vp != NULL)
				VOP_UNLOCK(vp, 0, td);
			return (1);
		}
	}
	/*
	 * Could not find any buffers without rollback dependencies,
	 * so just write the first one in the hopes of eventually
	 * making progress.
	 */
	TAILQ_FOREACH(bp, &bufqueues[QUEUE_DIRTY], b_freelist) {
		KASSERT((bp->b_flags & B_DELWRI),
		    ("unexpected clean buffer %p", bp));
		if ((bp->b_xflags & BX_BKGRDINPROG) != 0)
			continue;
		if (bp->b_flags & B_INVAL) {
			if (BUF_LOCK(bp, LK_EXCLUSIVE) != 0)
				panic("flushbufqueues: locked buf");
			bremfree(bp);
			brelse(bp);
			return (1);
		}
		/*
		 * We must hold the lock on a vnode before writing
		 * one of its buffers. Otherwise we may confuse, or
		 * in the case of a snapshot vnode, deadlock the
		 * system.
		 */
		if ((vp = bp->b_vp) == NULL ||
		    vn_lock(vp, LK_EXCLUSIVE | LK_NOWAIT, td) == 0) {
			vfs_bio_awrite(bp);
			if (vp != NULL)
				VOP_UNLOCK(vp, 0, td);
			flushwithdeps += 1;
			return (0);
		}
	}
	return (0);
}

/*
 * Check to see if a block is currently memory resident.
 */
struct buf *
incore(struct vnode * vp, daddr_t blkno)
{
	struct buf *bp;

	int s = splbio();
	VI_LOCK(vp);
	bp = gbincore(vp, blkno);
	VI_UNLOCK(vp);
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

	GIANT_REQUIRED;
	ASSERT_VOP_LOCKED(vp, "inmem");

	if (incore(vp, blkno))
		return 1;
	if (vp->v_mount == NULL)
		return 0;
	if (VOP_GETVOBJECT(vp, &obj) != 0 || (vp->v_vflag & VV_OBJBUF) == 0)
		return 0;

	size = PAGE_SIZE;
	if (size > vp->v_mount->mnt_stat.f_iosize)
		size = vp->v_mount->mnt_stat.f_iosize;
	off = (vm_ooffset_t)blkno * (vm_ooffset_t)vp->v_mount->mnt_stat.f_iosize;

	for (toff = 0; toff < vp->v_mount->mnt_stat.f_iosize; toff += tinc) {
		m = vm_page_lookup(obj, OFF_TO_IDX(off + toff));
		if (!m)
			goto notinmem;
		tinc = size;
		if (tinc > PAGE_SIZE - ((toff + off) & PAGE_MASK))
			tinc = PAGE_SIZE - ((toff + off) & PAGE_MASK);
		if (vm_page_is_valid(m,
		    (vm_offset_t) ((toff + off) & PAGE_MASK), tinc) == 0)
			goto notinmem;
	}
	return 1;

notinmem:
	return (0);
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

	GIANT_REQUIRED;
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

		vm_page_lock_queues();
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

		vm_page_unlock_queues();
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
 *	getblk() also forces a BUF_WRITE() for any B_DELWRI buffer whos
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
 *	intends to issue a READ, the caller must clear B_INVAL and BIO_ERROR
 *	prior to issuing the READ.  biodone() will *not* clear B_INVAL.
 */
struct buf *
getblk(struct vnode * vp, daddr_t blkno, int size, int slpflag, int slptimeo)
{
	struct buf *bp;
	int s;
#ifdef USE_BUFHASH
	struct bufhashhdr *bh;
#endif
	ASSERT_VOP_LOCKED(vp, "getblk");

	if (size > MAXBSIZE)
		panic("getblk: size(%d) > MAXBSIZE(%d)\n", size, MAXBSIZE);

	s = splbio();
loop:
	/*
	 * Block if we are low on buffers.   Certain processes are allowed
	 * to completely exhaust the buffer cache.
         *
         * If this check ever becomes a bottleneck it may be better to
         * move it into the else, when gbincore() fails.  At the moment
         * it isn't a problem.
	 *
	 * XXX remove if 0 sections (clean this up after its proven)
         */
	if (numfreebuffers == 0) {
		if (curthread == PCPU_GET(idlethread))
			return NULL;
		needsbuffer |= VFS_BIO_NEED_ANY;
	}

	VI_LOCK(vp);
	if ((bp = gbincore(vp, blkno))) {
		VI_UNLOCK(vp);
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
		 * invalid.  Otherwise, for a non-VMIO buffer, B_CACHE is set
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
					BUF_WRITE(bp);
				} else {
					if ((bp->b_flags & B_VMIO) &&
					   (LIST_FIRST(&bp->b_dep) == NULL)) {
						bp->b_flags |= B_RELBUF;
						brelse(bp);
					} else {
						bp->b_flags |= B_NOCACHE;
						BUF_WRITE(bp);
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
		 * NOTE!  b*write() sets B_CACHE.  If we cleared B_CACHE
		 * above while extending the buffer, we cannot allow the
		 * buffer to remain with B_CACHE set after the write
		 * completes or it will represent a corrupt state.  To
		 * deal with this we set B_NOCACHE to scrap the buffer
		 * after the write.
		 *
		 * We might be able to do something fancy, like setting
		 * B_CACHE in bwrite() except if B_DELWRI is already set,
		 * so the below call doesn't set B_CACHE, but that gets real
		 * confusing.  This is much easier.
		 */

		if ((bp->b_flags & (B_CACHE|B_DELWRI)) == B_DELWRI) {
			bp->b_flags |= B_NOCACHE;
			BUF_WRITE(bp);
			goto loop;
		}

		splx(s);
		bp->b_flags &= ~B_DONE;
	} else {
		int bsize, maxsize, vmio;
		off_t offset;

		/*
		 * Buffer is not in-core, create new buffer.  The buffer
		 * returned by getnewbuf() is locked.  Note that the returned
		 * buffer is also considered valid (not marked B_INVAL).
		 */
		VI_UNLOCK(vp);
		if (vn_isdisk(vp, NULL))
			bsize = DEV_BSIZE;
		else if (vp->v_mountedhere)
			bsize = vp->v_mountedhere->mnt_stat.f_iosize;
		else if (vp->v_mount)
			bsize = vp->v_mount->mnt_stat.f_iosize;
		else
			bsize = size;

		offset = blkno * bsize;
		vmio = (VOP_GETVOBJECT(vp, NULL) == 0) &&
		    (vp->v_vflag & VV_OBJBUF);
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
		 *
		 * Note: this must occur before we associate the buffer
		 * with the vp especially considering limitations in
		 * the splay tree implementation when dealing with duplicate
		 * lblkno's.
		 */
		VI_LOCK(vp);
		if (gbincore(vp, blkno)) {
			VI_UNLOCK(vp);
			bp->b_flags |= B_INVAL;
			brelse(bp);
			goto loop;
		}
		VI_UNLOCK(vp);

		/*
		 * Insert the buffer into the hash, so that it can
		 * be found by incore.
		 */
		bp->b_blkno = bp->b_lblkno = blkno;
		bp->b_offset = offset;

		bgetvp(vp, bp);
#ifdef USE_BUFHASH
		LIST_REMOVE(bp, b_hash);
		bh = bufhash(vp, blkno);
		LIST_INSERT_HEAD(bh, bp, b_hash);
#endif

		/*
		 * set B_VMIO bit.  allocbuf() the buffer bigger.  Since the
		 * buffer size starts out as 0, B_CACHE will be set by
		 * allocbuf() for the VMIO case prior to it testing the
		 * backing store for validity.
		 */

		if (vmio) {
			bp->b_flags |= B_VMIO;
#if defined(VFS_BIO_DEBUG)
			if (vp->v_type != VREG)
				printf("getblk: vmioing file type %d???\n", vp->v_type);
#endif
			VOP_GETVOBJECT(vp, &bp->b_object);
		} else {
			bp->b_flags &= ~B_VMIO;
			bp->b_object = NULL;
		}

		allocbuf(bp, size);

		splx(s);
		bp->b_flags &= ~B_DONE;
	}
	KASSERT(BUF_REFCNT(bp) == 1, ("getblk: bp %p not locked",bp));
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
	int maxsize;

	maxsize = (size + BKVAMASK) & ~BKVAMASK;

	s = splbio();
	while ((bp = getnewbuf(0, 0, size, maxsize)) == 0)
		continue;
	splx(s);
	allocbuf(bp, size);
	bp->b_flags |= B_INVAL;	/* b_dep cleared by getnewbuf() */
	KASSERT(BUF_REFCNT(bp) == 1, ("geteblk: bp %p not locked",bp));
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

	GIANT_REQUIRED;

	if (BUF_REFCNT(bp) == 0)
		panic("allocbuf: buffer not busy");

	if (bp->b_kvasize < size)
		panic("allocbuf: buffer too small");

	if ((bp->b_flags & B_VMIO) == 0) {
		caddr_t origbuf;
		int origbufsize;
		/*
		 * Just get anonymous memory from the kernel.  Don't
		 * mess with B_CACHE.
		 */
		mbsize = (size + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
		if (bp->b_flags & B_MALLOC)
			newbsize = mbsize;
		else
			newbsize = round_page(size);

		if (newbsize < bp->b_bufsize) {
			/*
			 * malloced buffers are not shrunk
			 */
			if (bp->b_flags & B_MALLOC) {
				if (newbsize) {
					bp->b_bcount = size;
				} else {
					free(bp->b_data, M_BIOBUF);
					if (bp->b_bufsize) {
						bufmallocspace -= bp->b_bufsize;
						bufspacewakeup();
						bp->b_bufsize = 0;
					}
					bp->b_data = bp->b_kvabase;
					bp->b_bcount = 0;
					bp->b_flags &= ~B_MALLOC;
				}
				return 1;
			}		
			vm_hold_free_pages(
			    bp,
			    (vm_offset_t) bp->b_data + newbsize,
			    (vm_offset_t) bp->b_data + bp->b_bufsize);
		} else if (newbsize > bp->b_bufsize) {
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
				bufmallocspace += mbsize;
				return 1;
			}
			origbuf = NULL;
			origbufsize = 0;
			/*
			 * If the buffer is growing on its other-than-first allocation,
			 * then we revert to the page-allocation scheme.
			 */
			if (bp->b_flags & B_MALLOC) {
				origbuf = bp->b_data;
				origbufsize = bp->b_bufsize;
				bp->b_data = bp->b_kvabase;
				if (bp->b_bufsize) {
					bufmallocspace -= bp->b_bufsize;
					bufspacewakeup();
					bp->b_bufsize = 0;
				}
				bp->b_flags &= ~B_MALLOC;
				newbsize = round_page(newbsize);
			}
			vm_hold_load_pages(
			    bp,
			    (vm_offset_t) bp->b_data + bp->b_bufsize,
			    (vm_offset_t) bp->b_data + newbsize);
			if (origbuf) {
				bcopy(origbuf, bp->b_data, origbufsize);
				free(origbuf, M_BIOBUF);
			}
		}
	} else {
		int desiredpages;

		newbsize = (size + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
		desiredpages = (size == 0) ? 0 :
			num_pages((bp->b_offset & PAGE_MASK) + newbsize);

		if (bp->b_flags & B_MALLOC)
			panic("allocbuf: VMIO buffer can't be malloced");
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
				vm_page_t m;

				vm_page_lock_queues();
				for (i = desiredpages; i < bp->b_npages; i++) {
					/*
					 * the page is not freed here -- it
					 * is the responsibility of 
					 * vnode_pager_setsize
					 */
					m = bp->b_pages[i];
					KASSERT(m != bogus_page,
					    ("allocbuf: bogus page found"));
					while (vm_page_sleep_if_busy(m, TRUE, "biodep"))
						vm_page_lock_queues();

					bp->b_pages[i] = NULL;
					vm_page_unwire(m, 0);
				}
				vm_page_unlock_queues();
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
			obj = bp->b_object;

			while (bp->b_npages < desiredpages) {
				vm_page_t m;
				vm_pindex_t pi;

				pi = OFF_TO_IDX(bp->b_offset) + bp->b_npages;
				if ((m = vm_page_lookup(obj, pi)) == NULL) {
					/*
					 * note: must allocate system pages
					 * since blocking here could intefere
					 * with paging I/O, no matter which
					 * process we are.
					 */
					m = vm_page_alloc(obj, pi,
					    VM_ALLOC_SYSTEM | VM_ALLOC_WIRED);
					if (m == NULL) {
						VM_WAIT;
						vm_pageout_deficit += desiredpages - bp->b_npages;
					} else {
						vm_page_lock_queues();
						vm_page_wakeup(m);
						vm_page_unlock_queues();
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
				vm_page_lock_queues();
				if (vm_page_sleep_if_busy(m, FALSE, "pgtblk"))
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
				vm_page_unlock_queues();
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
	if (newbsize < bp->b_bufsize)
		bufspacewakeup();
	bp->b_bufsize = newbsize;	/* actual buffer allocation	*/
	bp->b_bcount = size;		/* requested buffer size	*/
	return 1;
}

void
biodone(struct bio *bp)
{
	bp->bio_flags |= BIO_DONE;
	if (bp->bio_done != NULL)
		bp->bio_done(bp);
	else
		wakeup(bp);
}

/*
 * Wait for a BIO to finish.
 *
 * XXX: resort to a timeout for now.  The optimal locking (if any) for this
 * case is not yet clear.
 */
int
biowait(struct bio *bp, const char *wchan)
{

	while ((bp->bio_flags & BIO_DONE) == 0)
		msleep(bp, NULL, PRIBIO, wchan, hz / 10);
	if (bp->bio_error != 0)
		return (bp->bio_error);
	if (!(bp->bio_flags & BIO_ERROR))
		return (0);
	return (EIO);
}

void
biofinish(struct bio *bp, struct devstat *stat, int error)
{
	
	if (error) {
		bp->bio_error = error;
		bp->bio_flags |= BIO_ERROR;
	}
	if (stat != NULL)
		devstat_end_transaction_bio(stat, bp);
	biodone(bp);
}

void
bioq_init(struct bio_queue_head *head)
{
	TAILQ_INIT(&head->queue);
	head->last_pblkno = 0;
	head->insert_point = NULL;
	head->switch_point = NULL;
}

void
bioq_remove(struct bio_queue_head *head, struct bio *bp)
{
	if (bp == head->switch_point)
		head->switch_point = TAILQ_NEXT(bp, bio_queue);
	if (bp == head->insert_point) {
		head->insert_point = TAILQ_PREV(bp, bio_queue, bio_queue);
		if (head->insert_point == NULL)
			head->last_pblkno = 0;
	} else if (bp == TAILQ_FIRST(&head->queue))
		head->last_pblkno = bp->bio_pblkno;
	TAILQ_REMOVE(&head->queue, bp, bio_queue);
	if (TAILQ_FIRST(&head->queue) == head->switch_point)
		head->switch_point = NULL;
}

/*
 *	bufwait:
 *
 *	Wait for buffer I/O completion, returning error status.  The buffer
 *	is left locked and B_DONE on return.  B_EINTR is converted into an EINTR
 *	error and cleared.
 */
int
bufwait(register struct buf * bp)
{
	int s;

	s = splbio();
	while ((bp->b_flags & B_DONE) == 0) {
		if (bp->b_iocmd == BIO_READ)
			tsleep(bp, PRIBIO, "biord", 0);
		else
			tsleep(bp, PRIBIO, "biowr", 0);
	}
	splx(s);
	if (bp->b_flags & B_EINTR) {
		bp->b_flags &= ~B_EINTR;
		return (EINTR);
	}
	if (bp->b_ioflags & BIO_ERROR) {
		return (bp->b_error ? bp->b_error : EIO);
	} else {
		return (0);
	}
}

 /*
  * Call back function from struct bio back up to struct buf.
  * The corresponding initialization lives in sys/conf.h:DEV_STRATEGY().
  */
void
bufdonebio(struct bio *bp)
{
	bufdone(bp->bio_caller2);
}

/*
 *	bufdone:
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
bufdone(struct buf *bp)
{
	int s;
	void    (*biodone)(struct buf *);

	GIANT_REQUIRED;

	s = splbio();

	KASSERT(BUF_REFCNT(bp) > 0, ("biodone: bp %p not busy %d", bp, BUF_REFCNT(bp)));
	KASSERT(!(bp->b_flags & B_DONE), ("biodone: bp %p already done", bp));

	bp->b_flags |= B_DONE;
	runningbufwakeup(bp);

	if (bp->b_iocmd == BIO_DELETE) {
		brelse(bp);
		splx(s);
		return;
	}

	if (bp->b_iocmd == BIO_WRITE) {
		vwakeup(bp);
	}

	/* call optional completion function if requested */
	if (bp->b_iodone != NULL) {
		biodone = bp->b_iodone;
		bp->b_iodone = NULL;
		(*biodone) (bp);
		splx(s);
		return;
	}
	if (LIST_FIRST(&bp->b_dep) != NULL)
		buf_complete(bp);

	if (bp->b_flags & B_VMIO) {
		int i;
		vm_ooffset_t foff;
		vm_page_t m;
		vm_object_t obj;
		int iosize;
		struct vnode *vp = bp->b_vp;

		obj = bp->b_object;

#if defined(VFS_BIO_DEBUG)
		mp_fixme("usecount and vflag accessed without locks.");
		if (vp->v_usecount == 0) {
			panic("biodone: zero vnode ref count");
		}

		if ((vp->v_vflag & VV_OBJBUF) == 0) {
			panic("biodone: vnode is not setup for merged cache");
		}
#endif

		foff = bp->b_offset;
		KASSERT(bp->b_offset != NOOFFSET,
		    ("biodone: no buffer offset"));

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
		if (bp->b_iocmd == BIO_READ &&
		    !(bp->b_flags & (B_INVAL|B_NOCACHE)) &&
		    !(bp->b_ioflags & BIO_ERROR)) {
			bp->b_flags |= B_CACHE;
		}
		vm_page_lock_queues();
		for (i = 0; i < bp->b_npages; i++) {
			int bogusflag = 0;
			int resid;

			resid = ((foff + PAGE_SIZE) & ~(off_t)PAGE_MASK) - foff;
			if (resid > iosize)
				resid = iosize;

			/*
			 * cleanup bogus pages, restoring the originals
			 */
			m = bp->b_pages[i];
			if (m == bogus_page) {
				bogusflag = 1;
				m = vm_page_lookup(obj, OFF_TO_IDX(foff));
				if (m == NULL)
					panic("biodone: page disappeared!");
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
			}
#if defined(VFS_BIO_DEBUG)
			if (OFF_TO_IDX(foff) != m->pindex) {
				printf(
"biodone: foff(%jd)/m->pindex(%ju) mismatch\n",
				    (intmax_t)foff, (uintmax_t)m->pindex);
			}
#endif

			/*
			 * In the write case, the valid and clean bits are
			 * already changed correctly ( see bdwrite() ), so we 
			 * only need to do this here in the read case.
			 */
			if ((bp->b_iocmd == BIO_READ) && !bogusflag && resid > 0) {
				vfs_page_set_valid(bp, foff, i, m);
			}
			vm_page_flag_clear(m, PG_ZERO);

			/*
			 * when debugging new filesystems or buffer I/O methods, this
			 * is the most common error that pops up.  if you see this, you
			 * have not set the page busy flag correctly!!!
			 */
			if (m->busy == 0) {
				printf("biodone: page busy < 0, "
				    "pindex: %d, foff: 0x(%x,%x), "
				    "resid: %d, index: %d\n",
				    (int) m->pindex, (int)(foff >> 32),
						(int) foff & 0xffffffff, resid, i);
				if (!vn_isdisk(vp, NULL))
					printf(" iosize: %ld, lblkno: %jd, flags: 0x%lx, npages: %d\n",
					    bp->b_vp->v_mount->mnt_stat.f_iosize,
					    (intmax_t) bp->b_lblkno,
					    bp->b_flags, bp->b_npages);
				else
					printf(" VDEV, lblkno: %jd, flags: 0x%lx, npages: %d\n",
					    (intmax_t) bp->b_lblkno,
					    bp->b_flags, bp->b_npages);
				printf(" valid: 0x%x, dirty: 0x%x, wired: %d\n",
				    m->valid, m->dirty, m->wire_count);
				panic("biodone: page busy < 0\n");
			}
			vm_page_io_finish(m);
			vm_object_pip_subtract(obj, 1);
			foff = (foff + PAGE_SIZE) & ~(off_t)PAGE_MASK;
			iosize -= resid;
		}
		vm_page_unlock_queues();
		if (obj)
			vm_object_pip_wakeupn(obj, 0);
	}

	/*
	 * For asynchronous completions, release the buffer now. The brelse
	 * will do a wakeup there if necessary - so no need to do a wakeup
	 * here in the async case. The sync case always needs to do a wakeup.
	 */

	if (bp->b_flags & B_ASYNC) {
		if ((bp->b_flags & (B_NOCACHE | B_INVAL | B_RELBUF)) || (bp->b_ioflags & BIO_ERROR))
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

	GIANT_REQUIRED;

	runningbufwakeup(bp);
	if (bp->b_flags & B_VMIO) {
		vm_object_t obj;

		obj = bp->b_object;
		vm_page_lock_queues();
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];

			if (m == bogus_page) {
				m = vm_page_lookup(obj, OFF_TO_IDX(bp->b_offset) + i);
				if (!m) {
					panic("vfs_unbusy_pages: page missing\n");
				}
				bp->b_pages[i] = m;
				pmap_qenter(trunc_page((vm_offset_t)bp->b_data), bp->b_pages, bp->b_npages);
			}
			vm_object_pip_subtract(obj, 1);
			vm_page_flag_clear(m, PG_ZERO);
			vm_page_io_finish(m);
		}
		vm_page_unlock_queues();
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

	mtx_assert(&vm_page_queue_mtx, MA_OWNED);
	/*
	 * Start and end offsets in buffer.  eoff - soff may not cross a
	 * page boundry or cross the end of the buffer.  The end of the
	 * buffer, in this case, is our file EOF, not the allocation size
	 * of the buffer.
	 */
	soff = off;
	eoff = (off + PAGE_SIZE) & ~(off_t)PAGE_MASK;
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
 * such as BIO_ERROR or B_INVAL may be in an inconsistant state
 * and should be ignored.
 */
void
vfs_busy_pages(struct buf * bp, int clear_modify)
{
	int i, bogus;

	if (bp->b_flags & B_VMIO) {
		vm_object_t obj;
		vm_ooffset_t foff;

		obj = bp->b_object;
		foff = bp->b_offset;
		KASSERT(bp->b_offset != NOOFFSET,
		    ("vfs_busy_pages: no buffer offset"));
		vfs_setdirty(bp);
retry:
		vm_page_lock_queues();
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];

			if (vm_page_sleep_if_busy(m, FALSE, "vbpage"))
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
			pmap_remove_all(m);
			if (clear_modify)
				vfs_page_set_valid(bp, foff, i, m);
			else if (m->valid == VM_PAGE_BITS_ALL &&
				(bp->b_flags & B_CACHE) == 0) {
				bp->b_pages[i] = bogus_page;
				bogus++;
			}
			foff = (foff + PAGE_SIZE) & ~(off_t)PAGE_MASK;
		}
		vm_page_unlock_queues();
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

	GIANT_REQUIRED;

	if (bp->b_flags & B_VMIO) {
		vm_ooffset_t foff;

		foff = bp->b_offset;
		KASSERT(bp->b_offset != NOOFFSET,
		    ("vfs_clean_pages: no buffer offset"));
		vm_page_lock_queues();
		for (i = 0; i < bp->b_npages; i++) {
			vm_page_t m = bp->b_pages[i];
			vm_ooffset_t noff = (foff + PAGE_SIZE) & ~(off_t)PAGE_MASK;
			vm_ooffset_t eoff = noff;

			if (eoff > bp->b_offset + bp->b_bufsize)
				eoff = bp->b_offset + bp->b_bufsize;
			vfs_page_set_valid(bp, foff, i, m);
			/* vm_page_clear_dirty(m, foff & PAGE_MASK, eoff - foff); */
			foff = noff;
		}
		vm_page_unlock_queues();
	}
}

/*
 *	vfs_bio_set_validclean:
 *
 *	Set the range within the buffer to valid and clean.  The range is 
 *	relative to the beginning of the buffer, b_offset.  Note that b_offset
 *	itself may be offset from the beginning of the first page.
 *
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

		vm_page_lock_queues();
		for (i = base / PAGE_SIZE; size > 0 && i < bp->b_npages; ++i) {
			vm_page_t m = bp->b_pages[i];

			if (n > size)
				n = size;

			vm_page_set_validclean(m, base & PAGE_MASK, n);
			base += n;
			size -= n;
			n = PAGE_SIZE;
		}
		vm_page_unlock_queues();
	}
}

/*
 *	vfs_bio_clrbuf:
 *
 *	clear a buffer.  This routine essentially fakes an I/O, so we need
 *	to clear BIO_ERROR and B_INVAL.
 *
 *	Note that while we only theoretically need to clear through b_bcount,
 *	we go ahead and clear through b_bufsize.
 */

void
vfs_bio_clrbuf(struct buf *bp) 
{
	int i, mask = 0;
	caddr_t sa, ea;

	GIANT_REQUIRED;

	if ((bp->b_flags & (B_VMIO | B_MALLOC)) == B_VMIO) {
		bp->b_flags &= ~B_INVAL;
		bp->b_ioflags &= ~BIO_ERROR;
		if( (bp->b_npages == 1) && (bp->b_bufsize < PAGE_SIZE) &&
		    (bp->b_offset & PAGE_MASK) == 0) {
			mask = (1 << (bp->b_bufsize / DEV_BSIZE)) - 1;
			if ((bp->b_pages[0]->valid & mask) == mask) {
				bp->b_resid = 0;
				return;
			}
			if (((bp->b_pages[0]->flags & PG_ZERO) == 0) &&
			    ((bp->b_pages[0]->valid & mask) == 0)) {
				bzero(bp->b_data, bp->b_bufsize);
				bp->b_pages[0]->valid |= mask;
				bp->b_resid = 0;
				return;
			}
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
			vm_page_lock_queues();
			vm_page_flag_clear(bp->b_pages[i], PG_ZERO);
			vm_page_unlock_queues();
		}
		bp->b_resid = 0;
	} else {
		clrbuf(bp);
	}
}

/*
 * vm_hold_load_pages and vm_hold_free_pages get pages into
 * a buffers address space.  The pages are anonymous and are
 * not associated with a file object.
 */
static void
vm_hold_load_pages(struct buf * bp, vm_offset_t from, vm_offset_t to)
{
	vm_offset_t pg;
	vm_page_t p;
	int index;

	GIANT_REQUIRED;

	to = round_page(to);
	from = round_page(from);
	index = (from - trunc_page((vm_offset_t)bp->b_data)) >> PAGE_SHIFT;

	for (pg = from; pg < to; pg += PAGE_SIZE, index++) {
tryagain:
		/*
		 * note: must allocate system pages since blocking here
		 * could intefere with paging I/O, no matter which
		 * process we are.
		 */
		vm_object_lock(kernel_object);
		p = vm_page_alloc(kernel_object,
			((pg - VM_MIN_KERNEL_ADDRESS) >> PAGE_SHIFT),
		    VM_ALLOC_SYSTEM | VM_ALLOC_WIRED);
		vm_object_unlock(kernel_object);
		if (!p) {
			vm_pageout_deficit += (to - from) >> PAGE_SHIFT;
			VM_WAIT;
			goto tryagain;
		}
		vm_page_lock_queues();
		p->valid = VM_PAGE_BITS_ALL;
		vm_page_flag_clear(p, PG_ZERO);
		vm_page_unlock_queues();
		pmap_qenter(pg, &p, 1);
		bp->b_pages[index] = p;
		vm_page_lock_queues();
		vm_page_wakeup(p);
		vm_page_unlock_queues();
	}
	bp->b_npages = index;
}

/* Return pages associated with this buf to the vm system */
static void
vm_hold_free_pages(struct buf * bp, vm_offset_t from, vm_offset_t to)
{
	vm_offset_t pg;
	vm_page_t p;
	int index, newnpages;

	GIANT_REQUIRED;

	from = round_page(from);
	to = round_page(to);
	newnpages = index = (from - trunc_page((vm_offset_t)bp->b_data)) >> PAGE_SHIFT;

	for (pg = from; pg < to; pg += PAGE_SIZE, index++) {
		p = bp->b_pages[index];
		if (p && (index < bp->b_npages)) {
			if (p->busy) {
				printf(
			    "vm_hold_free_pages: blkno: %jd, lblkno: %jd\n",
				    (intmax_t)bp->b_blkno,
				    (intmax_t)bp->b_lblkno);
			}
			bp->b_pages[index] = NULL;
			pmap_qremove(pg, 1);
			vm_page_lock_queues();
			vm_page_busy(p);
			vm_page_unwire(p, 0);
			vm_page_free(p);
			vm_page_unlock_queues();
		}
	}
	bp->b_npages = newnpages;
}


#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>

/* DDB command to show buffer data */
DB_SHOW_COMMAND(buffer, db_show_buffer)
{
	/* get args */
	struct buf *bp = (struct buf *)addr;

	if (!have_addr) {
		db_printf("usage: show buffer <addr>\n");
		return;
	}

	db_printf("b_flags = 0x%b\n", (u_int)bp->b_flags, PRINT_BUF_FLAGS);
	db_printf(
	    "b_error = %d, b_bufsize = %ld, b_bcount = %ld, b_resid = %ld\n"
	    "b_dev = (%d,%d), b_data = %p, b_blkno = %jd, b_pblkno = %jd\n",
	    bp->b_error, bp->b_bufsize, bp->b_bcount, bp->b_resid,
	    major(bp->b_dev), minor(bp->b_dev), bp->b_data,
	    (intmax_t)bp->b_blkno, (intmax_t)bp->b_pblkno);
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
