/*
 * Copyright (c) 1994 John S. Dyson
 * Copyright (c) 1990 University of Utah.
 * Copyright (c) 1991, 1993
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
 * from: Utah $Hdr: swap_pager.c 1.4 91/04/30$
 *
 *	@(#)swap_pager.c	8.9 (Berkeley) 3/21/94
 * $Id: swap_pager.c,v 1.42 1995/07/13 08:48:15 davidg Exp $
 */

/*
 * Quick hack to page to dedicated partition(s).
 * TODO:
 *	Add multiprocessor locks
 *	Deal with async writes in a better fashion
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/malloc.h>

#include <miscfs/specfs/specdev.h>
#include <sys/rlist.h>

#include <vm/vm.h>
#include <vm/vm_pager.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/swap_pager.h>
#include <vm/vm_kern.h>

#ifndef NPENDINGIO
#define NPENDINGIO	10
#endif

int nswiodone;
int swap_pager_full;
extern int vm_swap_size;
int no_swap_space = 1;
struct rlist *swaplist;
int nswaplist;

#define MAX_PAGEOUT_CLUSTER 8

TAILQ_HEAD(swpclean, swpagerclean);

typedef struct swpagerclean *swp_clean_t;

struct swpagerclean {
	TAILQ_ENTRY(swpagerclean) spc_list;
	int spc_flags;
	struct buf *spc_bp;
	vm_object_t spc_object;
	vm_offset_t spc_kva;
	int spc_count;
	vm_page_t spc_m[MAX_PAGEOUT_CLUSTER];
} swcleanlist[NPENDINGIO];


/* spc_flags values */
#define SPC_ERROR	0x01

#define SWB_EMPTY (-1)

struct swpclean swap_pager_done;	/* list of completed page cleans */
struct swpclean swap_pager_inuse;	/* list of pending page cleans */
struct swpclean swap_pager_free;	/* list of free pager clean structs */
struct pagerlst swap_pager_object_list;	/* list of "named" anon region objects */
struct pagerlst swap_pager_un_object_list; /* list of "unnamed" anon region objects */

#define	SWAP_FREE_NEEDED	0x1	/* need a swap block */
#define SWAP_FREE_NEEDED_BY_PAGEOUT 0x2
int swap_pager_needflags;

struct pagerlst *swp_qs[] = {
	&swap_pager_object_list, &swap_pager_un_object_list, (struct pagerlst *) 0
};

/*
 * pagerops for OBJT_SWAP - "swap pager".
 */
struct pagerops swappagerops = {
	swap_pager_init,
	swap_pager_alloc,
	swap_pager_dealloc,
	swap_pager_getpages,
	swap_pager_putpages,
	swap_pager_haspage,
	swap_pager_sync
};

int npendingio = NPENDINGIO;
void swap_pager_finish();
int dmmin, dmmax;


static inline void
swapsizecheck()
{
	if (vm_swap_size < 128 * btodb(PAGE_SIZE)) {
		if (swap_pager_full == 0)
			printf("swap_pager: out of space\n");
		swap_pager_full = 1;
	} else if (vm_swap_size > 192 * btodb(PAGE_SIZE))
		swap_pager_full = 0;
}

void
swap_pager_init()
{
	TAILQ_INIT(&swap_pager_object_list);
	TAILQ_INIT(&swap_pager_un_object_list);

	/*
	 * Initialize clean lists
	 */
	TAILQ_INIT(&swap_pager_inuse);
	TAILQ_INIT(&swap_pager_done);
	TAILQ_INIT(&swap_pager_free);

	/*
	 * Calculate the swap allocation constants.
	 */
	dmmin = CLBYTES / DEV_BSIZE;
	dmmax = btodb(SWB_NPAGES * PAGE_SIZE) * 2;
}

void
swap_pager_swap_init()
{
	swp_clean_t spc;
	struct buf *bp;
	int i;

	/*
	 * kva's are allocated here so that we dont need to keep doing
	 * kmem_alloc pageables at runtime
	 */
	for (i = 0, spc = swcleanlist; i < npendingio; i++, spc++) {
		spc->spc_kva = kmem_alloc_pageable(pager_map, PAGE_SIZE * MAX_PAGEOUT_CLUSTER);
		if (!spc->spc_kva) {
			break;
		}
		spc->spc_bp = malloc(sizeof(*bp), M_TEMP, M_KERNEL);
		if (!spc->spc_bp) {
			kmem_free_wakeup(pager_map, spc->spc_kva, PAGE_SIZE);
			break;
		}
		spc->spc_flags = 0;
		TAILQ_INSERT_TAIL(&swap_pager_free, spc, spc_list);
	}
}

int
swap_pager_swp_alloc(object, wait)
	vm_object_t object;
	int wait;
{
	sw_blk_t swb;
	int nblocks;
	int i, j;

	nblocks = (btodb(object->size) + btodb(SWB_NPAGES * PAGE_SIZE) - 1) /
	    btodb(SWB_NPAGES * PAGE_SIZE);

	swb = malloc(nblocks * sizeof(*swb), M_VMPGDATA, wait);
	if (swb == NULL)
		return 1;

	for (i = 0; i < nblocks; i++) {
		swb[i].swb_valid = 0;
		swb[i].swb_locked = 0;
		for (j = 0; j < SWB_NPAGES; j++)
			swb[i].swb_block[j] = SWB_EMPTY;
	}

	object->un_pager.swp.swp_nblocks = nblocks;
	object->un_pager.swp.swp_allocsize = 0;
	object->un_pager.swp.swp_blocks = swb;
	object->un_pager.swp.swp_poip = 0;

	if (object->handle != NULL) {
		TAILQ_INSERT_TAIL(&swap_pager_object_list, object, pager_object_list);
	} else {
		TAILQ_INSERT_TAIL(&swap_pager_un_object_list, object, pager_object_list);
	}

	return 0;
}

/*
 * Allocate an object and associated resources.
 * Note that if we are called from the pageout daemon (handle == NULL)
 * we should not wait for memory as it could resulting in deadlock.
 */
vm_object_t
swap_pager_alloc(handle, size, prot, offset)
	void *handle;
	register vm_size_t size;
	vm_prot_t prot;
	vm_offset_t offset;
{
	vm_object_t object;
	int i;

	/*
	 * If this is a "named" anonymous region, look it up and use the
	 * object if it exists, otherwise allocate a new one.
	 */
	if (handle) {
		object = vm_pager_object_lookup(&swap_pager_object_list, handle);
		if (object != NULL) {
			vm_object_reference(object);
		} else {
			/*
			 * XXX - there is a race condition here. Two processes
			 * can request the same named object simultaneuously,
			 * and if one blocks for memory, the result is a disaster.
			 * Probably quite rare, but is yet another reason to just
			 * rip support of "named anonymous regions" out altogether.
			 */
			object = vm_object_allocate(OBJT_SWAP, offset + size);
			object->handle = handle;
			(void) swap_pager_swp_alloc(object, M_WAITOK);
		}
	} else {
		object = vm_object_allocate(OBJT_SWAP, offset + size);
		(void) swap_pager_swp_alloc(object, M_WAITOK);
	}

	return (object);
}

/*
 * returns disk block associated with pager and offset
 * additionally, as a side effect returns a flag indicating
 * if the block has been written
 */

inline static int *
swap_pager_diskaddr(object, offset, valid)
	vm_object_t object;
	vm_offset_t offset;
	int *valid;
{
	register sw_blk_t swb;
	int ix;

	if (valid)
		*valid = 0;
	ix = offset / (SWB_NPAGES * PAGE_SIZE);
	if ((ix >= object->un_pager.swp.swp_nblocks) ||
	    (offset >= object->size)) {
		return (FALSE);
	}
	swb = &object->un_pager.swp.swp_blocks[ix];
	ix = (offset % (SWB_NPAGES * PAGE_SIZE)) / PAGE_SIZE;
	if (valid)
		*valid = swb->swb_valid & (1 << ix);
	return &swb->swb_block[ix];
}

/*
 * Utility routine to set the valid (written) bit for
 * a block associated with a pager and offset
 */
static void
swap_pager_setvalid(object, offset, valid)
	vm_object_t object;
	vm_offset_t offset;
	int valid;
{
	register sw_blk_t swb;
	int ix;

	ix = offset / (SWB_NPAGES * PAGE_SIZE);
	if (ix >= object->un_pager.swp.swp_nblocks)
		return;

	swb = &object->un_pager.swp.swp_blocks[ix];
	ix = (offset % (SWB_NPAGES * PAGE_SIZE)) / PAGE_SIZE;
	if (valid)
		swb->swb_valid |= (1 << ix);
	else
		swb->swb_valid &= ~(1 << ix);
	return;
}

/*
 * this routine allocates swap space with a fragmentation
 * minimization policy.
 */
int
swap_pager_getswapspace(object, amount, rtval)
	vm_object_t object;
	unsigned int amount;
	unsigned int *rtval;
{
	vm_swap_size -= amount;
	if (!rlist_alloc(&swaplist, amount, rtval)) {
		vm_swap_size += amount;
		return 0;
	} else {
		swapsizecheck();
		object->un_pager.swp.swp_allocsize += amount;
		return 1;
	}
}

/*
 * this routine frees swap space with a fragmentation
 * minimization policy.
 */
void
swap_pager_freeswapspace(object, from, to)
	vm_object_t object;
	unsigned int from;
	unsigned int to;
{
	rlist_free(&swaplist, from, to);
	vm_swap_size += (to - from) + 1;
	object->un_pager.swp.swp_allocsize -= (to - from) + 1;
	swapsizecheck();
}
/*
 * this routine frees swap blocks from a specified pager
 */
void
swap_pager_freespace(object, start, size)
	vm_object_t object;
	vm_offset_t start;
	vm_offset_t size;
{
	vm_offset_t i;
	int s;

	s = splbio();
	for (i = start; i < round_page(start + size); i += PAGE_SIZE) {
		int valid;
		int *addr = swap_pager_diskaddr(object, i, &valid);

		if (addr && *addr != SWB_EMPTY) {
			swap_pager_freeswapspace(object, *addr, *addr + btodb(PAGE_SIZE) - 1);
			if (valid) {
				swap_pager_setvalid(object, i, 0);
			}
			*addr = SWB_EMPTY;
		}
	}
	splx(s);
}

static void
swap_pager_free_swap(object)
	vm_object_t object;
{
	register int i, j;
	register sw_blk_t swb;
	int first_block=0, block_count=0;
	int s;
	/*
	 * Free left over swap blocks
	 */
	s = splbio();
	for (i = 0, swb = object->un_pager.swp.swp_blocks;
	    i < object->un_pager.swp.swp_nblocks; i++, swb++) {
		for (j = 0; j < SWB_NPAGES; j++) {
			if (swb->swb_block[j] != SWB_EMPTY) {
				/*
				 * initially the length of the run is zero
				 */
				if (block_count == 0) {
					first_block = swb->swb_block[j];
					block_count = btodb(PAGE_SIZE);
					swb->swb_block[j] = SWB_EMPTY;
				/*
				 * if the new block can be included into the current run
				 */
				} else if (swb->swb_block[j] == first_block + block_count) {
					block_count += btodb(PAGE_SIZE);
					swb->swb_block[j] = SWB_EMPTY;
				/*
				 * terminate the previous run, and start a new one
				 */
				} else {
					swap_pager_freeswapspace(object, first_block,
				   	 (unsigned) first_block + block_count - 1);
					first_block = swb->swb_block[j];
					block_count = btodb(PAGE_SIZE);
					swb->swb_block[j] = SWB_EMPTY;
				}
			}
		}
	}

	if (block_count) {
		swap_pager_freeswapspace(object, first_block,
		   	 (unsigned) first_block + block_count - 1);
	}
	splx(s);
}


/*
 * swap_pager_reclaim frees up over-allocated space from all pagers
 * this eliminates internal fragmentation due to allocation of space
 * for segments that are never swapped to. It has been written so that
 * it does not block until the rlist_free operation occurs; it keeps
 * the queues consistant.
 */

/*
 * Maximum number of blocks (pages) to reclaim per pass
 */
#define MAXRECLAIM 128

void
swap_pager_reclaim()
{
	vm_object_t object;
	int i, j, k;
	int s;
	int reclaimcount;
	static struct {
		int address;
		vm_object_t object;
	} reclaims[MAXRECLAIM];
	static int in_reclaim;

	/*
	 * allow only one process to be in the swap_pager_reclaim subroutine
	 */
	s = splbio();
	if (in_reclaim) {
		tsleep(&in_reclaim, PSWP, "swrclm", 0);
		splx(s);
		return;
	}
	in_reclaim = 1;
	reclaimcount = 0;

	/* for each pager queue */
	for (k = 0; swp_qs[k]; k++) {

		object = swp_qs[k]->tqh_first;
		while (object && (reclaimcount < MAXRECLAIM)) {

			/*
			 * see if any blocks associated with a pager has been
			 * allocated but not used (written)
			 */
			for (i = 0; i < object->un_pager.swp.swp_nblocks; i++) {
				sw_blk_t swb = &object->un_pager.swp.swp_blocks[i];

				if (swb->swb_locked)
					continue;
				for (j = 0; j < SWB_NPAGES; j++) {
					if (swb->swb_block[j] != SWB_EMPTY &&
					    (swb->swb_valid & (1 << j)) == 0) {
						reclaims[reclaimcount].address = swb->swb_block[j];
						reclaims[reclaimcount++].object = object;
						swb->swb_block[j] = SWB_EMPTY;
						if (reclaimcount >= MAXRECLAIM)
							goto rfinished;
					}
				}
			}
			object = object->pager_object_list.tqe_next;
		}
	}

rfinished:

	/*
	 * free the blocks that have been added to the reclaim list
	 */
	for (i = 0; i < reclaimcount; i++) {
		swap_pager_freeswapspace(reclaims[i].object,
		    reclaims[i].address, reclaims[i].address + btodb(PAGE_SIZE) - 1);
	}
	splx(s);
	in_reclaim = 0;
	wakeup(&in_reclaim);
}


/*
 * swap_pager_copy copies blocks from one pager to another and
 * destroys the source pager
 */

void
swap_pager_copy(srcobject, srcoffset, dstobject, dstoffset, offset)
	vm_object_t srcobject;
	vm_offset_t srcoffset;
	vm_object_t dstobject;
	vm_offset_t dstoffset;
	vm_offset_t offset;
{
	vm_offset_t i;
	int origsize;
	int s;

	if (vm_swap_size)
		no_swap_space = 0;

	origsize = srcobject->un_pager.swp.swp_allocsize;

	/*
	 * remove the source object from the swap_pager internal queue
	 */
	if (srcobject->handle == NULL) {
		TAILQ_REMOVE(&swap_pager_un_object_list, srcobject, pager_object_list);
	} else {
		TAILQ_REMOVE(&swap_pager_object_list, srcobject, pager_object_list);
	}

	s = splbio();
	while (srcobject->un_pager.swp.swp_poip) {
		tsleep(srcobject, PVM, "spgout", 0);
	}
	splx(s);

	/*
	 * clean all of the pages that are currently active and finished
	 */
	swap_pager_sync();

	s = splbio();
	/*
	 * transfer source to destination
	 */
	for (i = 0; i < dstobject->size; i += PAGE_SIZE) {
		int srcvalid, dstvalid;
		int *srcaddrp = swap_pager_diskaddr(srcobject, i + offset + srcoffset,
						    &srcvalid);
		int *dstaddrp;

		/*
		 * see if the source has space allocated
		 */
		if (srcaddrp && *srcaddrp != SWB_EMPTY) {
			/*
			 * if the source is valid and the dest has no space,
			 * then copy the allocation from the srouce to the
			 * dest.
			 */
			if (srcvalid) {
				dstaddrp = swap_pager_diskaddr(dstobject, i + dstoffset,
							&dstvalid);
				/*
				 * if the dest already has a valid block,
				 * deallocate the source block without
				 * copying.
				 */
				if (!dstvalid && dstaddrp && *dstaddrp != SWB_EMPTY) {
					swap_pager_freeswapspace(dstobject, *dstaddrp,
						*dstaddrp + btodb(PAGE_SIZE) - 1);
					*dstaddrp = SWB_EMPTY;
				}
				if (dstaddrp && *dstaddrp == SWB_EMPTY) {
					*dstaddrp = *srcaddrp;
					*srcaddrp = SWB_EMPTY;
					dstobject->un_pager.swp.swp_allocsize += btodb(PAGE_SIZE);
					srcobject->un_pager.swp.swp_allocsize -= btodb(PAGE_SIZE);
					swap_pager_setvalid(dstobject, i + dstoffset, 1);
				}
			}
			/*
			 * if the source is not empty at this point, then
			 * deallocate the space.
			 */
			if (*srcaddrp != SWB_EMPTY) {
				swap_pager_freeswapspace(srcobject, *srcaddrp,
					*srcaddrp + btodb(PAGE_SIZE) - 1);
				*srcaddrp = SWB_EMPTY;
			}
		}
	}
	splx(s);

	/*
	 * Free left over swap blocks
	 */
	swap_pager_free_swap(srcobject);

	if (srcobject->un_pager.swp.swp_allocsize) {
		printf("swap_pager_copy: *warning* pager with %d blocks (orig: %d)\n",
		    srcobject->un_pager.swp.swp_allocsize, origsize);
	}

	free(srcobject->un_pager.swp.swp_blocks, M_VMPGDATA);
	srcobject->un_pager.swp.swp_blocks = NULL;

	return;
}

void
swap_pager_dealloc(object)
	vm_object_t object;
{
	int s;

	/*
	 * Remove from list right away so lookups will fail if we block for
	 * pageout completion.
	 */
	if (object->handle == NULL) {
		TAILQ_REMOVE(&swap_pager_un_object_list, object, pager_object_list);
	} else {
		TAILQ_REMOVE(&swap_pager_object_list, object, pager_object_list);
	}

	/*
	 * Wait for all pageouts to finish and remove all entries from
	 * cleaning list.
	 */

	s = splbio();
	while (object->un_pager.swp.swp_poip) {
		tsleep(object, PVM, "swpout", 0);
	}
	splx(s);


	swap_pager_sync();

	/*
	 * Free left over swap blocks
	 */
	swap_pager_free_swap(object);

	if (object->un_pager.swp.swp_allocsize) {
		printf("swap_pager_dealloc: *warning* freeing pager with %d blocks\n",
		    object->un_pager.swp.swp_allocsize);
	}
	/*
	 * Free swap management resources
	 */
	free(object->un_pager.swp.swp_blocks, M_VMPGDATA);
	object->un_pager.swp.swp_blocks = NULL;
}

static inline int
const
swap_pager_block_index(offset)
	vm_offset_t offset;
{
	return (offset / (SWB_NPAGES * PAGE_SIZE));
}

static inline int
const
swap_pager_block_offset(offset)
	vm_offset_t offset;
{
	return ((offset % (PAGE_SIZE * SWB_NPAGES)) / PAGE_SIZE);
}

/*
 * swap_pager_haspage returns TRUE if the pager has data that has
 * been written out.
 */
boolean_t
swap_pager_haspage(object, offset, before, after)
	vm_object_t object;
	vm_offset_t offset;
	int *before;
	int *after;
{
	register sw_blk_t swb;
	int ix;

	if (before != NULL)
		*before = 0;
	if (after != NULL)
		*after = 0;
	ix = offset / (SWB_NPAGES * PAGE_SIZE);
	if (ix >= object->un_pager.swp.swp_nblocks) {
		return (FALSE);
	}
	swb = &object->un_pager.swp.swp_blocks[ix];
	ix = (offset % (SWB_NPAGES * PAGE_SIZE)) / PAGE_SIZE;
	if (swb->swb_block[ix] != SWB_EMPTY) {
		if (swb->swb_valid & (1 << ix))
			return TRUE;
	}
	return (FALSE);
}

/*
 * swap_pager_freepage is a convienience routine that clears the busy
 * bit and deallocates a page.
 */
static void
swap_pager_freepage(m)
	vm_page_t m;
{
	PAGE_WAKEUP(m);
	vm_page_free(m);
}

/*
 * swap_pager_ridpages is a convienience routine that deallocates all
 * but the required page.  this is usually used in error returns that
 * need to invalidate the "extra" readahead pages.
 */
static void
swap_pager_ridpages(m, count, reqpage)
	vm_page_t *m;
	int count;
	int reqpage;
{
	int i;

	for (i = 0; i < count; i++)
		if (i != reqpage)
			swap_pager_freepage(m[i]);
}

/*
 * swap_pager_iodone1 is the completion routine for both reads and async writes
 */
void
swap_pager_iodone1(bp)
	struct buf *bp;
{
	bp->b_flags |= B_DONE;
	bp->b_flags &= ~B_ASYNC;
	wakeup(bp);
}

int
swap_pager_getpages(object, m, count, reqpage)
	vm_object_t object;
	vm_page_t *m;
	int count, reqpage;
{
	register struct buf *bp;
	sw_blk_t swb[count];
	register int s;
	int i;
	boolean_t rv;
	vm_offset_t kva, off[count];
	swp_clean_t spc;
	vm_offset_t paging_offset;
	int reqaddr[count];
	int sequential;

	int first, last;
	int failed;
	int reqdskregion;

	object = m[reqpage]->object;
	paging_offset = object->paging_offset;
	sequential = (m[reqpage]->offset == (object->last_read + PAGE_SIZE));

	for (i = 0; i < count; i++) {
		vm_offset_t foff = m[i]->offset + paging_offset;
		int ix = swap_pager_block_index(foff);

		if (ix >= object->un_pager.swp.swp_nblocks) {
			int j;

			if (i <= reqpage) {
				swap_pager_ridpages(m, count, reqpage);
				return (VM_PAGER_FAIL);
			}
			for (j = i; j < count; j++) {
				swap_pager_freepage(m[j]);
			}
			count = i;
			break;
		}
		swb[i] = &object->un_pager.swp.swp_blocks[ix];
		off[i] = swap_pager_block_offset(foff);
		reqaddr[i] = swb[i]->swb_block[off[i]];
	}

	/* make sure that our required input request is existant */

	if (reqaddr[reqpage] == SWB_EMPTY ||
	    (swb[reqpage]->swb_valid & (1 << off[reqpage])) == 0) {
		swap_pager_ridpages(m, count, reqpage);
		return (VM_PAGER_FAIL);
	}
	reqdskregion = reqaddr[reqpage] / dmmax;

	/*
	 * search backwards for the first contiguous page to transfer
	 */
	failed = 0;
	first = 0;
	for (i = reqpage - 1; i >= 0; --i) {
		if (sequential || failed || (reqaddr[i] == SWB_EMPTY) ||
		    (swb[i]->swb_valid & (1 << off[i])) == 0 ||
		    (reqaddr[i] != (reqaddr[reqpage] + (i - reqpage) * btodb(PAGE_SIZE))) ||
		    ((reqaddr[i] / dmmax) != reqdskregion)) {
			failed = 1;
			swap_pager_freepage(m[i]);
			if (first == 0)
				first = i + 1;
		}
	}
	/*
	 * search forwards for the last contiguous page to transfer
	 */
	failed = 0;
	last = count;
	for (i = reqpage + 1; i < count; i++) {
		if (failed || (reqaddr[i] == SWB_EMPTY) ||
		    (swb[i]->swb_valid & (1 << off[i])) == 0 ||
		    (reqaddr[i] != (reqaddr[reqpage] + (i - reqpage) * btodb(PAGE_SIZE))) ||
		    ((reqaddr[i] / dmmax) != reqdskregion)) {
			failed = 1;
			swap_pager_freepage(m[i]);
			if (last == count)
				last = i;
		}
	}

	count = last;
	if (first != 0) {
		for (i = first; i < count; i++) {
			m[i - first] = m[i];
			reqaddr[i - first] = reqaddr[i];
			off[i - first] = off[i];
		}
		count -= first;
		reqpage -= first;
	}
	++swb[reqpage]->swb_locked;

	/*
	 * at this point: "m" is a pointer to the array of vm_page_t for
	 * paging I/O "count" is the number of vm_page_t entries represented
	 * by "m" "object" is the vm_object_t for I/O "reqpage" is the index
	 * into "m" for the page actually faulted
	 */

	spc = NULL;	/* we might not use an spc data structure */

	if ((count == 1) && (swap_pager_free.tqh_first != NULL)) {
		/*
		 * if a kva has not been allocated, we can only do a one page
		 * transfer, so we free the other pages that might have been
		 * allocated by vm_fault.
		 */
		swap_pager_ridpages(m, count, reqpage);
		m[0] = m[reqpage];
		reqaddr[0] = reqaddr[reqpage];

		count = 1;
		reqpage = 0;
		/*
		 * get a swap pager clean data structure, block until we get
		 * it
		 */
		if (swap_pager_free.tqh_first == NULL) {
			s = splbio();
			if (curproc == pageproc)
				swap_pager_sync();
			else
				pagedaemon_wakeup();
			while (swap_pager_free.tqh_first == NULL) {
				swap_pager_needflags |= SWAP_FREE_NEEDED;
				if (curproc == pageproc)
					swap_pager_needflags |= SWAP_FREE_NEEDED_BY_PAGEOUT;
				tsleep(&swap_pager_free,
				    PVM, "swpfre", 0);
				if (curproc == pageproc)
					swap_pager_sync();
				else
					pagedaemon_wakeup();
			}
			splx(s);
		}
		spc = swap_pager_free.tqh_first;
		TAILQ_REMOVE(&swap_pager_free, spc, spc_list);
		kva = spc->spc_kva;
		bp = spc->spc_bp;
		bzero(bp, sizeof *bp);
		bp->b_spc = spc;
		bp->b_vnbufs.le_next = NOLIST;
	} else {
		/*
		 * Get a swap buffer header to perform the IO
		 */
		bp = getpbuf();
		kva = (vm_offset_t) bp->b_data;
	}

	/*
	 * map our page(s) into kva for input
	 */
	pmap_qenter(kva, m, count);

	bp->b_flags = B_BUSY | B_READ | B_CALL | B_PAGING;
	bp->b_iodone = swap_pager_iodone1;
	bp->b_proc = &proc0;	/* XXX (but without B_PHYS set this is ok) */
	bp->b_rcred = bp->b_wcred = bp->b_proc->p_ucred;
	crhold(bp->b_rcred);
	crhold(bp->b_wcred);
	bp->b_un.b_addr = (caddr_t) kva;
	bp->b_blkno = reqaddr[0];
	bp->b_bcount = PAGE_SIZE * count;
	bp->b_bufsize = PAGE_SIZE * count;

	pbgetvp(swapdev_vp, bp);

	cnt.v_swapin++;
	cnt.v_swappgsin += count;
	/*
	 * perform the I/O
	 */
	VOP_STRATEGY(bp);

	/*
	 * wait for the sync I/O to complete
	 */
	s = splbio();
	while ((bp->b_flags & B_DONE) == 0) {
		tsleep(bp, PVM, "swread", 0);
	}

	if (bp->b_flags & B_ERROR) {
		printf("swap_pager: I/O error - pagein failed; blkno %d, size %d, error %d\n",
		    bp->b_blkno, bp->b_bcount, bp->b_error);
		rv = VM_PAGER_ERROR;
	} else {
		rv = VM_PAGER_OK;
	}

	/*
	 * relpbuf does this, but we maintain our own buffer list also...
	 */
	if (bp->b_vp)
		pbrelvp(bp);

	splx(s);
	swb[reqpage]->swb_locked--;

	/*
	 * remove the mapping for kernel virtual
	 */
	pmap_qremove(kva, count);

	if (spc) {
		m[reqpage]->object->last_read = m[reqpage]->offset;
		if (bp->b_flags & B_WANTED)
			wakeup(bp);
		/*
		 * if we have used an spc, we need to free it.
		 */
		if (bp->b_rcred != NOCRED)
			crfree(bp->b_rcred);
		if (bp->b_wcred != NOCRED)
			crfree(bp->b_wcred);
		TAILQ_INSERT_TAIL(&swap_pager_free, spc, spc_list);
		if (swap_pager_needflags & SWAP_FREE_NEEDED) {
			wakeup(&swap_pager_free);
		}
		if (swap_pager_needflags & SWAP_FREE_NEEDED_BY_PAGEOUT)
			pagedaemon_wakeup();
		swap_pager_needflags &= ~(SWAP_FREE_NEEDED|SWAP_FREE_NEEDED_BY_PAGEOUT);
	} else {
		/*
		 * release the physical I/O buffer
		 */
		relpbuf(bp);
		/*
		 * finish up input if everything is ok
		 */
		if (rv == VM_PAGER_OK) {
			for (i = 0; i < count; i++) {
				pmap_clear_modify(VM_PAGE_TO_PHYS(m[i]));
				m[i]->dirty = 0;
				if (i != reqpage) {
					/*
					 * whether or not to leave the page
					 * activated is up in the air, but we
					 * should put the page on a page queue
					 * somewhere. (it already is in the
					 * object). After some emperical
					 * results, it is best to deactivate
					 * the readahead pages.
					 */
					vm_page_deactivate(m[i]);

					/*
					 * just in case someone was asking for
					 * this page we now tell them that it
					 * is ok to use
					 */
					m[i]->valid = VM_PAGE_BITS_ALL;
					PAGE_WAKEUP(m[i]);
				}
			}

			m[reqpage]->object->last_read = m[count-1]->offset;

			/*
			 * If we're out of swap space, then attempt to free
			 * some whenever pages are brought in. We must clear
			 * the clean flag so that the page contents will be
			 * preserved.
			 */
			if (swap_pager_full) {
				for (i = 0; i < count; i++) {
					m[i]->dirty = VM_PAGE_BITS_ALL;
				}
				swap_pager_freespace(object, m[0]->offset + paging_offset, count * PAGE_SIZE);
			}
		} else {
			swap_pager_ridpages(m, count, reqpage);
		}
	}
	return (rv);
}

int
swap_pager_putpages(object, m, count, sync, rtvals)
	vm_object_t object;
	vm_page_t *m;
	int count;
	boolean_t sync;
	int *rtvals;
{
	register struct buf *bp;
	sw_blk_t swb[count];
	register int s;
	int i, j, ix;
	boolean_t rv;
	vm_offset_t kva, off, foff;
	swp_clean_t spc;
	vm_offset_t paging_offset;
	int reqaddr[count];
	int failed;

	if (vm_swap_size)
		no_swap_space = 0;
	if (no_swap_space) {
		for (i = 0; i < count; i++)
			rtvals[i] = VM_PAGER_FAIL;
		return VM_PAGER_FAIL;
	}
	spc = NULL;

	object = m[0]->object;
	paging_offset = object->paging_offset;

	failed = 0;
	for (j = 0; j < count; j++) {
		foff = m[j]->offset + paging_offset;
		ix = swap_pager_block_index(foff);
		swb[j] = 0;
		if (ix >= object->un_pager.swp.swp_nblocks) {
			rtvals[j] = VM_PAGER_FAIL;
			failed = 1;
			continue;
		} else {
			rtvals[j] = VM_PAGER_OK;
		}
		swb[j] = &object->un_pager.swp.swp_blocks[ix];
		swb[j]->swb_locked++;
		if (failed) {
			rtvals[j] = VM_PAGER_FAIL;
			continue;
		}
		off = swap_pager_block_offset(foff);
		reqaddr[j] = swb[j]->swb_block[off];
		if (reqaddr[j] == SWB_EMPTY) {
			int blk;
			int tries;
			int ntoget;

			tries = 0;
			s = splbio();

			/*
			 * if any other pages have been allocated in this
			 * block, we only try to get one page.
			 */
			for (i = 0; i < SWB_NPAGES; i++) {
				if (swb[j]->swb_block[i] != SWB_EMPTY)
					break;
			}

			ntoget = (i == SWB_NPAGES) ? SWB_NPAGES : 1;
			/*
			 * this code is alittle conservative, but works (the
			 * intent of this code is to allocate small chunks for
			 * small objects)
			 */
			if ((foff == 0) &&
				((ntoget * PAGE_SIZE) > object->size)) {
				ntoget = (object->size + (PAGE_SIZE - 1)) / PAGE_SIZE;
			}
	retrygetspace:
			if (!swap_pager_full && ntoget > 1 &&
			    swap_pager_getswapspace(object, ntoget * btodb(PAGE_SIZE), &blk)) {

				for (i = 0; i < ntoget; i++) {
					swb[j]->swb_block[i] = blk + btodb(PAGE_SIZE) * i;
					swb[j]->swb_valid = 0;
				}

				reqaddr[j] = swb[j]->swb_block[off];
			} else if (!swap_pager_getswapspace(object, btodb(PAGE_SIZE),
				&swb[j]->swb_block[off])) {
				/*
				 * if the allocation has failed, we try to
				 * reclaim space and retry.
				 */
				if (++tries == 1) {
					swap_pager_reclaim();
					goto retrygetspace;
				}
				rtvals[j] = VM_PAGER_AGAIN;
				failed = 1;
				swap_pager_full = 1;
			} else {
				reqaddr[j] = swb[j]->swb_block[off];
				swb[j]->swb_valid &= ~(1 << off);
			}
			splx(s);
		}
	}

	/*
	 * search forwards for the last contiguous page to transfer
	 */
	failed = 0;
	for (i = 0; i < count; i++) {
		if (failed || (reqaddr[i] != reqaddr[0] + i * btodb(PAGE_SIZE)) ||
		    (reqaddr[i] / dmmax) != (reqaddr[0] / dmmax) ||
		    (rtvals[i] != VM_PAGER_OK)) {
			failed = 1;
			if (rtvals[i] == VM_PAGER_OK)
				rtvals[i] = VM_PAGER_AGAIN;
		}
	}

	for (i = 0; i < count; i++) {
		if (rtvals[i] != VM_PAGER_OK) {
			if (swb[i])
				--swb[i]->swb_locked;
		}
	}

	for (i = 0; i < count; i++)
		if (rtvals[i] != VM_PAGER_OK)
			break;

	if (i == 0) {
		return VM_PAGER_AGAIN;
	}
	count = i;
	for (i = 0; i < count; i++) {
		if (reqaddr[i] == SWB_EMPTY)
			printf("I/O to empty block????\n");
	}

	/*
	 * For synchronous writes, we clean up all completed async pageouts.
	 */
	if (sync == TRUE) {
		swap_pager_sync();
	}
	kva = 0;

	/*
	 * get a swap pager clean data structure, block until we get it
	 */
	if (swap_pager_free.tqh_first == NULL ||
		swap_pager_free.tqh_first->spc_list.tqe_next == NULL ||
		swap_pager_free.tqh_first->spc_list.tqe_next->spc_list.tqe_next == NULL) {
		s = splbio();
		if (curproc == pageproc) {
			swap_pager_sync();
#if 0
			splx(s);
			return VM_PAGER_AGAIN;
#endif
		} else
			pagedaemon_wakeup();
		while (swap_pager_free.tqh_first == NULL ||
			swap_pager_free.tqh_first->spc_list.tqe_next == NULL ||
			swap_pager_free.tqh_first->spc_list.tqe_next->spc_list.tqe_next == NULL) {
			if (curproc == pageproc) {
				swap_pager_needflags |= SWAP_FREE_NEEDED_BY_PAGEOUT;
			    if((cnt.v_free_count + cnt.v_cache_count) > cnt.v_free_reserved)
					wakeup(&cnt.v_free_count);
			}

			swap_pager_needflags |= SWAP_FREE_NEEDED;
			tsleep(&swap_pager_free, PVM, "swpfre", 0);
			if (curproc == pageproc)
				swap_pager_sync();
			else
				pagedaemon_wakeup();
		}
		splx(s);
	}
	spc = swap_pager_free.tqh_first;
	TAILQ_REMOVE(&swap_pager_free, spc, spc_list);

	kva = spc->spc_kva;

	/*
	 * map our page(s) into kva for I/O
	 */
	pmap_qenter(kva, m, count);

	/*
	 * get the base I/O offset into the swap file
	 */
	for (i = 0; i < count; i++) {
		foff = m[i]->offset + paging_offset;
		off = swap_pager_block_offset(foff);
		/*
		 * set the valid bit
		 */
		swb[i]->swb_valid |= (1 << off);
		/*
		 * and unlock the data structure
		 */
		swb[i]->swb_locked--;
	}

	/*
	 * Get a swap buffer header and perform the IO
	 */
	bp = spc->spc_bp;
	bzero(bp, sizeof *bp);
	bp->b_spc = spc;
	bp->b_vnbufs.le_next = NOLIST;

	bp->b_flags = B_BUSY | B_PAGING;
	bp->b_proc = &proc0;	/* XXX (but without B_PHYS set this is ok) */
	bp->b_rcred = bp->b_wcred = bp->b_proc->p_ucred;
	if (bp->b_rcred != NOCRED)
		crhold(bp->b_rcred);
	if (bp->b_wcred != NOCRED)
		crhold(bp->b_wcred);
	bp->b_data = (caddr_t) kva;
	bp->b_blkno = reqaddr[0];
	pbgetvp(swapdev_vp, bp);

	bp->b_bcount = PAGE_SIZE * count;
	bp->b_bufsize = PAGE_SIZE * count;
	swapdev_vp->v_numoutput++;

	/*
	 * If this is an async write we set up additional buffer fields and
	 * place a "cleaning" entry on the inuse queue.
	 */
	s = splbio();
	if (sync == FALSE) {
		spc->spc_flags = 0;
		spc->spc_object = object;
		for (i = 0; i < count; i++)
			spc->spc_m[i] = m[i];
		spc->spc_count = count;
		/*
		 * the completion routine for async writes
		 */
		bp->b_flags |= B_CALL;
		bp->b_iodone = swap_pager_iodone;
		bp->b_dirtyoff = 0;
		bp->b_dirtyend = bp->b_bcount;
		object->un_pager.swp.swp_poip++;
		TAILQ_INSERT_TAIL(&swap_pager_inuse, spc, spc_list);
	} else {
		object->un_pager.swp.swp_poip++;
		bp->b_flags |= B_CALL;
		bp->b_iodone = swap_pager_iodone1;
	}

	cnt.v_swapout++;
	cnt.v_swappgsout += count;
	/*
	 * perform the I/O
	 */
	VOP_STRATEGY(bp);
	if (sync == FALSE) {
		if ((bp->b_flags & B_DONE) == B_DONE) {
			swap_pager_sync();
		}
		splx(s);
		for (i = 0; i < count; i++) {
			rtvals[i] = VM_PAGER_PEND;
		}
		return VM_PAGER_PEND;
	}
	/*
	 * wait for the sync I/O to complete
	 */
	while ((bp->b_flags & B_DONE) == 0) {
		tsleep(bp, PVM, "swwrt", 0);
	}
	if (bp->b_flags & B_ERROR) {
		printf("swap_pager: I/O error - pageout failed; blkno %d, size %d, error %d\n",
		    bp->b_blkno, bp->b_bcount, bp->b_error);
		rv = VM_PAGER_ERROR;
	} else {
		rv = VM_PAGER_OK;
	}

	object->un_pager.swp.swp_poip--;
	if (object->un_pager.swp.swp_poip == 0)
		wakeup(object);

	if (bp->b_vp)
		pbrelvp(bp);
	if (bp->b_flags & B_WANTED)
		wakeup(bp);

	splx(s);

	/*
	 * remove the mapping for kernel virtual
	 */
	pmap_qremove(kva, count);

	/*
	 * if we have written the page, then indicate that the page is clean.
	 */
	if (rv == VM_PAGER_OK) {
		for (i = 0; i < count; i++) {
			if (rtvals[i] == VM_PAGER_OK) {
				pmap_clear_modify(VM_PAGE_TO_PHYS(m[i]));
				m[i]->dirty = 0;
				/*
				 * optimization, if a page has been read
				 * during the pageout process, we activate it.
				 */
				if ((m[i]->flags & PG_ACTIVE) == 0 &&
				    ((m[i]->flags & (PG_WANTED|PG_REFERENCED)) ||
				    pmap_is_referenced(VM_PAGE_TO_PHYS(m[i])))) {
					vm_page_activate(m[i]);
				}
			}
		}
	} else {
		for (i = 0; i < count; i++) {
			rtvals[i] = rv;
		}
	}

	if (bp->b_rcred != NOCRED)
		crfree(bp->b_rcred);
	if (bp->b_wcred != NOCRED)
		crfree(bp->b_wcred);
	TAILQ_INSERT_TAIL(&swap_pager_free, spc, spc_list);
	if (swap_pager_needflags & SWAP_FREE_NEEDED) {
		wakeup(&swap_pager_free);
	}
	if (swap_pager_needflags & SWAP_FREE_NEEDED_BY_PAGEOUT)
		pagedaemon_wakeup();
	swap_pager_needflags &= ~(SWAP_FREE_NEEDED|SWAP_FREE_NEEDED_BY_PAGEOUT);
	return (rv);
}

void
swap_pager_sync()
{
	register swp_clean_t spc, tspc;
	register int s;

	tspc = NULL;
	if (swap_pager_done.tqh_first == NULL)
		return;
	for (;;) {
		s = splbio();
		/*
		 * Look up and removal from done list must be done at splbio()
		 * to avoid conflicts with swap_pager_iodone.
		 */
		while ((spc = swap_pager_done.tqh_first) != 0) {
			pmap_qremove(spc->spc_kva, spc->spc_count);
			swap_pager_finish(spc);
			TAILQ_REMOVE(&swap_pager_done, spc, spc_list);
			goto doclean;
		}

		/*
		 * No operations done, thats all we can do for now.
		 */

		splx(s);
		break;

		/*
		 * The desired page was found to be busy earlier in the scan
		 * but has since completed.
		 */
doclean:
		if (tspc && tspc == spc) {
			tspc = NULL;
		}
		spc->spc_flags = 0;
		TAILQ_INSERT_TAIL(&swap_pager_free, spc, spc_list);
		if (swap_pager_needflags & SWAP_FREE_NEEDED) {
			wakeup(&swap_pager_free);
		}
		if( swap_pager_needflags & SWAP_FREE_NEEDED_BY_PAGEOUT)
			pagedaemon_wakeup();
		swap_pager_needflags &= ~(SWAP_FREE_NEEDED|SWAP_FREE_NEEDED_BY_PAGEOUT);
		splx(s);
	}

	return;
}

void
swap_pager_finish(spc)
	register swp_clean_t spc;
{
	vm_object_t object = spc->spc_m[0]->object;
	int i;

	object->paging_in_progress -= spc->spc_count;
	if ((object->paging_in_progress == 0) &&
	    (object->flags & OBJ_PIPWNT)) {
		object->flags &= ~OBJ_PIPWNT;
		wakeup(object);
	}

	/*
	 * If no error, mark as clean and inform the pmap system. If error,
	 * mark as dirty so we will try again. (XXX could get stuck doing
	 * this, should give up after awhile)
	 */
	if (spc->spc_flags & SPC_ERROR) {
		for (i = 0; i < spc->spc_count; i++) {
			printf("swap_pager_finish: I/O error, clean of page %lx failed\n",
			    (u_long) VM_PAGE_TO_PHYS(spc->spc_m[i]));
		}
	} else {
		for (i = 0; i < spc->spc_count; i++) {
			pmap_clear_modify(VM_PAGE_TO_PHYS(spc->spc_m[i]));
			spc->spc_m[i]->dirty = 0;
			if ((spc->spc_m[i]->flags & PG_ACTIVE) == 0 &&
			    ((spc->spc_m[i]->flags & PG_WANTED) || pmap_is_referenced(VM_PAGE_TO_PHYS(spc->spc_m[i]))))
				vm_page_activate(spc->spc_m[i]);
		}
	}


	for (i = 0; i < spc->spc_count; i++) {
		/*
		 * we wakeup any processes that are waiting on these pages.
		 */
		PAGE_WAKEUP(spc->spc_m[i]);
	}
	nswiodone -= spc->spc_count;

	return;
}

/*
 * swap_pager_iodone
 */
void
swap_pager_iodone(bp)
	register struct buf *bp;
{
	register swp_clean_t spc;
	int s;

	s = splbio();
	spc = (swp_clean_t) bp->b_spc;
	TAILQ_REMOVE(&swap_pager_inuse, spc, spc_list);
	TAILQ_INSERT_TAIL(&swap_pager_done, spc, spc_list);
	if (bp->b_flags & B_ERROR) {
		spc->spc_flags |= SPC_ERROR;
		printf("swap_pager: I/O error - async %s failed; blkno %lu, size %ld, error %d\n",
		    (bp->b_flags & B_READ) ? "pagein" : "pageout",
		    (u_long) bp->b_blkno, bp->b_bcount, bp->b_error);
	}

	if (bp->b_vp)
		pbrelvp(bp);

	if (bp->b_flags & B_WANTED)
		wakeup(bp);

	if (bp->b_rcred != NOCRED)
		crfree(bp->b_rcred);
	if (bp->b_wcred != NOCRED)
		crfree(bp->b_wcred);

	nswiodone += spc->spc_count;
	if (--spc->spc_object->un_pager.swp.swp_poip == 0) {
		wakeup(spc->spc_object);
	}
	if ((swap_pager_needflags & SWAP_FREE_NEEDED) ||
	    swap_pager_inuse.tqh_first == 0) {
		swap_pager_needflags &= ~SWAP_FREE_NEEDED;
		wakeup(&swap_pager_free);
	}

	if( swap_pager_needflags & SWAP_FREE_NEEDED_BY_PAGEOUT) {
		swap_pager_needflags &= ~SWAP_FREE_NEEDED_BY_PAGEOUT;
		pagedaemon_wakeup();
	}

	if (vm_pageout_pages_needed) {
		wakeup(&vm_pageout_pages_needed);
		vm_pageout_pages_needed = 0;
	}
	if ((swap_pager_inuse.tqh_first == NULL) ||
	    ((cnt.v_free_count + cnt.v_cache_count) < cnt.v_free_min &&
	    nswiodone + cnt.v_free_count + cnt.v_cache_count >= cnt.v_free_min)) {
		pagedaemon_wakeup();
	}
	splx(s);
}

/*
 * return true if any swap control structures can be allocated
 */
int
swap_pager_ready()
{
	if (swap_pager_free.tqh_first)
		return 1;
	else
		return 0;
}
