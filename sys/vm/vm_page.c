/*
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
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
 *	from: @(#)vm_page.c	7.4 (Berkeley) 5/7/91
 *	$Id: vm_page.c,v 1.128 1999/03/19 05:21:03 alc Exp $
 */

/*
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Authors: Avadis Tevanian, Jr., Michael Wayne Young
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

/*
 *	Resident memory management module.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_prot.h>
#include <sys/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

static void	vm_page_queue_init __P((void));
static vm_page_t vm_page_select_cache __P((vm_object_t, vm_pindex_t));

/*
 *	Associated with page of user-allocatable memory is a
 *	page structure.
 */

static struct vm_page **vm_page_buckets; /* Array of buckets */
static int vm_page_bucket_count;	/* How big is array? */
static int vm_page_hash_mask;		/* Mask for hash function */
static volatile int vm_page_bucket_generation;

struct pglist vm_page_queue_free[PQ_L2_SIZE] = {{0}};
struct pglist vm_page_queue_active = {0};
struct pglist vm_page_queue_inactive = {0};
struct pglist vm_page_queue_cache[PQ_L2_SIZE] = {{0}};

static int no_queue=0;

struct vpgqueues vm_page_queues[PQ_COUNT] = {{0}};
static int pqcnt[PQ_COUNT] = {0};

static void
vm_page_queue_init(void) {
	int i;

	vm_page_queues[PQ_NONE].pl = NULL;
	vm_page_queues[PQ_NONE].cnt = &no_queue;
	for(i=0;i<PQ_L2_SIZE;i++) {
		vm_page_queues[PQ_FREE+i].pl = &vm_page_queue_free[i];
		vm_page_queues[PQ_FREE+i].cnt = &cnt.v_free_count;
	}
	vm_page_queues[PQ_INACTIVE].pl = &vm_page_queue_inactive;
	vm_page_queues[PQ_INACTIVE].cnt = &cnt.v_inactive_count;

	vm_page_queues[PQ_ACTIVE].pl = &vm_page_queue_active;
	vm_page_queues[PQ_ACTIVE].cnt = &cnt.v_active_count;
	for(i=0;i<PQ_L2_SIZE;i++) {
		vm_page_queues[PQ_CACHE+i].pl = &vm_page_queue_cache[i];
		vm_page_queues[PQ_CACHE+i].cnt = &cnt.v_cache_count;
	}
	for(i=0;i<PQ_COUNT;i++) {
		if (vm_page_queues[i].pl) {
			TAILQ_INIT(vm_page_queues[i].pl);
		} else if (i != 0) {
			panic("vm_page_queue_init: queue %d is null", i);
		}
		vm_page_queues[i].lcnt = &pqcnt[i];
	}
}

vm_page_t vm_page_array = 0;
static int vm_page_array_size = 0;
long first_page = 0;
static long last_page;
static vm_size_t page_mask;
static int page_shift;
int vm_page_zero_count = 0;

static __inline int vm_page_hash __P((vm_object_t object, vm_pindex_t pindex));
static void vm_page_free_wakeup __P((void));

/*
 *	vm_set_page_size:
 *
 *	Sets the page size, perhaps based upon the memory
 *	size.  Must be called before any use of page-size
 *	dependent functions.
 *
 *	Sets page_shift and page_mask from cnt.v_page_size.
 */
void
vm_set_page_size()
{

	if (cnt.v_page_size == 0)
		cnt.v_page_size = DEFAULT_PAGE_SIZE;
	page_mask = cnt.v_page_size - 1;
	if ((page_mask & cnt.v_page_size) != 0)
		panic("vm_set_page_size: page size not a power of two");
	for (page_shift = 0;; page_shift++)
		if ((1 << page_shift) == cnt.v_page_size)
			break;
}

/*
 *	vm_page_startup:
 *
 *	Initializes the resident memory module.
 *
 *	Allocates memory for the page cells, and
 *	for the object/offset-to-page hash table headers.
 *	Each page cell is initialized and placed on the free list.
 */

vm_offset_t
vm_page_startup(starta, enda, vaddr)
	register vm_offset_t starta;
	vm_offset_t enda;
	register vm_offset_t vaddr;
{
	register vm_offset_t mapped;
	register vm_page_t m;
	register struct vm_page **bucket;
	vm_size_t npages, page_range;
	register vm_offset_t new_start;
	int i;
	vm_offset_t pa;
	int nblocks;
	vm_offset_t first_managed_page;

	/* the biggest memory array is the second group of pages */
	vm_offset_t start;
	vm_offset_t biggestone, biggestsize;

	vm_offset_t total;

	total = 0;
	biggestsize = 0;
	biggestone = 0;
	nblocks = 0;
	vaddr = round_page(vaddr);

	for (i = 0; phys_avail[i + 1]; i += 2) {
		phys_avail[i] = round_page(phys_avail[i]);
		phys_avail[i + 1] = trunc_page(phys_avail[i + 1]);
	}

	for (i = 0; phys_avail[i + 1]; i += 2) {
		int size = phys_avail[i + 1] - phys_avail[i];

		if (size > biggestsize) {
			biggestone = i;
			biggestsize = size;
		}
		++nblocks;
		total += size;
	}

	start = phys_avail[biggestone];

	/*
	 * Initialize the queue headers for the free queue, the active queue
	 * and the inactive queue.
	 */

	vm_page_queue_init();

	/*
	 * Allocate (and initialize) the hash table buckets.
	 *
	 * The number of buckets MUST BE a power of 2, and the actual value is
	 * the next power of 2 greater than the number of physical pages in
	 * the system.  
	 *
	 * We make the hash table approximately 2x the number of pages to
	 * reduce the chain length.  This is about the same size using the 
	 * singly-linked list as the 1x hash table we were using before 
	 * using TAILQ but the chain length will be smaller.
	 *
	 * Note: This computation can be tweaked if desired.
	 */
	vm_page_buckets = (struct vm_page **)vaddr;
	bucket = vm_page_buckets;
	if (vm_page_bucket_count == 0) {
		vm_page_bucket_count = 1;
		while (vm_page_bucket_count < atop(total))
			vm_page_bucket_count <<= 1;
	}
	vm_page_bucket_count <<= 1;
	vm_page_hash_mask = vm_page_bucket_count - 1;

	/*
	 * Validate these addresses.
	 */

	new_start = start + vm_page_bucket_count * sizeof(struct vm_page *);
	new_start = round_page(new_start);
	mapped = round_page(vaddr);
	vaddr = pmap_map(mapped, start, new_start,
	    VM_PROT_READ | VM_PROT_WRITE);
	start = new_start;
	vaddr = round_page(vaddr);
	bzero((caddr_t) mapped, vaddr - mapped);

	for (i = 0; i < vm_page_bucket_count; i++) {
		*bucket = NULL;
		bucket++;
	}

	/*
	 * Compute the number of pages of memory that will be available for
	 * use (taking into account the overhead of a page structure per
	 * page).
	 */

	first_page = phys_avail[0] / PAGE_SIZE;
	last_page = phys_avail[(nblocks - 1) * 2 + 1] / PAGE_SIZE;

	page_range = last_page - (phys_avail[0] / PAGE_SIZE);
	npages = (total - (page_range * sizeof(struct vm_page)) -
	    (start - phys_avail[biggestone])) / PAGE_SIZE;

	/*
	 * Initialize the mem entry structures now, and put them in the free
	 * queue.
	 */
	vm_page_array = (vm_page_t) vaddr;
	mapped = vaddr;

	/*
	 * Validate these addresses.
	 */
	new_start = round_page(start + page_range * sizeof(struct vm_page));
	mapped = pmap_map(mapped, start, new_start,
	    VM_PROT_READ | VM_PROT_WRITE);
	start = new_start;

	first_managed_page = start / PAGE_SIZE;

	/*
	 * Clear all of the page structures
	 */
	bzero((caddr_t) vm_page_array, page_range * sizeof(struct vm_page));
	vm_page_array_size = page_range;

	/*
	 * Construct the free queue(s) in descending order (by physical
	 * address) so that the first 16MB of physical memory is allocated
	 * last rather than first.  On large-memory machines, this avoids
	 * the exhaustion of low physical memory before isa_dmainit has run.
	 */
	cnt.v_page_count = 0;
	cnt.v_free_count = 0;
	for (i = 0; phys_avail[i + 1] && npages > 0; i += 2) {
		if (i == biggestone)
			pa = ptoa(first_managed_page);
		else
			pa = phys_avail[i];
		while (pa < phys_avail[i + 1] && npages-- > 0) {
			++cnt.v_page_count;
			++cnt.v_free_count;
			m = PHYS_TO_VM_PAGE(pa);
			m->phys_addr = pa;
			m->flags = 0;
			m->pc = (pa >> PAGE_SHIFT) & PQ_L2_MASK;
			m->queue = m->pc + PQ_FREE;
			TAILQ_INSERT_HEAD(vm_page_queues[m->queue].pl, m, pageq);
			++(*vm_page_queues[m->queue].lcnt);
			pa += PAGE_SIZE;
		}
	}
	return (mapped);
}

/*
 *	vm_page_hash:
 *
 *	Distributes the object/offset key pair among hash buckets.
 *
 *	NOTE:  This macro depends on vm_page_bucket_count being a power of 2.
 *	This routine may not block.
 *
 *	We try to randomize the hash based on the object to spread the pages
 *	out in the hash table without it costing us too much.
 */
static __inline int
vm_page_hash(object, pindex)
	vm_object_t object;
	vm_pindex_t pindex;
{
	int i = ((uintptr_t)object + pindex) ^ object->hash_rand;

	return(i & vm_page_hash_mask);
}

/*
 *	vm_page_insert:		[ internal use only ]
 *
 *	Inserts the given mem entry into the object and object list.
 *
 *	The pagetables are not updated but will presumably fault the page
 *	in if necessary, or if a kernel page the caller will at some point
 *	enter the page into the kernel's pmap.  We are not allowed to block
 *	here so we *can't* do this anyway.
 *
 *	The object and page must be locked, and must be splhigh.
 *	This routine may not block.
 */

void
vm_page_insert(m, object, pindex)
	register vm_page_t m;
	register vm_object_t object;
	register vm_pindex_t pindex;
{
	register struct vm_page **bucket;

	if (m->object != NULL)
		panic("vm_page_insert: already inserted");

	/*
	 * Record the object/offset pair in this page
	 */

	m->object = object;
	m->pindex = pindex;

	/*
	 * Insert it into the object_object/offset hash table
	 */

	bucket = &vm_page_buckets[vm_page_hash(object, pindex)];
	m->hnext = *bucket;
	*bucket = m;
	vm_page_bucket_generation++;

	/*
	 * Now link into the object's list of backed pages.
	 */

	TAILQ_INSERT_TAIL(&object->memq, m, listq);
	m->object->generation++;

	if (m->wire_count)
		object->wire_count++;

	if ((m->queue - m->pc) == PQ_CACHE)
		object->cache_count++;

	/*
	 * show that the object has one more resident page.
	 */

	object->resident_page_count++;

	/*
	 * Since we are inserting a new and possibly dirty page,
	 * update the object's OBJ_WRITEABLE and OBJ_MIGHTBEDIRTY flags.
	 */
	if (m->flags & PG_WRITEABLE)
	    vm_object_set_flag(object, OBJ_WRITEABLE|OBJ_MIGHTBEDIRTY);
}

/*
 *	vm_page_remove:
 *				NOTE: used by device pager as well -wfj
 *
 *	Removes the given mem entry from the object/offset-page
 *	table and the object page list, but do not invalidate/terminate
 *	the backing store.
 *
 *	The object and page must be locked, and at splhigh.
 *	The underlying pmap entry (if any) is NOT removed here.
 *	This routine may not block.
 */

void
vm_page_remove(m)
	vm_page_t m;
{
	vm_object_t object;

	if (m->object == NULL)
		return;

#if !defined(MAX_PERF)
	if ((m->flags & PG_BUSY) == 0) {
		panic("vm_page_remove: page not busy");
	}
#endif

	/*
	 * Basically destroy the page.
	 */

	vm_page_wakeup(m);

	object = m->object;

	if (m->wire_count)
		object->wire_count--;

	if ((m->queue - m->pc) == PQ_CACHE) 
		object->cache_count--;

	/*
	 * Remove from the object_object/offset hash table.  The object
	 * must be on the hash queue, we will panic if it isn't
	 *
	 * Note: we must NULL-out m->hnext to prevent loops in detached
	 * buffers with vm_page_lookup().
	 */

	{
		struct vm_page **bucket;

		bucket = &vm_page_buckets[vm_page_hash(m->object, m->pindex)];
		while (*bucket != m) {
#if !defined(MAX_PERF)
			if (*bucket == NULL)
				panic("vm_page_remove(): page not found in hash");
#endif
			bucket = &(*bucket)->hnext;
		}
		*bucket = m->hnext;
		m->hnext = NULL;
		vm_page_bucket_generation++;
	}

	/*
	 * Now remove from the object's list of backed pages.
	 */

	TAILQ_REMOVE(&object->memq, m, listq);

	/*
	 * And show that the object has one fewer resident page.
	 */

	object->resident_page_count--;
	object->generation++;

	m->object = NULL;
}

/*
 *	vm_page_lookup:
 *
 *	Returns the page associated with the object/offset
 *	pair specified; if none is found, NULL is returned.
 *
 *	NOTE: the code below does not lock.  It will operate properly if
 *	an interrupt makes a change, but the generation algorithm will not 
 *	operate properly in an SMP environment where both cpu's are able to run
 *	kernel code simultaniously.
 *
 *	The object must be locked.  No side effects.
 *	This routine may not block.
 *	This is a critical path routine
 */

vm_page_t
vm_page_lookup(object, pindex)
	register vm_object_t object;
	register vm_pindex_t pindex;
{
	register vm_page_t m;
	register struct vm_page **bucket;
	int generation;

	/*
	 * Search the hash table for this object/offset pair
	 */

retry:
	generation = vm_page_bucket_generation;
	bucket = &vm_page_buckets[vm_page_hash(object, pindex)];
	for (m = *bucket; m != NULL; m = m->hnext) {
		if ((m->object == object) && (m->pindex == pindex)) {
			if (vm_page_bucket_generation != generation)
				goto retry;
			return (m);
		}
	}
	if (vm_page_bucket_generation != generation)
		goto retry;
	return (NULL);
}

/*
 *	vm_page_rename:
 *
 *	Move the given memory entry from its
 *	current object to the specified target object/offset.
 *
 *	The object must be locked.
 *	This routine may not block.
 *
 *	Note: this routine will raise itself to splvm(), the caller need not. 
 *
 *	Note: swap associated with the page must be invalidated by the move.  We
 *	      have to do this for several reasons:  (1) we aren't freeing the
 *	      page, (2) we are dirtying the page, (3) the VM system is probably
 *	      moving the page from object A to B, and will then later move
 *	      the backing store from A to B and we can't have a conflict.
 *
 *	Note: we *always* dirty the page.  It is necessary both for the
 *	      fact that we moved it, and because we may be invalidating
 *	      swap.  If the page is on the cache, we have to deactivate it
 *	      or vm_page_dirty() will panic.  Dirty pages are not allowed
 *	      on the cache.
 */

void
vm_page_rename(m, new_object, new_pindex)
	register vm_page_t m;
	register vm_object_t new_object;
	vm_pindex_t new_pindex;
{
	int s;

	s = splvm();
	vm_page_remove(m);
	vm_page_insert(m, new_object, new_pindex);
	if (m->queue - m->pc == PQ_CACHE)
		vm_page_deactivate(m);
	vm_page_dirty(m);
	splx(s);
}

/*
 * vm_page_unqueue_nowakeup:
 *
 * 	vm_page_unqueue() without any wakeup
 *
 *	This routine must be called at splhigh().
 *	This routine may not block.
 */

void
vm_page_unqueue_nowakeup(m)
	vm_page_t m;
{
	int queue = m->queue;
	struct vpgqueues *pq;
	if (queue != PQ_NONE) {
		pq = &vm_page_queues[queue];
		m->queue = PQ_NONE;
		TAILQ_REMOVE(pq->pl, m, pageq);
		(*pq->cnt)--;
		(*pq->lcnt)--;
		if ((queue - m->pc) == PQ_CACHE) {
			if (m->object)
				m->object->cache_count--;
		}
	}
}

/*
 * vm_page_unqueue:
 *
 *	Remove a page from its queue.
 *
 *	This routine must be called at splhigh().
 *	This routine may not block.
 */

void
vm_page_unqueue(m)
	vm_page_t m;
{
	int queue = m->queue;
	struct vpgqueues *pq;
	if (queue != PQ_NONE) {
		m->queue = PQ_NONE;
		pq = &vm_page_queues[queue];
		TAILQ_REMOVE(pq->pl, m, pageq);
		(*pq->cnt)--;
		(*pq->lcnt)--;
		if ((queue - m->pc) == PQ_CACHE) {
			if ((cnt.v_cache_count + cnt.v_free_count) <
				(cnt.v_free_reserved + cnt.v_cache_min))
				pagedaemon_wakeup();
			if (m->object)
				m->object->cache_count--;
		}
	}
}

#if PQ_L2_SIZE > 1

/*
 *	vm_page_list_find:
 *
 *	Find a page on the specified queue with color optimization.
 *
 *	The page coloring optimization attempts to locate a page
 *	that does not overload other nearby pages in the object in
 *	the cpu's L1 or L2 caches.  We need this optmization because 
 *	cpu caches tend to be physical caches, while object spaces tend 
 *	to be virtual.
 *
 *	This routine must be called at splvm().
 *	This routine may not block.
 *
 *	This routine may only be called from the vm_page_list_find() macro
 *	in vm_page.h
 */
vm_page_t
_vm_page_list_find(basequeue, index)
	int basequeue, index;
{
	int i;
	vm_page_t m = NULL;
	struct vpgqueues *pq;

	pq = &vm_page_queues[basequeue];

	/*
	 * Note that for the first loop, index+i and index-i wind up at the
	 * same place.  Even though this is not totally optimal, we've already
	 * blown it by missing the cache case so we do not care.
	 */

	for(i = PQ_L2_SIZE / 2; i > 0; --i) {
		if ((m = TAILQ_FIRST(pq[(index + i) & PQ_L2_MASK].pl)) != NULL)
			break;

		if ((m = TAILQ_FIRST(pq[(index - i) & PQ_L2_MASK].pl)) != NULL)
			break;
	}
	return(m);
}

#endif

/*
 *	vm_page_select_cache:
 *
 *	Find a page on the cache queue with color optimization.  As pages
 *	might be found, but not applicable, they are deactivated.  This
 *	keeps us from using potentially busy cached pages.
 *
 *	This routine must be called at splvm().
 *	This routine may not block.
 */
vm_page_t
vm_page_select_cache(object, pindex)
	vm_object_t object;
	vm_pindex_t pindex;
{
	vm_page_t m;

	while (TRUE) {
		m = vm_page_list_find(
		    PQ_CACHE,
		    (pindex + object->pg_color) & PQ_L2_MASK,
		    FALSE
		);
		if (m && ((m->flags & PG_BUSY) || m->busy ||
			       m->hold_count || m->wire_count)) {
			vm_page_deactivate(m);
			continue;
		}
		return m;
	}
}

/*
 *	vm_page_select_free:
 *
 *	Find a free or zero page, with specified preference.  We attempt to
 *	inline the nominal case and fall back to _vm_page_select_free() 
 *	otherwise.
 *
 *	This routine must be called at splvm().
 *	This routine may not block.
 */

static __inline vm_page_t
vm_page_select_free(vm_object_t object, vm_pindex_t pindex, boolean_t prefer_zero)
{
	vm_page_t m;

	m = vm_page_list_find(
		PQ_FREE,
		(pindex + object->pg_color) & PQ_L2_MASK,
		prefer_zero
	);
	return(m);
}

/*
 *	vm_page_alloc:
 *
 *	Allocate and return a memory cell associated
 *	with this VM object/offset pair.
 *
 *	page_req classes:
 *	VM_ALLOC_NORMAL		normal process request
 *	VM_ALLOC_SYSTEM		system *really* needs a page
 *	VM_ALLOC_INTERRUPT	interrupt time request
 *	VM_ALLOC_ZERO		zero page
 *
 *	Object must be locked.
 *	This routine may not block.
 *
 *	Additional special handling is required when called from an
 *	interrupt (VM_ALLOC_INTERRUPT).  We are not allowed to mess with
 *	the page cache in this case.
 */

vm_page_t
vm_page_alloc(object, pindex, page_req)
	vm_object_t object;
	vm_pindex_t pindex;
	int page_req;
{
	register vm_page_t m = NULL;
	int s;

	KASSERT(!vm_page_lookup(object, pindex),
		("vm_page_alloc: page already allocated"));

	/*
	 * The pager is allowed to eat deeper into the free page list.
	 */

	if ((curproc == pageproc) && (page_req != VM_ALLOC_INTERRUPT)) {
		page_req = VM_ALLOC_SYSTEM;
	};

	s = splvm();

loop:
	if (cnt.v_free_count > cnt.v_free_reserved) {
		/*
		 * Allocate from the free queue if there are plenty of pages
		 * in it.
		 */
		if (page_req == VM_ALLOC_ZERO)
			m = vm_page_select_free(object, pindex, TRUE);
		else
			m = vm_page_select_free(object, pindex, FALSE);
	} else if (
	    (page_req == VM_ALLOC_SYSTEM && 
	     cnt.v_cache_count == 0 && 
	     cnt.v_free_count > cnt.v_interrupt_free_min) ||
	    (page_req == VM_ALLOC_INTERRUPT && cnt.v_free_count > 0)
	) {
		/*
		 * Interrupt or system, dig deeper into the free list.
		 */
		m = vm_page_select_free(object, pindex, FALSE);
	} else if (page_req != VM_ALLOC_INTERRUPT) {
		/*
		 * Allocateable from cache (non-interrupt only).  On success,
		 * we must free the page and try again, thus ensuring that
		 * cnt.v_*_free_min counters are replenished.
		 */
		m = vm_page_select_cache(object, pindex);
		if (m == NULL) {
			splx(s);
#if defined(DIAGNOSTIC)
			if (cnt.v_cache_count > 0)
				printf("vm_page_alloc(NORMAL): missing pages on cache queue: %d\n", cnt.v_cache_count);
#endif
			vm_pageout_deficit++;
			pagedaemon_wakeup();
			return (NULL);
		}
		KASSERT(m->dirty == 0, ("Found dirty cache page %p", m));
		vm_page_busy(m);
		vm_page_protect(m, VM_PROT_NONE);
		vm_page_free(m);
		goto loop;
	} else {
		/*
		 * Not allocateable from cache from interrupt, give up.
		 */
		splx(s);
		vm_pageout_deficit++;
		pagedaemon_wakeup();
		return (NULL);
	}

	/*
	 *  At this point we had better have found a good page.
	 */

	KASSERT(
	    m != NULL,
	    ("vm_page_alloc(): missing page on free queue\n")
	);

	/*
	 * Remove from free queue
	 */

	{
		struct vpgqueues *pq = &vm_page_queues[m->queue];

		TAILQ_REMOVE(pq->pl, m, pageq);
		(*pq->cnt)--;
		(*pq->lcnt)--;
	}

	/*
	 * Initialize structure.  Only the PG_ZERO flag is inherited.
	 */

	if (m->flags & PG_ZERO) {
		vm_page_zero_count--;
		m->flags = PG_ZERO | PG_BUSY;
	} else {
		m->flags = PG_BUSY;
	}
	m->wire_count = 0;
	m->hold_count = 0;
	m->act_count = 0;
	m->busy = 0;
	m->valid = 0;
	m->dirty = 0;
	m->queue = PQ_NONE;

	/*
	 * vm_page_insert() is safe prior to the splx().  Note also that
	 * inserting a page here does not insert it into the pmap (which
	 * could cause us to block allocating memory).  We cannot block 
	 * anywhere.
	 */

	vm_page_insert(m, object, pindex);

	/*
	 * Don't wakeup too often - wakeup the pageout daemon when
	 * we would be nearly out of memory.
	 */
	if (((cnt.v_free_count + cnt.v_cache_count) <
		(cnt.v_free_reserved + cnt.v_cache_min)) ||
			(cnt.v_free_count < cnt.v_pageout_free_min))
		pagedaemon_wakeup();

	splx(s);

	return (m);
}

/*
 *	vm_wait:	(also see VM_WAIT macro)
 *
 *	Block until free pages are available for allocation
 */

void
vm_wait()
{
	int s;

	s = splvm();
	if (curproc == pageproc) {
		vm_pageout_pages_needed = 1;
		tsleep(&vm_pageout_pages_needed, PSWP, "vmwait", 0);
	} else {
		if (!vm_pages_needed) {
			vm_pages_needed++;
			wakeup(&vm_pages_needed);
		}
		tsleep(&cnt.v_free_count, PVM, "vmwait", 0);
	}
	splx(s);
}

/*
 *	vm_await:	(also see VM_AWAIT macro)
 *
 *	asleep on an event that will signal when free pages are available
 *	for allocation.
 */

void
vm_await()
{
	int s;

	s = splvm();
	if (curproc == pageproc) {
		vm_pageout_pages_needed = 1;
		asleep(&vm_pageout_pages_needed, PSWP, "vmwait", 0);
	} else {
		if (!vm_pages_needed) {
			vm_pages_needed++;
			wakeup(&vm_pages_needed);
		}
		asleep(&cnt.v_free_count, PVM, "vmwait", 0);
	}
	splx(s);
}

#if 0
/*
 *	vm_page_sleep:
 *
 *	Block until page is no longer busy.
 */

int
vm_page_sleep(vm_page_t m, char *msg, char *busy) {
	int slept = 0;
	if ((busy && *busy) || (m->flags & PG_BUSY)) {
		int s;
		s = splvm();
		if ((busy && *busy) || (m->flags & PG_BUSY)) {
			vm_page_flag_set(m, PG_WANTED);
			tsleep(m, PVM, msg, 0);
			slept = 1;
		}
		splx(s);
	}
	return slept;
}

#endif

#if 0

/*
 *	vm_page_asleep:
 *
 *	Similar to vm_page_sleep(), but does not block.  Returns 0 if
 *	the page is not busy, or 1 if the page is busy.
 *
 *	This routine has the side effect of calling asleep() if the page
 *	was busy (1 returned).
 */

int
vm_page_asleep(vm_page_t m, char *msg, char *busy) {
	int slept = 0;
	if ((busy && *busy) || (m->flags & PG_BUSY)) {
		int s;
		s = splvm();
		if ((busy && *busy) || (m->flags & PG_BUSY)) {
			vm_page_flag_set(m, PG_WANTED);
			asleep(m, PVM, msg, 0);
			slept = 1;
		}
		splx(s);
	}
	return slept;
}

#endif

/*
 *	vm_page_activate:
 *
 *	Put the specified page on the active list (if appropriate).
 *
 *	The page queues must be locked.
 *	This routine may not block.
 */
void
vm_page_activate(m)
	register vm_page_t m;
{
	int s;

	s = splvm();
	if (m->queue != PQ_ACTIVE) {
		if ((m->queue - m->pc) == PQ_CACHE)
			cnt.v_reactivated++;

		vm_page_unqueue(m);

		if (m->wire_count == 0) {
			m->queue = PQ_ACTIVE;
			++(*vm_page_queues[PQ_ACTIVE].lcnt);
			TAILQ_INSERT_TAIL(&vm_page_queue_active, m, pageq);
			if (m->act_count < ACT_INIT)
				m->act_count = ACT_INIT;
			cnt.v_active_count++;
		}
	} else {
		if (m->act_count < ACT_INIT)
			m->act_count = ACT_INIT;
	}

	splx(s);
}

/*
 *	vm_page_free_wakeup:
 *
 *	Helper routine for vm_page_free_toq() and vm_page_cache().  This
 *	routine is called when a page has been added to the cache or free
 *	queues.
 *
 *	This routine may not block.
 *	This routine must be called at splvm()
 */
static __inline void
vm_page_free_wakeup()
{
	/*
	 * if pageout daemon needs pages, then tell it that there are
	 * some free.
	 */
	if (vm_pageout_pages_needed) {
		wakeup(&vm_pageout_pages_needed);
		vm_pageout_pages_needed = 0;
	}
	/*
	 * wakeup processes that are waiting on memory if we hit a
	 * high water mark. And wakeup scheduler process if we have
	 * lots of memory. this process will swapin processes.
	 */
	if (vm_pages_needed &&
		((cnt.v_free_count + cnt.v_cache_count) >= cnt.v_free_min)) {
		wakeup(&cnt.v_free_count);
		vm_pages_needed = 0;
	}
}

/*
 *	vm_page_free_toq:
 *
 *	Returns the given page to the PQ_FREE or PQ_ZERO list,
 *	disassociating it with any VM object.
 *
 *	Object and page must be locked prior to entry.
 *	This routine may not block.
 */

void
vm_page_free_toq(vm_page_t m)
{
	int s;
	struct vpgqueues *pq;
	vm_object_t object = m->object;

	s = splvm();

	cnt.v_tfree++;

#if !defined(MAX_PERF)
	if (m->busy || ((m->queue - m->pc) == PQ_FREE) ||
		(m->hold_count != 0)) {
		printf(
		"vm_page_free: pindex(%lu), busy(%d), PG_BUSY(%d), hold(%d)\n",
		    (u_long)m->pindex, m->busy, (m->flags & PG_BUSY) ? 1 : 0,
		    m->hold_count);
		if ((m->queue - m->pc) == PQ_FREE)
			panic("vm_page_free: freeing free page");
		else
			panic("vm_page_free: freeing busy page");
	}
#endif

	/*
	 * unqueue, then remove page.  Note that we cannot destroy
	 * the page here because we do not want to call the pager's
	 * callback routine until after we've put the page on the
	 * appropriate free queue.
	 */

	vm_page_unqueue_nowakeup(m);
	vm_page_remove(m);

	/*
	 * If fictitious remove object association and
	 * return, otherwise delay object association removal.
	 */

	if ((m->flags & PG_FICTITIOUS) != 0) {
		splx(s);
		return;
	}

	m->valid = 0;

	if (m->wire_count != 0) {
#if !defined(MAX_PERF)
		if (m->wire_count > 1) {
			panic("vm_page_free: invalid wire count (%d), pindex: 0x%x",
				m->wire_count, m->pindex);
		}
#endif
		printf("vm_page_free: freeing wired page\n");
		m->wire_count = 0;
		if (m->object)
			m->object->wire_count--;
		cnt.v_wire_count--;
	}

	/*
	 * If we've exhausted the object's resident pages we want to free
	 * it up.
	 */

	if (object && 
	    (object->type == OBJT_VNODE) &&
	    ((object->flags & OBJ_DEAD) == 0)
	) {
		struct vnode *vp = (struct vnode *)object->handle;

		if (vp && VSHOULDFREE(vp)) {
			if ((vp->v_flag & (VTBFREE|VDOOMED|VFREE)) == 0) {
				TAILQ_INSERT_TAIL(&vnode_tobefree_list, vp, v_freelist);
				vp->v_flag |= VTBFREE;
			}
		}
	}

#ifdef __alpha__
	pmap_page_is_free(m);
#endif

	m->queue = PQ_FREE + m->pc;
	pq = &vm_page_queues[m->queue];
	++(*pq->lcnt);
	++(*pq->cnt);

	/*
	 * Put zero'd pages on the end ( where we look for zero'd pages
	 * first ) and non-zerod pages at the head.
	 */

	if (m->flags & PG_ZERO) {
		TAILQ_INSERT_TAIL(pq->pl, m, pageq);
		++vm_page_zero_count;
	} else if (curproc == pageproc) {
		/*
		 * If the pageout daemon is freeing pages, the pages are 
		 * likely to NOT be in the L1 or L2 caches due to their age.
		 * For now we do not try to do anything special with this
		 * info.
		 */
		TAILQ_INSERT_HEAD(pq->pl, m, pageq);
	} else {
		TAILQ_INSERT_HEAD(pq->pl, m, pageq);
	}

	vm_page_free_wakeup();

	splx(s);
}

/*
 *	vm_page_wire:
 *
 *	Mark this page as wired down by yet
 *	another map, removing it from paging queues
 *	as necessary.
 *
 *	The page queues must be locked.
 *	This routine may not block.
 */
void
vm_page_wire(m)
	register vm_page_t m;
{
	int s;

	s = splvm();
	if (m->wire_count == 0) {
		vm_page_unqueue(m);
		cnt.v_wire_count++;
		if (m->object)
			m->object->wire_count++;
	}
	m->wire_count++;
	splx(s);
	(*vm_page_queues[PQ_NONE].lcnt)++;
	vm_page_flag_set(m, PG_MAPPED);
}

/*
 *	vm_page_unwire:
 *
 *	Release one wiring of this page, potentially
 *	enabling it to be paged again.
 *
 *	Many pages placed on the inactive queue should actually go
 *	into the cache, but it is difficult to figure out which.  What
 *	we do instead, if the inactive target is well met, is to put
 *	clean pages at the head of the inactive queue instead of the tail.
 *	This will cause them to be moved to the cache more quickly and
 *	if not actively re-referenced, freed more quickly.  If we just
 *	stick these pages at the end of the inactive queue, heavy filesystem
 *	meta-data accesses can cause an unnecessary paging load on memory bound 
 *	processes.  This optimization causes one-time-use metadata to be
 *	reused more quickly.
 *
 *	A number of routines use vm_page_unwire() to guarentee that the page
 *	will go into either the inactive or active queues, and will NEVER
 *	be placed in the cache - for example, just after dirtying a page.
 *	dirty pages in the cache are not allowed.
 *
 *	The page queues must be locked.
 *	This routine may not block.
 */
void
vm_page_unwire(m, activate)
	register vm_page_t m;
	int activate;
{
	int s;

	s = splvm();

	if (m->wire_count > 0) {
		m->wire_count--;
		if (m->wire_count == 0) {
			if (m->object)
				m->object->wire_count--;
			cnt.v_wire_count--;
			if (activate) {
				TAILQ_INSERT_TAIL(&vm_page_queue_active, m, pageq);
				m->queue = PQ_ACTIVE;
				(*vm_page_queues[PQ_ACTIVE].lcnt)++;
				cnt.v_active_count++;
			} else {
				TAILQ_INSERT_TAIL(&vm_page_queue_inactive, m, pageq);
				m->queue = PQ_INACTIVE;
				(*vm_page_queues[PQ_INACTIVE].lcnt)++;
				cnt.v_inactive_count++;
			}
		}
	} else {
#if !defined(MAX_PERF)
		panic("vm_page_unwire: invalid wire count: %d\n", m->wire_count);
#endif
	}
	splx(s);
}


/*
 * Move the specified page to the inactive queue.  If the page has
 * any associated swap, the swap is deallocated.
 *
 * This routine may not block.
 */
void
vm_page_deactivate(m)
	register vm_page_t m;
{
	int s;

	/*
	 * Ignore if already inactive.
	 */
	if (m->queue == PQ_INACTIVE)
		return;

	s = splvm();
	if (m->wire_count == 0) {
		if ((m->queue - m->pc) == PQ_CACHE)
			cnt.v_reactivated++;
		vm_page_unqueue(m);
		TAILQ_INSERT_TAIL(&vm_page_queue_inactive, m, pageq);
		m->queue = PQ_INACTIVE;
		++(*vm_page_queues[PQ_INACTIVE].lcnt);
		cnt.v_inactive_count++;
	}
	splx(s);
}

/*
 * vm_page_cache
 *
 * Put the specified page onto the page cache queue (if appropriate).
 *
 * This routine may not block.
 */
void
vm_page_cache(m)
	register vm_page_t m;
{
	int s;

#if !defined(MAX_PERF)
	if ((m->flags & PG_BUSY) || m->busy || m->wire_count) {
		printf("vm_page_cache: attempting to cache busy page\n");
		return;
	}
#endif
	if ((m->queue - m->pc) == PQ_CACHE)
		return;

	/*
	 * Remove all pmaps and indicate that the page is not
	 * writeable or mapped.
	 */

	vm_page_protect(m, VM_PROT_NONE);
#if !defined(MAX_PERF)
	if (m->dirty != 0) {
		panic("vm_page_cache: caching a dirty page, pindex: %d", m->pindex);
	}
#endif
	s = splvm();
	vm_page_unqueue_nowakeup(m);
	m->queue = PQ_CACHE + m->pc;
	(*vm_page_queues[m->queue].lcnt)++;
	TAILQ_INSERT_TAIL(vm_page_queues[m->queue].pl, m, pageq);
	cnt.v_cache_count++;
	m->object->cache_count++;
	vm_page_free_wakeup();
	splx(s);
}

/*
 * Grab a page, waiting until we are waken up due to the page
 * changing state.  We keep on waiting, if the page continues
 * to be in the object.  If the page doesn't exist, allocate it.
 *
 * This routine may block.
 */
vm_page_t
vm_page_grab(object, pindex, allocflags)
	vm_object_t object;
	vm_pindex_t pindex;
	int allocflags;
{

	vm_page_t m;
	int s, generation;

retrylookup:
	if ((m = vm_page_lookup(object, pindex)) != NULL) {
		if (m->busy || (m->flags & PG_BUSY)) {
			generation = object->generation;

			s = splvm();
			while ((object->generation == generation) &&
					(m->busy || (m->flags & PG_BUSY))) {
				vm_page_flag_set(m, PG_WANTED | PG_REFERENCED);
				tsleep(m, PVM, "pgrbwt", 0);
				if ((allocflags & VM_ALLOC_RETRY) == 0) {
					splx(s);
					return NULL;
				}
			}
			splx(s);
			goto retrylookup;
		} else {
			vm_page_busy(m);
			return m;
		}
	}

	m = vm_page_alloc(object, pindex, allocflags & ~VM_ALLOC_RETRY);
	if (m == NULL) {
		VM_WAIT;
		if ((allocflags & VM_ALLOC_RETRY) == 0)
			return NULL;
		goto retrylookup;
	}

	return m;
}

/*
 * Mapping function for valid bits or for dirty bits in
 * a page.  May not block.
 *
 * Inputs are required to range within a page.
 */

__inline int
vm_page_bits(int base, int size)
{
	int first_bit;
	int last_bit;

	KASSERT(
	    base + size <= PAGE_SIZE,
	    ("vm_page_bits: illegal base/size %d/%d", base, size)
	);

	if (size == 0)		/* handle degenerate case */
		return(0);

	first_bit = base >> DEV_BSHIFT;
	last_bit = (base + size - 1) >> DEV_BSHIFT;

	return ((2 << last_bit) - (1 << first_bit));
}

/*
 * set a page valid and clean.  May not block.
 *
 * In order to maintain consistancy due to the DEV_BSIZE granularity
 * of the valid bits, we have to zero non-DEV_BSIZE aligned portions of 
 * the page at the beginning and end of the valid range when the 
 * associated valid bits are not already set.
 *
 * (base + size) must be less then or equal to PAGE_SIZE.
 */
void
vm_page_set_validclean(m, base, size)
	vm_page_t m;
	int base;
	int size;
{
	int pagebits;
	int frag;
	int endoff;

	if (size == 0)	/* handle degenerate case */
		return;

	/*
	 * If the base is not DEV_BSIZE aligned and the valid
	 * bit is clear, we have to zero out a portion of the
	 * first block.
	 */

	if ((frag = base & ~(DEV_BSIZE - 1)) != base &&
	    (m->valid & (1 << (base >> DEV_BSHIFT))) == 0
	) {
		pmap_zero_page_area(
		    VM_PAGE_TO_PHYS(m),
		    frag,
		    base - frag
		);
	}

	/*
	 * If the ending offset is not DEV_BSIZE aligned and the 
	 * valid bit is clear, we have to zero out a portion of
	 * the last block.
	 */

	endoff = base + size;

	if ((frag = endoff & ~(DEV_BSIZE - 1)) != endoff &&
	    (m->valid & (1 << (endoff >> DEV_BSHIFT))) == 0
	) {
		pmap_zero_page_area(
		    VM_PAGE_TO_PHYS(m),
		    endoff,
		    DEV_BSIZE - (endoff & (DEV_BSIZE - 1))
		);
	}

	/*
	 * Set valid, clear dirty bits.  If validating the entire
	 * page we can safely clear the pmap modify bit.
	 */

	pagebits = vm_page_bits(base, size);
	m->valid |= pagebits;
	m->dirty &= ~pagebits;

	if (base == 0 && size == PAGE_SIZE)
		pmap_clear_modify(VM_PAGE_TO_PHYS(m));
}

/*
 * set a page (partially) invalid.  May not block.
 */
void
vm_page_set_invalid(m, base, size)
	vm_page_t m;
	int base;
	int size;
{
	int bits;

	m->valid &= ~(bits = vm_page_bits(base, size));
	if (m->valid == 0)
		m->dirty &= ~bits;
	m->object->generation++;
}

/*
 * vm_page_zero_invalid()
 *
 *	The kernel assumes that the invalid portions of a page contain 
 *	garbage, but such pages can be mapped into memory by user code.
 *	When this occurs, we must zero out the non-valid portions of the
 *	page so user code sees what it expects.
 *
 *	Pages are most often semi-valid when the end of a file is mapped 
 *	into memory and the file's size is not page aligned.
 */

void
vm_page_zero_invalid(vm_page_t m, boolean_t setvalid)
{
	int b;
	int i;

	/*
	 * Scan the valid bits looking for invalid sections that
	 * must be zerod.  Invalid sub-DEV_BSIZE'd areas ( where the
	 * valid bit may be set ) have already been zerod by
	 * vm_page_set_validclean().
	 */

	for (b = i = 0; i <= PAGE_SIZE / DEV_BSIZE; ++i) {
		if (i == (PAGE_SIZE / DEV_BSIZE) || 
		    (m->valid & (1 << i))
		) {
			if (i > b) {
				pmap_zero_page_area(
				    VM_PAGE_TO_PHYS(m), 
				    b << DEV_BSHIFT,
				    (i - b) << DEV_BSHIFT
				);
			}
			b = i + 1;
		}
	}

	/*
	 * setvalid is TRUE when we can safely set the zero'd areas
	 * as being valid.  We can do this if there are no cache consistancy
	 * issues.  e.g. it is ok to do with UFS, but not ok to do with NFS.
	 */

	if (setvalid)
		m->valid = VM_PAGE_BITS_ALL;
}

/*
 *	vm_page_is_valid:
 *
 *	Is (partial) page valid?  Note that the case where size == 0
 *	will return FALSE in the degenerate case where the page is
 *	entirely invalid, and TRUE otherwise.
 *
 *	May not block.
 */

int
vm_page_is_valid(m, base, size)
	vm_page_t m;
	int base;
	int size;
{
	int bits = vm_page_bits(base, size);

	if (m->valid && ((m->valid & bits) == bits))
		return 1;
	else
		return 0;
}

/*
 * update dirty bits from pmap/mmu.  May not block.
 */

void
vm_page_test_dirty(m)
	vm_page_t m;
{
	if ((m->dirty != VM_PAGE_BITS_ALL) &&
	    pmap_is_modified(VM_PAGE_TO_PHYS(m))) {
		vm_page_dirty(m);
	}
}

/*
 * This interface is for merging with malloc() someday.
 * Even if we never implement compaction so that contiguous allocation
 * works after initialization time, malloc()'s data structures are good
 * for statistics and for allocations of less than a page.
 */
void *
contigmalloc1(size, type, flags, low, high, alignment, boundary, map)
	unsigned long size;	/* should be size_t here and for malloc() */
	struct malloc_type *type;
	int flags;
	unsigned long low;
	unsigned long high;
	unsigned long alignment;
	unsigned long boundary;
	vm_map_t map;
{
	int i, s, start;
	vm_offset_t addr, phys, tmp_addr;
	int pass;
	vm_page_t pga = vm_page_array;

	size = round_page(size);
#if !defined(MAX_PERF)
	if (size == 0)
		panic("contigmalloc1: size must not be 0");
	if ((alignment & (alignment - 1)) != 0)
		panic("contigmalloc1: alignment must be a power of 2");
	if ((boundary & (boundary - 1)) != 0)
		panic("contigmalloc1: boundary must be a power of 2");
#endif

	start = 0;
	for (pass = 0; pass <= 1; pass++) {
		s = splvm();
again:
		/*
		 * Find first page in array that is free, within range, aligned, and
		 * such that the boundary won't be crossed.
		 */
		for (i = start; i < cnt.v_page_count; i++) {
			int pqtype;
			phys = VM_PAGE_TO_PHYS(&pga[i]);
			pqtype = pga[i].queue - pga[i].pc;
			if (((pqtype == PQ_FREE) || (pqtype == PQ_CACHE)) &&
			    (phys >= low) && (phys < high) &&
			    ((phys & (alignment - 1)) == 0) &&
			    (((phys ^ (phys + size - 1)) & ~(boundary - 1)) == 0))
				break;
		}

		/*
		 * If the above failed or we will exceed the upper bound, fail.
		 */
		if ((i == cnt.v_page_count) ||
			((VM_PAGE_TO_PHYS(&pga[i]) + size) > high)) {
			vm_page_t m, next;

again1:
			for (m = TAILQ_FIRST(&vm_page_queue_inactive);
				m != NULL;
				m = next) {

				if (m->queue != PQ_INACTIVE) {
					break;
				}

				next = TAILQ_NEXT(m, pageq);
				if (vm_page_sleep_busy(m, TRUE, "vpctw0"))
					goto again1;
				vm_page_test_dirty(m);
				if (m->dirty) {
					if (m->object->type == OBJT_VNODE) {
						vn_lock(m->object->handle, LK_EXCLUSIVE | LK_RETRY, curproc);
						vm_object_page_clean(m->object, 0, 0, OBJPC_SYNC);
						VOP_UNLOCK(m->object->handle, 0, curproc);
						goto again1;
					} else if (m->object->type == OBJT_SWAP ||
								m->object->type == OBJT_DEFAULT) {
						vm_pageout_flush(&m, 1, 0);
						goto again1;
					}
				}
				if ((m->dirty == 0) && (m->busy == 0) && (m->hold_count == 0))
					vm_page_cache(m);
			}

			for (m = TAILQ_FIRST(&vm_page_queue_active);
				m != NULL;
				m = next) {

				if (m->queue != PQ_ACTIVE) {
					break;
				}

				next = TAILQ_NEXT(m, pageq);
				if (vm_page_sleep_busy(m, TRUE, "vpctw1"))
					goto again1;
				vm_page_test_dirty(m);
				if (m->dirty) {
					if (m->object->type == OBJT_VNODE) {
						vn_lock(m->object->handle, LK_EXCLUSIVE | LK_RETRY, curproc);
						vm_object_page_clean(m->object, 0, 0, OBJPC_SYNC);
						VOP_UNLOCK(m->object->handle, 0, curproc);
						goto again1;
					} else if (m->object->type == OBJT_SWAP ||
								m->object->type == OBJT_DEFAULT) {
						vm_pageout_flush(&m, 1, 0);
						goto again1;
					}
				}
				if ((m->dirty == 0) && (m->busy == 0) && (m->hold_count == 0))
					vm_page_cache(m);
			}

			splx(s);
			continue;
		}
		start = i;

		/*
		 * Check successive pages for contiguous and free.
		 */
		for (i = start + 1; i < (start + size / PAGE_SIZE); i++) {
			int pqtype;
			pqtype = pga[i].queue - pga[i].pc;
			if ((VM_PAGE_TO_PHYS(&pga[i]) !=
			    (VM_PAGE_TO_PHYS(&pga[i - 1]) + PAGE_SIZE)) ||
			    ((pqtype != PQ_FREE) && (pqtype != PQ_CACHE))) {
				start++;
				goto again;
			}
		}

		for (i = start; i < (start + size / PAGE_SIZE); i++) {
			int pqtype;
			vm_page_t m = &pga[i];

			pqtype = m->queue - m->pc;
			if (pqtype == PQ_CACHE) {
				vm_page_busy(m);
				vm_page_free(m);
			}

			TAILQ_REMOVE(vm_page_queues[m->queue].pl, m, pageq);
			(*vm_page_queues[m->queue].lcnt)--;
			cnt.v_free_count--;
			m->valid = VM_PAGE_BITS_ALL;
			m->flags = 0;
			m->dirty = 0;
			m->wire_count = 0;
			m->busy = 0;
			m->queue = PQ_NONE;
			m->object = NULL;
			vm_page_wire(m);
		}

		/*
		 * We've found a contiguous chunk that meets are requirements.
		 * Allocate kernel VM, unfree and assign the physical pages to it and
		 * return kernel VM pointer.
		 */
		tmp_addr = addr = kmem_alloc_pageable(map, size);
		if (addr == 0) {
			/*
			 * XXX We almost never run out of kernel virtual
			 * space, so we don't make the allocated memory
			 * above available.
			 */
			splx(s);
			return (NULL);
		}

		for (i = start; i < (start + size / PAGE_SIZE); i++) {
			vm_page_t m = &pga[i];
			vm_page_insert(m, kernel_object,
				OFF_TO_IDX(tmp_addr - VM_MIN_KERNEL_ADDRESS));
			pmap_kenter(tmp_addr, VM_PAGE_TO_PHYS(m));
			tmp_addr += PAGE_SIZE;
		}

		splx(s);
		return ((void *)addr);
	}
	return NULL;
}

void *
contigmalloc(size, type, flags, low, high, alignment, boundary)
	unsigned long size;	/* should be size_t here and for malloc() */
	struct malloc_type *type;
	int flags;
	unsigned long low;
	unsigned long high;
	unsigned long alignment;
	unsigned long boundary;
{
	return contigmalloc1(size, type, flags, low, high, alignment, boundary,
			     kernel_map);
}

vm_offset_t
vm_page_alloc_contig(size, low, high, alignment)
	vm_offset_t size;
	vm_offset_t low;
	vm_offset_t high;
	vm_offset_t alignment;
{
	return ((vm_offset_t)contigmalloc1(size, M_DEVBUF, M_NOWAIT, low, high,
					  alignment, 0ul, kernel_map));
}

#include "opt_ddb.h"
#ifdef DDB
#include <sys/kernel.h>

#include <ddb/ddb.h>

DB_SHOW_COMMAND(page, vm_page_print_page_info)
{
	db_printf("cnt.v_free_count: %d\n", cnt.v_free_count);
	db_printf("cnt.v_cache_count: %d\n", cnt.v_cache_count);
	db_printf("cnt.v_inactive_count: %d\n", cnt.v_inactive_count);
	db_printf("cnt.v_active_count: %d\n", cnt.v_active_count);
	db_printf("cnt.v_wire_count: %d\n", cnt.v_wire_count);
	db_printf("cnt.v_free_reserved: %d\n", cnt.v_free_reserved);
	db_printf("cnt.v_free_min: %d\n", cnt.v_free_min);
	db_printf("cnt.v_free_target: %d\n", cnt.v_free_target);
	db_printf("cnt.v_cache_min: %d\n", cnt.v_cache_min);
	db_printf("cnt.v_inactive_target: %d\n", cnt.v_inactive_target);
}

DB_SHOW_COMMAND(pageq, vm_page_print_pageq_info)
{
	int i;
	db_printf("PQ_FREE:");
	for(i=0;i<PQ_L2_SIZE;i++) {
		db_printf(" %d", *vm_page_queues[PQ_FREE + i].lcnt);
	}
	db_printf("\n");
		
	db_printf("PQ_CACHE:");
	for(i=0;i<PQ_L2_SIZE;i++) {
		db_printf(" %d", *vm_page_queues[PQ_CACHE + i].lcnt);
	}
	db_printf("\n");

	db_printf("PQ_ACTIVE: %d, PQ_INACTIVE: %d\n",
		*vm_page_queues[PQ_ACTIVE].lcnt,
		*vm_page_queues[PQ_INACTIVE].lcnt);
}
#endif /* DDB */
