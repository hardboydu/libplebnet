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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

static int
vm_contig_launder(int queue)
{
	vm_object_t object;
	vm_page_t m, m_tmp, next;
	struct vnode *vp;

	for (m = TAILQ_FIRST(&vm_page_queues[queue].pl); m != NULL; m = next) {
		next = TAILQ_NEXT(m, pageq);
		KASSERT(m->queue == queue,
		    ("vm_contig_launder: page %p's queue is not %d", m, queue));
		if (!VM_OBJECT_TRYLOCK(m->object))
			continue;
		if (vm_page_sleep_if_busy(m, TRUE, "vpctw0")) {
			VM_OBJECT_UNLOCK(m->object);
			vm_page_lock_queues();
			return (TRUE);
		}
		vm_page_test_dirty(m);
		if (m->dirty == 0 && m->busy == 0 && m->hold_count == 0)
			pmap_remove_all(m);
		if (m->dirty) {
			object = m->object;
			if (object->type == OBJT_VNODE) {
				vm_page_unlock_queues();
				vp = object->handle;
				VM_OBJECT_UNLOCK(object);
				vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curthread);
				VM_OBJECT_LOCK(object);
				vm_object_page_clean(object, 0, 0, OBJPC_SYNC);
				VM_OBJECT_UNLOCK(object);
				VOP_UNLOCK(vp, 0, curthread);
				vm_page_lock_queues();
				return (TRUE);
			} else if (object->type == OBJT_SWAP ||
				   object->type == OBJT_DEFAULT) {
				m_tmp = m;
				vm_pageout_flush(&m_tmp, 1, VM_PAGER_PUT_SYNC);
				VM_OBJECT_UNLOCK(object);
				return (TRUE);
			}
		} else if (m->busy == 0 && m->hold_count == 0)
			vm_page_cache(m);
		VM_OBJECT_UNLOCK(m->object);
	}
	return (FALSE);
}

/*
 * This interface is for merging with malloc() someday.
 * Even if we never implement compaction so that contiguous allocation
 * works after initialization time, malloc()'s data structures are good
 * for statistics and for allocations of less than a page.
 */
static void *
contigmalloc1(
	unsigned long size,	/* should be size_t here and for malloc() */
	struct malloc_type *type,
	int flags,
	vm_paddr_t low,
	vm_paddr_t high,
	unsigned long alignment,
	unsigned long boundary,
	vm_map_t map)
{
	int i, start;
	vm_paddr_t phys;
	vm_object_t object;
	vm_offset_t addr, tmp_addr;
	int pass, pqtype;
	int inactl, actl, inactmax, actmax;
	vm_page_t pga = vm_page_array;

	size = round_page(size);
	if (size == 0)
		panic("contigmalloc1: size must not be 0");
	if ((alignment & (alignment - 1)) != 0)
		panic("contigmalloc1: alignment must be a power of 2");
	if ((boundary & (boundary - 1)) != 0)
		panic("contigmalloc1: boundary must be a power of 2");

	start = 0;
	for (pass = 2; pass >= 0; pass--) {
		vm_page_lock_queues();
again0:
		mtx_lock_spin(&vm_page_queue_free_mtx);
again:
		/*
		 * Find first page in array that is free, within range,
		 * aligned, and such that the boundary won't be crossed.
		 */
		for (i = start; i < cnt.v_page_count; i++) {
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
			mtx_unlock_spin(&vm_page_queue_free_mtx);
			/*
			 * Instead of racing to empty the inactive/active
			 * queues, give up, even with more left to free,
			 * if we try more than the initial amount of pages.
			 *
			 * There's no point attempting this on the last pass.
			 */
			if (pass > 0) {
				inactl = actl = 0;
				inactmax = vm_page_queues[PQ_INACTIVE].lcnt;
				actmax = vm_page_queues[PQ_ACTIVE].lcnt;
again1:
				if (inactl < inactmax &&
				    vm_contig_launder(PQ_INACTIVE)) {
					inactl++;
					goto again1;
				}
				if (actl < actmax &&
				    vm_contig_launder(PQ_ACTIVE)) {
					actl++;
					goto again1;
				}
			}
			vm_page_unlock_queues();
			continue;
		}
		start = i;

		/*
		 * Check successive pages for contiguous and free.
		 */
		for (i = start + 1; i < (start + size / PAGE_SIZE); i++) {
			pqtype = pga[i].queue - pga[i].pc;
			if ((VM_PAGE_TO_PHYS(&pga[i]) !=
			    (VM_PAGE_TO_PHYS(&pga[i - 1]) + PAGE_SIZE)) ||
			    ((pqtype != PQ_FREE) && (pqtype != PQ_CACHE))) {
				start++;
				goto again;
			}
		}
		mtx_unlock_spin(&vm_page_queue_free_mtx);
		for (i = start; i < (start + size / PAGE_SIZE); i++) {
			vm_page_t m = &pga[i];

			if ((m->queue - m->pc) == PQ_CACHE) {
				object = m->object;
				if (!VM_OBJECT_TRYLOCK(object)) {
					start++;
					goto again0;
				}
				vm_page_busy(m);
				vm_page_free(m);
				VM_OBJECT_UNLOCK(object);
			}
		}
		mtx_lock_spin(&vm_page_queue_free_mtx);
		for (i = start; i < (start + size / PAGE_SIZE); i++) {
			pqtype = pga[i].queue - pga[i].pc;
			if (pqtype != PQ_FREE) {
				start++;
				goto again;
			}
		}
		for (i = start; i < (start + size / PAGE_SIZE); i++) {
			vm_page_t m = &pga[i];
			vm_pageq_remove_nowakeup(m);
			m->valid = VM_PAGE_BITS_ALL;
			if (m->flags & PG_ZERO)
				vm_page_zero_count--;
			/* Don't clear the PG_ZERO flag, we'll need it later. */
			m->flags = PG_UNMANAGED | (m->flags & PG_ZERO);
			KASSERT(m->dirty == 0,
			    ("contigmalloc1: page %p was dirty", m));
			m->wire_count = 0;
			m->busy = 0;
			m->object = NULL;
		}
		mtx_unlock_spin(&vm_page_queue_free_mtx);
		vm_page_unlock_queues();
		/*
		 * We've found a contiguous chunk that meets are requirements.
		 * Allocate kernel VM, unfree and assign the physical pages to
		 * it and return kernel VM pointer.
		 */
		vm_map_lock(map);
		if (vm_map_findspace(map, vm_map_min(map), size, &addr) !=
		    KERN_SUCCESS) {
			/*
			 * XXX We almost never run out of kernel virtual
			 * space, so we don't make the allocated memory
			 * above available.
			 */
			vm_map_unlock(map);
			return (NULL);
		}
		vm_object_reference(kernel_object);
		vm_map_insert(map, kernel_object, addr - VM_MIN_KERNEL_ADDRESS,
		    addr, addr + size, VM_PROT_ALL, VM_PROT_ALL, 0);
		vm_map_unlock(map);

		tmp_addr = addr;
		VM_OBJECT_LOCK(kernel_object);
		for (i = start; i < (start + size / PAGE_SIZE); i++) {
			vm_page_t m = &pga[i];
			vm_page_insert(m, kernel_object,
				OFF_TO_IDX(tmp_addr - VM_MIN_KERNEL_ADDRESS));
			if ((flags & M_ZERO) && !(m->flags & PG_ZERO))
				pmap_zero_page(m);
			tmp_addr += PAGE_SIZE;
		}
		VM_OBJECT_UNLOCK(kernel_object);
		vm_map_wire(map, addr, addr + size,
		    VM_MAP_WIRE_SYSTEM|VM_MAP_WIRE_NOHOLES);

		return ((void *)addr);
	}
	return (NULL);
}

void *
contigmalloc(
	unsigned long size,	/* should be size_t here and for malloc() */
	struct malloc_type *type,
	int flags,
	vm_paddr_t low,
	vm_paddr_t high,
	unsigned long alignment,
	unsigned long boundary)
{
	void * ret;

	mtx_lock(&Giant);
	ret = contigmalloc1(size, type, flags, low, high, alignment, boundary,
	    kernel_map);
	mtx_unlock(&Giant);
	return (ret);
}

void
contigfree(void *addr, unsigned long size, struct malloc_type *type)
{

	kmem_free(kernel_map, (vm_offset_t)addr, size);
}
