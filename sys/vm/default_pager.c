/*
 * Copyright (c) 1995, David Greenman
 * All rights reserved.
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
 *	This product includes software developed by David Greenman.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: default_pager.c,v 1.13 1997/09/01 03:17:08 bde Exp $
 */

#include "opt_diagnostic.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_prot.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/default_pager.h>
#include <vm/swap_pager.h>

static vm_object_t default_pager_alloc __P((void *, vm_size_t, vm_prot_t,
		vm_ooffset_t));
static void default_pager_dealloc __P((vm_object_t));
static int default_pager_getpages __P((vm_object_t, vm_page_t *, int, int));
static int default_pager_putpages __P((vm_object_t, vm_page_t *, int, 
		boolean_t, int *));
static boolean_t default_pager_haspage __P((vm_object_t, vm_pindex_t, int *, 
		int *));
/*
 * pagerops for OBJT_DEFAULT - "default pager".
 */
struct pagerops defaultpagerops = {
	NULL,
	default_pager_alloc,
	default_pager_dealloc,
	default_pager_getpages,
	default_pager_putpages,
	default_pager_haspage,
	NULL
};

/*
 * no_pager_alloc just returns an initialized object.
 */
static vm_object_t
default_pager_alloc(void *handle, vm_size_t size, vm_prot_t prot,
		    vm_ooffset_t offset)
{
	if (handle != NULL)
		panic("default_pager_alloc: handle specified");

	return vm_object_allocate(OBJT_DEFAULT, OFF_TO_IDX(offset) + size);
}

static void
default_pager_dealloc(object)
	vm_object_t object;
{
	/*
	 * OBJT_DEFAULT objects have no special resources allocated to them.
	 */
}

/*
 * The default pager has no backing store, so we always return
 * failure.
 */
static int
default_pager_getpages(object, m, count, reqpage)
	vm_object_t object;
	vm_page_t *m;
	int count;
	int reqpage;
{
	return VM_PAGER_FAIL;
}

static int
default_pager_putpages(object, m, c, sync, rtvals)
	vm_object_t object;
	vm_page_t *m;
	int c;
	boolean_t sync;
	int *rtvals;
{
	int i;

	/*
	 * Try to convert the object type into a OBJT_SWAP.
	 * If the swp structure allocation fails, convert it
	 * back to OBJT_DEFAULT and return failure. Otherwise
	 * pass this putpages to the swap pager.
	 */
	object->type = OBJT_SWAP;

	if (swap_pager_swp_alloc(object, M_KERNEL) != 0) {
		object->type = OBJT_DEFAULT;
		for (i = 0; i < c; i++)
			rtvals[i] = VM_PAGER_FAIL;
		return VM_PAGER_FAIL;
	}

	return swap_pager_putpages(object, m, c, sync, rtvals);
}

static boolean_t
default_pager_haspage(object, pindex, before, after)
	vm_object_t object;
	vm_pindex_t pindex;
	int *before;
	int *after;
{
	return FALSE;
}

void
default_pager_convert_to_swap(object)
	vm_object_t object;
{
	object->type = OBJT_SWAP;
	if (swap_pager_swp_alloc(object, M_KERNEL) != 0) {
		object->type = OBJT_DEFAULT;
	}
}

void
default_pager_convert_to_swapq(object)
	vm_object_t object;
{
	if (object &&
		(object->type == OBJT_DEFAULT) &&
		(object != kernel_object && object != kmem_object) &&
		(object->size > ((cnt.v_page_count - cnt.v_wire_count) / 4)))
		default_pager_convert_to_swap(object);
}

