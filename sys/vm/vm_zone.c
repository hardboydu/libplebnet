/*
 * Copyright (c) 1997, 1998 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice immediately at the beginning of the file, without modification,
 *	this list of conditions, and the following disclaimer.
 * 2. Absolutely no warranty of function or purpose is made by the author
 *	John S. Dyson.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/vm_zone.h>

static MALLOC_DEFINE(M_ZONE, "ZONE", "Zone header");

#define ZENTRY_FREE		(void*)0x12342378

#define ZONE_ROUNDING		32

/*
 * This file comprises a very simple zone allocator.  This is used
 * in lieu of the malloc allocator, where needed or more optimal.
 *
 * Note that the initial implementation of this had coloring, and
 * absolutely no improvement (actually perf degradation) occurred.
 *
 * Note also that the zones are type stable.  The only restriction is
 * that the first two longwords of a data structure can be changed
 * between allocations.  Any data that must be stable between allocations
 * must reside in areas after the first two longwords.
 *
 * zinitna, zinit, zbootinit are the initialization routines.
 * zalloc, zfree, are the allocation/free routines.
 */

/*
 * Subsystem lock.  Never grab it while holding a zone lock.
 */
static struct mtx zone_mtx;

/*
 * Singly-linked list of zones, for book-keeping purposes
 */
static SLIST_HEAD(vm_zone_list, vm_zone) zlist;

/*
 * Statistics
 */
static int zone_kmem_pages;	/* Number of interrupt-safe pages allocated */
static int zone_kern_pages;	/* Number of KVA pages allocated */
static int zone_kmem_kvaspace;	/* Number of non-intsafe pages allocated */

/*
 * Subsystem initialization, called from vm_mem_init()
 */
void
vm_zone_init(void)
{
	mtx_init(&zone_mtx, "zone subsystem", MTX_DEF);
	SLIST_INIT(&zlist);
}

void
vm_zone_init2(void)
{
	/*
	 * LATER: traverse zlist looking for partially initialized
	 * LATER: zones and finish initializing them.
	 */
}

/*
 * Create a zone, but don't allocate the zone structure.  If the
 * zone had been previously created by the zone boot code, initialize
 * various parts of the zone code.
 *
 * If waits are not allowed during allocation (e.g. during interrupt
 * code), a-priori allocate the kernel virtual space, and allocate
 * only pages when needed.
 *
 * Arguments:
 * z		pointer to zone structure.
 * obj		pointer to VM object (opt).
 * name		name of zone.
 * size		size of zone entries.
 * nentries	number of zone entries allocated (only ZONE_INTERRUPT.)
 * flags	ZONE_INTERRUPT -- items can be allocated at interrupt time.
 * zalloc	number of pages allocated when memory is needed.
 *
 * Note that when using ZONE_INTERRUPT, the size of the zone is limited
 * by the nentries argument.  The size of the memory allocatable is
 * unlimited if ZONE_INTERRUPT is not set.
 *
 */
int
zinitna(vm_zone_t z, vm_object_t obj, char *name, int size,
	int nentries, int flags, int zalloc)
{
	int totsize, oldzflags;

	oldzflags = z->zflags;
	if ((z->zflags & ZONE_BOOT) == 0) {
		z->zsize = (size + ZONE_ROUNDING - 1) & ~(ZONE_ROUNDING - 1);
		z->zfreecnt = 0;
		z->ztotal = 0;
		z->zmax = 0;
		z->zname = name;
		z->znalloc = 0;
		z->zitems = NULL;
	}

	z->zflags |= flags;

	/*
	 * If we cannot wait, allocate KVA space up front, and we will fill
	 * in pages as needed.
	 */
	if (z->zflags & ZONE_INTERRUPT) {

		totsize = round_page(z->zsize * nentries);
		atomic_add_int(&zone_kmem_kvaspace, totsize);
		z->zkva = kmem_alloc_pageable(kernel_map, totsize);
		if (z->zkva == 0)
			return 0;

		z->zpagemax = totsize / PAGE_SIZE;
		if (obj == NULL) {
			z->zobj = vm_object_allocate(OBJT_DEFAULT, z->zpagemax);
		} else {
			z->zobj = obj;
			_vm_object_allocate(OBJT_DEFAULT, z->zpagemax, obj);
		}
		z->zallocflag = VM_ALLOC_INTERRUPT;
		z->zmax += nentries;
	} else {
		z->zallocflag = VM_ALLOC_SYSTEM;
		z->zmax = 0;
	}


	if (z->zsize > PAGE_SIZE)
		z->zfreemin = 1;
	else
		z->zfreemin = PAGE_SIZE / z->zsize;

	z->zpagecount = 0;
	if (zalloc)
		z->zalloc = zalloc;
	else
		z->zalloc = 1;

	/* our zone is good and ready, add it to the list */
	if ((z->zflags & ZONE_BOOT) == 0) {
		mtx_init(&(z)->zmtx, "zone", MTX_DEF);
		mtx_lock(&zone_mtx);
		SLIST_INSERT_HEAD(&zlist, z, zent);
		mtx_unlock(&zone_mtx);
	}
	
	return 1;
}

/*
 * Subroutine same as zinitna, except zone data structure is allocated
 * automatically by malloc.  This routine should normally be used, except
 * in certain tricky startup conditions in the VM system -- then
 * zbootinit and zinitna can be used.  Zinit is the standard zone
 * initialization call.
 */
vm_zone_t
zinit(char *name, int size, int nentries, int flags, int zalloc)
{
	vm_zone_t z;

	z = (vm_zone_t) malloc(sizeof (struct vm_zone), M_ZONE, M_NOWAIT | M_ZERO);
	if (z == NULL)
		return NULL;

	if (zinitna(z, NULL, name, size, nentries, flags, zalloc) == 0) {
		free(z, M_ZONE);
		return NULL;
	}

	return z;
}

/*
 * Initialize a zone before the system is fully up.
 *
 * We can't rely on being able to allocate items dynamically, so we
 * kickstart the zone with a number of static items provided by the
 * caller.
 *
 * This routine should only be called before full VM startup.
 */
void
zbootinit(vm_zone_t z, char *name, int size, void *item, int nitems)
{
	int i;

	z->zname = name;
	z->zsize = size;
	z->zpagemax = 0;
	z->zobj = NULL;
	z->zflags = ZONE_BOOT;
	z->zfreemin = 0;
	z->zallocflag = 0;
	z->zpagecount = 0;
	z->zalloc = 0;
	z->znalloc = 0;
	mtx_init(&(z)->zmtx, "zone", MTX_DEF);

	bzero(item, nitems * z->zsize);
	z->zitems = NULL;
	for (i = 0; i < nitems; i++) {
		((void **) item)[0] = z->zitems;
#ifdef INVARIANTS
		((void **) item)[1] = ZENTRY_FREE;
#endif
		z->zitems = item;
		(char *) item += z->zsize;
	}
	z->zfreecnt = nitems;
	z->zmax = nitems;
	z->ztotal = nitems;

	mtx_lock(&zone_mtx);
	SLIST_INSERT_HEAD(&zlist, z, zent);
	mtx_unlock(&zone_mtx);
}

/*
 * Grow the specified zone to accomodate more items.
 */
static void *
_zget(vm_zone_t z)
{
	int i;
	vm_page_t m;
	int nitems, nbytes;
	void *item;

	KASSERT(z != NULL, ("invalid zone"));
	mtx_assert(&z->zmtx, MA_OWNED);

	if (z->zflags & ZONE_INTERRUPT) {
		item = (char *) z->zkva + z->zpagecount * PAGE_SIZE;
		for (i = 0; ((i < z->zalloc) && (z->zpagecount < z->zpagemax));
		     i++) {
			vm_offset_t zkva;

			m = vm_page_alloc(z->zobj, z->zpagecount,
					  z->zallocflag);
			if (m == NULL)
				break;

			zkva = z->zkva + z->zpagecount * PAGE_SIZE;
			pmap_kenter(zkva, VM_PAGE_TO_PHYS(m));
			bzero((caddr_t) zkva, PAGE_SIZE);
			z->zpagecount++;
			atomic_add_int(&zone_kmem_pages, 1);
			cnt.v_wire_count++;
		}
		nitems = (i * PAGE_SIZE) / z->zsize;
	} else {
		nbytes = z->zalloc * PAGE_SIZE;

		/*
		 * Check to see if the kernel map is already locked.  We could allow
		 * for recursive locks, but that eliminates a valuable debugging
		 * mechanism, and opens up the kernel map for potential corruption
		 * by inconsistent data structure manipulation.  We could also use
		 * the interrupt allocation mechanism, but that has size limitations.
		 * Luckily, we have kmem_map that is a submap of kernel map available
		 * for memory allocation, and manipulation of that map doesn't affect
		 * the kernel map structures themselves.
		 *
		 * We can wait, so just do normal map allocation in the appropriate
		 * map.
		 */
		if (lockstatus(&kernel_map->lock, NULL)) {
			mtx_unlock(&z->zmtx);
			item = (void *) kmem_malloc(kmem_map, nbytes, M_WAITOK);
			mtx_lock(&z->zmtx);
			if (item != NULL)
				atomic_add_int(&zone_kmem_pages, z->zalloc);
		} else {
			mtx_unlock(&z->zmtx);
			item = (void *) kmem_alloc(kernel_map, nbytes);
			mtx_lock(&z->zmtx);
			if (item != NULL)
				atomic_add_int(&zone_kern_pages, z->zalloc);
		}
		if (item != NULL) {
			bzero(item, nbytes);
		} else {
			nbytes = 0;
		}
		nitems = nbytes / z->zsize;
	}
	z->ztotal += nitems;

	/*
	 * Save one for immediate allocation
	 */
	if (nitems != 0) {
		nitems -= 1;
		for (i = 0; i < nitems; i++) {
			((void **) item)[0] = z->zitems;
#ifdef INVARIANTS
			((void **) item)[1] = ZENTRY_FREE;
#endif
			z->zitems = item;
			(char *) item += z->zsize;
		}
		z->zfreecnt += nitems;
		z->znalloc++;
	} else if (z->zfreecnt > 0) {
		item = z->zitems;
		z->zitems = ((void **) item)[0];
#ifdef INVARIANTS
		KASSERT(((void **) item)[1] == ZENTRY_FREE,
		    ("item is not free"));
		((void **) item)[1] = 0;
#endif
		z->zfreecnt--;
		z->znalloc++;
	} else {
		item = NULL;
	}

	mtx_assert(&z->zmtx, MA_OWNED);
	return item;
}

/*
 * Allocates an item from the specified zone.
 */
void *
zalloc(vm_zone_t z)
{
	void *item;

	KASSERT(z != NULL, ("invalid zone"));
	mtx_lock(&z->zmtx);
	
	if (z->zfreecnt <= z->zfreemin) {
		item = _zget(z);
		mtx_unlock(&z->zmtx);
		return item;
	}

	item = z->zitems;
	z->zitems = ((void **) item)[0];
#ifdef INVARIANTS
	KASSERT(((void **) item)[1] == ZENTRY_FREE,
	    ("item is not free"));
	((void **) item)[1] = 0;
#endif

	z->zfreecnt--;
	z->znalloc++;
	
	mtx_unlock(&z->zmtx);
	return item;
}

/*
 * Frees an item back to the specified zone.
 */
void
zfree(vm_zone_t z, void *item)
{
	KASSERT(z != NULL, ("invalid zone"));
	KASSERT(item != NULL, ("invalid item"));
	mtx_lock(&z->zmtx);
	
	((void **) item)[0] = z->zitems;
#ifdef INVARIANTS
	KASSERT(((void **) item)[1] != ZENTRY_FREE,
	    ("item is already free"));
	((void **) item)[1] = (void *) ZENTRY_FREE;
#endif
	z->zitems = item;
	z->zfreecnt++;

	mtx_unlock(&z->zmtx);
}

/*
 * Sysctl handler for vm.zone 
 */
static int
sysctl_vm_zone(SYSCTL_HANDLER_ARGS)
{
	int error, len;
	char tmpbuf[128];
	vm_zone_t z;
	char *p;

	mtx_lock(&zone_mtx);
	len = snprintf(tmpbuf, sizeof(tmpbuf),
	    "\nITEM            SIZE     LIMIT    USED    FREE  REQUESTS\n\n");
	error = SYSCTL_OUT(req, tmpbuf, SLIST_EMPTY(&zlist) ? len-1 : len);
	SLIST_FOREACH(z, &zlist, zent) {
		mtx_lock(&z->zmtx);
		len = snprintf(tmpbuf, sizeof(tmpbuf),
		    "%-12.12s  %6.6u, %8.8u, %6.6u, %6.6u, %8.8u\n",
		    z->zname, z->zsize, z->zmax, (z->ztotal - z->zfreecnt),
		    z->zfreecnt, z->znalloc);
		for (p = tmpbuf + 12; p > tmpbuf && *p == ' '; --p)
			/* nothing */ ;
		p[1] = ':';
		mtx_unlock(&z->zmtx);
		if (SLIST_NEXT(z, zent) == NULL)
			tmpbuf[len - 1] = 0;
		if ((error = SYSCTL_OUT(req, tmpbuf, len)) != 0)
			break;
	}
	mtx_unlock(&zone_mtx);
	return (error);
}

SYSCTL_OID(_vm, OID_AUTO, zone, CTLTYPE_STRING|CTLFLAG_RD,
    NULL, 0, sysctl_vm_zone, "A", "Zone Info");

SYSCTL_INT(_vm, OID_AUTO, zone_kmem_pages, CTLFLAG_RD, &zone_kmem_pages, 0,
    "Number of interrupt safe pages allocated by zone");
SYSCTL_INT(_vm, OID_AUTO, zone_kmem_kvaspace, CTLFLAG_RD, &zone_kmem_kvaspace, 0,
    "KVA space allocated by zone");
SYSCTL_INT(_vm, OID_AUTO, zone_kern_pages, CTLFLAG_RD, &zone_kern_pages, 0,
    "Number of non-interrupt safe pages allocated by zone");
