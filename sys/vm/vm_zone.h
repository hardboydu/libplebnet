
/*
 * Copyright (c) 1997 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice immediately at the beginning of the file, without modification,
 *	this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. Absolutely no warranty of function or purpose is made by the author
 *	John S. Dyson.
 * 4. This work was done expressly for inclusion into FreeBSD.  Other use
 *	is allowed if this notation is included.
 * 5. Modifications may be freely made to this file if the above conditions
 *	are met.
 *
 * $Id: vm_zone.h,v 1.4 1997/08/07 03:52:55 dyson Exp $
 */

#if !defined(_SYS_ZONE_H)

#define _SYS_ZONE_H

#define ZONE_INTERRUPT 1	/* Use this if you need to allocate at int time */
#define ZONE_BOOT 16		/* This is an internal flag used by zbootinit */

#include	<machine/param.h>
#include	<sys/lock.h>


typedef struct vm_zone {
	struct	simplelock		zlock;			/* lock for data structure */
	void					*zitems;		/* linked list of items */
	int						zfreecnt;		/* free entries */
	int						zfreemin;		/* minimum number of free entries */
	int						znalloc;		/* number of allocations */
	vm_offset_t				zkva;			/* Base kva of zone */
	int						zpagecount;		/* Total # of allocated pages */
	int						zpagemax;		/* Max address space */
	int						zmax;			/* Max number of entries allocated */
	int						ztotal;			/* Total entries allocated now */
	int						zsize;			/* size of each entry */
	int						zalloc;			/* hint for # of pages to alloc */
	int						zflags;			/* flags for zone */
	int						zallocflag;		/* flag for allocation */
	struct	vm_object		*zobj;			/* object to hold zone */
	char					*zname;			/* name for diags */
	struct	vm_zone			*znext;			/* list of zones for sysctl */
} *vm_zone_t;


vm_zone_t zinit __P((char *name, int size, int nentries, int flags, int zalloc));
int zinitna __P((vm_zone_t z, struct vm_object *obj, char *name, int size,
		int nentries, int flags, int zalloc));
static void * zalloc __P((vm_zone_t z));
static void zfree __P((vm_zone_t z, void *item));
void * zalloci __P((vm_zone_t z));
void zfreei __P((vm_zone_t z, void *item));
void zbootinit __P((vm_zone_t z, char *name, int size, void *item, int nitems));
void * _zget __P((vm_zone_t z));

/*
 * void *zalloc(vm_zone_t zone) --
 *	Returns an item from a specified zone.
 *
 * void zfree(vm_zone_t zone, void *item) --
 *  Frees an item back to a specified zone.
 */
static __inline__ void *
_zalloc(vm_zone_t z) {
	void *item;

	if (z->zfreecnt <= z->zfreemin) {
		return _zget(z);
	}
	
	item = z->zitems;
	z->zitems = *(void **) item;
	z->zfreecnt--;
	z->znalloc++;
	return item;
}

static __inline__ void
_zfree(vm_zone_t z, void *item) {
	* (void **) item = z->zitems;
	z->zitems = item;
	z->zfreecnt++;
}

static __inline__ void *
zalloc(vm_zone_t z) {
#if NCPU > 1
	return zalloci(z);
#else
	return _zalloc(z);
#endif
}

static __inline__ void
zfree(vm_zone_t z, void *item) {
#if NCPU > 1
	zfreei(z, item);
#else
	_zfree(z, item);
#endif
}

#endif
