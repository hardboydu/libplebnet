/*
 * Copyright (c) 1999, Matthew Dillon.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided under the terms of the BSD
 * Copyright as found in /usr/src/COPYRIGHT in the FreeBSD source tree.
 */

#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1999\n"
    "Matthew Dillon.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static const char rcsid[] =
	"$Id: kvm_getswapinfo.c,v 1.38 1999/01/21 08:08:55 dillon Exp $";
#endif /* not lint */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/ucred.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/rlist.h>
#include <sys/blist.h>

#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct nlist kvm_swap_nl[] = {
	{ "_swaplist" },	/* old style swap list		*/
	{ "_swapblist" },	/* new radix swap list		*/
	{ "_swdevt" },		/* list of swap devices and sizes */
	{ "_nswdev" },		/* number of swap devices */
	{ "_dmmax" },		/* maximum size of a swap block */
	{ "" }
};

#define NL_SWAPLIST	0
#define NL_SWAPBLIST	1
#define NL_SWDEVT	2
#define NL_NSWDEV	3
#define NL_DMMAX	4

static int kvm_swap_nl_cached = 0;
static int nswdev;
static int unswdev;
static int dmmax;
static int type;

static void getswapinfo_old(kvm_t *kd, kvm_swap_t swap_ary, int swap_max, int flags);
static void getswapinfo_radix(kvm_t *kd, kvm_swap_t swap_ary, int swap_max, int flags);

#define	SVAR(var) __STRING(var)	/* to force expansion */
#define	KGET(idx, var)							\
	KGET1(idx, &var, sizeof(var), SVAR(var))
#define	KGET1(idx, p, s, msg)						\
	KGET2(kvm_swap_nl[idx].n_value, p, s, msg)
#define	KGET2(addr, p, s, msg)						\
	if (kvm_read(kd, (u_long)(addr), p, s) != s)			\
		warnx("cannot read %s: %s", msg, kvm_geterr(kd))
#define	KGETN(idx, var)							\
	KGET1N(idx, &var, sizeof(var), SVAR(var))
#define	KGET1N(idx, p, s, msg)						\
	KGET2N(kvm_swap_nl[idx].n_value, p, s, msg)
#define	KGET2N(addr, p, s, msg)						\
	((kvm_read(kd, (u_long)(addr), p, s) == s) ? 1 : 0)
#define	KGETRET(addr, p, s, msg)					\
	if (kvm_read(kd, (u_long)(addr), p, s) != s) {			\
		warnx("cannot read %s: %s", msg, kvm_geterr(kd));	\
		return (0);						\
	}

int
kvm_getswapinfo(
	kvm_t *kd, 
	struct kvm_swap *swap_ary,
	int swap_max, 
	int flags
) {
	int ti = 0;

	/*
	 * clear cache
	 */
	if (kd == NULL) {
		kvm_swap_nl_cached = 0;
		return(0);
	}

	/*
	 * namelist
	 */
	if (kvm_swap_nl_cached == 0) {
		struct swdevt *sw;

		if (kvm_nlist(kd, kvm_swap_nl) < 0)
			return(-1);

		/*
		 * required entries
		 */

		if (
		    kvm_swap_nl[NL_SWDEVT].n_value == 0 ||
		    kvm_swap_nl[NL_NSWDEV].n_value == 0 ||
		    kvm_swap_nl[NL_DMMAX].n_value == 0
		) {
			return(-1);
		}

		/*
		 * get globals, type of swap
		 */

		KGET(NL_NSWDEV, nswdev);
		KGET(NL_DMMAX, dmmax);

		if (kvm_swap_nl[NL_SWAPLIST].n_value)
			type = 1;

		if (kvm_swap_nl[NL_SWAPBLIST].n_value)
			type = 2;

		/*
		 * figure out how many actual swap devices are enabled
		 */

		KGET(NL_SWDEVT, sw);
		for (unswdev = nswdev - 1; unswdev >= 0; --unswdev) {
			struct swdevt swinfo;

			KGET2(&sw[unswdev], &swinfo, sizeof(swinfo), "swinfo");
			if (swinfo.sw_nblks)
				break;
		}
		++unswdev;

		kvm_swap_nl_cached = 1;
	}


	{
		struct swdevt *sw;
		int i;

		ti = unswdev;
		if (ti >= swap_max)
			ti = swap_max - 1;

		if (ti >= 0)
			bzero(swap_ary, sizeof(struct kvm_swap) * (ti + 1));

		KGET(NL_SWDEVT, sw);
		for (i = 0; i < unswdev; ++i) {
			struct swdevt swinfo;
			int ttl;

			KGET2(&sw[i], &swinfo, sizeof(swinfo), "swinfo");

			/*
			 * old style: everything in DEV_BSIZE'd chunks,
			 * convert to pages.
			 *
			 * new style: swinfo in DEV_BSIZE'd chunks but dmmax
			 * in pages.
			 */

			if (type == 1)
				ttl = dbtoc(swinfo.sw_nblks);
			else
				ttl = swinfo.sw_nblks;

			if (ttl == 0)
				continue;

			if (i < ti) {
				swap_ary[i].ksw_total = ttl;
				swap_ary[i].ksw_used = ttl;
				swap_ary[i].ksw_flags = swinfo.sw_flags;
				if (swinfo.sw_dev == NODEV) {
					snprintf(
					    swap_ary[i].ksw_devname,
					    sizeof(swap_ary[i].ksw_devname),
					    "%s",
					    "[NFS swap]"
					);
				} else {
					snprintf(
					    swap_ary[i].ksw_devname,
					    sizeof(swap_ary[i].ksw_devname),
					    "%s",
					    devname(swinfo.sw_dev, S_IFBLK)
					);
				}
			}
			if (ti >= 0) {
				swap_ary[ti].ksw_total += ttl;
				swap_ary[ti].ksw_used += ttl;
			}
		}
	}

	switch(type) {
	case 1:
		getswapinfo_old(kd, swap_ary, swap_max, flags);
		break;
	case 2:
		getswapinfo_radix(kd, swap_ary, swap_max, flags);
		break;
	default:
		ti = -1;
		break;
	}
	return(ti);
}

/*
 * scanradix() - support routine for radix scanner
 */

#define TABME	tab, tab, ""

static int
scanradix(
	blmeta_t *scan, 
	daddr_t blk,
	daddr_t radix,
	daddr_t skip, 
	daddr_t count,
	kvm_t *kd,
	int dmmax, 
	int nswdev,
	kvm_swap_t swap_ary,
	int swap_max,
	int tab,
	int flags
) {
	blmeta_t meta;
	int ti = (unswdev >= swap_max) ? swap_max - 1 : unswdev;

	KGET2(scan, &meta, sizeof(meta), "blmeta_t");

	/*
	 * Terminator
	 */
	if (meta.bm_bighint == (daddr_t)-1) {
		if (flags & SWIF_DUMP_TREE) {
			printf("%*.*s(0x%06x,%d) Terminator\n", 
			    TABME,
			    blk, 
			    radix
			);
		}
		return(-1);
	}

	if (radix == BLIST_BMAP_RADIX) {
		/*
		 * Leaf bitmap
		 */
		int i;

		if (flags & SWIF_DUMP_TREE) {
			printf("%*.*s(0x%06x,%d) Bitmap %08x big=%d\n", 
			    TABME,
			    blk, 
			    radix,
			    (int)meta.u.bmu_bitmap,
			    meta.bm_bighint
			);
		}

		/*
		 * If not all allocated, count.
		 */
		if (meta.u.bmu_bitmap != 0) {
			for (i = 0; i < BLIST_BMAP_RADIX && i < count; ++i) {
				/*
				 * A 0 bit means allocated
				 */
				if ((meta.u.bmu_bitmap & (1 << i))) {
					int t = 0;

					if (nswdev)
						t = (blk + i) / dmmax % nswdev;
					if (t < ti)
						--swap_ary[t].ksw_used;
					if (ti >= 0)
						--swap_ary[ti].ksw_used;
				}
			}
		}
	} else if (meta.u.bmu_avail == radix) {
		/*
		 * Meta node if all free
		 */
		if (flags & SWIF_DUMP_TREE) {
			printf("%*.*s(0x%06x,%d) Submap ALL-FREE {\n", 
			    TABME,
			    blk, 
			    radix,
			    (int)meta.u.bmu_avail,
			    meta.bm_bighint
			);
		}
		/*
		 * Note: both dmmax and radix are powers of 2.  However, dmmax
		 * may be larger then radix so use a smaller increment if
		 * necessary.
		 */
		{
			int t;
			int tinc = dmmax;

			while (tinc > radix)
				tinc >>= 1;

			for (t = blk; t < blk + radix; t += tinc) {
				int u = (nswdev) ? (t / dmmax % nswdev) : 0;

				if (u < ti)
					swap_ary[u].ksw_used -= tinc;
				if (ti >= 0)
					swap_ary[ti].ksw_used -= tinc;
			}
		}
	} else if (meta.u.bmu_avail == 0) {
		/*
		 * Meta node if all used
		 */
		if (flags & SWIF_DUMP_TREE) {
			printf("%*.*s(0x%06x,%d) Submap ALL-ALLOCATED\n", 
			    TABME,
			    blk, 
			    radix,
			    (int)meta.u.bmu_avail,
			    meta.bm_bighint
			);
		}
	} else {
		/*
		 * Meta node if not all free
		 */
		int i;
		int next_skip;

		radix >>= BLIST_META_RADIX_SHIFT;
		next_skip = skip >> BLIST_META_RADIX_SHIFT;

		if (flags & SWIF_DUMP_TREE) {
			printf("%*.*s(0x%06x,%d) Submap avail=%d big=%d {\n", 
			    TABME,
			    blk, 
			    radix,
			    (int)meta.u.bmu_avail,
			    meta.bm_bighint
			);
		}

		for (i = 1; i <= skip; i += next_skip) {
			int r;
			daddr_t vcount = (count > radix) ? radix : count;

			r = scanradix(
			    &scan[i],
			    blk,
			    radix,
			    next_skip - 1,
			    vcount,
			    kd,
			    dmmax,
			    nswdev,
			    swap_ary,
			    swap_max,
			    tab + 4,
			    flags
			);
			if (r < 0)
				break;
			blk += radix;
		}
		if (flags & SWIF_DUMP_TREE) {
			printf("%*.*s}\n", TABME);
		}
	}
	return(0);
}

static void
getswapinfo_radix(kvm_t *kd, kvm_swap_t swap_ary, int swap_max, int flags)
{
	struct blist *swapblist = NULL;
	struct blist blcopy = { 0 };

	KGET(NL_SWAPBLIST, swapblist);
	KGET2(swapblist, &blcopy, sizeof(blcopy), "*swapblist");

	if (flags & SWIF_DUMP_TREE) {
		printf("radix tree: %d/%d/%d blocks, %dK wired\n",
			blcopy.bl_free,
			blcopy.bl_blocks,
			blcopy.bl_radix,
			(blcopy.bl_rootblks * sizeof(blmeta_t) + 1023)/
			    1024
		);
	}
	scanradix(
	    blcopy.bl_root, 
	    0, 
	    blcopy.bl_radix, 
	    blcopy.bl_skip, 
	    blcopy.bl_rootblks, 
	    kd,
	    dmmax,
	    nswdev, 
	    swap_ary,
	    swap_max,
	    0,
	    flags
	);
}

static void
getswapinfo_old(kvm_t *kd, kvm_swap_t swap_ary, int swap_max, int flags)
{
	struct rlist *swapptr;
	struct rlisthdr swaplist;
	int ti = (unswdev >= swap_max) ? swap_max - 1 : unswdev;

	KGET(NL_SWAPLIST, swaplist);

	swapptr = swaplist.rlh_list;

	while (swapptr) {
		int	top;
		int	bottom;
		int	next_block;
		int	t;
		int	v;
		struct rlist head;

		KGET2(swapptr, &head, sizeof(head), "swapptr");

		top = head.rl_end;
		bottom = head.rl_start;

		/*
		 * Handle interleave indexing
		 */

		while (top / dmmax != bottom / dmmax) {
			next_block = ((bottom + dmmax) / dmmax);

			t = (bottom / dmmax) % nswdev;
			v = next_block * dmmax - bottom;

			if (t < ti)
				swap_ary[t].ksw_used -= dbtoc(v);
			if (ti >= 0)
				swap_ary[ti].ksw_used -= dbtoc(v);

			bottom = next_block * dmmax;
		}

		t = (bottom / dmmax) % nswdev;
		v = top - bottom + 1;

		if (t < ti)
			swap_ary[t].ksw_used -= dbtoc(v);
		if (ti >= 0)
			swap_ary[ti].ksw_used -= dbtoc(v);

		swapptr = head.rl_next;
	}
}

