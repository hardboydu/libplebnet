/*-
 * Copyright (c) 2004 Poul-Henning Kamp
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
 * $FreeBSD$
 */

/*
 * Architectural notes:
 *
 * bufobj is a new object which is what buffers hang from in the buffer
 * cache.
 *
 * This used to be vnodes, but we need non-vnode code to be able
 * to use the buffer cache as well, specifically geom classes like gbde,
 * raid3 and raid5.
 *
 * All vnodes will contain a bufobj initially, but down the road we may
 * want to only allocate bufobjs when they are needed.  There could be a
 * large number of vnodes in the system which wouldn't need a bufobj during
 * their lifetime.
 *
 * The exact relationship to the vmobject is not determined at this point,
 * it may in fact bee that we find them to be two sides of the same object 
 * once things starts to crystalize.
 */

#ifndef _SYS_BUFOBJ_H_
#define _SYS_BUFOBJ_H_

#if defined(_KERNEL) || defined(_KVM_VNODE)

#include <sys/queue.h>

struct bufobj;
struct buf_ops;

extern struct buf_ops buf_ops_bio;

TAILQ_HEAD(buflists, buf);

/* A Buffer splay list */
struct bufv {
	struct buflists	bv_hd;		/* Sorted blocklist */
	struct buf	*bv_root;	/* Buf splay tree */
	int		bv_cnt;		/* Number of buffers */
};

typedef void b_strategy_t(struct bufobj *, struct buf *);
typedef int b_write_t(struct buf *);

struct buf_ops {
	char		*bop_name;
	b_write_t	*bop_write;
	b_strategy_t	*bop_strategy;
};

struct bufobj {
	struct mtx	*bo_mtx;	/* Mutex which protects "i" things */
	struct bufv	bo_clean;	/* i Clean buffers */
	struct bufv	bo_dirty;	/* i Dirty buffers */
	long		bo_numoutput;	/* i Writes in progress */
	u_int		bo_flag;	/* i Flags */
	struct buf_ops	*bo_ops;	/* - buffer operatoins */
	struct vm_object *bo_object;	/* v Place to store VM object */
};

#define	BO_WWAIT	(1 << 1)	/* Wait for output to complete */

#define	BO_LOCK(bo) \
	do { \
		KASSERT (bo->bo_mtx != NULL, ("No lock in bufobj")); \
		mtx_lock((bo)->bo_mtx); \
	} while (0)

#define BO_UNLOCK(bo) \
	do { \
		KASSERT (bo->bo_mtx != NULL, ("No lock in bufobj")); \
		mtx_unlock((bo)->bo_mtx); \
	} while (0)

#define	BO_MTX(bo)		((bo)->bo_mtx)
#define	ASSERT_BO_LOCKED(bo)	mtx_assert(bo->bo_mtx, MA_OWNED)
#define	ASSERT_BO_UNLOCKED(bo)	mtx_assert(bo->bo_mtx, MA_NOTOWNED)

void bufobj_wdrop(struct bufobj *bo);
void bufobj_wref(struct bufobj *bo);
int bufobj_wwait(struct bufobj *bo, int slpflag, int timeo);

#endif /* defined(_KERNEL) || defined(_KVM_VNODE) */
#endif /* _SYS_BUFOBJ_H_ */


