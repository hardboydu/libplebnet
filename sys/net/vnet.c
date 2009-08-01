/*-
 * Copyright (c) 2004-2009 University of Zagreb
 * Copyright (c) 2006-2009 FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by the University of Zagreb and the
 * FreeBSD Foundation under sponsorship by the Stichting NLnet and the
 * FreeBSD Foundation.
 *
 * Copyright (c) 2009 Jeffrey Roberson <jeff@freebsd.org>
 * Copyright (c) 2009 Robert N. M. Watson
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/linker_set.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#ifdef DDB
#include <ddb/ddb.h>
#endif

#include <net/if.h>
#include <net/if_var.h>
#include <net/vnet.h>

/*-
 * This file implements core functions for virtual network stacks:
 *
 * - Virtual network stack management functions.
 *
 * - Virtual network stack memory allocator, which virtualizes global
 *   variables in the network stack
 *
 * - Virtualized SYSINIT's/SYSUNINIT's, which allow network stack subsystems
 *   to register startup/shutdown events to be run for each virtual network
 *   stack instance.
 */

MALLOC_DEFINE(M_VNET, "vnet", "network stack control block");

/*
 * The virtual network stack list has two read-write locks, one sleepable and
 * the other not, so that the list can be stablized and walked in a variety
 * of network stack contexts.  Both must be acquired exclusively to modify
 * the list, but a read lock of either lock is sufficient to walk the list.
 */
struct rwlock		vnet_rwlock;
struct sx		vnet_sxlock;

#define	VNET_LIST_WLOCK() do {						\
	sx_xlock(&vnet_sxlock);						\
	rw_wlock(&vnet_rwlock);						\
} while (0)

#define	VNET_LIST_WUNLOCK() do {					\
	rw_wunlock(&vnet_rwlock);					\
	sx_xunlock(&vnet_sxlock);					\
} while (0)

struct vnet_list_head vnet_head;
struct vnet *vnet0;

/*
 * The virtual network stack allocator provides storage for virtualized
 * global variables.  These variables are defined/declared using the
 * VNET_DEFINE()/VNET_DECLARE() macros, which place them in the 'set_vnet'
 * linker set.  The details of the implementation are somewhat subtle, but
 * allow the majority of most network subsystems to maintain
 * virtualization-agnostic.
 *
 * The virtual network stack allocator handles variables in the base kernel
 * vs. modules in similar but different ways.  In both cases, virtualized
 * global variables are marked as such by being declared to be part of the
 * vnet linker set.  These "master" copies of global variables serve two
 * functions:
 *
 * (1) They contain static initialization or "default" values for global
 *     variables which will be propagated to each virtual network stack
 *     instance when created.  As with normal global variables, they default
 *     to zero-filled.
 *
 * (2) They act as unique global names by which the variable can be referred
 *     to, regardless of network stack instance.  The single global symbol
 *     will be used to calculate the location of a per-virtual instance
 *     variable at run-time.
 *
 * Each virtual network stack instance has a complete copy of each
 * virtualized global variable, stored in a malloc'd block of memory
 * referred to by vnet->vnet_data_mem.  Critical to the design is that each
 * per-instance memory block is laid out identically to the master block so
 * that the offset of each global variable is the same across all blocks.  To
 * optimize run-time access, a precalculated 'base' address,
 * vnet->vnet_data_base, is stored in each vnet, and is the amount that can
 * be added to the address of a 'master' instance of a variable to get to the
 * per-vnet instance.
 *
 * Virtualized global variables are handled in a similar manner, but as each
 * module has its own 'set_vnet' linker set, and we want to keep all
 * virtualized globals togther, we reserve space in the kernel's linker set
 * for potential module variables using a per-vnet character array,
 * 'modspace'.  The virtual network stack allocator maintains a free list to
 * track what space in the array is free (all, initially) and as modules are
 * linked, allocates portions of the space to specific globals.  The kernel
 * module linker queries the virtual network stack allocator and will
 * bind references of the global to the location during linking.  It also
 * calls into the virtual network stack allocator, once the memory is
 * initialized, in order to propagate the new static initializations to all
 * existing virtual network stack instances so that the soon-to-be executing
 * module will find every network stack instance with proper default values.
 */

/*
 * Location of the kernel's 'set_vnet' linker set.
 */
extern uintptr_t	*__start_set_vnet;
extern uintptr_t	*__stop_set_vnet;

#define	VNET_START	(uintptr_t)&__start_set_vnet
#define	VNET_STOP	(uintptr_t)&__stop_set_vnet

/*
 * Number of bytes of data in the 'set_vnet' linker set, and hence the total
 * size of all kernel virtualized global variables, and the malloc(9) type
 * that will be used to allocate it.
 */
#define	VNET_BYTES	(VNET_STOP - VNET_START)

MALLOC_DEFINE(M_VNET_DATA, "vnet_data", "VNET data");

/*
 * VNET_MODMIN is the minimum number of bytes we will reserve for the sum of
 * global variables across all loaded modules.  As this actually sizes an
 * array declared as a virtualized global variable in the kernel itself, and
 * we want the virtualized global variable space to be page-sized, we may
 * have more space than that in practice.
 */
#define	VNET_MODMIN	8192
#define	VNET_SIZE	roundup2(VNET_BYTES, PAGE_SIZE)
#define	VNET_MODSIZE	(VNET_SIZE - (VNET_BYTES - VNET_MODMIN))

/*
 * Space to store virtualized global variables from loadable kernel modules,
 * and the free list to manage it.
 */
static VNET_DEFINE(char, modspace[VNET_MODMIN]);

/*
 * Global lists of subsystem constructor and destructors for vnets.  They are
 * registered via VNET_SYSINIT() and VNET_SYSUNINIT().  The lists are
 * protected by the vnet_sxlock global lock.
 */
static TAILQ_HEAD(vnet_sysinit_head, vnet_sysinit) vnet_constructors =
	TAILQ_HEAD_INITIALIZER(vnet_constructors);
static TAILQ_HEAD(vnet_sysuninit_head, vnet_sysinit) vnet_destructors =
	TAILQ_HEAD_INITIALIZER(vnet_destructors);

struct vnet_data_free {
	uintptr_t	vnd_start;
	int		vnd_len;
	TAILQ_ENTRY(vnet_data_free) vnd_link;
};

MALLOC_DEFINE(M_VNET_DATA_FREE, "vnet_data_free", "VNET resource accounting");
static TAILQ_HEAD(, vnet_data_free) vnet_data_free_head =
	    TAILQ_HEAD_INITIALIZER(vnet_data_free_head);
static struct sx vnet_data_free_lock;

/*
 * Allocate a virtual network stack.
 */
struct vnet *
vnet_alloc(void)
{
	struct vnet *vnet;

	vnet = malloc(sizeof(struct vnet), M_VNET, M_WAITOK | M_ZERO);
	vnet->vnet_magic_n = VNET_MAGIC_N;

	/*
	 * Allocate storage for virtualized global variables and copy in
	 * initial values form our 'master' copy.
	 */
	vnet->vnet_data_mem = malloc(VNET_SIZE, M_VNET_DATA, M_WAITOK);
	memcpy(vnet->vnet_data_mem, (void *)VNET_START, VNET_BYTES);

	/*
	 * All use of vnet-specific data will immediately subtract VNET_START
	 * from the base memory pointer, so pre-calculate that now to avoid
	 * it on each use.
	 */
	vnet->vnet_data_base = (uintptr_t)vnet->vnet_data_mem - VNET_START;

	/* Initialize / attach vnet module instances. */
	CURVNET_SET_QUIET(vnet);

	sx_xlock(&vnet_sxlock);
	vnet_sysinit();
	CURVNET_RESTORE();

	rw_wlock(&vnet_rwlock);
	LIST_INSERT_HEAD(&vnet_head, vnet, vnet_le);
	VNET_LIST_WUNLOCK();

	return (vnet);
}

/*
 * Destroy a virtual network stack.
 */
void
vnet_destroy(struct vnet *vnet)
{
	struct ifnet *ifp, *nifp;

	KASSERT(vnet->vnet_sockcnt == 0,
	    ("%s: vnet still has sockets", __func__));

	VNET_LIST_WLOCK();
	LIST_REMOVE(vnet, vnet_le);
	rw_wunlock(&vnet_rwlock);

	CURVNET_SET_QUIET(vnet);

	/* Return all inherited interfaces to their parent vnets. */
	TAILQ_FOREACH_SAFE(ifp, &V_ifnet, if_link, nifp) {
		if (ifp->if_home_vnet != ifp->if_vnet)
			if_vmove(ifp, ifp->if_home_vnet);
	}

	vnet_sysuninit();
	sx_xunlock(&vnet_sxlock);

	CURVNET_RESTORE();

	/*
	 * Release storage for the virtual network stack instance.
	 */
	free(vnet->vnet_data_mem, M_VNET_DATA);
	vnet->vnet_data_mem = NULL;
	vnet->vnet_data_base = 0;
	vnet->vnet_magic_n = 0xdeadbeef;
	free(vnet, M_VNET);
}

/*
 * Boot time initialization and allocation of virtual network stacks.
 */
static void
vnet_init_prelink(void *arg)
{

	rw_init(&vnet_rwlock, "vnet_rwlock");
	sx_init(&vnet_sxlock, "vnet_sxlock");
	LIST_INIT(&vnet_head);
}
SYSINIT(vnet_init_prelink, SI_SUB_VNET_PRELINK, SI_ORDER_FIRST,
    vnet_init_prelink, NULL);

static void
vnet0_init(void *arg)
{

	/* Warn people before take off - in case we crash early. */
	printf("WARNING: VIMAGE (virtualized network stack) is a highly "
	    "experimental feature.\n");

	/*
	 * We MUST clear curvnet in vi_init_done() before going SMP,
	 * otherwise CURVNET_SET() macros would scream about unnecessary
	 * curvnet recursions.
	 */
	curvnet = prison0.pr_vnet = vnet0 = vnet_alloc();
}
SYSINIT(vnet0_init, SI_SUB_VNET, SI_ORDER_FIRST, vnet0_init, NULL);

static void
vnet_init_done(void *unused)
{

	curvnet = NULL;
}

SYSINIT(vnet_init_done, SI_SUB_VNET_DONE, SI_ORDER_FIRST, vnet_init_done,
    NULL);

/*
 * Once on boot, initialize the modspace freelist to entirely cover modspace.
 */
static void
vnet_data_startup(void *dummy __unused)
{
	struct vnet_data_free *df;

	df = malloc(sizeof(*df), M_VNET_DATA_FREE, M_WAITOK | M_ZERO);
	df->vnd_start = (uintptr_t)&VNET_NAME(modspace);
	df->vnd_len = VNET_MODSIZE;
	TAILQ_INSERT_HEAD(&vnet_data_free_head, df, vnd_link);
	sx_init(&vnet_data_free_lock, "vnet_data alloc lock");
}
SYSINIT(vnet_data, SI_SUB_KLD, SI_ORDER_FIRST, vnet_data_startup, 0);

/*
 * When a module is loaded and requires storage for a virtualized global
 * variable, allocate space from the modspace free list.  This interface
 * should be used only by the kernel linker.
 */
void *
vnet_data_alloc(int size)
{
	struct vnet_data_free *df;
	void *s;

	s = NULL;
	size = roundup2(size, sizeof(void *));
	sx_xlock(&vnet_data_free_lock);
	TAILQ_FOREACH(df, &vnet_data_free_head, vnd_link) {
		if (df->vnd_len < size)
			continue;
		if (df->vnd_len == size) {
			s = (void *)df->vnd_start;
			TAILQ_REMOVE(&vnet_data_free_head, df, vnd_link);
			free(df, M_VNET_DATA_FREE);
			break;
		}
		s = (void *)df->vnd_start;
		df->vnd_len -= size;
		df->vnd_start = df->vnd_start + size;
		break;
	}
	sx_xunlock(&vnet_data_free_lock);

	return (s);
}

/*
 * Free space for a virtualized global variable on module unload.
 */
void
vnet_data_free(void *start_arg, int size)
{
	struct vnet_data_free *df;
	struct vnet_data_free *dn;
	uintptr_t start;
	uintptr_t end;

	size = roundup2(size, sizeof(void *));
	start = (uintptr_t)start_arg;
	end = start + size;
	/*
	 * Free a region of space and merge it with as many neighbors as
	 * possible.  Keeping the list sorted simplifies this operation.
	 */
	sx_xlock(&vnet_data_free_lock);
	TAILQ_FOREACH(df, &vnet_data_free_head, vnd_link) {
		if (df->vnd_start > end)
			break;
		/*
		 * If we expand at the end of an entry we may have to merge
		 * it with the one following it as well.
		 */
		if (df->vnd_start + df->vnd_len == start) {
			df->vnd_len += size;
			dn = TAILQ_NEXT(df, vnd_link);
			if (df->vnd_start + df->vnd_len == dn->vnd_start) {
				df->vnd_len += dn->vnd_len;
				TAILQ_REMOVE(&vnet_data_free_head, dn,
				    vnd_link);
				free(dn, M_VNET_DATA_FREE);
			}
			sx_xunlock(&vnet_data_free_lock);
			return;
		}
		if (df->vnd_start == end) {
			df->vnd_start = start;
			df->vnd_len += size;
			sx_xunlock(&vnet_data_free_lock);
			return;
		}
	}
	dn = malloc(sizeof(*df), M_VNET_DATA_FREE, M_WAITOK | M_ZERO);
	dn->vnd_start = start;
	dn->vnd_len = size;
	if (df)
		TAILQ_INSERT_BEFORE(df, dn, vnd_link);
	else
		TAILQ_INSERT_TAIL(&vnet_data_free_head, dn, vnd_link);
	sx_xunlock(&vnet_data_free_lock);
}

/*
 * When a new virtualized global variable has been allocated, propagate its
 * initial value to each already-allocated virtual network stack instance.
 */
void
vnet_data_copy(void *start, int size)
{
	struct vnet *vnet;

	VNET_LIST_RLOCK();
	LIST_FOREACH(vnet, &vnet_head, vnet_le)
		memcpy((void *)((uintptr_t)vnet->vnet_data_base +
		    (uintptr_t)start), start, size);
	VNET_LIST_RUNLOCK();
}

/*
 * Variants on sysctl_handle_foo that know how to handle virtualized global
 * variables: if 'arg1' is a pointer, then we transform it to the local vnet
 * offset.
 */
int
vnet_sysctl_handle_int(SYSCTL_HANDLER_ARGS)
{

	if (arg1 != NULL)
		arg1 = (void *)(curvnet->vnet_data_base + (uintptr_t)arg1);
	return (sysctl_handle_int(oidp, arg1, arg2, req));
}

int
vnet_sysctl_handle_opaque(SYSCTL_HANDLER_ARGS)
{

	if (arg1 != NULL)
		arg1 = (void *)(curvnet->vnet_data_base + (uintptr_t)arg1);
	return (sysctl_handle_opaque(oidp, arg1, arg2, req));
}

int
vnet_sysctl_handle_string(SYSCTL_HANDLER_ARGS)
{

	if (arg1 != NULL)
		arg1 = (void *)(curvnet->vnet_data_base + (uintptr_t)arg1);
	return (sysctl_handle_string(oidp, arg1, arg2, req));
}

int
vnet_sysctl_handle_uint(SYSCTL_HANDLER_ARGS)
{

	if (arg1 != NULL)
		arg1 = (void *)(curvnet->vnet_data_base + (uintptr_t)arg1);
	return (sysctl_handle_int(oidp, arg1, arg2, req));
}

/*
 * Support for special SYSINIT handlers registered via VNET_SYSINIT()
 * and VNET_SYSUNINIT().
 */
void
vnet_register_sysinit(void *arg)
{
	struct vnet_sysinit *vs, *vs2;	
	struct vnet *vnet;

	vs = arg;
	KASSERT(vs->subsystem > SI_SUB_VNET, ("vnet sysinit too early"));

	/* Add the constructor to the global list of vnet constructors. */
	sx_xlock(&vnet_sxlock);
	TAILQ_FOREACH(vs2, &vnet_constructors, link) {
		if (vs2->subsystem > vs->subsystem)
			break;
		if (vs2->subsystem == vs->subsystem && vs2->order > vs->order)
			break;
	}
	if (vs2 != NULL)
		TAILQ_INSERT_BEFORE(vs2, vs, link);
	else
		TAILQ_INSERT_TAIL(&vnet_constructors, vs, link);

	/*
	 * Invoke the constructor on all the existing vnets when it is
	 * registered.
	 */
	VNET_FOREACH(vnet) {
		CURVNET_SET_QUIET(vnet);
		vs->func(vs->arg);
		CURVNET_RESTORE();
	}
	sx_xunlock(&vnet_sxlock);
}

void
vnet_deregister_sysinit(void *arg)
{
	struct vnet_sysinit *vs;

	vs = arg;

	/* Remove the constructor from the global list of vnet constructors. */
	sx_xlock(&vnet_sxlock);
	TAILQ_REMOVE(&vnet_constructors, vs, link);
	sx_xunlock(&vnet_sxlock);
}

void
vnet_register_sysuninit(void *arg)
{
	struct vnet_sysinit *vs, *vs2;

	vs = arg;

	/* Add the destructor to the global list of vnet destructors. */
	sx_xlock(&vnet_sxlock);
	TAILQ_FOREACH(vs2, &vnet_destructors, link) {
		if (vs2->subsystem > vs->subsystem)
			break;
		if (vs2->subsystem == vs->subsystem && vs2->order > vs->order)
			break;
	}
	if (vs2 != NULL)
		TAILQ_INSERT_BEFORE(vs2, vs, link);
	else
		TAILQ_INSERT_TAIL(&vnet_destructors, vs, link);
	sx_xunlock(&vnet_sxlock);
}

void
vnet_deregister_sysuninit(void *arg)
{
	struct vnet_sysinit *vs;
	struct vnet *vnet;

	vs = arg;

	/*
	 * Invoke the destructor on all the existing vnets when it is
	 * deregistered.
	 */
	sx_xlock(&vnet_sxlock);
	VNET_FOREACH(vnet) {
		CURVNET_SET_QUIET(vnet);
		vs->func(vs->arg);
		CURVNET_RESTORE();
	}

	/* Remove the destructor from the global list of vnet destructors. */
	TAILQ_REMOVE(&vnet_destructors, vs, link);
	sx_xunlock(&vnet_sxlock);
}

/*
 * Invoke all registered vnet constructors on the current vnet.  Used during
 * vnet construction.  The caller is responsible for ensuring the new vnet is
 * the current vnet and that the vnet_sxlock lock is locked.
 */
void
vnet_sysinit(void)
{
	struct vnet_sysinit *vs;

	sx_assert(&vnet_sxlock, SA_LOCKED);
	TAILQ_FOREACH(vs, &vnet_constructors, link) {
		vs->func(vs->arg);
	}
}

/*
 * Invoke all registered vnet destructors on the current vnet.  Used during
 * vnet destruction.  The caller is responsible for ensuring the dying vnet
 * is the current vnet and that the vnet_sxlock lock is locked.
 */
void
vnet_sysuninit(void)
{
	struct vnet_sysinit *vs;

	sx_assert(&vnet_sxlock, SA_LOCKED);
	TAILQ_FOREACH_REVERSE(vs, &vnet_destructors, vnet_sysuninit_head,
	    link) {
		vs->func(vs->arg);
	}
}

#ifdef DDB
DB_SHOW_COMMAND(vnets, db_show_vnets)
{
	VNET_ITERATOR_DECL(vnet_iter);

#if SIZE_MAX == UINT32_MAX /* 32-bit arch */
	db_printf("      vnet ifs socks\n");
#else /* 64-bit arch, most probaly... */
	db_printf("              vnet ifs socks\n");
#endif
	VNET_FOREACH(vnet_iter) {
		db_printf("%p %3d %5d\n", vnet_iter, vnet_iter->vnet_ifcnt,
		    vnet_iter->vnet_sockcnt);
	}
}
#endif
