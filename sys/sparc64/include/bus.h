/*-
 * Copyright (c) 1996, 1997, 1998, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 1997-1999 Eduardo E. Horvath. All rights reserved.
 * Copyright (c) 1996 Charles M. Hannum.  All rights reserved.
 * Copyright (c) 1996 Christopher G. Demetriou.  All rights reserved.
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
 *      This product includes software developed by Christopher G. Demetriou
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * 	from: NetBSD: bus.h,v 1.28 2001/07/19 15:32:19 thorpej Exp
 *	and
 *	from: FreeBSD: src/sys/alpha/include/bus.h,v 1.9 2001/01/09
 *
 * $FreeBSD$
 */

#ifndef	_MACHINE_BUS_H_
#define	_MACHINE_BUS_H_

#include <machine/types.h>
#include <machine/cpufunc.h>

/*
 * Debug hooks
 */

#define	BSDB_ACCESS	0x01

extern int bus_space_debug;

/*
 * UPA and SBUS spaces are non-cached and big endian
 * (except for RAM and PROM)
 *
 * PCI spaces are non-cached and little endian
 */

#define	UPA_BUS_SPACE		0
#define	SBUS_BUS_SPACE		1
#define	PCI_CONFIG_BUS_SPACE	2
#define	PCI_IO_BUS_SPACE	3
#define	PCI_MEMORY_BUS_SPACE	4
#define	LAST_BUS_SPACE		5

extern int bus_type_asi[];
extern int bus_stream_asi[];

#define __BUS_SPACE_HAS_STREAM_METHODS	1

/*
 * Bus address and size types
 */
typedef	u_long		bus_space_handle_t;
typedef int		bus_type_t;
typedef u_long		bus_addr_t;
typedef u_long		bus_size_t;

#define BUS_SPACE_MAXSIZE_24BIT	0xFFFFFF
#define BUS_SPACE_MAXSIZE_32BIT 0xFFFFFFFF
#define BUS_SPACE_MAXSIZE	(128 * 1024) /* Maximum supported size */
#define BUS_SPACE_MAXADDR_24BIT	0xFFFFFF
#define BUS_SPACE_MAXADDR_32BIT 0xFFFFFFFF
#define BUS_SPACE_MAXADDR	0xFFFFFFFF

#define BUS_SPACE_UNRESTRICTED	(~0UL)

/*
 * Access methods for bus resources and address space.
 */
typedef struct bus_space_tag	*bus_space_tag_t;

struct bus_space_tag {
	void		*cookie;
	bus_space_tag_t	parent;
	int		type;

	void	(*bus_barrier) __P((
				bus_space_tag_t,
				bus_space_handle_t,
				bus_size_t,		/*offset*/
				bus_size_t,		/*size*/
				int));			/*flags*/
};

/*
 * Helpers
 */
int		sparc64_bus_mem_map __P((
				bus_type_t,
				bus_addr_t,
				bus_size_t,
				int,			/*flags*/
				vm_offset_t,		/*preferred vaddr*/
				void **));
int		sparc64_bus_mem_unmap __P((
				void *,
				bus_size_t));
bus_space_handle_t	sparc64_fake_bustag __P((
				int,
				bus_addr_t,
				struct bus_space_tag *));
    
/*
 * Bus space function prototypes.
 */
static void	bus_space_barrier __P((
				bus_space_tag_t,
				bus_space_handle_t,
				bus_size_t,
				bus_size_t,
				int));

/* This macro finds the first "upstream" implementation of method `f' */
#define _BS_CALL(t,f)			\
	while (t->f == NULL)		\
		t = t->parent;		\
	return (*(t)->f)

__inline__ void
bus_space_barrier(t, h, o, s, f)
	bus_space_tag_t t;
	bus_space_handle_t h;
	bus_size_t o;
	bus_size_t s;
	int f;
{
	_BS_CALL(t, bus_barrier)(t, h, o, s, f);
}

/* flags for bus space map functions */
#define BUS_SPACE_MAP_CACHEABLE		0x0001
#define BUS_SPACE_MAP_LINEAR		0x0002
#define BUS_SPACE_MAP_READONLY		0x0004
#define BUS_SPACE_MAP_PREFETCHABLE	0x0008
/* placeholders for bus functions... */
#define BUS_SPACE_MAP_BUS1		0x0100
#define BUS_SPACE_MAP_BUS2		0x0200
#define BUS_SPACE_MAP_BUS3		0x0400
#define BUS_SPACE_MAP_BUS4		0x0800

/* flags for bus_space_barrier() */
#define	BUS_SPACE_BARRIER_READ		0x01	/* force read barrier */
#define	BUS_SPACE_BARRIER_WRITE		0x02	/* force write barrier */

/*
 *	u_intN_t bus_space_read_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset));
 *
 * Read a 1, 2, 4, or 8 byte quantity from bus space
 * described by tag/handle/offset.
 */
#ifndef BUS_SPACE_DEBUG
#define	bus_space_read_1(t, h, o)					\
	    lduba_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type])

#define	bus_space_read_2(t, h, o)					\
	    lduha_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type])

#define	bus_space_read_4(t, h, o)					\
	    lduwa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type])

#define	bus_space_read_8(t, h, o)					\
	    ldxa_nc((caddr_t)(h) + (o), bus_type_asi[(t)->type])
#else
#define	bus_space_read_1(t, h, o) ({					\
	unsigned char __bv =				      		\
	    lduba_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr1(%llx + %llx, %x) -> %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], (unsigned int) __bv);		\
	__bv; })

#define	bus_space_read_2(t, h, o) ({					\
	unsigned short __bv =				      		\
	    lduha_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr2(%llx + %llx, %x) -> %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], (unsigned int)__bv);		\
	__bv; })

#define	bus_space_read_4(t, h, o) ({					\
	unsigned int __bv =				      		\
	    lduwa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr4(%llx + %llx, %x) -> %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], __bv);				\
	__bv; })

#define	bus_space_read_8(t, h, o) ({					\
	u_int64_t __bv =				      		\
	    ldxa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr8(%llx + %llx, %x) -> %llx\n", (u_int64_t)(h),	\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], __bv);				\
	__bv; })
#endif

/*
 *	void bus_space_read_multi_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t *addr, size_t count));
 *
 * Read `count' 1, 2, 4, or 8 byte quantities from bus space
 * described by tag/handle/offset and copy into buffer provided.
 */
#define	bus_space_read_multi_1(t, h, o, a, c) do {			\
	int i = c;							\
	u_int8_t *p = (u_int8_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_1(t, h, o);			\
} while (0)

#define	bus_space_read_multi_2(t, h, o, a, c) do {			\
	int i = c;							\
	u_int16_t *p = (u_int16_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_2(t, h, o);			\
} while (0)

#define	bus_space_read_multi_4(t, h, o, a, c) do {			\
	int i = c;							\
	u_int32_t *p = (u_int32_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_4(t, h, o);			\
} while (0)

#define	bus_space_read_multi_8(t, h, o, a, c) do {			\
	int i = c;							\
	u_int64_t *p = (u_int64_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_8(t, h, o);			\
} while (0)

/*
 *	void bus_space_write_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t value));
 *
 * Write the 1, 2, 4, or 8 byte value `value' to bus space
 * described by tag/handle/offset.
 */
#ifndef BUS_SPACE_DEBUG
#define	bus_space_write_1(t, h, o, v)					\
	stba_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v))

#define	bus_space_write_2(t, h, o, v)					\
	stha_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v))

#define	bus_space_write_4(t, h, o, v)					\
	stwa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v))

#define	bus_space_write_8(t, h, o, v)					\
	stxa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v))
#else
#define	bus_space_write_1(t, h, o, v) do {				\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw1(%llx + %llx, %x) <- %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], (unsigned int) v);		\
	stba_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v));	\
} while (0)

#define	bus_space_write_2(t, h, o, v) do {				\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw2(%llx + %llx, %x) <- %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], (unsigned int) v);		\
	stha_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v));	\
} while (0)

#define	bus_space_write_4(t, h, o, v) do {				\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw4(%llx + %llx, %x) <- %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], (unsigned int) v);		\
	stwa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v));	\
} while (0)

#define	bus_space_write_8(t, h, o, v) do {				\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw8(%llx + %llx, %x) <- %llx\n", (u_int64_t)(h),	\
		(u_int64_t)(o),						\
		bus_type_asi[(t)->type], (u_int64_t) v);		\
	stxa_nc((caddr_t)((h) + (o)), bus_type_asi[(t)->type], (v));	\
} while (0)
#endif

/*
 *	void bus_space_write_multi_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    const u_intN_t *addr, size_t count));
 *
 * Write `count' 1, 2, 4, or 8 byte quantities from the buffer
 * provided to bus space described by tag/handle/offset.
 */
#define	bus_space_write_multi_1(t, h, o, a, c) do {			\
	int i = c;							\
	u_int8_t *p = (u_int8_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_1(t, h, o, *p++);			\
} while (0)

#define bus_space_write_multi_2(t, h, o, a, c) do {			\
	int i = c;							\
	u_int16_t *p = (u_int16_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_2(t, h, o, *p++);			\
} while (0)

#define bus_space_write_multi_4(t, h, o, a, c) do {			\
	int i = c;							\
	u_int32_t *p = (u_int32_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_4(t, h, o, *p++);			\
} while (0)

#define bus_space_write_multi_8(t, h, o, a, c) do {			\
	int i = c;							\
	u_int64_t *p = (u_int64_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_8(t, h, o, *p++);			\
} while (0)

/*
 *	void bus_space_set_multi_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset, u_intN_t val,
 *	    size_t count));
 *
 * Write the 1, 2, 4, or 8 byte value `val' to bus space described
 * by tag/handle/offset `count' times.
 */
#define bus_space_set_multi_1(t, h, o, v, c) do {			\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_1(t, h, o, v);				\
} while (0)

#define bus_space_set_multi_2(t, h, o, v, c) do {			\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_2(t, h, o, v);				\
} while (0)

#define bus_space_set_multi_4(t, h, o, v, c) do {			\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_4(t, h, o, v);				\
} while (0)

#define bus_space_set_multi_8(t, h, o, v, c) do {			\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_8(t, h, o, v);				\
} while (0)

/*
 *	void bus_space_read_region_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t off,
 *	    u_intN_t *addr, bus_size_t count));
 *
 */
static void bus_space_read_region_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int8_t *,
	bus_size_t));
static void bus_space_read_region_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int16_t *,
	bus_size_t));
static void bus_space_read_region_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int32_t *,
	bus_size_t));
static void bus_space_read_region_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int64_t *,
	bus_size_t));

static __inline__ void
bus_space_read_region_1(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int8_t		*a;
{
	for (; c; a++, c--, o++)
		*a = bus_space_read_1(t, h, o);
}

static __inline__ void
bus_space_read_region_2(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int16_t		*a;
{
	for (; c; a++, c--, o+=2)
		*a = bus_space_read_2(t, h, o);
}

static __inline__ void
bus_space_read_region_4(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int32_t		*a;
{
	for (; c; a++, c--, o+=4)
		*a = bus_space_read_4(t, h, o);
}

static __inline__ void
bus_space_read_region_8(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int64_t		*a;
{
	for (; c; a++, c--, o+=8)
		*a = bus_space_read_8(t, h, o);
}

/*
 *	void bus_space_write_region_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t off,
 *	    u_intN_t *addr, bus_size_t count));
 *
 */
static void bus_space_write_region_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int8_t *,
	bus_size_t));
static void bus_space_write_region_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int16_t *,
	bus_size_t));
static void bus_space_write_region_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int32_t *,
	bus_size_t));
static void bus_space_write_region_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int64_t *,
	bus_size_t));

static __inline__ void
bus_space_write_region_1(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int8_t		*a;
{
	for (; c; a++, c--, o++)
		bus_space_write_1(t, h, o, *a);
}

static __inline__ void
bus_space_write_region_2(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int16_t		*a;
{
	for (; c; a++, c--, o+=2)
		bus_space_write_2(t, h, o, *a);
}

static __inline__ void
bus_space_write_region_4(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int32_t		*a;
{
	for (; c; a++, c--, o+=4)
		bus_space_write_4(t, h, o, *a);
}

static __inline__ void
bus_space_write_region_8(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int64_t		*a;
{
	for (; c; a++, c--, o+=8)
		bus_space_write_8(t, h, o, *a);
}

/*
 *	void bus_space_set_region_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t off,
 *	    u_intN_t *addr, bus_size_t count));
 *
 */
static void bus_space_set_region_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int8_t,
	bus_size_t));
static void bus_space_set_region_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int16_t,
	bus_size_t));
static void bus_space_set_region_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int32_t,
	bus_size_t));
static void bus_space_set_region_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int64_t,
	bus_size_t));

static __inline__ void
bus_space_set_region_1(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int8_t		v;
{
	for (; c; c--, o++)
		bus_space_write_1(t, h, o, v);
}

static __inline__ void
bus_space_set_region_2(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int16_t		v;
{
	for (; c; c--, o+=2)
		bus_space_write_2(t, h, o, v);
}

static __inline__ void
bus_space_set_region_4(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int32_t		v;
{
	for (; c; c--, o+=4)
		bus_space_write_4(t, h, o, v);
}

static __inline__ void
bus_space_set_region_8(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int64_t		v;
{
	for (; c; c--, o+=8)
		bus_space_write_8(t, h, o, v);
}

/*
 *	void bus_space_copy_region_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh1, bus_size_t off1,
 *	    bus_space_handle_t bsh2, bus_size_t off2,
 *	    bus_size_t count));
 *
 * Copy `count' 1, 2, 4, or 8 byte values from bus space starting
 * at tag/bsh1/off1 to bus space starting at tag/bsh2/off2.
 */
static void bus_space_copy_region_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));
static void bus_space_copy_region_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));
static void bus_space_copy_region_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));
static void bus_space_copy_region_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));

static __inline__ void
bus_space_copy_region_1(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1++, o2++)
	    bus_space_write_1(t, h1, o1, bus_space_read_1(t, h2, o2));
}

static __inline__ void
bus_space_copy_region_2(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1+=2, o2+=2)
	    bus_space_write_2(t, h1, o1, bus_space_read_2(t, h2, o2));
}

static __inline__ void
bus_space_copy_region_4(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1+=4, o2+=4)
	    bus_space_write_4(t, h1, o1, bus_space_read_4(t, h2, o2));
}

static __inline__ void
bus_space_copy_region_8(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1+=8, o2+=8)
	    bus_space_write_8(t, h1, o1, bus_space_read_8(t, h2, o2));
}

/*
 *	u_intN_t bus_space_read_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset));
 *
 * Read a 1, 2, 4, or 8 byte quantity from bus space
 * described by tag/handle/offset.
 */
#ifndef BUS_SPACE_DEBUG
#define	bus_space_read_stream_1(t, h, o)				\
	    lduba_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type])

#define	bus_space_read_stream_2(t, h, o)				\
	    lduha_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type])

#define	bus_space_read_stream_4(t, h, o)				\
	    lduwa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type])

#define	bus_space_read_stream_8(t, h, o)				\
	    ldxa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type])
#else
#define	bus_space_read_stream_1(t, h, o) ({				\
	unsigned char __bv =				      		\
	    lduba_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr1(%llx + %llx, %x) -> %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], (unsigned int) __bv);	\
	__bv; })

#define	bus_space_read_stream_2(t, h, o) ({				\
	unsigned short __bv =				      		\
	    lduha_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr2(%llx + %llx, %x) -> %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], (unsigned int)__bv);		\
	__bv; })

#define	bus_space_read_stream_4(t, h, o) ({				\
	unsigned int __bv =				      		\
	    lduwa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr4(%llx + %llx, %x) -> %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], __bv);			\
	__bv; })

#define	bus_space_read_stream_8(t, h, o) ({				\
	u_int64_t __bv =				      		\
	    ldxa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type]);	\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsr8(%llx + %llx, %x) -> %llx\n", (u_int64_t)(h),	\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], __bv);			\
	__bv; })
#endif

/*
 *	void bus_space_read_multi_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t *addr, size_t count));
 *
 * Read `count' 1, 2, 4, or 8 byte quantities from bus space
 * described by tag/handle/offset and copy into buffer provided.
 */
#define	bus_space_read_multi_stream_1(t, h, o, a, c) do {		\
	int i = c;							\
	u_int8_t *p = (u_int8_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_stream_1(t, h, o);		\
} while (0)

#define	bus_space_read_multi_stream_2(t, h, o, a, c) do {		\
	int i = c;							\
	u_int16_t *p = (u_int16_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_stream_2(t, h, o);		\
} while (0)

#define	bus_space_read_multi_stream_4(t, h, o, a, c) do {		\
	int i = c;							\
	u_int32_t *p = (u_int32_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_stream_4(t, h, o);		\
} while (0)

#define	bus_space_read_multi_stream_8(t, h, o, a, c) do {		\
	int i = c;							\
	u_int64_t *p = (u_int64_t *)a;					\
	while (i-- > 0)							\
		*p++ = bus_space_read_stream_8(t, h, o);		\
} while (0)

/*
 *	void bus_space_write_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t value));
 *
 * Write the 1, 2, 4, or 8 byte value `value' to bus space
 * described by tag/handle/offset.
 */
#ifndef BUS_SPACE_DEBUG
#define	bus_space_write_stream_1(t, h, o, v)				\
	stba_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v))

#define	bus_space_write_stream_2(t, h, o, v)				\
	stha_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v))

#define	bus_space_write_stream_4(t, h, o, v)				\
	stwa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v))

#define	bus_space_write_stream_8(t, h, o, v)				\
	stxa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v))
#else
#define	bus_space_write_stream_1(t, h, o, v) do {			\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw1(%llx + %llx, %x) <- %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], (unsigned int) v);		\
	stba_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v));	\
} while (0)

#define	bus_space_write_stream_2(t, h, o, v) do {			\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw2(%llx + %llx, %x) <- %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], (unsigned int) v);		\
	stha_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v));	\
} while (0)

#define	bus_space_write_stream_4(t, h, o, v) ({				\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw4(%llx + %llx, %x) <- %x\n", (u_int64_t)(h),		\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], (unsigned int) v);		\
	stwa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v));	\
} while (0)

#define	bus_space_write_stream_8(t, h, o, v) ({				\
	if (bus_space_debug & BSDB_ACCESS)				\
	printf("bsw8(%llx + %llx, %x) <- %llx\n", (u_int64_t)(h),	\
		(u_int64_t)(o),						\
		bus_stream_asi[(t)->type], (u_int64_t) v);		\
	stxa_nc((caddr_t)((h) + (o)), bus_stream_asi[(t)->type], (v));	\
} while (0)
#endif

/*
 *	void bus_space_write_multi_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    const u_intN_t *addr, size_t count));
 *
 * Write `count' 1, 2, 4, or 8 byte quantities from the buffer
 * provided to bus space described by tag/handle/offset.
 */
#define	bus_space_write_multi_stream_1(t, h, o, a, c) do {		\
	int i = c;							\
	u_int8_t *p = (u_int8_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_stream_1(t, h, o, *p++);		\
} while (0)

#define bus_space_write_multi_stream_2(t, h, o, a, c) do {		\
	int i = c;							\
	u_int16_t *p = (u_int16_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_stream_2(t, h, o, *p++);		\
} while (0)

#define bus_space_write_multi_stream_4(t, h, o, a, c) do {		\
	int i = c;							\
	u_int32_t *p = (u_int32_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_stream_4(t, h, o, *p++);		\
} while (0)

#define bus_space_write_multi_stream_8(t, h, o, a, c) do {		\
	int i = c;							\
	u_int64_t *p = (u_int64_t *)a;					\
	while (i-- > 0)							\
		bus_space_write_stream_8(t, h, o, *p++);		\
} while (0)

/*
 *	void bus_space_set_multi_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset, u_intN_t val,
 *	    size_t count));
 *
 * Write the 1, 2, 4, or 8 byte value `val' to bus space described
 * by tag/handle/offset `count' times.
 */
#define bus_space_set_multi_stream_1(t, h, o, v, c) do {		\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_stream_1(t, h, o, v);			\
} while (0)

#define bus_space_set_multi_stream_2(t, h, o, v, c) do {		\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_stream_2(t, h, o, v);			\
} while (0)

#define bus_space_set_multi_stream_4(t, h, o, v, c) do {		\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_stream_4(t, h, o, v);			\
} while (0)

#define bus_space_set_multi_stream_8(t, h, o, v, c) do {		\
	int i = c;							\
	while (i-- > 0)							\
		bus_space_write_stream_8(t, h, o, v);			\
} while (0)

/*
 *	void bus_space_read_region_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t off,
 *	    u_intN_t *addr, bus_size_t count));
 *
 */
static void bus_space_read_region_stream_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int8_t *,
	bus_size_t));
static void bus_space_read_region_stream_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int16_t *,
	bus_size_t));
static void bus_space_read_region_stream_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int32_t *,
	bus_size_t));
static void bus_space_read_region_stream_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	u_int64_t *,
	bus_size_t));

static __inline__ void
bus_space_read_region_stream_1(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int8_t		*a;
{
	for (; c; a++, c--, o++)
		*a = bus_space_read_stream_1(t, h, o);
}

static __inline__ void
bus_space_read_region_stream_2(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int16_t		*a;
{
	for (; c; a++, c--, o+=2)
		*a = bus_space_read_stream_2(t, h, o);
}

static __inline__ void
bus_space_read_region_stream_4(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int32_t		*a;
{
	for (; c; a++, c--, o+=4)
		*a = bus_space_read_stream_4(t, h, o);
}

static __inline__ void
bus_space_read_region_stream_8(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	u_int64_t		*a;
{
	for (; c; a++, c--, o+=8)
		*a = bus_space_read_stream_8(t, h, o);
}

/*
 *	void bus_space_write_region_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t off,
 *	    u_intN_t *addr, bus_size_t count));
 *
 */
static void bus_space_write_region_stream_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int8_t *,
	bus_size_t));
static void bus_space_write_region_stream_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int16_t *,
	bus_size_t));
static void bus_space_write_region_stream_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int32_t *,
	bus_size_t));
static void bus_space_write_region_stream_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int64_t *,
	bus_size_t));

static __inline__ void
bus_space_write_region_stream_1(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int8_t		*a;
{
	for (; c; a++, c--, o++)
		bus_space_write_stream_1(t, h, o, *a);
}

static __inline__ void
bus_space_write_region_stream_2(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int16_t		*a;
{
	for (; c; a++, c--, o+=2)
		bus_space_write_stream_2(t, h, o, *a);
}

static __inline__ void
bus_space_write_region_stream_4(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int32_t		*a;
{
	for (; c; a++, c--, o+=4)
		bus_space_write_stream_4(t, h, o, *a);
}

static __inline__ void
bus_space_write_region_stream_8(t, h, o, a, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int64_t		*a;
{
	for (; c; a++, c--, o+=8)
		bus_space_write_stream_8(t, h, o, *a);
}

/*
 *	void bus_space_set_region_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t off,
 *	    u_intN_t *addr, bus_size_t count));
 *
 */
static void bus_space_set_region_stream_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int8_t,
	bus_size_t));
static void bus_space_set_region_stream_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int16_t,
	bus_size_t));
static void bus_space_set_region_stream_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int32_t,
	bus_size_t));
static void bus_space_set_region_stream_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	const u_int64_t,
	bus_size_t));

static __inline__ void
bus_space_set_region_stream_1(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int8_t		v;
{
	for (; c; c--, o++)
		bus_space_write_stream_1(t, h, o, v);
}

static __inline__ void
bus_space_set_region_stream_2(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int16_t		v;
{
	for (; c; c--, o+=2)
		bus_space_write_stream_2(t, h, o, v);
}

static __inline__ void
bus_space_set_region_stream_4(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int32_t		v;
{
	for (; c; c--, o+=4)
		bus_space_write_stream_4(t, h, o, v);
}

static __inline__ void
bus_space_set_region_stream_8(t, h, o, v, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h;
	bus_size_t		o, c;
	const u_int64_t		v;
{
	for (; c; c--, o+=8)
		bus_space_write_stream_8(t, h, o, v);
}

/*
 *	void bus_space_copy_region_stream_N __P((bus_space_tag_t tag,
 *	    bus_space_handle_t bsh1, bus_size_t off1,
 *	    bus_space_handle_t bsh2, bus_size_t off2,
 *	    bus_size_t count));
 *
 * Copy `count' 1, 2, 4, or 8 byte values from bus space starting
 * at tag/bsh1/off1 to bus space starting at tag/bsh2/off2.
 */
static void bus_space_copy_region_stream_1 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));
static void bus_space_copy_region_stream_2 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));
static void bus_space_copy_region_stream_4 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));
static void bus_space_copy_region_stream_8 __P((bus_space_tag_t,
	bus_space_handle_t,
	bus_size_t,
	bus_space_handle_t,
	bus_size_t,
	bus_size_t));


static __inline__ void
bus_space_copy_region_stream_1(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1++, o2++)
	    bus_space_write_stream_1(t, h1, o1, bus_space_read_stream_1(t, h2,
		o2));
}

static __inline__ void
bus_space_copy_region_stream_2(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1+=2, o2+=2)
	    bus_space_write_stream_2(t, h1, o1, bus_space_read_stream_2(t, h2,
		o2));
}

static __inline__ void
bus_space_copy_region_stream_4(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1+=4, o2+=4)
	    bus_space_write_stream_4(t, h1, o1, bus_space_read_stream_4(t, h2,
		o2));
}

static __inline__ void
bus_space_copy_region_stream_8(t, h1, o1, h2, o2, c)
	bus_space_tag_t		t;
	bus_space_handle_t	h1, h2;
	bus_size_t		o1, o2;
	bus_size_t		c;
{
	for (; c; c--, o1+=8, o2+=8)
	    bus_space_write_stream_8(t, h1, o1, bus_space_read_8(t, h2, o2));
}

#define BUS_SPACE_ALIGNED_POINTER(p, t) ALIGNED_POINTER(p, t)

/* Back-compat functions for old ISA drivers */

extern bus_space_tag_t isa_io_bt;
extern bus_space_handle_t isa_io_hdl;
extern bus_space_tag_t isa_mem_bt;
extern bus_space_handle_t isa_mem_hdl;

#define inb(o)		bus_space_read_1(isa_io_bt, isa_io_hdl, o)
#define inw(o)		bus_space_read_2(isa_io_bt, isa_io_hdl, o)
#define inl(o)		bus_space_read_4(isa_io_bt, isa_io_hdl, o)
#if 0
#define outb(o, v) do {							\
	printf("outb used at %s:%d, address 0x%x -> 0x%lx\n",		\
	    __func__, __LINE__, o, (unsigned long)isa_io_hdl + o);	\
	bus_space_write_1(isa_io_bt, isa_io_hdl, o, v);			\
} while (0)
#else
#define outb(o, v) bus_space_write_1(isa_io_bt, isa_io_hdl, o, v)
#endif
#define outw(o, v)	bus_space_write_2(isa_io_bt, isa_io_hdl, o, v)
#define outl(o, v)	bus_space_write_4(isa_io_bt, isa_io_hdl, o, v)

#define readb(o)	bus_space_read_1(isa_mem_bt, isa_mem_hdl, o)
#define readw(o)	bus_space_read_2(isa_mem_bt, isa_mem_hdl, o)
#define readl(o)	bus_space_read_4(isa_mem_bt, isa_mem_hdl, o)
#define writeb(o, v)	bus_space_write_1(isa_mem_bt, isa_mem_hdl, o, v)
#define writew(o, v)	bus_space_write_2(isa_mem_bt, isa_mem_hdl, o, v)
#define writel(o, v)	bus_space_write_4(isa_mem_bt, isa_mem_hdl, o, v)

#define insb(o, a, c) \
	bus_space_read_multi_1(isa_io_bt, isa_io_hdl, o, (void*)a, c)
#define insw(o, a, c) \
	bus_space_read_multi_2(isa_io_bt, isa_io_hdl, o, (void*)a, c)
#define insl(o, a, c) \
	bus_space_read_multi_4(isa_io_bt, isa_io_hdl, o, (void*)a, c)
#define outsb(o, a, c) \
	bus_space_write_multi_1(isa_io_bt, isa_io_hdl, o, (void*)a, c)
#define outsw(o, a, c) \
	bus_space_write_multi_2(isa_io_bt, isa_io_hdl, o, (void*)a, c)
#define outsl(o, a, c) \
	bus_space_write_multi_4(isa_io_bt, isa_io_hdl, o, (void*)a, c)

#define memcpy_fromio(d, s, c) \
	bus_space_read_region_1(isa_mem_bt, isa_mem_hdl, s, d, c)
#define memcpy_toio(d, s, c) \
	bus_space_write_region_1(isa_mem_bt, isa_mem_hdl, d, s, c)
#define memcpy_io(d, s, c) \
	bus_space_copy_region_1(isa_mem_bt, isa_mem_hdl, s, isa_mem_hdl, d, c)
#define memset_io(d, v, c) \
	bus_space_set_region_1(isa_mem_bt, isa_mem_hdl, d, v, c)
#define memsetw_io(d, v, c) \
	bus_space_set_region_2(isa_mem_bt, isa_mem_hdl, d, v, c)

static __inline void
memsetw(void *d, int val, size_t size)
{
    u_int16_t *sp = d;

    while (size--)
	*sp++ = val;
}

/* DMA support */

/*
 * Flags used in various bus DMA methods.
 */
#define	BUS_DMA_WAITOK		0x000	/* safe to sleep (pseudo-flag) */
#define	BUS_DMA_NOWAIT		0x001	/* not safe to sleep */
#define	BUS_DMA_ALLOCNOW	0x002	/* perform resource allocation now */
#define	BUS_DMAMEM_NOSYNC	0x004	/* map memory to not require sync */
#define	BUS_DMA_NOWRITE		0x008
#define	BUS_DMA_BUS1		0x010	
#define	BUS_DMA_BUS2		0x020
#define	BUS_DMA_BUS3		0x040
#define	BUS_DMA_BUS4		0x080
/*
 * The following flags are from NetBSD, but are not implemented for all
 * architetures, and should therefore not be used in MI code.
 * Some have different values than under NetBSD.
 */
#define	BUS_DMA_STREAMING	0x100	/* hint: sequential, unidirectional */
#define	BUS_DMA_READ		0x200	/* mapping is device -> memory only */
#define	BUS_DMA_WRITE		0x400	/* mapping is memory -> device only */
#define	BUS_DMA_COHERENT	0x800	/* hint: map memory DMA coherent */

#define	BUS_DMA_NOCACHE		BUS_DMA_BUS1
/* Don't bother with alignment */
#define	BUS_DMA_DVMA		BUS_DMA_BUS2

/* Forwards needed by prototypes below. */
struct mbuf;
struct uio;

/*
 *	bus_dmasync_op_t
 *
 *	Operations performed by bus_dmamap_sync().
 */
typedef enum {
	BUS_DMASYNC_PREREAD,
	BUS_DMASYNC_POSTREAD,
	BUS_DMASYNC_PREWRITE,
	BUS_DMASYNC_POSTWRITE,
} bus_dmasync_op_t;

/*
 * A function that returns 1 if the address cannot be accessed by
 * a device and 0 if it can be.
 */
typedef int bus_dma_filter_t(void *, bus_addr_t);

typedef struct bus_dma_tag	*bus_dma_tag_t;
typedef struct bus_dmamap	*bus_dmamap_t;

/*
 *	bus_dma_segment_t
 *
 *	Describes a single contiguous DMA transaction.  Values
 *	are suitable for programming into DMA registers.
 */
struct bus_dma_segment {
	bus_addr_t	ds_addr;	/* DVMA address */
	bus_size_t	ds_len;		/* length of transfer */
};
typedef struct bus_dma_segment	bus_dma_segment_t;

/*
 * A function that processes a successfully loaded dma map or an error
 * from a delayed load map.
 */
typedef void bus_dmamap_callback_t(void *, bus_dma_segment_t *, int, int);

/*
 *	bus_dma_tag_t
 *
 *	A machine-dependent opaque type describing the implementation of
 *	DMA for a given bus.
 */
struct bus_dma_tag {
	void		*cookie;		/* cookie used in the guts */
	bus_dma_tag_t	parent;
	bus_size_t	alignment;
	bus_size_t	boundary;
	bus_addr_t	lowaddr;
	bus_addr_t	highaddr;
	bus_dma_filter_t	*filter;
	void		*filterarg;
	bus_size_t	maxsize;
	u_int		nsegments;
	bus_size_t	maxsegsz;
	int		flags;
	int		ref_count;
	int		map_count;

	/*
	 * DMA mapping methods.
	 */
	int	(*dmamap_create) __P((bus_dma_tag_t, int, bus_dmamap_t *));
	int	(*dmamap_destroy) __P((bus_dma_tag_t, bus_dmamap_t));
	int	(*dmamap_load) __P((bus_dma_tag_t, bus_dmamap_t, void *,
		    bus_size_t, bus_dmamap_callback_t *, void *, int));
	void	(*dmamap_unload) __P((bus_dma_tag_t, bus_dmamap_t));
	void	(*dmamap_sync) __P((bus_dma_tag_t, bus_dmamap_t,
		    bus_dmasync_op_t));

	/*
	 * DMA memory utility functions.
	 */
	int	(*dmamem_alloc) __P((bus_dma_tag_t, void **, int,
	    	    bus_dmamap_t *));
	void	(*dmamem_free) __P((bus_dma_tag_t, void *, bus_dmamap_t));
};

/*
 * XXX: This is a kluge. It would be better to handle dma tags in a hierarchical
 * way, and have a BUS_GET_DMA_TAG(); however, since this is not currently the
 * case, save a root tag in the relevant bus attach function and use that.
 * Keep the hierarchical structure, it might become needed in the future.
 */
extern bus_dma_tag_t sparc64_root_dma_tag;

int bus_dma_tag_create(bus_dma_tag_t, bus_size_t, bus_size_t, bus_addr_t,
	bus_addr_t, bus_dma_filter_t *, void *, bus_size_t, int, bus_size_t,
	int, bus_dma_tag_t *);

int bus_dma_tag_destroy(bus_dma_tag_t);

int sparc64_dmamem_alloc_map(bus_dma_tag_t dmat, bus_dmamap_t *mapp);
void sparc64_dmamem_free_map(bus_dma_tag_t dmat, bus_dmamap_t map);

#define	bus_dmamap_create(t, f, p)					\
	(*(t)->dmamap_create)((t), (f), (p))
#define	bus_dmamap_destroy(t, p)					\
	(*(t)->dmamap_destroy)((t), (p))
#define	bus_dmamap_load(t, m, p, s, cb, cba, f)				\
	(*(t)->dmamap_load)((t), (m), (p), (s), (cb), (cba), (f))
#define	bus_dmamap_unload(t, p)						\
	(*(t)->dmamap_unload)((t), (p))
#define	bus_dmamap_sync(t, m, op)					\
	(void)((t)->dmamap_sync ?					\
	    (*(t)->dmamap_sync)((t), (m), (op)) : (void)0)

#define	bus_dmamem_alloc(t, v, f, m)					\
	(*(t)->dmamem_alloc)((t), (v), (f), (m))
#define	bus_dmamem_free(t, v, m)					\
	(*(t)->dmamem_free)((t), (v), (m))

/*
 *	bus_dmamap_t
 *
 *	Describes a DMA mapping.
 */
struct bus_dmamap {
	bus_dma_tag_t	dmat;
	void		*buf;		/* unmapped buffer pointer */
	bus_size_t	buflen;		/* unmapped buffer length */
	bus_addr_t	start;		/* start of mapped region */
	struct resource *res;		/* associated resource */
};

#endif /* !_MACHINE_BUS_H_ */
