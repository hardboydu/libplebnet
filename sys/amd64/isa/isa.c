/*-
 * Copyright (c) 1998 Doug Rabson
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
 *	$Id: isa.c,v 1.127 1999/05/22 15:18:12 dfr Exp $
 */

/*
 * Modifications for Intel architecture by Garrett A. Wollman.
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <machine/bus.h>
#include <sys/rman.h>

#include <machine/resource.h>

#include <isa/isavar.h>
#include <isa/isa_common.h>

void
isa_init(void)
{
    isa_wrap_old_drivers();
}

/*
 * This implementation simply passes the request up to the parent
 * bus, which in our case is the special i386 nexus, substituting any
 * configured values if the caller defaulted.  We can get away with
 * this because there is no special mapping for ISA resources on an Intel
 * platform.  When porting this code to another architecture, it may be
 * necessary to interpose a mapping layer here.
 */
struct resource *
isa_alloc_resource(device_t bus, device_t child, int type, int *rid,
		   u_long start, u_long end, u_long count, u_int flags)
{
	/*
	 * Consider adding a resource definition. We allow rid 0-1 for
	 * irq and drq, 0-3 for memory and 0-7 for ports which is
	 * sufficient for isapnp.
	 */
	int passthrough = (device_get_parent(child) != bus);
	int isdefault = (start == 0UL && end == ~0UL);
	struct resource_list *rl;
	struct resource_list_entry *rle;
	
	if (!passthrough && !isdefault) {
		rl = device_get_ivars(child);
		rle = resource_list_find(rl, type, *rid);
		if (!rle) {
			if (*rid < 0)
				return 0;
			if (type == SYS_RES_IRQ && *rid > 1)
				return 0;
			if (type == SYS_RES_DRQ && *rid > 1)
				return 0;
			if (type != SYS_RES_MEMORY && *rid > 3)
				return 0;
			if (type == SYS_RES_IOPORT && *rid > 7)
				return 0;
			resource_list_add(rl, type, *rid, start, end, count);
		}
	}

	return resource_list_alloc(bus, child, type, rid,
				   start, end, count, flags);
}

int
isa_release_resource(device_t bus, device_t child, int type, int rid,
		     struct resource *r)
{
	return resource_list_release(bus, child, type, rid, r);
}

/*
 * We can't use the bus_generic_* versions of these methods because those
 * methods always pass the bus param as the requesting device, and we need
 * to pass the child (the i386 nexus knows about this and is prepared to
 * deal).
 */
int
isa_setup_intr(device_t bus, device_t child, struct resource *r, int flags,
	       void (*ihand)(void *), void *arg, void **cookiep)
{
	return (BUS_SETUP_INTR(device_get_parent(bus), child, r, flags,
			       ihand, arg, cookiep));
}

int
isa_teardown_intr(device_t bus, device_t child, struct resource *r,
		  void *cookie)
{
	return (BUS_TEARDOWN_INTR(device_get_parent(bus), child, r, cookie));
}
