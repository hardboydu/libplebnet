/*
 * Copyright (c) 1997, Stefan Esser <se@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * $Id: pcibus.c,v 1.6 1998/11/15 18:25:16 dfr Exp $
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/sysctl.h>
#include <sys/rman.h>

#include <pci/pcivar.h>
#include <machine/chipset.h>
#include <machine/cpuconf.h>
#include <machine/resource.h>

char chipset_type[10];
int chipset_bwx = 0;
long chipset_ports = 0;
long chipset_memory = 0;
long chipset_dense = 0;
long chipset_hae_mask = 0;

SYSCTL_NODE(_hw, OID_AUTO, chipset, CTLFLAG_RW, 0, "PCI chipset information");
SYSCTL_STRING(_hw_chipset, OID_AUTO, type, CTLFLAG_RD, chipset_type, 0,
	      "PCI chipset type");
SYSCTL_INT(_hw_chipset, OID_AUTO, bwx, CTLFLAG_RD, &chipset_bwx, 0,
	   "PCI chipset supports BWX access");
SYSCTL_LONG(_hw_chipset, OID_AUTO, ports, CTLFLAG_RD, &chipset_ports, 0,
	    "PCI chipset port address");
SYSCTL_LONG(_hw_chipset, OID_AUTO, memory, CTLFLAG_RD, &chipset_memory, 0,
	    "PCI chipset memory address");
SYSCTL_LONG(_hw_chipset, OID_AUTO, dense, CTLFLAG_RD, &chipset_dense, 0,
	    "PCI chipset dense memory address");
SYSCTL_LONG(_hw_chipset, OID_AUTO, hae_mask, CTLFLAG_RD, &chipset_hae_mask, 0,
	    "PCI chipset mask for HAE register");

static int cfgmech;
static int devmax;

#ifdef notyet

/* return max number of devices on the bus */
int
pci_maxdevs(pcicfgregs *cfg)
{
	return chipset.maxdevs(cfg->bus);
}

#endif

/* read configuration space register */

int
pci_cfgread(pcicfgregs *cfg, int reg, int bytes)
{
	switch (bytes) {
	case 1:
		return chipset.cfgreadb(cfg->bus, cfg->slot, cfg->func, reg);
	case 2:
		return chipset.cfgreadw(cfg->bus, cfg->slot, cfg->func, reg);
	case 4:
		return chipset.cfgreadl(cfg->bus, cfg->slot, cfg->func, reg);
	}
	return ~0;
}		


/* write configuration space register */

void
pci_cfgwrite(pcicfgregs *cfg, int reg, int data, int bytes)
{
	switch (bytes) {
	case 1:
		return chipset.cfgwriteb(cfg->bus, cfg->slot, cfg->func, reg, data);
	case 2:
		return chipset.cfgwritew(cfg->bus, cfg->slot, cfg->func, reg, data);
	case 4:
		return chipset.cfgwritel(cfg->bus, cfg->slot, cfg->func, reg, data);
	}
}

int
pci_cfgopen(void)
{
	return 1;
}

vm_offset_t 
pci_cvt_to_dense(vm_offset_t sparse)
{
	if(chipset.cvt_to_dense)
		return chipset.cvt_to_dense(sparse);
	else
		return NULL;
}

vm_offset_t
pci_cvt_to_bwx(vm_offset_t sparse)
{
	if(chipset.cvt_to_bwx)
		return chipset.cvt_to_bwx(sparse);
	else
		return NULL;
}

/*
 * These can disappear when I update the pci code to use the new
 * device framework.
 */
struct intrec *
intr_create(void *dev_instance, int irq, inthand2_t handler, void *arg,
	    intrmask_t *maskptr, int flags)
{
	struct resource *res;
	device_t pcib = chipset.intrdev;
	int zero = 0;
	void *cookie;

	res = BUS_ALLOC_RESOURCE(pcib, NULL, SYS_RES_IRQ, &zero,
				irq, irq, 1, RF_SHAREABLE | RF_ACTIVE);
	if (BUS_SETUP_INTR(pcib, pcib, res, (driver_intr_t *)handler, arg, &cookie))
		return 0;

	return (struct intrec *)cookie;
}

int
intr_connect(struct intrec *idesc)
{
	/*
	 * intr_create has already connected it (doesn't matter for the
	 * only consumer of this interface (pci).
	 */
	return 0;
}

void
alpha_platform_assign_pciintr(pcicfgregs *cfg)
{
	if(platform.pci_intr_map)
		platform.pci_intr_map((void *)cfg);
}

static struct rman irq_rman, port_rman, mem_rman;

void pci_init_resources()
{
	irq_rman.rm_start = 0;
	irq_rman.rm_end = 32;
	irq_rman.rm_type = RMAN_ARRAY;
	irq_rman.rm_descr = "PCI Interrupt request lines";
	if (rman_init(&irq_rman)
	    || rman_manage_region(&irq_rman, 0, 31))
		panic("cia_probe irq_rman");

	port_rman.rm_start = 0;
	port_rman.rm_end = 0xffff;
	port_rman.rm_type = RMAN_ARRAY;
	port_rman.rm_descr = "I/O ports";
	if (rman_init(&port_rman)
	    || rman_manage_region(&port_rman, 0, 0xffff))
		panic("cia_probe port_rman");

	mem_rman.rm_start = 0;
	mem_rman.rm_end = ~0u;
	mem_rman.rm_type = RMAN_ARRAY;
	mem_rman.rm_descr = "I/O memory addresses";
	if (rman_init(&mem_rman)
	    || rman_manage_region(&mem_rman, 0x0, (1L << 32)))
		panic("cia_probe mem_rman");
}

/*
 * Allocate a resource on behalf of child.  NB: child is usually going to be a
 * child of one of our descendants, not a direct child of the pci chipset.
 */
struct resource *
pci_alloc_resource(device_t bus, device_t child, int type, int *rid,
		   u_long start, u_long end, u_long count, u_int flags)
{
	struct	rman *rm;

	switch (type) {
	case SYS_RES_IRQ:
		rm = &irq_rman;
		break;

	case SYS_RES_IOPORT:
		rm = &port_rman;
		break;

	case SYS_RES_MEMORY:
		rm = &mem_rman;
		break;

	default:
		return 0;
	}

	return rman_reserve_resource(rm, start, end, count, flags, child);
}

int
pci_activate_resource(device_t bus, device_t child, int type, int rid,
		      struct resource *r)
{
	return (rman_activate_resource(r));
}

int
pci_deactivate_resource(device_t bus, device_t child, int type, int rid,
			  struct resource *r)
{
	return (rman_deactivate_resource(r));
}

int
pci_release_resource(device_t bus, device_t child, int type, int rid,
		       struct resource *r)
{
	return (rman_release_resource(r));
}

void
memcpy_fromio(void *d, u_int32_t s, size_t size)
{
    char *cp = d;

    while (size--)
	*cp++ = readb(s++);
}

void
memcpy_toio(u_int32_t d, void *s, size_t size)
{
    char *cp = s;

    while (size--)
	writeb(d++, *cp++);
}

void
memset_io(u_int32_t d, int val, size_t size)
{
    while (size--)
	writeb(d++, val);
}

#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>

DB_COMMAND(in, db_in)
{
    int c;
    int size;
    u_int32_t val;

    if (!have_addr)
	return;

    size = -1;
    while (c = *modif++) {
	switch (c) {
	case 'b':
	    size = 1;
	    break;
	case 'w':
	    size = 2;
	    break;
	case 'l':
	    size = 4;
	    break;
	}
    }

    if (size < 0) {
	db_printf("bad size\n");
	return;
    }

    if (count <= 0) count = 1;
    while (--count >= 0) {
	db_printf("%08x:\t", addr);
	switch (size) {
	case 1:
	    db_printf("%02x\n", inb(addr));
	    break;
	case 2:
	    db_printf("%04x\n", inw(addr));
	    break;
	case 4:
	    db_printf("%08x\n", inl(addr));
	    break;
	}
    }
}

#endif
