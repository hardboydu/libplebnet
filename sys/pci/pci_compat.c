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
 * $Id: pci_compat.c,v 1.12 1998/10/06 14:18:40 dfr Exp $
 *
 */

#include "pci.h"
#if NPCI > 0

/* for compatibility to FreeBSD-2.2 version of PCI code */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h> /* for DATA_SET support */

#include <vm/vm.h>
#include <vm/pmap.h>
#include <sys/interrupt.h>

#include <pci/pcireg.h>
#include <pci/pcivar.h>

#ifdef RESOURCE_CHECK
#include <sys/drvresource.h>
#endif

#ifdef APIC_IO
#include <machine/smp.h>
#endif

#ifdef PCI_COMPAT

/* ------------------------------------------------------------------------- */

static int
pci_mapno(pcicfgregs *cfg, int reg)
{
	int map = -1;
	if ((reg & 0x03) == 0) {
		map = (reg -0x10) / 4;
		if (map < 0 || map >= cfg->nummaps)
			map = -1;
	}
	return (map);
}

static int
pci_porten(pcicfgregs *cfg)
{
	return ((cfg->cmdreg & PCIM_CMD_PORTEN) != 0);
}

static int
pci_isportmap(pcicfgregs *cfg, int map)

{
	return ((unsigned)map < cfg->nummaps 
		&& (cfg->map[map].type & PCI_MAPPORT) != 0);
}

static int
pci_memen(pcicfgregs *cfg)
{
	return ((cfg->cmdreg & PCIM_CMD_MEMEN) != 0);
}

static int
pci_ismemmap(pcicfgregs *cfg, int map)
{
	return ((unsigned)map < cfg->nummaps 
		&& (cfg->map[map].type & PCI_MAPMEM) != 0);
}

/* ------------------------------------------------------------------------- */

u_long
pci_conf_read(pcici_t tag, u_long reg)
{
	return (pci_cfgread(tag, reg, 4));
}

void
pci_conf_write(pcici_t tag, u_long reg, u_long data)
{
	pci_cfgwrite(tag, reg, data, 4);
}

int pci_map_port(pcici_t cfg, u_long reg, pci_port_t* pa)
{
	int map;

	map = pci_mapno(cfg, reg);
	if (pci_porten(cfg) && pci_isportmap(cfg, map)) {
		u_int32_t iobase;
		u_int32_t iosize;

		iobase = cfg->map[map].base;
		iosize = 1 << cfg->map[map].ln2size;
#ifdef RESOURCE_CHECK
		if (resource_claim(cfg, REST_PORT, RESF_NONE, 
				   iobase, iobase + iosize -1) == 0)
#endif /* RESOURCE_CHECK */
		{
			*pa = iobase;
			return (1);
		}
	}
	return (0);
}

int pci_map_mem(pcici_t cfg, u_long reg, vm_offset_t* va, vm_offset_t* pa)
{
	int map;

	map = pci_mapno(cfg, reg);
	if (pci_memen(cfg) && pci_ismemmap(cfg, map)) {
		u_int32_t paddr;
		u_int32_t psize;

		paddr = cfg->map[map].base;
		psize = 1 << cfg->map[map].ln2size;
#ifdef RESOURCE_CHECK
		if (resource_claim(cfg, REST_MEM, RESF_NONE, 
				   paddr, paddr + psize -1) == 0)
#endif /* RESOURCE_CHECK */
		{
			u_int32_t poffs;
			vm_offset_t vaddr;

			poffs = paddr - trunc_page(paddr);
#ifdef __i386__
			vaddr = (vm_offset_t)pmap_mapdev(paddr-poffs, psize+poffs);
#endif
#ifdef __alpha__
			vaddr = paddr-poffs;
#endif
			if (vaddr != NULL) {
				vaddr += poffs;
				*va = vaddr;
				*pa = paddr;
				return (1);
			}
		}
	}
	return (0);
}

int 
pci_map_dense(pcici_t cfg, u_long reg, vm_offset_t* va, vm_offset_t* pa)
{
	vm_offset_t dense;
	int retval = 0;

	if(pci_map_mem(cfg, reg, va, pa)){
#ifdef __alpha__
		if(dense = pci_cvt_to_dense(*pa)){
			*pa = dense;
			*va = ALPHA_PHYS_TO_K0SEG(*pa);
			return (1);
		}
#endif
#ifdef __i386__
		return(1);
#endif
	}
	return (0);
}

int 
pci_map_bwx(pcici_t cfg, u_long reg, vm_offset_t* va, vm_offset_t* pa)
{
	vm_offset_t bwx;
	int retval = 0;

	if(pci_map_mem(cfg, reg, va, pa)){
#ifdef __alpha__
		if(bwx = pci_cvt_to_bwx(*pa)){
			*pa = bwx;
			*va = ALPHA_PHYS_TO_K0SEG(*pa);
			return (1);
		}
#endif
#ifdef __i386__
		return(1);
#endif
	}
	return (0);
}


int
pci_map_int(pcici_t cfg, pci_inthand_t *func, void *arg, unsigned *maskptr)
{
	int error;
#ifdef APIC_IO
	int nextpin, muxcnt;
#endif
	if (cfg->intpin != 0) {
		int irq = cfg->intline;
		void *dev_instance = (void *)-1; /* XXX use cfg->devdata  */
		void *idesc;

		idesc = intr_create(dev_instance, irq, func, arg, maskptr, 0);
		error = intr_connect(idesc);
		if (error != 0)
			return 0;
#ifdef APIC_IO
		nextpin = next_apic_irq(irq);
		
		if (nextpin < 0)
			return 1;

		/* 
		 * Attempt handling of some broken mp tables.
		 *
		 * It's OK to yell (since the mp tables are broken).
		 * 
		 * Hanging in the boot is not OK
		 */

		muxcnt = 2;
		nextpin = next_apic_irq(nextpin);
		while (muxcnt < 5 && nextpin >= 0) {
			muxcnt++;
			nextpin = next_apic_irq(nextpin);
		}
		if (muxcnt >= 5) {
			printf("bogus MP table, more than 4 IO APIC pins connected to the same PCI device or ISA/EISA interrupt\n");
			return 0;
		}
		
		printf("bogus MP table, %d IO APIC pins connected to the same PCI device or ISA/EISA interrupt\n", muxcnt);

		nextpin = next_apic_irq(irq);
		while (nextpin >= 0) {
			idesc = intr_create(dev_instance, nextpin, func, arg,
					    maskptr, 0);
			error = intr_connect(idesc);
			if (error != 0)
				return 0;
			printf("Registered extra interrupt handler for int %d (in addition to int %d)\n", nextpin, irq);
			nextpin = next_apic_irq(nextpin);
		}
#endif
	}
	return (1);
}

int
pci_unmap_int(pcici_t cfg)
{
	return (0); /* not supported, yet, since cfg doesn't know about idesc */
}

/* ------------------------------------------------------------------------- */

/*
 * Preliminary support for "wired" PCI devices.
 * This code supports currently only devices on PCI bus 0, since the
 * mapping from PCI BIOS bus numbers to configuration file bus numbers 
 * is not yet maintained, whenever a PCI to PCI bridge is found.
 * The "bus" field of "pciwirecfg" correlates an PCI bus with the bridge 
 * it is attached to. The "biosbus" field is to be updated for each bus,
 * whose bridge is probed. An entry with bus != 0 and biosbus == 0 is
 * invalid and will be skipped in the search for a wired unit, but not
 * in the test for a free unit number.
 */

typedef struct {
	char		*name;
	int		unit;
	u_int8_t	bus;
	u_int8_t	slot;
	u_int8_t	func;
	u_int8_t	biosbus;
} pciwirecfg;

static pciwirecfg pci_wireddevs[] = {
	/* driver,	unit,	bus,	slot,	func,	BIOS bus */
#ifdef PCI_DEBUG
	{ "ncr",	2,	1,	4,	0,	0	},
	{ "ed",		2,	1,	5,	0,	0	},
#endif /* PCI_DEBUG */
	/* do not delete the end marker that follows this comment !!! */
	{ NULL }
};

/* return unit number of wired device, or -1 if no match */

static int
pci_wiredunit(pcicfgregs *cfg, char *name)
{
	pciwirecfg *p;

	p = pci_wireddevs;
	while (p->name != NULL) {
		if (p->bus == cfg->bus
		    && p->slot == cfg->slot
		    && p->func == cfg->func
		    && strcmp(p->name, name) == 0)
			return (p->unit);
		p++;
	}
	return (-1);
}

/* return free unit number equal or greater to the one supplied as parameter */

static int
pci_freeunit(pcicfgregs *cfg, char *name, int unit)
{
	pciwirecfg *p;

	p = pci_wireddevs;
	while (p->name != NULL) {
		if (p->unit == unit && strcmp(p->name, name) == 0) {
			p = pci_wireddevs;
			unit++;
		} else {
			p++;
		}
	}
	return (unit);
}

static char *drvname;

static char*
pci_probedrv(pcicfgregs *cfg, struct pci_device *dvp)
{
	if (dvp && dvp->pd_probe) {
		pcidi_t type = (cfg->device << 16) + cfg->vendor;
		return (dvp->pd_probe(cfg, type));
	}
	return (NULL);
}

static struct pci_lkm *pci_lkm_head;

static struct pci_device*
pci_finddrv(pcicfgregs *cfg)
{
	struct pci_device **dvpp;
	struct pci_device *dvp = NULL;
	struct pci_lkm *lkm;

	drvname = NULL;
	lkm = pci_lkm_head;
	while (drvname == NULL && lkm != NULL) {
		dvp = lkm->dvp;
		drvname = pci_probedrv(cfg, dvp);
		lkm = lkm->next;
	}

	dvpp = (struct pci_device **)pcidevice_set.ls_items;
	while (drvname == NULL && (dvp = *dvpp++) != NULL)
		drvname = pci_probedrv(cfg, dvp);
	return (dvp);
}

static void
pci_drvmessage(pcicfgregs *cfg, char *name, int unit)
{
	if (drvname == NULL || *drvname == '\0')
		return;
	printf("%s%d: <%s> rev 0x%02x", name, unit, drvname, cfg->revid);
	if (cfg->intpin != 0)
		printf(" int %c irq %d", cfg->intpin + 'a' -1, cfg->intline);
	printf(" on pci%d.%d.%d\n", cfg->bus, cfg->slot, cfg->func);
}


void
pci_drvattach(struct pci_devinfo *dinfo)
{
	struct pci_device *dvp;
	pcicfgregs *cfg;

	cfg = &dinfo->cfg;
	dvp = pci_finddrv(cfg);
	if (dvp != NULL) {
		int unit;

		unit = pci_wiredunit(cfg, dvp->pd_name);
		if (unit < 0) {
			unit = pci_freeunit(cfg, dvp->pd_name, *dvp->pd_count);
			*dvp->pd_count = unit +1;
		}
		pci_drvmessage(cfg, dvp->pd_name, unit);
		if (dvp->pd_attach)
			dvp->pd_attach(cfg, unit);

		dinfo->device = dvp;

		/*
		 * XXX KDM for some devices, dvp->pd_name winds up NULL.
		 * I haven't investigated enough to figure out why this
		 * would happen.
		 */
		if (dvp->pd_name != NULL)
			strncpy(dinfo->conf.pd_name, dvp->pd_name,
				sizeof(dinfo->conf.pd_name));
		else
			strncpy(dinfo->conf.pd_name, "????",
				sizeof(dinfo->conf.pd_name));

		dinfo->conf.pd_unit = unit;

	}
}

/* ------------------------------------------------------------------------- */

static void
pci_rescan(void)
{
	/* XXX do nothing, currently, soon to come ... */
}

int pci_register_lkm (struct pci_device *dvp, int if_revision)
{
	struct pci_lkm *lkm;

	if (if_revision != 0) {
		return (-1);
	}
	if (dvp == NULL || dvp->pd_probe == NULL || dvp->pd_attach == NULL) {
		return (-1);
	}
	lkm = malloc (sizeof (*lkm), M_DEVBUF, M_WAITOK);
	if (lkm != NULL) {
		return (-1);
	}

	lkm->dvp = dvp;
	lkm->next = pci_lkm_head;
	pci_lkm_head = lkm;
	pci_rescan();
	return (0);
}

void
pci_configure(void)
{
	pci_probe(NULL);
}

/* ------------------------------------------------------------------------- */

#endif /* PCI_COMPAT */
#endif /* NPCI > 0 */
