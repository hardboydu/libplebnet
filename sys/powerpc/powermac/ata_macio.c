/*-
 * Copyright 2002 by Peter Grehan. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Mac-io ATA controller
 */
#include "opt_ata.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/sema.h>
#include <sys/taskqueue.h>
#include <vm/uma.h>
#include <machine/stdarg.h>
#include <machine/resource.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <sys/ata.h>
#include <dev/ata/ata-all.h>

#include <dev/ofw/ofw_bus.h>

/*
 * Offset to control registers from base
 */
#define ATA_MACIO_ALTOFFSET	0x160

/*
 * Define the gap between registers
 */
#define ATA_MACIO_REGGAP	16

/*
 * Define the macio ata bus attachment.
 */
static  int  ata_macio_probe(device_t dev);

static device_method_t ata_macio_methods[] = {
        /* Device interface */
	DEVMETHOD(device_probe,		ata_macio_probe),
	DEVMETHOD(device_attach,        ata_attach),

	{ 0, 0 }
};

static driver_t ata_macio_driver = {
	"ata",
	ata_macio_methods,
	sizeof(struct ata_channel),
};

DRIVER_MODULE(ata, macio, ata_macio_driver, ata_devclass, 0, 0);

static int
ata_macio_locknoop(struct ata_channel *ch, int type)
{

	return (ch->unit);
}

static void
ata_macio_setmode(struct ata_device *atadev, int mode)
{
#if 0
	atadev->mode = ata_limit_mode(atadev, mode, ATA_PIO_MAX);
#endif
	atadev->mode = ATA_PIO;
}

static int
ata_macio_probe(device_t dev)
{
	const char *type = ofw_bus_get_type(dev);
	struct ata_channel *ch;
	struct resource *mem;
	int rid, i;

	if (strcmp(type, "ata") != 0 &&
	    strcmp(type, "ide") != 0)
		return (ENXIO);

	ch = device_get_softc(dev);
	bzero(ch, sizeof(struct ata_channel));

	rid = 0;
	mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid, RF_ACTIVE);
	if (mem == NULL) {
		device_printf(dev, "could not allocate memory\n");
		return (ENXIO);
	}

	/*
	 * Set up the resource vectors
	 */
	for (i = ATA_DATA; i <= ATA_STATUS; i++) {
		ch->r_io[i].res = mem;
		ch->r_io[i].offset = i * ATA_MACIO_REGGAP;
	}
	ch->r_io[ATA_ALTSTAT].res = mem;
	ch->r_io[ATA_ALTSTAT].offset = ATA_MACIO_ALTOFFSET;

	ch->unit = 0;
	ch->flags |= ATA_USE_16BIT;
	ch->locking = ata_macio_locknoop;
	ch->device[MASTER].setmode = ata_macio_setmode;
	ch->device[SLAVE].setmode = ata_macio_setmode;
	ata_generic_hw(ch);

	return (ata_probe(dev));
}

