/*-
 * Copyright (c) 2004 M. Warner Losh.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/systm.h>
#include <machine/bus.h>

#include <machine/bus.h>

#include <dev/fdc/fdcvar.h>
#include <dev/fdc/fdcreg.h>
#include <dev/pccard/pccardvar.h>
#include "pccarddevs.h"

static void fdctl_wr_pcmcia(fdc_p, u_int8_t);
static int fdc_pccard_probe(device_t);
static int fdc_pccard_attach(device_t);

static const struct pccard_product fdc_pccard_products[] = {
	PCMCIA_CARD(YEDATA, EXTERNAL_FDD, 0),
};
	
static void
fdctl_wr_pcmcia(fdc_p fdc, u_int8_t v)
{
	bus_space_write_1(fdc->portt, fdc->porth, FDCTL+fdc->port_off, v);
}

static int
fdc_pccard_alloc_resources(device_t dev, struct fdc_data *fdc)
{
	fdc->rid_ioport = 0;
	fdc->res_ioport = bus_alloc_resource(dev, SYS_RES_IOPORT,
	    &fdc->rid_ioport, 0ul, ~0ul, 1, RF_ACTIVE);
	if (fdc->res_ioport == NULL) {
		device_printf(dev, "cannot alloc I/O port range\n");
		return (ENXIO);
	}
	fdc->portt = rman_get_bustag(fdc->res_ioport);
	fdc->porth = rman_get_bushandle(fdc->res_ioport);

	fdc->rid_irq = 0;
	fdc->res_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &fdc->rid_irq,
	    RF_ACTIVE | RF_SHAREABLE);
	if (fdc->res_irq == NULL) {
		device_printf(dev, "cannot reserve interrupt line\n");
		return (ENXIO);
	}
	return (0);
}

static int
fdc_pccard_probe(device_t dev)
{
	const struct pccard_product *pp;

	if ((pp = pccard_product_lookup(dev, fdc_pccard_products,
	    sizeof(fdc_pccard_products[0]), NULL)) != NULL) {
		if (pp->pp_name != NULL)
			device_set_desc(dev, pp->pp_name);
		return (0);
	}
	return (ENXIO);
}

static int
fdc_pccard_attach(device_t dev)
{
	struct	fdc_data *fdc;

	return ENXIO;

	fdc = device_get_softc(dev);
	fdc->fdctl_wr = fdctl_wr_pcmcia;
	fdc->flags = FDC_NODMA;
	fdc->fdct = FDC_NE765;
	fdc_pccard_alloc_resources(dev, fdc);
	return (fdc_attach(dev));
}

static device_method_t fdc_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		fdc_pccard_probe),
	DEVMETHOD(device_attach,	fdc_pccard_attach),
	DEVMETHOD(device_detach,	fdc_detach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	fdc_print_child),
	DEVMETHOD(bus_read_ivar,	fdc_read_ivar),
	DEVMETHOD(bus_write_ivar,       fdc_write_ivar),
	/* Our children never use any other bus interface methods. */

	{ 0, 0 }
};

static driver_t fdc_pccard_driver = {
	"fdc",
	fdc_pccard_methods,
	sizeof(struct fdc_data)
};

DRIVER_MODULE(fdc, pccard, fdc_pccard_driver, fdc_devclass, 0, 0);
