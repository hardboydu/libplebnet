/*	$FreeBSD$	*/
/*	$NecBSD: tmc18c30_pisa.c,v 1.22 1998/11/26 01:59:21 honda Exp $	*/
/*	$NetBSD$	*/

/*
 * [Ported for FreeBSD]
 *  Copyright (c) 2000
 *      Noriaki Mitsunaga, Mitsuru Iwasaki and Takanori Watanabe.
 *      All rights reserved.
 * [NetBSD for NEC PC-98 series]
 *  Copyright (c) 1996, 1997, 1998
 *	NetBSD/pc98 porting staff. All rights reserved.
 *  Copyright (c) 1996, 1997, 1998
 *	Naofumi HONDA. All rights reserved.
 *  Copyright (c) 1996, 1997, 1998
 *	Kouichi Matsuda. All rights reserved.
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/disklabel.h>
#if defined(__FreeBSD__) && __FreeBSD_version >= 500001
#include <sys/bio.h>
#endif
#include <sys/buf.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/errno.h>

#include <vm/vm.h>

#include <machine/bus.h>

#include <machine/bus_pio.h>
#include <i386/isa/isa_device.h>

#include <machine/dvcfg.h>

#if defined(__FreeBSD__) && __FreeBSD_version < 400001
static struct stg_softc *stg_get_softc(int);
extern struct stg_softc *stgdata[];
#define DEVPORT_ALLOCSOFTCFUNC stg_get_softc
#define DEVPORT_SOFTCARRAY     stgdata
#endif
#include <sys/device_port.h>

#include <cam/scsi/scsi_low.h>
#include <cam/scsi/scsi_low_pisa.h>

#include <dev/stg/tmc18c30reg.h>
#include <dev/stg/tmc18c30var.h>
#if defined(__FreeBSD__) && __FreeBSD_version < 400001
#include "stg.h"
#endif

#define	STG_HOSTID	7

/* pccard support */
#include	"card.h"
#if NCARD > 0
#include	<sys/kernel.h>
#include	<sys/module.h>
#if !defined(__FreeBSD__) || __FreeBSD_version < 500014
#include	<sys/select.h>
#endif
#include	<pccard/cardinfo.h>
#include	<pccard/slot.h>

static	int	stgprobe(DEVPORT_PDEVICE devi);
static	int	stgattach(DEVPORT_PDEVICE devi);

static	int	stg_card_intr	__P((DEVPORT_PDEVICE));
static	void	stg_card_unload	__P((DEVPORT_PDEVICE));
#if defined(__FreeBSD__) && __FreeBSD_version < 400001
static	int	stg_card_init	__P((DEVPORT_PDEVICE));
#endif

#if defined(__FreeBSD__) && __FreeBSD_version >= 400001
/*
 * Additional code for FreeBSD new-bus PCCard frontend
 */

static void
stg_pccard_intr(void * arg)
{
	stgintr(arg);
}

static void
stg_release_resource(DEVPORT_PDEVICE dev)
{
	struct stg_softc	*sc = device_get_softc(dev);

	if (sc->stg_intrhand) {
		bus_teardown_intr(dev, sc->irq_res, sc->stg_intrhand);
	}

	if (sc->port_res) {
		bus_release_resource(dev, SYS_RES_IOPORT,
				     sc->port_rid, sc->port_res);
	}

	if (sc->irq_res) {
		bus_release_resource(dev, SYS_RES_IRQ,
				     sc->irq_rid, sc->irq_res);
	}

	if (sc->mem_res) {
		bus_release_resource(dev, SYS_RES_MEMORY,
				     sc->mem_rid, sc->mem_res);
	}
}

static int
stg_alloc_resource(DEVPORT_PDEVICE dev)
{
	struct stg_softc	*sc = device_get_softc(dev);
	u_long			maddr, msize;
	int			error;

	sc->port_rid = 0;
	sc->port_res = bus_alloc_resource(dev, SYS_RES_IOPORT, &sc->port_rid,
					  0, ~0, STGIOSZ, RF_ACTIVE);
	if (sc->port_res == NULL) {
		stg_release_resource(dev);
		return(ENOMEM);
	}

	sc->irq_rid = 0;
	sc->irq_res = bus_alloc_resource(dev, SYS_RES_IRQ, &sc->irq_rid,
					 0, ~0, 1, RF_ACTIVE);
	if (sc->irq_res == NULL) {
		stg_release_resource(dev);
		return(ENOMEM);
	}

	error = bus_get_resource(dev, SYS_RES_MEMORY, 0, &maddr, &msize);
	if (error) {
		return(0);      /* XXX */
	}

	/* no need to allocate memory if not configured */
	if (maddr == 0 || msize == 0) {
		return(0);
	}

	sc->mem_rid = 0;
	sc->mem_res = bus_alloc_resource(dev, SYS_RES_MEMORY, &sc->mem_rid,
					 0, ~0, msize, RF_ACTIVE);
	if (sc->mem_res == NULL) {
		stg_release_resource(dev);
		return(ENOMEM);
	}

	return(0);
}

static int
stg_pccard_probe(DEVPORT_PDEVICE dev)
{
	struct stg_softc	*sc = device_get_softc(dev);
	int			error;

	bzero(sc, sizeof(struct stg_softc));

	error = stg_alloc_resource(dev);
	if (error) {
		return(error);
	}

	if (stgprobe(dev) == 0) {
		stg_release_resource(dev);
		return(ENXIO);
	}

	stg_release_resource(dev);

	return(0);
}

static int
stg_pccard_attach(DEVPORT_PDEVICE dev)
{
	struct stg_softc	*sc = device_get_softc(dev);
	int			error;

	error = stg_alloc_resource(dev);
	if (error) {
		return(error);
	}

	error = bus_setup_intr(dev, sc->irq_res, INTR_TYPE_CAM,
			       stg_pccard_intr, (void *)sc, &sc->stg_intrhand);
	if (error) {
		stg_release_resource(dev);
		return(error);
	}

	if (stgattach(dev) == 0) {
		stg_release_resource(dev);
		return(ENXIO);
	}

	return(0);
}

static	void
stg_pccard_detach(DEVPORT_PDEVICE dev)
{
	stg_card_unload(dev);
	stg_release_resource(dev);
}

static device_method_t stg_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		stg_pccard_probe),
	DEVMETHOD(device_attach,	stg_pccard_attach),
	DEVMETHOD(device_detach,	stg_pccard_detach),

	{ 0, 0 }
};

static driver_t stg_pccard_driver = {
	"stg",
	stg_pccard_methods,
	sizeof(struct stg_softc),
};

static devclass_t stg_devclass;

DRIVER_MODULE(stg, pccard, stg_pccard_driver, stg_devclass, 0, 0);

#else

PCCARD_MODULE(stg, stg_card_init,stg_card_unload, stg_card_intr, 0, cam_imask);

#endif

#if defined(__FreeBSD__) && __FreeBSD_version < 400001
static struct stg_softc *
stg_get_softc(int unit)
{
	struct stg_softc *sc;

	if (unit >= NSTG) {
		return(NULL);
	}

	if (stgdata[unit] == NULL) {
		sc = malloc(sizeof(struct stg_softc), M_TEMP,M_NOWAIT);
		if (sc == NULL) {
			printf("stg_get_softc: cannot malloc!\n");
			return(NULL);
		}
		stgdata[unit] = sc;
	} else {
		sc = stgdata[unit];
	}

	return(sc);
}

static	int
stg_card_init(DEVPORT_PDEVICE devi)
{
	int unit = DEVPORT_PDEVUNIT(devi);

	if (NSTG <= unit)
		return (ENODEV);

	printf("probe stg\n");
	if (stgprobe(devi) == 0)
		return (ENXIO);

	printf("attach stg\n");
	if (stgattach(devi) == 0)
		return (ENXIO);

	return (0);
}
#endif

static	void
stg_card_unload(DEVPORT_PDEVICE devi)
{
	struct stg_softc *sc = DEVPORT_PDEVGET_SOFTC(devi);

	printf("%s: unload\n",sc->sc_sclow.sl_xname);
	scsi_low_deactivate((struct scsi_low_softc *)sc);
        scsi_low_dettach(&sc->sc_sclow);
}

static	int
stg_card_intr(DEVPORT_PDEVICE devi)
{
	stgintr(DEVPORT_PDEVGET_SOFTC(devi));
	return 1;
}

static	int
stgprobe(DEVPORT_PDEVICE devi)
{
	int rv;
#if defined(__FreeBSD__) && __FreeBSD_version >= 400001
	struct stg_softc *sc = device_get_softc(devi);

	rv = stgprobesubr(rman_get_bustag(sc->port_res),
			  rman_get_bushandle(sc->port_res),
			  DEVPORT_PDEVFLAGS(devi));
#else
	rv = stgprobesubr(I386_BUS_SPACE_IO,
			  DEVPORT_PDEVIOBASE(devi), DEVPORT_PDEVFLAGS(devi));
#endif

	return rv;
}

static	int
stgattach(DEVPORT_PDEVICE devi)
{
	int unit = DEVPORT_PDEVUNIT(devi);
	struct stg_softc *sc;
	struct scsi_low_softc *slp;
	u_int32_t flags = DEVPORT_PDEVFLAGS(devi);
	u_int iobase = DEVPORT_PDEVIOBASE(devi);

	char	dvname[16];

	strcpy(dvname,"stg");

#if defined(__FreeBSD__) && __FreeBSD_version < 400001
	if (unit >= NSTG)
	{
		printf("%s: unit number too high\n",dvname);
		return (0);
	}
#endif

	if (iobase == 0)
	{
		printf("%s: no ioaddr is given\n", dvname);
		return (0);
	}

	sc = DEVPORT_PDEVALLOC_SOFTC(devi);
	if (sc == NULL) {
		return(0);
	}

	slp = &sc->sc_sclow;
#if defined(__FreeBSD__) && __FreeBSD_version >= 400001
	slp->sl_dev = devi;
	sc->sc_iot = rman_get_bustag(sc->port_res);
	sc->sc_ioh = rman_get_bushandle(sc->port_res);
#else
	bzero(sc, sizeof(struct stg_softc));
	strcpy(slp->sl_dev.dv_xname, dvname);
	slp->sl_dev.dv_unit = unit;
	sc->sc_iot = I386_BUS_SPACE_IO;
	sc->sc_ioh = iobase;
#endif

	slp->sl_hostid = STG_HOSTID;
	slp->sl_cfgflags = flags;

	stgattachsubr(sc);

	sc->sc_ih = stgintr;

	return(STGIOSZ);
}
#endif /* NCARD>0 */
