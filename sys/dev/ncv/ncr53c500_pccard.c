/*	$FreeBSD$	*/
/*	$NecBSD: ncr53c500_pisa.c,v 1.28 1998/11/26 01:59:11 honda Exp $	*/
/*	$NetBSD$	*/

/*
 * [Ported for FreeBSD]
 *  Copyright (c) 2000
 *      Noriaki Mitsunaga, Mitsuru Iwasaki and Takanori Watanabe.
 *      All rights reserved.
 * [NetBSD for NEC PC-98 series]
 *  Copyright (c) 1995, 1996, 1997, 1998
 *	NetBSD/pc98 porting staff. All rights reserved.
 *  Copyright (c) 1995, 1996, 1997, 1998
 *	Naofumi HONDA. All rights reserved.
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
static struct ncv_softc *ncv_get_softc(int);
extern struct ncv_softc *ncvdata[];
#define DEVPORT_ALLOCSOFTCFUNC	ncv_get_softc
#define DEVPORT_SOFTCARRAY	ncvdata
#endif
#include <sys/device_port.h>

#include <cam/scsi/scsi_low.h>
#include <cam/scsi/scsi_low_pisa.h>

#include <dev/ncv/ncr53c500reg.h>
#include <dev/ncv/ncr53c500hw.h>
#include <dev/ncv/ncr53c500var.h>
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD_version < 400001)
#include "ncv.h"
#endif

#define KME_KXLC004_01 0x100
#define OFFSET_KME_KXLC004_01 0x10

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

static int ncvprobe(DEVPORT_PDEVICE devi);
static int ncvattach(DEVPORT_PDEVICE devi);

static void	ncv_card_unload __P((DEVPORT_PDEVICE));
#if defined(__FreeBSD__) && __FreeBSD_version < 400001
static int	ncv_card_init __P((DEVPORT_PDEVICE));
static int	ncv_card_intr __P((DEVPORT_PDEVICE));
#endif

#if defined(__FreeBSD__) && __FreeBSD_version >= 400001
/*
 * Additional code for FreeBSD new-bus PCCard frontend
 */

static void
ncv_pccard_intr(void * arg)
{
	ncvintr(arg);
}

static void
ncv_release_resource(DEVPORT_PDEVICE dev)
{
	struct ncv_softc	*sc = device_get_softc(dev);

	if (sc->ncv_intrhand) {
		bus_teardown_intr(dev, sc->irq_res, sc->ncv_intrhand);
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
ncv_alloc_resource(DEVPORT_PDEVICE dev)
{
	struct ncv_softc	*sc = device_get_softc(dev);
	u_int32_t		flags = DEVPORT_PDEVFLAGS(dev);
	u_int			iobase = DEVPORT_PDEVIOBASE(dev);
	u_long			maddr, msize;
	int			error;
	bus_addr_t		offset = 0;

	if(flags & KME_KXLC004_01)
		offset = OFFSET_KME_KXLC004_01;

	sc->port_rid = 0;
	sc->port_res = bus_alloc_resource(dev, SYS_RES_IOPORT, &sc->port_rid,
					  iobase+offset, ~0, NCVIOSZ, RF_ACTIVE);
	if (sc->port_res == NULL) {
		ncv_release_resource(dev);
		return(ENOMEM);
	}

	sc->irq_rid = 0;
	sc->irq_res = bus_alloc_resource(dev, SYS_RES_IRQ, &sc->irq_rid,
					 0, ~0, 1, RF_ACTIVE);
	if (sc->irq_res == NULL) {
		ncv_release_resource(dev);
		return(ENOMEM);
	}

	error = bus_get_resource(dev, SYS_RES_MEMORY, 0, &maddr, &msize);
	if (error) {
		return(0);	/* XXX */
	}

	/* no need to allocate memory if not configured */
	if (maddr == 0 || msize == 0) {
		return(0);
	}

	sc->mem_rid = 0;
	sc->mem_res = bus_alloc_resource(dev, SYS_RES_MEMORY, &sc->mem_rid,
					 0, ~0, msize, RF_ACTIVE);
	if (sc->mem_res == NULL) {
		ncv_release_resource(dev);
		return(ENOMEM);
	}

	return(0);
}

static int
ncv_pccard_probe(DEVPORT_PDEVICE dev)
{
	struct ncv_softc	*sc = device_get_softc(dev);
	int			error;

	bzero(sc, sizeof(struct ncv_softc));

	error = ncv_alloc_resource(dev);
	if (error) {
		return(error);
	}

	if (ncvprobe(dev) == 0) {
		ncv_release_resource(dev);
		return(ENXIO);
	}

	ncv_release_resource(dev);

	return(0);
}

static int
ncv_pccard_attach(DEVPORT_PDEVICE dev)
{
	struct ncv_softc	*sc = device_get_softc(dev);
	int			error;

	error = ncv_alloc_resource(dev);
	if (error) {
		return(error);
	}

	error = bus_setup_intr(dev, sc->irq_res, INTR_TYPE_CAM,
			       ncv_pccard_intr, (void *)sc, &sc->ncv_intrhand);
	if (error) {
		ncv_release_resource(dev);
		return(error);
	}

	if (ncvattach(dev) == 0) {
		ncv_release_resource(dev);
		return(ENXIO);
	}

	return(0);
}

static	void
ncv_pccard_detach(DEVPORT_PDEVICE dev)
{
	ncv_card_unload(dev);
	ncv_release_resource(dev);
}

static device_method_t ncv_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ncv_pccard_probe),
	DEVMETHOD(device_attach,	ncv_pccard_attach),
	DEVMETHOD(device_detach,	ncv_pccard_detach),

	{ 0, 0 }
};

static driver_t ncv_pccard_driver = {
	"ncv",
	ncv_pccard_methods,
	sizeof(struct ncv_softc),
};

static devclass_t ncv_devclass;

DRIVER_MODULE(ncv, pccard, ncv_pccard_driver, ncv_devclass, 0, 0);

#else

PCCARD_MODULE(ncv, ncv_card_init, ncv_card_unload, ncv_card_intr, 0, cam_imask);

#endif

#if defined(__FreeBSD__) && __FreeBSD_version < 400001
static struct ncv_softc *
ncv_get_softc(int unit)
{
	struct ncv_softc *sc;

	if (unit >= NNCV) {
		return(NULL);
	}

	if (ncvdata[unit] == NULL) {
		sc = malloc(sizeof(struct ncv_softc), M_TEMP,M_NOWAIT);
		if (sc == NULL) {
			printf("ncv_get_softc: cannot malloc!\n");
			return(NULL);
		}
		ncvdata[unit] = sc;
	} else {
		sc = ncvdata[unit];
	}

	return(sc);
}

static int
ncv_card_init(DEVPORT_PDEVICE devi)
{
	int unit = DEVPORT_PDEVUNIT(devi);

	if (NNCV <= unit)
		return (ENODEV);

	if (ncvprobe(devi) == 0)
		return (ENXIO);

	if (ncvattach(devi) == 0)
		return (ENXIO);
	return (0);
}

static int
ncv_card_intr(DEVPORT_PDEVICE devi)
{

	ncvintr(DEVPORT_PDEVGET_SOFTC(devi));
	return 1;
}
#endif

static void
ncv_card_unload(DEVPORT_PDEVICE devi)
{
	struct ncv_softc *sc = DEVPORT_PDEVGET_SOFTC(devi);

	printf("%s: unload\n", sc->sc_sclow.sl_xname);
	scsi_low_deactivate((struct scsi_low_softc *)sc);
        scsi_low_dettach(&sc->sc_sclow);
}

static int
ncvprobe(DEVPORT_PDEVICE devi)
{
	int rv;
	struct ncv_softc *sc = device_get_softc(devi);
	u_int32_t flags = DEVPORT_PDEVFLAGS(devi);

#if defined(__FreeBSD__) && __FreeBSD_version >= 400001
	rv = ncvprobesubr(rman_get_bustag(sc->port_res),
			  rman_get_bushandle(sc->port_res),
			  flags, NCV_HOSTID);
#else
	bus_addr_t offset = 0;
	u_int iobase = DEVPORT_PDEVIOBASE(devi);

	if(flags & KME_KXLC004_01)
		offset = OFFSET_KME_KXLC004_01;

	rv = ncvprobesubr(I386_BUS_SPACE_IO,
			  iobase + offset,
			  flags, NCV_HOSTID);
#endif

	return rv;
}

static int
ncvattach(DEVPORT_PDEVICE devi)
{
	struct ncv_softc *sc;
	struct scsi_low_softc *slp;
	u_int32_t flags = DEVPORT_PDEVFLAGS(devi);
#if defined(__FreeBSD__) && __FreeBSD_version < 400001
	int unit = DEVPORT_PDEVUNIT(devi);
	bus_addr_t offset = 0;
	u_int iobase = DEVPORT_PDEVIOBASE(devi);
#endif
	char dvname[16]; /* SCSI_LOW_DVNAME_LEN */

	strcpy(dvname, "ncv");

#if defined(__FreeBSD__) && __FreeBSD_version < 400001
	if (unit >= NNCV)
	{
		printf("%s: unit number too high\n", dvname);
		return (0);
	}

	if (iobase == 0)
	{
		printf("%s: no ioaddr is given\n", dvname);
		return (0);
	}

	if(flags & KME_KXLC004_01)
		offset = OFFSET_KME_KXLC004_01;
#endif

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
	bzero(sc, sizeof(struct ncv_softc));
	strcpy(slp->sl_dev.dv_xname, dvname);
	slp->sl_dev.dv_unit = unit;
	sc->sc_iot = I386_BUS_SPACE_IO;
	sc->sc_ioh = iobase + offset;
#endif

	slp->sl_hostid = NCV_HOSTID;
	slp->sl_cfgflags = flags;

	ncvattachsubr(sc);

	sc->sc_ih = ncvintr;

	return(NCVIOSZ);
}
#endif /* NCARD */
