/*
 * Copyright (c) 1998 Martin Husemann <martin@rumolt.teuto.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
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
 *---------------------------------------------------------------------------
 *
 *	i4b_itk_ix1.c - ITK ix1 micro passive card driver for isdn4bsd
 *	--------------------------------------------------------------
 *
 *	$Id: i4b_itk_ix1.c,v 1.1 1998/12/27 21:46:46 phk Exp $
 *
 *      last edit-date: [Wed Dec 16 14:46:36 1998]
 *
 *---------------------------------------------------------------------------
 *
 * The ITK ix1 micro ISDN card is an ISA card with one region
 * of four io ports mapped and a fixed irq all jumpered on the card.
 * Access to the board is straight forward and simmilar to
 * the ELSA and DYNALINK cards. If a PCI version of this card
 * exists all we need is probably a pci-bus attachment, all
 * this low level routines should work imediately.
 *
 * To reset the card:
 *   - write 0x01 to ITK_CONFIG
 *   - wait >= 10 ms
 *   - write 0x00 to ITK_CONFIG
 *
 * To read or write data:
 *  - write address to ITK_ALE port
 *  - read data from or write data to ITK_ISAC_DATA port or ITK_HSCX_DATA port
 * The two HSCX channel registers are offset by HSCXA (0x00) and HSCXB (0x40).
 *
 * XXX - A reasonable probe routine has to be written.
 *
 *---------------------------------------------------------------------------*/

#if defined(__FreeBSD__)
#include "isic.h"
#include "opt_i4b.h"
#else
#define	NISIC 1
#endif
#if NISIC > 0 && defined(ITKIX1)

#include <sys/param.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/ioccom.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#ifdef __FreeBSD__
#include <machine/clock.h>
#include <i386/isa/isa_device.h>
#else
#include <machine/bus.h>
#include <sys/device.h>
#endif

#include <sys/socket.h>
#include <net/if.h>

#ifdef __FreeBSD__
#include <machine/i4b_debug.h>
#include <machine/i4b_ioctl.h>
#else
#include <i4b/i4b_debug.h>
#include <i4b/i4b_ioctl.h>
#endif

#include <i4b/layer1/i4b_l1.h>
#include <i4b/layer1/i4b_isac.h>
#include <i4b/layer1/i4b_hscx.h>

#include <i4b/include/i4b_global.h>

#define	ITK_ISAC_DATA	0
#define	ITK_HSCX_DATA	1
#define	ITK_ALE		2
#define	ITK_CONFIG	3
#define	ITK_IO_SIZE	4

#define	HSCXA	0
#define	HSCXB	0x40

#ifndef __FreeBSD__
static void itkix1_read_fifo(struct isic_softc *sc, int what, void *buf, size_t size);
static void itkix1_write_fifo(struct isic_softc *sc, int what, const void *buf, size_t size);
static void itkix1_write_reg(struct isic_softc *sc, int what, bus_size_t offs, u_int8_t data);
static u_int8_t itkix1_read_reg(struct isic_softc *sc, int what, bus_size_t offs);
#else
static u_char itkix1_read_reg(u_char *base, u_int offset);
static void itkix1_write_reg(u_char *base, u_int offset, u_int v);
static void itkix1_read_fifo(void *base, const void *buf, size_t len);
static void itkix1_write_fifo(void *base, const void *buf, size_t len);
#endif

/*
 * Probe for card
 */
#ifdef __FreeBSD__
int
isic_probe_itkix1(struct isa_device *dev)
{
	u_int8_t hd, cd;
	int ret;

	hd = inb(dev->id_iobase + ITK_HSCX_DATA);
	cd = inb(dev->id_iobase + ITK_CONFIG);

	ret = (hd == 0 && cd == 0xfc);

#define ITK_PROBE_DEBUG
#ifdef ITK_PROBE_DEBUG
	printf("\nITK ix1 micro probe: hscx = 0x%02x, config = 0x%02x, would have %s\n",
		hd, cd, ret ? "succeeded" : "failed");
	return 1;
#else
	return ret;
#endif
}
#else
int
isic_probe_itkix1(struct isic_attach_args *ia)
{
	bus_space_tag_t t = ia->ia_maps[0].t;
	bus_space_handle_t h = ia->ia_maps[0].h;
	u_int8_t hd, cd;
	int ret;

	hd = bus_space_read_1(t, h, ITK_HSCX_DATA);
	cd = bus_space_read_1(t, h, ITK_CONFIG);

	ret = (hd == 0 && cd == 0xfc);

#define ITK_PROBE_DEBUG
#ifdef ITK_PROBE_DEBUG
	printf("\nITK ix1 micro probe: hscx = 0x%02x, config = 0x%02x, would have %s\n",
		hd, cd, ret ? "succeeded" : "failed");
	return 1;
#else
	return ret;
#endif
}
#endif

/*
 *  Attach card
 */
#ifdef __FreeBSD__
int
isic_attach_itkix1(struct isa_device *dev)
{
	struct isic_softc *sc = &isic_sc[dev->id_unit];

	sc->sc_irq = dev->id_irq;

	dev->id_msize = 0;
	
	/* check if we got an iobase */
	sc->sc_port = dev->id_iobase;

	/* setup access routines */
	sc->clearirq = NULL;
	sc->readreg = itkix1_read_reg;
	sc->writereg = itkix1_write_reg;
	sc->readfifo = itkix1_read_fifo;
	sc->writefifo = itkix1_write_fifo;

	/* setup card type */	
	sc->sc_cardtyp = CARD_TYPEP_ITKIX1;

	/* setup IOM bus type */
	sc->sc_bustyp = BUS_TYPE_IOM2;

	sc->sc_ipac = 0;
	sc->sc_bfifolen = HSCX_FIFO_LEN;

	/* setup ISAC and HSCX base addr */
	ISAC_BASE = (caddr_t) sc->sc_port;
	HSCX_A_BASE = (caddr_t) sc->sc_port + 1;
	HSCX_B_BASE = (caddr_t) sc->sc_port + 2;

	/* Read HSCX A/B VSTR.  Expected value is 0x05 (V2.1). */
	if( ((HSCX_READ(0, H_VSTR) & 0xf) != 0x5) || ((HSCX_READ(1, H_VSTR) & 0xf) != 0x5) )
	{
		printf("isic%d: HSCX VSTR test failed for ITK ix1 micro\n",
			dev->id_unit);
		printf("isic%d: HSC0: VSTR: %#x\n",
			dev->id_unit, HSCX_READ(0, H_VSTR));
		printf("isic%d: HSC1: VSTR: %#x\n",
			dev->id_unit, HSCX_READ(1, H_VSTR));
		return (0);
	}                   

	outb((dev->id_iobase)+ITK_CONFIG, 1);
	DELAY(SEC_DELAY / 10);
	outb((dev->id_iobase)+ITK_CONFIG, 0);
	DELAY(SEC_DELAY / 10);
	return(1);
}

#else

int isic_attach_itkix1(struct isic_softc *sc)
{
	/* setup access routines */
	sc->clearirq = NULL;
	sc->readreg = itkix1_read_reg;
	sc->writereg = itkix1_write_reg;
	sc->readfifo = itkix1_read_fifo;
	sc->writefifo = itkix1_write_fifo;

	/* setup card type */	
	sc->sc_cardtyp = CARD_TYPEP_ITKIX1;

	/* setup IOM bus type */
	sc->sc_bustyp = BUS_TYPE_IOM2;

	sc->sc_ipac = 0;
	sc->sc_bfifolen = HSCX_FIFO_LEN;

	/* Read HSCX A/B VSTR.  Expected value is 0x05 (V2.1). */
	if( ((HSCX_READ(0, H_VSTR) & 0xf) != 0x5) || ((HSCX_READ(1, H_VSTR) & 0xf) != 0x5) )
	{
		printf("%s: HSCX VSTR test failed for ITK ix1 micro\n",
			sc->sc_dev.dv_xname);
		printf("%s: HSC0: VSTR: %#x\n",
			sc->sc_dev.dv_xname, HSCX_READ(0, H_VSTR));
		printf("%s: HSC1: VSTR: %#x\n",
			sc->sc_dev.dv_xname, HSCX_READ(1, H_VSTR));
		return 0;
	}                   

	bus_space_write_1(sc->sc_maps[0].t, sc->sc_maps[0].h, ITK_CONFIG, 1);
	DELAY(SEC_DELAY / 10);
	bus_space_write_1(sc->sc_maps[0].t, sc->sc_maps[0].h, ITK_CONFIG, 0);
	DELAY(SEC_DELAY / 10);
	return 1;
}

#endif

#ifdef __FreeBSD__
static void             
itkix1_read_fifo(void *buf, const void *base, size_t len)
{
	int port = (u_long)base & ~0x0003;
	switch ((u_long)base & 3) {
	case 0:	/* ISAC */
		outb(port+ITK_ALE, 0);
		insb(port+ITK_ISAC_DATA, (u_char *)buf, (u_int)len);
		break;
	case 1: /* HSCXA */
		outb(port+ITK_ALE, HSCXA);
		insb(port+ITK_HSCX_DATA, (u_char *)buf, (u_int)len);
		break;
	case 2: /* HSCXB */
		outb(port+ITK_ALE, HSCXB);
		insb(port+ITK_HSCX_DATA, (u_char *)buf, (u_int)len);
		break;
	}
}
#else
static void
itkix1_read_fifo(struct isic_softc *sc, int what, void *buf, size_t size)
{
	bus_space_tag_t t = sc->sc_maps[0].t;
	bus_space_handle_t h = sc->sc_maps[0].h;
	switch (what) {
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t, h, ITK_ALE, 0);
			bus_space_read_multi_1(t, h, ITK_ISAC_DATA, buf, size);
			break;
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t, h, ITK_ALE, HSCXA);
			bus_space_read_multi_1(t, h, ITK_HSCX_DATA, buf, size);
			break;
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t, h, ITK_ALE, HSCXB);
			bus_space_read_multi_1(t, h, ITK_HSCX_DATA, buf, size);
			break;
	}
}
#endif

#ifdef __FreeBSD__
static void
itkix1_write_fifo(void *base, const void *buf, size_t len)
{
	int port = (u_long)base & ~0x0003;
	switch ((u_long)base & 3) {
	case 0:	/* ISAC */
		outb(port+ITK_ALE, 0);
		outsb(port+ITK_ISAC_DATA, (u_char *)buf, (u_int)len);
		break;
	case 1: /* HSCXA */
		outb(port+ITK_ALE, HSCXA);
		outsb(port+ITK_HSCX_DATA, (u_char *)buf, (u_int)len);
		break;
	case 2: /* HSCXB */
		outb(port+ITK_ALE, HSCXB);
		outsb(port+ITK_HSCX_DATA, (u_char *)buf, (u_int)len);
		break;
	}
}
#else
static void itkix1_write_fifo(struct isic_softc *sc, int what, const void *buf, size_t size)
{
	bus_space_tag_t t = sc->sc_maps[0].t;
	bus_space_handle_t h = sc->sc_maps[0].h;
	switch (what) {
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t, h, ITK_ALE, 0);
			bus_space_write_multi_1(t, h, ITK_ISAC_DATA, (u_int8_t*)buf, size);
			break;
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t, h, ITK_ALE, HSCXA);
			bus_space_write_multi_1(t, h, ITK_HSCX_DATA, (u_int8_t*)buf, size);
			break;
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t, h, ITK_ALE, HSCXB);
			bus_space_write_multi_1(t, h, ITK_HSCX_DATA, (u_int8_t*)buf, size);
			break;
	}
}
#endif

#ifdef __FreeBSD__
static void
itkix1_write_reg(u_char *base, u_int offset, u_int v)
{
	int port = (u_long)base & ~0x0003;
	switch ((u_long)base & 3) {
	case 0:	/* ISAC */
		outb(port+ITK_ALE, offset);
		outb(port+ITK_ISAC_DATA, (u_char)v);
		break;
	case 1: /* HSCXA */
		outb(port+ITK_ALE, HSCXA+offset);
		outb(port+ITK_HSCX_DATA, (u_char)v);
		break;
	case 2: /* HSCXB */
		outb(port+ITK_ALE, HSCXB+offset);
		outb(port+ITK_HSCX_DATA, (u_char)v);
		break;
	}
}
#else
static void itkix1_write_reg(struct isic_softc *sc, int what, bus_size_t offs, u_int8_t data)
{
	bus_space_tag_t t = sc->sc_maps[0].t;
	bus_space_handle_t h = sc->sc_maps[0].h;
	switch (what) {
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t, h, ITK_ALE, offs);
			bus_space_write_1(t, h, ITK_ISAC_DATA, data);
			break;
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t, h, ITK_ALE, HSCXA+offs);
			bus_space_write_1(t, h, ITK_HSCX_DATA, data);
			break;
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t, h, ITK_ALE, HSCXB+offs);
			bus_space_write_1(t, h, ITK_HSCX_DATA, data);
			break;
	}
}
#endif

#ifdef __FreeBSD__
static u_char
itkix1_read_reg(u_char *base, u_int offset)
{
	int port = (u_long)base & ~0x0003;
	switch ((u_long)base & 3) {
	case 0:	/* ISAC */
		outb(port+ITK_ALE, offset);
		return (inb(port+ITK_ISAC_DATA));
	case 1: /* HSCXA */
		outb(port+ITK_ALE, HSCXA+offset);
		return (inb(port+ITK_HSCX_DATA));
	case 2: /* HSCXB */
		outb(port+ITK_ALE, HSCXB+offset);
		return (inb(port+ITK_HSCX_DATA));
	}
	panic("itkix1_read_reg: Fallthrough\n");
}
#else
static u_int8_t itkix1_read_reg(struct isic_softc *sc, int what, bus_size_t offs)
{
	bus_space_tag_t t = sc->sc_maps[0].t;
	bus_space_handle_t h = sc->sc_maps[0].h;
	switch (what) {
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t, h, ITK_ALE, offs);
			return bus_space_read_1(t, h, ITK_ISAC_DATA);
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t, h, ITK_ALE, HSCXA+offs);
			return bus_space_read_1(t, h, ITK_HSCX_DATA);
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t, h, ITK_ALE, HSCXB+offs);
			return bus_space_read_1(t, h, ITK_HSCX_DATA);
	}
	return 0;
}
#endif

#endif /* ITKIX1 */
