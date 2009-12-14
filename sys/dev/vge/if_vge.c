/*-
 * Copyright (c) 2004
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
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
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * VIA Networking Technologies VT612x PCI gigabit ethernet NIC driver.
 *
 * Written by Bill Paul <wpaul@windriver.com>
 * Senior Networking Software Engineer
 * Wind River Systems
 */

/*
 * The VIA Networking VT6122 is a 32bit, 33/66Mhz PCI device that
 * combines a tri-speed ethernet MAC and PHY, with the following
 * features:
 *
 *	o Jumbo frame support up to 16K
 *	o Transmit and receive flow control
 *	o IPv4 checksum offload
 *	o VLAN tag insertion and stripping
 *	o TCP large send
 *	o 64-bit multicast hash table filter
 *	o 64 entry CAM filter
 *	o 16K RX FIFO and 48K TX FIFO memory
 *	o Interrupt moderation
 *
 * The VT6122 supports up to four transmit DMA queues. The descriptors
 * in the transmit ring can address up to 7 data fragments; frames which
 * span more than 7 data buffers must be coalesced, but in general the
 * BSD TCP/IP stack rarely generates frames more than 2 or 3 fragments
 * long. The receive descriptors address only a single buffer.
 *
 * There are two peculiar design issues with the VT6122. One is that
 * receive data buffers must be aligned on a 32-bit boundary. This is
 * not a problem where the VT6122 is used as a LOM device in x86-based
 * systems, but on architectures that generate unaligned access traps, we
 * have to do some copying.
 *
 * The other issue has to do with the way 64-bit addresses are handled.
 * The DMA descriptors only allow you to specify 48 bits of addressing
 * information. The remaining 16 bits are specified using one of the
 * I/O registers. If you only have a 32-bit system, then this isn't
 * an issue, but if you have a 64-bit system and more than 4GB of
 * memory, you must have to make sure your network data buffers reside
 * in the same 48-bit 'segment.'
 *
 * Special thanks to Ryan Fu at VIA Networking for providing documentation
 * and sample NICs for testing.
 */

#ifdef HAVE_KERNEL_OPTION_HEADERS
#include "opt_device_polling.h"
#endif

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <net/bpf.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

MODULE_DEPEND(vge, pci, 1, 1, 1);
MODULE_DEPEND(vge, ether, 1, 1, 1);
MODULE_DEPEND(vge, miibus, 1, 1, 1);

/* "device miibus" required.  See GENERIC if you get errors here. */
#include "miibus_if.h"

#include <dev/vge/if_vgereg.h>
#include <dev/vge/if_vgevar.h>

#define VGE_CSUM_FEATURES    (CSUM_IP | CSUM_TCP | CSUM_UDP)

/* Tunables */
static int msi_disable = 0;
TUNABLE_INT("hw.vge.msi_disable", &msi_disable);

/*
 * Various supported device vendors/types and their names.
 */
static struct vge_type vge_devs[] = {
	{ VIA_VENDORID, VIA_DEVICEID_61XX,
		"VIA Networking Gigabit Ethernet" },
	{ 0, 0, NULL }
};

static int vge_probe		(device_t);
static int vge_attach		(device_t);
static int vge_detach		(device_t);

static int vge_encap		(struct vge_softc *, struct mbuf **);

static void vge_dmamap_cb	(void *, bus_dma_segment_t *, int, int);
static int vge_dma_alloc	(struct vge_softc *);
static void vge_dma_free	(struct vge_softc *);
static void vge_discard_rxbuf	(struct vge_softc *, int);
static int vge_newbuf		(struct vge_softc *, int);
static int vge_rx_list_init	(struct vge_softc *);
static int vge_tx_list_init	(struct vge_softc *);
static void vge_freebufs	(struct vge_softc *);
#ifndef __NO_STRICT_ALIGNMENT
static __inline void vge_fixup_rx
				(struct mbuf *);
#endif
static int vge_rxeof		(struct vge_softc *, int);
static void vge_txeof		(struct vge_softc *);
static void vge_intr		(void *);
static void vge_tick		(void *);
static void vge_start		(struct ifnet *);
static void vge_start_locked	(struct ifnet *);
static int vge_ioctl		(struct ifnet *, u_long, caddr_t);
static void vge_init		(void *);
static void vge_init_locked	(struct vge_softc *);
static void vge_stop		(struct vge_softc *);
static void vge_watchdog	(void *);
static int vge_suspend		(device_t);
static int vge_resume		(device_t);
static int vge_shutdown		(device_t);
static int vge_ifmedia_upd	(struct ifnet *);
static void vge_ifmedia_sts	(struct ifnet *, struct ifmediareq *);

#ifdef VGE_EEPROM
static void vge_eeprom_getword	(struct vge_softc *, int, uint16_t *);
#endif
static void vge_read_eeprom	(struct vge_softc *, caddr_t, int, int, int);

static void vge_miipoll_start	(struct vge_softc *);
static void vge_miipoll_stop	(struct vge_softc *);
static int vge_miibus_readreg	(device_t, int, int);
static int vge_miibus_writereg	(device_t, int, int, int);
static void vge_miibus_statchg	(device_t);

static void vge_cam_clear	(struct vge_softc *);
static int vge_cam_set		(struct vge_softc *, uint8_t *);
static void vge_setmulti	(struct vge_softc *);
static void vge_reset		(struct vge_softc *);

static device_method_t vge_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		vge_probe),
	DEVMETHOD(device_attach,	vge_attach),
	DEVMETHOD(device_detach,	vge_detach),
	DEVMETHOD(device_suspend,	vge_suspend),
	DEVMETHOD(device_resume,	vge_resume),
	DEVMETHOD(device_shutdown,	vge_shutdown),

	/* bus interface */
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_driver_added,	bus_generic_driver_added),

	/* MII interface */
	DEVMETHOD(miibus_readreg,	vge_miibus_readreg),
	DEVMETHOD(miibus_writereg,	vge_miibus_writereg),
	DEVMETHOD(miibus_statchg,	vge_miibus_statchg),

	{ 0, 0 }
};

static driver_t vge_driver = {
	"vge",
	vge_methods,
	sizeof(struct vge_softc)
};

static devclass_t vge_devclass;

DRIVER_MODULE(vge, pci, vge_driver, vge_devclass, 0, 0);
DRIVER_MODULE(miibus, vge, miibus_driver, miibus_devclass, 0, 0);

#ifdef VGE_EEPROM
/*
 * Read a word of data stored in the EEPROM at address 'addr.'
 */
static void
vge_eeprom_getword(struct vge_softc *sc, int addr, uint16_t *dest)
{
	int i;
	uint16_t word = 0;

	/*
	 * Enter EEPROM embedded programming mode. In order to
	 * access the EEPROM at all, we first have to set the
	 * EELOAD bit in the CHIPCFG2 register.
	 */
	CSR_SETBIT_1(sc, VGE_CHIPCFG2, VGE_CHIPCFG2_EELOAD);
	CSR_SETBIT_1(sc, VGE_EECSR, VGE_EECSR_EMBP/*|VGE_EECSR_ECS*/);

	/* Select the address of the word we want to read */
	CSR_WRITE_1(sc, VGE_EEADDR, addr);

	/* Issue read command */
	CSR_SETBIT_1(sc, VGE_EECMD, VGE_EECMD_ERD);

	/* Wait for the done bit to be set. */
	for (i = 0; i < VGE_TIMEOUT; i++) {
		if (CSR_READ_1(sc, VGE_EECMD) & VGE_EECMD_EDONE)
			break;
	}

	if (i == VGE_TIMEOUT) {
		device_printf(sc->vge_dev, "EEPROM read timed out\n");
		*dest = 0;
		return;
	}

	/* Read the result */
	word = CSR_READ_2(sc, VGE_EERDDAT);

	/* Turn off EEPROM access mode. */
	CSR_CLRBIT_1(sc, VGE_EECSR, VGE_EECSR_EMBP/*|VGE_EECSR_ECS*/);
	CSR_CLRBIT_1(sc, VGE_CHIPCFG2, VGE_CHIPCFG2_EELOAD);

	*dest = word;
}
#endif

/*
 * Read a sequence of words from the EEPROM.
 */
static void
vge_read_eeprom(struct vge_softc *sc, caddr_t dest, int off, int cnt, int swap)
{
	int i;
#ifdef VGE_EEPROM
	uint16_t word = 0, *ptr;

	for (i = 0; i < cnt; i++) {
		vge_eeprom_getword(sc, off + i, &word);
		ptr = (uint16_t *)(dest + (i * 2));
		if (swap)
			*ptr = ntohs(word);
		else
			*ptr = word;
	}
#else
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		dest[i] = CSR_READ_1(sc, VGE_PAR0 + i);
#endif
}

static void
vge_miipoll_stop(struct vge_softc *sc)
{
	int i;

	CSR_WRITE_1(sc, VGE_MIICMD, 0);

	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(1);
		if (CSR_READ_1(sc, VGE_MIISTS) & VGE_MIISTS_IIDL)
			break;
	}

	if (i == VGE_TIMEOUT)
		device_printf(sc->vge_dev, "failed to idle MII autopoll\n");
}

static void
vge_miipoll_start(struct vge_softc *sc)
{
	int i;

	/* First, make sure we're idle. */

	CSR_WRITE_1(sc, VGE_MIICMD, 0);
	CSR_WRITE_1(sc, VGE_MIIADDR, VGE_MIIADDR_SWMPL);

	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(1);
		if (CSR_READ_1(sc, VGE_MIISTS) & VGE_MIISTS_IIDL)
			break;
	}

	if (i == VGE_TIMEOUT) {
		device_printf(sc->vge_dev, "failed to idle MII autopoll\n");
		return;
	}

	/* Now enable auto poll mode. */

	CSR_WRITE_1(sc, VGE_MIICMD, VGE_MIICMD_MAUTO);

	/* And make sure it started. */

	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(1);
		if ((CSR_READ_1(sc, VGE_MIISTS) & VGE_MIISTS_IIDL) == 0)
			break;
	}

	if (i == VGE_TIMEOUT)
		device_printf(sc->vge_dev, "failed to start MII autopoll\n");
}

static int
vge_miibus_readreg(device_t dev, int phy, int reg)
{
	struct vge_softc *sc;
	int i;
	uint16_t rval = 0;

	sc = device_get_softc(dev);

	if (phy != sc->vge_phyaddr)
		return (0);

	vge_miipoll_stop(sc);

	/* Specify the register we want to read. */
	CSR_WRITE_1(sc, VGE_MIIADDR, reg);

	/* Issue read command. */
	CSR_SETBIT_1(sc, VGE_MIICMD, VGE_MIICMD_RCMD);

	/* Wait for the read command bit to self-clear. */
	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(1);
		if ((CSR_READ_1(sc, VGE_MIICMD) & VGE_MIICMD_RCMD) == 0)
			break;
	}

	if (i == VGE_TIMEOUT)
		device_printf(sc->vge_dev, "MII read timed out\n");
	else
		rval = CSR_READ_2(sc, VGE_MIIDATA);

	vge_miipoll_start(sc);

	return (rval);
}

static int
vge_miibus_writereg(device_t dev, int phy, int reg, int data)
{
	struct vge_softc *sc;
	int i, rval = 0;

	sc = device_get_softc(dev);

	if (phy != sc->vge_phyaddr)
		return (0);

	vge_miipoll_stop(sc);

	/* Specify the register we want to write. */
	CSR_WRITE_1(sc, VGE_MIIADDR, reg);

	/* Specify the data we want to write. */
	CSR_WRITE_2(sc, VGE_MIIDATA, data);

	/* Issue write command. */
	CSR_SETBIT_1(sc, VGE_MIICMD, VGE_MIICMD_WCMD);

	/* Wait for the write command bit to self-clear. */
	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(1);
		if ((CSR_READ_1(sc, VGE_MIICMD) & VGE_MIICMD_WCMD) == 0)
			break;
	}

	if (i == VGE_TIMEOUT) {
		device_printf(sc->vge_dev, "MII write timed out\n");
		rval = EIO;
	}

	vge_miipoll_start(sc);

	return (rval);
}

static void
vge_cam_clear(struct vge_softc *sc)
{
	int i;

	/*
	 * Turn off all the mask bits. This tells the chip
	 * that none of the entries in the CAM filter are valid.
	 * desired entries will be enabled as we fill the filter in.
	 */

	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_CAMMASK);
	CSR_WRITE_1(sc, VGE_CAMADDR, VGE_CAMADDR_ENABLE);
	for (i = 0; i < 8; i++)
		CSR_WRITE_1(sc, VGE_CAM0 + i, 0);

	/* Clear the VLAN filter too. */

	CSR_WRITE_1(sc, VGE_CAMADDR, VGE_CAMADDR_ENABLE|VGE_CAMADDR_AVSEL|0);
	for (i = 0; i < 8; i++)
		CSR_WRITE_1(sc, VGE_CAM0 + i, 0);

	CSR_WRITE_1(sc, VGE_CAMADDR, 0);
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_MAR);

	sc->vge_camidx = 0;
}

static int
vge_cam_set(struct vge_softc *sc, uint8_t *addr)
{
	int i, error = 0;

	if (sc->vge_camidx == VGE_CAM_MAXADDRS)
		return (ENOSPC);

	/* Select the CAM data page. */
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_CAMDATA);

	/* Set the filter entry we want to update and enable writing. */
	CSR_WRITE_1(sc, VGE_CAMADDR, VGE_CAMADDR_ENABLE|sc->vge_camidx);

	/* Write the address to the CAM registers */
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		CSR_WRITE_1(sc, VGE_CAM0 + i, addr[i]);

	/* Issue a write command. */
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_WRITE);

	/* Wake for it to clear. */
	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(1);
		if ((CSR_READ_1(sc, VGE_CAMCTL) & VGE_CAMCTL_WRITE) == 0)
			break;
	}

	if (i == VGE_TIMEOUT) {
		device_printf(sc->vge_dev, "setting CAM filter failed\n");
		error = EIO;
		goto fail;
	}

	/* Select the CAM mask page. */
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_CAMMASK);

	/* Set the mask bit that enables this filter. */
	CSR_SETBIT_1(sc, VGE_CAM0 + (sc->vge_camidx/8),
	    1<<(sc->vge_camidx & 7));

	sc->vge_camidx++;

fail:
	/* Turn off access to CAM. */
	CSR_WRITE_1(sc, VGE_CAMADDR, 0);
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_MAR);

	return (error);
}

/*
 * Program the multicast filter. We use the 64-entry CAM filter
 * for perfect filtering. If there's more than 64 multicast addresses,
 * we use the hash filter instead.
 */
static void
vge_setmulti(struct vge_softc *sc)
{
	struct ifnet *ifp;
	int error = 0/*, h = 0*/;
	struct ifmultiaddr *ifma;
	uint32_t h, hashes[2] = { 0, 0 };

	VGE_LOCK_ASSERT(sc);

	ifp = sc->vge_ifp;

	/* First, zot all the multicast entries. */
	vge_cam_clear(sc);
	CSR_WRITE_4(sc, VGE_MAR0, 0);
	CSR_WRITE_4(sc, VGE_MAR1, 0);

	/*
	 * If the user wants allmulti or promisc mode, enable reception
	 * of all multicast frames.
	 */
	if (ifp->if_flags & IFF_ALLMULTI || ifp->if_flags & IFF_PROMISC) {
		CSR_WRITE_4(sc, VGE_MAR0, 0xFFFFFFFF);
		CSR_WRITE_4(sc, VGE_MAR1, 0xFFFFFFFF);
		return;
	}

	/* Now program new ones */
	if_maddr_rlock(ifp);
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		error = vge_cam_set(sc,
		    LLADDR((struct sockaddr_dl *)ifma->ifma_addr));
		if (error)
			break;
	}

	/* If there were too many addresses, use the hash filter. */
	if (error) {
		vge_cam_clear(sc);

		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != AF_LINK)
				continue;
			h = ether_crc32_be(LLADDR((struct sockaddr_dl *)
			    ifma->ifma_addr), ETHER_ADDR_LEN) >> 26;
			if (h < 32)
				hashes[0] |= (1 << h);
			else
				hashes[1] |= (1 << (h - 32));
		}

		CSR_WRITE_4(sc, VGE_MAR0, hashes[0]);
		CSR_WRITE_4(sc, VGE_MAR1, hashes[1]);
	}
	if_maddr_runlock(ifp);
}

static void
vge_reset(struct vge_softc *sc)
{
	int i;

	CSR_WRITE_1(sc, VGE_CRS1, VGE_CR1_SOFTRESET);

	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(5);
		if ((CSR_READ_1(sc, VGE_CRS1) & VGE_CR1_SOFTRESET) == 0)
			break;
	}

	if (i == VGE_TIMEOUT) {
		device_printf(sc->vge_dev, "soft reset timed out");
		CSR_WRITE_1(sc, VGE_CRS3, VGE_CR3_STOP_FORCE);
		DELAY(2000);
	}

	DELAY(5000);

	CSR_SETBIT_1(sc, VGE_EECSR, VGE_EECSR_RELOAD);

	for (i = 0; i < VGE_TIMEOUT; i++) {
		DELAY(5);
		if ((CSR_READ_1(sc, VGE_EECSR) & VGE_EECSR_RELOAD) == 0)
			break;
	}

	if (i == VGE_TIMEOUT) {
		device_printf(sc->vge_dev, "EEPROM reload timed out\n");
		return;
	}

	CSR_CLRBIT_1(sc, VGE_CHIPCFG0, VGE_CHIPCFG0_PACPI);
}

/*
 * Probe for a VIA gigabit chip. Check the PCI vendor and device
 * IDs against our list and return a device name if we find a match.
 */
static int
vge_probe(device_t dev)
{
	struct vge_type	*t;

	t = vge_devs;

	while (t->vge_name != NULL) {
		if ((pci_get_vendor(dev) == t->vge_vid) &&
		    (pci_get_device(dev) == t->vge_did)) {
			device_set_desc(dev, t->vge_name);
			return (BUS_PROBE_DEFAULT);
		}
		t++;
	}

	return (ENXIO);
}

/*
 * Map a single buffer address.
 */

struct vge_dmamap_arg {
	bus_addr_t	vge_busaddr;
};

static void
vge_dmamap_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	struct vge_dmamap_arg *ctx;

	if (error != 0)
		return;

	KASSERT(nsegs == 1, ("%s: %d segments returned!", __func__, nsegs));

	ctx = (struct vge_dmamap_arg *)arg;
	ctx->vge_busaddr = segs[0].ds_addr;
}

static int
vge_dma_alloc(struct vge_softc *sc)
{
	struct vge_dmamap_arg ctx;
	struct vge_txdesc *txd;
	struct vge_rxdesc *rxd;
	bus_addr_t lowaddr, tx_ring_end, rx_ring_end;
	int error, i;

	lowaddr = BUS_SPACE_MAXADDR;

again:
	/* Create parent ring tag. */
	error = bus_dma_tag_create(bus_get_dma_tag(sc->vge_dev),/* parent */
	    1, 0,			/* algnmnt, boundary */
	    lowaddr,			/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    BUS_SPACE_MAXSIZE_32BIT,	/* maxsize */
	    0,				/* nsegments */
	    BUS_SPACE_MAXSIZE_32BIT,	/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->vge_cdata.vge_ring_tag);
	if (error != 0) {
		device_printf(sc->vge_dev,
		    "could not create parent DMA tag.\n");
		goto fail;
	}

	/* Create tag for Tx ring. */
	error = bus_dma_tag_create(sc->vge_cdata.vge_ring_tag,/* parent */
	    VGE_TX_RING_ALIGN, 0,	/* algnmnt, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    VGE_TX_LIST_SZ,		/* maxsize */
	    1,				/* nsegments */
	    VGE_TX_LIST_SZ,		/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->vge_cdata.vge_tx_ring_tag);
	if (error != 0) {
		device_printf(sc->vge_dev,
		    "could not allocate Tx ring DMA tag.\n");
		goto fail;
	}

	/* Create tag for Rx ring. */
	error = bus_dma_tag_create(sc->vge_cdata.vge_ring_tag,/* parent */
	    VGE_RX_RING_ALIGN, 0,	/* algnmnt, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    VGE_RX_LIST_SZ,		/* maxsize */
	    1,				/* nsegments */
	    VGE_RX_LIST_SZ,		/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->vge_cdata.vge_rx_ring_tag);
	if (error != 0) {
		device_printf(sc->vge_dev,
		    "could not allocate Rx ring DMA tag.\n");
		goto fail;
	}

	/* Allocate DMA'able memory and load the DMA map for Tx ring. */
	error = bus_dmamem_alloc(sc->vge_cdata.vge_tx_ring_tag,
	    (void **)&sc->vge_rdata.vge_tx_ring,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO | BUS_DMA_COHERENT,
	    &sc->vge_cdata.vge_tx_ring_map);
	if (error != 0) {
		device_printf(sc->vge_dev,
		    "could not allocate DMA'able memory for Tx ring.\n");
		goto fail;
	}

	ctx.vge_busaddr = 0;
	error = bus_dmamap_load(sc->vge_cdata.vge_tx_ring_tag,
	    sc->vge_cdata.vge_tx_ring_map, sc->vge_rdata.vge_tx_ring,
	    VGE_TX_LIST_SZ, vge_dmamap_cb, &ctx, BUS_DMA_NOWAIT);
	if (error != 0 || ctx.vge_busaddr == 0) {
		device_printf(sc->vge_dev,
		    "could not load DMA'able memory for Tx ring.\n");
		goto fail;
	}
	sc->vge_rdata.vge_tx_ring_paddr = ctx.vge_busaddr;

	/* Allocate DMA'able memory and load the DMA map for Rx ring. */
	error = bus_dmamem_alloc(sc->vge_cdata.vge_rx_ring_tag,
	    (void **)&sc->vge_rdata.vge_rx_ring,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO | BUS_DMA_COHERENT,
	    &sc->vge_cdata.vge_rx_ring_map);
	if (error != 0) {
		device_printf(sc->vge_dev,
		    "could not allocate DMA'able memory for Rx ring.\n");
		goto fail;
	}

	ctx.vge_busaddr = 0;
	error = bus_dmamap_load(sc->vge_cdata.vge_rx_ring_tag,
	    sc->vge_cdata.vge_rx_ring_map, sc->vge_rdata.vge_rx_ring,
	    VGE_RX_LIST_SZ, vge_dmamap_cb, &ctx, BUS_DMA_NOWAIT);
	if (error != 0 || ctx.vge_busaddr == 0) {
		device_printf(sc->vge_dev,
		    "could not load DMA'able memory for Rx ring.\n");
		goto fail;
	}
	sc->vge_rdata.vge_rx_ring_paddr = ctx.vge_busaddr;

	/* Tx/Rx descriptor queue should reside within 4GB boundary. */
	tx_ring_end = sc->vge_rdata.vge_tx_ring_paddr + VGE_TX_LIST_SZ;
	rx_ring_end = sc->vge_rdata.vge_rx_ring_paddr + VGE_RX_LIST_SZ;
	if ((VGE_ADDR_HI(tx_ring_end) !=
	    VGE_ADDR_HI(sc->vge_rdata.vge_tx_ring_paddr)) ||
	    (VGE_ADDR_HI(rx_ring_end) !=
	    VGE_ADDR_HI(sc->vge_rdata.vge_rx_ring_paddr)) ||
	    VGE_ADDR_HI(tx_ring_end) != VGE_ADDR_HI(rx_ring_end)) {
		device_printf(sc->vge_dev, "4GB boundary crossed, "
		    "switching to 32bit DMA address mode.\n");
		vge_dma_free(sc);
		/* Limit DMA address space to 32bit and try again. */
		lowaddr = BUS_SPACE_MAXADDR_32BIT;
		goto again;
	}

	/* Create parent buffer tag. */
	error = bus_dma_tag_create(bus_get_dma_tag(sc->vge_dev),/* parent */
	    1, 0,			/* algnmnt, boundary */
	    VGE_BUF_DMA_MAXADDR,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    BUS_SPACE_MAXSIZE_32BIT,	/* maxsize */
	    0,				/* nsegments */
	    BUS_SPACE_MAXSIZE_32BIT,	/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->vge_cdata.vge_buffer_tag);
	if (error != 0) {
		device_printf(sc->vge_dev,
		    "could not create parent buffer DMA tag.\n");
		goto fail;
	}

	/* Create tag for Tx buffers. */
	error = bus_dma_tag_create(sc->vge_cdata.vge_buffer_tag,/* parent */
	    1, 0,			/* algnmnt, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    MCLBYTES * VGE_MAXTXSEGS,	/* maxsize */
	    VGE_MAXTXSEGS,		/* nsegments */
	    MCLBYTES,			/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->vge_cdata.vge_tx_tag);
	if (error != 0) {
		device_printf(sc->vge_dev, "could not create Tx DMA tag.\n");
		goto fail;
	}

	/* Create tag for Rx buffers. */
	error = bus_dma_tag_create(sc->vge_cdata.vge_buffer_tag,/* parent */
	    VGE_RX_BUF_ALIGN, 0,	/* algnmnt, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    MCLBYTES,			/* maxsize */
	    1,				/* nsegments */
	    MCLBYTES,			/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->vge_cdata.vge_rx_tag);
	if (error != 0) {
		device_printf(sc->vge_dev, "could not create Rx DMA tag.\n");
		goto fail;
	}

	/* Create DMA maps for Tx buffers. */
	for (i = 0; i < VGE_TX_DESC_CNT; i++) {
		txd = &sc->vge_cdata.vge_txdesc[i];
		txd->tx_m = NULL;
		txd->tx_dmamap = NULL;
		error = bus_dmamap_create(sc->vge_cdata.vge_tx_tag, 0,
		    &txd->tx_dmamap);
		if (error != 0) {
			device_printf(sc->vge_dev,
			    "could not create Tx dmamap.\n");
			goto fail;
		}
	}
	/* Create DMA maps for Rx buffers. */
	if ((error = bus_dmamap_create(sc->vge_cdata.vge_rx_tag, 0,
	    &sc->vge_cdata.vge_rx_sparemap)) != 0) {
		device_printf(sc->vge_dev,
		    "could not create spare Rx dmamap.\n");
		goto fail;
	}
	for (i = 0; i < VGE_RX_DESC_CNT; i++) {
		rxd = &sc->vge_cdata.vge_rxdesc[i];
		rxd->rx_m = NULL;
		rxd->rx_dmamap = NULL;
		error = bus_dmamap_create(sc->vge_cdata.vge_rx_tag, 0,
		    &rxd->rx_dmamap);
		if (error != 0) {
			device_printf(sc->vge_dev,
			    "could not create Rx dmamap.\n");
			goto fail;
		}
	}

fail:
	return (error);
}

static void
vge_dma_free(struct vge_softc *sc)
{
	struct vge_txdesc *txd;
	struct vge_rxdesc *rxd;
	int i;

	/* Tx ring. */
	if (sc->vge_cdata.vge_tx_ring_tag != NULL) {
		if (sc->vge_cdata.vge_tx_ring_map)
			bus_dmamap_unload(sc->vge_cdata.vge_tx_ring_tag,
			    sc->vge_cdata.vge_tx_ring_map);
		if (sc->vge_cdata.vge_tx_ring_map &&
		    sc->vge_rdata.vge_tx_ring)
			bus_dmamem_free(sc->vge_cdata.vge_tx_ring_tag,
			    sc->vge_rdata.vge_tx_ring,
			    sc->vge_cdata.vge_tx_ring_map);
		sc->vge_rdata.vge_tx_ring = NULL;
		sc->vge_cdata.vge_tx_ring_map = NULL;
		bus_dma_tag_destroy(sc->vge_cdata.vge_tx_ring_tag);
		sc->vge_cdata.vge_tx_ring_tag = NULL;
	}
	/* Rx ring. */
	if (sc->vge_cdata.vge_rx_ring_tag != NULL) {
		if (sc->vge_cdata.vge_rx_ring_map)
			bus_dmamap_unload(sc->vge_cdata.vge_rx_ring_tag,
			    sc->vge_cdata.vge_rx_ring_map);
		if (sc->vge_cdata.vge_rx_ring_map &&
		    sc->vge_rdata.vge_rx_ring)
			bus_dmamem_free(sc->vge_cdata.vge_rx_ring_tag,
			    sc->vge_rdata.vge_rx_ring,
			    sc->vge_cdata.vge_rx_ring_map);
		sc->vge_rdata.vge_rx_ring = NULL;
		sc->vge_cdata.vge_rx_ring_map = NULL;
		bus_dma_tag_destroy(sc->vge_cdata.vge_rx_ring_tag);
		sc->vge_cdata.vge_rx_ring_tag = NULL;
	}
	/* Tx buffers. */
	if (sc->vge_cdata.vge_tx_tag != NULL) {
		for (i = 0; i < VGE_TX_DESC_CNT; i++) {
			txd = &sc->vge_cdata.vge_txdesc[i];
			if (txd->tx_dmamap != NULL) {
				bus_dmamap_destroy(sc->vge_cdata.vge_tx_tag,
				    txd->tx_dmamap);
				txd->tx_dmamap = NULL;
			}
		}
		bus_dma_tag_destroy(sc->vge_cdata.vge_tx_tag);
		sc->vge_cdata.vge_tx_tag = NULL;
	}
	/* Rx buffers. */
	if (sc->vge_cdata.vge_rx_tag != NULL) {
		for (i = 0; i < VGE_RX_DESC_CNT; i++) {
			rxd = &sc->vge_cdata.vge_rxdesc[i];
			if (rxd->rx_dmamap != NULL) {
				bus_dmamap_destroy(sc->vge_cdata.vge_rx_tag,
				    rxd->rx_dmamap);
				rxd->rx_dmamap = NULL;
			}
		}
		if (sc->vge_cdata.vge_rx_sparemap != NULL) {
			bus_dmamap_destroy(sc->vge_cdata.vge_rx_tag,
			    sc->vge_cdata.vge_rx_sparemap);
			sc->vge_cdata.vge_rx_sparemap = NULL;
		}
		bus_dma_tag_destroy(sc->vge_cdata.vge_rx_tag);
		sc->vge_cdata.vge_rx_tag = NULL;
	}

	if (sc->vge_cdata.vge_buffer_tag != NULL) {
		bus_dma_tag_destroy(sc->vge_cdata.vge_buffer_tag);
		sc->vge_cdata.vge_buffer_tag = NULL;
	}
	if (sc->vge_cdata.vge_ring_tag != NULL) {
		bus_dma_tag_destroy(sc->vge_cdata.vge_ring_tag);
		sc->vge_cdata.vge_ring_tag = NULL;
	}
}

/*
 * Attach the interface. Allocate softc structures, do ifmedia
 * setup and ethernet/BPF attach.
 */
static int
vge_attach(device_t dev)
{
	u_char eaddr[ETHER_ADDR_LEN];
	struct vge_softc *sc;
	struct ifnet *ifp;
	int error = 0, cap, msic, rid;

	sc = device_get_softc(dev);
	sc->vge_dev = dev;

	mtx_init(&sc->vge_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);
	callout_init_mtx(&sc->vge_watchdog, &sc->vge_mtx, 0);

	/*
	 * Map control/status registers.
	 */
	pci_enable_busmaster(dev);

	rid = PCIR_BAR(1);
	sc->vge_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);

	if (sc->vge_res == NULL) {
		device_printf(dev, "couldn't map ports/memory\n");
		error = ENXIO;
		goto fail;
	}

	if (pci_find_extcap(dev, PCIY_EXPRESS, &cap) == 0) {
		sc->vge_flags |= VGE_FLAG_PCIE;
		sc->vge_expcap = cap;
	}
	rid = 0;
	msic = pci_msi_count(dev);
	if (msi_disable == 0 && msic > 0) {
		msic = 1;
		if (pci_alloc_msi(dev, &msic) == 0) {
			if (msic == 1) {
				sc->vge_flags |= VGE_FLAG_MSI;
				device_printf(dev, "Using %d MSI message\n",
				    msic);
				rid = 1;
			} else
				pci_release_msi(dev);
		}
	}

	/* Allocate interrupt */
	sc->vge_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    ((sc->vge_flags & VGE_FLAG_MSI) ? 0 : RF_SHAREABLE) | RF_ACTIVE);
	if (sc->vge_irq == NULL) {
		device_printf(dev, "couldn't map interrupt\n");
		error = ENXIO;
		goto fail;
	}

	/* Reset the adapter. */
	vge_reset(sc);

	/*
	 * Get station address from the EEPROM.
	 */
	vge_read_eeprom(sc, (caddr_t)eaddr, VGE_EE_EADDR, 3, 0);
	/*
	 * Save configured PHY address.
	 * It seems the PHY address of PCIe controllers just
	 * reflects media jump strapping status so we assume the
	 * internal PHY address of PCIe controller is at 1.
	 */
	if ((sc->vge_flags & VGE_FLAG_PCIE) != 0)
		sc->vge_phyaddr = 1;
	else
		sc->vge_phyaddr = CSR_READ_1(sc, VGE_MIICFG) &
		    VGE_MIICFG_PHYADDR;
	error = vge_dma_alloc(sc);
	if (error)
		goto fail;

	ifp = sc->vge_ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(dev, "can not if_alloc()\n");
		error = ENOSPC;
		goto fail;
	}

	/* Do MII setup */
	if (mii_phy_probe(dev, &sc->vge_miibus,
	    vge_ifmedia_upd, vge_ifmedia_sts)) {
		device_printf(dev, "MII without any phy!\n");
		error = ENXIO;
		goto fail;
	}

	ifp->if_softc = sc;
	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_mtu = ETHERMTU;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = vge_ioctl;
	ifp->if_capabilities = IFCAP_VLAN_MTU;
	ifp->if_start = vge_start;
	ifp->if_hwassist = VGE_CSUM_FEATURES;
	ifp->if_capabilities |= IFCAP_HWCSUM|IFCAP_VLAN_HWTAGGING;
	ifp->if_capenable = ifp->if_capabilities;
#ifdef DEVICE_POLLING
	ifp->if_capabilities |= IFCAP_POLLING;
#endif
	ifp->if_init = vge_init;
	IFQ_SET_MAXLEN(&ifp->if_snd, VGE_TX_DESC_CNT - 1);
	ifp->if_snd.ifq_drv_maxlen = VGE_TX_DESC_CNT - 1;
	IFQ_SET_READY(&ifp->if_snd);

	/*
	 * Call MI attach routine.
	 */
	ether_ifattach(ifp, eaddr);

	/* Hook interrupt last to avoid having to lock softc */
	error = bus_setup_intr(dev, sc->vge_irq, INTR_TYPE_NET|INTR_MPSAFE,
	    NULL, vge_intr, sc, &sc->vge_intrhand);

	if (error) {
		device_printf(dev, "couldn't set up irq\n");
		ether_ifdetach(ifp);
		goto fail;
	}

fail:
	if (error)
		vge_detach(dev);

	return (error);
}

/*
 * Shutdown hardware and free up resources. This can be called any
 * time after the mutex has been initialized. It is called in both
 * the error case in attach and the normal detach case so it needs
 * to be careful about only freeing resources that have actually been
 * allocated.
 */
static int
vge_detach(device_t dev)
{
	struct vge_softc *sc;
	struct ifnet *ifp;

	sc = device_get_softc(dev);
	KASSERT(mtx_initialized(&sc->vge_mtx), ("vge mutex not initialized"));
	ifp = sc->vge_ifp;

#ifdef DEVICE_POLLING
	if (ifp->if_capenable & IFCAP_POLLING)
		ether_poll_deregister(ifp);
#endif

	/* These should only be active if attach succeeded */
	if (device_is_attached(dev)) {
		ether_ifdetach(ifp);
		VGE_LOCK(sc);
		vge_stop(sc);
		VGE_UNLOCK(sc);
		callout_drain(&sc->vge_watchdog);
	}
	if (sc->vge_miibus)
		device_delete_child(dev, sc->vge_miibus);
	bus_generic_detach(dev);

	if (sc->vge_intrhand)
		bus_teardown_intr(dev, sc->vge_irq, sc->vge_intrhand);
	if (sc->vge_irq)
		bus_release_resource(dev, SYS_RES_IRQ,
		    sc->vge_flags & VGE_FLAG_MSI ? 1 : 0, sc->vge_irq);
	if (sc->vge_flags & VGE_FLAG_MSI)
		pci_release_msi(dev);
	if (sc->vge_res)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    PCIR_BAR(1), sc->vge_res);
	if (ifp)
		if_free(ifp);

	vge_dma_free(sc);
	mtx_destroy(&sc->vge_mtx);

	return (0);
}

static void
vge_discard_rxbuf(struct vge_softc *sc, int prod)
{
	struct vge_rxdesc *rxd;
	int i;

	rxd = &sc->vge_cdata.vge_rxdesc[prod];
	rxd->rx_desc->vge_sts = 0;
	rxd->rx_desc->vge_ctl = 0;

	/*
	 * Note: the manual fails to document the fact that for
	 * proper opration, the driver needs to replentish the RX
	 * DMA ring 4 descriptors at a time (rather than one at a
	 * time, like most chips). We can allocate the new buffers
	 * but we should not set the OWN bits until we're ready
	 * to hand back 4 of them in one shot.
	 */
	if ((prod % VGE_RXCHUNK) == (VGE_RXCHUNK - 1)) {
		for (i = VGE_RXCHUNK; i > 0; i--) {
			rxd->rx_desc->vge_sts = htole32(VGE_RDSTS_OWN);
			rxd = rxd->rxd_prev;
		}
		sc->vge_cdata.vge_rx_commit += VGE_RXCHUNK;
	}
}

static int
vge_newbuf(struct vge_softc *sc, int prod)
{
	struct vge_rxdesc *rxd;
	struct mbuf *m;
	bus_dma_segment_t segs[1];
	bus_dmamap_t map;
	int i, nsegs;

	m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (ENOBUFS);
	/*
	 * This is part of an evil trick to deal with strict-alignment
	 * architectures. The VIA chip requires RX buffers to be aligned
	 * on 32-bit boundaries, but that will hose strict-alignment
	 * architectures. To get around this, we leave some empty space
	 * at the start of each buffer and for non-strict-alignment hosts,
	 * we copy the buffer back two bytes to achieve word alignment.
	 * This is slightly more efficient than allocating a new buffer,
	 * copying the contents, and discarding the old buffer.
	 */
	m->m_len = m->m_pkthdr.len = MCLBYTES;
	m_adj(m, VGE_RX_BUF_ALIGN);

	if (bus_dmamap_load_mbuf_sg(sc->vge_cdata.vge_rx_tag,
	    sc->vge_cdata.vge_rx_sparemap, m, segs, &nsegs, 0) != 0) {
		m_freem(m);
		return (ENOBUFS);
	}
	KASSERT(nsegs == 1, ("%s: %d segments returned!", __func__, nsegs));

	rxd = &sc->vge_cdata.vge_rxdesc[prod];
	if (rxd->rx_m != NULL) {
		bus_dmamap_sync(sc->vge_cdata.vge_rx_tag, rxd->rx_dmamap,
		    BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->vge_cdata.vge_rx_tag, rxd->rx_dmamap);
	}
	map = rxd->rx_dmamap;
	rxd->rx_dmamap = sc->vge_cdata.vge_rx_sparemap;
	sc->vge_cdata.vge_rx_sparemap = map;
	bus_dmamap_sync(sc->vge_cdata.vge_rx_tag, rxd->rx_dmamap,
	    BUS_DMASYNC_PREREAD);
	rxd->rx_m = m;

	rxd->rx_desc->vge_sts = 0;
	rxd->rx_desc->vge_ctl = 0;
	rxd->rx_desc->vge_addrlo = htole32(VGE_ADDR_LO(segs[0].ds_addr));
	rxd->rx_desc->vge_addrhi = htole32(VGE_ADDR_HI(segs[0].ds_addr) |
	    (VGE_BUFLEN(segs[0].ds_len) << 16) | VGE_RXDESC_I);

	/*
	 * Note: the manual fails to document the fact that for
	 * proper operation, the driver needs to replenish the RX
	 * DMA ring 4 descriptors at a time (rather than one at a
	 * time, like most chips). We can allocate the new buffers
	 * but we should not set the OWN bits until we're ready
	 * to hand back 4 of them in one shot.
	 */
	if ((prod % VGE_RXCHUNK) == (VGE_RXCHUNK - 1)) {
		for (i = VGE_RXCHUNK; i > 0; i--) {
			rxd->rx_desc->vge_sts = htole32(VGE_RDSTS_OWN);
			rxd = rxd->rxd_prev;
		}
		sc->vge_cdata.vge_rx_commit += VGE_RXCHUNK;
	}

	return (0);
}

static int
vge_tx_list_init(struct vge_softc *sc)
{
	struct vge_ring_data *rd;
	struct vge_txdesc *txd;
	int i;

	VGE_LOCK_ASSERT(sc);

	sc->vge_cdata.vge_tx_prodidx = 0;
	sc->vge_cdata.vge_tx_considx = 0;
	sc->vge_cdata.vge_tx_cnt = 0;

	rd = &sc->vge_rdata;
	bzero(rd->vge_tx_ring, VGE_TX_LIST_SZ);
	for (i = 0; i < VGE_TX_DESC_CNT; i++) {
		txd = &sc->vge_cdata.vge_txdesc[i];
		txd->tx_m = NULL;
		txd->tx_desc = &rd->vge_tx_ring[i];
	}

	bus_dmamap_sync(sc->vge_cdata.vge_tx_ring_tag,
	    sc->vge_cdata.vge_tx_ring_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	return (0);
}

static int
vge_rx_list_init(struct vge_softc *sc)
{
	struct vge_ring_data *rd;
	struct vge_rxdesc *rxd;
	int i;

	VGE_LOCK_ASSERT(sc);

	sc->vge_cdata.vge_rx_prodidx = 0;
	sc->vge_cdata.vge_head = NULL;
	sc->vge_cdata.vge_tail = NULL;
	sc->vge_cdata.vge_rx_commit = 0;

	rd = &sc->vge_rdata;
	bzero(rd->vge_rx_ring, VGE_RX_LIST_SZ);
	for (i = 0; i < VGE_RX_DESC_CNT; i++) {
		rxd = &sc->vge_cdata.vge_rxdesc[i];
		rxd->rx_m = NULL;
		rxd->rx_desc = &rd->vge_rx_ring[i];
		if (i == 0)
			rxd->rxd_prev =
			    &sc->vge_cdata.vge_rxdesc[VGE_RX_DESC_CNT - 1];
		else
			rxd->rxd_prev = &sc->vge_cdata.vge_rxdesc[i - 1];
		if (vge_newbuf(sc, i) != 0)
			return (ENOBUFS);
	}

	bus_dmamap_sync(sc->vge_cdata.vge_rx_ring_tag,
	    sc->vge_cdata.vge_rx_ring_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	sc->vge_cdata.vge_rx_commit = 0;

	return (0);
}

static void
vge_freebufs(struct vge_softc *sc)
{
	struct vge_txdesc *txd;
	struct vge_rxdesc *rxd;
	struct ifnet *ifp;
	int i;

	VGE_LOCK_ASSERT(sc);

	ifp = sc->vge_ifp;
	/*
	 * Free RX and TX mbufs still in the queues.
	 */
	for (i = 0; i < VGE_RX_DESC_CNT; i++) {
		rxd = &sc->vge_cdata.vge_rxdesc[i];
		if (rxd->rx_m != NULL) {
			bus_dmamap_sync(sc->vge_cdata.vge_rx_tag,
			    rxd->rx_dmamap, BUS_DMASYNC_POSTREAD);
			bus_dmamap_unload(sc->vge_cdata.vge_rx_tag,
			    rxd->rx_dmamap);
			m_freem(rxd->rx_m);
			rxd->rx_m = NULL;
		}
	}

	for (i = 0; i < VGE_TX_DESC_CNT; i++) {
		txd = &sc->vge_cdata.vge_txdesc[i];
		if (txd->tx_m != NULL) {
			bus_dmamap_sync(sc->vge_cdata.vge_tx_tag,
			    txd->tx_dmamap, BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->vge_cdata.vge_tx_tag,
			    txd->tx_dmamap);
			m_freem(txd->tx_m);
			txd->tx_m = NULL;
			ifp->if_oerrors++;
		}
	}
}

#ifndef	__NO_STRICT_ALIGNMENT
static __inline void
vge_fixup_rx(struct mbuf *m)
{
	int i;
	uint16_t *src, *dst;

	src = mtod(m, uint16_t *);
	dst = src - 1;

	for (i = 0; i < (m->m_len / sizeof(uint16_t) + 1); i++)
		*dst++ = *src++;

	m->m_data -= ETHER_ALIGN;
}
#endif

/*
 * RX handler. We support the reception of jumbo frames that have
 * been fragmented across multiple 2K mbuf cluster buffers.
 */
static int
vge_rxeof(struct vge_softc *sc, int count)
{
	struct mbuf *m;
	struct ifnet *ifp;
	int prod, prog, total_len;
	struct vge_rxdesc *rxd;
	struct vge_rx_desc *cur_rx;
	uint32_t rxstat, rxctl;

	VGE_LOCK_ASSERT(sc);

	ifp = sc->vge_ifp;

	bus_dmamap_sync(sc->vge_cdata.vge_rx_ring_tag,
	    sc->vge_cdata.vge_rx_ring_map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	prod = sc->vge_cdata.vge_rx_prodidx;
	for (prog = 0; count > 0 &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING) != 0;
	    VGE_RX_DESC_INC(prod)) {
		cur_rx = &sc->vge_rdata.vge_rx_ring[prod];
		rxstat = le32toh(cur_rx->vge_sts);
		if ((rxstat & VGE_RDSTS_OWN) != 0)
			break;
		count--;
		prog++;
		rxctl = le32toh(cur_rx->vge_ctl);
		total_len = VGE_RXBYTES(rxstat);
		rxd = &sc->vge_cdata.vge_rxdesc[prod];
		m = rxd->rx_m;

		/*
		 * If the 'start of frame' bit is set, this indicates
		 * either the first fragment in a multi-fragment receive,
		 * or an intermediate fragment. Either way, we want to
		 * accumulate the buffers.
		 */
		if ((rxstat & VGE_RXPKT_SOF) != 0) {
			if (vge_newbuf(sc, prod) != 0) {
				ifp->if_iqdrops++;
				VGE_CHAIN_RESET(sc);
				vge_discard_rxbuf(sc, prod);
				continue;
			}
			m->m_len = MCLBYTES - VGE_RX_BUF_ALIGN;
			if (sc->vge_cdata.vge_head == NULL) {
				sc->vge_cdata.vge_head = m;
				sc->vge_cdata.vge_tail = m;
			} else {
				m->m_flags &= ~M_PKTHDR;
				sc->vge_cdata.vge_tail->m_next = m;
				sc->vge_cdata.vge_tail = m;
			}
			continue;
		}

		/*
		 * Bad/error frames will have the RXOK bit cleared.
		 * However, there's one error case we want to allow:
		 * if a VLAN tagged frame arrives and the chip can't
		 * match it against the CAM filter, it considers this
		 * a 'VLAN CAM filter miss' and clears the 'RXOK' bit.
		 * We don't want to drop the frame though: our VLAN
		 * filtering is done in software.
		 * We also want to receive bad-checksummed frames and
		 * and frames with bad-length.
		 */
		if ((rxstat & VGE_RDSTS_RXOK) == 0 &&
		    (rxstat & (VGE_RDSTS_VIDM | VGE_RDSTS_RLERR |
		    VGE_RDSTS_CSUMERR)) == 0) {
			ifp->if_ierrors++;
			/*
			 * If this is part of a multi-fragment packet,
			 * discard all the pieces.
			 */
			VGE_CHAIN_RESET(sc);
			vge_discard_rxbuf(sc, prod);
			continue;
		}

		if (vge_newbuf(sc, prod) != 0) {
			ifp->if_iqdrops++;
			VGE_CHAIN_RESET(sc);
			vge_discard_rxbuf(sc, prod);
			continue;
		}

		/* Chain received mbufs. */
		if (sc->vge_cdata.vge_head != NULL) {
			m->m_len = total_len % (MCLBYTES - VGE_RX_BUF_ALIGN);
			/*
			 * Special case: if there's 4 bytes or less
			 * in this buffer, the mbuf can be discarded:
			 * the last 4 bytes is the CRC, which we don't
			 * care about anyway.
			 */
			if (m->m_len <= ETHER_CRC_LEN) {
				sc->vge_cdata.vge_tail->m_len -=
				    (ETHER_CRC_LEN - m->m_len);
				m_freem(m);
			} else {
				m->m_len -= ETHER_CRC_LEN;
				m->m_flags &= ~M_PKTHDR;
				sc->vge_cdata.vge_tail->m_next = m;
			}
			m = sc->vge_cdata.vge_head;
			m->m_flags |= M_PKTHDR;
			m->m_pkthdr.len = total_len - ETHER_CRC_LEN;
		} else {
			m->m_flags |= M_PKTHDR;
			m->m_pkthdr.len = m->m_len =
			    (total_len - ETHER_CRC_LEN);
		}

#ifndef	__NO_STRICT_ALIGNMENT
		vge_fixup_rx(m);
#endif
		m->m_pkthdr.rcvif = ifp;

		/* Do RX checksumming if enabled */
		if ((ifp->if_capenable & IFCAP_RXCSUM) != 0 &&
		    (rxctl & VGE_RDCTL_FRAG) == 0) {
			/* Check IP header checksum */
			if ((rxctl & VGE_RDCTL_IPPKT) != 0)
				m->m_pkthdr.csum_flags |= CSUM_IP_CHECKED;
			if ((rxctl & VGE_RDCTL_IPCSUMOK) != 0)
				m->m_pkthdr.csum_flags |= CSUM_IP_VALID;

			/* Check TCP/UDP checksum */
			if (rxctl & (VGE_RDCTL_TCPPKT | VGE_RDCTL_UDPPKT) &&
			    rxctl & VGE_RDCTL_PROTOCSUMOK) {
				m->m_pkthdr.csum_flags |=
				    CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
				m->m_pkthdr.csum_data = 0xffff;
			}
		}

		if ((rxstat & VGE_RDSTS_VTAG) != 0) {
			/*
			 * The 32-bit rxctl register is stored in little-endian.
			 * However, the 16-bit vlan tag is stored in big-endian,
			 * so we have to byte swap it.
			 */
			m->m_pkthdr.ether_vtag =
			    bswap16(rxctl & VGE_RDCTL_VLANID);
			m->m_flags |= M_VLANTAG;
		}

		VGE_UNLOCK(sc);
		(*ifp->if_input)(ifp, m);
		VGE_LOCK(sc);
		sc->vge_cdata.vge_head = NULL;
		sc->vge_cdata.vge_tail = NULL;
	}

	if (prog > 0) {
		sc->vge_cdata.vge_rx_prodidx = prod;
		bus_dmamap_sync(sc->vge_cdata.vge_rx_ring_tag,
		    sc->vge_cdata.vge_rx_ring_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* Update residue counter. */
		if (sc->vge_cdata.vge_rx_commit != 0) {
			CSR_WRITE_2(sc, VGE_RXDESC_RESIDUECNT,
			    sc->vge_cdata.vge_rx_commit);
			sc->vge_cdata.vge_rx_commit = 0;
		}
	}
	return (prog);
}

static void
vge_txeof(struct vge_softc *sc)
{
	struct ifnet *ifp;
	struct vge_tx_desc *cur_tx;
	struct vge_txdesc *txd;
	uint32_t txstat;
	int cons, prod;

	VGE_LOCK_ASSERT(sc);

	ifp = sc->vge_ifp;

	if (sc->vge_cdata.vge_tx_cnt == 0)
		return;

	bus_dmamap_sync(sc->vge_cdata.vge_tx_ring_tag,
	    sc->vge_cdata.vge_tx_ring_map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * Go through our tx list and free mbufs for those
	 * frames that have been transmitted.
	 */
	cons = sc->vge_cdata.vge_tx_considx;
	prod = sc->vge_cdata.vge_tx_prodidx;
	for (; cons != prod; VGE_TX_DESC_INC(cons)) {
		cur_tx = &sc->vge_rdata.vge_tx_ring[cons];
		txstat = le32toh(cur_tx->vge_sts);
		if ((txstat & VGE_TDSTS_OWN) != 0)
			break;
		sc->vge_cdata.vge_tx_cnt--;
		ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;

		txd = &sc->vge_cdata.vge_txdesc[cons];
		bus_dmamap_sync(sc->vge_cdata.vge_tx_tag, txd->tx_dmamap,
		    BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->vge_cdata.vge_tx_tag, txd->tx_dmamap);

		KASSERT(txd->tx_m != NULL, ("%s: freeing NULL mbuf!\n",
		    __func__));
		m_freem(txd->tx_m);
		txd->tx_m = NULL;
		txd->tx_desc->vge_frag[0].vge_addrhi = 0;
	}
	bus_dmamap_sync(sc->vge_cdata.vge_tx_ring_tag,
	    sc->vge_cdata.vge_tx_ring_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	sc->vge_cdata.vge_tx_considx = cons;
	if (sc->vge_cdata.vge_tx_cnt == 0)
		sc->vge_timer = 0;
	else {
		/*
		 * If not all descriptors have been released reaped yet,
		 * reload the timer so that we will eventually get another
		 * interrupt that will cause us to re-enter this routine.
		 * This is done in case the transmitter has gone idle.
		 */
		CSR_WRITE_1(sc, VGE_CRS1, VGE_CR1_TIMER0_ENABLE);
	}
}

static void
vge_tick(void *xsc)
{
	struct vge_softc *sc;
	struct ifnet *ifp;
	struct mii_data *mii;

	sc = xsc;
	ifp = sc->vge_ifp;
	VGE_LOCK_ASSERT(sc);
	mii = device_get_softc(sc->vge_miibus);

	mii_tick(mii);
	if ((sc->vge_flags & VGE_FLAG_LINK) != 0) {
		if (!(mii->mii_media_status & IFM_ACTIVE)) {
			sc->vge_flags &= ~VGE_FLAG_LINK;
			if_link_state_change(sc->vge_ifp,
			    LINK_STATE_DOWN);
		}
	} else {
		if (mii->mii_media_status & IFM_ACTIVE &&
		    IFM_SUBTYPE(mii->mii_media_active) != IFM_NONE) {
			sc->vge_flags |= VGE_FLAG_LINK;
			if_link_state_change(sc->vge_ifp,
			    LINK_STATE_UP);
			if (!IFQ_DRV_IS_EMPTY(&ifp->if_snd))
				vge_start_locked(ifp);
		}
	}
}

#ifdef DEVICE_POLLING
static int
vge_poll (struct ifnet *ifp, enum poll_cmd cmd, int count)
{
	struct vge_softc *sc = ifp->if_softc;
	int rx_npkts = 0;

	VGE_LOCK(sc);
	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING))
		goto done;

	rx_npkts = vge_rxeof(sc, count);
	vge_txeof(sc);

	if (!IFQ_DRV_IS_EMPTY(&ifp->if_snd))
		vge_start_locked(ifp);

	if (cmd == POLL_AND_CHECK_STATUS) { /* also check status register */
		uint32_t       status;
		status = CSR_READ_4(sc, VGE_ISR);
		if (status == 0xFFFFFFFF)
			goto done;
		if (status)
			CSR_WRITE_4(sc, VGE_ISR, status);

		/*
		 * XXX check behaviour on receiver stalls.
		 */

		if (status & VGE_ISR_TXDMA_STALL ||
		    status & VGE_ISR_RXDMA_STALL) {
			ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
			vge_init_locked(sc);
		}

		if (status & (VGE_ISR_RXOFLOW|VGE_ISR_RXNODESC)) {
			vge_rxeof(sc, count);
			ifp->if_ierrors++;
			CSR_WRITE_1(sc, VGE_RXQCSRS, VGE_RXQCSR_RUN);
			CSR_WRITE_1(sc, VGE_RXQCSRS, VGE_RXQCSR_WAK);
		}
	}
done:
	VGE_UNLOCK(sc);
	return (rx_npkts);
}
#endif /* DEVICE_POLLING */

static void
vge_intr(void *arg)
{
	struct vge_softc *sc;
	struct ifnet *ifp;
	uint32_t status;

	sc = arg;

	if (sc->suspended) {
		return;
	}

	VGE_LOCK(sc);
	ifp = sc->vge_ifp;

	if (!(ifp->if_flags & IFF_UP)) {
		VGE_UNLOCK(sc);
		return;
	}

#ifdef DEVICE_POLLING
	if  (ifp->if_capenable & IFCAP_POLLING) {
		VGE_UNLOCK(sc);
		return;
	}
#endif

	/* Disable interrupts */
	CSR_WRITE_1(sc, VGE_CRC3, VGE_CR3_INT_GMSK);

	for (;;) {

		status = CSR_READ_4(sc, VGE_ISR);
		/* If the card has gone away the read returns 0xffff. */
		if (status == 0xFFFFFFFF)
			break;

		if (status)
			CSR_WRITE_4(sc, VGE_ISR, status);

		if ((status & VGE_INTRS) == 0)
			break;

		if (status & (VGE_ISR_RXOK|VGE_ISR_RXOK_HIPRIO))
			vge_rxeof(sc, VGE_RX_DESC_CNT);

		if (status & (VGE_ISR_RXOFLOW|VGE_ISR_RXNODESC)) {
			vge_rxeof(sc, VGE_RX_DESC_CNT);
			CSR_WRITE_1(sc, VGE_RXQCSRS, VGE_RXQCSR_RUN);
			CSR_WRITE_1(sc, VGE_RXQCSRS, VGE_RXQCSR_WAK);
		}

		if (status & (VGE_ISR_TXOK0|VGE_ISR_TIMER0))
			vge_txeof(sc);

		if (status & (VGE_ISR_TXDMA_STALL|VGE_ISR_RXDMA_STALL)) {
			ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
			vge_init_locked(sc);
		}

		if (status & VGE_ISR_LINKSTS)
			vge_tick(sc);
	}

	/* Re-enable interrupts */
	CSR_WRITE_1(sc, VGE_CRS3, VGE_CR3_INT_GMSK);

	if (!IFQ_DRV_IS_EMPTY(&ifp->if_snd))
		vge_start_locked(ifp);

	VGE_UNLOCK(sc);
}

static int
vge_encap(struct vge_softc *sc, struct mbuf **m_head)
{
	struct vge_txdesc *txd;
	struct vge_tx_frag *frag;
	struct mbuf *m;
	bus_dma_segment_t txsegs[VGE_MAXTXSEGS];
	int error, i, nsegs, padlen;
	uint32_t cflags;

	VGE_LOCK_ASSERT(sc);

	M_ASSERTPKTHDR((*m_head));

	/* Argh. This chip does not autopad short frames. */
	if ((*m_head)->m_pkthdr.len < VGE_MIN_FRAMELEN) {
		m = *m_head;
		padlen = VGE_MIN_FRAMELEN - m->m_pkthdr.len;
		if (M_WRITABLE(m) == 0) {
			/* Get a writable copy. */
			m = m_dup(*m_head, M_DONTWAIT);
			m_freem(*m_head);
			if (m == NULL) {
				*m_head = NULL;
				return (ENOBUFS);
			}
			*m_head = m;
		}
		if (M_TRAILINGSPACE(m) < padlen) {
			m = m_defrag(m, M_DONTWAIT);
			if (m == NULL) {
				m_freem(*m_head);
				*m_head = NULL;
				return (ENOBUFS);
			}
		}
		/*
		 * Manually pad short frames, and zero the pad space
		 * to avoid leaking data.
		 */
		bzero(mtod(m, char *) + m->m_pkthdr.len, padlen);
		m->m_pkthdr.len += padlen;
		m->m_len = m->m_pkthdr.len;
		*m_head = m;
	}

	txd = &sc->vge_cdata.vge_txdesc[sc->vge_cdata.vge_tx_prodidx];

	error = bus_dmamap_load_mbuf_sg(sc->vge_cdata.vge_tx_tag,
	    txd->tx_dmamap, *m_head, txsegs, &nsegs, 0);
	if (error == EFBIG) {
		m = m_collapse(*m_head, M_DONTWAIT, VGE_MAXTXSEGS);
		if (m == NULL) {
			m_freem(*m_head);
			*m_head = NULL;
			return (ENOMEM);
		}
		*m_head = m;
		error = bus_dmamap_load_mbuf_sg(sc->vge_cdata.vge_tx_tag,
		    txd->tx_dmamap, *m_head, txsegs, &nsegs, 0);
		if (error != 0) {
			m_freem(*m_head);
			*m_head = NULL;
			return (error);
		}
	} else if (error != 0)
		return (error);
	bus_dmamap_sync(sc->vge_cdata.vge_tx_tag, txd->tx_dmamap,
	    BUS_DMASYNC_PREWRITE);

	m = *m_head;
	cflags = 0;

	/* Configure checksum offload. */
	if ((m->m_pkthdr.csum_flags & CSUM_IP) != 0)
		cflags |= VGE_TDCTL_IPCSUM;
	if ((m->m_pkthdr.csum_flags & CSUM_TCP) != 0)
		cflags |= VGE_TDCTL_TCPCSUM;
	if ((m->m_pkthdr.csum_flags & CSUM_UDP) != 0)
		cflags |= VGE_TDCTL_UDPCSUM;

	/* Configure VLAN. */
	if ((m->m_flags & M_VLANTAG) != 0)
		cflags |= m->m_pkthdr.ether_vtag | VGE_TDCTL_VTAG;
	txd->tx_desc->vge_sts = htole32(m->m_pkthdr.len << 16);
	/*
	 * XXX
	 * Velocity family seems to support TSO but no information
	 * for MSS configuration is available. Also the number of
	 * fragments supported by a descriptor is too small to hold
	 * entire 64KB TCP/IP segment. Maybe VGE_TD_LS_MOF,
	 * VGE_TD_LS_SOF and VGE_TD_LS_EOF could be used to build
	 * longer chain of buffers but no additional information is
	 * available.
	 *
	 * When telling the chip how many segments there are, we
	 * must use nsegs + 1 instead of just nsegs. Darned if I
	 * know why. This also means we can't use the last fragment
	 * field of Tx descriptor.
	 */
	txd->tx_desc->vge_ctl = htole32(cflags | ((nsegs + 1) << 28) |
	    VGE_TD_LS_NORM);
	for (i = 0; i < nsegs; i++) {
		frag = &txd->tx_desc->vge_frag[i];
		frag->vge_addrlo = htole32(VGE_ADDR_LO(txsegs[i].ds_addr));
		frag->vge_addrhi = htole32(VGE_ADDR_HI(txsegs[i].ds_addr) |
		    (VGE_BUFLEN(txsegs[i].ds_len) << 16));
	}

	sc->vge_cdata.vge_tx_cnt++;
	VGE_TX_DESC_INC(sc->vge_cdata.vge_tx_prodidx);

	/*
	 * Finally request interrupt and give the first descriptor
	 * ownership to hardware.
	 */
	txd->tx_desc->vge_ctl |= htole32(VGE_TDCTL_TIC);
	txd->tx_desc->vge_sts |= htole32(VGE_TDSTS_OWN);
	txd->tx_m = m;

	return (0);
}

/*
 * Main transmit routine.
 */

static void
vge_start(struct ifnet *ifp)
{
	struct vge_softc *sc;

	sc = ifp->if_softc;
	VGE_LOCK(sc);
	vge_start_locked(ifp);
	VGE_UNLOCK(sc);
}


static void
vge_start_locked(struct ifnet *ifp)
{
	struct vge_softc *sc;
	struct vge_txdesc *txd;
	struct mbuf *m_head;
	int enq, idx;

	sc = ifp->if_softc;

	VGE_LOCK_ASSERT(sc);

	if ((sc->vge_flags & VGE_FLAG_LINK) == 0 ||
	    (ifp->if_drv_flags & (IFF_DRV_RUNNING | IFF_DRV_OACTIVE)) !=
	    IFF_DRV_RUNNING)
		return;

	idx = sc->vge_cdata.vge_tx_prodidx;
	VGE_TX_DESC_DEC(idx);
	for (enq = 0; !IFQ_DRV_IS_EMPTY(&ifp->if_snd) &&
	    sc->vge_cdata.vge_tx_cnt < VGE_TX_DESC_CNT - 1; ) {
		IFQ_DRV_DEQUEUE(&ifp->if_snd, m_head);
		if (m_head == NULL)
			break;
		/*
		 * Pack the data into the transmit ring. If we
		 * don't have room, set the OACTIVE flag and wait
		 * for the NIC to drain the ring.
		 */
		if (vge_encap(sc, &m_head)) {
			if (m_head == NULL)
				break;
			IFQ_DRV_PREPEND(&ifp->if_snd, m_head);
			ifp->if_drv_flags |= IFF_DRV_OACTIVE;
			break;
		}

		txd = &sc->vge_cdata.vge_txdesc[idx];
		txd->tx_desc->vge_frag[0].vge_addrhi |= htole32(VGE_TXDESC_Q);
		VGE_TX_DESC_INC(idx);

		enq++;
		/*
		 * If there's a BPF listener, bounce a copy of this frame
		 * to him.
		 */
		ETHER_BPF_MTAP(ifp, m_head);
	}

	if (enq > 0) {
		bus_dmamap_sync(sc->vge_cdata.vge_tx_ring_tag,
		    sc->vge_cdata.vge_tx_ring_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/* Issue a transmit command. */
		CSR_WRITE_2(sc, VGE_TXQCSRS, VGE_TXQCSR_WAK0);
		/*
		 * Use the countdown timer for interrupt moderation.
		 * 'TX done' interrupts are disabled. Instead, we reset the
		 * countdown timer, which will begin counting until it hits
		 * the value in the SSTIMER register, and then trigger an
		 * interrupt. Each time we set the TIMER0_ENABLE bit, the
		 * the timer count is reloaded. Only when the transmitter
		 * is idle will the timer hit 0 and an interrupt fire.
		 */
		CSR_WRITE_1(sc, VGE_CRS1, VGE_CR1_TIMER0_ENABLE);

		/*
		 * Set a timeout in case the chip goes out to lunch.
		 */
		sc->vge_timer = 5;
	}
}

static void
vge_init(void *xsc)
{
	struct vge_softc *sc = xsc;

	VGE_LOCK(sc);
	vge_init_locked(sc);
	VGE_UNLOCK(sc);
}

static void
vge_init_locked(struct vge_softc *sc)
{
	struct ifnet *ifp = sc->vge_ifp;
	struct mii_data *mii;
	int error, i;

	VGE_LOCK_ASSERT(sc);
	mii = device_get_softc(sc->vge_miibus);

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) != 0)
		return;

	/*
	 * Cancel pending I/O and free all RX/TX buffers.
	 */
	vge_stop(sc);
	vge_reset(sc);

	/*
	 * Initialize the RX and TX descriptors and mbufs.
	 */

	error = vge_rx_list_init(sc);
	if (error != 0) {
                device_printf(sc->vge_dev, "no memory for Rx buffers.\n");
                return;
	}
	vge_tx_list_init(sc);

	/* Set our station address */
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		CSR_WRITE_1(sc, VGE_PAR0 + i, IF_LLADDR(sc->vge_ifp)[i]);

	/*
	 * Set receive FIFO threshold. Also allow transmission and
	 * reception of VLAN tagged frames.
	 */
	CSR_CLRBIT_1(sc, VGE_RXCFG, VGE_RXCFG_FIFO_THR|VGE_RXCFG_VTAGOPT);
	CSR_SETBIT_1(sc, VGE_RXCFG, VGE_RXFIFOTHR_128BYTES|VGE_VTAG_OPT2);

	/* Set DMA burst length */
	CSR_CLRBIT_1(sc, VGE_DMACFG0, VGE_DMACFG0_BURSTLEN);
	CSR_SETBIT_1(sc, VGE_DMACFG0, VGE_DMABURST_128);

	CSR_SETBIT_1(sc, VGE_TXCFG, VGE_TXCFG_ARB_PRIO|VGE_TXCFG_NONBLK);

	/* Set collision backoff algorithm */
	CSR_CLRBIT_1(sc, VGE_CHIPCFG1, VGE_CHIPCFG1_CRANDOM|
	    VGE_CHIPCFG1_CAP|VGE_CHIPCFG1_MBA|VGE_CHIPCFG1_BAKOPT);
	CSR_SETBIT_1(sc, VGE_CHIPCFG1, VGE_CHIPCFG1_OFSET);

	/* Disable LPSEL field in priority resolution */
	CSR_SETBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_LPSEL_DIS);

	/*
	 * Load the addresses of the DMA queues into the chip.
	 * Note that we only use one transmit queue.
	 */

	CSR_WRITE_4(sc, VGE_TXDESC_HIADDR,
	    VGE_ADDR_HI(sc->vge_rdata.vge_tx_ring_paddr));
	CSR_WRITE_4(sc, VGE_TXDESC_ADDR_LO0,
	    VGE_ADDR_LO(sc->vge_rdata.vge_tx_ring_paddr));
	CSR_WRITE_2(sc, VGE_TXDESCNUM, VGE_TX_DESC_CNT - 1);

	CSR_WRITE_4(sc, VGE_RXDESC_ADDR_LO,
	    VGE_ADDR_LO(sc->vge_rdata.vge_rx_ring_paddr));
	CSR_WRITE_2(sc, VGE_RXDESCNUM, VGE_RX_DESC_CNT - 1);
	CSR_WRITE_2(sc, VGE_RXDESC_RESIDUECNT, VGE_RX_DESC_CNT);

	/* Enable and wake up the RX descriptor queue */
	CSR_WRITE_1(sc, VGE_RXQCSRS, VGE_RXQCSR_RUN);
	CSR_WRITE_1(sc, VGE_RXQCSRS, VGE_RXQCSR_WAK);

	/* Enable the TX descriptor queue */
	CSR_WRITE_2(sc, VGE_TXQCSRS, VGE_TXQCSR_RUN0);

	/* Set up the receive filter -- allow large frames for VLANs. */
	CSR_WRITE_1(sc, VGE_RXCTL, VGE_RXCTL_RX_UCAST|VGE_RXCTL_RX_GIANT);

	/* If we want promiscuous mode, set the allframes bit. */
	if (ifp->if_flags & IFF_PROMISC) {
		CSR_SETBIT_1(sc, VGE_RXCTL, VGE_RXCTL_RX_PROMISC);
	}

	/* Set capture broadcast bit to capture broadcast frames. */
	if (ifp->if_flags & IFF_BROADCAST) {
		CSR_SETBIT_1(sc, VGE_RXCTL, VGE_RXCTL_RX_BCAST);
	}

	/* Set multicast bit to capture multicast frames. */
	if (ifp->if_flags & IFF_MULTICAST) {
		CSR_SETBIT_1(sc, VGE_RXCTL, VGE_RXCTL_RX_MCAST);
	}

	/* Init the cam filter. */
	vge_cam_clear(sc);

	/* Init the multicast filter. */
	vge_setmulti(sc);

	/* Enable flow control */

	CSR_WRITE_1(sc, VGE_CRS2, 0x8B);

	/* Enable jumbo frame reception (if desired) */

	/* Start the MAC. */
	CSR_WRITE_1(sc, VGE_CRC0, VGE_CR0_STOP);
	CSR_WRITE_1(sc, VGE_CRS1, VGE_CR1_NOPOLL);
	CSR_WRITE_1(sc, VGE_CRS0,
	    VGE_CR0_TX_ENABLE|VGE_CR0_RX_ENABLE|VGE_CR0_START);

	/*
	 * Configure one-shot timer for microsecond
	 * resolution and load it for 500 usecs.
	 */
	CSR_SETBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_TIMER0_RES);
	CSR_WRITE_2(sc, VGE_SSTIMER, 400);

	/*
	 * Configure interrupt moderation for receive. Enable
	 * the holdoff counter and load it, and set the RX
	 * suppression count to the number of descriptors we
	 * want to allow before triggering an interrupt.
	 * The holdoff timer is in units of 20 usecs.
	 */

#ifdef notyet
	CSR_WRITE_1(sc, VGE_INTCTL1, VGE_INTCTL_TXINTSUP_DISABLE);
	/* Select the interrupt holdoff timer page. */
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_INTHLDOFF);
	CSR_WRITE_1(sc, VGE_INTHOLDOFF, 10); /* ~200 usecs */

	/* Enable use of the holdoff timer. */
	CSR_WRITE_1(sc, VGE_CRS3, VGE_CR3_INT_HOLDOFF);
	CSR_WRITE_1(sc, VGE_INTCTL1, VGE_INTCTL_SC_RELOAD);

	/* Select the RX suppression threshold page. */
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_RXSUPPTHR);
	CSR_WRITE_1(sc, VGE_RXSUPPTHR, 64); /* interrupt after 64 packets */

	/* Restore the page select bits. */
	CSR_CLRBIT_1(sc, VGE_CAMCTL, VGE_CAMCTL_PAGESEL);
	CSR_SETBIT_1(sc, VGE_CAMCTL, VGE_PAGESEL_MAR);
#endif

#ifdef DEVICE_POLLING
	/*
	 * Disable interrupts if we are polling.
	 */
	if (ifp->if_capenable & IFCAP_POLLING) {
		CSR_WRITE_4(sc, VGE_IMR, 0);
		CSR_WRITE_1(sc, VGE_CRC3, VGE_CR3_INT_GMSK);
	} else	/* otherwise ... */
#endif
	{
	/*
	 * Enable interrupts.
	 */
		CSR_WRITE_4(sc, VGE_IMR, VGE_INTRS);
		CSR_WRITE_4(sc, VGE_ISR, 0);
		CSR_WRITE_1(sc, VGE_CRS3, VGE_CR3_INT_GMSK);
	}

	sc->vge_flags &= ~VGE_FLAG_LINK;
	mii_mediachg(mii);

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	callout_reset(&sc->vge_watchdog, hz, vge_watchdog, sc);
}

/*
 * Set media options.
 */
static int
vge_ifmedia_upd(struct ifnet *ifp)
{
	struct vge_softc *sc;
	struct mii_data *mii;

	sc = ifp->if_softc;
	VGE_LOCK(sc);
	mii = device_get_softc(sc->vge_miibus);
	mii_mediachg(mii);
	VGE_UNLOCK(sc);

	return (0);
}

/*
 * Report current media status.
 */
static void
vge_ifmedia_sts(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct vge_softc *sc;
	struct mii_data *mii;

	sc = ifp->if_softc;
	mii = device_get_softc(sc->vge_miibus);

	VGE_LOCK(sc);
	mii_pollstat(mii);
	VGE_UNLOCK(sc);
	ifmr->ifm_active = mii->mii_media_active;
	ifmr->ifm_status = mii->mii_media_status;
}

static void
vge_miibus_statchg(device_t dev)
{
	struct vge_softc *sc;
	struct mii_data *mii;
	struct ifmedia_entry *ife;

	sc = device_get_softc(dev);
	mii = device_get_softc(sc->vge_miibus);
	ife = mii->mii_media.ifm_cur;

	/*
	 * If the user manually selects a media mode, we need to turn
	 * on the forced MAC mode bit in the DIAGCTL register. If the
	 * user happens to choose a full duplex mode, we also need to
	 * set the 'force full duplex' bit. This applies only to
	 * 10Mbps and 100Mbps speeds. In autoselect mode, forced MAC
	 * mode is disabled, and in 1000baseT mode, full duplex is
	 * always implied, so we turn on the forced mode bit but leave
	 * the FDX bit cleared.
	 */

	switch (IFM_SUBTYPE(ife->ifm_media)) {
	case IFM_AUTO:
		CSR_CLRBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_MACFORCE);
		CSR_CLRBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_FDXFORCE);
		break;
	case IFM_1000_T:
		CSR_SETBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_MACFORCE);
		CSR_CLRBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_FDXFORCE);
		break;
	case IFM_100_TX:
	case IFM_10_T:
		CSR_SETBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_MACFORCE);
		if ((ife->ifm_media & IFM_GMASK) == IFM_FDX) {
			CSR_SETBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_FDXFORCE);
		} else {
			CSR_CLRBIT_1(sc, VGE_DIAGCTL, VGE_DIAGCTL_FDXFORCE);
		}
		break;
	default:
		device_printf(dev, "unknown media type: %x\n",
		    IFM_SUBTYPE(ife->ifm_media));
		break;
	}
}

static int
vge_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct vge_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *) data;
	struct mii_data *mii;
	int error = 0;

	switch (command) {
	case SIOCSIFMTU:
		if (ifr->ifr_mtu > VGE_JUMBO_MTU)
			error = EINVAL;
		ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCSIFFLAGS:
		VGE_LOCK(sc);
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING &&
			    ifp->if_flags & IFF_PROMISC &&
			    !(sc->vge_if_flags & IFF_PROMISC)) {
				CSR_SETBIT_1(sc, VGE_RXCTL,
				    VGE_RXCTL_RX_PROMISC);
				vge_setmulti(sc);
			} else if (ifp->if_drv_flags & IFF_DRV_RUNNING &&
			    !(ifp->if_flags & IFF_PROMISC) &&
			    sc->vge_if_flags & IFF_PROMISC) {
				CSR_CLRBIT_1(sc, VGE_RXCTL,
				    VGE_RXCTL_RX_PROMISC);
				vge_setmulti(sc);
                        } else
				vge_init_locked(sc);
		} else {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
				vge_stop(sc);
		}
		sc->vge_if_flags = ifp->if_flags;
		VGE_UNLOCK(sc);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		VGE_LOCK(sc);
		if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			vge_setmulti(sc);
		VGE_UNLOCK(sc);
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		mii = device_get_softc(sc->vge_miibus);
		error = ifmedia_ioctl(ifp, ifr, &mii->mii_media, command);
		break;
	case SIOCSIFCAP:
	    {
		int mask = ifr->ifr_reqcap ^ ifp->if_capenable;
#ifdef DEVICE_POLLING
		if (mask & IFCAP_POLLING) {
			if (ifr->ifr_reqcap & IFCAP_POLLING) {
				error = ether_poll_register(vge_poll, ifp);
				if (error)
					return (error);
				VGE_LOCK(sc);
					/* Disable interrupts */
				CSR_WRITE_4(sc, VGE_IMR, 0);
				CSR_WRITE_1(sc, VGE_CRC3, VGE_CR3_INT_GMSK);
				ifp->if_capenable |= IFCAP_POLLING;
				VGE_UNLOCK(sc);
			} else {
				error = ether_poll_deregister(ifp);
				/* Enable interrupts. */
				VGE_LOCK(sc);
				CSR_WRITE_4(sc, VGE_IMR, VGE_INTRS);
				CSR_WRITE_4(sc, VGE_ISR, 0xFFFFFFFF);
				CSR_WRITE_1(sc, VGE_CRS3, VGE_CR3_INT_GMSK);
				ifp->if_capenable &= ~IFCAP_POLLING;
				VGE_UNLOCK(sc);
			}
		}
#endif /* DEVICE_POLLING */
		VGE_LOCK(sc);
		if ((mask & IFCAP_TXCSUM) != 0 &&
		    (ifp->if_capabilities & IFCAP_TXCSUM) != 0) {
			ifp->if_capenable ^= IFCAP_TXCSUM;
			if ((ifp->if_capenable & IFCAP_TXCSUM) != 0)
				ifp->if_hwassist |= VGE_CSUM_FEATURES;
			else
				ifp->if_hwassist &= ~VGE_CSUM_FEATURES;
		}
		if ((mask & IFCAP_RXCSUM) != 0 &&
		    (ifp->if_capabilities & IFCAP_RXCSUM) != 0)
			ifp->if_capenable ^= IFCAP_RXCSUM;
		VGE_UNLOCK(sc);
	    }
		break;
	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}

	return (error);
}

static void
vge_watchdog(void *arg)
{
	struct vge_softc *sc;
	struct ifnet *ifp;

	sc = arg;
	VGE_LOCK_ASSERT(sc);
	callout_reset(&sc->vge_watchdog, hz, vge_watchdog, sc);
	if (sc->vge_timer == 0 || --sc->vge_timer > 0)
		return;

	ifp = sc->vge_ifp;
	if_printf(ifp, "watchdog timeout\n");
	ifp->if_oerrors++;

	vge_txeof(sc);
	vge_rxeof(sc, VGE_RX_DESC_CNT);

	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	vge_init_locked(sc);
}

/*
 * Stop the adapter and free any mbufs allocated to the
 * RX and TX lists.
 */
static void
vge_stop(struct vge_softc *sc)
{
	struct ifnet *ifp;

	VGE_LOCK_ASSERT(sc);
	ifp = sc->vge_ifp;
	sc->vge_timer = 0;
	callout_stop(&sc->vge_watchdog);

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	CSR_WRITE_1(sc, VGE_CRC3, VGE_CR3_INT_GMSK);
	CSR_WRITE_1(sc, VGE_CRS0, VGE_CR0_STOP);
	CSR_WRITE_4(sc, VGE_ISR, 0xFFFFFFFF);
	CSR_WRITE_2(sc, VGE_TXQCSRC, 0xFFFF);
	CSR_WRITE_1(sc, VGE_RXQCSRC, 0xFF);
	CSR_WRITE_4(sc, VGE_RXDESC_ADDR_LO, 0);

	VGE_CHAIN_RESET(sc);
	vge_txeof(sc);
	vge_freebufs(sc);
}

/*
 * Device suspend routine.  Stop the interface and save some PCI
 * settings in case the BIOS doesn't restore them properly on
 * resume.
 */
static int
vge_suspend(device_t dev)
{
	struct vge_softc *sc;

	sc = device_get_softc(dev);

	VGE_LOCK(sc);
	vge_stop(sc);

	sc->suspended = 1;
	VGE_UNLOCK(sc);

	return (0);
}

/*
 * Device resume routine.  Restore some PCI settings in case the BIOS
 * doesn't, re-enable busmastering, and restart the interface if
 * appropriate.
 */
static int
vge_resume(device_t dev)
{
	struct vge_softc *sc;
	struct ifnet *ifp;

	sc = device_get_softc(dev);
	ifp = sc->vge_ifp;

	/* reenable busmastering */
	pci_enable_busmaster(dev);
	pci_enable_io(dev, SYS_RES_MEMORY);

	/* reinitialize interface if necessary */
	VGE_LOCK(sc);
	if (ifp->if_flags & IFF_UP) {
		ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		vge_init_locked(sc);
	}
	sc->suspended = 0;
	VGE_UNLOCK(sc);

	return (0);
}

/*
 * Stop all chip I/O so that the kernel's probe routines don't
 * get confused by errant DMAs when rebooting.
 */
static int
vge_shutdown(device_t dev)
{
	struct vge_softc *sc;

	sc = device_get_softc(dev);

	VGE_LOCK(sc);
	vge_stop(sc);
	VGE_UNLOCK(sc);

	return (0);
}
