/*
 * Copyright (c) 1997, 1998, 1999, 2000
 *	Bill Paul <wpaul@ee.columbia.edu>.  All rights reserved.
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
 *
 * $FreeBSD$
 */

/*
 * CATC USB-EL1210A USB to ethernet driver. Used in the CATC Netmate
 * adapters and others.
 *
 * Written by Bill Paul <wpaul@ee.columbia.edu>
 * Electrical Engineering Department
 * Columbia University, New York City
 */

/*
 * The CATC USB-EL1210A provides USB ethernet support at 10Mbps. The
 * RX filter uses a 512-bit multicast hash table, single perfect entry
 * for the station address, and promiscuous mode. Unlike the ADMtek
 * and KLSI chips, the CATC ASIC supports read and write combining
 * mode where multiple packets can be transfered using a single bulk
 * transaction, which helps performance a great deal.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>

#include <net/bpf.h>

#include <machine/clock.h>      /* for DELAY */
#include <sys/bus.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usb_ethersubr.h>

#include <dev/usb/if_cuereg.h>

#ifndef lint
static const char rcsid[] =
  "$FreeBSD$";
#endif

/*
 * Various supported device vendors/products.
 */
static struct cue_type cue_devs[] = {
	{ USB_VENDOR_CATC, USB_PRODUCT_CATC_NETMATE },
	{ USB_VENDOR_CATC, USB_PRODUCT_CATC_NETMATE2 },
	{ 0, 0 }
};

static struct usb_qdat cue_qdat;

static int cue_match		__P((device_t));
static int cue_attach		__P((device_t));
static int cue_detach		__P((device_t));

static int cue_tx_list_init	__P((struct cue_softc *));
static int cue_rx_list_init	__P((struct cue_softc *));
static int cue_newbuf		__P((struct cue_softc *, struct cue_chain *,
				    struct mbuf *));
static int cue_encap		__P((struct cue_softc *, struct mbuf *, int));
static void cue_rxeof		__P((usbd_xfer_handle,
				    usbd_private_handle, usbd_status));
static void cue_txeof		__P((usbd_xfer_handle,
				    usbd_private_handle, usbd_status));
static void cue_tick		__P((void *));
static void cue_rxstart		__P((struct ifnet *));
static void cue_start		__P((struct ifnet *));
static int cue_ioctl		__P((struct ifnet *, u_long, caddr_t));
static void cue_init		__P((void *));
static void cue_stop		__P((struct cue_softc *));
static void cue_watchdog		__P((struct ifnet *));
static void cue_shutdown		__P((device_t));

static void cue_setmulti	__P((struct cue_softc *));
static u_int32_t cue_crc	__P((caddr_t));
static void cue_reset		__P((struct cue_softc *));

static int csr_read_1		__P((struct cue_softc *, int));
static int csr_write_1		__P((struct cue_softc *, int, int));
static int csr_read_2		__P((struct cue_softc *, int));
#ifdef notdef
static int csr_write_2		__P((struct cue_softc *, int, int));
#endif
static int cue_mem		__P((struct cue_softc *, int,
				    int, void *, int));
static int cue_getmac		__P((struct cue_softc *, void *));

static device_method_t cue_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		cue_match),
	DEVMETHOD(device_attach,	cue_attach),
	DEVMETHOD(device_detach,	cue_detach),
	DEVMETHOD(device_shutdown,	cue_shutdown),

	{ 0, 0 }
};

static driver_t cue_driver = {
	"cue",
	cue_methods,
	sizeof(struct cue_softc)
};

static devclass_t cue_devclass;

DRIVER_MODULE(if_cue, uhub, cue_driver, cue_devclass, usbd_driver_load, 0);

#define CUE_SETBIT(sc, reg, x)				\
	csr_write_1(sc, reg, csr_read_1(sc, reg) | (x))

#define CUE_CLRBIT(sc, reg, x)				\
	csr_write_1(sc, reg, csr_read_1(sc, reg) & ~(x))

static int csr_read_1(sc, reg)
	struct cue_softc	*sc;
	int			reg;
{
	usb_device_request_t	req;
	usbd_status		err;
	u_int8_t		val = 0;
	int			s;

	if (sc->cue_gone)
		return(0);

	s = splusb();

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = CUE_CMD_READREG;
	USETW(req.wValue, 0);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 1);

	err = usbd_do_request_flags(sc->cue_udev,
	    &req, &val, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err)
		return(0);

	return(val);
}

static int csr_read_2(sc, reg)
	struct cue_softc	*sc;
	int			reg;
{
	usb_device_request_t	req;
	usbd_status		err;
	u_int16_t		val = 0;
	int			s;

	if (sc->cue_gone)
		return(0);

	s = splusb();

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = CUE_CMD_READREG;
	USETW(req.wValue, 0);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 2);

	err = usbd_do_request_flags(sc->cue_udev,
	    &req, &val, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err)
		return(0);

	return(val);
}

static int csr_write_1(sc, reg, val)
	struct cue_softc	*sc;
	int			reg, val;
{
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	if (sc->cue_gone)
		return(0);

	s = splusb();

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = CUE_CMD_WRITEREG;
	USETW(req.wValue, val);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 0);

	err = usbd_do_request_flags(sc->cue_udev,
	    &req, &val, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err)
		return(-1);

	return(0);
}

#ifdef notdef
static int csr_write_2(sc, reg, val)
	struct cue_softc	*sc;
	int			reg, val;
{
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	if (sc->cue_gone)
		return(0);

	s = splusb();

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = CUE_CMD_WRITEREG;
	USETW(req.wValue, val);
	USETW(req.wIndex, reg);
	USETW(req.wLength, 0);

	err = usbd_do_request_flags(sc->cue_udev,
	    &req, &val, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err)
		return(-1);

	return(0);
}
#endif

static int cue_mem(sc, cmd, addr, buf, len)
	struct cue_softc	*sc;
	int			cmd;
	int			addr;
	void			*buf;
	int			len;
{
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	if (sc->cue_gone)
		return(0);

	s = splusb();

	if (cmd == CUE_CMD_READSRAM)
		req.bmRequestType = UT_READ_VENDOR_DEVICE;
	else
		req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = cmd;
	USETW(req.wValue, 0);
	USETW(req.wIndex, addr);
	USETW(req.wLength, len);

	err = usbd_do_request_flags(sc->cue_udev,
	    &req, &buf, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err)
		return(-1);

	return(0);
}

static int cue_getmac(sc, buf)
	struct cue_softc	*sc;
	void			*buf;
{
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	if (sc->cue_gone)
		return(0);

	s = splusb();

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = CUE_CMD_GET_MACADDR;
	USETW(req.wValue, 0);
	USETW(req.wIndex, 0);
	USETW(req.wLength, ETHER_ADDR_LEN);

	err = usbd_do_request_flags(sc->cue_udev,
	    &req, buf, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err) {
		printf("cue%d: read MAC address failed\n", sc->cue_unit);
		return(-1);
	}

	return(0);
}

#define CUE_POLY	0xEDB88320
#define CUE_BITS	9

static u_int32_t cue_crc(addr)
	caddr_t			addr;
{
	u_int32_t		idx, bit, data, crc;

	/* Compute CRC for the address value. */
	crc = 0xFFFFFFFF; /* initial value */

	for (idx = 0; idx < 6; idx++) {
		for (data = *addr++, bit = 0; bit < 8; bit++, data >>= 1)
			crc = (crc >> 1) ^ (((crc ^ data) & 1) ? CUE_POLY : 0);
	}

	return (crc & ((1 << CUE_BITS) - 1));
}

static void cue_setmulti(sc)
	struct cue_softc	*sc;
{
	struct ifnet		*ifp;
	struct ifmultiaddr	*ifma;
	u_int32_t		h = 0, i;

	ifp = &sc->arpcom.ac_if;

	if (ifp->if_flags & IFF_ALLMULTI || ifp->if_flags & IFF_PROMISC) {
		for (i = 0; i < CUE_MCAST_TABLE_LEN; i++)
			sc->cue_mctab[i] = 0xFF;
			cue_mem(sc, CUE_CMD_WRITESRAM, CUE_MCAST_TABLE_ADDR,
			    &sc->cue_mctab, CUE_MCAST_TABLE_LEN);
		return;
	}

	/* first, zot all the existing hash bits */
	for (i = 0; i < CUE_MCAST_TABLE_LEN; i++)
		sc->cue_mctab[i] = 0;

	/* now program new ones */
	for (ifma = ifp->if_multiaddrs.lh_first; ifma != NULL;
	    ifma = ifma->ifma_link.le_next) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		h = cue_crc(LLADDR((struct sockaddr_dl *)ifma->ifma_addr));
		sc->cue_mctab[h >> 3] |= 1 << (h & 0x7);		
	}

	/*
	 * Also include the broadcast address in the filter
	 * so we can receive broadcast frames.
 	 */
	if (ifp->if_flags & IFF_BROADCAST) {
		h = cue_crc(etherbroadcastaddr);
		sc->cue_mctab[h >> 3] |= 1 << (h & 0x7);		
	}

	cue_mem(sc, CUE_CMD_WRITESRAM, CUE_MCAST_TABLE_ADDR,
	    &sc->cue_mctab, CUE_MCAST_TABLE_LEN);

	return;
}

static void cue_reset(sc)
	struct cue_softc	*sc;
{
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	if (sc->cue_gone)
		return;

	s = splusb();

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = CUE_CMD_RESET;
	USETW(req.wValue, 0);
	USETW(req.wIndex, 0);
	USETW(req.wLength, 0);
	err = usbd_do_request_flags(sc->cue_udev,
	    &req, NULL, USBD_NO_TSLEEP, NULL);

	splx(s);

	if (err)
		printf("cue%d: reset failed\n", sc->cue_unit);

	/* Wait a little while for the chip to get its brains in order. */
	DELAY(1000);
        return;
}

/*
 * Probe for a Pegasus chip.
 */
USB_MATCH(cue)
{
	USB_MATCH_START(cue, uaa);
	struct cue_type			*t;

	if (!uaa->iface)
		return(UMATCH_NONE);

	t = cue_devs;
	while(t->cue_vid) {
		if (uaa->vendor == t->cue_vid &&
		    uaa->product == t->cue_did) {
			return(UMATCH_VENDOR_PRODUCT);
		}
		t++;
	}

	return(UMATCH_NONE);
}

/*
 * Attach the interface. Allocate softc structures, do ifmedia
 * setup and ethernet/BPF attach.
 */
USB_ATTACH(cue)
{
	USB_ATTACH_START(cue, sc, uaa);
	char			devinfo[1024];
	int			s;
	u_char			eaddr[ETHER_ADDR_LEN];
	struct ifnet		*ifp;
	usb_interface_descriptor_t	*id;
	usb_endpoint_descriptor_t	*ed;
	int			i;

	s = splimp();

	bzero(sc, sizeof(struct cue_softc));
	sc->cue_iface = uaa->iface;
	sc->cue_udev = uaa->device;
	sc->cue_unit = device_get_unit(self);

	if (usbd_set_config_no(sc->cue_udev, CUE_CONFIG_NO, 0)) {
		printf("cue%d: getting interface handle failed\n",
		    sc->cue_unit);
		splx(s);
		USB_ATTACH_ERROR_RETURN;
	}

	id = usbd_get_interface_descriptor(uaa->iface);

	usbd_devinfo(uaa->device, 0, devinfo);
	device_set_desc_copy(self, devinfo);
	printf("%s: %s\n", USBDEVNAME(self), devinfo);

	/* Find endpoints. */
	for (i = 0; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(uaa->iface, i);
		if (!ed) {
			printf("cue%d: couldn't get ep %d\n",
			    sc->cue_unit, i);
			splx(s);
			USB_ATTACH_ERROR_RETURN;
		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			sc->cue_ed[CUE_ENDPT_RX] = ed->bEndpointAddress;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			sc->cue_ed[CUE_ENDPT_TX] = ed->bEndpointAddress;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_INTERRUPT) {
			sc->cue_ed[CUE_ENDPT_INTR] = ed->bEndpointAddress;
		}
	}

#ifdef notdef
	/* Reset the adapter. */
	cue_reset(sc);
#endif
	/*
	 * Get station address.
	 */
	cue_getmac(sc, &eaddr);

	/*
	 * A CATC chip was detected. Inform the world.
	 */
	printf("cue%d: Ethernet address: %6D\n", sc->cue_unit, eaddr, ":");

	bcopy(eaddr, (char *)&sc->arpcom.ac_enaddr, ETHER_ADDR_LEN);

	ifp = &sc->arpcom.ac_if;
	ifp->if_softc = sc;
	ifp->if_unit = sc->cue_unit;
	ifp->if_name = "cue";
	ifp->if_mtu = ETHERMTU;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = cue_ioctl;
	ifp->if_output = ether_output;
	ifp->if_start = cue_start;
	ifp->if_watchdog = cue_watchdog;
	ifp->if_init = cue_init;
	ifp->if_baudrate = 10000000;
	ifp->if_snd.ifq_maxlen = IFQ_MAXLEN;

	cue_qdat.ifp = ifp;
	cue_qdat.if_rxstart = cue_rxstart;

	/*
	 * Call MI attach routines.
	 */
	if_attach(ifp);
	ether_ifattach(ifp);
	callout_handle_init(&sc->cue_stat_ch);
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	usb_register_netisr();
	sc->cue_gone = 0;

	splx(s);
	USB_ATTACH_SUCCESS_RETURN;
}

static int cue_detach(dev)
	device_t		dev;
{
	struct cue_softc	*sc;
	struct ifnet		*ifp;
	int			s;

	s = splusb();

	sc = device_get_softc(dev);
	ifp = &sc->arpcom.ac_if;

	sc->cue_gone = 1;
	untimeout(cue_tick, sc, sc->cue_stat_ch);
	if_detach(ifp);

	if (sc->cue_ep[CUE_ENDPT_TX] != NULL)
		usbd_abort_pipe(sc->cue_ep[CUE_ENDPT_TX]);
	if (sc->cue_ep[CUE_ENDPT_RX] != NULL)
		usbd_abort_pipe(sc->cue_ep[CUE_ENDPT_RX]);
	if (sc->cue_ep[CUE_ENDPT_INTR] != NULL)
		usbd_abort_pipe(sc->cue_ep[CUE_ENDPT_INTR]);

	splx(s);

	return(0);
}

/*
 * Initialize an RX descriptor and attach an MBUF cluster.
 */
static int cue_newbuf(sc, c, m)
	struct cue_softc	*sc;
	struct cue_chain	*c;
	struct mbuf		*m;
{
	struct mbuf		*m_new = NULL;

	if (m == NULL) {
		MGETHDR(m_new, M_DONTWAIT, MT_DATA);
		if (m_new == NULL) {
			printf("cue%d: no memory for rx list "
			    "-- packet dropped!\n", sc->cue_unit);
			return(ENOBUFS);
		}

		MCLGET(m_new, M_DONTWAIT);
		if (!(m_new->m_flags & M_EXT)) {
			printf("cue%d: no memory for rx list "
			    "-- packet dropped!\n", sc->cue_unit);
			m_freem(m_new);
			return(ENOBUFS);
		}
		m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;
	} else {
		m_new = m;
		m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;
		m_new->m_data = m_new->m_ext.ext_buf;
	}

	m_adj(m_new, ETHER_ALIGN);
	c->cue_mbuf = m_new;

	return(0);
}

static int cue_rx_list_init(sc)
	struct cue_softc	*sc;
{
	struct cue_cdata	*cd;
	struct cue_chain	*c;
	int			i;

	cd = &sc->cue_cdata;
	for (i = 0; i < CUE_RX_LIST_CNT; i++) {
		c = &cd->cue_rx_chain[i];
		c->cue_sc = sc;
		c->cue_idx = i;
		c->cue_accum = 0;
		if (cue_newbuf(sc, c, NULL) == ENOBUFS)
			return(ENOBUFS);
		if (c->cue_xfer == NULL) {
			c->cue_xfer = usbd_alloc_xfer(sc->cue_udev);
			if (c->cue_xfer == NULL)
				return(ENOBUFS);
		}
	}

	return(0);
}

static int cue_tx_list_init(sc)
	struct cue_softc	*sc;
{
	struct cue_cdata	*cd;
	struct cue_chain	*c;
	int			i;

	cd = &sc->cue_cdata;
	for (i = 0; i < CUE_TX_LIST_CNT; i++) {
		c = &cd->cue_tx_chain[i];
		c->cue_sc = sc;
		c->cue_idx = i;
		c->cue_mbuf = NULL;
		if (c->cue_xfer == NULL) {
			c->cue_xfer = usbd_alloc_xfer(sc->cue_udev);
			if (c->cue_xfer == NULL)
				return(ENOBUFS);
		}
		c->cue_buf = malloc(CUE_BUFSZ, M_USBDEV, M_NOWAIT);
		if (c->cue_buf == NULL)
			return(ENOBUFS);
	}

	return(0);
}

static void cue_rxstart(ifp)
	struct ifnet		*ifp;
{
	struct cue_softc	*sc;
	struct cue_chain	*c;

	sc = ifp->if_softc;
	c = &sc->cue_cdata.cue_rx_chain[sc->cue_cdata.cue_rx_prod];

	if (cue_newbuf(sc, c, NULL) == ENOBUFS) {
		ifp->if_ierrors++;
		return;
	}

	/* Setup new transfer. */
	usbd_setup_xfer(c->cue_xfer, sc->cue_ep[CUE_ENDPT_RX],
	    c, mtod(c->cue_mbuf, char *), CUE_CUTOFF, USBD_SHORT_XFER_OK,
	    USBD_NO_TIMEOUT, cue_rxeof);
	usbd_transfer(c->cue_xfer);

	return;
}

/*
 * A frame has been uploaded: pass the resulting mbuf chain up to
 * the higher level protocols.
 */
static void cue_rxeof(xfer, priv, status)
	usbd_xfer_handle	xfer;
	usbd_private_handle	priv;
	usbd_status		status;
{
	struct cue_softc	*sc;
	struct cue_chain	*c;
        struct mbuf		*m;
        struct ifnet		*ifp;
	int			total_len = 0;
	u_int16_t		len;

	c = priv;
	sc = c->cue_sc;
	ifp = &sc->arpcom.ac_if;

	if (!(ifp->if_flags & IFF_RUNNING))
		return;

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED)
			return;
		printf("cue%d: usb error on rx: %s\n", sc->cue_unit,
		    usbd_errstr(status));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall(sc->cue_ep[CUE_ENDPT_RX]);
		goto done;
	}

	usbd_get_xfer_status(xfer, NULL, NULL, &total_len, NULL);

	/*
	 * See if we've already accumulated some data from
	 * a previous transfer.
	 */
	if (c->cue_accum) {
		total_len += c->cue_accum;
		c->cue_accum = 0;
	}

	m = c->cue_mbuf;
	len = *mtod(m, u_int16_t *);

	/*
	 * Check to see if this is just the first chunk of a
	 * split transfer. We really need a more reliable way
	 * to detect this.
	 */
	if (len != total_len && total_len == CUE_CUTOFF) {
		c->cue_accum = CUE_CUTOFF;
		usbd_setup_xfer(xfer, sc->cue_ep[CUE_ENDPT_RX],
		    c, mtod(c->cue_mbuf, char *) + CUE_CUTOFF,
		    CUE_CUTOFF, USBD_SHORT_XFER_OK,
		    USBD_NO_TIMEOUT, cue_rxeof);
		usbd_transfer(xfer);
		return;
	}

	/* No errors; receive the packet. */
	total_len = len;

	if (len < sizeof(struct ether_header)) {
		ifp->if_ierrors++;
		goto done;
	}

	ifp->if_ipackets++;
	m_adj(m, sizeof(u_int16_t));
	m->m_pkthdr.rcvif = (struct ifnet *)&cue_qdat;
	m->m_pkthdr.len = m->m_len = total_len;

	/* Put the packet on the special USB input queue. */
	usb_ether_input(m);

	return;
done:
	/* Setup new transfer. */
	usbd_setup_xfer(c->cue_xfer, sc->cue_ep[CUE_ENDPT_RX],
	    c, mtod(c->cue_mbuf, char *), CUE_CUTOFF, USBD_SHORT_XFER_OK,
	    USBD_NO_TIMEOUT, cue_rxeof);
	usbd_transfer(c->cue_xfer);

	return;
}

/*
 * A frame was downloaded to the chip. It's safe for us to clean up
 * the list buffers.
 */

static void cue_txeof(xfer, priv, status)
	usbd_xfer_handle	xfer;
	usbd_private_handle	priv;
	usbd_status		status;
{
	struct cue_softc	*sc;
	struct cue_chain	*c;
	struct ifnet		*ifp;
	usbd_status		err;
	int			s;

	s = splimp();

	c = priv;
	sc = c->cue_sc;
	ifp = &sc->arpcom.ac_if;

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED) {
			splx(s);
			return;
		}
		printf("cue%d: usb error on tx: %s\n", sc->cue_unit,
		    usbd_errstr(status));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall(sc->cue_ep[CUE_ENDPT_TX]);
		splx(s);
		return;
	}

	ifp->if_timer = 0;
	ifp->if_flags &= ~IFF_OACTIVE;
	usbd_get_xfer_status(c->cue_xfer, NULL, NULL, NULL, &err);

	c->cue_mbuf->m_pkthdr.rcvif = ifp;
	usb_tx_done(c->cue_mbuf);
	c->cue_mbuf = NULL;

	if (err)
		ifp->if_oerrors++;
	else
		ifp->if_opackets++;

	splx(s);

	return;
}

static void cue_tick(xsc)
	void			*xsc;
{
	struct cue_softc	*sc;
	struct ifnet		*ifp;
	int			s;

	s = splimp();

	sc = xsc;

	if (sc == NULL) {
		splx(s);
		return;
	}

	ifp = &sc->arpcom.ac_if;

	ifp->if_collisions += csr_read_2(sc, CUE_TX_SINGLECOLL);
	ifp->if_collisions += csr_read_2(sc, CUE_TX_MULTICOLL);
	ifp->if_collisions += csr_read_2(sc, CUE_TX_EXCESSCOLL);

	if (csr_read_2(sc, CUE_RX_FRAMEERR))
		ifp->if_ierrors++;

	sc->cue_stat_ch = timeout(cue_tick, sc, hz);

	splx(s);

	return;
}

static int cue_encap(sc, m, idx)
	struct cue_softc	*sc;
	struct mbuf		*m;
	int			idx;
{
	int			total_len;
	struct cue_chain	*c;
	usbd_status		err;

	c = &sc->cue_cdata.cue_tx_chain[idx];

	/*
	 * Copy the mbuf data into a contiguous buffer, leaving two
	 * bytes at the beginning to hold the frame length.
	 */
	m_copydata(m, 0, m->m_pkthdr.len, c->cue_buf + 2);
	c->cue_mbuf = m;

	total_len = m->m_pkthdr.len + 2;

	/* The first two bytes are the frame length */
	c->cue_buf[0] = (u_int8_t)m->m_pkthdr.len;
	c->cue_buf[1] = (u_int8_t)(m->m_pkthdr.len >> 8);

	usbd_setup_xfer(c->cue_xfer, sc->cue_ep[CUE_ENDPT_TX],
	    c, c->cue_buf, total_len, 0, 10000, cue_txeof);

	/* Transmit */
	err = usbd_transfer(c->cue_xfer);
	if (err != USBD_IN_PROGRESS) {
		cue_stop(sc);
		return(EIO);
	}

	sc->cue_cdata.cue_tx_cnt++;

	return(0);
}

static void cue_start(ifp)
	struct ifnet		*ifp;
{
	struct cue_softc	*sc;
	struct mbuf		*m_head = NULL;

	sc = ifp->if_softc;

	if (ifp->if_flags & IFF_OACTIVE)
		return;

	IF_DEQUEUE(&ifp->if_snd, m_head);
	if (m_head == NULL)
		return;

	if (cue_encap(sc, m_head, 0)) {
		IF_PREPEND(&ifp->if_snd, m_head);
		ifp->if_flags |= IFF_OACTIVE;
		return;
	}

	/*
	 * If there's a BPF listener, bounce a copy of this frame
	 * to him.
	 */
	if (ifp->if_bpf)
		bpf_mtap(ifp, m_head);

	ifp->if_flags |= IFF_OACTIVE;

	/*
	 * Set a timeout in case the chip goes out to lunch.
	 */
	ifp->if_timer = 5;

	return;
}

static void cue_init(xsc)
	void			*xsc;
{
	struct cue_softc	*sc = xsc;
	struct ifnet		*ifp = &sc->arpcom.ac_if;
	struct cue_chain	*c;
	usbd_status		err;
	int			i, s;

	if (ifp->if_flags & IFF_RUNNING)
		return;

	s = splimp();

	/*
	 * Cancel pending I/O and free all RX/TX buffers.
	 */
#ifdef foo
	cue_reset(sc);
#endif

	/* Set MAC address */
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		csr_write_1(sc, CUE_PAR0 - i, sc->arpcom.ac_enaddr[i]);

	/* Enable RX logic. */
	csr_write_1(sc, CUE_ETHCTL, CUE_ETHCTL_RX_ON|CUE_ETHCTL_MCAST_ON);

	 /* If we want promiscuous mode, set the allframes bit. */
	if (ifp->if_flags & IFF_PROMISC) {
		CUE_SETBIT(sc, CUE_ETHCTL, CUE_ETHCTL_PROMISC);
	} else {
		CUE_CLRBIT(sc, CUE_ETHCTL, CUE_ETHCTL_PROMISC);
	}

	/* Init TX ring. */
	if (cue_tx_list_init(sc) == ENOBUFS) {
		printf("cue%d: tx list init failed\n", sc->cue_unit);
		splx(s);
		return;
	}

	/* Init RX ring. */
	if (cue_rx_list_init(sc) == ENOBUFS) {
		printf("cue%d: rx list init failed\n", sc->cue_unit);
		splx(s);
		return;
	}

	/* Load the multicast filter. */
	cue_setmulti(sc);

	/*
	 * Set the number of RX and TX buffers that we want
	 * to reserve inside the ASIC.
	 */
	csr_write_1(sc, CUE_RX_BUFPKTS, CUE_RX_FRAMES);
	csr_write_1(sc, CUE_TX_BUFPKTS, CUE_TX_FRAMES);

	/* Set advanced operation modes. */
	csr_write_1(sc, CUE_ADVANCED_OPMODES,
	    CUE_AOP_EMBED_RXLEN|0x01); /* 1 wait state */

	/* Program the LED operation. */
	csr_write_1(sc, CUE_LEDCTL, CUE_LEDCTL_FOLLOW_LINK);

	/* Open RX and TX pipes. */
	err = usbd_open_pipe(sc->cue_iface, sc->cue_ed[CUE_ENDPT_RX],
	    USBD_EXCLUSIVE_USE, &sc->cue_ep[CUE_ENDPT_RX]);
	if (err) {
		printf("cue%d: open rx pipe failed: %s\n",
		    sc->cue_unit, usbd_errstr(err));
		splx(s);
		return;
	}
	err = usbd_open_pipe(sc->cue_iface, sc->cue_ed[CUE_ENDPT_TX],
	    USBD_EXCLUSIVE_USE, &sc->cue_ep[CUE_ENDPT_TX]);
	if (err) {
		printf("cue%d: open tx pipe failed: %s\n",
		    sc->cue_unit, usbd_errstr(err));
		splx(s);
		return;
	}

	/* Start up the receive pipe. */
	for (i = 0; i < CUE_RX_LIST_CNT; i++) {
		c = &sc->cue_cdata.cue_rx_chain[i];
		usbd_setup_xfer(c->cue_xfer, sc->cue_ep[CUE_ENDPT_RX],
		    c, mtod(c->cue_mbuf, char *), CUE_CUTOFF,
		    USBD_SHORT_XFER_OK, USBD_NO_TIMEOUT, cue_rxeof);
		usbd_transfer(c->cue_xfer);
	}

	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	(void)splx(s);

	sc->cue_stat_ch = timeout(cue_tick, sc, hz);

	return;
}

static int cue_ioctl(ifp, command, data)
	struct ifnet		*ifp;
	u_long			command;
	caddr_t			data;
{
	struct cue_softc	*sc = ifp->if_softc;
	int			s, error = 0;

	s = splimp();

	switch(command) {
	case SIOCSIFADDR:
	case SIOCGIFADDR:
	case SIOCSIFMTU:
		error = ether_ioctl(ifp, command, data);
		break;
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_flags & IFF_RUNNING &&
			    ifp->if_flags & IFF_PROMISC &&
			    !(sc->cue_if_flags & IFF_PROMISC)) {
				CUE_SETBIT(sc, CUE_ETHCTL, CUE_ETHCTL_PROMISC);
				cue_setmulti(sc);
			} else if (ifp->if_flags & IFF_RUNNING &&
			    !(ifp->if_flags & IFF_PROMISC) &&
			    sc->cue_if_flags & IFF_PROMISC) {
				CUE_CLRBIT(sc, CUE_ETHCTL, CUE_ETHCTL_PROMISC);
				cue_setmulti(sc);
			} else if (!(ifp->if_flags & IFF_RUNNING))
				cue_init(sc);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				cue_stop(sc);
		}
		sc->cue_if_flags = ifp->if_flags;
		error = 0;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		cue_setmulti(sc);
		error = 0;
		break;
	default:
		error = EINVAL;
		break;
	}

	(void)splx(s);

	return(error);
}

static void cue_watchdog(ifp)
	struct ifnet		*ifp;
{
	struct cue_softc	*sc;

	sc = ifp->if_softc;

	ifp->if_oerrors++;
	printf("cue%d: watchdog timeout\n", sc->cue_unit);

	cue_init(sc);

	if (ifp->if_snd.ifq_head != NULL)
		cue_start(ifp);

	return;
}

/*
 * Stop the adapter and free any mbufs allocated to the
 * RX and TX lists.
 */
static void cue_stop(sc)
	struct cue_softc	*sc;
{
	usbd_status		err;
	struct ifnet		*ifp;
	int			i;

	ifp = &sc->arpcom.ac_if;
	ifp->if_timer = 0;

	csr_write_1(sc, CUE_ETHCTL, 0);
	cue_reset(sc);
	untimeout(cue_tick, sc, sc->cue_stat_ch);

	/* Stop transfers. */
	if (sc->cue_ep[CUE_ENDPT_RX] != NULL) {
		err = usbd_abort_pipe(sc->cue_ep[CUE_ENDPT_RX]);
		if (err) {
			printf("cue%d: abort rx pipe failed: %s\n",
		    	sc->cue_unit, usbd_errstr(err));
		}
		err = usbd_close_pipe(sc->cue_ep[CUE_ENDPT_RX]);
		if (err) {
			printf("cue%d: close rx pipe failed: %s\n",
		    	sc->cue_unit, usbd_errstr(err));
		}
		sc->cue_ep[CUE_ENDPT_RX] = NULL;
	}

	if (sc->cue_ep[CUE_ENDPT_TX] != NULL) {
		err = usbd_abort_pipe(sc->cue_ep[CUE_ENDPT_TX]);
		if (err) {
			printf("cue%d: abort tx pipe failed: %s\n",
		    	sc->cue_unit, usbd_errstr(err));
		}
		err = usbd_close_pipe(sc->cue_ep[CUE_ENDPT_TX]);
		if (err) {
			printf("cue%d: close tx pipe failed: %s\n",
			    sc->cue_unit, usbd_errstr(err));
		}
		sc->cue_ep[CUE_ENDPT_TX] = NULL;
	}

	if (sc->cue_ep[CUE_ENDPT_INTR] != NULL) {
		err = usbd_abort_pipe(sc->cue_ep[CUE_ENDPT_INTR]);
		if (err) {
			printf("cue%d: abort intr pipe failed: %s\n",
		    	sc->cue_unit, usbd_errstr(err));
		}
		err = usbd_close_pipe(sc->cue_ep[CUE_ENDPT_INTR]);
		if (err) {
			printf("cue%d: close intr pipe failed: %s\n",
			    sc->cue_unit, usbd_errstr(err));
		}
		sc->cue_ep[CUE_ENDPT_INTR] = NULL;
	}

	/* Free RX resources. */
	for (i = 0; i < CUE_RX_LIST_CNT; i++) {
		if (sc->cue_cdata.cue_rx_chain[i].cue_buf != NULL) {
			free(sc->cue_cdata.cue_rx_chain[i].cue_buf, M_USBDEV);
			sc->cue_cdata.cue_rx_chain[i].cue_buf = NULL;
		}
		if (sc->cue_cdata.cue_rx_chain[i].cue_mbuf != NULL) {
			m_freem(sc->cue_cdata.cue_rx_chain[i].cue_mbuf);
			sc->cue_cdata.cue_rx_chain[i].cue_mbuf = NULL;
		}
		if (sc->cue_cdata.cue_rx_chain[i].cue_xfer != NULL) {
			usbd_free_xfer(sc->cue_cdata.cue_rx_chain[i].cue_xfer);
			sc->cue_cdata.cue_rx_chain[i].cue_xfer = NULL;
		}
	}

	/* Free TX resources. */
	for (i = 0; i < CUE_TX_LIST_CNT; i++) {
		if (sc->cue_cdata.cue_tx_chain[i].cue_buf != NULL) {
			free(sc->cue_cdata.cue_tx_chain[i].cue_buf, M_USBDEV);
			sc->cue_cdata.cue_tx_chain[i].cue_buf = NULL;
		}
		if (sc->cue_cdata.cue_tx_chain[i].cue_mbuf != NULL) {
			m_freem(sc->cue_cdata.cue_tx_chain[i].cue_mbuf);
			sc->cue_cdata.cue_tx_chain[i].cue_mbuf = NULL;
		}
		if (sc->cue_cdata.cue_tx_chain[i].cue_xfer != NULL) {
			usbd_free_xfer(sc->cue_cdata.cue_tx_chain[i].cue_xfer);
			sc->cue_cdata.cue_tx_chain[i].cue_xfer = NULL;
		}
	}

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);

	return;
}

/*
 * Stop all chip I/O so that the kernel's probe routines don't
 * get confused by errant DMAs when rebooting.
 */
static void cue_shutdown(dev)
	device_t		dev;
{
	struct cue_softc	*sc;

	sc = device_get_softc(dev);

	cue_reset(sc);
	cue_stop(sc);

	return;
}
