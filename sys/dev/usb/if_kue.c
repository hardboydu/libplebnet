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
 * Kawasaki LSI KL5KUSB101B USB to ethernet adapter driver.
 *
 * Written by Bill Paul <wpaul@ee.columbia.edu>
 * Electrical Engineering Department
 * Columbia University, New York City
 */

/*
 * The KLSI USB to ethernet adapter chip contains an USB serial interface,
 * ethernet MAC and embedded microcontroller (called the QT Engine).
 * The chip must have firmware loaded into it before it will operate.
 * Packets are passed between the chip and host via bulk transfers.
 * There is an interrupt endpoint mentioned in the software spec, however
 * it's currently unused. This device is 10Mbps half-duplex only, hence
 * there is no media selection logic. The MAC supports a 128 entry
 * multicast filter, though the exact size of the filter can depend
 * on the firmware. Curiously, while the software spec describes various
 * ethernet statistics counters, my sample adapter and firmware combination
 * claims not to support any statistics counters at all.
 *
 * Note that once we load the firmware in the device, we have to be
 * careful not to load it again: if you restart your computer but
 * leave the adapter attached to the USB controller, it may remain
 * powered on and retain its firmware. In this case, we don't need
 * to load the firmware a second time.
 *
 * Special thanks to Rob Furr for providing an ADS Technologies
 * adapter for development and testing. No monkeys were harmed during
 * the development of this driver.
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
#include <net/if_media.h>

#include <net/bpf.h>

#include <machine/clock.h>      /* for DELAY */
#include <sys/bus.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usb_quirks.h>
#include <dev/usb/usb_ethersubr.h>

#include <dev/usb/if_kuereg.h>
#include <dev/usb/kue_fw.h>

#ifndef lint
static const char rcsid[] =
  "$FreeBSD$";
#endif

/*
 * Various supported device vendors/types and their names.
 */
static struct kue_type kue_devs[] = {
	{ USB_VENDOR_AOX, USB_PRODUCT_AOX_USB101,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_ADS, USB_PRODUCT_ADS_ENET,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_ATEN, USB_PRODUCT_ATEN_UC10T,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_NETGEAR, USB_PRODUCT_NETGEAR_EA101,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_PERACOM, USB_PRODUCT_PERACOM_ENET,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_PERACOM, USB_PRODUCT_PERACOM_ENET2,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_ENTREGA, USB_PRODUCT_ENTREGA_E45,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_3COM, USB_PRODUCT_3COM_3C19250,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_DLINK, USB_PRODUCT_DLINK_DSB650C,
	    "KLSI USB ethernet" },
	{ USB_VENDOR_SMC, USB_PRODUCT_SMC_2102USB,
	    "KLSI USB ethernet" },
	{ 0, 0, NULL }
};

static int kue_match		__P((device_t));
static int kue_attach		__P((device_t));
static int kue_detach		__P((device_t));
static void kue_shutdown		__P((device_t));
static int kue_tx_list_init	__P((struct kue_softc *));
static int kue_rx_list_init	__P((struct kue_softc *));
static int kue_newbuf		__P((struct kue_softc *, struct kue_chain *,
				    struct mbuf *));
static int kue_encap		__P((struct kue_softc *, struct mbuf *, int));
static void kue_rxeof		__P((usbd_xfer_handle,
				    usbd_private_handle, usbd_status));
static void kue_txeof		__P((usbd_xfer_handle,
				    usbd_private_handle, usbd_status));
static void kue_start		__P((struct ifnet *));
static int kue_ioctl		__P((struct ifnet *, u_long, caddr_t));
static void kue_init		__P((void *));
static void kue_stop		__P((struct kue_softc *));
static void kue_watchdog		__P((struct ifnet *));

static void kue_setmulti	__P((struct kue_softc *));
static void kue_reset		__P((struct kue_softc *));

static usbd_status kue_do_request
				__P((usbd_device_handle,
				    usb_device_request_t *, void *));
static usbd_status kue_ctl	__P((struct kue_softc *, int, u_int8_t,
				    u_int16_t, char *, int));
static usbd_status kue_setword	__P((struct kue_softc *, u_int8_t, u_int16_t));
static int kue_load_fw		__P((struct kue_softc *));

static device_method_t kue_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		kue_match),
	DEVMETHOD(device_attach,	kue_attach),
	DEVMETHOD(device_detach,	kue_detach),
	DEVMETHOD(device_shutdown,	kue_shutdown),

	{ 0, 0 }
};

static driver_t kue_driver = {
	"kue",
	kue_methods,
	sizeof(struct kue_softc)
};

static devclass_t kue_devclass;

DRIVER_MODULE(if_kue, uhub, kue_driver, kue_devclass, usbd_driver_load, 0);

/*
 * We have a custom do_request function which is almost like the
 * regular do_request function, except it has a much longer timeout.
 * Why? Because we need to make requests over the control endpoint
 * to download the firmware to the device, which can take longer
 * than the default timeout.
 */
static usbd_status kue_do_request(dev, req, data)
	usbd_device_handle	dev;
	usb_device_request_t	*req;
	void			*data;
{
	usbd_xfer_handle	xfer;
	usbd_status		err;

	xfer = usbd_alloc_xfer(dev);
	usbd_setup_default_xfer(xfer, dev, 0, 500000, req,
	    data, UGETW(req->wLength), USBD_SHORT_XFER_OK, 0);
	err = usbd_sync_transfer(xfer);
	usbd_free_xfer(xfer);
	return(err);
}

static usbd_status kue_setword(sc, breq, word)
	struct kue_softc	*sc;
	u_int8_t		breq;
	u_int16_t		word;
{
	usbd_device_handle	dev;
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	dev = sc->kue_udev;

	s = splusb();

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;

	req.bRequest = breq;
	USETW(req.wValue, word);
	USETW(req.wIndex, 0);
	USETW(req.wLength, 0);

	err = kue_do_request(dev, &req, NULL);

	splx(s);

	return(err);
}

static usbd_status kue_ctl(sc, rw, breq, val, data, len)
	struct kue_softc	*sc;
	int			rw;
	u_int8_t		breq;
	u_int16_t		val;
	char			*data;
	int			len;
{
	usbd_device_handle	dev;
	usb_device_request_t	req;
	usbd_status		err;
	int			s;

	dev = sc->kue_udev;

	s = splusb();

	if (rw == KUE_CTL_WRITE)
		req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	else
		req.bmRequestType = UT_READ_VENDOR_DEVICE;

	req.bRequest = breq;
	USETW(req.wValue, val);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);

	err = kue_do_request(dev, &req, data);

	splx(s);

	return(err);
}

static int kue_load_fw(sc)
	struct kue_softc	*sc;
{
	usbd_status		err;
	u_int8_t		eaddr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	/*
	 * First, check if we even need to load the firmware.
	 * If the device was still attached when the system was
	 * rebooted, it may already have firmware loaded in it.
	 * If this is the case, we don't need to do it again.
	 * And in fact, if we try to load it again, we'll hang,
	 * so we have to avoid this condition if we don't want
	 * to look stupid.
	 *
	 * We can test this quickly by trying to read the MAC
	 * address; if this fails to return any data, the firmware
	 * needs to be reloaded, otherwise the device is already
	 * operational and we can just return.
	 */
	err = kue_ctl(sc, KUE_CTL_READ, KUE_CMD_GET_MAC,
	    0, (char *)&eaddr, ETHER_ADDR_LEN);

	if (bcmp(eaddr, etherbroadcastaddr, ETHER_ADDR_LEN))
		return(USBD_NORMAL_COMPLETION);

	/* Load code segment */
	err = kue_ctl(sc, KUE_CTL_WRITE, KUE_CMD_SEND_SCAN,
	    0, kue_code_seg, sizeof(kue_code_seg));
	if (err) {
		printf("kue%d: failed to load code segment: %s\n",
		    sc->kue_unit, usbd_errstr(err));
			return(ENXIO);
	}

	/* Load fixup segment */
	err = kue_ctl(sc, KUE_CTL_WRITE, KUE_CMD_SEND_SCAN,
	    0, kue_fix_seg, sizeof(kue_fix_seg));
	if (err) {
		printf("kue%d: failed to load fixup segment: %s\n",
		    sc->kue_unit, usbd_errstr(err));
			return(ENXIO);
	}

	/* Send trigger command. */
	err = kue_ctl(sc, KUE_CTL_WRITE, KUE_CMD_SEND_SCAN,
	    0, kue_trig_seg, sizeof(kue_trig_seg));
	if (err) {
		printf("kue%d: failed to load trigger segment: %s\n",
		    sc->kue_unit, usbd_errstr(err));
			return(ENXIO);
	}

	return(0);
}

static void kue_setmulti(sc)
	struct kue_softc	*sc;
{
	struct ifnet		*ifp;
	struct ifmultiaddr	*ifma;
	int			i = 0;

	ifp = &sc->arpcom.ac_if;

	if (ifp->if_flags & IFF_ALLMULTI || ifp->if_flags & IFF_PROMISC) {
		sc->kue_rxfilt |= KUE_RXFILT_ALLMULTI;
		sc->kue_rxfilt &= ~KUE_RXFILT_MULTICAST;
		kue_setword(sc, KUE_CMD_SET_PKT_FILTER, sc->kue_rxfilt);
		return;
	}

	sc->kue_rxfilt &= ~KUE_RXFILT_ALLMULTI;

	for (ifma = ifp->if_multiaddrs.lh_first; ifma != NULL;
	    ifma = ifma->ifma_link.le_next) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		/*
		 * If there are too many addresses for the
		 * internal filter, switch over to allmulti mode.
		 */
		if (i == KUE_MCFILTCNT(sc)) {
			i = 0;
			break;
		}
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    KUE_MCFILT(sc, i), ETHER_ADDR_LEN);
		i++;
	}

	if (i) {
		sc->kue_rxfilt |= KUE_RXFILT_MULTICAST;
		kue_ctl(sc, KUE_CTL_WRITE, KUE_CMD_SET_MCAST_FILTERS,
		    i, sc->kue_mcfilters, i * ETHER_ADDR_LEN);
	} else
		sc->kue_rxfilt |= KUE_RXFILT_ALLMULTI;

	kue_setword(sc, KUE_CMD_SET_PKT_FILTER, sc->kue_rxfilt);

	return;
}

/*
 * Issue a SET_CONFIGURATION command to reset the MAC. This should be
 * done after the firmware is loaded into the adapter in order to
 * bring it into proper operation.
 */
static void kue_reset(sc)
	struct kue_softc	*sc;
{
	usbd_set_config_no(sc->kue_udev, 1, 0);
	/* Wait a little while for the chip to get its brains in order. */
	DELAY(1000);
        return;
}

/*
 * Probe for a KLSI chip.
 */
USB_MATCH(kue)
{
	USB_MATCH_START(kue, uaa);
	struct kue_type			*t;
	usb_device_descriptor_t		*dd;

	if (!uaa->iface)
		return(UMATCH_NONE);

	dd = &uaa->device->ddesc;

	t = kue_devs;
	while(t->kue_name != NULL) {
		if (uaa->vendor == t->kue_vid &&
		    uaa->product == t->kue_did) {
			/*
			 * Force the revision code and then rescan the
			 * quirks so that we get the right quirk bits set.
			 * Why? The chip without the firmware loaded returns
			 * one revision code. The chip with the firmware
			 * loaded and running returns a *different* revision
			 * code. This confuses the quirk mechanism, which is
			 * dependent on the revision data.
			 */
			USETW(dd->bcdDevice, 0x002);
			uaa->device->quirks = usbd_find_quirk(dd);
			device_set_desc(self, t->kue_name);
			return(UMATCH_VENDOR_PRODUCT);
		}
		t++;
	}

	return(UMATCH_NONE);
}

/*
 * Attach the interface. Allocate softc structures, do
 * setup and ethernet/BPF attach.
 */
USB_ATTACH(kue)
{
	USB_ATTACH_START(kue, sc, uaa);
	char			devinfo[1024];
	int			s;
	struct ifnet		*ifp;
	usbd_status		err;
	usb_interface_descriptor_t	*id;
	usb_endpoint_descriptor_t	*ed;
	int			i;

	s = splimp();

	bzero(sc, sizeof(struct kue_softc));
	sc->kue_iface = uaa->iface;
	sc->kue_udev = uaa->device;
	sc->kue_unit = device_get_unit(self);

	id = usbd_get_interface_descriptor(uaa->iface);

	usbd_devinfo(uaa->device, 0, devinfo);
	device_set_desc_copy(self, devinfo);
	printf("%s: %s\n", USBDEVNAME(self), devinfo);

	/* Find endpoints. */
	for (i = 0; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(uaa->iface, i);
		if (!ed) {
			printf("kue%d: couldn't get ep %d\n",
			    sc->kue_unit, i);
			splx(s);
			USB_ATTACH_ERROR_RETURN;
		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			sc->kue_ed[KUE_ENDPT_RX] = ed->bEndpointAddress;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			sc->kue_ed[KUE_ENDPT_TX] = ed->bEndpointAddress;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_INTERRUPT) {
			sc->kue_ed[KUE_ENDPT_INTR] = ed->bEndpointAddress;
		}
	}

	/* Load the firmware into the NIC. */
	if (kue_load_fw(sc)) {
		splx(s);
		USB_ATTACH_ERROR_RETURN;
	}

	/* Reset the adapter. */
	kue_reset(sc);

	/* Read ethernet descriptor */
	err = kue_ctl(sc, KUE_CTL_READ, KUE_CMD_GET_ETHER_DESCRIPTOR,
	    0, (char *)&sc->kue_desc, sizeof(sc->kue_desc));

	sc->kue_mcfilters = malloc(KUE_MCFILTCNT(sc) * ETHER_ADDR_LEN,
	    M_USBDEV, M_NOWAIT);

	/*
	 * A KLSI chip was detected. Inform the world.
	 */
	printf("kue%d: Ethernet address: %6D\n", sc->kue_unit,
	    sc->kue_desc.kue_macaddr, ":");

	bcopy(sc->kue_desc.kue_macaddr,
	    (char *)&sc->arpcom.ac_enaddr, ETHER_ADDR_LEN);

	ifp = &sc->arpcom.ac_if;
	ifp->if_softc = sc;
	ifp->if_unit = sc->kue_unit;
	ifp->if_name = "kue";
	ifp->if_mtu = ETHERMTU;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = kue_ioctl;
	ifp->if_output = ether_output;
	ifp->if_start = kue_start;
	ifp->if_watchdog = kue_watchdog;
	ifp->if_init = kue_init;
	ifp->if_baudrate = 10000000;
	ifp->if_snd.ifq_maxlen = IFQ_MAXLEN;

	/*
	 * Call MI attach routines.
	 */
	if_attach(ifp);
	ether_ifattach(ifp);
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	usb_register_netisr();

	splx(s);
	USB_ATTACH_SUCCESS_RETURN;
}

static int kue_detach(dev)
	device_t		dev;
{
	struct kue_softc	*sc;
	struct ifnet		*ifp;
	int			s;

	s = splusb();

	sc = device_get_softc(dev);
	ifp = &sc->arpcom.ac_if;

	if (ifp != NULL)
		if_detach(ifp);

	if (sc->kue_ep[KUE_ENDPT_TX] != NULL)
		usbd_abort_pipe(sc->kue_ep[KUE_ENDPT_TX]);
	if (sc->kue_ep[KUE_ENDPT_RX] != NULL)
		usbd_abort_pipe(sc->kue_ep[KUE_ENDPT_RX]);
	if (sc->kue_ep[KUE_ENDPT_INTR] != NULL)
		usbd_abort_pipe(sc->kue_ep[KUE_ENDPT_INTR]);

	if (sc->kue_mcfilters != NULL)
		free(sc->kue_mcfilters, M_USBDEV);

	splx(s);

	return(0);
}

/*
 * Initialize an RX descriptor and attach an MBUF cluster.
 */
static int kue_newbuf(sc, c, m)
	struct kue_softc	*sc;
	struct kue_chain	*c;
	struct mbuf		*m;
{
	struct mbuf		*m_new = NULL;

	if (m == NULL) {
		MGETHDR(m_new, M_DONTWAIT, MT_DATA);
		if (m_new == NULL) {
			printf("kue%d: no memory for rx list "
			    "-- packet dropped!\n", sc->kue_unit);
			return(ENOBUFS);
		}

		MCLGET(m_new, M_DONTWAIT);
		if (!(m_new->m_flags & M_EXT)) {
			printf("kue%d: no memory for rx list "
			    "-- packet dropped!\n", sc->kue_unit);
			m_freem(m_new);
			return(ENOBUFS);
		}
		m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;
	} else {
		m_new = m;
		m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;
		m_new->m_data = m_new->m_ext.ext_buf;
	}

	c->kue_mbuf = m_new;

	return(0);
}

static int kue_rx_list_init(sc)
	struct kue_softc	*sc;
{
	struct kue_cdata	*cd;
	struct kue_chain	*c;
	int			i;

	cd = &sc->kue_cdata;
	for (i = 0; i < KUE_RX_LIST_CNT; i++) {
		c = &cd->kue_rx_chain[i];
		c->kue_sc = sc;
		c->kue_idx = i;
		if (kue_newbuf(sc, c, NULL) == ENOBUFS)
			return(ENOBUFS);
		if (c->kue_xfer == NULL) {
			c->kue_xfer = usbd_alloc_xfer(sc->kue_udev);
			if (c->kue_xfer == NULL)
				return(ENOBUFS);
		}
	}

	return(0);
}

static int kue_tx_list_init(sc)
	struct kue_softc	*sc;
{
	struct kue_cdata	*cd;
	struct kue_chain	*c;
	int			i;

	cd = &sc->kue_cdata;
	for (i = 0; i < KUE_TX_LIST_CNT; i++) {
		c = &cd->kue_tx_chain[i];
		c->kue_sc = sc;
		c->kue_idx = i;
		c->kue_mbuf = NULL;
		if (c->kue_xfer == NULL) {
			c->kue_xfer = usbd_alloc_xfer(sc->kue_udev);
			if (c->kue_xfer == NULL)
				return(ENOBUFS);
		}
		c->kue_buf = malloc(KUE_BUFSZ, M_USBDEV, M_NOWAIT);
		if (c->kue_buf == NULL)
			return(ENOBUFS);
	}

	return(0);
}

/*
 * A frame has been uploaded: pass the resulting mbuf chain up to
 * the higher level protocols.
 */
static void kue_rxeof(xfer, priv, status)
	usbd_xfer_handle	xfer;
	usbd_private_handle	priv;
	usbd_status		status;
{
	struct kue_softc	*sc;
	struct kue_chain	*c;
        struct ether_header	*eh;
        struct mbuf		*m;
        struct ifnet		*ifp;
	int			total_len = 0;
	u_int16_t		len;

	c = priv;
	sc = c->kue_sc;
	ifp = &sc->arpcom.ac_if;

	if (!(ifp->if_flags & IFF_RUNNING))
		return;

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED)
			return;
		printf("kue%d: usb error on rx: %s\n", sc->kue_unit,
		    usbd_errstr(status));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall(sc->kue_ep[KUE_ENDPT_RX]);
		goto done;
	}

	usbd_get_xfer_status(xfer, NULL, NULL, &total_len, NULL);
	m = c->kue_mbuf;
	if (total_len == 1)
		goto done;

	len = *mtod(m, u_int16_t *);
	m_adj(m, sizeof(u_int16_t));

	/* No errors; receive the packet. */
	total_len = len;
	if (kue_newbuf(sc, c, NULL) == ENOBUFS) {
		ifp->if_ierrors++;
		goto done;
	}

	ifp->if_ipackets++;
	eh = mtod(m, struct ether_header *);
	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = m->m_len = total_len;

	/*
	 * Handle BPF listeners. Let the BPF user see the packet, but
	 * don't pass it up to the ether_input() layer unless it's
	 * a broadcast packet, multicast packet, matches our ethernet
	 * address or the interface is in promiscuous mode.
	 */
	if (ifp->if_bpf) {
		bpf_mtap(ifp, m);
		if (ifp->if_flags & IFF_PROMISC &&
		    (bcmp(eh->ether_dhost, sc->arpcom.ac_enaddr,
		    ETHER_ADDR_LEN) && !(eh->ether_dhost[0] & 1))) {
			m_freem(m);
			goto done;
		}
	}

	/* Put the packet on the special USB input queue. */
	usb_ether_input(m);

done:

	/* Setup new transfer. */
	usbd_setup_xfer(xfer, sc->kue_ep[KUE_ENDPT_RX],
	    c, mtod(c->kue_mbuf, char *), KUE_BUFSZ, USBD_SHORT_XFER_OK,
	    USBD_NO_TIMEOUT, kue_rxeof);
	usbd_transfer(xfer);

	return;
}

/*
 * A frame was downloaded to the chip. It's safe for us to clean up
 * the list buffers.
 */

static void kue_txeof(xfer, priv, status)
	usbd_xfer_handle	xfer;
	usbd_private_handle	priv;
	usbd_status		status;
{
	struct kue_softc	*sc;
	struct kue_chain	*c;
	struct ifnet		*ifp;
	usbd_status		err;
	int			s;

	s = splimp();

	c = priv;
	sc = c->kue_sc;
	ifp = &sc->arpcom.ac_if;
	ifp->if_timer = 0;
	ifp->if_flags &= ~IFF_OACTIVE;

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED) {
			splx(s);
			return;
		}
		printf("kue%d: usb error on tx: %s\n", sc->kue_unit,
		    usbd_errstr(status));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall(sc->kue_ep[KUE_ENDPT_TX]);
		splx(s);
		return;
	}

	usbd_get_xfer_status(c->kue_xfer, NULL, NULL, NULL, &err);

	m_freem(c->kue_mbuf);
	c->kue_mbuf = NULL;

	if (err)
		ifp->if_oerrors++;
	else
		ifp->if_opackets++;

	if (ifp->if_snd.ifq_head != NULL)
		kue_start(ifp);

	splx(s);

	return;
}

static int kue_encap(sc, m, idx)
	struct kue_softc	*sc;
	struct mbuf		*m;
	int			idx;
{
	int			total_len;
	struct kue_chain	*c;
	usbd_status		err;

	c = &sc->kue_cdata.kue_tx_chain[idx];

	/*
	 * Copy the mbuf data into a contiguous buffer, leaving two
	 * bytes at the beginning to hold the frame length.
	 */
	m_copydata(m, 0, m->m_pkthdr.len, c->kue_buf + 2);
	c->kue_mbuf = m;

	total_len = m->m_pkthdr.len + 2;
	total_len += 64 - (total_len % 64);

	/* Frame length is specified in the first 2 bytes of the buffer. */
	c->kue_buf[0] = (u_int8_t)m->m_pkthdr.len;
	c->kue_buf[1] = (u_int8_t)(m->m_pkthdr.len >> 8);

	usbd_setup_xfer(c->kue_xfer, sc->kue_ep[KUE_ENDPT_TX],
	    c, c->kue_buf, total_len, 0, 10000, kue_txeof);

	/* Transmit */
	err = usbd_transfer(c->kue_xfer);
	if (err != USBD_IN_PROGRESS) {
		kue_stop(sc);
		return(EIO);
	}

	sc->kue_cdata.kue_tx_cnt++;

	return(0);
}

static void kue_start(ifp)
	struct ifnet		*ifp;
{
	struct kue_softc	*sc;
	struct mbuf		*m_head = NULL;

	sc = ifp->if_softc;

	if (ifp->if_flags & IFF_OACTIVE)
		return;

	IF_DEQUEUE(&ifp->if_snd, m_head);
	if (m_head == NULL)
		return;

	if (kue_encap(sc, m_head, 0)) {
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

static void kue_init(xsc)
	void			*xsc;
{
	struct kue_softc	*sc = xsc;
	struct ifnet		*ifp = &sc->arpcom.ac_if;
	struct kue_chain	*c;
	usbd_status		err;
	int			i, s;

	if (ifp->if_flags & IFF_RUNNING)
		return;

	s = splimp();

	/* Set MAC address */
	kue_ctl(sc, KUE_CTL_WRITE, KUE_CMD_SET_MAC,
	    0, sc->arpcom.ac_enaddr, ETHER_ADDR_LEN);

	sc->kue_rxfilt = KUE_RXFILT_UNICAST|KUE_RXFILT_BROADCAST;

	 /* If we want promiscuous mode, set the allframes bit. */
	if (ifp->if_flags & IFF_PROMISC)
		sc->kue_rxfilt |= KUE_RXFILT_PROMISC;

	kue_setword(sc, KUE_CMD_SET_PKT_FILTER, sc->kue_rxfilt);

	/* I'm not sure how to tune these. */
#ifdef notdef
	/*
	 * Leave this one alone for now; setting it
	 * wrong causes lockups on some machines/controllers.
	 */
	kue_setword(sc, KUE_CMD_SET_SOFS, 1);
#endif
	kue_setword(sc, KUE_CMD_SET_URB_SIZE, 64);

	/* Init TX ring. */
	if (kue_tx_list_init(sc) == ENOBUFS) {
		printf("kue%d: tx list init failed\n", sc->kue_unit);
		splx(s);
		return;
	}

	/* Init RX ring. */
	if (kue_rx_list_init(sc) == ENOBUFS) {
		printf("kue%d: rx list init failed\n", sc->kue_unit);
		splx(s);
		return;
	}

	/* Load the multicast filter. */
	kue_setmulti(sc);

	/* Open RX and TX pipes. */
	err = usbd_open_pipe(sc->kue_iface, sc->kue_ed[KUE_ENDPT_RX],
	    USBD_EXCLUSIVE_USE, &sc->kue_ep[KUE_ENDPT_RX]);
	if (err) {
		printf("kue%d: open rx pipe failed: %s\n",
		    sc->kue_unit, usbd_errstr(err));
		splx(s);
		return;
	}

	err = usbd_open_pipe(sc->kue_iface, sc->kue_ed[KUE_ENDPT_TX],
	    USBD_EXCLUSIVE_USE, &sc->kue_ep[KUE_ENDPT_TX]);
	if (err) {
		printf("kue%d: open tx pipe failed: %s\n",
		    sc->kue_unit, usbd_errstr(err));
		splx(s);
		return;
	}

	/* Start up the receive pipe. */
	for (i = 0; i < KUE_RX_LIST_CNT; i++) {
		c = &sc->kue_cdata.kue_rx_chain[i];
		usbd_setup_xfer(c->kue_xfer, sc->kue_ep[KUE_ENDPT_RX],
		    c, mtod(c->kue_mbuf, char *), KUE_BUFSZ,
	    	USBD_SHORT_XFER_OK, USBD_NO_TIMEOUT, kue_rxeof);
		usbd_transfer(c->kue_xfer);
	}

	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	(void)splx(s);

	return;
}

static int kue_ioctl(ifp, command, data)
	struct ifnet		*ifp;
	u_long			command;
	caddr_t			data;
{
	struct kue_softc	*sc = ifp->if_softc;
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
			    !(sc->kue_if_flags & IFF_PROMISC)) {
				sc->kue_rxfilt |= KUE_RXFILT_PROMISC;
				kue_setword(sc, KUE_CMD_SET_PKT_FILTER,
				    sc->kue_rxfilt);
			} else if (ifp->if_flags & IFF_RUNNING &&
			    !(ifp->if_flags & IFF_PROMISC) &&
			    sc->kue_if_flags & IFF_PROMISC) {
				sc->kue_rxfilt &= ~KUE_RXFILT_PROMISC;
				kue_setword(sc, KUE_CMD_SET_PKT_FILTER,
				    sc->kue_rxfilt);
			} else if (!(ifp->if_flags & IFF_RUNNING))
				kue_init(sc);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				kue_stop(sc);
		}
		sc->kue_if_flags = ifp->if_flags;
		error = 0;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		kue_setmulti(sc);
		error = 0;
		break;
	default:
		error = EINVAL;
		break;
	}

	(void)splx(s);

	return(error);
}

static void kue_watchdog(ifp)
	struct ifnet		*ifp;
{
	struct kue_softc	*sc;

	sc = ifp->if_softc;

	ifp->if_oerrors++;
	printf("kue%d: watchdog timeout\n", sc->kue_unit);

	/*
	 * The polling business is a kludge to avoid allowing the
	 * USB code to call tsleep() in usbd_delay_ms(), which will
	 * kill us since the watchdog routine is invoked from
	 * interrupt context.
	 */
	sc->kue_udev->bus->use_polling++;
	kue_stop(sc);
	kue_init(sc);
	sc->kue_udev->bus->use_polling--;

	if (ifp->if_snd.ifq_head != NULL)
		kue_start(ifp);

	return;
}

/*
 * Stop the adapter and free any mbufs allocated to the
 * RX and TX lists.
 */
static void kue_stop(sc)
	struct kue_softc	*sc;
{
	usbd_status		err;
	struct ifnet		*ifp;
	int			i;

	ifp = &sc->arpcom.ac_if;
	ifp->if_timer = 0;

	/* Stop transfers. */
	if (sc->kue_ep[KUE_ENDPT_RX] != NULL) {
		err = usbd_abort_pipe(sc->kue_ep[KUE_ENDPT_RX]);
		if (err) {
			printf("kue%d: abort rx pipe failed: %s\n",
		    	sc->kue_unit, usbd_errstr(err));
		}
		err = usbd_close_pipe(sc->kue_ep[KUE_ENDPT_RX]);
		if (err) {
			printf("kue%d: close rx pipe failed: %s\n",
		    	sc->kue_unit, usbd_errstr(err));
		}
		sc->kue_ep[KUE_ENDPT_RX] = NULL;
	}

	if (sc->kue_ep[KUE_ENDPT_TX] != NULL) {
		err = usbd_abort_pipe(sc->kue_ep[KUE_ENDPT_TX]);
		if (err) {
			printf("kue%d: abort tx pipe failed: %s\n",
		    	sc->kue_unit, usbd_errstr(err));
		}
		err = usbd_close_pipe(sc->kue_ep[KUE_ENDPT_TX]);
		if (err) {
			printf("kue%d: close tx pipe failed: %s\n",
			    sc->kue_unit, usbd_errstr(err));
		}
		sc->kue_ep[KUE_ENDPT_TX] = NULL;
	}

	if (sc->kue_ep[KUE_ENDPT_INTR] != NULL) {
		err = usbd_abort_pipe(sc->kue_ep[KUE_ENDPT_INTR]);
		if (err) {
			printf("kue%d: abort intr pipe failed: %s\n",
		    	sc->kue_unit, usbd_errstr(err));
		}
		err = usbd_close_pipe(sc->kue_ep[KUE_ENDPT_INTR]);
		if (err) {
			printf("kue%d: close intr pipe failed: %s\n",
			    sc->kue_unit, usbd_errstr(err));
		}
		sc->kue_ep[KUE_ENDPT_INTR] = NULL;
	}

	/* Free RX resources. */
	for (i = 0; i < KUE_RX_LIST_CNT; i++) {
		if (sc->kue_cdata.kue_rx_chain[i].kue_buf != NULL) {
			free(sc->kue_cdata.kue_rx_chain[i].kue_buf, M_USBDEV);
			sc->kue_cdata.kue_rx_chain[i].kue_buf = NULL;
		}
		if (sc->kue_cdata.kue_rx_chain[i].kue_mbuf != NULL) {
			m_freem(sc->kue_cdata.kue_rx_chain[i].kue_mbuf);
			sc->kue_cdata.kue_rx_chain[i].kue_mbuf = NULL;
		}
		if (sc->kue_cdata.kue_rx_chain[i].kue_xfer != NULL) {
			usbd_free_xfer(sc->kue_cdata.kue_rx_chain[i].kue_xfer);
			sc->kue_cdata.kue_rx_chain[i].kue_xfer = NULL;
		}
	}

	/* Free TX resources. */
	for (i = 0; i < KUE_TX_LIST_CNT; i++) {
		if (sc->kue_cdata.kue_tx_chain[i].kue_buf != NULL) {
			free(sc->kue_cdata.kue_tx_chain[i].kue_buf, M_USBDEV);
			sc->kue_cdata.kue_tx_chain[i].kue_buf = NULL;
		}
		if (sc->kue_cdata.kue_tx_chain[i].kue_mbuf != NULL) {
			m_freem(sc->kue_cdata.kue_tx_chain[i].kue_mbuf);
			sc->kue_cdata.kue_tx_chain[i].kue_mbuf = NULL;
		}
		if (sc->kue_cdata.kue_tx_chain[i].kue_xfer != NULL) {
			usbd_free_xfer(sc->kue_cdata.kue_tx_chain[i].kue_xfer);
			sc->kue_cdata.kue_tx_chain[i].kue_xfer = NULL;
		}
	}

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);

	return;
}

/*
 * Stop all chip I/O so that the kernel's probe routines don't
 * get confused by errant DMAs when rebooting.
 */
static void kue_shutdown(dev)
	device_t		dev;
{
	struct kue_softc	*sc;

	sc = device_get_softc(dev);

	kue_stop(sc);

	return;
}
