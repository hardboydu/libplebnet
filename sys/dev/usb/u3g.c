/*
 * Copyright (c) 2008 AnyWi Technologies
 * Author: Andrea Guzzo <aguzzo@anywi.com>
 * * based on uark.c 1.1 2006/08/14 08:30:22 jsg *
 * * parts from ubsa.c 183348 2008-09-25 12:00:56Z phk *
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $FreeBSD$
 */

/*
 * Notes:
 * - The detour through the tty layer is ridiculously expensive wrt buffering
 *   due to the high speeds.
 *   We should consider adding a simple r/w device which allows attaching of PPP
 *   in a more efficient way.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/ioccom.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/tty.h>
#include <sys/file.h>
#include <sys/selinfo.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>

#include <dev/usb/ucomvar.h>

#include "usbdevs.h"

#define U3G_DEBUG	1
#ifdef U3G_DEBUG
#define DPRINTF(x...)		do { if (u3gdebug) device_printf(self, ##x); } while (0)
#define DPRINTFN(n, x...)	do { if (u3gdebug > (n)) device_printf(self, ##x); } while (0)
int	u3gdebug = 1;
#else
#define DPRINTF(x...)		/* nop */
#define DPRINTFN(n, x...)	/* nop */
#endif

#define U3G_BUFSIZ		10240
#define U3G_MAXPORTS		4
#define U3G_CONFIG_INDEX	0

struct u3g_softc {
	struct ucom_softc	sc_ucom[U3G_MAXPORTS];
	device_t		sc_dev;
	usbd_device_handle	sc_udev;
	u_int8_t		sc_speed;
	u_int8_t		sc_flags;
	u_char			sc_numports;
};

static int u3g_open(void *addr, int portno);
static void u3g_close(void *addr, int portno);

struct ucom_callback u3g_callback = {
	NULL,
	NULL,
	NULL,
	NULL,
	u3g_open,
	u3g_close,
	NULL,
	NULL,
};


/*
 * Various supported device vendors/products.
 */
struct u3g_dev_type_s {
	struct usb_devno	devno;
	u_int8_t		speed;
#define U3GSP_GPRS		1
#define U3GSP_EDGE		2
#define U3GSP_UMTS		3
#define U3GSP_HSDPA		4
#define U3GSP_HSUPA		5
#define U3GSP_HSPA		6

	u_int8_t		flags;
#define U3GFL_NONE		0x00
#define U3GFL_HUAWEI_INIT	0x01		// Requires init (Huawei cards)
#define U3GFL_STUB_WAIT		0x02		// Device reappears after a short delay
};

static const struct u3g_dev_type_s u3g_devs[] = {
	/* OEM: Option */
	{{ USB_VENDOR_OPTION, USB_PRODUCT_OPTION_GT3G },		U3GSP_UMTS,	U3GFL_NONE },
	{{ USB_VENDOR_OPTION, USB_PRODUCT_OPTION_GT3GQUAD },		U3GSP_UMTS,	U3GFL_NONE },
	{{ USB_VENDOR_OPTION, USB_PRODUCT_OPTION_GT3GPLUS },		U3GSP_UMTS,	U3GFL_NONE },
	{{ USB_VENDOR_OPTION, USB_PRODUCT_OPTION_GTMAX36 },		U3GSP_HSDPA,	U3GFL_NONE },
	{{ USB_VENDOR_OPTION, USB_PRODUCT_OPTION_GTMAXHSUPA },		U3GSP_HSDPA,	U3GFL_NONE },
	{{ USB_VENDOR_OPTION, USB_PRODUCT_OPTION_VODAFONEMC3G },	U3GSP_UMTS,	U3GFL_NONE },
	/* OEM: Qualcomm, Inc. */
	{{ USB_VENDOR_QUALCOMMINC, USB_PRODUCT_QUALCOMMINC_CDMA_MSM },	U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	/* OEM: Huawei */
	{{ USB_VENDOR_HUAWEI, USB_PRODUCT_HUAWEI_MOBILE },		U3GSP_HSDPA,	U3GFL_HUAWEI_INIT },
	{{ USB_VENDOR_HUAWEI, USB_PRODUCT_HUAWEI_E220 },		U3GSP_HSDPA,	U3GFL_HUAWEI_INIT },
	/* OEM: Novatel */
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_CDMA_MODEM },	U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_ES620 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_MC950D },		U3GSP_HSUPA,	U3GFL_STUB_WAIT },
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_U720 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_U727 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_U740 },		U3GSP_HSDPA,	U3GFL_STUB_WAIT },
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_U740_2 },		U3GSP_HSDPA,	U3GFL_STUB_WAIT },
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_U870 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_V620 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_V640 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_V720 },		U3GSP_UMTS,	U3GFL_STUB_WAIT },	// XXX
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_V740 },		U3GSP_HSDPA,	U3GFL_STUB_WAIT },
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_X950D },		U3GSP_HSUPA,	U3GFL_STUB_WAIT },
	{{ USB_VENDOR_NOVATEL, USB_PRODUCT_NOVATEL_XU870 },		U3GSP_HSDPA,	U3GFL_STUB_WAIT },
	{{ USB_VENDOR_DELL,    USB_PRODUCT_DELL_U740 },			U3GSP_HSDPA,	U3GFL_STUB_WAIT },
	/* OEM: Merlin */
	{{ USB_VENDOR_MERLIN, USB_PRODUCT_MERLIN_V620 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	/* OEM: Sierra Wireless: */
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AIRCARD580 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AIRCARD595 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC595U },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC597E },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_C597 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC880 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC880E },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC880U },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC881 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC881E },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC881U },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_EM5625 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC5720 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC5720_2 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC5725 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MINI5725 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AIRCARD875 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8755 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8755_2 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8755_3 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8765 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_AC875U },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8775_2 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8780 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
	{{ USB_VENDOR_SIERRA, USB_PRODUCT_SIERRA_MC8781 },		U3GSP_UMTS,	U3GFL_NONE },		// XXX
};
#define u3g_lookup(v, p) ((const struct u3g_dev_type_s *)usb_lookup(u3g_devs, v, p))

static int
u3g_match(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);
	const struct u3g_dev_type_s *u3g_dev_type;

	if (!uaa->iface)
		return UMATCH_NONE;

	u3g_dev_type = u3g_lookup(uaa->vendor, uaa->product);
	if (!u3g_dev_type)
		return UMATCH_NONE;

	if (u3g_dev_type->flags&U3GFL_HUAWEI_INIT) {
		/* If the interface class of the first interface is no longer
		 * mass storage the card has changed to modem (see u3g_attach()
		 * below).
		 */
		usb_interface_descriptor_t *id;
		id = usbd_get_interface_descriptor(uaa->iface);
		if (!id || id->bInterfaceClass == UICLASS_MASS)
			return UMATCH_NONE;
	}

	return UMATCH_VENDOR_PRODUCT_CONF_IFACE;
}

static int
u3g_attach(device_t self)
{
	struct u3g_softc *sc = device_get_softc(self);
	struct usb_attach_arg *uaa = device_get_ivars(self);
	const struct u3g_dev_type_s *u3g_dev_type;
	usbd_device_handle dev = uaa->device;
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed;
	int i, n; 
	usb_config_descriptor_t *cd;
	char devnamefmt[32];

	/* get the config descriptor */
	cd = usbd_get_config_descriptor(dev);
	if (cd == NULL) {
		device_printf(self, "failed to get configuration descriptor\n");
		return ENXIO;
	}

	sc->sc_dev = self;
	sc->sc_udev = dev;

	u3g_dev_type = u3g_lookup(uaa->vendor, uaa->product);
	sc->sc_flags = u3g_dev_type->flags;
	sc->sc_speed = u3g_dev_type->speed;

	sprintf(devnamefmt,"U%d.%%d", device_get_unit(self));
	int portno = 0;
	for (i = 0; i < uaa->nifaces && portno < U3G_MAXPORTS; i++) {
		if (uaa->ifaces[i] == NULL)
			continue;

		id = usbd_get_interface_descriptor(uaa->ifaces[i]);
		if (id && id->bInterfaceClass == UICLASS_MASS) {
			/* We attach to the interface instead of the device as
			 * some devices have a built-in SD card reader.
			 * Claim the first umass device (cdX) as it contains
			 * only Windows drivers anyway (CD-ROM), hiding it.
			 */
#ifndef U3G_DEBUG
			if (!bootverbose)
				if (uaa->vendor == USB_VENDOR_HUAWEI)
					if (id->bInterfaceNumber == 2)
						uaa->ifaces[i] = NULL;
#endif
			continue;
		}

		int bulkin_no = -1, bulkout_no = -1;
		for (n = 0; n < id->bNumEndpoints; n++) {
			ed = usbd_interface2endpoint_descriptor(uaa->ifaces[i], n);
			if (ed == NULL)
				continue;
			if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN
			    && UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK)
				bulkin_no = ed->bEndpointAddress;
			else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT
				 && UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK)
				bulkout_no = ed->bEndpointAddress;

			/* If we have found a pair of bulk-in/-out endpoints
			 * create a serial port for it. Note: We assume that
			 * the bulk-in and bulk-out endpoints appear in pairs.
			 */
			if (bulkin_no != -1 && bulkout_no != -1) {
				struct ucom_softc *ucom = &sc->sc_ucom[portno];

				ucom->sc_dev = self;
				ucom->sc_udev = dev;
				ucom->sc_iface = uaa->ifaces[i];
				ucom->sc_bulkin_no = bulkin_no;
				ucom->sc_ibufsize = U3G_BUFSIZ;
				ucom->sc_ibufsizepad = U3G_BUFSIZ;	// XXX What's this?
				ucom->sc_bulkout_no = bulkout_no;
				ucom->sc_obufsize = U3G_BUFSIZ;
				ucom->sc_opkthdrlen = 0;

				ucom->sc_callback = &u3g_callback;
				ucom->sc_parent = sc;
				ucom->sc_portno = portno;

				DPRINTF("port=%d iface=%d in=0x%x out=0x%x\n",
					 portno, i,
					 ucom->sc_bulkin_no,
					 ucom->sc_bulkout_no);
#if __FreeBSD_version < 800000
				ucom_attach_tty(ucom, TS_CALLOUT, devnamefmt, portno);
#else
				ucom_attach_tty(ucom, devnamefmt, portno);
#endif

				uaa->ifaces[i] = NULL;
				portno++;
				bulkin_no = bulkout_no = -1;
			}
		}

	}
	sc->sc_numports = portno;

	device_printf(self, "configured %d serial ports (%s)\n",
		      sc->sc_numports, devnamefmt);
	return 0;
}

static int
u3g_detach(device_t self)
{
	struct u3g_softc *sc = device_get_softc(self);
	int rv = 0;
	int i;

	for (i = 0; i < sc->sc_numports; i++) {
		sc->sc_ucom[i].sc_dying = 1;
		rv = ucom_detach(&sc->sc_ucom[i]);
		if (rv != 0) {
			device_printf(self, "ucom_detach(U%d.%d\n", device_get_unit(self), i);
			return rv;
		}
	}

	return 0;
}

static int
u3g_open(void *addr, int portno)
{
#if __FreeBSD_version < 800000
	/* Supply generous buffering for these cards to avoid disappointments
	 * when setting the speed incorrectly. Only do this for the first port
	 * assuming that the rest of the ports are used for diagnostics only
	 * anyway.
	 * Note: We abuse the fact that ucom sets the speed through
	 * ispeed/ospeed, not through ispeedwat/ospeedwat.
	 */
	if (portno == 0) {
		struct u3g_softc *sc = addr;
		struct ucom_softc *ucom = &sc->sc_ucom[portno];
		struct tty *tp = ucom->sc_tty;
#ifdef U3G_DEBUG
		device_t self = sc->sc_dev;
#endif

		if (sc->sc_speed&U3GSP_HSPA) {
			tp->t_ispeedwat = 7200000;
			tp->t_ospeedwat = 384000;
		} else if (sc->sc_speed&U3GSP_HSUPA) {
			tp->t_ispeedwat = 1200000;
			tp->t_ospeedwat = 384000;
		} else if (sc->sc_speed&U3GSP_HSDPA) {
			tp->t_ispeedwat = 1200000;
			tp->t_ospeedwat = 384000;
		} else if (sc->sc_speed&U3GSP_UMTS) {
			tp->t_ispeedwat = 384000;
			tp->t_ospeedwat = 64000;
		} else if (sc->sc_speed&U3GSP_EDGE) {
			tp->t_ispeedwat = 384000;
			tp->t_ospeedwat = 64000;
		} else {
			tp->t_ispeedwat = 64000;
			tp->t_ospeedwat = 64000;
		}

		/* Avoid excessive buffer sizes. On modern fast machines this is
		 * not needed.
		 * XXX The values here should be checked. Lower them and see
		 * whether 'lost chars' messages appear.
		 */
		if (tp->t_ispeedwat > 384000)
		    tp->t_ispeedwat = 384000;
		if (tp->t_ospeedwat > 384000)
		    tp->t_ospeedwat = 384000;

		DPRINTF("ispeedwat = %d, ospeedwat = %d\n",
			tp->t_ispeedwat, tp->t_ospeedwat);
		ttsetwater(tp);
	}
#endif

	return 0;
}

static void
u3g_close(void *addr, int portno)
{
#if __FreeBSD_version < 800000
	if (portno == 0) {	/* see u3g_open() */
		/* Reduce the buffers allocated above again */
		struct u3g_softc *sc = addr;
		struct ucom_softc *ucom = &sc->sc_ucom[portno];
		struct tty *tp = ucom->sc_tty;
#ifdef U3G_DEBUG
		device_t self = sc->sc_dev;
#endif

		tp->t_ispeedwat = (speed_t)-1;
		tp->t_ospeedwat = (speed_t)-1;

		DPRINTF("ispeedwat = default, ospeedwat = default\n");
		ttsetwater(tp);
	}
#endif
}	

static device_method_t u3g_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, u3g_match),
	DEVMETHOD(device_attach, u3g_attach),
	DEVMETHOD(device_detach, u3g_detach),

	{ 0, 0 }
};

static driver_t u3g_driver = {
	"ucom",
	u3g_methods,
	sizeof (struct u3g_softc)
};

DRIVER_MODULE(u3g, uhub, u3g_driver, ucom_devclass, usbd_driver_load, 0);
MODULE_DEPEND(u3g, usb, 1, 1, 1);
MODULE_DEPEND(u3g, ucom, UCOM_MINVER, UCOM_PREFVER, UCOM_MAXVER);

/*******************************************************************
 ****** Stub driver to hide devices that need to reinitialise ******
 *******************************************************************/

static void
u3gstub_huawei_init(usbd_device_handle dev)
{
	usb_device_request_t req;

	req.bmRequestType = UT_WRITE_DEVICE;
	req.bRequest = UR_SET_FEATURE;
	USETW(req.wValue, UF_DEVICE_REMOTE_WAKEUP);
	USETW(req.wIndex, UHF_PORT_SUSPEND);
	USETW(req.wLength, 0);

	(void) usbd_do_request(dev, &req, 0);		/* ignore any error */
}

static int
u3gstub_match(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);
	const struct u3g_dev_type_s *u3g_dev_type;
	usb_interface_descriptor_t *id;

	/* This stub handles 3G modem devices (E220, Mobile, etc.) with
	 * auto-install flash disks for Windows/MacOSX on the first interface.
	 * After some command or some delay they change appearance to a modem.
	 */

	if (!uaa->iface)
		return UMATCH_NONE;

	u3g_dev_type = u3g_lookup(uaa->vendor, uaa->product);
	if (!u3g_dev_type)
		return UMATCH_NONE;

	if (u3g_dev_type->flags&U3GFL_HUAWEI_INIT
	    || u3g_dev_type->flags&U3GFL_STUB_WAIT) {
		/* We assume that if the first interface is still a mass
		 * storage device the device has not yet changed appearance.
		 */
		id = usbd_get_interface_descriptor(uaa->iface);
		if (id && id->bInterfaceNumber == 0 && id->bInterfaceClass == UICLASS_MASS)
			return UMATCH_VENDOR_PRODUCT;
	}

	return UMATCH_NONE;
}

static int
u3gstub_attach(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);
	const struct u3g_dev_type_s *u3g_dev_type;
	int i;
#ifndef U3G_DEBUG
	if (!bootverbose)				// hide the stub attachment
		device_quiet(self);
#endif

	if (uaa->iface)
		for (i = 0; i < uaa->nifaces; i++)
			uaa->ifaces[i] = NULL;		// claim all interfaces

	u3g_dev_type = u3g_lookup(uaa->vendor, uaa->product);
	if (u3g_dev_type->flags&U3GFL_HUAWEI_INIT) {
		/* XXX Should we delay the kick?
		 */
		DPRINTF("changing Huawei modem to modem mode\n");
		u3gstub_huawei_init(uaa->device);
	} else if (u3g_dev_type->flags&U3GFL_STUB_WAIT) {
		/* nop  */
	}

	return 0;
}

static int
u3gstub_detach(device_t self)
{
	return 0;
}

static device_method_t u3gstub_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, u3gstub_match),
	DEVMETHOD(device_attach, u3gstub_attach),
	DEVMETHOD(device_detach, u3gstub_detach),

	{ 0, 0 }
};

static driver_t u3gstub_driver = {
	"u3gstub",
	u3gstub_methods,
	0
};

DRIVER_MODULE(u3gstub, uhub, u3gstub_driver, ucom_devclass, usbd_driver_load, 0);
MODULE_DEPEND(u3gstub, usb, 1, 1, 1);
