/*	$NetBSD: umodem.c,v 1.1 1998/12/03 19:58:09 augustss Exp $	*/

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (augustss@carlstedt.se) at
 * Carlstedt Research & Technology.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <dev/usb/usb_port.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#if defined(__NetBSD__)
#include <sys/device.h>
#include <sys/ioctl.h>
#elif defined(__FreeBSD__)
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/ioccom.h>
#include <sys/conf.h>
#endif
#include <sys/tty.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/device.h>
#include <sys/poll.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>

#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usb_quirks.h>
#include <dev/usb/hid.h>

#ifdef USB_DEBUG
#define DPRINTF(x)	if (umodemdebug) printf x
#define DPRINTFN(n,x)	if (umodemdebug>(n)) printf x
int	umodemdebug = 0;
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

struct umodem_softc {
	bdevice sc_dev;			/* base device */
	usbd_interface_handle sc_iface;	/* interface */
};

#if defined(__NetBSD__)
int umodem_match __P((struct device *, struct cfdata *, void *));
void umodem_attach __P((struct device *, struct device *, void *));
#elif defined(__FreeBSD__)
static device_probe_t umodem_match;
static device_attach_t umodem_attach;
static device_detach_t umodem_detach;
#endif

void umodem_intr __P((usbd_request_handle, usbd_private_handle, usbd_status));
void umodem_disco __P((void *));

#if defined(__NetBSD__)
extern struct cfdriver umodem_cd;

struct cfattach umodem_ca = {
	sizeof(struct umodem_softc), umodem_match, umodem_attach
};
#elif defined(__FreeBSD__)
static devclass_t umodem_devclass;

static device_method_t umodem_methods[] = {
	DEVMETHOD(device_probe, umodem_match),
	DEVMETHOD(device_attach, umodem_attach),
	DEVMETHOD(device_detach, umodem_detach),
	{0,0}
};

static driver_t umodem_driver = {
	"umodem",
	umodem_methods,
	DRIVER_TYPE_MISC,
	sizeof(struct umodem_softc)
};
#endif

#if defined(__NetBSD__)
int
umodem_match(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct usb_attach_arg *uaa = aux;
#elif defined(__FreeBSD__)
static int
umodem_match(device_t device)
{
	struct usb_attach_arg *uaa = device_get_ivars(device);
#endif

	usb_interface_descriptor_t *id;
	
	if (!uaa->iface)
		return (UMATCH_NONE);
	id = usbd_get_interface_descriptor(uaa->iface);
	if (id->bInterfaceClass != UCLASS_CDC ||
	    id->bInterfaceSubClass != USUBCLASS_MODEM)
		return (UMATCH_NONE);
	return (UMATCH_IFACECLASS_IFACESUBCLASS);
}

#if defined(__NetBSD__)
void
umodem_attach(parent, self, aux)
	struct device *parent;
	struct device *self;
	void *aux;
{
	struct umodem_softc *sc = (struct umodem_softc *)self;
	struct usb_attach_arg *uaa = aux;
#elif defined(__FreeBSD__)
static int
umodem_attach(device_t self)
{
	struct umodem_softc *sc = device_get_softc(self);
	struct usb_attach_arg *uaa = device_get_ivars(self);
#endif

	usbd_interface_handle iface = uaa->iface;
	usb_interface_descriptor_t *id;
	char devinfo[1024];
	
	sc->sc_iface = iface;
	id = usbd_get_interface_descriptor(iface);
	usbd_devinfo(uaa->device, 0, devinfo);
#if defined(__FreeBSD__)
        usb_device_set_desc(self, devinfo);
        printf("%s%d", device_get_name(self), device_get_unit(self));
#endif

	printf(": %s, iclass %d/%d\n", devinfo, id->bInterfaceClass, id->bInterfaceSubClass);

	ATTACH_SUCCESS_RETURN;
}

#if defined(__FreeBSD__)
static int
umodem_detach(device_t self)
{
	struct umodem_softc *sc = device_get_softc(self);
	char *devinfo = (char *) device_get_desc(self);

	if (devinfo) {
		device_set_desc(self, NULL);
		free(devinfo, M_USB);
	}

	return 0;
}
#endif

#if defined(__FreeBSD__)
DRIVER_MODULE(umodem, usb, umodem_driver, umodem_devclass, usb_driver_load, 0);
#endif

