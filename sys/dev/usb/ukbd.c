/*      $NetBSD: ukbd.c,v 1.22 1999/01/09 12:10:36 drochner Exp $        */
/*	$FreeBSD$	*/

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

/*
 * HID spec: http://www.usb.org/developers/data/usbhid10.pdf
 */

#include "ukbd.h"
#include "opt_kbd.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ioccom.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <machine/clock.h>
#include <sys/tty.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/poll.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usb_quirks.h>
#include <dev/usb/hid.h>

#include <sys/conf.h>
#include <dev/kbd/kbdreg.h>

#define UKBD_EMULATE_ATSCANCODE	1

#define DRIVER_NAME	"ukbd"

#define delay(d)         DELAY(d)

#ifdef UKBD_DEBUG
#define DPRINTF(x)	if (ukbddebug) logprintf x
#define DPRINTFN(n,x)	if (ukbddebug>(n)) logprintf x
int	ukbddebug = 1;
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

#define UPROTO_BOOT_KEYBOARD 1

#define NKEYCODE 6

struct ukbd_data {
	u_int8_t	modifiers;
#define MOD_CONTROL_L	0x01
#define MOD_CONTROL_R	0x10
#define MOD_SHIFT_L	0x02
#define MOD_SHIFT_R	0x20
#define MOD_ALT_L	0x04
#define MOD_ALT_R	0x40
#define MOD_WIN_L	0x08
#define MOD_WIN_R	0x80
	u_int8_t	reserved;
	u_int8_t	keycode[NKEYCODE];
};

#define MAXKEYS (NMOD+2*NKEYCODE)

typedef struct ukbd_softc {
	bdevice		sc_dev;		/* base device */
	usbd_interface_handle sc_iface;	/* interface */

	short		sc_flags;
#define	UKBD_ATTACHED	(1 << 0)
	keyboard_t	*sc_kbd;
#ifdef KBD_INSTALL_CDEV
	genkbd_softc_t	sc_gensc;
#endif
} ukbd_softc_t;

#define	UKBDUNIT(dev)	(minor(dev))
#define	UKBD_CHUNK	128	/* chunk size for read */
#define	UKBD_BSIZE	1020	/* buffer size */

typedef void usbd_intr_t(usbd_request_handle, usbd_private_handle, usbd_status);
typedef void usbd_disco_t(void *);

static usbd_intr_t	ukbd_intr;
static usbd_disco_t	ukbd_disconnect;
static int		ukbd_remove_kbd(struct ukbd_softc *sc);

#ifdef KBD_INSTALL_CDEV

static d_open_t		ukbdopen;
static d_close_t	ukbdclose;
static d_read_t		ukbdread;
static d_ioctl_t	ukbdioctl;
static d_poll_t		ukbdpoll;

static struct  cdevsw ukbd_cdevsw = {
	ukbdopen,	ukbdclose,	ukbdread,	nowrite,
	ukbdioctl,	nostop,		nullreset,	nodevtotty,
	ukbdpoll,	nommap,		NULL,		DRIVER_NAME,
	NULL,		-1,
};

#endif /* KBD_INSTALL_CDEV */

USB_DECLARE_DRIVER(ukbd);

USB_MATCH(ukbd)
{
	USB_MATCH_START(ukbd, uaa);

	keyboard_switch_t *sw;
	void *arg[4];
	int unit = device_get_unit(device);

	sw = kbd_get_switch(DRIVER_NAME);
	if (sw == NULL)
		return (UMATCH_NONE);

	arg[0] = (void *)uaa;
	arg[1] = (void *)ukbd_intr;
	arg[2] = (void *)ukbd_disconnect;
	arg[3] = (void *)device;
	if ((*sw->probe)(unit, (void *)arg, 0))
		return (UMATCH_NONE);

	return (UMATCH_IFACECLASS_IFACESUBCLASS_IFACEPROTO);
}

USB_ATTACH(ukbd)
{
	USB_ATTACH_START(ukbd, sc, uaa);
	usbd_interface_handle iface = uaa->iface;
	usb_interface_descriptor_t *id;
	char devinfo[1024];

	keyboard_switch_t *sw;
	void *arg[4];
	int unit = device_get_unit(self);

	sw = kbd_get_switch(DRIVER_NAME);
	if (sw == NULL)
		USB_ATTACH_ERROR_RETURN;

	sc->sc_iface = iface;
	id = usbd_get_interface_descriptor(iface);
	usbd_devinfo(uaa->device, 0, devinfo);
	USB_ATTACH_SETUP;
	printf("%s: %s, iclass %d/%d\n", USBDEVNAME(sc->sc_dev),
	       devinfo, id->bInterfaceClass, id->bInterfaceSubClass);

	arg[0] = (void *)uaa;
	arg[1] = (void *)ukbd_intr;
	arg[2] = (void *)ukbd_disconnect;
	arg[3] = (void *)self;
	sc->sc_kbd = NULL;
	if ((*sw->probe)(unit, (void *)arg, 0))
		USB_ATTACH_ERROR_RETURN;
	if ((*sw->init)(unit, &sc->sc_kbd, (void *)arg, 0))
		USB_ATTACH_ERROR_RETURN;
	(*sw->enable)(sc->sc_kbd);

#ifdef KBD_INSTALL_CDEV
	if (kbd_attach(makedev(0, unit), sc->sc_kbd, &ukbd_cdevsw))
		USB_ATTACH_ERROR_RETURN;
#endif
	if (bootverbose)
		(*sw->diag)(sc->sc_kbd, bootverbose);
	sc->sc_flags |= UKBD_ATTACHED;

	USB_ATTACH_SUCCESS_RETURN;
}

int
ukbd_detach(device_t self)
{
	struct ukbd_softc *sc = device_get_softc(self);
	int error;

	error = ukbd_remove_kbd(sc);
	if (error)
		return error;

	sc->sc_flags &= ~UKBD_ATTACHED;

	DPRINTF(("%s: disconnected\n", USBDEVNAME(self)));

	device_set_desc(self, NULL);

	return (0);
}

static void
ukbd_disconnect(void *p)
{
	device_t self = (device_t)p;
	struct ukbd_softc *sc = device_get_softc(self);

	DPRINTF(("ukbd_disconnect: sc:%p\n", sc));
	(*kbdsw[sc->sc_kbd->kb_index]->disable)(sc->sc_kbd);
}

static int
ukbd_remove_kbd(struct ukbd_softc *sc)
{
	int error;

#ifdef KBD_INSTALL_CDEV
	error = kbd_detach(makedev(0, sc->sc_kbd->kb_unit), sc->sc_kbd,
			   &ukbd_cdevsw);
	if (error)
		return error;
#endif
	error = (*kbdsw[sc->sc_kbd->kb_index]->term)(sc->sc_kbd);
	if (error)
		return error;
	sc->sc_kbd = NULL;

	return 0;
}

/* cdev driver functions */

#ifdef KBD_INSTALL_CDEV

static int
ukbdopen(dev_t dev, int flag, int mode, struct proc *p)
{
	USB_GET_SC_OPEN(ukbd, UKBDUNIT(dev), sc);

	/* FIXME: set the initial input mode (K_XLATE?) and lock state? */
	return genkbdopen(&sc->sc_gensc, sc->sc_kbd, flag, mode, p);
}

static int
ukbdclose(dev_t dev, int flag, int mode, struct proc *p)
{
	USB_GET_SC(ukbd, UKBDUNIT(dev),sc);

	return genkbdclose(&sc->sc_gensc, sc->sc_kbd, flag, mode, p);
}

static int
ukbdread(dev_t dev, struct uio *uio, int flag)
{
	USB_GET_SC(ukbd, UKBDUNIT(dev),sc);
	
	return genkbdread(&sc->sc_gensc, sc->sc_kbd, uio, flag);
}

static int
ukbdioctl(dev_t dev, u_long cmd, caddr_t arg, int flag, struct proc *p)
{
	USB_GET_SC(ukbd, UKBDUNIT(dev),sc);
	
	return genkbdioctl(&sc->sc_gensc, sc->sc_kbd, cmd, arg, flag, p);
}

static int
ukbdpoll(dev_t dev, int event, struct proc *p)
{
	USB_GET_SC(ukbd, UKBDUNIT(dev),sc);

	return genkbdpoll(&sc->sc_gensc, sc->sc_kbd, event, p);
}

#endif /* KBD_INSTALL_CDEV */

void
ukbd_intr(usbd_request_handle reqh, usbd_private_handle addr, usbd_status status)
{
	keyboard_t *kbd = (keyboard_t *)addr;

	(*kbdsw[kbd->kb_index]->intr)(kbd, (void *)status);
}

DRIVER_MODULE(ukbd, uhub, ukbd_driver, ukbd_devclass, usbd_driver_load, 0);

#include <machine/limits.h>
#include <machine/console.h>
#include <machine/clock.h>

#define UKBD_DEFAULT	0

#define KEY_ERROR	0x01

#define KEY_PRESS	0
#define KEY_RELEASE	0x400
#define KEY_INDEX(c)	((c) & ~KEY_RELEASE)

#define SCAN_PRESS	0
#define SCAN_RELEASE	0x80
#define SCAN_PREFIX_E0	0x100
#define SCAN_PREFIX_E1	0x200
#define SCAN_PREFIX_CTL	0x400
#define SCAN_PREFIX_SHIFT 0x800
#define SCAN_PREFIX	(SCAN_PREFIX_E0 | SCAN_PREFIX_E1 | SCAN_PREFIX_CTL \
			 | SCAN_PREFIX_SHIFT)
#define SCAN_CHAR(c)	((c) & 0x7f)

#define NMOD 8
static struct {
	int mask, key;
} ukbd_mods[NMOD] = {
	{ MOD_CONTROL_L, 0xe0 },
	{ MOD_CONTROL_R, 0xe4 },
	{ MOD_SHIFT_L,   0xe1 },
	{ MOD_SHIFT_R,   0xe5 },
	{ MOD_ALT_L,     0xe2 },
	{ MOD_ALT_R,     0xe6 },
	{ MOD_WIN_L,     0xe3 },
	{ MOD_WIN_R,	 0xe7 },
};

#define NN 0			/* no translation */
/* 
 * Translate USB keycodes to AT keyboard scancodes.
 */
/*
 * FIXME: Mac USB keyboard generates:
 * 0x53: keypad NumLock/Clear
 * 0x66: Power
 * 0x67: keypad =
 * 0x68: F13
 * 0x69: F14
 * 0x6a: F15
 */
static u_int8_t ukbd_trtab[256] = {
	   0,   0,   0,   0,  30,  48,  46,  32, /* 00 - 07 */
	  18,  33,  34,  35,  23,  36,  37,  38, /* 08 - 0F */
	  50,  49,  24,  25,  16,  19,  31,  20, /* 10 - 17 */
	  22,  47,  17,  45,  21,  44,   2,   3, /* 18 - 1F */
	   4,   5,   6,   7,   8,   9,  10,  11, /* 20 - 27 */
	  28,   1,  14,  15,  57,  12,  13,  26, /* 28 - 2F */
	  27,  43,  43,  39,  40,  41,  51,  52, /* 30 - 37 */
	  53,  58,  59,  60,  61,  62,  63,  64, /* 38 - 3F */
	  65,  66,  67,  68,  87,  88,  92,  70, /* 40 - 47 */
	 104, 102,  94,  96, 103,  99, 101,  98, /* 48 - 4F */
	  97, 100,  95,  69,  91,  55,  74,  78, /* 50 - 57 */
	  89,  79,  80,  81,  75,  76,  77,  71, /* 58 - 5F */
          72,  73,  82,  83,  86, 107,  NN,  NN, /* 60 - 67 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* 68 - 6F */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* 70 - 77 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* 78 - 7F */
          NN,  NN,  NN,  NN,  NN,  NN,  NN, 115, /* 80 - 87 */
         112, 125, 121, 123,  NN,  NN,  NN,  NN, /* 88 - 8F */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* 90 - 97 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* 98 - 9F */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* A0 - A7 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* A8 - AF */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* B0 - B7 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* B8 - BF */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* C0 - C7 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* C8 - CF */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* D0 - D7 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* D8 - DF */
          29,  42,  56, 105,  90,  54,  93, 106, /* E0 - E7 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* E8 - EF */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* F0 - F7 */
          NN,  NN,  NN,  NN,  NN,  NN,  NN,  NN, /* F8 - FF */
};

typedef struct ukbd_state {
	usbd_interface_handle ks_iface;	/* interface */
	usbd_pipe_handle ks_intrpipe;	/* interrupt pipe */
	struct usb_attach_arg *ks_uaa;
	int ks_ep_addr;

	struct ukbd_data ks_ndata;
	struct ukbd_data ks_odata;
	u_long		ks_ntime[NKEYCODE];
	u_long		ks_otime[NKEYCODE];

#define INPUTBUFSIZE	(NMOD + 2*NKEYCODE)
	u_int		ks_input[INPUTBUFSIZE];	/* input buffer */
	int		ks_inputs;
	int		ks_inputhead;
	int		ks_inputtail;

	int		ks_ifstate;
#define	INTRENABLED	(1 << 0)
#define	DISCONNECTED	(1 << 1)

	struct callout_handle ks_timeout_handle;

	int		ks_mode;	/* input mode (K_XLATE,K_RAW,K_CODE) */
	int		ks_flags;	/* flags */
#define COMPOSE		(1 << 0)
	int		ks_polling;
	int		ks_state;	/* shift/lock key state */
	int		ks_accents;	/* accent key index (> 0) */
	u_int		ks_composed_char; /* composed char code (> 0) */
#ifdef UKBD_EMULATE_ATSCANCODE
	u_int		ks_buffered_char[2];
#endif
} ukbd_state_t;

/* keyboard driver declaration */
static int		ukbd_configure(int flags);
static kbd_probe_t	ukbd_probe;
static kbd_init_t	ukbd_init;
static kbd_term_t	ukbd_term;
static kbd_intr_t	ukbd_interrupt;
static kbd_test_if_t	ukbd_test_if;
static kbd_enable_t	ukbd_enable;
static kbd_disable_t	ukbd_disable;
static kbd_read_t	ukbd_read;
static kbd_check_t	ukbd_check;
static kbd_read_char_t	ukbd_read_char;
static kbd_check_char_t	ukbd_check_char;
static kbd_ioctl_t	ukbd_ioctl;
static kbd_lock_t	ukbd_lock;
static kbd_clear_state_t ukbd_clear_state;
static kbd_get_state_t	ukbd_get_state;
static kbd_set_state_t	ukbd_set_state;
static kbd_poll_mode_t	ukbd_poll;

keyboard_switch_t ukbdsw = {
	ukbd_probe,
	ukbd_init,
	ukbd_term,
	ukbd_interrupt,
	ukbd_test_if,
	ukbd_enable,
	ukbd_disable,
	ukbd_read,
	ukbd_check,
	ukbd_read_char,
	ukbd_check_char,
	ukbd_ioctl,
	ukbd_lock,
	ukbd_clear_state,
	ukbd_get_state,
	ukbd_set_state,
	genkbd_get_fkeystr,
	ukbd_poll,
	genkbd_diag,
};

KEYBOARD_DRIVER(ukbd, ukbdsw, ukbd_configure);

/* local functions */
static int		ukbd_enable_intr(keyboard_t *kbd, int on,
					 usbd_intr_t *func);
static timeout_t	ukbd_timeout;

static int		ukbd_getc(ukbd_state_t *state);
static int		probe_keyboard(struct usb_attach_arg *uaa, int flags);
static int		init_keyboard(ukbd_state_t *state, int *type,
				      int flags);
static void		set_leds(ukbd_state_t *state, int leds);
static int		set_typematic(keyboard_t *kbd, int code);
#ifdef UKBD_EMULATE_ATSCANCODE
static int		keycode2scancode(int keycode, int shift, int up);
#endif

/* local variables */

/* the initial key map, accent map and fkey strings */
#ifdef UKBD_DFLT_KEYMAP
#define KBD_DFLT_KEYMAP
#include "ukbdmap.h"
#endif
#include <dev/kbd/kbdtables.h>

/* structures for the default keyboard */
static keyboard_t	default_kbd;
static ukbd_state_t	default_kbd_state;
static keymap_t		default_keymap;
static accentmap_t	default_accentmap;
static fkeytab_t	default_fkeytab[NUM_FKEYS];

/* 
 * The back door to the keyboard driver!
 * This function is called by the console driver, via the kbdio module,
 * to tickle keyboard drivers when the low-level console is being initialized.
 * Almost nothing in the kernel has been initialied yet.  Try to probe
 * keyboards if possible.
 * NOTE: because of the way the low-level conole is initialized, this routine
 * may be called more than once!!
 */
static int
ukbd_configure(int flags)
{
	return 0;

#if 0 /* not yet */
	keyboard_t *kbd;
	device_t device;
	struct usb_attach_arg *uaa;
	void *arg[4];

	device = devclass_get_device(ukbd_devclass, UKBD_DEFAULT);
	if (device == NULL)
		return 0;
	uaa = (struct usb_attach_arg *)device_get_ivars(device);
	if (uaa == NULL)
		return 0;

	/* probe the default keyboard */
	arg[0] = (void *)uaa;
	arg[1] = (void *)ukbd_intr;
	arg[2] = (void *)ukbd_disconnect;
	arg[3] = (void *)device;
	kbd = NULL;
	if (ukbd_probe(UKBD_DEFAULT, arg, flags))
		return 0;
	if (ukbd_init(UKBD_DEFAULT, &kbd, arg, flags))
		return 0;

	/* return the number of found keyboards */
	return 1;
#endif
}

/* low-level functions */

/* detect a keyboard */
static int
ukbd_probe(int unit, void *arg, int flags)
{
	void **data;
	struct usb_attach_arg *uaa;

	data = (void **)arg;
	uaa = (struct usb_attach_arg *)data[0];

	/* XXX */
	if (unit == UKBD_DEFAULT) {
		if (KBD_IS_PROBED(&default_kbd))
			return 0;
	}
	if (probe_keyboard(uaa, flags))
		return ENXIO;
	return 0;
}

/* reset and initialize the device */
static int
ukbd_init(int unit, keyboard_t **kbdp, void *arg, int flags)
{
	keyboard_t *kbd;
	ukbd_state_t *state;
	keymap_t *keymap;
	accentmap_t *accmap;
	fkeytab_t *fkeymap;
	int fkeymap_size;
	void **data = (void **)arg;
	struct usb_attach_arg *uaa = (struct usb_attach_arg *)data[0];

	/* XXX */
	if (unit == UKBD_DEFAULT) {
		*kbdp = kbd = &default_kbd;
		if (KBD_IS_INITIALIZED(kbd) && KBD_IS_CONFIGURED(kbd))
			return 0;
		state = &default_kbd_state;
		keymap = &default_keymap;
		accmap = &default_accentmap;
		fkeymap = default_fkeytab;
		fkeymap_size =
			sizeof(default_fkeytab)/sizeof(default_fkeytab[0]);
	} else if (*kbdp == NULL) {
		*kbdp = kbd = malloc(sizeof(*kbd), M_DEVBUF, M_NOWAIT);
		if (kbd == NULL)
			return ENOMEM;
		bzero(kbd, sizeof(*kbd));
		state = malloc(sizeof(*state), M_DEVBUF, M_NOWAIT);
		keymap = malloc(sizeof(key_map), M_DEVBUF, M_NOWAIT);
		accmap = malloc(sizeof(accent_map), M_DEVBUF, M_NOWAIT);
		fkeymap = malloc(sizeof(fkey_tab), M_DEVBUF, M_NOWAIT);
		fkeymap_size = sizeof(fkey_tab)/sizeof(fkey_tab[0]);
		if ((state == NULL) || (keymap == NULL) || (accmap == NULL)
		     || (fkeymap == NULL)) {
			if (state != NULL)
				free(state, M_DEVBUF);
			if (keymap != NULL)
				free(keymap, M_DEVBUF);
			if (accmap != NULL)
				free(accmap, M_DEVBUF);
			if (fkeymap != NULL)
				free(fkeymap, M_DEVBUF);
			free(kbd, M_DEVBUF);
			return ENOMEM;
		}
	} else if (KBD_IS_INITIALIZED(*kbdp) && KBD_IS_CONFIGURED(*kbdp)) {
		return 0;
	} else {
		kbd = *kbdp;
		state = (ukbd_state_t *)kbd->kb_data;
		keymap = kbd->kb_keymap;
		accmap = kbd->kb_accentmap;
		fkeymap = kbd->kb_fkeytab;
		fkeymap_size = kbd->kb_fkeytab_size;
	}

	if (!KBD_IS_PROBED(kbd)) {
		kbd_init_struct(kbd, DRIVER_NAME, KB_OTHER, unit, flags, 0, 0);
		bzero(state, sizeof(*state));
		bcopy(&key_map, keymap, sizeof(key_map));
		bcopy(&accent_map, accmap, sizeof(accent_map));
		bcopy(fkey_tab, fkeymap,
		      imin(fkeymap_size*sizeof(fkeymap[0]), sizeof(fkey_tab)));
		kbd_set_maps(kbd, keymap, accmap, fkeymap, fkeymap_size);
		kbd->kb_data = (void *)state;

		if (probe_keyboard(uaa, flags))
			return ENXIO;
		else
			KBD_FOUND_DEVICE(kbd);
		ukbd_clear_state(kbd);
		state->ks_mode = K_XLATE;
		state->ks_iface = uaa->iface;
		state->ks_uaa = uaa;
		state->ks_ifstate = 0;
		callout_handle_init(&state->ks_timeout_handle);
		/* 
		 * FIXME: set the initial value for lock keys in ks_state
		 * according to the BIOS data?
		 */
		KBD_PROBE_DONE(kbd);
	}
	if (!KBD_IS_INITIALIZED(kbd) && !(flags & KB_CONF_PROBE_ONLY)) {
		if (KBD_HAS_DEVICE(kbd)
		    && init_keyboard((ukbd_state_t *)kbd->kb_data,
				     &kbd->kb_type, kbd->kb_flags))
			return ENXIO;
		ukbd_ioctl(kbd, KDSETLED, (caddr_t)&(state->ks_state));
		KBD_INIT_DONE(kbd);
	}
	if (!KBD_IS_CONFIGURED(kbd)) {
		if (kbd_register(kbd) < 0)
			return ENXIO;
		if (ukbd_enable_intr(kbd, TRUE, (usbd_intr_t *)data[1]) == 0) {
			usbd_set_disco(state->ks_intrpipe,
				       (usbd_disco_t *)data[2], data[3]);
			ukbd_timeout((void *)kbd);
		}
		KBD_CONFIG_DONE(kbd);
	}

	return 0;
}

static int
ukbd_enable_intr(keyboard_t *kbd, int on, usbd_intr_t *func)
{
	ukbd_state_t *state = (ukbd_state_t *)kbd->kb_data;
	usbd_status r;

	if (on) {
		/* Set up interrupt pipe. */
		if (state->ks_ifstate & INTRENABLED)
			return EBUSY;
		
		state->ks_ifstate |= INTRENABLED;
		r = usbd_open_pipe_intr(state->ks_iface, state->ks_ep_addr, 
					USBD_SHORT_XFER_OK,
					&state->ks_intrpipe, kbd,
					&state->ks_ndata, 
					sizeof(state->ks_ndata), func);
		if (r != USBD_NORMAL_COMPLETION)
			return (EIO);
	} else {
		/* Disable interrupts. */
		usbd_abort_pipe(state->ks_intrpipe);
		usbd_close_pipe(state->ks_intrpipe);

		state->ks_ifstate &= ~INTRENABLED;
	}

	return (0);
}

/* finish using this keyboard */
static int
ukbd_term(keyboard_t *kbd)
{
	ukbd_state_t *state;
	int error;
	int s;

	s = splusb();

	state = (ukbd_state_t *)kbd->kb_data;
	DPRINTF(("ukbd_term: ks_ifstate=0x%x\n", state->ks_ifstate));

	untimeout(ukbd_timeout, (void *)kbd, state->ks_timeout_handle);
	callout_handle_init(&state->ks_timeout_handle);

	if (state->ks_ifstate & INTRENABLED)
		ukbd_enable_intr(kbd, FALSE, NULL);
	if (state->ks_ifstate & INTRENABLED) {
		splx(s);
		DPRINTF(("ukbd_term: INTRENABLED!\n"));
		return ENXIO;
	}

	error = kbd_unregister(kbd);
	DPRINTF(("ukbd_term: kbd_unregister() %d\n", error));
	if (error == 0) {
		kbd->kb_flags = 0;
		if (kbd != &default_kbd) {
			free(kbd->kb_keymap, M_DEVBUF);
			free(kbd->kb_accentmap, M_DEVBUF);
			free(kbd->kb_fkeytab, M_DEVBUF);
			free(state, M_DEVBUF);
			free(kbd, M_DEVBUF);
		}
	}

	splx(s);
	return error;
}


/* keyboard interrupt routine */

static void
ukbd_timeout(void *arg)
{
	keyboard_t *kbd;
	ukbd_state_t *state;
	int s;

	kbd = (keyboard_t *)arg;
	state = (ukbd_state_t *)kbd->kb_data;
	s = splusb();
	(*kbdsw[kbd->kb_index]->intr)(kbd, (void *)USBD_NORMAL_COMPLETION);
	state->ks_timeout_handle = timeout(ukbd_timeout, arg, hz/40);
	splx(s);
}

static int
ukbd_interrupt(keyboard_t *kbd, void *arg)
{
	usbd_status status = (usbd_status)arg;
	ukbd_state_t *state = (ukbd_state_t *)kbd->kb_data;
	struct ukbd_data *ud = &state->ks_ndata;
	struct timeval tv;
	u_long now;
	int mod, omod;
	int key, c;
	int i, j;

#define ADDKEY1(c) 		\
	if (state->ks_inputs < INPUTBUFSIZE) {				\
		state->ks_input[state->ks_inputtail] = (c);		\
		++state->ks_inputs;					\
		state->ks_inputtail = (state->ks_inputtail + 1)%INPUTBUFSIZE; \
	}

	DPRINTFN(5, ("ukbd_intr: status=%d\n", status));
	if (status == USBD_CANCELLED)
		return 0;

	if (status != USBD_NORMAL_COMPLETION) {
		DPRINTF(("ukbd_intr: status=%d\n", status));
		usbd_clear_endpoint_stall_async(state->ks_intrpipe);
		return 0;
	}

	if (ud->keycode[0] == KEY_ERROR)
		return 0;		/* ignore  */

	getmicrouptime(&tv);
	now = (u_long)tv.tv_sec*1000 + (u_long)tv.tv_usec/1000;

	mod = ud->modifiers;
	omod = state->ks_odata.modifiers;
	if (mod != omod) {
		for (i = 0; i < NMOD; i++)
			if (( mod & ukbd_mods[i].mask) != 
			    (omod & ukbd_mods[i].mask))
				ADDKEY1(ukbd_mods[i].key | 
				       (mod & ukbd_mods[i].mask 
					  ? KEY_PRESS : KEY_RELEASE));
	}

	/* Check for released keys. */
	for (i = 0; i < NKEYCODE; i++) {
		key = state->ks_odata.keycode[i];
		if (key == 0)
			break;
		for (j = 0; j < NKEYCODE; j++) {
			if (ud->keycode[j] == 0)
				break;
			if (key == ud->keycode[j])
				goto rfound;
		}
		ADDKEY1(key | KEY_RELEASE);
	rfound:
		;
	}
		
	/* Check for pressed keys. */
	for (i = 0; i < NKEYCODE; i++) {
		key = ud->keycode[i];
		if (key == 0)
			break;
		state->ks_ntime[i] = now + kbd->kb_delay1;
		for (j = 0; j < NKEYCODE; j++) {
			if (state->ks_odata.keycode[j] == 0)
				break;
			if (key == state->ks_odata.keycode[j]) {
				state->ks_ntime[i] = state->ks_otime[j];
				if (state->ks_otime[j] > now)
					goto pfound;
				state->ks_ntime[i] = now + kbd->kb_delay2;
				break;
			}
		}
		ADDKEY1(key | KEY_PRESS);
	pfound:
		;
	}

	state->ks_odata = *ud;
	bcopy(state->ks_ntime, state->ks_otime, sizeof(state->ks_ntime));
	if (state->ks_inputs <= 0)
		return 0;

#ifdef UKBD_DEBUG
	for (i = state->ks_inputhead, j = 0; j < state->ks_inputs; ++j,
		i = (i + 1)%INPUTBUFSIZE) {
		c = state->ks_input[i];
		printf("0x%x (%d) %s\n", c, c,
			(c & KEY_RELEASE) ? "released":"pressed");
	}
	if (ud->modifiers)
		printf("mod:0x%04x ", ud->modifiers);
        for (i = 0; i < NKEYCODE; i++) {
		if (ud->keycode[i])
			printf("%d ", ud->keycode[i]);
	}
	printf("\n");
#endif /* UKBD_DEBUG */

	if (state->ks_polling)
		return 0;

	if (KBD_IS_ACTIVE(kbd) && KBD_IS_BUSY(kbd)) {
		/* let the callback function to process the input */
		(*kbd->kb_callback.kc_func)(kbd, KBDIO_KEYINPUT,
					    kbd->kb_callback.kc_arg);
	} else {
		/* read and discard the input; no one is waiting for it */
		do {
			c = ukbd_read_char(kbd, FALSE);
		} while (c != NOKEY);
	}

	return 0;
}

static int
ukbd_getc(ukbd_state_t *state)
{
	usbd_lock_token l;
	int c;
	int s;

	if (state->ks_polling) {
		DPRINTFN(1,("ukbd_getc: polling\n"));
		l = usbd_lock();
		while (state->ks_inputs <= 0)
			usbd_dopoll(state->ks_iface);
		usbd_unlock(l);
	}
	s = splusb();
	if (state->ks_inputs <= 0) {
		c = -1;
	} else {
		c = state->ks_input[state->ks_inputhead];
		--state->ks_inputs;
		state->ks_inputhead = (state->ks_inputhead + 1)%INPUTBUFSIZE;
	}
	splx(s);
	return c;
}

/* test the interface to the device */
static int
ukbd_test_if(keyboard_t *kbd)
{
	return 0;
}

/* 
 * Enable the access to the device; until this function is called,
 * the client cannot read from the keyboard.
 */
static int
ukbd_enable(keyboard_t *kbd)
{
	int s;

	s = splusb();
	KBD_ACTIVATE(kbd);
	splx(s);
	return 0;
}

/* disallow the access to the device */
static int
ukbd_disable(keyboard_t *kbd)
{
	int s;

	s = splusb();
	KBD_DEACTIVATE(kbd);
	splx(s);
	return 0;
}

/* read one byte from the keyboard if it's allowed */
static int
ukbd_read(keyboard_t *kbd, int wait)
{
	ukbd_state_t *state;
	int usbcode;
#ifdef UKBD_EMULATE_ATSCANCODE
	int keycode;
	int scancode;
#endif

	state = (ukbd_state_t *)kbd->kb_data;
#ifdef UKBD_EMULATE_ATSCANCODE
	if (state->ks_buffered_char[0]) {
		scancode = state->ks_buffered_char[0];
		if (scancode & SCAN_PREFIX) {
			state->ks_buffered_char[0] = scancode & ~SCAN_PREFIX;
			return ((scancode & SCAN_PREFIX_E0) ? 0xe0 : 0xe1);
		} else {
			state->ks_buffered_char[0] = state->ks_buffered_char[1];
			state->ks_buffered_char[1] = 0;
			return scancode;
		}
	}
#endif /* UKBD_EMULATE_ATSCANCODE */

	/* XXX */
	usbcode = ukbd_getc(state);
	if (!KBD_IS_ACTIVE(kbd) || (usbcode == -1))
		return -1;
#ifdef UKBD_EMULATE_ATSCANCODE
	keycode = ukbd_trtab[KEY_INDEX(usbcode)];
	if (keycode == NN)
		return -1;

	scancode = keycode2scancode(keycode, state->ks_ndata.modifiers,
				    usbcode & KEY_RELEASE);
	if (scancode & SCAN_PREFIX) {
		if (scancode & SCAN_PREFIX_CTL) {
			state->ks_buffered_char[0] = 
				0x1d | (scancode & SCAN_RELEASE); /* Ctrl */
			state->ks_buffered_char[1] = scancode & ~SCAN_PREFIX;
		} else if (scancode & SCAN_PREFIX_SHIFT) {
			state->ks_buffered_char[0] = 
				0x2a | (scancode & SCAN_RELEASE); /* Shift */
			state->ks_buffered_char[1] = 
				scancode & ~SCAN_PREFIX_SHIFT;
		} else {
			state->ks_buffered_char[0] = scancode & ~SCAN_PREFIX;
			state->ks_buffered_char[1] = 0;
		}
		return ((scancode & SCAN_PREFIX_E0) ? 0xe0 : 0xe1);
	}
	return scancode;
#else /* !UKBD_EMULATE_ATSCANCODE */
	return usbcode;
#endif /* UKBD_EMULATE_ATSCANCODE */
}

/* check if data is waiting */
static int
ukbd_check(keyboard_t *kbd)
{
	if (!KBD_IS_ACTIVE(kbd))
		return FALSE;
#ifdef UKBD_EMULATE_ATSCANCODE
	if (((ukbd_state_t *)kbd->kb_data)->ks_buffered_char[0])
		return TRUE;
#endif
	if (((ukbd_state_t *)kbd->kb_data)->ks_inputs > 0)
		return TRUE;
	return FALSE;
}

/* read char from the keyboard */
static u_int
ukbd_read_char(keyboard_t *kbd, int wait)
{
	ukbd_state_t *state;
	u_int action;
	int usbcode;
	int keycode;
#ifdef UKBD_EMULATE_ATSCANCODE
	int scancode;
#endif

	state = (ukbd_state_t *)kbd->kb_data;
next_code:
	/* do we have a composed char to return? */
	if (!(state->ks_flags & COMPOSE) && (state->ks_composed_char > 0)) {
		action = state->ks_composed_char;
		state->ks_composed_char = 0;
		if (action > UCHAR_MAX)
			return ERRKEY;
		return action;
	}

#ifdef UKBD_EMULATE_ATSCANCODE
	/* do we have a pending raw scan code? */
	if (state->ks_mode == K_RAW) {
		if (state->ks_buffered_char[0]) {
			scancode = state->ks_buffered_char[0];
			if (scancode & SCAN_PREFIX) {
				state->ks_buffered_char[0] =
					scancode & ~SCAN_PREFIX;
				return ((scancode & SCAN_PREFIX_E0) ? 0xe0 : 0xe1);
			} else {
				state->ks_buffered_char[0] =
					state->ks_buffered_char[1];
				state->ks_buffered_char[1] = 0;
				return scancode;
			}
		}
	}
#endif /* UKBD_EMULATE_ATSCANCODE */

	/* see if there is something in the keyboard port */
	/* XXX */
	usbcode = ukbd_getc(state);
	if (usbcode == -1)
		return NOKEY;

#ifdef UKBD_EMULATE_ATSCANCODE
	/* USB key index -> key code -> AT scan code */
	keycode = ukbd_trtab[KEY_INDEX(usbcode)];
	if (keycode == NN)
		return NOKEY;

	/* return an AT scan code for the K_RAW mode */
	if (state->ks_mode == K_RAW) {
		scancode = keycode2scancode(keycode, state->ks_ndata.modifiers,
					    usbcode & KEY_RELEASE);
		if (scancode & SCAN_PREFIX) {
			if (scancode & SCAN_PREFIX_CTL) {
				state->ks_buffered_char[0] = 
					0x1d | (scancode & SCAN_RELEASE);
				state->ks_buffered_char[1] =
					scancode & ~SCAN_PREFIX;
			} else if (scancode & SCAN_PREFIX_SHIFT) {
				state->ks_buffered_char[0] = 
					0x2a | (scancode & SCAN_RELEASE);
				state->ks_buffered_char[1] =
					scancode & ~SCAN_PREFIX_SHIFT;
			} else {
				state->ks_buffered_char[0] =
					scancode & ~SCAN_PREFIX;
				state->ks_buffered_char[1] = 0;
			}
			return ((scancode & SCAN_PREFIX_E0) ? 0xe0 : 0xe1);
		}
		return scancode;
	}
#else /* !UKBD_EMULATE_ATSCANCODE */
	/* return the byte as is for the K_RAW mode */
	if (state->ks_mode == K_RAW)
		return usbcode;

	/* USB key index -> key code */
	keycode = ukbd_trtab[KEY_INDEX(usbcode)];
	if (keycode == NN)
		return NOKEY;
#endif /* UKBD_EMULATE_ATSCANCODE */

	switch (keycode) {
	case 0x38:	/* left alt (compose key) */
		if (usbcode & KEY_RELEASE) {
			if (state->ks_flags & COMPOSE) {
				state->ks_flags &= ~COMPOSE;
				if (state->ks_composed_char > UCHAR_MAX)
					state->ks_composed_char = 0;
			}
		} else {
			if (!(state->ks_flags & COMPOSE)) {
				state->ks_flags |= COMPOSE;
				state->ks_composed_char = 0;
			}
		}
		break;
	/* XXX: I don't like these... */
	case 0x5c:	/* print screen */
		if (state->ks_flags & ALTS)
			keycode = 0x54;	/* sysrq */
		break;
	case 0x68:	/* pause/break */
		if (state->ks_flags & CTLS)
			keycode = 0x6c;	/* break */
		break;
	}

	/* return the key code in the K_CODE mode */
	if (usbcode & KEY_RELEASE)
		keycode |= SCAN_RELEASE;
	if (state->ks_mode == K_CODE)
		return keycode;

	/* compose a character code */
	if (state->ks_flags & COMPOSE) {
		switch (keycode) {
		/* key pressed, process it */
		case 0x47: case 0x48: case 0x49:	/* keypad 7,8,9 */
			state->ks_composed_char *= 10;
			state->ks_composed_char += keycode - 0x40;
			if (state->ks_composed_char > UCHAR_MAX)
				return ERRKEY;
			goto next_code;
		case 0x4B: case 0x4C: case 0x4D:	/* keypad 4,5,6 */
			state->ks_composed_char *= 10;
			state->ks_composed_char += keycode - 0x47;
			if (state->ks_composed_char > UCHAR_MAX)
				return ERRKEY;
			goto next_code;
		case 0x4F: case 0x50: case 0x51:	/* keypad 1,2,3 */
			state->ks_composed_char *= 10;
			state->ks_composed_char += keycode - 0x4E;
			if (state->ks_composed_char > UCHAR_MAX)
				return ERRKEY;
			goto next_code;
		case 0x52:				/* keypad 0 */
			state->ks_composed_char *= 10;
			if (state->ks_composed_char > UCHAR_MAX)
				return ERRKEY;
			goto next_code;

		/* key released, no interest here */
		case SCAN_RELEASE | 0x47:
		case SCAN_RELEASE | 0x48:
		case SCAN_RELEASE | 0x49:		/* keypad 7,8,9 */
		case SCAN_RELEASE | 0x4B:
		case SCAN_RELEASE | 0x4C:
		case SCAN_RELEASE | 0x4D:		/* keypad 4,5,6 */
		case SCAN_RELEASE | 0x4F:
		case SCAN_RELEASE | 0x50:
		case SCAN_RELEASE | 0x51:		/* keypad 1,2,3 */
		case SCAN_RELEASE | 0x52:		/* keypad 0 */
			goto next_code;

		case 0x38:				/* left alt key */
			break;

		default:
			if (state->ks_composed_char > 0) {
				state->ks_flags &= ~COMPOSE;
				state->ks_composed_char = 0;
				return ERRKEY;
			}
			break;
		}
	}

	/* keycode to key action */
	action = genkbd_keyaction(kbd, SCAN_CHAR(keycode),
				  keycode & SCAN_RELEASE, &state->ks_state,
				  &state->ks_accents);
	if (action == NOKEY)
		goto next_code;
	else
		return action;
}

/* check if char is waiting */
static int
ukbd_check_char(keyboard_t *kbd)
{
	ukbd_state_t *state;

	if (!KBD_IS_ACTIVE(kbd))
		return FALSE;
	state = (ukbd_state_t *)kbd->kb_data;
	if (!(state->ks_flags & COMPOSE) && (state->ks_composed_char > 0))
		return TRUE;
	if (state->ks_inputs > 0)
		return TRUE;
	return FALSE;
}

/* some useful control functions */
static int
ukbd_ioctl(keyboard_t *kbd, u_long cmd, caddr_t arg)
{
	/* trasnlate LED_XXX bits into the device specific bits */
	static u_char ledmap[8] = {
		0, 2, 1, 3, 4, 6, 5, 7,
	};
	ukbd_state_t *state = kbd->kb_data;
	int s;
	int i;

	s = splusb();
	switch (cmd) {

	case KDGKBMODE:		/* get keyboard mode */
		*(int *)arg = state->ks_mode;
		break;
	case KDSKBMODE:		/* set keyboard mode */
		switch (*(int *)arg) {
		case K_XLATE:
			if (state->ks_mode != K_XLATE) {
				/* make lock key state and LED state match */
				state->ks_state &= ~LOCK_MASK;
				state->ks_state |= KBD_LED_VAL(kbd);
			}
			/* FALL THROUGH */
		case K_RAW:
		case K_CODE:
			if (state->ks_mode != *(int *)arg) {
				ukbd_clear_state(kbd);
				state->ks_mode = *(int *)arg;
			}
			break;
		default:
			splx(s);
			return EINVAL;
		}
		break;

	case KDGETLED:		/* get keyboard LED */
		*(int *)arg = KBD_LED_VAL(kbd);
		break;
	case KDSETLED:		/* set keyboard LED */
		/* NOTE: lock key state in ks_state won't be changed */
		if (*(int *)arg & ~LOCK_MASK) {
			splx(s);
			return EINVAL;
		}
		i = *(int *)arg;
		/* replace CAPS LED with ALTGR LED for ALTGR keyboards */
		if (kbd->kb_keymap->n_keys > ALTGR_OFFSET) {
			if (i & ALKED)
				i |= CLKED;
			else
				i &= ~CLKED;
		}
		if (KBD_HAS_DEVICE(kbd)) {
			set_leds(state, ledmap[i & LED_MASK]);
			/* XXX: error check? */
		}
		KBD_LED_VAL(kbd) = *(int *)arg;
		break;

	case KDGKBSTATE:	/* get lock key state */
		*(int *)arg = state->ks_state & LOCK_MASK;
		break;
	case KDSKBSTATE:	/* set lock key state */
		if (*(int *)arg & ~LOCK_MASK) {
			splx(s);
			return EINVAL;
		}
		state->ks_state &= ~LOCK_MASK;
		state->ks_state |= *(int *)arg;
		splx(s);
		/* set LEDs and quit */
		return ukbd_ioctl(kbd, KDSETLED, arg);

	case KDSETREPEAT:	/* set keyboard repeat rate (new interface) */
		splx(s);
		if (!KBD_HAS_DEVICE(kbd))
			return 0;
		if (((int *)arg)[1] < 0)
			return EINVAL;
		if (((int *)arg)[0] < 0)
			return EINVAL;
		else if (((int *)arg)[0] == 0)	/* fastest possible value */
			kbd->kb_delay1 = 200;
		else
			kbd->kb_delay1 = ((int *)arg)[0];
		kbd->kb_delay2 = ((int *)arg)[1];
		return 0;

	case KDSETRAD:		/* set keyboard repeat rate (old interface) */
		splx(s);
		return set_typematic(kbd, *(int *)arg);

	case PIO_KEYMAP:	/* set keyboard translation table */
	case PIO_KEYMAPENT:	/* set keyboard translation table entry */
	case PIO_DEADKEYMAP:	/* set accent key translation table */
		state->ks_accents = 0;
		/* FALL THROUGH */
	default:
		splx(s);
		return genkbd_commonioctl(kbd, cmd, arg);
	}

	splx(s);
	return 0;
}

/* lock the access to the keyboard */
static int
ukbd_lock(keyboard_t *kbd, int lock)
{
	/* XXX ? */
	return TRUE;
}

/* clear the internal state of the keyboard */
static void
ukbd_clear_state(keyboard_t *kbd)
{
	ukbd_state_t *state;

	state = (ukbd_state_t *)kbd->kb_data;
	state->ks_flags = 0;
	state->ks_polling = 0;
	state->ks_state &= LOCK_MASK;	/* preserve locking key state */
	state->ks_accents = 0;
	state->ks_composed_char = 0;
#ifdef UKBD_EMULATE_ATSCANCODE
	state->ks_buffered_char[0] = 0;
	state->ks_buffered_char[1] = 0;
#endif
	bzero(&state->ks_ndata, sizeof(state->ks_ndata));
	bzero(&state->ks_odata, sizeof(state->ks_odata));
	bzero(&state->ks_ntime, sizeof(state->ks_ntime));
	bzero(&state->ks_otime, sizeof(state->ks_otime));
}

/* save the internal state */
static int
ukbd_get_state(keyboard_t *kbd, void *buf, size_t len)
{
	if (len == 0)
		return sizeof(ukbd_state_t);
	if (len < sizeof(ukbd_state_t))
		return -1;
	bcopy(kbd->kb_data, buf, sizeof(ukbd_state_t));
	return 0;
}

/* set the internal state */
static int
ukbd_set_state(keyboard_t *kbd, void *buf, size_t len)
{
	if (len < sizeof(ukbd_state_t))
		return ENOMEM;
	bcopy(buf, kbd->kb_data, sizeof(ukbd_state_t));
	return 0;
}

static int
ukbd_poll(keyboard_t *kbd, int on)
{
	ukbd_state_t *state;
	int s;

	state = (ukbd_state_t *)kbd->kb_data;

	s = splusb();
	if (on) {
		if (state->ks_polling == 0)
			usbd_set_polling(state->ks_iface, on);
		++state->ks_polling;
	} else {
		--state->ks_polling;
		if (state->ks_polling == 0)
			usbd_set_polling(state->ks_iface, on);
	}
	splx(s);
	return 0;
}

/* local functions */

static int
probe_keyboard(struct usb_attach_arg *uaa, int flags)
{
	usb_interface_descriptor_t *id;
	
	if (!uaa->iface)	/* we attach to ifaces only */
		return EINVAL;

	/* Check that this is a keyboard that speaks the boot protocol. */
	id = usbd_get_interface_descriptor(uaa->iface);
	if (id
	    && id->bInterfaceClass == UCLASS_HID
	    && id->bInterfaceSubClass == USUBCLASS_BOOT
	    && id->bInterfaceProtocol == UPROTO_BOOT_KEYBOARD)
		return 0;	/* found it */

	return EINVAL;
}

static int
init_keyboard(ukbd_state_t *state, int *type, int flags)
{
	usb_endpoint_descriptor_t *ed;
	usbd_status r;
	
	*type = KB_OTHER;

	state->ks_ifstate |= DISCONNECTED;

	ed = usbd_interface2endpoint_descriptor(state->ks_iface, 0);
	if (!ed) {
		printf("ukbd: could not read endpoint descriptor\n");
		return EIO;
	}

	DPRINTFN(10,("ukbd:init_keyboard: \
bLength=%d bDescriptorType=%d bEndpointAddress=%d-%s bmAttributes=%d wMaxPacketSize=%d bInterval=%d\n",
	       ed->bLength, ed->bDescriptorType, ed->bEndpointAddress & UE_ADDR,
	       ed->bEndpointAddress & UE_IN ? "in" : "out",
	       ed->bmAttributes & UE_XFERTYPE,
	       UGETW(ed->wMaxPacketSize), ed->bInterval));

	if ((ed->bEndpointAddress & UE_IN) != UE_IN ||
	    (ed->bmAttributes & UE_XFERTYPE) != UE_INTERRUPT) {
		printf("ukbd: unexpected endpoint\n");
		return EINVAL;
	}

	if ((usbd_get_quirks(state->ks_uaa->device)->uq_flags & UQ_NO_SET_PROTO) == 0) {
		r = usbd_set_protocol(state->ks_iface, 0);
		DPRINTFN(5, ("ukbd:init_keyboard: protocol set\n"));
		if (r != USBD_NORMAL_COMPLETION) {
			printf("ukbd: set protocol failed\n");
			return EIO;
		}
	}
	/* Ignore if SETIDLE fails since it is not crucial. */
	usbd_set_idle(state->ks_iface, 0, 0);

	state->ks_ep_addr = ed->bEndpointAddress;
	state->ks_ifstate &= ~DISCONNECTED;

	return 0;
}

static void
set_leds(ukbd_state_t *state, int leds)
{
	u_int8_t res = leds;

	DPRINTF(("ukbd:set_leds: state=%p leds=%d\n", state, leds));

	usbd_set_report_async(state->ks_iface, UHID_OUTPUT_REPORT, 0, &res, 1);
}

static int
set_typematic(keyboard_t *kbd, int code)
{
	static int delays[] = { 250, 500, 750, 1000 };
	static int rates[] = {  34,  38,  42,  46,  50,  55,  59,  63,
				68,  76,  84,  92, 100, 110, 118, 126,
			       136, 152, 168, 184, 200, 220, 236, 252,
			       272, 304, 336, 368, 400, 440, 472, 504 };

	if (code & ~0x7f)
		return EINVAL;
	kbd->kb_delay1 = delays[(code >> 5) & 3];
	kbd->kb_delay2 = rates[code & 0x1f];
	return 0;
}

#ifdef UKBD_EMULATE_ATSCANCODE
static int
keycode2scancode(int keycode, int shift, int up)
{
	static int scan[] = {
		0x1c, 0x1d, 0x35, 
		0x37 | SCAN_PREFIX_SHIFT, /* PrintScreen */
		0x38, 0x47, 0x48, 0x49, 0x4b, 0x4d, 0x4f, 
		0x50, 0x51, 0x52, 0x53, 
		0x46, 	/* XXX Pause/Break */
		0x5b, 0x5c, 0x5d,
	};
	int scancode;

	scancode = keycode;
	if ((keycode >= 89) && (keycode < 89 + sizeof(scan)/sizeof(scan[0])))
		scancode = scan[keycode - 89] | SCAN_PREFIX_E0;
	/* Pause/Break */
	if ((keycode == 104) && !(shift & (MOD_CONTROL_L | MOD_CONTROL_R)))
		scancode = 0x45 | SCAN_PREFIX_E1 | SCAN_PREFIX_CTL;
	if (shift & (MOD_SHIFT_L | MOD_SHIFT_R))
		scancode &= ~SCAN_PREFIX_SHIFT;
	return (scancode | (up ? SCAN_RELEASE : SCAN_PRESS));
}
#endif /* UKBD_EMULATE_ATSCANCODE */
