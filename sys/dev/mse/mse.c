/*
 * Copyright 1992 by the University of Guelph
 *
 * Permission to use, copy and modify this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation.
 * University of Guelph makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * $FreeBSD$
 */
/*
 * Driver for the Logitech and ATI Inport Bus mice for use with 386bsd and
 * the X386 port, courtesy of
 * Rick Macklem, rick@snowhite.cis.uoguelph.ca
 * Caveats: The driver currently uses spltty(), but doesn't use any
 * generic tty code. It could use splmse() (that only masks off the
 * bus mouse interrupt, but that would require hacking in i386/isa/icu.s.
 * (This may be worth the effort, since the Logitech generates 30/60
 * interrupts/sec continuously while it is open.)
 * NB: The ATI has NOT been tested yet!
 */

/*
 * Modification history:
 * Sep 6, 1994 -- Lars Fredriksen(fredriks@mcs.com)
 *   improved probe based on input from Logitech.
 *
 * Oct 19, 1992 -- E. Stark (stark@cs.sunysb.edu)
 *   fixes to make it work with Microsoft InPort busmouse
 *
 * Jan, 1993 -- E. Stark (stark@cs.sunysb.edu)
 *   added patches for new "select" interface
 *
 * May 4, 1993 -- E. Stark (stark@cs.sunysb.edu)
 *   changed position of some spl()'s in mseread
 *
 * October 8, 1993 -- E. Stark (stark@cs.sunysb.edu)
 *   limit maximum negative x/y value to -127 to work around XFree problem
 *   that causes spurious button pushes.
 */

#include "mse.h"
#if NMSE > 0
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/uio.h>

#include <machine/clock.h>
#include <machine/mouse.h>

#include <i386/isa/isa_device.h>

/* driver configuration flags (config) */
#define MSE_CONFIG_ACCEL	0x00f0  /* acceleration factor */
#define MSE_CONFIG_FLAGS	(MSE_CONFIG_ACCEL)

static int mseprobe(struct isa_device *);
static int mseattach(struct isa_device *);

struct	isa_driver msedriver = {
	mseprobe, mseattach, "mse"
};

static	d_open_t	mseopen;
static	d_close_t	mseclose;
static	d_read_t	mseread;
static  d_ioctl_t	mseioctl;
static	d_poll_t	msepoll;

#define CDEV_MAJOR 27
static struct cdevsw mse_cdevsw = {
	/* open */	mseopen,
	/* close */	mseclose,
	/* read */	mseread,
	/* write */	nowrite,
	/* ioctl */	mseioctl,
	/* poll */	msepoll,
	/* mmap */	nommap,
	/* strategy */	nostrategy,
	/* name */	"mse",
	/* maj */	CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	0,
	/* bmaj */	-1
};

static ointhand2_t mseintr;

/*
 * Software control structure for mouse. The sc_enablemouse(),
 * sc_disablemouse() and sc_getmouse() routines must be called spl'd().
 */
static struct mse_softc {
	int	sc_flags;
	int	sc_mousetype;
	struct	selinfo sc_selp;
	u_int	sc_port;
	void	(*sc_enablemouse) __P((u_int port));
	void	(*sc_disablemouse) __P((u_int port));
	void	(*sc_getmouse) __P((u_int port, int *dx, int *dy, int *but));
	int	sc_deltax;
	int	sc_deltay;
	int	sc_obuttons;
	int	sc_buttons;
	int	sc_bytesread;
	u_char	sc_bytes[MOUSE_SYS_PACKETSIZE];
	mousehw_t	hw;
	mousemode_t	mode;
	mousestatus_t	status;
} mse_sc[NMSE];

/* Flags */
#define	MSESC_OPEN	0x1
#define	MSESC_WANT	0x2

/* and Mouse Types */
#define	MSE_NONE	0	/* don't move this! */
#define	MSE_LOGITECH	0x1
#define	MSE_ATIINPORT	0x2
#define	MSE_LOGI_SIG	0xA5

#define	MSE_PORTA	0
#define	MSE_PORTB	1
#define	MSE_PORTC	2
#define	MSE_PORTD	3

#define	MSE_UNIT(dev)		(minor(dev) >> 1)
#define	MSE_NBLOCKIO(dev)	(minor(dev) & 0x1)

/*
 * Logitech bus mouse definitions
 */
#define	MSE_SETUP	0x91	/* What does this mean? */
				/* The definition for the control port */
				/* is as follows: */

				/* D7 	 =  Mode set flag (1 = active) 	*/
				/* D6,D5 =  Mode selection (port A) 	*/
				/* 	    00 = Mode 0 = Basic I/O 	*/
				/* 	    01 = Mode 1 = Strobed I/O 	*/
				/* 	    10 = Mode 2 = Bi-dir bus 	*/
				/* D4	 =  Port A direction (1 = input)*/
				/* D3	 =  Port C (upper 4 bits) 	*/
				/*	    direction. (1 = input)	*/
				/* D2	 =  Mode selection (port B & C) */
				/*	    0 = Mode 0 = Basic I/O	*/
				/*	    1 = Mode 1 = Strobed I/O	*/
				/* D1	 =  Port B direction (1 = input)*/
				/* D0	 =  Port C (lower 4 bits)	*/
				/*	    direction. (1 = input)	*/

				/* So 91 means Basic I/O on all 3 ports,*/
				/* Port A is an input port, B is an 	*/
				/* output port, C is split with upper	*/
				/* 4 bits being an output port and lower*/
				/* 4 bits an input port, and enable the */
				/* sucker.				*/
				/* Courtesy Intel 8255 databook. Lars   */
#define	MSE_HOLD	0x80
#define	MSE_RXLOW	0x00
#define	MSE_RXHIGH	0x20
#define	MSE_RYLOW	0x40
#define	MSE_RYHIGH	0x60
#define	MSE_DISINTR	0x10
#define MSE_INTREN	0x00

static int mse_probelogi __P((struct isa_device *idp));
static void mse_disablelogi __P((u_int port));
static void mse_getlogi __P((u_int port, int *dx, int *dy, int *but));
static void mse_enablelogi __P((u_int port));

/*
 * ATI Inport mouse definitions
 */
#define	MSE_INPORT_RESET	0x80
#define	MSE_INPORT_STATUS	0x00
#define	MSE_INPORT_DX		0x01
#define	MSE_INPORT_DY		0x02
#define	MSE_INPORT_MODE		0x07
#define	MSE_INPORT_HOLD		0x20
#define	MSE_INPORT_INTREN	0x09

static int mse_probeati __P((struct isa_device *idp));
static void mse_enableati __P((u_int port));
static void mse_disableati __P((u_int port));
static void mse_getati __P((u_int port, int *dx, int *dy, int *but));

#define	MSEPRI	(PZERO + 3)

/*
 * Table of mouse types.
 * Keep the Logitech last, since I haven't figured out how to probe it
 * properly yet. (Someday I'll have the documentation.)
 */
static struct mse_types {
	int	m_type;		/* Type of bus mouse */
	int	(*m_probe) __P((struct isa_device *idp));
				/* Probe routine to test for it */
	void	(*m_enable) __P((u_int port));
				/* Start routine */
	void	(*m_disable) __P((u_int port));
				/* Disable interrupts routine */
	void	(*m_get) __P((u_int port, int *dx, int *dy, int *but));
				/* and get mouse status */
	mousehw_t   m_hw;	/* buttons iftype type model hwid */
	mousemode_t m_mode;	/* proto rate res accel level size mask */
} mse_types[] = {
	{ MSE_ATIINPORT, 
	  mse_probeati, mse_enableati, mse_disableati, mse_getati,
	  { 2, MOUSE_IF_INPORT, MOUSE_MOUSE, MOUSE_MODEL_GENERIC, 0, },
	  { MOUSE_PROTO_INPORT, -1, -1, 0, 0, MOUSE_MSC_PACKETSIZE, 
	    { MOUSE_MSC_SYNCMASK, MOUSE_MSC_SYNC, }, }, },
	{ MSE_LOGITECH, 
	  mse_probelogi, mse_enablelogi, mse_disablelogi, mse_getlogi,
	  { 2, MOUSE_IF_BUS, MOUSE_MOUSE, MOUSE_MODEL_GENERIC, 0, },
	  { MOUSE_PROTO_BUS, -1, -1, 0, 0, MOUSE_MSC_PACKETSIZE, 
	    { MOUSE_MSC_SYNCMASK, MOUSE_MSC_SYNC, }, }, },
	{ 0, },
};

int
mseprobe(idp)
	register struct isa_device *idp;
{
	register struct mse_softc *sc = &mse_sc[idp->id_unit];
	register int i;
	static int once;

	if (!once++)
		cdevsw_add(&mse_cdevsw);
	/*
	 * Check for each mouse type in the table.
	 */
	i = 0;
	while (mse_types[i].m_type) {
		if ((*mse_types[i].m_probe)(idp)) {
			sc->sc_mousetype = mse_types[i].m_type;
			sc->sc_enablemouse = mse_types[i].m_enable;
			sc->sc_disablemouse = mse_types[i].m_disable;
			sc->sc_getmouse = mse_types[i].m_get;
			sc->hw = mse_types[i].m_hw;
			sc->mode = mse_types[i].m_mode;
			return (1);
		}
		i++;
	}
	return (0);
}

int
mseattach(idp)
	struct isa_device *idp;
{
	int unit = idp->id_unit;
	struct mse_softc *sc = &mse_sc[unit];

	idp->id_ointr = mseintr;
	sc->sc_port = idp->id_iobase;
	sc->mode.accelfactor = (idp->id_flags & MSE_CONFIG_ACCEL) >> 4;
	make_dev(&mse_cdevsw, unit << 1, 0, 0, 0600, "mse%d", unit);
	make_dev(&mse_cdevsw, (unit<<1)+1, 0, 0, 0600, "nmse%d", unit);
	return (1);
}

/*
 * Exclusive open the mouse, initialize it and enable interrupts.
 */
static	int
mseopen(dev, flags, fmt, p)
	dev_t dev;
	int flags;
	int fmt;
	struct proc *p;
{
	register struct mse_softc *sc;
	int s;

	if (MSE_UNIT(dev) >= NMSE)
		return (ENXIO);
	sc = &mse_sc[MSE_UNIT(dev)];
	if (sc->sc_mousetype == MSE_NONE)
		return (ENXIO);
	if (sc->sc_flags & MSESC_OPEN)
		return (EBUSY);
	sc->sc_flags |= MSESC_OPEN;
	sc->sc_obuttons = sc->sc_buttons = MOUSE_MSC_BUTTONS;
	sc->sc_deltax = sc->sc_deltay = 0;
	sc->sc_bytesread = sc->mode.packetsize = MOUSE_MSC_PACKETSIZE;
	sc->mode.level = 0;
	sc->status.flags = 0;
	sc->status.button = sc->status.obutton = 0;
	sc->status.dx = sc->status.dy = sc->status.dz = 0;

	/*
	 * Initialize mouse interface and enable interrupts.
	 */
	s = spltty();
	(*sc->sc_enablemouse)(sc->sc_port);
	splx(s);
	return (0);
}

/*
 * mseclose: just turn off mouse innterrupts.
 */
static	int
mseclose(dev, flags, fmt, p)
	dev_t dev;
	int flags;
	int fmt;
	struct proc *p;
{
	struct mse_softc *sc = &mse_sc[MSE_UNIT(dev)];
	int s;

	s = spltty();
	(*sc->sc_disablemouse)(sc->sc_port);
	sc->sc_flags &= ~MSESC_OPEN;
	splx(s);
	return(0);
}

/*
 * mseread: return mouse info using the MSC serial protocol, but without
 * using bytes 4 and 5.
 * (Yes this is cheesy, but it makes the X386 server happy, so...)
 */
static	int
mseread(dev, uio, ioflag)
	dev_t dev;
	struct uio *uio;
	int ioflag;
{
	register struct mse_softc *sc = &mse_sc[MSE_UNIT(dev)];
	int xfer, s, error;

	/*
	 * If there are no protocol bytes to be read, set up a new protocol
	 * packet.
	 */
	s = spltty(); /* XXX Should be its own spl, but where is imlXX() */
	if (sc->sc_bytesread >= sc->mode.packetsize) {
		while (sc->sc_deltax == 0 && sc->sc_deltay == 0 &&
		       (sc->sc_obuttons ^ sc->sc_buttons) == 0) {
			if (MSE_NBLOCKIO(dev)) {
				splx(s);
				return (0);
			}
			sc->sc_flags |= MSESC_WANT;
			error = tsleep((caddr_t)sc, MSEPRI | PCATCH,
				"mseread", 0);
			if (error) {
				splx(s);
				return (error);
			}
		}

		/*
		 * Generate protocol bytes.
		 * For some reason X386 expects 5 bytes but never uses
		 * the fourth or fifth?
		 */
		sc->sc_bytes[0] = sc->mode.syncmask[1] 
		    | (sc->sc_buttons & ~sc->mode.syncmask[0]);
		if (sc->sc_deltax > 127)
			sc->sc_deltax = 127;
		if (sc->sc_deltax < -127)
			sc->sc_deltax = -127;
		sc->sc_deltay = -sc->sc_deltay;	/* Otherwise mousey goes wrong way */
		if (sc->sc_deltay > 127)
			sc->sc_deltay = 127;
		if (sc->sc_deltay < -127)
			sc->sc_deltay = -127;
		sc->sc_bytes[1] = sc->sc_deltax;
		sc->sc_bytes[2] = sc->sc_deltay;
		sc->sc_bytes[3] = sc->sc_bytes[4] = 0;
		sc->sc_bytes[5] = sc->sc_bytes[6] = 0;
		sc->sc_bytes[7] = MOUSE_SYS_EXTBUTTONS;
		sc->sc_obuttons = sc->sc_buttons;
		sc->sc_deltax = sc->sc_deltay = 0;
		sc->sc_bytesread = 0;
	}
	splx(s);
	xfer = min(uio->uio_resid, sc->mode.packetsize - sc->sc_bytesread);
	error = uiomove(&sc->sc_bytes[sc->sc_bytesread], xfer, uio);
	if (error)
		return (error);
	sc->sc_bytesread += xfer;
	return(0);
}

/*
 * mseioctl: process ioctl commands.
 */
static int
mseioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	u_long cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	register struct mse_softc *sc = &mse_sc[MSE_UNIT(dev)];
	mousestatus_t status;
	int err = 0;
	int s;

	switch (cmd) {

	case MOUSE_GETHWINFO:
		s = spltty();
		*(mousehw_t *)addr = sc->hw;
		if (sc->mode.level == 0)
			((mousehw_t *)addr)->model = MOUSE_MODEL_GENERIC;
		splx(s);
		break;

	case MOUSE_GETMODE:
		s = spltty();
		*(mousemode_t *)addr = sc->mode;
		switch (sc->mode.level) {
		case 0:
			break;
		case 1:
			((mousemode_t *)addr)->protocol = MOUSE_PROTO_SYSMOUSE;
	    		((mousemode_t *)addr)->syncmask[0] = MOUSE_SYS_SYNCMASK;
	    		((mousemode_t *)addr)->syncmask[1] = MOUSE_SYS_SYNC;
			break;
		}
		splx(s);
		break;

	case MOUSE_SETMODE:
		switch (((mousemode_t *)addr)->level) {
		case 0:
		case 1:
			break;
		default:
			return (EINVAL);
		}
		if (((mousemode_t *)addr)->accelfactor < -1)
			return (EINVAL);
		else if (((mousemode_t *)addr)->accelfactor >= 0)
			sc->mode.accelfactor = 
			    ((mousemode_t *)addr)->accelfactor;
		sc->mode.level = ((mousemode_t *)addr)->level;
		switch (sc->mode.level) {
		case 0:
			sc->sc_bytesread = sc->mode.packetsize 
			    = MOUSE_MSC_PACKETSIZE;
			break;
		case 1:
			sc->sc_bytesread = sc->mode.packetsize 
			    = MOUSE_SYS_PACKETSIZE;
			break;
		}
		break;

	case MOUSE_GETLEVEL:
		*(int *)addr = sc->mode.level;
		break;

	case MOUSE_SETLEVEL:
		switch (*(int *)addr) {
		case 0:
			sc->mode.level = *(int *)addr;
			sc->sc_bytesread = sc->mode.packetsize 
			    = MOUSE_MSC_PACKETSIZE;
			break;
		case 1:
			sc->mode.level = *(int *)addr;
			sc->sc_bytesread = sc->mode.packetsize 
			    = MOUSE_SYS_PACKETSIZE;
			break;
		default:
			return (EINVAL);
		}
		break;

	case MOUSE_GETSTATUS:
		s = spltty();
		status = sc->status;
		sc->status.flags = 0;
		sc->status.obutton = sc->status.button;
		sc->status.button = 0;
		sc->status.dx = 0;
		sc->status.dy = 0;
		sc->status.dz = 0;
		splx(s);
		*(mousestatus_t *)addr = status;
		break;

	case MOUSE_READSTATE:
	case MOUSE_READDATA:
		return (ENODEV);

#if (defined(MOUSE_GETVARS))
	case MOUSE_GETVARS:
	case MOUSE_SETVARS:
		return (ENODEV);
#endif

	default:
		return (ENOTTY);
	}
	return (err);
}

/*
 * msepoll: check for mouse input to be processed.
 */
static	int
msepoll(dev, events, p)
	dev_t dev;
	int events;
	struct proc *p;
{
	register struct mse_softc *sc = &mse_sc[MSE_UNIT(dev)];
	int s;
	int revents = 0;

	s = spltty();
	if (events & (POLLIN | POLLRDNORM)) {
		if (sc->sc_bytesread != sc->mode.packetsize ||
		    sc->sc_deltax != 0 || sc->sc_deltay != 0 ||
		    (sc->sc_obuttons ^ sc->sc_buttons) != 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else {
			/*
			 * Since this is an exclusive open device, any previous
			 * proc pointer is trash now, so we can just assign it.
			 */
			selrecord(p, &sc->sc_selp);
		}
	}
	splx(s);
	return (revents);
}

/*
 * mseintr: update mouse status. sc_deltax and sc_deltay are accumulative.
 */
static void
mseintr(unit)
	int unit;
{
	/*
	 * the table to turn MouseSystem button bits (MOUSE_MSC_BUTTON?UP)
	 * into `mousestatus' button bits (MOUSE_BUTTON?DOWN).
	 */
	static int butmap[8] = {
		0, 
		MOUSE_BUTTON3DOWN, 
		MOUSE_BUTTON2DOWN, 
		MOUSE_BUTTON2DOWN | MOUSE_BUTTON3DOWN, 
		MOUSE_BUTTON1DOWN, 
		MOUSE_BUTTON1DOWN | MOUSE_BUTTON3DOWN, 
		MOUSE_BUTTON1DOWN | MOUSE_BUTTON2DOWN,
        	MOUSE_BUTTON1DOWN | MOUSE_BUTTON2DOWN | MOUSE_BUTTON3DOWN
	};
	register struct mse_softc *sc = &mse_sc[unit];
	int dx, dy, but;
	int sign;

#ifdef DEBUG
	static int mse_intrcnt = 0;
	if((mse_intrcnt++ % 10000) == 0)
		printf("mseintr\n");
#endif /* DEBUG */
	if ((sc->sc_flags & MSESC_OPEN) == 0)
		return;

	(*sc->sc_getmouse)(sc->sc_port, &dx, &dy, &but);
	if (sc->mode.accelfactor > 0) {
		sign = (dx < 0);
		dx = dx * dx / sc->mode.accelfactor;
		if (dx == 0)
			dx = 1;
		if (sign)
			dx = -dx;
		sign = (dy < 0);
		dy = dy * dy / sc->mode.accelfactor;
		if (dy == 0)
			dy = 1;
		if (sign)
			dy = -dy;
	}
	sc->sc_deltax += dx;
	sc->sc_deltay += dy;
	sc->sc_buttons = but;

	but = butmap[~but & MOUSE_MSC_BUTTONS];
	sc->status.dx += dx;
	sc->status.dy += dy;
	sc->status.flags |= ((dx || dy) ? MOUSE_POSCHANGED : 0)
	    | (sc->status.button ^ but);
	sc->status.button = but;

	/*
	 * If mouse state has changed, wake up anyone wanting to know.
	 */
	if (sc->sc_deltax != 0 || sc->sc_deltay != 0 ||
	    (sc->sc_obuttons ^ sc->sc_buttons) != 0) {
		if (sc->sc_flags & MSESC_WANT) {
			sc->sc_flags &= ~MSESC_WANT;
			wakeup((caddr_t)sc);
		}
		selwakeup(&sc->sc_selp);
	}
}

/*
 * Routines for the Logitech mouse.
 */
/*
 * Test for a Logitech bus mouse and return 1 if it is.
 * (until I know how to use the signature port properly, just disable
 *  interrupts and return 1)
 */
static int
mse_probelogi(idp)
	register struct isa_device *idp;
{

	int sig;

	outb(idp->id_iobase + MSE_PORTD, MSE_SETUP);
		/* set the signature port */
	outb(idp->id_iobase + MSE_PORTB, MSE_LOGI_SIG);

	DELAY(30000); /* 30 ms delay */
	sig = inb(idp->id_iobase + MSE_PORTB) & 0xFF;
	if (sig == MSE_LOGI_SIG) {
		outb(idp->id_iobase + MSE_PORTC, MSE_DISINTR);
		return(1);
	} else {
		if (bootverbose)
			printf("mse%d: wrong signature %x\n",idp->id_unit,sig);
		return(0);
	}
}

/*
 * Initialize Logitech mouse and enable interrupts.
 */
static void
mse_enablelogi(port)
	register u_int port;
{
	int dx, dy, but;

	outb(port + MSE_PORTD, MSE_SETUP);
	mse_getlogi(port, &dx, &dy, &but);
}

/*
 * Disable interrupts for Logitech mouse.
 */
static void
mse_disablelogi(port)
	register u_int port;
{

	outb(port + MSE_PORTC, MSE_DISINTR);
}

/*
 * Get the current dx, dy and button up/down state.
 */
static void
mse_getlogi(port, dx, dy, but)
	register u_int port;
	int *dx;
	int *dy;
	int *but;
{
	register char x, y;

	outb(port + MSE_PORTC, MSE_HOLD | MSE_RXLOW);
	x = inb(port + MSE_PORTA);
	*but = (x >> 5) & MOUSE_MSC_BUTTONS;
	x &= 0xf;
	outb(port + MSE_PORTC, MSE_HOLD | MSE_RXHIGH);
	x |= (inb(port + MSE_PORTA) << 4);
	outb(port + MSE_PORTC, MSE_HOLD | MSE_RYLOW);
	y = (inb(port + MSE_PORTA) & 0xf);
	outb(port + MSE_PORTC, MSE_HOLD | MSE_RYHIGH);
	y |= (inb(port + MSE_PORTA) << 4);
	*dx = x;
	*dy = y;
	outb(port + MSE_PORTC, MSE_INTREN);
}

/*
 * Routines for the ATI Inport bus mouse.
 */
/*
 * Test for a ATI Inport bus mouse and return 1 if it is.
 * (do not enable interrupts)
 */
static int
mse_probeati(idp)
	register struct isa_device *idp;
{
	int i;

	for (i = 0; i < 2; i++)
		if (inb(idp->id_iobase + MSE_PORTC) == 0xde)
			return (1);
	return (0);
}

/*
 * Initialize ATI Inport mouse and enable interrupts.
 */
static void
mse_enableati(port)
	register u_int port;
{

	outb(port + MSE_PORTA, MSE_INPORT_RESET);
	outb(port + MSE_PORTA, MSE_INPORT_MODE);
	outb(port + MSE_PORTB, MSE_INPORT_INTREN);
}

/*
 * Disable interrupts for ATI Inport mouse.
 */
static void
mse_disableati(port)
	register u_int port;
{

	outb(port + MSE_PORTA, MSE_INPORT_MODE);
	outb(port + MSE_PORTB, 0);
}

/*
 * Get current dx, dy and up/down button state.
 */
static void
mse_getati(port, dx, dy, but)
	register u_int port;
	int *dx;
	int *dy;
	int *but;
{
	register char byte;

	outb(port + MSE_PORTA, MSE_INPORT_MODE);
	outb(port + MSE_PORTB, MSE_INPORT_HOLD);
	outb(port + MSE_PORTA, MSE_INPORT_STATUS);
	*but = ~inb(port + MSE_PORTB) & MOUSE_MSC_BUTTONS;
	outb(port + MSE_PORTA, MSE_INPORT_DX);
	byte = inb(port + MSE_PORTB);
	*dx = byte;
	outb(port + MSE_PORTA, MSE_INPORT_DY);
	byte = inb(port + MSE_PORTB);
	*dy = byte;
	outb(port + MSE_PORTA, MSE_INPORT_MODE);
	outb(port + MSE_PORTB, MSE_INPORT_INTREN);
}

#endif /* NMSE */
