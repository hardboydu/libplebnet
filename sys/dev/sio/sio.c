/*-
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)com.c	7.5 (Berkeley) 5/16/91
 *	$Id: sio.c,v 1.28 1994/02/07 18:37:21 ache Exp $
 */

#include "sio.h"
#if NSIO > 0
/*
 * Serial driver, based on 386BSD-0.1 com driver.
 * Mostly rewritten to use pseudo-DMA.
 * Works for National Semiconductor NS8250-NS16550AF UARTs.
 * COM driver, based on HP dca driver.
 */
#include "param.h"
#include "systm.h"
#include "ioctl.h"
#include "tty.h"
#include "proc.h"
#include "user.h"
#include "conf.h"
#include "file.h"
#include "uio.h"
#include "kernel.h"
#include "syslog.h"

#include "i386/isa/isa.h"
#include "i386/isa/isa_device.h"
#include "i386/isa/comreg.h"
#include "i386/isa/ic/ns16550.h"

#define FAKE_DCD(unit)	((unit) == comconsole)
#define	LOTS_OF_EVENTS	64	/* helps separate urgent events from input */
#define	RB_I_HIGH_WATER	(RBSZ - 2 * RS_IBUFSIZE)
#define	RB_I_LOW_WATER	((RBSZ - 2 * RS_IBUFSIZE) * 7 / 8)
#define	RS_IBUFSIZE	256
#define	TTY_BI		TTY_FE		/* XXX */
#define	TTY_OE		TTY_PE		/* XXX */

#ifndef COM_BIDIR
#define	UNIT(x)		(minor(x))	/* XXX */
#else /* COM_BIDIR */
#define COM_UNITMASK    0x7f
#define COM_CALLOUTMASK 0x80		/* for both minor and dev */
#define UNIT(x)         (minor(x) & COM_UNITMASK)
#define CALLOUT(x)      (minor(x) & COM_CALLOUTMASK)
#endif /* COM_BIDIR */

#ifdef COM_MULTIPORT
/* checks in flags for multiport and which is multiport "master chip"
 * for a given card
 */
#define COM_ISMULTIPORT(dev) ((dev)->id_flags & 0x01)
#define COM_MPMASTER(dev)    (((dev)->id_flags >> 8) & 0x0ff)
#endif /* COM_MULTIPORT */
#define COM_NOFIFO(dev) ((dev)->id_flags & 0x02)

#ifndef	FIFO_TRIGGER
/*
 * This driver is fast enough to work with any value and for high values
 * to be only slightly more efficient.  Low values may be better because
 * they give lower latency.
 * TODO: always use low values for low speeds.  Mouse movements are jerky
 * if more than one packet arrives at once.  The low speeds used for
 * serial mice help avoid this, but not if (large) fifos are enabled.
 */
#define FIFO_TRIGGER	FIFO_TRIGGER_14
#endif

#define	com_scr		7	/* scratch register for 16450-16550 (R/W) */
#define setsofttty()    (ipending |= 1 << 4)     /* XXX */

/*
 * Input buffer watermarks.
 * The external device is asked to stop sending when the buffer exactly reaches
 * high water, or when the high level requests it.
 * The high level is notified immediately (rather than at a later clock tick)
 * when this watermark is reached.
 * The buffer size is chosen so the watermark should almost never be reached.
 * The low watermark is invisibly 0 since the buffer is always emptied all at
 * once.
 */
#define	RS_IHIGHWATER (3 * RS_IBUFSIZE / 4)

/*
 * com state bits.
 * (CS_BUSY | CS_TTGO) and (CS_BUSY | CS_TTGO | CS_ODEVREADY) must be higher
 * than the other bits so that they can be tested as a group without masking
 * off the low bits.
 *
 * The following com and tty flags correspond closely:
 *	TS_BUSY		= CS_BUSY (maintained by comstart() and comflush())
 *	CS_TTGO		= ~TS_TTSTOP (maintained by comstart() and siostop())
 *	CS_CTS_OFLOW	= CCTS_OFLOW (maintained by comparam())
 *	CS_RTS_IFLOW	= CRTS_IFLOW (maintained by comparam())
 * TS_FLUSH is not used.
 * Bug: I think TIOCSETA doesn't clear TS_TTSTOP when it clears IXON.
 */
#define	CS_BUSY		0x80	/* output in progress */
#define	CS_TTGO		0x40	/* output not stopped by XOFF */
#define	CS_ODEVREADY	0x20	/* external device h/w ready (CTS) */
#define	CS_CHECKMSR	1	/* check of MSR scheduled */
#define	CS_CTS_OFLOW	2	/* use CTS output flow control */
#define	CS_ODONE	4	/* output completed */
#define	CS_RTS_IFLOW	8	/* use RTS input flow control */

static	char	*error_desc[] = {
#define	CE_OVERRUN			0
	"silo overflow",
#define	CE_INTERRUPT_BUF_OVERFLOW	1
	"interrupt-level buffer overflow",
#define	CE_TTY_BUF_OVERFLOW		2
	"tty-level buffer overflow",
};

#define	CE_NTYPES			3
#define	CE_RECORD(com, errnum)		(++(com)->delta_error_counts[errnum])

/* types.  XXX - should be elsewhere */
typedef u_int	Port_t;		/* hardware port */
typedef u_char	bool_t;		/* boolean */

/* com device structure */
struct com_s {
	u_char	state;		/* miscellaneous flag bits */
	u_char	cfcr_image;	/* copy of value written to CFCR */
	bool_t	hasfifo;	/* nonzero for 16550 UARTs */
	u_char	mcr_image;	/* copy of value written to MCR */
#ifdef COM_BIDIR
	bool_t  bidir;		/* is this unit bidirectional? */
	bool_t  active;		/* is the port active _at all_? */
	bool_t  active_in;	/* is the incoming port in use? */
	bool_t  active_out;	/* is the outgoing port in use? */
#endif /* COM_BIDIR */
#ifdef COM_MULTIPORT
	bool_t	multiport;	/* is this unit part of a multiport device? */
#endif /* COM_MULTIPORT */
	int	dtr_wait;	/* time to hold DTR down on close (* 1/HZ) */
	u_int	tx_fifo_size;

	/*
	 * The high level of the driver never reads status registers directly
	 * because there would be too many side effects to handle conveniently.
	 * Instead, it reads copies of the registers stored here by the
	 * interrupt handler.
	 */
	u_char	last_modem_status;	/* last MSR read by intr handler */
	u_char	prev_modem_status;	/* last MSR handled by high level */

	u_char	*ibuf;		/* start of input buffer */
	u_char	*ibufend;	/* end of input buffer */
	u_char	*ihighwater;	/* threshold in input buffer */
	u_char	*iptr;		/* next free spot in input buffer */

	u_char	*obufend;	/* end of output buffer */
	int	ocount;		/* original count for current output */
	u_char	*optr;		/* next char to output */

	Port_t	data_port;	/* i/o ports */
	Port_t	int_id_port;
	Port_t	iobase;
	Port_t	modem_ctl_port;
	Port_t	line_status_port;
	Port_t	modem_status_port;

	struct tty	*tp;	/* cross reference */

	u_long	bytes_in;	/* statistics */
	u_long	bytes_out;
	u_int	delta_error_counts[CE_NTYPES];
	u_int	error_counts[CE_NTYPES];

	/*
	 * Ping-pong input buffers.  The extra factor of 2 in the sizes is
	 * to allow for an error byte for each input byte.
	 */
#define	CE_INPUT_OFFSET		RS_IBUFSIZE
	u_char	ibuf1[2 * RS_IBUFSIZE];
	u_char	ibuf2[2 * RS_IBUFSIZE];
	int	do_timestamp;
	struct timeval  timestamp;
};

/*
 * These functions in the com module ought to be declared (with a prototype)
 * in a com-driver system header.  The void ones may need to be int to match
 * ancient devswitch declarations, but they don't actually return anything.
 */
#define	Dev_t	int		/* promoted dev_t */
struct consdev;

int	sioclose	__P((Dev_t dev, int fflag, int devtype,
			     struct proc *p));
void	siointr		__P((int unit));
int	sioioctl	__P((Dev_t dev, int cmd, caddr_t data,
			     int fflag, struct proc *p));
int	siocngetc	__P((Dev_t dev));
void	siocninit	__P((struct consdev *cp));
void	siocnprobe	__P((struct consdev *cp));
void	siocnputc	__P((Dev_t dev, int c));
int	sioopen		__P((Dev_t dev, int oflags, int devtype,
			     struct proc *p));
void	siopoll		__P((void));
int	sioread		__P((Dev_t dev, struct uio *uio, int ioflag));
int	sioselect	__P((Dev_t dev, int rw, struct proc *p));
void	siostop		__P((struct tty *tp, int rw));
int	siowrite	__P((Dev_t dev, struct uio *uio, int ioflag));
void	softsio1	__P((void));

static	int	sioattach	__P((struct isa_device *dev));
static	void	comflush	__P((struct com_s *com));
static	void	comhardclose	__P((struct com_s *com));
static	void	cominit		__P((int unit, int rate));
static	void	comintr1	__P((struct com_s *com));
static	void	commctl		__P((struct com_s *com, int bits, int how));
static	int	comparam	__P((struct tty *tp, struct termios *t));
static	int	sioprobe	__P((struct isa_device *dev));
static  void    comstart        __P((struct tty *tp));
static  void    comwakeup       __P((caddr_t chan, int ticks));
static	int	tiocm_xxx2mcr	__P((int tiocm_xxx));

/* table and macro for fast conversion from a unit number to its com struct */
static	struct com_s	*p_com_addr[NSIO];
#define	com_addr(unit)	(p_com_addr[unit])

static	struct com_s	com_structs[NSIO];

static  struct  timeval intr_timestamp;

struct isa_driver	siodriver = {
	sioprobe, sioattach, "sio"
};

#ifdef COMCONSOLE
static	int	comconsole = COMCONSOLE;
#else
static	int	comconsole = -1;
#endif
static	bool_t	comconsinit;
static	speed_t	comdefaultrate = TTYDEF_SPEED;
static	u_int	com_events;	/* input chars + weighted output completions */
static	int	commajor;
struct tty	sio_tty[NSIO];
extern	struct tty	*constty;
extern	u_int	ipending;	/* XXX */
extern	int	tk_nin;		/* XXX */
extern	int	tk_rawcc;	/* XXX */

#ifdef KGDB
#include "machine/remote-sl.h"

extern	int	kgdb_dev;
extern	int	kgdb_rate;
extern	int	kgdb_debug_init;
#endif

static	struct speedtab comspeedtab[] = {
	0,	0,
	50,	COMBRD(50),
	75,	COMBRD(75),
	110,	COMBRD(110),
	134,	COMBRD(134),
	150,	COMBRD(150),
	200,	COMBRD(200),
	300,	COMBRD(300),
	600,	COMBRD(600),
	1200,	COMBRD(1200),
	1800,	COMBRD(1800),
	2400,	COMBRD(2400),
	4800,	COMBRD(4800),
	9600,	COMBRD(9600),
	19200,	COMBRD(19200),
	38400,	COMBRD(38400),
	57600,	COMBRD(57600),
	115200,	COMBRD(115200),
	-1,	-1
};

/* XXX - configure this list */
static Port_t likely_com_ports[] = { 0x3f8, 0x2f8, 0x3e8, 0x2e8, };

static int
sioprobe(dev)
	struct isa_device	*dev;
{
	static bool_t	already_init;
	Port_t		*com_ptr;
	Port_t		iobase;
	int		result;

	if (!already_init) {
		/*
		 * Turn off MCR_IENABLE for all likely serial ports.  An unused
		 * port with its MCR_IENABLE gate open will inhibit interrupts
		 * from any used port that shares the interrupt vector.
		 */
		for (com_ptr = likely_com_ports;
		     com_ptr < &likely_com_ports[sizeof likely_com_ports
						 / sizeof likely_com_ports[0]];
		     ++com_ptr)
			outb(*com_ptr + com_mcr, 0);
		already_init = TRUE;
	}
	iobase = dev->id_iobase;
	result = IO_COMSIZE;

	/*
	 * We don't want to get actual interrupts, just masked ones.
	 * Interrupts from this line should already be masked in the ICU,
	 * but mask them in the processor as well in case there are some
	 * (misconfigured) shared interrupts.
	 */
	disable_intr();

	/*
	 * Initialize the speed so that any junk in the THR or output fifo will
	 * be transmitted in a known time.  (There may be lots of junk after a
	 * soft reboot, and output interrupts don't work right after a master
	 * reset, at least for 16550s.  (The speed is undefined after MR, but
	 * MR empties the THR and the TSR so it's not clear why this matters)).
	 * Enable output interrupts (only) and check the following:
	 *	o the CFCR, IER and MCR in UART hold the values written to them
	 *	  (the values happen to be all distinct - this is good for
	 *	  avoiding false positive tests from bus echoes).
	 *	o an output interrupt is generated and its vector is correct.
	 *	o the interrupt goes away when the IIR in the UART is read.
	 */
	outb(iobase + com_cfcr, CFCR_DLAB);
	outb(iobase + com_dlbl, COMBRD(9600) & 0xff);
	outb(iobase + com_dlbh, (u_int) COMBRD(9600) >> 8);
	outb(iobase + com_cfcr, CFCR_8BITS);	/* ensure IER is addressed */
	outb(iobase + com_mcr, MCR_IENABLE);	/* open gate early */
	outb(iobase + com_ier, 0);		/* ensure edge on next intr */
	outb(iobase + com_ier, IER_ETXRDY);	/* generate interrupt */
	DELAY((16 + 1) * 9600 / 10);		/* enough to drain 16 bytes */
	if (   inb(iobase + com_cfcr) != CFCR_8BITS
	    || inb(iobase + com_ier) != IER_ETXRDY
	    || inb(iobase + com_mcr) != MCR_IENABLE
#ifndef COM_MULTIPORT /* XXX - need to do more to enable interrupts */
	    || !isa_irq_pending(dev)
#endif
	    || (inb(iobase + com_iir) & IIR_IMASK) != IIR_TXRDY
	    || isa_irq_pending(dev)
	    || !(inb(iobase + com_iir) & IIR_NOPEND))
		result = 0;

	/*
	 * Turn off all device interrupts and check that they go off properly.
	 * Leave MCR_IENABLE set.  It gates the OUT2 output of the UART to
	 * the ICU input.  Closing the gate would give a floating ICU input
	 * (unless there is another device driving at) and spurious interrupts.
	 * (On the system that this was first tested on, the input floats high
	 * and gives a (masked) interrupt as soon as the gate is closed.)
	 */
	outb(iobase + com_ier, 0);
	outb(iobase + com_mcr, MCR_IENABLE);	/* dummy to avoid bus echo */
	if (   inb(iobase + com_ier) != 0
	    || isa_irq_pending(dev)
	    || !(inb(iobase + com_iir) & IIR_NOPEND))
		result = 0;
	if (result == 0)
		outb(iobase + com_mcr, 0);

	enable_intr();
	return (result);
}

static int
sioattach(isdp)
	struct isa_device	*isdp;
{
	struct com_s	*com;
	static bool_t	comwakeup_started = FALSE;
	Port_t		iobase;
	int		s;
	int		unit;

	iobase = isdp->id_iobase;
	unit = isdp->id_unit;
	if (unit == comconsole)
		DELAY(1000);	/* XXX */
	s = spltty();

	/*
	 * sioprobe() has initialized the device registers as follows:
	 *	o cfcr = CFCR_8BITS.
	 *	  It is most important that CFCR_DLAB is off, so that the
	 *	  data port is not hidden when we enable interrupts.
	 *	o ier = 0.
	 *	  Interrupts are only enabled when the line is open.
	 *	o mcr = MCR_IENABLE.
	 *	  Keeping MCR_DTR and MCR_RTS off might stop the external
	 *	  device from sending before we are ready.
	 */

	com = &com_structs[unit];
	com->cfcr_image = CFCR_8BITS;
	com->mcr_image = MCR_IENABLE;
	com->dtr_wait = 200;
	com->tx_fifo_size = 1;
	com->iptr = com->ibuf = com->ibuf1;
	com->ibufend = com->ibuf1 + RS_IBUFSIZE;
	com->ihighwater = com->ibuf1 + RS_IHIGHWATER;
	com->iobase = iobase;
	com->data_port = iobase + com_data;
	com->int_id_port = iobase + com_iir;
	com->modem_ctl_port = iobase + com_mcr;
	com->line_status_port = iobase + com_lsr;
	com->modem_status_port = iobase + com_msr;
	com->tp = &sio_tty[unit];

	/* attempt to determine UART type */
	printf("sio%d: type", unit);
#ifdef COM_MULTIPORT
	if (!COM_ISMULTIPORT(isdp))
#endif
	{
		u_char	scr;
		u_char	scr1;
		u_char	scr2;

		scr = inb(iobase + com_scr);
		outb(iobase + com_scr, 0xa5);
		scr1 = inb(iobase + com_scr);
		outb(iobase + com_scr, 0x5a);
		scr2 = inb(iobase + com_scr);
		outb(iobase + com_scr, scr);
		if (scr1 != 0xa5 || scr2 != 0x5a) {
			printf(" 8250");
			goto determined_type;
		}
	}
	outb(iobase + com_fifo, FIFO_ENABLE | FIFO_TRIGGER_14);
	DELAY(100);
	switch (inb(com->int_id_port) & IIR_FIFO_MASK) {
	case FIFO_TRIGGER_1:
		printf(" 16450");
		break;
	case FIFO_TRIGGER_4:
		printf(" 16450?");
		break;
	case FIFO_TRIGGER_8:
		printf(" 16550?");
		break;
	case FIFO_TRIGGER_14:
		printf(" 16550A");
		if (COM_NOFIFO(isdp)) {
			printf(" fifo software disabled");
		} else {
			com->hasfifo = TRUE;
			com->tx_fifo_size = 16;
		}
		break;
	}
	outb(iobase + com_fifo, 0);
determined_type: ;

#ifdef COM_MULTIPORT
	if (COM_ISMULTIPORT(isdp)) {
		struct isa_device *masterdev;

		com->multiport = TRUE;
		printf(" (multiport)");

		/* set the master's common-interrupt-enable reg.,
		 * as appropriate. YYY See your manual
		 */
		/* enable only common interrupt for port */
		outb(com->modem_ctl_port, com->mcr_image = 0);

		masterdev = find_isadev(isa_devtab_tty, &siodriver,
					COM_MPMASTER(isdp));
		outb(masterdev->id_iobase + com_scr, 0x80);
	} else
		com->multiport = FALSE;
#endif /* COM_MULTIPORT */
	printf("\n");

#ifdef KGDB
	if (kgdb_dev == makedev(commajor, unit)) {
		if (comconsole == unit)
			kgdb_dev = -1;	/* can't debug over console port */
		else {
			cominit(unit, kgdb_rate);
			if (kgdb_debug_init) {
				/*
				 * Print prefix of device name,
				 * let kgdb_connect print the rest.
				 */
				printf("sio%d: ", unit);
				kgdb_connect(1);
			} else
				printf("sio%d: kgdb enabled\n", unit);
		}
	}
#endif

	/*
	 * Need to reset baud rate, etc. of next print so reset comconsinit.
	 */
	if (unit == comconsole)
		comconsinit = FALSE;

	com_addr(unit) = com;
	splx(s);
	if (!comwakeup_started) {
		comwakeup((caddr_t) NULL, 0);
		comwakeup_started = TRUE;
	}
	return (1);
}

/* ARGSUSED */
int
sioopen(dev, flag, mode, p)
	dev_t		dev;
	int		flag;
	int		mode;
	struct proc	*p;
{
#ifdef COM_BIDIR
	bool_t		callout;
#endif /* COM_BIDIR */
	struct com_s	*com;
	int		error = 0;
	Port_t		iobase;
	int		s;
	struct tty	*tp;
	int		unit;

	unit = UNIT(dev);
	if ((u_int) unit >= NSIO || (com = com_addr(unit)) == NULL)
		return (ENXIO);
#ifdef COM_BIDIR
	/* if it's a callout device, and bidir not possible on that dev, die */
	callout = CALLOUT(dev);
	if (callout && !(com->bidir))
		return (ENXIO);
#endif /* COM_BIDIR */

	tp = com->tp;
	s = spltty();

#ifdef COM_BIDIR

bidir_open_top:
	/* if it's bidirectional, we've gotta deal with it... */
	if (com->bidir) {
		if (callout) {
			if (com->active_in) {
			    /* it's busy. die */
			    splx(s);
			    return (EBUSY);
			} else {
			    /* it's ours.  lock it down, and set it up */
			    com->active_out = TRUE;
			}
		} else {
			if (com->active_out) {
				/* it's busy, outgoing.  wait, if possible */
				if (flag & O_NONBLOCK) {
				    /* can't wait; bail */
				    splx(s);
				    return (EBUSY);
				} else {
				    /* wait for it... */
				    error = tsleep((caddr_t)&com->active_out,
						   TTIPRI|PCATCH,
						   "siooth",
						   0);
				    /* if there was an error, take off. */
				    if (error != 0) {
					splx(s);
					return (error);
				    }
				    /* else take it from the top */
				    goto bidir_open_top;
				}
			} else if (com->prev_modem_status & MSR_DCD
				   || FAKE_DCD(unit)) {
				/* there's a carrier on the line; we win */
				com->active_in = TRUE;
			} else {
				/* there is no carrier on the line */
				if (flag & O_NONBLOCK) {
				    /* can't wait; let it open */
				    com->active_in = TRUE;
				} else {
				    /* put DTR & RTS up */
				    /* XXX - bring up RTS earlier? */
				    commctl(com, MCR_DTR | MCR_RTS, DMSET);
				    outb(com->iobase + com_ier, IER_EMSC);

				    /* wait for it... */
				    error = tsleep((caddr_t)&com->active_in,
						   TTIPRI|PCATCH,
						   "siodcd",
						   0);

				    /* if not active, turn intrs and DTR off */
				    if (!com->active) {
					outb(com->iobase + com_ier, 0);
					commctl(com, MCR_DTR, DMBIC);
				    }

				    /* if there was an error, take off. */
				    if (error != 0) {
					splx(s);
					return (error);
				    }
				    /* else take it from the top */
				    goto bidir_open_top;
				}
			}
		}
	}

	com->active = TRUE;
#endif /* COM_BIDIR */

	tp->t_oproc = comstart;
	tp->t_param = comparam;
	tp->t_dev = dev;
	if (!(tp->t_state & TS_ISOPEN)) {
		tp->t_state |= TS_WOPEN;
		ttychars(tp);
		if (tp->t_ispeed == 0) {
			/*
			 * We no longer use the flags from <sys/ttydefaults.h>
			 * since those are only relevant for logins.  It's
			 * important to have echo off initially so that the
			 * line doesn't start blathering before the echo flag
			 * can be turned off.
			 */
			tp->t_iflag = 0;
			tp->t_oflag = 0;
#ifdef COMCONSOLE
			if (unit == comconsole)
			tp->t_oflag = TTYDEF_OFLAG;
#endif
			tp->t_cflag = CREAD | CS8 | HUPCL;
			tp->t_lflag = 0;
			tp->t_ispeed = tp->t_ospeed = comdefaultrate;
		}

		/*
		 * XXX the full state after a first open() needs to be
		 * programmable and separate for callin and callout.
		 */
#ifdef COM_BIDIR
		if (com->bidir) {
			if (callout)
				tp->t_cflag |= CLOCAL;
			else
				tp->t_cflag &= ~CLOCAL;
		}
#endif

		commctl(com, MCR_DTR | MCR_RTS, DMSET);
		error = comparam(tp, &tp->t_termios);
		if (error != 0)
			goto out;
		ttsetwater(tp);
		iobase = com->iobase;
		if (com->hasfifo) {
			/* (re)enable and drain FIFO */
			outb(iobase + com_fifo, FIFO_ENABLE | FIFO_TRIGGER
						| FIFO_RCV_RST | FIFO_XMT_RST);
			DELAY(100);
		}
		disable_intr();
		(void) inb(com->line_status_port);
		(void) inb(com->data_port);
		com->last_modem_status =
		com->prev_modem_status = inb(com->modem_status_port);
		outb(iobase + com_ier, IER_ERXRDY | IER_ETXRDY | IER_ERLS
				       | IER_EMSC);
		enable_intr();
		if (com->prev_modem_status & MSR_DCD || FAKE_DCD(unit))
			tp->t_state |= TS_CARR_ON;
	} else if (tp->t_state & TS_XCLUDE && p->p_ucred->cr_uid != 0) {
		splx(s);
		return (EBUSY);
	}
	while (!(flag & O_NONBLOCK) && !(tp->t_cflag & CLOCAL)
#ifdef COM_BIDIR
		/* We went through a lot of trouble to open it,
		 * but it's certain we have a carrier now, so
		 * don't spend any time on it now.
		 */
	       && !(com->bidir)
#endif /* COM_BIDIR */
	       && !(tp->t_state & TS_CARR_ON)) {
		tp->t_state |= TS_WOPEN;
		error = ttysleep(tp, (caddr_t)&tp->t_raw, TTIPRI | PCATCH,
				 ttopen, 0);
		if (error != 0)
			break;
	}
out:
	splx(s);
	if (error == 0)
		error = (*linesw[tp->t_line].l_open)(dev, tp, 0);

#ifdef COM_BIDIR
	/* wakeup sleepers */
	wakeup((caddr_t) &com->active_in);
#endif /* COM_BIDIR */

	/*
	 * XXX - the next step was once not done, so interrupts, DTR and RTS
	 * remained hot if the process was killed while it was sleeping
	 * waiting for carrier.  Now there is the opposite problem.  If several
	 * processes are sleeping waiting for carrier on the same line and one
	 * is killed, interrupts are turned off so the other processes will
	 * never see the carrier rise.
	 */
	if (error != 0 && !(tp->t_state & TS_ISOPEN))
		comhardclose(com);
	tp->t_state &= ~TS_WOPEN;

	return (error);
}

/*ARGSUSED*/
int
sioclose(dev, flag, mode, p)
	dev_t		dev;
	int		flag;
	int		mode;
	struct proc	*p;
{
	struct com_s	*com;
	struct tty	*tp;

	com = com_addr(UNIT(dev));
	tp = com->tp;
	(*linesw[tp->t_line].l_close)(tp, flag);
	comhardclose(com);
	ttyclose(tp);
	return (0);
}

static void
comhardclose(com)
	struct com_s	*com;
{
	Port_t		iobase;
	int		s;
	struct tty	*tp;
	int		unit;

	s = spltty();
	iobase = com->iobase;
	com->do_timestamp = 0;
	outb(iobase + com_cfcr, com->cfcr_image &= ~CFCR_SBREAK);
	unit = com - &com_structs[0];
#ifdef KGDB
	/* do not disable interrupts or hang up if debugging */
	if (kgdb_dev != makedev(commajor, unit))
#endif
	{
		outb(iobase + com_ier, 0);
		tp = com->tp;
		if (tp->t_cflag & HUPCL || tp->t_state & TS_WOPEN
		    || !(com->prev_modem_status & MSR_DCD) && !FAKE_DCD(unit)
		    || !(tp->t_state & TS_ISOPEN)) {
			commctl(com, MCR_RTS, DMSET);
			if (com->dtr_wait != 0)
				/*
				 * Uninterruptible sleep since we want to
				 * wait a fixed time.
				 * XXX - delay in open() (if necessary),
				 * not here (always).
				 */
				tsleep((caddr_t)&com->dtr_wait, TTIPRI,
				       "sioclose", com->dtr_wait);
		}
	}

#ifdef COM_BIDIR
	com->active = com->active_in = com->active_out = FALSE;

	/* wakeup sleepers who are waiting for out to finish */
	wakeup((caddr_t) &com->active_out);
#endif /* COM_BIDIR */

	splx(s);
}

int
sioread(dev, uio, flag)
	dev_t		dev;
	struct uio	*uio;
	int		flag;
{
	struct tty	*tp = com_addr(UNIT(dev))->tp;

	return ((*linesw[tp->t_line].l_read)(tp, uio, flag));
}

int
siowrite(dev, uio, flag)
	dev_t		dev;
	struct uio	*uio;
	int		flag;
{
	int		unit = UNIT(dev);
	struct tty	*tp = com_addr(unit)->tp;

	/*
	 * (XXX) We disallow virtual consoles if the physical console is
	 * a serial port.  This is in case there is a display attached that
	 * is not the console.  In that situation we don't need/want the X
	 * server taking over the console.
	 */
	if (constty && unit == comconsole)
		constty = NULL;
	return ((*linesw[tp->t_line].l_write)(tp, uio, flag));
}

/* Interrupt routine for timekeeping purposes */
void
siointrts(int unit)
{
	microtime(&intr_timestamp);
	siointr(unit);
}

void
siointr(unit)
	int	unit;
{
	struct com_s	*com;

#ifndef COM_MULTIPORT
	com = com_addr(unit);
	if (com != NULL)
		comintr1(com);
#else /* COM_MULTIPORT */
	bool_t		possibly_more_intrs;

	/*
	 * Loop until there is no activity on any port.  This is necessary
	 * to get an interrupt edge more than to avoid another interrupt.
	 * If the IRQ signal is just an OR of the IRQ signals from several
	 * devices, then the edge from one may be lost because another is
	 * on.
	 */
	do {
		possibly_more_intrs = FALSE;
		for (unit = 0; unit < NSIO; ++unit) {
			com = com_addr(unit);
			if (com != NULL
			    && !(inb(com->int_id_port) & IIR_NOPEND)) {
				/*
				 * XXX call comintr1() instead of here from
				 * comwakeup().  The interrupt edge problem
				 * only exists for real interrupts.
				 */
				comintr1(com);
				possibly_more_intrs = TRUE;
			}
		}
	} while (possibly_more_intrs);
#endif  /* COM_MULTIPORT */
}

static void
comintr1(com)
	struct com_s *com;
{
	u_char		line_status;
	u_char		modem_status;
	u_char		*ioptr;
	u_char		recv_data;

	if(com->do_timestamp)
		com->timestamp = intr_timestamp;
	while (TRUE) {
		line_status = inb(com->line_status_port);

		/* input event? (check first to help avoid overruns) */
		while (line_status & LSR_RCV_MASK) {
			/* break/unnattached error bits or real input? */
			if (!(line_status & LSR_RXRDY))
				recv_data = 0;
			else
				recv_data = inb(com->data_port);
			++com->bytes_in;
#ifdef KGDB
			/* trap into kgdb? (XXX - needs testing and optim) */
			if (recv_data == FRAME_END
			    && !(com->tp->t_state & TS_ISOPEN)
			    && kgdb_dev == makedev(commajor, unit)) {
				kgdb_connect(0);
				continue;
			}
#endif /* KGDB */
			ioptr = com->iptr;
			if (ioptr >= com->ibufend)
				CE_RECORD(com, CE_INTERRUPT_BUF_OVERFLOW);
			else {
				++com_events;
#if 0 /* for testing input latency vs efficiency */
if (com->iptr - com->ibuf == 8)
	setsofttty();
#endif
				ioptr[0] = recv_data;
				ioptr[CE_INPUT_OFFSET] = line_status;
				com->iptr = ++ioptr;
				if (ioptr == com->ihighwater
				    && com->state & CS_RTS_IFLOW)
					outb(com->modem_ctl_port,
					     com->mcr_image &= ~MCR_RTS);
				/* XXX - move this out of isr */
				if (line_status & LSR_OE)
					CE_RECORD(com, CE_OVERRUN);
			}

			/*
			 * "& 0x7F" is to avoid the gcc-1.40 generating a slow
			 * jump from the top of the loop to here
			 */
			line_status = inb(com->line_status_port) & 0x7F;
		}

		/* modem status change? (always check before doing output) */
		modem_status = inb(com->modem_status_port);
		if (modem_status != com->last_modem_status) {
			/*
			 * Schedule high level to handle DCD changes.  Note
			 * that we don't use the delta bits anywhere.  Some
			 * UARTs mess them up, and it's easy to remember the
			 * previous bits and calculate the delta.
			 */
			com->last_modem_status = modem_status;
			if (!(com->state & CS_CHECKMSR)) {
				com_events += LOTS_OF_EVENTS;
				com->state |= CS_CHECKMSR;
				setsofttty();
			}

			/* handle CTS change immediately for crisp flow ctl */
			if (com->state & CS_CTS_OFLOW) {
				if (modem_status & MSR_CTS)
					com->state |= CS_ODEVREADY;
				else
					com->state &= ~CS_ODEVREADY;
			}
		}

		/* output queued and everything ready? */
		if (line_status & LSR_TXRDY
		    && com->state >= (CS_ODEVREADY | CS_BUSY | CS_TTGO)) {
			ioptr = com->optr;
			if (com->tx_fifo_size > 1) {
				u_int	ocount;

				ocount = com->obufend - ioptr;
				if (ocount > com->tx_fifo_size)
					ocount = com->tx_fifo_size;
				com->bytes_out += ocount;
				do
					outb(com->data_port, *ioptr++);
				while (--ocount != 0);
			} else {
				outb(com->data_port, *ioptr++);
			++com->bytes_out;
			}
			com->optr = ioptr;
			if (ioptr >= com->obufend) {
				/* output just completed */
				com_events += LOTS_OF_EVENTS;
				com->state ^= (CS_ODONE | CS_BUSY);
				setsofttty();	/* handle at high level ASAP */
			}
		}

		/* finished? */
#ifndef COM_MULTIPORT
		if (inb(com->int_id_port) & IIR_NOPEND)
#endif /* COM_MULTIPORT */
			return;
	}
}

static int
tiocm_xxx2mcr(tiocm_xxx)
	int tiocm_xxx;
{
	int mcr;

	mcr = 0;
	if (tiocm_xxx & TIOCM_DTR)
		mcr |= MCR_DTR;
	if (tiocm_xxx & TIOCM_RTS)
		mcr |= MCR_RTS;
	return (mcr);
}

int
sioioctl(dev, cmd, data, flag, p)
	dev_t		dev;
	int		cmd;
	caddr_t		data;
	int		flag;
	struct proc	*p;
{
	struct com_s	*com;
	int		error;
	Port_t		iobase;
	int		mcr;
	int		msr;
	int		s;
	int		tiocm_xxx;
	struct tty	*tp;

	com = com_addr(UNIT(dev));
	tp = com->tp;
	error = (*linesw[tp->t_line].l_ioctl)(tp, cmd, data, flag);
	if (error >= 0)
		return (error);
	error = ttioctl(tp, cmd, data, flag);

#ifdef COM_BIDIR
	/* XXX: plug security hole while sticky bits not yet implemented */
	if (com->bidir && com->active_in && p->p_ucred->cr_uid != 0)
		tp->t_cflag &= ~CLOCAL;
#endif

	if (error >= 0)
		return (error);

	iobase = com->iobase;
	s = spltty();
	switch (cmd) {
	case TIOCSBRK:
		outb(iobase + com_cfcr, com->cfcr_image |= CFCR_SBREAK);
		break;
	case TIOCCBRK:
		outb(iobase + com_cfcr, com->cfcr_image &= ~CFCR_SBREAK);
		break;
	case TIOCSDTR:
		commctl(com, MCR_DTR, DMBIS);
		break;
	case TIOCCDTR:
		commctl(com, MCR_DTR, DMBIC);
		break;
	case TIOCMSET:
		commctl(com, tiocm_xxx2mcr(*(int *)data), DMSET);
		break;
	case TIOCMBIS:
		commctl(com, tiocm_xxx2mcr(*(int *)data), DMBIS);
		break;
	case TIOCMBIC:
		commctl(com, tiocm_xxx2mcr(*(int *)data), DMBIC);
		break;
	case TIOCMGET:
		tiocm_xxx = TIOCM_LE;	/* XXX - always enabled while open */
		mcr = com->mcr_image;
		if (mcr & MCR_DTR)
			tiocm_xxx |= TIOCM_DTR;
		if (mcr & MCR_RTS)
			tiocm_xxx |= TIOCM_RTS;
		msr = com->prev_modem_status;
		if (msr & MSR_CTS)
			tiocm_xxx |= TIOCM_CTS;
		if (msr & MSR_DCD)
			tiocm_xxx |= TIOCM_CD;
		if (msr & MSR_DSR)
			tiocm_xxx |= TIOCM_DSR;
		/*
		 * XXX - MSR_RI is naturally volatile, and we make MSR_TERI
		 * more volatile by reading the modem status a lot.  Perhaps
		 * we should latch both bits until the status is read here.
		 */
		if (msr & (MSR_RI | MSR_TERI))
			tiocm_xxx |= TIOCM_RI;
		*(int *)data = tiocm_xxx;
		break;
#ifdef COM_BIDIR
	case TIOCMSBIDIR:
		/* must be root to set bidir. capability */
		error = suser(p->p_ucred, &p->p_acflag);
		if (error != 0) {
			splx(s);
			return(EPERM);
		}

		/* if it's the console, can't do it (XXX why?) */
		if (UNIT(dev) == comconsole) {
			splx(s);
			return(ENOTTY);
		}

#if 0
		/* XXX - can't do the next, for obvious reasons...
		 * but there are problems to be looked at...
		 */
		/* if the port is active, don't do it */
		if (com->active) {
			splx(s);
			return(EBUSY);
		}
#endif

		com->bidir = *(int *)data;
		break;
	case TIOCMGBIDIR:
		*(int *)data = com->bidir;
		break;
#endif /* COM_BIDIR */
	case TIOCMSDTRWAIT:
		/* must be root since the wait applies to following logins */
		error = suser(p->p_ucred, &p->p_acflag);
		if (error != 0) {
			splx(s);
			return(EPERM);
		}

		/* if it's the console, can't do it (XXX why?) */
		if (UNIT(dev) == comconsole) {
			splx(s);
			return(ENOTTY);
		}

		com->dtr_wait = *(int *)data;
		break;
	case TIOCMGDTRWAIT:
		*(int *)data = com->dtr_wait;
		break;
	case TIOCTIMESTAMP:
		com->do_timestamp = 1;
		*(struct timeval *)data = com->timestamp;
		break;
	default:
		splx(s);
		return (ENOTTY);
	}
	splx(s);
	return (0);
}

/* cancel pending output */
static void
comflush(com)
	struct com_s	*com;
{
	struct ringb	*rbp;

	disable_intr();
	if (com->state & CS_ODONE)
		com_events -= LOTS_OF_EVENTS;
	com->state &= ~(CS_ODONE | CS_BUSY);
	enable_intr();
	rbp = &com->tp->t_out;
	rbp->rb_hd += com->ocount;
	rbp->rb_hd = RB_ROLLOVER(rbp, rbp->rb_hd);
	com->ocount = 0;
	com->tp->t_state &= ~TS_BUSY;
}

void
siopoll()
{
	static bool_t	awake = FALSE;
	int		s;
	int		unit;

	if (com_events == 0)
		return;
	disable_intr();
	if (awake) {
		enable_intr();
		return;
	}
	awake = TRUE;
	enable_intr();
	s = spltty();
repeat:
	for (unit = 0; unit < NSIO; ++unit) {
		u_char          *buf;
		struct com_s    *com;
		u_char		*ibuf;
		int		incc;
		struct tty	*tp;

		com = com_addr(unit);
		if (com == NULL)
			continue;
		tp = com->tp;

		/* switch the role of the low-level input buffers */
		if (com->iptr == (ibuf = com->ibuf)) {
			buf = NULL;     /* not used, but compiler can't tell */
			incc = 0;
		} else {
			buf = ibuf;
			disable_intr();
			incc = com->iptr - buf;
			com_events -= incc;
			if (ibuf == com->ibuf1)
				ibuf = com->ibuf2;
			else
				ibuf = com->ibuf1;
			com->ibufend = ibuf + RS_IBUFSIZE;
			com->ihighwater = ibuf + RS_IHIGHWATER;
			com->iptr = ibuf;

			/*
			 * There is now room for another low-level buffer full
			 * of input, so enable RTS if it is now disabled and
			 * there is room in the high-level buffer.
			 */
			if (!(com->mcr_image & MCR_RTS)
			    && !(tp->t_state & TS_RTS_IFLOW))
				outb(com->modem_ctl_port,
				     com->mcr_image |= MCR_RTS);
			enable_intr();
			com->ibuf = ibuf;
		}

		if (com->state & CS_CHECKMSR) {
			u_char	delta_modem_status;

			disable_intr();
			delta_modem_status = com->last_modem_status
					     ^ com->prev_modem_status;
			com->prev_modem_status = com->last_modem_status;
			com_events -= LOTS_OF_EVENTS;
			com->state &= ~CS_CHECKMSR;
			enable_intr();
			if (delta_modem_status & MSR_DCD && !FAKE_DCD(unit)) {
				if (com->prev_modem_status & MSR_DCD) {
					(*linesw[tp->t_line].l_modem)(tp, 1);
#ifdef COM_BIDIR
					wakeup((caddr_t) &com->active_in);
#endif /* COM_BIDIR */
				} else
					(*linesw[tp->t_line].l_modem)(tp, 0);
			}
		}

		/* XXX */
		if (TRUE) {
			u_int delta;
			int errnum;
			u_long total;

			for (errnum = 0; errnum < CE_NTYPES; ++errnum) {
			disable_intr();
				delta = com->delta_error_counts[errnum];
				com->delta_error_counts[errnum] = 0;
			enable_intr();
				if (delta != 0) {
					total =
					com->error_counts[errnum] += delta;
					log(LOG_WARNING,
					"sio%d: %u more %s%s (total %lu)\n",
					    unit, delta, error_desc[errnum],
					    delta == 1 ? "" : "s", total);
				}
			}
		}
		if (com->state & CS_ODONE) {
			comflush(com);
			/* XXX - why isn't the table used for t_line == 0? */
			if (tp->t_line != 0)
				(*linesw[tp->t_line].l_start)(tp);
			else
				comstart(tp);
		}
		if (incc <= 0 || !(tp->t_state & TS_ISOPEN))
			continue;
		if (com->state & CS_RTS_IFLOW
		    && RB_LEN(&tp->t_raw) + incc >= RB_I_HIGH_WATER
		    && !(tp->t_state & TS_RTS_IFLOW)
		    /*
		     * XXX - need RTS flow control for all line disciplines.
		     * Only have it in standard one now.
		     */
		    && linesw[tp->t_line].l_rint == ttyinput) {
			tp->t_state |= TS_RTS_IFLOW;
			ttstart(tp);
		}
		/*
		 * Avoid the grotesquely inefficient lineswitch routine
		 * (ttyinput) in "raw" mode.  It usually takes about 450
		 * instructions (that's without canonical processing or echo!).
		 * slinput is reasonably fast (usually 40 instructions plus
		 * call overhead).
		 */
		if (!(tp->t_iflag & (ICRNL | IGNCR | IMAXBEL | INLCR | ISTRIP
				   | IXOFF | IXON))
		    && !(tp->t_lflag & (ECHO | ECHONL | ICANON | IEXTEN | ISIG
				   | PENDIN))
		    && !(tp->t_state & (TS_CNTTB | TS_LNCH))
		    && linesw[tp->t_line].l_rint == ttyinput) {
			tk_nin += incc;
			tk_rawcc += incc;
			tp->t_rawcc += incc;
			com->delta_error_counts[CE_TTY_BUF_OVERFLOW]
				+= incc - rb_write(&tp->t_raw, (char *) buf,
						   incc);
			ttwakeup(tp);
			if (tp->t_state & TS_TTSTOP
			    && (tp->t_iflag & IXANY
				|| tp->t_cc[VSTART] == tp->t_cc[VSTOP])) {
				tp->t_state &= ~TS_TTSTOP;
				tp->t_lflag &= ~FLUSHO;
				ttstart(tp);
			}
		} else {
			do {
				u_char	line_status;
				int	recv_data;

				line_status = (u_char) buf[CE_INPUT_OFFSET];
				recv_data = (u_char) *buf++;
				if (line_status
				    & (LSR_BI | LSR_FE | LSR_OE | LSR_PE)) {
					if (line_status & LSR_BI)
						recv_data |= TTY_BI;
					if (line_status & LSR_FE)
						recv_data |= TTY_FE;
					if (line_status & LSR_OE)
						recv_data |= TTY_OE;
					if (line_status & LSR_PE)
						recv_data |= TTY_PE;
				}
				(*linesw[tp->t_line].l_rint)(recv_data, tp);
			} while (--incc > 0);
		}
		if (com_events == 0)
			break;
	}
	if (com_events >= LOTS_OF_EVENTS)
		goto repeat;
	splx(s);
	awake = FALSE;
}

static int
comparam(tp, t)
	struct tty	*tp;
	struct termios	*t;
{
	u_int		cfcr;
	int		cflag;
	struct com_s	*com;
	int		divisor;
	int		error;
	Port_t		iobase;
	int		s;
	int		unit;

	/* check requested parameters */
	divisor = ttspeedtab(t->c_ospeed, comspeedtab);
	if (t->c_ispeed == 0)
		t->c_ispeed = t->c_ospeed;
	if (divisor < 0 || t->c_ispeed != t->c_ospeed)
		return (EINVAL);

	/* parameters are OK, convert them to the com struct and the device */
	unit = UNIT(tp->t_dev);
	com = com_addr(unit);
	iobase = com->iobase;
	s = spltty();
	if (divisor == 0)
		commctl(com, MCR_DTR, DMBIC);	/* hang up line */
	else
		commctl(com, MCR_DTR, DMBIS);
	cflag = t->c_cflag;
	switch (cflag & CSIZE) {
	case CS5:
		cfcr = CFCR_5BITS;
		break;
	case CS6:
		cfcr = CFCR_6BITS;
		break;
	case CS7:
		cfcr = CFCR_7BITS;
		break;
	default:
		cfcr = CFCR_8BITS;
		break;
	}
	if (cflag & PARENB) {
		cfcr |= CFCR_PENAB;
		if (!(cflag & PARODD))
			cfcr |= CFCR_PEVEN;
	}
	if (cflag & CSTOPB)
		cfcr |= CFCR_STOPB;

	/*
	 * Some UARTs lock up if the divisor latch registers are selected
	 * while the UART is doing output (they refuse to transmit anything
	 * more until given a hard reset).  Fix this by stopping filling
	 * the device buffers and waiting for them to drain.  Reading the
	 * line status port outside of siointr() might lose some receiver
	 * error bits, but that is acceptable here.
	 */
	disable_intr();
retry:
	com->state &= ~CS_TTGO;
	enable_intr();
	while ((inb(com->line_status_port) & (LSR_TSRE | LSR_TXRDY))
	       != (LSR_TSRE | LSR_TXRDY)) {
		error = ttysleep(tp, (caddr_t)&tp->t_raw, TTIPRI | PCATCH,
				 "sioparam", 1);
		if (error != 0 && error != EAGAIN) {
			if (!(tp->t_state & TS_TTSTOP)) {
				disable_intr();
				com->state |= CS_TTGO;
				enable_intr();
			}
			splx(s);
			return (error);
		}
	}

	disable_intr();		/* very important while com_data is hidden */

	/*
	 * XXX - clearing CS_TTGO is not sufficient to stop further output,
	 * because siopoll() calls comstart() which usually sets it again
	 * because TS_TTSTOP is clear.  Setting TS_TTSTOP would not be
	 * sufficient, for similar reasons.
	 */
	if ((inb(com->line_status_port) & (LSR_TSRE | LSR_TXRDY))
	       != (LSR_TSRE | LSR_TXRDY))
		goto retry;

	if (divisor != 0) {
		outb(iobase + com_cfcr, cfcr | CFCR_DLAB);
		outb(iobase + com_dlbl, divisor & 0xFF);
		outb(iobase + com_dlbh, (u_int) divisor >> 8);
	}
	outb(iobase + com_cfcr, com->cfcr_image = cfcr);
	if (!(tp->t_state & TS_TTSTOP))
		com->state |= CS_TTGO;
	if (cflag & CRTS_IFLOW)
		com->state |= CS_RTS_IFLOW;	/* XXX - secondary changes? */
	else
		com->state &= ~CS_RTS_IFLOW;

	/*
	 * Set up state to handle output flow control.
	 * XXX - worth handling MDMBUF (DCD) flow control at the lowest level?
	 * Now has 16+ msec latency, while CTS flow has 50- usec latency.
	 */
	com->state &= ~CS_CTS_OFLOW;
	com->state |= CS_ODEVREADY;
	if (cflag & CCTS_OFLOW) {
		com->state |= CS_CTS_OFLOW;
		if (!(com->last_modem_status & MSR_CTS))
			com->state &= ~CS_ODEVREADY;
	}

	/*
	 * Recover from fiddling with CS_TTGO.  We used to call siointr()
	 * unconditionally, but that defeated the careful discarding of
	 * stale input in sioopen().
	 *
	 * XXX sioopen() is not careful waiting for carrier for the callout
	 * case.
	 */
	if (com->state >= (CS_BUSY | CS_TTGO))
		comintr1(com);

	enable_intr();
	splx(s);
	return (0);
}

static void
comstart(tp)
	struct tty	*tp;
{
	struct com_s	*com;
	int		s;
	int		unit;

	unit = UNIT(tp->t_dev);
	com = com_addr(unit);
	s = spltty();
	disable_intr();
	if (tp->t_state & TS_TTSTOP)
		com->state &= ~CS_TTGO;
	else
		com->state |= CS_TTGO;
	if (tp->t_state & TS_RTS_IFLOW) {
		if (com->mcr_image & MCR_RTS && com->state & CS_RTS_IFLOW)
			outb(com->modem_ctl_port, com->mcr_image &= ~MCR_RTS);
	} else {
		if (!(com->mcr_image & MCR_RTS) && com->iptr < com->ihighwater)
			outb(com->modem_ctl_port, com->mcr_image |= MCR_RTS);
	}
	enable_intr();
	if (tp->t_state & (TS_TIMEOUT | TS_TTSTOP))
		goto out;
	if (RB_LEN(&tp->t_out) <= tp->t_lowat) {
		if (tp->t_state & TS_ASLEEP) {
			tp->t_state &= ~TS_ASLEEP;
			wakeup((caddr_t)&tp->t_out);
		}
		if (tp->t_wsel) {
			selwakeup(tp->t_wsel, tp->t_state & TS_WCOLL);
			tp->t_wsel = 0;
			tp->t_state &= ~TS_WCOLL;
		}
	}
	if (com->ocount != 0) {
		disable_intr();
		comintr1(com);
		enable_intr();
	} else if (RB_LEN(&tp->t_out) != 0) {
		tp->t_state |= TS_BUSY;
		com->ocount = RB_CONTIGGET(&tp->t_out);
		disable_intr();
		com->obufend = (com->optr = (u_char *) tp->t_out.rb_hd)
			      + com->ocount;
		com->state |= CS_BUSY;
		comintr1(com);  /* fake interrupt to start output */
		enable_intr();
	}
out:
	splx(s);
}

void
siostop(tp, rw)
	struct tty	*tp;
	int		rw;
{
	struct com_s	*com;

	com = com_addr(UNIT(tp->t_dev));
	if (rw & FWRITE)
		comflush(com);
	disable_intr();
	if (rw & FREAD) {
		com_events -= (com->iptr - com->ibuf);
		com->iptr = com->ibuf;
	}
	if (tp->t_state & TS_TTSTOP)
		com->state &= ~CS_TTGO;
	else
		com->state |= CS_TTGO;
	enable_intr();
}

int
sioselect(dev, rw, p)
	dev_t		dev;
	int		rw;
	struct proc	*p;
{
#ifdef COM_BIDIR
	return ttselect(dev & ~COM_CALLOUTMASK, rw, p);
#else
	return ttselect(dev, rw, p);
#endif
}

static void
commctl(com, bits, how)
	struct com_s	*com;
	int		bits;
	int		how;
{
	disable_intr();
	switch (how) {
	case DMSET:
		outb(com->modem_ctl_port,
		     com->mcr_image = bits | (com->mcr_image & MCR_IENABLE));
		break;
	case DMBIS:
		outb(com->modem_ctl_port, com->mcr_image |= bits);
		break;
	case DMBIC:
		outb(com->modem_ctl_port, com->mcr_image &= ~bits);
		break;
	}
	enable_intr();
}

static void
comwakeup(chan, ticks)
	caddr_t chan;
	int ticks;
{
	int		unit;

	timeout(comwakeup, (caddr_t) NULL, hz / 100);
	if (com_events != 0)
		/* schedule siopoll() to run when the cpl allows */
		setsofttty();

	/* recover from lost output interrupts */
	for (unit = 0; unit < NSIO; ++unit) {
		struct com_s	*com;

		com = com_addr(unit);
		if (com != NULL && com->state >= (CS_BUSY | CS_TTGO)) {
			disable_intr();
			comintr1(com);
			enable_intr();
		}
	}
	return;
}

void
softsio1()
{
	siopoll();
}

/*
 * Following are all routines needed for SIO to act as console
 * XXX - not tested in this version
 * XXX - i386/cons.c only knows about the com driver (NCOM and not NSIO)
 * XXX - check that the corresponding serial interrupts are never enabled
 */
#include "i386/i386/cons.h"

void
siocnprobe(cp)
	struct consdev	*cp;
{
	int	unit;

	/* locate the major number */
	for (commajor = 0; commajor < nchrdev; commajor++)
		if (cdevsw[commajor].d_open == sioopen)
			break;

	/* XXX: ick */
	unit = UNIT(CONUNIT);
	com_addr(unit) = &com_structs[unit];
	com_addr(unit)->iobase = CONADDR;

	/* make sure hardware exists?  XXX */

	/* initialize required fields */
	cp->cn_dev = makedev(commajor, unit);
#ifdef	COMCONSOLE
	cp->cn_pri = CN_REMOTE;		/* Force a serial port console */
#else
	cp->cn_pri = CN_NORMAL;
#endif
}

void
siocninit(cp)
	struct consdev	*cp;
{
	int	unit;

	unit = UNIT(cp->cn_dev);
	cominit(unit, comdefaultrate);
	comconsole = unit;
	comconsinit = TRUE;
}

static void
cominit(unit, rate)
	int	unit;
	int	rate;
{
	Port_t	iobase;
	int	s;

	iobase = com_addr(unit)->iobase;
	s = splhigh();
	outb(iobase + com_cfcr, CFCR_DLAB);
	rate = ttspeedtab(comdefaultrate, comspeedtab);
	outb(iobase + com_dlbl, rate & 0xFF);
	outb(iobase + com_dlbh, rate >> 8);
	outb(iobase + com_cfcr, CFCR_8BITS);
	outb(iobase + com_fifo,
	     FIFO_ENABLE | FIFO_TRIGGER | FIFO_RCV_RST | FIFO_XMT_RST);
	DELAY(100);
	(void) inb(iobase + com_lsr);
	(void) inb(iobase + com_data);
	(void) inb(iobase + com_msr);

	/*
	 * XXX - fishy to enable interrupts and then poll.
	 * It shouldn't be necessary to ready the iir.
	 */
	outb(iobase + com_ier, IER_ERXRDY | IER_ETXRDY | IER_ERLS | IER_EMSC);
	(void) inb(iobase + com_iir);
	splx(s);
}

int
siocngetc(dev)
	dev_t	dev;
{
	int	c;
	Port_t	iobase;
	int	s;

	iobase = com_addr(UNIT(dev))->iobase;
	s = splhigh();
	while (!(inb(iobase + com_lsr) & LSR_RXRDY))
		;
	c = inb(iobase + com_data);
	(void) inb(iobase + com_iir);
	splx(s);
	return (c);
}

void
siocnputc(dev, c)
	dev_t	dev;
	int	c;
{
	Port_t	iobase;
	int	s;
	int	timo;

	iobase = com_addr(UNIT(dev))->iobase;
	s = splhigh();
#ifdef KGDB
	if (dev != kgdb_dev)
#endif
	if (!comconsinit) {
		cominit(UNIT(dev), comdefaultrate);
		comconsinit = TRUE;
	}
	/* wait for any pending transmission to finish */
	timo = 50000;
	while (!(inb(iobase + com_lsr) & LSR_TXRDY) && --timo)
		;
	outb(iobase + com_data, c);
	/* wait for this transmission to complete */
	timo = 1500000;
	while (!(inb(iobase + com_lsr) & LSR_TXRDY) && --timo)
		;
	/* clear any interrupts generated by this transmission */
	(void) inb(iobase + com_iir);
	splx(s);
}

#endif /* NSIO > 0 */
