/*-
 * Copyright (c) 1992, 1993, University of Vermont and State
 *  Agricultural College.
 * Copyright (c) 1992, 1993, Garrett A. Wollman.
 *
 * Portions:
 * Copyright (c) 1990, 1991, William F. Jolitz
 * Copyright (c) 1990, The Regents of the University of California
 *
 * 3Com 3C507 support:
 * Copyright (c) 1993, 1994, Charles M. Hannum
 *
 * EtherExpress 16 support:
 * Copyright (c) 1993, 1994, 1995, Rodney W. Grimes
 * Copyright (c) 1997, Aaron C. Smith
 *
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
 *	Vermont and State Agricultural College and Garrett A. Wollman, by
 *	William F. Jolitz, by the University of California, Berkeley,
 *	Lawrence Berkeley Laboratory, and their contributors, by
 *	Charles M. Hannum, by Rodney W. Grimes, and by Aaron C. Smith.
 * 4. Neither the names of the Universities nor the names of the authors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR AUTHORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 * MAINTAINER: Matthew N. Dodd <winter@jurai.net>
 */

/*
 * Intel 82586 Ethernet chip
 * Register, bit, and structure definitions.
 *
 * Written by GAW with reference to the Clarkson Packet Driver code for this
 * chip written by Russ Nelson and others.
 *
 * Intel EtherExpress 16 support from if_ix.c, written by Rodney W. Grimes.
 */

/*
 * The i82586 is a very versatile chip, found in many implementations.
 * Programming this chip is mostly the same, but certain details differ
 * from card to card.  This driver is written so that different cards
 * can be automatically detected at run-time.
 */

/*
Mode of operation:

We run the 82586 in a standard Ethernet mode.  We keep NFRAMES received
frame descriptors around for the receiver to use, and NRXBUFS associated
receive buffer descriptors, both in a circular list.  Whenever a frame is
received, we rotate both lists as necessary.  (The 586 treats both lists
as a simple queue.)  We also keep a transmit command around so that packets
can be sent off quickly.

We configure the adapter in AL-LOC = 1 mode, which means that the
Ethernet/802.3 MAC header is placed at the beginning of the receive buffer
rather than being split off into various fields in the RFD.  This also
means that we must include this header in the transmit buffer as well.

By convention, all transmit commands, and only transmit commands, shall
have the I (IE_CMD_INTR) bit set in the command.  This way, when an
interrupt arrives at ieintr(), it is immediately possible to tell
what precisely caused it.  ANY OTHER command-sending routines should
run at splimp(), and should post an acknowledgement to every interrupt
they generate.

The 82586 has a 24-bit address space internally, and the adaptor's memory
is located at the top of this region.  However, the value we are given in
configuration is normally the *bottom* of the adaptor RAM.  So, we must go
through a few gyrations to come up with a kernel virtual address which
represents the actual beginning of the 586 address space.  First, we
autosize the RAM by running through several possible sizes and trying to
initialize the adapter under the assumption that the selected size is
correct.  Then, knowing the correct RAM size, we set up our pointers in
the softc `iomem' represents the computed base of the 586 address
space.  `iomembot' represents the actual configured base of adapter RAM.
Finally, `iosize' represents the calculated size of 586 RAM.  Then, when
laying out commands, we use the interval [iomembot, iomembot + iosize); to
make 24-pointers, we subtract iomem, and to make 16-pointers, we subtract
iomem and and with 0xffff.

*/

#include "ie.h"
#include "opt_inet.h"
#include "opt_ipx.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <machine/md_var.h>

#include <i386/isa/isa_device.h>
#include <i386/isa/icu.h>
#include <dev/ic/i82586.h>
#include <dev/ie/if_iereg.h>
#include <dev/ie/if_ie507.h>
#include <dev/ie/if_iee16.h>
#include <i386/isa/elink.h>

#include <net/bpf.h>

#ifndef COMPAT_OLDISA
#error "The ie device requires the old isa compatibility shims"
#endif

#ifdef DEBUG
#define IED_RINT	0x01
#define IED_TINT	0x02
#define IED_RNR		0x04
#define IED_CNA		0x08
#define IED_READFRAME	0x10
static int	ie_debug = IED_RNR;

#endif

#define IE_BUF_LEN	ETHER_MAX_LEN	/* length of transmit buffer */

/* Forward declaration */
struct ie_softc;

static int	ieprobe			(struct isa_device * dvp);
static int	ieattach		(struct isa_device * dvp);
static ointhand2_t	ieintr;
static int	sl_probe		(struct isa_device * dvp);
static int	el_probe		(struct isa_device * dvp);
static int	ee16_probe		(struct isa_device * dvp);

static int	check_ie_present	(struct ie_softc *, caddr_t, unsigned);
static void	ieinit			(void *);
static void	ie_stop			(struct ie_softc *);
static int	ieioctl			(struct ifnet *, u_long, caddr_t);
static void	iestart			(struct ifnet *);

static void	el_reset_586		(struct ie_softc *);
static void	el_chan_attn		(struct ie_softc *);

static void	sl_reset_586		(struct ie_softc *);
static void	sl_chan_attn		(struct ie_softc *);

static void	ee16_reset_586		(struct ie_softc *);
static void	ee16_chan_attn		(struct ie_softc *);
static __inline void
		ee16_interrupt_enable	(struct ie_softc *);
static void	ee16_eeprom_outbits	(struct ie_softc *, int, int);
static void	ee16_eeprom_clock	(struct ie_softc *, int);
static u_short	ee16_read_eeprom	(struct ie_softc *, int);
static int	ee16_eeprom_inbits	(struct ie_softc *);
static void	ee16_shutdown		(void *, int);

static __inline void
		ie_ack			(struct ie_softc *, u_int);
static void	iereset			(struct ie_softc *);
static void	ie_readframe		(struct ie_softc *, int);
static void	ie_drop_packet_buffer	(struct ie_softc *);
static void	sl_read_ether		(struct ie_softc *, unsigned char *);
static void	find_ie_mem_size	(struct ie_softc *);
static void	chan_attn_timeout	(void *);
static int	command_and_wait	(struct ie_softc *,
					 int, void volatile *, int);
static void	run_tdr			(struct ie_softc *,
					 volatile struct ie_tdr_cmd *);
static int	ierint			(struct ie_softc *);
static int	ietint			(struct ie_softc *);
static int	iernr			(struct ie_softc *);
static void	start_receiver		(struct ie_softc *);
static __inline int
		ieget			(struct ie_softc *, struct mbuf **);
static v_caddr_t setup_rfa		(struct ie_softc *, v_caddr_t);
static int	mc_setup		(struct ie_softc *);
static void	ie_mc_reset		(struct ie_softc *);

#ifdef DEBUG
static void	print_rbd		(volatile struct ie_recv_buf_desc * rbd);

static int	in_ierint = 0;
static int	in_ietint = 0;

#endif

/*
 * This tells the autoconf code how to set us up.
 */
struct isa_driver iedriver = {
	INTR_TYPE_NET,
	ieprobe, ieattach, "ie"
};
COMPAT_ISA_DRIVER(ie, iedriver);

enum ie_hardware {
	IE_STARLAN10,
	IE_EN100,
	IE_SLFIBER,
	IE_3C507,
	IE_NI5210,
	IE_EE16,
	IE_UNKNOWN
};

static const char *ie_hardware_names[] = {
	"StarLAN 10",
	"EN100",
	"StarLAN Fiber",
	"3C507",
	"NI5210",
	"EtherExpress 16",
	"Unknown"
};

/*
sizeof(iscp) == 1+1+2+4 == 8
sizeof(scb) == 2+2+2+2+2+2+2+2 == 16
NFRAMES * sizeof(rfd) == NFRAMES*(2+2+2+2+6+6+2+2) == NFRAMES*24 == 384
sizeof(xmit_cmd) == 2+2+2+2+6+2 == 18
sizeof(transmit buffer) == 1512
sizeof(transmit buffer desc) == 8
-----
1946

NRXBUFS * sizeof(rbd) == NRXBUFS*(2+2+4+2+2) == NRXBUFS*12
NRXBUFS * IE_RBUF_SIZE == NRXBUFS*256

NRXBUFS should be (16384 - 1946) / (256 + 12) == 14438 / 268 == 53

With NRXBUFS == 48, this leaves us 1574 bytes for another command or
more buffers.  Another transmit command would be 18+8+1512 == 1538
---just barely fits!

Obviously all these would have to be reduced for smaller memory sizes.
With a larger memory, it would be possible to roughly double the number of
both transmit and receive buffers.
*/

#define NFRAMES		8	/* number of receive frames */
#define NRXBUFS		48	/* number of buffers to allocate */
#define IE_RBUF_SIZE	256	/* size of each buffer, MUST BE POWER OF TWO */
#define NTXBUFS		2	/* number of transmit commands */
#define IE_TBUF_SIZE	ETHER_MAX_LEN	/* size of transmit buffer */

/*
 * Ethernet status, per interface.
 */
static struct ie_softc {
	struct	 arpcom arpcom;
	void	 (*ie_reset_586) (struct ie_softc *);
	void	 (*ie_chan_attn) (struct ie_softc *);
	enum	 ie_hardware hard_type;
	int	 hard_vers;
	int	 unit;

	u_short	 port;		/* i/o base address for this interface */
	caddr_t	 iomem;		/* memory size */
	caddr_t	 iomembot;	/* memory base address */
	unsigned iosize;
	int	 bus_use;	/* 0 means 16bit, 1 means 8 bit adapter */

	int	 want_mcsetup;
	int	 promisc;
	int	 nframes;
	int	 nrxbufs;
	int	 ntxbufs;
	volatile struct ie_int_sys_conf_ptr *iscp;
	volatile struct ie_sys_ctl_block *scb;
	volatile struct ie_recv_frame_desc **rframes;	/* nframes worth */
	volatile struct ie_recv_buf_desc **rbuffs;	/* nrxbufs worth */
	volatile u_char **cbuffs;			/* nrxbufs worth */
	int	 rfhead, rftail, rbhead, rbtail;

	volatile struct ie_xmit_cmd **xmit_cmds;	/* ntxbufs worth */
	volatile struct ie_xmit_buf **xmit_buffs;	/* ntxbufs worth */
	volatile u_char	 **xmit_cbuffs;			/* ntxbufs worth */
	int	 xmit_count;

	struct	 ie_en_addr mcast_addrs[MAXMCAST + 1];
	int	 mcast_count;

	u_short	 irq_encoded;	/* encoded interrupt on IEE16 */
}	ie_softc[NIE];

#define MK_24(base, ptr) ((caddr_t)((uintptr_t)ptr - (uintptr_t)base))
#define MK_16(base, ptr) ((u_short)(uintptr_t)MK_24(base, ptr))

#define	PORT(sc)	(sc->port)
#define	MEM(sc)		(sc->iomem)

static int
ieprobe(struct isa_device *dvp)
{
	int	ret;

	ret = sl_probe(dvp);
	if (!ret)
		ret = el_probe(dvp);
	if (!ret)
		ret = ee16_probe(dvp);

	return (ret);
}

static int
sl_probe(struct isa_device *dvp)
{
	struct ie_softc *	sc = &ie_softc[dvp->id_unit];
	u_char			c;

	sc->port = dvp->id_iobase;
	sc->iomembot = dvp->id_maddr;
	sc->iomem = 0;
	sc->bus_use = 0;

	c = inb(PORT(sc) + IEATT_REVISION);
	switch (SL_BOARD(c)) {
	case SL10_BOARD:
		sc->hard_type = IE_STARLAN10;
		break;
	case EN100_BOARD:
		sc->hard_type = IE_EN100;
		break;
	case SLFIBER_BOARD:
		sc->hard_type = IE_SLFIBER;
		break;
	case 0x00:
		if (inb(PORT(sc) + IEATT_ATTRIB) != 0x55)
			return (0);
	
		sc->hard_type = IE_NI5210;
		sc->bus_use = 1;

		break;

		/*
		 * Anything else is not recognized or cannot be used.
		 */
	default:
		return (0);
	}

	sc->ie_reset_586 = sl_reset_586;
	sc->ie_chan_attn = sl_chan_attn;

	sc->hard_vers = SL_REV(c);

	/*
	 * Divine memory size on-board the card.  Ususally 16k.
	 */
	find_ie_mem_size(sc);

	if (!sc->iosize) {
		return (0);
	}

	if (!dvp->id_msize) {
		dvp->id_msize = sc->iosize;
	} else if (dvp->id_msize != sc->iosize) {
		printf("ie%d: kernel configured msize %d "
		       "doesn't match board configured msize %d\n",
			sc->unit,
			dvp->id_msize,
			sc->iosize);
		return (0);
	}

	switch (sc->hard_type) {
		case IE_EN100:
		case IE_STARLAN10:
		case IE_SLFIBER:
		case IE_NI5210:
			sl_read_ether(sc, sc->arpcom.ac_enaddr);
			break;
	default:
		if (bootverbose)
			printf("ie%d: unknown AT&T board type code %d\n",
				sc->unit,
		       		sc->hard_type);
		return (0);
	}

	return (16);
}

static int
el_probe(struct isa_device *dvp)
{
	struct ie_softc *sc = &ie_softc[dvp->id_unit];
	u_char	c;
	int	i;
	u_char	signature[] = "*3COM*";

	sc->unit = dvp->id_unit;
	sc->port = dvp->id_iobase;
	sc->iomembot = dvp->id_maddr;
	sc->bus_use = 0;

	/* Need this for part of the probe. */
	sc->ie_reset_586 = el_reset_586;
	sc->ie_chan_attn = el_chan_attn;

	/* Reset and put card in CONFIG state without changing address. */
	elink_reset();
	outb(ELINK_ID_PORT, 0x00);
	elink_idseq(ELINK_507_POLY);
	elink_idseq(ELINK_507_POLY);
	outb(ELINK_ID_PORT, 0xff);

	c = inb(PORT(sc) + IE507_MADDR);
	if (c & 0x20) {
#ifdef DEBUG
		printf("ie%d: can't map 3C507 RAM in high memory\n", sc->unit);
#endif
		return (0);
	}
	/* go to RUN state */
	outb(ELINK_ID_PORT, 0x00);
	elink_idseq(ELINK_507_POLY);
	outb(ELINK_ID_PORT, 0x00);

	outb(PORT(sc) + IE507_CTRL, EL_CTRL_NRST);

	for (i = 0; i < 6; i++)
		if (inb(PORT(sc) + i) != signature[i])
			return (0);

	c = inb(PORT(sc) + IE507_IRQ) & 0x0f;

	if (dvp->id_irq != (1 << c)) {
		printf("ie%d: kernel configured irq %d "
		       "doesn't match board configured irq %d\n",
		       sc->unit, ffs(dvp->id_irq) - 1, c);
		return (0);
	}
	c = (inb(PORT(sc) + IE507_MADDR) & 0x1c) + 0xc0;

	if (kvtop(dvp->id_maddr) != ((int) c << 12)) {
		printf("ie%d: kernel configured maddr %lx "
		       "doesn't match board configured maddr %x\n",
		       sc->unit, (u_long)kvtop(dvp->id_maddr), (int) c << 12);
		return (0);
	}
	outb(PORT(sc) + IE507_CTRL, EL_CTRL_NORMAL);

	sc->hard_type = IE_3C507;
	sc->hard_vers = 0;	/* 3C507 has no version number. */

	/*
	 * Divine memory size on-board the card.
	 */
	find_ie_mem_size(sc);

	if (!sc->iosize) {
		printf("ie%d: can't find shared memory\n", sc->unit);
		outb(PORT(sc) + IE507_CTRL, EL_CTRL_NRST);
		return (0);
	}
	if (!dvp->id_msize)
		dvp->id_msize = sc->iosize;
	else if (dvp->id_msize != sc->iosize) {
		printf("ie%d: kernel configured msize %d "
		       "doesn't match board configured msize %d\n",
		       sc->unit, dvp->id_msize, sc->iosize);
		outb(PORT(sc) + IE507_CTRL, EL_CTRL_NRST);
		return (0);
	}
	sl_read_ether(sc, sc->arpcom.ac_enaddr);

	/* Clear the interrupt latch just in case. */
	outb(PORT(sc) + IE507_ICTRL, 1);

	return (16);
}


static void
ee16_shutdown(void *xsc, int howto)
{
	struct	ie_softc *sc = (struct ie_softc *)xsc;

	ee16_reset_586(sc);
	outb(PORT(sc) + IEE16_ECTRL, IEE16_RESET_ASIC);
	outb(PORT(sc) + IEE16_ECTRL, 0);
}


/* Taken almost exactly from Rod's if_ix.c. */

static int
ee16_probe(struct isa_device *dvp)
{
	struct ie_softc *sc = &ie_softc[dvp->id_unit];

	int	i;
	u_short board_id, id_var1, id_var2, checksum = 0;
	u_short eaddrtemp, irq;
	u_short pg, adjust, decode, edecode;
	u_char	bart_config;
	u_long	bd_maddr;

	short	irq_translate[] = {0, IRQ9, IRQ3, IRQ4, IRQ5, IRQ10, IRQ11, 0};
	char	irq_encode[] = {0, 0, 0, 2, 3, 4, 0, 0, 0, 1, 5, 6, 0, 0, 0, 0};

	/* Need this for part of the probe. */
	sc->ie_reset_586 = ee16_reset_586;
	sc->ie_chan_attn = ee16_chan_attn;

	/* unsure if this is necessary */
	sc->bus_use = 0;

	/* reset any ee16 at the current iobase */
	outb(dvp->id_iobase + IEE16_ECTRL, IEE16_RESET_ASIC);
	outb(dvp->id_iobase + IEE16_ECTRL, 0);
	DELAY(240);

	/* now look for ee16. */
	board_id = id_var1 = id_var2 = 0;
	for (i = 0; i < 4; i++) {
		id_var1 = inb(dvp->id_iobase + IEE16_ID_PORT);
		id_var2 = ((id_var1 & 0x03) << 2);
		board_id |= ((id_var1 >> 4) << id_var2);
	}

	if (board_id != IEE16_ID) {
		if (bootverbose)
			printf("ie%d: unknown board_id: %x\n", sc->unit, board_id);
		return (0);
	}
	/* need sc->port for ee16_read_eeprom */
	sc->port = dvp->id_iobase;
	sc->hard_type = IE_EE16;

	/*
	 * The shared RAM location on the EE16 is encoded into bits 3-7 of
	 * EEPROM location 6.  We zero the upper byte, and shift the 5 bits
	 * right 3.  The resulting number tells us the RAM location.
	 * Because the EE16 supports either 16k or 32k of shared RAM, we
	 * only worry about the 32k locations.
	 *
	 * NOTE: if a 64k EE16 exists, it should be added to this switch. then
	 * the ia->ia_msize would need to be set per case statement.
	 *
	 * value	msize	location
	 * =====	=====	========
	 * 0x03		0x8000	0xCC000
	 * 0x06		0x8000	0xD0000
	 * 0x0C		0x8000	0xD4000
	 * 0x18		0x8000	0xD8000
	 *
	 */

	bd_maddr = 0;
	i = (ee16_read_eeprom(sc, 6) & 0x00ff) >> 3;
	switch (i) {
	case 0x03:
		bd_maddr = 0xCC000;
		break;
	case 0x06:
		bd_maddr = 0xD0000;
		break;
	case 0x0c:
		bd_maddr = 0xD4000;
		break;
	case 0x18:
		bd_maddr = 0xD8000;
		break;
	default:
		bd_maddr = 0;
		break;
	}
	dvp->id_msize = 0x8000;
	if (kvtop(dvp->id_maddr) != bd_maddr) {
		printf("ie%d: kernel configured maddr %lx "
		       "doesn't match board configured maddr %lx\n",
		       sc->unit, (u_long)kvtop(dvp->id_maddr), bd_maddr);
	}
	sc->iomembot = dvp->id_maddr;
	sc->iomem = 0;		/* XXX some probes set this and some don't */
	sc->iosize = dvp->id_msize;

	/* need to put the 586 in RESET while we access the eeprom. */
	outb(PORT(sc) + IEE16_ECTRL, IEE16_RESET_586);

	/* read the eeprom and checksum it, should == IEE16_ID */
	for (i = 0; i < 0x40; i++)
		checksum += ee16_read_eeprom(sc, i);

	if (checksum != IEE16_ID) {
		printf("ie%d: invalid eeprom checksum: %x\n", sc->unit, checksum);
		return (0);
	}
	/*
	 * Size and test the memory on the board.  The size of the memory
	 * can be one of 16k, 32k, 48k or 64k.	It can be located in the
	 * address range 0xC0000 to 0xEFFFF on 16k boundaries.
	 *
	 * If the size does not match the passed in memory allocation size
	 * issue a warning, but continue with the minimum of the two sizes.
	 */

	switch (dvp->id_msize) {
	case 65536:
	case 32768:		/* XXX Only support 32k and 64k right now */
		break;
	case 16384:
	case 49512:
	default:
		printf("ie%d: mapped memory size %d not supported\n",
		       sc->unit, dvp->id_msize);
		return (0);
		break;		/* NOTREACHED */
	}

	if ((kvtop(dvp->id_maddr) < 0xC0000) ||
	    (kvtop(dvp->id_maddr) + sc->iosize > 0xF0000)) {
		printf("ie%d: mapped memory location %p out of range\n",
		       sc->unit, (void *)dvp->id_maddr);
		return (0);
	}
	pg = (kvtop(dvp->id_maddr) & 0x3C000) >> 14;
	adjust = IEE16_MCTRL_FMCS16 | (pg & 0x3) << 2;
	decode = ((1 << (sc->iosize / 16384)) - 1) << pg;
	edecode = ((~decode >> 4) & 0xF0) | (decode >> 8);

	/* ZZZ This should be checked against eeprom location 6, low byte */
	outb(PORT(sc) + IEE16_MEMDEC, decode & 0xFF);
	/* ZZZ This should be checked against eeprom location 1, low byte */
	outb(PORT(sc) + IEE16_MCTRL, adjust);
	/* ZZZ Now if I could find this one I would have it made */
	outb(PORT(sc) + IEE16_MPCTRL, (~decode & 0xFF));
	/* ZZZ I think this is location 6, high byte */
	outb(PORT(sc) + IEE16_MECTRL, edecode);	/* XXX disable Exxx */

	(void) kvtop(dvp->id_maddr);

	/*
	 * first prime the stupid bart DRAM controller so that it works,
	 * then zero out all of memory.
	 */
	bzero(sc->iomembot, 32);
	bzero(sc->iomembot, sc->iosize);

	/*
	 * Get the encoded interrupt number from the EEPROM, check it
	 * against the passed in IRQ.  Issue a warning if they do not match.
	 * Always use the passed in IRQ, not the one in the EEPROM.
	 */
	irq = ee16_read_eeprom(sc, IEE16_EEPROM_CONFIG1);
	irq = (irq & IEE16_EEPROM_IRQ) >> IEE16_EEPROM_IRQ_SHIFT;
	irq = irq_translate[irq];
	if (dvp->id_irq > 0) {
		if (irq != dvp->id_irq) {
			printf("ie%d: WARNING: board configured "
			       "at irq %u, using %u\n",
			       dvp->id_unit, dvp->id_irq, irq);
			irq = dvp->id_unit;
		}
	} else {
		dvp->id_irq = irq;
	}
	sc->irq_encoded = irq_encode[ffs(irq) - 1];

	/*
	 * Get the hardware ethernet address from the EEPROM and save it in
	 * the softc for use by the 586 setup code.
	 */
	eaddrtemp = ee16_read_eeprom(sc, IEE16_EEPROM_ENET_HIGH);
	sc->arpcom.ac_enaddr[1] = eaddrtemp & 0xFF;
	sc->arpcom.ac_enaddr[0] = eaddrtemp >> 8;
	eaddrtemp = ee16_read_eeprom(sc, IEE16_EEPROM_ENET_MID);
	sc->arpcom.ac_enaddr[3] = eaddrtemp & 0xFF;
	sc->arpcom.ac_enaddr[2] = eaddrtemp >> 8;
	eaddrtemp = ee16_read_eeprom(sc, IEE16_EEPROM_ENET_LOW);
	sc->arpcom.ac_enaddr[5] = eaddrtemp & 0xFF;
	sc->arpcom.ac_enaddr[4] = eaddrtemp >> 8;

	/* disable the board interrupts */
	outb(PORT(sc) + IEE16_IRQ, sc->irq_encoded);

	/* enable loopback to keep bad packets off the wire */
	if (sc->hard_type == IE_EE16) {
		bart_config = inb(PORT(sc) + IEE16_CONFIG);
		bart_config |= IEE16_BART_LOOPBACK;
		bart_config |= IEE16_BART_MCS16_TEST;/* inb doesn't get bit! */
		outb(PORT(sc) + IEE16_CONFIG, bart_config);
		bart_config = inb(PORT(sc) + IEE16_CONFIG);
	}
	/* take the board out of reset state */
	outb(PORT(sc) + IEE16_ECTRL, 0);
	DELAY(100);

	if (!check_ie_present(sc, dvp->id_maddr, sc->iosize))
		return (0);

	return (16);		/* return the number of I/O ports */
}

/*
 * Taken almost exactly from Bill's if_is.c, then modified beyond recognition.
 */
static int
ieattach(struct isa_device *dvp)
{
	int	factor;
	struct ie_softc *sc = &ie_softc[dvp->id_unit];
	struct ifnet *ifp = &sc->arpcom.ac_if;
	size_t	allocsize;

	dvp->id_ointr = ieintr;

	/*
	 * based on the amount of memory we have, allocate our tx and rx
	 * resources.
	 */
	factor = dvp->id_msize / 16384;
	sc->nframes = factor * NFRAMES;
	sc->nrxbufs = factor * NRXBUFS;
	sc->ntxbufs = factor * NTXBUFS;

	/*
	 * Since all of these guys are arrays of pointers, allocate as one
	 * big chunk and dole out accordingly.
	 */
	allocsize = sizeof(void *) * (sc->nframes
				      + (sc->nrxbufs * 2)
				      + (sc->ntxbufs * 3));
	sc->rframes = (volatile struct ie_recv_frame_desc **) malloc(allocsize,
								     M_DEVBUF,
								   M_NOWAIT);
	if (sc->rframes == NULL)
		return (0);
	sc->rbuffs =
	    (volatile struct ie_recv_buf_desc **)&sc->rframes[sc->nframes];
	sc->cbuffs = (volatile u_char **)&sc->rbuffs[sc->nrxbufs];
	sc->xmit_cmds =
	    (volatile struct ie_xmit_cmd **)&sc->cbuffs[sc->nrxbufs];
	sc->xmit_buffs =
	    (volatile struct ie_xmit_buf **)&sc->xmit_cmds[sc->ntxbufs];
	sc->xmit_cbuffs = (volatile u_char **)&sc->xmit_buffs[sc->ntxbufs];

	ifp->if_softc = sc;
	ifp->if_unit = dvp->id_unit;
	ifp->if_name = "ie";
	ifp->if_mtu = ETHERMTU;
	printf("ie%d: <%s R%d> address %6D\n", sc->unit,
	       ie_hardware_names[sc->hard_type],
	       sc->hard_vers + 1,
	       sc->arpcom.ac_enaddr, ":");

	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = iestart;
	ifp->if_ioctl = ieioctl;
	ifp->if_init = ieinit;
	ifp->if_snd.ifq_maxlen = IFQ_MAXLEN;

	if (sc->hard_type == IE_EE16)
		EVENTHANDLER_REGISTER(shutdown_post_sync, ee16_shutdown,
				      sc, SHUTDOWN_PRI_DEFAULT);

	ether_ifattach(ifp, sc->arpcom.ac_enaddr);
	return (1);
}

/*
 * What to do upon receipt of an interrupt.
 */
static void
ieintr(int unit)
{
	struct ie_softc *sc = &ie_softc[unit];
	u_short status;

	/* Clear the interrupt latch on the 3C507. */
	if (sc->hard_type == IE_3C507
	 && (inb(PORT(sc) + IE507_CTRL) & EL_CTRL_INTL))
		outb(PORT(sc) + IE507_ICTRL, 1);

	/* disable interrupts on the EE16. */
	if (sc->hard_type == IE_EE16)
		outb(PORT(sc) + IEE16_IRQ, sc->irq_encoded);

	status = sc->scb->ie_status;

loop:

	/* Don't ack interrupts which we didn't receive */
	ie_ack(sc, IE_ST_WHENCE & status);

	if (status & (IE_ST_RECV | IE_ST_RNR)) {
#ifdef DEBUG
		in_ierint++;
		if (ie_debug & IED_RINT)
			printf("ie%d: rint\n", sc->unit);
#endif
		ierint(sc);
#ifdef DEBUG
		in_ierint--;
#endif
	}
	if (status & IE_ST_DONE) {
#ifdef DEBUG
		in_ietint++;
		if (ie_debug & IED_TINT)
			printf("ie%d: tint\n", sc->unit);
#endif
		ietint(sc);
#ifdef DEBUG
		in_ietint--;
#endif
	}
	if (status & IE_ST_RNR) {
#ifdef DEBUG
		if (ie_debug & IED_RNR)
			printf("ie%d: rnr\n", sc->unit);
#endif
		iernr(sc);
	}
#ifdef DEBUG
	if ((status & IE_ST_ALLDONE) && (ie_debug & IED_CNA))
		printf("ie%d: cna\n", sc->unit);
#endif

	if ((status = sc->scb->ie_status) & IE_ST_WHENCE)
		goto loop;

	/* Clear the interrupt latch on the 3C507. */
	if (sc->hard_type == IE_3C507)
		outb(PORT(sc) + IE507_ICTRL, 1);

	/* enable interrupts on the EE16. */
	if (sc->hard_type == IE_EE16)
		outb(PORT(sc) + IEE16_IRQ, sc->irq_encoded | IEE16_IRQ_ENABLE);

}

/*
 * Process a received-frame interrupt.
 */
static int
ierint(struct ie_softc *sc)
{
	int	i, status;
	static int timesthru = 1024;

	i = sc->rfhead;
	while (1) {
		status = sc->rframes[i]->ie_fd_status;

		if ((status & IE_FD_COMPLETE) && (status & IE_FD_OK)) {
			sc->arpcom.ac_if.if_ipackets++;
			if (!--timesthru) {
				sc->arpcom.ac_if.if_ierrors +=
				    sc->scb->ie_err_crc +
				    sc->scb->ie_err_align +
				    sc->scb->ie_err_resource +
				    sc->scb->ie_err_overrun;
				sc->scb->ie_err_crc = 0;
				sc->scb->ie_err_align = 0;
				sc->scb->ie_err_resource = 0;
				sc->scb->ie_err_overrun = 0;
				timesthru = 1024;
			}
			ie_readframe(sc, i);
		} else {
			if (status & IE_FD_RNR) {
				if (!(sc->scb->ie_status & IE_RU_READY)) {
					sc->rframes[0]->ie_fd_next =
					    MK_16(MEM(sc), sc->rbuffs[0]);
					sc->scb->ie_recv_list =
					    MK_16(MEM(sc), sc->rframes[0]);
					command_and_wait(sc, IE_RU_START, 0, 0);
				}
			}
			break;
		}
		i = (i + 1) % sc->nframes;
	}
	return (0);
}

/*
 * Process a command-complete interrupt.  These are only generated by
 * the transmission of frames.	This routine is deceptively simple, since
 * most of the real work is done by iestart().
 */
static int
ietint(struct ie_softc *sc)
{
	int	status;
	int	i;

	sc->arpcom.ac_if.if_timer = 0;
	sc->arpcom.ac_if.if_flags &= ~IFF_OACTIVE;

	for (i = 0; i < sc->xmit_count; i++) {
		status = sc->xmit_cmds[i]->ie_xmit_status;

		if (status & IE_XS_LATECOLL) {
			printf("ie%d: late collision\n", sc->unit);
			sc->arpcom.ac_if.if_collisions++;
			sc->arpcom.ac_if.if_oerrors++;
		} else if (status & IE_XS_NOCARRIER) {
			printf("ie%d: no carrier\n", sc->unit);
			sc->arpcom.ac_if.if_oerrors++;
		} else if (status & IE_XS_LOSTCTS) {
			printf("ie%d: lost CTS\n", sc->unit);
			sc->arpcom.ac_if.if_oerrors++;
		} else if (status & IE_XS_UNDERRUN) {
			printf("ie%d: DMA underrun\n", sc->unit);
			sc->arpcom.ac_if.if_oerrors++;
		} else if (status & IE_XS_EXCMAX) {
			printf("ie%d: too many collisions\n", sc->unit);
			sc->arpcom.ac_if.if_collisions += 16;
			sc->arpcom.ac_if.if_oerrors++;
		} else {
			sc->arpcom.ac_if.if_opackets++;
			sc->arpcom.ac_if.if_collisions += status & IE_XS_MAXCOLL;
		}
	}
	sc->xmit_count = 0;

	/*
	 * If multicast addresses were added or deleted while we were
	 * transmitting, ie_mc_reset() set the want_mcsetup flag indicating
	 * that we should do it.
	 */
	if (sc->want_mcsetup) {
		mc_setup(sc);
		sc->want_mcsetup = 0;
	}
	/* Wish I knew why this seems to be necessary... */
	sc->xmit_cmds[0]->ie_xmit_status |= IE_STAT_COMPL;

	iestart(&sc->arpcom.ac_if);
	return (0);		/* shouldn't be necessary */
}

/*
 * Process a receiver-not-ready interrupt.  I believe that we get these
 * when there aren't enough buffers to go around.  For now (FIXME), we
 * just restart the receiver, and hope everything's ok.
 */
static int
iernr(struct ie_softc *sc)
{
#ifdef doesnt_work
	setup_rfa(sc, (v_caddr_t) sc->rframes[0]);

	sc->scb->ie_recv_list = MK_16(MEM(sc), sc->rframes[0]);
	command_and_wait(sc, IE_RU_START, 0, 0);
#else
	/* This doesn't work either, but it doesn't hang either. */
	command_and_wait(sc, IE_RU_DISABLE, 0, 0);	/* just in case */
	setup_rfa(sc, (v_caddr_t) sc->rframes[0]);	/* ignore cast-qual */

	sc->scb->ie_recv_list = MK_16(MEM(sc), sc->rframes[0]);
	command_and_wait(sc, IE_RU_START, 0, 0);	/* was ENABLE */

#endif
	ie_ack(sc, IE_ST_WHENCE);

	sc->arpcom.ac_if.if_ierrors++;
	return (0);
}

/*
 * Compare two Ether/802 addresses for equality, inlined and
 * unrolled for speed.	I'd love to have an inline assembler
 * version of this...
 */
static __inline int
ether_equal(u_char * one, u_char * two)
{
	if (one[0] != two[0])
		return (0);
	if (one[1] != two[1])
		return (0);
	if (one[2] != two[2])
		return (0);
	if (one[3] != two[3])
		return (0);
	if (one[4] != two[4])
		return (0);
	if (one[5] != two[5])
		return (0);
	return 1;
}

/*
 * Determine quickly whether we should bother reading in this packet.
 * This depends on whether BPF and/or bridging is enabled, whether we
 * are receiving multicast address, and whether promiscuous mode is enabled.
 * We assume that if IFF_PROMISC is set, then *somebody* wants to see
 * all incoming packets.
 */
static __inline int
check_eh(struct ie_softc *sc, struct ether_header *eh)
{
	/* Optimize the common case: normal operation. We've received
	   either a unicast with our dest or a multicast packet. */
	if (sc->promisc == 0) {
		int i;

		/* If not multicast, it's definitely for us */
		if ((eh->ether_dhost[0] & 1) == 0)
			return (1);

		/* Accept broadcasts (loose but fast check) */
		if (eh->ether_dhost[0] == 0xff)
			return (1);

		/* Compare against our multicast addresses */
		for (i = 0; i < sc->mcast_count; i++) {
			if (ether_equal(eh->ether_dhost,
			    (u_char *)&sc->mcast_addrs[i]))
				return (1);
		}
		return (0);
	}

	/* Always accept packets when in promiscuous mode */
	if ((sc->promisc & IFF_PROMISC) != 0)
		return (1);

	/* Always accept packets directed at us */
	if (ether_equal(eh->ether_dhost, sc->arpcom.ac_enaddr))
		return (1);

	/* Must have IFF_ALLMULTI but not IFF_PROMISC set. The chip is
	   actually in promiscuous mode, so discard unicast packets. */
	return((eh->ether_dhost[0] & 1) != 0);
}

/*
 * We want to isolate the bits that have meaning...  This assumes that
 * IE_RBUF_SIZE is an even power of two.  If somehow the act_len exceeds
 * the size of the buffer, then we are screwed anyway.
 */
static __inline int
ie_buflen(struct ie_softc *sc, int head)
{
	return (sc->rbuffs[head]->ie_rbd_actual
		& (IE_RBUF_SIZE | (IE_RBUF_SIZE - 1)));
}

static __inline int
ie_packet_len(struct ie_softc *sc)
{
	int	i;
	int	head = sc->rbhead;
	int	acc = 0;

	do {
		if (!(sc->rbuffs[sc->rbhead]->ie_rbd_actual & IE_RBD_USED)) {
#ifdef DEBUG
			print_rbd(sc->rbuffs[sc->rbhead]);
#endif
			log(LOG_ERR,
			    "ie%d: receive descriptors out of sync at %d\n",
			    sc->unit, sc->rbhead);
			iereset(sc);
			return (-1);
		}
		i = sc->rbuffs[head]->ie_rbd_actual & IE_RBD_LAST;

		acc += ie_buflen(sc, head);
		head = (head + 1) % sc->nrxbufs;
	} while (!i);

	return (acc);
}

/*
 * Read data off the interface, and turn it into an mbuf chain.
 *
 * This code is DRAMATICALLY different from the previous version; this
 * version tries to allocate the entire mbuf chain up front, given the
 * length of the data available.  This enables us to allocate mbuf
 * clusters in many situations where before we would have had a long
 * chain of partially-full mbufs.  This should help to speed up the
 * operation considerably.  (Provided that it works, of course.)
 */
static __inline int
ieget(struct ie_softc *sc, struct mbuf **mp)
{
	struct	ether_header eh;
	struct	mbuf *m, *top, **mymp;
	int	offset;
	int	totlen, resid;
	int	thismboff;
	int	head;

	totlen = ie_packet_len(sc);
	if (totlen <= 0)
		return (-1);

	/*
	 * Snarf the Ethernet header.
	 */
	bcopy((caddr_t)sc->cbuffs[sc->rbhead], &eh, sizeof(struct ether_header));
	/* ignore cast-qual warning here */

	/*
	 * As quickly as possible, check if this packet is for us. If not,
	 * don't waste a single cycle copying the rest of the packet in.
	 * This is only a consideration when FILTER is defined; i.e., when
	 * we are either running BPF or doing multicasting.
	 */
	if (!check_eh(sc, &eh)) {
		ie_drop_packet_buffer(sc);
		sc->arpcom.ac_if.if_ierrors--;	/* just this case, it's not an
						 * error
						 */
		return (-1);
	}

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (!m) {
		ie_drop_packet_buffer(sc);
		/* XXXX if_ierrors++; */
		return (-1);
	}

	*mp = m;
	m->m_pkthdr.rcvif = &sc->arpcom.ac_if;
	m->m_len = MHLEN;
	resid = m->m_pkthdr.len = totlen;
	top = 0;

	mymp = &top;

	/*
	 * This loop goes through and allocates mbufs for all the data we
	 * will be copying in.	It does not actually do the copying yet.
	 */
	do {			/* while(resid > 0) */
		/*
		 * Try to allocate an mbuf to hold the data that we have.
		 * If we already allocated one, just get another one and
		 * stick it on the end (eventually).  If we don't already
		 * have one, try to allocate an mbuf cluster big enough to
		 * hold the whole packet, if we think it's reasonable, or a
		 * single mbuf which may or may not be big enough. Got that?
		 */
		if (top) {
			MGET(m, M_DONTWAIT, MT_DATA);
			if (!m) {
				m_freem(top);
				ie_drop_packet_buffer(sc);
				return (-1);
			}
			m->m_len = MLEN;
		}
		if (resid >= MINCLSIZE) {
			MCLGET(m, M_DONTWAIT);
			if (m->m_flags & M_EXT)
				m->m_len = min(resid, MCLBYTES);
		} else {
			if (resid < m->m_len) {
				if (!top && resid + max_linkhdr <= m->m_len)
					m->m_data += max_linkhdr;
				m->m_len = resid;
			}
		}
		resid -= m->m_len;
		*mymp = m;
		mymp = &m->m_next;
	} while (resid > 0);

	resid = totlen;					/* remaining data */
	offset = 0;					/* packet offset */
	thismboff = 0;					/* offset in m */

	m = top;					/* current mbuf */
	head = sc->rbhead;				/* current rx buffer */

	/*
	 * Now we take the mbuf chain (hopefully only one mbuf most of the
	 * time) and stuff the data into it.  There are no possible failures
	 * at or after this point.
	 */
	while (resid > 0) {	/* while there's stuff left */
		int	thislen = ie_buflen(sc, head) - offset;

		/*
		 * If too much data for the current mbuf, then fill the
		 * current one up, go to the next one, and try again.
		 */
		if (thislen > m->m_len - thismboff) {
			int	newlen = m->m_len - thismboff;

			bcopy((v_caddr_t) (sc->cbuffs[head] + offset),
			      mtod(m, caddr_t) +thismboff, (unsigned) newlen);
			/* ignore cast-qual warning */
			m = m->m_next;
			thismboff = 0;		/* new mbuf, so no offset */
			offset += newlen;	/* we are now this far into
						 * the packet */
			resid -= newlen;	/* so there is this much left
						 * to get */
			continue;
		}
		/*
		 * If there is more than enough space in the mbuf to hold
		 * the contents of this buffer, copy everything in, advance
		 * pointers, and so on.
		 */
		if (thislen < m->m_len - thismboff) {
			bcopy((v_caddr_t) (sc->cbuffs[head] + offset),
			    mtod(m, caddr_t) +thismboff, (unsigned) thislen);
			thismboff += thislen;	/* we are this far into the
						 * mbuf */
			resid -= thislen;	/* and this much is left */
			goto nextbuf;
		}
		/*
		 * Otherwise, there is exactly enough space to put this
		 * buffer's contents into the current mbuf.  Do the
		 * combination of the above actions.
		 */
		bcopy((v_caddr_t) (sc->cbuffs[head] + offset),
		      mtod(m, caddr_t) + thismboff, (unsigned) thislen);
		m = m->m_next;
		thismboff = 0;		/* new mbuf, start at the beginning */
		resid -= thislen;	/* and we are this far through */

		/*
		 * Advance all the pointers.  We can get here from either of
		 * the last two cases, but never the first.
		 */
nextbuf:
		offset = 0;
		sc->rbuffs[head]->ie_rbd_actual = 0;
		sc->rbuffs[head]->ie_rbd_length |= IE_RBD_LAST;
		sc->rbhead = head = (head + 1) % sc->nrxbufs;
		sc->rbuffs[sc->rbtail]->ie_rbd_length &= ~IE_RBD_LAST;
		sc->rbtail = (sc->rbtail + 1) % sc->nrxbufs;
	}

	/*
	 * Unless something changed strangely while we were doing the copy,
	 * we have now copied everything in from the shared memory. This
	 * means that we are done.
	 */
	return (0);
}

/*
 * Read frame NUM from unit UNIT (pre-cached as IE).
 *
 * This routine reads the RFD at NUM, and copies in the buffers from
 * the list of RBD, then rotates the RBD and RFD lists so that the receiver
 * doesn't start complaining.  Trailers are DROPPED---there's no point
 * in wasting time on confusing code to deal with them.	 Hopefully,
 * this machine will never ARP for trailers anyway.
 */
static void
ie_readframe(struct ie_softc *sc, int	num/* frame number to read */)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	struct ie_recv_frame_desc rfd;
	struct mbuf *m = 0;
#ifdef DEBUG
	struct ether_header *eh;
#endif

	bcopy((v_caddr_t) (sc->rframes[num]), &rfd,
	      sizeof(struct ie_recv_frame_desc));

	/*
	 * Immediately advance the RFD list, since we we have copied ours
	 * now.
	 */
	sc->rframes[num]->ie_fd_status = 0;
	sc->rframes[num]->ie_fd_last |= IE_FD_LAST;
	sc->rframes[sc->rftail]->ie_fd_last &= ~IE_FD_LAST;
	sc->rftail = (sc->rftail + 1) % sc->nframes;
	sc->rfhead = (sc->rfhead + 1) % sc->nframes;

	if (rfd.ie_fd_status & IE_FD_OK) {
		if (ieget(sc, &m)) {
			sc->arpcom.ac_if.if_ierrors++;	/* this counts as an
							 * error */
			return;
		}
	}
#ifdef DEBUG
	eh = mtod(m, struct ether_header *);
	if (ie_debug & IED_READFRAME) {
		printf("ie%d: frame from ether %6D type %x\n", sc->unit,
		       eh->ether_shost, ":", (unsigned) eh->ether_type);
	}
	if (ntohs(eh->ether_type) > ETHERTYPE_TRAIL
	    && ntohs(eh->ether_type) < (ETHERTYPE_TRAIL + ETHERTYPE_NTRAILER))
		printf("received trailer!\n");
#endif

	if (!m)
		return;

	/*
	 * Finally pass this packet up to higher layers.
	 */
	(*ifp->if_input)(ifp, m);
}

static void
ie_drop_packet_buffer(struct ie_softc *sc)
{
	int	i;

	do {
		/*
		 * This means we are somehow out of sync.  So, we reset the
		 * adapter.
		 */
		if (!(sc->rbuffs[sc->rbhead]->ie_rbd_actual & IE_RBD_USED)) {
#ifdef DEBUG
			print_rbd(sc->rbuffs[sc->rbhead]);
#endif
			log(LOG_ERR, "ie%d: receive descriptors out of sync at %d\n",
			    sc->unit, sc->rbhead);
			iereset(sc);
			return;
		}
		i = sc->rbuffs[sc->rbhead]->ie_rbd_actual & IE_RBD_LAST;

		sc->rbuffs[sc->rbhead]->ie_rbd_length |= IE_RBD_LAST;
		sc->rbuffs[sc->rbhead]->ie_rbd_actual = 0;
		sc->rbhead = (sc->rbhead + 1) % sc->nrxbufs;
		sc->rbuffs[sc->rbtail]->ie_rbd_length &= ~IE_RBD_LAST;
		sc->rbtail = (sc->rbtail + 1) % sc->nrxbufs;
	} while (!i);
}


/*
 * Start transmission on an interface.
 */
static void
iestart(struct ifnet *ifp)
{
	struct	 ie_softc *sc = ifp->if_softc;
	struct	 mbuf *m0, *m;
	volatile unsigned char *buffer;
	u_short	 len;

	/*
	 * This is not really volatile, in this routine, but it makes gcc
	 * happy.
	 */
	volatile u_short *bptr = &sc->scb->ie_command_list;

	if (!(ifp->if_flags & IFF_RUNNING))
		return;
	if (ifp->if_flags & IFF_OACTIVE)
		return;

	do {
		IF_DEQUEUE(&sc->arpcom.ac_if.if_snd, m);
		if (!m)
			break;

		buffer = sc->xmit_cbuffs[sc->xmit_count];
		len = 0;

		for (m0 = m; m && len < IE_BUF_LEN; m = m->m_next) {
			bcopy(mtod(m, caddr_t), buffer, m->m_len);
			buffer += m->m_len;
			len += m->m_len;
		}

		m_freem(m0);
		len = max(len, ETHER_MIN_LEN);

		/*
		 * See if bpf is listening on this interface, let it see the
		 * packet before we commit it to the wire.
		 */
		BPF_TAP(&sc->arpcom.ac_if,
			(void *)sc->xmit_cbuffs[sc->xmit_count], len);

		sc->xmit_buffs[sc->xmit_count]->ie_xmit_flags =
		    IE_XMIT_LAST|len;
		sc->xmit_buffs[sc->xmit_count]->ie_xmit_next = 0xffff;
		sc->xmit_buffs[sc->xmit_count]->ie_xmit_buf =
		    MK_24(sc->iomem, sc->xmit_cbuffs[sc->xmit_count]);

		sc->xmit_cmds[sc->xmit_count]->com.ie_cmd_cmd = IE_CMD_XMIT;
		sc->xmit_cmds[sc->xmit_count]->ie_xmit_status = 0;
		sc->xmit_cmds[sc->xmit_count]->ie_xmit_desc =
		    MK_16(sc->iomem, sc->xmit_buffs[sc->xmit_count]);

		*bptr = MK_16(sc->iomem, sc->xmit_cmds[sc->xmit_count]);
		bptr = &sc->xmit_cmds[sc->xmit_count]->com.ie_cmd_link;
		sc->xmit_count++;
	} while (sc->xmit_count < sc->ntxbufs);

	/*
	 * If we queued up anything for transmission, send it.
	 */
	if (sc->xmit_count) {
		sc->xmit_cmds[sc->xmit_count - 1]->com.ie_cmd_cmd |=
		    IE_CMD_LAST | IE_CMD_INTR;

		/*
		 * By passing the command pointer as a null, we tell
		 * command_and_wait() to pretend that this isn't an action
		 * command.  I wish I understood what was happening here.
		 */
		command_and_wait(sc, IE_CU_START, 0, 0);
		ifp->if_flags |= IFF_OACTIVE;
	}
	return;
}

/*
 * Check to see if there's an 82586 out there.
 */
static int
check_ie_present(struct ie_softc *sc, caddr_t where, unsigned size)
{
	volatile struct ie_sys_conf_ptr *scp;
	volatile struct ie_int_sys_conf_ptr *iscp;
	volatile struct ie_sys_ctl_block *scb;
	u_long	realbase;
	int	s;

	s = splimp();

	realbase = (uintptr_t) where + size - (1 << 24);

	scp = (volatile struct ie_sys_conf_ptr *) (uintptr_t)
	      (realbase + IE_SCP_ADDR);
	bzero((volatile char *) scp, sizeof *scp);

	/*
	 * First we put the ISCP at the bottom of memory; this tests to make
	 * sure that our idea of the size of memory is the same as the
	 * controller's. This is NOT where the ISCP will be in normal
	 * operation.
	 */
	iscp = (volatile struct ie_int_sys_conf_ptr *) where;
	bzero((volatile char *)iscp, sizeof *iscp);

	scb = (volatile struct ie_sys_ctl_block *) where;
	bzero((volatile char *)scb, sizeof *scb);

	scp->ie_bus_use = sc->bus_use;	/* 8-bit or 16-bit */
	scp->ie_iscp_ptr = (caddr_t) (uintptr_t)
	    ((volatile char *) iscp - (volatile char *) (uintptr_t) realbase);

	iscp->ie_busy = 1;
	iscp->ie_scb_offset = MK_16(realbase, scb) + 256;

	(*sc->ie_reset_586) (sc);
	(*sc->ie_chan_attn) (sc);

	DELAY(100);		/* wait a while... */

	if (iscp->ie_busy) {
		splx(s);
		return (0);
	}
	/*
	 * Now relocate the ISCP to its real home, and reset the controller
	 * again.
	 */
	iscp = (void *) Align((caddr_t) (uintptr_t)
			      (realbase + IE_SCP_ADDR -
			       sizeof(struct ie_int_sys_conf_ptr)));
	bzero((volatile char *) iscp, sizeof *iscp);	/* ignore cast-qual */

	scp->ie_iscp_ptr = (caddr_t) (uintptr_t)
	    ((volatile char *) iscp - (volatile char *) (uintptr_t) realbase);

	iscp->ie_busy = 1;
	iscp->ie_scb_offset = MK_16(realbase, scb);

	(*sc->ie_reset_586) (sc);
	(*sc->ie_chan_attn) (sc);

	DELAY(100);

	if (iscp->ie_busy) {
		splx(s);
		return (0);
	}
	sc->iosize = size;
	sc->iomem = (caddr_t) (uintptr_t) realbase;

	sc->iscp = iscp;
	sc->scb = scb;

	/*
	 * Acknowledge any interrupts we may have caused...
	 */
	ie_ack(sc, IE_ST_WHENCE);
	splx(s);

	return (1);
}

/*
 * Divine the memory size of ie board UNIT.
 * Better hope there's nothing important hiding just below the ie card...
 */
static void
find_ie_mem_size(struct ie_softc *sc)
{
	unsigned size;

	sc->iosize = 0;

	for (size = 65536; size >= 8192; size -= 8192) {
		if (check_ie_present(sc, sc->iomembot, size)) {
			return;
		}
	}

	return;
}

static void
el_reset_586(struct ie_softc *sc)
{
	outb(PORT(sc) + IE507_CTRL, EL_CTRL_RESET);
	DELAY(100);
	outb(PORT(sc) + IE507_CTRL, EL_CTRL_NORMAL);
	DELAY(100);
}

static void
sl_reset_586(struct ie_softc *sc)
{
	outb(PORT(sc) + IEATT_RESET, 0);
}

static void
ee16_reset_586(struct ie_softc *sc)
{
	outb(PORT(sc) + IEE16_ECTRL, IEE16_RESET_586);
	DELAY(100);
	outb(PORT(sc) + IEE16_ECTRL, 0);
	DELAY(100);
}

static void
el_chan_attn(struct ie_softc *sc)
{
	outb(PORT(sc) + IE507_ATTN, 1);
}

static void
sl_chan_attn(struct ie_softc *sc)
{
	outb(PORT(sc) + IEATT_ATTN, 0);
}

static void
ee16_chan_attn(struct ie_softc *sc)
{
	outb(PORT(sc) + IEE16_ATTN, 0);
}

static u_short
ee16_read_eeprom(struct ie_softc *sc, int location)
{
	int	ectrl, edata;

	ectrl = inb(sc->port + IEE16_ECTRL);
	ectrl &= IEE16_ECTRL_MASK;
	ectrl |= IEE16_ECTRL_EECS;
	outb(sc->port + IEE16_ECTRL, ectrl);

	ee16_eeprom_outbits(sc, IEE16_EEPROM_READ, IEE16_EEPROM_OPSIZE1);
	ee16_eeprom_outbits(sc, location, IEE16_EEPROM_ADDR_SIZE);
	edata = ee16_eeprom_inbits(sc);
	ectrl = inb(sc->port + IEE16_ECTRL);
	ectrl &= ~(IEE16_RESET_ASIC | IEE16_ECTRL_EEDI | IEE16_ECTRL_EECS);
	outb(sc->port + IEE16_ECTRL, ectrl);
	ee16_eeprom_clock(sc, 1);
	ee16_eeprom_clock(sc, 0);
	return edata;
}

static void
ee16_eeprom_outbits(struct ie_softc *sc, int edata, int count)
{
	int	ectrl, i;

	ectrl = inb(sc->port + IEE16_ECTRL);
	ectrl &= ~IEE16_RESET_ASIC;
	for (i = count - 1; i >= 0; i--) {
		ectrl &= ~IEE16_ECTRL_EEDI;
		if (edata & (1 << i)) {
			ectrl |= IEE16_ECTRL_EEDI;
		}
		outb(sc->port + IEE16_ECTRL, ectrl);
		DELAY(1);	/* eeprom data must be setup for 0.4 uSec */
		ee16_eeprom_clock(sc, 1);
		ee16_eeprom_clock(sc, 0);
	}
	ectrl &= ~IEE16_ECTRL_EEDI;
	outb(sc->port + IEE16_ECTRL, ectrl);
	DELAY(1);		/* eeprom data must be held for 0.4 uSec */
}

static int
ee16_eeprom_inbits(struct ie_softc *sc)
{
	int	ectrl, edata, i;

	ectrl = inb(sc->port + IEE16_ECTRL);
	ectrl &= ~IEE16_RESET_ASIC;
	for (edata = 0, i = 0; i < 16; i++) {
		edata = edata << 1;
		ee16_eeprom_clock(sc, 1);
		ectrl = inb(sc->port + IEE16_ECTRL);
		if (ectrl & IEE16_ECTRL_EEDO) {
			edata |= 1;
		}
		ee16_eeprom_clock(sc, 0);
	}
	return (edata);
}

static void
ee16_eeprom_clock(struct ie_softc *sc, int state)
{
	int	ectrl;

	ectrl = inb(sc->port + IEE16_ECTRL);
	ectrl &= ~(IEE16_RESET_ASIC | IEE16_ECTRL_EESK);
	if (state) {
		ectrl |= IEE16_ECTRL_EESK;
	}
	outb(sc->port + IEE16_ECTRL, ectrl);
	DELAY(9);		/* EESK must be stable for 8.38 uSec */
}

static __inline void
ee16_interrupt_enable(struct ie_softc *sc)
{
	DELAY(100);
	outb(sc->port + IEE16_IRQ, sc->irq_encoded | IEE16_IRQ_ENABLE);
	DELAY(100);
}

static void
sl_read_ether(struct ie_softc *sc, unsigned char *addr)
{
	int	i;

	for (i = 0; i < 6; i++)
		addr[i] = inb(PORT(sc) + i);
}

static __inline void
ie_ack(struct ie_softc *sc, u_int mask)
{

	sc->scb->ie_command = sc->scb->ie_status & mask;
	(*sc->ie_chan_attn) (sc);
}

static void
iereset(struct ie_softc *sc)
{
	int	s = splimp();

	if (sc->unit >= NIE) {
		splx(s);
		return;
	}
	printf("ie%d: reset\n", sc->unit);
	sc->arpcom.ac_if.if_flags &= ~IFF_UP;
	ieioctl(&sc->arpcom.ac_if, SIOCSIFFLAGS, 0);

	/*
	 * Stop i82586 dead in its tracks.
	 */
	if (command_and_wait(sc, IE_RU_ABORT | IE_CU_ABORT, 0, 0))
		printf("ie%d: abort commands timed out\n", sc->unit);

	if (command_and_wait(sc, IE_RU_DISABLE | IE_CU_STOP, 0, 0))
		printf("ie%d: disable commands timed out\n", sc->unit);

#ifdef notdef
	if (!check_ie_present(sc, sc->iomembot, sc->iosize))
		panic("ie disappeared!");
#endif

	sc->arpcom.ac_if.if_flags |= IFF_UP;
	ieioctl(&sc->arpcom.ac_if, SIOCSIFFLAGS, 0);

	splx(s);
	return;
}

/*
 * This is called if we time out.
 */
static void
chan_attn_timeout(void *rock)
{
	*(int *) rock = 1;
}

/*
 * Send a command to the controller and wait for it to either
 * complete or be accepted, depending on the command.  If the
 * command pointer is null, then pretend that the command is
 * not an action command.  If the command pointer is not null,
 * and the command is an action command, wait for
 * ((volatile struct ie_cmd_common *)pcmd)->ie_cmd_status & MASK
 * to become true.
 */
static int
command_and_wait(struct ie_softc *sc, int cmd, volatile void *pcmd, int mask)
{
	volatile struct ie_cmd_common *cc = pcmd;
	volatile int timedout = 0;
	struct	 callout_handle ch;

	sc->scb->ie_command = (u_short) cmd;

	if (IE_ACTION_COMMAND(cmd) && pcmd) {
		(*sc->ie_chan_attn) (sc);

		/*
		 * According to the packet driver, the minimum timeout
		 * should be .369 seconds, which we round up to .37.
		 */
		ch = timeout(chan_attn_timeout, (caddr_t)&timedout,
			     37 * hz / 100);
		/* ignore cast-qual */

		/*
		 * Now spin-lock waiting for status.  This is not a very
		 * nice thing to do, but I haven't figured out how, or
		 * indeed if, we can put the process waiting for action to
		 * sleep.  (We may be getting called through some other
		 * timeout running in the kernel.)
		 */
		while (1) {
			if ((cc->ie_cmd_status & mask) || timedout)
				break;
		}

		untimeout(chan_attn_timeout, (caddr_t)&timedout, ch);
		/* ignore cast-qual */

		return (timedout);
	} else {

		/*
		 * Otherwise, just wait for the command to be accepted.
		 */
		(*sc->ie_chan_attn) (sc);

		while (sc->scb->ie_command);	/* spin lock */

		return (0);
	}
}

/*
 * Run the time-domain reflectometer...
 */
static void
run_tdr(struct ie_softc *sc, volatile struct ie_tdr_cmd *cmd)
{
	int	result;

	cmd->com.ie_cmd_status = 0;
	cmd->com.ie_cmd_cmd = IE_CMD_TDR | IE_CMD_LAST;
	cmd->com.ie_cmd_link = 0xffff;
	cmd->ie_tdr_time = 0;

	sc->scb->ie_command_list = MK_16(MEM(sc), cmd);
	cmd->ie_tdr_time = 0;

	if (command_and_wait(sc, IE_CU_START, cmd, IE_STAT_COMPL))
		result = 0x2000;
	else
		result = cmd->ie_tdr_time;

	ie_ack(sc, IE_ST_WHENCE);

	if (result & IE_TDR_SUCCESS)
		return;

	if (result & IE_TDR_XCVR) {
		printf("ie%d: transceiver problem\n", sc->unit);
	} else if (result & IE_TDR_OPEN) {
		printf("ie%d: TDR detected an open %d clocks away\n", sc->unit,
		       result & IE_TDR_TIME);
	} else if (result & IE_TDR_SHORT) {
		printf("ie%d: TDR detected a short %d clocks away\n", sc->unit,
		       result & IE_TDR_TIME);
	} else {
		printf("ie%d: TDR returned unknown status %x\n", sc->unit, result);
	}
}

static void
start_receiver(struct ie_softc *sc)
{
	int	s = splimp();

	sc->scb->ie_recv_list = MK_16(MEM(sc), sc->rframes[0]);
	command_and_wait(sc, IE_RU_START, 0, 0);

	ie_ack(sc, IE_ST_WHENCE);

	splx(s);
}

/*
 * Here is a helper routine for iernr() and ieinit().  This sets up
 * the RFA.
 */
static v_caddr_t
setup_rfa(struct ie_softc *sc, v_caddr_t ptr)
{
	volatile struct ie_recv_frame_desc *rfd = (volatile void *)ptr;
	volatile struct ie_recv_buf_desc *rbd;
	int	i;

	/* First lay them out */
	for (i = 0; i < sc->nframes; i++) {
		sc->rframes[i] = rfd;
		bzero((volatile char *) rfd, sizeof *rfd);	/* ignore cast-qual */
		rfd++;
	}

	ptr = Alignvol(rfd);		/* ignore cast-qual */

	/* Now link them together */
	for (i = 0; i < sc->nframes; i++) {
		sc->rframes[i]->ie_fd_next =
		    MK_16(MEM(sc), sc->rframes[(i + 1) % sc->nframes]);
	}

	/* Finally, set the EOL bit on the last one. */
	sc->rframes[sc->nframes - 1]->ie_fd_last |= IE_FD_LAST;

	/*
	 * Now lay out some buffers for the incoming frames.  Note that we
	 * set aside a bit of slop in each buffer, to make sure that we have
	 * enough space to hold a single frame in every buffer.
	 */
	rbd = (volatile void *) ptr;

	for (i = 0; i < sc->nrxbufs; i++) {
		sc->rbuffs[i] = rbd;
		bzero((volatile char *)rbd, sizeof *rbd);
		ptr = Alignvol(ptr + sizeof *rbd);
		rbd->ie_rbd_length = IE_RBUF_SIZE;
		rbd->ie_rbd_buffer = MK_24(MEM(sc), ptr);
		sc->cbuffs[i] = (volatile void *) ptr;
		ptr += IE_RBUF_SIZE;
		rbd = (volatile void *) ptr;
	}

	/* Now link them together */
	for (i = 0; i < sc->nrxbufs; i++) {
		sc->rbuffs[i]->ie_rbd_next =
		    MK_16(MEM(sc), sc->rbuffs[(i + 1) % sc->nrxbufs]);
	}

	/* Tag EOF on the last one */
	sc->rbuffs[sc->nrxbufs - 1]->ie_rbd_length |= IE_RBD_LAST;

	/*
	 * We use the head and tail pointers on receive to keep track of the
	 * order in which RFDs and RBDs are used.
	 */
	sc->rfhead = 0;
	sc->rftail = sc->nframes - 1;
	sc->rbhead = 0;
	sc->rbtail = sc->nrxbufs - 1;

	sc->scb->ie_recv_list = MK_16(MEM(sc), sc->rframes[0]);
	sc->rframes[0]->ie_fd_buf_desc = MK_16(MEM(sc), sc->rbuffs[0]);

	ptr = Alignvol(ptr);
	return (ptr);
}

/*
 * Run the multicast setup command.
 * Call at splimp().
 */
static int
mc_setup(struct ie_softc *sc)
{
	volatile struct ie_mcast_cmd *cmd = (volatile void *)sc->xmit_cbuffs[0];

	cmd->com.ie_cmd_status = 0;
	cmd->com.ie_cmd_cmd = IE_CMD_MCAST | IE_CMD_LAST;
	cmd->com.ie_cmd_link = 0xffff;

	/* ignore cast-qual */
	bcopy((v_caddr_t) sc->mcast_addrs, (v_caddr_t) cmd->ie_mcast_addrs,
	      sc->mcast_count * sizeof *sc->mcast_addrs);

	cmd->ie_mcast_bytes = sc->mcast_count * 6;	/* grrr... */

	sc->scb->ie_command_list = MK_16(MEM(sc), cmd);
	if (command_and_wait(sc, IE_CU_START, cmd, IE_STAT_COMPL)
	    || !(cmd->com.ie_cmd_status & IE_STAT_OK)) {
		printf("ie%d: multicast address setup command failed\n", sc->unit);
		return (0);
	}
	return (1);
}

/*
 * This routine takes the environment generated by check_ie_present()
 * and adds to it all the other structures we need to operate the adapter.
 * This includes executing the CONFIGURE, IA-SETUP, and MC-SETUP commands,
 * starting the receiver unit, and clearing interrupts.
 *
 * THIS ROUTINE MUST BE CALLED AT splimp() OR HIGHER.
 */
static void
ieinit(xsc)
	void *xsc;
{
	struct ie_softc *sc = xsc;
	volatile struct ie_sys_ctl_block *scb = sc->scb;
	caddr_t ptr;
	int	i;
	int	unit = sc->unit;

	ptr = Alignvol((volatile char *) scb + sizeof *scb);

	/*
	 * Send the configure command first.
	 */
	{
		volatile struct ie_config_cmd *cmd = (volatile void *) ptr;

		ie_setup_config(cmd, sc->promisc,
				sc->hard_type == IE_STARLAN10);
		cmd->com.ie_cmd_status = 0;
		cmd->com.ie_cmd_cmd = IE_CMD_CONFIG | IE_CMD_LAST;
		cmd->com.ie_cmd_link = 0xffff;

		scb->ie_command_list = MK_16(MEM(sc), cmd);

		if (command_and_wait(sc, IE_CU_START, cmd, IE_STAT_COMPL)
		 || !(cmd->com.ie_cmd_status & IE_STAT_OK)) {
			printf("ie%d: configure command failed\n", unit);
			return;
		}
	}
	/*
	 * Now send the Individual Address Setup command.
	 */
	{
		volatile struct ie_iasetup_cmd *cmd = (volatile void *) ptr;

		cmd->com.ie_cmd_status = 0;
		cmd->com.ie_cmd_cmd = IE_CMD_IASETUP | IE_CMD_LAST;
		cmd->com.ie_cmd_link = 0xffff;

		bcopy((volatile char *)sc->arpcom.ac_enaddr,
		      (volatile char *)&cmd->ie_address, sizeof cmd->ie_address);
		scb->ie_command_list = MK_16(MEM(sc), cmd);
		if (command_and_wait(sc, IE_CU_START, cmd, IE_STAT_COMPL)
		    || !(cmd->com.ie_cmd_status & IE_STAT_OK)) {
			printf("ie%d: individual address "
			       "setup command failed\n", sc->unit);
			return;
		}
	}

	/*
	 * Now run the time-domain reflectometer.
	 */
	run_tdr(sc, (volatile void *) ptr);

	/*
	 * Acknowledge any interrupts we have generated thus far.
	 */
	ie_ack(sc, IE_ST_WHENCE);

	/*
	 * Set up the RFA.
	 */
	ptr = setup_rfa(sc, ptr);

	/*
	 * Finally, the transmit command and buffer are the last little bit
	 * of work.
	 */

	/* transmit command buffers */
	for (i = 0; i < sc->ntxbufs; i++) {
		sc->xmit_cmds[i] = (volatile void *) ptr;
		ptr += sizeof *sc->xmit_cmds[i];
		ptr = Alignvol(ptr);
		sc->xmit_buffs[i] = (volatile void *)ptr;
		ptr += sizeof *sc->xmit_buffs[i];
		ptr = Alignvol(ptr);
	}

	/* transmit buffers */
	for (i = 0; i < sc->ntxbufs - 1; i++) {
		sc->xmit_cbuffs[i] = (volatile void *)ptr;
		ptr += IE_BUF_LEN;
		ptr = Alignvol(ptr);
	}
	sc->xmit_cbuffs[sc->ntxbufs - 1] = (volatile void *) ptr;

	for (i = 1; i < sc->ntxbufs; i++) {
		bzero((v_caddr_t) sc->xmit_cmds[i], sizeof *sc->xmit_cmds[i]);
		bzero((v_caddr_t) sc->xmit_buffs[i], sizeof *sc->xmit_buffs[i]);
	}

	/*
	 * This must be coordinated with iestart() and ietint().
	 */
	sc->xmit_cmds[0]->ie_xmit_status = IE_STAT_COMPL;

	/* take the ee16 out of loopback */
	if (sc->hard_type == IE_EE16) {
		u_int8_t bart_config;

		bart_config = inb(PORT(sc) + IEE16_CONFIG);
		bart_config &= ~IEE16_BART_LOOPBACK;
		/* inb doesn't get bit! */
		bart_config |= IEE16_BART_MCS16_TEST;
		outb(PORT(sc) + IEE16_CONFIG, bart_config);
		ee16_interrupt_enable(sc);
		ee16_chan_attn(sc);
	}
	sc->arpcom.ac_if.if_flags |= IFF_RUNNING;	/* tell higher levels
							 * we're here */
	start_receiver(sc);

	return;
}

static void
ie_stop(struct ie_softc *sc)
{
	command_and_wait(sc, IE_RU_DISABLE, 0, 0);
}

static int
ieioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	int	s, error = 0;
	struct	 ie_softc *sc = ifp->if_softc;

	s = splimp();

	switch (command) {
	case SIOCSIFFLAGS:
		/*
		 * Note that this device doesn't have an "all multicast"
		 * mode, so we must turn on promiscuous mode and do the
		 * filtering manually.
		 */
		if ((ifp->if_flags & IFF_UP) == 0 &&
		    (ifp->if_flags & IFF_RUNNING)) {
			ifp->if_flags &= ~IFF_RUNNING;
			ie_stop(sc);
		} else if ((ifp->if_flags & IFF_UP) &&
			   (ifp->if_flags & IFF_RUNNING) == 0) {
			sc->promisc =
			    ifp->if_flags & (IFF_PROMISC | IFF_ALLMULTI);
			ieinit(sc);
		} else if (sc->promisc ^
			   (ifp->if_flags & (IFF_PROMISC | IFF_ALLMULTI))) {
			sc->promisc =
			    ifp->if_flags & (IFF_PROMISC | IFF_ALLMULTI);
			ieinit(sc);
		}
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		/*
		 * Update multicast listeners
		 */
		/* reset multicast filtering */
		ie_mc_reset(sc);
		error = 0;
		break;

	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}

	splx(s);
	return (error);
}

static void
ie_mc_reset(struct ie_softc *sc)
{
	struct ifmultiaddr *ifma;

	/*
	 * Step through the list of addresses.
	 */
	sc->mcast_count = 0;
	TAILQ_FOREACH(ifma, &sc->arpcom.ac_if.if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;

		/* XXX - this is broken... */
		if (sc->mcast_count >= MAXMCAST) {
			sc->arpcom.ac_if.if_flags |= IFF_ALLMULTI;
			ieioctl(&sc->arpcom.ac_if, SIOCSIFFLAGS, (void *) 0);
			goto setflag;
		}
		bcopy(LLADDR((struct sockaddr_dl *) ifma->ifma_addr),
		      &(sc->mcast_addrs[sc->mcast_count]), 6);
		sc->mcast_count++;
	}

setflag:
	sc->want_mcsetup = 1;
}


#ifdef DEBUG
static void
print_rbd(volatile struct ie_recv_buf_desc * rbd)
{
	printf("RBD at %p:\n"
	       "actual %04x, next %04x, buffer %p\n"
	       "length %04x, mbz %04x\n",
	       (volatile void *) rbd,
	       rbd->ie_rbd_actual, rbd->ie_rbd_next,
	       (void *) rbd->ie_rbd_buffer,
	       rbd->ie_rbd_length, rbd->mbz);
}

#endif				/* DEBUG */
