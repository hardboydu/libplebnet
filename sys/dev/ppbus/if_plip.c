/*-
 * Copyright (c) 1997 Poul-Henning Kamp
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	From Id: lpt.c,v 1.55.2.1 1996/11/12 09:08:38 phk Exp
 *	$Id: if_plip.c,v 1.9 1999/01/30 15:35:39 nsouch Exp $
 */

/*
 * Parallel port TCP/IP interfaces added.  I looked at the driver from
 * MACH but this is a complete rewrite, and btw. incompatible, and it
 * should perform better too.  I have never run the MACH driver though.
 *
 * This driver sends two bytes (0x08, 0x00) in front of each packet,
 * to allow us to distinguish another format later.
 *
 * Now added an Linux/Crynwr compatibility mode which is enabled using
 * IF_LINK0 - Tim Wilkinson.
 *
 * TODO:
 *    Make HDLC/PPP mode, use IF_LLC1 to enable.
 *
 * Connect the two computers using a Laplink parallel cable to use this
 * feature:
 *
 *      +----------------------------------------+
 * 	|A-name	A-End	B-End	Descr.	Port/Bit |
 *      +----------------------------------------+
 *	|DATA0	2	15	Data	0/0x01   |
 *	|-ERROR	15	2	   	1/0x08   |
 *      +----------------------------------------+
 *	|DATA1	3	13	Data	0/0x02	 |
 *	|+SLCT	13	3	   	1/0x10   |
 *      +----------------------------------------+
 *	|DATA2	4	12	Data	0/0x04   |
 *	|+PE	12	4	   	1/0x20   |
 *      +----------------------------------------+
 *	|DATA3	5	10	Strobe	0/0x08   |
 *	|-ACK	10	5	   	1/0x40   |
 *      +----------------------------------------+
 *	|DATA4	6	11	Data	0/0x10   |
 *	|BUSY	11	6	   	1/~0x80  |
 *      +----------------------------------------+
 *	|GND	18-25	18-25	GND	-        |
 *      +----------------------------------------+
 *
 * Expect transfer-rates up to 75 kbyte/sec.
 *
 * If GCC could correctly grok
 *	register int port asm("edx")
 * the code would be cleaner
 *
 * Poul-Henning Kamp <phk@freebsd.org>
 */

/*
 * Update for ppbus, PLIP support only - Nicolas Souchu
 */ 

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_var.h>

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <dev/ppbus/ppbconf.h>
#include <dev/ppbus/nlpt.h>

#include "opt_plip.h"

#ifndef LPMTU			/* MTU for the lp# interfaces */
#define	LPMTU	1500
#endif

#ifndef LPMAXSPIN1		/* DELAY factor for the lp# interfaces */
#define	LPMAXSPIN1	8000   /* Spinning for remote intr to happen */
#endif

#ifndef LPMAXSPIN2		/* DELAY factor for the lp# interfaces */
#define	LPMAXSPIN2	500	/* Spinning for remote handshake to happen */
#endif

#ifndef LPMAXERRS		/* Max errors before !RUNNING */
#define	LPMAXERRS	100
#endif

#define CLPIPHDRLEN	14	/* We send dummy ethernet addresses (two) + packet type in front of packet */
#define	CLPIP_SHAKE	0x80	/* This bit toggles between nibble reception */
#define MLPIPHDRLEN	CLPIPHDRLEN

#define LPIPHDRLEN	2	/* We send 0x08, 0x00 in front of packet */
#define	LPIP_SHAKE	0x40	/* This bit toggles between nibble reception */
#if !defined(MLPIPHDRLEN) || LPIPHDRLEN > MLPIPHDRLEN
#define MLPIPHDRLEN	LPIPHDRLEN
#endif

#define	LPIPTBLSIZE	256	/* Size of octet translation table */

#define lprintf		if (lptflag) printf

#ifdef PLIP_DEBUG
static int volatile lptflag = 1;
#else
static int volatile lptflag = 0;
#endif

struct lpt_softc {
	unsigned short lp_unit;

	struct ppb_device lp_dev;

	struct  ifnet	sc_if;
	u_char		*sc_ifbuf;
	int		sc_iferrs;
};

static int	nlp = 0;
#define MAXPLIP	8			/* XXX not much better! */
static struct lpt_softc *lpdata[MAXPLIP];


/* Tables for the lp# interface */
static u_char *txmith;
#define txmitl (txmith+(1*LPIPTBLSIZE))
#define trecvh (txmith+(2*LPIPTBLSIZE))
#define trecvl (txmith+(3*LPIPTBLSIZE))

static u_char *ctxmith;
#define ctxmitl (ctxmith+(1*LPIPTBLSIZE))
#define ctrecvh (ctxmith+(2*LPIPTBLSIZE))
#define ctrecvl (ctxmith+(3*LPIPTBLSIZE))

/* Functions for the lp# interface */
static struct ppb_device	*lpprobe(struct ppb_data *);
static int			lpattach(struct ppb_device *);

static int lpinittables(void);
static int lpioctl(struct ifnet *, u_long, caddr_t);
static int lpoutput(struct ifnet *, struct mbuf *, struct sockaddr *,
	struct rtentry *);
static void lpintr(int);

/*
 * Make ourselves visible as a ppbus driver
 */

static struct ppb_driver lpdriver = {
    lpprobe, lpattach, "lp"
};
DATA_SET(ppbdriver_set, lpdriver);


/*
 * lpprobe()
 */
static struct ppb_device *
lpprobe(struct ppb_data *ppb)
{
	struct lpt_softc *lp;

	/* if we haven't interrupts, the probe fails */
	if (!ppb->ppb_link->id_irq)
		return (0);

	lp = (struct lpt_softc *) malloc(sizeof(struct lpt_softc),
							M_TEMP, M_NOWAIT);
	if (!lp) {
		printf("lp: cannot malloc!\n");
		return (0);
	}
	bzero(lp, sizeof(struct lpt_softc));

	lpdata[nlp] = lp;

	/*
	 * lp dependent initialisation.
	 */
	lp->lp_unit = nlp;

	if (bootverbose)
		printf("plip: irq %d\n", ppb->ppb_link->id_irq);

	/*
	 * ppbus dependent initialisation.
	 */
	lp->lp_dev.id_unit = lp->lp_unit;
	lp->lp_dev.name = lpdriver.name;
	lp->lp_dev.ppb = ppb;
	lp->lp_dev.intr = lpintr;

	/* Ok, go to next device on next probe */
	nlp ++;

	return (&lp->lp_dev);
}

static int
lpattach (struct ppb_device *dev)
{
	int unit = dev->id_unit;
	struct lpt_softc *sc = lpdata[unit];
	struct ifnet *ifp = &sc->sc_if;

	/*
	 * Report ourselves
	 */
	printf("plip%d: <PLIP network interface> on ppbus %d\n",
	       dev->id_unit, dev->ppb->ppb_link->adapter_unit);

	ifp->if_softc = sc;
	ifp->if_name = "lp";
	ifp->if_unit = unit;
	ifp->if_mtu = LPMTU;
	ifp->if_flags = IFF_SIMPLEX | IFF_POINTOPOINT | IFF_MULTICAST;
	ifp->if_ioctl = lpioctl;
	ifp->if_output = lpoutput;
	ifp->if_type = IFT_PARA;
	ifp->if_hdrlen = 0;
	ifp->if_addrlen = 0;
	ifp->if_snd.ifq_maxlen = IFQ_MAXLEN;
	if_attach(ifp);

#if NBPFILTER > 0
	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));
#endif

	return (1);
}
/*
 * Build the translation tables for the LPIP (BSD unix) protocol.
 * We don't want to calculate these nasties in our tight loop, so we
 * precalculate them when we initialize.
 */
static int
lpinittables (void)
{
    int i;

    if (!txmith)
	txmith = malloc(4*LPIPTBLSIZE, M_DEVBUF, M_NOWAIT);

    if (!txmith)
	return 1;

    if (!ctxmith)
	ctxmith = malloc(4*LPIPTBLSIZE, M_DEVBUF, M_NOWAIT);

    if (!ctxmith)
	return 1;

    for (i=0; i < LPIPTBLSIZE; i++) {
	ctxmith[i] = (i & 0xF0) >> 4;
	ctxmitl[i] = 0x10 | (i & 0x0F);
	ctrecvh[i] = (i & 0x78) << 1;
	ctrecvl[i] = (i & 0x78) >> 3;
    }

    for (i=0; i < LPIPTBLSIZE; i++) {
	txmith[i] = ((i & 0x80) >> 3) | ((i & 0x70) >> 4) | 0x08;
	txmitl[i] = ((i & 0x08) << 1) | (i & 0x07);
	trecvh[i] = ((~i) & 0x80) | ((i & 0x38) << 1);
	trecvl[i] = (((~i) & 0x80) >> 4) | ((i & 0x38) >> 3);
    }

    return 0;
}

/*
 * Process an ioctl request.
 */

static int
lpioctl (struct ifnet *ifp, u_long cmd, caddr_t data)
{
    struct lpt_softc *sc = lpdata[ifp->if_unit];
    struct ifaddr *ifa = (struct ifaddr *)data;
    struct ifreq *ifr = (struct ifreq *)data;
    u_char *ptr;
    int error;

    switch (cmd) {

    case SIOCSIFDSTADDR:
    case SIOCAIFADDR:
    case SIOCSIFADDR:
	if (ifa->ifa_addr->sa_family != AF_INET)
	    return EAFNOSUPPORT;

	ifp->if_flags |= IFF_UP;
	/* FALLTHROUGH */
    case SIOCSIFFLAGS:
	if ((!(ifp->if_flags & IFF_UP)) && (ifp->if_flags & IFF_RUNNING)) {

	    ppb_wctr(&sc->lp_dev, 0x00);
	    ifp->if_flags &= ~IFF_RUNNING;

	    /* IFF_UP is not set, try to release the bus anyway */
	    ppb_release_bus(&sc->lp_dev);
	    break;
	}
	if (((ifp->if_flags & IFF_UP)) && (!(ifp->if_flags & IFF_RUNNING))) {

	    /* XXX
	     * Should the request be interruptible?
	     */
	    if ((error = ppb_request_bus(&sc->lp_dev, PPB_WAIT|PPB_INTR)))
		return (error);

	    /* Now IFF_UP means that we own the bus */

	    ppb_set_mode(&sc->lp_dev, PPB_COMPATIBLE);

	    if (lpinittables()) {
		ppb_release_bus(&sc->lp_dev);
		return ENOBUFS;
	    }

	    sc->sc_ifbuf = malloc(sc->sc_if.if_mtu + MLPIPHDRLEN,
				  M_DEVBUF, M_WAITOK);
	    if (!sc->sc_ifbuf) {
		ppb_release_bus(&sc->lp_dev);
		return ENOBUFS;
	    }

	    ppb_wctr(&sc->lp_dev, LPC_ENA);
	    ifp->if_flags |= IFF_RUNNING;
	}
	break;

    case SIOCSIFMTU:
	ptr = sc->sc_ifbuf;
	sc->sc_ifbuf = malloc(ifr->ifr_mtu+MLPIPHDRLEN, M_DEVBUF, M_NOWAIT);
	if (!sc->sc_ifbuf) {
	    sc->sc_ifbuf = ptr;
	    return ENOBUFS;
	}
	if (ptr)
	    free(ptr,M_DEVBUF);
	sc->sc_if.if_mtu = ifr->ifr_mtu;
	break;

    case SIOCGIFMTU:
	ifr->ifr_mtu = sc->sc_if.if_mtu;
	break;

    case SIOCADDMULTI:
    case SIOCDELMULTI:
	if (ifr == 0) {
	    return EAFNOSUPPORT;		/* XXX */
	}
	switch (ifr->ifr_addr.sa_family) {

	case AF_INET:
	    break;

	default:
	    return EAFNOSUPPORT;
	}
	break;

    case SIOCGIFMEDIA:
	/*
	 * No ifmedia support at this stage; maybe use it
	 * in future for eg. protocol selection.
	 */
	return EINVAL;

    default:
	lprintf("LP:ioctl(0x%lx)\n", cmd);
	return EINVAL;
    }
    return 0;
}

static __inline int
clpoutbyte (u_char byte, int spin, struct ppb_device *dev)
{
	ppb_wdtr(dev, ctxmitl[byte]);
	while (ppb_rstr(dev) & CLPIP_SHAKE)
		if (--spin == 0) {
			return 1;
		}
	ppb_wdtr(dev, ctxmith[byte]);
	while (!(ppb_rstr(dev) & CLPIP_SHAKE))
		if (--spin == 0) {
			return 1;
		}
	return 0;
}

static __inline int
clpinbyte (int spin, struct ppb_device *dev)
{
	u_char c, cl;

	while((ppb_rstr(dev) & CLPIP_SHAKE))
	    if(!--spin) {
		return -1;
	    }
	cl = ppb_rstr(dev);
	ppb_wdtr(dev, 0x10);

	while(!(ppb_rstr(dev) & CLPIP_SHAKE))
	    if(!--spin) {
		return -1;
	    }
	c = ppb_rstr(dev);
	ppb_wdtr(dev, 0x00);

	return (ctrecvl[cl] | ctrecvh[c]);
}

#if NBPFILTER > 0
static void
lptap(struct ifnet *ifp, struct mbuf *m)
{
	/*
	 * Send a packet through bpf. We need to prepend the address family
	 * as a four byte field. Cons up a dummy header to pacify bpf. This
	 * is safe because bpf will only read from the mbuf (i.e., it won't
	 * try to free it or keep a pointer to it).
	 */
	u_int32_t af = AF_INET;
	struct mbuf m0;
	
	m0.m_next = m;
	m0.m_len = sizeof(u_int32_t);
	m0.m_data = (char *)&af;
	bpf_mtap(ifp, &m0);
}
#endif

static void
lpintr (int unit)
{
	struct   lpt_softc *sc = lpdata[unit];
	int len, s, j;
	u_char *bp;
	u_char c, cl;
	struct mbuf *top;

	s = splhigh();

	if (sc->sc_if.if_flags & IFF_LINK0) {

	    /* Ack. the request */
	    ppb_wdtr(&sc->lp_dev, 0x01);

	    /* Get the packet length */
	    j = clpinbyte(LPMAXSPIN2, &sc->lp_dev);
	    if (j == -1)
		goto err;
	    len = j;
	    j = clpinbyte(LPMAXSPIN2, &sc->lp_dev);
	    if (j == -1)
		goto err;
	    len = len + (j << 8);
	    if (len > sc->sc_if.if_mtu + MLPIPHDRLEN)
		goto err;

	    bp  = sc->sc_ifbuf;
	
	    while (len--) {
	        j = clpinbyte(LPMAXSPIN2, &sc->lp_dev);
	        if (j == -1) {
		    goto err;
	        }
	        *bp++ = j;
	    }
	    /* Get and ignore checksum */
	    j = clpinbyte(LPMAXSPIN2, &sc->lp_dev);
	    if (j == -1) {
	        goto err;
	    }

	    len = bp - sc->sc_ifbuf;
	    if (len <= CLPIPHDRLEN)
	        goto err;

	    sc->sc_iferrs = 0;

	    if (IF_QFULL(&ipintrq)) {
	        lprintf("DROP");
	        IF_DROP(&ipintrq);
		goto done;
	    }
	    len -= CLPIPHDRLEN;
	    sc->sc_if.if_ipackets++;
	    sc->sc_if.if_ibytes += len;
	    top = m_devget(sc->sc_ifbuf + CLPIPHDRLEN, len, 0, &sc->sc_if, 0);
	    if (top) {
#if NBPFILTER > 0
		if (sc->sc_if.if_bpf)
		    lptap(&sc->sc_if, top);
#endif
	        IF_ENQUEUE(&ipintrq, top);
	        schednetisr(NETISR_IP);
	    }
	    goto done;
	}
	while ((ppb_rstr(&sc->lp_dev) & LPIP_SHAKE)) {
	    len = sc->sc_if.if_mtu + LPIPHDRLEN;
	    bp  = sc->sc_ifbuf;
	    while (len--) {

		cl = ppb_rstr(&sc->lp_dev);
		ppb_wdtr(&sc->lp_dev, 8);

		j = LPMAXSPIN2;
		while((ppb_rstr(&sc->lp_dev) & LPIP_SHAKE))
		    if(!--j) goto err;

		c = ppb_rstr(&sc->lp_dev);
		ppb_wdtr(&sc->lp_dev, 0);

		*bp++= trecvh[cl] | trecvl[c];

		j = LPMAXSPIN2;
		while (!((cl=ppb_rstr(&sc->lp_dev)) & LPIP_SHAKE)) {
		    if (cl != c &&
			(((cl = ppb_rstr(&sc->lp_dev)) ^ 0xb8) & 0xf8) ==
			  (c & 0xf8))
			goto end;
		    if (!--j) goto err;
		}
	    }

	end:
	    len = bp - sc->sc_ifbuf;
	    if (len <= LPIPHDRLEN)
		goto err;

	    sc->sc_iferrs = 0;

	    if (IF_QFULL(&ipintrq)) {
		lprintf("DROP");
		IF_DROP(&ipintrq);
		goto done;
	    }
	    len -= LPIPHDRLEN;
	    sc->sc_if.if_ipackets++;
	    sc->sc_if.if_ibytes += len;
	    top = m_devget(sc->sc_ifbuf + LPIPHDRLEN, len, 0, &sc->sc_if, 0);
	    if (top) {
#if NBPFILTER > 0
		if (sc->sc_if.if_bpf)
		    lptap(&sc->sc_if, top);
#endif
		IF_ENQUEUE(&ipintrq, top);
		schednetisr(NETISR_IP);
	    }
	}
	goto done;

    err:
	ppb_wdtr(&sc->lp_dev, 0);
	lprintf("R");
	sc->sc_if.if_ierrors++;
	sc->sc_iferrs++;

	/*
	 * We are not able to send receive anything for now,
	 * so stop wasting our time
	 */
	if (sc->sc_iferrs > LPMAXERRS) {
	    printf("lp%d: Too many errors, Going off-line.\n", unit);
	    ppb_wctr(&sc->lp_dev, 0x00);
	    sc->sc_if.if_flags &= ~IFF_RUNNING;
	    sc->sc_iferrs=0;
	}

    done:
	splx(s);
	return;
}

static __inline int
lpoutbyte (u_char byte, int spin, struct ppb_device *dev)
{
    ppb_wdtr(dev, txmith[byte]);
    while (!(ppb_rstr(dev) & LPIP_SHAKE))
	if (--spin == 0)
		return 1;
    ppb_wdtr(dev, txmitl[byte]);
    while (ppb_rstr(dev) & LPIP_SHAKE)
	if (--spin == 0)
		return 1;
    return 0;
}

static int
lpoutput (struct ifnet *ifp, struct mbuf *m,
	  struct sockaddr *dst, struct rtentry *rt)
{
    struct lpt_softc *sc = lpdata[ifp->if_unit];
    int s, err;
    struct mbuf *mm;
    u_char *cp = "\0\0";
    u_char chksum = 0;
    int count = 0;
    int i, len, spin;

    /* We need a sensible value if we abort */
    cp++;
    ifp->if_flags |= IFF_RUNNING;

    err = 1;			/* assume we're aborting because of an error */

    s = splhigh();

    /* Suspend (on laptops) or receive-errors might have taken us offline */
    ppb_wctr(&sc->lp_dev, LPC_ENA);

    if (ifp->if_flags & IFF_LINK0) {

	if (!(ppb_rstr(&sc->lp_dev) & CLPIP_SHAKE)) {
	    lprintf("&");
	    lpintr(ifp->if_unit);
	}

	/* Alert other end to pending packet */
	spin = LPMAXSPIN1;
	ppb_wdtr(&sc->lp_dev, 0x08);
	while ((ppb_rstr(&sc->lp_dev) & 0x08) == 0)
		if (--spin == 0) {
			goto nend;
		}

	/* Calculate length of packet, then send that */

	count += 14;		/* Ethernet header len */

	mm = m;
	for (mm = m; mm; mm = mm->m_next) {
		count += mm->m_len;
	}
	if (clpoutbyte(count & 0xFF, LPMAXSPIN1, &sc->lp_dev))
		goto nend;
	if (clpoutbyte((count >> 8) & 0xFF, LPMAXSPIN1, &sc->lp_dev))
		goto nend;

	/* Send dummy ethernet header */
	for (i = 0; i < 12; i++) {
		if (clpoutbyte(i, LPMAXSPIN1, &sc->lp_dev))
			goto nend;
		chksum += i;
	}

	if (clpoutbyte(0x08, LPMAXSPIN1, &sc->lp_dev))
		goto nend;
	if (clpoutbyte(0x00, LPMAXSPIN1, &sc->lp_dev))
		goto nend;
	chksum += 0x08 + 0x00;		/* Add into checksum */

	mm = m;
	do {
		cp = mtod(mm, u_char *);
		len = mm->m_len;
		while (len--) {
			chksum += *cp;
			if (clpoutbyte(*cp++, LPMAXSPIN2, &sc->lp_dev))
				goto nend;
		}
	} while ((mm = mm->m_next));

	/* Send checksum */
	if (clpoutbyte(chksum, LPMAXSPIN2, &sc->lp_dev))
		goto nend;

	/* Go quiescent */
	ppb_wdtr(&sc->lp_dev, 0);

	err = 0;			/* No errors */

	nend:
	if (err)  {				/* if we didn't timeout... */
		ifp->if_oerrors++;
		lprintf("X");
	} else {
		ifp->if_opackets++;
		ifp->if_obytes += m->m_pkthdr.len;
#if NBPFILTER > 0
		if (ifp->if_bpf)
		    lptap(ifp, m);
#endif
	}

	m_freem(m);

	if (!(ppb_rstr(&sc->lp_dev) & CLPIP_SHAKE)) {
		lprintf("^");
		lpintr(ifp->if_unit);
	}
	(void) splx(s);
	return 0;
    }

    if (ppb_rstr(&sc->lp_dev) & LPIP_SHAKE) {
        lprintf("&");
        lpintr(ifp->if_unit);
    }

    if (lpoutbyte(0x08, LPMAXSPIN1, &sc->lp_dev))
        goto end;
    if (lpoutbyte(0x00, LPMAXSPIN2, &sc->lp_dev))
        goto end;

    mm = m;
    do {
        cp = mtod(mm,u_char *);
	len = mm->m_len;
        while (len--)
	    if (lpoutbyte(*cp++, LPMAXSPIN2, &sc->lp_dev))
	        goto end;
    } while ((mm = mm->m_next));

    err = 0;				/* no errors were encountered */

    end:
    --cp;
    ppb_wdtr(&sc->lp_dev, txmitl[*cp] ^ 0x17);

    if (err)  {				/* if we didn't timeout... */
	ifp->if_oerrors++;
        lprintf("X");
    } else {
	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;
#if NBPFILTER > 0
	if (ifp->if_bpf)
	    lptap(ifp, m);
#endif
    }

    m_freem(m);

    if (ppb_rstr(&sc->lp_dev) & LPIP_SHAKE) {
	lprintf("^");
	lpintr(ifp->if_unit);
    }

    (void) splx(s);
    return 0;
}
