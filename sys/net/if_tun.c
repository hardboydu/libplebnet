/*	$NetBSD: if_tun.c,v 1.14 1994/06/29 06:36:25 cgd Exp $	*/

/*
 * Copyright (c) 1988, Julian Onions <jpo@cs.nott.ac.uk>
 * Nottingham University 1987.
 *
 * This source may be freely distributed, however I would be interested
 * in any changes that are made.
 *
 * This driver takes packets off the IP i/f and hands them up to a
 * user process to have its wicked way with. This driver has it's
 * roots in a similar driver written by Phil Cockcroft (formerly) at
 * UCL. This driver is based much more on read/write/poll mode of
 * operation though.
 */

#include "tun.h"
#if NTUN > 0

#include "opt_devfs.h"
#include "opt_inet.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/filio.h>
#include <sys/sockio.h>
#include <sys/ttycom.h>
#include <sys/poll.h>
#include <sys/signalvar.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif /*DEVFS*/
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <net/if_tunvar.h>
#include <net/if_tun.h>

static void tunattach __P((void *));
PSEUDO_SET(tunattach, if_tun);

#define TUNDEBUG	if (tundebug) printf
static int tundebug = 0;
SYSCTL_INT(_debug, OID_AUTO, if_tun_debug, CTLFLAG_RW, &tundebug, 0, "");

static struct tun_softc tunctl[NTUN];

static int tunoutput __P((struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *rt));
static int tunifioctl __P((struct ifnet *, u_long, caddr_t));
static int tuninit __P((int));

static	d_open_t	tunopen;
static	d_close_t	tunclose;
static	d_read_t	tunread;
static	d_write_t	tunwrite;
static	d_ioctl_t	tunioctl;
static	d_poll_t	tunpoll;

#define CDEV_MAJOR 52
static struct cdevsw tun_cdevsw = {
	tunopen,	tunclose,	tunread,	tunwrite,
	tunioctl,	nullstop,	noreset,	nodevtotty,
	tunpoll,	nommap,		nostrategy,	"tun",	NULL,	-1
};


static	int	tun_devsw_installed;
#ifdef	DEVFS
static	void	*tun_devfs_token[NTUN];
#endif

#define minor_val(n) ((((n) & ~0xff) << 8) | ((n) & 0xff))
#define dev_val(n) (((n) >> 8) | ((n) & 0xff))

static void
tunattach(dummy)
	void *dummy;
{
	register int i;
	struct ifnet *ifp;
	dev_t dev;

	if ( tun_devsw_installed )
		return;
	dev = makedev(CDEV_MAJOR, 0);
	cdevsw_add(&dev, &tun_cdevsw, NULL);
	tun_devsw_installed = 1;
	for ( i = 0; i < NTUN; i++ ) {
#ifdef DEVFS
		tun_devfs_token[i] = devfs_add_devswf(&tun_cdevsw, minor_val(i),
						      DV_CHR, UID_UUCP,
						      GID_DIALER, 0600,
						      "tun%d", i);
#endif
		tunctl[i].tun_flags = TUN_INITED;

		ifp = &tunctl[i].tun_if;
		ifp->if_unit = i;
		ifp->if_name = "tun";
		ifp->if_mtu = TUNMTU;
		ifp->if_ioctl = tunifioctl;
		ifp->if_output = tunoutput;
		ifp->if_flags = IFF_POINTOPOINT | IFF_MULTICAST;
		ifp->if_snd.ifq_maxlen = ifqmaxlen;
		if_attach(ifp);
#if NBPFILTER > 0
		bpfattach(ifp, DLT_NULL, sizeof(u_int));
#endif
	}
}

/*
 * tunnel open - must be superuser & the device must be
 * configured in
 */
static	int
tunopen(dev, flag, mode, p)
	dev_t	dev;
	int	flag, mode;
	struct proc *p;
{
	struct ifnet	*ifp;
	struct tun_softc *tp;
	register int	unit, error;

	error = suser(p);
	if (error)
		return (error);

	if ((unit = dev_val(minor(dev))) >= NTUN)
		return (ENXIO);
	tp = &tunctl[unit];
	if (tp->tun_flags & TUN_OPEN)
		return EBUSY;
	ifp = &tp->tun_if;
	tp->tun_flags |= TUN_OPEN;
	TUNDEBUG("%s%d: open\n", ifp->if_name, ifp->if_unit);
	return (0);
}

/*
 * tunclose - close the device - mark i/f down & delete
 * routing info
 */
static	int
tunclose(dev, foo, bar, p)
	dev_t dev;
	int foo;
	int bar;
	struct proc *p;
{
	register int	unit = dev_val(minor(dev)), s;
	struct tun_softc *tp = &tunctl[unit];
	struct ifnet	*ifp = &tp->tun_if;
	struct mbuf	*m;

	tp->tun_flags &= ~TUN_OPEN;

	/*
	 * junk all pending output
	 */
	do {
		s = splimp();
		IF_DEQUEUE(&ifp->if_snd, m);
		splx(s);
		if (m)
			m_freem(m);
	} while (m);

	if (ifp->if_flags & IFF_UP) {
		s = splimp();
		if_down(ifp);
		if (ifp->if_flags & IFF_RUNNING) {
		    /* find internet addresses and delete routes */
		    register struct ifaddr *ifa;
		    for (ifa = ifp->if_addrhead.tqh_first; ifa;
			 ifa = ifa->ifa_link.tqe_next) {
			if (ifa->ifa_addr->sa_family == AF_INET) {
			    rtinit(ifa, (int)RTM_DELETE,
				   tp->tun_flags & TUN_DSTADDR ? RTF_HOST : 0);
			}
		    }
		}
		splx(s);
	}
	funsetown(tp->tun_sigio);
	selwakeup(&tp->tun_rsel);

	TUNDEBUG ("%s%d: closed\n", ifp->if_name, ifp->if_unit);
	return (0);
}

static int
tuninit(unit)
	int	unit;
{
	struct tun_softc *tp = &tunctl[unit];
	struct ifnet	*ifp = &tp->tun_if;
	register struct ifaddr *ifa;

	TUNDEBUG("%s%d: tuninit\n", ifp->if_name, ifp->if_unit);

	ifp->if_flags |= IFF_UP | IFF_RUNNING;
	getmicrotime(&ifp->if_lastchange);

	for (ifa = ifp->if_addrhead.tqh_first; ifa; 
	     ifa = ifa->ifa_link.tqe_next) {
#ifdef INET
		if (ifa->ifa_addr->sa_family == AF_INET) {
		    struct sockaddr_in *si;

		    si = (struct sockaddr_in *)ifa->ifa_addr;
		    if (si && si->sin_addr.s_addr)
			    tp->tun_flags |= TUN_IASET;

		    si = (struct sockaddr_in *)ifa->ifa_dstaddr;
		    if (si && si->sin_addr.s_addr)
			    tp->tun_flags |= TUN_DSTADDR;
		}
#endif
	}
	return 0;
}

/*
 * Process an ioctl request.
 */
int
tunifioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long	cmd;
	caddr_t	data;
{
	register struct ifreq *ifr = (struct ifreq *)data;
	int		error = 0, s;

	s = splimp();
	switch(cmd) {
	case SIOCSIFADDR:
		tuninit(ifp->if_unit);
		TUNDEBUG("%s%d: address set\n",
			 ifp->if_name, ifp->if_unit);
		break;
	case SIOCSIFDSTADDR:
		tuninit(ifp->if_unit);
		TUNDEBUG("%s%d: destination address set\n",
			 ifp->if_name, ifp->if_unit);
		break;
	case SIOCSIFMTU:
		ifp->if_mtu = ifr->ifr_mtu;
		TUNDEBUG("%s%d: mtu set\n",
			 ifp->if_name, ifp->if_unit);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;


	default:
		error = EINVAL;
	}
	splx(s);
	return (error);
}

/*
 * tunoutput - queue packets from higher level ready to put out.
 */
int
tunoutput(ifp, m0, dst, rt)
	struct ifnet   *ifp;
	struct mbuf    *m0;
	struct sockaddr *dst;
	struct rtentry *rt;
{
	struct tun_softc *tp = &tunctl[ifp->if_unit];
	int		s;

	TUNDEBUG ("%s%d: tunoutput\n", ifp->if_name, ifp->if_unit);

	if ((tp->tun_flags & TUN_READY) != TUN_READY) {
		TUNDEBUG ("%s%d: not ready 0%o\n", ifp->if_name,
			  ifp->if_unit, tp->tun_flags);
		m_freem (m0);
		return EHOSTDOWN;
	}

#if NBPFILTER > 0
	/* BPF write needs to be handled specially */
	if (dst->sa_family == AF_UNSPEC) {
		dst->sa_family = *(mtod(m0, int *));
		m0->m_len -= sizeof(int);
		m0->m_pkthdr.len -= sizeof(int);
		m0->m_data += sizeof(int);
	}

	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer to it).
		 */
		struct mbuf m;
		u_int af = dst->sa_family;

		m.m_next = m0;
		m.m_len = 4;
		m.m_data = (char *)&af;

		bpf_mtap(ifp, &m);
	}
#endif /* NBPFILTER > 0 */

	/* prepend sockaddr? this may abort if the mbuf allocation fails */
	if (tp->tun_flags & TUN_LMODE) {
		/* allocate space for sockaddr */
		M_PREPEND(m0, dst->sa_len, M_DONTWAIT);

		/* if allocation failed drop packet */
		if (m0 == NULL){
			s = splimp();	/* spl on queue manipulation */
			IF_DROP(&ifp->if_snd);
			splx(s);
			ifp->if_oerrors++;
			return (ENOBUFS);
		} else {
			bcopy(dst, m0->m_data, dst->sa_len);
		}
	}

	switch(dst->sa_family) {
#ifdef INET
	case AF_INET:
		s = splimp();
		if (IF_QFULL(&ifp->if_snd)) {
			IF_DROP(&ifp->if_snd);
			m_freem(m0);
			splx(s);
			ifp->if_collisions++;
			return (ENOBUFS);
		}
		ifp->if_obytes += m0->m_pkthdr.len;
		IF_ENQUEUE(&ifp->if_snd, m0);
		splx(s);
		ifp->if_opackets++;
		break;
#endif
	default:
		m_freem(m0);
		return EAFNOSUPPORT;
	}

	if (tp->tun_flags & TUN_RWAIT) {
		tp->tun_flags &= ~TUN_RWAIT;
		wakeup((caddr_t)tp);
	}
	if (tp->tun_flags & TUN_ASYNC && tp->tun_sigio)
		pgsigio(tp->tun_sigio, SIGIO, 0);
	selwakeup(&tp->tun_rsel);
	return 0;
}

/*
 * the cdevsw interface is now pretty minimal.
 */
static	int
tunioctl(dev, cmd, data, flag, p)
	dev_t		dev;
	u_long		cmd;
	caddr_t		data;
	int		flag;
	struct proc	*p;
{
	int		unit = dev_val(minor(dev)), s;
	struct tun_softc *tp = &tunctl[unit];
 	struct tuninfo *tunp;

	switch (cmd) {
 	case TUNSIFINFO:
 	        tunp = (struct tuninfo *)data;
 		tp->tun_if.if_mtu = tunp->mtu;
 		tp->tun_if.if_type = tunp->type;
 		tp->tun_if.if_baudrate = tunp->baudrate;
 		break;
 	case TUNGIFINFO:
 		tunp = (struct tuninfo *)data;
 		tunp->mtu = tp->tun_if.if_mtu;
 		tunp->type = tp->tun_if.if_type;
 		tunp->baudrate = tp->tun_if.if_baudrate;
 		break;
	case TUNSDEBUG:
		tundebug = *(int *)data;
		break;
	case TUNGDEBUG:
		*(int *)data = tundebug;
		break;
	case TUNSLMODE:
		if (*(int *)data)
			tp->tun_flags |= TUN_LMODE;
		else 
			tp->tun_flags &= ~TUN_LMODE;
		break;
	case TUNSIFMODE:
		/* deny this if UP */
		if (tp->tun_if.if_flags & IFF_UP)
			return(EBUSY);

		switch (*(int *)data) {
		case IFF_POINTOPOINT:
			tp->tun_if.if_flags |= IFF_POINTOPOINT;
			tp->tun_if.if_flags &= ~IFF_BROADCAST;
			break;
		case IFF_BROADCAST:
			tp->tun_if.if_flags &= ~IFF_POINTOPOINT;
			tp->tun_if.if_flags |= IFF_BROADCAST;
			break;
		default:
			return(EINVAL);
		}
		break;
	case FIONBIO:
		break;
	case FIOASYNC:
		if (*(int *)data)
			tp->tun_flags |= TUN_ASYNC;
		else
			tp->tun_flags &= ~TUN_ASYNC;
		break;
	case FIONREAD:
		s = splimp();
		if (tp->tun_if.if_snd.ifq_head) {
			struct mbuf *mb = tp->tun_if.if_snd.ifq_head;
			for( *(int *)data = 0; mb != 0; mb = mb->m_next) 
				*(int *)data += mb->m_len;
		} else
			*(int *)data = 0;
		splx(s);
		break;
	case FIOSETOWN:
		return (fsetown(*(int *)data, &tp->tun_sigio));

	case FIOGETOWN:
		*(int *)data = fgetown(tp->tun_sigio);
		return (0);

	/* This is deprecated, FIOSETOWN should be used instead. */
	case TIOCSPGRP:
		return (fsetown(-(*(int *)data), &tp->tun_sigio));

	/* This is deprecated, FIOGETOWN should be used instead. */
	case TIOCGPGRP:
		*(int *)data = -fgetown(tp->tun_sigio);
		return (0);

	default:
		return (ENOTTY);
	}
	return (0);
}

/*
 * The cdevsw read interface - reads a packet at a time, or at
 * least as much of a packet as can be read.
 */
static	int
tunread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	int		unit = dev_val(minor(dev));
	struct tun_softc *tp = &tunctl[unit];
	struct ifnet	*ifp = &tp->tun_if;
	struct mbuf	*m, *m0;
	int		error=0, len, s;

	TUNDEBUG ("%s%d: read\n", ifp->if_name, ifp->if_unit);
	if ((tp->tun_flags & TUN_READY) != TUN_READY) {
		TUNDEBUG ("%s%d: not ready 0%o\n", ifp->if_name,
			  ifp->if_unit, tp->tun_flags);
		return EHOSTDOWN;
	}

	tp->tun_flags &= ~TUN_RWAIT;

	s = splimp();
	do {
		IF_DEQUEUE(&ifp->if_snd, m0);
		if (m0 == 0) {
			if (flag & IO_NDELAY) {
				splx(s);
				return EWOULDBLOCK;
			}
			tp->tun_flags |= TUN_RWAIT;
			if((error = tsleep((caddr_t)tp, PCATCH | (PZERO + 1),
					"tunread", 0)) != 0) {
				splx(s);
				return error;
			}
		}
	} while (m0 == 0);
	splx(s);

	while (m0 && uio->uio_resid > 0 && error == 0) {
		len = min(uio->uio_resid, m0->m_len);
		if (len == 0)
			break;
		error = uiomove(mtod(m0, caddr_t), len, uio);
		MFREE(m0, m);
		m0 = m;
	}

	if (m0) {
		TUNDEBUG("Dropping mbuf\n");
		m_freem(m0);
	}
	return error;
}

/*
 * the cdevsw write interface - an atomic write is a packet - or else!
 */
static	int
tunwrite(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	int		unit = dev_val(minor(dev));
	struct ifnet	*ifp = &tunctl[unit].tun_if;
	struct mbuf	*top, **mp, *m;
	int		error=0, s, tlen, mlen;

	TUNDEBUG("%s%d: tunwrite\n", ifp->if_name, ifp->if_unit);

	if (uio->uio_resid < 0 || uio->uio_resid > TUNMRU) {
		TUNDEBUG("%s%d: len=%d!\n", ifp->if_name, ifp->if_unit,
		    uio->uio_resid);
		return EIO;
	}
	tlen = uio->uio_resid;

	/* get a header mbuf */
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return ENOBUFS;
	mlen = MHLEN;

	top = 0;
	mp = &top;
	while (error == 0 && uio->uio_resid > 0) {
		m->m_len = min(mlen, uio->uio_resid);
		error = uiomove(mtod (m, caddr_t), m->m_len, uio);
		*mp = m;
		mp = &m->m_next;
		if (uio->uio_resid > 0) {
			MGET (m, M_DONTWAIT, MT_DATA);
			if (m == 0) {
				error = ENOBUFS;
				break;
			}
			mlen = MLEN;
		}
	}
	if (error) {
		if (top)
			m_freem (top);
		return error;
	}

	top->m_pkthdr.len = tlen;
	top->m_pkthdr.rcvif = ifp;

#if NBPFILTER > 0
	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer to it).
		 */
		struct mbuf m;
		u_int af = AF_INET;

		m.m_next = top;
		m.m_len = 4;
		m.m_data = (char *)&af;

		bpf_mtap(ifp, &m);
	}
#endif

#ifdef INET
	s = splimp();
	if (IF_QFULL (&ipintrq)) {
		IF_DROP(&ipintrq);
		splx(s);
		ifp->if_collisions++;
		m_freem(top);
		return ENOBUFS;
	}
	IF_ENQUEUE(&ipintrq, top);
	splx(s);
	ifp->if_ibytes += tlen;
	ifp->if_ipackets++;
	schednetisr(NETISR_IP);
#endif
	return error;
}

/*
 * tunpoll - the poll interface, this is only useful on reads
 * really. The write detect always returns true, write never blocks
 * anyway, it either accepts the packet or drops it.
 */
static	int
tunpoll(dev, events, p)
	dev_t dev;
	int events;
	struct proc *p;
{
	int		unit = dev_val(minor(dev)), s;
	struct tun_softc *tp = &tunctl[unit];
	struct ifnet	*ifp = &tp->tun_if;
	int		revents = 0;

	s = splimp();
	TUNDEBUG("%s%d: tunpoll\n", ifp->if_name, ifp->if_unit);

	if (events & (POLLIN | POLLRDNORM))
		if (ifp->if_snd.ifq_len > 0) {
			TUNDEBUG("%s%d: tunpoll q=%d\n", ifp->if_name,
			    ifp->if_unit, ifp->if_snd.ifq_len);
			revents |= events & (POLLIN | POLLRDNORM);
		} else {
			TUNDEBUG("%s%d: tunpoll waiting\n", ifp->if_name,
			    ifp->if_unit);
			selrecord(p, &tp->tun_rsel);
		}

	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	splx(s);
	return (revents);
}


#endif  /* NTUN */
