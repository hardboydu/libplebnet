/*
 * Copyright (c) 1995 Ugen J.S.Antsilevich
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * Snoop stuff.
 */

#include "snp.h"

#if NSNP > 0

#include "opt_compat.h"
#include "opt_devfs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filio.h>
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
#include <sys/ioctl_compat.h>
#endif
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/poll.h>
#include <sys/kernel.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif /*DEVFS*/
#include <sys/snoop.h>
#include <sys/vnode.h>

static	d_open_t	snpopen;
static	d_close_t	snpclose;
static	d_read_t	snpread;
static	d_write_t	snpwrite;
static	d_ioctl_t	snpioctl;
static	d_poll_t	snppoll;

#define CDEV_MAJOR 53
static struct cdevsw snp_cdevsw = {
	/* open */	snpopen,
	/* close */	snpclose,
	/* read */	snpread,
	/* write */	snpwrite,
	/* ioctl */	snpioctl,
	/* stop */	nostop,
	/* reset */	noreset,
	/* devtotty */	nodevtotty,
	/* poll */	snppoll,
	/* mmap */	nommap,
	/* strategy */	nostrategy,
	/* name */	"snp",
	/* parms */	noparms,
	/* maj */	CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	0,
	/* maxio */	0,
	/* bmaj */	-1
};


#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

static struct snoop snoopsw[NSNP];

static struct tty	*snpdevtotty __P((dev_t dev));
static int		snp_detach __P((struct snoop *snp));

static struct tty *
snpdevtotty (dev)
	dev_t		dev;
{
	struct cdevsw	*cdp;
	int		maj;

	maj = major(dev);
	if ((u_int)maj >= nchrdev)
		return (NULL);
	cdp = devsw(dev);
	if (cdp == NULL)
		return (NULL);
	return ((*cdp->d_devtotty)(dev));
}

#define SNP_INPUT_BUF	5	/* This is even too  much,the maximal
				 * interactive mode write is 3 bytes
				 * length for function keys...
				 */

static	int
snpwrite(dev, uio, flag)
	dev_t           dev;
	struct uio     *uio;
	int             flag;
{
	int             unit = minor(dev), len, i, error;
	struct snoop   *snp = &snoopsw[unit];
	struct tty     *tp;
	char		c[SNP_INPUT_BUF];

	if (snp->snp_tty == NULL)
		return (EIO);

	tp = snp->snp_tty;

	if ((tp->t_sc == snp) && (tp->t_state & TS_SNOOP) &&
	    (tp->t_line == OTTYDISC || tp->t_line == NTTYDISC))
		goto tty_input;

	printf("Snoop: attempt to write to bad tty.\n");
	return (EIO);

tty_input:
	if (!(tp->t_state & TS_ISOPEN))
		return (EIO);

	while (uio->uio_resid > 0) {
		len = MIN(uio->uio_resid,SNP_INPUT_BUF);
		if ((error = uiomove(c, len, uio)) != 0)
			return (error);
		for (i=0;i<len;i++) {
			if (ttyinput(c[i] , tp))
				return (EIO);
		}
	}
	return 0;

}


static	int
snpread(dev, uio, flag)
	dev_t           dev;
	struct uio     *uio;
	int             flag;
{
	int             unit = minor(dev), s;
	struct snoop   *snp = &snoopsw[unit];
	int             len, n, nblen, error = 0;
	caddr_t         from;
	char           *nbuf;

	KASSERT(snp->snp_len + snp->snp_base <= snp->snp_blen,
	    ("snoop buffer error"));

	if (snp->snp_tty == NULL)
		return (EIO);

	snp->snp_flags &= ~SNOOP_RWAIT;

	do {
		if (snp->snp_len == 0) {
			if (flag & IO_NDELAY)
				return (EWOULDBLOCK);
			snp->snp_flags |= SNOOP_RWAIT;
			tsleep((caddr_t) snp, (PZERO + 1) | PCATCH, "snoopread", 0);
		}
	} while (snp->snp_len == 0);

	n = snp->snp_len;

	while (snp->snp_len > 0 && uio->uio_resid > 0 && error == 0) {
		len = MIN(uio->uio_resid, snp->snp_len);
		from = (caddr_t) (snp->snp_buf + snp->snp_base);
		if (len == 0)
			break;

		error = uiomove(from, len, uio);
		snp->snp_base += len;
		snp->snp_len -= len;
	}
	if ((snp->snp_flags & SNOOP_OFLOW) && (n < snp->snp_len)) {
		snp->snp_flags &= ~SNOOP_OFLOW;
	}
	s = spltty();
	nblen = snp->snp_blen;
	if (((nblen / 2) >= SNOOP_MINLEN) && (nblen / 2) >= snp->snp_len) {
		while (((nblen / 2) >= snp->snp_len) && ((nblen / 2) >= SNOOP_MINLEN))
			nblen = nblen / 2;
		if ((nbuf = malloc(nblen, M_TTYS, M_NOWAIT)) != NULL) {
			bcopy(snp->snp_buf + snp->snp_base, nbuf, snp->snp_len);
			free(snp->snp_buf, M_TTYS);
			snp->snp_buf = nbuf;
			snp->snp_blen = nblen;
			snp->snp_base = 0;
		}
	}
	splx(s);

	return error;
}

int
snpinc(struct snoop *snp, char c)
{
        char    buf[1];

        buf[0]=c;
        return (snpin(snp,buf,1));
}


int
snpin(snp, buf, n)
	struct snoop   *snp;
	char           *buf;
	int             n;
{
	int             s_free, s_tail;
	int             s, len, nblen;
	caddr_t         from, to;
	char           *nbuf;

	KASSERT(n >= 0, ("negative snoop char count"));

	if (n == 0)
		return 0;

#ifdef DIAGNOSTIC
	if (!(snp->snp_flags & SNOOP_OPEN)) {
		printf("Snoop: data coming to closed device.\n");
		return 0;
	}
#endif
	if (snp->snp_flags & SNOOP_DOWN) {
		printf("Snoop: more data to down interface.\n");
		return 0;
	}

	if (snp->snp_flags & SNOOP_OFLOW) {
		printf("Snoop: buffer overflow.\n");
		/*
		 * On overflow we just repeat the standart close
		 * procedure...yes , this is waste of space but.. Then next
		 * read from device will fail if one would recall he is
		 * snooping and retry...
		 */

		return (snpdown(snp));
	}
	s_tail = snp->snp_blen - (snp->snp_len + snp->snp_base);
	s_free = snp->snp_blen - snp->snp_len;


	if (n > s_free) {
		s = spltty();
		nblen = snp->snp_blen;
		while ((n > s_free) && ((nblen * 2) <= SNOOP_MAXLEN)) {
			nblen = snp->snp_blen * 2;
			s_free = nblen - (snp->snp_len + snp->snp_base);
		}
		if ((n <= s_free) && (nbuf = malloc(nblen, M_TTYS, M_NOWAIT))) {
			bcopy(snp->snp_buf + snp->snp_base, nbuf, snp->snp_len);
			free(snp->snp_buf, M_TTYS);
			snp->snp_buf = nbuf;
			snp->snp_blen = nblen;
			snp->snp_base = 0;
		} else {
			snp->snp_flags |= SNOOP_OFLOW;
			if (snp->snp_flags & SNOOP_RWAIT) {
				snp->snp_flags &= ~SNOOP_RWAIT;
				wakeup((caddr_t) snp);
			}
			splx(s);
			return 0;
		}
		splx(s);
	}
	if (n > s_tail) {
		from = (caddr_t) (snp->snp_buf + snp->snp_base);
		to = (caddr_t) (snp->snp_buf);
		len = snp->snp_len;
		bcopy(from, to, len);
		snp->snp_base = 0;
	}
	to = (caddr_t) (snp->snp_buf + snp->snp_base + snp->snp_len);
	bcopy(buf, to, n);
	snp->snp_len += n;

	if (snp->snp_flags & SNOOP_RWAIT) {
		snp->snp_flags &= ~SNOOP_RWAIT;
		wakeup((caddr_t) snp);
	}
	selwakeup(&snp->snp_sel);
	snp->snp_sel.si_pid = 0;

	return n;
}

static	int
snpopen(dev, flag, mode, p)
	dev_t           dev;
	int             flag, mode;
	struct proc    *p;
{
	struct snoop   *snp;
	register int    unit, error;

	if ((error = suser(p)) != 0)
		return (error);

	if ((unit = minor(dev)) >= NSNP)
		return (ENXIO);

	snp = &snoopsw[unit];

	if (snp->snp_flags & SNOOP_OPEN)
		return (ENXIO);

	/*
	 * We intentionally do not OR flags with SNOOP_OPEN,but set them so
	 * all previous settings (especially SNOOP_OFLOW) will be cleared.
	 */
	snp->snp_flags = SNOOP_OPEN;

	snp->snp_buf = malloc(SNOOP_MINLEN, M_TTYS, M_WAITOK);
	snp->snp_blen = SNOOP_MINLEN;
	snp->snp_base = 0;
	snp->snp_len = 0;

	/*
	 * snp_tty == NULL  is for inactive snoop devices.
	 */
	snp->snp_tty = NULL;
	snp->snp_target = NODEV;
	return (0);
}


static int
snp_detach(snp)
	struct snoop   *snp;
{
	struct tty     *tp;

	snp->snp_base = 0;
	snp->snp_len = 0;

	/*
	 * If line disc. changed we do not touch this pointer,SLIP/PPP will
	 * change it anyway.
	 */

	if (snp->snp_tty == NULL)
		goto detach_notty;

	tp = snp->snp_tty;

	if (tp && (tp->t_sc == snp) && (tp->t_state & TS_SNOOP) &&
	    (tp->t_line == OTTYDISC || tp->t_line == NTTYDISC)) {
		tp->t_sc = NULL;
		tp->t_state &= ~TS_SNOOP;
	} else
		printf("Snoop: bad attached tty data.\n");

	snp->snp_tty = NULL;
	snp->snp_target = NODEV;

detach_notty:
	selwakeup(&snp->snp_sel);
	snp->snp_sel.si_pid = 0;

	return (0);
}

static	int
snpclose(dev, flags, fmt, p)
	dev_t           dev;
	int             flags;
	int             fmt;
	struct proc    *p;
{
	register int    unit = minor(dev);
	struct snoop   *snp = &snoopsw[unit];

	snp->snp_blen = 0;
	free(snp->snp_buf, M_TTYS);
	snp->snp_flags &= ~SNOOP_OPEN;

	return (snp_detach(snp));
}

int
snpdown(snp)
	struct snoop	*snp;
{
	snp->snp_blen = SNOOP_MINLEN;
	free(snp->snp_buf, M_TTYS);
	snp->snp_buf = malloc(SNOOP_MINLEN, M_TTYS, M_WAITOK);
	snp->snp_flags |= SNOOP_DOWN;

	return (snp_detach(snp));
}


static	int
snpioctl(dev, cmd, data, flags, p)
	dev_t           dev;
	u_long          cmd;
	caddr_t         data;
	int             flags;
	struct proc    *p;
{
	int             unit = minor(dev), s;
	dev_t		tdev;
	struct snoop   *snp = &snoopsw[unit];
	struct tty     *tp, *tpo;

	switch (cmd) {
	case SNPSTTY:
		tdev = *((dev_t *) data);
		if (tdev == NODEV)
			return (snpdown(snp));

		tp = snpdevtotty(tdev);
		if (!tp)
			return (EINVAL);

		if ((tp->t_sc != (caddr_t) snp) && (tp->t_state & TS_SNOOP))
			return (EBUSY);

		if ((tp->t_line != OTTYDISC) && (tp->t_line != NTTYDISC))
			return (EBUSY);

		s = spltty();

		if (snp->snp_target == NODEV) {
			tpo = snp->snp_tty;
			if (tpo)
				tpo->t_state &= ~TS_SNOOP;
		}

		tp->t_sc = (caddr_t) snp;
		tp->t_state |= TS_SNOOP;
		snp->snp_tty = tp;
		snp->snp_target = tdev;

		/*
		 * Clean overflow and down flags -
		 * we'll have a chance to get them in the future :)))
		 */
		snp->snp_flags &= ~SNOOP_OFLOW;
		snp->snp_flags &= ~SNOOP_DOWN;
		splx(s);
		break;

	case SNPGTTY:
		/*
		 * We keep snp_target field specially to make
		 * SNPGTTY happy,else we can't know what is device
		 * major/minor for tty.
		 */
		*((dev_t *) data) = snp->snp_target;
		break;

	case FIONBIO:
		break;

	case FIOASYNC:
		if (*(int *) data)
			snp->snp_flags |= SNOOP_ASYNC;
		else
			snp->snp_flags &= ~SNOOP_ASYNC;
		break;

	case FIONREAD:
		s = spltty();
		if (snp->snp_tty != NULL)
			*(int *) data = snp->snp_len;
		else
			if (snp->snp_flags & SNOOP_DOWN) {
				if (snp->snp_flags & SNOOP_OFLOW)
					*(int *) data = SNP_OFLOW;
				else
					*(int *) data = SNP_TTYCLOSE;
			} else {
				*(int *) data = SNP_DETACH;
			}
		splx(s);
		break;

	default:
		return (ENOTTY);
	}
	return (0);
}


static	int
snppoll(dev, events, p)
	dev_t           dev;
	int             events;
	struct proc    *p;
{
	int             unit = minor(dev);
	struct snoop   *snp = &snoopsw[unit];
	int		revents = 0;


	/*
	 * If snoop is down,we don't want to poll() forever so we return 1.
	 * Caller should see if we down via FIONREAD ioctl().The last should
	 * return -1 to indicate down state.
	 */
	if (events & (POLLIN | POLLRDNORM)) {
		if (snp->snp_flags & SNOOP_DOWN || snp->snp_len > 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(p, &snp->snp_sel);
	}
	return (revents);
}

#ifdef DEVFS
static	void	*snp_devfs_token[NSNP];
#endif
static	int	snp_devsw_installed;

static void snp_drvinit __P((void *unused));
static void
snp_drvinit(unused)
	void *unused;
{
	dev_t dev;
#ifdef DEVFS
	int	i;
#endif

	if( ! snp_devsw_installed ) {
		dev = makedev(CDEV_MAJOR, 0);
		cdevsw_add(&dev,&snp_cdevsw, NULL);
		snp_devsw_installed = 1;
#ifdef DEVFS
		for ( i = 0 ; i < NSNP ; i++) {
			snp_devfs_token[i] =
				devfs_add_devswf(&snp_cdevsw, i, DV_CHR, 0, 0, 
						0600, "snp%d", i);
		}
#endif
    	}
}

SYSINIT(snpdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,snp_drvinit,NULL)


#endif
