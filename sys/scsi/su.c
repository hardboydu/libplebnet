/* su: SCSI Universal. This is a universal SCSI device that
 * has a fixed minor number format.  This allows you to refer
 * to your devices by BUS, ID, LUN instead of st0, st1, ...
 *
 * This code looks up the underlying device for a given SCSI
 * target and uses that driver.
 *
 *Begin copyright
 *
 * Copyright (C) 1993, 1994, 1995, HD Associates, Inc.
 * PO Box 276
 * Pepperell, MA 01463
 * 508 433 5266
 * dufault@hda.com
 *
 * This code is contributed to the University of California at Berkeley:
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
 *End copyright
 *
 *      $Id: su.c,v 1.20 1998/07/04 22:30:25 julian Exp $
 *
 * Tabstops 4
 * XXX devfs entries for this device should be handled by generic scsiconfig
 * Add a bdevsw interface.. ?
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <scsi/scsiconf.h>
#define CDEV_MAJOR 18

/* These three used by ssc. */
extern	d_open_t	suopen;
extern	d_close_t	suclose;
extern	d_ioctl_t	suioctl;

static	d_read_t	suread;
static	d_write_t	suwrite;
static	d_poll_t	supoll;
static	d_strategy_t	sustrategy;

static struct cdevsw su_cdevsw = 
	{ suopen,	suclose,	suread,		suwrite,	/*18*/
	  suioctl,	nostop,		nullreset,	nodevtotty,/* scsi */
	  supoll,	nommap,		sustrategy, "su",	NULL,	-1 };


/* Build an old style device number (unit encoded in the minor number)
 * from a base old one (no flag bits) and a full new one
 * (BUS, LUN, TARG in the minor number, and flag bits).
 *
 * OLDDEV has the major number and device unit only.  It was constructed
 * at attach time and is stored in the scsi_link structure.
 *
 * NEWDEV can have whatever in it, but only the old control flags and the
 * super bit are present.  IT CAN'T HAVE ANY UNIT INFORMATION or you'll
 * wind up with the wrong unit.
 */
#define OLD_DEV(NEWDEV, OLDDEV) ((OLDDEV) | ((NEWDEV) & 0x080000FF))

/* cnxio: non existent device entries. */

static	d_open_t	nxopen;
static	d_close_t	nxclose;
static	d_read_t	nxread;
static	d_write_t	nxwrite;
static	d_ioctl_t	nxioctl;
#define	nxstop	nostop		/* one void return is as good as another */
#define	nxreset	noreset		/* one unused function is as good as another */
#define	nxdevtotty nodevtotty	/* one NULL return is as good as another */
#define	nxmmap	nommap		/* one -1 return is as good as another */
#define	nxstrategy nostrategy	/* one NULL value is as good as another */
static	d_dump_t	nxdump;
#define	nxpsize	nopsize		/* one NULL value is as good as another */

static struct cdevsw cnxio = {
	nxopen,
	nxclose,
	nxread,
	nxwrite,
	nxioctl,
	nxstop,
	nxreset,
	nxdevtotty,
	seltrue,
	nxmmap,
	nxstrategy,
	"NON",
	NULL,
	-1,
	nxdump,
	nxpsize,
	0,
	0,
	-1
};

/* getsws: Look up the base dev switch for a given "by minor number" style
 * device.
 */
static int
getsws(dev_t dev, int type, struct cdevsw **devswpp, dev_t *base)
{
	int ret = 0;
	struct scsi_link *scsi_link;
	int chr_dev, blk_dev;

	struct cdevsw *devswp;

	int bus = SCSI_BUS(dev),
	    lun = SCSI_LUN(dev),
	    id =  SCSI_ID(dev);

	/* Try to look up the base device by finding the major number in
	 * the scsi_link structure:
	 */
	if ((scsi_link = scsi_link_get(bus, id, lun)) == 0 ||
	scsi_link->dev == NODEV)
	{
		ret = ENXIO;
		devswp = &cnxio;
		chr_dev = NODEV;
		blk_dev = NODEV;
	}
	else
	{
		int bmaj, cmaj;

		cmaj = major(scsi_link->dev);
		devswp = cdevsw[cmaj];
		chr_dev = OLD_DEV(dev, scsi_link->dev);
		bmaj = devswp->d_bmaj;
		blk_dev = OLD_DEV(dev, makedev(bmaj, minor(scsi_link->dev)));
	}

	if (devswp)
		*devswpp = devswp;

	if (type == S_IFCHR)
		*base = chr_dev;
	else
		*base = blk_dev;

	return ret;
}

int
suopen(dev_t dev, int flag, int type, struct proc *p)
{
	struct cdevsw *devswp;
	dev_t base;

	if (getsws(dev, type, &devswp, &base))
	{
		/* Device not configured?  Reprobe then try again.
		 */
		int bus = SCSI_BUS(dev), lun = SCSI_LUN(dev), id =  SCSI_ID(dev);

		if (scsi_probe_bus(bus, id, lun) || getsws(dev, type, &devswp,
		&base))
			return ENXIO;
	}

	/* There is a properly configured underlying device.
	 * Synthesize an appropriate device number:
	 */
	return (*devswp->d_open)(base, flag, type, p);
}

int
suclose(dev_t dev, int fflag, int type, struct proc *p)
{
	struct cdevsw *devswp;
	dev_t base;

	(void)getsws(dev, type, &devswp, &base);

	return (*devswp->d_close)(base, fflag, type, p);
}

static	void
sustrategy(struct buf *bp)
{
	dev_t base;
	struct cdevsw *devswp;
	dev_t dev = bp->b_dev;

	/* XXX: I have no way of knowing if this was through the
	 * block or the character entry point.
	 */
	(void)getsws(dev, S_IFBLK, &devswp, &base);

	bp->b_dev = base;

	(*devswp->d_strategy)(bp);

	bp->b_dev = dev; /* strat needs a dev_t */
}

int
suioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
	struct cdevsw *devswp;
	dev_t base;

	/* XXX: I have no way of knowing if this was through the
	 * block or the character entry point.
	 */
	(void)getsws(dev, S_IFCHR, &devswp, &base);

	return (*devswp->d_ioctl)(base, cmd, data, fflag, p);
}

static	int
suread(dev_t dev, struct uio *uio, int ioflag)
{
	dev_t base;
	struct cdevsw *devswp;

	(void)getsws(dev, S_IFCHR, &devswp, &base);

	return (*devswp->d_read)(base, uio, ioflag);
}

static	int
suwrite(dev_t dev, struct uio *uio, int ioflag)
{
	dev_t base;
	struct cdevsw *devswp;

	(void)getsws(dev, S_IFCHR, &devswp, &base);

	return (*devswp->d_write)(base, uio, ioflag);
}

static	int
supoll(dev_t dev, int events, struct proc *p)
{
	dev_t base;
	struct cdevsw *devswp;

	(void)getsws(dev, S_IFCHR, &devswp, &base);

	return (*devswp->d_poll)(base, events, p);
}

static int
nxopen(dev, flags, fmt, p)
	dev_t dev;
	int flags;
	int fmt;
	struct proc *p;
{

	return (ENXIO);
}

static int
nxclose(dev, flags, fmt, p)
	dev_t dev;
	int flags;
	int fmt;
	struct proc *p;
{

	printf("nxclose(0x%x) called\n", dev);
	return (ENXIO);
}

static int
nxread(dev, uio, ioflag)
	dev_t dev;
	struct uio *uio;
	int ioflag;
{

	printf("nxread(0x%x) called\n", dev);
	return (ENXIO);
}

static int
nxwrite(dev, uio, ioflag)
	dev_t dev;
	struct uio *uio;
	int ioflag;
{

	printf("nxwrite(0x%x) called\n", dev);
	return (ENXIO);
}

static int
nxioctl(dev, cmd, data, flags, p)
	dev_t dev;
	u_long cmd;
	caddr_t data;
	int flags;
	struct proc *p;
{

	printf("nxioctl(0x%x) called\n", dev);
	return (ENXIO);
}

static int
nxdump(dev)
	dev_t dev;
{

	printf("nxdump(0x%x) called\n", dev);
	return (ENXIO);
}

static su_devsw_installed = 0;

static void
su_drvinit(void *unused)
{
	dev_t dev;

	if( ! su_devsw_installed ) {
		dev = makedev(CDEV_MAJOR, 0);
		cdevsw_add(&dev,&su_cdevsw, NULL);
		su_devsw_installed = 1;
    	}
}

SYSINIT(sudev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,su_drvinit,NULL)


