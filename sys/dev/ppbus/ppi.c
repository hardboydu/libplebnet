/*-
 * Copyright (c) 1997 Nicolas Souchu
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
 *	$Id$
 *
 */
#include <sys/types.h>

#ifdef KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <sys/uio.h>
#include <sys/syslog.h>
#include <sys/malloc.h>

#include <machine/stdarg.h>
#include <machine/clock.h>

#include <i386/isa/isa.h>
#include <i386/isa/isa_device.h>

#include <sys/kernel.h>
#endif /*KERNEL */

#include <dev/ppbus/ppbconf.h>
#include <dev/ppbus/ppi.h>

static int	nppi = 0;
#define MAXPPI	8			/* XXX not much better! */
static struct ppi_data *ppidata[MAXPPI];

/*
 * Make ourselves visible as a ppbus driver
 */

static struct ppb_device	*ppiprobe(struct ppb_data *ppb);
static int			ppiattach(struct ppb_device *dev);
static void			ppiintr(int unit);

#ifdef KERNEL

static struct ppb_driver ppidriver = {
    ppiprobe, ppiattach, "ppi"
};
DATA_SET(ppbdriver_set, ppidriver);

#endif /* KERNEL */

static	d_open_t	ppiopen;
static	d_close_t	ppiclose;
static	d_ioctl_t	ppiioctl;

#define CDEV_MAJOR 14			/* XXX */
static struct cdevsw ppi_cdevsw = 
	{ ppiopen,	ppiclose,	noread,		nowrite,
	  ppiioctl,	nullstop,	nullreset,	nodevtotty,
	  seltrue,	nommap,		nostrat,	"ppi",	NULL,	-1 };

/*
 * ppiprobe()
 */
static struct ppb_device *
ppiprobe(struct ppb_data *ppb)
{
	struct ppi_data *ppi;

	ppi = (struct ppi_data *) malloc(sizeof(struct ppi_data),
							M_TEMP, M_NOWAIT);
	if (!ppi) {
		printf("ppi: cannot malloc!\n");
		return 0;
	}
	bzero(ppi, sizeof(struct ppi_data));

	ppidata[nppi] = ppi;

	/*
	 * ppi dependent initialisation.
	 */
	ppi->ppi_unit = nppi;

	/*
	 * ppbus dependent initialisation.
	 */
	ppi->ppi_dev.id_unit = ppi->ppi_unit;
	ppi->ppi_dev.ppb = ppb;
	ppi->ppi_dev.intr = ppiintr;

	/* Ok, go to next device on next probe */
	nppi ++;

	return &ppi->ppi_dev;
}

static int
ppiattach(struct ppb_device *dev)
{
	struct ppi_data *ppi = ppidata[dev->id_unit];

	/*
	 * Report ourselves
	 */
	printf("ppi%d: <generic parallel i/o> on ppbus %d\n",
	       dev->id_unit, dev->ppb->ppb_link->adapter_unit);

	return (1);
}

static void
ppiintr(int unit)
{
	return;
}

static int
ppiopen(dev_t dev, int flags, int fmt, struct proc *p)
{
	return (EOPNOTSUPP);
}

static int
ppiclose(dev_t dev, int flags, int fmt, struct proc *p)
{
	return (EOPNOTSUPP);
}

static int
ppiioctl(dev_t dev, int cmd, caddr_t data, int flags, struct proc *p)
{
	return (EOPNOTSUPP);
}

static ppi_devsw_installed = 0;

static void 	ppi_drvinit(void *unused)
{
	dev_t dev;

	if( ! ppi_devsw_installed ) {
		dev = makedev(CDEV_MAJOR, 0);
		cdevsw_add(&dev, &ppi_cdevsw, NULL);
		ppi_devsw_installed = 1;
    	}
}

SYSINIT(ppidev, SI_SUB_DRIVERS, SI_ORDER_MIDDLE + CDEV_MAJOR, ppi_drvinit, NULL)
