/*
 * Copyright (c) 1997, 1998 Hellmuth Michaelis. All rights reserved.
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
 *---------------------------------------------------------------------------
 *
 *	i4b_ctl.c - i4b system control port driver
 *	------------------------------------------
 *
 *	$Id: i4b_ctl.c,v 1.17 1998/12/05 18:02:39 hm Exp $
 *
 *	last edit-date: [Sat Dec  5 17:59:15 1998]
 *
 *---------------------------------------------------------------------------*/

#include "i4bctl.h"

#if NI4BCTL > 1
#error "only 1 (one) i4bctl device allowed!"
#endif

#if NI4BCTL > 0

#include <sys/param.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/ioccom.h>
#include <i386/isa/isa_device.h>
#else
#include <sys/ioctl.h>
#endif

#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef __FreeBSD__
#include "opt_devfs.h"
#endif

#ifdef DEVFS
#include <sys/devfsext.h>
#endif

#ifdef __FreeBSD__
#include <machine/i4b_debug.h>
#include <machine/i4b_ioctl.h>
#else
#include <machine/bus.h>
#include <sys/device.h>
#include <i4b/i4b_debug.h>
#include <i4b/i4b_ioctl.h>
#endif

#include <i4b/include/i4b_global.h>
#include <i4b/include/i4b_mbuf.h>
#include <i4b/layer1/i4b_l1.h>

static int openflag = 0;

#if BSD > 199306 && defined(__FreeBSD__)
static	d_open_t	i4bctlopen;
static	d_close_t	i4bctlclose;
static	d_ioctl_t	i4bctlioctl;
#if defined(__FreeBSD_version) && __FreeBSD_version >= 300001
static d_poll_t		i4bctlpoll;
#endif

#define CDEV_MAJOR 55
static struct cdevsw i4bctl_cdevsw = 
	{ i4bctlopen,	i4bctlclose,	noread,		nowrite,
	  i4bctlioctl,	nostop,		nullreset,	nodevtotty,
#if defined(__FreeBSD_version) && __FreeBSD_version >= 300001
	  i4bctlpoll,	nommap,		NULL,	"i4bctl", NULL,	-1 };
#else
	  noselect,	nommap,		NULL,	"i4bctl", NULL,	-1 };
#endif

static void i4bctlattach(void *);
PSEUDO_SET(i4bctlattach, i4b_i4bctldrv);

#define PDEVSTATIC	static
#endif /* __FreeBSD__ */

#ifdef DEVFS
static void *devfs_token;
#endif

#ifndef __FreeBSD__
#define PDEVSTATIC	/* */
void i4bctlattach __P((void));
int i4bctlopen __P((dev_t dev, int flag, int fmt, struct proc *p));
int i4bctlclose __P((dev_t dev, int flag, int fmt, struct proc *p));
int i4bctlioctl __P((dev_t dev, int cmd, caddr_t data, int flag, struct proc *p));
#endif	/* !FreeBSD */

#if BSD > 199306 && defined(__FreeBSD__)
/*---------------------------------------------------------------------------*
 *	initialization at kernel load time
 *---------------------------------------------------------------------------*/
static void
i4bctlinit(void *unused)
{
    dev_t dev;
    
    dev = makedev(CDEV_MAJOR, 0);

    cdevsw_add(&dev, &i4bctl_cdevsw, NULL);
}

SYSINIT(i4bctldev, SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR, &i4bctlinit, NULL);

#endif /* BSD > 199306 && defined(__FreeBSD__) */

/*---------------------------------------------------------------------------*
 *	interface attach routine
 *---------------------------------------------------------------------------*/
PDEVSTATIC void
#ifdef __FreeBSD__
i4bctlattach(void *dummy)
#else
i4bctlattach()
#endif
{
#ifndef HACK_NO_PSEUDO_ATTACH_MSG
	printf("i4bctl: ISDN system control port attached\n");
#endif
#ifdef DEVFS
	devfs_token = devfs_add_devswf(&i4bctl_cdevsw, 0, DV_CHR,
				       UID_ROOT, GID_WHEEL, 0600,
				       "i4bctl", 0);
#endif
}

/*---------------------------------------------------------------------------*
 *	i4bctlopen - device driver open routine
 *---------------------------------------------------------------------------*/
PDEVSTATIC int
i4bctlopen(dev_t dev, int flag, int fmt, struct proc *p)
{
	if(minor(dev))
		return (ENXIO);

	if(openflag)
		return (EBUSY);
	
	openflag = 1;
	
	return (0);
}

/*---------------------------------------------------------------------------*
 *	i4bctlclose - device driver close routine
 *---------------------------------------------------------------------------*/
PDEVSTATIC int
i4bctlclose(dev_t dev, int flag, int fmt, struct proc *p)
{
	openflag = 0;
	return (0);
}

/*---------------------------------------------------------------------------*
 *	i4bctlioctl - device driver ioctl routine
 *---------------------------------------------------------------------------*/
PDEVSTATIC int
#if defined (__FreeBSD_version) && __FreeBSD_version >= 300003
i4bctlioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
#else
i4bctlioctl(dev_t dev, int cmd, caddr_t data, int flag, struct proc *p)
#endif
{
	ctl_debug_t *cdbg;	
	int error = 0;
	
#ifndef DO_I4B_DEBUG
       return(ENODEV);
#else
	if(minor(dev))
		return(ENODEV);

	switch(cmd)
	{
		case I4B_CTL_GET_DEBUG:
			cdbg = (ctl_debug_t *)data;
			cdbg->l1 = i4b_l1_debug;
			cdbg->l2 = i4b_l2_debug;
			cdbg->l3 = i4b_l3_debug;
			cdbg->l4 = i4b_l4_debug;
			break;
		
		case I4B_CTL_SET_DEBUG:
			cdbg = (ctl_debug_t *)data;
			i4b_l1_debug = cdbg->l1;
			i4b_l2_debug = cdbg->l2;
			i4b_l3_debug = cdbg->l3;
			i4b_l4_debug = cdbg->l4;
			break;

                case I4B_CTL_GET_HSCXSTAT:
                {
                        hscxstat_t *hst;
                        struct isic_softc *sc;
                        hst = (hscxstat_t *)data;

                        if( hst->unit < 0		||
			    hst->unit > ISIC_MAXUNIT	||
			    hst->chan < 0		||
			    hst->chan > 1 )
                        {
                        	error = EINVAL;
				break;
			}
			  
#ifndef __FreeBSD__
			sc = isic_find_sc(hst->unit);
#else
			sc = &isic_sc[hst->unit];
#endif
			hst->vfr = sc->sc_chan[hst->chan].stat_VFR;
			hst->rdo = sc->sc_chan[hst->chan].stat_RDO;
			hst->crc = sc->sc_chan[hst->chan].stat_CRC;
			hst->rab = sc->sc_chan[hst->chan].stat_RAB;
			hst->xdu = sc->sc_chan[hst->chan].stat_XDU;
			hst->rfo = sc->sc_chan[hst->chan].stat_RFO;
                        break;
                }

                case I4B_CTL_CLR_HSCXSTAT:
                {
                        hscxstat_t *hst;
                        struct isic_softc *sc;
                        hst = (hscxstat_t *)data;

                        if( hst->unit < 0		||
			    hst->unit > ISIC_MAXUNIT	||
			    hst->chan < 0		||
			    hst->chan > 1 )
                        {
                        	error = EINVAL;
				break;
			}
			  
#ifndef __FreeBSD__
			sc = isic_find_sc(hst->unit);
#else
			sc = &isic_sc[hst->unit];
#endif

			sc->sc_chan[hst->chan].stat_VFR = 0;
			sc->sc_chan[hst->chan].stat_RDO = 0;
			sc->sc_chan[hst->chan].stat_CRC = 0;
			sc->sc_chan[hst->chan].stat_RAB = 0;
			sc->sc_chan[hst->chan].stat_XDU = 0;
			sc->sc_chan[hst->chan].stat_RFO = 0;
			
                        break;
                }

		default:
			error = ENOTTY;
			break;
	}
	return(error);
#endif DO_I4B_DEBUG
}

/*---------------------------------------------------------------------------*
 *	i4bctlpoll - device driver poll routine
 *---------------------------------------------------------------------------*/
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static int
i4bctlpoll (dev_t dev, int events, struct proc *p)
{
	return (ENODEV);
}
#endif

#endif /* NI4BCTL > 0 */
