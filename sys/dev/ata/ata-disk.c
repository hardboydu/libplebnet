/*-
 * Copyright (c) 1998,1999 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$Id: ata-disk.c,v 1.14 1999/03/01 21:03:15 sos Exp sos $
 */

#include "ata.h"
#include "atadisk.h"
#include "opt_devfs.h"

#if NATA > 0 && NATADISK > 0

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include <sys/devicestat.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif
#include <machine/clock.h>
#include <i386/isa/isa.h>
#include <i386/isa/isa_device.h>
#include <dev/ata/ata-all.h>
#include <dev/ata/ata-disk.h>

static d_open_t		adopen;
static d_close_t	adclose;
static d_write_t	adwrite;
static d_read_t		adread;
static d_ioctl_t	adioctl;
static d_strategy_t	adstrategy;
static d_psize_t	adpsize;

#define BDEV_MAJOR 0
#define CDEV_MAJOR 3
static struct cdevsw ad_cdevsw = {
    adopen,	adclose,	adread,		adwrite,	
    adioctl,	nostop,		nullreset,	nodevtotty,
    seltrue,	nommap,		adstrategy,	"ad",
    NULL,	-1,		nodump,		adpsize,
    D_DISK,	0,		-1
};

/* misc defines */
#define UNIT(dev) (dev>>3 & 0x1f)		/* assume 8 minor # per unit */
#define NUNIT	16				/* max # of devices */

/* prototypes */
static void ad_attach(void *);
static void ad_strategy(struct buf *);
static void ad_start(struct ad_softc *);
static void ad_sleep(struct ad_softc *, int8_t *);
static int32_t ad_command(struct ad_softc *, u_int32_t, u_int32_t, u_int32_t, u_int32_t, u_int32_t);
static int8_t ad_version(u_int16_t);
static void ad_drvinit(void);

static struct ad_softc *adtab[NUNIT];
static int32_t adnlun = 0;     			/* number of config'd drives */
static struct intr_config_hook *ad_attach_hook;

static void
ad_attach(void *notused)
{
    struct ad_softc *adp;
    int32_t ctlr, dev;
    int8_t model_buf[40+1];
    int8_t revision_buf[8+1];

    /* now, run through atadevices and look for ATA disks */
    for (ctlr=0; ctlr<MAXATA && atadevices[ctlr]; ctlr++) {
	for (dev=0; dev<2; dev++) {
	    if (atadevices[ctlr]->ata_parm[dev]) {
    		adp = adtab[adnlun];
    		if (adp)
        	    printf("ad%d: unit already attached\n", adnlun);
    		adp = malloc(sizeof(struct ad_softc), M_DEVBUF, M_NOWAIT);
    		if (adp == NULL)
        	    printf("ad%d: failed to allocate driver storage\n", adnlun);
    		bzero(adp, sizeof(struct ad_softc));
	        adp->controller = atadevices[ctlr];
	        adp->ata_parm = atadevices[ctlr]->ata_parm[dev];
		adp->unit = (dev == 0) ? ATA_MASTER : ATA_SLAVE;
		adp->cylinders = adp->ata_parm->cylinders;
		adp->heads = adp->ata_parm->heads;
		adp->sectors = adp->ata_parm->sectors;
		adp->total_secs = adp->ata_parm->lbasize;

		/* support multiple sectors / interrupt ? */
		if (ad_command(adp, ATA_C_SET_MULTI, 0, 0, 0, 16))
		    adp->transfersize = DEV_BSIZE;
		else {
		    if (ata_wait(adp->controller, ATA_S_DRDY) < 0)
		        adp->transfersize = DEV_BSIZE;
		    else
			adp->transfersize = 16*DEV_BSIZE;
		}
	        bpack(adp->ata_parm->model, model_buf, sizeof(model_buf));
		bpack(adp->ata_parm->revision, revision_buf, 
		      sizeof(revision_buf));
		printf("ad%d: <%s/%s> ATA-%c disk at ata%d as %s\n", 
		       adnlun,
           	       model_buf, revision_buf,
		       ad_version(adp->ata_parm->versmajor),
		       ctlr,
		       (adp->unit == ATA_MASTER) ? "master" : "slave ");
		printf("ad%d: %luMB (%u sectors), "
		       "%u cyls, %u heads, %u S/T, %u B/S\n",
		       adnlun,
		       adp->total_secs / ((1024L * 1024L) / DEV_BSIZE),
		       adp->total_secs,
		       adp->cylinders,
		       adp->heads,
		       adp->sectors,
		       DEV_BSIZE);
		printf("ad%d: %d secs/int, %d depth queue \n", 
		       adnlun, adp->transfersize / DEV_BSIZE,
		       adp->ata_parm->queuelen & 0x1f);
                devstat_add_entry(&adp->stats, "ad", adnlun, DEV_BSIZE,
				  DEVSTAT_NO_ORDERED_TAGS,
                                  DEVSTAT_TYPE_DIRECT | DEVSTAT_TYPE_IF_IDE,
				  0x180);
		bufq_init(&adp->queue);
	        adtab[adnlun++] = adp;
            }
	}
    }
    config_intrhook_disestablish(ad_attach_hook);
}

static int32_t
adopen(dev_t dev, int32_t flags, int32_t fmt, struct proc *p)
{
    int32_t lun = UNIT(dev);
    struct ad_softc *adp;
    struct disklabel label;
    int32_t error;

#ifdef AD_DEBUG
printf("adopen: lun=%d adnlun=%d\n", lun, adnlun);
#endif
    if (lun >= adnlun || !(adp = adtab[lun]))
        return ENXIO;

    /* spinwait if anybody else is reading the disk label */
    while (adp->flags & AD_F_LABELLING)
        tsleep((caddr_t)&adp->flags, PZERO - 1, "adop1", 1);

    /* protect agains label race */
    adp->flags |= AD_F_LABELLING;

    /* build disklabel and initilize slice tables */
    bzero(&label, sizeof label);
    label.d_secsize = DEV_BSIZE;
    label.d_nsectors = adp->sectors;
    label.d_ntracks = adp->heads;
    label.d_ncylinders = adp->cylinders;
    label.d_secpercyl = adp->sectors * adp->heads;
    label.d_secperunit = adp->total_secs;

    error = dsopen("ad", dev, fmt, 0, &adp->slices, &label, ad_strategy,
                   (ds_setgeom_t *)NULL, &ad_cdevsw);

    adp->flags &= ~AD_F_LABELLING;
    ad_sleep(adp, "adop2");
    return error;
}

static int32_t 
adclose(dev_t dev, int32_t flags, int32_t fmt, struct proc *p)
{
    int32_t lun = UNIT(dev);
    struct ad_softc *adp;

#ifdef AD_DEBUG
printf("adclose: lun=%d adnlun=%d\n", lun, adnlun);
#endif
    if (lun >= adnlun || !(adp = adtab[lun]))
        return ENXIO;

    dsclose(dev, fmt, adp->slices);
    return 0;
}

static int32_t
adread(dev_t dev, struct uio *uio, int32_t ioflag)
{
    return physio(adstrategy, NULL, dev, 1, minphys, uio);
}

static int32_t
adwrite(dev_t dev, struct uio *uio, int32_t ioflag)
{
    return physio(adstrategy, NULL, dev, 0, minphys, uio);
}

static int32_t 
adioctl(dev_t dev, u_long cmd, caddr_t addr, int32_t flags, struct proc *p)
{
    struct ad_softc *adp;
    int32_t lun = UNIT(dev);
    int32_t error = 0;

    if (lun >= adnlun || !(adp = adtab[lun]))
        return ENXIO;

    ad_sleep(adp, "adioct");
    error = dsioctl("sd", dev, cmd, addr, flags, &adp->slices, 
		    ad_strategy, (ds_setgeom_t *)NULL);

    if (error != ENOIOCTL)
        return error;
    return ENOTTY;
}

static int32_t
adpsize(dev_t dev)
{
    struct ad_softc *adp;
    int32_t lun = UNIT(dev);

    if (lun >= adnlun || !(adp = adtab[lun]))
        return -1;
    return (dssize(dev, &adp->slices, adopen, adclose));
}

static void 
adstrategy(struct buf *bp)
{
    struct ad_softc *adp;
    int32_t lun = UNIT(bp->b_dev);
    int32_t s;

#ifdef AD_DEBUG
printf("adstrategy: entered\n");
#endif
    if (lun >= adnlun ||  bp->b_blkno < 0 || !(adp = adtab[lun]) 
	|| bp->b_bcount % DEV_BSIZE != 0) {
        bp->b_error = EINVAL; 
        bp->b_flags |= B_ERROR;
        goto done;
    }

    if (dscheck(bp, adp->slices) <= 0)
        goto done;

    s = splbio();

    /* hang around if somebody else is labelling */
    if (adp->flags & AD_F_LABELLING)
        ad_sleep(adp, "adlab");

    bufqdisksort(&adp->queue, bp);

    if (!adp->active)
	ad_start(adp);

    if (!adp->controller->active)
	ata_start(adp->controller);

    devstat_start_transaction(&adp->stats);

    splx(s);
    return;

done:                           
    s = splbio();   
    biodone(bp);
    splx(s);
}

static void 
ad_strategy(struct buf *bp)
{
    adstrategy(bp);
}

static void
ad_start(struct ad_softc *adp)
{
    struct buf *bp;

#ifdef AD_DEBUG
printf("ad_start:\n");
#endif
    /* newer called when adp->active != 0 SOS */
    if (adp->active)
	return;

    if (!(bp = bufq_first(&adp->queue)))
        return;

    bp->b_driver1 = adp;
    bufq_remove(&adp->queue, bp); 

    /* link onto controller queue */
    bufq_insert_tail(&adp->controller->ata_queue, bp);

    /* mark the drive as busy */
    adp->active = 1;
}

void
ad_transfer(struct buf *bp)
{
    struct ad_softc *adp;
    u_int32_t blknum, secsprcyl;
    u_int32_t cylinder, head, sector, count, command;

    /* get request params */
    adp = bp->b_driver1;

    /* calculate transfer details */
    blknum = bp->b_pblkno + (adp->donecount / DEV_BSIZE);
   
#ifdef AD_DEBUG
        printf("ad_transfer: blknum=%d\n", blknum);
#endif
    if (adp->donecount == 0) {

	/* setup transfer parameters */
        adp->bytecount = bp->b_bcount;
        secsprcyl = adp->sectors * adp->heads;
        cylinder = blknum / secsprcyl;
        head = (blknum % secsprcyl) / adp->sectors;
        sector = blknum % adp->sectors;
	count = howmany(adp->bytecount, DEV_BSIZE);

	if (count > 255) /* SOS */
            printf("ad_transfer: count=%d\n", count);


	/* setup transfer length if multible sector access present */
     	adp->currentsize = min(adp->bytecount, adp->transfersize);
	if (adp->currentsize > DEV_BSIZE)
	    command = (bp->b_flags&B_READ) ? ATA_C_READ_MULTI:ATA_C_WRITE_MULTI;
	else
	    command = (bp->b_flags&B_READ) ? ATA_C_READ : ATA_C_WRITE;

        /* ready to issue command ? */
        while (ata_wait(adp->controller, 0) < 0) {
            printf("ad_transfer: timeout waiting to give command");
            /*ata_unwedge(adp->controller); SOS */
        }                       

        outb(adp->controller->ioaddr + ATA_DRIVE, ATA_D_IBM | adp->unit | head);
        outb(adp->controller->ioaddr + ATA_PRECOMP, 0);	/* no precompensation */
        outb(adp->controller->ioaddr + ATA_CYL_LSB, cylinder);
        outb(adp->controller->ioaddr + ATA_CYL_MSB, cylinder >> 8);
        outb(adp->controller->ioaddr + ATA_SECTOR, sector + 1);
        outb(adp->controller->ioaddr + ATA_COUNT, count);
/*
        if (ata_wait(adp->controller, ATA_S_DRDY) < 0) 
	    printf("ad_transfer: timeout waiting to send command");
*/
        outb(adp->controller->ioaddr + ATA_CMD, command);
    }
   
    /* if this is a read operation, return and wait for interrupt */
    if (bp->b_flags & B_READ) {
#ifdef AD_DEBUG
    printf("ad_transfer: return waiting to read data\n");
#endif
        return;
    }

    /* ready to write data ? */
    if (ata_wait(adp->controller, ATA_S_DRDY | ATA_S_DSC | ATA_S_DRQ) < 0) {
        printf("ad_transfer: timeout waiting for DRQ");
    }                               

    /* calculate transfer length */
    adp->currentsize = min(adp->bytecount, adp->transfersize);
    
    /* output the data */
#if 0
    outsw(adp->controller->ioaddr + ATA_DATA,
          (void *)((int32_t)bp->b_data + adp->donecount),
          adp->currentsize / sizeof(int16_t));
#else
    outsl(adp->controller->ioaddr + ATA_DATA,
          (void *)((int32_t)bp->b_data + adp->donecount),
          adp->currentsize / sizeof(int32_t));
#endif
    adp->bytecount -= adp->currentsize;
#ifdef AD_DEBUG
    printf("ad_transfer: return wrote data\n");
#endif
}

void
ad_interrupt(struct buf *bp)
{
    struct ad_softc *adp = bp->b_driver1;

    /* finish DMA stuff */

    /* get drive status */
    if (ata_wait(adp->controller, 0) < 0)
        printf("ad_interrupt: timeout waiting for status");

    if (adp->controller->status & (ATA_S_ERROR | ATA_S_CORR)) {
oops:
	printf("ad%d: status=%02x error=%02x\n", 
	       adp->unit, adp->controller->status, adp->controller->error);
	if (adp->controller->status & ATA_S_ERROR) {
       	    printf("ad_interrupt: hard error"); 
            bp->b_error = EIO;
            bp->b_flags |= B_ERROR;
	}
	if (adp->controller->status & ATA_S_CORR)
       	    printf("ad_interrupt: soft ECC"); 
    }
    /* if this was a read operation, get the data */
    if (((bp->b_flags & (B_READ | B_ERROR)) == B_READ) && adp->active) {

        /* ready to receive data? */
        if ((adp->controller->status & (ATA_S_DRDY | ATA_S_DSC | ATA_S_DRQ))
            != (ATA_S_DRDY | ATA_S_DSC | ATA_S_DRQ))
            printf("ad_interrupt: read interrupt arrived early");

        if (ata_wait(adp->controller, ATA_S_DRDY | ATA_S_DSC | ATA_S_DRQ) != 0){
            printf("ad_interrupt: read error detected late");
            goto oops;   
        }

    	/* calculate transfer length */
     	adp->currentsize = min(adp->bytecount, adp->currentsize);

        /* data are ready, get them  */
#if 0
        insw(adp->controller->ioaddr + ATA_DATA,
             (void *)((int32_t)bp->b_data + adp->donecount), 
	     adp->currentsize / sizeof(int16_t));
#else
        insl(adp->controller->ioaddr + ATA_DATA,
             (void *)((int32_t)bp->b_data + adp->donecount), 
	     adp->currentsize / sizeof(int32_t));
#endif
        adp->bytecount -= adp->currentsize;
#ifdef AD_DEBUG
    printf("ad_interrupt: read in data\n");
#endif
    }

    /* finish up this tranfer, check for more work on this buffer */
    if (adp->controller->active) {
	if ((bp->b_flags & B_ERROR) == 0) {
	    adp->donecount += adp->currentsize;
#ifdef AD_DEBUG
    printf("ad_interrupt: %s operation OK\n", (bp->b_flags & B_READ)?"R":"W");
#endif
	    if (adp->bytecount > 0) {
	        ad_transfer(bp);		/* MESSY!! only needed for W */
		return;
	    }
	}
	bufq_remove(&adp->controller->ata_queue, bp);
	bp->b_resid = bp->b_bcount - adp->donecount;
	adp->donecount = 0;
        devstat_end_transaction(&adp->stats, bp->b_bcount - bp->b_resid,
                                DEVSTAT_TAG_NONE,
                                (bp->b_flags & B_READ) ? 
				DEVSTAT_READ : DEVSTAT_WRITE);
	biodone(bp);
	adp->active = 0;
    }
    adp->controller->active = ATA_IDLE;
    ad_start(adp);
#ifdef AD_DEBUG
    printf("ad_interrupt: completed\n");
#endif
    ata_start(adp->controller);
}

static void
ad_sleep(struct ad_softc *adp, int8_t *mesg)
{
    int32_t s = splbio();  

    while (adp->controller->active)
        tsleep((caddr_t)&adp->controller->active, PZERO - 1, mesg, 1);
    splx(s);
}

static int32_t
ad_command(struct ad_softc *adp, u_int32_t command,
	   u_int32_t cylinder, u_int32_t head, u_int32_t sector, 
	   u_int32_t count)
{
    /* ready to issue command ? */ 
    while (ata_wait(adp->controller, 0) < 0) {
        printf("ad_transfer: timeout waiting to give command");
	return -1;
    }

    outb(adp->controller->ioaddr + ATA_DRIVE, ATA_D_IBM | adp->unit | head);
    outb(adp->controller->ioaddr + ATA_PRECOMP, 0); /* no precompensation */
    outb(adp->controller->ioaddr + ATA_CYL_LSB, cylinder);
    outb(adp->controller->ioaddr + ATA_CYL_MSB, cylinder >> 8);
    outb(adp->controller->ioaddr + ATA_SECTOR, sector + 1);
    outb(adp->controller->ioaddr + ATA_COUNT, count);
/*
    if (ata_wait(adp->controller, ATA_S_DRDY) < 0) {
        printf("ad_transfer: timeout waiting to send command");
	return -1;
    }
*/  
    adp->controller->active = ATA_IGNORE_INTR;
    outb(adp->controller->ioaddr + ATA_CMD, command);
    return 0;
}

static int8_t
ad_version(u_int16_t version)
{
    int32_t bit;

    if (version == 0xffff)
	return '?';
    for (bit = 15; bit >= 0; bit--)
	if (version & (1<<bit))
	    return ('0' + bit);
    return '?';
}

static void 
ad_drvinit(void)
{
    static ad_devsw_installed = 0;

    if (!ad_devsw_installed) {
        cdevsw_add_generic(BDEV_MAJOR, CDEV_MAJOR, &ad_cdevsw);
        ad_devsw_installed = 1;
    }
    /* register callback for when interrupts are enabled */
    if (!(ad_attach_hook = 
	(struct intr_config_hook *)malloc(sizeof(struct intr_config_hook),
                                          M_TEMP, M_NOWAIT))) {
	printf("ad: malloc attach_hook failed\n");
        return;
    }
    bzero(ad_attach_hook, sizeof(struct intr_config_hook));

    ad_attach_hook->ich_func = ad_attach;
    if (config_intrhook_establish(ad_attach_hook) != 0) {
        printf("ad: config_intrhook_establish failed\n");
        free(ad_attach_hook, M_TEMP);
    }
}

SYSINIT(addev, SI_SUB_DRIVERS, SI_ORDER_SECOND, ad_drvinit, NULL)
#endif /* NATA && NATADISK */
