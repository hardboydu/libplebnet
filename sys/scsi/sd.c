/*
 * Written by Julian Elischer (julian@dialix.oz.au)
 * for TRW Financial Systems for use under the MACH(2.5) operating system.
 *
 * TRW Financial Systems, in accordance with their agreement with Carnegie
 * Mellon University, makes this software available to CMU to distribute
 * or use in any manner that they see fit as long as this message is kept with
 * the software. For this reason TFS also grants any other persons or
 * organisations permission to use or modify this software.
 *
 * TFS supplies this software to be publicly redistributed
 * on the understanding that TFS is not responsible for the correct
 * functioning of this software in any circumstances.
 *
 * Ported to run under 386BSD by Julian Elischer (julian@dialix.oz.au) Sept 1992
 *
 *      $Id: sd.c,v 1.128 1998/05/07 02:05:21 julian Exp $
 */

#include "opt_bounce.h"
#include "opt_devfs.h"
#include "opt_hw_wdog.h"
#include "opt_scsi.h"

#define SPLSD splbio
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/dkbad.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include <sys/dkstat.h>
#include <sys/conf.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#ifdef SLICE
#include <sys/device.h>
#include <sys/fcntl.h>
#include <dev/slice/slice.h>
#endif	/* SLICE */
#endif	/* DEVFS */

#include <scsi/scsi_disk.h>
#include <scsi/scsiconf.h>
#include <scsi/scsi_debug.h>
#include <scsi/scsi_driver.h>

#include <vm/vm.h>
#include <vm/vm_prot.h>
#include <vm/pmap.h>
#include <machine/md_var.h>
#include <i386/i386/cons.h>		/* XXX *//* for aborting dump */
#ifdef PC98
#include <pc98/pc98/pc98_machdep.h>
#endif

static u_int32_t sdstrats, sdqueues;

#define SECSIZE 512
#ifdef PC98
#define	SDOUTSTANDING	2
#else
#define	SDOUTSTANDING	4
#endif
#define	SD_RETRIES	4
#define	MAXTRANSFER	8		/* 1 page at a time */

#define	PARTITION(dev)	dkpart(dev)
#define	SDUNIT(dev)	dkunit(dev)

/* XXX introduce a dkmodunit() macro for this. */
#define SDSETUNIT(DEV, U) \
 makedev(major(DEV), dkmakeminor((U), dkslice(DEV), dkpart(DEV)))

static errval	sd_get_parms __P((int unit, int flags));
#if 0
static errval	sd_reassign_blocks __P((int unit, int block));
#endif
static int sd_size(int unit, u_int32_t *sizep, u_int16_t *secsizep,  int flags);
static	void	sdstrategy1 __P((struct buf *));

static int		sd_sense_handler __P((struct scsi_xfer *));
static void    sdstart __P((u_int32_t, u_int32_t));

struct scsi_data {
	u_int32_t flags;
#define	SDINIT		0x04	/* device has been init'd */
	struct disk_parms {
		u_char		heads;		/* Number of heads */
		u_int16_t	cyls;		/* Number of cylinders */
		u_char		sectors;/*XXX*/	/* Number of sectors/track */
		u_int16_t	secsiz;		/* Number of bytes/sector */
		u_int32_t	disksize;	/* total number sectors */
	} params;
	struct diskslices	*dk_slices;	/* virtual drives */
	struct buf_queue_head	buf_queue;
	int			dkunit;		/* disk stats unit number */
#ifdef	DEVFS
#ifdef SLICE
	struct slice		*slice;
	int			mynor;
	struct slicelimits	limit;
	struct scsi_link	*sc_link;
	int			unit;
	struct intr_config_hook	ich;
#else	/* SLICE */
	void			*b_devfs_token;
	void			*c_devfs_token;
#endif	/* SLICE */
	void			*ctl_devfs_token;
#endif
};


#ifndef	SLICE
static int sdunit(dev_t dev) { return SDUNIT(dev); }
static dev_t sdsetunit(dev_t dev, int unit) { return SDSETUNIT(dev, unit); }
static errval sd_open __P((dev_t dev, int mode, int fmt, struct proc *p,
			struct scsi_link *sc_link));
static errval sd_ioctl(dev_t dev, int cmd, caddr_t addr, int flag,
			struct proc *p, struct scsi_link *sc_link);
static errval sd_close __P((dev_t dev, int flag, int fmt, struct proc *p,
			struct scsi_link *sc_link));
static void sd_strategy(struct buf *bp, struct scsi_link *sc_link);

static	d_open_t	sdopen;
static	d_close_t	sdclose;
static	d_ioctl_t	sdioctl;
static	d_dump_t	sddump;
static	d_psize_t	sdsize;
static	d_strategy_t	sdstrategy;

#define CDEV_MAJOR 13
#define BDEV_MAJOR 4
static struct cdevsw sd_cdevsw;
static struct bdevsw sd_bdevsw = 
	{ sdopen,	sdclose,	sdstrategy,	sdioctl,	/*4*/
	  sddump,	sdsize,		D_DISK,	"sd",	&sd_cdevsw,	-1 };
#else	/* ! SLICE */

static errval sdattach(struct scsi_link *sc_link);
static sl_h_IO_req_t	sdsIOreq;	/* IO req downward (to device) */
static sl_h_ioctl_t	sdsioctl;	/* ioctl req downward (to device) */
static sl_h_open_t	sdsopen;	/* downwards travelling open */
static sl_h_close_t	sdsclose;	/* downwards travelling close */
static	void	sds_init (void *arg);
static sl_h_dump_t	sdsdump;	/* core dump req downward */

static struct slice_handler slicetype = {
	"scsidisk",
	0,
	NULL,
	0,
	NULL,	/* constructor */
	&sdsIOreq,
	&sdsioctl,
	&sdsopen,
	NULL,	/* was close, now free */
	NULL,	/* revoke */
	NULL,	/* claim */
	NULL,	/* verify */
	NULL,	/* upconfig */
	&sdsdump
};
#endif


#ifndef SLICE

SCSI_DEVICE_ENTRIES(sd)

static struct scsi_device sd_switch =
{
	sd_sense_handler,
	sdstart,			/* have a queue, served by this */
	NULL,			/* have no async handler */
	NULL,			/* Use default 'done' routine */
	"sd",
	0,
	{0, 0},
	0,				/* Link flags */
	sdattach,
	"Direct-Access",
	sdopen,
	sizeof(struct scsi_data),
	T_DIRECT,
	sdunit,
	sdsetunit,
	sd_open,
	sd_ioctl,
	sd_close,
	sd_strategy,
};
#else	/* SLICE */
static struct scsi_device sd_switch =
{
	sd_sense_handler,
	sdstart,			/* have a queue, served by this */
	NULL,			/* have no async handler */
	NULL,			/* Use default 'done' routine */
	"sd",
	0,
	{0, 0},
	0,				/* Link flags */
	sdattach,
	"Direct-Access",
	NULL,
	sizeof(struct scsi_data),
	T_DIRECT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};


/* this should be called by the SYSINIT (?!) */
void
sdinit(void) 
{
	scsi_device_register(&sd_switch);
}

#endif	/* SLICE */
static struct scsi_xfer sx;


static __inline void
sd_registerdev(int unit)
{
	if(dk_ndrive < DK_NDRIVE) {
		sprintf(dk_names[dk_ndrive], "sd%d", unit);
		dk_wpms[dk_ndrive] = (8*1024*1024/2);
		SCSI_DATA(&sd_switch, unit)->dkunit = dk_ndrive++;
	} else {
		SCSI_DATA(&sd_switch, unit)->dkunit = -1;
	}
}


/*
 * The routine called by the low level scsi routine when it discovers
 * a device suitable for this driver.
 */
static errval
sdattach(struct scsi_link *sc_link)
{
	u_int32_t unit;
	struct disk_parms *dp;
#ifdef DEVFS
	int	mynor;
#endif

	struct scsi_data *sd = sc_link->sd;

	unit = sc_link->dev_unit;

	dp = &(sd->params);

	if (sc_link->opennings > SDOUTSTANDING)
		sc_link->opennings = SDOUTSTANDING;

	bufq_init(&sd->buf_queue);
	/*
	 * In case it is a funny one, tell it to start
	 * not needed for  most hard drives (ignore failure)
	 */
	scsi_start_unit(sc_link,
			SCSI_ERR_OK | SCSI_SILENT | SCSI_NOSLEEP | SCSI_NOMASK);
	/*
	 * Use the subdriver to request information regarding
	 * the drive. We cannot use interrupts yet, so the
	 * request must specify this. This may fail with removable media.
	 */
	if (sd_get_parms(unit, SCSI_NOSLEEP | SCSI_NOMASK) == 0) {
		/*
		 * if we don't have actual parameters, assume 512 bytes/sec
		 * (could happen on removable media - MOD)
		 * -- this avoids the division below from falling over
	 	 */
		printf("%ldMB (%ld %d byte sectors)",
		    dp->disksize / ((1024L * 1024L) / dp->secsiz),
		    dp->disksize,
		    dp->secsiz);

#ifndef SCSI_REPORT_GEOMETRY
		if ( (sc_link->flags & SDEV_BOOTVERBOSE) )
#endif
		{
			sc_print_addr(sc_link);
			printf("with %d cyls, %d heads, and an average %d sectors/track",
	   		dp->cyls, dp->heads, dp->sectors);
		}
	} else {
		printf("Media parameters not available");
	}
	sd->flags |= SDINIT;
	sd_registerdev(unit);

#ifdef DEVFS
#ifdef SLICE
	{
		char namebuf[64];
		sd->unit = unit;
		sd->sc_link = sc_link;
		sprintf(namebuf,"sd%d",sd->unit);
		sd->mynor = dkmakeminor(unit, WHOLE_DISK_SLICE, RAW_PART);
		sd->limit.blksize = sd->params.secsiz;
		/* need to cast to avoid overflow! */
		sd->limit.slicesize =
		  (u_int64_t)sd->params.secsiz * sd->params.disksize;
		sl_make_slice(&slicetype,
				sd,
				&sd->limit,
	 			&sd->slice,
				NULL,
				namebuf);
		/* Allow full probing */
		sd->slice->probeinfo.typespecific = NULL;
		sd->slice->probeinfo.type = NULL;
	}
	sd->ich.ich_func = sds_init;
	sd->ich.ich_arg = sd;
	config_intrhook_establish(&sd->ich);
#else	/* SLICE */
	mynor = dkmakeminor(unit, WHOLE_DISK_SLICE, RAW_PART);
	sd->b_devfs_token = devfs_add_devswf(&sd_bdevsw, mynor, DV_BLK,
					     UID_ROOT, GID_OPERATOR, 0640,
					     "sd%d", unit);
	sd->c_devfs_token = devfs_add_devswf(&sd_cdevsw, mynor, DV_CHR,
					     UID_ROOT, GID_OPERATOR, 0640,
					     "rsd%d", unit);
	mynor = dkmakeminor(unit, 0, 0);	/* XXX */
	sd->ctl_devfs_token = devfs_add_devswf(&sd_cdevsw,
					       mynor | SCSI_CONTROL_MASK,
					       DV_CHR,
					       UID_ROOT, GID_WHEEL, 0600,
					       "rsd%d.ctl", unit);
#endif	/* SLICE */
#endif
	return 0;
}

#ifdef SLICE
/* run a LOT later */
static void
sds_init(void *arg)
{
	struct scsi_data *sd = arg;
	sh_p	tp;

	if ((tp = slice_probeall(sd->slice)) != NULL) {
		(*tp->constructor)(sd->slice);
	}
	config_intrhook_disestablish(&sd->ich);
}
#endif	/* SLICE */

/*
 * open the device. Make sure the partition info is a up-to-date as can be.
 */
#ifdef	SLICE
static int
sdsopen(void *private, int flags, int mode, struct proc *p)
#else /* !SLICE */
static errval
sd_open(dev_t dev, int mode, int fmt, struct proc *p, struct scsi_link *sc_link)
#endif
{
#ifdef	SLICE
	errval  errcode = 0;
	struct scsi_data *sd = private;
	struct scsi_link *sc_link = sd->sc_link;
	u_int32_t unit = sd->unit;

	if ((flags & (FREAD|FWRITE)) == 0) {
		/* Mode chenge to mode 0 (closed) */
		errcode = scsi_device_lock(sc_link);
		if (errcode) {
			return errcode;	/* how can close fail? */
		}
		scsi_prevent(sc_link, PR_ALLOW, SCSI_SILENT | SCSI_ERR_OK);
		sc_link->flags &= ~SDEV_OPEN;
		scsi_device_unlock(sc_link);
		return (0);
	}
#else	/* !SLICE */
	errval  errcode = 0;
	u_int32_t unit;
	struct disklabel label;
	struct scsi_data *sd;

	unit = SDUNIT(dev);
	sd = sc_link->sd;
#endif	/* !SLICE */

	/*
	 * Make sure the disk has been initialised
	 * At some point in the future, get the scsi driver
	 * to look for a new device if we are not initted
	 */
	if ((!sd) || (!(sd->flags & SDINIT))) {
		return (ENXIO);
	}

#ifdef	SLICE
	SC_DEBUG(sc_link, SDEV_DB1, ("sdsopen: (unit %ld)\n", unit));
#else	/* !SLICE */
	SC_DEBUG(sc_link, SDEV_DB1,
	    ("sd_open: dev=0x%lx (unit %ld, partition %d)\n",
		dev, unit, PARTITION(dev)));
#endif	/* !SLICE */

	/*
	 * "unit attention" errors should occur here if the
	 * drive has been restarted or the pack changed.
	 * just ingnore the result, it's a decoy instruction
	 * The error handlers will act on the error though
	 * and invalidate any media information we had.
	 */
	scsi_test_unit_ready(sc_link, 0);

	errcode = scsi_device_lock(sc_link);
	if (errcode)
		return errcode;

	/*
	 * If it's been invalidated, then forget the label
	 */
	sc_link->flags |= SDEV_OPEN;	/* unit attn becomes an err now */
	if (!(sc_link->flags & SDEV_MEDIA_LOADED) && sd->dk_slices != NULL) {
#ifndef	SLICE
		/*
		 * If somebody still has it open, then forbid re-entry.
		 */
		if (dsisopen(sd->dk_slices)) {
			errcode = ENXIO;
			goto close;
		}

		dsgone(&sd->dk_slices);
#endif /* !SLICE */
	}

	/*
	 * Check that it is still responding and ok.
	 */
	if (scsi_test_unit_ready(sc_link, 0)) {
		SC_DEBUG(sc_link, SDEV_DB3, ("device not reponding\n"));
		errcode = ENXIO;
		goto close;
	}
	SC_DEBUG(sc_link, SDEV_DB3, ("device ok\n"));

	/*
	 * Load the physical device parameters
	 */
	if(errcode = sd_get_parms(unit, 0))	/* sets SDEV_MEDIA_LOADED */
		goto close;

	SC_DEBUG(sc_link, SDEV_DB3, ("Params loaded "));

	/* Lock the pack in. */
	scsi_prevent(sc_link, PR_PREVENT, SCSI_ERR_OK | SCSI_SILENT);

#ifndef	SLICE
	/* Build label for whole disk. */
	bzero(&label, sizeof label);
	label.d_secsize = sd->params.secsiz;
	label.d_nsectors = sd->params.sectors;
	label.d_ntracks = sd->params.heads;
	label.d_ncylinders = sd->params.cyls;
	label.d_secpercyl = sd->params.heads * sd->params.sectors;
	if (label.d_secpercyl == 0)
		label.d_secpercyl = 100;
		/* XXX as long as it's not 0 - readdisklabel divides by it (?) */
	label.d_secperunit = sd->params.disksize;

	/* Initialize slice tables. */
	errcode = dsopen("sd", dev, fmt, &sd->dk_slices, &label, sdstrategy1,
			 (ds_setgeom_t *)NULL, &sd_bdevsw, &sd_cdevsw);
	if (errcode != 0)
		goto close;
#endif	/* !SLICE */
	SC_DEBUG(sc_link, SDEV_DB3, ("Slice tables initialized "));

	SC_DEBUG(sc_link, SDEV_DB3, ("open %ld %ld\n", sdstrats, sdqueues));

	scsi_device_unlock(sc_link);
	return 0;

close:
#ifndef	SLICE
	if (!dsisopen(sd->dk_slices))
#else
	if((sd->slice->flags & SLF_OPEN_STATE) == SLF_CLOSED)
#endif
	{
		scsi_prevent(sc_link, PR_ALLOW, SCSI_ERR_OK | SCSI_SILENT);
		sc_link->flags &= ~SDEV_OPEN;
	}
	scsi_device_unlock(sc_link);
	return errcode;
}

#ifndef	SLICE
/*
 * close the device.. only called if we are the LAST occurence of an open
 * device.  Convenient now but usually a pain.
 */
static errval
sd_close(dev_t dev,int mode, int fmt, struct proc *p, struct scsi_link *sc_link)
{
	struct scsi_data *sd;
	errval errcode;

	sd = sc_link->sd;
	errcode = scsi_device_lock(sc_link);
	if (errcode)
		return errcode;
	dsclose(dev, fmt, sd->dk_slices);
	if (!dsisopen(sd->dk_slices)) {
		scsi_prevent(sc_link, PR_ALLOW, SCSI_SILENT | SCSI_ERR_OK);
		sc_link->flags &= ~SDEV_OPEN;
	}
	scsi_device_unlock(sc_link);
	return (0);
}

/*
 * Actually translate the requested transfer into one the physical driver
 * can understand.  The transfer is described by a buf and will include
 * only one physical transfer.
 */
static void
sd_strategy(struct buf *bp, struct scsi_link *sc_link)
{
	u_int32_t opri;
	struct scsi_data *sd;
	u_int32_t unit, secsize;

	sdstrats++;
	unit = SDUNIT((bp->b_dev));
	sd = sc_link->sd;
	/*
	 * If the device has been made invalid, error out
	 */
	if (!(sc_link->flags & SDEV_MEDIA_LOADED)) {
		bp->b_error = EIO;
		goto bad;
	}

	/*
	 * check it's not too big a transfer for our adapter
	 */
        scsi_minphys(bp,&sd_switch);

	/*
	 * Odd number of bytes or negative offset
	 */
	if (bp->b_blkno < 0 ) {
		bp->b_error = EINVAL;
		printf("sd_strategy: Negative block number: 0x%x\n",
			bp->b_blkno);
		goto bad;
	}

	secsize = sd->params.secsiz;

	/* make sure the blkno is scalable */
	if( (bp->b_blkno % (secsize/DEV_BSIZE)) != 0 ) {
		bp->b_error = EINVAL;
		printf("sd_strategy: Block number is not multiple of sector size (2): 0x%x\n", bp->b_blkno);
		goto bad;
	}

	/* make sure that the transfer size is a multiple of the sector size */
	if( (bp->b_bcount % secsize) != 0 ) {
		bp->b_error = EINVAL;
		printf("sd_strategy: Invalid b_bcount %d at block number: 0x%x\n", bp->b_bcount, bp->b_blkno);
		goto bad;
	}

	/*
	 * Do bounds checking, adjust transfer, set b_cylin and b_pbklno.
	 */
	{
		int status;
		int sec_blk_ratio = secsize/DEV_BSIZE;
		int b_blkno = bp->b_blkno;

		/* Replace blkno and count with scaled values. */
		bp->b_blkno /= sec_blk_ratio;
		bp->b_bcount /= sec_blk_ratio;
	
		/* enforce limits and map to physical block number */
		status = dscheck(bp, sd->dk_slices);

		/*
		 * Restore blkno and unscale the values set by dscheck(),
		 * except for b_pblkno.
		 */
		bp->b_blkno = b_blkno;
		bp->b_bcount *= sec_blk_ratio;
		bp->b_resid *= sec_blk_ratio;

		/* see if the mapping failed */
		if (status <= 0)
			goto done;	/* XXX check b_resid */
	}

	opri = SPLSD();
	/*
	 * Use a bounce buffer if necessary
	 */
#ifdef BOUNCE_BUFFERS
	if (sc_link->flags & SDEV_BOUNCE)
		vm_bounce_alloc(bp);
#endif

	/*
	 * Place it in the queue of disk activities for this disk
	 */
#ifdef SDDISKSORT
	bufq_disksort(&sd->buf_queue, bp);
#else
	bufq_insert_tail(&sd->buf_queue, bp);
#endif

	/*
	 * Tell the device to get going on the transfer if it's
	 * not doing anything, otherwise just wait for completion
	 */
	sdstart(unit, 0);

	splx(opri);
	return /*0*/;
bad:
	bp->b_flags |= B_ERROR;
done:

	/*
	 * Correctly set the buf to indicate a completed xfer
	 */
	bp->b_resid = bp->b_bcount;
	biodone(bp);
	return /*0*/;
}

static void
sdstrategy1(struct buf *bp)
{
	/*
	 * XXX - do something to make sdstrategy() but not this block while
	 * we're doing dsinit() and dsioctl().
	 */
	sdstrategy(bp);
}

#endif	/* ! SLICE */
/*
 * sdstart looks to see if there is a buf waiting for the device
 * and that the device is not already busy. If both are true,
 * It dequeues the buf and creates a scsi command to perform the
 * transfer in the buf. The transfer request will call scsi_done
 * on completion, which will in turn call this routine again
 * so that the next queued transfer is performed.
 * The bufs are queued by the strategy routine (sdstrategy)
 *
 * This routine is also called after other non-queued requests
 * have been made of the scsi driver, to ensure that the queue
 * continues to be drained.
 *
 * must be called at the correct (highish) spl level
 * sdstart() is called at SPLSD  from sdstrategy and scsi_done
 */
static void
sdstart(u_int32_t unit, u_int32_t flags)
{
	register struct	scsi_link *sc_link = SCSI_LINK(&sd_switch, unit);
	register struct scsi_data *sd = sc_link->sd;
	struct buf *bp = NULL;
	struct scsi_rw_big cmd;
	u_int32_t blkno, nblk, secsize;

	SC_DEBUG(sc_link, SDEV_DB2, ("sdstart "));
	/*
	 * Check if the device has room for another command
	 */
	while (sc_link->opennings) {

		/*
		 * there is excess capacity, but a special waits
		 * It'll need the adapter as soon as we clear out of the
		 * way and let it run (user level wait).
		 */
		if (sc_link->flags & SDEV_WAITING) {
			return;
		}
		/*
		 * See if there is a buf with work for us to do..
		 */
		bp = bufq_first(&sd->buf_queue);
		if (bp == NULL) {	/* yes, an assign */
			return;
		}
		bufq_remove(&sd->buf_queue, bp);

		/*
		 *  If the device has become invalid, abort all the
		 * reads and writes until all files have been closed and
		 * re-openned
		 */
		if (!(sc_link->flags & SDEV_MEDIA_LOADED)) {
			goto bad;
		}
		/*
		 * We have a buf, now we know we are going to go through
		 * With this thing..
		 */
		secsize = sd->params.secsiz;
		blkno = bp->b_pblkno;
		if (bp->b_bcount & (secsize - 1))
		{
		    goto bad;
		}
		nblk = bp->b_bcount / secsize;

		/*
		 *  Fill out the scsi command
		 */
		cmd.op_code = (bp->b_flags & B_READ)
		    ? READ_BIG : WRITE_BIG;
		cmd.addr_3 = (blkno & 0xff000000UL) >> 24;
		cmd.addr_2 = (blkno & 0xff0000) >> 16;
		cmd.addr_1 = (blkno & 0xff00) >> 8;
		cmd.addr_0 = blkno & 0xff;
		cmd.length2 = (nblk & 0xff00) >> 8;
		cmd.length1 = (nblk & 0xff);
		cmd.byte2 = cmd.reserved = cmd.control = 0;
		/*
		 * Call the routine that chats with the adapter.
		 * Note: we cannot sleep as we may be an interrupt
		 */
		if (scsi_scsi_cmd(sc_link,
			(struct scsi_generic *) &cmd,
			sizeof(cmd),
			(u_char *) bp->b_data,
			bp->b_bcount,
			SD_RETRIES,
			10000,
			bp,
			flags | ((bp->b_flags & B_READ) ?
			    SCSI_DATA_IN : SCSI_DATA_OUT))
		    == SUCCESSFULLY_QUEUED) {
			sdqueues++;
			if(sd->dkunit >= 0) {
				dk_xfer[sd->dkunit]++;
				dk_seek[sd->dkunit]++; /* don't know */
				dk_wds[sd->dkunit] += bp->b_bcount >> 6;
			}
		} else {
bad:
			printf("sd%ld: oops not queued\n", unit);
			bp->b_error = EIO;
			bp->b_flags |= B_ERROR;
			biodone(bp);
		}
	}
}

/*
 * Perform special action on behalf of the user
 * Knows about the internals of this device
 */
#ifdef	SLICE
static int
sdsioctl( void *private, int cmd, caddr_t addr, int flag, struct proc *p)
#else	/* SLICE */
static errval
sd_ioctl(dev_t dev, int cmd, caddr_t addr, int flag, struct proc *p,
	 struct scsi_link *sc_link)
#endif	/* !SLICE */
{
#ifdef	SLICE
	struct scsi_data *sd = private;
	struct scsi_link *sc_link = sd->sc_link;
	dev_t dev = makedev(0,sd->mynor);

#else	/* SLICE */
	errval  error;
	struct scsi_data *sd = sc_link->sd;
#endif	/* !SLICE */
	SC_DEBUG(sc_link, SDEV_DB1, ("sdioctl (0x%x)", cmd));

#if 0
	/* Wait until we have exclusive access to the device. */
	/* XXX this is how wd does it.  How did we work without this? */
	sdsleep(du->dk_ctrlr, "wdioct");
#endif

	/*
	 * If the device is not valid.. abandon ship
	 */
	if (!(sc_link->flags & SDEV_MEDIA_LOADED))
		return (EIO);

	if (cmd == DIOCSBAD)
		return (EINVAL);	/* XXX */
	
#ifndef	SLICE
	error = scsi_device_lock(sc_link);
	if (error)
		return error;
	error = dsioctl("sd", dev, cmd, addr, flag, &sd->dk_slices,
			sdstrategy1, (ds_setgeom_t *)NULL);
	scsi_device_unlock(sc_link);
	if (error != ENOIOCTL)
		return (error);
	if (PARTITION(dev) != RAW_PART)
		return (ENOTTY);
#endif	/* ! SLICE */ /* really only take this from the ctl device XXX */
	return (scsi_do_ioctl(dev, cmd, addr, flag, p, sc_link));
}

/*
 * Find out from the device what its capacity is. It turns
 * out this is also the best way to find out the sector size.
 */
static int
sd_size(int unit, u_int32_t *sizep, u_int16_t *secsizep,  int flags)
{
	struct scsi_read_cap_data rdcap;
	struct scsi_read_capacity scsi_cmd;
	u_int32_t size;
	u_int32_t secsize;
	struct scsi_link *sc_link = SCSI_LINK(&sd_switch, unit);

	/*
	 * make up a scsi command and ask the scsi driver to do
	 * it for you.
	 */
	bzero(&scsi_cmd, sizeof(scsi_cmd));
	scsi_cmd.op_code = READ_CAPACITY;

	/*
	 * If the command works, interpret the result as a 4 byte
	 * number of blocks
	 */
	if (scsi_scsi_cmd(sc_link,
		(struct scsi_generic *) &scsi_cmd,
		sizeof(scsi_cmd),
		(u_char *) & rdcap,
		sizeof(rdcap),
		SD_RETRIES,
		2000,
		NULL,
		flags | SCSI_DATA_IN) != 0) {
		printf("sd%d: could not get size\n", unit);
		return (ENXIO);
	}
	size = rdcap.addr_0 + 1;
	size += rdcap.addr_1 << 8;
	size += rdcap.addr_2 << 16;
	size += rdcap.addr_3 << 24;
	secsize = rdcap.length_0;
	secsize += rdcap.length_1 << 8;
	secsize += rdcap.length_2 << 16;
	secsize += rdcap.length_3 << 24;
	*secsizep = secsize;
	*sizep = size;
	return (0);
}

#if 0
/*
 * Tell the device to map out a defective block
 */
static errval
sd_reassign_blocks(unit, block)
	int	unit, block;
{
	struct scsi_reassign_blocks scsi_cmd;
	struct scsi_reassign_blocks_data rbdata;
	struct scsi_link *sc_link = SCSI_LINK(&sd_switch, unit);

	bzero(&scsi_cmd, sizeof(scsi_cmd));
	bzero(&rbdata, sizeof(rbdata));
	scsi_cmd.op_code = REASSIGN_BLOCKS;

	rbdata.length_msb = 0;
	rbdata.length_lsb = sizeof(rbdata.defect_descriptor[0]);
	rbdata.defect_descriptor[0].dlbaddr_3 = ((block >> 24) & 0xff);
	rbdata.defect_descriptor[0].dlbaddr_2 = ((block >> 16) & 0xff);
	rbdata.defect_descriptor[0].dlbaddr_1 = ((block >> 8) & 0xff);
	rbdata.defect_descriptor[0].dlbaddr_0 = ((block) & 0xff);

	return (scsi_scsi_cmd(sc_link,
		(struct scsi_generic *) &scsi_cmd,
		sizeof(scsi_cmd),
		(u_char *) & rbdata,
		sizeof(rbdata),
		SD_RETRIES,
		5000,
		NULL,
		SCSI_DATA_OUT));
}
#endif

#define b2tol(a)	(((unsigned)(a##_1) << 8) + (unsigned)a##_0 )

/*
 * Get the scsi driver to send a full inquiry to the
 * device and use the results to fill out the disk
 * parameter structure.
 * Even if we get an error, complete with some dummy information.
 * XXX this is backwards. The read_cap (sd_size()) should be done first.
 */
static errval
sd_get_parms(int unit, int flags)
{
	struct scsi_link *sc_link = SCSI_LINK(&sd_switch, unit);
	struct scsi_data *sd = sc_link->sd;
	struct disk_parms *disk_parms = &sd->params;
	struct scsi_mode_sense scsi_cmd;
	struct scsi_mode_sense_data {
		struct scsi_mode_header header;
		struct blk_desc blk_desc;
		union disk_pages pages;
	} scsi_sense;
	u_int32_t sectors;
	int error = 0;

	/*
	 * First check if we have it all loaded
	 */
	if (sc_link->flags & SDEV_MEDIA_LOADED)
		return 0;

	/*
	 * do a "mode sense page 4"
	 */
	bzero(&scsi_cmd, sizeof(scsi_cmd));
	scsi_cmd.op_code = MODE_SENSE;
	scsi_cmd.page = 4;
	scsi_cmd.length = 0x20;
#ifdef PC98
	if (sd_bios_parms(disk_parms, sc_link)) {
	} else
#endif
	/*
	 * If the command worked, use the results to fill out
	 * the parameter structure
	 */
	if (scsi_scsi_cmd(sc_link,
		(struct scsi_generic *) &scsi_cmd,
		sizeof(scsi_cmd),
		(u_char *) & scsi_sense,
		sizeof(scsi_sense),
		SD_RETRIES,
		4000,
		NULL,
		flags | SCSI_DATA_IN) != 0) {

		printf("sd%d could not mode sense (4).", unit);
		printf(" Using fictitious geometry\n");
		/*
		 * use adaptec standard fictitious geometry
		 * this depends on which controller (e.g. 1542C is
		 * different. but we have to put SOMETHING here..)
		 */
		if (error = sd_size(unit, &sectors, &disk_parms->secsiz, flags)) {
			/* we couldn't get anyhthing. removable? */
			sectors = 32 * 64;
			disk_parms->secsiz= DEV_BSIZE;;
		}
		disk_parms->heads = 64;
		disk_parms->sectors = 32;
		disk_parms->cyls = sectors / (64 * 32);
		disk_parms->disksize = sectors;
	} else {

		SC_DEBUG(sc_link, SDEV_DB3,
		    ("%ld cyls, %d heads, %d precomp, %d red_write, %d land_zone\n",
			scsi_3btou(&scsi_sense.pages.rigid_geometry.ncyl_2),
			scsi_sense.pages.rigid_geometry.nheads,
			b2tol(scsi_sense.pages.rigid_geometry.st_cyl_wp),
			b2tol(scsi_sense.pages.rigid_geometry.st_cyl_rwc),
			b2tol(scsi_sense.pages.rigid_geometry.land_zone)));

		/*
		 * KLUDGE!!(for zone recorded disks)
		 * give a number of sectors so that sec * trks * cyls
		 * is <= disk_size
		 * can lead to wasted space! THINK ABOUT THIS !
		 */
		disk_parms->heads = scsi_sense.pages.rigid_geometry.nheads;
		disk_parms->cyls = scsi_3btou(
				&scsi_sense.pages.rigid_geometry.ncyl_2);
		/* set in a default value */
		disk_parms->secsiz = scsi_3btou(scsi_sense.blk_desc.blklen);

		if (error = sd_size(unit, &sectors,
				&disk_parms->secsiz, flags)) {
			/* we couldn't get anyhthing. removable? */
			sectors = 64 * 32; /* just so non 0 */
		}
		disk_parms->disksize = sectors;
		/* Check if none of these values are zero */
		if(disk_parms->heads && disk_parms->cyls) {
			sectors /= (disk_parms->heads * disk_parms->cyls);
		} else {
			/* set it to something reasonable */
			disk_parms->heads = 64;
			disk_parms->cyls = sectors / (64 * 32);
			sectors = 32;
		}
		/* keep secsiz sane too - we may divide by it later */
		if(disk_parms->secsiz == 0)
			disk_parms->secsiz = SECSIZE;
		disk_parms->sectors = sectors;	/* dubious on SCSI *//*XXX */
	}
	switch (sd->params.secsiz) {
	case 512:
	case 1024:
	case 2048:
		break;
	default:
		printf("sd%ld: Can't deal with %d bytes logical blocks\n",
		    unit, sd->params.secsiz);
		error = ENXIO;
	}
	if (error == 0)
		sc_link->flags |= SDEV_MEDIA_LOADED;
	return (error);
}

#ifndef	SLICE
static int
sdsize(dev_t dev)
{
	struct scsi_data *sd;

	sd = SCSI_DATA(&sd_switch, (u_int32_t) SDUNIT(dev));
	if (sd == NULL)
		return (-1);
	return (dssize(dev, &sd->dk_slices, sdopen, sdclose));
}

#endif	/* ! SLICE */
/*
 * sense handler: Called to determine what to do when the
 * device returns a CHECK CONDITION.
 *
 * This will issue a retry when the device returns a
 * non-media hardware failure.  The CDC-WREN IV does this
 * when you access it during thermal calibrarion, so the drive
 * is pretty useless without this.
 *
 * In general, you probably almost always would like to issue a retry
 * for your disk I/O.  It can't hurt too much (the caller only retries
 * so many times) and it may save your butt.
 */

static int
sd_sense_handler(struct scsi_xfer *xs)
{
	struct scsi_sense_data *sense;
	struct scsi_inquiry_data *inqbuf;

	sense = &(xs->sense);

	/* I don't know what the heck to do with a deferred error,
	 * so I'll just kick it back to the caller.
	 */
	if ((sense->error_code & SSD_ERRCODE) == 0x71)
		return SCSIRET_CONTINUE;

	if (((sense->error_code & SSD_ERRCODE) == 0x70) &&
		((sense->ext.extended.flags & SSD_KEY) == 0x05))
		/* No point in retrying Illegal Requests */
			return SCSIRET_CONTINUE;

	inqbuf = &(xs->sc_link->inqbuf);

	/* It is dangerous to retry on removable drives without
	 * looking carefully at the additional sense code
	 * and sense code qualifier and ensuring the disk hasn't changed:
	 */
	if (inqbuf->dev_qual2 & SID_REMOVABLE)
		return SCSIRET_CONTINUE;

	/* Retry all disk errors.
	 */
	scsi_sense_print(xs);
	if (xs->retries)
		printf(", retries:%d\n", xs->retries);
	else
		printf(", FAILURE\n");

	return SCSIRET_DO_RETRY;
}

/*
 * dump all of physical memory into the partition specified, starting
 * at offset 'dumplo' into the partition.
 * XXX for SLICE starts at argument 'start'.
 */
#ifndef SLICE
static errval
sddump(dev_t dev)
#else
static int
sdsdump(void *private, int32_t start, int32_t num)
#endif /* SLICE */
{				/* dump core after a system crash */
#ifndef SLICE
	struct disklabel *lp;
	int32_t	num;		/* number of sectors to write */
	u_int32_t	unit, part;
	int32_t	nblocks;
	int32_t	blkoff;
	static	int sddoingadump = 0;
#endif /* SLICE */
	register struct scsi_data *sd;	/* disk unit to do the IO */
	struct scsi_link *sc_link;
	int32_t	blknum, blkcnt = MAXTRANSFER;
	char	*addr;
	struct	scsi_rw_big cmd;
	struct	scsi_xfer *xs = &sx;
	errval	retval;

	addr = (char *) 0;	/* starting address */

#ifndef SLICE
	/* toss any characters present prior to dump */
	while (cncheckc() != -1) ;

	/* size of memory to dump */
	num = Maxmem;
	unit = SDUNIT(dev);	/* eventually support floppies? */
	part = PARTITION(dev);	/* file system */

	sc_link = SCSI_LINK(&sd_switch, unit);

	if (!sc_link)
		return ENXIO;

	sd = sc_link->sd;
#else
	sd = private;
	sc_link = sd->sc_link;
#endif /* SLICE */

	/* was it ever initialized etc. ? */
	if (!(sd->flags & SDINIT))
		return (ENXIO);
	if ((sc_link->flags & SDEV_MEDIA_LOADED) != SDEV_MEDIA_LOADED)
		return (ENXIO);
#ifndef SLICE
	if (sd->dk_slices == NULL)
		Debugger("sddump: no slices");
	if ((lp = dsgetlabel(dev, sd->dk_slices)) == NULL)
		return (ENXIO);

	/* Convert to disk sectors */
	/* XXX it must be 512 */
	num = (u_int32_t) num * PAGE_SIZE / sd->params.secsiz;

	/* check if controller active */
	if (sddoingadump)
		return (EFAULT);

	nblocks = lp->d_partitions[part].p_size;
	blkoff = lp->d_partitions[part].p_offset;
	/* XXX */
	blkoff += sd->dk_slices->dss_slices[dkslice(dev)].ds_offset;

	/* check transfer bounds against partition size */
	if ((dumplo < 0) || ((dumplo + num) > nblocks))
		return (EINVAL);

	sddoingadump = 1;

	blknum = dumplo + blkoff;
#else
	blknum = start;
#endif /* SLICE */
	while (num > 0) {
		if (is_physical_memory((vm_offset_t)addr))
		    pmap_enter(kernel_pmap, (vm_offset_t)CADDR1,
		 	       trunc_page(addr), VM_PROT_READ, TRUE);
		else
		    pmap_enter(kernel_pmap, (vm_offset_t)CADDR1,
			       trunc_page(0), VM_PROT_READ, TRUE);
		/*
		 *  Fill out the scsi command
		 */
		bzero(&cmd, sizeof(cmd));
		cmd.op_code = WRITE_BIG;
		cmd.addr_3 = (blknum & 0xff000000) >> 24;
		cmd.addr_2 = (blknum & 0xff0000) >> 16;
		cmd.addr_1 = (blknum & 0xff00) >> 8;
		cmd.addr_0 = blknum & 0xff;
		cmd.length2 = (blkcnt & 0xff00) >> 8;
		cmd.length1 = (blkcnt & 0xff);
		/*
		 * Fill out the scsi_xfer structure
		 *    Note: we cannot sleep as we may be an interrupt
		 * don't use scsi_scsi_cmd() as it may want
		 * to wait for an xs.
		 */
		bzero(xs, sizeof(sx));
		xs->flags |= SCSI_NOMASK | SCSI_NOSLEEP | INUSE | SCSI_DATA_OUT;
		xs->sc_link = sc_link;
		xs->retries = SD_RETRIES;
		xs->timeout = 10000;	/* 10000 millisecs for a disk ! */
		xs->cmd = (struct scsi_generic *) &cmd;
		xs->cmdlen = sizeof(cmd);
		xs->resid = 0;
		xs->error = XS_NOERROR;
		xs->bp = 0;
		xs->data = (u_char *) CADDR1;	/* XXX use pmap_enter() */
		xs->datalen = blkcnt * sd->params.secsiz;

		/*
		 * Pass all this info to the scsi driver.
		 */
		retval = (*(sc_link->adapter->scsi_cmd)) (xs);
		switch (retval) {
		case SUCCESSFULLY_QUEUED:
		case HAD_ERROR:
			return (ENXIO);		/* we said not to sleep! */
		case COMPLETE:
			break;
		default:
			return (ENXIO);		/* we said not to sleep! */
		}

		/*
		 * If we are dumping core, it may take a while.
		 * So reassure the user and hold off any watchdogs.
		 */
		if ((unsigned)addr % (1024 * 1024) == 0) {
#ifdef	HW_WDOG
			if (wdog_tickler)
				(*wdog_tickler)();
#endif /* HW_WDOG */
			printf("%ld ", num / 2048);
		}
		/* update block count */
		num -= blkcnt;
		blknum += blkcnt;
		(int) addr += blkcnt * sd->params.secsiz;

		/* operator aborting dump? */
		if (cncheckc() != -1)
			return (EINTR);
	}
	return (0);
}

#ifndef SLICE
static sd_devsw_installed = 0;

static void 	sd_drvinit(void *unused)
{

	if( ! sd_devsw_installed ) {
		bdevsw_add_generic(BDEV_MAJOR, CDEV_MAJOR, &sd_bdevsw);
		sd_devsw_installed = 1;
    	}
}

SYSINIT(sddev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,sd_drvinit,NULL)

#endif /* !SLICE */
#ifdef SLICE

/*
 * arguments, and schedules the transfer.  Does not wait for the transfer
 * to complete.  Multi-page transfers are supported.  All I/O requests must
 * be a multiple of a sector in length.
scsi_strategy(bp, &sd_switch);
 */
static void 
sdsIOreq(void *private ,struct buf *bp)
{
	struct scsi_data *sd = private;
	u_int32_t opri;
	u_int32_t unit = sd->unit;
	struct scsi_link *sc_link = sd->sc_link;

	SC_DEBUG(sc_link, SDEV_DB2, ("sdIOreq\n"));
	SC_DEBUG(sc_link, SDEV_DB1, ("%ld bytes @ blk%ld\n",
		bp->b_bcount, bp->b_pblkno));

	bp->b_resid = 0;
	bp->b_error = 0;

	(*sc_link->adapter->scsi_minphys)(bp);

	sdstrats++;
	/*
	 * If the device has been made invalid, error out
	 */
	if (!(sc_link->flags & SDEV_MEDIA_LOADED)) {
		bp->b_error = EIO;
		goto bad;
	}

	/*
	 * check it's not too big a transfer for our adapter
	 */
        /*scsi_minphys(bp,&sd_switch);*/

	opri = SPLSD();
	/*
	 * Use a bounce buffer if necessary
	 */
#ifdef BOUNCE_BUFFERS
	if (sc_link->flags & SDEV_BOUNCE)
		vm_bounce_alloc(bp);
#endif

	/*
	 * Place it in the queue of disk activities for this disk
	 */
#ifdef SDDISKSORT
	bufq_disksort(&sd->buf_queue, bp);
#else
	bufq_insert_tail(&sd->buf_queue, bp);
#endif

	/*
	 * Tell the device to get going on the transfer if it's
	 * not doing anything, otherwise just wait for completion
	 */
	sdstart(unit, 0);

	splx(opri);
	return;
bad:
	bp->b_flags |= B_ERROR;
	bp->b_resid = bp->b_bcount;
	biodone(bp);
	return;
}
#endif
