/*
 * Implementation of SCSI Sequential Access Peripheral driver for CAM.
 *
 * Copyright (c) 1997 Justin T. Gibbs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      $Id: scsi_sa.c,v 1.10 1998/12/19 23:33:21 mjacob Exp $
 */

#include <sys/param.h>
#include <sys/queue.h>
#ifdef KERNEL
#include <sys/systm.h>
#include <sys/kernel.h>
#endif
#include <sys/types.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mtio.h>
#include <sys/conf.h>
#include <sys/buf.h>
#include <sys/devicestat.h>
#include <machine/limits.h>

#ifndef KERNEL
#include <stdio.h>
#include <string.h>
#endif

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_extend.h>
#include <cam/cam_periph.h>
#include <cam/cam_xpt_periph.h>
#include <cam/cam_debug.h>

#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_message.h>
#include <cam/scsi/scsi_sa.h>

#ifdef KERNEL

#include <opt_sa.h>

#ifndef SA_SPACE_TIMEOUT
#define SA_SPACE_TIMEOUT	1 * 60
#endif
#ifndef SA_REWIND_TIMEOUT
#define SA_REWIND_TIMEOUT	2 * 60
#endif
#ifndef SA_ERASE_TIMEOUT
#define SA_ERASE_TIMEOUT	4 * 60
#endif

#define	SAUNIT(DEV) ((minor(DEV)&0xF0) >> 4)	/* 4 bit unit.	*/
#define	SASETUNIT(DEV, U) makedev(major(DEV), ((U) << 4))

#ifndef	UNUSED_PARAMETER
#define	UNUSED_PARAMETER(x)	x = x
#endif

typedef enum {
	SA_STATE_NORMAL
} sa_state;

typedef enum {
	SA_CCB_BUFFER_IO,
	SA_CCB_WAITING
} sa_ccb_types;

#define ccb_type ppriv_field0
#define ccb_bp	 ppriv_ptr1

typedef enum {
	SA_FLAG_OPEN		= 0x0001,
	SA_FLAG_FIXED		= 0x0002,
	SA_FLAG_TAPE_LOCKED	= 0x0004,
	SA_FLAG_TAPE_MOUNTED	= 0x0008,
	SA_FLAG_TAPE_WP		= 0x0010,
	SA_FLAG_TAPE_WRITTEN	= 0x0020,
	SA_FLAG_EOM_PENDING	= 0x0040,
	SA_FLAG_EIO_PENDING	= 0x0080,
	SA_FLAG_EOF_PENDING	= 0x0100,
	SA_FLAG_ERR_PENDING	= (SA_FLAG_EOM_PENDING|SA_FLAG_EIO_PENDING|
				   SA_FLAG_EOF_PENDING),
	SA_FLAG_INVALID		= 0x0200,
	SA_FLAG_COMP_ENABLED	= 0x0400,
	SA_FLAG_COMP_UNSUPP	= 0x0800
} sa_flags;

typedef enum {
	SA_MODE_REWIND		= 0x00,
	SA_MODE_NOREWIND	= 0x01,
	SA_MODE_OFFLINE		= 0x02
} sa_mode;

typedef enum {
	SA_PARAM_NONE		= 0x00,
	SA_PARAM_BLOCKSIZE	= 0x01,
	SA_PARAM_DENSITY	= 0x02,
	SA_PARAM_COMPRESSION	= 0x04,
	SA_PARAM_BUFF_MODE	= 0x08,
	SA_PARAM_NUMBLOCKS	= 0x10,
	SA_PARAM_WP		= 0x20,
	SA_PARAM_SPEED		= 0x40,
	SA_PARAM_ALL		= 0x7f
} sa_params;

typedef enum {
	SA_QUIRK_NONE		= 0x00,
	SA_QUIRK_NOCOMP		= 0x01,	/* can't deal with compression at all */
	SA_QUIRK_FIXED		= 0x02,	/* force fixed mode */
	SA_QUIRK_VARIABLE	= 0x04,	/* force variable mode */
	SA_QUIRK_2FM		= 0x05,	/* Two File Marks at EOD */
	SA_QUIRK_NORRLS		= 0x06	/* Don't attempt RESERVE/RELEASE */
} sa_quirks;

struct sa_softc {
	sa_state	state;
	sa_flags	flags;
	sa_quirks	quirks;
	struct		buf_queue_head buf_queue;
	struct		devstat device_stats;
	int		blk_gran;
	int		blk_mask;
	int		blk_shift;
	u_int32_t	max_blk;
	u_int32_t	min_blk;
	u_int32_t	comp_algorithm;
	u_int32_t	saved_comp_algorithm;
	u_int32_t	media_blksize;
	u_int32_t	last_media_blksize;
	u_int32_t	media_numblks;
	u_int8_t	media_density;
	u_int8_t	speed;
	u_int8_t	scsi_rev;
	int		buffer_mode;
	int		filemarks;
	union		ccb saved_ccb;
	/*
	 * Latched Error Info
	 */
	struct {
		struct scsi_sense_data _last_io_sense;
		u_int32_t _last_io_resid;
		u_int8_t _last_io_cdb[CAM_MAX_CDBLEN];
		struct scsi_sense_data _last_ctl_sense;
		u_int32_t _last_ctl_resid;
		u_int8_t _last_ctl_cdb[CAM_MAX_CDBLEN];
#define	last_io_sense	errinfo._last_io_sense
#define	last_io_resid	errinfo._last_io_resid
#define	last_io_cdb	errinfo._last_io_cdb
#define	last_ctl_sense	errinfo._last_ctl_sense
#define	last_ctl_resid	errinfo._last_ctl_resid
#define	last_ctl_cdb	errinfo._last_ctl_cdb
	} errinfo;
};

struct sa_quirk_entry {
	struct scsi_inquiry_pattern inq_pat;
	sa_quirks quirks;
};

static struct sa_quirk_entry sa_quirk_table[] =
{
	{
		{ T_SEQUENTIAL, SIP_MEDIA_REMOVABLE, "ARCHIVE",
		  "Python 25601*", "*"}, SA_QUIRK_NOCOMP
	},
	{
		{ T_SEQUENTIAL, SIP_MEDIA_REMOVABLE, "TANDBERG",
		  " TDC 3600", "U07:"}, SA_QUIRK_NOCOMP
	}
};

static	d_open_t	saopen;
static	d_read_t	saread;
static	d_write_t	sawrite;
static	d_close_t	saclose;
static	d_strategy_t	sastrategy;
static	d_ioctl_t	saioctl;
static	periph_init_t	sainit;
static	periph_ctor_t	saregister;
static	periph_oninv_t	saoninvalidate;
static	periph_dtor_t	sacleanup;
static	periph_start_t	sastart;
static	void		saasync(void *callback_arg, u_int32_t code,
				struct cam_path *path, void *arg);
static	void		sadone(struct cam_periph *periph,
			       union ccb *start_ccb);
static  int		saerror(union ccb *ccb, u_int32_t cam_flags,
				u_int32_t sense_flags);
static int		sacheckeod(struct cam_periph *periph);
static int		sagetparams(struct cam_periph *periph,
				    sa_params params_to_get,
				    u_int32_t *blocksize, u_int8_t *density,
				    u_int32_t *numblocks, int *buff_mode,
				    u_int8_t *write_protect, u_int8_t *speed,
				    int *comp_supported, int *comp_enabled,
				    u_int32_t *comp_algorithm,
				  struct scsi_data_compression_page *comp_page);
static int		sasetparams(struct cam_periph *periph,
				    sa_params params_to_set,
				    u_int32_t blocksize, u_int8_t density,
				    u_int32_t comp_algorithm);
static void		saprevent(struct cam_periph *periph, int action);
static int		sarewind(struct cam_periph *periph);
static int		saspace(struct cam_periph *periph, int count,
				scsi_space_code code);
static int		samount(struct cam_periph *, int, dev_t);
static int		saretension(struct cam_periph *periph);
static int		sareservereleaseunit(struct cam_periph *periph,
					     int reserve);
static int		saloadunload(struct cam_periph *periph, int load);
static int		saerase(struct cam_periph *periph, int longerase);
static int		sawritefilemarks(struct cam_periph *periph,
					 int nmarks, int setmarks);
static int		sardpos(struct cam_periph *periph, int, u_int32_t *);
static int		sasetpos(struct cam_periph *periph, int, u_int32_t *);


static struct periph_driver sadriver =
{
	sainit, "sa",
	TAILQ_HEAD_INITIALIZER(sadriver.units), /* generation */ 0
};

DATA_SET(periphdriver_set, sadriver);

#define SAUNIT(DEV) ((minor(DEV)&0xF0) >> 4)	/* 4 bit unit. */
#define SASETUNIT(DEV, U) makedev(major(DEV), ((U) << 4))

#define SAMODE(z) ((minor(z) & 0x03))
#define SADENSITY(z) (((minor(z) >> 2) & 0x03))

/* For 2.2-stable support */
#ifndef D_TAPE
#define D_TAPE 0
#endif

#define CTLMODE	3
#define SA_CDEV_MAJOR 14
#define SA_BDEV_MAJOR 5

static struct cdevsw sa_cdevsw = 
{
	/*d_open*/	saopen,
	/*d_close*/	saclose,
	/*d_read*/	saread,
	/*d_write*/	sawrite,
	/*d_ioctl*/	saioctl,
	/*d_stop*/	nostop,
	/*d_reset*/	noreset,
	/*d_devtotty*/	nodevtotty,
	/*d_poll*/	seltrue,
	/*d_mmap*/	nommap,
	/*d_strategy*/	sastrategy,
	/*d_name*/	"sa",
	/*d_spare*/	NULL,
	/*d_maj*/	-1,
	/*d_dump*/	nodump,
	/*d_psize*/	nopsize,
	/*d_flags*/	D_TAPE,
	/*d_maxio*/	0,
	/*b_maj*/	-1
};

static struct extend_array *saperiphs;

static int
saopen(dev_t dev, int flags, int fmt, struct proc *p)
{
	struct cam_periph *periph;
	struct sa_softc *softc;
	int unit;
	int mode;
	int density;
	int error;
	int s;

	unit = SAUNIT(dev);
	mode = SAMODE(dev);
	density = SADENSITY(dev);

	periph = cam_extend_get(saperiphs, unit);
	if (periph == NULL)
		return (ENXIO);	

	softc = (struct sa_softc *)periph->softc;

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE,
	    ("saaopen: dev=0x%x (unit %d , mode %d, density %d)\n", dev,
	     unit, mode, density));

	s = splsoftcam();
	if (softc->flags & SA_FLAG_INVALID) {
		splx(s);
		return(ENXIO);
	}

	if ((error = cam_periph_lock(periph, PRIBIO|PCATCH)) != 0) {
		splx(s);
		return (error); /* error code from tsleep */
	}

	splx(s);

	if ((softc->flags & SA_FLAG_OPEN) == 0) {
		if (cam_periph_acquire(periph) != CAM_REQ_CMP)
			return(ENXIO);

		if ((error = sareservereleaseunit(periph, TRUE)) != 0) {
			cam_periph_unlock(periph);
			cam_periph_release(periph);
			return(error);
		}
	}

	if (error == 0) {
		if ((softc->flags & SA_FLAG_OPEN) != 0) {
			error = EBUSY;
		}
		
		if (error == 0)
			error = samount(periph, flags, dev);
		/* Perform other checking... */
	}

	if (error == 0) {
		saprevent(periph, PR_PREVENT);
		softc->flags |= SA_FLAG_OPEN;
	}
	
	cam_periph_unlock(periph);
	return (error);
}

static int
saclose(dev_t dev, int flag, int fmt, struct proc *p)
{
	struct	cam_periph *periph;
	struct	sa_softc *softc;
	int	unit;
	int	mode;
	int	error;
	int	closedbits = SA_FLAG_OPEN;

	unit = SAUNIT(dev);
	mode = SAMODE(dev);
	periph = cam_extend_get(saperiphs, unit);
	if (periph == NULL)
		return (ENXIO);	

	softc = (struct sa_softc *)periph->softc;

	if ((error = cam_periph_lock(periph, PRIBIO)) != 0) {
		return (error); /* error code from tsleep */
	}

	/*
	 * See whether or not we need to write filemarks...
	 */
	error = sacheckeod(periph);
	if (error) {
		xpt_print_path(periph->path);
		printf("failure at writing filemarks - opting for safety\n");
		mode = SA_MODE_OFFLINE;
	}

	/*
	 * Whatever we end up doing, allow users to eject tapes from here on.
	 */
	saprevent(periph, PR_ALLOW);

	/*
	 * Decide how to end...
	 */
	switch (mode) {
	default:
		xpt_print_path(periph->path);
		printf("unknown close mode %x- opting for safety\n", mode);
		/* FALLTHROUGH */
	case SA_MODE_OFFLINE:
		sarewind(periph);
		saloadunload(periph, FALSE);
		closedbits |= SA_FLAG_TAPE_MOUNTED;	/* not mounted now */
		break;
	case SA_MODE_REWIND:
		sarewind(periph);
		closedbits |= SA_FLAG_TAPE_MOUNTED;	/* not mounted now */
		break;
	case SA_MODE_NOREWIND:
		/*
		 * If we're not rewinding/unloading the tape, find out
		 * whether we need to back up over one of two filemarks
		 * we wrote (if we wrote two filemarks) so that appends
		 * from this point on will be sane.
		 */
		if ((softc->quirks & SA_QUIRK_2FM) && 
		    (softc->flags & SA_FLAG_TAPE_WRITTEN)) {
			error = saspace(periph, -1, SS_FILEMARKS);
			if (error) {
				xpt_print_path(periph->path);
				printf("unable to backspace over one of double"
				   " filemarks at EOD- opting for safety\n");
				sarewind(periph);
				saloadunload(periph, FALSE);
				closedbits |= SA_FLAG_TAPE_MOUNTED;
			}
		}
		break;
	}

	/*
	 * We wish to note here that there are no more filemarks to be written.
	 */
	softc->filemarks = 0;
	softc->flags &= ~SA_FLAG_TAPE_WRITTEN;

	/*
	 * And we are no longer open for business.
	 */

	softc->flags &= ~closedbits;
	
	/* release the device */
	sareservereleaseunit(periph, FALSE);

	cam_periph_unlock(periph);
	cam_periph_release(periph);

	return (0);	
}

static int
saread(dev_t dev, struct uio *uio, int ioflag)
{
	return(physio(sastrategy, NULL, dev, 1, minphys, uio));
}

static int
sawrite(dev_t dev, struct uio *uio, int ioflag)
{
	return(physio(sastrategy, NULL, dev, 0, minphys, uio));
}

/*
 * Actually translate the requested transfer into one the physical driver
 * can understand.  The transfer is described by a buf and will include
 * only one physical transfer.
 */
static void
sastrategy(struct buf *bp)
{
	struct cam_periph *periph;
	struct sa_softc *softc;
	u_int  unit;
	int    s;
	
	unit = SAUNIT(bp->b_dev);
	periph = cam_extend_get(saperiphs, unit);
	if (periph == NULL) {
		bp->b_error = ENXIO;
		goto bad;
	}
	softc = (struct sa_softc *)periph->softc;

	s = splsoftcam();

	if (softc->flags & SA_FLAG_INVALID) {
		splx(s);
		bp->b_error = ENXIO;
		goto bad;
	}

	splx(s);

	/*
	 * If it's a null transfer, return immediatly
	 */
	if (bp->b_bcount == 0)
		goto done;

	/* valid request?  */
	if (softc->flags & SA_FLAG_FIXED) {
		/*
		 * Fixed block device.  The byte count must
		 * be a multiple of our block size.
		 */
		if (((softc->blk_mask != ~0)
		  && ((bp->b_bcount & softc->blk_mask) != 0))
		 || ((softc->blk_mask == ~0)
		  && ((bp->b_bcount % softc->min_blk) != 0))) {
			xpt_print_path(periph->path);
			printf("Invalid request.  Fixed block device "
			       "requests must be a multiple "
			       "of %d bytes\n", softc->min_blk);
			bp->b_error = EINVAL;
			goto bad;
		}
	} else if ((bp->b_bcount > softc->max_blk)
		|| (bp->b_bcount < softc->min_blk)
		|| (bp->b_bcount & softc->blk_mask) != 0) {

		xpt_print_path(periph->path);
		printf("Invalid request.  Variable block device "
		       "requests must be ");
		if (softc->blk_mask != 0) {
			printf("a multiple of %d ",
			       (0x1 << softc->blk_gran));
		}
		printf("between %d and %d bytes\n",
		       softc->min_blk, softc->max_blk);
		bp->b_error = EINVAL;
		goto bad;
        }
	
	/*
	 * Mask interrupts so that the pack cannot be invalidated until
	 * after we are in the queue.  Otherwise, we might not properly
	 * clean up one of the buffers.
	 */
	s = splbio();
	
	/*
	 * Place it in the queue of disk activities for this disk
	 */
	bufq_insert_tail(&softc->buf_queue, bp);

	splx(s);
	
	/*
	 * Schedule ourselves for performing the work.
	 */
	xpt_schedule(periph, /* XXX priority */1);

	return;
bad:
	bp->b_flags |= B_ERROR;
done:

	/*
	 * Correctly set the buf to indicate a completed xfer
	 */
	bp->b_resid = bp->b_bcount;
	biodone(bp);
}

static int
saioctl(dev_t dev, u_long cmd, caddr_t arg, int flag, struct proc *p)
{
	struct cam_periph *periph;
	struct sa_softc *softc;
	int unit;
	int mode;
	int density;
	int error;

	unit = SAUNIT(dev);
	mode = SAMODE(dev);
	density = SADENSITY(dev);

	periph = cam_extend_get(saperiphs, unit);
	if (periph == NULL)
		return (ENXIO);	

	softc = (struct sa_softc *)periph->softc;

	/*
	 * Find the device that the user is talking about
	 */
	switch (cmd) {
	case MTIOCGET:
	{
		struct mtget *g = (struct mtget *)arg;

		CAM_DEBUG(periph->path, CAM_DEBUG_TRACE,
		    ("saioctl: MTIOGET\n"));

		bzero(g, sizeof(struct mtget));
		g->mt_type = MT_ISAR;
		g->mt_density = softc->media_density;
		g->mt_blksiz = softc->media_blksize;
		if (softc->flags & SA_FLAG_COMP_UNSUPP) {
			g->mt_comp = MT_COMP_UNSUPP;
			g->mt_comp0 = MT_COMP_UNSUPP;
			g->mt_comp1 = MT_COMP_UNSUPP;
			g->mt_comp2 = MT_COMP_UNSUPP;
			g->mt_comp3 = MT_COMP_UNSUPP;
		} else if ((softc->flags & SA_FLAG_COMP_ENABLED) == 0) {
			g->mt_comp = MT_COMP_DISABLED;
			g->mt_comp0 = MT_COMP_DISABLED;
			g->mt_comp1 = MT_COMP_DISABLED;
			g->mt_comp2 = MT_COMP_DISABLED;
			g->mt_comp3 = MT_COMP_DISABLED;
		} else {
			g->mt_comp = softc->comp_algorithm;
			g->mt_comp0 = softc->comp_algorithm;
			g->mt_comp1 = softc->comp_algorithm;
			g->mt_comp2 = softc->comp_algorithm;
			g->mt_comp3 = softc->comp_algorithm;
		}
		g->mt_density0 = softc->media_density;
		g->mt_density1 = softc->media_density;
		g->mt_density2 = softc->media_density;
		g->mt_density3 = softc->media_density;
		g->mt_blksiz0 = softc->media_blksize;
		g->mt_blksiz1 = softc->media_blksize;
		g->mt_blksiz2 = softc->media_blksize;
		g->mt_blksiz3 = softc->media_blksize;
		error = 0;
		break;
	}
	case MTIOCERRSTAT:
	{
		struct scsi_tape_errors *sep =
		    &((union mterrstat *)arg)->scsi_errstat;

		CAM_DEBUG(periph->path, CAM_DEBUG_TRACE,
		    ("saioctl: MTIOCERRSTAT\n"));

		bzero(sep, sizeof(*sep));
		sep->io_resid = softc->last_io_resid;
		bcopy((caddr_t) &softc->last_io_sense, sep->io_sense,
		    sizeof (sep->io_sense));
		bcopy((caddr_t) &softc->last_io_cdb, sep->io_cdb,
		    sizeof (sep->io_cdb));
		sep->ctl_resid = softc->last_ctl_resid;
		bcopy((caddr_t) &softc->last_ctl_sense, sep->ctl_sense,
		    sizeof (sep->ctl_sense));
		bcopy((caddr_t) &softc->last_ctl_cdb, sep->ctl_cdb,
		    sizeof (sep->ctl_cdb));
		bzero((caddr_t) &softc->errinfo, sizeof (softc->errinfo));
		error = 0;
		break;
	}
	case MTIOCTOP:
	{
		struct mtop *mt;
		int    count;

		mt = (struct mtop *)arg;

		CAM_DEBUG(periph->path, CAM_DEBUG_TRACE,
			 ("saioctl: op=0x%x count=0x%x\n",
			  mt->mt_op, mt->mt_count));

		count = mt->mt_count;
		switch (mt->mt_op) {
		case MTWEOF:	/* write an end-of-file marker */
			error = sawritefilemarks(periph, count, FALSE);
			break;
		case MTWSS:	/* write a setmark */
			error = sawritefilemarks(periph, count, TRUE);
			break;
		case MTBSR:	/* backward space record */
		case MTFSR:	/* forward space record */
		case MTBSF:	/* backward space file */
		case MTFSF:	/* forward space file */
		case MTBSS:	/* backward space setmark */
		case MTFSS:	/* forward space setmark */
		case MTEOD:	/* space to end of recorded medium */
		{
			int nmarks;
			scsi_space_code spaceop = SS_FILEMARKS;

			nmarks = softc->filemarks;
			error = sacheckeod(periph);
			if (error) {
				xpt_print_path(periph->path);
				printf("EOD check prior to spacing failed\n");
				softc->flags |= SA_FLAG_EIO_PENDING;
				break;
			}
			nmarks -= softc->filemarks;
			switch(mt->mt_op) {
			case MTBSR:
				count = -count;
				/* FALLTHROUGH */
			case MTFSR:
				spaceop = SS_BLOCKS;
				break;
			case MTBSF:
				count = -count;
				/* FALLTHROUGH */
			case MTFSF:
				break;
			case MTBSS:
				count = -count;
				/* FALLTHROUGH */
			case MTFSS:
				spaceop = SS_SETMARKS;
				break;
			case MTEOD:
				spaceop = SS_EOD;
				count = 0;
				nmarks = 0;
				break;
			default:
				error = EINVAL;
				break;
			}
			if (error)
				break;

			nmarks = softc->filemarks;
			/*
			 * XXX: Why are we checking again?
			 */
			error = sacheckeod(periph);
			if (error)
				break;
			nmarks -= softc->filemarks;
			error = saspace(periph, count - nmarks, spaceop);
			/*
			 * At this point, clear that we've written the tape
			 * and that we've written any filemarks. We really
			 * don't know what the applications wishes to do next-
			 * the sacheckeod's will make sure we terminated the
			 * tape correctly if we'd been writing, but the next
			 * action the user application takes will set again
			 * whether we need to write filemarks.
			 */
			softc->flags &= ~SA_FLAG_TAPE_WRITTEN;
			softc->filemarks = 0;
			break;
		}
		case MTREW:	/* rewind */
			(void) sacheckeod(periph);
			error = sarewind(periph);
			/* see above */
			softc->flags &=
			    ~SA_FLAG_TAPE_WRITTEN|SA_FLAG_TAPE_MOUNTED;
			softc->filemarks = 0;
			break;
		case MTERASE:	/* erase */
			error = saerase(periph, count);
			break;
		case MTRETENS:	/* re-tension tape */
			error = saretension(periph);		
			break;
		case MTOFFL:	/* rewind and put the drive offline */

			(void) sacheckeod(periph);
			/* see above */
			softc->flags &= ~SA_FLAG_TAPE_WRITTEN;
			softc->filemarks = 0;

			/*
			 * Be sure to allow media removal before
			 * attempting the eject.
			 */
			saprevent(periph, PR_ALLOW);
			error = sarewind(periph);

			if (error == 0)
				error = saloadunload(periph, /*load*/FALSE);
			else
				break;

			softc->flags &= ~SA_FLAG_TAPE_LOCKED;
			softc->flags &= ~SA_FLAG_TAPE_MOUNTED;
			break;
		case MTNOP:	/* no operation, sets status only */
		case MTCACHE:	/* enable controller cache */
		case MTNOCACHE:	/* disable controller cache */
			error = 0;
			break;
		case MTSETBSIZ:	/* Set block size for device */

			error = sasetparams(periph, SA_PARAM_BLOCKSIZE, count,
					    0, 0);
			if (error == 0) {
				softc->last_media_blksize =
				    softc->media_blksize;
				softc->media_blksize = count;
				if (count) {
					softc->flags |= SA_FLAG_FIXED;
					if (powerof2(count)) {
						softc->blk_shift =
						    ffs(count) - 1;
						softc->blk_mask = count - 1;
					} else {
						softc->blk_mask = ~0;
						softc->blk_shift = 0;
					}
					/*
					 * Make the user's desire 'persistent'.
					 */
					softc->quirks &= ~SA_QUIRK_VARIABLE;
					softc->quirks |= SA_QUIRK_FIXED;
				} else {
					softc->flags &= ~SA_FLAG_FIXED;
					if (softc->max_blk == 0) {
						softc->max_blk = ~0;
					}
					softc->blk_shift = 0;
					if (softc->blk_gran != 0) {
						softc->blk_mask =
						    softc->blk_gran - 1;
					} else {
						softc->blk_mask = 0;
					}
					/*
					 * Make the user's desire 'persistent'.
					 */
					softc->quirks |= SA_QUIRK_VARIABLE;
					softc->quirks &= ~SA_QUIRK_FIXED;
				}
			}
			break;
		case MTSETDNSTY:	/* Set density for device and mode */
			if (count > UCHAR_MAX) {
				error = EINVAL;	
				break;
			} else {
				error = sasetparams(periph, SA_PARAM_DENSITY,
						    0, count, 0);
			}
			break;
		case MTCOMP:	/* enable compression */
			/*
			 * Some devices don't support compression, and
			 * don't like it if you ask them for the
			 * compression page.
			 */
			if ((softc->quirks & SA_QUIRK_NOCOMP)
			 || (softc->flags & SA_FLAG_COMP_UNSUPP)) {
				error = ENODEV;
				break;
			}
			error = sasetparams(periph, SA_PARAM_COMPRESSION,
					    0, 0, count);
			break;
		default:
			error = EINVAL;
		}
		break;
	}
	case MTIOCIEOT:
	case MTIOCEEOT:
		error = 0;
		break;
	case MTIOCRDSPOS:
		error = sardpos(periph, 0, (u_int32_t *) arg);
		break;
	case MTIOCRDHPOS:
		error = sardpos(periph, 1, (u_int32_t *) arg);
		break;
	case MTIOCSLOCATE:
		error = sasetpos(periph, 0, (u_int32_t *) arg);
		break;
	case MTIOCHLOCATE:
		error = sasetpos(periph, 1, (u_int32_t *) arg);
		break;
	default:
		error = cam_periph_ioctl(periph, cmd, arg, saerror);
		break;
	}
	return (error);
}

static void
sainit(void)
{
	cam_status status;
	struct cam_path *path;

	/*
	 * Create our extend array for storing the devices we attach to.
	 */
	saperiphs = cam_extend_new();
	if (saperiphs == NULL) {
		printf("sa: Failed to alloc extend array!\n");
		return;
	}
	
	/*
	 * Install a global async callback.
	 */
	status = xpt_create_path(&path, NULL, CAM_XPT_PATH_ID,
				 CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD);

	if (status == CAM_REQ_CMP) {
		/* Register the async callbacks of interrest */
		struct ccb_setasync csa; /*
					  * This is an immediate CCB,
					  * so using the stack is OK
					  */
		xpt_setup_ccb(&csa.ccb_h, path, /*priority*/5);
		csa.ccb_h.func_code = XPT_SASYNC_CB;
		csa.event_enable = AC_FOUND_DEVICE;
		csa.callback = saasync;
		csa.callback_arg = NULL;
		xpt_action((union ccb *)&csa);
		status = csa.ccb_h.status;
		xpt_free_path(path);
	}

	if (status != CAM_REQ_CMP) {
		printf("sa: Failed to attach master async callback "
		       "due to status 0x%x!\n", status);
	} else {
		/* If we were successfull, register our devsw */
		cdevsw_add_generic(SA_BDEV_MAJOR, SA_CDEV_MAJOR, &sa_cdevsw);
	}
}

static void
saoninvalidate(struct cam_periph *periph)
{
	struct sa_softc *softc;
	struct buf *q_bp;
	struct ccb_setasync csa;
	int s;

	softc = (struct sa_softc *)periph->softc;

	/*
	 * De-register any async callbacks.
	 */
	xpt_setup_ccb(&csa.ccb_h, periph->path,
		      /* priority */ 5);
	csa.ccb_h.func_code = XPT_SASYNC_CB;
	csa.event_enable = 0;
	csa.callback = saasync;
	csa.callback_arg = periph;
	xpt_action((union ccb *)&csa);

	softc->flags |= SA_FLAG_INVALID;

	/*
	 * Although the oninvalidate() routines are always called at
	 * splsoftcam, we need to be at splbio() here to keep the buffer
	 * queue from being modified while we traverse it.
	 */
	s = splbio();

	/*
	 * Return all queued I/O with ENXIO.
	 * XXX Handle any transactions queued to the card
	 *     with XPT_ABORT_CCB.
	 */
	while ((q_bp = bufq_first(&softc->buf_queue)) != NULL){
		bufq_remove(&softc->buf_queue, q_bp);
		q_bp->b_resid = q_bp->b_bcount;
		q_bp->b_error = ENXIO;
		q_bp->b_flags |= B_ERROR;
		biodone(q_bp);
	}
	splx(s);

	xpt_print_path(periph->path);
	printf("lost device\n");

}

static void
sacleanup(struct cam_periph *periph)
{
	struct sa_softc *softc;

	softc = (struct sa_softc *)periph->softc;

	devstat_remove_entry(&softc->device_stats);
	cam_extend_release(saperiphs, periph->unit_number);
	xpt_print_path(periph->path);
	printf("removing device entry\n");
	free(softc, M_DEVBUF);
}

static void
saasync(void *callback_arg, u_int32_t code,
	struct cam_path *path, void *arg)
{
	struct cam_periph *periph;

	periph = (struct cam_periph *)callback_arg;
	switch (code) {
	case AC_FOUND_DEVICE:
	{
		struct ccb_getdev *cgd;
		cam_status status;

		cgd = (struct ccb_getdev *)arg;

		if (cgd->pd_type != T_SEQUENTIAL)
			break;

		/*
		 * Allocate a peripheral instance for
		 * this device and start the probe
		 * process.
		 */
		status = cam_periph_alloc(saregister, saoninvalidate,
					  sacleanup, sastart,
					  "sa", CAM_PERIPH_BIO, cgd->ccb_h.path,
					  saasync, AC_FOUND_DEVICE, cgd);

		if (status != CAM_REQ_CMP
		 && status != CAM_REQ_INPROG)
			printf("saasync: Unable to probe new device "
				"due to status 0x%x\n", status);
		break;
	}
	case AC_LOST_DEVICE:
		cam_periph_invalidate(periph);
		break;
	case AC_TRANSFER_NEG:
	case AC_SENT_BDR:
	case AC_SCSI_AEN:
	case AC_UNSOL_RESEL:
	case AC_BUS_RESET:
	default:
		break;
	}
}

static cam_status
saregister(struct cam_periph *periph, void *arg)
{
	struct sa_softc *softc;
	struct ccb_setasync csa;
	struct ccb_getdev *cgd;
	caddr_t match;
	
	cgd = (struct ccb_getdev *)arg;
	if (periph == NULL) {
		printf("saregister: periph was NULL!!\n");
		return(CAM_REQ_CMP_ERR);
	}

	if (cgd == NULL) {
		printf("saregister: no getdev CCB, can't register device\n");
		return(CAM_REQ_CMP_ERR);
	}

	softc = (struct sa_softc *)malloc(sizeof(*softc),M_DEVBUF,M_NOWAIT);

	if (softc == NULL) {
		printf("saregister: Unable to probe new device. "
		       "Unable to allocate softc\n");				
		return(CAM_REQ_CMP_ERR);
	}

	bzero(softc, sizeof(*softc));
	softc->scsi_rev = SID_ANSI_REV(&cgd->inq_data);
	softc->state = SA_STATE_NORMAL;
	bufq_init(&softc->buf_queue);
	periph->softc = softc;
	cam_extend_set(saperiphs, periph->unit_number, periph);

	/*
	 * See if this device has any quirks.
	 */
	match = cam_quirkmatch((caddr_t)&cgd->inq_data,
			       (caddr_t)sa_quirk_table,
			       sizeof(sa_quirk_table)/sizeof(*sa_quirk_table),
			       sizeof(*sa_quirk_table), scsi_inquiry_match);

	if (match != NULL)
		softc->quirks = ((struct sa_quirk_entry *)match)->quirks;
	else
		softc->quirks = SA_QUIRK_NONE;

	/*
 	 * The SA driver supports a blocksize, but we don't know the
	 * blocksize until we sense the media.  So, set a flag to
	 * indicate that the blocksize is unavailable right now.
	 * We'll clear the flag as soon as we've done a read capacity.
	 */
	devstat_add_entry(&softc->device_stats, "sa",
			  periph->unit_number, 0,
			  DEVSTAT_BS_UNAVAILABLE,
			  cgd->pd_type | DEVSTAT_TYPE_IF_SCSI);
  
	/*
	 * Add an async callback so that we get
	 * notified if this device goes away.
	 */
	xpt_setup_ccb(&csa.ccb_h, periph->path, /* priority */ 5);
	csa.ccb_h.func_code = XPT_SASYNC_CB;
	csa.event_enable = AC_LOST_DEVICE;
	csa.callback = saasync;
	csa.callback_arg = periph;
	xpt_action((union ccb *)&csa);

	xpt_announce_periph(periph, NULL);

	return(CAM_REQ_CMP);
}

static void
sastart(struct cam_periph *periph, union ccb *start_ccb)
{
	struct sa_softc *softc;

	softc = (struct sa_softc *)periph->softc;

	CAM_DEBUG(periph->path, CAM_DEBUG_INFO, ("sastart"));
	
	switch (softc->state) {
	case SA_STATE_NORMAL:
	{
		/* Pull a buffer from the queue and get going on it */		
		struct buf *bp;
		int s;

		/*
		 * See if there is a buf with work for us to do..
		 */
		s = splbio();
		bp = bufq_first(&softc->buf_queue);
		if (periph->immediate_priority <= periph->pinfo.priority) {
			CAM_DEBUG_PRINT(CAM_DEBUG_SUBTRACE,
					("queuing for immediate ccb\n"));
			start_ccb->ccb_h.ccb_type = SA_CCB_WAITING;
			SLIST_INSERT_HEAD(&periph->ccb_list, &start_ccb->ccb_h,
					  periph_links.sle);
			periph->immediate_priority = CAM_PRIORITY_NONE;
			splx(s);
			wakeup(&periph->ccb_list);
		} else if (bp == NULL) {
			splx(s);
			xpt_release_ccb(start_ccb);
		} else if ((softc->flags & SA_FLAG_ERR_PENDING) != 0) {
			struct buf *done_bp;
			CAM_DEBUG(periph->path, CAM_DEBUG_INFO,
			    ("sastart- coping with pending error %x\n",
			    softc->flags & SA_FLAG_ERR_PENDING));
			bufq_remove(&softc->buf_queue, bp);
			bp->b_resid = bp->b_bcount;
			bp->b_flags |= B_ERROR;
			if ((softc->flags & SA_FLAG_EOM_PENDING) != 0) {
				if ((bp->b_flags & B_READ) == 0)
					bp->b_error = ENOSPC;
			}
			if ((softc->flags & SA_FLAG_EOF_PENDING) != 0) {
				bp->b_error = EIO;
			}
			if ((softc->flags & SA_FLAG_EIO_PENDING) != 0) {
				bp->b_error = EIO;
			}
			softc->flags &= ~SA_FLAG_ERR_PENDING;
			done_bp = bp;
			bp = bufq_first(&softc->buf_queue);
			splx(s);
			biodone(done_bp);
		} else {
			u_int32_t length;

			bufq_remove(&softc->buf_queue, bp);

			if ((softc->flags & SA_FLAG_FIXED) != 0) {
				if (softc->blk_shift != 0) {
					length =
					    bp->b_bcount >> softc->blk_shift;
				} else {
					if (softc->media_blksize == 0) {
						bp->b_error = EIO;
						xpt_print_path(periph->path);
						printf("zero blocksize for "
						    "FIXED length writes?\n");
						splx(s);
						biodone(bp);
						break;
					}
					length =
					    bp->b_bcount / softc->media_blksize;
				}
				CAM_DEBUG(periph->path, CAM_DEBUG_INFO,
				    ("Fixed Record Count is %d\n", length));
			} else {
				length = bp->b_bcount;
				CAM_DEBUG(start_ccb->ccb_h.path, CAM_DEBUG_INFO,
				    ("Variable Record Count is %d\n", length));
			}

			devstat_start_transaction(&softc->device_stats);

			/*
			 * Some people have theorized that we should
			 * suppress illegal length indication if we are
			 * running in variable block mode so that we don't
			 * have to request sense every time our requested
			 * block size is larger than the written block.
			 * The residual information from the ccb allows
			 * us to identify this situation anyway.  The only
			 * problem with this is that we will not get
			 * information about blocks that are larger than
			 * our read buffer unless we set the block size
			 * in the mode page to something other than 0.
			 *
			 * I believe that this is a non-issue. If user apps
			 * don't adjust their read size to match our record
			 * size, that's just life. Anyway, the typical usage
			 * would be to issue, e.g., 64KB reads and occasionally
			 * have to do deal with 512 byte or 1KB intermediate
			 * records.
			 */
			scsi_sa_read_write(&start_ccb->csio,
					   /* No Retries */0,
					   sadone,
					   MSG_SIMPLE_Q_TAG,
					   bp->b_flags & B_READ,
					   /*SILI*/FALSE,
					   softc->flags & SA_FLAG_FIXED,
					   length,
					   bp->b_data,
					   bp->b_bcount,
					   SSD_FULL_SIZE,
					   120 * 60 * 1000); /* 2min */
			start_ccb->ccb_h.ccb_type = SA_CCB_BUFFER_IO;
			start_ccb->ccb_h.ccb_bp = bp;
			bp = bufq_first(&softc->buf_queue);
			splx(s);
			xpt_action(start_ccb);
		}
		
		if (bp != NULL) {
			/* Have more work to do, so ensure we stay scheduled */
			xpt_schedule(periph, /* XXX priority */1);
		}
		break;
	}
	}
}


static void
sadone(struct cam_periph *periph, union ccb *done_ccb)
{
	struct sa_softc *softc;
	struct ccb_scsiio *csio;

	softc = (struct sa_softc *)periph->softc;
	csio = &done_ccb->csio;
	switch (csio->ccb_h.ccb_type) {
	case SA_CCB_BUFFER_IO:
	{
		struct buf *bp;
		int error;

		bp = (struct buf *)done_ccb->ccb_h.ccb_bp;
		error = 0;
		if ((done_ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
			if ((error = saerror(done_ccb, 0, 0)) == ERESTART) {
				/*
				 * A retry was scheduled, so just return.
				 */
				return;
			}
		}

		if (error == EIO) {
			int s;			
			struct buf *q_bp;

			/*
			 * Catastrophic error.  Mark our pack as invalid,
			 * return all queued I/O with EIO, and unfreeze
			 * our queue so that future transactions that
			 * attempt to fix this problem can get to the
			 * device.
			 *
			 */

			s = splbio();
			softc->flags &= ~SA_FLAG_TAPE_MOUNTED;

			while ((q_bp = bufq_first(&softc->buf_queue)) != NULL) {
				bufq_remove(&softc->buf_queue, q_bp);
				q_bp->b_resid = q_bp->b_bcount;
				q_bp->b_error = EIO;
				q_bp->b_flags |= B_ERROR;
				biodone(q_bp);
			}
			splx(s);
		}
		if (error != 0) {
			bp->b_resid = bp->b_bcount;
			bp->b_error = error;
			bp->b_flags |= B_ERROR;
			cam_release_devq(done_ccb->ccb_h.path,
					 /*relsim_flags*/0,
					 /*reduction*/0,
					 /*timeout*/0,
					 /*getcount_only*/0);
		} else {
			bp->b_resid = csio->resid;
			bp->b_error = 0;
			if (csio->resid != 0) {
				bp->b_flags |= B_ERROR;
			}
			if ((bp->b_flags & B_READ) == 0) {
				softc->flags |= SA_FLAG_TAPE_WRITTEN;
				softc->filemarks = 0;
			}
		}
#ifdef	CAMDEBUG
		if (error || bp->b_resid) {
			CAM_DEBUG(periph->path, CAM_DEBUG_INFO,
			    	  ("error %d resid %ld count %ld\n", error,
				  bp->b_resid, bp->b_bcount));
		}
#endif
		devstat_end_transaction(&softc->device_stats,
					bp->b_bcount - bp->b_resid,
					done_ccb->csio.tag_action & 0xf,
					(bp->b_flags & B_READ) ? DEVSTAT_READ
							       : DEVSTAT_WRITE);
		biodone(bp);
		break;
	}
	case SA_CCB_WAITING:
	{
		/* Caller will release the CCB */
		wakeup(&done_ccb->ccb_h.cbfcnp);
		return;
	}
	}
	xpt_release_ccb(done_ccb);
}


/*
 * Mount the tape (make sure it's ready for I/O).
 */
static int
samount(struct cam_periph *periph, int oflags, dev_t dev)
{
	struct	sa_softc *softc;
	union	ccb *ccb;
	struct	ccb_scsiio *csio;
	int	error;

	/*
	 * oflags can be checked for 'kind' of open (read-only check) - later
	 * dev can be checked for a control-mode or compression open - later
	 */
	UNUSED_PARAMETER(oflags);
	UNUSED_PARAMETER(dev);


	softc = (struct sa_softc *)periph->softc;
	ccb = cam_periph_getccb(periph, /* priority */1);
	csio = &ccb->csio;
	error = 0;

	/*
	 * Determine if something has happend since the last
	 * open/mount that would invalidate a mount.  This
	 * will also eat any pending UAs.
	 */
	scsi_test_unit_ready(csio,
			     /*retries*/1,
			     sadone,
			     MSG_SIMPLE_Q_TAG,
			     SSD_FULL_SIZE,
			     /*timeout*/5000);

	cam_periph_runccb(ccb, /*error handler*/NULL, /*cam_flags*/0,
			  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0) {	
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
		softc->flags &= ~SA_FLAG_TAPE_MOUNTED;
	}

	if ((softc->flags & SA_FLAG_TAPE_MOUNTED) == 0) {
		struct	scsi_read_block_limits_data *rblim;
		int	comp_enabled, comp_supported;
		u_int8_t write_protect, guessing = 0;

		/*
		 * Clear out old state.
		 */
		softc->flags &= ~(SA_FLAG_TAPE_WP|SA_FLAG_TAPE_WRITTEN|
				  SA_FLAG_ERR_PENDING|SA_FLAG_COMP_ENABLED|
				  SA_FLAG_COMP_UNSUPP);
		softc->filemarks = 0;

		/*
		 * First off, determine block limits.
		 */
		rblim = (struct  scsi_read_block_limits_data *)
		    malloc(sizeof(*rblim), M_TEMP, M_WAITOK);

		scsi_read_block_limits(csio,
				       /*retries*/1,
				       sadone,
				       MSG_SIMPLE_Q_TAG,
				       rblim,
				       SSD_FULL_SIZE,
				       /*timeout*/5000);

		error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
					  /*sense_flags*/SF_RETRY_UA,
					  &softc->device_stats);

		xpt_release_ccb(ccb);

		if (error != 0) {
			/*
			 * If it's less than SCSI-2, READ BLOCK LIMITS is not
			 * a MANDATORY command. Anyway- it doesn't matter-
			 * we can proceed anyway.
			 */
			softc->blk_gran = 0;
			softc->max_blk = ~0;
			softc->min_blk = 0;
		} else {
			if (softc->scsi_rev >= SCSI_REV_3) {
				softc->blk_gran = RBL_GRAN(rblim);
			} else {
				softc->blk_gran = 0;
			}
			/*
			 * We take max_blk == min_blk to mean a default to
			 * fixed mode- but note that whatever we get out of
			 * sagetparams below will actually determine whether
			 * we are actually *in* fixed mode.
			 */
			softc->max_blk = scsi_3btoul(rblim->maximum);
			softc->min_blk = scsi_2btoul(rblim->minimum);


		}
		/*
		 * Next, perform a mode sense to determine
		 * current density, blocksize, compression etc.
		 */
		error = sagetparams(periph, SA_PARAM_ALL,
				    &softc->media_blksize,
				    &softc->media_density,
				    &softc->media_numblks,
				    &softc->buffer_mode, &write_protect,
				    &softc->speed, &comp_supported,
				    &comp_enabled, &softc->comp_algorithm,
				    NULL);

		if (error != 0) {
			/*
			 * We could work a little harder here. We could
			 * adjust our attempts to get information. It
			 * might be an ancient tape drive. If someone
			 * nudges us, we'll do that.
			 */
			goto exit;
		}

		/*
		 * If no quirk has determined that this is a device that is
		 * preferred to be in fixed or variable mode, now is the time
		 * to find out.
	 	 */
		if ((softc->quirks & (SA_QUIRK_FIXED|SA_QUIRK_VARIABLE)) == 0) {
			guessing = 1;
			switch (softc->media_density) {
			case SCSI_DENSITY_QIC_11_4TRK:
			case SCSI_DENSITY_QIC_11_9TRK:
			case SCSI_DENSITY_QIC_24:
			case SCSI_DENSITY_QIC_120:
			case SCSI_DENSITY_QIC_150:
				softc->quirks |= SA_QUIRK_FIXED;
				softc->last_media_blksize = 512;
				break;
			default:
				softc->last_media_blksize =
				    softc->media_blksize;
				softc->quirks |= SA_QUIRK_VARIABLE;
				break;
			}
		}
		/*
		 * If no quirk has determined that this is a device that needs
		 * to have 2 Filemarks at EOD, now is the time to find out.
		 */
		if ((softc->quirks & SA_QUIRK_2FM) != 0) {
			switch (softc->media_density) {
			case SCSI_DENSITY_HALFINCH_800:
			case SCSI_DENSITY_HALFINCH_1600:
			case SCSI_DENSITY_HALFINCH_6250:
			case SCSI_DENSITY_HALFINCH_6250C:
			case SCSI_DENSITY_HALFINCH_PE:
				softc->quirks |= SA_QUIRK_2FM;
				break;
			default:
				break;
			}
		}

		/*
		 * Now validate that some info we got makes sense.
		 */

		if ((softc->max_blk < softc->media_blksize) ||
		    (softc->min_blk > softc->media_blksize &&
		    softc->media_blksize)) {
			xpt_print_path(ccb->ccb_h.path);
			printf("BLOCK LIMITS (%d..%d) could not match current "
			    "block settings (%d)- adjusting\n", softc->min_blk,
			    softc->max_blk, softc->media_blksize);
			softc->max_blk = softc->min_blk =
			    softc->media_blksize;
		}

		/*
		 * Now put ourselves into the right frame of mind based
		 * upon quirks...
		 */
tryagain:
		if ((softc->quirks & SA_QUIRK_FIXED) &&
		    (softc->media_blksize == 0)) {
			softc->media_blksize = softc->last_media_blksize;
			if (softc->media_blksize == 0) {
				softc->media_blksize = BLKDEV_IOSIZE;
				if (softc->media_blksize < softc->min_blk) {
					softc->media_blksize = softc->min_blk;
				}
			}
			error = sasetparams(periph, SA_PARAM_BLOCKSIZE,
			    softc->media_blksize, 0, 0);
			if (error) {
				xpt_print_path(ccb->ccb_h.path);
				printf("unable to set fixed blocksize to %d\n",
				     softc->media_blksize);
				goto exit;
			}
		}

		if ((softc->quirks & SA_QUIRK_VARIABLE) && 
		    (softc->media_blksize != 0)) {
			softc->last_media_blksize = softc->media_blksize;
			softc->media_blksize = 0;
			error = sasetparams(periph, SA_PARAM_BLOCKSIZE,
			    0, 0, 0);
			if (error) {
				/*
				 * If this fails and we were guessing, just
				 * assume that we got it wrong and go try
				 * fixed block mode...
				 */
				xpt_print_path(ccb->ccb_h.path);
				if (guessing && softc->media_density ==
				    SCSI_DEFAULT_DENSITY) {
					softc->quirks &= ~SA_QUIRK_VARIABLE;
					softc->quirks |= SA_QUIRK_FIXED;
					if (softc->last_media_blksize == 0)
						softc->last_media_blksize = 512;
					goto tryagain;
				}
				printf("unable to set variable blocksize\n");
				goto exit;
			}
		}

		/*
		 * Now that we have the current block size,
		 * set up some parameters for sastart's usage.
		 */
		if (softc->media_blksize) {
			softc->flags |= SA_FLAG_FIXED;
			if (powerof2(softc->media_blksize)) {
				softc->blk_shift =
				    ffs(softc->media_blksize) - 1;
				softc->blk_mask = softc->media_blksize - 1;
			} else {
				softc->blk_mask = ~0;
				softc->blk_shift = 0;
			}
		} else {
			/*
			 * The SCSI-3 spec allows 0 to mean "unspecified".
			 * The SCSI-1 spec allows 0 to mean 'infinite'.
			 *
			 * Either works here.
			 */
			if (softc->max_blk == 0) {
				softc->max_blk = ~0;
			}
			softc->blk_shift = 0;
			if (softc->blk_gran != 0) {
				softc->blk_mask = softc->blk_gran - 1;
			} else {
				softc->blk_mask = 0;
			}
		}

		if (write_protect) 
			softc->flags |= SA_FLAG_TAPE_WP;

		if (comp_supported) {
			if (comp_enabled) {
				softc->flags |= SA_FLAG_COMP_ENABLED;

				if (softc->saved_comp_algorithm == 0)
					softc->saved_comp_algorithm =
						softc->comp_algorithm;
			}
		} else
			softc->flags |= SA_FLAG_COMP_UNSUPP;

		if (softc->buffer_mode == SMH_SA_BUF_MODE_NOBUF) {
			error = sasetparams(periph, SA_PARAM_BUFF_MODE, 0,
			    0, 0);
			if (error == 0)
				softc->buffer_mode = SMH_SA_BUF_MODE_SIBUF;
		}


		if (error == 0)
			softc->flags |= SA_FLAG_TAPE_MOUNTED;
exit:
		if (rblim != NULL)
			free(rblim, M_TEMP);

		if (error != 0) {
			cam_release_devq(ccb->ccb_h.path,
					 /*relsim_flags*/0,
					 /*reduction*/0, 
					 /*timeout*/0,
					 /*getcount_only*/0);
		}
	} else
		xpt_release_ccb(ccb);

	return (error);
}

static int
sacheckeod(struct cam_periph *periph)
{
	int	error;
	int	markswanted;
	struct	sa_softc *softc;

	softc = (struct sa_softc *)periph->softc;
	markswanted = 0;

	if ((softc->flags & SA_FLAG_TAPE_WRITTEN) != 0) {
		markswanted++;
		if ((softc->quirks & SA_QUIRK_2FM) != 0)
			markswanted++;
	}

	if (softc->filemarks < markswanted) {
		markswanted -= softc->filemarks;
		error = sawritefilemarks(periph, markswanted, FALSE);
	} else {
		error = 0;
	}
	return (error);
}

static int
saerror(union ccb *ccb, u_int32_t cam_flags, u_int32_t sense_flags)
{
	struct	cam_periph *periph;
	struct	sa_softc *softc;
	struct	ccb_scsiio *csio;
	struct	scsi_sense_data *sense;
	u_int32_t info, resid;
	int	error_code, sense_key, asc, ascq;
	int	error;

	periph = xpt_path_periph(ccb->ccb_h.path);
	softc = (struct sa_softc *)periph->softc;
	csio = &ccb->csio;
	sense = &csio->sense_data;
	scsi_extract_sense(sense, &error_code, &sense_key, &asc, &ascq);
	error = 0;
	if ((csio->ccb_h.status & CAM_STATUS_MASK) == CAM_SCSI_STATUS_ERROR) {
		if ((sense->error_code & SSD_ERRCODE_VALID) != 0) {
			info = scsi_4btoul(sense->info);
			resid = info;
			if ((softc->flags & SA_FLAG_FIXED) != 0)
				resid *= softc->media_blksize;
		} else {
			resid = csio->dxfer_len;
			info = resid;
			if ((softc->flags & SA_FLAG_FIXED) != 0) {
				if (softc->media_blksize)
					info /= softc->media_blksize;
			}
		}
		if (csio->ccb_h.ccb_type == SA_CCB_BUFFER_IO) {
			bcopy((caddr_t) sense, (caddr_t) &softc->last_io_sense,
			    sizeof (struct scsi_sense_data));
			bcopy(csio->cdb_io.cdb_bytes, softc->last_io_cdb,
			    (int) csio->cdb_len);
			softc->last_io_resid = resid;
		} else {
			bcopy((caddr_t) sense, (caddr_t) &softc->last_ctl_sense,
			    sizeof (struct scsi_sense_data));
			bcopy(csio->cdb_io.cdb_bytes, softc->last_ctl_cdb,
			    (int) csio->cdb_len);
			softc->last_ctl_resid = resid;
		}
	}

	if (((csio->ccb_h.status & CAM_STATUS_MASK) == CAM_SCSI_STATUS_ERROR)
	 && ((sense->flags & (SSD_EOM|SSD_FILEMARK|SSD_ILI)) != 0)
	 && ((sense_key == SSD_KEY_NO_SENSE)
	  || (sense_key == SSD_KEY_BLANK_CHECK))) {
		int	defer_action;

		CAM_DEBUG(periph->path, CAM_DEBUG_INFO,
		    ("Key 0x%x ASC/ASCQ 0x%x 0x%x flags 0x%x resid %d "
		    "dxfer_len %d\n", sense_key, asc, ascq,
		    sense->flags & ~SSD_KEY_RESERVED, resid,
		    csio->dxfer_len));
		 
		if (resid > 0 && resid < csio->dxfer_len &&
		    (softc->flags & SA_FLAG_FIXED) != 0)
			defer_action = TRUE;
		else
			defer_action = FALSE;

		if ((sense->flags & SSD_EOM) != 0
		 || (sense_key == 0x8 /* BLANK CHECK*/)) {
			csio->resid = resid;
			if (defer_action) {
				softc->flags |= SA_FLAG_EOM_PENDING;
			} else {
				if (csio->cdb_io.cdb_bytes[0] == SA_WRITE)
					error = ENOSPC;
			}
		}
		if ((sense->flags & SSD_FILEMARK) != 0) {
			csio->resid = resid;
			if (defer_action)
				softc->flags |= SA_FLAG_EOF_PENDING;
		}
		if (sense->flags & SSD_ILI) {
			if (info < 0) {
				/*
				 * The record was too big.
				 */
				xpt_print_path(csio->ccb_h.path);
				printf("%d-byte tape record bigger "
				       "than suplied read buffer\n",
				       csio->dxfer_len - info);
				csio->resid = csio->dxfer_len;
				error = EIO;
			} else {
				csio->resid = resid;
				if ((softc->flags & SA_FLAG_FIXED) != 0) {
					if (defer_action)
						softc->flags |=
						    SA_FLAG_EIO_PENDING;
					else
						error = EIO;
				}
			}
		}
	}
	if (error == 0)
		error = cam_periph_error(ccb, cam_flags, sense_flags,
					 &softc->saved_ccb);

	return (error);
}

static int
sagetparams(struct cam_periph *periph, sa_params params_to_get,
	    u_int32_t *blocksize, u_int8_t *density, u_int32_t *numblocks,
	    int *buff_mode, u_int8_t *write_protect, u_int8_t *speed,
	    int *comp_supported, int *comp_enabled, u_int32_t *comp_algorithm,
	    struct scsi_data_compression_page *comp_page)
{
	union ccb *ccb;
	void *mode_buffer;
	struct scsi_mode_header_6 *mode_hdr;
	struct scsi_mode_blk_desc *mode_blk;
	struct scsi_data_compression_page *ncomp_page;
	int mode_buffer_len;
	struct sa_softc *softc;
	int error;
	cam_status status;

	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/ 1);

retry:
	mode_buffer_len = sizeof(*mode_hdr) + sizeof(*mode_blk);

	if (params_to_get & SA_PARAM_COMPRESSION) {
		if (softc->quirks & SA_QUIRK_NOCOMP) {
			*comp_supported = FALSE;
			params_to_get &= ~SA_PARAM_COMPRESSION;
		} else
			mode_buffer_len +=
				sizeof(struct scsi_data_compression_page);
	}

	mode_buffer = malloc(mode_buffer_len, M_TEMP, M_WAITOK);

	bzero(mode_buffer, mode_buffer_len);

	mode_hdr = (struct scsi_mode_header_6 *)mode_buffer;
	mode_blk = (struct scsi_mode_blk_desc *)&mode_hdr[1];

	if (params_to_get & SA_PARAM_COMPRESSION)
		ncomp_page = (struct scsi_data_compression_page *)&mode_blk[1];
	else
		ncomp_page = NULL;

	scsi_mode_sense(&ccb->csio,
			/*retries*/ 1,
			/*cbfcnp*/ sadone,
			/*tag_action*/ MSG_SIMPLE_Q_TAG,
			/*dbd*/ FALSE,
			/*page_code*/ SMS_PAGE_CTRL_CURRENT,
			/*page*/ (params_to_get & SA_PARAM_COMPRESSION) ?
				  SA_DATA_COMPRESSION_PAGE :
				  SMS_VENDOR_SPECIFIC_PAGE,
			/*param_buf*/ mode_buffer,
			/*param_len*/ mode_buffer_len,
			/*sense_len*/ SSD_FULL_SIZE,
			/*timeout*/ 5000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/ 0,
				  /*sense_flags*/SF_NO_PRINT,
				  &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /* relsim_flags */0,
				 /* opening_reduction */0,
				 /* timeout */0,
				 /* getcount_only */ FALSE);

	status = ccb->ccb_h.status & CAM_STATUS_MASK;

	if (error == EINVAL
	 && (params_to_get & SA_PARAM_COMPRESSION) != 0) {
		/*
		 * Most likely doesn't support the compression
		 * page.  Remember this for the future and attempt
		 * the request without asking for compression info.
		 */
		softc->quirks |= SA_QUIRK_NOCOMP;
		free(mode_buffer, M_TEMP);
		goto retry;
	} else if (error == 0) {
		struct scsi_data_compression_page *temp_comp_page;

		temp_comp_page = NULL;

		/*
		 * If the user only wants the compression information, and
		 * the device doesn't send back the block descriptor, it's
		 * no big deal.  If the user wants more than just
		 * compression, though, and the device doesn't pass back the
		 * block descriptor, we need to send another mode sense to
		 * get the block descriptor.
		 */
		if ((mode_hdr->blk_desc_len == 0) 
		 && (params_to_get & SA_PARAM_COMPRESSION)
		 && ((params_to_get & ~(SA_PARAM_COMPRESSION)) != 0)) {

			/*
			 * Decrease the mode buffer length by the size of
			 * the compression page, to make sure the data
			 * there doesn't get overwritten.
			 */
			mode_buffer_len -= sizeof(*ncomp_page);

			/*
			 * Now move the compression page that we presumably
			 * got back down the memory chunk a little bit so
			 * it doesn't get spammed.
			 */
			temp_comp_page =
			      (struct scsi_data_compression_page *)&mode_hdr[1];
			bcopy(temp_comp_page, ncomp_page, sizeof(*ncomp_page));

			/*
			 * Now, we issue another mode sense and just ask
			 * for the block descriptor, etc.
			 */
			scsi_mode_sense(&ccb->csio,
					/*retries*/ 1,
					/*cbfcnp*/ sadone,
					/*tag_action*/ MSG_SIMPLE_Q_TAG,
					/*dbd*/ FALSE,
					/*page_code*/ SMS_PAGE_CTRL_CURRENT,
					/*page*/ SMS_VENDOR_SPECIFIC_PAGE,
					/*param_buf*/ mode_buffer,
					/*param_len*/ mode_buffer_len,
					/*sense_len*/ SSD_FULL_SIZE,
					/*timeout*/ 5000);

			error = cam_periph_runccb(ccb, saerror, /*cam_flags*/ 0,
						  /*sense_flags*/ 0,
						  &softc->device_stats);

			if (error != 0)
				goto sagetparamsexit;

		}

		if (params_to_get & SA_PARAM_BLOCKSIZE)
			*blocksize = scsi_3btoul(mode_blk->blklen);

		if (params_to_get & SA_PARAM_NUMBLOCKS)
			*numblocks = scsi_3btoul(mode_blk->nblocks);

		if (params_to_get & SA_PARAM_BUFF_MODE)
			*buff_mode = mode_hdr->dev_spec & SMH_SA_BUF_MODE_MASK;

		if (params_to_get & SA_PARAM_DENSITY)
			*density = mode_blk->density;

		if (params_to_get & SA_PARAM_WP)
			*write_protect = (mode_hdr->dev_spec & SMH_SA_WP) ?
					 TRUE : FALSE;
		if (params_to_get & SA_PARAM_SPEED)
			*speed = mode_hdr->dev_spec & SMH_SA_SPEED_MASK;

		if (params_to_get & SA_PARAM_COMPRESSION) {
			*comp_supported =(ncomp_page->dce_and_dcc & SA_DCP_DCC)?
					 TRUE : FALSE;
			*comp_enabled = (ncomp_page->dce_and_dcc & SA_DCP_DCE)?
					TRUE : FALSE;
			*comp_algorithm =
				scsi_4btoul(ncomp_page->comp_algorithm);
			if (comp_page != NULL)
				bcopy(ncomp_page, comp_page,sizeof(*comp_page));
		}

		if (CAM_DEBUGGED(periph->path, CAM_DEBUG_INFO)) {
			int idx;
			char *xyz = mode_buffer;
			xpt_print_path(periph->path);
			printf("Mode Sense Data=");
			for (idx = 0; idx < mode_buffer_len; idx++)
				printf(" 0x%02x", xyz[idx] & 0xff);
			printf("\n");
		}
	} else if (status == CAM_SCSI_STATUS_ERROR) {
		/* Tell the user about the fatal error. */
		scsi_sense_print(&ccb->csio);
	}

sagetparamsexit:

	xpt_release_ccb(ccb);
	free(mode_buffer, M_TEMP);
	return(error);
}

/*
 * The purpose of this function is to set one of four different parameters
 * for a tape drive:
 *	- blocksize
 *	- density
 *	- compression / compression algorithm
 *	- buffering mode
 *
 * The assumption is that this will be called from saioctl(), and therefore
 * from a process context.  Thus the waiting malloc calls below.  If that
 * assumption ever changes, the malloc calls should be changed to be
 * NOWAIT mallocs.
 *
 * Any or all of the four parameters may be set when this function is
 * called.  It should handle setting more than one parameter at once.
 */
static int
sasetparams(struct cam_periph *periph, sa_params params_to_set,
	    u_int32_t blocksize, u_int8_t density, u_int32_t comp_algorithm)
{
	struct sa_softc *softc;
	u_int32_t current_blocksize;
	u_int32_t current_comp_algorithm;
	u_int8_t current_density;
	u_int8_t current_speed;
	int comp_enabled, comp_supported;
	void *mode_buffer;
	int mode_buffer_len;
	struct scsi_mode_header_6 *mode_hdr;
	struct scsi_mode_blk_desc *mode_blk;
	struct scsi_data_compression_page *comp_page;
	struct scsi_data_compression_page *current_comp_page;
	int buff_mode;
	union ccb *ccb;
	int error;

	softc = (struct sa_softc *)periph->softc;

	/* silence the compiler */
	ccb = NULL;

	current_comp_page = malloc(sizeof(*current_comp_page),M_TEMP, M_WAITOK);

	/*
	 * Since it doesn't make sense to set the number of blocks, or
	 * write protection, we won't try to get the current value.  We
	 * always want to get the blocksize, so we can set it back to the
	 * proper value.
	 */
	error = sagetparams(periph, params_to_set | SA_PARAM_BLOCKSIZE |
			    SA_PARAM_SPEED, &current_blocksize,
			    &current_density, NULL, &buff_mode, NULL,
			    &current_speed, &comp_supported, &comp_enabled,
			    &current_comp_algorithm, current_comp_page);

	if (error != 0) {
		free(current_comp_page, M_TEMP);
		return(error);
	}

	mode_buffer_len = sizeof(*mode_hdr) + sizeof(*mode_blk);
	if (params_to_set & SA_PARAM_COMPRESSION)
		mode_buffer_len += sizeof(struct scsi_data_compression_page);

	mode_buffer = malloc(mode_buffer_len, M_TEMP, M_WAITOK);

	bzero(mode_buffer, mode_buffer_len);

	mode_hdr = (struct scsi_mode_header_6 *)mode_buffer;
	mode_blk = (struct scsi_mode_blk_desc *)&mode_hdr[1];

	if (params_to_set & SA_PARAM_COMPRESSION) {
		comp_page = (struct scsi_data_compression_page *)&mode_blk[1];
		bcopy(current_comp_page, comp_page, sizeof(*comp_page));
	} else
		comp_page = NULL;

	/*
	 * If the caller wants us to set the blocksize, use the one they
	 * pass in.  Otherwise, use the blocksize we got back from the
	 * mode select above.
	 */
	if (params_to_set & SA_PARAM_BLOCKSIZE)
		scsi_ulto3b(blocksize, mode_blk->blklen);
	else
		scsi_ulto3b(current_blocksize, mode_blk->blklen);

	/*
	 * Set density if requested, else preserve old density.
	 * SCSI_SAME_DENSITY only applies to SCSI-2 or better
	 * devices, else density we've latched up in our softc.
	 */
	if (params_to_set & SA_PARAM_DENSITY) {
		mode_blk->density = density;
	} else if (softc->scsi_rev > SCSI_REV_CCS) {
		mode_blk->density = SCSI_SAME_DENSITY;
	} else {
		mode_blk->density = softc->media_density;
	}

	/*
	 * For mode selects, these two fields must be zero.
	 */
	mode_hdr->data_length = 0;
	mode_hdr->medium_type = 0;

	/* set the speed to the current value */
	mode_hdr->dev_spec = current_speed;

	/* set single-initiator buffering mode */
	mode_hdr->dev_spec |= SMH_SA_BUF_MODE_SIBUF;

	mode_hdr->blk_desc_len = sizeof(struct scsi_mode_blk_desc);

	/*
	 * First, if the user wants us to set the compression algorithm or
	 * just turn compression on, check to make sure that this drive
	 * supports compression.
	 */
	if ((params_to_set & SA_PARAM_COMPRESSION) 
	 && (current_comp_page->dce_and_dcc & SA_DCP_DCC)) {

		/*
		 * If the compression algorithm is 0, disable compression.
		 * If the compression algorithm is non-zero, enable
		 * compression and set the compression type to the
		 * specified compression algorithm, unless the algorithm is
		 * MT_COMP_ENABLE.  In that case, we look at the
		 * compression algorithm that is currently set and if it is
		 * non-zero, we leave it as-is.  If it is zero, and we have
		 * saved a compression algorithm from a time when
		 * compression was enabled before, set the compression to
		 * the saved value.
		 */
		if (comp_algorithm == 0) {
			/* disable compression */
			comp_page->dce_and_dcc &= ~SA_DCP_DCE;
		} else {
			/* enable compression */
			comp_page->dce_and_dcc |= SA_DCP_DCE;

			/* enable decompression */
			comp_page->dde_and_red |= SA_DCP_DDE;

			if (comp_algorithm != MT_COMP_ENABLE) {
				/* set the compression algorithm */
				scsi_ulto4b(comp_algorithm,
					    comp_page->comp_algorithm);

			} else if ((scsi_4btoul(comp_page->comp_algorithm) == 0)
				&& (softc->saved_comp_algorithm != 0)) {
				scsi_ulto4b(softc->saved_comp_algorithm,
					    comp_page->comp_algorithm);
			}
		}
	} else if (params_to_set & SA_PARAM_COMPRESSION) {
		/*
		 * The drive doesn't support compression, so turn off the
		 * set compression bit.
		 */
		params_to_set &= ~SA_PARAM_COMPRESSION;


		/*
		 * Should probably do something other than a printf...like
		 * set a flag in the softc saying that this drive doesn't
		 * support compression.
		 */
		xpt_print_path(periph->path);
		printf("sasetparams: device does not support compression\n");

		/*
		 * If that was the only thing the user wanted us to set,
		 * clean up allocated resources and return with 'operation
		 * not supported'.
		 */
		if (params_to_set == SA_PARAM_NONE) {
			free(mode_buffer, M_TEMP);
			return(ENODEV);
		}
	
		/*
		 * That wasn't the only thing the user wanted us to set.
		 * So, decrease the stated mode buffer length by the size
		 * of the compression mode page.
		 */
		mode_buffer_len -= sizeof(*comp_page);
	}

	ccb = cam_periph_getccb(periph, /*priority*/ 1);


	scsi_mode_select(&ccb->csio,
			/*retries*/1,
			/*cbfcnp*/ sadone,
			/*tag_action*/ MSG_SIMPLE_Q_TAG,
			/*scsi_page_fmt*/(params_to_set & SA_PARAM_COMPRESSION)?
					 TRUE : FALSE,
			/*save_pages*/ FALSE,
			/*param_buf*/ mode_buffer,
			/*param_len*/ mode_buffer_len,
			/*sense_len*/ SSD_FULL_SIZE,
			/*timeout*/ 5000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/ 0,
				  /*sense_flags*/ 0, &softc->device_stats);

	if (CAM_DEBUGGED(periph->path, CAM_DEBUG_INFO) ||
	    params_to_set == SA_PARAM_BUFF_MODE) {
		int idx;
		char *xyz = mode_buffer;
		xpt_print_path(periph->path);
		printf("Err%d, Mode Select Data=", error);
		for (idx = 0; idx < mode_buffer_len; idx++)
			printf(" 0x%02x", xyz[idx] & 0xff);
		printf("\n");
	}


	if (error == 0) {
		xpt_release_ccb(ccb);
	} else {
		if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
			cam_release_devq(ccb->ccb_h.path, 0, 0, 0, 0);

		/*
		 * If we were setting the blocksize, and that failed, we
		 * want to set it to its original value.  If we weren't
		 * setting the blocksize, we don't want to change it.
		 */
		scsi_ulto3b(current_blocksize, mode_blk->blklen);

		/*
		 * Set density if requested, else preserve old density.
		 * SCSI_SAME_DENSITY only applies to SCSI-2 or better
		 * devices, else density we've latched up in our softc.
		 */
		if (params_to_set & SA_PARAM_DENSITY) {
			mode_blk->density = current_density;
		} else if (softc->scsi_rev > SCSI_REV_CCS) {
			mode_blk->density = SCSI_SAME_DENSITY;
		} else {
			mode_blk->density = softc->media_density;
		}

		if (params_to_set & SA_PARAM_COMPRESSION)
			bcopy(current_comp_page, comp_page,
			      sizeof(struct scsi_data_compression_page));

		/*
		 * The retry count is the only CCB field that might have been
		 * changed that we care about, so reset it back to 1.
		 */
		ccb->ccb_h.retry_count = 1;
		cam_periph_runccb(ccb, saerror, 0, 0, &softc->device_stats);

		if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
			cam_release_devq(ccb->ccb_h.path, 0, 0, 0, 0);

		xpt_release_ccb(ccb);
	}

	if (current_comp_page != NULL)
		free(current_comp_page, M_TEMP);

	if (params_to_set & SA_PARAM_COMPRESSION) {
		if (error) {
			softc->flags &= ~SA_FLAG_COMP_ENABLED;
			softc->saved_comp_algorithm = softc->comp_algorithm;
			softc->comp_algorithm = 0;
		} else {
			softc->flags |= SA_FLAG_COMP_ENABLED;
			softc->comp_algorithm = comp_algorithm;
		}
	}

	free(mode_buffer, M_TEMP);
	return(error);
}

static void
saprevent(struct cam_periph *periph, int action)
{
	struct	sa_softc *softc;
	union	ccb *ccb;		
	int	error;
		
	softc = (struct sa_softc *)periph->softc;

	if (((action == PR_ALLOW)
	  && (softc->flags & SA_FLAG_TAPE_LOCKED) == 0)
	 || ((action == PR_PREVENT)
	  && (softc->flags & SA_FLAG_TAPE_LOCKED) != 0)) {
		return;
	}

	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_prevent(&ccb->csio,
		     /*retries*/0,
		     /*cbcfp*/sadone,
		     MSG_SIMPLE_Q_TAG,
		     action,
		     SSD_FULL_SIZE,
		     60000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
		

	if (error == 0) {
		if (action == PR_ALLOW)
			softc->flags &= ~SA_FLAG_TAPE_LOCKED;
		else
			softc->flags |= SA_FLAG_TAPE_LOCKED;
	}

	xpt_release_ccb(ccb);
}

static int
sarewind(struct cam_periph *periph)
{
	union	ccb *ccb;
	struct	sa_softc *softc;
	int	error;
		
	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_rewind(&ccb->csio,
		    /*retries*/1,
		    /*cbcfp*/sadone,
		    MSG_SIMPLE_Q_TAG,
		    /*immediate*/FALSE,
		    SSD_FULL_SIZE,
		    (SA_REWIND_TIMEOUT) * 60 * 1000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
	xpt_release_ccb(ccb);
	return (error);
}

static int
saspace(struct cam_periph *periph, int count, scsi_space_code code)
{
	union	ccb *ccb;
	struct	sa_softc *softc;
	int	error;
		
	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_space(&ccb->csio,
		   /*retries*/1,
		   /*cbcfp*/sadone,
		   MSG_SIMPLE_Q_TAG,
		   code, count,
		   SSD_FULL_SIZE,
		   (SA_SPACE_TIMEOUT) * 60 * 1000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
	xpt_release_ccb(ccb);
	return (error);
}

static int
sawritefilemarks(struct cam_periph *periph, int nmarks, int setmarks)
{
	union	ccb *ccb;
	struct	sa_softc *softc;
	int	error;

	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_write_filemarks(&ccb->csio, 1, sadone, MSG_SIMPLE_Q_TAG,
	    FALSE, setmarks, nmarks, SSD_FULL_SIZE, 60000);

	error = cam_periph_runccb(ccb, saerror, 0, 0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path, 0, 0, 0, 0);

	/*
	 * XXXX: Actually, we need to get back the actual number of filemarks
	 * XXXX: written (there can be a residual).
	 */
	if (error == 0 && nmarks) {
		struct sa_softc *softc = (struct sa_softc *)periph->softc;
		softc->filemarks += nmarks;
	}
	xpt_release_ccb(ccb);
	return (error);
}

static int
sardpos(struct cam_periph *periph, int hard, u_int32_t *blkptr)
{
	struct scsi_tape_position_data loc;
	union ccb *ccb;
	struct sa_softc *softc;
	int error;

	/*
	 * First flush any pending writes...
	 */
	error = sawritefilemarks(periph, 0, 0);

	/*
	 * The latter case is for 'write protected' tapes
	 * which are too stupid to recognize a zero count
	 * for writing filemarks as a no-op.
	 */
	if (error != 0 && error != EACCES)
		return (error);

	softc = (struct sa_softc *)periph->softc;
	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_read_position(&ccb->csio, 1, sadone, MSG_SIMPLE_Q_TAG,
	    hard, &loc, SSD_FULL_SIZE, 5000);
	error = cam_periph_runccb(ccb, saerror, 0, 0, &softc->device_stats);
	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path, 0, 0, 0, 0);

	if (error == 0) {
		if (loc.flags & SA_RPOS_UNCERTAIN) {
			error = EINVAL;		/* nothing is certain */
		} else {
			*blkptr = scsi_4btoul(loc.firstblk);
		}
	}

	xpt_release_ccb(ccb);
	return (error);
}

static int
sasetpos(struct cam_periph *periph, int hard, u_int32_t *blkptr)
{
	union ccb *ccb;
	struct sa_softc *softc;
	int error;

	/*
	 * First flush any pending writes...
	 */
	error = sawritefilemarks(periph, 0, 0);

	/*
	 * The latter case is for 'write protected' tapes
	 * which are too stupid to recognize a zero count
	 * for writing filemarks as a no-op.
	 */
	if (error != 0 && error != EACCES)
		return (error);

	softc = (struct sa_softc *)periph->softc;
	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_set_position(&ccb->csio, 1, sadone, MSG_SIMPLE_Q_TAG,
	    hard, *blkptr, SSD_FULL_SIZE, 60 * 60 * 1000);
	error = cam_periph_runccb(ccb, saerror, 0, 0, &softc->device_stats);
	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path, 0, 0, 0, 0);
	xpt_release_ccb(ccb);
	/*
	 * XXX: Note relative file && block number position now unknown (if
	 * XXX: these things ever start being maintained in this driver).
	 */
	return (error);
}


static int
saretension(struct cam_periph *periph)
{
	union ccb *ccb;
	struct sa_softc *softc;
	int error;

	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_load_unload(&ccb->csio,
			 /*retries*/ 1,
			 /*cbfcnp*/ sadone,
			 MSG_SIMPLE_Q_TAG,
			 /*immediate*/ FALSE,
			 /*eot*/ FALSE,
			 /*reten*/ TRUE,
			 /*load*/ TRUE,
			 SSD_FULL_SIZE,
			 60000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
	xpt_release_ccb(ccb);
	return(error);
}

static int
sareservereleaseunit(struct cam_periph *periph, int reserve)
{
	union ccb *ccb;
	struct sa_softc *softc;
	int error, sflags;

	softc = (struct sa_softc *)periph->softc;
	if (softc->quirks & SA_QUIRK_NORRLS)
		return (0);

	if (CAM_DEBUGGED(periph->path, CAM_DEBUG_INFO))
		sflags = SF_RETRY_UA;
	else
		sflags = SF_RETRY_UA|SF_QUIET_IR;
		
	ccb = cam_periph_getccb(periph, /*priority*/ 1);

	scsi_reserve_release_unit(&ccb->csio,
				  /*retries*/ 1,
				  /*cbfcnp*/ sadone,
				  /*tag_action*/ MSG_SIMPLE_Q_TAG,
				  /*third_party*/ FALSE,
				  /*third_party_id*/ 0,
				  /*sense_len*/ SSD_FULL_SIZE,
				  /*timeout*/ 5000,
				  reserve);

	/*
	 * We set SF_RETRY_UA, since this is often the first command run
	 * when a tape device is opened, and there may be a unit attention
	 * condition pending.
	 */
	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/sflags,
				  &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);

	xpt_release_ccb(ccb);

	/*
	 * If the error was Illegal Request, then the device doesn't support
	 * RESERVE/RELEASE. This is not an error.
	 */
	if (error == EINVAL) {
		softc->quirks |= SA_QUIRK_NORRLS;
		error = 0;
	}

	return (error);
}

static int
saloadunload(struct cam_periph *periph, int load)
{
	union	ccb *ccb;
	struct	sa_softc *softc;
	int	error;

	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/1);

	scsi_load_unload(&ccb->csio,
			 /*retries*/1,
			 /*cbfcnp*/sadone,
			 MSG_SIMPLE_Q_TAG,
			 /*immediate*/FALSE,
			 /*eot*/FALSE,
			 /*reten*/FALSE,
			 load,
			 SSD_FULL_SIZE,
			 60000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
	xpt_release_ccb(ccb);
	return (error);
}

static int
saerase(struct cam_periph *periph, int longerase)
{

	union	ccb *ccb;
	struct	sa_softc *softc;
	int error;

	softc = (struct sa_softc *)periph->softc;

	ccb = cam_periph_getccb(periph, /*priority*/ 1);

	scsi_erase(&ccb->csio,
		   /*retries*/ 1,
		   /*cbfcnp*/ sadone,
		   /*tag_action*/ MSG_SIMPLE_Q_TAG,
		   /*immediate*/ FALSE,
		   /*long_erase*/ longerase,
		   /*sense_len*/ SSD_FULL_SIZE,
		   /*timeout*/ (SA_ERASE_TIMEOUT) * 60 * 1000);

	error = cam_periph_runccb(ccb, saerror, /*cam_flags*/0,
				  /*sense_flags*/0, &softc->device_stats);

	if ((ccb->ccb_h.status & CAM_DEV_QFRZN) != 0)
		cam_release_devq(ccb->ccb_h.path,
				 /*relsim_flags*/0,
				 /*reduction*/0, 
				 /*timeout*/0,
				 /*getcount_only*/0);
	xpt_release_ccb(ccb);
	return (error);
}

#endif /* KERNEL */

/*
 * Read tape block limits command.
 */
void
scsi_read_block_limits(struct ccb_scsiio *csio, u_int32_t retries,
		   void (*cbfcnp)(struct cam_periph *, union ccb *),
		   u_int8_t tag_action,
		   struct scsi_read_block_limits_data *rlimit_buf,
		   u_int8_t sense_len, u_int32_t timeout)
{
	struct scsi_read_block_limits *scsi_cmd;

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/CAM_DIR_IN,
		      tag_action,
		      /*data_ptr*/(u_int8_t *)rlimit_buf,
		      /*dxfer_len*/sizeof(*rlimit_buf),
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);

	scsi_cmd = (struct scsi_read_block_limits *)&csio->cdb_io.cdb_bytes;
	bzero(scsi_cmd, sizeof(*scsi_cmd));
	scsi_cmd->opcode = READ_BLOCK_LIMITS;
}

void
scsi_sa_read_write(struct ccb_scsiio *csio, u_int32_t retries,
		   void (*cbfcnp)(struct cam_periph *, union ccb *),
		   u_int8_t tag_action, int readop, int sli,
		   int fixed, u_int32_t length, u_int8_t *data_ptr,
		   u_int32_t dxfer_len, u_int8_t sense_len, u_int32_t timeout)
{
	struct scsi_sa_rw *scsi_cmd;

	scsi_cmd = (struct scsi_sa_rw *)&csio->cdb_io.cdb_bytes;
	scsi_cmd->opcode = readop ? SA_READ : SA_WRITE;
	scsi_cmd->sli_fixed = 0;
	if (sli && readop)
		scsi_cmd->sli_fixed |= SAR_SLI;
	if (fixed)
		scsi_cmd->sli_fixed |= SARW_FIXED;
	scsi_ulto3b(length, scsi_cmd->length);
	scsi_cmd->control = 0;

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/readop ? CAM_DIR_IN : CAM_DIR_OUT,
		      tag_action,
		      data_ptr,
		      dxfer_len, 
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);
}

void
scsi_load_unload(struct ccb_scsiio *csio, u_int32_t retries,         
		 void (*cbfcnp)(struct cam_periph *, union ccb *),   
		 u_int8_t tag_action, int immediate, int eot,
		 int reten, int load, u_int8_t sense_len,
		 u_int32_t timeout)
{
	struct scsi_load_unload *scsi_cmd;

	scsi_cmd = (struct scsi_load_unload *)&csio->cdb_io.cdb_bytes;
	bzero(scsi_cmd, sizeof(*scsi_cmd));
	scsi_cmd->opcode = LOAD_UNLOAD;
	if (immediate)
		scsi_cmd->immediate = SLU_IMMED;
	if (eot)
		scsi_cmd->eot_reten_load |= SLU_EOT;
	if (reten)
		scsi_cmd->eot_reten_load |= SLU_RETEN;
	if (load)
		scsi_cmd->eot_reten_load |= SLU_LOAD;

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/CAM_DIR_NONE,
		      tag_action,
		      /*data_ptr*/NULL,
		      /*dxfer_len*/0,
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);	
}

void
scsi_rewind(struct ccb_scsiio *csio, u_int32_t retries,         
	    void (*cbfcnp)(struct cam_periph *, union ccb *),   
	    u_int8_t tag_action, int immediate, u_int8_t sense_len,     
	    u_int32_t timeout)
{
	struct scsi_rewind *scsi_cmd;

	scsi_cmd = (struct scsi_rewind *)&csio->cdb_io.cdb_bytes;
	bzero(scsi_cmd, sizeof(*scsi_cmd));
	scsi_cmd->opcode = REWIND;
	if (immediate)
		scsi_cmd->immediate = SREW_IMMED;
	
	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/CAM_DIR_NONE,
		      tag_action,
		      /*data_ptr*/NULL,
		      /*dxfer_len*/0,
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);
}

void
scsi_space(struct ccb_scsiio *csio, u_int32_t retries,
	   void (*cbfcnp)(struct cam_periph *, union ccb *),
	   u_int8_t tag_action, scsi_space_code code,
	   u_int32_t count, u_int8_t sense_len, u_int32_t timeout)
{
	struct scsi_space *scsi_cmd;

	scsi_cmd = (struct scsi_space *)&csio->cdb_io.cdb_bytes;
	scsi_cmd->opcode = SPACE;
	scsi_cmd->code = code;
	scsi_ulto3b(count, scsi_cmd->count);
	scsi_cmd->control = 0;

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/CAM_DIR_NONE,
		      tag_action,
		      /*data_ptr*/NULL,
		      /*dxfer_len*/0,
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);
}

void
scsi_write_filemarks(struct ccb_scsiio *csio, u_int32_t retries,
		     void (*cbfcnp)(struct cam_periph *, union ccb *),
		     u_int8_t tag_action, int immediate, int setmark,
		     u_int32_t num_marks, u_int8_t sense_len,
		     u_int32_t timeout)
{
	struct scsi_write_filemarks *scsi_cmd;

	scsi_cmd = (struct scsi_write_filemarks *)&csio->cdb_io.cdb_bytes;
	bzero(scsi_cmd, sizeof(*scsi_cmd));
	scsi_cmd->opcode = WRITE_FILEMARKS;
	if (immediate)
		scsi_cmd->byte2 |= SWFMRK_IMMED;
	if (setmark)
		scsi_cmd->byte2 |= SWFMRK_WSMK;
	
	scsi_ulto3b(num_marks, scsi_cmd->num_marks);

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/CAM_DIR_NONE,
		      tag_action,
		      /*data_ptr*/NULL,
		      /*dxfer_len*/0,
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);
}

/*
 * The reserve and release unit commands differ only by their opcodes.
 */
void
scsi_reserve_release_unit(struct ccb_scsiio *csio, u_int32_t retries,
			  void (*cbfcnp)(struct cam_periph *, union ccb *),
			  u_int8_t tag_action, int third_party,
			  int third_party_id, u_int8_t sense_len,
			  u_int32_t timeout, int reserve)
{
	struct scsi_reserve_release_unit *scsi_cmd;

	scsi_cmd = (struct scsi_reserve_release_unit *)&csio->cdb_io.cdb_bytes;
	bzero(scsi_cmd, sizeof(*scsi_cmd));

	if (reserve)
		scsi_cmd->opcode = RESERVE_UNIT;
	else
		scsi_cmd->opcode = RELEASE_UNIT;

	if (third_party) {
		scsi_cmd->lun_thirdparty |= SRRU_3RD_PARTY;
		scsi_cmd->lun_thirdparty |=
			((third_party_id << SRRU_3RD_SHAMT) & SRRU_3RD_MASK);
	}

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/ CAM_DIR_NONE,
		      tag_action,
		      /*data_ptr*/ NULL,
		      /*dxfer_len*/ 0,
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);
}

void
scsi_erase(struct ccb_scsiio *csio, u_int32_t retries,
	   void (*cbfcnp)(struct cam_periph *, union ccb *),
	   u_int8_t tag_action, int immediate, int long_erase,
	   u_int8_t sense_len, u_int32_t timeout)
{
	struct scsi_erase *scsi_cmd;

	scsi_cmd = (struct scsi_erase *)&csio->cdb_io.cdb_bytes;
	bzero(scsi_cmd, sizeof(*scsi_cmd));

	scsi_cmd->opcode = ERASE;

	if (immediate)
		scsi_cmd->lun_imm_long |= SE_IMMED;

	if (long_erase)
		scsi_cmd->lun_imm_long |= SE_LONG;

	cam_fill_csio(csio,
		      retries,
		      cbfcnp,
		      /*flags*/ CAM_DIR_NONE,
		      tag_action,
		      /*data_ptr*/ NULL,
		      /*dxfer_len*/ 0,
		      sense_len,
		      sizeof(*scsi_cmd),
		      timeout);
}

/*
 * Read Tape Position command.
 */
void
scsi_read_position(struct ccb_scsiio *csio, u_int32_t retries,
		   void (*cbfcnp)(struct cam_periph *, union ccb *),
		   u_int8_t tag_action, int hardsoft,
		   struct scsi_tape_position_data *sbp,
		   u_int8_t sense_len, u_int32_t timeout)
{
	struct scsi_tape_read_position *scmd;

	cam_fill_csio(csio, retries, cbfcnp, CAM_DIR_IN, tag_action,
	    (u_int8_t *)sbp, sizeof (*sbp), sense_len, sizeof(*scmd), timeout);
	scmd = (struct scsi_tape_read_position *)&csio->cdb_io.cdb_bytes;
	bzero(scmd, sizeof(*scmd));
	scmd->opcode = READ_POSITION;
	scmd->byte1 = hardsoft;
}

/*
 * Set Tape Position command.
 */
void
scsi_set_position(struct ccb_scsiio *csio, u_int32_t retries,
		   void (*cbfcnp)(struct cam_periph *, union ccb *),
		   u_int8_t tag_action, int hardsoft, u_int32_t blkno,
		   u_int8_t sense_len, u_int32_t timeout)
{
	struct scsi_tape_locate *scmd;

	cam_fill_csio(csio, retries, cbfcnp, CAM_DIR_NONE, tag_action,
	    (u_int8_t *)NULL, 0, sense_len, sizeof(*scmd), timeout);
	scmd = (struct scsi_tape_locate *)&csio->cdb_io.cdb_bytes;
	bzero(scmd, sizeof(*scmd));
	scmd->opcode = LOCATE;
	if (hardsoft)
		scmd->byte1 |= SA_SPOS_BT;
	scsi_ulto4b(blkno, scmd->blkaddr);
}
