/*
 * Copyright (c) 1997 Justin T. Gibbs.
 * Copyright (c) 1997, 1998 Kenneth D. Merry.
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
 *      $Id: scsi_cd.c,v 1.6 1998/10/12 17:02:37 ken Exp $
 */
/*
 * Portions of this driver taken from the original FreeBSD cd driver.
 * Written by Julian Elischer (julian@tfs.com)
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
 * Ported to run under 386BSD by Julian Elischer (julian@tfs.com) Sept 1992
 *
 *      from: cd.c,v 1.83 1997/05/04 15:24:22 joerg Exp $
 */

#include "opt_cd.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/buf.h>
#include <sys/dkbad.h>
#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/cdio.h>
#include <sys/devicestat.h>
#include <sys/sysctl.h>

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_extend.h>
#include <cam/cam_periph.h>
#include <cam/cam_xpt_periph.h>
#include <cam/cam_queue.h>

#include <cam/scsi/scsi_message.h>
#include <cam/scsi/scsi_da.h>
#include <cam/scsi/scsi_cd.h>

#define LEADOUT         0xaa            /* leadout toc entry */

struct cd_params {
	u_int32_t blksize;
	u_long    disksize;
};

typedef enum {
	CD_Q_NONE	= 0x00,
	CD_Q_NO_TOUCH	= 0x01,
	CD_Q_BCD_TRACKS	= 0x02,
	CD_Q_NO_CHANGER	= 0x04,
	CD_Q_CHANGER	= 0x08
} cd_quirks;

typedef enum {
	CD_FLAG_INVALID		= 0x001,
	CD_FLAG_NEW_DISC	= 0x002,
	CD_FLAG_DISC_LOCKED	= 0x004,
	CD_FLAG_DISC_REMOVABLE	= 0x008,
	CD_FLAG_TAGGED_QUEUING	= 0x010,
	CD_FLAG_OPEN		= 0x020,
	CD_FLAG_CHANGER		= 0x040,
	CD_FLAG_ACTIVE		= 0x080,
	CD_FLAG_SCHED_ON_COMP	= 0x100,
	CD_FLAG_RETRY_UA	= 0x200
} cd_flags;

typedef enum {
	CD_CCB_PROBE		= 0x01,
	CD_CCB_BUFFER_IO	= 0x02,
	CD_CCB_WAITING		= 0x03,
	CD_CCB_TYPE_MASK	= 0x0F,
	CD_CCB_RETRY_UA		= 0x10
} cd_ccb_state;

typedef enum {
	CHANGER_TIMEOUT_SCHED		= 0x01,
	CHANGER_SHORT_TMOUT_SCHED	= 0x02,
	CHANGER_MANUAL_CALL		= 0x04,
	CHANGER_NEED_TIMEOUT		= 0x08
} cd_changer_flags;

#define ccb_state ppriv_field0
#define ccb_bp ppriv_ptr1

typedef enum {
	CD_STATE_PROBE,
	CD_STATE_NORMAL
} cd_state;

struct cd_softc {
	cam_pinfo		pinfo;
	cd_state		state;
	cd_flags		flags;
	struct buf_queue_head	buf_queue;
	LIST_HEAD(, ccb_hdr)	pending_ccbs;
	struct cd_params	params;
	struct diskslices 	*cd_slices;
	union ccb		saved_ccb;
	cd_quirks		quirks;
	struct devstat		device_stats;
	STAILQ_ENTRY(cd_softc)	changer_links;
	struct cdchanger	*changer;
	int			bufs_left;
	struct cam_periph	*periph;
};

struct cd_quirk_entry {
	struct scsi_inquiry_pattern inq_pat;
	cd_quirks quirks;
};

/*
 * These quirk entries aren't strictly necessary.  Basically, what they do
 * is tell cdregister() up front that a device is a changer.  Otherwise, it
 * will figure that fact out once it sees a LUN on the device that is
 * greater than 0.  If it is known up front that a device is a changer, all
 * I/O to the device will go through the changer scheduling routines, as
 * opposed to the "normal" CD code.
 */
static struct cd_quirk_entry cd_quirk_table[] =
{
	{
		{ T_CDROM, SIP_MEDIA_REMOVABLE, "NRC", "MBR-7", "*"},
		 /*quirks*/ CD_Q_CHANGER
	},
	{
		{ T_CDROM, SIP_MEDIA_REMOVABLE, "PIONEER", "CD-ROM DRM-604X",
		  "*"}, /* quirks */ CD_Q_CHANGER
	},
	{
		{ T_CDROM, SIP_MEDIA_REMOVABLE, "CHINON", "CD-ROM CDS-535","*"},
		/* quirks */ CD_Q_BCD_TRACKS
	}
};

#ifndef MIN
#define MIN(x,y) ((x<y) ? x : y)
#endif

#define CD_CDEV_MAJOR 15
#define CD_BDEV_MAJOR 6

static	d_open_t	cdopen;
static	d_read_t	cdread;
static	d_close_t	cdclose;
static	d_ioctl_t	cdioctl;
static	d_strategy_t	cdstrategy;
static	d_strategy_t	cdstrategy1;

static	periph_init_t	cdinit;
static	periph_ctor_t	cdregister;
static	periph_dtor_t	cdcleanup;
static	periph_start_t	cdstart;
static	void		cdasync(void *callback_arg, u_int32_t code,
				struct cam_path *path, void *arg);
static	void		cdshorttimeout(void *arg);
static	void		cdschedule(struct cam_periph *periph, int priority);
static	void		cdrunchangerqueue(void *arg);
static	void		cdchangerschedule(struct cd_softc *softc);
static	int		cdrunccb(union ccb *ccb,
				 int (*error_routine)(union ccb *ccb,
						      u_int32_t cam_flags,
						      u_int32_t sense_flags),
				 u_int32_t cam_flags, u_int32_t sense_flags);
union	ccb 		*cdgetccb(struct cam_periph *periph,
				  u_int32_t priority);
static	void		cddone(struct cam_periph *periph,
			       union ccb *start_ccb);
static	int		cderror(union ccb *ccb, u_int32_t cam_flags,
				u_int32_t sense_flags);
static	void		cdprevent(struct cam_periph *periph, int action);
static	int		cdsize(dev_t dev, u_int32_t *size);
static	int		cdreadtoc(struct cam_periph *periph, u_int32_t mode, 
				  u_int32_t start, struct cd_toc_entry *data, 
				  u_int32_t len);
static	int		cdgetmode(struct cam_periph *periph, 
				  struct cd_mode_data *data, u_int32_t page);
static	int		cdsetmode(struct cam_periph *periph,
				  struct cd_mode_data *data);
static	int		cdplay(struct cam_periph *periph, u_int32_t blk, 
			       u_int32_t len);
static	int		cdreadsubchannel(struct cam_periph *periph, 
					 u_int32_t mode, u_int32_t format, 
					 int track, 
					 struct cd_sub_channel_info *data, 
					 u_int32_t len);
static	int		cdplaymsf(struct cam_periph *periph, u_int32_t startm, 
				  u_int32_t starts, u_int32_t startf, 
				  u_int32_t endm, u_int32_t ends, 
				  u_int32_t endf);
static	int		cdplaytracks(struct cam_periph *periph, 
				     u_int32_t strack, u_int32_t sindex,
				     u_int32_t etrack, u_int32_t eindex);
static	int		cdpause(struct cam_periph *periph, u_int32_t go);
static	int		cdstopunit(struct cam_periph *periph, u_int32_t eject);
static	int		cdstartunit(struct cam_periph *periph);

static struct periph_driver cddriver =
{
	cdinit, "cd",
	TAILQ_HEAD_INITIALIZER(cddriver.units), /* generation */ 0
};

DATA_SET(periphdriver_set, cddriver);

/* For 2.2-stable support */
#ifndef D_DISK
#define D_DISK 0
#endif
static struct cdevsw cd_cdevsw = 
{
	/*d_open*/	cdopen,
	/*d_close*/	cdclose,
	/*d_read*/	cdread,
	/*d_write*/	nowrite,
	/*d_ioctl*/	cdioctl,
	/*d_stop*/	nostop,
	/*d_reset*/	noreset,
	/*d_devtotty*/	nodevtotty,
	/*d_poll*/	seltrue,
	/*d_mmap*/	nommap,
	/*d_strategy*/	cdstrategy,
	/*d_name*/	"cd",
	/*d_spare*/	NULL,
	/*d_maj*/	-1,
	/*d_dump*/	nodump,
	/*d_psize*/	nopsize,
	/*d_flags*/	D_DISK,
	/*d_maxio*/	0,
	/*b_maj*/	-1
};

static struct extend_array *cdperiphs;
static int num_changers;

#ifndef CHANGER_MIN_BUSY_SECONDS
#define CHANGER_MIN_BUSY_SECONDS	2
#endif
#ifndef CHANGER_MAX_BUSY_SECONDS
#define CHANGER_MAX_BUSY_SECONDS	10
#endif

static int changer_min_busy_seconds = CHANGER_MIN_BUSY_SECONDS;
static int changer_max_busy_seconds = CHANGER_MAX_BUSY_SECONDS;

/*
 * XXX KDM this CAM node should be moved if we ever get more CAM sysctl
 * variables.
 */
SYSCTL_NODE(_kern, OID_AUTO, cam, CTLFLAG_RD, 0, "CAM Subsystem");
SYSCTL_NODE(_kern_cam, OID_AUTO, cd, CTLFLAG_RD, 0, "CAM CDROM driver");
SYSCTL_NODE(_kern_cam_cd, OID_AUTO, changer, CTLFLAG_RD, 0, "CD Changer");
SYSCTL_INT(_kern_cam_cd_changer, OID_AUTO, min_busy_seconds, CTLFLAG_RW,
	   &changer_min_busy_seconds, 0, "Minimum changer scheduling quantum");
SYSCTL_INT(_kern_cam_cd_changer, OID_AUTO, max_busy_seconds, CTLFLAG_RW,
	   &changer_max_busy_seconds, 0, "Maximum changer scheduling quantum");

struct cdchanger {
	path_id_t			 path_id;
	target_id_t			 target_id;
	int				 num_devices;
	struct camq			 devq;
	struct timeval			 start_time;
	struct cd_softc			 *cur_device;
	struct callout_handle		 short_handle;
	struct callout_handle		 long_handle;
	cd_changer_flags		 flags;
	STAILQ_ENTRY(cdchanger)		 changer_links;
	STAILQ_HEAD(chdevlist, cd_softc) chluns;
};

STAILQ_HEAD(changerlist, cdchanger) changerq;

void
cdinit(void)
{
	cam_status status;
	struct cam_path *path;

	/*
	 * Create our extend array for storing the devices we attach to.
	 */
	cdperiphs = cam_extend_new();
	if (cdperiphs == NULL) {
		printf("cd: Failed to alloc extend array!\n");
		return;
	}

	/*
	 * Install a global async callback.  This callback will
	 * receive async callbacks like "new device found".
	 */
	status = xpt_create_path(&path, /*periph*/NULL, CAM_XPT_PATH_ID,
				 CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD);

	if (status == CAM_REQ_CMP) {
		struct ccb_setasync csa;

                xpt_setup_ccb(&csa.ccb_h, path, /*priority*/5);
                csa.ccb_h.func_code = XPT_SASYNC_CB;
                csa.event_enable = AC_FOUND_DEVICE;
                csa.callback = cdasync;
                csa.callback_arg = NULL;
                xpt_action((union ccb *)&csa);
		status = csa.ccb_h.status;
                xpt_free_path(path);
        }

	if (status != CAM_REQ_CMP) {
		printf("cd: Failed to attach master async callback "
		       "due to status 0x%x!\n", status);
	} else {
		/* If we were successfull, register our devsw */
		cdevsw_add_generic(CD_BDEV_MAJOR, CD_CDEV_MAJOR, &cd_cdevsw);
	}
}

static void
cdcleanup(struct cam_periph *periph)
{
	struct cd_softc *softc;

	softc = (struct cd_softc *)periph->softc;

	xpt_print_path(periph->path);
	printf("removing device entry\n");
	/*
	 * In the queued, non-active case, the device in question
	 * has already been removed from the changer run queue.  Since this
	 * device is active, we need to de-activate it, and schedule
	 * another device to run.  (if there is another one to run)
	 */
	if ((softc->flags & CD_FLAG_CHANGER)
	 && (softc->flags & CD_FLAG_ACTIVE)) {

		/*
		 * The purpose of the short timeout is soley to determine
		 * whether the current device has finished or not.  Well,
		 * since we're removing the active device, we know that it
		 * is finished.  So, get rid of the short timeout.
		 * Otherwise, if we're in the time period before the short
		 * timeout fires, and there are no other devices in the
		 * queue to run, there won't be any other device put in the
		 * active slot.  i.e., when we call cdrunchangerqueue()
		 * below, it won't do anything.  Then, when the short
		 * timeout fires, it'll look at the "current device", which
		 * we are free below, and possibly panic the kernel on a
		 * bogus pointer reference.
		 *
		 * The long timeout doesn't really matter, since we
		 * decrement the qfrozen_cnt to indicate that there is
		 * nothing in the active slot now.  Therefore, there won't
		 * be any bogus pointer references there.
		 */
		if (softc->changer->flags & CHANGER_SHORT_TMOUT_SCHED) {
			untimeout(cdshorttimeout, softc->changer,
				  softc->changer->short_handle);
			softc->changer->flags &= ~CHANGER_SHORT_TMOUT_SCHED;
		}
		softc->changer->devq.qfrozen_cnt--;
		softc->changer->flags |= CHANGER_MANUAL_CALL;
		cdrunchangerqueue(softc->changer);
	}

	/*
	 * If we're removing the last device on the changer, go ahead and
	 * remove the changer device structure.
	 */
	if ((softc->flags & CD_FLAG_CHANGER)
	 && (--softc->changer->num_devices == 0)) {

		/*
		 * Theoretically, there shouldn't be any timeouts left, but
		 * I'm not completely sure that that will be the case.  So,
		 * it won't hurt to check and see if there are any left.
		 */
		if (softc->changer->flags & CHANGER_TIMEOUT_SCHED) {
			untimeout(cdrunchangerqueue, softc->changer,
				  softc->changer->long_handle);
			softc->changer->flags &= ~CHANGER_TIMEOUT_SCHED;
		}

		if (softc->changer->flags & CHANGER_SHORT_TMOUT_SCHED) {
			untimeout(cdshorttimeout, softc->changer,
				  softc->changer->short_handle);
			softc->changer->flags &= ~CHANGER_SHORT_TMOUT_SCHED;
		}

		STAILQ_REMOVE(&changerq, softc->changer, cdchanger,
			      changer_links);
		xpt_print_path(periph->path);
		printf("removing changer entry\n");
		free(softc->changer, M_DEVBUF);
		num_changers--;
	}
	cam_extend_release(cdperiphs, periph->unit_number);
	free(periph->softc, M_DEVBUF);
}

static void
cdasync(void *callback_arg, u_int32_t code,
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

		if ((cgd->pd_type != T_CDROM) && (cgd->pd_type != T_WORM))
			break;

		/*
		 * Allocate a peripheral instance for
		 * this device and start the probe
		 * process.
		 */
		status = cam_periph_alloc(cdregister, cdcleanup, cdstart,
					  "cd", CAM_PERIPH_BIO, cgd->ccb_h.path,
					  cdasync, AC_FOUND_DEVICE, cgd);

		if (status != CAM_REQ_CMP
		 && status != CAM_REQ_INPROG)
			printf("cdasync: Unable to attach new device "
			       "due to status 0x%x\n", status);

		break;
	}
	case AC_LOST_DEVICE:
	{
		int s;
		struct cd_softc *softc;
		struct buf *q_bp;
		struct ccb_setasync csa;

		softc = (struct cd_softc *)periph->softc;

		/*
		 * Insure that no other async callbacks that
		 * might affect this peripheral can come through.
		 */
		s = splcam();

		/*
		 * De-register any async callbacks.
		 */
		xpt_setup_ccb(&csa.ccb_h, periph->path,
			      /* priority */ 5);
		csa.ccb_h.func_code = XPT_SASYNC_CB;
		csa.event_enable = 0;
		csa.callback = cdasync;
		csa.callback_arg = periph;
		xpt_action((union ccb *)&csa);

		softc->flags |= CD_FLAG_INVALID;

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

		/*
		 * If this device is part of a changer, and it was scheduled
		 * to run, remove it from the run queue since we just nuked
		 * all of its scheduled I/O.
		 */
		if ((softc->flags & CD_FLAG_CHANGER)
		 && (softc->pinfo.index != CAM_UNQUEUED_INDEX))
			camq_remove(&softc->changer->devq, softc->pinfo.index);

		devstat_remove_entry(&softc->device_stats);

		xpt_print_path(periph->path);
		printf("lost device\n");

		splx(s);

		cam_periph_invalidate(periph);
		break;
	}
	case AC_SENT_BDR:
	case AC_BUS_RESET:
	{
		struct cd_softc *softc;
		struct ccb_hdr *ccbh;
		int s;

		softc = (struct cd_softc *)periph->softc;
		s = splsoftcam();
		/*
		 * Don't fail on the expected unit attention
		 * that will occur.
		 */
		softc->flags |= CD_FLAG_RETRY_UA;
		for (ccbh = LIST_FIRST(&softc->pending_ccbs);
		     ccbh != NULL; ccbh = LIST_NEXT(ccbh, periph_links.le))
			ccbh->ccb_state |= CD_CCB_RETRY_UA;
		splx(s);
		break;
	}
	case AC_TRANSFER_NEG:
	case AC_SCSI_AEN:
	case AC_UNSOL_RESEL:
	default:
		break;
	}
}

static cam_status
cdregister(struct cam_periph *periph, void *arg)
{
	struct cd_softc *softc;
	struct ccb_setasync csa;
	struct ccb_getdev *cgd;
	caddr_t match;

	cgd = (struct ccb_getdev *)arg;
	if (periph == NULL) {
		printf("cdregister: periph was NULL!!\n");
		return(CAM_REQ_CMP_ERR);
	}
	if (cgd == NULL) {
		printf("cdregister: no getdev CCB, can't register device\n");
		return(CAM_REQ_CMP_ERR);
	}

	softc = (struct cd_softc *)malloc(sizeof(*softc),M_DEVBUF,M_NOWAIT);

	if (softc == NULL) {
		printf("cdregister: Unable to probe new device. "
		       "Unable to allocate softc\n");				
		return(CAM_REQ_CMP_ERR);
	}

	bzero(softc, sizeof(*softc));
	LIST_INIT(&softc->pending_ccbs);
	softc->state = CD_STATE_PROBE;
	bufq_init(&softc->buf_queue);
	if (SID_IS_REMOVABLE(&cgd->inq_data))
		softc->flags |= CD_FLAG_DISC_REMOVABLE;
	if ((cgd->inq_data.flags & SID_CmdQue) != 0)
		softc->flags |= CD_FLAG_TAGGED_QUEUING;

	periph->softc = softc;
	softc->periph = periph;

	cam_extend_set(cdperiphs, periph->unit_number, periph);

	/*
	 * See if this device has any quirks.
	 */
	match = cam_quirkmatch((caddr_t)&cgd->inq_data,
			       (caddr_t)cd_quirk_table,
			       sizeof(cd_quirk_table)/sizeof(*cd_quirk_table),
			       sizeof(*cd_quirk_table), scsi_inquiry_match);

	if (match != NULL)
		softc->quirks = ((struct cd_quirk_entry *)match)->quirks;
	else
		softc->quirks = CD_Q_NONE;

	/*
	 * We need to register the statistics structure for this device,
	 * but we don't have the blocksize yet for it.  So, we register
	 * the structure and indicate that we don't have the blocksize
	 * yet.  Unlike other SCSI peripheral drivers, we explicitly set
	 * the device type here to be CDROM, rather than just ORing in
	 * cgd->pd_type.  This is because this driver can attach to either
	 * CDROM or WORM devices, and we want this peripheral driver to
	 * show up in the devstat list as a CD peripheral driver, not a
	 * WORM peripheral driver.  WORM drives will also have the WORM
	 * driver attached to them.
	 */
	devstat_add_entry(&softc->device_stats, "cd", 
			  periph->unit_number, 0,
	  		  DEVSTAT_BS_UNAVAILABLE,
			  DEVSTAT_TYPE_CDROM | DEVSTAT_TYPE_IF_SCSI);

	/*
	 * Add an async callback so that we get
	 * notified if this device goes away.
	 */
	xpt_setup_ccb(&csa.ccb_h, periph->path,
		      /* priority */ 5);
	csa.ccb_h.func_code = XPT_SASYNC_CB;
	csa.event_enable = AC_SENT_BDR | AC_BUS_RESET | AC_LOST_DEVICE;
	csa.callback = cdasync;
	csa.callback_arg = periph;
	xpt_action((union ccb *)&csa);

	/*
	 * If the target lun is greater than 0, we most likely have a CD
	 * changer device.  Check the quirk entries as well, though, just
	 * in case someone has a CD tower with one lun per drive or
	 * something like that.  Also, if we know up front that a
	 * particular device is a changer, we can mark it as such starting
	 * with lun 0, instead of lun 1.  It shouldn't be necessary to have
	 * a quirk entry to define something as a changer, however.
	 */
	if (((cgd->ccb_h.target_lun > 0)
	  && ((softc->quirks & CD_Q_NO_CHANGER) == 0))
	 || ((softc->quirks & CD_Q_CHANGER) != 0)) {
		struct cdchanger *nchanger;
		struct cam_periph *nperiph;
		struct cam_path *path;
		cam_status status;
		int found;

		/* Set the changer flag in the current device's softc */
		softc->flags |= CD_FLAG_CHANGER;

		if (num_changers == 0)
			STAILQ_INIT(&changerq);

		/*
		 * Now, look around for an existing changer device with the
		 * same path and target ID as the current device.
		 */
		for (found = 0,
		     nchanger = (struct cdchanger *)STAILQ_FIRST(&changerq);
		     nchanger != NULL;
		     nchanger = STAILQ_NEXT(nchanger, changer_links)){
			if ((nchanger->path_id == cgd->ccb_h.path_id) 
			 && (nchanger->target_id == cgd->ccb_h.target_id)) {
				found = 1;
				break;
			}
		}

		/*
		 * If we found a matching entry, just add this device to
		 * the list of devices on this changer.
		 */
		if (found == 1) {
			struct chdevlist *chlunhead;

			chlunhead = &nchanger->chluns;

			/*
			 * XXX KDM look at consolidating this code with the
			 * code below in a separate function.
			 */

			/*
			 * Create a path with lun id 0, and see if we can
			 * find a matching device
			 */
			status = xpt_create_path(&path, /*periph*/ periph,
						 cgd->ccb_h.path_id,
						 cgd->ccb_h.target_id, 0);

			if ((status == CAM_REQ_CMP)
			 && ((nperiph = cam_periph_find(path, "cd")) != NULL)){
				struct cd_softc *nsoftc;

				nsoftc = (struct cd_softc *)nperiph->softc;

				if ((nsoftc->flags & CD_FLAG_CHANGER) == 0){
					nsoftc->flags |= CD_FLAG_CHANGER;
					nchanger->num_devices++;
					if (camq_resize(&nchanger->devq,
					   nchanger->num_devices)!=CAM_REQ_CMP){
						printf("cdregister: "
						       "camq_resize "
						       "failed, changer "
						       "support may "
						       "be messed up\n");
					}
					nsoftc->changer = nchanger;
					nsoftc->pinfo.index =CAM_UNQUEUED_INDEX;

					STAILQ_INSERT_TAIL(&nchanger->chluns,
							  nsoftc,changer_links);
				}
			} else if (status == CAM_REQ_CMP)
				xpt_free_path(path);
			else {
				printf("cdregister: unable to allocate path\n"
				       "cdregister: changer support may be "
				       "broken\n");
			}

			nchanger->num_devices++;

			softc->changer = nchanger;
			softc->pinfo.index = CAM_UNQUEUED_INDEX;

			if (camq_resize(&nchanger->devq,
			    nchanger->num_devices) != CAM_REQ_CMP) {
				printf("cdregister: camq_resize "
				       "failed, changer support may "
				       "be messed up\n");
			}

			STAILQ_INSERT_TAIL(chlunhead, softc, changer_links);
		}
		/*
		 * In this case, we don't already have an entry for this
		 * particular changer, so we need to create one, add it to
		 * the queue, and queue this device on the list for this
		 * changer.  Before we queue this device, however, we need
		 * to search for lun id 0 on this target, and add it to the
		 * queue first, if it exists.  (and if it hasn't already
		 * been marked as part of the changer.)
		 */
		else {
			nchanger = malloc(sizeof(struct cdchanger),
				M_DEVBUF, M_NOWAIT);

			if (nchanger == NULL) {
				softc->flags &= ~CD_FLAG_CHANGER;
				printf("cdregister: unable to malloc "
				       "changer structure\ncdregister: "
				       "changer support disabled\n");

				/*
				 * Yes, gotos can be gross but in this case
				 * I think it's justified..
				 */
				goto cdregisterexit;
			}

			/* zero the structure */
			bzero(nchanger, sizeof(struct cdchanger));

			if (camq_init(&nchanger->devq, 1) != 0) {
				softc->flags &= ~CD_FLAG_CHANGER;
				printf("cdregister: changer support "
				       "disabled\n");
				goto cdregisterexit;
			}

			num_changers++;

			nchanger->path_id = cgd->ccb_h.path_id;
			nchanger->target_id = cgd->ccb_h.target_id;

			/* this is superfluous, but it makes things clearer */
			nchanger->num_devices = 0;

			STAILQ_INIT(&nchanger->chluns);

			STAILQ_INSERT_TAIL(&changerq, nchanger,
					   changer_links);
			
			/*
			 * Create a path with lun id 0, and see if we can
			 * find a matching device
			 */
			status = xpt_create_path(&path, /*periph*/ periph,
						 cgd->ccb_h.path_id,
						 cgd->ccb_h.target_id, 0);

			/*
			 * If we were able to allocate the path, and if we
			 * find a matching device and it isn't already
			 * marked as part of a changer, then we add it to
			 * the current changer.
			 */
			if ((status == CAM_REQ_CMP)
			 && ((nperiph = cam_periph_find(path, "cd")) != NULL)
			 && ((((struct cd_softc *)periph->softc)->flags &
			       CD_FLAG_CHANGER) == 0)) {
				struct cd_softc *nsoftc;

				nsoftc = (struct cd_softc *)nperiph->softc;

				nsoftc->flags |= CD_FLAG_CHANGER;
				nchanger->num_devices++;
				if (camq_resize(&nchanger->devq,
				    nchanger->num_devices) != CAM_REQ_CMP) {
					printf("cdregister: camq_resize "
					       "failed, changer support may "
					       "be messed up\n");
				}
				nsoftc->changer = nchanger;
				nsoftc->pinfo.index = CAM_UNQUEUED_INDEX;

				STAILQ_INSERT_TAIL(&nchanger->chluns,
						   nsoftc, changer_links);
			} else if (status == CAM_REQ_CMP)
				xpt_free_path(path);
			else {
				printf("cdregister: unable to allocate path\n"
				       "cdregister: changer support may be "
				       "broken\n");
			}

			softc->changer = nchanger;
			softc->pinfo.index = CAM_UNQUEUED_INDEX;
			nchanger->num_devices++;
			if (camq_resize(&nchanger->devq,
			    nchanger->num_devices) != CAM_REQ_CMP) {
				printf("cdregister: camq_resize "
				       "failed, changer support may "
				       "be messed up\n");
			}
			STAILQ_INSERT_TAIL(&nchanger->chluns, softc,
					   changer_links);
		}
	}

cdregisterexit:

	/* Lock this peripheral until we are setup */
	/* Can't block */
	cam_periph_lock(periph, PRIBIO); 

	if ((softc->flags & CD_FLAG_CHANGER) == 0)
		xpt_schedule(periph, /*priority*/5);
	else
		cdschedule(periph, /*priority*/ 5);

	return(CAM_REQ_CMP);
}

static int
cdopen(dev_t dev, int flags, int fmt, struct proc *p)
{
	struct disklabel label;
	struct cam_periph *periph;
	struct cd_softc *softc;
	struct ccb_getdev cgd;
	u_int32_t size;
	int unit, error;

	unit = dkunit(dev);
	periph = cam_extend_get(cdperiphs, unit);

	if (periph == NULL)
		return (ENXIO);

	softc = (struct cd_softc *)periph->softc;

	if (softc->flags & CD_FLAG_INVALID)
		return(ENXIO);

	if ((error = cam_periph_lock(periph, PRIBIO | PCATCH)) != 0)
		return (error);

	if ((softc->flags & CD_FLAG_OPEN) == 0) {
		if (cam_periph_acquire(periph) != CAM_REQ_CMP)
			return(ENXIO);
		softc->flags |= CD_FLAG_OPEN;

		cdprevent(periph, PR_PREVENT);
	}

	/* find out the size */
	if ((error = cdsize(dev, &size)) != 0) {
		if (dsisopen(softc->cd_slices) == 0) {
			cdprevent(periph, PR_ALLOW);
			softc->flags &= ~CD_FLAG_OPEN;
		}
		cam_periph_unlock(periph);

		if ((softc->flags & CD_FLAG_OPEN) == 0)
			cam_periph_release(periph);

		return(error);
	}

	/*
	 * Build prototype label for whole disk.
	 * Should take information about different data tracks from the
	 * TOC and put it in the partition table.
	 */
	bzero(&label, sizeof(label));
	label.d_type = DTYPE_SCSI;

	/*
	 * Grab the inquiry data to get the vendor and product names.
	 * Put them in the typename and packname for the label.
	 */
	xpt_setup_ccb(&cgd.ccb_h, periph->path, /*priority*/ 1);
	cgd.ccb_h.func_code = XPT_GDEV_TYPE;
	xpt_action((union ccb *)&cgd);

	strncpy(label.d_typename, cgd.inq_data.vendor,
		min(SID_VENDOR_SIZE, sizeof(label.d_typename)));
	strncpy(label.d_packname, cgd.inq_data.product,
		min(SID_PRODUCT_SIZE, sizeof(label.d_packname)));
		
	label.d_secsize = softc->params.blksize;
	label.d_secperunit = softc->params.disksize;
	label.d_flags = D_REMOVABLE;
	/*
	 * Make partition 'a' cover the whole disk.  This is a temporary
	 * compatibility hack.  The 'a' partition should not exist, so
	 * the slice code won't create it.  The slice code will make
	 * partition (RAW_PART + 'a') cover the whole disk and fill in
	 * some more defaults.
	 */
	label.d_partitions[0].p_size = label.d_secperunit;
	label.d_partitions[0].p_fstype = FS_OTHER;

	/* Initialize slice tables. */
	error = dsopen("cd", dev, fmt, DSO_NOLABELS | DSO_ONESLICE,
		       &softc->cd_slices, &label, cdstrategy,
		       (ds_setgeom_t *)NULL, &cd_cdevsw);

	if (error == 0) {
		/*
		 * We unconditionally (re)set the blocksize each time the
		 * CD device is opened.  This is because the CD can change,
		 * and therefore the blocksize might change.
		 * XXX problems here if some slice or partition is still
		 * open with the old size?
		 */
		if ((softc->device_stats.flags & DEVSTAT_BS_UNAVAILABLE) != 0)
			softc->device_stats.flags &= ~DEVSTAT_BS_UNAVAILABLE;
		softc->device_stats.block_size = softc->params.blksize;
	} else {
		if ((dsisopen(softc->cd_slices) == 0)
		 && ((softc->flags & CD_FLAG_DISC_REMOVABLE) != 0))
			cdprevent(periph, PR_ALLOW);
	}

	cam_periph_unlock(periph);

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("leaving cdopen\n"));

	return (error);
}

static int
cdclose(dev_t dev, int flag, int fmt, struct proc *p)
{
	struct 	cam_periph *periph;
	struct	cd_softc *softc;
	int	unit, error;

	unit = dkunit(dev);
	periph = cam_extend_get(cdperiphs, unit);
	if (periph == NULL)
		return (ENXIO);	

	softc = (struct cd_softc *)periph->softc;

	if ((error = cam_periph_lock(periph, PRIBIO)) != 0)
		return (error);

	dsclose(dev, fmt, softc->cd_slices);
	if (dsisopen(softc->cd_slices)) {
		cam_periph_unlock(periph);
		return (0);
	}

	if ((softc->flags & CD_FLAG_DISC_REMOVABLE) != 0)
		cdprevent(periph, PR_ALLOW);

	/*
	 * Since we're closing this CD, mark the blocksize as unavailable.
	 * It will be marked as available whence the CD is opened again.
	 */
	softc->device_stats.flags |= DEVSTAT_BS_UNAVAILABLE;

	softc->flags &= ~CD_FLAG_OPEN;
	cam_periph_unlock(periph);
	cam_periph_release(periph);

	return (0);
}

static int
cdread(dev_t dev, struct uio *uio, int ioflag)
{
	return(physio(cdstrategy, NULL, dev, 1, minphys, uio));
}

static void
cdshorttimeout(void *arg)
{
	struct cdchanger *changer;
	int s;

	s = splsoftcam();

	changer = (struct cdchanger *)arg;

	/* Always clear the short timeout flag, since that's what we're in */
	changer->flags &= ~CHANGER_SHORT_TMOUT_SCHED;

	/*
	 * Check to see if there is any more pending or outstanding I/O for
	 * this device.  If not, move it out of the active slot.
	 */
	if ((bufq_first(&changer->cur_device->buf_queue) == NULL)
	 && (changer->cur_device->device_stats.busy_count == 0)) {
		changer->flags |= CHANGER_MANUAL_CALL;
		cdrunchangerqueue(changer);
	}

	splx(s);
}

/*
 * This is a wrapper for xpt_schedule.  It only applies to changers.
 */
static void
cdschedule(struct cam_periph *periph, int priority)
{
	struct cd_softc *softc;
	int s;

	s = splsoftcam();

	softc = (struct cd_softc *)periph->softc;

	/*
	 * If this device isn't currently queued, and if it isn't
	 * the active device, then we queue this device and run the
	 * changer queue if there is no timeout scheduled to do it.
	 * If this device is the active device, just schedule it
	 * to run again.  If this device is queued, there should be
	 * a timeout in place already that will make sure it runs.
	 */
	if ((softc->pinfo.index == CAM_UNQUEUED_INDEX) 
	 && ((softc->flags & CD_FLAG_ACTIVE) == 0)) {
		/*
		 * We don't do anything with the priority here.
		 * This is strictly a fifo queue.
		 */
		softc->pinfo.priority = 1;
		if (softc->changer->devq.generation++ == 0)
			camq_regen(&softc->changer->devq);
		softc->pinfo.generation =
			softc->changer->devq.generation;
		camq_insert(&softc->changer->devq, (cam_pinfo *)softc);

		/*
		 * Since we just put a device in the changer queue,
		 * check and see if there is a timeout scheduled for
		 * this changer.  If so, let the timeout handle
		 * switching this device into the active slot.  If
		 * not, manually call the timeout routine to
		 * bootstrap things.
		 */
		if (((softc->changer->flags & CHANGER_TIMEOUT_SCHED)==0)
		 &&((softc->changer->flags & CHANGER_NEED_TIMEOUT)==0)){
			softc->changer->flags |= CHANGER_MANUAL_CALL;
			cdrunchangerqueue(softc->changer);
		}
	} else if ((softc->flags & CD_FLAG_ACTIVE)
		&& ((softc->flags & CD_FLAG_SCHED_ON_COMP) == 0))
		xpt_schedule(periph, priority);

	splx(s);

}

static void
cdrunchangerqueue(void *arg)
{
	struct cd_softc *softc;
	struct cdchanger *changer;
	int called_from_timeout;
	int s;

	s = splsoftcam();

	changer = (struct cdchanger *)arg;

	/*
	 * If we have NOT been called from cdstrategy() or cddone(), and
	 * instead from a timeout routine, go ahead and clear the
	 * timeout flag.
	 */
	if ((changer->flags & CHANGER_MANUAL_CALL) == 0) {
		changer->flags &= ~CHANGER_TIMEOUT_SCHED;
		called_from_timeout = 1;
	} else
		called_from_timeout = 0;

	/* Always clear the manual call flag */
	changer->flags &= ~CHANGER_MANUAL_CALL;

	/* nothing to do if the queue is empty */
	if (changer->devq.entries <= 0) {
		splx(s);
		return;
	}

	/*
	 * If the changer queue is frozen, that means we have an active
	 * device.
	 */
	if (changer->devq.qfrozen_cnt > 0) {

		if (changer->cur_device->device_stats.busy_count > 0) {
			changer->cur_device->flags |= CD_FLAG_SCHED_ON_COMP;
			changer->cur_device->bufs_left = 
				changer->cur_device->device_stats.busy_count;
			if (called_from_timeout) {
				changer->long_handle =
					timeout(cdrunchangerqueue, changer,
				        changer_max_busy_seconds * hz);
				changer->flags |= CHANGER_TIMEOUT_SCHED;
			}
			splx(s);
			return;
		}

		/*
		 * We always need to reset the frozen count and clear the
		 * active flag.
		 */
		changer->devq.qfrozen_cnt--;
		changer->cur_device->flags &= ~CD_FLAG_ACTIVE;
		changer->cur_device->flags &= ~CD_FLAG_SCHED_ON_COMP;

		/*
		 * Check to see whether the current device has any I/O left
		 * to do.  If so, requeue it at the end of the queue.  If
		 * not, there is no need to requeue it.
		 */
		if (bufq_first(&changer->cur_device->buf_queue) != NULL) {

			if (changer->devq.generation++ == 0)
				camq_regen(&changer->devq);

			changer->cur_device->pinfo.generation =
				changer->devq.generation;
			camq_insert(&changer->devq,
				(cam_pinfo *)changer->cur_device);
		} 
	}

	softc = (struct cd_softc *)camq_remove(&changer->devq, 0);

	changer->cur_device = softc;

	changer->devq.qfrozen_cnt++;
	softc->flags |= CD_FLAG_ACTIVE;

	/* Just in case this device is waiting */
	wakeup(&softc->changer);
	xpt_schedule(softc->periph, /*priority*/ 1);

	/*
	 * Get rid of any pending timeouts, and set a flag to schedule new
	 * ones so this device gets its full time quantum.
	 */
	if (changer->flags & CHANGER_TIMEOUT_SCHED) {
		untimeout(cdrunchangerqueue, changer, changer->long_handle);
		changer->flags &= ~CHANGER_TIMEOUT_SCHED;
	}

	if (changer->flags & CHANGER_SHORT_TMOUT_SCHED) {
		untimeout(cdshorttimeout, changer, changer->short_handle);
		changer->flags &= ~CHANGER_SHORT_TMOUT_SCHED;
	}

	/*
	 * We need to schedule timeouts, but we only do this after the
	 * first transaction has completed.  This eliminates the changer
	 * switch time.
	 */
	changer->flags |= CHANGER_NEED_TIMEOUT;

	splx(s);
}

static void
cdchangerschedule(struct cd_softc *softc)
{
	struct cdchanger *changer;
	int s;

	s = splsoftcam();

	changer = softc->changer;

	/*
	 * If this is a changer, and this is the current device,
	 * and this device has at least the minimum time quantum to
	 * run, see if we can switch it out.
	 */
	if ((softc->flags & CD_FLAG_ACTIVE) 
	 && ((changer->flags & CHANGER_SHORT_TMOUT_SCHED) == 0)
	 && ((changer->flags & CHANGER_NEED_TIMEOUT) == 0)) {
		/*
		 * We try three things here.  The first is that we
		 * check to see whether the schedule on completion
		 * flag is set.  If it is, we decrement the number
		 * of buffers left, and if it's zero, we reschedule.
		 * Next, we check to see whether the pending buffer
		 * queue is empty and whether there are no
		 * outstanding transactions.  If so, we reschedule.
		 * Next, we see if the pending buffer queue is empty.
		 * If it is, we set the number of buffers left to
		 * the current active buffer count and set the
		 * schedule on complete flag.
		 */
		if (softc->flags & CD_FLAG_SCHED_ON_COMP) {
		 	if (--softc->bufs_left == 0) {
				softc->changer->flags |=
					CHANGER_MANUAL_CALL;
				softc->flags &= ~CD_FLAG_SCHED_ON_COMP;
				cdrunchangerqueue(softc->changer);
			}
		} else if ((bufq_first(&softc->buf_queue) == NULL)
		        && (softc->device_stats.busy_count == 0)) {
			softc->changer->flags |= CHANGER_MANUAL_CALL;
			cdrunchangerqueue(softc->changer);
		}
	} else if ((softc->changer->flags & CHANGER_NEED_TIMEOUT) 
		&& (softc->flags & CD_FLAG_ACTIVE)) {

		/*
		 * Now that the first transaction to this
		 * particular device has completed, we can go ahead
		 * and schedule our timeouts.
		 */
		if ((changer->flags & CHANGER_TIMEOUT_SCHED) == 0) {
			changer->long_handle =
			    timeout(cdrunchangerqueue, changer,
				    changer_max_busy_seconds * hz);
			changer->flags |= CHANGER_TIMEOUT_SCHED;
		} else
			printf("cdchangerschedule: already have a long"
			       " timeout!\n");

		if ((changer->flags & CHANGER_SHORT_TMOUT_SCHED) == 0) {
			changer->short_handle =
			    timeout(cdshorttimeout, changer,
				    changer_min_busy_seconds * hz);
			changer->flags |= CHANGER_SHORT_TMOUT_SCHED;
		} else
			printf("cdchangerschedule: already have a short "
			       "timeout!\n");

		/*
		 * We just scheduled timeouts, no need to schedule
		 * more.
		 */
		changer->flags &= ~CHANGER_NEED_TIMEOUT;

	}
	splx(s);
}

static int
cdrunccb(union ccb *ccb, int (*error_routine)(union ccb *ccb,
					      u_int32_t cam_flags,
					      u_int32_t sense_flags),
	 u_int32_t cam_flags, u_int32_t sense_flags)
{
	struct cd_softc *softc;
	struct cam_periph *periph;
	int error;

	periph = xpt_path_periph(ccb->ccb_h.path);
	softc = (struct cd_softc *)periph->softc;

	error = cam_periph_runccb(ccb, error_routine, cam_flags, sense_flags,
				  &softc->device_stats);

	if (softc->flags & CD_FLAG_CHANGER)
		cdchangerschedule(softc);

	return(error);
}

union ccb *
cdgetccb(struct cam_periph *periph, u_int32_t priority)
{
	struct cd_softc *softc;
	int s;

	softc = (struct cd_softc *)periph->softc;

	if (softc->flags & CD_FLAG_CHANGER) {

		s = splsoftcam();

		/*
		 * This should work the first time this device is woken up,
		 * but just in case it doesn't, we use a while loop.
		 */
		while ((((volatile cd_flags)softc->flags) & CD_FLAG_ACTIVE)==0){
			/*
			 * If this changer isn't already queued, queue it up.
			 */
			if (softc->pinfo.index == CAM_UNQUEUED_INDEX) {
				softc->pinfo.priority = 1;
				if (softc->changer->devq.generation++ == 0)
					camq_regen(&softc->changer->devq);
				softc->pinfo.generation =
					softc->changer->devq.generation;
				camq_insert(&softc->changer->devq,
					    (cam_pinfo *)softc);
			}
			if (((((volatile cd_changer_flags)softc->changer->flags)
				& CHANGER_TIMEOUT_SCHED)==0)
			 &&((((volatile cd_changer_flags)softc->changer->flags)
				& CHANGER_NEED_TIMEOUT)==0)){
				softc->changer->flags |= CHANGER_MANUAL_CALL;
				cdrunchangerqueue(softc->changer);
			} else
				tsleep(&softc->changer, PRIBIO, "cgticb", 0);
		}
		splx(s);
	}
	return(cam_periph_getccb(periph, priority));
}


/*
 * Actually translate the requested transfer into one the physical driver
 * can understand.  The transfer is described by a buf and will include
 * only one physical transfer.
 */
static void
cdstrategy(struct buf *bp)
{
	struct cam_periph *periph;
	struct cd_softc *softc;
	u_int  unit, part;
	int    s;

	unit = dkunit(bp->b_dev);
	part = dkpart(bp->b_dev);
	periph = cam_extend_get(cdperiphs, unit);
	if (periph == NULL) {
		bp->b_error = ENXIO;
		goto bad;
	}

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("entering cdstrategy\n"));

	softc = (struct cd_softc *)periph->softc;

	/*
	 * Do bounds checking, adjust transfer, and set b_pbklno.
	 */
	if (dscheck(bp, softc->cd_slices) <= 0)
		goto done;

	/*
	 * Mask interrupts so that the pack cannot be invalidated until
	 * after we are in the queue.  Otherwise, we might not properly
	 * clean up one of the buffers.
	 */
	s = splbio();
	
	/*
	 * If the device has been made invalid, error out
	 */
	if ((softc->flags & CD_FLAG_INVALID)) {
		splx(s);
		bp->b_error = ENXIO;
		goto bad;
	}

	/*
	 * Place it in the queue of disk activities for this disk
	 */
	bufqdisksort(&softc->buf_queue, bp);

	splx(s);
	
	/*
	 * Schedule ourselves for performing the work.  We do things
	 * differently for changers.
	 */
	if ((softc->flags & CD_FLAG_CHANGER) == 0)
		xpt_schedule(periph, /* XXX priority */1);
	else
		cdschedule(periph, /* priority */ 1);

	return;
bad:
	bp->b_flags |= B_ERROR;
done:
	/*
	 * Correctly set the buf to indicate a completed xfer
	 */
	bp->b_resid = bp->b_bcount;
	biodone(bp);
	return;
}

static void
cdstrategy1(struct buf *bp)
{
	/*
	 * XXX - do something to make cdstrategy() but not this block while
	 * we're doing dsopen() and dsioctl().
	 */
	cdstrategy(bp);
}

static void
cdstart(struct cam_periph *periph, union ccb *start_ccb)
{
	struct cd_softc *softc;
	struct buf *bp;
	struct ccb_scsiio *csio;
	struct scsi_read_capacity_data *rcap;
	int s;

	softc = (struct cd_softc *)periph->softc;

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("entering cdstart\n"));

	switch (softc->state) {
	case CD_STATE_NORMAL:
	{
		int oldspl;

		s = splbio();
		bp = bufq_first(&softc->buf_queue);
		if (periph->immediate_priority <= periph->pinfo.priority) {
			start_ccb->ccb_h.ccb_state = CD_CCB_WAITING;

			SLIST_INSERT_HEAD(&periph->ccb_list, &start_ccb->ccb_h,
					  periph_links.sle);
			periph->immediate_priority = CAM_PRIORITY_NONE;
			splx(s);
			wakeup(&periph->ccb_list);
		} else if (bp == NULL) {
			splx(s);
			xpt_release_ccb(start_ccb);
		} else {
			bufq_remove(&softc->buf_queue, bp);

			devstat_start_transaction(&softc->device_stats);

			scsi_read_write(&start_ccb->csio,
					/*retries*/4,
					/* cbfcnp */ cddone,
					(bp->b_flags & B_ORDERED) != 0 ?
					    MSG_ORDERED_Q_TAG : 
					    MSG_SIMPLE_Q_TAG,
					/* read */bp->b_flags & B_READ,
					/* byte2 */ 0,
					/* minimum_cmd_size */ 10,
					/* lba */ bp->b_pblkno,
					bp->b_bcount / softc->params.blksize,
					/* data_ptr */ bp->b_data,
					/* dxfer_len */ bp->b_bcount,
					/* sense_len */ SSD_FULL_SIZE,
					/* timeout */ 30000);
			start_ccb->ccb_h.ccb_state = CD_CCB_BUFFER_IO;

			
			/*
			 * Block out any asyncronous callbacks
			 * while we touch the pending ccb list.
			 */
			oldspl = splcam();
			LIST_INSERT_HEAD(&softc->pending_ccbs,
					 &start_ccb->ccb_h, periph_links.le);
			splx(oldspl);

			/* We expect a unit attention from this device */
			if ((softc->flags & CD_FLAG_RETRY_UA) != 0) {
				start_ccb->ccb_h.ccb_state |= CD_CCB_RETRY_UA;
				softc->flags &= ~CD_FLAG_RETRY_UA;
			}

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
	case CD_STATE_PROBE:
	{

		rcap = (struct scsi_read_capacity_data *)malloc(sizeof(*rcap),
								M_TEMP,
								M_NOWAIT);
		if (rcap == NULL) {
			xpt_print_path(periph->path);
			printf("cdstart: Couldn't malloc read_capacity data\n");
			/* cd_free_periph??? */
			break;
		}
		csio = &start_ccb->csio;
		scsi_read_capacity(csio,
				   /*retries*/1,
				   cddone,
				   MSG_SIMPLE_Q_TAG,
				   rcap,
				   SSD_FULL_SIZE,
				   /*timeout*/20000);
		start_ccb->ccb_h.ccb_bp = NULL;
		start_ccb->ccb_h.ccb_state = CD_CCB_PROBE;
		xpt_action(start_ccb);
		break;
	}
	}
}

static void
cddone(struct cam_periph *periph, union ccb *done_ccb)
{ 
	struct cd_softc *softc;
	struct ccb_scsiio *csio;

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("entering cddone\n"));

	softc = (struct cd_softc *)periph->softc;
	csio = &done_ccb->csio;

	switch (csio->ccb_h.ccb_state & CD_CCB_TYPE_MASK) {
	case CD_CCB_BUFFER_IO:
	{
		struct buf	*bp;
		int		error;
		int		oldspl;

		bp = (struct buf *)done_ccb->ccb_h.ccb_bp;
		error = 0;

		if ((done_ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
			int sf;

			if ((done_ccb->ccb_h.ccb_state & CD_CCB_RETRY_UA) != 0)
				sf = SF_RETRY_UA;
			else
				sf = 0;
			
			if ((error = cderror(done_ccb, 0, sf)) == ERESTART) {
				/*
				 * A retry was scheuled, so
				 * just return.
				 */
				return;
			}
		}

		if (error != 0) {
			int s;
			struct buf *q_bp;

			xpt_print_path(periph->path);
			printf("cddone: got error %#x back\n", error);
			s = splbio();
			while ((q_bp = bufq_first(&softc->buf_queue)) != NULL) {
				bufq_remove(&softc->buf_queue, q_bp);
				q_bp->b_resid = q_bp->b_bcount;
				q_bp->b_error = EIO;
				q_bp->b_flags |= B_ERROR;
				biodone(q_bp);
			}
			splx(s);
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
			if (bp->b_resid != 0) {
				/* Short transfer ??? */
				bp->b_flags |= B_ERROR;
			}
		}

		/*
		 * Block out any asyncronous callbacks
		 * while we touch the pending ccb list.
		 */
		oldspl = splcam();
		LIST_REMOVE(&done_ccb->ccb_h, periph_links.le);
		splx(oldspl);

		devstat_end_transaction(&softc->device_stats,
					bp->b_bcount - bp->b_resid,
					done_ccb->csio.tag_action & 0xf, 
					(bp->b_flags & B_READ) ? DEVSTAT_READ
							       : DEVSTAT_WRITE);

		if (softc->flags & CD_FLAG_CHANGER)
			cdchangerschedule(softc);

		biodone(bp);
		break;
	}
	case CD_CCB_PROBE:
	{
		struct	   scsi_read_capacity_data *rdcap;
		char	   announce_buf[120]; /*
					       * Currently (9/30/97) the 
					       * longest possible announce 
					       * buffer is 108 bytes, for the 
					       * first error case below.  
					       * That is 39 bytes for the 
					       * basic string, 16 bytes for the
					       * biggest sense key (hardware 
					       * error), 52 bytes for the
					       * text of the largest sense 
					       * qualifier valid for a CDROM,
					       * (0x72, 0x03 or 0x04,
					       * 0x03), and one byte for the
					       * null terminating character.
					       * To allow for longer strings, 
					       * the announce buffer is 120
					       * bytes.
					       */
		struct	   cd_params *cdp;

		cdp = &softc->params;

		rdcap = (struct scsi_read_capacity_data *)csio->data_ptr;
		
		cdp->disksize = scsi_4btoul (rdcap->addr) + 1;
		cdp->blksize = scsi_4btoul (rdcap->length);

		if ((csio->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP) {

			sprintf(announce_buf,
				"cd present [%lu x %lu byte records]",
				cdp->disksize, (u_long)cdp->blksize);

		} else {
			int	error;
			/*
			 * Retry any UNIT ATTENTION type errors.  They
			 * are expected at boot.
			 */
			error = cderror(done_ccb, 0, SF_RETRY_UA|SF_NO_PRINT);
			if (error == ERESTART) {
				/*
				 * A retry was scheuled, so
				 * just return.
				 */
				return;
			} else if (error != 0) {

				struct scsi_sense_data *sense;
				int asc, ascq;
				int sense_key, error_code;
				int have_sense;
				cam_status status;
				struct ccb_getdev cgd;

				/* Don't wedge this device's queue */
				cam_release_devq(done_ccb->ccb_h.path,
						 /*relsim_flags*/0,
						 /*reduction*/0,
						 /*timeout*/0,
						 /*getcount_only*/0);

				status = done_ccb->ccb_h.status;

				xpt_setup_ccb(&cgd.ccb_h, 
					      done_ccb->ccb_h.path,
					      /* priority */ 1);
				cgd.ccb_h.func_code = XPT_GDEV_TYPE;
				xpt_action((union ccb *)&cgd);

				if (((csio->ccb_h.flags & CAM_SENSE_PHYS) != 0)
				 || ((csio->ccb_h.flags & CAM_SENSE_PTR) != 0)
				 || ((status & CAM_AUTOSNS_VALID) == 0))
					have_sense = FALSE;
				else
					have_sense = TRUE;

				if (have_sense) {
					sense = &csio->sense_data;
					scsi_extract_sense(sense, &error_code,
							   &sense_key, 
							   &asc, &ascq);
				}
				/*
				 * With CDROM devices, we expect 0x3a
				 * (Medium not present) errors, since not
				 * everyone leaves a CD in the drive.  Some
				 * broken Philips and HP WORM drives return
				 * 0x04,0x00 (logical unit not ready, cause
				 * not reportable), so we accept any "not
				 * ready" type errors as well.  If the error
				 * is anything else, though, we shouldn't
				 * attach.
				 */
				if ((have_sense)
				 && ((asc == 0x3a) || (asc == 0x04))
				 && (error_code == SSD_CURRENT_ERROR))
					sprintf(announce_buf, 
						"Attempt to query device "
						"size failed: %s, %s",
						scsi_sense_key_text[sense_key],
						scsi_sense_desc(asc,ascq,
								&cgd.inq_data));
				else if (cgd.pd_type == T_CDROM) { 
					/*
					 * We only print out an error for
					 * CDROM type devices.  For WORM
					 * devices, we don't print out an
					 * error since a few WORM devices
					 * don't support CDROM commands.
					 * If we have sense information, go
					 * ahead and print it out.
					 * Otherwise, just say that we 
					 * couldn't attach.
					 */

					/*
					 * Just print out the error, not
					 * the full probe message, when we
					 * don't attach.
					 */
					if (have_sense)
						scsi_sense_print(
							&done_ccb->csio);
					else {
						xpt_print_path(periph->path);
						printf("got CAM status %#x\n",
						       done_ccb->ccb_h.status);
					}
					xpt_print_path(periph->path);
					printf("fatal error, failed" 
					       " to attach to device");

					/*
					 * Free up resources.
					 */
					cam_periph_invalidate(periph);

					announce_buf[0] = '\0';
				} else {
					/*
					 * Free up resources.
					 */
					cam_periph_invalidate(periph);
					announce_buf[0] = '\0';
				}
			}
		}
		free(rdcap, M_TEMP);
		if (announce_buf[0] != '\0')
			xpt_announce_periph(periph, announce_buf);
		softc->state = CD_STATE_NORMAL;		
		if (softc->flags & CD_FLAG_CHANGER)
			cdchangerschedule(softc);
		cam_periph_unlock(periph);

		break;
	}
	case CD_CCB_WAITING:
	{
		/* Caller will release the CCB */
		CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, 
			  ("trying to wakeup ccbwait\n"));

		wakeup(&done_ccb->ccb_h.cbfcnp);
		return;
	}
	}
	xpt_release_ccb(done_ccb);
}

static int
cdioctl(dev_t dev, u_long cmd, caddr_t addr, int flag, struct proc *p)
{

	struct 	cam_periph *periph;
	struct	cd_softc *softc;
	int	error, unit;

	unit = dkunit(dev);

	periph = cam_extend_get(cdperiphs, unit);
	if (periph == NULL)
		return(ENXIO);	

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("entering cdioctl\n"));

	softc = (struct cd_softc *)periph->softc;

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, 
		  ("trying to do ioctl %#lx\n", cmd));

	error = cam_periph_lock(periph, PRIBIO | PCATCH);

	if (error != 0)
		return(error);

	switch (cmd) {

	case CDIOCPLAYTRACKS:
		{
			struct ioc_play_track *args
			    = (struct ioc_play_track *) addr;
			struct cd_mode_data *data;

			data = malloc(sizeof(struct cd_mode_data), M_TEMP, 
				      M_WAITOK);

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCPLAYTRACKS\n"));

			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.flags &= ~CD_PA_SOTC;
			data->page.audio.flags |= CD_PA_IMMED;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
			if (error)
				break;
			if (softc->quirks & CD_Q_BCD_TRACKS) {
				args->start_track = bin2bcd(args->start_track);
				args->end_track = bin2bcd(args->end_track);
			}
			error = cdplaytracks(periph,
					     args->start_track,
					     args->start_index,
					     args->end_track,
					     args->end_index);
		}
		break;
	case CDIOCPLAYMSF:
		{
			struct ioc_play_msf *args
				= (struct ioc_play_msf *) addr;
			struct cd_mode_data *data;

			data = malloc(sizeof(struct cd_mode_data), M_TEMP,
				      M_WAITOK);

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCPLAYMSF\n"));

			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.flags &= ~CD_PA_SOTC;
			data->page.audio.flags |= CD_PA_IMMED;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
			if (error)
				break;
			error = cdplaymsf(periph,
					  args->start_m,
					  args->start_s,
					  args->start_f,
					  args->end_m,
					  args->end_s,
					  args->end_f);
		}
		break;
	case CDIOCPLAYBLOCKS:
		{
			struct ioc_play_blocks *args
				= (struct ioc_play_blocks *) addr;
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCPLAYBLOCKS\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP,
				      M_WAITOK);

			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.flags &= ~CD_PA_SOTC;
			data->page.audio.flags |= CD_PA_IMMED;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
			if (error)
				break;
			error = cdplay(periph, args->blk, args->len);
		}
		break;
	case CDIOCREADSUBCHANNEL:
		{
			struct ioc_read_subchannel *args
				= (struct ioc_read_subchannel *) addr;
			struct cd_sub_channel_info *data;
			u_int32_t len = args->data_len;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCREADSUBCHANNEL\n"));

			data = malloc(sizeof(struct cd_sub_channel_info), 
				      M_TEMP, M_WAITOK);

			if ((len > sizeof(struct cd_sub_channel_info)) ||
			    (len < sizeof(struct cd_sub_channel_header))) {
				printf(
					"scsi_cd: cdioctl: "
					"cdioreadsubchannel: error, len=%d\n",
					len);
				error = EINVAL;
				free(data, M_TEMP);
				break;
			}

			if (softc->quirks & CD_Q_BCD_TRACKS)
				args->track = bin2bcd(args->track);

			error = cdreadsubchannel(periph, args->address_format,
				args->data_format, args->track, data, len);

			if (error) {
				free(data, M_TEMP);
	 			break;
			}
			if (softc->quirks & CD_Q_BCD_TRACKS)
				data->what.track_info.track_number =
				    bcd2bin(data->what.track_info.track_number);
			len = min(len, ((data->header.data_len[0] << 8) +
				data->header.data_len[1] +
				sizeof(struct cd_sub_channel_header)));
			if (copyout(data, args->data, len) != 0) {
				error = EFAULT;
			}
			free(data, M_TEMP);
		}
		break;

	case CDIOREADTOCHEADER:
		{
			struct ioc_toc_header *th;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOREADTOCHEADER\n"));

			th = malloc(sizeof(struct ioc_toc_header), M_TEMP,
				    M_WAITOK);
			error = cdreadtoc(periph, 0, 0, 
					  (struct cd_toc_entry *)th, 
				          sizeof (*th));
			if (error) {
				free(th, M_TEMP);
				break;
			}
			if (softc->quirks & CD_Q_BCD_TRACKS) {
				/* we are going to have to convert the BCD
				 * encoding on the cd to what is expected
				 */
				th->starting_track = 
					bcd2bin(th->starting_track);
				th->ending_track = bcd2bin(th->ending_track);
			}
			NTOHS(th->len);
			bcopy(th, addr, sizeof(*th));
			free(th, M_TEMP);
		}
		break;
	case CDIOREADTOCENTRYS:
		{
			typedef struct {
				struct ioc_toc_header header;
				struct cd_toc_entry entries[100];
			} data_t;
			typedef struct {
				struct ioc_toc_header header;
				struct cd_toc_entry entry;
			} lead_t;

			data_t *data;
			lead_t *lead;
			struct ioc_read_toc_entry *te =
				(struct ioc_read_toc_entry *) addr;
			struct ioc_toc_header *th;
			u_int32_t len, readlen, idx, num;
			u_int32_t starting_track = te->starting_track;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOREADTOCENTRYS\n"));

			data = malloc(sizeof(data_t), M_TEMP, M_WAITOK);
			lead = malloc(sizeof(lead_t), M_TEMP, M_WAITOK);

			if (te->data_len < sizeof(struct cd_toc_entry)
			 || (te->data_len % sizeof(struct cd_toc_entry)) != 0
			 || (te->address_format != CD_MSF_FORMAT
			  && te->address_format != CD_LBA_FORMAT)) {
				error = EINVAL;
				printf("scsi_cd: error in readtocentries, "
				       "returning EINVAL\n");
				free(data, M_TEMP);
				free(lead, M_TEMP);
				break;
			}

			th = &data->header;
			error = cdreadtoc(periph, 0, 0, 
					  (struct cd_toc_entry *)th, 
					  sizeof (*th));
			if (error) {
				free(data, M_TEMP);
				free(lead, M_TEMP);
				break;
			}

			if (softc->quirks & CD_Q_BCD_TRACKS) {
				/* we are going to have to convert the BCD
				 * encoding on the cd to what is expected
				 */
				th->starting_track =
				    bcd2bin(th->starting_track);
				th->ending_track = bcd2bin(th->ending_track);
			}

			if (starting_track == 0)
				starting_track = th->starting_track;
			else if (starting_track == LEADOUT)
				starting_track = th->ending_track + 1;
			else if (starting_track < th->starting_track ||
				 starting_track > th->ending_track + 1) {
				printf("scsi_cd: error in readtocentries, "
				       "returning EINVAL\n");
				free(data, M_TEMP);
				free(lead, M_TEMP);
				error = EINVAL;
				break;
			}

			/* calculate reading length without leadout entry */
			readlen = (th->ending_track - starting_track + 1) *
				  sizeof(struct cd_toc_entry);

			/* and with leadout entry */
			len = readlen + sizeof(struct cd_toc_entry);
			if (te->data_len < len) {
				len = te->data_len;
				if (readlen > len)
					readlen = len;
			}
			if (len > sizeof(data->entries)) {
				printf("scsi_cd: error in readtocentries, "
				       "returning EINVAL\n");
				error = EINVAL;
				free(data, M_TEMP);
				free(lead, M_TEMP);
				break;
			}
			num = len / sizeof(struct cd_toc_entry);

			if (readlen > 0) {
				error = cdreadtoc(periph, te->address_format,
						  starting_track,
						  (struct cd_toc_entry *)data,
						  readlen + sizeof (*th));
				if (error) {
					free(data, M_TEMP);
					free(lead, M_TEMP);
					break;
				}
			}

			/* make leadout entry if needed */
			idx = starting_track + num - 1;
			if (softc->quirks & CD_Q_BCD_TRACKS)
				th->ending_track = bcd2bin(th->ending_track);
			if (idx == th->ending_track + 1) {
				error = cdreadtoc(periph, te->address_format,
						  LEADOUT, 
						  (struct cd_toc_entry *)lead,
						  sizeof(*lead));
				if (error) {
					free(data, M_TEMP);
					free(lead, M_TEMP);
					break;
				}
				data->entries[idx - starting_track] = 
					lead->entry;
			}
			if (softc->quirks & CD_Q_BCD_TRACKS) {
				for (idx = 0; idx < num - 1; idx++) {
					data->entries[idx].track =
					    bcd2bin(data->entries[idx].track);
				}
			}

			error = copyout(data->entries, te->data, len);
			free(data, M_TEMP);
			free(lead, M_TEMP);
		}
		break;
	case CDIOREADTOCENTRY:
		{
			/* yeah yeah, this is ugly */
			typedef struct {
				struct ioc_toc_header header;
				struct cd_toc_entry entry;
			} data_t;

			data_t *data;
			struct ioc_read_toc_single_entry *te =
				(struct ioc_read_toc_single_entry *) addr;
			struct ioc_toc_header *th;
			u_int32_t track;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOREADTOCENTRY\n"));

			data = malloc(sizeof(data_t), M_TEMP, M_WAITOK);

			if (te->address_format != CD_MSF_FORMAT
			    && te->address_format != CD_LBA_FORMAT) {
				printf("error in readtocentry, "
				       " returning EINVAL\n");
				free(data, M_TEMP);
				error = EINVAL;
				break;
			}

			th = &data->header;
			error = cdreadtoc(periph, 0, 0, 
					  (struct cd_toc_entry *)th,
					  sizeof (*th));
			if (error) {
				free(data, M_TEMP);
				break;
			}

			if (softc->quirks & CD_Q_BCD_TRACKS) {
				/* we are going to have to convert the BCD
				 * encoding on the cd to what is expected
				 */
				th->starting_track =
				    bcd2bin(th->starting_track);
				th->ending_track = bcd2bin(th->ending_track);
			}
			track = te->track;
			if (track == 0)
				track = th->starting_track;
			else if (track == LEADOUT)
				/* OK */;
			else if (track < th->starting_track ||
				 track > th->ending_track + 1) {
				printf("error in readtocentry, "
				       " returning EINVAL\n");
				free(data, M_TEMP);
				error = EINVAL;
				break;
			}

			error = cdreadtoc(periph, te->address_format, track,
					  (struct cd_toc_entry *)data,
					  sizeof(data_t));
			if (error) {
				free(data, M_TEMP);
				break;
			}

			if (softc->quirks & CD_Q_BCD_TRACKS)
				data->entry.track = bcd2bin(data->entry.track);
			bcopy(&data->entry, &te->entry,
			      sizeof(struct cd_toc_entry));
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETPATCH:
		{
			struct ioc_patch *arg = (struct ioc_patch *) addr;
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETPATCH\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP, 
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = 
				arg->patch[0];
			data->page.audio.port[RIGHT_PORT].channels = 
				arg->patch[1];
			data->page.audio.port[2].channels = arg->patch[2];
			data->page.audio.port[3].channels = arg->patch[3];
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCGETVOL:
		{
			struct ioc_vol *arg = (struct ioc_vol *) addr;
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCGETVOL\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP, 
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			arg->vol[LEFT_PORT] = 
				data->page.audio.port[LEFT_PORT].volume;
			arg->vol[RIGHT_PORT] = 
				data->page.audio.port[RIGHT_PORT].volume;
			arg->vol[2] = data->page.audio.port[2].volume;
			arg->vol[3] = data->page.audio.port[3].volume;
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETVOL:
		{
			struct ioc_vol *arg = (struct ioc_vol *) addr;
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETVOL\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP, 
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = CHANNEL_0;
			data->page.audio.port[LEFT_PORT].volume = 
				arg->vol[LEFT_PORT];
			data->page.audio.port[RIGHT_PORT].channels = CHANNEL_1;
			data->page.audio.port[RIGHT_PORT].volume = 
				arg->vol[RIGHT_PORT];
			data->page.audio.port[2].volume = arg->vol[2];
			data->page.audio.port[3].volume = arg->vol[3];
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETMONO:
		{
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETMONO\n"));

			data = malloc(sizeof(struct cd_mode_data), 
				      M_TEMP, M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = 
				LEFT_CHANNEL | RIGHT_CHANNEL;
			data->page.audio.port[RIGHT_PORT].channels = 
				LEFT_CHANNEL | RIGHT_CHANNEL;
			data->page.audio.port[2].channels = 0;
			data->page.audio.port[3].channels = 0;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETSTEREO:
		{
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETSTEREO\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP,
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = 
				LEFT_CHANNEL;
			data->page.audio.port[RIGHT_PORT].channels = 
				RIGHT_CHANNEL;
			data->page.audio.port[2].channels = 0;
			data->page.audio.port[3].channels = 0;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETMUTE:
		{
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETMUTE\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP,
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = 0;
			data->page.audio.port[RIGHT_PORT].channels = 0;
			data->page.audio.port[2].channels = 0;
			data->page.audio.port[3].channels = 0;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETLEFT:
		{
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETLEFT\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP,
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = 
				LEFT_CHANNEL;
			data->page.audio.port[RIGHT_PORT].channels = 
				LEFT_CHANNEL;
			data->page.audio.port[2].channels = 0;
			data->page.audio.port[3].channels = 0;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCSETRIGHT:
		{
			struct cd_mode_data *data;

			CAM_DEBUG(periph->path, CAM_DEBUG_SUBTRACE, 
				  ("trying to do CDIOCSETRIGHT\n"));

			data = malloc(sizeof(struct cd_mode_data), M_TEMP,
				      M_WAITOK);
			error = cdgetmode(periph, data, AUDIO_PAGE);
			if (error) {
				free(data, M_TEMP);
				break;
			}
			data->page.audio.port[LEFT_PORT].channels = 
				RIGHT_CHANNEL;
			data->page.audio.port[RIGHT_PORT].channels = 
				RIGHT_CHANNEL;
			data->page.audio.port[2].channels = 0;
			data->page.audio.port[3].channels = 0;
			error = cdsetmode(periph, data);
			free(data, M_TEMP);
		}
		break;
	case CDIOCRESUME:
		error = cdpause(periph, 1);
		break;
	case CDIOCPAUSE:
		error = cdpause(periph, 0);
		break;
	case CDIOCSTART:
		error = cdstartunit(periph);
		break;
	case CDIOCSTOP:
		error = cdstopunit(periph, 0);
		break;
	case CDIOCEJECT:
		error = cdstopunit(periph, 1);
		break;
	case CDIOCALLOW:
		cdprevent(periph, PR_ALLOW);
		break;
	case CDIOCPREVENT:
		cdprevent(periph, PR_PREVENT);
		break;
	case CDIOCSETDEBUG:
		/* sc_link->flags |= (SDEV_DB1 | SDEV_DB2); */
		error = ENOTTY;
		break;
	case CDIOCCLRDEBUG:
		/* sc_link->flags &= ~(SDEV_DB1 | SDEV_DB2); */
		error = ENOTTY;
		break;
	case CDIOCRESET:
		/* return (cd_reset(periph)); */
		error = ENOTTY;
		break;
	default:
		if (cmd == DIOCSBAD) {
			error = EINVAL;	/* XXX */ 
			break;
		}

		/*
		 * Check to see whether we've got a disk-type ioctl.  If we
		 * don't, dsioctl will pass back an error code of ENOIOCTL.
		 */
		error = dsioctl("cd", dev, cmd, addr, flag, &softc->cd_slices,
				cdstrategy, (ds_setgeom_t *)NULL);

		if (error != ENOIOCTL)
			break;

		error = cam_periph_ioctl(periph, cmd, addr, cderror);
		break;
	}

	cam_periph_unlock(periph);

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("leaving cdioctl\n"));

	return (error);
}

static void
cdprevent(struct cam_periph *periph, int action)
{
	union	ccb *ccb;
	struct	cd_softc *softc;
	int	error;

	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("entering cdprevent\n"));

	softc = (struct cd_softc *)periph->softc;
	
	if (((action == PR_ALLOW)
	  && (softc->flags & CD_FLAG_DISC_LOCKED) == 0)
	 || ((action == PR_PREVENT)
	  && (softc->flags & CD_FLAG_DISC_LOCKED) != 0)) {
		return;
	}
	    
	ccb = cdgetccb(periph, /* priority */ 1);

	scsi_prevent(&ccb->csio, 
		     /*retries*/ 1,
		     cddone,
		     MSG_SIMPLE_Q_TAG,
		     action,
		     SSD_FULL_SIZE,
		     /* timeout */60000);
	
	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA|SF_NO_PRINT);

	xpt_release_ccb(ccb);

	if (error == 0) {
		if (action == PR_ALLOW)
			softc->flags &= ~CD_FLAG_DISC_LOCKED;
		else
			softc->flags |= CD_FLAG_DISC_LOCKED;
	}
}

static int
cdsize(dev_t dev, u_int32_t *size)
{
	struct cam_periph *periph;
	struct cd_softc *softc;
	union ccb *ccb;
	struct scsi_read_capacity_data *rcap_buf;
	int error;

	periph = cam_extend_get(cdperiphs, dkunit(dev));

	if (periph == NULL)
		return (ENXIO);
        
	CAM_DEBUG(periph->path, CAM_DEBUG_TRACE, ("entering cdsize\n"));

	softc = (struct cd_softc *)periph->softc;
             
	ccb = cdgetccb(periph, /* priority */ 1);

	rcap_buf = malloc(sizeof(struct scsi_read_capacity_data), 
			  M_TEMP, M_WAITOK);

	scsi_read_capacity(&ccb->csio, 
			   /*retries*/ 1,
			   cddone,
			   MSG_SIMPLE_Q_TAG,
			   rcap_buf,
			   SSD_FULL_SIZE,
			   /* timeout */20000);

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA|SF_NO_PRINT);

	xpt_release_ccb(ccb);

	softc->params.disksize = scsi_4btoul(rcap_buf->addr) + 1;
	softc->params.blksize  = scsi_4btoul(rcap_buf->length);

	free(rcap_buf, M_TEMP);
	*size = softc->params.disksize;

	return (error);

}

static int
cderror(union ccb *ccb, u_int32_t cam_flags, u_int32_t sense_flags)
{
	struct cd_softc *softc;
	struct cam_periph *periph;

	periph = xpt_path_periph(ccb->ccb_h.path);
	softc = (struct cd_softc *)periph->softc;

	/*
	 * XXX
	 * Until we have a better way of doing pack validation,
	 * don't treat UAs as errors.
	 */
	sense_flags |= SF_RETRY_UA;
	return (cam_periph_error(ccb, cam_flags, sense_flags, 
				 &softc->saved_ccb));
}

/*
 * Read table of contents
 */
static int 
cdreadtoc(struct cam_periph *periph, u_int32_t mode, u_int32_t start, 
	    struct cd_toc_entry *data, u_int32_t len)
{
	struct scsi_read_toc *scsi_cmd;
	u_int32_t ntoc;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	ntoc = len;
	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_IN,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ (u_int8_t *)data,
		      /* dxfer_len */ len,
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_read_toc),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_read_toc *)&csio->cdb_io.cdb_bytes;
	bzero (scsi_cmd, sizeof(*scsi_cmd));

	if (mode == CD_MSF_FORMAT)
		scsi_cmd->byte2 |= CD_MSF;
	scsi_cmd->from_track = start;
	/* scsi_ulto2b(ntoc, (u_int8_t *)scsi_cmd->data_len); */
	scsi_cmd->data_len[0] = (ntoc) >> 8;
	scsi_cmd->data_len[1] = (ntoc) & 0xff;

	scsi_cmd->op_code = READ_TOC;

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}

static int
cdreadsubchannel(struct cam_periph *periph, u_int32_t mode, 
		 u_int32_t format, int track, 
		 struct cd_sub_channel_info *data, u_int32_t len) 
{
	struct scsi_read_subchannel *scsi_cmd;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_IN,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ (u_int8_t *)data,
		      /* dxfer_len */ len,
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_read_subchannel),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_read_subchannel *)&csio->cdb_io.cdb_bytes;
	bzero (scsi_cmd, sizeof(*scsi_cmd));

	scsi_cmd->op_code = READ_SUBCHANNEL;
	if (mode == CD_MSF_FORMAT)
		scsi_cmd->byte1 |= CD_MSF;
	scsi_cmd->byte2 = SRS_SUBQ;
	scsi_cmd->subchan_format = format;
	scsi_cmd->track = track;
	scsi_ulto2b(len, (u_int8_t *)scsi_cmd->data_len);
	scsi_cmd->control = 0;

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}


static int
cdgetmode(struct cam_periph *periph, struct cd_mode_data *data, u_int32_t page)
{
	struct scsi_mode_sense_6 *scsi_cmd;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	bzero(data, sizeof(*data));
	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_IN,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ (u_int8_t *)data,
		      /* dxfer_len */ sizeof(*data),
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_mode_sense_6),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_mode_sense_6 *)&csio->cdb_io.cdb_bytes;
	bzero (scsi_cmd, sizeof(*scsi_cmd));

	scsi_cmd->page = page;
	scsi_cmd->length = sizeof(*data) & 0xff;
	scsi_cmd->opcode = MODE_SENSE;

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}

static int
cdsetmode(struct cam_periph *periph, struct cd_mode_data *data)
{
	struct scsi_mode_select_6 *scsi_cmd;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	error = 0;

	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_OUT,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ (u_int8_t *)data,
		      /* dxfer_len */ sizeof(*data),
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_mode_select_6),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_mode_select_6 *)&csio->cdb_io.cdb_bytes;

	bzero(scsi_cmd, sizeof(*scsi_cmd));
	scsi_cmd->opcode = MODE_SELECT;
	scsi_cmd->byte2 |= SMS_PF;
	scsi_cmd->length = sizeof(*data) & 0xff;
	data->header.data_length = 0;
	/*
	 * SONY drives do not allow a mode select with a medium_type
	 * value that has just been returned by a mode sense; use a
	 * medium_type of 0 (Default) instead.
	 */
	data->header.medium_type = 0;

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}


static int 
cdplay(struct cam_periph *periph, u_int32_t blk, u_int32_t len)
{
	struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;
	u_int8_t cdb_len;

	error = 0;
	ccb = cdgetccb(periph, /* priority */ 1);
	csio = &ccb->csio;
	/*
	 * Use the smallest possible command to perform the operation.
	 */
	if ((len & 0xffff0000) == 0) {
		/*
		 * We can fit in a 10 byte cdb.
		 */
		struct scsi_play_10 *scsi_cmd;

		scsi_cmd = (struct scsi_play_10 *)&csio->cdb_io.cdb_bytes;
		bzero (scsi_cmd, sizeof(*scsi_cmd));
		scsi_cmd->op_code = PLAY_10;
		scsi_ulto4b(blk, (u_int8_t *)scsi_cmd->blk_addr);
		scsi_ulto2b(len, (u_int8_t *)scsi_cmd->xfer_len);
		cdb_len = sizeof(*scsi_cmd);
	} else  {
		struct scsi_play_12 *scsi_cmd;

		scsi_cmd = (struct scsi_play_12 *)&csio->cdb_io.cdb_bytes;
		bzero (scsi_cmd, sizeof(*scsi_cmd));
		scsi_cmd->op_code = PLAY_12;
		scsi_ulto4b(blk, (u_int8_t *)scsi_cmd->blk_addr);
		scsi_ulto4b(len, (u_int8_t *)scsi_cmd->xfer_len);
		cdb_len = sizeof(*scsi_cmd);
	}
	cam_fill_csio(csio,
		      /*retries*/2,
		      cddone,
		      /*flags*/CAM_DIR_NONE,
		      MSG_SIMPLE_Q_TAG,
		      /*dataptr*/NULL,
		      /*datalen*/0,
		      /*sense_len*/SSD_FULL_SIZE,
		      cdb_len,
		      /*timeout*/50 * 1000);

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
			 /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}

static int
cdplaymsf(struct cam_periph *periph, u_int32_t startm, u_int32_t starts,
	  u_int32_t startf, u_int32_t endm, u_int32_t ends, u_int32_t endf)
{
	struct scsi_play_msf *scsi_cmd;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_NONE,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ NULL,
		      /* dxfer_len */ 0,
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_play_msf),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_play_msf *)&csio->cdb_io.cdb_bytes;
	bzero (scsi_cmd, sizeof(*scsi_cmd));

        scsi_cmd->op_code = PLAY_MSF;
        scsi_cmd->start_m = startm;
        scsi_cmd->start_s = starts;
        scsi_cmd->start_f = startf;
        scsi_cmd->end_m = endm;
        scsi_cmd->end_s = ends;
        scsi_cmd->end_f = endf; 

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);
	
	xpt_release_ccb(ccb);

	return(error);
}


static int
cdplaytracks(struct cam_periph *periph, u_int32_t strack, u_int32_t sindex,
	     u_int32_t etrack, u_int32_t eindex)
{
	struct scsi_play_track *scsi_cmd;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_NONE,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ NULL,
		      /* dxfer_len */ 0,
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_play_track),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_play_track *)&csio->cdb_io.cdb_bytes;
	bzero (scsi_cmd, sizeof(*scsi_cmd));

        scsi_cmd->op_code = PLAY_TRACK;
        scsi_cmd->start_track = strack;
        scsi_cmd->start_index = sindex;
        scsi_cmd->end_track = etrack;
        scsi_cmd->end_index = eindex;

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}

static int
cdpause(struct cam_periph *periph, u_int32_t go)
{
	struct scsi_pause *scsi_cmd;
        struct ccb_scsiio *csio;
	union ccb *ccb;
	int error;

	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	csio = &ccb->csio;

	cam_fill_csio(csio, 
		      /* retries */ 1, 
		      /* cbfcnp */ cddone, 
		      /* flags */ CAM_DIR_NONE,
		      /* tag_action */ MSG_SIMPLE_Q_TAG,
		      /* data_ptr */ NULL,
		      /* dxfer_len */ 0,
		      /* sense_len */ SSD_FULL_SIZE,
		      sizeof(struct scsi_pause),
 		      /* timeout */ 50000);

	scsi_cmd = (struct scsi_pause *)&csio->cdb_io.cdb_bytes;
	bzero (scsi_cmd, sizeof(*scsi_cmd));

        scsi_cmd->op_code = PAUSE;
	scsi_cmd->resume = go;

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}

static int
cdstartunit(struct cam_periph *periph)
{
	union ccb *ccb;
	int error;

	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	scsi_start_stop(&ccb->csio,
			/* retries */ 1,
			/* cbfcnp */ cddone,
			/* tag_action */ MSG_SIMPLE_Q_TAG,
			/* start */ TRUE,
			/* load_eject */ TRUE,
			/* immediate */ FALSE,
			/* sense_len */ SSD_FULL_SIZE,
			/* timeout */ 50000);

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}

static int
cdstopunit(struct cam_periph *periph, u_int32_t eject)
{
	union ccb *ccb;
	int error;

	error = 0;

	ccb = cdgetccb(periph, /* priority */ 1);

	scsi_start_stop(&ccb->csio,
			/* retries */ 1,
			/* cbfcnp */ cddone,
			/* tag_action */ MSG_SIMPLE_Q_TAG,
			/* start */ FALSE,
			/* load_eject */ eject,
			/* immediate */ FALSE,
			/* sense_len */ SSD_FULL_SIZE,
			/* timeout */ 50000);

	error = cdrunccb(ccb, cderror, /*cam_flags*/0,
				  /*sense_flags*/SF_RETRY_UA);

	xpt_release_ccb(ccb);

	return(error);
}
