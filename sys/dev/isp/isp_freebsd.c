/* $FreeBSD$ */
/*
 * Platform (FreeBSD) dependent common attachment code for Qlogic adapters.
 *
 * Copyright (c) 1997, 1998, 1999, 2000, 2001 by Matthew Jacob
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
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
 */
#include <dev/isp/isp_freebsd.h>
#include <sys/unistd.h>
#include <sys/kthread.h>
#include <machine/stdarg.h>	/* for use by isp_prt below */
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <dev/isp/isp_ioctl.h>


static d_ioctl_t ispioctl;
static void isp_intr_enable(void *);
static void isp_cam_async(void *, u_int32_t, struct cam_path *, void *);
static void isp_poll(struct cam_sim *);
#if	0
static void isp_relsim(void *);
#endif
static timeout_t isp_watchdog;
static void isp_kthread(void *);
static void isp_action(struct cam_sim *, union ccb *);


#define ISP_CDEV_MAJOR	248
static struct cdevsw isp_cdevsw = {
	/* open */	nullopen,
	/* close */	nullclose,
	/* read */	noread,
	/* write */	nowrite,
	/* ioctl */	ispioctl,
	/* poll */	nopoll,
	/* mmap */	nommap,
	/* strategy */	nostrategy,
	/* name */	"isp",
	/* maj */	ISP_CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	D_TAPE,
};

static struct ispsoftc *isplist = NULL;

void
isp_attach(struct ispsoftc *isp)
{
	int primary, secondary;
	struct ccb_setasync csa;
	struct cam_devq *devq;
	struct cam_sim *sim;
	struct cam_path *path;

	/*
	 * Establish (in case of 12X0) which bus is the primary.
	 */

	primary = 0;
	secondary = 1;

	/*
	 * Create the device queue for our SIM(s).
	 */
	devq = cam_simq_alloc(isp->isp_maxcmds);
	if (devq == NULL) {
		return;
	}

	/*
	 * Construct our SIM entry.
	 */
	sim = cam_sim_alloc(isp_action, isp_poll, "isp", isp,
	    device_get_unit(isp->isp_dev), 1, isp->isp_maxcmds, devq);
	if (sim == NULL) {
		cam_simq_free(devq);
		return;
	}

	isp->isp_osinfo.ehook.ich_func = isp_intr_enable;
	isp->isp_osinfo.ehook.ich_arg = isp;
	if (config_intrhook_establish(&isp->isp_osinfo.ehook) != 0) {
		isp_prt(isp, ISP_LOGERR,
		    "could not establish interrupt enable hook");
		cam_sim_free(sim, TRUE);
		return;
	}

	if (xpt_bus_register(sim, primary) != CAM_SUCCESS) {
		cam_sim_free(sim, TRUE);
		return;
	}

	if (xpt_create_path(&path, NULL, cam_sim_path(sim),
	    CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD) != CAM_REQ_CMP) {
		xpt_bus_deregister(cam_sim_path(sim));
		cam_sim_free(sim, TRUE);
		config_intrhook_disestablish(&isp->isp_osinfo.ehook);
		return;
	}

	xpt_setup_ccb(&csa.ccb_h, path, 5);
	csa.ccb_h.func_code = XPT_SASYNC_CB;
	csa.event_enable = AC_LOST_DEVICE;
	csa.callback = isp_cam_async;
	csa.callback_arg = sim;
	xpt_action((union ccb *)&csa);
	isp->isp_sim = sim;
	isp->isp_path = path;
	/*
	 * Create a kernel thread for fibre channel instances. We
	 * don't have dual channel FC cards.
	 */
	if (IS_FC(isp)) {
		cv_init(&isp->isp_osinfo.kthread_cv, "isp_kthread_cv");
		if (kthread_create(isp_kthread, isp, &isp->isp_osinfo.kproc,
		    RFHIGHPID, "%s: fc_thrd",
		    device_get_nameunit(isp->isp_dev))) {
			isp_prt(isp, ISP_LOGERR, "could not create kthread");
			xpt_bus_deregister(cam_sim_path(sim));
			cam_sim_free(sim, TRUE);
			config_intrhook_disestablish(&isp->isp_osinfo.ehook);
			return;
		}
	}


	/*
	 * If we have a second channel, construct SIM entry for that.
	 */
	if (IS_DUALBUS(isp)) {
		sim = cam_sim_alloc(isp_action, isp_poll, "isp", isp,
		    device_get_unit(isp->isp_dev), 1, isp->isp_maxcmds, devq);
		if (sim == NULL) {
			xpt_bus_deregister(cam_sim_path(isp->isp_sim));
			xpt_free_path(isp->isp_path);
			cam_simq_free(devq);
			config_intrhook_disestablish(&isp->isp_osinfo.ehook);
			return;
		}
		if (xpt_bus_register(sim, secondary) != CAM_SUCCESS) {
			xpt_bus_deregister(cam_sim_path(isp->isp_sim));
			xpt_free_path(isp->isp_path);
			cam_sim_free(sim, TRUE);
			config_intrhook_disestablish(&isp->isp_osinfo.ehook);
			return;
		}

		if (xpt_create_path(&path, NULL, cam_sim_path(sim),
		    CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD) != CAM_REQ_CMP) {
			xpt_bus_deregister(cam_sim_path(isp->isp_sim));
			xpt_free_path(isp->isp_path);
			xpt_bus_deregister(cam_sim_path(sim));
			cam_sim_free(sim, TRUE);
			config_intrhook_disestablish(&isp->isp_osinfo.ehook);
			return;
		}

		xpt_setup_ccb(&csa.ccb_h, path, 5);
		csa.ccb_h.func_code = XPT_SASYNC_CB;
		csa.event_enable = AC_LOST_DEVICE;
		csa.callback = isp_cam_async;
		csa.callback_arg = sim;
		xpt_action((union ccb *)&csa);
		isp->isp_sim2 = sim;
		isp->isp_path2 = path;
	}

	/*
	 * Create device nodes
	 */
	(void) make_dev(&isp_cdevsw, device_get_unit(isp->isp_dev), UID_ROOT,
	    GID_OPERATOR, 0600, "%s", device_get_nameunit(isp->isp_dev));

	if (isp->isp_role != ISP_ROLE_NONE) {
		isp->isp_state = ISP_RUNSTATE;
		ENABLE_INTS(isp);
	}
	if (isplist == NULL) {
		isplist = isp;
	} else {
		struct ispsoftc *tmp = isplist;
		while (tmp->isp_osinfo.next) {
			tmp = tmp->isp_osinfo.next;
		}
		tmp->isp_osinfo.next = isp;
	}

}

static int
ispioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc *p)
{
	struct ispsoftc *isp;
	int retval = ENOTTY;

	isp = isplist;
	while (isp) {
		if (minor(dev) == device_get_unit(isp->isp_dev)) {
			break;
		}
		isp = isp->isp_osinfo.next;
	}
	if (isp == NULL)
		return (ENXIO);
	
	switch (cmd) {
	case ISP_SDBLEV:
	{
		int olddblev = isp->isp_dblev;
		isp->isp_dblev = *(int *)addr;
		*(int *)addr = olddblev;
		retval = 0;
		break;
	}
	case ISP_RESETHBA:
		ISP_LOCK(isp);
		isp_reinit(isp);
		ISP_UNLOCK(isp);
		retval = 0;
		break;
	case ISP_FC_RESCAN:
		if (IS_FC(isp)) {
			ISP_LOCK(isp);
			if (isp_fc_runstate(isp, 5 * 1000000)) {
				retval = EIO;
			} else {
				retval = 0;
			}
			ISP_UNLOCK(isp);
		}
		break;
	case ISP_FC_LIP:
		if (IS_FC(isp)) {
			ISP_LOCK(isp);
			if (isp_control(isp, ISPCTL_SEND_LIP, 0)) {
				retval = EIO;
			} else {
				retval = 0;
			}
			ISP_UNLOCK(isp);
		}
		break;
	case ISP_FC_GETDINFO:
	{
		struct isp_fc_device *ifc = (struct isp_fc_device *) addr;
		struct lportdb *lp;

		if (ifc->loopid < 0 || ifc->loopid >= MAX_FC_TARG) {
			retval = EINVAL;
			break;
		}
		ISP_LOCK(isp);
		lp = &FCPARAM(isp)->portdb[ifc->loopid];
		if (lp->valid) {
			ifc->loopid = lp->loopid;
			ifc->portid = lp->portid;
			ifc->node_wwn = lp->node_wwn;
			ifc->port_wwn = lp->port_wwn;
			retval = 0;
		} else {
			retval = ENODEV;
		}
		ISP_UNLOCK(isp);
		break;
	}
	default:
		break;
	}
	return (retval);
}

static void
isp_intr_enable(void *arg)
{
	struct ispsoftc *isp = arg;
	if (isp->isp_role != ISP_ROLE_NONE) {
		ENABLE_INTS(isp);
		isp->isp_osinfo.intsok = 1;
	}
	/* Release our hook so that the boot can continue. */
	config_intrhook_disestablish(&isp->isp_osinfo.ehook);
}

/*
 * Put the target mode functions here, because some are inlines
 */

#ifdef	ISP_TARGET_MODE

static __inline int is_lun_enabled(struct ispsoftc *, int, lun_id_t);
static __inline int are_any_luns_enabled(struct ispsoftc *, int);
static __inline tstate_t *get_lun_statep(struct ispsoftc *, int, lun_id_t);
static __inline void rls_lun_statep(struct ispsoftc *, tstate_t *);
static __inline int isp_psema_sig_rqe(struct ispsoftc *);
static __inline int isp_cv_wait_timed_rqe(struct ispsoftc *, int);
static __inline void isp_cv_signal_rqe(struct ispsoftc *, int);
static __inline void isp_vsema_rqe(struct ispsoftc *);
static cam_status
create_lun_state(struct ispsoftc *, int, struct cam_path *, tstate_t **);
static void destroy_lun_state(struct ispsoftc *, tstate_t *);
static void isp_en_lun(struct ispsoftc *, union ccb *);
static cam_status isp_abort_tgt_ccb(struct ispsoftc *, union ccb *);
static timeout_t isp_refire_putback_atio;
static void isp_complete_ctio(union ccb *);
static void isp_target_putback_atio(union ccb *);
static cam_status isp_target_start_ctio(struct ispsoftc *, union ccb *);
static int isp_handle_platform_atio(struct ispsoftc *, at_entry_t *);
static int isp_handle_platform_atio2(struct ispsoftc *, at2_entry_t *);
static int isp_handle_platform_ctio(struct ispsoftc *, void *);

static __inline int
is_lun_enabled(struct ispsoftc *isp, int bus, lun_id_t lun)
{
	tstate_t *tptr;
	tptr = isp->isp_osinfo.lun_hash[LUN_HASH_FUNC(isp, bus, lun)];
	if (tptr == NULL) {
		ISP_UNLOCK(isp);
		return (0);
	}
	do {
		if (tptr->lun == (lun_id_t) lun && tptr->bus == bus) {
			ISP_UNLOCK(isp);
			return (1);
		}
	} while ((tptr = tptr->next) != NULL);
	return (0);
}

static __inline int
are_any_luns_enabled(struct ispsoftc *isp, int port)
{
	int lo, hi;
	if (IS_DUALBUS(isp)) {
		lo = (port * (LUN_HASH_SIZE >> 1));
		hi = lo + (LUN_HASH_SIZE >> 1);
	} else {
		lo = 0;
		hi = LUN_HASH_SIZE;
	}
	for (lo = 0; lo < hi; lo++) {
		if (isp->isp_osinfo.lun_hash[lo]) {
			return (1);
		}
	}
	return (0);
}

static __inline tstate_t *
get_lun_statep(struct ispsoftc *isp, int bus, lun_id_t lun)
{
	tstate_t *tptr;

	if (lun == CAM_LUN_WILDCARD) {
		tptr = &isp->isp_osinfo.tsdflt[bus];
		tptr->hold++;
		return (tptr);
	} else {
		tptr = isp->isp_osinfo.lun_hash[LUN_HASH_FUNC(isp, bus, lun)];
	}
	if (tptr == NULL) {
		return (NULL);
	}

	do {
		if (tptr->lun == lun && tptr->bus == bus) {
			tptr->hold++;
			return (tptr);
		}
	} while ((tptr = tptr->next) != NULL);
	return (tptr);
}

static __inline void
rls_lun_statep(struct ispsoftc *isp, tstate_t *tptr)
{
	if (tptr->hold)
		tptr->hold--;
}

static __inline int
isp_psema_sig_rqe(struct ispsoftc *isp)
{
	while (isp->isp_osinfo.tmflags & TM_BUSY) {
		isp->isp_osinfo.tmflags |= TM_WANTED;
		if (tsleep(&isp->isp_osinfo.tmflags, PRIBIO|PCATCH, "i0", 0)) {
			return (-1);
		}
		isp->isp_osinfo.tmflags |= TM_BUSY;
	}
	return (0);
}

static __inline int
isp_cv_wait_timed_rqe(struct ispsoftc *isp, int timo)
{
	if (tsleep(&isp->isp_osinfo.rstatus, PRIBIO, "qt1", timo)) {
		ISP_UNLOCK(isp);
		return (-1);
	}
	return (0);
}

static __inline void
isp_cv_signal_rqe(struct ispsoftc *isp, int status)
{
	isp->isp_osinfo.rstatus = status;
	wakeup(&isp->isp_osinfo.rstatus);
}

static __inline void
isp_vsema_rqe(struct ispsoftc *isp)
{
	if (isp->isp_osinfo.tmflags & TM_WANTED) {
		isp->isp_osinfo.tmflags &= ~TM_WANTED;
		wakeup(&isp->isp_osinfo.tmflags);
	}
	isp->isp_osinfo.tmflags &= ~TM_BUSY;
}

static cam_status
create_lun_state(struct ispsoftc *isp, int bus,
    struct cam_path *path, tstate_t **rslt)
{
	cam_status status;
	lun_id_t lun;
	int hfx;
	tstate_t *tptr, *new;

	lun = xpt_path_lun_id(path);
	if (lun < 0) {
		return (CAM_LUN_INVALID);
	}
	if (is_lun_enabled(isp, bus, lun)) {
		return (CAM_LUN_ALRDY_ENA);
	}
	new = (tstate_t *) malloc(sizeof (tstate_t), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (new == NULL) {
		return (CAM_RESRC_UNAVAIL);
	}

	status = xpt_create_path(&new->owner, NULL, xpt_path_path_id(path),
	    xpt_path_target_id(path), xpt_path_lun_id(path));
	if (status != CAM_REQ_CMP) {
		free(new, M_DEVBUF);
		return (status);
	}
	new->bus = bus;
	new->lun = lun;
	SLIST_INIT(&new->atios);
	SLIST_INIT(&new->inots);
	new->hold = 1;

	hfx = LUN_HASH_FUNC(isp, new->bus, new->lun);
	tptr = isp->isp_osinfo.lun_hash[hfx];
	if (tptr == NULL) {
		isp->isp_osinfo.lun_hash[hfx] = new;
	} else {
		while (tptr->next)
			tptr = tptr->next;
		tptr->next = new;
	}
	*rslt = new;
	return (CAM_REQ_CMP);
}

static __inline void
destroy_lun_state(struct ispsoftc *isp, tstate_t *tptr)
{
	int hfx;
	tstate_t *lw, *pw;

	hfx = LUN_HASH_FUNC(isp, tptr->bus, tptr->lun);
	if (tptr->hold) {
		return;
	}
	pw = isp->isp_osinfo.lun_hash[hfx];
	if (pw == NULL) {
		return;
	} else if (pw->lun == tptr->lun && pw->bus == tptr->bus) {
		isp->isp_osinfo.lun_hash[hfx] = pw->next;
	} else {
		lw = pw;
		pw = lw->next;
		while (pw) {
			if (pw->lun == tptr->lun && pw->bus == tptr->bus) {
				lw->next = pw->next;
				break;
			}
			lw = pw;
			pw = pw->next;
		}
		if (pw == NULL) {
			ISP_UNLOCK(isp);
			return;
		}
	}
	free(tptr, M_DEVBUF);
}

/*
 * we enter with our locks held.
 */
static void
isp_en_lun(struct ispsoftc *isp, union ccb *ccb)
{
	const char lfmt[] = "Lun now %sabled for target mode on channel %d";
	struct ccb_en_lun *cel = &ccb->cel;
	tstate_t *tptr;
	u_int16_t rstat;
	int bus, cmd, frozen = 0;
	lun_id_t lun;
	target_id_t tgt;


	bus = XS_CHANNEL(ccb) & 0x1;
	tgt = ccb->ccb_h.target_id;
	lun = ccb->ccb_h.target_lun;

	/*
	 * Do some sanity checking first.
	 */

	if ((lun != CAM_LUN_WILDCARD) &&
	    (lun < 0 || lun >= (lun_id_t) isp->isp_maxluns)) {
		ccb->ccb_h.status = CAM_LUN_INVALID;
		return;
	}
	if (IS_SCSI(isp)) {
		sdparam *sdp = isp->isp_param;
		sdp += bus;
		if (tgt != CAM_TARGET_WILDCARD &&
		    tgt != sdp->isp_initiator_id) {
			ccb->ccb_h.status = CAM_TID_INVALID;
			return;
		}
	} else {
		if (tgt != CAM_TARGET_WILDCARD &&
		    tgt != FCPARAM(isp)->isp_iid) {
			ccb->ccb_h.status = CAM_TID_INVALID;
			return;
		}
	}

	if (tgt == CAM_TARGET_WILDCARD) {
		if (lun != CAM_LUN_WILDCARD) {
			ccb->ccb_h.status = CAM_LUN_INVALID;
			return;
		}
	}

	/*
	 * If Fibre Channel, stop and drain all activity to this bus.
	 */
#if	0
	if (IS_FC(isp)) {
		ISP_LOCK(isp);
		frozen = 1;
		xpt_freeze_simq(isp->isp_sim, 1);
		isp->isp_osinfo.drain = 1;
		while (isp->isp_osinfo.drain) {
			(void) msleep(&isp->isp_osinfo.drain, &isp->isp_lock,
			    PRIBIO, "ispdrain", 10 * hz);
		}
		ISP_UNLOCK(isp);
	}
#endif

	/*
	 * Check to see if we're enabling on fibre channel and
	 * don't yet have a notion of who the heck we are (no
	 * loop yet).
	 */
	if (IS_FC(isp) && cel->enable &&
	    (isp->isp_osinfo.tmflags & TM_TMODE_ENABLED) == 0) {
		fcparam *fcp = isp->isp_param;
		int rv;

		rv = isp_fc_runstate(isp, 2 * 1000000);
		if (fcp->isp_fwstate != FW_READY ||
		    fcp->isp_loopstate != LOOP_READY) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGWARN,
			    "could not get a good port database read");
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			if (frozen) {
				ISPLOCK_2_CAMLOCK(isp);
				xpt_release_simq(isp->isp_sim, 1);
				CAMLOCK_2_ISPLOCK(isp);
			}
			return;
		}
	}


	/*
	 * Next check to see whether this is a target/lun wildcard action.
	 *
	 * If so, we enable/disable target mode but don't do any lun enabling.
	 */
	if (lun == CAM_LUN_WILDCARD && tgt == CAM_TARGET_WILDCARD) {
		int av = bus << 31;
		tptr = &isp->isp_osinfo.tsdflt[bus];
		if (cel->enable) {
			if (isp->isp_osinfo.tmflags & (1 << bus)) {
				ccb->ccb_h.status = CAM_LUN_ALRDY_ENA;
				if (frozen) {
					ISPLOCK_2_CAMLOCK(isp);
					xpt_release_simq(isp->isp_sim, 1);
					CAMLOCK_2_ISPLOCK(isp);
				}
				return;
			}
			ccb->ccb_h.status =
			    xpt_create_path(&tptr->owner, NULL,
			    xpt_path_path_id(ccb->ccb_h.path),
			    xpt_path_target_id(ccb->ccb_h.path),
			    xpt_path_lun_id(ccb->ccb_h.path));
			if (ccb->ccb_h.status != CAM_REQ_CMP) {
				if (frozen) {
					ISPLOCK_2_CAMLOCK(isp);
					xpt_release_simq(isp->isp_sim, 1);
					CAMLOCK_2_ISPLOCK(isp);
				}
				return;
			}
			SLIST_INIT(&tptr->atios);
			SLIST_INIT(&tptr->inots);
			av |= ENABLE_TARGET_FLAG;
			av = isp_control(isp, ISPCTL_TOGGLE_TMODE, &av);
			if (av) {
				ccb->ccb_h.status = CAM_FUNC_NOTAVAIL;
				xpt_free_path(tptr->owner);
				if (frozen) {
					ISPLOCK_2_CAMLOCK(isp);
					xpt_release_simq(isp->isp_sim, 1);
					CAMLOCK_2_ISPLOCK(isp);
				}
				return;
			}
			isp->isp_osinfo.tmflags |= (1 << bus);
		} else {
			if ((isp->isp_osinfo.tmflags & (1 << bus)) == 0) {
				ccb->ccb_h.status = CAM_LUN_INVALID;
				if (frozen) {
					ISPLOCK_2_CAMLOCK(isp);
					xpt_release_simq(isp->isp_sim, 1);
					CAMLOCK_2_ISPLOCK(isp);
				}
				return;
			}
			if (are_any_luns_enabled(isp, bus)) {
				ccb->ccb_h.status = CAM_SCSI_BUSY;
				if (frozen) {
					ISPLOCK_2_CAMLOCK(isp);
					xpt_release_simq(isp->isp_sim, 1);
					CAMLOCK_2_ISPLOCK(isp);
				}
				return;
			}
			av = isp_control(isp, ISPCTL_TOGGLE_TMODE, &av);
			if (av) {
				ccb->ccb_h.status = CAM_FUNC_NOTAVAIL;
				if (frozen) {
					ISPLOCK_2_CAMLOCK(isp);
					xpt_release_simq(isp->isp_sim, 1);
					CAMLOCK_2_ISPLOCK(isp);
				}
				return;
			}
			isp->isp_osinfo.tmflags &= ~(1 << bus);
			ccb->ccb_h.status = CAM_REQ_CMP;
		}
		xpt_print_path(ccb->ccb_h.path);
		isp_prt(isp, ISP_LOGINFO, "Target Mode %sabled on channel %d",
		    (cel->enable) ? "en" : "dis", bus);
		if (frozen) {
			ISPLOCK_2_CAMLOCK(isp);
			xpt_release_simq(isp->isp_sim, 1);
			CAMLOCK_2_ISPLOCK(isp);
		}
		return;
	}

	/*
	 * We can move along now...
	 */

	if (frozen) {
		ISPLOCK_2_CAMLOCK(isp);
		xpt_release_simq(isp->isp_sim, 1);
		CAMLOCK_2_ISPLOCK(isp);
	}


	if (cel->enable) {
		ccb->ccb_h.status =
		    create_lun_state(isp, bus, ccb->ccb_h.path, &tptr);
		if (ccb->ccb_h.status != CAM_REQ_CMP) {
			return;
		}
	} else {
		tptr = get_lun_statep(isp, bus, lun);
		if (tptr == NULL) {
			ccb->ccb_h.status = CAM_LUN_INVALID;
			return;
		}
	}

	if (isp_psema_sig_rqe(isp)) {
		rls_lun_statep(isp, tptr);
		if (cel->enable)
			destroy_lun_state(isp, tptr);
		ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		return;
	}

	if (cel->enable) {
		u_int32_t seq = isp->isp_osinfo.rollinfo++;
		int c, n, ulun = lun;

		cmd = RQSTYPE_ENABLE_LUN;
		c = DFLT_CMND_CNT;
		n = DFLT_INOT_CNT;
		if (IS_FC(isp) && lun != 0) {
			cmd = RQSTYPE_MODIFY_LUN;
			n = 0;
			/*
		 	 * For SCC firmware, we only deal with setting
			 * (enabling or modifying) lun 0.
			 */
			ulun = 0;
		}
		rstat = LUN_ERR;
		if (isp_lun_cmd(isp, cmd, bus, tgt, ulun, c, n, seq)) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGWARN, "isp_lun_cmd failed");
			goto out;
		}
		if (isp_cv_wait_timed_rqe(isp, 30 * hz)) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR,
			    "wait for ENABLE/MODIFY LUN timed out");
			goto out;
		}
		rstat = isp->isp_osinfo.rstatus;
		if (rstat != LUN_OK) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR,
			    "ENABLE/MODIFY LUN returned 0x%x", rstat);
			goto out;
		}
	} else {
		int c, n, ulun = lun;
		u_int32_t seq;

		rstat = LUN_ERR;
		seq = isp->isp_osinfo.rollinfo++;
		cmd = -RQSTYPE_MODIFY_LUN;

		c = DFLT_CMND_CNT;
		n = DFLT_INOT_CNT;
		if (IS_FC(isp) && lun != 0) {
			n = 0;
			/*
		 	 * For SCC firmware, we only deal with setting
			 * (enabling or modifying) lun 0.
			 */
			ulun = 0;
		}
		if (isp_lun_cmd(isp, cmd, bus, tgt, ulun, c, n, seq)) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR, "isp_lun_cmd failed");
			goto out;
		}
		if (isp_cv_wait_timed_rqe(isp, 30 * hz)) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR,
			    "wait for MODIFY LUN timed out");
			goto out;
		}
		rstat = isp->isp_osinfo.rstatus;
		if (rstat != LUN_OK) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR,
			    "MODIFY LUN returned 0x%x", rstat);
			goto out;
		}
		if (IS_FC(isp) && lun) {
			goto out;
		}

		seq = isp->isp_osinfo.rollinfo++;

		rstat = LUN_ERR;
		cmd = -RQSTYPE_ENABLE_LUN;
		if (isp_lun_cmd(isp, cmd, bus, tgt, lun, 0, 0, seq)) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR, "isp_lun_cmd failed");
			goto out;
		}
		if (isp_cv_wait_timed_rqe(isp, 30 * hz)) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGERR,
			     "wait for DISABLE LUN timed out");
			goto out;
		}
		rstat = isp->isp_osinfo.rstatus;
		if (rstat != LUN_OK) {
			xpt_print_path(ccb->ccb_h.path);
			isp_prt(isp, ISP_LOGWARN,
			    "DISABLE LUN returned 0x%x", rstat);
			goto out;
		}
	}
out:
	isp_vsema_rqe(isp);

	if (rstat != LUN_OK) {
		xpt_print_path(ccb->ccb_h.path);
		isp_prt(isp, ISP_LOGWARN,
		    "lun %sable failed", (cel->enable) ? "en" : "dis");
		ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		rls_lun_statep(isp, tptr);
		if (cel->enable)
			destroy_lun_state(isp, tptr);
	} else {
		xpt_print_path(ccb->ccb_h.path);
		isp_prt(isp, ISP_LOGINFO, lfmt,
		    (cel->enable) ? "en" : "dis", bus);
		rls_lun_statep(isp, tptr);
		if (cel->enable == 0) {
			destroy_lun_state(isp, tptr);
		}
		ccb->ccb_h.status = CAM_REQ_CMP;
	}
}

static cam_status
isp_abort_tgt_ccb(struct ispsoftc *isp, union ccb *ccb)
{
	tstate_t *tptr;
	struct ccb_hdr_slist *lp;
	struct ccb_hdr *curelm;
	int found;
	union ccb *accb = ccb->cab.abort_ccb;

	if (accb->ccb_h.target_id != CAM_TARGET_WILDCARD) {
		if (IS_FC(isp) && (accb->ccb_h.target_id != 
		    ((fcparam *) isp->isp_param)->isp_loopid)) {
			return (CAM_PATH_INVALID);
		} else if (IS_SCSI(isp) && (accb->ccb_h.target_id != 
		    ((sdparam *) isp->isp_param)->isp_initiator_id)) {
			return (CAM_PATH_INVALID);
		}
	}
	tptr = get_lun_statep(isp, XS_CHANNEL(ccb), accb->ccb_h.target_lun);
	if (tptr == NULL) {
		return (CAM_PATH_INVALID);
	}
	if (accb->ccb_h.func_code == XPT_ACCEPT_TARGET_IO) {
		lp = &tptr->atios;
	} else if (accb->ccb_h.func_code == XPT_IMMED_NOTIFY) {
		lp = &tptr->inots;
	} else {
		rls_lun_statep(isp, tptr);
		return (CAM_UA_ABORT);
	}
	curelm = SLIST_FIRST(lp);
	found = 0;
	if (curelm == &accb->ccb_h) {
		found = 1;
		SLIST_REMOVE_HEAD(lp, sim_links.sle);
	} else {
		while(curelm != NULL) {
			struct ccb_hdr *nextelm;

			nextelm = SLIST_NEXT(curelm, sim_links.sle);
			if (nextelm == &accb->ccb_h) {
				found = 1;
				SLIST_NEXT(curelm, sim_links.sle) =
				    SLIST_NEXT(nextelm, sim_links.sle);
				break;
			}
			curelm = nextelm;
		}
	}
	rls_lun_statep(isp, tptr);
	if (found) {
		accb->ccb_h.status = CAM_REQ_ABORTED;
		return (CAM_REQ_CMP);
	}
	return(CAM_PATH_INVALID);
}

static cam_status
isp_target_start_ctio(struct ispsoftc *isp, union ccb *ccb)
{
	void *qe;
	struct ccb_scsiio *cso = &ccb->csio;
	u_int16_t *hp, save_handle;
	u_int16_t iptr, optr;


	if (isp_getrqentry(isp, &iptr, &optr, &qe)) {
		xpt_print_path(ccb->ccb_h.path);
		printf("Request Queue Overflow in isp_target_start_ctio\n");
		return (CAM_RESRC_UNAVAIL);
	}
	bzero(qe, QENTRY_LEN);

	/*
	 * We're either moving data or completing a command here.
	 */

	if (IS_FC(isp)) {
		struct ccb_accept_tio *atiop;
		ct2_entry_t *cto = qe;

		cto->ct_header.rqs_entry_type = RQSTYPE_CTIO2;
		cto->ct_header.rqs_entry_count = 1;
		cto->ct_iid = cso->init_id;
		if (isp->isp_maxluns <= 16) {
			cto->ct_lun = ccb->ccb_h.target_lun;
		}
		/*
		 * Start with a residual based on what the original datalength
		 * was supposed to be. Basically, we ignore what CAM has set
		 * for residuals. The data transfer routines will knock off
		 * the residual for each byte actually moved- and also will
		 * be responsible for setting the underrun flag.
		 */
		/* HACK! HACK! */
		if ((atiop = ccb->ccb_h.periph_priv.entries[1].ptr) != NULL) {
			cto->ct_resid = atiop->ccb_h.spriv_field0;
		}

		cto->ct_rxid = cso->tag_id;
		if (cso->dxfer_len == 0) {
			cto->ct_flags |= CT2_FLAG_MODE1 | CT2_NO_DATA;
			if (ccb->ccb_h.flags & CAM_SEND_STATUS) {
				cto->ct_flags |= CT2_SENDSTATUS;
				cto->rsp.m1.ct_scsi_status = cso->scsi_status;
			}
			if ((ccb->ccb_h.flags & CAM_SEND_SENSE) != 0) {
				int m = min(cso->sense_len, MAXRESPLEN);
				bcopy(&cso->sense_data, cto->rsp.m1.ct_resp, m);
				cto->rsp.m1.ct_senselen = m;
				cto->rsp.m1.ct_scsi_status |= CT2_SNSLEN_VALID;
			}
		} else {
			cto->ct_flags |= CT2_FLAG_MODE0;
			if ((cso->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
				cto->ct_flags |= CT2_DATA_IN;
			} else {
				cto->ct_flags |= CT2_DATA_OUT;
			}
			if ((ccb->ccb_h.flags & CAM_SEND_STATUS) != 0) {
				cto->ct_flags |= CT2_SENDSTATUS;
				cto->rsp.m0.ct_scsi_status = cso->scsi_status;
			}
			/*
			 * If we're sending data and status back together,
			 * we can't also send back sense data as well.
			 */
			ccb->ccb_h.flags &= ~CAM_SEND_SENSE;
		}
		if (cto->ct_flags & CT2_SENDSTATUS) {
			isp_prt(isp, ISP_LOGTDEBUG1,
			    "CTIO2[%x] SCSI STATUS 0x%x datalength %u",
			    cto->ct_rxid, cso->scsi_status, cto->ct_resid);
		}
		if  (cto->ct_flags & CT2_SENDSTATUS)
			cto->ct_flags |= CT2_CCINCR;
		cto->ct_timeout = 10;
		hp = &cto->ct_syshandle;
	} else {
		ct_entry_t *cto = qe;

		cto->ct_header.rqs_entry_type = RQSTYPE_CTIO;
		cto->ct_header.rqs_entry_count = 1;
		cto->ct_iid = cso->init_id;
		cto->ct_iid |= XS_CHANNEL(ccb) << 7;
		cto->ct_tgt = ccb->ccb_h.target_id;
		cto->ct_lun = ccb->ccb_h.target_lun;
		cto->ct_fwhandle = AT_GET_HANDLE(cso->tag_id);
		if (AT_HAS_TAG(cso->tag_id)) {
			cto->ct_tag_val = (u_int8_t) AT_GET_TAG(cso->tag_id);
			cto->ct_flags |= CT_TQAE;
		}
		if (ccb->ccb_h.flags & CAM_DIS_DISCONNECT) {
			cto->ct_flags |= CT_NODISC;
		}
		if (cso->dxfer_len == 0) {
			cto->ct_flags |= CT_NO_DATA;
		} else if ((cso->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
			cto->ct_flags |= CT_DATA_IN;
		} else {
			cto->ct_flags |= CT_DATA_OUT;
		}
		if (ccb->ccb_h.flags & CAM_SEND_STATUS) {
			cto->ct_flags |= CT_SENDSTATUS;
			cto->ct_scsi_status = cso->scsi_status;
			cto->ct_resid = cso->resid;
		}
		if (cto->ct_flags & CT_SENDSTATUS) {
			isp_prt(isp, ISP_LOGTDEBUG1,
			    "CTIO[%x] SCSI STATUS 0x%x resid %d tag_id %x",
			    cto->ct_fwhandle, cso->scsi_status, cso->resid,
			    cso->tag_id);
		}
		cto->ct_timeout = 10;
		hp = &cto->ct_syshandle;
		ccb->ccb_h.flags &= ~CAM_SEND_SENSE;
		if (cto->ct_flags & CT_SENDSTATUS)
			cto->ct_flags |= CT_CCINCR;
	}

	if (isp_save_xs(isp, (XS_T *)ccb, hp)) {
		xpt_print_path(ccb->ccb_h.path);
		printf("No XFLIST pointers for isp_target_start_ctio\n");
		return (CAM_RESRC_UNAVAIL);
	}


	/*
	 * Call the dma setup routines for this entry (and any subsequent
	 * CTIOs) if there's data to move, and then tell the f/w it's got
	 * new things to play with. As with isp_start's usage of DMA setup,
	 * any swizzling is done in the machine dependent layer. Because
	 * of this, we put the request onto the queue area first in native
	 * format.
	 */

	save_handle = *hp;

	switch (ISP_DMASETUP(isp, cso, qe, &iptr, optr)) {
	case CMD_QUEUED:
		ISP_ADD_REQUEST(isp, iptr);
		return (CAM_REQ_INPROG);

	case CMD_EAGAIN:
		ccb->ccb_h.status = CAM_RESRC_UNAVAIL;
		isp_destroy_handle(isp, save_handle);
		return (CAM_RESRC_UNAVAIL);

	default:
		isp_destroy_handle(isp, save_handle);
		return (XS_ERR(ccb));
	}
}

static void
isp_refire_putback_atio(void *arg)
{
	int s = splcam();
	isp_target_putback_atio(arg);
	splx(s);
}

static void
isp_target_putback_atio(union ccb *ccb)
{
	struct ispsoftc *isp;
	struct ccb_scsiio *cso;
	u_int16_t iptr, optr;
	void *qe;

	isp = XS_ISP(ccb);

	if (isp_getrqentry(isp, &iptr, &optr, &qe)) {
		(void) timeout(isp_refire_putback_atio, ccb, 10);
		isp_prt(isp, ISP_LOGWARN,
		    "isp_target_putback_atio: Request Queue Overflow"); 
		return;
	}
	bzero(qe, QENTRY_LEN);
	cso = &ccb->csio;
	if (IS_FC(isp)) {
		at2_entry_t *at = qe;
		at->at_header.rqs_entry_type = RQSTYPE_ATIO2;
		at->at_header.rqs_entry_count = 1;
		if (isp->isp_maxluns > 16) {
			at->at_scclun = (uint16_t) ccb->ccb_h.target_lun;
		} else {
			at->at_lun = (uint8_t) ccb->ccb_h.target_lun;
		}
		at->at_status = CT_OK;
		at->at_rxid = cso->tag_id;
		ISP_SWIZ_ATIO2(isp, qe, qe);
	} else {
		at_entry_t *at = qe;
		at->at_header.rqs_entry_type = RQSTYPE_ATIO;
		at->at_header.rqs_entry_count = 1;
		at->at_iid = cso->init_id;
		at->at_iid |= XS_CHANNEL(ccb) << 7;
		at->at_tgt = cso->ccb_h.target_id;
		at->at_lun = cso->ccb_h.target_lun;
		at->at_status = CT_OK;
		at->at_tag_val = AT_GET_TAG(cso->tag_id);
		at->at_handle = AT_GET_HANDLE(cso->tag_id);
		ISP_SWIZ_ATIO(isp, qe, qe);
	}
	ISP_TDQE(isp, "isp_target_putback_atio", (int) optr, qe);
	ISP_ADD_REQUEST(isp, iptr);
	isp_complete_ctio(ccb);
}

static void
isp_complete_ctio(union ccb *ccb)
{
	struct ispsoftc *isp = XS_ISP(ccb);
	if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_INPROG) {
		ccb->ccb_h.status |= CAM_REQ_CMP;
	}
	ccb->ccb_h.status &= ~CAM_SIM_QUEUED;
	if (isp->isp_osinfo.simqfrozen & SIMQFRZ_RESOURCE) {
		isp->isp_osinfo.simqfrozen &= ~SIMQFRZ_RESOURCE;
		if (isp->isp_osinfo.simqfrozen == 0) {
			if ((ccb->ccb_h.status & CAM_DEV_QFRZN) == 0) {
				isp_prt(isp, ISP_LOGDEBUG2, "ctio->relsimq");
				ccb->ccb_h.status |= CAM_RELEASE_SIMQ;
			} else {
				isp_prt(isp, ISP_LOGWARN, "ctio->devqfrozen");
			}
		} else {
			isp_prt(isp, ISP_LOGWARN,
			    "ctio->simqfrozen(%x)", isp->isp_osinfo.simqfrozen);
		}
	}
	xpt_done(ccb);
}

/*
 * Handle ATIO stuff that the generic code can't.
 * This means handling CDBs.
 */

static int
isp_handle_platform_atio(struct ispsoftc *isp, at_entry_t *aep)
{
	tstate_t *tptr;
	int status, bus;
	struct ccb_accept_tio *atiop;

	/*
	 * The firmware status (except for the QLTM_SVALID bit)
	 * indicates why this ATIO was sent to us.
	 *
	 * If QLTM_SVALID is set, the firware has recommended Sense Data.
	 *
	 * If the DISCONNECTS DISABLED bit is set in the flags field,
	 * we're still connected on the SCSI bus.
	 */
	status = aep->at_status;
	if ((status & ~QLTM_SVALID) == AT_PHASE_ERROR) {
		/*
		 * Bus Phase Sequence error. We should have sense data
		 * suggested by the f/w. I'm not sure quite yet what
		 * to do about this for CAM.
		 */
		isp_prt(isp, ISP_LOGWARN, "PHASE ERROR");
		isp_endcmd(isp, aep, SCSI_STATUS_BUSY, 0);
		return (0);
	}
	if ((status & ~QLTM_SVALID) != AT_CDB) {
		isp_prt(isp, ISP_LOGWARN, "bad atio (0x%x) leaked to platform",
		    status);
		isp_endcmd(isp, aep, SCSI_STATUS_BUSY, 0);
		return (0);
	}

	bus = GET_BUS_VAL(aep->at_iid);
	tptr = get_lun_statep(isp, bus, aep->at_lun);
	if (tptr == NULL) {
		tptr = get_lun_statep(isp, bus, CAM_LUN_WILDCARD);
	}

	if (tptr == NULL) {
		/*
		 * Because we can't autofeed sense data back with
		 * a command for parallel SCSI, we can't give back
		 * a CHECK CONDITION. We'll give back a BUSY status
		 * instead. This works out okay because the only
		 * time we should, in fact, get this, is in the
		 * case that somebody configured us without the
		 * blackhole driver, so they get what they deserve.
		 */
		isp_endcmd(isp, aep, SCSI_STATUS_BUSY, 0);
		return (0);
	}

	atiop = (struct ccb_accept_tio *) SLIST_FIRST(&tptr->atios);
	if (atiop == NULL) {
		/*
		 * Because we can't autofeed sense data back with
		 * a command for parallel SCSI, we can't give back
		 * a CHECK CONDITION. We'll give back a QUEUE FULL status
		 * instead. This works out okay because the only time we
		 * should, in fact, get this, is in the case that we've
		 * run out of ATIOS.
		 */
		xpt_print_path(tptr->owner);
		isp_prt(isp, ISP_LOGWARN,
		    "no ATIOS for lun %d from initiator %d on channel %d",
		    aep->at_lun, GET_IID_VAL(aep->at_iid), bus);
		rls_lun_statep(isp, tptr);
		if (aep->at_flags & AT_TQAE)
			isp_endcmd(isp, aep, SCSI_STATUS_QUEUE_FULL, 0);
		else
			isp_endcmd(isp, aep, SCSI_STATUS_BUSY, 0);
		return (0);
	}
	SLIST_REMOVE_HEAD(&tptr->atios, sim_links.sle);
	if (tptr == &isp->isp_osinfo.tsdflt[bus]) {
		atiop->ccb_h.target_id = aep->at_tgt;
		atiop->ccb_h.target_lun = aep->at_lun;
	}
	if (aep->at_flags & AT_NODISC) {
		atiop->ccb_h.flags = CAM_DIS_DISCONNECT;
	} else {
		atiop->ccb_h.flags = 0;
	}

	if (status & QLTM_SVALID) {
		size_t amt = imin(QLTM_SENSELEN, sizeof (atiop->sense_data));
		atiop->sense_len = amt;
		MEMCPY(&atiop->sense_data, aep->at_sense, amt);
	} else {
		atiop->sense_len = 0;
	}

	atiop->init_id = GET_IID_VAL(aep->at_iid);
	atiop->cdb_len = aep->at_cdblen;
	MEMCPY(atiop->cdb_io.cdb_bytes, aep->at_cdb, aep->at_cdblen);
	atiop->ccb_h.status = CAM_CDB_RECVD;
	/*
	 * Construct a tag 'id' based upon tag value (which may be 0..255)
	 * and the handle (which we have to preserve).
	 */
	AT_MAKE_TAGID(atiop->tag_id, aep);
	if (aep->at_flags & AT_TQAE) {
		atiop->tag_action = aep->at_tag_type;
		atiop->ccb_h.status |= CAM_TAG_ACTION_VALID;
	}
	xpt_done((union ccb*)atiop);
	isp_prt(isp, ISP_LOGTDEBUG1,
	    "ATIO[%x] CDB=0x%x bus %d iid%d->lun%d tag 0x%x ttype 0x%x %s",
	    aep->at_handle, aep->at_cdb[0] & 0xff, GET_BUS_VAL(aep->at_iid),
	    GET_IID_VAL(aep->at_iid), aep->at_lun, aep->at_tag_val & 0xff,
	    aep->at_tag_type, (aep->at_flags & AT_NODISC)?
	    "nondisc" : "disconnecting");
	rls_lun_statep(isp, tptr);
	return (0);
}

static int
isp_handle_platform_atio2(struct ispsoftc *isp, at2_entry_t *aep)
{
	lun_id_t lun;
	tstate_t *tptr;
	struct ccb_accept_tio *atiop;

	/*
	 * The firmware status (except for the QLTM_SVALID bit)
	 * indicates why this ATIO was sent to us.
	 *
	 * If QLTM_SVALID is set, the firware has recommended Sense Data.
	 */
	if ((aep->at_status & ~QLTM_SVALID) != AT_CDB) {
		isp_prt(isp, ISP_LOGWARN,
		    "bogus atio (0x%x) leaked to platform", aep->at_status);
		isp_endcmd(isp, aep, SCSI_STATUS_BUSY, 0);
		return (0);
	}

	if (isp->isp_maxluns > 16) {
		lun = aep->at_scclun;
	} else {
		lun = aep->at_lun;
	}
	tptr = get_lun_statep(isp, 0, lun);
	if (tptr == NULL) {
		tptr = get_lun_statep(isp, 0, CAM_LUN_WILDCARD);
	}

	if (tptr == NULL) {
		/*
		 * What we'd like to know is whether or not we have a listener
		 * upstream that really hasn't configured yet. If we do, then
		 * we can give a more sensible reply here. If not, then we can
		 * reject this out of hand.
		 *
		 * Choices for what to send were
		 *
                 *	Not Ready, Unit Not Self-Configured Yet
		 *	(0x2,0x3e,0x00)
		 *
		 * for the former and
		 *
		 *	Illegal Request, Logical Unit Not Supported
		 *	(0x5,0x25,0x00)
		 *
		 * for the latter.
		 *
		 * We used to decide whether there was at least one listener
		 * based upon whether the black hole driver was configured.
		 * However, recent config(8) changes have made this hard to do
		 * at this time.
		 *
		 */
		u_int32_t ccode = SCSI_STATUS_BUSY;

		/*
		 * Because we can't autofeed sense data back with
		 * a command for parallel SCSI, we can't give back
		 * a CHECK CONDITION. We'll give back a BUSY status
		 * instead. This works out okay because the only
		 * time we should, in fact, get this, is in the
		 * case that somebody configured us without the
		 * blackhole driver, so they get what they deserve.
		 */
		isp_endcmd(isp, aep, ccode, 0);
		return (0);
	}

	atiop = (struct ccb_accept_tio *) SLIST_FIRST(&tptr->atios);
	if (atiop == NULL) {
		/*
		 * Because we can't autofeed sense data back with
		 * a command for parallel SCSI, we can't give back
		 * a CHECK CONDITION. We'll give back a QUEUE FULL status
		 * instead. This works out okay because the only time we
		 * should, in fact, get this, is in the case that we've
		 * run out of ATIOS.
		 */
		xpt_print_path(tptr->owner);
		isp_prt(isp, ISP_LOGWARN,
		    "no ATIOS for lun %d from initiator %d", lun, aep->at_iid);
		rls_lun_statep(isp, tptr);
		if (aep->at_flags & AT_TQAE)
			isp_endcmd(isp, aep, SCSI_STATUS_QUEUE_FULL, 0);
		else
			isp_endcmd(isp, aep, SCSI_STATUS_BUSY, 0);
		return (0);
	}
	SLIST_REMOVE_HEAD(&tptr->atios, sim_links.sle);

	if (tptr == &isp->isp_osinfo.tsdflt[0]) {
		atiop->ccb_h.target_id =
			((fcparam *)isp->isp_param)->isp_loopid;
		atiop->ccb_h.target_lun = lun;
	}
	/*
	 * We don't get 'suggested' sense data as we do with SCSI cards.
	 */
	atiop->sense_len = 0;

	atiop->init_id = aep->at_iid;
	atiop->cdb_len = ATIO2_CDBLEN;
	MEMCPY(atiop->cdb_io.cdb_bytes, aep->at_cdb, ATIO2_CDBLEN);
	atiop->ccb_h.status = CAM_CDB_RECVD;
	atiop->tag_id = aep->at_rxid;
	switch (aep->at_taskflags & ATIO2_TC_ATTR_MASK) {
	case ATIO2_TC_ATTR_SIMPLEQ:
		atiop->tag_action = MSG_SIMPLE_Q_TAG;
		break;
        case ATIO2_TC_ATTR_HEADOFQ:
		atiop->tag_action = MSG_HEAD_OF_Q_TAG;
		break;
        case ATIO2_TC_ATTR_ORDERED:
		atiop->tag_action = MSG_ORDERED_Q_TAG;
		break;
        case ATIO2_TC_ATTR_ACAQ:		/* ?? */
	case ATIO2_TC_ATTR_UNTAGGED:
	default:
		atiop->tag_action = 0;
		break;
	}
	if (atiop->tag_action != 0) {
		atiop->ccb_h.status |= CAM_TAG_ACTION_VALID;
	}

	/*
	 * Preserve overall command datalength in private field.
	 */
	atiop->ccb_h.spriv_field0 = aep->at_datalen;

	xpt_done((union ccb*)atiop);
	isp_prt(isp, ISP_LOGTDEBUG1,
	    "ATIO2[%x] CDB=0x%x iid%d->lun%d tattr 0x%x datalen %u",
	    aep->at_rxid, aep->at_cdb[0] & 0xff, aep->at_iid,
	    lun, aep->at_taskflags, aep->at_datalen);
	rls_lun_statep(isp, tptr);
	return (0);
}

static int
isp_handle_platform_ctio(struct ispsoftc *isp, void *arg)
{
	union ccb *ccb;
	int sentstatus, ok, notify_cam, resid = 0;

	/*
	 * CTIO and CTIO2 are close enough....
	 */

	ccb = (union ccb *) isp_find_xs(isp, ((ct_entry_t *)arg)->ct_syshandle);
	KASSERT((ccb != NULL), ("null ccb in isp_handle_platform_ctio"));
	isp_destroy_handle(isp, ((ct_entry_t *)arg)->ct_syshandle);

	if (IS_FC(isp)) {
		ct2_entry_t *ct = arg;
		sentstatus = ct->ct_flags & CT2_SENDSTATUS;
		ok = (ct->ct_status & ~QLTM_SVALID) == CT_OK;
		if (ok && sentstatus && (ccb->ccb_h.flags & CAM_SEND_SENSE)) {
			ccb->ccb_h.status |= CAM_SENT_SENSE;
		}
		isp_prt(isp, ISP_LOGTDEBUG1,
		    "CTIO2[%x] sts 0x%x flg 0x%x sns %d %s",
		    ct->ct_rxid, ct->ct_status, ct->ct_flags,
		    (ccb->ccb_h.status & CAM_SENT_SENSE) != 0,
		    sentstatus? "FIN" : "MID");
		notify_cam = ct->ct_header.rqs_seqno & 0x1;
		if ((ct->ct_flags & CT2_DATAMASK) != CT2_NO_DATA) {
			resid = ct->ct_resid;
		}
	} else {
		ct_entry_t *ct = arg;
		sentstatus = ct->ct_flags & CT_SENDSTATUS;
		ok = (ct->ct_status  & ~QLTM_SVALID) == CT_OK;
		isp_prt(isp, ISP_LOGTDEBUG1,
		    "CTIO[%x] tag %x iid %x tgt %d lun %d sts 0x%x flg %x %s",
		    ct->ct_fwhandle, ct->ct_tag_val, ct->ct_iid, ct->ct_tgt,
		    ct->ct_lun, ct->ct_status, ct->ct_flags,
		    sentstatus? "FIN" : "MID");

		/*
		 * We *ought* to be able to get back to the original ATIO
		 * here, but for some reason this gets lost. It's just as
		 * well because it's squirrelled away as part of periph
		 * private data.
		 *
		 * We can live without it as long as we continue to use
		 * the auto-replenish feature for CTIOs.
		 */
		notify_cam = ct->ct_header.rqs_seqno & 0x1;
		if (ct->ct_status & QLTM_SVALID) {
			char *sp = (char *)ct;
			sp += CTIO_SENSE_OFFSET;
			ccb->csio.sense_len =
			    min(sizeof (ccb->csio.sense_data), QLTM_SENSELEN);
			MEMCPY(&ccb->csio.sense_data, sp, ccb->csio.sense_len);
			ccb->ccb_h.status |= CAM_AUTOSNS_VALID;
		}
		if ((ct->ct_flags & CT_DATAMASK) != CT_NO_DATA) {
			resid = ct->ct_resid;
		}
	}
	ccb->csio.resid += resid;

	/*
	 * We're here either because intermediate data transfers are done
	 * and/or the final status CTIO (which may have joined with a
	 * Data Transfer) is done.
	 *
	 * In any case, for this platform, the upper layers figure out
	 * what to do next, so all we do here is collect status and
	 * pass information along. Any DMA handles have already been
	 * freed.
	 */
	if (notify_cam == 0) {
		isp_prt(isp, ISP_LOGTDEBUG0, "  INTER CTIO done");
		return (0);
	}

	isp_prt(isp, ISP_LOGTDEBUG0, "%s CTIO done (resid %d)",
	    (sentstatus)? "  FINAL " : "MIDTERM ", ccb->csio.resid);

	if (!ok) {
		isp_target_putback_atio(ccb);
	} else {
		isp_complete_ctio(ccb);

	}
	return (0);
}
#endif

static void
isp_cam_async(void *cbarg, u_int32_t code, struct cam_path *path, void *arg)
{
	struct cam_sim *sim;
	struct ispsoftc *isp;

	sim = (struct cam_sim *)cbarg;
	isp = (struct ispsoftc *) cam_sim_softc(sim);
	switch (code) {
	case AC_LOST_DEVICE:
		if (IS_SCSI(isp)) {
			u_int16_t oflags, nflags;
			sdparam *sdp = isp->isp_param;
			int tgt;

			tgt = xpt_path_target_id(path);
			ISP_LOCK(isp);
			sdp += cam_sim_bus(sim);
#ifndef	ISP_TARGET_MODE
			if (tgt == sdp->isp_initiator_id) {
				nflags = DPARM_DEFAULT;
			} else {
				nflags = DPARM_SAFE_DFLT;
				if (isp->isp_loaded_fw) {
					nflags |= DPARM_NARROW | DPARM_ASYNC;
				}
			}
#else
			nflags = DPARM_DEFAULT;
#endif
			oflags = sdp->isp_devparam[tgt].dev_flags;
			sdp->isp_devparam[tgt].dev_flags = nflags;
			sdp->isp_devparam[tgt].dev_update = 1;
			isp->isp_update |= (1 << cam_sim_bus(sim));
			(void) isp_control(isp, ISPCTL_UPDATE_PARAMS, NULL);
			sdp->isp_devparam[tgt].dev_flags = oflags;
			ISP_UNLOCK(isp);
		}
		break;
	default:
		isp_prt(isp, ISP_LOGWARN, "isp_cam_async: Code 0x%x", code);
		break;
	}
}

static void
isp_poll(struct cam_sim *sim)
{
	struct ispsoftc *isp = cam_sim_softc(sim);
	ISP_LOCK(isp);
	(void) isp_intr(isp);
	ISP_UNLOCK(isp);
}

#if	0
static void
isp_relsim(void *arg)
{
	struct ispsoftc *isp = arg;
	ISP_LOCK(isp);
	if (isp->isp_osinfo.simqfrozen & SIMQFRZ_TIMED) {
		int wasfrozen = isp->isp_osinfo.simqfrozen & SIMQFRZ_TIMED;
		isp->isp_osinfo.simqfrozen &= ~SIMQFRZ_TIMED;
		if (wasfrozen && isp->isp_osinfo.simqfrozen == 0) {
			xpt_release_simq(isp->isp_sim, 1);
			isp_prt(isp, ISP_LOGDEBUG2, "timed relsimq");
		}
	}
	ISP_UNLOCK(isp);
}
#endif

static void
isp_watchdog(void *arg)
{
	XS_T *xs = arg;
	struct ispsoftc *isp = XS_ISP(xs);
	u_int32_t handle;

	/*
	 * We've decided this command is dead. Make sure we're not trying
	 * to kill a command that's already dead by getting it's handle and
	 * and seeing whether it's still alive.
	 */
	ISP_LOCK(isp);
	handle = isp_find_handle(isp, xs);
	if (handle) {
		u_int16_t r;

		if (XS_CMD_DONE_P(xs)) {
			isp_prt(isp, ISP_LOGDEBUG1,
			    "watchdog found done cmd (handle 0x%x)", handle);
			ISP_UNLOCK(isp);
			return;
		}

		if (XS_CMD_WDOG_P(xs)) {
			isp_prt(isp, ISP_LOGDEBUG2,
			    "recursive watchdog (handle 0x%x)", handle);
			ISP_UNLOCK(isp);
			return;
		}

		XS_CMD_S_WDOG(xs);

		r = ISP_READ(isp, BIU_ISR);

		if (INT_PENDING(isp, r) && isp_intr(isp) && XS_CMD_DONE_P(xs)) {
			isp_prt(isp, ISP_LOGDEBUG2,
			    "watchdog cleanup (%x, %x)", handle, r);
			xpt_done((union ccb *) xs);
		} else if (XS_CMD_GRACE_P(xs)) {
			/*
			 * Make sure the command is *really* dead before we
			 * release the handle (and DMA resources) for reuse.
			 */
			(void) isp_control(isp, ISPCTL_ABORT_CMD, arg);

			/*
			 * After this point, the comamnd is really dead.
			 */
			if (XS_XFRLEN(xs)) {
				ISP_DMAFREE(isp, xs, handle);
                	} 
			isp_destroy_handle(isp, handle);
			xpt_print_path(xs->ccb_h.path);
			isp_prt(isp, ISP_LOGWARN,
			    "watchdog timeout (%x, %x)", handle, r);
			XS_SETERR(xs, CAM_CMD_TIMEOUT);
			XS_CMD_C_WDOG(xs);
			isp_done(xs);
		} else {
			u_int16_t iptr, optr;
			ispreq_t *mp;

			XS_CMD_C_WDOG(xs);
			xs->ccb_h.timeout_ch = timeout(isp_watchdog, xs, hz);
			if (isp_getrqentry(isp, &iptr, &optr, (void **) &mp)) {
				ISP_UNLOCK(isp);
				return;
			}
			XS_CMD_S_GRACE(xs);
			MEMZERO((void *) mp, sizeof (*mp));
			mp->req_header.rqs_entry_count = 1;
			mp->req_header.rqs_entry_type = RQSTYPE_MARKER;
			mp->req_modifier = SYNC_ALL;
			mp->req_target = XS_CHANNEL(xs) << 7;
			ISP_SWIZZLE_REQUEST(isp, mp);
			ISP_ADD_REQUEST(isp, iptr);
		}
	} else {
		isp_prt(isp, ISP_LOGDEBUG2, "watchdog with no command");
	}
	ISP_UNLOCK(isp);
}

#ifdef	ISP_SMPLOCK
static void
isp_kthread(void *arg)
{
	int wasfrozen;
	struct ispsoftc *isp = arg;

	mtx_lock(&isp->isp_lock);
	for (;;) {
		isp_prt(isp, ISP_LOGDEBUG0, "kthread checking FC state");
		while (isp_fc_runstate(isp, 2 * 1000000) != 0) {
#if	0
			msleep(&lbolt, &isp->isp_lock,
			    PRIBIO, "isp_fcthrd", 0);
#else
			msleep(isp_kthread, &isp->isp_lock,
			    PRIBIO, "isp_fcthrd", hz);
#endif
		}
		wasfrozen = isp->isp_osinfo.simqfrozen & SIMQFRZ_LOOPDOWN;
		isp->isp_osinfo.simqfrozen &= ~SIMQFRZ_LOOPDOWN;
		if (wasfrozen && isp->isp_osinfo.simqfrozen == 0) {
			isp_prt(isp, ISP_LOGDEBUG0, "kthread up release simq");
			ISPLOCK_2_CAMLOCK(isp);
			xpt_release_simq(isp->isp_sim, 1);
			CAMLOCK_2_ISPLOCK(isp);
		}
		cv_wait(&isp->isp_osinfo.kthread_cv, &isp->isp_lock);
	}
}
#else
static void
isp_kthread(void *arg)
{
	int wasfrozen;
	struct ispsoftc *isp = arg;

	mtx_lock(&Giant);
	for (;;) {
		isp_prt(isp, ISP_LOGDEBUG0, "kthread checking FC state");
		while (isp_fc_runstate(isp, 2 * 1000000) != 0) {
			tsleep(isp_kthread, PRIBIO, "isp_fcthrd", hz);
		}
		wasfrozen = isp->isp_osinfo.simqfrozen & SIMQFRZ_LOOPDOWN;
		isp->isp_osinfo.simqfrozen &= ~SIMQFRZ_LOOPDOWN;
		if (wasfrozen && isp->isp_osinfo.simqfrozen == 0) {
			isp_prt(isp, ISP_LOGDEBUG0, "kthread up release simq");
			ISPLOCK_2_CAMLOCK(isp);
			xpt_release_simq(isp->isp_sim, 1);
			CAMLOCK_2_ISPLOCK(isp);
		}
		tsleep(&isp->isp_osinfo.kthread_cv, PRIBIO, "isp_fc_worker", 0);
	}
}
#endif
static void
isp_action(struct cam_sim *sim, union ccb *ccb)
{
	int bus, tgt, error;
	struct ispsoftc *isp;
	struct ccb_trans_settings *cts;

	CAM_DEBUG(ccb->ccb_h.path, CAM_DEBUG_TRACE, ("isp_action\n"));
	
	isp = (struct ispsoftc *)cam_sim_softc(sim);
	ccb->ccb_h.sim_priv.entries[0].field = 0;
	ccb->ccb_h.sim_priv.entries[1].ptr = isp;
	if (isp->isp_state != ISP_RUNSTATE &&
	    ccb->ccb_h.func_code == XPT_SCSI_IO) {
		CAMLOCK_2_ISPLOCK(isp);
		isp_init(isp);
		if (isp->isp_state != ISP_INITSTATE) {
			ISP_UNLOCK(isp);
			/*
			 * Lie. Say it was a selection timeout.
			 */
			ccb->ccb_h.status = CAM_SEL_TIMEOUT | CAM_DEV_QFRZN;
			xpt_freeze_devq(ccb->ccb_h.path, 1);
			xpt_done(ccb);
			return;
		}
		isp->isp_state = ISP_RUNSTATE;
		ISPLOCK_2_CAMLOCK(isp);
	}
	isp_prt(isp, ISP_LOGDEBUG2, "isp_action code %x", ccb->ccb_h.func_code);


	switch (ccb->ccb_h.func_code) {
	case XPT_SCSI_IO:	/* Execute the requested I/O operation */
		/*
		 * Do a couple of preliminary checks...
		 */
		if ((ccb->ccb_h.flags & CAM_CDB_POINTER) != 0) {
			if ((ccb->ccb_h.flags & CAM_CDB_PHYS) != 0) {
				ccb->ccb_h.status = CAM_REQ_INVALID;
				xpt_done(ccb);
				break;
			}
		}
#ifdef	DIAGNOSTIC
		if (ccb->ccb_h.target_id > (ISP_MAX_TARGETS(isp) - 1)) {
			ccb->ccb_h.status = CAM_PATH_INVALID;
		} else if (ccb->ccb_h.target_lun > (ISP_MAX_LUNS(isp) - 1)) {
			ccb->ccb_h.status = CAM_PATH_INVALID;
		}
		if (ccb->ccb_h.status == CAM_PATH_INVALID) {
			isp_prt(isp, ISP_LOGERR,
			    "invalid tgt/lun (%d.%d) in XPT_SCSI_IO",
			    ccb->ccb_h.target_id, ccb->ccb_h.target_lun);
			xpt_done(ccb);
			break;
		}
#endif
		((struct ccb_scsiio *) ccb)->scsi_status = SCSI_STATUS_OK;
		CAMLOCK_2_ISPLOCK(isp);
		error = isp_start((XS_T *) ccb);
		switch (error) {
		case CMD_QUEUED:
			ccb->ccb_h.status |= CAM_SIM_QUEUED;
			if (ccb->ccb_h.timeout != CAM_TIME_INFINITY) {
				u_int64_t ticks = (u_int64_t) hz;
				if (ccb->ccb_h.timeout == CAM_TIME_DEFAULT)
					ticks = 60 * 1000 * ticks;
				else
					ticks = ccb->ccb_h.timeout * hz;
				ticks = ((ticks + 999) / 1000) + hz + hz;
				if (ticks >= 0x80000000) {
					isp_prt(isp, ISP_LOGERR,
					    "timeout overflow");
					ticks = 0x80000000;
				}
				ccb->ccb_h.timeout_ch = timeout(isp_watchdog,
				    (caddr_t)ccb, (int)ticks);
			} else {
				callout_handle_init(&ccb->ccb_h.timeout_ch);
			}
			ISPLOCK_2_CAMLOCK(isp);
			break;
		case CMD_RQLATER:
#ifdef	ISP_SMPLOCK
			cv_signal(&isp->isp_osinfo.kthread_cv);
#else
			wakeup(&isp->isp_osinfo.kthread_cv);
#endif
			if (isp->isp_osinfo.simqfrozen == 0) {
				isp_prt(isp, ISP_LOGDEBUG2,
				    "RQLATER freeze simq");
#if	0
				isp->isp_osinfo.simqfrozen |= SIMQFRZ_TIMED;
				timeout(isp_relsim, isp, 500);
#else
				isp->isp_osinfo.simqfrozen |= SIMQFRZ_LOOPDOWN;
#endif
				ISPLOCK_2_CAMLOCK(isp);
				xpt_freeze_simq(sim, 1);
			} else {
				ISPLOCK_2_CAMLOCK(isp);
			}
			XS_SETERR(ccb, CAM_REQUEUE_REQ);
			xpt_done(ccb);
			break;
		case CMD_EAGAIN:
			if (isp->isp_osinfo.simqfrozen == 0) {
				xpt_freeze_simq(sim, 1);
				isp_prt(isp, ISP_LOGDEBUG2,
				    "EAGAIN freeze simq");
			}
			isp->isp_osinfo.simqfrozen |= SIMQFRZ_RESOURCE;
			XS_SETERR(ccb, CAM_REQUEUE_REQ);
			ISPLOCK_2_CAMLOCK(isp);
			xpt_done(ccb);
			break;
		case CMD_COMPLETE:
			isp_done((struct ccb_scsiio *) ccb);
			ISPLOCK_2_CAMLOCK(isp);
			break;
		default:
			isp_prt(isp, ISP_LOGERR,
			    "What's this? 0x%x at %d in file %s",
			    error, __LINE__, __FILE__);
			XS_SETERR(ccb, CAM_REQ_CMP_ERR);
			xpt_done(ccb);
			ISPLOCK_2_CAMLOCK(isp);
		}
		break;

#ifdef	ISP_TARGET_MODE
	case XPT_EN_LUN:		/* Enable LUN as a target */
		CAMLOCK_2_ISPLOCK(isp);
		isp_en_lun(isp, ccb);
		ISPLOCK_2_CAMLOCK(isp);
		xpt_done(ccb);
		break;

	case XPT_NOTIFY_ACK:		/* recycle notify ack */
	case XPT_IMMED_NOTIFY:		/* Add Immediate Notify Resource */
	case XPT_ACCEPT_TARGET_IO:	/* Add Accept Target IO Resource */
	{
		tstate_t *tptr =
		    get_lun_statep(isp, XS_CHANNEL(ccb), ccb->ccb_h.target_lun);
		if (tptr == NULL) {
			ccb->ccb_h.status = CAM_LUN_INVALID;
			xpt_done(ccb);
			break;
		}
		ccb->ccb_h.sim_priv.entries[0].field = 0;
		ccb->ccb_h.sim_priv.entries[1].ptr = isp;
		CAMLOCK_2_ISPLOCK(isp);
		if (ccb->ccb_h.func_code == XPT_ACCEPT_TARGET_IO) {
			SLIST_INSERT_HEAD(&tptr->atios,
			    &ccb->ccb_h, sim_links.sle);
		} else {
			SLIST_INSERT_HEAD(&tptr->inots, &ccb->ccb_h,
			    sim_links.sle);
		}
		rls_lun_statep(isp, tptr);
		ccb->ccb_h.status = CAM_REQ_INPROG;
		ISPLOCK_2_CAMLOCK(isp);
		break;
	}
	case XPT_CONT_TARGET_IO:
	{
		CAMLOCK_2_ISPLOCK(isp);
		ccb->ccb_h.status = isp_target_start_ctio(isp, ccb);
		if (ccb->ccb_h.status != CAM_REQ_INPROG) {
			if (isp->isp_osinfo.simqfrozen == 0) {
				xpt_freeze_simq(sim, 1);
				xpt_print_path(ccb->ccb_h.path);
				isp_prt(isp, ISP_LOGINFO,
				    "XPT_CONT_TARGET_IO freeze simq");
			}
			isp->isp_osinfo.simqfrozen |= SIMQFRZ_RESOURCE;
			XS_SETERR(ccb, CAM_REQUEUE_REQ);
			ISPLOCK_2_CAMLOCK(isp);
			xpt_done(ccb);
		} else {
			ISPLOCK_2_CAMLOCK(isp);
			ccb->ccb_h.status |= CAM_SIM_QUEUED;
		}
		break;
	}
#endif
	case XPT_RESET_DEV:		/* BDR the specified SCSI device */

		bus = cam_sim_bus(xpt_path_sim(ccb->ccb_h.path));
		tgt = ccb->ccb_h.target_id;
		tgt |= (bus << 16);

		CAMLOCK_2_ISPLOCK(isp);
		error = isp_control(isp, ISPCTL_RESET_DEV, &tgt);
		ISPLOCK_2_CAMLOCK(isp);
		if (error) {
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		} else {
			ccb->ccb_h.status = CAM_REQ_CMP;
		}
		xpt_done(ccb);
		break;
	case XPT_ABORT:			/* Abort the specified CCB */
	{
		union ccb *accb = ccb->cab.abort_ccb;
		CAMLOCK_2_ISPLOCK(isp);
		switch (accb->ccb_h.func_code) {
#ifdef	ISP_TARGET_MODE
		case XPT_ACCEPT_TARGET_IO:
		case XPT_IMMED_NOTIFY:
        		ccb->ccb_h.status = isp_abort_tgt_ccb(isp, ccb);
			break;
		case XPT_CONT_TARGET_IO:
			isp_prt(isp, ISP_LOGERR, "cannot abort CTIOs yet");
			ccb->ccb_h.status = CAM_UA_ABORT;
			break;
#endif
		case XPT_SCSI_IO:
			error = isp_control(isp, ISPCTL_ABORT_CMD, ccb);
			if (error) {
				ccb->ccb_h.status = CAM_UA_ABORT;
			} else {
				ccb->ccb_h.status = CAM_REQ_CMP;
			}
			break;
		default:
			ccb->ccb_h.status = CAM_REQ_INVALID;
			break;
		}
		ISPLOCK_2_CAMLOCK(isp);
		xpt_done(ccb);
		break;
	}
	case XPT_SET_TRAN_SETTINGS:	/* Nexus Settings */

		cts = &ccb->cts;
		tgt = cts->ccb_h.target_id;
		CAMLOCK_2_ISPLOCK(isp);
		if (IS_SCSI(isp)) {
			sdparam *sdp = isp->isp_param;
			u_int16_t *dptr;

			bus = cam_sim_bus(xpt_path_sim(cts->ccb_h.path));

			sdp += bus;
#if	0
			if (cts->flags & CCB_TRANS_CURRENT_SETTINGS)
				dptr = &sdp->isp_devparam[tgt].cur_dflags;
			else
				dptr = &sdp->isp_devparam[tgt].dev_flags;
#else
			/*
			 * We always update (internally) from dev_flags
			 * so any request to change settings just gets
			 * vectored to that location.
			 */
			dptr = &sdp->isp_devparam[tgt].dev_flags;
#endif

			/*
			 * Note that these operations affect the
			 * the goal flags (dev_flags)- not
			 * the current state flags. Then we mark
			 * things so that the next operation to
			 * this HBA will cause the update to occur.
			 */
			if (cts->valid & CCB_TRANS_DISC_VALID) {
				if ((cts->flags & CCB_TRANS_DISC_ENB) != 0) {
					*dptr |= DPARM_DISC;
				} else {
					*dptr &= ~DPARM_DISC;
				}
			}
			if (cts->valid & CCB_TRANS_TQ_VALID) {
				if ((cts->flags & CCB_TRANS_TAG_ENB) != 0) {
					*dptr |= DPARM_TQING;
				} else {
					*dptr &= ~DPARM_TQING;
				}
			}
			if (cts->valid & CCB_TRANS_BUS_WIDTH_VALID) {
				switch (cts->bus_width) {
				case MSG_EXT_WDTR_BUS_16_BIT:
					*dptr |= DPARM_WIDE;
					break;
				default:
					*dptr &= ~DPARM_WIDE;
				}
			}
			/*
			 * Any SYNC RATE of nonzero and SYNC_OFFSET
			 * of nonzero will cause us to go to the
			 * selected (from NVRAM) maximum value for
			 * this device. At a later point, we'll
			 * allow finer control.
			 */
			if ((cts->valid & CCB_TRANS_SYNC_RATE_VALID) &&
			    (cts->valid & CCB_TRANS_SYNC_OFFSET_VALID) &&
			    (cts->sync_offset > 0)) {
				*dptr |= DPARM_SYNC;
			} else {
				*dptr &= ~DPARM_SYNC;
			}
			*dptr |= DPARM_SAFE_DFLT;
			isp_prt(isp, ISP_LOGDEBUG0,
			    "%d.%d set %s period 0x%x offset 0x%x flags 0x%x",
			    bus, tgt, (cts->flags & CCB_TRANS_CURRENT_SETTINGS)?
			    "current" : "user", 
			    sdp->isp_devparam[tgt].sync_period,
			    sdp->isp_devparam[tgt].sync_offset,
			    sdp->isp_devparam[tgt].dev_flags);
			sdp->isp_devparam[tgt].dev_update = 1;
			isp->isp_update |= (1 << bus);
		}
		ISPLOCK_2_CAMLOCK(isp);
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		break;

	case XPT_GET_TRAN_SETTINGS:

		cts = &ccb->cts;
		tgt = cts->ccb_h.target_id;
		if (IS_FC(isp)) {
			/*
			 * a lot of normal SCSI things don't make sense.
			 */
			cts->flags = CCB_TRANS_TAG_ENB | CCB_TRANS_DISC_ENB;
			cts->valid = CCB_TRANS_DISC_VALID | CCB_TRANS_TQ_VALID;
			/*
			 * How do you measure the width of a high
			 * speed serial bus? Well, in bytes.
			 *
			 * Offset and period make no sense, though, so we set
			 * (above) a 'base' transfer speed to be gigabit.
			 */
			cts->bus_width = MSG_EXT_WDTR_BUS_8_BIT;
		} else {
			sdparam *sdp = isp->isp_param;
			u_int16_t dval, pval, oval;
			int bus = cam_sim_bus(xpt_path_sim(cts->ccb_h.path));

			CAMLOCK_2_ISPLOCK(isp);
			sdp += bus;
			if (cts->flags & CCB_TRANS_CURRENT_SETTINGS) {
				sdp->isp_devparam[tgt].dev_refresh = 1;
				isp->isp_update |= (1 << bus);
				(void) isp_control(isp, ISPCTL_UPDATE_PARAMS,
				    NULL);
				dval = sdp->isp_devparam[tgt].cur_dflags;
				oval = sdp->isp_devparam[tgt].cur_offset;
				pval = sdp->isp_devparam[tgt].cur_period;
			} else {
				dval = sdp->isp_devparam[tgt].dev_flags;
				oval = sdp->isp_devparam[tgt].sync_offset;
				pval = sdp->isp_devparam[tgt].sync_period;
			}

			cts->flags &= ~(CCB_TRANS_DISC_ENB|CCB_TRANS_TAG_ENB);

			if (dval & DPARM_DISC) {
				cts->flags |= CCB_TRANS_DISC_ENB;
			}
			if (dval & DPARM_TQING) {
				cts->flags |= CCB_TRANS_TAG_ENB;
			}
			if (dval & DPARM_WIDE) {
				cts->bus_width = MSG_EXT_WDTR_BUS_16_BIT;
			} else {
				cts->bus_width = MSG_EXT_WDTR_BUS_8_BIT;
			}
			cts->valid = CCB_TRANS_BUS_WIDTH_VALID |
			    CCB_TRANS_DISC_VALID | CCB_TRANS_TQ_VALID;

			if ((dval & DPARM_SYNC) && oval != 0) {
				cts->sync_period = pval;
				cts->sync_offset = oval;
				cts->valid |=
				    CCB_TRANS_SYNC_RATE_VALID |
				    CCB_TRANS_SYNC_OFFSET_VALID;
			}
			ISPLOCK_2_CAMLOCK(isp);
			isp_prt(isp, ISP_LOGDEBUG0,
			    "%d.%d get %s period 0x%x offset 0x%x flags 0x%x",
			    bus, tgt, (cts->flags & CCB_TRANS_CURRENT_SETTINGS)?
			    "current" : "user", pval, oval, dval);
		}
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		break;

	case XPT_CALC_GEOMETRY:
	{
		struct ccb_calc_geometry *ccg;
		u_int32_t secs_per_cylinder;
		u_int32_t size_mb;

		ccg = &ccb->ccg;
		if (ccg->block_size == 0) {
			isp_prt(isp, ISP_LOGERR,
			    "%d.%d XPT_CALC_GEOMETRY block size 0?",
			    ccg->ccb_h.target_id, ccg->ccb_h.target_lun);
			ccb->ccb_h.status = CAM_REQ_INVALID;
			xpt_done(ccb);
			break;
		}
		size_mb = ccg->volume_size /((1024L * 1024L) / ccg->block_size);
		if (size_mb > 1024) {
			ccg->heads = 255;
			ccg->secs_per_track = 63;
		} else {
			ccg->heads = 64;
			ccg->secs_per_track = 32;
		}
		secs_per_cylinder = ccg->heads * ccg->secs_per_track;
		ccg->cylinders = ccg->volume_size / secs_per_cylinder;
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		break;
	}
	case XPT_RESET_BUS:		/* Reset the specified bus */
		bus = cam_sim_bus(sim);
		CAMLOCK_2_ISPLOCK(isp);
		error = isp_control(isp, ISPCTL_RESET_BUS, &bus);
		ISPLOCK_2_CAMLOCK(isp);
		if (error)
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		else {
			if (cam_sim_bus(sim) && isp->isp_path2 != NULL)
				xpt_async(AC_BUS_RESET, isp->isp_path2, NULL);
			else if (isp->isp_path != NULL)
				xpt_async(AC_BUS_RESET, isp->isp_path, NULL);
			ccb->ccb_h.status = CAM_REQ_CMP;
		}
		xpt_done(ccb);
		break;

	case XPT_TERM_IO:		/* Terminate the I/O process */
		ccb->ccb_h.status = CAM_REQ_INVALID;
		xpt_done(ccb);
		break;

	case XPT_PATH_INQ:		/* Path routing inquiry */
	{
		struct ccb_pathinq *cpi = &ccb->cpi;

		cpi->version_num = 1;
#ifdef	ISP_TARGET_MODE
		cpi->target_sprt = PIT_PROCESSOR | PIT_DISCONNECT | PIT_TERM_IO;
#else
		cpi->target_sprt = 0;
#endif
		cpi->hba_eng_cnt = 0;
		cpi->max_target = ISP_MAX_TARGETS(isp) - 1;
		cpi->max_lun = ISP_MAX_LUNS(isp) - 1;
		cpi->bus_id = cam_sim_bus(sim);
		if (IS_FC(isp)) {
			cpi->hba_misc = PIM_NOBUSRESET;
			/*
			 * Because our loop ID can shift from time to time,
			 * make our initiator ID out of range of our bus.
			 */
			cpi->initiator_id = cpi->max_target + 1;

			/*
			 * Set base transfer capabilities for Fibre Channel.
			 * Technically not correct because we don't know
			 * what media we're running on top of- but we'll
			 * look good if we always say 100MB/s.
			 */
			cpi->base_transfer_speed = 100000;
			cpi->hba_inquiry = PI_TAG_ABLE;
		} else {
			sdparam *sdp = isp->isp_param;
			sdp += cam_sim_bus(xpt_path_sim(cpi->ccb_h.path));
			cpi->hba_inquiry = PI_SDTR_ABLE|PI_TAG_ABLE|PI_WIDE_16;
			cpi->hba_misc = 0;
			cpi->initiator_id = sdp->isp_initiator_id;
			cpi->base_transfer_speed = 3300;
		}
		strncpy(cpi->sim_vid, "FreeBSD", SIM_IDLEN);
		strncpy(cpi->hba_vid, "Qlogic", HBA_IDLEN);
		strncpy(cpi->dev_name, cam_sim_name(sim), DEV_IDLEN);
		cpi->unit_number = cam_sim_unit(sim);
		cpi->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		break;
	}
	default:
		ccb->ccb_h.status = CAM_REQ_INVALID;
		xpt_done(ccb);
		break;
	}
}

#define	ISPDDB	(CAM_DEBUG_INFO|CAM_DEBUG_TRACE|CAM_DEBUG_CDB)
void
isp_done(struct ccb_scsiio *sccb)
{
	struct ispsoftc *isp = XS_ISP(sccb);

	if (XS_NOERR(sccb))
		XS_SETERR(sccb, CAM_REQ_CMP);

	if ((sccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP &&
	    (sccb->scsi_status != SCSI_STATUS_OK)) {
		sccb->ccb_h.status &= ~CAM_STATUS_MASK;
		if ((sccb->scsi_status == SCSI_STATUS_CHECK_COND) && 
		    (sccb->ccb_h.status & CAM_AUTOSNS_VALID) == 0) {
			sccb->ccb_h.status |= CAM_AUTOSENSE_FAIL;
		} else {
			sccb->ccb_h.status |= CAM_SCSI_STATUS_ERROR;
		}
	}

	sccb->ccb_h.status &= ~CAM_SIM_QUEUED;
	if ((sccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
		if ((sccb->ccb_h.status & CAM_DEV_QFRZN) == 0) {
			sccb->ccb_h.status |= CAM_DEV_QFRZN;
			xpt_freeze_devq(sccb->ccb_h.path, 1);
			if (sccb->scsi_status != SCSI_STATUS_OK)
				isp_prt(isp, ISP_LOGDEBUG2,
				    "freeze devq %d.%d %x %x",
				    sccb->ccb_h.target_id,
				    sccb->ccb_h.target_lun, sccb->ccb_h.status,
				    sccb->scsi_status);
		}
	}

	/*
	 * If we were frozen waiting resources, clear that we were frozen
	 * waiting for resources. If we are no longer frozen, and the devq
	 * isn't frozen, mark the completing CCB to have the XPT layer
	 * release the simq.
	 */
	if (isp->isp_osinfo.simqfrozen & SIMQFRZ_RESOURCE) {
		isp->isp_osinfo.simqfrozen &= ~SIMQFRZ_RESOURCE;
		if (isp->isp_osinfo.simqfrozen == 0) {
			if ((sccb->ccb_h.status & CAM_DEV_QFRZN) == 0) {
				isp_prt(isp, ISP_LOGDEBUG2,
				    "isp_done->relsimq");
				sccb->ccb_h.status |= CAM_RELEASE_SIMQ;
			} else {
				isp_prt(isp, ISP_LOGDEBUG2,
				    "isp_done->devq frozen");
			}
		} else {
			isp_prt(isp, ISP_LOGDEBUG2,
			    "isp_done -> simqfrozen = %x",
			    isp->isp_osinfo.simqfrozen);
		}
	}
	if ((CAM_DEBUGGED(sccb->ccb_h.path, ISPDDB)) &&
	    (sccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
		xpt_print_path(sccb->ccb_h.path);
		isp_prt(isp, ISP_LOGINFO, 
		    "cam completion status 0x%x", sccb->ccb_h.status);
	}

	XS_CMD_S_DONE(sccb);
	if (XS_CMD_WDOG_P(sccb) == 0) {
		untimeout(isp_watchdog, (caddr_t)sccb, sccb->ccb_h.timeout_ch);
		if (XS_CMD_GRACE_P(sccb)) {
			isp_prt(isp, ISP_LOGDEBUG2,
			    "finished command on borrowed time");
		}
		XS_CMD_S_CLEAR(sccb);
		ISPLOCK_2_CAMLOCK(isp);
		xpt_done((union ccb *) sccb);
		CAMLOCK_2_ISPLOCK(isp);
	}
}

int
isp_async(struct ispsoftc *isp, ispasync_t cmd, void *arg)
{
	int bus, rv = 0;
	switch (cmd) {
	case ISPASYNC_NEW_TGT_PARAMS:
	{
		int flags, tgt;
		sdparam *sdp = isp->isp_param;
		struct ccb_trans_settings neg;
		struct cam_path *tmppath;

		tgt = *((int *)arg);
		bus = (tgt >> 16) & 0xffff;
		tgt &= 0xffff;
		sdp += bus;
		if (xpt_create_path(&tmppath, NULL,
		    cam_sim_path(bus? isp->isp_sim2 : isp->isp_sim),
		    tgt, CAM_LUN_WILDCARD) != CAM_REQ_CMP) {
			isp_prt(isp, ISP_LOGWARN,
			    "isp_async cannot make temp path for %d.%d",
			    tgt, bus);
			rv = -1;
			break;
		}
		flags = sdp->isp_devparam[tgt].cur_dflags;
		neg.valid = CCB_TRANS_DISC_VALID | CCB_TRANS_TQ_VALID;
		if (flags & DPARM_DISC) {
			neg.flags |= CCB_TRANS_DISC_ENB;
		}
		if (flags & DPARM_TQING) {
			neg.flags |= CCB_TRANS_TAG_ENB;
		}
		neg.valid |= CCB_TRANS_BUS_WIDTH_VALID;
		neg.bus_width = (flags & DPARM_WIDE)?
		    MSG_EXT_WDTR_BUS_8_BIT : MSG_EXT_WDTR_BUS_16_BIT;
		neg.sync_period = sdp->isp_devparam[tgt].cur_period;
		neg.sync_offset = sdp->isp_devparam[tgt].cur_offset;
		if (flags & DPARM_SYNC) {
			neg.valid |=
			    CCB_TRANS_SYNC_RATE_VALID |
			    CCB_TRANS_SYNC_OFFSET_VALID;
		}
		isp_prt(isp, ISP_LOGDEBUG2,
		    "NEW_TGT_PARAMS bus %d tgt %d period %x offset %x flags %x",
		    bus, tgt, neg.sync_period, neg.sync_offset, flags);
		xpt_setup_ccb(&neg.ccb_h, tmppath, 1);
		ISPLOCK_2_CAMLOCK(isp);
		xpt_async(AC_TRANSFER_NEG, tmppath, &neg);
		CAMLOCK_2_ISPLOCK(isp);
		xpt_free_path(tmppath);
		break;
	}
	case ISPASYNC_BUS_RESET:
		bus = *((int *)arg);
		isp_prt(isp, ISP_LOGINFO, "SCSI bus reset on bus %d detected",
		    bus);
		if (bus > 0 && isp->isp_path2) {
			ISPLOCK_2_CAMLOCK(isp);
			xpt_async(AC_BUS_RESET, isp->isp_path2, NULL);
			CAMLOCK_2_ISPLOCK(isp);
		} else if (isp->isp_path) {
			ISPLOCK_2_CAMLOCK(isp);
			xpt_async(AC_BUS_RESET, isp->isp_path, NULL);
			CAMLOCK_2_ISPLOCK(isp);
		}
		break;
	case ISPASYNC_LIP:
		if (isp->isp_path) {
			if (isp->isp_osinfo.simqfrozen == 0) {
				isp_prt(isp, ISP_LOGDEBUG0, "LIP freeze simq");
				ISPLOCK_2_CAMLOCK(isp);
				xpt_freeze_simq(isp->isp_sim, 1);
				CAMLOCK_2_ISPLOCK(isp);
			}
			isp->isp_osinfo.simqfrozen |= SIMQFRZ_LOOPDOWN;
		}
		isp_prt(isp, ISP_LOGINFO, "LIP Received");
		break;
	case ISPASYNC_LOOP_RESET:
		if (isp->isp_path) {
			if (isp->isp_osinfo.simqfrozen == 0) {
				isp_prt(isp, ISP_LOGDEBUG0,
				    "Loop Reset freeze simq");
				ISPLOCK_2_CAMLOCK(isp);
				xpt_freeze_simq(isp->isp_sim, 1);
				CAMLOCK_2_ISPLOCK(isp);
			}
			isp->isp_osinfo.simqfrozen |= SIMQFRZ_LOOPDOWN;
		}
		isp_prt(isp, ISP_LOGINFO, "Loop Reset Received");
		break;
	case ISPASYNC_LOOP_DOWN:
		if (isp->isp_path) {
			if (isp->isp_osinfo.simqfrozen == 0) {
				isp_prt(isp, ISP_LOGDEBUG0,
				    "loop down freeze simq");
				ISPLOCK_2_CAMLOCK(isp);
				xpt_freeze_simq(isp->isp_sim, 1);
				CAMLOCK_2_ISPLOCK(isp);
			}
			isp->isp_osinfo.simqfrozen |= SIMQFRZ_LOOPDOWN;
		}
		isp_prt(isp, ISP_LOGINFO, "Loop DOWN");
		break;
	case ISPASYNC_LOOP_UP:
		/*
		 * Now we just note that Loop has come up. We don't
		 * actually do anything because we're waiting for a
		 * Change Notify before activating the FC cleanup
		 * thread to look at the state of the loop again.
		 */
		isp_prt(isp, ISP_LOGINFO, "Loop UP");
		break;
	case ISPASYNC_PROMENADE:
	{
		const char *fmt = "Target %d (Loop 0x%x) Port ID 0x%x "
		    "(role %s) %s\n Port WWN 0x%08x%08x\n Node WWN 0x%08x%08x";
		static const char *roles[4] = {
		    "(none)", "Target", "Initiator", "Target/Initiator"
		};
		fcparam *fcp = isp->isp_param;
		int tgt = *((int *) arg);
		struct lportdb *lp = &fcp->portdb[tgt]; 

		isp_prt(isp, ISP_LOGINFO, fmt, tgt, lp->loopid, lp->portid,
		    roles[lp->roles & 0x3],
		    (lp->valid)? "Arrived" : "Departed",
		    (u_int32_t) (lp->port_wwn >> 32),
		    (u_int32_t) (lp->port_wwn & 0xffffffffLL),
		    (u_int32_t) (lp->node_wwn >> 32),
		    (u_int32_t) (lp->node_wwn & 0xffffffffLL));
		break;
	}
	case ISPASYNC_CHANGE_NOTIFY:
		if (arg == (void *) 1) {
			isp_prt(isp, ISP_LOGINFO,
			    "Name Server Database Changed");
		} else {
			isp_prt(isp, ISP_LOGINFO,
			    "Name Server Database Changed");
		}
#ifdef	ISP_SMPLOCK
		cv_signal(&isp->isp_osinfo.kthread_cv);
#else
		wakeup(&isp->isp_osinfo.kthread_cv);
#endif
		break;
	case ISPASYNC_FABRIC_DEV:
	{
		int target, lrange;
		struct lportdb *lp = NULL;
		char *pt;
		sns_ganrsp_t *resp = (sns_ganrsp_t *) arg;
		u_int32_t portid;
		u_int64_t wwpn, wwnn;
		fcparam *fcp = isp->isp_param;

		portid =
		    (((u_int32_t) resp->snscb_port_id[0]) << 16) |
		    (((u_int32_t) resp->snscb_port_id[1]) << 8) |
		    (((u_int32_t) resp->snscb_port_id[2]));

		wwpn =
		    (((u_int64_t)resp->snscb_portname[0]) << 56) |
		    (((u_int64_t)resp->snscb_portname[1]) << 48) |
		    (((u_int64_t)resp->snscb_portname[2]) << 40) |
		    (((u_int64_t)resp->snscb_portname[3]) << 32) |
		    (((u_int64_t)resp->snscb_portname[4]) << 24) |
		    (((u_int64_t)resp->snscb_portname[5]) << 16) |
		    (((u_int64_t)resp->snscb_portname[6]) <<  8) |
		    (((u_int64_t)resp->snscb_portname[7]));

		wwnn =
		    (((u_int64_t)resp->snscb_nodename[0]) << 56) |
		    (((u_int64_t)resp->snscb_nodename[1]) << 48) |
		    (((u_int64_t)resp->snscb_nodename[2]) << 40) |
		    (((u_int64_t)resp->snscb_nodename[3]) << 32) |
		    (((u_int64_t)resp->snscb_nodename[4]) << 24) |
		    (((u_int64_t)resp->snscb_nodename[5]) << 16) |
		    (((u_int64_t)resp->snscb_nodename[6]) <<  8) |
		    (((u_int64_t)resp->snscb_nodename[7]));
		if (portid == 0 || wwpn == 0) {
			break;
		}

		switch (resp->snscb_port_type) {
		case 1:
			pt = "   N_Port";
			break;
		case 2:
			pt = "  NL_Port";
			break;
		case 3:
			pt = "F/NL_Port";
			break;
		case 0x7f:
			pt = "  Nx_Port";
			break;
		case 0x81:
			pt = "  F_port";
			break;
		case 0x82:
			pt = "  FL_Port";
			break;
		case 0x84:
			pt = "   E_port";
			break;
		default:
			pt = "?";
			break;
		}
		isp_prt(isp, ISP_LOGINFO,
		    "%s @ 0x%x, Node 0x%08x%08x Port %08x%08x",
		    pt, portid, ((u_int32_t) (wwnn >> 32)), ((u_int32_t) wwnn),
		    ((u_int32_t) (wwpn >> 32)), ((u_int32_t) wwpn));
		/*
		 * We're only interested in SCSI_FCP types (for now)
		 */
		if ((resp->snscb_fc4_types[2] & 1) == 0) {
			break;
		}
		if (fcp->isp_topo != TOPO_F_PORT)
			lrange = FC_SNS_ID+1;
		else
			lrange = 0;
		/*
		 * Is it already in our list?
		 */
		for (target = lrange; target < MAX_FC_TARG; target++) {
			if (target >= FL_PORT_ID && target <= FC_SNS_ID) {
				continue;
			}
			lp = &fcp->portdb[target];
			if (lp->port_wwn == wwpn && lp->node_wwn == wwnn) {
				lp->fabric_dev = 1;
				break;
			}
		}
		if (target < MAX_FC_TARG) {
			break;
		}
		for (target = lrange; target < MAX_FC_TARG; target++) {
			if (target >= FL_PORT_ID && target <= FC_SNS_ID) {
				continue;
			}
			lp = &fcp->portdb[target];
			if (lp->port_wwn == 0) {
				break;
			}
		}
		if (target == MAX_FC_TARG) {
			isp_prt(isp, ISP_LOGWARN,
			    "no more space for fabric devices");
			break;
		}
		lp->node_wwn = wwnn;
		lp->port_wwn = wwpn;
		lp->portid = portid;
		lp->fabric_dev = 1;
		break;
	}
#ifdef	ISP_TARGET_MODE
	case ISPASYNC_TARGET_MESSAGE:
	{
		tmd_msg_t *mp = arg;
		isp_prt(isp, ISP_LOGDEBUG2,
		    "bus %d iid %d tgt %d lun %d ttype %x tval %x msg[0]=%x",
		    mp->nt_bus, (int) mp->nt_iid, (int) mp->nt_tgt,
		    (int) mp->nt_lun, mp->nt_tagtype, mp->nt_tagval,
		    mp->nt_msg[0]);
		break;
	}
	case ISPASYNC_TARGET_EVENT:
	{
		tmd_event_t *ep = arg;
		isp_prt(isp, ISP_LOGDEBUG2,
		    "bus %d event code 0x%x", ep->ev_bus, ep->ev_event);
		break;
	}
	case ISPASYNC_TARGET_ACTION:
		switch (((isphdr_t *)arg)->rqs_entry_type) {
		default:
			isp_prt(isp, ISP_LOGWARN,
			   "event 0x%x for unhandled target action",
			    ((isphdr_t *)arg)->rqs_entry_type);
			break;
		case RQSTYPE_ATIO:
			rv = isp_handle_platform_atio(isp, (at_entry_t *) arg);
			break;
		case RQSTYPE_ATIO2:
			rv = isp_handle_platform_atio2(isp, (at2_entry_t *)arg);
			break;
		case RQSTYPE_CTIO2:
		case RQSTYPE_CTIO:
			rv = isp_handle_platform_ctio(isp, arg);
			break;
		case RQSTYPE_ENABLE_LUN:
		case RQSTYPE_MODIFY_LUN:
			isp_cv_signal_rqe(isp, ((lun_entry_t *)arg)->le_status);
			break;
		}
		break;
#endif
	default:
		isp_prt(isp, ISP_LOGERR, "unknown isp_async event %d", cmd);
		rv = -1;
		break;
	}
	return (rv);
}


/*
 * Locks are held before coming here.
 */
void
isp_uninit(struct ispsoftc *isp)
{
	ISP_WRITE(isp, HCCR, HCCR_CMD_RESET);
	DISABLE_INTS(isp);
}

void
isp_prt(struct ispsoftc *isp, int level, const char *fmt, ...)
{
	va_list ap;
	if (level != ISP_LOGALL && (level & isp->isp_dblev) == 0) {
		return;
	}
	printf("%s: ", device_get_nameunit(isp->isp_dev));
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}
