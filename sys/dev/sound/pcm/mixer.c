/*-
 * Copyright (c) 1999 Cameron Grant <cg@freebsd.org>
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
 */

#include <dev/sound/pcm/sound.h>

#include "mixer_if.h"

SND_DECLARE_FILE("$FreeBSD$");

MALLOC_DEFINE(M_MIXER, "mixer", "mixer");

#define MIXER_NAMELEN	16
struct snd_mixer {
	KOBJ_FIELDS;
	const char *type;
	void *devinfo;
	int busy;
	int hwvol_muted;
	int hwvol_mixer;
	int hwvol_step;
	device_t dev;
	u_int32_t hwvol_mute_level;
	u_int32_t devs;
	u_int32_t recdevs;
	u_int32_t recsrc;
	u_int16_t level[32];
	char name[MIXER_NAMELEN];
	struct mtx *lock;
	oss_mixer_enuminfo enuminfo;
	/** 
	 * Counter is incremented when applications change any of this
	 * mixer's controls.  A change in value indicates that persistent
	 * mixer applications should update their displays.
	 */
	int modify_counter;
};

static u_int16_t snd_mixerdefaults[SOUND_MIXER_NRDEVICES] = {
	[SOUND_MIXER_VOLUME]	= 75,
	[SOUND_MIXER_BASS]	= 50,
	[SOUND_MIXER_TREBLE]	= 50,
	[SOUND_MIXER_SYNTH]	= 75,
	[SOUND_MIXER_PCM]	= 75,
	[SOUND_MIXER_SPEAKER]	= 75,
	[SOUND_MIXER_LINE]	= 75,
	[SOUND_MIXER_MIC] 	= 0,
	[SOUND_MIXER_CD]	= 75,
	[SOUND_MIXER_IGAIN]	= 0,
	[SOUND_MIXER_LINE1]	= 75,
	[SOUND_MIXER_VIDEO]	= 75,
	[SOUND_MIXER_RECLEV]	= 0,
	[SOUND_MIXER_OGAIN]	= 50,
	[SOUND_MIXER_MONITOR]	= 75,
};

static char* snd_mixernames[SOUND_MIXER_NRDEVICES] = SOUND_DEVICE_NAMES;

static d_open_t mixer_open;
static d_close_t mixer_close;

static struct cdevsw mixer_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_TRACKCLOSE | D_NEEDGIANT,
	.d_open =	mixer_open,
	.d_close =	mixer_close,
	.d_ioctl =	mixer_ioctl,
	.d_name =	"mixer",
};

/**
 * Keeps a count of mixer devices; used only by OSSv4 SNDCTL_SYSINFO ioctl.
 */
int mixer_count = 0;

#ifdef USING_DEVFS
static eventhandler_tag mixer_ehtag;
#endif

static struct cdev *
mixer_get_devt(device_t dev)
{
	struct snddev_info *snddev;

	snddev = device_get_softc(dev);

	return snddev->mixer_dev;
}

#ifdef SND_DYNSYSCTL
static int
mixer_lookup(char *devname)
{
	int i;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++)
		if (strncmp(devname, snd_mixernames[i],
		    strlen(snd_mixernames[i])) == 0)
			return i;
	return -1;
}
#endif

static int
mixer_set(struct snd_mixer *mixer, unsigned dev, unsigned lev)
{
	struct snddev_info *d;
	unsigned l, r;
	int v;

	if ((dev >= SOUND_MIXER_NRDEVICES) || (0 == (mixer->devs & (1 << dev))))
		return -1;

	l = min((lev & 0x00ff), 100);
	r = min(((lev & 0xff00) >> 8), 100);

	d = device_get_softc(mixer->dev);
	if (dev == SOUND_MIXER_PCM && d &&
			(d->flags & SD_F_SOFTVOL)) {
		struct snddev_channel *sce;
		struct pcm_channel *ch;
#ifdef USING_MUTEX
		int locked = (mixer->lock && mtx_owned((struct mtx *)(mixer->lock))) ? 1 : 0;

		if (locked)
			snd_mtxunlock(mixer->lock);
#endif
		SLIST_FOREACH(sce, &d->channels, link) {
			ch = sce->channel;
			CHN_LOCK(ch);
			if (ch->direction == PCMDIR_PLAY &&
					(ch->feederflags & (1 << FEEDER_VOLUME)))
				chn_setvolume(ch, l, r);
			CHN_UNLOCK(ch);
		}
#ifdef USING_MUTEX
		if (locked)
			snd_mtxlock(mixer->lock);
#endif
	} else {
		v = MIXER_SET(mixer, dev, l, r);
		if (v < 0)
			return -1;
	}

	mixer->level[dev] = l | (r << 8);
	return 0;
}

static int
mixer_get(struct snd_mixer *mixer, int dev)
{
	if ((dev < SOUND_MIXER_NRDEVICES) && (mixer->devs & (1 << dev)))
		return mixer->level[dev];
	else return -1;
}

static int
mixer_setrecsrc(struct snd_mixer *mixer, u_int32_t src)
{
	src &= mixer->recdevs;
	if (src == 0)
		src = SOUND_MASK_MIC;
	mixer->recsrc = MIXER_SETRECSRC(mixer, src);
	return 0;
}

static int
mixer_getrecsrc(struct snd_mixer *mixer)
{
	return mixer->recsrc;
}

/**
 * @brief Retrieve the route number of the current recording device
 *
 * OSSv4 assigns routing numbers to recording devices, unlike the previous
 * API which relied on a fixed table of device numbers and names.  This
 * function returns the routing number of the device currently selected
 * for recording.
 *
 * For now, this function is kind of a goofy compatibility stub atop the
 * existing sound system.  (For example, in theory, the old sound system
 * allows multiple recording devices to be specified via a bitmask.)
 *
 * @param m	mixer context container thing
 *
 * @retval 0		success
 * @retval EIDRM	no recording device found (generally not possible)
 * @todo Ask about error code
 */
static int
mixer_get_recroute(struct snd_mixer *m, int *route)
{
	int i, cnt;

	cnt = 0;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		/** @todo can user set a multi-device mask? (== or &?) */
		if ((1 << i) == m->recsrc)
			break;
		if ((1 << i) & m->recdevs)
			++cnt;
	}

	if (i == SOUND_MIXER_NRDEVICES)
		return EIDRM;

	*route = cnt;
	return 0;
}

/**
 * @brief Select a device for recording
 *
 * This function sets a recording source based on a recording device's
 * routing number.  Said number is translated to an old school recdev
 * mask and passed over mixer_setrecsrc. 
 *
 * @param m	mixer context container thing
 *
 * @retval 0		success(?)
 * @retval EINVAL	User specified an invalid device number
 * @retval otherwise	error from mixer_setrecsrc
 */
static int
mixer_set_recroute(struct snd_mixer *m, int route)
{
	int i, cnt, ret;

	ret = 0;
	cnt = 0;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if ((1 << i) & m->recdevs) {
			if (route == cnt)
				break;
			++cnt;
		}
	}

	if (i == SOUND_MIXER_NRDEVICES)
		ret = EINVAL;
	else
		ret = mixer_setrecsrc(m, (1 << i));

	return ret;
}

void
mix_setdevs(struct snd_mixer *m, u_int32_t v)
{
	struct snddev_info *d = device_get_softc(m->dev);
	if (d && (d->flags & SD_F_SOFTVOL))
		v |= SOUND_MASK_PCM;
	m->devs = v;
}

/**
 * @brief Record mask of available recording devices
 *
 * Calling functions are responsible for defining the mask of available
 * recording devices.  This function records that value in a structure
 * used by the rest of the mixer code.
 *
 * This function also populates a structure used by the SNDCTL_DSP_*RECSRC*
 * family of ioctls that are part of OSSV4.  All recording device labels
 * are concatenated in ascending order corresponding to their routing
 * numbers.  (Ex:  a system might have 0 => 'vol', 1 => 'cd', 2 => 'line',
 * etc.)  For now, these labels are just the standard recording device
 * names (cd, line1, etc.), but will eventually be fully dynamic and user
 * controlled.
 *
 * @param m	mixer device context container thing
 * @param v	mask of recording devices
 */
void
mix_setrecdevs(struct snd_mixer *m, u_int32_t v)
{
	oss_mixer_enuminfo *ei;
	char *loc;
	int i, nvalues, nwrote, nleft, ncopied;

	ei = &m->enuminfo;

	nvalues = 0;
	nwrote = 0;
	nleft = sizeof(ei->strings);
	loc = ei->strings;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if ((1 << i) & v) {
			ei->strindex[nvalues] = nwrote;
			ncopied = strlcpy(loc, snd_mixernames[i], nleft) + 1;
			    /* strlcpy retval doesn't include terminator */

			nwrote += ncopied;
			nleft -= ncopied;
			nvalues++;

			/*
			 * XXX I don't think this should ever be possible.
			 * Even with a move to dynamic device/channel names,
			 * each label is limited to ~16 characters, so that'd
			 * take a LOT to fill this buffer.
			 */
			if ((nleft <= 0) || (nvalues >= OSS_ENUM_MAXVALUE)) {
				device_printf(m->dev,
				    "mix_setrecdevs:  Not enough room to store device names--please file a bug report.\n");
				device_printf(m->dev, 
				    "mix_setrecdevs:  Please include details about your sound hardware, OS version, etc.\n");
				break;
			}

			loc = &ei->strings[nwrote];
		}
	}

	/*
	 * NB:	The SNDCTL_DSP_GET_RECSRC_NAMES ioctl ignores the dev
	 * 	and ctrl fields.
	 */
	ei->nvalues = nvalues;
	m->recdevs = v;
}

u_int32_t
mix_getdevs(struct snd_mixer *m)
{
	return m->devs;
}

u_int32_t
mix_getrecdevs(struct snd_mixer *m)
{
	return m->recdevs;
}

void *
mix_getdevinfo(struct snd_mixer *m)
{
	return m->devinfo;
}

int
mixer_init(device_t dev, kobj_class_t cls, void *devinfo)
{
	struct snddev_info *snddev;
	struct snd_mixer *m;
	u_int16_t v;
	struct cdev *pdev;
	int i, unit, val;

	m = (struct snd_mixer *)kobj_create(cls, M_MIXER, M_WAITOK | M_ZERO);
	snprintf(m->name, MIXER_NAMELEN, "%s:mixer", device_get_nameunit(dev));
	m->lock = snd_mtxcreate(m->name, "pcm mixer");
	m->type = cls->name;
	m->devinfo = devinfo;
	m->busy = 0;
	m->dev = dev;

	if (MIXER_INIT(m))
		goto bad;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		v = snd_mixerdefaults[i];

		if (resource_int_value(device_get_name(dev),
		    device_get_unit(dev), snd_mixernames[i], &val) == 0) {
			if (val >= 0 && val <= 100) {
				v = (u_int16_t) val;
			}
		}

		mixer_set(m, i, v | (v << 8));
	}

	mixer_setrecsrc(m, SOUND_MASK_MIC);

	unit = device_get_unit(dev);
	pdev = make_dev(&mixer_cdevsw, PCMMKMINOR(unit, SND_DEV_CTL, 0),
		 UID_ROOT, GID_WHEEL, 0666, "mixer%d", unit);
	pdev->si_drv1 = m;
	snddev = device_get_softc(dev);
	snddev->mixer_dev = pdev;

	++mixer_count;

	return 0;

bad:
	snd_mtxlock(m->lock);
	snd_mtxfree(m->lock);
	kobj_delete((kobj_t)m, M_MIXER);
	return -1;
}

int
mixer_uninit(device_t dev)
{
	int i;
	struct snddev_info *d;
	struct snd_mixer *m;
	struct cdev *pdev;

	d = device_get_softc(dev);
	pdev = mixer_get_devt(dev);
	if (d == NULL || pdev == NULL || pdev->si_drv1 == NULL)
		return EBADF;
	m = pdev->si_drv1;
	snd_mtxlock(m->lock);

	if (m->busy) {
		snd_mtxunlock(m->lock);
		return EBUSY;
	}

	pdev->si_drv1 = NULL;
	destroy_dev(pdev);

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++)
		mixer_set(m, i, 0);

	mixer_setrecsrc(m, SOUND_MASK_MIC);

	MIXER_UNINIT(m);

	snd_mtxfree(m->lock);
	kobj_delete((kobj_t)m, M_MIXER);

	d->mixer_dev = NULL;

	--mixer_count;

	return 0;
}

int
mixer_reinit(device_t dev)
{
	struct snd_mixer *m;
	struct cdev *pdev;
	int i;

	pdev = mixer_get_devt(dev);
	m = pdev->si_drv1;
	snd_mtxlock(m->lock);

	i = MIXER_REINIT(m);
	if (i) {
		snd_mtxunlock(m->lock);
		return i;
	}

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++)
		mixer_set(m, i, m->level[i]);

	mixer_setrecsrc(m, m->recsrc);
	snd_mtxunlock(m->lock);

	return 0;
}

#ifdef SND_DYNSYSCTL
static int
sysctl_hw_snd_hwvol_mixer(SYSCTL_HANDLER_ARGS)
{
	char devname[32];
	int error, dev;
	struct snd_mixer *m;

	m = oidp->oid_arg1;
	snd_mtxlock(m->lock);
	strncpy(devname, snd_mixernames[m->hwvol_mixer], sizeof(devname));
	snd_mtxunlock(m->lock);
	error = sysctl_handle_string(oidp, &devname[0], sizeof(devname), req);
	snd_mtxlock(m->lock);
	if (error == 0 && req->newptr != NULL) {
		dev = mixer_lookup(devname);
		if (dev == -1) {
			snd_mtxunlock(m->lock);
			return EINVAL;
		}
		else if (dev != m->hwvol_mixer) {
			m->hwvol_mixer = dev;
			m->hwvol_muted = 0;
		}
	}
	snd_mtxunlock(m->lock);
	return error;
}
#endif

int
mixer_hwvol_init(device_t dev)
{
	struct snd_mixer *m;
	struct cdev *pdev;

	pdev = mixer_get_devt(dev);
	m = pdev->si_drv1;

	m->hwvol_mixer = SOUND_MIXER_VOLUME;
	m->hwvol_step = 5;
#ifdef SND_DYNSYSCTL
	SYSCTL_ADD_INT(snd_sysctl_tree(dev), SYSCTL_CHILDREN(snd_sysctl_tree_top(dev)),
            OID_AUTO, "hwvol_step", CTLFLAG_RW, &m->hwvol_step, 0, "");
	SYSCTL_ADD_PROC(snd_sysctl_tree(dev), SYSCTL_CHILDREN(snd_sysctl_tree_top(dev)),
            OID_AUTO, "hwvol_mixer", CTLTYPE_STRING | CTLFLAG_RW, m, 0,
	    sysctl_hw_snd_hwvol_mixer, "A", "");
#endif
	return 0;
}

void
mixer_hwvol_mute(device_t dev)
{
	struct snd_mixer *m;
	struct cdev *pdev;

	pdev = mixer_get_devt(dev);
	m = pdev->si_drv1;
	snd_mtxlock(m->lock);
	if (m->hwvol_muted) {
		m->hwvol_muted = 0;
		mixer_set(m, m->hwvol_mixer, m->hwvol_mute_level);
	} else {
		m->hwvol_muted++;
		m->hwvol_mute_level = mixer_get(m, m->hwvol_mixer);
		mixer_set(m, m->hwvol_mixer, 0);
	}
	snd_mtxunlock(m->lock);
}

void
mixer_hwvol_step(device_t dev, int left_step, int right_step)
{
	struct snd_mixer *m;
	int level, left, right;
	struct cdev *pdev;

	pdev = mixer_get_devt(dev);
	m = pdev->si_drv1;
	snd_mtxlock(m->lock);
	if (m->hwvol_muted) {
		m->hwvol_muted = 0;
		level = m->hwvol_mute_level;
	} else
		level = mixer_get(m, m->hwvol_mixer);
	if (level != -1) {
		left = level & 0xff;
		right = level >> 8;
		left += left_step * m->hwvol_step;
		if (left < 0)
			left = 0;
		right += right_step * m->hwvol_step;
		if (right < 0)
			right = 0;
		mixer_set(m, m->hwvol_mixer, left | right << 8);
	}
	snd_mtxunlock(m->lock);
}

/* ----------------------------------------------------------------------- */

static int
mixer_open(struct cdev *i_dev, int flags, int mode, struct thread *td)
{
	struct snd_mixer *m;

	m = i_dev->si_drv1;
	snd_mtxlock(m->lock);

	m->busy++;

	snd_mtxunlock(m->lock);
	return 0;
}

static int
mixer_close(struct cdev *i_dev, int flags, int mode, struct thread *td)
{
	struct snd_mixer *m;

	m = i_dev->si_drv1;
	snd_mtxlock(m->lock);

	if (!m->busy) {
		snd_mtxunlock(m->lock);
		return EBADF;
	}
	m->busy--;

	snd_mtxunlock(m->lock);
	return 0;
}

int
mixer_ioctl(struct cdev *i_dev, u_long cmd, caddr_t arg, int mode, struct thread *td)
{
	struct snd_mixer *m;
	int ret, *arg_i = (int *)arg;
	int v = -1, j = cmd & 0xff;

	m = i_dev->si_drv1;

	if (m == NULL)
		return EBADF;

	snd_mtxlock(m->lock);
	if (mode != -1 && !m->busy) {
		snd_mtxunlock(m->lock);
		return EBADF;
	}

	if (cmd == SNDCTL_MIXERINFO) {
		snd_mtxunlock(m->lock);
		return mixer_oss_mixerinfo(i_dev, (oss_mixerinfo *)arg);
	}

	if ((cmd & MIXER_WRITE(0)) == MIXER_WRITE(0)) {
		if (j == SOUND_MIXER_RECSRC)
			ret = mixer_setrecsrc(m, *arg_i);
		else
			ret = mixer_set(m, j, *arg_i);
		snd_mtxunlock(m->lock);
		return (ret == 0)? 0 : ENXIO;
	}

    	if ((cmd & MIXER_READ(0)) == MIXER_READ(0)) {
		switch (j) {
    		case SOUND_MIXER_DEVMASK:
    		case SOUND_MIXER_CAPS:
    		case SOUND_MIXER_STEREODEVS:
			v = mix_getdevs(m);
			break;

    		case SOUND_MIXER_RECMASK:
			v = mix_getrecdevs(m);
			break;

    		case SOUND_MIXER_RECSRC:
			v = mixer_getrecsrc(m);
			break;

		default:
			v = mixer_get(m, j);
		}
		*arg_i = v;
		snd_mtxunlock(m->lock);
		return (v != -1)? 0 : ENXIO;
	}

	ret = 0;

	switch (cmd) {
 	/** @todo Double check return values, error codes. */
	case SNDCTL_SYSINFO:
		sound_oss_sysinfo((oss_sysinfo *)arg);
		break;
	case SNDCTL_AUDIOINFO:
		ret = dsp_oss_audioinfo(i_dev, (oss_audioinfo *)arg);
		break;
	case SNDCTL_DSP_GET_RECSRC_NAMES:
		bcopy((void *)&m->enuminfo, arg, sizeof(oss_mixer_enuminfo));
		break;
	case SNDCTL_DSP_GET_RECSRC:
		ret = mixer_get_recroute(m, arg_i);
		break;
	case SNDCTL_DSP_SET_RECSRC:
		ret = mixer_set_recroute(m, *arg_i);
		break;
	default:
		ret = ENXIO;
	}

	snd_mtxunlock(m->lock);
	return ret;
}

#ifdef USING_DEVFS
static void
mixer_clone(void *arg, struct ucred *cred, char *name, int namelen,
    struct cdev **dev)
{
	struct snddev_info *sd;

	if (*dev != NULL)
		return;
	if (strcmp(name, "mixer") == 0) {
		sd = devclass_get_softc(pcm_devclass, snd_unit);
		if (sd != NULL && sd->mixer_dev != NULL) {
			*dev = sd->mixer_dev;
			dev_ref(*dev);
		}
	}
}

static void
mixer_sysinit(void *p)
{
	mixer_ehtag = EVENTHANDLER_REGISTER(dev_clone, mixer_clone, 0, 1000);
}

static void
mixer_sysuninit(void *p)
{
	if (mixer_ehtag != NULL)
		EVENTHANDLER_DEREGISTER(dev_clone, mixer_ehtag);
}

SYSINIT(mixer_sysinit, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, mixer_sysinit, NULL);
SYSUNINIT(mixer_sysuninit, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, mixer_sysuninit, NULL);
#endif

/**
 * @brief Handler for SNDCTL_MIXERINFO
 *
 * This function searches for a mixer based on the numeric ID stored
 * in oss_miserinfo::dev.  If set to -1, then information about the
 * current mixer handling the request is provided.  Note, however, that
 * this ioctl may be made with any sound device (audio, mixer, midi).
 *
 * @note Caller must not hold any PCM device, channel, or mixer locks.
 *
 * See http://manuals.opensound.com/developer/SNDCTL_MIXERINFO.html for
 * more information.
 *
 * @param i_dev	character device on which the ioctl arrived
 * @param arg	user argument (oss_mixerinfo *)
 *
 * @retval EINVAL	oss_mixerinfo::dev specified a bad value
 * @retval 0		success
 */
int
mixer_oss_mixerinfo(struct cdev *i_dev, oss_mixerinfo *mi)
{
	struct snddev_info *d;
	struct snd_mixer *m;
	struct cdev *t_cdev;
	int nmix, ret, pcmunit, i;

	/*
	 * If probing the device handling the ioctl, make sure it's a mixer
	 * device.  (This ioctl is valid on audio, mixer, and midi devices.)
	 */
	if ((mi->dev == -1) && (i_dev->si_devsw != &mixer_cdevsw))
		return EINVAL;

	m = NULL;
	t_cdev = NULL;
	nmix = 0;
	ret = 0;
	pcmunit = -1; /* pcmX */

	/*
	 * There's a 1:1 relationship between mixers and PCM devices, so
	 * begin by iterating over PCM devices and search for our mixer.
	 */
	for (i = 0; i < devclass_get_maxunit(pcm_devclass); i++) {
		d = devclass_get_softc(pcm_devclass, i);
		if (d == NULL)
			continue;

		/* See the note in function docblock. */
		mtx_assert(d->lock, MA_NOTOWNED);
		pcm_inprog(d, 1);
		pcm_lock(d);

		if (d->mixer_dev != NULL) {
			if (((mi->dev == -1) && (d->mixer_dev == i_dev)) || (mi->dev == nmix)) {
				t_cdev = d->mixer_dev;
				pcmunit = i;
				break;
			}
			++nmix;
		}

		pcm_unlock(d);
		pcm_inprog(d, -1);
	}

	/*
	 * If t_cdev is NULL, then search was exhausted and device wasn't
	 * found.  No locks are held, so just return.
	 */
	if (t_cdev == NULL)
		return EINVAL;

	m = t_cdev->si_drv1;
	mtx_lock(m->lock);

	/*
	 * At this point, the following synchronization stuff has happened:
	 *   - a specific PCM device is locked and its "in progress
	 *     operations" counter has been incremented, so be sure to unlock
	 *     and decrement when exiting;
	 *   - a specific mixer device has been locked, so be sure to unlock
	 *     when existing.
	 */

	bzero((void *)mi, sizeof(*mi));

	mi->dev = nmix;
	snprintf(mi->id, sizeof(mi->id), "mixer%d", dev2unit(t_cdev));
	strlcpy(mi->name, m->name, sizeof(mi->name));
	mi->modify_counter = m->modify_counter;
	mi->card_number = pcmunit;
	/*
	 * Currently, FreeBSD assumes 1:1 relationship between a pcm and
	 * mixer devices, so this is hardcoded to 0.
	 */
	mi->port_number = 0;

	/**
	 * @todo Fill in @sa oss_mixerinfo::mixerhandle.
	 * @note From 4Front:  "mixerhandle is an arbitrary string that
	 * 	 identifies the mixer better than the device number
	 * 	 (mixerinfo.dev). Device numbers may change depending on
	 * 	 the order the drivers are loaded. However the handle
	 * 	 should remain the same provided that the sound card is
	 * 	 not moved to another PCI slot."
	 */

	/**
	 * @note
	 * @sa oss_mixerinfo::magic is a reserved field.
	 * 
	 * @par
	 * From 4Front:  "magic is usually 0. However some devices may have
	 * dedicated setup utilities and the magic field may contain an
	 * unique driver specific value (managed by [4Front])."
	 */

	mi->enabled = device_is_attached(m->dev) ? 1 : 0;
	/**
	 * The only flag for @sa oss_mixerinfo::caps is currently
	 * MIXER_CAP_VIRTUAL, which I'm not sure we really worry about.
	 */
	/**
	 * Mixer extensions currently aren't supported, so leave 
	 * @sa oss_mixerinfo::nrext blank for now.
	 */
	/**
	 * @todo Fill in @sa oss_mixerinfo::priority (requires touching
	 * 	 drivers?)
	 * @note The priority field is for mixer applets to determine which
	 * mixer should be the default, with 0 being least preferred and 10
	 * being most preferred.  From 4Front:  "OSS drivers like ICH use
	 * higher values (10) because such chips are known to be used only
	 * on motherboards.  Drivers for high end pro devices use 0 because
	 * they will never be the default mixer. Other devices use values 1
	 * to 9 depending on the estimated probability of being the default
	 * device.
	 *
	 * XXX Described by Hannu@4Front, but not found in soundcard.h.
	strlcpy(mi->devnode, t_cdev->si_name, sizeof(mi->devnode));
	mi->legacy_device = pcmunit;
	 */

	mtx_unlock(m->lock);
	pcm_unlock(d);
	pcm_inprog(d, -1);

	return ret;
}
