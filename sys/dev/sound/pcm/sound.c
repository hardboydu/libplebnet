/*
 * Copyright (c) 1999 Cameron Grant <gandalf@vilnya.demon.co.uk>
 * (C) 1997 Luigi Rizzo (luigi@iet.unipi.it)
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
 * $FreeBSD$
 */

#include "opt_devfs.h"

#include <dev/sound/pcm/sound.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif /* DEVFS */

#if NPCM > 0	/* from "pcm.h" via disgusting #include in snd/sound.h */

extern struct isa_driver pcmdriver;

static int 	status_isopen = 0;
static int 	status_init(char *buf, int size);
static int 	status_read(struct uio *buf);

static d_open_t sndopen;
static d_close_t sndclose;
static d_ioctl_t sndioctl;
static d_read_t sndread;
static d_write_t sndwrite;
static d_mmap_t sndmmap;
static d_poll_t sndpoll;

#define CDEV_MAJOR 30
static struct cdevsw snd_cdevsw = {
	/* open */	sndopen,
	/* close */	sndclose,
	/* read */	sndread,
	/* write */	sndwrite,
	/* ioctl */	sndioctl,
	/* poll */	sndpoll,
	/* mmap */	sndmmap,
	/* strategy */	nostrategy,
	/* name */	"snd",
	/* maj */	CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	0,
	/* bmaj */	-1
};

/* PROPOSAL:
each unit needs:
status, mixer, dsp, dspW, audio, sequencer, midi-in, seq2, sndproc = 9 devices
dspW and audio are deprecated.
dsp needs min 64 channels, will give it 256

minor = (unit << 12) + (dev << 8) + channel
currently minor = (channel << 8) + (unit << 4) + dev

nomenclature:
	/dev/pcmX/dsp.(0..255)
	/dev/pcmX/dspW
	/dev/pcmX/audio
	/dev/pcmX/status
	/dev/pcmX/mixer
	[etc.]

currently:
minor = (channel << 8) + (unit << 4) + dev
*/

#define PCMMINOR(x) (minor(x))
#define PCMCHAN(x) ((PCMMINOR(x) & 0x0000ff00) >> 8)
#define PCMUNIT(x) ((PCMMINOR(x) & 0x000000f0) >> 4)
#define PCMDEV(x)   (PCMMINOR(x) & 0x0000000f)
#define PCMMKMINOR(u, d) (((u) & 0x0f) << 4 | ((d) & 0x0f))

static devclass_t pcm_devclass;

static snddev_info *
gsd(int unit)
{
	return devclass_get_softc(pcm_devclass, unit);
}

int
pcm_addchan(device_t dev, int dir, pcm_channel *templ, void *devinfo)
{
    	snddev_info *d = device_get_softc(dev);
	pcm_channel *ch;

	ch = (dir == PCMDIR_PLAY)? &d->play[d->playcount++] : &d->rec[d->reccount++];
	*ch = *templ;
	chn_init(ch, devinfo, dir);
	d->chancount++;
	return 0;
}

int
pcm_setstatus(device_t dev, char *str)
{
    	snddev_info *d = device_get_softc(dev);
	strncpy(d->status, str, SND_STATUSLEN);
	return 0;
}

u_int32_t
pcm_getflags(device_t dev)
{
    	snddev_info *d = device_get_softc(dev);
	return d->flags;
}

void
pcm_setflags(device_t dev, u_int32_t val)
{
    	snddev_info *d = device_get_softc(dev);
	d->flags = val;
}

/* This is the generic init routine */
int
pcm_register(device_t dev, void *devinfo, int numplay, int numrec)
{
    	int sz, unit = device_get_unit(dev);
    	snddev_info *d = device_get_softc(dev);

    	if (!pcm_devclass) {
    		pcm_devclass = device_get_devclass(dev);
		make_dev(&snd_cdevsw, PCMMKMINOR(0, SND_DEV_STATUS),
			 UID_ROOT, GID_WHEEL, 0444, "sndstat");
	}
	make_dev(&snd_cdevsw, PCMMKMINOR(unit, SND_DEV_CTL),
		 UID_ROOT, GID_WHEEL, 0666, "mixer%d", unit);
	make_dev(&snd_cdevsw, PCMMKMINOR(unit, SND_DEV_DSP),
		 UID_ROOT, GID_WHEEL, 0666, "dsp%d", unit);
	make_dev(&snd_cdevsw, PCMMKMINOR(unit, SND_DEV_AUDIO),
		 UID_ROOT, GID_WHEEL, 0666, "audio%d", unit);
	make_dev(&snd_cdevsw, PCMMKMINOR(unit, SND_DEV_DSP16),
		 UID_ROOT, GID_WHEEL, 0666, "dspW%d", unit);
	/* XXX SND_DEV_NORESET? */
	d->devinfo = devinfo;
	d->chancount = d->playcount = d->reccount = 0;
    	sz = (numplay + numrec) * sizeof(pcm_channel *);
    	d->aplay = (pcm_channel **)malloc(sz, M_DEVBUF, M_NOWAIT);
    	if (!d->aplay) goto no;
    	d->arec = (pcm_channel **)malloc(sz, M_DEVBUF, M_NOWAIT);
    	if (!d->arec) goto no;
    	bzero(d->aplay, sz);
    	bzero(d->arec, sz);

    	d->play = (pcm_channel *)malloc(numplay * sizeof(pcm_channel),
					M_DEVBUF, M_NOWAIT);
    	if (!d->play) goto no;
    	d->rec = (pcm_channel *)malloc(numrec * sizeof(pcm_channel),
				       M_DEVBUF, M_NOWAIT);
    	if (!d->rec) goto no;
    	bzero(d->play, numplay * sizeof(pcm_channel));
    	bzero(d->rec, numrec * sizeof(pcm_channel));

	fkchan_setup(&d->fakechan);
	chn_init(&d->fakechan, NULL, 0);
	d->magic = MAGIC(unit); /* debugging... */

    	return 0;
no:
	if (d->aplay) free(d->aplay, M_DEVBUF);
	if (d->play) free(d->play, M_DEVBUF);
	if (d->arec) free(d->arec, M_DEVBUF);
	if (d->rec) free(d->rec, M_DEVBUF);
	return ENXIO;
}

/*
 * a small utility function which, given a device number, returns
 * a pointer to the associated snddev_info struct, and sets the unit
 * number.
 */
static snddev_info *
get_snddev_info(dev_t i_dev, int *unit, int *dev, int *chan)
{
    	int u, d, c;

    	u = PCMUNIT(i_dev);
    	d = PCMDEV(i_dev);
    	c = PCMCHAN(i_dev);
    	if (u > devclass_get_maxunit(pcm_devclass)) u = -1;
    	if (unit) *unit = u;
    	if (dev) *dev = d;
    	if (chan) *chan = c;
    	if (u < 0) return NULL;

    	switch(d) {
    	case SND_DEV_CTL:	/* /dev/mixer handled by pcm */
    	case SND_DEV_STATUS: /* /dev/sndstat handled by pcm */
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
    	case SND_DEV_AUDIO:
		return gsd(u);

    	case SND_DEV_SEQ: /* XXX when enabled... */
    	case SND_DEV_SEQ2:
    	case SND_DEV_MIDIN:
    	case SND_DEV_SNDPROC:	/* /dev/sndproc handled by pcm */
    	default:
		printf("unsupported subdevice %d\n", d);
		return NULL;
    	}
}

static int
sndopen(dev_t i_dev, int flags, int mode, struct proc *p)
{
    	int dev, unit, chan;
    	snddev_info *d = get_snddev_info(i_dev, &unit, &dev, &chan);

    	DEB(printf("open snd%d subdev %d flags 0x%08x mode 0x%08x\n",
		unit, dev, flags, mode));

    	switch(dev) {
    	case SND_DEV_STATUS:
		if (status_isopen) return EBUSY;
		status_isopen = 1;
		return 0;

    	case SND_DEV_CTL:
		return d? 0 : ENXIO;

    	case SND_DEV_AUDIO:
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
	case SND_DEV_NORESET:
		return d? dsp_open(d, chan, flags, dev) : ENXIO;

    	default:
    		return ENXIO;
    	}
}

static int
sndclose(dev_t i_dev, int flags, int mode, struct proc *p)
{
    	int dev, unit, chan;
    	snddev_info *d = get_snddev_info(i_dev, &unit, &dev, &chan);

    	DEB(printf("close snd%d subdev %d\n", unit, dev));

    	switch(dev) { /* only those for which close makes sense */
    	case SND_DEV_STATUS:
		if (!status_isopen) return EBADF;
		status_isopen = 0;
		return 0;

    	case SND_DEV_CTL:
		return d? 0 : ENXIO;

    	case SND_DEV_AUDIO:
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
		return d? dsp_close(d, chan, dev) : ENXIO;

    	default:
		return ENXIO;
    	}
}

static int
sndread(dev_t i_dev, struct uio *buf, int flag)
{
    	int dev, unit, chan;
    	snddev_info *d = get_snddev_info(i_dev, &unit, &dev, &chan);
    	DEB(printf("read snd%d subdev %d flag 0x%08x\n", unit, dev, flag));

    	switch(dev) {
    	case SND_DEV_STATUS:
		return status_isopen? status_read(buf) : EBADF;

    	case SND_DEV_AUDIO:
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
        	return d? dsp_read(d, chan, buf, flag) : EBADF;

    	default:
    		return ENXIO;
    	}
}

static int
sndwrite(dev_t i_dev, struct uio *buf, int flag)
{
    	int dev, unit, chan;
    	snddev_info *d = get_snddev_info(i_dev, &unit, &dev, &chan);

    	DEB(printf("write snd%d subdev %d flag 0x%08x\n", unit, dev & 0xf, flag));

    	switch(dev) {	/* only writeable devices */
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
    	case SND_DEV_AUDIO:
		return d? dsp_write(d, chan, buf, flag) : EBADF;

    	default:
		return EPERM; /* for non-writeable devices ; */
    	}
}

static int
sndioctl(dev_t i_dev, u_long cmd, caddr_t arg, int mode, struct proc * p)
{
    	int dev, chan;
    	snddev_info *d = get_snddev_info(i_dev, NULL, &dev, &chan);

    	if (d == NULL) return ENXIO;

    	switch(dev) {
    	case SND_DEV_CTL:
		return mixer_ioctl(d, cmd, arg);

    	case SND_DEV_AUDIO:
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
		return dsp_ioctl(d, chan, cmd, arg);

    	default:
    		return ENXIO;
    	}
}

static int
sndpoll(dev_t i_dev, int events, struct proc *p)
{
    	int dev, chan;
    	snddev_info *d = get_snddev_info(i_dev, NULL, &dev, &chan);

    	DEB(printf("sndpoll dev 0x%04x events 0x%08x\n", i_dev, events));

    	if (d == NULL) return ENXIO;

    	switch(dev) {
    	case SND_DEV_AUDIO:
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
		return dsp_poll(d, chan, events, p);

    	default:
    		return (events &
       		       (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)) | POLLHUP;
    	}
}

/*
 * The mmap interface allows access to the play and read buffer,
 * plus the device descriptor.
 * The various blocks are accessible at the following offsets:
 *
 * 0x00000000 ( 0   ) : write buffer ;
 * 0x01000000 (16 MB) : read buffer ;
 * 0x02000000 (32 MB) : device descriptor (dangerous!)
 *
 * WARNING: the mmap routines assume memory areas are aligned. This
 * is true (probably) for the dma buffers, but likely false for the
 * device descriptor. As a consequence, we do not know where it is
 * located in the requested area.
 */
static int
sndmmap(dev_t i_dev, vm_offset_t offset, int nprot)
{
    	int unit, dev, chan;
    	snddev_info *d = get_snddev_info(i_dev, &unit, &dev, &chan);

    	DEB(printf("sndmmap d 0x%p dev 0x%04x ofs 0x%08x nprot 0x%08x\n",
		   d, dev, offset, nprot));

    	if (d == NULL || nprot & PROT_EXEC)	return -1; /* forbidden */

    	switch(dev) {
    	case SND_DEV_AUDIO:
    	case SND_DEV_DSP:
    	case SND_DEV_DSP16:
		return dsp_mmap(d, chan, offset, nprot);

    	default:
    		return -1;
    	}
}

static int
status_init(char *buf, int size)
{
    	int             i;
    	device_t	    dev;
    	snddev_info     *d;

    	snprintf(buf, size, "FreeBSD Audio Driver (newpcm) %s %s\n"
		 "Installed devices:\n", __DATE__, __TIME__);

    	for (i = 0; i <= devclass_get_maxunit(pcm_devclass); i++) {
		d = gsd(i);
		if (!d) continue;
		dev = devclass_get_device(pcm_devclass, i);
        	if (1) snprintf(buf + strlen(buf), size - strlen(buf),
		            	"pcm%d: <%s> %s (%d/%d channels%s)\n",
		            	i, device_get_desc(dev), d->status,
		            	d->playcount, d->reccount,
			    	(!(d->flags & SD_F_SIMPLEX))? " duplex" : "");
    	}
    	return strlen(buf);
}

static int
status_read(struct uio *buf)
{
    	static char	status_buf[4096];
    	static int 	bufptr = 0, buflen = 0;
    	int l;

    	if (status_isopen == 1) {
		status_isopen++;
		bufptr = 0;
		buflen = status_init(status_buf, sizeof status_buf);
    	}

    	l = min(buf->uio_resid, buflen - bufptr);
    	bufptr += l;
    	return (l > 0)? uiomove(status_buf + bufptr - l, l, buf) : 0;
}

#endif	/* NPCM > 0 */
