/*
 * Copyright (c) 1999 Cameron Grant <gandalf@vilnya.demon.co.uk>
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/kernel.h>

#include <dev/pcm/sound.h>

static int getchns(snddev_info *d, int chan, pcm_channel **rdch, pcm_channel **wrch);

static pcm_channel *
allocchn(snddev_info *d, int direction)
{
	pcm_channel *chns = (direction == PCMDIR_PLAY)? d->play : d->rec;
	int i, cnt = (direction == PCMDIR_PLAY)? d->playcount : d->reccount;
	for (i = 0; i < cnt; i++) {
		if (!(chns[i].flags & CHN_F_BUSY)) {
			chns[i].flags |= CHN_F_BUSY;
			return &chns[i];
		}
	}
	return NULL;
}

static int
getchns(snddev_info *d, int chan, pcm_channel **rdch, pcm_channel **wrch)
{
	if ((d->flags & SD_F_PRIO_SET) == SD_F_PRIO_SET)
		panic("read and write both prioritised");
	if (d->flags & SD_F_SIMPLEX) {
		*rdch = (d->flags & SD_F_PRIO_RD)? d->arec[chan] : &d->fakechan;
		*wrch = (d->flags & SD_F_PRIO_WR)? d->aplay[chan] : &d->fakechan;
	} else {
		*rdch = d->arec[chan];
		*wrch = d->aplay[chan];
	}
	return 0;
}

static void
setchns(snddev_info *d, int chan)
{
	if ((d->flags & SD_F_PRIO_SET) == SD_F_PRIO_SET)
		panic("read and write both prioritised");
	d->flags |= SD_F_DIR_SET;
	if (d->flags & SD_F_EVILSB16) {
		if ((d->flags & SD_F_PRIO_RD) && (d->aplay[chan])) {
			pcm_channel *tmp;
			tmp = d->arec[chan];
			d->arec[chan] = d->aplay[chan];
			d->aplay[chan] = tmp;
		}
		if (d->aplay[chan]) chn_setdir(d->aplay[chan], PCMDIR_PLAY);
		if (d->arec[chan]) chn_setdir(d->arec[chan], PCMDIR_REC);
	}
}

int
dsp_open(snddev_info *d, int chan, int oflags, int devtype)
{
	pcm_channel *rdch = NULL, *wrch = NULL;
	u_int32_t fmt;

	if (chan >= d->chancount) return ENODEV;
	if (d->aplay[chan] || d->arec[chan]) return EBUSY;
	if (oflags & FREAD) {
		rdch = allocchn(d, PCMDIR_REC);
		if (!rdch) return EBUSY;
	}
	if (oflags & FWRITE) {
		wrch = allocchn(d, PCMDIR_PLAY);
		if (!wrch) {
			if (rdch) rdch->flags &= ~CHN_F_BUSY;
			return EBUSY;
		}
	}
	d->aplay[chan] = wrch;
	d->arec[chan] = rdch;
	switch (devtype) {
	case SND_DEV_DSP16:
		fmt = AFMT_S16_LE;
		break;

	case SND_DEV_DSP:
		fmt = AFMT_U8;
		break;

	case SND_DEV_AUDIO:
		fmt = AFMT_MU_LAW;
		break;

	default:
		return ENXIO;
	}

	if (rdch) {
	        chn_reset(rdch);
		if (oflags & O_NONBLOCK) rdch->flags |= CHN_F_NBIO;
		rdch->volume = (100 << 8) | 100;
		rdch->format = fmt;
		rdch->speed = DSP_DEFAULT_SPEED;
		rdch->blocksize = 2048;
	}
	if (wrch) {
	        chn_reset(wrch);
		if (oflags & O_NONBLOCK) wrch->flags |= CHN_F_NBIO;
		wrch->volume = (100 << 8) | 100;
		wrch->format = fmt;
		wrch->speed = DSP_DEFAULT_SPEED;
		wrch->blocksize = 2048;
	}
	return 0;
}

int
dsp_close(snddev_info *d, int chan, int devtype)
{
	pcm_channel *rdch, *wrch;

	d->flags &= ~SD_F_TRANSIENT;
	getchns(d, chan, &rdch, &wrch);

	if (rdch) {
		chn_abort(rdch);
		rdch->flags &= ~(CHN_F_BUSY | CHN_F_RUNNING | CHN_F_MAPPED);
	}
	if (wrch) wrch->flags &= ~(CHN_F_BUSY | CHN_F_RUNNING | CHN_F_MAPPED);
	d->aplay[chan] = NULL;
	d->arec[chan] = NULL;
	return 0;
}

int
dsp_read(snddev_info *d, int chan, struct uio *buf, int flag)
{
	pcm_channel *rdch, *wrch;

	if (!(d->flags & SD_F_PRIO_SET)) d->flags |= SD_F_PRIO_RD;
	if (!(d->flags & SD_F_DIR_SET)) setchns(d, chan);
	getchns(d, chan, &rdch, &wrch);
	if (!rdch || !(rdch->flags & CHN_F_BUSY))
		panic("dsp_read: non%s channel", rdch? "busy" : "existant");
	if (rdch->flags & CHN_F_MAPPED) return EINVAL;
	if (!(rdch->flags & CHN_F_RUNNING)) rdch->flags |= CHN_F_RUNNING;
	return chn_read(rdch, buf);
}

int
dsp_write(snddev_info *d, int chan, struct uio *buf, int flag)
{
	pcm_channel *rdch, *wrch;

	if (!(d->flags & SD_F_PRIO_SET)) d->flags |= SD_F_PRIO_WR;
	if (!(d->flags & SD_F_DIR_SET)) setchns(d, chan);
	getchns(d, chan, &rdch, &wrch);
	if (!wrch || !(wrch->flags & CHN_F_BUSY))
		panic("dsp_write: non%s channel", wrch? "busy" : "existant");
	if (wrch->flags & CHN_F_MAPPED) return EINVAL;
	if (!(wrch->flags & CHN_F_RUNNING)) wrch->flags |= CHN_F_RUNNING;
	return chn_write(wrch, buf);
}

int
dsp_ioctl(snddev_info *d, int chan, u_long cmd, caddr_t arg)
{
    	int ret = 0, *arg_i = (int *)arg;
    	u_long s;
    	pcm_channel *wrch = NULL, *rdch = NULL;

    	getchns(d, chan, &rdch, &wrch);

    	/*
     	 * all routines are called with int. blocked. Make sure that
     	 * ints are re-enabled when calling slow or blocking functions!
     	 */
    	s = spltty();
    	switch(cmd) {

    	/*
     	 * we start with the new ioctl interface.
     	 */
    	case AIONWRITE:	/* how many bytes can write ? */
		if (wrch && wrch->buffer.dl) chn_dmaupdate(wrch);
		*arg_i = wrch? wrch->buffer.fl : 0;
		break;

    	case AIOSSIZE:     /* set the current blocksize */
		{
	    		struct snd_size *p = (struct snd_size *)arg;
	    		splx(s);
	    		if (wrch) chn_setblocksize(wrch, p->play_size);
	    		if (rdch) chn_setblocksize(rdch, p->rec_size);
		}
		/* FALLTHROUGH */
    	case AIOGSIZE:	/* get the current blocksize */
		{
	    		struct snd_size *p = (struct snd_size *)arg;
	    		if (wrch) p->play_size = wrch->blocksize;
	    		if (rdch) p->rec_size = rdch->blocksize;
		}
		break;

    	case AIOSFMT:
		{
	    		snd_chan_param *p = (snd_chan_param *)arg;
	    		splx(s);
	    		if (wrch) {
				chn_setformat(wrch, p->play_format);
				chn_setspeed(wrch, p->play_rate);
	    		}
	    		if (rdch) {
				chn_setformat(rdch, p->rec_format);
				chn_setspeed(rdch, p->rec_rate);
	    		}
		}
		/* FALLTHROUGH */

    	case AIOGFMT:
		{
	    		snd_chan_param *p = (snd_chan_param *)arg;
	    		p->play_rate = wrch? wrch->speed : 0;
	    		p->rec_rate = rdch? rdch->speed : 0;
	    		p->play_format = wrch? wrch->format : 0;
	    		p->rec_format = rdch? rdch->format : 0;
		}
		break;

    	case AIOGCAP:     /* get capabilities */
		{
	    		snd_capabilities *p = (snd_capabilities *)arg;
			pcmchan_caps *pcaps = NULL, *rcaps = NULL;
			if (rdch) rcaps = chn_getcaps(rdch);
			if (wrch) pcaps = chn_getcaps(wrch);
	    		p->rate_min = max(rcaps? rcaps->minspeed : 0,
	                      		  pcaps? pcaps->minspeed : 0);
	    		p->rate_max = min(rcaps? rcaps->maxspeed : 1000000,
	                      		  pcaps? pcaps->maxspeed : 1000000);
	    		p->bufsize = min(rdch? rdch->buffer.bufsize : 1000000,
	                     		 wrch? wrch->buffer.bufsize : 1000000);
			/* XXX bad on sb16 */
	    		p->formats = (rcaps? rcaps->formats : 0xffffffff) &
			 	     (pcaps? pcaps->formats : 0xffffffff);
	    		p->mixers = 1; /* default: one mixer */
	    		p->inputs = d->mixer.devs;
	    		p->left = p->right = 100;
		}
		break;

    	case AIOSTOP:
		if (*arg_i == AIOSYNC_PLAY && wrch) *arg_i = chn_abort(wrch);
		else if (*arg_i == AIOSYNC_CAPTURE && rdch) *arg_i = chn_abort(rdch);
		else {
		    	splx(s);
	   	 	printf("AIOSTOP: bad channel 0x%x\n", *arg_i);
	    		*arg_i = 0;
		}
		break;

    	case AIOSYNC:
		printf("AIOSYNC chan 0x%03lx pos %lu unimplemented\n",
	    		((snd_sync_parm *)arg)->chan, ((snd_sync_parm *)arg)->pos);
		break;
    	/*
     	* here follow the standard ioctls (filio.h etc.)
     	*/
    	case FIONREAD: /* get # bytes to read */
		if (rdch && rdch->buffer.dl) chn_dmaupdate(rdch);
		*arg_i = rdch? rdch->buffer.rl : 0;
		break;

    	case FIOASYNC: /*set/clear async i/o */
		DEB( printf("FIOASYNC\n") ; )
		break;

    	case SNDCTL_DSP_NONBLOCK:
    	case FIONBIO: /* set/clear non-blocking i/o */
		if (rdch) rdch->flags &= ~CHN_F_NBIO;
		if (wrch) wrch->flags &= ~CHN_F_NBIO;
		if (*arg_i) {
		    	if (rdch) rdch->flags |= CHN_F_NBIO;
		    	if (wrch) wrch->flags |= CHN_F_NBIO;
		}
		break;

    	/*
     	* Finally, here is the linux-compatible ioctl interface
     	*/
	#define THE_REAL_SNDCTL_DSP_GETBLKSIZE _IOWR('P', 4, int)
    	case THE_REAL_SNDCTL_DSP_GETBLKSIZE:
    	case SNDCTL_DSP_GETBLKSIZE:
		*arg_i = wrch? wrch->blocksize : 0; /* XXX rdch? */
		break ;

    	case SNDCTL_DSP_SETBLKSIZE:
		splx(s);
		if (wrch) chn_setblocksize(wrch, *arg_i);
		if (rdch) chn_setblocksize(rdch, *arg_i);
		break;

    	case SNDCTL_DSP_RESET:
		DEB(printf("dsp reset\n"));
		if (wrch) chn_abort(wrch);
		if (rdch) chn_abort(rdch);
		break;

    	case SNDCTL_DSP_SYNC:
		printf("dsp sync\n");
		splx(s);
		if (wrch) chn_sync(wrch, wrch->buffer.bufsize - 4);
		break;

    	case SNDCTL_DSP_SPEED:
		splx(s);
		if (wrch) chn_setspeed(wrch, *arg_i);
		if (rdch) chn_setspeed(rdch, *arg_i);
		/* fallthru */

    	case SOUND_PCM_READ_RATE:
		*arg_i = wrch? wrch->speed : rdch->speed;
		break;

    	case SNDCTL_DSP_STEREO:
		splx(s);
		if (wrch) chn_setformat(wrch, (wrch->format & ~AFMT_STEREO) |
					((*arg_i)? AFMT_STEREO : 0));
		if (rdch) chn_setformat(rdch, (rdch->format & ~AFMT_STEREO) |
				        ((*arg_i)? AFMT_STEREO : 0));
		*arg_i = ((wrch? wrch->format : rdch->format) & AFMT_STEREO)? 1 : 0;
		break;

    	case SOUND_PCM_WRITE_CHANNELS:
		splx(s);
		if (wrch) chn_setformat(wrch, (wrch->format & ~AFMT_STEREO) |
					((*arg_i == 2)? AFMT_STEREO : 0));
		if (rdch) chn_setformat(rdch, (rdch->format & ~AFMT_STEREO) |
					((*arg_i == 2)? AFMT_STEREO : 0));
		/* fallthru */

    	case SOUND_PCM_READ_CHANNELS:
		*arg_i = ((wrch? wrch->format : rdch->format) & AFMT_STEREO)? 2 : 1;
		break;

    	case SNDCTL_DSP_GETFMTS:	/* returns a mask of supported fmts */
		*arg_i = wrch? chn_getcaps(wrch)->formats : chn_getcaps(rdch)->formats;
		break ;

    	case SNDCTL_DSP_SETFMT:	/* sets _one_ format */
		splx(s);
		if (wrch) chn_setformat(wrch, *arg_i);
		if (rdch) chn_setformat(rdch, *arg_i);
		*arg_i = wrch? wrch->format : rdch->format;
		break;

    	case SNDCTL_DSP_SUBDIVIDE:
		/* XXX watch out, this is RW! */
		DEB(printf("SNDCTL_DSP_SUBDIVIDE unimplemented\n");)
		break;

    	case SNDCTL_DSP_SETFRAGMENT:
		/* XXX watch out, this is RW! */
		DEB(printf("SNDCTL_DSP_SETFRAGMENT 0x%08x\n", *(int *)arg));
		{
		    	int bytes = 1 << min(*arg_i & 0xffff, 16);
     		    	int count = (*arg_i >> 16) & 0xffff;
			pcm_channel *c = wrch? wrch : rdch;
	    		splx(s);
		    	if (rdch) chn_setblocksize(rdch, bytes);
		    	if (wrch) chn_setblocksize(wrch, bytes);

			/* eg: 4dwave can only interrupt at buffer midpoint, so
			 * it will force blocksize == bufsize/2
			 */
	    		count = c->buffer.bufsize / c->blocksize;
	    		bytes = ffs(c->blocksize) - 1;
	    		*arg_i = (count << 16) | bytes;
		}
		break;

    	case SNDCTL_DSP_GETISPACE:
		/* return space available in the input queue */
		{
	    		audio_buf_info *a = (audio_buf_info *)arg;
	    		if (rdch) {
	        		snd_dbuf *b = &rdch->buffer;
	        		if (b->dl) chn_dmaupdate(rdch);
				a->bytes = b->fl;
	        		a->fragments = 1;
	        		a->fragstotal = b->bufsize / rdch->blocksize;
	        		a->fragsize = rdch->blocksize;
	    		}
		}
		break;

    	case SNDCTL_DSP_GETOSPACE:
		/* return space available in the output queue */
		{
	    		audio_buf_info *a = (audio_buf_info *)arg;
	    		if (wrch) {
	        		snd_dbuf *b = &wrch->buffer;
	        		if (b->dl) chn_dmaupdate(wrch);
				a->bytes = b->fl;
	        		a->fragments = 1;
	        		a->fragstotal = b->bufsize / wrch->blocksize;
	        		a->fragsize = wrch->blocksize;
	    		}
		}
		break;

    	case SNDCTL_DSP_GETIPTR:
		{
	    		count_info *a = (count_info *)arg;
	    		if (rdch) {
    	        		snd_dbuf *b = &rdch->buffer;
	        		if (b->dl) chn_dmaupdate(rdch);
	        		a->bytes = b->total;
	        		a->blocks = (b->total - b->prev_total) / rdch->blocksize;
	        		a->ptr = b->fp;
	        		b->prev_total += a->blocks * rdch->blocksize;
	    		} else ret = EINVAL;
		}
		break;

    	case SNDCTL_DSP_GETOPTR:
		{
	    		count_info *a = (count_info *)arg;
	    		if (wrch) {
    	        		snd_dbuf *b = &wrch->buffer;
	        		if (b->dl) chn_dmaupdate(wrch);
	        		a->bytes = b->total;
	        		a->blocks = (b->total - b->prev_total) / wrch->blocksize;
	        		a->ptr = b->rp;
	        		b->prev_total += a->blocks * wrch->blocksize;
	    		} else ret = EINVAL;
		}
		break;

    	case SNDCTL_DSP_GETCAPS:
		*arg_i = DSP_CAP_REALTIME | DSP_CAP_MMAP | DSP_CAP_TRIGGER;
		if (rdch && wrch && !(d->flags & SD_F_SIMPLEX))
			*arg_i |= DSP_CAP_DUPLEX;
		break;

    	case SOUND_PCM_READ_BITS:
        	*arg_i = ((wrch? wrch->format : rdch->format) & AFMT_16BIT)? 16 : 8;
		break;

    	case SNDCTL_DSP_SETTRIGGER:
		if (rdch) {
			rdch->flags &= ~CHN_F_TRIGGERED;
		    	if (*arg_i & PCM_ENABLE_INPUT)
				rdch->flags |= CHN_F_TRIGGERED;
			chn_intr(rdch);
		}
		if (wrch) {
			wrch->flags &= ~CHN_F_TRIGGERED;
		    	if (*arg_i & PCM_ENABLE_OUTPUT)
				wrch->flags |= CHN_F_TRIGGERED;
			chn_intr(wrch);
		}
		break;

    	case SNDCTL_DSP_GETTRIGGER:
		*arg_i = 0;
		if (wrch && wrch->flags & CHN_F_TRIGGERED)
			*arg_i |= PCM_ENABLE_OUTPUT;
		if (rdch && rdch->flags & CHN_F_TRIGGERED)
			*arg_i |= PCM_ENABLE_INPUT;
		break;

    	case SNDCTL_DSP_MAPINBUF:
    	case SNDCTL_DSP_MAPOUTBUF:
    	case SNDCTL_DSP_SETSYNCRO:
		/* undocumented */

    	case SNDCTL_DSP_POST:
    	case SOUND_PCM_WRITE_FILTER:
    	case SOUND_PCM_READ_FILTER:
		/* dunno what these do, don't sound important */
    	default:
		DEB(printf("default ioctl snd%d fn 0x%08x fail\n", unit, cmd));
		ret = EINVAL;
		break;
    	}
    	splx(s);
    	return ret;
}

int
dsp_poll(snddev_info *d, int chan, int events, struct proc *p)
{
	int ret = 0, e;
	pcm_channel *wrch = NULL, *rdch = NULL;

	getchns(d, chan, &rdch, &wrch);
	e = events & (POLLOUT | POLLWRNORM);
	if (wrch && e) ret |= chn_poll(wrch, e, p);
	e = events & (POLLIN | POLLRDNORM);
	if (rdch && e) ret |= chn_poll(rdch, e, p);
	return ret;
}

int
dsp_mmap(snddev_info *d, int chan, vm_offset_t offset, int nprot)
{
	pcm_channel *wrch = NULL, *rdch = NULL, *c = NULL;

	getchns(d, chan, &rdch, &wrch);
	/* XXX this is broken by line 204 of vm/device_pager.c, so force write buffer */
	if (1 || (wrch && (nprot & PROT_WRITE))) c = wrch;
	else if (rdch && (nprot & PROT_READ)) c = rdch;
	if (c) {
		c->flags |= CHN_F_MAPPED;
		return atop(vtophys(c->buffer.buf + offset));
	}
	return -1;
}

