/*
 * Copyright (c) 1999 Cameron Grant <gandalf@vilnya.demon.co.uk>
 * Portions Copyright by Luigi Rizzo - 1997-99
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

#include <dev/sound/pcm/sound.h>

#include "feeder_if.h"

#define MIN_CHUNK_SIZE 		256	/* for uiomove etc. */
#define	DMA_ALIGN_THRESHOLD	4
#define	DMA_ALIGN_MASK		(~(DMA_ALIGN_THRESHOLD - 1))

#define	MIN(x, y) (((x) < (y))? (x) : (y))
#define CANCHANGE(c) (!(c->flags & CHN_F_TRIGGERED))

/*
#define DEB(x) x
*/

static int chn_buildfeeder(pcm_channel *c);

static void
chn_lockinit(pcm_channel *c)
{
	mtx_init(&c->mutex, c->name, MTX_RECURSE);
	mtx_enter(&c->mutex, MTX_DEF);
}

static void
chn_lockdestroy(pcm_channel *c)
{
	mtx_destroy(&c->mutex);
}

void
chn_lock(pcm_channel *c, const char *file, int line)
{
	_mtx_enter(&c->mutex, MTX_DEF, file, line);
}

void
chn_unlock(pcm_channel *c, const char *file, int line)
{
	_mtx_exit(&c->mutex, MTX_DEF, file, line);
}

void
chn_lockassert(pcm_channel *c, const char *file, int line)
{
	/* _mtx_assert(&c->mutex, MA_OWNED, file, line); */
}

static int
chn_polltrigger(pcm_channel *c)
{
	snd_dbuf *bs = &c->buffer2nd;
	unsigned amt, lim;

	CHN_LOCKASSERT(c);
	if (c->flags & CHN_F_MAPPED) {
		if (sndbuf_getprevblocks(bs) == 0)
			return 1;
		else
			return (sndbuf_getblocks(bs) > sndbuf_getprevblocks(bs))? 1 : 0;
	} else {
		amt = (c->direction == PCMDIR_PLAY)? sndbuf_getfree(bs) : sndbuf_getready(bs);
		lim = (c->flags & CHN_F_HAS_SIZE)? sndbuf_getblksz(bs) : 1;
		lim = 0;
		return (amt >= lim)? 1 : 0;
	}
	return 0;
}

static int
chn_pollreset(pcm_channel *c)
{
	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	sndbuf_updateprevtotal(bs);
	return 1;
}

static void
chn_wakeup(pcm_channel *c)
{
    	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	if (sndbuf_getsel(bs)->si_pid && chn_polltrigger(c))
		selwakeup(sndbuf_getsel(bs));
	wakeup(bs);
}

static int
chn_sleep(pcm_channel *c, char *str, int timeout)
{
    	snd_dbuf *bs = &c->buffer2nd;
	int ret;

	CHN_LOCKASSERT(c);
	ret = msleep(bs, &c->mutex, PRIBIO | PCATCH, str, timeout);

	return ret;
}

/*
 * chn_dmaupdate() tracks the status of a dma transfer,
 * updating pointers. It must be called at spltty().
 */

static unsigned int
chn_dmaupdate(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;
	unsigned int delta, old, hwptr, amt;

	CHN_LOCKASSERT(c);
	old = sndbuf_gethwptr(b);
	hwptr = chn_getptr(c);
	delta = (sndbuf_getsize(b) + hwptr - old) % sndbuf_getsize(b);
	sndbuf_sethwptr(b, hwptr);

	DEB(
	if (delta >= ((sndbuf_getsize(b) * 15) / 16)) {
		if (!(c->flags & (CHN_F_CLOSING | CHN_F_ABORTING)))
			device_printf(c->parent->dev, "hwptr went backwards %d -> %d\n", old, hwptr);
	}
	);

	if (c->direction == PCMDIR_PLAY) {
		amt = MIN(delta, sndbuf_getready(b));
		if (amt > 0)
			sndbuf_dispose(b, NULL, amt);
	} else {
		amt = MIN(delta, sndbuf_getfree(b));
		if (amt > 0)
		       sndbuf_acquire(b, NULL, amt);
	}

	return delta;
}

void
chn_wrupdate(pcm_channel *c)
{
	int ret;

	CHN_LOCKASSERT(c);
	KASSERT(c->direction == PCMDIR_PLAY, ("chn_wrupdate on bad channel"));

	if ((c->flags & CHN_F_MAPPED) || !(c->flags & CHN_F_TRIGGERED))
		return;
	chn_dmaupdate(c);
	ret = chn_wrfeed(c);
	/* tell the driver we've updated the primary buffer */
	chn_trigger(c, PCMTRIG_EMLDMAWR);
	if (ret)
		printf("chn_wrfeed: %d\n", ret);

}

int
chn_wrfeed(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;
	unsigned int ret, amt;

	CHN_LOCKASSERT(c);
    	DEB(
	if (c->flags & CHN_F_CLOSING) {
		sndbuf_dump(b, "b", 0x02);
		sndbuf_dump(bs, "bs", 0x02);
	})

	amt = sndbuf_getfree(b);
	ret = (amt > 0)? sndbuf_feed(bs, b, c, amt) : ENOSPC;
	if (ret == 0)
		chn_wakeup(c);

	return ret;
}

static void
chn_wrintr(pcm_channel *c)
{
	int ret;

	CHN_LOCKASSERT(c);
	/* update pointers in primary buffer */
	chn_dmaupdate(c);
	/* ...and feed from secondary to primary */
	ret = chn_wrfeed(c);
	/* tell the driver we've updated the primary buffer */
	chn_trigger(c, PCMTRIG_EMLDMAWR);
	if (ret)
		printf("chn_wrfeed: %d\n", ret);
}

/*
 * user write routine - uiomove data into secondary buffer, trigger if necessary
 * if blocking, sleep, rinse and repeat.
 *
 * called externally, so must handle locking
 */

int
chn_write(pcm_channel *c, struct uio *buf)
{
	int ret, timeout, newsize, count, sz;
	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	/*
	 * XXX Certain applications attempt to write larger size
	 * of pcm data than c->blocksize2nd without blocking,
	 * resulting partial write. Expand the block size so that
	 * the write operation avoids blocking.
	 */
	if ((c->flags & CHN_F_NBIO) && buf->uio_resid > sndbuf_getblksz(bs)) {
		DEB(device_printf(c->parent->dev, "broken app, nbio and tried to write %d bytes with fragsz %d\n",
			buf->uio_resid, sndbuf_getblksz(bs)));
		newsize = 16;
		while (newsize < min(buf->uio_resid, CHN_2NDBUFMAXSIZE / 2))
			newsize <<= 1;
		chn_setblocksize(c, sndbuf_getblkcnt(bs), newsize);
		DEB(device_printf(c->parent->dev, "frags reset to %d x %d\n", sndbuf_getblkcnt(bs), sndbuf_getblksz(bs)));
	}

	ret = 0;
	count = hz;
	while (!ret && (buf->uio_resid > 0) && (count > 0)) {
		sz = sndbuf_getfree(bs);
		if (sz == 0) {
			if (c->flags & CHN_F_NBIO)
				ret = EWOULDBLOCK;
			else {
				timeout = (hz * sndbuf_getblksz(bs)) / (sndbuf_getspd(bs) * sndbuf_getbps(bs));
				if (timeout < 1)
					timeout = 1;
	   			ret = chn_sleep(c, "pcmwr", timeout);
				if (ret == EWOULDBLOCK) {
					count -= timeout;
					ret = 0;
				} else if (ret == 0)
					count = hz;
			}
		} else {
			sz = MIN(sz, buf->uio_resid);
			KASSERT(sz > 0, ("confusion in chn_write"));
			/* printf("sz: %d\n", sz); */
			ret = sndbuf_uiomove(bs, buf, sz);
			if (ret == 0 && !(c->flags & CHN_F_TRIGGERED))
				chn_start(c, 0);
		}
	}
	/* printf("ret: %d left: %d\n", ret, buf->uio_resid); */

	if (count <= 0) {
		c->flags |= CHN_F_DEAD;
		device_printf(c->parent->dev, "play interrupt timeout, channel dead\n");
	}

	return ret;
}

static int
chn_rddump(pcm_channel *c, unsigned int cnt)
{
    	snd_dbuf *b = &c->buffer;

	CHN_LOCKASSERT(c);
	sndbuf_setxrun(b, sndbuf_getxrun(b) + cnt);
	return sndbuf_dispose(b, NULL, cnt);
}

/*
 * Feed new data from the read buffer. Can be called in the bottom half.
 * Hence must be called at spltty.
 */
int
chn_rdfeed(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;
	int ret;

	CHN_LOCKASSERT(c);
    	DEB(
	if (c->flags & CHN_F_CLOSING) {
		sndbuf_dump(b, "b", 0x02);
		sndbuf_dump(bs, "bs", 0x02);
	})

	ret = sndbuf_feed(b, bs, c, sndbuf_getblksz(b));

	if (ret == 0)
		chn_wakeup(c);

	return ret;
}

void
chn_rdupdate(pcm_channel *c)
{
	int ret;

	CHN_LOCKASSERT(c);
	KASSERT(c->direction == PCMDIR_REC, ("chn_rdupdate on bad channel"));

	if ((c->flags & CHN_F_MAPPED) || !(c->flags & CHN_F_TRIGGERED))
		return;
	chn_trigger(c, PCMTRIG_EMLDMARD);
	chn_dmaupdate(c);
	ret = chn_rdfeed(c);
	if (ret)
		printf("chn_rdfeed: %d\n", ret);

}

/* read interrupt routine. Must be called with interrupts blocked. */
static void
chn_rdintr(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
	int ret;

	CHN_LOCKASSERT(c);
	/* tell the driver to update the primary buffer if non-dma */
	chn_trigger(c, PCMTRIG_EMLDMARD);
	/* update pointers in primary buffer */
	chn_dmaupdate(c);
	/* ...and feed from primary to secondary */
	ret = chn_rdfeed(c);
	if (ret)
		chn_rddump(c, sndbuf_getblksz(b));
}

/*
 * user read routine - trigger if necessary, uiomove data from secondary buffer
 * if blocking, sleep, rinse and repeat.
 *
 * called externally, so must handle locking
 */

int
chn_read(pcm_channel *c, struct uio *buf)
{
	int		ret, timeout, sz, count;
	snd_dbuf       *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	if (!(c->flags & CHN_F_TRIGGERED))
		chn_start(c, 0);

	ret = 0;
	count = hz;
	while (!ret && (buf->uio_resid > 0) && (count > 0)) {
		sz = MIN(buf->uio_resid, sndbuf_getblksz(bs));

		if (sz <= sndbuf_getready(bs)) {
			ret = sndbuf_uiomove(bs, buf, sz);
		} else {
			if (c->flags & CHN_F_NBIO)
				ret = EWOULDBLOCK;
			else {
				timeout = (hz * sndbuf_getblksz(bs)) / (sndbuf_getspd(bs) * sndbuf_getbps(bs));
				if (timeout < 1)
					timeout = 1;
				CHN_UNLOCK(c);
	   			ret = chn_sleep(c, "pcmrd", timeout);
				CHN_LOCK(c);
				if (ret == EWOULDBLOCK) {
					count -= timeout;
					ret = 0;
				}
			}
		}
	}

	if (count <= 0) {
		c->flags |= CHN_F_DEAD;
		device_printf(c->parent->dev, "record interrupt timeout, channel dead\n");
	}

	return ret;
}

void
chn_intr(pcm_channel *c)
{
	CHN_LOCK(c);
	if (c->direction == PCMDIR_PLAY)
		chn_wrintr(c);
	else
		chn_rdintr(c);
	CHN_UNLOCK(c);
}

u_int32_t
chn_start(pcm_channel *c, int force)
{
	u_int32_t i;
	snd_dbuf *b = &c->buffer;
	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	/* if we're running, or if we're prevented from triggering, bail */
	if ((c->flags & CHN_F_TRIGGERED) || (c->flags & CHN_F_NOTRIGGER))
		return EINVAL;

	i = (c->direction == PCMDIR_PLAY)? sndbuf_getready(bs) : sndbuf_getfree(bs);
	if (force || (i >= sndbuf_getblksz(b))) {
		c->flags |= CHN_F_TRIGGERED;
		if (c->direction == PCMDIR_PLAY)
			chn_wrfeed(c);
		sndbuf_setrun(b, 1);
	    	chn_trigger(c, PCMTRIG_START);
		return 0;
	}

	return 0;
}

void
chn_resetbuf(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;
	snd_dbuf *bs = &c->buffer2nd;

	c->blocks = 0;
	sndbuf_reset(b);
	sndbuf_reset(bs);
}

/*
 * chn_sync waits until the space in the given channel goes above
 * a threshold. The threshold is checked against fl or rl respectively.
 * Assume that the condition can become true, do not check here...
 */
int
chn_sync(pcm_channel *c, int threshold)
{
    	u_long rdy;
    	int ret;
    	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
    	for (;;) {
		chn_wrupdate(c);
		rdy = (c->direction == PCMDIR_PLAY)? sndbuf_getfree(bs) : sndbuf_getready(bs);
		if (rdy <= threshold) {
	    		ret = chn_sleep(c, "pcmsyn", 1);
	    		if (ret == ERESTART || ret == EINTR) {
				DEB(printf("chn_sync: tsleep returns %d\n", ret));
				return -1;
	    		}
		} else
			break;
    	}
    	return 0;
}

/* called externally, handle locking */
int
chn_poll(pcm_channel *c, int ev, struct proc *p)
{
	snd_dbuf *bs = &c->buffer2nd;
	int ret;

	CHN_LOCKASSERT(c);
    	if (!(c->flags & CHN_F_MAPPED) && !(c->flags & CHN_F_TRIGGERED))
		chn_start(c, 1);
	ret = 0;
	if (chn_polltrigger(c) && chn_pollreset(c))
		ret = ev;
	else
		selrecord(p, sndbuf_getsel(bs));
	return ret;
}

/*
 * chn_abort terminates a running dma transfer.  it may sleep up to 200ms.
 * it returns the number of bytes that have not been transferred.
 *
 * called from: dsp_close, dsp_ioctl, with both buffers locked
 */
int
chn_abort(pcm_channel *c)
{
    	int missing = 0, cnt = 0;
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	if (!(c->flags & CHN_F_TRIGGERED))
		return 0;
	c->flags |= CHN_F_ABORTING;

	/* wait up to 200ms for the secondary buffer to empty */
	cnt = 10;
	while ((sndbuf_getready(bs) > 0) && (cnt-- > 0)) {
		chn_sleep(c, "pcmabr", hz / 50);
	}

	c->flags &= ~CHN_F_TRIGGERED;
	/* kill the channel */
	chn_trigger(c, PCMTRIG_ABORT);
	sndbuf_setrun(b, 0);
	chn_dmaupdate(c);
    	missing = sndbuf_getready(bs) + sndbuf_getready(b);

	c->flags &= ~CHN_F_ABORTING;
	return missing;
}

/*
 * this routine tries to flush the dma transfer. It is called
 * on a close. We immediately abort any read DMA
 * operation, and then wait for the play buffer to drain.
 *
 * called from: dsp_close
 */

int
chn_flush(pcm_channel *c)
{
    	int ret, count, resid, resid_p;
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCKASSERT(c);
	KASSERT(c->direction == PCMDIR_PLAY, ("chn_wrupdate on bad channel"));
    	DEB(printf("chn_flush c->flags 0x%08x\n", c->flags));
	if (!(c->flags & CHN_F_TRIGGERED))
		return 0;

	c->flags |= CHN_F_CLOSING;
	resid = sndbuf_getready(bs) + sndbuf_getready(b);
	resid_p = resid;
	count = 10;
	ret = 0;
	while ((count > 0) && (resid > sndbuf_getsize(b)) && (ret == 0)) {
		/* still pending output data. */
		ret = chn_sleep(c, "pcmflu", hz / 10);
		if (ret == EWOULDBLOCK)
			ret = 0;
		if (ret == 0) {
			resid = sndbuf_getready(bs) + sndbuf_getready(b);
			if (resid >= resid_p)
				count--;
			resid_p = resid;
		}
   	}
	if (count == 0)
		DEB(printf("chn_flush: timeout\n"));

	c->flags &= ~CHN_F_TRIGGERED;
	/* kill the channel */
	chn_trigger(c, PCMTRIG_ABORT);
	sndbuf_setrun(b, 0);

    	c->flags &= ~CHN_F_CLOSING;
    	return 0;
}

int
fmtvalid(u_int32_t fmt, u_int32_t *fmtlist)
{
	int i;

	for (i = 0; fmtlist[i]; i++)
		if (fmt == fmtlist[i])
			return 1;
	return 0;
}

int
chn_reset(pcm_channel *c, u_int32_t fmt)
{
	int hwspd, r = 0;

	CHN_LOCKASSERT(c);
	c->flags &= CHN_F_RESET;
	CHANNEL_RESET(c->methods, c->devinfo);
	if (fmt) {
		hwspd = DSP_DEFAULT_SPEED;
		RANGE(hwspd, chn_getcaps(c)->minspeed, chn_getcaps(c)->maxspeed);
		c->speed = hwspd;

		r = chn_setformat(c, fmt);
		if (r == 0)
			r = chn_setspeed(c, hwspd);
		if (r == 0)
			r = chn_setvolume(c, 100, 100);
	}
	r = chn_setblocksize(c, 0, 0);
	if (r == 0) {
		chn_resetbuf(c);
		CHANNEL_RESETDONE(c->methods, c->devinfo);
	}
	return r;
}

int
chn_init(pcm_channel *c, void *devinfo, int dir)
{
	struct feeder_class *fc;
	snd_dbuf *b = &c->buffer;
	snd_dbuf *bs = &c->buffer2nd;

	chn_lockinit(c);
	/* Initialize the hardware and DMA buffer first. */
	c->feeder = NULL;
	fc = feeder_getclass(NULL);
	if (fc == NULL)
		return EINVAL;
	if (chn_addfeeder(c, fc, NULL))
		return EINVAL;

	sndbuf_setup(bs, NULL, 0);
	if (sndbuf_init(b, c->name, "primary"))
		return ENOMEM;
	if (sndbuf_init(bs, c->name, "secondary")) {
		sndbuf_destroy(b);
		return ENOMEM;
	}
	c->flags = 0;
	c->feederflags = 0;
	c->devinfo = CHANNEL_INIT(c->methods, devinfo, b, c, dir);
	if (c->devinfo == NULL) {
		sndbuf_destroy(bs);
		sndbuf_destroy(b);
		return ENODEV;
	}
	if (sndbuf_getsize(b) == 0) {
		sndbuf_destroy(bs);
		sndbuf_destroy(b);
		return ENOMEM;
	}
	chn_setdir(c, dir);

	/* And the secondary buffer. */
	sndbuf_setfmt(b, AFMT_U8);
	sndbuf_setfmt(bs, AFMT_U8);
	CHN_UNLOCK(c);
	return 0;
}

int
chn_kill(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;

	CHN_LOCK(c);
	if (c->flags & CHN_F_TRIGGERED)
		chn_trigger(c, PCMTRIG_ABORT);
	while (chn_removefeeder(c) == 0);
	if (CHANNEL_FREE(c->methods, c->devinfo))
		sndbuf_free(&c->buffer);
	c->flags |= CHN_F_DEAD;
	sndbuf_destroy(bs);
	sndbuf_destroy(b);
	chn_lockdestroy(c);
	return 0;
}

int
chn_setdir(pcm_channel *c, int dir)
{
    	snd_dbuf *b = &c->buffer;
	int r;

	CHN_LOCKASSERT(c);
	c->direction = dir;
	r = CHANNEL_SETDIR(c->methods, c->devinfo, c->direction);
	if (!r && ISA_DMA(b))
		sndbuf_isadmasetdir(b, c->direction);
	return r;
}

int
chn_setvolume(pcm_channel *c, int left, int right)
{
	CHN_LOCKASSERT(c);
	/* could add a feeder for volume changing if channel returns -1 */
	c->volume = (left << 8) | right;
	return 0;
}

int
chn_setspeed(pcm_channel *c, int speed)
{
	pcm_feeder *f;
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;
	int r, delta;

	CHN_LOCKASSERT(c);
	DEB(printf("want speed %d, ", speed));
	if (speed <= 0)
		return EINVAL;
	if (CANCHANGE(c)) {
		r = 0;
		c->speed = speed;
		sndbuf_setspd(bs, speed);
		RANGE(speed, chn_getcaps(c)->minspeed, chn_getcaps(c)->maxspeed);
		sndbuf_setspd(b, speed);
		DEB(printf("try speed %d, ", sndbuf_getspd(b)));
		sndbuf_setspd(b, CHANNEL_SETSPEED(c->methods, c->devinfo, sndbuf_getspd(b)));
		DEB(printf("got speed %d, ", sndbuf_getspd(b)));

		delta = sndbuf_getspd(b) - sndbuf_getspd(bs);
		if (delta < 0)
			delta = -delta;

		c->feederflags &= ~(1 << FEEDER_RATE);
		if (delta > 500)
			c->feederflags |= 1 << FEEDER_RATE;
		else
			sndbuf_setspd(bs, sndbuf_getspd(b));

		r = chn_buildfeeder(c);
		DEB(printf("r = %d\n", r));
		if (r)
			goto out;

		r = chn_setblocksize(c, 0, 0);
		if (r)
			goto out;

		if (!(c->feederflags & (1 << FEEDER_RATE)))
			goto out;

		r = EINVAL;
		f = chn_findfeeder(c, FEEDER_RATE);
		DEB(printf("feedrate = %p\n", f));
		if (f == NULL)
			goto out;

		r = FEEDER_SET(f, FEEDRATE_SRC, sndbuf_getspd(bs));
		DEB(printf("feeder_set(FEEDRATE_SRC, %d) = %d\n", sndbuf_getspd(bs), r));
		if (r)
			goto out;

		r = FEEDER_SET(f, FEEDRATE_DST, sndbuf_getspd(b));
		DEB(printf("feeder_set(FEEDRATE_DST, %d) = %d\n", sndbuf_getspd(b), r));
out:
		return r;
	} else
		return EINVAL;
}

int
chn_setformat(pcm_channel *c, u_int32_t fmt)
{
	snd_dbuf *b = &c->buffer;
	snd_dbuf *bs = &c->buffer2nd;
	int r;
	u_int32_t hwfmt;

	CHN_LOCKASSERT(c);
	if (CANCHANGE(c)) {
		DEB(printf("want format %d\n", fmt));
		c->format = fmt;
		hwfmt = c->format;
		c->feederflags &= ~(1 << FEEDER_FMT);
		if (!fmtvalid(hwfmt, chn_getcaps(c)->fmtlist))
			c->feederflags |= 1 << FEEDER_FMT;
		r = chn_buildfeeder(c);
		if (r == 0) {
			hwfmt = c->feeder->desc->out;
			sndbuf_setfmt(b, hwfmt);
			sndbuf_setfmt(bs, fmt);
			chn_resetbuf(c);
			CHANNEL_SETFORMAT(c->methods, c->devinfo, hwfmt);
			r = chn_setspeed(c, c->speed);
		}
		return r;
	} else
		return EINVAL;
}

int
chn_setblocksize(pcm_channel *c, int blkcnt, int blksz)
{
	snd_dbuf *b = &c->buffer;
	snd_dbuf *bs = &c->buffer2nd;
	int bufsz, irqhz, tmp, ret;

	CHN_LOCKASSERT(c);
	if (!CANCHANGE(c) || (c->flags & CHN_F_MAPPED))
		return EINVAL;

	ret = 0;
	DEB(printf("%s(%d, %d)\n", __FUNCTION__, blkcnt, blksz));
	if (blksz == 0 || blksz == -1) {
		if (blksz == -1)
			c->flags &= ~CHN_F_HAS_SIZE;
		if (!(c->flags & CHN_F_HAS_SIZE)) {
			blksz = (sndbuf_getbps(bs) * sndbuf_getspd(bs)) / CHN_DEFAULT_HZ;
	      		tmp = 32;
			while (tmp <= blksz)
				tmp <<= 1;
			tmp >>= 1;
			blksz = tmp;

			RANGE(blksz, 16, CHN_2NDBUFMAXSIZE / 2);
			RANGE(blkcnt, 2, CHN_2NDBUFMAXSIZE / blksz);
			DEB(printf("%s: defaulting to (%d, %d)\n", __FUNCTION__, blkcnt, blksz));
		} else {
			blkcnt = sndbuf_getblkcnt(bs);
			blksz = sndbuf_getblksz(bs);
			DEB(printf("%s: updating (%d, %d)\n", __FUNCTION__, blkcnt, blksz));
		}
	} else {
		ret = EINVAL;
		if ((blksz < 16) || (blkcnt < 2) || (blkcnt * blksz > CHN_2NDBUFMAXSIZE))
			goto out;
		ret = 0;
		c->flags |= CHN_F_HAS_SIZE;
	}

	bufsz = blkcnt * blksz;

	ret = ENOMEM;
	if (sndbuf_remalloc(bs, blkcnt, blksz))
		goto out;
	ret = 0;

	/* adjust for different hw format/speed */
	irqhz = (sndbuf_getbps(bs) * sndbuf_getspd(bs)) / sndbuf_getblksz(bs);
	DEB(printf("%s: soft bps %d, spd %d, irqhz == %d\n", __FUNCTION__, sndbuf_getbps(bs), sndbuf_getspd(bs), irqhz));
	RANGE(irqhz, 16, 512);

	sndbuf_setblksz(b, (sndbuf_getbps(b) * sndbuf_getspd(b)) / irqhz);

	/* round down to 2^x */
	blksz = 32;
	while (blksz <= sndbuf_getblksz(b))
		blksz <<= 1;
	blksz >>= 1;

	/* round down to fit hw buffer size */
	RANGE(blksz, 16, sndbuf_getmaxsize(b) / 2);
	DEB(printf("%s: hard blksz requested %d (maxsize %d), ", __FUNCTION__, blksz, sndbuf_getmaxsize(b)));

	sndbuf_setblksz(b, CHANNEL_SETBLOCKSIZE(c->methods, c->devinfo, blksz));

	irqhz = (sndbuf_getbps(b) * sndbuf_getspd(b)) / sndbuf_getblksz(b);
	DEB(printf("got %d, irqhz == %d\n", sndbuf_getblksz(b), irqhz));

	chn_resetbuf(c);
out:
	return ret;
}

int
chn_trigger(pcm_channel *c, int go)
{
    	snd_dbuf *b = &c->buffer;
	int ret;

	CHN_LOCKASSERT(c);
	if (ISA_DMA(b) && (go == PCMTRIG_EMLDMAWR || go == PCMTRIG_EMLDMARD))
		sndbuf_isadmabounce(b);
	ret = CHANNEL_TRIGGER(c->methods, c->devinfo, go);

	return ret;
}

int
chn_getptr(pcm_channel *c)
{
	int hwptr;
	int a = (1 << c->align) - 1;

	CHN_LOCKASSERT(c);
	hwptr = (c->flags & CHN_F_TRIGGERED)? CHANNEL_GETPTR(c->methods, c->devinfo) : 0;
	/* don't allow unaligned values in the hwa ptr */
	hwptr &= ~a ; /* Apply channel align mask */
	hwptr &= DMA_ALIGN_MASK; /* Apply DMA align mask */
	return hwptr;
}

pcmchan_caps *
chn_getcaps(pcm_channel *c)
{
	CHN_LOCKASSERT(c);
	return CHANNEL_GETCAPS(c->methods, c->devinfo);
}

u_int32_t
chn_getformats(pcm_channel *c)
{
	u_int32_t *fmtlist, fmts;
	int i;

	fmtlist = chn_getcaps(c)->fmtlist;
	fmts = 0;
	for (i = 0; fmtlist[i]; i++)
		fmts |= fmtlist[i];

	return fmts;
}

static int
chn_buildfeeder(pcm_channel *c)
{
	struct feeder_class *fc;
	struct pcm_feederdesc desc;
	u_int32_t tmp[2], src, dst, type, flags;

	CHN_LOCKASSERT(c);
	while (chn_removefeeder(c) == 0);
	KASSERT((c->feeder == NULL), ("feeder chain not empty"));
	c->align = sndbuf_getalign(&c->buffer2nd);
	fc = feeder_getclass(NULL);
	if (fc == NULL)
		return EINVAL;
	if (chn_addfeeder(c, fc, NULL))
		return EINVAL;
	c->feeder->desc->out = c->format;

	flags = c->feederflags;
	src = c->feeder->desc->out;
	if ((c->flags & CHN_F_MAPPED) && (flags != 0))
		return EINVAL;
	DEB(printf("not mapped, flags %x, ", flags));
	for (type = FEEDER_RATE; type <= FEEDER_LAST; type++) {
		if (flags & (1 << type)) {
			desc.type = type;
			desc.in = 0;
			desc.out = 0;
			desc.flags = 0;
			DEB(printf("find feeder type %d, ", type));
			fc = feeder_getclass(&desc);
			DEB(printf("got %p\n", fc));
			if (fc == NULL)
				return EINVAL;
			dst = fc->desc->in;
			if (src != dst) {
 				DEB(printf("build fmtchain from %x to %x: ", src, dst));
				tmp[0] = dst;
				tmp[1] = 0;
				if (chn_fmtchain(c, tmp) == 0)
					return EINVAL;
 				DEB(printf("ok\n"));
			}
			if (chn_addfeeder(c, fc, fc->desc))
				return EINVAL;
			src = fc->desc->out;
			DEB(printf("added feeder %p, output %x\n", fc, src));
			dst = 0;
			flags &= ~(1 << type);
		}
	}
	if (!fmtvalid(src, chn_getcaps(c)->fmtlist)) {
		if (chn_fmtchain(c, chn_getcaps(c)->fmtlist) == 0)
			return EINVAL;
		DEB(printf("built fmtchain from %x to %x\n", src, c->feeder->desc->out));
		flags &= ~(1 << FEEDER_FMT);
	}
	return 0;
}



