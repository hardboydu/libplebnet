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

#define MIN_CHUNK_SIZE 		256	/* for uiomove etc. */
#define	DMA_ALIGN_THRESHOLD	4
#define	DMA_ALIGN_MASK		(~(DMA_ALIGN_THRESHOLD - 1))

#define ISA_DMA(b) (((b)->chan >= 0 && (b)->chan != 4 && (b)->chan < 8))
#define CANCHANGE(c) (!(c)->buffer.dl)

static void chn_clearbuf(pcm_channel *c, int length);
/*
 * SOUND OUTPUT

We use a circular buffer to store samples directed to the DAC.
The buffer is split into two variable-size regions, each identified
by an offset in the buffer (rp,fp) and a length (rl,fl):

      0          rp,rl        fp,fl    bufsize
      |__________>____________>________|
	  FREE   d   READY    w FREE

  READY: data written from the process and ready to be sent to the DAC;
  FREE: free part of the buffer.

Both regions can wrap around the end of the buffer.  At initialization,
READY is empty, FREE takes all the available space, and dma is
idle.  dl contains the length of the current DMA transfer, dl=0
means that the dma is idle.

The two boundaries (rp,fp) in the buffers are advanced by DMA [d]
and write() [w] operations. The first portion of the READY region
is used for DMA transfers. The transfer is started at rp and with
chunks of length dl. During DMA operations, dsp_wr_dmaupdate()
updates rp, rl and fl tracking the ISA DMA engine as the transfer
makes progress.
When a new block is written, fp advances and rl,fl are updated
accordingly.

The code works as follows: the user write routine dsp_write_body()
fills up the READY region with new data (reclaiming space from the
FREE region) and starts the write DMA engine if inactive.  When a
DMA transfer is complete, an interrupt causes dsp_wrintr() to be
called which extends the FREE region and possibly starts the next
transfer.

In some cases, the code tries to track the current status of DMA
operations by calling dsp_wr_dmaupdate() which changes rp, rl and fl.

The sistem tries to make all DMA transfers use the same size,
play_blocksize or rec_blocksize. The size is either selected by
the user, or computed by the system to correspond to about .25s of
audio. The blocksize must be within a range which is currently:

	min(5ms, 40 bytes) ... 1/2 buffer size.

When there aren't enough data (write) or space (read), a transfer
is started with a reduced size.

To reduce problems in case of overruns, the routine which fills up
the buffer should initialize (e.g. by repeating the last value) a
reasonably long area after the last block so that no noise is
produced on overruns.

  *
  */


/* XXX  this is broken: in the event a bounce buffer is used, data never
 * gets copied in or out of the real buffer.  fix requires mods to isa_dma.c
 * and possibly fixes to other autodma mode clients
 */
static void
chn_isadmabounce(pcm_channel *c)
{
	if (ISA_DMA(&c->buffer)) {
		/* tell isa_dma to bounce data in/out */
    	} else KASSERT(1, ("chn_isadmabounce called on invalid channel"));
}

static int
chn_polltrigger(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;
	unsigned lim = (c->flags & CHN_F_HAS_SIZE)? c->blocksize : 1;
	int trig = 0;

	if (c->flags & CHN_F_MAPPED)
		trig = ((b->int_count > b->prev_int_count) || b->first_poll);
	else trig = (((c->direction == PCMDIR_PLAY)? b->fl : b->rl) >= lim);
	return trig;
}

static int
chn_pollreset(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;

	if (c->flags & CHN_F_MAPPED) b->prev_int_count = b->int_count;
	b->first_poll = 0;
	return 1;
}

/*
 * chn_dmadone() updates pointers and wakes up any process waiting
 * on a select(). Must be called at spltty().
 */
static void
chn_dmadone(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;

	chn_dmaupdate(c);
	if (ISA_DMA(b)) chn_isadmabounce(c); /* sync bounce buffer */
	b->int_count++;
	if (b->sel.si_pid && chn_polltrigger(c)) selwakeup(&b->sel);
}

/*
 * chn_dmawakeup() wakes up any process sleeping. Separated from
 * chn_dma_done() so that wakeup occurs only when feed from a
 * secondary buffer to a DMA buffer takes place. Must be called
 * at spltty().
 */
static void
chn_dmawakeup(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;

	wakeup(b);
}

/*
 * chn_dmaupdate() tracks the status of a dma transfer,
 * updating pointers. It must be called at spltty().
 *
 * NOTE: when we are using auto dma in the device, rl might become
 * negative.
 */
DEB (static int chn_updatecount=0);

void
chn_dmaupdate(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;
	int delta, hwptr;
	DEB (int b_rl=b->rl; int b_fl=b->fl; int b_rp=b->rp; int b_fp=b->fp);

	hwptr = chn_getptr(c);
	if (c->direction == PCMDIR_PLAY) {
		delta = (b->bufsize + hwptr - b->rp) % b->bufsize;
		b->rp = hwptr;
		b->rl -= delta;
		b->fl += delta;
		DEB(if (b->rl<0) printf("OUCH!(%d) rl %d(%d) delta %d bufsize %d hwptr %d rp %d(%d)\n", chn_updatecount++, b->rl, b_rl, delta, b->bufsize, hwptr, b->rp, b_rp));
	} else {
		delta = (b->bufsize + hwptr - b->fp) % b->bufsize;
		b->fp = hwptr;
		b->rl += delta;
		b->fl -= delta;
		DEB(if (b->fl<0) printf("OUCH!(%d) fl %d(%d) delta %d bufsize %d hwptr %d fp %d(%d)\n", chn_updatecount++, b->fl, b_fl, delta, b->bufsize, hwptr, b->fp, b_fp));
	}
	b->total += delta;
}

/*
 * Check channel for underflow occured. Reset DMA buffer in case of
 * underflow, so that new data can go into the buffer. It must be
 * called at spltty().
 */
static void
chn_checkunderflow(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;

	if (b->underflow) {
		DEB(printf("Clear underflow condition\n"));
		/*
		 * The DMA keeps running even after underflow occurs.
		 * Hence the value returned by chn_getptr() here soon
		 * gets a lag when we get back to chn_write(). Although
		 * there are no easy and precise methods to figure out
		 * the lag, a quarter of b->bufsize would be a fair
		 * choice, provided that a DMA interrupt generates upon
		 * each transfer of a half b->bufsize.
		 */
		b->rp = chn_getptr(c);
		b->fp = (b->rp + b->bufsize / 4) % b->bufsize;
		b->rl = b->bufsize / 4;
		b->fl = b->bufsize - b->rl;
	  	b->underflow=0;
	} else {
		chn_dmaupdate(c);
	}
}

/*
 * Feeds new data to the write dma buffer. Can be called in the bottom half.
 * Hence must be called at spltty.
 */
static int
chn_wrfeed(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;
	int a, l, lacc;

	/* ensure we always have a whole number of samples */
	a = (1 << c->align) - 1;
	lacc = 0;
	/* Don't allow write unaligned data */
	while (bs->rl > a && b->fl > a) {
		/* ensure we always have a whole number of samples */
		l = min(min(bs->rl, bs->bufsize - bs->rp), min(b->fl, b->bufsize - b->fp)) & ~a;
		if (l == 0)
			return lacc;
		/* Move the samples, update the markers and pointers. */
		bcopy(bs->buf + bs->rp, b->buf + b->fp, l);
		bs->fl += l;
		bs->rl -= l;
		bs->rp = (bs->rp + l) % bs->bufsize;
		b->rl += l;
		b->fl -= l;
		b->fp = (b->fp + l) % b->bufsize;
		/* Accumulate the total bytes of the moved samples. */
		lacc += l;
	}

	return lacc;
}

/* Feeds new data to the secondary write buffer. */
static int
chn_wrfeed2nd(pcm_channel *c, struct uio *buf)
{
    	snd_dbuf *bs = &c->buffer2nd;
	int l, w, wacc;

	/* ensure we always have a whole number of samples */
	wacc = 0;
	while (buf->uio_resid > 0 && bs->fl > 0) {
		/*
		 * The size of the data to move here does not have to be
		 * aligned. We take care of it upon moving the data to a
		 * DMA buffer.
		 */
		l = min(bs->fl, bs->bufsize - bs->fp);
		/* Move the samples, update the markers and pointers. */
		w = c->feeder->feed(c->feeder, c, bs->buf + bs->fp, l, buf);
		if (w == 0) panic("no feed");
		bs->rl += w;
		bs->fl -= w;
		bs->fp = (bs->fp + w) % bs->bufsize;
		/* Accumulate the total bytes of the moved samples. */
		wacc += w;
	}

	return wacc;
}

/*
 * Write interrupt routine. Can be called from other places (e.g.
 * to start a paused transfer), but with interrupts disabled.
 */
static void
chn_wrintr(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	int start;

    	if (b->underflow && !(c->flags & CHN_F_MAPPED)) return; /* nothing new happened */
	if (b->dl) chn_dmadone(c);

    	/*
     	* start another dma operation only if have ready data in the buffer,
     	* there is no pending abort, have a full-duplex device, or have a
     	* half duplex device and there is no pending op on the other side.
     	*
     	* Force transfers to be aligned to a boundary of 4, which is
     	* needed when doing stereo and 16-bit.
     	*/
    	if (c->flags & CHN_F_MAPPED) start = c->flags & CHN_F_TRIGGERED;
    	else {
		/*
		 * Fill up the DMA buffer. This may result in making new
		 * free space in the secondary buffer, thus we can wake up
		 * the top half if feed occurs.
		 */
		if (chn_wrfeed(c) > 0) {
			chn_dmawakeup(c);
			while (chn_wrfeed(c) > 0);
		}
		start = (b->rl >= DMA_ALIGN_THRESHOLD && !(c->flags & CHN_F_ABORTING));
	}
    	if (start) {
		int l;
		chn_dmaupdate(c);
		if (c->flags & CHN_F_MAPPED) l = c->blocksize;
		else l = min(b->rl, c->blocksize) & DMA_ALIGN_MASK;
		/*
	 	 * check if we need to reprogram the DMA on the sound card.
	 	 * This happens if the size has changed from zero
	 	 */
		if (b->dl == 0) {
			/* Start DMA operation */
	    		b->dl = c->blocksize; /* record new transfer size */
	    		chn_trigger(c, PCMTRIG_START);
		}
		if (b->dl != l)
			/*
			 * we are near to underflow condition, so to prevent
			 * audio 'clicks' clear next b->fl bytes
			 */
			 chn_clearbuf(c, b->fl);
    	} else {
		/* cannot start a new dma transfer */
		DEB(printf("cannot start wr-dma flags 0x%08x rp %d rl %d\n",
			   c->flags, b->rp, b->rl));
		if (b->dl) { /* DMA was active */
	    		chn_trigger(c, PCMTRIG_STOP);
			b->dl = 0;
			b->underflow = 1; /* set underflow flag */
			chn_clearbuf(c, b->bufsize); /* and clear all DMA buffer */
		}
    	}
}

/*
 * user write routine
 *
 * advance the boundary between READY and FREE, fill the space with
 * uiomove(), and possibly start DMA. Do the above until the transfer
 * is complete.
 *
 * To minimize latency in case a pending DMA transfer is about to end,
 * we do the transfer in pieces of increasing sizes, extending the
 * READY area at every checkpoint. In the (necessary) assumption that
 * memory bandwidth is larger than the rate at which the dma consumes
 * data, we reduce the latency to something proportional to the length
 * of the first piece, while keeping the overhead low and being able
 * to feed the DMA with large blocks.
 */

int
chn_write(pcm_channel *c, struct uio *buf)
{
	int 		ret = 0, timeout;
	long		s;
	snd_dbuf       *b = &c->buffer;

	if (c->flags & CHN_F_WRITING) {
		/* This shouldn't happen and is actually silly
		 * - will never wake up, just timeout; why not sleep on b?
		 */
	       	tsleep(&s, PZERO, "pcmwrW", hz);
		return EBUSY;
	}
	c->flags |= CHN_F_WRITING;
	/*
	 * Fill up the secondary and DMA buffer.
	 * chn_wrfeed*() takes care of the alignment.
	 */
	s = spltty();
	/* Check for underflow before writing into the buffers. */
	chn_checkunderflow(c);
  	while (chn_wrfeed2nd(c, buf) > 0 || chn_wrfeed(c) > 0);
	/* Start playing if not yet. */
	if (b->rl && !b->dl) chn_wrintr(c);
   	if (!(c->flags & CHN_F_NBIO)) {
   		/* Wait until all samples are played in blocking mode. */
   		while (buf->uio_resid > 0) {
			splx(s);
			/* Wait for new free space to write new pcm samples. */
			timeout = (buf->uio_resid >= b->dl)? hz / 20 : 1;
   			ret = tsleep(b, PRIBIO | PCATCH, "pcmwr", timeout);
   			s = spltty();
 			if (ret == EINTR) chn_abort(c);
 			if (ret == EINTR || ret == ERESTART) break;
			/* Check for underflow before writing into the buffers. */
			chn_checkunderflow(c);
			/* Fill up the buffers with new pcm data. */
  			while (chn_wrfeed2nd(c, buf) > 0 || chn_wrfeed(c) > 0);
			/* Start playing if necessary. */
  			if (b->rl && !b->dl) chn_wrintr(c);
 		}
  	}
	c->flags &= ~CHN_F_WRITING;
   	splx(s);
	return (ret > 0)? ret : 0;
}

/*
 * SOUND INPUT
 *

The input part is similar to the output one, with a circular buffer
split in two regions, and boundaries advancing because of read() calls
[r] or dma operation [d].  At initialization, as for the write
routine, READY is empty, and FREE takes all the space.

      0          rp,rl        fp,fl    bufsize
      |__________>____________>________|
	  FREE   r   READY    d  FREE

Operation is as follows: upon user read (dsp_read_body()) a DMA read
is started if not already active (marked by b->dl > 0),
then as soon as data are available in the READY region they are
transferred to the user buffer, thus advancing the boundary between FREE
and READY. Upon interrupts, caused by a completion of a DMA transfer,
the READY region is extended and possibly a new transfer is started.

When necessary, dsp_rd_dmaupdate() is called to advance fp (and update
rl,fl accordingly). Upon user reads, rp is advanced and rl,fl are
updated accordingly.

The rules to choose the size of the new DMA area are similar to
the other case, with a preferred constant transfer size equal to
rec_blocksize, and fallback to smaller sizes if no space is available.

 */

/*
 * Feed new data from the read buffer. Can be called in the bottom half.
 * Hence must be called at spltty.
 */
static int
chn_rdfeed(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;
	int l, lacc;

	/* ensure we always have a whole number of samples */
	lacc = 0;
	while (bs->fl >= DMA_ALIGN_THRESHOLD && b->rl >= DMA_ALIGN_THRESHOLD) {
		l = min(min(bs->fl, bs->bufsize - bs->fp), min(b->rl, b->bufsize - b->rp)) & DMA_ALIGN_MASK;
		/* Move the samples, update the markers and pointers. */
		bcopy(b->buf + b->rp, bs->buf + bs->fp, l);
		bs->fl -= l;
		bs->rl += l;
		bs->fp = (bs->fp + l) % bs->bufsize;
		b->rl -= l;
		b->fl += l;
		b->rp = (b->rp + l) % b->bufsize;
		/* Accumulate the total bytes of the moved samples. */
		lacc += l;
	}

	return lacc;
}

/* Feeds new data from the secondary read buffer. */
static int
chn_rdfeed2nd(pcm_channel *c, struct uio *buf)
{
    	snd_dbuf *bs = &c->buffer2nd;
	int l, w, wacc;

	/* ensure we always have a whole number of samples */
	wacc = 0;
	while (buf->uio_resid > 0 && bs->rl > 0) {
		/*
		 * The size of the data to move here does not have to be
		 * aligned. We take care of it upon moving the data to a
		 * DMA buffer.
		 */
		l = min(bs->rl, bs->bufsize - bs->rp);
		/* Move the samples, update the markers and pointers. */
		w = c->feeder->feed(c->feeder, c, bs->buf + bs->rp, l, buf);
		if (w == 0) panic("no feed");
		bs->fl += w;
		bs->rl -= w;
		bs->rp = (bs->rp + w) % bs->bufsize;
		/* Accumulate the total bytes of the moved samples. */
		wacc += w;
	}

	return wacc;
}

/* read interrupt routine. Must be called with interrupts blocked. */
static void
chn_rdintr(pcm_channel *c)
{
    	snd_dbuf *b = &c->buffer;
    	int start;

    	if (b->dl) chn_dmadone(c);

    	DEB(printf("rdintr: start dl %d, rp:rl %d:%d, fp:fl %d:%d\n",
		b->dl, b->rp, b->rl, b->fp, b->fl));
    	/* Restart if have enough free space to absorb overruns */
    	if (c->flags & CHN_F_MAPPED) start = c->flags & CHN_F_TRIGGERED;
    	else {
		/*
		 * Suck up the DMA buffer. This may result in making new
		 * captured data in the secondary buffer, thus we can wake
		 * up the top half if feed occurs.
		 */
		if (chn_rdfeed(c) > 0) {
			chn_dmawakeup(c);
			while (chn_rdfeed(c) > 0);
		}
		start = (b->fl > 0x200 && !(c->flags & CHN_F_ABORTING));
	}
    	if (start) {
		int l = min(b->fl - 0x100, c->blocksize);
		if (c->flags & CHN_F_MAPPED) l = c->blocksize;
		l &= DMA_ALIGN_MASK ; /* realign sizes */

		DEB(printf("rdintr: dl %d -> %d\n", b->dl, l);)
		if (l != b->dl) {
	    		/* size has changed. Stop and restart */
	    		if (b->dl) {
	    			chn_trigger(c, PCMTRIG_STOP);
				chn_dmaupdate(c);
				l = min(b->fl - 0x100, c->blocksize);
				l &= DMA_ALIGN_MASK ; /* realign sizes */
	    		}
	    		b->dl = l;
	    		chn_trigger(c, PCMTRIG_START);
		}
    	} else {
		if (b->dl) { /* was active */
	    		b->dl = 0;
	    		chn_dmaupdate(c);
	    		chn_trigger(c, PCMTRIG_STOP);
		}
    	}
}

/*
 * body of user-read routine
 *
 * Start DMA if not active; wait for READY not empty.
 * Transfer data from READY region using uiomove(), advance boundary
 * between FREE and READY. Repeat until transfer is complete.
 *
 * To avoid excessive latency in freeing up space for the DMA
 * engine, transfers are done in blocks of increasing size, so that
 * the latency is proportional to the size of the smallest block, but
 * we have a low overhead and are able to feed the dma engine with
 * large blocks.
 *
 * NOTE: in the current version, read will not return more than
 * blocksize bytes at once (unless more are already available), to
 * avoid that requests using very large buffers block for too long.
 */

int
chn_read(pcm_channel *c, struct uio *buf)
{
	int		ret = 0, timeout, limit;
	long		s;
	snd_dbuf       *b = &c->buffer;

	if (c->flags & CHN_F_READING) {
		/* This shouldn't happen and is actually silly */
		tsleep(&s, PZERO, "pcmrdR", hz);
		return (EBUSY);
	}

  	s = spltty();
	c->flags |= CHN_F_READING;
	limit = buf->uio_resid - c->blocksize;
	if (limit < 0) limit = 0;
	/* Start capturing if not yet. */
  	if (!b->rl & !b->dl) chn_rdintr(c);
	/* Suck up the DMA and secondary buffers. */
 	while (chn_rdfeed(c) > 0 || chn_rdfeed2nd(c, buf) > 0);
  	if (!(c->flags & CHN_F_NBIO)) {
  		/* Wait until all samples are captured. */
  		while (buf->uio_resid > 0) {
			splx(s);
			/* Wait for new pcm samples. */
			timeout = (buf->uio_resid - limit >= b->dl)? hz / 20 : 1;
  			ret = tsleep(b, PRIBIO | PCATCH, "pcmrd", timeout);
  			s = spltty();
			if (ret == EINTR) chn_abort(c);
			if (ret == EINTR || ret == ERESTART) break;
			/* Start capturing if necessary. */
 			if (!b->rl & !b->dl) chn_rdintr(c);
			/* Suck up the DMA and secondary buffers. */
 			while (chn_rdfeed(c) > 0 || chn_rdfeed2nd(c, buf) > 0);
		}
	}
	c->flags &= ~CHN_F_READING;
  	splx(s);
	return ret;
}

void
chn_intr(pcm_channel *c)
{
	if (c->direction == PCMDIR_PLAY) chn_wrintr(c); else chn_rdintr(c);
}

static void
chn_dma_setmap(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	snd_dbuf *b = (snd_dbuf *)arg;

	if (bootverbose) {
		printf("pcm: setmap %lx, %lx; ", (unsigned long)segs->ds_addr,
		       (unsigned long)segs->ds_len);
		printf("%p -> %lx\n", b->buf, (unsigned long)vtophys(b->buf));
	}
}

int
chn_allocbuf(snd_dbuf *b, bus_dma_tag_t parent_dmat)
{
	if (bus_dmamem_alloc(parent_dmat, (void **)&b->buf,
			     BUS_DMA_NOWAIT, &b->dmamap)) return -1;
	if (bus_dmamap_load(parent_dmat, b->dmamap, b->buf,
			    b->bufsize, chn_dma_setmap, b, 0)) return -1;
	return 0;
}

static void
chn_clearbuf(pcm_channel *c, int length)
{
int i;
u_int16_t data, *p;

	snd_dbuf *b = &c->buffer;
	/* rely on length & DMA_ALIGN_MASK == 0 */
	length&=DMA_ALIGN_MASK;
	if (c->hwfmt & AFMT_SIGNED)	data = 0x00; else data = 0x80;
	if (c->hwfmt & AFMT_16BIT)	data <<= 8; else data |= data << 8;
	if (c->hwfmt & AFMT_BIGENDIAN)
		data = ((data >> 8) & 0x00ff) | ((data << 8) & 0xff00);
	for (i = b->fp, p=(u_int16_t*)(b->buf+b->fp) ; i < b->bufsize && length; i += 2, length-=2)
		*p++ = data;
	for (i = 0, p=(u_int16_t*)b->buf; i < b->bufsize && length; i += 2, length-=2)
		*p++ = data;

	return;
}

void
chn_resetbuf(pcm_channel *c)
{
	snd_dbuf *b = &c->buffer;
	snd_dbuf *bs = &c->buffer2nd;

	c->smegcnt = 0;
	c->buffer.sample_size = 1;
	c->buffer.sample_size <<= (c->hwfmt & AFMT_STEREO)? 1 : 0;
	c->buffer.sample_size <<= (c->hwfmt & AFMT_16BIT)? 1 : 0;
	b->rp = b->fp = 0;
	b->dl = b->rl = 0;
	b->fl = b->bufsize;
	chn_clearbuf(c, b->bufsize);
	b->prev_total = b->total = 0;
	b->prev_int_count = b->int_count = 0;
	b->first_poll = 1;
	b->underflow=0;
	bs->rp = bs->fp = 0;
	bs->dl = bs->rl = 0;
	bs->fl = bs->bufsize;
}

void
buf_isadma(snd_dbuf *b, int go)
{
	if (ISA_DMA(b)) {
        	if (go == PCMTRIG_START) {
			DEB(printf("buf 0x%p ISA DMA started\n", b));
			isa_dmastart(b->dir | B_RAW, b->buf,
					b->bufsize, b->chan);
		} else {
			DEB(printf("buf 0x%p ISA DMA stopped\n", b));
			isa_dmastop(b->chan);
			isa_dmadone(b->dir | B_RAW, b->buf, b->bufsize,
				    b->chan);
		}
    	} else KASSERT(1, ("buf_isadma called on invalid channel"));
}

int
buf_isadmaptr(snd_dbuf *b)
{
	if (ISA_DMA(b)) {
		int i = b->dl? isa_dmastatus(b->chan) : b->bufsize;
		if (i < 0) i = 0;
		return b->bufsize - i;
    	} else KASSERT(1, ("buf_isadmaptr called on invalid channel"));
	return -1;
}

/*
 * snd_sync waits until the space in the given channel goes above
 * a threshold. The threshold is checked against fl or rl respectively.
 * Assume that the condition can become true, do not check here...
 */
int
chn_sync(pcm_channel *c, int threshold)
{
    	u_long s, rdy;
    	int ret;
    	snd_dbuf *b = &c->buffer;

    	for (;;) {
		s = spltty();
		chn_dmaupdate(c);
		rdy = (c->direction == PCMDIR_PLAY)? b->fl : b->rl;
		if (rdy <= threshold) {
	    		ret = tsleep((caddr_t)b, PRIBIO | PCATCH, "pcmsyn", 1);
	    		splx(s);
	    		if (ret == ERESTART || ret == EINTR) {
				DEB(printf("chn_sync: tsleep returns %d\n", ret));
				return -1;
	    		}
		} else break;
    	}
    	splx(s);
    	return 0;
}

int
chn_poll(pcm_channel *c, int ev, struct proc *p)
{
	snd_dbuf *b = &c->buffer;
	u_long s = spltty();
	if (b->dl) chn_dmaupdate(c);
	splx(s);
	if (chn_polltrigger(c) && chn_pollreset(c)) return ev;
	else {
		selrecord(p, &b->sel);
		return 0;
	}
}

/*
 * chn_abort is a non-blocking function which aborts a pending
 * DMA transfer and flushes the buffers.
 * It returns the number of bytes that have not been transferred.
 */
int
chn_abort(pcm_channel *c)
{
    	int missing = 0, cnt = 0;
    	snd_dbuf *b = &c->buffer;
    	snd_dbuf *bs = &c->buffer2nd;

	if (!b->dl) return 0;
	c->flags |= CHN_F_ABORTING;
	while (!b->underflow && (b->dl > 0) && (cnt < 20)) {
		tsleep((caddr_t)b, PRIBIO, "pcmabr", hz / 20);
		cnt++;
	}
	chn_trigger(c, PCMTRIG_ABORT);
	b->dl = 0;
    	missing = b->rl + bs->rl;
    	return missing;
}

/*
 * this routine tries to flush the dma transfer. It is called
 * on a close. We immediately abort any read DMA
 * operation, and then wait for the play buffer to drain.
 */

int
chn_flush(pcm_channel *c)
{
    	int ret, count = 10;
    	snd_dbuf *b = &c->buffer;

    	DEB(printf("snd_flush c->flags 0x%08x\n", c->flags));
    	c->flags |= CHN_F_CLOSING;
    	if (c->direction != PCMDIR_PLAY) chn_abort(c);
    	else if (b->dl) while (!b->underflow) {
		/* still pending output data. */
		ret = tsleep((caddr_t)b, PRIBIO | PCATCH, "pcmflu", hz);
		DEB(chn_dmaupdate(c));
		DEB(printf("snd_sync: now rl : fl  %d : %d\n", b->rl, b->fl));
		if (ret == EINTR || ret == ERESTART) {
	    		DEB(printf("chn_flush: tsleep returns %d\n", ret));
	    		return -1;
		}
		if (ret && --count == 0) {
	    		DEB(printf("chn_flush: timeout flushing dbuf_out, cnt 0x%x flags 0x%x\n",\
			       b->rl, c->flags));
	    		break;
		}
    	}
    	c->flags &= ~CHN_F_CLOSING;
    	if (c->direction == PCMDIR_PLAY) chn_abort(c);
    	return 0;
}

int
chn_reset(pcm_channel *c)
{
	chn_abort(c);
	c->flags &= CHN_F_RESET;
	chn_resetbuf(c);
	c->flags |= CHN_F_INIT;
	return 0;
}

int
chn_reinit(pcm_channel *c)
{
	if ((c->flags & CHN_F_INIT) && CANCHANGE(c)) {
		chn_setformat(c, c->format);
		chn_setspeed(c, c->speed);
		chn_setblocksize(c, (c->flags & CHN_F_HAS_SIZE) ? c->blocksize : 0);
		chn_setvolume(c, (c->volume >> 8) & 0xff, c->volume & 0xff);
		c->flags &= ~CHN_F_INIT;
		return 1;
	}
	if (CANCHANGE(c) && !(c->flags & CHN_F_HAS_SIZE) )
		chn_setblocksize(c, 0); /* Apply new block size */
	return 0;
}

int
chn_init(pcm_channel *c, void *devinfo, int dir)
{
	snd_dbuf       *bs = &c->buffer2nd;

	c->flags = 0;
	c->feeder = &feeder_root;
	c->buffer.chan = -1;
	c->devinfo = c->init(devinfo, &c->buffer, c, dir);
	chn_setdir(c, dir);
	bs->bufsize = CHN_2NDBUFBLKSIZE * CHN_2NDBUFBLKNUM;
	bs->buf = malloc(bs->bufsize, M_DEVBUF, M_NOWAIT);
	bzero(bs->buf, bs->bufsize);
	bs->rl = bs->rp = bs->fp = 0;
	bs->fl = bs->bufsize;
	return 0;
}

int
chn_setdir(pcm_channel *c, int dir)
{
	c->direction = dir;
	if (ISA_DMA(&c->buffer))
		c->buffer.dir = (dir == PCMDIR_PLAY)? B_WRITE : B_READ;
	return c->setdir(c->devinfo, c->direction);
}

int
chn_setvolume(pcm_channel *c, int left, int right)
{
	/* could add a feeder for volume changing if channel returns -1 */
	if (CANCHANGE(c)) {
		return -1;
	}
	c->volume = (left << 8) | right;
	c->flags |= CHN_F_INIT;
	return 0;
}

int
chn_setspeed(pcm_channel *c, int speed)
{
	/* could add a feeder for rate conversion */
	if (CANCHANGE(c)) {
		c->speed = c->setspeed(c->devinfo, speed);
		return c->speed;
	}
	c->speed = speed;
	c->flags |= CHN_F_INIT;
	return 0;
}

int
chn_setformat(pcm_channel *c, u_int32_t fmt)
{
	if (CANCHANGE(c)) {
		c->hwfmt = c->format = fmt;
		c->hwfmt = chn_feedchain(c);
		chn_resetbuf(c);
		c->setformat(c->devinfo, c->hwfmt);
		return fmt;
	}
	c->format = fmt;
	c->flags |= CHN_F_INIT;
	return 0;
}

int
chn_setblocksize(pcm_channel *c, int blksz)
{
	if (CANCHANGE(c)) {
		c->flags &= ~CHN_F_HAS_SIZE;
		if (blksz >= 2) c->flags |= CHN_F_HAS_SIZE;
		if (blksz < 0) blksz = -blksz;
		if (blksz < 2) blksz = c->buffer.sample_size * (c->speed >> 2);
		RANGE(blksz, 1024, c->buffer.bufsize / 4);
		blksz &= DMA_ALIGN_MASK;
		c->blocksize = c->setblocksize(c->devinfo, blksz) & DMA_ALIGN_MASK;
		return c->blocksize;
	}
	c->blocksize = blksz;
	c->flags |= CHN_F_INIT;
	return 0;
}

int
chn_trigger(pcm_channel *c, int go)
{
	return c->trigger(c->devinfo, go);
}

int
chn_getptr(pcm_channel *c)
{
	int hwptr;
	int a = (1 << c->align) - 1;

	hwptr=c->getptr(c->devinfo);
	/* don't allow unaligned values in the hwa ptr */
	hwptr &= ~a ; /* Apply channel align mask */
	hwptr &= DMA_ALIGN_MASK; /* Apply DMA align mask */
	return hwptr;
}

pcmchan_caps *
chn_getcaps(pcm_channel *c)
{
	return c->getcaps(c->devinfo);
}
