/*
 * Copyright (c) 2003 Hidetoshi Shimokawa
 * Copyright (c) 1998-2002 Katsushi Kobayashi and Hidetoshi Shimokawa
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the acknowledgement as bellow:
 *
 *    This product includes software developed by K. Kobayashi and H. Shimokawa
 *
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * $FreeBSD$
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/mbuf.h>

#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/poll.h>

#include <sys/bus.h>
#include <machine/bus.h>

#include <sys/ioccom.h>

#include <dev/firewire/firewire.h>
#include <dev/firewire/firewirereg.h>
#include <dev/firewire/fwdma.h>
#include <dev/firewire/fwmem.h>
#include <dev/firewire/iec68113.h>

#define CDEV_MAJOR 127
#define	FWNODE_INVAL 0xffff

static	d_open_t	fw_open;
static	d_close_t	fw_close;
static	d_ioctl_t	fw_ioctl;
static	d_poll_t	fw_poll;
static	d_read_t	fw_read;	/* for Isochronous packet */
static	d_write_t	fw_write;
static	d_mmap_t	fw_mmap;

struct cdevsw firewire_cdevsw = 
{
#if __FreeBSD_version >= 500104
	.d_open =	fw_open,
	.d_close =	fw_close,
	.d_read =	fw_read,
	.d_write =	fw_write,
	.d_ioctl =	fw_ioctl,
	.d_poll =	fw_poll,
	.d_mmap =	fw_mmap,
	.d_name =	"fw",
	.d_maj =	CDEV_MAJOR,
	.d_flags =	D_MEM
#else
	fw_open, fw_close, fw_read, fw_write, fw_ioctl,
	fw_poll, fw_mmap, nostrategy, "fw", CDEV_MAJOR, nodump, nopsize, D_MEM
#endif
};

static int
fw_open (dev_t dev, int flags, int fmt, fw_proc *td)
{
	struct firewire_softc *sc;
	int unit = DEV2UNIT(dev);
	int sub = DEV2DMACH(dev);

	int err = 0;

	if (DEV_FWMEM(dev))
		return fwmem_open(dev, flags, fmt, td);

	sc = devclass_get_softc(firewire_devclass, unit);
	if(sc->fc->ir[sub]->flag & FWXFERQ_OPEN){
		err = EBUSY;
		return err;
	}
	if(sc->fc->it[sub]->flag & FWXFERQ_OPEN){
		err = EBUSY;
		return err;
	}
	if(sc->fc->ir[sub]->flag & FWXFERQ_MODEMASK){
		err = EBUSY;
		return err;
	}
/* Default is per packet mode */
	sc->fc->ir[sub]->flag |= FWXFERQ_OPEN;
	sc->fc->it[sub]->flag |= FWXFERQ_OPEN;
	return err;
}

static int
fw_close (dev_t dev, int flags, int fmt, fw_proc *td)
{
	struct firewire_softc *sc;
	int unit = DEV2UNIT(dev);
	int sub = DEV2DMACH(dev);
	struct fw_xfer *xfer;
	struct fw_bind *fwb;
	int err = 0;

	if (DEV_FWMEM(dev))
		return fwmem_close(dev, flags, fmt, td);

	sc = devclass_get_softc(firewire_devclass, unit);
	if(!(sc->fc->ir[sub]->flag & FWXFERQ_OPEN)){
		err = EINVAL;
		return err;
	}
	sc->fc->ir[sub]->flag &= ~FWXFERQ_OPEN;
	if(!(sc->fc->it[sub]->flag & FWXFERQ_OPEN)){
		err = EINVAL;
		return err;
	}
	sc->fc->it[sub]->flag &= ~FWXFERQ_OPEN;

	if(sc->fc->ir[sub]->flag & FWXFERQ_RUNNING){
		sc->fc->irx_disable(sc->fc, sub);
	}
	if(sc->fc->it[sub]->flag & FWXFERQ_RUNNING){
		sc->fc->it[sub]->flag &= ~FWXFERQ_RUNNING;
		sc->fc->itx_disable(sc->fc, sub);
	}
	if(sc->fc->ir[sub]->flag & FWXFERQ_EXTBUF){
		if (sc->fc->ir[sub]->buf != NULL)
			fwdma_free_multiseg(sc->fc->ir[sub]->buf);
		sc->fc->ir[sub]->buf = NULL;
		free(sc->fc->ir[sub]->bulkxfer, M_FW);
		sc->fc->ir[sub]->bulkxfer = NULL;
		sc->fc->ir[sub]->flag &= ~FWXFERQ_EXTBUF;
		sc->fc->ir[sub]->psize = PAGE_SIZE;
		sc->fc->ir[sub]->maxq = FWMAXQUEUE;
	}
	if(sc->fc->it[sub]->flag & FWXFERQ_EXTBUF){
		if (sc->fc->it[sub]->buf != NULL)
			fwdma_free_multiseg(sc->fc->it[sub]->buf);
		sc->fc->it[sub]->buf = NULL;
		free(sc->fc->it[sub]->bulkxfer, M_FW);
		sc->fc->it[sub]->bulkxfer = NULL;
		sc->fc->it[sub]->flag &= ~FWXFERQ_EXTBUF;
		sc->fc->it[sub]->psize = 0;
		sc->fc->it[sub]->maxq = FWMAXQUEUE;
	}
	for(xfer = STAILQ_FIRST(&sc->fc->ir[sub]->q);
		xfer != NULL; xfer = STAILQ_FIRST(&sc->fc->ir[sub]->q)){
		sc->fc->ir[sub]->queued--;
		STAILQ_REMOVE_HEAD(&sc->fc->ir[sub]->q, link);

		xfer->resp = 0;
		fw_xfer_done(xfer);
	}
	for(fwb = STAILQ_FIRST(&sc->fc->ir[sub]->binds); fwb != NULL;
		fwb = STAILQ_FIRST(&sc->fc->ir[sub]->binds)){
		STAILQ_REMOVE(&sc->fc->binds, fwb, fw_bind, fclist);
		STAILQ_REMOVE_HEAD(&sc->fc->ir[sub]->binds, chlist);
		free(fwb, M_FW);
	}
	sc->fc->ir[sub]->flag &= ~(FWXFERQ_MODEMASK | FWXFERQ_CHTAGMASK);
	sc->fc->it[sub]->flag &= ~(FWXFERQ_MODEMASK | FWXFERQ_CHTAGMASK);
	return err;
}

/*
 * read request.
 */
static int
fw_read (dev_t dev, struct uio *uio, int ioflag)
{
	struct firewire_softc *sc;
	struct fw_xferq *ir;
	struct fw_xfer *xfer;
	int err = 0, s, slept = 0;
	int unit = DEV2UNIT(dev);
	int sub = DEV2DMACH(dev);
	struct fw_pkt *fp;

	if (DEV_FWMEM(dev))
		return fwmem_read(dev, uio, ioflag);

	sc = devclass_get_softc(firewire_devclass, unit);

	ir = sc->fc->ir[sub];

readloop:
	xfer = STAILQ_FIRST(&ir->q);
	if (ir->stproc == NULL) {
		/* iso bulkxfer */
		ir->stproc = STAILQ_FIRST(&ir->stvalid);
		if (ir->stproc != NULL) {
			s = splfw();
			STAILQ_REMOVE_HEAD(&ir->stvalid, link);
			splx(s);
			ir->queued = 0;
		}
	}
	if (xfer == NULL && ir->stproc == NULL) {
		/* no data avaliable */
		if (slept == 0) {
			slept = 1;
			ir->flag |= FWXFERQ_WAKEUP;
			err = tsleep(ir, FWPRI, "fw_read", hz);
			ir->flag &= ~FWXFERQ_WAKEUP;
			if (err == 0)
				goto readloop;
		} else if (slept == 1)
			err = EIO;
		return err;
	} else if(xfer != NULL) {
		/* per packet mode or FWACT_CH bind?*/
		s = splfw();
		ir->queued --;
		STAILQ_REMOVE_HEAD(&ir->q, link);
		splx(s);
		fp = (struct fw_pkt *)xfer->recv.buf;
		if(sc->fc->irx_post != NULL)
			sc->fc->irx_post(sc->fc, fp->mode.ld);
		err = uiomove(xfer->recv.buf, xfer->recv.len, uio);
		/* XXX we should recycle this xfer */
		fw_xfer_free( xfer);
	} else if(ir->stproc != NULL) {
		/* iso bulkxfer */
		fp = (struct fw_pkt *)fwdma_v_addr(ir->buf, 
				ir->stproc->poffset + ir->queued);
		if(sc->fc->irx_post != NULL)
			sc->fc->irx_post(sc->fc, fp->mode.ld);
		if(fp->mode.stream.len == 0){
			err = EIO;
			return err;
		}
		err = uiomove((caddr_t)fp,
			fp->mode.stream.len + sizeof(u_int32_t), uio);
		ir->queued ++;
		if(ir->queued >= ir->bnpacket){
			s = splfw();
			STAILQ_INSERT_TAIL(&ir->stfree, ir->stproc, link);
			splx(s);
			sc->fc->irx_enable(sc->fc, sub);
			ir->stproc = NULL;
		}
		if (uio->uio_resid >= ir->psize) {
			slept = -1;
			goto readloop;
		}
	}
	return err;
}

static int
fw_write (dev_t dev, struct uio *uio, int ioflag)
{
	int err = 0;
	struct firewire_softc *sc;
	int unit = DEV2UNIT(dev);
	int sub = DEV2DMACH(dev);
	int s, slept = 0;
	struct fw_pkt *fp;
	struct firewire_comm *fc;
	struct fw_xferq *it;

	if (DEV_FWMEM(dev))
		return fwmem_write(dev, uio, ioflag);

	sc = devclass_get_softc(firewire_devclass, unit);
	fc = sc->fc;
	it = sc->fc->it[sub];
isoloop:
	if (it->stproc == NULL) {
		it->stproc = STAILQ_FIRST(&it->stfree);
		if (it->stproc != NULL) {
			s = splfw();
			STAILQ_REMOVE_HEAD(&it->stfree, link);
			splx(s);
			it->queued = 0;
		} else if (slept == 0) {
			slept = 1;
			err = sc->fc->itx_enable(sc->fc, sub);
			if (err)
				return err;
			err = tsleep(it, FWPRI, "fw_write", hz);
			if (err)
				return err;
			goto isoloop;
		} else {
			err = EIO;
			return err;
		}
	}
	fp = (struct fw_pkt *)fwdma_v_addr(it->buf,
			it->stproc->poffset + it->queued);
	err = uiomove((caddr_t)fp, sizeof(struct fw_isohdr), uio);
	err = uiomove((caddr_t)fp->mode.stream.payload,
				fp->mode.stream.len, uio);
	it->queued ++;
	if (it->queued >= it->bnpacket) {
		s = splfw();
		STAILQ_INSERT_TAIL(&it->stvalid, it->stproc, link);
		splx(s);
		it->stproc = NULL;
		err = sc->fc->itx_enable(sc->fc, sub);
	}
	if (uio->uio_resid >= sizeof(struct fw_isohdr)) {
		slept = 0;
		goto isoloop;
	}
	return err;
}

/*
 * ioctl support.
 */
int
fw_ioctl (dev_t dev, u_long cmd, caddr_t data, int flag, fw_proc *td)
{
	struct firewire_softc *sc;
	int unit = DEV2UNIT(dev);
	int sub = DEV2DMACH(dev);
	int s, i, len, err = 0;
	struct fw_device *fwdev;
	struct fw_bind *fwb;
	struct fw_xferq *ir, *it;
	struct fw_xfer *xfer;
	struct fw_pkt *fp;
	struct fw_devinfo *devinfo;

	struct fw_devlstreq *fwdevlst = (struct fw_devlstreq *)data;
	struct fw_asyreq *asyreq = (struct fw_asyreq *)data;
	struct fw_isochreq *ichreq = (struct fw_isochreq *)data;
	struct fw_isobufreq *ibufreq = (struct fw_isobufreq *)data;
	struct fw_asybindreq *bindreq = (struct fw_asybindreq *)data;
	struct fw_crom_buf *crom_buf = (struct fw_crom_buf *)data;

	if (DEV_FWMEM(dev))
		return fwmem_ioctl(dev, cmd, data, flag, td);

	sc = devclass_get_softc(firewire_devclass, unit);
	if (!data)
		return(EINVAL);

	switch (cmd) {
	case FW_STSTREAM:
		sc->fc->it[sub]->flag &= ~0xff;
		sc->fc->it[sub]->flag |= (0x3f & ichreq->ch);
		sc->fc->it[sub]->flag |= ((0x3 & ichreq->tag) << 6);
		err = 0;
		break;
	case FW_GTSTREAM:
		ichreq->ch = sc->fc->it[sub]->flag & 0x3f;
		ichreq->tag =(sc->fc->it[sub]->flag) >> 2 & 0x3;
		err = 0;
		break;
	case FW_SRSTREAM:
		sc->fc->ir[sub]->flag &= ~0xff;
		sc->fc->ir[sub]->flag |= (0x3f & ichreq->ch);
		sc->fc->ir[sub]->flag |= ((0x3 & ichreq->tag) << 6);
		err = sc->fc->irx_enable(sc->fc, sub);
		break;
	case FW_GRSTREAM:
		ichreq->ch = sc->fc->ir[sub]->flag & 0x3f;
		ichreq->tag =(sc->fc->ir[sub]->flag) >> 2 & 0x3;
		err = 0;
		break;
	case FW_SSTBUF:
		ir = sc->fc->ir[sub];
		it = sc->fc->it[sub];

		if(ir->flag & FWXFERQ_RUNNING || it->flag & FWXFERQ_RUNNING){
			return(EBUSY);
		}
		if((ir->flag & FWXFERQ_EXTBUF) || (it->flag & FWXFERQ_EXTBUF)){
			return(EBUSY);
		}
		if((ibufreq->rx.nchunk *
			ibufreq->rx.psize * ibufreq->rx.npacket) +
		   (ibufreq->tx.nchunk *
			ibufreq->tx.psize * ibufreq->tx.npacket) <= 0){
				return(EINVAL);
		}
		ir->bulkxfer
			= (struct fw_bulkxfer *)malloc(sizeof(struct fw_bulkxfer) * ibufreq->rx.nchunk, M_FW, M_WAITOK);
		if(ir->bulkxfer == NULL){
			return(ENOMEM);
		}
		it->bulkxfer
			= (struct fw_bulkxfer *)malloc(sizeof(struct fw_bulkxfer) * ibufreq->tx.nchunk, M_FW, M_WAITOK);
		if(it->bulkxfer == NULL){
			return(ENOMEM);
		}
		if (ibufreq->rx.psize > 0) {
			ibufreq->rx.psize = roundup2(ibufreq->rx.psize,
							sizeof(u_int32_t));
			ir->buf = fwdma_malloc_multiseg(
				sc->fc, sizeof(u_int32_t),
				ibufreq->rx.psize,
				ibufreq->rx.nchunk * ibufreq->rx.npacket,
				BUS_DMA_WAITOK);

			if(ir->buf == NULL){
				free(ir->bulkxfer, M_FW);
				free(it->bulkxfer, M_FW);
				ir->bulkxfer = NULL;
				it->bulkxfer = NULL;
				it->buf = NULL;
				return(ENOMEM);
			}
		}
		if (ibufreq->tx.psize > 0) {
			ibufreq->tx.psize = roundup2(ibufreq->tx.psize,
							sizeof(u_int32_t));
			it->buf = fwdma_malloc_multiseg(
				sc->fc, sizeof(u_int32_t),
				ibufreq->tx.psize,
				ibufreq->tx.nchunk * ibufreq->tx.npacket,
				BUS_DMA_WAITOK);

			if(it->buf == NULL){
				free(ir->bulkxfer, M_FW);
				free(it->bulkxfer, M_FW);
				fwdma_free_multiseg(ir->buf);
				ir->bulkxfer = NULL;
				it->bulkxfer = NULL;
				it->buf = NULL;
				return(ENOMEM);
			}
		}

		ir->bnchunk = ibufreq->rx.nchunk;
		ir->bnpacket = ibufreq->rx.npacket;
		ir->psize = (ibufreq->rx.psize + 3) & ~3;
		ir->queued = 0;

		it->bnchunk = ibufreq->tx.nchunk;
		it->bnpacket = ibufreq->tx.npacket;
		it->psize = (ibufreq->tx.psize + 3) & ~3;
		it->queued = 0;

		STAILQ_INIT(&ir->stvalid);
		STAILQ_INIT(&ir->stfree);
		STAILQ_INIT(&ir->stdma);
		ir->stproc = NULL;

		STAILQ_INIT(&it->stvalid);
		STAILQ_INIT(&it->stfree);
		STAILQ_INIT(&it->stdma);
		it->stproc = NULL;

		for(i = 0 ; i < sc->fc->ir[sub]->bnchunk; i++){
			ir->bulkxfer[i].poffset = i * ir->bnpacket;
			ir->bulkxfer[i].mbuf = NULL;
			STAILQ_INSERT_TAIL(&ir->stfree,
					&ir->bulkxfer[i], link);
		}
		for(i = 0 ; i < sc->fc->it[sub]->bnchunk; i++){
			it->bulkxfer[i].poffset = i * it->bnpacket;
			it->bulkxfer[i].mbuf = NULL;
			STAILQ_INSERT_TAIL(&it->stfree,
					&it->bulkxfer[i], link);
		}
		ir->flag &= ~FWXFERQ_MODEMASK;
		ir->flag |= FWXFERQ_STREAM;
		ir->flag |= FWXFERQ_EXTBUF;

		it->flag &= ~FWXFERQ_MODEMASK;
		it->flag |= FWXFERQ_STREAM;
		it->flag |= FWXFERQ_EXTBUF;
		err = 0;
		break;
	case FW_GSTBUF:
		ibufreq->rx.nchunk = sc->fc->ir[sub]->bnchunk;
		ibufreq->rx.npacket = sc->fc->ir[sub]->bnpacket;
		ibufreq->rx.psize = sc->fc->ir[sub]->psize;

		ibufreq->tx.nchunk = sc->fc->it[sub]->bnchunk;
		ibufreq->tx.npacket = sc->fc->it[sub]->bnpacket;
		ibufreq->tx.psize = sc->fc->it[sub]->psize;
		break;
	case FW_ASYREQ:
		xfer = fw_xfer_alloc_buf(M_FWXFER, asyreq->req.len,
							PAGE_SIZE /* XXX */);
		if(xfer == NULL){
			err = ENOMEM;
			return err;
		}
		fp = &asyreq->pkt;
		switch (asyreq->req.type) {
		case FWASREQNODE:
			xfer->dst = fp->mode.hdr.dst;
			break;
		case FWASREQEUI:
			fwdev = fw_noderesolve_eui64(sc->fc,
						&asyreq->req.dst.eui);
			if (fwdev == NULL) {
				device_printf(sc->fc->bdev,
					"cannot find node\n");
				err = EINVAL;
				goto error;
			}
			xfer->dst = FWLOCALBUS | fwdev->dst;
			fp->mode.hdr.dst = xfer->dst;
			break;
		case FWASRESTL:
			/* XXX what's this? */
			break;
		case FWASREQSTREAM:
			/* nothing to do */
			break;
		}
		xfer->spd = asyreq->req.sped;
		bcopy(fp, xfer->send.buf, xfer->send.len);
		xfer->act.hand = fw_asy_callback;
		err = fw_asyreq(sc->fc, sub, xfer);
		if(err){
			fw_xfer_free( xfer);
			return err;
		}
		err = tsleep(xfer, FWPRI, "asyreq", hz);
		if(err == 0){
			if(asyreq->req.len >= xfer->recv.len){
				asyreq->req.len = xfer->recv.len;
			}else{
				err = EINVAL;
			}
			bcopy(xfer->recv.buf, fp, asyreq->req.len);
		}
error:
		fw_xfer_free( xfer);
		break;
	case FW_IBUSRST:
		sc->fc->ibr(sc->fc);
		break;
	case FW_CBINDADDR:
		fwb = fw_bindlookup(sc->fc,
				bindreq->start.hi, bindreq->start.lo);
		if(fwb == NULL){
			err = EINVAL;
			break;
		}
		STAILQ_REMOVE(&sc->fc->binds, fwb, fw_bind, fclist);
		STAILQ_REMOVE(&sc->fc->ir[sub]->binds, fwb, fw_bind, chlist);
		free(fwb, M_FW);
		break;
	case FW_SBINDADDR:
		if(bindreq->len <= 0 ){
			err = EINVAL;
			break;
		}
		if(bindreq->start.hi > 0xffff ){
			err = EINVAL;
			break;
		}
		fwb = (struct fw_bind *)malloc(sizeof (struct fw_bind), M_FW, M_NOWAIT);
		if(fwb == NULL){
			err = ENOMEM;
			break;
		}
		fwb->start_hi = bindreq->start.hi;
		fwb->start_lo = bindreq->start.lo;
		fwb->addrlen = bindreq->len;
		fwb->sub = sub;
		fwb->act_type = FWACT_CH;

		xfer = fw_xfer_alloc(M_FWXFER);
		if(xfer == NULL){
			err = ENOMEM;
			return err;
		}
		xfer->fc = sc->fc;

		s = splfw();
		/* XXX broken. need multiple xfer */
		STAILQ_INIT(&fwb->xferlist);
		STAILQ_INSERT_TAIL(&fwb->xferlist, xfer, link);
		splx(s);
		err = fw_bindadd(sc->fc, fwb);
		break;
	case FW_GDEVLST:
		i = len = 1;
		/* myself */
		devinfo = &fwdevlst->dev[0];
		devinfo->dst = sc->fc->nodeid;
		devinfo->status = 0;	/* XXX */
		devinfo->eui.hi = sc->fc->eui.hi;
		devinfo->eui.lo = sc->fc->eui.lo;
		STAILQ_FOREACH(fwdev, &sc->fc->devices, link) {
			if(len < FW_MAX_DEVLST){
				devinfo = &fwdevlst->dev[len++];
				devinfo->dst = fwdev->dst;
				devinfo->status = 
					(fwdev->status == FWDEVINVAL)?0:1;
				devinfo->eui.hi = fwdev->eui.hi;
				devinfo->eui.lo = fwdev->eui.lo;
			}
			i++;
		}
		fwdevlst->n = i;
		fwdevlst->info_len = len;
		break;
	case FW_GTPMAP:
		bcopy(sc->fc->topology_map, data,
				(sc->fc->topology_map->crc_len + 1) * 4);
		break;
	case FW_GCROM:
		STAILQ_FOREACH(fwdev, &sc->fc->devices, link)
			if (FW_EUI64_EQUAL(fwdev->eui, crom_buf->eui))
				break;
		if (fwdev == NULL) {
			err = FWNODE_INVAL;
			break;
		}
		if (fwdev->rommax < CSRROMOFF)
			len = 0;
		else
			len = fwdev->rommax - CSRROMOFF + 4;
		if (crom_buf->len < len)
			len = crom_buf->len;
		else
			crom_buf->len = len;
		err = copyout(&fwdev->csrrom[0], crom_buf->ptr, len);
		break;
	default:
		sc->fc->ioctl (dev, cmd, data, flag, td);
		break;
	}
	return err;
}
int
fw_poll(dev_t dev, int events, fw_proc *td)
{
	int revents;
	int tmp;
	int unit = DEV2UNIT(dev);
	int sub = DEV2DMACH(dev);
	struct firewire_softc *sc;

	if (DEV_FWMEM(dev))
		return fwmem_poll(dev, events, td);

	sc = devclass_get_softc(firewire_devclass, unit);
	revents = 0;
	tmp = POLLIN | POLLRDNORM;
	if (events & tmp) {
		if (STAILQ_FIRST(&sc->fc->ir[sub]->q) != NULL)
			revents |= tmp;
		else
			selrecord(td, &sc->fc->ir[sub]->rsel);
	}
	tmp = POLLOUT | POLLWRNORM;
	if (events & tmp) {
		/* XXX should be fixed */	
		revents |= tmp;
	}

	return revents;
}

static int
#if __FreeBSD_version < 500102
fw_mmap (dev_t dev, vm_offset_t offset, int nproto)
#else
fw_mmap (dev_t dev, vm_offset_t offset, vm_paddr_t *paddr, int nproto)
#endif
{  
	struct firewire_softc *fc;
	int unit = DEV2UNIT(dev);

	if (DEV_FWMEM(dev))
#if __FreeBSD_version < 500102
		return fwmem_mmap(dev, offset, nproto);
#else
		return fwmem_mmap(dev, offset, paddr, nproto);
#endif

	fc = devclass_get_softc(firewire_devclass, unit);

	return EINVAL;
}
