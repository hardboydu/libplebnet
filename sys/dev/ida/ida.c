/*-
 * Copyright (c) 1999 Jonathan Lemon
 * All rights reserved.
 *
 # Derived from the original IDA Compaq RAID driver, which is
 * Copyright (c) 1996, 1997, 1998, 1999
 *    Mark Dawson and David James. All rights reserved.
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
 *	$Id$
 */

/*
 * Generic driver for Compaq SMART RAID adapters.
 *
 * Specific probe routines are in:
 *	pci/ida_pci.c		
 *	i386/eisa/ida_eisa.c
 */

#include <pci.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>

#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/devicestat.h>

#if NPCI > 0
#include <machine/bus_memio.h>
#endif
#include <machine/bus_pio.h>
#include <machine/bus.h>
#include <machine/clock.h>
#include <sys/rman.h>

#include <dev/ida/idareg.h>
#include <dev/ida/idavar.h>

#define ida_inl(ida, port) \
	bus_space_read_4((ida)->tag, (ida)->bsh, port)

#define ida_outl(ida, port, val) \
	bus_space_write_4((ida)->tag, (ida)->bsh, port, val)

/* prototypes */
static void ida_alloc_qcb(struct ida_softc *ida);
static void ida_construct_qcb(struct ida_softc *ida);
static void ida_start(struct ida_softc *ida);
static void ida_done(struct ida_softc *ida, struct ida_qcb *qcb);

void
ida_free(struct ida_softc *ida)
{

	/*
 	 * still need to call bus_dmamap_destroy() for each map created
	 * in ida_alloc_qcb().
	 */

	if (ida->hwqcb_busaddr)
		bus_dmamap_unload(ida->hwqcb_dmat, ida->hwqcb_dmamap);

	if (ida->hwqcbs)
		bus_dmamem_free(ida->hwqcb_dmat, ida->hwqcbs,
		    ida->hwqcb_dmamap);

	if (ida->buffer_dmat)
		bus_dma_tag_destroy(ida->buffer_dmat);

	if (ida->hwqcb_dmat)
		bus_dma_tag_destroy(ida->hwqcb_dmat);

	if (ida->qcbs != NULL)
		free(ida->qcbs, M_DEVBUF);

	if (ida->ih != NULL)
                bus_teardown_intr(ida->dev, ida->irq, ida->ih);

	if (ida->irq != NULL)
		bus_release_resource(ida->dev, ida->irq_res_type,
		    0, ida->irq);

	if (ida->parent_dmat != NULL)
		bus_dma_tag_destroy(ida->parent_dmat);

	if (ida->regs != NULL)
		bus_release_resource(ida->dev, ida->regs_res_type,
		    ida->regs_res_id, ida->regs);
}

/*
 * record bus address from bus_dmamap_load
 */
static void
ida_dma_map_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error) 
{
        bus_addr_t *baddr;

        baddr = (bus_addr_t *)arg;
        *baddr = segs->ds_addr;
}

static __inline struct ida_qcb *
ida_get_qcb(struct ida_softc *ida)
{
	struct ida_qcb *qcb;

	if ((qcb = SLIST_FIRST(&ida->free_qcbs)) != NULL) {
		SLIST_REMOVE_HEAD(&ida->free_qcbs, link.sle);
	} else {
		ida_alloc_qcb(ida);
		if ((qcb = SLIST_FIRST(&ida->free_qcbs)) != NULL)
			SLIST_REMOVE_HEAD(&ida->free_qcbs, link.sle);
	}
	return (qcb);
}

/*
 * XXX
 * since we allocate all QCB space up front during initialization, then
 * why bother with this routine?
 */
static void
ida_alloc_qcb(struct ida_softc *ida)
{
	struct ida_qcb *qcb;
	int error;

	if (ida->num_qcbs >= IDA_QCB_MAX)
		return;

	qcb = &ida->qcbs[ida->num_qcbs];

	error = bus_dmamap_create(ida->buffer_dmat, /*flags*/0, &qcb->dmamap);
	if (error != 0)
		return;

	qcb->flags = QCB_FREE;
	qcb->hwqcb = &ida->hwqcbs[ida->num_qcbs];
	qcb->hwqcb->qcb = qcb;
	SLIST_INSERT_HEAD(&ida->free_qcbs, qcb, link.sle);
	ida->num_qcbs++;
}

int
ida_init(struct ida_softc *ida)
{
	int error;

	ida->unit = device_get_unit(ida->dev);
	ida->tag = rman_get_bustag(ida->regs);
	ida->bsh = rman_get_bushandle(ida->regs);

	SLIST_INIT(&ida->free_qcbs);
	STAILQ_INIT(&ida->qcb_queue);
        bufq_init(&ida->buf_queue);

	ida->qcbs = (struct ida_qcb *)
	    malloc(IDA_QCB_MAX * sizeof(struct ida_qcb), M_DEVBUF, M_NOWAIT);
	if (ida->qcbs == NULL)
		return (ENOMEM);
	bzero(ida->qcbs, IDA_QCB_MAX * sizeof(struct ida_qcb));

	/*
	 * Create our DMA tags
	 */

	/* DMA tag for our hardware QCB structures */
	error = bus_dma_tag_create(ida->parent_dmat,
	    /*alignment*/0, /*boundary*/0,
	    /*lowaddr*/BUS_SPACE_MAXADDR, /*highaddr*/BUS_SPACE_MAXADDR,
	    /*filter*/NULL, /*filterarg*/NULL,
	    IDA_QCB_MAX * sizeof(struct ida_hardware_qcb),
	    /*nsegments*/1, /*maxsegsz*/BUS_SPACE_MAXSIZE_32BIT,
	    /*flags*/0, &ida->hwqcb_dmat);
	if (error)
                return (ENOMEM);

	/* DMA tag for mapping buffers into device space */
	error = bus_dma_tag_create(ida->parent_dmat,
	    /*alignment*/0, /*boundary*/0,
	    /*lowaddr*/BUS_SPACE_MAXADDR, /*highaddr*/BUS_SPACE_MAXADDR,
	    /*filter*/NULL, /*filterarg*/NULL,
	    /*maxsize*/MAXBSIZE, /*nsegments*/IDA_NSEG,
	    /*maxsegsz*/BUS_SPACE_MAXSIZE_32BIT, /*flags*/0, &ida->buffer_dmat);
	if (error)
                return (ENOMEM);

        /* Allocation of hardware QCBs */
	/* XXX allocation is rounded to hardware page size */
	error = bus_dmamem_alloc(ida->hwqcb_dmat,
	    (void **)&ida->hwqcbs, BUS_DMA_NOWAIT, &ida->hwqcb_dmamap);
	if (error)
                return (ENOMEM);

        /* And permanently map them in */
        bus_dmamap_load(ida->hwqcb_dmat, ida->hwqcb_dmamap,
	    ida->hwqcbs, IDA_QCB_MAX * sizeof(struct ida_hardware_qcb),
	    ida_dma_map_cb, &ida->hwqcb_busaddr, /*flags*/0);

	bzero(ida->hwqcbs, IDA_QCB_MAX * sizeof(struct ida_hardware_qcb));

	ida_alloc_qcb(ida);		/* allocate an initial qcb */

	return (0);
}

void
ida_attach(struct ida_softc *ida)
{
	struct ida_controller_info cinfo;
	int error, i;

	ida_outl(ida, R_INT_MASK, INT_DISABLE);

	error = ida_command(ida, CMD_GET_CTRL_INFO, &cinfo, sizeof(cinfo),
	    IDA_CONTROLLER, DMA_DATA_IN);
	if (error) {
		device_printf(ida->dev, "CMD_GET_CTRL_INFO failed.\n");
		return;
	}

	device_printf(ida->dev, "drives=%d firm_rev=%c%c%c%c\n",
	    cinfo.num_drvs, cinfo.firm_rev[0], cinfo.firm_rev[1],
	    cinfo.firm_rev[2], cinfo.firm_rev[3]);

	ida->num_drives = cinfo.num_drvs;

	for (i = 0; i < ida->num_drives; i++)
		device_add_child(ida->dev, "id", i, NULL);

	bus_generic_attach(ida->dev);

	ida_outl(ida, R_INT_MASK, INT_ENABLE);
}

static void
ida_setup_dmamap(void *arg, bus_dma_segment_t *segs, int nsegments, int error)
{
	struct ida_hardware_qcb *hwqcb = (struct ida_hardware_qcb *)arg;
	int i;

	hwqcb->hdr.size = (sizeof(struct ida_req) + 
	    sizeof(struct ida_sgb) * IDA_NSEG) >> 2;

	for (i = 0; i < nsegments; i++) {
		hwqcb->seg[i].addr = segs[i].ds_addr;
		hwqcb->seg[i].length = segs[i].ds_len;
	}
	hwqcb->req.sgcount = nsegments;
}

int
ida_command(struct ida_softc *ida, int command, void *data, int datasize,
	int drive, int flags)
{
	struct ida_hardware_qcb *hwqcb;
	struct ida_qcb *qcb;
	bus_dmasync_op_t op;
	int s;

	s = splbio();
	qcb = ida_get_qcb(ida);
	splx(s);

	if (qcb == NULL) {
		printf("ida_command: out of QCBs");
		return (1);
	}

	hwqcb = qcb->hwqcb;
	bzero(hwqcb, sizeof(struct ida_hdr) + sizeof(struct ida_req));

	bus_dmamap_load(ida->buffer_dmat, qcb->dmamap,
	    (void *)data, datasize, ida_setup_dmamap, hwqcb, 0);
	op = qcb->flags & DMA_DATA_IN ?
	    BUS_DMASYNC_PREREAD : BUS_DMASYNC_PREWRITE;
	bus_dmamap_sync(ida->buffer_dmat, qcb->dmamap, op);

	hwqcb->hdr.drive = drive;		/* XXX */
	hwqcb->req.bcount = howmany(datasize, DEV_BSIZE);
	hwqcb->req.command = command;

	qcb->flags = flags | IDA_COMMAND;

	s = splbio();
	STAILQ_INSERT_TAIL(&ida->qcb_queue, qcb, link.stqe);
	ida_start(ida);
	ida_wait(ida, qcb, 500);
	splx(s);

	/* XXX should have status returned here? */
	/* XXX have "status pointer" area in QCB? */

	return (0);
}

void
ida_submit_buf(struct ida_softc *ida, struct buf *bp)
{
        bufq_insert_tail(&ida->buf_queue, bp);
        ida_construct_qcb(ida);
	ida_start(ida);
}

static void
ida_construct_qcb(struct ida_softc *ida)
{
	struct ida_hardware_qcb *hwqcb;
	struct ida_qcb *qcb;
	bus_dmasync_op_t op;
	struct buf *bp;

	bp = bufq_first(&ida->buf_queue);
	if (bp == NULL)
		return;				/* no more buffers */

	qcb = ida_get_qcb(ida);
	if (qcb == NULL)
		return;				/* out of resources */

	bufq_remove(&ida->buf_queue, bp);
	qcb->buf = bp;
	qcb->flags = 0;

	hwqcb = qcb->hwqcb;
	bzero(hwqcb, sizeof(struct ida_hdr) + sizeof(struct ida_req));

	bus_dmamap_load(ida->buffer_dmat, qcb->dmamap,
	    (void *)bp->b_data, bp->b_bcount, ida_setup_dmamap, hwqcb, 0);
	op = qcb->flags & DMA_DATA_IN ?
	    BUS_DMASYNC_PREREAD : BUS_DMASYNC_PREWRITE;
	bus_dmamap_sync(ida->buffer_dmat, qcb->dmamap, op);

	/*
	 * XXX
	 */
	{
		struct id_softc *drv = (struct id_softc *)bp->b_driver1;
		hwqcb->hdr.drive = drv->unit;
	}

	hwqcb->req.blkno = bp->b_pblkno;
	hwqcb->req.bcount = howmany(bp->b_bcount, DEV_BSIZE);
	hwqcb->req.command = bp->b_flags & B_READ ? CMD_READ : CMD_WRITE;

	STAILQ_INSERT_TAIL(&ida->qcb_queue, qcb, link.stqe);
}

static __inline bus_addr_t
idahwqcbvtop(struct ida_softc *ida, struct ida_hardware_qcb *hwqcb)
{
	return (ida->hwqcb_busaddr +
	    ((bus_addr_t)hwqcb - (bus_addr_t)ida->hwqcbs));
}

static __inline struct ida_qcb *
idahwqcbptov(struct ida_softc *ida, bus_addr_t hwqcb_addr)
{
	struct ida_hardware_qcb *hwqcb;

	hwqcb = (struct ida_hardware_qcb *)
	    ((bus_addr_t)ida->hwqcbs + (hwqcb_addr - ida->hwqcb_busaddr));
	return (hwqcb->qcb);
}

/*
 * This routine will be called from ida_intr in order to queue up more
 * I/O, meaning that we may be in an interrupt context.  Hence, we should
 * not muck around with spl() in this routine.
 */
static void
ida_start(struct ida_softc *ida)
{
	struct ida_qcb *qcb;

	while ((qcb = STAILQ_FIRST(&ida->qcb_queue)) != NULL) {
		if (ida_inl(ida, R_CMD_FIFO) == 0)
			break;				/* fifo is full */
		STAILQ_REMOVE_HEAD(&ida->qcb_queue, link.stqe);
		/*
		 * XXX
		 * place the qcb on an active list and set a timeout?
		 */
		qcb->state = QCB_ACTIVE;
		/*
		 * XXX
		 * cache the physaddr so we don't keep doing this?
		 */
		ida_outl(ida, R_CMD_FIFO, idahwqcbvtop(ida, qcb->hwqcb));
	}
}

void
ida_wait(struct ida_softc *ida, struct ida_qcb *qcb, int delay)
{
	struct ida_qcb *qcb_done = NULL;
	bus_addr_t completed;

	if (ida->flags & IDA_ATTACHED) {
		if (tsleep((caddr_t)qcb, PRIBIO, "idacmd", delay))
			panic("ida_command: timeout waiting for interrupt");
		return;
	}

	while ((completed = ida_inl(ida, R_DONE_FIFO)) == 0) {
		if (delay-- == 0)
			panic("ida_wait: timeout waiting for completion");
		DELAY(10);
	}

	qcb_done = idahwqcbptov(ida, completed & ~3);
	if (qcb_done != qcb)
		panic("ida_wait: incorrect qcb returned");
	ida_done(ida, qcb);
	return;
}

void
ida_intr(void *data)
{
	struct ida_softc *ida;
	struct ida_qcb *qcb;
	bus_addr_t completed;

	ida = (struct ida_softc *)data;

	if (ida_inl(ida, R_INT_PENDING) == 0)
		return;				/* not our interrupt */

	while ((completed = ida_inl(ida, R_DONE_FIFO)) != 0) {
		qcb = idahwqcbptov(ida, completed & ~3);

		if (qcb == NULL || qcb->state != QCB_ACTIVE) {
			device_printf(ida->dev,
			    "ignoring completion %x\n", completed);
			continue;
		}
		ida_done(ida, qcb);
	}
	ida_start(ida);
}

/*
 * should switch out command type; may be status, not just I/O.
 */
static void
ida_done(struct ida_softc *ida, struct ida_qcb *qcb)
{
	int error = 0;

	/*
	 * finish up command
	 */
	if (qcb->flags & DMA_DATA_TRANSFER) {
		bus_dmasync_op_t op;

		op = qcb->flags & DMA_DATA_IN ?
		    BUS_DMASYNC_POSTREAD : BUS_DMASYNC_POSTWRITE;
		bus_dmamap_sync(ida->buffer_dmat, qcb->dmamap, op);
		bus_dmamap_unload(ida->buffer_dmat, qcb->dmamap);
	}

	if (qcb->hwqcb->req.error & SOFT_ERROR)
		device_printf(ida->dev, "soft error\n");
	if (qcb->hwqcb->req.error & HARD_ERROR) {
		error = 1;
		device_printf(ida->dev, "hard error\n");
	}
	if (qcb->hwqcb->req.error & CMD_REJECTED) {
		error = 1;
		device_printf(ida->dev, "invalid request\n");
	}

	if (qcb->flags & IDA_COMMAND) {
		if (ida->flags & IDA_ATTACHED)
			wakeup(qcb);
	} else {
		if (error)
			qcb->buf->b_flags |= B_ERROR;
		id_intr(qcb->buf);
	}

	qcb->state = QCB_FREE;
	SLIST_INSERT_HEAD(&ida->free_qcbs, qcb, link.sle);
	ida_construct_qcb(ida);
}
