/* $FreeBSD$ */
/* $Id: isp_pci.c,v 1.4 1998/09/15 10:06:22 gibbs Exp $ */
/*
 * PCI specific probe and attach routines for Qlogic ISP SCSI adapters.
 * FreeBSD Version.
 *
 *---------------------------------------
 * Copyright (c) 1997, 1998 by Matthew Jacob
 * NASA/Ames Research Center
 * All rights reserved.
 *---------------------------------------
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
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
#include <dev/isp/asm_pci.h>
#include <sys/malloc.h>
#include <vm/vm.h>                      
#include <vm/pmap.h>
#include <vm/vm_extern.h>


#include <pci/pcireg.h>
#include <pci/pcivar.h>

#ifdef	SCSI_CAM
#include <machine/bus_memio.h>
#include <machine/bus_pio.h>
#include <machine/bus.h>
#endif

static u_int16_t isp_pci_rd_reg __P((struct ispsoftc *, int));
static void isp_pci_wr_reg __P((struct ispsoftc *, int, u_int16_t));
static int isp_pci_mbxdma __P((struct ispsoftc *));
static int isp_pci_dmasetup __P((struct ispsoftc *, ISP_SCSI_XFER_T *,
	ispreq_t *, u_int8_t *, u_int8_t));
#ifdef	SCSI_CAM
static void
isp_pci_dmateardown __P((struct ispsoftc *, ISP_SCSI_XFER_T *, u_int32_t));
#else
#define	isp_pci_dmateardown	NULL
#endif

static void isp_pci_reset1 __P((struct ispsoftc *));
static void isp_pci_dumpregs __P((struct ispsoftc *));

static struct ispmdvec mdvec = {
	isp_pci_rd_reg,
	isp_pci_wr_reg,
	isp_pci_mbxdma,
	isp_pci_dmasetup,
	isp_pci_dmateardown,
	NULL,
	isp_pci_reset1,
	isp_pci_dumpregs,
	ISP_RISC_CODE,
	ISP_CODE_LENGTH,
	ISP_CODE_ORG,
	ISP_CODE_VERSION,
	BIU_BURST_ENABLE,
	0
};

static struct ispmdvec mdvec_2100 = {
	isp_pci_rd_reg,
	isp_pci_wr_reg,
	isp_pci_mbxdma,
	isp_pci_dmasetup,
	isp_pci_dmateardown,
	NULL,
	isp_pci_reset1,
	isp_pci_dumpregs,
	ISP2100_RISC_CODE,
	ISP2100_CODE_LENGTH,
	ISP2100_CODE_ORG,
	ISP2100_CODE_VERSION,
	BIU_BURST_ENABLE,
	0
};

#ifndef	PCIM_CMD_INVEN
#define	PCIM_CMD_INVEN			0x10
#endif
#ifndef	PCIM_CMD_BUSMASTEREN
#define	PCIM_CMD_BUSMASTEREN		0x0004
#endif

#ifndef	PCI_VENDOR_QLOGIC
#define	PCI_VENDOR_QLOGIC		0x1077
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP1020
#define	PCI_PRODUCT_QLOGIC_ISP1020	0x1020
#endif

#define	PCI_QLOGIC_ISP	\
	((PCI_PRODUCT_QLOGIC_ISP1020 << 16) | PCI_VENDOR_QLOGIC)

#ifndef	PCI_PRODUCT_QLOGIC_ISP2100
#define	PCI_PRODUCT_QLOGIC_ISP2100	0x2100
#endif

#define	PCI_QLOGIC_ISP2100	\
	((PCI_PRODUCT_QLOGIC_ISP2100 << 16) | PCI_VENDOR_QLOGIC)

#define IO_MAP_REG	0x10
#define MEM_MAP_REG	0x14


static char *isp_pci_probe __P((pcici_t tag, pcidi_t type));
static void isp_pci_attach __P((pcici_t config_d, int unit));

/* This distinguishing define is not right, but it does work */
 
#ifndef	SCSI_CAM
#define	IO_SPACE_MAPPING	0
#define	MEM_SPACE_MAPPING	1
typedef int bus_space_tag_t;
typedef u_long bus_space_handle_t;
#ifdef __alpha__
#define	bus_space_read_2(st, sh, offset)	\
	(st == IO_SPACE_MAPPING)? \
		inw((pci_port_t)sh + offset) : readw((pci_port_t)sh + offset)
#define	bus_space_write_2(st, sh, offset, val)	\
	if (st == IO_SPACE_MAPPING) outw((pci_port_t)sh + offset, val); else \
                writew((pci_port_t)sh + offset, val)
#else
#define	bus_space_read_2(st, sh, offset)	\
	(st == IO_SPACE_MAPPING)? \
		inw((pci_port_t)sh + offset) : *((u_int16_t *)(uintptr_t)sh)
#define	bus_space_write_2(st, sh, offset, val)	\
	if (st == IO_SPACE_MAPPING) outw((pci_port_t)sh + offset, val); else \
		*((u_int16_t *)(uintptr_t)sh) = val
#endif
#else
#ifdef __alpha__
#define IO_SPACE_MAPPING	ALPHA_BUS_SPACE_IO
#define MEM_SPACE_MAPPING	ALPHA_BUS_SPACE_MEM
#else
#define IO_SPACE_MAPPING	I386_BUS_SPACE_IO
#define MEM_SPACE_MAPPING	I386_BUS_SPACE_MEM
#endif
#endif

struct isp_pcisoftc {
	struct ispsoftc			pci_isp;
        pcici_t				pci_id;
	bus_space_tag_t			pci_st;
	bus_space_handle_t		pci_sh;
#ifdef	SCSI_CAM
	bus_dma_tag_t			parent_dmat;
	bus_dma_tag_t			cntrol_dmat;
	bus_dmamap_t			cntrol_dmap;
	bus_dmamap_t			dmaps[MAXISPREQUEST];
#endif
	union {
		sdparam	_x;
		struct {
			fcparam _a;
			char _b[ISP2100_SCRLEN];
		} _y;
	} _z;
};

static u_long ispunit;

struct pci_device isp_pci_driver = {
	"isp",
	isp_pci_probe,
	isp_pci_attach,
	&ispunit,
	NULL
};
DATA_SET (pcidevice_set, isp_pci_driver);


static char *
isp_pci_probe(tag, type)
	pcici_t tag;
	pcidi_t type;
{       
	static int oneshot = 1;
	char *x;

        switch (type) {
	case PCI_QLOGIC_ISP:
		x = "Qlogic ISP 10X0 PCI SCSI Adapter";
		break;
	case PCI_QLOGIC_ISP2100:
		x = "Qlogic ISP 2100 PCI FC-AL Adapter";
		break;
	default:
		return (NULL);
	}
	if (oneshot) {
		oneshot = 0;
		printf("%s Version %d.%d, Core Version %d.%d\n", PVS,
		    ISP_PLATFORM_VERSION_MAJOR, ISP_PLATFORM_VERSION_MINOR,
		    ISP_CORE_VERSION_MAJOR, ISP_CORE_VERSION_MINOR);
	}
	return (x);
}


static void    
isp_pci_attach(config_id, unit)
        pcici_t config_id;
        int unit;
{
	int mapped;
	pci_port_t io_port;
	u_int32_t data;
	struct isp_pcisoftc *pcs;
	struct ispsoftc *isp;
	vm_offset_t vaddr, paddr;
	ISP_LOCKVAL_DECL;


	pcs = malloc(sizeof (struct isp_pcisoftc), M_DEVBUF, M_NOWAIT);
	if (pcs == NULL) {
		printf("isp%d: cannot allocate softc\n", unit);
		return;
	}
	bzero(pcs, sizeof (struct isp_pcisoftc));

	vaddr = paddr = NULL;
	mapped = 0;
	data = pci_conf_read(config_id, PCI_COMMAND_STATUS_REG);
	if (mapped == 0 && (data & PCI_COMMAND_MEM_ENABLE)) {
		if (pci_map_mem(config_id, MEM_MAP_REG, &vaddr, &paddr)) {
			pcs->pci_st = MEM_SPACE_MAPPING;
			pcs->pci_sh = vaddr;
			mapped++;
		}
	}
	if (mapped == 0 && (data & PCI_COMMAND_IO_ENABLE)) {
		if (pci_map_port(config_id, PCI_MAP_REG_START, &io_port)) {
			pcs->pci_st = IO_SPACE_MAPPING;
			pcs->pci_sh = io_port;
			mapped++;
		}
	}
	if (mapped == 0) {
		printf("isp%d: unable to map any ports!\n", unit);
		free(pcs, M_DEVBUF);
		return;
	}
	printf("isp%d: using %s space register mapping\n", unit,
	    pcs->pci_st == IO_SPACE_MAPPING? "I/O" : "Memory");

	isp = &pcs->pci_isp;
	(void) sprintf(isp->isp_name, "isp%d", unit);
	isp->isp_osinfo.unit = unit;

	data = pci_conf_read(config_id, PCI_ID_REG);
	if (data == PCI_QLOGIC_ISP) {
		isp->isp_mdvec = &mdvec;
		isp->isp_type = ISP_HA_SCSI_UNKNOWN;
		isp->isp_param = &pcs->_z._x;
	} else if (data == PCI_QLOGIC_ISP2100) {
		isp->isp_mdvec = &mdvec_2100;
		isp->isp_type = ISP_HA_FC_2100;
		isp->isp_param = &pcs->_z._y._a;

		ISP_LOCK(isp);
		data = pci_conf_read(config_id, PCI_COMMAND_STATUS_REG);
		data |= PCIM_CMD_BUSMASTEREN | PCIM_CMD_INVEN;
		pci_conf_write(config_id, PCI_COMMAND_STATUS_REG, data);

		/*
		 * Wierd- we need to clear the lsb in offset 0x30 to take the
		 * chip out of reset state.
		 */
		data = pci_conf_read(config_id, 0x30);
		data &= ~1;
		pci_conf_write(config_id, 0x30, data);
		ISP_UNLOCK(isp);
	} else {
		printf("%s: unknown dev (%x)- punting\n", isp->isp_name, data);
		free(pcs, M_DEVBUF);
		return;
	}

#ifdef	SCSI_CAM
	if (bus_dma_tag_create(NULL, 0, 0, BUS_SPACE_MAXADDR_32BIT,
	    BUS_SPACE_MAXADDR, NULL, NULL, 1<<24,
	    255, 1<<24, 0, &pcs->parent_dmat) != 0) {
		printf("%s: could not create master dma tag\n", isp->isp_name);
		free(pcs, M_DEVBUF);
		return;
	}
#endif
	if (pci_map_int(config_id, (void (*)(void *))isp_intr,
	    (void *)isp, &IMASK) == 0) {
		printf("%s: could not map interrupt\n", isp->isp_name);
		free(pcs, M_DEVBUF);
		return;
	}

	pcs->pci_id = config_id;
	ISP_LOCK(isp);
	isp_reset(isp);
	if (isp->isp_state != ISP_RESETSTATE) {
		ISP_UNLOCK(isp);
		free(pcs, M_DEVBUF);
		return;
	}
	isp_init(isp);
	if (isp->isp_state != ISP_INITSTATE) {
		isp_uninit(isp);
		ISP_UNLOCK(isp);
		free(pcs, M_DEVBUF);
		return;
	}
	isp_attach(isp);
	if (isp->isp_state != ISP_RUNSTATE) {
		isp_uninit(isp);
		free(pcs, M_DEVBUF);
	}
	ISP_UNLOCK(isp);
}

#define  PCI_BIU_REGS_OFF		BIU_REGS_OFF

static u_int16_t
isp_pci_rd_reg(isp, regoff)
	struct ispsoftc *isp;
	int regoff;
{
	u_int16_t rv;
	struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
	int offset, oldsxp = 0;

	if ((regoff & BIU_BLOCK) != 0) {
		offset = PCI_BIU_REGS_OFF;
	} else if ((regoff & MBOX_BLOCK) != 0) {
		if (isp->isp_type & ISP_HA_SCSI)
			offset = PCI_MBOX_REGS_OFF;
		else
			offset = PCI_MBOX_REGS2100_OFF;
	} else if ((regoff & SXP_BLOCK) != 0) {
		offset = PCI_SXP_REGS_OFF;
		/*
		 * We will assume that someone has paused the RISC processor.
		 */
		oldsxp = isp_pci_rd_reg(isp, BIU_CONF1);
		isp_pci_wr_reg(isp, BIU_CONF1, oldsxp & ~BIU_PCI_CONF1_SXP);
	} else {
		offset = PCI_RISC_REGS_OFF;
	}
	regoff &= 0xff;
	offset += regoff;
	rv = bus_space_read_2(pcs->pci_st, pcs->pci_sh, offset);
	if ((regoff & SXP_BLOCK) != 0) {
		isp_pci_wr_reg(isp, BIU_CONF1, oldsxp);
	}
	return (rv);
}

static void
isp_pci_wr_reg(isp, regoff, val)
	struct ispsoftc *isp;
	int regoff;
	u_int16_t val;
{
	struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
	int offset, oldsxp = 0;
	if ((regoff & BIU_BLOCK) != 0) {
		offset = PCI_BIU_REGS_OFF;
	} else if ((regoff & MBOX_BLOCK) != 0) {
		if (isp->isp_type & ISP_HA_SCSI)
			offset = PCI_MBOX_REGS_OFF;
		else
			offset = PCI_MBOX_REGS2100_OFF;
	} else if ((regoff & SXP_BLOCK) != 0) {
		offset = PCI_SXP_REGS_OFF;
		/*
		 * We will assume that someone has paused the RISC processor.
		 */
		oldsxp = isp_pci_rd_reg(isp, BIU_CONF1);
		isp_pci_wr_reg(isp, BIU_CONF1, oldsxp & ~BIU_PCI_CONF1_SXP);
	} else {
		offset = PCI_RISC_REGS_OFF;
	}
	regoff &= 0xff;
	offset += regoff;
	bus_space_write_2(pcs->pci_st, pcs->pci_sh, offset, val);
	if ((regoff & SXP_BLOCK) != 0) {
		isp_pci_wr_reg(isp, BIU_CONF1, oldsxp);
	}
}

#ifdef	SCSI_CAM
static void isp_map_rquest __P((void *, bus_dma_segment_t *, int, int));
static void isp_map_result __P((void *, bus_dma_segment_t *, int, int));
static void isp_map_fcscrt __P((void *, bus_dma_segment_t *, int, int));

static void
isp_map_rquest(arg, segs, nseg, error)
	void *arg;
	bus_dma_segment_t *segs;
	int nseg;
	int error;
{
	struct ispsoftc *isp = (struct ispsoftc *) arg;
	isp->isp_rquest_dma = segs->ds_addr;
}

static void
isp_map_result(arg, segs, nseg, error)
	void *arg;
	bus_dma_segment_t *segs;
	int nseg;
	int error;
{
	struct ispsoftc *isp = (struct ispsoftc *) arg;
	isp->isp_result_dma = segs->ds_addr;
}

static void
isp_map_fcscrt(arg, segs, nseg, error)
	void *arg;
	bus_dma_segment_t *segs;
	int nseg;
	int error;
{
	struct ispsoftc *isp = (struct ispsoftc *) arg;
	fcparam *fcp = isp->isp_param;
	fcp->isp_scdma = segs->ds_addr;
}

static int
isp_pci_mbxdma(isp)
	struct ispsoftc *isp;
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	caddr_t base;
	u_int32_t len;
	int i, error;

	/*
	 * Allocate and map the request, result queues, plus FC scratch area.
	 */
	len = ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN);
	len += ISP_QUEUE_SIZE(RESULT_QUEUE_LEN);
	if (isp->isp_type & ISP_HA_FC) {
		len += ISP2100_SCRLEN;
	}
	if (bus_dma_tag_create(pci->parent_dmat, 0, 0, BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR, NULL, NULL, len, 1, BUS_SPACE_MAXSIZE_32BIT,
	    0, &pci->cntrol_dmat) != 0) {
		printf("%s: cannot create a dma tag for control spaces\n",
		    isp->isp_name);
		return (1);
	}
	if (bus_dmamem_alloc(pci->cntrol_dmat, (void **)&base,
	    BUS_DMA_NOWAIT, &pci->cntrol_dmap) != 0) {
		printf("%s: cannot allocate CCB memory\n", isp->isp_name);
		return (1);
	}

	isp->isp_rquest = base;
	bus_dmamap_load(pci->cntrol_dmat, pci->cntrol_dmap, isp->isp_rquest,
	    ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN), isp_map_rquest, pci, 0);

	isp->isp_result = base + ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN);
	bus_dmamap_load(pci->cntrol_dmat, pci->cntrol_dmap, isp->isp_result,
	    ISP_QUEUE_SIZE(RESULT_QUEUE_LEN), isp_map_result, pci, 0);

	if (isp->isp_type & ISP_HA_FC) {
		fcparam *fcp = (fcparam *) isp->isp_param;
		fcp->isp_scratch = isp->isp_result +
		    ISP_QUEUE_SIZE(RESULT_QUEUE_LEN);
		bus_dmamap_load(pci->cntrol_dmat, pci->cntrol_dmap,
		    fcp->isp_scratch, ISP2100_SCRLEN, isp_map_fcscrt, pci, 0);
	}

	/*
	 * Use this opportunity to initialize/create data DMA maps.
	 */
	for (i = 0; i < MAXISPREQUEST; i++) {
		error = bus_dmamap_create(pci->parent_dmat, 0, &pci->dmaps[i]);
		if (error) {
			printf("%s: error %d creating data DMA maps\n",
			    isp->isp_name, error);
			return (1);
		}
	}
	return (0);
}

static void dma2 __P((void *, bus_dma_segment_t *, int, int));
typedef struct {
	struct ispsoftc *isp;
	ISP_SCSI_XFER_T *ccb;
	ispreq_t *rq;
	u_int8_t *iptrp;
	u_int8_t optr;
	u_int error;
} mush_t;

static void
dma2(arg, dm_segs, nseg, error)
	void *arg;
	bus_dma_segment_t *dm_segs;
	int nseg;
	int error;
{
	mush_t *mp;
	ISP_SCSI_XFER_T *ccb;
	struct ispsoftc *isp;
	struct isp_pcisoftc *pci;
	bus_dmamap_t *dp;
	bus_dma_segment_t *eseg;
	ispreq_t *rq;
	u_int8_t *iptrp;
	u_int8_t optr;
	ispcontreq_t *crq;
	int drq, seglim, datalen;

	mp = (mush_t *) arg;
	if (error) {
		mp->error = error;
		return;
	}

	isp = mp->isp;
	if (nseg < 1) {
		printf("%s: zero or negative segment count\n", isp->isp_name);
		mp->error = EFAULT;
		return;
	}
	ccb = mp->ccb;
	rq = mp->rq;
	iptrp = mp->iptrp;
	optr = mp->optr;

	pci = (struct isp_pcisoftc *)isp;
	dp = &pci->dmaps[rq->req_handle - 1];
	if ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREREAD);
		drq = REQFLAG_DATA_IN;
	} else {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREWRITE);
		drq = REQFLAG_DATA_OUT;
	}

	datalen = XS_XFRLEN(ccb);
	if (isp->isp_type & ISP_HA_FC) {
		seglim = ISP_RQDSEG_T2;
		((ispreqt2_t *)rq)->req_totalcnt = datalen;
		((ispreqt2_t *)rq)->req_flags |= drq;
	} else {
		seglim = ISP_RQDSEG;
		rq->req_flags |= drq;
	}

	eseg = dm_segs + nseg;

	while (datalen != 0 && rq->req_seg_count < seglim && dm_segs != eseg) {
		if (isp->isp_type & ISP_HA_FC) {
			ispreqt2_t *rq2 = (ispreqt2_t *)rq;
			rq2->req_dataseg[rq2->req_seg_count].ds_base =
			    dm_segs->ds_addr;
			rq2->req_dataseg[rq2->req_seg_count].ds_count =
			    dm_segs->ds_len;
		} else {
			rq->req_dataseg[rq->req_seg_count].ds_base =
				dm_segs->ds_addr;
			rq->req_dataseg[rq->req_seg_count].ds_count =
				dm_segs->ds_len;
		}
		datalen -= dm_segs->ds_len;
#if	0
		if (isp->isp_type & ISP_HA_FC) {
			ispreqt2_t *rq2 = (ispreqt2_t *)rq;
			printf("%s: seg0[%d] cnt 0x%x paddr 0x%08x\n",
			    isp->isp_name, rq->req_seg_count,
			    rq2->req_dataseg[rq2->req_seg_count].ds_count,
			    rq2->req_dataseg[rq2->req_seg_count].ds_base);
		} else {
			printf("%s: seg0[%d] cnt 0x%x paddr 0x%08x\n",
			    isp->isp_name, rq->req_seg_count,
			    rq->req_dataseg[rq->req_seg_count].ds_count,
			    rq->req_dataseg[rq->req_seg_count].ds_base);
		}
#endif
		rq->req_seg_count++;
		dm_segs++;
	}

	if (datalen == 0)
		return;

	while (datalen > 0 && dm_segs != eseg) {
		crq = (ispcontreq_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, *iptrp);
		*iptrp = (*iptrp + 1) & (RQUEST_QUEUE_LEN - 1);
		if (*iptrp == optr) {
			printf("%s: Request Queue Overflow+\n", isp->isp_name);
			mp->error = EFBIG;
			return;
		}
		rq->req_header.rqs_entry_count++;
		bzero((void *)crq, sizeof (*crq));
		crq->req_header.rqs_entry_count = 1;
		crq->req_header.rqs_entry_type = RQSTYPE_DATASEG;

		seglim = 0;
		while (datalen > 0 && seglim < ISP_CDSEG && dm_segs != eseg) {
			crq->req_dataseg[seglim].ds_base =
			    dm_segs->ds_addr;
			crq->req_dataseg[seglim].ds_count =
			    dm_segs->ds_len;
#if	0
			printf("%s: seg%d[%d] cnt 0x%x paddr 0x%08x\n",
			    isp->isp_name, rq->req_header.rqs_entry_count-1,
			    seglim, crq->req_dataseg[seglim].ds_count,
			    crq->req_dataseg[seglim].ds_base);
#endif
			rq->req_seg_count++;
			dm_segs++;
			seglim++;
			datalen -= dm_segs->ds_len;
		}
	}
}

static int
isp_pci_dmasetup(isp, ccb, rq, iptrp, optr)
	struct ispsoftc *isp;
	ISP_SCSI_XFER_T *ccb;
	ispreq_t *rq;
	u_int8_t *iptrp;
	u_int8_t optr;
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	struct ccb_hdr *ccb_h;
	struct ccb_scsiio *csio;
	bus_dmamap_t *dp;
	mush_t mush, *mp;

	csio = (struct ccb_scsiio *) ccb;
	ccb_h = &csio->ccb_h;

	if ((ccb_h->flags & CAM_DIR_MASK) == CAM_DIR_NONE) {
		rq->req_seg_count = 1;
		return (0);
	}
	dp = &pci->dmaps[rq->req_handle - 1];

	/*
	 * Do a virtual grapevine step to collect info for
	 * a callback method we really didn't want.
	 */
	mp = &mush;
	mp->isp = isp;
	mp->ccb = ccb;
	mp->rq = rq;
	mp->iptrp = iptrp;
	mp->optr = optr;
	mp->error = 0;

	if ((ccb_h->flags & CAM_SCATTER_VALID) == 0) {
		if ((ccb_h->flags & CAM_DATA_PHYS) == 0) {
			int error;
			/*
			 * spls are spls, locks are locks.
			 * it isn't clear whether splsoftvm, if s spl,
			 * is a RAISE over splcam, or not.
			 */
#if	0
			int s;
			s = splsoftvm();
#endif
			error = bus_dmamap_load(pci->parent_dmat, *dp,
			    csio->data_ptr, csio->dxfer_len, dma2, mp, 0);
#if	0
			splx(s);
#endif
			if (error == EINPROGRESS) {
				/*
				 * We simply aren't going to support
				 * this at this time. This mechanism
				 * is too rigid for my taste.
				 */
				printf("%s: sorry, we're not doing bounceio\n",
				    isp->isp_name);
				bus_dmamap_unload(pci->parent_dmat, *dp);
				mp->error = EINVAL;
			} else if (error && mp->error == 0) {
				mp->error = error;
			}
		} else {
			/* Pointer to physical buffer */
			struct bus_dma_segment seg; 
			seg.ds_addr = (bus_addr_t)csio->data_ptr;
			seg.ds_len = csio->dxfer_len;
			dma2(mp, &seg, 1, 0);
		}
	} else {
		struct bus_dma_segment *segs;

		if ((ccb_h->flags & CAM_DATA_PHYS) != 0) {
			printf("%s: Physical segment pointers unsupported",
				isp->isp_name);
			mp->error = EINVAL;
		} else if ((ccb_h->flags&CAM_SG_LIST_PHYS) == 0) {
			printf("%s: Virtual segment addresses unsupported",
				isp->isp_name);
			mp->error = EINVAL;
		} else {
			/* Just use the segments provided */
			segs = (struct bus_dma_segment *) csio->data_ptr;
			dma2(mp, segs, csio->sglist_cnt, 0);
		}
	}
	if (mp->error) {
		if (mp->error != EFBIG) {
                        printf("%s: Unexepected error 0x%x returned from "
                               "bus_dmamap_load\n", isp->isp_name, mp->error);
                        ccb_h->status = CAM_REQ_TOO_BIG;
		} else if (mp->error == EINVAL) {
			ccb_h->status = CAM_REQ_INVALID;
		} else {
			ccb_h->status = CAM_UNREC_HBA_ERROR;
		}
		ccb_h->status |= CAM_DEV_QFRZN;
		printf("%s:isp_pci_dmasetup->xpt_freeze_devq\n", isp->isp_name);
		xpt_freeze_devq(ccb_h->path, 1);
	}
	return (mp->error);
}

static void
isp_pci_dmateardown(isp, ccb, handle)
	struct ispsoftc *isp;
	ISP_SCSI_XFER_T *ccb;
	u_int32_t handle;
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	bus_dmamap_t *dp = &pci->dmaps[handle];

	if ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_POSTREAD);
	} else {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_POSTWRITE);
	}
	bus_dmamap_unload(pci->parent_dmat, *dp);
}

#else	/* SCSI_CAM */

static int
isp_pci_mbxdma(isp)
	struct ispsoftc *isp;
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	u_int32_t len;
	int rseg;

	/* XXXX CHECK FOR ALIGNMENT */
	/*
	 * Allocate and map the request queue.
	 */
	len = ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN);
	isp->isp_rquest = malloc(len, M_DEVBUF, M_NOWAIT);
	if (isp->isp_rquest == NULL) {
		printf("%s: cannot malloc request queue\n", isp->isp_name);
		return (1);
	}
	isp->isp_rquest_dma = vtophys(isp->isp_rquest);

#if	0
	printf("RQUEST=0x%x (0x%x)...", isp->isp_rquest, isp->isp_rquest_dma);
#endif

	/*
	 * Allocate and map the result queue.
	 */
	len = ISP_QUEUE_SIZE(RESULT_QUEUE_LEN);
	isp->isp_result = malloc(len, M_DEVBUF, M_NOWAIT);
	if (isp->isp_result == NULL) {
		free(isp->isp_rquest, M_DEVBUF);
		printf("%s: cannot malloc result queue\n", isp->isp_name);
		return (1);
	}
	isp->isp_result_dma = vtophys(isp->isp_result);
#if	0
	printf("RESULT=0x%x (0x%x)\n", isp->isp_result, isp->isp_result_dma);
#endif
	if (isp->isp_type & ISP_HA_FC) {
		fcparam *fcp = isp->isp_param;
		len = ISP2100_SCRLEN;
		fcp->isp_scratch = (volatile caddr_t) &pci->_z._y._b;
		fcp->isp_scdma = vtophys(fcp->isp_scratch);
	}
	return (0);
}

static int
isp_pci_dmasetup(isp, xs, rq, iptrp, optr)
	struct ispsoftc *isp;
	ISP_SCSI_XFER_T *xs;
	ispreq_t *rq;
	u_int8_t *iptrp;
	u_int8_t optr;
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	ispcontreq_t *crq;
	vm_offset_t vaddr;
	int drq, seglim;
	u_int32_t paddr, nextpaddr, datalen, size, *ctrp;

	if (xs->datalen == 0) {
		rq->req_seg_count = 1;
		return (0);
	}

	if (xs->flags & SCSI_DATA_IN) {
		drq = REQFLAG_DATA_IN;
	} else {
		drq = REQFLAG_DATA_OUT;
	}

	if (isp->isp_type & ISP_HA_FC) {
		seglim = ISP_RQDSEG_T2;
		((ispreqt2_t *)rq)->req_totalcnt = XS_XFRLEN(xs);
		((ispreqt2_t *)rq)->req_flags |= drq;
	} else {
		seglim = ISP_RQDSEG;
		rq->req_flags |= drq;
	}

	datalen = XS_XFRLEN(xs);
	vaddr = (vm_offset_t) xs->data;
	paddr = vtophys(vaddr);

	while (datalen != 0 && rq->req_seg_count < seglim) {
		if (isp->isp_type & ISP_HA_FC) {
			ispreqt2_t *rq2 = (ispreqt2_t *)rq;
			rq2->req_dataseg[rq2->req_seg_count].ds_base = paddr;
			ctrp = &rq2->req_dataseg[rq2->req_seg_count].ds_count;
		} else {
			rq->req_dataseg[rq->req_seg_count].ds_base = paddr;
			ctrp = &rq->req_dataseg[rq->req_seg_count].ds_count;
		}
		nextpaddr = paddr;
		*(ctrp) = 0;

		while (datalen != 0 && paddr == nextpaddr) {
			nextpaddr = (paddr & (~PAGE_MASK)) + PAGE_SIZE;
			size = nextpaddr - paddr;
			if (size > datalen)
				size = datalen;
			
			*(ctrp) += size;
			vaddr += size;
			datalen -= size;
			if (datalen != 0)
				paddr = vtophys(vaddr);

		}
#if	0
		if (isp->isp_type & ISP_HA_FC) {
			ispreqt2_t *rq2 = (ispreqt2_t *)rq;
			printf("%s: seg0[%d] cnt 0x%x paddr 0x%08x\n",
			    isp->isp_name, rq->req_seg_count,
			    rq2->req_dataseg[rq2->req_seg_count].ds_count,
			    rq2->req_dataseg[rq2->req_seg_count].ds_base);
		} else {
			printf("%s: seg0[%d] cnt 0x%x paddr 0x%08x\n",
			    isp->isp_name, rq->req_seg_count,
			    rq->req_dataseg[rq->req_seg_count].ds_count,
			    rq->req_dataseg[rq->req_seg_count].ds_base);
		}
#endif
		rq->req_seg_count++;
	}



	if (datalen == 0)
		return (0);

	paddr = vtophys(vaddr);
	while (datalen > 0) {
		crq = (ispcontreq_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, *iptrp);
		*iptrp = (*iptrp + 1) & (RQUEST_QUEUE_LEN - 1);
		if (*iptrp == optr) {
			printf("%s: Request Queue Overflow\n", isp->isp_name);
			XS_SETERR(xs, HBA_BOTCH);
			return (EFBIG);
		}
		rq->req_header.rqs_entry_count++;
		bzero((void *)crq, sizeof (*crq));
		crq->req_header.rqs_entry_count = 1;
		crq->req_header.rqs_entry_type = RQSTYPE_DATASEG;

		for (seglim = 0; datalen != 0 && seglim < ISP_CDSEG; seglim++) {
			crq->req_dataseg[seglim].ds_base = paddr;
			ctrp = &crq->req_dataseg[seglim].ds_count;
			*(ctrp) = 0;
			nextpaddr = paddr;
			while (datalen != 0 && paddr == nextpaddr) {
				nextpaddr = (paddr & (~PAGE_MASK)) + PAGE_SIZE;
				size = nextpaddr - paddr;
				if (size > datalen)
					size = datalen;
			
				*(ctrp) += size;
				vaddr += size;
				datalen -= size;
				if (datalen != 0)
					paddr = vtophys(vaddr);
			}
#if	0
			printf("%s: seg%d[%d] cnt 0x%x paddr 0x%08x\n",
			    isp->isp_name, rq->req_header.rqs_entry_count-1,
			    seglim, crq->req_dataseg[seglim].ds_count,
			    crq->req_dataseg[seglim].ds_base);
#endif
			rq->req_seg_count++;
		}
	}

	return (0);
}
#endif

static void
isp_pci_reset1(isp)
	struct ispsoftc *isp;
{
	/* Make sure the BIOS is disabled */
	isp_pci_wr_reg(isp, HCCR, PCI_HCCR_CMD_BIOS);
}

static void
isp_pci_dumpregs(isp)
	struct ispsoftc *isp;
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	printf("%s: PCI Status Command/Status=%lx\n", pci->pci_isp.isp_name,
	    pci_conf_read(pci->pci_id, PCI_COMMAND_STATUS_REG));
}
