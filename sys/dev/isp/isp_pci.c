/* $FreeBSD$ */
/*
 * PCI specific probe and attach routines for Qlogic ISP SCSI adapters.
 * FreeBSD Version.
 *
 *---------------------------------------
 * Copyright (c) 1997, 1998, 1999 by Matthew Jacob
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


#include <pci/pcireg.h>
#include <pci/pcivar.h>

#include <machine/bus_memio.h>
#include <machine/bus_pio.h>
#include <machine/bus.h>
#include <machine/md_var.h>

static u_int16_t isp_pci_rd_reg __P((struct ispsoftc *, int));
static void isp_pci_wr_reg __P((struct ispsoftc *, int, u_int16_t));
#ifndef ISP_DISABLE_1080_SUPPORT
static u_int16_t isp_pci_rd_reg_1080 __P((struct ispsoftc *, int));
static void isp_pci_wr_reg_1080 __P((struct ispsoftc *, int, u_int16_t));
#endif
static int isp_pci_mbxdma __P((struct ispsoftc *));
static int isp_pci_dmasetup __P((struct ispsoftc *, ISP_SCSI_XFER_T *,
	ispreq_t *, u_int16_t *, u_int16_t));
static void
isp_pci_dmateardown __P((struct ispsoftc *, ISP_SCSI_XFER_T *, u_int32_t));

static void isp_pci_reset1 __P((struct ispsoftc *));
static void isp_pci_dumpregs __P((struct ispsoftc *));

#ifndef	ISP_CODE_ORG
#define	ISP_CODE_ORG		0x1000
#endif
#ifndef	ISP_1040_RISC_CODE
#define	ISP_1040_RISC_CODE	NULL
#endif
#ifndef	ISP_1080_RISC_CODE
#define	ISP_1080_RISC_CODE	NULL
#endif
#ifndef	ISP_2100_RISC_CODE
#define	ISP_2100_RISC_CODE	NULL
#endif
#ifndef	ISP_2200_RISC_CODE
#define	ISP_2200_RISC_CODE	NULL
#endif

#ifndef ISP_DISABLE_1020_SUPPORT
static struct ispmdvec mdvec = {
	isp_pci_rd_reg,
	isp_pci_wr_reg,
	isp_pci_mbxdma,
	isp_pci_dmasetup,
	isp_pci_dmateardown,
	NULL,
	isp_pci_reset1,
	isp_pci_dumpregs,
	ISP_1040_RISC_CODE,
	0,
	ISP_CODE_ORG,
	0,
	BIU_BURST_ENABLE|BIU_PCI_CONF1_FIFO_64,
	0
};
#endif

#ifndef ISP_DISABLE_1080_SUPPORT
static struct ispmdvec mdvec_1080 = {
	isp_pci_rd_reg_1080,
	isp_pci_wr_reg_1080,
	isp_pci_mbxdma,
	isp_pci_dmasetup,
	isp_pci_dmateardown,
	NULL,
	isp_pci_reset1,
	isp_pci_dumpregs,
	ISP_1080_RISC_CODE,
	0,
	ISP_CODE_ORG,
	0,
	BIU_BURST_ENABLE|BIU_PCI_CONF1_FIFO_64,
	0
};
#endif

#ifndef ISP_DISABLE_2100_SUPPORT
static struct ispmdvec mdvec_2100 = {
	isp_pci_rd_reg,
	isp_pci_wr_reg,
	isp_pci_mbxdma,
	isp_pci_dmasetup,
	isp_pci_dmateardown,
	NULL,
	isp_pci_reset1,
	isp_pci_dumpregs,
	ISP_2100_RISC_CODE,
	0,
	ISP_CODE_ORG,
	0,
	0,
	0
};
#endif

#ifndef	ISP_DISABLE_2200_SUPPORT
static struct ispmdvec mdvec_2200 = {
	isp_pci_rd_reg,
	isp_pci_wr_reg,
	isp_pci_mbxdma,
	isp_pci_dmasetup,
	isp_pci_dmateardown,
	NULL,
	isp_pci_reset1,
	isp_pci_dumpregs,
	ISP_2200_RISC_CODE,
	0,
	ISP_CODE_ORG,
	0,
	0,
	0
};
#endif

#ifndef	SCSI_ISP_PREFER_MEM_MAP
#define	SCSI_ISP_PREFER_MEM_MAP	0
#endif

#ifndef	PCIM_CMD_INVEN
#define	PCIM_CMD_INVEN			0x10
#endif
#ifndef	PCIM_CMD_BUSMASTEREN
#define	PCIM_CMD_BUSMASTEREN		0x0004
#endif
#ifndef	PCIM_CMD_PERRESPEN
#define	PCIM_CMD_PERRESPEN		0x0040
#endif
#ifndef	PCIM_CMD_SEREN
#define	PCIM_CMD_SEREN			0x0100
#endif

#ifndef	PCIR_COMMAND
#define	PCIR_COMMAND			0x04
#endif

#ifndef	PCIR_CACHELNSZ
#define	PCIR_CACHELNSZ			0x0c
#endif

#ifndef	PCIR_LATTIMER
#define	PCIR_LATTIMER			0x0d
#endif

#ifndef	PCIR_ROMADDR
#define	PCIR_ROMADDR			0x30
#endif

#ifndef	PCI_VENDOR_QLOGIC
#define	PCI_VENDOR_QLOGIC	0x1077
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP1020
#define	PCI_PRODUCT_QLOGIC_ISP1020	0x1020
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP1080
#define	PCI_PRODUCT_QLOGIC_ISP1080	0x1080
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP1240
#define	PCI_PRODUCT_QLOGIC_ISP1240	0x1240
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP1280
#define	PCI_PRODUCT_QLOGIC_ISP1280	0x1280
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP2100
#define	PCI_PRODUCT_QLOGIC_ISP2100	0x2100
#endif

#ifndef	PCI_PRODUCT_QLOGIC_ISP2200
#define	PCI_PRODUCT_QLOGIC_ISP2200	0x2200
#endif

#define	PCI_QLOGIC_ISP	((PCI_PRODUCT_QLOGIC_ISP1020 << 16) | PCI_VENDOR_QLOGIC)

#define	PCI_QLOGIC_ISP1080	\
	((PCI_PRODUCT_QLOGIC_ISP1080 << 16) | PCI_VENDOR_QLOGIC)

#define	PCI_QLOGIC_ISP1240	\
	((PCI_PRODUCT_QLOGIC_ISP1240 << 16) | PCI_VENDOR_QLOGIC)

#define	PCI_QLOGIC_ISP1280	\
	((PCI_PRODUCT_QLOGIC_ISP1280 << 16) | PCI_VENDOR_QLOGIC)

#define	PCI_QLOGIC_ISP2100	\
	((PCI_PRODUCT_QLOGIC_ISP2100 << 16) | PCI_VENDOR_QLOGIC)

#define	PCI_QLOGIC_ISP2200	\
	((PCI_PRODUCT_QLOGIC_ISP2200 << 16) | PCI_VENDOR_QLOGIC)

#define	IO_MAP_REG	0x10
#define	MEM_MAP_REG	0x14

#define	PCI_DFLT_LTNCY	0x40
#define	PCI_DFLT_LNSZ	0x10

static const char *isp_pci_probe __P((pcici_t tag, pcidi_t type));
static void isp_pci_attach __P((pcici_t config_d, int unit));

/* This distinguishing define is not right, but it does work */
#ifdef __alpha__
#define IO_SPACE_MAPPING	ALPHA_BUS_SPACE_IO
#define MEM_SPACE_MAPPING	ALPHA_BUS_SPACE_MEM
#else
#define IO_SPACE_MAPPING	I386_BUS_SPACE_IO
#define MEM_SPACE_MAPPING	I386_BUS_SPACE_MEM
#endif

struct isp_pcisoftc {
	struct ispsoftc			pci_isp;
        pcici_t				pci_id;
	bus_space_tag_t			pci_st;
	bus_space_handle_t		pci_sh;
	int16_t				pci_poff[_NREG_BLKS];
	bus_dma_tag_t			parent_dmat;
	bus_dma_tag_t			cntrol_dmat;
	bus_dmamap_t			cntrol_dmap;
	bus_dmamap_t			*dmaps;
};

static u_long ispunit;

static struct pci_device isp_pci_driver = {
	"isp",
	isp_pci_probe,
	isp_pci_attach,
	&ispunit,
	NULL
};
COMPAT_PCI_DRIVER (isp_pci, isp_pci_driver);


static const char *
isp_pci_probe(pcici_t tag, pcidi_t type)
{
	static int oneshot = 1;
	char *x;

        switch (type) {
#ifndef	ISP_DISABLE_1020_SUPPORT
	case PCI_QLOGIC_ISP:
		x = "Qlogic ISP 1020/1040 PCI SCSI Adapter";
		break;
#endif
#ifndef	ISP_DISABLE_1080_SUPPORT
	case PCI_QLOGIC_ISP1080:
		x = "Qlogic ISP 1080 PCI SCSI Adapter";
		break;
	case PCI_QLOGIC_ISP1240:
		x = "Qlogic ISP 1240 PCI SCSI Adapter";
		break;
	case PCI_QLOGIC_ISP1280:
		x = "Qlogic ISP 1280 PCI SCSI Adapter";
		break;
#endif
#ifndef	ISP_DISABLE_2100_SUPPORT
	case PCI_QLOGIC_ISP2100:
		x = "Qlogic ISP 2100 PCI FC-AL Adapter";
		break;
#endif
#ifndef	ISP_DISABLE_2200_SUPPORT
	case PCI_QLOGIC_ISP2200:
		x = "Qlogic ISP 2200 PCI FC-AL Adapter";
		break;
#endif
	default:
		return (NULL);
	}
	if (oneshot) {
		oneshot = 0;
		CFGPRINTF("Qlogic ISP Driver, FreeBSD Version %d.%d, "
		    "Core Version %d.%d\n",
		    ISP_PLATFORM_VERSION_MAJOR, ISP_PLATFORM_VERSION_MINOR,
		    ISP_CORE_VERSION_MAJOR, ISP_CORE_VERSION_MINOR);
	}
	return (x);
}

static void
isp_pci_attach(pcici_t cfid, int unit)
{
#ifdef	SCSI_ISP_WWN
	const char *name = SCSI_ISP_WWN;
	char *vtp = NULL;
#endif
	int mapped, prefer_mem_map, bitmap;
	pci_port_t io_port;
	u_int32_t data, rev, linesz, psize, basetype;
	struct isp_pcisoftc *pcs;
	struct ispsoftc *isp;
	vm_offset_t vaddr, paddr;
	struct ispmdvec *mdvp;
	bus_size_t lim;
	ISP_LOCKVAL_DECL;

	pcs = malloc(sizeof (struct isp_pcisoftc), M_DEVBUF, M_NOWAIT);
	if (pcs == NULL) {
		printf("isp%d: cannot allocate softc\n", unit);
		return;
	}
	bzero(pcs, sizeof (struct isp_pcisoftc));

	/*
	 * Figure out if we're supposed to skip this one.
	 */
	if (getenv_int("isp_disable", &bitmap)) {
		if (bitmap & (1 << unit)) {
			printf("isp%d: not configuring\n", unit);
			return;
		}
	}

	/*
	 * Figure out which we should try first - memory mapping or i/o mapping?
	 */
#if	SCSI_ISP_PREFER_MEM_MAP == 1
	prefer_mem_map = 1;
#else
	prefer_mem_map = 0;
#endif
	bitmap = 0;
	if (getenv_int("isp_mem_map", &bitmap)) {
		if (bitmap & (1 << unit))
			prefer_mem_map = 1;
	}
	bitmap = 0;
	if (getenv_int("isp_io_map", &bitmap)) {
		if (bitmap & (1 << unit))
			prefer_mem_map = 0;
	}

	vaddr = paddr = NULL;
	mapped = 0;
	linesz = PCI_DFLT_LNSZ;
	/*
	 * Note that pci_conf_read is a 32 bit word aligned function.
	 */
	data = pci_conf_read(cfid, PCIR_COMMAND);
	if (prefer_mem_map) {
		if (data & PCI_COMMAND_MEM_ENABLE) {
			if (pci_map_mem(cfid, MEM_MAP_REG, &vaddr, &paddr)) {
				pcs->pci_st = MEM_SPACE_MAPPING;
				pcs->pci_sh = vaddr;
				mapped++;
			}
		}
		if (mapped == 0 && (data & PCI_COMMAND_IO_ENABLE)) {
			if (pci_map_port(cfid, PCI_MAP_REG_START, &io_port)) {
				pcs->pci_st = IO_SPACE_MAPPING;
				pcs->pci_sh = io_port;
				mapped++;
			}
		}
	} else {
		if (data & PCI_COMMAND_IO_ENABLE) {
			if (pci_map_port(cfid, PCI_MAP_REG_START, &io_port)) {
				pcs->pci_st = IO_SPACE_MAPPING;
				pcs->pci_sh = io_port;
				mapped++;
			}
		}
		if (mapped == 0 && (data & PCI_COMMAND_MEM_ENABLE)) {
			if (pci_map_mem(cfid, MEM_MAP_REG, &vaddr, &paddr)) {
				pcs->pci_st = MEM_SPACE_MAPPING;
				pcs->pci_sh = vaddr;
				mapped++;
			}
		}
	}
	if (mapped == 0) {
		printf("isp%d: unable to map any ports!\n", unit);
		free(pcs, M_DEVBUF);
		return;
	}
	if (bootverbose)
		printf("isp%d: using %s space register mapping\n", unit,
		    pcs->pci_st == IO_SPACE_MAPPING? "I/O" : "Memory");

	data = pci_conf_read(cfid, PCI_ID_REG);
	rev = pci_conf_read(cfid, PCI_CLASS_REG) & 0xff;	/* revision */
	pcs->pci_poff[BIU_BLOCK >> _BLK_REG_SHFT] = BIU_REGS_OFF;
	pcs->pci_poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS_OFF;
	pcs->pci_poff[SXP_BLOCK >> _BLK_REG_SHFT] = PCI_SXP_REGS_OFF;
	pcs->pci_poff[RISC_BLOCK >> _BLK_REG_SHFT] = PCI_RISC_REGS_OFF;
	pcs->pci_poff[DMA_BLOCK >> _BLK_REG_SHFT] = DMA_REGS_OFF;
	/*
 	 * GCC!
	 */
	mdvp = &mdvec;
	basetype = ISP_HA_SCSI_UNKNOWN;
	psize = sizeof (sdparam);
	lim = BUS_SPACE_MAXSIZE_32BIT;
#ifndef	ISP_DISABLE_1020_SUPPORT
	if (data == PCI_QLOGIC_ISP) {
		mdvp = &mdvec;
		basetype = ISP_HA_SCSI_UNKNOWN;
		psize = sizeof (sdparam);
		lim = BUS_SPACE_MAXSIZE_24BIT;
	}
#endif
#ifndef	ISP_DISABLE_1080_SUPPORT
	if (data == PCI_QLOGIC_ISP1080) {
		mdvp = &mdvec_1080;
		basetype = ISP_HA_SCSI_1080;
		psize = sizeof (sdparam);
		pcs->pci_poff[DMA_BLOCK >> _BLK_REG_SHFT] =
		    ISP1080_DMA_REGS_OFF;
	}
	if (data == PCI_QLOGIC_ISP1240) {
		mdvp = &mdvec_1080;
		basetype = ISP_HA_SCSI_1240;
		psize = 2 * sizeof (sdparam);
		pcs->pci_poff[DMA_BLOCK >> _BLK_REG_SHFT] =
		    ISP1080_DMA_REGS_OFF;
	}
	if (data == PCI_QLOGIC_ISP1280) {
		mdvp = &mdvec_1080;
		basetype = ISP_HA_SCSI_1280;
		psize = 2 * sizeof (sdparam);
		pcs->pci_poff[DMA_BLOCK >> _BLK_REG_SHFT] =
		    ISP1080_DMA_REGS_OFF;
	}
#endif
#ifndef	ISP_DISABLE_2100_SUPPORT
	if (data == PCI_QLOGIC_ISP2100) {
		mdvp = &mdvec_2100;
		basetype = ISP_HA_FC_2100;
		psize = sizeof (fcparam);
		pcs->pci_poff[MBOX_BLOCK >> _BLK_REG_SHFT] =
		    PCI_MBOX_REGS2100_OFF;
		if (rev < 3) {
			/*
			 * XXX: Need to get the actual revision
			 * XXX: number of the 2100 FB. At any rate,
			 * XXX: lower cache line size for early revision
			 * XXX; boards.
			 */
			linesz = 1;
		}
	}
#endif
#ifndef	ISP_DISABLE_2200_SUPPORT
	if (data == PCI_QLOGIC_ISP2200) {
		mdvp = &mdvec_2200;
		basetype = ISP_HA_FC_2200;
		psize = sizeof (fcparam);
		pcs->pci_poff[MBOX_BLOCK >> _BLK_REG_SHFT] =
		    PCI_MBOX_REGS2100_OFF;
	}
#endif
	isp = &pcs->pci_isp;
	isp->isp_param = malloc(psize, M_DEVBUF, M_NOWAIT);
	if (isp->isp_param == NULL) {
		printf("isp%d: cannot allocate parameter data\n", unit);
		return;
	}
	bzero(isp->isp_param, psize);
	isp->isp_mdvec = mdvp;
	isp->isp_type = basetype;
	isp->isp_revision = rev;
	(void) snprintf(isp->isp_name, sizeof (isp->isp_name), "isp%d", unit);
	isp->isp_osinfo.unit = unit;

	ISP_LOCK(isp);

	/*
	 * Make sure that SERR, PERR, WRITE INVALIDATE and BUSMASTER
	 * are set.
	 */
	data = pci_cfgread(cfid, PCIR_COMMAND, 2);
	data |=	PCIM_CMD_SEREN		|
		PCIM_CMD_PERRESPEN	|
		PCIM_CMD_BUSMASTEREN	|
		PCIM_CMD_INVEN;
	pci_cfgwrite(cfid, PCIR_COMMAND, 2, data);

	/*
	 * Make sure the Cache Line Size register is set sensibly.
	 */
	data = pci_cfgread(cfid, PCIR_CACHELNSZ, 1);
	if (data != linesz) {
		data = PCI_DFLT_LNSZ;
		CFGPRINTF("%s: set PCI line size to %d\n", isp->isp_name, data);
		pci_cfgwrite(cfid, PCIR_CACHELNSZ, data, 1);
	}

	/*
	 * Make sure the Latency Timer is sane.
	 */
	data = pci_cfgread(cfid, PCIR_LATTIMER, 1);
	if (data < PCI_DFLT_LTNCY) {
		data = PCI_DFLT_LTNCY;
		CFGPRINTF("%s: set PCI latency to %d\n", isp->isp_name, data);
		pci_cfgwrite(cfid, PCIR_LATTIMER, data, 1);
	}

	/*
	 * Make sure we've disabled the ROM.
	 */
	data = pci_cfgread(cfid, PCIR_ROMADDR, 4);
	data &= ~1;
	pci_cfgwrite(cfid, PCIR_ROMADDR, data, 4);
	ISP_UNLOCK(isp);

	if (bus_dma_tag_create(NULL, 1, 0, BUS_SPACE_MAXADDR_32BIT,
	    BUS_SPACE_MAXADDR, NULL, NULL, lim + 1,
	    255, lim, 0, &pcs->parent_dmat) != 0) {
		printf("%s: could not create master dma tag\n", isp->isp_name);
		free(pcs, M_DEVBUF);
		return;
	}
	if (pci_map_int(cfid, (void (*)(void *))isp_intr,
	    (void *)isp, &IMASK) == 0) {
		printf("%s: could not map interrupt\n", isp->isp_name);
		free(pcs, M_DEVBUF);
		return;
	}

	pcs->pci_id = cfid;
#ifdef	SCSI_ISP_NO_FWLOAD_MASK
	if (SCSI_ISP_NO_FWLOAD_MASK && (SCSI_ISP_NO_FWLOAD_MASK & (1 << unit)))
		isp->isp_confopts |= ISP_CFG_NORELOAD;
#endif
	if (getenv_int("isp_no_fwload", &bitmap)) {
		if (bitmap & (1 << unit))
			isp->isp_confopts |= ISP_CFG_NORELOAD;
	}
	if (getenv_int("isp_fwload", &bitmap)) {
		if (bitmap & (1 << unit))
			isp->isp_confopts &= ~ISP_CFG_NORELOAD;
	}

#ifdef	SCSI_ISP_NO_NVRAM_MASK
	if (SCSI_ISP_NO_NVRAM_MASK && (SCSI_ISP_NO_NVRAM_MASK & (1 << unit))) {
		printf("%s: ignoring NVRAM\n", isp->isp_name);
		isp->isp_confopts |= ISP_CFG_NONVRAM;
	}
#endif
	if (getenv_int("isp_no_nvram", &bitmap)) {
		if (bitmap & (1 << unit))
			isp->isp_confopts |= ISP_CFG_NONVRAM;
	}
	if (getenv_int("isp_nvram", &bitmap)) {
		if (bitmap & (1 << unit))
			isp->isp_confopts &= ~ISP_CFG_NONVRAM;
	}

#ifdef	SCSI_ISP_FCDUPLEX
	if (IS_FC(isp)) {
		if (SCSI_ISP_FCDUPLEX && (SCSI_ISP_FCDUPLEX & (1 << unit))) {
			isp->isp_confopts |= ISP_CFG_FULL_DUPLEX;
		}
	}
#endif
	if (getenv_int("isp_fcduplex", &bitmap)) {
		if (bitmap & (1 << unit))
			isp->isp_confopts |= ISP_CFG_FULL_DUPLEX;
	}
	if (getenv_int("isp_no_fcduplex", &bitmap)) {
		if (bitmap & (1 << unit))
			isp->isp_confopts &= ~ISP_CFG_FULL_DUPLEX;
	}
	/*
	 * Look for overriding WWN. This is a Node WWN so it binds to
	 * all FC instances. A Port WWN will be constructed from it
	 * as appropriate.
	 */
#ifdef	SCSI_ISP_WWN
	isp->isp_osinfo.default_wwn = strtoq(name, &vtp, 16);
	if (vtp != name && *vtp == 0) {
		isp->isp_confopts |= ISP_CFG_OWNWWN;
	} else
#endif
	if (!getenv_quad("isp_wwn", (quad_t *) &isp->isp_osinfo.default_wwn)) {
		int i;
		u_int64_t seed = (u_int64_t) (intptr_t) isp;

		seed <<= 16;
		seed &= ((1LL << 48) - 1LL);
		/*
		 * This isn't very random, but it's the best we can do for
		 * the real edge case of cards that don't have WWNs. If
		 * you recompile a new vers.c, you'll get a different WWN.
		 */
		for (i = 0; version[i] != 0; i++) {
			seed += version[i];
		}
		/*
		 * Make sure the top nibble has something vaguely sensible.
		 */
		isp->isp_osinfo.default_wwn |= (4LL << 60) | seed;
	} else {
		isp->isp_confopts |= ISP_CFG_OWNWWN;
	}
	(void) getenv_int("isp_debug", &isp_debug);
#ifdef	ISP_TARGET_MODE
	(void) getenv_int("isp_tdebug", &isp_tdebug);
#endif
	ISP_LOCK(isp);
	isp_reset(isp);
	if (isp->isp_state != ISP_RESETSTATE) {
		(void) pci_unmap_int(cfid);
		ISP_UNLOCK(isp);
		free(pcs, M_DEVBUF);
		return;
	}
	isp_init(isp);
	if (isp->isp_state != ISP_INITSTATE) {
		/* If we're a Fibre Channel Card, we allow deferred attach */
		if (IS_SCSI(isp)) {
			isp_uninit(isp);
			(void) pci_unmap_int(cfid); /* Does nothing */
			ISP_UNLOCK(isp);
			free(pcs, M_DEVBUF);
			return;
		}
	}
	isp_attach(isp);
	if (isp->isp_state != ISP_RUNSTATE) {
		/* If we're a Fibre Channel Card, we allow deferred attach */
		if (IS_SCSI(isp)) {
			isp_uninit(isp);
			(void) pci_unmap_int(cfid); /* Does nothing */
			ISP_UNLOCK(isp);
			free(pcs, M_DEVBUF);
			return;
		}
	}
	ISP_UNLOCK(isp);
}

static u_int16_t
isp_pci_rd_reg(isp, regoff)
	struct ispsoftc *isp;
	int regoff;
{
	u_int16_t rv;
	struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
	int offset, oldconf = 0;

	if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
		/*
		 * We will assume that someone has paused the RISC processor.
		 */
		oldconf = isp_pci_rd_reg(isp, BIU_CONF1);
		isp_pci_wr_reg(isp, BIU_CONF1, oldconf | BIU_PCI_CONF1_SXP);
	}
	offset = pcs->pci_poff[(regoff & _BLK_REG_MASK) >> _BLK_REG_SHFT];
	offset += (regoff & 0xff);
	rv = bus_space_read_2(pcs->pci_st, pcs->pci_sh, offset);
	if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
		isp_pci_wr_reg(isp, BIU_CONF1, oldconf);
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
	int offset, oldconf = 0;

	if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
		/*
		 * We will assume that someone has paused the RISC processor.
		 */
		oldconf = isp_pci_rd_reg(isp, BIU_CONF1);
		isp_pci_wr_reg(isp, BIU_CONF1, oldconf | BIU_PCI_CONF1_SXP);
	}
	offset = pcs->pci_poff[(regoff & _BLK_REG_MASK) >> _BLK_REG_SHFT];
	offset += (regoff & 0xff);
	bus_space_write_2(pcs->pci_st, pcs->pci_sh, offset, val);
	if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
		isp_pci_wr_reg(isp, BIU_CONF1, oldconf);
	}
}

#ifndef	ISP_DISABLE_1080_SUPPORT
static u_int16_t
isp_pci_rd_reg_1080(isp, regoff)
	struct ispsoftc *isp;
	int regoff;
{
	u_int16_t rv, oc = 0;
	struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
	int offset;

	if ((regoff & _BLK_REG_MASK) == SXP_BLOCK ||
	    (regoff & _BLK_REG_MASK) == (SXP_BLOCK|SXP_BANK1_SELECT)) {
		u_int16_t tc;
		/*
		 * We will assume that someone has paused the RISC processor.
		 */
		oc = isp_pci_rd_reg(isp, BIU_CONF1);
		tc = oc & ~BIU_PCI1080_CONF1_DMA;
		if (regoff & SXP_BANK1_SELECT)
			tc |= BIU_PCI1080_CONF1_SXP1;
		else
			tc |= BIU_PCI1080_CONF1_SXP0;
		isp_pci_wr_reg(isp, BIU_CONF1, tc);
	} else if ((regoff & _BLK_REG_MASK) == DMA_BLOCK) {
		oc = isp_pci_rd_reg(isp, BIU_CONF1);
		isp_pci_wr_reg(isp, BIU_CONF1, oc | BIU_PCI1080_CONF1_DMA);
	}
	offset = pcs->pci_poff[(regoff & _BLK_REG_MASK) >> _BLK_REG_SHFT];
	offset += (regoff & 0xff);
	rv = bus_space_read_2(pcs->pci_st, pcs->pci_sh, offset);
	if (oc) {
		isp_pci_wr_reg(isp, BIU_CONF1, oc);
	}
	return (rv);
}

static void
isp_pci_wr_reg_1080(isp, regoff, val)
	struct ispsoftc *isp;
	int regoff;
	u_int16_t val;
{
	struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
	int offset, oc = 0;

	if ((regoff & _BLK_REG_MASK) == SXP_BLOCK ||
	    (regoff & _BLK_REG_MASK) == (SXP_BLOCK|SXP_BANK1_SELECT)) {
		u_int16_t tc;
		/*
		 * We will assume that someone has paused the RISC processor.
		 */
		oc = isp_pci_rd_reg(isp, BIU_CONF1);
		tc = oc & ~BIU_PCI1080_CONF1_DMA;
		if (regoff & SXP_BANK1_SELECT)
			tc |= BIU_PCI1080_CONF1_SXP1;
		else
			tc |= BIU_PCI1080_CONF1_SXP0;
		isp_pci_wr_reg(isp, BIU_CONF1, tc);
	} else if ((regoff & _BLK_REG_MASK) == DMA_BLOCK) {
		oc = isp_pci_rd_reg(isp, BIU_CONF1);
		isp_pci_wr_reg(isp, BIU_CONF1, oc | BIU_PCI1080_CONF1_DMA);
	}
	offset = pcs->pci_poff[(regoff & _BLK_REG_MASK) >> _BLK_REG_SHFT];
	offset += (regoff & 0xff);
	bus_space_write_2(pcs->pci_st, pcs->pci_sh, offset, val);
	if (oc) {
		isp_pci_wr_reg(isp, BIU_CONF1, oc);
	}
}
#endif


static void isp_map_rquest __P((void *, bus_dma_segment_t *, int, int));
static void isp_map_result __P((void *, bus_dma_segment_t *, int, int));
static void isp_map_fcscrt __P((void *, bus_dma_segment_t *, int, int));

struct imush {
	struct ispsoftc *isp;
	int error;
};

static void
isp_map_rquest(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct imush *imushp = (struct imush *) arg;
	if (error) {
		imushp->error = error;
	} else {
		imushp->isp->isp_rquest_dma = segs->ds_addr;
	}
}

static void
isp_map_result(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct imush *imushp = (struct imush *) arg;
	if (error) {
		imushp->error = error;
	} else {
		imushp->isp->isp_result_dma = segs->ds_addr;
	}
}

static void
isp_map_fcscrt(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct imush *imushp = (struct imush *) arg;
	if (error) {
		imushp->error = error;
	} else {
		fcparam *fcp = imushp->isp->isp_param;
		fcp->isp_scdma = segs->ds_addr;
	}
}

static int
isp_pci_mbxdma(struct ispsoftc *isp)
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	caddr_t base;
	u_int32_t len;
	int i, error;
	bus_size_t lim;
	struct imush im;


	/*
	 * Already been here? If so, leave...
	 */
	if (isp->isp_rquest) {
		return (0);
	}

	len = sizeof (ISP_SCSI_XFER_T **) * isp->isp_maxcmds;
	isp->isp_xflist = (ISP_SCSI_XFER_T **) malloc(len, M_DEVBUF, M_WAITOK);
	if (isp->isp_xflist == NULL) {
		printf("%s: can't alloc xflist array\n", isp->isp_name);
		return (1);
	}
	bzero(isp->isp_xflist, len);
	len = sizeof (bus_dmamap_t) * isp->isp_maxcmds;
	pci->dmaps = (bus_dmamap_t *) malloc(len, M_DEVBUF,  M_WAITOK);
	if (pci->dmaps == NULL) {
		printf("%s: can't alloc dma maps\n", isp->isp_name);
		free(isp->isp_xflist, M_DEVBUF);
		return (1);
	}

	if (IS_FC(isp) || IS_ULTRA2(isp))
		lim = BUS_SPACE_MAXADDR + 1;
	else
		lim = BUS_SPACE_MAXADDR_24BIT + 1;

	/*
	 * Allocate and map the request, result queues, plus FC scratch area.
	 */
	len = ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN);
	len += ISP_QUEUE_SIZE(RESULT_QUEUE_LEN);
	if (IS_FC(isp)) {
		len += ISP2100_SCRLEN;
	}
	if (bus_dma_tag_create(pci->parent_dmat, PAGE_SIZE, lim,
	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL, len, 1,
	    BUS_SPACE_MAXSIZE_32BIT, 0, &pci->cntrol_dmat) != 0) {
		printf("%s: cannot create a dma tag for control spaces\n",
		    isp->isp_name);
		free(isp->isp_xflist, M_DEVBUF);
		free(pci->dmaps, M_DEVBUF);
		return (1);
	}
	if (bus_dmamem_alloc(pci->cntrol_dmat, (void **)&base,
	    BUS_DMA_NOWAIT, &pci->cntrol_dmap) != 0) {
		printf("%s: cannot allocate %d bytes of CCB memory\n",
		    isp->isp_name, len);
		free(isp->isp_xflist, M_DEVBUF);
		free(pci->dmaps, M_DEVBUF);
		return (1);
	}

	isp->isp_rquest = base;
	im.isp = isp;
	im.error = 0;
	bus_dmamap_load(pci->cntrol_dmat, pci->cntrol_dmap, isp->isp_rquest,
	    ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN), isp_map_rquest, &im, 0);
	if (im.error) {
		printf("%s: error %d loading dma map for DMA request queue\n",
		    isp->isp_name, im.error);
		free(isp->isp_xflist, M_DEVBUF);
		free(pci->dmaps, M_DEVBUF);
		isp->isp_rquest = NULL;
		return (1);
	}
	isp->isp_result = base + ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN);
	im.error = 0;
	bus_dmamap_load(pci->cntrol_dmat, pci->cntrol_dmap, isp->isp_result,
	    ISP_QUEUE_SIZE(RESULT_QUEUE_LEN), isp_map_result, &im, 0);
	if (im.error) {
		printf("%s: error %d loading dma map for DMA result queue\n",
		    isp->isp_name, im.error);
		free(isp->isp_xflist, M_DEVBUF);
		free(pci->dmaps, M_DEVBUF);
		isp->isp_rquest = NULL;
		return (1);
	}

	for (i = 0; i < isp->isp_maxcmds; i++) {
		error = bus_dmamap_create(pci->parent_dmat, 0, &pci->dmaps[i]);
		if (error) {
			printf("%s: error %d creating per-cmd DMA maps\n",
			    isp->isp_name, error);
			free(isp->isp_xflist, M_DEVBUF);
			free(pci->dmaps, M_DEVBUF);
			isp->isp_rquest = NULL;
			return (1);
		}
	}

	if (IS_FC(isp)) {
		fcparam *fcp = (fcparam *) isp->isp_param;
		fcp->isp_scratch = base +
			ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN) +
			ISP_QUEUE_SIZE(RESULT_QUEUE_LEN);
		im.error = 0;
		bus_dmamap_load(pci->cntrol_dmat, pci->cntrol_dmap,
		    fcp->isp_scratch, ISP2100_SCRLEN, isp_map_fcscrt, &im, 0);
		if (im.error) {
			printf("%s: error %d loading FC scratch area\n",
			    isp->isp_name, im.error);
			free(isp->isp_xflist, M_DEVBUF);
			free(pci->dmaps, M_DEVBUF);
			isp->isp_rquest = NULL;
			return (1);
		}
	}
	return (0);
}

typedef struct {
	struct ispsoftc *isp;
	void *cmd_token;
	void *rq;
	u_int16_t *iptrp;
	u_int16_t optr;
	u_int error;
} mush_t;

#define	MUSHERR_NOQENTRIES	-2

#ifdef	ISP_TARGET_MODE
/*
 * We need to handle DMA for target mode differently from initiator mode.
 * 
 * DMA mapping and construction and submission of CTIO Request Entries
 * and rendevous for completion are very tightly coupled because we start
 * out by knowing (per platform) how much data we have to move, but we
 * don't know, up front, how many DMA mapping segments will have to be used
 * cover that data, so we don't know how many CTIO Request Entries we
 * will end up using. Further, for performance reasons we may want to
 * (on the last CTIO for Fibre Channel), send status too (if all went well).
 *
 * The standard vector still goes through isp_pci_dmasetup, but the callback
 * for the DMA mapping routines comes here instead with the whole transfer
 * mapped and a pointer to a partially filled in already allocated request
 * queue entry. We finish the job.
 */
static void dma2_tgt __P((void *, bus_dma_segment_t *, int, int));
static void dma2_tgt_fc __P((void *, bus_dma_segment_t *, int, int));

static void
dma2_tgt(void *arg, bus_dma_segment_t *dm_segs, int nseg, int error)
{
	mush_t *mp;
	struct ccb_scsiio *csio;
	struct isp_pcisoftc *pci;
	bus_dmamap_t *dp;
	u_int8_t scsi_status, send_status;
	ct_entry_t *cto;
	u_int32_t handle;
	int nctios;

	mp = (mush_t *) arg;
	if (error) {
		mp->error = error;
		return;
	}

	csio = mp->cmd_token;
	cto = mp->rq;

	cto->ct_xfrlen = 0;
	cto->ct_resid = 0;
	cto->ct_seg_count = 0;
	bzero(cto->ct_dataseg, sizeof (cto->ct_dataseg));
	if (nseg == 0) {
	 	cto->ct_header.rqs_entry_count = 1;
		ISP_TDQE(mp->isp, "dma2_tgt[no data]", *mp->iptrp, cto);
		if (isp_tdebug) {
			printf("%s:CTIO lun %d->iid%d flgs 0x%x sts 0x%x ssts "
			    "0x%x res %u\n", mp->isp->isp_name,
			    csio->ccb_h.target_lun, cto->ct_iid, cto->ct_flags,
			    cto->ct_status, cto->ct_scsi_status, cto->ct_resid);
		}
		ISP_SWIZ_CTIO(isp, cto, cto);
		return;
	}

	/*
	 * Save handle, and potentially any SCSI status, which
	 * we'll reinsert on the last CTIO we're going to send.
	 */
	handle = cto->ct_reserved;
	cto->ct_reserved = 0;
	scsi_status = cto->ct_scsi_status;
	cto->ct_scsi_status = 0;
	send_status = cto->ct_flags & CT_SENDSTATUS;
	cto->ct_flags &= ~CT_SENDSTATUS;

	nctios = nseg / ISP_RQDSEG;
	if (nseg % ISP_RQDSEG) {
		nctios++;
	}

	pci = (struct isp_pcisoftc *)mp->isp;
	dp = &pci->dmaps[handle - 1];
	if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREREAD);
	} else {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREWRITE);
	}


	while (nctios--) {
		int seg, seglim;

		seglim = nseg;
		if (seglim > ISP_RQDSEG)
			seglim = ISP_RQDSEG;

		for (seg = 0; seg < seglim; seg++) {
			cto->ct_dataseg[seg].ds_base = dm_segs->ds_addr;
			cto->ct_dataseg[seg].ds_count = dm_segs->ds_len;
			cto->ct_xfrlen += dm_segs->ds_len;
			dm_segs++;
		}

		cto->ct_seg_count = seg;
		cto->ct_flags &= CT_DATAMASK;
		if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
			cto->ct_flags |= CT_DATA_IN;
		} else {
			cto->ct_flags |= CT_DATA_OUT;
		}

		if (nctios == 0) {
			/*
			 * We're the last in a sequence of CTIOs, so mark this
			 * CTIO and save the handle to the CCB such that when
			 * this CTIO completes we can free dma resources and
			 * do whatever else we need to do to finish the rest
			 * of the command.
			 */
			cto->ct_header.rqs_seqno = 1;
			cto->ct_reserved = handle;
			cto->ct_scsi_status = scsi_status;
			cto->ct_flags |= send_status;
			ISP_TDQE(mp->isp, "last dma2_tgt", *mp->iptrp, cto);
			if (isp_tdebug) {
				printf("%s:CTIO lun %d->iid%d flgs 0x%x sts "
				    "0x%x ssts 0x%x res %u\n",
				    mp->isp->isp_name, csio->ccb_h.target_lun,
				    cto->ct_iid, cto->ct_flags, cto->ct_status,
				    cto->ct_scsi_status, cto->ct_resid);
			}
			ISP_SWIZ_CTIO(isp, cto, cto);
		} else {
			ct_entry_t *octo = cto;
			cto->ct_reserved = 0;
			cto->ct_header.rqs_seqno = 0;
			ISP_TDQE(mp->isp, "dma2_tgt", *mp->iptrp, cto);
			if (isp_tdebug) {
				printf("%s:CTIO lun %d->iid%d flgs 0x%x res"
				    " %u\n", mp->isp->isp_name,
				    csio->ccb_h.target_lun, cto->ct_iid,
				    cto->ct_flags, cto->ct_resid);
			}
			cto = (ct_entry_t *)
			    ISP_QUEUE_ENTRY(mp->isp->isp_rquest, *mp->iptrp);
			*mp->iptrp =
			    ISP_NXT_QENTRY(*mp->iptrp, RQUEST_QUEUE_LEN);
			if (*mp->iptrp == mp->optr) {
				printf("%s: Queue Overflow in dma2_tgt\n",
				    mp->isp->isp_name);
				mp->error = MUSHERR_NOQENTRIES;
				return;
			}
			/*
			 * Fill in the new CTIO with info from the old one.
			 */
			cto->ct_header.rqs_entry_type = RQSTYPE_CTIO;
			cto->ct_header.rqs_entry_count = 1;
			cto->ct_header.rqs_flags = 0;
			/* ct_header.rqs_seqno && ct_reserved filled in later */
			cto->ct_lun = octo->ct_lun;
			cto->ct_iid = octo->ct_iid;
			cto->ct_reserved2 = octo->ct_reserved2;
			cto->ct_tgt = octo->ct_tgt;
			cto->ct_flags = octo->ct_flags & ~CT_DATAMASK;
			cto->ct_status = 0;
			cto->ct_scsi_status = 0;
			cto->ct_tag_val = octo->ct_tag_val;
			cto->ct_tag_type = octo->ct_tag_type;
			cto->ct_xfrlen = 0;
			cto->ct_resid = 0;
			cto->ct_timeout = octo->ct_timeout;
			cto->ct_seg_count = 0;
			bzero(cto->ct_dataseg, sizeof (cto->ct_dataseg));
			ISP_SWIZ_CTIO(isp, octo, octo);
		}
	}
}

static void
dma2_tgt_fc(void *arg, bus_dma_segment_t *dm_segs, int nseg, int error)
{
	mush_t *mp;
	struct ccb_scsiio *csio;
	struct isp_pcisoftc *pci;
	bus_dmamap_t *dp;
	ct2_entry_t *cto;
	u_int16_t scsi_status, send_status, send_sense;
	u_int32_t handle, totxfr;
	u_int8_t sense[QLTM_SENSELEN];
	int nctios;
	int32_t resid;

	mp = (mush_t *) arg;
	if (error) {
		mp->error = error;
		return;
	}

	csio = mp->cmd_token;
	cto = mp->rq;

	if (nseg == 0) {
		if ((cto->ct_flags & CT2_FLAG_MMASK) != CT2_FLAG_MODE1) {
			printf("%s: dma2_tgt_fc, a status CTIO2 without MODE1 "
			    "set (0x%x)\n", mp->isp->isp_name, cto->ct_flags);
			mp->error = EINVAL;
			return;
		}
	 	cto->ct_header.rqs_entry_count = 1;
		/* ct_reserved contains the handle set by caller */
		/*
		 * We preserve ct_lun, ct_iid, ct_rxid. We set the data
		 * flags to NO DATA and clear relative offset flags.
		 * We preserve the ct_resid and the response area.
		 */
		cto->ct_flags |= CT2_NO_DATA;
		cto->ct_seg_count = 0;
		cto->ct_reloff = 0;
		ISP_TDQE(mp->isp, "dma2_tgt_fc[no data]", *mp->iptrp, cto);
		if (isp_tdebug) {
			scsi_status = cto->rsp.m1.ct_scsi_status;
			printf("%s:CTIO2 RX_ID 0x%x lun %d->iid%d flgs 0x%x "
			    "sts 0x%x ssts 0x%x res %u\n", mp->isp->isp_name,
			    cto->ct_rxid, csio->ccb_h.target_lun, cto->ct_iid,
			    cto->ct_flags, cto->ct_status,
			    cto->rsp.m1.ct_scsi_status, cto->ct_resid);
		}
		ISP_SWIZ_CTIO2(isp, cto, cto);
		return;
	}

	if ((cto->ct_flags & CT2_FLAG_MMASK) != CT2_FLAG_MODE0) {
		printf("%s: dma2_tgt_fc, a data CTIO2 without MODE0 set "
		    "(0x%x)\n\n", mp->isp->isp_name, cto->ct_flags);
		mp->error = EINVAL;
		return;
	}


	nctios = nseg / ISP_RQDSEG_T2;
	if (nseg % ISP_RQDSEG_T2) {
		nctios++;
	}

	/*
	 * Save the handle, status, reloff, and residual. We'll reinsert the
	 * handle into the last CTIO2 we're going to send, and reinsert status
	 * and residual (and possibly sense data) if that's to be sent as well.
	 *
	 * We preserve ct_reloff and adjust it for each data CTIO2 we send past
	 * the first one. This is needed so that the FCP DATA IUs being sent
	 * out have the correct offset (they can arrive at the other end out
	 * of order).
	 */

	handle = cto->ct_reserved;
	cto->ct_reserved = 0;

	if ((send_status = (cto->ct_flags & CT2_SENDSTATUS)) != 0) {
		cto->ct_flags &= ~CT2_SENDSTATUS;

		/*
		 * Preserve residual.
		 */
		resid = cto->ct_resid;

		/*
		 * Save actual SCSI status. We'll reinsert the
		 * CT2_SNSLEN_VALID later if appropriate.
		 */
		scsi_status = cto->rsp.m0.ct_scsi_status & 0xff;
		send_sense = cto->rsp.m0.ct_scsi_status & CT2_SNSLEN_VALID;

		/*
		 * If we're sending status and have a CHECK CONDTION and
		 * have sense data,  we send one more CTIO2 with just the
		 * status and sense data. The upper layers have stashed
		 * the sense data in the dataseg structure for us.
		 */

		if ((scsi_status & 0xf) == SCSI_STATUS_CHECK_COND &&
		    send_sense) {
			bcopy(cto->rsp.m0.ct_dataseg, sense, QLTM_SENSELEN);
			nctios++;
		}
	} else {
		scsi_status = send_sense = resid = 0;
	}

	totxfr = cto->ct_resid = 0;
	cto->rsp.m0.ct_scsi_status = 0;
	bzero(&cto->rsp, sizeof (cto->rsp));

	pci = (struct isp_pcisoftc *)mp->isp;
	dp = &pci->dmaps[handle - 1];
	if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREREAD);
	} else {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREWRITE);
	}

	while (nctios--) {
		int seg, seglim;

		seglim = nseg;
		if (seglim) {
			if (seglim > ISP_RQDSEG_T2)
				seglim = ISP_RQDSEG_T2;

			for (seg = 0; seg < seglim; seg++) {
				cto->rsp.m0.ct_dataseg[seg].ds_base =
				    dm_segs->ds_addr;
				cto->rsp.m0.ct_dataseg[seg].ds_count =
				    dm_segs->ds_len;
				cto->rsp.m0.ct_xfrlen += dm_segs->ds_len;
				totxfr += dm_segs->ds_len;
				dm_segs++;
			}
			cto->ct_seg_count = seg;
		} else {
			/*
			 * This case should only happen when we're sending a
			 * synthesized MODE1 final status with sense data.
			 */
			if (send_sense == 0) {
				printf("%s: dma2_tgt_fc ran out of segments, "
				    "no SENSE DATA\n", mp->isp->isp_name);
				mp->error = EINVAL;
				return;
			}
		}

		/*
		 * At this point, the fields ct_lun, ct_iid, ct_rxid,
		 * ct_timeout have been carried over unchanged from what
		 * our caller had set.
		 *
		 * The field ct_reloff is either what the caller set, or
		 * what we've added to below.
		 *
		 * The dataseg fields and the seg_count fields we just got
		 * through setting. The data direction we've preserved all
		 * along and only clear it if we're sending a MODE1 status
		 * as the last CTIO.
		 *
		 */

		if (nctios == 0) {

			/*
			 * We're the last in a sequence of CTIO2s, so mark this
			 * CTIO2 and save the handle to the CCB such that when
			 * this CTIO2 completes we can free dma resources and
			 * do whatever else we need to do to finish the rest
			 * of the command.
			 */

			cto->ct_reserved = handle;
			cto->ct_header.rqs_seqno = 1;

			if (send_status) {
				if (send_sense) {
					bcopy(sense, cto->rsp.m1.ct_resp,
					    QLTM_SENSELEN);
					cto->rsp.m1.ct_senselen =
					    QLTM_SENSELEN;
					scsi_status |= CT2_SNSLEN_VALID;
					cto->rsp.m1.ct_scsi_status =
					    scsi_status;
					cto->ct_flags &= CT2_FLAG_MMASK;
					cto->ct_flags |= CT2_FLAG_MODE1 |
					    CT2_NO_DATA| CT2_SENDSTATUS;
				} else {
					cto->rsp.m0.ct_scsi_status =
					    scsi_status;
					cto->ct_flags |= CT2_SENDSTATUS;
				}
				cto->ct_resid = resid - totxfr;
			}
			ISP_TDQE(mp->isp, "last dma2_tgt_fc", *mp->iptrp, cto);
			if (isp_tdebug) {
				printf("%s:CTIO2 RX_ID 0x%x lun %d->iid%d flgs"
				    "0x%x sts 0x%x ssts 0x%x res %u\n",
				    mp->isp->isp_name, cto->ct_rxid,
				    csio->ccb_h.target_lun, (int) cto->ct_iid,
				    cto->ct_flags, cto->ct_status,
				    cto->rsp.m1.ct_scsi_status, cto->ct_resid);
			}
			ISP_SWIZ_CTIO2(isp, cto, cto);
		} else {
			ct2_entry_t *octo = cto;

			/*
			 * Make sure handle fields are clean
			 */
			cto->ct_reserved = 0;
			cto->ct_header.rqs_seqno = 0;

			ISP_TDQE(mp->isp, "dma2_tgt_fc", *mp->iptrp, cto);
			if (isp_tdebug) {
				printf("%s:CTIO2 RX_ID 0x%x lun %d->iid%d flgs"
				    "0x%x\n", mp->isp->isp_name, cto->ct_rxid,
				    csio->ccb_h.target_lun, (int) cto->ct_iid,
				    cto->ct_flags);
			}
			/*
			 * Get a new CTIO2
			 */
			cto = (ct2_entry_t *)
			    ISP_QUEUE_ENTRY(mp->isp->isp_rquest, *mp->iptrp);
			*mp->iptrp =
			    ISP_NXT_QENTRY(*mp->iptrp, RQUEST_QUEUE_LEN);
			if (*mp->iptrp == mp->optr) {
				printf("%s: Queue Overflow in dma2_tgt_fc\n",
				    mp->isp->isp_name);
				mp->error = MUSHERR_NOQENTRIES;
				return;
			}

			/*
			 * Fill in the new CTIO2 with info from the old one.
			 */
			cto->ct_header.rqs_entry_type = RQSTYPE_CTIO2;
			cto->ct_header.rqs_entry_count = 1;
			cto->ct_header.rqs_flags = 0;
			/* ct_header.rqs_seqno && ct_reserved done later */
			cto->ct_lun = octo->ct_lun;
			cto->ct_iid = octo->ct_iid;
			cto->ct_rxid = octo->ct_rxid;
			cto->ct_flags = octo->ct_flags;
			cto->ct_status = 0;
			cto->ct_resid = 0;
			cto->ct_timeout = octo->ct_timeout;
			cto->ct_seg_count = 0;
			/*
			 * Adjust the new relative offset by the amount which
			 * is recorded in the data segment of the old CTIO2 we
			 * just finished filling out.
			 */
			cto->ct_reloff += octo->rsp.m0.ct_xfrlen;
			bzero(&cto->rsp, sizeof (cto->rsp));
			ISP_SWIZ_CTIO2(isp, cto, cto);
		}
	}
}
#endif

static void dma2 __P((void *, bus_dma_segment_t *, int, int));

static void
dma2(void *arg, bus_dma_segment_t *dm_segs, int nseg, int error)
{
	mush_t *mp;
	struct ccb_scsiio *csio;
	struct isp_pcisoftc *pci;
	bus_dmamap_t *dp;
	bus_dma_segment_t *eseg;
	ispreq_t *rq;
	ispcontreq_t *crq;
	int seglim, datalen;

	mp = (mush_t *) arg;
	if (error) {
		mp->error = error;
		return;
	}

	if (nseg < 1) {
		printf("%s: bad segment count (%d)\n", mp->isp->isp_name, nseg);
		mp->error = EFAULT;
		return;
	}
	csio = mp->cmd_token;
	rq = mp->rq;
	pci = (struct isp_pcisoftc *)mp->isp;
	dp = &pci->dmaps[rq->req_handle - 1];

	if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREREAD);
	} else {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_PREWRITE);
	}

	datalen = XS_XFRLEN(csio);

	/*
	 * We're passed an initial partially filled in entry that
	 * has most fields filled in except for data transfer
	 * related values.
	 *
	 * Our job is to fill in the initial request queue entry and
	 * then to start allocating and filling in continuation entries
	 * until we've covered the entire transfer.
	 */

	if (IS_FC(mp->isp)) {
		seglim = ISP_RQDSEG_T2;
		((ispreqt2_t *)rq)->req_totalcnt = datalen;
		if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
			((ispreqt2_t *)rq)->req_flags |= REQFLAG_DATA_IN;
		} else {
			((ispreqt2_t *)rq)->req_flags |= REQFLAG_DATA_OUT;
		}
	} else {
		seglim = ISP_RQDSEG;
		if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
			rq->req_flags |= REQFLAG_DATA_IN;
		} else {
			rq->req_flags |= REQFLAG_DATA_OUT;
		}
	}

	eseg = dm_segs + nseg;

	while (datalen != 0 && rq->req_seg_count < seglim && dm_segs != eseg) {
		if (IS_FC(mp->isp)) {
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
		if (IS_FC(mp->isp)) {
			ispreqt2_t *rq2 = (ispreqt2_t *)rq;
			printf("%s: seg0[%d] cnt 0x%x paddr 0x%08x\n",
			    mp->isp->isp_name, rq->req_seg_count,
			    rq2->req_dataseg[rq2->req_seg_count].ds_count,
			    rq2->req_dataseg[rq2->req_seg_count].ds_base);
		} else {
			printf("%s: seg0[%d] cnt 0x%x paddr 0x%08x\n",
			    mp->isp->isp_name, rq->req_seg_count,
			    rq->req_dataseg[rq->req_seg_count].ds_count,
			    rq->req_dataseg[rq->req_seg_count].ds_base);
		}
#endif
		rq->req_seg_count++;
		dm_segs++;
	}

	while (datalen > 0 && dm_segs != eseg) {
		crq = (ispcontreq_t *)
		    ISP_QUEUE_ENTRY(mp->isp->isp_rquest, *mp->iptrp);
		*mp->iptrp = ISP_NXT_QENTRY(*mp->iptrp, RQUEST_QUEUE_LEN);
		if (*mp->iptrp == mp->optr) {
#if	0
			printf("%s: Request Queue Overflow++\n",
			    mp->isp->isp_name);
#endif
			mp->error = MUSHERR_NOQENTRIES;
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
			    mp->isp->isp_name, rq->req_header.rqs_entry_count-1,
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
isp_pci_dmasetup(struct ispsoftc *isp, struct ccb_scsiio *csio, ispreq_t *rq,
	u_int16_t *iptrp, u_int16_t optr)
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	bus_dmamap_t *dp = NULL;
	mush_t mush, *mp;
	void (*eptr) __P((void *, bus_dma_segment_t *, int, int));

#ifdef	ISP_TARGET_MODE
	if (csio->ccb_h.func_code == XPT_CONT_TARGET_IO) {
		if (IS_FC(isp)) {
			eptr = dma2_tgt_fc;
		} else {
			eptr = dma2_tgt;
		}
		if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_NONE) {
			rq->req_seg_count = 1;
			mp = &mush;
			mp->isp = isp;
			mp->cmd_token = csio;
			mp->rq = rq;
			mp->iptrp = iptrp;
			mp->optr = optr;
			mp->error = 0;
			(*eptr)(mp, NULL, 0, 0);
			goto exit;
		}
	} else
#endif
	eptr = dma2;

	/*
	 * NB: if we need to do request queue entry swizzling,
	 * NB: this is where it would need to be done for cmds
	 * NB: that move no data. For commands that move data,
	 * NB: swizzling would take place in those functions.
	 */
	if ((csio->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_NONE) {
		rq->req_seg_count = 1;
		return (CMD_QUEUED);
	}

	/*
	 * Do a virtual grapevine step to collect info for
	 * the callback dma allocation that we have to use...
	 */
	mp = &mush;
	mp->isp = isp;
	mp->cmd_token = csio;
	mp->rq = rq;
	mp->iptrp = iptrp;
	mp->optr = optr;
	mp->error = 0;

	if ((csio->ccb_h.flags & CAM_SCATTER_VALID) == 0) {
		if ((csio->ccb_h.flags & CAM_DATA_PHYS) == 0) {
			int error, s;
			dp = &pci->dmaps[rq->req_handle - 1];
			s = splsoftvm();
			error = bus_dmamap_load(pci->parent_dmat, *dp,
			    csio->data_ptr, csio->dxfer_len, eptr, mp, 0);
			if (error == EINPROGRESS) {
				bus_dmamap_unload(pci->parent_dmat, *dp);
				mp->error = EINVAL;
				printf("%s: deferred dma allocation not "
				    "supported\n", isp->isp_name);
			} else if (error && mp->error == 0) {
#ifdef	DIAGNOSTIC
				printf("%s: error %d in dma mapping code\n",
				    isp->isp_name, error);
#endif
				mp->error = error;
			}
			splx(s);
		} else {
			/* Pointer to physical buffer */
			struct bus_dma_segment seg;
			seg.ds_addr = (bus_addr_t)csio->data_ptr;
			seg.ds_len = csio->dxfer_len;
			(*eptr)(mp, &seg, 1, 0);
		}
	} else {
		struct bus_dma_segment *segs;

		if ((csio->ccb_h.flags & CAM_DATA_PHYS) != 0) {
			printf("%s: Physical segment pointers unsupported",
				isp->isp_name);
			mp->error = EINVAL;
		} else if ((csio->ccb_h.flags & CAM_SG_LIST_PHYS) == 0) {
			printf("%s: Virtual segment addresses unsupported",
				isp->isp_name);
			mp->error = EINVAL;
		} else {
			/* Just use the segments provided */
			segs = (struct bus_dma_segment *) csio->data_ptr;
			(*eptr)(mp, segs, csio->sglist_cnt, 0);
		}
	}
#ifdef	ISP_TARGET_MODE
exit:
#endif
	if (mp->error) {
		int retval = CMD_COMPLETE;
		if (mp->error == MUSHERR_NOQENTRIES) {
			retval = CMD_EAGAIN;
		} else if (mp->error == EFBIG) {
			XS_SETERR(csio, CAM_REQ_TOO_BIG);
		} else if (mp->error == EINVAL) {
			XS_SETERR(csio, CAM_REQ_INVALID);
		} else {
			XS_SETERR(csio, CAM_UNREC_HBA_ERROR);
		}
		return (retval);
	} else {
		/*
		 * Check to see if we weren't cancelled while sleeping on
		 * getting DMA resources...
		 */
		if ((csio->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_INPROG) {
			if (dp) {
				bus_dmamap_unload(pci->parent_dmat, *dp);
			}
			return (CMD_COMPLETE);
		}
		return (CMD_QUEUED);
	}
}

static void
isp_pci_dmateardown(struct ispsoftc *isp, ISP_SCSI_XFER_T *xs, u_int32_t handle)
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	bus_dmamap_t *dp = &pci->dmaps[handle - 1];
	KASSERT((handle > 0 && handle <= isp->isp_maxcmds),
	    ("bad handle in isp_pci_dmateardonw"));
	if ((xs->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_POSTREAD);
	} else {
		bus_dmamap_sync(pci->parent_dmat, *dp, BUS_DMASYNC_POSTWRITE);
	}
	bus_dmamap_unload(pci->parent_dmat, *dp);
}


static void
isp_pci_reset1(struct ispsoftc *isp)
{
	/* Make sure the BIOS is disabled */
	isp_pci_wr_reg(isp, HCCR, PCI_HCCR_CMD_BIOS);
}

static void
isp_pci_dumpregs(struct ispsoftc *isp)
{
	struct isp_pcisoftc *pci = (struct isp_pcisoftc *)isp;
	printf("%s: PCI Status Command/Status=%lx\n", pci->pci_isp.isp_name,
	    pci_conf_read(pci->pci_id, PCIR_COMMAND));
}
