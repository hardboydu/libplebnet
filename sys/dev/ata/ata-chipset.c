/*-
 * Copyright (c) 1998 - 2003 S�ren Schmidt <sos@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */
#include "opt_ata.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/ata.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <machine/stdarg.h>
#include <machine/resource.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <pci/pcivar.h>
#include <pci/pcireg.h>
#include <dev/ata/ata-all.h>
#include <dev/ata/ata-pci.h>

/* misc defines */
#define GRANDPARENT(dev)	device_get_parent(device_get_parent(dev))
#define ATAPI_DEVICE(atadev) \
				((atadev->unit == ATA_MASTER && \
				atadev->channel->devices & ATA_ATAPI_MASTER) ||\
				(atadev->unit == ATA_SLAVE && \
				atadev->channel->devices & ATA_ATAPI_SLAVE))

/* local prototypes */
static int ata_generic_chipinit(device_t);
static void ata_generic_intr(void *);
static void ata_generic_setmode(struct ata_device *, int);
static int ata_acard_chipinit(device_t);
static void ata_acard_intr(void *);
static void ata_acard_850_setmode(struct ata_device *, int);
static void ata_acard_86X_setmode(struct ata_device *, int);
static int ata_ali_chipinit(device_t);
static void ata_ali_setmode(struct ata_device *, int);
static int ata_amd_chipinit(device_t);
static int ata_cyrix_chipinit(device_t);
static void ata_cyrix_setmode(struct ata_device *, int);
static int ata_cypress_chipinit(device_t);
static void ata_cypress_setmode(struct ata_device *, int);
static int ata_highpoint_chipinit(device_t);
static void ata_highpoint_intr(void *);
static void ata_highpoint_setmode(struct ata_device *, int);
static int ata_highpoint_check_80pin(struct ata_device *, int);
static int ata_intel_chipinit(device_t);
static void ata_intel_old_setmode(struct ata_device *, int);
static void ata_intel_new_setmode(struct ata_device *, int);
static int ata_nvidia_chipinit(device_t);
static int ata_via_chipinit(device_t);
static void ata_via_family_setmode(struct ata_device *, int);
static void ata_via_southbridge_fixup(device_t);
static int ata_promise_chipinit(device_t);
static void ata_promise_intr(void *);
static void ata_promise_tx2_intr(void *);
static void ata_promise_setmode(struct ata_device *, int);
static int ata_promise_dmainit(struct ata_channel *);
static int ata_promise_dmastart(struct ata_device *, caddr_t, int32_t, int);
static int ata_promise_dmastop(struct ata_device *);
static int ata_serverworks_chipinit(device_t);
static void ata_serverworks_setmode(struct ata_device *, int);
static int ata_sii_chipinit(device_t);
static void ata_cmd_intr(void *);
static void ata_sii_setmode(struct ata_device *, int);
static void ata_cmd_setmode(struct ata_device *, int);
static int ata_sis_chipinit(device_t);
static void ata_sis_setmode(struct ata_device *, int);
static int ata_mode2idx(int);
static int ata_check_80pin(struct ata_device *, int);
static int ata_find_dev(device_t, u_int32_t, u_int32_t);
static struct ata_chip_id *ata_match_chip(device_t, struct ata_chip_id *);
static int ata_default_interrupt(device_t);
static void ata_pci_serialize(struct ata_channel *, int);

/* generic or unknown ATA chipset init code */
int
ata_generic_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    device_set_desc(dev, "GENERIC ATA controller");
    ctlr->chipinit = ata_generic_chipinit;
    return 0;
}

static int
ata_generic_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;
    ctlr->setmode = ata_generic_setmode;
    return 0;
}

static void
ata_generic_intr(void *data)
{
    struct ata_pci_controller *ctlr = data;
    struct ata_channel *ch;
    u_int8_t dmastat;
    int unit;

    /* implement this as a toggle instead to balance load XXX */
    for (unit = 0; unit < 2; unit++) {
	if (!(ch = ctlr->interrupt[unit].argument))
	    continue;
	if (ch->flags & ATA_DMA_ACTIVE) {
	    if (!((dmastat = ch->dma->status(ch)) & ATA_BMSTAT_INTERRUPT))
		continue;
	    ATA_OUTB(ch->r_bmio, ATA_BMSTAT_PORT, dmastat|ATA_BMSTAT_INTERRUPT);
	    DELAY(1);
	}
	ctlr->interrupt[unit].function(ch);
    }
}

static void
ata_generic_setmode(struct ata_device *atadev, int mode)
{
    if (mode >= ATA_DMA)
	atadev->mode = ATA_DMA;
    else
	atadev->mode = ATA_PIO;
    return;
}

/*
 * Acard chipset support functions
 */
int
ata_acard_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_ATP850R, 0, ATPOLD, 0x00, ATA_UDMA2, "Acard ATP850" },
     { ATA_ATP860A, 0, 0,      0x00, ATA_UDMA4, "Acard ATP860A" },
     { ATA_ATP860R, 0, 0,      0x00, ATA_UDMA4, "Acard ATP860R" },
     { ATA_ATP865A, 0, 0,      0x00, ATA_UDMA6, "Acard ATP865A" },
     { ATA_ATP865R, 0, 0,      0x00, ATA_UDMA6, "Acard ATP865R" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64]; 

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_acard_chipinit;
    return 0;
}

static int
ata_acard_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    int rid = ATA_IRQ_RID;

    if (!(ctlr->r_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1,
					   RF_SHAREABLE | RF_ACTIVE))) {
	device_printf(dev, "unable to map interrupt\n");
	return ENXIO;
    }
    if ((bus_setup_intr(dev, ctlr->r_irq, INTR_TYPE_BIO | INTR_ENTROPY,
			ata_acard_intr, ctlr, &ctlr->handle))) {
	device_printf(dev, "unable to setup interrupt\n");
	return ENXIO;
    }
    if (ctlr->chip->cfg1 == ATPOLD) {
	ctlr->setmode = ata_acard_850_setmode;
	ctlr->locking = ata_pci_serialize;
    }
    else
	ctlr->setmode = ata_acard_86X_setmode;
    return 0;
}

static void
ata_acard_intr(void *data)
{
    struct ata_pci_controller *ctlr = data;
    struct ata_channel *ch;
    u_int8_t dmastat;
    int unit;

    /* implement this as a toggle instead to balance load XXX */
    for (unit = 0; unit < 2; unit++) {
	if (ctlr->chip->cfg1 == ATPOLD && ctlr->locked_ch != unit)
		continue;
	ch = ctlr->interrupt[unit].argument;
	if (ch->flags & ATA_DMA_ACTIVE) {
	    if (!((dmastat = ch->dma->status(ch)) & ATA_BMSTAT_INTERRUPT))
		continue;
	    ATA_OUTB(ch->r_bmio, ATA_BMSTAT_PORT, dmastat|ATA_BMSTAT_INTERRUPT);
	    DELAY(1);
	    ATA_OUTB(ch->r_bmio, ATA_BMCMD_PORT,
		     ATA_INB(ch->r_bmio, ATA_BMCMD_PORT)&~ATA_BMCMD_START_STOP);
	    DELAY(1);
	}
	ctlr->interrupt[unit].function(ch);
    }
}

static void
ata_acard_850_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;

    mode = ata_limit_mode(atadev, mode,
			  ATAPI_DEVICE(atadev)?ATA_PIO_MAX:ctlr->chip->max_dma);

/* XXX missing WDMA0+1 + PIO modes */
    if (mode >= ATA_WDMA2) {
	error = ata_command(atadev, ATA_C_SETFEATURES, 0,
			    mode, ATA_C_F_SETXFER, ATA_WAIT_READY);
	if (bootverbose)
	    ata_prtdev(atadev, "%s setting %s on %s chip\n",
		       (error) ? "failed" : "success",
		       ata_mode2str(mode), ctlr->chip->text);
	if (!error) {
	    u_int8_t reg54 = pci_read_config(parent, 0x54, 1);
	    
	    reg54 &= ~(0x03 << (devno << 1));
	    if (mode >= ATA_UDMA0)
		reg54 |= (((mode & ATA_MODE_MASK) + 1) << (devno << 1));
	    pci_write_config(parent, 0x54, reg54, 1);
	    pci_write_config(parent, 0x4a, 0xa6, 1);
	    pci_write_config(parent, 0x40 + (devno << 1), 0x0301, 2);
	    atadev->mode = mode;
	    return;
	}
    }
    /* we could set PIO mode timings, but we assume the BIOS did that */
}

static void
ata_acard_86X_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;


    mode = ata_limit_mode(atadev, mode,
			  ATAPI_DEVICE(atadev)?ATA_PIO_MAX:ctlr->chip->max_dma);

    mode = ata_check_80pin(atadev, mode);

/* XXX missing WDMA0+1 + PIO modes */
    if (mode >= ATA_WDMA2) {
	error = ata_command(atadev, ATA_C_SETFEATURES, 0,
			    mode, ATA_C_F_SETXFER, ATA_WAIT_READY);
	if (bootverbose)
	    ata_prtdev(atadev, "%s setting %s on %s chip\n",
		       (error) ? "failed" : "success",
		       ata_mode2str(mode), ctlr->chip->text);
	if (!error) {
	    u_int16_t reg44 = pci_read_config(parent, 0x44, 2);
	    
	    reg44 &= ~(0x000f << (devno << 2));
	    if (mode >= ATA_UDMA0)
		reg44 |= (((mode & ATA_MODE_MASK) + 1) << (devno << 2));
	    pci_write_config(parent, 0x44, reg44, 2);
	    pci_write_config(parent, 0x4a, 0xa6, 1);
	    pci_write_config(parent, 0x40 + devno, 0x31, 1);
	    atadev->mode = mode;
	    return;
	}
    }
    /* we could set PIO mode timings, but we assume the BIOS did that */
}

/*
 * Acer Labs Inc (ALI) chipset support functions
 */
int
ata_ali_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_ALI_5229, 0xc4, 0, ALINEW, ATA_UDMA5, "AcerLabs Aladdin" },
     { ATA_ALI_5229, 0xc2, 0, ALINEW, ATA_UDMA4, "AcerLabs Aladdin" },
     { ATA_ALI_5229, 0x20, 0, ALIOLD, ATA_UDMA2, "AcerLabs Aladdin" },
     { ATA_ALI_5229, 0x00, 0, ALIOLD, ATA_WDMA2, "AcerLabs Aladdin" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64]; 

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_ali_chipinit;
    return 0;
}

static int
ata_ali_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    /* deactivate the ATAPI FIFO and enable ATAPI UDMA */
    pci_write_config(dev, 0x53, pci_read_config(dev, 0x53, 1) | 0x03, 1);
 
    /* enable cable detection and UDMA support on newer chips */
    if (ctlr->chip->cfg2 & ALINEW)
	pci_write_config(dev, 0x4b, pci_read_config(dev, 0x4b, 1) | 0x09, 1);
    ctlr->setmode = ata_ali_setmode;
    return 0;
}

static void
ata_ali_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    if (ctlr->chip->cfg2 & ALINEW) {
	if (mode > ATA_UDMA2 &&
	    pci_read_config(parent, 0x4a, 1) & (1 << atadev->channel->unit)) {
	    ata_prtdev(atadev,
		       "DMA limited to UDMA33, non-ATA66 cable or device\n");
	    mode = ATA_UDMA2;
	}
    }
    else
	mode = ata_check_80pin(atadev, mode);

    if (ctlr->chip->cfg2 & ALIOLD) {
	/* doesn't support ATAPI DMA on write */
	atadev->channel->flags |= ATA_ATAPI_DMA_RO;
	if (atadev->channel->devices & ATA_ATAPI_MASTER &&
	    atadev->channel->devices & ATA_ATAPI_SLAVE) {
	    /* doesn't support ATAPI DMA on two ATAPI devices */
	    ata_prtdev(atadev, "two atapi devices on this channel, no DMA\n");
	    mode = ata_limit_mode(atadev, mode, ATA_PIO_MAX);
	}
    }

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success", 
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	if (mode >= ATA_UDMA0) {
	    u_int8_t udma[] = {0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x0f};
	    u_int32_t word54 = pci_read_config(parent, 0x54, 4);

	    word54 &= ~(0x000f000f << (devno << 2));
	    word54 |= (((udma[mode&ATA_MODE_MASK]<<16)|0x05)<<(devno<<2));
	    pci_write_config(parent, 0x54, word54, 4);
	    pci_write_config(parent, 0x58 + (atadev->channel->unit << 2),
			     0x00310001, 4);
	}
	else {
	    u_int32_t piotimings[] =
		{ 0x006d0003, 0x00580002, 0x00440001, 0x00330001,
		  0x00310001, 0x00440001, 0x00330001, 0x00310001};

	    pci_write_config(parent, 0x54, pci_read_config(parent, 0x54, 4) &
					   ~(0x0008000f << (devno << 2)), 4);
	    pci_write_config(parent, 0x58 + (atadev->channel->unit << 2),
			     piotimings[ata_mode2idx(mode)], 4);
	}
	atadev->mode = mode;
    }
}

/*
 * American Micro Devices (AMD) support function
 */
int
ata_amd_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_AMD756,  0x00, AMDNVIDIA, 0x00,	      ATA_UDMA4, "AMD 756" },
     { ATA_AMD766,  0x00, AMDNVIDIA, AMDCABLE|AMDBUG, ATA_UDMA5, "AMD 766" },
     { ATA_AMD768,  0x00, AMDNVIDIA, AMDCABLE,	      ATA_UDMA5, "AMD 768" },
     { ATA_AMD8111, 0x00, AMDNVIDIA, 0x00,	      ATA_UDMA6, "AMD 8111" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64]; 

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_amd_chipinit;
    return 0;
}

static int
ata_amd_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    /* set prefetch, postwrite */
    if (ctlr->chip->cfg2 & AMDBUG)
	pci_write_config(dev, 0x41, pci_read_config(dev, 0x41, 1) & 0x0f, 1);
    else
	pci_write_config(dev, 0x41, pci_read_config(dev, 0x41, 1) | 0xf0, 1);

    ctlr->setmode = ata_via_family_setmode;
    return 0;
}

/*
 * Cyrix chipset support functions
 */
int
ata_cyrix_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (pci_get_devid(dev) == ATA_CYRIX_5530) {
	device_set_desc(dev, "Cyrix 5530 ATA33 controller");
	ctlr->chipinit = ata_cyrix_chipinit;
	return 0;
    }
    return ENXIO;
}

static int
ata_cyrix_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    ctlr->setmode = ata_cyrix_setmode;
    return 0;
}

static void
ata_cyrix_setmode(struct ata_device *atadev, int mode)
{
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    u_int32_t piotiming[] = 
	{ 0x00009172, 0x00012171, 0x00020080, 0x00032010, 0x00040010 };
    u_int32_t dmatiming[] = { 0x00077771, 0x00012121, 0x00002020 };
    u_int32_t udmatiming[] = { 0x00921250, 0x00911140, 0x00911030 };
    int error;

    mode = ata_limit_mode(atadev, mode, ATA_UDMA2);
    atadev->channel->dma->alignment = 16;

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on Cyrix chip\n",
		   (error) ? "failed" : "success", ata_mode2str(mode));
    if (!error) {
	if (mode >= ATA_UDMA0) {
	    ATA_OUTL(atadev->channel->r_bmio, (devno << 3) + 0x24,
		     udmatiming[mode % ATA_MODE_MASK]);
	}
	else if (mode >= ATA_WDMA0) {
	    ATA_OUTL(atadev->channel->r_bmio, (devno << 3) + 0x24,
		     dmatiming[mode % ATA_MODE_MASK]);
	}
	else {
	    ATA_OUTL(atadev->channel->r_bmio, (devno << 3) + 0x20,
		     piotiming[mode % ATA_MODE_MASK]);
	}
	atadev->mode = mode;
    }
}

/*
 * Cypress chipset support functions
 */
int
ata_cypress_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    /*
     * the Cypress chip is a mess, it contains two ATA functions, but
     * both channels are visible on the first one.
     * simply ignore the second function for now, as the right
     * solution (ignoring the second channel on the first function)
     * doesn't work with the crappy ATA interrupt setup on the alpha.
     */
    if (pci_get_devid(dev) == ATA_CYPRESS_82C693 &&
	pci_get_function(dev) == 1 &&
	pci_get_subclass(dev) == PCIS_STORAGE_IDE) {
	device_set_desc(dev, "Cypress 82C693 ATA controller");
	ctlr->chipinit = ata_cypress_chipinit;
	return 0;
    }
    return ENXIO;
}

static int
ata_cypress_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    ctlr->setmode = ata_cypress_setmode;
    return 0;
}

static void
ata_cypress_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    int error;

    mode = ata_limit_mode(atadev, mode, ATA_WDMA2);

/* XXX missing WDMA0+1 + PIO modes */
    if (mode == ATA_WDMA2) { 
	error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			    ATA_C_F_SETXFER, ATA_WAIT_READY);
	if (bootverbose)
	    ata_prtdev(atadev, "%s setting WDMA2 on Cypress chip\n",
		       error ? "failed" : "success");
	if (!error) {
	    pci_write_config(parent, atadev->channel->unit?0x4e:0x4c,0x2020,2);
	    atadev->mode = mode;
	    return;
	}
    }
    /* we could set PIO mode timings, but we assume the BIOS did that */
}

/*
 * HighPoint chipset support functions
 */
int
ata_highpoint_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_HPT366, 0x05, HPT372, 0x00,	 ATA_UDMA6, "HighPoint HPT372" },
     { ATA_HPT366, 0x03, HPT370, 0x00,	 ATA_UDMA5, "HighPoint HPT370" },
     { ATA_HPT366, 0x02, HPT366, 0x00,	 ATA_UDMA4, "HighPoint HPT368" },
     { ATA_HPT366, 0x00, HPT366, HPTOLD, ATA_UDMA4, "HighPoint HPT366" },
     { ATA_HPT372, 0x01, HPT372, 0x00,	 ATA_UDMA6, "HighPoint HPT372" },
     { ATA_HPT374, 0x07, HPT374, 0x00,	 ATA_UDMA6, "HighPoint HPT374" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64];

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_highpoint_chipinit;
    return 0;
}

static int
ata_highpoint_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    int rid = ATA_IRQ_RID;

    if (!(ctlr->r_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1,
					   RF_SHAREABLE | RF_ACTIVE))) {
	device_printf(dev, "unable to map interrupt\n");
	return ENXIO;
    }
    if ((bus_setup_intr(dev, ctlr->r_irq, INTR_TYPE_BIO | INTR_ENTROPY,
			ata_highpoint_intr, ctlr, &ctlr->handle))) {
	device_printf(dev, "unable to setup interrupt\n");
	return ENXIO;
    }

    if (ctlr->chip->cfg2 == HPTOLD) {
	/* turn off interrupt prediction */
	pci_write_config(dev, 0x51, (pci_read_config(dev, 0x51, 1) & ~0x80), 1);
    }
    else {
	/* turn off interrupt prediction */
	pci_write_config(dev, 0x51, (pci_read_config(dev, 0x51, 1) & ~0x03), 1);
	pci_write_config(dev, 0x55, (pci_read_config(dev, 0x55, 1) & ~0x03), 1);

	/* turn on interrupts */
	pci_write_config(dev, 0x5a, (pci_read_config(dev, 0x5a, 1) & ~0x10), 1);

	/* set clocks etc */
	if (ctlr->chip->cfg1 < HPT372)
	    pci_write_config(dev, 0x5b, 0x22, 1);
	else
	    pci_write_config(dev, 0x5b,
			     (pci_read_config(dev, 0x5b, 1) & 0x01) | 0x20, 1);
    }
    ctlr->setmode = ata_highpoint_setmode;
    return 0;
}

static void
ata_highpoint_intr(void *data)
{
    struct ata_pci_controller *ctlr = data;
    struct ata_channel *ch;
    u_int8_t dmastat;
    int unit;

    /* implement this as a toggle instead to balance load XXX */
    for (unit = 0; unit < 2; unit++) {
	if (!(ch = ctlr->interrupt[unit].argument))
	    continue;
	if (((dmastat = ch->dma->status(ch)) & 
	     (ATA_BMSTAT_ACTIVE | ATA_BMSTAT_INTERRUPT))!=ATA_BMSTAT_INTERRUPT)
	    continue;
	ATA_OUTB(ch->r_bmio, ATA_BMSTAT_PORT, dmastat | ATA_BMSTAT_INTERRUPT);
	DELAY(1);
	ctlr->interrupt[unit].function(ch);
    }
}

static void
ata_highpoint_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;
    u_int32_t timings33[][4] = {
    /*	  HPT366      HPT370	  HPT372      HPT374		   mode */
	{ 0x40d0a7aa, 0x06914e57, 0x0d029d5e, 0x0ac1f48a },	/* PIO 0 */
	{ 0x40d0a7a3, 0x06914e43, 0x0d029d26, 0x0ac1f465 },	/* PIO 1 */
	{ 0x40d0a753, 0x06514e33, 0x0c829ca6, 0x0a81f454 },	/* PIO 2 */
	{ 0x40c8a742, 0x06514e22, 0x0c829c84, 0x0a81f443 },	/* PIO 3 */
	{ 0x40c8a731, 0x06514e21, 0x0c829c62, 0x0a81f442 },	/* PIO 4 */
	{ 0x20c8a797, 0x26514e97, 0x2c82922e, 0x228082ea },	/* MWDMA 0 */
	{ 0x20c8a732, 0x26514e33, 0x2c829266, 0x22808254 },	/* MWDMA 1 */
	{ 0x20c8a731, 0x26514e21, 0x2c829262, 0x22808242 },	/* MWDMA 2 */
	{ 0x10c8a731, 0x16514e31, 0x1c82dc62, 0x121882ea },	/* UDMA 0 */
	{ 0x10cba731, 0x164d4e31, 0x1c9adc62, 0x12148254 },	/* UDMA 1 */
	{ 0x10caa731, 0x16494e31, 0x1c91dc62, 0x120c8242 },	/* UDMA 2 */
	{ 0x10cfa731, 0x166d4e31, 0x1c8edc62, 0x128c8242 },	/* UDMA 3 */
	{ 0x10c9a731, 0x16454e31, 0x1c8ddc62, 0x12ac8242 },	/* UDMA 4 */
	{ 0,	      0x16454e31, 0x1c6ddc62, 0x12848242 },	/* UDMA 5 */
	{ 0,	      0,	  0x1c81dc62, 0x12808242 }	/* UDMA 6 */
    };

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    if (ctlr->chip->cfg1 == HPT366 && ATAPI_DEVICE(atadev))
	mode = ata_limit_mode(atadev, mode, ATA_PIO_MAX);

    mode = ata_highpoint_check_80pin(atadev, mode);

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on HighPoint chip\n",
		   (error) ? "failed" : "success", ata_mode2str(mode));
    if (!error)
	pci_write_config(parent, 0x40 + (devno << 2),
			 timings33[ata_mode2idx(mode)][ctlr->chip->cfg1], 4);
    atadev->mode = mode;
}

static int
ata_highpoint_check_80pin(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    u_int8_t reg, val, res;

    if (ctlr->chip->cfg1 == HPT374 && pci_get_function(parent) == 1) {
	reg = atadev->channel->unit ? 0x57 : 0x53;
	val = pci_read_config(parent, reg, 1);
	pci_write_config(parent, reg, val | 0x80, 1);
    }
    else {
	reg = 0x5b;
	val = pci_read_config(parent, reg, 1);
	pci_write_config(parent, reg, val & 0xfe, 1);
    }
    res = pci_read_config(parent, 0x5a, 1) & (atadev->channel->unit ? 0x1:0x2);
    pci_write_config(parent, reg, val, 1);

    if (mode > ATA_UDMA2 && res) {
	ata_prtdev(atadev,"DMA limited to UDMA33, non-ATA66 cable or device\n");
	mode = ATA_UDMA2;
    }
    return mode;
}

/*
 * Intel chipset support functions
 */
int
ata_intel_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_I82371FB,   0, 0, 0x00, ATA_WDMA2, "Intel PIIX" },
     { ATA_I82371SB,   0, 0, 0x00, ATA_WDMA2, "Intel PIIX3" },
     { ATA_I82371AB,   0, 0, 0x00, ATA_UDMA2, "Intel PIIX4" },
     { ATA_I82443MX,   0, 0, 0x00, ATA_UDMA2, "Intel PIIX4" },
     { ATA_I82451NX,   0, 0, 0x00, ATA_UDMA2, "Intel PIIX4" },
     { ATA_I82801AB,   0, 0, 0x00, ATA_UDMA2, "Intel ICH0" },
     { ATA_I82801AA,   0, 0, 0x00, ATA_UDMA4, "Intel ICH" },
     { ATA_I82372FB,   0, 0, 0x00, ATA_UDMA4, "Intel ICH" },
     { ATA_I82801BA,   0, 0, 0x00, ATA_UDMA5, "Intel ICH2" },
     { ATA_I82801BA_1, 0, 0, 0x00, ATA_UDMA5, "Intel ICH2" },
     { ATA_I82801CA,   0, 0, 0x00, ATA_UDMA5, "Intel ICH3" },
     { ATA_I82801CA_1, 0, 0, 0x00, ATA_UDMA5, "Intel ICH3" },
     { ATA_I82801DB,   0, 0, 0x00, ATA_UDMA5, "Intel ICH4" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64]; 

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_intel_chipinit;
    return 0;
}

static int
ata_intel_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    if (ctlr->chip->chiptype == ATA_I82371FB)
	ctlr->setmode = ata_intel_old_setmode;
    else 
	ctlr->setmode = ata_intel_new_setmode;
    return 0;
}

static void
ata_intel_old_setmode(struct ata_device *atadev, int mode)
{
    /* NOT YET */
}

static void
ata_intel_new_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    u_int32_t reg40 = pci_read_config(parent, 0x40, 4);
    u_int8_t reg44 = pci_read_config(parent, 0x44, 1);
    u_int8_t reg48 = pci_read_config(parent, 0x48, 1);
    u_int16_t reg4a = pci_read_config(parent, 0x4a, 2);
    u_int16_t reg54 = pci_read_config(parent, 0x54, 2);
    u_int32_t mask40 = 0, new40 = 0;
    u_int8_t mask44 = 0, new44 = 0;
    int error;
    u_int8_t timings[] = { 0x00, 0x00, 0x10, 0x21, 0x23, 0x10, 0x21, 0x23,
			   0x23, 0x23, 0x23, 0x23, 0x23, 0x23 };

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    if (ctlr->chip->max_dma && mode > ATA_UDMA2 && !(reg54 & (0x10 << devno))) {
	ata_prtdev(atadev,"DMA limited to UDMA33, non-ATA66 cable or device\n");
	mode = ATA_UDMA2;
    }

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success",
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	if (mode >= ATA_UDMA0) {
	    pci_write_config(parent, 0x48, reg48 | (0x0001 << devno), 2);
	    pci_write_config(parent, 0x4a, (reg4a & ~(0x3 << (devno<<2))) | 
					   (0x01 + !(mode & 0x01)), 2);
	}
	else {
	    pci_write_config(parent, 0x48, reg48 & ~(0x0001 << devno), 2);
	    pci_write_config(parent, 0x4a, (reg4a & ~(0x3 << (devno << 2))), 2);
	}
	if (mode >= ATA_UDMA2)
	    pci_write_config(parent, 0x54, reg54 | (0x1 << devno), 2);
	else
	    pci_write_config(parent, 0x54, reg54 & ~(0x1 << devno), 2);

	if (mode >= ATA_UDMA5)
	    pci_write_config(parent, 0x54, reg54 | (0x10000 << devno), 2);
	else 
	    pci_write_config(parent, 0x54, reg54 & ~(0x10000 << devno), 2);

	reg40 &= ~0x00ff00ff;
	reg40 |= 0x40774077;

	if (atadev->unit == ATA_MASTER) {
	    mask40 = 0x3300;
	    new40 = timings[ata_mode2idx(mode)] << 8;
	}
	else {
	    mask44 = 0x0f;
	    new44 = ((timings[ata_mode2idx(mode)] & 0x30) >> 2) |
		    (timings[ata_mode2idx(mode)] & 0x03);
	}
	if (atadev->channel->unit) {
	    mask40 <<= 16;
	    new40 <<= 16;
	    mask44 <<= 4;
	    new44 <<= 4;
	}
	pci_write_config(parent, 0x40, (reg40 & ~mask40) | new40, 4);
	pci_write_config(parent, 0x44, (reg44 & ~mask44) | new44, 1);
	atadev->mode = mode;
    }
}

/*
 * nVidia chipset support functions
 */
int
ata_nvidia_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_NFORCE1, 0, AMDNVIDIA, NVIDIA|AMDBUG, ATA_UDMA5, "nVidia nForce" },
     { ATA_NFORCE2, 0, AMDNVIDIA, NVIDIA|AMDBUG, ATA_UDMA6, "nVidia nForce2" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64];

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_nvidia_chipinit;
    return 0;
}

static int
ata_nvidia_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    /* set prefetch, postwrite */
    if (ctlr->chip->cfg2 & AMDBUG) 
	pci_write_config(dev, 0x51, pci_read_config(dev, 0x51, 1) & 0x0f, 1);
    else
	pci_write_config(dev, 0x51, pci_read_config(dev, 0x51, 1) | 0xf0, 1);

    ctlr->setmode = ata_via_family_setmode;
    return 0;
}

/*
 * Promise chipset support functions
 */
int
ata_promise_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_PDC20246,  0, PROLD, 0x00,	ATA_UDMA2, "Promise" },
     { ATA_PDC20262,  0, PRNEW, 0x00,	ATA_UDMA4, "Promise" },
     { ATA_PDC20263,  0, PRNEW, 0x00,	ATA_UDMA4, "Promise" },
     { ATA_PDC20265,  0, PRNEW, 0x00,	ATA_UDMA5, "Promise" },
     { ATA_PDC20267,  0, PRNEW, 0x00,	ATA_UDMA5, "Promise" },
     { ATA_PDC20268,  0, PRTX,  PRTX4,	ATA_UDMA5, "Promise TX2" },
     { ATA_PDC20268R, 0, PRTX,  PRTX4,	ATA_UDMA5, "Promise TX2" },
     { ATA_PDC20269,  0, PRTX,  0x00,	ATA_UDMA6, "Promise TX2" },
     { ATA_PDC20271,  0, PRTX,  0x00,	ATA_UDMA6, "Promise TX2" },
     { ATA_PDC20275,  0, PRTX,  0x00,	ATA_UDMA6, "Promise TX2" },
     { ATA_PDC20276,  0, PRTX,  PRSX6K, ATA_UDMA6, "Promise TX2" },
     { ATA_PDC20277,  0, PRTX,  0x00,	ATA_UDMA6, "Promise TX2" },
#if notyet
     { ATA_PDC20376,  0, PRCH,  0x00,	ATA_UDMA6, "Promise SATA" },
     { ATA_PDC20621,  0, PRCH,  0x00,	ATA_UDMA6, "Promise SX4000" },
#endif
     { 0, 0, 0, 0, 0, 0}};
    char *desc, buffer[64];
    uintptr_t devid = 0;

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    /* if we are on a SuperTrak SX6000 dont attach */
    if ((idx->cfg2 & PRSX6K) && pci_get_class(GRANDPARENT(dev))==PCIC_BRIDGE &&
	!BUS_READ_IVAR(device_get_parent(GRANDPARENT(dev)),
		       GRANDPARENT(dev), PCI_IVAR_DEVID, &devid) &&
	devid == ATA_I960RM) 
	return ENXIO;

    /* if we are on a FastTrak TX4, adjust the interrupt resource */
    if ((idx->cfg2 & PRTX4) && pci_get_class(GRANDPARENT(dev))==PCIC_BRIDGE &&
	!BUS_READ_IVAR(device_get_parent(GRANDPARENT(dev)),
		       GRANDPARENT(dev), PCI_IVAR_DEVID, &devid) &&
	devid == ATA_DEC_21150) {
	static long start = 0, end = 0;

	if (pci_get_slot(dev) == 1) {
	    bus_get_resource(dev, SYS_RES_IRQ, 0, &start, &end);
	    desc = "Promise TX4 (channel 0+1)";
	}
	else if (pci_get_slot(dev) == 2 && start && end) {
	    bus_set_resource(dev, SYS_RES_IRQ, 0, start, end);
	    start = end = 0;
	    desc = "Promise TX4 (channel 2+3)";
	}
	else {
	    start = end = 0;
	    desc = "Promise TX2";
	}
    }
    else 
	desc = idx->text;
    sprintf(buffer, "%s %s controller", desc, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_promise_chipinit;
    return 0;
}

static int
ata_promise_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    int rid = ATA_IRQ_RID;

    if (!(ctlr->r_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1,
					   RF_SHAREABLE | RF_ACTIVE))) {
	device_printf(dev, "unable to map interrupt\n");
	return ENXIO;
    }
    if ((bus_setup_intr(dev, ctlr->r_irq, INTR_TYPE_BIO | INTR_ENTROPY,
			ctlr->chip->cfg1 == PRTX ?
			    ata_promise_tx2_intr : ata_promise_intr,
			ctlr, &ctlr->handle))) {
	device_printf(dev, "unable to setup interrupt\n");
	return ENXIO;
    }
    ctlr->setmode = ata_promise_setmode;
    if (ctlr->chip->cfg1 == PRNEW )
	ctlr->dmainit = ata_promise_dmainit;
    return 0;
}

static void
ata_promise_intr(void *data)
{
    struct ata_pci_controller *ctlr = data;
    struct ata_channel *ch = ctlr->interrupt[0].argument;
    u_int8_t dmastat;
    int unit;

    /* implement this as a toggle instead to balance load XXX */
    for (unit = 0; unit < 2; unit++) {
	if (!(ch = ctlr->interrupt[unit].argument))
	    continue;
	if (ATA_INL(ch->r_bmio, (ch->unit ? 0x14 : 0x1c)) &
	    (ch->unit ? 0x00004000 : 0x00000400)) {
	    if (ch->flags & ATA_DMA_ACTIVE) {
		if (!((dmastat = ch->dma->status(ch)) & ATA_BMSTAT_INTERRUPT))
		    continue;
		ATA_OUTB(ch->r_bmio, ATA_BMSTAT_PORT,
			 dmastat | ATA_BMSTAT_INTERRUPT);
		DELAY(1);
	    }
	    ctlr->interrupt[unit].function(ch);
	}
    }
}

static void
ata_promise_tx2_intr(void *data)
{
    struct ata_pci_controller *ctlr = data;
    struct ata_channel *ch;
    u_int8_t dmastat;
    int unit;

    /* implement this as a toggle instead to balance load XXX */
    for (unit = 0; unit < 2; unit++) {
	if (!(ch = ctlr->interrupt[unit].argument))
	    continue;
	ATA_OUTB(ch->r_bmio, ATA_BMDEVSPEC_0, 0x0b);
	if (ATA_INB(ch->r_bmio, ATA_BMDEVSPEC_1) & 0x20) {
	    if (ch->flags & ATA_DMA_ACTIVE) {
		if (!((dmastat = ch->dma->status(ch)) & ATA_BMSTAT_INTERRUPT))
		    continue;
		ATA_OUTB(ch->r_bmio, ATA_BMSTAT_PORT,
			 dmastat | ATA_BMSTAT_INTERRUPT);
		DELAY(1);
	    }
	    ctlr->interrupt[unit].function(ch);
	}
    }
}

static void
ata_promise_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;
    u_int32_t timings33[][2] = {
    /*	  PROLD	      PRNEW		   mode */
	{ 0x004ff329, 0x004fff2f },	/* PIO 0 */
	{ 0x004fec25, 0x004ff82a },	/* PIO 1 */
	{ 0x004fe823, 0x004ff026 },	/* PIO 2 */
	{ 0x004fe622, 0x004fec24 },	/* PIO 3 */
	{ 0x004fe421, 0x004fe822 },	/* PIO 4 */
	{ 0x004567f3, 0x004acef6 },	/* MWDMA 0 */
	{ 0x004467f3, 0x0048cef6 },	/* MWDMA 1 */
	{ 0x004367f3, 0x0046cef6 },	/* MWDMA 2 */
	{ 0x004367f3, 0x0046cef6 },	/* UDMA 0 */
	{ 0x004247f3, 0x00448ef6 },	/* UDMA 1 */
	{ 0x004127f3, 0x00436ef6 },	/* UDMA 2 */
	{ 0,	      0x00424ef6 },	/* UDMA 3 */
	{ 0,	      0x004127f3 },	/* UDMA 4 */
	{ 0,	      0x004127f3 }	/* UDMA 5 */
    };

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    /* is this a TX2 or later chip ? */
    if (ctlr->chip->cfg1 >= PRTX) {
	ATA_OUTB(atadev->channel->r_bmio, ATA_BMDEVSPEC_0, 0x0b);
	if (mode > ATA_UDMA2 &&
	    ATA_INB(atadev->channel->r_bmio, ATA_BMDEVSPEC_1) & 0x04) {
	    ata_prtdev(atadev,
		       "DMA limited to UDMA33, non-ATA66 cable or device\n");
	    mode = ATA_UDMA2;
	}
    }
    else {
	if (mode > ATA_UDMA2 && (pci_read_config(parent, 0x50, 2) &
				 (atadev->channel->unit ? 1 << 11 : 1 << 10))) {
	    ata_prtdev(atadev,
		       "DMA limited to UDMA33, non-ATA66 cable or device\n");
	    mode = ATA_UDMA2;
	}
	if (ATAPI_DEVICE(atadev) && mode > ATA_PIO_MAX)
	    mode = ata_limit_mode(atadev, mode, ATA_PIO_MAX);
    }

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode, 
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success",
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	if (ctlr->chip->cfg1 < PRTX)
	    pci_write_config(device_get_parent(atadev->channel->dev),
			     0x60 + (devno << 2),
			     timings33[ctlr->chip->cfg1][ata_mode2idx(mode)],4);
	atadev->mode = mode;
    }
    return;
}

static int
ata_promise_dmainit(struct ata_channel *ch)
{
    int error;

    if ((error = ata_dmainit(ch)))
	return error;

    ch->dma->start = ata_promise_dmastart;
    ch->dma->stop = ata_promise_dmastop;
    return 0;
}

static int
ata_promise_dmastart(struct ata_device *atadev,
		     caddr_t data, int32_t count, int dir)
{
    struct ata_channel *ch = atadev->channel;
    int error;

    if ((error = ata_dmastart(atadev, data, count, dir)))
	return error;

    if (ch->flags & ATA_48BIT_ACTIVE) {
	ATA_OUTB(ch->r_bmio, (ch->unit ? 0x09 : 0x11),
		 ATA_INB(ch->r_bmio, (ch->unit ? 0x09 : 0x11)) |
		 (ch->unit ? 0x08 : 0x02));
	ATA_OUTL(ch->r_bmio, (ch->unit ? 0x1c : 0x20),
		 (dir ? 0x05000000 : 0x06000000) | (count >> 1));
    }
    return 0;
}

static int
ata_promise_dmastop(struct ata_device *atadev)
{
    struct ata_channel *ch = atadev->channel;

    if (ch->flags & ATA_48BIT_ACTIVE) {
	ATA_OUTB(ch->r_bmio, (ch->unit ? 0x09 : 0x11),
		 ATA_INB(ch->r_bmio, (ch->unit ? 0x09 : 0x11)) &
		 ~(ch->unit ? 0x08 : 0x02));
	ATA_OUTL(ch->r_bmio, (ch->unit ? 0x1c : 0x20), 0);
    }
    return ata_dmastop(atadev);
}

/*
 * ServerWorks chipset support functions
 */
int
ata_serverworks_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_ROSB4,  0x00, SWKS33,  0x00, ATA_UDMA2, "ServerWorks ROSB4" },
     { ATA_CSB5,   0x92, SWKS100, 0x00, ATA_UDMA5, "ServerWorks CSB5" },
     { ATA_CSB5,   0x00, SWKS66,  0x00, ATA_UDMA4, "ServerWorks CSB5" },
     { ATA_CSB6,   0x00, SWKS100, 0x00, ATA_UDMA5, "ServerWorks CSB6" },
     { ATA_CSB6_1, 0x00, SWKS66,  0x00, ATA_UDMA4, "ServerWorks CSB6" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64];

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_serverworks_chipinit;
    return 0;
}

static int
ata_serverworks_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;

    if (ctlr->chip->cfg1 > SWKS33)
	pci_write_config(dev, 0x5a,
			 (pci_read_config(dev, 0x5a, 1) & ~0x40) |
			 (ctlr->chip->cfg1 == SWKS100) ? 0x03 : 0x02, 1);
    else
	pci_write_config(dev, 0x64,
			 (pci_read_config(dev, 0x64, 4) & ~0x00002000) |
			 0x00004000, 4);
    ctlr->setmode = ata_serverworks_setmode;
    return 0;
}

static void
ata_serverworks_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int offset = devno ^ 0x01;
    int error;
    u_int8_t timings[] = { 0x5d, 0x47, 0x34, 0x22, 0x20, 0x34, 0x22, 0x20,
			   0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    mode = ata_check_80pin(atadev, mode);

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success",
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	if (mode >= ATA_UDMA0) {
	    pci_write_config(parent, 0x54, pci_read_config(parent, 0x54, 1) |
					   (0x01 << devno), 1);
	    pci_write_config(parent, 0x56, 
			     (pci_read_config(parent, 0x56, 2) &
			      ~(0xf << (devno << 2))) |
			     ((mode & ATA_MODE_MASK) << (devno << 2)), 2);
	}
	else
	    pci_write_config(parent, 0x54, pci_read_config(parent, 0x54, 1) |
					   ~(0x01 << devno), 1);
	pci_write_config(parent, 0x44, 
			 (pci_read_config(parent, 0x44, 4) &
			  ~(0xff << (offset << 8))) |
			 (timings[ata_mode2idx(mode)] << (offset << 8)), 4);
	atadev->mode = mode;
    }
}

/*
 * Silicon Image (former CMD) chipset support functions
 */
int
ata_sii_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_SII0680, 0x00, 0, SII_SETCLK, ATA_UDMA6, "SiI 0680" },
     { ATA_CMD649,  0x00, 0, SII_INTR,   ATA_UDMA5, "CMD 649" },
     { ATA_CMD648,  0x00, 0, SII_INTR,   ATA_UDMA4, "CMD 648" },
     { ATA_CMD646,  0x07, 0, SII_ENINTR, ATA_UDMA2, "CMD 646U2" },
     { ATA_CMD646,  0x00, 0, SII_ENINTR, ATA_WDMA2, "CMD 646" },
     { 0, 0, 0, 0, 0, 0}};
    char buffer[64];

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_sii_chipinit;
    return 0;
}

static int
ata_sii_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    int rid = ATA_IRQ_RID;

    if (!(ctlr->r_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1,
					   RF_SHAREABLE | RF_ACTIVE))) {
	device_printf(dev, "unable to map interrupt\n");
	return ENXIO;
    }
    if ((bus_setup_intr(dev, ctlr->r_irq, INTR_TYPE_BIO | INTR_ENTROPY,
			ctlr->chip->cfg2 & SII_INTR ? 
			ata_cmd_intr : ata_generic_intr,
			ctlr, &ctlr->handle))) {
	device_printf(dev, "unable to setup interrupt\n");
	return ENXIO;
    }

    if (ctlr->chip->cfg2 & SII_ENINTR)
	pci_write_config(dev, 0x71, 0x01, 1);

    if (ctlr->chip->cfg2 & SII_SETCLK) {
	if ((pci_read_config(dev, 0x8a, 1) & 0x30) != 0x10)
	    pci_write_config(dev, 0x8a, 
			     (pci_read_config(dev, 0x8a, 1) & 0x0F) | 0x10, 1);
	if ((pci_read_config(dev, 0x8a, 1) & 0x30) != 0x10)
	    device_printf(dev, "%s could not set ATA133 clock\n",
			  ctlr->chip->text);
	ctlr->setmode = ata_sii_setmode;
    }
    else 
	ctlr->setmode = ata_cmd_setmode;
    return 0;
}

static void
ata_cmd_intr(void *data)
{
    struct ata_pci_controller *ctlr = data;
    struct ata_channel *ch;
    u_int8_t dmastat;
    int unit;

    /* implement this as a toggle instead to balance load XXX */
    for (unit = 0; unit < 2; unit++) {
	if (!(ch = ctlr->interrupt[unit].argument))
	    continue;
	if (!(pci_read_config(device_get_parent(ch->dev), 0x71, 1) &
	      (ch->unit ? 0x08 : 0x04)))
	    continue;
	pci_write_config(device_get_parent(ch->dev), 0x71,
			 (ch->unit ? 0x08 : 0x04), 1);
	if (ch->flags & ATA_DMA_ACTIVE) {
	    if (!((dmastat = ch->dma->status(ch)) & ATA_BMSTAT_INTERRUPT))
		continue;
	    ATA_OUTB(ch->r_bmio, ATA_BMSTAT_PORT, dmastat|ATA_BMSTAT_INTERRUPT);
	    DELAY(1);
	}
	ctlr->interrupt[unit].function(ch);
    }
}

static void
ata_sii_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 4) + (ATA_DEV(atadev->unit) << 1);
    int mreg = atadev->channel->unit ? 0x84 : 0x80;
    int mask = 0x03 << (ATA_DEV(atadev->unit) << 2);
    int mval = pci_read_config(parent, mreg, 1) & ~mask;
    int error;

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    mode = ata_check_80pin(atadev, mode);

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success",
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	if (mode >= ATA_UDMA0) {
	    u_int8_t udmatimings[] = { 0xf, 0xb, 0x7, 0x5, 0x3, 0x2, 0x1 };
	    u_int8_t ureg = 0xac + devno;

	    pci_write_config(parent, mreg,
			     mval | (0x03 << (ATA_DEV(atadev->unit) << 2)), 1);
	    pci_write_config(parent, ureg, 
			     (pci_read_config(parent, ureg, 1) & 0x3f) |
			     udmatimings[mode & ATA_MODE_MASK], 1);

	}
	else if (mode >= ATA_WDMA0) {
	    u_int8_t dreg = 0xa8 + devno;
	    u_int16_t dmatimings[] = { 0x2208, 0x10c2, 0x10c1 };

	    pci_write_config(parent, mreg,
			     mval | (0x02 << (ATA_DEV(atadev->unit) << 2)), 1);
	    pci_write_config(parent, dreg, dmatimings[mode & ATA_MODE_MASK], 2);

	}
	else {
	    u_int8_t preg = 0xa4 + devno;
	    u_int16_t piotimings[] = { 0x328a, 0x2283, 0x1104, 0x10c3, 0x10c1 };

	    pci_write_config(parent, mreg,
			     mval | (0x01 << (ATA_DEV(atadev->unit) << 2)), 1);
	    pci_write_config(parent, preg, piotimings[mode & ATA_MODE_MASK], 2);
	}
	atadev->mode = mode;
    }
}

static void
ata_cmd_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    mode = ata_check_80pin(atadev, mode);

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success",
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	int treg = 0x54 + (devno < 3) ? (devno << 1) : 7;
	int ureg = atadev->channel->unit ? 0x7b : 0x73;

	if (mode >= ATA_UDMA0) {	
	    int udmatimings[][2] = { { 0x31,  0xc2 }, { 0x21,  0x82 },
				     { 0x11,  0x42 }, { 0x25,  0x8a },
				     { 0x15,  0x4a }, { 0x05,  0x0a } };

	    u_int8_t umode = pci_read_config(parent, ureg, 1);

	    umode &= ~(atadev->unit == ATA_MASTER ? 0x35 : 0xca);
	    umode |= udmatimings[mode & ATA_MODE_MASK][ATA_DEV(atadev->unit)];
	    pci_write_config(parent, ureg, umode, 1);
	}
	else if (mode >= ATA_WDMA0) { 
	    int dmatimings[] = { 0x87, 0x32, 0x3f };

	    pci_write_config(parent, treg, dmatimings[mode & ATA_MODE_MASK], 1);
	    pci_write_config(parent, ureg, 
			     pci_read_config(parent, ureg, 1) &
			     ~(atadev->unit == ATA_MASTER ? 0x35 : 0xca), 1);
	}
	else {
	   int piotimings[] = { 0xa9, 0x57, 0x44, 0x32, 0x3f };
	    pci_write_config(parent, treg,
			     piotimings[(mode & ATA_MODE_MASK) - ATA_PIO0], 1);
	    pci_write_config(parent, ureg, 
			     pci_read_config(parent, ureg, 1) &
			     ~(atadev->unit == ATA_MASTER ? 0x35 : 0xca), 1);
	}
	atadev->mode = mode;
    }
}

/*
 * SiS chipset support functions
 */
int
ata_sis_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_SIS963, 0x00, SIS133NEW, 0, ATA_UDMA6, "SiS 963" },	/* south */
     { ATA_SIS962, 0x00, SIS133NEW, 0, ATA_UDMA6, "SiS 962" },	/* south */

     { ATA_SIS755, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 755" },	/* ext south */
     { ATA_SIS752, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 752" },	/* unknown */
     { ATA_SIS751, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 751" },	/* unknown */
     { ATA_SIS750, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 750" },	/* unknown */
     { ATA_SIS748, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 748" },	/* unknown */
     { ATA_SIS746, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 746" },	/* ext south */
     { ATA_SIS745, 0x00, SIS100NEW, 0, ATA_UDMA5, "SiS 745" },	/* 1chip */
     { ATA_SIS740, 0x00, SIS_SOUTH, 0, ATA_UDMA5, "SiS 740" },	/* ext south */
     { ATA_SIS735, 0x00, SIS100NEW, 0, ATA_UDMA5, "SiS 735" },	/* 1chip */
     { ATA_SIS733, 0x00, SIS100NEW, 0, ATA_UDMA5, "SiS 733" },	/* 1chip */
     { ATA_SIS730, 0x00, SIS100OLD, 0, ATA_UDMA5, "SiS 730" },	/* 1chip */

     { ATA_SIS658, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 658" },	/* ext south */
     { ATA_SIS655, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 655" },	/* ext south */
     { ATA_SIS652, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 652" },	/* unknown */
     { ATA_SIS651, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 651" },	/* ext south */
     { ATA_SIS650, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 650" },	/* ext south */
     { ATA_SIS648, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 648" },	/* ext south */
     { ATA_SIS646, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 645DX" },/* ext south */
     { ATA_SIS645, 0x00, SIS_SOUTH, 0, ATA_UDMA6, "SiS 645" },	/* ext south */
     { ATA_SIS640, 0x00, SIS_SOUTH, 0, ATA_UDMA4, "SiS 640" },	/* ext south */
     { ATA_SIS635, 0x00, SIS100NEW, 0, ATA_UDMA5, "SiS 635" },	/* unknown */
     { ATA_SIS633, 0x00, SIS100NEW, 0, ATA_UDMA5, "SiS 633" },	/* unknown */
     { ATA_SIS630, 0x30, SIS100NEW, 0, ATA_UDMA5, "SiS 630S" }, /* 1chip */
     { ATA_SIS630, 0x00, SIS66,	    0, ATA_UDMA4, "SiS 630" },	/* 1chip */
     { ATA_SIS620, 0x00, SIS66,	    0, ATA_UDMA4, "SiS 620" },	/* 1chip */

     { ATA_SIS550, 0x00, SIS66,	    0, ATA_UDMA5, "SiS 550" },
     { ATA_SIS540, 0x00, SIS66,	    0, ATA_UDMA4, "SiS 540" },
     { ATA_SIS530, 0x00, SIS66,	    0, ATA_UDMA4, "SiS 530" },
     { 0, 0, 0, 0, 0, 0 }};
    char buffer[64];

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    if (idx->cfg1 == SIS_SOUTH) {
	pci_write_config(dev, 0x57, pci_read_config(dev, 0x57, 1) & 0x7f, 1);
	if (pci_read_config(dev, 0x00, 4) == ATA_SIS5518) {
	    idx->cfg1 = SIS133NEW;
	    sprintf(buffer, "SiS 96X %s controller",ata_mode2str(idx->max_dma));
	}
	else {
	    if (ata_find_dev(dev, ATA_SISSOUTH, 0x10))
		idx->cfg1 = SIS133OLD;
	    else {
		idx->max_dma = ATA_UDMA5;
		idx->cfg1 = SIS100NEW;
	    }
	    sprintf(buffer, "SiS 961 %s controller",ata_mode2str(idx->max_dma));
	}
	pci_write_config(dev, 0x57, pci_read_config(dev, 0x57, 1) | 0x80, 1);
    }
    else
	sprintf(buffer,"%s %s controller",idx->text,ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_sis_chipinit;
    return 0;
}

static int
ata_sis_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;
    
    switch (ctlr->chip->cfg1) {
    case SIS66:
    case SIS100OLD:
	pci_write_config(dev, 0x52, pci_read_config(dev, 0x52, 1) | 0x04, 1);
	break;
    case SIS100NEW:
    case SIS133OLD:
	pci_write_config(dev, 0x49, pci_read_config(dev, 0x49, 1) | 0x01, 1);
	break;
    case SIS133NEW:
	pci_write_config(dev, 0x50, pci_read_config(dev, 0x50, 2) & 0xfff7, 2);
	pci_write_config(dev, 0x52, pci_read_config(dev, 0x52, 2) & 0xfff7, 2);
	break;
    default:
	return ENXIO;
    }
    ctlr->setmode = ata_sis_setmode;
    return 0;
}

static void
ata_sis_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int error;

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    if (ctlr->chip->cfg1 == SIS133NEW) {
	if (mode > ATA_UDMA2 &&
	    pci_read_config(parent, atadev->channel->unit?0x52:0x50,2)&0x8000){
		ata_prtdev(atadev,
		    "DMA limited to UDMA33, non-ATA66 cable or device\n");
	    mode = ATA_UDMA2;
	}
    }
    else {
	if (mode > ATA_UDMA2 &&
	    pci_read_config(parent, 0x48, 1) & atadev->channel->unit?0x20:0x10){
		ata_prtdev(atadev,
		    "DMA limited to UDMA33, non-ATA66 cable or device\n");
	    mode = ATA_UDMA2;
	}
    }

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success",
		   ata_mode2str(mode), ctlr->chip->text);
    if (!error) {
	switch (ctlr->chip->cfg1) {
	case SIS133NEW: {
	    u_int32_t timings[] = 
		{ 0x28269008, 0x0c266008, 0x04263008, 0x0c0a3008, 0x05093008,
		  0x22190608, 0x0c0a3008, 0x05093008, 0x050939fc, 0x050936ac,
		  0x0509347c, 0x0509325c, 0x0509323c, 0x0509322c, 0x0509321c};
	    u_int32_t reg;

	    reg = (pci_read_config(parent, 0x57, 1)&0x40?0x70:0x40)+(devno<<2);
	    pci_write_config(parent, reg, timings[ata_mode2idx(mode)], 4);
	    break;
	    }
	case SIS133OLD: {
	    u_int16_t timings[] =
	     { 0x00cb, 0x0067, 0x0044, 0x0033, 0x0031, 0x0044, 0x0033, 0x0031,
	       0x8f31, 0x8a31, 0x8731, 0x8531, 0x8331, 0x8231, 0x8131 };
		  
	    u_int16_t reg = 0x40 + (devno << 1);

	    pci_write_config(parent, reg, timings[ata_mode2idx(mode)], 2);
	    break;
	    }
	case SIS100NEW: {
	    u_int16_t timings[] =
		{ 0x00cb, 0x0067, 0x0044, 0x0033, 0x0031, 0x0044, 0x0033,
		  0x0031, 0x8b31, 0x8731, 0x8531, 0x8431, 0x8231, 0x8131 };
	    u_int16_t reg = 0x40 + (devno << 1);

	    pci_write_config(parent, reg, timings[ata_mode2idx(mode)], 2);
	    break;
	    }
	case SIS100OLD:
	case SIS66: {
	    u_int16_t timings[] =
		{ 0x0c0b, 0x0607, 0x0404, 0x0303, 0x0301, 0x0404, 0x0303,
		  0x0301, 0xf301, 0xd301, 0xb301, 0xa301, 0x9301, 0x8301 };
	    u_int16_t reg = 0x40 + (devno << 1);

	    pci_write_config(parent, reg, timings[ata_mode2idx(mode)], 2);
	    break;
	    }
	}
	atadev->mode = mode;
    }
}

/* VIA chipsets */
int
ata_via_ident(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    struct ata_chip_id *idx;
    static struct ata_chip_id ids[] =
    {{ ATA_VIA82C586, 0x02, VIA33,  0x00,   ATA_UDMA2, "VIA 82C586b" },
     { ATA_VIA82C586, 0x00, VIA33,  0x00,   ATA_WDMA2, "VIA 82C586" },
     { ATA_VIA82C596, 0x12, VIA66,  VIACLK, ATA_UDMA4, "VIA 82C596b" },
     { ATA_VIA82C596, 0x00, VIA33,  0x00,   ATA_UDMA2, "VIA 82C596" },
     { ATA_VIA82C686, 0x40, VIA100, VIABUG, ATA_UDMA5, "VIA 82C686b"},
     { ATA_VIA82C686, 0x10, VIA66,  VIACLK, ATA_UDMA4, "VIA 82C686a" },
     { ATA_VIA82C686, 0x00, VIA33,  0x00,   ATA_UDMA2, "VIA 82C686" },
     { ATA_VIA8231,   0x00, VIA100, VIABUG, ATA_UDMA5, "VIA 8231" },
     { ATA_VIA8233,   0x00, VIA100, 0x00,   ATA_UDMA5, "VIA 8233" },
     { ATA_VIA8233C,  0x00, VIA100, 0x00,   ATA_UDMA5, "VIA 8233c" },
     { ATA_VIA8233A,  0x00, VIA133, 0x00,   ATA_UDMA6, "VIA 8233a" },
     { ATA_VIA8235,   0x00, VIA133, 0x00,   ATA_UDMA6, "VIA 8235" },
     { 0, 0, 0, 0, 0, 0 }};
    char buffer[64];

    if (!(idx = ata_match_chip(dev, ids))) 
	return ENXIO;

    sprintf(buffer, "%s %s controller", idx->text, ata_mode2str(idx->max_dma));
    device_set_desc_copy(dev, buffer);
    ctlr->chip = idx;
    ctlr->chipinit = ata_via_chipinit;
    return 0;
}

static int
ata_via_chipinit(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);

    if (ata_default_interrupt(dev))
	return ENXIO;
    
    /* prepare for ATA-66 on the 82C686a and 82C596b */
    if (ctlr->chip->cfg2 & VIACLK)
	pci_write_config(dev, 0x50, 0x030b030b, 4);	  

    /* the southbridge might need the data corruption fix */
    if (ctlr->chip->cfg2 & VIABUG)
	ata_via_southbridge_fixup(dev);

    /* set prefetch, postwrite */
    pci_write_config(dev, 0x41, pci_read_config(dev, 0x41, 1) | 0xf0, 1);

    /* set fifo configuration half'n'half */
    pci_write_config(dev, 0x43, 
		     (pci_read_config(dev, 0x43, 1) & 0x90) | 0x2a, 1);

    /* set status register read retry */
    pci_write_config(dev, 0x44, pci_read_config(dev, 0x44, 1) | 0x08, 1);

    /* set DMA read & end-of-sector fifo flush */
    pci_write_config(dev, 0x46, 
		     (pci_read_config(dev, 0x46, 1) & 0x0c) | 0xf0, 1);

    /* set sector size */
    pci_write_config(dev, 0x60, DEV_BSIZE, 2);
    pci_write_config(dev, 0x68, DEV_BSIZE, 2);

    ctlr->setmode = ata_via_family_setmode;
    return 0;
}

static void
ata_via_southbridge_fixup(device_t dev)
{
    device_t *children;
    int nchildren, i;

    if (device_get_children(device_get_parent(dev), &children, &nchildren))
	return;

    for (i = 0; i < nchildren; i++) {
	if (pci_get_devid(children[i]) == ATA_VIA8363 ||
	    pci_get_devid(children[i]) == ATA_VIA8371 ||
	    pci_get_devid(children[i]) == ATA_VIA8662 ||
	    pci_get_devid(children[i]) == ATA_VIA8361) {
	    u_int8_t reg76 = pci_read_config(children[i], 0x76, 1);

	    if ((reg76 & 0xf0) != 0xd0) {
		device_printf(dev,
		"Correcting VIA config for southbridge data corruption bug\n");
		pci_write_config(children[i], 0x75, 0x80, 1);
		pci_write_config(children[i], 0x76, (reg76 & 0x0f) | 0xd0, 1);
	    }
	    break;
	}
    }
    free(children, M_TEMP);
}

/* common code for VIA, AMD & nVidia */
static void
ata_via_family_setmode(struct ata_device *atadev, int mode)
{
    device_t parent = device_get_parent(atadev->channel->dev);
    struct ata_pci_controller *ctlr = device_get_softc(parent);
    u_int8_t timings[] = { 0xff, 0xff, 0xff, 0x55, 0x51, 0xff, 0x55, 0x51,
			   0x51, 0x51, 0x51, 0x51, 0x51, 0x51 };
    int modes[][7] = {
	{ 0xc2, 0xc1, 0xc0, 0x00, 0x00, 0x00, 0x00 },	/* VIA ATA33 */
	{ 0xee, 0xec, 0xea, 0xe9, 0xe8, 0x00, 0x00 },	/* VIA ATA66 */
	{ 0xf7, 0xf6, 0xf4, 0xf2, 0xf1, 0xf0, 0x00 },	/* VIA ATA100 */
	{ 0xf7, 0xf7, 0xf6, 0xf4, 0xf2, 0xf1, 0xf0 },	/* VIA ATA133 */
	{ 0xc2, 0xc1, 0xc0, 0xc4, 0xc5, 0xc6, 0xc7 }};	/* AMD/nVIDIA */
    int devno = (atadev->channel->unit << 1) + ATA_DEV(atadev->unit);
    int reg = 0x53 - devno;
    int error;

    mode = ata_limit_mode(atadev, mode, ctlr->chip->max_dma);

    if (ctlr->chip->cfg2 & AMDCABLE) {
	if (mode > ATA_UDMA2 && !pci_read_config(parent, 0x42, 1) & (1<<devno)){
		ata_prtdev(atadev,
		    "DMA limited to UDMA33, non-ATA66 cable or device\n");
	    mode = ATA_UDMA2;
	}
    }
    else 
	mode = ata_check_80pin(atadev, mode);

    if (ctlr->chip->cfg2 & NVIDIA)
	reg += 0x10;

    pci_write_config(parent, reg - 0x08, timings[ata_mode2idx(mode)], 1);

    error = ata_command(atadev, ATA_C_SETFEATURES, 0, mode,
			ATA_C_F_SETXFER, ATA_WAIT_READY);
    if (bootverbose)
	ata_prtdev(atadev, "%s setting %s on %s chip\n",
		   (error) ? "failed" : "success", ata_mode2str(mode),
		   ctlr->chip->text);
    if (!error) {
	if (mode >= ATA_UDMA0)
	    pci_write_config(parent, reg,
			     modes[ctlr->chip->cfg1][mode & ATA_MODE_MASK], 1);
	else
	    pci_write_config(parent, reg, 0x8b, 1);
	atadev->mode = mode;
    }
}

/* misc functions */
static int
ata_mode2idx(int mode)
{
    if ((mode & ATA_DMA_MASK) == ATA_UDMA0)
	 return (mode & ATA_MODE_MASK) + 8;
    if ((mode & ATA_DMA_MASK) == ATA_WDMA0)
	 return (mode & ATA_MODE_MASK) + 5;
    return (mode & ATA_MODE_MASK) - ATA_PIO0;
}

static int
ata_check_80pin(struct ata_device *atadev, int mode)
{
    if (mode > ATA_UDMA2 && !atadev->param->hwres_cblid) {
	ata_prtdev(atadev,"DMA limited to UDMA33, non-ATA66 cable or device\n");
	mode = ATA_UDMA2;
    }
    return mode;
}

static int
ata_find_dev(device_t dev, u_int32_t devid, u_int32_t revid)
{
    device_t *children;
    int nchildren, i;

    if (device_get_children(device_get_parent(dev), &children, &nchildren))
	return 0;

    for (i = 0; i < nchildren; i++) {
	if (pci_get_devid(children[i]) == devid &&
	    pci_get_revid(children[i]) >= revid) {
	    free(children, M_TEMP);
	    return 1;
	}
    }
    free(children, M_TEMP);
    return 0;
}

static struct ata_chip_id *
ata_match_chip(device_t dev, struct ata_chip_id *index)
{
    while (index->chiptype != 0) {
	if (ata_find_dev(dev, index->chiptype, index->chiprev))
	    return index;
	index++;
    }
    return NULL;
}

static int
ata_default_interrupt(device_t dev)
{
    struct ata_pci_controller *ctlr = device_get_softc(dev);
    int rid = ATA_IRQ_RID;

    if (!ATA_MASTERDEV(dev)) {
	if (!(ctlr->r_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1,
					       RF_SHAREABLE | RF_ACTIVE))) {
	    device_printf(dev, "unable to map interrupt\n");
	    return ENXIO;
	}
	if ((bus_setup_intr(dev, ctlr->r_irq, INTR_TYPE_BIO | INTR_ENTROPY,
			    ata_generic_intr, ctlr, &ctlr->handle))) {
	    device_printf(dev, "unable to setup interrupt\n");
	    return ENXIO;
	}
    }
    return 0;
}

static void
ata_pci_serialize(struct ata_channel *ch, int flags)
{
    struct ata_pci_controller *scp =
	device_get_softc(device_get_parent(ch->dev));

    switch (flags) {
    case ATA_LF_LOCK:
	if (scp->locked_ch == ch->unit)
	    break;
	while (!atomic_cmpset_acq_int(&scp->locked_ch, -1, ch->unit))
	    tsleep(ch->locking, PRIBIO, "atalck", 1);
	break;

    case ATA_LF_UNLOCK:
	if (scp->locked_ch == -1 || scp->locked_ch != ch->unit)
	    break;
	atomic_store_rel_int(&scp->locked_ch, -1);
	wakeup(ch->locking);
	break;
    }
    return;
}
