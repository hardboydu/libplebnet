/*-
 * Copyright (c) 1998,1999,2000 S�ren Schmidt
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

#include "pci.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/malloc.h> 
#include <sys/bus.h>
#include <sys/disk.h>
#include <sys/devicestat.h>
#include <vm/vm.h>	     
#include <vm/pmap.h>
#if NPCI > 0
#include <pci/pcivar.h>
#endif
#include <dev/ata/ata-all.h>
#include <dev/ata/ata-disk.h>

#if NPCI > 0

/* prototypes */
static void promise_timing(struct ata_softc *, int32_t, int32_t);
static void hpt_timing(struct ata_softc *, int32_t, int32_t);

/* misc defines */
#ifdef __alpha__
#undef vtophys
#define vtophys(va)	alpha_XXX_dmamap((vm_offset_t)va)
#endif

void
ata_dmainit(struct ata_softc *scp, int32_t device, 
	    int32_t apiomode, int32_t wdmamode, int32_t udmamode)
{
    device_t parent = device_get_parent(scp->dev);
    int devno = (scp->unit << 1) + ATA_DEV(device);
    int error;

    /* set our most pessimistic default mode */
    scp->mode[ATA_DEV(device)] = ATA_PIO;

    if (!scp->bmaddr)
	return;

    /* if simplex controller, only allow DMA on primary channel */
    if (scp->unit == 1) {
	outb(scp->bmaddr + ATA_BMSTAT_PORT, inb(scp->bmaddr + ATA_BMSTAT_PORT) &
	     (ATA_BMSTAT_DMA_MASTER | ATA_BMSTAT_DMA_SLAVE));
	if (inb(scp->bmaddr + ATA_BMSTAT_PORT) & ATA_BMSTAT_DMA_SIMPLEX) {
	    ata_printf(scp, device, "simplex device, DMA on primary only\n");
	    return;
	}
    }

    if (!scp->dmatab[ATA_DEV(device)]) {
	void *dmatab;

	if (!(dmatab = malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT)))
	    return;
	if (((uintptr_t)dmatab >> PAGE_SHIFT) ^
	    (((uintptr_t)dmatab + PAGE_SIZE - 1) >> PAGE_SHIFT)) {
	    ata_printf(scp, device, "dmatab crosses page boundary, no DMA\n");
	    free(dmatab, M_DEVBUF);
	    return;
	}
	scp->dmatab[ATA_DEV(device)] = dmatab;
    }
    if (udmamode > 2 && !ATA_PARAM(scp, device)->cblid) {
	ata_printf(scp, device,
		   "DMA limited to UDMA33, non-ATA66 compliant cable\n");
	udmamode = 2;
    }

    switch (scp->chiptype) {

    case 0x244b8086:	/* Intel ICH2 */
	if (udmamode >= 5) {
	    int32_t mask48, new48;
	    int16_t word54;

	    word54 = pci_read_config(parent, 0x54, 2);
	    if (word54 & (0x10 << devno)) {
	        error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				    ATA_UDMA5,  ATA_C_F_SETXFER,ATA_WAIT_READY);
	    	if (bootverbose)
		    ata_printf(scp, device,
			       "%s setting up UDMA5 mode on ICH2 chip\n",
			       (error) ? "failed" : "success");
		if (!error) {
		    mask48 = (1 << devno) + (3 << (16 + (devno << 2)));
		    new48 = (1 << devno) + (1 << (16 + (devno << 2)));
		    pci_write_config(parent, 0x48,
				     (pci_read_config(parent, 0x48, 4) &
				     ~mask48) | new48, 4);
	    	    pci_write_config(parent, 0x54, word54 | (0x1000<<devno), 2);
		    scp->mode[ATA_DEV(device)] = ATA_UDMA5;
		    return;
		}
	    }
	}
	/* make sure eventual ATA100 mode from the BIOS is disabled */
	pci_write_config(parent, 0x54, 
			 pci_read_config(parent, 0x54, 2) & ~(0x1000<<devno),2);
	/* FALLTHROUGH */

    case 0x24118086:    /* Intel ICH */
	if (udmamode >= 4) {
	    int32_t mask48, new48;
	    int16_t word54;

	    word54 = pci_read_config(parent, 0x54, 2);
	    if (word54 & (0x10 << devno)) {
	        error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				    ATA_UDMA4,  ATA_C_F_SETXFER,ATA_WAIT_READY);
	    	if (bootverbose)
		    ata_printf(scp, device,
			       "%s setting up UDMA4 mode on ICH%s chip\n",
			       (error) ? "failed" : "success",
			       (scp->chiptype == 0x244b8086) ? "2" : "");
		if (!error) {
		    mask48 = (1 << devno) + (3 << (16 + (devno << 2)));
		    new48 = (1 << devno) + (2 << (16 + (devno << 2)));
		    pci_write_config(parent, 0x48,
				     (pci_read_config(parent, 0x48, 4) &
				     ~mask48) | new48, 4);
		    pci_write_config(parent, 0x54, word54 | (1 << devno), 2);
		    scp->mode[ATA_DEV(device)] = ATA_UDMA4;
		    return;
		}
	    }
	}           
	/* make sure eventual ATA66 mode from the BIOS is disabled */
	pci_write_config(parent, 0x54, 
			 pci_read_config(parent, 0x54, 2) & ~(1 << devno), 2);
	/* FALLTHROUGH */

    case 0x71118086:	/* Intel PIIX4 */
    case 0x71998086:	/* Intel PIIX4e */
    case 0x24218086:	/* Intel ICH0 */
	if (udmamode >= 2) {
	    int32_t mask48, new48;

	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, "%s setting up UDMA2 mode on %s chip\n",
			   (error) ? "failed" : "success",
			   (scp->chiptype == 0x244b8086) ? "ICH2" : 
			    (scp->chiptype == 0x24118086) ? "ICH" : 
			     (scp->chiptype == 0x24218086) ? "ICH0" :"PIIX4");
	    if (!error) {
		mask48 = (1 << devno) + (3 << (16 + (devno << 2)));
		new48 = (1 << devno) + (2 << (16 + (devno << 2)));
		pci_write_config(parent, 0x48, 
				 (pci_read_config(parent, 0x48, 4) &
				 ~mask48) | new48, 4);
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	/* make sure eventual ATA33 mode from the BIOS is disabled */
	pci_write_config(parent, 0x48, 
			 pci_read_config(parent, 0x48, 4) & ~(1 << devno), 4);
	/* FALLTHROUGH */

    case 0x70108086:	/* Intel PIIX3 */
	if (wdmamode >= 2 && apiomode >= 4) {
	    int32_t mask40, new40, mask44, new44;

	    /* if SITRE not set doit for both channels */
	    if (!((pci_read_config(parent, 0x40, 4)>>(scp->unit<<8))&0x4000)){
		new40 = pci_read_config(parent, 0x40, 4);
		new44 = pci_read_config(parent, 0x44, 4); 
		if (!(new40 & 0x00004000)) {
		    new44 &= ~0x0000000f;
		    new44 |= ((new40&0x00003000)>>10)|((new40&0x00000300)>>8);
		}
		if (!(new40 & 0x40000000)) {
		    new44 &= ~0x000000f0;
		    new44 |= ((new40&0x30000000)>>22)|((new40&0x03000000)>>20);
		}
		new40 |= 0x40004000;
		pci_write_config(parent, 0x40, new40, 4);
		pci_write_config(parent, 0x44, new44, 4);
	    }
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, "%s setting up WDMA2 mode on %s chip\n",
			   (error) ? "failed" : "success",
			   (scp->chiptype == 0x244b8086) ? "ICH2" : 
			    (scp->chiptype == 0x24118086) ? "ICH" :
			     (scp->chiptype == 0x24218086) ? "ICH0" :
			      (scp->chiptype == 0x70108086) ? "PIIX3":"PIIX4");
	    if (!error) {
		if (device == ATA_MASTER) {
		    mask40 = 0x0000330f;
		    new40 = 0x00002307;
		    mask44 = 0;
		    new44 = 0;
		}
		else {
		    mask40 = 0x000000f0;
		    new40 = 0x00000070;
		    mask44 = 0x0000000f;
		    new44 = 0x0000000b;
		}
		if (scp->unit) {
		    mask40 <<= 16;
		    new40 <<= 16;
		    mask44 <<= 4;
		    new44 <<= 4;
		}
		pci_write_config(parent, 0x40,
				 (pci_read_config(parent, 0x40, 4) & ~mask40)|
 				 new40, 4);
		pci_write_config(parent, 0x44,
				 (pci_read_config(parent, 0x44, 4) & ~mask44)|
 				 new44, 4);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	/* we could set PIO mode timings, but we assume the BIOS did that */
	break;

    case 0x12308086:	/* Intel PIIX */
	if (wdmamode >= 2 && apiomode >= 4) {
	    int32_t word40;

	    word40 = pci_read_config(parent, 0x40, 4);
	    word40 >>= scp->unit * 16;

	    /* Check for timing config usable for DMA on controller */
	    if (!((word40 & 0x3300) == 0x2300 &&
		  ((word40 >> (device == ATA_MASTER ? 0 : 4)) & 1) == 1))
		break;

	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, 
			   "%s setting up WDMA2 mode on PIIX chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	break;

    case 0x522910b9:	/* AcerLabs Aladdin IV/V */
	/* the Aladdin doesn't support ATAPI DMA on both master & slave */
	if (scp->devices & ATA_ATAPI_MASTER && scp->devices & ATA_ATAPI_SLAVE) {
	    ata_printf(scp, device,
		       "Aladdin: two atapi devices on this channel, no DMA\n");
	    break;
	}
	if (udmamode >= 2) {
	    int32_t word54 = pci_read_config(parent, 0x54, 4);
	
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA2 mode on Aladdin chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		word54 &= ~(0x000f000f << (devno << 2));
		word54 |= (0x000a0005 << (devno << 2));
		pci_write_config(parent, 0x54, word54, 4);
		pci_write_config(parent, 0x53, 
				 pci_read_config(parent, 0x53, 1) | 0x03, 1);
		scp->flags |= ATA_ATAPI_DMA_RO;
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	if (wdmamode >= 2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, 
			   "%s setting up WDMA2 mode on Aladdin chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		pci_write_config(parent, 0x53, 
				 pci_read_config(parent, 0x53, 1) | 0x03, 1);
		scp->flags |= ATA_ATAPI_DMA_RO;
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	pci_write_config(parent, 0x53,
			 (pci_read_config(parent, 0x53, 1) & ~0x01) | 0x02, 1);
	/* we could set PIO mode timings, but we assume the BIOS did that */
	break;

    case 0x74091022:	/* AMD 756 */
	if (udmamode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA4, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA4 mode on AMD chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
	        pci_write_config(parent, 0x53 - devno, 0xc3, 1);
		scp->mode[ATA_DEV(device)] = ATA_UDMA4;
		return;
	    }
	}
	goto via_82c586;

    case 0x06861106:	/* VIA 82C686 */
via_82c686:
	if (udmamode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA4, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, 
			   "%s setting up UDMA4 mode on VIA chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		pci_write_config(parent, 0x53 - devno, 0xe8, 1);
		scp->mode[ATA_DEV(device)] = ATA_UDMA4;
		return;
	    }
	}
	if (udmamode >= 2) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA2 mode on VIA chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		pci_write_config(parent, 0x53 - devno, 0xea, 1);
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	goto via_generic;

    case 0x05961106:	/* VIA 82C596 */
	/* 82c596 revision >= 0x12 is like the 82c686 */
	if (ata_find_dev(parent, 0x05961106, 0x12))
	    goto via_82c686;
	/* FALLTHROUGH */

    case 0x05861106:	/* VIA 82C586 */
via_82c586:
	/* UDMA2 mode only on 82C586 > rev1, 82C596, AMD 756 */
	if ((udmamode >= 2 && ata_find_dev(parent, 0x05861106, 0x02)) ||
	    (udmamode >= 2 && scp->chiptype == 0x05961106) ||
	    (udmamode >= 2 && scp->chiptype == 0x74091022)) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, "%s setting up UDMA2 mode on %s chip\n",
			   (error) ? "failed" : "success",
			   (scp->chiptype == 0x74091022) ? "AMD" : "VIA");
	    if (!error) {
	        pci_write_config(parent, 0x53 - devno, 0xc0, 1);
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	/* FALLTHROUGH */

    case 0x05711106:	/* VIA 82C571 */
via_generic:
	if (wdmamode >= 2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device, "%s setting up WDMA2 mode on %s chip\n",
			   (error) ? "failed" : "success",
			   (scp->chiptype == 0x74091022) ? "AMD" : "VIA");
	    if (!error) {
	        pci_write_config(parent, 0x53 - devno, 0x82, 1);
	        pci_write_config(parent, 0x4b - devno, 0x31, 1);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	/* we could set PIO mode timings, but we assume the BIOS did that */
	break;

    case 0x55131039:	/* SiS 5591 */
	if (udmamode >= 2) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA2 mode on SiS chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		pci_write_config(parent, 0x40 + (devno << 1), 0xa301, 2);
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	if (wdmamode >=2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up WDMA2 mode on SiS chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		pci_write_config(parent, 0x40 + (devno << 1), 0x0301, 2);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	/* we could set PIO mode timings, but we assume the BIOS did that */
	break;

    case 0x06461095:	/* CMD 646 ATA controller */
	if (wdmamode >= 2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up WDMA2 mode on CMD646 chip\n",
			   error ? "failed" : "success");
	    if (!error) {
		int32_t offset = (devno < 3) ? (devno << 1) : 7;

		pci_write_config(parent, 0x54 + offset, 0x3f, 1);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	/* we could set PIO mode timings, but we assume the BIOS did that */
	break;

    case 0xc6931080:	/* Cypress 82c693 ATA controller */
	if (wdmamode >= 2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up WDMA2 mode on Cypress chip\n",
			   error ? "failed" : "success");
	    if (!error) {
		pci_write_config(scp->dev, scp->unit ? 0x4e : 0x4c, 0x2020, 2);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	/* we could set PIO mode timings, but we assume the BIOS did that */
	break;

    case 0x4d33105a:	/* Promise Ultra33 / FastTrak33 controllers */
    case 0x4d38105a:	/* Promise Ultra66 / FastTrak66 controllers */
    case 0x4d30105a:	/* Promise Ultra100 / FastTrak100 controllers */
	/* the Promise can only do DMA on ATA disks not on ATAPI devices */
	if ((device == ATA_MASTER && scp->devices & ATA_ATAPI_MASTER) ||
	    (device == ATA_SLAVE && scp->devices & ATA_ATAPI_SLAVE))
	    break;

	if (udmamode >=5 && scp->chiptype == 0x4d30105a &&
	    !(pci_read_config(parent, 0x50, 2)&(scp->unit ? 1<<11 : 1<<10))) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA5, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA5 mode on Promise chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		promise_timing(scp, devno, ATA_UDMA5);
		scp->mode[ATA_DEV(device)] = ATA_UDMA5;
		return;
	    }
	}
	if (udmamode >=4 && 
	    (scp->chiptype == 0x4d38105a || scp->chiptype == 0x4d30105a) &&
	    !(pci_read_config(parent, 0x50, 2)&(scp->unit ? 1<<11 : 1<<10))) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA4, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA4 mode on Promise chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		promise_timing(scp, devno, ATA_UDMA4);
		scp->mode[ATA_DEV(device)] = ATA_UDMA4;
		return;
	    }
	}
	if (udmamode >= 2) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA2 mode on Promise chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		promise_timing(scp, devno, ATA_UDMA2);
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	if (wdmamode >= 2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up WDMA2 mode on Promise chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		promise_timing(scp, devno, ATA_WDMA2);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
			    ata_pio2mode(apiomode), 
			    ATA_C_F_SETXFER, ATA_WAIT_READY);
	if (bootverbose)
	    ata_printf(scp, device,
		       "%s setting up PIO%d mode on Promise chip\n",
		       (error) ? "failed" : "success",
		       (apiomode >= 0) ? apiomode : 0);
	promise_timing(scp, devno, ata_pio2mode(apiomode));
	scp->mode[ATA_DEV(device)] = ata_pio2mode(apiomode);
	return;
    
    case 0x00041103:	/* HighPoint HPT366/368/370 controllers */
	/* no ATAPI devices for now */
	if ((device == ATA_MASTER && scp->devices & ATA_ATAPI_MASTER) ||
	    (device == ATA_SLAVE && scp->devices & ATA_ATAPI_SLAVE))
	    break;

	if (udmamode >=5 && pci_get_revid(parent) >= 0x03 &&
	    !(pci_read_config(parent, 0x5a, 1) & (scp->unit ? 0x01 : 0x02))) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA5, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA5 mode on HPT370 chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		hpt_timing(scp, devno, ATA_UDMA5);
		scp->mode[ATA_DEV(device)] = ATA_UDMA5;
		return;
	    }
	}

	if (udmamode >=4 && 
	    !(pci_read_config(parent, 0x5a, 1) & (scp->unit ? 0x01 : 0x02))) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA4, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA4 mode on HPT366 chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		hpt_timing(scp, devno, ATA_UDMA4);
		scp->mode[ATA_DEV(device)] = ATA_UDMA4;
		return;
	    }
	}
	if (udmamode >= 2) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_UDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up UDMA2 mode on HPT366 chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		hpt_timing(scp, devno, ATA_UDMA2);
		scp->mode[ATA_DEV(device)] = ATA_UDMA2;
		return;
	    }
	}
	if (wdmamode >= 2 && apiomode >= 4) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up WDMA2 mode on HPT366 chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		hpt_timing(scp, devno, ATA_WDMA2);
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
	error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
			    ata_pio2mode(apiomode), 
			    ATA_C_F_SETXFER, ATA_WAIT_READY);
	if (bootverbose)
	    ata_printf(scp, device, "%s setting up PIO%d mode on HPT366 chip\n",
		       (error) ? "failed" : "success",
		       (apiomode >= 0) ? apiomode : 0);
	hpt_timing(scp, devno, ata_pio2mode(apiomode));
	scp->mode[ATA_DEV(device)] = ata_pio2mode(apiomode);
	return;

    default:		/* unknown controller chip */
	/* better not try generic DMA on ATAPI devices it almost never works */
	if ((device == ATA_MASTER && scp->devices & ATA_ATAPI_MASTER) ||
	    (device == ATA_SLAVE && scp->devices & ATA_ATAPI_SLAVE))
	    break;

	/* if controller says its setup for DMA take the easy way out */
	/* the downside is we dont know what DMA mode we are in */
	if ((udmamode >= 0 || wdmamode > 1) &&
	    (inb(scp->bmaddr + ATA_BMSTAT_PORT) &
	     ((device==ATA_MASTER) ? 
	      ATA_BMSTAT_DMA_MASTER : ATA_BMSTAT_DMA_SLAVE))) {
	    scp->mode[ATA_DEV(device)] = ATA_DMA;
	    return;
	}

	/* well, we have no support for this, but try anyways */
	if ((wdmamode >= 2 && apiomode >= 4) && scp->bmaddr) {
	    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
				ATA_WDMA2, ATA_C_F_SETXFER, ATA_WAIT_READY);
	    if (bootverbose)
		ata_printf(scp, device,
			   "%s setting up WDMA2 mode on generic chip\n",
			   (error) ? "failed" : "success");
	    if (!error) {
		scp->mode[ATA_DEV(device)] = ATA_WDMA2;
		return;
	    }
	}
    }
    error = ata_command(scp, device, ATA_C_SETFEATURES, 0, 0, 0,
			ata_pio2mode(apiomode), ATA_C_F_SETXFER,ATA_WAIT_READY);
    if (bootverbose)
	ata_printf(scp, device, "%s setting up PIO%d mode on generic chip\n",
		   (error) ? "failed" : "success", apiomode < 0 ? 0 : apiomode);
    if (!error)
        scp->mode[ATA_DEV(device)] = ata_pio2mode(apiomode);
    else {
	if (bootverbose)
	    ata_printf(scp, device, "using PIO mode set by BIOS\n");
        scp->mode[ATA_DEV(device)] = ATA_PIO;
    }
}

int32_t
ata_dmasetup(struct ata_softc *scp, int32_t device, 
	     int8_t *data, int32_t count, int32_t flags)
{
    struct ata_dmaentry *dmatab;
    u_int32_t dma_count, dma_base;
    int i = 0;

    if (((uintptr_t)data & 1) || (count & 1))
	return -1;

    if (!count) {
	ata_printf(scp, device, "zero length DMA transfer attempted\n");
	return -1;
    }
    
    dmatab = scp->dmatab[ATA_DEV(device)];
    dma_base = vtophys(data);
    dma_count = min(count, (PAGE_SIZE - ((uintptr_t)data & PAGE_MASK)));
    data += dma_count;
    count -= dma_count;

    while (count) {
	dmatab[i].base = dma_base;
	dmatab[i].count = (dma_count & 0xffff);
	i++; 
	if (i >= ATA_DMA_ENTRIES) {
	    ata_printf(scp, device, "too many segments in DMA table\n");
	    return -1;
	}
	dma_base = vtophys(data);
	dma_count = min(count, PAGE_SIZE);
	data += min(count, PAGE_SIZE);
	count -= min(count, PAGE_SIZE);
    }
    dmatab[i].base = dma_base;
    dmatab[i].count = (dma_count & 0xffff) | ATA_DMA_EOT;
    outl(scp->bmaddr + ATA_BMDTP_PORT, vtophys(dmatab));
    outb(scp->bmaddr + ATA_BMCMD_PORT, flags ? ATA_BMCMD_WRITE_READ:0);
    outb(scp->bmaddr + ATA_BMSTAT_PORT, (inb(scp->bmaddr + ATA_BMSTAT_PORT) | 
				   (ATA_BMSTAT_INTERRUPT | ATA_BMSTAT_ERROR)));
    return 0;
}

void
ata_dmastart(struct ata_softc *scp)
{
    scp->flags |= ATA_DMA_ACTIVE;
    outb(scp->bmaddr + ATA_BMCMD_PORT, 
	 inb(scp->bmaddr + ATA_BMCMD_PORT) | ATA_BMCMD_START_STOP);
}

int32_t
ata_dmadone(struct ata_softc *scp)
{
    outb(scp->bmaddr + ATA_BMCMD_PORT, 
	 inb(scp->bmaddr + ATA_BMCMD_PORT) & ~ATA_BMCMD_START_STOP);
    scp->flags &= ~ATA_DMA_ACTIVE;
    return inb(scp->bmaddr + ATA_BMSTAT_PORT) & ATA_BMSTAT_MASK;
}

int32_t
ata_dmastatus(struct ata_softc *scp)
{
    return inb(scp->bmaddr + ATA_BMSTAT_PORT) & ATA_BMSTAT_MASK;
}

static void
promise_timing(struct ata_softc *scp, int32_t devno, int32_t mode)
{
    u_int32_t timing = 0;
    struct promise_timing {
	u_int8_t  pa:4;
	u_int8_t  prefetch:1;
	u_int8_t  iordy:1;
	u_int8_t  errdy:1;
	u_int8_t  syncin:1;
	u_int8_t  pb:5;
	u_int8_t  mb:3;
	u_int8_t  mc:4;
	u_int8_t  dmaw:1;
	u_int8_t  dmar:1;
	u_int8_t  iordyp:1;
	u_int8_t  dmarqp:1;
	u_int8_t  reserved:8;
    } *t = (struct promise_timing*)&timing;

    t->iordy = 1; t->iordyp = 1;
    if (mode >= ATA_DMA) {
	t->prefetch = 1; t->errdy = 1; t->syncin = 1;
    }

    switch (scp->chiptype) {
    case 0x4d33105a:  /* Promise 33's */
	switch (mode) {
	default:
	case ATA_PIO0:  t->pa =  9; t->pb = 19; t->mb = 7; t->mc = 15; break;
	case ATA_PIO1:  t->pa =  5; t->pb = 12; t->mb = 7; t->mc = 15; break;
	case ATA_PIO2:  t->pa =  3; t->pb =  8; t->mb = 7; t->mc = 15; break;
	case ATA_PIO3:  t->pa =  2; t->pb =  6; t->mb = 7; t->mc = 15; break;
	case ATA_PIO4:  t->pa =  1; t->pb =  4; t->mb = 7; t->mc = 15; break;
	case ATA_WDMA2: t->pa =  3; t->pb =  7; t->mb = 3; t->mc =  3; break;
	case ATA_UDMA2: t->pa =  3; t->pb =  7; t->mb = 1; t->mc =  1; break;
	}
	break;

    case 0x4d38105a:  /* Promise 66's */
    case 0x4d30105a:  /* Promise 100's */
	switch (mode) {
	default:
	case ATA_PIO0:  t->pa = 15; t->pb = 31; t->mb = 7; t->mc = 15; break;
	case ATA_PIO1:  t->pa = 10; t->pb = 24; t->mb = 7; t->mc = 15; break;
	case ATA_PIO2:  t->pa =  6; t->pb = 16; t->mb = 7; t->mc = 15; break;
	case ATA_PIO3:  t->pa =  4; t->pb = 12; t->mb = 7; t->mc = 15; break;
	case ATA_PIO4:  t->pa =  2; t->pb =  8; t->mb = 7; t->mc = 15; break;
	case ATA_WDMA2: t->pa =  6; t->pb = 14; t->mb = 6; t->mc =  6; break;
	case ATA_UDMA2: t->pa =  6; t->pb = 14; t->mb = 2; t->mc =  2; break;
	case ATA_UDMA4: t->pa =  3; t->pb =  7; t->mb = 1; t->mc =  1; break;
	case ATA_UDMA5: t->pa =  3; t->pb =  7; t->mb = 1; t->mc =  1; break;
	}
	break;
    }
    pci_write_config(device_get_parent(scp->dev), 0x60 + (devno<<2), timing, 4);
}

static void
hpt_timing(struct ata_softc *scp, int32_t devno, int32_t mode)
{
    device_t parent = device_get_parent(scp->dev);
    u_int32_t timing;

    if (pci_get_revid(parent) >= 0x03) {	/* HPT370 */
	switch (mode) {
	case ATA_PIO0:	timing = 0x06914e57; break;
	case ATA_PIO1:	timing = 0x06914e43; break;
	case ATA_PIO2:	timing = 0x06514e33; break;
	case ATA_PIO3:	timing = 0x06514e22; break;
	case ATA_PIO4:	timing = 0x06514e21; break;
	case ATA_WDMA2:	timing = 0x26514e21; break;
	case ATA_UDMA2:	timing = 0x16494e31; break;
	case ATA_UDMA4:	timing = 0x16454e31; break;
	case ATA_UDMA5:	timing = 0x16454e31; break;
	default:	timing = 0x06514e57;
	}
	pci_write_config(parent, 0x40 + (devno << 2) , timing, 4);
	pci_write_config(parent, 0x5b, 0x22, 1);
    }
    else {					/* HPT36[68] */
	switch (pci_read_config(parent, 0x41 + (devno << 2), 1)) {
	case 0x85:	/* 25Mhz */
	    switch (mode) {
	    case ATA_PIO0:	timing = 0xc0d08585; break;
	    case ATA_PIO1:	timing = 0xc0d08572; break;
	    case ATA_PIO2:	timing = 0xc0ca8542; break;
	    case ATA_PIO3:	timing = 0xc0ca8532; break;
	    case ATA_PIO4:	timing = 0xc0ca8521; break;
	    case ATA_WDMA2:	timing = 0xa0ca8521; break;
	    case ATA_UDMA2:	timing = 0x90cf8521; break;
	    case ATA_UDMA4:	timing = 0x90c98521; break;
	    default:		timing = 0x01208585;
	    }
	    break;
	default:
	case 0xa7:	/* 33MHz */
	    switch (mode) {
	    case ATA_PIO0:	timing = 0xc0d0a7aa; break;
	    case ATA_PIO1:	timing = 0xc0d0a7a3; break;
	    case ATA_PIO2:	timing = 0xc0d0a753; break;
	    case ATA_PIO3:	timing = 0xc0c8a742; break;
	    case ATA_PIO4:	timing = 0xc0c8a731; break;
	    case ATA_WDMA2:	timing = 0xa0c8a731; break;
	    case ATA_UDMA2:	timing = 0x90caa731; break;
	    case ATA_UDMA4:	timing = 0x90c9a731; break;
	    default:		timing = 0x0120a7a7;
	    }
	    break;
	case 0xd9:	/* 40Mhz */
	    switch (mode) {
	    case ATA_PIO0:	timing = 0xc018d9d9; break;
	    case ATA_PIO1:	timing = 0xc010d9c7; break;
	    case ATA_PIO2:	timing = 0xc010d997; break;
	    case ATA_PIO3:	timing = 0xc010d974; break;
	    case ATA_PIO4:	timing = 0xc008d963; break;
	    case ATA_WDMA2:	timing = 0xa008d943; break;
	    case ATA_UDMA2:	timing = 0x900bd943; break;
	    case ATA_UDMA4:	timing = 0x900fd943; break;
	    default:		timing = 0x0120d9d9;
	    }
	}
	pci_write_config(parent, 0x40 + (devno << 2), (timing & ~0x80000000),4);
    }
}

#else /* NPCI > 0 */

void
ata_dmainit(struct ata_softc *scp, int32_t device,
	    int32_t piomode, int32_t wdmamode, int32_t udmamode)
{
}

int32_t
ata_dmasetup(struct ata_softc *scp, int32_t device,
	     int8_t *data, int32_t count, int32_t flags)
{
    return -1;
}

void 
ata_dmastart(struct ata_softc *scp)
{
}

int32_t
ata_dmadone(struct ata_softc *scp)
{
    return -1;
}

int32_t
ata_dmastatus(struct ata_softc *scp)
{
    return -1;
}

#endif /* NPCI > 0 */
