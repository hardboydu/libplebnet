/*
 * Copyright (c) KATO Takenori, 1996, 1997.
 *
 * All rights reserved.  Unpublished rights reserved under the copyright
 * laws of Japan.
 *
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified.
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
 */

#include "opt_pc98.h"

#include <sys/param.h>
#include <sys/systm.h>

#include <scsi/scsiconf.h>

#include <pc98/pc98/pc98.h>
#include <pc98/pc98/pc98_machdep.h>

extern	int Maxmem;
extern	int Maxmem_under16M;

#ifdef notyet
static	void init_cpu_accel_mem __P((void));
#endif

/*
 * Initialize DMA controller
 */
void
pc98_init_dmac(void)
{
	outb(0x439, (inb(0x439) & 0xfb));	/* DMA Accsess Control over 1MB */
	outb(0x29, (0x0c | 0));				/* Bank Mode Reg. 16M mode */
	outb(0x29, (0x0c | 1));				/* Bank Mode Reg. 16M mode */
	outb(0x29, (0x0c | 2));				/* Bank Mode Reg. 16M mode */
	outb(0x29, (0x0c | 3));				/* Bank Mode Reg. 16M mode */
	outb(0x11, 0x50);
}

#ifdef EPSON_MEMWIN
static	void init_epson_memwin __P((void));

/*
 * Disconnect phisical memory in 15-16MB region.
 *
 * EPSON PC-486GR, P, SR, SE, HX, HG and HA only.  Other system support
 * this feature with software DIP switch.
 */
static void
init_epson_memwin(void)
{

	if (pc98_machine_type & M_EPSON_PC98) {
		if (Maxmem > 3840) {
			if (Maxmem == Maxmem_under16M) {
				Maxmem = 3840;
				Maxmem_under16M = 3840;
			} else if (Maxmem_under16M > 3840) {
				Maxmem_under16M = 3840;
			}
		}

		/* Disable 15MB-16MB caching. */
		switch (epson_machine_id) {
		case 0x34:	/* PC486HX */
		case 0x35:	/* PC486HG */
		case 0x3B:	/* PC486HA */
			/* Cache control start. */
			outb(0x43f, 0x42);
			outw(0xc40, 0x0033);

			/* Disable 0xF00000-0xFFFFFF. */
			outb(0xc48, 0x49);
			outb(0xc4c, 0x00);
			outb(0xc48, 0x48);
			outb(0xc4c, 0xf0);
			outb(0xc48, 0x4d);
			outb(0xc4c, 0x00);
			outb(0xc48, 0x4c);
			outb(0xc4c, 0xff);
			outb(0xc48, 0x4f);
			outb(0xc4c, 0x00);

			/* Cache control end. */
			outb(0x43f, 0x40);
			break;

		case 0x2B:	/* PC486GR/GF */
		case 0x30:	/* PC486P */
		case 0x31:	/* PC486GRSuper */
		case 0x32:	/* PC486GR+ */
		case 0x37:	/* PC486SE */
		case 0x38:	/* PC486SR */
			/* Disable 0xF00000-0xFFFFFF. */
			outb(0x43f, 0x42);
			outb(0x467, 0xe0);
			outb(0x567, 0xd8);

			outb(0x43f, 0x40);
			outb(0x467, 0xe0);
			outb(0x567, 0xe0);
			break;
		}

		/* Disable 15MB-16MB RAM and enable memory window. */
		outb(0x43b, inb(0x43b) & 0xfd);	/* Clear bit1. */
	}
}
#endif

#ifdef notyet
static	void init_cpu_accel_mem(void);

static void
init_cpu_accel_mem(void)
{
	u_int target_page;
	/*
	 * Certain 'CPU accelerator' supports over 16MB memory on
	 * the machines whose BIOS doesn't store true size.  
	 * To support this, we don't trust BIOS values if Maxmem < 4096.
	 */
	if (Maxmem < 4096) {
		for (target_page = ptoa(4096);		/* 16MB */
			 target_page < ptoa(32768);		/* 128MB */
			 target_page += 256 * PAGE_SIZE	/* 1MB step */) {
			u_int tmp, page_bad = FALSE, OrigMaxmem = Maxmem;

			*(int *)CMAP1 = PG_V | PG_RW | PG_N | target_page;
			invltlb();

			tmp = *(u_int *)CADDR1;
			/*
			 * Test for alternating 1's and 0's
			 */
			*(volatile u_int *)CADDR1 = 0xaaaaaaaa;
			if (*(volatile u_int *)CADDR1 != 0xaaaaaaaa) {
				page_bad = TRUE;
			}
			/*
			 * Test for alternating 0's and 1's
			 */
			*(volatile u_int *)CADDR1 = 0x55555555;
			if (*(volatile u_int *)CADDR1 != 0x55555555) {
				page_bad = TRUE;
			}
			/*
			 * Test for all 1's
			 */
			*(volatile u_int *)CADDR1 = 0xffffffff;
			if (*(volatile u_int *)CADDR1 != 0xffffffff) {
				page_bad = TRUE;
			}
			/*
			 * Test for all 0's
			 */
			*(volatile u_int *)CADDR1 = 0x0;
			if (*(volatile u_int *)CADDR1 != 0x0) {
				/*
				 * test of page failed
				 */
				page_bad = TRUE;
			}
			/*
			 * Restore original value.
			 */
			*(u_int *)CADDR1 = tmp;
			if (page_bad == TRUE) {
				Maxmem = atop(target_page) + 256;
			} else 
				break;
		}
		*(int *)CMAP1 = 0;
		invltlb();
	}
}
#endif

/*
 * Get physical memory size
 */
void
pc98_getmemsize(void)
{
	unsigned char under16, over16;

	/* available protected memory size under 16MB / 128KB */
	under16 = PC98_SYSTEM_PARAMETER(0x401);
	/* available protected memory size over 16MB / 1MB */
	over16 = PC98_SYSTEM_PARAMETER(0x594);
	/* add conventional memory size (1024KB / 128KB = 8) */
	under16 += 8;

	Maxmem = Maxmem_under16M = under16 * 128 * 1024 / PAGE_SIZE;
	Maxmem += (over16 * 1024 * 1024 / PAGE_SIZE);
#ifdef EPSON_MEMWIN
	init_epson_memwin();
#endif
}

#include "sd.h"

#if NSD > 0
/*
 * XXX copied from sd.c.
 */
struct disk_parms {
	u_char	heads;	/* Number of heads */
	u_int16_t	cyls;	/* Number of cylinders */
	u_char	sectors;	/*dubious *//* Number of sectors/track */
	u_int16_t	secsiz;	/* Number of bytes/sector */
	u_int32_t	disksize;	/* total number sectors */
};

/*
 * Read a geometry information of SCSI HDD from BIOS work area.
 *
 * XXX - Before reading BIOS work area, we should check whether
 * host adapter support it.
 */
int
sd_bios_parms(disk_parms, sc_link)
	struct	disk_parms *disk_parms;
	struct	scsi_link *sc_link;
{
	u_char *tmp;

	tmp = (u_char *)&PC98_SYSTEM_PARAMETER(0x460 + sc_link->target*4);
	if ((PC98_SYSTEM_PARAMETER(0x482) & ((1 << sc_link->target)&0xff)) != 0) {
		disk_parms->sectors = *tmp;
		disk_parms->cyls = ((*(tmp+3)<<8)|*(tmp+2))&0xfff;
		switch (*(tmp + 3) & 0x30) {
		case 0x00:
			disk_parms->secsiz = 256;
			printf("Warning!: not supported.\n");
			break;
		case 0x10:
			disk_parms->secsiz = 512;
			break;
		case 0x20:
			disk_parms->secsiz = 1024;
			break;
		default:
			disk_parms->secsiz = 512;
			printf("Warning!: not supported. But force to 512\n");
			break;
		}
		if (*(tmp+3) & 0x40) {
			disk_parms->cyls += (*(tmp+1)&0xf0)<<8;
			disk_parms->heads = *(tmp+1)&0x0f;
		} else {
			disk_parms->heads = *(tmp+1);
		}
		disk_parms->disksize = disk_parms->sectors * disk_parms->heads *
									disk_parms->cyls;
		return 1;
	}
	return 0;
}
#endif
