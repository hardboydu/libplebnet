/* BT848 1.3-ALPHA  Driver for Brooktree's Bt848 based cards.
   The Brooktree  BT848 Driver driver is based upon Mark Tinguely and
   Jim Lowe's driver for the Matrox Meteor PCI card . The 
   Philips SAA 7116 and SAA 7196 are very different chipsets than
   the BT848. For starters, the BT848 is a one chipset solution and
   it incorporates a RISC engine to control the DMA transfers --
   that is it the actual dma process is control by a program which
   resides in the hosts memory also the register definitions between
   the Philips chipsets and the Bt848 are very different.

   The original copyright notice by Mark and Jim is included mostly
   to honor their fantastic work in the Matrox Meteor driver!

      Enjoy,
      Amancio

 */

/*
 * 1. Redistributions of source code must retain the 
 * Copyright (c) 1997 Amancio Hasty
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
 *    must display the following acknowledgement:
 *	This product includes software developed by Amancio Hasty
 * 4. The name of the author may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */




/*
 * 1. Redistributions of source code must retain the 
 * Copyright (c) 1995 Mark Tinguely and Jim Lowe
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
 *    must display the following acknowledgement:
 *	This product includes software developed by Mark Tinguely and Jim Lowe
 * 4. The name of the author may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*		Change History:
1.0		1/24/97	   First Alpha release

1.1		2/20/97	   Added video ioctl so we can do PCI To PCI
			   data transfers. This is for capturing data
			   directly to a vga frame buffer which has
			   a linear frame buffer. Minor code clean-up.

1.3		2/23/97	   Fixed system lock-up reported by 
			   Randall Hopper <rhh@ct.picker.com>. This
			   problem seems somehow to be exhibited only
			   in his system. I changed the setting of
			   INT_MASK for CAP_CONTINUOUS to be exactly
			   the same as CAP_SINGLE apparently setting
			   bit 23 cleared the system lock up. 
			   version 1.1 of the driver has been reported
			   to work with STB's WinTv, Hauppage's Wincast/Tv
			   and last but not least with the Intel Smart
			   Video Recorder.

1.4		3/9/97	   fsmp@freefall.org
			   Merged code to support tuners on STB and WinCast
			   cards.
			   Modifications to the contrast and chroma ioctls.
			   Textual cleanup.

1.5             3/15/97    fsmp@freefall.org
                	   new bt848 specific versions of hue/bright/
                           contrast/satu/satv.
                           Amancio's patch to fix "screen freeze" problem.

1.6             3/19/97    fsmp@freefall.org
			   new table-driven frequency lookup.
			   removed disable_intr()/enable_intr() calls from i2c.
			   misc. cleanup.

1.7             3/19/97    fsmp@freefall.org
			   added audio support submitted by:
				Michael Petry <petry@netwolf.NetMasters.com>
1.8             3/20/97    fsmp@freefall.org
			   extended audio support.
			   card auto-detection.
			   major cleanup, order of routines, declarations, etc.
*/

#include "bktr.h"

#if NBKTR > 0

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/mman.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif /* DEVFS */
#include <machine/clock.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>


/*
 * This is for start-up convenience only, NOT mandatory.
 * XXX: we need to support additional sets of frequencies.
 *
 * this selects the set of frequencies used by the tuner.
 * in your kernel config file set one of:
options	DEFAULT_CHNLSET=1	# CHNLSET_NABCST
options	DEFAULT_CHNLSET=2	# CHNLSET_CABLEIRC
 *
 * alternately, in this file, you can select one of:
 *
#define DEFAULT_CHNLSET	CHNLSET_NABCST
#define DEFAULT_CHNLSET	CHNLSET_CABLEIRC
 */
#if !defined( DEFAULT_CHNLSET )
#define DEFAULT_CHNLSET	CHNLSET_NABCST
#endif

/*
 * the recognized cards.
 * used as indexes of several tables.
 */
#define	CARD_UNKNOWN		0
#define	CARD_MIRO		1
#define	CARD_HAUPPAUGE		2
#define	CARD_STB		3
#define	CARD_INTEL		4


/*
 * XXX: hack to allow multiple programs to open the device,
 *      ie., a tv client and a remote control
 *      we need to make this a MINOR UNIT type thing someday...
 */
#define MULTIPLE_OPENS

/* XXX Fixme: remove me??? */
#define ORIGINAL_DELAYS_NOT

/* XXX Fixme: anomolies still exist in the i2c code */
#define EXTRA_START
#define FUNNY_HI
#define REALLY_ACK

/* XXX attempt to hold sync on marginal signals, experimental */
#define LOW_SYNC_NOT

/* srart of audio support */
#define AUDIO_SUPPORT


#include "pci.h"
#if NPCI > 0

#include <pci/pcivar.h>
#include <pci/pcireg.h>
#endif

#include <machine/ioctl_meteor.h>
#include <machine/ioctl_bt848.h>	/* extensions to ioctl_meteor.h */
#include <pci/brktree_reg.h>


#define METPRI (PZERO+8)|PCATCH

static void	bktr_intr __P((void *arg));
static		bt_enable_cnt;
static u_long	btl_status_prev;

/* 
 * Allocate enough memory for:
 *	768x576 RGB 16 or YUV (16 storage bits/pixel) = 884736 = 216 pages
 *
 * You may override this using the options "METEOR_ALLOC_PAGES=value" in your
 * kernel configuration file.
 */
#ifndef BROOKTREE_ALLOC_PAGES
#define BROOKTREE_ALLOC_PAGES	217*4
#endif
#define BROOKTREE_ALLOC		(BROOKTREE_ALLOC_PAGES * PAGE_SIZE)

static bktr_reg_t brooktree[NBKTR];
#define BROOKTRE_NUM(mtr)	((bktr - &brooktree[0])/sizeof(bktr_reg_t))

#define BKTRPRI (PZERO+8)|PCATCH

static char*	bktr_probe( pcici_t tag, pcidi_t type );
static void	bktr_attach( pcici_t tag, int unit );

static u_long	bktr_count;

static struct	pci_device bktr_device = {
	"bktr",
	bktr_probe,
	bktr_attach,
	&bktr_count
};

DATA_SET (pcidevice_set, bktr_device);

static	d_open_t	bktr_open;
static	d_close_t	bktr_close;
static	d_read_t	bktr_read;
static	d_write_t	bktr_write;
static	d_ioctl_t	bktr_ioctl;
static	d_mmap_t	bktr_mmap;

#define CDEV_MAJOR 79
static struct cdevsw bktr_cdevsw = 
{
	bktr_open,	bktr_close,	bktr_read,	bktr_write,
	bktr_ioctl,	nostop,		nullreset,	nodevtotty,
	seltrue,	bktr_mmap,	NULL,		"bktr",
	NULL,		-1
};


/*
 * misc. support routines.
 */
struct CARDTYPE {
	char*	name;
	u_char	tuner;
	u_char	dbx;
	u_char	audiomuxs[4];	/* tuner, external, internal/unused, mute */
};
static struct CARDTYPE card_types[];
static int	probe_card( bktr_reg_t *bktr, int verbose );
static vm_offset_t get_bktr_mem( int unit, unsigned size );


/*
 * bt848 RISC programming routines.
 */
static int	dump_bt848( volatile u_char *bt848 );

static void	yuvpack_prog( bktr_reg_t * bktr, char i_flag, int cols,
			      int rows,  int interlace) ;

static void	yuv422_prog( bktr_reg_t * bktr, char i_flag, int cols,
			     int rows, int interlace);
static void	rgb_prog( bktr_reg_t * bktr, char i_flag, int cols,
			  int rows, int pixel_width, int interlace) ;
static void	build_dma_prog( bktr_reg_t * bktr, char i_flag);


/*
 * video & video capture specific routines.
 */
static void	start_capture( bktr_reg_t *bktr, unsigned type );
static void	set_fps( bktr_reg_t *bktr, u_short fps );


/*
 * tuner specific functions.
 */
static int	tv_channel( bktr_reg_t* bktr, int channel );
static int	tv_freq( bktr_reg_t* bktr, int frequency );
static int	tuner_status( bktr_reg_t* bktr );


#if defined( AUDIO_SUPPORT )
/*
 * audio specific functions.
 */
static int	set_audio( bktr_reg_t * bktr, int mode );
static int	set_BTSC( bktr_reg_t * bktr, int control );
#endif /* AUDIO_SUPPORT */


/*
 * the boot time probe routine.
 */
static char*
bktr_probe( pcici_t tag, pcidi_t type )
{
	switch (type) {
	case BROOKTREE_848_ID:
		return("BrookTree 848");
	};

	return ((char *)0);
}


/*
 * interrupt handling routine complete bktr_read() if using interrupts.
 */
static void
bktr_intr( void *arg )
{ 
	bktr_reg_t		*bktr = (bktr_reg_t *) arg;
	volatile u_long		*btl_reg, t_pc;
	volatile u_char		*bt848, *bt_reg, s_status;
	volatile u_short	*bts_reg;
	u_long			bktr_status, *bktr_pc;

#if 0
/* XXX: what is this for??? */
	u_long	next_base  = (u_long)(vtophys(bktr->bigbuf)), stat;
#endif

	bt848 = bktr->base;
	bt_reg = (u_char *) &bt848;
	s_status = *bt_reg;
	*bt_reg = 0;

	if (!(bktr->flags & METEOR_OPEN)) {
		bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
		*bts_reg = 0;
		btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
		*btl_reg = 0;
	}

	btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
	bktr_status = *btl_reg ;
	*btl_reg = *btl_reg;
	*btl_reg = 0;
	if (*btl_reg & (1 << 25))
		*btl_reg |= 1 << 8;
	bktr_pc = (u_long *) &bt848[BKTR_RISC_COUNT];
	t_pc = *bktr_pc;

	/*    printf(" STATUS %x %x %x \n", s_status, bktr_status, t_pc);  */

	if (!((bktr_status  & 0x800) || (bktr_status & 1 << 19 ))) {
		btl_status_prev = bktr_status;
		/* return; */
	}

	/* if risc was disabled re-start process again */
	if (!(bktr_status & (1 << 27)) || ((bktr_status & 0xff000) != 0) ) {

		btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
		*btl_reg = *btl_reg;

		bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
		*bts_reg = 0;

		btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
		*btl_reg = 0;

		btl_reg = (u_long *) &bt848[BKTR_RISC_STRT_ADD] ;
		*btl_reg =  vtophys(bktr->dma_prog);

		bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
		*bts_reg = 1;
		*bts_reg = bktr->capcontrol;

		btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
		*btl_reg =   1 << 23 |	1 << 11 |  2 | 1;
 	        bt848[BKTR_CAP_CTL]  = bktr->bktr_cap_ctl;

		return;
	}

	btl_reg = (u_long *) &bt848[BKTR_CAP_CTL];
	if (!(bktr_status & (1 << 11))) return;

	bktr_pc = (u_long *) &bt848[BKTR_RISC_COUNT];

	/*printf("intr status %x %x %x\n", bktr_status, s_status, *bktr_pc);*/

	/*
	 * Disable future interrupts if a capture mode is not selected.
	 * This can happen when we are in the process of closing or 
	 * changing capture modes, otherwise it shouldn't happen.
	 */
	if (!(bktr->flags & METEOR_CAP_MASK))
	    *btl_reg = 0;

	/*
	 * If we have a complete frame.
	 */
	if (!(bktr->flags & METEOR_WANT_MASK)) {
		bktr->frames_captured++;
		/*
		 * post the completion time. 
		 */
		if (bktr->flags & METEOR_WANT_TS) {
			struct timeval *ts;
			
			if ((u_int) bktr->alloc_pages * PAGE_SIZE
			   <= (bktr->frame_size + sizeof(struct timeval))) {
				ts =(struct timeval *)bktr->bigbuf +
				  bktr->frame_size;
				/* doesn't work in synch mode except
				 *  for first frame */
				/* XXX */
				microtime(ts);
			}
		}

		/*
		 * Wake up the user in single capture mode.
		 */
		if (bktr->flags & METEOR_SINGLE) {

			if (!(bktr_status & (1 << 24)))
			    return;

			/* stop dma */
			btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
			*btl_reg = 0;
			bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
			*bts_reg = 1; /* disable risc and fifo */
			wakeup((caddr_t)bktr);
		}

		/*
		 * If the user requested to be notified via signal,
		 * let them know the frame is complete.
		 */
		if (bktr->proc && !(bktr->signal & METEOR_SIG_MODE_MASK))
		    psignal(bktr->proc, bktr->signal&(~METEOR_SIG_MODE_MASK));

		/*
		 * Reset the want flags if in continuous or
		 * synchronous capture mode.
		 */
		if (bktr->flags & (METEOR_CONTIN|METEOR_SYNCAP)) {
			switch(bktr->flags & METEOR_ONLY_FIELDS_MASK) {
			case METEOR_ONLY_ODD_FIELDS:
				bktr->flags |= METEOR_WANT_ODD;
				break;
			case METEOR_ONLY_EVEN_FIELDS:
				bktr->flags |= METEOR_WANT_EVEN;
				break;
			default:
				bktr->flags |= METEOR_WANT_MASK;
				break;
			}
		}
	}

	return;
}


/*
 * what should we do here?
 */
static void
bktr_init ( bktr_reg_t *bktr )
{
	return;
}


/*
 * the attach routine.
 */
static	void
bktr_attach( pcici_t tag, int unit )
{
	bktr_reg_t	*bktr;
	volatile u_char	*bt848;
	volatile u_long	*btl_reg;
#ifdef BROOKTREE_IRQ
	u_long		old_irq, new_irq;
#endif 
	u_char		*test;
	vm_offset_t	buf;
	u_long		latency;
	u_long		fun;

	bt_enable_cnt = 0;
	bktr = &brooktree[unit];

	if (unit >= NBKTR) {
		printf("brooktree%d: attach: only %d units configured.\n",
				unit, NBKTR);
		printf("brooktree%d: attach: invalid unit number.\n", unit);
		return ;
	}

	bktr->tag = tag;
	pci_map_mem(tag, PCI_MAP_REG_START, (vm_offset_t *) &bktr->base,
				&bktr->phys_base);

	fun = pci_conf_read(tag, PCI_COMMAND_STATUS_REG);

#ifdef BROOKTREE_IRQ		/* from the configuration file */
	old_irq = pci_conf_read(tag, PCI_INTERRUPT_REG);
	pci_conf_write(tag, PCI_INTERRUPT_REG, BROOKTREE_IRQ);
	new_irq = pci_conf_read(tag, PCI_INTERRUPT_REG);
	printf("bktr%d: attach: irq changed from %d to %d\n",
		unit, (old_irq & 0xff), (new_irq & 0xff));
#endif 
	/* setup the interrupt handling routine */
	pci_map_int(tag, bktr_intr, (void*) bktr, &net_imask);
	
/*
 * PCI latency timer.  32 is a good value for 4 bus mastering slots, if
 * you have more than for, then 16 would probably be a better value.
 */
#ifndef BROOKTREE_DEF_LATENCY_VALUE
#define BROOKTREE_DEF_LATENCY_VALUE	10
#endif
	latency = pci_conf_read(tag, PCI_LATENCY_TIMER);
	latency = (latency >> 8) & 0xff;
	if ( bootverbose ) {
		if (latency)
			printf("brooktree%d: PCI bus latency is", unit);
		else
			printf("brooktree%d: PCI bus latency was 0 changing to",
				unit);
	}
	if ( !latency ) {
		latency = BROOKTREE_DEF_LATENCY_VALUE;
		pci_conf_write(tag, PCI_LATENCY_TIMER,	latency<<8);
	}
	if ( bootverbose ) {
		printf(" %d.\n", latency);
	}

	/*	bktr_init(bktr);	 set up the bt848 */

	/* allocate space for dma program */
	bktr->dma_prog = get_bktr_mem(unit, 8);
	bktr->odd_dma_prog = get_bktr_mem(unit, 8);
	if ( BROOKTREE_ALLOC )
		buf = get_bktr_mem(unit, BROOKTREE_ALLOC);
	else
		buf = 0;

	if ( bootverbose ) {
		printf("bktr%d: buffer size %d, addr 0x%x\n",
			unit, BROOKTREE_ALLOC, vtophys(buf));
	}

	bktr->bigbuf = buf;
	bktr->alloc_pages = BROOKTREE_ALLOC_PAGES;
	if ( buf != 0 ) {
		bzero((caddr_t) buf, BROOKTREE_ALLOC);
		buf = vtophys(buf);

#ifdef amancio					/* 640x480 RGB 16 */

amancio : setup dma risc program 
		bktr->base->dma1e = buf;
		bktr->base->dma1o = buf + 0x500;
		bktr->base->dma_end_e = 
		bktr->base->dma_end_o = buf + METEOR_ALLOC;
end of setup up dma risc program
	/* 1 frame of 640x480 RGB 16 */
	bktr->flags |= METEOR_INITALIZED | METEOR_AUTOMODE | METEOR_DEV0 |
		   METEOR_RGB16;
#endif /* amancio */

		bktr->flags = METEOR_INITALIZED | METEOR_AUTOMODE |
			      METEOR_DEV0 | METEOR_RGB16;
		bktr->dma_prog_loaded = 0;
		bktr->cols = 640;
		bktr->rows = 480;
		bktr->depth = 2;		/* two bytes per pixel */
		bktr->frames = 1;		/* one frame */
		bt848 = bktr->base;
		btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
		*btl_reg = 0;
		bt848[BKTR_GPIO_DMA_CTL] = 0;
	}

	/* defaults for the tuner section of the card */
	bktr->tuner.frequency = 0;
	bktr->tuner.channel = 0;
	bktr->tuner.chnlset = DEFAULT_CHNLSET;

	probe_card( bktr, 1 );

#ifdef DEVFS
	bktr->devfs_token = devfs_add_devswf(&bktr_cdevsw, unit,
					     DV_CHR, 0, 0, 0644, "brooktree");
#endif /* DEVFS */
}

#define UNIT(x) ((x) & 0x07)


/*---------------------------------------------------------
**
**	BrookTree 848 character device driver routines
**
**---------------------------------------------------------
*/


/*
 * 
 */
int
bktr_open( dev_t dev, int flags, int fmt, struct proc *p )
{
	bktr_reg_t	*bktr;
	int		unit;
	int		i;
	volatile u_char	*bt848;
	volatile u_char	*bt_reg;
	volatile u_long	*btl_reg;

	unit = UNIT(minor(dev));
	if (unit >= NBKTR)			/* unit out of range */
		return(ENXIO);

	bktr = &(brooktree[unit]);

	if (!(bktr->flags & METEOR_INITALIZED)) /* device not found */
		return(ENXIO);	

#if defined( MULTIPLE_OPENS )
	if (bktr->flags & METEOR_OPEN)		/* device already open */
		return 0;
#else
	if (bktr->flags & METEOR_OPEN)		/* device is busy */
		return(EBUSY);
#endif /* MULTIPLE_OPENS */

	bktr->flags |= METEOR_OPEN;
	
	bt848 = bktr->base;

#if 0
	dump_bt848( bt848 );
#endif /* 0 */

	*bt848 = 0x3;				/* bt848[ 0 ] */
	*bt848 = 0xc0;

#if defined( LOW_SYNC )
	bt848[BKTR_ADC] = 0xa1;
#else
	bt848[BKTR_ADC] = 0x81;
#endif /* LOW_SYNC */

	bt848[BKTR_IFORM] = 0x69;
	bktr->flags = (bktr->flags & ~METEOR_DEV_MASK) | METEOR_DEV0;

	bt848[BKTR_COLOR_CTL] = 0x20;

	bt848[BKTR_E_HSCALE_LO] = 0xaa;
	bt848[BKTR_O_HSCALE_LO] = 0xaa;

	bt848[BKTR_E_DELAY_LO] = 0x72;
	bt848[BKTR_O_DELAY_LO] = 0x72;
	bt848[BKTR_E_SCLOOP] = 0;
	bt848[BKTR_O_SCLOOP] = 0;

	bt848[BKTR_VBI_PACK_SIZE] = 0;
	bt848[BKTR_VBI_PACK_DEL] = 0;

	bzero((u_char *) bktr->bigbuf, 640*480*4);
	bktr->fifo_errors = 0;
	bktr->dma_errors = 0;
	bktr->frames_captured = 0;
	bktr->even_fields_captured = 0;
	bktr->odd_fields_captured = 0;
	bktr->proc = (struct proc *)0;
	set_fps(bktr, 30);
	bktr->video.addr = 0;
	bktr->video.width = 0;
	bktr->video.banksize = 0;
	bktr->video.ramsize = 0;

	btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
	*btl_reg = 1 << 23;

#if defined( AUDIO_SUPPORT )
	set_audio( bktr, AUDIO_UNMUTE );
	if ( card_types[ bktr->card_type ].dbx )
		set_BTSC( bktr, 0 );		/* enable the stereo chip */
#endif /* AUDIO_SUPPORT */

	return(0);
}


/*
 * 
 */
int
bktr_close( dev_t dev, int flags, int fmt, struct proc *p )
{
	bktr_reg_t	*bktr;
	int		unit;
	volatile u_char *bt848;
	volatile u_long *btl_reg;
	u_short		*bts_reg;
#ifdef METEOR_DEALLOC_ABOVE
	int		temp;
#endif

	unit = UNIT(minor(dev));
	if (unit >= NBKTR)			/* unit out of range */
		return(ENXIO);

	bktr = &(brooktree[unit]);

	bktr->flags &= ~METEOR_OPEN;
	bktr->flags &= ~(METEOR_SINGLE | METEOR_WANT_MASK);
	bktr->flags &= ~(METEOR_CAP_MASK|METEOR_WANT_MASK);
	bt848 = bktr->base;
	bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
	*bts_reg = 0;
	bt848[BKTR_CAP_CTL] = 0;

	bktr->dma_prog_loaded = 0;
	bt848[BKTR_TDEC] = 0;
	btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
	*btl_reg = 0;

	bt848[BKTR_SRESET] = 0xf;
	btl_reg = (u_long *) &bt848[BKTR_INT_STAT] ;
	*btl_reg = 0xffffffff;

#if defined( AUDIO_SUPPORT )
	/* mute the audio by switching the mux */
	set_audio( bktr, AUDIO_MUTE );
#endif /* AUDIO_SUPPORT */

	return(0);
}


/*
 * 
 */
int
bktr_read( dev_t dev, struct uio *uio, int ioflag )
{
	bktr_reg_t	*bktr;
	int		unit;
	int		status;
	int		count;
	volatile u_char *bt848;
	u_short		*bts_reg;

	unit = UNIT(minor(dev));
	if (unit >= NBKTR)	/* unit out of range */
		return(ENXIO);

	bktr = &(brooktree[unit]);
	if (bktr->bigbuf == 0)	/* no frame buffer allocated (ioctl failed) */
		return(ENOMEM);

	if (bktr->flags & METEOR_CAP_MASK)
		return(EIO);	/* already capturing */

	bt848 = (u_char *) bktr->base;


	count = bktr->rows * bktr->cols * bktr->depth;
	if ((int) uio->uio_iov->iov_len < count)
		return(EINVAL);
	bktr->flags &= ~(METEOR_CAP_MASK|METEOR_WANT_MASK);

	/* Start capture */
	bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
	*bts_reg = 0x1;
	*bts_reg = 0x3;

	status=tsleep((caddr_t)bktr, METPRI, "capturing", 0);
	if (!status)		/* successful capture */
		status = uiomove((caddr_t)bktr->bigbuf, count, uio);
	else
		printf ("meteor%d: read: tsleep error %d\n", unit, status);

	bktr->flags &= ~(METEOR_SINGLE | METEOR_WANT_MASK);

	return(status);
}


/*
 * 
 */
int
bktr_write( dev_t dev, struct uio *uio, int ioflag )
{
	return(0);
}


/*
 * 
 */
int
bktr_ioctl( dev_t dev, int cmd, caddr_t arg, int flag, struct proc *pr )
{
	bktr_reg_t		*bktr;
	int			unit;
	int			status;
	int			count;
	int			tmp_int;
	volatile u_char		*bt848, c_temp;
	volatile u_short	*bts_reg, s_temp;
	volatile u_long		*btl_reg;
	unsigned int		temp, temp1;
	unsigned int		error;
	struct meteor_geomet	*geo;
	struct meteor_counts	*cnt;
	struct meteor_video	*video;
	vm_offset_t		buf;

	unit = UNIT(minor(dev));
	if (unit >= NBKTR)	/* unit out of range */
		return(ENXIO);


	bktr = &(brooktree[unit]);
	if (bktr->bigbuf == 0)	/* no frame buffer allocated (ioctl failed) */
		return(ENOMEM);

	bt848 =	 bktr->base;
	switch (cmd) {

	case TVTUNER_SETCHNL:
#if defined( AUDIO_SUPPORT )
		set_audio( bktr, AUDIO_MUTE );
#endif /* AUDIO_SUPPORT */
		temp = tv_channel( bktr, (int)*(unsigned long *)arg );
#if defined( AUDIO_SUPPORT )
		set_audio( bktr, AUDIO_UNMUTE );
#endif /* AUDIO_SUPPORT */
		if ( temp < 0 )
			return EINVAL;
		*(unsigned long *)arg = temp;
		break;

	case TVTUNER_GETCHNL:
		*(unsigned long *)arg = bktr->tuner.channel;
		break;

	case TVTUNER_SETTYPE:
		temp = *(unsigned long *)arg;
		if ( (temp < CHNLSET_MIN) || (temp > CHNLSET_MAX) )
			return EINVAL;
		bktr->tuner.chnlset = temp;
		break;

	case TVTUNER_GETTYPE:
		*(unsigned long *)arg = bktr->tuner.chnlset;
		break;

	case TVTUNER_GETSTATUS:
		temp = tuner_status( bktr );
		*(unsigned long *)arg = temp & 0xff;
		break;

	case TVTUNER_SETFREQ:
#if defined( AUDIO_SUPPORT_XXX )
		set_audio( bktr, AUDIO_MUTE );
#endif /* AUDIO_SUPPORT */
		temp = tv_freq( bktr, (int)*(unsigned long *)arg );
#if defined( AUDIO_SUPPORT_XXX )
		set_audio( bktr, AUDIO_UNMUTE );
#endif /* AUDIO_SUPPORT */
		if ( temp < 0 )
			return EINVAL;
		*(unsigned long *)arg = temp;
		break;

	case TVTUNER_GETFREQ:
		*(unsigned long *)arg = bktr->tuner.frequency;
		break;

	case METEORSTATUS:	/* get 7196 status */
		c_temp = bt848[0];
		temp = 0;
		if (!(c_temp & 0x40)) temp |= METEOR_STATUS_HCLK;
		if (!(c_temp & 0x10)) temp |= METEOR_STATUS_FIDT;
		*(u_short *)arg = temp;
		break;

	case METEORSINPUT:	/* set input device */
		switch(*(unsigned long *)arg & METEOR_DEV_MASK) {

		/* this is the RCA video input */
		case 0:		/* default */
		case METEOR_INPUT_DEV0:
			bktr->flags = (bktr->flags & ~METEOR_DEV_MASK)
				| METEOR_DEV0;
			bt848[BKTR_IFORM] &= ~0x60;
			bt848[BKTR_IFORM] |= 0x60;
			bt848[BKTR_E_CONTROL] &= ~0x40;
			bt848[BKTR_O_CONTROL] &= ~0x40;
#if defined( AUDIO_SUPPORT )
			set_audio( bktr, AUDIO_MUTE );
			set_audio( bktr, AUDIO_EXTERN );
			set_audio( bktr, AUDIO_UNMUTE );
#endif /* AUDIO_SUPPORT */
			break;

		/* this is the tuner input */
		case METEOR_INPUT_DEV1:
			bktr->flags = (bktr->flags & ~METEOR_DEV_MASK)
				| METEOR_DEV1;
			bt848[BKTR_IFORM] &= ~0x60;
			bt848[BKTR_IFORM] |= 0x40;
			bt848[BKTR_E_CONTROL] &= ~0x40;
			bt848[BKTR_O_CONTROL] &= ~0x40;
#if defined( AUDIO_SUPPORT )
			set_audio( bktr, AUDIO_MUTE );
			set_audio( bktr, AUDIO_TUNER );
			set_audio( bktr, AUDIO_UNMUTE );
#endif /* AUDIO_SUPPORT */
			break;

		/* this is the S-VHS input */
		case METEOR_INPUT_DEV2:
		case METEOR_INPUT_DEV_SVIDEO:
			bktr->flags = (bktr->flags & ~METEOR_DEV_MASK)
				| METEOR_DEV2;
			bt848[BKTR_IFORM] &= ~0x60;
			bt848[BKTR_IFORM] |= 0x20;
			bt848[BKTR_E_CONTROL] |= 0x40;
			bt848[BKTR_O_CONTROL] |= 0x40;
#if defined( AUDIO_SUPPORT )
			set_audio( bktr, AUDIO_MUTE );
			set_audio( bktr, AUDIO_EXTERN );
			set_audio( bktr, AUDIO_UNMUTE );
#endif /* AUDIO_SUPPORT */
			break;

		default:
			return EINVAL;
		}
		break;

	case METEORGINPUT:	/* get input device */
		*(u_long *)arg = bktr->flags & METEOR_DEV_MASK;
		break;

	case METEORSFMT:	/* set input format */
		switch(*(unsigned long *)arg & METEOR_FORM_MASK ) {
		case 0:		/* default */
		case METEOR_FMT_NTSC:
			bktr->flags = (bktr->flags & ~METEOR_FORM_MASK) |
				METEOR_NTSC;
			bt848[BKTR_IFORM] &= ~0x3;
			bt848[BKTR_IFORM] |= 1;
			break;

		case METEOR_FMT_AUTOMODE:
			bktr->flags = (bktr->flags & ~METEOR_FORM_MASK) |
				METEOR_AUTOMODE;
			bt848[BKTR_IFORM] &= ~0x3;
			break;

		default:
			return EINVAL;
		}
		break;

	case METEORGFMT:	/* get input format */
		*(u_long *)arg = bktr->flags & METEOR_FORM_MASK;
		break;

	case METEORSCOUNT:	/* (re)set error counts */
		cnt = (struct meteor_counts *) arg;
		bktr->fifo_errors = cnt->fifo_errors;
		bktr->dma_errors = cnt->dma_errors;
		bktr->frames_captured = cnt->frames_captured;
		bktr->even_fields_captured = cnt->even_fields_captured;
		bktr->odd_fields_captured = cnt->odd_fields_captured;
		break;

	case METEORGCOUNT:	/* get error counts */
		cnt = (struct meteor_counts *) arg;
		cnt->fifo_errors = bktr->fifo_errors;
		cnt->dma_errors = bktr->dma_errors;
		cnt->frames_captured = bktr->frames_captured;
		cnt->even_fields_captured = bktr->even_fields_captured;
		cnt->odd_fields_captured = bktr->odd_fields_captured;
		break;

	case METEORGVIDEO:
		video = (struct meteor_video *)arg;
		video->addr = bktr->video.addr;
		video->width = bktr->video.width;
		video->banksize = bktr->video.banksize;
		video->ramsize = bktr->video.ramsize;
		break;

	case METEORSVIDEO:
		video = (struct meteor_video *)arg;
		bktr->video.addr = video->addr;
		bktr->video.width = video->width;
		bktr->video.banksize = video->banksize;
		bktr->video.ramsize = video->ramsize;
		break;

	case METEORSFPS:
		set_fps(bktr, *(u_short *)arg);
		break;

	case METEORGFPS:
		*(u_short *)arg = bktr->fps;
		break;

	case METEORSHUE:	/* set hue */
		bt848[BKTR_HUE] = (*(u_char *) arg) & 0xff;
		break;

	case METEORGHUE:	/* get hue */
		*(u_char *)arg = bt848[BKTR_HUE];
		break;

	case METEORSBRIG:	/* set brightness */
		bt848[BKTR_BRIGHT] =  *(u_char *)arg & 0xff;
		break;

	case METEORGBRIG:	/* get brightness */
		*(u_char *)arg = bt848[BKTR_BRIGHT];
		break;

	case METEORSCSAT:	/* set chroma saturation */
		temp = (int)*(u_char *)arg;

		bt848[BKTR_SAT_U_LO] = bt848[BKTR_SAT_V_LO] =
			(temp << 1) & 0xff;

		bt848[BKTR_E_CONTROL] &= ~0x3;	/* clear U/V MSBs */
		bt848[BKTR_O_CONTROL] &= ~0x3;	/* clear U/V MSBs */

		if ( temp & 0x80 ) {
			bt848[BKTR_E_CONTROL] |= 0x3;
			bt848[BKTR_O_CONTROL] |= 0x3;
		}
		break;

	case METEORGCSAT:	/* get chroma saturation */
		temp = (bt848[BKTR_SAT_V_LO] >> 1) & 0xff;
		if ( bt848[BKTR_E_CONTROL] & 0x01 )
			temp |= 0x80;
		*(u_char *)arg = (u_char)temp;
		break;

	case METEORSCONT:	/* set contrast */
		temp = (int)*(u_char *)arg & 0xff;
		temp <<= 1;
		bt848[BKTR_CONTRAST_LO] =  temp & 0xff;
		bt848[BKTR_E_CONTROL] &= ~0x4;
		bt848[BKTR_O_CONTROL] &= ~0x4;
		bt848[BKTR_E_CONTROL] |= ((temp & 0x100) >> 6 ) & 0x4 ;
		bt848[BKTR_O_CONTROL] |= ((temp & 0x100) >> 6 ) & 0x4 ;
		break;

	case METEORGCONT:	/* get contrast */
		temp = (int)bt848[BKTR_CONTRAST_LO] & 0xff;
		temp |= ((int)bt848[BKTR_O_CONTROL] & 0x04) << 6;
		*(u_char *)arg = (u_char)((temp >> 1) & 0xff);
		break;

	/* hue is a 2's compliment number, -90' to +89.3' in 0.7' steps */
	case BT848_SHUE:	/* set hue */
		bt848[BKTR_HUE] = (u_char)(*(int*)arg & 0xff);
		break;

	case BT848_GHUE:	/* get hue */
		*(int*)arg = bt848[BKTR_HUE] & 0xff;
		break;

	/* brightness is a 2's compliment #, -50 to +%49.6% in 0.39% steps */
	case BT848_SBRIG:	/* set brightness */
		bt848[BKTR_BRIGHT] = (u_char)(*(int *)arg & 0xff);
		break;

	case BT848_GBRIG:	/* get brightness */
		*(int *)arg = bt848[BKTR_BRIGHT] & 0xff;
		break;

	/*  */
	case BT848_SCSAT:	/* set chroma saturation */
		tmp_int = *(int*)arg;

		temp = bt848[BKTR_E_CONTROL] & 0xfc;
		temp1 = bt848[BKTR_O_CONTROL] & 0xfc;
		if ( tmp_int & 0x100 ) {
			temp |= 0x03;
			temp1 |= 0x03;
		}

		bt848[BKTR_SAT_U_LO] = (u_char)(tmp_int & 0xff);
		bt848[BKTR_SAT_V_LO] = (u_char)(tmp_int & 0xff);
		bt848[BKTR_E_CONTROL] = temp;
		bt848[BKTR_O_CONTROL] = temp1;
		break;

	case BT848_GCSAT:	/* get chroma saturation */
		tmp_int = (int)bt848[BKTR_SAT_V_LO] & 0xff;
		if ( bt848[BKTR_E_CONTROL] & 0x01 )
			tmp_int |= 0x0100;
		*(int*)arg = tmp_int;
		break;

	/*  */
	case BT848_SVSAT:	/* set chroma V saturation */
		tmp_int = *(int*)arg;

		temp = bt848[BKTR_E_CONTROL] & 0xfe;
		temp1 = bt848[BKTR_O_CONTROL] & 0xfe;
		if ( tmp_int & 0x100 ) {
			temp |= 0x01;
			temp1 |= 0x01;
		}

		bt848[BKTR_SAT_V_LO] = (u_char)(tmp_int & 0xff);
		bt848[BKTR_E_CONTROL] = temp;
		bt848[BKTR_O_CONTROL] = temp1;
		break;

	case BT848_GVSAT:	/* get chroma V saturation */
		tmp_int = (int)bt848[BKTR_SAT_V_LO] & 0xff;
		if ( bt848[BKTR_E_CONTROL] & 0x01 )
			tmp_int |= 0x0100;
		*(int*)arg = tmp_int;
		break;

	/*  */
	case BT848_SUSAT:	/* set chroma U saturation */
		tmp_int = *(int*)arg;

		temp = bt848[BKTR_E_CONTROL] & 0xfd;
		temp1 = bt848[BKTR_O_CONTROL] & 0xfd;
		if ( tmp_int & 0x100 ) {
			temp |= 0x02;
			temp1 |= 0x02;
		}

		bt848[BKTR_SAT_U_LO] = (u_char)(tmp_int & 0xff);
		bt848[BKTR_E_CONTROL] = temp;
		bt848[BKTR_O_CONTROL] = temp1;
		break;

	case BT848_GUSAT:	/* get chroma U saturation */
		tmp_int = (int)bt848[BKTR_SAT_U_LO] & 0xff;
		if ( bt848[BKTR_E_CONTROL] & 0x02 )
			tmp_int |= 0x0100;
		*(int*)arg = tmp_int;
		break;

	/*  */
	case BT848_SCONT:	/* set contrast */
		tmp_int = *(int*)arg;

		temp = bt848[BKTR_E_CONTROL] & 0xfb;
		temp1 = bt848[BKTR_O_CONTROL] & 0xfb;
		if ( tmp_int & 0x100 ) {
			temp |= 0x04;
			temp1 |= 0x04;
		}

		bt848[BKTR_CONTRAST_LO] = (u_char)(tmp_int & 0xff);
		bt848[BKTR_E_CONTROL] = temp;
		bt848[BKTR_O_CONTROL] = temp1;
		break;

	case BT848_GCONT:	/* get contrast */
		tmp_int = (int)bt848[BKTR_CONTRAST_LO] & 0xff;
		if ( bt848[BKTR_E_CONTROL] & 0x04 )
			tmp_int |= 0x0100;
		*(int*)arg = tmp_int;
		break;

	case BT848_SCBARS:	/* set colorbar output */
		bt848[BKTR_COLOR_CTL] |= 0x40;
		break;

	case BT848_CCBARS:	/* clear colorbar output */
		bt848[BKTR_COLOR_CTL] &= ~0x40;
		break;

#if defined( AUDIO_SUPPORT )
	case BT848_SAUDIO:	/* set audio channel */
		if ( set_audio( bktr, *(int*)arg ) < 0 )
			return EIO;
		break;

	case BT848_GAUDIO:	/* get audio channel */
		temp = bktr->audio_mux_select;
		if ( bktr->audio_mute_state == TRUE )
			temp |= AUDIO_MUTE;
		*(int*)arg = temp;
		break;

	case BT848_SBTSC:	/* set audio channel */
		if ( set_BTSC( bktr, *(int*)arg ) < 0 )
			return EIO;
		break;
#endif /* AUDIO_SUPPORT */

	case METEORSSIGNAL:
		bktr->signal = *(int *) arg;
		bktr->proc = pr;
		break;

	case METEORGSIGNAL:
		*(int *)arg = bktr->signal;
		break;

	case METEORCAPTUR:
		temp = bktr->flags;
		switch (*(int *) arg) {
		case METEOR_CAP_SINGLE:

			if (bktr->bigbuf==0)	/* no frame buffer allocated */
				return(ENOMEM);

			/*			if (temp & METEOR_CAP_MASK)
				return(EIO);		 already capturing */

			start_capture(bktr, METEOR_SINGLE);
			bktr->flags |= METEOR_SINGLE;
			bktr->flags &= ~METEOR_WANT_MASK;

			/* wait for capture to complete */
			btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
			*btl_reg = 0xffffffff;

			btl_reg = (u_long *) &bt848[BKTR_GPIO_OUT_EN];
			*btl_reg = 1;
			bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
			*bts_reg = 0x1;
			*bts_reg = bktr->capcontrol;

			btl_reg = (u_long *) &bt848[BKTR_INT_MASK];

			*btl_reg =    1 << 23 |	 1 << 11 |  2 | 1;

			error=tsleep((caddr_t)bktr, METPRI, "capturing",  hz);

			if (error) {
			    btl_reg = (u_long *) &bt848[BKTR_RISC_COUNT];

				printf("bktr%d: ioctl: tsleep error %d %x\n",
					unit, error, *btl_reg);
			}
			bktr->flags &= ~(METEOR_SINGLE|METEOR_WANT_MASK);
			btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
			break;

		case METEOR_CAP_CONTINOUS:
			if (bktr->bigbuf==0)	/* no frame buffer allocated */
				return(ENOMEM);

			if (temp & METEOR_CAP_MASK)
				return(EIO);		/* already capturing */

			start_capture(bktr, METEOR_CONTIN);
			btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
			*btl_reg = *btl_reg;

			bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];

			*bts_reg = 1;
			*bts_reg = bktr->capcontrol;

			btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
			*btl_reg =    1 << 23 |	 1 << 11 |  2 | 1;

#if 0
			dump_bt848( bt848 );
#endif /* 0 */

			break;
		
		case METEOR_CAP_STOP_CONT:
			if (bktr->flags & METEOR_CONTIN) {
				/* turn off capture */
				btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
				*btl_reg = 0;
				bts_reg = (u_short *)&bt848[BKTR_GPIO_DMA_CTL];
				*bts_reg = 0;

				bktr->flags &= ~(METEOR_CONTIN|METEOR_WANT_MASK);
			}
		}
		break;

	case METEORSETGEO:

		geo = (struct meteor_geomet *) arg;

		error = 0;
		/* Either even or odd, if even & odd, then these a zero */
		if ((geo->oformat & METEOR_GEO_ODD_ONLY) &&
			(geo->oformat & METEOR_GEO_EVEN_ONLY)) {
			printf("bktr%d: ioctl: Geometry odd or even only.\n",
				unit);

			return EINVAL;
		}

		/* set/clear even/odd flags */
		if (geo->oformat & METEOR_GEO_ODD_ONLY)
			bktr->flags |= METEOR_ONLY_ODD_FIELDS;
		else
			bktr->flags &= ~METEOR_ONLY_ODD_FIELDS;
		if (geo->oformat & METEOR_GEO_EVEN_ONLY)
			bktr->flags |= METEOR_ONLY_EVEN_FIELDS;
		else
			bktr->flags &= ~METEOR_ONLY_EVEN_FIELDS;

		/* can't change parameters while capturing */
/* XXX:
		if (bktr->flags & METEOR_CAP_MASK)
			return(EBUSY);
*/
		if ((geo->columns & 0x3fe) != geo->columns) {
			printf(
			"bktr%d: ioctl: %d: columns too large or not even.\n",
				unit, geo->columns);
			error = EINVAL;
		}
		if (((geo->rows & 0x7fe) != geo->rows) ||
			((geo->oformat & METEOR_GEO_FIELD_MASK) &&
				((geo->rows & 0x3fe) != geo->rows)) ) {
			printf(
			"bktr%d: ioctl: %d: rows too large or not even.\n",
				unit, geo->rows);
			error = EINVAL;
		}
		if (geo->frames > 32) {
			printf("bktr%d: ioctl: too many frames.\n", unit);

			error = EINVAL;
		}

		if (error) return error;
		bktr->dma_prog_loaded = 0;
		bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
		*bts_reg = 0;

		btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
		*btl_reg = 0;

		if (temp=geo->rows * geo->columns * geo->frames * 2) {
			if (geo->oformat & METEOR_GEO_RGB24) temp = temp * 2;

			/* meteor_mem structure for SYNC Capture */
			if (geo->frames > 1) temp += PAGE_SIZE;

			temp = btoc(temp);
			if ((int) temp > bktr->alloc_pages
			    && bktr->video.addr == 0) {
				buf = get_bktr_mem(unit, temp*PAGE_SIZE);
				if (buf != 0) {
					kmem_free(kernel_map, bktr->bigbuf,
					  (bktr->alloc_pages * PAGE_SIZE));
					bktr->bigbuf = buf;
					bktr->alloc_pages = temp;
					if (bootverbose)
						printf(
				"meteor%d: ioctl: Allocating %d bytes\n",
							unit, temp*PAGE_SIZE);
				} else {
					error = ENOMEM;
				}
			}
		}

		if (error)
			return error;

		bktr->rows = geo->rows;
		bktr->cols = geo->columns;
		bktr->frames = geo->frames;

		/* horizontal scale */
		/* temp = ((910.0/( (float) bktr->cols *1.21875)) - 1.0) * 4096.0;*/
		/* temp = ((910.0/( (float) bktr->cols *1.212)) - 1.0) * 4096.0; */
		temp = ((910.0/( (float) bktr->cols *1.21875)) - 1.0) * 4096.0;
		/* temp = ((754.0/(float) bktr->cols) - 1 ) * 4096.0;*/

		bt848[BKTR_E_HSCALE_LO] = temp & 0xff;
		bt848[BKTR_O_HSCALE_LO] = temp & 0xff;
		bt848[BKTR_E_HSCALE_HI] = ( temp >> 8 ) & 0xff;
		bt848[BKTR_O_HSCALE_HI] = ( temp >> 8 ) & 0xff;

		/* horizontal active */
		temp = bktr->cols;
		bt848[BKTR_E_HACTIVE_LO] = temp & 0xff;
		bt848[BKTR_O_HACTIVE_LO] = temp & 0xff;
		bt848[BKTR_EVEN_CROP] &= ~0x3;
		bt848[BKTR_ODD_CROP]  &= ~0x3;
		bt848[BKTR_EVEN_CROP] |= (temp >> 8 ) & 0x3;
		bt848[BKTR_ODD_CROP]  |= (temp >> 8 ) & 0x3;

		/* horizontal delay */
		temp = ((135.0/754.0) * (float) bktr->cols) ;
		temp = temp + 2;
		temp = temp &  0x3fe;
		bt848[BKTR_E_DELAY_LO] = temp & 0xff;
		bt848[BKTR_O_DELAY_LO] = temp & 0xff;
		bt848[BKTR_EVEN_CROP] &= ~0xc;
		bt848[BKTR_ODD_CROP] &= ~0xc;
		bt848[BKTR_EVEN_CROP] |= (temp >> 6) & 0xc;
		bt848[BKTR_ODD_CROP] |= (temp >> 6) & 0xc;

		/* vscale */
		if (geo->oformat & METEOR_GEO_ODD_ONLY ||
		   geo->oformat & METEOR_GEO_EVEN_ONLY) {
		  tmp_int = 65536.0 - (((240.0/(float) bktr->rows) - 1.0) * 512.0);
		} else {
		  tmp_int = 65536 - (((480.0/(float) bktr->rows) - 1.0) * 512);
		}
		tmp_int &= 0x1fff;

		/* Vertical scaling */
		bt848[BKTR_E_VSCALE_LO] = tmp_int & 0xff;
		bt848[BKTR_O_VSCALE_LO] = tmp_int & 0xff;
		bt848[BKTR_E_VSCALE_HI] &= ~0x1f;
		bt848[BKTR_O_VSCALE_HI] &= ~0x1f;
		bt848[BKTR_E_VSCALE_HI] |= (tmp_int >> 8) & 0x1f;
		bt848[BKTR_O_VSCALE_HI] |= (tmp_int >> 8) & 0x1f;

		bktr->format = METEOR_GEO_YUV_422;
		switch (geo->oformat & METEOR_GEO_OUTPUT_MASK) {
		case 0:			/* default */
		case METEOR_GEO_RGB16:
			bktr->format = METEOR_GEO_RGB16;
			bktr->depth = 2;
			break;
		case METEOR_GEO_RGB24:
			bktr->format = METEOR_GEO_RGB24;
			bktr->depth = 4;
			break;
		case METEOR_GEO_YUV_422:
			bktr->format = METEOR_GEO_YUV_422;
			break;
		case METEOR_GEO_YUV_PACKED:
			bktr->format = METEOR_GEO_YUV_PACKED;
			break;
		}

/*
		if (geo->oformat & METEOR_GEO_YUV_12 )
			bktr->format |= METEOR_GEO_YUV_12;
		else if (geo->oformat & METEOR_GEO_YUV_9 )
			bktr->format |= METEOR_GEO_YUV_9;
*/

		if (bktr->flags & METEOR_CAP_MASK) {

			if (bktr->flags & (METEOR_CONTIN|METEOR_SYNCAP)) {
				switch(bktr->flags & METEOR_ONLY_FIELDS_MASK) {
				case METEOR_ONLY_ODD_FIELDS:
					bktr->flags |= METEOR_WANT_ODD;
					break;
				case METEOR_ONLY_EVEN_FIELDS:
					bktr->flags |= METEOR_WANT_EVEN;
					break;
				default:
					bktr->flags |= METEOR_WANT_MASK;
					break;
				}

				start_capture(bktr, METEOR_CONTIN);
				btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
				*btl_reg = *btl_reg;
				bts_reg = (u_short *)&bt848[BKTR_GPIO_DMA_CTL];
				*bts_reg = 0x1;
				*bts_reg = bktr->capcontrol;
				btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
				*btl_reg =    1 << 23 |	  2 | 1;
			}
		}
		break;
	/* end of METEORSETGEO */

	default:
		return ENODEV;
	}

	return 0;
}


/*
 * 
 */
int
bktr_mmap( dev_t dev, int offset, int nprot )
{
	int		unit;
	bktr_reg_t	*bktr;

	unit = UNIT(minor(dev));

	if (unit >= NBKTR)		/* at this point could this happen? */
		return(-1);

	bktr = &(brooktree[unit]);

	if (nprot & PROT_EXEC)
		return -1;

	if (offset >= bktr->alloc_pages * PAGE_SIZE)
		return -1;

	return i386_btop(vtophys(bktr->bigbuf) + offset);
}


/******************************************************************************
 * bt848 RISC programming routines:
 */


/*
 * 
 */
static int
dump_bt848( volatile u_char *bt848 )
{
	u_long	*bt_long;
	u_short *bt_short;
	int	r[60]={
			   4,    8, 0xc, 0x8c, 0x10, 0x90, 0x14, 0x94, 
			0x18, 0x98, 0x1c, 0x9c, 0x20, 0xa0, 0x24, 0xa4,
			0x28, 0x2c, 0xac, 0x30, 0x34, 0x38, 0x3c, 0x40,
			0xc0, 0x48, 0x4c, 0xcc, 0x50, 0xd0, 0xd4, 0x60,
			0x64, 0x68, 0x6c, 0xec, 0xd8, 0xdc, 0xe0, 0xe4,
			0,	 0,    0,    0
		   };
	int	i;

	for (i = 0; i < 40; i+=4) {
		printf(" Reg:value : \t%x:%x \t%x:%x \t %x:%x \t %x:%x\n",
		       r[i], bt848[r[i]],
		       r[i+1], bt848[r[i+1]],
		       r[i+2], bt848[r[i+2]],
		       r[i+3], bt848[r[i+3]]);
	}

	bt_long = (u_long *) &bt848[BKTR_INT_STAT];
	printf(" Reg 100 %x \n",  *bt_long);

	bt_long = (u_long *) &bt848[BKTR_INT_MASK];
	printf(" Reg 104 %x \n",  *bt_long);

	bt_long = (u_long *) &bt848[BKTR_GPIO_DMA_CTL];
	printf(" Reg 10C %x \n",  *bt_long);

	return 0;
}


/*
 * build write instruction
 */
#define BKTR_FM1      0x6
#define BKTR_FM3      0xe
#define BKTR_VRE      0x4
#define BKTR_VRO      0xC
#define BKTR_PXV      0x0
#define BKTR_EOL      0x1
#define BKTR_SOL      0x2

#define OP_WRITE      0x1 << 28
#define OP_WRITEC     0x5 << 28
#define OP_JUMP	      0x7 << 28
#define OP_SYNC	      0x8 << 28
#define OP_WRITE123   0x9 << 28
#define OP_WRITES123  0xb << 28
#define OP_SOL	      1 << 27
#define OP_EOL	      1 << 26

static void
rgb_prog( bktr_reg_t * bktr, char i_flag, int cols,
	  int rows, int pixel_width, int interlace )
{
	int			i;
	int  			byte_count;
	volatile unsigned int	inst;
	volatile unsigned int	inst2;
	volatile unsigned int	inst3;
	volatile u_long		target_buffer, buffer;
	volatile u_char		*bt848, *bt_reg;
	volatile u_short	*bts_reg;
	volatile u_long		pitch;
	volatile  u_long	*dma_prog, *btl_reg, *t_test;
	int			b, c;

	bt848 = bktr->base;

	/* color format : rgb32 */
	if (bktr->depth == 4)
		bt848[BKTR_COLOR_FMT] = 0;
	else
		bt848[BKTR_COLOR_FMT] = 0x33;

	bt848[BKTR_COLOR_CTL] = 0x40;
	bt848[BKTR_COLOR_CTL] = 0x10;

#if 0
	bt848[0x10] = 0x1C;
	bt848[0x90] = 0x1C;
#endif

	bt848[BKTR_VBI_PACK_SIZE] = 0;	    
	bt848[BKTR_VBI_PACK_DEL] = 0;

	bt848[BKTR_ADC] = 0x81;
	bt848[BKTR_COLOR_CTL] = 0x20;

	bt848[BKTR_E_VSCALE_HI] |= 0xc0;
	bt848[BKTR_O_VSCALE_HI] |= 0xc0;

	bktr->capcontrol = 3 << 2 |  3;

	dma_prog = (u_long *) bktr->dma_prog;

	/* Construct Write */
	bt_enable_cnt = 0;

	b = (cols * pixel_width ) / 2;

	/* write, sol, eol */
	inst = OP_WRITE	 |  OP_SOL  |  bt_enable_cnt << 12 |  (b);
	inst2 = OP_WRITE |  bt_enable_cnt << 12 |  (cols * pixel_width/2); 
	/* write , sol, eol */
	inst3 = OP_WRITE |  OP_EOL  |  bt_enable_cnt << 12 |  (b);

	if (bktr->video.addr) {
		target_buffer = (u_long) bktr->video.addr;
		pitch = bktr->video.width;
	}
	else {
		target_buffer = (u_long) vtophys(bktr->bigbuf);
		pitch = cols*pixel_width;
	}

	buffer = target_buffer;

	/* contruct sync : for video packet format */
	*dma_prog++ = OP_SYNC | 0xC << 24 | 1 << 15 | BKTR_FM1;

	/* sync, mode indicator packed data */
	*dma_prog++ = 0;  /* NULL WORD */

	for (i = 0; i < (rows/interlace); i++) {
		*dma_prog++ = inst;
		*dma_prog++ = target_buffer;
		*dma_prog++ = inst3;
		*dma_prog++ = target_buffer + b;
		target_buffer += interlace*pitch;
	}

	switch (i_flag) {
	case 1:
		/* sync vre */
		*dma_prog++ = OP_SYNC | 0xC << 24 | 1 << 24 | BKTR_VRE;
		*dma_prog++ = 0;  /* NULL WORD */

		*dma_prog++ = OP_JUMP	| 0xC << 24;
		*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
		return;

	case 2:
		/* sync vre */
		*dma_prog++ = OP_SYNC | 1 << 24 | 1 << 20 | BKTR_VRO;
		*dma_prog++ = 0;  /* NULL WORD */

		*dma_prog++ = OP_JUMP;
		*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
		return;

	case 3:
		/* sync vre */
		*dma_prog++ = OP_SYNC | 0xC << 24 | 1 << 24 | 1 << 15 | BKTR_VRO;
		*dma_prog++ = 0;  /* NULL WORD */
		*dma_prog++ = OP_JUMP | 0xc << 24 ;
		*dma_prog = (u_long ) vtophys(bktr->odd_dma_prog);
		break;
	}

	if (interlace == 2) {

		target_buffer =	 (u_long) buffer + pitch;

		dma_prog = (u_long *) bktr->odd_dma_prog;

		/* sync vre IRQ bit */
		*dma_prog++ = OP_SYNC | 0xc << 24 | 1 << 15 | BKTR_FM1;
		*dma_prog++ = 0;  /* NULL WORD */

		for (i = 0; i < (rows/interlace); i++) {
			*dma_prog++ = inst;
			*dma_prog++ = target_buffer;
			*dma_prog++ = inst3;
			*dma_prog++ = target_buffer + b;
			target_buffer += interlace * pitch;
		}
	}

	/* sync vre IRQ bit */
	*dma_prog++ = OP_SYNC | 0xc << 24 | 1 << 24 | 1 << 15 | BKTR_VRE;
	*dma_prog++ = 0;  /* NULL WORD */
	*dma_prog++ = OP_JUMP | 0xc << 24;
	*dma_prog++ = (u_long ) vtophys(bktr->dma_prog) ;
	*dma_prog++ = 0;  /* NULL WORD */
}


/*
 * 
 */
static void
yuvpack_prog( bktr_reg_t *bktr, char i_flag,
	      int cols, int rows, int interlace )
{
	int			i;
	int  			byte_count;
	volatile unsigned int	inst;
	volatile unsigned int	inst2;
	volatile unsigned int	inst3;
	volatile u_long		target_buffer, buffer;
	volatile u_char		*bt848, *bt_reg;
	volatile u_short	*bts_reg;
	volatile  u_long	*dma_prog, *btl_reg;
	int			b;

	bt848 = bktr->base;

	/* color format : yuvpack */
	bt848[BKTR_COLOR_FMT] = 0x44;

	bt848[BKTR_E_SCLOOP] |= 0x40; /* enable chroma comb */
	bt848[BKTR_O_SCLOOP] |= 0x40;

	bt848[BKTR_COLOR_CTL] = 0x30;
	bt848[BKTR_ADC] = 0x81;

	bktr->capcontrol =   1 << 6 | 1 << 4 | 1 << 2 | 3;
	bktr->capcontrol =   1 << 5 | 1 << 4 | 1 << 2 | 3;

	dma_prog = (u_long *) bktr->dma_prog;

	/* Construct Write */
	bt_enable_cnt = 0;
    
	/* write , sol, eol */
	inst = OP_WRITE	 | OP_SOL | 0xf << 16 | bt_enable_cnt << 12 | (cols*2);
	/* write , sol, eol */
	inst3 = OP_WRITE | OP_EOL | 0xf << 16 | bt_enable_cnt << 12 | (cols);
	inst2 = OP_WRITE | bt_enable_cnt << 12 | (cols ); 

	if (bktr->video.addr)
		target_buffer = (u_long) bktr->video.addr;
	else
		target_buffer = (u_long) vtophys(bktr->bigbuf);

	buffer = target_buffer;

	/* contruct sync : for video packet format */
	/* sync, mode indicator packed data */
	*dma_prog++ = OP_SYNC | 1 << 24 | 1 << 15 | BKTR_FM1;
	*dma_prog++ = 0;  /* NULL WORD */

	b = cols;

	for (i = 0; i < (rows/interlace); i++) {
		*dma_prog++ = inst;
		*dma_prog++ = target_buffer;
		*dma_prog++ = inst3;
		*dma_prog++ = target_buffer + b; 
		target_buffer += interlace*(cols * 2);
	}

	switch (i_flag) {
	case 1:
		/* sync vre */
		*dma_prog++ = OP_SYNC  | 1 << 24  | BKTR_VRE;
		*dma_prog++ = 0;  /* NULL WORD */

		*dma_prog++ = OP_JUMP;
		*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
		return;

	case 2:
		/* sync vre */
		*dma_prog++ = OP_SYNC  | 1 << 24 | 1 << 20 | BKTR_VRO;
		*dma_prog++ = 0;  /* NULL WORD */
		*dma_prog++ = OP_JUMP;
		*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
		return;

	case 3:
		/* sync vre */
		*dma_prog++ = OP_SYNC	| 1 << 24 |  0xf << 16 | BKTR_VRE;
		*dma_prog++ = 0;  /* NULL WORD */
		*dma_prog++ = OP_JUMP  ;
		*dma_prog = (u_long ) vtophys(bktr->odd_dma_prog);
		break;
	}

	if (interlace == 2) {

		target_buffer =	 (u_long) buffer + cols*2;

		dma_prog = (u_long * ) bktr->odd_dma_prog;

		/* sync vre */
		*dma_prog++ = OP_SYNC | 1 << 24 | 0xf << 16 | 1 << 15
				| BKTR_FM1;
		*dma_prog++ = 0;  /* NULL WORD */

		for (i = 0; i < (rows/interlace) ; i++) {
			*dma_prog++ = inst;
			*dma_prog++ = target_buffer;
			*dma_prog++ = inst3;
			*dma_prog++ = target_buffer + b;
			target_buffer += interlace * ( cols*2);
		}
	}

	/* sync vre IRQ bit */
	*dma_prog++ = OP_SYNC	| 1 << 24 |  0xf << 16 |  BKTR_VRO;
	*dma_prog++ = 0;  /* NULL WORD */
	*dma_prog++ = OP_JUMP | 0xf << 16;
	*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);

	*dma_prog++ = OP_JUMP;
	*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
	*dma_prog++ = 0;  /* NULL WORD */
}


/*
 * 
 */
static void
yuv422_prog( bktr_reg_t * bktr, char i_flag,
	     int cols, int rows, int interlace ){

	int			i, j;
	int			byte_count;
	volatile unsigned int	inst;
	volatile unsigned int	inst2;
	volatile unsigned int	instskip, instskip2, instskip3;
	volatile unsigned int	inst3;
	volatile u_long		target_buffer, t1, buffer;
	volatile u_char		*bt848, *bt_reg;
	volatile u_short	*bts_reg;
	volatile  u_long	*dma_prog, *btl_reg;
	int			b, b1;

	bt848 = bktr->base;
	dma_prog = (u_long *) bktr->dma_prog;

	bktr->capcontrol =   1 << 6 | 1 << 4 |	3;

	bt848[BKTR_ADC] = 0x81 ;
	bt848[BKTR_OFORM] = 0x00;

	bt848[BKTR_E_CONTROL] |= 0x20;		/* disable luma decimation */
	bt848[BKTR_O_CONTROL] |= 0x20;

	bt848[BKTR_E_SCLOOP] |= 0x40;		/* chroma agc enable */
	bt848[BKTR_O_SCLOOP] |= 0x40; 

	bt848[BKTR_E_VSCALE_HI] |= 0xc0;	/* luma comb and comb enable */
	bt848[BKTR_O_VSCALE_HI] |= 0xc0;

	bt848[BKTR_COLOR_FMT] = 0x88;

	bt848[BKTR_COLOR_CTL] = 0x10;		/* disable gamma correction */

	bt_enable_cnt = 0;

	/* Construct Write */
	inst  = OP_WRITE123  | OP_SOL | OP_EOL | bt_enable_cnt << 12 | (cols); 
	inst2 = OP_WRITES123 | OP_SOL | OP_EOL | bt_enable_cnt << 12 | (cols); 

	if (bktr->video.addr)
		target_buffer = (u_long) bktr->video.addr;
	else
		target_buffer = (u_long) vtophys(bktr->bigbuf);
    
	buffer = target_buffer;

	t1 = target_buffer;

	/* contruct sync : for video packet format */
	*dma_prog++ = OP_SYNC | 0xC << 24 | 1 << 15 |	BKTR_FM3; /*sync, mode indicator packed data*/
	*dma_prog++ = 0;  /* NULL WORD */

	for (i = 0; i < (rows/interlace ); i++) {
		*dma_prog++ = inst;
		*dma_prog++ = cols/2 | cols/2 << 16;
		*dma_prog++ = target_buffer;
		*dma_prog++ = t1 + (cols*rows) + i*cols/2 * interlace;
		*dma_prog++ = t1 + (cols*rows) + (cols*rows/2) + i*cols/2 * interlace;
		target_buffer += interlace*cols;
	}

	switch (i_flag) {
	case 1:
		*dma_prog++ = OP_SYNC  | 0xC << 24 | 1 << 24 |	BKTR_VRE;  /*sync vre*/
		*dma_prog++ = 0;  /* NULL WORD */

		*dma_prog++ = OP_JUMP | 0xc << 24;
		*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
		return;
		break;
	case 2:
		*dma_prog++ = OP_SYNC  | 0xC << 24 | 1 << 24 |	BKTR_VRO;  /*sync vre*/
		*dma_prog++ = 0;  /* NULL WORD */

		*dma_prog++ = OP_JUMP;
		*dma_prog++ = (u_long ) vtophys(bktr->dma_prog);
		return;
		break;
	case 3:
		*dma_prog++ = OP_SYNC	| 0xc << 24 |  1 << 15 |  BKTR_VRO;  
		*dma_prog++ = 0;  /* NULL WORD */

		*dma_prog++ = OP_JUMP  | 0xc << 24 ;
		*dma_prog = (u_long ) vtophys(bktr->odd_dma_prog);
		break;
	}

	if (interlace == 2) {

		dma_prog = (u_long * ) bktr->odd_dma_prog;

		target_buffer  = (u_long) buffer + cols;
		t1 = target_buffer + cols/2;
		*dma_prog++ = OP_SYNC	| 0xc << 24 |  1 << 24 |   1 << 15 | BKTR_FM3; 
		*dma_prog++ = 0;  /* NULL WORD */

		for (i = 0; i < (rows/interlace ) ; i++) {
			*dma_prog++ = inst;
			*dma_prog++ = cols/2 | cols/2 << 16;
			*dma_prog++ = target_buffer;
			*dma_prog++ = t1 + (cols*rows) + i*cols/2 * interlace;
			*dma_prog++ = t1 + (cols*rows) + (cols*rows/2) + i*cols/2 * interlace;
			target_buffer += interlace*cols;
		}
	}
    
	*dma_prog++ = OP_SYNC  | 0xC << 24 | 1 << 24 |	BKTR_VRE; 
	*dma_prog++ = 0;  /* NULL WORD */
	*dma_prog++ = OP_JUMP | 0xC << 24;;
	*dma_prog++ = (u_long ) vtophys(bktr->dma_prog) ;
	*dma_prog++ = 0;  /* NULL WORD */
}


/*
 * 
 */
static void
build_dma_prog( bktr_reg_t * bktr, char i_flag )
{
	int			i;
	int			pixel_width, rows, cols, byte_count, interlace;
	volatile unsigned int	inst;
	volatile unsigned int	inst2;
	volatile unsigned int	inst3;
	volatile u_long		target_buffer;
	volatile u_char		*bt848, *bt_reg;
	volatile u_short	*bts_reg;
	volatile  u_long	*dma_prog, *btl_reg;
	int			b;

	bt848 = bktr->base;
	btl_reg = (u_long *) &bt848[BKTR_INT_MASK] ;
	*btl_reg = 0;

	bts_reg = (u_short * ) &bt848[BKTR_GPIO_DMA_CTL];
	*bts_reg &= ~3;

	/* capture control */
	switch (i_flag) {
	case 1:
 	        bktr->bktr_cap_ctl  = 0x11;
		bt848[BKTR_CAP_CTL] = 0x11;
		bt848[BKTR_E_VSCALE_HI] &= ~0x20;
		bt848[BKTR_O_VSCALE_HI] &= ~0x20;
		interlace = 1;
		break;
	 case 2:
 	        bktr->bktr_cap_ctl  = 0x12;
		bt848[BKTR_CAP_CTL] = 0x12;
		bt848[BKTR_E_VSCALE_HI] &= ~0x20;
		bt848[BKTR_O_VSCALE_HI] &= ~0x20;
		interlace = 1;
		break;
	 default:
 	        bktr->bktr_cap_ctl  = 0x13;
		bt848[BKTR_CAP_CTL] = 0x13;
		bt848[BKTR_E_VSCALE_HI] |= 0x20;
		bt848[BKTR_O_VSCALE_HI] |= 0x20;
		interlace = 2;
		break;
	}

	btl_reg = (u_long *) &bt848[BKTR_RISC_STRT_ADD] ;
	*btl_reg =  vtophys(bktr->dma_prog);

	pixel_width = bktr->depth;
	rows = bktr->rows;
	cols = bktr->cols;

	if (bktr->format  == METEOR_GEO_RGB24 ||
	    bktr->format  == METEOR_GEO_RGB16) {
		rgb_prog(bktr, i_flag, cols, rows, pixel_width, interlace);
		return;
	}

	if (bktr->format == METEOR_GEO_YUV_422 ){
		yuv422_prog(bktr, i_flag, cols, rows, interlace);
		return;
	}

	if (bktr->format == METEOR_GEO_YUV_PACKED ){
		yuvpack_prog(bktr, i_flag, cols, rows, interlace);
		return;
	}

	return;
}


/******************************************************************************
 * video & video capture specific routines:
 */


/*
 * 
 */
static void
start_capture( bktr_reg_t *bktr, unsigned type )
{
	volatile u_char		*bt848, *bt_reg, i_flag;
	volatile u_short	*bts_reg;
	volatile u_long		*btl_reg;

	bt848 = (u_char *) bktr->base;

	*bt848 = 0;
	btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
	*btl_reg = *btl_reg;

	bktr->flags |= type;
	switch(bktr->flags & METEOR_ONLY_FIELDS_MASK) {
	case METEOR_ONLY_EVEN_FIELDS:
		bktr->flags |= METEOR_WANT_EVEN;
		i_flag = 1;
		break;
	case METEOR_ONLY_ODD_FIELDS:
		bktr->flags |= METEOR_WANT_ODD;
		i_flag = 2;
		break;
	default:
		bktr->flags |= METEOR_WANT_MASK;
		i_flag = 3;
		break;
	}

	if (!bktr->dma_prog_loaded) {
		build_dma_prog(bktr, i_flag);
		bktr->dma_prog_loaded = 1;
	}
	
/*XXX
	switch(bktr->flags & METEOR_ONLY_FIELDS_MASK) {
	default:
	*bts_reg |= 0xb;
	}
*/

	btl_reg = (u_long *) &bt848[BKTR_RISC_STRT_ADD];
	*btl_reg =  vtophys(bktr->dma_prog);

/*XXX
	bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
	*bts_reg = 0x3;
*/

}

/*
 * 
 */
static void
set_fps( bktr_reg_t *bktr, u_short fps )
{
	volatile u_char		*bt848, *bt_reg;
	volatile u_long		*btl_reg;
	volatile u_short	*bts_reg;

	bt848 = (u_char *) bktr->base;

	bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
	*bts_reg = 0;
	btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
	*btl_reg = 0xffffffff;

	bktr->fps = fps;

	if ( fps == 30 ) {
		bt848[BKTR_TDEC] = 0;
		return;
	} else {
		bt848[BKTR_TDEC] = (int) (((float) fps / 30.0) * 60.0) & 0x3f;
		bt848[BKTR_TDEC] |= 0x80;
	}

	if ( bktr->flags & METEOR_CAP_MASK ) {

		btl_reg = (u_long *) &bt848[BKTR_INT_STAT];
		*btl_reg = 0xffffffff;	  
		btl_reg = (u_long *) &bt848[BKTR_RISC_STRT_ADD];
		*btl_reg =  vtophys(bktr->dma_prog);

		bts_reg = (u_short *) &bt848[BKTR_GPIO_DMA_CTL];
		*bts_reg = 1;
		*bts_reg = bktr->capcontrol;
		btl_reg = (u_long *) &bt848[BKTR_INT_MASK];
		*btl_reg =    1 << 11 |	 2 | 1;
	}

	return;
}


/*
 * There is also a problem with range checking on the 7116.
 * It seems to only work for 22 bits, so the max size we can allocate
 * is 22 bits long or 4194304 bytes assuming that we put the beginning
 * of the buffer on a 2^24 bit boundary.  The range registers will use
 * the top 8 bits of the dma start registers along with the bottom 22
 * bits of the range register to determine if we go out of range.
 * This makes getting memory a real kludge.
 *
 */

#define RANGE_BOUNDARY	(1<<22)
static vm_offset_t
get_bktr_mem( int unit, unsigned size )
{
	vm_offset_t	addr = 0;

	addr = vm_page_alloc_contig(size, 0x100000, 0xffffffff, 1<<24);
	if (addr == 0)
		addr = vm_page_alloc_contig(size, 0x100000, 0xffffffff,
								PAGE_SIZE);
	if (addr == 0) {
		printf("meteor%d: Unable to allocate %d bytes of memory.\n",
			unit, size);
	}

	return addr;
}


/******************************************************************************
 * i2c primitives:
 */

/* delays for the I2C bus transactions */
#define NDELAY			0
#if defined ( ORIGINAL_DELAYS )
#define SDELAY			2
#define LDELAY			20
#else
#define SDELAY			10
#define LDELAY			40
#endif /* ORIGINAL_DELAYS */

/* macros to show the details more clearly */
typedef volatile u_long*	i2c_regptr_t;

/*
 * primitives for the I2C clock phases
 */
static inline void
DataLo_ClockLo( i2c_regptr_t bti2c, int delay )
{
	*bti2c = 0;
	if ( delay )
		DELAY( delay );
}
static inline void
DataHi_ClockLo( i2c_regptr_t bti2c, int delay )
{
	*bti2c = 1;
	if ( delay )
		DELAY( delay );
}

static inline void
DataLo_ClockHi( i2c_regptr_t bti2c, int delay )
{
	*bti2c = 2;
	if ( delay )
		DELAY( delay );
}

static inline void
DataHi_ClockHi( i2c_regptr_t bti2c, int delay )
{
	*bti2c = 3;
	if ( delay )
		DELAY( delay );
}

static inline int
DataRead( i2c_regptr_t bti2c )
{
	return ( *bti2c & 1 );
}


/* forward reference */
static int i2cWrite( i2c_regptr_t, u_char );

/*
 * start an I2C bus transaction
 */
static int
i2cStart( i2c_regptr_t bti2c, int address )
{
#if defined( EXTRA_START )
	/* ensure the proper starting state */
	DataHi_ClockLo( bti2c, LDELAY );	/* release data */
	DataHi_ClockHi( bti2c, LDELAY );	/* release clock */
#endif /* EXTRA_START */

	DataLo_ClockHi( bti2c, LDELAY );	/* lower data */
	DataLo_ClockLo( bti2c, LDELAY );	/* lower clock */

	/* send the address of the device */
	return i2cWrite( bti2c, address );
}

/*
 * stop an I2C bus transaction
 */
static void
i2cStop( i2c_regptr_t bti2c )
{
	DELAY( LDELAY );
	DataLo_ClockLo( bti2c, LDELAY );	/* lower clock & data */
	DataLo_ClockHi( bti2c, LDELAY );	/* release clock */
	DataHi_ClockHi( bti2c, LDELAY );	/* release data */
}

/*
 * place a '1' bit on the I2C bus
 */
static void
i2cHi( i2c_regptr_t bti2c )
{
	DataHi_ClockLo( bti2c, LDELAY );	/* assert HI data */
	DataHi_ClockHi( bti2c, LDELAY );	/* strobe clock */
	DataHi_ClockLo( bti2c, LDELAY );	/* release clock */
}

/*
 * place a '0' bit on the I2C bus
 */
static void
i2cLo( i2c_regptr_t bti2c )
{
	DataLo_ClockLo( bti2c, LDELAY );	/* assert LO data */
	DataLo_ClockHi( bti2c, LDELAY );	/* strobe clock */
	DataLo_ClockLo( bti2c, LDELAY );	/* release clock */
}

/*
 * give an 'ACK' to the slave
 */
static void
i2cGrantAck( i2c_regptr_t bti2c )
{
	DataLo_ClockLo( bti2c, LDELAY );	/* assert LO data */
	DataLo_ClockHi( bti2c, LDELAY );	/* strobe clock */
	DataLo_ClockLo( bti2c, LDELAY );	/* remove clock */
	DataHi_ClockLo( bti2c, NDELAY );	/* float data */
}

/*
 * get an 'ACK' from the slave
 */
static int
i2cAck( i2c_regptr_t bti2c )
{
	int acknowledge;

	DataHi_ClockLo( bti2c, LDELAY );	/* float data */
	DataHi_ClockHi( bti2c, LDELAY );	/* strobe clock */

	acknowledge = DataRead( bti2c );	/* read ACK bit */

	DataHi_ClockLo( bti2c, LDELAY );	/* release clock */

	return acknowledge;
}

/*
 * read a byte from the I2C bus
 */
static int
i2cRead( i2c_regptr_t bti2c, int ack )
{
	int x;
	int byte;

	DataHi_ClockLo( bti2c, SDELAY );	/* float data */

	for ( byte = 0, x = 7; x >= 0; --x ) {
		DataHi_ClockHi( bti2c, SDELAY );	/* strobe clock */

		if ( DataRead( bti2c ) )		/* read data */
			byte |= (1<<x);			/* bit was Hi */

		DataHi_ClockLo( bti2c, SDELAY );	/* release clock */
	}

#if defined( FUNNY_HI )
	i2cHi( bti2c );
#endif /* FUNNY_HI */
#if defined( REALLY_ACK )
	if ( ack )
		i2cGrantAck( bti2c );			/* Grant ACK */
#endif /* REALLY_ACK */
	return byte;
}

/*
 * write a byte to the I2C bus
 */
static int
i2cWrite( i2c_regptr_t bti2c, u_char byte )
{
	int x;

	DataLo_ClockLo( bti2c, LDELAY );	/* lower data & clock */

	for ( x = 7; x >= 0; --x )
		(byte & (1<<x)) ? i2cHi( bti2c ) : i2cLo( bti2c );

	return i2cAck( bti2c );
}

#undef NDELAY
#undef SDELAY
#undef LDELAY


#define I2C_REGADDR()		(i2c_regptr_t)&bktr->base[ BKTR_I2C_CONTROL ]


/******************************************************************************
 * card probe
 */


/* guaranteed address for any TSA5522 (PLL on all(?) tuners) */
#define TSA5522_WADDR		0xc2
#define TSA5522_RADDR		0xc3

/* address of BTSC/SAP decoder chip */
#define TDA9850_WADDR		0xb6
#define TDA9850_RADDR		0xb7

/* EEProm (128 * 8) on an STB card */
#define X24C01_WADDR		0xae
#define X24C01_RADDR		0xaf

/* EEProm (256 * 8) on a Hauppauge card */
#define PFC8582_WADDR		0xa0
#define PFC8582_RADDR		0xa1

/*
 * the data for each type of card
 */

#define NO_TUNER		0
#define TEMIC_TUNER		1
#define PHILIPS_TUNER		2


/*
 * Note:
 *   these entried MUST be kept in the order defined by the CARD_XXX defines!
 */
struct CARDTYPE card_types[] = {

	/* CARD_UNKNOWN */
	{ "Unknown",
	   NO_TUNER,
	   0,
	   { 0, 0, 0, 0 } },

	/* CARD_MIRO */
	{ "Miro TV",
	   NO_TUNER, /** TEMIC_TUNER ??? */
	   0,
	   { 0x02, 0x01, 0x00, 0x00 } },	/* XXX ??? */

	/* CARD_HAUPPAUGE */
	{ "Hauppauge WinCast/TV",
	   PHILIPS_TUNER,
	   0,
	   { 0x00, 0x02, 0x01, 0x01 } },

	/* CARD_STB */
	{ "STB TV/PCI",
	   TEMIC_TUNER,
	   0,
	   { 0x00, 0x01, 0x02, 0x02 } },

	/* CARD_INTEL */
	{ "Intel Smart Video III",
	   NO_TUNER,
	   0,
	   { 0, 0, 0, 0 } }
};

/*
 * If probe_card() fails to detect the proper card on boot you can
 * override it by setting the following define to the card you are using:
 *
#define OVERRIDE_CARD	<card type>
 *
 * where <card type> is one of the card defines in the above array.
 */
#define PRESENT		0
#define ABSENT		1
static int
probe_card( bktr_reg_t *bktr, int verbose )
{
	i2c_regptr_t	bti2c;
	int		status;

#if defined( OVERRIDE_CARD )
	bktr->card_type = OVERRIDE_CARD;
	goto end;
#endif
	/* get the i2c register address */
	bti2c = I2C_REGADDR();

	/* look for a tuner */
	status = i2cStart( bti2c, TSA5522_WADDR );
	i2cStop( bti2c );
	if ( status == ABSENT ) {
		bktr->card_type = CARD_INTEL;
		goto checkDBX;
	}

	/* look for a hauppauge card */
	status = i2cStart( bti2c, PFC8582_WADDR );
	i2cStop( bti2c );
	if ( status == PRESENT ) {
		bktr->card_type = CARD_HAUPPAUGE;
		goto checkTuner;
	}

	/* look for an STB card */
	status = i2cStart( bti2c, X24C01_WADDR );
	i2cStop( bti2c );
	if ( status == PRESENT ) {
		bktr->card_type = CARD_STB;
		goto checkTuner;
	}

	/* XXX FIXME: (how do I) look for a Miro card */
	bktr->card_type = CARD_MIRO;

checkTuner:
	/**
	 * XXX FIXME: how can we differentiate TEMIC vs. PHILIPS tuners ???
	 */
	status = i2cStart( bti2c, 0xc0 );
	i2cStop( bti2c );
	if ( status == PRESENT ) {
		card_types[ bktr->card_type ].tuner = TEMIC_TUNER;
		goto checkDBX;
	}

	status = i2cStart( bti2c, 0xc6 );
	i2cStop( bti2c );
	if ( status == PRESENT ) {
		card_types[ bktr->card_type ].tuner = PHILIPS_TUNER;
		goto checkDBX;
	}

	card_types[ bktr->card_type ].tuner = NO_TUNER;

checkDBX:
	/*
	 * probe for BTSC (dbx) chips.
	 */
	status = i2cStart( bti2c, TDA9850_WADDR );
	i2cStop( bti2c );
	if ( status == PRESENT )
		card_types[ bktr->card_type ].dbx = 1;

end:
	if ( verbose ) {
		printf( "%s", card_types[ bktr->card_type ].name );

		if ( card_types[ bktr->card_type ].tuner )
			printf( ", %s tuner",
			        card_types[ bktr->card_type ].tuner
			         == TEMIC_TUNER ? "Temic" : "Philips" );

		if ( card_types[ bktr->card_type ].dbx )
			printf( ", dbx stereo" );

		printf( "\n" );
	}
	return bktr->card_type;
}
#undef ABSENT
#undef PRESENT


#define TSA5522_BANDA	band_addrs[card_types[bktr->card_type].tuner-1][0]
#define TSA5522_BANDB	band_addrs[card_types[bktr->card_type].tuner-1][1]
#define TSA5522_BANDC	band_addrs[card_types[bktr->card_type].tuner-1][2]

u_char band_addrs[][3] = {
	/* BANDA BANDB  BANDC */
	{  0x02,  0x04,  0x01 },	/* TEMIC */
	{  0xa0,  0x90,  0x30 }		/* PHILIPS */
};


/******************************************************************************
 * tuner specific routines:
 */


/*
 * bit 7: CONTROL BYTE = 1
 * bit 6: CP = 0		moderate speed tuning, better FM
 * bit 5: T2 = 0		normal operation
 * bit 4: T1 = 0		normal operation
 * bit 3: T0 = 1		normal operation
 * bit 2: RSA = 1		62.5kHz
 * bit 1: RSB = 1		62.5kHz
 * bit 0: OS = 0		normal operation
 *
 * FIXME: create defines for the above bitfields.
 */
#if 0
#define TSA5522_CONTROL		0xce
#else
#define TSA5522_CONTROL		0x8e
#endif


/* scaling factor for frequencies expressed as ints */
#define FREQFACTOR		16

/*
 * Format:
 *	entry 0:         MAX legal channel
 *	entry 1:         IF frequency
 *			 expressed as fi{mHz} * 16,
 *			 eg 45.75mHz == 45.75 * 16 = 732
 *	entry 2:         [place holder/future]
 *	entry 3:         base of channel record 0
 *	entry 3 + (x*3): base of channel record 'x'
 *	entry LAST:      NULL channel entry marking end of records
 *
 * Record:
 *	int 0:		base channel
 *	int 1:		frequency of base channel,
 *			 expressed as fb{mHz} * 16,
 *	int 2:		offset frequency between channels,
 *			 expressed as fo{mHz} * 16,
 */

/*
 * North American Broadcast Channels:
 *
 *  2:  55.25 mHz -  4:  67.25 mHz
 *  5:  77.25 mHz -  6:	 83.25 mHz
 *  7: 175.25 mHz - 13:	211.25 mHz
 * 14: 471.25 mHz - 83:	885.25 mHz
 *
 * IF freq: 45.75 mHz
 */
#define OFFSET	6.00
int	nabcst[] = {
	83,	(int)( 45.75 * FREQFACTOR),	0,
	14,	(int)(471.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 7,	(int)(175.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 5,	(int)( 77.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 2,	(int)( 55.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 0
};
#undef OFFSET

/*
 * North American Cable Channels, IRC:
 *
 *  2:  55.25 mHz -  4:  67.25 mHz
 *  5:  77.25 mHz -  6:  83.25 mHz
 *  7: 175.25 mHz - 13: 211.25 mHz
 * 14: 121.25 mHz - 22: 169.25 mHz
 * 23: 217.25 mHz - 94: 643.25 mHz
 * 95:  91.25 mHz - 99: 115.25 mHz
 *
 * IF freq: 45.75 mHz
 */
#define OFFSET	6.00
int	irccable[] = {
	99,	(int)( 45.75 * FREQFACTOR),	0,
	95,	(int)( 91.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	23,	(int)(217.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	14,	(int)(121.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 7,	(int)(175.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 5,	(int)( 77.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 2,	(int)( 55.25 * FREQFACTOR),	(int)(OFFSET * FREQFACTOR),
	 0
};
#undef OFFSET

/*
 * North American Cable Channels, HRC:
 *
 */
int	hrccable[] = {
	0, 0, 0,
	0
};

/*
 * Western European channels:
 *
 */
int	weurope[] = {
	0, 0, 0,
	0
};

int* freqTable[] = {
	NULL,
	nabcst,
	irccable,
	hrccable,
	weurope
};


#define TBL_CHNL	freqTable[ bktr->tuner.chnlset ][ x ]
#define TBL_BASE_FREQ	freqTable[ bktr->tuner.chnlset ][ x + 1 ]
#define TBL_OFFSET	freqTable[ bktr->tuner.chnlset ][ x + 2 ]
static int
frequency_lookup( bktr_reg_t* bktr, int channel )
{
	int	x;

	/* check for "> MAX channel" */
	x = 0;
	if ( channel > TBL_CHNL )
		return -1;

	/* search the table for data */
	for ( x = 3; TBL_CHNL; x += 3 ) {
		if ( channel >= TBL_CHNL ) {
			return
			  (TBL_BASE_FREQ + ((channel-TBL_CHNL) * TBL_OFFSET));
		}
	}

	/* not found, must be below the MIN channel */
	return -1;
}
#undef TBL_OFFSET
#undef TBL_BASE_FREQ
#undef TBL_CHNL


#define TBL_IF	freqTable[ bktr->tuner.chnlset ][ 1 ]
/*
 * set the frequency of the tuner
 */
static int
tv_freq( bktr_reg_t* bktr, int frequency )
{
	i2c_regptr_t	bti2c;
	u_char		band;
	int		N;
	int		order;

	/*
	 * select the band based on frequency
	 * FIXME: do the cross-over points need to be set on a
	 * tuner by tuner basis?
	 */
	if ( frequency < (160 * FREQFACTOR) )
		band = TSA5522_BANDA;
	else if ( frequency < (454 * FREQFACTOR) )
		band = TSA5522_BANDB;
	else
		band = TSA5522_BANDC;

	/*
	 * N = 16 * { fRF(pc) + fIF(pc) }
	 * where:
	 *  pc is picture carrier, fRF & fIF are in mHz
	 *
	 * frequency was passed in as mHz * 16
	 */
	N = frequency + TBL_IF;

	/* get the i2c register address */
	bti2c = I2C_REGADDR();

	/* send the data to the TSA5522 */
	i2cStart( bti2c, TSA5522_WADDR );

	/* the data sheet wants the order set according to direction */
	if ( frequency > bktr->tuner.frequency ) {
		i2cWrite( bti2c, (N >> 8) & 0x7f );	/* divisor MSB */
		i2cWrite( bti2c, N & 0xff );		/* divisor LSB */
		i2cWrite( bti2c, TSA5522_CONTROL );	/* control bits */
		i2cWrite( bti2c, band );		/* band select */
	}
	else {
		i2cWrite( bti2c, TSA5522_CONTROL );	/* control bits */
		i2cWrite( bti2c, band );		/* band select */
		i2cWrite( bti2c, (N >> 8) & 0x7f );	/* divisor MSB */
		i2cWrite( bti2c, N & 0xff );		/* divisor LSB */
	}

	i2cStop( bti2c );

	bktr->tuner.frequency = frequency;

	return 0;
}
#undef TBL_IF


/*
 * set the channel of the tuner
 */
static int
tv_channel( bktr_reg_t* bktr, int channel )
{
	int frequency;

	/* calculate the frequency according to tuner type */
	if ( (frequency = frequency_lookup( bktr, channel )) < 0 )
		return -1;

	/* set the new frequency */
	if ( tv_freq( bktr, frequency ) < 0 )
		return -1;

	/* OK to update records */
	bktr->tuner.channel = channel;

	return channel;
}


/*
 * get the status of the tuner
 */
static int
tuner_status( bktr_reg_t* bktr )
{
	i2c_regptr_t	bti2c;
	int		status;

	/* get the i2c register address */
	bti2c = I2C_REGADDR();

	/* send the request to the TSA5522 */
	i2cStart( bti2c, TSA5522_RADDR );

	status = i2cRead( bti2c, 0 );	/* no ACK */

	i2cStop( bti2c );

	return status;
}


#if defined( AUDIO_SUPPORT )
/******************************************************************************
 * audio specific routines:
 */


/*
 * 
 */
#define AUDIOMUX_DISCOVER_NOT
static int
set_audio( bktr_reg_t *bktr, int cmd )
{
	volatile u_char		*bt848;
	volatile u_char		temp;
	volatile u_char		idx;

#if defined( AUDIOMUX_DISCOVER )
	if ( cmd >= 200 )
		cmd -= 200;
	else
#endif /* AUDIOMUX_DISCOVER */

	switch (cmd) {
	case AUDIO_TUNER:
		bktr->audio_mux_select = 0;
		break;
	case AUDIO_EXTERN:
		bktr->audio_mux_select = 1;
		break;
	case AUDIO_INTERN:
		bktr->audio_mux_select = 2;
		break;
	case AUDIO_MUTE:
		bktr->audio_mute_state = TRUE;	/* set mute */
		break;
	case AUDIO_UNMUTE:
		bktr->audio_mute_state = FALSE;	/* clear mute */
		break;
	default:
		printf("bktr: audio cmd error %02x\n", cmd);
		return -1;
	}

	bt848 =	bktr->base;

	/*
	 * Leave the upper bits of the GPIO port alone in case they control
	 * something like the dbx or teletext chips.  This doesn't guarantee
	 * success, but follows the rule of least astonishment.
	 */
	bt848[BKTR_GPIO_OUT_EN] = 0x07;		/* drive low 3 bits */
	bt848[BKTR_GPIO_REG_INP] = 0xf8;	/* read state of others */

#if defined( AUDIOMUX_DISCOVER )
	printf("cmd: %d\n", cmd );

	temp = bt848[BKTR_GPIO_DATA] & ~7;
	bt848[BKTR_GPIO_DATA] = temp | (cmd & 0xff);

	return 0;
#endif /* AUDIOMUX_DISCOVER */

	if ( bktr->audio_mute_state == TRUE )
		idx = 3;
	else
		idx = bktr->audio_mux_select;

	temp = bt848[BKTR_GPIO_DATA] & ~7; /* mask off lower three bits */
	bt848[BKTR_GPIO_DATA] =
		temp | card_types[bktr->card_type].audiomuxs[idx];

	return 0;
}


/*
 * 
 */
#define CON1ADDR		0x04
#define CON2ADDR		0x05
#define CON3ADDR		0x06
#define CON4ADDR		0x07

static int
set_BTSC( bktr_reg_t *bktr, int control )
{
	i2c_regptr_t	bti2c;

	/* get the i2c register address */
	bti2c = I2C_REGADDR();

	/* send the data to the TDA9850 BTSC */
	if ( i2cStart( bti2c, TDA9850_WADDR ) )
		goto fubar;

	if ( i2cWrite( bti2c, CON3ADDR ) )
		goto fubar;

	if ( i2cWrite( bti2c, control ) )
		goto fubar;

	i2cStop( bti2c );
	return 0;

 fubar:
	i2cStop( bti2c );
	return -1;
}
#endif /* AUDIO_SUPPORT */


/******************************************************************************
 * magic:
 */


static bktr_devsw_installed = 0;

static void
bktr_drvinit( void *unused )
{
	dev_t dev;

	if ( ! bktr_devsw_installed ) {
		dev = makedev(CDEV_MAJOR, 0);
		cdevsw_add(&dev,&bktr_cdevsw, NULL);
		bktr_devsw_installed = 1;
	}
}

SYSINIT(bktrdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,bktr_drvinit,NULL)

#endif /* NBKTR > 0 */
