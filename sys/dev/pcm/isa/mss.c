/*
 * sound/ad1848.c
 * 
 * Driver for Microsoft Sound System/Windows Sound System (mss)
 * -compatible boards. This includes:
 * 
 * AD1848, CS4248, CS423x, OPTi931, Yamaha OPL/SAx and many others.
 *
 * Copyright Luigi Rizzo, 1997,1998
 * Copyright by Hannu Savolainen 1994, 1995
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * Full data sheets in PDF format for the MSS-compatible chips
 * are available at
 *
 *	http://www.crystal.com/ for the CS42XX series, or
 *	http://www.opti.com/	for the OPTi931
 */

#include <i386/isa/snd/sound.h>
#if NPCM > 0

/*
 * board-specific include files
 */

#include <i386/isa/snd/mss.h>

/*
 * prototypes for procedures exported in the device descriptor
 */

static int mss_probe(struct isa_device *dev);
static int mss_attach(struct isa_device *dev);

d_open_t mss_open; /* this is a generic full-duplex open routine */
static d_close_t mss_close;
static d_ioctl_t mss_ioctl;
static irq_proc_t mss_intr;
static irq_proc_t opti931_intr;
static  snd_callback_t mss_callback;
   
/*
 * prototypes for local functions
 */

static void mss_reinit(snddev_info *d);
static int AD_WAIT_INIT(snddev_info *d, int x);
static int mss_mixer_set(snddev_info *d, int dev, int value);
static int mss_set_recsrc(snddev_info *d, int mask);
static void ad1848_mixer_reset(snddev_info *d);

static void opti_write(int io_base, u_char reg, u_char data);
static u_char opti_read(int io_base, u_char reg);
static void ad_write(snddev_info *d, int reg, u_char data);
static void ad_write_cnt(snddev_info *d, int reg, u_short data);
static int ad_read(snddev_info *d, int reg);

/* ad1816 prototypes */

/* IO primitives */
static int      ad1816_wait_init(snddev_info * d, int x);
static unsigned short ad1816_read(snddev_info * d, unsigned int reg);
static void     ad1816_write(snddev_info * d, unsigned int reg, unsigned short data);
/* intr and callback functions */
static irq_proc_t ad1816_intr;
static snd_callback_t ad1816_callback;
/* device specific ioctl calls */
static d_ioctl_t ad1816_ioctl;
/* parameter set functions */
static void     ad1816_reinit(snddev_info * d);
static int      ad1816_mixer_set(snddev_info * d, int dev, int value);
static int      ad1816_set_recsrc(snddev_info * d, int mask);
static void     ad1816_mixer_reset(snddev_info * d);

/* ad1816 prototypes end */

/*
 * device descriptors for the boards supported by this module.
 */
snddev_info mss_op_desc = {
    "mss",

    SNDCARD_MSS,
    mss_probe,
    mss_attach,

    mss_open,
    mss_close,
    NULL /* mss_read */,
    NULL /* mss_write */,
    mss_ioctl,
    sndselect /* mss_select */,

    mss_intr,
    mss_callback ,

    DSP_BUFFSIZE,	/* bufsize */

    AFMT_STEREO |
    AFMT_U8 | AFMT_S16_LE | AFMT_MU_LAW | AFMT_A_LAW,	/* audio formats */
    /*
     * the enhanced boards also have AFMT_IMA_ADPCM | AFMT_S16_BE
     * but we do not use these modes.
     */
} ;

/*
 * mss_probe() is the probe routine. Note, it is not necessary to
 * go through this for PnP devices, since they are already
 * indentified precisely using their PnP id.
 *
 * The base address supplied in the device refers to the old MSS
 * specs where the four 4 registers in io space contain configuration
 * information. Some boards (as an example, early MSS boards)
 * has such a block of registers, whereas others (generally CS42xx)
 * do not.  In order to distinguish between the two and do not have
 * to supply two separate probe routines, the flags entry in isa_device
 * has a bit to mark this.
 *
 */

static int
mss_probe(struct isa_device *dev)
{
    u_char   tmp;
    int irq = ffs(dev->id_irq) - 1;
 
    bzero(&pcm_info[dev->id_unit], sizeof(pcm_info[dev->id_unit]) );
    if (dev->id_iobase == -1) {
        dev->id_iobase = 0x530;
        BVDDB(printf("mss_probe: no address supplied, try default 0x%x\n",
	    dev->id_iobase));
    }
    if (snd_conflict(dev->id_iobase))
	return 0 ;

    if ( !(dev->id_flags & DV_F_TRUE_MSS) ) /* Has no IRQ/DMA registers */
	goto mss_probe_end;

    /*
     * Check if the IO port returns valid signature. The original MS
     * Sound system returns 0x04 while some cards
     * (AudioTriX Pro for example) return 0x00 or 0x0f.
     */

    tmp = inb(dev->id_iobase + 3);
    if (tmp == 0xff) {	/* Bus float */
	BVDDB(printf("I/O address inactive (%x), try pseudo_mss\n", tmp));
	dev->id_flags &= ~DV_F_TRUE_MSS ;
	goto mss_probe_end;
    }
    tmp &= 0x3f ;
    if (tmp != 0x04 && tmp != 0x0f && tmp != 0x00) {
	BVDDB(printf("No MSS signature detected on port 0x%x (0x%x)\n",
		   dev->id_iobase, inb(dev->id_iobase + 3)));
	return 0;
    }
    if (irq > 11) {
	printf("MSS: Bad IRQ %d\n", irq);
	return 0;
    }
    if (dev->id_drq != 0 && dev->id_drq != 1 && dev->id_drq != 3) {
	printf("MSS: Bad DMA %d\n", dev->id_drq);
	return 0;
    }
    if (inb(dev->id_iobase + 3) & 0x80) {
	/* 8-bit board: only drq1/3 and irq7/9 */
	if (dev->id_drq == 0) {
	    printf("MSS: Can't use DMA0 with a 8 bit card/slot\n");
	    return 0;
	}
	if (irq != 7 && irq != 9) {
	    printf("MSS: Can't use IRQ%d with a 8 bit card/slot\n", irq);
	    return 0;
	}
    }
mss_probe_end:
    return mss_detect(dev) ? 8 : 0 ; /* mss uses 8 regs */
}

static int
ad1816_attach(struct isa_device *dev)
{
    snddev_info *d = &(pcm_info[dev->id_unit]);

    dev->id_alive = 16;	/* number of io ports */

    if (FULL_DUPLEX(d))
	d->audio_fmt |= AFMT_FULLDUPLEX;

    ad1816_write(d, 1, 0x2);/* disable interrupts */
    ad1816_write(d, 32, 0x90F0);	/* SoundSystem Mode, split format */

    ad1816_write(d, 5, 0x8080);	/* FM volume mute */
    ad1816_write(d, 6, 0x8080);	/* I2S1 volume mute */
    ad1816_write(d, 7, 0x8080);	/* I2S0 volume mute */
    ad1816_write(d, 17, 0x8888);	/* VID Volume mute */
    ad1816_write(d, 20, 0x5050);	/* Source select Mic & auto gain ctrl
				     * off */
    /* adc gain is set to 0 */
    ad1816_reinit(d);
    ad1816_mixer_reset(d);
    return 0 ;
}

/*
 * the address passed as io_base for mss_attach is also the old
 * MSS base address (e.g. 0x530). The codec is four locations ahead.
 * Note that the attach routine for PnP devices might support
 * device-specific initializations.
 */

static int
mss_attach(struct isa_device *dev)
{
    snddev_info *d = &(pcm_info[dev->id_unit]);

    printf("mss_attach <%s>%d at 0x%x irq %d dma %d:%d flags 0x%x\n",
	d->name, dev->id_unit,
	d->io_base, d->irq, d->dbuf_out.chan, d->dbuf_in.chan, dev->id_flags);

    if (d->bd_id == MD_AD1816)
	return ad1816_attach(dev);

    dev->id_alive = 8 ; /* number of io ports */
    /* should be already set but just in case... */

    if ( dev->id_flags & DV_F_TRUE_MSS ) {
	/* has IRQ/DMA registers, set IRQ and DMA addr */
	static char     interrupt_bits[12] = {
	    -1, -1, -1, -1, -1, 0x28, -1, 0x08, -1, 0x10, 0x18, 0x20
	};
	static char     dma_bits[4] = { 1, 2, 0, 3 };
	char	bits ;

	if (d->irq == -1 || (bits = interrupt_bits[d->irq]) == -1) {
	    dev->id_irq = 0 ; /* makk invalid irq */
	    return 0 ;
	}

	outb(dev->id_iobase, bits | 0x40);	/* config port */
	if ((inb(dev->id_iobase + 3) & 0x40) == 0) /* version port */
	    printf("[IRQ Conflict?]");

	/* Write IRQ+DMA setup */
	if ( ! FULL_DUPLEX(d) ) /* single chan dma */
	    outb(dev->id_iobase, bits | dma_bits[d->dbuf_out.chan]);
	else {
	    if (d->dbuf_out.chan == 0 && d->dbuf_in.chan == 1)
		bits |= 5 ;
	    else if (d->dbuf_out.chan == 1 && d->dbuf_in.chan == 0)
		bits |= 6 ;
	    else if (d->dbuf_out.chan == 3 && d->dbuf_in.chan == 0)
		bits |= 7 ;
	    else {
		printf("invalid dual dma config %d:%d\n",
			d->dbuf_out.chan, d->dbuf_in.chan);
		dev->id_irq = 0 ;
		dev->id_alive = 0 ; /* this makes attach fail. */
		return 0 ;
	    }
	    outb(dev->id_iobase, bits );
	}
    }
    if (1) { /* machine-specific code for the Toshiba Libretto */
        u_char r6, r9;
        outb( 0x370, 6 /* dma config */ );
        outb( 0x371, 0xa9 /* config: DMA-B for rec, DMA-A for play */);
        r6 = inb( 0x371 /* read */ ); 
        outb( 0x370, 0xa /* version */ );
        r9 = inb( 0x371 /* read */ );
        DEB(printf("Yamaha: ver 0x%x DMA config 0x%x\n", r6, r9);)
	/*
	 * yamaha - set volume to max
	 */
	outb( 0x370, 7 /* volume left */ );
	outb( 0x371, 0 /* max level */ );
	outb( 0x370, 8 /* volume right */ );
	outb( 0x371, 0 /* max level */ );
    }
    if ( FULL_DUPLEX(d) )
	d->audio_fmt |= AFMT_FULLDUPLEX ;
    if (d->bd_id == MD_YM0020) {
	DDB(printf("setting up yamaha registers\n"));
	outb(0x370, 6 /* dma config */ ) ;
	if (FULL_DUPLEX(d))
	    outb(0x371, 0xa9 ); /* use both dma chans */
	else
	    outb(0x371, 0x8b ); /* use low dma chan */
    }
    mss_reinit(d);
    ad1848_mixer_reset(d);
    return 0;
}

int
mss_open(dev_t dev, int flags, int mode, struct proc * p)
{
    int unit;
    snddev_info *d;
    u_long s;
    
    dev = minor(dev);
    unit = dev >> 4 ;
    dev &= 0xf ;
    d = &pcm_info[unit] ;       
    
    s = spltty();
    /*
     * This was meant to support up to 2 open descriptors for the
     * some device, and check proper device usage on open.
     * Unfortunately, the kernel will trap all close() calls but
     * the last one, with the consequence that we cannot really
     * keep track of which channels are busy.
     * So, the correct tests cannot be done :( and we must rely
     * on the locks on concurrent operations of the same type and
     * on some approximate tests...
     */
    
    if (dev == SND_DEV_AUDIO)
	d->flags |= SND_F_BUSY_AUDIO ;
    else if (dev == SND_DEV_DSP)
	d->flags |= SND_F_BUSY_DSP ;
    else if (dev == SND_DEV_DSP16)
	d->flags |= SND_F_BUSY_DSP16 ;
    if ( d->flags & SND_F_BUSY )
	splx(s); /* device was already set, no need to reinit */
    else {
	/*
	 * device was idle. Do the necessary initialization,
	 * but no need keep interrupts blocked.
	 * will not get them
	 */

	splx(s);
	d->play_speed = d->rec_speed = DSP_DEFAULT_SPEED ;
	d->flags |= SND_F_BUSY ;

	d->wsel.si_pid = 0;
	d->wsel.si_flags = 0;

	d->rsel.si_pid = 0;
	d->rsel.si_flags = 0;

	d->dbuf_out.total = d->dbuf_out.prev_total = 0 ;
	d->dbuf_in.total = d->dbuf_in.prev_total = 0 ;

	if (flags & O_NONBLOCK)
	    d->flags |= SND_F_NBIO ;

	switch (dev) {
	default :
	case SND_DEV_AUDIO :
	    d->play_fmt = d->rec_fmt = AFMT_MU_LAW ;
	    break ;
	case SND_DEV_DSP :
	    d->play_fmt = d->rec_fmt = AFMT_U8 ;
	    break ;
	case SND_DEV_DSP16 :
	    d->play_fmt = d->rec_fmt = AFMT_S16_LE ;
	    break;
	}
	ask_init(d); /* and reset buffers... */
    }
    return 0 ;
}

static int
mss_close(dev_t dev, int flags, int mode, struct proc * p)
{
    int unit;
    snddev_info *d;
    u_long s;

    dev = minor(dev);
    unit = dev >> 4 ;
    dev &= 0xf;
    d = &pcm_info[unit] ;

    /*
     * We will only get a single close call when the last reference
     * to the device is gone. But we must handle ourselves references
     * through different devices.
     */

    s = spltty();

    if (dev == SND_DEV_AUDIO)
	d->flags &= ~SND_F_BUSY_AUDIO ;
    else if (dev == SND_DEV_DSP)
	d->flags &= ~SND_F_BUSY_DSP ;
    else if (dev == SND_DEV_DSP16)
	d->flags &= ~SND_F_BUSY_DSP16 ;
    if ( d->flags & SND_F_BUSY_ANY )	/* still some device open */
	splx(s);
    else {				/* last one */
	d->flags |= SND_F_CLOSING ;
	splx(s); /* is this ok here ? */
	snd_flush(d);
	/* Clear interrupt status */
	if ( d->bd_id == MD_AD1816 )
	    outb(ad1816_int(d), 0);
	else
	    outb(io_Status(d), 0);
	d->flags = 0 ;
    }
    return 0 ;
}

static int
mss_ioctl(dev_t dev, u_long cmd, caddr_t arg, int mode, struct proc * p)
{
    snddev_info *d;
    int unit;

    dev = minor(dev);
    unit = dev >> 4 ;
    d = &pcm_info[unit] ;
    /*
     * handle mixer calls first. Reads are in the default handler,
     * so do not bother about them.
     */
    if ( (cmd & MIXER_WRITE(0)) == MIXER_WRITE(0) ) {
        cmd &= 0xff ;
        if (cmd == SOUND_MIXER_RECSRC)
	    return mss_set_recsrc(d, *(int *)arg) ;
	else
	    return mss_mixer_set(d, cmd, *(int *)arg) ;
    }

    return ENOSYS ; /* fallback to the default ioctl handler */
}


/*
 * the callback routine to handle all dma ops etc.
 * With the exception of INIT, all other callbacks are invoked
 * with interrupts disabled.
 */

static int
mss_callback(snddev_info *d, int reason)
{
    u_char m;
    int retry, wr, cnt;

    DEB(printf("-- mss_callback reason 0x%03x\n", reason));
    wr = reason & SND_CB_WR ;
    reason &= SND_CB_REASON_MASK ;
    switch (reason) {
    case SND_CB_INIT : /* called with int enabled and no pending I/O */
	/*
	 * perform all necessary initializations for i/o
	 */
	d->rec_fmt = d->play_fmt ; /* no split format on the MSS */
	snd_set_blocksize(d);
	mss_reinit(d);
	reset_dbuf(& (d->dbuf_in), SND_CHAN_RD );
	reset_dbuf(& (d->dbuf_out), SND_CHAN_WR );
	return 1 ;
	break ;
    
    case SND_CB_START :
	cnt = wr ? d->dbuf_out.dl : d->dbuf_in.dl ;
	if (d->play_fmt == AFMT_S16_LE)
	    cnt /= 2;
	if (d->flags & SND_F_STEREO)
	    cnt /= 2;
	cnt-- ;

	DEB(printf("-- (re)start cnt %d\n", cnt));
	m = ad_read(d,9) ;
	DEB( if (m & 4) printf("OUCH! reg 9 0x%02x\n", m); );
	m |= wr ? I9_PEN : I9_CEN ; /* enable DMA */
	/*
	 * on the OPTi931 the enable bit seems hard to set...
	 */
	for (retry = 10; retry; retry--) {
	    ad_write(d, 9, m );
	    if (ad_read(d,9) ==m) break;
	}
	if (retry == 0)
	    printf("start dma, failed to set bit 0x%02x 0x%02x\n",
		m, ad_read(d, 9) ) ;
	if (wr || ! FULL_DUPLEX(d) )
	    ad_write_cnt(d, 14, cnt);
	else
	    ad_write_cnt(d, 30, cnt);

	break ;

    case SND_CB_STOP :
    case SND_CB_ABORT : /* XXX check this... */
	m = ad_read(d,9) ;
	m &= wr ?  ~I9_PEN : ~I9_CEN ; /* Stop DMA */
	/*
	 * on the OPTi931 the enable bit seems hard to set...
	 */
	for (retry = 10; retry ; retry-- ) {
	    ad_write(d, 9, m );
	    if (ad_read(d,9) ==m) break;
	}
	if (retry == 0)
	    printf("start dma, failed to clear bit 0x%02x 0x%02x\n",
		m, ad_read(d, 9) ) ;
#if 1
	/*
	 * try to disable DMA by clearing count registers. Not sure it
	 * is needed, and it might cause false interrupts when the
	 * DMA is re-enabled later.
	 */
	if (wr || ! FULL_DUPLEX(d) )
	    ad_write_cnt(d, 14, 0);
	else
	    ad_write_cnt(d, 30, 0);
	break;
#endif
    }
    return 0 ;
}

/*
 * main irq handler for the CS423x. The OPTi931 code is
 * a separate one.
 * The correct way to operate for a device with multiple internal
 * interrupt sources is to loop on the status register and ack
 * interrupts until all interrupts are served and none are reported. At
 * this point the IRQ line to the ISA IRQ controller should go low
 * and be raised at the next interrupt.
 *
 * Since the ISA IRQ controller is sent EOI _before_ passing control
 * to the isr, it might happen that we serve an interrupt early, in
 * which case the status register at the next interrupt should just
 * say that there are no more interrupts...
 */

static void
mss_intr(int unit)
{
    snddev_info *d = &pcm_info[unit];
    u_char c, served = 0;
    int i;

    DEB(printf("mss_intr\n"));
    ad_read(d, 11); /* fake read of status bits */

    /*
     * loop until there are interrupts, but no more than 10 times.
     */
    for (i=10 ; i && inb(io_Status(d)) & 1 ; i-- ) {
	/* get exact reason for full-duplex boards */
	c = FULL_DUPLEX(d) ? ad_read(d, 24) : 0x30 ;
	c &= ~served ;
	if ( d->dbuf_out.dl && (c & 0x10) ) {
	    served |= 0x10 ;
	    dsp_wrintr(d);
	}
	if ( d->dbuf_in.dl && (c & 0x20) ) {
	    served |= 0x20 ;
	    dsp_rdintr(d);
	}
	/* 
	 * now ack the interrupt
	 */
	if ( FULL_DUPLEX(d) )
	    ad_write(d, 24, ~c); /* ack selectively */
	else
	    outb(io_Status(d), 0);	/* Clear interrupt status */
    }
    if (served == 0) {
	printf("How strange... mss_intr with no reason!\n");
	/*
	 * this should not happen... I have no idea what to do now.
	 * maybe should do a sanity check and restart dmas ?
	 */
	outb(io_Status(d), 0);	/* Clear interrupt status */
    }
}

/*
 * the opti931 seems to miss interrupts when working in full
 * duplex, so we try some heuristics to catch them.
 */
static void
opti931_intr(int unit)
{
    snddev_info *d = &pcm_info[unit];
    u_char masked=0, i11, mc11, c=0;
    u_char reason; /* b0 = playback, b1 = capture, b2 = timer */
    int loops = 10;

#if 0
    reason = inb(io_Status(d));
    if ( ! (reason & 1) ) {/* no int, maybe a shared line ? */
	printf("opti931_intr: flag 0, mcir11 0x%02x\n", ad_read(d,11));
	return;
    }
#endif
    i11 = ad_read(d, 11); /* XXX what's for ? */
again:

    c=mc11 = FULL_DUPLEX(d) ? opti_read(d->conf_base, 11) : 0xc ;
    mc11 &= 0x0c ;
    if (c & 0x10) {
	DEB(printf("Warning: CD interrupt\n");)
	mc11 |= 0x10 ;
    }
    if (c & 0x20) {
	DEB(printf("Warning: MPU interrupt\n");)
	mc11 |= 0x20 ;
    }
    if (mc11 & masked) 
        printf("irq reset failed, mc11 0x%02x, masked 0x%02x\n", mc11, masked);
    masked |= mc11 ;
    /*
     * the nice OPTi931 sets the IRQ line before setting the bits in
     * mc11. So, on some occasions I have to retry (max 10 times).
     */
    if ( mc11 == 0 ) { /* perhaps can return ... */
	reason = inb(io_Status(d));
	if (reason & 1) {
	    DEB(printf("one more try...\n");)
	    if (--loops)
		goto again;
	    else
		DDB(printf("opti_intr: irq but mc11 not set!...\n");)
	}
	if (loops==10)
	    printf("ouch, intr but nothing in mcir11 0x%02x\n", mc11);
	return;
    }

    if ( d->dbuf_in.dl && (mc11 & 8) ) {
	dsp_rdintr(d);
    }
    if ( d->dbuf_out.dl && (mc11 & 4) ) {
	dsp_wrintr(d);
    }
    opti_write(d->conf_base, 11, ~mc11); /* ack */
    if (--loops)
	goto again;
    DEB(printf("xxx too many loops\n");)
}

/*
 * Second part of the file: functions local to this module.
 * in this section a few routines to access MSS registers
 *
 */

static void
opti_write(int io_base, u_char reg, u_char value)
{
    outb(io_base, reg);
    outb(io_base+1, value);
}

static u_char
opti_read(int io_base, u_char reg)
{
    outb(io_base, reg);
    return inb(io_base+1);
}

static void
gus_write(int io_base, u_char reg, u_char value)
{
    outb(io_base + 3, reg);
    outb(io_base + 5, value);
}

#if 0
static void
gus_writew(int io_base, u_char reg, u_short value)
{
    outb(io_base + 3, reg);
    outb(io_base + 4, value);
}
#endif

static u_char
gus_read(int io_base, u_char reg)
{
    outb(io_base+3, reg);
    return inb(io_base+5);
}

#if 0
static u_short
gus_readw(int io_base, u_char reg)
{
    outb(io_base+3, reg);
    return inw(io_base+4);
}
#endif

/*
 * AD_WAIT_INIT waits if we are initializing the board and
 * we cannot modify its settings
 */
static int
AD_WAIT_INIT(snddev_info *d, int x)
{
    int arg=x, n = 0; /* to shut up the compiler... */
    for (; x-- ; )
	if ( (n=inb(io_Index_Addr(d))) & IA_BUSY)
	    DELAY(10);
	else
	    return n ;
    printf("AD_WAIT_INIT FAILED %d 0x%02x\n", arg, n);
    return n ;
}

static int
ad_read(snddev_info *d, int reg)
{
    u_long   flags;
    int             x;

    flags = spltty();
    AD_WAIT_INIT(d, 201);
    x = inb(io_Index_Addr(d)) & ~IA_AMASK ;
    outb(io_Index_Addr(d), (u_char) (reg & IA_AMASK) | x ) ;
    x = inb(io_Indexed_Data(d));
    splx(flags);
    return x;
}

static void
ad_write(snddev_info *d, int reg, u_char data)
{
    u_long   flags;

    int x ;
    flags = spltty();
    AD_WAIT_INIT(d, 1002);
    x = inb(io_Index_Addr(d)) & ~IA_AMASK ;
    outb(io_Index_Addr(d), (u_char) (reg & IA_AMASK) | x ) ;
    outb(io_Indexed_Data(d), data);
    splx(flags);
}

static void
ad_write_cnt(snddev_info *d, int reg, u_short cnt)
{
    ad_write(d, reg+1, cnt & 0xff );
    ad_write(d, reg, cnt >> 8 ); /* upper base must be last */
}

static void
wait_for_calibration(snddev_info *d)
{
    int n, t;

    /*
     * Wait until the auto calibration process has finished.
     * 
     * 1) Wait until the chip becomes ready (reads don't return 0x80).
     * 2) Wait until the ACI bit of I11 gets on
     * 3) Wait until the ACI bit of I11 gets off
     */

    n = AD_WAIT_INIT(d, 1000);
    if (n & IA_BUSY)
	printf("mss: Auto calibration timed out(1).\n");

    for (t = 100 ; t>0 && (ad_read(d, 11) & 0x20) == 0 ; t--)
	    DELAY(100);
    for (t = 100 ; t>0 && ad_read(d, 11) & 0x20 ; t--)
	    DELAY(100);
}

#if 0 /* unused right now... */
static void
ad_mute(snddev_info *d)
{
    ad_write(d, 6, ad_read(d,6) | I6_MUTE);
    ad_write(d, 7, ad_read(d,7) | I6_MUTE);
}

static void
ad_unmute(snddev_info *d)
{
    ad_write(d, 6, ad_read(d,6) & ~I6_MUTE);
    ad_write(d, 7, ad_read(d,7) & ~I6_MUTE);
}
#endif

static void
ad_enter_MCE(snddev_info *d)
{
    int prev;

    d->bd_flags |= BD_F_MCE_BIT;
    AD_WAIT_INIT(d, 203);
    prev = inb(io_Index_Addr(d));
    prev &= ~IA_TRD ;
    outb(io_Index_Addr(d), prev | IA_MCE ) ;
}

static void
ad_leave_MCE(snddev_info *d)
{
    u_long   flags;
    u_char   prev;

    if ( (d->bd_flags & BD_F_MCE_BIT) == 0 ) {
	printf("--- hey, leave_MCE: MCE bit was not set!\n");
	return;
    }

    AD_WAIT_INIT(d, 1000);

    flags = spltty();
    d->bd_flags &= ~BD_F_MCE_BIT;

    prev = inb(io_Index_Addr(d));
    prev &= ~IA_TRD ;
    outb(io_Index_Addr(d), prev & ~IA_MCE ); /* Clear the MCE bit */
    wait_for_calibration(d);
    splx(flags);
}

/*
 * only one source can be set...
 */
static int
mss_set_recsrc(snddev_info *d, int mask)
{
    u_char   recdev;

    mask &= d->mix_rec_devs;
    switch (mask) {
    case SOUND_MASK_LINE:
    case SOUND_MASK_LINE3:
	recdev = 0;
	break;

    case SOUND_MASK_CD:
    case SOUND_MASK_LINE1:
	recdev = 0x40;
	break;

    case SOUND_MASK_IMIX:
	recdev = 0xc0;
	break;

    case SOUND_MASK_MIC:
    default:
	mask = SOUND_MASK_MIC;
	recdev = 0x80;
    }

    ad_write(d, 0, (ad_read(d, 0) & 0x3f) | recdev);
    ad_write(d, 1, (ad_read(d, 1) & 0x3f) | recdev);

    d->mix_recsrc = mask;
    return 0;
}

/*
 * there are differences in the mixer depending on the actual sound
 * card.
 */
static int
mss_mixer_set(snddev_info *d, int dev, int value)
{
    int             left = value & 0x000000ff;
    int             right = (value & 0x0000ff00) >> 8;

    int             regoffs;
    mixer_tab *mix_d = &mix_devices;

    u_char  old, val;

    if (dev > 31)
	return EINVAL;

    if (!(d->mix_devs & (1 << dev)))
	return EINVAL;

    if (d->bd_id == MD_OPTI931)
	mix_d = &(opti931_devices);

    if ((*mix_d)[dev][LEFT_CHN].nbits == 0) {
	DEB(printf("nbits = 0 for dev %d\n", dev) );
	return EINVAL;
    }

    if (left > 100)
	left = 100;
    if (right > 100)
	right = 100;


    if ( (*mix_d)[dev][RIGHT_CHN].nbits == 0)	/* Mono control */
	right = left;

    d->mix_levels[dev] = left | (right << 8);

#if 0
    /* Scale volumes */
    left = mix_cvt[left];
    right = mix_cvt[right];
#endif
    /*
     * Set the left channel
     */

    regoffs = (*mix_d)[dev][LEFT_CHN].regno;
    old = val = ad_read(d, regoffs);
    /*
     * if volume is 0, mute chan. Otherwise, unmute.
     */
    if (regoffs != 0)  /* main input is different */
	val = (left == 0 ) ? old | 0x80 : old & 0x7f ;

    change_bits(mix_d, &val, dev, LEFT_CHN, left);
    ad_write(d, regoffs, val);
    DEB(printf("LEFT: dev %d reg %d old 0x%02x new 0x%02x\n",
	dev, regoffs, old, val));

    if ((*mix_d)[dev][RIGHT_CHN].nbits != 0) { /* have stereo */
	/*
	 * Set the right channel
	 */
	regoffs = (*mix_d)[dev][RIGHT_CHN].regno;
	old = val = ad_read(d, regoffs);
	if (regoffs != 1)
	    val = (right == 0 ) ? old | 0x80 : old & 0x7f ;
	change_bits(mix_d, &val, dev, RIGHT_CHN, right);
	ad_write(d, regoffs, val);
	DEB(printf("RIGHT: dev %d reg %d old 0x%02x new 0x%02x\n",
	    dev, regoffs, old, val));
    }
    return 0; /* success */
}

static void
ad1848_mixer_reset(snddev_info *d)
{
    int             i;

    if (d->bd_id == MD_OPTI931)
	d->mix_devs = OPTI931_MIXER_DEVICES;
    else if (d->bd_id != MD_AD1848)
	d->mix_devs = MODE2_MIXER_DEVICES;
    else
	d->mix_devs = MODE1_MIXER_DEVICES;

    d->mix_rec_devs = MSS_REC_DEVICES;

    for (i = 0; i < SOUND_MIXER_NRDEVICES; i++)
	if (d->mix_devs & (1 << i))
	    mss_mixer_set(d, i, default_mixer_levels[i]);
    mss_set_recsrc(d, SOUND_MASK_MIC);
    /*
     * some device-specific things, mostly mute the mic to
     * the output mixer so as to avoid hisses. In many cases this
     * is the default after reset, this code is here mostly as a
     * reminder that this might be necessary on other boards.
     */
    switch(d->bd_id) {
    case MD_OPTI931:
	ad_write(d, 20, 0x88);
	ad_write(d, 21, 0x88);
	break;

    case MD_YM0020:
	/* set master volume to max */
	DDB(printf("set yamaha master volume to max\n"); )
	outb(0x370, 7) ;
	outb(0x371, 0) ;
	outb(0x370, 8) ;
	outb(0x371, 0) ;
	break;

    case MD_GUSPNP:
	/* this is only necessary in mode 3 ... */
	ad_write(d, 22, 0x88);
	ad_write(d, 23, 0x88);
    }
}

/*
 * mss_speed processes the value in play_speed finding the
 * matching one. As a side effect, it returns the value to
 * be written in the speed bits of the codec. It does _NOT_
 * set the speed of the device (but it should!)
 */

static int
mss_speed(snddev_info *d)
{
    /*
     * In the CS4231, the low 4 bits of I8 are used to hold the
     * sample rate.  Only a fixed number of values is allowed. This
     * table lists them. The speed-setting routines scans the table
     * looking for the closest match. This is the only supported method.
     *
     * In the CS4236, there is an alternate metod (which we do not
     * support yet) which provides almost arbitrary frequency setting.
     * In the AD1845, it looks like the sample rate can be
     * almost arbitrary, and written directly to a register.
     * In the OPTi931, there is a SB command which provides for
     * almost arbitrary frequency setting.
     *
     */
    static int speeds[] = {
	8000, 5512, 16000, 11025, 27429, 18900, 32000, 22050,
	-1, 37800, -1, 44100, 48000, 33075, 9600, 6615
    };

    int arg, i, sel = 0; /* assume entry 0 does not contain -1 */

    arg = d->play_speed ;

    for (i=1; i < 16 ; i++)
	if (speeds[i] >0 && abs(arg-speeds[i]) < abs(arg-speeds[sel]) )
	    sel = i ;

    d->play_speed = d->rec_speed = speeds[sel] ;
    return sel ;
}

/*
 * mss_format checks that the format is supported (or defaults to AFMT_U8)
 * and returns the bit setting for the 1848 register corresponding to
 * the desired format.
 *
 * fixed lr970724
 */

static int
mss_format(snddev_info *d)
{
    int i, arg = d->play_fmt ;

    /*
     * The data format uses 3 bits (just 2 on the 1848). For each
     * bit setting, the following array returns the corresponding format.
     * The code scans the array looking for a suitable format. In
     * case it is not found, default to AFMT_U8 (not such a good
     * choice, but let's do it for compatibility...).
     */

    static int fmts[] = {
	AFMT_U8, AFMT_MU_LAW, AFMT_S16_LE, AFMT_A_LAW,
	-1, AFMT_IMA_ADPCM, AFMT_U16_BE, -1
    };

    if ( (arg & d->audio_fmt) == 0 ) /* unsupported fmt, default to AFMT_U8 */
	arg = AFMT_U8 ;

    /* ulaw/alaw seems broken on the opti931... */
    if (d->bd_id == MD_OPTI931 || d->bd_id == MD_GUSPNP) {
	if (arg == AFMT_MU_LAW) {
	    arg = AFMT_U8 ;
	    d->flags |= SND_F_XLAT8 ;
	} else
	    d->flags &= ~SND_F_XLAT8 ;
    }
    /*
     * check that arg is one of the supported formats in d->format;
     * otherwise fallback to AFMT_U8
     */

    for (i=0 ; i<8 ; i++)
	if (arg == fmts[i]) break;
    if (i==8) {	/* not found, default to AFMT_U8 */
	arg = AFMT_U8 ;
	i = 0 ;
    }
    d->play_fmt = d->rec_fmt = arg;

    return i ;
}

/*
 * mss_detect can be used in the probe and the attach routine.
 *
 * We store probe information in pcm_info[unit]. This descriptor
 * is reinitialized just before the attach, so all relevant
 * information is lost, and mss_detect must be run again in
 * the attach routine if necessary.
 */

int
mss_detect(struct isa_device *dev)
{
    int             i;
    u_char   tmp, tmp1, tmp2 ;
    snddev_info *d = &(pcm_info[dev->id_unit]);
    char *name;

    d->io_base = dev->id_iobase;
    d->bd_flags |= BD_F_MCE_BIT ;
    if (d->bd_id != 0) {
	printf("preselected bd_id 0x%04x -- %s\n",
		d->bd_id, d->name ? d->name : "???");
	return 1;
    }

    name = "AD1848" ;
    d->bd_id = MD_AD1848; /* AD1848 or CS4248 */

    /*
     * Check that the I/O address is in use.
     * 
     * bit 7 of the base I/O port is known to be 0 after the chip has
     * performed its power on initialization. Just assume this has
     * happened before the OS is starting.
     * 
     * If the I/O address is unused, it typically returns 0xff.
     */

    for (i=0; i<10; i++)
	if (inb(io_Index_Addr(d)) & IA_BUSY)
	    DELAY(10000); /* maybe busy, wait & retry later */
	else
	    break ;
    if ((inb(io_Index_Addr(d)) & IA_BUSY) != 0x00) {	/* Not a AD1848 */
	BVDDB(printf("mss_detect error, busy still set (0x%02x)\n",
		   inb(io_Index_Addr(d))));
	return 0;
    }
    /*
     * Test if it's possible to change contents of the indirect
     * registers. Registers 0 and 1 are ADC volume registers. The bit
     * 0x10 is read only so try to avoid using it.
     */

    ad_write(d, 0, 0xaa);
    ad_write(d, 1, 0x45);/* 0x55 with bit 0x10 clear */
    tmp1 = ad_read(d, 0) ;
    tmp2 = ad_read(d, 1) ;
    if ( tmp1 != 0xaa || tmp2 != 0x45) {
	BVDDB(printf("mss_detect error - IREG (0x%02x/0x%02x) want 0xaa/0x45\n",
		tmp1, tmp2));
	return 0;
    }

    ad_write(d, 0, 0x45);
    ad_write(d, 1, 0xaa);
    tmp1 = ad_read(d, 0) ;
    tmp2 = ad_read(d, 1) ;

    if (tmp1 != 0x45 || tmp2 != 0xaa) {
	BVDDB(printf("mss_detect error - IREG2 (%x/%x)\n", tmp1, tmp2));
	return 0;
    }

    /*
     * The indirect register I12 has some read only bits. Lets try to
     * change them.
     */

    tmp = ad_read(d, 12);
    ad_write(d, 12, (~tmp) & 0x0f);
    tmp1 = ad_read(d, 12);

    if ((tmp & 0x0f) != (tmp1 & 0x0f)) {
	BVDDB(printf("mss_detect error - I12 (0x%02x was 0x%02x)\n",
	    tmp1, tmp));
	return 0;
    }

    /*
     * NOTE! Last 4 bits of the reg I12 tell the chip revision.
     *	0x01=RevB
     *  0x0A=RevC. also CS4231/CS4231A and OPTi931
     */

    BVDDB(printf("mss_detect - chip revision 0x%02x\n", tmp & 0x0f);)

    /*
     * The original AD1848/CS4248 has just 16 indirect registers. This
     * means that I0 and I16 should return the same value (etc.). Ensure
     * that the Mode2 enable bit of I12 is 0. Otherwise this test fails
     * with new parts.
     */

    ad_write(d, 12, 0);	/* Mode2=disabled */

    for (i = 0; i < 16; i++)
	if ((tmp1 = ad_read(d, i)) != (tmp2 = ad_read(d, i + 16))) {
	    BVDDB(printf("mss_detect warning - I%d: 0x%02x/0x%02x\n",
		i, tmp1, tmp2));
	    /*
	     * note - this seems to fail on the 4232 on I11. So we just break
	     * rather than fail.
	     */
	    break ; /* return 0; */
	}
    /*
     * Try to switch the chip to mode2 (CS4231) by setting the MODE2 bit
     * (0x40). The bit 0x80 is always 1 in CS4248 and CS4231.
     *
     * On the OPTi931, however, I12 is readonly and only contains the
     * chip revision ID (as in the CS4231A). The upper bits return 0.
     */

    ad_write(d, 12, 0x40);	/* Set mode2, clear 0x80 */

    tmp1 = ad_read(d, 12);
    if (tmp1 & 0x80) {
	name = "CS4248" ; /* Our best knowledge just now */
    }
    if ((tmp1 & 0xf0) == 0x00) {
	BVDDB(printf("this should be an OPTi931\n");)
    } else if ((tmp1 & 0xc0) == 0xC0) {
	/*
	 * The 4231 has bit7=1 always, and bit6 we just set to 1.
	 * We want to check that this is really a CS4231
	 * Verify that setting I0 doesn't change I16.
	 */
	ad_write(d, 16, 0);	/* Set I16 to known value */

	ad_write(d, 0, 0x45);
	if ((tmp1 = ad_read(d, 16)) != 0x45) { /* No change -> CS4231? */

	    ad_write(d, 0, 0xaa);
	    if ((tmp1 = ad_read(d, 16)) == 0xaa) {	/* Rotten bits? */
		BVDDB(printf("mss_detect error - step H(%x)\n", tmp1));
		return 0;
	    }
	    /*
	     * Verify that some bits of I25 are read only.
	     */

	    tmp1 = ad_read(d, 25);	/* Original bits */
	    ad_write(d, 25, ~tmp1);	/* Invert all bits */
	    if ((ad_read(d, 25) & 0xe7) == (tmp1 & 0xe7)) {
		int             id;

		/*
		 * It's at least CS4231
		 */
		name = "CS4231" ;
		d->bd_id = MD_CS4231;

		/*
		 * It could be an AD1845 or CS4231A as well.
		 * CS4231 and AD1845 report the same revision info in I25
		 * while the CS4231A reports different.
		 */

		id = ad_read(d, 25) & 0xe7;
		/*
		 * b7-b5 = version number;
		 *	100 : all CS4231
		 *	101 : CS4231A
		 *      
		 * b2-b0 = chip id;
		 */
		switch (id) {

		case 0xa0:
		    name = "CS4231A" ;
		    d->bd_id = MD_CS4231A;
		    break;

		case 0xa2:
		    name = "CS4232" ;
		    d->bd_id = MD_CS4232;
		    break;

		case 0xb2:
		    /* strange: the 4231 data sheet says b4-b3 are XX
		     * so this should be the same as 0xa2
		     */
		    name = "CS4232A" ;
		    d->bd_id = MD_CS4232A;
		    break;

		case 0x80:
		    /*
		     * It must be a CS4231 or AD1845. The register I23
		     * of CS4231 is undefined and it appears to be read
		     * only. AD1845 uses I23 for setting sample rate.
		     * Assume the chip is AD1845 if I23 is changeable.
		     */

		    tmp = ad_read(d, 23);

		    ad_write(d, 23, ~tmp);
		    if (ad_read(d, 23) != tmp) {	/* AD1845 ? */
			name = "AD1845" ;
			d->bd_id = MD_AD1845;
		    }
		    ad_write(d, 23, tmp);	/* Restore */
		    DDB(printf("... try to identify the yamaha\n") ;)
		    tmp = inb(0x370) ;
		    outb(0x370, 6 /* dma config */ ) ;
		    if (inb(0x370) != 6 ) /* not a yamaha... restore. */
			outb(0x370, tmp ) ;
		    else
			d->bd_id = MD_YM0020 ;
		    break;

		case 0x83:	/* CS4236 */
		case 0x03:      /* CS4236 on Intel PR440FX motherboard XXX */
		    name = "CS4236";
		    d->bd_id = MD_CS4236;
		    break ;

		default:	/* Assume CS4231 */
		    BVDDB(printf("unknown id 0x%02x, assuming CS4231\n", id);)
		    d->bd_id = MD_CS4231;
		}
	    }
	    ad_write(d, 25, tmp1);	/* Restore bits */

	}
    }
    BVDDB(printf("mss_detect() - Detected %s\n", name));
    snprintf(d->name, sizeof(d->name), "%s", name);
    dev->id_flags &= ~DV_F_DEV_MASK ;
    dev->id_flags |= (d->bd_id << DV_F_DEV_SHIFT) & DV_F_DEV_MASK ;
    return 1;
}


/*
 * mss_reinit resets registers of the codec
 */
static void
mss_reinit(snddev_info *d)
{
    u_char r;

    r = mss_speed(d) ;
    r |= (mss_format(d) << 5) ;
    if (d->flags & SND_F_STEREO)
	r |= 0x10 ;
    /* XXX check if MCE is necessary... */
    ad_enter_MCE(d);

    /*
     * perhaps this is not the place to set mode2, should be done
     * only once at attach time...
     */
    if ( FULL_DUPLEX(d) && d->bd_id != MD_OPTI931)
	/*
	 * set mode2 bit for dual dma op. This bit is not implemented
	 * on the OPTi931
	 */
	ad_write(d, 12, ad_read(d, 12) | 0x40 /* mode 2 on the CS42xx */ );

    /*
     * XXX this should really go into mss-speed...
     */
    if (d->bd_id == MD_AD1845) { /* Use alternate speed select regs */
	r &= 0xf0;	/* Mask off the rate select bits */

	ad_write(d, 22, (d->play_speed >> 8) & 0xff);	/* Speed MSB */
	ad_write(d, 23, d->play_speed & 0xff);	/* Speed LSB */
	/*
	 * XXX must also do something in I27 for the ad1845
	 */
    }

    ad_write(d, 8, r) ;
    if ( FULL_DUPLEX(d) ) {
#if 0
	if (d->bd_id == MD_GUSPNP && d->play_fmt == AFMT_MU_LAW) {
	    printf("warning, cannot do ulaw rec + play on the GUS\n");
	    r = 0 ; /* move to U8 */
	}
#endif
	ad_write(d, 28, r & 0xf0 ) ; /* capture mode */
	ad_write(d, 9, 0 /* no capture, no playback, dual dma */) ;
    } else
	ad_write(d, 9, 4 /* no capture, no playback, single dma */) ;
    ad_leave_MCE(d);
    /*
     * not sure if this is really needed...
     */
    ad_write_cnt(d, 14, 0 ); /* playback count */
    if ( FULL_DUPLEX(d) )
	ad_write_cnt(d, 30, 0 ); /* rec. count on dual dma */

    ad_write(d, 10, 2 /* int enable */) ;
    outb(io_Status(d), 0);	/* Clear interrupt status */
    /* the following seem required on the CS4232 */
    ad_write(d, 6, ad_read(d,6) & ~I6_MUTE);
    ad_write(d, 7, ad_read(d,7) & ~I6_MUTE);

    snd_set_blocksize(d); /* update blocksize if user did not force it */
}

/*
 * here we have support for PnP cards
 *
 */

#if NPNP > 0

static char * cs423x_probe(u_long csn, u_long vend_id);
static void 
cs423x_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev);

static struct pnp_device cs423x = {
    "CS423x/Yamaha/AD1816",
	cs423x_probe,
	cs423x_attach,
	&nsnd,	/* use this for all sound cards */
	&tty_imask	/* imask */
};
DATA_SET (pnpdevice_set, cs423x);

static char *
cs423x_probe(u_long csn, u_long vend_id)
{
    char *s = NULL ;
    u_long id = vend_id & 0xff00ffff;
    if ( id == 0x3700630e )
	s = "CS4237" ;
    else if ( id == 0x2500630e )
	s = "CS4235" ;
    else if ( id == 0x3600630e )
	s = "CS4236" ;
    else if ( id == 0x3500630e )
	s = "CS4236B" ;
    else if ( id == 0x3200630e)
	s = "CS4232" ;
    else if ( id == 0x2000a865)
	s = "Yamaha SA2";
    else if ( id == 0x3000a865)
	s = "Yamaha SA3";
    else if (vend_id == 0x0000a865)
	s = "Yamaha YMF719 OPL-SA3";
    else if (vend_id == 0x8140d315)
	s = "SoundscapeVIVO";
    else if (vend_id == 0x1114b250)
	s = "Terratec Soundsystem BASE 1";
    else if (vend_id == 0x50719304)
	s = "Generic AD1815";
    if (s) {
	struct pnp_cinfo d;
	read_pnp_parms(&d, 0);
	if (d.enable == 0) {
	    printf("This is a %s, but LDN 0 is disabled\n", s);
	    return NULL ;
	}
	return s;
    }

    return NULL ;
}

extern snddev_info sb_op_desc;

static void
cs423x_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev)
{
    struct pnp_cinfo d ;
    snddev_info tmp_d ; /* patched copy of the basic snddev_info */
    int ldn = 0 ;

    if (read_pnp_parms ( &d , ldn ) == 0 ) {
	printf("failed to read pnp parms\n");
	return ;
    }
    snddev_last_probed = &tmp_d;

    /* AD1816 */
    if (vend_id == 0x1114b250 || vend_id == 0x50719304) {
	dev->id_alive = 16;	/* number of io ports ? */

	tmp_d = mss_op_desc;	/* copy it */

	tmp_d.ioctl = ad1816_ioctl;
	tmp_d.isr = ad1816_intr;
	tmp_d.callback = ad1816_callback;
	tmp_d.audio_fmt = AFMT_STEREO | AFMT_U8 |
	    AFMT_A_LAW | AFMT_MU_LAW |
	    AFMT_S16_LE | AFMT_S16_BE;

	dev->id_iobase = d.port[2];
	tmp_d.alt_base = d.port[0];	/* soundblaster comp. but we don't
					 * use that */
	tmp_d.bd_id = MD_AD1816;
	strcpy(tmp_d.name, name);
    } else if (d.flags & DV_PNP_SBCODEC) { /* use sb-compatible codec */
	dev->id_alive = 16 ; /* number of io ports ? */
	tmp_d = sb_op_desc ;
	if (vend_id==0x2000a865 || vend_id==0x3000a865 ||
	    vend_id==0x0008a865 || vend_id==0x8140d315) {
	    /* Yamaha SA2/SA3 or ENSONIQ SoundscapeVIVO ENS4081 */
	    dev->id_iobase = d.port[0] ;
	    tmp_d.alt_base = d.port[1] ;
	    d.irq[1] = 0 ; /* only needed for the VIVO */
	} else {
	    dev->id_iobase = d.port[2] ;
	    tmp_d.alt_base = d.port[0] - 4;
	}
	d.drq[1] = 4 ; /* disable, it is not used ... */
    } else {			/* mss-compatible codec */
	dev->id_alive = 8 ; /* number of io ports ? */
	tmp_d = mss_op_desc ;
	dev->id_iobase = d.port[0] -4 ; /* XXX old mss have 4 bytes before... */
	tmp_d.alt_base = d.port[2];
	switch (vend_id & 0xff00ffff) {

	case 0x2000a865:	/* Yamaha SA2 */
	case 0x3000a865:	/* Yamaha SA3 */
	case 0x0000a865:	/* Yamaha TMF719 SA3 */
	    dev->id_iobase = d.port[1];
	    tmp_d.alt_base = d.port[0];
	    tmp_d.conf_base = d.port[4];
	    tmp_d.bd_id = MD_YM0020 ;
	    break;

	case 0x8100d315:	/* ENSONIQ SoundscapeVIVO */
	    dev->id_iobase = d.port[1];
	    tmp_d.alt_base = d.port[0];
	    tmp_d.bd_id = MD_VIVO ;
	    d.irq[1] = 0 ;
	    break;

	case 0x3700630e:        /* CS4237 */
	    tmp_d.bd_id = MD_CS4237 ;
	    break;

	case 0x2500630e:	/* AOpen AW37, CS4235 */
	    tmp_d.bd_id = MD_CS4237 ;
	    break ;

	case 0x3500630e:        /* CS4236B */
	case 0x3600630e:        /* CS4236 */
	    tmp_d.bd_id = MD_CS4236 ;
	    break;

        default:
		tmp_d.bd_id = MD_CS4232;	/* to short-circuit the
						 * detect routine */
	    break;
	}
	snprintf(tmp_d.name, sizeof(tmp_d.name), "%s", name);
	tmp_d.audio_fmt |= AFMT_FULLDUPLEX ;
    }

    write_pnp_parms( &d, ldn );
    enable_pnp_card();

    if ( (vend_id & 0x0000ffff) == 0x0000a865 ) {
	/* special volume setting for the Yamaha... */
	outb(tmp_d.conf_base, 7 /* volume, left */);
	outb(tmp_d.conf_base+1, 0 );
	outb(tmp_d.conf_base, 8 /* volume, right */);
	outb(tmp_d.conf_base+1, 0 );
    }
    dev->id_drq = d.drq[0] ; /* primary dma */
    dev->id_irq = (1 << d.irq[0] ) ;
    dev->id_intr = pcmintr ;
    dev->id_flags = DV_F_DUAL_DMA | (d.drq[1] ) ;

    tmp_d.synth_base = d.port[1]; /* XXX check this for yamaha */
    pcmattach(dev);
}

static char *opti931_probe(u_long csn, u_long vend_id);
static void opti931_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev);
static struct pnp_device opti931 = {
	"OPTi931",
	opti931_probe,
	opti931_attach,
	&nsnd,	/* use this for all sound cards */
	&tty_imask	/* imask */
};
DATA_SET (pnpdevice_set, opti931);

static char *
opti931_probe(u_long csn, u_long vend_id)
{
    if (vend_id == 0x3109143e) {
	struct pnp_cinfo d;
	read_pnp_parms(&d, 1);
	if (d.enable == 0) {
	    printf("This is an OPTi931, but LDN 1 is disabled\n");
	    return NULL ;
	}
	return "OPTi931" ;
    }
    return NULL ;
}

static void
opti931_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev)
{
    struct pnp_cinfo d ;
    snddev_info tmp_d ; /* patched copy of the basic snddev_info */
    int p;

    read_pnp_parms ( &d , 3 ); /* free resources taken by LDN 3 */
    d.irq[0]=0; /* free irq... */
    d.port[0]=0; /* free address... */
    d.enable = 0 ;
    write_pnp_parms ( &d , 3 );

    read_pnp_parms ( &d , 2 ); /* disable LDN 2 */
    d.enable = 0 ;
    write_pnp_parms ( &d , 2 );

    read_pnp_parms ( &d , 1 ) ;
    write_pnp_parms( &d, 1 );
    enable_pnp_card();

    snddev_last_probed = &tmp_d;
    tmp_d =  d.flags & DV_PNP_SBCODEC ? sb_op_desc : mss_op_desc ;

    snprintf(tmp_d.name, sizeof(tmp_d.name), "%s", name);

    /*
     * My MED3931 v.1.0 allocates 3 bytes for the config space,
     * whereas v.2.0 allocates 4 bytes. What I know for sure is that the
     * upper two ports must be used, and they should end on a boundary
     * of 4 bytes. So I need the following trick...
     */
    p = tmp_d.conf_base = (d.port[3] & ~3) + 2; /* config port */

    /*
     * now set default values for both modes.
     */
    dev->id_iobase = d.port[0] - 4 ; /* old mss have 4 bytes before... */
    tmp_d.io_base = dev->id_iobase; /* needed for ad_write to work... */
    tmp_d.alt_base = d.port[2];
    tmp_d.synth_base = d.port[1];
    opti_write(p, 4, 0xd6 /* fifo empty, OPL3, audio enable, SB3.2 */ );
    ad_write (&tmp_d, 10, 2); /* enable interrupts */

    if (d.flags & DV_PNP_SBCODEC) { /* sb-compatible codec */
	/*
	 * the 931 is not a real SB, it has important pieces of
	 * hardware controlled by both the MSS and the SB port...
	 */
	printf("--- opti931 in sb mode ---\n");
	opti_write(p, 6, 1); /* MCIR6 mss disable, sb enable */
	/*
	 * swap the main and alternate iobase address since we want
	 * to work in sb mode.
	 */
	dev->id_iobase = d.port[2] ;
	tmp_d.alt_base = d.port[0] - 4;
	dev->id_flags = DV_F_DUAL_DMA | d.drq[1] ;
    } else { /* mss-compatible codec */
	tmp_d.bd_id = MD_OPTI931 ; /* to short-circuit the detect routine */
	opti_write(p, 6 , 2);  /* MCIR6: mss enable, sb disable */
	opti_write(p, 5, 0x28);  /* MCIR5: codec in exp. mode,fifo */
	dev->id_flags = DV_F_DUAL_DMA | d.drq[1] ;
	tmp_d.audio_fmt |= AFMT_FULLDUPLEX ; /* not really well... */
	tmp_d.isr = opti931_intr;
    }
    dev->id_drq = d.drq[0] ; /* primary dma */
    dev->id_irq = (1 << d.irq[0] ) ;
    dev->id_intr = pcmintr ;
    pcmattach(dev);
}

static char *opti925_probe(u_long csn, u_long vend_id);
static void opti925_attach(u_long csn, u_long vend_id, char *name,
        struct isa_device *dev);
    
static struct pnp_device opti925 = {
        "opti925",
        opti925_probe,
        opti925_attach,
        &nsnd,  /* use this for all sound cards */
        &tty_imask      /* imask */ 
};  
DATA_SET (pnpdevice_set, opti925);
    
static char *
opti925_probe(u_long csn, u_long vend_id)
{
    if (vend_id == 0x2509143e) {
        struct pnp_cinfo d ;
        read_pnp_parms ( &d , 1 ) ;
        if (d.enable == 0) {
            printf("This is an OPTi925, but LDN 1 is disabled\n");
            return NULL;
        }
        return "OPTi925" ;
    }
    return NULL ;
}  

static void 
opti925_attach(u_long csn, u_long vend_id, char *name, 
        struct isa_device *dev) 
{
    struct pnp_cinfo d ; 
    snddev_info tmp_d ; /* patched copy of the basic snddev_info */
    int the_irq = 0 ; 

    tmp_d = mss_op_desc;
    snddev_last_probed = &tmp_d; 
  
    read_pnp_parms ( &d , 3 );  /* disable LDN 3 */
    the_irq = d.irq[0];
    d.port[0] = 0 ;
    d.enable = 0 ;
    write_pnp_parms ( &d , 3 );

    read_pnp_parms ( &d , 2 ); /* disable LDN 2 */
    d.port[0] = 0 ;
    d.enable = 0 ; 
    write_pnp_parms ( &d , 2 );

    read_pnp_parms ( &d , 1 ) ;
    d.irq[0] = the_irq ;
    dev->id_iobase = d.port[1];
    tmp_d.alt_base = d.port[0];  
    write_pnp_parms ( &d , 1 );
    enable_pnp_card();

    tmp_d.conf_base = d.port[3];

    dev->id_drq = d.drq[0] ; /* primary dma */
    dev->id_irq = (1 << d.irq[0] ) ;
    dev->id_intr = pcmintr ;
    dev->id_flags = DV_F_DUAL_DMA | d.drq[1] ;
    tmp_d.audio_fmt |= AFMT_FULLDUPLEX ;

    snddev_last_probed->probe(dev); /* not really necessary but doesn't harm */
 
    pcmattach(dev);
}

#if 0
static void gus_mem_cfg(snddev_info *tmp);
#endif

static char *guspnp_probe(u_long csn, u_long vend_id);
static void guspnp_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev);
static struct pnp_device guspnp = {
	"GusPnP",
	guspnp_probe,
	guspnp_attach,
	&nsnd,	/* use this for all sound cards */
	&tty_imask	/* imask */
};
DATA_SET (pnpdevice_set, guspnp);

static char *
guspnp_probe(u_long csn, u_long vend_id)
{
    if (vend_id == 0x0100561e) {
	struct pnp_cinfo d;
	read_pnp_parms(&d, 0);
	if (d.enable == 0) {
	    printf("This is a GusPnP, but LDN 0 is disabled\n");
	    return NULL ;
	}
	return "GusPnP" ;
    }
    return NULL ;
}

static void
guspnp_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev)
{
    struct pnp_cinfo d ;
    snddev_info tmp_d ; /* patched copy of the basic snddev_info */

    u_char tmp;

    read_pnp_parms ( &d , 0 ) ;

    /* d.irq[1] = d.irq[0] ; */
    pnp_write ( 0xf2, 0xff ); /* enable power on the guspnp */

    write_pnp_parms ( &d , 0 );
    enable_pnp_card();

    tmp_d = mss_op_desc ;
    snddev_last_probed = &tmp_d;

    dev->id_iobase = d.port[2] - 4 ; /* room for 4 mss registers */
    dev->id_drq = d.drq[1] ; /* XXX PLAY dma */
    dev->id_irq = (1 << d.irq[0] ) ;
    dev->id_intr = pcmintr ;
    dev->id_flags = DV_F_DUAL_DMA | d.drq[0]  ; /* REC dma */

    tmp_d.io_base = d.port[2] - 4;
    tmp_d.alt_base = d.port[0]; /* 0x220 */
    tmp_d.conf_base = d.port[1];  /* gus control block... */
    tmp_d.bd_id = MD_GUSPNP ;

    /* reset */
    gus_write(tmp_d.conf_base, 0x4c /* _URSTI */, 0 );/* Pull reset */
    DELAY(1000 * 30);
    /* release reset  and enable DAC */
    gus_write(tmp_d.conf_base, 0x4c /* _URSTI */, 3 );
    DELAY(1000 * 30);
    /* end of reset */

    outb( tmp_d.alt_base, 0xC ); /* enable int and dma */

    /*
     * unmute left & right line. Need to go in mode3, unmute,
     * and back to mode 2
     */
    tmp = ad_read(&tmp_d, 0x0c);
    ad_write(&tmp_d, 0x0c, 0x6c ); /* special value to enter mode 3 */
    ad_write(&tmp_d, 0x19, 0 ); /* unmute left */
    ad_write(&tmp_d, 0x1b, 0 ); /* unmute right */
    ad_write(&tmp_d, 0x0c, tmp ); /* restore old mode */

    /* send codec interrupts on irq1 and only use that one */
    gus_write(tmp_d.conf_base, 0x5a , 0x4f );

    /* enable access to hidden regs */
    tmp = gus_read(tmp_d.conf_base, 0x5b /* IVERI */ );
    gus_write(tmp_d.conf_base, 0x5b , tmp | 1 );
    BVDDB(printf("GUS: silicon rev %c\n", 'A' + ( ( tmp & 0xf ) >> 4) );)

    snprintf(tmp_d.name, sizeof(tmp_d.name), "%s", name);

    pcmattach(dev);
}

#if 0
int
gus_mem_write(snddev_info *d, int addr, u_char data)
{
    gus_writew(d->conf_base, 0x43 , addr & 0xffff );
    gus_write(d->conf_base, 0x44 , (addr>>16) & 0xff );
    outb(d->conf_base + 7, data);
}

u_char
gus_mem_read(snddev_info *d, int addr)
{
    gus_writew(d->conf_base, 0x43 , addr & 0xffff );
    gus_write(d->conf_base, 0x44 , (addr>>16) & 0xff );
    return inb(d->conf_base + 7);
}

void
gus_mem_cfg(snddev_info *d)
{
    int base;
    u_char old;
    u_char a, b;

    printf("configuring gus memory...\n");
    gus_writew(d->conf_base, 0x52 /* LMCFI */, 1 /* 512K*/);
    old = gus_read(d->conf_base, 0x19);
    gus_write(d->conf_base, 0x19, old | 1); /* enable enhaced mode */
    for (base = 0; base < 1024; base++) {
	a=gus_mem_read(d, base*1024);
	a = ~a ;
	gus_mem_write(d, base*1024, a);
	b=gus_mem_read(d, base*1024);
	if ( b != a )
		break ;
    }
    printf("Have found %d KB ( 0x%x != 0x%x)\n", base, a, b);
}
#endif /* gus mem cfg... */

static int
ad1816_ioctl(dev_t dev, u_long cmd, caddr_t arg, int mode, struct proc * p)
{
    snddev_info    *d;
    int             unit;

    dev = minor(dev);
    unit = dev >> 4;
    d = &pcm_info[unit];

    if ((cmd & MIXER_WRITE(0)) == MIXER_WRITE(0)) {
	cmd &= 0xff;
	if (cmd == SOUND_MIXER_RECSRC)
	    return ad1816_set_recsrc(d, *(int *) arg);
	else
	    return ad1816_mixer_set(d, cmd, *(int *) arg);
    }
    switch (cmd) {		/* driver specific ioctls other than mixer
				 * calls */
	/* ad1816 has special features */
    case AIOGCAP:		/* get capabilities */
	{
	    snd_capabilities *p = (snd_capabilities *) arg;
	    p->rate_min = 4000;
	    p->rate_max = 55200;
	    p->bufsize = d->bufsize;
	    p->formats = d->audio_fmt;
	    p->mixers = 1;
	    p->inputs = d->mix_devs;
	    p->left = p->right = 100;
	    return 0;
	}
    default:
	{
	    return ENOSYS;	/* fallback to default */
	}
	break;
    }
}

static int
ad1816_callback(snddev_info * d, int reason)
{
    int             wr, cnt;

    wr = reason & SND_CB_WR;
    reason &= SND_CB_REASON_MASK;

    switch (reason) {
    case SND_CB_INIT:
	ad1816_reinit(d);
	reset_dbuf(&(d->dbuf_in), SND_CHAN_RD);
	reset_dbuf(&(d->dbuf_out), SND_CHAN_WR);
	return 1;
	break;

    case SND_CB_START:
	cnt = wr ? d->dbuf_out.dl : d->dbuf_in.dl;

	cnt /= 4;
	cnt--;

	/* start only if not already running */
	if (wr && !(inb(ad1816_play(d)) & AD1816_ENABLE)) {
	    /* set dma counter */
	    ad1816_write(d, 8, cnt);	/* playback count */
	    /* int enable */
	    ad1816_write(d, 1, ad1816_read(d, 1) | 0x8000);
	    /* enable playback */
	    outb(ad1816_play(d), (inb(ad1816_play(d)) | AD1816_ENABLE));
	    /* check if we succeeded */
	    if (!(inb(ad1816_play(d)) & AD1816_ENABLE)) {
		printf("ad1816: failed to start write (playback) DMA !\n");
	    }
	} else if (!wr && !(inb(ad1816_capt(d)) & AD1816_ENABLE)) {
	    /* same for capture */
	    ad1816_write(d, 10, cnt);	/* capture count */
	    ad1816_write(d, 1, ad1816_read(d, 1) | 0x4000);	/* int */
	    outb(ad1816_capt(d), (inb(ad1816_capt(d)) | AD1816_ENABLE));	/* CEN */
	    if (!(inb(ad1816_capt(d)) & AD1816_ENABLE)) {	/* check */
		printf("ad1816: failed to start read (capture) DMA !\n");
	    }
	}
	break;

    case SND_CB_STOP:
    case SND_CB_ABORT:		/* XXX check this... */
	/* we don't test here if it is running... */
	if (wr) {
	    ad1816_write(d, 1, ad1816_read(d, 1) & ~0x8000);
	    /* disable int */
	    outb(ad1816_play(d), (inb(ad1816_play(d)) & ~AD1816_ENABLE));
	    /* disable playback */
	    if ((inb(ad1816_play(d)) & AD1816_ENABLE)) {
		printf("ad1816: failed to stop write (playback) DMA !\n");
	    }
	    ad1816_write(d, 8, 0);	/* reset base counter */
	    ad1816_write(d, 9, 0);	/* reset cur counter */
	} else {
	    /* same for capture */
	    ad1816_write(d, 1, ad1816_read(d, 1) & ~0x4000);
	    outb(ad1816_capt(d), (inb(ad1816_capt(d)) & ~AD1816_ENABLE));
	    if ((inb(ad1816_capt(d)) & AD1816_ENABLE)) {
		printf("ad1816: failed to stop read (capture) DMA !\n");
	    }
	    ad1816_write(d, 10, 0);
	    ad1816_write(d, 11, 0);
	}
	break;
    }

    return 0;
}

static void
ad1816_intr(int unit)
{
    snddev_info    *d = &pcm_info[unit];
    unsigned char   c, served = 0;

    /* get interupt status */
    c = inb(ad1816_int(d));

    /* check for stray interupts */
    if (c & ~(AD1816_INTRCI | AD1816_INTRPI)) {
	printf("ad1816: Stray interrupt 0x%x.\n", c);
	c = c & (AD1816_INTRCI | AD1816_INTRPI);
	outb(ad1816_int(d), c);	/* ack it anyway */
    }
    /* check for capture interupt */
    if (d->dbuf_in.dl && (c & AD1816_INTRCI)) {
	outb(ad1816_int(d), c & ~AD1816_INTRCI);	/* ack it */
	if (inb(ad1816_int(d)) & AD1816_INTRCI)
	    printf("ad1816: Failed to clear cp int !!!\n");
	dsp_rdintr(d);
	served |= AD1816_INTRCI;		/* cp served */
    }
    /* check for playback interupt */
    if (d->dbuf_out.dl && (c & AD1816_INTRPI)) {
	outb(ad1816_int(d), c & ~AD1816_INTRPI);	/* ack it */
	if (inb(ad1816_int(d)) & AD1816_INTRPI != 0)
	    printf("ad1816: Failed to clear pb int !!!\n");
	dsp_wrintr(d);
	served |= AD1816_INTRPI;		/* pb served */
    }
    if (served == 0) {
	/* this probably means this is not a (working) ad1816 chip, */
	/* or an error in dma handling                              */
	printf("ad1816: raised an interrupt without reason 0x%x.\n", c);
	outb(ad1816_int(d), 0);	/* Clear interrupt status anyway */
    }
}

static int
ad1816_wait_init(snddev_info * d, int x)
{
    int             n = 0;	/* to shut up the compiler... */

    for (; x--;)
	if (((n = (inb(ad1816_ale(d)) & AD1816_BUSY))) == 0)
	    DELAY(10);
	else
	    return n;
    printf("ad1816_wait_init failed 0x%02x.\n", inb(ad1816_ale(d)));
    return n;
}

static unsigned short
ad1816_read(snddev_info * d, unsigned int reg)
{
    int             flags;
    u_short         x;

    /* we don't want to be blocked here */
    flags = spltty();
    if (ad1816_wait_init(d, 100) == 0) {
	printf("ad1816_read: chip timeout before read.\n");
	return 0;
    }
    outb(ad1816_ale(d), (u_char) 0);
    outb(ad1816_ale(d), (u_char) (reg & AD1816_ALEMASK));
    if (ad1816_wait_init(d, 100) == 0) {
	printf("ad1816_read: chip timeout during read.\n");
	return 0;
    }
    x = (inb(ad1816_high(d)) << 8) | inb(ad1816_low(d));
    splx(flags);
    return x;
}

static void
ad1816_write(snddev_info * d, unsigned int reg, unsigned short data)
{
    int             flags;

    flags = spltty();
    if (ad1816_wait_init(d, 100) == 0) {
	printf("ad1816_write: chip timeout before write.\n");
	return;
    }
    outb(ad1816_ale(d), (u_char) (reg & AD1816_ALEMASK));
    outb(ad1816_low(d), (u_char) (data & 0x000000ff));
    outb(ad1816_high(d), (u_char) ((data & 0x0000ff00) >> 8));
    splx(flags);
}

#if 0				/* unused right now..., and untested... */
static void
ad1816_mute(snddev_info * d)
{
    ad1816_write(d, 14, ad1816_read(d, 14) | 0x8000 | 0x80);
}

static void
ad1816_unmute(snddev_info * d)
{
    ad1816_write(d, 14, ad1816_read(d, 14) & ~(0x8000 | 0x80));
}
#endif

/* only one rec source is possible */

static int
ad1816_set_recsrc(snddev_info * d, int mask)
{
    mask &= d->mix_rec_devs;

    switch (mask) {
    case SOUND_MASK_LINE:
    case SOUND_MASK_LINE3:
	ad1816_write(d, 20, (ad1816_read(d, 20) & ~0x7070) | 0x0000);
	break;

    case SOUND_MASK_CD:
    case SOUND_MASK_LINE1:
	ad1816_write(d, 20, (ad1816_read(d, 20) & ~0x7070) | 0x2020);
	break;

    case SOUND_MASK_MIC:
    default:
	ad1816_write(d, 20, (ad1816_read(d, 20) & ~0x7070) | 0x5050);
    }

    d->mix_recsrc = mask;

    return 0;			/* success */
}

#define AD1816_MUTE 31		/* value for mute */

static int
ad1816_mixer_set(snddev_info * d, int dev, int value)
{
    u_char          left = (value & 0x000000ff);
    u_char          right = (value & 0x0000ff00) >> 8;
    u_short         reg = 0;

    if (dev > 31)
	return EINVAL;

    if (!(d->mix_devs & (1 << dev)))
	return EINVAL;

    if (left > 100)
	left = 100;
    if (right > 100)
	right = 100;

    d->mix_levels[dev] = left | (right << 8);

    /* Scale volumes */
    left = AD1816_MUTE - (AD1816_MUTE * left) / 100;
    right = AD1816_MUTE - (AD1816_MUTE * right) / 100;

    reg = (left << 8) | right;

    /* do channel selective muting if volume is zero */
    if (left == AD1816_MUTE)
	reg |= 0x8000;
    if (right == AD1816_MUTE)
	reg |= 0x0080;

    switch (dev) {
    case SOUND_MIXER_VOLUME:	/* Register 14 master volume */
	ad1816_write(d, 14, reg);
	break;
    case SOUND_MIXER_CD:	/* Register 15 cd */
    case SOUND_MIXER_LINE1:
	ad1816_write(d, 15, reg);
	break;
    case SOUND_MIXER_SYNTH:	/* Register 16 synth */
	ad1816_write(d, 16, reg);
	break;
    case SOUND_MIXER_PCM:	/* Register 4 pcm */
	ad1816_write(d, 4, reg);
	break;
    case SOUND_MIXER_LINE:
    case SOUND_MIXER_LINE3:	/* Register 18 line in */
	ad1816_write(d, 18, reg);
	break;
    case SOUND_MIXER_MIC:	/* Register 19 mic volume */
	ad1816_write(d, 19, reg & ~0xff);	/* mic is mono */
	break;
    case SOUND_MIXER_IGAIN:
	/* and now to something completely different ... */
	ad1816_write(d, 20, ((ad1816_read(d, 20) & ~0x0f0f)
	      | (((AD1816_MUTE - left) / 2) << 8) /* four bits of adc gain */
	      | ((AD1816_MUTE - right) / 2)));
	break;
    default:
	printf("ad1816_mixer_set(): unknown device.\n");
	break;
    }

    return 0;			/* success */
}

static void
ad1816_mixer_reset(snddev_info * d)
{
    int             i;

    d->mix_devs = AD1816_MIXER_DEVICES;
    d->mix_rec_devs = AD1816_REC_DEVICES;

    for (i = 0; i < SOUND_MIXER_NRDEVICES; i++)
	if (d->mix_devs & (1 << i))
	    ad1816_mixer_set(d, i, default_mixer_levels[i]);
    ad1816_set_recsrc(d, SOUND_MASK_MIC);
}

/* Set the playback and capture rates. */

static int
ad1816_speed(snddev_info * d)
{
    RANGE(d->play_speed,4000,55200);
    RANGE(d->rec_speed,4000,55200);

    ad1816_write(d, 2, d->play_speed);
    ad1816_write(d, 3, d->rec_speed);

    return d->play_speed;
}

/*
 * ad1816_format checks that the format is supported (or defaults to AFMT_U8)
 * and sets the chip to the desired format.
 */

static int
ad1816_format(snddev_info * d)
{
    int oldplay =inb(ad1816_play(d)) & ~AD1816_FORMASK;
    int oldrec = inb(ad1816_capt(d)) & ~AD1816_FORMASK;
    int play = (d->play_fmt & d->audio_fmt) ? d->play_fmt : AFMT_U8;
    int rec =  (d->rec_fmt  & d->audio_fmt) ? d->rec_fmt : AFMT_U8;

    /*
     * check that arg is one of the supported formats in d->format; otherwise
     * fallback to AFMT_U8
     */

    switch (play) {
    case AFMT_A_LAW:
	outb(ad1816_play(d), oldplay | AD1816_ALAW);
	break;
    case AFMT_MU_LAW:
	outb(ad1816_play(d), oldplay | AD1816_MULAW);
	break;
    case AFMT_S16_LE:
	outb(ad1816_play(d), oldplay | AD1816_S16LE);
	break;
    case AFMT_S16_BE:
	outb(ad1816_play(d), oldplay | AD1816_S16BE);
	break;
    default:
	/* unlikely to happen */
	printf("ad1816: unknown play format. defaulting to U8.\n");
    case AFMT_U8:
	outb(ad1816_play(d), oldplay | AD1816_U8);
	break;
    }

    switch (rec) {
    case AFMT_A_LAW:
	outb(ad1816_capt(d), oldrec | AD1816_ALAW);
	break;
    case AFMT_MU_LAW:
	outb(ad1816_capt(d), oldrec | AD1816_MULAW);
	break;
    case AFMT_S16_LE:
	outb(ad1816_capt(d), oldrec | AD1816_S16LE);
	break;
    case AFMT_S16_BE:
	outb(ad1816_capt(d), oldrec | AD1816_S16BE);
	break;
    default:
	printf("ad1816: unknown capture format. defaulting to U8.\n");
    case AFMT_U8:
	outb(ad1816_capt(d), oldrec | AD1816_U8);
	break;
    }

    d->play_fmt = play;
    d->rec_fmt = rec;

    return (play);
}

/*
 * ad1816_reinit resets codec registers
 */
static void
ad1816_reinit(snddev_info * d)
{
    ad1816_write(d, 8, 0x0000);	/* reset base and current counter */
    ad1816_write(d, 9, 0x0000);	/* for playback and capture */
    ad1816_write(d, 10, 0x0000);
    ad1816_write(d, 11, 0x0000);

    if (d->flags & SND_F_STEREO) {
	outb((ad1816_play(d)), AD1816_STEREO);	/* set playback to stereo */
	outb((ad1816_capt(d)), AD1816_STEREO);	/* set capture to stereo */
    } else {
	outb((ad1816_play(d)), 0x00);	/* set playback to mono */
	outb((ad1816_capt(d)), 0x00);	/* set capture to mono */
    }

    ad1816_format(d);
    ad1816_speed(d);

    snd_set_blocksize(d);	/* update blocksize if user did not force it */
}

#endif	/* NPNP > 0 */
#endif /* NPCM > 0 */
