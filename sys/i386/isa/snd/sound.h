/*
 * sound.h
 *
 * include file for kernel sources, sound driver.
 * 
 * Copyright by Hannu Savolainen 1995
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
 */

#ifdef KERNEL
#include "pcm.h"
#else
#define NPCM 1
#endif
#if NPCM > 0

/*
 * first, include kernel header files.
 */

#ifndef _OS_H_
#define _OS_H_

#ifdef KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioccom.h>

#include <sys/filio.h>
#include <sys/sockio.h>
#include <sys/fcntl.h>
#include <sys/tty.h>
#include <sys/proc.h>

#include <sys/kernel.h> /* for DATA_SET */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <i386/isa/isa_device.h>
#include <machine/clock.h>	/* for DELAY */

/* To minimize changes with the code in 2.2.X */
#include <sys/poll.h>
#define d_select_t d_poll_t

#else
struct isa_device { int dummy ; } ;
#define d_open_t void
#define d_close_t void
#define d_read_t void
#define d_write_t void
#define d_ioctl_t void
#define d_select_t void
#endif /* KERNEL */
typedef void    (irq_proc_t) (int irq);

#endif	/* _OS_H_ */

/*      
 * descriptor of a dma buffer. See dmabuf.c for documentation.
 * (rp,rl) and (fp,fl) identify the READY and FREE regions of the
 * buffer. dl contains the length used for dma transfer, dl>0 also
 * means that the channel is busy and there is a DMA transfer in progress.
 */     
        
typedef struct _snd_dbuf {
        char *buf;
        int     bufsize ;
        volatile int rp, fp; /* pointers to the ready and free area */
        volatile int dl; /* transfer size */
	volatile int rl, fl; /* lenght of ready and free areas. */
	int int_count;
	int chan;       /* dma channel */
	int sample_size ; /* 1, 2, 4 */
	struct selinfo sel;
	u_long total;	/* total bytes processed */
	u_long prev_total; /* copy of the above when GETxPTR called */
} snd_dbuf ;

/*
 * descriptor of audio operations ...
 *
 */
typedef struct _snddev_info snddev_info ;
typedef int (snd_callback_t)(snddev_info *d, int reason);

struct _snddev_info {

    /*
     * the first part of the descriptor is filled up from a
     * template.
     */
    char name[64];

    int type ;

    int (*probe)(struct isa_device * dev);
    int (*attach)(struct isa_device * dev) ;
    d_open_t *open ;
    d_close_t *close ;
    d_read_t *read ;
    d_write_t *write ;
    d_ioctl_t *ioctl ;
    d_select_t *select ;
    irq_proc_t  *isr ;
    snd_callback_t *callback;

    int     bufsize;        /* space used for buffers */

    u_long  audio_fmt ;     /* supported audio formats */


    /*
     * combinations of the following flags are used as second argument in
     * the callback from the dma module to the device-specific routines.
     */

#define SND_CB_RD       0x100   /* read callback */
#define SND_CB_WR       0x200   /* write callback */
#define SND_CB_REASON_MASK      0xff
#define SND_CB_START    0x01   /* start dma op */
#define SND_CB_STOP     0x03   /* stop dma op */
#define SND_CB_ABORT    0x04   /* abort dma op */
#define SND_CB_INIT     0x05   /* init board parameters */
	/* init can only be called with int enabled and
	 * no pending DMA activity.
	 */

    /*
     * whereas from here, parameters are set at runtime.
     * io_base == 0 means that the board is not configured.
     */

    int     io_base ;	/* primary I/O address for the board */
    int     alt_base ; /* some codecs are accessible as SB+WSS... */
    int     conf_base ; /* and the opti931 also has a config space */
    int     mix_base ; /* base for the mixer... */
    int     midi_base ; /* base for the midi */

    int     irq ;
    int bd_id ;     /* used to hold board-id info, eg. sb version,
		     * mss codec type, etc. etc.
		     */

    snd_dbuf dbuf_out, dbuf_in;

    int     status_ptr;     /* used to implement sndstat */

        /*
         * these parameters describe the operation of the board.
         * Generic things like busy flag, speed, etc are here.
         */

    volatile u_long  flags ;     /* 32 bits, used for various purposes. */

    /*
     * we have separate flags for read and write, although in some
     * cases this is probably not necessary (e.g. because we cannot
     * know how many processes are using the device, we cannot
     * distinguish if open, close, abort are for a write or for a
     * read).
     */

    /*
     * the following flag is used by open-close routines
     * to mark the status of the device.
     */
#define SND_F_BUSY              0x0001  /* has been opened 	*/
    /*
     * Only the last close for a device will propagate to the driver.
     * Unfortunately, voxware uses 3 different minor numbers
     * (dsp, dsp16 and audio) to access the same unit. So, if
     * we want to support multiple opens and still keep track of
     * what is happening, we also need a separate flag for each minor
     * number. These are below...
     */
#define	SND_F_BUSY_AUDIO	0x10000000
#define	SND_F_BUSY_DSP		0x20000000
#define	SND_F_BUSY_DSP16	0x40000000
#define	SND_F_BUSY_ANY		0x70000000
#define	SND_F_BUSY_SYNTH	0x80000000
    /*
     * the next two are used to allow only one pending operation of
     * each type.
     */
#define SND_F_READING           0x0004  /* have a pending read */
#define SND_F_WRITING           0x0008  /* have a pending write */
    /*
     * these mark pending DMA operations. When you have pending dma ops,
     * you might get interrupts, so some manipulations of the
     * descriptors must be done with interrupts blocked.
     */
#if 0
#define SND_F_RD_DMA            0x0010  /* read-dma active */
#define SND_F_WR_DMA            0x0020  /* write-dma active */

#define	SND_F_PENDING_IN	(SND_F_READING | SND_F_RD_DMA)
#define	SND_F_PENDING_OUT	(SND_F_WRITING | SND_F_WR_DMA)
#endif
#define	SND_F_PENDING_IO	(SND_F_READING | SND_F_WRITING)

    /*
     * flag used to mark a pending close.
     */
#define SND_F_CLOSING           0x0040  /* a pending close */

    /*
     * if user has not set block size, then make it adaptive
     * (0.25s, or the perhaps last read/write ?)
     */
#define	SND_F_HAS_SIZE		0x0080	/* user set block size */
    /*
     * assorted flags related to operating mode.
     */
#define SND_F_STEREO            0x0100	/* doing stereo */
#define SND_F_NBIO              0x0200	/* do non-blocking i/o */

    /*
     * the user requested ulaw, but the board does not support it
     * natively, so a (software) format conversion is necessary.
     * The kernel is not really the place to do this, but since
     * many applications expect to use /dev/audio , we do it for
     * portability.
     */
#define SND_F_XLAT8             0x0400  /* u-law <--> 8-bit unsigned */
#define SND_F_XLAT16            0x0800  /* u-law <--> 16-bit signed */

    /*
     * these flags mark a pending abort on a r/w operation.
     */
#define SND_F_ABORTING          0x1000  /* a pending abort */

    /*
     * this is used to mark that board initialization is needed, e.g.
     * because of a change in sampling rate, format, etc. -- It will
     * be done at the next convenient time.
     */
#define SND_F_INIT              0x4000  /* changed parameters. need init */

    u_long  bd_flags;       /* board-specific flags */
    int     play_speed, rec_speed;

    int     play_blocksize, rec_blocksize;  /* blocksize for io and dma ops */
    u_long  play_fmt, rec_fmt ;      /* current audio format */

    /*
     * mixer parameters
     */
    u_long  mix_devs;	/* existing devices for mixer */
    u_long  mix_rec_devs;	/* possible recording sources */
    u_long  mix_recsrc;	/* current recording source(s) */
    u_short mix_levels[32];

#define wsel dbuf_out.sel
#define rsel dbuf_in.sel
    u_long	interrupts;	/* counter of interrupts */
    u_long	magic;
#define	MAGIC(unit) ( 0xa4d10de0 + unit )
    int     synth_base ; /* base for the synth */
    int     synth_type ; /* type of synth */
    void    *device_data ;	/* just in case it is needed...*/
} ;

/*
 * then ioctls and other stuff
 */

#define NPCM_MAX	8	/* Number of supported devices */

/*
 * values used in bd_id for the mss boards
 */
#define MD_AD1848	0x91
#define MD_AD1845	0x92
#define MD_CS4248	0xA1
#define MD_CS4231	0xA2
#define MD_CS4231A	0xA3
#define MD_CS4232	0xA4
#define MD_CS4232A	0xA5
#define MD_CS4236	0xA6
#define MD_CS4237	0xA7
#define	MD_OPTI931	0xB1
#define	MD_GUSPNP	0xB8
#define	MD_YM0020	0xC1
#define	MD_VIVO		0xD1

/*
 * TODO: add some card classes rather than specific types.
 */
#include <machine/soundcard.h>
/*
 * many variables should be reduced to a range. Here define a macro
 */

#define RANGE(var, low, high) (var) = \
	((var)<(low)?(low) : (var)>(high)?(high) : (var))

/*
 * finally, all default parameters
 */
#define DSP_BUFFSIZE (65536 - 256) /* XXX */
/*
 * the last 256 bytes are room for buggy soundcard to overflow.
 */

#ifdef KERNEL
#include "pnp.h"
#if NPNP > 0
#include <i386/isa/pnp.h>	/* XXX pnp support */
#endif
#endif /* KERNEL */

/*
 * Minor numbers for the sound driver.
 *
 * Unfortunately Creative called the codec chip of SB as a DSP. For this
 * reason the /dev/dsp is reserved for digitized audio use. There is a
 * device for true DSP processors but it will be called something else.
 * In v3.0 it's /dev/sndproc but this could be a temporary solution.
 */


#define SND_DEV_CTL	0	/* Control port /dev/mixer */
#define SND_DEV_SEQ	1	/* Sequencer output /dev/sequencer (FM
				   synthesizer and MIDI output) */
#define SND_DEV_MIDIN	2	/* Raw midi access */
#define SND_DEV_DSP	3	/* Digitized voice /dev/dsp */
#define SND_DEV_AUDIO	4	/* Sparc compatible /dev/audio */
#define SND_DEV_DSP16	5	/* Like /dev/dsp but 16 bits/sample */
#define SND_DEV_STATUS	6	/* /dev/sndstat */
	/* #7 not in use now. Was in 2.4. Free for use after v3.0. */
#define SND_DEV_SEQ2	8	/* /dev/sequencer, level 2 interface */
#define SND_DEV_SNDPROC 9	/* /dev/sndproc for programmable devices */
#define SND_DEV_PSS	SND_DEV_SNDPROC

#define DSP_DEFAULT_SPEED	8000

#define ON		1
#define OFF		0


#define SYNTH_MAX_VOICES	32

struct voice_alloc_info {
	int max_voice;
	int used_voices;
	int ptr;		/* For device specific use */
	u_short map[SYNTH_MAX_VOICES]; /* (ch << 8) | (note+1) */
	int timestamp;
	int alloc_times[SYNTH_MAX_VOICES];
};

struct channel_info {
	int pgm_num;
	int bender_value;
	u_char controllers[128];
};

/*
 * mixer description structure and macros
 */

struct mixer_def {
    u_int    regno:7;
    u_int    polarity:1;	/* 1 means reversed */
    u_int    bitoffs:4;
    u_int    nbits:4;
};
typedef struct mixer_def mixer_ent;
typedef struct mixer_def mixer_tab[32][2];

#ifdef KERNEL

#define FULL_DUPLEX(d) (d->dbuf_out.chan != d->dbuf_in.chan)
#define MIX_ENT(name, reg_l, pol_l, pos_l, len_l, reg_r, pol_r, pos_r, len_r) \
    {{reg_l, pol_l, pos_l, len_l}, {reg_r, pol_r, pos_r, len_r}}
#define PMIX_ENT(name, reg_l, pos_l, len_l, reg_r, pos_r, len_r) \
    {{reg_l, 0, pos_l, len_l}, {reg_r, 0, pos_r, len_r}}

#define MIX_NONE(name) MIX_ENT(name, 0,0,0,0, 0,0,0,0)

/*
 * some macros for debugging purposes
 * DDB/DEB to enable/disable debugging stuff
 * BVDDB   to enable debugging when bootverbose
 */
#define DDB(x)	x	/* XXX */
#define BVDDB(x) if (bootverbose) x

#ifndef DEB
#define DEB(x)
#endif

extern snddev_info pcm_info[NPCM_MAX] ;
extern snddev_info midi_info[NPCM_MAX] ;
extern snddev_info synth_info[NPCM_MAX] ;

extern u_long nsnd ;
extern snddev_info *snddev_last_probed;

int pcmprobe(struct isa_device * dev);
int midiprobe(struct isa_device * dev);
int synthprobe(struct isa_device * dev);
int pcmattach(struct isa_device * dev);
int midiattach(struct isa_device * dev);
int synthattach(struct isa_device * dev);

/*
 *      DMA buffer calls
 */

void dsp_wrintr(snddev_info *d);
void dsp_rdintr(snddev_info *d);
int dsp_write_body(snddev_info *d, struct uio *buf);
int dsp_read_body(snddev_info *d, struct uio *buf);
void alloc_dbuf(snd_dbuf *d, int size);

int snd_flush(snddev_info *d);

/* the following parameters are used in snd_sync and reset_dbuf
 * to decide whether or not to restart a channel
 */
#define	SND_CHAN_NONE	0x0
#define	SND_CHAN_WR	0x1
#define	SND_CHAN_RD	0x2

void reset_dbuf(snd_dbuf *b, int chan);
int snd_sync(snddev_info *d, int chan, int threshold);
int dsp_wrabort(snddev_info *d, int restart);
int dsp_rdabort(snddev_info *d, int restart);
void dsp_wr_dmaupdate(snd_dbuf *b);
void dsp_rd_dmaupdate(snd_dbuf *b);

d_select_t sndselect;

/*
 * library functions (in sound.c)
 */

int ask_init(snddev_info *d);
void translate_bytes(u_char *table, u_char *buff, int n);
void change_bits(mixer_tab *t, u_char *regval, int dev, int chn, int newval);
int snd_conflict(int io_base);
void snd_set_blocksize(snddev_info *d);
int isa_dmastatus1(int channel);
/*
 * routines in ad1848.c and sb_dsp.c which others might use
 */
int mss_detect (struct isa_device *dev);
int sb_cmd (int io_base, u_char cmd);
int sb_cmd2 (int io_base, u_char cmd, int val);
int sb_cmd3 (int io_base, u_char cmd, int val);
int sb_reset_dsp (int io_base);
void sb_setmixer (int io_base, u_int port, u_int value);
int sb_getmixer (int io_base, u_int port);

#endif /* KERNEL */

/*
 * usage of flags in device config entry (config file)
 */

#define DV_F_DRQ_MASK	0x00000007	/* mask for secondary drq */
#define	DV_F_DUAL_DMA	0x00000010	/* set to use secondary dma channel */
#define	DV_F_DEV_MASK	0x0000ff00	/* force device type/class */
#define	DV_F_DEV_SHIFT	8	/* force device type/class */

/*
 * some flags are used in a device-specific manner, so that values can
 * be used multiple times.
 */

#define	DV_F_TRUE_MSS	0x00010000	/* mss _with_ base regs */
    /* almost all modern cards do not have this set of registers,
     * so it is better to make this the default behaviour
     */

/*
 * the following flags are for PnP cards only and are undocumented
 */
#define DV_PNP_SBCODEC 0x1

#endif
