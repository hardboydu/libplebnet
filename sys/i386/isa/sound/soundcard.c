/*
 * sound/386bsd/soundcard.c
 * 
 * Soundcard driver for FreeBSD.
 * 
 * Copyright by Hannu Savolainen 1993
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
 * $Id: soundcard.c,v 1.52 1997/07/20 11:58:40 bde Exp $
 */

#include <i386/isa/sound/sound_config.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>

#ifdef CONFIGURE_SOUNDCARD

#include <i386/isa/sound/dev_table.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif /*DEVFS*/

#define FIX_RETURN(ret) { \
			  int tmp_ret = (ret); \
			  if (tmp_ret<0) return -tmp_ret; else return 0; \
			}

static int      timer_running = 0;

static int      soundcards_installed = 0;	/* Number of installed
						 * soundcards */
static int      soundcard_configured = 0;

static struct fileinfo files[SND_NDEVS];

#ifdef DEVFS
static void * snd_devfs_token[SND_NDEVS];
static void * sndstat_devfs_token;
#endif 

struct selinfo selinfo[SND_NDEVS >> 4];

static int	sndprobe (struct isa_device *dev);
static int	sndattach (struct isa_device *dev);
static void	sound_mem_init(void);

static d_open_t		sndopen;
static d_close_t	sndclose;
static d_read_t		sndread;
static d_write_t	sndwrite;
static d_ioctl_t	sndioctl;
static d_poll_t		sndpoll;

#define CDEV_MAJOR 30
static struct cdevsw snd_cdevsw = 
	{ sndopen,	sndclose,	sndread,	sndwrite,	/*30*/
  	  sndioctl,	nostop,		nullreset,	nodevtotty,/* sound */
  	  sndpoll,	nommap,		NULL,	"snd", NULL, -1 };

struct isa_driver opldriver	= {sndprobe, sndattach, "opl"};
struct isa_driver sbdriver	= {sndprobe, sndattach, "sb"};
struct isa_driver sbxvidriver	= {sndprobe, sndattach, "sbxvi"};
struct isa_driver sbmididriver	= {sndprobe, sndattach, "sbmidi"};
struct isa_driver awedriver	= {sndprobe, sndattach, "awe"};
struct isa_driver pasdriver	= {sndprobe, sndattach, "pas"};
struct isa_driver mpudriver	= {sndprobe, sndattach, "mpu"};
struct isa_driver gusdriver	= {sndprobe, sndattach, "gus"};
struct isa_driver gusxvidriver	= {sndprobe, sndattach, "gusxvi"};
struct isa_driver gusmaxdriver	= {sndprobe, sndattach, "gusmax"};
struct isa_driver uartdriver	= {sndprobe, sndattach, "uart"};
struct isa_driver mssdriver	= {sndprobe, sndattach, "mss"};
#ifdef PC98
struct isa_driver pcmdriver	= {sndprobe, sndattach, "pcm"};
#endif

static int
ipri_to_irq (unsigned short ipri);

void
adintr(INT_HANDLER_PARMS(unit,dummy))
{ 
#ifndef EXCLUDE_AD1848
	static short unit_to_irq[4] = { -1, -1, -1, -1 };
        struct isa_device *dev;

        if (unit_to_irq [unit] > 0)
		ad1848_interrupt(INT_HANDLER_CALL (unit_to_irq [unit]));
	else {
                dev = find_isadev (isa_devtab_null, &mssdriver, unit);
                if (!dev)
			printk ("ad1848: Couldn't determine unit\n");
                else {
			unit_to_irq [unit] = ipri_to_irq (dev->id_irq);
			ad1848_interrupt(INT_HANDLER_CALL (unit_to_irq [unit]));
 		}
	}
#endif
}

unsigned
long
get_time(void)
{
struct timeval timecopy;
int x;

   x = splclock();
   timecopy = time;
   splx(x);
   return timecopy.tv_usec/(1000000/HZ) +
	  (unsigned long)timecopy.tv_sec*HZ;
}
 

static int
sndread (dev_t dev, struct uio *buf, int ioflag)
{
  int             count = buf->uio_resid;

  dev = minor (dev);

  FIX_RETURN (sound_read_sw (dev, &files[dev], buf, count));
}

static int
sndwrite (dev_t dev, struct uio *buf, int ioflag)
{
  int             count = buf->uio_resid;

  dev = minor (dev);

  FIX_RETURN (sound_write_sw (dev, &files[dev], buf, count));
}

static int
sndopen (dev_t dev, int flags, int fmt, struct proc *p)
{
  dev = minor (dev);

  if (!soundcard_configured && dev)
    {
      printk ("SoundCard Error: The soundcard system has not been configured\n");
      FIX_RETURN (-ENODEV);
    }

  files[dev].mode = 0;

  if (flags & FREAD && flags & FWRITE)
    files[dev].mode = OPEN_READWRITE;
  else if (flags & FREAD)
    files[dev].mode = OPEN_READ;
  else if (flags & FWRITE)
    files[dev].mode = OPEN_WRITE;

  selinfo[dev >> 4].si_pid = 0;
  selinfo[dev >> 4].si_flags = 0;

  FIX_RETURN(sound_open_sw (dev, &files[dev]));
}

static int
sndclose (dev_t dev, int flags, int fmt, struct proc *p)
{

  dev = minor (dev);

  sound_release_sw(dev, &files[dev]);
  FIX_RETURN (0);
}

static int
sndioctl (dev_t dev, int cmd, caddr_t arg, int flags, struct proc *p)
{
  dev = minor (dev);

  FIX_RETURN (sound_ioctl_sw (dev, &files[dev], cmd, (unsigned int) arg));
}

static int
sndpoll (dev_t dev, int events, struct proc *p)
{
  dev = minor (dev);

  DEB (printk ("snd_poll(dev=%d, rw=%d, pid=%d)\n", dev, rw, p->p_pid));
#ifdef ALLOW_SELECT
  switch (dev & 0x0f)
    {
#ifndef EXCLUDE_SEQUENCER
    case SND_DEV_SEQ:
    case SND_DEV_SEQ2:
      return sequencer_poll (dev, &files[dev], events, p);
      break;
#endif

#ifndef EXCLUDE_MIDI
    case SND_DEV_MIDIN:
      return MIDIbuf_poll (dev, &files[dev], events, p);
      break;
#endif

#ifndef EXCLUDE_AUDIO
    case SND_DEV_DSP:
    case SND_DEV_DSP16:
    case SND_DEV_AUDIO:
      return audio_poll (dev, &files[dev], events, p);
      break;
#endif

    default:
      return 0;
    }

#endif

  return 0;
}

static int
ipri_to_irq (unsigned short ipri)
{
  /*
   * Converts the ipri (bitmask) to the corresponding irq number
   */
  int             irq;

  for (irq = 0; irq < 16; irq++)
    if (ipri == (1 << irq))
      return irq;

  return -1;			/* Invalid argument */
}

static int
driver_to_voxunit(struct isa_driver *driver)
{
  /* converts a sound driver pointer into the equivalent
     VoxWare device unit number */
  if(driver == &opldriver)
    return(SNDCARD_ADLIB);
  else if(driver == &sbdriver)
    return(SNDCARD_SB);
  else if(driver == &pasdriver)
    return(SNDCARD_PAS);
  else if(driver == &gusdriver)
    return(SNDCARD_GUS);
  else if(driver == &mpudriver)
    return(SNDCARD_MPU401);
  else if(driver == &sbxvidriver)
    return(SNDCARD_SB16);
  else if(driver == &sbmididriver)
    return(SNDCARD_SB16MIDI);
  else if(driver == &awedriver)
    return(SNDCARD_AWE32);
  else if(driver == &uartdriver)
    return(SNDCARD_UART6850);
  else if(driver == &gusdriver)
    return(SNDCARD_GUS16);
  else if(driver == &mssdriver)
    return(SNDCARD_MSS);
#ifdef PC98
  else if(driver == &pcmdriver)
    return(SNDCARD_PCM86);
#endif
  else
    return(0);
}

static int
sndprobe (struct isa_device *dev)
{
  struct address_info hw_config;
  int unit;

  unit = driver_to_voxunit(dev->id_driver);
  hw_config.io_base = dev->id_iobase;
  hw_config.irq = ipri_to_irq (dev->id_irq);
  hw_config.dma = dev->id_drq;
  hw_config.dma_read = dev->id_flags;	/* misuse the flags field for read dma*/
  
  if(unit) {
      int result;

      result = sndtable_probe (unit, &hw_config);
      dev->id_iobase = hw_config.io_base;
      dev->id_irq = hw_config.irq == -1 ? 0 : (1 << hw_config.irq);
      dev->id_drq = hw_config.dma;

      return result;
  } else
      return 0;
}

static int
sndattach (struct isa_device *dev)
{
  int             unit;
  int             minor;
  int             voxunit;
  static int      midi_initialized = 0;
  static int      seq_initialized = 0;
  unsigned long	  mem_start = 0xefffffffUL;
  struct address_info hw_config;

  unit = dev->id_unit;
  voxunit = driver_to_voxunit(dev->id_driver);
  hw_config.io_base = dev->id_iobase;
  hw_config.irq = ipri_to_irq (dev->id_irq);
  hw_config.dma = dev->id_drq;
  hw_config.dma_read = dev->id_flags;	/* misuse the flags field for read dma*/

  if(!voxunit)
    return FALSE;
  if (!sndtable_init_card (voxunit, &hw_config))
    {
      printf (" <Driver not configured>");
      return FALSE;
    }

  /*
   * Init the high level sound driver
   */

  if (!(soundcards_installed = sndtable_get_cardcount ()))
    {
      printf (" <No such hardware>");
      return FALSE;		/* No cards detected */
    }

  printf("\n");

#ifndef EXCLUDE_AUDIO
  if (num_audiodevs)	/* Audio devices present */
    {
      mem_start = DMAbuf_init (mem_start);
      mem_start = audio_init (mem_start);
      sound_mem_init ();
    }

  soundcard_configured = 1;
#endif

#ifndef EXCLUDE_MIDI
  if (num_midis && !midi_initialized)
    {
      midi_initialized = 1;
      mem_start = MIDIbuf_init (mem_start);
    }
#endif

#ifndef EXCLUDE_SEQUENCER
  if ((num_midis + num_synths) && !seq_initialized)
    {
      seq_initialized = 1;
      mem_start = sequencer_init (mem_start);
    }
#endif

#ifdef DEVFS
/* XXX */ /* should only create devices if that card has them */
  if ( ! sndstat_devfs_token) 
    {
      sndstat_devfs_token = 
	devfs_add_devswf(&snd_cdevsw, SND_DEV_STATUS, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "sndstat");
    }
    
  minor = (unit << 4)+SND_DEV_CTL;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "mixer%d", unit);
    }

#ifndef EXCLUDE_SEQUENCER
  minor = (unit << 4)+SND_DEV_SEQ;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
      	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
      	      	      	 GID_WHEEL, 0600, "sequencer%d", unit);
    }
  
  minor = (unit << 4)+SND_DEV_SEQ2;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "music%d", unit);
    }
#endif

#ifndef EXCLUDE_MIDI
  minor = (unit << 4)+SND_DEV_MIDIN;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
      	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
		      	 GID_WHEEL, 0600, "midi%d", unit);
    }
#endif

#ifndef EXCLUDE_AUDIO
  minor = (unit << 4)+SND_DEV_DSP;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "dsp%d", unit);
    }

  minor = (unit << 4)+SND_DEV_AUDIO;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "audio%d", unit);
    }

  minor = (unit << 4)+SND_DEV_DSP16;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "dspW%d", unit);
    }
#endif

  minor = (unit << 4)+SND_DEV_SNDPROC;
  if ( ! snd_devfs_token[minor])
    {
      snd_devfs_token[minor] =
	devfs_add_devswf(&snd_cdevsw, minor, DV_CHR, UID_ROOT,
	      	      	 GID_WHEEL, 0600, "pss%d", unit);
    }
#endif /* DEVFS */
  return TRUE;
}

void
tenmicrosec (void)
{
  int             i;

  for (i = 0; i < 16; i++)
    inb (0x80);
}

#ifndef EXCLUDE_SEQUENCER
void
request_sound_timer (int count)
{
  static int      current = 0;
  int             tmp = count;

  if (count < 0)
    timeout (sequencer_timer, 0, -count);
  else
    {

      if (count < current)
	current = 0;		/* Timer restarted */

      count = count - current;

      current = tmp;

      if (!count)
	count = 1;

      timeout (sequencer_timer, 0, count);
    }
  timer_running = 1;
}

void
sound_stop_timer (void)
{
  if (timer_running)
    untimeout (sequencer_timer, 0);
  timer_running = 0;
}
#endif

#ifndef EXCLUDE_AUDIO
static void
sound_mem_init (void)
{
  int             dev;
  unsigned long   dma_pagesize;
  struct dma_buffparms *dmap;
  static unsigned long dsp_init_mask = 0;

  for (dev = 0; dev < num_audiodevs; dev++)	/* Enumerate devices */
    if (!(dsp_init_mask & (1 << dev)))	/* Not already done */
#ifdef PC98
      if (audio_devs[dev]->buffcount > 0 && audio_devs[dev]->dmachan >= 0)
#else
      if (audio_devs[dev]->buffcount > 0 && audio_devs[dev]->dmachan > 0)
#endif
	{
	  dsp_init_mask |= (1 << dev);
	  dmap = audio_devs[dev]->dmap;

	  if (audio_devs[dev]->flags & DMA_AUTOMODE)
	    audio_devs[dev]->buffcount = 1;

	  audio_devs[dev]->buffsize &= ~0xfff;	/* Truncate to n*4k */

	  if (audio_devs[dev]->dmachan > 3 && audio_devs[dev]->buffsize > 65536)
	    dma_pagesize = 131072;	/* 128k */
	  else
	    dma_pagesize = 65536;

	  /* More sanity checks */

	  if (audio_devs[dev]->buffsize > dma_pagesize)
	    audio_devs[dev]->buffsize = dma_pagesize;
	  if (audio_devs[dev]->buffsize < 4096)
	    audio_devs[dev]->buffsize = 4096;

	  /* Now allocate the buffers */

	  for (dmap->raw_count = 0; dmap->raw_count < audio_devs[dev]->buffcount; dmap->raw_count++)
	    {
	      char           *tmpbuf = (char *)vm_page_alloc_contig(audio_devs[dev]->buffsize, 0ul, 0xfffffful, dma_pagesize);

	      if (tmpbuf == NULL)
		{
		  printk ("snd: Unable to allocate %ld bytes of buffer\n",
			  audio_devs[dev]->buffsize);
		  return;
		}

	      dmap->raw_buf[dmap->raw_count] = tmpbuf;
	      /*
	       * Use virtual address as the physical address, since
	       * isa_dmastart performs the phys address computation.
	       */
	      dmap->raw_buf_phys[dmap->raw_count] =
		(unsigned long) dmap->raw_buf[dmap->raw_count];
	    }
	}			/* for dev */

}

#endif

int
snd_set_irq_handler (int interrupt_level, INT_HANDLER_PROTO(), char *name)
{
  return 1;
}


void
snd_release_irq(int vect)
{
}

static snd_devsw_installed = 0;

static void 
snd_drvinit(void *unused)
{
	dev_t dev;

	if( ! snd_devsw_installed ) {
		dev = makedev(CDEV_MAJOR, 0);
		cdevsw_add(&dev,&snd_cdevsw, NULL);
		snd_devsw_installed = 1;
    	}
}

SYSINIT(snddev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,snd_drvinit,NULL)

#endif

