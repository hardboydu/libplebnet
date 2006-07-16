/*-
 * Copyright (c) 1999 Cameron Grant <gandalf@vilnya.demon.co.uk>
 * Copyright (c) 2003-2006 Yuriy Tsibizov <yuriy.tsibizov@gfk.ru>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHERIN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <sys/systm.h>
#include <sys/sbuf.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <dev/sound/chip.h>
#include <dev/sound/pcm/sound.h>
#include <dev/sound/pcm/ac97.h>

#include "mixer_if.h"

#include "opt_emu10kx.h"
#include <dev/sound/pci/emu10kx.h>
#include "emu10k1-alsa%diked.h"

struct emu_pcm_pchinfo {
	int		spd;
	int		fmt;
	int		blksz;
	int		run;
	struct emu_voice *master;
	struct emu_voice *slave;
	struct snd_dbuf	*buffer;
	struct pcm_channel *channel;
	struct emu_pcm_info *pcm;
	int		timer;
};

struct emu_pcm_rchinfo {
	int		spd;
	int		fmt;
	int		blksz;
	int		run;
	uint32_t 	idxreg;
	uint32_t	basereg;
	uint32_t	sizereg;
	uint32_t	setupreg;
	uint32_t	irqmask;
	uint32_t	iprmask;
	int 		ihandle;
	struct snd_dbuf	*buffer;
	struct pcm_channel *channel;
	struct emu_pcm_info *pcm;
};

/* Hardware channels for front output */
#define	MAX_CHANNELS	4

#if MAX_CHANNELS > 13
#error	Too many hardware channels defined. 13 is the maximum
#endif
struct emu_pcm_info {
	struct mtx		*lock;
	device_t		dev;		/* device information */
	struct snddev_info 	*devinfo;	/* pcm device information */
	struct emu_sc_info 	*card;
	struct emu_pcm_pchinfo	pch[MAX_CHANNELS];	/* hardware channels */
	int			pnum;		/* next free channel number */
	struct emu_pcm_rchinfo	rch;
	struct emu_route	rt;
	int			route;
	int			ihandle;	/* interrupt handler */
	unsigned int		bufsz;
	int			is_emu10k1;
	struct ac97_info	*codec;
	uint32_t 		ac97_state[0x7F];
};


static uint32_t emu_rfmt[] = {
	AFMT_S16_LE,
	AFMT_STEREO | AFMT_S16_LE,
	0
};
static struct pcmchan_caps emu_reccaps = {
	/* XXX should be "8000, 48000, emu_rfmt, 0", but 8000/8bit/mono is broken */
	11025, 48000, emu_rfmt, 0
};

static uint32_t emu_pfmt[] = {
	AFMT_U8,
	AFMT_STEREO | AFMT_U8,
	AFMT_S16_LE,
	AFMT_STEREO | AFMT_S16_LE,
	0
};
static uint32_t emu_pfmt_mono[] = {
	AFMT_U8,
	AFMT_S16_LE,
	0
};

static struct pcmchan_caps emu_playcaps = {4000, 48000, emu_pfmt, 0};
static struct pcmchan_caps emu_playcaps_mono = {4000, 48000, emu_pfmt_mono, 0};

static int emu10k1_adcspeed[8] = {48000, 44100, 32000, 24000, 22050, 16000, 11025, 8000};
/* audigy supports 12kHz. */
static int emu10k2_adcspeed[9] = {48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000};

static uint32_t emu_pcm_intr(void *pcm, uint32_t stat);

static const struct emu_dspmix_props {
	u_int8_t	present;
} dspmix [SOUND_MIXER_NRDEVICES] = {
	[SOUND_MIXER_VOLUME] =	{1},
	[SOUND_MIXER_PCM] =	{1},
};

static int
emu_dspmixer_init(struct snd_mixer *m)
{
	int i;
	int v;

	v = 0;
	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if (dspmix[i].present)
			v |= 1 << i;
	}
	mix_setdevs(m, v);

	mix_setrecdevs(m, 0);
	return (0);
}

static int
emu_dspmixer_set(struct snd_mixer *m, unsigned dev, unsigned left, unsigned right)
{
	struct emu_pcm_info *sc;

	sc = mix_getdevinfo(m);

	switch (dev) {
	case SOUND_MIXER_VOLUME:
		switch (sc->route) {
		case RT_REAR:
			emumix_set_volume(sc->card, M_MASTER_REAR_L, left);
			emumix_set_volume(sc->card, M_MASTER_REAR_R, right);
			break;
		case RT_CENTER:
			emumix_set_volume(sc->card, M_MASTER_CENTER, (left+right)/2);
			break;
		case RT_SUB:
			emumix_set_volume(sc->card, M_MASTER_SUBWOOFER, (left+right)/2);
			break;
		}
		break;
	case SOUND_MIXER_PCM:
		switch (sc->route) {
		case RT_REAR:
			emumix_set_volume(sc->card, M_FX2_REAR_L, left);
			emumix_set_volume(sc->card, M_FX3_REAR_R, right);
			break;
		case RT_CENTER:
			emumix_set_volume(sc->card, M_FX4_CENTER, (left+right)/2);
			break;
		case RT_SUB:
			emumix_set_volume(sc->card, M_FX5_SUBWOOFER, (left+right)/2);
			break;
		}
		break;
	default:
		device_printf(sc->dev, "mixer error: unknown device %d\n", dev);
	}
	return  (0);
}

static int
emu_dspmixer_setrecsrc(struct snd_mixer *m __unused, u_int32_t src __unused)
{
	return (0);
}

static kobj_method_t emudspmixer_methods[] = {
	KOBJMETHOD(mixer_init,		emu_dspmixer_init),
	KOBJMETHOD(mixer_set,		emu_dspmixer_set),
	KOBJMETHOD(mixer_setrecsrc,	emu_dspmixer_setrecsrc),
	{ 0, 0 }
};
MIXER_DECLARE(emudspmixer);

/*
 * AC97 emulation code for Audigy and later cards.
 * Some parts of AC97 codec are not used by hardware, but can be used
 * to change some DSP controls via AC97 mixer interface. This includes:
 * - master volume controls MASTER_FRONT_[R|L]
 * - pcm volume controls FX[0|1]_FRONT_[R|L]
 * - rec volume controls MASTER_REC_[R|L]
 * We do it because we need to put it under user control....
 * We also keep some parts of AC97 disabled to get better sound quality
 */

#define	AC97LEFT(x)	((x & 0x7F00)>>8)
#define	AC97RIGHT(x)	(x & 0x007F)
#define	AC97MUTE(x)	((x & 0x8000)>>15)
#define	BIT4_TO100(x)	(100-(x)*100/(0x0f))
#define	BIT6_TO100(x)	(100-(x)*100/(0x3f))
#define	BIT4_TO255(x)	(255-(x)*255/(0x0f))
#define	BIT6_TO255(x)	(255-(x)*255/(0x3f))
#define	V100_TOBIT6(x)	(0x3f*(100-x)/100)
#define	V100_TOBIT4(x)	(0x0f*(100-x)/100)
#define	AC97ENCODE(x_muted,x_left,x_right)	(((x_muted&1)<<15) | ((x_left&0x3f)<<8) | (x_right&0x3f))

static int
emu_ac97_read_emulation(struct emu_pcm_info *sc, int regno)
{
	int use_ac97;
	int emulated;
	int tmp;

	use_ac97 = 1;
	emulated = 0;

	switch (regno) {
	case AC97_MIX_MASTER:
		emulated = sc->ac97_state[AC97_MIX_MASTER];
		use_ac97 = 0;
		break;
	case AC97_MIX_PCM:
		emulated = sc->ac97_state[AC97_MIX_PCM];
		use_ac97 = 0;
		break;
	case AC97_REG_RECSEL:
		emulated = 0x0505;
		use_ac97 = 0;
		break;
	case AC97_MIX_RGAIN:
		emulated = sc->ac97_state[AC97_MIX_RGAIN];
		use_ac97 = 0;
		break;
	}

	emu_wr(sc->card, AC97ADDRESS, regno, 1);
	tmp = emu_rd(sc->card, AC97DATA, 2);

	if (use_ac97)
		emulated = tmp;

	return (emulated);
}

static void
emu_ac97_write_emulation(struct emu_pcm_info *sc, int regno, uint32_t data)
{
	int write_ac97;
	int left, right;
	uint32_t emu_left, emu_right;
	int is_mute;

	write_ac97 = 1;

	left = AC97LEFT(data);
	emu_left = BIT6_TO100(left);	/* We show us as 6-bit AC97 mixer */
	right = AC97RIGHT(data);
	emu_right = BIT6_TO100(right);
	is_mute = AC97MUTE(data);
	if (is_mute)
		emu_left = emu_right = 0;

	switch (regno) {
		/* TODO: reset emulator on AC97_RESET */
	case AC97_MIX_MASTER:
		emumix_set_volume(sc->card, M_MASTER_FRONT_L, emu_left);
		emumix_set_volume(sc->card, M_MASTER_FRONT_R, emu_right);
		sc->ac97_state[AC97_MIX_MASTER] = data & (0x8000 | 0x3f3f);
		data = 0x8000;	/* Mute AC97 main out */
		break;
	case AC97_MIX_PCM:	/* PCM OUT VOL */
		emumix_set_volume(sc->card, M_FX0_FRONT_L, emu_left);
		emumix_set_volume(sc->card, M_FX1_FRONT_R, emu_right);
		sc->ac97_state[AC97_MIX_PCM] = data & (0x8000 | 0x3f3f);
		data = 0x8000;	/* Mute AC97 PCM out */
		break;
	case AC97_REG_RECSEL:
		/*
		 * PCM recording source is set to "stereo mix" (labeled "vol"
		 * in mixer) XXX !I can't remember why!
		 */
		data = 0x0505;
		break;
	case AC97_MIX_RGAIN:	/* RECORD GAIN */
		emu_left = BIT4_TO100(left);	/* rgain is 4-bit */
		emu_right = BIT4_TO100(right);
		emumix_set_volume(sc->card, M_MASTER_REC_L, 100-emu_left);
		emumix_set_volume(sc->card, M_MASTER_REC_R, 100-emu_right);
		/*
		 * Record gain on AC97 should stay zero to get AC97 sound on
		 * AC97_[RL] connectors on EMU10K2 chip. AC97 on Audigy is not
		 * directly connected to any output, only to EMU10K2 chip Use
		 * this control to set AC97 mix volume inside EMU10K2 chip
		 */
		sc->ac97_state[AC97_MIX_RGAIN] = data & (0x8000 | 0x0f0f);
		data = 0x0000;
		break;
	}
	if (write_ac97) {
		emu_wr(sc->card, AC97ADDRESS, regno, 1);
		emu_wr(sc->card, AC97DATA, data, 2);
	}
}

static int
emu_erdcd(kobj_t obj __unused, void *devinfo, int regno)
{
	struct emu_pcm_info *sc = (struct emu_pcm_info *)devinfo;

	return (emu_ac97_read_emulation(sc, regno));
}

static int
emu_ewrcd(kobj_t obj __unused, void *devinfo, int regno, uint32_t data)
{
	struct emu_pcm_info *sc = (struct emu_pcm_info *)devinfo;

	emu_ac97_write_emulation(sc, regno, data);
	return (0);
}

static kobj_method_t emu_eac97_methods[] = {
	KOBJMETHOD(ac97_read, emu_erdcd),
	KOBJMETHOD(ac97_write, emu_ewrcd),
	{0, 0}
};
AC97_DECLARE(emu_eac97);

/* real ac97 codec */
static int
emu_rdcd(kobj_t obj __unused, void *devinfo, int regno)
{
	int rd;
	struct emu_pcm_info *sc = (struct emu_pcm_info *)devinfo;

	KASSERT(sc->card != NULL, ("emu_rdcd: no soundcard"));
	emu_wr(sc->card, AC97ADDRESS, regno, 1);
	rd = emu_rd(sc->card, AC97DATA, 2);
	return (rd);
}

static int
emu_wrcd(kobj_t obj __unused, void *devinfo, int regno, uint32_t data)
{
	struct emu_pcm_info *sc = (struct emu_pcm_info *)devinfo;

	KASSERT(sc->card != NULL, ("emu_wrcd: no soundcard"));
	emu_wr(sc->card, AC97ADDRESS, regno, 1);
	emu_wr(sc->card, AC97DATA, data, 2);
	return (0);
}

static kobj_method_t emu_ac97_methods[] = {
	KOBJMETHOD(ac97_read, emu_rdcd),
	KOBJMETHOD(ac97_write, emu_wrcd),
	{0, 0}
};
AC97_DECLARE(emu_ac97);


static int
emu_k1_recval(int speed)
{
	int val;

	val = 0;
	while ((val < 7) && (speed < emu10k1_adcspeed[val]))
		val++;
	if (val == 6) val=5; /* XXX 8kHz does not work */
	return (val);
}

static int
emu_k2_recval(int speed)
{
	int val;

	val = 0;
	while ((val < 8) && (speed < emu10k2_adcspeed[val]))
		val++;
	if (val == 7) val=6; /* XXX 8kHz does not work */
	return (val);
}

static void *
emupchan_init(kobj_t obj __unused, void *devinfo, struct snd_dbuf *b, struct pcm_channel *c, int dir __unused)
{
	struct emu_pcm_info *sc = devinfo;
	struct emu_pcm_pchinfo *ch;
	void *r;

	KASSERT(dir == PCMDIR_PLAY, ("emupchan_init: bad direction"));
	KASSERT(sc->card != NULL, ("empchan_init: no soundcard"));


	if (sc->pnum >= MAX_CHANNELS)
		return (NULL);
	ch = &(sc->pch[sc->pnum++]);
	ch->buffer = b;
	ch->pcm = sc;
	ch->channel = c;
	ch->blksz = sc->bufsz;
	ch->fmt = AFMT_U8;
	ch->spd = 8000;
	ch->master = emu_valloc(sc->card);
	/*
	 * XXX we have to allocate slave even for mono channel until we
	 * fix emu_vfree to handle this case.
	 */
	ch->slave = emu_valloc(sc->card);
	ch->timer = emu_timer_create(sc->card);
	r = (emu_vinit(sc->card, ch->master, ch->slave, sc->bufsz, ch->buffer)) ? NULL : ch;
	return (r);
}

static int
emupchan_free(kobj_t obj __unused, void *c_devinfo)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;

	emu_timer_clear(sc->card, ch->timer);
	if (ch->slave != NULL)
		emu_vfree(sc->card, ch->slave);
	emu_vfree(sc->card, ch->master);
	return (0);
}

static int
emupchan_setformat(kobj_t obj __unused, void *c_devinfo, uint32_t format)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;

	ch->fmt = format;
	return (0);
}

static int
emupchan_setspeed(kobj_t obj __unused, void *c_devinfo, uint32_t speed)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;

	ch->spd = speed;
	return (ch->spd);
}

static int
emupchan_setblocksize(kobj_t obj __unused, void *c_devinfo, uint32_t blocksize)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;

	if (blocksize > ch->pcm->bufsz)
		blocksize = ch->pcm->bufsz;
	snd_mtxlock(sc->lock);
	ch->blksz = blocksize;
	emu_timer_set(sc->card, ch->timer, ch->blksz / sndbuf_getbps(ch->buffer));
	snd_mtxunlock(sc->lock);
	return (blocksize);
}

static int
emupchan_trigger(kobj_t obj __unused, void *c_devinfo, int go)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;

	if (go == PCMTRIG_EMLDMAWR || go == PCMTRIG_EMLDMARD)
		return (0);
	snd_mtxlock(sc->lock); /* XXX can we trigger on parallel threads ? */
	if (go == PCMTRIG_START) {
		emu_vsetup(ch->master, ch->fmt, ch->spd);
		emu_vroute(sc->card, &(sc->rt), ch->master);
		emu_vwrite(sc->card, ch->master);
		emu_timer_set(sc->card, ch->timer, ch->blksz / sndbuf_getbps(ch->buffer));
		emu_timer_enable(sc->card, ch->timer, 1);
	}
	/* PCM interrupt handler will handle PCMTRIG_STOP event */
	ch->run = (go == PCMTRIG_START) ? 1 : 0;
	emu_vtrigger(sc->card, ch->master, ch->run);
	snd_mtxunlock(sc->lock);
	return (0);
}

static int
emupchan_getptr(kobj_t obj __unused, void *c_devinfo)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;
	int r;

	r = emu_vpos(sc->card, ch->master);

	return (r);
}

static struct pcmchan_caps *
emupchan_getcaps(kobj_t obj __unused, void *c_devinfo __unused)
{
	struct emu_pcm_pchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;

	switch (sc->route) {
	case RT_FRONT:
		/* FALLTHROUGH */
	case RT_REAR:
		/* FALLTHROUGH */
	case RT_SIDE:
		return (&emu_playcaps);
		break;
	case RT_CENTER:
		/* FALLTHROUGH */
	case RT_SUB:
		return (&emu_playcaps_mono);
		break;
	}
	return (NULL);
}

static kobj_method_t emupchan_methods[] = {
	KOBJMETHOD(channel_init, emupchan_init),
	KOBJMETHOD(channel_free, emupchan_free),
	KOBJMETHOD(channel_setformat, emupchan_setformat),
	KOBJMETHOD(channel_setspeed, emupchan_setspeed),
	KOBJMETHOD(channel_setblocksize, emupchan_setblocksize),
	KOBJMETHOD(channel_trigger, emupchan_trigger),
	KOBJMETHOD(channel_getptr, emupchan_getptr),
	KOBJMETHOD(channel_getcaps, emupchan_getcaps),
	{0, 0}
};
CHANNEL_DECLARE(emupchan);

static void *
emurchan_init(kobj_t obj __unused, void *devinfo, struct snd_dbuf *b, struct pcm_channel *c, int dir __unused)
{
	struct emu_pcm_info *sc = devinfo;
	struct emu_pcm_rchinfo *ch;

	KASSERT(dir == PCMDIR_REC, ("emurchan_init: bad direction"));
	ch = &sc->rch;
	ch->buffer = b;
	ch->pcm = sc;
	ch->channel = c;
	ch->blksz = sc->bufsz;
	ch->fmt = AFMT_U8;
	ch->spd = 11025;	/* XXX 8000 Hz does not work */
	ch->idxreg = sc->is_emu10k1 ? ADCIDX : A_ADCIDX;
	ch->basereg = ADCBA;
	ch->sizereg = ADCBS;
	ch->setupreg = ADCCR;
	ch->irqmask = INTE_ADCBUFENABLE;
	ch->iprmask = IPR_ADCBUFFULL | IPR_ADCBUFHALFFULL;

	if (sndbuf_alloc(ch->buffer, emu_gettag(sc->card), sc->bufsz) != 0)
		return (NULL);
	else {
		emu_wrptr(sc->card, 0, ch->basereg, sndbuf_getbufaddr(ch->buffer));
		emu_wrptr(sc->card, 0, ch->sizereg, 0);	/* off */
		return (ch);
	}
}

static int
emurchan_setformat(kobj_t obj __unused, void *c_devinfo, uint32_t format)
{
	struct emu_pcm_rchinfo *ch = c_devinfo;

	ch->fmt = format;
	return (0);
}

static int
emurchan_setspeed(kobj_t obj __unused, void *c_devinfo, uint32_t speed)
{
	struct emu_pcm_rchinfo *ch = c_devinfo;

	if (ch->pcm->is_emu10k1) {
		speed = emu10k1_adcspeed[emu_k1_recval(speed)];
	} else {
		speed = emu10k2_adcspeed[emu_k2_recval(speed)];
	}
	ch->spd = speed;
	return (ch->spd);
}

static int
emurchan_setblocksize(kobj_t obj __unused, void *c_devinfo, uint32_t blocksize)
{
	struct emu_pcm_rchinfo *ch = c_devinfo;

	ch->blksz = blocksize;
	return (blocksize);
}

static int
emurchan_trigger(kobj_t obj __unused, void *c_devinfo, int go)
{
	struct emu_pcm_rchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;
	uint32_t val, sz;

	switch (sc->bufsz) {
	case 4096:
		sz = ADCBS_BUFSIZE_4096;
		break;
	case 8192:
		sz = ADCBS_BUFSIZE_8192;
		break;
	case 16384:
		sz = ADCBS_BUFSIZE_16384;
		break;
	case 32768:
		sz = ADCBS_BUFSIZE_32768;
		break;
	case 65536:
		sz = ADCBS_BUFSIZE_65536;
		break;
	default:
		sz = ADCBS_BUFSIZE_4096;
	}

	snd_mtxlock(sc->lock);
	switch (go) {
	case PCMTRIG_START:
		ch->run = 1;
		emu_wrptr(sc->card, 0, ch->sizereg, sz);
		val = sc->is_emu10k1 ? ADCCR_LCHANENABLE : A_ADCCR_LCHANENABLE;
		if (ch->fmt & AFMT_STEREO)
			val |= sc->is_emu10k1 ? ADCCR_RCHANENABLE : A_ADCCR_RCHANENABLE;
		val |= sc->is_emu10k1 ? emu_k1_recval(ch->spd) : emu_k2_recval(ch->spd);
		emu_wrptr(sc->card, 0, ch->setupreg, 0);
		emu_wrptr(sc->card, 0, ch->setupreg, val);
		ch->ihandle = emu_intr_register(sc->card, ch->irqmask, ch->iprmask, &emu_pcm_intr, sc);
		break;
	case PCMTRIG_STOP:
		/* FALLTHROUGH */
	case PCMTRIG_ABORT:
		ch->run = 0;
		emu_wrptr(sc->card, 0, ch->sizereg, 0);
		if (ch->setupreg)
			emu_wrptr(sc->card, 0, ch->setupreg, 0);
		(void)emu_intr_unregister(sc->card, ch->ihandle);
		break;
	case PCMTRIG_EMLDMAWR:
		/* FALLTHROUGH */
	case PCMTRIG_EMLDMARD:
		/* FALLTHROUGH */
	default:
		break;
	}
	snd_mtxunlock(sc->lock);

	return (0);
}

static int
emurchan_getptr(kobj_t obj __unused, void *c_devinfo)
{
	struct emu_pcm_rchinfo *ch = c_devinfo;
	struct emu_pcm_info *sc = ch->pcm;
	int r;

	r = emu_rdptr(sc->card, 0, ch->idxreg) & 0x0000ffff;

	return (r);
}

static struct pcmchan_caps *
emurchan_getcaps(kobj_t obj __unused, void *c_devinfo __unused)
{
	return (&emu_reccaps);
}

static kobj_method_t emurchan_methods[] = {
	KOBJMETHOD(channel_init, emurchan_init),
	KOBJMETHOD(channel_setformat, emurchan_setformat),
	KOBJMETHOD(channel_setspeed, emurchan_setspeed),
	KOBJMETHOD(channel_setblocksize, emurchan_setblocksize),
	KOBJMETHOD(channel_trigger, emurchan_trigger),
	KOBJMETHOD(channel_getptr, emurchan_getptr),
	KOBJMETHOD(channel_getcaps, emurchan_getcaps),
	{0, 0}
};
CHANNEL_DECLARE(emurchan);


static uint32_t
emu_pcm_intr(void *pcm, uint32_t stat)
{
	struct emu_pcm_info *sc = (struct emu_pcm_info *)pcm;
	uint32_t ack;
	int i;

	ack = 0;

	if (stat & IPR_INTERVALTIMER) {
		ack |= IPR_INTERVALTIMER;
		for (i = 0; i < MAX_CHANNELS; i++)
			if (sc->pch[i].channel) {
				if (sc->pch[i].run == 1)
					chn_intr(sc->pch[i].channel);
				else
					emu_timer_enable(sc->card, sc->pch[i].timer, 0);
			}
	}


	if (stat & (IPR_ADCBUFFULL | IPR_ADCBUFHALFFULL)) {
		ack |= stat & (IPR_ADCBUFFULL | IPR_ADCBUFHALFFULL);
		if (sc->rch.channel)
			chn_intr(sc->rch.channel);
	}
	return (ack);
}

static int
emu_pcm_init(struct emu_pcm_info *sc)
{
	sc->bufsz = pcm_getbuffersize(sc->dev, 4096, EMU_DEFAULT_BUFSZ, EMU_MAX_BUFSZ);
	return (0);
}

static int
emu_pcm_uninit(struct emu_pcm_info *sc __unused)
{
	return (0);
}

static int
emu_pcm_probe(device_t dev)
{
	uintptr_t func, route, r;
	const char *rt;
	char buffer[255];

	r = BUS_READ_IVAR(device_get_parent(dev), dev, EMU_VAR_FUNC, &func);

	if (func != SCF_PCM)
		return (ENXIO);

	rt = "UNKNOWN";
	r = BUS_READ_IVAR(device_get_parent(dev), dev, EMU_VAR_ROUTE, &route);
	switch (route) {
	case RT_FRONT:
		rt = "FRONT";
		break;
	case RT_REAR:
		rt = "REAR";
		break;
	case RT_CENTER:
		rt = "CENTER";
		break;
	case RT_SUB:
		rt = "SUBWOOFER";
		break;
	case RT_SIDE:
		rt = "SIDE";
		break;
	}

	snprintf(buffer, 255, "EMU10Kx DSP %s PCM Interface", rt);
	device_set_desc_copy(dev, buffer);
	return (0);
}

static int
emu_pcm_attach(device_t dev)
{
	struct emu_pcm_info *sc;
	unsigned int i;
	char status[SND_STATUSLEN];
	uint32_t inte, ipr;
	uintptr_t route, r, is_emu10k1;

	if ((sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK | M_ZERO)) == NULL) {
		device_printf(dev, "cannot allocate softc\n");
		return (ENXIO);
	}
	bzero(sc, sizeof(*sc));

	sc->card = (struct emu_sc_info *)(device_get_softc(device_get_parent(dev)));
	if (sc->card == NULL) {
		device_printf(dev, "cannot get bridge conf\n");
		return (ENXIO);
	}

	sc->lock = snd_mtxcreate(device_get_nameunit(dev), "sound softc");
	sc->dev = dev;

	r = BUS_READ_IVAR(device_get_parent(dev), dev, EMU_VAR_ISEMU10K1, &is_emu10k1);
	sc->is_emu10k1 = is_emu10k1 ? 1 : 0;

	sc->codec = NULL;

	for (i = 0; i < 8; i++) {
		sc->rt.routing_left[i] = i;
		sc->rt.amounts_left[i] = 0x00;
		sc->rt.routing_right[i] = i;
		sc->rt.amounts_right[i] = 0x00;
	}

	r = BUS_READ_IVAR(device_get_parent(dev), dev, EMU_VAR_ROUTE, &route);
	sc->route = route;
	switch (route) {
	case RT_FRONT:
		sc->rt.amounts_left[0] = 0xff;
		sc->rt.amounts_right[1] = 0xff;
		if (sc->is_emu10k1)
			sc->codec = AC97_CREATE(dev, sc, emu_ac97);
		else
			sc->codec = AC97_CREATE(dev, sc, emu_eac97);
 		if (sc->codec == NULL) {
 			if (mixer_init(dev, &emudspmixer_class, sc)) {
 				device_printf(dev, "failed to initialize DSP mixer\n");
 				goto bad;
 			}
 		} else
			if (mixer_init(dev, ac97_getmixerclass(), sc->codec) == -1) {
 				device_printf(dev, "can't initialize AC97 mixer!\n");
 				goto bad;
			}
		break;
	case RT_REAR:
		sc->rt.amounts_left[2] = 0xff;
		sc->rt.amounts_right[3] = 0xff;
		if (mixer_init(dev, &emudspmixer_class, sc)) {
			device_printf(dev, "failed to initialize mixer\n");
			goto bad;
		}
		break;
	case RT_CENTER:
		sc->rt.amounts_left[4] = 0xff;
		if (mixer_init(dev, &emudspmixer_class, sc)) {
			device_printf(dev, "failed to initialize mixer\n");
			goto bad;
		}
		break;
	case RT_SUB:
		sc->rt.amounts_left[5] = 0xff;
		if (mixer_init(dev, &emudspmixer_class, sc)) {
			device_printf(dev, "failed to initialize mixer\n");
			goto bad;
		}
		break;
	case RT_SIDE:
		sc->rt.amounts_left[6] = 0xff;
		sc->rt.amounts_right[7] = 0xff;
		if (mixer_init(dev, &emudspmixer_class, sc)) {
			device_printf(dev, "failed to initialize mixer\n");
			goto bad;
		}
		break;
	default:
		device_printf(dev, "invalid default route\n");
		goto bad;
	}

	inte = INTE_INTERVALTIMERENB;
	ipr = IPR_INTERVALTIMER; /* Used by playback */
	sc->ihandle = emu_intr_register(sc->card, inte, ipr, &emu_pcm_intr, sc);

	if (emu_pcm_init(sc) == -1) {
		device_printf(dev, "unable to initialize PCM part of the card\n");
		goto bad;
	}

	/* XXX we should better get number of available channels from parent */
	if (pcm_register(dev, sc, (route == RT_FRONT) ? MAX_CHANNELS : 1, (route == RT_FRONT) ? 1 : 0)) {
		device_printf(dev, "can't register PCM channels!\n");
		goto bad;
	}
	sc->pnum = 0;
	pcm_addchan(dev, PCMDIR_PLAY, &emupchan_class, sc);
	if (route == RT_FRONT) {
		for (i = 1; i < MAX_CHANNELS; i++)
			pcm_addchan(dev, PCMDIR_PLAY, &emupchan_class, sc);
		pcm_addchan(dev, PCMDIR_REC, &emurchan_class, sc);
	}
	snprintf(status, SND_STATUSLEN, "on %s", device_get_nameunit(device_get_parent(dev)));
	pcm_setstatus(dev, status);

	return (0);

bad:
	if (sc->codec)
		ac97_destroy(sc->codec);
	if (sc->lock)
		snd_mtxfree(sc->lock);
	free(sc, M_DEVBUF);
	return (ENXIO);
}

static int
emu_pcm_detach(device_t dev)
{
	int r;
	struct emu_pcm_info *sc;

	sc = pcm_getdevinfo(dev);

	r = pcm_unregister(dev);

	if (r) 	return (r);

	emu_pcm_uninit(sc);

	if (sc->lock)
		snd_mtxfree(sc->lock);
	free(sc, M_DEVBUF);

	return (0);
}

static device_method_t emu_pcm_methods[] = {
	DEVMETHOD(device_probe, emu_pcm_probe),
	DEVMETHOD(device_attach, emu_pcm_attach),
	DEVMETHOD(device_detach, emu_pcm_detach),

	{0, 0}
};

static driver_t emu_pcm_driver = {
	"pcm",
	emu_pcm_methods,
	PCM_SOFTC_SIZE,
	NULL,
	0,
	NULL
};
DRIVER_MODULE(snd_emu10kx_pcm, emu10kx, emu_pcm_driver, pcm_devclass, 0, 0);
MODULE_DEPEND(snd_emu10kx_pcm, snd_emu10kx, SND_EMU10KX_MINVER, SND_EMU10KX_PREFVER, SND_EMU10KX_MAXVER);
MODULE_DEPEND(snd_emu10kx_pcm, sound, SOUND_MINVER, SOUND_PREFVER, SOUND_MAXVER);
MODULE_VERSION(snd_emu10kx_pcm, SND_EMU10KX_PREFVER);
