/*
 * Copyright (c) UNIX System Laboratories, Inc.  All or some portions
 * of this file are derived from material licensed to the
 * University of California by American Telephone and Telegraph Co.
 * or UNIX System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 */
/*
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)conf.c	5.8 (Berkeley) 5/12/91
 *	$Id: conf.c,v 1.30 1994/08/30 20:11:40 davidg Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/tty.h>
#include <sys/conf.h>

typedef int d_open_t __P((dev_t, int, int, struct proc *));
typedef int d_close_t __P((dev_t, int, int, struct proc *));
typedef int d_strategy_t __P((struct buf *));
typedef int d_ioctl_t __P((dev_t, int, caddr_t, int, struct proc *));
typedef int d_dump_t __P(());
typedef int d_psize_t __P((dev_t));

typedef int d_rdwr_t __P((dev_t, struct uio *, int));
typedef int d_stop_t __P((struct tty *, int));
typedef int d_reset_t __P((int));
typedef int d_select_t __P((dev_t, int, struct proc *));
typedef int d_mmap_t __P((/* XXX */));

d_rdwr_t rawread, rawwrite;
d_strategy_t swstrategy;

#ifdef LKM
int lkmenodev();
#define	lkmopen		(d_open_t *)lkmenodev
#define	lkmclose	(d_close_t *)lkmenodev
#define lkmread		(d_rdwr_t *)lkmenodev
#define lkmwrite	(d_rdwr_t *)lkmenodev
#define	lkmstrategy	(d_strategy_t *)lkmenodev
#define	lkmioctl	(d_ioctl_t *)lkmenodev
#define	lkmdump		(d_dump_t *)lkmenodev
#define	lkmsize		(d_psize_t *)0
#define lkmstop		(d_stop_t *)lkmenodev
#define lkmreset	(d_reset_t *)lkmenodev
#define lkmmmap		(d_mmap_t *)lkmenodev
#define lkmselect	(d_select_t *)lkmenodev
#else
#define	lkmopen		(d_open_t *)enxio
#define	lkmclose	(d_close_t *)enxio
#define lkmread		(d_rdwr_t *)enxio
#define lkmwrite	(d_rdwr_t *)enxio
#define	lkmstrategy	(d_strategy_t *)enxio
#define	lkmioctl	(d_ioctl_t *)enxio
#define	lkmdump		(d_dump_t *)enxio
#define	lkmsize		(d_psize_t *)0
#define lkmstop		(d_stop_t *)enxio
#define lkmreset	(d_reset_t *)enxio
#define lkmmmap		(d_mmap_t *)enxio
#define lkmselect	(d_select_t *)enxio
#endif

#include "wd.h"
#if (NWD > 0)
d_open_t wdopen;
d_close_t wdclose;
d_strategy_t wdstrategy;
d_ioctl_t wdioctl;
d_dump_t wddump;
d_psize_t wdsize;
#else
#define	wdopen		(d_open_t *)enxio
#define	wdclose		(d_close_t *)enxio
#define	wdstrategy	(d_strategy_t *)enxio
#define	wdioctl		(d_ioctl_t *)enxio
#define	wddump		(d_dump_t *)enxio
#define	wdsize		(d_psize_t *)0
#endif

#include "sd.h"
#if NSD > 0
d_open_t sdopen;
d_close_t sdclose;
d_strategy_t sdstrategy;
d_ioctl_t sdioctl;
d_dump_t sddump;
d_psize_t sdsize;
#else
#define	sdopen		(d_open_t *)enxio
#define	sdclose		(d_close_t *)enxio
#define	sdstrategy	(d_strategy_t *)enxio
#define	sdioctl		(d_ioctl_t *)enxio
#define	sddump		(d_dump_t *)enxio
#define	sdsize		(d_psize_t *)0
#endif

#include "st.h"
#if NST > 0
d_open_t stopen;
d_close_t stclose;
d_strategy_t ststrategy;
d_ioctl_t stioctl;
/*int	stdump(),stsize();*/
#define	stdump		(d_dump_t *)enxio
#define	stsize		(d_psize_t *)0
#else
#define	stopen		(d_open_t *)enxio
#define	stclose		(d_close_t *)enxio
#define	ststrategy	(d_strategy_t *)enxio
#define	stioctl		(d_ioctl_t *)enxio
#define	stdump		(d_dump_t *)enxio
#define	stsize		(d_psize_t *)0
#endif

#include "cd.h"
#if NCD > 0
d_open_t cdopen;
d_close_t cdclose;
d_strategy_t cdstrategy;
d_ioctl_t cdioctl;
d_psize_t cdsize;
#define	cddump		(d_dump_t *)enxio
#else
#define	cdopen		(d_open_t *)enxio
#define	cdclose		(d_close_t *)enxio
#define	cdstrategy	(d_strategy_t *)enxio
#define	cdioctl		(d_ioctl_t *)enxio
#define	cddump		(d_dump_t *)enxio
#define	cdsize		(d_psize_t *)0
#endif

#include "mcd.h"
#if NMCD > 0
d_open_t mcdopen;
d_close_t mcdclose;
d_strategy_t mcdstrategy;
d_ioctl_t mcdioctl;
d_psize_t mcdsize;
#define	mcddump		(d_dump_t *)enxio
#else
#define	mcdopen		(d_open_t *)enxio
#define	mcdclose	(d_close_t *)enxio
#define	mcdstrategy	(d_strategy_t *)enxio
#define	mcdioctl	(d_ioctl_t *)enxio
#define	mcddump		(d_dump_t *)enxio
#define	mcdsize		(d_psize_t *)0
#endif

#include "ch.h"
#if NCH > 0
d_open_t chopen;
d_close_t chclose;
d_ioctl_t chioctl;
#else
#define	chopen		(d_open_t *)enxio
#define	chclose		(d_close_t *)enxio
#define	chioctl		(d_ioctl_t *)enxio
#endif

#include "wt.h"
#if NWT > 0
d_open_t wtopen;
d_close_t wtclose;
d_strategy_t wtstrategy;
d_ioctl_t wtioctl;
d_dump_t wtdump;
d_psize_t wtsize;
#else
#define	wtopen		(d_open_t *)enxio
#define	wtclose		(d_close_t *)enxio
#define	wtstrategy	(d_strategy_t *)enxio
#define	wtioctl		(d_ioctl_t *)enxio
#define	wtdump		(d_dump_t *)enxio
#define	wtsize		(d_psize_t *)0
#endif

#include "fd.h"
#if NFD > 0
d_open_t Fdopen;
d_close_t fdclose;
d_strategy_t fdstrategy;
d_ioctl_t fdioctl;
#define	fddump		(d_dump_t *)enxio
#define	fdsize		(d_psize_t *)0
#else
#define	Fdopen		(d_open_t *)enxio
#define	fdclose		(d_close_t *)enxio
#define	fdstrategy	(d_strategy_t *)enxio
#define	fdioctl		(d_ioctl_t *)enxio
#define	fddump		(d_dump_t *)enxio
#define	fdsize		(d_psize_t *)0
#endif

#define swopen		(d_open_t *)enodev
#define swclose		(d_close_t *)enodev
#define swioctl		(d_ioctl_t *)enodev
#define swdump		(d_dump_t *)enodev
#define swsize		(d_psize_t *)enodev

d_rdwr_t swread, swwrite;

struct bdevsw	bdevsw[] =
{
	{ wdopen,	wdclose,	wdstrategy,	wdioctl,	/*0*/
	  wddump,	wdsize,		0 },
	{ swopen,	swclose,	swstrategy,	swioctl,	/*1*/
	  swdump,	swsize,		0 },
	{ Fdopen,	fdclose,	fdstrategy,	fdioctl,	/*2*/
	  fddump,	fdsize,		0 },
	{ wtopen,	wtclose,	wtstrategy,	wtioctl,	/*3*/
	  wtdump,	wtsize,		B_TAPE },
	{ sdopen,	sdclose,	sdstrategy,	sdioctl,	/*4*/
	  sddump,	sdsize,		0 },
	{ stopen,	stclose,	ststrategy,	stioctl,	/*5*/
	  stdump,	stsize,		0 },
	{ cdopen,	cdclose,	cdstrategy,	cdioctl,	/*6*/
	  cddump,	cdsize,		0 },
	{ mcdopen,	mcdclose,	mcdstrategy,	mcdioctl,	/*7*/
	  mcddump,	mcdsize,	0 },
#ifdef LKM
	{ lkmopen,	lkmclose,	lkmstrategy,	lkmioctl,	/*8*/
	  lkmdump,	lkmsize,	NULL },
	{ lkmopen,	lkmclose,	lkmstrategy,	lkmioctl,	/*9*/
	  lkmdump,	lkmsize,	NULL },
	{ lkmopen,	lkmclose,	lkmstrategy,	lkmioctl,	/*10*/
	  lkmdump,	lkmsize,	NULL },
	{ lkmopen,	lkmclose,	lkmstrategy,	lkmioctl,	/*11*/
	  lkmdump,	lkmsize,	NULL },
	{ lkmopen,	lkmclose,	lkmstrategy,	lkmioctl,	/*12*/
	  lkmdump,	lkmsize,	NULL },
	{ lkmopen,	lkmclose,	lkmstrategy,	lkmioctl,	/*13*/
	  lkmdump,	lkmsize,	NULL },
#endif
	/* block device 14 is reserved for local use */
	{ (d_open_t *)enxio,		(d_close_t *)enxio,
	  (d_strategy_t *)enxio,	(d_ioctl_t *)enxio,		/*14*/
	  (d_dump_t *)enxio,		(d_psize_t *)0,		NULL }
/*
 * If you need a bdev major number, please contact the FreeBSD team
 * by sending mail to "FreeBSD-hackers@freefall.cdrom.com".
 * If you assign one yourself it may conflict with someone else.
 */
};
int	nblkdev = sizeof (bdevsw) / sizeof (bdevsw[0]);

/* console */
#include "machine/cons.h"

/* more console */
#include "sc.h"
#if NSC > 0
d_open_t pcopen;
d_close_t pcclose;
d_rdwr_t pcread, pcwrite;
d_ioctl_t pcioctl;
d_mmap_t pcmmap;
extern	struct tty pccons[];
#else
#define pcopen		(d_open_t *)enxio
#define pcclose		(d_close_t *)enxio
#define pcread		(d_rdwr_t *)enxio
#define pcwrite		(d_rdwr_t *)enxio
#define pcioctl		(d_ioctl_t *)enxio
#define pcmmap		(d_mmap_t *)enxio
#define pccons		NULL
#endif

/* controlling TTY */
d_open_t cttyopen;
d_rdwr_t cttyread, cttywrite;
d_ioctl_t cttyioctl;
d_select_t cttyselect;

/* /dev/mem */
d_open_t mmopen;
d_close_t mmclose;
d_rdwr_t mmrw;
d_mmap_t memmmap;
#define	mmselect	seltrue

#include "pty.h"
#if NPTY > 0
d_open_t ptsopen;
d_close_t ptsclose;
d_rdwr_t ptsread, ptswrite;
d_stop_t ptsstop;
d_open_t ptcopen;
d_close_t ptcclose;
d_rdwr_t ptcread, ptcwrite;
d_select_t ptcselect;
d_ioctl_t ptyioctl;
extern struct	tty pt_tty[];
#else
#define ptsopen		(d_open_t *)enxio
#define ptsclose	(d_close_t *)enxio
#define ptsread		(d_rdwr_t *)enxio
#define ptswrite	(d_rdwr_t *)enxio
#define ptcopen		(d_open_t *)enxio
#define ptcclose	(d_close_t *)enxio
#define ptcread		(d_rdwr_t *)enxio
#define ptcwrite	(d_rdwr_t *)enxio
#define ptyioctl	(d_ioctl_t *)enxio
#define	pt_tty		NULL
#define	ptcselect	(d_select_t *)enxio
#define	ptsstop		(d_stop_t *)nullop
#endif

/* /dev/klog */
d_open_t logopen;
d_close_t logclose;
d_rdwr_t logread;
d_ioctl_t logioctl;
d_select_t logselect;

#include "lpt.h"
#if NLPT > 0
d_open_t lptopen;
d_close_t lptclose;
d_rdwr_t lptwrite;
d_ioctl_t lptioctl;
#else
#define	lptopen		(d_open_t *)enxio
#define	lptclose	(d_close_t *)enxio
#define	lptwrite	(d_rdwr_t *)enxio
#define	lptioctl	(d_ioctl_t *)enxio
#endif

#include "tw.h"
#if NTW > 0
d_open_t twopen;
d_close_t twclose;
d_rdwr_t twread, twwrite;
d_select_t twselect;
#else
#define twopen		(d_open_t *)enxio
#define twclose		(d_close_t *)enxio
#define twread		(d_rdwr_t *)enxio
#define twwrite		(d_rdwr_t *)enxio
#define twselect	(d_select_t *)enxio
#endif

#include "sb.h"                 /* Sound Blaster */
#if     NSB > 0
d_open_t sbopen;
d_close_t sbclose;
d_ioctl_t sbioctl;
d_rdwr_t sbread, sbwrite;
d_select_t sbselect;
#else
#define sbopen         (d_open_t *)enxio
#define sbclose        (d_close_t *)enxio
#define sbioctl        (d_ioctl_t *)enxio
#define sbread         (d_rdwr_t *)enxio
#define sbwrite        (d_rdwr_t *)enxio
#define sbselect       seltrue
#endif

#include "psm.h"
#if NPSM > 0
d_open_t psmopen;
d_close_t psmclose;
d_rdwr_t psmread;
d_select_t psmselect;
d_ioctl_t psmioctl;
#else
#define psmopen		(d_open_t *)enxio
#define psmclose	(d_close_t *)enxio
#define psmread		(d_rdwr_t *)enxio
#define psmselect	(d_select_t *)enxio
#define psmioctl	(d_ioctl_t *)enxio
#endif

#include "snd.h"                 /* General Sound Driver */
#if     NSND > 0
d_open_t sndopen;
d_close_t sndclose;
d_ioctl_t sndioctl;
d_rdwr_t sndread, sndwrite;
d_select_t sndselect;
#else
#define sndopen         (d_open_t *)enxio
#define sndclose        (d_close_t *)enxio
#define sndioctl        (d_ioctl_t *)enxio
#define sndread         (d_rdwr_t *)enxio
#define sndwrite        (d_rdwr_t *)enxio
#define sndselect       seltrue
#endif

/* /dev/fd/NNN */
d_open_t fdopen;

#include "bpfilter.h"
#if NBPFILTER > 0
d_open_t bpfopen;
d_close_t bpfclose;
d_rdwr_t bpfread, bpfwrite;
d_select_t bpfselect;
d_ioctl_t bpfioctl;
#else
#define	bpfopen		(d_open_t *)enxio
#define	bpfclose	(d_close_t *)enxio
#define	bpfread		(d_rdwr_t *)enxio
#define	bpfwrite	(d_rdwr_t *)enxio
#define	bpfselect	(d_select_t *)enxio
#define	bpfioctl	(d_ioctl_t *)enxio
#endif

#include "speaker.h"
#if NSPEAKER > 0
d_open_t spkropen;
d_close_t spkrclose;
d_rdwr_t spkrwrite;
d_ioctl_t spkrioctl;
#else
#define spkropen	(d_open_t *)enxio
#define spkrclose	(d_close_t *)enxio
#define spkrwrite	(d_rdwr_t *)enxio
#define spkrioctl	(d_ioctl_t *)enxio
#endif

#include "pca.h"
#if NPCA > 0
d_open_t pcaopen;
d_close_t pcaclose;
d_rdwr_t pcawrite;
d_ioctl_t pcaioctl;
#else
#define pcaopen		(d_open_t *)enxio
#define pcaclose	(d_close_t *)enxio
#define pcawrite	(d_rdwr_t *)enxio
#define pcaioctl	(d_ioctl_t *)enxio
#endif

#include "mse.h"
#if NMSE > 0
d_open_t mseopen;
d_close_t mseclose;
d_rdwr_t mseread;
d_select_t mseselect;
#else
#define	mseopen		(d_open_t *)enxio
#define	mseclose	(d_close_t *)enxio
#define	mseread		(d_rdwr_t *)enxio
#define	mseselect	(d_select_t *)enxio
#endif

#include "sio.h"
#if NSIO > 0
d_open_t sioopen;
d_close_t sioclose;
d_rdwr_t sioread, siowrite;
d_ioctl_t sioioctl;
d_select_t sioselect;
d_stop_t siostop;
#define sioreset	(d_reset_t *)enxio
extern	struct tty sio_tty[];
#else
#define sioopen		(d_open_t *)enxio
#define sioclose	(d_close_t *)enxio
#define sioread		(d_rdwr_t *)enxio
#define siowrite	(d_rdwr_t *)enxio
#define sioioctl	(d_ioctl_t *)enxio
#define siostop		(d_stop_t *)enxio
#define sioreset	(d_reset_t *)enxio
#define sioselect	(d_select_t *)enxio
#define	sio_tty		NULL
#endif

#include "su.h"
#if NSU > 0
d_open_t suopen;
d_close_t suclose;
d_ioctl_t suioctl;
#else
#define	suopen		(d_open_t *)enxio
#define	suclose		(d_close_t *)enxio
#define	suioctl		(d_ioctl_t *)enxio
#endif

#include "uk.h"
#if NUK > 0
d_open_t ukopen;
d_close_t ukclose;
d_ioctl_t ukioctl;
#else
#define	ukopen		(d_open_t *)enxio
#define	ukclose		(d_close_t *)enxio
#define	ukioctl		(d_ioctl_t *)enxio
#endif

#ifdef LKM
d_open_t lkmcopen;
d_close_t lkmcclose;
d_ioctl_t lkmcioctl;
#else
#define	lkmcopen	(d_open_t *)enxio
#define lkmcclose	(d_close_t *)enxio
#define lkmcioctl	(d_ioctl_t *)enxio
#endif

#define noopen		(d_open_t *)enodev
#define noclose		(d_close_t *)enodev
#define noread		(d_rdwr_t *)enodev
#define nowrite		noread
#define noioc		(d_ioctl_t *)enodev
#define nostop		(d_stop_t *)enodev
#define noreset		(d_reset_t *)enodev
#define noselect	(d_select_t *)enodev
#define nommap		(d_mmap_t *)enodev
#define nostrat		(d_strategy_t *)enodev

#define nullopen	(d_open_t *)nullop
#define nullclose	(d_close_t *)nullop
#define nullstop	(d_stop_t *)nullop
#define nullreset	(d_reset_t *)nullop

/* open, close, read, write, ioctl, stop, reset, ttys, select, mmap, strat */
struct cdevsw	cdevsw[] =
{
	{ cnopen,	cnclose,	cnread,		cnwrite,	/*0*/
	  cnioctl,	nullstop,	nullreset,	NULL,	/* console */
	  cnselect,	nommap,		NULL },
	{ cttyopen,	nullclose,	cttyread,	cttywrite,	/*1*/
	  cttyioctl,	nullstop,	nullreset,	NULL,	/* tty */
	  cttyselect,	nommap,		NULL },
	{ mmopen,	mmclose,	mmrw,		mmrw,		/*2*/
	  noioc,	nullstop,	nullreset,	NULL,	/* memory */
	  mmselect,	memmmap,	NULL },
	{ wdopen,	wdclose,	rawread,	rawwrite,	/*3*/
	  wdioctl,	nostop,		nullreset,	NULL,	/* wd */
	  seltrue,	nommap,		wdstrategy },
	{ nullopen,	nullclose,	rawread,	rawwrite,	/*4*/
	  noioc,	nostop,		noreset,	NULL,	/* swap */
	  noselect,	nommap,		swstrategy },
	{ ptsopen,	ptsclose,	ptsread,	ptswrite,	/*5*/
	  ptyioctl,	ptsstop,	nullreset,	pt_tty, /* ttyp */
	  ttselect,	nommap,		NULL },
	{ ptcopen,	ptcclose,	ptcread,	ptcwrite,	/*6*/
	  ptyioctl,	nullstop,	nullreset,	pt_tty, /* ptyp */
	  ptcselect,	nommap,		NULL },
	{ logopen,	logclose,	logread,	nowrite,	/*7*/
	  logioctl,	nostop,		nullreset,	NULL,	/* klog */
	  logselect,	nommap,		NULL },
	{ (d_open_t *)enxio,	(d_close_t *)enxio,	(d_rdwr_t *)enxio, /*8*/
	  (d_rdwr_t *)enxio,	(d_ioctl_t *)enxio,	(d_stop_t *)enxio, /* unused */
	  (d_reset_t *)enxio,	NULL,			(d_select_t *)enxio,
	  (d_mmap_t *)enxio,	NULL },
	{ Fdopen,	fdclose,	rawread,	rawwrite,	/*9*/
	  fdioctl,	nostop,		nullreset,	NULL,	/* Fd (!=fd) */
	  seltrue,	nommap,		fdstrategy },
	{ wtopen,	wtclose,	rawread,	rawwrite,	/*10*/
	  wtioctl,	nostop,		nullreset,	NULL,	/* wt */
	  seltrue,	nommap,		wtstrategy },
	{ noopen,	noclose,	noread,		nowrite,	/*11*/
	  noioc,	nostop,		nullreset,	NULL,
	  seltrue,	nommap,		nostrat },
	{ pcopen,	pcclose,	pcread,		pcwrite,	/*12*/
	  pcioctl,	nullstop,	nullreset,	pccons, /* pc */
	  ttselect,	pcmmap,		NULL },
	{ sdopen,	sdclose,	rawread,	rawwrite,	/*13*/
	  sdioctl,	nostop,		nullreset,	NULL,	/* sd */
	  seltrue,	nommap,		sdstrategy },
	{ stopen,	stclose,	rawread,	rawwrite,	/*14*/
	  stioctl,	nostop,		nullreset,	NULL,	/* st */
	  seltrue,	nommap,		ststrategy },
	{ cdopen,	cdclose,	rawread,	nowrite,	/*15*/
	  cdioctl,	nostop,		nullreset,	NULL,	/* cd */
	  seltrue,	nommap,		cdstrategy },
	{ lptopen,	lptclose,	noread,		lptwrite,	/*16*/
	  lptioctl,	nullstop,	nullreset,	NULL,	/* lpt */
	  seltrue,	nommap,		nostrat},
	{ chopen,	chclose,	noread,		nowrite,	/*17*/
	  chioctl,	nostop,		nullreset,	NULL,	/* ch */
	  noselect,	nommap,		nostrat },
	{ suopen,	suclose,	noread,		nowrite,	/*18*/
	  suioctl,	nostop,		nullreset,	NULL,	/* scsi 'generic' */
	  seltrue,	nommap,		nostrat },
	{ twopen,	twclose,	twread,		twwrite,	/*19*/
	  noioc,	nullstop,	nullreset,	NULL,	/* tw */
	  twselect,	nommap,		nostrat },
	{ sbopen,	sbclose,	sbread,		sbwrite,	/*20*/
	  sbioctl,	nostop,		nullreset,	NULL,	/* soundblaster*/
	  sbselect,	nommap,		NULL },
	{ psmopen,	psmclose,	psmread,	nowrite,	/*21*/
	  psmioctl,	nostop,		nullreset,	NULL,	/* psm mice */
	  psmselect,	nommap,		NULL },
	{ fdopen,	noclose,	noread,		nowrite,	/*22*/
	  noioc,	nostop,		nullreset,	NULL,	/* fd (!=Fd) */
	  noselect,	nommap,		nostrat },
 	{ bpfopen,	bpfclose,	bpfread,	bpfwrite,	/*23*/
 	  bpfioctl,	nostop,		nullreset,	NULL,	/* bpf */
 	  bpfselect,	nommap,		NULL },
 	{ pcaopen,      pcaclose,       noread,         pcawrite,       /*24*/
 	  pcaioctl,     nostop,         nullreset,      NULL,	/* pcaudio */
 	  seltrue,	nommap,		NULL },
	{ (d_open_t *)enxio,	(d_close_t *)enxio,	(d_rdwr_t *)enxio, /*25*/
	  (d_rdwr_t *)enxio,	(d_ioctl_t *)enxio,	(d_stop_t *)enxio, /* unused */
	  (d_reset_t *)enxio,	NULL,			(d_select_t *)enxio,
	  (d_mmap_t *)enxio,	NULL },
	{ spkropen,     spkrclose,      noread,         spkrwrite,      /*26*/
	  spkrioctl,    nostop,         nullreset,      NULL,	/* spkr */
	  seltrue,	nommap,		NULL },
	{ mseopen,	mseclose,	mseread,	nowrite,	/*27*/
	  noioc,	nostop,		nullreset,	NULL,	/* mse */
	  mseselect,	nommap,		NULL },
	{ sioopen,	sioclose,	sioread,	siowrite,	/*28*/
	  sioioctl,	siostop,	sioreset,	sio_tty, /* sio */
	  sioselect,	nommap,		NULL },
	{ mcdopen,	mcdclose,	rawread,	nowrite,	/*29*/
	  mcdioctl,	nostop,		nullreset,	NULL,	/* mitsumi cd */
	  seltrue,	nommap,		mcdstrategy },
	{ sndopen,	sndclose,	sndread,	sndwrite,	/*30*/
  	  sndioctl,	nostop,		nullreset,	NULL,	/* sound driver */
  	  sndselect,	nommap,		NULL },
	{ ukopen,	ukclose,	noread,         nowrite,      	/*31*/
	  ukioctl,	nostop,		nullreset,	NULL,	/* unknown */
	  seltrue,	nommap,		NULL },			/* scsi */
	{ lkmcopen,	lkmcclose,	noread,		nowrite,	/*32*/
	  lkmcioctl,	nostop,		nullreset,	NULL,
	  noselect,	nommap,		NULL },
	{ lkmopen,	lkmclose,	lkmread,	lkmwrite,	/*33*/
	  lkmioctl,	lkmstop,	lkmreset,	NULL,
	  lkmselect,	lkmmmap,	NULL },
	{ lkmopen,	lkmclose,	lkmread,	lkmwrite,	/*34*/
	  lkmioctl,	lkmstop,	lkmreset,	NULL,
	  lkmselect,	lkmmmap,	NULL },
	{ lkmopen,	lkmclose,	lkmread,	lkmwrite,	/*35*/
	  lkmioctl,	lkmstop,	lkmreset,	NULL,
	  lkmselect,	lkmmmap,	NULL },
	{ lkmopen,	lkmclose,	lkmread,	lkmwrite,	/*36*/
	  lkmioctl,	lkmstop,	lkmreset,	NULL,
	  lkmselect,	lkmmmap,	NULL },
	{ lkmopen,	lkmclose,	lkmread,	lkmwrite,	/*37*/
	  lkmioctl,	lkmstop,	lkmreset,	NULL,
	  lkmselect,	lkmmmap,	NULL },
	{ lkmopen,	lkmclose,	lkmread,	lkmwrite,	/*38*/
	  lkmioctl,	lkmstop,	lkmreset,	NULL,
	  lkmselect,	lkmmmap,	NULL },
	/* character device 39 is reserved for local use */
	{ (d_open_t *)enxio,	(d_close_t *)enxio,	(d_rdwr_t *)enxio, /*39*/
	  (d_rdwr_t *)enxio,	(d_ioctl_t *)enxio,	(d_stop_t *)enxio,
	  (d_reset_t *)enxio,	NULL,			(d_select_t *)enxio,
	  (d_mmap_t *)enxio,	NULL }
/*
 * If you need a cdev major number, please contact the FreeBSD team
 * by sending mail to `freebsd-hackers@freefall.cdrom.com'.
 * If you assign one yourself it may then conflict with someone else.
 */
};
int	nchrdev = sizeof (cdevsw) / sizeof (cdevsw[0]);

int	mem_no = 2; 	/* major device number of memory special file */

/*
 * Swapdev is a fake device implemented
 * in sw.c used only internally to get to swstrategy.
 * It cannot be provided to the users, because the
 * swstrategy routine munches the b_dev and b_blkno entries
 * before calling the appropriate driver.  This would horribly
 * confuse, e.g. the hashing routines. Instead, /dev/drum is
 * provided as a character (raw) device.
 */
dev_t	swapdev = makedev(1, 0);

/*
 * Routine that identifies /dev/mem and /dev/kmem.
 *
 * A minimal stub routine can always return 0.
 */
int
iskmemdev(dev)
	dev_t dev;
{

	return (major(dev) == 2 && (minor(dev) == 0 || minor(dev) == 1));
}

int
iszerodev(dev)
	dev_t dev;
{
	return (major(dev) == 2 && minor(dev) == 12);
}

/*
 * Routine to determine if a device is a disk.
 *
 * A minimal stub routine can always return 0.
 */
int
isdisk(dev, type)
	dev_t dev;
	int type;
{

	switch (major(dev)) {
	case 0:
	case 2:
	case 4:
	case 6:
	case 7:
		if (type == VBLK)
			return (1);
		return (0);
	case 3:
	case 9:
	case 13:
	case 15:
	case 29:
		if (type == VCHR)
			return (1);
		/* fall through */
	default:
		return (0);
	}
	/* NOTREACHED */
}

#define MAXDEV 32
static int chrtoblktbl[MAXDEV] =  {
	/* VCHR */	/* VBLK */
	/* 0 */		NODEV,
	/* 1 */		NODEV,
	/* 2 */		NODEV,
	/* 3 */		0,
	/* 4 */		NODEV,
	/* 5 */		NODEV,
	/* 6 */		NODEV,
	/* 7 */		NODEV,
	/* 8 */		NODEV,
	/* 9 */		2,
	/* 10 */	3,
	/* 11 */	NODEV,
	/* 12 */	NODEV,
	/* 13 */	4,
	/* 14 */	5,
	/* 15 */	6,
	/* 16 */	NODEV,
	/* 17 */	NODEV,
	/* 18 */	NODEV,
	/* 19 */	NODEV,
	/* 20 */	NODEV,
	/* 21 */	NODEV,
	/* 22 */	NODEV,
	/* 23 */	NODEV,
	/* 25 */	NODEV,
	/* 26 */	NODEV,
	/* 27 */	NODEV,
	/* 28 */	NODEV,
	/* 29 */	7,
	/* 30 */	NODEV,
	/* 31 */	NODEV,
};
/*
 * Routine to convert from character to block device number.
 *
 * A minimal stub routine can always return NODEV.
 */
int
chrtoblk(dev)
	dev_t dev;
{
	int blkmaj;

	if (major(dev) >= MAXDEV || (blkmaj = chrtoblktbl[major(dev)]) == NODEV)
		return (NODEV);
	return (makedev(blkmaj, minor(dev)));
}
