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
 *	$Id: conf.c,v 1.63 1995/02/14 22:36:49 jkh Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/tty.h>
#include <sys/conf.h>

d_rdwr_t rawread, rawwrite;
d_strategy_t swstrategy;

/* Lots of bogus defines for shorthand purposes */
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
#define nodump		(d_dump_t *)enodev

#define nxopen		(d_open_t *)enxio
#define	nxclose		(d_close_t *)enxio
#define	nxread		(d_rdwr_t *)enxio
#define	nxwrite		nxread
#define	nxstrategy	(d_strategy_t *)enxio
#define	nxioctl		(d_ioctl_t *)enxio
#define	nxdump		(d_dump_t *)enxio
#define nxstop		(d_stop_t *)enxio
#define nxreset		(d_reset_t *)enxio
#define nxselect	(d_select_t *)enxio
#define nxmmap		(d_mmap_t *)enxio

#define nullopen	(d_open_t *)nullop
#define nullclose	(d_close_t *)nullop
#define nullstop	(d_stop_t *)nullop
#define nullreset	(d_reset_t *)nullop

#define zerosize	(d_psize_t *)0

int lkmenodev();
#define	lkmopen		(d_open_t *)lkmenodev
#define	lkmclose	(d_close_t *)lkmenodev
#define lkmread		(d_rdwr_t *)lkmenodev
#define lkmwrite	(d_rdwr_t *)lkmenodev
#define	lkmstrategy	(d_strategy_t *)lkmenodev
#define	lkmioctl	(d_ioctl_t *)lkmenodev
#define	lkmdump		(d_dump_t *)lkmenodev
#define	lkmsize		zerosize
#define lkmstop		(d_stop_t *)lkmenodev
#define lkmreset	(d_reset_t *)lkmenodev
#define lkmmmap		(d_mmap_t *)lkmenodev
#define lkmselect	(d_select_t *)lkmenodev

#include "wd.h"
#if (NWD > 0)
d_open_t	wdopen;
d_close_t	wdclose;
d_strategy_t	wdstrategy;
d_ioctl_t	wdioctl;
d_dump_t	wddump;
d_psize_t	wdsize;
#else
#define	wdopen		nxopen
#define	wdclose		nxclose
#define	wdstrategy	nxstrategy
#define	wdioctl		nxioctl
#define	wddump		nxdump
#define	wdsize		zerosize
#endif

#include "sd.h"
#if NSD > 0
d_open_t	sdopen;
d_close_t	sdclose;
d_strategy_t	sdstrategy;
d_ioctl_t	sdioctl;
d_dump_t	sddump;
d_psize_t	sdsize;
#else
#define	sdopen		nxopen
#define	sdclose		nxclose
#define	sdstrategy	nxstrategy
#define	sdioctl		nxioctl
#define	sddump		nxdump
#define	sdsize		zerosize
#endif

#include "st.h"
#if NST > 0
d_open_t	stopen;
d_close_t	stclose;
d_strategy_t	ststrategy;
d_ioctl_t	stioctl;
/*int	stdump(),stsize();*/
#define	stdump		nxdump
#define	stsize		zerosize
#else
#define	stopen		nxopen
#define	stclose		nxclose
#define	ststrategy	nxstrategy
#define	stioctl		nxioctl
#define	stdump		nxdump
#define	stsize		zerosize
#endif

#include "cd.h"
#if NCD > 0
d_open_t	cdopen;
d_close_t	cdclose;
d_strategy_t	cdstrategy;
d_ioctl_t	cdioctl;
d_psize_t	cdsize;
#define	cddump		nxdump
#else
#define	cdopen		nxopen
#define	cdclose		nxclose
#define	cdstrategy	nxstrategy
#define	cdioctl		nxioctl
#define	cddump		nxdump
#define	cdsize		zerosize
#endif

#include "mcd.h"
#if NMCD > 0
d_open_t	mcdopen;
d_close_t	mcdclose;
d_strategy_t	mcdstrategy;
d_ioctl_t	mcdioctl;
d_psize_t	mcdsize;
#define	mcddump		nxdump
#else
#define	mcdopen		nxopen
#define	mcdclose	nxclose
#define	mcdstrategy	nxstrategy
#define	mcdioctl	nxioctl
#define	mcddump		nxdump
#define	mcdsize		zerosize
#endif

#include "scd.h"
#if NSCD > 0
d_open_t	scdopen;
d_close_t	scdclose;
d_strategy_t	scdstrategy;
d_ioctl_t	scdioctl;
d_psize_t	scdsize;
#define	scddump		nxdump
#else
#define	scdopen		nxopen
#define	scdclose	nxclose
#define	scdstrategy	nxstrategy
#define	scdioctl	nxioctl
#define	scddump		nxdump
#define	scdsize		zerosize
#endif

#include "pcd.h"
#if NPCD > 0
d_open_t	pcdopen;
d_close_t	pcdclose;
d_strategy_t	pcdstrategy;
d_ioctl_t	pcdioctl;
d_psize_t	pcdsize;
#define	pcddump		nxdump
#else
#define	pcdopen		nxopen
#define	pcdclose	nxclose
#define	pcdstrategy	nxstrategy
#define	pcdioctl	nxioctl
#define	pcddump		nxdump
#define	pcdsize		zerosize
#endif

#include "ch.h"
#if NCH > 0
d_open_t	chopen;
d_close_t	chclose;
d_ioctl_t	chioctl;
#else
#define	chopen		nxopen
#define	chclose		nxclose
#define	chioctl		nxioctl
#endif

#include "wt.h"
#if NWT > 0
d_open_t	wtopen;
d_close_t	wtclose;
d_strategy_t	wtstrategy;
d_ioctl_t	wtioctl;
d_dump_t	wtdump;
d_psize_t	wtsize;
#else
#define	wtopen		nxopen
#define	wtclose		nxclose
#define	wtstrategy	nxstrategy
#define	wtioctl		nxioctl
#define	wtdump		nxdump
#define	wtsize		zerosize
#endif

#include "fd.h"
#if NFD > 0
d_open_t	Fdopen;
d_close_t	fdclose;
d_strategy_t	fdstrategy;
d_ioctl_t	fdioctl;
#define	fddump		nxdump
#define	fdsize		zerosize
#else
#define	Fdopen		nxopen
#define	fdclose		nxclose
#define	fdstrategy	nxstrategy
#define	fdioctl		nxioctl
#define	fddump		nxdump
#define	fdsize		zerosize
#endif

#include "vn.h"
#if NVN > 0
d_open_t	vnopen;
d_close_t	vnclose;
d_strategy_t	vnstrategy;
d_ioctl_t	vnioctl;
d_dump_t	vndump;
d_psize_t	vnsize;
#else
#define	vnopen		nxopen
#define	vnclose		nxclose
#define	vnstrategy	nxstrategy
#define	vnioctl		nxioctl
#define	vndump		nxdump
#define	vnsize		zerosize
#endif

#define swopen		noopen
#define swclose		noclose
#define swioctl		noioc
#define swdump		nodump
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
	/* block device 14 is reserved for local use */
	{ nxopen,	nxclose,	nxstrategy,	nxioctl,	/*14*/
	  nxdump,	zerosize,	NULL },
	{ vnopen,	vnclose,	vnstrategy,	vnioctl,	/*15*/
	  vndump,	vnsize,		0 },
	{ scdopen,	scdclose,	scdstrategy,	scdioctl,	/*16*/
	  scddump,	scdsize,	0 },
	{ pcdopen,	pcdclose,	pcdstrategy,	pcdioctl,	/*17*/
	  pcddump,	pcdsize,	0 }
/*
 * If you need a bdev major number for a driver that you intend to donate
 * back to the group or release publically, please contact the FreeBSD team
 * by sending mail to "FreeBSD-hackers@freefall.cdrom.com".
 * If you assign one yourself it may conflict with someone else.
 * Otherwise, simply use the one reserved for local use.
 */
};
int	nblkdev = sizeof (bdevsw) / sizeof (bdevsw[0]);

/* console */
#include "machine/cons.h"

/* more console */
#include "sc.h"
#include "vt.h"
#if NSC > 0
d_open_t	scopen;
d_close_t	scclose;
d_rdwr_t	scread, scwrite;
d_ioctl_t	scioctl;
d_mmap_t	scmmap;
extern	struct tty sccons[];
#else
#define scopen		nxopen
#define scclose		nxclose
#define scread		nxread
#define scwrite		nxwrite
#define scioctl		nxioctl
#define scmmap		nxmmap
#define sccons		NULL
#endif

/* controlling TTY */
d_open_t	cttyopen;
d_rdwr_t	cttyread;
d_rdwr_t	cttywrite;
d_ioctl_t	cttyioctl;
d_select_t	cttyselect;

/* /dev/mem */
d_open_t	mmopen;
d_close_t	mmclose;
d_rdwr_t	mmrw;
d_mmap_t	memmmap;
#define	mmselect	seltrue

#include "pty.h"
#if NPTY > 0
d_open_t	ptsopen;
d_close_t	ptsclose;
d_rdwr_t	ptsread, ptswrite;
d_stop_t	ptsstop;
d_open_t	ptcopen;
d_close_t	ptcclose;
d_rdwr_t	ptcread;
d_rdwr_t	ptcwrite;
d_select_t	ptcselect;
d_ioctl_t	ptyioctl;
extern struct	tty pt_tty[];
#else
#define ptsopen		nxopen
#define ptsclose	nxclose
#define ptsread		nxread
#define ptswrite	nxwrite
#define ptcopen		nxopen
#define ptcclose	nxclose
#define ptcread		nxread
#define ptcwrite	nxwrite
#define ptyioctl	nxioctl
#define	pt_tty		NULL
#define	ptcselect	nxselect
#define	ptsstop		nullstop
#endif


#include "snp.h"
#if NSNP > 0
d_open_t	snpopen;
d_close_t	snpclose;
d_rdwr_t	snpread;
d_select_t	snpselect;
d_ioctl_t	snpioctl;
#else
#define snpopen		nxopen
#define snpclose	nxclose
#define snpread		nxread
#define snpioctl	nxioctl
#define	snpselect	nxselect
#endif


/* /dev/klog */
d_open_t	logopen;
d_close_t	logclose;
d_rdwr_t	logread;
d_ioctl_t	logioctl;
d_select_t	logselect;

#include "bqu.h"
#if NBQU > 0
d_open_t	bquopen;
d_close_t	bquclose;
d_rdwr_t	bquread, bquwrite;
d_select_t	bquselect; 
d_ioctl_t	bquioctl;
#else 
#define bquopen         nxopen 
#define bquclose        nxclose
#define bquread         nxread
#define bquwrite        nxwrite
#define bquselect       nxselect
#define bquioctl        nxioctl 
#endif

#include "lpt.h"
#if NLPT > 0
d_open_t	lptopen;
d_close_t	lptclose;
d_rdwr_t	lptwrite;
d_ioctl_t	lptioctl;
#else
#define	lptopen		nxopen
#define	lptclose	nxclose
#define	lptwrite	nxwrite
#define	lptioctl	nxioctl
#endif

#include "tw.h"
#if NTW > 0
d_open_t	twopen;
d_close_t	twclose;
d_rdwr_t	twread, twwrite;
d_select_t	twselect;
#else
#define twopen		nxopen
#define twclose		nxclose
#define twread		nxread
#define twwrite		nxwrite
#define twselect	nxselect
#endif

#include "psm.h"
#if NPSM > 0
d_open_t	psmopen;
d_close_t	psmclose;
d_rdwr_t	psmread;
d_select_t	psmselect;
d_ioctl_t	psmioctl;
#else
#define psmopen		nxopen
#define psmclose	nxclose
#define psmread		nxread
#define psmselect	nxselect
#define psmioctl	nxioctl
#endif

#include "snd.h"                 /* General Sound Driver */
#if     NSND > 0
d_open_t	sndopen;
d_close_t	sndclose;
d_ioctl_t	sndioctl;
d_rdwr_t	sndread, sndwrite;
d_select_t	sndselect;
#else
#define sndopen         nxopen
#define sndclose        nxclose
#define sndioctl       	nxioctl
#define sndread         nxread
#define sndwrite        nxwrite
#define sndselect       seltrue
#endif

#include "vat_audio.h"		/* BSD audio driver emulator for voxware */
#if     NVAT_AUDIO > 0		/* not general purpose, just vat */
d_open_t	vaopen;
d_close_t	vaclose;
d_ioctl_t	vaioctl;
d_rdwr_t	varead, vawrite;
d_select_t	vaselect;
#else
#define vaopen          nxopen
#define vaclose         nxclose
#define vaioctl         nxioctl
#define varead          nxread
#define vawrite         nxwrite
#define vaselect        seltrue
#endif

/* /dev/fd/NNN */
d_open_t fdopen;

#include "bpfilter.h"
#if NBPFILTER > 0
d_open_t	bpfopen;
d_close_t	bpfclose;
d_rdwr_t	bpfread, bpfwrite;
d_select_t	bpfselect;
d_ioctl_t	bpfioctl;
#else
#define	bpfopen		nxopen
#define	bpfclose	nxclose
#define	bpfread		nxread
#define	bpfwrite	nxwrite
#define	bpfselect	nxselect
#define	bpfioctl	nxioctl
#endif

#include "speaker.h"
#if NSPEAKER > 0
d_open_t	spkropen;
d_close_t	spkrclose;
d_rdwr_t	spkrwrite;
d_ioctl_t	spkrioctl;
#else
#define spkropen	nxopen
#define spkrclose	nxclose
#define spkrwrite	nxwrite
#define spkrioctl	nxioctl
#endif

#include "pca.h"
#if NPCA > 0
d_open_t	pcaopen;
d_close_t	pcaclose;
d_rdwr_t	pcawrite;
d_ioctl_t	pcaioctl;
d_select_t	pcaselect;
#else
#define pcaopen		nxopen
#define pcaclose	nxclose
#define pcawrite	nxwrite
#define pcaioctl	nxioctl
#define pcaselect	nxselect
#endif

#include "mse.h"
#if NMSE > 0
d_open_t	mseopen;
d_close_t	mseclose;
d_rdwr_t	mseread;
d_select_t	mseselect;
#else
#define	mseopen		nxopen
#define	mseclose	nxclose
#define	mseread		nxread
#define	mseselect	nxselect
#endif

#include "sio.h"
#if NSIO > 0
d_open_t	sioopen;
d_close_t	sioclose;
d_rdwr_t	sioread, siowrite;
d_ioctl_t	sioioctl;
d_select_t	sioselect;
d_stop_t	siostop;
#define sioreset	nxreset
extern	struct tty sio_tty[];
#else
#define sioopen		nxopen
#define sioclose	nxclose
#define sioread		nxread
#define siowrite	nxwrite
#define sioioctl	nxioctl
#define siostop		nxstop
#define sioreset	nxreset
#define sioselect	nxselect
#define	sio_tty		(struct tty *)NULL
#endif

#include "su.h"
#if NSU > 0
d_open_t	suopen;
d_close_t	suclose;
d_ioctl_t	suioctl;
d_rdwr_t	suread, suwrite;
d_select_t	suselect;
#define	summap		nxmmap
d_strategy_t	sustrategy;
#else
#define	suopen		nxopen
#define	suclose		nxclose
#define	suioctl		nxioctl
#define	suread		nxread
#define	suwrite		nxwrite
#define	suselect	nxselect
#define	summap		nxmmap
#define	sustrategy	nxstrategy
#endif

#include "uk.h"
#if NUK > 0
d_open_t	ukopen;
d_close_t	ukclose;
d_ioctl_t	ukioctl;
#else
#define	ukopen		nxopen
#define	ukclose		nxclose
#define	ukioctl		nxioctl
#endif

d_open_t	lkmcopen;
d_close_t	lkmcclose;
d_ioctl_t	lkmcioctl;

#include "apm.h"
#if NAPM > 0
d_open_t	apmopen;
d_close_t	apmclose;
d_ioctl_t	apmioctl;
#else
#define	apmopen		nxopen
#define	apmclose	nxclose
#define	apmioctl	nxioctl
#endif

#ifdef IBCS2
d_open_t	sockopen;
d_close_t	sockclose;
d_ioctl_t	sockioctl;
#else
#define	sockopen	nxopen
#define	sockclose	nxclose
#define	sockioctl	nxioctl
#endif

#include "ctx.h"
#if NCTX > 0
d_open_t	ctxopen;
d_close_t	ctxclose;
d_rdwr_t	ctxread;
d_rdwr_t	ctxwrite;
d_ioctl_t	ctxioctl;
#else
#define ctxopen		nxopen
#define ctxclose	nxclose
#define ctxread		nxread
#define ctxwrite	nxwrite
#define ctxioctl	nxioctl
#endif

#include "ssc.h"
#if NSSC > 0
d_open_t	sscopen;
d_close_t	sscclose;
d_ioctl_t	sscioctl;
d_rdwr_t	sscread, sscwrite;
d_select_t	sscselect;
#define	sscmmap		nxmmap
d_strategy_t	sscstrategy;
#else
#define	sscopen		nxopen
#define	sscclose	nxclose
#define	sscioctl	nxioctl
#define	sscread		nxread
#define	sscwrite	nxwrite
#define	sscselect	nxselect
#define	sscmmap		nxmmap
#define	sscstrategy	nxstrategy
#endif

#include "cx.h"
#if NCX > 0
d_open_t	cxopen;
d_close_t	cxclose;
d_rdwr_t	cxread, cxwrite;
d_ioctl_t	cxioctl;
d_select_t	cxselect;
d_stop_t	cxstop;
extern	struct tty cx_tty[];
#else
#define cxopen		nxopen
#define cxclose		nxclose
#define cxread		nxread
#define cxwrite		nxwrite
#define cxioctl		nxioctl
#define cxstop		nxstop
#define cxselect	nxselect
#define cx_tty		(struct tty *)NULL
#endif

#include "gp.h"
#if NGP > 0
d_open_t	gpopen;
d_close_t	gpclose;
d_rdwr_t	gpwrite;
d_ioctl_t	gpioctl; 
#else   
#define gpopen  	nxopen
#define gpclose 	nxclose
#define gpwrite 	nxwrite
#define gpioctl 	nxioctl
#endif

#include "gsc.h"
#if NGSC > 0
d_open_t	gscopen;
d_close_t	gscclose;
d_rdwr_t	gscread;
d_ioctl_t	gscioctl; 
#else   
#define gscopen		nxopen
#define gscclose	nxclose
#define gscread		nxread
#define gscioctl	nxioctl
#endif

#include "joy.h"
#if NJOY > 0
d_open_t	joyopen;
d_close_t	joyclose;
d_rdwr_t	joyread;
d_ioctl_t	joyioctl;
#else
#define joyopen		nxopen
#define joyclose	nxclose
#define joyread		nxread
#define	joyioctl	nxioctl
#endif

#include "tun.h"
#if NTUN > 0
d_open_t	tunopen;
d_close_t	tunclose;
d_rdwr_t	tunread, tunwrite;
d_ioctl_t	tunioctl;
d_select_t	tunselect;
#else
#define tunopen         nxopen
#define tunclose        nxclose
#define tunread         nxread
#define tunwrite        nxwrite
#define tunioctl        nxioctl
#define tunselect       nxselect
#endif

#include "spigot.h"     
#if     NSPIGOT > 0     
d_open_t        spigot_open;
d_close_t       spigot_close;
d_ioctl_t       spigot_ioctl;
d_rdwr_t        spigot_read, spigot_write;
d_select_t      spigot_select;
d_mmap_t        spigot_mmap;
#else
#define spigot_open     nxopen     
#define spigot_close    nxclose     
#define spigot_ioctl    nxioctl     
#define spigot_read     nxread     
#define spigot_write    nxwrite     
#define spigot_select   seltrue     
#define spigot_mmap     nommap
#endif

/* Cyclades serial driver */
#include "cy.h"
#if	NCY > 0
d_open_t        cyopen;
d_close_t       cyclose;
d_read_t        cyread;
d_write_t       cywrite;
d_ioctl_t	cyioctl;
d_stop_t        cystop;
d_reset_t       cyreset;
d_select_t      cyselect;
d_mmap_t        cymmap;
d_strategy_t    cystrategy;
extern	struct tty cy_tty[];
#else
#define	cyopen		nxopen
#define cyclose		nxclose
#define cyread		nxread
#define cywrite		nxwrite
#define cyioctl		nxioctl
#define cystop		nxstop
#define cyreset		nxreset
#define cyselect	nxselect
#define cymmap		nxmmap
#define cystrategy	nxstrategy
#define cy_tty          (struct tty *)NULL
#endif

#include "ity.h"
#if NITY > 0
int	ityopen(),ityclose(),ityread(),itywrite(),ityioctl(),ityselect();
#define ityreset	nxreset
extern	struct tty ity_tty[];
#else
#define ityopen		nxopen
#define ityclose	nxclose
#define ityread		nxread
#define itywrite	nxwrite
#define ityioctl	nxioctl
#define ityreset	nxreset
#define ityselect	nxselect
#define	ity_tty		(struct tty *)NULL
#endif

#include "nic.h"
#if NNIC > 0
int	nicopen(),nicclose(),nicioctl();
#else
#define nicopen		nxopen
#define nicclose	nxclose
#define nicioctl	nxioctl
#endif

#include "nnic.h"
#if NNNIC > 0
int     nnicopen(),nnicclose(),nnicioctl();
#else
#define nnicopen        nxopen
#define nnicclose       nxclose
#define nnicioctl       nxioctl
#endif

#include "snic.h"
#if NSNIC > 0
int	snicopen(),snicclose(),snicioctl();
#else
#define snicopen	nxopen
#define snicclose	nxclose
#define snicioctl	nxioctl
#endif

#include "isdn.h"
#if NISDN > 0
int	isdnopen(),isdnclose(),isdnread(),isdnioctl();
#else
#define isdnopen	nxopen
#define isdnclose	nxclose
#define isdnread	nxread
#define isdnioctl	nxioctl
#endif

#include "itel.h"
#if NITEL > 0
int	itelopen(),itelclose(),itelread(),itelwrite(),itelioctl();
#else
#define itelopen	nxopen
#define itelclose	nxclose
#define itelread	nxread
#define itelwrite	nxwrite
#define itelioctl	nxioctl
#endif

#include "ispy.h"
#if NISPY > 0
int     ispyopen(),ispyclose(),ispyread(),ispywrite(),ispyioctl();
#else
#define ispyopen        nxopen
#define ispyclose       nxclose
#define ispyread        nxread
#define ispywrite       nxwrite
#define ispyioctl       nxioctl
#endif


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
	{ bquopen,      bquclose,       bquread,        bquwrite,       /*8*/
	  bquioctl,     nostop,         nullreset,      NULL,   /* tputer */
	  bquselect,    nommap,         NULL },
	{ Fdopen,	fdclose,	rawread,	rawwrite,	/*9*/
	  fdioctl,	nostop,		nullreset,	NULL,	/* Fd (!=fd) */
	  seltrue,	nommap,		fdstrategy },
	{ wtopen,	wtclose,	rawread,	rawwrite,	/*10*/
	  wtioctl,	nostop,		nullreset,	NULL,	/* wt */
	  seltrue,	nommap,		wtstrategy },
	{ spigot_open,	spigot_close,	spigot_read,	spigot_write,	/*11*/
	  spigot_ioctl,	nostop,		nullreset,	NULL,	/* Spigot */
	  spigot_select, spigot_mmap,	NULL },
	{ scopen,	scclose,	scread,		scwrite,	/*12*/
	  scioctl,	nullstop,	nullreset,	sccons, /* sc */
	  ttselect,	scmmap,		NULL },
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
	{ suopen,	suclose,	suread,		suwrite,	/*18*/
	  suioctl,	nostop,		nullreset,	NULL,	/* scsi */
	  suselect,	summap,		sustrategy },		/* 'generic' */
	{ twopen,	twclose,	twread,		twwrite,	/*19*/
	  noioc,	nullstop,	nullreset,	NULL,	/* tw */
	  twselect,	nommap,		nostrat },
/*
 * If you need a cdev major number for a driver that you intend to donate
 * back to the group or release publically, please contact the FreeBSD team
 * by sending mail to "FreeBSD-hackers@freefall.cdrom.com".
 * If you assign one yourself it may conflict with someone else.
 * Otherwise, simply use the one reserved for local use.
 */
	/* character device 20 is reserved for local use */
	{ nxopen, nxclose, nxread,	/*20*/
	  nxwrite, nxioctl, nxstop,
	  nxreset, NULL, nxselect,
	  nxmmap, NULL },
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
 	  pcaselect,	nommap,		NULL },
	{ vaopen,	vaclose,	varead,		vawrite,	/*25*/
  	  vaioctl,	nostop,		nullreset,	NULL,	/* vat */
  	  vaselect,	nommap,		NULL },
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
	  mcdioctl,	nostop,		nullreset,	NULL, /* mitsumi cd */
	  seltrue,	nommap,		mcdstrategy },
	{ sndopen,	sndclose,	sndread,	sndwrite,	/*30*/
  	  sndioctl,	nostop,		nullreset,	NULL,	/* sound */
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
	{ apmopen,	apmclose,	noread,		nowrite,	/*39*/
	  apmioctl,	nostop,		nullreset,	NULL, /* laptop APM */
	  seltrue,	nommap,		NULL },
	{ ctxopen,	ctxclose,	ctxread,	ctxwrite,	/*40*/
	  ctxioctl,	nostop,		nullreset,	NULL,	/* cortex */
	  seltrue,	nommap,		NULL },
	{ sockopen,	sockclose,	noread,		nowrite,	/*41*/
	  sockioctl,	nostop,		nullreset,	NULL,	/* socksys */
	  seltrue,	nommap,		NULL },
	{ cxopen,	cxclose,	cxread,		cxwrite,	/*42*/
	  cxioctl,	cxstop,		nullreset,	cx_tty,	/* cronyx */
	  cxselect,	nommap,		NULL },
	{ vnopen,	vnclose,	rawread,	rawwrite,	/*43*/
	  vnioctl,	nostop,		nullreset,	NULL,	/* vn */
	  seltrue,	nommap,		vnstrategy },
	{ gpopen,	gpclose,	noread,		gpwrite,	/*44*/
	  gpioctl,	nostop,		nullreset,	NULL,   /* GPIB */
          seltrue,	nommap,		NULL },                 
	{ scdopen,	scdclose,	rawread,	nowrite,	/*45*/
	  scdioctl,	nostop,		nullreset,	NULL,	/* sony cd */
	  seltrue,	nommap,		scdstrategy },
	{ pcdopen,	pcdclose,	rawread,	nowrite,	/*46*/
	  pcdioctl,	nostop,		nullreset,	NULL,	/* pana cd */
	  seltrue,	nommap,		pcdstrategy },
	{ gscopen,      gscclose,       gscread,        nowrite,	/*47*/
	  gscioctl,     nostop,         nullreset,      NULL,	/* gsc */
	  seltrue,      nommap,         NULL },
	{ cyopen,	cyclose,	cyread,		cywrite,	/*48*/
	  cyioctl,	cystop,		cyreset,	cy_tty,
	  cyselect,	cymmap,		cystrategy },		/* cyclades */
	{ sscopen,	sscclose,	sscread,	sscwrite,	/*49*/
	  sscioctl,	nostop,		nullreset,	NULL, /* scsi super */
	  sscselect,	sscmmap,	sscstrategy },
	{ nxopen,	nxclose,	nxread,		nxwrite,	/*50*/
	  nxioctl,	nxstop,		nxreset,	NULL,	/* pcmcia */
	  nxselect,	nxmmap,		NULL },
	{ joyopen,	joyclose,	joyread,	nowrite,	/*51*/
	  joyioctl,	nostop,		nullreset,	NULL,	/*joystick */
	  seltrue,	nommap,		NULL},
	{ tunopen,      tunclose,       tunread,        tunwrite,       /*52*/
	  tunioctl,     nostop,         nullreset,      NULL,   /* tunnel */
	  tunselect,    nommap,         NULL },
	{ snpopen,	snpclose,	snpread,	nowrite,	/*53*/
	  snpioctl,	nostop,		nullreset,	NULL,	/* snoop */
	  snpselect,	nommap,		NULL },
	{ nicopen,	nicclose,	enodev,		enodev,		/*54*/
	  nicioctl,	nullop,		nullop,		NULL,	/* nic */
	  seltrue,	enodev,		enodev},
	{ isdnopen,	isdnclose,	isdnread,	enodev,		/*55*/
	  isdnioctl,	nullop,		nullop,		NULL,	/* isdn */
	  seltrue,	enodev,		enodev},
	{ ityopen,	ityclose,	ityread,	itywrite,	/*56*/
	  ityioctl,	enodev,		ityreset,	ity_tty,/* ity */
	  ityselect,	enodev,		NULL },
	{ itelopen,	itelclose,	itelread,	itelwrite,	/*57*/
	  itelioctl,	nullop,		nullop,		NULL,	/* itel */
	  seltrue,	enodev,		enodev},
	{ snicopen,	snicclose,	enodev,		enodev,		/*58*/
	  snicioctl,	nullop,		nullop,		NULL,	/* snic */
	  seltrue,	enodev,		enodev},
	{ ispyopen,     ispyclose,      ispyread,       enodev,		/*59*/
	  ispyioctl,    nullop,         nullop,         NULL,   /* ispy */
	  seltrue,      enodev,         enodev},
	{ nnicopen,	nnicclose,	enodev,		enodev,		/*60*/
	  nnicioctl,	nullop,		nullop,		NULL,	/* nnic */
	  seltrue,	enodev,		enodev},
};
int	nchrdev = sizeof (cdevsw) / sizeof (cdevsw[0]);

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
	case 15:
		return (1);
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
	case 29:
	case 43:
		if (type == VCHR)
			return (1);
		/* fall through */
	default:
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Routine to convert from character to block device number.
 *
 * A minimal stub routine can always return NODEV.
 */
dev_t
chrtoblk(dev)
	dev_t dev;
{
	int blkmaj;

	switch (major(dev)) {
	case 3:		blkmaj = 0;  break;
	case 9:		blkmaj = 2;  break;
	case 10:	blkmaj = 3;  break;
	case 13:	blkmaj = 4;  break;
	case 14:	blkmaj = 5;  break;
	case 15:	blkmaj = 6;  break;
	case 29:	blkmaj = 7;  break;
	case 43:	blkmaj = 15; break;
	default:
		return (NODEV);
	}
	return (makedev(blkmaj, minor(dev)));
}
