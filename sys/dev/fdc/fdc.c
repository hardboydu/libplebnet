/*#define DEBUG 1*/
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Don Ahn.
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
 *	from:	@(#)fd.c	7.4 (Berkeley) 5/25/91
 *	$Id: fd.c,v 1.22 1994/03/02 08:10:42 alm Exp $
 *
 */

#include "ft.h"
#if NFT < 1
#undef NFDC
#endif
#include "fd.h"

#if NFDC > 0

#include <sys/param.h>
#include <sys/dkbad.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <machine/ioctl_fd.h>
#include <sys/disklabel.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/syslog.h>
#include "i386/isa/isa.h"
#include "i386/isa/isa_device.h"
#include "i386/isa/fdreg.h"
#include "i386/isa/fdc.h"
#include "i386/isa/icu.h"
#include "i386/isa/rtc.h"

#if NFT > 0
extern int ftopen(), ftintr(), ftattach(), ftclose(), ftioctl();
#endif

#define b_cylin b_resid
#define FDBLK 512

/* misuse a flag to identify format operation */
#define B_FORMAT B_XXX

#define NUMTYPES 14
#define NUMDENS  (NUMTYPES - 6)

/* This defines (-1) must match index for fd_types */
#define F_TAPE_TYPE	0x020	/* bit for fd_types to indicate tape */
#define NO_TYPE		0	/* must match NO_TYPE in ft.c */
#define FD_1720         1
#define FD_1480         2
#define FD_1440         3
#define FD_1200         4
#define FD_820          5
#define FD_800          6
#define FD_720          7
#define FD_360          8

#define FD_1480in5_25   9
#define FD_1440in5_25   10
#define FD_820in5_25    11
#define FD_800in5_25    12
#define FD_720in5_25    13
#define FD_360in5_25    14


struct fd_type fd_types[NUMTYPES] =
{
{ 21,2,0xFF,0x04,82,3444,1,FDC_500KBPS,2,0x0C,2 }, /* 1.72M in HD 3.5in */
{ 18,2,0xFF,0x1B,82,2952,1,FDC_500KBPS,2,0x6C,1 }, /* 1.48M in HD 3.5in */
{ 18,2,0xFF,0x1B,80,2880,1,FDC_500KBPS,2,0x6C,1 }, /* 1.44M in HD 3.5in */
{ 15,2,0xFF,0x1B,80,2400,1,FDC_500KBPS,2,0x54,1 }, /*  1.2M in HD 5.25/3.5 */
{ 10,2,0xFF,0x10,82,1640,1,FDC_250KBPS,2,0x2E,1 }, /*  820K in HD 3.5in */
{ 10,2,0xFF,0x10,80,1600,1,FDC_250KBPS,2,0x2E,1 }, /*  800K in HD 3.5in */
{  9,2,0xFF,0x20,80,1440,1,FDC_250KBPS,2,0x50,1 }, /*  720K in HD 3.5in */
{  9,2,0xFF,0x2A,40, 720,1,FDC_250KBPS,2,0x50,1 }, /*  360K in DD 5.25in */

{ 18,2,0xFF,0x02,82,2952,1,FDC_500KBPS,2,0x02,2 }, /* 1.48M in HD 5.25in */
{ 18,2,0xFF,0x02,80,2880,1,FDC_500KBPS,2,0x02,2 }, /* 1.44M in HD 5.25in */
{ 10,2,0xFF,0x10,82,1640,1,FDC_300KBPS,2,0x2E,1 }, /*  820K in HD 5.25in */
{ 10,2,0xFF,0x10,80,1600,1,FDC_300KBPS,2,0x2E,1 }, /*  800K in HD 5.25in */
{  9,2,0xFF,0x20,80,1440,1,FDC_300KBPS,2,0x50,1 }, /*  720K in HD 5.25in */
{  9,2,0xFF,0x23,40, 720,2,FDC_300KBPS,2,0x50,1 }, /*  360K in HD 5.25in */
};

#define DRVS_PER_CTLR 2		/* 2 floppies */
/***********************************************************************\
* Per controller structure.						*
\***********************************************************************/
struct fdc_data fdc_data[NFDC];

/***********************************************************************\
* Per drive structure.							*
* N per controller  (DRVS_PER_CTLR)					*
\***********************************************************************/
struct fd_data {
	struct	fdc_data *fdc;	/* pointer to controller structure */
	int	fdsu;		/* this units number on this controller */
	int	type;		/* Drive type (HD, DD     */
	struct	fd_type *ft;	/* pointer to the type descriptor */
	int	flags;
#define	FD_OPEN		0x01	/* it's open		*/
#define	FD_ACTIVE	0x02	/* it's active		*/
#define	FD_MOTOR	0x04	/* motor should be on	*/
#define	FD_MOTOR_WAIT	0x08	/* motor coming up	*/
	int skip;
	int hddrv;
	int track;		/* where we think the head is */
} fd_data[NFD];

/***********************************************************************\
* Throughout this file the following conventions will be used:		*
* fd is a pointer to the fd_data struct for the drive in question	*
* fdc is a pointer to the fdc_data struct for the controller		*
* fdu is the floppy drive unit number					*
* fdcu is the floppy controller unit number				*
* fdsu is the floppy drive unit number on that controller. (sub-unit)	*
\***********************************************************************/

#define	id_physid id_scsiid	/* this biotab field doubles as a field */
				/* for the physical unit number on the controller */

static int retrier(fdcu_t);

#define DEVIDLE		0
#define FINDWORK	1
#define	DOSEEK		2
#define SEEKCOMPLETE 	3
#define	IOCOMPLETE	4
#define RECALCOMPLETE	5
#define	STARTRECAL	6
#define	RESETCTLR	7
#define	SEEKWAIT	8
#define	RECALWAIT	9
#define	MOTORWAIT	10
#define	IOTIMEDOUT	11

#ifdef	DEBUG
char *fdstates[] =
{
"DEVIDLE",
"FINDWORK",
"DOSEEK",
"SEEKCOMPLETE",
"IOCOMPLETE",
"RECALCOMPLETE",
"STARTRECAL",
"RESETCTLR",
"SEEKWAIT",
"RECALWAIT",
"MOTORWAIT",
"IOTIMEDOUT"
};


int	fd_debug = 1;
#define TRACE0(arg) if(fd_debug) printf(arg)
#define TRACE1(arg1,arg2) if(fd_debug) printf(arg1,arg2)
#else /* DEBUG */
#define TRACE0(arg)
#define TRACE1(arg1,arg2)
#endif /* DEBUG */

static void fdstart(fdcu_t);
void fdintr(fdcu_t);
static void fd_turnoff(caddr_t, int);

/****************************************************************************/
/*                      autoconfiguration stuff                             */
/****************************************************************************/
static int fdprobe(struct isa_device *);
static int fdattach(struct isa_device *);

struct	isa_driver fdcdriver = {
	fdprobe, fdattach, "fdc",
};

/*
 * probe for existance of controller
 */
int
fdprobe(dev)
	struct isa_device *dev;
{
	fdcu_t	fdcu = dev->id_unit;
	if(fdc_data[fdcu].flags & FDC_ATTACHED)
	{
		printf("fdc: same unit (%d) used multiple times\n",fdcu);
		return 0;
	}

	fdc_data[fdcu].baseport = dev->id_iobase;

	/* First - lets reset the floppy controller */

	outb(dev->id_iobase+fdout,0);
	DELAY(100);
	outb(dev->id_iobase+fdout,FDO_FRST);

	/* see if it can handle a command */
	if (out_fdc(fdcu,NE7CMD_SPECIFY) < 0)
	{
		return(0);
	}
	out_fdc(fdcu,0xDF);
	out_fdc(fdcu,2);
	return (IO_FDCSIZE);
}

/*
 * wire controller into system, look for floppy units
 */
int
fdattach(dev)
	struct isa_device *dev;
{
	unsigned fdt,st0, cyl;
	int	hdr;
	fdu_t	fdu;
	fdcu_t	fdcu = dev->id_unit;
	fdc_p	fdc = fdc_data + fdcu;
	fd_p	fd;
	int	fdsu;
	struct isa_device *fdup;

	fdc->fdcu = fdcu;
	fdc->flags |= FDC_ATTACHED;
	fdc->dmachan = dev->id_drq;
	fdc->state = DEVIDLE;
	hdr = 0;
	printf("fdc%d:", fdcu);

	/* check for each floppy drive */
	for (fdup = isa_biotab_fdc; fdup->id_driver != 0; fdup++) {
		if (fdup->id_iobase != dev->id_iobase)
			continue;
		fdu = fdup->id_unit;
		fd = &fd_data[fdu];
		if (fdu >= (NFD+NFT))
			continue;
		fdsu = fdup->id_physid;
				/* look up what bios thinks we have */
		switch (fdu) {
			case 0: fdt = (rtcin(RTC_FDISKETTE) & 0xf0);
				break;
			case 1: fdt = ((rtcin(RTC_FDISKETTE) << 4) & 0xf0);
				break;
			default: fdt = RTCFDT_NONE;
				break;
		}
		/* is there a unit? */
		if ((fdt == RTCFDT_NONE)
#if NFT > 0
		|| (fdsu >= DRVS_PER_CTLR)) {
#else
		) {
			fd->type = NO_TYPE;
#endif
#if NFT > 0
				/* If BIOS says no floppy, or > 2nd device */
				/* Probe for and attach a floppy tape.     */
			if (ftattach(dev, fdup))
				continue;
			if (fdsu < DRVS_PER_CTLR) 
				fd->type = NO_TYPE;
#endif
			continue;
		}

#ifdef notyet
		/* select it */
		fd_turnon1(fdu);
		spinwait(1000);	/* 1 sec */
		out_fdc(fdcu,NE7CMD_RECAL);	/* Recalibrate Function */
		out_fdc(fdcu,fdsu);
		spinwait(1000);	/* 1 sec */

		/* anything responding */
		out_fdc(fdcu,NE7CMD_SENSEI);
		st0 = in_fdc(fdcu);
		cyl = in_fdc(fdcu);
		if (st0 & 0xd0)
			continue;

#endif
		fd->track = -2;
		fd->fdc = fdc;
		fd->fdsu = fdsu;
		printf(" [%d: fd%d: ", fdsu, fdu);
		
		switch (fdt) {
		case RTCFDT_12M:
			printf("1.2MB 5.25in]");
			fd->type = FD_1200;
			break;
		case RTCFDT_144M:
			printf("1.44MB 3.5in]");
			fd->type = FD_1440;
			break;
		case RTCFDT_360K:
			printf("360KB 5.25in]");
			fd->type = FD_360;
			break;
		case RTCFDT_720K:
			printf("720KB 3.5in]");
			fd->type = FD_720;
			break;
		default:
			printf("unknown]");
			fd->type = NO_TYPE;
			break;
		}

		fd_turnoff((caddr_t)fdu, 0);
		hdr = 1;
	}
	printf("\n");

	/* Set transfer to 500kbps */
	outb(fdc->baseport+fdctl,0); /*XXX*/
	return 1;
}

int
fdsize(dev)
	dev_t	dev;
{
	return(0);
}

/****************************************************************************/
/*                               fdstrategy                                 */
/****************************************************************************/
void fdstrategy(struct buf *bp)
{
	register struct buf *dp,*dp0,*dp1;
	long nblocks,blknum;
 	int	s;
 	fdcu_t	fdcu;
 	fdu_t	fdu;
 	fdc_p	fdc;
 	fd_p	fd;

 	fdu = FDUNIT(minor(bp->b_dev));
	fd = &fd_data[fdu];
	fdc = fd->fdc;
	fdcu = fdc->fdcu;

#if NFT > 0
	/* check for controller already busy with tape */
	if (fdc->flags & FDC_TAPE_BUSY) {
		bp->b_error = EBUSY;
		bp->b_flags |= B_ERROR;
		return; 
		}
#endif
	if ((fdu >= NFD) || (bp->b_blkno < 0)) {
		printf("fdstrat: fdu = %d, blkno = %d, bcount = %d\n",
			fdu, bp->b_blkno, bp->b_bcount);
		pg("fd:error in fdstrategy");
		bp->b_error = EINVAL;
		bp->b_flags |= B_ERROR;
		goto bad;
	}
	/*
	 * Set up block calculations.
	 */
	blknum = (unsigned long) bp->b_blkno * DEV_BSIZE/FDBLK;
 	nblocks = fd->ft->size;
	if (blknum + (bp->b_bcount / FDBLK) > nblocks) {
		if (blknum == nblocks) {
			bp->b_resid = bp->b_bcount;
		} else {
			bp->b_error = ENOSPC;
			bp->b_flags |= B_ERROR;
		}
		goto bad;
	}
 	bp->b_cylin = blknum / (fd->ft->sectrac * fd->ft->heads);
	dp = &(fdc->head);
	s = splbio();
	disksort(dp, bp);
	untimeout(fd_turnoff, (caddr_t)fdu); /* a good idea */
	fdstart(fdcu);
	splx(s);
	return;

bad:
	biodone(bp);
	return;
}

/****************************************************************************/
/*                            motor control stuff                           */
/*		remember to not deselect the drive we're working on         */
/****************************************************************************/
void
set_motor(fdcu, fdu, reset)
	fdcu_t fdcu;
	fdu_t fdu;
	int reset;
{
	int m0,m1;
	int selunit;
	fd_p fd;
	if(fd = fdc_data[fdcu].fd)/* yes an assign! */
	{
		selunit =  fd->fdsu;
	}
	else
	{
		selunit = 0;
	}
	m0 = fd_data[fdcu * DRVS_PER_CTLR + 0].flags & FD_MOTOR;
	m1 = fd_data[fdcu * DRVS_PER_CTLR + 1].flags & FD_MOTOR;
	outb(fdc_data[fdcu].baseport+fdout,
		selunit
		| (reset ? 0 : (FDO_FRST|FDO_FDMAEN))
		| (m0 ? FDO_MOEN0 : 0)
		| (m1 ? FDO_MOEN1 : 0));
	TRACE1("[0x%x->fdout]",(
		selunit
		| (reset ? 0 : (FDO_FRST|FDO_FDMAEN))
		| (m0 ? FDO_MOEN0 : 0)
		| (m1 ? FDO_MOEN1 : 0)));
}

static void
fd_turnoff(caddr_t arg1, int arg2)
{
	fdu_t fdu = (fdu_t)arg1;
	int	s;

	fd_p fd = fd_data + fdu;
	s = splbio();
	fd->flags &= ~FD_MOTOR;
	set_motor(fd->fdc->fdcu,fd->fdsu,0);
	splx(s);
}

void
fd_motor_on(caddr_t arg1, int arg2)
{
	fdu_t fdu = (fdu_t)arg1;
	int	s;

	fd_p fd = fd_data + fdu;
	s = splbio();
	fd->flags &= ~FD_MOTOR_WAIT;
	if((fd->fdc->fd == fd) && (fd->fdc->state == MOTORWAIT))
	{
		fdintr(fd->fdc->fdcu);
	}
	splx(s);
}

static void fd_turnon1(fdu_t);

void
fd_turnon(fdu) 
	fdu_t fdu;
{
	fd_p fd = fd_data + fdu;
	if(!(fd->flags & FD_MOTOR))
	{
		fd_turnon1(fdu);
		fd->flags |= FD_MOTOR_WAIT;
		timeout(fd_motor_on, (caddr_t)fdu, hz); /* in 1 sec its ok */
	}
}

static void
fd_turnon1(fdu_t fdu) 
{
	fd_p fd = fd_data + fdu;
	fd->flags |= FD_MOTOR;
	set_motor(fd->fdc->fdcu,fd->fdsu,0);
}

/****************************************************************************/
/*                             fdc in/out                                   */
/****************************************************************************/
int
in_fdc(fdcu)
	fdcu_t fdcu;
{
	int baseport = fdc_data[fdcu].baseport;
	int i, j = 100000;
	while ((i = inb(baseport+fdsts) & (NE7_DIO|NE7_RQM))
		!= (NE7_DIO|NE7_RQM) && j-- > 0)
		if (i == NE7_RQM) return -1;
	if (j <= 0)
		return(-1);
#ifdef	DEBUG
	i = inb(baseport+fddata);
	TRACE1("[fddata->0x%x]",(unsigned char)i);
	return(i);
#else
	return inb(baseport+fddata);
#endif
}

int
out_fdc(fdcu, x)
	fdcu_t fdcu;
	int x;
{
	int baseport = fdc_data[fdcu].baseport;
	int i;

	/* Check that the direction bit is set */
	i = 100000;
	while ((inb(baseport+fdsts) & NE7_DIO) && i-- > 0);
	if (i <= 0) return (-1);	/* Floppy timed out */

	/* Check that the floppy controller is ready for a command */
	i = 100000;
	while ((inb(baseport+fdsts) & NE7_RQM) == 0 && i-- > 0);
	if (i <= 0) return (-1);	/* Floppy timed out */

	/* Send the command and return */
	outb(baseport+fddata,x);
	TRACE1("[0x%x->fddata]",x);
	return (0);
}

/****************************************************************************/
/*                           fdopen/fdclose                                 */
/****************************************************************************/
int
Fdopen(dev, flags)
	dev_t	dev;
	int	flags;
{
 	fdu_t fdu = FDUNIT(minor(dev));
	int type = FDTYPE(minor(dev));
	fdc_p	fdc;

#if NFT > 0
	/* check for a tape open */
	if (type & F_TAPE_TYPE)
		return(ftopen(dev, flags));
#endif
	/* check bounds */
	if (fdu >= NFD) 
		return(ENXIO);
	fdc = fd_data[fdu].fdc;
	if ((fdc == NULL) || (fd_data[fdu].type == NO_TYPE))
		return(ENXIO);
	if (type > NUMDENS)
		return(ENXIO);
	if (type == 0)
		type = fd_data[fdu].type;
	else {
		if (type != fd_data[fdu].type) {
			switch (fd_data[fdu].type) {
			case FD_360:
				return(ENXIO);
			case FD_720:
				if (   type != FD_820
				    && type != FD_800
				   )
					return(ENXIO);
				break;
			case FD_1200:
				switch (type) {
				case FD_1480:
					type = FD_1480in5_25;
					break;
				case FD_1440:
					type = FD_1440in5_25;
					break;
				case FD_820:
					type = FD_820in5_25;
					break;
				case FD_800:
					type = FD_800in5_25;
					break;
				case FD_720:
					type = FD_720in5_25;
					break;
				case FD_360:
					type = FD_360in5_25;
					break;
				default:
					return(ENXIO);
				}
				break;
			case FD_1440:
				if (   type != FD_1720
				    && type != FD_1480
				    && type != FD_1200
				    && type != FD_820
				    && type != FD_800
				    && type != FD_720
				    )
					return(ENXIO);
				break;
			}
		}
	}
	fd_data[fdu].ft = fd_types + type - 1;
	fd_data[fdu].flags |= FD_OPEN;

	return 0;
}

int
fdclose(dev, flags)
	dev_t dev;
	int flags;
{
 	fdu_t fdu = FDUNIT(minor(dev));
	int type = FDTYPE(minor(dev));

#if NFT > 0
	if (type & F_TAPE_TYPE)
		return ftclose(0);
#endif
	fd_data[fdu].flags &= ~FD_OPEN;
	return(0);
}


/***************************************************************\
*				fdstart				*
* We have just queued something.. if the controller is not busy	*
* then simulate the case where it has just finished a command	*
* So that it (the interrupt routine) looks on the queue for more*
* work to do and picks up what we just added.			*
* If the controller is already busy, we need do nothing, as it	*
* will pick up our work when the present work completes		*
\***************************************************************/
static void
fdstart(fdcu)
	fdcu_t fdcu;
{
	register struct buf *dp,*bp;
	int s;
 	fdu_t fdu;

	s = splbio();
	if(fdc_data[fdcu].state == DEVIDLE)
	{
		fdintr(fdcu);
	}
	splx(s);
}

static void
fd_timeout(caddr_t arg1, int arg2)
{
	fdcu_t fdcu = (fdcu_t)arg1;
	fdu_t fdu = fdc_data[fdcu].fdu;
	int st0, st3, cyl;
	struct buf *dp,*bp;
	int	s;

	dp = &fdc_data[fdcu].head;
	s = splbio();
	bp = dp->b_actf;

	out_fdc(fdcu,NE7CMD_SENSED);
	out_fdc(fdcu,fd_data[fdu].hddrv);
	st3 = in_fdc(fdcu);

	out_fdc(fdcu,NE7CMD_SENSEI);
	st0 = in_fdc(fdcu);
	cyl = in_fdc(fdcu);
	printf("fd%d: Operation timeout ST0 %b cyl %d ST3 %b\n",
			fdu,
			st0,
			NE7_ST0BITS,
			cyl,
			st3,
			NE7_ST3BITS);

	if (bp)
	{
		retrier(fdcu);
		fdc_data[fdcu].status[0] = 0xc0;
		fdc_data[fdcu].state = IOTIMEDOUT;
		if( fdc_data[fdcu].retry < 6)
			fdc_data[fdcu].retry = 6;
	}
	else
	{
		fdc_data[fdcu].fd = (fd_p) 0;
		fdc_data[fdcu].fdu = -1;
		fdc_data[fdcu].state = DEVIDLE;
	}
	fdintr(fdcu);
	splx(s);
}

/* just ensure it has the right spl */
static void
fd_pseudointr(caddr_t arg1, int arg2)
{
	fdcu_t fdcu = (fdcu_t)arg1;
	int	s;
	s = splbio();
	fdintr(fdcu);
	splx(s);
}

/***********************************************************************\
*                                 fdintr				*
* keep calling the state machine until it returns a 0			*
* ALWAYS called at SPLBIO 						*
\***********************************************************************/
void
fdintr(fdcu_t fdcu)
{
	fdc_p fdc = fdc_data + fdcu;
#if NFT > 0
	fdu_t fdu = fdc->fdu;

	if (fdc->flags & FDC_TAPE_BUSY)
		(ftintr(fdu));
	else
#endif
	while(fdstate(fdcu, fdc))
	  ;
}

/***********************************************************************\
* The controller state machine.						*
* if it returns a non zero value, it should be called again immediatly	*
\***********************************************************************/
int
fdstate(fdcu, fdc)
	fdcu_t fdcu;
	fdc_p fdc;
{
	int read, format, head, trac, sec = 0, i = 0, s, sectrac, cyl, st0;
	unsigned long blknum;
	fdu_t fdu = fdc->fdu;
	fd_p fd;
	register struct buf *dp,*bp;
	struct fd_formb *finfo = NULL;

	dp = &(fdc->head);
	bp = dp->b_actf;
	if(!bp) 
	{
		/***********************************************\
		* nothing left for this controller to do	*
		* Force into the IDLE state,			*
		\***********************************************/
		fdc->state = DEVIDLE;
		if(fdc->fd)
		{
			printf("unexpected valid fd pointer (fdu = %d)\n"
						,fdc->fdu);
			fdc->fd = (fd_p) 0;
			fdc->fdu = -1;
		}
		TRACE1("[fdc%d IDLE]",fdcu);
 		return(0);
	}
	fdu = FDUNIT(minor(bp->b_dev));
	fd = fd_data + fdu;
	if (fdc->fd && (fd != fdc->fd))
	{
		printf("confused fd pointers\n");
	}
	read = bp->b_flags & B_READ;
	format = bp->b_flags & B_FORMAT;
	if(format)
		finfo = (struct fd_formb *)bp->b_un.b_addr;
	TRACE1("fd%d",fdu);
	TRACE1("[%s]",fdstates[fdc->state]);
	TRACE1("(0x%x)",fd->flags);
	untimeout(fd_turnoff, (caddr_t)fdu);
	timeout(fd_turnoff, (caddr_t)fdu, 4 * hz);
	switch (fdc->state)
	{
	case DEVIDLE:
	case FINDWORK:	/* we have found new work */
		fdc->retry = 0;
		fd->skip = 0;
		fdc->fd = fd;
		fdc->fdu = fdu;
		/*******************************************************\
		* If the next drive has a motor startup pending, then	*
		* it will start up in it's own good time		*
		\*******************************************************/
		if(fd->flags & FD_MOTOR_WAIT)
		{
			fdc->state = MOTORWAIT;
			return(0); /* come back later */
		}
		/*******************************************************\
		* Maybe if it's not starting, it SHOULD be starting	*
		\*******************************************************/
		if (!(fd->flags & FD_MOTOR))
		{
			fdc->state = MOTORWAIT;
			fd_turnon(fdu);
			return(0);
		}
		else	/* at least make sure we are selected */
		{
			set_motor(fdcu,fd->fdsu,0);
		}
		fdc->state = DOSEEK;
		break;
	case DOSEEK:
		if (bp->b_cylin == fd->track)
		{
			fdc->state = SEEKCOMPLETE;
			break;
		}
		out_fdc(fdcu,NE7CMD_SEEK);	/* Seek function */
		out_fdc(fdcu,fd->fdsu);		/* Drive number */
		out_fdc(fdcu,bp->b_cylin * fd->ft->steptrac);
		fd->track = -2;
		fdc->state = SEEKWAIT;
		timeout(fd_timeout, (caddr_t)fdcu, 2 * hz);
		return(0);	/* will return later */
	case SEEKWAIT:
		untimeout(fd_timeout, (caddr_t)fdcu);
		/* allow heads to settle */
		timeout(fd_pseudointr, (caddr_t)fdcu, hz / 50);
		fdc->state = SEEKCOMPLETE;
		return(0);	/* will return later */
		break;
		
	case SEEKCOMPLETE : /* SEEK DONE, START DMA */
		/* Make sure seek really happened*/
		if(fd->track == -2)
		{
			int descyl = bp->b_cylin * fd->ft->steptrac;
			out_fdc(fdcu,NE7CMD_SENSEI);
			i = in_fdc(fdcu);
			cyl = in_fdc(fdcu);
			if (cyl != descyl)
			{
				printf("fd%d: Seek to cyl %d failed; am at cyl %d (ST0 = 0x%x)\n",
				fdu, descyl, cyl, i, NE7_ST0BITS);
				return(retrier(fdcu));
			}
		}

		fd->track = bp->b_cylin;
		if(format)
			fd->skip = (char *)&(finfo->fd_formb_cylno(0))
				- (char *)finfo;
		isa_dmastart(bp->b_flags, bp->b_un.b_addr+fd->skip,
			format ? bp->b_bcount : FDBLK, fdc->dmachan);
		blknum = (unsigned long)bp->b_blkno*DEV_BSIZE/FDBLK
			+ fd->skip/FDBLK;
		sectrac = fd->ft->sectrac;
		sec = blknum %  (sectrac * fd->ft->heads);
		head = sec / sectrac;
		sec = sec % sectrac + 1;
/*XXX*/		fd->hddrv = ((head&1)<<2)+fdu;

		if(format)
		{
			/* formatting */
			out_fdc(fdcu,/* NE7CMD_FORMAT */ 0x4d);
			out_fdc(fdcu,head << 2 | fdu);
			out_fdc(fdcu,finfo->fd_formb_secshift);
			out_fdc(fdcu,finfo->fd_formb_nsecs);
			out_fdc(fdcu,finfo->fd_formb_gaplen);
			out_fdc(fdcu,finfo->fd_formb_fillbyte);
		}			
		else
		{
			if (read)
			{
				out_fdc(fdcu,NE7CMD_READ);      /* READ */
			}
			else
			{
				out_fdc(fdcu,NE7CMD_WRITE);     /* WRITE */
			}
			out_fdc(fdcu,head << 2 | fdu);  /* head & unit */
			out_fdc(fdcu,fd->track);        /* track */
			out_fdc(fdcu,head);
			out_fdc(fdcu,sec);              /* sector XXX +1? */
			out_fdc(fdcu,fd->ft->secsize);  /* sector size */
			out_fdc(fdcu,sectrac);          /* sectors/track */
			out_fdc(fdcu,fd->ft->gap);      /* gap size */
			out_fdc(fdcu,fd->ft->datalen);  /* data length */
		}
		fdc->state = IOCOMPLETE;
		timeout(fd_timeout, (caddr_t)fdcu, 2 * hz);
		return(0);	/* will return later */
	case IOCOMPLETE: /* IO DONE, post-analyze */
		untimeout(fd_timeout, (caddr_t)fdcu);
		for(i=0;i<7;i++)
		{
			fdc->status[i] = in_fdc(fdcu);
		}
	case IOTIMEDOUT: /*XXX*/
		isa_dmadone(bp->b_flags, bp->b_un.b_addr+fd->skip,
			format ? bp->b_bcount : FDBLK, fdc->dmachan);
		if (fdc->status[0]&0xF8)
		{
                        if (fdc->status[1] & 0x10) {
                                /*
				 * Operation not completed in reasonable time.
				 * Just restart it, don't increment retry count.
				 * (vak)
                                 */
                                fdc->state = SEEKCOMPLETE;
                                return (1);
                        }
			return(retrier(fdcu));
		}
		/* All OK */
		fd->skip += FDBLK;
		if (!format && fd->skip < bp->b_bcount)
		{
			/* set up next transfer */
			blknum = (unsigned long)bp->b_blkno*DEV_BSIZE/FDBLK
				+ fd->skip/FDBLK;
			bp->b_cylin = (blknum / (fd->ft->sectrac * fd->ft->heads));
			fdc->state = DOSEEK;
		}
		else
		{
			/* ALL DONE */
			fd->skip = 0;
			bp->b_resid = 0;
			dp->b_actf = bp->av_forw;
			biodone(bp);
			fdc->fd = (fd_p) 0;
			fdc->fdu = -1;
			fdc->state = FINDWORK;
		}
		return(1);
	case RESETCTLR:
		/* Try a reset, keep motor on */
		set_motor(fdcu,fd->fdsu,1);
		DELAY(100);
		set_motor(fdcu,fd->fdsu,0);
		outb(fdc->baseport+fdctl,fd->ft->trans);
		TRACE1("[0x%x->fdctl]",fd->ft->trans);
		fdc->retry++;
		fdc->state = STARTRECAL;
		break;
	case STARTRECAL:
		out_fdc(fdcu,NE7CMD_SPECIFY); /* specify command */
		out_fdc(fdcu,0xDF);
		out_fdc(fdcu,2);
		out_fdc(fdcu,NE7CMD_RECAL);	/* Recalibrate Function */
		out_fdc(fdcu,fdu);
		fdc->state = RECALWAIT;
		return(0);	/* will return later */
	case RECALWAIT:
		/* allow heads to settle */
		timeout(fd_pseudointr, (caddr_t)fdcu, hz / 30);
		fdc->state = RECALCOMPLETE;
		return(0);	/* will return later */
	case RECALCOMPLETE:
		out_fdc(fdcu,NE7CMD_SENSEI);
		st0 = in_fdc(fdcu);
		cyl = in_fdc(fdcu);
		if (cyl != 0)
		{
			printf("fd%d: recal failed ST0 %b cyl %d\n", fdu,
				st0, NE7_ST0BITS, cyl);
			return(retrier(fdcu));
		}
		fd->track = 0;
		/* Seek (probably) necessary */
		fdc->state = DOSEEK;
		return(1);	/* will return immediatly */
	case	MOTORWAIT:
		if(fd->flags & FD_MOTOR_WAIT)
		{
			return(0); /* time's not up yet */
		}
		fdc->state = DOSEEK;
		return(1);	/* will return immediatly */
	default:
		printf("Unexpected FD int->");
		out_fdc(fdcu,NE7CMD_SENSEI);
		st0 = in_fdc(fdcu);
		cyl = in_fdc(fdcu);
		printf("ST0 = %lx, PCN = %lx\n",i,sec);
		out_fdc(fdcu,0x4A); 
		out_fdc(fdcu,fd->fdsu);
		for(i=0;i<7;i++) {
			fdc->status[i] = in_fdc(fdcu);
		}
	printf("intr status :%lx %lx %lx %lx %lx %lx %lx ",
		fdc->status[0],
		fdc->status[1],
		fdc->status[2],
		fdc->status[3],
		fdc->status[4],
		fdc->status[5],
		fdc->status[6] );
		return(0);
	}
	return(1); /* Come back immediatly to new state */
}

static int
retrier(fdcu)
	fdcu_t fdcu;
{
	fdc_p fdc = fdc_data + fdcu;
	register struct buf *dp,*bp;

	dp = &(fdc->head);
	bp = dp->b_actf;

	switch(fdc->retry)
	{
	case 0: case 1: case 2:
		fdc->state = SEEKCOMPLETE;
		break;
	case 3: case 4: case 5:
		fdc->state = STARTRECAL;
		break;
	case 6:
		fdc->state = RESETCTLR;
		break;
	case 7:
		break;
	default:
		{
			dev_t sav_b_dev = bp->b_dev;
			/* Trick diskerr */
			bp->b_dev = makedev(major(bp->b_dev), (FDUNIT(minor(bp->b_dev))<<3)|3);
			diskerr(bp, "fd", "hard error", LOG_PRINTF,
				fdc->fd->skip, (struct disklabel *)NULL);
			bp->b_dev = sav_b_dev;
			printf(" (ST0 %b ", fdc->status[0], NE7_ST0BITS);
			printf(" ST1 %b ", fdc->status[1], NE7_ST1BITS);
			printf(" ST2 %b ", fdc->status[2], NE7_ST2BITS);
			printf("cyl %d hd %d sec %d)\n",
			       fdc->status[3], fdc->status[4], fdc->status[5]);
		}
		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
		bp->b_resid = bp->b_bcount - fdc->fd->skip;
		dp->b_actf = bp->av_forw;
		fdc->fd->skip = 0;
		biodone(bp);
		fdc->state = FINDWORK;
		fdc->fd = (fd_p) 0;
		fdc->fdu = -1;
		/* XXX abort current command, if any.  */
		return(1);
	}
	fdc->retry++;
	return(1);
}

static int
fdformat(dev, finfo, p)
	dev_t dev;
	struct fd_formb *finfo;
	struct proc *p;
{
 	fdu_t	fdu;
 	fd_p	fd;

	struct buf *bp;
	int rv = 0, s;
	
 	fdu = FDUNIT(minor(dev));
	fd = &fd_data[fdu];

	/* set up a buffer header for fdstrategy() */
	bp = (struct buf *)malloc(sizeof(struct buf), M_TEMP, M_NOWAIT);
	if(bp == 0)
		return ENOBUFS;
	bzero((void *)bp, sizeof(struct buf));
	bp->b_flags = B_BUSY | B_PHYS | B_FORMAT;
	bp->b_proc = p;
	bp->b_dev = dev;

	/*
	 * calculate a fake blkno, so fdstrategy() would initiate a
	 * seek to the requested cylinder
	 */
	bp->b_blkno = (finfo->cyl * (fd->ft->sectrac * fd->ft->heads)
		+ finfo->head * fd->ft->sectrac) * FDBLK / DEV_BSIZE;

	bp->b_bcount = sizeof(struct fd_idfield_data) * finfo->fd_formb_nsecs;
	bp->b_un.b_addr = (caddr_t)finfo;
	
	/* now do the format */
	fdstrategy(bp);

	/* ...and wait for it to complete */
	s = splbio();
	while(!(bp->b_flags & B_DONE))
	{
		rv = tsleep((caddr_t)bp, PRIBIO, "fdform", 20 * hz);
		if(rv == EWOULDBLOCK)
			break;
	}
	splx(s);
	
	if(rv == EWOULDBLOCK)
	{
		/* timed out */
		biodone(bp);
		rv = EIO;
	}
	free(bp, M_TEMP);
	return rv;
}

/*
 * fdioctl() from jc@irbs.UUCP (John Capo)
 * i386/i386/conf.c needs to have fdioctl() declared and remove the line that
 * defines fdioctl to be enxio.
 *
 * TODO: Reformat.
 *       Think about allocating buffer off stack.
 *       Don't pass uncast 0's and NULL's to read/write/setdisklabel().
 *       Watch out for NetBSD's different *disklabel() interface.
 *
 * Added functionality for floppy formatting
 * joerg_wunsch@uriah.sax.de (Joerg Wunsch)
 */

int
fdioctl (dev, cmd, addr, flag, p)
	dev_t dev;
	int cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	struct fd_type *fdt;
	struct disklabel *dl;
	char buffer[DEV_BSIZE];
	int error;

#if NFT > 0
	int type = FDTYPE(minor(dev));

	/* check for a tape ioctl */
	if (type & F_TAPE_TYPE)
		return ftioctl(dev, cmd, addr, flag, p);
#endif

	error = 0;

	switch (cmd)
	{
	case DIOCGDINFO:
		bzero(buffer, sizeof (buffer));
		dl = (struct disklabel *)buffer;
		dl->d_secsize = FDBLK;
		fdt = fd_data[FDUNIT(minor(dev))].ft;
		dl->d_secpercyl = fdt->size / fdt->tracks;
		dl->d_type = DTYPE_FLOPPY;

		if (readdisklabel(dev, fdstrategy, dl, NULL, 0, 0) == NULL)
			error = 0;
		else
			error = EINVAL;

		*(struct disklabel *)addr = *dl;
		break;

	case DIOCSDINFO:
		if ((flag & FWRITE) == 0)
			error = EBADF;
		break;

	case DIOCWLABEL:
		if ((flag & FWRITE) == 0)
			error = EBADF;
		break;

	case DIOCWDINFO:
		if ((flag & FWRITE) == 0)
		{
			error = EBADF;
			break;
		}

		dl = (struct disklabel *)addr;

		if (error = setdisklabel ((struct disklabel *)buffer,
		    dl, 0, NULL))
			break;

		error = writedisklabel(dev, fdstrategy,
			(struct disklabel *)buffer, NULL);
		break;

	case FD_FORM:
		if((flag & FWRITE) == 0)
			error = EBADF;	/* must be opened for writing */
		else if(((struct fd_formb *)addr)->format_version !=
			FD_FORMAT_VERSION)
			error = EINVAL;	/* wrong version of formatting prog */
		else
			error = fdformat(dev, (struct fd_formb *)addr, p);
		break;

	case FD_GTYPE:                  /* get drive type */
		*(struct fd_type *)addr = *fd_data[FDUNIT(minor(dev))].ft;
		break;

	default:
		error = EINVAL;
		break;
	}
	return (error);
}

#endif
