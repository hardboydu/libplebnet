/*
 * FreeBSD Connectix QuickCam parallel-port camera video capture driver.
 * Copyright (c) 1996, Paul Traina.
 *
 * This driver is based in part on the Linux QuickCam driver which is
 * Copyright (c) 1996, Thomas Davis.
 *
 * QuickCam(TM) is a registered trademark of Connectix Inc.
 * Use this driver at your own risk, it is not warranted by
 * Connectix or the authors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
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
 * The information in this file is private and shared between various
 * parts of the QuickCam(TM) driver.
 */

#ifndef	_QCAM_DEFS_H
#define	_QCAM_DEFS_H 1

extern int qcam_debug;

struct qcam_softc {
	u_char		*buffer;		/* frame buffer */
	u_char		*buffer_end;		/* end of frame buffer */
	u_int		flags;
	u_int		iobase;
	int		unit;			/* device */
	void		(*scanner)(struct qcam_softc *);

	int		init_req;		/* initialization required */
	int		x_size;			/* pixels */
	int		y_size;			/* pixels */
	int		x_origin;		/* ?? units */
	int		y_origin;		/* ?? units */
	int		zoom;			/* 0=none, 1=1.5x, 2=2x */
	int		bpp;			/* 4 or 6 */
	u_char		xferparms;		/* calcualted transfer params */
	u_char		contrast;
	u_char		brightness;
	u_char		whitebalance;

#ifdef	KERNEL
#ifdef	__FreeBSD__
	struct		kern_devconf kdc;	/* kernel config database */
#ifdef	DEVFS
	void		*devfs_token;
#endif	/* DEVFS */
#endif	/* __FreeBSD__ */
#endif	/* KERNEL */
};

/* flags in softc */
#define	QC_OPEN			0x01		/* device open */
#define	QC_ALIVE		0x02		/* probed and attached */
#define	QC_BIDIR_HW		0x04		/* bidir parallel port */
#define	QC_FORCEUNI		0x08		/* ...but force unidir mode */

#define	QC_MAXFRAMEBUFSIZE	(QC_MAX_XSIZE*QC_MAX_YSIZE)

#ifdef	LINUX			/* Linux is backwards from *BSD */

#define	read_data(P)		inb((P))
#define	read_data_word(P)	inw((P))
#define	read_status(P)		inb((P)+1)
#define	write_data(P, V)	outb((V), (P)+0)
#define	write_status(P, V)	outb((V), (P)+1)
#define write_control(P, V)	outb((V), (P)+2)

#else				/* FreeBSD/NetBSD/BSDI */

#define	read_data(P)		inb((P))
#define	read_data_word(P)	inw((P))
#define	read_status(P)		inb((P)+1)
#define	write_data(P, V)	outb((P)+0, (V))
#define	write_status(P, V)	outb((P)+1, (V))
#define write_control(P, V)	outb((P)+2, (V))

#endif

#define	QC_TIMEOUT_INIT		60000		/* timeout for first
						   read of scan */
#define	QC_TIMEOUT_CMD		5000		/* timeout for control cmds */
#define	QC_TIMEOUT		400		/* timeout on scan reads */

extern int  qcam_detect		__P((u_int  port));
extern void qcam_reset		__P((struct qcam_softc *qs));
extern int  qcam_scan		__P((struct qcam_softc *qs));
extern void qcam_default	__P((struct qcam_softc *qs));

#endif	/* _QCAM_DEFS_H */
