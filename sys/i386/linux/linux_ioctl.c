/*
 * Copyright (c) 1994-1995 S�ren Schmidt
 * All rights reserved.
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
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/proc.h>
#include <sys/cdio.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/tty.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/sockio.h>
#include <sys/soundcard.h>

#include <machine/console.h>

#include <i386/linux/linux.h>
#include <i386/linux/linux_proto.h>
#include <i386/linux/linux_util.h>
#include <i386/linux/linux_mib.h>

#define ISSIGVALID(sig)		((sig) > 0 && (sig) < NSIG)

struct linux_termio {
    unsigned short c_iflag;
    unsigned short c_oflag;
    unsigned short c_cflag;
    unsigned short c_lflag;
    unsigned char c_line;
    unsigned char c_cc[LINUX_NCC];
};


struct linux_termios {
    unsigned int    c_iflag;
    unsigned int    c_oflag;
    unsigned int    c_cflag;
    unsigned int    c_lflag;
    unsigned char   c_line;
    unsigned char   c_cc[LINUX_NCCS];
};

struct linux_winsize {
    unsigned short ws_row, ws_col;
    unsigned short ws_xpixel, ws_ypixel;
};

static struct speedtab sptab[] = {
    { B0, LINUX_B0 }, { B50, LINUX_B50 },
    { B75, LINUX_B75 }, { B110, LINUX_B110 },
    { B134, LINUX_B134 }, { B150, LINUX_B150 },
    { B200, LINUX_B200 }, { B300, LINUX_B300 },
    { B600, LINUX_B600 }, { B1200, LINUX_B1200 },
    { B1800, LINUX_B1800 }, { B2400, LINUX_B2400 },
    { B4800, LINUX_B4800 }, { B9600, LINUX_B9600 },
    { B19200, LINUX_B19200 }, { B38400, LINUX_B38400 },
    { B57600, LINUX_B57600 }, { B115200, LINUX_B115200 },
    {-1, -1 }
};

struct linux_serial_struct {
        int     type;
        int     line;
        int     port;
        int     irq;
        int     flags;
        int     xmit_fifo_size;
        int     custom_divisor;
        int     baud_base;
        unsigned short  close_delay;
        char    reserved_char[2];
        int     hub6;
        unsigned short  closing_wait;
        unsigned short  closing_wait2;
        int     reserved[4];
};


static int
linux_to_bsd_speed(int code, struct speedtab *table)
{
    for ( ; table->sp_code != -1; table++)
	if (table->sp_code == code)
	    return (table->sp_speed);
    return -1;
}

static int
bsd_to_linux_speed(int speed, struct speedtab *table)
{
    for ( ; table->sp_speed != -1; table++)
	if (table->sp_speed == speed)
	    return (table->sp_code);
    return -1;
}

static void
bsd_to_linux_termios(struct termios *bsd_termios, 
		struct linux_termios *linux_termios)
{
    int i;

#ifdef DEBUG
    printf("LINUX: BSD termios structure (input):\n");
    printf("i=%08x o=%08x c=%08x l=%08x ispeed=%d ospeed=%d\n",
	   bsd_termios->c_iflag, bsd_termios->c_oflag,
	   bsd_termios->c_cflag, bsd_termios->c_lflag,
	   bsd_termios->c_ispeed, bsd_termios->c_ospeed);
    printf("c_cc ");
    for (i=0; i<NCCS; i++)
	printf("%02x ", bsd_termios->c_cc[i]);
    printf("\n");
#endif
    linux_termios->c_iflag = 0;
    if (bsd_termios->c_iflag & IGNBRK)
	linux_termios->c_iflag |= LINUX_IGNBRK;
    if (bsd_termios->c_iflag & BRKINT)
	linux_termios->c_iflag |= LINUX_BRKINT;
    if (bsd_termios->c_iflag & IGNPAR)
	linux_termios->c_iflag |= LINUX_IGNPAR;
    if (bsd_termios->c_iflag & PARMRK)
	linux_termios->c_iflag |= LINUX_PARMRK;
    if (bsd_termios->c_iflag & INPCK)
	linux_termios->c_iflag |= LINUX_INPCK;
    if (bsd_termios->c_iflag & ISTRIP)
	linux_termios->c_iflag |= LINUX_ISTRIP;
    if (bsd_termios->c_iflag & INLCR)
	linux_termios->c_iflag |= LINUX_INLCR;
    if (bsd_termios->c_iflag & IGNCR)
	linux_termios->c_iflag |= LINUX_IGNCR;
    if (bsd_termios->c_iflag & ICRNL)
	linux_termios->c_iflag |= LINUX_ICRNL;
    if (bsd_termios->c_iflag & IXON)
	linux_termios->c_iflag |= LINUX_IXON;
    if (bsd_termios->c_iflag & IXANY)
	linux_termios->c_iflag |= LINUX_IXANY;
    if (bsd_termios->c_iflag & IXOFF)
	linux_termios->c_iflag |= LINUX_IXOFF;
    if (bsd_termios->c_iflag & IMAXBEL)
	linux_termios->c_iflag |= LINUX_IMAXBEL;

    linux_termios->c_oflag = 0;
    if (bsd_termios->c_oflag & OPOST)
	linux_termios->c_oflag |= LINUX_OPOST;
    if (bsd_termios->c_oflag & ONLCR)
	linux_termios->c_oflag |= LINUX_ONLCR;
    if (bsd_termios->c_oflag & OXTABS)
	linux_termios->c_oflag |= LINUX_XTABS;

    linux_termios->c_cflag =
	bsd_to_linux_speed(bsd_termios->c_ispeed, sptab);
    linux_termios->c_cflag |= (bsd_termios->c_cflag & CSIZE) >> 4;
    if (bsd_termios->c_cflag & CSTOPB)
	linux_termios->c_cflag |= LINUX_CSTOPB;
    if (bsd_termios->c_cflag & CREAD)
	linux_termios->c_cflag |= LINUX_CREAD;
    if (bsd_termios->c_cflag & PARENB)
	linux_termios->c_cflag |= LINUX_PARENB;
    if (bsd_termios->c_cflag & PARODD)
	linux_termios->c_cflag |= LINUX_PARODD;
    if (bsd_termios->c_cflag & HUPCL)
	linux_termios->c_cflag |= LINUX_HUPCL;
    if (bsd_termios->c_cflag & CLOCAL)
	linux_termios->c_cflag |= LINUX_CLOCAL;
    if (bsd_termios->c_cflag & CRTSCTS)
	linux_termios->c_cflag |= LINUX_CRTSCTS;

    linux_termios->c_lflag = 0;
    if (bsd_termios->c_lflag & ISIG)
	linux_termios->c_lflag |= LINUX_ISIG;
    if (bsd_termios->c_lflag & ICANON)
	linux_termios->c_lflag |= LINUX_ICANON;
    if (bsd_termios->c_lflag & ECHO)
	linux_termios->c_lflag |= LINUX_ECHO;
    if (bsd_termios->c_lflag & ECHOE)
	linux_termios->c_lflag |= LINUX_ECHOE;
    if (bsd_termios->c_lflag & ECHOK)
	linux_termios->c_lflag |= LINUX_ECHOK;
    if (bsd_termios->c_lflag & ECHONL)
	linux_termios->c_lflag |= LINUX_ECHONL;
    if (bsd_termios->c_lflag & NOFLSH)
	linux_termios->c_lflag |= LINUX_NOFLSH;
    if (bsd_termios->c_lflag & TOSTOP)
	linux_termios->c_lflag |= LINUX_TOSTOP;
    if (bsd_termios->c_lflag & ECHOCTL)
	linux_termios->c_lflag |= LINUX_ECHOCTL;
    if (bsd_termios->c_lflag & ECHOPRT)
	linux_termios->c_lflag |= LINUX_ECHOPRT;
    if (bsd_termios->c_lflag & ECHOKE)
	linux_termios->c_lflag |= LINUX_ECHOKE;
    if (bsd_termios->c_lflag & FLUSHO)
	linux_termios->c_lflag |= LINUX_FLUSHO;
    if (bsd_termios->c_lflag & PENDIN)
	linux_termios->c_lflag |= LINUX_PENDIN;
    if (bsd_termios->c_lflag & IEXTEN)
	linux_termios->c_lflag |= LINUX_IEXTEN;

    for (i=0; i<LINUX_NCCS; i++) 
	linux_termios->c_cc[i] = LINUX_POSIX_VDISABLE;
    linux_termios->c_cc[LINUX_VINTR] = bsd_termios->c_cc[VINTR];
    linux_termios->c_cc[LINUX_VQUIT] = bsd_termios->c_cc[VQUIT];
    linux_termios->c_cc[LINUX_VERASE] = bsd_termios->c_cc[VERASE];
    linux_termios->c_cc[LINUX_VKILL] = bsd_termios->c_cc[VKILL];
    linux_termios->c_cc[LINUX_VEOF] = bsd_termios->c_cc[VEOF];
    linux_termios->c_cc[LINUX_VEOL] = bsd_termios->c_cc[VEOL];
    linux_termios->c_cc[LINUX_VMIN] = bsd_termios->c_cc[VMIN];
    linux_termios->c_cc[LINUX_VTIME] = bsd_termios->c_cc[VTIME];
    linux_termios->c_cc[LINUX_VEOL2] = bsd_termios->c_cc[VEOL2];
    linux_termios->c_cc[LINUX_VSUSP] = bsd_termios->c_cc[VSUSP];
    linux_termios->c_cc[LINUX_VSTART] = bsd_termios->c_cc[VSTART];
    linux_termios->c_cc[LINUX_VSTOP] = bsd_termios->c_cc[VSTOP];
    linux_termios->c_cc[LINUX_VREPRINT] = bsd_termios->c_cc[VREPRINT];
    linux_termios->c_cc[LINUX_VDISCARD] = bsd_termios->c_cc[VDISCARD];
    linux_termios->c_cc[LINUX_VWERASE] = bsd_termios->c_cc[VWERASE];
    linux_termios->c_cc[LINUX_VLNEXT] = bsd_termios->c_cc[VLNEXT];

    for (i=0; i<LINUX_NCCS; i++) {
      if (linux_termios->c_cc[i] == _POSIX_VDISABLE)
	linux_termios->c_cc[i] = LINUX_POSIX_VDISABLE;
    }

    linux_termios->c_line = 0;
#ifdef DEBUG
    printf("LINUX: LINUX termios structure (output):\n");
    printf("i=%08x o=%08x c=%08x l=%08x line=%d\n",
	linux_termios->c_iflag, linux_termios->c_oflag, linux_termios->c_cflag,
	linux_termios->c_lflag, (int)linux_termios->c_line);
    printf("c_cc ");
    for (i=0; i<LINUX_NCCS; i++) 
	printf("%02x ", linux_termios->c_cc[i]);
    printf("\n");
#endif
}


static void
linux_to_bsd_termios(struct linux_termios *linux_termios,
		struct termios *bsd_termios)
{
    int i;
#ifdef DEBUG
    printf("LINUX: LINUX termios structure (input):\n");
    printf("i=%08x o=%08x c=%08x l=%08x line=%d\n",
	linux_termios->c_iflag, linux_termios->c_oflag, linux_termios->c_cflag,
	linux_termios->c_lflag, (int)linux_termios->c_line);
    printf("c_cc ");
    for (i=0; i<LINUX_NCCS; i++) 
	printf("%02x ", linux_termios->c_cc[i]);
    printf("\n");
#endif
    bsd_termios->c_iflag = 0;
    if (linux_termios->c_iflag & LINUX_IGNBRK)
	bsd_termios->c_iflag |= IGNBRK;
    if (linux_termios->c_iflag & LINUX_BRKINT)
	bsd_termios->c_iflag |= BRKINT;
    if (linux_termios->c_iflag & LINUX_IGNPAR)
	bsd_termios->c_iflag |= IGNPAR;
    if (linux_termios->c_iflag & LINUX_PARMRK)
	bsd_termios->c_iflag |= PARMRK;
    if (linux_termios->c_iflag & LINUX_INPCK)
	bsd_termios->c_iflag |= INPCK;
    if (linux_termios->c_iflag & LINUX_ISTRIP)
	bsd_termios->c_iflag |= ISTRIP;
    if (linux_termios->c_iflag & LINUX_INLCR)
	bsd_termios->c_iflag |= INLCR;
    if (linux_termios->c_iflag & LINUX_IGNCR)
	bsd_termios->c_iflag |= IGNCR;
    if (linux_termios->c_iflag & LINUX_ICRNL)
	bsd_termios->c_iflag |= ICRNL;
    if (linux_termios->c_iflag & LINUX_IXON)
	bsd_termios->c_iflag |= IXON;
    if (linux_termios->c_iflag & LINUX_IXANY)
	bsd_termios->c_iflag |= IXANY;
    if (linux_termios->c_iflag & LINUX_IXOFF)
	bsd_termios->c_iflag |= IXOFF;
    if (linux_termios->c_iflag & LINUX_IMAXBEL)
	bsd_termios->c_iflag |= IMAXBEL;

    bsd_termios->c_oflag = 0;
    if (linux_termios->c_oflag & LINUX_OPOST)
	bsd_termios->c_oflag |= OPOST;
    if (linux_termios->c_oflag & LINUX_ONLCR)
	bsd_termios->c_oflag |= ONLCR;
    if (linux_termios->c_oflag & LINUX_XTABS)
	bsd_termios->c_oflag |= OXTABS;

    bsd_termios->c_cflag = (linux_termios->c_cflag & LINUX_CSIZE) << 4;
    if (linux_termios->c_cflag & LINUX_CSTOPB)
	bsd_termios->c_cflag |= CSTOPB;
    if (linux_termios->c_cflag & LINUX_CREAD)
	bsd_termios->c_cflag |= CREAD;
    if (linux_termios->c_cflag & LINUX_PARENB)
	bsd_termios->c_cflag |= PARENB;
    if (linux_termios->c_cflag & LINUX_PARODD)
	bsd_termios->c_cflag |= PARODD;
    if (linux_termios->c_cflag & LINUX_HUPCL)
	bsd_termios->c_cflag |= HUPCL;
    if (linux_termios->c_cflag & LINUX_CLOCAL)
	bsd_termios->c_cflag |= CLOCAL;
    if (linux_termios->c_cflag & LINUX_CRTSCTS)
	bsd_termios->c_cflag |= CRTSCTS;

    bsd_termios->c_lflag = 0;
    if (linux_termios->c_lflag & LINUX_ISIG)
	bsd_termios->c_lflag |= ISIG;
    if (linux_termios->c_lflag & LINUX_ICANON)
	bsd_termios->c_lflag |= ICANON;
    if (linux_termios->c_lflag & LINUX_ECHO)
	bsd_termios->c_lflag |= ECHO;
    if (linux_termios->c_lflag & LINUX_ECHOE)
	bsd_termios->c_lflag |= ECHOE;
    if (linux_termios->c_lflag & LINUX_ECHOK)
	bsd_termios->c_lflag |= ECHOK;
    if (linux_termios->c_lflag & LINUX_ECHONL)
	bsd_termios->c_lflag |= ECHONL;
    if (linux_termios->c_lflag & LINUX_NOFLSH)
	bsd_termios->c_lflag |= NOFLSH;
    if (linux_termios->c_lflag & LINUX_TOSTOP)
	bsd_termios->c_lflag |= TOSTOP;
    if (linux_termios->c_lflag & LINUX_ECHOCTL)
	bsd_termios->c_lflag |= ECHOCTL;
    if (linux_termios->c_lflag & LINUX_ECHOPRT)
	bsd_termios->c_lflag |= ECHOPRT;
    if (linux_termios->c_lflag & LINUX_ECHOKE)
	bsd_termios->c_lflag |= ECHOKE;
    if (linux_termios->c_lflag & LINUX_FLUSHO)
	bsd_termios->c_lflag |= FLUSHO;
    if (linux_termios->c_lflag & LINUX_PENDIN)
	bsd_termios->c_lflag |= PENDIN;
    if (linux_termios->c_lflag & LINUX_IEXTEN)
	bsd_termios->c_lflag |= IEXTEN;

    for (i=0; i<NCCS; i++)
	bsd_termios->c_cc[i] = _POSIX_VDISABLE;
    bsd_termios->c_cc[VINTR] = linux_termios->c_cc[LINUX_VINTR];
    bsd_termios->c_cc[VQUIT] = linux_termios->c_cc[LINUX_VQUIT];
    bsd_termios->c_cc[VERASE] = linux_termios->c_cc[LINUX_VERASE];
    bsd_termios->c_cc[VKILL] = linux_termios->c_cc[LINUX_VKILL];
    bsd_termios->c_cc[VEOF] = linux_termios->c_cc[LINUX_VEOF];
    bsd_termios->c_cc[VEOL] = linux_termios->c_cc[LINUX_VEOL];
    bsd_termios->c_cc[VMIN] = linux_termios->c_cc[LINUX_VMIN];
    bsd_termios->c_cc[VTIME] = linux_termios->c_cc[LINUX_VTIME];
    bsd_termios->c_cc[VEOL2] = linux_termios->c_cc[LINUX_VEOL2];
    bsd_termios->c_cc[VSUSP] = linux_termios->c_cc[LINUX_VSUSP];
    bsd_termios->c_cc[VSTART] = linux_termios->c_cc[LINUX_VSTART];
    bsd_termios->c_cc[VSTOP] = linux_termios->c_cc[LINUX_VSTOP];
    bsd_termios->c_cc[VREPRINT] = linux_termios->c_cc[LINUX_VREPRINT];
    bsd_termios->c_cc[VDISCARD] = linux_termios->c_cc[LINUX_VDISCARD];
    bsd_termios->c_cc[VWERASE] = linux_termios->c_cc[LINUX_VWERASE];
    bsd_termios->c_cc[VLNEXT] = linux_termios->c_cc[LINUX_VLNEXT];

    for (i=0; i<NCCS; i++) {
      if (bsd_termios->c_cc[i] == LINUX_POSIX_VDISABLE)
	bsd_termios->c_cc[i] = _POSIX_VDISABLE;
    }

    bsd_termios->c_ispeed = bsd_termios->c_ospeed =
	linux_to_bsd_speed(linux_termios->c_cflag & LINUX_CBAUD, sptab);
#ifdef DEBUG
	printf("LINUX: BSD termios structure (output):\n");
	printf("i=%08x o=%08x c=%08x l=%08x ispeed=%d ospeed=%d\n",
	       bsd_termios->c_iflag, bsd_termios->c_oflag,
	       bsd_termios->c_cflag, bsd_termios->c_lflag,
	       bsd_termios->c_ispeed, bsd_termios->c_ospeed);
	printf("c_cc ");
	for (i=0; i<NCCS; i++) 
	    printf("%02x ", bsd_termios->c_cc[i]);
	printf("\n");
#endif
}


static void
bsd_to_linux_termio(struct termios *bsd_termios, 
		struct linux_termio *linux_termio)
{
  struct linux_termios tmios;

  bsd_to_linux_termios(bsd_termios, &tmios);
  linux_termio->c_iflag = tmios.c_iflag;
  linux_termio->c_oflag = tmios.c_oflag;
  linux_termio->c_cflag = tmios.c_cflag;
  linux_termio->c_lflag = tmios.c_lflag;
  linux_termio->c_line  = tmios.c_line;
  memcpy(linux_termio->c_cc, tmios.c_cc, LINUX_NCC);
}

static void
linux_to_bsd_termio(struct linux_termio *linux_termio,
		struct termios *bsd_termios)
{
  struct linux_termios tmios;
  int i;

  tmios.c_iflag = linux_termio->c_iflag;
  tmios.c_oflag = linux_termio->c_oflag;
  tmios.c_cflag = linux_termio->c_cflag;
  tmios.c_lflag = linux_termio->c_lflag;

  for (i=LINUX_NCC; i<LINUX_NCCS; i++)
    tmios.c_cc[i] = LINUX_POSIX_VDISABLE;
  memcpy(tmios.c_cc, linux_termio->c_cc, LINUX_NCC);

  linux_to_bsd_termios(&tmios, bsd_termios);
}

struct linux_cdrom_msf
{
    u_char	cdmsf_min0;
    u_char	cdmsf_sec0;
    u_char	cdmsf_frame0;
    u_char	cdmsf_min1;
    u_char	cdmsf_sec1;
    u_char	cdmsf_frame1;
};

struct linux_cdrom_tochdr
{
    u_char	cdth_trk0;
    u_char	cdth_trk1;
};

union linux_cdrom_addr
{
    struct {
	u_char	minute;
	u_char	second;
	u_char	frame;
    } msf;
    int		lba;
};

struct linux_cdrom_tocentry
{
    u_char	cdte_track;     
    u_char	cdte_adr:4;
    u_char	cdte_ctrl:4;
    u_char	cdte_format;    
    union linux_cdrom_addr cdte_addr;
    u_char	cdte_datamode;  
};

struct linux_cdrom_subchnl
{
    u_char      cdsc_format;
    u_char      cdsc_audiostatus;
    u_char      cdsc_adr:4;
    u_char      cdsc_ctrl:4;
    u_char      cdsc_trk;
    u_char      cdsc_ind;
    union linux_cdrom_addr cdsc_absaddr;
    union linux_cdrom_addr cdsc_reladdr;
};

#if 0
static void
linux_to_bsd_msf_lba(u_char address_format,
    union linux_cdrom_addr *lp, union msf_lba *bp)
{
    if (address_format == CD_LBA_FORMAT)
	bp->lba = lp->lba;
    else {
	bp->msf.minute = lp->msf.minute;
	bp->msf.second = lp->msf.second;
	bp->msf.frame = lp->msf.frame;
    }
}
#endif

static void
bsd_to_linux_msf_lba(u_char address_format,
    union msf_lba *bp, union linux_cdrom_addr *lp)
{
    if (address_format == CD_LBA_FORMAT)
	lp->lba = bp->lba;
    else {
	lp->msf.minute = bp->msf.minute;
	lp->msf.second = bp->msf.second;
	lp->msf.frame = bp->msf.frame;
    }
}

static void
set_linux_cdrom_addr(union linux_cdrom_addr *addr, int format, int lba)
{
    if (format == LINUX_CDROM_MSF) {
        addr->msf.frame = lba % 75;
        lba /= 75;
        lba += 2;
        addr->msf.second = lba % 60;
        addr->msf.minute = lba / 60;
    }
    else
        addr->lba = lba;
}

static unsigned dirbits[4] = { IOC_VOID, IOC_IN, IOC_OUT, IOC_INOUT };

#define SETDIR(c)	(((c) & ~IOC_DIRMASK) | dirbits[args->cmd >> 30])

int
linux_ioctl(struct proc *p, struct linux_ioctl_args *args)
{
    struct termios bsd_termios;
    struct linux_termios linux_termios;
    struct linux_termio linux_termio;
    struct filedesc *fdp = p->p_fd;
    struct file *fp;
    int bsd_line, linux_line;
    int error;

#ifdef DEBUG
    printf("Linux-emul(%ld): ioctl(%d, %04lx, *)\n", 
	(long)p->p_pid, args->fd, args->cmd);
#endif
    if ((unsigned)args->fd >= fdp->fd_nfiles 
	|| (fp = fdp->fd_ofiles[args->fd]) == 0)
	return EBADF;

    if (!fp || (fp->f_flag & (FREAD | FWRITE)) == 0) {
	return EBADF;
    }

    switch (args->cmd & 0xffff) {

    case LINUX_TCGETA:
	if ((error = fo_ioctl(fp, TIOCGETA, (caddr_t)&bsd_termios, p)) != 0)
	    return error;
	bsd_to_linux_termio(&bsd_termios, &linux_termio);
	return copyout((caddr_t)&linux_termio, (caddr_t)args->arg,
		       sizeof(linux_termio));

    case LINUX_TCSETA:
	error = copyin((caddr_t)args->arg, &linux_termio, sizeof(linux_termio));
	if (error)
	    return error;
	linux_to_bsd_termio(&linux_termio, &bsd_termios);
	return fo_ioctl(fp, TIOCSETA, (caddr_t)&bsd_termios, p);

    case LINUX_TCSETAW:
	error = copyin((caddr_t)args->arg, &linux_termio, sizeof(linux_termio));
	if (error)
	    return error;
	linux_to_bsd_termio(&linux_termio, &bsd_termios);
	return fo_ioctl(fp, TIOCSETAW, (caddr_t)&bsd_termios, p);

    case LINUX_TCSETAF:
	error = copyin((caddr_t)args->arg, &linux_termio, sizeof(linux_termio));
	if (error)
	    return error;
	linux_to_bsd_termio(&linux_termio, &bsd_termios);
	return fo_ioctl(fp, TIOCSETAF, (caddr_t)&bsd_termios, p);

    case LINUX_TCGETS:
	if ((error = fo_ioctl(fp, TIOCGETA, (caddr_t)&bsd_termios, p)) != 0)
	    return error;
	bsd_to_linux_termios(&bsd_termios, &linux_termios);
	return copyout((caddr_t)&linux_termios, (caddr_t)args->arg,
		       sizeof(linux_termios));

    case LINUX_TCSETS:
	error = copyin((caddr_t)args->arg, &linux_termios,
		       sizeof(linux_termios));
	if (error)
	    return error;
	linux_to_bsd_termios(&linux_termios, &bsd_termios);
	return fo_ioctl(fp, TIOCSETA, (caddr_t)&bsd_termios, p);

    case LINUX_TCSETSW:
	error = copyin((caddr_t)args->arg, &linux_termios,
		       sizeof(linux_termios));
	if (error)
	    return error;
	linux_to_bsd_termios(&linux_termios, &bsd_termios);
	return fo_ioctl(fp, TIOCSETAW, (caddr_t)&bsd_termios, p);

    case LINUX_TCSETSF:
	error = copyin((caddr_t)args->arg, &linux_termios,
		       sizeof(linux_termios));
	if (error)
	    return error;
	linux_to_bsd_termios(&linux_termios, &bsd_termios);
	return fo_ioctl(fp, TIOCSETAF, (caddr_t)&bsd_termios, p);
	    
    case LINUX_TIOCGPGRP:
	args->cmd = TIOCGPGRP;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCSPGRP:
	args->cmd = TIOCSPGRP;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCGWINSZ:
	args->cmd = TIOCGWINSZ;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCSWINSZ:
	args->cmd = TIOCSWINSZ;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCMGET:
	args->cmd = TIOCMGET;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCMBIS:
	args->cmd = TIOCMBIS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCMBIC:
	args->cmd = TIOCMBIC;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCMSET:
	args->cmd = TIOCMSET;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIONREAD:
	args->cmd = FIONREAD;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIONBIO:
	args->cmd = FIONBIO;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIOASYNC:
	args->cmd = FIOASYNC;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIONCLEX:
	args->cmd = FIONCLEX;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIOCLEX:
	args->cmd = FIOCLEX;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCEXCL:
	args->cmd = TIOCEXCL;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCNXCL:
	args->cmd = TIOCNXCL;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCCONS:
	args->cmd = TIOCCONS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCNOTTY:
	args->cmd = TIOCNOTTY;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGIFCONF:
	args->cmd = OSIOCGIFCONF;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGIFFLAGS:
	args->cmd = SIOCGIFFLAGS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGIFADDR:
	args->cmd = OSIOCGIFADDR;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGIFDSTADDR:
	args->cmd = OSIOCGIFDSTADDR;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGIFBRDADDR:
	args->cmd = OSIOCGIFBRDADDR;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGIFNETMASK:
	args->cmd = OSIOCGIFNETMASK;
	return ioctl(p, (struct ioctl_args *)args);

	/* get hardware address */
    case LINUX_SIOCGIFHWADDR:
    {
	int			ifn;
	struct ifnet		*ifp;
	struct ifaddr		*ifa;
	struct sockaddr_dl	*sdl;
	struct linux_ifreq	*ifr = (struct linux_ifreq *)args->arg;

	/* 
	 * Note that we don't actually respect the name in the ifreq structure, as
	 * Linux interface names are all different
	 */

	for (ifn = 0; ifn < if_index; ifn++) {

	    ifp = ifnet_addrs[ifn]->ifa_ifp;	/* pointer to interface */
	    if (ifp->if_type == IFT_ETHER) {	/* looks good */
		/* walk the address list */
		for (ifa = TAILQ_FIRST(&ifp->if_addrhead); ifa; ifa = TAILQ_NEXT(ifa, ifa_link)) {
		    if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) &&	/* we have an address structure */
			(sdl->sdl_family == AF_LINK) &&			/* it's a link address */
			(sdl->sdl_type == IFT_ETHER)) {			/* for an ethernet link */

			return(copyout(LLADDR(sdl), (caddr_t)&ifr->ifr_hwaddr.sa_data, LINUX_IFHWADDRLEN));
		    }
		}
	    }
	}
	return(ENOENT);		/* ??? */
    }

    case LINUX_SIOCADDMULTI:
	args->cmd = SIOCADDMULTI;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCDELMULTI:
	args->cmd = SIOCDELMULTI;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIOSETOWN:
	args->cmd = FIOSETOWN;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCSPGRP:
	args->cmd = SIOCSPGRP;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_FIOGETOWN:
	args->cmd = FIOGETOWN;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCGPGRP:
	args->cmd = SIOCGPGRP;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SIOCATMARK:
	args->cmd = SIOCATMARK;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCSETD:
	switch (args->arg) {
	case LINUX_N_TTY:
	    bsd_line = TTYDISC;
	    return fo_ioctl(fp, TIOCSETD, (caddr_t)&bsd_line, p);
	case LINUX_N_SLIP:
	    bsd_line = SLIPDISC;
	    return fo_ioctl(fp, TIOCSETD, (caddr_t)&bsd_line, p);
	case LINUX_N_PPP:
	    bsd_line = PPPDISC;
	    return fo_ioctl(fp, TIOCSETD, (caddr_t)&bsd_line, p);
	default:
	    return EINVAL;
	}

    case LINUX_TIOCGETD:
	bsd_line = TTYDISC;
	error = fo_ioctl(fp, TIOCGETD, (caddr_t)&bsd_line, p);
	if (error)
	    return error;
	switch (bsd_line) {
	case TTYDISC:
	    linux_line = LINUX_N_TTY;
	    break;
	case SLIPDISC:
	    linux_line = LINUX_N_SLIP;
	    break;
	case PPPDISC:
	    linux_line = LINUX_N_PPP;
	    break;
	default:
	    return EINVAL;
	}
	return copyout(&linux_line, (caddr_t)args->arg, 
		       sizeof(int));

    case LINUX_SNDCTL_SEQ_RESET:
	args->cmd = SNDCTL_SEQ_RESET;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_SYNC:
	args->cmd = SNDCTL_SEQ_SYNC;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SYNTH_INFO:
	args->cmd = SNDCTL_SYNTH_INFO;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_CTRLRATE:
	args->cmd = SNDCTL_SEQ_CTRLRATE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_GETOUTCOUNT:
	args->cmd = SNDCTL_SEQ_GETOUTCOUNT;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_GETINCOUNT:
	args->cmd = SNDCTL_SEQ_GETINCOUNT;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_PERCMODE:
	args->cmd = SNDCTL_SEQ_PERCMODE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_FM_LOAD_INSTR:
	args->cmd = SNDCTL_FM_LOAD_INSTR;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_TESTMIDI:
	args->cmd = SNDCTL_SEQ_TESTMIDI;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_RESETSAMPLES:
	args->cmd = SNDCTL_SEQ_RESETSAMPLES;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_NRSYNTHS:
	args->cmd = SNDCTL_SEQ_NRSYNTHS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_NRMIDIS:
	args->cmd = SNDCTL_SEQ_NRMIDIS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_MIDI_INFO:
	args->cmd = SNDCTL_MIDI_INFO;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SEQ_TRESHOLD:
	args->cmd = SNDCTL_SEQ_TRESHOLD;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_SYNTH_MEMAVL:
	args->cmd = SNDCTL_SYNTH_MEMAVL;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETOPTR :
	args->cmd = SNDCTL_DSP_GETOPTR;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETIPTR :
	args->cmd = SNDCTL_DSP_GETIPTR;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_SETTRIGGER:
	args->cmd = SNDCTL_DSP_SETTRIGGER;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETCAPS:
	args->cmd = SNDCTL_DSP_GETCAPS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_RESET:
	args->cmd = SNDCTL_DSP_RESET;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_SYNC:
	args->cmd = SNDCTL_DSP_SYNC;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_SPEED:
	args->cmd = SNDCTL_DSP_SPEED;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_STEREO:
	args->cmd = SNDCTL_DSP_STEREO;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETBLKSIZE:
      /* LINUX_SNDCTL_DSP_SETBLKSIZE */
	args->cmd = SNDCTL_DSP_GETBLKSIZE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_SETFMT:
	args->cmd = SNDCTL_DSP_SETFMT;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_PCM_WRITE_CHANNELS:
	args->cmd = SOUND_PCM_WRITE_CHANNELS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_PCM_WRITE_FILTER:
	args->cmd = SOUND_PCM_WRITE_FILTER;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_POST:
	args->cmd = SNDCTL_DSP_POST;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_SUBDIVIDE:
	args->cmd = SNDCTL_DSP_SUBDIVIDE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_SETFRAGMENT:
	args->cmd = SNDCTL_DSP_SETFRAGMENT;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETFMTS:
	args->cmd = SNDCTL_DSP_GETFMTS;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETOSPACE:
	args->cmd = SNDCTL_DSP_GETOSPACE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_GETISPACE:
	args->cmd = SNDCTL_DSP_GETISPACE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SNDCTL_DSP_NONBLOCK:
	args->cmd = SNDCTL_DSP_NONBLOCK;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_VOLUME:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_VOLUME);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_BASS:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_BASS);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_TREBLE:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_TREBLE);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_SYNTH:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_SYNTH);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_PCM:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_PCM);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_SPEAKER:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_SPEAKER);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_LINE:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_LINE);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_MIC:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_MIC);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_CD:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_CD);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_IMIX:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_IMIX);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_ALTPCM:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_ALTPCM);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_RECLEV:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_RECLEV);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_IGAIN:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_IGAIN);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_OGAIN:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_OGAIN);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_LINE1:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_LINE1);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_LINE2:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_LINE2);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_WRITE_LINE3:
	args->cmd = SETDIR(SOUND_MIXER_WRITE_LINE3);
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_SOUND_MIXER_READ_DEVMASK:
	args->cmd = SOUND_MIXER_READ_DEVMASK;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_TIOCGSERIAL: {
	struct linux_serial_struct lss;

	lss.type = LINUX_PORT_16550A;
	lss.flags = 0;
	lss.close_delay = 0;
	return copyout((caddr_t)&lss, (caddr_t)args->arg, sizeof(lss));
    }

    case LINUX_TIOCSSERIAL: {
        struct linux_serial_struct lss;

	error = copyin((caddr_t)args->arg, (caddr_t)&lss, sizeof(lss));
	if (error)
	    return error;
	/*
	 * XXX - It really helps to have an implementation that does nothing.
	 *       NOT!
	 */
	return 0;
    }

    case LINUX_TCXONC:
      switch (args->arg) {
      case LINUX_TCOOFF:
	      args->cmd = TIOCSTOP;
	      break;
      case LINUX_TCOON:
	      args->cmd = TIOCSTART;
	      break;
      case LINUX_TCIOFF:
      case LINUX_TCION: {
	      u_char c;
	      struct write_args wr;
	      error = fo_ioctl(fp, TIOCGETA, (caddr_t)&bsd_termios, p);
              if (error != 0)
		      return error;
	      c = bsd_termios.c_cc[args->arg == LINUX_TCIOFF ? VSTOP : VSTART];
	      if (c != _POSIX_VDISABLE) {
		      wr.fd = args->fd;
		      wr.buf = &c;
		      wr.nbyte = sizeof(c);
		      return write(p, &wr);
	      }
	      else
		      return (0);
      }
      default:
	      return EINVAL;
      }
      args->arg = 0;
      return ioctl(p, (struct ioctl_args *)args);
      
    case LINUX_TCFLSH:
      args->cmd = TIOCFLUSH;
      switch (args->arg) {
        case LINUX_TCIFLUSH:
                args->arg = FREAD;
                break;
        case LINUX_TCOFLUSH:
                args->arg = FWRITE;
                break;
        case LINUX_TCIOFLUSH:
                args->arg = FREAD | FWRITE;
                break;
        default:
	        return EINVAL;
      }
      return ioctl(p, (struct ioctl_args *)args);

   case LINUX_VT_OPENQRY:

	args->cmd = VT_OPENQRY;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_VT_GETMODE:

	args->cmd = VT_GETMODE;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_VT_SETMODE: 
      {
	struct vt_mode *mode;
	args->cmd = VT_SETMODE;
	mode = (struct vt_mode *)args->arg;
	if (!ISSIGVALID(mode->frsig) && ISSIGVALID(mode->acqsig))
	    mode->frsig = mode->acqsig;
	return ioctl(p, (struct ioctl_args *)args);
      }

    case LINUX_VT_GETSTATE:

	args->cmd = VT_GETACTIVE;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_VT_RELDISP:

       args->cmd = VT_RELDISP;
       return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_VT_ACTIVATE:

	args->cmd = VT_ACTIVATE;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_VT_WAITACTIVE:

	args->cmd = VT_WAITACTIVE;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_KDGKBMODE:

	args->cmd = KDGKBMODE;
	return ioctl(p, (struct ioctl_args *)args);

    case LINUX_KDSKBMODE:
      {
        int kbdmode;
	switch (args->arg) {
	case LINUX_KBD_RAW:
	    kbdmode = K_RAW;
	    return fo_ioctl(fp, KDSKBMODE, (caddr_t)&kbdmode, p);
	case LINUX_KBD_XLATE:  
	    kbdmode = K_XLATE;
	    return fo_ioctl(fp, KDSKBMODE , (caddr_t)&kbdmode, p);
	case LINUX_KBD_MEDIUMRAW:
	    kbdmode = K_RAW;
	    return fo_ioctl(fp, KDSKBMODE , (caddr_t)&kbdmode, p);
	default:
	    return EINVAL;
	}
      }

    case LINUX_KDGETMODE:
	args->cmd = KDGETMODE;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_KDSETMODE:
	args->cmd = KDSETMODE;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_KDSETLED:
	args->cmd = KDSETLED;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_KDGETLED:
	args->cmd = KDGETLED;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_KIOCSOUND:
	args->cmd = KIOCSOUND;
	return  ioctl(p, (struct ioctl_args *)args);

    case LINUX_KDMKTONE:
	args->cmd = KDMKTONE;
	return  ioctl(p, (struct ioctl_args *)args);


    case LINUX_CDROMPAUSE:
	args->cmd = CDIOCPAUSE;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMRESUME:
	args->cmd = CDIOCRESUME;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMPLAYMSF:
	args->cmd = CDIOCPLAYMSF;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMPLAYTRKIND:
	args->cmd = CDIOCPLAYTRACKS;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMSTART:
	args->cmd = CDIOCSTART;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMSTOP:
	args->cmd = CDIOCSTOP;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMEJECT:
	args->cmd = CDIOCEJECT;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMRESET:
	args->cmd = CDIOCRESET;
	return	ioctl(p, (struct ioctl_args *)args);

    case LINUX_CDROMREADTOCHDR: {
	struct ioc_toc_header th;
	struct linux_cdrom_tochdr lth;
	error = fo_ioctl(fp, CDIOREADTOCHEADER, (caddr_t)&th, p);
	if (!error) {
	    lth.cdth_trk0 = th.starting_track;
	    lth.cdth_trk1 = th.ending_track;
	    copyout((caddr_t)&lth, (caddr_t)args->arg, sizeof(lth));
	}
	return error;
    }

    case LINUX_CDROMREADTOCENTRY: {
	struct linux_cdrom_tocentry lte, *ltep =
	    (struct linux_cdrom_tocentry *)args->arg;
	struct ioc_read_toc_single_entry irtse;
	irtse.address_format = ltep->cdte_format;
	irtse.track = ltep->cdte_track;
	error = fo_ioctl(fp, CDIOREADTOCENTRY, (caddr_t)&irtse, p);
	if (!error) {
	    lte = *ltep;
	    lte.cdte_ctrl = irtse.entry.control;
	    lte.cdte_adr = irtse.entry.addr_type;
	    bsd_to_linux_msf_lba(irtse.address_format,
		&irtse.entry.addr, &lte.cdte_addr);
	    copyout((caddr_t)&lte, (caddr_t)args->arg, sizeof(lte));
	}
	return error;
    }

    case LINUX_CDROMSUBCHNL: {
	caddr_t sg;
	struct linux_cdrom_subchnl sc;
	struct ioc_read_subchannel bsdsc;
	struct cd_sub_channel_info *bsdinfo;

	sg = stackgap_init();
	bsdinfo = (struct cd_sub_channel_info*)stackgap_alloc(&sg,
			sizeof(struct cd_sub_channel_info));

	bsdsc.address_format = CD_LBA_FORMAT;
	bsdsc.data_format = CD_CURRENT_POSITION;
	bsdsc.data_len = sizeof(struct cd_sub_channel_info);
	bsdsc.data = bsdinfo;
	error = fo_ioctl(fp, CDIOCREADSUBCHANNEL, (caddr_t)&bsdsc, p);
	if (error)
	    return error;

	error = copyin((caddr_t)args->arg, (caddr_t)&sc,
			sizeof(struct linux_cdrom_subchnl));
	if (error)
	    return error;

	sc.cdsc_audiostatus = bsdinfo->header.audio_status;
	sc.cdsc_adr = bsdinfo->what.position.addr_type;
	sc.cdsc_ctrl = bsdinfo->what.position.control;
	sc.cdsc_trk = bsdinfo->what.position.track_number;
	sc.cdsc_ind = bsdinfo->what.position.index_number;
	set_linux_cdrom_addr(&sc.cdsc_absaddr, sc.cdsc_format,
			bsdinfo->what.position.absaddr.lba);
	set_linux_cdrom_addr(&sc.cdsc_reladdr, sc.cdsc_format,
			bsdinfo->what.position.reladdr.lba);
	error = copyout((caddr_t)&sc, (caddr_t)args->arg,
			sizeof(struct linux_cdrom_subchnl));
	return error;
    }

    case LINUX_OSS_GETVERSION: {
	int version;

	version = linux_get_oss_version(p);
	return copyout((caddr_t)&version, (caddr_t)args->arg, sizeof(int));
    }

    }

    uprintf("LINUX: 'ioctl' fd=%d, typ=0x%x(%c), num=0x%x not implemented\n",
	args->fd, (u_int)((args->cmd & 0xffff00) >> 8),
	(int)((args->cmd & 0xffff00) >> 8), (u_int)(args->cmd & 0xff));
    return EINVAL;
}
