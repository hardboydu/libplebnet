/*
 * Copyright (c) 2000 Alfred Perlstein <alfred@freebsd.org>
 * All rights reserved.
 * Copyright (c) 2000 Paul Saab <ps@freebsd.org>
 * All rights reserved.
 * Copyright (c) 2000 John Baldwin <jhb@freebsd.org>
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
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <stand.h>

#include <sys/reboot.h>
#include <string.h>
#include <sys/reboot.h>
#include <arpa/tftp.h>

#include <stdarg.h>

#include <bootstrap.h>
#include "btxv86.h"
#include "pxe.h"

/*
 * Allocate the PXE buffers statically instead of sticking grimy fingers into
 * BTX's private data area.  The scratch buffer is used to send information to
 * the PXE BIOS, and the data buffer is used to receive data from the PXE BIOS.
 */
#define	PXE_BUFFER_SIZE		0x2000
#define	PXE_TFTP_BUFFER_SIZE	512
static char	scratch_buffer[PXE_BUFFER_SIZE];
static char	data_buffer[PXE_BUFFER_SIZE];

static uint32_t	myip;		/* my IP address */
static uint32_t	serverip;	/* where I got my initial bootstrap from */
static uint32_t	secondip;	/* where I should go to get the rest of my boot files */
static char	*servername = NULL;	/* name of server I DHCP'd from */
static char	*bootfile = NULL;	/* name of file that I booted with */
static uint16_t	pxe_return_status;
static uint16_t pxe_open_status;
static pxenv_t  *pxenv_p = NULL;        /* PXENV+ */
static pxe_t    *pxe_p = NULL;          /* !PXE */

void		pxe_enable(void *pxeinfo);
static int	pxe_init(void);
static int	pxe_strategy(void *devdata, int flag, daddr_t dblk, size_t size,
			     void *buf, size_t *rsize);
static int	pxe_open(struct open_file *f, ...);
static int	pxe_close(struct open_file *f);
static void	pxe_print(int verbose);

static void	pxe_perror(int error);
void		pxe_call(int func);

static int	pxe_fs_open(const char *path, struct open_file *f);
static int	pxe_fs_close(struct open_file *f);
static int	pxe_fs_read(struct open_file *f, void *buf, size_t size, size_t *resid);
static int	pxe_fs_write(struct open_file *f, void *buf, size_t size, size_t *resid);
static off_t	pxe_fs_seek(struct open_file *f, off_t offset, int where);
static int	pxe_fs_stat(struct open_file *f, struct stat *sb);


struct devsw pxedisk = {
	"pxe", 
	DEVT_NET,
	pxe_init,
	pxe_strategy, 
	pxe_open, 
	pxe_close, 
	noioctl,
	pxe_print
};

struct fs_ops pxe_fsops = {
	"pxe",
	pxe_fs_open,
	pxe_fs_close,
	pxe_fs_read,
	pxe_fs_write,
	pxe_fs_seek,
	pxe_fs_stat
};

/*
 * This function is called by the loader to enable PXE support if we
 * are booted by PXE.  The passed in pointer is a pointer to the
 * PXENV+ structure.
 */
void
pxe_enable(void *pxeinfo)
{
	pxenv_p = (pxenv_t *)pxeinfo;
}

/* 
 * return true if pxe structures are found/initialized,
 * also figures out our IP information via the pxe cached info struct 
 */
static int
pxe_init(void)
{
	t_PXENV_GET_CACHED_INFO	*gci_p;
	BOOTPLAYER	*bootplayer;
	int	counter;
	uint8_t checksum;
	uint8_t *checkptr;
	
	if(pxenv_p == NULL)
		return (0);

	/*  look for "PXENV+" */
	if (bcmp((void *)pxenv_p->Signature, S_SIZE("PXENV+")))
		return (0);

	/* make sure the size is something we can handle */
	if (pxenv_p->Length > sizeof(*pxenv_p)) {
	  	printf("PXENV+ structure too large, ignoring\n");
		pxenv_p = NULL;
		return (0);
	}
	    
	/* 
	 * do byte checksum:
	 * add up each byte in the structure, the total should be 0
	 */
	checksum = 0;	
	checkptr = (uint8_t *) pxenv_p;
	for (counter = 0; counter < pxenv_p->Length; counter++)
		checksum += *checkptr++;
	if (checksum != 0) {
		printf("PXENV+ structure failed checksum, ignoring\n");
		pxenv_p = NULL;
		return (0);
	}
	printf("\nPXENV+ version %d.%d, real mode entry point @%04x:%04x\n", 
		(uint8_t) (pxenv_p->Version >> 8),
	        (uint8_t) (pxenv_p->Version & 0xFF),
		pxenv_p->RMEntry.segment, pxenv_p->RMEntry.offset);

	gci_p = (t_PXENV_GET_CACHED_INFO *) scratch_buffer;
	bzero(gci_p, sizeof(*gci_p));
	gci_p->PacketType =  PXENV_PACKET_TYPE_BINL_REPLY;
	pxe_call(PXENV_GET_CACHED_INFO);
	if (gci_p->Status != 0) {
		pxe_perror(gci_p->Status);
		pxenv_p = NULL;
		return (0);
	}
	bootplayer = (BOOTPLAYER *) 
		PTOV((gci_p->Buffer.segment << 4) + gci_p->Buffer.offset);
	serverip = bootplayer->sip;
	servername = strdup(bootplayer->Sname);
	bootfile = strdup(bootplayer->bootfile);
	myip = bootplayer->yip;
	secondip = bootplayer->sip;

	return (1);
}

int
pxe_tftpopen(uint32_t srcip, uint32_t gateip, char *filename, uint16_t port,
             uint16_t pktsize)
{
	t_PXENV_TFTP_OPEN *tftpo_p;

	tftpo_p = (t_PXENV_TFTP_OPEN *)scratch_buffer;
	bzero(tftpo_p, sizeof(*tftpo_p));
	tftpo_p->ServerIPAddress	= srcip;
	tftpo_p->GatewayIPAddress	= gateip;
	tftpo_p->TFTPPort		= port;
	tftpo_p->PacketSize		= pktsize;
	bcopy(filename, tftpo_p->FileName, strlen(filename));
	pxe_call(PXENV_TFTP_OPEN);
	pxe_return_status = tftpo_p->Status;
	if (tftpo_p->Status != 0)
		return (-1);
	return (tftpo_p->PacketSize);
}

int
pxe_tftpclose(void)
{
	t_PXENV_TFTP_CLOSE *tftpc_p;

	tftpc_p = (t_PXENV_TFTP_CLOSE *)scratch_buffer;
	bzero(tftpc_p, sizeof(*tftpc_p));
	pxe_call(PXENV_TFTP_CLOSE);
	pxe_return_status = tftpc_p->Status;
	if (tftpc_p->Status != 0)
		return (-1);
	return (1);
}

int
pxe_tftpread(void *buf)
{
	t_PXENV_TFTP_READ *tftpr_p;

	tftpr_p = (t_PXENV_TFTP_READ *)scratch_buffer;
	bzero(tftpr_p, sizeof(*tftpr_p));
        
	tftpr_p->Buffer.segment	= VTOPSEG(data_buffer);
	tftpr_p->Buffer.offset	= VTOPOFF(data_buffer);

	pxe_call(PXENV_TFTP_READ);

	/* XXX - I don't know why we need this. */
	delay(1000);

	pxe_return_status = tftpr_p->Status;
	if (tftpr_p->Status != 0)
		return (-1);
	bcopy(data_buffer, buf, tftpr_p->BufferSize);
	return (tftpr_p->BufferSize);
}

void
pxe_perror(int err)
{
	return;
}


void
pxe_call(int func)
{
	bzero(&v86, sizeof(v86));
	bzero(data_buffer, sizeof(data_buffer));
	v86.ctl = V86_ADDR | V86_CALLF | V86_FLAGS;
	/* high 16 == segment, low 16 == offset, shift and or */
	v86.addr = 
	    ((uint32_t)pxenv_p->RMEntry.segment << 16) | pxenv_p->RMEntry.offset;
	v86.es = VTOPSEG(scratch_buffer);
	v86.edi = VTOPOFF(scratch_buffer);
	v86.ebx = func;
	v86int();
	v86.ctl = V86_FLAGS;
}

static int
pxe_strategy(void *devdata, int flag, daddr_t dblk, size_t size,
		void *buf, size_t *rsize)
{
	return (EIO);
}

static int
pxe_open(struct open_file *f, ...)
{
	return (0);
}

static int
pxe_close(struct open_file *f)
{
	return (0);
}

static void
pxe_print(int verbose)
{
	if (pxenv_p != NULL) {
		if (*servername == '\0') {
			printf("      "IP_STR":/%s\n", IP_ARGS(htonl(serverip)),
			       bootfile);
		} else {
			printf("      %s:/%s\n", servername, bootfile);
		}
	}

	return;
}


/*
 * Most of this code was ripped from libstand/tftp.c and
 * modified to work with pxe. :)
 */
#define RSPACE 520              /* max data packet, rounded up */

struct tftp_handle {
        int             currblock;      /* contents of lastdata */
        int             islastblock;    /* flag */
        int             validsize;
        int             off;
	int		opened;
        char           *path;   /* saved for re-requests */
	u_char		space[RSPACE];
};

static int 
tftp_makereq(h)
        struct tftp_handle *h;
{
        ssize_t         res;
	char *p;
	
	p = h->path;

	if (*p == '/')
		++p;
	if (h->opened)
		pxe_tftpclose();
	
	if (pxe_tftpopen(serverip, 0, p, htons(69), PXE_TFTP_BUFFER_SIZE) < 0)
		return(ENOENT);
	pxe_open_status = pxe_return_status;
	res = pxe_tftpread(h->space);
	
        if (res == -1)
                return (errno);
        h->currblock = 1;
        h->validsize = res;
        h->islastblock = 0;
        if (res < SEGSIZE)
                h->islastblock = 1;     /* very short file */
        return (0);
}

/* ack block, expect next */
static int 
tftp_getnextblock(h)
        struct tftp_handle *h;
{
	int res;

	res = pxe_tftpread(h->space);

        if (res == -1)          /* 0 is OK! */
                return (errno);

        h->currblock++;
        h->validsize = res;
        if (res < SEGSIZE)
                h->islastblock = 1;     /* EOF */
        return (0);
}

static int
pxe_fs_open(const char *path, struct open_file *f)
{
        struct tftp_handle *tftpfile;
	int             res;

	/* make sure the device is a PXE device */
	if(f->f_dev != &pxedisk)
		return (EINVAL);

	tftpfile = (struct tftp_handle *) malloc(sizeof(*tftpfile));
        if (!tftpfile)
                return (ENOMEM);

        tftpfile->off = 0;
        tftpfile->path = strdup(path);
        if (tftpfile->path == NULL) {
        	free(tftpfile);
        	return(ENOMEM);
        }

        res = tftp_makereq(tftpfile);

        if (res) {
                free(tftpfile->path);
                free(tftpfile);
                return (res);
        }
	tftpfile->opened = 1;
        f->f_fsdata = (void *) tftpfile;
	return(0);
}

static int
pxe_fs_close(struct open_file *f)
{
	struct tftp_handle *tftpfile;
        tftpfile = (struct tftp_handle *) f->f_fsdata;

	if (tftpfile) {
		if (tftpfile->opened) 
			pxe_tftpclose();
		free(tftpfile->path);
                free(tftpfile);
        }
	return (0);
}

static int
pxe_fs_read(struct open_file *f, void *addr, size_t size, size_t *resid)
{
        struct tftp_handle *tftpfile;
        static int      tc = 0;
	char *dest = (char *)addr;
        tftpfile = (struct tftp_handle *) f->f_fsdata;

	while (size > 0) {
                int needblock, count;

                if (!(tc++ % 16))
                        twiddle();

                needblock = tftpfile->off / SEGSIZE + 1;

                if (tftpfile->currblock > needblock)    /* seek backwards */
                        tftp_makereq(tftpfile); /* no error check, it worked
                                                 * for open */

                while (tftpfile->currblock < needblock) {
                        int res;

                        res = tftp_getnextblock(tftpfile);
                        if (res) {      /* no answer */
                                return (res);
                        }
                        if (tftpfile->islastblock)
                                break;
                }

                if (tftpfile->currblock == needblock) {
                        int offinblock, inbuffer;
                        offinblock = tftpfile->off % SEGSIZE;
			
                        inbuffer = tftpfile->validsize - offinblock;
                        if (inbuffer < 0) {
                                return (EINVAL);
                        }
                        count = (size < inbuffer ? size : inbuffer);
                        bcopy(tftpfile->space + offinblock,
                            dest, count);

                        dest += count;
                        tftpfile->off += count;
                        size -= count;

                        if ((tftpfile->islastblock) && (count == inbuffer))
                                break;  /* EOF */
                } else {
                        printf("tftp: block %d not found\n", needblock);
                        return (EINVAL);
                }

        }

	if (resid)
	        *resid = size;
	return(0);
}

static int
pxe_fs_write(struct open_file *f, void *buf, size_t size, size_t *resid)
{
	return 0;
}

static off_t
pxe_fs_seek(struct open_file *f, off_t offset, int where)
{
	struct tftp_handle *tftpfile;
        tftpfile = (struct tftp_handle *) f->f_fsdata;

        switch (where) {
        case SEEK_SET:
                tftpfile->off = offset;
                break;
        case SEEK_CUR:
                tftpfile->off += offset;
                break;
        default:
                errno = EOFFSET;
                return (-1);
        }
        return (tftpfile->off);
}

static int
pxe_fs_stat(struct open_file *f, struct stat *sb)
{
	if (pxe_open_status != 0)
		return -1;
	
	sb->st_mode = 0444 | S_IFREG;
        sb->st_nlink = 1;
        sb->st_uid = 0;
        sb->st_gid = 0;
        sb->st_size = -1;

	return 0;
}
