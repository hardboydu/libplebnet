/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
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
 *	$Id: biosdisk.c,v 1.14 1998/10/11 10:29:49 peter Exp $
 */

/*
 * BIOS disk device handling.
 * 
 * Ideas and algorithms from:
 *
 * - NetBSD libi386/biosdisk.c
 * - FreeBSD biosboot/disk.c
 *
 * XXX Todo: add bad144 support.
 */

#include <stand.h>

#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include <sys/reboot.h>

#include <stdarg.h>

#include <bootstrap.h>
#include <btxv86.h>
#include "libi386.h"

#define BIOSDISK_SECSIZE	512
#define BUFSIZE			(1 * BIOSDISK_SECSIZE)
#define	MAXBDDEV		MAXDEV

#define DT_ATAPI		0x10		/* disk type for ATAPI floppies */
#define WDMAJOR			0		/* major numbers for devices we frontend for */
#define WFDMAJOR		1
#define FDMAJOR			2
#define DAMAJOR			4

#ifdef DISK_DEBUG
# define DEBUG(fmt, args...)	printf("%s: " fmt "\n" , __FUNCTION__ , ## args)
#else
# define DEBUG(fmt, args...)
#endif

struct open_disk {
    int			od_dkunit;		/* disk unit number */
    int			od_unit;		/* BIOS unit number */
    int			od_cyl;			/* BIOS geometry */
    int			od_hds;
    int			od_sec;
    int			od_boff;		/* block offset from beginning of BIOS disk */
    int			od_flags;
#define	BD_MODEMASK	0x3
#define BD_MODEINT13	0x0
#define BD_MODEEDD1	0x1
#define BD_MODEEDD3	0x2
#define BD_FLOPPY	(1<<2)
    struct disklabel		od_disklabel;
    struct dos_partition	od_parttab[NDOSPART];	/* XXX needs to grow for extended partitions */
#define BD_LABELOK	(1<<3)
#define BD_PARTTABOK	(1<<4)
};

/*
 * List of BIOS devices, translation from disk unit number to
 * BIOS unit number.
 */
static struct bdinfo
{
    int		bd_unit;		/* BIOS unit number */
    int		bd_flags;
    int		bd_type;		/* BIOS 'drive type' (floppy only) */
} bdinfo [MAXBDDEV];
static int nbdinfo = 0;

static int	bd_getgeom(struct open_disk *od);
static int	bd_read(struct open_disk *od, daddr_t dblk, int blks, caddr_t dest);

static int	bd_int13probe(struct bdinfo *bd);

static int	bd_init(void);
static int	bd_strategy(void *devdata, int flag, daddr_t dblk, size_t size, void *buf, size_t *rsize);
static int	bd_open(struct open_file *f, ...);
static int	bd_close(struct open_file *f);

struct devsw biosdisk = {
    "disk", 
    DEVT_DISK, 
    bd_init,
    bd_strategy, 
    bd_open, 
    bd_close, 
    noioctl
};

static int	bd_opendisk(struct open_disk **odp, struct i386_devdesc *dev);
static void	bd_closedisk(struct open_disk *od);
static int	bd_bestslice(struct dos_partition *dptr);

/*
 * Translate between BIOS device numbers and our private unit numbers.
 */
int
bd_bios2unit(int biosdev)
{
    int		i;
    
    DEBUG("looking for bios device 0x%x", biosdev);
    for (i = 0; i < nbdinfo; i++) {
	DEBUG("bd unit %d is BIOS device 0x%x", i, bdinfo[i].bd_unit);
	if (bdinfo[i].bd_unit == biosdev)
	    return(i);
    }
    return(-1);
}

int
bd_unit2bios(int unit)
{
    if ((unit >= 0) && (unit < nbdinfo))
	return(bdinfo[unit].bd_unit);
    return(-1);
}

/*    
 * Quiz the BIOS for disk devices, save a little info about them.
 *
 * XXX should we be consulting the BIOS equipment list, specifically
 *     the value at 0x475?
 */
static int
bd_init(void) 
{
    int		base, unit;

    /* sequence 0, 0x80 */
    for (base = 0; base <= 0x80; base += 0x80) {
	for (unit = base; (nbdinfo < MAXBDDEV); unit++) {
	    bdinfo[nbdinfo].bd_unit = unit;
	    bdinfo[nbdinfo].bd_flags = (unit < 0x80) ? BD_FLOPPY : 0;

	    /* XXX add EDD probes */
	    if (!bd_int13probe(&bdinfo[nbdinfo]))
		break;

	    /* XXX we need "disk aliases" to make this simpler */
	    printf("BIOS drive %c: is disk%d\n", 
		   (unit < 0x80) ? ('A' + unit) : ('C' + unit - 0x80), nbdinfo);
	    bdinfo[nbdinfo].bd_unit = unit;
	    nbdinfo++;
	}
    }
    return(0);
}

/*
 * Try to detect a device supported by the legacy int13 BIOS
 */

static int
bd_int13probe(struct bdinfo *bd)
{

    v86.ctl = V86_FLAGS;
    v86.addr = 0x13;
    v86.eax = 0x800;
    v86.edx = bd->bd_unit;
    v86int();
    
    if (!(v86.efl & 0x1) &&				/* carry clear */
	((v86.edx & 0xff) > (bd->bd_unit & 0x7f))) {	/* unit # OK */
	bd->bd_flags |= BD_MODEINT13;
	bd->bd_type = v86.ebx & 0xff;
	return(1);
    }
    return(0);
}

/*
 * Attempt to open the disk described by (dev) for use by (f).
 *
 * Note that the philosophy here is "give them exactly what
 * they ask for".  This is necessary because being too "smart"
 * about what the user might want leads to complications.
 * (eg. given no slice or partition value, with a disk that is
 *  sliced - are they after the first BSD slice, or the DOS
 *  slice before it?)
 */
static int 
bd_open(struct open_file *f, ...)
{
    va_list			ap;
    struct i386_devdesc		*dev;
    struct open_disk		*od;
    int				error;

    va_start(ap, f);
    dev = va_arg(ap, struct i386_devdesc *);
    va_end(ap);
    if ((error = bd_opendisk(&od, dev)))
	return(error);
    
    /*
     * Save our context
     */
    ((struct i386_devdesc *)(f->f_devdata))->d_kind.biosdisk.data = od;
    DEBUG("open_disk %p, partition at 0x%x", od, od->od_boff);
    return(0);
}

static int
bd_opendisk(struct open_disk **odp, struct i386_devdesc *dev)
{
    struct dos_partition	*dptr;
    struct disklabel		*lp;
    struct open_disk		*od;
    int				sector, slice, i;
    int				error;
    u_char			buf[BUFSIZE];
    daddr_t			pref_slice[4];

    if (dev->d_kind.biosdisk.unit >= nbdinfo) {
	DEBUG("attempt to open nonexistent disk");
	return(ENXIO);
    }
    
    od = (struct open_disk *)malloc(sizeof(struct open_disk));
    if (!od) {
	DEBUG("no memory");
	return (ENOMEM);
    }

    /* Look up BIOS unit number, intialise open_disk structure */
    od->od_dkunit = dev->d_kind.biosdisk.unit;
    od->od_unit = bdinfo[od->od_dkunit].bd_unit;
    od->od_flags = bdinfo[od->od_dkunit].bd_flags;
    od->od_boff = 0;
    error = 0;
    DEBUG("open '%s', unit 0x%x slice %d partition %c",
	     i386_fmtdev(dev), dev->d_kind.biosdisk.unit, 
	     dev->d_kind.biosdisk.slice, dev->d_kind.biosdisk.partition + 'a');

    /* Get geometry for this open (removable device may have changed) */
    if (bd_getgeom(od)) {
	DEBUG("can't get geometry");
	error = ENXIO;
	goto out;
    }

    /*
     * Following calculations attempt to determine the correct value
     * for d->od_boff by looking for the slice and partition specified,
     * or searching for reasonable defaults.
     */

    /*
     * Find the slice in the DOS slice table.
     */
    if (bd_read(od, 0, 1, buf)) {
	DEBUG("error reading MBR");
	error = EIO;
	goto out;
    }

    /* 
     * Check the slice table magic.
     */
    if ((buf[0x1fe] != 0x55) || (buf[0x1ff] != 0xaa)) {
	/* If a slice number was explicitly supplied, this is an error */
	if (dev->d_kind.biosdisk.slice > 0) {
	    DEBUG("no slice table/MBR (no magic)");
	    error = ENOENT;
	    goto out;
	}
	sector = 0;
	goto unsliced;		/* may be a floppy */
    }
    bcopy(buf + DOSPARTOFF, &od->od_parttab, sizeof(struct dos_partition) * NDOSPART);
    dptr = &od->od_parttab[0];
    od->od_flags |= BD_PARTTABOK;

    /* Try to auto-detect the best slice; this should always give a slice number */
    if (dev->d_kind.biosdisk.slice < 1)
	dev->d_kind.biosdisk.slice = bd_bestslice(dptr);

    switch (dev->d_kind.biosdisk.slice) {
    case -1:
	error = ENOENT;
	goto out;
    case 0:
	sector = 0;
	goto unsliced;
    default:
	break;
    }

    /*
     * Accept the supplied slice number unequivocally (we may be looking
     * at a DOS partition).
     */
    dptr += (dev->d_kind.biosdisk.slice - 1);	/* we number 1-4, offsets are 0-3 */
    sector = dptr->dp_start;
    DEBUG("slice entry %d at %d, %d sectors", dev->d_kind.biosdisk.slice - 1, sector, dptr->dp_size);

    /*
     * If we are looking at a BSD slice, and the partition is < 0, assume the 'a' partition
     */
    if ((dptr->dp_typ == DOSPTYP_386BSD) && (dev->d_kind.biosdisk.partition < 0))
	dev->d_kind.biosdisk.partition = 0;

 unsliced:
    /* 
     * Now we have the slice offset, look for the partition in the disklabel if we have
     * a partition to start with.
     *
     * XXX we might want to check the label checksum.
     */
    if (dev->d_kind.biosdisk.partition < 0) {
	od->od_boff = sector;		/* no partition, must be after the slice */
	DEBUG("opening raw slice");
    } else {
	
	if (bd_read(od, sector + LABELSECTOR, 1, buf)) {
	    DEBUG("error reading disklabel");
	    error = EIO;
	    goto out;
	}
	DEBUG("copy %d bytes of label from %p to %p", sizeof(struct disklabel), buf + LABELOFFSET, &od->od_disklabel);
	bcopy(buf + LABELOFFSET, &od->od_disklabel, sizeof(struct disklabel));
	lp = &od->od_disklabel;
	od->od_flags |= BD_LABELOK;

	if (lp->d_magic != DISKMAGIC) {
	    DEBUG("no disklabel");
	    error = ENOENT;
	    goto out;
	}
	if (dev->d_kind.biosdisk.partition >= lp->d_npartitions) {
	    DEBUG("partition '%c' exceeds partitions in table (a-'%c')",
		  'a' + dev->d_kind.biosdisk.partition, 'a' + lp->d_npartitions);
	    error = EPART;
	    goto out;

	}

	/* Complain if the partition type is wrong */
	if ((lp->d_partitions[dev->d_kind.biosdisk.partition].p_fstype == FS_UNUSED) &&
	    !(od->od_flags & BD_FLOPPY))	    /* Floppies often have bogus fstype */
	    DEBUG("warning, partition marked as unused");
	
	od->od_boff = lp->d_partitions[dev->d_kind.biosdisk.partition].p_offset;
    }
    
 out:
    if (error) {
	free(od);
    } else {
	*odp = od;	/* return the open disk */
    }
    return(error);
}


/*
 * Search for a slice with the following preferences:
 *
 * 1: Active FreeBSD slice
 * 2: Non-active FreeBSD slice
 * 3: Active FAT/FAT32 slice
 * 4: non-active FAT/FAT32 slice
 */
#define PREF_FBSD_ACT	0
#define PREF_FBSD	1
#define PREF_DOS_ACT	2
#define PREF_DOS	3
#define PREF_NONE	4

static int
bd_bestslice(struct dos_partition *dptr)
{
    int		i;
    int		preflevel, pref;

	
    /*
     * Check for the historically bogus MBR found on true dedicated disks
     */
    if ((dptr[3].dp_typ == DOSPTYP_386BSD) &&
	(dptr[3].dp_start == 0) &&
	(dptr[3].dp_size == 50000)) 
	return(0);

    preflevel = PREF_NONE;
    pref = -1;
    
    /* 
     * XXX No support here for 'extended' slices
     */
    for (i = 0; i < NDOSPART; i++) {
	switch(dptr[i].dp_typ) {
	case DOSPTYP_386BSD:			/* FreeBSD */
	    if ((dptr[i].dp_flag & 0x80) && (preflevel > PREF_FBSD_ACT)) {
		pref = i;
		preflevel = PREF_FBSD_ACT;
	    } else if (preflevel > PREF_FBSD) {
		pref = i;
		preflevel = PREF_FBSD;
	    }
	    break;
	    
	    case 0x04:				/* DOS/Windows */
	    case 0x06:
	    case 0x0b:
	    case 0x0c:
	    case 0x0e:
	    case 0x63:
	    if ((dptr[i].dp_flag & 0x80) && (preflevel > PREF_DOS_ACT)) {
		pref = i;
		preflevel = PREF_DOS_ACT;
	    } else if (preflevel > PREF_DOS) {
		pref = i;
		preflevel = PREF_DOS;
	    }
	    break;
	}
    }
    return(pref + 1);	/* slices numbered 1-4 */
}
 

static int 
bd_close(struct open_file *f)
{
    struct open_disk	*od = (struct open_disk *)(((struct i386_devdesc *)(f->f_devdata))->d_kind.biosdisk.data);

    bd_closedisk(od);
    return(0);
}

static void
bd_closedisk(struct open_disk *od)
{
    DEBUG("open_disk %p", od);
#if 0
    /* XXX is this required? (especially if disk already open...) */
    if (od->od_flags & BD_FLOPPY)
	delay(3000000);
#endif
    free(od);
}

static int 
bd_strategy(void *devdata, int rw, daddr_t dblk, size_t size, void *buf, size_t *rsize)
{
    struct open_disk	*od = (struct open_disk *)(((struct i386_devdesc *)devdata)->d_kind.biosdisk.data);
    int			blks;
#ifdef BD_SUPPORT_FRAGS
    char		fragbuf[BIOSDISK_SECSIZE];
    size_t		fragsize;

    fragsize = size % BIOSDISK_SECSIZE;
#else
    if (size % BIOSDISK_SECSIZE)
	panic("bd_strategy: %d bytes I/O not multiple of block size", size);
#endif

    DEBUG("open_disk %p", od);

    if (rw != F_READ)
	return(EROFS);


    blks = size / BIOSDISK_SECSIZE;
    DEBUG("read %d from %d+%d to %p", blks, od->od_boff, dblk, buf);

    if (rsize)
	*rsize = 0;
    if (blks && bd_read(od, dblk + od->od_boff, blks, buf)) {
	DEBUG("read error");
	return (EIO);
    }
#ifdef BD_SUPPORT_FRAGS
    DEBUG("bd_strategy: frag read %d from %d+%d+d to %p", 
	     fragsize, od->od_boff, dblk, blks, buf + (blks * BIOSDISK_SECSIZE));
    if (fragsize && bd_read(od, dblk + od->od_boff + blks, 1, fragsize)) {
	DEBUG("frag read error");
	return(EIO);
    }
    bcopy(fragbuf, buf + (blks * BIOSDISK_SECSIZE), fragsize);
#endif
    if (rsize)
	*rsize = size;
    return (0);
}

/* Max number of sectors to bounce-buffer if the request crosses a 64k boundary */
#define FLOPPY_BOUNCEBUF	18

static int
bd_read(struct open_disk *od, daddr_t dblk, int blks, caddr_t dest)
{
    int		x, bpc, cyl, hd, sec, result, resid, cnt, retry, maxfer;
    caddr_t	p, xp, bbuf, breg;
    
    bpc = (od->od_sec * od->od_hds);		/* blocks per cylinder */
    resid = blks;
    p = dest;

    /* Decide whether we have to bounce */
    if ((od->od_unit < 0x80) && 
	((VTOP(dest) >> 16) != (VTOP(dest + blks * BIOSDISK_SECSIZE) >> 16))) {

	/* 
	 * There is a 64k physical boundary somewhere in the destination buffer, so we have
	 * to arrange a suitable bounce buffer.  Allocate a buffer twice as large as we
	 * need to.  Use the bottom half unless there is a break there, in which case we
	 * use the top half.
	 */
	x = min(FLOPPY_BOUNCEBUF, blks);
	bbuf = malloc(x * 2 * BIOSDISK_SECSIZE);
	if (((u_int32_t)VTOP(bbuf) & 0xffff0000) == ((u_int32_t)VTOP(dest + x * BIOSDISK_SECSIZE) & 0xffff0000)) {
	    breg = bbuf;
	} else {
	    breg = bbuf + x * BIOSDISK_SECSIZE;
	}
	maxfer = x;			/* limit transfers to bounce region size */
    } else {
	bbuf = NULL;
	maxfer = 0;
    }
    
    while (resid > 0) {
	x = dblk;
	cyl = x / bpc;			/* block # / blocks per cylinder */
	x %= bpc;			/* block offset into cylinder */
	hd = x / od->od_sec;		/* offset / blocks per track */
	sec = x % od->od_sec;		/* offset into track */

	/* play it safe and don't cross track boundaries (XXX this is probably unnecessary) */
	x = min(od->od_sec - sec, resid);
	if (maxfer > 0)
	    x = min(x, maxfer);		/* fit bounce buffer */

	/* where do we transfer to? */
	xp = bbuf == NULL ? p : breg;

	/* correct sector number for 1-based BIOS numbering */
	sec++;

	/* Loop retrying the operation a couple of times.  The BIOS may also retry. */
	for (retry = 0; retry < 3; retry++) {
	    /* if retrying, reset the drive */
	    if (retry > 0) {
		v86.ctl = V86_FLAGS;
		v86.addr = 0x13;
		v86.eax = 0;
		v86.edx = od->od_unit;
		v86int();
	    }
	    
	    /* build request  XXX support EDD requests too */
	    v86.ctl = V86_FLAGS;
	    v86.addr = 0x13;
	    v86.eax = 0x200 | x;
	    v86.ecx = ((cyl & 0xff) << 8) | ((cyl & 0x300) >> 2) | sec;
	    v86.edx = (hd << 8) | od->od_unit;
	    v86.es = VTOPSEG(xp);
	    v86.ebx = VTOPOFF(xp);
	    v86int();
	    result = (v86.efl & 0x1);
	    if (result == 0)
		break;
	}
	
 	DEBUG("%d sectors from %d/%d/%d to %p (0x%x) %s", x, cyl, hd, sec - 1, p, VTOP(p), result ? "failed" : "ok");
	/* BUG here, cannot use v86 in printf because putchar uses it too */
	DEBUG("ax = 0x%04x cx = 0x%04x dx = 0x%04x status 0x%x", 
	      0x200 | x, ((cyl & 0xff) << 8) | ((cyl & 0x300) >> 2) | sec, (hd << 8) | od->od_unit, (v86.eax >> 8) & 0xff);
	if (result) {
	    if (bbuf != NULL)
		free(bbuf);
	    return(-1);
	}
	if (bbuf != NULL)
	    bcopy(breg, p, x * BIOSDISK_SECSIZE);
	p += (x * BIOSDISK_SECSIZE);
	dblk += x;
	resid -= x;
    }
	
/*    hexdump(dest, (blks * BIOSDISK_SECSIZE)); */
    if (bbuf != NULL)
	free(bbuf);
    return(0);
}

static int
bd_getgeom(struct open_disk *od)
{

    v86.ctl = V86_FLAGS;
    v86.addr = 0x13;
    v86.eax = 0x800;
    v86.edx = od->od_unit;
    v86int();

    if ((v86.efl & 0x1) ||				/* carry set */
	((v86.edx & 0xff) <= (od->od_unit & 0x7f)))	/* unit # bad */
	return(1);
    
    /* convert max cyl # -> # of cylinders */
    od->od_cyl = ((v86.ecx & 0xc0) << 2) + ((v86.ecx & 0xff00) >> 8) + 1;
    /* convert max head # -> # of heads */
    od->od_hds = ((v86.edx & 0xff00) >> 8) + 1;
    od->od_sec = v86.ecx & 0x3f;

    DEBUG("unit 0x%x geometry %d/%d/%d", od->od_unit, od->od_cyl, od->od_hds, od->od_sec);
    return(0);
}

/*
 * Return a suitable dev_t value for (dev)
 */
int
bd_getdev(struct i386_devdesc *dev)
{
    struct open_disk		*od;
    int				biosdev;
    int 			major;
    int				rootdev;

    biosdev = bd_unit2bios(dev->d_kind.biosdisk.unit);
    DEBUG("unit %d BIOS device %d", dev->d_kind.biosdisk.unit, biosdev);
    if (biosdev == -1)				/* not a BIOS device */
	return(-1);
    if (bd_opendisk(&od, dev) != 0)		/* oops, not a viable device */
	return(-1);

    if (biosdev < 0x80) {
	/* floppy (or emulated floppy) or ATAPI device */
	if (bdinfo[dev->d_kind.biosdisk.unit].bd_type == DT_ATAPI) {
	    /* is an ATAPI disk */
	    major = WFDMAJOR;
	} else {
	    /* is a floppy disk */
	    major = FDMAJOR;
	}
    } else {
	/* harddisk */
	if ((od->od_flags & BD_LABELOK) && (od->od_disklabel.d_type == DTYPE_SCSI)) {
	    /* label OK, disk labelled as SCSI */
	    major = DAMAJOR;
	} else {
	    /* assume an IDE disk */
	    major = WDMAJOR;
	}
    }
    rootdev = MAKEBOOTDEV(major,
			  (dev->d_kind.biosdisk.slice + 1) >> 4, 	/* XXX slices may be wrong here */
			  (dev->d_kind.biosdisk.slice + 1) & 0xf, 
			  biosdev & 0x7f,				/* XXX allow/compute shift for da when wd present */
			  dev->d_kind.biosdisk.partition);
    DEBUG("dev is 0x%x\n", rootdev);
    return(rootdev);
}

/*
 * Fix (dev) so that it refers to the 'real' disk/slice/partition that it implies.
 */
int
bd_fixupdev(struct i386_devdesc *dev)
{
    struct open_disk *od;
    
    /*
     * Open the disk.  This will fix up the slice and partition fields.
     */
    if (bd_opendisk(&od, dev) != 0)
	return(ENOENT);
    
    bd_closedisk(od);
}
