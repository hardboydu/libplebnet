/*-
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
 *	from: @(#)autoconf.c	7.1 (Berkeley) 5/9/91
 *	$Id$
 */

/*
 * Setup the system to run on the current machine.
 *
 * Configure() is called at boot time and initializes the vba
 * device tables and the memory controller monitoring.  Available
 * devices are determined (from possibilities mentioned in ioconf.c),
 * and the drivers are initialized.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/dmap.h>
#include <sys/reboot.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>

#include <machine/bootinfo.h>
#include <machine/cons.h>
#include <machine/md_var.h>
#include <i386/isa/icu.h> /* For interrupts */

#include "isa.h"
#if NISA > 0
#include <i386/isa/isa_device.h>
#endif

#include "eisa.h"
#if NEISA > 0
#include <i386/eisa/eisaconf.h>
#endif

#include "pci.h"
#if NPCI > 0
#include <pci/pcivar.h>
#endif

#include "crd.h"
#if NCRD > 0
#include <pccard/driver.h>
#endif

#include "scbus.h"
#if NSCBUS > 0
#include <scsi/scsiconf.h>
#endif

static void	configure __P((void *));
SYSINIT(configure, SI_SUB_CONFIGURE, SI_ORDER_FIRST, configure, NULL)

static void	configure_finish __P((void));
static void	configure_start __P((void));
static int	setdumpdev __P((dev_t dev));
static void	setroot __P((void));

#ifdef CD9660

#include <isofs/cd9660/iso.h>

/* We need to try out all our potential CDROM drives, so we need a table. */
static struct {
	char *name;
	int major;
} try_cdrom[] = {
	{ "cd", 6 },
	{ "mcd", 7 },
	{ "scd", 16 },
	{ "matcd", 17 },
	{ 0, 0}
};

static int	find_cdrom_root __P((void *));

static int
find_cdrom_root(dummy)
	void *dummy;
{
	int i,j,k;

	for (j = 0 ; j < 2; j++)
		for (k = 0 ; try_cdrom[k].name ; k++) {
			rootdev = makedev(try_cdrom[k].major,j*8);
			printf("trying rootdev=0x%lx (%s%d)\n",
				rootdev, try_cdrom[k].name,j);
			i = (*cd9660_mountroot)();
			if (!i) return i;
		}
	return EINVAL;
}
#endif /* CD9660 */

static void
configure_start()
{
#if NSCBUS > 0
	scsi_configure_start();
#endif
}

static void
configure_finish()
{
#if NSCBUS > 0
	scsi_configure_finish();
#endif
}

/*
 * Determine i/o configuration for a machine.
 */
static void
configure(dummy)
	void *dummy;
{
	int i;

	configure_start();

	/* Allow all routines to decide for themselves if they want intrs */
        enable_intr();
        INTREN(IRQ_SLAVE);

#if NEISA > 0
	eisa_configure();
#endif

#if NPCI > 0
	pci_configure();
#endif

#if NISA > 0
	isa_configure();
#endif

#if NCRD > 0
	/* After everyone else has a chance at grabbing resources */
	pccard_configure();
#endif

	if (setdumpdev(dumpdev) != 0)
		dumpdev = NODEV;

	configure_finish();

	cninit_finish();

	if (bootverbose) {
		/*
		 * Print out the BIOS's idea of the disk geometries.
		 */
		printf("BIOS Geometries:\n");
		for (i = 0; i < N_BIOS_GEOM; i++) {
			unsigned long bios_geom;
			int max_cylinder, max_head, max_sector;

			bios_geom = bootinfo.bi_bios_geom[i];

			/*
			 * XXX the bootstrap punts a 1200K floppy geometry
			 * when the get-disk-geometry interrupt fails.  Skip
			 * drives that have this geometry.
			 */
			if (bios_geom == 0x4f010f)
				continue;

			printf(" %x:%08lx ", i, bios_geom);
			max_cylinder = bios_geom >> 16;
			max_head = (bios_geom >> 8) & 0xff;
			max_sector = bios_geom & 0xff;
			printf(
		"0..%d=%d cylinders, 0..%d=%d heads, 1..%d=%d sectors\n",
			       max_cylinder, max_cylinder + 1,
			       max_head, max_head + 1,
			       max_sector, max_sector);
		}
		printf(" %d accounted for\n", bootinfo.bi_n_bios_used);

		printf("Device configuration finished.\n");
	}

#ifdef CD9660
	if ((boothowto & RB_CDROM)) {
		if (bootverbose)
			printf("Considering CD-ROM root f/s.\n");
		mountrootfsname = "cd9660";
	}
#endif

#ifdef MFS_ROOT
	if (!mountrootfsname) {
		if (bootverbose)
			printf("Considering MFS root f/s.\n");
		mountrootfsname = "mfs";
		/*
		 * Ignore the -a flag if this kernel isn't compiled
		 * with a generic root/swap configuration: if we skip
		 * setroot() and we aren't a generic kernel, chaos
		 * will ensue because setconf() will be a no-op.
		 * (rootdev is always initialized to NODEV in a
		 * generic configuration, so we test for that.)
		 */
		if ((boothowto & RB_ASKNAME) == 0 || rootdev != NODEV)
			setroot();
	}
#endif

#ifdef NFS
	if (!mountrootfsname && nfs_diskless_valid) {
		if (bootverbose)
			printf("Considering NFS root f/s.\n");
		mountrootfsname = "nfs";
	}
#endif /* NFS */

#ifdef FFS
	if (!mountrootfsname) {
		mountrootfsname = "ufs";
		if (bootverbose)
			printf("Considering FFS root f/s.\n");
		/*
		 * Ignore the -a flag if this kernel isn't compiled
		 * with a generic root/swap configuration: if we skip
		 * setroot() and we aren't a generic kernel, chaos
		 * will ensue because setconf() will be a no-op.
		 * (rootdev is always initialized to NODEV in a
		 * generic configuration, so we test for that.)
		 */
		if ((boothowto & RB_ASKNAME) == 0 || rootdev != NODEV)
			setroot();
	}
#endif

#ifdef LFS
	if (!mountrootfsname) {
		if (bootverbose)
			printf("Considering LFS root f/s.\n");
		mountrootfsname = "lfs";
		/*
		 * Ignore the -a flag if this kernel isn't compiled
		 * with a generic root/swap configuration: if we skip
		 * setroot() and we aren't a generic kernel, chaos
		 * will ensue because setconf() will be a no-op.
		 * (rootdev is always initialized to NODEV in a
		 * generic configuration, so we test for that.)
		 */
		if ((boothowto & RB_ASKNAME) == 0 || rootdev != NODEV)
			setroot();
	}
#endif

	if (!mountrootfsname) {
		panic("Nobody wants to mount my root for me");
	}

	setconf();
	cold = 0;
	if (bootverbose)
		printf("configure() finished.\n");
}

static int
setdumpdev(dev)
	dev_t dev;
{
	int maj, psize;
	long newdumplo;

	if (dev == NODEV) {
		dumpdev = dev;
		return (0);
	}
	maj = major(dev);
	if (maj >= nblkdev)
		return (ENXIO);
	if (bdevsw[maj] == NULL)
		return (ENXIO);		/* XXX is this right? */
	if (bdevsw[maj]->d_psize == NULL)
		return (ENXIO);		/* XXX should be ENODEV ? */
	psize = bdevsw[maj]->d_psize(dev);
	if (psize == -1)
		return (ENXIO);		/* XXX should be ENODEV ? */
	newdumplo = psize - Maxmem * PAGE_SIZE / DEV_BSIZE;
	if (newdumplo < 0)
		return (ENOSPC);
	dumpdev = dev;
	dumplo = newdumplo;
	return (0);
}

u_long	bootdev = 0;		/* not a dev_t - encoding is different */

static	char devname[][2] = {
      {'w','d'},      /* 0 = wd */
      {'s','w'},      /* 1 = sw */
#define FDMAJOR 2
      {'f','d'},      /* 2 = fd */
      {'w','t'},      /* 3 = wt */
      {'s','d'},      /* 4 = sd -- new SCSI system */
};

#define	PARTITIONMASK	0x7
#define	PARTITIONSHIFT	3
#define FDUNITSHIFT     6
#define RAW_PART        2

/*
 * Attempt to find the device from which we were booted.
 * If we can do so, and not instructed not to do so,
 * change rootdev to correspond to the load device.
 */
static void
setroot()
{
	int  majdev, mindev, unit, part, adaptor;
	dev_t orootdev;

/*printf("howto %x bootdev %x ", boothowto, bootdev);*/
	if (boothowto & RB_DFLTROOT ||
	    (bootdev & B_MAGICMASK) != (u_long)B_DEVMAGIC)
		return;
	majdev = (bootdev >> B_TYPESHIFT) & B_TYPEMASK;
	if (majdev > sizeof(devname) / sizeof(devname[0]))
		return;
	adaptor = (bootdev >> B_ADAPTORSHIFT) & B_ADAPTORMASK;
	unit = (bootdev >> B_UNITSHIFT) & B_UNITMASK;
	if (majdev == FDMAJOR) {
		part = RAW_PART;
		mindev = unit << FDUNITSHIFT;
	}
	else {
		part = (bootdev >> B_PARTITIONSHIFT) & B_PARTITIONMASK;
		mindev = (unit << PARTITIONSHIFT) + part;
	}
	orootdev = rootdev;
	rootdev = makedev(majdev, mindev);
	/*
	 * If the original rootdev is the same as the one
	 * just calculated, don't need to adjust the swap configuration.
	 */
	if (rootdev == orootdev)
		return;
	printf("changing root device to %c%c%d%c\n",
		devname[majdev][0], devname[majdev][1],
		mindev >> (majdev == FDMAJOR ? FDUNITSHIFT : PARTITIONSHIFT),
		part + 'a');
}

static int
sysctl_kern_dumpdev SYSCTL_HANDLER_ARGS
{
	int error;
	dev_t ndumpdev;

	ndumpdev = dumpdev;
	error = sysctl_handle_opaque(oidp, &ndumpdev, sizeof ndumpdev, req);
	if (error == 0 && req->newptr != NULL)
		error = setdumpdev(ndumpdev);
	return (error);
}

SYSCTL_PROC(_kern, KERN_DUMPDEV, dumpdev, CTLTYPE_OPAQUE|CTLFLAG_RW,
	0, sizeof dumpdev, sysctl_kern_dumpdev, "T,dev_t", "");
