/*
 * Copyright (c) HONDA Naofumi, KATO Takenori, 1996.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
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
 */

/***************************************************
 * misc device header in bs_softc
 ***************************************************/
#ifdef __NetBSD__
#define	OS_DEPEND_DEVICE_HEADER			\
	struct device sc_dev;			\
	void *sc_ih;

#define OS_DEPEND_SCSI_HEADER			\
	struct scsi_link sc_link;

#define	OS_DEPEND_MISC_HEADER			\
	pisa_device_handle_t sc_pdv;		\
	bus_chipset_tag_t sc_bc;		\
	bus_io_handle_t sc_ioh;			\
	bus_io_handle_t sc_delayioh;		\
	bus_mem_handle_t sc_memh;

#endif	/* __NetBSD__ */
#ifdef __FreeBSD__
#define OS_DEPEND_DEVICE_HEADER			\
	int unit;

#define OS_DEPEND_SCSI_HEADER			\
	struct scsi_link sc_link;

#define	OS_DEPEND_MISC_HEADER
#endif	/* __FreeBSD__ */

#if	defined(__NetBSD__)
#define BSHW_NBPG	NBPG
#endif
#if	defined(__FreeBSD__)
#define BSHW_NBPG	PAGE_SIZE
#endif

/***************************************************
 * include
 ***************************************************/
/* (I) common include */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/disklabel.h>
#include <sys/buf.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/errno.h>

#include <vm/vm.h>

/* (II) os depend include */
#ifdef	__NetBSD__
#include <sys/device.h>

#include <dev/isa/isareg.h>
#include <dev/isa/isavar.h>
#include <dev/isa/pisaif.h>

#include <machine/cpufunc.h>
#include <machine/bus.h>
#include <machine/intr.h>
#include <machine/dvcfg.h>

#include <scsi/scsi_all.h>
#include <scsi/scsiconf.h>
#include <scsi/scsi_disk.h>
#endif	/* __NetBSD__ */

#ifdef __FreeBSD__
#include <sys/device.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <machine/clock.h>
#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/vmparam.h>
#include <vm/pmap.h>
#include <sys/proc.h>

#include <scsi/scsi_all.h>
#include <scsi/scsiconf.h>
#include <scsi/scsi_disk.h>

#include <pc98/pc98/pc98.h>
#include <i386/isa/isa_device.h>
#include <i386/isa/icu.h>
#endif	/* __FreeBSD__ */

/***************************************************
 * BUS IO MAPPINGS & BS specific inclusion
 ***************************************************/
#ifdef	__NetBSD__
#define	BUS_IO_DELAY ((void) bus_io_read_1(bsc->sc_bc, bsc->sc_delayioh, 0))
#define	BUS_IO_WEIGHT (bus_io_write_1(bsc->sc_bc, bsc->sc_delayioh, 0, 0))
#define	BUS_IOR(offs) (BUS_IO_DELAY, bus_io_read_1(bsc->sc_bc, bsc->sc_ioh, (offs)))
#define	BUS_IOW(offs, val) (BUS_IO_DELAY, bus_io_write_1(bsc->sc_bc, bsc->sc_ioh, (offs), (val)))

#include <dev/ic/wd33c93reg.h>
#include <dev/isa/ccbque.h>

#include <dev/isa/scsi_dvcfg.h>
#include <dev/isa/bs/bsvar.h>
#include <dev/isa/bs/bshw.h>
#include <dev/isa/bs/bsfunc.h>
#endif	/* __NetBSD__ */

#ifdef	__FreeBSD__
#define	BUS_IO_DELAY ((void) inb(0x5f))
#define	BUS_IO_WEIGHT (outb(0x5f, 0))
#define	BUS_IOR(offs) (BUS_IO_DELAY, inb(bsc->sc_iobase + (offs)))
#define	BUS_IOW(offs, val) (BUS_IO_DELAY, outb(bsc->sc_iobase + (offs), (val)))

#include <i386/isa/ic/wd33c93.h>
#include <i386/isa/bs/ccbque.h>
#include <i386/isa/bs/dvcfg.h>

#include <i386/isa/bs/scsi_dvcfg.h>
#include <i386/isa/bs/bsvar.h>
#include <i386/isa/bs/bshw.h>
#include <i386/isa/bs/bsfunc.h>
#endif	/* __FreeBSD__ */

/***************************************************
 * XS return type
 ***************************************************/
#ifdef	__NetBSD__
#define	XSBS_INT32T	int
#endif	/* __NetBSD__ */
#ifdef	__FreeBSD__
#define	XSBS_INT32T	int32_t
#endif	/* __FreeBSD__ */

/***************************************************
 * xs flags's abstraction (all currently used)
 ***************************************************/
#define	XSBS_ITSDONE	ITSDONE
#define	XSBS_SCSI_NOSLEEP	SCSI_NOSLEEP
#ifdef __NetBSD__
#define XSBS_SCSI_POLL	SCSI_POLL
#endif	/* __NetBSD__ */
#ifdef __FreeBSD__
#define XSBS_SCSI_POLL	SCSI_NOMASK
#endif	/* __FreeBSD__ */

/***************************************************
 * Special operations
 ***************************************************/
#ifdef __FreeBSD__
#define	BS_ADDRESS_CHECK
#endif	/* __FreeBSD__ */

/***************************************************
 * declare
 ***************************************************/
/* (I) common declare */
void bs_alloc_buf __P((struct targ_info *));
XSBS_INT32T bs_target_open __P((struct scsi_link *, struct cfdata *));
XSBS_INT32T bs_scsi_cmd __P((struct scsi_xfer *));

extern int delaycount;

/* (II) os depend declare */
#ifdef __NetBSD__
int bsprobe __P((struct device *, struct device *, void *));
void bsattach __P((struct device *, struct device *, void *));
#endif	/* __NetBSD__ */

#ifdef __FreeBSD__
static BS_INLINE void memcopy __P((void *from, void *to, register size_t len));
u_int32_t bs_adapter_info __P((int));
#define delay(y) DELAY(y)
extern int dma_init_flag;
#define softintr(y) ipending |= (y)

static BS_INLINE void
memcopy(from, to, len)
	void *from, *to;
	register size_t len;
{

	len >>= 2;
	__asm __volatile("cld\n\trep\n\tmovsl" : :
			 "S" (from), "D" (to), "c" (len) :
			 "%esi", "%edi", "%ecx");
}
#endif	/* __FreeBSD__ */
