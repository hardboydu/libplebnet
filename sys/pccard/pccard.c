/*
 *	pccard.c - Interface code for PC-CARD controllers.
 *
 *	June 1995, Andrew McRae (andrew@mega.com.au)
 *-------------------------------------------------------------------------
 *
 * Copyright (c) 1995 Andrew McRae.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include "opt_pcic.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/select.h>
#include <sys/sysctl.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/interrupt.h>
#include <sys/bus.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <machine/resource.h>

#include <i386/isa/isa_device.h>
#include <i386/isa/icu.h>
#include <i386/isa/intr_machdep.h>

#include "apm.h"
#if	NAPM > 0
#include <machine/apm_bios.h>
#endif	/* NAPM > 0 */

#include <pccard/cardinfo.h>
#include <pccard/driver.h>
#include <pccard/pcic.h>
#include <pccard/slot.h>
#include <pccard/pccard_nbk.h>

#include <machine/md_var.h>

/*
 * XXX We shouldn't be using processor-specific/bus-specific code in
 * here, but we need the start of the ISA hole (IOM_BEGIN).
 */
#ifdef PC98
#include <pc98/pc98/pc98.h>
#else
#include <i386/isa/isa.h>
#endif

SYSCTL_NODE(_machdep, OID_AUTO, pccard, CTLFLAG_RW, 0, "pccard");

static int pcic_resume_reset =
#ifdef PCIC_RESUME_RESET	/* opt_pcic.h */
	1;
#else
	0;
#endif

SYSCTL_INT(_machdep_pccard, OID_AUTO, pcic_resume_reset, CTLFLAG_RW, 
	&pcic_resume_reset, 0, "");

#define	PCCARD_MEMSIZE	(4*1024)

#define MIN(a,b)	((a)<(b)?(a):(b))

static int		allocate_driver(struct slot *, struct dev_desc *);
static void		inserted(void *);
static void		disable_slot(struct slot *);
static int		invalid_io_memory(unsigned long, int);
static void		power_off_slot(void *);

#if	NAPM > 0
/*
 *    For the APM stuff, the apmhook structure is kept
 *    separate from the slot structure so that the slot
 *    drivers do not need to know about the hooks (or the
 *    data structures).
 */
static int	slot_suspend(void *arg);
static int	slot_resume(void *arg);
static struct	apmhook s_hook[MAXSLOT];	/* APM suspend */
static struct	apmhook r_hook[MAXSLOT];	/* APM resume */
#endif	/* NAPM > 0 */

static struct slot	*pccard_slots[MAXSLOT];	/* slot entries */
static struct slot	*slot_list;
static struct slot_ctrl *cont_list;

/*
 *	The driver interface for read/write uses a block
 *	of memory in the ISA I/O memory space allocated via
 *	an ioctl setting.
 */
static unsigned long pccard_mem;	/* Physical memory */
static unsigned char *pccard_kmem;	/* Kernel virtual address */

static	d_open_t	crdopen;
static	d_close_t	crdclose;
static	d_read_t	crdread;
static	d_write_t	crdwrite;
static	d_ioctl_t	crdioctl;
static	d_poll_t	crdpoll;

#define CDEV_MAJOR 50
static struct cdevsw crd_cdevsw = {
	/* open */	crdopen,
	/* close */	crdclose,
	/* read */	crdread,
	/* write */	crdwrite,
	/* ioctl */	crdioctl,
	/* poll */	crdpoll,
	/* mmap */	nommap,
	/* strategy */	nostrategy,
	/* name */	"crd",
	/* maj */	CDEV_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	0,
	/* bmaj */	-1
};

/*
 *	Power off the slot.
 *	(doing it immediately makes the removal of some cards unstable)
 */
static void
power_off_slot(void *arg)
{
	struct slot *slt = (struct slot *)arg;
	int s;

	/* 
	 * The following will generate an interrupt.  So, to hold off
	 * the interrupt unitl after disable runs so that we can get rid
	 * rid of the interrupt before it becomes unsafe to touch the 
	 * device.
	 */
	s = splhigh();
	/* Power off the slot. */
	slt->pwr_off_pending = 0;
	slt->ctrl->disable(slt);
	splx(s);
}

/*
 *	disable_slot - Disables the slot by removing
 *	the power and unmapping the I/O
 */
static void
disable_slot(struct slot *slt)
{
	device_t pccarddev;
	struct pccard_devinfo *devi;
	int i;

	/*
	 * Unload all the drivers on this slot. Note we can't
	 * remove the device structures themselves, because this
	 * may be called from the event routine, which is called
	 * from the slot controller's ISR, and removing the structures
	 * shouldn't happen during the middle of some driver activity.
	 *
	 * Note that a race condition is possible here; if a
	 * driver is accessing the device and it is removed, then
	 * all bets are off...
	 */
	pccarddev = devclass_get_device(pccard_devclass, 0);
	for (devi = slt->devices; devi; devi = devi->next) {
		if (devi->isahd.id_device != 0) {
			device_delete_child(pccarddev, devi->isahd.id_device);
			devi->isahd.id_device = 0;
		}
	}

	/* Power off the slot 1/2 second after removal of the card */
	slt->poff_ch = timeout(power_off_slot, (caddr_t)slt, hz / 2);
	slt->pwr_off_pending = 1;
}

/*
 *	APM hooks for suspending and resuming.
 */
#if   NAPM > 0
static int
slot_suspend(void *arg)
{
	struct slot *slt = arg;

	/* This code stolen from pccard_event:card_removed */
	if (slt->state == filled) {
		int s = splhigh();
		disable_slot(slt);
		slt->laststate = filled;
		slt->state = suspend;
		splx(s);
		printf("pccard: card disabled, slot %d\n", slt->slotnum);
	}
	/*
	 * Disable any pending timeouts for this slot since we're
	 * powering it down/disabling now.
	 */
	untimeout(power_off_slot, (caddr_t)slt, slt->poff_ch);
	slt->ctrl->disable(slt);
	return (0);
}

static int
slot_resume(void *arg)
{
	struct slot *slt = arg;

	if (pcic_resume_reset)
		slt->ctrl->resume(slt);
	/* This code stolen from pccard_event:card_inserted */
	if (slt->state == suspend) {
		slt->laststate = suspend;
		slt->state = empty;
		slt->insert_seq = 1;
		untimeout(inserted, (void *)slt, slt->insert_ch);
		slt->insert_ch = timeout(inserted, (void *)slt, hz/4);
		selwakeup(&slt->selp);
	}
	return (0);
}
#endif	/* NAPM > 0 */

/*
 *	pccard_alloc_slot - Called from controller probe
 *	routine, this function allocates a new PC-CARD slot
 *	and initialises the data structures using the data provided.
 *	It returns the allocated structure to the probe routine
 *	to allow the controller specific data to be initialised.
 */
struct slot *
pccard_alloc_slot(struct slot_ctrl *ctrl)
{
	struct slot *slt;
	int slotno;

	for (slotno = 0; slotno < MAXSLOT; slotno++)
		if (pccard_slots[slotno] == 0)
			break;
	if (slotno == MAXSLOT)
		return(0);

	MALLOC(slt, struct slot *, sizeof(*slt), M_DEVBUF, M_WAITOK);
	bzero(slt, sizeof(*slt));
	make_dev(&crd_cdevsw, slotno, 0, 0, 0600, "card%d", slotno);
	if (ctrl->extra) {
		MALLOC(slt->cdata, void *, ctrl->extra, M_DEVBUF, M_WAITOK);
		bzero(slt->cdata, ctrl->extra);
	}
	slt->ctrl = ctrl;
	slt->slotnum = slotno;
	pccard_slots[slotno] = slt;
	slt->next = slot_list;
	slot_list = slt;
	/*
	 *	If this controller hasn't been seen before, then
	 *	link it into the list of controllers.
	 */
	if (ctrl->slots++ == 0) {
		ctrl->next = cont_list;
		cont_list = ctrl;
		if (ctrl->maxmem > NUM_MEM_WINDOWS)
			ctrl->maxmem = NUM_MEM_WINDOWS;
		if (ctrl->maxio > NUM_IO_WINDOWS)
			ctrl->maxio = NUM_IO_WINDOWS;
	}
	callout_handle_init(&slt->insert_ch);
	callout_handle_init(&slt->poff_ch);
#if NAPM > 0
	{
		struct apmhook *ap;

		ap = &s_hook[slt->slotnum];
		ap->ah_fun = slot_suspend;
		ap->ah_arg = (void *)slt;
		ap->ah_name = "pcccard";
		ap->ah_order = APM_MID_ORDER;
		apm_hook_establish(APM_HOOK_SUSPEND, ap);
		ap = &r_hook[slt->slotnum];
		ap->ah_fun = slot_resume;
		ap->ah_arg = (void *)slt;
		ap->ah_name = "pccard";
		ap->ah_order = APM_MID_ORDER;
		apm_hook_establish(APM_HOOK_RESUME, ap);
	}
#endif /* NAPM > 0 */
	return(slt);
}

/*
 *	allocate_driver - Create a new device entry for this
 *	slot, and attach a driver to it.
 */
static int
allocate_driver(struct slot *slt, struct dev_desc *desc)
{
	struct pccard_devinfo *devi;
	device_t pccarddev;
	int err, irq = 0;
	device_t child;

	pccarddev = devclass_get_device(pccard_devclass, 0);
	irq = ffs(desc->irqmask) - 1;
	MALLOC(devi, struct pccard_devinfo *, sizeof(*devi), M_DEVBUF, M_WAITOK);
	bzero(devi, sizeof(*devi));
	strcpy(devi->name, desc->name);
	/*
	 *	Create an entry for the device under this slot.
	 */
	devi->running = 1;
	devi->slt = slt;
	bcopy(desc->misc, devi->misc, sizeof(desc->misc));
	resource_list_init(&devi->resources);
	child = devi->isahd.id_device = device_add_child(pccarddev, devi->name,
	    desc->unit, devi);
	device_set_flags(child, desc->flags);
	err = bus_set_resource(child, SYS_RES_IOPORT, 0, desc->iobase,
	    desc->iosize);
	if (err)
		goto err;
	if (irq)
		err = bus_set_resource(child, SYS_RES_IRQ, 0, irq, 1);
	if (err) 
		goto err;
	if (desc->memsize) {
		err = bus_set_resource(child, SYS_RES_MEMORY, 0, desc->mem, 
		    desc->memsize);
		if (err) 
			goto err;
	}
	err = device_probe_and_attach(child);
err:
	if (err)
		device_delete_child(pccarddev, child);
	return (err);
}

/*
 *	card insert routine - Called from a timeout to debounce
 *	insertion events.
 */
static void
inserted(void *arg)
{
	struct slot *slt = arg;

	slt->state = filled;
	/*
	 *	Enable 5V to the card so that the CIS can be read.
	 */
	slt->pwr.vcc = 50;
	slt->pwr.vpp = 0;
	/*
	 * Disable any pending timeouts for this slot, and explicitly
	 * power it off right now.  Then, re-enable the power using
	 * the (possibly new) power settings.
	 */
	untimeout(power_off_slot, (caddr_t)slt, slt->poff_ch);
	power_off_slot(slt);
	slt->ctrl->power(slt);

	printf("pccard: card inserted, slot %d\n", slt->slotnum);
	/*
	 *	Now start resetting the card.
	 */
	slt->ctrl->reset(slt);
}

/*
 *	Card event callback. Called at splhigh to prevent
 *	device interrupts from interceding.
 */
void
pccard_event(struct slot *slt, enum card_event event)
{
	if (slt->insert_seq) {
		slt->insert_seq = 0;
		untimeout(inserted, (void *)slt, slt->insert_ch);
	}

	switch(event) {
	case card_removed:
		/*
		 *	The slot and devices are disabled, but the
		 *	data structures are not unlinked.
		 */
		if (slt->state == filled) {
			int s = splhigh();
			disable_slot(slt);
			slt->state = empty;
			splx(s);
			printf("pccard: card removed, slot %d\n", slt->slotnum);
			pccard_remove_beep();
			selwakeup(&slt->selp);
		}
		break;
	case card_inserted:
		slt->insert_seq = 1;
		slt->insert_ch = timeout(inserted, (void *)slt, hz/4);
		pccard_insert_beep();
		break;
	}
}

/*
 *	Device driver interface.
 */
static	int
crdopen(dev_t dev, int oflags, int devtype, struct proc *p)
{
	struct slot *slt;

	if (minor(dev) >= MAXSLOT)
		return(ENXIO);
	slt = pccard_slots[minor(dev)];
	if (slt == 0)
		return(ENXIO);
	if (slt->rwmem == 0)
		slt->rwmem = MDF_ATTR;
	return(0);
}

/*
 *	Close doesn't de-allocate any resources, since
 *	slots may be assigned to drivers already.
 */
static	int
crdclose(dev_t dev, int fflag, int devtype, struct proc *p)
{
	return(0);
}

/*
 *	read interface. Map memory at lseek offset,
 *	then transfer to user space.
 */
static	int
crdread(dev_t dev, struct uio *uio, int ioflag)
{
	struct slot *slt = pccard_slots[minor(dev)];
	struct mem_desc *mp, oldmap;
	unsigned char *p;
	unsigned int offs;
	int error = 0, win, count;

	if (slt == 0 || slt->state != filled)
		return(ENXIO);
	if (pccard_mem == 0)
		return(ENOMEM);
	for (win = 0; win < slt->ctrl->maxmem; win++)
		if ((slt->mem[win].flags & MDF_ACTIVE) == 0)
			break;
	if (win >= slt->ctrl->maxmem)
		return(EBUSY);
	mp = &slt->mem[win];
	oldmap = *mp;
	mp->flags = slt->rwmem|MDF_ACTIVE;
	while (uio->uio_resid && error == 0) {
		mp->card = uio->uio_offset;
		mp->size = PCCARD_MEMSIZE;
		mp->start = (caddr_t)(void *)(uintptr_t)pccard_mem;
		if ((error = slt->ctrl->mapmem(slt, win)) != 0)
			break;
		offs = (unsigned int)uio->uio_offset & (PCCARD_MEMSIZE - 1);
		p = pccard_kmem + offs;
		count = MIN(PCCARD_MEMSIZE - offs, uio->uio_resid);
		error = uiomove(p, count, uio);
	}
	/*
	 *	Restore original map.
	 */
	*mp = oldmap;
	slt->ctrl->mapmem(slt, win);

	return(error);
}

/*
 *	crdwrite - Write data to card memory.
 *	Handles wrap around so that only one memory
 *	window is used.
 */
static	int
crdwrite(dev_t dev, struct uio *uio, int ioflag)
{
	struct slot *slt = pccard_slots[minor(dev)];
	struct mem_desc *mp, oldmap;
	unsigned char *p;
	unsigned int offs;
	int error = 0, win, count;

	if (slt == 0 || slt->state != filled)
		return(ENXIO);
	if (pccard_mem == 0)
		return(ENOMEM);
	for (win = 0; win < slt->ctrl->maxmem; win++)
		if ((slt->mem[win].flags & MDF_ACTIVE) == 0)
			break;
	if (win >= slt->ctrl->maxmem)
		return(EBUSY);
	mp = &slt->mem[win];
	oldmap = *mp;
	mp->flags = slt->rwmem|MDF_ACTIVE;
	while (uio->uio_resid && error == 0) {
		mp->card = uio->uio_offset;
		mp->size = PCCARD_MEMSIZE;
		mp->start = (caddr_t)(void *)(uintptr_t)pccard_mem;
		if ((error = slt->ctrl->mapmem(slt, win)) != 0)
			break;
		offs = (unsigned int)uio->uio_offset & (PCCARD_MEMSIZE - 1);
		p = pccard_kmem + offs;
		count = MIN(PCCARD_MEMSIZE - offs, uio->uio_resid);
		error = uiomove(p, count, uio);
	}
	/*
	 *	Restore original map.
	 */
	*mp = oldmap;
	slt->ctrl->mapmem(slt, win);

	return(error);
}

/*
 *	ioctl calls - allows setting/getting of memory and I/O
 *	descriptors, and assignment of drivers.
 */
static	int
crdioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
	struct slot *slt = pccard_slots[minor(dev)];
	struct mem_desc *mp;
	struct io_desc *ip;
	int s, err;

	/* beep is disabled until the 1st call of crdioctl() */
	pccard_beep_select(BEEP_ON);

	if (slt == 0 && cmd != PIOCRWMEM)
		return(ENXIO);
	switch(cmd) {
	default:
		if (slt->ctrl->ioctl)
			return(slt->ctrl->ioctl(slt, cmd, data));
		return(ENOTTY);
	/*
	 * Get slot state.
	 */
	case PIOCGSTATE:
		s = splhigh();
		((struct slotstate *)data)->state = slt->state;
		((struct slotstate *)data)->laststate = slt->laststate;
		slt->laststate = slt->state;
		splx(s);
		((struct slotstate *)data)->maxmem = slt->ctrl->maxmem;
		((struct slotstate *)data)->maxio = slt->ctrl->maxio;
		((struct slotstate *)data)->irqs = 0;
		break;
	/*
	 * Get memory context.
	 */
	case PIOCGMEM:
		s = ((struct mem_desc *)data)->window;
		if (s < 0 || s >= slt->ctrl->maxmem)
			return(EINVAL);
		mp = &slt->mem[s];
		((struct mem_desc *)data)->flags = mp->flags;
		((struct mem_desc *)data)->start = mp->start;
		((struct mem_desc *)data)->size = mp->size;
		((struct mem_desc *)data)->card = mp->card;
		break;
	/*
	 * Set memory context. If context already active, then unmap it.
	 * It is hard to see how the parameters can be checked.
	 * At the very least, we only allow root to set the context.
	 */
	case PIOCSMEM:
		if (suser(p))
			return(EPERM);
		if (slt->state != filled)
			return(ENXIO);
		s = ((struct mem_desc *)data)->window;
		if (s < 0 || s >= slt->ctrl->maxmem)
			return(EINVAL);
		slt->mem[s] = *((struct mem_desc *)data);
		return(slt->ctrl->mapmem(slt, s));
	/*
	 * Get I/O port context.
	 */
	case PIOCGIO:
		s = ((struct io_desc *)data)->window;
		if (s < 0 || s >= slt->ctrl->maxio)
			return(EINVAL);
		ip = &slt->io[s];
		((struct io_desc *)data)->flags = ip->flags;
		((struct io_desc *)data)->start = ip->start;
		((struct io_desc *)data)->size = ip->size;
		break;
	/*
	 * Set I/O port context.
	 */
	case PIOCSIO:
		if (suser(p))
			return(EPERM);
		if (slt->state != filled)
			return(ENXIO);
		s = ((struct io_desc *)data)->window;
		if (s < 0 || s >= slt->ctrl->maxio)
			return(EINVAL);
		slt->io[s] = *((struct io_desc *)data);
		/* XXX Don't actually map */
		return 0;
		break;
	/*
	 * Set memory window flags for read/write interface.
	 */
	case PIOCRWFLAG:
		slt->rwmem = *(int *)data;
		break;
	/*
	 * Set the memory window to be used for the read/write interface.
	 */
	case PIOCRWMEM:
		if (*(unsigned long *)data == 0) {
			if (pccard_mem)
				*(unsigned long *)data = pccard_mem;
			break;
		}
		if (suser(p))
			return(EPERM);
		/*
		 * Validate the memory by checking it against the I/O
		 * memory range. It must also start on an aligned block size.
		 */
		if (invalid_io_memory(*(unsigned long *)data, PCCARD_MEMSIZE))
			return(EINVAL);
		if (*(unsigned long *)data & (PCCARD_MEMSIZE-1))
			return(EINVAL);
		/*
		 *	Map it to kernel VM.
		 */
		pccard_mem = *(unsigned long *)data;
		pccard_kmem =
		    (unsigned char *)(void *)(uintptr_t)
		    (pccard_mem + atdevbase - IOM_BEGIN);
		break;
	/*
	 * Set power values.
	 */
	case PIOCSPOW:
		slt->pwr = *(struct power *)data;
		return(slt->ctrl->power(slt));
	/*
	 * Allocate a driver to this slot.
	 */
	case PIOCSDRV:
		if (suser(p))
			return(EPERM);
		err = allocate_driver(slt, (struct dev_desc *)data);
		if (!err)
			pccard_success_beep();
		else
			pccard_failure_beep();
		return err;
	case PIOCSBEEP:
		if (pccard_beep_select(*(int *)data)) {
			return EINVAL;
		}
		break;
	}
	return(0);
}

/*
 *	poll - Poll on exceptions will return true
 *	when a change in card status occurs.
 */
static	int
crdpoll(dev_t dev, int events, struct proc *p)
{
	int s;
	struct slot *slt = pccard_slots[minor(dev)];
	int revents = 0;

	if (events & (POLLIN | POLLRDNORM))
		revents |= events & (POLLIN | POLLRDNORM);

	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLIN | POLLRDNORM);

	s = splhigh();
	/*
	 *	select for exception - card event.
	 */
	if (events & POLLRDBAND)
		if (slt == 0 || slt->laststate != slt->state)
			revents |= POLLRDBAND;

	if (revents == 0)
		selrecord(p, &slt->selp);

	splx(s);
	return (revents);
}

/*
 *	invalid_io_memory - verify that the ISA I/O memory block
 *	is a valid and unallocated address.
 *	A simple check of the range is done, and then a
 *	search of the current devices is done to check for
 *	overlapping regions.
 */
static int
invalid_io_memory(unsigned long adr, int size)
{
	/* XXX - What's magic about 0xC0000?? */
	if (adr < 0xC0000 || (adr+size) > IOM_END)
		return(1);
	return(0);
}
