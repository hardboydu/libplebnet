/*-
 * Copyright (c) 2003 John Baldwin <jhb@FreeBSD.org>
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
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 */

/*
 * PIC driver for the 8259A Master and Slave PICs in PC/AT machines.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_auto_eoi.h"
#include "opt_isa.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>

#include <machine/cpufunc.h>
#include <machine/frame.h>
#include <machine/intr_machdep.h>
#include <machine/md_var.h>
#include <machine/resource.h>
#include <machine/segments.h>

#include <dev/ic/i8259.h>
#include <amd64/isa/icu.h>
#include <amd64/isa/isa.h>

#include <isa/isavar.h>

#define	MASTER	0
#define	SLAVE	1

#ifdef AUTO_EOI_1
#define	MASTER_MODE	(ICW4_8086 | ICW4_AEOI)
#else
#define	MASTER_MODE	ICW4_8086
#endif
#ifdef AUTO_EOI_2
#define	SLAVE_MODE	(ICW4_8086 | ICW4_AEOI)
#else
#define	SLAVE_MODE	ICW4_8086
#endif

static void	atpic_init(void *dummy);

unsigned int imen;	/* XXX */

inthand_t
	IDTVEC(atpic_intr0), IDTVEC(atpic_intr1), IDTVEC(atpic_intr2),
	IDTVEC(atpic_intr3), IDTVEC(atpic_intr4), IDTVEC(atpic_intr5),
	IDTVEC(atpic_intr6), IDTVEC(atpic_intr7), IDTVEC(atpic_intr8),
	IDTVEC(atpic_intr9), IDTVEC(atpic_intr10), IDTVEC(atpic_intr11),
	IDTVEC(atpic_intr12), IDTVEC(atpic_intr13), IDTVEC(atpic_intr14),
	IDTVEC(atpic_intr15);

#define	IRQ(ap, ai)	((ap)->at_irqbase + (ai)->at_irq)

#define	ATPIC(io, base, eoi, imenptr)				\
     	{ { atpic_enable_source, atpic_disable_source, (eoi),		\
	    atpic_enable_intr, atpic_vector, atpic_source_pending, NULL, \
	    atpic_resume }, (io), (base), IDT_IO_INTS + (base), (imenptr) }

#define	INTSRC(irq)							\
	{ { &atpics[(irq) / 8].at_pic }, (irq) % 8,			\
	    IDTVEC(atpic_intr ## irq ) }

struct atpic {
	struct pic at_pic;
	int	at_ioaddr;
	int	at_irqbase;
	uint8_t	at_intbase;
	uint8_t	*at_imen;
};

struct atpic_intsrc {
	struct intsrc at_intsrc;
	int	at_irq;		/* Relative to PIC base. */
	inthand_t *at_intr;
	u_long	at_count;
	u_long	at_straycount;
};

static void atpic_enable_source(struct intsrc *isrc);
static void atpic_disable_source(struct intsrc *isrc);
static void atpic_eoi_master(struct intsrc *isrc);
static void atpic_eoi_slave(struct intsrc *isrc);
static void atpic_enable_intr(struct intsrc *isrc);
static int atpic_vector(struct intsrc *isrc);
static void atpic_resume(struct intsrc *isrc);
static int atpic_source_pending(struct intsrc *isrc);
static void i8259_init(struct atpic *pic, int slave);

static struct atpic atpics[] = {
	ATPIC(IO_ICU1, 0, atpic_eoi_master, (uint8_t *)&imen),
	ATPIC(IO_ICU2, 8, atpic_eoi_slave, ((uint8_t *)&imen) + 1)
};

static struct atpic_intsrc atintrs[] = {
	INTSRC(0),
	INTSRC(1),
	INTSRC(2),
	INTSRC(3),
	INTSRC(4),
	INTSRC(5),
	INTSRC(6),
	INTSRC(7),
	INTSRC(8),
	INTSRC(9),
	INTSRC(10),
	INTSRC(11),
	INTSRC(12),
	INTSRC(13),
	INTSRC(14),
	INTSRC(15),
};

static void
atpic_enable_source(struct intsrc *isrc)
{
	struct atpic_intsrc *ai = (struct atpic_intsrc *)isrc;
	struct atpic *ap = (struct atpic *)isrc->is_pic;

	mtx_lock_spin(&icu_lock);
	*ap->at_imen &= ~(1 << ai->at_irq);
	outb(ap->at_ioaddr + ICU_IMR_OFFSET, *ap->at_imen);
	mtx_unlock_spin(&icu_lock);
}

static void
atpic_disable_source(struct intsrc *isrc)
{
	struct atpic_intsrc *ai = (struct atpic_intsrc *)isrc;
	struct atpic *ap = (struct atpic *)isrc->is_pic;

	mtx_lock_spin(&icu_lock);
	*ap->at_imen |= (1 << ai->at_irq);
	outb(ap->at_ioaddr + ICU_IMR_OFFSET, *ap->at_imen);
	mtx_unlock_spin(&icu_lock);
}

static void
atpic_eoi_master(struct intsrc *isrc)
{

	KASSERT(isrc->is_pic == &atpics[MASTER].at_pic,
	    ("%s: mismatched pic", __func__));
#ifndef AUTO_EOI_1
	mtx_lock_spin(&icu_lock);
	outb(atpics[MASTER].at_ioaddr, ICU_EOI);
	mtx_unlock_spin(&icu_lock);
#endif
}

/*
 * The data sheet says no auto-EOI on slave, but it sometimes works.
 * So, if AUTO_EOI_2 is enabled, we use it.
 */
static void
atpic_eoi_slave(struct intsrc *isrc)
{

	KASSERT(isrc->is_pic == &atpics[SLAVE].at_pic,
	    ("%s: mismatched pic", __func__));
#ifndef AUTO_EOI_2
	mtx_lock_spin(&icu_lock);
	outb(atpics[SLAVE].at_ioaddr, ICU_EOI);
#ifndef AUTO_EOI_1
	outb(atpics[MASTER].at_ioaddr, ICU_EOI);
#endif
	mtx_unlock_spin(&icu_lock);
#endif
}

static void
atpic_enable_intr(struct intsrc *isrc)
{
}

static int
atpic_vector(struct intsrc *isrc)
{
	struct atpic_intsrc *ai = (struct atpic_intsrc *)isrc;
	struct atpic *ap = (struct atpic *)isrc->is_pic;

	return (IRQ(ap, ai));
}

static int
atpic_source_pending(struct intsrc *isrc)
{
	struct atpic_intsrc *ai = (struct atpic_intsrc *)isrc;
	struct atpic *ap = (struct atpic *)isrc->is_pic;

	return (inb(ap->at_ioaddr) & (1 << ai->at_irq));
}

static void
atpic_resume(struct intsrc *isrc)
{
	struct atpic_intsrc *ai = (struct atpic_intsrc *)isrc;
	struct atpic *ap = (struct atpic *)isrc->is_pic;

	if (ai->at_irq == 0)
		i8259_init(ap, ap == &atpics[SLAVE]);
}

static void
i8259_init(struct atpic *pic, int slave)
{
	int imr_addr;

	/* Reset the PIC and program with next four bytes. */
	mtx_lock_spin(&icu_lock);
	outb(pic->at_ioaddr, ICW1_RESET | ICW1_IC4);
	imr_addr = pic->at_ioaddr + ICU_IMR_OFFSET;

	/* Start vector. */
	outb(imr_addr, pic->at_intbase);

	/*
	 * Setup slave links.  For the master pic, indicate what line
	 * the slave is configured on.  For the slave indicate
	 * which line on the master we are connected to.
	 */
	if (slave)
		outb(imr_addr, ICU_SLAVEID);	/* my slave id is 7 */
	else
		outb(imr_addr, IRQ_SLAVE);	/* slave on line 7 */

	/* Set mode. */
	if (slave)
		outb(imr_addr, SLAVE_MODE);
	else
		outb(imr_addr, MASTER_MODE);

	/* Set interrupt enable mask. */
	outb(imr_addr, *pic->at_imen);

	/* Reset is finished, default to IRR on read. */
	outb(pic->at_ioaddr, OCW3_SEL | OCW3_RR);

	/* OCW2_L1 sets priority order to 3-7, 0-2 (com2 first). */
	if (!slave)
		outb(pic->at_ioaddr, OCW2_R | OCW2_SL | OCW2_L1);
	mtx_unlock_spin(&icu_lock);
}

void
atpic_startup(void)
{
	struct atpic_intsrc *ai;
	int i;

	/* Start off with all interrupts disabled. */
	imen = 0xffff;
	i8259_init(&atpics[MASTER], 0);
	i8259_init(&atpics[SLAVE], 1);
	atpic_enable_source((struct intsrc *)&atintrs[ICU_SLAVEID]);

	/* Install low-level interrupt handlers for all of our IRQs. */
	for (i = 0; i < sizeof(atintrs) / sizeof(struct atpic_intsrc); i++) {
		if (i == ICU_SLAVEID)
			continue;
		ai = &atintrs[i];
		ai->at_intsrc.is_count = &ai->at_count;
		ai->at_intsrc.is_straycount = &ai->at_straycount;
		setidt(((struct atpic *)ai->at_intsrc.is_pic)->at_intbase +
		    ai->at_irq, ai->at_intr, SDT_SYSIGT, SEL_KPL, 0);
	}
}

static void
atpic_init(void *dummy __unused)
{
	int i;

	/* Loop through all interrupt sources and add them. */
	for (i = 0; i < sizeof(atintrs) / sizeof(struct atpic_intsrc); i++) {
		if (i == ICU_SLAVEID)
			continue;
		intr_register_source(&atintrs[i].at_intsrc);
	}
}
SYSINIT(atpic_init, SI_SUB_INTR, SI_ORDER_SECOND + 1, atpic_init, NULL)

void
atpic_handle_intr(void *cookie, struct intrframe iframe)
{
	struct intsrc *isrc;
	int vec = (uintptr_t)cookie;

	KASSERT(vec < ICU_LEN, ("unknown int %d\n", vec));
	isrc = &atintrs[vec].at_intsrc;

	/*
	 * If we don't have an ithread, see if this is a spurious
	 * interrupt.
	 */
	if (isrc->is_ithread == NULL && (vec == 7 || vec == 15)) {
		int port, isr;

		/*
		 * Read the ISR register to see if IRQ 7/15 is really
		 * pending.  Reset read register back to IRR when done.
		 */
		port = ((struct atpic *)isrc->is_pic)->at_ioaddr;
		mtx_lock_spin(&icu_lock);
		outb(port, OCW3_SEL | OCW3_RR | OCW3_RIS);
		isr = inb(port);
		outb(port, OCW3_SEL | OCW3_RR);
		mtx_unlock_spin(&icu_lock);
		if ((isr & IRQ7) == 0)
			return;
	}
	intr_execute_handlers(isrc, &iframe);
}

#ifdef DEV_ISA
/*
 * Bus attachment for the ISA PIC.
 */
static struct isa_pnp_id atpic_ids[] = {
	{ 0x0000d041 /* PNP0000 */, "AT interrupt controller" },
	{ 0 }
};

static int
atpic_probe(device_t dev)
{
	int result;
	
	result = ISA_PNP_PROBE(device_get_parent(dev), dev, atpic_ids);
	if (result <= 0)
		device_quiet(dev);
	return (result);
}

/*
 * We might be granted IRQ 2, as this is typically consumed by chaining
 * between the two PIC components.  If we're using the APIC, however,
 * this may not be the case, and as such we should free the resource.
 * (XXX untested)
 *
 * The generic ISA attachment code will handle allocating any other resources
 * that we don't explicitly claim here.
 */
static int
atpic_attach(device_t dev)
{
	struct resource *res;
	int rid;

	/* Try to allocate our IRQ and then free it. */
	rid = 0;
	res = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1, 0);
	if (res != NULL)
		bus_release_resource(dev, SYS_RES_IRQ, rid, res);
	return (0);
}

static device_method_t atpic_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		atpic_probe),
	DEVMETHOD(device_attach,	atpic_attach),
	DEVMETHOD(device_detach,	bus_generic_detach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),
	{ 0, 0 }
};

static driver_t atpic_driver = {
	"atpic",
	atpic_methods,
	1,		/* no softc */
};

static devclass_t atpic_devclass;

DRIVER_MODULE(atpic, isa, atpic_driver, atpic_devclass, 0, 0);
DRIVER_MODULE(atpic, acpi, atpic_driver, atpic_devclass, 0, 0);

/*
 * Return a bitmap of the current interrupt requests.  This is 8259-specific
 * and is only suitable for use at probe time.
 */
intrmask_t
isa_irq_pending(void)
{
	u_char irr1;
	u_char irr2;

	irr1 = inb(IO_ICU1);
	irr2 = inb(IO_ICU2);
	return ((irr2 << 8) | irr1);
}
#endif /* DEV_ISA */
