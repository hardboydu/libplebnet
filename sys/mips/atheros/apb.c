/*-
 * Copyright (c) 2009, Oleksandr Tymoshenko <gonzo@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/malloc.h>

#include <machine/bus.h>
#include <machine/intr_machdep.h>

#include <mips/atheros/apbvar.h>
#include <mips/atheros/ar71xxreg.h>
#include <mips/atheros/ar71xx_setup.h>

#undef APB_DEBUG
#ifdef APB_DEBUG
#define dprintf printf
#else 
#define dprintf(x, arg...)
#endif  /* APB_DEBUG */

static int	apb_activate_resource(device_t, device_t, int, int,
		    struct resource *);
static device_t	apb_add_child(device_t, u_int, const char *, int);
static struct resource *
		apb_alloc_resource(device_t, device_t, int, int *, u_long,
		    u_long, u_long, u_int);
static int	apb_attach(device_t);
static int	apb_deactivate_resource(device_t, device_t, int, int,
		    struct resource *);
static struct resource_list *
		apb_get_resource_list(device_t, device_t);
static void	apb_hinted_child(device_t, const char *, int);
static int	apb_intr(void *);
static int	apb_probe(device_t);
static int	apb_release_resource(device_t, device_t, int, int,
		    struct resource *);
static int	apb_setup_intr(device_t, device_t, struct resource *, int,
		    driver_filter_t *, driver_intr_t *, void *, void **);
static int	apb_teardown_intr(device_t, device_t, struct resource *,
		    void *);

static void 
apb_mask_irq(void *source)
{
	unsigned int irq = (unsigned int)source;
	uint32_t reg;

	reg = ATH_READ_REG(AR71XX_MISC_INTR_MASK);
	ATH_WRITE_REG(AR71XX_MISC_INTR_MASK, reg & ~(1 << irq));

}

static void 
apb_unmask_irq(void *source)
{
	uint32_t reg;
	unsigned int irq = (unsigned int)source;

	reg = ATH_READ_REG(AR71XX_MISC_INTR_MASK);
	ATH_WRITE_REG(AR71XX_MISC_INTR_MASK, reg | (1 << irq));
}

static int
apb_probe(device_t dev)
{

	return (0);
}

static int
apb_attach(device_t dev)
{
	struct apb_softc *sc = device_get_softc(dev);
	int rid = 0;

	device_set_desc(dev, "APB Bus bridge");

	sc->apb_mem_rman.rm_type = RMAN_ARRAY;
	sc->apb_mem_rman.rm_descr = "APB memory window";

	if (rman_init(&sc->apb_mem_rman) != 0 ||
	    rman_manage_region(&sc->apb_mem_rman, 
			AR71XX_APB_BASE, 
			AR71XX_APB_BASE + AR71XX_APB_SIZE - 1) != 0)
		panic("apb_attach: failed to set up memory rman");

	sc->apb_irq_rman.rm_type = RMAN_ARRAY;
	sc->apb_irq_rman.rm_descr = "APB IRQ";

	if (rman_init(&sc->apb_irq_rman) != 0 ||
	    rman_manage_region(&sc->apb_irq_rman, 
			APB_IRQ_BASE, APB_IRQ_END) != 0)
		panic("apb_attach: failed to set up IRQ rman");

	if ((sc->sc_misc_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid, 
	    RF_SHAREABLE | RF_ACTIVE)) == NULL) {
		device_printf(dev, "unable to allocate IRQ resource\n");
		return (ENXIO);
	}

	if ((bus_setup_intr(dev, sc->sc_misc_irq, INTR_TYPE_MISC, 
	    apb_intr, NULL, sc, &sc->sc_misc_ih))) {
		device_printf(dev,
		    "WARNING: unable to register interrupt handler\n");
		return (ENXIO);
	}

	bus_generic_probe(dev);
	bus_enumerate_hinted_children(dev);
	bus_generic_attach(dev);

	return (0);
}

static struct resource *
apb_alloc_resource(device_t bus, device_t child, int type, int *rid,
    u_long start, u_long end, u_long count, u_int flags)
{
	struct apb_softc		*sc = device_get_softc(bus);
	struct apb_ivar			*ivar = device_get_ivars(child);
	struct resource			*rv;
	struct resource_list_entry	*rle;
	struct rman			*rm;
	int				 isdefault, needactivate, passthrough;

	isdefault = (start == 0UL && end == ~0UL);
	needactivate = flags & RF_ACTIVE;
	/*
	 * Pass memory requests to nexus device
	 */
	passthrough = (device_get_parent(child) != bus);
	rle = NULL;

	dprintf("%s: entry (%p, %p, %d, %d, %p, %p, %ld, %d)\n",
	    __func__, bus, child, type, *rid, (void *)(intptr_t)start,
	    (void *)(intptr_t)end, count, flags);

	if (passthrough)
		return (BUS_ALLOC_RESOURCE(device_get_parent(bus), child, type,
		    rid, start, end, count, flags));

	/*
	 * If this is an allocation of the "default" range for a given RID,
	 * and we know what the resources for this device are (ie. they aren't
	 * maintained by a child bus), then work out the start/end values.
	 */

	if (isdefault) {
		rle = resource_list_find(&ivar->resources, type, *rid);
		if (rle == NULL) {
			return (NULL);
		}

		if (rle->res != NULL) {
			panic("%s: resource entry is busy", __func__);
		}
		start = rle->start;
		end = rle->end;
		count = rle->count;

		dprintf("%s: default resource (%p, %p, %ld)\n",
		    __func__, (void *)(intptr_t)start,
		    (void *)(intptr_t)end, count);
	}

	switch (type) {
	case SYS_RES_IRQ:
		rm = &sc->apb_irq_rman;
		break;
	case SYS_RES_MEMORY:
		rm = &sc->apb_mem_rman;
		break;
	default:
		printf("%s: unknown resource type %d\n", __func__, type);
		return (0);
	}

	rv = rman_reserve_resource(rm, start, end, count, flags, child);
	if (rv == 0) {
		printf("%s: could not reserve resource\n", __func__);
		return (0);
	}

	rman_set_rid(rv, *rid);

	if (needactivate) {
		if (bus_activate_resource(child, type, *rid, rv)) {
			printf("%s: could not activate resource\n", __func__);
			rman_release_resource(rv);
			return (0);
		}
	}

	return (rv);
}

static int
apb_activate_resource(device_t bus, device_t child, int type, int rid,
    struct resource *r)
{

	/* XXX: should we mask/unmask IRQ here? */
	return (BUS_ACTIVATE_RESOURCE(device_get_parent(bus), child,
		type, rid, r));
}

static int
apb_deactivate_resource(device_t bus, device_t child, int type, int rid,
    struct resource *r)
{

	/* XXX: should we mask/unmask IRQ here? */
	return (BUS_DEACTIVATE_RESOURCE(device_get_parent(bus), child,
		type, rid, r));
}

static int
apb_release_resource(device_t dev, device_t child, int type,
    int rid, struct resource *r)
{
	struct resource_list *rl;
	struct resource_list_entry *rle;

	rl = apb_get_resource_list(dev, child);
	if (rl == NULL)
		return (EINVAL);
	rle = resource_list_find(rl, type, rid);
	if (rle == NULL)
		return (EINVAL);
	rman_release_resource(r);
	rle->res = NULL;

	return (0);
}

static int
apb_setup_intr(device_t bus, device_t child, struct resource *ires,
		int flags, driver_filter_t *filt, driver_intr_t *handler,
		void *arg, void **cookiep)
{
	struct apb_softc *sc = device_get_softc(bus);
	struct intr_event *event;
	int irq, error;

	irq = rman_get_start(ires);

	if (irq > APB_IRQ_END)
		panic("%s: bad irq %d", __func__, irq);

	event = sc->sc_eventstab[irq];
	if (event == NULL) {
		error = intr_event_create(&event, (void *)irq, 0, irq, 
		    apb_mask_irq, apb_unmask_irq,
		    NULL, NULL,
		    "apb intr%d:", irq);

		if (error == 0) {
			sc->sc_eventstab[irq] = event;
			sc->sc_intr_counter[irq] =
			    mips_intrcnt_create(event->ie_name);
		}
		else
			return (error);
	}

	intr_event_add_handler(event, device_get_nameunit(child), filt,
	    handler, arg, intr_priority(flags), flags, cookiep);
	mips_intrcnt_setname(sc->sc_intr_counter[irq], event->ie_fullname);

	apb_unmask_irq((void*)irq);

	return (0);
}

static int
apb_teardown_intr(device_t dev, device_t child, struct resource *ires,
    void *cookie)
{
	struct apb_softc *sc = device_get_softc(dev);
	int irq, result;

	irq = rman_get_start(ires);
	if (irq > APB_IRQ_END)
		panic("%s: bad irq %d", __func__, irq);

	if (sc->sc_eventstab[irq] == NULL)
		panic("Trying to teardown unoccupied IRQ");

	apb_mask_irq((void*)irq);

	result = intr_event_remove_handler(cookie);
	if (!result)
		sc->sc_eventstab[irq] = NULL;

	return (result);
}

static int
apb_intr(void *arg)
{
	struct apb_softc *sc = arg;
	struct intr_event *event;
	uint32_t reg, irq;

	reg = ATH_READ_REG(AR71XX_MISC_INTR_STATUS);
	for (irq = 0; irq < APB_NIRQS; irq++) {
		if (reg & (1 << irq)) {

			switch (ar71xx_soc) {
			case AR71XX_SOC_AR7240:
			case AR71XX_SOC_AR7241:
			case AR71XX_SOC_AR7242:
				/* Ack/clear the irq on status register for AR724x */
				ATH_WRITE_REG(AR71XX_MISC_INTR_STATUS,
				    reg & ~(1 << irq));
				break;
			default:
				/* fallthrough */
				break;
			}

			event = sc->sc_eventstab[irq];
			if (!event || TAILQ_EMPTY(&event->ie_handlers)) {
				/* Ignore timer interrupts */
				if (irq != 0)
					printf("Stray APB IRQ %d\n", irq);
				continue;
			}

			/* TODO: frame instead of NULL? */
			intr_event_handle(event, NULL);
			mips_intrcnt_inc(sc->sc_intr_counter[irq]);
		}
	}

	return (FILTER_HANDLED);
}

static void
apb_hinted_child(device_t bus, const char *dname, int dunit)
{
	device_t		child;
	long			maddr;
	int			msize;
	int			irq;
	int			result;
	int			mem_hints_count;

	child = BUS_ADD_CHILD(bus, 0, dname, dunit);

	/*
	 * Set hard-wired resources for hinted child using
	 * specific RIDs.
	 */
	mem_hints_count = 0;
	if (resource_long_value(dname, dunit, "maddr", &maddr) == 0)
		mem_hints_count++;
	if (resource_int_value(dname, dunit, "msize", &msize) == 0)
		mem_hints_count++;

	/* check if all info for mem resource has been provided */
	if ((mem_hints_count > 0) && (mem_hints_count < 2)) {
		printf("Either maddr or msize hint is missing for %s%d\n",
		    dname, dunit);
	} else if (mem_hints_count) {
		result = bus_set_resource(child, SYS_RES_MEMORY, 0,
		    maddr, msize);
		if (result != 0)
			device_printf(bus, 
			    "warning: bus_set_resource() failed\n");
	}

	if (resource_int_value(dname, dunit, "irq", &irq) == 0) {
		result = bus_set_resource(child, SYS_RES_IRQ, 0, irq, 1);
		if (result != 0)
			device_printf(bus,
			    "warning: bus_set_resource() failed\n");
	}
}

static device_t
apb_add_child(device_t bus, u_int order, const char *name, int unit)
{
	device_t		child;
	struct apb_ivar	*ivar;

	ivar = malloc(sizeof(struct apb_ivar), M_DEVBUF, M_WAITOK | M_ZERO);
	if (ivar == NULL) {
		printf("Failed to allocate ivar\n");
		return (0);
	}
	resource_list_init(&ivar->resources);

	child = device_add_child_ordered(bus, order, name, unit);
	if (child == NULL) {
		printf("Can't add child %s%d ordered\n", name, unit);
		return (0);
	}

	device_set_ivars(child, ivar);

	return (child);
}

/*
 * Helper routine for bus_generic_rl_get_resource/bus_generic_rl_set_resource
 * Provides pointer to resource_list for these routines
 */
static struct resource_list *
apb_get_resource_list(device_t dev, device_t child)
{
	struct apb_ivar *ivar;

	ivar = device_get_ivars(child);
	return (&(ivar->resources));
}

static device_method_t apb_methods[] = {
	DEVMETHOD(bus_activate_resource,	apb_activate_resource),
	DEVMETHOD(bus_add_child,		apb_add_child),
	DEVMETHOD(bus_alloc_resource,		apb_alloc_resource),
	DEVMETHOD(bus_deactivate_resource,	apb_deactivate_resource),
	DEVMETHOD(bus_get_resource_list,	apb_get_resource_list),
	DEVMETHOD(bus_hinted_child,		apb_hinted_child),
	DEVMETHOD(bus_print_child,		bus_generic_print_child),
	DEVMETHOD(bus_release_resource,		apb_release_resource),
	DEVMETHOD(bus_setup_intr,		apb_setup_intr),
	DEVMETHOD(bus_teardown_intr,		apb_teardown_intr),
	DEVMETHOD(device_attach,		apb_attach),
	DEVMETHOD(device_probe,			apb_probe),
	DEVMETHOD(bus_get_resource,		bus_generic_rl_get_resource),
	DEVMETHOD(bus_set_resource,		bus_generic_rl_set_resource),

	{0, 0},
};

static driver_t apb_driver = {
	"apb",
	apb_methods,
	sizeof(struct apb_softc),
};
static devclass_t apb_devclass;

DRIVER_MODULE(apb, nexus, apb_driver, apb_devclass, 0, 0);
