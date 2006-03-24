/*-
 * Copyright (c) 2006 M. Warner Losh.  All rights reserved.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <machine/bus.h>

#include <arm/at91/at91_pioreg.h>

struct at91_pio_softc
{
	device_t dev;			/* Myself */
	void *intrhand;			/* Interrupt handle */
	struct resource *irq_res;	/* IRQ resource */
	struct resource	*mem_res;	/* Memory resource */
	struct mtx sc_mtx;		/* basically a perimeter lock */
	struct cdev *cdev;
	int flags;
#define OPENED 1
};

static inline uint32_t
RD4(struct at91_pio_softc *sc, bus_size_t off)
{
	return bus_read_4(sc->mem_res, off);
}

static inline void
WR4(struct at91_pio_softc *sc, bus_size_t off, uint32_t val)
{
	bus_write_4(sc->mem_res, off, val);
}

#define AT91_PIO_LOCK(_sc)		mtx_lock_spin(&(_sc)->sc_mtx)
#define	AT91_PIO_UNLOCK(_sc)		mtx_unlock_spin(&(_sc)->sc_mtx)
#define AT91_PIO_LOCK_INIT(_sc) \
	mtx_init(&_sc->sc_mtx, device_get_nameunit(_sc->dev), \
	    "pio", MTX_SPIN)
#define AT91_PIO_LOCK_DESTROY(_sc)	mtx_destroy(&_sc->sc_mtx);
#define AT91_PIO_ASSERT_LOCKED(_sc)	mtx_assert(&_sc->sc_mtx, MA_OWNED);
#define AT91_PIO_ASSERT_UNLOCKED(_sc) mtx_assert(&_sc->sc_mtx, MA_NOTOWNED);
#define CDEV2SOFTC(dev)		((dev)->si_drv1)

static devclass_t at91_pio_devclass;

/* bus entry points */

static int at91_pio_probe(device_t dev);
static int at91_pio_attach(device_t dev);
static int at91_pio_detach(device_t dev);
static void at91_pio_intr(void *);

/* helper routines */
static int at91_pio_activate(device_t dev);
static void at91_pio_deactivate(device_t dev);

/* cdev routines */
static d_open_t at91_pio_open;
static d_close_t at91_pio_close;
static d_ioctl_t at91_pio_ioctl;

static struct cdevsw at91_pio_cdevsw =
{
	.d_version = D_VERSION,
	.d_open = at91_pio_open,
	.d_close = at91_pio_close,
	.d_ioctl = at91_pio_ioctl
};

static int
at91_pio_probe(device_t dev)
{
	device_set_desc(dev, "PIO");
	return (0);
}

static int
at91_pio_attach(device_t dev)
{
	struct at91_pio_softc *sc = device_get_softc(dev);
	int err;

	sc->dev = dev;
	err = at91_pio_activate(dev);
	if (err)
		goto out;

	AT91_PIO_LOCK_INIT(sc);

	/*
	 * Activate the interrupt, but disable all interrupts in the hardware
	 */
	WR4(sc, PIO_IDR, 0xffffffff);
	err = bus_setup_intr(dev, sc->irq_res, INTR_TYPE_MISC | INTR_FAST,
	    at91_pio_intr, sc, &sc->intrhand);
	if (err) {
		AT91_PIO_LOCK_DESTROY(sc);
		goto out;
	}
	sc->cdev = make_dev(&at91_pio_cdevsw, device_get_unit(dev), UID_ROOT
	    , GID_WHEEL, 0600, "pio%d", device_get_unit(dev));
	if (sc->cdev == NULL) {
		err = ENOMEM;
		goto out;
	}
	sc->cdev->si_drv1 = sc;
out:;
	if (err)
		at91_pio_deactivate(dev);
	return (err);
}

static int
at91_pio_detach(device_t dev)
{
	return (EBUSY);	/* XXX */
}

static int
at91_pio_activate(device_t dev)
{
	struct at91_pio_softc *sc;
	int rid;

	sc = device_get_softc(dev);
	rid = 0;
	sc->mem_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (sc->mem_res == NULL)
		goto errout;
	rid = 0;
	sc->irq_res = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    RF_ACTIVE | RF_SHAREABLE);
	if (sc->irq_res == NULL)
		goto errout;
	return (0);
errout:
	at91_pio_deactivate(dev);
	return (ENOMEM);
}

static void
at91_pio_deactivate(device_t dev)
{
	struct at91_pio_softc *sc;

	sc = device_get_softc(dev);
	if (sc->intrhand)
		bus_teardown_intr(dev, sc->irq_res, sc->intrhand);
	sc->intrhand = 0;
	bus_generic_detach(sc->dev);
	if (sc->mem_res)
		bus_release_resource(dev, SYS_RES_IOPORT,
		    rman_get_rid(sc->mem_res), sc->mem_res);
	sc->mem_res = 0;
	if (sc->irq_res)
		bus_release_resource(dev, SYS_RES_IRQ,
		    rman_get_rid(sc->irq_res), sc->irq_res);
	sc->irq_res = 0;
	return;
}

static void
at91_pio_intr(void *xsc)
{
	struct at91_pio_softc *sc = xsc;
#if 0
	uint32_t status;

	/* Reading the status also clears the interrupt */
	status = RD4(sc, PIO_SR);
	if (status == 0)
		return;
	AT91_PIO_LOCK(sc);
	AT91_PIO_UNLOCK(sc);
#endif
	wakeup(sc);
	return;
}

static int 
at91_pio_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct at91_pio_softc *sc;

	sc = CDEV2SOFTC(dev);
	AT91_PIO_LOCK(sc);
	if (!(sc->flags & OPENED)) {
		sc->flags |= OPENED;
#if 0
	// Enable interrupts
#endif
	}
	AT91_PIO_UNLOCK(sc);
    	return (0);
}

static int
at91_pio_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct at91_pio_softc *sc;

	sc = CDEV2SOFTC(dev);
	AT91_PIO_LOCK(sc);
	sc->flags &= ~OPENED;
#if 0
	// Disable interrupts
#endif
	AT91_PIO_UNLOCK(sc);
	return (0);
}

static int
at91_pio_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	return (ENXIO);
}

static device_method_t at91_pio_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		at91_pio_probe),
	DEVMETHOD(device_attach,	at91_pio_attach),
	DEVMETHOD(device_detach,	at91_pio_detach),

	{ 0, 0 }
};

static driver_t at91_pio_driver = {
	"at91_pio",
	at91_pio_methods,
	sizeof(struct at91_pio_softc),
};

DRIVER_MODULE(at91_pio, atmelarm, at91_pio_driver, at91_pio_devclass, 0, 0);
