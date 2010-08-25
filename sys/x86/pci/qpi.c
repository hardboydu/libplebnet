/*-
 * Copyright (c) 2010 Advanced Computing Technologies LLC
 * Written by: John H. Baldwin <jhb@FreeBSD.org>
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
 */

/*
 * This driver provides a psuedo-bus to enumerate the PCI buses
 * present on a sytem using a QPI chipset.  It creates a qpi0 bus that
 * is a child of nexus0 and then creates two Host-PCI bridges as a
 * child of that.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/systm.h>

#include <machine/cputypes.h>
#include <machine/md_var.h>
#include <machine/pci_cfgreg.h>
#include <machine/specialreg.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcib_private.h>
#include "pcib_if.h"

struct qpi_device {
	int	qd_pcibus;
};

static MALLOC_DEFINE(M_QPI, "qpidrv", "qpi system device");

static void
qpi_identify(driver_t *driver, device_t parent)
{

        /* Check CPUID to ensure this is an i7 CPU of some sort. */
        if (!(cpu_vendor_id == CPU_VENDOR_INTEL && CPUID_TO_FAMILY(cpu_id) &&
	    (CPUID_TO_MODEL(cpu_id) == 0x1a || CPUID_TO_MODEL(cpu_id) == 0x2c)))
                return;

        /* PCI config register access is required. */
        if (pci_cfgregopen() == 0)
                return;

	/* Add a qpi bus device. */
	if (BUS_ADD_CHILD(parent, 20, "qpi", -1) == NULL)
		panic("Failed to add qpi bus");
}

static int
qpi_probe(device_t dev)
{

	device_set_desc(dev, "QPI system bus");
	return (BUS_PROBE_SPECIFIC);
}

static int
qpi_attach(device_t dev)
{
	struct qpi_device *qdev;
	device_t child;

	/*
	 * Add two Host-PCI bridge devices, one for PCI bus 254 and
	 * one for PCI bus 255.
	 */
	child = BUS_ADD_CHILD(dev, 0, "pcib", -1);
	if (child == NULL)
		panic("%s: failed to add pci bus 254",
		    device_get_nameunit(dev));
	qdev = malloc(sizeof(struct qpi_device), M_QPI, M_WAITOK);
	qdev->qd_pcibus = 254;
	device_set_ivars(child, qdev);

	child = BUS_ADD_CHILD(dev, 0, "pcib", -1);
	if (child == NULL)
		panic("%s: failed to add pci bus 255",
		    device_get_nameunit(dev));
	qdev = malloc(sizeof(struct qpi_device), M_QPI, M_WAITOK);
	qdev->qd_pcibus = 255;
	device_set_ivars(child, qdev);

	return (bus_generic_attach(dev));
}

static int
qpi_print_child(device_t bus, device_t child)
{
	struct qpi_device *qdev;
	int retval = 0;

	qdev = device_get_ivars(child);
	retval += bus_print_child_header(bus, child);
	if (qdev->qd_pcibus != -1)
		retval += printf(" pcibus %d", qdev->qd_pcibus);
	retval += bus_print_child_footer(bus, child);

	return (retval);
}

static int
qpi_read_ivar(device_t dev, device_t child, int which, uintptr_t *result)
{
	struct qpi_device *qdev;

	qdev = device_get_ivars(child);
	switch (which) {
	case PCIB_IVAR_BUS:
		*result = qdev->qd_pcibus;
		break;
	default:
		return (ENOENT);
	}
	return (0);
}

static device_method_t qpi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	qpi_identify),
	DEVMETHOD(device_probe,		qpi_probe),
	DEVMETHOD(device_attach,	qpi_attach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	qpi_print_child),
	DEVMETHOD(bus_add_child,	bus_generic_add_child),
	DEVMETHOD(bus_read_ivar,	qpi_read_ivar),
	DEVMETHOD(bus_alloc_resource,	bus_generic_alloc_resource),
	DEVMETHOD(bus_release_resource,	bus_generic_release_resource),
	DEVMETHOD(bus_activate_resource, bus_generic_activate_resource),
	DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
	DEVMETHOD(bus_setup_intr,	bus_generic_setup_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),

	{ 0, 0 }
};

static devclass_t qpi_devclass;

DEFINE_CLASS_0(qpi, qpi_driver, qpi_methods, 0);
DRIVER_MODULE(qpi, nexus, qpi_driver, qpi_devclass, 0, 0);

static int
qpi_pcib_probe(device_t dev)
{

	device_set_desc(dev, "QPI Host-PCI bridge");
	return (BUS_PROBE_SPECIFIC);
}

static int
qpi_pcib_attach(device_t dev)
{

	device_add_child(dev, "pci", pcib_get_bus(dev));      
        return (bus_generic_attach(dev));
}

static int
qpi_pcib_read_ivar(device_t dev, device_t child, int which, uintptr_t *result)
{

	switch (which) {
	case PCIB_IVAR_DOMAIN:
		*result = 0;
		return (0);
	case PCIB_IVAR_BUS:
		*result = pcib_get_bus(dev);
		return (0);
	default:
		return (ENOENT);
	}
}

static uint32_t
qpi_pcib_read_config(device_t dev, u_int bus, u_int slot, u_int func,
    u_int reg, int bytes)
{

	return (pci_cfgregread(bus, slot, func, reg, bytes));
}

static void
qpi_pcib_write_config(device_t dev, u_int bus, u_int slot, u_int func,
    u_int reg, uint32_t data, int bytes)
{

	pci_cfgregwrite(bus, slot, func, reg, data, bytes);
}

static int
qpi_pcib_alloc_msi(device_t pcib, device_t dev, int count, int maxcount,
    int *irqs)
{
	device_t bus;

	bus = device_get_parent(pcib);
	return (PCIB_ALLOC_MSI(device_get_parent(bus), dev, count, maxcount,
	    irqs));
}

static int
qpi_pcib_alloc_msix(device_t pcib, device_t dev, int *irq)
{
	device_t bus;

	bus = device_get_parent(pcib);
	return (PCIB_ALLOC_MSIX(device_get_parent(bus), dev, irq));
}

static int
qpi_pcib_map_msi(device_t pcib, device_t dev, int irq, uint64_t *addr,
    uint32_t *data)
{
	device_t bus;

	bus = device_get_parent(pcib);
	return (PCIB_MAP_MSI(device_get_parent(bus), dev, irq, addr, data));
}

static device_method_t qpi_pcib_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		qpi_pcib_probe),
	DEVMETHOD(device_attach,	qpi_pcib_attach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_read_ivar,	qpi_pcib_read_ivar),
	DEVMETHOD(bus_alloc_resource,	bus_generic_alloc_resource),
	DEVMETHOD(bus_release_resource,	bus_generic_release_resource),
	DEVMETHOD(bus_activate_resource, bus_generic_activate_resource),
	DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
	DEVMETHOD(bus_setup_intr,	bus_generic_setup_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),

	/* pcib interface */
	DEVMETHOD(pcib_maxslots,	pcib_maxslots),
	DEVMETHOD(pcib_read_config,	qpi_pcib_read_config),
	DEVMETHOD(pcib_write_config,	qpi_pcib_write_config),
	DEVMETHOD(pcib_alloc_msi,	qpi_pcib_alloc_msi),
	DEVMETHOD(pcib_release_msi,	pcib_release_msi),
	DEVMETHOD(pcib_alloc_msix,	qpi_pcib_alloc_msix),
	DEVMETHOD(pcib_release_msix,	pcib_release_msix),
	DEVMETHOD(pcib_map_msi,		qpi_pcib_map_msi),

	{0, 0}
};

static devclass_t qpi_pcib_devclass;

DEFINE_CLASS_0(pcib, qpi_pcib_driver, qpi_pcib_methods, 0);
DRIVER_MODULE(pcib, qpi, qpi_pcib_driver, qpi_pcib_devclass, 0, 0);
