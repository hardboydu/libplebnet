/*-
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2000 BSDi
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/kernel.h>

#include "acpi.h"
#include <dev/acpica/acpivar.h>
#include <dev/acpica/acpi_pcibvar.h>

#include <dev/pci/pcivar.h>
#include "pcib_if.h"

/* Hooks for the ACPI CA debugging infrastructure. */
#define _COMPONENT	ACPI_BUS
ACPI_MODULE_NAME("PCI")

int
acpi_pcib_attach(device_t dev, ACPI_BUFFER *prt, int busno)
{
    device_t			child;
    ACPI_STATUS			status;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    /*
     * Don't attach if we're not really there.
     *
     * XXX: This isn't entirely correct since we may be a PCI bus
     * on a hot-plug docking station, etc.
     */
    if (!acpi_DeviceIsPresent(dev))
	return_VALUE(ENXIO);

    /*
     * Get the PCI interrupt routing table for this bus.  If we can't
     * get it, this is not an error but may reduce functionality.
     */
    prt->Length = ACPI_ALLOCATE_BUFFER;
    status = AcpiGetIrqRoutingTable(acpi_get_handle(dev), prt);
    if (ACPI_FAILURE(status))
	device_printf(dev,
	    "could not get PCI interrupt routing table for %s - %s\n",
	    acpi_name(acpi_get_handle(dev)), AcpiFormatException(status));

    /*
     * Attach the PCI bus proper.
     */
    if ((child = device_add_child(dev, "pci", busno)) == NULL) {
	device_printf(device_get_parent(dev), "couldn't attach pci bus\n");
	return_VALUE(ENXIO);
    }

    /*
     * Now go scan the bus.
     */
    acpi_pci_link_config(dev, prt, busno);

    return_VALUE (bus_generic_attach(dev));
}

int
acpi_pcib_resume(device_t dev, ACPI_BUFFER *prt, int busno)
{
    acpi_pci_link_resume(dev, prt, busno);
    return (bus_generic_resume(dev));
}

/*
 * Route an interrupt for a child of the bridge.
 *
 * XXX clean up error messages
 *
 * XXX this function is somewhat bulky
 */
int
acpi_pcib_route_interrupt(device_t pcib, device_t dev, int pin,
    ACPI_BUFFER *prtbuf)
{
    ACPI_PCI_ROUTING_TABLE	*prt;
    ACPI_HANDLE			lnkdev;
    ACPI_BUFFER			crsbuf, prsbuf, buf;
    ACPI_RESOURCE		*crsres, *prsres, resbuf;
    ACPI_DEVICE_INFO		*devinfo;
    ACPI_STATUS			status;
    UINT32			NumberOfInterrupts;
    UINT32			*Interrupts;
    u_int8_t			*prtp;
    int				interrupt;
    int				i;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    
    crsres = NULL;
    buf.Pointer = NULL;
    crsbuf.Pointer = NULL;
    prsbuf.Pointer = NULL;
    interrupt = PCI_INVALID_IRQ;

    /* ACPI numbers pins 0-3, not 1-4 like the BIOS. */
    pin--;

    /* We failed to retrieve the routing table. */
    prtp = prtbuf->Pointer;
    if (prtp == NULL)
	goto out;

    /* Scan the table to look for this device. */
    for (;;) {
	prt = (ACPI_PCI_ROUTING_TABLE *)prtp;

	/* We hit the end of the table. */
	if (prt->Length == 0)
	    goto out;

	/*
	 * Compare the slot number (high word of Address) and pin number
	 * (note that ACPI uses 0 for INTA) to check for a match.
	 *
	 * Note that the low word of the Address field (function number)
	 * is required by the specification to be 0xffff.  We don't risk
	 * checking it here.
	 */
	if (((prt->Address & 0xffff0000) >> 16) == pci_get_slot(dev) &&
	    prt->Pin == pin) {
	    if (bootverbose)
		device_printf(pcib, "matched entry for %d.%d.INT%c (src %s)\n",
			      pci_get_bus(dev), pci_get_slot(dev), 'A' + pin,
			      prt->Source);
	    break;
	}
	
	/* Skip to the next entry. */
	prtp += prt->Length;
    }

    /*
     * If source is empty/NULL, the source index is the global IRQ number.
     */
    if (prt->Source == NULL || prt->Source[0] == '\0') {
	if (bootverbose)
	    device_printf(pcib, "device is hardwired to IRQ %d\n",
			  prt->SourceIndex);
	interrupt = prt->SourceIndex;
	goto out;
    }
    
    /*
     * We have to find the source device (PCI interrupt link device).
     */
    if (ACPI_FAILURE(AcpiGetHandle(ACPI_ROOT_OBJECT, prt->Source, &lnkdev))) {
	device_printf(pcib, "couldn't find PCI interrupt link device %s\n",
	    prt->Source);
	goto out;
    }

    /*
     * Verify that this is a PCI link device and that it's present.
     */
    buf.Length = ACPI_ALLOCATE_BUFFER;
    if (ACPI_FAILURE(AcpiGetObjectInfo(lnkdev, &buf))) {
	device_printf(pcib, "couldn't validate PCI interrupt link device %s\n",
		      prt->Source);
	goto out;
    }
    devinfo = (ACPI_DEVICE_INFO *)buf.Pointer;
    if ((devinfo->Valid & ACPI_VALID_HID) == 0 ||
	strcmp("PNP0C0F", devinfo->HardwareId.Value) != 0) {
	device_printf(pcib, "PCI interrupt link %s has invalid _HID (%s)\n",
		      prt->Source, devinfo->HardwareId.Value);
	goto out;
    }
    if ((devinfo->Valid & ACPI_VALID_STA) != 0 &&
	(devinfo->CurrentStatus & 0x9) != 0x9) {
	device_printf(pcib, "PCI interrupt link device %s not present\n",
		      prt->Source);
	goto out;
    }

    /*
     * Get the current and possible resources for the interrupt link device.
     * If we fail to get the current resources, this is a fatal error.
     */
    crsbuf.Length = ACPI_ALLOCATE_BUFFER;
    if (ACPI_FAILURE(status = AcpiGetCurrentResources(lnkdev, &crsbuf))) {
	device_printf(pcib, "PCI interrupt link device _CRS failed - %s\n",
		      AcpiFormatException(status));
	goto out;
    }
    prsbuf.Length = ACPI_ALLOCATE_BUFFER;
    if (ACPI_FAILURE(status = AcpiGetPossibleResources(lnkdev, &prsbuf))) {
	device_printf(pcib, "PCI interrupt link device _PRS failed - %s\n",
		      AcpiFormatException(status));
    }
    ACPI_DEBUG_PRINT((ACPI_DB_RESOURCES, "got %ld bytes for %s._CRS\n",
		     (long)crsbuf.Length, acpi_name(lnkdev)));
    ACPI_DEBUG_PRINT((ACPI_DB_RESOURCES, "got %ld bytes for %s._PRS\n",
		     (long)prsbuf.Length, acpi_name(lnkdev)));

    /*
     * The interrupt may already be routed, so check _CRS first.  We don't
     * check the 'decoding' bit in the _STA result, since there's nothing in
     * the spec that mandates it be set, however some BIOS' will set it if
     * the decode is active.
     *
     * The Source Index points to the particular resource entry we're
     * interested in.
     */
    if (ACPI_FAILURE(acpi_FindIndexedResource(&crsbuf, prt->SourceIndex,
	&crsres))) {
	device_printf(pcib, "_CRS buffer corrupt, cannot route interrupt\n");
	goto out;
    }

    /* Type-check the resource we've found. */
    if (crsres->Id != ACPI_RSTYPE_IRQ && crsres->Id != ACPI_RSTYPE_EXT_IRQ) {
	device_printf(pcib, "_CRS resource entry has unsupported type %d\n",
		      crsres->Id);
	goto out;
    }

    /* Set variables based on resource type. */
    if (crsres->Id == ACPI_RSTYPE_IRQ) {
	NumberOfInterrupts = crsres->Data.Irq.NumberOfInterrupts;
	Interrupts = crsres->Data.Irq.Interrupts;
    } else {
	NumberOfInterrupts = crsres->Data.ExtendedIrq.NumberOfInterrupts;
	Interrupts = crsres->Data.ExtendedIrq.Interrupts;
    }

    /* If there's more than one interrupt, this is an error. */
    if (NumberOfInterrupts > 1) {
	device_printf(pcib, "device has too many interrupts (%d)\n",
		      NumberOfInterrupts);
	goto out;
    }

    /* 
     * If there's only one interrupt, and it's not zero, then it's already
     * routed.
     *
     * Note that we could also check the 'decoding' bit in _STA, but can't
     * depend on it since it's not part of the spec.
     *
     * XXX check ASL examples to see if this is an acceptable set of tests
     */
    if (NumberOfInterrupts == 1 && Interrupts[0] != 0) {
	device_printf(pcib, "slot %d INT%c is routed to irq %d\n",
		      pci_get_slot(dev), 'A' + pin, Interrupts[0]);
	interrupt = Interrupts[0];
	goto out;
    }
    
    /* 
     * There isn't an interrupt, so we have to look at _PRS to get one.
     * Get the set of allowed interrupts from the _PRS resource indexed
     * by SourceIndex.
     */
    if (prsbuf.Pointer == NULL) {
	device_printf(pcib, "no routed irq and no _PRS on irq link device\n");
	goto out;
    }

    /*
     * Search through the _PRS resources, looking for an IRQ or extended
     * IRQ resource.  Skip dependent function resources for now.  In the
     * future, we might use these for priority but this is good enough for
     * now until BIOS vendors actually mean something by using them.
     */
    prsres = NULL;
    for (i = prt->SourceIndex; prsres == NULL; i++) {
	if (ACPI_FAILURE(acpi_FindIndexedResource(&prsbuf, i, &prsres))) {
	    device_printf(pcib, "_PRS lacks IRQ resource, routing failed\n");
	    goto out;
	}
	switch (prsres->Id) {
	case ACPI_RSTYPE_IRQ:
	    NumberOfInterrupts = prsres->Data.Irq.NumberOfInterrupts;
	    Interrupts = prsres->Data.Irq.Interrupts;
	    break;
	case ACPI_RSTYPE_EXT_IRQ:
	    NumberOfInterrupts = prsres->Data.ExtendedIrq.NumberOfInterrupts;
	    Interrupts = prsres->Data.ExtendedIrq.Interrupts;
	    break;
	case ACPI_RSTYPE_START_DPF:
	    prsres = NULL;
	    continue;
	default:
	    device_printf(pcib, "_PRS has invalid type %d\n", prsres->Id);
	    goto out;
	}
    }

    /* There has to be at least one interrupt available. */
    if (NumberOfInterrupts < 1) {
	device_printf(pcib, "device has no interrupts\n");
	goto out;
    }

    /*
     * Pick an interrupt to use.  Note that a more scientific approach than
     * just taking the first one available would be desirable.
     *
     * The PCI BIOS $PIR table offers "preferred PCI interrupts", but ACPI
     * doesn't seem to offer a similar mechanism, so picking a "good"
     * interrupt here is a difficult task.
     *
     * Build a resource buffer and pass it to AcpiSetCurrentResources to
     * route the new interrupt.
     */
    device_printf(pcib, "possible interrupts:");
    for (i = 0; i < NumberOfInterrupts; i++)
	printf("  %d", Interrupts[i]);
    printf("\n");

    /* This should never happen. */
    if (crsbuf.Pointer != NULL)
	AcpiOsFree(crsbuf.Pointer);

    /* XXX Data.Irq and Data.ExtendedIrq are implicitly structure-copied. */
    crsbuf.Pointer = NULL;
    crsres = NULL;
    if (prsres->Id == ACPI_RSTYPE_IRQ) {
	resbuf.Id = ACPI_RSTYPE_IRQ;
	resbuf.Length = ACPI_SIZEOF_RESOURCE(ACPI_RESOURCE_IRQ);
	resbuf.Data.Irq = prsres->Data.Irq;
	resbuf.Data.Irq.NumberOfInterrupts = 1;
	resbuf.Data.Irq.Interrupts[0] = Interrupts[0];
    } else {
	resbuf.Id = ACPI_RSTYPE_EXT_IRQ;
	resbuf.Length = ACPI_SIZEOF_RESOURCE(ACPI_RESOURCE_EXT_IRQ);
	resbuf.Data.ExtendedIrq = prsres->Data.ExtendedIrq;
	resbuf.Data.ExtendedIrq.NumberOfInterrupts = 1;
	resbuf.Data.ExtendedIrq.Interrupts[0] = Interrupts[0];
    }
    if (ACPI_FAILURE(status = acpi_AppendBufferResource(&crsbuf, &resbuf))) {
	device_printf(pcib, "buf append failed for interrupt %d via %s - %s\n",
		      Interrupts[0], acpi_name(lnkdev),
		      AcpiFormatException(status));
	goto out;
    }
    /* XXX Figure out how this is happening when the append succeeds. */
    if (crsbuf.Pointer == NULL) {
	device_printf(pcib, "_CRS buf NULL after append?\n");
	goto out;
    }
    if (ACPI_FAILURE(status = AcpiSetCurrentResources(lnkdev, &crsbuf))) {
	device_printf(pcib, "_SRS failed for interrupt %d via %s - %s\n",
		      Interrupts[0], acpi_name(lnkdev),
		      AcpiFormatException(status));
	goto out;
    }
    crsres = &resbuf;
    
    /* Return the interrupt we just routed. */
    device_printf(pcib, "slot %d INT%c routed to irq %d via %s\n", 
		  pci_get_slot(dev), 'A' + pin, Interrupts[0],
		  acpi_name(lnkdev));
    interrupt = Interrupts[0];

out:
    if (PCI_INTERRUPT_VALID(interrupt) && crsres != NULL)
	acpi_config_intr(dev, crsres);
    if (crsbuf.Pointer != NULL)
	AcpiOsFree(crsbuf.Pointer);
    if (prsbuf.Pointer != NULL)
	AcpiOsFree(prsbuf.Pointer);
    if (buf.Pointer != NULL)
	AcpiOsFree(buf.Pointer);

    return_VALUE (interrupt);
}
