/*
 * FreeBSD, PCI product support functions
 *
 * Copyright (c) 1995, 1996, 1997, 1998, 1999, 2000 Justin T. Gibbs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 *
 * $FreeBSD$
 */

#include <dev/aic7xxx/aic7xxx_freebsd.h>

#define	AHC_PCI_IOADDR  PCIR_MAPS	/* I/O Address */
#define	AHC_PCI_MEMADDR (PCIR_MAPS + 4) /* Mem I/O Address */

static int ahc_pci_probe(device_t dev);
static int ahc_pci_attach(device_t dev);

static device_method_t ahc_pci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ahc_pci_probe),
	DEVMETHOD(device_attach,	ahc_pci_attach),
	DEVMETHOD(device_detach,	ahc_detach),
	{ 0, 0 }
};

static driver_t ahc_pci_driver = {
	"ahc",
	ahc_pci_methods,
	sizeof(struct ahc_softc)
};

static devclass_t ahc_devclass;

DRIVER_MODULE(ahc, pci, ahc_pci_driver, ahc_devclass, 0, 0);
DRIVER_MODULE(ahc, cardbus, ahc_pci_driver, ahc_devclass, 0, 0);

static int
ahc_pci_probe(device_t dev)
{
	struct	ahc_pci_identity *entry;

	entry = ahc_find_pci_device(dev);
	if (entry != NULL) {
		device_set_desc(dev, entry->name);
		return (0);
	}
	return (ENXIO);
}

static int
ahc_pci_attach(device_t dev)
{
	struct	 ahc_pci_identity *entry;
	struct	 ahc_softc *ahc;
	char	*name;
	int	 error;

	entry = ahc_find_pci_device(dev);
	if (entry == NULL)
		return (ENXIO);

	/*
	 * Allocate a softc for this card and
	 * set it up for attachment by our
	 * common detect routine.
	 */
	name = malloc(strlen(device_get_nameunit(dev)) + 1, M_DEVBUF, M_NOWAIT);
	if (name == NULL)
		return (ENOMEM);
	strcpy(name, device_get_nameunit(dev));
	ahc = ahc_alloc(dev, name);
	if (ahc == NULL)
		return (ENOMEM);

	/* Allocate a dmatag for our SCB DMA maps */
	/* XXX Should be a child of the PCI bus dma tag */
	error = bus_dma_tag_create(/*parent*/NULL, /*alignment*/1,
				   /*boundary*/0,
				   /*lowaddr*/BUS_SPACE_MAXADDR_32BIT,
				   /*highaddr*/BUS_SPACE_MAXADDR,
				   /*filter*/NULL, /*filterarg*/NULL,
				   /*maxsize*/MAXBSIZE, /*nsegments*/AHC_NSEG,
				   /*maxsegsz*/AHC_MAXTRANSFER_SIZE,
				   /*flags*/BUS_DMA_ALLOCNOW,
				   &ahc->parent_dmat);

	if (error != 0) {
		printf("ahc_pci_attach: Could not allocate DMA tag "
		       "- error %d\n", error);
		ahc_free(ahc);
		return (ENOMEM);
	}
	ahc->dev_softc = dev;
	error = ahc_pci_config(ahc, entry);
	if (error != 0) {
		ahc_free(ahc);
		return (error);
	}

	ahc_attach(ahc);
	return (0);
}

int
ahc_pci_map_registers(struct ahc_softc *ahc)
{
	struct	resource *regs;
	u_int	command;
	int	regs_type;
	int	regs_id;

	command = ahc_pci_read_config(ahc->dev_softc, PCIR_COMMAND, /*bytes*/1);
	regs = NULL;
	regs_type = 0;
	regs_id = 0;
#ifdef AHC_ALLOW_MEMIO
	if ((command & PCIM_CMD_MEMEN) != 0) {

		regs_type = SYS_RES_MEMORY;
		regs_id = AHC_PCI_MEMADDR;
		regs = bus_alloc_resource(ahc->dev_softc, regs_type,
					  &regs_id, 0, ~0, 1, RF_ACTIVE);
		if (regs != NULL) {
			ahc->tag = rman_get_bustag(regs);
			ahc->bsh = rman_get_bushandle(regs);

			/*
			 * Do a quick test to see if memory mapped
			 * I/O is functioning correctly.
			 */
			if (ahc_inb(ahc, HCNTRL) == 0xFF) {
				device_printf(ahc->dev_softc,
				       "PCI Device %d:%d:%d failed memory "
				       "mapped test.  Using PIO.\n",
				       ahc_get_pci_bus(ahc->dev_softc),
				       ahc_get_pci_slot(ahc->dev_softc),
				       ahc_get_pci_function(ahc->dev_softc));
				bus_release_resource(ahc->dev_softc, regs_type,
						     regs_id, regs);
				regs = NULL;
			} else {
				command &= ~PCIM_CMD_PORTEN;
				ahc_pci_write_config(ahc->dev_softc,
						     PCIR_COMMAND,
						     command, /*bytes*/1);
			}
		}
	}
#endif
	if (regs == NULL && (command & PCIM_CMD_PORTEN) != 0) {
		regs_type = SYS_RES_IOPORT;
		regs_id = AHC_PCI_IOADDR;
		regs = bus_alloc_resource(ahc->dev_softc, regs_type,
					  &regs_id, 0, ~0, 1, RF_ACTIVE);
		ahc->tag = rman_get_bustag(regs);
		ahc->bsh = rman_get_bushandle(regs);
		command &= ~PCIM_CMD_MEMEN;
		ahc_pci_write_config(ahc->dev_softc,
				     PCIR_COMMAND,
				     command, /*bytes*/1);
	}
	ahc->platform_data->regs_res_type = regs_type;
	ahc->platform_data->regs_res_id = regs_id;
	ahc->platform_data->regs = regs;
 
	if (regs == NULL) {
		device_printf(ahc->dev_softc,
			      "can't allocate register resources\n");
		return (ENOMEM);
	}
	return (0);
}

int
ahc_pci_map_int(struct ahc_softc *ahc)
{
	int zero;

	zero = 0;
	ahc->platform_data->irq =
	    bus_alloc_resource(ahc->dev_softc, SYS_RES_IRQ, &zero,
			       0, ~0, 1, RF_ACTIVE | RF_SHAREABLE);
	if (ahc->platform_data->irq == NULL)
		return (ENOMEM);
	ahc->platform_data->irq_res_type = SYS_RES_IRQ;
	return (0);
}
