/*
 * Copyright (c) 1997 Ted Faber
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Absolutely no warranty of function or purpose is made by the author
 *    Ted Faber.
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
 * $Id: pcic_p.c,v 1.9 1999/04/01 15:28:09 nsayer Exp $
 */

#include "pci.h"
#if NPCI > 0

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <pci/pcireg.h>
#include <pci/pcivar.h>
#include <pci/pcic_p.h>
#include <pccard/i82365.h>
#include <vm/vm.h>
#include <vm/pmap.h>

static u_long pcic_pci_count = 0;

static const char *pcic_pci_probe(pcici_t, pcidi_t);
static void  pcic_pci_attach(pcici_t, int);

static void  pd6832_legacy_init(pcici_t tag, int unit);

static struct pci_device pcic_pci_driver = {
	"pcic",
	pcic_pci_probe,
	pcic_pci_attach,
	&pcic_pci_count,
	NULL
};

#ifdef COMPAT_PCI_DRIVER
COMPAT_PCI_DRIVER(pcic_pci, pcic_pci_driver);
#else
DATA_SET(pcidevice_set, pcic_pci_driver);
#endif /* COMPAT_PCI_DRIVER */

/*
 * Return the ID string for the controller if the vendor/product id
 * matches, NULL otherwise.
 */
static const char *
pcic_pci_probe(pcici_t tag, pcidi_t type)
{
	switch (type) {
	case PCI_DEVICE_ID_PCIC_CLPD6832:
		return ("Cirrus Logic PD6832 PCI/CardBus Bridge");
	case PCI_DEVICE_ID_PCIC_TI1130:
		return ("TI PCI-1130 PCI-CardBus Bridge");
	case PCI_DEVICE_ID_PCIC_TI1131:
		return ("TI PCI-1131 PCI-CardBus Bridge");
	case PCI_DEVICE_ID_PCIC_TI1220:
		return ("TI PCI-1220 PCI-CardBus Bridge");
	case PCI_DEVICE_ID_PCIC_TI1221:
		return ("TI PCI-1221 PCI-CardBus Bridge");
	case PCI_DEVICE_ID_PCIC_TI1250:
		return ("TI PCI-1250 PCI-CardBus Bridge");
	case PCI_DEVICE_ID_TOSHIBA_TOPIC95:
		return ("Toshiba ToPIC95 PCI-CardBus Bridge");
	case PCI_DEVICE_ID_TOSHIBA_TOPIC97:
		return ("Toshiba ToPIC97 PCI-CardBus Bridge");
 	case PCI_DEVICE_ID_RICOH_RL5C465:
		return ("Ricoh RL5C465 PCI-CardBus Brige");
	case PCI_DEVICE_ID_RICOH_RL5C475:
		return ("Ricoh RL5C475 PCI-CardBus Brige");
	case PCI_DEVICE_ID_RICOH_RL5C476:
		return ("Ricoh RL5C476 PCI-CardBus Brige");
	case PCI_DEVICE_ID_RICOH_RL5C478:
		return ("Ricoh RL5C478 PCI-CardBus Brige");
	/* 16bit PC-card bridges */
	case PCI_DEVICE_ID_PCIC_CLPD6729:
		return ("Cirrus Logic PD6729/6730 PC-Card Controller");
	case PCI_DEVICE_ID_PCIC_OZ6729:
		return ("O2micro OZ6729 PC-Card Bridge");
	case PCI_DEVICE_ID_PCIC_OZ6730:
		return ("O2micro OZ6730 PC-Card Bridge");

	default:
		break;
	}
	return (NULL);
}


/*
 * General PCI based card dispatch routine.  Right now
 * it only understands the CL-PD6832.
 */
static void
pcic_pci_attach(pcici_t config_id, int unit)
{
	u_long pcic_type;	/* The vendor id of the PCI pcic */

	pcic_type = pci_conf_read(config_id, PCI_ID_REG);

	switch (pcic_type) { 
	case PCI_DEVICE_ID_PCIC_CLPD6832:
		pd6832_legacy_init(config_id, unit);
		break;
	}

	if (bootverbose) { 		
		int i, j;
		u_char *p;
		u_long *pl;

		printf("PCI Config space:\n");
		for (j = 0; j < 0x98; j += 16) {
			printf("%02x: ", j);
			for (i = 0; i < 16; i += 4)
				printf(" %08lx", pci_conf_read(config_id, i+j));
			printf("\n");
		}
		p = (u_char *)pmap_mapdev(pci_conf_read(config_id, 0x10),
					  0x1000);
		pl = (u_long *)p;
		printf("Cardbus Socket registers:\n");
		printf("00: ");
		for (i = 0; i < 4; i += 1)
			printf(" %08lx:", pl[i]);
		printf("\n10: ");
		for (i = 4; i < 8; i += 1)
			printf(" %08lx:", pl[i]);
		printf("\nExCa registers:\n");
		for (i = 0; i < 0x40; i += 16)
			printf("%02x: %16D\n", i, p + 0x800 + i, " ");
	}
}

/*
 * Set up the CL-PD6832 to look like a ISA based PCMCIA chip (a
 * PD672X).  This routine is called once per PCMCIA socket.
 */
static void
pd6832_legacy_init(pcici_t tag, int unit)
{
	u_long bcr; 		/* to set interrupts */
	u_short io_port;	/* the io_port to map this slot on */
	static int num6832 = 0; /* The number of 6832s initialized */

	/*
	 * Some BIOS leave the legacy address uninitialized.  This
	 * insures that the PD6832 puts itself where the driver will
	 * look.  We assume that multiple 6832's should be laid out
	 * sequentially.  We only initialize the first socket's legacy port,
	 * the other is a dummy.
	 */
	io_port = PCIC_INDEX_0 + num6832 * CLPD6832_NUM_REGS;
	if (unit == 0)
	    pci_conf_write(tag, CLPD6832_LEGACY_16BIT_IOADDR,
		           io_port & ~PCI_MAP_IO);

	/*
	 * I think this should be a call to pci_map_port, but that
	 * routine won't map regiaters above 0x28, and the register we
	 * need to map is 0x44.
	 */
	io_port = pci_conf_read(tag, CLPD6832_LEGACY_16BIT_IOADDR)
	    & ~PCI_MAP_IO;

	/*
	 * Configure the first I/O window to contain CLPD6832_NUM_REGS
	 * words and deactivate the second by setting the limit lower
	 * than the base.
	 */
	pci_conf_write(tag, CLPD6832_IO_BASE0, io_port | 1);
	pci_conf_write(tag, CLPD6832_IO_LIMIT0,
		       (io_port + CLPD6832_NUM_REGS) | 1);

	pci_conf_write(tag, CLPD6832_IO_BASE1, (io_port + 0x20) | 1);
	pci_conf_write(tag, CLPD6832_IO_LIMIT1, io_port | 1 );

	/*
	 * Set default operating mode (I/O port space) and allocate
	 * this socket to the current unit.
	 */
	pci_conf_write(tag, PCI_COMMAND_STATUS_REG, CLPD6832_COMMAND_DEFAULTS );
	pci_conf_write(tag, CLPD6832_SOCKET, unit);

	/*
	 * Set up the card inserted/card removed interrupts to come
	 * through the isa IRQ.
	 */
	bcr = pci_conf_read(tag, CLPD6832_BRIDGE_CONTROL);
	bcr |= (CLPD6832_BCR_ISA_IRQ|CLPD6832_BCR_MGMT_IRQ_ENA);
	pci_conf_write(tag, CLPD6832_BRIDGE_CONTROL, bcr);

	/* After initializing 2 sockets, the chip is fully configured */
	if (unit == 1)
		num6832++;

	if (bootverbose)
		printf("CardBus: Legacy PC-card 16bit I/O address [0x%x]\n",
		       io_port);
}
#endif /* NPCI > 0 */
