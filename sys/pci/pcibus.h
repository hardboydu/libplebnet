/**************************************************************************
**
**  $FreeBSD$
**
**  Declarations for pci bus driver.
**
**  FreeBSD
**
**-------------------------------------------------------------------------
**
** Copyright (c) 1995 Wolfgang Stanglmeier.  All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
***************************************************************************
*/

#ifndef __PCI_BUS_H__
#define __PCI_BUS_H__	"pl1 95/03/13"

/*-----------------------------------------------------------------
**
**	The following functions are provided by the pci bios.
**	They are used only by the pci configuration.
**
**	pcibus_setup():
**		Probes for a pci system.
**		Sets pci_maxdevice and pci_mechanism.
**
**	pcibus_tag():
**		Creates a handle for pci configuration space access.
**		This handle is given to the read/write functions.
**
**	pcibus_ftag():
**		Creates a modified handle.
**
**	pcibus_read():
**		Read a long word from the pci configuration space.
**		Requires a tag (from pcitag) and the register
**		number (should be a long word alligned one).
**
**	pcibus_write():
**		Writes a long word to the pci configuration space.
**		Requires a tag (from pcitag), the register number
**		(should be a long word alligned one), and a value.
**
**	pcibus_regirq():
**		Register an interrupt handler for a pci device.
**		Requires a tag (from pcitag), the register number
**		(should be a long word alligned one), and a value.
**
**-----------------------------------------------------------------
*/

struct pcibus {
	char     *pb_name;
	void	(*pb_setup )  (void);
	pcici_t (*pb_tag   )  (u_char bus, u_char device, u_char func);
	pcici_t (*pb_ftag  )  (pcici_t tag, u_char func);
	u_long	(*pb_read  )  (pcici_t tag, u_long reg);
	void	(*pb_write )  (pcici_t tag, u_long reg, u_long data);
	unsigned  pb_maxirq;
	int	(*pb_iattach) (int irq, inthand2_t *func, int arg,
			       unsigned *maskptr);
	int	(*pb_idetach) (int irq, inthand2_t *func);
	int	(*pb_imaskinc)(int irq, unsigned *maskptr);
	int	(*pb_imaskexc)(int irq, unsigned *maskptr);
};

#define PCI_MAX_IRQ   (16)

/*
**	The following structure should be generated by the driver
*/

extern struct linker_set pcibus_set;

int pci_register_lkm (struct pci_device *dvp);

#endif
