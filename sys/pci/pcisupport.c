/**************************************************************************
**
**  $Id: pcisupport.c,v 1.16 1995/07/27 22:04:57 se Exp $
**
**  Device driver for DEC/INTEL PCI chipsets.
**
**  FreeBSD
**
**-------------------------------------------------------------------------
**
**  Written for FreeBSD by
**	wolf@cologne.de 	Wolfgang Stanglmeier
**	se@mi.Uni-Koeln.de	Stefan Esser
**
**-------------------------------------------------------------------------
**
** Copyright (c) 1994,1995 Stefan Esser.  All rights reserved.
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

#define __PCISUPPORT_C__     "pl4 95/03/21"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/devconf.h>

#include <machine/cpu.h>

#include <pci/pcivar.h>
#include <pci/pcireg.h>

/*---------------------------------------------------------
**
**	Intel chipsets for 486 / Pentium processor
**
**---------------------------------------------------------
*/

static	char*	chipset_probe (pcici_t tag, pcidi_t type);
static	void	chipset_attach(pcici_t tag, int unit);
static	u_long	chipset_count;

struct pci_device chipset_device = {
	"chip",
	chipset_probe,
	chipset_attach,
	&chipset_count,
	NULL
};

DATA_SET (pcidevice_set, chipset_device);

struct condmsg {
    unsigned char	port;
    unsigned char	mask;
    unsigned char	value;
    char	flags;
    char       *text;
};

static char*
chipset_probe (pcici_t tag, pcidi_t type)
{
	u_long data;
	unsigned	rev;

	switch (type) {
	case 0x04848086:
		rev = (unsigned) pci_conf_read (tag, PCI_CLASS_REG) & 0xff;
		if (rev == 3)
		    return ("Intel 82378ZB PCI-ISA bridge");
		return ("Intel 82378IB PCI-ISA bridge");
	case 0x04838086:
		return ("Intel 82424ZX (Saturn) cache DRAM controller");
	case 0x04828086:
		return ("Intel 82375EB PCI-EISA bridge");
	case 0x04868086:
		return ("Intel 82430ZX (Aries)");
	case 0x04a38086:
		rev = (unsigned) pci_conf_read (tag, PCI_CLASS_REG) & 0xff;
		if (rev == 16 || rev == 17)
		    return ("Intel 82434NX (Neptune) PCI cache memory controller");
		return ("Intel 82434LX (Mercury) PCI cache memory controller");
	case 0x122d8086:
		return ("Intel 82437 (Triton)");
	case 0x122e8086:
		return ("Intel 82371 (Triton)");
	case 0x12308086:
		return ("Intel 82438 (Triton)");
	case 0x04961039:
		return ("SiS 85c496");
	case 0x04061039:
		return ("SiS 85c501");
	case 0x00081039:
		return ("SiS 85c503");
	case 0x06011039:
		return ("SiS 85c601");
	case 0x00011011:
		return ("DEC 21050 PCI-PCI bridge");
	};

	/*
	**	check classes
	*/

	data = pci_conf_read(tag, PCI_CLASS_REG);
	switch (data & (PCI_CLASS_MASK|PCI_SUBCLASS_MASK)) {

	case PCI_CLASS_BRIDGE|PCI_SUBCLASS_BRIDGE_HOST:
		return ("CPU-PCI bridge");
	case PCI_CLASS_BRIDGE|PCI_SUBCLASS_BRIDGE_ISA:
		return ("PCI-ISA bridge");
	case PCI_CLASS_BRIDGE|PCI_SUBCLASS_BRIDGE_EISA:
		return ("PCI-EISA bridge");
	case PCI_CLASS_BRIDGE|PCI_SUBCLASS_BRIDGE_MC:
		return ("PCI-MC bridge");
	case PCI_CLASS_BRIDGE|PCI_SUBCLASS_BRIDGE_PCI:
		return ("PCI-PCI bridge");
	case PCI_CLASS_BRIDGE|PCI_SUBCLASS_BRIDGE_PCMCIA:
		return ("PCI-PCMCIA bridge");
	};
	return ((char*)0);
}

#define M_EQ 0  /* mask and return true if equal */
#define M_NE 1  /* mask and return true if not equal */
#define TRUE 2  /* don't read config, always true */

static const struct condmsg conf82424zx[] =
{
    { 0x00, 0x00, 0x00, TRUE, "\tCPU: " },
    { 0x50, 0xe0, 0x00, M_EQ, "486DX" },
    { 0x50, 0xe0, 0x20, M_EQ, "486SX" },
    { 0x50, 0xe0, 0x40, M_EQ, "486DX2 or 486DX4" },
    { 0x50, 0xe0, 0x80, M_EQ, "Overdrive (writeback)" },

    { 0x00, 0x00, 0x00, TRUE, ", bus=" },
    { 0x50, 0x03, 0x00, M_EQ, "25MHz" },
    { 0x50, 0x03, 0x01, M_EQ, "33MHz" },
    { 0x53, 0x01, 0x01, TRUE, ", CPU->Memory posting "},
    { 0x53, 0x01, 0x00, M_EQ, "OFF" },
    { 0x53, 0x01, 0x01, M_EQ, "ON" },

    { 0x56, 0x30, 0x00, M_NE, "\n\tWarning:" },
    { 0x56, 0x20, 0x00, M_NE, " NO cache parity!" },
    { 0x56, 0x10, 0x00, M_NE, " NO DRAM parity!" },
    { 0x55, 0x04, 0x04, M_EQ, "\n\tWarning: refresh OFF! " },

    { 0x00, 0x00, 0x00, TRUE, "\n\tCache: " },
    { 0x52, 0x01, 0x00, M_EQ, "None" },
    { 0x52, 0xc1, 0x01, M_EQ, "64KB" },
    { 0x52, 0xc1, 0x41, M_EQ, "128KB" },
    { 0x52, 0xc1, 0x81, M_EQ, "256KB" },
    { 0x52, 0xc1, 0xc1, M_EQ, "512KB" },
    { 0x52, 0x03, 0x01, M_EQ, " writethrough" },
    { 0x52, 0x03, 0x03, M_EQ, " writeback" },

    { 0x52, 0x01, 0x01, M_EQ, ", cache clocks=" },
    { 0x52, 0x05, 0x01, M_EQ, "3-1-1-1" },
    { 0x52, 0x05, 0x05, M_EQ, "2-1-1-1" },

    { 0x00, 0x00, 0x00, TRUE, "\n\tDRAM:" },
    { 0x55, 0x43, 0x00, M_NE, " page mode" },
    { 0x55, 0x02, 0x02, M_EQ, " code fetch" },
    { 0x55, 0x43, 0x43, M_EQ, "," },
    { 0x55, 0x43, 0x42, M_EQ, " and" },
    { 0x55, 0x40, 0x40, M_EQ, " read" },
    { 0x55, 0x03, 0x03, M_EQ, " and" },
    { 0x55, 0x43, 0x41, M_EQ, " and" },
    { 0x55, 0x01, 0x01, M_EQ, " write" },
    { 0x55, 0x43, 0x00, M_NE, "," },

    { 0x00, 0x00, 0x00, TRUE, " memory clocks=" },
    { 0x55, 0x20, 0x00, M_EQ, "X-2-2-2" },
    { 0x55, 0x20, 0x20, M_EQ, "X-1-2-1" },

    { 0x00, 0x00, 0x00, TRUE, "\n\tCPU->PCI: posting " },
    { 0x53, 0x02, 0x00, M_NE, "ON" },
    { 0x53, 0x02, 0x00, M_EQ, "OFF" },
    { 0x00, 0x00, 0x00, TRUE, ", burst mode " },
    { 0x54, 0x02, 0x00, M_NE, "ON" },
    { 0x54, 0x02, 0x00, M_EQ, "OFF" },
    { 0x00, 0x00, 0x00, TRUE, "\n\tPCI->Memory: posting " },
    { 0x54, 0x01, 0x00, M_NE, "ON" },
    { 0x54, 0x01, 0x00, M_EQ, "OFF" },

    { 0x00, 0x00, 0x00, TRUE, "\n" },

/* end marker */
    { 0 }
};

static const struct condmsg conf82434lx[] =
{
    { 0x00, 0x00, 0x00, TRUE, "\tCPU: " },
    { 0x50, 0xe3, 0x82, M_EQ, "Pentium, 60MHz" },
    { 0x50, 0xe3, 0x83, M_EQ, "Pentium, 66MHz" },
    { 0x50, 0xe3, 0xa2, M_EQ, "Pentium, 90MHz" },
    { 0x50, 0xe3, 0xa3, M_EQ, "Pentium, 100MHz" },
    { 0x50, 0xc2, 0x82, M_NE, "(unknown)" },
    { 0x50, 0x04, 0x00, M_EQ, " (primary cache OFF)" },

    { 0x53, 0x01, 0x01, TRUE, ", CPU->Memory posting "},
    { 0x53, 0x01, 0x01, M_NE, "OFF" },
    { 0x53, 0x01, 0x01, M_EQ, "ON" },

    { 0x53, 0x08, 0x00, M_NE, ", read around write"},

    { 0x70, 0x04, 0x00, M_EQ, "\n\tWarning: Cache parity disabled!" },
    { 0x57, 0x20, 0x00, M_NE, "\n\tWarning: DRAM parity mask!" },
    { 0x57, 0x01, 0x00, M_EQ, "\n\tWarning: refresh OFF! " },

    { 0x00, 0x00, 0x00, TRUE, "\n\tCache: " },
    { 0x52, 0x01, 0x00, M_EQ, "None" },
    { 0x52, 0x81, 0x01, M_EQ, "" },
    { 0x52, 0xc1, 0x81, M_EQ, "256KB" },
    { 0x52, 0xc1, 0xc1, M_EQ, "512KB" },
    { 0x52, 0x03, 0x01, M_EQ, " writethrough" },
    { 0x52, 0x03, 0x03, M_EQ, " writeback" },

    { 0x52, 0x01, 0x01, M_EQ, ", cache clocks=" },
    { 0x52, 0x21, 0x01, M_EQ, "3-2-2-2/4-2-2-2" },
    { 0x52, 0x21, 0x21, M_EQ, "3-1-1-1" },

    { 0x52, 0x01, 0x01, M_EQ, "\n\tCache flags: " },
    { 0x52, 0x11, 0x11, M_EQ, " cache-all" },
    { 0x52, 0x09, 0x09, M_EQ, " byte-control" },
    { 0x52, 0x05, 0x05, M_EQ, " powersaver" },

    { 0x00, 0x00, 0x00, TRUE, "\n\tDRAM:" },
    { 0x57, 0x10, 0x00, M_EQ, " page mode" },

    { 0x00, 0x00, 0x00, TRUE, " memory clocks=" },
    { 0x57, 0xc0, 0x00, M_EQ, "X-4-4-4 (70ns)" },
    { 0x57, 0xc0, 0x40, M_EQ, "X-4-4-4/X-3-3-3 (60ns)" },
    { 0x57, 0xc0, 0x80, M_EQ, "???" },
    { 0x57, 0xc0, 0xc0, M_EQ, "X-3-3-3 (50ns)" },
    { 0x58, 0x02, 0x02, M_EQ, ", RAS-wait" },
    { 0x58, 0x01, 0x01, M_EQ, ", CAS-wait" },

    { 0x00, 0x00, 0x00, TRUE, "\n\tCPU->PCI: posting " },
    { 0x53, 0x02, 0x02, M_EQ, "ON" },
    { 0x53, 0x02, 0x00, M_EQ, "OFF" },
    { 0x00, 0x00, 0x00, TRUE, ", burst mode " },
    { 0x54, 0x02, 0x00, M_NE, "ON" },
    { 0x54, 0x02, 0x00, M_EQ, "OFF" },
    { 0x54, 0x04, 0x00, TRUE, ", PCI clocks=" },
    { 0x54, 0x04, 0x00, M_EQ, "2-2-2-2" },
    { 0x54, 0x04, 0x00, M_NE, "2-1-1-1" },
    { 0x00, 0x00, 0x00, TRUE, "\n\tPCI->Memory: posting " },
    { 0x54, 0x01, 0x00, M_NE, "ON" },
    { 0x54, 0x01, 0x00, M_EQ, "OFF" },

    { 0x00, 0x00, 0x00, TRUE, "\n" },

/* end marker */
    { 0 }
};

static const struct condmsg conf82378[] =
{
    { 0x4d, 0x20, 0x20, M_EQ, "\tCoprocessor errors enabled" },
    { 0x4d, 0x10, 0x10, M_EQ, "\tMouse function enabled" },

    { 0x4e, 0x30, 0x10, M_EQ, "\n\tIDE controller: Primary (1F0h-1F7h,3F6h,3F7h)" },
    { 0x4e, 0x30, 0x30, M_EQ, "\n\tIDE controller: Secondary (170h-177h,376h,377h)" },
    { 0x4e, 0x28, 0x08, M_EQ, "\n\tFloppy controller: 3F0h,3F1h " },
    { 0x4e, 0x24, 0x04, M_EQ, "\n\tFloppy controller: 3F2h-3F7h " },
    { 0x4e, 0x28, 0x28, M_EQ, "\n\tFloppy controller: 370h,371h " },
    { 0x4e, 0x24, 0x24, M_EQ, "\n\tFloppy controller: 372h-377h " },
    { 0x4e, 0x02, 0x02, M_EQ, "\n\tKeyboard controller: 60h,62h,64h,66h" },
    { 0x4e, 0x01, 0x01, M_EQ, "\n\tRTC: 70h-77h" },

    { 0x4f, 0x80, 0x80, M_EQ, "\n\tConfiguration RAM: 0C00h,0800h-08FFh" },
    { 0x4f, 0x40, 0x40, M_EQ, "\n\tPort 92: enabled" },
    { 0x4f, 0x03, 0x00, M_EQ, "\n\tSerial Port A: COM1 (3F8h-3FFh)" },
    { 0x4f, 0x03, 0x01, M_EQ, "\n\tSerial Port A: COM2 (2F8h-2FFh)" },
    { 0x4f, 0x0c, 0x00, M_EQ, "\n\tSerial Port B: COM1 (3F8h-3FFh)" },
    { 0x4f, 0x0c, 0x04, M_EQ, "\n\tSerial Port B: COM2 (2F8h-2FFh)" },
    { 0x4f, 0x30, 0x00, M_EQ, "\n\tParallel Port: LPT1 (3BCh-3BFh)" },
    { 0x4f, 0x30, 0x04, M_EQ, "\n\tParallel Port: LPT2 (378h-37Fh)" },
    { 0x4f, 0x30, 0x20, M_EQ, "\n\tParallel Port: LPT3 (278h-27Fh)" },
    { 0x00, 0x00, 0x00, TRUE, "\n" },

/* end marker */
    { 0 }
};

static char confread (pcici_t config_id, int port)
{
    unsigned long portw = port & ~3;
    unsigned long ports = (port - portw) << 3;

    unsigned long l = pci_conf_read (config_id, portw);
    return (l >> ports);
}

static void
writeconfig (pcici_t config_id, const struct condmsg *tbl)
{
    while (tbl->text) {
	int cond = 0;
	if (tbl->flags == TRUE) {
	    cond = 1;
	} else {
	    unsigned char v = (unsigned char) confread(config_id, tbl->port);
	    switch (tbl->flags) {
    case M_EQ:
		if ((v & tbl->mask) == tbl->value) cond = 1;
		break;
    case M_NE:
		if ((v & tbl->mask) != tbl->value) cond = 1;
		break;
	    }
	}
	if (cond) printf ("%s", tbl->text);
	tbl++;
    }
}

static void
chipset_attach (pcici_t config_id, int unit)
{
	if (!bootverbose)
		return;

	switch (pci_conf_read (config_id, PCI_ID_REG)) {

	case 0x04838086:
		writeconfig (config_id, conf82424zx);
		break;
	case 0x04a38086:
		writeconfig (config_id, conf82434lx);
		break;
	case 0x04848086:
		writeconfig (config_id, conf82378);
		break;
	case 0x04828086:
		printf ("\t[40] %lx [50] %lx [54] %lx\n",
			pci_conf_read (config_id, 0x40),
			pci_conf_read (config_id, 0x50),
			pci_conf_read (config_id, 0x54));
		break;
	};
}

/*---------------------------------------------------------
**
**	Catchall driver for VGA devices
**
**	By Garrett Wollman
**	<wollman@halloran-eldar.lcs.mit.edu>
**
**---------------------------------------------------------
*/

static	char*	vga_probe  (pcici_t tag, pcidi_t type);
static	void	vga_attach (pcici_t tag, int unit);
static	u_long	vga_count;

struct pci_device vga_device = {
	"vga",
	vga_probe,
	vga_attach,
	&vga_count,
	NULL
};

DATA_SET (pcidevice_set, vga_device);

static char* vga_probe (pcici_t tag, pcidi_t type)
{
	int data = pci_conf_read(tag, PCI_CLASS_REG);

	switch (data & PCI_CLASS_MASK) {

	case PCI_CLASS_PREHISTORIC:
		if ((data & PCI_SUBCLASS_MASK)
			!= PCI_SUBCLASS_PREHISTORIC_VGA)
			break;

	case PCI_CLASS_DISPLAY:
		if ((data & PCI_SUBCLASS_MASK)
		    == PCI_SUBCLASS_DISPLAY_VGA)
			return "VGA-compatible display device";
		else
			return ("Display device");
	};
	return ((char*)0);
}

static void vga_attach (pcici_t tag, int unit)
{
/*
**	If the assigned addresses are remapped,
**	the console driver has to be informed about the new address.
*/
#if 0
	vm_offset_t va;
	vm_offset_t pa;
	int reg;
	for (reg = PCI_MAP_REG_START; reg < PCI_MAP_REG_END; reg += 4)
		(void) pci_map_mem (tag, reg, &va, &pa);
#endif
}

/*---------------------------------------------------------
**
**	Hook for loadable pci drivers
**
**---------------------------------------------------------
*/

static	char*	lkm_probe  (pcici_t tag, pcidi_t type);
static	void	lkm_attach (pcici_t tag, int unit);
static	u_long	lkm_count;

struct pci_device lkm_device = {
	"lkm",
	lkm_probe,
	lkm_attach,
	&lkm_count,
	NULL
};

DATA_SET (pcidevice_set, lkm_device);

static char*
lkm_probe (pcici_t tag, pcidi_t type)
{
	/*
	**	Not yet!
	**	(Should try to load a matching driver)
	*/
	return ((char*)0);
}

static void
lkm_attach (pcici_t tag, int unit)
{}

/*---------------------------------------------------------
**
**	Devices to ignore
**
**---------------------------------------------------------
*/

static	char*	ign_probe  (pcici_t tag, pcidi_t type);
static	void	ign_attach (pcici_t tag, int unit);
static	u_long	ign_count;

struct pci_device ign_device = {
	NULL,
	ign_probe,
	ign_attach,
	&ign_count,
	NULL
};

DATA_SET (pcidevice_set, ign_device);

static char*
ign_probe (pcici_t tag, pcidi_t type)
{
	switch (type) {

	case 0x10001042ul:	/* wd */
		return ("");
/*		return ("SMC FDC 37c665");*/
	};
	return ((char*)0);
}

static void
ign_attach (pcici_t tag, int unit)
{}
