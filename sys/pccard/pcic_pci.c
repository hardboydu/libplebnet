/*
 * Copyright (c) 2001 M. Warner Losh.  All Rights Reserved.
 * Copyright (c) 1997 Ted Faber All rights reserved.
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
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#if __FreeBSD_version < 500000
#include <pci/pcireg.h>
#include <pci/pcivar.h>
#else
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#endif

#include <pccard/pcic_pci.h>
#include <pccard/i82365.h>
#include <pccard/cardinfo.h>
#include <pccard/slot.h>
#include <pccard/pcicvar.h>

#include <dev/pccard/pccardvar.h>
#include "card_if.h"

#define PRVERB(x)	do { \
				if (bootverbose) { device_printf x; } \
			} while (0)

static int pcic_pci_get_memory(device_t dev);

SYSCTL_DECL(_hw_pcic);

static int pcic_ignore_function_1 = 0;
TUNABLE_INT("hw.pcic.ignore_function_1", &pcic_ignore_function_1);
SYSCTL_INT(_hw_pcic, OID_AUTO, ignore_function_1, CTLFLAG_RD,
    &pcic_ignore_function_1, 0,
    "When set, driver ignores pci function 1 of the bridge");

/*
 * The following should be a hint, so we can do it on a per device
 * instance, but this is convenient.  Do not set this unless pci
 * routing doesn't work.  It is purposely vague and undocumented
 * at the moment.
 */
static int pcic_intr_path = (int)pcic_iw_pci;
TUNABLE_INT("hw.pcic.intr_path", &pcic_intr_path);
SYSCTL_INT(_hw_pcic, OID_AUTO, intr_path, CTLFLAG_RD, &pcic_intr_path, 0,
    "Which path to send the interrupts over.");

static int pcic_init_routing = 0;
TUNABLE_INT("hw.pcic.init_routing", &pcic_init_routing);
SYSCTL_INT(_hw_pcic, OID_AUTO, init_routing, CTLFLAG_RD,
    &pcic_init_routing, 0,
    "Force the interrupt routing to be initialized on those bridges where\n\
doing so will cause probelms.  Often when no interrupts appear to be routed\n\
setting this tunable to 1 will resolve the problem.  PCI Cards will almost\n\
always require this, while builtin bridges need it less often");

static void pcic_pci_cardbus_init(device_t);
static pcic_intr_mapirq_t pcic_pci_gen_mapirq;

static pcic_intr_way_t pcic_pci_oz67xx_func;
static pcic_intr_way_t pcic_pci_oz67xx_csc;
static pcic_init_t pcic_pci_oz67xx_init;

static pcic_intr_way_t pcic_pci_oz68xx_func;
static pcic_intr_way_t pcic_pci_oz68xx_csc;
static pcic_init_t pcic_pci_oz68xx_init;

static pcic_intr_way_t pcic_pci_pd67xx_func;
static pcic_intr_way_t pcic_pci_pd67xx_csc;
static pcic_init_t pcic_pci_pd67xx_init;

static pcic_intr_way_t pcic_pci_pd68xx_func;
static pcic_intr_way_t pcic_pci_pd68xx_csc;
static pcic_init_t pcic_pci_pd68xx_init;

static pcic_intr_way_t pcic_pci_ricoh_func;
static pcic_intr_way_t pcic_pci_ricoh_csc;
static pcic_init_t pcic_pci_ricoh_init;

static pcic_intr_way_t pcic_pci_ti113x_func;
static pcic_intr_way_t pcic_pci_ti113x_csc;
static pcic_init_t pcic_pci_ti_init;

static pcic_intr_way_t pcic_pci_ti12xx_func;
static pcic_intr_way_t pcic_pci_ti12xx_csc;

static pcic_intr_way_t pcic_pci_topic_func;
static pcic_intr_way_t pcic_pci_topic_csc;
static pcic_init_t pcic_pci_topic_init;

static struct pcic_chip pcic_pci_oz67xx_chip = {
	pcic_pci_oz67xx_func,
	pcic_pci_oz67xx_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_oz67xx_init
};

static struct pcic_chip pcic_pci_oz68xx_chip = {
	pcic_pci_oz68xx_func,
	pcic_pci_oz68xx_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_oz68xx_init
};

static struct pcic_chip pcic_pci_pd67xx_chip = {
	pcic_pci_pd67xx_func,
	pcic_pci_pd67xx_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_pd67xx_init
};

static struct pcic_chip pcic_pci_pd68xx_chip = {
	pcic_pci_pd68xx_func,
	pcic_pci_pd68xx_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_pd68xx_init
};

static struct pcic_chip pcic_pci_ricoh_chip = {
	pcic_pci_ricoh_func,
	pcic_pci_ricoh_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_ricoh_init
};

static struct pcic_chip pcic_pci_ti113x_chip = {
	pcic_pci_ti113x_func,
	pcic_pci_ti113x_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_ti_init
};

static struct pcic_chip pcic_pci_ti12xx_chip = {
	pcic_pci_ti12xx_func,
	pcic_pci_ti12xx_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_ti_init
};

static struct pcic_chip pcic_pci_topic_chip = {
	pcic_pci_topic_func,
	pcic_pci_topic_csc,
	pcic_pci_gen_mapirq,
	pcic_pci_topic_init
};

struct pcic_pci_table
{
	u_int32_t	devid;
	const char	*descr;
	int		type;
	u_int32_t	flags;
	struct pcic_chip *chip;
} pcic_pci_devs[] = {
	{ PCI_DEVICE_ID_PCIC_CLPD6729,
	  "Cirrus Logic PD6729/6730 PC-Card Controller",
	  PCIC_PD672X, PCIC_PD_POWER, &pcic_pci_pd67xx_chip },
	{ PCI_DEVICE_ID_PCIC_CLPD6832,
	  "Cirrus Logic PD6832 PCI-CardBus Bridge",
	  PCIC_PD672X, PCIC_PD_POWER, &pcic_pci_pd68xx_chip },
	{ PCI_DEVICE_ID_PCIC_CLPD6833,
	  "Cirrus Logic PD6833 PCI-CardBus Bridge",
	  PCIC_PD672X, PCIC_PD_POWER, &pcic_pci_pd68xx_chip },
	{ PCI_DEVICE_ID_PCIC_OZ6729,
	  "O2micro OZ6729 PC-Card Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_oz67xx_chip },
	{ PCI_DEVICE_ID_PCIC_OZ6730,
	  "O2micro OZ6730 PC-Card Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_oz67xx_chip },
	{ PCI_DEVICE_ID_PCIC_OZ6832,
	  "O2micro 6832/6833 PCI-Cardbus Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_oz68xx_chip },
	{ PCI_DEVICE_ID_PCIC_OZ6860,
	  "O2micro 6860/6836 PCI-Cardbus Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_oz68xx_chip },
	{ PCI_DEVICE_ID_PCIC_OZ6872,
	  "O2micro 6812/6872 PCI-Cardbus Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_oz68xx_chip },
	{ PCI_DEVICE_ID_RICOH_RL5C465,
	  "Ricoh RL5C465 PCI-CardBus Bridge",
	  PCIC_RF5C296, PCIC_RICOH_POWER, &pcic_pci_ricoh_chip },
	{ PCI_DEVICE_ID_RICOH_RL5C475,
	  "Ricoh RL5C475 PCI-CardBus Bridge",
	  PCIC_RF5C296, PCIC_RICOH_POWER, &pcic_pci_ricoh_chip },
	{ PCI_DEVICE_ID_RICOH_RL5C476,
	  "Ricoh RL5C476 PCI-CardBus Bridge",
	  PCIC_RF5C296, PCIC_RICOH_POWER, &pcic_pci_ricoh_chip },
	{ PCI_DEVICE_ID_RICOH_RL5C477,
	  "Ricoh RL5C477 PCI-CardBus Bridge",
	  PCIC_RF5C296, PCIC_RICOH_POWER, &pcic_pci_ricoh_chip },
	{ PCI_DEVICE_ID_RICOH_RL5C478,
	  "Ricoh RL5C478 PCI-CardBus Bridge",
	  PCIC_RF5C296, PCIC_RICOH_POWER, &pcic_pci_ricoh_chip },
	{ PCI_DEVICE_ID_PCIC_TI1031,
	  "TI PCI-1031 PCI-PCMCIA Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti113x_chip },
	{ PCI_DEVICE_ID_PCIC_TI1130,
	  "TI PCI-1130 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti113x_chip },
	{ PCI_DEVICE_ID_PCIC_TI1131,
	  "TI PCI-1131 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti113x_chip },
	{ PCI_DEVICE_ID_PCIC_TI1210,
	  "TI PCI-1210 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1211,
	  "TI PCI-1211 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1220,
	  "TI PCI-1220 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1221,
	  "TI PCI-1221 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1225,
	  "TI PCI-1225 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1250,
	  "TI PCI-1250 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1251,
	  "TI PCI-1251 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1251B,
	  "TI PCI-1251B PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1410,
	  "TI PCI-1410 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1420,
	  "TI PCI-1420 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1450,
	  "TI PCI-1450 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI1451,
	  "TI PCI-1451 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI4410,
	  "TI PCI-4410 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI4450,
	  "TI PCI-4450 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_PCIC_TI4451,
	  "TI PCI-4451 PCI-CardBus Bridge",
	  PCIC_I82365SL_DF, PCIC_DF_POWER, &pcic_pci_ti12xx_chip },
	{ PCI_DEVICE_ID_TOSHIBA_TOPIC95,
	  "Toshiba ToPIC95 PCI-CardBus Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_topic_chip },
	{ PCI_DEVICE_ID_TOSHIBA_TOPIC95B,
	  "Toshiba ToPIC95B PCI-CardBus Bridge",
	  PCIC_I82365, PCIC_AB_POWER, &pcic_pci_topic_chip },
	{ PCI_DEVICE_ID_TOSHIBA_TOPIC97,
	  "Toshiba ToPIC97 PCI-CardBus Bridge",
	  PCIC_I82365, PCIC_DF_POWER, &pcic_pci_topic_chip },
	{ PCI_DEVICE_ID_TOSHIBA_TOPIC100,
	  "Toshiba ToPIC100 PCI-CardBus Bridge",
	  PCIC_I82365, PCIC_DF_POWER, &pcic_pci_topic_chip },
	{ 0, NULL, 0, 0, NULL }
};

/*
 * Read a register from the PCIC.
 */
static unsigned char
pcic_pci_getb2(struct pcic_slot *sp, int reg)
{
	return (bus_space_read_1(sp->bst, sp->bsh, sp->offset + reg));
}

/*
 * Write a register on the PCIC
 */
static void
pcic_pci_putb2(struct pcic_slot *sp, int reg, unsigned char val)
{
	bus_space_write_1(sp->bst, sp->bsh, sp->offset + reg, val);
}

/*
 * lookup inside the table
 */
static struct pcic_pci_table *
pcic_pci_lookup(u_int32_t devid, struct pcic_pci_table *tbl)
{
	while (tbl->devid) {
		if (tbl->devid == devid)
			return (tbl);
		tbl++;
	}
	return (NULL);
}

/*
 * The standard way to control fuction interrupts is via bit 7 in the BCR
 * register.  Some data sheets indicate that this is just for "intterupts"
 * while others are clear that it is for function interrupts.  When this
 * bit is set, function interrupts are routed via the ExCA register.  When
 * this bit is clear, they are routed via the PCI bus, usually via the int
 * in the INTPIN register.
 */
static int
pcic_pci_gen_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	u_int16_t bcr;
	
	bcr = pci_read_config(sp->sc->dev, CB_PCI_BRIDGE_CTRL, 2);
	if (way == pcic_iw_pci)
		bcr &= ~CB_BCR_INT_EXCA;
	else
		bcr |= CB_BCR_INT_EXCA;
	pci_write_config(sp->sc->dev, CB_PCI_BRIDGE_CTRL, bcr, 2);
	return (0);
}


/*
 * The O2micro OZ67xx chips functions.
 */
static int
pcic_pci_oz67xx_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_oz67xx_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	/*
	 * Need datasheet to find out what's going on.  However, the
	 * 68xx datasheets are so vague that it is hard to know what
	 * the right thing to do is.
	 */
	/* XXX */
	return (0);
}


static void
pcic_pci_oz67xx_init(device_t dev)
{
	device_printf(dev, "Warning: O2micro OZ67xx chips may not work\n");
	pcic_pci_cardbus_init(dev);
}

/*
 * The O2micro OZ68xx chips functions.
 */
static int
pcic_pci_oz68xx_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_oz68xx_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	/*
	 * The 68xx datasheets make it hard to know what the right thing
	 * do do here is.  We do hwat we knjow, which is nothing, and
	 * hope for the best.
	 */
	/* XXX */
	return (0);
}

static void
pcic_pci_oz68xx_init(device_t dev)
{
	/*
	 * This is almost certainly incomplete.
	 */
	device_printf(dev, "Warning: O2micro OZ68xx chips may not work\n");
	pcic_pci_cardbus_init(dev);
}

/*
 * The Cirrus Logic PD6729/30.  These are weird beasts, so be careful.
 */
static int
pcic_pci_pd67xx_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	/*
	 * We're only supporting ISA interrupts, so do nothing for the
	 * moment.
	 */
	/* XXX */
	return (0);
}

static int
pcic_pci_pd67xx_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	/*
	 * We're only supporting ISA interrupts, so do nothing for the
	 * moment.
	 */
	/* XXX */
	return (0);
}


static void
pcic_pci_pd67xx_init(device_t dev)
{
	struct pcic_softc *sc = device_get_softc(dev);

	if (sc->csc_route == pcic_iw_pci || sc->func_route == pcic_iw_pci)
		device_printf(dev, "CL-PD67xx broken for PCI routing.\n");
}

/*
 * Set up the CL-PD6832 and 6833.
 */
static int
pcic_pci_pd68xx_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_pd68xx_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	struct pcic_softc *sc = sp->sc;
	device_t	dev = sc->dev;
	u_int32_t	device_id = pci_get_devid(dev);
	u_long bcr;
	u_long cm1;

	/*
	 * CLPD6832 management interrupt enable bit is bit 11
	 * (MGMT_IRQ_ENA) in bridge control register(offset 0x3d).
	 * When on, card status interrupts are ISA controlled by
	 * the ExCA register 0x05.
	 *
	 * The CLPD6833 does things differently.  It doesn't have bit
	 * 11 in the bridge control register.  Instead, this
	 * functionality appears to be in the "Configuration
	 * Miscellaneous 1" register bit 1.
	 */
	if (device_id == PCI_DEVICE_ID_PCIC_CLPD6832) {
		bcr = pci_read_config(dev, CB_PCI_BRIDGE_CTRL, 2);
		if (way == pcic_iw_pci)
			bcr &= ~CLPD6832_BCR_MGMT_IRQ_ENA;
		else
			bcr |= CLPD6832_BCR_MGMT_IRQ_ENA;
		pci_write_config(dev, CB_PCI_BRIDGE_CTRL, bcr, 2);
	}
	if (device_id == PCI_DEVICE_ID_PCIC_CLPD6833) {
		cm1 = pci_read_config(dev, CLPD6833_CFG_MISC_1, 4);
		if (way == pcic_iw_pci)
			cm1 &= ~CLPD6833_CM1_MGMT_EXCA_ENA;
		else
			cm1 |= CLPD6833_CM1_MGMT_EXCA_ENA;
		pci_write_config(dev, CLPD6833_CFG_MISC_1, cm1, 4);
	}
	return (0);
}

static void
pcic_pci_pd68xx_init(device_t dev)
{
	pcic_pci_cardbus_init(dev);
}

static int
pcic_pci_ricoh_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_ricoh_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	struct pcic_softc *sc = sp->sc;
	device_t	dev = sc->dev;
	u_int16_t	mcr2;

	/*
	 * For CSC interrupts via ISA, we can't do that exactly.
	 * However, we can disable INT# routing, which is usually what
	 * we want.  This is bit 7 in the field.  Note, bit 6 looks
	 * interesting, but appears to be unnecessary.
	 */
	mcr2 = pci_read_config(dev, R5C47X_MISC_CONTROL_REGISTER_2, 2);
	if (way == pcic_iw_pci)
		mcr2 &= ~R5C47X_MCR2_CSC_TO_INTX_DISABLE;
	else
		mcr2 |= R5C47X_MCR2_CSC_TO_INTX_DISABLE;
	pci_write_config(dev,  R5C47X_MISC_CONTROL_REGISTER_2, mcr2, 2);

	return (0);
}

static void
pcic_pci_ricoh_init(device_t dev)
{
	u_int16_t	brgcntl;
	u_int32_t	device_id = pci_get_devid(dev);

	switch (device_id) {
	case PCI_DEVICE_ID_RICOH_RL5C465:
	case PCI_DEVICE_ID_RICOH_RL5C466:
		/*
		 * Ricoh chips have a legacy bridge enable different than most
		 * Code cribbed from NEWBUS's bridge code since I can't find a
		 * datasheet for them that has register definitions.
		 */
		brgcntl = pci_read_config(dev, CB_PCI_BRIDGE_CTRL, 2);
		brgcntl &= ~(CB_BCR_RL_3E2_EN | CB_BCR_RL_3E0_EN);
		pci_write_config(dev, CB_PCI_BRIDGE_CTRL, brgcntl, 2);
		break;
	}
	pcic_pci_cardbus_init(dev);
}

/*
 * TI 1030, 1130, and 1131.
 */
static int
pcic_pci_ti113x_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	u_int32_t	cardcntl;
	device_t	dev = sp->sc->dev;

	/*
	 * The TI-1130 (and 1030 and 1131) have a different interrupt
	 * routing control than the newer cards.  assume we're not
	 * routing PCI, but enable as necessary when we find someone
	 * uses PCI interrupts.  In order to get any pci interrupts,
	 * PCI_IRQ_ENA (bit 5) must be set.  If either PCI_IREQ (bit
	 * 4) or PCI_CSC (bit 3) are set, then set bit 5 at the same
	 * time, since setting them enables the PCI interrupt routing.
	 *
	 * It also appears necessary to set the function routing bit
	 * in the bridge control register, but cardbus_init does that
	 * for us.
	 */
	cardcntl = pci_read_config(dev, TI113X_PCI_CARD_CONTROL,   1);
	if (way == pcic_iw_pci)
		cardcntl |= TI113X_CARDCNTL_PCI_IREQ;
	else
		cardcntl &= ~TI113X_CARDCNTL_PCI_IREQ;
	if (cardcntl & (TI113X_CARDCNTL_PCI_IREQ | TI113X_CARDCNTL_PCI_CSC))
		cardcntl &= ~TI113X_CARDCNTL_PCI_IRQ_ENA;
	else
		cardcntl |= TI113X_CARDCNTL_PCI_IRQ_ENA;
	pci_write_config(dev, TI113X_PCI_CARD_CONTROL,  cardcntl, 1);

	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_ti113x_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	u_int32_t	cardcntl;
	device_t	dev = sp->sc->dev;

	/*
	 * The TI-1130 (and 1030 and 1131) have a different interrupt
	 * routing control than the newer cards.  assume we're not
	 * routing PCI, but enable as necessary when we find someone
	 * uses PCI interrupts.  In order to get any pci interrupts,
	 * PCI_IRQ_ENA (bit 5) must be set.  If either PCI_IREQ (bit
	 * 4) or PCI_CSC (bit 3) are set, then set bit 5 at the same
	 * time, since setting them enables the PCI interrupt routing.
	 *
	 * It also appears necessary to set the function routing bit
	 * in the bridge control register, but cardbus_init does that
	 * for us.
	 */
	cardcntl = pci_read_config(dev, TI113X_PCI_CARD_CONTROL,   1);
	if (way == pcic_iw_pci)
		cardcntl |= TI113X_CARDCNTL_PCI_CSC;
	else
		cardcntl &= ~TI113X_CARDCNTL_PCI_CSC;
	if (cardcntl & (TI113X_CARDCNTL_PCI_IREQ | TI113X_CARDCNTL_PCI_CSC))
		cardcntl &= ~TI113X_CARDCNTL_PCI_IRQ_ENA;
	else
		cardcntl |= TI113X_CARDCNTL_PCI_IRQ_ENA;
	pci_write_config(dev, TI113X_PCI_CARD_CONTROL,  cardcntl, 1);

	return (0);
}

static int
pcic_pci_ti12xx_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_ti12xx_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	/*
	 * Nothing happens here.  The TI12xx parts will route the
	 * CSC interrupt via PCI if ExCA register tells it to use
	 * interrupt 0.  And via IRQ otherwise (except for reserved
	 * values which may or may not do anything).
	 *
	 * We just hope for the best here that doing nothing is the
	 * right thing to do.
	 */
	return (0);
}

/*
 * TI PCI-CardBus Host Adapter specific function code.
 * This function is separated from pcic_pci_attach().
 * Takeshi Shibagaki(shiba@jp.freebsd.org).
 */
static void
pcic_pci_ti_init(device_t dev)
{
	u_int32_t	syscntl, diagctl, devcntl, cardcntl;
	u_int32_t	device_id = pci_get_devid(dev);
	struct pcic_softc *sc = device_get_softc(dev);
	int	 	ti113x = (device_id == PCI_DEVICE_ID_PCIC_TI1031) ||
	    (device_id == PCI_DEVICE_ID_PCIC_TI1130) ||
	    (device_id == PCI_DEVICE_ID_PCIC_TI1131);

	syscntl  = pci_read_config(dev, TI113X_PCI_SYSTEM_CONTROL, 4);
	devcntl  = pci_read_config(dev, TI113X_PCI_DEVICE_CONTROL, 1);
	cardcntl = pci_read_config(dev, TI113X_PCI_CARD_CONTROL,   1);

	if (ti113x) {
		device_printf(dev, "TI113X PCI Config Reg: ");
		if (syscntl & TI113X_SYSCNTL_CLKRUN_ENA) {
			if (syscntl & TI113X_SYSCNTL_CLKRUN_SEL)
				printf("[clkrun irq 12]");
			else
				printf("[clkrun irq 10]");
		}
	} else {
		device_printf(dev, "TI12XX PCI Config Reg: ");

		/*
		 * Turn on async CSC interrupts.  This appears to
		 * be the default, but the old, pre pci-aware, code
		 * did this and it appears PAO does as well.
		 */
		diagctl = pci_read_config(dev, TI12XX_PCI_DIAGNOSTIC, 1);
		diagctl |= TI12XX_DIAG_CSC_INTR;
		pci_write_config(dev, TI12XX_PCI_DIAGNOSTIC, diagctl, 1);

		/*
		 * Turn off Zoom Video.  Some cards have this enabled,
		 * some do not but it causes problems when enabled.  This
		 * register doesn't exist on the 1130 (and likely the 1131,
		 * but without a datasheet it is impossible to know).
		 * Some 12xx chips may not have it, but setting it is
		 * believed to be harmless.
		 */
		pci_write_config(dev, TI12XX_PCI_MULTIMEDIA_CONTROL, 0, 4);
	}
	/*
	 * Special code for the Orinoco cards (and a few others).  They
	 * seem to need this special code to make them work only over pci
	 * interrupts.  Sadly, doing this code also causes problems for
	 * many laptops, so we have to make it controlled by a tunable.
	 */
	if (sc->func_route == pcic_iw_pci) {
		if (pcic_init_routing) {
			devcntl &= ~TI113X_DEVCNTL_INTR_MASK;
			pci_write_config(dev, TI113X_PCI_DEVICE_CONTROL,
			    devcntl, 1);
			devcntl = pci_read_config(dev,
			    TI113X_PCI_DEVICE_CONTROL, 1);
			syscntl |= TI113X_SYSCNTL_INTRTIE;
		}
		syscntl &= ~TI113X_SYSCNTL_SMIENB;
		pci_write_config(dev, TI113X_PCI_SYSTEM_CONTROL, syscntl, 1);
	}
	if (cardcntl & TI113X_CARDCNTL_RING_ENA)
		printf("[ring enable]");
	if (cardcntl & TI113X_CARDCNTL_SPKR_ENA)
		printf("[speaker enable]");
	if (syscntl & TI113X_SYSCNTL_PWRSAVINGS)
		printf("[pwr save]");
	switch(devcntl & TI113X_DEVCNTL_INTR_MASK){
		case TI113X_DEVCNTL_INTR_ISA :
			printf("[CSC parallel isa irq]");
			break;
		case TI113X_DEVCNTL_INTR_SERIAL :
			printf("[CSC serial isa irq]");
			break;
		case TI113X_DEVCNTL_INTR_NONE :
			printf("[pci only]");
			break;
		case TI12XX_DEVCNTL_INTR_ALLSERIAL :
			printf("[FUNC pci int + CSC serial isa irq]");
			break;
	}
	printf("\n");
	pcic_pci_cardbus_init(dev);
}

/*
 * Code for TOPIC chips
 */
static int
pcic_pci_topic_func(struct pcic_slot *sp, enum pcic_intr_way way)
{
	return (pcic_pci_gen_func(sp, way));
}

static int
pcic_pci_topic_csc(struct pcic_slot *sp, enum pcic_intr_way way)
{
	device_t	dev = sp->sc->dev;
	u_int32_t	icr;

	icr = pci_read_config(dev, TOPIC_INTERRUPT_CONTROL, 1);
	if (way == pcic_iw_pci)
		icr |= TOPIC_ICR_INTA;
	else
		icr &= ~TOPIC_ICR_INTA;
	pci_write_config(dev, TOPIC_INTERRUPT_CONTROL, icr, 1);

	return (0);
}

static void
pcic_pci_topic_init(device_t dev)
{
	struct pcic_softc *sc = device_get_softc(dev);
	u_int32_t device_id;

	device_id = pci_get_devid(dev);
	if (device_id == PCI_DEVICE_ID_TOSHIBA_TOPIC100 ||
	    device_id == PCI_DEVICE_ID_TOSHIBA_TOPIC97) {
		/*
		 * We need to enable voltage sense and 3V cards explicitly
		 * in the bridge.  The datasheets I have for both the
		 * ToPIC 97 and 100 both lists these ports.  Without
		 * datasheets for the ToPIC95s, I can't tell if we need
		 * to do it there or not.
		 */
		pcic_setb(&sc->slots[0], PCIC_TOPIC_FCR,
		    PCIC_FCR_3V_EN | PCIC_FCR_VS_EN);
	}
	pcic_pci_cardbus_init(dev);
}

static void
pcic_pci_cardbus_init(device_t dev)
{
	struct pcic_softc *sc = device_get_softc(dev);
	u_int16_t	brgcntl;
	int		unit;

	unit = device_get_unit(dev);

	brgcntl = pci_read_config(dev, CB_PCI_BRIDGE_CTRL, 2);
	brgcntl |= CB_BCR_WRITE_POST_EN | CB_BCR_MASTER_ABORT;
	pci_write_config(dev, CB_PCI_BRIDGE_CTRL, brgcntl, 2);

	/* Turn off legacy address */
	pci_write_config(dev, CB_PCI_LEGACY16_IOADDR, 0, 2);

	/* 
	 * Write zeros into the remaining memory I/O windows.  This
	 * seems to turn off the pci configuration of these things and
	 * make the cardbus bridge use the values for memory
	 * programmed into the pcic registers.
	 */
	pci_write_config(dev, CB_PCI_MEMBASE0, 0, 4);
	pci_write_config(dev, CB_PCI_MEMLIMIT0, 0, 4);
	pci_write_config(dev, CB_PCI_MEMBASE1, 0, 4);
	pci_write_config(dev, CB_PCI_MEMLIMIT1, 0, 4);
	pci_write_config(dev, CB_PCI_IOBASE0, 0, 4);
	pci_write_config(dev, CB_PCI_IOLIMIT0, 0, 4);
	pci_write_config(dev, CB_PCI_IOBASE1, 0, 4);
	pci_write_config(dev, CB_PCI_IOLIMIT1, 0, 4);

	/*
	 * Force the function interrupts to be pulse rather than
	 * edge triggered.
	 */
	sc->chip->func_intr_way(&sc->slots[0], pcic_iw_isa);
	sc->chip->csc_intr_way(&sc->slots[0], sc->csc_route);

	return;
}

static const char *
pcic_pci_cardtype(u_int32_t stat)
{
	if (stat & CB_SS_NOTCARD)
		return ("Cardtype unrecognized by bridge");
	if ((stat & (CB_SS_16BIT | CB_SS_CB)) == (CB_SS_16BIT | CB_SS_CB))
		return ("16-bit and 32-bit (can't happen)");
	if (stat & CB_SS_16BIT)
		return ("16-bit pccard");
	if (stat & CB_SS_CB)
		return ("32-bit cardbus");
	return ("none (can't happen)");
}

/*
 * Card insertion and removal code.  The insertion events need to be
 * debounced so that the noisy insertion/removal events don't result
 * in the hardware being initialized many times, only to be torn down
 * as well.  This may also cause races with pccardd.  Instead, we wait
 * for the insertion signal to be stable for 0.5 seconds before we declare
 * it to be a real insertion event.  Removal is done right away.
 *
 * Note: We only handle the card detect change events.  We don't handle
 * power events and status change events.
 */
static void
pcic_cd_insert(void *arg) 
{
	struct pcic_softc *sc = (struct pcic_softc *) arg;
	struct pcic_slot *sp = &sc->slots[0];
	u_int32_t stat;

 	sc->cd_pending = 0;
	stat = bus_space_read_4(sp->bst, sp->bsh, CB_SOCKET_STATE);

	/* Just return if the interrupt handler missed a remove transition. */
	if ((stat & CB_SS_CD) != 0)
		return;
	sc->cd_present = 1;
	if ((stat & CB_SS_16BIT) == 0)
		device_printf(sp->sc->dev, "Card type %s is unsupported\n",
		    pcic_pci_cardtype(stat));
	else
		pccard_event(sp->slt, card_inserted);
}

static void
pcic_pci_intr(void *arg)
{
	struct pcic_softc *sc = (struct pcic_softc *) arg;
	struct pcic_slot *sp = &sc->slots[0];
	u_int32_t event;
	u_int32_t stat;
	int present;

	event = bus_space_read_4(sp->bst, sp->bsh, CB_SOCKET_EVENT);
	if (event != 0) {
		stat = bus_space_read_4(sp->bst, sp->bsh, CB_SOCKET_STATE);
		if (bootverbose)
			device_printf(sc->dev, "Event mask 0x%x stat 0x%x\n",
			    event, stat);

		present = (stat & CB_SS_CD) == 0;
		if (present != sc->cd_present) {
			if (sc->cd_pending) {
				untimeout(pcic_cd_insert, arg, sc->cd_ch);
				sc->cd_pending = 0;
			}
			/* Delay insert events to debounce noisy signals. */
			if (present) {
				sc->cd_ch = timeout(pcic_cd_insert, arg, hz/2);
				sc->cd_pending = 1;
			} else {
				sc->cd_present = 0;
				pccard_event(sp->slt, card_removed);
			}
		}
		if (event & CB_SE_POWER)
			device_printf(sc->dev, "Power interrupt\n");
		if (stat & CB_SS_BADVCC)
			device_printf(sc->dev, "BAD Vcc request\n");

		/* Ack the interrupt */
		bus_space_write_4(sp->bst, sp->bsh, 0, event);
	}

	/*
	 * Some TI chips also require us to read the old ExCA register for
	 * card status change when we route CSC via PCI!  So, we go ahead
	 * and read it to clear the bits.  Maybe we should check the status
	 * ala the ISA interrupt handler, but those changes should be caught
	 * in the CD change.
	 */
	sp->getb(sp, PCIC_STAT_CHG);
}

/*
 * Return the ID string for the controller if the vendor/product id
 * matches, NULL otherwise.
 */
static int
pcic_pci_probe(device_t dev)
{
	u_int8_t	subclass;
	u_int8_t	progif;
	const char	*desc;
	u_int32_t	device_id;
	struct pcic_pci_table *itm;
	struct resource	*res;
	int		rid;

	device_id = pci_get_devid(dev);
	desc = NULL;
	itm = pcic_pci_lookup(device_id, &pcic_pci_devs[0]);
	if (pcic_ignore_function_1 && pci_get_function(dev) == 1) {
		if (itm != NULL)
			PRVERB((dev, "Ignoring function 1\n"));
		return (ENXIO);
	}
	if (itm != NULL)
		desc = itm->descr;
	if (desc == NULL && pci_get_class(dev) == PCIC_BRIDGE) {
		subclass = pci_get_subclass(dev);
		progif = pci_get_progif(dev);
		if (subclass == PCIS_BRIDGE_PCMCIA && progif == 0)
			desc = "Generic PCI-PCMCIA Bridge";
		if (subclass == PCIS_BRIDGE_CARDBUS && progif == 0)
			desc = "YENTA PCI-CARDBUS Bridge";
		if (bootverbose && desc)
			printf("Found unknown %s devid 0x%x\n", desc, device_id);
	}
	if (desc == NULL)
		return (ENXIO);
	device_set_desc(dev, desc);

	/*
	 * Take us out of power down mode, if necessary.  It also
	 * appears that even reading the power register is enough on
	 * some systems to cause correct behavior.
	 */
	if (pci_get_powerstate(dev) != PCI_POWERSTATE_D0) {
		/* Reset the power state. */
		device_printf(dev, "chip is in D%d power mode "
		    "-- setting to D0\n", pci_get_powerstate(dev));
		pci_set_powerstate(dev, PCI_POWERSTATE_D0);
	}

	/*
	 * Allocated/deallocate interrupt.  This forces the PCI BIOS or
	 * other MD method to route the interrupts to this card.
	 * This so we get the interrupt number in the probe message.
	 * We only need to route interrupts when we're doing pci
	 * parallel interrupt routing.
	 *
	 * Note: The CLPD6729 is a special case.  See its init function
	 * for an explaination of ISA vs PCI interrupts.
	 */
	if (pcic_intr_path == pcic_iw_pci && 
	    device_id != PCI_DEVICE_ID_PCIC_CLPD6729) {
		rid = 0;
#ifdef __i386__
		/*
		 * IRQ 0 is invalid on x86, but not other platforms.
		 * If we have irq 0, then write 255 to force a new, non-
		 * bogus one to be assigned.
		 */
		if (pci_get_irq(dev) == 0) {
			pci_set_irq(dev, 255);
			pci_write_config(dev, PCIR_INTLINE, 255, 1);
		}
#endif
		res = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1,
		    RF_ACTIVE);
		if (res)
			bus_release_resource(dev, SYS_RES_IRQ, rid, res);
	}
	
	return (0);
}

static void
pcic_pci_shutdown(device_t dev)
{
	struct pcic_softc *sc;
	struct pcic_slot *sp;
		
	sc = (struct pcic_softc *) device_get_softc(dev);
	sp = &sc->slots[0];

	/*
	 * Make the chips use ISA again.
	 */
	sc->chip->func_intr_way(&sc->slots[0], pcic_iw_isa);
	sc->chip->csc_intr_way(&sc->slots[0], pcic_iw_isa);

	/*
	 * Turn off the power to the slot in an attempt to
	 * keep the system from hanging on reboot.  We also turn off
	 * card interrupts in an attempt to control interrupt storms.
	 * on some (all?) this has the effect of also turning off
	 * card status change interrupts.  A side effect of writing 0
	 * to INT_GEN is that the card is placed into "reset" mode
	 * where nothing happens until it is taken out of "reset"
	 * mode.
	 *
	 * Also, turn off the generation of status interrupts too.
	 */
	sp->putb(sp, PCIC_INT_GEN, 0);
	sp->putb(sp, PCIC_STAT_INT, 0);
	sp->putb(sp, PCIC_POWER, 0);

	/*
	 * Writing to INT_GEN can cause an interrupt, so we blindly
	 * ack all possible interrupts here.  Reading the stat change
	 * shouldn't be necessary, but some TI chipsets need it in the
	 * normal course of operations, so we do it here too.  We can't
	 * lose any interrupts after this point, so go ahead and ack
	 * everything.  The bits in INT_GEN clear upon reading them.
	 * We also set the interrupt mask to 0, in an effort to avoid
	 * getting further interrupts.
	 */
	bus_space_write_4(sp->bst, sp->bsh, CB_SOCKET_MASK, 0);
	bus_space_write_4(sp->bst, sp->bsh, CB_SOCKET_EVENT, 0xffffffff);
	sp->getb(sp, PCIC_STAT_CHG);
}

/*
 * General PCI based card dispatch routine.  Right now
 * it only understands the Ricoh, CL-PD6832 and TI parts.  It does
 * try to do generic things with other parts.
 */
static int
pcic_pci_attach(device_t dev)
{
	u_int32_t device_id = pci_get_devid(dev);
	u_long command;
	struct pcic_slot *sp;
	struct pcic_softc *sc;
	u_int32_t sockbase;
	u_int32_t stat;
	struct pcic_pci_table *itm;
	int rid;
	int i;
	struct resource *r = NULL;
	int error;
	u_long irq = 0;
	driver_intr_t *intr = NULL;

	/*
	 * In sys/pci/pcireg.h, PCIR_COMMAND must be separated
	 * PCI_COMMAND_REG(0x04) and PCI_STATUS_REG(0x06).
	 * Takeshi Shibagaki(shiba@jp.freebsd.org).
	 */
	command = pci_read_config(dev, PCIR_COMMAND, 4);
	command |= PCIM_CMD_PORTEN | PCIM_CMD_MEMEN;
	pci_write_config(dev, PCIR_COMMAND, command, 4);

	sc = (struct pcic_softc *) device_get_softc(dev);
	sp = &sc->slots[0];
	sp->sc = sc;
	sockbase = pci_read_config(dev, 0x10, 4);
	if (sockbase & 0x1) {
		sc->iorid = CB_PCI_SOCKET_BASE;
		sc->iores = bus_alloc_resource(dev, SYS_RES_IOPORT,
		    &sc->iorid, 0, ~0, 1, RF_ACTIVE | RF_SHAREABLE);
		if (sc->iores == NULL)
			return (ENOMEM);
		sp->bst = rman_get_bustag(sc->iores);
		sp->bsh = rman_get_bushandle(sc->iores);
		sp->controller = PCIC_PD672X;
		sp->revision = 0;
		sc->flags = PCIC_PD_POWER;
		itm = pcic_pci_lookup(device_id, &pcic_pci_devs[0]);
		for (i = 0; i < 2; i++) {
			sp[i].getb = pcic_getb_io;
			sp[i].putb = pcic_putb_io;
			sp[i].offset = i * PCIC_SLOT_SIZE;
			sp[i].controller = PCIC_PD672X;
			printf("ID is 0x%x\n", sp[i].getb(sp, PCIC_ID_REV));
			if ((sp[i].getb(sp, PCIC_ID_REV) & 0xc0) == 0x80)
				sp[i].slt = (struct slot *) 1;
		}
		/*
		 * We only support isa at this time.  These cards can be
		 * wired up as either ISA cards *OR* PCI cards (well, weird
		 * hybrids are possible, but not seen in the wild).  Since it
		 * is an either or thing, we assume ISA since all laptops that
		 * we supported in 4.3 and earlier work.
		 */ 
		sc->csc_route = pcic_iw_isa;
		sc->func_route = pcic_iw_isa;
		if (itm)
			sc->flags = itm->flags;
	} else {
		sc->memrid = CB_PCI_SOCKET_BASE;
		sc->memres = bus_alloc_resource(dev, SYS_RES_MEMORY,
		    &sc->memrid, 0, ~0, 1, RF_ACTIVE);
		if (sc->memres == NULL && pcic_pci_get_memory(dev) != 0)
			return (ENOMEM);
		sp->getb = pcic_pci_getb2;
		sp->putb = pcic_pci_putb2;
		sp->offset = CB_EXCA_OFFSET;
		sp->bst = rman_get_bustag(sc->memres);
		sp->bsh = rman_get_bushandle(sc->memres);
		itm = pcic_pci_lookup(device_id, &pcic_pci_devs[0]);
		if (itm != NULL) {
			sp->controller = itm->type;
			sp->revision = 0;
			sc->flags = itm->flags;
		} else {
			/* By default, assume we're a D step compatible */
			sp->controller = PCIC_I82365SL_DF;
			sp->revision = 0;
			sc->flags = PCIC_DF_POWER;
		}
		/* sc->flags = PCIC_CARDBUS_POWER; */
		sp->slt = (struct slot *) 1;
		sc->csc_route = pcic_intr_path;
		sc->func_route = pcic_intr_path;
		stat = bus_space_read_4(sp->bst, sp->bsh, CB_SOCKET_STATE);
		sc->cd_present = (stat & CB_SS_CD) == 0;	
	}
	sc->dev = dev;
	sc->chip = itm->chip;

	if (sc->csc_route == pcic_iw_pci) {
		rid = 0;
		r = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0, 1, 
		    RF_ACTIVE | RF_SHAREABLE);
		if (r == NULL) {
			sc->csc_route = pcic_iw_isa;
			sc->func_route = pcic_iw_isa;
			device_printf(dev,
			    "No PCI interrupt routed, trying ISA.\n");
		} else {
			intr = pcic_pci_intr;
			irq = rman_get_start(r);
		}
	}
	if (sc->csc_route == pcic_iw_isa) {
		rid = 0;
		irq = pcic_override_irq;
		if (irq != 0) {
			r = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, irq,
			    irq, 1, RF_ACTIVE);
			if (r == NULL) {
				device_printf(dev,
				    "Can't route ISA CSC interrupt.\n");
				pcic_dealloc(dev);
				return (ENXIO);
			}
			device_printf(dev,
			    "Management interrupt on ISA IRQ %ld\n", irq);
			intr = pcic_isa_intr;
		} else {
			sc->slot_poll = pcic_timeout;
			sc->timeout_ch = timeout(sc->slot_poll, sc, hz/2);
			device_printf(dev, "Polling mode\n");
			intr = NULL;
		}
	}

	/*
	 * Initialize AFTER we figure out what kind of interrupt we're
	 * going to be using, if any.
	 */
	if (!sc->chip)
		panic("Bug: sc->chip not set!\n");
	sc->chip->init(dev);

	/*
	 * Now install the interrupt handler, if necessary.
	 */
	sc->irqrid = rid;
	sc->irqres = r;
	sc->irq = irq;
	if (intr) {
		error = bus_setup_intr(dev, r, INTR_TYPE_AV, intr, sc, &sc->ih);
		if (error) {
			pcic_dealloc(dev);
			return (error);
		}
	}
	return (pcic_attach(dev));
}

static int
pcic_pci_detach(device_t dev)
{
	return (EBUSY);			/* Can't detach this device */
}

/*
 * The PCI bus should do this for us.  However, it doesn't quite yet, so
 * we cope by doing it ourselves.  If it ever does, this code can go quietly
 * into that good night.
 */
static int
pcic_pci_get_memory(device_t dev)
{
	struct pcic_softc *sc;
	u_int32_t sockbase;

	sc = (struct pcic_softc *) device_get_softc(dev);
	sockbase = pci_read_config(dev, sc->memrid, 4);
	if (sockbase >= 0x100000 && sockbase < 0xfffffff0) {
		device_printf(dev, "Could not map register memory\n");
		return (ENOMEM);
	}
	pci_write_config(dev, sc->memrid, 0xffffffff, 4);
	sockbase = pci_read_config(dev, sc->memrid, 4);
	sockbase = (sockbase & 0xfffffff0) & -(sockbase & 0xfffffff0);
#define CARDBUS_SYS_RES_MEMORY_START    0x44000000
#define CARDBUS_SYS_RES_MEMORY_END	0xFFFFFFFF
	sc->memres = bus_generic_alloc_resource(device_get_parent(dev),
	    dev, SYS_RES_MEMORY, &sc->memrid,
	    CARDBUS_SYS_RES_MEMORY_START, CARDBUS_SYS_RES_MEMORY_END,
	    sockbase, RF_ACTIVE | rman_make_alignment_flags(sockbase));
	if (sc->memres == NULL) {
		device_printf(dev, "Could not grab register memory\n");
		return (ENOMEM);
	}
	sockbase = rman_get_start(sc->memres);
	pci_write_config(dev, sc->memrid, sockbase, 4);
	device_printf(dev, "PCI Memory allocated: 0x%08x\n", sockbase);
	return (0);
}

static int
pcic_pci_gen_mapirq(struct pcic_slot *sp, int irq)
{
	/*
	 * If we're doing ISA interrupt routing, then just go to the
	 * generic ISA routine.  Also, irq 0 means turn off the interrupts
	 * at the bridge.  We do this by making the interrupts edge
	 * triggered rather then level.
	 */
	if (sp->sc->func_route == pcic_iw_isa || irq == 0)
		return (pcic_isa_mapirq(sp, irq));

	return (sp->sc->chip->func_intr_way(sp, pcic_iw_pci));
}

static device_method_t pcic_pci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		pcic_pci_probe),
	DEVMETHOD(device_attach,	pcic_pci_attach),
	DEVMETHOD(device_detach,	pcic_pci_detach),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),
	DEVMETHOD(device_shutdown,	pcic_pci_shutdown),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_alloc_resource,	pcic_alloc_resource),
	DEVMETHOD(bus_release_resource,	bus_generic_release_resource),
	DEVMETHOD(bus_activate_resource, pcic_activate_resource),
	DEVMETHOD(bus_deactivate_resource, pcic_deactivate_resource),
	DEVMETHOD(bus_setup_intr,	pcic_setup_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),

	/* Card interface */
	DEVMETHOD(card_set_res_flags,	pcic_set_res_flags),
	DEVMETHOD(card_get_res_flags,	pcic_get_res_flags),
	DEVMETHOD(card_set_memory_offset, pcic_set_memory_offset),
	DEVMETHOD(card_get_memory_offset, pcic_get_memory_offset),

	{0, 0}
};

static driver_t pcic_pci_driver = {
	"pcic",
	pcic_pci_methods,
	sizeof(struct pcic_softc)
};

DRIVER_MODULE(pcic, pci, pcic_pci_driver, pcic_devclass, 0, 0);
