/*
 * Copyright (c) 2000,2001 Jonathan Chen.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
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
 * $FreeBSD$
 */

/*
 * Driver for PCI to Cardbus Bridge chips
 *
 * References:
 *  TI Datasheets:
 *   http://www-s.ti.com/cgi-bin/sc/generic2.cgi?family=PCI+CARDBUS+CONTROLLERS
 *
 * Written by Jonathan Chen <jon@freebsd.org>
 * The author would like to acknowledge:
 *  * HAYAKAWA Koichi: Author of the NetBSD code for the same thing
 *  * Warner Losh: Newbus/newcard guru and author of the pccard side of things
 *  * YAMAMOTO Shigeru: Author of another FreeBSD cardbus driver
 *  * David Cross: Author of the initial ugly hack for a specific cardbus card
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/kthread.h>
#include <sys/bus.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <machine/resource.h>

#include <pci/pcireg.h>
#include <pci/pcivar.h>
#include <machine/clock.h>

#include <dev/pccard/pccardreg.h>
#include <dev/pccard/pccardvar.h>

#include <dev/exca/excareg.h>
#include <dev/exca/excavar.h>

#include <dev/pccbb/pccbbreg.h>
#include <dev/pccbb/pccbbvar.h>

#include "power_if.h"
#include "card_if.h"
#include "pcib_if.h"

#define	DPRINTF(x) do { if (cbb_debug) printf x; } while (0)
#define	DEVPRINTF(x) do { if (cbb_debug) device_printf x; } while (0)

#define	PCI_MASK_CONFIG(DEV,REG,MASK,SIZE)				\
	pci_write_config(DEV, REG, pci_read_config(DEV, REG, SIZE) MASK, SIZE)
#define	PCI_MASK2_CONFIG(DEV,REG,MASK1,MASK2,SIZE)			\
	pci_write_config(DEV, REG, (					\
		pci_read_config(DEV, REG, SIZE) MASK1) MASK2, SIZE)

#define PCCBB_START_MEM	0x84000000
#define PCCBB_START_32_IO 0x1000
#define PCCBB_START_16_IO 0x100

struct yenta_chipinfo {
	uint32_t yc_id;
	const	char *yc_name;
	int	yc_chiptype;
} yc_chipsets[] = {
	/* Texas Instruments chips */
	{PCI_DEVICE_ID_PCIC_TI1031, "TI1031 PCI-PC Card Bridge", CB_TI113X},
	{PCI_DEVICE_ID_PCIC_TI1130, "TI1130 PCI-CardBus Bridge", CB_TI113X},
	{PCI_DEVICE_ID_PCIC_TI1131, "TI1131 PCI-CardBus Bridge", CB_TI113X},

	{PCI_DEVICE_ID_PCIC_TI1210, "TI1210 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1211, "TI1211 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1220, "TI1220 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1221, "TI1221 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1225, "TI1225 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1250, "TI1250 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1251, "TI1251 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1251B,"TI1251B PCI-CardBus Bridge",CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1260, "TI1260 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1260B,"TI1260B PCI-CardBus Bridge",CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1410, "TI1410 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1420, "TI1420 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1421, "TI1421 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1450, "TI1450 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI1451, "TI1451 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI4410, "TI4410 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI4450, "TI4450 PCI-CardBus Bridge", CB_TI12XX},
	{PCI_DEVICE_ID_PCIC_TI4451, "TI4451 PCI-CardBus Bridge", CB_TI12XX},

	/* Ricoh chips */
	{PCI_DEVICE_ID_RICOH_RL5C465, "RF5C465 PCI-CardBus Bridge",
	    CB_RF5C46X},
	{PCI_DEVICE_ID_RICOH_RL5C466, "RF5C466 PCI-CardBus Bridge",
	    CB_RF5C46X},
	{PCI_DEVICE_ID_RICOH_RL5C475, "RF5C475 PCI-CardBus Bridge",
	    CB_RF5C47X},
	{PCI_DEVICE_ID_RICOH_RL5C476, "RF5C476 PCI-CardBus Bridge",
	    CB_RF5C47X},
	{PCI_DEVICE_ID_RICOH_RL5C477, "RF5C477 PCI-CardBus Bridge",
	    CB_RF5C47X},
	{PCI_DEVICE_ID_RICOH_RL5C478, "RF5C478 PCI-CardBus Bridge",
	    CB_RF5C47X},

	/* Toshiba products */
	{PCI_DEVICE_ID_TOSHIBA_TOPIC95, "ToPIC95 PCI-CardBus Bridge",
	    CB_TOPIC95},
	{PCI_DEVICE_ID_TOSHIBA_TOPIC95B, "ToPIC95B PCI-CardBus Bridge",
	    CB_TOPIC95},
	{PCI_DEVICE_ID_TOSHIBA_TOPIC97, "ToPIC97 PCI-CardBus Bridge",
	    CB_TOPIC97},
	{PCI_DEVICE_ID_TOSHIBA_TOPIC100, "ToPIC100 PCI-CardBus Bridge",
	    CB_TOPIC97},

	/* Cirrus Logic */
	{PCI_DEVICE_ID_PCIC_CLPD6832, "CLPD6832 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_CLPD6833, "CLPD6833 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_CLPD6834, "CLPD6834 PCI-CardBus Bridge",
	    CB_CIRRUS},

	/* 02Micro */
	{PCI_DEVICE_ID_PCIC_OZ6832, "O2Mirco OZ6832/6833 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_OZ6860, "O2Mirco OZ6836/6860 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_OZ6872, "O2Mirco OZ6812/6872 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_OZ6912, "O2Mirco OZ6912/6972 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_OZ6922, "O2Mirco OZ6822 PCI-CardBus Bridge",
	    CB_CIRRUS},
	{PCI_DEVICE_ID_PCIC_OZ6933, "O2Mirco OZ6833 PCI-CardBus Bridge",
	    CB_CIRRUS},

	/* sentinel */
	{0 /* null id */, "unknown", CB_UNKNOWN},
};

/* sysctl vars */
SYSCTL_NODE(_hw, OID_AUTO, cbb, CTLFLAG_RD, 0, "CBB parameters");

/* There's no way to say TUNEABLE_LONG to get the right types */
u_long pccbb_start_mem = PCCBB_START_MEM;
TUNABLE_INT("hw.cbb.start_memory", (int *)&pccbb_start_mem);
SYSCTL_ULONG(_hw_cbb, OID_AUTO, start_mem, CTLFLAG_RD,
    &pccbb_start_mem, PCCBB_START_MEM,
    "Starting address for memory allocations");

u_long pccbb_start_16_io = PCCBB_START_16_IO;
TUNABLE_INT("hw.cbb.start_16_io", (int *)&pccbb_start_16_io);
SYSCTL_ULONG(_hw_cbb, OID_AUTO, start_16_io, CTLFLAG_RD,
    &pccbb_start_16_io, PCCBB_START_16_IO,
    "Starting ioport for 16-bit cards");

u_long pccbb_start_32_io = PCCBB_START_32_IO;
TUNABLE_INT("hw.cbb.start_32_io", (int *)&pccbb_start_32_io);
SYSCTL_ULONG(_hw_cbb, OID_AUTO, start_32_io, CTLFLAG_RD,
    &pccbb_start_32_io, PCCBB_START_32_IO,
    "Starting ioport for 32-bit cards");

int cbb_debug = 0;
TUNABLE_INT("hw.cbb.debug", &cbb_debug);
SYSCTL_ULONG(_hw_cbb, OID_AUTO, debug, CTLFLAG_RD, &cbb_debug, 0,
    "Verbose cardbus bridge debugging");

static int	pccbb_chipset(uint32_t pci_id, const char **namep);
static int	pccbb_probe(device_t brdev);
static void	pccbb_chipinit(struct pccbb_softc *sc);
static int	pccbb_attach(device_t brdev);
static int	pccbb_detach(device_t brdev);
static int	pccbb_shutdown(device_t brdev);
static void	pccbb_driver_added(device_t brdev, driver_t *driver);
static void	pccbb_child_detached(device_t brdev, device_t child);
static int	pccbb_card_reprobe(device_t brdev, device_t busdev);
static void	pccbb_event_thread(void *arg);
static void	pccbb_insert(struct pccbb_softc *sc);
static void	pccbb_removal(struct pccbb_softc *sc);
static void	pccbb_intr(void *arg);
static int	pccbb_detect_voltage(device_t brdev);
static int	pccbb_power(device_t brdev, int volts);
static void	pccbb_cardbus_reset(device_t brdev);
static int	pccbb_cardbus_power_enable_socket(device_t brdev,
		    device_t child);
static void	pccbb_cardbus_power_disable_socket(device_t brdev,
		    device_t child);
static int	pccbb_cardbus_io_open(device_t brdev, int win, uint32_t start,
		    uint32_t end);
static int	pccbb_cardbus_mem_open(device_t brdev, int win,
		    uint32_t start, uint32_t end);
static void	pccbb_cardbus_auto_open(struct pccbb_softc *sc, int type);
static int	pccbb_cardbus_activate_resource(device_t brdev, device_t child,
		    int type, int rid, struct resource *res);
static int	pccbb_cardbus_deactivate_resource(device_t brdev,
		    device_t child, int type, int rid, struct resource *res);
static struct resource	*pccbb_cardbus_alloc_resource(device_t brdev,
		    device_t child, int type, int *rid, u_long start,
		    u_long end, u_long count, uint flags);
static int	pccbb_cardbus_release_resource(device_t brdev, device_t child,
		    int type, int rid, struct resource *res);
static int	pccbb_power_enable_socket(device_t brdev, device_t child);
static void	pccbb_power_disable_socket(device_t brdev, device_t child);
static int	pccbb_activate_resource(device_t brdev, device_t child,
		    int type, int rid, struct resource *r);
static int	pccbb_deactivate_resource(device_t brdev, device_t child,
		    int type, int rid, struct resource *r);
static struct resource	*pccbb_alloc_resource(device_t brdev, device_t child,
		    int type, int *rid, u_long start, u_long end, u_long count,
		    uint flags);
static int	pccbb_release_resource(device_t brdev, device_t child,
		    int type, int rid, struct resource *r);
static int	pccbb_read_ivar(device_t brdev, device_t child, int which,
		    uintptr_t *result);
static int	pccbb_write_ivar(device_t brdev, device_t child, int which,
		    uintptr_t value);
static int	pccbb_maxslots(device_t brdev);
static uint32_t pccbb_read_config(device_t brdev, int b, int s, int f,
		    int reg, int width);
static void	pccbb_write_config(device_t brdev, int b, int s, int f,
		    int reg, uint32_t val, int width);

/*
 */
static __inline void
pccbb_set(struct pccbb_softc *sc, uint32_t reg, uint32_t val)
{
	bus_space_write_4(sc->bst, sc->bsh, reg, val);
}

static __inline uint32_t
pccbb_get(struct pccbb_softc *sc, uint32_t reg)
{
	return (bus_space_read_4(sc->bst, sc->bsh, reg));
}

static __inline void
pccbb_setb(struct pccbb_softc *sc, uint32_t reg, uint32_t bits)
{
	pccbb_set(sc, reg, pccbb_get(sc, reg) | bits);
}

static __inline void
pccbb_clrb(struct pccbb_softc *sc, uint32_t reg, uint32_t bits)
{
	pccbb_set(sc, reg, pccbb_get(sc, reg) & ~bits);
}

static __inline uint8_t
pccbb_pcic_read(struct exca_softc *sc, int reg)
{
	return (bus_space_read_1(sc->bst, sc->bsh, sc->offset + reg));
}

static __inline void
pccbb_pcic_write(struct exca_softc *sc, int reg, uint8_t val)
{
	return (bus_space_write_1(sc->bst, sc->bsh, sc->offset + reg, val));
}

static void
pccbb_remove_res(struct pccbb_softc *sc, struct resource *res)
{
	struct pccbb_reslist *rle;

	SLIST_FOREACH(rle, &sc->rl, link) {
		if (rle->res == res) {
			SLIST_REMOVE(&sc->rl, rle, pccbb_reslist, link);
			free(rle, M_DEVBUF);
			return;
		}
	}
}

static struct resource *
pccbb_find_res(struct pccbb_softc *sc, int type, int rid)
{
	struct pccbb_reslist *rle;
	
	SLIST_FOREACH(rle, &sc->rl, link)
		if (SYS_RES_MEMORY == rle->type && rid == rle->rid)
			return (rle->res);
	return (NULL);
}

static void
pccbb_insert_res(struct pccbb_softc *sc, struct resource *res, int type,
    int rid)
{
	struct pccbb_reslist *rle;

	/*
	 * Need to record allocated resource so we can iterate through
	 * it later.
	 */
	rle = malloc(sizeof(struct pccbb_reslist), M_DEVBUF, M_NOWAIT);
	if (!res)
		panic("pccbb_cardbus_alloc_resource: can't record entry!");
	rle->res = res;
	rle->type = type;
	rle->rid = rid;
	SLIST_INSERT_HEAD(&sc->rl, rle, link);
}

static void
pccbb_destroy_res(struct pccbb_softc *sc)
{
	struct pccbb_reslist *rle;

	while ((rle = SLIST_FIRST(&sc->rl)) != NULL) {
		device_printf(sc->dev, "Danger Will Robinson: Resource "
		    "left allocated!  This is a bug... "
		    "(rid=%x, type=%d, addr=%lx)\n", rle->rid, rle->type,
		    rman_get_start(rle->res));
		SLIST_REMOVE_HEAD(&sc->rl, link);
		free(rle, M_DEVBUF);
	}
}

/************************************************************************/
/* Probe/Attach								*/
/************************************************************************/

static int
pccbb_chipset(uint32_t pci_id, const char **namep)
{
	struct yenta_chipinfo *ycp;

	for (ycp = yc_chipsets; ycp->yc_id != 0 && pci_id != ycp->yc_id; ++ycp)
	    continue;
	if (namep != NULL)
		*namep = ycp->yc_name;
	return (ycp->yc_chiptype);
}

static int
pccbb_probe(device_t brdev)
{
	const char *name;
	uint32_t progif;
	uint32_t subclass;

	/*
	 * Do we know that we support the chipset?  If so, then we
	 * accept the device.
	 */
	if (pccbb_chipset(pci_get_devid(brdev), &name) != CB_UNKNOWN) {
		device_set_desc(brdev, name);
		return (0);
	}

	/*
	 * We do support generic CardBus bridges.  All that we've seen
	 * to date have progif 0 (the Yenta spec, and successors mandate
	 * this).  We do not support PCI PCMCIA bridges (with one exception)
	 * with this driver since they generally are I/O mapped.  Those
	 * are supported by the pcic driver.  This should help us be more
	 * future proof.
	 */
	subclass = pci_get_subclass(brdev);
	progif = pci_get_progif(brdev);
	if (subclass == PCIS_BRIDGE_CARDBUS && progif == 0) {
		device_set_desc(brdev, "PCI-CardBus Bridge");
		return (0);
	}
	return (ENXIO);
}


static void
pccbb_chipinit(struct pccbb_softc *sc)
{
	/* Set CardBus latency timer */
	if (pci_read_config(sc->dev, PCIR_SECLAT_1, 1) < 0x20)
		pci_write_config(sc->dev, PCIR_SECLAT_1, 0x20, 1);

	/* Set PCI latency timer */
	if (pci_read_config(sc->dev, PCIR_LATTIMER, 1) < 0x20)
		pci_write_config(sc->dev, PCIR_LATTIMER, 0x20, 1);

	/* Enable memory access */
	PCI_MASK_CONFIG(sc->dev, PCIR_COMMAND,
	    | PCIM_CMD_MEMEN
	    | PCIM_CMD_PORTEN
	    | PCIM_CMD_BUSMASTEREN, 2);

	/* disable Legacy IO */
	switch (sc->chipset) {
	case CB_RF5C46X:
		PCI_MASK_CONFIG(sc->dev, CBBR_BRIDGECTRL,
		    & ~(CBBM_BRIDGECTRL_RL_3E0_EN |
		    CBBM_BRIDGECTRL_RL_3E2_EN), 2);
		break;
	default:
		pci_write_config(sc->dev, CBBR_LEGACY, 0x0, 4);
		break;
	}

	/* Use PCI interrupt for interrupt routing */
	PCI_MASK2_CONFIG(sc->dev, CBBR_BRIDGECTRL,
	    & ~(CBBM_BRIDGECTRL_MASTER_ABORT |
	    CBBM_BRIDGECTRL_INTR_IREQ_EN),
	    | CBBM_BRIDGECTRL_WRITE_POST_EN,
	    2);

	/*
	 * XXX this should be a function table, ala OLDCARD.  This means
	 * that we could more easily support ISA interrupts for pccard
	 * cards if we had to.
	 */
	switch (sc->chipset) {
	case CB_TI113X:
		/*
		 * The TI 1031, TI 1130 and TI 1131 all require another bit
		 * be set to enable PCI routing of interrupts, and then
		 * a bit for each of the CSC and Function interrupts we
		 * want routed.
		 */
		PCI_MASK_CONFIG(sc->dev, CBBR_CBCTRL,
		    | CBBM_CBCTRL_113X_PCI_INTR |
		    CBBM_CBCTRL_113X_PCI_CSC | CBBM_CBCTRL_113X_PCI_IRQ_EN,
		    1);
		PCI_MASK_CONFIG(sc->dev, CBBR_DEVCTRL,
		    & ~(CBBM_DEVCTRL_INT_SERIAL |
		    CBBM_DEVCTRL_INT_PCI), 1);
		break;
	case CB_TOPIC97:
		/*
		 * Disable Zoom Video, ToPIC 97, 100.
		 */
		pci_write_config(sc->dev, CBBR_TOPIC_ZV_CONTROL, 0, 1);
		/*
		 * ToPIC 97, 100
		 * At offset 0xa1: INTERRUPT CONTROL register
		 * 0x1: Turn on INT interrupts.
		 */
		PCI_MASK_CONFIG(sc->dev, CBBR_TOPIC_INTCTRL,
		    | CBBM_TOPIC_INTCTRL_INTIRQSEL, 1);
		goto topic_common;
	case CB_TOPIC95:
		/*
		 * SOCKETCTRL appears to be TOPIC 95/B specific
		 */
		PCI_MASK_CONFIG(sc->dev, CBBR_TOPIC_SOCKETCTRL,
		    | CBBM_TOPIC_SOCKETCTRL_SCR_IRQSEL, 4);

	topic_common:;
		/*
		 * At offset 0xa0: SLOT CONTROL
		 * 0x80 Enable Cardbus Functionality
		 * 0x40 Enable Cardbus and PC Card registers
		 * 0x20 Lock ID in exca regs
		 * 0x10 Write protect ID in config regs
		 * Clear the rest of the bits, which defaults the slot
		 * in legacy mode to 0x3e0 and offset 0. (legacy
		 * mode is determined elsewhere)
		 */
		pci_write_config(sc->dev, CBBR_TOPIC_SLOTCTRL,
		    CBBM_TOPIC_SLOTCTRL_SLOTON |
		    CBBM_TOPIC_SLOTCTRL_SLOTEN |
		    CBBM_TOPIC_SLOTCTRL_ID_LOCK |
		    CBBM_TOPIC_SLOTCTRL_ID_WP, 1);

		/*
		 * At offset 0xa3 Card Detect Control Register
		 * 0x80 CARDBUS enbale
		 * 0x01 Cleared for hardware change detect
		 */
		PCI_MASK2_CONFIG(sc->dev, CBBR_TOPIC_CDC,
		    | CBBM_TOPIC_CDC_CARDBUS,
		    & ~CBBM_TOPIC_CDC_SWDETECT, 4);
		break;
	}

	/*
	 * Need to tell ExCA registers to route via PCI interrupts.  There
	 * are two ways to do this.  Once is to set INTR_ENABLE and the
	 * other is to set CSC to 0.  Since both methods are mutually
	 * compatible, we do both.
	 */
	exca_write(&sc->exca, EXCA_INTR, EXCA_INTR_ENABLE);
	exca_write(&sc->exca, EXCA_CSC_INTR, 0);

	/* close all memory and io windows */
	pci_write_config(sc->dev, CBBR_MEMBASE0, 0xffffffff, 4);
	pci_write_config(sc->dev, CBBR_MEMLIMIT0, 0, 4);
	pci_write_config(sc->dev, CBBR_MEMBASE1, 0xffffffff, 4);
	pci_write_config(sc->dev, CBBR_MEMLIMIT1, 0, 4);
	pci_write_config(sc->dev, CBBR_IOBASE0, 0xffffffff, 4);
	pci_write_config(sc->dev, CBBR_IOLIMIT0, 0, 4);
	pci_write_config(sc->dev, CBBR_IOBASE1, 0xffffffff, 4);
	pci_write_config(sc->dev, CBBR_IOLIMIT1, 0, 4);
}

static int
pccbb_attach(device_t brdev)
{
	struct pccbb_softc *sc = (struct pccbb_softc *)device_get_softc(brdev);
	int rid;
	uint32_t sockbase;

	mtx_init(&sc->mtx, device_get_nameunit(brdev), MTX_DEF);
	sc->chipset = pccbb_chipset(pci_get_devid(brdev), NULL);
	sc->dev = brdev;
	sc->cbdev = NULL;
	sc->pccarddev = NULL;
	sc->secbus = pci_read_config(brdev, PCIR_SECBUS_2, 1);
	sc->subbus = pci_read_config(brdev, PCIR_SUBBUS_2, 1);
	SLIST_INIT(&sc->rl);

	/*
	 * The PCI bus code should assign us memory in the absense
	 * of the BIOS doing so.  However, 'should' isn't 'is,' so we kludge
	 * up something here until the PCI/acpi code properly assigns the
	 * resource.
	 */
	rid = CBBR_SOCKBASE;
	sc->base_res = bus_alloc_resource(brdev, SYS_RES_MEMORY, &rid,
	    0, ~0, 1, RF_ACTIVE);
	if (!sc->base_res) {
		/*
		 * Generally, the BIOS will assign this memory for us.
		 * However, newer BIOSes do not because the MS design
		 * documents have mandated that this is for the OS
		 * to assign rather than the BIOS.  This driver shouldn't
		 * be doing this, but until the pci bus code (or acpi)
		 * does this, we allow CardBus bridges to work on more
		 * machines.
		 */
		sockbase = pci_read_config(brdev, rid, 4);
		if (sockbase < 0x100000 || sockbase >= 0xfffffff0) {
			pci_write_config(brdev, rid, 0xffffffff, 4);
			sockbase = pci_read_config(brdev, rid, 4);
			sockbase = (sockbase & 0xfffffff0) &
			    -(sockbase & 0xfffffff0);
			sc->base_res = bus_generic_alloc_resource(
			    device_get_parent(brdev), brdev, SYS_RES_MEMORY,
			    &rid, pccbb_start_mem, ~0, sockbase,
			    RF_ACTIVE|rman_make_alignment_flags(sockbase));
			if (!sc->base_res) {
				device_printf(brdev,
				    "Could not grab register memory\n");
				mtx_destroy(&sc->mtx);
				return (ENOMEM);
			}
			pci_write_config(brdev, CBBR_SOCKBASE,
			    rman_get_start(sc->base_res), 4);
			DEVPRINTF((brdev, "PCI Memory allocated: %08lx\n",
			    rman_get_start(sc->base_res)));
		} else {
			device_printf(brdev, "Could not map register memory\n");
			mtx_destroy(&sc->mtx);
			return (ENOMEM);
		}
	}

	sc->bst = rman_get_bustag(sc->base_res);
	sc->bsh = rman_get_bushandle(sc->base_res);
	exca_init(&sc->exca, brdev, &pccbb_pcic_write, &pccbb_pcic_read,
	  sc->bst, sc->bsh, 0x800);
	pccbb_chipinit(sc);

	/* attach children */
	sc->cbdev = device_add_child(brdev, "cardbus", -1);
	if (sc->cbdev == NULL)
		DEVPRINTF((brdev, "WARNING: cannot add cardbus bus.\n"));
	else if (device_probe_and_attach(sc->cbdev) != 0) {
		DEVPRINTF((brdev, "WARNING: cannot attach cardbus bus!\n"));
		sc->cbdev = NULL;
	}

	sc->pccarddev = device_add_child(brdev, "pccard", -1);
	if (sc->pccarddev == NULL)
		DEVPRINTF((brdev, "WARNING: cannot add pccard bus.\n"));
	else if (device_probe_and_attach(sc->pccarddev) != 0) {
		DEVPRINTF((brdev, "WARNING: cannot attach pccard bus.\n"));
		sc->pccarddev = NULL;
	}

	/* Map and establish the interrupt. */
	rid = 0;
	sc->irq_res = bus_alloc_resource(brdev, SYS_RES_IRQ, &rid, 0, ~0, 1,
	    RF_SHAREABLE | RF_ACTIVE);
	if (sc->irq_res == NULL) {
		printf("pccbb: Unable to map IRQ...\n");
		bus_release_resource(brdev, SYS_RES_MEMORY, CBBR_SOCKBASE,
		    sc->base_res);
		mtx_destroy(&sc->mtx);
		return (ENOMEM);
	}

	if (bus_setup_intr(brdev, sc->irq_res, INTR_TYPE_AV, pccbb_intr, sc,
	    &sc->intrhand)) {
		device_printf(brdev, "couldn't establish interrupt");
		bus_release_resource(brdev, SYS_RES_IRQ, 0, sc->irq_res);
		bus_release_resource(brdev, SYS_RES_MEMORY, CBBR_SOCKBASE,
		    sc->base_res);
		mtx_destroy(&sc->mtx);
		return (ENOMEM);
	}

	/* CSC Interrupt: Card detect interrupt on */
	pccbb_setb(sc, CBB_SOCKET_MASK, CBB_SOCKET_MASK_CD);

	/* reset interrupt */
	pccbb_set(sc, CBB_SOCKET_EVENT, pccbb_get(sc, CBB_SOCKET_EVENT));

	/* Start the thread */
	if (kthread_create(pccbb_event_thread, sc, &sc->event_thread, 0,
		"%s%d", device_get_name(sc->dev), device_get_unit(sc->dev))) {
		device_printf (sc->dev, "unable to create event thread.\n");
		panic ("pccbb_create_event_thread");
	}

	return (0);
}

static int
pccbb_detach(device_t brdev)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int numdevs;
	device_t *devlist;
	int tmp;
	int error;

	device_get_children(brdev, &devlist, &numdevs);

	error = 0;
	for (tmp = 0; tmp < numdevs; tmp++) {
		if (device_detach(devlist[tmp]) == 0)
			device_delete_child(brdev, devlist[tmp]);
		else
			error++;
	}
	free(devlist, M_TEMP);
	if (error > 0)
		return (ENXIO);

	mtx_lock(&sc->mtx);
	bus_teardown_intr(brdev, sc->irq_res, sc->intrhand);
	sc->flags |= PCCBB_KTHREAD_DONE;
	if (sc->flags & PCCBB_KTHREAD_RUNNING) {
		wakeup(sc);
		mtx_unlock(&sc->mtx);
		DEVPRINTF((brdev, "waiting for kthread exit..."));
		error = tsleep(sc, PWAIT, "pccbb-detach-wait", 60 * hz);
		if (error)
			DPRINTF(("timeout\n"));
		else
			DPRINTF(("done\n"));
	} else {
		mtx_unlock(&sc->mtx);
	}

	bus_release_resource(brdev, SYS_RES_IRQ, 0, sc->irq_res);
	bus_release_resource(brdev, SYS_RES_MEMORY, CBBR_SOCKBASE,
	    sc->base_res);
	mtx_destroy(&sc->mtx);
	return (0);
}

static int
pccbb_shutdown(device_t brdev)
{
	struct pccbb_softc *sc = (struct pccbb_softc *)device_get_softc(brdev);
	/* properly reset everything at shutdown */

	PCI_MASK_CONFIG(brdev, CBBR_BRIDGECTRL, |CBBM_BRIDGECTRL_RESET, 2);
	exca_clrb(&sc->exca, EXCA_INTR, EXCA_INTR_RESET);

	pccbb_set(sc, CBB_SOCKET_MASK, 0);

	pccbb_power(brdev, CARD_VCC_0V | CARD_VPP_0V);

	exca_write(&sc->exca, EXCA_ADDRWIN_ENABLE, 0);
	pci_write_config(brdev, CBBR_MEMBASE0, 0, 4);
	pci_write_config(brdev, CBBR_MEMLIMIT0, 0, 4);
	pci_write_config(brdev, CBBR_MEMBASE1, 0, 4);
	pci_write_config(brdev, CBBR_MEMLIMIT1, 0, 4);
	pci_write_config(brdev, CBBR_IOBASE0, 0, 4);
	pci_write_config(brdev, CBBR_IOLIMIT0, 0, 4);
	pci_write_config(brdev, CBBR_IOBASE1, 0, 4);
	pci_write_config(brdev, CBBR_IOLIMIT1, 0, 4);
	pci_write_config(brdev, PCIR_COMMAND, 0, 2);
	return (0);
}

static int
pccbb_setup_intr(device_t dev, device_t child, struct resource *irq,
  int flags, driver_intr_t *intr, void *arg, void **cookiep)
{
	int err;

	/*
	 * You aren't allowed to have fast interrupts for pccard/cardbus
	 * things since those interrupts are PCI and shared.  Since we use
	 * the PCI interrupt for the status change interrupts, it can't be
	 * free for use by the driver.  Fast interrupts must not be shared.
	 */
	if ((flags & INTR_FAST) != 0)
		return (EINVAL);
	err = bus_generic_setup_intr(dev, child, irq, flags, intr, arg,
	    cookiep);
	/*
	 * XXX need to turn on ISA interrupts, if we ever support them, but
	 * XXX for now that's all we need to do.
	 */
	return (err);
}

static int
pccbb_teardown_intr(device_t dev, device_t child, struct resource *irq,
    void *cookie)
{
	/* XXX Need to do different things for ISA interrupts. */
	return (bus_generic_teardown_intr(dev, child, irq, cookie));
}


static void
pccbb_driver_added(device_t brdev, driver_t *driver)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	device_t *devlist;
	int tmp;
	int numdevs;
	int wake;
	uint32_t sockstate;

	DEVICE_IDENTIFY(driver, brdev);
	device_get_children(brdev, &devlist, &numdevs);
	wake = 0;
	sockstate = pccbb_get(sc, CBB_SOCKET_STATE);
	for (tmp = 0; tmp < numdevs; tmp++) {
		if (device_get_state(devlist[tmp]) == DS_NOTPRESENT &&
		    device_probe_and_attach(devlist[tmp]) == 0) {
			if (devlist[tmp] == NULL)
				/* NOTHING */;
			else if (strcmp(driver->name, "cardbus") == 0) {
				sc->cbdev = devlist[tmp];
				if (((sockstate & CBB_SOCKET_STAT_CD) == 0) &&
				    (sockstate & CBB_SOCKET_STAT_CB))
					wake++;
			} else if (strcmp(driver->name, "pccard") == 0) {
				sc->pccarddev = devlist[tmp];
				if (((sockstate & CBB_SOCKET_STAT_CD) == 0) &&
				    (sockstate & CBB_SOCKET_STAT_16BIT))
					wake++;
			} else
				device_printf(brdev,
				    "Unsupported child bus: %s\n",
				    driver->name);
		}
	}
	free(devlist, M_TEMP);

	if (wake > 0) {
		if ((pccbb_get(sc, CBB_SOCKET_STATE) & CBB_SOCKET_STAT_CD)
		    == 0) {
			mtx_lock(&sc->mtx);
			wakeup(sc);
			mtx_unlock(&sc->mtx);
		}
	}
}

static void
pccbb_child_detached(device_t brdev, device_t child)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (child == sc->cbdev)
		sc->cbdev = NULL;
	else if (child == sc->pccarddev)
		sc->pccarddev = NULL;
	else
		device_printf(brdev, "Unknown child detached: %s %p/%p\n",
		    device_get_nameunit(child), sc->cbdev, sc->pccarddev);
}

static int
pccbb_card_reprobe(device_t brdev, device_t busdev)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int wake = 0;
	uint32_t sockstate;

	sockstate = pccbb_get(sc, CBB_SOCKET_STATE);

	if ((sockstate & CBB_SOCKET_STAT_CD) == 0) {
		if (busdev == sc->cbdev &&
		    (sockstate & CBB_SOCKET_STAT_CB))
			wake++;
		else if (busdev == sc->pccarddev &&
		    (sockstate & CBB_SOCKET_STAT_16BIT))
			wake++;

		if (wake > 0) {
			mtx_lock(&sc->mtx);
			wakeup(sc);
			mtx_unlock(&sc->mtx);
			return (0);
		}
		return (EBUSY);
	}
	return (ENOENT);
}

/************************************************************************/
/* Kthreads								*/
/************************************************************************/

static void
pccbb_event_thread(void *arg)
{
	struct pccbb_softc *sc = arg;
	uint32_t status;
	int err;

	/*
	 * We take out Giant here because we drop it in tsleep
	 * and need it for kthread_exit, which drops it
	 */
	mtx_lock(&Giant);
	sc->flags |= PCCBB_KTHREAD_RUNNING;
	for(;;) {
		/*
		 * Wait until it has been 1s since the last time we
		 * get an interrupt.
		 */
		tsleep (sc, PWAIT, "pccbbev", 0);
		do {
			err = tsleep (sc, PWAIT, "pccbbev", 1 * hz);
		} while (err != EWOULDBLOCK &&
		    (sc->flags & PCCBB_KTHREAD_DONE) == 0);
		mtx_lock(&sc->mtx);
		if (sc->flags & PCCBB_KTHREAD_DONE)
			break;

		status = pccbb_get(sc, CBB_SOCKET_STATE);
		if ((status & CBB_SOCKET_STAT_CD) == 0)
			pccbb_insert(sc);
		else
			pccbb_removal(sc);
		mtx_unlock(&sc->mtx);
	}
	mtx_unlock(&sc->mtx);
	sc->flags &= ~PCCBB_KTHREAD_RUNNING;
	wakeup(sc);
	/*
	 * XXX I think there's a race here.  If we wakeup in the other
	 * thread before kthread_exit is called and this routine returns,
	 * and that thread causes us to be unmapped, then we are setting
	 * ourselves up for a panic.  Make sure that I check out
	 * jhb's crash.c for a fix.
	 */
	kthread_exit(0);
}

/************************************************************************/
/* Insert/removal							*/
/************************************************************************/

static void
pccbb_insert(struct pccbb_softc *sc)
{
	uint32_t sockevent, sockstate;
	int timeout = 30;

	/*
	 * Debounce interrupt.  However, most of the debounce
	 * is done in the thread's timeout routines.
	 */
	do {
		sockevent = pccbb_get(sc, CBB_SOCKET_EVENT);
		sockstate = pccbb_get(sc, CBB_SOCKET_STATE);
	} while (sockstate & CBB_SOCKET_STAT_CD && --timeout > 0);

	if (timeout < 0) {
		device_printf (sc->dev, "insert timeout");
		return;
	}

	DEVPRINTF((sc->dev, "card inserted: event=0x%08x, state=%08x\n",
	    sockevent, sockstate));

	if (sockstate & CBB_SOCKET_STAT_16BIT) {
		if (sc->pccarddev != NULL) {
			sc->flags |= PCCBB_16BIT_CARD;
			if (CARD_ATTACH_CARD(sc->pccarddev) != 0)
				device_printf(sc->dev,
				    "PC Card card activation failed\n");
		} else {
			device_printf(sc->dev,
			    "PC Card inserted, but no pccard bus.\n");
		}
	} else if (sockstate & CBB_SOCKET_STAT_CB) {
		if (sc->cbdev != NULL) {
			sc->flags &= ~PCCBB_16BIT_CARD;
			if (CARD_ATTACH_CARD(sc->cbdev) != 0)
				device_printf(sc->dev,
				    "CardBus card activation failed\n");
		} else {
			device_printf(sc->dev,
			    "CardBUS card inserted, but no cardbus bus.\n");
		}
	} else {
		/*
		 * We should power the card down, and try again a couple of
		 * times if this happens. XXX
		 */
		device_printf (sc->dev, "Unsupported card type detected\n");
	}
}

static void
pccbb_removal(struct pccbb_softc *sc)
{
	if (sc->flags & PCCBB_16BIT_CARD && sc->pccarddev != NULL)
		CARD_DETACH_CARD(sc->pccarddev, DETACH_FORCE);
	else if ((!(sc->flags & PCCBB_16BIT_CARD)) && sc->cbdev != NULL)
		CARD_DETACH_CARD(sc->cbdev, DETACH_FORCE);
	pccbb_destroy_res(sc);
}

/************************************************************************/
/* Interrupt Handler							*/
/************************************************************************/

static void
pccbb_intr(void *arg)
{
	struct pccbb_softc *sc = arg;
	uint32_t sockevent;

	/*
	 * This ISR needs work XXX
	 */
	sockevent = pccbb_get(sc, CBB_SOCKET_EVENT);
	if (sockevent) {
		/* ack the interrupt */
		pccbb_setb(sc, CBB_SOCKET_EVENT, sockevent);

		if (sockevent & CBB_SOCKET_EVENT_CD) {
			mtx_lock(&sc->mtx);
			wakeup(sc);
			mtx_unlock(&sc->mtx);
		}
		if (sockevent & CBB_SOCKET_EVENT_CSTS) {
			DPRINTF((" cstsevent occured: 0x%08x\n",
			    pccbb_get(sc, CBB_SOCKET_STATE)));
		}
		if (sockevent & CBB_SOCKET_EVENT_POWER) {
			DPRINTF((" pwrevent occured: 0x%08x\n",
			    pccbb_get(sc, CBB_SOCKET_STATE)));
		}
		/* Other bits? */
	}

	/* Call the interrupt if we still have the card */
}

/************************************************************************/
/* Generic Power functions						*/
/************************************************************************/

static int
pccbb_detect_voltage(device_t brdev)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	uint32_t psr;
	int vol = CARD_UKN_CARD;

	psr = pccbb_get(sc, CBB_SOCKET_STATE);

	if (psr & CBB_SOCKET_STAT_5VCARD)
		vol |= CARD_5V_CARD;
	if (psr & CBB_SOCKET_STAT_3VCARD)
		vol |= CARD_3V_CARD;
	if (psr & CBB_SOCKET_STAT_XVCARD)
		vol |= CARD_XV_CARD;
	if (psr & CBB_SOCKET_STAT_YVCARD)
		vol |= CARD_YV_CARD;

	return (vol);
}

static int
pccbb_power(device_t brdev, int volts)
{
	uint32_t status, sock_ctrl;
	struct pccbb_softc *sc = device_get_softc(brdev);
	int timeout;
	uint32_t sockevent;

	DEVPRINTF((sc->dev, "pccbb_power: %s and %s [%x]\n",
	    (volts & CARD_VCCMASK) == CARD_VCC_UC ? "CARD_VCC_UC" :
	    (volts & CARD_VCCMASK) == CARD_VCC_5V ? "CARD_VCC_5V" :
	    (volts & CARD_VCCMASK) == CARD_VCC_3V ? "CARD_VCC_3V" :
	    (volts & CARD_VCCMASK) == CARD_VCC_XV ? "CARD_VCC_XV" :
	    (volts & CARD_VCCMASK) == CARD_VCC_YV ? "CARD_VCC_YV" :
	    (volts & CARD_VCCMASK) == CARD_VCC_0V ? "CARD_VCC_0V" :
	    "VCC-UNKNOWN",
	    (volts & CARD_VPPMASK) == CARD_VPP_UC ? "CARD_VPP_UC" :
	    (volts & CARD_VPPMASK) == CARD_VPP_12V ? "CARD_VPP_12V" :
	    (volts & CARD_VPPMASK) == CARD_VPP_VCC ? "CARD_VPP_VCC" :
	    (volts & CARD_VPPMASK) == CARD_VPP_0V ? "CARD_VPP_0V" :
	    "VPP-UNKNOWN",
	    volts));

	status = pccbb_get(sc, CBB_SOCKET_STATE);
	sock_ctrl = pccbb_get(sc, CBB_SOCKET_CONTROL);

	switch (volts & CARD_VCCMASK) {
	case CARD_VCC_UC:
		break;
	case CARD_VCC_5V:
		if (CBB_SOCKET_STAT_5VCARD & status) { /* check 5 V card */
			sock_ctrl &= ~CBB_SOCKET_CTRL_VCCMASK;
			sock_ctrl |= CBB_SOCKET_CTRL_VCC_5V;
		} else {
			device_printf(sc->dev,
			    "BAD voltage request: no 5 V card\n");
		}
		break;
	case CARD_VCC_3V:
		if (CBB_SOCKET_STAT_3VCARD & status) {
			sock_ctrl &= ~CBB_SOCKET_CTRL_VCCMASK;
			sock_ctrl |= CBB_SOCKET_CTRL_VCC_3V;
		} else {
			device_printf(sc->dev,
			    "BAD voltage request: no 3.3 V card\n");
		}
		break;
	case CARD_VCC_0V:
		sock_ctrl &= ~CBB_SOCKET_CTRL_VCCMASK;
		break;
	default:
		return (0);			/* power NEVER changed */
		break;
	}

	switch (volts & CARD_VPPMASK) {
	case CARD_VPP_UC:
		break;
	case CARD_VPP_0V:
		sock_ctrl &= ~CBB_SOCKET_CTRL_VPPMASK;
		break;
	case CARD_VPP_VCC:
		sock_ctrl &= ~CBB_SOCKET_CTRL_VPPMASK;
		sock_ctrl |= ((sock_ctrl >> 4) & 0x07);
		break;
	case CARD_VPP_12V:
		sock_ctrl &= ~CBB_SOCKET_CTRL_VPPMASK;
		sock_ctrl |= CBB_SOCKET_CTRL_VPP_12V;
		break;
	}

	if (pccbb_get(sc, CBB_SOCKET_CONTROL) == sock_ctrl)
		return (1); /* no change necessary */

	pccbb_set(sc, CBB_SOCKET_CONTROL, sock_ctrl);
	status = pccbb_get(sc, CBB_SOCKET_STATE);

	/* 
	 * XXX This busy wait is bogus.  We should wait for a power
	 * interrupt and then whine if the status is bad.  If we're
	 * worried about the card not coming up, then we should also
	 * schedule a timeout which we can cacel in the power interrupt.
	 */
	timeout = 20;
	do {
		DELAY(20*1000);
		sockevent = pccbb_get(sc, CBB_SOCKET_EVENT);
	} while (!(sockevent & CBB_SOCKET_EVENT_POWER) && --timeout > 0);
	/* reset event status */
	/* XXX should only reset EVENT_POWER */
	pccbb_set(sc, CBB_SOCKET_EVENT, sockevent);
	if (timeout < 0) {
		printf ("VCC supply failed.\n");
		return (0);
	}

	/* XXX
	 * delay 400 ms: thgough the standard defines that the Vcc set-up time
	 * is 20 ms, some PC-Card bridge requires longer duration.
	 * XXX Note: We should check the stutus AFTER the delay to give time
	 * for things to stabilize.
	 */
	DELAY(400*1000);

	if (status & CBB_SOCKET_STAT_BADVCC) {
		device_printf(sc->dev,
		    "bad Vcc request. ctrl=0x%x, status=0x%x\n",
		    sock_ctrl ,status);
		printf("pccbb_power: %s and %s [%x]\n",
		    (volts & CARD_VCCMASK) == CARD_VCC_UC ? "CARD_VCC_UC" :
		    (volts & CARD_VCCMASK) == CARD_VCC_5V ? "CARD_VCC_5V" :
		    (volts & CARD_VCCMASK) == CARD_VCC_3V ? "CARD_VCC_3V" :
		    (volts & CARD_VCCMASK) == CARD_VCC_XV ? "CARD_VCC_XV" :
		    (volts & CARD_VCCMASK) == CARD_VCC_YV ? "CARD_VCC_YV" :
		    (volts & CARD_VCCMASK) == CARD_VCC_0V ? "CARD_VCC_0V" :
		    "VCC-UNKNOWN",
		    (volts & CARD_VPPMASK) == CARD_VPP_UC ? "CARD_VPP_UC" :
		    (volts & CARD_VPPMASK) == CARD_VPP_12V ? "CARD_VPP_12V":
		    (volts & CARD_VPPMASK) == CARD_VPP_VCC ? "CARD_VPP_VCC":
		    (volts & CARD_VPPMASK) == CARD_VPP_0V ? "CARD_VPP_0V" :
		    "VPP-UNKNOWN",
		    volts);
		return (0);
	}
	return (1);		/* power changed correctly */
}

/*
 * detect the voltage for the card, and set it.  Since the power
 * used is the square of the voltage, lower voltages is a big win
 * and what Windows does (and what Microsoft prefers).  The MS paper
 * also talks about preferring the CIS entry as well.
 */
static int
pccbb_do_power(device_t brdev)
{
	int voltage;

	/* Prefer lowest voltage supported */
	voltage = pccbb_detect_voltage(brdev);
	pccbb_power(brdev, CARD_VCC_0V | CARD_VPP_0V);
	if (voltage & CARD_YV_CARD)
		pccbb_power(brdev, CARD_VCC_YV | CARD_VPP_VCC);
	else if (voltage & CARD_XV_CARD)
		pccbb_power(brdev, CARD_VCC_XV | CARD_VPP_VCC);
	else if (voltage & CARD_3V_CARD)
		pccbb_power(brdev, CARD_VCC_3V | CARD_VPP_VCC);
	else if (voltage & CARD_5V_CARD)
		pccbb_power(brdev, CARD_VCC_5V | CARD_VPP_VCC);
	else {
		device_printf(brdev, "Unknown card voltage\n");
		return (ENXIO);
	}
	return (0);
}

/************************************************************************/
/* Cardbus power functions						*/
/************************************************************************/

static void
pccbb_cardbus_reset(device_t brdev)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int delay_us;

	delay_us = sc->chipset == CB_RF5C47X ? 400*1000 : 20*1000;

	PCI_MASK_CONFIG(brdev, CBBR_BRIDGECTRL, |CBBM_BRIDGECTRL_RESET, 2);

	DELAY(delay_us);

	/* If a card exists, unreset it! */
	if ((pccbb_get(sc, CBB_SOCKET_STATE) & CBB_SOCKET_STAT_CD) == 0) {
		PCI_MASK_CONFIG(brdev, CBBR_BRIDGECTRL,
		    &~CBBM_BRIDGECTRL_RESET, 2);
		DELAY(delay_us);
	}
}

static int
pccbb_cardbus_power_enable_socket(device_t brdev, device_t child)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int err;

	if ((pccbb_get(sc, CBB_SOCKET_STATE) & CBB_SOCKET_STAT_CD) ==
	    CBB_SOCKET_STAT_CD)
		return (ENODEV);

	err = pccbb_do_power(brdev);
	if (err)
		return (err);
	pccbb_cardbus_reset(brdev);
	return (0);
}

static void
pccbb_cardbus_power_disable_socket(device_t brdev, device_t child)
{
	pccbb_power(brdev, CARD_VCC_0V | CARD_VPP_0V);
	pccbb_cardbus_reset(brdev);
}

/************************************************************************/
/* Cardbus Resource							*/
/************************************************************************/

static int
pccbb_cardbus_io_open(device_t brdev, int win, uint32_t start, uint32_t end)
{
	int basereg;
	int limitreg;

	if ((win < 0) || (win > 1)) {
		DEVPRINTF((brdev,
		    "pccbb_cardbus_io_open: window out of range %d\n", win));
		return (EINVAL);
	}

	basereg = win * 8 + CBBR_IOBASE0;
	limitreg = win * 8 + CBBR_IOLIMIT0;

	pci_write_config(brdev, basereg, start, 4);
	pci_write_config(brdev, limitreg, end, 4);
	return (0);
}

static int
pccbb_cardbus_mem_open(device_t brdev, int win, uint32_t start, uint32_t end)
{
	int basereg;
	int limitreg;

	if ((win < 0) || (win > 1)) {
		DEVPRINTF((brdev,
		    "pccbb_cardbus_mem_open: window out of range %d\n", win));
		return (EINVAL);
	}

	basereg = win*8 + CBBR_MEMBASE0;
	limitreg = win*8 + CBBR_MEMLIMIT0;

	pci_write_config(brdev, basereg, start, 4);
	pci_write_config(brdev, limitreg, end, 4);
	return (0);
}

/*
 * XXX The following function belongs in the pci bus layer.
 */
static void
pccbb_cardbus_auto_open(struct pccbb_softc *sc, int type)
{
	uint32_t starts[2];
	uint32_t ends[2];
	struct pccbb_reslist *rle;
	int align;
	int prefetchable[2];
	uint32_t reg;

	starts[0] = starts[1] = 0xffffffff;
	ends[0] = ends[1] = 0;

	if (type == SYS_RES_MEMORY)
		align = CBB_MEMALIGN;
	else if (type == SYS_RES_IOPORT)
		align = CBB_IOALIGN;
	else
		align = 1;

	SLIST_FOREACH(rle, &sc->rl, link) {
		if (rle->type != type)
			;
		else if (rle->res == NULL) {
			device_printf(sc->dev, "WARNING: Resource not reserved?  "
			    "(type=%d, addr=%lx)\n",
			    rle->type, rman_get_start(rle->res));
		} else if (!(rman_get_flags(rle->res) & RF_ACTIVE)) {
			/* XXX */
		} else if (starts[0] == 0xffffffff) {
			starts[0] = rman_get_start(rle->res);
			ends[0] = rman_get_end(rle->res);
			prefetchable[0] =
			    rman_get_flags(rle->res) & RF_PREFETCHABLE;
		} else if (rman_get_end(rle->res) > ends[0] &&
		    rman_get_start(rle->res) - ends[0] <
		    PCCBB_AUTO_OPEN_SMALLHOLE && prefetchable[0] ==
		    (rman_get_flags(rle->res) & RF_PREFETCHABLE)) {
			ends[0] = rman_get_end(rle->res);
		} else if (rman_get_start(rle->res) < starts[0] &&
		    starts[0] - rman_get_end(rle->res) <
		    PCCBB_AUTO_OPEN_SMALLHOLE && prefetchable[0] ==
		    (rman_get_flags(rle->res) & RF_PREFETCHABLE)) {
			starts[0] = rman_get_start(rle->res);
		} else if (starts[1] == 0xffffffff) {
			starts[1] = rman_get_start(rle->res);
			ends[1] = rman_get_end(rle->res);
			prefetchable[1] =
			    rman_get_flags(rle->res) & RF_PREFETCHABLE;
		} else if (rman_get_end(rle->res) > ends[1] &&
		    rman_get_start(rle->res) - ends[1] <
		    PCCBB_AUTO_OPEN_SMALLHOLE && prefetchable[1] ==
		    (rman_get_flags(rle->res) & RF_PREFETCHABLE)) {
			ends[1] = rman_get_end(rle->res);
		} else if (rman_get_start(rle->res) < starts[1] &&
		    starts[1] - rman_get_end(rle->res) <
		    PCCBB_AUTO_OPEN_SMALLHOLE && prefetchable[1] ==
		    (rman_get_flags(rle->res) & RF_PREFETCHABLE)) {
			starts[1] = rman_get_start(rle->res);
		} else {
			uint32_t diffs[2];
			int win;

			diffs[0] = diffs[1] = 0xffffffff;
			if (rman_get_start(rle->res) > ends[0])
				diffs[0] = rman_get_start(rle->res) - ends[0];
			else if (rman_get_end(rle->res) < starts[0])
				diffs[0] = starts[0] - rman_get_end(rle->res);
			if (rman_get_start(rle->res) > ends[1])
				diffs[1] = rman_get_start(rle->res) - ends[1];
			else if (rman_get_end(rle->res) < starts[1])
				diffs[1] = starts[1] - rman_get_end(rle->res);

			win = (diffs[0] <= diffs[1])?0:1;
			if (rman_get_start(rle->res) > ends[win])
				ends[win] = rman_get_end(rle->res);
			else if (rman_get_end(rle->res) < starts[win])
				starts[win] = rman_get_start(rle->res);
			if (!(rman_get_flags(rle->res) & RF_PREFETCHABLE))
				prefetchable[win] = 0;
		}

		if (starts[0] != 0xffffffff)
			starts[0] -= starts[0] % align;
		if (starts[1] != 0xffffffff)
			starts[1] -= starts[1] % align;
		if (ends[0] % align != 0)
			ends[0] += align - ends[0]%align - 1;
		if (ends[1] % align != 0)
			ends[1] += align - ends[1]%align - 1;
	}

	if (type == SYS_RES_MEMORY) {
		pccbb_cardbus_mem_open(sc->dev, 0, starts[0], ends[0]);
		pccbb_cardbus_mem_open(sc->dev, 1, starts[1], ends[1]);
		reg = pci_read_config(sc->dev, CBBR_BRIDGECTRL, 2);
		reg &= ~(CBBM_BRIDGECTRL_PREFETCH_0|
		    CBBM_BRIDGECTRL_PREFETCH_1);
		reg |= (prefetchable[0]?CBBM_BRIDGECTRL_PREFETCH_0:0)|
		    (prefetchable[1]?CBBM_BRIDGECTRL_PREFETCH_1:0);
		pci_write_config(sc->dev, CBBR_BRIDGECTRL, reg, 2);
	} else if (type == SYS_RES_IOPORT) {
		pccbb_cardbus_io_open(sc->dev, 0, starts[0], ends[0]);
		pccbb_cardbus_io_open(sc->dev, 1, starts[1], ends[1]);
	}
}

static int
pccbb_cardbus_activate_resource(device_t brdev, device_t child, int type,
    int rid, struct resource *res)
{
	int ret;

	ret = BUS_ACTIVATE_RESOURCE(device_get_parent(brdev), child,
	    type, rid, res);
	if (ret != 0)
		return (ret);
	pccbb_cardbus_auto_open(device_get_softc(brdev), type);
	return (0);
}

static int
pccbb_cardbus_deactivate_resource(device_t brdev, device_t child, int type,
    int rid, struct resource *res)
{
	int ret;

	ret = BUS_DEACTIVATE_RESOURCE(device_get_parent(brdev), child,
	    type, rid, res);
	if (ret != 0)
		return (ret);
	pccbb_cardbus_auto_open(device_get_softc(brdev), type);
	return (0);
}

static struct resource *
pccbb_cardbus_alloc_resource(device_t brdev, device_t child, int type,
    int *rid, u_long start, u_long end, u_long count, uint flags)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int tmp;
	struct resource *res;

	switch (type) {
	case SYS_RES_IRQ:
		tmp = rman_get_start(sc->irq_res);
		if (start > tmp || end < tmp || count != 1) {
			device_printf(child, "requested interrupt %ld-%ld,"
			    "count = %ld not supported by pccbb\n",
			    start, end, count);
			return (NULL);
		}
		start = end = tmp;
		break;
	case SYS_RES_IOPORT:
		if (start <= pccbb_start_32_io)
			start = pccbb_start_32_io;
		if (end < start)
			end = start;
		break;
	case SYS_RES_MEMORY:
		if (start <= pccbb_start_mem)
			start = pccbb_start_mem;
		if (end < start)
			end = start;
		break;
	}

	res = BUS_ALLOC_RESOURCE(device_get_parent(brdev), child, type, rid,
	    start, end, count, flags & ~RF_ACTIVE);
	if (res == NULL) {
		printf("pccbb alloc res fail\n");
		return (NULL);
	}
	pccbb_insert_res(sc, res, type, *rid);
	if (flags & RF_ACTIVE)
		if (bus_activate_resource(child, type, *rid, res) != 0) {
			bus_release_resource(child, type, *rid, res);
			return (NULL);
		}

	return (res);
}

static int
pccbb_cardbus_release_resource(device_t brdev, device_t child, int type,
    int rid, struct resource *res)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int error;

	if (rman_get_flags(res) & RF_ACTIVE) {
		error = bus_deactivate_resource(child, type, rid, res);
		if (error != 0)
			return (error);
	}
	pccbb_remove_res(sc, res);
	return (BUS_RELEASE_RESOURCE(device_get_parent(brdev), child,
	    type, rid, res));
}

/************************************************************************/
/* PC Card Power Functions						*/
/************************************************************************/

static int
pccbb_pcic_power_enable_socket(device_t brdev, device_t child)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int err;

	DPRINTF(("pccbb_pcic_socket_enable:\n"));

	/* power down/up the socket to reset */
	err = pccbb_do_power(brdev);
	if (err)
		return (err);
	exca_reset(&sc->exca, child);

	return (0);
}

static void
pccbb_pcic_power_disable_socket(device_t brdev, device_t child)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	DPRINTF(("pccbb_pcic_socket_disable\n"));

	/* reset signal asserting... */
	exca_clrb(&sc->exca, EXCA_INTR, EXCA_INTR_RESET);
	DELAY(2*1000);

	/* power down the socket */
	pccbb_power(brdev, CARD_VCC_0V | CARD_VPP_0V);
	exca_clrb(&sc->exca, EXCA_PWRCTL, EXCA_PWRCTL_OE);

	/* wait 300ms until power fails (Tpf). */
	DELAY(300 * 1000);
}

/************************************************************************/
/* POWER methods							*/
/************************************************************************/

static int
pccbb_power_enable_socket(device_t brdev, device_t child)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (sc->flags & PCCBB_16BIT_CARD)
		return (pccbb_pcic_power_enable_socket(brdev, child));
	else
		return (pccbb_cardbus_power_enable_socket(brdev, child));
}

static void
pccbb_power_disable_socket(device_t brdev, device_t child)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	if (sc->flags & PCCBB_16BIT_CARD)
		pccbb_pcic_power_disable_socket(brdev, child);
	else
		pccbb_cardbus_power_disable_socket(brdev, child);
}
static int
pccbb_pcic_activate_resource(device_t brdev, device_t child, int type, int rid,
    struct resource *res)
{
	int err;
	struct pccbb_softc *sc = device_get_softc(brdev);
	if (!(rman_get_flags(res) & RF_ACTIVE)) { /* not already activated */
		switch (type) {
		case SYS_RES_IOPORT:
			err = exca_io_map(&sc->exca, 0, res);
			break;
		case SYS_RES_MEMORY:
			err = exca_mem_map(&sc->exca, 0, res);
			break;
		default:
			err = 0;
			break;
		}
		if (err)
			return (err);

	}
	return (BUS_ACTIVATE_RESOURCE(device_get_parent(brdev), child,
	    type, rid, res));
}

static int
pccbb_pcic_deactivate_resource(device_t brdev, device_t child, int type,
    int rid, struct resource *res)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (rman_get_flags(res) & RF_ACTIVE) { /* if activated */
		switch (type) {
		case SYS_RES_IOPORT:
			if (exca_io_unmap_res(&sc->exca, res))
				return (ENOENT);
			break;
		case SYS_RES_MEMORY:
			if (exca_mem_unmap_res(&sc->exca, res))
				return (ENOENT);
			break;
		}
	}
	return (BUS_DEACTIVATE_RESOURCE(device_get_parent(brdev), child,
	    type, rid, res));
}

static struct resource *
pccbb_pcic_alloc_resource(device_t brdev, device_t child, int type, int *rid,
    u_long start, u_long end, u_long count, uint flags)
{
	struct resource *res = NULL;
	struct pccbb_softc *sc = device_get_softc(brdev);
	int tmp;

	switch (type) {
	case SYS_RES_MEMORY:
		if (start < pccbb_start_mem)
			start = pccbb_start_mem;
		if (end < start)
			end = start;
		flags = (flags & ~RF_ALIGNMENT_MASK) |
		    rman_make_alignment_flags(CBB_MEMALIGN);
		break;
	case SYS_RES_IOPORT:
		if (start < pccbb_start_16_io)
			start = pccbb_start_16_io;
		if (end < start)
			end = start;
		break;
	case SYS_RES_IRQ:
		tmp = rman_get_start(sc->irq_res);
		if (start > tmp || end < tmp || count != 1) {
			device_printf(child, "requested interrupt %ld-%ld,"
			    "count = %ld not supported by pccbb\n",
			    start, end, count);
			return (NULL);
		}
		flags |= RF_SHAREABLE;
		start = end = rman_get_start(sc->irq_res);
		break;
	}
	res = BUS_ALLOC_RESOURCE(device_get_parent(brdev), child, type, rid,
	    start, end, count, flags & ~RF_ACTIVE);
	if (res == NULL)
		return (NULL);
	pccbb_insert_res(sc, res, type, *rid);
	if (flags & RF_ACTIVE) {
		if (bus_activate_resource(child, type, *rid, res) != 0) {
			bus_release_resource(child, type, *rid, res);
			return (NULL);
		}
	}

	return (res);
}

static int
pccbb_pcic_release_resource(device_t brdev, device_t child, int type,
    int rid, struct resource *res)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	int error;

	if (rman_get_flags(res) & RF_ACTIVE) {
		error = bus_deactivate_resource(child, type, rid, res);
		if (error != 0)
			return (error);
	}
	pccbb_remove_res(sc, res);
	return (BUS_RELEASE_RESOURCE(device_get_parent(brdev), child,
	    type, rid, res));
}

/************************************************************************/
/* PC Card methods							*/
/************************************************************************/

static int
pccbb_pcic_set_res_flags(device_t brdev, device_t child, int type, int rid,
    uint32_t flags)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	struct resource *res;

	if (type != SYS_RES_MEMORY)
		return (EINVAL);
	res = pccbb_find_res(sc, type, rid);
	if (res == NULL) {
		device_printf(brdev,
		    "set_res_flags: specified rid not found\n");
		return (ENOENT);
	}
	return (exca_mem_set_flags(&sc->exca, res, flags));
}

static int
pccbb_pcic_set_memory_offset(device_t brdev, device_t child, int rid,
    uint32_t cardaddr, uint32_t *deltap)
{
	struct pccbb_softc *sc = device_get_softc(brdev);
	struct resource *res;

	res = pccbb_find_res(sc, SYS_RES_MEMORY, rid);
	if (res == NULL) {
		device_printf(brdev,
		    "set_memory_offset: specified rid not found\n");
		return (ENOENT);
	}
	return (exca_mem_set_offset(&sc->exca, res, cardaddr, deltap));
}

/************************************************************************/
/* BUS Methods								*/
/************************************************************************/


static int
pccbb_activate_resource(device_t brdev, device_t child, int type, int rid,
    struct resource *r)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (sc->flags & PCCBB_16BIT_CARD)
		return (pccbb_pcic_activate_resource(brdev, child, type, rid, r));
	else
		return (pccbb_cardbus_activate_resource(brdev, child, type, rid,
		    r));
}

static int
pccbb_deactivate_resource(device_t brdev, device_t child, int type,
    int rid, struct resource *r)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (sc->flags & PCCBB_16BIT_CARD)
		return (pccbb_pcic_deactivate_resource(brdev, child, type,
		    rid, r));
	else
		return (pccbb_cardbus_deactivate_resource(brdev, child, type,
		    rid, r));
}

static struct resource *
pccbb_alloc_resource(device_t brdev, device_t child, int type, int *rid,
    u_long start, u_long end, u_long count, uint flags)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (sc->flags & PCCBB_16BIT_CARD)
		return (pccbb_pcic_alloc_resource(brdev, child, type, rid,
		    start, end, count, flags));
	else
		return (pccbb_cardbus_alloc_resource(brdev, child, type, rid,
		    start, end, count, flags));
}

static int
pccbb_release_resource(device_t brdev, device_t child, int type, int rid,
    struct resource *r)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	if (sc->flags & PCCBB_16BIT_CARD)
		return (pccbb_pcic_release_resource(brdev, child, type,
		    rid, r));
	else
		return (pccbb_cardbus_release_resource(brdev, child, type,
		    rid, r));
}

static int
pccbb_read_ivar(device_t brdev, device_t child, int which, uintptr_t *result)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	switch (which) {
	case PCIB_IVAR_BUS:
		*result = sc->secbus;
		return (0);
	}
	return (ENOENT);
}

static int
pccbb_write_ivar(device_t brdev, device_t child, int which, uintptr_t value)
{
	struct pccbb_softc *sc = device_get_softc(brdev);

	switch (which) {
	case PCIB_IVAR_BUS:
		sc->secbus = value;
		break;
	}
	return (ENOENT);
}

/************************************************************************/
/* PCI compat methods							*/
/************************************************************************/

static int
pccbb_maxslots(device_t brdev)
{
	return (0);
}

static uint32_t
pccbb_read_config(device_t brdev, int b, int s, int f, int reg, int width)
{
	/*
	 * Pass through to the next ppb up the chain (i.e. our grandparent).
	 */
	return (PCIB_READ_CONFIG(device_get_parent(device_get_parent(brdev)),
	    b, s, f, reg, width));
}

static void
pccbb_write_config(device_t brdev, int b, int s, int f, int reg, uint32_t val,
    int width)
{
	/*
	 * Pass through to the next ppb up the chain (i.e. our grandparent).
	 */
	PCIB_WRITE_CONFIG(device_get_parent(device_get_parent(brdev)),
	    b, s, f, reg, val, width);
}

static int
pccbb_suspend(device_t self)
{
	int			error = 0;
	struct pccbb_softc*	sc = device_get_softc(self);

	bus_teardown_intr(self, sc->irq_res, sc->intrhand);
	error = bus_generic_suspend(self);
	return (error);
}

static int
pccbb_resume(device_t self)
{
	int	error = 0;
	struct pccbb_softc *sc = (struct pccbb_softc *)device_get_softc(self);
	uint32_t tmp;

	pci_write_config(self, CBBR_SOCKBASE, rman_get_start(sc->base_res), 4);
	DEVPRINTF((self, "PCI Memory allocated: %08lx\n",
	    rman_get_start(sc->base_res)));

	pccbb_chipinit(sc);

	/* re-establish the interrupt. */
	if (bus_setup_intr(self, sc->irq_res, INTR_TYPE_AV, pccbb_intr, sc,
	    &sc->intrhand)) {
		device_printf(self, "couldn't re-establish interrupt");
		bus_release_resource(self, SYS_RES_IRQ, 0, sc->irq_res);
		bus_release_resource(self, SYS_RES_MEMORY, CBBR_SOCKBASE,
		    sc->base_res);
		sc->irq_res = NULL;
		sc->base_res = NULL;
		return (ENOMEM);
	}

	/* CSC Interrupt: Card detect interrupt on */
	pccbb_setb(sc, CBB_SOCKET_MASK, CBB_SOCKET_MASK_CD);

	/* reset interrupt */
	tmp = pccbb_get(sc, CBB_SOCKET_EVENT);
	pccbb_set(sc, CBB_SOCKET_EVENT, tmp);

	/*
	 * Some BIOSes will not save the BARs for the pci chips, so we
	 * must do it ourselves.  If the BAR is reset to 0 for an I/O
	 * device, it will read back as 0x1, so no explicit test for
	 * memory devices are needed.
	 *
	 * Note: The PCI bus code should do this automatically for us on
	 * suspend/resume, but until it does, we have to cope.
	 */
	if (pci_read_config(self, CBBR_SOCKBASE, 4) == 0)
                pci_write_config(self, CBBR_SOCKBASE,
		    rman_get_start(sc->base_res), 4);

	error = bus_generic_resume(self);

	return (error);
}

static device_method_t pccbb_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			pccbb_probe),
	DEVMETHOD(device_attach,		pccbb_attach),
	DEVMETHOD(device_detach,		pccbb_detach),
	DEVMETHOD(device_shutdown,		pccbb_shutdown),
	DEVMETHOD(device_suspend,		pccbb_suspend),
	DEVMETHOD(device_resume,		pccbb_resume),

	/* bus methods */
	DEVMETHOD(bus_print_child,		bus_generic_print_child),
	DEVMETHOD(bus_read_ivar,		pccbb_read_ivar),
	DEVMETHOD(bus_write_ivar,		pccbb_write_ivar),
	DEVMETHOD(bus_alloc_resource,		pccbb_alloc_resource),
	DEVMETHOD(bus_release_resource,		pccbb_release_resource),
	DEVMETHOD(bus_activate_resource,	pccbb_activate_resource),
	DEVMETHOD(bus_deactivate_resource,	pccbb_deactivate_resource),
	DEVMETHOD(bus_driver_added,		pccbb_driver_added),
	DEVMETHOD(bus_child_detached,		pccbb_child_detached),
	DEVMETHOD(bus_setup_intr,		pccbb_setup_intr),
	DEVMETHOD(bus_teardown_intr,		pccbb_teardown_intr),

	/* 16-bit card interface */
	DEVMETHOD(card_set_res_flags,		pccbb_pcic_set_res_flags),
	DEVMETHOD(card_set_memory_offset,	pccbb_pcic_set_memory_offset),
	DEVMETHOD(card_reprobe_card,		pccbb_card_reprobe),

	/* power interface */
	DEVMETHOD(power_enable_socket,		pccbb_power_enable_socket),
	DEVMETHOD(power_disable_socket,		pccbb_power_disable_socket),

	/* pcib compatibility interface */
	DEVMETHOD(pcib_maxslots,		pccbb_maxslots),
	DEVMETHOD(pcib_read_config,		pccbb_read_config),
	DEVMETHOD(pcib_write_config,		pccbb_write_config),
	{0,0}
};

static driver_t pccbb_driver = {
	"pccbb",
	pccbb_methods,
	sizeof(struct pccbb_softc)
};

static devclass_t pccbb_devclass;

DRIVER_MODULE(pccbb, pci, pccbb_driver, pccbb_devclass, 0, 0);
