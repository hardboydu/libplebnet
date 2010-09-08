/*-
 * Copyright (c) 2003-2009 RMI Corporation
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
 * 3. Neither the name of RMI Corporation, nor the names of its contributors,
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 * RMI_BSD */

/*
 * The XLR device supports upto four 10/100/1000 Ethernet MACs and upto
 * two 10G Ethernet MACs (of XGMII). Alternatively, each 10G port can used
 * as a SPI-4 interface, with 8 ports per such interface. The MACs are
 * encapsulated in another hardware block referred to as network accelerator,
 * such that there are three instances of these in a XLR. One of them controls
 * the four 1G RGMII ports while one each of the others controls an XGMII port.
 * Enabling MACs requires configuring the corresponding network accelerator
 * and the individual port.
 * The XLS device supports upto 8 10/100/1000 Ethernet MACs or max 2 10G
 * Ethernet MACs. The 1G MACs are of SGMII and 10G MACs are of XAUI
 * interface. These ports are part of two network accelerators.
 * The nlge driver configures and initializes non-SPI4 Ethernet ports in the
 * XLR/XLS devices and enables data transfer on them.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#ifdef HAVE_KERNEL_OPTION_HEADERS
#include "opt_device_polling.h"
#endif

#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/limits.h>
#include <sys/bus.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#define __RMAN_RESOURCE_VISIBLE
#include <sys/rman.h>
#include <sys/taskqueue.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/bpf.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/uma.h>

#include <machine/reg.h>
#include <machine/cpu.h>
#include <machine/mips_opcode.h>
#include <machine/asm.h>
#include <machine/cpuregs.h>
#include <machine/param.h>
#include <machine/intr_machdep.h>
#include <machine/clock.h>	/* for DELAY */
#include <machine/bus.h>
#include <machine/resource.h>

#include <mips/rmi/interrupt.h>
#include <mips/rmi/msgring.h>
#include <mips/rmi/iomap.h>
#include <mips/rmi/pic.h>
#include <mips/rmi/board.h>
#include <mips/rmi/rmi_mips_exts.h>
#include <mips/rmi/rmi_boot_info.h>
#include <mips/rmi/dev/xlr/atx_cpld.h>
#include <mips/rmi/dev/xlr/xgmac_mdio.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>
#include "miidevs.h"
#include <dev/mii/brgphyreg.h>
#include "miibus_if.h"

#include <mips/rmi/dev/nlge/if_nlge.h>

MODULE_DEPEND(nlna, nlge, 1, 1, 1);
MODULE_DEPEND(nlge, ether, 1, 1, 1);
MODULE_DEPEND(nlge, miibus, 1, 1, 1);

/* Network accelarator entry points */
static int      nlna_probe(device_t);
static int      nlna_attach(device_t);
static int      nlna_detach(device_t);
static int      nlna_suspend(device_t);
static int      nlna_resume(device_t);
static int 	nlna_shutdown(device_t);

/* GMAC port entry points */
static int	nlge_probe(device_t);
static int	nlge_attach(device_t);
static int	nlge_detach(device_t);
static int	nlge_suspend(device_t);
static int	nlge_resume(device_t);
static void	nlge_init(void *);
static int	nlge_ioctl(struct ifnet *, u_long, caddr_t);
static void	nlge_start(struct ifnet *);
static void 	nlge_rx(struct nlge_softc *sc, vm_paddr_t paddr, int len);

static int	nlge_mii_write(struct device *, int, int, int);
static int	nlge_mii_read(struct device *, int, int);
static void	nlge_mac_mii_statchg(device_t);
static int	nlge_mediachange(struct ifnet *ifp);
static void	nlge_mediastatus(struct ifnet *ifp, struct ifmediareq *ifmr);

/* Other internal/helper functions */
static void 	*get_buf(void);
static struct mbuf *get_mbuf(void);

static void	nlna_add_to_port_set(struct nlge_port_set *pset,
    struct nlge_softc *sc);
static void	nlna_config_pde(struct nlna_softc *);
static void	nlna_config_parser(struct nlna_softc *);
static void	nlna_config_classifier(struct nlna_softc *);
static void	nlna_config_fifo_spill_area(struct nlna_softc *sc);
static void	nlna_config_common(struct nlna_softc *);
static void	nlna_disable_ports(struct nlna_softc *sc);
static void	nlna_enable_intr(struct nlna_softc *sc);
static void	nlna_disable_intr(struct nlna_softc *sc);
static void	nlna_enable_ports(struct nlna_softc *sc);
static void	nlna_get_all_softc(device_t iodi_dev,
    struct nlna_softc **sc_vec, uint32_t vec_sz);
static void 	nlna_hw_init(struct nlna_softc *sc);
static int 	nlna_is_last_active_na(struct nlna_softc *sc);
static void	nlna_media_specific_config(struct nlna_softc *sc);
static void 	nlna_reset_ports(struct nlna_softc *sc,
    struct xlr_gmac_block_t *blk);
static struct nlna_softc *nlna_sc_init(device_t dev,
    struct xlr_gmac_block_t *blk);
static __inline__ int nlna_send_free_desc(struct nlna_softc *nlna,
    vm_paddr_t addr);
static void	nlna_setup_intr(struct nlna_softc *sc);
static void	nlna_smp_update_pde(void *dummy __unused);
static void	nlna_submit_rx_free_desc(struct nlna_softc *sc,
    uint32_t n_desc);

static int	nlge_gmac_config_speed(struct nlge_softc *, int quick);
static void	nlge_hw_init(struct nlge_softc *sc);
static int	nlge_if_init(struct nlge_softc *sc);
static void	nlge_intr(void *arg);
static int	nlge_irq_init(struct nlge_softc *sc);
static void	nlge_irq_fini(struct nlge_softc *sc);
static void	nlge_media_specific_init(struct nlge_softc *sc);
static void	nlge_mii_init(device_t dev, struct nlge_softc *sc);
static int	nlge_mii_read_internal(xlr_reg_t *mii_base, int phyaddr,
    int regidx);
static void 	nlge_mii_write_internal(xlr_reg_t *mii_base, int phyaddr,
    int regidx, int regval);
void 		nlge_msgring_handler(int bucket, int size, int code,
    int stid, struct msgrng_msg *msg, void *data);
static void 	nlge_port_disable(int id, xlr_reg_t *base, int port_type);
static void 	nlge_port_enable(struct nlge_softc *sc);
static void 	nlge_read_mac_addr(struct nlge_softc *sc);
static void	nlge_sc_init(struct nlge_softc *sc, device_t dev,
    struct xlr_gmac_port *port_info);
static void 	nlge_set_mac_addr(struct nlge_softc *sc);
static void	nlge_set_port_attribs(struct nlge_softc *,
    struct xlr_gmac_port *);
static void 	nlge_sgmii_init(struct nlge_softc *sc);
static void	nlge_start_locked(struct ifnet *ifp, struct nlge_softc *sc);

static int	prepare_fmn_message(struct nlge_softc *sc,
    struct msgrng_msg *msg, uint32_t *n_entries, struct mbuf *m_head,
    uint64_t fr_stid, struct nlge_tx_desc **tx_desc);

static void	release_mbuf(uint64_t phy_addr);
static void 	release_tx_desc(vm_paddr_t phy_addr);
static int	send_fmn_msg_tx(struct nlge_softc *, struct msgrng_msg *,
    uint32_t n_entries);

//#define DEBUG
#ifdef DEBUG
static int	mac_debug = 1;
static int 	reg_dump = 0;
#undef PDEBUG
#define PDEBUG(fmt, args...) \
        do {\
            if (mac_debug) {\
                printf("[%s@%d|%s]: cpu_%d: " fmt, \
                __FILE__, __LINE__, __FUNCTION__,  PCPU_GET(cpuid), ##args);\
            }\
        } while(0);

/* Debug/dump functions */
static void 	dump_reg(xlr_reg_t *addr, uint32_t offset, char *name);
static void	dump_gmac_registers(struct nlge_softc *);
static void	dump_na_registers(xlr_reg_t *base, int port_id);
static void	dump_mac_stats(struct nlge_softc *sc);
static void 	dump_mii_regs(struct nlge_softc *sc) __attribute__((used));
static void 	dump_mii_data(struct mii_data *mii) __attribute__((used));
static void	dump_board_info(struct xlr_board_info *);
static void	dump_pcs_regs(struct nlge_softc *sc, int phy);

#else
#undef PDEBUG
#define PDEBUG(fmt, args...)
#define dump_reg(a, o, n)		/* nop */
#define dump_gmac_registers(a)		/* nop */
#define dump_na_registers(a, p)	/* nop */
#define dump_board_info(b)		/* nop */
#define dump_mac_stats(sc)		/* nop */
#define dump_mii_regs(sc)		/* nop */
#define dump_mii_data(mii)		/* nop */
#define dump_pcs_regs(sc, phy)		/* nop */
#endif

/* Wrappers etc. to export the driver entry points. */
static device_method_t nlna_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,         nlna_probe),
	DEVMETHOD(device_attach,        nlna_attach),
	DEVMETHOD(device_detach,        nlna_detach),
	DEVMETHOD(device_shutdown,      nlna_shutdown),
	DEVMETHOD(device_suspend,       nlna_suspend),
	DEVMETHOD(device_resume,        nlna_resume),

	/* bus interface : TBD : what are these for ? */
	DEVMETHOD(bus_setup_intr,       bus_generic_setup_intr),
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_driver_added,	bus_generic_driver_added),

	{ 0, 0 }
};

static driver_t	nlna_driver = {
	"nlna",
	nlna_methods,
	sizeof(struct nlna_softc)
};

static devclass_t nlna_devclass;

static device_method_t nlge_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,         nlge_probe),
	DEVMETHOD(device_attach,        nlge_attach),
	DEVMETHOD(device_detach,        nlge_detach),
	DEVMETHOD(device_shutdown,      bus_generic_shutdown),
	DEVMETHOD(device_suspend,       nlge_suspend),
	DEVMETHOD(device_resume,        nlge_resume),

	/* MII interface */
	DEVMETHOD(miibus_readreg, nlge_mii_read),
	DEVMETHOD(miibus_writereg, nlge_mii_write),
	DEVMETHOD(miibus_statchg, nlge_mac_mii_statchg),

	{0, 0}
};

static driver_t	nlge_driver = {
	"nlge",
	nlge_methods,
	sizeof(struct nlge_softc)
};

static devclass_t nlge_devclass;

DRIVER_MODULE(nlna, iodi, nlna_driver, nlna_devclass, 0, 0);
DRIVER_MODULE(nlge, nlna,  nlge_driver, nlge_devclass, 0, 0);
DRIVER_MODULE(miibus, nlge, miibus_driver, miibus_devclass, 0, 0);

static uma_zone_t nl_tx_desc_zone;

/* Function to atomically increment an integer with the given value. */
static __inline__ unsigned int
ldadd_wu(unsigned int value, unsigned long *addr)
{
	__asm__	 __volatile__( ".set push\n"
			       ".set noreorder\n"
			       "move $8, %2\n"
			       "move $9, %3\n"
			       /* "ldaddwu $8, $9\n" */
			       ".word 0x71280011\n"
			       "move %0, $8\n"
			       ".set pop\n"
			       : "=&r"(value), "+m"(*addr)
			       : "0"(value), "r" ((unsigned long)addr)
			       :  "$8", "$9");
	return value;
}

static __inline__ uint32_t
xlr_enable_kx(void)
{
	uint32_t sr = mips_rd_status();

	mips_wr_status((sr & ~MIPS_SR_INT_IE) | MIPS_SR_KX);
	return sr;
}

static int
nlna_probe(device_t dev)
{
	return (BUS_PROBE_DEFAULT);
}

/*
 * Add all attached GMAC/XGMAC ports to the device tree. Port
 * configuration is spread in two regions - common configuration
 * for all ports in the NA and per-port configuration in MAC-specific
 * region. This function does the following:
 *  - adds the ports to the device tree
 *  - reset the ports
 *  - do all the common initialization
 *  - invoke bus_generic_attach for per-port configuration
 *  - supply initial free rx descriptors to ports
 *  - initialize s/w data structures
 *  - finally, enable interrupts (only in the last NA).
 *
 * For reference, sample address space for common and per-port
 * registers is given below.
 *
 * The address map for RNA0 is:                           (typical value)
 *
 * XLR_IO_BASE +--------------------------------------+   0xbef0_0000
 *             |                                      |
 *             |                                      |
 *             |                                      |
 *             |                                      |
 *             |                                      |
 *             |                                      |
 * GMAC0  ---> +--------------------------------------+   0xbef0_c000
 *             |                                      |
 *             |                                      |
 * (common) -> |......................................|   0xbef0_c400
 *             |                                      |
 *             |   (RGMII/SGMII: common registers)    |
 *             |                                      |
 * GMAC1  ---> |--------------------------------------|   0xbef0_d000
 *             |                                      |
 *             |                                      |
 * (common) -> |......................................|   0xbef0_d400
 *             |                                      |
 *             |   (RGMII/SGMII: common registers)    |
 *             |                                      |
 *             |......................................|
 *       and so on ....
 *
 * Ref: Figure 14-3 and Table 14-1 of XLR PRM
 */
static int
nlna_attach(device_t dev)
{
	struct xlr_gmac_block_t *block_info;
	device_t		 gmac_dev;
	struct nlna_softc	*sc;
	int			 error;
	int			 i;
	int			 id;

	id = device_get_unit(dev);
	block_info = device_get_ivars(dev);
	if (!block_info->enabled) {
		return 0;
	}

#ifdef DEBUG
	dump_board_info(&xlr_board_info);
#endif
	block_info->baseaddr += DEFAULT_XLR_IO_BASE;

	/* Initialize nlna state in softc structure */
	sc = nlna_sc_init(dev, block_info);

	/* Add device's for the ports controlled by this NA. */
	if (block_info->type == XLR_GMAC) {
		KASSERT(id < 2, ("No GMACs supported with this network"
		    "accelerator: %d", id));
		for (i = 0; i < sc->num_ports; i++) {
			gmac_dev = device_add_child(dev, "nlge", -1);
			device_set_ivars(gmac_dev, &block_info->gmac_port[i]);
		}
	} else if (block_info->type == XLR_XGMAC) {
		KASSERT(id > 0 && id <= 2, ("No XGMACs supported with this"
		    "network accelerator: %d", id));
		gmac_dev = device_add_child(dev, "nlge", -1);
		device_set_ivars(gmac_dev, &block_info->gmac_port[0]);
	} else if (block_info->type == XLR_SPI4) {
		/* SPI4 is not supported here */
		device_printf(dev, "Unsupported: NA with SPI4 type");
		return (ENOTSUP);
	}

	nlna_reset_ports(sc, block_info);

	/* Initialize Network Accelarator registers. */
	nlna_hw_init(sc);

	error = bus_generic_attach(dev);
	if (error) {
		device_printf(dev, "failed to attach port(s)\n");
		goto fail;
	}

	/* Send out the initial pool of free-descriptors for the rx path */
	nlna_submit_rx_free_desc(sc, MAX_FRIN_SPILL);

	/* S/w data structure initializations shared by all NA's. */
	if (nl_tx_desc_zone == NULL) {
		/* Create a zone for allocating tx descriptors */
		nl_tx_desc_zone = uma_zcreate("NL Tx Desc",
		    sizeof(struct nlge_tx_desc), NULL, NULL, NULL, NULL,
		    XLR_CACHELINE_SIZE, 0);
	}

	/* Enable NA interrupts */
	nlna_setup_intr(sc);

	return (0);

fail:
	return (error);
}

static int
nlna_detach(device_t dev)
{
	struct nlna_softc *sc;

	sc = device_get_softc(dev);
	if (device_is_alive(dev)) {
		nlna_disable_intr(sc);
		/* This will make sure that per-port detach is complete
		 * and all traffic on the ports has been stopped. */
		bus_generic_detach(dev);
		uma_zdestroy(nl_tx_desc_zone);
	}

	return (0);
}

static int
nlna_suspend(device_t dev)
{

	return (0);
}

static int
nlna_resume(device_t dev)
{

	return (0);
}

static int
nlna_shutdown(device_t dev)
{
	return (0);
}


/* GMAC port entry points */
static int
nlge_probe(device_t dev)
{
	struct nlge_softc	*sc;
	struct xlr_gmac_port	*port_info;
	int index;
	char *desc[] = { "RGMII", "SGMII", "RGMII/SGMII", "XGMAC", "XAUI",
	    "Unknown"};

	port_info = device_get_ivars(dev);
	index = (port_info->type < XLR_RGMII || port_info->type > XLR_XAUI) ?
	    5 : port_info->type;
	device_set_desc_copy(dev, desc[index]);

	sc = device_get_softc(dev);
	nlge_sc_init(sc, dev, port_info);

	nlge_port_disable(sc->id, sc->base, sc->port_type);

	return (0);
}

static int
nlge_attach(device_t dev)
{
	struct nlge_softc *sc;
	struct nlna_softc *nsc;
	int error;

	sc = device_get_softc(dev);

	nlge_if_init(sc);
	nlge_mii_init(dev, sc);
	error = nlge_irq_init(sc);
	if (error)
		return error;
	nlge_hw_init(sc);

	nsc = (struct nlna_softc *)device_get_softc(device_get_parent(dev));
	nsc->child_sc[sc->instance] = sc;

	return (0);
}

static int
nlge_detach(device_t dev)
{
	struct nlge_softc *sc;
	struct ifnet   *ifp;
	
	sc = device_get_softc(dev);
	ifp = sc->nlge_if;

	if (device_is_attached(dev)) {
		ifp->if_drv_flags &= ~(IFF_DRV_OACTIVE | IFF_DRV_RUNNING);
		nlge_port_disable(sc->id, sc->base, sc->port_type);
		nlge_irq_fini(sc);
		ether_ifdetach(ifp);
		bus_generic_detach(dev);
	}
	if (ifp)
		if_free(ifp);

	return (0);
}

static int
nlge_suspend(device_t dev)
{
	return (0);
}

static int
nlge_resume(device_t dev)
{
	return (0);
}

static void
nlge_init(void *addr)
{
	struct nlge_softc *sc;
	struct ifnet   *ifp;

	sc = (struct nlge_softc *)addr;
	ifp = sc->nlge_if;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		return;

	nlge_gmac_config_speed(sc, 0);
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	nlge_port_enable(sc);

	if (sc->port_type == XLR_SGMII) {
		dump_pcs_regs(sc, 27);
	}
	dump_gmac_registers(sc);
	dump_mac_stats(sc);
}

static int
nlge_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct mii_data 	*mii;
	struct nlge_softc 	*sc;
	struct ifreq 		*ifr;
	int 			error;

	sc = ifp->if_softc;
	error = 0;
	ifr = (struct ifreq *)data;
	switch(command) {
	case SIOCSIFFLAGS:
		break;
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		if (sc->mii_bus != NULL) {
			mii = (struct mii_data *)device_get_softc(sc->mii_bus);
			error = ifmedia_ioctl(ifp, ifr, &mii->mii_media,
			    command);
		}
		break;
	case SIOCSIFADDR:
			// intentional fall thru
	case SIOCSIFMTU:
	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}

	return (error);
}

/* This function is called from an interrupt handler */
void
nlge_msgring_handler(int bucket, int size, int code, int stid,
		    struct msgrng_msg *msg, void *data)
{
	struct nlna_softc *na_sc;
	struct nlge_softc *sc;
	struct ifnet   *ifp;
	vm_paddr_t	phys_addr;
	unsigned long	addr;
	uint32_t	length;
	int		ctrl;
	int		cpu;
	int		tx_error;
	int		port;
	int 		vcpu;
	int		is_p2p;

	cpu = xlr_core_id();
	vcpu = (cpu << 2) + xlr_thr_id();

	addr = 0;
	is_p2p = 0;
	tx_error = 0;
	length = (msg->msg0 >> 40) & 0x3fff;
	na_sc = (struct nlna_softc *)data;
	if (length == 0) {
		ctrl = CTRL_REG_FREE;
		phys_addr = msg->msg0 & 0xffffffffffULL;
		port = (msg->msg0 >> 54) & 0x0f;
		is_p2p = (msg->msg0 >> 62) & 0x1;
		tx_error = (msg->msg0 >> 58) & 0xf;
	} else {
		ctrl = CTRL_SNGL;
		phys_addr = msg->msg0 & 0xffffffffe0ULL;
		length = length - BYTE_OFFSET - MAC_CRC_LEN;
		port = msg->msg0 & 0x0f;
	}

	sc = na_sc->child_sc[port];
	if (sc == NULL) {
		printf("Message (of %d len) with softc=NULL on %d port (type=%s)\n",
		    length, port, (ctrl == CTRL_SNGL ? "Pkt rx" :
		    "Freeback for tx packet"));
		return;
	}

	if (ctrl == CTRL_REG_FREE || ctrl == CTRL_JUMBO_FREE) {
		if (is_p2p) {
			release_tx_desc(phys_addr);
		} else {
			release_mbuf(phys_addr);
		}

		ifp = sc->nlge_if;
		if (ifp->if_drv_flags & IFF_DRV_OACTIVE){
			ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
		}
		ldadd_wu(1, (tx_error) ? &ifp->if_oerrors: &ifp->if_opackets);
	} else if (ctrl == CTRL_SNGL || ctrl == CTRL_START) {
		/* Rx Packet */

		nlge_rx(sc, phys_addr, length);
		nlna_submit_rx_free_desc(na_sc, 1);	/* return free descr to NA */
	} else {
		printf("[%s]: unrecognized ctrl=%d!\n", __FUNCTION__, ctrl);
	}

}

static void
nlge_start(struct ifnet *ifp)
{
	struct nlge_softc	*sc;

	sc = ifp->if_softc;
	//NLGE_LOCK(sc);
	nlge_start_locked(ifp, sc);
	//NLGE_UNLOCK(sc);
}
	
static void
nlge_start_locked(struct ifnet *ifp, struct nlge_softc *sc)
{
	struct msgrng_msg 	msg;
	struct mbuf  		*m;
	struct nlge_tx_desc 	*tx_desc;
	uint64_t		fr_stid;
	uint32_t		cpu;	
	uint32_t		n_entries;	
	uint32_t		tid;
	int 			ret;
	int 			sent;

	cpu = xlr_core_id();	
	tid = xlr_thr_id();
	fr_stid = cpu * 8 + tid + 4;

	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		return;
	}

	do {
		/* Grab a packet off the queue. */
		IF_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL) {
			return;
		}

		tx_desc = NULL;
		ret = prepare_fmn_message(sc, &msg, &n_entries, m, fr_stid, &tx_desc);
		if (ret) {
			goto fail;
		}
		sent = send_fmn_msg_tx(sc, &msg, n_entries);
		if (sent != 0) {
			goto fail;
		}
	} while(1);

	return;

fail:
	if (tx_desc != NULL) {
		uma_zfree(nl_tx_desc_zone, tx_desc);
	}
	if (m != NULL) {
		/*
		 * TBD: It is observed that only when both of the statements
		 * below are not enabled, traffic continues till the end.
		 * Otherwise, the port locks up in the middle and never
		 * recovers from it. The current theory for this behavior
		 * is that the queue is full and the upper layer is neither
		 * able to add to it not invoke nlge_start to drian the
		 * queue. The driver may have to do something in addition
		 * to reset'ing the OACTIVE bit when a trasnmit free-back
		 * is received.
		 */
		//ifp->if_drv_flags |= IFF_DRV_OACTIVE;
		//IF_PREPEND(&ifp->if_snd, m);
		m_freem(m);
		ldadd_wu(1, &ifp->if_iqdrops);
	}
	return;
}

static void
nlge_rx(struct nlge_softc *sc, vm_paddr_t paddr, int len)
{
	struct ifnet   *ifp;
	struct mbuf    *m;
	uint32_t tm, mag, sr;

	sr = xlr_enable_kx();
	tm = xlr_paddr_lw(paddr - XLR_CACHELINE_SIZE);
	mag = xlr_paddr_lw(paddr - XLR_CACHELINE_SIZE + sizeof(uint32_t));
	mips_wr_status(sr);

	m = (struct mbuf *)(intptr_t)tm;
	if (mag != 0xf00bad) {
		/* somebody else's packet. Error - FIXME in intialization */
		printf("cpu %d: *ERROR* Not my packet paddr %llx\n",
		    xlr_core_id(), (uint64_t) paddr);
		return;
	}

	ifp = sc->nlge_if;
	/* align the data */
	m->m_data += BYTE_OFFSET;
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = ifp;

	ldadd_wu(1, &ifp->if_ipackets);
	(*ifp->if_input)(ifp, m);
}

static int
nlge_mii_write(struct device *dev, int phyaddr, int regidx, int regval)
{
	struct nlge_softc *sc;

	sc = device_get_softc(dev);
	if (sc->phy_addr == phyaddr && sc->port_type != XLR_XGMII)
		nlge_mii_write_internal(sc->mii_base, phyaddr, regidx, regval);

	return (0);
}

static int
nlge_mii_read(struct device *dev, int phyaddr, int regidx)
{
	struct nlge_softc *sc;
	int val;

	sc = device_get_softc(dev);
	val = (sc->phy_addr != phyaddr && sc->port_type != XLR_XGMII) ? (0xffff) :
	    nlge_mii_read_internal(sc->mii_base, phyaddr, regidx);

	return (val);
}

static void
nlge_mac_mii_statchg(device_t dev)
{
}

static int
nlge_mediachange(struct ifnet *ifp)
{
	return 0;
}

static void
nlge_mediastatus(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct nlge_softc *sc;
	struct mii_data *md;
	
	md = NULL;
	sc = ifp->if_softc;
	if (sc->mii_bus)
		md = device_get_softc(sc->mii_bus);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (sc->link == xlr_mac_link_down)
		return;

	if (md != NULL)
		ifmr->ifm_active = md->mii_media.ifm_cur->ifm_media;
	ifmr->ifm_status |= IFM_ACTIVE;
}

static struct nlna_softc *
nlna_sc_init(device_t dev, struct xlr_gmac_block_t *blk)
{
	struct nlna_softc	*sc;

	sc = device_get_softc(dev);
	memset(sc, 0, sizeof(*sc));
	sc->nlna_dev = dev;
	sc->base = (xlr_reg_t *) blk->baseaddr;
	sc->rfrbucket = blk->station_rfr;
	sc->station_id = blk->station_id;
	sc->na_type = blk->type;
	sc->mac_type = blk->mode;
	sc->num_ports = blk->num_ports;

	sc->mdio_set.port_vec 	= sc->mdio_sc;
	sc->mdio_set.vec_sz   	= XLR_MAX_MACS;

	return (sc);
}

/*
 * Do:
 *     - Initialize common GMAC registers (index range 0x100-0x3ff).
 */
static void
nlna_hw_init(struct nlna_softc *sc)
{

	/*
	 * It is seen that this is a critical function in bringing up FreeBSD.
	 * When it is not invoked, FreeBSD panics and fails during the
	 * multi-processor init (SI_SUB_SMP of * mi_startup). The key function
	 * in this sequence seems to be platform_prep_smp_launch. */
	if (register_msgring_handler(sc->station_id, nlge_msgring_handler, sc)) {
		panic("Couldn't register msgring handler\n");
	}
	nlna_config_fifo_spill_area(sc);
	nlna_config_pde(sc);
	nlna_config_common(sc);
	nlna_config_parser(sc);
	nlna_config_classifier(sc);
}

/*
 * Enable interrupts on all the ports controlled by this NA. For now, we
 * only care about the MII interrupt and this has to be enabled only
 * on the port id0.
 *
 * This function is not in-sync with the regular way of doing things - it
 * executes only in the context of the last active network accelerator (and
 * thereby has some ugly accesses in the device tree). Though inelegant, it
 * is necessary to do it this way as the per-port interrupts can be
 * setup/enabled only after all the network accelerators have been
 * initialized.
 */
static void
nlna_setup_intr(struct nlna_softc *sc)
{
	struct nlna_softc *na_sc[XLR_MAX_NLNA];
	struct nlge_port_set *pset;
	struct xlr_gmac_port *port_info;
	device_t	iodi_dev;
	int 		i, j;

	if (!nlna_is_last_active_na(sc))
		return ;

	/* Collect all nlna softc pointers */
	memset(na_sc, 0, sizeof(*na_sc) * XLR_MAX_NLNA);
	iodi_dev = device_get_parent(sc->nlna_dev);
	nlna_get_all_softc(iodi_dev, na_sc, XLR_MAX_NLNA);

	/* Setup the MDIO interrupt lists. */
	/*
	 * MDIO interrupts are coarse - a single interrupt line provides
	 * information about one of many possible ports. To figure out the
	 * exact port on which action is to be taken, all of the ports
	 * linked to an MDIO interrupt should be read. To enable this,
	 * ports need to add themselves to port sets.
	 */
	for (i = 0; i < XLR_MAX_NLNA; i++) {
		if (na_sc[i] == NULL)
			continue;
		for (j = 0; j < na_sc[i]->num_ports; j++) {
			/* processing j-th port on i-th NA */
			port_info = device_get_ivars(
			    na_sc[i]->child_sc[j]->nlge_dev);	
			pset = &na_sc[port_info->mdint_id]->mdio_set;
			nlna_add_to_port_set(pset, na_sc[i]->child_sc[j]);
		}
	}

	/* Enable interrupts */
	for (i = 0; i < XLR_MAX_NLNA; i++) {
		if (na_sc[i] != NULL && na_sc[i]->na_type != XLR_XGMAC) {
			nlna_enable_intr(na_sc[i]);
		}
	}
}

static void
nlna_add_to_port_set(struct nlge_port_set *pset, struct nlge_softc *sc)
{
	int i;

	/* step past the non-NULL elements */
	for (i = 0; i < pset->vec_sz && pset->port_vec[i] != NULL; i++) ;
	if (i < pset->vec_sz)
		pset->port_vec[i] = sc;
	else
		printf("warning: internal error: out-of-bounds for MDIO array");
}

static void
nlna_enable_intr(struct nlna_softc *sc)
{
	int i;

	for (i = 0; i < sc->num_ports; i++) {
		if (sc->child_sc[i]->instance == 0)
			NLGE_WRITE(sc->child_sc[i]->base, R_INTMASK,
			    (1 << O_INTMASK__MDInt));
	}
}

static void
nlna_disable_intr(struct nlna_softc *sc)
{
	int i;

	for (i = 0; i < sc->num_ports; i++) {
		if (sc->child_sc[i]->instance == 0)
			NLGE_WRITE(sc->child_sc[i]->base, R_INTMASK, 0);
	}
}

static int
nlna_is_last_active_na(struct nlna_softc *sc)
{
	int id;

	id = device_get_unit(sc->nlna_dev);
	return (id == 2 || xlr_board_info.gmac_block[id + 1].enabled == 0);
}

static __inline__ int
nlna_send_free_desc(struct nlna_softc *sc, vm_paddr_t addr)
{
	struct msgrng_msg msg;
	uint32_t msgrng_flags;
	int i = 0, stid, code, ret;

	stid = sc->rfrbucket;
	memset(&msg, 0, sizeof(msg));
	msg.msg0 = (uint64_t) addr & 0xffffffffe0ULL;

	code = (sc->na_type == XLR_XGMAC) ? MSGRNG_CODE_XGMAC : MSGRNG_CODE_MAC;
	do {
		msgrng_flags = msgrng_access_enable();
		ret = message_send_retry(1, code, stid, &msg);
		msgrng_restore(msgrng_flags);
		KASSERT(i++ < 100000, ("Too many credit fails\n"));
	} while (ret != 0);
	return (0);
}

static void
nlna_submit_rx_free_desc(struct nlna_softc *sc, uint32_t n_desc)
{
	void           *ptr;
	int		i;
	int		ret;

	if (n_desc > 1) {
		PDEBUG("Sending %d free-in descriptors to station=%d\n", n_desc,
		    sc->rfrbucket);
	}

	for (i = 0; i < n_desc; i++) {
		ptr = get_buf();
		if (!ptr) {
			ret = -ENOMEM;
			device_printf(sc->nlna_dev, "Cannot allocate mbuf\n");
			break;
		}

		/* Send the free Rx desc to the MAC */
		ret = nlna_send_free_desc(sc, vtophys(ptr));
		if (ret != 0)  /* no point trying other descriptors after
		             a failure. */
			break;
	}
}

static __inline__ void *
nlna_config_spill(xlr_reg_t *base, int reg_start_0, int reg_start_1,
    int reg_size, int size)
{
	void	*spill;
	uint64_t phys_addr;
	uint32_t spill_size;

	spill_size = size;
	spill = contigmalloc((spill_size + XLR_CACHELINE_SIZE), M_DEVBUF,
	    M_NOWAIT | M_ZERO, 0, 0xffffffff, XLR_CACHELINE_SIZE, 0);
	if (spill == NULL || ((vm_offset_t) spill & (XLR_CACHELINE_SIZE - 1))) {
		panic("Unable to allocate memory for spill area!\n");
	}
	phys_addr = vtophys(spill);
	PDEBUG("Allocated spill %d bytes at %llx\n", size, phys_addr);
	NLGE_WRITE(base, reg_start_0, (phys_addr >> 5) & 0xffffffff);
	NLGE_WRITE(base, reg_start_1, (phys_addr >> 37) & 0x07);
	NLGE_WRITE(base, reg_size, spill_size);

	return (spill);
}

/*
 * Configure the 6 FIFO's that are used by the network accelarator to
 * communicate with the rest of the XLx device. 4 of the FIFO's are for
 * packets from NA --> cpu (called Class FIFO's) and 2 are for feeding
 * the NA with free descriptors.
 */
static void
nlna_config_fifo_spill_area(struct nlna_softc *sc)
{
	sc->frin_spill = nlna_config_spill(sc->base,
				     	R_REG_FRIN_SPILL_MEM_START_0,
				     	R_REG_FRIN_SPILL_MEM_START_1,
				     	R_REG_FRIN_SPILL_MEM_SIZE,
				     	MAX_FRIN_SPILL *
				     	sizeof(struct fr_desc));
	sc->frout_spill = nlna_config_spill(sc->base,
				     	R_FROUT_SPILL_MEM_START_0,
				     	R_FROUT_SPILL_MEM_START_1,
				     	R_FROUT_SPILL_MEM_SIZE,
				     	MAX_FROUT_SPILL *
				     	sizeof(struct fr_desc));
	sc->class_0_spill = nlna_config_spill(sc->base,
				     	R_CLASS0_SPILL_MEM_START_0,
				     	R_CLASS0_SPILL_MEM_START_1,
				     	R_CLASS0_SPILL_MEM_SIZE,
				     	MAX_CLASS_0_SPILL *
				     	sizeof(union rx_tx_desc));
	sc->class_1_spill = nlna_config_spill(sc->base,
				     	R_CLASS1_SPILL_MEM_START_0,
				     	R_CLASS1_SPILL_MEM_START_1,
				     	R_CLASS1_SPILL_MEM_SIZE,
				     	MAX_CLASS_1_SPILL *
				     	sizeof(union rx_tx_desc));
	sc->class_2_spill = nlna_config_spill(sc->base,
				     	R_CLASS2_SPILL_MEM_START_0,
				     	R_CLASS2_SPILL_MEM_START_1,
				     	R_CLASS2_SPILL_MEM_SIZE,
				     	MAX_CLASS_2_SPILL *
				     	sizeof(union rx_tx_desc));
	sc->class_3_spill = nlna_config_spill(sc->base,
				     	R_CLASS3_SPILL_MEM_START_0,
				     	R_CLASS3_SPILL_MEM_START_1,
				     	R_CLASS3_SPILL_MEM_SIZE,
				     	MAX_CLASS_3_SPILL *
				     	sizeof(union rx_tx_desc));
}

/* Set the CPU buckets that receive packets from the NA class FIFOs. */
static void
nlna_config_pde(struct nlna_softc *sc)
{
	uint64_t	bucket_map;
	uint32_t	cpumask;
	int		i, cpu, bucket;

	cpumask = 0x1;
#ifdef SMP
	/*
         * rge may be called before SMP start in a BOOTP/NFSROOT
         * setup. we will distribute packets to other cpus only when
         * the SMP is started.
	 */
	if (smp_started)
		cpumask = xlr_hw_thread_mask;
#endif

	bucket_map = 0;
	for (i = 0; i < 32; i++) {
		if (cpumask & (1 << i)) {
			cpu = i;
			bucket = ((cpu >> 2) << 3);
			bucket_map |= (1ULL << bucket);
		}
	}
	NLGE_WRITE(sc->base, R_PDE_CLASS_0, (bucket_map & 0xffffffff));
	NLGE_WRITE(sc->base, R_PDE_CLASS_0 + 1, ((bucket_map >> 32) & 0xffffffff));

	NLGE_WRITE(sc->base, R_PDE_CLASS_1, (bucket_map & 0xffffffff));
	NLGE_WRITE(sc->base, R_PDE_CLASS_1 + 1, ((bucket_map >> 32) & 0xffffffff));

	NLGE_WRITE(sc->base, R_PDE_CLASS_2, (bucket_map & 0xffffffff));
	NLGE_WRITE(sc->base, R_PDE_CLASS_2 + 1, ((bucket_map >> 32) & 0xffffffff));

	NLGE_WRITE(sc->base, R_PDE_CLASS_3, (bucket_map & 0xffffffff));
	NLGE_WRITE(sc->base, R_PDE_CLASS_3 + 1, ((bucket_map >> 32) & 0xffffffff));
}

static void
nlna_smp_update_pde(void *dummy __unused)
{
	device_t	   iodi_dev;
	struct nlna_softc *na_sc[XLR_MAX_NLNA];
	int i;

	printf("Updating packet distribution for SMP\n");

	iodi_dev = devclass_get_device(devclass_find("iodi"), 0);
	nlna_get_all_softc(iodi_dev, na_sc, XLR_MAX_NLNA);

	for (i = 0; i < XLR_MAX_NLNA; i++) {
		if (na_sc[i] == NULL)
			continue;
		nlna_disable_ports(na_sc[i]);
		nlna_config_pde(na_sc[i]);
		nlna_enable_ports(na_sc[i]);
	}
}

SYSINIT(nlna_smp_update_pde, SI_SUB_SMP, SI_ORDER_ANY, nlna_smp_update_pde,
    NULL);

static void
nlna_config_parser(struct nlna_softc *sc)
{
	/*
	 * Mark it as no classification. The parser extract is gauranteed to
	 * be zero with no classfication
	 */
	NLGE_WRITE(sc->base, R_L2TYPE_0, 0x00);
	NLGE_WRITE(sc->base, R_L2TYPE_0, 0x01);

	/* configure the parser : L2 Type is configured in the bootloader */
	/* extract IP: src, dest protocol */
	NLGE_WRITE(sc->base, R_L3CTABLE,
	    (9 << 20) | (1 << 19) | (1 << 18) | (0x01 << 16) |
	    (0x0800 << 0));
	NLGE_WRITE(sc->base, R_L3CTABLE + 1,
	    (12 << 25) | (4 << 21) | (16 << 14) | (4 << 10));
}

static void
nlna_config_classifier(struct nlna_softc *sc)
{
	int i;

	if (sc->mac_type == XLR_XGMII) {	/* TBD: XGMII init sequence */
		/* xgmac translation table doesn't have sane values on reset */
		for (i = 0; i < 64; i++)
			NLGE_WRITE(sc->base, R_TRANSLATETABLE + i, 0x0);

		/*
		 * use upper 7 bits of the parser extract to index the
		 * translate table
		 */
		NLGE_WRITE(sc->base, R_PARSERCONFIGREG, 0x0);
	}
}

/*
 * Complete a bunch of h/w register initializations that are common for all the
 * ports controlled by a NA.
 */
static void
nlna_config_common(struct nlna_softc *sc)
{
	struct xlr_gmac_block_t *block_info;
	struct stn_cc 		*gmac_cc_config;
	int			i, id;

	block_info = device_get_ivars(sc->nlna_dev);

	id = device_get_unit(sc->nlna_dev);
	gmac_cc_config = block_info->credit_config;
	for (i = 0; i < MAX_NUM_MSGRNG_STN_CC; i++) {
		NLGE_WRITE(sc->base, R_CC_CPU0_0 + i,
		    gmac_cc_config->counters[i >> 3][i & 0x07]);
	}

	NLGE_WRITE(sc->base, R_MSG_TX_THRESHOLD, 3);

	NLGE_WRITE(sc->base, R_DMACR0, 0xffffffff);
	NLGE_WRITE(sc->base, R_DMACR1, 0xffffffff);
	NLGE_WRITE(sc->base, R_DMACR2, 0xffffffff);
	NLGE_WRITE(sc->base, R_DMACR3, 0xffffffff);
	NLGE_WRITE(sc->base, R_FREEQCARVE, 0);

	nlna_media_specific_config(sc);
}

static void
nlna_media_specific_config(struct nlna_softc *sc)
{
	struct bucket_size *bucket_sizes;

	bucket_sizes = xlr_board_info.bucket_sizes;
	switch (sc->mac_type) {
	case XLR_RGMII:
	case XLR_SGMII:
	case XLR_XAUI:
		NLGE_WRITE(sc->base, R_GMAC_JFR0_BUCKET_SIZE,
		    bucket_sizes->bucket[MSGRNG_STNID_GMACJFR_0]);
		NLGE_WRITE(sc->base, R_GMAC_RFR0_BUCKET_SIZE,
		    bucket_sizes->bucket[MSGRNG_STNID_GMACRFR_0]);
		NLGE_WRITE(sc->base, R_GMAC_JFR1_BUCKET_SIZE,
		    bucket_sizes->bucket[MSGRNG_STNID_GMACJFR_1]);
		NLGE_WRITE(sc->base, R_GMAC_RFR1_BUCKET_SIZE,
		    bucket_sizes->bucket[MSGRNG_STNID_GMACRFR_1]);

		if (sc->mac_type == XLR_XAUI) {
			NLGE_WRITE(sc->base, R_TXDATAFIFO0, (224 << 16));
		}
		break;
	
	case XLR_XGMII:
		NLGE_WRITE(sc->base, R_XGS_RFR_BUCKET_SIZE,
		    bucket_sizes->bucket[sc->rfrbucket]);

	default:
		break;
	}
}

static void
nlna_reset_ports(struct nlna_softc *sc, struct xlr_gmac_block_t *blk)
{
	xlr_reg_t *addr;
	int i;
	uint32_t   rx_ctrl;

	/* Refer Section 13.9.3 in the PRM for the reset sequence */

	for (i = 0; i < sc->num_ports; i++) {
		uint32_t base = (uint32_t)DEFAULT_XLR_IO_BASE;

		base += blk->gmac_port[i].base_addr;
		addr = (xlr_reg_t *) base;

		/* 1. Reset RxEnable in MAC_CONFIG */
		switch (sc->mac_type) {
		case XLR_RGMII:
		case XLR_SGMII:
			NLGE_UPDATE(addr, R_MAC_CONFIG_1, 0,
			    (1 << O_MAC_CONFIG_1__rxen));
			break;
		case XLR_XAUI:
		case XLR_XGMII:
			NLGE_UPDATE(addr, R_RX_CONTROL, 0,
			   (1 << O_RX_CONTROL__RxEnable));
			break;
		default:
			printf("Error: Unsupported port_type=%d\n",
			    sc->mac_type);
		}

		/* 1.1 Wait for RxControl.RxHalt to be set */
		do {
			rx_ctrl = NLGE_READ(addr, R_RX_CONTROL);
		} while (!(rx_ctrl & 0x2));

		/* 2. Set the soft reset bit in RxControl */
		NLGE_UPDATE(addr, R_RX_CONTROL, (1 << O_RX_CONTROL__SoftReset),
		    (1 << O_RX_CONTROL__SoftReset));

		/* 2.1 Wait for RxControl.SoftResetDone to be set */
		do {
			rx_ctrl = NLGE_READ(addr, R_RX_CONTROL);
		} while (!(rx_ctrl & 0x8));

		/* 3. Clear the soft reset bit in RxControl */
		NLGE_UPDATE(addr, R_RX_CONTROL, 0,
		    (1 << O_RX_CONTROL__SoftReset));

		/* Turn off tx/rx on the port. */
		NLGE_UPDATE(addr, R_RX_CONTROL, 0,
		    (1 << O_RX_CONTROL__RxEnable));
		NLGE_UPDATE(addr, R_TX_CONTROL, 0,
		    (1 << O_TX_CONTROL__TxEnable));
	}
}

static void
nlna_disable_ports(struct nlna_softc *sc)
{
	struct xlr_gmac_block_t *blk;
	xlr_reg_t *addr;
	int i;

	blk = device_get_ivars(sc->nlna_dev);
	for (i = 0; i < sc->num_ports; i++) {
		uint32_t base = (uint32_t)DEFAULT_XLR_IO_BASE;

		base += blk->gmac_port[i].base_addr;
		addr = (xlr_reg_t *) base;
		nlge_port_disable(i, addr, blk->gmac_port[i].type);
	}
}

static void
nlna_enable_ports(struct nlna_softc *sc)
{
	device_t		nlge_dev, *devlist;
	struct nlge_softc 	*port_sc;
	int 			i, numdevs;

	device_get_children(sc->nlna_dev, &devlist, &numdevs);
	for (i = 0; i < numdevs; i++) {
		nlge_dev = devlist[i];
		if (nlge_dev == NULL)
			continue;
		port_sc = device_get_softc(nlge_dev);
		if (port_sc->nlge_if->if_drv_flags & IFF_DRV_RUNNING)
			nlge_port_enable(port_sc);
	}
	free(devlist, M_TEMP);
}

static void
nlna_get_all_softc(device_t iodi_dev, struct nlna_softc **sc_vec,
		   uint32_t vec_sz)
{
	device_t  na_dev;
	int       i;

	for (i = 0; i < vec_sz; i++) {
		sc_vec[i] = NULL;
		na_dev = device_find_child(iodi_dev, "nlna", i);
		if (na_dev != NULL)
			sc_vec[i] = device_get_softc(na_dev);
	}
}

static void
nlge_port_disable(int id, xlr_reg_t *base, int port_type)
{
	uint32_t rd;

	NLGE_UPDATE(base, R_RX_CONTROL, 0x0, 1 << O_RX_CONTROL__RxEnable);
	do {
		rd = NLGE_READ(base, R_RX_CONTROL);
	} while (!(rd & (1 << O_RX_CONTROL__RxHalt)));

	NLGE_UPDATE(base, R_TX_CONTROL, 0, 1 << O_TX_CONTROL__TxEnable);
	do {
		rd = NLGE_READ(base, R_TX_CONTROL);
	} while (!(rd & (1 << O_TX_CONTROL__TxIdle)));

	switch (port_type) {
	case XLR_RGMII:
	case XLR_SGMII:
		NLGE_UPDATE(base, R_MAC_CONFIG_1, 0,
		   ((1 << O_MAC_CONFIG_1__rxen) |
		   (1 << O_MAC_CONFIG_1__txen)));
		break;
	case XLR_XGMII:
	case XLR_XAUI:
		NLGE_UPDATE(base, R_XGMAC_CONFIG_1, 0,
		   ((1 << O_XGMAC_CONFIG_1__hsttfen) |
		   (1 << O_XGMAC_CONFIG_1__hstrfen)));
		break;
	default:
		panic("Unknown MAC type on port %d\n", id);
	}
}

static void
nlge_port_enable(struct nlge_softc *sc)
{
	struct xlr_gmac_port  *self;
	xlr_reg_t *base;

	base = sc->base;
	self = device_get_ivars(sc->nlge_dev);
	if (xlr_board_info.is_xls && sc->port_type == XLR_RGMII)
		NLGE_UPDATE(base, R_RX_CONTROL, (1 << O_RX_CONTROL__RGMII),
	    	    (1 << O_RX_CONTROL__RGMII));

	NLGE_UPDATE(base, R_RX_CONTROL, (1 << O_RX_CONTROL__RxEnable),
	    (1 << O_RX_CONTROL__RxEnable));
	NLGE_UPDATE(base, R_TX_CONTROL,
	    (1 << O_TX_CONTROL__TxEnable | RGE_TX_THRESHOLD_BYTES),
	    (1 << O_TX_CONTROL__TxEnable | 0x3fff));
	switch (sc->port_type) {
	case XLR_RGMII:
	case XLR_SGMII:
		NLGE_UPDATE(base, R_MAC_CONFIG_1,
		    ((1 << O_MAC_CONFIG_1__rxen) | (1 << O_MAC_CONFIG_1__txen)),
		    ((1 << O_MAC_CONFIG_1__rxen) | (1 << O_MAC_CONFIG_1__txen)));
		break;
	case XLR_XGMII:
	case XLR_XAUI:
		NLGE_UPDATE(base, R_XGMAC_CONFIG_1,
		    ((1 << O_XGMAC_CONFIG_1__hsttfen) | (1 << O_XGMAC_CONFIG_1__hstrfen)),
		    ((1 << O_XGMAC_CONFIG_1__hsttfen) | (1 << O_XGMAC_CONFIG_1__hstrfen)));
		break;
	default:
		panic("Unknown MAC type on port %d\n", sc->id);
	}
}

static void
nlge_sgmii_init(struct nlge_softc *sc)
{
	xlr_reg_t *mmio_gpio;
	int i;
	int phy;

	if (sc->port_type != XLR_SGMII)
		return;

	nlge_mii_write_internal(sc->serdes_addr, 26, 0, 0x6DB0);
	nlge_mii_write_internal(sc->serdes_addr, 26, 1, 0xFFFF);
	nlge_mii_write_internal(sc->serdes_addr, 26, 2, 0xB6D0);
	nlge_mii_write_internal(sc->serdes_addr, 26, 3, 0x00FF);
	nlge_mii_write_internal(sc->serdes_addr, 26, 4, 0x0000);
	nlge_mii_write_internal(sc->serdes_addr, 26, 5, 0x0000);
	nlge_mii_write_internal(sc->serdes_addr, 26, 6, 0x0005);
	nlge_mii_write_internal(sc->serdes_addr, 26, 7, 0x0001);
	nlge_mii_write_internal(sc->serdes_addr, 26, 8, 0x0000);
	nlge_mii_write_internal(sc->serdes_addr, 26, 9, 0x0000);
	nlge_mii_write_internal(sc->serdes_addr, 26,10, 0x0000);

	for(i=0;i<10000000;i++){}	/* delay */
	/* program  GPIO values for serdes init parameters */
	mmio_gpio = (xlr_reg_t *) (DEFAULT_XLR_IO_BASE + XLR_IO_GPIO_OFFSET);
	mmio_gpio[0x20] = 0x7e6802;
	mmio_gpio[0x10] = 0x7104;
	for(i=0;i<100000000;i++){}

	/* enable autoneg - more magic */
	phy = sc->phy_addr % 4 + 27;
	nlge_mii_write_internal(sc->pcs_addr, phy, 0, 0x1000);
	DELAY(100000);
	nlge_mii_write_internal(sc->pcs_addr, phy, 0, 0x0200);
	DELAY(100000);
}

static void
nlge_intr(void *arg)
{
	struct nlge_port_set    *pset;
	struct nlge_softc 	*sc;
	struct nlge_softc 	*port_sc;
	xlr_reg_t 		*base;
	uint32_t		intreg;
	uint32_t		intr_status;
	int 			i;

	sc = arg;
	if (sc == NULL) {
		printf("warning: No port registered for interrupt\n");
		return;
	}
	base = sc->base;

	intreg = NLGE_READ(base, R_INTREG);
	if (intreg & (1 << O_INTREG__MDInt)) {
		pset = sc->mdio_pset;
		if (pset == NULL) {
			printf("warning: No ports for MDIO interrupt\n");
			return;
		}
		for (i = 0; i < pset->vec_sz; i++) {
			port_sc = pset->port_vec[i];

			if (port_sc == NULL)
				continue;

			/* Ack phy interrupt - clear on read*/
			intr_status = nlge_mii_read_internal(port_sc->mii_base,
			    port_sc->phy_addr, 26);
			PDEBUG("Phy_%d: int_status=0x%08x\n", port_sc->phy_addr,
			    intr_status);

			if (!(intr_status & 0x8000)) {
				/* no interrupt for this port */
				continue;
			}

			if (intr_status & 0x2410) {
				/* update link status for port */
				nlge_gmac_config_speed(port_sc, 0);
			} else {
				printf("%s: Unsupported phy interrupt"
				    " (0x%08x)\n",
				    device_get_nameunit(port_sc->nlge_dev),
				    intr_status);
			}
		}
	}

	/* Clear the NA interrupt */
	xlr_write_reg(base, R_INTREG, 0xffffffff);

	return;
}

static int
nlge_irq_init(struct nlge_softc *sc)
{
	struct resource		irq_res;
	struct nlna_softc  	*na_sc;
	struct xlr_gmac_block_t *block_info;
	device_t		na_dev;
	int			ret;
	int			irq_num;

	na_dev = device_get_parent(sc->nlge_dev);
	block_info = device_get_ivars(na_dev);

	irq_num = block_info->baseirq + sc->instance;
	irq_res.__r_i = (struct resource_i *)(intptr_t) (irq_num);
	ret = bus_setup_intr(sc->nlge_dev, &irq_res, (INTR_FAST |
	    INTR_TYPE_NET | INTR_MPSAFE), NULL, nlge_intr, sc, NULL);
	if (ret) {
		nlge_detach(sc->nlge_dev);
		device_printf(sc->nlge_dev, "couldn't set up irq: error=%d\n",
		    ret);
		return (ENXIO);
	}
	PDEBUG("Setup intr for dev=%s, irq=%d\n",
	    device_get_nameunit(sc->nlge_dev), irq_num);
	
	if (sc->instance == 0) {
		na_sc = device_get_softc(na_dev);
		sc->mdio_pset = &na_sc->mdio_set;
	}
	return (0);
}

static void
nlge_irq_fini(struct nlge_softc *sc)
{
}

static void
nlge_hw_init(struct nlge_softc *sc)
{
	struct xlr_gmac_port  *port_info;
	xlr_reg_t *base;

	base = sc->base;
	port_info = device_get_ivars(sc->nlge_dev);
	sc->tx_bucket_id = port_info->tx_bucket_id;

	/* each packet buffer is 1536 bytes */
	NLGE_WRITE(base, R_DESC_PACK_CTRL,
		  (1 << O_DESC_PACK_CTRL__MaxEntry) |
		  (MAX_FRAME_SIZE << O_DESC_PACK_CTRL__RegularSize));
	NLGE_WRITE(base, R_STATCTRL, ((1 << O_STATCTRL__Sten) |
	    (1 << O_STATCTRL__ClrCnt)));
	NLGE_WRITE(base, R_L2ALLOCCTRL, 0xffffffff);
	NLGE_WRITE(base, R_INTMASK, 0);
	nlge_set_mac_addr(sc);
	nlge_media_specific_init(sc);
}

static void
nlge_sc_init(struct nlge_softc *sc, device_t dev,
    struct xlr_gmac_port *port_info)
{
	memset(sc, 0, sizeof(*sc));
	sc->nlge_dev = dev;
	sc->id = device_get_unit(dev);
	nlge_set_port_attribs(sc, port_info);
}

static void
nlge_media_specific_init(struct nlge_softc *sc)
{
	struct mii_data *media;
	struct bucket_size *bucket_sizes;

	bucket_sizes = xlr_board_info.bucket_sizes;
	switch (sc->port_type) {
	case XLR_RGMII:
	case XLR_SGMII:
	case XLR_XAUI:
		NLGE_UPDATE(sc->base, R_DESC_PACK_CTRL,
		    (BYTE_OFFSET << O_DESC_PACK_CTRL__ByteOffset),
		    (W_DESC_PACK_CTRL__ByteOffset <<
		        O_DESC_PACK_CTRL__ByteOffset));
		NLGE_WRITE(sc->base, R_GMAC_TX0_BUCKET_SIZE + sc->instance,
		    bucket_sizes->bucket[sc->tx_bucket_id]);
		if (sc->port_type != XLR_XAUI) {
			nlge_gmac_config_speed(sc, 1);
			if (sc->mii_bus) {
				media = (struct mii_data *)device_get_softc(
				    sc->mii_bus);
			}
		}
		break;

	case XLR_XGMII:
		NLGE_WRITE(sc->base, R_BYTEOFFSET0, 0x2);
		NLGE_WRITE(sc->base, R_XGMACPADCALIBRATION, 0x30);
		NLGE_WRITE(sc->base, R_XGS_TX0_BUCKET_SIZE,
		    bucket_sizes->bucket[sc->tx_bucket_id]);
		break;
	default:
		break;
	}
}

/*
 * Read the MAC address from the XLR boot registers. All port addresses
 * are identical except for the lowest octet.
 */
static void
nlge_read_mac_addr(struct nlge_softc *sc)
{
	int i, j;

	for (i = 0, j = 40; i < ETHER_ADDR_LEN && j >= 0; i++, j-= 8)
		sc->dev_addr[i] = (xlr_boot1_info.mac_addr >> j) & 0xff;

	sc->dev_addr[i - 1] +=  sc->id;	/* last octet is port-specific */
}

/*
 * Write the MAC address to the XLR MAC port. Also, set the address
 * masks and MAC filter configuration.
 */
static void
nlge_set_mac_addr(struct nlge_softc *sc)
{
	NLGE_WRITE(sc->base, R_MAC_ADDR0,
		  ((sc->dev_addr[5] << 24) | (sc->dev_addr[4] << 16) |
		   (sc->dev_addr[3] << 8) | (sc->dev_addr[2])));
	NLGE_WRITE(sc->base, R_MAC_ADDR0 + 1,
		  ((sc->dev_addr[1] << 24) | (sc-> dev_addr[0] << 16)));

	NLGE_WRITE(sc->base, R_MAC_ADDR_MASK2, 0xffffffff);
	NLGE_WRITE(sc->base, R_MAC_ADDR_MASK2 + 1, 0xffffffff);
	NLGE_WRITE(sc->base, R_MAC_ADDR_MASK3, 0xffffffff);
	NLGE_WRITE(sc->base, R_MAC_ADDR_MASK3 + 1, 0xffffffff);

	NLGE_WRITE(sc->base, R_MAC_FILTER_CONFIG,
		  (1 << O_MAC_FILTER_CONFIG__BROADCAST_EN) |
		  (1 << O_MAC_FILTER_CONFIG__ALL_MCAST_EN) |
		  (1 << O_MAC_FILTER_CONFIG__MAC_ADDR0_VALID));

	if (sc->port_type == XLR_RGMII || sc->port_type == XLR_SGMII) {
		NLGE_UPDATE(sc->base, R_IPG_IFG, MAC_B2B_IPG, 0x7f);
	}
}

static int
nlge_if_init(struct nlge_softc *sc)
{
	struct ifnet 	*ifp;
	device_t	dev;
	int error;

	error = 0;
	dev = sc->nlge_dev;
	NLGE_LOCK_INIT(sc, device_get_nameunit(dev));

	ifp = sc->nlge_if = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(dev, "can not if_alloc()\n");
		error = ENOSPC;
		goto fail;
	}
	ifp->if_softc = sc;
	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_capabilities = IFCAP_TXCSUM | IFCAP_VLAN_HWTAGGING;
	ifp->if_capenable = ifp->if_capabilities;
	ifp->if_ioctl = nlge_ioctl;
	ifp->if_start = nlge_start;
	ifp->if_init = nlge_init;
	ifp->if_hwassist = 0;
	ifp->if_snd.ifq_drv_maxlen = RGE_TX_Q_SIZE;
	IFQ_SET_MAXLEN(&ifp->if_snd, ifp->if_snd.ifq_drv_maxlen);
	IFQ_SET_READY(&ifp->if_snd);

	ifmedia_init(&sc->nlge_mii.mii_media, 0, nlge_mediachange,
	    nlge_mediastatus);
	ifmedia_add(&sc->nlge_mii.mii_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->nlge_mii.mii_media, IFM_ETHER | IFM_AUTO);
	sc->nlge_mii.mii_media.ifm_media = sc->nlge_mii.mii_media.ifm_cur->ifm_media;
	nlge_read_mac_addr(sc);

	ether_ifattach(ifp, sc->dev_addr);

fail:
	return (error);
}

static void
nlge_mii_init(device_t dev, struct nlge_softc *sc)
{
	int error;

	if (sc->port_type != XLR_XAUI && sc->port_type != XLR_XGMII) {
		NLGE_WRITE(sc->mii_base, R_MII_MGMT_CONFIG, 0x07);
	}
	error = mii_phy_probe(dev, &sc->mii_bus, nlge_mediachange, nlge_mediastatus);
	if (error) {
		device_printf(dev, "no PHY device found\n");
		sc->mii_bus = NULL;
	}
	if (sc->mii_bus != NULL) {
		/*
		 * Enable all MDIO interrupts in the phy. RX_ER bit seems to get
		 * set about every 1 sec in GigE mode, ignore it for now...
		 */
		nlge_mii_write_internal(sc->mii_base, sc->phy_addr, 25,
		    0xfffffffe);
	}
}

/*
 *  Read a PHY register.
 *
 *  Input parameters:
 *  	   mii_base - Base address of MII
 *  	   phyaddr - PHY's address
 *  	   regidx = index of register to read
 *
 *  Return value:
 *  	   value read, or 0 if an error occurred.
 */

static int
nlge_mii_read_internal(xlr_reg_t *mii_base, int phyaddr, int regidx)
{
	int i, val;

	/* setup the phy reg to be used */
	NLGE_WRITE(mii_base, R_MII_MGMT_ADDRESS,
	    (phyaddr << 8) | (regidx << 0));
	/* Issue the read command */
	NLGE_WRITE(mii_base, R_MII_MGMT_COMMAND,
	    (1 << O_MII_MGMT_COMMAND__rstat));

	/* poll for the read cycle to complete */
	for (i = 0; i < PHY_STATUS_RETRIES; i++) {
		if (NLGE_READ(mii_base, R_MII_MGMT_INDICATORS) == 0)
			break;
	}

	/* clear the read cycle */
	NLGE_WRITE(mii_base, R_MII_MGMT_COMMAND, 0);

	if (i == PHY_STATUS_RETRIES) {
		return (0xffffffff);
	}

	val = NLGE_READ(mii_base, R_MII_MGMT_STATUS);

	return (val);
}

/*
 *  Write a value to a PHY register.
 *
 *  Input parameters:
 *  	   mii_base - Base address of MII
 *  	   phyaddr - PHY to use
 *  	   regidx - register within the PHY
 *  	   regval - data to write to register
 *
 *  Return value:
 *  	   nothing
 */
static void
nlge_mii_write_internal(xlr_reg_t *mii_base, int phyaddr, int regidx,
    int regval)
{
	int i;

	NLGE_WRITE(mii_base, R_MII_MGMT_ADDRESS,
	   (phyaddr << 8) | (regidx << 0));

	/* Write the data which starts the write cycle */
	NLGE_WRITE(mii_base, R_MII_MGMT_WRITE_DATA, regval);

	/* poll for the write cycle to complete */
	for (i = 0; i < PHY_STATUS_RETRIES; i++) {
		if (NLGE_READ(mii_base, R_MII_MGMT_INDICATORS) == 0)
			break;
	}
}

/*
 * Function to optimize the use of p2d descriptors for the given PDU.
 * As it is on the fast-path (called during packet transmission), it
 * described in more detail than the initialization functions.
 *
 * Input: mbuf chain (MC), pointer to fmn message
 * Input constraints: None
 * Output: FMN message to transmit the data in MC
 * Return values: 0 - success
 *                1 - MC cannot be handled (see Limitations below)
 *                2 - MC cannot be handled presently (maybe worth re-trying)
 * Other output: Number of entries filled in the FMN message
 *
 * Output structure/constraints:
 *     1. Max 3 p2d's + 1 zero-len (ZL) p2d with virtual address of MC.
 *     2. 3 p2d's + 1 p2p with max 14 p2d's (ZL p2d not required in this case).
 *     3. Each p2d points to physically contiguous chunk of data (subject to
 *        entire MC requiring max 17 p2d's).
 * Limitations:
 *     1. MC's that require more than 17 p2d's are not handled.
 * Benefits: MC's that require <= 3 p2d's avoid the overhead of allocating
 *           the p2p structure. Small packets (which typically give low
 *           performance) are expected to have a small MC that takes
 *           advantage of this.
 */
static int
prepare_fmn_message(struct nlge_softc *sc, struct msgrng_msg *fmn_msg,
    uint32_t *n_entries, struct mbuf *mbuf_chain, uint64_t fb_stn_id, 
    struct nlge_tx_desc **tx_desc)
{
	struct mbuf     *m;
	struct nlge_tx_desc *p2p;
	uint64_t        *cur_p2d;
	vm_offset_t	buf;
	vm_paddr_t      paddr;
	int             msg_sz, p2p_sz, is_p2p;
	int             len, frag_sz;
	/* Num entries per FMN msg is 4 for XLR/XLS */
	const int       FMN_SZ = sizeof(*fmn_msg) / sizeof(uint64_t);

	msg_sz = p2p_sz = is_p2p = 0;
	p2p = NULL;
	cur_p2d = &fmn_msg->msg0;

	for (m = mbuf_chain; m != NULL; m = m->m_next) {
		buf = (vm_offset_t) m->m_data;
		len = m->m_len;

		while (len) {
			if (msg_sz == (FMN_SZ - 1)) {
				p2p = uma_zalloc(nl_tx_desc_zone, M_NOWAIT);
				if (p2p == NULL) {
					return 2;
				}
				/*
				 * As we currently use xlr_paddr_lw on a 32-bit
				 * OS, both the pointers are laid out in one
				 * 64-bit location - this makes it easy to
				 * retrieve the pointers when processing the
				 * tx free-back descriptor.
				 */
				p2p->frag[XLR_MAX_TX_FRAGS] =
				    (((uint64_t) (vm_offset_t) p2p) << 32) |
				    ((vm_offset_t) mbuf_chain);
				cur_p2d = &p2p->frag[0];
				is_p2p = 1;
			} else if (msg_sz == (FMN_SZ - 2 + XLR_MAX_TX_FRAGS)) {
				uma_zfree(nl_tx_desc_zone, p2p);
				return 1;
			}
			paddr = vtophys(buf);
			frag_sz = PAGE_SIZE - (buf & PAGE_MASK);
			if (len < frag_sz)
				frag_sz = len;
			*cur_p2d++ = (127ULL << 54) | ((uint64_t)frag_sz << 40)
			    | paddr;
			msg_sz++;
			if (is_p2p)
				p2p_sz++;
			len -= frag_sz;
			buf += frag_sz;
		}
	}

	if (msg_sz ==  0) {
		printf("Zero-length mbuf chain ??\n");
		*n_entries = msg_sz ;
		return 0;
	}

	cur_p2d[-1] |= (1ULL << 63); /* set eop in most-recent p2d */
	*cur_p2d = (1ULL << 63) | ((uint64_t)fb_stn_id << 54) |
	     (vm_offset_t) mbuf_chain;
	*tx_desc = p2p;

	if (is_p2p) {
		paddr = vtophys(p2p);
		p2p_sz++;
		fmn_msg->msg3 = (1ULL << 62) | ((uint64_t)fb_stn_id << 54) |
		    ((uint64_t)(p2p_sz * 8) << 40) | paddr;
		*n_entries = FMN_SZ;
	} else {
		*n_entries = msg_sz + 1;
	}

	return (0);
}

static int
send_fmn_msg_tx(struct nlge_softc *sc, struct msgrng_msg *msg,
    uint32_t n_entries)
{
	uint32_t msgrng_flags;
	int i = 0, ret;

	do {
		msgrng_flags = msgrng_access_enable();
		ret = message_send_retry(n_entries, MSGRNG_CODE_MAC,
		    sc->tx_bucket_id, msg);
		msgrng_restore(msgrng_flags);
		KASSERT(i++ < 100000, ("Too many credit fails\n"));
	} while (ret != 0);
	return (0);
}

static void
release_mbuf(uint64_t phy_addr)
{
	struct mbuf	*m;

	m = (struct mbuf *)((uint32_t) phy_addr);
	m_freem(m);
}

static void
release_tx_desc(vm_paddr_t paddr)
{
	struct nlge_tx_desc *tx_desc;
	uint32_t 	sr;
	uint32_t	val1, val2;

	paddr += (XLR_MAX_TX_FRAGS * sizeof(uint64_t));
	sr = xlr_enable_kx();
	val1 = xlr_paddr_lw(paddr);
	paddr += sizeof(void *);
	val2 = xlr_paddr_lw(paddr);
	mips_wr_status(sr);

	tx_desc = (struct nlge_tx_desc*)(intptr_t) val1;
	uma_zfree(nl_tx_desc_zone, tx_desc);
}

static struct mbuf *
get_mbuf(void)
{
	struct mbuf *m_new;

	if ((m_new = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR)) == NULL)
		return NULL;
	m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;
	return (m_new);
}

static void *
get_buf(void)
{
	struct mbuf    *m_new;
	vm_paddr_t 	temp1, temp2;
	unsigned int 	*md;

	m_new = get_mbuf();
	if (m_new == NULL)
		return m_new;

	m_adj(m_new, XLR_CACHELINE_SIZE - ((unsigned int)m_new->m_data & 0x1f));
	md = (unsigned int *)m_new->m_data;
	md[0] = (unsigned int)m_new;	/* Back Ptr */
	md[1] = 0xf00bad;
	m_adj(m_new, XLR_CACHELINE_SIZE);

	temp1 = vtophys((vm_offset_t) m_new->m_data);
	temp2 = vtophys((vm_offset_t) m_new->m_data + 1536);
	if ((temp1 + 1536) != temp2)
		panic("ALLOCED BUFFER IS NOT CONTIGUOUS\n");

	return ((void *)m_new->m_data);
}

static int
nlge_gmac_config_speed(struct nlge_softc *sc, int quick)
{
	struct mii_data *md;
	xlr_reg_t  *mmio;
	int bmsr, n_tries, max_tries;
	int core_ctl[]    = { 0x2, 0x1, 0x0, 0x1 };
	int sgmii_speed[] = { SGMII_SPEED_10,
			      SGMII_SPEED_100,
			      SGMII_SPEED_1000,
			      SGMII_SPEED_100 };    /* default to 100Mbps */
	char *speed_str[] = { "10",
			      "100",
			      "1000",
			      "unknown, defaulting to 100" };
	int link_state = LINK_STATE_DOWN;

	if (sc->port_type == XLR_XAUI || sc->port_type == XLR_XGMII)
		return 0;

	md = NULL;
	mmio = sc->base;
	if (sc->mii_base != NULL) {
		max_tries = (quick == 1) ? 100 : 4000;
		bmsr = 0;
		for (n_tries = 0; n_tries < max_tries; n_tries++) {
			bmsr = nlge_mii_read_internal(sc->mii_base,
			    sc->phy_addr, MII_BMSR);
			if ((bmsr & BMSR_ACOMP) && (bmsr & BMSR_LINK))
				break; /* Auto-negotiation is complete
					  and link is up */
			DELAY(1000);
		}
		bmsr &= BMSR_LINK;
		sc->link = (bmsr == 0) ? xlr_mac_link_down : xlr_mac_link_up;
		sc->speed = nlge_mii_read_internal(sc->mii_base, sc->phy_addr, 28);
		sc->speed = (sc->speed >> 3) & 0x03;
		if (sc->link == xlr_mac_link_up) {
			link_state = LINK_STATE_UP;
			nlge_sgmii_init(sc);
		}
		if (sc->mii_bus)
			md = (struct mii_data *)device_get_softc(sc->mii_bus);
	}

	if (sc->port_type != XLR_RGMII)
		NLGE_WRITE(mmio, R_INTERFACE_CONTROL, sgmii_speed[sc->speed]);
	if (sc->speed == xlr_mac_speed_10 || sc->speed == xlr_mac_speed_100 ||
	    sc->speed == xlr_mac_speed_rsvd) {
		NLGE_WRITE(mmio, R_MAC_CONFIG_2, 0x7117);
	} else if (sc->speed == xlr_mac_speed_1000) {
		NLGE_WRITE(mmio, R_MAC_CONFIG_2, 0x7217);
		if (md != NULL) {
			ifmedia_set(&md->mii_media, IFM_MAKEWORD(IFM_ETHER,
			    IFM_1000_T, IFM_FDX, md->mii_instance));
		}
	}
	NLGE_WRITE(mmio, R_CORECONTROL, core_ctl[sc->speed]);
	if_link_state_change(sc->nlge_if, link_state);
	printf("%s: [%sMbps]\n", device_get_nameunit(sc->nlge_dev),
	    speed_str[sc->speed]);
		
	return (0);
}

/*
 * This function is called for each port that was added to the device tree
 * and it initializes the following port attributes:
 * 	- type
 *      - base (base address to access port-specific registers)
 *      - mii_base
 * 	- phy_addr
 */
static void
nlge_set_port_attribs(struct nlge_softc *sc,
    struct xlr_gmac_port *port_info)
{
	sc->instance = port_info->instance % 4;	/* TBD: will not work for SPI-4 */
	sc->port_type = port_info->type;
	sc->base = (xlr_reg_t *) (port_info->base_addr +
	    (uint32_t)DEFAULT_XLR_IO_BASE);
	sc->mii_base = (xlr_reg_t *) (port_info->mii_addr +
	    (uint32_t)DEFAULT_XLR_IO_BASE);
	if (port_info->pcs_addr != 0)
		sc->pcs_addr = (xlr_reg_t *) (port_info->pcs_addr +
		    (uint32_t)DEFAULT_XLR_IO_BASE);
	if (port_info->serdes_addr != 0)
		sc->serdes_addr = (xlr_reg_t *) (port_info->serdes_addr +
		    (uint32_t)DEFAULT_XLR_IO_BASE);
	sc->phy_addr = port_info->phy_addr;

	PDEBUG("Port%d: base=%p, mii_base=%p, phy_addr=%d\n", sc->id, sc->base,
	    sc->mii_base, sc->phy_addr);
}

/* ------------------------------------------------------------------------ */

/* Debug dump functions */

#ifdef DEBUG

static void
dump_reg(xlr_reg_t *base, uint32_t offset, char *name)
{
	int val;

	val = NLGE_READ(base, offset);
	printf("%-30s: 0x%8x 0x%8x\n", name, offset, val);
}

#define STRINGIFY(x) 		#x

static void
dump_na_registers(xlr_reg_t *base_addr, int port_id)
{
	PDEBUG("Register dump for NA (of port=%d)\n", port_id);
	dump_reg(base_addr, R_PARSERCONFIGREG, STRINGIFY(R_PARSERCONFIGREG));
	PDEBUG("Tx bucket sizes\n");
	dump_reg(base_addr, R_GMAC_JFR0_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_JFR0_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_RFR0_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_RFR0_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_TX0_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_TX0_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_TX1_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_TX1_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_TX2_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_TX2_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_TX3_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_TX3_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_JFR1_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_JFR1_BUCKET_SIZE));
	dump_reg(base_addr, R_GMAC_RFR1_BUCKET_SIZE,
	    STRINGIFY(R_GMAC_RFR1_BUCKET_SIZE));
	dump_reg(base_addr, R_TXDATAFIFO0, STRINGIFY(R_TXDATAFIFO0));
	dump_reg(base_addr, R_TXDATAFIFO1, STRINGIFY(R_TXDATAFIFO1));
}

static void
dump_gmac_registers(struct nlge_softc *sc)
{
	xlr_reg_t *base_addr = sc->base;
	int port_id = sc->instance;

	PDEBUG("Register dump for port=%d\n", port_id);
	if (sc->port_type == XLR_RGMII || sc->port_type == XLR_SGMII) {
		dump_reg(base_addr, R_MAC_CONFIG_1, STRINGIFY(R_MAC_CONFIG_1));
		dump_reg(base_addr, R_MAC_CONFIG_2, STRINGIFY(R_MAC_CONFIG_2));
		dump_reg(base_addr, R_IPG_IFG, STRINGIFY(R_IPG_IFG));
		dump_reg(base_addr, R_HALF_DUPLEX, STRINGIFY(R_HALF_DUPLEX));
		dump_reg(base_addr, R_MAXIMUM_FRAME_LENGTH,
		    STRINGIFY(R_MAXIMUM_FRAME_LENGTH));
		dump_reg(base_addr, R_TEST, STRINGIFY(R_TEST));
		dump_reg(base_addr, R_MII_MGMT_CONFIG,
		    STRINGIFY(R_MII_MGMT_CONFIG));
		dump_reg(base_addr, R_MII_MGMT_COMMAND,
		    STRINGIFY(R_MII_MGMT_COMMAND));
		dump_reg(base_addr, R_MII_MGMT_ADDRESS,
		    STRINGIFY(R_MII_MGMT_ADDRESS));
		dump_reg(base_addr, R_MII_MGMT_WRITE_DATA,
		    STRINGIFY(R_MII_MGMT_WRITE_DATA));
		dump_reg(base_addr, R_MII_MGMT_STATUS,
		    STRINGIFY(R_MII_MGMT_STATUS));
		dump_reg(base_addr, R_MII_MGMT_INDICATORS,
		    STRINGIFY(R_MII_MGMT_INDICATORS));
		dump_reg(base_addr, R_INTERFACE_CONTROL,
		    STRINGIFY(R_INTERFACE_CONTROL));
		dump_reg(base_addr, R_INTERFACE_STATUS,
		    STRINGIFY(R_INTERFACE_STATUS));
	} else if (sc->port_type == XLR_XAUI || sc->port_type == XLR_XGMII) {
		dump_reg(base_addr, R_XGMAC_CONFIG_0,
		    STRINGIFY(R_XGMAC_CONFIG_0));
		dump_reg(base_addr, R_XGMAC_CONFIG_1,
		    STRINGIFY(R_XGMAC_CONFIG_1));
		dump_reg(base_addr, R_XGMAC_CONFIG_2,
		    STRINGIFY(R_XGMAC_CONFIG_2));
		dump_reg(base_addr, R_XGMAC_CONFIG_3,
		    STRINGIFY(R_XGMAC_CONFIG_3));
		dump_reg(base_addr, R_XGMAC_STATION_ADDRESS_LS,
		    STRINGIFY(R_XGMAC_STATION_ADDRESS_LS));
		dump_reg(base_addr, R_XGMAC_STATION_ADDRESS_MS,
		    STRINGIFY(R_XGMAC_STATION_ADDRESS_MS));
		dump_reg(base_addr, R_XGMAC_MAX_FRAME_LEN,
		    STRINGIFY(R_XGMAC_MAX_FRAME_LEN));
		dump_reg(base_addr, R_XGMAC_REV_LEVEL,
		    STRINGIFY(R_XGMAC_REV_LEVEL));
		dump_reg(base_addr, R_XGMAC_MIIM_COMMAND,
		    STRINGIFY(R_XGMAC_MIIM_COMMAND));
		dump_reg(base_addr, R_XGMAC_MIIM_FILED,
		    STRINGIFY(R_XGMAC_MIIM_FILED));
		dump_reg(base_addr, R_XGMAC_MIIM_CONFIG,
		    STRINGIFY(R_XGMAC_MIIM_CONFIG));
		dump_reg(base_addr, R_XGMAC_MIIM_LINK_FAIL_VECTOR,
		    STRINGIFY(R_XGMAC_MIIM_LINK_FAIL_VECTOR));
		dump_reg(base_addr, R_XGMAC_MIIM_INDICATOR,
		    STRINGIFY(R_XGMAC_MIIM_INDICATOR));
	}

	dump_reg(base_addr, R_MAC_ADDR0, STRINGIFY(R_MAC_ADDR0));
	dump_reg(base_addr, R_MAC_ADDR0 + 1, STRINGIFY(R_MAC_ADDR0+1));
	dump_reg(base_addr, R_MAC_ADDR1, STRINGIFY(R_MAC_ADDR1));
	dump_reg(base_addr, R_MAC_ADDR2, STRINGIFY(R_MAC_ADDR2));
	dump_reg(base_addr, R_MAC_ADDR3, STRINGIFY(R_MAC_ADDR3));
	dump_reg(base_addr, R_MAC_ADDR_MASK2, STRINGIFY(R_MAC_ADDR_MASK2));
	dump_reg(base_addr, R_MAC_ADDR_MASK3, STRINGIFY(R_MAC_ADDR_MASK3));
	dump_reg(base_addr, R_MAC_FILTER_CONFIG, STRINGIFY(R_MAC_FILTER_CONFIG));
	dump_reg(base_addr, R_TX_CONTROL, STRINGIFY(R_TX_CONTROL));
	dump_reg(base_addr, R_RX_CONTROL, STRINGIFY(R_RX_CONTROL));
	dump_reg(base_addr, R_DESC_PACK_CTRL, STRINGIFY(R_DESC_PACK_CTRL));
	dump_reg(base_addr, R_STATCTRL, STRINGIFY(R_STATCTRL));
	dump_reg(base_addr, R_L2ALLOCCTRL, STRINGIFY(R_L2ALLOCCTRL));
	dump_reg(base_addr, R_INTMASK, STRINGIFY(R_INTMASK));
	dump_reg(base_addr, R_INTREG, STRINGIFY(R_INTREG));
	dump_reg(base_addr, R_TXRETRY, STRINGIFY(R_TXRETRY));
	dump_reg(base_addr, R_CORECONTROL, STRINGIFY(R_CORECONTROL));
	dump_reg(base_addr, R_BYTEOFFSET0, STRINGIFY(R_BYTEOFFSET0));
	dump_reg(base_addr, R_BYTEOFFSET1, STRINGIFY(R_BYTEOFFSET1));
	dump_reg(base_addr, R_L2TYPE_0, STRINGIFY(R_L2TYPE_0));
	dump_na_registers(base_addr, port_id);
}

static void
dump_fmn_cpu_credits_for_gmac(struct xlr_board_info *board, int gmac_id)
{
	struct stn_cc *cc;
	int gmac_bucket_ids[] = { 97, 98, 99, 100, 101, 103 };
	int j, k, r, c;
	int n_gmac_buckets;

	n_gmac_buckets = sizeof (gmac_bucket_ids) / sizeof (gmac_bucket_ids[0]);
	for (j = 0; j < 8; j++) { 		// for each cpu
		cc = board->credit_configs[j];
		printf("Credits for Station CPU_%d ---> GMAC buckets (tx path)\n", j);
		for (k = 0; k < n_gmac_buckets; k++) {
			r = gmac_bucket_ids[k] / 8;
			c = gmac_bucket_ids[k] % 8;
			printf ("    --> gmac%d_bucket_%-3d: credits=%d\n", gmac_id,
				gmac_bucket_ids[k], cc->counters[r][c]);
		}
	}
}

static void
dump_fmn_gmac_credits(struct xlr_board_info *board, int gmac_id)
{
	struct stn_cc *cc;
	int j, k;

	cc = board->gmac_block[gmac_id].credit_config;
	printf("Credits for Station: GMAC_%d ---> CPU buckets (rx path)\n", gmac_id);
	for (j = 0; j < 8; j++) { 		// for each cpu
		printf("    ---> cpu_%d\n", j);
		for (k = 0; k < 8; k++) {	// for each bucket in cpu
			printf("        ---> bucket_%d: credits=%d\n", j * 8 + k,
			       cc->counters[j][k]);
		}
	}
}

static void
dump_board_info(struct xlr_board_info *board)
{
	struct xlr_gmac_block_t *gm;
	int i, k;

	printf("cpu=%x ", xlr_revision());
	printf("board_version: major=%llx, minor=%llx\n",
	    xlr_boot1_info.board_major_version,
	    xlr_boot1_info.board_minor_version);
	printf("is_xls=%d, nr_cpus=%d, usb=%s, cfi=%s, ata=%s\npci_irq=%d,"
	    "gmac_ports=%d\n", board->is_xls, board->nr_cpus,
	    board->usb ? "Yes" : "No", board->cfi ? "Yes": "No",
	    board->ata ? "Yes" : "No", board->pci_irq, board->gmacports);
	printf("FMN: Core-station bucket sizes\n");
	for (i = 0; i < 128; i++) {
		if (i && ((i % 16) == 0))
			printf("\n");
		printf ("b[%d] = %d ", i, board->bucket_sizes->bucket[i]);
	}
	printf("\n");
	for (i = 0; i < 3; i++) {
		gm = &board->gmac_block[i];
		printf("RNA_%d: type=%d, enabled=%s, mode=%d, station_id=%d,"
		    "station_txbase=%d, station_rfr=%d ", i, gm->type,
		    gm->enabled ? "Yes" : "No", gm->mode, gm->station_id,
		    gm->station_txbase, gm->station_rfr);
		printf("n_ports=%d, baseaddr=%p, baseirq=%d, baseinst=%d\n",
		     gm->num_ports, (xlr_reg_t *)gm->baseaddr, gm->baseirq,
		     gm->baseinst);
	}
	for (k = 0; k < 3; k++) { 	// for each NA
		dump_fmn_cpu_credits_for_gmac(board, k);
		dump_fmn_gmac_credits(board, k);
	}
}

static void
dump_mac_stats(struct nlge_softc *sc)
{
	xlr_reg_t *addr;
	uint32_t pkts_tx, pkts_rx;

	addr = sc->base;
	pkts_rx = NLGE_READ(sc->base, R_RPKT);
	pkts_tx = NLGE_READ(sc->base, R_TPKT);

	printf("[nlge_%d mac stats]: pkts_tx=%u, pkts_rx=%u\n", sc->id, pkts_tx,
	    pkts_rx);
	if (pkts_rx > 0) {
		uint32_t r;

		/* dump all rx counters. we need this because pkts_rx includes
		   bad packets. */
		for (r = R_RFCS; r <= R_ROVR; r++)
			printf("[nlge_%d mac stats]: [0x%x]=%u\n", sc->id, r,
			    NLGE_READ(sc->base, r));
	}
	if (pkts_tx > 0) {
		uint32_t r;

		/* dump all tx counters. might be useful for debugging. */
		for (r = R_TMCA; r <= R_TFRG; r++) {
			if ((r == (R_TNCL + 1)) || (r == (R_TNCL + 2)))
				continue;
			printf("[nlge_%d mac stats]: [0x%x]=%u\n", sc->id, r,
			    NLGE_READ(sc->base, r));
		}
	}
		
}

static void
dump_mii_regs(struct nlge_softc *sc)
{
	uint32_t mii_regs[] = {  0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
	                         0x8,  0x9,  0xa,  0xf, 0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				0x1c, 0x1d, 0x1e};
	int i, n_regs;

	if (sc->mii_base == NULL || sc->mii_bus == NULL)
		return;

	n_regs = sizeof (mii_regs) / sizeof (mii_regs[0]);
	for (i = 0; i < n_regs; i++) {
		printf("[mii_0x%x] = %x\n", mii_regs[i],
		    nlge_mii_read_internal(sc->mii_base, sc->phy_addr,
		        mii_regs[i]));
	}
}

static void
dump_ifmedia(struct ifmedia *ifm)
{
	printf("ifm_mask=%08x, ifm_media=%08x, cur=%p\n", ifm->ifm_mask,
	    ifm->ifm_media, ifm->ifm_cur);
	if (ifm->ifm_cur != NULL) {
		printf("Cur attribs: ifmedia_entry.ifm_media=%08x,"
		    " ifmedia_entry.ifm_data=%08x\n", ifm->ifm_cur->ifm_media,
		    ifm->ifm_cur->ifm_data);
	}
}

static void
dump_mii_data(struct mii_data *mii)
{
	dump_ifmedia(&mii->mii_media);
	printf("ifp=%p, mii_instance=%d, mii_media_status=%08x,"
	    " mii_media_active=%08x\n", mii->mii_ifp, mii->mii_instance,
	    mii->mii_media_status, mii->mii_media_active);
}

static void
dump_pcs_regs(struct nlge_softc *sc, int phy)
{
	int i, val;

	printf("PCS regs from %p for phy=%d\n", sc->pcs_addr, phy);
	for (i = 0; i < 18; i++) {
		if (i == 2 || i == 3 || (i >= 9 && i <= 14))
			continue;
		val = nlge_mii_read_internal(sc->pcs_addr, phy, i);
		printf("PHY:%d pcs[0x%x] is 0x%x\n", phy, i, val);
	}
}
#endif
