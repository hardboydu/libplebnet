/******************************************************************************

  Copyright (c) 2001-2009, Intel Corporation 
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:
  
   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
  
   2. Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
  
   3. Neither the name of the Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived from 
      this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/*$FreeBSD$*/


#ifdef HAVE_KERNEL_OPTION_HEADERS
#include "opt_device_polling.h"
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#if __FreeBSD_version >= 800000
#include <sys/buf_ring.h>
#endif
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/eventhandler.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <machine/smp.h>
#include <machine/bus.h>
#include <machine/resource.h>

#ifdef IGB_IEEE1588
#include <sys/ieee1588.h>
#endif

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_lro.h>
#include <netinet/udp.h>

#include <machine/in_cksum.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include "e1000_api.h"
#include "e1000_82575.h"
#include "if_igb.h"

/*********************************************************************
 *  Set this to one to display debug statistics
 *********************************************************************/
int	igb_display_debug_stats = 0;

/*********************************************************************
 *  Driver version:
 *********************************************************************/
char igb_driver_version[] = "version - 1.7.3";


/*********************************************************************
 *  PCI Device ID Table
 *
 *  Used by probe to select devices to load on
 *  Last field stores an index into e1000_strings
 *  Last entry must be all 0s
 *
 *  { Vendor ID, Device ID, SubVendor ID, SubDevice ID, String Index }
 *********************************************************************/

static igb_vendor_info_t igb_vendor_info_array[] =
{
	{ 0x8086, E1000_DEV_ID_82575EB_COPPER,	PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82575EB_FIBER_SERDES,
						PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82575GB_QUAD_COPPER,
						PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82576,		PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82576_NS,	PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82576_FIBER,	PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82576_SERDES,	PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82576_SERDES_QUAD,
						PCI_ANY_ID, PCI_ANY_ID, 0},
	{ 0x8086, E1000_DEV_ID_82576_QUAD_COPPER,
						PCI_ANY_ID, PCI_ANY_ID, 0},
	/* required last entry */
	{ 0, 0, 0, 0, 0}
};

/*********************************************************************
 *  Table of branding strings for all supported NICs.
 *********************************************************************/

static char *igb_strings[] = {
	"Intel(R) PRO/1000 Network Connection"
};

/*********************************************************************
 *  Function prototypes
 *********************************************************************/
static int	igb_probe(device_t);
static int	igb_attach(device_t);
static int	igb_detach(device_t);
static int	igb_shutdown(device_t);
static int	igb_suspend(device_t);
static int	igb_resume(device_t);
static void	igb_start(struct ifnet *);
static void	igb_start_locked(struct tx_ring *, struct ifnet *ifp);
#if __FreeBSD_version >= 800000
static int	igb_mq_start(struct ifnet *, struct mbuf *);
static int	igb_mq_start_locked(struct ifnet *,
		    struct tx_ring *, struct mbuf *);
static void	igb_qflush(struct ifnet *);
#endif
static int	igb_ioctl(struct ifnet *, u_long, caddr_t);
static void	igb_watchdog(struct adapter *);
static void	igb_init(void *);
static void	igb_init_locked(struct adapter *);
static void	igb_stop(void *);
static void	igb_media_status(struct ifnet *, struct ifmediareq *);
static int	igb_media_change(struct ifnet *);
static void	igb_identify_hardware(struct adapter *);
static int	igb_allocate_pci_resources(struct adapter *);
static int	igb_allocate_msix(struct adapter *);
static int	igb_allocate_legacy(struct adapter *);
static int	igb_setup_msix(struct adapter *);
static void	igb_free_pci_resources(struct adapter *);
static void	igb_local_timer(void *);
static int	igb_hardware_init(struct adapter *);
static void	igb_setup_interface(device_t, struct adapter *);
static int	igb_allocate_queues(struct adapter *);
static void	igb_configure_queues(struct adapter *);

static int	igb_allocate_transmit_buffers(struct tx_ring *);
static void	igb_setup_transmit_structures(struct adapter *);
static void	igb_setup_transmit_ring(struct tx_ring *);
static void	igb_initialize_transmit_units(struct adapter *);
static void	igb_free_transmit_structures(struct adapter *);
static void	igb_free_transmit_buffers(struct tx_ring *);

static int	igb_allocate_receive_buffers(struct rx_ring *);
static int	igb_setup_receive_structures(struct adapter *);
static int	igb_setup_receive_ring(struct rx_ring *);
static void	igb_initialize_receive_units(struct adapter *);
static void	igb_free_receive_structures(struct adapter *);
static void	igb_free_receive_buffers(struct rx_ring *);

static void	igb_enable_intr(struct adapter *);
static void	igb_disable_intr(struct adapter *);
static void	igb_update_stats_counters(struct adapter *);
static bool	igb_txeof(struct tx_ring *);
static bool	igb_rxeof(struct rx_ring *, int);
static void	igb_rx_checksum(u32, struct mbuf *, bool);
static int	igb_tx_ctx_setup(struct tx_ring *, struct mbuf *);
static bool	igb_tso_setup(struct tx_ring *, struct mbuf *, u32 *);
static void	igb_set_promisc(struct adapter *);
static void	igb_disable_promisc(struct adapter *);
static void	igb_set_multi(struct adapter *);
static void	igb_print_hw_stats(struct adapter *);
static void	igb_update_link_status(struct adapter *);
static int	igb_get_buf(struct rx_ring *, int, u8);

static void	igb_register_vlan(void *, struct ifnet *, u16);
static void	igb_unregister_vlan(void *, struct ifnet *, u16);
static void	igb_setup_vlan_hw_support(struct adapter *);

static int	igb_xmit(struct tx_ring *, struct mbuf **);
static int	igb_dma_malloc(struct adapter *, bus_size_t,
		    struct igb_dma_alloc *, int);
static void	igb_dma_free(struct adapter *, struct igb_dma_alloc *);
static void	igb_print_debug_info(struct adapter *);
static void	igb_print_nvm_info(struct adapter *);
static int 	igb_is_valid_ether_addr(u8 *);
static int	igb_sysctl_stats(SYSCTL_HANDLER_ARGS);
static int	igb_sysctl_debug_info(SYSCTL_HANDLER_ARGS);
/* Management and WOL Support */
static void	igb_init_manageability(struct adapter *);
static void	igb_release_manageability(struct adapter *);
static void     igb_get_hw_control(struct adapter *);
static void     igb_release_hw_control(struct adapter *);
static void     igb_enable_wakeup(device_t);

static int	igb_irq_fast(void *);
static void	igb_add_rx_process_limit(struct adapter *, const char *,
		    const char *, int *, int);
static void	igb_handle_rxtx(void *context, int pending);
static void	igb_handle_tx(void *context, int pending);
static void	igb_handle_rx(void *context, int pending);

/* These are MSIX only irq handlers */
static void	igb_msix_rx(void *);
static void	igb_msix_tx(void *);
static void	igb_msix_link(void *);

/* Adaptive Interrupt Moderation */
static void	igb_update_aim(struct rx_ring *);

/*********************************************************************
 *  FreeBSD Device Interface Entry Points
 *********************************************************************/

static device_method_t igb_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, igb_probe),
	DEVMETHOD(device_attach, igb_attach),
	DEVMETHOD(device_detach, igb_detach),
	DEVMETHOD(device_shutdown, igb_shutdown),
	DEVMETHOD(device_suspend, igb_suspend),
	DEVMETHOD(device_resume, igb_resume),
	{0, 0}
};

static driver_t igb_driver = {
	"igb", igb_methods, sizeof(struct adapter),
};

static devclass_t igb_devclass;
DRIVER_MODULE(igb, pci, igb_driver, igb_devclass, 0, 0);
MODULE_DEPEND(igb, pci, 1, 1, 1);
MODULE_DEPEND(igb, ether, 1, 1, 1);

/*********************************************************************
 *  Tunable default values.
 *********************************************************************/

/* Descriptor defaults */
static int igb_rxd = IGB_DEFAULT_RXD;
static int igb_txd = IGB_DEFAULT_TXD;
TUNABLE_INT("hw.igb.rxd", &igb_rxd);
TUNABLE_INT("hw.igb.txd", &igb_txd);

/*
** These parameters are used in Adaptive
** Interrupt Moderation. The value is set
** into EITR and controls the interrupt
** frequency. A variable static scheme can
** be created by changing the assigned value
** of igb_ave_latency to the desired value,
** and then set igb_enable_aim to FALSE.
** This will result in all EITR registers
** getting set to that value statically.
*/
static int igb_enable_aim = TRUE;
TUNABLE_INT("hw.igb.enable_aim", &igb_enable_aim);
static int igb_low_latency = IGB_LOW_LATENCY;
TUNABLE_INT("hw.igb.low_latency", &igb_low_latency);
static int igb_ave_latency = IGB_AVE_LATENCY;
TUNABLE_INT("hw.igb.ave_latency", &igb_ave_latency);
static int igb_bulk_latency = IGB_BULK_LATENCY;
TUNABLE_INT("hw.igb.bulk_latency", &igb_bulk_latency);
                
/*
** This will autoconfigure based on the number
** of CPUs if set to 0. Only a matched pair of
** TX and RX rings are allowed.
*/
static int igb_num_queues = 1;
TUNABLE_INT("hw.igb.num_queues", &igb_num_queues);

/* How many packets rxeof tries to clean at a time */
static int igb_rx_process_limit = 100;
TUNABLE_INT("hw.igb.rx_process_limit", &igb_rx_process_limit);

/* Flow control setting - default to FULL */
static int igb_fc_setting = e1000_fc_full;
TUNABLE_INT("hw.igb.fc_setting", &igb_fc_setting);

/*
** Shadow VFTA table, this is needed because
** the real filter table gets cleared during
** a soft reset and the driver needs to be able
** to repopulate it.
*/
static u32 igb_shadow_vfta[IGB_VFTA_SIZE];


/*********************************************************************
 *  Device identification routine
 *
 *  igb_probe determines if the driver should be loaded on
 *  adapter based on PCI vendor/device id of the adapter.
 *
 *  return BUS_PROBE_DEFAULT on success, positive on failure
 *********************************************************************/

static int
igb_probe(device_t dev)
{
	char		adapter_name[60];
	uint16_t	pci_vendor_id = 0;
	uint16_t	pci_device_id = 0;
	uint16_t	pci_subvendor_id = 0;
	uint16_t	pci_subdevice_id = 0;
	igb_vendor_info_t *ent;

	INIT_DEBUGOUT("igb_probe: begin");

	pci_vendor_id = pci_get_vendor(dev);
	if (pci_vendor_id != IGB_VENDOR_ID)
		return (ENXIO);

	pci_device_id = pci_get_device(dev);
	pci_subvendor_id = pci_get_subvendor(dev);
	pci_subdevice_id = pci_get_subdevice(dev);

	ent = igb_vendor_info_array;
	while (ent->vendor_id != 0) {
		if ((pci_vendor_id == ent->vendor_id) &&
		    (pci_device_id == ent->device_id) &&

		    ((pci_subvendor_id == ent->subvendor_id) ||
		    (ent->subvendor_id == PCI_ANY_ID)) &&

		    ((pci_subdevice_id == ent->subdevice_id) ||
		    (ent->subdevice_id == PCI_ANY_ID))) {
			sprintf(adapter_name, "%s %s",
				igb_strings[ent->index],
				igb_driver_version);
			device_set_desc_copy(dev, adapter_name);
			return (BUS_PROBE_DEFAULT);
		}
		ent++;
	}

	return (ENXIO);
}

/*********************************************************************
 *  Device initialization routine
 *
 *  The attach entry point is called when the driver is being loaded.
 *  This routine identifies the type of hardware, allocates all resources
 *  and initializes the hardware.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/

static int
igb_attach(device_t dev)
{
	struct adapter	*adapter;
	int		error = 0;
	u16		eeprom_data;

	INIT_DEBUGOUT("igb_attach: begin");

	adapter = device_get_softc(dev);
	adapter->dev = adapter->osdep.dev = dev;
	IGB_CORE_LOCK_INIT(adapter, device_get_nameunit(dev));

	/* SYSCTL stuff */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "debug", CTLTYPE_INT|CTLFLAG_RW, adapter, 0,
	    igb_sysctl_debug_info, "I", "Debug Information");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "stats", CTLTYPE_INT|CTLFLAG_RW, adapter, 0,
	    igb_sysctl_stats, "I", "Statistics");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(adapter->dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(adapter->dev)),
	    OID_AUTO, "flow_control", CTLTYPE_INT|CTLFLAG_RW,
	    &igb_fc_setting, 0, "Flow Control");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "enable_aim", CTLTYPE_INT|CTLFLAG_RW,
	    &igb_enable_aim, 1, "Interrupt Moderation");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "low_latency", CTLTYPE_INT|CTLFLAG_RW,
	    &igb_low_latency, 1, "Low Latency");
                
	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "ave_latency", CTLTYPE_INT|CTLFLAG_RW,
	    &igb_ave_latency, 1, "Average Latency");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "bulk_latency", CTLTYPE_INT|CTLFLAG_RW,
	    &igb_bulk_latency, 1, "Bulk Latency");
 
	callout_init_mtx(&adapter->timer, &adapter->core_mtx, 0);

	/* Determine hardware and mac info */
	igb_identify_hardware(adapter);

	/* Setup PCI resources */
	if (igb_allocate_pci_resources(adapter)) {
		device_printf(dev, "Allocation of PCI resources failed\n");
		error = ENXIO;
		goto err_pci;
	}

	/* Do Shared Code initialization */
	if (e1000_setup_init_funcs(&adapter->hw, TRUE)) {
		device_printf(dev, "Setup of Shared code failed\n");
		error = ENXIO;
		goto err_pci;
	}

	e1000_get_bus_info(&adapter->hw);

	/* Sysctls for limiting the amount of work done in the taskqueue */
	igb_add_rx_process_limit(adapter, "rx_processing_limit",
	    "max number of rx packets to process", &adapter->rx_process_limit,
	    igb_rx_process_limit);

	/*
	 * Validate number of transmit and receive descriptors. It
	 * must not exceed hardware maximum, and must be multiple
	 * of E1000_DBA_ALIGN.
	 */
	if (((igb_txd * sizeof(struct e1000_tx_desc)) % IGB_DBA_ALIGN) != 0 ||
	    (igb_txd > IGB_MAX_TXD) || (igb_txd < IGB_MIN_TXD)) {
		device_printf(dev, "Using %d TX descriptors instead of %d!\n",
		    IGB_DEFAULT_TXD, igb_txd);
		adapter->num_tx_desc = IGB_DEFAULT_TXD;
	} else
		adapter->num_tx_desc = igb_txd;
	if (((igb_rxd * sizeof(struct e1000_rx_desc)) % IGB_DBA_ALIGN) != 0 ||
	    (igb_rxd > IGB_MAX_RXD) || (igb_rxd < IGB_MIN_RXD)) {
		device_printf(dev, "Using %d RX descriptors instead of %d!\n",
		    IGB_DEFAULT_RXD, igb_rxd);
		adapter->num_rx_desc = IGB_DEFAULT_RXD;
	} else
		adapter->num_rx_desc = igb_rxd;

	adapter->hw.mac.autoneg = DO_AUTO_NEG;
	adapter->hw.phy.autoneg_wait_to_complete = FALSE;
	adapter->hw.phy.autoneg_advertised = AUTONEG_ADV_DEFAULT;

	/* Copper options */
	if (adapter->hw.phy.media_type == e1000_media_type_copper) {
		adapter->hw.phy.mdix = AUTO_ALL_MODES;
		adapter->hw.phy.disable_polarity_correction = FALSE;
		adapter->hw.phy.ms_type = IGB_MASTER_SLAVE;
	}

	/*
	 * Set the frame limits assuming
	 * standard ethernet sized frames.
	 */
	adapter->max_frame_size = ETHERMTU + ETHER_HDR_LEN + ETHERNET_FCS_SIZE;
	adapter->min_frame_size = ETH_ZLEN + ETHERNET_FCS_SIZE;

	/*
	** Allocate and Setup Queues
	*/
	if (igb_allocate_queues(adapter)) {
		error = ENOMEM;
		goto err_pci;
	}

	/*
	** Start from a known state, this is
	** important in reading the nvm and
	** mac from that.
	*/
	e1000_reset_hw(&adapter->hw);

	/* Make sure we have a good EEPROM before we read from it */
	if (e1000_validate_nvm_checksum(&adapter->hw) < 0) {
		/*
		** Some PCI-E parts fail the first check due to
		** the link being in sleep state, call it again,
		** if it fails a second time its a real issue.
		*/
		if (e1000_validate_nvm_checksum(&adapter->hw) < 0) {
			device_printf(dev,
			    "The EEPROM Checksum Is Not Valid\n");
			error = EIO;
			goto err_late;
		}
	}

	/*
	** Copy the permanent MAC address out of the EEPROM
	*/
	if (e1000_read_mac_addr(&adapter->hw) < 0) {
		device_printf(dev, "EEPROM read error while reading MAC"
		    " address\n");
		error = EIO;
		goto err_late;
	}
	/* Check its sanity */
	if (!igb_is_valid_ether_addr(adapter->hw.mac.addr)) {
		device_printf(dev, "Invalid MAC address\n");
		error = EIO;
		goto err_late;
	}

	/* Now Initialize the hardware */
	if (igb_hardware_init(adapter)) {
		device_printf(dev, "Unable to initialize the hardware\n");
		error = EIO;
		goto err_late;
	}

	/* 
	** Configure Interrupts
	*/
	if (adapter->msix > 1) /* MSIX */
		error = igb_allocate_msix(adapter);
	else /* MSI or Legacy */
		error = igb_allocate_legacy(adapter);
	if (error)
		goto err_late;

	/* Setup OS specific network interface */
	igb_setup_interface(dev, adapter);

#ifdef IGB_IEEE1588
        /*
        ** Setup the timer: IEEE 1588 support
        */
        adapter->cycles.read = igb_read_clock;
        adapter->cycles.mask = (u64)-1;
        adapter->cycles.mult = 1;
        adapter->cycles.shift = IGB_TSYNC_SHIFT;
        E1000_WRITE_REG(&adapter->hw, E1000_TIMINCA, (1<<24) |
            IGB_TSYNC_CYCLE_TIME * IGB_TSYNC_SHIFT);
        E1000_WRITE_REG(&adapter->hw, E1000_SYSTIML, 0x00000000);
        E1000_WRITE_REG(&adapter->hw, E1000_SYSTIMH, 0xFF800000);

	// JFV - this is not complete yet
#endif

	/* Initialize statistics */
	igb_update_stats_counters(adapter);

	adapter->hw.mac.get_link_status = 1;
	igb_update_link_status(adapter);

	/* Indicate SOL/IDER usage */
	if (e1000_check_reset_block(&adapter->hw))
		device_printf(dev,
		    "PHY reset is blocked due to SOL/IDER session.\n");

	/* Determine if we have to control management hardware */
	adapter->has_manage = e1000_enable_mng_pass_thru(&adapter->hw);

	/*
	 * Setup Wake-on-Lan
	 */
	/* APME bit in EEPROM is mapped to WUC.APME */
	eeprom_data = E1000_READ_REG(&adapter->hw, E1000_WUC) & E1000_WUC_APME;
	if (eeprom_data)
		adapter->wol = E1000_WUFC_MAG;

	/* Register for VLAN events */
	adapter->vlan_attach = EVENTHANDLER_REGISTER(vlan_config,
	     igb_register_vlan, adapter, EVENTHANDLER_PRI_FIRST);
	adapter->vlan_detach = EVENTHANDLER_REGISTER(vlan_unconfig,
	     igb_unregister_vlan, adapter, EVENTHANDLER_PRI_FIRST);

	/* Tell the stack that the interface is not active */
	adapter->ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	INIT_DEBUGOUT("igb_attach: end");

	return (0);

err_late:
	igb_free_transmit_structures(adapter);
	igb_free_receive_structures(adapter);
	igb_release_hw_control(adapter);
err_pci:
	igb_free_pci_resources(adapter);
	IGB_CORE_LOCK_DESTROY(adapter);

	return (error);
}

/*********************************************************************
 *  Device removal routine
 *
 *  The detach entry point is called when the driver is being removed.
 *  This routine stops the adapter and deallocates all the resources
 *  that were allocated for driver operation.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/

static int
igb_detach(device_t dev)
{
	struct adapter	*adapter = device_get_softc(dev);
	struct ifnet	*ifp = adapter->ifp;

	INIT_DEBUGOUT("igb_detach: begin");

	/* Make sure VLANS are not using driver */
	if (adapter->ifp->if_vlantrunk != NULL) {
		device_printf(dev,"Vlan in use, detach first\n");
		return (EBUSY);
	}

	IGB_CORE_LOCK(adapter);
	adapter->in_detach = 1;
	igb_stop(adapter);
	IGB_CORE_UNLOCK(adapter);

	e1000_phy_hw_reset(&adapter->hw);

	/* Give control back to firmware */
	igb_release_manageability(adapter);
	igb_release_hw_control(adapter);

	if (adapter->wol) {
		E1000_WRITE_REG(&adapter->hw, E1000_WUC, E1000_WUC_PME_EN);
		E1000_WRITE_REG(&adapter->hw, E1000_WUFC, adapter->wol);
		igb_enable_wakeup(dev);
	}

	/* Unregister VLAN events */
	if (adapter->vlan_attach != NULL)
		EVENTHANDLER_DEREGISTER(vlan_config, adapter->vlan_attach);
	if (adapter->vlan_detach != NULL)
		EVENTHANDLER_DEREGISTER(vlan_unconfig, adapter->vlan_detach);

	ether_ifdetach(adapter->ifp);

	callout_drain(&adapter->timer);

	igb_free_pci_resources(adapter);
	bus_generic_detach(dev);
	if_free(ifp);

	igb_free_transmit_structures(adapter);
	igb_free_receive_structures(adapter);

	IGB_CORE_LOCK_DESTROY(adapter);

	return (0);
}

/*********************************************************************
 *
 *  Shutdown entry point
 *
 **********************************************************************/

static int
igb_shutdown(device_t dev)
{
	return igb_suspend(dev);
}

/*
 * Suspend/resume device methods.
 */
static int
igb_suspend(device_t dev)
{
	struct adapter *adapter = device_get_softc(dev);

	IGB_CORE_LOCK(adapter);

	igb_stop(adapter);

        igb_release_manageability(adapter);
	igb_release_hw_control(adapter);

        if (adapter->wol) {
                E1000_WRITE_REG(&adapter->hw, E1000_WUC, E1000_WUC_PME_EN);
                E1000_WRITE_REG(&adapter->hw, E1000_WUFC, adapter->wol);
                igb_enable_wakeup(dev);
        }

	IGB_CORE_UNLOCK(adapter);

	return bus_generic_suspend(dev);
}

static int
igb_resume(device_t dev)
{
	struct adapter *adapter = device_get_softc(dev);
	struct ifnet *ifp = adapter->ifp;

	IGB_CORE_LOCK(adapter);
	igb_init_locked(adapter);
	igb_init_manageability(adapter);

	if ((ifp->if_flags & IFF_UP) &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING))
		igb_start(ifp);

	IGB_CORE_UNLOCK(adapter);

	return bus_generic_resume(dev);
}


/*********************************************************************
 *  Transmit entry point
 *
 *  igb_start is called by the stack to initiate a transmit.
 *  The driver will remain in this routine as long as there are
 *  packets to transmit and transmit resources are available.
 *  In case resources are not available stack is notified and
 *  the packet is requeued.
 **********************************************************************/

static void
igb_start_locked(struct tx_ring *txr, struct ifnet *ifp)
{
	struct adapter	*adapter = ifp->if_softc;
	struct mbuf	*m_head;

	IGB_TX_LOCK_ASSERT(txr);

	if ((ifp->if_drv_flags & (IFF_DRV_RUNNING|IFF_DRV_OACTIVE)) !=
	    IFF_DRV_RUNNING)
		return;
	if (!adapter->link_active)
		return;

	while (!IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {

		IFQ_DRV_DEQUEUE(&ifp->if_snd, m_head);
		if (m_head == NULL)
			break;
		/*
		 *  Encapsulation can modify our pointer, and or make it
		 *  NULL on failure.  In that event, we can't requeue.
		 */
		if (igb_xmit(txr, &m_head)) {
			if (m_head == NULL)
				break;
			ifp->if_drv_flags |= IFF_DRV_OACTIVE;
			IFQ_DRV_PREPEND(&ifp->if_snd, m_head);
			break;
		}

		/* Send a copy of the frame to the BPF listener */
		ETHER_BPF_MTAP(ifp, m_head);

		/* Set timeout in case hardware has problems transmitting. */
		txr->watchdog_timer = IGB_TX_TIMEOUT;
	}
}
 
/*
 * Legacy TX driver routine, called from the
 * stack, always uses tx[0], and spins for it.
 * Should not be used with multiqueue tx
 */
static void
igb_start(struct ifnet *ifp)
{
	struct adapter	*adapter = ifp->if_softc;
	struct tx_ring	*txr = adapter->tx_rings;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		IGB_TX_LOCK(txr);
		igb_start_locked(txr, ifp);
		IGB_TX_UNLOCK(txr);
	}
	return;
}

#if __FreeBSD_version >= 800000
/*
** Multiqueue Transmit driver
**
*/
static int
igb_mq_start(struct ifnet *ifp, struct mbuf *m)
{
	struct adapter	*adapter = ifp->if_softc;
	struct tx_ring	*txr;
	int 		i = 0, err = 0;

	/* Which queue to use */
	if ((m->m_flags & M_FLOWID) != 0)
		i = m->m_pkthdr.flowid % adapter->num_queues;
	txr = &adapter->tx_rings[i];

	if (IGB_TX_TRYLOCK(txr)) {
		err = igb_mq_start_locked(ifp, txr, m);
		IGB_TX_UNLOCK(txr);
	} else
		err = drbr_enqueue(ifp, txr->br, m);

	return (err);
}

static int
igb_mq_start_locked(struct ifnet *ifp, struct tx_ring *txr, struct mbuf *m)
{
	struct adapter  *adapter = txr->adapter;
        struct mbuf     *next;
        int             err = 0;

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0) {
		err = drbr_enqueue(ifp, txr->br, m);
		return (err);
	}

	if (m == NULL) /* Called by tasklet */
		goto process;

	/* If nothing queued go right to xmit */
	if (drbr_empty(ifp, txr->br)) {
		if ((err = igb_xmit(txr, &m)) != 0) {
			if (m != NULL)
				err = drbr_enqueue(ifp, txr->br, m);
			return (err);
		} else {
			/* Success, update stats */
			drbr_stats_update(ifp, m->m_pkthdr.len, m->m_flags);
			/* Send a copy of the frame to the BPF listener */
			ETHER_BPF_MTAP(ifp, m);
			/* Set the watchdog */
			txr->watchdog_timer = IGB_TX_TIMEOUT;
                }

        } else if ((err = drbr_enqueue(ifp, txr->br, m)) != 0)
		return (err);

process:
	if (drbr_empty(ifp, txr->br))
		return (err);

	/* Process the queue */
	while (TRUE) {
		if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
			break;
		next = drbr_dequeue(ifp, txr->br);
		if (next == NULL)
			break;
		if ((err = igb_xmit(txr, &next)) != 0) {
			if (next != NULL)
				err = drbr_enqueue(ifp, txr->br, next);
			break;
		}
		drbr_stats_update(ifp, next->m_pkthdr.len, next->m_flags);
		ETHER_BPF_MTAP(ifp, next);
		/* Set the watchdog */
		txr->watchdog_timer = IGB_TX_TIMEOUT;
	}
		
	if (txr->tx_avail <= IGB_TX_OP_THRESHOLD)
		ifp->if_drv_flags |= IFF_DRV_OACTIVE;

	return (err);
}

/*
** Flush all ring buffers
*/
static void
igb_qflush(struct ifnet *ifp)
{
	struct adapter	*adapter = ifp->if_softc;
	struct tx_ring	*txr = adapter->tx_rings;
	struct mbuf	*m;

	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		IGB_TX_LOCK(txr);
		while ((m = buf_ring_dequeue_sc(txr->br)) != NULL)
			m_freem(m);
		IGB_TX_UNLOCK(txr);
	}
	if_qflush(ifp);
}
#endif /* __FreeBSD_version >= 800000 */

/*********************************************************************
 *  Ioctl entry point
 *
 *  igb_ioctl is called when the user wants to configure the
 *  interface.
 *
 *  return 0 on success, positive on failure
 **********************************************************************/

static int
igb_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct adapter	*adapter = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
#ifdef INET
	struct ifaddr *ifa = (struct ifaddr *)data;
#endif
	int error = 0;

	if (adapter->in_detach)
		return (error);

	switch (command) {
	case SIOCSIFADDR:
#ifdef INET
		if (ifa->ifa_addr->sa_family == AF_INET) {
			/*
			 * XXX
			 * Since resetting hardware takes a very long time
			 * and results in link renegotiation we only
			 * initialize the hardware only when it is absolutely
			 * required.
			 */
			ifp->if_flags |= IFF_UP;
			if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
				IGB_CORE_LOCK(adapter);
				igb_init_locked(adapter);
				IGB_CORE_UNLOCK(adapter);
			}
			if (!(ifp->if_flags & IFF_NOARP))
				arp_ifinit(ifp, ifa);
		} else
#endif
			error = ether_ioctl(ifp, command, data);
		break;
	case SIOCSIFMTU:
	    {
		int max_frame_size;

		IOCTL_DEBUGOUT("ioctl rcv'd: SIOCSIFMTU (Set Interface MTU)");

		IGB_CORE_LOCK(adapter);
		max_frame_size = 9234;
		if (ifr->ifr_mtu > max_frame_size - ETHER_HDR_LEN -
		    ETHER_CRC_LEN) {
			IGB_CORE_UNLOCK(adapter);
			error = EINVAL;
			break;
		}

		ifp->if_mtu = ifr->ifr_mtu;
		adapter->max_frame_size =
		    ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
		igb_init_locked(adapter);
		IGB_CORE_UNLOCK(adapter);
		break;
	    }
	case SIOCSIFFLAGS:
		IOCTL_DEBUGOUT("ioctl rcv'd:\
		    SIOCSIFFLAGS (Set Interface Flags)");
		IGB_CORE_LOCK(adapter);
		if (ifp->if_flags & IFF_UP) {
			if ((ifp->if_drv_flags & IFF_DRV_RUNNING)) {
				if ((ifp->if_flags ^ adapter->if_flags) &
				    (IFF_PROMISC | IFF_ALLMULTI)) {
					igb_disable_promisc(adapter);
					igb_set_promisc(adapter);
				}
			} else
				igb_init_locked(adapter);
		} else
			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
				igb_stop(adapter);
		adapter->if_flags = ifp->if_flags;
		IGB_CORE_UNLOCK(adapter);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		IOCTL_DEBUGOUT("ioctl rcv'd: SIOC(ADD|DEL)MULTI");
		if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
			IGB_CORE_LOCK(adapter);
			igb_disable_intr(adapter);
			igb_set_multi(adapter);
				igb_enable_intr(adapter);
			IGB_CORE_UNLOCK(adapter);
		}
		break;
	case SIOCSIFMEDIA:
		/* Check SOL/IDER usage */
		IGB_CORE_LOCK(adapter);
		if (e1000_check_reset_block(&adapter->hw)) {
			IGB_CORE_UNLOCK(adapter);
			device_printf(adapter->dev, "Media change is"
			    " blocked due to SOL/IDER session.\n");
			break;
		}
		IGB_CORE_UNLOCK(adapter);
	case SIOCGIFMEDIA:
		IOCTL_DEBUGOUT("ioctl rcv'd: \
		    SIOCxIFMEDIA (Get/Set Interface Media)");
		error = ifmedia_ioctl(ifp, ifr, &adapter->media, command);
		break;
	case SIOCSIFCAP:
	    {
		int mask, reinit;

		IOCTL_DEBUGOUT("ioctl rcv'd: SIOCSIFCAP (Set Capabilities)");
		reinit = 0;
		mask = ifr->ifr_reqcap ^ ifp->if_capenable;
		if (mask & IFCAP_HWCSUM) {
			ifp->if_capenable ^= IFCAP_HWCSUM;
			reinit = 1;
		}
		if (mask & IFCAP_TSO4) {
			ifp->if_capenable ^= IFCAP_TSO4;
			reinit = 1;
		}
		if (mask & IFCAP_VLAN_HWTAGGING) {
			ifp->if_capenable ^= IFCAP_VLAN_HWTAGGING;
			reinit = 1;
		}
		if (mask & IFCAP_LRO) {
			ifp->if_capenable ^= IFCAP_LRO;
			reinit = 1;
		}
		if (reinit && (ifp->if_drv_flags & IFF_DRV_RUNNING))
			igb_init(adapter);
		VLAN_CAPABILITIES(ifp);
		break;
	    }

#ifdef IGB_IEEE1588
	/*
	** IOCTL support for Precision Time (IEEE 1588) Support
	*/
	case SIOCSHWTSTAMP:
		error = igb_hwtstamp_ioctl(adapter, ifp);
		break;
#endif

	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}

	return (error);
}

/*********************************************************************
 *  Watchdog timer:
 *
 *  This routine is called from the local timer every second.
 *  As long as transmit descriptors are being cleaned the value
 *  is non-zero and we do nothing. Reaching 0 indicates a tx hang
 *  and we then reset the device.
 *
 **********************************************************************/

static void
igb_watchdog(struct adapter *adapter)
{
	struct tx_ring	*txr = adapter->tx_rings;
	bool		tx_hang = FALSE;

	IGB_CORE_LOCK_ASSERT(adapter);

	/*
	** The timer is set to 5 every time start() queues a packet.
	** Then txeof keeps resetting it as long as it cleans at
	** least one descriptor.
	** Finally, anytime all descriptors are clean the timer is
	** set to 0.
	**
	** With TX Multiqueue we need to check every queue's timer,
	** if any time out we do the reset.
	*/
	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		IGB_TX_LOCK(txr);
		if (txr->watchdog_timer == 0 ||
		    (--txr->watchdog_timer)) {
			IGB_TX_UNLOCK(txr);
			continue;
		} else {
			tx_hang = TRUE;
			IGB_TX_UNLOCK(txr);
			break;
		}
	}
	if (tx_hang == FALSE)
		return;

	/* If we are in this routine because of pause frames, then
	 * don't reset the hardware.
	 */
	if (E1000_READ_REG(&adapter->hw, E1000_STATUS) &
	    E1000_STATUS_TXOFF) {
		txr = adapter->tx_rings; /* reset pointer */
		for (int i = 0; i < adapter->num_queues; i++, txr++) {
			IGB_TX_LOCK(txr);
			txr->watchdog_timer = IGB_TX_TIMEOUT;
			IGB_TX_UNLOCK(txr);
		}
		return;
	}

	if (e1000_check_for_link(&adapter->hw) == 0)
		device_printf(adapter->dev, "watchdog timeout -- resetting\n");

	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		device_printf(adapter->dev, "Queue(%d) tdh = %d, tdt = %d\n",
		    i, E1000_READ_REG(&adapter->hw, E1000_TDH(i)),
		    E1000_READ_REG(&adapter->hw, E1000_TDT(i)));
		device_printf(adapter->dev, "Queue(%d) desc avail = %d,"
		    " Next Desc to Clean = %d\n", i, txr->tx_avail,
		    txr->next_to_clean);
	}

	adapter->ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	adapter->watchdog_events++;

	igb_init_locked(adapter);
}

/*********************************************************************
 *  Init entry point
 *
 *  This routine is used in two ways. It is used by the stack as
 *  init entry point in network interface structure. It is also used
 *  by the driver as a hw/sw initialization routine to get to a
 *  consistent state.
 *
 *  return 0 on success, positive on failure
 **********************************************************************/

static void
igb_init_locked(struct adapter *adapter)
{
	struct rx_ring *rxr = adapter->rx_rings;
	struct tx_ring *txr = adapter->tx_rings;
	struct ifnet	*ifp = adapter->ifp;
	device_t	dev = adapter->dev;
	u32		pba = 0;

	INIT_DEBUGOUT("igb_init: begin");

	IGB_CORE_LOCK_ASSERT(adapter);

	igb_stop(adapter);

	/*
	 * Packet Buffer Allocation (PBA)
	 * Writing PBA sets the receive portion of the buffer
	 * the remainder is used for the transmit buffer.
	 */
	if (adapter->hw.mac.type == e1000_82575) {
		INIT_DEBUGOUT1("igb_init: pba=%dK",pba);
		pba = E1000_PBA_32K; /* 32K for Rx, 16K for Tx */
		E1000_WRITE_REG(&adapter->hw, E1000_PBA, pba);
	}
	
	/* Get the latest mac address, User can use a LAA */
        bcopy(IF_LLADDR(adapter->ifp), adapter->hw.mac.addr,
              ETHER_ADDR_LEN);

	/* Put the address into the Receive Address Array */
	e1000_rar_set(&adapter->hw, adapter->hw.mac.addr, 0);

	/* Initialize the hardware */
	if (igb_hardware_init(adapter)) {
		device_printf(dev, "Unable to initialize the hardware\n");
		return;
	}
	igb_update_link_status(adapter);

	E1000_WRITE_REG(&adapter->hw, E1000_VET, ETHERTYPE_VLAN);

	/* Set hardware offload abilities */
	ifp->if_hwassist = 0;
	if (ifp->if_capenable & IFCAP_TXCSUM) {
		ifp->if_hwassist |= (CSUM_TCP | CSUM_UDP);
#if __FreeBSD_version >= 800000
		if (adapter->hw.mac.type == e1000_82576)
			ifp->if_hwassist |= CSUM_SCTP;
#endif
	}

	if (ifp->if_capenable & IFCAP_TSO4)
		ifp->if_hwassist |= CSUM_TSO;

	/* Configure for OS presence */
	igb_init_manageability(adapter);

	/* Prepare transmit descriptors and buffers */
	igb_setup_transmit_structures(adapter);
	igb_initialize_transmit_units(adapter);

	/* Setup Multicast table */
	igb_set_multi(adapter);

	/*
	** Figure out the desired mbuf pool
	** for doing jumbo/packetsplit
	*/
	if (ifp->if_mtu > ETHERMTU)
		adapter->rx_mbuf_sz = MJUMPAGESIZE;
	else
		adapter->rx_mbuf_sz = MCLBYTES;

	/* Prepare receive descriptors and buffers */
	if (igb_setup_receive_structures(adapter)) {
		device_printf(dev, "Could not setup receive structures\n");
		igb_stop(adapter);
		return;
	}
	igb_initialize_receive_units(adapter);

	/* Don't lose promiscuous settings */
	igb_set_promisc(adapter);

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;

	callout_reset(&adapter->timer, hz, igb_local_timer, adapter);
	e1000_clear_hw_cntrs_base_generic(&adapter->hw);

	if (adapter->msix > 1) /* Set up queue routing */
		igb_configure_queues(adapter);

	/* Set up VLAN tag offload and filter */
	igb_setup_vlan_hw_support(adapter);

        /* Set default RX interrupt moderation */
	for (int i = 0; i < adapter->num_queues; i++, rxr++) {
		E1000_WRITE_REG(&adapter->hw,
		    E1000_EITR(rxr->msix), igb_ave_latency);
		rxr->eitr_setting = igb_ave_latency;
	}

	/* Set TX interrupt rate & reset TX watchdog */
	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		E1000_WRITE_REG(&adapter->hw, 
		    E1000_EITR(txr->msix), igb_ave_latency);
		txr->watchdog_timer = FALSE;
	}

	{
		/* this clears any pending interrupts */
		E1000_READ_REG(&adapter->hw, E1000_ICR);
		igb_enable_intr(adapter);
		E1000_WRITE_REG(&adapter->hw, E1000_ICS, E1000_ICS_LSC);
	}

	/* Don't reset the phy next time init gets called */
	adapter->hw.phy.reset_disable = TRUE;
}

static void
igb_init(void *arg)
{
	struct adapter *adapter = arg;

	IGB_CORE_LOCK(adapter);
	igb_init_locked(adapter);
	IGB_CORE_UNLOCK(adapter);
}


static void
igb_handle_rxtx(void *context, int pending)
{
	struct adapter	*adapter = context;
	struct tx_ring	*txr = adapter->tx_rings;
	struct rx_ring	*rxr = adapter->rx_rings;
	struct ifnet	*ifp;

	ifp = adapter->ifp;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		if (igb_rxeof(rxr, adapter->rx_process_limit))
			taskqueue_enqueue(adapter->tq, &adapter->rxtx_task);
		IGB_TX_LOCK(txr);
		igb_txeof(txr);

#if __FreeBSD_version >= 800000
		if (!drbr_empty(ifp, txr->br))
			igb_mq_start_locked(ifp, txr, NULL);
#else
		if (!IFQ_DRV_IS_EMPTY(&ifp->if_snd))
			igb_start_locked(txr, ifp);
#endif
		IGB_TX_UNLOCK(txr);
	}

	igb_enable_intr(adapter);
}

static void
igb_handle_rx(void *context, int pending)
{
	struct rx_ring  *rxr = context;
	struct adapter  *adapter = rxr->adapter;
	struct ifnet    *ifp = adapter->ifp;
            
	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		if (igb_rxeof(rxr, adapter->rx_process_limit) != 0)
			/* More to clean, schedule another task */
			taskqueue_enqueue(adapter->tq, &rxr->rx_task);
                
}

static void
igb_handle_tx(void *context, int pending)
{
	struct tx_ring  *txr = context;
	struct adapter  *adapter = txr->adapter;
	struct ifnet    *ifp = adapter->ifp;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		IGB_TX_LOCK(txr);
		igb_txeof(txr);
#if __FreeBSD_version >= 800000
		if (!drbr_empty(ifp, txr->br))
			igb_mq_start_locked(ifp, txr, NULL);
#else
		if (!IFQ_DRV_IS_EMPTY(&ifp->if_snd))
			igb_start_locked(txr, ifp);
#endif
		IGB_TX_UNLOCK(txr);
	}
}


/*********************************************************************
 *
 *  MSI/Legacy Deferred
 *  Interrupt Service routine  
 *
 *********************************************************************/
static int
igb_irq_fast(void *arg)
{
	struct adapter	*adapter = arg;
	uint32_t	reg_icr;


	reg_icr = E1000_READ_REG(&adapter->hw, E1000_ICR);

	/* Hot eject?  */
	if (reg_icr == 0xffffffff)
		return FILTER_STRAY;

	/* Definitely not our interrupt.  */
	if (reg_icr == 0x0)
		return FILTER_STRAY;

	if ((reg_icr & E1000_ICR_INT_ASSERTED) == 0)
		return FILTER_STRAY;

	/*
	 * Mask interrupts until the taskqueue is finished running.  This is
	 * cheap, just assume that it is needed.  This also works around the
	 * MSI message reordering errata on certain systems.
	 */
	igb_disable_intr(adapter);
	taskqueue_enqueue(adapter->tq, &adapter->rxtx_task);

	/* Link status change */
	if (reg_icr & (E1000_ICR_RXSEQ | E1000_ICR_LSC)) {
		adapter->hw.mac.get_link_status = 1;
		igb_update_link_status(adapter);
	}

	if (reg_icr & E1000_ICR_RXO)
		adapter->rx_overruns++;
	return FILTER_HANDLED;
}


/*********************************************************************
 *
 *  MSIX TX Interrupt Service routine
 *
 **********************************************************************/
static void
igb_msix_tx(void *arg)
{
	struct tx_ring *txr = arg;
	struct adapter *adapter = txr->adapter;
	u32		loop = IGB_MAX_LOOP;
	bool		more;

	++txr->tx_irq;
	IGB_TX_LOCK(txr);

	do {
		more = igb_txeof(txr);
	} while (loop-- && more);

	IGB_TX_UNLOCK(txr);

	/* Schedule a clean task */
	taskqueue_enqueue(adapter->tq, &txr->tx_task);

	/* Reenable this interrupt */
	E1000_WRITE_REG(&adapter->hw, E1000_EIMS, txr->eims);
	return;
}

/*********************************************************************
 *
 *  MSIX RX Interrupt Service routine
 *
 **********************************************************************/

static void
igb_msix_rx(void *arg)
{
	struct rx_ring *rxr = arg;
	struct adapter *adapter = rxr->adapter;
	u32		loop = IGB_MAX_LOOP;
	bool		more;

	++rxr->rx_irq;
	do {
		more = igb_rxeof(rxr, adapter->rx_process_limit);
	} while (loop-- && more);

	/* Update interrupt rate */
	if (igb_enable_aim == TRUE)
		igb_update_aim(rxr);

	/* Schedule another clean */
	taskqueue_enqueue(adapter->tq, &rxr->rx_task);

	/* Reenable this interrupt */
	E1000_WRITE_REG(&adapter->hw, E1000_EIMS, rxr->eims);
	return;
}


/*********************************************************************
 *
 *  MSIX Link Interrupt Service routine
 *
 **********************************************************************/

static void
igb_msix_link(void *arg)
{
	struct adapter	*adapter = arg;
	u32       	icr;

	++adapter->link_irq;
	icr = E1000_READ_REG(&adapter->hw, E1000_ICR);
	if (!(icr & E1000_ICR_LSC))
		goto spurious;
	adapter->hw.mac.get_link_status = 1;
	igb_update_link_status(adapter);

spurious:
	/* Rearm */
	E1000_WRITE_REG(&adapter->hw, E1000_IMS, E1000_IMS_LSC);
	E1000_WRITE_REG(&adapter->hw, E1000_EIMS, adapter->link_mask);
	return;
}


/*
** Routine to adjust the RX EITR value based on traffic,
** its a simple three state model, but seems to help.
**
** Note that the three EITR values are tuneable using
** sysctl in real time. The feature can be effectively
** nullified by setting them equal.
*/
#define BULK_THRESHOLD	10000
#define AVE_THRESHOLD	1600 

static void
igb_update_aim(struct rx_ring *rxr)
{
	struct adapter	*adapter = rxr->adapter;
	u32		olditr, newitr;

	/* Update interrupt moderation based on traffic */
	olditr = rxr->eitr_setting;
	newitr = olditr;

	/* Idle, don't change setting */
	if (rxr->bytes == 0)
		return;

	if (olditr == igb_low_latency) {
		if (rxr->bytes > AVE_THRESHOLD)
			newitr = igb_ave_latency;
	} else if (olditr == igb_ave_latency) {
		if (rxr->bytes < AVE_THRESHOLD) 
			newitr = igb_low_latency;
		else if (rxr->bytes > BULK_THRESHOLD)
			newitr = igb_bulk_latency;
	} else if (olditr == igb_bulk_latency) {
		if (rxr->bytes < BULK_THRESHOLD)
			newitr = igb_ave_latency;
	}

	if (olditr != newitr) {
		/* Change interrupt rate */
		rxr->eitr_setting = newitr;
		if (adapter->hw.mac.type == e1000_82575)
			newitr |= newitr << 16;
		else
			newitr |= 0x8000000;
		E1000_WRITE_REG(&adapter->hw, E1000_EITR(rxr->me), newitr);
	}

	rxr->bytes = 0;
        return;
}


/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called whenever the user queries the status of
 *  the interface using ifconfig.
 *
 **********************************************************************/
static void
igb_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct adapter *adapter = ifp->if_softc;
	u_char fiber_type = IFM_1000_SX;

	INIT_DEBUGOUT("igb_media_status: begin");

	IGB_CORE_LOCK(adapter);
	igb_update_link_status(adapter);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!adapter->link_active) {
		IGB_CORE_UNLOCK(adapter);
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;

	if ((adapter->hw.phy.media_type == e1000_media_type_fiber) ||
	    (adapter->hw.phy.media_type == e1000_media_type_internal_serdes))
		ifmr->ifm_active |= fiber_type | IFM_FDX;
	else {
		switch (adapter->link_speed) {
		case 10:
			ifmr->ifm_active |= IFM_10_T;
			break;
		case 100:
			ifmr->ifm_active |= IFM_100_TX;
			break;
		case 1000:
			ifmr->ifm_active |= IFM_1000_T;
			break;
		}
		if (adapter->link_duplex == FULL_DUPLEX)
			ifmr->ifm_active |= IFM_FDX;
		else
			ifmr->ifm_active |= IFM_HDX;
	}
	IGB_CORE_UNLOCK(adapter);
}

/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called when the user changes speed/duplex using
 *  media/mediopt option with ifconfig.
 *
 **********************************************************************/
static int
igb_media_change(struct ifnet *ifp)
{
	struct adapter *adapter = ifp->if_softc;
	struct ifmedia  *ifm = &adapter->media;

	INIT_DEBUGOUT("igb_media_change: begin");

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	IGB_CORE_LOCK(adapter);
	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
		adapter->hw.mac.autoneg = DO_AUTO_NEG;
		adapter->hw.phy.autoneg_advertised = AUTONEG_ADV_DEFAULT;
		break;
	case IFM_1000_LX:
	case IFM_1000_SX:
	case IFM_1000_T:
		adapter->hw.mac.autoneg = DO_AUTO_NEG;
		adapter->hw.phy.autoneg_advertised = ADVERTISE_1000_FULL;
		break;
	case IFM_100_TX:
		adapter->hw.mac.autoneg = FALSE;
		adapter->hw.phy.autoneg_advertised = 0;
		if ((ifm->ifm_media & IFM_GMASK) == IFM_FDX)
			adapter->hw.mac.forced_speed_duplex = ADVERTISE_100_FULL;
		else
			adapter->hw.mac.forced_speed_duplex = ADVERTISE_100_HALF;
		break;
	case IFM_10_T:
		adapter->hw.mac.autoneg = FALSE;
		adapter->hw.phy.autoneg_advertised = 0;
		if ((ifm->ifm_media & IFM_GMASK) == IFM_FDX)
			adapter->hw.mac.forced_speed_duplex = ADVERTISE_10_FULL;
		else
			adapter->hw.mac.forced_speed_duplex = ADVERTISE_10_HALF;
		break;
	default:
		device_printf(adapter->dev, "Unsupported media type\n");
	}

	/* As the speed/duplex settings my have changed we need to
	 * reset the PHY.
	 */
	adapter->hw.phy.reset_disable = FALSE;

	igb_init_locked(adapter);
	IGB_CORE_UNLOCK(adapter);

	return (0);
}


/*********************************************************************
 *
 *  This routine maps the mbufs to Advanced TX descriptors.
 *  used by the 82575 adapter.
 *  
 **********************************************************************/

static int
igb_xmit(struct tx_ring *txr, struct mbuf **m_headp)
{
	struct adapter		*adapter = txr->adapter;
	bus_dma_segment_t	segs[IGB_MAX_SCATTER];
	bus_dmamap_t		map;
	struct igb_tx_buffer	*tx_buffer, *tx_buffer_mapped;
	union e1000_adv_tx_desc	*txd = NULL;
	struct mbuf		*m_head;
	u32			olinfo_status = 0, cmd_type_len = 0;
	int			nsegs, i, j, error, first, last = 0;
	u32			hdrlen = 0;

	m_head = *m_headp;


	/* Set basic descriptor constants */
	cmd_type_len |= E1000_ADVTXD_DTYP_DATA;
	cmd_type_len |= E1000_ADVTXD_DCMD_IFCS | E1000_ADVTXD_DCMD_DEXT;
	if (m_head->m_flags & M_VLANTAG)
		cmd_type_len |= E1000_ADVTXD_DCMD_VLE;

        /*
         * Force a cleanup if number of TX descriptors
         * available hits the threshold
         */
	if (txr->tx_avail <= IGB_TX_CLEANUP_THRESHOLD) {
		igb_txeof(txr);
		/* Now do we at least have a minimal? */
		if (txr->tx_avail <= IGB_TX_OP_THRESHOLD) {
			txr->no_desc_avail++;
			return (ENOBUFS);
		}
	}

	/*
         * Map the packet for DMA.
	 *
	 * Capture the first descriptor index,
	 * this descriptor will have the index
	 * of the EOP which is the only one that
	 * now gets a DONE bit writeback.
	 */
	first = txr->next_avail_desc;
	tx_buffer = &txr->tx_buffers[first];
	tx_buffer_mapped = tx_buffer;
	map = tx_buffer->map;

	error = bus_dmamap_load_mbuf_sg(txr->txtag, map,
	    *m_headp, segs, &nsegs, BUS_DMA_NOWAIT);

	if (error == EFBIG) {
		struct mbuf *m;

		m = m_defrag(*m_headp, M_DONTWAIT);
		if (m == NULL) {
			adapter->mbuf_defrag_failed++;
			m_freem(*m_headp);
			*m_headp = NULL;
			return (ENOBUFS);
		}
		*m_headp = m;

		/* Try it again */
		error = bus_dmamap_load_mbuf_sg(txr->txtag, map,
		    *m_headp, segs, &nsegs, BUS_DMA_NOWAIT);

		if (error == ENOMEM) {
			adapter->no_tx_dma_setup++;
			return (error);
		} else if (error != 0) {
			adapter->no_tx_dma_setup++;
			m_freem(*m_headp);
			*m_headp = NULL;
			return (error);
		}
	} else if (error == ENOMEM) {
		adapter->no_tx_dma_setup++;
		return (error);
	} else if (error != 0) {
		adapter->no_tx_dma_setup++;
		m_freem(*m_headp);
		*m_headp = NULL;
		return (error);
	}

	/* Check again to be sure we have enough descriptors */
        if (nsegs > (txr->tx_avail - 2)) {
                txr->no_desc_avail++;
		bus_dmamap_unload(txr->txtag, map);
		return (ENOBUFS);
        }
	m_head = *m_headp;

        /*
         * Set up the context descriptor:
         * used when any hardware offload is done.
	 * This includes CSUM, VLAN, and TSO. It
	 * will use the first descriptor.
         */
        if (m_head->m_pkthdr.csum_flags & CSUM_TSO) {
		if (igb_tso_setup(txr, m_head, &hdrlen)) {
			cmd_type_len |= E1000_ADVTXD_DCMD_TSE;
			olinfo_status |= E1000_TXD_POPTS_IXSM << 8;
			olinfo_status |= E1000_TXD_POPTS_TXSM << 8;
		} else
			return (ENXIO); 
	} else if (igb_tx_ctx_setup(txr, m_head))
		olinfo_status |= E1000_TXD_POPTS_TXSM << 8;

#ifdef IGB_IEEE1588
	/* This is changing soon to an mtag detection */
	if (we detect this mbuf has a TSTAMP mtag)
		cmd_type_len |= E1000_ADVTXD_MAC_TSTAMP;
#endif
	/* Calculate payload length */
	olinfo_status |= ((m_head->m_pkthdr.len - hdrlen)
	    << E1000_ADVTXD_PAYLEN_SHIFT);

	/* Set up our transmit descriptors */
	i = txr->next_avail_desc;
	for (j = 0; j < nsegs; j++) {
		bus_size_t seg_len;
		bus_addr_t seg_addr;

		tx_buffer = &txr->tx_buffers[i];
		txd = (union e1000_adv_tx_desc *)&txr->tx_base[i];
		seg_addr = segs[j].ds_addr;
		seg_len  = segs[j].ds_len;

		txd->read.buffer_addr = htole64(seg_addr);
		txd->read.cmd_type_len = htole32(
		    adapter->txd_cmd | cmd_type_len | seg_len);
		txd->read.olinfo_status = htole32(olinfo_status);
		last = i;
		if (++i == adapter->num_tx_desc)
			i = 0;
		tx_buffer->m_head = NULL;
		tx_buffer->next_eop = -1;
	}

	txr->next_avail_desc = i;
	txr->tx_avail -= nsegs;

        tx_buffer->m_head = m_head;
	tx_buffer_mapped->map = tx_buffer->map;
	tx_buffer->map = map;
        bus_dmamap_sync(txr->txtag, map, BUS_DMASYNC_PREWRITE);

        /*
         * Last Descriptor of Packet
	 * needs End Of Packet (EOP)
	 * and Report Status (RS)
         */
        txd->read.cmd_type_len |=
	    htole32(E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS);
	/*
	 * Keep track in the first buffer which
	 * descriptor will be written back
	 */
	tx_buffer = &txr->tx_buffers[first];
	tx_buffer->next_eop = last;

	/*
	 * Advance the Transmit Descriptor Tail (TDT), this tells the E1000
	 * that this frame is available to transmit.
	 */
	bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	E1000_WRITE_REG(&adapter->hw, E1000_TDT(txr->me), i);
	++txr->tx_packets;

	return (0);

}

static void
igb_set_promisc(struct adapter *adapter)
{
	struct ifnet	*ifp = adapter->ifp;
	uint32_t	reg_rctl;

	reg_rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);

	if (ifp->if_flags & IFF_PROMISC) {
		reg_rctl |= (E1000_RCTL_UPE | E1000_RCTL_MPE);
		E1000_WRITE_REG(&adapter->hw, E1000_RCTL, reg_rctl);
	} else if (ifp->if_flags & IFF_ALLMULTI) {
		reg_rctl |= E1000_RCTL_MPE;
		reg_rctl &= ~E1000_RCTL_UPE;
		E1000_WRITE_REG(&adapter->hw, E1000_RCTL, reg_rctl);
	}
}

static void
igb_disable_promisc(struct adapter *adapter)
{
	uint32_t	reg_rctl;

	reg_rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);

	reg_rctl &=  (~E1000_RCTL_UPE);
	reg_rctl &=  (~E1000_RCTL_MPE);
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, reg_rctl);
}


/*********************************************************************
 *  Multicast Update
 *
 *  This routine is called whenever multicast address list is updated.
 *
 **********************************************************************/

static void
igb_set_multi(struct adapter *adapter)
{
	struct ifnet	*ifp = adapter->ifp;
	struct ifmultiaddr *ifma;
	u32 reg_rctl = 0;
	u8  mta[MAX_NUM_MULTICAST_ADDRESSES * ETH_ADDR_LEN];

	int mcnt = 0;

	IOCTL_DEBUGOUT("igb_set_multi: begin");

	if_maddr_rlock(ifp);
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;

		if (mcnt == MAX_NUM_MULTICAST_ADDRESSES)
			break;

		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    &mta[mcnt * ETH_ADDR_LEN], ETH_ADDR_LEN);
		mcnt++;
	}
	if_maddr_runlock(ifp);

	if (mcnt >= MAX_NUM_MULTICAST_ADDRESSES) {
		reg_rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
		reg_rctl |= E1000_RCTL_MPE;
		E1000_WRITE_REG(&adapter->hw, E1000_RCTL, reg_rctl);
	} else
		e1000_update_mc_addr_list(&adapter->hw, mta, mcnt);
}


/*********************************************************************
 *  Timer routine
 *
 *  This routine checks for link status and updates statistics.
 *
 **********************************************************************/

static void
igb_local_timer(void *arg)
{
	struct adapter	*adapter = arg;
	struct ifnet	*ifp = adapter->ifp;

	IGB_CORE_LOCK_ASSERT(adapter);

	igb_update_link_status(adapter);
	igb_update_stats_counters(adapter);

	if (igb_display_debug_stats && ifp->if_drv_flags & IFF_DRV_RUNNING)
		igb_print_hw_stats(adapter);

	/*
	 * Each second we check the watchdog to 
	 * protect against hardware hangs.
	 */
	igb_watchdog(adapter);

	/* Trigger an RX interrupt on all queues */
	E1000_WRITE_REG(&adapter->hw, E1000_EICS, adapter->rx_mask);
 
	callout_reset(&adapter->timer, hz, igb_local_timer, adapter);

}

static void
igb_update_link_status(struct adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct ifnet *ifp = adapter->ifp;
	device_t dev = adapter->dev;
	struct tx_ring *txr = adapter->tx_rings;
	u32 link_check = 0;

	/* Get the cached link value or read for real */
        switch (hw->phy.media_type) {
        case e1000_media_type_copper:
                if (hw->mac.get_link_status) {
			/* Do the work to read phy */
                        e1000_check_for_link(hw);
                        link_check = !hw->mac.get_link_status;
                } else
                        link_check = TRUE;
                break;
        case e1000_media_type_fiber:
                e1000_check_for_link(hw);
                link_check = (E1000_READ_REG(hw, E1000_STATUS) &
                                 E1000_STATUS_LU);
                break;
        case e1000_media_type_internal_serdes:
                e1000_check_for_link(hw);
                link_check = adapter->hw.mac.serdes_has_link;
                break;
        default:
        case e1000_media_type_unknown:
                break;
        }

	/* Now we check if a transition has happened */
	if (link_check && (adapter->link_active == 0)) {
		e1000_get_speed_and_duplex(&adapter->hw, 
		    &adapter->link_speed, &adapter->link_duplex);
		if (bootverbose)
			device_printf(dev, "Link is up %d Mbps %s\n",
			    adapter->link_speed,
			    ((adapter->link_duplex == FULL_DUPLEX) ?
			    "Full Duplex" : "Half Duplex"));
		adapter->link_active = 1;
		ifp->if_baudrate = adapter->link_speed * 1000000;
		if_link_state_change(ifp, LINK_STATE_UP);
	} else if (!link_check && (adapter->link_active == 1)) {
		ifp->if_baudrate = adapter->link_speed = 0;
		adapter->link_duplex = 0;
		if (bootverbose)
			device_printf(dev, "Link is Down\n");
		adapter->link_active = 0;
		if_link_state_change(ifp, LINK_STATE_DOWN);
		/* Turn off watchdogs */
		for (int i = 0; i < adapter->num_queues; i++, txr++)
			txr->watchdog_timer = FALSE;
	}
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC and deallocates TX/RX buffers.
 *
 **********************************************************************/

static void
igb_stop(void *arg)
{
	struct adapter	*adapter = arg;
	struct ifnet	*ifp = adapter->ifp;

	IGB_CORE_LOCK_ASSERT(adapter);

	INIT_DEBUGOUT("igb_stop: begin");

	igb_disable_intr(adapter);

	callout_stop(&adapter->timer);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	e1000_reset_hw(&adapter->hw);
	E1000_WRITE_REG(&adapter->hw, E1000_WUC, 0);
}


/*********************************************************************
 *
 *  Determine hardware revision.
 *
 **********************************************************************/
static void
igb_identify_hardware(struct adapter *adapter)
{
	device_t dev = adapter->dev;

	/* Make sure our PCI config space has the necessary stuff set */
	adapter->hw.bus.pci_cmd_word = pci_read_config(dev, PCIR_COMMAND, 2);
	if (!((adapter->hw.bus.pci_cmd_word & PCIM_CMD_BUSMASTEREN) &&
	    (adapter->hw.bus.pci_cmd_word & PCIM_CMD_MEMEN))) {
		device_printf(dev, "Memory Access and/or Bus Master bits "
		    "were not set!\n");
		adapter->hw.bus.pci_cmd_word |=
		(PCIM_CMD_BUSMASTEREN | PCIM_CMD_MEMEN);
		pci_write_config(dev, PCIR_COMMAND,
		    adapter->hw.bus.pci_cmd_word, 2);
	}

	/* Save off the information about this board */
	adapter->hw.vendor_id = pci_get_vendor(dev);
	adapter->hw.device_id = pci_get_device(dev);
	adapter->hw.revision_id = pci_read_config(dev, PCIR_REVID, 1);
	adapter->hw.subsystem_vendor_id =
	    pci_read_config(dev, PCIR_SUBVEND_0, 2);
	adapter->hw.subsystem_device_id =
	    pci_read_config(dev, PCIR_SUBDEV_0, 2);

	/* Do Shared Code Init and Setup */
	if (e1000_set_mac_type(&adapter->hw)) {
		device_printf(dev, "Setup init failure\n");
		return;
	}
}

static int
igb_allocate_pci_resources(struct adapter *adapter)
{
	device_t	dev = adapter->dev;
	int		rid;

	rid = PCIR_BAR(0);
	adapter->pci_mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &rid, RF_ACTIVE);
	if (adapter->pci_mem == NULL) {
		device_printf(dev, "Unable to allocate bus resource: memory\n");
		return (ENXIO);
	}
	adapter->osdep.mem_bus_space_tag =
	    rman_get_bustag(adapter->pci_mem);
	adapter->osdep.mem_bus_space_handle =
	    rman_get_bushandle(adapter->pci_mem);
	adapter->hw.hw_addr = (u8 *)&adapter->osdep.mem_bus_space_handle;

	adapter->num_queues = 1; /* Defaults for Legacy or MSI */

	/* This will setup either MSI/X or MSI */
	adapter->msix = igb_setup_msix(adapter);
	adapter->hw.back = &adapter->osdep;

	return (0);
}

/*********************************************************************
 *
 *  Setup the Legacy or MSI Interrupt handler
 *
 **********************************************************************/
static int
igb_allocate_legacy(struct adapter *adapter)
{
	device_t dev = adapter->dev;
	int error, rid = 0;

	/* Turn off all interrupts */
	E1000_WRITE_REG(&adapter->hw, E1000_IMC, 0xffffffff);

	/* MSI RID is 1 */
	if (adapter->msix == 1)
		rid = 1;

	/* We allocate a single interrupt resource */
	adapter->res = bus_alloc_resource_any(dev,
	    SYS_RES_IRQ, &rid, RF_SHAREABLE | RF_ACTIVE);
	if (adapter->res == NULL) {
		device_printf(dev, "Unable to allocate bus resource: "
		    "interrupt\n");
		return (ENXIO);
	}

	/*
	 * Try allocating a fast interrupt and the associated deferred
	 * processing contexts.
	 */
	TASK_INIT(&adapter->rxtx_task, 0, igb_handle_rxtx, adapter);
	adapter->tq = taskqueue_create_fast("igb_taskq", M_NOWAIT,
	    taskqueue_thread_enqueue, &adapter->tq);
	taskqueue_start_threads(&adapter->tq, 1, PI_NET, "%s taskq",
	    device_get_nameunit(adapter->dev));
	if ((error = bus_setup_intr(dev, adapter->res,
	    INTR_TYPE_NET | INTR_MPSAFE, igb_irq_fast, NULL,
	    adapter, &adapter->tag)) != 0) {
		device_printf(dev, "Failed to register fast interrupt "
			    "handler: %d\n", error);
		taskqueue_free(adapter->tq);
		adapter->tq = NULL;
		return (error);
	}

	return (0);
}


/*********************************************************************
 *
 *  Setup the MSIX Interrupt handlers: 
 *
 **********************************************************************/
static int
igb_allocate_msix(struct adapter *adapter)
{
	device_t dev = adapter->dev;
	struct tx_ring *txr = adapter->tx_rings;
	struct rx_ring *rxr = adapter->rx_rings;
	int error, rid, vector = 0;

	/*
	 * Setup the interrupt handlers
	 */

	/* TX Setup */
	for (int i = 0; i < adapter->num_queues; i++, vector++, txr++) {
		rid = vector +1;
		txr->res = bus_alloc_resource_any(dev,
		    SYS_RES_IRQ, &rid, RF_SHAREABLE | RF_ACTIVE);
		if (txr->res == NULL) {
			device_printf(dev,
			    "Unable to allocate bus resource: "
			    "MSIX TX Interrupt\n");
			return (ENXIO);
		}
		error = bus_setup_intr(dev, txr->res,
	    	    INTR_TYPE_NET | INTR_MPSAFE, NULL,
		    igb_msix_tx, txr, &txr->tag);
		if (error) {
			txr->res = NULL;
			device_printf(dev, "Failed to register TX handler");
			return (error);
		}
		/* Make tasklet for deferred handling - one per queue */
		TASK_INIT(&txr->tx_task, 0, igb_handle_tx, txr);
		txr->msix = vector;
		if (adapter->hw.mac.type == e1000_82575)
			txr->eims = E1000_EICR_TX_QUEUE0 << i;
		else
			txr->eims = 1 << vector;
		/*
		** Bind the msix vector, and thus the
		** ring to the corresponding cpu.
		*/
		if (adapter->num_queues > 1)
			bus_bind_intr(dev, txr->res, i);
	}

	/* RX Setup */
	for (int i = 0; i < adapter->num_queues; i++, vector++, rxr++) {
		rid = vector +1;
		rxr->res = bus_alloc_resource_any(dev,
		    SYS_RES_IRQ, &rid, RF_SHAREABLE | RF_ACTIVE);
		if (rxr->res == NULL) {
			device_printf(dev,
			    "Unable to allocate bus resource: "
			    "MSIX RX Interrupt\n");
			return (ENXIO);
		}
		error = bus_setup_intr(dev, rxr->res,
	    	    INTR_TYPE_NET | INTR_MPSAFE, NULL,
		    igb_msix_rx, rxr, &rxr->tag);
		if (error) {
			rxr->res = NULL;
			device_printf(dev, "Failed to register RX handler");
			return (error);
		}
		/* Make tasklet for deferred handling - one per queue */
		TASK_INIT(&rxr->rx_task, 0, igb_handle_rx, rxr);
		rxr->msix = vector;
		if (adapter->hw.mac.type == e1000_82575)
			rxr->eims = E1000_EICR_RX_QUEUE0 << i;
		else
			rxr->eims = 1 << vector;
		/* Get a mask for local timer */
		adapter->rx_mask |= rxr->eims;
		/*
		** Bind the msix vector, and thus the
		** ring to the corresponding cpu.
		** Notice that this makes an RX/TX pair
		** bound to each CPU, limited by the MSIX
		** vectors.
		*/
		if (adapter->num_queues > 1)
			bus_bind_intr(dev, rxr->res, i);
	}

	/* And Link */
	rid = vector +1;
	adapter->res = bus_alloc_resource_any(dev,
	    SYS_RES_IRQ, &rid, RF_SHAREABLE | RF_ACTIVE);
	if (adapter->res == NULL) {
		device_printf(dev,
		    "Unable to allocate bus resource: "
		    "MSIX Link Interrupt\n");
		return (ENXIO);
	}
	if ((error = bus_setup_intr(dev, adapter->res,
	    INTR_TYPE_NET | INTR_MPSAFE, NULL,
	    igb_msix_link, adapter, &adapter->tag)) != 0) {
		device_printf(dev, "Failed to register Link handler");
		return (error);
	}
	adapter->linkvec = vector;
	adapter->tq = taskqueue_create_fast("igb_taskq", M_NOWAIT,
	    taskqueue_thread_enqueue, &adapter->tq);
	taskqueue_start_threads(&adapter->tq, 1, PI_NET, "%s taskq",
	    device_get_nameunit(adapter->dev));

	return (0);
}


static void
igb_configure_queues(struct adapter *adapter)
{
	struct	e1000_hw *hw = &adapter->hw;
	struct	tx_ring	*txr;
	struct	rx_ring	*rxr;

	/* Turn on MSIX */
	/*
	** 82576 uses IVARs to route MSI/X
	** interrupts, its not very intuitive,
	** study the code carefully :)
	*/
	if (adapter->hw.mac.type == e1000_82576) {
		u32	ivar = 0;
		/* First turn on the capability */
		E1000_WRITE_REG(hw, E1000_GPIE,
		    E1000_GPIE_MSIX_MODE |
		    E1000_GPIE_EIAME |
		    E1000_GPIE_PBA | E1000_GPIE_NSICR);
		/* RX */
		for (int i = 0; i < adapter->num_queues; i++) {
			u32 index = i & 0x7; /* Each IVAR has two entries */
			ivar = E1000_READ_REG_ARRAY(hw, E1000_IVAR0, index);
			rxr = &adapter->rx_rings[i];
			if (i < 8) {
				ivar &= 0xFFFFFF00;
				ivar |= rxr->msix | E1000_IVAR_VALID;
			} else {
				ivar &= 0xFF00FFFF;
				ivar |= (rxr->msix | E1000_IVAR_VALID) << 16;
			}
			E1000_WRITE_REG_ARRAY(hw, E1000_IVAR0, index, ivar);
			adapter->eims_mask |= rxr->eims;
		}
		/* TX */
		for (int i = 0; i < adapter->num_queues; i++) {
			u32 index = i & 0x7; /* Each IVAR has two entries */
			ivar = E1000_READ_REG_ARRAY(hw, E1000_IVAR0, index);
			txr = &adapter->tx_rings[i];
			if (i < 8) {
				ivar &= 0xFFFF00FF;
				ivar |= (txr->msix | E1000_IVAR_VALID) << 8;
			} else {
				ivar &= 0x00FFFFFF;
				ivar |= (txr->msix | E1000_IVAR_VALID) << 24;
			}
			E1000_WRITE_REG_ARRAY(hw, E1000_IVAR0, index, ivar);
			adapter->eims_mask |= txr->eims;
		}

		/* And for the link interrupt */
		ivar = (adapter->linkvec | E1000_IVAR_VALID) << 8;
		adapter->link_mask = 1 << adapter->linkvec;
		adapter->eims_mask |= adapter->link_mask;
		E1000_WRITE_REG(hw, E1000_IVAR_MISC, ivar);
	} else
	{ /* 82575 */
		int tmp;

                /* enable MSI-X PBA support*/
		tmp = E1000_READ_REG(hw, E1000_CTRL_EXT);
                tmp |= E1000_CTRL_EXT_PBA_CLR;
                /* Auto-Mask interrupts upon ICR read. */
                tmp |= E1000_CTRL_EXT_EIAME;
                tmp |= E1000_CTRL_EXT_IRCA;
                E1000_WRITE_REG(hw, E1000_CTRL_EXT, tmp);

		/* TX */
		for (int i = 0; i < adapter->num_queues; i++) {
			txr = &adapter->tx_rings[i];
			E1000_WRITE_REG(hw, E1000_MSIXBM(txr->msix),
			    txr->eims);
			adapter->eims_mask |= txr->eims;
		}

		/* RX */
		for (int i = 0; i < adapter->num_queues; i++) {
			rxr = &adapter->rx_rings[i];
			E1000_WRITE_REG(hw, E1000_MSIXBM(rxr->msix),
			    rxr->eims);
			adapter->eims_mask |= rxr->eims;
		}

		/* Link */
		E1000_WRITE_REG(hw, E1000_MSIXBM(adapter->linkvec),
		    E1000_EIMS_OTHER);
		adapter->link_mask |= E1000_EIMS_OTHER;
		adapter->eims_mask |= adapter->link_mask;
	}
	return;
}


static void
igb_free_pci_resources(struct adapter *adapter)
{
	struct          tx_ring *txr = adapter->tx_rings;
	struct          rx_ring *rxr = adapter->rx_rings;
	device_t	dev = adapter->dev;
	int		rid;

	/*
	** There is a slight possibility of a failure mode
	** in attach that will result in entering this function
	** before interrupt resources have been initialized, and
	** in that case we do not want to execute the loops below
	** We can detect this reliably by the state of the adapter
	** res pointer.
	*/
	if (adapter->res == NULL)
		goto mem;

	/*
	 * First release all the TX/RX interrupt resources:
	 */
	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		rid = txr->msix + 1;
		if (txr->tag != NULL) {
			bus_teardown_intr(dev, txr->res, txr->tag);
			txr->tag = NULL;
		}
		if (txr->res != NULL)
			bus_release_resource(dev, SYS_RES_IRQ, rid, txr->res);
	}

	for (int i = 0; i < adapter->num_queues; i++, rxr++) {
		rid = rxr->msix + 1;
		if (rxr->tag != NULL) {
			bus_teardown_intr(dev, rxr->res, rxr->tag);
			rxr->tag = NULL;
		}
		if (rxr->res != NULL)
			bus_release_resource(dev, SYS_RES_IRQ, rid, rxr->res);
	}

	/* Clean the Legacy or Link interrupt last */
	if (adapter->linkvec) /* we are doing MSIX */
		rid = adapter->linkvec + 1;
	else
		(adapter->msix != 0) ? (rid = 1):(rid = 0);

	if (adapter->tag != NULL) {
		bus_teardown_intr(dev, adapter->res, adapter->tag);
		adapter->tag = NULL;
	}
	if (adapter->res != NULL)
		bus_release_resource(dev, SYS_RES_IRQ, rid, adapter->res);

mem:
	if (adapter->msix)
		pci_release_msi(dev);

	if (adapter->msix_mem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    PCIR_BAR(IGB_MSIX_BAR), adapter->msix_mem);

	if (adapter->pci_mem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    PCIR_BAR(0), adapter->pci_mem);

}

/*
 * Setup Either MSI/X or MSI
 */
static int
igb_setup_msix(struct adapter *adapter)
{
	device_t dev = adapter->dev;
	int rid, want, queues, msgs;

	/* First try MSI/X */
	rid = PCIR_BAR(IGB_MSIX_BAR);
	adapter->msix_mem = bus_alloc_resource_any(dev,
	    SYS_RES_MEMORY, &rid, RF_ACTIVE);
       	if (!adapter->msix_mem) {
		/* May not be enabled */
		device_printf(adapter->dev,
		    "Unable to map MSIX table \n");
		goto msi;
	}

	msgs = pci_msix_count(dev); 
	if (msgs == 0) { /* system has msix disabled */
		bus_release_resource(dev, SYS_RES_MEMORY,
		    PCIR_BAR(IGB_MSIX_BAR), adapter->msix_mem);
		adapter->msix_mem = NULL;
		goto msi;
	}

	/* Figure out a reasonable auto config value */
	queues = (mp_ncpus > ((msgs-1)/2)) ? (msgs-1)/2 : mp_ncpus;

	if (igb_num_queues == 0)
		igb_num_queues = queues;
	/*
	** Two vectors (RX/TX pair) per queue
	** plus an additional for Link interrupt
	*/
	want = (igb_num_queues * 2) + 1;
	if (msgs >= want)
		msgs = want;
	else {
               	device_printf(adapter->dev,
		    "MSIX Configuration Problem, "
		    "%d vectors configured, but %d queues wanted!\n",
		    msgs, want);
		return (ENXIO);
	}
	if ((msgs) && pci_alloc_msix(dev, &msgs) == 0) {
               	device_printf(adapter->dev,
		    "Using MSIX interrupts with %d vectors\n", msgs);
		adapter->num_queues = igb_num_queues;
		return (msgs);
	}
msi:
       	msgs = pci_msi_count(dev);
       	if (msgs == 1 && pci_alloc_msi(dev, &msgs) == 0)
               	device_printf(adapter->dev,"Using MSI interrupt\n");
	return (msgs);
}

/*********************************************************************
 *
 *  Initialize the hardware to a configuration
 *  as specified by the adapter structure.
 *
 **********************************************************************/
static int
igb_hardware_init(struct adapter *adapter)
{
	device_t	dev = adapter->dev;
	u32		rx_buffer_size;

	INIT_DEBUGOUT("igb_hardware_init: begin");

	/* Issue a global reset */
	e1000_reset_hw(&adapter->hw);

	/* Let the firmware know the OS is in control */
	igb_get_hw_control(adapter);

	/*
	 * These parameters control the automatic generation (Tx) and
	 * response (Rx) to Ethernet PAUSE frames.
	 * - High water mark should allow for at least two frames to be
	 *   received after sending an XOFF.
	 * - Low water mark works best when it is very near the high water mark.
	 *   This allows the receiver to restart by sending XON when it has
	 *   drained a bit. Here we use an arbitary value of 1500 which will
	 *   restart after one full frame is pulled from the buffer. There
	 *   could be several smaller frames in the buffer and if so they will
	 *   not trigger the XON until their total number reduces the buffer
	 *   by 1500.
	 * - The pause time is fairly large at 1000 x 512ns = 512 usec.
	 */
	if (adapter->hw.mac.type == e1000_82576)
		rx_buffer_size = ((E1000_READ_REG(&adapter->hw,
		    E1000_RXPBS) & 0xffff) << 10 );
	else
		rx_buffer_size = ((E1000_READ_REG(&adapter->hw,
		    E1000_PBA) & 0xffff) << 10 );

	adapter->hw.fc.high_water = rx_buffer_size -
	    roundup2(adapter->max_frame_size, 1024);
	adapter->hw.fc.low_water = adapter->hw.fc.high_water - 1500;

	adapter->hw.fc.pause_time = IGB_FC_PAUSE_TIME;
	adapter->hw.fc.send_xon = TRUE;

	/* Set Flow control, use the tunable location if sane */
	if ((igb_fc_setting >= 0) || (igb_fc_setting < 4))
		adapter->hw.fc.requested_mode = igb_fc_setting;
	else
		adapter->hw.fc.requested_mode = e1000_fc_none;

	if (e1000_init_hw(&adapter->hw) < 0) {
		device_printf(dev, "Hardware Initialization Failed\n");
		return (EIO);
	}

	e1000_check_for_link(&adapter->hw);

	return (0);
}

/*********************************************************************
 *
 *  Setup networking device structure and register an interface.
 *
 **********************************************************************/
static void
igb_setup_interface(device_t dev, struct adapter *adapter)
{
	struct ifnet   *ifp;

	INIT_DEBUGOUT("igb_setup_interface: begin");

	ifp = adapter->ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL)
		panic("%s: can not if_alloc()", device_get_nameunit(dev));
	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_mtu = ETHERMTU;
	ifp->if_init =  igb_init;
	ifp->if_softc = adapter;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = igb_ioctl;
	ifp->if_start = igb_start;
#if __FreeBSD_version >= 800000
	ifp->if_transmit = igb_mq_start;
	ifp->if_qflush = igb_qflush;
#endif
	IFQ_SET_MAXLEN(&ifp->if_snd, adapter->num_tx_desc - 1);
	ifp->if_snd.ifq_drv_maxlen = adapter->num_tx_desc - 1;
	IFQ_SET_READY(&ifp->if_snd);

	ether_ifattach(ifp, adapter->hw.mac.addr);

	ifp->if_capabilities = ifp->if_capenable = 0;

	ifp->if_capabilities = IFCAP_HWCSUM | IFCAP_VLAN_MTU;
	ifp->if_capabilities |= IFCAP_TSO4;
	ifp->if_capabilities |= IFCAP_JUMBO_MTU;
	ifp->if_capenable = ifp->if_capabilities;

	/*
	 * Tell the upper layer(s) we support long frames.
	 */
	ifp->if_data.ifi_hdrlen = sizeof(struct ether_vlan_header);
	ifp->if_capabilities |= IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_MTU;
	ifp->if_capenable |= IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_MTU;

	/*
	 * Specify the media types supported by this adapter and register
	 * callbacks to update media and link information
	 */
	ifmedia_init(&adapter->media, IFM_IMASK,
	    igb_media_change, igb_media_status);
	if ((adapter->hw.phy.media_type == e1000_media_type_fiber) ||
	    (adapter->hw.phy.media_type == e1000_media_type_internal_serdes)) {
		ifmedia_add(&adapter->media, IFM_ETHER | IFM_1000_SX | IFM_FDX, 
			    0, NULL);
		ifmedia_add(&adapter->media, IFM_ETHER | IFM_1000_SX, 0, NULL);
	} else {
		ifmedia_add(&adapter->media, IFM_ETHER | IFM_10_T, 0, NULL);
		ifmedia_add(&adapter->media, IFM_ETHER | IFM_10_T | IFM_FDX,
			    0, NULL);
		ifmedia_add(&adapter->media, IFM_ETHER | IFM_100_TX,
			    0, NULL);
		ifmedia_add(&adapter->media, IFM_ETHER | IFM_100_TX | IFM_FDX,
			    0, NULL);
		if (adapter->hw.phy.type != e1000_phy_ife) {
			ifmedia_add(&adapter->media,
				IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
			ifmedia_add(&adapter->media,
				IFM_ETHER | IFM_1000_T, 0, NULL);
		}
	}
	ifmedia_add(&adapter->media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&adapter->media, IFM_ETHER | IFM_AUTO);
}


/*
 * Manage DMA'able memory.
 */
static void
igb_dmamap_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	if (error)
		return;
	*(bus_addr_t *) arg = segs[0].ds_addr;
}

static int
igb_dma_malloc(struct adapter *adapter, bus_size_t size,
        struct igb_dma_alloc *dma, int mapflags)
{
	int error;

	error = bus_dma_tag_create(bus_get_dma_tag(adapter->dev), /* parent */
				IGB_DBA_ALIGN, 0,	/* alignment, bounds */
				BUS_SPACE_MAXADDR,	/* lowaddr */
				BUS_SPACE_MAXADDR,	/* highaddr */
				NULL, NULL,		/* filter, filterarg */
				size,			/* maxsize */
				1,			/* nsegments */
				size,			/* maxsegsize */
				0,			/* flags */
				NULL,			/* lockfunc */
				NULL,			/* lockarg */
				&dma->dma_tag);
	if (error) {
		device_printf(adapter->dev,
		    "%s: bus_dma_tag_create failed: %d\n",
		    __func__, error);
		goto fail_0;
	}

	error = bus_dmamem_alloc(dma->dma_tag, (void**) &dma->dma_vaddr,
	    BUS_DMA_NOWAIT, &dma->dma_map);
	if (error) {
		device_printf(adapter->dev,
		    "%s: bus_dmamem_alloc(%ju) failed: %d\n",
		    __func__, (uintmax_t)size, error);
		goto fail_2;
	}

	dma->dma_paddr = 0;
	error = bus_dmamap_load(dma->dma_tag, dma->dma_map, dma->dma_vaddr,
	    size, igb_dmamap_cb, &dma->dma_paddr, mapflags | BUS_DMA_NOWAIT);
	if (error || dma->dma_paddr == 0) {
		device_printf(adapter->dev,
		    "%s: bus_dmamap_load failed: %d\n",
		    __func__, error);
		goto fail_3;
	}

	return (0);

fail_3:
	bus_dmamap_unload(dma->dma_tag, dma->dma_map);
fail_2:
	bus_dmamem_free(dma->dma_tag, dma->dma_vaddr, dma->dma_map);
	bus_dma_tag_destroy(dma->dma_tag);
fail_0:
	dma->dma_map = NULL;
	dma->dma_tag = NULL;

	return (error);
}

static void
igb_dma_free(struct adapter *adapter, struct igb_dma_alloc *dma)
{
	if (dma->dma_tag == NULL)
		return;
	if (dma->dma_map != NULL) {
		bus_dmamap_sync(dma->dma_tag, dma->dma_map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(dma->dma_tag, dma->dma_map);
		bus_dmamem_free(dma->dma_tag, dma->dma_vaddr, dma->dma_map);
		dma->dma_map = NULL;
	}
	bus_dma_tag_destroy(dma->dma_tag);
	dma->dma_tag = NULL;
}


/*********************************************************************
 *
 *  Allocate memory for the transmit and receive rings, and then
 *  the descriptors associated with each, called only once at attach.
 *
 **********************************************************************/
static int
igb_allocate_queues(struct adapter *adapter)
{
	device_t dev = adapter->dev;
	struct tx_ring *txr;
	struct rx_ring *rxr;
	int rsize, tsize, error = E1000_SUCCESS;
	int txconf = 0, rxconf = 0;

	/* First allocate the TX ring struct memory */
	if (!(adapter->tx_rings =
	    (struct tx_ring *) malloc(sizeof(struct tx_ring) *
	    adapter->num_queues, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "Unable to allocate TX ring memory\n");
		error = ENOMEM;
		goto fail;
	}
	txr = adapter->tx_rings;

	/* Next allocate the RX */
	if (!(adapter->rx_rings =
	    (struct rx_ring *) malloc(sizeof(struct rx_ring) *
	    adapter->num_queues, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "Unable to allocate RX ring memory\n");
		error = ENOMEM;
		goto rx_fail;
	}
	rxr = adapter->rx_rings;

	tsize = roundup2(adapter->num_tx_desc *
	    sizeof(union e1000_adv_tx_desc), IGB_DBA_ALIGN);
	/*
	 * Now set up the TX queues, txconf is needed to handle the
	 * possibility that things fail midcourse and we need to
	 * undo memory gracefully
	 */ 
	for (int i = 0; i < adapter->num_queues; i++, txconf++) {
		/* Set up some basics */
		txr = &adapter->tx_rings[i];
		txr->adapter = adapter;
		txr->me = i;

		/* Initialize the TX lock */
		snprintf(txr->mtx_name, sizeof(txr->mtx_name), "%s:tx(%d)",
		    device_get_nameunit(dev), txr->me);
		mtx_init(&txr->tx_mtx, txr->mtx_name, NULL, MTX_DEF);

		if (igb_dma_malloc(adapter, tsize,
			&txr->txdma, BUS_DMA_NOWAIT)) {
			device_printf(dev,
			    "Unable to allocate TX Descriptor memory\n");
			error = ENOMEM;
			goto err_tx_desc;
		}
		txr->tx_base = (struct e1000_tx_desc *)txr->txdma.dma_vaddr;
		bzero((void *)txr->tx_base, tsize);

        	/* Now allocate transmit buffers for the ring */
        	if (igb_allocate_transmit_buffers(txr)) {
			device_printf(dev,
			    "Critical Failure setting up transmit buffers\n");
			error = ENOMEM;
			goto err_tx_desc;
        	}
#if __FreeBSD_version >= 800000
		/* Allocate a buf ring */
		txr->br = buf_ring_alloc(IGB_BR_SIZE, M_DEVBUF,
		    M_WAITOK, &txr->tx_mtx);
#endif
	}

	/*
	 * Next the RX queues...
	 */ 
	rsize = roundup2(adapter->num_rx_desc *
	    sizeof(union e1000_adv_rx_desc), IGB_DBA_ALIGN);
	for (int i = 0; i < adapter->num_queues; i++, rxconf++) {
		rxr = &adapter->rx_rings[i];
		rxr->adapter = adapter;
		rxr->me = i;

		/* Initialize the RX lock */
		snprintf(rxr->mtx_name, sizeof(rxr->mtx_name), "%s:rx(%d)",
		    device_get_nameunit(dev), txr->me);
		mtx_init(&rxr->rx_mtx, rxr->mtx_name, NULL, MTX_DEF);

		if (igb_dma_malloc(adapter, rsize,
			&rxr->rxdma, BUS_DMA_NOWAIT)) {
			device_printf(dev,
			    "Unable to allocate RxDescriptor memory\n");
			error = ENOMEM;
			goto err_rx_desc;
		}
		rxr->rx_base = (union e1000_adv_rx_desc *)rxr->rxdma.dma_vaddr;
		bzero((void *)rxr->rx_base, rsize);

        	/* Allocate receive buffers for the ring*/
		if (igb_allocate_receive_buffers(rxr)) {
			device_printf(dev,
			    "Critical Failure setting up receive buffers\n");
			error = ENOMEM;
			goto err_rx_desc;
		}
	}

	return (0);

err_rx_desc:
	for (rxr = adapter->rx_rings; rxconf > 0; rxr++, rxconf--)
		igb_dma_free(adapter, &rxr->rxdma);
err_tx_desc:
	for (txr = adapter->tx_rings; txconf > 0; txr++, txconf--)
		igb_dma_free(adapter, &txr->txdma);
	free(adapter->rx_rings, M_DEVBUF);
rx_fail:
	free(adapter->tx_rings, M_DEVBUF);
fail:
	return (error);
}

/*********************************************************************
 *
 *  Allocate memory for tx_buffer structures. The tx_buffer stores all
 *  the information needed to transmit a packet on the wire. This is
 *  called only once at attach, setup is done every reset.
 *
 **********************************************************************/
static int
igb_allocate_transmit_buffers(struct tx_ring *txr)
{
	struct adapter *adapter = txr->adapter;
	device_t dev = adapter->dev;
	struct igb_tx_buffer *txbuf;
	int error, i;

	/*
	 * Setup DMA descriptor areas.
	 */
	if ((error = bus_dma_tag_create(NULL,		/* parent */
			       PAGE_SIZE, 0,		/* alignment, bounds */
			       BUS_SPACE_MAXADDR,	/* lowaddr */
			       BUS_SPACE_MAXADDR,	/* highaddr */
			       NULL, NULL,		/* filter, filterarg */
			       IGB_TSO_SIZE,		/* maxsize */
			       IGB_MAX_SCATTER,		/* nsegments */
			       PAGE_SIZE,		/* maxsegsize */
			       0,			/* flags */
			       NULL,			/* lockfunc */
			       NULL,			/* lockfuncarg */
			       &txr->txtag))) {
		device_printf(dev,"Unable to allocate TX DMA tag\n");
		goto fail;
	}

	if (!(txr->tx_buffers =
	    (struct igb_tx_buffer *) malloc(sizeof(struct igb_tx_buffer) *
	    adapter->num_tx_desc, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "Unable to allocate tx_buffer memory\n");
		error = ENOMEM;
		goto fail;
	}

        /* Create the descriptor buffer dma maps */
	txbuf = txr->tx_buffers;
	for (i = 0; i < adapter->num_tx_desc; i++, txbuf++) {
		error = bus_dmamap_create(txr->txtag, 0, &txbuf->map);
		if (error != 0) {
			device_printf(dev, "Unable to create TX DMA map\n");
			goto fail;
		}
	}

	return 0;
fail:
	/* We free all, it handles case where we are in the middle */
	igb_free_transmit_structures(adapter);
	return (error);
}

/*********************************************************************
 *
 *  Initialize a transmit ring.
 *
 **********************************************************************/
static void
igb_setup_transmit_ring(struct tx_ring *txr)
{
	struct adapter *adapter = txr->adapter;
	struct igb_tx_buffer *txbuf;
	int i;

	/* Clear the old descriptor contents */
	bzero((void *)txr->tx_base,
	      (sizeof(union e1000_adv_tx_desc)) * adapter->num_tx_desc);
	/* Reset indices */
	txr->next_avail_desc = 0;
	txr->next_to_clean = 0;

	/* Free any existing tx buffers. */
        txbuf = txr->tx_buffers;
	for (i = 0; i < adapter->num_tx_desc; i++, txbuf++) {
		if (txbuf->m_head != NULL) {
			bus_dmamap_sync(txr->txtag, txbuf->map,
			    BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(txr->txtag, txbuf->map);
			m_freem(txbuf->m_head);
			txbuf->m_head = NULL;
		}
		/* clear the watch index */
		txbuf->next_eop = -1;
        }

	/* Set number of descriptors available */
	txr->tx_avail = adapter->num_tx_desc;

	bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

}

/*********************************************************************
 *
 *  Initialize all transmit rings.
 *
 **********************************************************************/
static void
igb_setup_transmit_structures(struct adapter *adapter)
{
	struct tx_ring *txr = adapter->tx_rings;

	for (int i = 0; i < adapter->num_queues; i++, txr++)
		igb_setup_transmit_ring(txr);

	return;
}

/*********************************************************************
 *
 *  Enable transmit unit.
 *
 **********************************************************************/
static void
igb_initialize_transmit_units(struct adapter *adapter)
{
	struct tx_ring	*txr = adapter->tx_rings;
	u32		tctl, txdctl;

	 INIT_DEBUGOUT("igb_initialize_transmit_units: begin");

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		u64 bus_addr = txr->txdma.dma_paddr;

		E1000_WRITE_REG(&adapter->hw, E1000_TDLEN(i),
		    adapter->num_tx_desc * sizeof(struct e1000_tx_desc));
		E1000_WRITE_REG(&adapter->hw, E1000_TDBAH(i),
		    (uint32_t)(bus_addr >> 32));
		E1000_WRITE_REG(&adapter->hw, E1000_TDBAL(i),
		    (uint32_t)bus_addr);

		/* Setup the HW Tx Head and Tail descriptor pointers */
		E1000_WRITE_REG(&adapter->hw, E1000_TDT(i), 0);
		E1000_WRITE_REG(&adapter->hw, E1000_TDH(i), 0);

		HW_DEBUGOUT2("Base = %x, Length = %x\n",
		    E1000_READ_REG(&adapter->hw, E1000_TDBAL(i)),
		    E1000_READ_REG(&adapter->hw, E1000_TDLEN(i)));

		/* Setup Transmit Descriptor Base Settings */   
		adapter->txd_cmd = E1000_TXD_CMD_IFCS;

		txdctl = E1000_READ_REG(&adapter->hw, E1000_TXDCTL(i));
		txdctl |= E1000_TXDCTL_QUEUE_ENABLE;
		E1000_WRITE_REG(&adapter->hw, E1000_TXDCTL(i), txdctl);
	}

	/* Program the Transmit Control Register */
	tctl = E1000_READ_REG(&adapter->hw, E1000_TCTL);
	tctl &= ~E1000_TCTL_CT;
	tctl |= (E1000_TCTL_PSP | E1000_TCTL_RTLC | E1000_TCTL_EN |
		   (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT));

	e1000_config_collision_dist(&adapter->hw);

	/* This write will effectively turn on the transmit unit. */
	E1000_WRITE_REG(&adapter->hw, E1000_TCTL, tctl);

}

/*********************************************************************
 *
 *  Free all transmit rings.
 *
 **********************************************************************/
static void
igb_free_transmit_structures(struct adapter *adapter)
{
	struct tx_ring *txr = adapter->tx_rings;

	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		IGB_TX_LOCK(txr);
		igb_free_transmit_buffers(txr);
		igb_dma_free(adapter, &txr->txdma);
		IGB_TX_UNLOCK(txr);
		IGB_TX_LOCK_DESTROY(txr);
	}
	free(adapter->tx_rings, M_DEVBUF);
}

/*********************************************************************
 *
 *  Free transmit ring related data structures.
 *
 **********************************************************************/
static void
igb_free_transmit_buffers(struct tx_ring *txr)
{
	struct adapter *adapter = txr->adapter;
	struct igb_tx_buffer *tx_buffer;
	int             i;

	INIT_DEBUGOUT("free_transmit_ring: begin");

	if (txr->tx_buffers == NULL)
		return;

	tx_buffer = txr->tx_buffers;
	for (i = 0; i < adapter->num_tx_desc; i++, tx_buffer++) {
		if (tx_buffer->m_head != NULL) {
			bus_dmamap_sync(txr->txtag, tx_buffer->map,
			    BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(txr->txtag,
			    tx_buffer->map);
			m_freem(tx_buffer->m_head);
			tx_buffer->m_head = NULL;
			if (tx_buffer->map != NULL) {
				bus_dmamap_destroy(txr->txtag,
				    tx_buffer->map);
				tx_buffer->map = NULL;
			}
		} else if (tx_buffer->map != NULL) {
			bus_dmamap_unload(txr->txtag,
			    tx_buffer->map);
			bus_dmamap_destroy(txr->txtag,
			    tx_buffer->map);
			tx_buffer->map = NULL;
		}
	}
#if __FreeBSD_version >= 800000
	if (txr->br != NULL)
		buf_ring_free(txr->br, M_DEVBUF);
#endif
	if (txr->tx_buffers != NULL) {
		free(txr->tx_buffers, M_DEVBUF);
		txr->tx_buffers = NULL;
	}
	if (txr->txtag != NULL) {
		bus_dma_tag_destroy(txr->txtag);
		txr->txtag = NULL;
	}
	return;
}

/**********************************************************************
 *
 *  Setup work for hardware segmentation offload (TSO) on
 *  adapters using advanced tx descriptors (82575)
 *
 **********************************************************************/
static boolean_t
igb_tso_setup(struct tx_ring *txr, struct mbuf *mp, u32 *hdrlen)
{
	struct adapter *adapter = txr->adapter;
	struct e1000_adv_tx_context_desc *TXD;
	struct igb_tx_buffer        *tx_buffer;
	u32 vlan_macip_lens = 0, type_tucmd_mlhl = 0;
	u32 mss_l4len_idx = 0;
	u16 vtag = 0;
	int ctxd, ehdrlen, ip_hlen, tcp_hlen;
	struct ether_vlan_header *eh;
	struct ip *ip;
	struct tcphdr *th;


	/*
	 * Determine where frame payload starts.
	 * Jump over vlan headers if already present
	 */
	eh = mtod(mp, struct ether_vlan_header *);
	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN))
		ehdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	else
		ehdrlen = ETHER_HDR_LEN;

	/* Ensure we have at least the IP+TCP header in the first mbuf. */
	if (mp->m_len < ehdrlen + sizeof(struct ip) + sizeof(struct tcphdr))
		return FALSE;

	/* Only supports IPV4 for now */
	ctxd = txr->next_avail_desc;
	tx_buffer = &txr->tx_buffers[ctxd];
	TXD = (struct e1000_adv_tx_context_desc *) &txr->tx_base[ctxd];

	ip = (struct ip *)(mp->m_data + ehdrlen);
	if (ip->ip_p != IPPROTO_TCP)
                return FALSE;   /* 0 */
	ip->ip_sum = 0;
	ip_hlen = ip->ip_hl << 2;
	th = (struct tcphdr *)((caddr_t)ip + ip_hlen);
	th->th_sum = in_pseudo(ip->ip_src.s_addr,
	    ip->ip_dst.s_addr, htons(IPPROTO_TCP));
	tcp_hlen = th->th_off << 2;
	/*
	 * Calculate header length, this is used
	 * in the transmit desc in igb_xmit
	 */
	*hdrlen = ehdrlen + ip_hlen + tcp_hlen;

	/* VLAN MACLEN IPLEN */
	if (mp->m_flags & M_VLANTAG) {
		vtag = htole16(mp->m_pkthdr.ether_vtag);
		vlan_macip_lens |= (vtag << E1000_ADVTXD_VLAN_SHIFT);
	}

	vlan_macip_lens |= (ehdrlen << E1000_ADVTXD_MACLEN_SHIFT);
	vlan_macip_lens |= ip_hlen;
	TXD->vlan_macip_lens |= htole32(vlan_macip_lens);

	/* ADV DTYPE TUCMD */
	type_tucmd_mlhl |= E1000_ADVTXD_DCMD_DEXT | E1000_ADVTXD_DTYP_CTXT;
	type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_TCP;
	type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV4;
	TXD->type_tucmd_mlhl |= htole32(type_tucmd_mlhl);

	/* MSS L4LEN IDX */
	mss_l4len_idx |= (mp->m_pkthdr.tso_segsz << E1000_ADVTXD_MSS_SHIFT);
	mss_l4len_idx |= (tcp_hlen << E1000_ADVTXD_L4LEN_SHIFT);
	TXD->mss_l4len_idx = htole32(mss_l4len_idx);

	TXD->seqnum_seed = htole32(0);
	tx_buffer->m_head = NULL;
	tx_buffer->next_eop = -1;

	if (++ctxd == adapter->num_tx_desc)
		ctxd = 0;

	txr->tx_avail--;
	txr->next_avail_desc = ctxd;
	return TRUE;
}


/*********************************************************************
 *
 *  Context Descriptor setup for VLAN or CSUM
 *
 **********************************************************************/

static bool
igb_tx_ctx_setup(struct tx_ring *txr, struct mbuf *mp)
{
	struct adapter *adapter = txr->adapter;
	struct e1000_adv_tx_context_desc *TXD;
	struct igb_tx_buffer        *tx_buffer;
	uint32_t vlan_macip_lens = 0, type_tucmd_mlhl = 0;
	struct ether_vlan_header *eh;
	struct ip *ip = NULL;
	struct ip6_hdr *ip6;
	int  ehdrlen, ctxd, ip_hlen = 0;
	u16	etype, vtag = 0;
	u8	ipproto = 0;
	bool	offload = TRUE;

	if ((mp->m_pkthdr.csum_flags & CSUM_OFFLOAD) == 0)
		offload = FALSE;

	ctxd = txr->next_avail_desc;
	tx_buffer = &txr->tx_buffers[ctxd];
	TXD = (struct e1000_adv_tx_context_desc *) &txr->tx_base[ctxd];

	/*
	** In advanced descriptors the vlan tag must 
	** be placed into the context descriptor, thus
	** we need to be here just for that setup.
	*/
	if (mp->m_flags & M_VLANTAG) {
		vtag = htole16(mp->m_pkthdr.ether_vtag);
		vlan_macip_lens |= (vtag << E1000_ADVTXD_VLAN_SHIFT);
	} else if (offload == FALSE)
		return FALSE;

	/*
	 * Determine where frame payload starts.
	 * Jump over vlan headers if already present,
	 * helpful for QinQ too.
	 */
	eh = mtod(mp, struct ether_vlan_header *);
	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		etype = ntohs(eh->evl_proto);
		ehdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		etype = ntohs(eh->evl_encap_proto);
		ehdrlen = ETHER_HDR_LEN;
	}

	/* Set the ether header length */
	vlan_macip_lens |= ehdrlen << E1000_ADVTXD_MACLEN_SHIFT;

	switch (etype) {
		case ETHERTYPE_IP:
			ip = (struct ip *)(mp->m_data + ehdrlen);
			ip_hlen = ip->ip_hl << 2;
			if (mp->m_len < ehdrlen + ip_hlen) {
				offload = FALSE;
				break;
			}
			ipproto = ip->ip_p;
			type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV4;
			break;
		case ETHERTYPE_IPV6:
			ip6 = (struct ip6_hdr *)(mp->m_data + ehdrlen);
			ip_hlen = sizeof(struct ip6_hdr);
			if (mp->m_len < ehdrlen + ip_hlen)
				return (FALSE);
			ipproto = ip6->ip6_nxt;
			type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV6;
			break;
		default:
			offload = FALSE;
			break;
	}

	vlan_macip_lens |= ip_hlen;
	type_tucmd_mlhl |= E1000_ADVTXD_DCMD_DEXT | E1000_ADVTXD_DTYP_CTXT;

	switch (ipproto) {
		case IPPROTO_TCP:
			if (mp->m_pkthdr.csum_flags & CSUM_TCP)
				type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_TCP;
			break;
		case IPPROTO_UDP:
			if (mp->m_pkthdr.csum_flags & CSUM_UDP)
				type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_UDP;
			break;
#if __FreeBSD_version >= 800000
		case IPPROTO_SCTP:
			if (mp->m_pkthdr.csum_flags & CSUM_SCTP)
				type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_SCTP;
			break;
#endif
		default:
			offload = FALSE;
			break;
	}

	/* Now copy bits into descriptor */
	TXD->vlan_macip_lens |= htole32(vlan_macip_lens);
	TXD->type_tucmd_mlhl |= htole32(type_tucmd_mlhl);
	TXD->seqnum_seed = htole32(0);
	TXD->mss_l4len_idx = htole32(0);

	tx_buffer->m_head = NULL;
	tx_buffer->next_eop = -1;

	/* We've consumed the first desc, adjust counters */
	if (++ctxd == adapter->num_tx_desc)
		ctxd = 0;
	txr->next_avail_desc = ctxd;
	--txr->tx_avail;

        return (offload);
}


/**********************************************************************
 *
 *  Examine each tx_buffer in the used queue. If the hardware is done
 *  processing the packet then free associated resources. The
 *  tx_buffer is put back on the free queue.
 *
 *  TRUE return means there's work in the ring to clean, FALSE its empty.
 **********************************************************************/
static bool
igb_txeof(struct tx_ring *txr)
{
	struct adapter	*adapter = txr->adapter;
        int first, last, done, num_avail;
	u32	cleaned = 0;
        struct igb_tx_buffer *tx_buffer;
        struct e1000_tx_desc   *tx_desc, *eop_desc;
	struct ifnet   *ifp = adapter->ifp;

	IGB_TX_LOCK_ASSERT(txr);

        if (txr->tx_avail == adapter->num_tx_desc)
                return FALSE;

        num_avail = txr->tx_avail;
        first = txr->next_to_clean;
        tx_desc = &txr->tx_base[first];
        tx_buffer = &txr->tx_buffers[first];
	last = tx_buffer->next_eop;
        eop_desc = &txr->tx_base[last];

	/*
	 * What this does is get the index of the
	 * first descriptor AFTER the EOP of the 
	 * first packet, that way we can do the
	 * simple comparison on the inner while loop.
	 */
	if (++last == adapter->num_tx_desc)
 		last = 0;
	done = last;

        bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
            BUS_DMASYNC_POSTREAD);

        while (eop_desc->upper.fields.status & E1000_TXD_STAT_DD) {
		/* We clean the range of the packet */
		while (first != done) {
                	tx_desc->upper.data = 0;
                	tx_desc->lower.data = 0;
                	tx_desc->buffer_addr = 0;
                	++num_avail; ++cleaned;

			if (tx_buffer->m_head) {
				ifp->if_opackets++;
				bus_dmamap_sync(txr->txtag,
				    tx_buffer->map,
				    BUS_DMASYNC_POSTWRITE);
				bus_dmamap_unload(txr->txtag,
				    tx_buffer->map);

                        	m_freem(tx_buffer->m_head);
                        	tx_buffer->m_head = NULL;
                	}
			tx_buffer->next_eop = -1;

	                if (++first == adapter->num_tx_desc)
				first = 0;

	                tx_buffer = &txr->tx_buffers[first];
			tx_desc = &txr->tx_base[first];
		}
		/* See if we can continue to the next packet */
		last = tx_buffer->next_eop;
		if (last != -1) {
        		eop_desc = &txr->tx_base[last];
			/* Get new done point */
			if (++last == adapter->num_tx_desc) last = 0;
			done = last;
		} else
			break;
        }
        bus_dmamap_sync(txr->txdma.dma_tag, txr->txdma.dma_map,
            BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

        txr->next_to_clean = first;

        /*
         * If we have enough room, clear IFF_DRV_OACTIVE to tell the stack
         * that it is OK to send packets.
         * If there are no pending descriptors, clear the timeout. Otherwise,
         * if some descriptors have been freed, restart the timeout.
         */
        if (num_avail > IGB_TX_CLEANUP_THRESHOLD) {                
                ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
		/* All clean, turn off the timer */
                if (num_avail == adapter->num_tx_desc) {
			txr->watchdog_timer = 0;
        		txr->tx_avail = num_avail;
			return FALSE;
		}
        }

	/* Some cleaned, reset the timer */
	if (cleaned)
		txr->watchdog_timer = IGB_TX_TIMEOUT;
        txr->tx_avail = num_avail;
        return TRUE;
}


/*********************************************************************
 *
 *  Setup descriptor buffer(s) from system mbuf buffer pools.
 *  		i - designates the ring index
 *		clean - tells the function whether to update
 *		        the header, the packet buffer, or both.
 *
 **********************************************************************/
static int
igb_get_buf(struct rx_ring *rxr, int i, u8 clean)
{
	struct adapter		*adapter = rxr->adapter;
	struct mbuf		*mh, *mp;
	bus_dma_segment_t	seg[2];
	bus_dmamap_t		map;
	struct igb_rx_buffer	*rx_buffer;
	int			error, nsegs;
	int			merr = 0;


	rx_buffer = &rxr->rx_buffers[i];

	/* First get our header and payload mbuf */
	if (clean & IGB_CLEAN_HEADER) {
		mh = m_gethdr(M_DONTWAIT, MT_DATA);
		if (mh == NULL)
			goto remap;
	} else  /* reuse */
		mh = rxr->rx_buffers[i].m_head;

	mh->m_len = MHLEN;
	mh->m_flags |= M_PKTHDR;

	if (clean & IGB_CLEAN_PAYLOAD) {
		mp = m_getjcl(M_DONTWAIT, MT_DATA,
		    M_PKTHDR, adapter->rx_mbuf_sz);
		if (mp == NULL)
			goto remap;
		mp->m_len = adapter->rx_mbuf_sz;
		mp->m_flags &= ~M_PKTHDR;
	} else {	/* reusing */
		mp = rxr->rx_buffers[i].m_pack;
		mp->m_len = adapter->rx_mbuf_sz;
		mp->m_flags &= ~M_PKTHDR;
	}
	/*
	** Need to create a chain for the following
	** dmamap call at this point.
	*/
	mh->m_next = mp;
	mh->m_pkthdr.len = mh->m_len + mp->m_len;

	/* Get the memory mapping */
	error = bus_dmamap_load_mbuf_sg(rxr->rxtag,
	    rxr->rx_spare_map, mh, seg, &nsegs, BUS_DMA_NOWAIT);
	if (error != 0) {
		printf("GET BUF: dmamap load failure - %d\n", error);
		m_free(mh);
		return (error);
	}

	/* Unload old mapping and update buffer struct */
	if (rx_buffer->m_head != NULL)
			bus_dmamap_unload(rxr->rxtag, rx_buffer->map);
	map = rx_buffer->map;
	rx_buffer->map = rxr->rx_spare_map;
	rxr->rx_spare_map = map;
	rx_buffer->m_head = mh;
	rx_buffer->m_pack = mp;
	bus_dmamap_sync(rxr->rxtag,
	    rx_buffer->map, BUS_DMASYNC_PREREAD);

	/* Update descriptor */
	rxr->rx_base[i].read.hdr_addr = htole64(seg[0].ds_addr);
	rxr->rx_base[i].read.pkt_addr = htole64(seg[1].ds_addr);

	return (0);

	/*
	** If we get here, we have an mbuf resource
	** issue, so we discard the incoming packet
	** and attempt to reuse existing mbufs next
	** pass thru the ring, but to do so we must
	** fix up the descriptor which had the address
	** clobbered with writeback info.
	*/
remap:
	adapter->mbuf_header_failed++;
	merr = ENOBUFS;
	/* Is there a reusable buffer? */
	mh = rxr->rx_buffers[i].m_head;
	if (mh == NULL) /* Nope, init error */
		return (merr);
	mp = rxr->rx_buffers[i].m_pack;
	if (mp == NULL) /* Nope, init error */
		return (merr);
	/* Get our old mapping */
	rx_buffer = &rxr->rx_buffers[i];
	error = bus_dmamap_load_mbuf_sg(rxr->rxtag,
	    rx_buffer->map, mh, seg, &nsegs, BUS_DMA_NOWAIT);
	if (error != 0) {
		/* We really have a problem */
		m_free(mh);
		return (error);
	}
	/* Now fix the descriptor as needed */
	rxr->rx_base[i].read.hdr_addr = htole64(seg[0].ds_addr);
	rxr->rx_base[i].read.pkt_addr = htole64(seg[1].ds_addr);
	return (merr);
}


/*********************************************************************
 *
 *  Allocate memory for rx_buffer structures. Since we use one
 *  rx_buffer per received packet, the maximum number of rx_buffer's
 *  that we'll need is equal to the number of receive descriptors
 *  that we've allocated.
 *
 **********************************************************************/
static int
igb_allocate_receive_buffers(struct rx_ring *rxr)
{
	struct	adapter 	*adapter = rxr->adapter;
	device_t 		dev = adapter->dev;
	struct igb_rx_buffer 	*rxbuf;
	int             	i, bsize, error;

	bsize = sizeof(struct igb_rx_buffer) * adapter->num_rx_desc;
	if (!(rxr->rx_buffers =
	    (struct igb_rx_buffer *) malloc(bsize,
	    M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "Unable to allocate rx_buffer memory\n");
		error = ENOMEM;
		goto fail;
	}

	/*
	** The tag is made to accomodate the largest buffer size
	** with packet split (hence the two segments, even though
	** it may not always use this.
	*/
	if ((error = bus_dma_tag_create(NULL,		/* parent */
				   PAGE_SIZE, 0,	/* alignment, bounds */
				   BUS_SPACE_MAXADDR,	/* lowaddr */
				   BUS_SPACE_MAXADDR,	/* highaddr */
				   NULL, NULL,		/* filter, filterarg */
				   MJUM16BYTES,		/* maxsize */
				   2,			/* nsegments */
				   MJUMPAGESIZE,	/* maxsegsize */
				   0,			/* flags */
				   NULL,		/* lockfunc */
				   NULL,		/* lockfuncarg */
				   &rxr->rxtag))) {
		device_printf(dev, "Unable to create RX DMA tag\n");
		goto fail;
	}

	/* Create the spare map (used by getbuf) */
        error = bus_dmamap_create(rxr->rxtag, BUS_DMA_NOWAIT,
	     &rxr->rx_spare_map);
	if (error) {
		device_printf(dev,
		    "%s: bus_dmamap_create header spare failed: %d\n",
		    __func__, error);
		goto fail;
	}

	for (i = 0; i < adapter->num_rx_desc; i++, rxbuf++) {
		rxbuf = &rxr->rx_buffers[i];
		error = bus_dmamap_create(rxr->rxtag,
		    BUS_DMA_NOWAIT, &rxbuf->map);
		if (error) {
			device_printf(dev, "Unable to create RX DMA maps\n");
			goto fail;
		}
	}

	return (0);

fail:
	/* Frees all, but can handle partial completion */
	igb_free_receive_structures(adapter);
	return (error);
}

/*********************************************************************
 *
 *  Initialize a receive ring and its buffers.
 *
 **********************************************************************/
static int
igb_setup_receive_ring(struct rx_ring *rxr)
{
	struct	adapter		*adapter;
	struct  ifnet		*ifp;
	device_t		dev;
	struct igb_rx_buffer	*rxbuf;
	struct lro_ctrl		*lro = &rxr->lro;
	int			j, rsize;

	adapter = rxr->adapter;
	dev = adapter->dev;
	ifp = adapter->ifp;
	rxr->lro_enabled = FALSE;
	rxr->hdr_split = FALSE;

	/* Clear the ring contents */
	rsize = roundup2(adapter->num_rx_desc *
	    sizeof(union e1000_adv_rx_desc), IGB_DBA_ALIGN);
	bzero((void *)rxr->rx_base, rsize);

	/*
	** Free current RX buffer structures and their mbufs
	*/
	for (int i = 0; i < adapter->num_rx_desc; i++) {
		rxbuf = &rxr->rx_buffers[i];
		bus_dmamap_sync(rxr->rxtag, rxbuf->map,
		    BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(rxr->rxtag, rxbuf->map);
		if (rxbuf->m_head) {
			rxbuf->m_head->m_next = rxbuf->m_pack;
			m_freem(rxbuf->m_head);
		}
		rxbuf->m_head = NULL;
		rxbuf->m_pack = NULL;
	}

	/* Next replenish the ring */
	for (j = 0; j < adapter->num_rx_desc; j++) {
		if (igb_get_buf(rxr, j, IGB_CLEAN_BOTH) == ENOBUFS) {
			rxr->rx_buffers[j].m_head = NULL;
			rxr->rx_buffers[j].m_pack = NULL;
			rxr->rx_base[j].read.hdr_addr = 0;
			rxr->rx_base[j].read.pkt_addr = 0;
			goto fail;
		}
	}

	/* Setup our descriptor indices */
	rxr->next_to_check = 0;
	rxr->last_cleaned = 0;

	bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	/*
	** Now set up the LRO interface, we
	** also only do head split when LRO
	** is enabled, since so often they
	** are undesireable in similar setups.
	*/
	if (ifp->if_capenable & IFCAP_LRO) {
		int err = tcp_lro_init(lro);
		if (err) {
			device_printf(dev,"LRO Initialization failed!\n");
			goto fail;
		}
		INIT_DEBUGOUT("RX LRO Initialized\n");
		rxr->lro_enabled = TRUE;
		rxr->hdr_split = TRUE;
		lro->ifp = adapter->ifp;
	}

	return (0);
fail:
	/*
	 * We need to clean up any buffers allocated
	 * so far, 'j' is the failing index.
	 */
	for (int i = 0; i < j; i++) {
		rxbuf = &rxr->rx_buffers[i];
		if (rxbuf->m_head != NULL) {
			bus_dmamap_sync(rxr->rxtag, rxbuf->map,
			    BUS_DMASYNC_POSTREAD);
			bus_dmamap_unload(rxr->rxtag, rxbuf->map);
			m_freem(rxbuf->m_head);
			rxbuf->m_head = NULL;
		}
	}
	return (ENOBUFS);
}

/*********************************************************************
 *
 *  Initialize all receive rings.
 *
 **********************************************************************/
static int
igb_setup_receive_structures(struct adapter *adapter)
{
	struct rx_ring *rxr = adapter->rx_rings;
	int i, j;

	for (i = 0; i < adapter->num_queues; i++, rxr++)
		if (igb_setup_receive_ring(rxr))
			goto fail;

	return (0);
fail:
	/*
	 * Free RX buffers allocated so far, we will only handle
	 * the rings that completed, the failing case will have
	 * cleaned up for itself. The value of 'i' will be the
	 * failed ring so we must pre-decrement it.
	 */
	rxr = adapter->rx_rings;
	for (--i; i > 0; i--, rxr++) {
		for (j = 0; j < adapter->num_rx_desc; j++) {
			struct igb_rx_buffer *rxbuf;
			rxbuf = &rxr->rx_buffers[j];
			if (rxbuf->m_head != NULL) {
				bus_dmamap_sync(rxr->rxtag, rxbuf->map,
			  	  BUS_DMASYNC_POSTREAD);
				bus_dmamap_unload(rxr->rxtag, rxbuf->map);
				m_freem(rxbuf->m_head);
				rxbuf->m_head = NULL;
			}
		}
	}

	return (ENOBUFS);
}

/*********************************************************************
 *
 *  Enable receive unit.
 *
 **********************************************************************/
static void
igb_initialize_receive_units(struct adapter *adapter)
{
	struct rx_ring	*rxr = adapter->rx_rings;
	struct ifnet	*ifp = adapter->ifp;
	u32		rctl, rxcsum, psize, srrctl = 0;

	INIT_DEBUGOUT("igb_initialize_receive_unit: begin");

	/*
	 * Make sure receives are disabled while setting
	 * up the descriptor ring
	 */
	rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl & ~E1000_RCTL_EN);

	/*
	** Set up for header split
	*/
	if (rxr->hdr_split) {
		/* Use a standard mbuf for the header */
		srrctl |= IGB_HDR_BUF << E1000_SRRCTL_BSIZEHDRSIZE_SHIFT;
		srrctl |= E1000_SRRCTL_DESCTYPE_HDR_SPLIT_ALWAYS;
	} else
		srrctl |= E1000_SRRCTL_DESCTYPE_ADV_ONEBUF;

	/*
	** Set up for jumbo frames
	*/
	if (ifp->if_mtu > ETHERMTU) {
		rctl |= E1000_RCTL_LPE;
		srrctl |= 4096 >> E1000_SRRCTL_BSIZEPKT_SHIFT;
		rctl |= E1000_RCTL_SZ_4096 | E1000_RCTL_BSEX;

		/* Set maximum packet len */
		psize = adapter->max_frame_size;
		/* are we on a vlan? */
		if (adapter->ifp->if_vlantrunk != NULL)
			psize += VLAN_TAG_SIZE;
		E1000_WRITE_REG(&adapter->hw, E1000_RLPML, psize);
	} else {
		rctl &= ~E1000_RCTL_LPE;
		srrctl |= 2048 >> E1000_SRRCTL_BSIZEPKT_SHIFT;
		rctl |= E1000_RCTL_SZ_2048;
	}

	/* Setup the Base and Length of the Rx Descriptor Rings */
	for (int i = 0; i < adapter->num_queues; i++, rxr++) {
		u64 bus_addr = rxr->rxdma.dma_paddr;
		u32 rxdctl;

		E1000_WRITE_REG(&adapter->hw, E1000_RDLEN(i),
		    adapter->num_rx_desc * sizeof(struct e1000_rx_desc));
		E1000_WRITE_REG(&adapter->hw, E1000_RDBAH(i),
		    (uint32_t)(bus_addr >> 32));
		E1000_WRITE_REG(&adapter->hw, E1000_RDBAL(i),
		    (uint32_t)bus_addr);
		E1000_WRITE_REG(&adapter->hw, E1000_SRRCTL(i), srrctl);
		/* Enable this Queue */
		rxdctl = E1000_READ_REG(&adapter->hw, E1000_RXDCTL(i));
		rxdctl |= E1000_RXDCTL_QUEUE_ENABLE;
		rxdctl &= 0xFFF00000;
		rxdctl |= IGB_RX_PTHRESH;
		rxdctl |= IGB_RX_HTHRESH << 8;
		rxdctl |= IGB_RX_WTHRESH << 16;
		E1000_WRITE_REG(&adapter->hw, E1000_RXDCTL(i), rxdctl);
	}

	/*
	** Setup for RX MultiQueue
	*/
	rxcsum = E1000_READ_REG(&adapter->hw, E1000_RXCSUM);
	if (adapter->num_queues >1) {
		u32 random[10], mrqc, shift = 0;
		union igb_reta {
			u32 dword;
			u8  bytes[4];
		} reta;

		arc4rand(&random, sizeof(random), 0);
		if (adapter->hw.mac.type == e1000_82575)
			shift = 6;
		/* Warning FM follows */
		for (int i = 0; i < 128; i++) {
			reta.bytes[i & 3] =
			    (i % adapter->num_queues) << shift;
			if ((i & 3) == 3)
				E1000_WRITE_REG(&adapter->hw,
				    E1000_RETA(i >> 2), reta.dword);
		}
		/* Now fill in hash table */
		mrqc = E1000_MRQC_ENABLE_RSS_4Q;
		for (int i = 0; i < 10; i++)
			E1000_WRITE_REG_ARRAY(&adapter->hw,
			    E1000_RSSRK(0), i, random[i]);

		mrqc |= (E1000_MRQC_RSS_FIELD_IPV4 |
		    E1000_MRQC_RSS_FIELD_IPV4_TCP);
		mrqc |= (E1000_MRQC_RSS_FIELD_IPV6 |
		    E1000_MRQC_RSS_FIELD_IPV6_TCP);
		mrqc |=( E1000_MRQC_RSS_FIELD_IPV4_UDP |
		    E1000_MRQC_RSS_FIELD_IPV6_UDP);
		mrqc |=( E1000_MRQC_RSS_FIELD_IPV6_UDP_EX |
		    E1000_MRQC_RSS_FIELD_IPV6_TCP_EX);

		E1000_WRITE_REG(&adapter->hw, E1000_MRQC, mrqc);

		/*
		** NOTE: Receive Full-Packet Checksum Offload 
		** is mutually exclusive with Multiqueue. However
		** this is not the same as TCP/IP checksums which
		** still work.
		*/
		rxcsum |= E1000_RXCSUM_PCSD;
#if __FreeBSD_version >= 800000
		/* For SCTP Offload */
		if ((adapter->hw.mac.type == e1000_82576)
		    && (ifp->if_capenable & IFCAP_RXCSUM))
			rxcsum |= E1000_RXCSUM_CRCOFL;
#endif
	} else {
		/* Non RSS setup */
		if (ifp->if_capenable & IFCAP_RXCSUM) {
			rxcsum |= E1000_RXCSUM_IPPCSE;
#if __FreeBSD_version >= 800000
			if (adapter->hw.mac.type == e1000_82576)
				rxcsum |= E1000_RXCSUM_CRCOFL;
#endif
		} else
			rxcsum &= ~E1000_RXCSUM_TUOFL;
	}
	E1000_WRITE_REG(&adapter->hw, E1000_RXCSUM, rxcsum);

	/* Setup the Receive Control Register */
	rctl &= ~(3 << E1000_RCTL_MO_SHIFT);
	rctl |= E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_LBM_NO |
		   E1000_RCTL_RDMTS_HALF |
		   (adapter->hw.mac.mc_filter_type << E1000_RCTL_MO_SHIFT);

	/* Make sure VLAN Filters are off */
	rctl &= ~E1000_RCTL_VFE;
	/* Don't store bad packets */
	rctl &= ~E1000_RCTL_SBP;

	/* Enable Receives */
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);

	/*
	 * Setup the HW Rx Head and Tail Descriptor Pointers
	 *   - needs to be after enable
	 */
	for (int i = 0; i < adapter->num_queues; i++) {
		E1000_WRITE_REG(&adapter->hw, E1000_RDH(i), 0);
		E1000_WRITE_REG(&adapter->hw, E1000_RDT(i),
		     adapter->num_rx_desc - 1);
	}
	return;
}

/*********************************************************************
 *
 *  Free receive rings.
 *
 **********************************************************************/
static void
igb_free_receive_structures(struct adapter *adapter)
{
	struct rx_ring *rxr = adapter->rx_rings;

	for (int i = 0; i < adapter->num_queues; i++, rxr++) {
		struct lro_ctrl	*lro = &rxr->lro;
		igb_free_receive_buffers(rxr);
		tcp_lro_free(lro);
		igb_dma_free(adapter, &rxr->rxdma);
	}

	free(adapter->rx_rings, M_DEVBUF);
}

/*********************************************************************
 *
 *  Free receive ring data structures.
 *
 **********************************************************************/
static void
igb_free_receive_buffers(struct rx_ring *rxr)
{
	struct adapter	*adapter = rxr->adapter;
	struct igb_rx_buffer *rx_buffer;

	INIT_DEBUGOUT("free_receive_structures: begin");

	if (rxr->rx_spare_map) {
		bus_dmamap_destroy(rxr->rxtag, rxr->rx_spare_map);
		rxr->rx_spare_map = NULL;
	}

	/* Cleanup any existing buffers */
	if (rxr->rx_buffers != NULL) {
		rx_buffer = &rxr->rx_buffers[0];
		for (int i = 0; i < adapter->num_rx_desc; i++, rx_buffer++) {
			if (rx_buffer->m_head != NULL) {
				bus_dmamap_sync(rxr->rxtag, rx_buffer->map,
				    BUS_DMASYNC_POSTREAD);
				bus_dmamap_unload(rxr->rxtag,
				    rx_buffer->map);
				m_freem(rx_buffer->m_head);
				rx_buffer->m_head = NULL;
			} else if (rx_buffer->map != NULL)
				bus_dmamap_unload(rxr->rxtag,
				    rx_buffer->map);
			if (rx_buffer->map != NULL) {
				bus_dmamap_destroy(rxr->rxtag,
				    rx_buffer->map);
				rx_buffer->map = NULL;
			}
		}
	}

	if (rxr->rx_buffers != NULL) {
		free(rxr->rx_buffers, M_DEVBUF);
		rxr->rx_buffers = NULL;
	}

	if (rxr->rxtag != NULL) {
		bus_dma_tag_destroy(rxr->rxtag);
		rxr->rxtag = NULL;
	}
}
/*********************************************************************
 *
 *  This routine executes in interrupt context. It replenishes
 *  the mbufs in the descriptor and sends data which has been
 *  dma'ed into host memory to upper layer.
 *
 *  We loop at most count times if count is > 0, or until done if
 *  count < 0.
 *
 *  Return TRUE if more to clean, FALSE otherwise
 *********************************************************************/
static bool
igb_rxeof(struct rx_ring *rxr, int count)
{
	struct adapter		*adapter = rxr->adapter;
	struct ifnet		*ifp;
	struct lro_ctrl		*lro = &rxr->lro;
	struct lro_entry	*queued;
	int			i;
	u32			staterr;
	union e1000_adv_rx_desc	*cur;


	IGB_RX_LOCK(rxr);
	ifp = adapter->ifp;
	i = rxr->next_to_check;
	cur = &rxr->rx_base[i];
	staterr = cur->wb.upper.status_error;

	if (!(staterr & E1000_RXD_STAT_DD)) {
		IGB_RX_UNLOCK(rxr);
		return FALSE;
	}

	/* Sync the ring */
	bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
	    BUS_DMASYNC_POSTREAD);

	/* Main clean loop */
	while ((staterr & E1000_RXD_STAT_DD) &&
	    (count != 0) &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		struct mbuf *sendmp, *mh, *mp;
		u16 hlen, plen, hdr, ptype, len_adj, vtag;
		u8 dopayload, accept_frame, eop;
 
		accept_frame = 1;
		hlen = plen = len_adj = vtag = 0;
		sendmp = mh = mp = NULL;
		ptype = (u16)(cur->wb.lower.lo_dword.data >> 4);

		/* Sync the buffers */
		bus_dmamap_sync(rxr->rxtag, rxr->rx_buffers[i].map,
			    BUS_DMASYNC_POSTREAD);

		/*
		** The way the hardware is configured to
		** split, it will ONLY use the header buffer
		** when header split is enabled, otherwise we
		** get normal behavior, ie, both header and
		** payload are DMA'd into the payload buffer.
		**
		** The fmp test is to catch the case where a
		** packet spans multiple descriptors, in that
		** case only the first header is valid.
		*/
		if ((rxr->hdr_split) && (rxr->fmp == NULL)){
			hdr = le16toh(cur->
			    wb.lower.lo_dword.hs_rss.hdr_info);
			hlen = (hdr & E1000_RXDADV_HDRBUFLEN_MASK) >>
			    E1000_RXDADV_HDRBUFLEN_SHIFT;
			if (hlen > IGB_HDR_BUF)
				hlen = IGB_HDR_BUF;
			plen = le16toh(cur->wb.upper.length);
			/* Handle the header mbuf */
			mh = rxr->rx_buffers[i].m_head;
			mh->m_len = hlen;
			dopayload = IGB_CLEAN_HEADER;
			/*
			** Get the payload length, this
			** could be zero if its a small
			** packet.
			*/
			if (plen) {
				mp = rxr->rx_buffers[i].m_pack;
				mp->m_len = plen;
				mp->m_next = NULL;
				mp->m_flags &= ~M_PKTHDR;
				mh->m_next = mp;
				mh->m_flags |= M_PKTHDR;
				dopayload = IGB_CLEAN_BOTH;
				rxr->rx_split_packets++;
			} else {  /* small packets */
				mh->m_flags &= ~M_PKTHDR;
				mh->m_next = NULL;
			}
		} else {
			/*
			** Either no header split, or a
			** secondary piece of a fragmented
			** split packet.
			*/
			mh = rxr->rx_buffers[i].m_pack;
			mh->m_flags |= M_PKTHDR;
			mh->m_len = le16toh(cur->wb.upper.length);
			dopayload = IGB_CLEAN_PAYLOAD;
		}

		if (staterr & E1000_RXD_STAT_EOP) {
			count--;
			eop = 1;
			/*
			** Strip CRC and account for frag
			*/
			if (mp) { 
				if (mp->m_len < ETHER_CRC_LEN) {
					/* a frag, how much is left? */
					len_adj = ETHER_CRC_LEN - mp->m_len;
					mp->m_len = 0;
				} else
					mp->m_len -= ETHER_CRC_LEN;
			} else { /* not split */
				if (mh->m_len < ETHER_CRC_LEN) {
					len_adj = ETHER_CRC_LEN - mh->m_len;
					mh->m_len = 0;
				} else
					mh->m_len -= ETHER_CRC_LEN;
			}
		} else 
			eop = 0;

		if (staterr & E1000_RXDEXT_ERR_FRAME_ERR_MASK)
			accept_frame = 0;
#ifdef IGB_IEEE1588
	This linux code needs to be converted to work here
	-----------------------------------------------------
               if (unlikely(staterr & E1000_RXD_STAT_TS)) {
                       u64 regval;
                       u64 ns;
// Create an mtag and set it up
                       struct skb_shared_hwtstamps *shhwtstamps =
                               skb_hwtstamps(skb);

                       rd32(E1000_TSYNCRXCTL) & E1000_TSYNCRXCTL_VALID),
                       "igb: no RX time stamp available for time stamped packet");
                       regval = rd32(E1000_RXSTMPL);
                       regval |= (u64)rd32(E1000_RXSTMPH) << 32;
// Do time conversion from the register
                       ns = timecounter_cyc2time(&adapter->clock, regval);
                       clocksync_update(&adapter->sync, ns);
                       memset(shhwtstamps, 0, sizeof(*shhwtstamps));
                       shhwtstamps->hwtstamp = ns_to_ktime(ns);
                       shhwtstamps->syststamp =
                               clocksync_hw2sys(&adapter->sync, ns);
               }
#endif
		if (accept_frame) {
			/*
			** get_buf will overwrite the writeback
			** descriptor so save the VLAN tag now.
			*/
			vtag = le16toh(cur->wb.upper.vlan);
			if (igb_get_buf(rxr, i, dopayload) != 0) {
				ifp->if_iqdrops++;
				goto discard;
			}
			/* Initial frame - setup */
			if (rxr->fmp == NULL) {
				mh->m_flags |= M_PKTHDR;
				mh->m_pkthdr.len = mh->m_len;
				rxr->fmp = mh; /* Store the first mbuf */
				rxr->lmp = mh;
				if (mp) { /* Add payload if split */
					mh->m_pkthdr.len += mp->m_len;
					rxr->lmp = mh->m_next;
				}
			} else {
				/* Chain mbuf's together */
				mh->m_flags &= ~M_PKTHDR;
				rxr->lmp->m_next = mh;
				rxr->lmp = rxr->lmp->m_next;
				rxr->fmp->m_pkthdr.len += mh->m_len;
				/* Adjust for CRC frag */
				if (len_adj) {
					rxr->lmp->m_len -= len_adj;
					rxr->fmp->m_pkthdr.len -= len_adj;
				}
			}

			if (eop) {
				bool sctp = ((ptype & 0x40) != 0);
				rxr->fmp->m_pkthdr.rcvif = ifp;
				ifp->if_ipackets++;
				rxr->rx_packets++;
				/* capture data for AIM */
				rxr->bytes += rxr->fmp->m_pkthdr.len;
				rxr->rx_bytes += rxr->fmp->m_pkthdr.len;

				igb_rx_checksum(staterr, rxr->fmp, sctp);
				if (staterr & E1000_RXD_STAT_VP) {
					rxr->fmp->m_pkthdr.ether_vtag = vtag;
					rxr->fmp->m_flags |= M_VLANTAG;
				}
#if __FreeBSD_version >= 800000
                                rxr->fmp->m_pkthdr.flowid = curcpu;
                                rxr->fmp->m_flags |= M_FLOWID;
#endif
				sendmp = rxr->fmp;
				rxr->fmp = NULL;
				rxr->lmp = NULL;
			}
		} else {
			ifp->if_ierrors++;
discard:
			/* Reuse loaded DMA map and just update mbuf chain */
			if (hlen) {
				mh = rxr->rx_buffers[i].m_head;
				mh->m_len = MHLEN;
				mh->m_next = NULL;
			}
			mp = rxr->rx_buffers[i].m_pack;
			mp->m_len = mp->m_pkthdr.len = adapter->rx_mbuf_sz;
			mp->m_data = mp->m_ext.ext_buf;
			mp->m_next = NULL;
			if (adapter->max_frame_size <=
			    (MCLBYTES - ETHER_ALIGN))
				m_adj(mp, ETHER_ALIGN);
			if (rxr->fmp != NULL) {
				/* handles the whole chain */
				m_freem(rxr->fmp);
				rxr->fmp = NULL;
				rxr->lmp = NULL;
			}
			sendmp = NULL;
		}

		bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		rxr->last_cleaned = i; /* For updating tail */

		/* Advance our pointers to the next descriptor. */
		if (++i == adapter->num_rx_desc)
			i = 0;
 
		/*
		** Note that we hold the RX lock thru
		** the following call so this ring's
		** next_to_check is not gonna change.
		*/
		if (sendmp != NULL) {
			/*
			** Send to the stack if:
			**  - LRO not enabled, or
			**  - no LRO resources, or
			**  - lro enqueue fails
			*/
			if ((!rxr->lro_enabled) ||
			    ((!lro->lro_cnt) || (tcp_lro_rx(lro, sendmp, 0))))
                                (*ifp->if_input)(ifp, sendmp);
                }

		/* Get the next descriptor */
		cur = &rxr->rx_base[i];
		staterr = cur->wb.upper.status_error;
	}
	rxr->next_to_check = i;

	/* Advance the E1000's Receive Queue #0  "Tail Pointer". */
	E1000_WRITE_REG(&adapter->hw, E1000_RDT(rxr->me), rxr->last_cleaned);

	/*
	 * Flush any outstanding LRO work
	 */
	while (!SLIST_EMPTY(&lro->lro_active)) {
		queued = SLIST_FIRST(&lro->lro_active);
		SLIST_REMOVE_HEAD(&lro->lro_active, next);
		tcp_lro_flush(lro, queued);
	}

	IGB_RX_UNLOCK(rxr);

	/*
	** We still have cleaning to do?
	** Schedule another interrupt if so.
	*/
	if (staterr & E1000_RXD_STAT_DD) {
		E1000_WRITE_REG(&adapter->hw, E1000_EICS, rxr->eims);
		return TRUE;
	}

	return FALSE;
}


/*********************************************************************
 *
 *  Verify that the hardware indicated that the checksum is valid.
 *  Inform the stack about the status of checksum so that stack
 *  doesn't spend time verifying the checksum.
 *
 *********************************************************************/
static void
igb_rx_checksum(u32 staterr, struct mbuf *mp, bool sctp)
{
	u16 status = (u16)staterr;
	u8  errors = (u8) (staterr >> 24);

	/* Ignore Checksum bit is set */
	if (status & E1000_RXD_STAT_IXSM) {
		mp->m_pkthdr.csum_flags = 0;
		return;
	}

	if (status & E1000_RXD_STAT_IPCS) {
		/* Did it pass? */
		if (!(errors & E1000_RXD_ERR_IPE)) {
			/* IP Checksum Good */
			mp->m_pkthdr.csum_flags = CSUM_IP_CHECKED;
			mp->m_pkthdr.csum_flags |= CSUM_IP_VALID;
		} else
			mp->m_pkthdr.csum_flags = 0;
	}

	if (status & (E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS)) {
		u16 type = (CSUM_DATA_VALID | CSUM_PSEUDO_HDR);
#if __FreeBSD_version >= 800000
		if (sctp) /* reassign */
			type = CSUM_SCTP_VALID;
#endif
		/* Did it pass? */
		if (!(errors & E1000_RXD_ERR_TCPE)) {
			mp->m_pkthdr.csum_flags |= type;
			if (!sctp)
				mp->m_pkthdr.csum_data = htons(0xffff);
		}
	}
	return;
}

/*
 * This routine is run via an vlan
 * config EVENT
 */
static void
igb_register_vlan(void *arg, struct ifnet *ifp, u16 vtag)
{
	struct adapter	*adapter = ifp->if_softc;
	u32		index, bit;

	if (ifp->if_softc !=  arg)   /* Not our event */
		return;

	if ((vtag == 0) || (vtag > 4095))       /* Invalid */
                return;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	igb_shadow_vfta[index] |= (1 << bit);
	++adapter->num_vlans;
	/* Re-init to load the changes */
	igb_init(adapter);
}

/*
 * This routine is run via an vlan
 * unconfig EVENT
 */
static void
igb_unregister_vlan(void *arg, struct ifnet *ifp, u16 vtag)
{
	struct adapter	*adapter = ifp->if_softc;
	u32		index, bit;

	if (ifp->if_softc !=  arg)
		return;

	if ((vtag == 0) || (vtag > 4095))       /* Invalid */
                return;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	igb_shadow_vfta[index] &= ~(1 << bit);
	--adapter->num_vlans;
	/* Re-init to load the changes */
	igb_init(adapter);
}

static void
igb_setup_vlan_hw_support(struct adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32             reg;

	/*
	** We get here thru init_locked, meaning
	** a soft reset, this has already cleared
	** the VFTA and other state, so if there
	** have been no vlan's registered do nothing.
	*/
	if (adapter->num_vlans == 0)
                return;

	/*
	** A soft reset zero's out the VFTA, so
	** we need to repopulate it now.
	*/
	for (int i = 0; i < IGB_VFTA_SIZE; i++)
                if (igb_shadow_vfta[i] != 0)
			E1000_WRITE_REG_ARRAY(hw, E1000_VFTA,
                            i, igb_shadow_vfta[i]);

	reg = E1000_READ_REG(hw, E1000_CTRL);
	reg |= E1000_CTRL_VME;
	E1000_WRITE_REG(hw, E1000_CTRL, reg);

	/* Enable the Filter Table */
	reg = E1000_READ_REG(hw, E1000_RCTL);
	reg &= ~E1000_RCTL_CFIEN;
	reg |= E1000_RCTL_VFE;
	E1000_WRITE_REG(hw, E1000_RCTL, reg);

	/* Update the frame size */
	E1000_WRITE_REG(&adapter->hw, E1000_RLPML,
	    adapter->max_frame_size + VLAN_TAG_SIZE);
}

static void
igb_enable_intr(struct adapter *adapter)
{
	/* With RSS set up what to auto clear */
	if (adapter->msix_mem) {
		E1000_WRITE_REG(&adapter->hw, E1000_EIAC,
		    adapter->eims_mask);
		E1000_WRITE_REG(&adapter->hw, E1000_EIAM,
		    adapter->eims_mask);
		E1000_WRITE_REG(&adapter->hw, E1000_EIMS,
		    adapter->eims_mask);
		E1000_WRITE_REG(&adapter->hw, E1000_IMS,
		    E1000_IMS_LSC);
	} else {
		E1000_WRITE_REG(&adapter->hw, E1000_IMS,
		    IMS_ENABLE_MASK);
	}
	E1000_WRITE_FLUSH(&adapter->hw);

	return;
}

static void
igb_disable_intr(struct adapter *adapter)
{
	if (adapter->msix_mem) {
		E1000_WRITE_REG(&adapter->hw, E1000_EIMC, ~0);
		E1000_WRITE_REG(&adapter->hw, E1000_EIAC, 0);
	} 
	E1000_WRITE_REG(&adapter->hw, E1000_IMC, ~0);
	E1000_WRITE_FLUSH(&adapter->hw);
	return;
}

/*
 * Bit of a misnomer, what this really means is
 * to enable OS management of the system... aka
 * to disable special hardware management features 
 */
static void
igb_init_manageability(struct adapter *adapter)
{
	if (adapter->has_manage) {
		int manc2h = E1000_READ_REG(&adapter->hw, E1000_MANC2H);
		int manc = E1000_READ_REG(&adapter->hw, E1000_MANC);

		/* disable hardware interception of ARP */
		manc &= ~(E1000_MANC_ARP_EN);

                /* enable receiving management packets to the host */
		manc |= E1000_MANC_EN_MNG2HOST;
		manc2h |= 1 << 5;  /* Mng Port 623 */
		manc2h |= 1 << 6;  /* Mng Port 664 */
		E1000_WRITE_REG(&adapter->hw, E1000_MANC2H, manc2h);
		E1000_WRITE_REG(&adapter->hw, E1000_MANC, manc);
	}
}

/*
 * Give control back to hardware management
 * controller if there is one.
 */
static void
igb_release_manageability(struct adapter *adapter)
{
	if (adapter->has_manage) {
		int manc = E1000_READ_REG(&adapter->hw, E1000_MANC);

		/* re-enable hardware interception of ARP */
		manc |= E1000_MANC_ARP_EN;
		manc &= ~E1000_MANC_EN_MNG2HOST;

		E1000_WRITE_REG(&adapter->hw, E1000_MANC, manc);
	}
}

/*
 * igb_get_hw_control sets CTRL_EXT:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that
 * the driver is loaded. 
 *
 */
static void
igb_get_hw_control(struct adapter *adapter)
{
	u32 ctrl_ext;

	/* Let firmware know the driver has taken over */
	ctrl_ext = E1000_READ_REG(&adapter->hw, E1000_CTRL_EXT);
	E1000_WRITE_REG(&adapter->hw, E1000_CTRL_EXT,
	    ctrl_ext | E1000_CTRL_EXT_DRV_LOAD);
}

/*
 * igb_release_hw_control resets CTRL_EXT:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that the
 * driver is no longer loaded.
 *
 */
static void
igb_release_hw_control(struct adapter *adapter)
{
	u32 ctrl_ext;

	/* Let firmware taken over control of h/w */
	ctrl_ext = E1000_READ_REG(&adapter->hw, E1000_CTRL_EXT);
	E1000_WRITE_REG(&adapter->hw, E1000_CTRL_EXT,
	    ctrl_ext & ~E1000_CTRL_EXT_DRV_LOAD);
}

static int
igb_is_valid_ether_addr(uint8_t *addr)
{
	char zero_addr[6] = { 0, 0, 0, 0, 0, 0 };

	if ((addr[0] & 1) || (!bcmp(addr, zero_addr, ETHER_ADDR_LEN))) {
		return (FALSE);
	}

	return (TRUE);
}


/*
 * Enable PCI Wake On Lan capability
 */
void
igb_enable_wakeup(device_t dev)
{
	u16     cap, status;
	u8      id;

	/* First find the capabilities pointer*/
	cap = pci_read_config(dev, PCIR_CAP_PTR, 2);
	/* Read the PM Capabilities */
	id = pci_read_config(dev, cap, 1);
	if (id != PCIY_PMG)     /* Something wrong */
		return;
	/* OK, we have the power capabilities, so
	   now get the status register */
	cap += PCIR_POWER_STATUS;
	status = pci_read_config(dev, cap, 2);
	status |= PCIM_PSTAT_PME | PCIM_PSTAT_PMEENABLE;
	pci_write_config(dev, cap, status, 2);
	return;
}


/**********************************************************************
 *
 *  Update the board statistics counters.
 *
 **********************************************************************/
static void
igb_update_stats_counters(struct adapter *adapter)
{
	struct ifnet   *ifp;

	if(adapter->hw.phy.media_type == e1000_media_type_copper ||
	   (E1000_READ_REG(&adapter->hw, E1000_STATUS) & E1000_STATUS_LU)) {
		adapter->stats.symerrs += E1000_READ_REG(&adapter->hw, E1000_SYMERRS);
		adapter->stats.sec += E1000_READ_REG(&adapter->hw, E1000_SEC);
	}
	adapter->stats.crcerrs += E1000_READ_REG(&adapter->hw, E1000_CRCERRS);
	adapter->stats.mpc += E1000_READ_REG(&adapter->hw, E1000_MPC);
	adapter->stats.scc += E1000_READ_REG(&adapter->hw, E1000_SCC);
	adapter->stats.ecol += E1000_READ_REG(&adapter->hw, E1000_ECOL);

	adapter->stats.mcc += E1000_READ_REG(&adapter->hw, E1000_MCC);
	adapter->stats.latecol += E1000_READ_REG(&adapter->hw, E1000_LATECOL);
	adapter->stats.colc += E1000_READ_REG(&adapter->hw, E1000_COLC);
	adapter->stats.dc += E1000_READ_REG(&adapter->hw, E1000_DC);
	adapter->stats.rlec += E1000_READ_REG(&adapter->hw, E1000_RLEC);
	adapter->stats.xonrxc += E1000_READ_REG(&adapter->hw, E1000_XONRXC);
	adapter->stats.xontxc += E1000_READ_REG(&adapter->hw, E1000_XONTXC);
	adapter->stats.xoffrxc += E1000_READ_REG(&adapter->hw, E1000_XOFFRXC);
	adapter->stats.xofftxc += E1000_READ_REG(&adapter->hw, E1000_XOFFTXC);
	adapter->stats.fcruc += E1000_READ_REG(&adapter->hw, E1000_FCRUC);
	adapter->stats.prc64 += E1000_READ_REG(&adapter->hw, E1000_PRC64);
	adapter->stats.prc127 += E1000_READ_REG(&adapter->hw, E1000_PRC127);
	adapter->stats.prc255 += E1000_READ_REG(&adapter->hw, E1000_PRC255);
	adapter->stats.prc511 += E1000_READ_REG(&adapter->hw, E1000_PRC511);
	adapter->stats.prc1023 += E1000_READ_REG(&adapter->hw, E1000_PRC1023);
	adapter->stats.prc1522 += E1000_READ_REG(&adapter->hw, E1000_PRC1522);
	adapter->stats.gprc += E1000_READ_REG(&adapter->hw, E1000_GPRC);
	adapter->stats.bprc += E1000_READ_REG(&adapter->hw, E1000_BPRC);
	adapter->stats.mprc += E1000_READ_REG(&adapter->hw, E1000_MPRC);
	adapter->stats.gptc += E1000_READ_REG(&adapter->hw, E1000_GPTC);

	/* For the 64-bit byte counters the low dword must be read first. */
	/* Both registers clear on the read of the high dword */

	adapter->stats.gorc += E1000_READ_REG(&adapter->hw, E1000_GORCH);
	adapter->stats.gotc += E1000_READ_REG(&adapter->hw, E1000_GOTCH);

	adapter->stats.rnbc += E1000_READ_REG(&adapter->hw, E1000_RNBC);
	adapter->stats.ruc += E1000_READ_REG(&adapter->hw, E1000_RUC);
	adapter->stats.rfc += E1000_READ_REG(&adapter->hw, E1000_RFC);
	adapter->stats.roc += E1000_READ_REG(&adapter->hw, E1000_ROC);
	adapter->stats.rjc += E1000_READ_REG(&adapter->hw, E1000_RJC);

	adapter->stats.tor += E1000_READ_REG(&adapter->hw, E1000_TORH);
	adapter->stats.tot += E1000_READ_REG(&adapter->hw, E1000_TOTH);

	adapter->stats.tpr += E1000_READ_REG(&adapter->hw, E1000_TPR);
	adapter->stats.tpt += E1000_READ_REG(&adapter->hw, E1000_TPT);
	adapter->stats.ptc64 += E1000_READ_REG(&adapter->hw, E1000_PTC64);
	adapter->stats.ptc127 += E1000_READ_REG(&adapter->hw, E1000_PTC127);
	adapter->stats.ptc255 += E1000_READ_REG(&adapter->hw, E1000_PTC255);
	adapter->stats.ptc511 += E1000_READ_REG(&adapter->hw, E1000_PTC511);
	adapter->stats.ptc1023 += E1000_READ_REG(&adapter->hw, E1000_PTC1023);
	adapter->stats.ptc1522 += E1000_READ_REG(&adapter->hw, E1000_PTC1522);
	adapter->stats.mptc += E1000_READ_REG(&adapter->hw, E1000_MPTC);
	adapter->stats.bptc += E1000_READ_REG(&adapter->hw, E1000_BPTC);

	adapter->stats.algnerrc += 
		E1000_READ_REG(&adapter->hw, E1000_ALGNERRC);
	adapter->stats.rxerrc += 
		E1000_READ_REG(&adapter->hw, E1000_RXERRC);
	adapter->stats.tncrs += 
		E1000_READ_REG(&adapter->hw, E1000_TNCRS);
	adapter->stats.cexterr += 
		E1000_READ_REG(&adapter->hw, E1000_CEXTERR);
	adapter->stats.tsctc += 
		E1000_READ_REG(&adapter->hw, E1000_TSCTC);
	adapter->stats.tsctfc += 
		E1000_READ_REG(&adapter->hw, E1000_TSCTFC);
	ifp = adapter->ifp;

	ifp->if_collisions = adapter->stats.colc;

	/* Rx Errors */
	ifp->if_ierrors = adapter->dropped_pkts + adapter->stats.rxerrc +
	    adapter->stats.crcerrs + adapter->stats.algnerrc +
	    adapter->stats.ruc + adapter->stats.roc +
	    adapter->stats.mpc + adapter->stats.cexterr;

	/* Tx Errors */
	ifp->if_oerrors = adapter->stats.ecol +
	    adapter->stats.latecol + adapter->watchdog_events;
}


/**********************************************************************
 *
 *  This routine is called only when igb_display_debug_stats is enabled.
 *  This routine provides a way to take a look at important statistics
 *  maintained by the driver and hardware.
 *
 **********************************************************************/
static void
igb_print_debug_info(struct adapter *adapter)
{
	device_t dev = adapter->dev;
	struct rx_ring *rxr = adapter->rx_rings;
	struct tx_ring *txr = adapter->tx_rings;
	uint8_t *hw_addr = adapter->hw.hw_addr;

	device_printf(dev, "Adapter hardware address = %p \n", hw_addr);
	device_printf(dev, "CTRL = 0x%x RCTL = 0x%x \n",
	    E1000_READ_REG(&adapter->hw, E1000_CTRL),
	    E1000_READ_REG(&adapter->hw, E1000_RCTL));

#if	(DEBUG_HW > 0)  /* Dont output these errors normally */
	device_printf(dev, "IMS = 0x%x EIMS = 0x%x \n",
	    E1000_READ_REG(&adapter->hw, E1000_IMS),
	    E1000_READ_REG(&adapter->hw, E1000_EIMS));
#endif

	device_printf(dev, "Packet buffer = Tx=%dk Rx=%dk \n",
	    ((E1000_READ_REG(&adapter->hw, E1000_PBA) & 0xffff0000) >> 16),\
	    (E1000_READ_REG(&adapter->hw, E1000_PBA) & 0xffff) );
	device_printf(dev, "Flow control watermarks high = %d low = %d\n",
	    adapter->hw.fc.high_water,
	    adapter->hw.fc.low_water);

	for (int i = 0; i < adapter->num_queues; i++, txr++) {
		device_printf(dev, "Queue(%d) tdh = %d, tdt = %d\n", i,
		    E1000_READ_REG(&adapter->hw, E1000_TDH(i)),
		    E1000_READ_REG(&adapter->hw, E1000_TDT(i)));
		device_printf(dev, "TX(%d) no descriptors avail event = %lld\n",
		    txr->me, (long long)txr->no_desc_avail);
		device_printf(dev, "TX(%d) MSIX IRQ Handled = %lld\n", txr->me,
		    (long long)txr->tx_irq);
		device_printf(dev, "TX(%d) Packets sent = %lld\n", txr->me,
		    (long long)txr->tx_packets);
	}

	for (int i = 0; i < adapter->num_queues; i++, rxr++) {
		struct lro_ctrl *lro = &rxr->lro;
		device_printf(dev, "Queue(%d) rdh = %d, rdt = %d\n", i,
		    E1000_READ_REG(&adapter->hw, E1000_RDH(i)),
		    E1000_READ_REG(&adapter->hw, E1000_RDT(i)));
		device_printf(dev, "RX(%d) Packets received = %lld\n", rxr->me,
		    (long long)rxr->rx_packets);
		device_printf(dev, "RX(%d) Split Packets = %lld\n", rxr->me,
		    (long long)rxr->rx_split_packets);
		device_printf(dev, "RX(%d) Byte count = %lld\n", rxr->me,
		    (long long)rxr->rx_bytes);
		device_printf(dev, "RX(%d) MSIX IRQ Handled = %lld\n", rxr->me,
		    (long long)rxr->rx_irq);
		device_printf(dev,"RX(%d) LRO Queued= %d\n",
		    rxr->me, lro->lro_queued);
		device_printf(dev,"RX(%d) LRO Flushed= %d\n",
		    rxr->me, lro->lro_flushed);
	}

	device_printf(dev, "LINK MSIX IRQ Handled = %u\n", adapter->link_irq);

	device_printf(dev, "Mbuf defrag failed = %ld\n",
	    adapter->mbuf_defrag_failed);
	device_printf(dev, "Std mbuf header failed = %ld\n",
	    adapter->mbuf_header_failed);
	device_printf(dev, "Std mbuf packet failed = %ld\n",
	    adapter->mbuf_packet_failed);
	device_printf(dev, "Driver dropped packets = %ld\n",
	    adapter->dropped_pkts);
	device_printf(dev, "Driver tx dma failure in xmit = %ld\n",
		adapter->no_tx_dma_setup);
}

static void
igb_print_hw_stats(struct adapter *adapter)
{
	device_t dev = adapter->dev;

	device_printf(dev, "Excessive collisions = %lld\n",
	    (long long)adapter->stats.ecol);
#if	(DEBUG_HW > 0)  /* Dont output these errors normally */
	device_printf(dev, "Symbol errors = %lld\n",
	    (long long)adapter->stats.symerrs);
#endif
	device_printf(dev, "Sequence errors = %lld\n",
	    (long long)adapter->stats.sec);
	device_printf(dev, "Defer count = %lld\n",
	    (long long)adapter->stats.dc);
	device_printf(dev, "Missed Packets = %lld\n",
	    (long long)adapter->stats.mpc);
	device_printf(dev, "Receive No Buffers = %lld\n",
	    (long long)adapter->stats.rnbc);
	/* RLEC is inaccurate on some hardware, calculate our own. */
	device_printf(dev, "Receive Length Errors = %lld\n",
	    ((long long)adapter->stats.roc + (long long)adapter->stats.ruc));
	device_printf(dev, "Receive errors = %lld\n",
	    (long long)adapter->stats.rxerrc);
	device_printf(dev, "Crc errors = %lld\n",
	    (long long)adapter->stats.crcerrs);
	device_printf(dev, "Alignment errors = %lld\n",
	    (long long)adapter->stats.algnerrc);
	/* On 82575 these are collision counts */
	device_printf(dev, "Collision/Carrier extension errors = %lld\n",
	    (long long)adapter->stats.cexterr);
	device_printf(dev, "RX overruns = %ld\n", adapter->rx_overruns);
	device_printf(dev, "watchdog timeouts = %ld\n",
	    adapter->watchdog_events);
	device_printf(dev, "XON Rcvd = %lld\n",
	    (long long)adapter->stats.xonrxc);
	device_printf(dev, "XON Xmtd = %lld\n",
	    (long long)adapter->stats.xontxc);
	device_printf(dev, "XOFF Rcvd = %lld\n",
	    (long long)adapter->stats.xoffrxc);
	device_printf(dev, "XOFF Xmtd = %lld\n",
	    (long long)adapter->stats.xofftxc);
	device_printf(dev, "Good Packets Rcvd = %lld\n",
	    (long long)adapter->stats.gprc);
	device_printf(dev, "Good Packets Xmtd = %lld\n",
	    (long long)adapter->stats.gptc);
	device_printf(dev, "TSO Contexts Xmtd = %lld\n",
	    (long long)adapter->stats.tsctc);
	device_printf(dev, "TSO Contexts Failed = %lld\n",
	    (long long)adapter->stats.tsctfc);
}

/**********************************************************************
 *
 *  This routine provides a way to dump out the adapter eeprom,
 *  often a useful debug/service tool. This only dumps the first
 *  32 words, stuff that matters is in that extent.
 *
 **********************************************************************/
static void
igb_print_nvm_info(struct adapter *adapter)
{
	u16	eeprom_data;
	int	i, j, row = 0;

	/* Its a bit crude, but it gets the job done */
	printf("\nInterface EEPROM Dump:\n");
	printf("Offset\n0x0000  ");
	for (i = 0, j = 0; i < 32; i++, j++) {
		if (j == 8) { /* Make the offset block */
			j = 0; ++row;
			printf("\n0x00%x0  ",row);
		}
		e1000_read_nvm(&adapter->hw, i, 1, &eeprom_data);
		printf("%04x ", eeprom_data);
	}
	printf("\n");
}

static int
igb_sysctl_debug_info(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter;
	int error;
	int result;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);

	if (error || !req->newptr)
		return (error);

	if (result == 1) {
		adapter = (struct adapter *)arg1;
		igb_print_debug_info(adapter);
	}
	/*
	 * This value will cause a hex dump of the
	 * first 32 16-bit words of the EEPROM to
	 * the screen.
	 */
	if (result == 2) {
		adapter = (struct adapter *)arg1;
		igb_print_nvm_info(adapter);
        }

	return (error);
}


static int
igb_sysctl_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter;
	int error;
	int result;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);

	if (error || !req->newptr)
		return (error);

	if (result == 1) {
		adapter = (struct adapter *)arg1;
		igb_print_hw_stats(adapter);
	}

	return (error);
}

static void
igb_add_rx_process_limit(struct adapter *adapter, const char *name,
	const char *description, int *limit, int value)
{
	*limit = value;
	SYSCTL_ADD_INT(device_get_sysctl_ctx(adapter->dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(adapter->dev)),
	    OID_AUTO, name, CTLTYPE_INT|CTLFLAG_RW, limit, value, description);
}

#ifdef IGB_IEEE1588
/*
** igb_hwtstamp_ioctl - control hardware time stamping
**
** Outgoing time stamping can be enabled and disabled. Play nice and
** disable it when requested, although it shouldn't case any overhead
** when no packet needs it. At most one packet in the queue may be
** marked for time stamping, otherwise it would be impossible to tell
** for sure to which packet the hardware time stamp belongs.
**
** Incoming time stamping has to be configured via the hardware
** filters. Not all combinations are supported, in particular event
** type has to be specified. Matching the kind of event packet is
** not supported, with the exception of "all V2 events regardless of
** level 2 or 4".
**
*/
static int
igb_hwtstamp_ioctl(struct adapter *adapter, struct ifreq *ifr)
{
	struct e1000_hw *hw = &adapter->hw;
	struct hwtstamp_ctrl *config;
	u32 tsync_tx_ctl_bit = E1000_TSYNCTXCTL_ENABLED;
	u32 tsync_rx_ctl_bit = E1000_TSYNCRXCTL_ENABLED;
	u32 tsync_rx_ctl_type = 0;
	u32 tsync_rx_cfg = 0;
	int is_l4 = 0;
	int is_l2 = 0;
	u16 port = 319; /* PTP */
	u32 regval;

	config = (struct hwtstamp_ctrl *) ifr->ifr_data;

	/* reserved for future extensions */
	if (config->flags)
		return (EINVAL);

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		tsync_tx_ctl_bit = 0;
		break;
	case HWTSTAMP_TX_ON:
		tsync_tx_ctl_bit = E1000_TSYNCTXCTL_ENABLED;
		break;
	default:
		return (ERANGE);
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		tsync_rx_ctl_bit = 0;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_ALL:
		/*
		 * register TSYNCRXCFG must be set, therefore it is not
		 * possible to time stamp both Sync and Delay_Req messages
		 * => fall back to time stamping all packets
		 */
		tsync_rx_ctl_type = E1000_TSYNCRXCTL_TYPE_ALL;
		config->rx_filter = HWTSTAMP_FILTER_ALL;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
		tsync_rx_ctl_type = E1000_TSYNCRXCTL_TYPE_L4_V1;
		tsync_rx_cfg = E1000_TSYNCRXCFG_PTP_V1_SYNC_MESSAGE;
		is_l4 = 1;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		tsync_rx_ctl_type = E1000_TSYNCRXCTL_TYPE_L4_V1;
		tsync_rx_cfg = E1000_TSYNCRXCFG_PTP_V1_DELAY_REQ_MESSAGE;
		is_l4 = 1;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
		tsync_rx_ctl_type = E1000_TSYNCRXCTL_TYPE_L2_L4_V2;
		tsync_rx_cfg = E1000_TSYNCRXCFG_PTP_V2_SYNC_MESSAGE;
		is_l2 = 1;
		is_l4 = 1;
		config->rx_filter = HWTSTAMP_FILTER_SOME;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		tsync_rx_ctl_type = E1000_TSYNCRXCTL_TYPE_L2_L4_V2;
		tsync_rx_cfg = E1000_TSYNCRXCFG_PTP_V2_DELAY_REQ_MESSAGE;
		is_l2 = 1;
		is_l4 = 1;
		config->rx_filter = HWTSTAMP_FILTER_SOME;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		tsync_rx_ctl_type = E1000_TSYNCRXCTL_TYPE_EVENT_V2;
		config->rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		is_l2 = 1;
		break;
	default:
		return -ERANGE;
	}

	/* enable/disable TX */
	regval = E1000_READ_REG(hw, E1000_TSYNCTXCTL);
	regval = (regval & ~E1000_TSYNCTXCTL_ENABLED) | tsync_tx_ctl_bit;
	E1000_WRITE_REG(hw, E1000_TSYNCTXCTL, regval);

	/* enable/disable RX, define which PTP packets are time stamped */
	regval = E1000_READ_REG(hw, E1000_TSYNCRXCTL);
	regval = (regval & ~E1000_TSYNCRXCTL_ENABLED) | tsync_rx_ctl_bit;
	regval = (regval & ~0xE) | tsync_rx_ctl_type;
	E1000_WRITE_REG(hw, E1000_TSYNCRXCTL, regval);
	E1000_WRITE_REG(hw, E1000_TSYNCRXCFG, tsync_rx_cfg);

	/*
	 * Ethertype Filter Queue Filter[0][15:0] = 0x88F7
	 *                                          (Ethertype to filter on)
	 * Ethertype Filter Queue Filter[0][26] = 0x1 (Enable filter)
	 * Ethertype Filter Queue Filter[0][30] = 0x1 (Enable Timestamping)
	 */
	E1000_WRITE_REG(hw, E1000_ETQF0, is_l2 ? 0x440088f7 : 0);

	/* L4 Queue Filter[0]: only filter by source and destination port */
	E1000_WRITE_REG(hw, E1000_SPQF0, htons(port));
	E1000_WRITE_REG(hw, E1000_IMIREXT(0), is_l4 ?
	     ((1<<12) | (1<<19) /* bypass size and control flags */) : 0);
	E1000_WRITE_REG(hw, E1000_IMIR(0), is_l4 ?
	     (htons(port)
	      | (0<<16) /* immediate interrupt disabled */
	      | 0 /* (1<<17) bit cleared: do not bypass
		     destination port check */)
		: 0);
	E1000_WRITE_REG(hw, E1000_FTQF0, is_l4 ?
	     (0x11 /* UDP */
	      | (1<<15) /* VF not compared */
	      | (1<<27) /* Enable Timestamping */
	      | (7<<28) /* only source port filter enabled,
			   source/target address and protocol
			   masked */)
	     : ((1<<15) | (15<<28) /* all mask bits set = filter not
				      enabled */));

	wrfl();

	adapter->hwtstamp_ctrl = config;

	/* clear TX/RX time stamp registers, just to be sure */
	regval = E1000_READ_REG(hw, E1000_TXSTMPH);
	regval = E1000_READ_REG(hw, E1000_RXSTMPH);

	return (error);
}

/*
** igb_read_clock - read raw cycle counter (to be used by time counter)
*/
static cycle_t igb_read_clock(const struct cyclecounter *tc)
{
       struct igb_adapter *adapter =
               container_of(tc, struct igb_adapter, cycles);
       struct e1000_hw *hw = &adapter->hw;
       u64 stamp;

       stamp =  E1000_READ_REG(hw, E1000_SYSTIML);
       stamp |= (u64)E1000_READ_REG(hw, E1000_SYSTIMH) << 32ULL;

       return (stamp);
}

#endif /* IGB_IEEE1588 */
