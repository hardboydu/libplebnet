/*
 *       Copyright (c) 1997 by Simon Shapiro
 *       All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 */

/*
 *  dptpci.c:  Pseudo device drivers for DPT on PCI on FreeBSD 
 *
 *  caveats:   We may need an eisa and an isa files too
 */

#ident "$Id: dpt_pci.c,v 1.3 1998/02/10 17:36:41 eivind Exp $"

#include "opt_devfs.h"
#include "opt_dpt.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/kernel.h>

#include <scsi/scsiconf.h>

#include <pci/pcireg.h>
#include <pci/pcivar.h>

#include <sys/dpt.h>
#include <pci/dpt_pci.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#define PCI_BASEADR0  PCI_MAP_REG_START  /* I/O Address */
#define PCI_BASEADR1  PCI_MAP_REG_START + 4  /* Mem I/O Address */

#define ISA_PRIMARY_WD_ADDRESS    0x1f8

/* Global variables */

int dpt_controllers_present = 0;

/* Function Prototypes */

static char    *dpt_pci_probe(pcici_t tag, pcidi_t type);
static void     dpt_pci_attach(pcici_t config_id, int unit);
static int      dpt_pci_shutdown(int foo, int bar);

extern struct cdevsw dpt_cdevsw;

static  struct pci_device dpt_pci_driver =
{
    "dpt",
    dpt_pci_probe,
    dpt_pci_attach,
    &dpt_unit,
    dpt_pci_shutdown
};

DATA_SET(pcidevice_set, dpt_pci_driver);

/*
 * Probe the PCI device.
 * Some of this work will have to be duplicated in _attach
 * because we do not know for sure how the two relate.
 */

static char *
dpt_pci_probe(pcici_t tag, pcidi_t type)
{
    static char silly_message[64];
    static int  already_announced = 0;

    u_int32_t  dpt_id;
    u_int32_t command;
    u_int32_t class;

#define pci_device  tag.cfg2.port
#define pci_bus     tag.cfg2.forward
#define pci_index   tag.cfg2.enable

#ifndef PCI_COMMAND_MASTER_ENABLE
#define PCI_COMMAND_MASTER_ENABLE 0x00000004
#endif

#ifndef PCI_SUBCLASS_MASS_STORAGE_SCSI
#define PCI_SUBCLASS_MASS_STORAGE_SCSI 0x00000000
#endif

    if ( !already_announced ) {
	printf("DPT:  PCI SCSI HBA Driver, version %d.%d.%d\n",
	       DPT_RELEASE, DPT_VERSION, DPT_PATCH);
	++already_announced;
    }

    if ((dpt_id = (type & 0xffff0000) >> 16) == DPT_DEVICE_ID) {
	/* This one appears to belong to us, but what is it? */
	class = pci_conf_read(tag, PCI_CLASS_REG);
	if (((class & PCI_CLASS_MASK) == PCI_CLASS_MASS_STORAGE) &&
	    ((class & PCI_SUBCLASS_MASK) == PCI_SUBCLASS_MASS_STORAGE_SCSI) ) {
	    /* It is a SCSI storage device.  How do talk to it? */
	    command = pci_conf_read(tag, PCI_COMMAND_STATUS_REG);
#ifdef DPT_ALLOW_MEMIO
	    if ( ((command & PCI_COMMAND_IO_ENABLE) == 0)
		 && ((command & PCI_COMMAND_MEM_ENABLE) == 0) )
#else
	    if ( ((command & PCI_COMMAND_IO_ENABLE) == 0) )
#endif /* DPT_ALLOW_MEMIO */
		{
		    printf("DPT:  Cannot map the controller registers :-(\n");
		    return(NULL);
		}
	} else {
	    printf("DPT:  Device is not Mass Storage, nor SCSI controller\n");
	    return(NULL);
	}

	command = pci_conf_read(tag, PCI_COMMAND_STATUS_REG);
	if ( (command & PCI_COMMAND_MASTER_ENABLE) == 0 ) {
	    printf("DPT:  Cannot be functional without BUSMASTER. :-(\n");
	    return (NULL);
	}

#ifdef DPT_DEBUG_PCI
	printf("DPT:  Controller is %s mapable\n",
	       (command & PCI_COMMAND_MEM_ENABLE)
	       ? "MEMORY"
	       : ((command & PCI_COMMAND_IO_ENABLE)
		  ? "I/O"
		  : "NOT"));
#endif
	return ("DPT Caching SCSI RAID Controller");
    } 

#if defined(DPT_DEBUG_PCI) && defined(DPT_DEBUG_WARN)
    printf("DPT:  Unknown Controller Type %x Found\n", dpt_id);
    printf("     (class = %x, command = %x\n", class, command);
#endif
    return (NULL);
}

static void
dpt_pci_attach(pcici_t config_id, int unit)
{
    int          ospl;
    int          result;
    int          ndx;

    vm_offset_t  vaddr;
    vm_offset_t  paddr;
    u_int16_t    io_base;
    u_int32_t    command;
    u_int32_t    data;
    dpt_conf_t  *config;
    dpt_softc_t *dpt;

    if (dpt_controllers_present >= DPT_MAX_ADAPTERS) {
	  printf("dpt%d: More than %d Adapters found!  Adapter rejected\n",
			 unit, DPT_MAX_ADAPTERS);
	  return;
    }

    if ((dpt = (dpt_softc_t *) malloc(sizeof(dpt_softc_t), M_DEVBUF, M_NOWAIT))
		== NULL) {
	  printf("dpt%d: Failed to allocate %d bytes for a DPT softc\n",
			 unit, sizeof(dpt_softc_t));
	  return;
    }

    /*
     * Initialize the queues.  See dpt.h for details. We do this here,
     * as we may get hit with interrupts at any moment and we want to
     * have a minimal structure in place to handle them. We also want to
     * register interrupts correctly. To do so, we need a valid dpt
     * structure. To have that, we need this  minimal setup here.
     */
    bzero(dpt, sizeof(dpt_softc_t));
    
    TAILQ_INIT(&dpt->free_ccbs);
    TAILQ_INIT(&dpt->waiting_ccbs);
    TAILQ_INIT(&dpt->submitted_ccbs);
    TAILQ_INIT(&dpt->completed_ccbs);

    if (TAILQ_EMPTY(&dpt_softc_list)) {
	  TAILQ_INIT(&dpt_softc_list);
    }

    TAILQ_INSERT_TAIL(&dpt_softc_list, dpt, links);
    dpt->queue_status       = DPT_QUEUES_NONE_ACTIVE;
    dpt->commands_processed = 0;

#ifdef DPT_MEASURE_PERFORMANCE
    /* Zero out all command counters */
    bzero((void *)&dpt->performance, sizeof(dpt_perf_t));
    for ( ndx = 0; ndx < 256; ndx ++ )
	  dpt->performance.min_command_time[ndx] = BIG_ENOUGH;
    
    dpt->performance.min_intr_time     = BIG_ENOUGH;
    dpt->performance.min_waiting_time  = BIG_ENOUGH;
    dpt->performance.min_submit_time   = BIG_ENOUGH;
    dpt->performance.min_complete_time = BIG_ENOUGH;
    dpt->performance.min_eata_tries    = BIG_ENOUGH;
    
    for (ndx = 0; ndx < 10; ndx++ ) {
	    dpt->performance.read_by_size_min_time[ndx] = BIG_ENOUGH;
	    dpt->performance.write_by_size_min_time[ndx] = BIG_ENOUGH;
    }
#endif        /* DPT_MEASURE_PERFORMANCE */

    dpt->unit = unit;
    dpt->handle_interrupts = 0;  /* 
								  * Do not set to 1 until all
								  * initialization is done 
								  */
    dpt->v_membase = NULL;
    dpt->p_membase = NULL;
    io_base = 0;
    vaddr   = 0;
    paddr   = 0;
    command = pci_conf_read(config_id, PCI_COMMAND_STATUS_REG);

#ifdef DPT_ALLOW_MEMIO
    if ( (command & PCI_COMMAND_MEM_ENABLE) == 0 ) {
#ifdef DPT_DEBUG_PCI
	  printf("dpt%d: Cannot be memory mapped\n", unit);
#endif
	force_io:
	  if ((command & PCI_COMMAND_IO_ENABLE) == 0 ) {
	    printf("dpt%d: Cannot be I/O mapped either :-(\n", unit);
	    free(dpt, M_DEVBUF);
	    return;
	  } else {
	    data = pci_conf_read(config_id, PCI_MAP_REG_START);
	    if ( pci_map_port(config_id, PCI_MAP_REG_START, &io_base) == 0 ) {
#ifdef DPT_DEBUG_ERROR
		  printf("dpt%d: Failed to map as I/O :-(\n", unit);
#endif
		  free(dpt, M_DEVBUF);
		  return;
	    } else {
		  dpt->io_base = io_base + 0x10;
#ifdef DPT_DEBUG_PCI
		  printf("dpt%d: Mapped registers to I/O space, "
				 "starting at %x\n",
				 dpt->unit, dpt->io_base);
#endif
	    }
	  }
    } else {
	  if ( pci_map_mem(config_id, PCI_MAP_REG_START + 4, &vaddr,
					   &paddr) == 0 ) {
#ifdef DPT_DEBUG_ERROR
	    printf("dpt%d: Failed to map as MEMORY.\n"
			   "  Attemting to force I/O mapping\n", unit);
#endif
	    goto force_io;
	  } else {
	    dpt->v_membase = (volatile u_int8_t *)(vaddr + 0x10);
	    dpt->p_membase = (volatile u_int8_t *)(paddr + 0x10);
#ifdef DPT_DEBUG_PCI
	    printf("dpt%d: Mapped registers to MEMORY space, "
			   "starting at %x/%x\n",
			   dpt->unit, dpt->v_membase, dpt->p_membase);
#endif
	  }
    }

#else /* !DPT_ALLOW_MEMIO */
    data = pci_conf_read(config_id, PCI_MAP_REG_START);
    if ((command & PCI_COMMAND_IO_ENABLE) == 0 ) {
	  printf("dpt%d: Registers cannot be I/O mapped :-(\n", unit);
	  free(dpt, M_DEVBUF);
	  return;
    } else {
	  if ( pci_map_port(config_id, PCI_MAP_REG_START, &io_base) == 0 ) {
#ifdef DPT_DEBUG_ERROR
	    printf("dpt%d: Failed to map registers as I/O :-(\n", unit);
#endif
	    free(dpt, M_DEVBUF);
	    return;
	  } else {
	    dpt->io_base = io_base + 0x10;
#ifdef DPT_DEBUG_PCI
	    printf("dpt%d: Mapped registers to I/O space, starting at %x\n",
			   dpt->unit, dpt->io_base);
#endif
	  }
    }
#endif /* !DPT_ALLOW_MEMIO */
  
    if (pci_map_int(config_id, dpt_intr, (void *)dpt, &cam_imask) == 0) {
#ifdef DPT_DEBUG_WARN
	  printf("dpt%d: Failed to map interrupt :-(\n", unit);
#endif
	  free(dpt, M_DEVBUF);
	  return;
    }

    /* If the DPT is mapped as an IDE controller, let it be IDE controller */
    if (io_base == (ISA_PRIMARY_WD_ADDRESS)) {
#ifdef DPT_DEBUG_WARN
	  printf("dpt%d: Mapped as an IDE controller.  "
			 "Disabling SCSI setup\n", unit);
#endif
	  free(dpt, M_DEVBUF);
	  return;
    } else {
	  if ((config = dpt_get_conf(dpt, 0xc1, 7,
								 sizeof(dpt_conf_t), 1)) == NULL) {
#ifdef DPT_DEBUG_ERROR
	    printf("dpt%d: Failed to get board configuration (%x)\n",
			   unit, BaseRegister(dpt));
#endif
	    free(dpt, M_DEVBUF);
	    return;
	  }
    }

    dpt->max_id      = config->MAX_ID;
    dpt->max_lun     = config->MAX_LUN;
    dpt->irq         = config->IRQ;
    dpt->channels    = config->MAX_CHAN;
    dpt->dma_channel = (8 - config->DMA_channel) & 7;

#ifdef DPT_DEBUG_SETUP
    printf("dpt%d: max_id = %d, max_chan = %d, max_lun = %d\n",
		   dpt->unit, dpt->max_id, dpt->channels, dpt->max_lun);
#endif

    if (result = dpt_setup(dpt, config)) {
	  free(config, M_TEMP);
	  free(dpt, M_DEVBUF);
	  printf("dpt%d: dpt_setup failed (%d).  Driver Disabled :-(\n",
			 dpt->unit, result);
    } else {
	  /* clean up the informational data, and display */
	  char clean_vendor[9];
	  char clean_model[17];
	  char clean_firmware[5];
	  char clean_protocol[5];
	  char clean_other[7];

	  int     ndx;

	  strncpy(clean_other, dpt->board_data.otherData, 8);
	  clean_other[6] = '\0';
	  for (ndx = 5; ndx >= 0; ndx--) {
	    if (clean_other[ndx] == ' ')
		  clean_other[ndx] = '\0';
	    else
		  break;
	  }
	  strncpy(dpt->board_data.otherData, clean_other, 6);

	  strncpy(clean_vendor, dpt->board_data.vendor, 8);
	  clean_vendor[8] = '\0';
	  for (ndx = 7; ndx >= 0; ndx--) {
	    if (clean_vendor[ndx] == ' ')
		  clean_vendor[ndx] = '\0';
	    else
		  break;
	  }
	  strncpy(dpt->board_data.vendor, clean_vendor, 8);

	  strncpy(clean_model, dpt->board_data.modelNum, 16);
	  clean_model[16] = '\0';
	  for (ndx = 15; ndx >= 0; ndx--) {
	    if (clean_model[ndx] == ' ')
		  clean_model[ndx] = '\0';
	    else
		  break;
	  }
	  strncpy(dpt->board_data.modelNum, clean_model, 16);

	  strncpy(clean_firmware, dpt->board_data.firmware, 4);
	  clean_firmware[4] = '\0';
	  for (ndx = 3; ndx >= 0; ndx--) {
	    if (clean_firmware[ndx] == ' ')
		  clean_firmware[ndx] = '\0';
	    else
		  break;
	  }
	  strncpy(dpt->board_data.firmware, clean_firmware, 4);

	  strncpy(clean_protocol, dpt->board_data.protocol, 4);
	  clean_protocol[4] = '\0';
	  for (ndx = 3; ndx >= 0; ndx--) {
	    if (clean_protocol[ndx] == ' ')
		  clean_protocol[ndx] = '\0';
	    else
		  break;
	  }
	  strncpy(dpt->board_data.protocol, clean_protocol, 4);

	  dpt_detect_cache(dpt);

	  printf("dpt%d: %s type %x, model %s firmware %s, Protocol %s \n"
			 "      on port %x with %s cache.  LED = %s\n",
			 dpt->unit, clean_vendor, dpt->board_data.deviceType,
			 clean_model, clean_firmware, clean_protocol, dpt->io_base,
			 (dpt->cache_type == DPT_NO_CACHE)
			 ? "Disabled"
			 : (dpt->cache_type == DPT_CACHE_WRITETHROUGH)
			 ? "Write-Through"
			 : "Write-Back",
			 i2bin(dpt_blinking_led(dpt), 8));
	  printf("dpt%d: Enabled Options:\n", dpt->unit);
#ifdef DPT_LOST_IRQ
	  printf("      Recover Lost Interrupts\n");
#endif
#ifdef DPT_VERIFY_HINTR
	  printf("      Verify Lost Transactions\n");
#endif
#ifdef DPT_RESTRICTED_FREELIST
	  printf("      Restrict the Freelist Size\n");
#endif
#ifdef DPT_MEASURE_PERFORMANCE
	  printf("      Collect Metrics\n");
#endif
#ifdef DPT_FREELIST_IS_STACK
	  printf("      Optimize CPU Cache\n");
#endif
#ifdef DPT_HANDLE_TIMEOUTS
	  printf("      Handle Timeouts\n");
#endif
#ifdef DPT_ALLOW_MEMIO
	  printf("      Allow I/O to be Memeory Mapped\n");
#endif
#ifdef DPT_HINTR_CHECK_SOFTC
	  printf("      Validate SoftC at Interrupt\n");
#endif

	  /* register shutdown handlers */
	  result = at_shutdown((bootlist_fn)dpt_shutdown, (void *)dpt,
						   SHUTDOWN_POST_SYNC);
	  switch ( result ) {
	  case 0:
#ifdef DPT_DEBUG_SHUTDOWN
		printf("dpt%d: Shutdown handler registered\n", dpt->unit);
#endif
		break;
	  default:
#ifdef DPT_DEBUG_WARN
		printf("dpt%d: Failed to register shutdown handler (%d)\n",
			   dpt->unit, result);
#endif
		break;
	  }

	  /* Attach SCSI devices */
	  dpt_attach(dpt);
	  ++dpt_controllers_present;

	  /*
	   * Now we create the DEVFS entry.
	   * This would be normally done from dpt_control.c,
	   * But since it appears to be called before we do here,
	   * We never get the entries made.
       */
#ifdef DEVFS
	  dpt->devfs_data_token = devfs_add_devswf(&dpt_cdevsw, dpt->unit, DV_CHR,
											   UID_ROOT, GID_WHEEL, 0600,
											   "dpt%d", dpt->unit);
	  dpt->devfs_ctl_token = devfs_add_devswf(&dpt_cdevsw,
											  dpt->unit | SCSI_CONTROL_MASK,
											  DV_CHR,
											  UID_ROOT, GID_WHEEL, 0600,
											  "dpt%d.ctl", dpt->unit);
#endif
    }
}

static int
dpt_pci_shutdown(int foo, int bar)
{
#ifdef DPT_DEBUG_WARN
    printf("dpt_pci_shutdown(%x, %x)\n", foo, bar);
#endif
    return (0);
}

/* End of the DPT PCI part of the driver */

/*
 * Hello emacs, these are the
 * Local Variables:
 *  c-indent-level:               8
 *  c-continued-statement-offset: 8
 *  c-continued-brace-offset:     0
 *  c-brace-offset:              -8
 *  c-brace-imaginary-offset:     0
 *  c-argdecl-indent:             8
 *  c-label-offset:              -8
 *  c++-hanging-braces:           1
 *  c++-access-specifier-offset: -8
 *  c++-empty-arglist-indent:     8
 *  c++-friend-offset:            0
 * End:
 */
