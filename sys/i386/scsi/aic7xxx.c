/*
 * Generic driver for the aic7xxx based adaptec SCSI controllers
 * Product specific probe and attach routines can be found in:
 * i386/eisa/aic7770.c	27/284X and aic7770 motherboard controllers
 * pci/aic7870.c	3940, 2940, aic7880, aic7870, aic7860,
 *			and aic7850 controllers
 *
 * Copyright (c) 1994, 1995, 1996, 1997 Justin T. Gibbs.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
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
 *      $Id: aic7xxx.c,v 1.115 1997/04/10 19:14:58 gibbs Exp $
 */
/*
 * TODO:
 *	Implement Target Mode
 *
 * A few notes on features of the driver.
 *
 * SCB paging takes advantage of the fact that devices stay disconnected
 * from the bus a relatively long time and that while they're disconnected,
 * having the SCBs for these transactions down on the host adapter is of
 * little use.  Instead of leaving this idle SCB down on the card we copy
 * it back up into kernel memory and reuse the SCB slot on the card to
 * schedule another transaction.  This can be a real payoff when doing random
 * I/O to tagged queueing devices since there are more transactions active at
 * once for the device to sort for optimal seek reduction. The algorithm goes
 * like this...
 *
 * The sequencer maintains two lists of its hardware SCBs.  The first is the
 * singly linked free list which tracks all SCBs that are not currently in
 * use.  The second is the doubly linked disconnected list which holds the
 * SCBs of transactions that are in the disconnected state sorted most
 * recently disconnected first.  When the kernel queues a transaction to
 * the card, a hardware SCB to "house" this transaction is retrieved from
 * either of these two lists.  If the SCB came from the disconnected list,
 * a check is made to see if any data transfer or SCB linking (more on linking
 * in a bit) information has been changed since it was copied from the host
 * and if so, DMAs the SCB back up before it can be used.  Once a hardware
 * SCB has been obtained, the SCB is DMAed from the host.  Before any work
 * can begin on this SCB, the sequencer must ensure that either the SCB is
 * for a tagged transaction or the target is not already working on another
 * non-tagged transaction.  If a conflict arises in the non-tagged case, the
 * sequencer finds the SCB for the active transactions and sets the SCB_LINKED
 * field in that SCB to this next SCB to execute.  To facilitate finding
 * active non-tagged SCBs, the last four bytes of up to the first four hardware
 * SCBs serve as a storage area for the currently active SCB ID for each
 * target.
 *
 * When a device reconnects, a search is made of the hardware SCBs to find
 * the SCB for this transaction.  If the search fails, a hardware SCB is
 * pulled from either the free or disconnected SCB list and the proper
 * SCB is DMAed from the host.  If the SCB_ABORTED control bit is set
 * in the control byte of the SCB while it was disconnected, the sequencer
 * will send an abort or abort tag message to the target during the
 * reconnection and signal the kernel that the abort was successfull.
 *
 * When a command completes, a check for non-zero status and residuals is
 * made.  If either of these conditions exists, the SCB is DMAed back up to
 * the host so that it can interpret this information.  Additionally, in the
 * case of bad status, the sequencer generates a special interrupt and pauses
 * itself.  This allows the host to setup a request sense command if it 
 * chooses for this target synchronously with the error so that sense
 * information isn't lost.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#if defined(__NetBSD__)
#include <sys/device.h>
#include <machine/bus.h>
#include <machine/intr.h>
#endif /* defined(__NetBSD__) */

#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/proc.h>

#include <scsi/scsi_all.h>
#include <scsi/scsi_message.h>
#if defined(__NetBSD__)
#include <scsi/scsi_debug.h>
#endif
#include <scsi/scsiconf.h>
#include <scsi/scsi_debug.h>

#if defined(__FreeBSD__)
#include <machine/clock.h>
#endif

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#if defined(__FreeBSD__)
#include <i386/scsi/aic7xxx.h>
#include <dev/aic7xxx/sequencer.h>
#include <aic7xxx_reg.h>
#include <aic7xxx_seq.h>
#endif /* defined(__FreeBSD__) */

#if defined(__NetBSD__)
#include <dev/ic/aic7xxxreg.h>
#include <dev/ic/aic7xxxvar.h>

#define bootverbose	1

#if DEBUGTARGET < 0	/* Negative numbers for disabling cause warnings */
#define DEBUGTARGET	17
#endif
#endif /* defined(__NetBSD__) */

#include <sys/kernel.h>

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define ALL_TARGETS -1
#define ALL_LUNS -1
#define ALL_CHANNELS '\0'

#if defined(__FreeBSD__)
u_long ahc_unit = 0;
#endif

#ifdef AHC_DEBUG
static int     ahc_debug = AHC_DEBUG;
#endif

#ifdef AHC_BROKEN_CACHE
int ahc_broken_cache = 1;

/*
 * "wbinvd" cause writing back whole cache (both CPU internal & external)
 * to memory, so that the instruction takes a lot of time.
 * This makes machine slow.
 */
#define	INVALIDATE_CACHE()	__asm __volatile("wbinvd")
#endif

/**** bit definitions for SCSIDEF ****/
#define	HSCSIID		0x07		/* our SCSI ID */
#define HWSCSIID	0x0f		/* our SCSI ID if Wide Bus */

static void	ahcminphys __P((struct buf *bp));
static int32_t	ahc_scsi_cmd __P((struct scsi_xfer *xs));
static void	ahc_run_waiting_queue __P((struct ahc_softc *ahc));
static struct scb *
                ahc_get_scb __P((struct ahc_softc *ahc, u_int32_t flags));
static void     ahc_free_scb __P((struct ahc_softc *ahc, struct scb *scb));
static struct scb *
		ahc_alloc_scb __P((struct ahc_softc *ahc));
static inline void pause_sequencer __P((struct ahc_softc *ahc));
static inline void unpause_sequencer __P((struct ahc_softc *ahc,
					  int unpause_always));
static inline void restart_sequencer __P((struct ahc_softc *ahc));

static int	timeouts_work;		/*
					 * Boolean that lets the driver know
					 * that it can safely use timeouts
					 * for event scheduling.  Timeouts
					 * don't work early in the boot
					 * process.
					 */

#define AHC_BUSRESET_DELAY	1000	/* Reset delay in us */
#define AHC_BUSSETTLE_DELAY (100 * 1000)/* Delay before taking commands
					 * after a reset in us
					 */

static struct scsi_adapter ahc_switch =
{
	ahc_scsi_cmd,
	ahcminphys,
	NULL,
	NULL,
#if defined(__FreeBSD__)
	NULL,
	"ahc",
	{ 0, 0 }
#endif
};

static struct scsi_device ahc_dev =
{
	NULL,			/* Use default error handler */
	NULL,			/* have a queue, served by this */
	NULL,			/* have no async handler */
	NULL,			/* Use default 'done' routine */
#if defined(__FreeBSD__)
	"ahc",
	0,
	{ 0, 0 }
#endif
};

static inline void
pause_sequencer(ahc)
	struct ahc_softc *ahc;
{
	ahc_outb(ahc, HCNTRL, ahc->pause);

	/*
	 * Since the sequencer can disable pausing in a critical section, we
	 * must loop until it actually stops.
	 */
	while ((ahc_inb(ahc, HCNTRL) & PAUSE) == 0)
		;
}

static inline void
unpause_sequencer(ahc, unpause_always)
	struct ahc_softc *ahc;
	int unpause_always;
{
	if (unpause_always
	 || (ahc_inb(ahc, INTSTAT) & (SCSIINT | SEQINT | BRKADRINT)) == 0)
		ahc_outb(ahc, HCNTRL, ahc->unpause);
}

/*
 * Restart the sequencer program from address zero
 */
static inline void
restart_sequencer(ahc)
	struct ahc_softc *ahc;
{
	do {
		ahc_outb(ahc, SEQCTL, SEQRESET|FASTMODE);
	} while ((ahc_inb(ahc, SEQADDR0) != 0)
	      || (ahc_inb(ahc, SEQADDR1) != 0));

	unpause_sequencer(ahc, /*unpause_always*/TRUE);
}

#if defined(__FreeBSD__)
#define	IS_SCSIBUS_B(ahc, sc_link)	\
	(((u_int32_t)((sc_link)->fordriver) & SELBUSB) != 0)
#else /* NetBSD/OpenBSD */
#define	IS_SCSIBUS_B(ahc, sc_link)	\
	((sc_link)->scsibus == (ahc)->sc_link_b.scsibus)
#endif

#define SCB_TARGET(scb) \
	(((scb)->hscb->tcl & TID) >> 4)
#define SCB_LUN(scb)    \
	((scb)->hscb->tcl & LID)
#define SCB_IS_SCSIBUS_B(scb)   \
	(((scb)->hscb->tcl & SELBUSB) != 0)

static u_int8_t	ahc_abort_wscb __P((struct ahc_softc *ahc, struct scb *scbp,
				    u_int8_t scbpos, u_int8_t prev,
				    u_int32_t xs_error));
static void	ahc_done __P((struct ahc_softc *ahc, struct scb *scbp));
static void 	ahc_handle_seqint __P((struct ahc_softc *ahc, u_int8_t intstat));
static void	ahc_handle_scsiint __P((struct ahc_softc *ahc,
					u_int8_t intstat));
static void	ahc_handle_devreset __P((struct ahc_softc *ahc,
					 struct scb *scb));
static void	ahc_loadseq __P((struct ahc_softc *ahc));
static struct patch *
		ahc_next_patch __P((struct patch *cur_patch, int options,
				    int instrptr));
static void	ahc_download_instr __P((struct ahc_softc *ahc, int options,
					int instrptr));
static int	ahc_match_scb __P((struct scb *scb, int target, char channel,
				   int lun, u_int8_t tag));
static int	ahc_poll __P((struct ahc_softc *ahc, int wait));
#ifdef AHC_DEBUG
static void	ahc_print_scb __P((struct scb *scb));
#endif
static u_int8_t ahc_find_scb __P((struct ahc_softc *ahc, struct scb *scb));
static int	ahc_search_qinfifo __P((struct ahc_softc *ahc, int target,
					char channel, int lun, u_int8_t tag,
					u_int32_t flags, u_int32_t xs_error,
					int requeue));
static int	ahc_reset_channel __P((struct ahc_softc *ahc, char channel,
				       u_int32_t xs_error, int initiate_reset));
static int	ahc_reset_device __P((struct ahc_softc *ahc, int target,
				      char channel, int lun, u_int8_t tag,
				      u_int32_t xs_error));
static u_int8_t	ahc_rem_scb_from_disc_list __P((struct ahc_softc *ahc,
						u_int8_t scbptr));
static void	ahc_add_curscb_to_free_list __P((struct ahc_softc *ahc));
static void	ahc_clear_intstat __P((struct ahc_softc *ahc));
static void	ahc_reset_current_bus __P((struct ahc_softc *ahc));
static void	ahc_run_done_queue __P((struct ahc_softc *ahc));
static void	ahc_untimeout_done_queue __P((struct ahc_softc *ahc));
static void	ahc_scsirate __P((struct ahc_softc* ahc, u_int8_t *scsirate,
				  u_int8_t *period, u_int8_t *offset,
				  char channel, int target));
#if defined(__FreeBSD__)
static timeout_t
		ahc_timeout;
#elif defined(__NetBSD__)
static void	ahc_timeout __P((void *));
#endif

static timeout_t
		ahc_first_timeout;

static timeout_t
		ahc_busreset_complete;

static timeout_t
		ahc_busreset_settle_complete;

static u_int8_t	ahc_index_busy_target __P((struct ahc_softc *ahc, int target,
					   char channel, int unbusy));

static void	ahc_busy_target __P((struct ahc_softc *ahc, int target,
				     char channel, u_int8_t scbid));

static void	ahc_construct_sdtr __P((struct ahc_softc *ahc, int start_byte,
					u_int8_t period, u_int8_t offset));

static void	ahc_construct_wdtr __P((struct ahc_softc *ahc, int start_byte,
					u_int8_t bus_width));

static void	ahc_calc_residual __P((struct scb *scb));

#if defined(__FreeBSD__)

char *ahc_name(ahc)
	struct ahc_softc *ahc;
{
	static char name[10];

	sprintf(name, "ahc%d", ahc->unit);
	return (name);
}

#elif defined(__NetBSD__)
struct cfdriver ahc_cd = {
	NULL, "ahc", DV_DULL
};
#endif

#ifdef  AHC_DEBUG
static void
ahc_print_scb(scb)
        struct scb *scb;
{
	struct hardware_scb *hscb = scb->hscb;

	printf("scb:%p control:0x%x tcl:0x%x cmdlen:%d cmdpointer:0x%lx\n",
		scb,
		hscb->control,
		hscb->tcl,
		hscb->cmdlen,
		hscb->cmdpointer );
	printf("        datlen:%d data:0x%lx segs:0x%x segp:0x%lx\n",
		hscb->datalen,
		hscb->data,
		hscb->SG_segment_count,
		hscb->SG_list_pointer);
	printf("	sg_addr:%lx sg_len:%ld\n",
		hscb->ahc_dma[0].addr,
		hscb->ahc_dma[0].len);
}

#endif

static struct {
        u_int8_t errno;
	char *errmesg;
} hard_error[] = {
	{ ILLHADDR,  "Illegal Host Access" },
	{ ILLSADDR,  "Illegal Sequencer Address referrenced" },
	{ ILLOPCODE, "Illegal Opcode in sequencer program" },
	{ PARERR,    "Sequencer Ram Parity Error" }
};


/*
 * Valid SCSIRATE values.  (p. 3-17)
 * Provides a mapping of tranfer periods in ns to the proper value to
 * stick in the scsiscfr reg to use that transfer rate.
 */
static struct {
	int sxfr;
	/* Rates in Ultra mode have bit 8 of sxfr set */
#define		ULTRA_SXFR 0x100
	u_int8_t period; /* Period to send to SCSI target */
	char *rate;
} ahc_syncrates[] = {
	{ 0x100, 12, "20.0"  },
	{ 0x110, 15, "16.0"  },
	{ 0x120, 18, "13.4"  },
	{ 0x000, 25, "10.0"  },
	{ 0x010, 31,  "8.0"  },
	{ 0x020, 37,  "6.67" },
	{ 0x030, 43,  "5.7"  },
	{ 0x040, 50,  "5.0"  },
	{ 0x050, 56,  "4.4"  },
	{ 0x060, 62,  "4.0"  },
	{ 0x070, 68,  "3.6"  }
};

static int ahc_num_syncrates =
	sizeof(ahc_syncrates) / sizeof(ahc_syncrates[0]);

/*
 * Allocate a controller structure for a new device and initialize it.
 */
#if defined(__FreeBSD__)
struct ahc_softc *
ahc_alloc(unit, iobase, maddr, type, flags, scb_data)
	int unit;
	u_int32_t iobase;
#elif defined(__NetBSD__)
void
ahc_construct(ahc, bc, ioh, maddr, type, flags)
	struct  ahc_softc *ahc;
	bus_chipset_tag_t bc;
	bus_io_handle_t ioh;
#endif
	vm_offset_t maddr;
	ahc_type type;
	ahc_flag flags;
	struct	scb_data *scb_data;
{
	/*
	 * find unit and check we have that many defined
	 */
#if defined(__FreeBSD__)
	struct  ahc_softc *ahc;
	size_t	alloc_size;

	/*
	 * Allocate a storage area for us
	 */
	if (scb_data == NULL)
		/*
		 * We are not sharing SCB space with another controller
		 * so allocate our own SCB data space.
		 */
		alloc_size = sizeof(struct full_ahc_softc);
	else
		alloc_size = sizeof(struct ahc_softc);
	ahc = malloc(alloc_size, M_DEVBUF, M_NOWAIT);
	if (!ahc) {
		printf("ahc%d: cannot malloc!\n", unit);
		return NULL;
	}
	bzero(ahc, alloc_size);
#endif
	if (scb_data == NULL) {
		struct full_ahc_softc* full_softc = (struct full_ahc_softc*)ahc;
		ahc->scb_data = &full_softc->scb_data_storage;
		STAILQ_INIT(&ahc->scb_data->free_scbs);
	} else
		ahc->scb_data = scb_data;
	STAILQ_INIT(&ahc->waiting_scbs);
#if defined(__FreeBSD__)
	ahc->unit = unit;
#endif
#if defined(__FreeBSD__)
	ahc->baseport = iobase;
#elif defined(__NetBSD__)
	ahc->sc_bc = bc;
	ahc->sc_ioh = ioh;
#endif
	ahc->maddr = (volatile u_int8_t *)maddr;
	ahc->type = type;
	ahc->flags = flags;
	ahc->unpause = (ahc_inb(ahc, HCNTRL) & IRQMS) | INTEN;
	ahc->pause = ahc->unpause | PAUSE;

	ahc->busreset_args.ahc = ahc;
	ahc->busreset_args.bus = 'A';
	ahc->busreset_args_b.ahc = ahc;
	ahc->busreset_args_b.bus = 'B';

#if defined(__FreeBSD__)
	return (ahc);
#endif
}

void
ahc_free(ahc)
	struct ahc_softc *ahc;
{
#if defined(__FreeBSD__)
	free(ahc, M_DEVBUF);
	return;
#endif
}

void
ahc_reset(ahc)
	struct	ahc_softc *ahc;
{
        u_int8_t hcntrl;
	int wait;

	/* Retain the IRQ type accross the chip reset */
	hcntrl = (ahc_inb(ahc, HCNTRL) & IRQMS) | INTEN;

	ahc_outb(ahc, HCNTRL, CHIPRST | PAUSE);
	/*
	 * Ensure that the reset has finished
	 */
	wait = 1000;
	while (--wait && !(ahc_inb(ahc, HCNTRL) & CHIPRSTACK))
		DELAY(1000);
	if (wait == 0) {
		printf("%s: WARNING - Failed chip reset!  "
		       "Trying to initialize anyway.\n", ahc_name(ahc));
	}
	ahc_outb(ahc, HCNTRL, hcntrl | PAUSE);
}

/*
 * Look up the valid period to SCSIRATE conversion in our table.
 */
static void
ahc_scsirate(ahc, scsirate, period, offset, channel, target )
	struct	 ahc_softc *ahc;
	u_int8_t *scsirate;
	u_int8_t *period;
	u_int8_t *offset;
	char	 channel;
	int	 target;
{
	int i;
	u_int32_t ultra_enb_addr;
	u_int8_t  sxfrctl0;
	u_int8_t  ultra_enb;

	i = ahc_num_syncrates; /* Default to async */
	
	if (*period >= ahc_syncrates[0].period && *offset != 0) {
		for (i = 0; i < ahc_num_syncrates; i++) {

			if (*period <= ahc_syncrates[i].period) {
				/*
				 * Watch out for Ultra speeds when ultra is not
				 * enabled and vice-versa.
				 */
				if (!(ahc->type & AHC_ULTRA) 
				  && (ahc_syncrates[i].sxfr & ULTRA_SXFR)) {
					/*
					 * This should only happen if the
					 * drive is the first to negotiate
					 * and chooses a high rate.  We'll
					 * just move down the table util
					 * we hit a non ultra speed.
					 */
					continue;
				}
				*scsirate = (ahc_syncrates[i].sxfr & 0xF0)
					  | (*offset & 0x0f);
				*period = ahc_syncrates[i].period;

				if (bootverbose) {
					printf("%s: target %d synchronous at "
					       "%sMHz, offset = 0x%x\n",
					        ahc_name(ahc), target,
						ahc_syncrates[i].rate, *offset );
				}
				break;
			}
		}
	}
	if (i >= ahc_num_syncrates) {
		/* Use asynchronous transfers. */
		*scsirate = 0;
		*period = 0;
		*offset = 0;
		if (bootverbose)
			printf("%s: target %d using asynchronous transfers\n",
			       ahc_name(ahc), target );
	}
	/*
	 * Ensure Ultra mode is set properly for
	 * this target.
	 */
	ultra_enb_addr = ULTRA_ENB;
	if (channel == 'B' || target > 7)
		ultra_enb_addr++;
	ultra_enb = ahc_inb(ahc, ultra_enb_addr);	
	sxfrctl0 = ahc_inb(ahc, SXFRCTL0);
	if (*scsirate != 0 && ahc_syncrates[i].sxfr & ULTRA_SXFR) {
		ultra_enb |= 0x01 << (target & 0x07);
		sxfrctl0 |= FAST20;
	} else {
		ultra_enb &= ~(0x01 << (target & 0x07));
		sxfrctl0 &= ~FAST20;
	}
	ahc_outb(ahc, ultra_enb_addr, ultra_enb);
	ahc_outb(ahc, SXFRCTL0, sxfrctl0);
}

#if defined(__NetBSD__)
int
ahcprint(aux, name)
	void *aux;
	char *name;
{
	if (name != NULL)
		printf("%s: scsibus ", name);
	return UNCONF;
}
#endif


/*
 * Attach all the sub-devices we can find
 */
int
ahc_attach(ahc)
	struct ahc_softc *ahc;
{
	struct scsibus_data *scbus;

#ifdef AHC_BROKEN_CACHE
	if (cpu_class == CPUCLASS_386)	/* doesn't have "wbinvd" instruction */
		ahc_broken_cache = 0;
#endif
	/*
	 * fill in the prototype scsi_links.
	 */
#if defined(__FreeBSD__)
	ahc->sc_link.adapter_unit = ahc->unit;
	ahc->sc_link.adapter_targ = ahc->our_id;
	ahc->sc_link.fordriver = 0;
#elif defined(__NetBSD__)
	ahc->sc_link.adapter_target = ahc->our_id;
#endif
	ahc->sc_link.adapter_softc = ahc;
	ahc->sc_link.adapter = &ahc_switch;
	ahc->sc_link.opennings = 2;
	ahc->sc_link.device = &ahc_dev;
	ahc->sc_link.flags = DEBUGLEVEL;

	if (ahc->type & AHC_TWIN) {
		/* Configure the second scsi bus */
		ahc->sc_link_b = ahc->sc_link;
#if defined(__FreeBSD__)
		ahc->sc_link_b.adapter_targ = ahc->our_id_b;
		ahc->sc_link_b.adapter_bus = 1;
		ahc->sc_link_b.fordriver = (void *)SELBUSB;
#elif defined(__NetBSD__)
		ahc->sc_link_b.adapter_target = ahc->our_id_b;
#endif
	}


#if defined(__FreeBSD__)
	/*
	 * Prepare the scsibus_data area for the upperlevel
	 * scsi code.
	 */
	scbus = scsi_alloc_bus();
	if(!scbus) 
		return 0;
	scbus->adapter_link = (ahc->flags & AHC_CHANNEL_B_PRIMARY) ?
				&ahc->sc_link_b : &ahc->sc_link;
	if (ahc->type & AHC_WIDE)
		scbus->maxtarg = 15;
	
	/*
	 * ask the adapter what subunits are present
	 */
	if (bootverbose)
		printf("ahc%d: Probing channel %c\n", ahc->unit,
			(ahc->flags & AHC_CHANNEL_B_PRIMARY) ? 'B' : 'A');
	scsi_attachdevs(scbus);
	scbus = NULL;	/* Upper-level SCSI code owns this now */

	if (ahc->type & AHC_TWIN) {
		scbus =  scsi_alloc_bus();
		if (!scbus) 
			return 0;
		scbus->adapter_link = (ahc->flags & AHC_CHANNEL_B_PRIMARY) ? 
					&ahc->sc_link : &ahc->sc_link_b;
		if (ahc->type & AHC_WIDE)
			scbus->maxtarg = 15;
		if (bootverbose)
			printf("ahc%d: Probing Channel %c\n", ahc->unit,
			       (ahc->flags & AHC_CHANNEL_B_PRIMARY) ? 'A': 'B');
		scsi_attachdevs(scbus);
		scbus = NULL;	/* Upper-level SCSI code owns this now */
	}
#elif defined(__NetBSD__)
	/*
	 * XXX - Update MI SCSI code
	 *
	 * if(ahc->type & AHC_WIDE)
	 *	max target of both channel A and B = 15;
	 */
	
	/*
	 * ask the adapter what subunits are present
	 */
	if ((ahc->flags & AHC_CHANNEL_B_PRIMARY) == 0) {
		/* make IS_SCSIBUS_B() == false, while probing channel A */
		ahc->sc_link_b.scsibus = 0xff;

		if (ahc->type & AHC_TWIN)
			printf("%s: Probing channel A\n", ahc_name(ahc));
		config_found((void *)ahc, &ahc->sc_link, ahcprint);
		if (ahc->type & AHC_TWIN) {
			printf("%s: Probing channel B\n", ahc_name(ahc));
			config_found((void *)ahc, &ahc->sc_link_b, ahcprint);
		}
	} else {
		/*
		 * if implementation of IS_SCSIBUS_B() is changed to use
		 * ahc->sc_link.scsibus, then "ahc->sc_link.scsibus = 0xff;"
		 * is needed, here.
		 */

		/* assert(ahc->type & AHC_TWIN); */
		printf("%s: Probing channel B\n", ahc_name(ahc));
		config_found((void *)ahc, &ahc->sc_link_b, ahcprint);
		printf("%s: Probing channel A\n", ahc_name(ahc));
		config_found((void *)ahc, &ahc->sc_link, ahcprint);
	}
#endif
	return 1;
}

/*
 * Catch an interrupt from the adapter
 */
#if defined(__FreeBSD__)
void
#elif defined (__NetBSD__)
int
#endif
ahc_intr(arg)
        void *arg;
{
	struct	 ahc_softc *ahc;
	u_int8_t intstat;

	ahc = (struct ahc_softc *)arg; 
	intstat = ahc_inb(ahc, INTSTAT);
	/*
	 * Is this interrupt for me? or for
	 * someone who is sharing my interrupt?
	 */
	if (!(intstat & INT_PEND))
#if defined(__FreeBSD__)
		return;
#elif defined(__NetBSD__)
		return 0;
#endif

	if (intstat & CMDCMPLT) {
		struct	 scb *scb;
		u_int8_t scb_index;
		u_int8_t qoutcnt;
		int	 int_cleared;

		int_cleared = 0;
		while (qoutcnt = (ahc_inb(ahc, QOUTCNT) & ahc->qcntmask)) {
			for (; qoutcnt > 0; qoutcnt--) {
				scb_index = ahc_inb(ahc, QOUTFIFO);
				scb = ahc->scb_data->scbarray[scb_index];
				if (!scb || !(scb->flags & SCB_ACTIVE)) {
					printf("%s: WARNING "
					       "no command for scb %d "
					       "(cmdcmplt)\nQOUTCNT == %d\n",
						ahc_name(ahc), scb_index,
						qoutcnt);
					continue;
				}
				/*
				 * Save off the residual if there is one.
				 */
				if (scb->hscb->residual_SG_segment_count != 0)
					ahc_calc_residual(scb);
				if ((scb->flags & SCB_QUEUED_ABORT) != 0) {
					/* Have to clean up any possible
					 * entries in the waiting queue and
					 * QINFIFO.
					 */
					int target;
					char channel;
					int lun;
					u_int8_t tag;

					tag = SCB_LIST_NULL;
					target = scb->xs->sc_link->target;
					lun = scb->xs->sc_link->lun;
					channel = (scb->hscb->tcl & SELBUSB)
						  ? 'B': 'A';
					if (scb->hscb->control & TAG_ENB)
						tag = scb->hscb->tag;
					ahc_reset_device(ahc,
							 target,
							 channel,
							 lun,
							 tag,
							 scb->xs->error);
					ahc_run_done_queue(ahc);
				}
				ahc_done(ahc, scb);
			}
			ahc_outb(ahc, CLRINT, CLRCMDINT);
			int_cleared++;
		} 

		if (int_cleared == 0)
			ahc_outb(ahc, CLRINT, CLRCMDINT);
	}
	if (intstat & BRKADRINT) {
		/*
		 * We upset the sequencer :-(
		 * Lookup the error message
		 */
		int i, error, num_errors;

		error = ahc_inb(ahc, ERROR);
		num_errors =  sizeof(hard_error)/sizeof(hard_error[0]);
		for (i = 0; error != 1 && i < num_errors; i++)
			error >>= 1;
		printf("%s: brkadrint, %s at seqaddr = 0x%x\n",
		       ahc_name(ahc), hard_error[i].errmesg,
		       (ahc_inb(ahc, SEQADDR1) << 8) |
		       ahc_inb(ahc, SEQADDR0));

		ahc_reset_device(ahc, ALL_TARGETS, ALL_CHANNELS, ALL_LUNS,
				 SCB_LIST_NULL, XS_DRIVER_STUFFUP);
		ahc_run_done_queue(ahc);
	}
	if (intstat & SEQINT)
		ahc_handle_seqint(ahc, intstat);
	
	if (intstat & SCSIINT)
		ahc_handle_scsiint(ahc, intstat);

	if (ahc->waiting_scbs.stqh_first != NULL)
		ahc_run_waiting_queue(ahc);
#if defined(__NetBSD__)
	return 1;
#endif
}

static void
ahc_handle_seqint(ahc, intstat)
	struct ahc_softc *ahc;
	u_int8_t intstat;
{
	struct scb *scb;
	u_int16_t targ_mask;
	u_int8_t target;
	int scratch_offset;
	char channel;

	if ((ahc_inb(ahc, SEQ_FLAGS) & RESELECTED) != 0)
		target = ahc_inb(ahc, SELID);
	else
		target = ahc_inb(ahc, SCSIID);
	target = (target >> 4) & 0x0f;
	scratch_offset = target;
	channel = ahc_inb(ahc, SBLKCTL) & SELBUSB ? 'B': 'A';
	if (channel == 'B')
		scratch_offset += 8;
	targ_mask = (0x01 << scratch_offset);

	switch (intstat & SEQINT_MASK) {
	case NO_MATCH:
	{
		/*
		 * This could be for a normal abort request.
		 * Figure out the SCB that we were trying to find
		 * and only give an error if we didn't ask for this
		 * to happen.
		 */
		u_int8_t scb_index;
		u_int8_t busy_scbid;

		busy_scbid = ahc_index_busy_target(ahc, target, channel,
						   /*unbusy*/FALSE);
		scb_index = ahc_inb(ahc, ARG_1);

		if (scb_index == SCB_LIST_NULL)
			/* Untagged Request */
			scb_index = busy_scbid;

		if (scb_index < ahc->scb_data->numscbs) {
			scb = ahc->scb_data->scbarray[scb_index];

			if (scb->hscb->control & ABORT_SCB) {
				/*
				 * We expected this.  Let the busfree
				 * handler take care of this when we
				 * the abort is finially sent.
				 * Set IDENTIFY_SEEN so that the busfree
				 * handler knows that there is an SCB to
				 * cleanup.
				 */
				ahc_outb(ahc, SEQ_FLAGS, ahc_inb(ahc, SEQ_FLAGS)
							| IDENTIFY_SEEN);
				sc_print_addr(scb->xs->sc_link);
				printf("reconnect SCB abort successfull\n");
				break;
			}
		}

		/*
		 * We expect a busfree to occur, so don't bother to interrupt
		 * when it happens - we've already handled the error.
		 */
		ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) & ~ENBUSFREE);

		/*
		 * XXX Don't know why this happened or which transaction
		 * caused it, so we have to be pretty heavy handed.  We should
		 * probably modify the sequencer so we can issue a bus device
		 * reset instead of an abort in this case.
		 */
		ahc_reset_device(ahc, target, channel, ALL_LUNS, SCB_LIST_NULL,
				 XS_TIMEOUT);

		printf("%s:%c:%d: no active SCB for reconnecting "
		       "target - issuing ABORT\n",
		       ahc_name(ahc), channel, target);
		printf("SAVED_TCL == 0x%x\n",
		       ahc_inb(ahc, SAVED_TCL));
		break;
	}
	case NO_MATCH_BUSY:
	{
		/*
		 * XXX Leave this as a panic for the time being since
		 * it indicates a bug in the timeout code for this
		 * to happen.
		 */
		u_int8_t scb_index;
		u_int8_t busy_scbindex;

		scb_index = ahc_inb(ahc, CUR_SCBID);
		scb = ahc->scb_data->scbarray[scb_index];

		panic("%s:%c:%d: Target busy link failure.\n",
		      ahc_name(ahc), (scb->hscb->tcl & SELBUSB) ? 'B' : 'A',
		      scb->xs->sc_link->target);
	}
	case SEND_REJECT: 
	{
		u_int8_t rejbyte = ahc_inb(ahc, REJBYTE);
		printf("%s:%c:%d: Warning - unknown message received from "
		       "target (0x%x).  Rejecting\n", 
		       ahc_name(ahc), channel, target, rejbyte);
		break; 
	}
	case NO_IDENT: 
	{
		/*
		 * The reconnecting target either did not send an identify
		 * message, or did, but we didn't find and SCB to match and
		 * before it could respond to our ATN/abort, it hit a dataphase.
		 * The only safe thing to do is to blow it away with a bus
		 * reset.
		 */
		int found;

		printf("%s:%c:%d: Target did not send an IDENTIFY message. "
		       "LASTPHASE = 0x%x, SAVED_TCL == 0x%x\n",
		       ahc_name(ahc), channel, target, ahc_inb(ahc, LASTPHASE),
		       ahc_inb(ahc, SAVED_TCL));
		found = ahc_reset_channel(ahc, channel, XS_TIMEOUT,
					  /*initiate reset*/TRUE);
		printf("%s: Issued Channel %c Bus Reset. "
		       "%d SCBs aborted\n", ahc_name(ahc), channel, found);
		break;
	}
	case BAD_PHASE:
		if (ahc_inb(ahc, LASTPHASE) == P_BUSFREE) {
			printf("%s:%c:%d: Missed busfree.\n", ahc_name(ahc),
			       channel, target);
			restart_sequencer(ahc);
		} else {
			printf("%s:%c:%d: unknown scsi bus phase.  Attempting "
			       "to continue\n", ahc_name(ahc), channel, target);
		}
		break; 
	case EXTENDED_MSG:
	{
		u_int8_t message_length;
		u_int8_t message_code;
		u_int8_t scb_index;

		message_length = ahc_inb(ahc, MSGIN_EXT_LEN);
		message_code = ahc_inb(ahc, MSGIN_EXT_OPCODE);
		scb_index = ahc_inb(ahc, SCB_TAG);
		scb = ahc->scb_data->scbarray[scb_index];
		switch (message_code) {
		case MSG_EXT_SDTR:
		{
			u_int8_t period;
			u_int8_t offset;
			u_int8_t saved_offset;
			u_int8_t targ_scratch;
			u_int8_t maxoffset;
			u_int8_t rate;
			
			if (message_length != MSG_EXT_SDTR_LEN) {
				ahc_outb(ahc, RETURN_1, SEND_REJ);
				break;
			}
			period = ahc_inb(ahc, MSGIN_EXT_BYTES);
			saved_offset = ahc_inb(ahc, MSGIN_EXT_BYTES + 1);
			targ_scratch = ahc_inb(ahc, TARG_SCRATCH
					       + scratch_offset);
			if (targ_scratch & WIDEXFER)
				maxoffset = MAX_OFFSET_16BIT;
			else
				maxoffset = MAX_OFFSET_8BIT;
			offset = MIN(saved_offset, maxoffset);
			ahc_scsirate(ahc, &rate, &period, &offset,
				     channel, target);
			/* Preserve the WideXfer flag */
			targ_scratch = rate | (targ_scratch & WIDEXFER);

			/*
			 * Update both the target scratch area and the
			 * current SCSIRATE.
			 */
			ahc_outb(ahc, TARG_SCRATCH + scratch_offset,
				 targ_scratch);
			ahc_outb(ahc, SCSIRATE, targ_scratch); 

			/*
			 * See if we initiated Sync Negotiation
			 * and didn't have to fall down to async
			 * transfers.
			 */
			if ((scb->flags & SCB_MSGOUT_SDTR) != 0) {
				/* We started it */
				if (saved_offset == offset) {
					/*
					 * Don't send an SDTR back to
					 * the target
					 */
					ahc_outb(ahc, RETURN_1, 0);
				} else
					/* Went too low - force async */
					ahc_outb(ahc, RETURN_1, SEND_REJ);
			} else {
				/*
				 * Send our own SDTR in reply
				 */
				printf("Sending SDTR!!\n");
				ahc_construct_sdtr(ahc, /*start_byte*/0,
						   period, offset);
				ahc_outb(ahc, RETURN_1, SEND_MSG);
			}
			ahc->needsdtr &= ~targ_mask;
			break;
		}
		case MSG_EXT_WDTR:
		{
			u_int8_t scratch, bus_width;

			if (message_length != MSG_EXT_WDTR_LEN) {
				ahc_outb(ahc, RETURN_1, SEND_REJ);
				break;
			}

			bus_width = ahc_inb(ahc, MSGIN_EXT_BYTES);
			scratch = ahc_inb(ahc, TARG_SCRATCH + scratch_offset);

			if ((scb->flags & SCB_MSGOUT_WDTR) != 0) {
				/*
				 * Don't send a WDTR back to the
				 * target, since we asked first.
				 */
				ahc_outb(ahc, RETURN_1, 0);
				switch (bus_width){
				case BUS_8_BIT:
					scratch &= 0x7f;
					break;
				case BUS_16_BIT:
					if (bootverbose)
						printf("%s: target %d using "
						       "16Bit transfers\n",
						       ahc_name(ahc), target);
					scratch |= WIDEXFER;	
					break;
				case BUS_32_BIT:
					/*
					 * How can we do 32bit transfers
					 * on a 16bit bus?
					 */
					ahc_outb(ahc, RETURN_1, SEND_REJ);
					printf("%s: target %d requested 32Bit "
					       "transfers.  Rejecting...\n",
					       ahc_name(ahc), target);
					break;
				default:
					break;
				}
			} else {
				/*
				 * Send our own WDTR in reply
				 */
				switch (bus_width) {
				case BUS_8_BIT:
					scratch &= 0x7f;
					break;
				case BUS_32_BIT:
				case BUS_16_BIT:
					if (ahc->type & AHC_WIDE) {
						/* Negotiate 16_BITS */
						bus_width = BUS_16_BIT;
						if (bootverbose)
							printf("%s: target %d "
							       "using 16Bit "
							       "transfers\n",
							       ahc_name(ahc),
							       target);
						scratch |= WIDEXFER;	
					} else
						bus_width = BUS_8_BIT;
					break;
				default:
					break;
				}
				ahc_construct_wdtr(ahc, /*start_byte*/0,
						   bus_width);
				ahc_outb(ahc, RETURN_1, SEND_MSG);
			}
			ahc->needwdtr &= ~targ_mask;
			ahc_outb(ahc, TARG_SCRATCH + scratch_offset, scratch);
			ahc_outb(ahc, SCSIRATE, scratch); 
			break;
		}
		default:
			/* Unknown extended message.  Reject it. */
			ahc_outb(ahc, RETURN_1, SEND_REJ);
		}
		break;
	}
	case REJECT_MSG:
	{
		/*
		 * What we care about here is if we had an
		 * outstanding SDTR or WDTR message for this
		 * target.  If we did, this is a signal that
		 * the target is refusing negotiation.
		 */

		u_int8_t targ_scratch;
		u_int8_t scb_index;

		scb_index = ahc_inb(ahc, SCB_TAG);
		scb = ahc->scb_data->scbarray[scb_index];

		targ_scratch = ahc_inb(ahc, TARG_SCRATCH
				       + scratch_offset);

		if ((scb->flags & SCB_MSGOUT_WDTR) != 0) {
			/* note 8bit xfers and clear flag */
			targ_scratch &= 0x7f;
			ahc->needwdtr &= ~targ_mask;
			printf("%s:%c:%d: refuses WIDE negotiation.  Using "
			       "8bit transfers\n", ahc_name(ahc),
			       channel, target);
		} else if ((scb->flags & SCB_MSGOUT_SDTR) != 0) {
			/* note asynch xfers and clear flag */
			targ_scratch &= 0xf0;
			ahc->needsdtr &= ~targ_mask;
			printf("%s:%c:%d: refuses synchronous negotiation. "
			       "Using asynchronous transfers\n",
			       ahc_name(ahc),
			       channel, target);
		} else {
			/*
			 * Otherwise, we ignore it.
			 */
#ifdef AHC_DEBUG
			if (ahc_debug & AHC_SHOWMISC)
				printf("%s:%c:%d: Message reject -- ignored\n",
				       ahc_name(ahc), channel, target);
#endif
			break;
		}
		ahc_outb(ahc, TARG_SCRATCH + scratch_offset, targ_scratch);
		ahc_outb(ahc, SCSIRATE, targ_scratch);
		break;
	}
	case BAD_STATUS:
	{
		u_int8_t scb_index;
		struct	 scsi_xfer *xs;
		struct	 hardware_scb *hscb;

		/*
		 * The sequencer will notify us when a command
		 * has an error that would be of interest to
		 * the kernel.  This allows us to leave the sequencer
		 * running in the common case of command completes
		 * without error.  The sequencer will already have
		 * dma'd the SCB back up to us, so we can reference
		 * the in kernel copy directly.
		 */

		scb_index = ahc_inb(ahc, SCB_TAG);
		scb = ahc->scb_data->scbarray[scb_index];
		hscb = scb->hscb; 

		/*
		 * Set the default return value to 0 (don't
		 * send sense).  The sense code will change
		 * this if needed and this reduces code
		 * duplication.
		 */
		ahc_outb(ahc, RETURN_1, 0);
		if (!(scb && (scb->flags & SCB_ACTIVE))) {
			printf("%s:%c:%d: ahc_intr - referenced scb "
			       "not valid during seqint 0x%x scb(%d)\n",
			       ahc_name(ahc),
			       channel, target, intstat,
			       scb_index);
			goto clear;
		}

		xs = scb->xs;

		xs->status = hscb->status;
		switch (hscb->status){
		case SCSI_OK:
			printf("%s: Interrupted for staus of"
			       " 0???\n", ahc_name(ahc));
			break;
		case SCSI_CHECK:
#ifdef AHC_DEBUG
			if (ahc_debug & AHC_SHOWSENSE) {
				sc_print_addr(xs->sc_link);
				printf("SCB %d: requests Check Status\n",
				       scb->hscb->tag);
			}
#endif

			if ((xs->error == XS_NOERROR)
			 && !(scb->flags & SCB_SENSE)) {
				struct ahc_dma_seg *sg = scb->ahc_dma;
				struct scsi_sense *sc = &(scb->sense_cmd);

				/*
				 * Save off the residual if there is one.
				 */
				if (hscb->residual_SG_segment_count != 0)
					ahc_calc_residual(scb);

#ifdef AHC_DEBUG
				if (ahc_debug & AHC_SHOWSENSE) {
					sc_print_addr(xs->sc_link);
					printf("Sending Sense\n");
				}
#endif
#if defined(__FreeBSD__)
				sc->op_code = REQUEST_SENSE;
#elif defined(__NetBSD__)
				sc->opcode = REQUEST_SENSE;
#endif
				sc->byte2 =  xs->sc_link->lun << 5;
				sc->length = sizeof(struct scsi_sense_data);
				sc->control = 0;

				sg->addr = vtophys(&xs->sense);
				sg->len = sizeof(struct scsi_sense_data);

				hscb->control &= DISCENB;
				hscb->status = 0;
				hscb->SG_segment_count = 1;
				hscb->SG_list_pointer = vtophys(sg);
				hscb->data = sg->addr; 
				/* Maintain SCB_LINKED_NEXT */
				hscb->datalen &= 0xFF000000;
				hscb->datalen |= sg->len;
				hscb->cmdpointer = vtophys(sc);
				hscb->cmdlen = sizeof(*sc);
				scb->sg_count = hscb->SG_segment_count;
				scb->flags |= SCB_SENSE;
				/*
				 * Ensure the target is busy since this
				 * will be an untagged request.
				 */
				ahc_busy_target(ahc, target, channel, 
						hscb->tag);
				ahc_outb(ahc, RETURN_1, SEND_SENSE);

				/*
				 * Ensure we have enough time to actually
				 * retrieve the sense.
				 */
				untimeout(ahc_timeout, (caddr_t)scb);
				timeout(ahc_timeout, (caddr_t)scb, hz);
				break;
			}
			/*
			 * Clear the SCB_SENSE Flag and have
			 * the sequencer do a normal command
			 * complete with either a "DRIVER_STUFFUP"
			 * error or whatever other error condition
			 * we already had.
			 */
			scb->flags &= ~SCB_SENSE;
			if (xs->error == XS_NOERROR)
				xs->error = XS_DRIVER_STUFFUP;
			break;
		case SCSI_QUEUE_FULL:
			if (scb->hscb->control & TAG_ENB) {
				/*
				 * The upper level SCSI code in 3.0
				 * handles this properly...
				 */
				struct scsi_link *sc_link;

				sc_link = xs->sc_link;
				if (sc_link->active > 2
				 && sc_link->opennings != 0) {
					/* truncate the opennings */
					sc_link->opennings = 0;
					sc_print_addr(sc_link);
					printf("Tagged openings reduced to "
					       "%d\n", sc_link->active);
				}
				/*
				 * XXX requeue this unconditionally.
				 */
				scb->xs->retries++;
				scb->xs->error = XS_BUSY;
				break;
			}
			/* Else treat as if it is a BUSY condition */
			scb->hscb->status = SCSI_BUSY;
			/* Fall Through... */
		case SCSI_BUSY:
			xs->error = XS_BUSY;
			sc_print_addr(xs->sc_link);
			printf("Target Busy\n");
			break;
		default:
			sc_print_addr(xs->sc_link);
			printf("unexpected targ_status: %x\n", hscb->status);
			xs->error = XS_DRIVER_STUFFUP;
			break;
		}
		break;
	}
	case AWAITING_MSG:
	{
		int	 scb_index;
		u_int8_t message_offset;

		scb_index = ahc_inb(ahc, SCB_TAG);
		scb = ahc->scb_data->scbarray[scb_index];

		/*
		 * This SCB had MK_MESSAGE set in its control byte,
		 * informing the sequencer that we wanted to send a
		 * special message to this target.
		 */
		message_offset = ahc_inb(ahc, MSG_LEN);
		if (scb->flags & SCB_DEVICE_RESET) {
			ahc_outb(ahc, MSG_OUT, MSG_BUS_DEV_RESET);
			ahc_outb(ahc, MSG_LEN, 1);
			sc_print_addr(scb->xs->sc_link);
			printf("Bus Device Reset Message Sent\n");
		} else if (scb->flags & SCB_ABORT) {
			if ((scb->hscb->control & TAG_ENB) != 0)
				ahc_outb(ahc, MSG_OUT + message_offset,
					 MSG_ABORT_TAG);
			else
				ahc_outb(ahc, MSG_OUT + message_offset,
					 MSG_ABORT);
			ahc_outb(ahc, MSG_LEN, message_offset + 1);
			sc_print_addr(scb->xs->sc_link);
			printf("Abort Message Sent\n");
		} else if (scb->flags & SCB_MSGOUT_WDTR) {
			ahc_construct_wdtr(ahc, message_offset, BUS_16_BIT);
		} else if (scb->flags & SCB_MSGOUT_SDTR) {
			int sxfr;
			int i;
			u_int16_t ultraenable;
			u_int8_t target_scratch;

			/* Pull the user defined setting */
			target_scratch = ahc_inb(ahc, TARG_SCRATCH
						 + scratch_offset);
			
			sxfr = target_scratch & SXFR;
			ultraenable = ahc_inb(ahc, ULTRA_ENB)
				    | (ahc_inb(ahc, ULTRA_ENB + 1) << 8);
			
			if (ultraenable & targ_mask)
				/* Want an ultra speed in the table */
				sxfr |= 0x100;
			
			for (i = 0; i < ahc_num_syncrates; i++)
				if (sxfr == ahc_syncrates[i].sxfr)
					break;
							
			ahc_construct_sdtr(ahc, message_offset,
					   ahc_syncrates[i].period,
					   (target_scratch & WIDEXFER) ?
					   MAX_OFFSET_16BIT : MAX_OFFSET_8BIT);
		} else	
			panic("ahc_intr: AWAITING_MSG for an SCB that "
			      "does not have a waiting message");
		break;
	}
	case DATA_OVERRUN:
	{
		/*
		 * When the sequencer detects an overrun, it
		 * sets STCNT to 0x00ffffff and allows the
		 * target to complete its transfer in
		 * BITBUCKET mode.
		 */
		u_int8_t scbindex = ahc_inb(ahc, SCB_TAG);
		u_int8_t lastphase = ahc_inb(ahc, LASTPHASE);
		u_int32_t overrun;
		int i;
		scb = ahc->scb_data->scbarray[scbindex];
		overrun = ahc_inb(ahc, STCNT)
			| (ahc_inb(ahc, STCNT + 1) << 8)
			| (ahc_inb(ahc, STCNT + 2) << 16);
		overrun = 0x00ffffff - overrun;
		sc_print_addr(scb->xs->sc_link);
		printf("data overrun of %d bytes detected in %s phase."
		       "  Tag == 0x%x.  Forcing a retry.\n", overrun,
		       lastphase == P_DATAIN ? "Data-In" : "Data-Out",
		       scb->hscb->tag);
		sc_print_addr(scb->xs->sc_link);
		printf("%s seen Data Phase.  Length = %d.  NumSGs = %d.\n",
		       ahc_inb(ahc, SEQ_FLAGS) & DPHASE ? "Have" : "Haven't",
		       scb->xs->datalen, scb->sg_count);
		for (i = 0; i < scb->sg_count; i++) {
			printf("sg[%d] - Addr 0x%x : Length %d\n",
			       i,
			       scb->ahc_dma[i].addr,
			       scb->ahc_dma[i].len);
		}
		/*
		 * Set this and it will take affect when the
		 * target does a command complete.
		 */
		scb->xs->error = XS_DRIVER_STUFFUP;
		break;
	}
#if NOT_YET
	/* XXX Fill these in later */
	case MESG_BUFFER_BUSY:
		break;
	case MSGIN_PHASEMIS:
		break;
#endif
#if 0
	case SCB_TRACE_POINT:
	{
		/*
		 * Print out the bus phase
		 */
		char	 *phase;
		u_int8_t scbindex = ahc_inb(ahc, SCB_TAG);
		u_int8_t lastphase = ahc_inb(ahc, LASTPHASE);

		scb = ahc->scb_data->scbarray[scbindex];
		sc_print_addr(scb->xs->sc_link);

		switch (lastphase) {
		case P_DATAOUT:
			phase = "Data-Out";
			break;
		case P_DATAIN:
			phase = "Data-In";
			break;
		case P_COMMAND:
			phase = "Command";
			break;
		case P_MESGOUT:
			phase = "Message-Out";
			break;
		case P_STATUS:
			phase = "Status";
			break;
		case P_MESGIN:
			phase = "Message-In";
			break;
		default:
			phase = "busfree";
			break;
		}
		printf("- %s\n", phase);
		break;
	}
#endif
	case ABORT_CMDCMPLT:
		/* This interrupt serves to pause the sequencer
		 * until we can clean up the QOUTFIFO allowing us
		 * to hanle any abort SCBs that may have completed
		 * yet still have an SCB in the QINFIFO or
		 * waiting for selection queue.  By the time we get
		 * here, we should have already cleaned up the 
		 * queues, so all we need to do is unpause the sequencer.
		 */
		break;
	default:
		printf("ahc_intr: seqint, "
		       "intstat == 0x%x, scsisigi = 0x%x\n",
		       intstat, ahc_inb(ahc, SCSISIGI));
		break;
	}
	
clear:
	/*
	 * Clear the upper byte that holds SEQINT status
	 * codes and clear the SEQINT bit.
	 */
	ahc_outb(ahc, CLRINT, CLRSEQINT);

	/*
	 *  The sequencer is paused immediately on
	 *  a SEQINT, so we should restart it when
	 *  we're done.
	 */
	unpause_sequencer(ahc, /*unpause_always*/TRUE);
}

static void
ahc_handle_scsiint(ahc, intstat)
	struct ahc_softc *ahc;
	u_int8_t intstat;
{
	u_int8_t scb_index;
	u_int8_t status;
	struct scb *scb;

	scb_index = ahc_inb(ahc, SCB_TAG);
	status = ahc_inb(ahc, SSTAT1);

	if (scb_index < ahc->scb_data->numscbs) {
		scb = ahc->scb_data->scbarray[scb_index];
		if ((scb->flags & SCB_ACTIVE) == 0)
			scb = NULL;
	} else
		scb = NULL;

	if ((status & SCSIRSTI) != 0) {
		char channel;
		channel = (ahc_inb(ahc, SBLKCTL) & SELBUSB) ? 'B' : 'A';
		printf("%s: Someone reset channel %c\n",
			ahc_name(ahc), channel);
		ahc_reset_channel(ahc, 
				  channel,
				  XS_BUSY,
				  /* Initiate Reset */FALSE);
		scb = NULL;
	} else if ((status & BUSFREE) != 0 && (status & SELTO) == 0) {
		/*
		 * First look at what phase we were last in.
		 * If its message out, chances are pretty good
		 * that the busfree was in response to one of
		 * our abort requests.
		 */
		u_int8_t lastphase = ahc_inb(ahc, LASTPHASE);
		u_int8_t target = (ahc_inb(ahc, SCSIID) >> 4) & 0x0f;
		u_int8_t scbptr = ahc_inb(ahc, SCBPTR);
		u_int8_t scb_control = ahc_inb(ahc, SCB_CONTROL);
		char channel = ahc_inb(ahc, SBLKCTL) & SELBUSB ? 'B': 'A';
		int printerror = 1;

		ahc_outb(ahc, SCSISEQ, 0);
		if (lastphase != P_BUSFREE) {
			u_int8_t flags = ahc_inb(ahc, SEQ_FLAGS)
					& (IDENTIFY_SEEN|RESELECTED);

			if (flags == 0 || flags == (IDENTIFY_SEEN|RESELECTED)) {
				/*
				 * We have an SCB we have to clean up.
				 */
				/* Did we ask for this?? */
				if ((lastphase == P_MESGOUT
				  || lastphase == P_MESGIN) && scb != NULL) {
					if (scb->flags & SCB_DEVICE_RESET) {
						ahc_handle_devreset(ahc, scb);
						scb = NULL;
						printerror = 0;
					} else if (scb->flags & SCB_ABORT) {
						struct hardware_scb *hscb;
						u_int8_t tag;

						hscb = scb->hscb;
						tag = SCB_LIST_NULL;
						sc_print_addr(scb->xs->sc_link);
						printf("SCB %d - Abort "
						       "Completed.\n",
						       scbptr);
						if (hscb->control & TAG_ENB)
							tag = scb->hscb->tag;
						ahc_reset_device(ahc,
								 target,
								 channel,
								 SCB_LUN(scb),
								 tag,
								 XS_TIMEOUT);
						ahc_run_done_queue(ahc);
						scb = NULL;
						printerror = 0;
					}
				}
			}
		}
		if (printerror != 0) {
			if (scb != NULL) {
				u_int8_t tag;

				if ((scb->hscb->control & TAG_ENB) != 0)
					tag = scb->hscb->tag;
				else
					tag = SCB_LIST_NULL;
				ahc_reset_device(ahc, target, channel,
						 SCB_LUN(scb), tag, XS_TIMEOUT);
			} else {
				/*
				 * XXX can we handle this better?
				 * Reset the bus?  Send a Bus Device Reset?
				 */
				ahc_reset_device(ahc, target, channel,
						 ALL_LUNS, SCB_LIST_NULL,
						 XS_TIMEOUT);
				printf("%s: ", ahc_name(ahc));
			}
			printf("Unexpected busfree.  LASTPHASE == 0x%x\n"
			       "SEQADDR == 0x%x\n",
			       lastphase, (ahc_inb(ahc, SEQADDR1) << 8)
					| ahc_inb(ahc, SEQADDR0));
		}
		ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) & ~ENBUSFREE);
		ahc_outb(ahc, CLRSINT1, CLRBUSFREE);
		ahc_outb(ahc, CLRINT, CLRSCSIINT);
		restart_sequencer(ahc);
	} else if ((status & SELTO) != 0) {
		struct scsi_xfer *xs;
		u_int8_t scbptr;
		u_int8_t nextscb;

		scbptr = ahc_inb(ahc, WAITING_SCBH);
		ahc_outb(ahc, SCBPTR, scbptr);
		scb_index = ahc_inb(ahc, SCB_TAG);

		if (scb_index < ahc->scb_data->numscbs) {
			scb = ahc->scb_data->scbarray[scb_index];
			if ((scb->flags & SCB_ACTIVE) == 0)
				scb = NULL;
		} else
			scb = NULL;

		if (scb == NULL) {
			printf("%s: ahc_intr - referenced scb not "
			       "valid during SELTO scb(%d)\n",
			       ahc_name(ahc), scb_index);
			printf("SEQADDR = 0x%x SCSISEQ = 0x%x "
				"SSTAT0 = 0x%x SSTAT1 = 0x%x\n",
				ahc_inb(ahc, SEQADDR0)
				| (ahc_inb(ahc, SEQADDR1) << 8),
				ahc_inb(ahc, SCSISEQ), ahc_inb(ahc, SSTAT0),
				ahc_inb(ahc,SSTAT1));
		} else {
			/*
			 * XXX If we queued an abort tag, go clean up the
			 * disconnected list.
			 */
			xs = scb->xs;
			xs->error = XS_SELTIMEOUT;
			/*
			 * Clear any pending messages for the timed out
			 * target, and mark the target as free
			 */
			ahc_outb(ahc, MSG_LEN, 0);
			ahc_index_busy_target(ahc, SCB_TARGET(scb),
					      SCB_IS_SCSIBUS_B(scb) ? 'B' : 'A',
					      /*unbusy*/TRUE);

			ahc_outb(ahc, SCB_CONTROL, 0);
			/* Shift the waiting Q forward. */
			nextscb = ahc_inb(ahc, SCB_NEXT);
			ahc_outb(ahc, WAITING_SCBH, nextscb);

			ahc_add_curscb_to_free_list(ahc);
		}
		/* Stop the selection */
		ahc_outb(ahc, SCSISEQ, 0);

		ahc_outb(ahc, CLRSINT1, CLRSELTIMEO|CLRBUSFREE);

		ahc_outb(ahc, CLRINT, CLRSCSIINT);

		restart_sequencer(ahc);
	} else if (scb == NULL) {
		printf("%s: ahc_intr - referenced scb not "
		       "valid during scsiint 0x%x scb(%d)\n"
		       "SIMODE0 = 0x%x, SIMODE1 = 0x%x, SSTAT0 = 0x%x\n"
		       "SEQADDR = 0x%x\n", ahc_name(ahc),
			status, scb_index, ahc_inb(ahc, SIMODE0),
			ahc_inb(ahc, SIMODE1), ahc_inb(ahc, SSTAT0),
			(ahc_inb(ahc, SEQADDR1) << 8)
			| ahc_inb(ahc, SEQADDR0));
		ahc_outb(ahc, CLRSINT1, status);
		ahc_outb(ahc, CLRINT, CLRSCSIINT);
		unpause_sequencer(ahc, /*unpause_always*/TRUE);
		scb = NULL;
	} else if ((status & SCSIPERR) != 0) {
		/*
		 * Determine the bus phase and
		 * queue an appropriate message
		 */
		char	 *phase;
		u_int8_t mesg_out = MSG_NOOP;
		u_int8_t lastphase = ahc_inb(ahc, LASTPHASE);
		struct	 scsi_xfer *xs;

		xs = scb->xs;
		sc_print_addr(xs->sc_link);

		switch (lastphase) {
		case P_DATAOUT:
			phase = "Data-Out";
			break;
		case P_DATAIN:
			phase = "Data-In";
			mesg_out = MSG_INITIATOR_DET_ERR;
			break;
		case P_COMMAND:
			phase = "Command";
			break;
		case P_MESGOUT:
			phase = "Message-Out";
			break;
		case P_STATUS:
			phase = "Status";
			mesg_out = MSG_INITIATOR_DET_ERR;
			break;
		case P_MESGIN:
			phase = "Message-In";
			mesg_out = MSG_PARITY_ERROR;
			break;
		default:
			phase = "unknown";
			break;
		}
		printf("parity error during %s phase.\n", phase);

		/*
		 * We've set the hardware to assert ATN if we   
		 * get a parity error on "in" phases, so all we  
		 * need to do is stuff the message buffer with
		 * the appropriate message.  "In" phases have set
		 * mesg_out to something other than MSG_NOP.
		 */
		if (mesg_out != MSG_NOOP) {
			ahc_outb(ahc, MSG_OUT, mesg_out);
			ahc_outb(ahc, MSG_LEN, 1);
			scb = NULL;
		} else
			/*
			 * Should we allow the target to make
			 * this decision for us?  If we get a
			 * sense request from the drive, we will
			 * not fetch it since xs->error != XS_NOERROR.
			 * perhaps we need two error fields in the
			 * xs structure?
			 */
			xs->error = XS_DRIVER_STUFFUP;
		ahc_outb(ahc, CLRSINT1, CLRSCSIPERR);
		ahc_outb(ahc, CLRINT, CLRSCSIINT);
		unpause_sequencer(ahc, /*unpause_always*/TRUE);
	} else {
		sc_print_addr(scb->xs->sc_link);
		printf("Unknown SCSIINT. Status = 0x%x\n", status);
		ahc_outb(ahc, CLRSINT1, status);
		ahc_outb(ahc, CLRINT, CLRSCSIINT);
		unpause_sequencer(ahc, /*unpause_always*/TRUE);
		scb = NULL;
	}
	if (scb != NULL) {
		/* We want to process the command */
		ahc_done(ahc, scb);
	}
}

static void
ahc_handle_devreset(ahc, scb)
	struct ahc_softc *ahc;
	struct scb *scb;
{
	u_int16_t targ_mask;
	u_int8_t targ_scratch;
	int target = scb->xs->sc_link->target;
	int lun = scb->xs->sc_link->lun;
	int scratch_offset = target;
	char channel = (scb->hscb->tcl & SELBUSB) ? 'B': 'A';
	int found;

	if (channel == 'B')     
		scratch_offset += 8;    
	targ_mask = (0x01 << scratch_offset);
	/*
	 * Go back to async/narrow transfers and
	 * renegotiate.
	 */
	ahc->needsdtr |= ahc->needsdtr_orig & targ_mask;
	ahc->needwdtr |= ahc->needwdtr_orig & targ_mask;
	ahc->sdtrpending &= ~targ_mask;
	ahc->wdtrpending &= ~targ_mask;
	targ_scratch = ahc_inb(ahc, TARG_SCRATCH + scratch_offset);
	targ_scratch &= SXFR;
	ahc_outb(ahc, TARG_SCRATCH + scratch_offset, targ_scratch);
	sc_print_addr(scb->xs->sc_link);
	found = ahc_reset_device(ahc, target, channel, lun,
				 SCB_LIST_NULL, XS_NOERROR);
	printf("Bus Device Reset delivered. %d SCBs aborted\n", found);
	ahc_run_done_queue(ahc);
}

/*
 * We have a scb which has been processed by the
 * adaptor, now we look to see how the operation
 * went.
 */
static void
ahc_done(ahc, scb)
	struct ahc_softc *ahc;
	struct scb *scb;
{
	struct scsi_xfer *xs = scb->xs;

	SC_DEBUG(xs->sc_link, SDEV_DB2, ("ahc_done\n"));
	/*
	 * If the recovery SCB completes, we have to be
	 * out of our timeout.
	 */
	if (scb->flags & SCB_RECOVERY_SCB) {
		ahc->in_timeout = FALSE;
		sc_print_addr(scb->xs->sc_link);
		printf("no longer in timeout\n");
	}
	/*
	 * Put the results of the operation
	 * into the xfer and call whoever started it
	 */
	/* Don't override the error value. */
	if (xs->error == XS_NOERROR
	 && (scb->flags & SCB_SENSE) != 0)
		xs->error = XS_SENSE;

#if defined(__FreeBSD__)
	if ((xs->flags & SCSI_ERR_OK) && !(xs->error == XS_SENSE)) {
		/* All went correctly  OR errors expected */
		xs->error = XS_NOERROR;
	}
#elif defined(__NetBSD__)
	/*
	 * Since NetBSD doesn't have error ignoring operation mode
	 * (SCSI_ERR_OK in FreeBSD), we don't have to care this case.
	 */
#endif
	xs->flags |= ITSDONE;
#ifdef AHC_TAGENABLE
	/*
	 * This functionality will be provided by the generic SCSI layer 
	 * in FreeBSD 3.0.
	 */
	if (xs->cmd->opcode == INQUIRY && xs->error == XS_NOERROR) {
		struct scsi_inquiry_data *inq_data;
		u_int16_t mask = 0x01 << (xs->sc_link->target |
				          (scb->hscb->tcl & 0x08));
		/*
		 * Sneak a look at the results of the SCSI Inquiry
		 * command and see if we can do Tagged queing.  This
		 * should really be done by the higher level drivers.
		 */
		inq_data = (struct scsi_inquiry_data *)xs->data;
		if ((inq_data->flags & SID_CmdQue)
		 && !(ahc->tagenable & mask)) {
		        printf("%s: target %d Tagged Queuing Device\n",
				ahc_name(ahc), xs->sc_link->target);
			ahc->tagenable |= mask;
			if (ahc->scb_data->maxhscbs >= 16
			 || (ahc->flags & AHC_PAGESCBS)) {
				/* Default to 8 tags */
				xs->sc_link->opennings += 6;
			} else {
				/*
				 * Default to 4 tags on whimpy
				 * cards that don't have much SCB
				 * space and can't page.  This prevents
				 * a single device from hogging all
				 * slots.  We should really have a better
				 * way of providing fairness.
				 */
				xs->sc_link->opennings += 2;
			}
		}
	}
#endif /* AHC_TAGENABLE */
	if ((scb->flags & SCB_MSGOUT_WDTR|SCB_MSGOUT_SDTR) != 0) {
		/*
		 * Turn off the pending flags for any DTR messages
		 * regardless of whether they completed successfully 
		 * or not.  This ensures that we don't have lingering
		 * state after we abort an SCB.
		 */
		u_int16_t mask;

		mask = (0x01 << (xs->sc_link->target
			| (IS_SCSIBUS_B(ahc, xs->sc_link) ? SELBUSB : 0)));
		if (scb->flags & SCB_MSGOUT_WDTR)
			ahc->wdtrpending &= ~mask;
		if (scb->flags & SCB_MSGOUT_SDTR)
			ahc->sdtrpending &= ~mask;
	}
	untimeout(ahc_timeout, (caddr_t)scb);
	ahc_free_scb(ahc, scb);
	/*
	 * If we're polling, we rely on the ITS_DONE flag in the xs structure
	 * to know that the command has completed.  Unfortunately, scsi_done
	 * can cause the same xs to get requeued putting us in an infinite
	 * loop.  So, we defer the scsi_done call until the poll routine exits
	 * its loop.  I hate the way this works.
	 */
	if ((xs->flags & SCSI_NOMASK) == 0)
		scsi_done(xs);
}

/*
 * Start the board, ready for normal operation
 */
int
ahc_init(ahc)
	struct  ahc_softc *ahc;
{
	u_int8_t  scsi_conf, sblkctl, sxfrctl1, i;
	u_int16_t ultraenable = 0;
	int       max_targ = 15;
	/*
	 * Assume we have a board at this stage and it has been reset.
	 */

	/* Handle the SCBPAGING option */
#ifndef AHC_SCBPAGING_ENABLE
	ahc->flags &= ~AHC_PAGESCBS;
#endif

	/* Determine channel configuration and who we are on the scsi bus. */
	switch ((sblkctl = ahc_inb(ahc, SBLKCTL) & 0x0a)) {
	case 0:
		ahc->our_id = (ahc_inb(ahc, SCSICONF) & HSCSIID);
		ahc->flags &= ~AHC_CHANNEL_B_PRIMARY;
		if ((ahc->type & AHC_39X) != 0) {
			char channel = 'A';

			if ((ahc->flags & (AHC_CHNLB|AHC_CHNLC)) != 0)
				channel = ahc->flags & AHC_CHNLB ? 'B' : 'C';
			printf("Channel %c, SCSI Id=%d, ", channel,
				ahc->our_id);
		} else
			printf("Single Channel, SCSI Id=%d, ", ahc->our_id);
		ahc_outb(ahc, SEQ_FLAGS, ahc->flags & AHC_PAGESCBS);
		break;
	case 2:
		ahc->our_id = (ahc_inb(ahc, SCSICONF + 1) & HWSCSIID);
		ahc->flags &= ~AHC_CHANNEL_B_PRIMARY;
		if ((ahc->type & AHC_39X) != 0)  {
			char channel = 'A';

			if ((ahc->flags & (AHC_CHNLB|AHC_CHNLC)) != 0)
				channel = ahc->flags & AHC_CHNLB ? 'B' : 'C';
			printf("Wide Channel %c, SCSI Id=%d, ", channel,
				ahc->our_id);
		} else
			printf("Wide Channel, SCSI Id=%d, ", ahc->our_id);
		ahc->type |= AHC_WIDE;
		ahc_outb(ahc, SEQ_FLAGS, WIDE_BUS | (ahc->flags & AHC_PAGESCBS));
		break;
	case 8:
		ahc->our_id = (ahc_inb(ahc, SCSICONF) & HSCSIID);
		ahc->our_id_b = (ahc_inb(ahc, SCSICONF + 1) & HSCSIID);
		printf("Twin Channel, A SCSI Id=%d, B SCSI Id=%d, ",
			ahc->our_id, ahc->our_id_b);
		ahc->type |= AHC_TWIN;
		ahc_outb(ahc, SEQ_FLAGS, TWIN_BUS | (ahc->flags & AHC_PAGESCBS));
		break;
	default:
		printf(" Unsupported adapter type.  Ignoring\n");
		return(-1);
	}

	/* Determine the number of SCBs and initialize them */

	if (ahc->scb_data->maxhscbs == 0) {
		/* SCB 0 heads the free list */
		ahc_outb(ahc, FREE_SCBH, 0);
		for (i = 0; i < AHC_SCB_MAX; i++) {
			ahc_outb(ahc, SCBPTR, i);
			ahc_outb(ahc, SCB_CONTROL, i);
			if(ahc_inb(ahc, SCB_CONTROL) != i)
				break;
			ahc_outb(ahc, SCBPTR, 0);
			if(ahc_inb(ahc, SCB_CONTROL) != 0)
				break;
			ahc_outb(ahc, SCBPTR, i);

			/* Clear the control byte. */
			ahc_outb(ahc, SCB_CONTROL, 0);

			/* Set the next pointer */
			ahc_outb(ahc, SCB_NEXT, i+1);

			/* Make the tag number invalid */
			ahc_outb(ahc, SCB_TAG, SCB_LIST_NULL);

			/* No Busy non-tagged targets yet */
			ahc_outb(ahc, SCB_BUSYTARGETS, SCB_LIST_NULL);
			ahc_outb(ahc, SCB_BUSYTARGETS + 1, SCB_LIST_NULL);
			ahc_outb(ahc, SCB_BUSYTARGETS + 2, SCB_LIST_NULL);
			ahc_outb(ahc, SCB_BUSYTARGETS + 3, SCB_LIST_NULL);
		}

		/* Make that the last SCB terminates the free list */
		ahc_outb(ahc, SCBPTR, i-1);
		ahc_outb(ahc, SCB_NEXT, SCB_LIST_NULL);

		/* Ensure we clear the 0 SCB's control byte. */
		ahc_outb(ahc, SCBPTR, 0);
		ahc_outb(ahc, SCB_CONTROL, 0);

		ahc->scb_data->maxhscbs = i;
	}

	if ((ahc->scb_data->maxhscbs < AHC_SCB_MAX)
	 && (ahc->flags & AHC_PAGESCBS)) {
		u_int8_t max_scbid = 255;

		/* Determine the number of valid bits in the FIFOs */
		ahc_outb(ahc, QINFIFO, max_scbid);
		max_scbid = ahc_inb(ahc, QINFIFO);
		ahc->scb_data->maxscbs = MIN(AHC_SCB_MAX, max_scbid + 1);
		printf("%d/%d SCBs\n", ahc->scb_data->maxhscbs,
			ahc->scb_data->maxscbs);
	} else {
		ahc->scb_data->maxscbs = ahc->scb_data->maxhscbs;
		ahc->flags &= ~AHC_PAGESCBS;
		printf("%d SCBs\n", ahc->scb_data->maxhscbs);
	}

#ifdef AHC_DEBUG
	if (ahc_debug & AHC_SHOWMISC) {
		printf("%s: hardware scb %d bytes; kernel scb %d bytes; "
		       "ahc_dma %d bytes\n",
			ahc_name(ahc),
		        sizeof(struct hardware_scb),
			sizeof(struct scb),
			sizeof(struct ahc_dma_seg));
	}
#endif /* AHC_DEBUG */

	/* Set the SCSI Id, SXFRCTL0, SXFRCTL1, and SIMODE1, for both channels*/
	if (ahc->type & AHC_TWIN) {
		/*
		 * The device is gated to channel B after a chip reset,
		 * so set those values first
		 */
		ahc_outb(ahc, SCSIID, ahc->our_id_b);
		scsi_conf = ahc_inb(ahc, SCSICONF + 1);
		sxfrctl1 = ahc_inb(ahc, SXFRCTL1);
		ahc_outb(ahc, SXFRCTL1, (scsi_conf & (ENSPCHK|STIMESEL))
					|(sxfrctl1 & STPWEN)
					|ENSTIMER|ACTNEGEN);
		ahc_outb(ahc, SIMODE1, ENSELTIMO|ENSCSIRST|ENSCSIPERR);
		if (ahc->type & AHC_ULTRA)
			ahc_outb(ahc, SXFRCTL0, DFON|SPIOEN|FAST20);
		else
			ahc_outb(ahc, SXFRCTL0, DFON|SPIOEN);

		if (scsi_conf & RESET_SCSI) {
			/* Reset the bus */
			if (bootverbose)
				printf("%s: Resetting Channel B\n",
				       ahc_name(ahc));
			ahc_reset_current_bus(ahc);
		}

		/* Select Channel A */
		ahc_outb(ahc, SBLKCTL, 0);
	}
	ahc_outb(ahc, SCSIID, ahc->our_id);
	scsi_conf = ahc_inb(ahc, SCSICONF);
	sxfrctl1 = ahc_inb(ahc, SXFRCTL1);
	ahc_outb(ahc, SXFRCTL1, (scsi_conf & (ENSPCHK|STIMESEL))
				|(sxfrctl1 & STPWEN)
				|ENSTIMER|ACTNEGEN);
	ahc_outb(ahc, SIMODE1, ENSELTIMO|ENSCSIRST|ENSCSIPERR);
	if (ahc->type & AHC_ULTRA)
		ahc_outb(ahc, SXFRCTL0, DFON|SPIOEN|FAST20);
	else
		ahc_outb(ahc, SXFRCTL0, DFON|SPIOEN);

	if (scsi_conf & RESET_SCSI) {
		/* Reset the bus */
		if (bootverbose)
			printf("%s: Resetting Channel A\n", ahc_name(ahc));

		ahc_reset_current_bus(ahc);
	}

	/*
	 * Look at the information that board initialization or
	 * the board bios has left us.  In the lower four bits of each
	 * target's scratch space any value other than 0 indicates
	 * that we should initiate synchronous transfers.  If it's zero,
	 * the user or the BIOS has decided to disable synchronous
	 * negotiation to that target so we don't activate the needsdtr
	 * flag.
	 */
	ahc->needsdtr_orig = 0;
	ahc->needwdtr_orig = 0;

	/* Grab the disconnection disable table and invert it for our needs */
	if (ahc->flags & AHC_USEDEFAULTS) {
		printf("%s: Host Adapter Bios disabled.  Using default SCSI "
			"device parameters\n", ahc_name(ahc));
		ahc->discenable = 0xff;
	} else
		ahc->discenable = ~((ahc_inb(ahc, DISC_DSB + 1) << 8)
				   | ahc_inb(ahc, DISC_DSB));

	if (!(ahc->type & (AHC_WIDE|AHC_TWIN)))
		max_targ = 7;

	for (i = 0; i <= max_targ; i++) {
		u_int8_t target_settings;
		if (ahc->flags & AHC_USEDEFAULTS) {
			target_settings = 0; /* 10MHz/20MHz */
			ahc->needsdtr_orig |= (0x01 << i);
			ahc->needwdtr_orig |= (0x01 << i);
			if (ahc->type & AHC_ULTRA)
				ultraenable |= (0x01 << i);
		} else {
			/* Take the settings leftover in scratch RAM. */
			target_settings = ahc_inb(ahc, TARG_SCRATCH + i);

			if (target_settings & 0x0f) {
				ahc->needsdtr_orig |= (0x01 << i);
				/*Default to a asynchronous transfers(0 offset)*/
				target_settings &= 0xf0;
			}
			if (target_settings & 0x80) {
				ahc->needwdtr_orig |= (0x01 << i);
				/*
				 * We'll set the Wide flag when we
				 * are successful with Wide negotiation.
				 * Turn it off for now so we aren't
				 * confused.
				 */
				target_settings &= 0x7f;
			}
			if (ahc->type & AHC_ULTRA) {
				/*
				 * Enable Ultra for any target that
				 * has a valid ultra syncrate setting.
				 */
				u_int8_t rate = target_settings & 0x70;
				if (rate == 0x00 || rate == 0x10 ||
				    rate == 0x20 || rate == 0x40) {
					if (rate == 0x40) {
						/* Treat 10MHz specially */
						target_settings &= ~0x70;
					} else
						ultraenable |= (0x01 << i);
				}
			}
		}
		ahc_outb(ahc, TARG_SCRATCH+i,target_settings);
	}
	/*
	 * If we are not a WIDE device, forget WDTR.  This
	 * makes the driver work on some cards that don't
	 * leave these fields cleared when the BIOS is not
	 * installed.
	 */
	if ((ahc->type & AHC_WIDE) == 0)
		ahc->needwdtr_orig = 0;
	ahc->needsdtr = ahc->needsdtr_orig;
	ahc->needwdtr = ahc->needwdtr_orig;
	ahc->sdtrpending = 0;
	ahc->wdtrpending = 0;
	ahc->tagenable = 0;
	ahc->orderedtag = 0;

	ahc_outb(ahc, ULTRA_ENB, ultraenable & 0xff);
	ahc_outb(ahc, ULTRA_ENB + 1, (ultraenable >> 8) & 0xff);

#ifdef AHC_DEBUG
	/* How did we do? */
	if (ahc_debug & AHC_SHOWMISC)
		printf("NEEDSDTR == 0x%x\nNEEDWDTR == 0x%x\n"
			"DISCENABLE == 0x%x\n", ahc->needsdtr, 
			ahc->needwdtr, ahc->discenable);
#endif
	/*
	 * Set the number of available hardware SCBs
	 */
	ahc_outb(ahc, SCBCOUNT, ahc->scb_data->maxhscbs);

	/*
	 * 2's compliment of maximum tag value
	 */
	i = ahc->scb_data->maxscbs;
	ahc_outb(ahc, COMP_SCBCOUNT, -i & 0xff);

	/*
	 * Allocate enough "hardware scbs" to handle
	 * the maximum number of concurrent transactions
	 * we can have active.  We have to use contigmalloc
	 * if this array crosses a page boundary since the
	 * sequencer depends on this array being physically
	 * contiguous.
	 */
	if (ahc->scb_data->hscbs == NULL) {
		size_t array_size;
		u_int32_t hscb_physaddr;

		array_size = ahc->scb_data->maxscbs*sizeof(struct hardware_scb);
		if (array_size > PAGE_SIZE) {
			ahc->scb_data->hscbs = (struct hardware_scb *)
					contigmalloc(array_size, M_DEVBUF,
						     M_NOWAIT, 0ul, 0xffffffff,
						     PAGE_SIZE, 0x10000);
		} else {
			ahc->scb_data->hscbs = (struct hardware_scb *)
				     malloc(array_size, M_DEVBUF, M_NOWAIT);
		}
	
		if (ahc->scb_data->hscbs == NULL) {
			printf("%s: unable to allocate hardware SCB array.  "
			       "Failing attach\n");
			return (-1);
		}
		/* At least the control byte of each hscb needs to be zeroed */
		bzero(ahc->scb_data->hscbs, array_size);

		/* Tell the sequencer where it can find the hscb array. */
		hscb_physaddr = vtophys(ahc->scb_data->hscbs);
		ahc_outb(ahc, HSCB_ADDR, hscb_physaddr & 0xFF);
		ahc_outb(ahc, HSCB_ADDR + 1, (hscb_physaddr >> 8)& 0xFF);
		ahc_outb(ahc, HSCB_ADDR + 2, (hscb_physaddr >> 16)& 0xFF);
		ahc_outb(ahc, HSCB_ADDR + 3, (hscb_physaddr >> 24)& 0xFF);
	}

	/*
	 * Q-Full-Count.  Some cards have more Q space
	 * then SCBs.
	 */
	if (ahc->type & AHC_AIC7770) {
		ahc->qfullcount = 4;
		ahc->qcntmask = 0x07;
	} else if (ahc->type & AHC_AIC7850) {
		ahc->qfullcount = 8;
		ahc->qcntmask = 0x0f;
	} else if (ahc->scb_data->maxhscbs == 255) {
		/* 7870/7880 with external SRAM */
		ahc->qfullcount = 255;
		ahc->qcntmask = 0xff;
	} else {
		/* 7870/7880 */
		ahc->qfullcount = 16;
		ahc->qcntmask = 0x1f;
	}

	/*
	 * QCount mask to deal with broken aic7850s that
	 * sporadically get garbage in the upper bits of
	 * their QCount registers.
	 */
	ahc_outb(ahc, QCNTMASK, ahc->qcntmask);

	/* We don't have any waiting selections */
	ahc_outb(ahc, WAITING_SCBH, SCB_LIST_NULL);

	/* Our disconnection list is empty too */
	ahc_outb(ahc, DISCONNECTED_SCBH, SCB_LIST_NULL);

	/* Message out buffer starts empty */
	ahc_outb(ahc, MSG_LEN, 0x00);

	/*
	 * Load the Sequencer program and Enable the adapter
	 * in "fast" mode.
         */
	if (bootverbose)
		printf("%s: Downloading Sequencer Program...",
		       ahc_name(ahc));

	ahc_loadseq(ahc);

	if (bootverbose)
		printf("Done\n");

	unpause_sequencer(ahc, /*unpause_always*/TRUE);

	/* Notify us when the system can handle timeouts */
	timeout(ahc_first_timeout, NULL, 0);

	/*
	 * Note that we are going and return (to probe)
	 */
	ahc->flags |= AHC_INIT;
	return (0);
}

static void
ahcminphys(bp)
        struct buf *bp;
{
/*
 * Even though the card can transfer up to 16megs per command
 * we are limited by the number of segments in the dma segment
 * list that we can hold.  The worst case is that all pages are
 * discontinuous physically, hense the "page per segment" limit
 * enforced here.
 */
        if (bp->b_bcount > ((AHC_NSEG - 1) * PAGE_SIZE)) {
                bp->b_bcount = ((AHC_NSEG - 1) * PAGE_SIZE);
        }
#if defined(__NetBSD__)
	minphys(bp);
#endif
}

/*
 * start a scsi operation given the command and
 * the data address, target, and lun all of which
 * are stored in the scsi_xfer struct
 */
static int32_t
ahc_scsi_cmd(xs)
        struct scsi_xfer *xs;
{
	struct	  scb *scb;
	struct	  hardware_scb *hscb;
	struct	  ahc_softc *ahc;
	u_int16_t mask;
	int	  flags;
	int	  s;

	ahc = (struct ahc_softc *)xs->sc_link->adapter_softc;
	mask = (0x01 << (xs->sc_link->target
			 | (IS_SCSIBUS_B(ahc, xs->sc_link) ? SELBUSB : 0)));
	SC_DEBUG(xs->sc_link, SDEV_DB2, ("ahc_scsi_cmd\n"));
	flags = xs->flags;

	if (ahc->in_reset != 0) {
		/*
		 * If we are still in a reset, send the transaction
		 * back indicating that it was aborted due to a
		 * reset.
		 */
		if ((IS_SCSIBUS_B(ahc, xs->sc_link)
		  && (ahc->in_reset & CHANNEL_B_RESET) != 0)
		 || (!IS_SCSIBUS_B(ahc, xs->sc_link)
		  && (ahc->in_reset & CHANNEL_A_RESET) != 0)) {
			/* Ick, but I don't want it to abort this */
			xs->retries++;
		 	xs->error = XS_BUSY;
			return(COMPLETE);
		}
	}

	/*
	 * get an scb to use. If the transfer
	 * is from a buf (possibly from interrupt time)
	 * then we can't allow it to sleep
	 */
	if ((scb = ahc_get_scb(ahc, flags)) == NULL) {
		xs->error = XS_DRIVER_STUFFUP;
		return (TRY_AGAIN_LATER);
	}
	hscb = scb->hscb;
	SC_DEBUG(xs->sc_link, SDEV_DB3, ("start scb(%p)\n", scb));
	scb->xs = xs;

	/*
	 * Put all the arguments for the xfer in the scb
	 */
	if (ahc->discenable & mask) {
		hscb->control |= DISCENB;
		if (ahc->tagenable & mask)
			hscb->control |= MSG_SIMPLE_Q_TAG;
		if (ahc->orderedtag & mask) {
			/* XXX this should be handled by the upper SCSI layer */
			printf("Ordered Tag sent\n");
			hscb->control |= MSG_ORDERED_Q_TAG;
			ahc->orderedtag &= ~mask;
		}
	}

	if (flags & SCSI_RESET) {
		scb->flags |= SCB_DEVICE_RESET;
		hscb->control |= MK_MESSAGE;		
	} else if ((ahc->needwdtr & mask) && !(ahc->wdtrpending & mask)) {
		ahc->wdtrpending |= mask;
		hscb->control |= MK_MESSAGE;
		scb->flags |= SCB_MSGOUT_WDTR;
	} else if((ahc->needsdtr & mask) && !(ahc->sdtrpending & mask)) {
		ahc->sdtrpending |= mask;
		hscb->control |= MK_MESSAGE;		
		scb->flags |= SCB_MSGOUT_SDTR;
	}

#if 0
	/* Set the trace flag if this is the target we want to trace */
	if (ahc->unit == 2 && xs->sc_link->target == 3)
		hscb->control |= TRACE_SCB;
#endif

	hscb->tcl = ((xs->sc_link->target << 4) & 0xF0)
		  | (IS_SCSIBUS_B(ahc,xs->sc_link)? SELBUSB : 0)
		  | (xs->sc_link->lun & 0x07);
	hscb->cmdlen = xs->cmdlen;
	hscb->cmdpointer = vtophys(xs->cmd);
	xs->resid = 0;
	xs->status = 0;

	/* Only use S/G if non-zero length */
	if (xs->datalen) {
		int		seg;
		u_int32_t	datalen;
		vm_offset_t	vaddr;
		u_int32_t	paddr;
		u_int32_t	nextpaddr;
		struct		ahc_dma_seg *sg;
	
		seg = 0;
		datalen = xs->datalen;
		vaddr = (vm_offset_t)xs->data;
		paddr = vtophys(vaddr);
		sg = scb->ahc_dma;
		hscb->SG_list_pointer = vtophys(sg);

		while ((datalen > 0) && (seg < AHC_NSEG)) {
			/* put in the base address and length */
			sg->addr = paddr;
			sg->len = 0;

			/* do it at least once */
			nextpaddr = paddr;

			while ((datalen > 0) && (paddr == nextpaddr)) {
				u_int32_t	size;
				/*
				 * This page is contiguous (physically)
				 * with the the last, just extend the
				 * length
				 */
				/* how far to the end of the page */
				nextpaddr = (paddr & (~PAGE_MASK)) + PAGE_SIZE;

				/*
				 * Compute the maximum size
				 */
				size = nextpaddr - paddr;
				if (size > datalen)
				        size = datalen;

				sg->len += size;
				vaddr   += size;
				datalen -= size;
				if (datalen > 0)
					paddr = vtophys(vaddr);
			}
			/*
			 * next page isn't contiguous, finish the seg
			 */
			seg++;
			sg++;
		}
		hscb->SG_segment_count = seg;
		scb->sg_count = hscb->SG_segment_count;

		/* Copy the first SG into the data pointer area */
		hscb->data = scb->ahc_dma->addr;
		hscb->datalen = scb->ahc_dma->len | (SCB_LIST_NULL << 24);
		if (datalen) { 
			/* there's still data, must have run out of segs! */
			printf("%s: ahc_scsi_cmd: more than %d DMA segs\n",
				ahc_name(ahc), AHC_NSEG);
			xs->error = XS_DRIVER_STUFFUP;
			ahc_free_scb(ahc, scb);
			return (COMPLETE);
		}
#ifdef AHC_BROKEN_CACHE
		if (ahc_broken_cache)
			INVALIDATE_CACHE();
#endif
	} else {
		/*
		 * No data xfer, use non S/G values
	 	 */
		hscb->SG_segment_count = 0;
		scb->sg_count = hscb->SG_segment_count;
		hscb->SG_list_pointer = 0;
		hscb->data = 0;
		hscb->datalen = (SCB_LIST_NULL << 24);
	}

#ifdef AHC_DEBUG
	if((ahc_debug & AHC_SHOWSCBS) && (xs->sc_link->target == DEBUGTARGET))
		ahc_print_scb(scb);
#endif
	s = splbio();

	STAILQ_INSERT_TAIL(&ahc->waiting_scbs, scb, links);

	scb->flags |= SCB_ACTIVE|SCB_WAITINGQ;

	ahc_run_waiting_queue(ahc);

	if ((flags & SCSI_NOMASK) == 0) {
		timeout(ahc_timeout, (caddr_t)scb, (xs->timeout * hz) / 1000);
		splx(s);
		return (SUCCESSFULLY_QUEUED);
	}
	/*
	 * If we can't use interrupts, poll for completion
	 */
	SC_DEBUG(xs->sc_link, SDEV_DB3, ("cmd_poll\n"));
	do {
		if (ahc_poll(ahc, xs->timeout)) {
			if (!(xs->flags & SCSI_SILENT))
				printf("cmd fail\n");
			ahc_timeout(scb);
			break;
		}
	} while ((xs->flags & ITSDONE) == 0);  /* a non command complete intr */
	scsi_done(xs);
	splx(s); 
	return (COMPLETE);
}

/*
 * Look for space in the QINFIFO and queue as many SCBs in the waiting
 * queue as possible.  Assumes that it is called at splbio().
 */
static void
ahc_run_waiting_queue(ahc)
	struct	ahc_softc *ahc;
{
	struct scb *scb;

	/*
	 * On aic78X0 chips, we rely on Auto Access Pause (AAP)
	 * instead of doing an explicit pause/unpause.
	 */
	if ((ahc->type & AHC_AIC78X0) == 0)
		pause_sequencer(ahc);

	while ((scb = ahc->waiting_scbs.stqh_first) != NULL) {

		if (ahc->curqincnt >= ahc->qfullcount) {
			ahc->curqincnt = ahc_inb(ahc, QINCNT) & ahc->qcntmask;
			if (ahc->curqincnt >= ahc->qfullcount)
				/* Still no space */
				break;
		}
		STAILQ_REMOVE_HEAD(&ahc->waiting_scbs, links);
		scb->flags &= ~SCB_WAITINGQ;
		ahc_outb(ahc, QINFIFO, scb->hscb->tag);

		if ((ahc->flags & AHC_PAGESCBS) != 0)
			/*
			 * We only care about this statistic when paging
			 * since it is impossible to overflow the qinfifo
			 * in the non-paging case.
			 */
			ahc->curqincnt++;
	}
	if ((ahc->type & AHC_AIC78X0) == 0)
		unpause_sequencer(ahc, /*Unpause always*/FALSE);
}

/*
 * An scb (and hence an scb entry on the board) is put onto the
 * free list.
 */
static void
ahc_free_scb(ahc, scb)
	struct	ahc_softc *ahc;
	struct	scb *scb;
{       
	struct hardware_scb *hscb;
	int opri;

	hscb = scb->hscb;

	opri = splbio();

	/* Clean up for the next user */
	scb->flags = SCB_FREE;
	hscb->control = 0;
	hscb->status = 0;

	STAILQ_INSERT_HEAD(&ahc->scb_data->free_scbs, scb, links);
	if (scb->links.stqe_next == NULL) {
		/*
		 * If there were no SCBs available, wake anybody waiting
		 * for one to come free.
		 */
		wakeup((caddr_t)&ahc->scb_data->free_scbs);
	}
#ifdef AHC_DEBUG
	ahc->activescbs--;
#endif
	splx(opri);
}

/*
 * Get a free scb, either one already assigned to a hardware slot
 * on the adapter or one that will require an SCB to be paged out before
 * use. If there are none, see if we can allocate a new SCB.  Otherwise
 * either return an error or sleep.
 */
static struct scb *
ahc_get_scb(ahc, flags)
	struct  ahc_softc *ahc;
	u_int32_t flags;
{
	struct scb *scbp;
	int opri;

	opri = splbio();
	/*
	 * If we can and have to, sleep waiting for one to come free
	 * but only if we can't allocate a new one.
	 */
	while (1) {
		if ((scbp = ahc->scb_data->free_scbs.stqh_first)) {
			STAILQ_REMOVE_HEAD(&ahc->scb_data->free_scbs, links);
		} else if(ahc->scb_data->numscbs < ahc->scb_data->maxscbs) {
			scbp = ahc_alloc_scb(ahc);
			if (scbp == NULL)
				printf("%s: Can't malloc SCB\n", ahc_name(ahc));
		} else if ((flags & SCSI_NOSLEEP) == 0) {
			tsleep((caddr_t)&ahc->scb_data->free_scbs, PRIBIO,
				"ahcscb", 0);
			continue;
		}
		break;
	}

#ifdef AHC_DEBUG
	if (scbp) {
		ahc->activescbs++;
		if((ahc_debug & AHC_SHOWSCBCNT)
		  && (ahc->activescbs == ahc->scb_data->maxhscbs))
			printf("%s: Max SCBs active\n", ahc_name(ahc));
	}
#endif

	splx(opri);

	return (scbp);
}


static struct scb *
ahc_alloc_scb(ahc)
	struct	ahc_softc *ahc;
{
	static	struct ahc_dma_seg *next_sg_array = NULL;
	static	int sg_arrays_free = 0;
	struct	scb *newscb;

	newscb = (struct scb *) malloc(sizeof(struct scb), M_DEVBUF, M_NOWAIT);
	if (newscb != NULL) {
		bzero(newscb, sizeof(struct scb));
		if (next_sg_array == NULL) {
			size_t	alloc_size = sizeof(struct ahc_dma_seg)
					     * AHC_NSEG; 
			sg_arrays_free = PAGE_SIZE / alloc_size;
			alloc_size *= sg_arrays_free;
			if (alloc_size == 0)
				panic("%s: SG list doesn't fit in a page",
				      ahc_name(ahc));
			next_sg_array = (struct ahc_dma_seg *)
					malloc(alloc_size, M_DEVBUF, M_NOWAIT);
		}
		if (next_sg_array != NULL) {
			struct hardware_scb *hscb;

			newscb->ahc_dma = next_sg_array;
			sg_arrays_free--;
			if (sg_arrays_free == 0)
				next_sg_array = NULL;
			else
				next_sg_array = &next_sg_array[AHC_NSEG];
			hscb = &ahc->scb_data->hscbs[ahc->scb_data->numscbs];
			newscb->hscb = hscb;
			hscb->control = 0;
			hscb->status = 0;
			hscb->tag = ahc->scb_data->numscbs;
			hscb->residual_data_count[2] = 0;
			hscb->residual_data_count[1] = 0;
			hscb->residual_data_count[0] = 0;
			hscb->residual_SG_segment_count = 0;
			ahc->scb_data->numscbs++;
			/*
			 * Place in the scbarray
			 * Never is removed.
			 */
			ahc->scb_data->scbarray[hscb->tag] = newscb;
		} else {
			free(newscb, M_DEVBUF);
			newscb = NULL;
		}
	}
	return newscb;
}

static void
ahc_loadseq(ahc)
	struct ahc_softc *ahc;
{
	int options;
	struct patch *cur_patch;
	int i;
	int downloaded;

	options = 1;	/* Code for all options */
	downloaded = 0;
	if ((ahc->type & AHC_ULTRA) != 0)
		options |= ULTRA;
	if ((ahc->type & AHC_TWIN) != 0)
		options |= TWIN_CHANNEL;
	if (ahc->scb_data->maxscbs > ahc->scb_data->maxhscbs)
		options |= SCB_PAGING;

	cur_patch = patches;
	ahc_outb(ahc, SEQCTL, PERRORDIS|LOADRAM);
	ahc_outb(ahc, SEQADDR0, 0);
	ahc_outb(ahc, SEQADDR1, 0);

	for(i = 0; i < sizeof(seqprog)/4; i++) {
		cur_patch = ahc_next_patch(cur_patch, options, i);
		
		if (cur_patch && cur_patch->begin <= i && cur_patch->end > i)
			/* Skip this instruction for this configuration */
			continue;
		ahc_download_instr(ahc, options, i);
		downloaded++;
	}

	ahc_outb(ahc, SEQCTL, FASTMODE);
	ahc_outb(ahc, SEQADDR0, 0);
	ahc_outb(ahc, SEQADDR1, 0);
	if (bootverbose)
		printf("%s: %d instructions downloaded\n", ahc_name(ahc),
			downloaded);
}

static struct patch *
ahc_next_patch(cur_patch, options, instrptr)
	struct patch *cur_patch;
	int	options;
	int	instrptr;
{
	while(cur_patch != NULL) {
		if (((cur_patch->options & options) != 0
		   && cur_patch->negative == FALSE)
		 || ((cur_patch->options & options) == 0
		   && cur_patch->negative == TRUE)
		 || (instrptr >= cur_patch->end)) {
			/*
			 * Either we want to keep this section of code,
			 * or we have consumed this patch. Skip to the
			 * next patch.
			 */
			cur_patch++;
			if (cur_patch->options == 0)
				/* Out of patches */
				cur_patch =  NULL;
		} else
			/* Found an okay patch */
			break;
	}
	return (cur_patch);
}

static void
ahc_download_instr(ahc, options, instrptr)
	struct ahc_softc *ahc;
	int options;
	int instrptr;
{
	u_int8_t opcode;
	struct	 ins_format3 *instr;

	instr = (struct ins_format3 *)&seqprog[instrptr * 4];
	/* Pull the opcode */
	opcode = instr->opcode_addr >> 1;
	switch (opcode) {
	case AIC_OP_JMP:
	case AIC_OP_JC:
	case AIC_OP_JNC:
	case AIC_OP_CALL:
	case AIC_OP_JNE:
	case AIC_OP_JNZ:
	case AIC_OP_JE:
	case AIC_OP_JZ:
	{
		int address_offset;
		struct ins_format3 new_instr;
		u_int address;
		struct patch *patch;
		int i;

		address_offset = 0;
		new_instr = *instr; /* structure copy */
		address = new_instr.address;
		address |= (new_instr.opcode_addr & ADDR_HIGH_BIT) << 8;
		for (i = 0; i < sizeof(patches)/sizeof(patches[0]); i++) {
			patch = &patches[i];
			if (((patch->options & options) == 0
			   && patch->negative == FALSE)
			|| ((patch->options & options) != 0
			   && patch->negative == TRUE)) {
				if (address >= patch->end)
					address_offset +=
					    patch->end - patch->begin;
			}
		}
		address -= address_offset;
		new_instr.address = address & 0xFF;
		new_instr.opcode_addr &= ~ADDR_HIGH_BIT;
		new_instr.opcode_addr |= (address >> 8) & ADDR_HIGH_BIT;
		ahc_outsb(ahc, SEQRAM, &new_instr.immediate, 4);
		break;
	}
	case AIC_OP_OR:
	case AIC_OP_AND:
	case AIC_OP_XOR:
	case AIC_OP_ADD:
	case AIC_OP_ADC:
	case AIC_OP_ROL:
		ahc_outsb(ahc, SEQRAM, &instr->immediate, 4);
		break;
	default:
		panic("Unknown opcode encountered in seq program");
		break;
	}
}

/*
 * Function to poll for command completion when
 * interrupts are disabled (crash dumps)
 */
static int
ahc_poll(ahc, wait)
	struct	ahc_softc *ahc;
	int	wait; /* in msec */
{
	while (--wait) {
		DELAY(1000);
		if (ahc_inb(ahc, INTSTAT) & INT_PEND)
			break;
	} if (wait == 0) {
		printf("%s: board is not responding\n", ahc_name(ahc));
		return (EIO);
	}
	ahc_intr((void *)ahc);
	return (0);
}

/*
 * Handler to register that the system is capable of
 * delivering timeouts.  We register this timeout in
 * ahc_init and it should go off as soon as we're through
 * the boot process.
 */
static void
ahc_first_timeout(arg)
	void	*arg;
{
	timeouts_work = 1;
}

static void
ahc_timeout(arg)
	void	*arg;
{
	struct	 scb *scb = (struct scb *)arg;
	struct	 ahc_softc *ahc;
	int	 s, found;
	u_int8_t bus_state;
	char	 channel;

	ahc = (struct ahc_softc *)scb->xs->sc_link->adapter_softc;

	s = splbio();

	/*
	 * Ensure that the card doesn't do anything
	 * behind our back.  Also make sure that we
	 * didn't "just" miss an interrupt that would
	 * affect this timeout.
	 */
	do {
		ahc_intr(ahc);
		pause_sequencer(ahc);
	} while (ahc_inb(ahc, INTSTAT) & INT_PEND);

	if (!(scb->flags & SCB_ACTIVE)) {
		/* Previous timeout took care of me already */
		printf("Timedout SCB handled by another timeout\n");
		unpause_sequencer(ahc, /*unpause_always*/TRUE);
		splx(s);
		return;
	}

	if (ahc->in_timeout) {
		/*
		 * Some other SCB has started a recovery operation
		 * and is still working on cleaning things up.
		 */
		if ((scb->flags & SCB_RECOVERY_SCB) == 0) {
			/*
			 * This is not the SCB that started this timeout
			 * processing.  Give this scb another lifetime so
			 * that it can continue once we deal with the
			 * timeout.
			 */
			scb->flags |= SCB_TIMEDOUT;
			sc_print_addr(scb->xs->sc_link);
			printf("SCB 0x%x timedout while recovery in progress\n",
				scb->hscb->tag);
			timeout(ahc_timeout, (caddr_t)scb, 
				(scb->xs->timeout * hz) / 1000);
			unpause_sequencer(ahc, /*unpause_always*/TRUE);
			splx(s);
			return;
		}
	}
	ahc->in_timeout = TRUE;

	sc_print_addr(scb->xs->sc_link);
	printf("SCB 0x%x - timed out ", scb->hscb->tag);
	/*
	 * Take a snapshot of the bus state and print out
	 * some information so we can track down driver bugs.
	 */
	bus_state = ahc_inb(ahc, LASTPHASE);

	switch(bus_state)
	{
	case P_DATAOUT:
		printf("in dataout phase");
		break;
	case P_DATAIN:
		printf("in datain phase");
		break;
	case P_COMMAND:
		printf("in command phase");
		break;
	case P_MESGOUT:
		printf("in message out phase");
		break;
	case P_STATUS:
		printf("in status phase");
		break;
	case P_MESGIN:
		printf("in message in phase");
		break;
	case P_BUSFREE:
		printf("while idle, LASTPHASE == 0x%x",
			bus_state);
		break;
	default:
		/* 
		 * We aren't in a valid phase, so assume we're
		 * idle.
		 */
		printf("invalid phase, LASTPHASE == 0x%x",
			bus_state);
		break;
	}

	printf(", SCSISIGI == 0x%x\n", ahc_inb(ahc, SCSISIGI));

	printf("SEQADDR = 0x%x SCSISEQ = 0x%x SSTAT0 = 0x%x SSTAT1 = 0x%x\n",
		ahc_inb(ahc, SEQADDR0) | (ahc_inb(ahc, SEQADDR1) << 8),
		ahc_inb(ahc, SCSISEQ), ahc_inb(ahc, SSTAT0),
		ahc_inb(ahc,SSTAT1));
	/* Decide our course of action */

	channel = (scb->hscb->tcl & SELBUSB) ? 'B': 'A';
	if (scb->flags & SCB_ABORT) {
		/*
		 * Been down this road before.
		 * Do a full bus reset.
		 */
bus_reset:
		scb->flags |= SCB_RECOVERY_SCB;
		found = ahc_reset_channel(ahc, channel, XS_TIMEOUT,
					  /*Initiate Reset*/TRUE);
		printf("%s: Issued Channel %c Bus Reset. "
		       "%d SCBs aborted\n", ahc_name(ahc), channel, found);
	} else if ((scb->hscb->control & TAG_ENB) != 0
		&& (scb->flags & SCB_SENTORDEREDTAG) == 0) {
		/*
		 * We could be starving this command
		 * try sending an ordered tag command
		 * to the target we come from.
		 */
		u_int16_t mask;

		mask = (0x01 << (scb->xs->sc_link->target
			 	 | (IS_SCSIBUS_B(ahc, scb->xs->sc_link) ?
				    SELBUSB : 0)));
		scb->flags |= SCB_SENTORDEREDTAG|SCB_RECOVERY_SCB;
		ahc->orderedtag |= mask;
		timeout(ahc_timeout, (caddr_t)scb, (5 * hz));
		unpause_sequencer(ahc, /*unpause_always*/TRUE);
		printf("Ordered Tag queued\n");
	} else {
		/*
		 * Send an Abort Message:
		 * The target that is holding up the bus may not
		 * be the same as the one that triggered this timeout
		 * (different commands have different timeout lengths).
		 * Our strategy here is to queue an abort message
		 * to the timed out target if it is disconnected.
		 * Otherwise, if we have an active target we stuff the
		 * message buffer with an abort message and assert ATN
		 * in the hopes that the target will let go of the bus
		 * and go to the mesgout phase.  If this fails, we'll
		 * get another timeout 2 seconds later which will attempt
		 * a bus reset.
		 */
		u_int8_t saved_scbptr;
		u_int8_t active_scb_index;
		struct scb *active_scb;

		saved_scbptr = ahc_inb(ahc, SCBPTR);
		active_scb_index = ahc_inb(ahc, SCB_TAG);
		active_scb = ahc->scb_data->scbarray[active_scb_index];

		if (bus_state != P_BUSFREE) {
			if (active_scb_index >= ahc->scb_data->numscbs) {
				/* Go "immediatly" to the bus reset */
				/*
				 * XXX queue an abort for the timedout SCB
				 * instead.
				 */
				sc_print_addr(scb->xs->sc_link);
				printf("SCB %d: Yucky Immediate reset.  "
					"Flags = 0x%x\n", scb->hscb->tag,
					scb->flags);
				goto bus_reset;
			}
			/* Send the abort to the active SCB */
			ahc_outb(ahc, MSG_LEN, 1);
			ahc_outb(ahc, MSG_OUT,
				 (active_scb->hscb->control & TAG_ENB) == 0 ?
				 MSG_ABORT : MSG_ABORT_TAG);
			ahc_outb(ahc, SCSISIGO, bus_state|ATNO);
			sc_print_addr(active_scb->xs->sc_link);
			printf("abort message in message buffer\n");
			active_scb->flags |= SCB_ABORT|SCB_RECOVERY_SCB;
			if (active_scb != scb) {
				untimeout(ahc_timeout, 
					  (caddr_t)active_scb);
				/* Give scb a new lease on life */
				timeout(ahc_timeout, (caddr_t)scb, 
					(scb->xs->timeout * hz) / 1000);
			}
			timeout(ahc_timeout, (caddr_t)active_scb,
				(200 * hz) / 1000);
			unpause_sequencer(ahc, /*unpause_always*/TRUE);
		} else {
			int	 disconnected;
			u_int8_t hscb_index;
			u_int8_t linked_next;

			disconnected = FALSE;
			hscb_index = ahc_find_scb(ahc, scb);
			if (hscb_index == SCB_LIST_NULL) {
				disconnected = TRUE;
				linked_next = (scb->hscb->datalen >> 24)
					      & 0xFF000000;
			} else {
				ahc_outb(ahc, SCBPTR, hscb_index);
				if (ahc_inb(ahc, SCB_CONTROL) & DISCONNECTED)
					disconnected = TRUE;
				linked_next = ahc_inb(ahc, SCB_LINKED_NEXT);
			}

			if (disconnected) {
				/*
				 * Simply set the ABORT_SCB control bit
				 * and preserve the linked next pointer
				 */
				scb->hscb->control |= ABORT_SCB|MK_MESSAGE;
				scb->hscb->datalen &= ~0xFF000000;
				scb->hscb->datalen |= linked_next << 24;
				if ((ahc->flags & AHC_PAGESCBS) == 0)
					scb->hscb->control &= ~DISCONNECTED;
				scb->flags |= SCB_QUEUED_ABORT
					   |  SCB_ABORT|SCB_RECOVERY_SCB;
				if (hscb_index != SCB_LIST_NULL) {
					u_int8_t scb_control;

					scb_control = ahc_inb(ahc, SCB_CONTROL);
					ahc_outb(ahc, SCB_CONTROL,
						 scb_control | MK_MESSAGE
						 | ABORT_SCB);
				}
				/*
				 * Actually re-queue this SCB in case we can
				 * select the device before it reconnects.  If
				 * the transaction we want to abort is not
				 * tagged, unbusy it first so that we don't
				 * get held back from sending the command.
				 */
				if ((scb->hscb->control & TAG_ENB) == 0) {
					int target;
					int lun;

					target = scb->xs->sc_link->target;
					lun = scb->xs->sc_link->lun;
					ahc_search_qinfifo(ahc, target,
							   channel,
							   lun,
							   SCB_LIST_NULL,
							   0, 0,
							   /*requeue*/TRUE);
				}
				sc_print_addr(scb->xs->sc_link);
				printf("Queueing an Abort SCB\n");
				STAILQ_INSERT_HEAD(&ahc->waiting_scbs, scb,
						   links);
				scb->flags |= SCB_WAITINGQ;
				timeout(ahc_timeout, (caddr_t)scb,
					(200 * hz) / 1000);
				ahc_outb(ahc, SCBPTR, saved_scbptr);
				/*
				 * ahc_run_waiting_queue may unpause us
				 * so do this last.
				 */
				ahc_run_waiting_queue(ahc);
				/*
				 * If we are using AAP, ahc_run_waiting_queue
				 * will not unpause us, so ensure we are
				 * unpaused.
				 */
				unpause_sequencer(ahc, /*unpause_always*/FALSE);
			} else {
				/* Go "immediatly" to the bus reset */
				sc_print_addr(scb->xs->sc_link);
				printf("SCB %d: Immediate reset.  "
					"Flags = 0x%x\n", scb->hscb->tag,
					scb->flags);
				goto bus_reset;
			}
		}
	}
	splx(s);
}

/*
 * Look through the SCB array of the card and attempt to find the
 * hardware SCB that corresponds to the passed in SCB.  Return
 * SCB_LIST_NULL if unsuccessful.  This routine assumes that the
 * card is already paused.
 */
static u_int8_t
ahc_find_scb(ahc, scb)
	struct ahc_softc *ahc;
	struct scb *scb;
{
	u_int8_t saved_scbptr;
	u_int8_t curindex;

	saved_scbptr = ahc_inb(ahc, SCBPTR);
	for (curindex = 0; curindex < ahc->scb_data->maxhscbs; curindex++) {
		ahc_outb(ahc, SCBPTR, curindex);
		if (ahc_inb(ahc, SCB_TAG) == scb->hscb->tag)
			break;
	}
	ahc_outb(ahc, SCBPTR, saved_scbptr);
	if (curindex >= ahc->scb_data->maxhscbs)
		curindex = SCB_LIST_NULL;

	return curindex;
}

static int
ahc_search_qinfifo(ahc, target, channel, lun, tag, flags, xs_error, requeue)
	struct	  ahc_softc *ahc;
	int	  target;
	char	  channel;
	int	  lun;
	u_int8_t  tag;
	u_int32_t flags;
	u_int32_t xs_error;
	int	  requeue;
{
	u_int8_t saved_queue[AHC_SCB_MAX];
	int	 queued = ahc_inb(ahc, QINCNT) & ahc->qcntmask;
	int	 i;
	int	 found;
	struct	 scb *scbp;
	STAILQ_HEAD(, scb) removed_scbs;

	found = 0;
	STAILQ_INIT(&removed_scbs);
	for (i = 0; i < (queued - found); i++) {
		saved_queue[i] = ahc_inb(ahc, QINFIFO);
		scbp = ahc->scb_data->scbarray[saved_queue[i]];
		if (ahc_match_scb(scbp, target, channel, lun, tag)) {
			/*
			 * We found an scb that needs to be removed.
			 */
			if (requeue) {
				STAILQ_INSERT_HEAD(&removed_scbs, scbp, links);
			} else {
				scbp->flags |= flags;
				scbp->flags &= ~SCB_ACTIVE;
				scbp->xs->error = xs_error;
			}
			i--;
			found++;
		}
	}
	/* Now put the saved scbs back. */
	for (queued = 0; queued < i; queued++)
		ahc_outb(ahc, QINFIFO, saved_queue[queued]);

	if (requeue) {
		while ((scbp = removed_scbs.stqh_first) != NULL) {
			STAILQ_REMOVE_HEAD(&removed_scbs, links);
			STAILQ_INSERT_HEAD(&ahc->waiting_scbs, scbp, links);
			scbp->flags |= SCB_WAITINGQ;
		}
	}

	return found;
}


/*
 * The device at the given target/channel has been reset.  Abort 
 * all active and queued scbs for that target/channel. 
 */
static int
ahc_reset_device(ahc, target, channel, lun, tag, xs_error)
	struct	  ahc_softc *ahc;
	int	  target;
	char	  channel;
	int	  lun;
	u_int8_t  tag;
	u_int32_t xs_error;
{
	struct scb *scbp;
	u_int8_t active_scb;
	int i;
	int found;

	/* restore this when we're done */
	active_scb = ahc_inb(ahc, SCBPTR);

	/*
	 * Deal with the busy target and linked next issues.
	 */
	{
		int min_target, max_target;
		u_int8_t busy_scbid;

		/* Make all targets 'relative' to bus A */
		if (target == ALL_TARGETS) {
			switch (channel) {
			case 'A':
				min_target = 0;
				max_target = ahc->type & AHC_WIDE ? 15 : 7;
				break;
			case 'B':
				min_target = 8;
				max_target = 15;
				break;
			case ALL_CHANNELS:
				min_target = 0;
				max_target = ahc->type & AHC_WIDE|AHC_TWIN
					     ? 15 : 7;
				break;
			}
		} else {
			min_target = max_target = target
						  + channel == 'B' ? 8 : 0;
		}

		for (i = min_target; i <= max_target; i++) {
			busy_scbid = ahc_index_busy_target(ahc, i, 'A',
						           /*unbusy*/FALSE);
			if (busy_scbid < ahc->scb_data->numscbs) {
				struct scb *busy_scb;
				struct scb *next_scb;
				u_int8_t next_scbid;

				busy_scb = ahc->scb_data->scbarray[busy_scbid];
	
				next_scbid = busy_scb->hscb->datalen >> 24;

				if (next_scbid == SCB_LIST_NULL) {
					busy_scbid = ahc_find_scb(ahc,
								  busy_scb);

					if (busy_scbid != SCB_LIST_NULL) {
						ahc_outb(ahc, SCBPTR,
							 busy_scbid);
						next_scbid = ahc_inb(ahc,
							       SCB_LINKED_NEXT);
					}
				}

				if (ahc_match_scb(busy_scb, target, channel,
						  lun, tag)) {
					ahc_index_busy_target(ahc, i, 'A',
							      /*unbusy*/TRUE);
				}

				if (next_scbid != SCB_LIST_NULL) {
					next_scb = ahc->scb_data->scbarray[next_scbid];
					if (ahc_match_scb(next_scb, target,
							   channel, lun, tag))
						continue;
					/* Requeue for later processing */
					STAILQ_INSERT_HEAD(&ahc->waiting_scbs,
							   next_scb, links);
					next_scb->flags |= SCB_WAITINGQ;
				}
			}
		}
	}
	/*
	 * Remove any entries from the Queue-In FIFO.
	 */
	found = ahc_search_qinfifo(ahc, target, channel, lun, tag,
				   SCB_ABORTED|SCB_QUEUED_FOR_DONE, xs_error,
				   /*requeue*/FALSE);

	/*
	 * Search waiting for selection list.
	 */
	{
		u_int8_t next, prev;

		next = ahc_inb(ahc, WAITING_SCBH);  /* Start at head of list. */
		prev = SCB_LIST_NULL;

		while (next != SCB_LIST_NULL) {
			u_int8_t scb_index;

			ahc_outb(ahc, SCBPTR, next);
			scb_index = ahc_inb(ahc, SCB_TAG);
			if (scb_index >= ahc->scb_data->numscbs) {
				panic("Waiting List inconsistency. "
				      "SCB index == %d, yet numscbs == %d.",
				      scb_index, ahc->scb_data->numscbs);
			}
			scbp = ahc->scb_data->scbarray[scb_index];
			if (ahc_match_scb(scbp, target, channel, lun, tag)) {
				u_int8_t linked_next;

				next = ahc_abort_wscb(ahc, scbp, next, prev,
						      xs_error);
				linked_next = ahc_inb(ahc, SCB_LINKED_NEXT);
				if (linked_next != SCB_LIST_NULL) {
					struct scb *next_scb;

					/*
					 * Re-queue the waiting SCB via the
					 * waiting list.
					 */
					next_scb =
					    ahc->scb_data->scbarray[linked_next];
					if (!ahc_match_scb(next_scb, target,
							  channel, lun, tag)) {
						STAILQ_INSERT_HEAD(&ahc->waiting_scbs,
								   next_scb,
								   links);
						next_scb->flags |= SCB_WAITINGQ;
					}
				}
				found++;
			} else {
				prev = next;
				next = ahc_inb(ahc, SCB_NEXT);
			}
		}
	}
	/*
	 * Go through the disconnected list and remove any entries we
	 * have queued for completion, 0'ing their control byte too.
	 */
	{
		u_int8_t next, prev;

		next = ahc_inb(ahc, DISCONNECTED_SCBH);
		prev = SCB_LIST_NULL;

		while (next != SCB_LIST_NULL) {
			u_int8_t scb_index;

			ahc_outb(ahc, SCBPTR, next);
			scb_index = ahc_inb(ahc, SCB_TAG);
			if (scb_index >= ahc->scb_data->numscbs) {
				panic("Disconnected List inconsistency. "
				      "SCB index == %d, yet numscbs == %d.",
				      scb_index, ahc->scb_data->numscbs);
			}
			scbp = ahc->scb_data->scbarray[scb_index];
			if (ahc_match_scb(scbp, target, channel, lun, tag)) {
				next = ahc_rem_scb_from_disc_list(ahc, next);
			} else {
				prev = next;
				next = ahc_inb(ahc, SCB_NEXT);
			}
		}
	}
	/*
	 * Go through the hardware SCB array looking for commands that
	 * were active but not on any list.
	 */
	for(i = 0; i < ahc->scb_data->maxhscbs; i++) {
		u_int8_t scbid;

		ahc_outb(ahc, SCBPTR, i);
		scbid = ahc_inb(ahc, SCB_TAG);
		if (scbid < ahc->scb_data->numscbs) {
			scbp = ahc->scb_data->scbarray[scbid];
			if (ahc_match_scb(scbp, target, channel, lun, tag)) {
				ahc_add_curscb_to_free_list(ahc);
			}
		}
	}
	/*
	 * Go through the entire SCB array now and look for 
	 * commands for this target that are still active.  These
	 * are other tagged commands that were disconnected when
	 * the reset occured or untagged commands that were linked
	 * to the command that preceeded it.
	 */
	for (i = 0; i < ahc->scb_data->numscbs; i++) {
		scbp = ahc->scb_data->scbarray[i];
		if ((scbp->flags & SCB_ACTIVE) != 0
		 &&  ahc_match_scb(scbp, target, channel, lun, tag)) {
			scbp->flags |= SCB_ABORTED|SCB_QUEUED_FOR_DONE;
			scbp->flags &= ~SCB_ACTIVE;
			scbp->xs->error = xs_error;
			found++;

			if ((scbp->flags & SCB_WAITINGQ) != 0) {
				STAILQ_REMOVE(&ahc->waiting_scbs, scbp, scb,
					      links);
				scbp->flags &= ~SCB_WAITINGQ;
			}
		}
	}
	ahc_outb(ahc, SCBPTR, active_scb);
	return found;
}

static u_int8_t
ahc_rem_scb_from_disc_list(ahc, scbptr)
	struct	 ahc_softc *ahc;
	u_int8_t scbptr;
{
	u_int8_t next;
	u_int8_t prev;

	ahc_outb(ahc, SCBPTR, scbptr);
	next = ahc_inb(ahc, SCB_NEXT);
	prev = ahc_inb(ahc, SCB_PREV);

	ahc_outb(ahc, SCB_CONTROL, 0);

	ahc_add_curscb_to_free_list(ahc);

	if (prev != SCB_LIST_NULL) {
		ahc_outb(ahc, SCBPTR, prev);
		ahc_outb(ahc, SCB_NEXT, next);
	} else
		ahc_outb(ahc, DISCONNECTED_SCBH, next);

	if (next != SCB_LIST_NULL) {
		ahc_outb(ahc, SCBPTR, next);
		ahc_outb(ahc, SCB_PREV, prev);
	}
	return next;
}

static void
ahc_add_curscb_to_free_list(ahc)
	struct ahc_softc *ahc;
{
	/* Invalidate the tag so that ahc_find_scb doesn't think it's active */
	ahc_outb(ahc, SCB_TAG, SCB_LIST_NULL);

	ahc_outb(ahc, SCB_NEXT, ahc_inb(ahc, FREE_SCBH));
	ahc_outb(ahc, FREE_SCBH, ahc_inb(ahc, SCBPTR));
}

/*
 * Manipulate the waiting for selection list and return the
 * scb that follows the one that we remove.
 */
static u_char
ahc_abort_wscb (ahc, scbp, scbpos, prev, xs_error)
	struct	  ahc_softc *ahc;
	struct	  scb *scbp;
	u_int8_t  scbpos;
	u_int8_t  prev;
	u_int32_t xs_error;
{       
	u_int8_t curscb, next;
	int target = ((scbp->hscb->tcl >> 4) & 0x0f);
	char channel = (scbp->hscb->tcl & SELBUSB) ? 'B' : 'A';
	/*
	 * Select the SCB we want to abort and
	 * pull the next pointer out of it.
	 */
	curscb = ahc_inb(ahc, SCBPTR);
	ahc_outb(ahc, SCBPTR, scbpos);
	next = ahc_inb(ahc, SCB_NEXT);

	/* Clear the necessary fields */
	ahc_outb(ahc, SCB_CONTROL, 0);

	ahc_add_curscb_to_free_list(ahc);

	/* update the waiting list */
	if (prev == SCB_LIST_NULL) 
		/* First in the list */
		ahc_outb(ahc, WAITING_SCBH, next); 
	else {
		/*
		 * Select the scb that pointed to us 
		 * and update its next pointer.
		 */
		ahc_outb(ahc, SCBPTR, prev);
		ahc_outb(ahc, SCB_NEXT, next);
	}

	/*
	 * Point us back at the original scb position
	 * and inform the SCSI system that the command
	 * has been aborted.
	 */
	ahc_outb(ahc, SCBPTR, curscb);
	scbp->flags |= SCB_ABORTED|SCB_QUEUED_FOR_DONE;
	scbp->flags &= ~SCB_ACTIVE;
	scbp->xs->error = xs_error;
	return next;
}

static u_int8_t
ahc_index_busy_target(ahc, target, channel, unbusy)
	struct	ahc_softc *ahc;
	int	target;
	char	channel;
	int	unbusy;
{
	u_int8_t  active_scb;
	u_int8_t  info_scb;
	u_int8_t  busy_scbid;
	u_int32_t scb_offset;

	info_scb = target / 4;
	if (channel == 'B')
		info_scb += 2;
	active_scb = ahc_inb(ahc, SCBPTR);
	ahc_outb(ahc, SCBPTR, info_scb);
	scb_offset = SCB_BUSYTARGETS + (target & 0x03);
	busy_scbid = ahc_inb(ahc, scb_offset);
	if (unbusy)
		ahc_outb(ahc, scb_offset, SCB_LIST_NULL);
	ahc_outb(ahc, SCBPTR, active_scb);
	return busy_scbid;
}

static void
ahc_busy_target(ahc, target, channel, scbid)
	struct	 ahc_softc *ahc;
	int	 target;
	char	 channel;
	u_int8_t scbid;
{
	u_int8_t  active_scb;
	u_int8_t  info_scb;
	u_int8_t  busy_scbid;
	u_int32_t scb_offset;

	info_scb = target / 4;
	if (channel == 'B')
		info_scb += 2;
	active_scb = ahc_inb(ahc, SCBPTR);
	ahc_outb(ahc, SCBPTR, info_scb);
	scb_offset = SCB_BUSYTARGETS + (target & 0x03);
	ahc_outb(ahc, scb_offset, scbid);
	ahc_outb(ahc, SCBPTR, active_scb);
	return;
}

static void
ahc_clear_intstat(ahc)
	struct ahc_softc *ahc;
{
	/* Clear any interrupt conditions this may have caused */
	ahc_outb(ahc, CLRSINT0, CLRSELDO|CLRSELDI|CLRSELINGO);
	ahc_outb(ahc, CLRSINT1, CLRSELTIMEO|CLRATNO|CLRSCSIRSTI
				|CLRBUSFREE|CLRSCSIPERR|CLRPHASECHG|
				CLRREQINIT);
	ahc_outb(ahc, CLRINT, CLRSCSIINT);
}

static void
ahc_reset_current_bus(ahc)
	struct ahc_softc *ahc;
{
	u_int8_t scsiseq;
	u_int8_t sblkctl;

	ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) & ~ENSCSIRST);
	scsiseq = ahc_inb(ahc, SCSISEQ);
	ahc_outb(ahc, SCSISEQ, scsiseq | SCSIRSTO);
	if (timeouts_work != 0) {
		struct ahc_busreset_args *args;

		sblkctl = ahc_inb(ahc, SBLKCTL);
		args = (sblkctl & SELBUSB) ? &ahc->busreset_args_b
					   : &ahc->busreset_args;
		ahc->in_reset |= (args->bus == 'A' ? CHANNEL_A_RESET
						   : CHANNEL_B_RESET);
		timeout(ahc_busreset_complete, args,
			MAX((AHC_BUSRESET_DELAY * hz) / 1000000, 1));
	} else {
		DELAY(AHC_BUSRESET_DELAY);
		/* Turn off the bus reset */
		ahc_outb(ahc, SCSISEQ, scsiseq & ~SCSIRSTO);

		ahc_clear_intstat(ahc);

		/* Re-enable reset interrupts */
		ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) | ENSCSIRST);

		/* Wait a minimal bus settle delay */
		DELAY(AHC_BUSSETTLE_DELAY);

		ahc_run_done_queue(ahc);
	}
}

static void
ahc_busreset_complete(arg)
	void	*arg;
{
	struct	 ahc_busreset_args *args;
	struct	 ahc_softc *ahc;
	int	 s;
	u_int8_t scsiseq;
	u_int8_t sblkctl;

	args = (struct ahc_busreset_args *)arg;
	ahc = (struct ahc_softc *)args->ahc;

	s = splbio();
	pause_sequencer(ahc);

	/* Save the current block control state */
	sblkctl = ahc_inb(ahc, SBLKCTL);

	/* Switch to the right bus */
	if (args->bus == 'A')
		ahc_outb(ahc, SBLKCTL, sblkctl & ~SELBUSB);
	else
		ahc_outb(ahc, SBLKCTL, sblkctl | SELBUSB);

	/* Turn off the bus reset */
	printf("Clearing bus reset\n");
	scsiseq = ahc_inb(ahc, SCSISEQ);
	ahc_outb(ahc, SCSISEQ, scsiseq & ~SCSIRSTO);

	ahc_clear_intstat(ahc);

	/* Re-enable reset interrupts */
	ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) | ENSCSIRST);

	/*
	 * Set a 100ms timeout to clear our in_reset flag.
	 * It will be *at-least* that long before any targets
	 * respond to real commands on the bus.
	 */
	timeout(ahc_busreset_settle_complete, args,
		(AHC_BUSSETTLE_DELAY * hz) / 1000000);

	/* Restore the original channel */
	ahc_outb(ahc, SBLKCTL, sblkctl);
	unpause_sequencer(ahc, /*unpause_always*/FALSE);
	splx(s);
}

static void
ahc_busreset_settle_complete(arg)
	void	*arg;
{
	struct	ahc_busreset_args *args;
	struct	ahc_softc *ahc;
	int	s;

	args = (struct ahc_busreset_args *)arg;
	ahc = (struct ahc_softc *)args->ahc;
	/* Clear the reset flag */
	s = splbio();
	printf("Clearing 'in-reset' flag\n");
	ahc->in_reset &= (args->bus == 'A' ? ~CHANNEL_A_RESET
					   : ~CHANNEL_B_RESET);
	ahc_run_done_queue(ahc);
	splx(s);
}

static int
ahc_reset_channel(ahc, channel, xs_error, initiate_reset)
	struct	  ahc_softc *ahc;
	char	  channel;
	u_int32_t xs_error;
	int	  initiate_reset;
{
	u_int32_t offset, offset_max;
	int	  found;
	int	  target;
	u_int8_t  sblkctl;
	char	  cur_channel;

	pause_sequencer(ahc);
	/*
	 * Clean up all the state information for the
	 * pending transactions on this bus.
	 */
	found = ahc_reset_device(ahc, ALL_TARGETS, channel, ALL_LUNS,
				 SCB_LIST_NULL, xs_error);
	if (channel == 'B') {
		ahc->needsdtr |= (ahc->needsdtr_orig & 0xff00);
		ahc->sdtrpending &= 0x00ff;
		ahc->orderedtag &= 0x00ff;
		offset = TARG_SCRATCH + 8;
		offset_max = TARG_SCRATCH + 16;
	} else if (ahc->type & AHC_WIDE){
		ahc->needsdtr = ahc->needsdtr_orig;
		ahc->needwdtr = ahc->needwdtr_orig;
		ahc->orderedtag = 0;
		ahc->sdtrpending = 0;
		ahc->wdtrpending = 0;
		offset = TARG_SCRATCH;
		offset_max = TARG_SCRATCH + 16;
	} else {
		ahc->needsdtr |= (ahc->needsdtr_orig & 0x00ff);
		ahc->sdtrpending &= 0xff00;
		ahc->orderedtag &= 0xff00;
		offset = TARG_SCRATCH;
		offset_max = TARG_SCRATCH + 8;
	}

	for (; offset < offset_max; offset++) {
		/*
		 * Revert to async/narrow transfers
		 * until we renegotiate.
		 */
		u_int8_t targ_scratch;

		targ_scratch = ahc_inb(ahc, offset);
		targ_scratch &= SXFR;
		ahc_outb(ahc, offset, targ_scratch);
	}

	/*
	 * Reset the bus if we are initiating this reset and
	 * restart/unpause the sequencer
	 */
	sblkctl = ahc_inb(ahc, SBLKCTL);
	cur_channel = (sblkctl & SELBUSB) ? 'B' : 'A';
	if (cur_channel != channel) {
		/* Case 1: Command for another bus is active
		 * Stealthily reset the other bus without
		 * upsetting the current bus.
		 */
		ahc_outb(ahc, SBLKCTL, sblkctl ^ SELBUSB);
		ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) & ~ENBUSFREE);
		if (initiate_reset)
			ahc_reset_current_bus(ahc);
		ahc_outb(ahc, SCSISEQ, 0);
		ahc_clear_intstat(ahc);
		ahc_outb(ahc, SBLKCTL, sblkctl);
		unpause_sequencer(ahc, /*unpause_always*/FALSE);
	} else {
		/* Case 2: A command from this bus is active or we're idle */ 
		ahc_outb(ahc, SIMODE1, ahc_inb(ahc, SIMODE1) & ~ENBUSFREE);
		if (initiate_reset)
			ahc_reset_current_bus(ahc);
		ahc_outb(ahc, SCSISEQ, 0);
		ahc_clear_intstat(ahc);
		restart_sequencer(ahc);
	}
	/*
	 * Untimeout our scbs now in case we have to delay our done
	 * processing.
	 */
	ahc_untimeout_done_queue(ahc);
	if (initiate_reset == 0) {
		/*
		 * If we initiated the reset, we'll run the queue
		 * once our bus-settle delay has expired.
		 */
		ahc_run_done_queue(ahc);
	}
	return found;
}

static void
ahc_run_done_queue(ahc)
	struct ahc_softc *ahc;
{
	int i;
	struct scb *scbp;
	
	for (i = 0; i < ahc->scb_data->numscbs; i++) {
		scbp = ahc->scb_data->scbarray[i];
		if (scbp->flags & SCB_QUEUED_FOR_DONE) 
			ahc_done(ahc, scbp);
	}
}
	
static void
ahc_untimeout_done_queue(ahc)
	struct ahc_softc *ahc;
{
	int i;
	struct scb *scbp;
	
	for (i = 0; i < ahc->scb_data->numscbs; i++) {
		scbp = ahc->scb_data->scbarray[i];
		if (scbp->flags & SCB_QUEUED_FOR_DONE) 
			untimeout(ahc_timeout, (caddr_t)scbp);
	}
}

static int
ahc_match_scb (scb, target, channel, lun, tag)
	struct	 scb *scb;
	int	 target;
	char	 channel;
	int	 lun;
	u_int8_t tag;
{
	int targ = (scb->hscb->tcl >> 4) & 0x0f;
	char chan = (scb->hscb->tcl & SELBUSB) ? 'B' : 'A';
	int slun = scb->hscb->tcl & 0x07;
	int match;

	match = ((chan == channel) || (channel == ALL_CHANNELS));
	if (match != 0)
		match = ((targ == target) || (target == ALL_TARGETS));
	if (match != 0)
		match = ((lun == slun) || (lun == ALL_LUNS));
	if (match != 0)
		match = ((tag == scb->hscb->tag) || (tag == SCB_LIST_NULL));

	return match;
}

static void
ahc_construct_sdtr(ahc, start_byte, period, offset)
	struct ahc_softc *ahc;
	int start_byte;
	u_int8_t period;
	u_int8_t offset;
{
	ahc_outb(ahc, MSG_OUT + start_byte, MSG_EXTENDED);
	ahc_outb(ahc, MSG_OUT + 1 + start_byte, MSG_EXT_SDTR_LEN);
	ahc_outb(ahc, MSG_OUT + 2 + start_byte, MSG_EXT_SDTR);
	ahc_outb(ahc, MSG_OUT + 3 + start_byte, period);
	ahc_outb(ahc, MSG_OUT + 4 + start_byte, offset);
	ahc_outb(ahc, MSG_LEN, start_byte + 5);
}

static void
ahc_construct_wdtr(ahc, start_byte, bus_width)
	struct ahc_softc *ahc;
	int start_byte;
	u_int8_t bus_width;
{
	ahc_outb(ahc, MSG_OUT + start_byte, MSG_EXTENDED);
	ahc_outb(ahc, MSG_OUT + 1 + start_byte, MSG_EXT_WDTR_LEN);
	ahc_outb(ahc, MSG_OUT + 2 + start_byte, MSG_EXT_WDTR);
	ahc_outb(ahc, MSG_OUT + 3 + start_byte, bus_width);
	ahc_outb(ahc, MSG_LEN, start_byte + 4);
}

static void
ahc_calc_residual(scb)
	struct scb *scb;
{
	struct	scsi_xfer *xs;
	struct	hardware_scb *hscb;
	int	resid_sgs;

	xs = scb->xs;
	hscb = scb->hscb;

	/*
	 * If the disconnected flag is still set, this is bogus
	 * residual information left over from a sequencer
	 * pagin/pageout, so ignore this case.
	 */
	if ((scb->hscb->control & DISCONNECTED) == 0
	 && (scb->flags & SCB_SENSE) == 0) {
		/*
		 * Remainder of the SG where the transfer
		 * stopped.
		 */
		xs->resid = (hscb->residual_data_count[2] <<16) |
			    (hscb->residual_data_count[1] <<8)  |
			    (hscb->residual_data_count[0]);

		/*
		 * Add up the contents of all residual
		 * SG segments that are after the SG where
		 * the transfer stopped.
		 */
		resid_sgs = scb->hscb->residual_SG_segment_count - 1;
		while (resid_sgs > 0) {
			int sg;

			sg = scb->sg_count - resid_sgs;
			xs->resid += scb->ahc_dma[sg].len;
			resid_sgs--;
		}
#if defined(__FreeBSD__)
		xs->flags |= SCSI_RESID_VALID;
#elif defined(__NetBSD__)
		/* XXX - Update to do this right */
#endif
	}

	/*
	 * Clean out the residual information in this SCB for its
	 * next consumer.
	 */
	hscb->residual_data_count[2] = 0;
	hscb->residual_data_count[1] = 0;
	hscb->residual_data_count[0] = 0;
	hscb->residual_SG_segment_count = 0;

#ifdef AHC_DEBUG
	if (ahc_debug & AHC_SHOWMISC) {
		sc_print_addr(xs->sc_link);
		printf("Handled Residual of %ld bytes\n" ,xs->resid);
	}
#endif
}
