/*
 * Copyright (c) 1996, Sujal M. Patel
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
 *      $Id: pnp.c,v 1.9 1999/01/14 06:22:07 jdp Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/linker_set.h>
#include <sys/malloc.h>
#include <sys/interrupt.h>
#include <machine/clock.h>
#include <machine/md_var.h>

#include <i386/isa/icu.h>
#include <i386/isa/isa_device.h>
#include <i386/isa/pnp.h>

typedef struct _pnp_id {
	u_long vendor_id;
	u_long serial;
	u_char checksum;
	u_long comp_id;
} pnp_id;

static int num_pnp_cards = 0;
static pnp_id pnp_devices[MAX_PNP_CARDS];
struct pnp_dlist_node *pnp_device_list;
static struct pnp_dlist_node **pnp_device_list_last_ptr;

/*
 * these entries are initialized using the autoconfig menu
 * The struct is invalid (and must be initialized) if the first
 * CSN is zero. The init code fills invalid entries with CSN 255
 * which is not a supported value.
 */

struct pnp_cinfo pnp_ldn_overrides[MAX_PNP_LDN] = { { 0 } };

/*
 * the following is a flag which tells if the data is valid.
 */
static int doing_pnp_probe = 0 ;
static int current_csn ;
static int current_pnp_id ;
static int current_pnp_serial ;

/*
 * the following block is an example on what is needed for
 * a PnP device driver.
 */
static  char*   nullpnp_probe(u_long csn, u_long vendor_id);
static  void    nullpnp_attach(u_long csn, u_long vendor_id, char *name,
    struct isa_device *dev);
static  u_long	nullpnp_count = 0 ;

static struct pnp_device nullpnp_device = {
    "goodpnp",
    nullpnp_probe,
    nullpnp_attach,
    &nullpnp_count,
    NULL /* imask */
};

DATA_SET (pnpdevice_set, nullpnp_device);

static char*
nullpnp_probe(u_long tag, u_long type)
{
    if (bootverbose)
	    printf("Called nullpnp_probe with tag 0x%08lx, type 0x%08lx\n",
		    tag, type);
    return NULL;
}

static void
nullpnp_attach(u_long csn, u_long vend_id, char *name,
	struct isa_device *dev)
{
    printf("nullpnp_attach: csn %ld, vend_id 0x%08lx name %s unit %d\n",
	    csn, vend_id, name, dev->id_unit);
    return;
}

/* The READ_DATA port that we are using currently */
static int pnp_rd_port;

static void   pnp_send_Initiation_LFSR (void);
static int    pnp_get_serial (pnp_id *p);
static void   config_pnp_device (pnp_id *p, int csn);
static int    pnp_isolation_protocol (void);

void
pnp_write(int d, u_char r)
{
    outb (_PNP_ADDRESS, d);
    outb (_PNP_WRITE_DATA, r);
}

u_char
pnp_read(int d)
{
    outb (_PNP_ADDRESS, d);
    return (inb(3 | (pnp_rd_port <<2)));
}

/*
 * Send Initiation LFSR as described in "Plug and Play ISA Specification",
 * Intel May 94.
 */
static void
pnp_send_Initiation_LFSR()
{
    int cur, i;

    /* Reset the LSFR */
    outb(_PNP_ADDRESS, 0);
    outb(_PNP_ADDRESS, 0); /* yes, we do need it twice! */

    cur = 0x6a;
    outb(_PNP_ADDRESS, cur);

    for (i = 1; i < 32; i++) {
	cur = (cur >> 1) | (((cur ^ (cur >> 1)) << 7) & 0xff);
	outb(_PNP_ADDRESS, cur);
    }
}


/*
 * Get the device's serial number.  Returns 1 if the serial is valid.
 */
static int
pnp_get_serial(pnp_id *p)
{
    int i, bit, valid = 0, sum = 0x6a;
    u_char *data = (u_char *)p;

    bzero(data, sizeof(char) * 9);
    outb(_PNP_ADDRESS, SERIAL_ISOLATION);
    for (i = 0; i < 72; i++) {
	bit = inb((pnp_rd_port << 2) | 0x3) == 0x55;
	DELAY(250);	/* Delay 250 usec */

	/* Can't Short Circuit the next evaluation, so 'and' is last */
	bit = (inb((pnp_rd_port << 2) | 0x3) == 0xaa) && bit;
	DELAY(250);	/* Delay 250 usec */

	valid = valid || bit;

	if (i < 64)
	    sum = (sum >> 1) |
		(((sum ^ (sum >> 1) ^ bit) << 7) & 0xff);

	data[i / 8] = (data[i / 8] >> 1) | (bit ? 0x80 : 0);
    }

    valid = valid && (data[8] == sum);

    return valid;
}

/*
 * Fill's the buffer with resource info from the device.
 * Returns 0 if the device fails to report
 */
static int
pnp_get_resource_info(u_char *buffer, int len)
{
    int i, j;
    u_char temp;

    for (i = 0; i < len; i++) {
	outb(_PNP_ADDRESS, STATUS);
	for (j = 0; j < 100; j++) {
	    if ((inb((pnp_rd_port << 2) | 0x3)) & 0x1)
		break;
	    DELAY(1);
	}
	if (j == 100) {
	    printf("PnP device failed to report resource data\n");
	    return 0;
	}
	outb(_PNP_ADDRESS, RESOURCE_DATA);
	temp = inb((pnp_rd_port << 2) | 0x3);
	if (buffer != NULL)
	    buffer[i] = temp;
    }
    return 1;
}

/*
 * read_pnp_parms loads pnp parameters from the currently selected
 * device into the struct pnp_cinfo parameter passed.
 * The second argument specifies the Logical Device to use.
 */
int
read_pnp_parms(struct pnp_cinfo *d, int ldn)
{
    int i ;

    if (doing_pnp_probe == 0 || d == NULL)
	return 0 ;	/* fail */

    bzero(d, sizeof(struct pnp_cinfo));
    d->vendor_id = current_pnp_id ;
    d->serial = current_pnp_serial ;

    d->csn = current_csn ;
    d->ldn = ldn ;	/* XXX this should be different ... */
    pnp_write (SET_LDN, ldn );
    i = pnp_read(SET_LDN) ;
    if (i != ldn) {
	printf("Warning: LDN %d does not exist\n", ldn);
    }
    for (i = 0; i < 8; i++) {
	d->port[i] = pnp_read(IO_CONFIG_BASE + i * 2) << 8 ;
	d->port[i] |= pnp_read(IO_CONFIG_BASE + i * 2 + 1);

	if (i < 4) {
	    d->mem[i].base = pnp_read (MEM_CONFIG + i*8) << 16 ;
	    d->mem[i].base |= pnp_read (MEM_CONFIG + i*8 + 1) << 8 ;
	    d->mem[i].control = pnp_read (MEM_CONFIG + i*8 + 2) ;
	    d->mem[i].range = pnp_read (MEM_CONFIG + i*8 + 3) << 16 ;
	    d->mem[i].range |= pnp_read (MEM_CONFIG + i*8 + 4) << 8 ;
	}
	if (i < 2) {
	    d->irq[i] = pnp_read(IRQ_CONFIG + i * 2);
	    d->irq_type[i] = pnp_read(IRQ_CONFIG + 1 + i * 2);
	    d->drq[i] = pnp_read(DRQ_CONFIG + i);
	}
    }
    d->enable = pnp_read(ACTIVATE);
    for (i = 0 ; i < MAX_PNP_LDN; i++) {
	if (pnp_ldn_overrides[i].csn == d->csn &&
		pnp_ldn_overrides[i].ldn == ldn) {
	    d->flags = pnp_ldn_overrides[i].flags ;
	    d->override = pnp_ldn_overrides[i].override ;
	    break ;
	}
    }
    if (bootverbose)
	printf("port 0x%04x 0x%04x 0x%04x 0x%04x irq %d:%d drq %d:%d en %d\n",
	    d->port[0], d->port[1], d->port[2], d->port[3],
	    d->irq[0], d->irq[1],
	    d->drq[0], d->drq[1],
	    d->enable);
    return 1 ; /* success */
}

/*
 * write_pnp_parms initializes a logical device with the parms
 * in d, and then activates the board if the last parameter is 1.
 */

int
write_pnp_parms(struct pnp_cinfo *d, int ldn)
{
    int i, empty = -1 ;

    /*
     * some safety checks first.
     */
    if (doing_pnp_probe == 0 || d==NULL || d->vendor_id != current_pnp_id)
	return 0 ;	/* fail */

    pnp_write (SET_LDN, ldn );
    i = pnp_read(SET_LDN) ;
    if (i != ldn) {
	printf("Warning: LDN %d does not exist\n", ldn);
    }
    for (i = 0; i < 8; i++) {
	pnp_write(IO_CONFIG_BASE + i * 2, d->port[i] >> 8 );
	pnp_write(IO_CONFIG_BASE + i * 2 + 1, d->port[i] & 0xff );
    }
    for (i = 0; i < 4; i++) {
	pnp_write(MEM_CONFIG + i*8, (d->mem[i].base >> 16) & 0xff );
	pnp_write(MEM_CONFIG + i*8+1, (d->mem[i].base >> 8) & 0xff );
	pnp_write(MEM_CONFIG + i*8+2, d->mem[i].control & 0xff );
	pnp_write(MEM_CONFIG + i*8+3, (d->mem[i].range >> 16) & 0xff );
	pnp_write(MEM_CONFIG + i*8+4, (d->mem[i].range >> 8) & 0xff );
    }
    for (i = 0; i < 2; i++) {
	pnp_write(IRQ_CONFIG + i*2    , d->irq[i] );
	pnp_write(IRQ_CONFIG + i*2 + 1, d->irq_type[i] );
	pnp_write(DRQ_CONFIG + i, d->drq[i] );
    }
    /*
     * store parameters read into the current kernel
     * so manual editing next time is easier
     */
    for (i = 0 ; i < MAX_PNP_LDN; i++) {
	if (pnp_ldn_overrides[i].csn == d->csn &&
		pnp_ldn_overrides[i].ldn == ldn) {
	    d->flags = pnp_ldn_overrides[i].flags ;
	    pnp_ldn_overrides[i] = *d ;
	    break ;
	} else if (pnp_ldn_overrides[i].csn < 1 ||
		pnp_ldn_overrides[i].csn == 255)
	    empty = i ;
    }
    if (i== MAX_PNP_LDN && empty != -1)
	pnp_ldn_overrides[empty] = *d;

    /*
     * Here should really perform the range check, and
     * return a failure if not successful.
     */
    pnp_write (IO_RANGE_CHECK, 0);
    DELAY(1000); /* XXX is it really necessary ? */
    pnp_write (ACTIVATE, d->enable ? 1 : 0);
    DELAY(1000); /* XXX is it really necessary ? */
    return 1 ;
}

/*
 * To finalize a card's initialization, and before accessing its
 * registers, we need to bring the card in WaitForKey. To this purpose,
 * we need to issue a WaitForKey command, which brings _all_ cards
 * in that state. So, before configuring the next board, we must also
 * sent the Init-Key to bring cards to the SLEEP state again.
 *
 * In fact, one could hope that cards respond to normal I/O accesses
 * even in the SLEEP state, which could be done by issuing a WAKE[0].
 * This seems to work on the CS4236, but not on the CS4232 on my Zappa
 * motherboard .
 */
int
enable_pnp_card()
{
    /* the next wake should bring the card in WaitForKey ? */
    pnp_write (WAKE, 0);
    pnp_write(CONFIG_CONTROL, 0x02);	/* All cards in WaitForKey */
    DELAY(1000); /* XXX is it really necessary ? */
    return 1 ; /* success */
}

/*
 * Configure PnP devices. pnp_id is made of:
 *	4 bytes: board id (which can be printed as an ascii string);
 *	4 bytes: board serial number (often 0 or -1 ?)
 */

static void
config_pnp_device(pnp_id *p, int csn)
{
    static struct pnp_dlist_node *nod = NULL;
    int i;
    u_char *data = (u_char *)p;
    u_char *comp = (u_char *)&p->comp_id;

    /* these are for autoconfigure a-la pci */
    struct pnp_device *dvp, **dvpp;
    char *name = NULL;

    printf("CSN %d Vendor ID: %c%c%c%02x%02x [0x%08lx] Serial 0x%08lx Comp ID: %c%c%c%02x%02x [0x%08lx]\n",
	csn,
	((data[0] & 0x7c) >> 2) + '@',
	(((data[0] & 0x03) << 3) | ((data[1] & 0xe0) >> 5)) + '@',
	(data[1] & 0x1f) + '@', data[2], data[3],
	p->vendor_id, p->serial,
	((comp[0] & 0x7c) >> 2) + '@',
	(((comp[0] & 0x03) << 3) | ((comp[1] & 0xe0) >> 5)) + '@',
	(comp[1] & 0x1f) + '@', comp[2], comp[3],
	p->comp_id);

    doing_pnp_probe = 1 ;
    current_csn = csn ;
    current_pnp_id = p->vendor_id ;
    current_pnp_serial = p->serial ;

    /*
     * use kernel table to override possible devices
     */
    for (i = 0 ; i < MAX_PNP_LDN; i++) {
	if (pnp_ldn_overrides[i].csn == csn &&
		pnp_ldn_overrides[i].override == 1) {
	    struct pnp_cinfo d;
	    if (bootverbose)
		printf("PnP: override config for CSN %d LDN %d "
		    "vend_id 0x%08x\n", csn, pnp_ldn_overrides[i].ldn,
		    current_pnp_id);
	    /* next assignement is done otherwise read fails */
	    d.vendor_id = current_pnp_id ;
	    read_pnp_parms(&d, pnp_ldn_overrides[i].ldn);
	    if (pnp_ldn_overrides[i].enable == 0) {
		/* just disable ... */
		d.enable = 0;
		write_pnp_parms(&d, pnp_ldn_overrides[i].ldn);
	    } else {
		/* set all parameters */
		/* next assignement is done otherwise write fails */
		pnp_ldn_overrides[i].vendor_id = current_pnp_id ;
		write_pnp_parms(&pnp_ldn_overrides[i],
		    pnp_ldn_overrides[i].ldn);
	    }
	}
    }

    /* lookup device in ioconfiguration */
    dvpp = (struct pnp_device **)pnpdevice_set.ls_items;
    while ((dvp = *dvpp++)) {
	if (dvp->pd_probe) {
	    if ( ((name = (*dvp->pd_probe)(csn, p->vendor_id)) && *name) ||
		(p->comp_id &&
		    (name = (*dvp->pd_probe)(csn, p->comp_id))))
		break;
	}
    }
    if (dvp && name && *name && dvp->pd_count) { /* found a matching device */
	int unit ;

	/* pnpcb->pnpcb_seen |= ( 1ul << csn ) ; */

	/* get and increment the unit */
	unit = (*dvp->pd_count)++;

	/*
	 * now call the attach routine. The board has not been
	 * configured yet, so better not access isa registers in
	 * the attach routine until enable_pnp_card() has been done.
	 */
	
	if (nod == NULL)
		nod = malloc(sizeof(struct pnp_dlist_node), M_DEVBUF, M_NOWAIT);
	if (nod == NULL)
		panic("malloc failed for PnP resource use");
	bzero(nod, sizeof(*nod));
	nod->pnp = dvp;
	nod->dev.id_unit = unit ;
	if (dvp->pd_attach)
	    (*dvp->pd_attach) (csn, p->vendor_id, name, &(nod->dev));
	printf("%s%d (%s <%s> sn 0x%08lx)", nod->dev.id_driver &&
	    nod->dev.id_driver->name ? nod->dev.id_driver->name : "unknown",
	    unit, dvp->pd_name, name, p->serial);
	if (nod->dev.id_alive) {
	    if (nod->dev.id_irq != 0 && nod->dev.id_intr != NULL) {
		/* the board uses interrupts. Register it. */
		if (dvp->imask)
		    INTRMASK( *(dvp->imask), nod->dev.id_irq );
		register_intr(ffs(nod->dev.id_irq) - 1, nod->dev.id_id,
		    nod->dev.id_ri_flags, nod->dev.id_intr,
		    dvp->imask, nod->dev.id_unit);
		INTREN(nod->dev.id_irq);
	    }
	    if (nod->dev.id_alive != 0) {
	        if (nod->dev.id_iobase == -1) 
		    printf(" at ?");
		else {
		    printf(" at 0x%x", nod->dev.id_iobase);
		    if ((nod->dev.id_iobase + nod->dev.id_alive -1) !=
			nod->dev.id_iobase) {
			printf("-0x%x", nod->dev.id_iobase + nod->dev.id_alive
			    - 1);
		    }
		}
	    }
	    if (nod->dev.id_irq)
		printf(" irq %d", ffs(nod->dev.id_irq) - 1);
	    if (nod->dev.id_drq != -1)
		printf(" drq %d", nod->dev.id_drq);
	    if (nod->dev.id_maddr)
		printf(" maddr 0x%lx", kvtop(nod->dev.id_maddr));
	    if (nod->dev.id_msize)
		printf(" msize %d", nod->dev.id_msize);
	    if (nod->dev.id_flags)
		printf(" flags 0x%x", nod->dev.id_flags);
	    if (nod->dev.id_iobase && !(nod->dev.id_iobase & 0xf300)) {
		printf(" on motherboard");
		printf(" id %d", nod->dev.id_id);
	    } else if (nod->dev.id_iobase >= 0x1000 &&
		!(nod->dev.id_iobase & 0x300)) {
		printf (" on eisa slot %d",
		    nod->dev.id_iobase >> 12);
	    } else {
		printf (" on isa");
	    }
	    printf("\n");
	    if (pnp_device_list_last_ptr == NULL)
		pnp_device_list = nod;
	    else
	        *pnp_device_list_last_ptr = nod;
	    pnp_device_list_last_ptr = &(nod->next);
	    nod = NULL;
	} else
	    printf(" failed to attach\n");
    }
    doing_pnp_probe = 0 ;
}

/*
 * Scan Resource Data for Compatible Device ID.
 *
 * This function exits as soon as it gets a Compatible Device ID, an error
 * reading *ANY* Resource Data or ir reaches the end of Resource Data.
 * In the first case the return value will be TRUE, FALSE otherwise.
 */
static int
pnp_scan_resdata(pnp_id *p, int csn)
{
    u_char tag, resinfo[8];
    int large_len, scanning = 1024, retval = FALSE;

    while (scanning-- > 0 && pnp_get_resource_info(&tag, 1)) {
	if (PNP_RES_TYPE(tag) == 0) {
	    /* Small resource */
	    switch (PNP_SRES_NUM(tag)) {
		case COMP_DEVICE_ID:
		    /* Got a compatible device id resource */
		    if (pnp_get_resource_info(resinfo, PNP_SRES_LEN(tag))) {
		        bcopy(resinfo, &p->comp_id, 4);
			retval = TRUE;
			if (bootverbose)
			    printf("PnP: CSN %d COMP_DEVICE_ID = 0x%08lx\n", csn, p->comp_id);
		    }
		    /*
		     * We found what we were looking for, or got an error from
		     * pnp_get_resource, => stop scanning (FALLTHROUGH)
		     */
		case END_TAG:
		    scanning = 0;
		    break;
		default:
		    /* Skip this resource */
		    if (pnp_get_resource_info(NULL, PNP_SRES_LEN(tag)) == 0)
			scanning = 0;
		    break;
	    }
	} else
	    /* Large resource, skip it */
	    if (!(pnp_get_resource_info((u_char *)&large_len, 2) && pnp_get_resource_info(NULL, large_len)))
		scanning = 0;
    }

    return retval;
}

/*
 * Run the isolation protocol. Use pnp_rd_port as the READ_DATA port
 * value (caller should try multiple READ_DATA locations before giving
 * up). Upon exiting, all cards are aware that they should use
 * pnp_rd_port as the READ_DATA port.
 *
 * In the first pass, a csn is assigned to each board and pnp_id's
 * are saved to an array, pnp_devices. In the second pass, each
 * card is woken up and the device configuration is called.
 */
static int
pnp_isolation_protocol()
{
    int csn;

    pnp_send_Initiation_LFSR();

    pnp_write(CONFIG_CONTROL, 0x04);	/* Reset CSN for All Cards */

    for (csn = 1; (csn < MAX_PNP_CARDS); csn++) {
	/* Wake up cards without a CSN */
	pnp_write(WAKE, 0);
	pnp_write(SET_RD_DATA, pnp_rd_port);
	outb(_PNP_ADDRESS, SERIAL_ISOLATION);
	DELAY(1000);	/* Delay 1 msec */

	if (pnp_get_serial( &(pnp_devices[csn-1]) ) ) {
	    pnp_write(SET_CSN, csn);
	    /* pnp_write(CONFIG_CONTROL, 2); */
	    if (!pnp_scan_resdata(&(pnp_devices[csn-1]), csn))
		pnp_devices[csn-1].comp_id = NULL;
	} else
	    break;
    }
    num_pnp_cards = csn - 1;
    for (csn = 1; csn <= num_pnp_cards ; csn++) {
	/*
	 * make sure cards are in SLEEP state
	 */
	pnp_send_Initiation_LFSR();
	pnp_write(WAKE, csn);
	config_pnp_device( &(pnp_devices[csn-1]), csn);
	/*
	 * Put all cards in WaitForKey, just in case the previous
	 * attach routine forgot it.
	 */
	pnp_write(CONFIG_CONTROL, 0x02);
	DELAY(1000); /* XXX is it really necessary ? */
    }
    return num_pnp_cards ;
}


/*
 * pnp_configure()
 *
 * autoconfiguration of pnp devices. This routine just runs the
 * isolation protocol over several ports, until one is successful.
 *
 * may be called more than once ?
 *
 */

void
pnp_configure()
{
    int num_pnp_devs;

    if (pnp_ldn_overrides[0].csn == 0) {
	if (bootverbose)
	    printf("Initializing PnP override table\n");
	bzero (pnp_ldn_overrides, sizeof(pnp_ldn_overrides));
        pnp_ldn_overrides[0].csn = 255 ;
    }
    printf("Probing for PnP devices:\n");

    /* Try various READ_DATA ports from 0x203-0x3ff */
    for (pnp_rd_port = 0x80; (pnp_rd_port < 0xff); pnp_rd_port += 0x10) {
	if (bootverbose)
	    printf("Trying Read_Port at %x\n", (pnp_rd_port << 2) | 0x3);

	num_pnp_devs = pnp_isolation_protocol();
	if (num_pnp_devs)
	    break;
    }
    if (!num_pnp_devs) {
	if (bootverbose)
	    printf("No Plug-n-Play devices were found\n");
	return;
    }
}
