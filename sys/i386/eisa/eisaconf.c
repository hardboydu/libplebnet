/*
 * EISA bus probe and attach routines 
 *
 * Copyright (c) 1995, 1996 Justin T. Gibbs.
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
 *	$Id: eisaconf.c,v 1.34 1998/02/09 06:08:09 eivind Exp $
 */

#include "opt_eisa.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <machine/limits.h>

#include <i386/eisa/eisaconf.h>

#include <sys/interrupt.h>

struct eisa_device_node{
	struct	eisa_device dev;
	struct	eisa_device_node *next;
};

/* 
 * This should probably be a list of "struct device" once it exists.
 * A struct device will incorperate ioconf and driver entry point data
 * regardless of how its attached to the system (via unions) as well
 * as more generic information that all device types should support (unit
 * number, if its installed, etc).
 */
static struct eisa_device_node *eisa_dev_list;
static struct eisa_device_node **eisa_dev_list_tail = &eisa_dev_list;
static u_long eisa_unit;

static struct eisa_driver mainboard_drv = {
				     "eisa",
				     NULL,
				     NULL,
				     NULL,
				     &eisa_unit
				   };

/*
 * Add the mainboard_drv to the eisa driver linkerset so that it is
 * defined even if no EISA drivers are linked into the kernel.
 */
DATA_SET (eisadriver_set, mainboard_drv);

/*
 * Local function declarations and static variables
 */
static void eisa_reg_print __P((struct eisa_device *e_dev,
				char *string, char *separator));
static int eisa_add_resvaddr __P((struct eisa_device *e_dev,
				  struct resvlist *head, u_long	base,
				  u_long size, int flags));
static int eisa_reg_resvaddr __P((struct eisa_device *e_dev, 
				  struct resvlist *head, resvaddr_t *resvaddr,
				  int *reg_count));

/*
 * Keep some state about what we've printed so far
 * to make probe output pretty.
 */
static struct {
	int	in_registration;/* reg_start has been called */
	int	num_interrupts;	
	int	num_ioaddrs;
	int	num_maddrs;
	int	column;		/* How much we have output so far. */
#define	MAX_COL 80
} reg_state;

/* Global variable, so UserConfig can change it. */
#ifndef EISA_SLOTS
#define EISA_SLOTS 10   /* PCI clashes with higher ones.. fix later */
#endif
int num_eisa_slots = EISA_SLOTS;
		
/*
** probe for EISA devices
*/
void
eisa_configure()
{
	int i,slot;
	struct eisa_device_node *dev_node;
	struct eisa_driver **e_drvp;
	struct eisa_driver *e_drv;
	struct eisa_device *e_dev;
	int eisaBase = 0xc80;
	eisa_id_t eisa_id;

	e_drvp = (struct eisa_driver**)eisadriver_set.ls_items;

	for (slot = 0; slot < num_eisa_slots; eisaBase+=0x1000, slot++) {
		int id_size = sizeof(eisa_id);
		eisa_id = 0;
    		for( i = 0; i < id_size; i++ ) {
			outb(eisaBase,0x80 + i); /*Some cards require priming*/
			eisa_id |= inb(eisaBase+i) << ((id_size-i-1)*CHAR_BIT);
		}
		if (eisa_id & 0x80000000)
			continue;  /* no EISA card in slot */

		/* Prepare an eisa_device_node for this slot */
		dev_node = (struct eisa_device_node *)malloc(sizeof(*dev_node),
							    M_DEVBUF, M_NOWAIT);
		if (!dev_node) {
			printf("eisa0: cannot malloc eisa_device_node");
			break; /* Try to attach what we have already */
		}
		bzero(dev_node, sizeof(*dev_node));
		e_dev = &(dev_node->dev);

		e_dev->id = eisa_id;

		e_dev->full_name = "Unattached Device";

		e_dev->ioconf.slot = slot; 

		/* Initialize our lists of reserved addresses */
		LIST_INIT(&(e_dev->ioconf.ioaddrs));
		LIST_INIT(&(e_dev->ioconf.maddrs));
		TAILQ_INIT(&(e_dev->ioconf.irqs));

		*eisa_dev_list_tail = dev_node;
		eisa_dev_list_tail = &dev_node->next;
	}

	dev_node = eisa_dev_list;

	/*
	 * "Attach" the system board
	 */

	/* The first will be the motherboard in a true EISA system */
	if (dev_node && (dev_node->dev.ioconf.slot == 0)) {
		char *idstring;

		e_dev = &dev_node->dev;
		e_dev->driver = &mainboard_drv;
		e_dev->unit = (*e_dev->driver->unit)++; 
		idstring = (char *)malloc(8 + sizeof(" (System Board)") + 1,
					  M_DEVBUF, M_NOWAIT);
		if (idstring == NULL) {
			panic("Eisa probe unable to malloc");
		}
		sprintf(idstring, "%c%c%c%x%x (System Board)",
			EISA_MFCTR_CHAR0(e_dev->id),
			EISA_MFCTR_CHAR1(e_dev->id),
			EISA_MFCTR_CHAR2(e_dev->id),
			EISA_PRODUCT_ID(e_dev->id),
			EISA_REVISION_ID(e_dev->id));
		e_dev->full_name = idstring;

		printf("%s%ld: <%s>\n",
		       e_dev->driver->name,
		       e_dev->unit,
		       e_dev->full_name);

		/* Should set the iosize, but I don't have a spec handy */
		printf("Probing for devices on the EISA bus\n");
		dev_node = dev_node->next;
	}

	if (!eisa_dev_list) {
		/*
		 * No devices.
		 */
		return;
    	}
	/*
	 * See what devices we recognize.
	 */
	while((e_drv = *e_drvp++)) {
		if (e_drv->probe)
			(*e_drv->probe)();
	}

	/*
	 * Attach the devices we found in slot order
	 */
	for (; dev_node; dev_node=dev_node->next) {
		e_dev = &dev_node->dev;
		e_drv = e_dev->driver;

		if (e_drv) {
			/*
			 * Determine the proper unit number for this device.
			 * Here we should look in the device table generated
			 * by config to see if this type of device is enabled
			 * either generically or for this particular address
			 * as well as determine if a reserved unit number
			 * should be used.  We should also ensure that the
			 * "next availible unit number" skips over "wired" unit
			 * numbers. This will be done after config is fixed or
			 * some other configuration method is chosen.
			 */
			e_dev->unit = (*e_drv->unit)++;
			if ((*e_drv->attach)(e_dev) < 0) {
				/* Ensure registration has ended */
				reg_state.in_registration = 0;
				printf("\n%s0:%d <%s> attach failed\n",
					mainboard_drv.name, 
					e_dev->ioconf.slot,
					e_dev->full_name);
				continue;
			}
			/* Ensure registration has ended */
			reg_state.in_registration = 0;
		}
		else {
			/* Announce unattached device */
			printf("%s0:%d <%c%c%c%x%x=0x%x> unknown device\n",
				mainboard_drv.name,
				e_dev->ioconf.slot,
				EISA_MFCTR_CHAR0(e_dev->id),
				EISA_MFCTR_CHAR1(e_dev->id), 
				EISA_MFCTR_CHAR2(e_dev->id), 
				EISA_PRODUCT_ID(e_dev->id),
				EISA_REVISION_ID(e_dev->id),
				e_dev->id);
		}
	}
}

struct eisa_device *
eisa_match_dev(e_dev, match_func)
	struct eisa_device *e_dev;
	const char* (*match_func)(eisa_id_t);
{
	struct eisa_device_node *e_node = eisa_dev_list;

	if (e_dev) {
		/* Start our search from the last successful match */
		e_node = ((struct eisa_device_node *)e_dev)->next;
	}

	for(; e_node; e_node = e_node->next) {
		const char *result;
		if (e_node->dev.driver) {
			/* Already claimed */
			continue;
		}
		result = (*match_func)(e_node->dev.id);
		if (result) {
			e_node->dev.full_name = result;
			return (&(e_node->dev));
		}
	}
	return NULL;
}

/* Interrupt and I/O space registration facitlities */
void
eisa_reg_start(e_dev)
	struct eisa_device *e_dev;
{
	/*
	 * Announce the device.
	 */
	char *string;

	reg_state.in_registration = 1;
	reg_state.num_interrupts = 0;
	reg_state.num_ioaddrs = 0;
	reg_state.num_maddrs = 0;
	reg_state.column = 0;

	string = malloc(strlen(e_dev->full_name) + sizeof(" <>") + /*NULL*/1,
			M_TEMP, M_NOWAIT);
	if(!string) {
		printf("eisa0: cannot malloc device description string\n");
		return;
	}
	sprintf(string, " <%s>", e_dev->full_name);
	eisa_reg_print(e_dev, string, /*separator=*/NULL);
	free(string, M_TEMP);
}

/*
 * Output registration information mindfull of screen wrap.
 * Output an optional character separator before the string
 * if the line does not wrap.
 */
static void
eisa_reg_print(e_dev, string, separator)
	struct eisa_device *e_dev;
	char *string;
	char *separator;
{
	int len = strlen(string);

	if(separator)
		len++;

	if(reg_state.column + len > MAX_COL) {
		printf("\n");
		reg_state.column = 0;
	}
	else if(separator) {
		printf("%c", *separator);
		reg_state.column++;
	}

	if(reg_state.column == 0)
		reg_state.column += printf("%s%ld:%s",
					   e_dev->driver->name,
					   e_dev->unit,
					   string);
	else
		reg_state.column += printf("%s", string);
}

/* Interrupt and I/O space registration facitlities */
void
eisa_reg_end(e_dev)
	struct eisa_device *e_dev;
{
	if( reg_state.in_registration )
	{
		char string[25];

		sprintf(string, " on %s0 slot %d",
			mainboard_drv.name,
			e_dev->ioconf.slot);
		eisa_reg_print(e_dev, string, NULL);
		printf("\n");
		reg_state.in_registration = 0;
	}
	else
		printf("eisa_reg_end called outside of a "
		       "registration session\n");
}

int
eisa_add_intr(e_dev, irq)
	struct eisa_device *e_dev;
	int irq;
{
	struct	irq_node *irq_info;
 
	irq_info = (struct irq_node *)malloc(sizeof(*irq_info), M_DEVBUF,
					     M_NOWAIT);
	if (irq_info == NULL)
		return (1);

	irq_info->irq_no = irq;
	irq_info->idesc = NULL;
	TAILQ_INSERT_TAIL(&e_dev->ioconf.irqs, irq_info, links);
	return 0;
}

int
eisa_reg_intr(e_dev, irq, func, arg, maskptr, shared)
	struct eisa_device *e_dev;
	int   irq;
	void (*func)(void *);
	void  *arg;
	u_int *maskptr;
	int   shared;
{
	char string[25];
	char separator = ',';

#if NOT_YET
	/* 
	 * Punt on conflict detection for the moment.
	 * I want to develop a generic routine to do
	 * this for all device types.
	 */
	int checkthese = CC_IRQ;
	if (haveseen_dev(dev, checkthese))
        	return 1;
#endif
	if (reg_state.in_registration) {
		/*
		 * Find the first instance of this irq that has a
		 * NULL idesc.
		 */
		struct irq_node *cur_irq;

		cur_irq = TAILQ_FIRST(&e_dev->ioconf.irqs);
		while (cur_irq != NULL) {
			if (cur_irq->irq_no == irq
			 && cur_irq->idesc == NULL) {
				/* XXX use cfg->devdata  */
                		void *dev_instance = (void *)-1;

				cur_irq->idesc = intr_create(dev_instance,
							     irq,
							     func,
							     arg,
							     maskptr, 0);
				break;
			}
			cur_irq = TAILQ_NEXT(cur_irq, links);
		}
 
		if (cur_irq == NULL || cur_irq->idesc == NULL)
			return (-1);
	} else {
		return EPERM;
	}

	sprintf(string, " irq %d", irq);
	eisa_reg_print(e_dev, string, reg_state.num_interrupts ? 
				      &separator : NULL);
	reg_state.num_interrupts++;
	return (0);
}

int
eisa_release_intr(e_dev, irq, func)
	struct eisa_device *e_dev;
	int   irq;
	void  (*func)(void *);
{
	int	result;
	struct	irq_node *cur_irq;

	result = -1;
	cur_irq = TAILQ_FIRST(&e_dev->ioconf.irqs);
       	while (cur_irq != NULL) {
		if (cur_irq->irq_no == irq) {
			struct	irq_node *next_irq;

			next_irq = TAILQ_NEXT(cur_irq, links);
			if (cur_irq->idesc != NULL)
				intr_destroy(cur_irq->idesc);
			TAILQ_REMOVE(&e_dev->ioconf.irqs, cur_irq, links);
			free(cur_irq, M_DEVBUF);
			cur_irq = next_irq;
			result = 0;
		} else {
			cur_irq = TAILQ_NEXT(cur_irq, links);
		}
	}
	if (result != 0) {
		printf("%s%ld: Attempted to release an interrupt (%d) "
		       "it doesn't own\n", e_dev->driver->name,
			e_dev->unit, irq);
	}

	return (result);
}

int
eisa_enable_intr(e_dev, irq)
	struct eisa_device *e_dev;
	int irq;
{
	struct	irq_node *cur_irq;
	int	result;

	result = -1;
	cur_irq = TAILQ_FIRST(&e_dev->ioconf.irqs);
       	while (cur_irq != NULL) {
		if (cur_irq->irq_no == irq
		 && cur_irq->idesc != NULL) {
			result = intr_connect(cur_irq->idesc);
		}
		cur_irq = TAILQ_NEXT(cur_irq, links);
	}
	return (result);
}

static int
eisa_add_resvaddr(e_dev, head, base, size, flags)
	struct eisa_device *e_dev;
	struct resvlist *head;
	u_long	base;
	u_long	size;
	int	flags;
{
	resvaddr_t *reservation;

	reservation = (resvaddr_t *)malloc(sizeof(resvaddr_t),
					   M_DEVBUF, M_NOWAIT);
	if(!reservation)
		return (ENOMEM);

	reservation->addr = base;
	reservation->size = size;
	reservation->flags = flags;

	if (!head->lh_first) {
		LIST_INSERT_HEAD(head, reservation, links);
	}
	else {
		resvaddr_t *node;
		for(node = head->lh_first; node; node = node->links.le_next) {
			if (node->addr > reservation->addr) {
				/*
				 * List is sorted in increasing
				 * address order.
				 */
				LIST_INSERT_BEFORE(node, reservation, links);
				break;
			}

			if (node->addr == reservation->addr) {
				/*
				 * If the entry we want to add
				 * matches any already in here,
				 * fail.
				 */
				free(reservation, M_DEVBUF);
				return (EEXIST);
			}

			if (!node->links.le_next) {
				LIST_INSERT_AFTER(node, reservation, links);
				break;
			}
		}
	}
	return (0);
}

int
eisa_add_mspace(e_dev, mbase, msize, flags)
	struct eisa_device *e_dev;
	u_long	mbase;
	u_long	msize;
	int	flags;
{
	return	eisa_add_resvaddr(e_dev, &(e_dev->ioconf.maddrs), mbase, msize,
				  flags);
}

int
eisa_add_iospace(e_dev, iobase, iosize, flags)
	struct eisa_device *e_dev;
	u_long	iobase;
	u_long	iosize;
	int	flags;
{
	return	eisa_add_resvaddr(e_dev, &(e_dev->ioconf.ioaddrs), iobase,
				  iosize, flags);
}

static int
eisa_reg_resvaddr(e_dev, head, resvaddr, reg_count)
	struct eisa_device *e_dev;
	struct resvlist *head;
	resvaddr_t *resvaddr;
	int *reg_count;
{
	if (reg_state.in_registration) {
		resvaddr_t *node;
		/*
		 * Ensure that this resvaddr is actually in the devices'
		 * reservation list.
		 */
		for(node = head->lh_first; node;
		    node = node->links.le_next) {
			if (node == resvaddr) {
				char buf[35];
				char separator = ',';
				char *string = buf;

				if (*reg_count == 0) {
					/* First time */
					string += sprintf(string, " at");
				}

				if (node->size == 1 
				  || (node->flags & RESVADDR_BITMASK))
					sprintf(string, " 0x%lx", node->addr);
				else
					sprintf(string, " 0x%lx-0x%lx",
						node->addr,
						node->addr + node->size - 1);
				eisa_reg_print(e_dev, buf,
						*reg_count ? &separator : NULL);
				(*reg_count)++;
				return (0);
			}
		}
		return (ENOENT);
	}
	return EPERM;
}

int
eisa_reg_mspace(e_dev, resvaddr)
	struct eisa_device *e_dev;
	resvaddr_t *resvaddr;
{
#ifdef NOT_YET
	/* 
	 * Punt on conflict detection for the moment.
	 * I want to develop a generic routine to do
	 * this for all device types.
	 */
	int checkthese = CC_MADDR;
	if (haveseen_dev(dev, checkthese))
		return -1;
#endif
	return (eisa_reg_resvaddr(e_dev, &(e_dev->ioconf.maddrs), resvaddr,
				  &(reg_state.num_maddrs)));
}
	
int
eisa_reg_iospace(e_dev, resvaddr)
	struct eisa_device *e_dev;
	resvaddr_t *resvaddr;
{
#ifdef NOT_YET
	/* 
	 * Punt on conflict detection for the moment.
	 * I want to develop a generic routine to do
	 * this for all device types.
	 */
	int checkthese = CC_IOADDR;
	if (haveseen_dev(dev, checkthese))
		return -1;
#endif
	return (eisa_reg_resvaddr(e_dev, &(e_dev->ioconf.ioaddrs), resvaddr,
				  &(reg_state.num_ioaddrs)));
}

int
eisa_registerdev(e_dev, driver)
	struct eisa_device *e_dev;
	struct eisa_driver *driver;
{
	e_dev->driver = driver;	/* Driver now owns this device */
	return (0);
}

