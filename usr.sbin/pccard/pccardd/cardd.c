#define HERE() printf("<%d>\n",__LINE__)
/*
 *	pcmciad
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <syslog.h>
#include <varargs.h>
#include "cardd.h"


char	*config_file = "/etc/card.conf";

struct card_config *assign_driver(struct card *);
int	setup_slot(struct slot *);
void	read_ether(struct slot *);
void	dump_config_file();
void	pr_cmd(struct cmd *);
void	readslots();
void	slot_change(struct slot *);
void	card_removed(struct slot *);
void	card_inserted(struct slot *);
int	assign_io(struct slot *sp);

/*
 *	mainline code for cardd
 */
int
main(int argc, char *argv[])
{
struct slot *sp;
int count, debug = 0;
int	verbose = 0;
extern char *optarg;
extern int optind, optopt;

	while ((count = getopt(argc, argv, ":dvf:")) != -1) {
		switch(count) {
		case 'd':
			setbuf(stdout,0);
			setbuf(stderr,0);
			debug = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'f':
			config_file = optarg;
			break;
		case ':':
			die("No config file argument");
			break;
		case '?':
			die("Illegal option");
			break;
		}
	}
#ifdef	DEBUG
	debug = 1;
#endif
	io_avail = bit_alloc(IOPORTS);	/* Only supports ISA ports */
/*
 *	Mem allocation done in MEMUNIT units.
 */
	mem_avail = bit_alloc(MEMBLKS);
	readfile(config_file);
	if (verbose)
		dump_config_file();
	if (!debug)
		{
		if (daemon(0, 0))
			die("fork failed");
		openlog("cardd", LOG_PID, LOG_DAEMON);
		do_log = 1;
		}
	printf("Before readslots\n");
	readslots();
	printf("After readslots\n");
	if (slots == 0)
		die("No PC-CARD slots");
	for (;;)
		{
		fd_set mask;
		FD_ZERO(&mask);
		for (sp = slots; sp; sp = sp->next)
			FD_SET(sp->fd,&mask);
printf("Doing select\n");
		count = select(32, 0, 0, &mask, 0);
printf("select=%d\n",count);
		if (count == -1)
			{
			perror("Select");
			continue;
			}
		if (count)
			for (sp = slots; sp; sp = sp->next)
			if (FD_ISSET(sp->fd,&mask))
				slot_change(sp);
		}
}
/*
 *	Dump configuration file data.
 */
void
dump_config_file()
{
struct card *cp;
struct card_config *confp;

	for (cp = cards; cp; cp = cp->next)
		{
		printf("Card manuf %s, vers %s\n", cp->manuf, cp->version);
		printf("Configuration entries:\n");
		for (confp = cp->config; confp; confp = confp->next)
			printf("\tIndex code = 0x%x, driver name = %s\n",
				confp->index, confp->driver->name);
		if (cp->insert)
			{
			printf("Insert commands are:\n");
			pr_cmd(cp->insert);
			}
		if (cp->remove)
			{
			printf("Remove commands are:\n");
			pr_cmd(cp->remove);
			}
		}
#if 0
	for (devp = devlist; devp; devp = devp->next)
		{
		if (devp->insert)
			{
			printf("Insert commands are:\n");
			pr_cmd(devp->insert);
			}
		if (devp->remove)
			{
			printf("Remove commands are:\n");
			pr_cmd(devp->remove);
			}
		}
#endif
}
void
pr_cmd(struct cmd *cp)
{
	while (cp)
		{
		printf("\t%s\n", cp->line);
		cp = cp->next;
		}
}
/*
 *	readslots - read all the PCMCIA slots, and build
 *	a list of the slots.
 */
void
readslots()
{
char	name[128];
int	i, fd;
struct slot *sp;

	for (i = 0; i < MAXSLOT; i++)
		{
		sprintf(name, CARD_DEVICE, i);
		fd = open(name, 2);
		if (fd < 0)
			continue;
printf("opened %s\n",name);
		sp = xmalloc(sizeof(*sp));
		sp->fd = fd;
		sp->name = newstr(name);
		sp->slot = i;
		sp->state = empty;
/*
 *	Check to see if the controller memory has been set up.
 */
		if (slots == 0)
			{
			unsigned long mem = 0;

HERE();
			if (ioctl(fd, PIOCRWMEM, &mem))
				perror("ioctl (PIOCRWMEM)");
			if (mem == 0)
				{
HERE();
				mem = alloc_memory(4*1024);
HERE();
				if (mem == 0)
		die("Can't allocate memory for controller access");
				if (ioctl(fd, PIOCRWMEM, &mem))
					perror("ioctl (PIOCRWMEM)");
				}
			}
		sp->next = slots;
		slots = sp;
HERE();
#if 0
		slot_change(sp);
#endif
HERE();
		}
}
/*
 *	slot_change - Card status has changed.
 *	read new state and process.
 */
void
slot_change(struct slot *sp)
{
int state;

	current_slot = sp;
HERE();
	if (ioctl(sp->fd, PIOCGSTATE, &state))
		{
		perror("ioctl (PIOCGSTATE)");
		return;
		}
HERE();
	if (state == sp->state)
		return;
HERE();
	sp->state = state;
HERE();
	switch (sp->state)
		{
	case empty:
	case noslot:
HERE();
		card_removed(sp);
HERE();
		break;
	case filled:
HERE();
		card_inserted(sp);
HERE();
		break;
		}
}
/*
 *	card_removed - card has been removed from slot.
 *	Execute the remove commands, and clear the slot's state.
 *	Execute the device commands, then the driver commands
 *	and then the card commands. This is the reverse
 *	order to the insertion commands
 */
void
card_removed(struct slot *sp)
{
struct card *cp;

HERE();
	if (sp->cis)
		freecis(sp->cis);
	if (sp->config)
		{
		sp->config->inuse = 0;
		sp->config->driver->inuse = 0;
		}
HERE();
	if ((cp = sp->card) != 0)
		execute(cp->remove);
HERE();
	sp->cis = 0;
	sp->config = 0;
HERE();
}
/*
 * card_inserted - Card has been inserted;
 *	- Read the CIS
 *	- match the card type.
 *	- Match the driver and allocate a driver instance.
 *	- Allocate I/O ports, memory and IRQ.
 *	- Set up the slot.
 *	- assign the driver (if failed, then terminate).
 *	- Run the card commands.
 *	- Run the driver commands
 *	- Run the device commands
 */
void
card_inserted(struct slot *sp)
{
struct card *cp;

	sp->cis = readcis(sp->fd);
	if (sp->cis == 0)
		{
		log_1s("Error reading CIS on %s\n", sp->name);
		return;
		}
	for (cp = cards; cp; cp = cp->next)
		if (strcmp(cp->manuf, sp->cis->manuf) == 0 &&
			strcmp(cp->version, sp->cis->vers) == 0)
			break;
	sp->card = cp;
/*
	reset_slot(sp);
 */
	if (cp == 0)
		{
		log_1s("No card in database for %s", sp->cis->manuf);
		return;
		}
	if (cp->ether)
		read_ether(sp);
	sp->config = assign_driver(cp);
	if (sp->config == 0)
		{
		execute(cp->insert);
		return;
		}
	if (assign_io(sp))
		{
		log_1s("Resource allocation failure for %s", sp->cis->manuf);
		return;
		}
/*
 *	Once assigned, then set up the I/O & mem contexts, and
 *	set up the windows, and then attach the driver.
 */
	if (setup_slot(sp))
		execute(cp->insert);
#if 0
	else
		reset_slot(sp);
#endif
}
/*
 *	read_ether - read ethernet address from card. Offset is
 *	the offset into the attribute memory of the card.
 */
void
read_ether(struct slot *sp)
{
unsigned char net_addr[12];

	lseek(sp->fd, (off_t)sp->card->ether, SEEK_SET);
	if (read(sp->fd, net_addr, sizeof(net_addr)) != sizeof(net_addr))
		{
		logerr("read err on net addr");
		return;
		}
	sp->eaddr[0] = net_addr[0];
	sp->eaddr[1] = net_addr[2];
	sp->eaddr[2] = net_addr[4];
	sp->eaddr[3] = net_addr[6];
	sp->eaddr[4] = net_addr[8];
	sp->eaddr[5] = net_addr[10];
}
/*
 *	assign_driver - Assign driver to card.
 *	First, see if an existing driver is already setup.
 */
struct card_config *
assign_driver(struct card *cp)
{
struct driver *drvp;
struct card_config *conf;

	for (conf = cp->config; conf; conf = conf->next)
		if (conf->inuse == 0 && conf->driver->card == cp &&
		    conf->driver->config == conf)
			{
#ifdef	DEBUG
			fprintf(stderr, "Found existing driver (%s) for %s\n",
				conf->driver->name, cp->manuf);
#endif /* DEBUG */
			return(conf);
			}
/*
 *	New driver must be allocated. Find one that matches the
 *	any configurations not in use.
 */
	for (conf = cp->config; conf; conf = conf->next)
		if (conf->inuse == 0 && conf->driver->card == 0)
			break;
	if (conf == 0)
		{
		log_1s("No free configuration for card %s", cp->manuf);
		return(0);
		}
/*
 *	Now we have a free driver and a matching configuration.
 *	Before assigning and allocating everything, check to
 *	see if a device class can be allocated to this.
 */
	drvp = conf->driver;
/*
 *	If none available, then we can't use this card.
 */
	if (drvp->inuse)
		{
		log_1s("Driver already being used for %s", cp->manuf);
		return(0);
		}
#if 0
/*
 *	Allocate I/O, memory and IRQ resources.
 */
	for (ap = drvp->io; ap; ap = ap->next)
		{
		if (ap->addr == 0 && ap->size)
			{
			int i = bit_fns(io_avail, IOPORTS, ap->size);
	
			if (i < 0)
				{
				log_1s("Failed to allocate I/O ports for %s\n",
					cp->manuf);
				return(0);
				}
			ap->addr = i;
			bit_nclear(io_avail, i, ap->size);
			}
		}
	if (drvp->irq == 0)
		{
		int i;
		for (i = 1; i < 16; i++)
			if (pool_irq[i])
				{
				drvp->irq = i;
				pool_irq[i] = 0;
				break;
				}
		if (drvp->irq == 0)
			{
			log_1s("Failed to allocate IRQ for %s\n", cp->manuf);
			return(0);
			}
		}
	for (ap = drvp->mem; ap; ap = ap->next)
		{
		if (ap->addr == 0 && ap->size)
			{
			ap->addr = alloc_memory(ap->size);
			if (ap->addr == 0)
				{
				log_1s("Failed to allocate memory for %s\n",
					cp->manuf);
				return(0);
				}
			}
		}
#endif /* 0 */
	drvp->card = cp;
	drvp->config = conf;
	drvp->inuse = 1;
	conf->inuse = 1;
	return(conf);
}
/*
 *	assign_io - Allocate resources to slot matching the
 *	configuration index selected.
 */
int
assign_io(struct slot *sp)
{
struct cis *cis;
struct cis_config *cisconf, *defconf;

	cis = sp->cis;
	defconf = cis->def_config;
	for (cisconf = cis->conf; cisconf; cisconf = cisconf->next)
		if (cisconf->id == sp->config->index)
			break;
	if (cisconf == 0)
		return(-1);
	sp->card_config = cisconf;
/*
 *	Found a matching configuration. Now look at the I/O, memory and IRQ
 *	to create the desired parameters. Look at memory first.
 */
	if (cisconf->memspace || (defconf && defconf->memspace))
		{
		struct cis_memblk *mp;

		mp = cisconf->mem;
		if (!cisconf->memspace)
			mp = defconf->mem;
		sp->mem.size = mp->length;
		sp->mem.cardaddr = mp->address;
/*
 *	For now, we allocate our own memory from the pool.
 */
		sp->mem.addr = sp->config->driver->mem;
/*
 *	Host memory address is required. Allocate one
 *	from our pool.
 */
		if (sp->mem.size && sp->mem.addr == 0)
			{
			sp->mem.addr = alloc_memory(mp->length);
			if (sp->mem.addr == 0)
				return(-1);
			sp->config->driver->mem = sp->mem.addr;
			}
#ifdef	DEBUG
		fprintf(stderr, "Using mem addr 0x%x, size %d, card addr 0x%x\n",
			sp->mem.addr, sp->mem.cardaddr, sp->mem.size);
#endif /* DEBUG */
		}
/*
 *	Now look at I/O.
 */
	bzero(&sp->io, sizeof(sp->io));
	if (cisconf->iospace || (defconf && defconf->iospace))
		{
		struct cis_config *cp;

		cp = cisconf;
		if (!cisconf->iospace)
			cp = defconf;
/*
 *	If # of I/O lines decoded == 10, then card does its
 *	own decoding.
 */
/*
 *	If an I/O block exists, then use it.
 *	If no address (but a length) is available, allocate
 *	from the pool.
 */
		if (cp->io)
			{
			sp->io.addr = cp->io->addr;
			sp->io.size = cp->io->size;
			}
/*
 *	No I/O block, assume the address lines decode gives the size.
 */
		else
			sp->io.size = 1 << cp->io_addr;
		if (sp->io.addr == 0)
			{
			int i = bit_fns(io_avail, IOPORTS, sp->io.size);
	
			if (i < 0)
				return(-1);
			sp->io.addr = i;
			}
		bit_nclear(io_avail, sp->io.addr, sp->io.size);
/*
 *	Set up the size to take into account the decode lines.
 */
		sp->io.cardaddr = cp->io_addr;
		switch(cp->io_bus)
			{
		case 0:
			break;
		case 1:
			sp->io.flags = IODF_WS;
			break;
		case 2:
			sp->io.flags = IODF_WS|IODF_CS16;
			break;
		case 3:
			sp->io.flags = IODF_WS|IODF_CS16|IODF_16BIT;
			break;
			}
#ifdef	DEBUG
		fprintf(stderr, "Using I/O addr 0x%x, size %d\n",
			sp->io.addr, sp->io.size);
#endif /* DEBUG */
		}
	sp->irq = sp->config->irq;
	return(0);
}
/*
 *	setup_slot - Allocate the I/O and memory contexts
 *	return true if completed OK.
 */
int
setup_slot(struct slot *sp)
{
struct mem_desc mem;
struct io_desc io;
struct drv_desc drv;
struct driver *drvp = sp->config->driver;
char c;
off_t offs;
int	rw_flags;

	offs = sp->cis->reg_addr;
	rw_flags = MDF_ATTR;
	ioctl(sp->fd, PIOCRWFLAG, &rw_flags);
	lseek(sp->fd, offs, SEEK_SET);
	c = 0x80;
	write(sp->fd, &c, sizeof(c));
	usleep(sp->card->reset_time*1000);
	lseek(sp->fd, offs, SEEK_SET);
	c = 0x00;
	write(sp->fd, &c, sizeof(c));
	usleep(sp->card->reset_time*1000);
	lseek(sp->fd, offs, SEEK_SET);
	c = sp->config->index;
	write(sp->fd, &c, sizeof(c));
#ifdef	DEBUG
	printf("Setting config reg at offs 0x%x to 0x%x\n",
		sp->cis->reg_addr, c);
	printf("Reset time = %d ms\n", sp->card->reset_time);
#endif
	usleep(sp->card->reset_time*1000);
/*
 *	If other config registers exist, set them up.
 */
	if (sp->cis->ccrs & 2)		/* CCSR */
		{
		c = 0;
		if (sp->cis->def_config && sp->cis->def_config->misc_valid &&
		    (sp->cis->def_config->misc & 0x8))
			c |= 0x08;
		if (sp->card_config->io_bus == 1)
			c |= 0x20;
		lseek(sp->fd, offs+2, SEEK_SET);
		write(sp->fd, &c, sizeof(c));
#ifdef	DEBUG
		printf("Setting CCSR reg to 0x%x\n", c);
#endif
		}
	mem.window = 0;
	if (sp->mem.size)
		{
		mem.window = 0;
		mem.flags = sp->mem.flags;
		mem.start = (caddr_t)sp->mem.addr;
		mem.card = sp->mem.cardaddr;
		mem.size = sp->mem.size;
		if (ioctl(sp->fd, PIOCSMEM, &mem))
			{
			logerr("ioctl (PIOCSMEM)");
			return(0);
			}
		}
	io.window = 0;
	if (sp->io.size)
		{
		io.flags = sp->io.flags;
		io.start = sp->io.addr;
		io.size = sp->io.size;
/*
		io.start = sp->io.addr & ~((1 << sp->io.cardaddr)-1);
		io.size = 1 << sp->io.cardaddr;
		if (io.start < 0x100)
			{
			io.start = 0x100;
			io.size = 0x300;
			}
 */
#ifdef	DEBUG
		printf("Assigning I/O window 0, start 0x%x, size 0x%x\n",
			io.start, io.size);
#endif
		if (ioctl(sp->fd, PIOCSIO, &io))
			{
			logerr("ioctl (PIOCSIO)");
			return(0);
			}
		}
	strcpy(drv.name, drvp->kernel);
	drv.unit = drvp->unit;
	drv.irqmask = 1 << sp->irq;
	if (sp->mem.size)
		{
		drv.mem = sp->mem.addr;
		drv.memsize = sp->mem.size;
		}
	else
		{
		drv.mem = 0;
		drv.memsize = 0;
		}
	if (sp->io.size)
		drv.iobase = sp->io.addr;
	else
		drv.iobase = 0;
#ifdef	DEBUG
	fprintf(stderr, "Assign %s%d, io 0x%x, mem 0x%x, %d bytes, irq %x\n",
	   drv.name, drv.unit, drv.iobase, drv.mem, drv.memsize, drv.irqmask);
#endif /* DEBUG */
/*
 *	If the driver fails to be connected to the device,
 *	then it may mean that the driver did not recognise it.
 */
	if (ioctl(sp->fd, PIOCSDRV, &drv))
		{
#ifdef	DEBUG
		perror(sp->card->manuf);
#endif
		log_1s("driver allocation failed for %s", sp->card->manuf);
		return(0);
		}
	return(1);
}
