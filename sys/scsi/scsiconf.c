/*
 * Written by Julian Elischer (julian@tfs.com)
 * for TRW Financial Systems for use under the MACH(2.5) operating system.
 *
 * TRW Financial Systems, in accordance with their agreement with Carnegie
 * Mellon University, makes this software available to CMU to distribute
 * or use in any manner that they see fit as long as this message is kept with
 * the software. For this reason TFS also grants any other persons or
 * organisations permission to use or modify this software.
 *
 * TFS supplies this software to be publicly redistributed
 * on the understanding that TFS is not responsible for the correct
 * functioning of this software in any circumstances.
 *
 * Ported to run under 386BSD by Julian Elischer (julian@tfs.com) Sept 1992
 *
 * New configuration setup: dufault@hda.com
 *
 *      $Id: scsiconf.c,v 1.19 1995/02/14 06:18:06 phk Exp $
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stat.h>

#include <sys/malloc.h>
#include <sys/devconf.h>
#include <sys/conf.h>
#include <machine/clock.h>

#include "scbus.h"

#include "sd.h"
#include "st.h"
#include "cd.h"
#include "ch.h"

#include "su.h"

#include <scsi/scsi_all.h>
#include <scsi/scsiconf.h>

/* Extensible arrays: Use a realloc like implementation to permit
 * the arrays to be extend.  These are set up to be moved out
 * of this file if needed elsewhere.
 */
struct extend_array
{
	int nelem;
	void **ps;
};

static void *extend_alloc(size_t s)
{
	void *p = malloc(s, M_DEVBUF, M_NOWAIT);
	if (!p)
		panic("extend_alloc: malloc failed.");
	return p;
}

static void extend_free(void *p) { free(p, M_DEVBUF); }

#define EXTEND_CHUNK 8

struct extend_array *extend_new(void)
{
	struct extend_array *p = extend_alloc(sizeof(*p));
	p->nelem = 0;
	p->ps = 0;

	return p;
}

void *extend_set(struct extend_array *ea, int index, void *value)
{
	if (index >= ea->nelem) {
		void **space;
		space = extend_alloc(sizeof(void *) * (index + EXTEND_CHUNK));
		bzero(space, sizeof(void *) * (index + EXTEND_CHUNK));

		/* Make sure we have something to copy before we copy it */
		if (ea->nelem) {
			bcopy(ea->ps, space, sizeof(void *) * ea->nelem);
			extend_free(ea->ps);
		}

		ea->ps = space;
		ea->nelem = index + EXTEND_CHUNK;
	}
	if (ea->ps[index]) {
		printf("extend_set: entry %d already has storage.\n", index);
		return 0;
	}
	else
		ea->ps[index] = value;

	return value;
}

void *extend_get(struct extend_array *ea, int index)
{
	if (index >= ea->nelem || index < 0)
		return 0;
	return ea->ps[index];
}

void extend_release(struct extend_array *ea, int index)
{
	void *p = extend_get(ea, index);
	if (p) {
		ea->ps[index] = 0;
	}
}

/*
 * This extend_array holds an array of "scsibus_data" pointers.
 * One of these is allocated and filled in for each scsi bus.
 * it holds pointers to allow the scsi bus to get to the driver
 * That is running each LUN on the bus
 * it also has a template entry which is the prototype struct
 * supplied by the adapter driver, this is used to initialise
 * the others, before they have the rest of the fields filled in
 */

struct extend_array *scbusses;

/*
 * The structure of known drivers for autoconfiguration
 */
struct scsidevs {
	u_int32 type;
	boolean removable;
	char   *manufacturer;
	char   *model;
	char   *version;
	char   *devname;
	char    flags;		/* 1 show my comparisons during boot(debug) */
#ifdef NEW_SCSICONF
	u_int16	quirks;
	void   *devmodes;
#endif
};

#define SC_SHOWME	0x01
#define	SC_ONE_LU	0x00
#define	SC_MORE_LUS	0x02

static struct scsidevs unknowndev = 
	{
		T_UNKNOWN, 0, "*", "*", "*", 
		"uk", SC_MORE_LUS
	};

#ifdef NEW_SCSICONF
static st_modes mode_tandberg3600 = 
	{
	    {0, 0, 0},					/* minor 0,1,2,3 */
	    {0, ST_Q_FORCE_VAR_MODE, QIC_525},		/* minor 4,5,6,7 */
	    {0, 0, QIC_150},				/* minor 8,9,10,11 */
	    {0, 0, QIC_120}				/* minor 12,13,14,15 */
	};
static st_modes mode_archive2525 =
	{
	    {0, ST_Q_SNS_HLP, 0},			/* minor 0,1,2,3 */
	    {0, ST_Q_SNS_HLP, QIC_525},			/* minor 4,5,6,7 */
	    {0, 0, QIC_150},				/* minor 8,9,10,11 */
	    {0, 0, QIC_120}				/* minor 12,13,14,15 */
	};
static st_modes mode_archive150 =
	{
	    {0, 0, 0},					/* minor 0,1,2,3 */
	    {0, 0, QIC_150},				/* minor 4,5,6,7 */
	    {0, 0, QIC_120},				/* minor 8,9,10,11 */
	    {0, 0, QIC_24}				/* minor 12,13,14,15 */
	};
static st_modes mode_wangtek5525 =
	{
	    {0, 0, 0},					/* minor 0,1,2,3 */
	    {0, ST_Q_BLKSIZ, QIC_525},			/* minor 4,5,6,7 */
	    {0, 0, QIC_150},				/* minor 8,9,10,11 */
	    {0, 0, QIC_120}				/* minor 12,13,14,15 */
	};
static st_modes mode_wangdat1300 =
	{
	    {0, 0, 0},					/* minor 0,1,2,3 */
	    {512, ST_Q_FORCE_FIXED_MODE, DDS},		/* minor 4,5,6,7 */
	    {1024, ST_Q_FORCE_FIXED_MODE, DDS},		/* minor 8,9,10,11 */
	    {0, ST_Q_FORCE_VAR_MODE, DDS}		/* minor 12,13,14,15 */
	};
static st_modes mode_unktape =
	{
	    {512, ST_Q_FORCE_FIXED_MODE, 0},		/* minor 0,1,2,3 */
	    {512, ST_Q_FORCE_FIXED_MODE, QIC_24},	/* minor 4,5,6,7 */
	    {0, ST_Q_FORCE_VAR_MODE, HALFINCH_1600},	/* minor 8,9,10,11 */
	    {0, ST_Q_FORCE_VAR_MODE, HALFINCH_6250}	/* minor 12,13,14,15 */
	};
#endif /* NEW_SCSICONF */

static struct scsidevs knowndevs[] =
#ifdef NEW_SCSICONF
{
#if NSD > 0
	{
		T_DIRECT, T_FIXED, "MAXTOR", "XT-4170S", "B5A", 
		"mx1", SC_ONE_LU
	},
	{
		T_DIRECT, T_FIXED, "*", "*", "*", 
		"sd", SC_ONE_LU
	},
#endif	/* NSD */
#if NST > 0
	{
		T_SEQUENTIAL, T_REMOV, "TANDBERG", " TDC 3600", "*",
		"st", SC_ONE_LU, ST_Q_NEEDS_PAGE_0, mode_tandberg3600
	},
	{
		T_SEQUENTIAL, T_REMOV, "ARCHIVE", "VIPER 2525*", "-005",
		"st", SC_ONE_LU, 0, mode_archive2525
	},
	{
		T_SEQUENTIAL, T_REMOV, "ARCHIVE", "VIPER 150", "*",
		"st", SC_ONE_LU, ST_Q_NEEDS_PAGE_0, mode_archive150
	},
	{
		T_SEQUENTIAL, T_REMOV, "WANGTEK", "5525ES*", "*",
		"st", SC_ONE_LU, 0, mode_wangtek5525
	},
	{
		T_SEQUENTIAL, T_REMOV, "WangDAT", "Model 1300", "*",
		"st", SC_ONE_LU, 0, mode_wangdat1300
	},
	{
		T_SEQUENTIAL, T_REMOV, "*", "*", "*", 
		"st", SC_ONE_LU, 0, mode_unktape
	},
#endif	/* NST */
#if NCH > 0
	{
		T_CHANGER, T_REMOV, "*", "*", "*", 
		"ch", SC_ONE_LU
	},
#endif	/* NCH */
#if NCD > 0
#ifndef UKTEST	/* make cdroms unrecognised to test the uk driver */
	{
		T_READONLY, T_REMOV, "SONY", "CD-ROM CDU-8012", "3.1a", 
		"cd", SC_ONE_LU
	},
	{
		T_READONLY, T_REMOV, "PIONEER", "CD-ROM DRM-600", "*",
		"cd", SC_MORE_LUS
	},
#endif
#endif	/* NCD */
	{
		0
	}
};
#else
{
#if NSD > 0
	{
		T_DIRECT, T_FIXED, "standard", "any"
		    ,"any", "sd", SC_ONE_LU
	},
	{
		T_DIRECT, T_FIXED, "MAXTOR  ", "XT-4170S        "
		    ,"B5A ", "mx1", SC_ONE_LU
	},
#endif	/* NSD */
#if NST > 0
	{
		T_SEQUENTIAL, T_REMOV, "standard", "any"
		    ,"any", "st", SC_ONE_LU
	},
#endif	/* NST */
#if NCH > 0
	{
		T_CHANGER, T_REMOV, "standard", "any"
		    ,"any", "ch", SC_ONE_LU
	},
#endif	/* NCH */
#if NCD > 0
#ifndef UKTEST	/* make cdroms unrecognised to test the uk driver */
	{
		T_READONLY, T_REMOV, "SONY    ", "CD-ROM CDU-8012 "
		    ,"3.1a", "cd", SC_ONE_LU
	},
	{
		T_READONLY, T_REMOV, "PIONEER ", "CD-ROM DRM-600  "
		    ,"any", "cd", SC_MORE_LUS
	},
#endif
#endif	/* NCD */
	{
		0
	}
};
#endif /* NEW_SCSICONF */

/*
 * Declarations
 */
struct scsidevs *scsi_probedev();
struct scsidevs *scsi_selectdev();
errval scsi_probe_bus(int bus, int targ, int lun);

/* XXX dufault@hda.com
 * This scsi_device doesn't have the scsi_data_size.
 * This is used during probe and used to be "probe_switch".
 */
struct scsi_device inval_switch =
{
    NULL,
    NULL,
    NULL,
    NULL,
    "??",
    0,
	{0, 0},
    NULL,
    0
};

/*
 * XXX
 * This is BOGUS.
 * We do this because it was easier than adding the requisite information
 * to the scsi_link structure and modifying everything to use that.
 * Someday, we will do just that, and users will be able to nail down their
 * preferred SCSI ids.
 *
 */
struct kern_devconf kdc_scbus0 = {
	0, 0, 0,		/* filled in by dev_attach */
	"scbus", 0, MDDC_SCBUS,
	0, 0, 0, 0,		/* no external data */
	0,			/* no parent */
	0,			/* no parentdata */
	DC_BUSY,		/* busses are always busy */
	"SCSI subsystem"
};

static int free_bus;			/* First bus not wired down */

extern void ukinit();

static struct scsi_device *device_list;
static int next_free_type = T_NTYPES;

/* Register new functions at the head of the list.  That allows
 * you to replace a standard driver with a new one.
 *
 * You can't register the exact device (the same in memory structure)
 * more than once - the list links are part of the structure.  That is
 * prevented.
 *
 * Unusual devices should always be registered as type "-1".  Then
 * the next available type number will be allocated for it.
 *
 * Be careful not to register a type as 0 unless you really mean to
 * replace the disk driver.
 */

void
scsi_device_register(struct scsi_device *sd)
{
	/* Not only is it pointless to add the same device more than once
	 * but it will also screw up the list.
	 */
	struct scsi_device *is_there;
	for (is_there = device_list; is_there; is_there = is_there->next)
		if (is_there == sd)
			return;

	if (sd->type == -1)
		sd->type = next_free_type++;

	sd->next = device_list;
	device_list = sd;

	if (sd->links == 0)
		sd->links = extend_new();
}

static struct scsi_device *
scsi_device_lookup(int type)
{
	extern struct scsi_device uk_switch;
	struct scsi_device *sd;

	for (sd = device_list; sd; sd = sd->next)
		if (sd->type == type)
			return sd;

	return &uk_switch;
}

static struct scsi_device *
scsi_device_lookup_by_name(char *name)
{
	extern struct scsi_device uk_switch;
	struct scsi_device *sd;

	for (sd = device_list; sd; sd = sd->next)
		if (strcmp(sd->name, name) == 0)
			return sd;

	return &uk_switch;
}

/* Macro that lets us know something is specified.
 */
#define IS_SPECIFIED(ARG) (ARG != SCCONF_UNSPEC && ARG != SCCONF_ANY)

/* scsi_init: Do all the one time processing.  This initializes the
 * type drivers and initializes the configuration.
 */
static void 
scsi_init(void)
{
	static int done = 0;
	if(!done) {
		int i;

		done = 1;

		scbusses = extend_new();

		dev_attach(&kdc_scbus0);

		/* First call all type initialization functions.
		 */
		ukinit();

		for (i = 0; scsi_tinit[i]; i++)
			(*scsi_tinit[i])();

		/* Lowest free bus for auto-configure is one
		 * more than the first one not
		 * specified in config:
		 */
		for (i = 0; scsi_cinit[i].driver; i++)
			if (IS_SPECIFIED(scsi_cinit[i].unit) &&
			  free_bus <= scsi_cinit[i].unit)
				free_bus = scsi_cinit[i].unit + 1;
	
		/* Lowest free unit for each type for auto-configure is one
		 * more than the first one not specified in the config file:
		 */
	 	for (i = 0; scsi_dinit[i].name; i++) {
			struct scsi_device_config *sdc = scsi_dinit + i;
			struct scsi_device *sd =
			 scsi_device_lookup_by_name(sdc->name);

			/* This is a little tricky: We don't want "sd 4" to match as
			 * a wired down device, but we do want "sd 4 target 5" or
			 * even "sd 4 scbus 1" to match.
			 */
			if (IS_SPECIFIED(sdc->unit) &&
			  (IS_SPECIFIED(sdc->target) || IS_SPECIFIED(sdc->cunit)) &&
			  sd->free_unit <= sdc->unit)
				sd->free_unit = sdc->unit + 1;
	 	}
	}
}

/* Feel free to take this out when everyone is sure this config
 * code works well:
 */
#define CONFIGD() printf(" config'd at ")

/* scsi_bus_conf: Figure out which bus this is.  If it is wired in config
 * use that.  Otherwise use the next free one.
 */
static int
scsi_bus_conf(sc_link_proto)
	struct scsi_link *sc_link_proto;
{
	int i;
	int bus;

	/* Which bus is this?  Try to find a match in the "scsi_cinit"
	 * table.  If it isn't wired down auto-configure it at the
	 * next available bus.
	 */

	printf("scbus");
	bus = SCCONF_UNSPEC;
	for (i = 0; scsi_cinit[i].driver; i++) {
		if (IS_SPECIFIED(scsi_cinit[i].unit))
		{
			if (!strcmp(sc_link_proto->adapter->name, scsi_cinit[i].driver) &&
			(sc_link_proto->adapter_unit == scsi_cinit[i].unit) )
			{
				CONFIGD();
				bus = scsi_cinit[i].bus;
				break;
			}
		}
	}

	if (bus == SCCONF_UNSPEC)
		bus = free_bus++;

	printf("%d: ", bus);

	return bus;
}

/* scsi_assign_unit: Look through the structure generated by config.
 * See if there is a fixed assignment for this unit.  If there isn't,
 * assign the next free unit.
 */
static int
scsi_assign_unit(struct scsi_link *sc_link)
{
	int i;
	int found;
	printf("%s", sc_link->device->name);
	found = 0;
 	for (i = 0; scsi_dinit[i].name; i++) {
		if ((strcmp(sc_link->device->name, scsi_dinit[i].name) == 0) &&
		sc_link->target == scsi_dinit[i].target &&
		(
		 (sc_link->lun == scsi_dinit[i].lun) ||
		 (sc_link->lun == 0 && scsi_dinit[i].lun == SCCONF_UNSPEC)
		) &&
		sc_link->scsibus == scsi_dinit[i].cunit) {
			CONFIGD();
			sc_link->dev_unit = scsi_dinit[i].unit;
			found = 1;
			break;
		}
	}

	if (!found)
		sc_link->dev_unit = sc_link->device->free_unit++;

	printf("%d: ", sc_link->dev_unit);

	return sc_link->dev_unit;
}

/*
 * The routine called by the adapter boards to get all their
 * devices configured in.
 */
void
scsi_attachdevs(sc_link_proto)
	struct scsi_link *sc_link_proto;
{
	int scsibus;
	struct scsibus_data *scbus;

	scsi_init();

	if ( (scsibus = scsi_bus_conf(sc_link_proto)) == -1) {
		return;
	}
	sc_link_proto->scsibus = scsibus;
	scbus = malloc(sizeof(struct scsibus_data), M_TEMP, M_NOWAIT);
	if(scbus == 0 || extend_set(scbusses, scsibus, scbus) == 0) {
		panic("scsi_attachdevs: malloc\n");
	}
	bzero(scbus, sizeof(struct scsibus_data));
	scbus->adapter_link = sc_link_proto;
#if defined(SCSI_DELAY) && SCSI_DELAY > 2
	printf("%s%d waiting for scsi devices to settle\n",
	    sc_link_proto->adapter->name, sc_link_proto->adapter_unit);
#else	/* SCSI_DELAY > 2 */
#undef	SCSI_DELAY
#define SCSI_DELAY 2
#endif	/* SCSI_DELAY */
	DELAY(1000000 * SCSI_DELAY);
	scsi_probe_bus(scsibus,-1,-1);
}

/*
 * Probe the requested scsi bus. It must be already set up.
 * -1 requests all set up scsi busses.
 * targ and lun optionally narrow the search if not -1
 */
errval
scsi_probe_busses(int bus, int targ, int lun)
{
	if (bus == -1) {
		for(bus = 0; bus < scbusses->nelem; bus++) {
			scsi_probe_bus(bus, targ, lun);
		}
		return 0;
	} else {
		return scsi_probe_bus(bus, targ, lun);
	}
}

/* scsi_alloc_unit: Register a scsi_data pointer for a given
 * unit in a given scsi_device structure.
 *
 * XXX dufault@hda.com: I still don't like the way this reallocs stuff -
 * but at least now it is collected in one place instead of existing
 * in multiple type drivers.  I'd like it better if we had it do a
 * second pass after it knew the sizes of everything and set up everything
 * at once.
 */
static int
scsi_alloc_unit(struct scsi_link *sc_link)
{
	u_int32 unit;
	struct scsi_link **strealloc;
	struct scsi_data *sd;
	struct scsi_device *dsw;

	unit = sc_link->dev_unit;
	dsw = sc_link->device;

	/*
	 * allocate the per unit data area
	 */
	if (dsw->sizeof_scsi_data)
	{
		sd = malloc(dsw->sizeof_scsi_data, M_DEVBUF, M_NOWAIT);
		if (!sd) {
			printf("%s%ld: malloc failed for scsi_data\n",
				sc_link->device->name, unit);
			return 0;
		}
		bzero(sd, dsw->sizeof_scsi_data);
	}
	else
		sd = 0;

	sc_link->sd = sd;

	if (extend_set(dsw->links, unit, (void *)sc_link) == 0) {
		printf("%s%ld: Can't store link pointer.\n",
		sc_link->device->name, unit);
		free(sd, M_DEVBUF);
		return 0;
	}

	return 1;
}

static void
scsi_free_unit(struct scsi_link *sc_link)
{
	if (sc_link->sd)
	{
		free(sc_link->sd, M_DEVBUF);
		sc_link->sd = 0;
	}
	extend_release(sc_link->device->links, sc_link->dev_unit);
}

/*
 * Probe the requested scsi bus. It must be already set up.
 * targ and lun optionally narrow the search if not -1
 */
errval
scsi_probe_bus(int bus, int targ, int lun)
{
	struct scsibus_data *scsi ;
	int	maxtarg,mintarg,maxlun,minlun;
	struct scsi_link *sc_link_proto;
	u_int8  scsi_addr ;
	struct scsidevs *bestmatch = NULL;
	struct scsi_link *sc_link = NULL;
	boolean maybe_more;

	if ((bus < 0 ) || ( bus >= scbusses->nelem)) {
		return ENXIO;
	}
	scsi = (struct scsibus_data *)extend_get(scbusses, bus);
	if(!scsi) return ENXIO;
	sc_link_proto = scsi->adapter_link;
	scsi_addr = sc_link_proto->adapter_targ;
	if(targ == -1){
		maxtarg = 7;
		mintarg = 0;
	} else {
		if((targ < 0 ) || (targ > 7)) return EINVAL;
		maxtarg = mintarg = targ;
	}

	if(lun == -1){
		maxlun = 7;
		minlun = 0;
	} else {
		if((lun < 0 ) || (lun > 7)) return EINVAL;
		maxlun = minlun = lun;
	}

	for ( targ = mintarg;targ <= maxtarg; targ++) {
		maybe_more = 0;	/* by default only check 1 lun */
		if (targ == scsi_addr) {
			continue;
		}
		for ( lun = minlun; lun <= maxlun ;lun++) {
			/*
			 * The spot appears to already have something
			 * linked in, skip past it. Must be doing a 'reprobe'
			 */
			if(scsi->sc_link[targ][lun])
			{/* don't do this one, but check other luns */
				maybe_more = 1;
				continue;
			}
			/*
			 * If we presently don't have a link block
			 * then allocate one to use while probing
			 */
			if (!sc_link) {
				sc_link = malloc(sizeof(*sc_link), M_TEMP, M_NOWAIT);
			}
			*sc_link = *sc_link_proto;	/* struct copy */
			sc_link->opennings = 1;
			sc_link->device = &inval_switch;
			sc_link->target = targ;
			sc_link->lun = lun;
			sc_link->quirks = 0;
			bestmatch = scsi_probedev(sc_link, &maybe_more);
#ifdef NEW_SCSICONF
			if (bestmatch) {
			    sc_link->quirks = bestmatch->quirks;
			    sc_link->devmodes = bestmatch->devmodes;
			} else {
			    sc_link->quirks = 0;
			    sc_link->devmodes = NULL;
			}
#endif
			if (bestmatch) {		/* FOUND */
				sc_link->device = scsi_device_lookup(bestmatch->type);

				(void)scsi_assign_unit(sc_link);
				
				if (scsi_alloc_unit(sc_link)) {

					if (scsi_device_attach(sc_link) == 0) {
						scsi->sc_link[targ][lun] = sc_link;
						sc_link = NULL;		/* it's been used */
					}
					else
						scsi_free_unit(sc_link);
				}
			}

			if (!(maybe_more)) {	/* nothing suggests we'll find more */
				break;				/* nothing here, skip to next targ */
			}
			/* otherwise something says we should look further */
		}
	}
	if (sc_link) {
		free(sc_link, M_TEMP);
	}
	return 0;
}

/* Return the scsi_link for this device, if any.
 */
struct scsi_link *
scsi_link_get(bus, targ, lun)
	int bus;
	int targ;
	int lun;
{
	struct scsibus_data *scsi =
	 (struct scsibus_data *)extend_get(scbusses, bus);
	return (scsi) ? scsi->sc_link[targ][lun] : 0;
}
/*
 * given a target and lu, ask the device what
 * it is, and find the correct driver table
 * entry.
 */
struct scsidevs *
scsi_probedev(sc_link, maybe_more)
	boolean *maybe_more;
	struct scsi_link *sc_link;
{
	u_int8  unit = sc_link->adapter_unit;
	u_int8  target = sc_link->target;
	u_int8  lu = sc_link->lun;
	struct scsi_adapter *scsi_adapter = sc_link->adapter;
	struct scsidevs *bestmatch = (struct scsidevs *) 0;
	char   *dtype = (char *) 0, *desc;
	char   *qtype;
	struct scsi_inquiry_data *inqbuf;
	u_int32 len, qualifier, type;
	boolean remov;
	char    manu[32];
	char    model[32];
	char    version[32];
	int	z;

 	inqbuf = &sc_link->inqbuf;
 
 	bzero(inqbuf, sizeof(*inqbuf));
	/*
	 * Ask the device what it is
	 */
#ifdef	SCSIDEBUG
	if ((target == DEBUGTARG) && (lu == DEBUGLUN))
		sc_link->flags |= (DEBUGLEVEL);
	else
		sc_link->flags &= ~(SDEV_DB1 | SDEV_DB2 | SDEV_DB3 | SDEV_DB4);
#endif	/* SCSIDEBUG */
	/* catch unit attn */
	scsi_test_unit_ready(sc_link, SCSI_NOSLEEP | SCSI_NOMASK | SCSI_SILENT);
#ifdef	DOUBTFULL
	switch (scsi_test_unit_ready(sc_link, SCSI_NOSLEEP | SCSI_NOMASK | SCSI_SILENT)) {
	case 0:		/* said it WAS ready */
	case EBUSY:		/* replied 'NOT READY' but WAS present, continue */
	case ENXIO:
		break;
	case EIO:		/* device timed out */
	case EINVAL:		/* Lun not supported */
	default:
		return (struct scsidevs *) 0;

	}
#endif	/*DOUBTFULL*/
#ifdef	SCSI_2_DEF
	/* some devices need to be told to go to SCSI2 */
	/* However some just explode if you tell them this.. leave it out */
	scsi_change_def(sc_link, SCSI_NOSLEEP | SCSI_NOMASK | SCSI_SILENT);
#endif /*SCSI_2_DEF */

	/* Now go ask the device all about itself */
	if (scsi_inquire(sc_link, inqbuf, SCSI_NOSLEEP | SCSI_NOMASK) != 0) {
		return (struct scsidevs *) 0;
	}

	/*
	 * note what BASIC type of device it is
	 */
	type = inqbuf->device & SID_TYPE;
	qualifier = inqbuf->device & SID_QUAL;
	remov = inqbuf->dev_qual2 & SID_REMOVABLE;

	/*
	 * Any device qualifier that has the top bit set (qualifier&4 != 0)
	 * is vendor specific and won't match in this switch.
	 */

	switch ((int)qualifier) {
	case SID_QUAL_LU_OK:
		qtype = "";
		break;

	case SID_QUAL_LU_OFFLINE:
		qtype = ", Unit not Connected!";
		break;

	case SID_QUAL_RSVD:
		qtype = ", Reserved Peripheral Qualifier!";
		*maybe_more = 1;
		return (struct scsidevs *) 0;
		break;

	case SID_QUAL_BAD_LU:
		/*
		 * Check for a non-existent unit.  If the device is returning
		 * this much, then we must set the flag that has
		 * the searchers keep looking on other luns.
		 */
		qtype = ", The Target can't support this Unit!";
		*maybe_more = 1;
		return (struct scsidevs *) 0;

	default:
		dtype = "vendor specific";
		qtype = "";
		*maybe_more = 1;
		break;
	}

	if (dtype == 0) {
		if (type == T_NODEVICE) {
			*maybe_more = 1;
			return (struct scsidevs *) 0;
		}
		dtype = scsi_type_long_name(type);
	}
	/*
	 * Then if it's advanced enough, more detailed
	 * information
	 */
	if ((inqbuf->version & SID_ANSII) > 0) {
		if ((len = inqbuf->additional_length
			+ ((char *) inqbuf->unused
			    - (char *) inqbuf))
		    > (sizeof(struct scsi_inquiry_data) - 1))
			        len = sizeof(struct scsi_inquiry_data) - 1;
		desc = inqbuf->vendor;
		desc[len - (desc - (char *) inqbuf)] = 0;
		strncpy(manu, inqbuf->vendor, 8);
		strncpy(model, inqbuf->product, 16);
		strncpy(version, inqbuf->revision, 4);
		for(z = 0; z < 4; z++) {
			if (version[z]<' ') version[z]='?';
		}
	} else
		/*
		 * If not advanced enough, use default values
		 */
	{
		desc = "early protocol device";
		strncpy(manu, "unknown", 8);
		strncpy(model, "unknown", 16);
		strncpy(version, "????", 4);
	}
	manu[8] = 0;
	model[16] = 0;
	version[4] = 0;
	printf("%s%d targ %d lun %d: type %ld(%s) %s SCSI%d\n"
	    ,scsi_adapter->name
	    ,unit
	    ,target
	    ,lu
	    ,type
	    ,dtype
	    ,remov ? "removable" : "fixed"
	    ,inqbuf->version & SID_ANSII
	    );
	printf("%s%d targ %d lun %d: <%s%s%s>\n"
	    ,scsi_adapter->name
	    ,unit
	    ,target
	    ,lu
	    ,manu
	    ,model
	    ,version
	    );
	if (qtype[0]) {
		printf("%s%d targ %d lun %d: qualifier %ld(%s)\n"
		    ,scsi_adapter->name
		    ,unit
		    ,target
		    ,lu
		    ,qualifier
		    ,qtype
		    );
	}
	/*
	 * Try make as good a match as possible with
	 * available sub drivers       
	 */
	bestmatch = (scsi_selectdev(
		qualifier, type, remov ? T_REMOV : T_FIXED, manu, model, version));
	if ((bestmatch) && (bestmatch->flags & SC_MORE_LUS)) {
		*maybe_more = 1;
	}
	return bestmatch;
}

/* Try to find the major number for a device during attach.
 */
dev_t
scsi_dev_lookup(d_open)
	int (*d_open)();
{
	int i;

	dev_t d = NODEV;

	for (i = 0; i < nchrdev; i++)
		if (cdevsw[i].d_open == d_open)
		{
			d = makedev(i, 0);
			break;
		}

	return d;
}

#ifdef NEW_SCSICONF
/*
 * Compare name with pattern, return 0 on match.
 * Short pattern matches trailing blanks in name, 
 * wildcard '*' in pattern matches rest of name
 */
int
match(pattern, name)
	char *pattern;
	char *name;
{
	char c;
	while (c = *pattern++)
	{
		if (c == '*') return 0;
		if (c != *name++) return 1;
	}
	while (c = *name++)
	{
		if (c != ' ') return 1;
	}
	return 0;
}
#endif

/*
 * Try make as good a match as possible with
 * available sub drivers       
 */
struct scsidevs *
scsi_selectdev(qualifier, type, remov, manu, model, rev)
	u_int32 qualifier, type;
	boolean remov;
	char   *manu, *model, *rev;
{
#ifdef NEW_SCSICONF
	struct scsidevs *bestmatch = NULL;
	struct scsidevs *thisentry;

	type |= qualifier;	/* why? */

	for ( thisentry = knowndevs; thisentry->manufacturer; thisentry++ )
	{
		if (type != thisentry->type) {
			continue;
		}
		if (remov != thisentry->removable) {
			continue;
		}

		if (thisentry->flags & SC_SHOWME)
			printf("\n%s-\n%s-", thisentry->manufacturer, manu);
		if (match(thisentry->manufacturer, manu)) {
			continue;
		}
		if (thisentry->flags & SC_SHOWME)
			printf("\n%s-\n%s-", thisentry->model, model);
		if (match(thisentry->model, model)) {
			continue;
		}
		if (thisentry->flags & SC_SHOWME)
			printf("\n%s-\n%s-", thisentry->version, rev);
		if (match(thisentry->version, rev)) {
			continue;
		}
		bestmatch = thisentry;
		break;
	}
#else
	u_int32 numents = (sizeof(knowndevs) / sizeof(struct scsidevs)) - 1;
	u_int32 count = 0;
	u_int32 bestmatches = 0;
	struct scsidevs *bestmatch = (struct scsidevs *) 0;
	struct scsidevs *thisentry = knowndevs;

	type |= qualifier;	/* why? */

	thisentry--;
	while (count++ < numents) {
		thisentry++;
		if (type != thisentry->type) {
			continue;
		}
		if (bestmatches < 1) {
			bestmatches = 1;
			bestmatch = thisentry;
		}
		if (remov != thisentry->removable) {
			continue;
		}
		if (bestmatches < 2) {
			bestmatches = 2;
			bestmatch = thisentry;
		}
		if (thisentry->flags & SC_SHOWME)
			printf("\n%s-\n%s-", thisentry->manufacturer, manu);
		if (strcmp(thisentry->manufacturer, manu)) {
			continue;
		}
		if (bestmatches < 3) {
			bestmatches = 3;
			bestmatch = thisentry;
		}
		if (thisentry->flags & SC_SHOWME)
			printf("\n%s-\n%s-", thisentry->model, model);
		if (strcmp(thisentry->model, model)) {
			continue;
		}
		if (bestmatches < 4) {
			bestmatches = 4;
			bestmatch = thisentry;
		}
		if (thisentry->flags & SC_SHOWME)
			printf("\n%s-\n%s-", thisentry->version, rev);
		if (strcmp(thisentry->version, rev)) {
			continue;
		}
		if (bestmatches < 5) {
			bestmatches = 5;
			bestmatch = thisentry;
			break;
		}
	}
#endif /* NEW_SCSICONF */
	if (bestmatch == (struct scsidevs *) 0) {
	/* XXX At this point we should default to a base type driver.
	 */
		printf("No explicit driver match.  Attaching as unknown.\n");
		bestmatch = &unknowndev;
	}
	return (bestmatch);
}

int
scsi_externalize(struct scsi_link *sl, void *userp, size_t *lenp)
{
	if(*lenp < sizeof *sl)
		return ENOMEM;

	*lenp -= sizeof *sl;

	return copyout(sl, userp, sizeof *sl);
}

/* XXX dufault@hda.com:
 *  having this table of names conflicts with our decision
 *  that all type information be contained in a type driver.
 */
static struct {char *name; char *long_name; } types[] = {
	{ "sd", "direct" },
	{ "st", "sequential" },
	{ "prn", "printer" },
	{ "proc", "processor" },
	{ "worm", "worm" },
	{ "cd", "readonly" },
	{ "scan", "scanner" },
	{ "opmem", "optical" },
	{ "ch", "changer" },
	{ "comm", "communication" },
	{ "asc0", "ASC-0" },
	{ "asc1", "ASC-1" },
	{ "uk", "unknown" },
	{ "inval", "invalid" },
};

char *
scsi_type_name(int type)
{
	if (type >= 0 && type < (sizeof(types) / sizeof(types[0])))
		return types[type].name;

	return "inval";
}

char *
scsi_type_long_name(int type)
{
	if (type >= 0 && type < (sizeof(types) / sizeof(types[0])))
		return types[type].long_name;

	return "invalid";
}

