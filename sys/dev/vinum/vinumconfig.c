/* To do:

 * Don't store drive configuration on the config DB: read each drive's header
 * to decide where it is.
 *
 * Accept any old crap in the config_<foo> functions, and complain when
 * we try to bring it up.
 *
 * When trying to bring volumes up, check that the complete address range
 * is covered.
 */
/*-
 * Copyright (c) 1997, 1998
 *	Nan Yang Computer Services Limited.  All rights reserved.
 *
 *  This software is distributed under the so-called ``Berkeley
 *  License'':
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Nan Yang Computer
 *      Services Limited.
 * 4. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even if
 * advised of the possibility of such damage.
 *
 * $Id: config.c,v 1.19 1998/10/05 02:48:15 grog Exp grog $
 */

#define STATIC						    /* nothing while we're testing XXX */

#define REALLYKERNEL
#include "vinumhdr.h"

extern jmp_buf command_fail;				    /* return on a failed command */

#if __FreeBSD__ >= 3
/* Why aren't these declared anywhere? XXX */
void longjmp(jmp_buf, int);
#endif

#define MAXTOKEN 64					    /* maximum number of tokens in a line */

/* We can afford the luxury of global variables here,
 * since start_config ensures that these functions
 * are single-threaded. */

/* These are indices in vinum_conf of the last-mentioned of each kind of object */
static int current_drive = -1;				    /* note the last drive we mention, for
							    * some defaults */
static int current_plex = -1;				    /* and the same for the last plex */
static int current_volume = -1;				    /* and the last volme */
static struct _ioctl_reply *ioctl_reply;		    /* struct to return via ioctl */


/* These values are used by most of these routines, so set them as globals */
static char *token[MAXTOKEN];				    /* pointers to individual tokens */
static int tokens;					    /* number of tokens */

#define TOCONS	0x01
#define TOTTY	0x02
#define TOLOG	0x04

struct putchar_arg {
    int flags;
    struct tty *tty;
};

#define MSG_MAX 1024					    /* maximum length of a formatted message */
/* Format an error message and return to the user in the reply.
 * CARE: This routine is designed to be called only from the
 * configuration routines, so it assumes it's the owner of
 * the configuration lock, and unlocks it on exit */
void 
throw_rude_remark(int error, char *msg,...)
{
    BROKEN_GDB;
    int retval;
    va_list ap;
    char *text;
    static int finishing;				    /* don't recurse */
    int was_finishing;

    va_start(ap, msg);
    if ((ioctl_reply != NULL)				    /* we're called from the user */
    &&(!(vinum_conf.flags & VF_KERNELOP))) {		    /* and we're not doing kernel things: return msg */
	/* XXX We can't just format to ioctl_reply, since it
	 * may contain our input parameters */
	text = Malloc(MSG_MAX);
	if (text == NULL) {
	    printf("vinum: can't allocate error message buffer");
	    printf("vinum: ");
	    vprintf(msg, ap);				    /* print to the console */
	    printf("\n");
	} else {
	    retval = kvprintf(msg, NULL, (void *) text, 10, ap);
	    text[retval] = '\0';			    /* delimit */
	    strcpy(ioctl_reply->msg, text);
	    ioctl_reply->error = error;			    /* first byte is the error number */
	    Free(text);
	}
    } else {
	printf("vinum: ");
	vprintf(msg, ap);				    /* print to the console */
	printf("\n");
    }
    va_end(ap);

    if (vinum_conf.flags & VF_READING_CONFIG)		    /* go through to the bitter end, */
	return;
    /* We have a problem here: we want to unlock the
     * configuration, which implies tidying up, but
     * if we find an error while tidying up, we could
     * recurse for ever.  Use this kludge to only try
     * once */
    was_finishing = finishing;
    finishing = 1;
    finish_config(was_finishing);			    /* unlock anything we may be holding */
    finishing = was_finishing;
    longjmp(command_fail, error);
}

/* Function declarations */
int atoi(char *);					    /* no atoi in the kernel */

/* Minimal version of atoi */
int 
atoi(char *s)
{							    /* no atoi in the kernel */
    BROKEN_GDB;
    int r = 0;
    int sign = 1;

    while (((*s >= '0') && (*s <= '9')) || (*s == '-')) {
	if (*s == '-')
	    sign = -sign;
	else
	    r = r * 10 + (*s - '0');
    }
    return r;
}

/* Find index of volume in vinum_conf.  Return the index
 * if found, or -1 if not */
int 
volume_index(struct volume *vol)
{
    BROKEN_GDB;
    int i;

    for (i = 0; i < vinum_conf.volumes_used; i++)
	if (&VOL[i] == vol)
	    return i;
    return -1;
}

/* Find index of plex in vinum_conf.  Return the index
 * if found, or -1 if not */
int 
plex_index(struct plex *plex)
{
    BROKEN_GDB;
    int i;

    for (i = 0; i < vinum_conf.plexes_used; i++)
	if (&PLEX[i] == plex)
	    return i;
    return -1;
}

/* Find index of subdisk in vinum_conf.  Return the index
 * if found, or -1 if not */
int 
sd_index(struct sd *sd)
{
    BROKEN_GDB;
    int i;

    for (i = 0; i < vinum_conf.subdisks_used; i++)
	if (&SD[i] == sd)
	    return i;
    return -1;
}

/* Find index of drive in vinum_conf.  Return the index
 * if found, or -1 if not */
int 
drive_index(struct drive *drive)
{
    BROKEN_GDB;
    int i;

    for (i = 0; i < vinum_conf.drives_used; i++)
	if (&DRIVE[i] == drive)
	    return i;
    return -1;
}

/* Check a volume to see if the plex is already assigned to it.
 * Return index in volume->plex, or -1 if not assigned */
int 
my_plex(int volno, int plexno)
{
    BROKEN_GDB;
    int i;
    struct volume *vol;

    vol = &VOL[volno];					    /* point to volno */
    for (i = 0; i < vol->plexes; i++)
	if (vol->plex[i] == plexno)
	    return i;
    return -1;						    /* not found */
}

/* Check a plex to see if the subdisk is already assigned to it.
 * Return index in plex->sd, or -1 if not assigned */
int 
my_sd(int plexno, int sdno)
{
    BROKEN_GDB;
    int i;
    struct plex *plex;

    plex = &PLEX[plexno];
    for (i = 0; i < plex->subdisks; i++)
	if (plex->sdnos[i] == sdno)
	    return i;
    return -1;						    /* not found */
}

/* Check that this operation is being done in the kernel.
 * longjmp out if not.  op the name of the operation. */
void 
checkkernel(char *op)
{
    BROKEN_GDB;
    if (vinum_conf.flags & VF_KERNELOP == 0)
	throw_rude_remark(EPERM, "Can't perform '%s' from user space", op);
}

/* Add plex to the volume if possible */
int 
give_plex_to_volume(int volno, int plexno)
{
    BROKEN_GDB;
    struct volume *vol;

    /* XXX It's not an error for the plex to already
     * belong to the volume, but we need to check a
     * number of things to make sure it's done right.
     * Some day. */
    if (my_plex(volno, plexno) >= 0)
	return plexno;					    /* that's it */

    vol = &VOL[volno];					    /* point to volume */
    if (vol->plexes == MAXPLEX)				    /* all plexes allocated */
	throw_rude_remark(ENOSPC,
	    "Too many plexes for volume %s",
	    vol->name);
    vol->plex[vol->plexes] = plexno;			    /* this one */
    vol->plexes++;					    /* add another plex */
    PLEX[plexno].volno = volno;				    /* note the number of our volume */

    return vol->plexes - 1;				    /* and return its index */
}

/* Add subdisk to a plex if possible */
int 
give_sd_to_plex(int plexno, int sdno)
{
    BROKEN_GDB;
    int i;
    struct plex *plex;
    struct sd *sd;

    /* XXX It's not an error for the sd to already
     * belong to the plex, but we need to check a
     * number of things to make sure it's done right.
     * Some day. */
    i = my_sd(plexno, sdno);
    if (i >= 0)						    /* does it already belong to us? */
	return i;					    /* that's it */

    plex = &PLEX[plexno];				    /* point to the plex */
    sd = &SD[sdno];					    /* and the subdisk */

    /* Do we have an offset?  Otherwise put it after the last one */
    if (sd->plexoffset < 0) {				    /* no offset specified */
	if (plex->subdisks > 0) {
	    struct sd *lastsd = &SD[plex->sdnos[plex->subdisks - 1]]; /* last subdisk */
	    sd->plexoffset = lastsd->sectors + lastsd->plexoffset; /* take it */
	} else						    /* first subdisk */
	    sd->plexoffset = 0;				    /* start at the beginning */
    }
    if (plex->subdisks == MAXSD)			    /* we already have our maximum */
	throw_rude_remark(ENOSPC,			    /* crap out */
	    "Can't add %s to %s: plex full\n",
	    sd->name,
	    plex->name);

    plex->subdisks++;					    /* another entry */
    if (plex->subdisks >= plex->subdisks_allocated)	    /* need more space */
	EXPAND(plex->sdnos, int, plex->subdisks_allocated, INITIAL_SUBDISKS_IN_PLEX);

    /* XXX I'm not sure this makes any sense
     * for anything except concatenated plexes,
     * and it comes up with the wrong answer for
     * RAID-5 plexes, but it's currently needed
     * for the calculations.  We'll adjust for
     * RAID-5 in config_plex */
    if ((sd->sectors + sd->plexoffset) > plex->length) {    /* gone beyond the end of the plex */
	plex->length = sd->sectors + sd->plexoffset;	    /* adjust the length */

	if ((plex->volno >= 0)				    /* we have a volume */
	&&(plex->length > VOL[plex->volno].size))	    /* and we're now the longest plex */
	    VOL[plex->volno].size = plex->length;	    /* increase the size of the volume */
    }
    /* We need to check that the subdisks don't overlap,
     * but we can't do that until a point where we *must*
     * know the size of all the subdisks.  That's not
     * here.  But we need to sort them by offset */
    for (i = 0; i < plex->subdisks - 1; i++) {
	if (sd->plexoffset < SD[plex->sdnos[i]].plexoffset) { /* it fits before this one */
	    /* First move any remaining subdisks by one */
	    int j;

	    for (j = plex->subdisks - 1; j > i; j--)	    /* move up one at a time */
		plex->sdnos[j] = plex->sdnos[j - 1];
	    plex->sdnos[i] = sdno;
	    return i;
	}
    }

    /* The plex doesn't have any subdisk with a larger
     * offset.  Insert it */
    plex->sdnos[i] = sdno;
    return i;
}

/* Add a subdisk to drive if possible.  The pointer to the drive
 * must already be stored in the sd structure, but the drive
 * doesn't know about the subdisk yet.  */
static void 
give_sd_to_drive(int sdno)
{
    BROKEN_GDB;
    struct sd *sd;					    /* pointer to subdisk */
    struct drive *drive;				    /* and drive */
    int fe;						    /* index in free list */

    sd = &SD[sdno];					    /* point to sd */
    drive = &DRIVE[sd->driveno];			    /* and drive */

    if (drive->state != drive_up)			    /* not up */
	throw_rude_remark(EIO, "Drive %s is not accessible", drive->label.name);
    else if (sd->sectors > drive->sectors_available) {	    /* too big, */
	sd->driveoffset = -1;				    /* don't be confusing */
	throw_rude_remark(ENOSPC, "No space for %s on %s", sd->name, drive->label.name);
    }
    drive->subdisks_used++;				    /* one more subdisk */

    /* no offset specified, find one */
    if (sd->driveoffset < 0) {
	for (fe = 0; fe < drive->freelist_entries; fe++) {
	    if (drive->freelist[fe].sectors >= sd->sectors) { /* it'll fit here */
		sd->driveoffset = drive->freelist[fe].offset;
		if (sd->sectors == drive->freelist[fe].sectors) { /* used up the entire entry */
		    if (fe < (drive->freelist_entries - 1)) /* not the last one, */
			bcopy(&drive->freelist[fe + 1],
			    &drive->freelist[fe],
			    (drive->freelist_entries - fe) * sizeof(struct drive_freelist));
		    drive->freelist_entries--;		    /* one less entry */
		} else {
		    drive->freelist[fe].sectors -= sd->sectors;	/* this much less space */
		    drive->freelist[fe].offset += sd->sectors; /* this much further on */
		}
		drive->sectors_available -= sd->sectors;    /* and note how much less space we have */
		break;
	    }
	}
	if (fe == drive->freelist_entries)
	    /* Didn't find anything.  Although the drive has
	     * enough space, it's too fragmented */
	{
	    sd->driveoffset = -1;			    /* don't be confusing */
	    throw_rude_remark(ENOSPC, "No space for %s on %s", sd->name, drive->label.name);
	}
    } else {						    /* specific offset */
	/* For a specific offset to work, the space must be
	 * entirely in a single freelist entry.  Look for it. */
	u_int64_t sdend = sd->driveoffset + sd->sectors;    /* end of our subdisk */
	for (fe = 0; fe < drive->freelist_entries; fe++) {
	    u_int64_t dend = drive->freelist[fe].offset + drive->freelist[fe].sectors; /* end of entry */
	    if (dend >= sdend) {			    /* fits before here */
		if (drive->freelist[fe].offset > sd->driveoffset) /* starts after the beginning of sd area */
		    throw_rude_remark(ENOSPC,
			"No space for subdisk %s on drive %s at offset %qd\n",
			sd->name,
			drive->label.name);

		/* We've found the space, and we can allocate it.
		 * We don't need to say that to the subdisk, which
		 * already knows about it.  We need to tell it to
		 * the free list, though.  We have four possibilities:
		 *
		 * 1.  The subdisk exactly eats up the entry.  That's the
		 *     same as above.
		 * 2.  The subdisk starts at the beginning and leaves space
		 *     at the end.
		 * 3.  The subdisk starts after the beginning and leaves
		 *     space at the end as well: we end up with another
		 *     fragment.
		 * 4.  The subdisk leaves space at the beginning and finishes
		 *     at the end.
		 */
		drive->sectors_available -= sd->sectors;    /* note how much less space we have */
		if (sd->driveoffset == drive->freelist[fe].offset) { /* 1 or 2 */
		    if (sd->sectors == drive->freelist[fe].sectors) { /* 1: used up the entire entry */
			if (fe < (drive->freelist_entries - 1))	/* not the last one, */
			    bcopy(&drive->freelist[fe + 1],
				&drive->freelist[fe],
				(drive->freelist_entries - fe) * sizeof(struct drive_freelist));
			drive->freelist_entries--;	    /* one less entry */
		    } else {				    /* 2: space at the end */
			drive->freelist[fe].sectors -= sd->sectors; /* this much less space */
			drive->freelist[fe].offset += sd->sectors; /* this much further on */
		    }
		} else {				    /* 3 or 4 */
		    drive->freelist[fe].sectors = sd->driveoffset - drive->freelist[fe].offset;
		    if (dend > sdend) {			    /* 3: space at the end as well */
			if (fe < (drive->freelist_entries - 1))	/* not the last one */
			    bcopy(&drive->freelist[fe],	    /* move the rest down */
				&drive->freelist[fe + 1],
				(drive->freelist_entries - fe) * sizeof(struct drive_freelist));
			drive->freelist_entries++;	    /* one less entry */
			drive->freelist[fe + 1].offset = sdend;	/* second entry starts after sd */
			drive->freelist[fe + 1].sectors = dend - sdend;	/* and is this long */
		    }
		}
		break;
	    }
	}
    }
    drive->opencount++;					    /* one more subdisk attached */
}

/* Get an empty drive entry from the drive table */
int 
get_empty_drive(void)
{
    BROKEN_GDB;
    int driveno;
    struct drive *drive;

    /* first see if we have one which has been deallocated */
    for (driveno = 0; driveno < vinum_conf.drives_used; driveno++) {
	if (DRIVE[driveno].state == drive_unallocated)	    /* bingo */
	    break;
    }

    if (driveno >= vinum_conf.drives_used)
	/* Couldn't find a deallocated drive.  Allocate a new one */
    {
	vinum_conf.drives_used++;
	if (vinum_conf.drives_used > vinum_conf.drives_allocated) /* we've used all our allocation */
	    EXPAND(DRIVE, struct drive, vinum_conf.drives_allocated, INITIAL_DRIVES);
    }
    /* got a drive entry.  Make it pretty */
    drive = &DRIVE[driveno];
    bzero(drive, sizeof(struct drive));
    drive->driveno = driveno;				    /* put number in structure */
    return driveno;					    /* return the index */
}

/* Find the named drive in vinum_conf.drive, return a pointer
 * return the index in vinum_conf.drive.
 * Don't mark the drive as allocated (XXX SMP)
 * If create != 0, create an entry if it doesn't exist
 */
/* XXX check if we have it open from attach */
int 
find_drive(const char *name, int create)
{
    BROKEN_GDB;
    int driveno;
    struct drive *drive;

    if (name != NULL) {
	for (driveno = 0; driveno < vinum_conf.drives_used; driveno++) {
	    drive = &DRIVE[driveno];			    /* point to drive */
	    if ((drive->label.name[0] != '\0')		    /* it has a name */
	    &&(strcmp(drive->label.name, name) == 0))	    /* and it's this one: found */
		return driveno;
	}
    }
    /* the drive isn't in the list.  Add it if he wants */
    if (create == 0)					    /* don't want to create */
	return -1;					    /* give up */

    driveno = get_empty_drive();
    drive = &DRIVE[driveno];
    if (name != NULL)
	bcopy(name,					    /* put in its name */
	    drive->label.name,
	    min(sizeof(drive->label.name),
		strlen(name)));
    drive->state = drive_uninit;			    /* in use, nothing worthwhile there */
    return driveno;					    /* return the index */
}

/* Find a drive given its device name.
 * devname must be valid.
 * Otherwise the same as find_drive above */
int 
find_drive_by_dev(const char *devname, int create)
{
    BROKEN_GDB;
    int driveno;
    struct drive *drive;

    for (driveno = 0; driveno < vinum_conf.drives_used; driveno++) {
	drive = &DRIVE[driveno];			    /* point to drive */
	if ((drive->label.name[0] != '\0')		    /* it has a name */
	&&(strcmp(drive->label.name, devname) == 0))	    /* and it's this one: found */
	    return driveno;
    }

    /* the drive isn't in the list.  Add it if he wants */
    if (create == 0)					    /* don't want to create */
	return -1;					    /* give up */

    driveno = get_empty_drive();
    drive = &DRIVE[driveno];
    bcopy(devname,					    /* put in its name */
	drive->devicename,
	min(sizeof(drive->devicename),
	    strlen(devname)));
    drive->state = drive_uninit;			    /* in use, nothing worthwhile there */
    return driveno;					    /* return the index */
}

/* Find an empty subdisk in the subdisk table */
int 
get_empty_sd(void)
{
    BROKEN_GDB;
    int sdno;
    struct sd *sd;

    /* first see if we have one which has been deallocated */
    for (sdno = 0; sdno < vinum_conf.subdisks_used; sdno++) {
	if (SD[sdno].state == sd_unallocated)		    /* bingo */
	    break;
    }

    if (sdno >= vinum_conf.subdisks_used) {		    /* No unused sd found.  Allocate a new one */
	vinum_conf.subdisks_used++;
	if (vinum_conf.subdisks_used > vinum_conf.subdisks_allocated)
	    EXPAND(SD, struct sd, vinum_conf.subdisks_allocated, INITIAL_SUBDISKS);
    }
    /* initialize some things */
    sd = &SD[sdno];					    /* point to it */
    bzero(sd, sizeof(struct sd));			    /* initialize */
    sd->plexno = -1;					    /* no plex */
    sd->driveno = -1;					    /* and no drive */
    sd->plexoffset = -1;				    /* and no offsets */
    sd->driveoffset = -1;
    return sdno;					    /* return the index */
}

/* return a drive to the free pool */
void 
free_drive(struct drive *drive)
{
    BROKEN_GDB;
    if (drive->vp != NULL)				    /* device open */
	vn_close(drive->vp, FREAD | FWRITE, FSCRED, drive->p);
    bzero(drive, sizeof(struct drive));			    /* this also sets drive_unallocated */
    vinum_conf.drives_used--;				    /* one less drive */
}

/* Find the named subdisk in vinum_conf.sd.

 * If create != 0, create an entry if it doesn't exist
 *
 * Return index in vinum_conf.sd
 */
int 
find_subdisk(const char *name, int create)
{
    BROKEN_GDB;
    int sdno;
    struct sd *sd;

    for (sdno = 0; sdno < vinum_conf.subdisks_allocated; sdno++) {
	if (strcmp(SD[sdno].name, name) == 0)		    /* found it */
	    return sdno;
    }

    /* the subdisk isn't in the list.  Add it if he wants */
    if (create == 0)					    /* don't want to create */
	return -1;					    /* give up */

    /* Allocate one and insert the name */
    sdno = get_empty_sd();
    sd = &SD[sdno];
    bcopy(name, sd->name, min(sizeof(sd->name), strlen(name)));	/* put in its name */
    return sdno;					    /* return the pointer */
}

/* Free an allocated sd entry
 * This performs memory management only.  remove()
 * is responsible for checking relationships.
 */
void 
free_sd(int sdno)
{
    BROKEN_GDB;
    struct sd *sd;
    struct drive *drive;
    int fe;						    /* free list entry */
    u_int64_t sdend;					    /* end of our subdisk */
    u_int64_t dend;					    /* end of our freelist entry */

    sd = &SD[sdno];
    if ((sd->driveno >= 0)				    /* we have a drive, */
    &&(sd->sectors > 0)) {				    /* and some space on it */
	drive = &DRIVE[sd->driveno];
	sdend = sd->driveoffset + sd->sectors;		    /* end of our subdisk */

	/* Look for where to return the sd address space */
	for (fe = 0;
	    (fe < drive->freelist_entries) && (drive->freelist[fe].offset < sd->driveoffset);
	    fe++);
	/* Now we are pointing to the last entry, the first
	 * with a higher offset than the subdisk, or both. */
	if ((fe > 1)					    /* not the first entry */
	&&((fe == drive->freelist_entries)		    /* gone past the end */
	||(drive->freelist[fe].offset > sd->driveoffset)))  /* or past the block were looking for */
	    fe--;					    /* point to the block before */
	dend = drive->freelist[fe].offset + drive->freelist[fe].sectors; /* end of the entry */

	/* At this point, we are pointing to the correct
	 * place in the free list.  A number of possibilities
	 * exist:
	 *
	 * 1.  The block to be freed immediately follows
	 *     the block to which we are pointing.  Just
	 *     enlarge it.
	 * 2.  The block to be freed starts at the end of
	 *     the current block and ends at the beginning
	 *     of the following block.  Merge the three
	 *     areas into a single block.
	 * 3.  The block to be freed starts after the end
	 *     of the block and ends before the start of
	 *     the following block.  Create a new free block.
	 * 4.  The block to be freed starts after the end
	 *     of the block, but ends at the start of the
	 *     following block.  Enlarge the following block
	 *     downwards.
	 *
	 */
	if (sd->driveoffset == dend) {			    /* it starts after the end of this block */
	    if ((fe < drive->freelist_entries - 1)	    /* we're not the last block in the free list */
	    &&(sdend == drive->freelist[fe + 1].offset)) {  /* and the subdisk ends at the start of the
																			   * next block */
		drive->freelist[fe].sectors = drive->freelist[fe + 1].sectors; /* 2: merge all three blocks */
		if (fe < drive->freelist_entries - 2)	    /* still more blocks after next */
		    bcopy(&drive->freelist[fe + 2],	    /* move down one */
			&drive->freelist[fe + 1],
			(drive->freelist_entries - 2 - fe) * sizeof(struct drive_freelist));
		drive->freelist_entries--;		    /* one less entry in the free list */
	    } else					    /* 1: just enlarge this block */
		drive->freelist[fe].sectors += sd->sectors;
	} else {
	    if (sd->driveoffset > dend)			    /* it starts after this block */
		fe++;					    /* so look at the next block */
	    if ((fe < drive->freelist_entries)		    /* we're not the last block in the free list */
	    &&(sdend == drive->freelist[fe].offset)) {	    /* and the subdisk ends at the start of
																		   * this block: case 4 */
		drive->freelist[fe].offset = sd->driveoffset; /* it starts where the sd was */
		drive->freelist[fe].sectors += sd->sectors; /* and it's this much bigger */
	    } else {					    /* case 3: non-contiguous */
		if (fe < drive->freelist_entries)	    /* not after the last block, */
		    bcopy(&drive->freelist[fe],		    /* move the rest up one entry */
			&drive->freelist[fe + 1],
			(drive->freelist_entries - fe) * sizeof(struct drive_freelist));
		drive->freelist_entries++;		    /* one less entry */
		drive->freelist[fe].offset = sd->driveoffset; /* this entry represents the sd */
		drive->freelist[fe].sectors = sd->sectors;
	    }
	}
	drive->opencount--;				    /* one less subdisk attached */
    }
    bzero(sd, sizeof(struct sd));			    /* and clear it out */
    sd->state = sd_unallocated;
    vinum_conf.subdisks_used--;				    /* one less sd */
}

/* Find an empty plex in the plex table */
int 
get_empty_plex(void)
{
    BROKEN_GDB;
    int plexno;
    struct plex *plex;					    /* if we allocate one */

    /* first see if we have one which has been deallocated */
    for (plexno = 0; plexno < vinum_conf.plexes_used; plexno++) {
	if (PLEX[plexno].state == plex_unallocated)	    /* bingo */
	    break;					    /* and get out of here */
    }

    if (plexno >= vinum_conf.plexes_used) {
	/* Couldn't find a deallocated plex.  Allocate a new one */
	vinum_conf.plexes_used++;
	if (vinum_conf.plexes_used > vinum_conf.plexes_allocated)
	    EXPAND(PLEX, struct plex, vinum_conf.plexes_allocated, INITIAL_PLEXES);
    }
    /* Found a plex.  Give it an sd structure */
    plex = &PLEX[plexno];				    /* this one is ours */
    bzero(plex, sizeof(struct plex));			    /* polish it up */
    plex->sdnos = (int *) Malloc(sizeof(int) * INITIAL_SUBDISKS_IN_PLEX); /* allocate sd table */
    CHECKALLOC(plex->sdnos, "vinum: Can't allocate plex subdisk table");
    bzero(plex->sdnos, (sizeof(int) * INITIAL_SUBDISKS_IN_PLEX)); /* do we need this? */
    plex->subdisks = 0;					    /* no subdisks in use */
    plex->subdisks_allocated = INITIAL_SUBDISKS_IN_PLEX;    /* and we have space for this many */
    plex->organization = plex_disorg;			    /* and it's not organized */
    plex->volno = -1;					    /* no volume yet */
    return plexno;					    /* return the index */
}

/* Find the named plex in vinum_conf.plex

 * If create != 0, create an entry if it doesn't exist
 * return index in vinum_conf.plex
 */
int 
find_plex(const char *name, int create)
{
    BROKEN_GDB;
    int plexno;
    struct plex *plex;

    for (plexno = 0; plexno < vinum_conf.plexes_allocated; plexno++) {
	if (strcmp(PLEX[plexno].name, name) == 0)	    /* found it */
	    return plexno;
    }

    /* the plex isn't in the list.  Add it if he wants */
    if (create == 0)					    /* don't want to create */
	return -1;					    /* give up */

    /* Allocate one and insert the name */
    plexno = get_empty_plex();
    plex = &PLEX[plexno];				    /* point to it */
    bcopy(name, plex->name, min(sizeof(plex->name), strlen(name))); /* put in its name */
    return plexno;					    /* return the pointer */
}

/* Free an allocated plex entry
 * and its associated memory areas */
void 
free_plex(int plexno)
{
    BROKEN_GDB;
    struct plex *plex;

    plex = &PLEX[plexno];
    if (plex->sdnos)
	Free(plex->sdnos);
    if (plex->lock)
	Free(plex->lock);
    if (plex->defective_region)
	Free(plex->defective_region);
    if (plex->unmapped_region)
	Free(plex->unmapped_region);
    bzero(plex, sizeof(struct plex));			    /* and clear it out */
    plex->state = plex_unallocated;
    vinum_conf.plexes_used--;				    /* one less plex */
}

/* Find an empty volume in the volume table */
int 
get_empty_volume(void)
{
    BROKEN_GDB;
    int volno;
    struct volume *vol;

    /* first see if we have one which has been deallocated */
    for (volno = 0; volno < vinum_conf.volumes_used; volno++) {
	if (VOL[volno].state == volume_unallocated)	    /* bingo */
	    break;
    }

    if (volno >= vinum_conf.volumes_used)
	/* Couldn't find a deallocated volume.  Allocate a new one */
    {
	vinum_conf.volumes_used++;
	if (vinum_conf.volumes_used > vinum_conf.volumes_allocated)
	    EXPAND(VOL, struct volume, vinum_conf.volumes_allocated, INITIAL_VOLUMES);
    }
    /* Now initialize fields */
    vol = &VOL[volno];
    bzero(vol, sizeof(struct volume));
    vol->preferred_plex = -1;				    /* default to round robin */
    vol->preferred_plex = ROUND_ROBIN_READPOL;		    /* round robin */

    return volno;					    /* return the index */
}

/* Find the named volume in vinum_conf.volume.

 * If create != 0, create an entry if it doesn't exist
 * return the index in vinum_conf
 */
int 
find_volume(const char *name, int create)
{
    BROKEN_GDB;
    int volno;
    struct volume *vol;

    for (volno = 0; volno < vinum_conf.volumes_used; volno++) {
	if (strcmp(VOL[volno].name, name) == 0)		    /* found it */
	    return volno;
    }

    /* the volume isn't in the list.  Add it if he wants */
    if (create == 0)					    /* don't want to create */
	return -1;					    /* give up */

    /* Allocate one and insert the name */
    volno = get_empty_volume();
    vol = &VOL[volno];
    bcopy(name, vol->name, min(sizeof(vol->name), strlen(name))); /* put in its name */
    vol->blocksize = DEV_BSIZE;				    /* block size of this volume */
    return volno;					    /* return the pointer */
}

/* Free an allocated volume entry
 * and its associated memory areas */
void 
free_volume(int volno)
{
    BROKEN_GDB;
    struct volume *vol;

    vol = &VOL[volno];
    bzero(vol, sizeof(struct volume));			    /* and clear it out */
    vol->state = volume_unallocated;
    vinum_conf.volumes_used--;				    /* one less volume */
}

/* Handle a drive definition.  We store the information in the global variable
 * drive, so we don't need to allocate.
 *
 * If we find an error, print a message and return
 */
void 
config_drive(void)
{
    BROKEN_GDB;
    enum drive_label_info partition_status;		    /* info about the partition */
    int parameter;
    int driveno;					    /* index of drive in vinum_conf */
    struct drive *drive;				    /* and pointer to it */

    if (tokens < 2)					    /* not enough tokens */
	throw_rude_remark(EINVAL, "Drive has no name");
    driveno = find_drive(token[1], 1);			    /* allocate a drive to initialize */
    drive = &DRIVE[driveno];				    /* and get a pointer */

    if (drive->state != drive_uninit) {			    /* we already know this drive */
	/* XXX Check which definition is more up-to-date.  Give
	 * preference for the definition on its own drive */
	return;						    /* XXX */
    }
    for (parameter = 2; parameter < tokens; parameter++) {  /* look at the other tokens */
	switch (get_keyword(token[parameter], &keyword_set)) {
	case kw_device:
	    parameter++;
	    if (drive->devicename[0] != '\0') {		    /* we know this drive... */
		if (strcmp(drive->devicename, token[parameter])) /* different name */
		    close_drive(drive);			    /* close it if it's open */
		else					    /* no change */
		    break;
	    }
	    bcopy(token[parameter],			    /* insert device information */
		drive->devicename,
		min(sizeof(drive->devicename),
		    strlen(token[parameter])));
	    /* open the device and get the configuration */
	    partition_status = read_drive_label(drive);
	    if (partition_status == DL_CANT_OPEN) {	    /* not our kind */
		close_drive(drive);
		if (drive->lasterror == EFTYPE)		    /* wrong kind of partition */
		    throw_rude_remark(drive->lasterror,
			"Drive %s has invalid partition type",
			drive->label.name);
		else					    /* I/O error of some kind */
		    throw_rude_remark(drive->lasterror,
			"Can't initialize drive %s",
			drive->label.name);
	    } else if (partition_status == DL_WRONG_DRIVE) { /* valid drive, not ours */
		close_drive(drive);
		throw_rude_remark(drive->lasterror,
		    "Incorrect drive name %s specified for drive %s",
		    token[1],
		    drive->label.name);
	    }
	    break;

	case kw_state:
	    checkkernel(token[++parameter]);		    /* must be a kernel user */
	    drive->state = DriveState(token[parameter]);    /* set the state */
	    break;

	default:
	    close_drive(drive);
	    throw_rude_remark(EINVAL,
		"Drive %s, invalid keyword: %s",
		token[1],
		token[parameter]);
	}
    }

    if (drive->devicename[0] == '\0') {
	drive->state = drive_unallocated;		    /* deallocate the drive */
	throw_rude_remark(EINVAL, "No device name for %s", drive->label.name);
    }
}

/* Handle a subdisk definition.  We store the information in the global variable
 * sd, so we don't need to allocate.
 *
 * If we find an error, print a message and return
 */
void 
config_subdisk(void)
{
    BROKEN_GDB;
    int parameter;
    int sdno;						    /* index of sd in vinum_conf */
    struct sd *sd;					    /* and pointer to it */
    u_int64_t size;
    int sectors;					    /* sector offset value */
    int detached = 0;					    /* set to 1 if this is a detached subdisk */
    int sdindex = -1;					    /* index in plexes subdisk table */
    int namedsdno;

    sdno = get_empty_sd();				    /* allocate an SD to initialize */
    sd = &SD[sdno];					    /* and get a pointer */
    for (parameter = 1; parameter < tokens; parameter++) {  /* look at the other tokens */
	switch (get_keyword(token[parameter], &keyword_set)) {
	case kw_detached:
	    detached = 1;
	    break;

	case kw_plexoffset:
	    size = sizespec(token[++parameter]);
	    if ((size % DEV_BSIZE) != 0)
		throw_rude_remark(EINVAL, "sd %s, bad plex offset alignment: %qd", sd->name, size);
	    else
		sd->plexoffset = size / DEV_BSIZE;
	    break;

	case kw_driveoffset:
	    size = sizespec(token[++parameter]);
	    if ((size % DEV_BSIZE) != 0)
		throw_rude_remark(EINVAL, "sd %s, bad drive offset alignment: %qd", sd->name, size);
	    else
		sd->driveoffset = size / DEV_BSIZE;
	    break;

	case kw_name:
	    namedsdno = find_subdisk(token[++parameter], 0); /* find an existing sd with this name */
	    if (namedsdno >= 0)
		throw_rude_remark(EINVAL, "Duplicate subdisk %s", token[parameter]);
	    bcopy(token[parameter],
		sd->name,
		min(sizeof(sd->name), strlen(token[parameter])));
	    break;

	case kw_len:
	    size = sizespec(token[++parameter]);
	    if ((size % DEV_BSIZE) != 0)
		throw_rude_remark(EINVAL, "sd %s, length %d not multiple of sector size", sd->name, size);
	    else
		sd->sectors = size / DEV_BSIZE;
	    break;

	case kw_drive:
	    sd->driveno = find_drive(token[++parameter], 1); /* insert drive information */
	    break;

	case kw_plex:
	    sd->plexno = find_plex(token[++parameter], 1);  /* insert plex information */
	    break;

	case kw_state:
	    checkkernel(token[++parameter]);		    /* must be a kernel user */
	    sd->state = SdState(token[parameter]);	    /* set the state */
	    break;

	default:
	    throw_rude_remark(EINVAL, "sd %s, invalid keyword: %s", sd->name, token[parameter]);
	}
    }

    /* Check we have a drive name */
    if (sd->driveno < 0) {				    /* didn't specify a drive */
	sd->driveno = current_drive;			    /* set to the current drive */
	if (sd->driveno < 0)				    /* no current drive? */
	    throw_rude_remark(EINVAL, "Subdisk %s is not associated with a drive", sd->name);
    }
    /*  Check for a plex name */
    if ((sd->plexno < 0)				    /* didn't specify a plex */
    &&(!detached))					    /* and didn't say not to, */
	sd->plexno = current_plex;			    /* set to the current plex */

    if (sd->plexno >= 0)
	sdindex = give_sd_to_plex(sd->plexno, sdno);	    /* now tell the plex that it has this sd */

    sd->sdno = sdno;					    /* point to our entry in the table */

    /* Does the subdisk have a name?  If not, give it one */
    if (sd->name[0] == '\0') {				    /* no name */
	char sdsuffix[8];				    /* form sd name suffix here */

	/* Do we have a plex name? */
	if (sdindex >= 0)				    /* we have a plex */
	    strcpy(sd->name, PLEX[sd->plexno].name);	    /* take it from there */
	else						    /* no way */
	    throw_rude_remark(EINVAL, "Unnamed sd is not associated with a plex");
	sprintf(sdsuffix, ".s%d", sdindex);		    /* form the suffix */
	strcat(sd->name, sdsuffix);			    /* and add it to the name */
    }
    /* do we have complete info for this subdisk? */
    if (sd->sectors == 0)
	throw_rude_remark(EINVAL, "sd %s has no length spec", sd->name);

    if (sd->state == sd_unallocated)			    /* no state decided, */
	sd->state = sd_init;				    /* at least we're in the game */

    /* register the subdisk with the drive.  This action
     * will have the side effect of setting the offset if
     * we haven't specified one, and causing an error
     * message if it overlaps with another subdisk. */
    give_sd_to_drive(sdno);
}

/* Handle a plex definition.
 * If we find an error, print a message, deallocate the nascent plex, and return
 */
void 
config_plex(void)
{
    BROKEN_GDB;
    int parameter;
    int plexno;						    /* index of plex in vinum_conf */
    struct plex *plex;					    /* and pointer to it */
    int pindex = MAXPLEX;				    /* index in volume's plex list */
    int detached = 0;					    /* don't give it to a volume */
    int namedplexno;

    current_plex = -1;					    /* forget the previous plex */
    plexno = get_empty_plex();				    /* allocate a plex */
    plex = &PLEX[plexno];				    /* and point to it */
    plex->plexno = plexno;				    /* and back to the config */
    for (parameter = 1; parameter < tokens; parameter++) {  /* look at the other tokens */
	switch (get_keyword(token[parameter], &keyword_set)) {
	case kw_detached:
	    detached = 1;
	    break;

	case kw_name:
	    namedplexno = find_plex(token[++parameter], 0); /* find an existing plex with this name */
	    if (namedplexno >= 0)
		throw_rude_remark(EINVAL, "Duplicate plex %s", token[parameter]);
	    bcopy(token[parameter],			    /* put in the name */
		plex->name,
		min(MAXPLEXNAME, strlen(token[parameter])));
	    break;

	case kw_org:					    /* plex organization */
	    switch (get_keyword(token[++parameter], &keyword_set)) {
	    case kw_concat:
		plex->organization = plex_concat;
		break;

	    case kw_striped:
		{
		    int stripesize = sizespec(token[++parameter]);

		    plex->organization = plex_striped;
		    if (stripesize % DEV_BSIZE != 0)	    /* not a multiple of block size, */
			throw_rude_remark(EINVAL, "plex %s: stripe size %d not a multiple of sector size",
			    plex->name,
			    stripesize);
		    else
			plex->stripesize = stripesize / DEV_BSIZE;
		    break;
		}


	    default:
		throw_rude_remark(EINVAL, "Invalid plex organization");
	    }
	    if (((plex->organization == plex_striped)
		)
		&& (plex->stripesize == 0))		    /* didn't specify a valid stripe size */
		throw_rude_remark(EINVAL, "Need a stripe size parameter");
	    break;

	case kw_volume:
	    plex->volno = find_volume(token[++parameter], 1); /* insert a pointer to the volume */
	    break;

	case kw_sd:					    /* add a subdisk */
	    {
		int sdno;

		sdno = find_subdisk(token[++parameter], 1); /* find a subdisk */
		SD[sdno].plexoffset = sizespec(token[++parameter]); /* get the offset */
		give_sd_to_plex(plexno, sdno);		    /* and insert it there */
		break;
	    }

	case kw_state:
	    checkkernel(token[++parameter]);		    /* only for kernel use */
	    plex->state = PlexState(token[parameter]);	    /* set the state */
	    break;

	default:
	    throw_rude_remark(EINVAL, "plex %s, invalid keyword: %s",
		plex->name,
		token[parameter]);
	}
    }

    if ((plex->volno < 0)				    /* we don't have a volume */
    &&(!detached))					    /* and we wouldn't object */
	plex->volno = current_volume;

    if (plex->volno >= 0)
	pindex = give_plex_to_volume(plex->volno, plexno);  /* Now tell the volume that it has this plex */

    /* Does the plex have a name?  If not, give it one */
    if (plex->name[0] == '\0') {			    /* no name */
	char plexsuffix[8];				    /* form plex name suffix here */
	/* Do we have a volume name? */
	if (plex->volno >= 0)				    /* we have a volume */
	    strcpy(plex->name,				    /* take it from there */
		VOL[plex->volno].name);
	else						    /* no way */
	    throw_rude_remark(EINVAL, "Unnamed plex is not associated with a volume");
	sprintf(plexsuffix, ".p%d", pindex);		    /* form the suffix */
	strcat(plex->name, plexsuffix);			    /* and add it to the name */
    }
    /* Note the last plex we configured */
    current_plex = plexno;
    if (plex->state == plex_unallocated)		    /* we haven't changed the state, */
	plex->state = plex_init;			    /* we're initialized now */
}

/* Handle a volume definition.
 * If we find an error, print a message, deallocate the nascent volume, and return
 */
void 
config_volume(void)
{
    BROKEN_GDB;
    int parameter;
    int volno;
    struct volume *vol;					    /* collect volume info here */
    int i;

    if (tokens < 2)					    /* not enough tokens */
	throw_rude_remark(EINVAL, "Volume has no name");
    current_volume = -1;				    /* forget the previous volume */
    volno = find_volume(token[1], 1);			    /* allocate a volume to initialize */
    vol = &VOL[volno];					    /* and get a pointer */

    for (parameter = 2; parameter < tokens; parameter++) {  /* look at all tokens */
	switch (get_keyword(token[parameter], &keyword_set)) {
	case kw_plex:
	    {
		int plexno;				    /* index of this plex */

		plexno = find_plex(token[++parameter], 1);  /* find a plex */
		if (plexno < 0)				    /* couldn't */
		    break;				    /* we've already had an error message */
		plexno = my_plex(volno, plexno);	    /* does it already belong to us? */
		if (plexno > 0)				    /* yes, shouldn't get it again */
		    throw_rude_remark(EINVAL,
			"Plex %s already belongs to volume %s",
			token[parameter],
			vol->name);
		else if (++vol->plexes > 8)		    /* another entry */
		    throw_rude_remark(EINVAL,
			"Too many plexes for volume %s",
			vol->name);
		vol->plex[vol->plexes - 1] = plexno;
	    }
	    break;

	case kw_readpol:
	    switch (get_keyword(token[++parameter], &keyword_set)) { /* decide what to do */
	    case kw_round:
		vol->preferred_plex = ROUND_ROBIN_READPOL;  /* default */
		break;

	    case kw_prefer:
		{
		    int myplexno;			    /* index of this plex */

		    myplexno = find_plex(token[++parameter], 1); /* find a plex */
		    if (myplexno < 0)			    /* couldn't */
			break;				    /* we've already had an error message */
		    myplexno = my_plex(volno, myplexno);    /* does it already belong to us? */
		    if (myplexno > 0)			    /* yes */
			vol->preferred_plex = myplexno;	    /* just note the index */
		    else if (++vol->plexes > 8)		    /* another entry */
			throw_rude_remark(EINVAL, "Too many plexes");
		    else {				    /* space for the new plex */
			vol->plex[vol->plexes - 1] = myplexno; /* add it to our list */
			vol->preferred_plex = vol->plexes - 1; /* and note the index */
		    }
		}
		break;

	    default:
		throw_rude_remark(EINVAL, "Invalid read policy");
	    }

	case kw_setupstate:
	    vol->flags |= VF_CONFIG_SETUPSTATE;		    /* set the volume up later on */
	    break;

	case kw_state:
	    checkkernel(token[++parameter]);		    /* must be a kernel user */
	    vol->state = VolState(token[parameter]);	    /* set the state */
	    break;

	    /* XXX experimental ideas.  These are not
	     * documented, and will not be until I
	     * decide they're worth keeping */
	case kw_writethrough:				    /* set writethrough mode */
	    vol->flags |= VF_WRITETHROUGH;
	    break;

	case kw_writeback:				    /* set writeback mode */
	    vol->flags &= ~VF_WRITETHROUGH;
	    break;

	case kw_raw:
	    vol->flags |= VF_RAW;			    /* raw volume (no label) */
	    break;

	default:
	    throw_rude_remark(EINVAL, "volume %s, invalid keyword: %s",
		vol->name,
		token[parameter]);
	}
    }

    current_volume = volno;				    /* note last referred volume */
    vol->devno = VINUMBDEV(volno, 0, 0, VINUM_VOLUME_TYPE); /* also note device number */

    /* Before we can actually use the volume, we need
     * a volume label.  We could start to fake one here,
     * but it will be a lot easier when we have some
     * to copy from the drives, so defer it until we
     * set up the configuration. XXX */
    if (vol->state == volume_unallocated)
	vol->state = volume_down;			    /* now ready to bring up at the end */

    /* Find out how big our volume is */
    for (i = 0; i < vol->plexes; i++)
	vol->size = max(vol->size, PLEX[vol->plex[i]].length);
}

/* Parse a config entry.  CARE!  This destroys the original contents of the
 * config entry, which we don't really need after this.  More specifically, it
 * places \0 characters at the end of each token.
 *
 * Return 0 if all is well, otherwise EINVAL */
int 
parse_config(char *cptr, struct keywordset *keyset)
{
    BROKEN_GDB;
    int status;

    status = 0;						    /* until proven otherwise */
    tokens = tokenize(cptr, token);			    /* chop up into tokens */

    if (tokens <= 0)					    /* screwed up or empty line */
	return tokens;					    /* give up */

    if (token[0][0] == '#')				    /* comment line */
	return 0;

    switch (get_keyword(token[0], keyset)) {		    /* decide what to do */
    case kw_read:					    /* read config from a specified drive */
	vinum_conf.flags |= VF_KERNELOP | VF_READING_CONFIG; /* kernel operation: reading config */
	status = check_drive(token[1]);			    /* check the drive info */
	vinum_conf.flags &= ~(VF_KERNELOP | VF_READING_CONFIG);
	if (status != 0) {
	    char *msg = "Can't read configuration from %s";
	    if (status == ENODEV)
		msg = "No vinum configuration on %s";
	    throw_rude_remark(status, msg, token[1]);
	}
	updateconfig(VF_KERNELOP);			    /* update from kernel space */
	break;

    case kw_drive:
	config_drive();
	break;

    case kw_subdisk:
	config_subdisk();
	break;

    case kw_plex:
	config_plex();
	break;

    case kw_volume:
	config_volume();
	break;

	/* Anything else is invalid in this context */
    default:
	throw_rude_remark(EINVAL,			    /* should we die? */
	    "Invalid configuration information: %s",
	    token[0]);
    }
    return status;
}

/* parse a line handed in from userland via ioctl.
 * This differs only by the error reporting mechanism:
 * we return the error indication in the reply to the
 * ioctl, so we need to set a global static pointer in
 * this file.  This technique works because we have
 * ensured that configuration is performed in a single-
 * threaded manner */
int 
parse_user_config(char *cptr, struct keywordset *keyset)
{
    BROKEN_GDB;
    int status;

    ioctl_reply = (struct _ioctl_reply *) cptr;
    status = parse_config(cptr, keyset);
    ioctl_reply = NULL;					    /* don't do this again */
    return status;
}

/* Remove an object */
void 
remove(struct vinum_ioctl_msg *msg)
{
    struct vinum_ioctl_msg message = *msg;		    /* make a copy to hand on */

    ioctl_reply = (struct _ioctl_reply *) msg;		    /* reinstate the address to reply to */
    ioctl_reply->error = 0;				    /* no error, */
    ioctl_reply->msg[0] = '\0';				    /* no message */

    switch (message.type) {
    case drive_object:
	remove_drive_entry(message.index, message.force, message.recurse);
	updateconfig(0);
	return;

    case sd_object:
	remove_sd_entry(message.index, message.force, message.recurse);
	updateconfig(0);
	return;

    case plex_object:
	remove_plex_entry(message.index, message.force, message.recurse);
	updateconfig(0);
	return;

    case volume_object:
	remove_volume_entry(message.index, message.force, message.recurse);
	updateconfig(0);
	return;

    default:
	ioctl_reply->error = EINVAL;
	strcpy(ioctl_reply->msg, "Invalid object type");
    }
}

/* Remove a drive.  */
void 
remove_drive_entry(int driveno, int force, int recurse)
{
    struct drive *drive = &DRIVE[driveno];

    if ((driveno > vinum_conf.drives_used)		    /* not a valid drive */
    ||(drive->state == drive_unallocated)) {		    /* or nothing there */
	ioctl_reply->error = EINVAL;
	strcpy(ioctl_reply->msg, "No such drive");
    } else if (drive->opencount > 0) {			    /* we have subdisks */
	if (force) {					    /* do it at any cost */
	    int sdno;
	    struct vinum_ioctl_msg sdmsg;

	    for (sdno = 0; sdno < vinum_conf.subdisks_used; sdno++) {
		if ((SD[sdno].state != sd_unallocated)	    /* subdisk is allocated */
		&&(SD[sdno].driveno == driveno)) {	    /* and it belongs to this drive */
		    sdmsg.type = sd_object;
		    sdmsg.recurse = 1;
		    sdmsg.force = force;
		    remove(&sdmsg);			    /* remove the subdisk by force */
		}
	    }
	    remove_drive(driveno);			    /* now remove it */
	} else
	    ioctl_reply->error = EBUSY;			    /* can't do that */
    } else
	remove_drive(driveno);				    /* just remove it */
}

/* remove a subdisk */
void 
remove_sd_entry(int sdno, int force, int recurse)
{
    struct sd *sd = &SD[sdno];

    if ((sdno > vinum_conf.subdisks_used)		    /* not a valid sd */
    ||(sd->state == sd_unallocated)) {			    /* or nothing there */
	ioctl_reply->error = EINVAL;
	strcpy(ioctl_reply->msg, "No such subdisk");
    } else if (sd->plexno >= 0) {			    /* we have a plex */
	if (force) {					    /* do it at any cost */
	    struct plex *plex = &PLEX[sd->plexno];	    /* point to our plex */
	    int mysdno;

	    for (mysdno = 0;				    /* look for ourselves */
		mysdno < plex->subdisks && &SD[plex->sdnos[mysdno]] != sd;
		mysdno++);
	    if (mysdno == plex->subdisks)		    /* didn't find it */
		throw_rude_remark(ENOENT, "plex %s does not contain subdisk %s", plex->name, sd->name);
	    if (mysdno < (plex->subdisks - 1))		    /* not the last subdisk */
		bcopy(&plex->sdnos[mysdno + 1],
		    &plex->sdnos[mysdno],
		    (plex->subdisks - 1 - mysdno) * sizeof(int));
	    plex->subdisks--;
	    /* removing a subdisk from a striped or
	     * RAID-5 plex really tears the hell out
	     * of the structure, and it needs to be
	     * reinitialized */
	    if (plex->organization != plex_concat)	    /* not concatenated, */
		set_plex_state(plex->plexno, plex_faulty, setstate_force); /* need to reinitialize */
	    rebuild_plex_unmappedlist(plex);		    /* and see what remains */
	    free_sd(sdno);
	} else
	    ioctl_reply->error = EBUSY;			    /* can't do that */
    } else
	free_sd(sdno);
}

/* remove a plex */
void 
remove_plex_entry(int plexno, int force, int recurse)
{
    struct plex *plex = &PLEX[plexno];
    int sdno;

    if ((plexno > vinum_conf.plexes_used)		    /* not a valid plex */
    ||(plex->state == plex_unallocated)) {		    /* or nothing there */
	ioctl_reply->error = EINVAL;
	strcpy(ioctl_reply->msg, "No such plex");
    } else if (plex->pid) {				    /* we're open */
	ioctl_reply->error = EBUSY;			    /* no getting around that */
	return;
    }
    if (plex->subdisks) {
	if (force) {					    /* do it anyway */
	    if (recurse) {				    /* remove all below */
		for (sdno = 0; sdno < plex->subdisks; sdno++)
		    free_sd(plex->sdnos[sdno]);		    /* free all subdisks */
	    } else {					    /* just tear them out */
		for (sdno = 0; sdno < plex->subdisks; sdno++)
		    SD[plex->sdnos[sdno]].plexno = -1;	    /* no plex any more */
	    }
	} else {					    /* can't do it without force */
	    ioctl_reply->error = EBUSY;			    /* can't do that */
	    return;
	}
    }
    if (plex->volno >= 0) {				    /* we are part of a volume */
	/* XXX This should be more intelligent.  We should
	 * be able to remove a plex as long as the volume
	 * does not lose any data, which is normally the
	 * case when it has more than one plex.  To do it
	 * right we must compare the completeness of the
	 * mapping of all the plexes in the volume */
	if (force) {					    /* do it at any cost */
	    struct volume *vol = &VOL[plex->volno];
	    int myplexno;

	    for (myplexno = 0; myplexno < vol->plexes; myplexno++)
		if (vol->plex[myplexno] == plexno)	    /* found it */
		    break;
	    if (myplexno == vol->plexes)		    /* didn't find it.  Huh? */
		throw_rude_remark(ENOENT, "volume %s does not contain plex %s", vol->name, plex->name);
	    if (myplexno < (vol->plexes - 1))		    /* not the last plex in the list */
		bcopy(&vol->plex[myplexno + 1], &vol->plex[myplexno], vol->plexes - 1 - myplexno);
	    vol->plexes--;
	} else {
	    ioctl_reply->error = EBUSY;			    /* can't do that */
	    return;
	}
    }
    free_plex(plexno);
}

/* remove a volume */
void 
remove_volume_entry(int volno, int force, int recurse)
{
    struct volume *vol = &VOL[volno];
    int plexno;

    if ((volno > vinum_conf.volumes_used)		    /* not a valid volume */
    ||(vol->state == volume_unallocated)) {		    /* or nothing there */
	ioctl_reply->error = EINVAL;
	strcpy(ioctl_reply->msg, "No such volume");
    } else if (vol->opencount)				    /* we're open */
	ioctl_reply->error = EBUSY;			    /* no getting around that */
    else if (vol->plexes) {
	if (recurse && force) {				    /* remove all below */
	    struct vinum_ioctl_msg plexmsg;

	    plexmsg.type = plex_object;
	    plexmsg.recurse = 1;
	    plexmsg.force = force;
	    for (plexno = 0; plexno < vol->plexes; plexno++) {
		plexmsg.index = vol->plex[plexno];	    /* plex number */
		remove(&plexmsg);
	    }
	    free_volume(volno);
	} else
	    ioctl_reply->error = EBUSY;			    /* can't do that */
    } else
	free_volume(volno);
}

void 
update_sd_config(int sdno, int kernelstate)
{
    if (!kernelstate)
	set_sd_state(sdno, sd_up, setstate_configuring | setstate_norecurse);
}

void 
update_plex_config(int plexno, int kernelstate)
{
    int error = 0;
    int size;
    int sdno;
    struct plex *plex = &PLEX[plexno];
    enum plexstate state = plex_up;			    /* state we want the plex in */

    /* XXX Insert checks here for sparse plexes and volumes */

    /* Check that our subdisks make sense.  For
     * striped and RAID5 plexes, we need at least
     * two subdisks, and they must all be the same
     * size */
    if (((plex->organization == plex_striped)
	)
	&& (plex->subdisks < 2)) {
	error = 1;
	printf("vinum: plex %s does not have at least 2 subdisks\n", plex->name);
	if (!kernelstate)
	    set_plex_state(plexno, plex_down, setstate_force | setstate_configuring | setstate_norecurse);
    }
    size = 0;
    for (sdno = 0; sdno < plex->subdisks; sdno++) {
	if (((plex->organization == plex_striped)
	    )
	    && (sdno > 0)
	    && (SD[plex->sdnos[sdno]].sectors != SD[plex->sdnos[sdno - 1]].sectors)) {
	    error = 1;
	    printf("vinum: plex %s must have equal sized subdisks\n", plex->name);
	    set_plex_state(plexno, plex_down, setstate_force | setstate_configuring | setstate_norecurse);
	}
	size += SD[plex->sdnos[sdno]].sectors;
    }

    if (plex->subdisks) {				    /* plex has subdisks, calculate size */
	rebuild_plex_unmappedlist(plex);		    /* rebuild the unmapped list first */

	plex->length = size;
    } else {						    /* no subdisks, */
	plex->length = 0;				    /* no size */
	state = plex_down;				    /* take it down */
    }
    if (!(kernelstate || error))
	set_plex_state(plexno, state, setstate_none | setstate_configuring | setstate_norecurse);
}

void 
update_volume_config(int volno, int kernelstate)
{
    struct volume *vol = &VOL[volno];
    struct plex *plex;
    int plexno;

    if (vol->state != volume_unallocated)
	/* Recalculate the size of the volume */
    {
	vol->size = 0;
	for (plexno = 0; plexno < vol->plexes; plexno++) {
	    plex = &PLEX[vol->plex[plexno]];
	    vol->size = max(plex->length, vol->size);	    /* maximum size */
	    plex->volplexno = plexno;			    /* note it in the plex */
	}
    }
    if (!kernelstate)					    /* try to bring it up */
	set_volume_state(volno, volume_up, setstate_configuring | setstate_norecurse);
}

/* Update the global configuration.
 * kernelstate is != 0 if we're reading in a config
 * from disk.  In this case, we don't try to
 * bring the devices up, though we will bring
 * them down if there's some error which got
 * missed when writing to disk.
 */
void 
updateconfig(int kernelstate)
{
    BROKEN_GDB;
    int sdno;
    int plexno;
    int volno;
    struct volume *vol;
    struct plex *plex;

    for (sdno = 0; sdno < vinum_conf.subdisks_used; sdno++)
	update_sd_config(sdno, kernelstate);

    for (plexno = 0; plexno < vinum_conf.plexes_used; plexno++)
	update_plex_config(plexno, kernelstate);

    for (volno = 0; volno < vinum_conf.volumes_used; volno++)
	update_volume_config(volno, kernelstate);
    save_config();
}

/* Start manual changes to the configuration and lock out
 * others who may wish to do so.
 * XXX why do we need this and lock_config too? */
int 
start_config(void)
{
    int error;

    while ((vinum_conf.flags & VF_CONFIGURING) != 0) {
	vinum_conf.flags |= VF_WILL_CONFIGURE;
	if ((error = tsleep(&vinum_conf, PRIBIO | PCATCH, "vincfg", 0)) != 0)
	    return error;
    }
    /* We need two flags here: VF_CONFIGURING
     * tells other processes to hold off (this 
     * function), and VF_CONFIG_INCOMPLETE
     * tells the state change routines not to
     * propagate incrememntal state changes */
    vinum_conf.flags |= VF_CONFIGURING | VF_CONFIG_INCOMPLETE;
    current_drive = -1;					    /* reset the defaults */
    current_plex = -1;					    /* and the same for the last plex */
    current_volume = -1;				    /* and the last volme */
    return 0;
}

/* Update the config if update is 1, and unlock
 * it.  We won't update the configuration if we
 * are called in a recursive loop via throw_rude_remark.
 */
void 
finish_config(int update)
{
    vinum_conf.flags &= ~VF_CONFIG_INCOMPLETE;		    /* we've finished our config */
    if (update)
	updateconfig(0);				    /* so update things */
    else
	updateconfig(1);				    /* do some updates only */
    vinum_conf.flags &= ~VF_CONFIGURING;		    /* and now other people can take a turn */
    if ((vinum_conf.flags & VF_WILL_CONFIGURE) != 0) {
	vinum_conf.flags &= ~VF_WILL_CONFIGURE;
	wakeup(&vinum_conf);
    }
}
