/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $Id: rules.c,v 1.2 1995/04/29 04:00:56 phk Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/diskslice.h>
#include <sys/disklabel.h>
#include <err.h>
#include "libdisk.h"

int
Aligned(struct disk *d, u_long offset)
{
	if (!d->bios_sect)
		return 1;
	if (offset % d->bios_sect)
		return 0;
	return 1;
}

u_long
Prev_Aligned(struct disk *d, u_long offset)
{
	if (!d->bios_sect)
		return offset;
	return (offset / d->bios_sect) * d->bios_sect;
}

u_long
Next_Aligned(struct disk *d, u_long offset)
{
	if (!d->bios_sect)
		return offset;
	return Prev_Aligned(d,offset + d->bios_sect);
}

/*
 *  Rule#0:
 *	Chunks of type 'whole' can have max NDOSPART children.
 */
void
Rule_000(struct disk *d, struct chunk *c, char *msg)
{
	int i;
	struct chunk *c1;

	if (c->type != whole)
		return;
	for (i=0, c1=c->part; c1; c1=c1->next)
		if (c1->type != unused)
			i++;
	if (i <= NDOSPART)
		return;
	sprintf(msg+strlen(msg),
		"%d is too many children of the 'whole' chunk.  Max is %d\n",
		i, NDOSPART);
}

/* 
 * Rule#1:
 *	All children of 'whole' must be track-aligned.
 *	Exception: the end can be unaligned if it matches the end of 'whole'
 */
void
Rule_001(struct disk *d, struct chunk *c, char *msg)
{
	int i;
	struct chunk *c1;

	if (c->type != whole)
		return;
	for (i=0, c1=c->part; c1; c1=c1->next) {
		if (c1->type == reserved)
			continue;
		if (c1->type == unused)
			continue;
		if (!Aligned(d,c1->offset))
			sprintf(msg+strlen(msg),
		    "chunk '%s' [%ld..%ld] does not start on a track boundary\n",
				c1->name,c1->offset,c1->end);
		if (c->end != c1->end && !Aligned(d,c1->end+1))
			sprintf(msg+strlen(msg),
		    "chunk '%s' [%ld..%ld] does not end on a track boundary\n",
				c1->name,c1->offset,c1->end);
	}
}

/* 
 * Rule#2:
 *	Max one 'fat' as child of 'whole'
 */
void
Rule_002(struct disk *d, struct chunk *c, char *msg)
{
	int i;
	struct chunk *c1;

	if (c->type != whole)
		return;
	for (i=0, c1=c->part; c1; c1=c1->next) {
		if (c1->type != fat)
			continue;
		i++;
	}
	if (i > 1) {
		sprintf(msg+strlen(msg),
		    "Max one 'fat' allowed as child of 'whole'\n");
	}
}

/* 
 * Rule#3:
 *	Max one extended as child of 'whole'
 */
void
Rule_003(struct disk *d, struct chunk *c, char *msg)
{
	int i;
	struct chunk *c1;

	if (c->type != whole)
		return;
	for (i=0, c1=c->part; c1; c1=c1->next) {
		if (c1->type != extended)
			continue;
		i++;
	}
	if (i > 1) {
		sprintf(msg+strlen(msg),
		    "Max one 'extended' allowed as child of 'whole'\n");
	}
}

void
Check_Chunk(struct disk *d, struct chunk *c, char *msg)
{
	Rule_000(d,c,msg);
	Rule_001(d,c,msg);
	Rule_002(d,c,msg);
	Rule_003(d,c,msg);
	if (c->part)
		Check_Chunk(d,c->part,msg);
	if (c->next)
		Check_Chunk(d,c->next,msg);
	return;
}

char *
CheckRules(struct disk *d)
{
	char msg[BUFSIZ];

	*msg = '\0';
	Check_Chunk(d,d->chunks,msg);
	if (*msg)
		return strdup(msg);
	return 0;
}
