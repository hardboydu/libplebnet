/*
 * Copyright (c) 1994, Paul Richards.
 *
 * All rights reserved.
 *
 * This software may be used, modified, copied, distributed, and
 * sold, in both source and binary form provided that the above
 * copyright and these terms are retained, verbatim, as the first
 * lines of this file.  Under no circumstances is the author
 * responsible for the proper functioning of this software, nor does
 * the author assume any responsibility for damages incurred with
 * its use.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/disklabel.h>
#include <sys/uio.h>
#include <unistd.h>
#include <ncurses.h>
#include <dialog.h>

#include "mbr.h"

extern struct mbr *mbr;
extern char *errmsg;
extern int inst_part;

struct part_type part_types[] = PARTITION_TYPES

char *
part_type(int type)
{
	int num_types = (sizeof(part_types)/sizeof(struct part_type));
	int next_type = 0;
	struct part_type *ptr = part_types;

	while (next_type < num_types) {
		if(ptr->type == type)
			return(ptr->name);
		ptr++;
		next_type++;
	}
	return("Uknown");
}

int
read_mbr(int fd, struct mbr *mbr)
{
	if (lseek(fd, 0, SEEK_SET) == -1) {
		sprintf(errmsg, "Couldn't seek for master boot record read\n");
		return(-1);
	}
	if (read(fd, &(mbr->bootcode), 512) == -1) {
		sprintf(errmsg, "Failed to read master boot record\n");
		return(-1);
	}
	/* Validate the master boot record */
	if (mbr->magic != MBR_MAGIC) {
		sprintf(errmsg, "Master boot record is invalid\n");
		return(-1);
	}
	return(0);
}

int
write_mbr(int fd, struct mbr *mbr)
{
	if (lseek(fd, 0, SEEK_SET) == -1) {
		sprintf(errmsg, "Couldn't seek for master boot record write\n");
		return(-1);
	}

	if (write(fd, mbr->bootcode, MBRSIZE) == -1) {
		sprintf(errmsg, "Failed to write master boot record\n");
		return(-1);
	}

	return(0);
}

void
show_mbr(struct mbr *mbr)
{
	int i, j, key = 0;
	int x, y;
	WINDOW *window;

	window = newwin(LINES, COLS, 0, 0);
	keypad(window, TRUE);

	draw_box(window, 0, 0, LINES - 1, COLS - 1,
				COLOR_PAIR(COLOR_YELLOW), COLOR_PAIR(COLOR_BLUE));

	for (i=0; i<NDOSPART/2; i++) {
		for (j=0; j<NDOSPART/2; j++) {
			x = (j * 38) + 3;
			y = (i * 11) + 2;
			mvwprintw(window, y, x, "Partition %d: flags = %x",
					  (i*2)+j, mbr->dospart[(i*2)+j].dp_flag);
			mvwprintw(window, y+1, x, "Starting at (H%d, S%d, C%d)",
					  mbr->dospart[(i*2)+j].dp_shd,
					  mbr->dospart[(i*2)+j].dp_ssect,
					  mbr->dospart[(i*2)+j].dp_scyl);
			mvwprintw(window, y+2, x, "Type: %s (%x)",
					  part_type(mbr->dospart[(i*2)+j].dp_typ),
		           mbr->dospart[(i*2)+j].dp_typ);
			mvwprintw(window, y+3, x, "Ending at (H%d, S%d, C%d)",
					  mbr->dospart[(i*2)+j].dp_shd,
					  mbr->dospart[(i*2)+j].dp_esect,
					  mbr->dospart[(i*2)+j].dp_ecyl);
			mvwprintw(window, y+4, x, "Absolute start sector %ld",
					  mbr->dospart[(i*2)+j].dp_start);
			mvwprintw(window, y+5, x, "Size %ld", mbr->dospart[(i*2)+j].dp_size);
		}
	}
	refresh();

	while (key != '\n')
		key = wgetch(window);

	delwin(window);
}

void
clear_mbr(struct mbr *mbr)
{
	int i;

	/* Create an empty partition table */
	for (i=0; i < NDOSPART; i++) {
		mbr->dospart[i].dp_flag = 0;
		mbr->dospart[i].dp_shd = 0;
		mbr->dospart[i].dp_ssect = 0;
		mbr->dospart[i].dp_scyl = 0;
		mbr->dospart[i].dp_typ = 0;
		mbr->dospart[i].dp_ehd = 0;
		mbr->dospart[i].dp_esect = 0;
		mbr->dospart[i].dp_ecyl = 0;
		mbr->dospart[i].dp_start = 0;
		mbr->dospart[i].dp_size = 0;
	}
}

int
build_mbr(struct mbr *mbr, struct disklabel *label)
{
	int i;

	/*
	 * This is the biggie, need to spend some time getting all
	 * the different possibilities sorted out.
	 */

	if (inst_part == -1) {
		/* Install to entire disk */
		clear_mbr(mbr);
		mbr->dospart[0].dp_flag = ACTIVE;
		mbr->dospart[0].dp_shd = 1;
		mbr->dospart[0].dp_ssect = 0;
		mbr->dospart[0].dp_scyl = 0;
		mbr->dospart[0].dp_typ = DOSPTYP_386BSD ;
		mbr->dospart[0].dp_ehd = label->d_ntracks;
		mbr->dospart[0].dp_esect = label->d_nsectors;
		mbr->dospart[0].dp_ecyl = label->d_ncylinders;
		mbr->dospart[0].dp_start = 0;
		mbr->dospart[0].dp_size = 
			  label->d_ntracks * label->d_nsectors * label->d_ncylinders;
		return(1);
	} else {
		/* Validate partition - XXX need to spend some time making this robust */
		if ((inst_part) && (!mbr->dospart[inst_part].dp_start)) {
			strcpy(errmsg, "The start address of the selected partition is 0\n");
			return(0);
		}
	}

	/* Set partition type to FreeBSD and make it the only active partition */
	for (i=0; i < NDOSPART; i++)
		mbr->dospart[i].dp_flag &= ~ACTIVE;
	mbr->dospart[inst_part].dp_typ = DOSPTYP_386BSD;
	mbr->dospart[inst_part].dp_flag = ACTIVE;
	return(1);
}

void
edit_mbr(struct mbr *mbr, struct disklabel *label)
{

	dialog_msgbox("DOS partition table editor", 
		"This editor is still under construction :-)", 10, 75, 1);
	show_mbr(mbr);
}
