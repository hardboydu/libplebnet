/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: disks.c,v 1.104 1998/10/07 03:15:08 jkh Exp $
 *
 * Copyright (c) 1995
 *	Jordan Hubbard.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    verbatim and that no modifications are made prior to this
 *    point in the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY JORDAN HUBBARD ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JORDAN HUBBARD OR HIS PETS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, LIFE OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "sysinstall.h"
#include <ctype.h>
#include <sys/disklabel.h>

/* Where we start displaying chunk information on the screen */
#define CHUNK_START_ROW		5

/* Where we keep track of MBR chunks */
static struct chunk *chunk_info[16];
static int current_chunk;

static void	diskPartitionNonInteractive(Device *dev);

static void
record_chunks(Disk *d)
{
    struct chunk *c1 = NULL;
    int i = 0;
    int last_free = 0;

    if (!d->chunks)
	msgFatal("No chunk list found for %s!", d->name);

    for (c1 = d->chunks->part; c1; c1 = c1->next) {
	if (c1->type == unused && c1->size > last_free) {
	    last_free = c1->size;
	    current_chunk = i;
	}
	chunk_info[i++] = c1;
    }
    chunk_info[i] = NULL;
    if (current_chunk >= i)
	current_chunk = i - 1;
}

static int Total;

static void
print_chunks(Disk *d)
{
    int row;
    int i;

    for (i = Total = 0; chunk_info[i]; i++)
	Total += chunk_info[i]->size;
    if (d->bios_cyl > 65536 || d->bios_hd > 256 || d->bios_sect >= 64) {
	dialog_clear_norefresh();
	msgConfirm("WARNING:  A geometry of %d/%d/%d for %s is incorrect.  Using\n"
		   "a more likely geometry.  If this geometry is incorrect or you\n"
		   "are unsure as to whether or not it's correct, please consult\n"
		   "the Hardware Guide in the Documentation submenu or use the\n"
		   "(G)eometry command to change it now.\n\n"
		   "Remember: you need to enter whatever your BIOS thinks the\n"
		   "geometry is!  For IDE, it's what you were told in the BIOS\n"
		   "setup. For SCSI, it's the translation mode your controller is\n"
		   "using.  Do NOT use a ``physical geometry''.",
	  d->bios_cyl, d->bios_hd, d->bios_sect, d->name);
	Sanitize_Bios_Geom(d);
    }
    attrset(A_NORMAL);
    mvaddstr(0, 0, "Disk name:\t");
    clrtobot();
    attrset(A_REVERSE); addstr(d->name); attrset(A_NORMAL);
    attrset(A_REVERSE); mvaddstr(0, 55, "FDISK Partition Editor"); attrset(A_NORMAL);
    mvprintw(1, 0,
	     "DISK Geometry:\t%lu cyls/%lu heads/%lu sectors = %lu sectors",
	     d->bios_cyl, d->bios_hd, d->bios_sect,
	     d->bios_cyl * d->bios_hd * d->bios_sect);
    mvprintw(3, 0, "%10s %10s %10s %8s %6s %10s %8s %8s",
	     "Offset", "Size", "End", "Name", "PType", "Desc",
	     "Subtype", "Flags");
    for (i = 0, row = CHUNK_START_ROW; chunk_info[i]; i++, row++) {
	if (i == current_chunk)
	    attrset(ATTR_SELECTED);
	mvprintw(row, 0, "%10ld %10lu %10lu %8s %6d %10s %8d\t%-6s",
		 chunk_info[i]->offset, chunk_info[i]->size,
		 chunk_info[i]->end, chunk_info[i]->name,
		 chunk_info[i]->type, 
		 slice_type_name(chunk_info[i]->type, chunk_info[i]->subtype),
		 chunk_info[i]->subtype, ShowChunkFlags(chunk_info[i]));
	if (i == current_chunk)
	    attrset(A_NORMAL);
    }
}

static void
print_command_summary()
{
    mvprintw(14, 0, "The following commands are supported (in upper or lower case):");
    mvprintw(16, 0, "A = Use Entire Disk    B = Bad Block Scan       C = Create Slice");
    mvprintw(17, 0, "D = Delete Slice       G = Set Drive Geometry   S = Set Bootable");
    mvprintw(18, 0, "T = Change Type        U = Undo All Changes     Q = Finish");
    if (!RunningAsInit)
	mvprintw(18, 48, "W = Write Changes");
    mvprintw(21, 0, "Use F1 or ? to get more help, arrow keys to select.");
    move(0, 0);
}

static u_char *
getBootMgr(char *dname)
{
    extern u_char mbr[], boot0[];
    char str[80];
    char *cp;
    int i = 0;

#ifndef __alpha__	/* only meaningful on x86 */
    cp = variable_get(VAR_BOOTMGR);
    if (!cp) {
	/* Figure out what kind of MBR the user wants */
	sprintf(str, "Install Boot Manager for drive %s?", dname);
	MenuMBRType.title = str;
	i = dmenuOpenSimple(&MenuMBRType, FALSE);
    }
    else {
	if (!strncmp(cp, "boot", 4))
	    BootMgr = 0;
	else if (!strcmp(cp, "standard"))
	    BootMgr = 1;
	else
	    BootMgr = 2;
    }
    if (cp || i) {
	switch (BootMgr) {
	case 0:
	    return boot0;

	case 1:
	    return mbr;

	case 2:
	default:
	    break;
	}
    }
#endif
    return NULL;
}

int
diskGetSelectCount(Device ***devs)
{
    int i, cnt, enabled;
    char *cp;
    Device **dp;

    cp = variable_get(VAR_DISK);
    dp = *devs = deviceFind(cp, DEVICE_TYPE_DISK);
    cnt = deviceCount(dp);
    if (!cnt)
	return -1;
    for (i = 0, enabled = 0; i < cnt; i++) {
	if (dp[i]->enabled)
	    ++enabled;
    }
    return enabled;
}

void
diskPartition(Device *dev)
{
    char *cp, *p;
    int rv, key = 0;
    Boolean chunking;
    char *msg = NULL;
    u_char *mbrContents;
    WINDOW *w = savescr();
    Disk *d = (Disk *)dev->private;

    chunking = TRUE;
    keypad(stdscr, TRUE);

    /* Flush both the dialog and curses library views of the screen
       since we don't always know who called us */
    dialog_clear_norefresh(), clear();
    current_chunk = 0;

    /* Set up the chunk array */
    record_chunks(d);

    while (chunking) {
	char *val, geometry[80];
	    
	/* Now print our overall state */
	if (d)
	    print_chunks(d);
	print_command_summary();
	if (msg) {
	    attrset(title_attr); mvprintw(23, 0, msg); attrset(A_NORMAL);
	    beep();
	    msg = NULL;
	}
	else {
	    move(23, 0);
	    clrtoeol();
	}

	/* Get command character */
	key = getch();
	switch (toupper(key)) {
	case '\014':	/* ^L (redraw) */
	    clear();
	    msg = NULL;
	    break;
	    
	case '\020':	/* ^P */
	case KEY_UP:
	case '-':
	    if (current_chunk != 0)
		--current_chunk;
	    break;
	    
	case '\016':	/* ^N */
	case KEY_DOWN:
	case '+':
	case '\r':
	case '\n':
	    if (chunk_info[current_chunk + 1])
		++current_chunk;
	    break;

	case KEY_HOME:
	    current_chunk = 0;
	    break;

	case KEY_END:
	    while (chunk_info[current_chunk + 1])
		++current_chunk;
	    break;

	case KEY_F(1):
	case '?':
	    systemDisplayHelp("slice");
	    clear();
	    break;

	case 'A':
#ifdef __alpha__
	    rv = 1;
#else	    /* The rest is only relevant on x86 */
	    cp = variable_get(VAR_DEDICATE_DISK);
	    if (cp && !strcasecmp(cp, "always"))
		rv = 1;
	    else {
		rv = msgYesNo("Do you want to do this with a true partition entry\n"
			      "so as to remain cooperative with any future possible\n"
			      "operating systems on the drive(s)?\n"
			      "(See also the section about ``dangerously dedicated''\n"
			      "disks in the FreeBSD FAQ.)");
		if (rv == -1)
		    rv = 0;
	    }
#endif
	    All_FreeBSD(d, rv);
	    variable_set2(DISK_PARTITIONED, "yes");
	    record_chunks(d);
	    clear();
	    break;
	    
	case 'B':
	    if (chunk_info[current_chunk]->type != freebsd)
		msg = "Can only scan for bad blocks in FreeBSD slice.";
	    else if (strncmp(d->name, "sd", 2) ||
		     strncmp(d->name, "da", 2) ||
		     !msgYesNo("This typically makes sense only for ESDI, IDE or MFM drives.\n"
			       "Are you sure you want to do this on a SCSI disk?")) {
		if (chunk_info[current_chunk]->flags & CHUNK_BAD144)
		    chunk_info[current_chunk]->flags &= ~CHUNK_BAD144;
		else
		    chunk_info[current_chunk]->flags |= CHUNK_BAD144;
	    }
	    clear();
	    break;
	    
	case 'C':
	    if (chunk_info[current_chunk]->type != unused)
		msg = "Slice in use, delete it first or move to an unused one.";
	    else {
		char *val, tmp[20], *cp;
		int size, subtype;
		chunk_e partitiontype;
		
		snprintf(tmp, 20, "%lu", chunk_info[current_chunk]->size);
		val = msgGetInput(tmp, "Please specify the size for new FreeBSD slice in blocks\n"
				  "or append a trailing `M' for megabytes (e.g. 20M).");
		if (val && (size = strtol(val, &cp, 0)) > 0) {
		    if (*cp && toupper(*cp) == 'M')
			size *= ONE_MEG;
		    strcpy(tmp, "165");
		    val = msgGetInput(tmp, "Enter type of partition to create:\n\n"
				      "Pressing Enter will choose the default, a native FreeBSD\n"
				      "slice (type 165).  You can choose other types, 6 for a\n"
				      "DOS partition or 131 for a Linux partition, for example.\n\n"
				      "Note:  If you choose a non-FreeBSD partition type, it will not\n"
				      "be formatted or otherwise prepared, it will simply reserve space\n"
				      "for you to use another tool, such as DOS FORMAT, to later format\n"
				      "and use the partition.");
		    if (val && (subtype = strtol(val, NULL, 0)) > 0) {
			if (subtype == 165)
			    partitiontype = freebsd;
			else if (subtype == 6)
			    partitiontype = fat;
			else
			    partitiontype = unknown;
#ifdef __alpha__
			if (partitiontype == freebsd && size == chunk_info[current_chunk]->size)
			    All_FreeBSD(d, 1);
			else
#endif
			Create_Chunk(d, chunk_info[current_chunk]->offset, size, partitiontype, subtype,
				     (chunk_info[current_chunk]->flags & CHUNK_ALIGN));
			variable_set2(DISK_PARTITIONED, "yes");
			record_chunks(d);
		    }
		}
		clear();
	    }
	    break;
	    
	case KEY_DC:
	case 'D':
	    if (chunk_info[current_chunk]->type == unused)
		msg = "Slice is already unused!";
	    else {
		Delete_Chunk(d, chunk_info[current_chunk]);
		variable_set2(DISK_PARTITIONED, "yes");
		record_chunks(d);
	    }
	    break;
	    
	case 'T':
	    if (chunk_info[current_chunk]->type == unused)
		msg = "Slice is currently unused (use create instead)";
	    else {
		char *val, tmp[20];
		int subtype;
		chunk_e partitiontype;
		WINDOW *save = savescr();

		strcpy(tmp, "165");
		val = msgGetInput(tmp, "New partition type:\n\n"
				  "Pressing Enter will choose the default, a native FreeBSD\n"
				  "slice (type 165).  Other popular values are 6 for\n"
				  "DOS FAT partition, 131 for a Linux ext2fs partition or\n"
				  "130 for a Linux swap partition.\n\n"
				  "Note:  If you choose a non-FreeBSD partition type, it will not\n"
				  "be formatted or otherwise prepared, it will simply reserve space\n"
				  "for you to use another tool, such as DOS format, to later format\n"
				  "and actually use the partition.");
		if (val && (subtype = strtol(val, NULL, 0)) > 0) {
		    if (subtype == 165)
			partitiontype = freebsd;
		    else if (subtype == 6)
			partitiontype = fat;
		    else
			partitiontype = unknown;
		    chunk_info[current_chunk]->type = partitiontype;
		    chunk_info[current_chunk]->subtype = subtype;
		}
		restorescr(save);
	    }
	    break;
	    
	case 'G':
	    snprintf(geometry, 80, "%lu/%lu/%lu", d->bios_cyl, d->bios_hd, d->bios_sect);
	    val = msgGetInput(geometry, "Please specify the new geometry in cyl/hd/sect format.\n"
			      "Don't forget to use the two slash (/) separator characters!\n"
			      "It's not possible to parse the field without them.");
	    if (val) {
		long nc, nh, ns;
		nc = strtol(val, &val, 0);
		nh = strtol(val + 1, &val, 0);
		ns = strtol(val + 1, 0, 0);
		Set_Bios_Geom(d, nc, nh, ns);
	    }
	    clear();
	    break;
	
	case 'S':
	    /* Set Bootable */
	    chunk_info[current_chunk]->flags |= CHUNK_ACTIVE;
	    break;
	
	case 'U':
	    if ((cp = variable_get(DISK_LABELLED)) && !strcmp(cp, "written")) {
		msgConfirm("You've already written this information out - you\n"
			   "can't undo it.");
	    }
	    else if (!msgYesNo("Are you SURE you want to Undo everything?")) {
		char cp[BUFSIZ];

		sstrncpy(cp, d->name, sizeof cp);
		Free_Disk(dev->private);
		d = Open_Disk(cp);
		if (!d)
		    msgConfirm("Can't reopen disk %s! Internal state is probably corrupted", cp);
		dev->private = d;
		variable_unset(DISK_PARTITIONED);
		variable_unset(DISK_LABELLED);
		if (d)
		    record_chunks(d);
	    }
	    clear();
	    break;

	case 'W':
	    if (!msgYesNo("WARNING:  This should only be used when modifying an EXISTING\n"
			       "installation.  If you are installing FreeBSD for the first time\n"
			       "then you should simply type Q when you're finished here and your\n"
			       "changes will be committed in one batch automatically at the end of\n"
			       "these questions.  If you're adding a disk, you should NOT write\n"
			       "from this screen, you should do it from the label editor.\n\n"
			       "Are you absolutely sure you want to do this now?")) {
		variable_set2(DISK_PARTITIONED, "yes");
		
		/* Don't trash the MBR if the first (and therefore only) chunk is marked for a truly dedicated
		 * disk (i.e., the disklabel starts at sector 0), even in cases where the user has requested
		 * booteasy or a "standard" MBR -- both would be fatal in this case.
		 */
#if 0
		if ((d->chunks->part->flags & CHUNK_FORCE_ALL) != CHUNK_FORCE_ALL
		    && (mbrContents = getBootMgr(d->name)) != NULL)
		    Set_Boot_Mgr(d, mbrContents);
#else
		/*
		 * Don't offer to update the MBR on this disk if the first "real" chunk looks like
		 * a FreeBSD "all disk" partition, or the disk is entirely FreeBSD.
		 */
		if (((d->chunks->part->type != freebsd) || (d->chunks->part->offset > 1)) &&
		    (mbrContents = getBootMgr(d->name)) != NULL)
		    Set_Boot_Mgr(d, mbrContents);
#endif
		
		if (DITEM_STATUS(diskPartitionWrite(NULL)) != DITEM_SUCCESS)
		    msgConfirm("Disk partition write returned an error status!");
		else
		    msgConfirm("Wrote FDISK partition information out successfully.");
	    }
	    clear();
	    break;
	    
	case '|':
	    if (!msgYesNo("Are you SURE you want to go into Wizard mode?\n"
			  "No seat belts whatsoever are provided!")) {
		clear();
		refresh();
		slice_wizard(d);
		variable_set2(DISK_PARTITIONED, "yes");
		record_chunks(d);
	    }
	    else
		msg = "Wise choice!";
	    clear();
	    break;

	case '\033':	/* ESC */
	case 'Q':
	    chunking = FALSE;
	    /* Don't trash the MBR if the first (and therefore only) chunk is marked for a truly dedicated
	     * disk (i.e., the disklabel starts at sector 0), even in cases where the user has requested
	     * booteasy or a "standard" MBR -- both would be fatal in this case.
	     */
#if 0
	    if ((d->chunks->part->flags & CHUNK_FORCE_ALL) != CHUNK_FORCE_ALL
		&& (mbrContents = getBootMgr(d->name)) != NULL)
		Set_Boot_Mgr(d, mbrContents);
#else
	    /*
	     * Don't offer to update the MBR on this disk if the first "real" chunk looks like
	     * a FreeBSD "all disk" partition, or the disk is entirely FreeBSD. 
	     */
	    if (((d->chunks->part->type != freebsd) || (d->chunks->part->offset > 1)) &&
		(mbrContents = getBootMgr(d->name)) != NULL)
		Set_Boot_Mgr(d, mbrContents);
#endif
	    break;
	    
	default:
	    beep();
	    msg = "Type F1 or ? for help";
	    break;
	}
    }
    p = CheckRules(d);
    if (p) {
	char buf[FILENAME_MAX];
	
	dialog_clear_norefresh();
        use_helpline("Press F1 to read more about disk slices.");
	use_helpfile(systemHelpFile("partition", buf));
	if (!variable_get(VAR_NO_WARN))
	    dialog_mesgbox("Disk slicing warning:", p, -1, -1);
	free(p);
    }
    restorescr(w);
}

static int
partitionHook(dialogMenuItem *selected)
{
    Device **devs = NULL;

    devs = deviceFind(selected->prompt, DEVICE_TYPE_DISK);
    if (!devs) {
	msgConfirm("Unable to find disk %s!", selected->prompt);
	return DITEM_FAILURE;
    }
    /* Toggle enabled status? */
    if (!devs[0]->enabled) {
	devs[0]->enabled = TRUE;
	diskPartition(devs[0]);
    }
    else
	devs[0]->enabled = FALSE;
    return DITEM_SUCCESS | DITEM_RESTORE;
}

static int
partitionCheck(dialogMenuItem *selected)
{
    Device **devs = NULL;

    devs = deviceFind(selected->prompt, DEVICE_TYPE_DISK);
    if (!devs || devs[0]->enabled == FALSE)
	return FALSE;
    return TRUE;
}

int
diskPartitionEditor(dialogMenuItem *self)
{
    DMenu *menu;
    Device **devs;
    int i, cnt, devcnt;

    cnt = diskGetSelectCount(&devs);
    devcnt = deviceCount(devs);
    if (cnt == -1) {
	msgConfirm("No disks found!  Please verify that your disk controller is being\n"
		   "properly probed at boot time.  See the Hardware Guide on the\n"
		   "Documentation menu for clues on diagnosing this type of problem.");
	return DITEM_FAILURE;
    }
    else if (cnt) {
	/* Some are already selected */
	for (i = 0; i < devcnt; i++) {
	    if (devs[i]->enabled) {
		if (variable_get(VAR_NONINTERACTIVE))
		    diskPartitionNonInteractive(devs[i]);
		else
		    diskPartition(devs[i]);
	    }
	}
    }
    else {
	/* No disks are selected, fall-back case now */
	if (devcnt == 1) {
	    devs[0]->enabled = TRUE;
	    if (variable_get(VAR_NONINTERACTIVE))
		diskPartitionNonInteractive(devs[0]);
	    else
		diskPartition(devs[0]);
	    return DITEM_SUCCESS;
	}
	else {
	    menu = deviceCreateMenu(&MenuDiskDevices, DEVICE_TYPE_DISK, partitionHook, partitionCheck);
	    if (!menu) {
		msgConfirm("No devices suitable for installation found!\n\n"
			   "Please verify that your disk controller (and attached drives)\n"
			   "were detected properly.  This can be done by pressing the\n"
			   "[Scroll Lock] key and using the Arrow keys to move back to\n"
			   "the boot messages.  Press [Scroll Lock] again to return.");
		return DITEM_FAILURE;
	    }
	    else {
		i = dmenuOpenSimple(menu, FALSE) ? DITEM_SUCCESS : DITEM_FAILURE;
		free(menu);
	    }
	    return i | DITEM_RESTORE;
	}
    }
    return DITEM_SUCCESS;
}

int
diskPartitionWrite(dialogMenuItem *self)
{
    Device **devs;
    int i;
    char *cp;

    devs = deviceFind(NULL, DEVICE_TYPE_DISK);
    if (!devs) {
	msgConfirm("Unable to find any disks to write to??");
	return DITEM_FAILURE;
    }
    if (isDebug())
	msgDebug("diskPartitionWrite: Examining %d devices\n", deviceCount(devs));
    cp = variable_get(DISK_PARTITIONED);
    if (cp && !strcmp(cp, "written"))
	return DITEM_SUCCESS;

    for (i = 0; devs[i]; i++) {
	Chunk *c1;
	Disk *d = (Disk *)devs[i]->private;

	if (!devs[i]->enabled)
	    continue;

#ifdef __alpha__
	Set_Boot_Blocks(d, boot1, NULL);
#else
	Set_Boot_Blocks(d, boot1, boot2);
#endif
	msgNotify("Writing partition information to drive %s", d->name);
	if (!Fake && Write_Disk(d)) {
	    msgConfirm("ERROR: Unable to write data to disk %s!", d->name);
	    return DITEM_FAILURE;
	}

	/* If we've been through here before, we don't need to do the rest */
	if (cp && !strcmp(cp, "written"))
	    return DITEM_SUCCESS;

	/* Now scan for bad blocks, if necessary */
	for (c1 = d->chunks->part; c1; c1 = c1->next) {
	    if (c1->flags & CHUNK_BAD144) {
		int ret;

		msgNotify("Running bad block scan on slice %s", c1->name);
		if (!Fake) {
		    ret = vsystem("bad144 -v /dev/r%s 1234", c1->name);
		    if (ret)
			msgConfirm("Bad144 init on %s returned status of %d!", c1->name, ret);
		    ret = vsystem("bad144 -v -s /dev/r%s", c1->name);
		    if (ret)
			msgConfirm("Bad144 scan on %s returned status of %d!", c1->name, ret);
		}
	    }
	}
    }
    /* Now it's not "yes", but "written" */
    variable_set2(DISK_PARTITIONED, "written");
    return DITEM_SUCCESS;
}

/* Partition a disk based wholly on which variables are set */
static void
diskPartitionNonInteractive(Device *dev)
{
    char *cp;
    int i, sz, all_disk = 0;
    u_char *mbrContents;
    Disk *d = (Disk *)dev->private;

    record_chunks(d);
    cp = variable_get(VAR_GEOMETRY);
    if (cp) {
	msgDebug("Setting geometry from script to: %s\n", cp);
	d->bios_cyl = strtol(cp, &cp, 0);
	d->bios_hd = strtol(cp + 1, &cp, 0);
	d->bios_sect = strtol(cp + 1, 0, 0);
    }

    cp = variable_get(VAR_PARTITION);
    if (cp) {
	if (!strcmp(cp, "free")) {
	    /* Do free disk space case */
	    for (i = 0; chunk_info[i]; i++) {
		/* If a chunk is at least 10MB in size, use it. */
		if (chunk_info[i]->type == unused && chunk_info[i]->size > (10 * ONE_MEG)) {
		    Create_Chunk(d, chunk_info[i]->offset, chunk_info[i]->size, freebsd, 3,
				 (chunk_info[i]->flags & CHUNK_ALIGN));
		    variable_set2(DISK_PARTITIONED, "yes");
		    break;
		}
	    }
	    if (!chunk_info[i]) {
		dialog_clear();
		msgConfirm("Unable to find any free space on this disk!");
		return;
	    }
	}
	else if (!strcmp(cp, "all")) {
	    /* Do all disk space case */
	    msgDebug("Warning:  Devoting all of disk %s to FreeBSD.\n", d->name);

	    All_FreeBSD(d, FALSE);
	}
	else if (!strcmp(cp, "exclusive")) {
	    /* Do really-all-the-disk-space case */
	    msgDebug("Warning:  Devoting all of disk %s to FreeBSD.\n", d->name);

	    All_FreeBSD(d, all_disk = TRUE);
	}
	else if ((sz = strtol(cp, &cp, 0))) {
	    /* Look for sz bytes free */
	    if (*cp && toupper(*cp) == 'M')
		sz *= ONE_MEG;
	    for (i = 0; chunk_info[i]; i++) {
		/* If a chunk is at least sz MB, use it. */
		if (chunk_info[i]->type == unused && chunk_info[i]->size >= sz) {
		    Create_Chunk(d, chunk_info[i]->offset, sz, freebsd, 3, (chunk_info[i]->flags & CHUNK_ALIGN));
		    variable_set2(DISK_PARTITIONED, "yes");
		    break;
		}
	    }
	    if (!chunk_info[i]) {
		dialog_clear();
		msgConfirm("Unable to find %d free blocks on this disk!", sz);
		return;
	    }
	}
	else if (!strcmp(cp, "existing")) {
	    /* Do existing FreeBSD case */
	    for (i = 0; chunk_info[i]; i++) {
		if (chunk_info[i]->type == freebsd)
		    break;
	    }
	    if (!chunk_info[i]) {
		dialog_clear();
		msgConfirm("Unable to find any existing FreeBSD partitions on this disk!");
		return;
	    }
	}
	else {
	    dialog_clear();
	    msgConfirm("`%s' is an invalid value for %s - is config file valid?", cp, VAR_PARTITION);
	    return;
	}
	if (!all_disk) {
	    mbrContents = getBootMgr(d->name);
	    Set_Boot_Mgr(d, mbrContents);
	}
	variable_set2(DISK_PARTITIONED, "yes");
    }
}
