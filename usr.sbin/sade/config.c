/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: config.c,v 1.22 1996/03/24 18:57:34 joerg Exp $
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jordan Hubbard
 *	for the FreeBSD Project.
 * 4. The name of Jordan Hubbard or the FreeBSD project may not be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
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
#include <sys/disklabel.h>
#include <sys/wait.h>

static Chunk *chunk_list[MAX_CHUNKS];
static int nchunks;

/* arg to sort */
static int
chunk_compare(Chunk *c1, Chunk *c2)
{
    if (!c1 && !c2)
	return 0;
    else if (!c1 && c2)
	return 1;
    else if (c1 && !c2)
	return -1;
    else if (!c1->private_data && !c2->private_data)
	return 0;
    else if (c1->private_data && !c2->private_data)
	return 1;
    else if (!c1->private_data && c2->private_data)
	return -1;
    else
	return strcmp(((PartInfo *)(c1->private_data))->mountpoint, ((PartInfo *)(c2->private_data))->mountpoint);
}

static void
chunk_sort(void)
{
    int i, j;

    for (i = 0; i < nchunks; i++) {
	for (j = 0; j < nchunks; j++) {
	    if (chunk_compare(chunk_list[j], chunk_list[j + 1]) > 0) {
		Chunk *tmp = chunk_list[j];

		chunk_list[j] = chunk_list[j + 1];
		chunk_list[j + 1] = tmp;
	    }
	}
    }
}

static char *
name_of(Chunk *c1)
{
    static char rootname[32];

    /* Our boot blocks can't deal with root partitions on slices - need the compatbility name */
    if (c1->type == part && c1->flags & CHUNK_IS_ROOT) {
        sprintf(rootname, "%sa", c1->disk->name);
        return rootname;
    }
    else
        return c1->name;
}

static char *
mount_point(Chunk *c1)
{
    if (c1->type == part && c1->subtype == FS_SWAP)
	return "none";
    else if (c1->type == part || c1->type == fat)
	return ((PartInfo *)c1->private_data)->mountpoint;
    return "/bogus";
}

static char *
fstype(Chunk *c1)
{
    if (c1->type == fat)
	return "msdos";
    else if (c1->type == part) {
	if (c1->subtype != FS_SWAP)
	    return "ufs";
	else
	    return "swap";
    }
    return "bogus";
}

static char *
fstype_short(Chunk *c1)
{
    if (c1->type == part) {
	if (c1->subtype != FS_SWAP)
	    return "rw";
	else
	    return "sw";
    }
    else if (c1->type == fat)
	return "ro";
    return "bog";
}

static int
seq_num(Chunk *c1)
{
    if (c1->type == part && c1->subtype != FS_SWAP)
	return 1;
    return 0;
}

int
configFstab(void)
{
    Device **devs;
    Disk *disk;
    FILE *fstab;
    int i, cnt;
    Chunk *c1, *c2;

    if (!RunningAsInit) {
	if (file_readable("/etc/fstab"))
	    return RET_SUCCESS;
	else {
	    dialog_clear();
	    msgConfirm("Attempting to rebuild your /etc/fstab file.  Warning: If you had\n"
		       "any CD devices in use before running sysinstall then they may NOT\n"
		       "be found by this run!");
	}
    }

    devs = deviceFind(NULL, DEVICE_TYPE_DISK);
    if (!devs) {
	dialog_clear();
	msgConfirm("No disks found!");
	return RET_FAIL;
    }

    /* Record all the chunks */
    nchunks = 0;
    for (i = 0; devs[i]; i++) {
	if (!devs[i]->enabled)
	    continue;
	disk = (Disk *)devs[i]->private;
	if (!disk->chunks)
	    msgFatal("No chunk list found for %s!", disk->name);
	for (c1 = disk->chunks->part; c1; c1 = c1->next) {
	    if (c1->type == freebsd) {
		for (c2 = c1->part; c2; c2 = c2->next) {
		    if (c2->type == part && (c2->subtype == FS_SWAP || c2->private_data))
			chunk_list[nchunks++] = c2;
		}
	    }
	    else if (c1->type == fat && c1->private_data)
		chunk_list[nchunks++] = c1;
	}
    }
    chunk_list[nchunks] = 0;
    chunk_sort();

    fstab = fopen("/etc/fstab", "w");
    if (!fstab) {
	dialog_clear();
	msgConfirm("Unable to create a new /etc/fstab file!  Manual intervention\n"
		   "will be required.");
	return RET_FAIL;
    }

    /* Go for the burn */
    msgDebug("Generating /etc/fstab file\n");
    for (i = 0; i < nchunks; i++)
	fprintf(fstab, "/dev/%s\t\t\t%s\t\t%s\t%s %d %d\n", name_of(chunk_list[i]), mount_point(chunk_list[i]),
		fstype(chunk_list[i]), fstype_short(chunk_list[i]), seq_num(chunk_list[i]), seq_num(chunk_list[i]));
    Mkdir("/proc", NULL);
    fprintf(fstab, "proc\t\t\t\t/proc\t\tprocfs\trw 0 0\n");

    /* Now look for the CDROMs */
    devs = deviceFind(NULL, DEVICE_TYPE_CDROM);
    cnt = deviceCount(devs);

    /* Write the first one out as /cdrom */
    if (cnt) {
	if (Mkdir("/cdrom", NULL)) {
	    dialog_clear();
	    msgConfirm("Unable to make mount point for: /cdrom");
	}
	else
	    fprintf(fstab, "/dev/%s\t\t\t/cdrom\t\tcd9660\tro,noauto 0 0\n", devs[0]->name);
    }

    /* Write the others out as /cdrom<n> */
    for (i = 1; i < cnt; i++) {
	char cdname[10];

	sprintf(cdname, "/cdrom%d", i);
	if (Mkdir(cdname, NULL)) {
	    dialog_clear();
	    msgConfirm("Unable to make mount point for: %s", cdname);
	}
	else
	    fprintf(fstab, "/dev/%s\t\t\t%s\t\tcd9660\tro,noauto 0 0\n", devs[i]->name, cdname);
    }
    fclose(fstab);
    if (isDebug())
	msgDebug("Wrote out /etc/fstab file\n");
    return RET_SUCCESS;
}

/*
 * This sucks in /etc/sysconfig, substitutes anything needing substitution, then
 * writes it all back out.  It's pretty gross and needs re-writing at some point.
 */

#define MAX_LINES  2000 /* Some big number we're not likely to ever reach - I'm being really lazy here, I know */
void
configSysconfig(void)
{
    FILE *fp;
    char *lines[MAX_LINES], *cp;
    char line[256];
    Variable *v;
    int i, nlines;

    fp = fopen("/etc/sysconfig", "r");
    if (!fp) {
	dialog_clear();
	msgConfirm("Unable to open /etc/sysconfig file!  Things may work\n"
		   "rather strangely as a result of this.");
	return;
    }
    msgNotify("Writing configuration changes to /etc/sysconfig file..");

    nlines = 0;
    /* Read in the entire file */
    for (i = 0; i < MAX_LINES; i++) {
	if (!fgets(line, 255, fp))
	    break;
	lines[nlines++] = strdup(line);
    }
    msgDebug("Read %d lines from sysconfig.\n", nlines);
    /* Now do variable substitutions */
    for (v = VarHead; v; v = v->next) {
	for (i = 0; i < nlines; i++) {
	    char tmp[256];

	    /* Skip the comments */
	    if (lines[i][0] == '#')
		continue;
	    strcpy(tmp, lines[i]);
	    cp = index(tmp, '=');
	    if (!cp)
		continue;
	    *(cp++) = '\0';
	    if (!strcmp(tmp, v->name)) {
		free(lines[i]);
		lines[i] = (char *)malloc(strlen(v->name) + strlen(v->value) + 5);
		sprintf(lines[i], "%s=\"%s\"\n", v->name, v->value);
		msgDebug("Variable substitution on: %s\n", lines[i]);
	    }
	}
    }

    /* Now write it all back out again */
    fclose(fp);
    fp = fopen("/etc/sysconfig", "w");
    for (i = 0; i < nlines; i++) {
	static Boolean firstTime = TRUE;

	fprintf(fp, lines[i]);
	/* Stand by for bogus special case handling - we try to dump the interface specs here */
	if (firstTime && !strncmp(lines[i], VAR_INTERFACES, strlen(VAR_INTERFACES))) {
	    Device **devp;
	    int j, cnt;

	    devp = deviceFind(NULL, DEVICE_TYPE_NETWORK);
	    cnt = deviceCount(devp);
	    for (j = 0; j < cnt; j++) {
		char iname[255];

		snprintf(iname, 255, "%s%s", VAR_IFCONFIG, devp[j]->name);
		if ((cp = variable_get(iname))) {
		    fprintf(fp, "%s=\"%s\"\n", iname, cp);
		}
	    }
	    firstTime = FALSE;
	}
	free(lines[i]);
    }
    fclose(fp);
}

int
configSaverTimeout(dialogMenuItem *self)
{
    return variable_get_value(VAR_BLANKTIME, "Enter time-out period in seconds for screen saver") ?
	RET_SUCCESS : RET_FAIL;
}

int
configNTP(dialogMenuItem *self)
{
    return variable_get_value(VAR_NTPDATE, "Enter the name of an NTP server") ? RET_SUCCESS : RET_FAIL;
}

int
configXFree86(dialogMenuItem *self)
{
    if (file_executable("/usr/X11R6/bin/xf86config")) {
	systemExecute("/usr/X11R6/bin/xf86config");
	return RET_SUCCESS;
    }
    else {
	msgConfirm("XFree86 does not appear to be installed!  Please install\n"
		   "The XFree86 distribution before attempting to configure it.");
	return RET_FAIL;
    }
}

void
configResolv(void)
{
    FILE *fp;
    char *cp, *dp, *hp;

    if (!RunningAsInit && file_readable("/etc/resolv.conf"))
	return;

    if (!variable_get(VAR_NAMESERVER)) {
	if (mediaDevice && (mediaDevice->type == DEVICE_TYPE_NFS || mediaDevice->type == DEVICE_TYPE_FTP)) {
	    dialog_clear();
	    msgConfirm("Warning:  Missing name server value - network operations\n"
		       "may fail as a result!");
	}
	goto skip;
    }
    if (Mkdir("/etc", NULL)) {
	dialog_clear();
	msgConfirm("Unable to create /etc directory.  Network configuration\n"
		   "files will therefore not be written!");
	return;
    }
    fp = fopen("/etc/resolv.conf", "w");
    if (!fp) {
	dialog_clear();
	msgConfirm("Unable to open /etc/resolv.conf!  You will need to do this manually.");
	return;
    }
    if (variable_get(VAR_DOMAINNAME))
	fprintf(fp, "domain\t%s\n", variable_get(VAR_DOMAINNAME));
    fprintf(fp, "nameserver\t%s\n", variable_get(VAR_NAMESERVER));
    fclose(fp);
    if (isDebug())
	msgDebug("Wrote out /etc/resolv.conf\n");

skip:
    /* Tack ourselves into /etc/hosts */
    cp = variable_get(VAR_IPADDR);
    dp = variable_get(VAR_DOMAINNAME);
    if (cp && *cp != '0' && (hp = variable_get(VAR_HOSTNAME))) {
	char cp2[255];

	(void)vsystem("/bin/hostname %s", hp);
	fp = fopen("/etc/hosts", "w");
	if (!index(hp, '.'))
	    cp2[0] = '\0';
	else {
	    strcpy(cp2, hp);
	    *(index(cp2, '.')) = '\0';
	}
	fprintf(fp, "127.0.0.1\t\tlocalhost.%s localhost\n", dp ? dp : "my.domain");
	fprintf(fp, "%s\t\t%s %s\n", cp, hp, cp2);
	fclose(fp);
	if (isDebug())
	    msgDebug("Wrote entry for %s to /etc/hosts\n", cp);
    }
}

int
configRoutedFlags(dialogMenuItem *self)
{
    return variable_get_value(VAR_ROUTEDFLAGS, 
			      "Specify the flags for routed; -q is the default, -s is\n"
			      "a good choice for gateway machines.") ? RET_SUCCESS : RET_FAIL;
}

int
configPackages(dialogMenuItem *self)
{
    static PkgNode top, plist;
    static Boolean index_initted = FALSE;
    PkgNodePtr tmp;
    int fd;

    if (!mediaVerify())
	return RET_FAIL;

    if (!mediaDevice->init(mediaDevice))
	return RET_FAIL;

    if (!index_initted) {
	msgNotify("Attempting to fetch packages/INDEX file from selected media.");
	fd = mediaDevice->get(mediaDevice, "packages/INDEX", TRUE);
	if (fd < 0) {
	    dialog_clear();
	    msgConfirm("Unable to get packages/INDEX file from selected media.\n"
		       "This may be because the packages collection is not available at\n"
		       "on the distribution media you've chosen (most likely an FTP site\n"
		       "without the packages collection mirrored).  Please verify media\n"
		       "(or path to media) and try again.  If your local site does not\n"
		       "carry the packages collection, then we recommend either a CD\n"
		       "distribution or the master distribution on ftp.freebsd.org.");
	    return RET_FAIL;
	}
	msgNotify("Got INDEX successfully, now building packages menu..");
	index_init(&top, &plist);
	if (index_read(fd, &top)) {
	    dialog_clear();
	    msgConfirm("I/O or format error on packages/INDEX file.\n"
		       "Please verify media (or path to media) and try again.");
	    mediaDevice->close(mediaDevice, fd);
	    return RET_FAIL;
	}
	mediaDevice->close(mediaDevice, fd);
	index_sort(&top);
	index_initted = TRUE;
    }
    while (1) {
	int ret, pos, scroll;

	/* Bring up the packages menu */
	pos = scroll = 0;
	index_menu(&top, &plist, &pos, &scroll);

	if (plist.kids) {
	    /* Now show the packing list menu */
	    pos = scroll = 0;
	    ret = index_menu(&plist, NULL, &pos, &scroll);
	    if (ret == RET_DONE)
		break;
	    else if (ret != RET_FAIL) {
		index_extract(mediaDevice, &top, &plist);
		break;
	    }
	}
	else {
	    dialog_clear();
	    msgConfirm("No packages were selected for extraction.");
	    break;
	}
    }
    tmp = &plist;
    while (tmp) {
        PkgNodePtr tmp2 = tmp->next;
           
        safe_free(tmp);
        tmp = tmp2;
    }
    index_init(NULL, &plist);
    mediaDevice->shutdown(mediaDevice);
    return RET_SUCCESS;
}

int
configPorts(dialogMenuItem *self)
{
    char *cp, *dist = NULL; /* Shut up compiler */

    if (!variable_get(VAR_PORTS_PATH))
	variable_set2(VAR_PORTS_PATH, dist = "/cdrom/ports");
    while (!directory_exists(dist)) {
	dist = variable_get_value(VAR_PORTS_PATH,
				  "Unable to locate a ports tree on CDROM.  Please specify the\n"
				  "location of the master ports directory you wish to create the\n"
				  "link tree to.");
	if (!dist)
	    break;
    }
    if (dist) {
	cp = msgGetInput("/usr/ports",
			 "Where would you like to create the link tree?\n"
			 "(press [ENTER] for default location).  The link tree should\n"
			 "reside in a directory with as much free space as possible,\n"
			 "as you'll need space to compile any ports.");
	if (!cp || !*cp)
	    return RET_FAIL;
	if (Mkdir(cp, NULL)) {
	    dialog_clear();
	    msgConfirm("Unable to make the %s directory!", cp);
	    return RET_FAIL;
	}
	else {
	    if (strcmp(cp, "/usr/ports")) {
		unlink("/usr/ports");
		if (symlink(cp, "/usr/ports") == -1) {
		    msgConfirm("Unable to create a symlink from /usr/ports to %s!\n"
			       "I can't continue, sorry!", cp);
		    return RET_FAIL;
		}
		else {
		    msgConfirm("NOTE: This directory is also now symlinked to /usr/ports\n"
			       "which, for a variety of reasons, is the directory the ports\n"
			       "framework expects to find its files in.  You should refer to\n"
			       "/usr/ports instead of %s directly when you're working in the\n"
			       "ports collection.", cp);
		}
	    }
	    msgNotify("Making a link tree from %s to %s.", dist, cp);
	    if (lndir(dist, cp) != RET_SUCCESS) {
		dialog_clear();
		msgConfirm("The lndir function returned an error status and may not have.\n"
			   "successfully generated the link tree.  You may wish to inspect\n"
			   "the /usr/ports directory carefully for any missing link files.");
	    }
	    else {
		msgConfirm("The /usr/ports directory is now ready to use.  When the system comes\n"
			   "up fully, you can cd to this directory and type `make' in any sub-\n"
			   "directory for which you'd like to compile a port.  You can also\n"
			   "cd to /usr/ports and type `make print-index' for a complete list of all\n"
			   "ports in the hierarchy.");
	    }
	}
    }
    else
	return RET_FAIL;
    return RET_SUCCESS;
}
