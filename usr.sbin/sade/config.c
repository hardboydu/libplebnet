/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $FreeBSD$
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
#include <sys/disklabel.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>

static Chunk *chunk_list[MAX_CHUNKS];
static int nchunks;
static int rootdev_is_od;

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

static void
check_rootdev(Chunk **list, int n)
{
	int i;
	Chunk *c;

	rootdev_is_od = 0;
	for (i = 0; i < n; i++) {
		c = *list++;
		if (c->type == part && (c->flags & CHUNK_IS_ROOT)
		    && strncmp(c->disk->name, "od", 2) == 0)
			rootdev_is_od = 1;
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
	if (c1->subtype != FS_SWAP) {
	    if (rootdev_is_od == 0 && strncmp(c1->name, "od", 2) == 0)
		return "rw,noauto";
	    else
		return "rw";
	}
	else
	    return "sw";
    }
    else if (c1->type == fat) {
	if (strncmp(c1->name, "od", 2) == 0)
	    return "ro,noauto";
	else
	    return "ro";
    }
    return "bog";
}

static int
seq_num(Chunk *c1)
{
    if (c1->type == part && c1->subtype != FS_SWAP) {
	if (rootdev_is_od == 0 && strncmp(c1->name, "od", 2) == 0)
	    return 0;
	else
	    return 1;
    }
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
	    return DITEM_SUCCESS;
	else {
	    msgConfirm("Attempting to rebuild your /etc/fstab file.  Warning: If you had\n"
		       "any CD devices in use before running sysinstall then they may NOT\n"
		       "be found by this run!");
	}
    }

    devs = deviceFind(NULL, DEVICE_TYPE_DISK);
    if (!devs) {
	msgConfirm("No disks found!");
	return DITEM_FAILURE;
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
	msgConfirm("Unable to create a new /etc/fstab file!  Manual intervention\n"
		   "will be required.");
	return DITEM_FAILURE;
    }

    check_rootdev(chunk_list, nchunks);

    /* Go for the burn */
    msgDebug("Generating /etc/fstab file\n");
    fprintf(fstab, "# Device\t\tMountpoint\tFStype\tOptions\t\tDump?\tfsck pass#\n");
    fprintf(fstab, "#\t\t\t\t\t\t\t\t\t(0=no) (0=no fsck)\n");
    for (i = 0; i < nchunks; i++)
	fprintf(fstab, "/dev/%s\t\t%s\t\t%s\t%s\t\t%d\t%d\n", name_of(chunk_list[i]), mount_point(chunk_list[i]),
		fstype(chunk_list[i]), fstype_short(chunk_list[i]), seq_num(chunk_list[i]), seq_num(chunk_list[i]));
    Mkdir("/proc");
    fprintf(fstab, "proc\t\t\t/proc\t\tprocfs\t\trw\t0\t0\n");

    /* Now look for the CDROMs */
    devs = deviceFind(NULL, DEVICE_TYPE_CDROM);
    cnt = deviceCount(devs);

    /* Write the first one out as /cdrom */
    if (cnt) {
	if (Mkdir("/cdrom")) {
	    msgConfirm("Unable to make mount point for: /cdrom");
	}
	else
	    fprintf(fstab, "/dev/%s\t\t/cdrom\tcd9660\t\tro,noauto\t0\t0\n", devs[0]->name);
    }

    /* Write the others out as /cdrom<n> */
    for (i = 1; i < cnt; i++) {
	char cdname[10];

	sprintf(cdname, "/cdrom%d", i);
	if (Mkdir(cdname)) {
	    msgConfirm("Unable to make mount point for: %s", cdname);
	}
	else
	    fprintf(fstab, "/dev/%s\t\t%s\tcd9660\t\tro,noauto\t0\t0\n", devs[i]->name, cdname);
    }
    fclose(fstab);
    if (isDebug())
	msgDebug("Wrote out /etc/fstab file\n");
    return DITEM_SUCCESS;
}

/* Do the work of sucking in a config file.
 * config is the filename to read in.
 * lines is a fixed (max) sized array of char *.
 * returns number of lines read.  line contents
 * are malloc'd and must be freed by the caller.
 */
int
readConfig(char *config, char **lines, int max)
{
    FILE *fp;
    char line[256];
    int i, nlines;

    fp = fopen(config, "r");
    if (!fp)
	return -1;

    nlines = 0;
    /* Read in the entire file */
    for (i = 0; i < max; i++) {
	if (!fgets(line, sizeof line, fp))
	    break;
	lines[nlines++] = strdup(line);
    }
    fclose(fp);
    if (isDebug())
	msgDebug("readConfig: Read %d lines from %s.\n", nlines, config);
    return nlines;
}

#define MAX_LINES  2000 /* Some big number we're not likely to ever reach - I'm being really lazy here, I know */

/* Load the environment from a sysconfig file */
void
configEnvironmentSysconfig(char *config)
{
    char *lines[MAX_LINES], *cp, *cp2;
    int i, j, nlines;

    nlines = readConfig(config, lines, MAX_LINES);
    if (nlines == -1)
	return;

    for (i = 0; i < nlines; i++) {
	/* Skip the comments & non-variable settings */
	if (lines[i][0] == '#' || !(cp = index(lines[i], '='))) {
	    free(lines[i]);
	    continue;
	}
	*cp++ = '\0';
	(void)string_prune(lines[i]);
	cp = string_skipwhite(string_prune(cp));
	if ((cp2 = index(cp, '"')))	/* Eliminate leading quote if it's quoted */
	    cp = cp2 + 1;
	j = strlen(cp) - 1;
	if (cp[j] == '"') /* And trailing one */
	    cp[j] = '\0';
	if (strlen(cp))
	    variable_set2(lines[i], cp);
	free(lines[i]);
    }
}
    
/* Load the environment from a resolv.conf file */
void
configEnvironmentResolv(char *config)
{
    char *lines[MAX_LINES];
    int i, nlines;

    nlines = readConfig(config, lines, MAX_LINES);
    if (nlines == -1)
	return;
    for (i = 0; i < nlines; i++) {
	Boolean name_set = FALSE;

	if (!strncmp(lines[i], "domain", 6))
	    variable_set2(VAR_DOMAINNAME, string_skipwhite(lines[i] + 6));
	else if (!strncmp(lines[i], "nameserver", 10) && !name_set) {
	    /* Only take the first nameserver setting - we're lame */
	    variable_set2(VAR_NAMESERVER, string_skipwhite(lines[i] + 10));
	    name_set = TRUE;
	}
	free(lines[i]);
    }
}

/*
 * This sucks in /etc/sysconfig, substitutes anything needing substitution, then
 * writes it all back out.  It's pretty gross and needs re-writing at some point.
 */
void
configSysconfig(char *config)
{
    FILE *fp;
    char *lines[MAX_LINES], *cp;
    Variable *v;
    int i, nlines;

    nlines = readConfig(config, lines, MAX_LINES);
    if (nlines == -1) {
	msgConfirm("Unable to open %s file!  This is bad!", config);
	return;
    }

    /* Now do variable substitutions */
    for (v = VarHead; v; v = v->next) {
	for (i = 0; i < nlines; i++) {
	    /* Skip the comments & non-variable settings */
	    if (lines[i][0] == '#' || !(cp = index(lines[i], '=')))
		continue;
	    if (!strncmp(lines[i], v->name, cp - lines[i])) {
		free(lines[i]);
		lines[i] = (char *)malloc(strlen(v->name) + strlen(v->value) + 5);
		sprintf(lines[i], "%s=\"%s\"\n", v->name, v->value);
	    }
	}
    }

    /* Now write it all back out again */
    if (isDebug())
	msgDebug("Writing configuration changes to %s file..", config);
    if (Fake)
	fp = fdopen(DebugFD, "w");
    else {
	(void)vsystem("cp %s %s.previous", config, config);
    	fp = fopen(config, "w");
    }
    for (i = 0; i < nlines; i++) {
	fprintf(fp, lines[i]);
	/* Stand by for bogus special case handling - we try to dump the interface specs here */
	if (!strncmp(lines[i], VAR_INTERFACES, strlen(VAR_INTERFACES))) {
	    Device **devp;
	    int j, cnt;

	    devp = deviceFind(NULL, DEVICE_TYPE_NETWORK);
	    cnt = deviceCount(devp);
	    for (j = 0; j < cnt; j++) {
		char iname[255], toadd[512];
		int k, addit = TRUE;

		snprintf(iname, 255, "%s%s", VAR_IFCONFIG, devp[j]->name);
		if ((cp = variable_get(iname))) {
		    snprintf(toadd, sizeof toadd, "%s=\"%s\"\n", iname, cp);
		    for (k = 0; k < nlines; k++) {
			if (!strcmp(lines[k], toadd)) {
			    addit = FALSE;
			    break;
			}
		    }
		    if (addit)
			fprintf(fp, toadd);
		}
	    }
	}
	free(lines[i]);
    }
    fclose(fp);
}

int
configSaver(dialogMenuItem *self)
{
    variable_set((char *)self->data);
    if (!variable_get(VAR_BLANKTIME))
	variable_set2(VAR_BLANKTIME, "300");
    return DITEM_SUCCESS;
}

int
configSaverTimeout(dialogMenuItem *self)
{
    return (variable_get_value(VAR_BLANKTIME, "Enter time-out period in seconds for screen saver") ?
	    DITEM_SUCCESS : DITEM_FAILURE) | DITEM_RESTORE;
}

int
configNTP(dialogMenuItem *self)
{
    int status;

    status = variable_get_value(VAR_NTPDATE, "Enter the name of an NTP server") ? DITEM_SUCCESS : DITEM_FAILURE;
    if (status == DITEM_SUCCESS) {
	static char tmp[255];

	snprintf(tmp, 255, "%s=%s", VAR_NTPDATE, variable_get(VAR_NTPDATE));
	self->aux = (int)tmp;
    }
    return status | DITEM_RESTORE;
}

int
configUsers(dialogMenuItem *self)
{
    dialog_clear_norefresh();
    dmenuOpenSimple(&MenuUsermgmt, FALSE); 
    dialog_clear();
    return DITEM_SUCCESS | DITEM_RESTORE;
}

int
configXFree86(dialogMenuItem *self)
{
    char *config, *execfile;

    dialog_clear_norefresh();
    dmenuOpenSimple(&MenuXF86Config, FALSE); 

    config = variable_get(VAR_XF86_CONFIG);
    if (!config)
	return DITEM_FAILURE | DITEM_RESTORE;
    execfile = string_concat("/usr/X11R6/bin/", config);
    if (file_executable(execfile)) {
	dialog_clear_norefresh();
	if (!file_readable("/dev/mouse") && !msgYesNo("Does this system have a mouse attached to it?"))
	    dmenuOpenSimple(&MenuMouse, FALSE); 
	dialog_clear();
	systemExecute("/sbin/ldconfig /usr/lib /usr/X11R6/lib /usr/local/lib /usr/lib/compat");
	systemExecute(execfile);
	return DITEM_SUCCESS | DITEM_RESTORE;
    }
    else {
	dialog_clear_norefresh();
	msgConfirm("XFree86 does not appear to be installed!  Please install\n"
		   "The XFree86 distribution before attempting to configure it.");
	return DITEM_FAILURE;
    }
}

void
configResolv(void)
{
    FILE *fp;
    char *cp, *dp, *hp;

    cp = variable_get(VAR_NAMESERVER);
    if (!cp || !*cp)
	goto skip;
    fp = fopen("/etc/resolv.conf", "w");
    if (!fp)
	return;
    if (variable_get(VAR_DOMAINNAME))
	fprintf(fp, "domain\t%s\n", variable_get(VAR_DOMAINNAME));
    fprintf(fp, "nameserver\t%s\n", cp);
    fclose(fp);
    if (isDebug())
	msgDebug("Wrote out /etc/resolv.conf\n");

skip:
    dp = variable_get(VAR_DOMAINNAME);
    cp = variable_get(VAR_IPADDR);
    hp = variable_get(VAR_HOSTNAME);
    if ((!dp || !cp || !hp) && file_readable("/etc/hosts"))
	return;
    /* Tack ourselves into /etc/hosts */
    fp = fopen("/etc/hosts", "w");
    if (!fp)
	return;
    /* Add an entry for localhost */
    fprintf(fp, "127.0.0.1\t\tlocalhost.%s localhost\n", dp ? dp : "my.domain");
    /* Now the host entries, if applicable */
    if (cp && cp[0] != '0' && hp) {
	char cp2[255];

	if (!index(hp, '.'))
	    cp2[0] = '\0';
	else {
	    SAFE_STRCPY(cp2, hp);
	    *(index(cp2, '.')) = '\0';
	}
	fprintf(fp, "%s\t\t%s %s\n", cp, hp, cp2);
	fprintf(fp, "%s\t\t%s.\n", cp, hp);
    }
    fclose(fp);
    if (isDebug())
	msgDebug("Wrote out /etc/hosts\n");
}

int
configRouter(dialogMenuItem *self)
{
    int ret;

    ret = variable_get_value(VAR_ROUTER,
			     "Please specify the router you wish to use.  Routed is\n"
			     "provided with the stock system and gated is provided\n"
			     "as an optional package which this installation system\n"
			     "will attempt to load if you select gated.  Any other\n"
			     "choice of routing daemon will be assumed to be something\n"
			     "the user intends to install themselves before rebooting\n"
			     "the system.  If you don't want any routing daemon, choose NO") ?
	DITEM_SUCCESS : DITEM_FAILURE;

    if (ret == DITEM_SUCCESS) {
	char *cp;

	cp = variable_get(VAR_ROUTER);
	if (strcmp(cp, "NO")) {
	    if (!strcmp(cp, "gated")) {
		if (package_add(variable_get(VAR_GATED_PKG)) != DITEM_SUCCESS) {
		    msgConfirm("Unable to load gated package.  Falling back to no router.");
		    variable_set2(VAR_ROUTER, "NO");
		}
	    }
	    /* Now get the flags, if they chose a router */
	    ret = variable_get_value(VAR_ROUTERFLAGS, 
				     "Please Specify the routing daemon flags; if you're running routed\n"
				     "then -q is the right choice for nodes and -s for gateway hosts.\n") ? DITEM_SUCCESS : DITEM_FAILURE;
	    if (ret != DITEM_SUCCESS) {
		variable_unset(VAR_ROUTER);
		variable_unset(VAR_ROUTERFLAGS);
	    }
	}
    }
    return ret | DITEM_RESTORE;
}

int
configPackages(dialogMenuItem *self)
{
    static PkgNode top, plist;
    static Boolean index_initted = FALSE;
    PkgNodePtr tmp;
    FILE *fp;

    if (!mediaVerify())
	return DITEM_FAILURE;

    if (!mediaDevice->init(mediaDevice))
	return DITEM_FAILURE;

    if (!index_initted) {
	msgNotify("Attempting to fetch packages/INDEX file from selected media.");
	fp = mediaDevice->get(mediaDevice, "packages/INDEX", TRUE);
	if (!fp) {
	    dialog_clear_norefresh();
	    msgConfirm("Unable to get packages/INDEX file from selected media.\n"
		       "This may be because the packages collection is not available at\n"
		       "on the distribution media you've chosen (most likely an FTP site\n"
		       "without the packages collection mirrored).  Please verify media\n"
		       "(or path to media) and try again.  If your local site does not\n"
		       "carry the packages collection, then we recommend either a CD\n"
		       "distribution or the master distribution on ftp.freebsd.org.");
	    mediaDevice->shutdown(mediaDevice);
	    return DITEM_FAILURE | DITEM_RESTORE;
	}
	msgNotify("Located INDEX, now reading package data from it...");
	index_init(&top, &plist);
	if (index_read(fp, &top)) {
	    msgConfirm("I/O or format error on packages/INDEX file.\n"
		       "Please verify media (or path to media) and try again.");
	    fclose(fp);
	    return DITEM_FAILURE | DITEM_RESTORE;
	}
	fclose(fp);
	index_sort(&top);
	index_initted = TRUE;
    }
    while (1) {
	int ret, pos, scroll;

	/* Bring up the packages menu */
	pos = scroll = 0;
	index_menu(&top, &plist, &pos, &scroll);

	if (plist.kids && plist.kids->name) {
	    /* Now show the packing list menu */
	    pos = scroll = 0;
	    ret = index_menu(&plist, NULL, &pos, &scroll);
	    if (ret & DITEM_LEAVE_MENU)
		break;
	    else if (DITEM_STATUS(ret) != DITEM_FAILURE) {
		index_extract(mediaDevice, &top, &plist);
		break;
	    }
	}
	else {
	    dialog_clear_norefresh();
	    msgConfirm("No packages were selected for extraction.");
	    break;
	}
    }
    tmp = plist.kids;
    while (tmp) {
        PkgNodePtr tmp2 = tmp->next;
           
        safe_free(tmp);
        tmp = tmp2;
    }
    index_init(NULL, &plist);
    return DITEM_SUCCESS | DITEM_RESTORE;
}

#ifdef NETCON_EXTENTIONS
/* Load novell client/server package */
int
configNovell(dialogMenuItem *self)
{
    int ret = DITEM_SUCCESS;

    if (!RunningAsInit) {
	msgConfirm("This package can only be installed in multi-user mode.");
	return ret;
    }
    if (variable_get(VAR_NOVELL))
	variable_unset(VAR_NOVELL);
    else {
	ret = package_add(PACKAGE_NETCON);
	if (DITEM_STATUS(ret) == DITEM_SUCCESS)
	    variable_set2(VAR_NOVELL, "YES");
    }
    return ret | DITEM_RESTORE;
}
#endif

/* Load pcnfsd package */
int
configPCNFSD(dialogMenuItem *self)
{
    int ret = DITEM_SUCCESS;

    if (variable_get(VAR_PCNFSD))
	variable_unset(VAR_PCNFSD);
    else {
	ret = package_add(variable_get(VAR_PCNFSD_PKG));
	if (DITEM_STATUS(ret) == DITEM_SUCCESS) {
	    variable_set2(VAR_PCNFSD, "YES");
	    variable_set2("weak_mountd_authentication", "YES");
	}
    }
    return ret;
}

int
configNFSServer(dialogMenuItem *self)
{
    char cmd[256];

    /* If we're an NFS server, we need an exports file */
    if (!file_readable("/etc/exports")) {
	WINDOW *w = savescr();

	dialog_clear_norefresh();
	msgConfirm("Operating as an NFS server means that you must first configure\n"
		   "an /etc/exports file to indicate which hosts are allowed certain\n"
		   "kinds of access to your local file systems.\n"
		   "Press [ENTER] now to invoke an editor on /etc/exports\n");
	vsystem("echo '#The following examples export /usr to 3 machines named after ducks,' > /etc/exports");
	vsystem("echo '#/home and all directories under it to machines named after dead rock stars' >> /etc/exports");
	vsystem("echo '#and, finally, /a to 2 privileged machines allowed to write on it as root.' >> /etc/exports");
	vsystem("echo '#/usr                huey louie dewie' >> /etc/exports");
	vsystem("echo '#/home   -alldirs    janice jimmy frank' >> /etc/exports");
	vsystem("echo '#/a      -maproot=0  bill albert' >> /etc/exports");
	vsystem("echo '#' >> /etc/exports");
	vsystem("echo '# You should replace these lines with your actual exported filesystems.' >> /etc/exports");
	vsystem("echo >> /etc/exports");
	sprintf(cmd, "%s /etc/exports", variable_get(VAR_EDITOR));
	dialog_clear();
	systemExecute(cmd);
	restorescr(w);
	variable_set2(VAR_NFS_SERVER, "YES");
    }
    else if (variable_get(VAR_NFS_SERVER)) { /* We want to turn it off again? */
	unlink("/etc/exports");
	variable_unset(VAR_NFS_SERVER);
    }
    return DITEM_SUCCESS;
}
