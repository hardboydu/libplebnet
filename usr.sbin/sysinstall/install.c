/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: install.c,v 1.75 1996/01/29 20:17:27 joerg Exp $
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
#include <ctype.h>
#include <sys/disklabel.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/param.h>
#define MSDOSFS
#include <sys/mount.h>
#undef MSDOSFS
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>

static void	create_termcap(void);

#define TERMCAP_FILE	"/usr/share/misc/termcap"

static Boolean
checkLabels(Chunk **rdev, Chunk **sdev, Chunk **udev)
{
    Device **devs;
    Boolean status;
    Disk *disk;
    Chunk *c1, *c2, *rootdev, *swapdev, *usrdev;
    int i;

    status = TRUE;
    *rdev = *sdev = *udev = rootdev = swapdev = usrdev = NULL;
    devs = deviceFind(NULL, DEVICE_TYPE_DISK);
    /* First verify that we have a root device */
    for (i = 0; devs[i]; i++) {
	if (!devs[i]->enabled)
	    continue;
	disk = (Disk *)devs[i]->private;
	msgDebug("Scanning disk %s for root filesystem\n", disk->name);
	if (!disk->chunks)
	    msgFatal("No chunk list found for %s!", disk->name);
	for (c1 = disk->chunks->part; c1; c1 = c1->next) {
	    if (c1->type == freebsd) {
		for (c2 = c1->part; c2; c2 = c2->next) {
		    if (c2->type == part && c2->subtype != FS_SWAP && c2->private) {
			if (c2->flags & CHUNK_IS_ROOT) {
			    if (rootdev) {
				dialog_clear();
				msgConfirm("WARNING:  You have more than one root device set?!\n"
					   "Using the first one found.");
				continue;
			    }
			    rootdev = c2;
			    if (isDebug())
				msgDebug("Found rootdev at %s!\n", rootdev->name);
			}
			else if (!strcmp(((PartInfo *)c2->private)->mountpoint, "/usr")) {
			    if (usrdev) {
				dialog_clear();
				msgConfirm("WARNING:  You have more than one /usr filesystem.\n"
					   "Using the first one found.");
				continue;
			    }
			    usrdev = c2;
			    if (isDebug())
				msgDebug("Found usrdev at %s!\n", usrdev->name);
			}
		    }
		}
	    }
	}
    }

    swapdev = NULL;
    /* Now check for swap devices */
    for (i = 0; devs[i]; i++) {
	if (!devs[i]->enabled)
	    continue;
	disk = (Disk *)devs[i]->private;
	msgDebug("Scanning disk %s for swap partitions\n", disk->name);
	if (!disk->chunks)
	    msgFatal("No chunk list found for %s!", disk->name);
	for (c1 = disk->chunks->part; c1; c1 = c1->next) {
	    if (c1->type == freebsd) {
		for (c2 = c1->part; c2; c2 = c2->next) {
		    if (c2->type == part && c2->subtype == FS_SWAP && !swapdev) {
			swapdev = c2;
			if (isDebug())
			    msgDebug("Found swapdev at %s!\n", swapdev->name);
			break;
		    }
		}
	    }
	}
    }

    *rdev = rootdev;
    if (!rootdev) {
	dialog_clear();
	msgConfirm("No root device found - you must label a partition as /\n"
		   "in the label editor.");
	status = FALSE;
    }

    *sdev = swapdev;
    if (!swapdev) {
	dialog_clear();
	msgConfirm("No swap devices found - you must create at least one\n"
		   "swap partition.");
	status = FALSE;
    }

    *udev = usrdev;
    if (!usrdev) {
	dialog_clear();
	msgConfirm("WARNING:  No /usr filesystem found.  This is not technically\n"
		   "an error if your root filesystem is big enough (or you later\n"
		   "intend to mount your /usr filesystem over NFS), but it may otherwise\n"
		   "cause you trouble if you're not exactly sure what you are doing!");
    }
    return status;
}

static int
installInitial(void)
{
    static Boolean alreadyDone = FALSE;

    if (alreadyDone)
	return RET_SUCCESS;

    if (!variable_get(DISK_LABELLED)) {
	dialog_clear();
	msgConfirm("You need to assign disk labels before you can proceed with\nthe installation.");
	return RET_FAIL;
    }
    /* If it's labelled, assume it's also partitioned */
    if (!variable_get(DISK_PARTITIONED))
	variable_set2(DISK_PARTITIONED, "yes");

    /* If we refuse to proceed, bail. */
    dialog_clear();
    if (msgYesNo("Last Chance!  Are you SURE you want continue the installation?\n\n"
		 "If you're running this on a disk with data you wish to save\n"
		 "then WE STRONGLY ENCOURAGE YOU TO MAKE PROPER BACKUPS before\n"
		 "proceeding!\n\n"
		 "We can take no responsibility for lost disk contents!"))
	return RET_FAIL;

    if (diskLabelCommit(NULL) != RET_SUCCESS) {
	dialog_clear();
	msgConfirm("Couldn't make filesystems properly.  Aborting.");
	return RET_FAIL;
    }

    if (!copySelf()) {
	dialog_clear();
	msgConfirm("Couldn't clone the boot floppy onto the root file system.\n"
		   "Aborting.");
	return RET_FAIL;
    }

    dialog_clear();
    /* stick a helpful shell over on the 4th VTY */
    systemCreateHoloshell();

    if (chroot("/mnt") == -1) {
	dialog_clear();
	msgConfirm("Unable to chroot to /mnt - this is bad!");
	return RET_FAIL;
    }

    chdir("/");
    variable_set2(RUNNING_ON_ROOT, "yes");

    alreadyDone = TRUE;
    return RET_SUCCESS;
}

int
installFixit(char *str)
{
    struct ufs_args args;
    pid_t child;
    int waitstatus;

    memset(&args, 0, sizeof(args));
    args.fspec = "/dev/fd0";
    Mkdir("/mnt2", NULL);

    while (1) {
	dialog_clear();
	msgConfirm("Please insert a writable fixit floppy and press return");
	if (mount(MOUNT_UFS, "/mnt2", 0, (caddr_t)&args) != -1)
	    break;
	dialog_clear();
	if (msgYesNo("Unable to mount the fixit floppy - do you want to try again?"))
	    return RET_FAIL;
    }
    dialog_clear();
    dialog_update();
    end_dialog();
    DialogActive = FALSE;
    if (!directoryExists("/tmp"))
	(void)symlink("/mnt2/tmp", "/tmp");
    if (!directoryExists("/var/tmp/vi.recover")) {
	if (Mkdir("/var/tmp/vi.recover", NULL) != RET_SUCCESS) {
	    dialog_clear();
	    msgConfirm("Warning:  Was unable to create a /var/tmp/vi.recover directory.\n"
		       "vi will kvetch and moan about it as a result but should still\n"
		       "be essentially usable.");
	}
    }
    /* Link the spwd.db file */
    if (Mkdir("/etc", NULL) != RET_SUCCESS) {
	dialog_clear();
	msgConfirm("Unable to create an /etc directory!  Things are weird on this floppy..");
    }
    else {
	if (symlink("/mnt2/etc/spwd.db", "/etc/spwd.db") == -1) {
	    dialog_clear();
	    msgConfirm("Couldn't symlink the /etc/spwd.db file!  I'm not sure I like this..");
	}
    }
    if (!file_readable(TERMCAP_FILE))
	create_termcap();
    if (!(child = fork())) {
	struct termios foo;

	signal(SIGTTOU, SIG_IGN);
	if (tcgetattr(0, &foo) != -1) {
	    foo.c_cc[VERASE] = '\010';
	    if (tcsetattr(0, TCSANOW, &foo) == -1)
		msgDebug("fixit shell: Unable to set erase character.\n");
	}
	else
	    msgDebug("fixit shell: Unable to get terminal attributes!\n");
	printf("When you're finished with this shell, please type exit.\n");
	printf("The fixit floppy itself is mounted as /mnt2\n");
	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/stand:/mnt2/stand", 1);
	execlp("sh", "-sh", 0);
	msgDebug("fixit shell: Failed to execute shell!\n");
	return -1;
    }
    else
	(void)waitpid(child, &waitstatus, 0);

    DialogActive = TRUE;
    clear();
    dialog_clear();
    dialog_update();
    unmount("/mnt2", MNT_FORCE);
    dialog_clear();
    msgConfirm("Please remove the fixit floppy now.");
    return RET_SUCCESS;
}
  
int
installExpress(char *str)
{
    if (diskPartitionEditor("express") == RET_FAIL)
	return RET_FAIL;
    
    if (diskLabelEditor("express") == RET_FAIL)
	return RET_FAIL;

    if (!Dists) {
	if (!dmenuOpenSimple(&MenuDistributions))
	    return RET_FAIL;
    }

    if (!mediaDevice) {
	if (!dmenuOpenSimple(&MenuMedia) || !mediaDevice)
	    return RET_FAIL;
    }

    if (installCommit("express") == RET_FAIL)
	return RET_FAIL;

    return RET_DONE;
}

/* Novice mode installation */
int
installNovice(char *str)
{
    dialog_clear();
    msgConfirm("In the next menu, you will need to set up a DOS-style (\"fdisk\") partitioning\n"
	       "scheme for your hard disk.  If you simply wish to devote all disk space\n"
	       "to FreeBSD (overwritting anything else that might be on the disk(s) selected)\n"
	       "then use the (A)ll command to select the default partitioning scheme followed\n"
	       "by a (Q)uit.  If you wish to allocate only free space to FreeBSD, move to a\n"
	       "partition marked \"unused\" and use the (C)reate command.");

    if (diskPartitionEditor("novice") == RET_FAIL)
	return RET_FAIL;
    
    dialog_clear();
    msgConfirm("Next, you need to create BSD partitions inside of the fdisk partition(s)\n"
	       "just created.  If you have a reasonable amount of disk space (200MB or more)\n"
	       "and don't have any special requirements, simply use the (A)uto command to\n"
	       "allocate space automatically.  If you have more specific needs or just don't\n"
	       "care for the layout chosen by (A)uto, press F1 for more information on\n"
	       "manual layout.");

    if (diskLabelEditor("novice") == RET_FAIL)
	return RET_FAIL;

    dialog_clear();
    msgConfirm("Now it is time to select an installation subset.  There are a number of\n"
	       "canned distribution sets, ranging from minimal installation sets to full\n"
	       "X11 developer oriented configurations.  You can also select a custom set\n"
	       "of distributions if none of the provided ones are suitable.");
    while (1) {
	if (!dmenuOpenSimple(&MenuDistributions))
	    return RET_FAIL;
	
	if (Dists || !msgYesNo("No distributions selected.  Are you sure you wish to continue?"))
	    break;
    }

    if (!mediaDevice) {
	dialog_clear();
	msgConfirm("Finally, you must specify an installation medium.");
	if (!dmenuOpenSimple(&MenuMedia) || !mediaDevice)
	    return RET_FAIL;
    }

    if (installCommit("novice") == RET_FAIL)
	return RET_FAIL;

    return RET_DONE;
}

/*
 * What happens when we select "Commit" in the custom installation menu.
 *
 * This is broken into multiple stages so that the user can do a full installation but come back here
 * again to load more distributions, perhaps from a different media type.  This would allow, for
 * example, the user to load the majority of the system from CDROM and then use ftp to load just the
 * DES dist.
 */
int
installCommit(char *str)
{
    int i;
    extern Boolean cdromMounted;

    if (!mediaVerify())
	return RET_FAIL;

    i = RET_DONE;
    if (RunningAsInit) {
	if (installInitial() == RET_FAIL)
	    return RET_FAIL;
	if (configFstab() == RET_FAIL)
	    return RET_FAIL;
	if (!rootExtract()) {
	    dialog_clear();
	    msgConfirm("Failed to load the ROOT distribution.  Please correct\n"
		       "this problem and try again.");
	    return RET_FAIL;
	}
    }

    if (distExtractAll(NULL) == RET_FAIL)
	i = RET_FAIL;

    if (installFixup(NULL) == RET_FAIL)
	i = RET_FAIL;

    if (i != RET_FAIL)
	variable_set2(SYSTEM_STATE, "base-install");

    if (i != RET_FAIL && !strcmp(str, "novice")) {
	dialog_clear();
	msgConfirm("Since you're running the novice installation, a few post-configuration\n"
		   "questions will be asked at this point.  For any option you do not wish\n"
		   "to configure, select Cancel.");

	if (mediaDevice->type != DEVICE_TYPE_FTP && mediaDevice->type != DEVICE_TYPE_NFS) {
	    dialog_clear();
	    if (!msgYesNo("Would you like to configure this machine's network interfaces?")) {
		Device *save = mediaDevice;

		/* This will also set the media device, which we don't want */
		tcpDeviceSelect();
		mediaDevice = save;
	    }
	}

	dialog_clear();
	if (!msgYesNo("Would you like to configure Samba for connecting NETBUI clients to this\n"
		      "machine?  Windows 95, Windows NT and Windows for Workgroups\n"
		      "machines can use NETBUI transport for disk and printer sharing."))
	    configSamba(NULL);

	dialog_clear();
	if (!msgYesNo("Will this machine be an IP gateway (e.g. will it forward packets\n"
		      "between interfaces)?"))
	    variable_set2("gateway", "YES");

	dialog_clear();
	if (!msgYesNo("Do you want to allow anonymous FTP connections to this machine?"))
	    configAnonFTP(NULL);

	dialog_clear();
	if (!msgYesNo("Do you want to configure this machine as an NFS server?"))
	    configNFSServer(NULL);

	dialog_clear();
	if (!msgYesNo("Do you want to configure this machine as an NFS client?"))
	    variable_set2("nfs_client", "YES");

	dialog_clear();
	if (!msgYesNo("Do you want to configure this machine as a WEB server?"))
	    configApache(NULL);

	dialog_clear();
	if (!msgYesNo("Would you like to customize your system console settings?"))
	    dmenuOpenSimple(&MenuSyscons);

	dialog_clear();
	if (!msgYesNo("Would you like to set this machine's time zone now?"))
	    systemExecute("rm -f /etc/wall_cmos_clock /etc/localtime; tzsetup");

	dialog_clear();
	if (!msgYesNo("Does this system have a mouse attached to it?"))
	    dmenuOpenSimple(&MenuMouse);

	if (directoryExists("/usr/X11R6")) {
	    dialog_clear();
	    if (!msgYesNo("Would you like to configure your X server at this time?"))
		systemExecute("/usr/X11R6/bin/xf86config");
	}

	if (cdromMounted) {
	    dialog_clear();
	    if (!msgYesNo("Would you like to link to the ports tree on your CDROM?\n\n"
			  "This will require that you have your FreeBSD CD in the CDROM\n"
			  "drive to use the ports collection, but at a substantial savings\n"
			  "in disk space (NOTE:  This may take as long as 15 or 20 minutes\n"
			  "depending on the speed of your CDROM drive)."))
		configPorts(NULL);
	}

	dialog_clear();
	if (!msgYesNo("The FreeBSD package collection is a collection of over 300 ready-to-run\n"
		      "applications, from text editors to games to WEB servers.  Would you like\n"
		      "to browse the collection now?"))
	    configPackages(NULL);

	/* XXX Put whatever other nice configuration questions you'd like to ask the user here XXX */
	
    }

    /* Final menu of last resort */
    dialog_clear();
    if (!msgYesNo("Would you like to go to the general configuration menu for a chance to set\n"
		  "any last configuration options?"))
	dmenuOpenSimple(&MenuConfigure);

    /* Write out any changes .. */
    configResolv();
    configSysconfig();

    variable_set2(SYSTEM_STATE, i == RET_FAIL ? "error-install" : "full-install");

    /* Don't print this if we're express or novice installing */
    if (strcmp(str, "express") && strcmp(str, "novice")) {
	if (Dists || i == RET_FAIL) {
	    dialog_clear();
	    msgConfirm("Installation completed with some errors.  You may wish to\n"
		       "scroll through the debugging messages on VTY1 with the\n"
		       "scroll-lock feature.");
	}
	else {
	    dialog_clear();
	    msgConfirm("Installation completed successfully.\n\n"
		       "If you have any network devices you have not yet configured,\n"
		       "see the Interfaces configuration item on the Configuration menu.");
	}
    }
    else if (!strcmp(str, "novice")) {
	if (Dists || i == RET_FAIL) {
	    dialog_clear();
	    msgConfirm("Installation completed with some errors.  You may wish to\n"
		       "scroll through the debugging messages on VTY1 with the\n"
		       "scroll-lock feature.  You can also chose \"No\" at the next\n"
		       "prompt and go back into the installation menus to try and retry\n"
		       "whichever operations have failed.");
	}
	else {
	    dialog_clear();
	    msgConfirm("Congradulations!  You now have FreeBSD installed on your system.\n"
		       "At this stage, there shouldn't be much left to do from this\n"
		       "installation utility so if you wish to come up from the hard disk\n"
		       "now, simply select \"Yes\" at the next prompt to reboot.\n"
		       "If you wish to re-enter this utility after the system is up, you\n"
		       "may do so by typing: /stand/sysinstall.");
	}
    }
    return i;
}

int
installFixup(char *str)
{
    Device **devs;
    int i;

    if (!file_readable("/kernel")) {
	if (file_readable("/kernel.GENERIC")) {
	    if (vsystem("cp -p /kernel.GENERIC /kernel")) {
		dialog_clear();
		msgConfirm("Unable to link /kernel into place!");
		return RET_FAIL;
	    }
	}
	else {
	    dialog_clear();
	    msgConfirm("Can't find a kernel image to link to on the root file system!\n"
		       "You're going to have a hard time getting this system to\n"
		       "boot from the hard disk, I'm afraid!");
	    return RET_FAIL;
	}
    }
    /* Resurrect /dev after bin distribution screws it up */
    if (RunningAsInit) {
	msgNotify("Remaking all devices.. Please wait!");
	if (vsystem("cd /dev; sh MAKEDEV all")) {
	    dialog_clear();
	    msgConfirm("MAKEDEV returned non-zero status");
	    return RET_FAIL;
	}

	msgNotify("Resurrecting /dev entries for slices..");
	devs = deviceFind(NULL, DEVICE_TYPE_DISK);
	if (!devs)
	    msgFatal("Couldn't get a disk device list!");

	/* Resurrect the slices that the former clobbered */
	for (i = 0; devs[i]; i++) {
	    Disk *disk = (Disk *)devs[i]->private;
	    Chunk *c1;

	    if (!devs[i]->enabled)
		continue;
	    if (!disk->chunks)
		msgFatal("No chunk list found for %s!", disk->name);
	    for (c1 = disk->chunks->part; c1; c1 = c1->next) {
		if (c1->type == freebsd) {
		    msgNotify("Making slice entries for %s", c1->name);
		    if (vsystem("cd /dev; sh MAKEDEV %sh", c1->name)) {
			dialog_clear();
			msgConfirm("Unable to make slice entries for %s!", c1->name);
			return RET_FAIL;
		    }
		}
	    }
	}
	/* XXX Do all the last ugly work-arounds here which we'll try and excise someday right?? XXX */

	msgNotify("Fixing permissions..");
	/* BOGON #1:  XFree86 extracting /usr/X11R6 with root-only perms */
	if (directoryExists("/usr/X11R6")) {
	    system("chmod -R a+r /usr/X11R6");
	    system("find /usr/X11R6 -type d | xargs chmod a+x");
	}
	/* BOGON #2: We leave /etc in a bad state */
	chmod("/etc", 0755);

	/* BOGON #3: No /var/db/mountdtab complains */
	Mkdir("/var/db", NULL);
	creat("/var/db/mountdtab", 0644);

	/* Now run all the mtree stuff to fix things up */
        vsystem("mtree -deU -f /etc/mtree/BSD.root.dist -p /");
        vsystem("mtree -deU -f /etc/mtree/BSD.var.dist -p /var");
        vsystem("mtree -deU -f /etc/mtree/BSD.usr.dist -p /usr");
    }
    return RET_SUCCESS;
}

/* Go newfs and/or mount all the filesystems we've been asked to */
int
installFilesystems(char *str)
{
    int i;
    Disk *disk;
    Chunk *c1, *c2, *rootdev, *swapdev, *usrdev;
    Device **devs;
    PartInfo *root;
    char dname[80];
    extern int MakeDevChunk(Chunk *c, char *n);
    Boolean upgrade = FALSE;

    if (!(str && !strcmp(str, "script")) && !checkLabels(&rootdev, &swapdev, &usrdev))
	return RET_FAIL;

    root = (PartInfo *)rootdev->private;
    command_clear();
    upgrade = str && !strcmp(str, "upgrade");

    /* As the very first thing, try to get ourselves some swap space */
    sprintf(dname, "/dev/%s", swapdev->name);
    if (!MakeDevChunk(swapdev, "/dev") || !file_readable(dname)) {
	dialog_clear();
	msgConfirm("Unable to make device node for %s in /dev!\n"
		   "The creation of filesystems will be aborted.", dname);
	return RET_FAIL;
    }
    if (!swapon(dname))
	msgNotify("Added %s as initial swap device", dname);
    else
	msgConfirm("WARNING!  Unable to swap to %s: %s\n"
		   "This may cause the installation to fail at some point\n"
		   "if you don't have a lot of memory.", dname, strerror(errno));

    /* Next, create and/or mount the root device */
    sprintf(dname, "/dev/r%sa", rootdev->disk->name);
    if (!MakeDevChunk(rootdev, "/dev") || !file_readable(dname)) {
	dialog_clear();
	msgConfirm("Unable to make device node for %s in /dev!\n"
		   "The creation of filesystems will be aborted.", dname);
	return RET_FAIL;
    }

    if (strcmp(root->mountpoint, "/")) {
	dialog_clear();
	msgConfirm("Warning: %s is marked as a root partition but is mounted on %s", rootdev->name, root->mountpoint);
    }

    if (root->newfs) {
	int i;

	msgNotify("Making a new root filesystem on %s", dname);
	i = vsystem("%s %s", root->newfs_cmd, dname);
	if (i) {
	    dialog_clear();
	    msgConfirm("Unable to make new root filesystem on %s!\n"
		       "Command returned status %d", dname, i);
	    return RET_FAIL;
	}
    }
    else {
	if (!upgrade) {
	    dialog_clear();
	    msgConfirm("Warning:  Root device is selected read-only.  It will be assumed\n"
		       "that you have the appropriate device entries already in /dev.");
	}
	msgNotify("Checking integrity of existing %s filesystem.", dname);
	i = vsystem("fsck -y %s", dname);
	if (i) {
	    dialog_clear();
	    msgConfirm("Warning: fsck returned status of %d for %s.\n"
		       "This partition may be unsafe to use.", i, dname);
	}
    }
    /* Switch to block device */
    sprintf(dname, "/dev/%sa", rootdev->disk->name);
    if (Mount("/mnt", dname)) {
	dialog_clear();
	msgConfirm("Unable to mount the root file system on %s!  Giving up.", dname);
	return RET_FAIL;
    }

    /* Now buzz through the rest of the partitions and mount them too */
    devs = deviceFind(NULL, DEVICE_TYPE_DISK);
    for (i = 0; devs[i]; i++) {
	if (!devs[i]->enabled)
	    continue;

	disk = (Disk *)devs[i]->private;
	if (!disk->chunks) {
	    dialog_clear();
	    msgConfirm("No chunk list found for %s!", disk->name);
	    return RET_FAIL;
	}
	if (root->newfs || upgrade) {
	    Mkdir("/mnt/dev", NULL);
	    MakeDevDisk(disk, "/mnt/dev");
	}

	for (c1 = disk->chunks->part; c1; c1 = c1->next) {
	    if (c1->type == freebsd) {
		for (c2 = c1->part; c2; c2 = c2->next) {
		    if (c2->type == part && c2->subtype != FS_SWAP && c2->private) {
			PartInfo *tmp = (PartInfo *)c2->private;

			/* Already did root */
			if (c2 == rootdev)
			    continue;

			if (tmp->newfs)
			    command_shell_add(tmp->mountpoint, "%s /mnt/dev/r%s", tmp->newfs_cmd, c2->name);
			else
			    command_shell_add(tmp->mountpoint, "fsck -y /mnt/dev/r%s", c2->name);
			command_func_add(tmp->mountpoint, Mount, c2->name);
		    }
		    else if (c2->type == part && c2->subtype == FS_SWAP) {
			char fname[80];
			int i;

			if (c2 == swapdev)
			    continue;
			sprintf(fname, "/mnt/dev/%s", c2->name);
			i = swapon(fname);
			if (!i)
			    msgNotify("Added %s as an additional swap device", fname);
			else {
			    dialog_clear();
			    msgConfirm("Unable to add %s as a swap device: %s", fname, strerror(errno));
			}
		    }
		}
	    }
	    else if (c1->type == fat && c1->private && (root->newfs || upgrade)) {
		char name[FILENAME_MAX];

		sprintf(name, "/mnt%s", ((PartInfo *)c1->private)->mountpoint);
		Mkdir(name, NULL);
	    }
	}
    }

    msgNotify("Copying initial device files..");
    /* Copy the boot floppy's dev files */
    if ((root->newfs || upgrade) && vsystem("find -x /dev | cpio -pdumv /mnt")) {
	dialog_clear();
	msgConfirm("Couldn't clone the /dev files!");
	return RET_FAIL;
    }
    
    command_sort();
    command_execute();
    return RET_SUCCESS;
}

int
installVarDefaults(char *unused)
{
    /* Set default startup options */
    variable_set2(VAR_ROUTEDFLAGS,		"-q");
    variable_set2(VAR_RELNAME,			RELEASE_NAME);
    variable_set2(VAR_CPIO_VERBOSITY,		"high");
    variable_set2(VAR_TAPE_BLOCKSIZE,		DEFAULT_TAPE_BLOCKSIZE);
    variable_set2(VAR_FTP_USER,			"ftp");
    variable_set2(VAR_BROWSER_PACKAGE,		"lynx-2.4.2");
    variable_set2(VAR_BROWSER_BINARY,		"/usr/local/bin/lynx");
    variable_set2(VAR_CONFIG_FILE,		"freebsd.cfg");
    variable_set2(VAR_FTP_STATE,		"passive");
    variable_set2(VAR_FTP_ONERROR,		"abort");
    variable_set2(VAR_FTP_RETRIES,		MAX_FTP_RETRIES);
    if (getpid() != 1)
	variable_set2(SYSTEM_STATE,		"update");
    else
	variable_set2(SYSTEM_STATE,		"init");
    return RET_SUCCESS;
}

/* Copy the boot floppy contents into /stand */
Boolean
copySelf(void)
{
    int i;

    msgWeHaveOutput("Copying the boot floppy to /stand on root filesystem");
    i = vsystem("find -x /stand | cpio -pdumv /mnt");
    if (i) {
	dialog_clear();
	msgConfirm("Copy returned error status of %d!", i);
	return FALSE;
    }

    /* Copy the /etc files into their rightful place */
    if (vsystem("cd /mnt/stand; find etc | cpio -pdumv /mnt")) {
	dialog_clear();
	msgConfirm("Couldn't copy up the /etc files!");
	return TRUE;
    }
    return TRUE;
}

static Boolean loop_on_root_floppy(void);

Boolean
rootExtract(void)
{
    int fd;
    static Boolean alreadyExtracted = FALSE;

    if (alreadyExtracted)
	return TRUE;

    if (mediaDevice) {
	if (isDebug())
	    msgDebug("Attempting to extract root image from %s\n", mediaDevice->name);
	switch(mediaDevice->type) {

	case DEVICE_TYPE_FLOPPY:
	    alreadyExtracted = loop_on_root_floppy();
	    break;

	default:
	    if (!mediaDevice->init(mediaDevice))
		break;
	    fd = mediaDevice->get(mediaDevice, "floppies/root.flp", FALSE);
	    if (fd < 0) {
		dialog_clear();
		msgConfirm("Couldn't get root image from %s!\n"
			   "Will try to get it from floppy.", mediaDevice->name);
		mediaDevice->shutdown(mediaDevice);
	        alreadyExtracted = loop_on_root_floppy();
	    }
	    else {
		msgNotify("Loading root image from:\n%s", mediaDevice->name);
		alreadyExtracted = mediaExtractDist("/", fd);
		mediaDevice->close(mediaDevice, fd);
	    }
	    break;
	}
    }
    else
	alreadyExtracted = loop_on_root_floppy();
    return alreadyExtracted;
}

static Boolean
loop_on_root_floppy(void)
{
    int fd;
    int status = FALSE;

    while (1) {
	fd = getRootFloppy();
	if (fd != -1) {
	    msgNotify("Extracting root floppy..");
	    status = mediaExtractDist("/", fd);
	    close(fd);
	    break;
	}
    }
    return status;
}

static void
create_termcap(void)
{
    FILE *fp;

    const char *caps[] = {
	termcap_vt100, termcap_cons25, termcap_cons25_m, termcap_cons25r,
	termcap_cons25r_m, termcap_cons25l1, termcap_cons25l1_m, NULL,
    };
    const char **cp;

    if (!file_readable(TERMCAP_FILE)) {
	Mkdir("/usr/share/misc", NULL);
	fp = fopen(TERMCAP_FILE, "w");
	if (!fp) {
	    dialog_clear();
	    msgConfirm("Unable to initialize termcap file. Some screen-oriented\nutilities may not work.");
	    return;
	}
	cp = caps;
	while (*cp)
	    fprintf(fp, "%s\n", *(cp++));
	fclose(fp);
    }
}

