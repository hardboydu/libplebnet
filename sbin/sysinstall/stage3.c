/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $Id: stage3.c,v 1.7 1994/11/02 06:19:47 jkh Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <dialog.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <fstab.h>

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "sysinstall.h"

void
stage3()
{
    char	pbuf[90],*p;
    int		mountflags;
    struct	fstab *fs;

    /*
     * Mount things in /etc/fstab we like.
     */

    mountflags = MNT_UPDATE;
    while((fs = getfsent()) != NULL) {
	p = fs->fs_spec;
	if (*p++ != '/') continue;
	if (*p++ != 'd') continue;
	if (*p++ != 'e') continue;
	if (*p++ != 'v') continue;
	if (*p++ != '/') continue;

	if (!strcmp(fs->fs_type, "sw")) {
	    swapon(fs->fs_spec);
	    continue;
	}

	if (strcmp(fs->fs_vfstype, "ufs")) continue;

	if (!strcmp(fs->fs_type, "ro"))
	    mountflags |= MNT_RDONLY;
	else if (!strcmp(fs->fs_type, "rw"))
	    ;
	else
	    continue;
	strcpy(pbuf, "/dev/r");
	strcat(pbuf,p);
	TellEm("fsck -y %s",pbuf);
	if (exec(0, "/stand/fsck",
		 "/stand/fsck", "-y", pbuf, 0) == -1)
	    Fatal(errmsg);

	MountUfs(p, fs->fs_file, 0, mountflags);
	mountflags = 0;
    }
    endfsent();
}
