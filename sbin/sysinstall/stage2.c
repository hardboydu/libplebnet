/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dkuug.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $Id: stage2.c,v 1.12 1994/11/04 21:38:36 phk Exp $
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <dialog.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>

#include "sysinstall.h"

void
stage2()
{
    char *p, *q;
    char pbuf[90];
    char dbuf[90];
    FILE *f1;
    int i, j;

    /* Sort in mountpoint order */
    memset(Fsize, 0, sizeof Fsize);

    for (i = 1; Fname[i]; i++)
	Fsize[i] = i;
    Fsize[i] = 0;

    for (j = 1; j;)
	for (j = 0, i = 1; Fsize[i+1]; i++) {
	    if (strcmp(Fmount[Fsize[i]], Fmount[Fsize[i+1]]) > 0) {
		j = Fsize[i];
		Fsize[i] = Fsize[i+1];
		Fsize[i + 1] = j;
	    }
	}

    for (j = 1; Fsize[j]; j++) {
	if (strcmp(Ftype[Fsize[j]], "ufs")) 
	    continue;
	p = Fname[Fsize[j]];
	TellEm("newfs /dev/r%s",p); 
	strcpy(pbuf, "/dev/r");
	strcat(pbuf, p);
	i = exec(0, "/stand/newfs", "/stand/newfs", "-n", "1", pbuf, 0);
	if (i) 
	    Fatal("Exec(/stand/newfs) failed, code=%d.",i);
    }

    for (j = 1; Fsize[j]; j++) {
	if (strcmp(Ftype[Fsize[j]], "ufs"))
	    continue;
	strcpy(dbuf, "/mnt");
	p = Fname[Fsize[j]];
	q = Fmount[Fsize[j]];
	if (strcmp(q, "/"))
	    strcat(dbuf, q);
	MountUfs(p, dbuf, 1, 0);
    }

    Mkdir("/mnt/etc");
    Mkdir("/mnt/dev");
    Mkdir("/mnt/mnt");
    Mkdir("/mnt/stand");

    CopyFile("/stand/sysinstall","/mnt/stand/sysinstall");
    Link("/mnt/stand/sysinstall","/mnt/stand/cpio");
    Link("/mnt/stand/sysinstall","/mnt/stand/gunzip");
    Link("/mnt/stand/sysinstall","/mnt/stand/gzip");
    Link("/mnt/stand/sysinstall","/mnt/stand/zcat");
    Link("/mnt/stand/sysinstall","/mnt/stand/newfs");
    Link("/mnt/stand/sysinstall","/mnt/stand/fsck");
    Link("/mnt/stand/sysinstall","/mnt/stand/dialog");

    CopyFile("/kernel","/mnt/kernel");
    TellEm("make /dev entries");
    chdir("/mnt/dev");
    makedevs();
    chdir("/");

    TellEm("Making /mnt/etc/fstab");
    f1 = fopen("/mnt/etc/fstab","w");
    if (!f1)
	Fatal("Couldn't open /mnt/etc/fstab for writing.");

    TellEm("Writing filesystems");
    for (j = 1; Fsize[j]; j++) {
	if (!strcmp(Ftype[Fsize[j]],"swap"))
	    fprintf(f1, "/dev/%s\t\tnone\tswap sw 0 0\n", Fname[Fsize[j]]);
	else
	    fprintf(f1, "/dev/%s\t\t%s\t%s rw 1 1\n",
		    Fname[Fsize[j]], Fmount[Fsize[j]], Ftype[Fsize[j]]);
    }
    TellEm("Writing procfs");
    fprintf(f1,"proc\t\t/proc\tprocfs rw 0 0\n");
    fclose(f1);

    sync();
    TellEm("Make marker file");
    i = open("/mnt/stand/need_cpio_floppy",O_CREAT|O_WRONLY|O_TRUNC);
    close(i);
    
    TellEm("Unmount disks");
    for (j = 1; Fsize[j]; j++) 
	continue;
	
    for (j--; j > 0; j--) {
	if (!strcmp(Ftype[Fsize[j]],"swap")) 
	    continue;
	strcpy(dbuf,"/mnt");
	if (strcmp(Fmount[Fsize[j]],"/"))
	    strcat(dbuf, Fmount[Fsize[j]]);
	TellEm("unmount %s", dbuf);
	/* Don't do error-check, we reboot anyway... */
	unmount(dbuf, 0);
    }
    dialog_msgbox(TITLE,"Remove the floppy from the drive and hit return to reboot from the hard disk",6, 75, 1);
    dialog_clear();
}
