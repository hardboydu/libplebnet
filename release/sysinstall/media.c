/*
 * The new sysinstall program.
 *
 * This is probably the last attempt in the `sysinstall' line, the next
 * generation being slated to essentially a complete rewrite.
 *
 * $Id: media.c,v 1.22 1995/05/29 11:01:27 jkh Exp $
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

#include <stdio.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "sysinstall.h"

static int
genericHook(char *str, DeviceType type)
{
    Device **devs;

    /* Clip garbage off the ends */
    string_prune(str);
    str = string_skipwhite(str);
    if (!*str)
	return 0;
    devs = deviceFind(str, type);
    if (devs)
	mediaDevice = devs[0];
    return devs ? 1 : 0;
}

static int
cdromHook(char *str)
{
    return genericHook(str, DEVICE_TYPE_CDROM);
}

/*
 * Return 1 if we successfully found and set the installation type to
 * be a CD.
 */
int
mediaSetCDROM(char *str)
{
    Device **devs;
    int cnt;

    if (OnCDROM == TRUE) {
	static Device bootCD;

	/* This may need to be extended a little, but the basic idea is sound */
	strcpy(bootCD.name, "bootCD");
	bootCD.type = DEVICE_TYPE_CDROM;
	bootCD.get = mediaGetCDROM;
	mediaDevice = &bootCD;
	return 1;
    }
    else {
	devs = deviceFind(NULL, DEVICE_TYPE_CDROM);
	cnt = deviceCount(devs);
	if (!cnt) {
	    msgConfirm("No CDROM devices found!  Please check that your system's\nconfiguration is correct and that the CDROM drive is of a supported\ntype.  For more information, consult the hardware guide\nin the Doc menu.");
	    return 0;
        }
	else if (cnt > 1) {
	    DMenu *menu;

	    menu = deviceCreateMenu(&MenuMediaCDROM, DEVICE_TYPE_CDROM, cdromHook);
	    if (!menu)
		msgFatal("Unable to create CDROM menu!  Something is seriously wrong.");
	    dmenuOpenSimple(menu);
	    free(menu);
	}
	else
	    mediaDevice = devs[0];
    }
    return mediaDevice ? 1 : 0;
}

static int
floppyHook(char *str)
{
    return genericHook(str, DEVICE_TYPE_FLOPPY);
}

/*
 * Return 1 if we successfully found and set the installation type to
 * be a floppy
 */
int
mediaSetFloppy(char *str)
{
    Device **devs;
    int cnt;

    devs = deviceFind(NULL, DEVICE_TYPE_FLOPPY);
    cnt = deviceCount(devs);
    if (!cnt) {
	msgConfirm("No floppy devices found!  Please check that your system's\nconfiguration is correct.  For more information, consult the hardware guide\nin the Doc menu.");
	return 0;
    }
    else if (cnt > 1) {
	DMenu *menu;

	menu = deviceCreateMenu(&MenuMediaFloppy, DEVICE_TYPE_FLOPPY, floppyHook);
	if (!menu)
	    msgFatal("Unable to create Floppy menu!  Something is seriously wrong.");
	dmenuOpenSimple(menu);
	free(menu);
    }
    else
	mediaDevice = devs[0];
    return mediaDevice ? 1 : 0;
}

static int
DOSHook(char *str)
{
    return genericHook(str, DEVICE_TYPE_DOS);
}

/*
 * Return 1 if we successfully found and set the installation type to
 * be a DOS partition.
 */
int
mediaSetDOS(char *str)
{
    Device **devs;
    int cnt;

    devs = deviceFind(NULL, DEVICE_TYPE_DOS);
    cnt = deviceCount(devs);
    if (!cnt) {
	msgConfirm("No DOS primary partitions found!  This installation method is unavailable");
	return 0;
    }
    else if (cnt > 1) {
	DMenu *menu;

	menu = deviceCreateMenu(&MenuMediaDOS, DEVICE_TYPE_DOS, DOSHook);
	if (!menu)
	    msgFatal("Unable to create DOS menu!  Something is seriously wrong.");
	dmenuOpenSimple(menu);
	free(menu);
    }
    else
	mediaDevice = devs[0];
    return mediaDevice ? 1 : 0;
}

static int
tapeHook(char *str)
{
    return genericHook(str, DEVICE_TYPE_TAPE);
}

/*
 * Return 1 if we successfully found and set the installation type to
 * be a tape drive.
 */
int
mediaSetTape(char *str)
{
    Device **devs;
    int cnt;

    devs = deviceFind(NULL, DEVICE_TYPE_TAPE);
    cnt = deviceCount(devs);
    if (!cnt) {
	msgConfirm("No tape drive devices found!  Please check that your system's\nconfiguration is correct.  For more information, consult the hardware guide\nin the Doc menu.");
	return 0;
    }
    else if (cnt > 1) {
	DMenu *menu;

	menu = deviceCreateMenu(&MenuMediaTape, DEVICE_TYPE_TAPE, tapeHook);
	if (!menu)
	    msgFatal("Unable to create tape drive menu!  Something is seriously wrong.");
	dmenuOpenSimple(menu);
	free(menu);
    }
    else
	mediaDevice = devs[0];
    return mediaDevice ? 1 : 0;
}

/*
 * Return 0 if we successfully found and set the installation type to
 * be an ftp server
 */
int
mediaSetFTP(char *str)
{
    static Device ftpDevice;
    char *cp;

    dmenuOpenSimple(&MenuMediaFTP);
    cp = getenv("ftp");
    if (!cp)
	return 0;
    if (!strcmp(cp, "other")) {
	cp = msgGetInput("ftp://", "Please specify the URL of a FreeBSD distribution on a\nremote ftp site.  This site must accept anonymous ftp!\nA URL looks like this:  ftp://<hostname>/<path>");
	if (!cp || strncmp("ftp://", cp, 6))
	    return 0;
	else
	    variable_set2("ftp", cp);
    }
    tcpDeviceSelect(NULL);
    strcpy(ftpDevice.name, cp);
    ftpDevice.type = DEVICE_TYPE_FTP;
    ftpDevice.init = mediaInitFTP;
    ftpDevice.get = mediaGetFTP;
    ftpDevice.close = mediaCloseFTP;
    ftpDevice.shutdown = mediaShutdownFTP;
    ftpDevice.private = mediaDevice;
    mediaDevice = &ftpDevice;
    return 1;
}

int
mediaSetUFS(char *str)
{
    static Device ufsDevice;
    char *val;

    val = msgGetInput(NULL, "Enter a fully qualified pathname for the directory\ncontaining the FreeBSD distribtion files:");
    if (!val)
	return 0;
    strcpy(ufsDevice.name, "ufs");
    ufsDevice.type = DEVICE_TYPE_UFS;
    ufsDevice.get = mediaGetUFS;
    ufsDevice.private = strdup(val);
    mediaDevice = &ufsDevice;
    return 1;
}

int
mediaSetNFS(char *str)
{
    static Device nfsDevice;
    char *val;

    val = msgGetInput(NULL, "Please enter the full NFS file specification for the remote\nhost and directory containing the FreeBSD distribution files.\nThis should be in the format:  hostname:/some/freebsd/dir");
    if (!val)
	return 0;
    tcpDeviceSelect(NULL);
    strncpy(nfsDevice.name, val, DEV_NAME_MAX);
    nfsDevice.type = DEVICE_TYPE_NFS;
    nfsDevice.init = mediaInitNFS;
    nfsDevice.get = mediaGetNFS;
    nfsDevice.shutdown = mediaShutdownNFS;
    nfsDevice.private = mediaDevice;
    mediaDevice = &nfsDevice;
    return 1;
}

Boolean
mediaExtractDistBegin(char *dir, int *fd, int *zpid, int *cpid)
{
    int i, pfd[2],qfd[2];

    if (!dir)
	dir = "/";
    Mkdir(dir, NULL);
    chdir(dir);
    pipe(pfd);
    pipe(qfd);
    *zpid = fork();
    if (!*zpid) {
	dup2(qfd[0], 0); close(qfd[0]);
	dup2(pfd[1], 1); close(pfd[1]);
	if (DebugFD != -1)
	    dup2(DebugFD, 2);
	else {
	    close(2);
	    open("/dev/null", O_WRONLY);
	}
	close(qfd[1]);
	close(pfd[0]);
	i = execl("/stand/gunzip", "/stand/gunzip", 0);
	if (isDebug())
	    msgDebug("/stand/gunzip command returns %d status\n", i);
	exit(i);
    }
    *fd = qfd[1];
    close(qfd[0]);
    *cpid = fork();
    if (!*cpid) {
	dup2(pfd[0], 0); close(pfd[0]);
	close(pfd[1]);
	close(qfd[1]);
	if (DebugFD != -1) {
	    dup2(DebugFD, 1);
	    dup2(DebugFD, 2);
	}
	else {
	    close(1); open("/dev/null", O_WRONLY);
	    dup2(1, 2);
	}
	i = execl("/stand/cpio", "/stand/cpio", "-iduVm", "-H", "tar", 0);
	if (isDebug())
	    msgDebug("/stand/cpio command returns %d status\n", i);
	exit(i);
    }
    close(pfd[0]);
    close(pfd[1]);
    return TRUE;
}

Boolean
mediaExtractDistEnd(int zpid, int cpid)
{
    int i,j;

    i = waitpid(zpid, &j, 0);
    if (i < 0) { /* Don't check status - gunzip seems to return a bogus one! */
	dialog_clear();
	if (isDebug())
	    msgDebug("wait for gunzip returned status of %d!\n", i);
	return FALSE;
    }
    i = waitpid(cpid, &j, 0);
    if (i < 0 || WEXITSTATUS(j)) {
	dialog_clear();
	if (isDebug())
	    msgDebug("cpio returned error status of %d!\n", WEXITSTATUS(j));
	return FALSE;
    }
    return TRUE;
}


Boolean
mediaExtractDist(char *dir, int fd)
{
    int i, j, zpid, cpid, pfd[2];

    if (!dir)
	dir = "/";

    Mkdir(dir, NULL);
    chdir(dir);
    pipe(pfd);
    zpid = fork();
    if (!zpid) {
	dup2(fd, 0); close(fd);
	dup2(pfd[1], 1); close(pfd[1]);
	if (DebugFD != -1)
	    dup2(DebugFD, 2);
	else {
	    close(2);
	    open("/dev/null", O_WRONLY);
	}
	close(pfd[0]);
	i = execl("/stand/gunzip", "/stand/gunzip", 0);
	if (isDebug())
	    msgDebug("/stand/gunzip command returns %d status\n", i);
	exit(i);
    }
    cpid = fork();
    if (!cpid) {
	dup2(pfd[0], 0); close(pfd[0]);
	close(fd);
	close(pfd[1]);
	if (DebugFD != -1) {
	    dup2(DebugFD, 1);
	    dup2(DebugFD, 2);
	}
	else {
	    close(1); open("/dev/null", O_WRONLY);
	    dup2(1, 2);
	}
	i = execl("/stand/cpio", "/stand/cpio", "-iduVm", "-H", "tar", 0);
	if (isDebug())
	    msgDebug("/stand/cpio command returns %d status\n", i);
	exit(i);
    }
    close(pfd[0]);
    close(pfd[1]);

    i = waitpid(zpid, &j, 0);
    if (i < 0) { /* Don't check status - gunzip seems to return a bogus one! */
	dialog_clear();
	if (isDebug())
	    msgDebug("wait for gunzip returned status of %d!\n", i);
	return FALSE;
    }
    i = waitpid(cpid, &j, 0);
    if (i < 0 || WEXITSTATUS(j)) {
	dialog_clear();
	if (isDebug())
	    msgDebug("cpio returned error status of %d!\n", WEXITSTATUS(j));
	return FALSE;
    }
    return TRUE;
}

Boolean
mediaGetType(void)
{
    dmenuOpenSimple(&MenuMedia);
    return TRUE;
}

/* Return TRUE if all the media variables are set up correctly */
Boolean
mediaVerify(void)
{
    if (!mediaDevice) {
	msgConfirm("Media type not set!  Please select a media type\nfrom the Installation menu before proceeding.");
	return FALSE;
    }
    return TRUE;
}
