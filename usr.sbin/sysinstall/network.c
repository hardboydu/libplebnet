/*
 * The new sysinstall program.
 *
 * This is probably the last attempt in the `sysinstall' line, the next
 * generation being slated to essentially a complete rewrite.
 *
 * $Id: network.c,v 1.6.2.14 1995/06/07 09:26:29 jkh Exp $
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

/* These routines deal with getting things off of network media */

#include "sysinstall.h"
#include <sys/fcntl.h>
#include <signal.h>
#include <sys/stat.h>

static Boolean	networkInitialized;
static pid_t	pppPid;
static pid_t	startPPP(Device *devp);

Boolean
mediaInitNetwork(Device *dev)
{
    int i;
    char *rp;

    if (networkInitialized || (dev->flags & OPT_LEAVE_NETWORK_UP))
	return TRUE;

    configResolv();
    if (!strncmp("cuaa", dev->name, 4)) {
	if (!msgYesNo("You have selected a serial-line network interface.\nDo you want to use PPP with it?")) {
	    if (!(dev->private = (void *)startPPP(dev))) {
		msgConfirm("Unable to start PPP!  This installation method\ncannot be used.");
		return FALSE;
	    }
	    networkInitialized = TRUE;
	    return TRUE;
	}
	else {
	    char *val;
	    char attach[256];

	    /* Cheesy slip attach */
	    snprintf(attach, 256, "slattach -a -h -l -s 9600 %s", dev->devname);
	    val = msgGetInput(attach, "Warning:  SLIP is rather poorly supported in this revision\nof the installation due to the lack of a dialing utility.\nIf you can use PPP for this instead then you're much better\noff doing so, otherwise SLIP works fairly well for *hardwired*\nlinks.  Please edit the following slattach command for\ncorrectness (default here is VJ compression, Hardware flow-control,\nignore carrier and 9600 baud data rate) and hit return to execute it.");
	    if (!val)
		return FALSE;
	    else
		strcpy(attach, val);
	    if (!vsystem(attach)) {
		dev->private = NULL;
		return TRUE;
	    }
	    else {
		msgConfirm("slattach returned a bad status!  Please verify that\nthe command is correct and try again.");
		return FALSE;
	    }
	}
    }
    else {
	char *cp, ifconfig[64];

	snprintf(ifconfig, 64, "%s%s", VAR_IFCONFIG, dev->name);
	cp = getenv(ifconfig);
	if (!cp) {
	    msgConfirm("The %s device is not configured.  You will need to do so\nin the Networking configuration menu before proceeding.");
	    return FALSE;
	}
	i = vsystem("ifconfig %s %s", dev->name, cp);
	if (i) {
	    msgConfirm("Unable to configure the %s interface!\nThis installation method cannot be used.", dev->name);
	    return FALSE;
	}
    }

    rp = getenv(VAR_GATEWAY);
    if (!rp || *rp == '0')
	msgConfirm("No gateway has been set. You may be unable to access hosts\nnot on your local network\n");
    else
	vsystem("route add default %s", rp);
    networkInitialized = TRUE;
    return TRUE;
}

void
mediaShutdownNetwork(Device *dev)
{
    char *cp;

    if (!networkInitialized || (dev->flags & OPT_LEAVE_NETWORK_UP))
	return;

    if (strncmp("cuaa", dev->name, 4)) {
	int i;
	char ifconfig[64];

	snprintf(ifconfig, 64, "%s%s", VAR_IFCONFIG, dev->name);
	cp = getenv(ifconfig);
	if (!cp)
	    return;
	i = vsystem("ifconfig %s down", dev->name);
	if (i)
	    msgConfirm("Warning: Unable to down the %s interface properly", dev->name);
	cp = getenv(VAR_GATEWAY);
	if (cp)
	    vsystem("route delete default");
	networkInitialized = FALSE;
    }
    else if (pppPid != 0) {
	kill(pppPid, SIGTERM);
	pppPid = 0;
    }
}

/* Start PPP on the 3rd screen */
static pid_t
startPPP(Device *devp)
{
    int vfd, fd2;
    FILE *fp;
    char *val;
    pid_t pid;
    char myaddr[16], provider[16], speed[16];

    /* We're going over to VTY2 */
    vfd = open("/dev/ttyv2", O_RDWR);
    if (vfd == -1)
	return 0;

    /* These are needed to make ppp work */
    Mkdir("/var/log", NULL);
    Mkdir("/var/spool/lock", NULL);
    Mkdir("/etc/ppp", NULL);

    /* Get any important user values */
    val = msgGetInput("115200",
"Enter the baud rate for your modem - this can be higher than the actual\nmaximum data rate since most modems can talk at one speed to the\ncomputer and at another speed to the remote end.\n\nIf you're not sure what to put here, just select the default.");
    strcpy(speed, val ? val : "115200");

    strcpy(provider, getenv(VAR_GATEWAY) ? getenv(VAR_GATEWAY) : "0");
    val = msgGetInput(provider, "Enter the IP address of your service provider or 0 if you\ndon't know it and would prefer to negotiate it dynamically.");
    strcpy(provider, val ? val : "0");

    if (devp->private && ((DevInfo *)devp->private)->ipaddr[0])
	strcpy(myaddr, ((DevInfo *)devp->private)->ipaddr);
    else
	strcpy(myaddr, "0");

    fp = fopen("/etc/ppp/ppp.linkup", "w");
    if (fp != NULL) {
	fprintf(fp, "MYADDR:\n");
	fprintf(fp, " delete ALL\n");
        fprintf(fp, " add 0 0 HISADDR\n");
	fchmod(fileno(fp), 0755);
	fclose(fp);
    }
    fd2 = open("/etc/ppp/ppp.secret", O_CREAT);
    if (fd2 != -1) {
	fchmod(fd2, 0755);
	close(fd2);
    }
    fp = fopen("/etc/ppp/ppp.conf", "w");
    if (!fp) {
	msgConfirm("Couldn't open /etc/ppp/ppp.conf file!  This isn't going to work");
	return 0;
    }
    fprintf(fp, "default:\n");
    fprintf(fp, " set speed %s\n", speed);
    fprintf(fp, " set device %s\n", devp->devname);
    fprintf(fp, " set ifaddr %s %s\n", myaddr, provider);
    fclose(fp);

    if (isDebug())
	msgDebug("Creating /dev/tun0 device.\n");
    if (!file_readable("/dev/tun0") && mknod("/dev/tun0", 0600 | S_IFCHR, makedev(52, 0))) {
	msgConfirm("Warning:  No /dev/tun0 device.  PPP will not work!");
	return 0;
    }
    if (!(pid = fork())) {
	dup2(vfd, 0);
	dup2(vfd, 1);
	dup2(vfd, 2);
	execl("/stand/ppp", "/stand/ppp", (char *)NULL);
	exit(1);
    }
    msgConfirm("The PPP command is now started on screen 3 (type ALT-F3 to\ninteract with it, ALT-F1 to switch back here). The only command\nyou'll probably want or need to use is the \"term\" command\nwhich starts a terminal emulator you can use to talk to your\nmodem and dial the service provider.  Once you're connected,\ncome back to this screen and press return.  DO NOT PRESS RETURN\nHERE UNTIL THE CONNECTION IS FULLY ESTABLISHED!");
    return pid;
}
