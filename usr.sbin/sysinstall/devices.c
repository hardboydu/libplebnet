/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: devices.c,v 1.23 1995/05/20 15:47:18 jkh Exp $
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

#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>

#define	NSIP
#include <netns/ns.h>
#include <netns/ns_if.h>
#include <netdb.h>

#define EON
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <sys/protosw.h>

#include <ctype.h>

static Device *Devices[DEV_MAX];
static int numDevs;

static struct {
    DeviceType type;
    char *name;
    char *description;
} device_names[] = {
    { DEVICE_TYPE_CDROM, "cd0a",	"SCSI CDROM drive"					},
    { DEVICE_TYPE_CDROM, "cd1a",	"SCSI CDROM drive (2nd unit)"				},
    { DEVICE_TYPE_CDROM, "mcd0a",	"Mitsumi (old model) CDROM drive"			},
    { DEVICE_TYPE_CDROM, "mcd1a",	"Mitsumi (old model) CDROM drive (2nd unit)"		},
    { DEVICE_TYPE_CDROM, "scd0a",	"Sony CDROM drive - CDU31/33A type",			},
    { DEVICE_TYPE_CDROM, "scd1a",	"Sony CDROM drive - CDU31/33A type (2nd unit)"		},
    { DEVICE_TYPE_CDROM, "matcd0a",	"Matsushita CDROM ('sound blaster' type)"		},
    { DEVICE_TYPE_CDROM, "matcd1a",	"Matsushita CDROM (2nd unit)"				},
    { DEVICE_TYPE_TAPE,  "rst0",	"SCSI tape drive"					},
    { DEVICE_TYPE_TAPE,  "rst1",	"SCSI tape drive (2nd unit)"				},
    { DEVICE_TYPE_TAPE,  "ft0",		"Floppy tape drive (QIC-02)"				},
    { DEVICE_TYPE_TAPE,  "wt0",		"Wangtek tape drive"					},
    { DEVICE_TYPE_DISK,  "sd",		"SCSI disk device"					},
    { DEVICE_TYPE_DISK,  "wd",		"IDE/ESDI/MFM/ST506 disk device"			},
    { DEVICE_TYPE_FLOPPY, "rfd0",	"Floppy disk drive (unit A)"				},
    { DEVICE_TYPE_FLOPPY, "rfd1",	"Floppy disk drive (unit B)"				},
    { DEVICE_TYPE_NETWORK, "cuaa0",	"Serial port (COM1) - possible PPP device"		},
    { DEVICE_TYPE_NETWORK, "cuaa1",	"Serial port (COM2) - possible PPP device"		},
    { DEVICE_TYPE_NETWORK, "lo",	"Loop-back (local) network interface"			},
    { DEVICE_TYPE_NETWORK, "sl",	"Serial-line IP (SLIP) interface"			},
    { DEVICE_TYPE_NETWORK, "ppp",	"Point-to-Point Protocol (PPP) interface"		},
    { DEVICE_TYPE_NETWORK, "ed",	"WD/SMC 80xx; Novell NE1000/2000; 3Com 3C503 cards"	},
    { DEVICE_TYPE_NETWORK, "ep",	"3Com 3C509 interface card"				},
    { DEVICE_TYPE_NETWORK, "el",	"3Com 3C501 interface card"				},
    { DEVICE_TYPE_NETWORK, "fe",	"Fujitsu MB86960A/MB86965A Ethernet"			},
    { DEVICE_TYPE_NETWORK, "ie",	"AT&T StarLAN 10 and EN100; 3Com 3C507; NI5210"		},
    { DEVICE_TYPE_NETWORK, "le",	"DEC EtherWorks 2 and 3"				},
    { DEVICE_TYPE_NETWORK, "lnc",	"Lance/PCnet cards (Isolan/Novell NE2100/NE32-VL)"	},
    { DEVICE_TYPE_NETWORK, "ze",	"IBM/National Semiconductor PCMCIA ethernet"		},
    { DEVICE_TYPE_NETWORK, "zp",	"3Com PCMCIA Etherlink III"				},
    { NULL },
};

Device *
new_device(char *name)
{
    Device *dev;

    dev = safe_malloc(sizeof(Device));
    if (name)
	strcpy(dev->name, name);
    else
	dev->name[0] = '\0';
    return dev;
}

static int
deviceTry(char *name, char *try)
{
    int fd;

    snprintf(try, FILENAME_MAX, "/dev/%s", name);
    fd = open(try, O_RDWR);
    if (fd > 0)
	return fd;
    snprintf(try, FILENAME_MAX, "/mnt/dev/%s", name);
    fd = open(try, O_RDONLY);
    return fd;
}

static void
deviceDiskFree(Device *dev)
{
    Free_Disk(dev->private);
}

/* Register a new device in the devices array */
Device *
deviceRegister(char *name, char *desc, char *devname, DeviceType type, Boolean enabled,
	       Boolean (*init)(Device *), Boolean (*get)(char *), void (*close)(Device *), void *private)
{
    Device *newdev;

    if (numDevs == DEV_MAX)
	msgFatal("Too many devices found!");
    newdev = new_device(name);
    newdev->description = desc;
    newdev->devname = devname;
    newdev->type = type;
    newdev->enabled = enabled;
    newdev->init = init;
    newdev->get = get;
    newdev->close = close;
    newdev->private = private;
    Devices[numDevs] = newdev;
    Devices[++numDevs] = NULL;
    return newdev;
}
		
/* Get all device information for devices we have attached */
void
deviceGetAll(void)
{
    int i, fd, s;
    struct ifconf ifc;
    struct ifreq *ifptr, *end;
    int ifflags;
    char buffer[INTERFACE_MAX * sizeof(struct ifreq)];
    char **names;

    /* Try and get the disks first */
    if ((names = Disk_Names()) != NULL) {
	int i;

	for (i = 0; names[i]; i++) {
	    Disk *d;

	    d = Open_Disk(names[i]);
	    if (!d)
		msgFatal("Unable to open disk %s", names[i]);

	    (void)deviceRegister(names[i], names[i], d->name, DEVICE_TYPE_DISK, FALSE,
				 mediaInitUFS, mediaGetUFS, deviceDiskFree, d);
	    msgDebug("Found a device of type disk named: %s\n", names[i]);
	}
	free(names);
    }

    /*
     * Try to get all the types of devices it makes sense to get at the
     * second stage of the installation.
     */
    for (i = 0; device_names[i].name; i++) {
	char try[FILENAME_MAX];

	switch(device_names[i].type) {
	case DEVICE_TYPE_CDROM:
	    fd = deviceTry(device_names[i].name, try);
	    if (fd >= 0) {
		close(fd);
		(void)deviceRegister(device_names[i].name, device_names[i].description, strdup(try),
				     DEVICE_TYPE_CDROM, TRUE, mediaInitCDROM, mediaGetCDROM, mediaCloseCDROM, NULL);
		msgDebug("Found a device of type CDROM named: %s\n", device_names[i].name);
	    }
	    break;

	case DEVICE_TYPE_TAPE:
	    fd = deviceTry(device_names[i].name, try);
	    if (fd >= 0) {
		close(fd);
		deviceRegister(device_names[i].name, device_names[i].description, strdup(try),
			       DEVICE_TYPE_TAPE, TRUE, mediaInitTape, mediaGetTape, mediaCloseTape, NULL);
		msgDebug("Found a device of type TAPE named: %s\n", device_names[i].name);
	    }
	    break;

	case DEVICE_TYPE_FLOPPY:
	    fd = deviceTry(device_names[i].name, try);
	    if (fd >= 0) {
		close(fd);
		deviceRegister(device_names[i].name, device_names[i].description, strdup(try),
			       DEVICE_TYPE_FLOPPY, TRUE, mediaInitFloppy, mediaGetFloppy, mediaCloseFloppy, NULL);
		msgDebug("Found a device of type TAPE named: %s\n", device_names[i].name);
	    }
	    break;

	case DEVICE_TYPE_NETWORK:
	    fd = deviceTry(device_names[i].name, try);
	    if (fd >= 0) {
		close(fd);
		/* The only network devices that have fds associated are serial ones */
		deviceRegister("ppp0", device_names[i].description, strdup(try),
			       DEVICE_TYPE_NETWORK, TRUE, mediaInitNetwork, mediaGetNetwork, mediaCloseNetwork, NULL);
		msgDebug("Found a device of type network named: %s\n", device_names[i].name);
	    }
	    break;

	default:
	    break;
	}
    }

    /* Now go for the (other) network interfaces dynamically.  Stolen shamelessly from ifconfig! */
    ifc.ifc_len = sizeof(buffer);
    ifc.ifc_buf = buffer;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
	msgConfirm("ifconfig: socket");
	return;
    }
    if (ioctl(s, SIOCGIFCONF, (char *) &ifc) < 0) {
	msgConfirm("ifconfig (SIOCGIFCONF)");
	return;
    }
    ifflags = ifc.ifc_req->ifr_flags;
    end = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifptr = ifc.ifc_req; ifptr < end; ifptr++) {
	/* If it's not a link entry, forget it */
	if (ifptr->ifr_ifru.ifru_addr.sa_family != AF_LINK) 
	    continue;
	/* Eliminate network devices that don't make sense */
	if (!strncmp(ifptr->ifr_name, "tun", 3)
	    || !strncmp(ifptr->ifr_name, "lo0", 3))
	    continue;
	deviceRegister(ifptr->ifr_name, ifptr->ifr_name, ifptr->ifr_name,
		       DEVICE_TYPE_NETWORK, TRUE, mediaInitNetwork, mediaGetNetwork, mediaCloseNetwork, NULL);
	msgDebug("Found a device of type network named: %s\n", ifptr->ifr_name);
	close(s);
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	    msgConfirm("ifconfig: socket");
	    continue;
	}
	if (ifptr->ifr_addr.sa_len)	/* I'm not sure why this is here - it's inherited */
	    ifptr = (struct ifreq *)((caddr_t)ifptr + ifptr->ifr_addr.sa_len - sizeof(struct sockaddr));
    }
}

/*
 * Find all devices that match the criteria, allowing "wildcarding" as well
 * by allowing NULL or ANY values to match all.  The array returned is static
 * and may be used until the next invocation of deviceFind().
 */
Device **
deviceFind(char *name, DeviceType class)
{
    static Device *found[DEV_MAX];
    int i, j;

    for (i = 0, j = 0; i < numDevs; i++) {
	if ((!name || !strcmp(Devices[i]->name, name))
	    && (class == DEVICE_TYPE_ANY || class == Devices[i]->type))
	    found[j++] = Devices[i];
    }
    found[j] = NULL;
    return j ? found : NULL;
}

int
deviceCount(Device **devs)
{
    int i;

    if (!devs)
	return 0;
    for (i = 0; devs[i]; i++);
    return i;
}

/*
 * Create a menu listing all the devices of a certain type in the system.
 * The passed-in menu is expected to be a "prototype" from which the new
 * menu is cloned.
 */
DMenu *
deviceCreateMenu(DMenu *menu, DeviceType type, int (*hook)())
{
    Device **devs;
    int numdevs;
    DMenu *tmp = NULL;
    int i, j;

    devs = deviceFind(NULL, type);
    if (!devs)
	return NULL;

    for (numdevs = 0; devs[numdevs]; numdevs++);
    tmp = (DMenu *)safe_malloc(sizeof(DMenu) + (sizeof(DMenuItem) * (numdevs + 1)));
    bcopy(menu, tmp, sizeof(DMenu));
    for (i = 0; devs[i]; i++) {
	tmp->items[i].title = devs[i]->name;
	for (j = 0; device_names[j].name; j++) {
	    if (!strncmp(devs[i]->name, device_names[j].name,
			 strlen(device_names[j].name))) {
		tmp->items[i].prompt = device_names[j].description;
		break;
	    }
	}
	if (!device_names[j].name)
	    tmp->items[i].prompt = "<unknown device type>";
	tmp->items[i].type = DMENU_CALL;
	tmp->items[i].ptr = hook;
	tmp->items[i].disabled = FALSE;
    }
    tmp->items[i].type = DMENU_NOP;
    tmp->items[i].title = NULL;
    return tmp;
}
