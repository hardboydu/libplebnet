/*
 * The new sysinstall program.
 *
 * This is probably the last attempt in the `sysinstall' line, the next
 * generation being slated to essentially a complete rewrite.
 *
 * $Id: cdrom.c,v 1.6.2.3 1995/06/05 12:03:44 jkh Exp $
 *
 * Copyright (c) 1995
 *	Jordan Hubbard.  All rights reserved.
 * Copyright (c) 1995
 * 	Gary J Palmer. All rights reserved.
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

/* These routines deal with getting things off of CDROM media */

#include "sysinstall.h"
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#include <fcntl.h>

#define CD9660
#include <sys/mount.h>
#undef CD9660

static Boolean cdromMounted;

Boolean
mediaInitCDROM(Device *dev)
{
    struct iso_args	args;
    struct stat		sb;

    if (cdromMounted)
	return TRUE;

    if (Mkdir("/cdrom", NULL))
	return FALSE;

    bzero(&args, sizeof(args));
    args.fspec = dev->devname;
    args.flags = 0;

    if (mount(MOUNT_CD9660, "/cdrom", MNT_RDONLY, (caddr_t) &args) == -1) {
	msgConfirm("Error mounting %s on /cdrom: %s (%u)\n", dev, strerror(errno), errno);
	return FALSE;
    }

    /*
     * Do a very simple check to see if this looks roughly like a 2.0.5 CDROM
     * Unfortunately FreeBSD won't let us read the ``label'' AFAIK, which is one
     * sure way of telling the disc version :-(
     */
    if (stat("/cdrom/dists", &sb)) {
	if (errno == ENOENT) {
	    msgConfirm("Couldn't locate the directory `dists' on the CD.\nIs this a 2.0.5 CDROM?\n");
	    return FALSE;
	}
	else {
	    msgConfirm("Couldn't stat directory %s: %s", "/cdrom/dists", strerror(errno));
	    return FALSE;
	}
    }
    cdromMounted = TRUE;
    return TRUE;
}

int
mediaGetCDROM(Device *dev, char *file, Attribs *dist_attrs)
{
    char		buf[PATH_MAX];

    snprintf(buf, PATH_MAX, "/cdrom/%s", file);
    if (!access(buf,R_OK))
	return open(buf, O_RDONLY);
    snprintf(buf, PATH_MAX, "/cdrom/dists/%s", file);
    return open(buf, O_RDONLY);
}

void
mediaShutdownCDROM(Device *dev)
{
    if (!cdromMounted)
	return;
    msgDebug("Unmounting /cdrom\n");
    if (unmount("/cdrom", MNT_FORCE) != 0)
	msgConfirm("Could not unmount the CDROM: %s\n", strerror(errno));
    msgDebug("Unmount returned\n");
    cdromMounted = FALSE;
    return;
}
