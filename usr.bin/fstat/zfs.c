/*-
 * Copyright (c) 2007 Ulf Lilleengen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#define _KERNEL
#include <sys/mount.h>
#include <sys/taskqueue.h>
#undef _KERNEL
#include <sys/sysctl.h>

#undef lbolt
#undef lbolt64
#undef gethrestime_sec
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_sa.h>

#include <err.h>
#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>

#define ZFS
#undef dprintf
#include <fstat.h>

/* 
 * Offset calculations that are used to get data from znode without having the
 * definition.
 */
#define LOCATION_ZID (2 * sizeof(void *))
#define LOCATION_ZPHYS(zsize) ((zsize) - (2 * sizeof(void *) + sizeof(struct task)))

int
zfs_filestat(struct vnode *vp, struct filestat *fsp)
{

	znode_phys_t zphys;
	struct mount mount, *mountptr;
	uint64_t *zid;
	void *znodeptr, *vnodeptr;
	char *dataptr;
	void *zphys_addr;
	size_t len;
	int size;

	len = sizeof(size);
	if (sysctlbyname("debug.sizeof.znode", &size, &len, NULL, 0) == -1) {
		dprintf(stderr, "error getting sysctl\n");
		return (0);
	}
	znodeptr = malloc(size);
	if (znodeptr == NULL) {
		dprintf(stderr, "error allocating memory for znode storage\n");
		return (0);
	}

	/* Since we have problems including vnode.h, we'll use the wrappers. */
	vnodeptr = getvnodedata(vp);
	if (!KVM_READ(vnodeptr, znodeptr, (size_t)size)) {
		dprintf(stderr, "can't read znode at %p for pid %d\n",
		    (void *)vnodeptr, Pid);
		goto bad;
	}

	/* 
	 * z_id field is stored in the third pointer. We therefore skip the two
	 * first bytes. 
	 *
	 * Pointer to the z_phys structure is the next last pointer. Therefore
	 * go back two bytes from the end.
	 */
	dataptr = znodeptr;
	zid = (uint64_t *)(dataptr + LOCATION_ZID);
	zphys_addr = *(void **)(dataptr + LOCATION_ZPHYS(size));

	if (!KVM_READ(zphys_addr, &zphys, sizeof(zphys))) {
		dprintf(stderr, "can't read znode_phys at %p for pid %d\n",
		    zphys_addr, Pid);
		goto bad;
	}

	/* Get the mount pointer, and read from the address. */
	mountptr = getvnodemount(vp);
	if (!KVM_READ(mountptr, &mount, sizeof(mount))) {
		dprintf(stderr, "can't read mount at %p for pid %d\n",
		    (void *)mountptr, Pid);
		goto bad;
	}

	fsp->fsid = (long)(uint32_t)mount.mnt_stat.f_fsid.val[0];
	fsp->fileid = *zid;
	/*
	 * XXX: Shows up wrong in output, but UFS has this error too. Could
	 * be that we're casting mode-variables from 64-bit to 8-bit or simply
	 * error in the mode-to-string function.
	 */
	fsp->mode = (mode_t)zphys.zp_mode;
	fsp->size = (u_long)zphys.zp_size;
	fsp->rdev = (dev_t)zphys.zp_rdev;
	free(znodeptr);
	return (1);
bad:
	free(znodeptr);
	return (0);
}
