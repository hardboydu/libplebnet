/*
 * Copyright (c) 2002 Juli Mallett.  All rights reserved.
 *
 * This software was written by Juli Mallett <jmallett@FreeBSD.org> for the
 * FreeBSD project.  Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistribution of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistribution in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/disklabel.h>
#include <sys/stat.h>

#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libufs.h>

ssize_t
bread(struct uufsd *disk, ufs2_daddr_t blockno, void *data, size_t size)
{
	char *buf;
	ssize_t cnt;

	DEBUG(NULL);

	/*
	 * For when we need to work with the data as a buffer.
	 */
	buf = data;

	cnt = pread(disk->d_fd, data, size, (off_t)(blockno * disk->d_bsize));
	/*
	 * In case of failure, zero data, which must be fs_bsize.
	 */
	if (cnt != size) {
		DEBUG("short read");
		for (cnt = 0; cnt < disk->d_fs.fs_bsize; cnt++)
			buf[cnt] = 0;
		return -1;
	}
	return cnt;
}

ssize_t
bwrite(struct uufsd *disk, ufs2_daddr_t blockno, const void *data, size_t size)
{
	ssize_t cnt;

	DEBUG(NULL);

	cnt = pwrite(disk->d_fd, data, size, (off_t)(blockno * disk->d_bsize));
	if (cnt != size) {
		DEBUG("short write");
		return -1;
	}
	
	return cnt;
}
