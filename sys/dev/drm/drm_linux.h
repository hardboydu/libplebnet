/*
 * Copyright (c) 2000 by Coleman Kane <cokane@FreeBSD.org>
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Gardner Buchanan.
 * 4. The name of Gardner Buchanan may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/* FIXME: There are IOCTLS to merge in here, see drm.h*/

/* Query IOCTLs */
/* XFree86 4.1.x DRI support */

#define LINUX_DRM_IOCTL_VERSION		0x6400
#define LINUX_DRM_IOCTL_GET_UNIQUE	0x6401
#define LINUX_DRM_IOCTL_GET_MAGIC	0x6402
#define LINUX_DRM_IOCTL_IRQ_BUSID	0x6403
#define LINUX_DRM_IOCTL_GET_MAP		0x6404
#define LINUX_DRM_IOCTL_GET_CLIENT	0x6405
#define LINUX_DRM_IOCTL_GET_STATS	0x6406

#define LINUX_DRM_IOCTL_SET_UNIQUE	0x6410
#define LINUX_DRM_IOCTL_AUTH_MAGIC	0x6411
#define LINUX_DRM_IOCTL_BLOCK		0x6412
#define LINUX_DRM_IOCTL_UNBLOCK		0x6413
#define LINUX_DRM_IOCTL_CONTROL		0x6414
#define LINUX_DRM_IOCTL_ADD_MAP		0x6415
#define LINUX_DRM_IOCTL_ADD_BUFS	0x6416
#define LINUX_DRM_IOCTL_MARK_BUFS	0x6417
#define LINUX_DRM_IOCTL_INFO_BUFS	0x6418
#define LINUX_DRM_IOCTL_MAP_BUFS	0x6419
#define LINUX_DRM_IOCTL_FREE_BUFS	0x641a

#define LINUX_DRM_IOCTL_RM_MAP		0x641b

#define LINUX_DRM_IOCTL_SET_SAREA_CTX	0x641c
#define LINUX_DRM_IOCTL_GET_SAREA_CTX 	0x641d

#define LINUX_DRM_IOCTL_ADD_CTX		0x6420
#define LINUX_DRM_IOCTL_RM_CTX		0x6421
#define LINUX_DRM_IOCTL_MOD_CTX		0x6422
#define LINUX_DRM_IOCTL_GET_CTX		0x6423
#define LINUX_DRM_IOCTL_SWITCH_CTX	0x6424
#define LINUX_DRM_IOCTL_NEW_CTX		0x6425
#define LINUX_DRM_IOCTL_RES_CTX		0x6426
#define LINUX_DRM_IOCTL_ADD_DRAW	0x6427
#define LINUX_DRM_IOCTL_RM_DRAW		0x6428
#define LINUX_DRM_IOCTL_DMA		0x6429
#define LINUX_DRM_IOCTL_LOCK		0x642a
#define LINUX_DRM_IOCTL_UNLOCK		0x642b
#define LINUX_DRM_IOCTL_FINISH		0x642c

#define LINUX_DRM_IOCTL_AGP_ACQUIRE	0x6430
#define LINUX_DRM_IOCTL_AGP_RELEASE	0x6431
#define LINUX_DRM_IOCTL_AGP_ENABLE	0x6432
#define LINUX_DRM_IOCTL_AGP_INFO	0x6433
#define LINUX_DRM_IOCTL_AGP_ALLOC	0x6434
#define LINUX_DRM_IOCTL_AGP_FREE	0x6435
#define LINUX_DRM_IOCTL_AGP_BIND	0x6436
#define LINUX_DRM_IOCTL_AGP_UNBIND	0x6437

#define LINUX_DRM_IOCTL_SG_ALLOC	0x6438
#define LINUX_DRM_IOCTL_SG_FREE		0x6439

/* MGA specific ioctls */
#define LINUX_DRM_IOCTL_MGA_INIT	0x6440
#define LINUX_DRM_IOCTL_MGA_FLUSH	0x6441
#define LINUX_DRM_IOCTL_MGA_RESET	0x6442
#define LINUX_DRM_IOCTL_MGA_SWAP	0x6443
#define LINUX_DRM_IOCTL_MGA_CLEAR	0x6444
#define LINUX_DRM_IOCTL_MGA_VERTEX	0x6445
#define LINUX_DRM_IOCTL_MGA_INDICES	0x6446
#define LINUX_DRM_IOCTL_MGA_ILOAD	0x6447
#define LINUX_DRM_IOCTL_MGA_BLIT	0x6448

/* i810 specific ioctls */
#define LINUX_DRM_IOCTL_I810_INIT	0x6440
#define LINUX_DRM_IOCTL_I810_VERTEX	0x6441
#define LINUX_DRM_IOCTL_I810_CLEAR	0x6442
#define LINUX_DRM_IOCTL_I810_FLUSH	0x6443
#define LINUX_DRM_IOCTL_I810_GETAGE	0x6444
#define LINUX_DRM_IOCTL_I810_GETBUF	0x6445
#define LINUX_DRM_IOCTL_I810_SWAP	0x6446
#define LINUX_DRM_IOCTL_I810_COPY	0x6447
#define LINUX_DRM_IOCTL_I810_DOCOPY	0x6448

/* Rage 128 specific ioctls */
#define LINUX_DRM_IOCTL_R128_INIT	0x6440
#define LINUX_DRM_IOCTL_R128_CCE_START	0x6441
#define LINUX_DRM_IOCTL_R128_CCE_STOP	0x6442
#define LINUX_DRM_IOCTL_R128_CCE_RESET	0x6443
#define LINUX_DRM_IOCTL_R128_CCE_IDLE	0x6444
#define LINUX_DRM_IOCTL_R128_RESET	0x6446
#define LINUX_DRM_IOCTL_R128_SWAP	0x6447
#define LINUX_DRM_IOCTL_R128_CLEAR	0x6448
#define LINUX_DRM_IOCTL_R128_VERTEX	0x6449
#define LINUX_DRM_IOCTL_R128_INDICES	0x644a
#define LINUX_DRM_IOCTL_R128_BLIT	0x644b
#define LINUX_DRM_IOCTL_R128_DEPTH	0x644c
#define LINUX_DRM_IOCTL_R128_STIPPLE	0x644d
#define LINUX_DRM_IOCTL_R128_INDIRECT	0x644f
#define LINUX_DRM_IOCTL_R128_FULLSCREEN	0x6450

/* Radeon specific ioctls */
#define LINUX_DRM_IOCTL_RADEON_CP_INIT	0x6440
#define LINUX_DRM_IOCTL_RADEON_CP_START	0x6441
#define LINUX_DRM_IOCTL_RADEON_CP_STOP	0x6442
#define LINUX_DRM_IOCTL_RADEON_CP_RESET	0x6443
#define LINUX_DRM_IOCTL_RADEON_CP_IDLE	0x6444
#define LINUX_DRM_IOCTL_RADEON_RESET	0x6445
#define LINUX_DRM_IOCTL_RADEON_FULLSCREEN	0x6446
#define LINUX_DRM_IOCTL_RADEON_SWAP	0x6447
#define LINUX_DRM_IOCTL_RADEON_CLEAR	0x6448
#define LINUX_DRM_IOCTL_RADEON_VERTEX	0x6449
#define LINUX_DRM_IOCTL_RADEON_INDICES	0x644a
#define LINUX_DRM_IOCTL_RADEON_STIPPLE	0x644c
#define LINUX_DRM_IOCTL_RADEON_INDIRECT	0x644d
#define LINUX_DRM_IOCTL_RADEON_TEXTURE	0x644e

/* card specific ioctls may increase the DRM_MAX */
#define  LINUX_IOCTL_DRM_MIN		LINUX_DRM_IOCTL_VERSION
#define  LINUX_IOCTL_DRM_MAX		LINUX_DRM_IOCTL_R128_FULLSCREEN
