/*-
 * Copyright (c) 2000 Doug Rabson
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
 *	$FreeBSD$
 */

#ifndef _PCI_AGPREG_H_
#define _PCI_AGPREG_H_

/*
 * Offsets for various AGP configuration registers.
 */
#define AGP_APBASE		0x10
#define AGP_CAPPTR		0x34

/*
 * Offsets from the AGP Capability pointer.
 */
#define AGP_CAPID		0x0
#define AGP_CAPID_GET_MAJOR(x)		(((x) & 0x00f00000U) >> 20)
#define AGP_CAPID_GET_MINOR(x)		(((x) & 0x000f0000U) >> 16)
#define AGP_CAPID_GET_NEXT_PTR(x)	(((x) & 0x0000ff00U) >> 8)
#define AGP_CAPID_GET_CAP_ID(x)		(((x) & 0x000000ffU) >> 0)

#define AGP_STATUS		0x4
#define AGP_COMMAND		0x8

/*
 * Config offsets for Intel AGP chipsets.
 */
#define AGP_INTEL_NBXCFG	0x50
#define AGP_INTEL_ERRSTS	0x91
#define AGP_INTEL_AGPCTRL	0xb0
#define AGP_INTEL_APSIZE	0xb4
#define AGP_INTEL_ATTBASE	0xb8

/*
 * Config offsets for VIA AGP chipsets.
 */
#define AGP_VIA_GARTCTRL	0x80
#define AGP_VIA_APSIZE		0x84
#define AGP_VIA_ATTBASE		0x88

/*
 * Config offsets for SiS AGP chipsets.
 */
#define AGP_SIS_ATTBASE		0x90
#define AGP_SIS_WINCTRL		0x94
#define AGP_SIS_TLBCTRL		0x97
#define AGP_SIS_TLBFLUSH	0x98

/*
 * Config offsets for Ali AGP chipsets.
 */
#define AGP_ALI_AGPCTRL		0xb8
#define AGP_ALI_ATTBASE		0xbc
#define AGP_ALI_TLBCTRL		0xc0

/*
 * Config offsets for the AMD 751 chipset.
 */
#define AGP_AMD751_REGISTERS	0x14
#define AGP_AMD751_APCTRL	0xac
#define AGP_AMD751_MODECTRL	0xb0

/*
 * Memory mapped register offsets for AMD 751 chipset.
 */
#define AGP_AMD751_CAPS		0x00
#define AGP_AMD751_CAPS_EHI		0x0800
#define AGP_AMD751_CAPS_P2P		0x0400
#define AGP_AMD751_CAPS_MPC		0x0200
#define AGP_AMD751_CAPS_VBE		0x0100
#define AGP_AMD751_CAPS_REV		0x00ff
#define AGP_AMD751_STATUS	0x02
#define AGP_AMD751_STATUS_P2PS		0x0800
#define AGP_AMD751_STATUS_GCS		0x0400
#define AGP_AMD751_STATUS_MPS		0x0200
#define AGP_AMD751_STATUS_VBES		0x0100
#define AGP_AMD751_STATUS_P2PE		0x0008
#define AGP_AMD751_STATUS_GCE		0x0004
#define AGP_AMD751_STATUS_VBEE		0x0001
#define AGP_AMD751_ATTBASE	0x04
#define AGP_AMD751_TLBCTRL	0x0c


#endif /* !_PCI_AGPREG_H_ */
