/*-
 * Copyright (c) 1997 Michael Smith
 * Copyright (c) 1998 Jonathan Lemon
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
 *      $Id: bios.h,v 1.5 1999/08/18 02:20:04 msmith Exp $
 */

/* 
 * Signature structure for the BIOS32 Service Directory header 
 */
struct bios32_SDheader 
{
    u_int8_t	sig[4];
    u_int32_t	entry;
    u_int8_t	revision;
    u_int8_t	len;
    u_int8_t	cksum;
    u_int8_t	pad[5];
};

/* 
 * BIOS32 Service Directory entry.  Caller supplies name, bios32_SDlookup
 * fills in the rest of the details.
 */
struct bios32_SDentry 
{
    union 
    {
	u_int8_t	name[4];	/* service identifier */
	u_int32_t	id;		/* as a 32-bit value */
    } ident;
    u_int32_t	base;			/* base of service */
    u_int32_t	len;			/* service length */
    u_int32_t	entry;			/* entrypoint offset from base */
};

extern int		bios32_SDlookup(struct bios32_SDentry *ent);
extern u_int32_t	bios_sigsearch(u_int32_t start, u_char *sig, int siglen, 
					 int paralen, int sigofs);

#define BIOS_PADDRTOVADDR(x)	(((x) - ISA_HOLE_START) + atdevbase)
#define BIOS_VADDRTOPADDR(x)	(((x) - atdevbase) + ISA_HOLE_START)


/* 
 * PnP BIOS presence structure
 */
struct PnPBIOS_table 
{
    u_int8_t	sig[4];			/* "$PnP */
    u_int8_t	version;		/* should be 0x10 */
    u_int8_t	len;    		/* total structure length */
    u_int16_t	control;		/* BIOS feature flags */
    u_int8_t	cksum;			/* checksum */
    u_int32_t	evflagaddr;		/* address of event notificaton flag */
    u_int16_t	rmentryoffset;		/* real-mode entry offset */
    u_int16_t	rmentryseg;		/*                 segment */
    u_int16_t	pmentryoffset;		/* protected-mode entry offset */
    u_int32_t	pmentrybase;		/*                segment base */
    u_int32_t	oemdevid;		/* motherboard EISA ID */
    u_int16_t	rmbiosseg;		/* real-mode BIOS segment */
    u_int32_t	pmdataseg;		/* protected-mode data segment */
} __attribute__ ((packed));


/* 
 * Exported lookup results 
 */
extern struct bios32_SDentry	PCIbios;
extern struct PnPBIOS_table	*PnPBIOStable;

struct segment_info {
	u_int	base;
	u_int	limit;
};

#define BIOSCODE_FLAG	0x01
#define BIOSDATA_FLAG	0x02
#define BIOSUTIL_FLAG	0x04
#define BIOSARGS_FLAG	0x08

struct bios_segments {
	struct	segment_info code32;		/* 32-bit code (mandatory) */
	struct	segment_info code16;		/* 16-bit code */
	struct	segment_info data;		/* 16-bit data */
	struct	segment_info util;		/* 16-bit utility */
	struct	segment_info args;		/* 16-bit args */
};

struct bios_regs {
	u_int	eax;
	u_int	ebx;
	u_int	ecx;
	u_int	edx;
	u_int	esi;
	u_int	edi;
};

struct bios_args {
	u_int	entry;				/* entry point of routine */
	struct	bios_regs r;
	struct	bios_segments seg;
};

/*
 * PnP BIOS return codes
 */
#define PNP_SUCCESS				0x00
#define PNP_NOT_SET_STATICALLY			0x7f
#define PNP_UNKNOWN_FUNCTION			0x81
#define PNP_FUNTION_NOT_SUPPORTED		0x82
#define PNP_INVALID_HANDLE			0x83
#define PNP_BAD_PARAMETER			0x84
#define PNP_SET_FAILED				0x85
#define PNP_EVENTS_NOT_PENDING			0x86
#define PNP_SYSTEM_NOT_DOCKED			0x87
#define PNP_NO_ISA_PNP_CARDS			0x88
#define PNP_UNABLE_TO_DETERMINE_DOCK_CAPABILITIES 0x89
#define PNP_CONFIG_CHANGE_FAILED_NO_BATTERY	0x8a
#define PNP_CONFIG_CHANGE_FAILED_RESOURCE_CONFLICT 0x8b
#define PNP_BUFFER_TOO_SMALL			0x8c
#define PNP_USE_ESCD_SUPPORT			0x8d
#define PNP_MESSAGE_NOT_SUPPORTED		0x8e
#define PNP_HARDWARE_ERROR			0x8f

/*
 * DMI return codes
 */
#define DMI_SUCCESS				0x00
#define DMI_UNKNOWN_FUNCTION			0x81
#define DMI_FUNCTION_NOT_SUPPORTED		0x82
#define DMI_INVALID_HANDLE			0x83
#define DMI_BAD_PARAMETER			0x84
#define DMI_INVALID_SUBFUNCTION			0x85
#define DMI_NO_CHANGE				0x86
#define DMI_ADD_STRUCTURE_FAILED		0x87
#define DMI_READ_ONLY				0x8d
#define DMI_LOCK_NOT_SUPPORTED			0x90
#define DMI_CURRENTLY_LOCKED			0x91
#define DMI_INVALID_LOCK			0x92

/*
 * format specifiers and defines for bios16()
 *     s	= short (16 bits)
 *     i	= int (32 bits)
 *     p	= pointer (converted to seg:offset)
 *     C,D,U 	= selector (corresponding to code/data/utility segment)
 */
#define PNP_COUNT_DEVNODES	"sppD",		0x00
#define PNP_GET_DEVNODE		"sppsD",	0x01
#define PNP_SET_DEVNODE		"sppsD",	0x02
#define PNP_GET_EVENT		"spD",		0x03
#define PNP_SEND_MSG		"ssD",		0x04
#define PNP_GET_DOCK_INFO	"spD",		0x05

#define PNP_SEL_PRIBOOT		"ssiiisspD",	0x07
#define PNP_GET_PRIBOOT		"sspppppD",	0x08
#define PNP_SET_RESINFO		"spD",		0x09
#define PNP_GET_RESINFO		"spD",		0x0A
#define PNP_GET_APM_ID		"sppD",		0x0B

#define PNP_GET_ISA_INFO	"spD",		0x40
#define PNP_GET_ECSD_INFO	"spppD",	0x41
#define PNP_READ_ESCD		"spUD",		0x42
#define PNP_WRITE_ESCD		"spUD",		0x43

#define PNP_GET_DMI_INFO	"spppppD",	0x50
#define PNP_GET_DMI_STRUCTURE	"sppUD",	0x51
#define PNP_SET_DMI_STRUCTURE	"sppsUD"	0x52
#define PNP_GET_DMI_CHANGE	"spUD"		0x53
#define PNP_DMI_CONTROL		"sspsUD"	0x54
#define PNP_GET_GPNV_INFO	"sppppD"	0x55
#define PNP_READ_GPNV_DATA	"ssppUD"	0x56
#define PNP_WRITE_GPNV_DATA	"sspsUD"	0x57

#define PNP_BOOT_CHECK		"sp",		0x60
#define PNP_COUNT_IPL		"sppp",		0x61
#define PNP_GET_BOOTPRI		"spp",		0x62
#define PNP_SET_BOOTPRI		"sp",		0x63
#define PNP_GET_LASTBOOT	"sp",		0x64
#define PNP_GET_BOOTFIRST	"sp",		0x65
#define PNP_SET_BOOTFIRST	"sp",		0x66

extern int bios16(struct bios_args *, char *, ...);
extern int bios16_call(struct bios_regs *, char *);
extern int bios32(struct bios_regs *, u_int, u_short);
extern void set_bios_selectors(struct bios_segments *, int);
