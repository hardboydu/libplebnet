/*
 * Copyright (c) 2002 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#ifndef _SYS_GPT_H_
#define	_SYS_GPT_H_

struct gpt_hdr {
	char		hdr_sig[8];
#define	GPT_HDR_SIG		"EFI PART"
	uint32_t	hdr_revision;
#define	GPT_HDR_REVISION	0x00010000
	uint32_t	hdr_size;
	uint32_t	hdr_crc_self;
	uint32_t	__reserved;
	uint64_t	hdr_lba_self;
	uint64_t	hdr_lba_alt;
	uint64_t	hdr_lba_start;
	uint64_t	hdr_lba_end;
	struct uuid	hdr_uuid;
	uint64_t	hdr_lba_table;
	uint32_t	hdr_entries;
	uint32_t	hdr_entsz;
	uint32_t	hdr_crc_table;
};

struct gpt_ent {
	struct uuid	ent_type;
	struct uuid	ent_uuid;
	uint64_t	ent_lba_start;
	uint64_t	ent_lba_end;
	uint64_t	ent_attr;
#define	GPT_ENT_ATTR_PLATFORM		(1ULL << 0)
	short		ent_name[36];		/* UNICODE!!! */
};

#define	GPT_ENT_TYPE_UNUSED		\
	{0x00000000,0x0000,0x0000,0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x00}}
#define	GPT_ENT_TYPE_EFI		\
	{0xc12a7328,0xf81f,0x11d2,0xba,0x4b,{0x00,0xa0,0xc9,0x3e,0xc9,0x3b}}
#define	GPT_ENT_TYPE_MBR		\
	{0x024dee41,0x33e7,0x11d3,0x9d,0x69,{0x00,0x08,0xc7,0x81,0xf3,0x9f}}
#define	GPT_ENT_TYPE_FREEBSD		\
	{0x516e7cb4,0x6ecf,0x11d6,0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}}
#define	GPT_ENT_TYPE_FREEBSD_SWAP	\
	{0x516e7cb5,0x6ecf,0x11d6,0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}}
#define	GPT_ENT_TYPE_FREEBSD_UFS	\
	{0x516e7cb6,0x6ecf,0x11d6,0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}}
#define	GPT_ENT_TYPE_FREEBSD_UFS2	\
	{0x516e7cb7,0x6ecf,0x11d6,0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}}
#define	GPT_ENT_TYPE_FREEBSD_VINUM	\
	{0x516e7cb8,0x6ecf,0x11d6,0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}}

#endif /* _SYS_GPT_H_ */
