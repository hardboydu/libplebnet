/*-
 * Copyright (c) 1999 FreeBSD(98) Porting Team.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _PC98_PC98_SC_MACHDEP_H_
#define	_PC98_PC98_SC_MACHDEP_H_

#undef SC_ALT_MOUSE_IMAGE
#undef SC_DFLT_FONT
#undef SC_MOUSE_CHAR
#undef SC_PIXEL_MODE
#undef SC_NO_FONT_LOADING
#define SC_NO_FONT_LOADING	1
#undef SC_NO_PALETTE_LOADING
#define SC_NO_PALETTE_LOADING	1

#ifndef SC_KERNEL_CONS_ATTR
#define SC_KERNEL_CONS_ATTR	(FG_LIGHTGREY | BG_BLACK)
#endif

#define KANJI			1

#define BELL_DURATION		5
#define BELL_PITCH_8M		1339
#define BELL_PITCH_5M		1678

#define	UJIS			0
#define SJIS			1

#define PRINTABLE(c)		((c) > 0x1b || ((c) > 0x0f && (c) < 0x1b) \
				 || (c) < 0x07)

#define ISMOUSEAVAIL(af)	(1)
#define ISFONTAVAIL(af)		((af) & V_ADP_FONT)
#define ISPALAVAIL(af)		((af) & V_ADP_PALETTE)

#ifdef KANJI

#define IS_KTYPE_ASCII_or_HANKAKU(A)	(!((A) & 0xee))
#define IS_KTYPE_KANA(A)		((A) & 0x11)
#define KTYPE_MASK_CTRL(A)		((A) &= 0xF0)

#define _SCR_MD_STAT_DECLARED_
typedef struct {
	u_char			kanji_1st_char;
	u_char			kanji_type;
#define KTYPE_ASCII		0		/* ASCII */
#define KTYPE_KANA		1		/* HANKAKU */
#define KTYPE_JKANA		0x10		/* JIS HANKAKU */
#define KTYPE_7JIS		0x20		/* JIS */
#define KTYPE_SJIS		2		/* Shift JIS */
#define KTYPE_UJIS		4		/* UJIS */
#define KTYPE_SUKANA		3		/* Shift JIS or UJIS HANKAKU */
#define KTYPE_SUJIS		6		/* SHift JIS or UJIS */
#define KTYPE_KANIN		0x80		/* Kanji Invoke sequence */
#define KTYPE_ASCIN		0x40		/* ASCII Invoke sequence */
} scr_md_stat_t;

#endif /* KANJI */

#endif /* !_PC98_PC98_SC_MACHDEP_H_ */
