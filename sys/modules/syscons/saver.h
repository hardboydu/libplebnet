/*-
 * Copyright (c) 1995-1998 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 *	$Id: saver.h,v 1.13 1998/11/04 03:49:38 peter Exp $
 */
#include <machine/apm_bios.h>
#include <machine/console.h>

#include <i386/isa/videoio.h>
#include <i386/isa/syscons.h>

extern scr_stat	*cur_console;
extern u_short	*Crtat;
extern u_int	crtc_addr;
extern char	crtc_type;
extern char	scr_map[];
extern int	scrn_blanked;
extern int	fonts_loaded;
extern char	font_8[], font_14[], font_16[];
extern char	palette[];

#define SAVER_MODULE(name) \
	static int name ## _modevent(module_t mod, int type, void *data) \
	{ \
		switch ((modeventtype_t)type) { \
		case MOD_LOAD: \
			return name ## _load(); \
		case MOD_UNLOAD: \
			return name ## _unload(); \
		default: \
			break; \
		} \
		return 0; \
	} \
	static moduledata_t name ## _mod = { \
		#name, \
		name ## _modevent, \
		NULL \
	}; \
	DECLARE_MODULE(name, name ## _mod, SI_SUB_PSEUDO, SI_ORDER_MIDDLE)
