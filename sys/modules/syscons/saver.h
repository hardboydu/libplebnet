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
 *	$Id: saver.h,v 1.15 1999/01/11 03:18:42 yokota Exp $
 */
#include <machine/apm_bios.h>
#include <machine/console.h>

#include <dev/fb/fbreg.h>
#include <dev/fb/splashreg.h>

#include <dev/syscons/syscons.h>

#define set_video_mode(adp, mode, pal, border)				\
	{								\
		(*vidsw[(adp)->va_index]->set_mode)((adp), (mode));	\
		(*vidsw[(adp)->va_index]->load_palette)((adp), (pal));	\
		(*vidsw[(adp)->va_index]->set_border)((adp), (border));	\
	}
#define get_mode_info(adp, mode, buf)					\
	(*vidsw[(adp)->va_index]->get_info)((adp), (mode), (buf))
#define set_origin(adp, o)						\
	(*vidsw[(adp)->va_index]->set_win_org)(adp, o)
	
extern scr_stat	*cur_console;
extern char	scr_map[];
