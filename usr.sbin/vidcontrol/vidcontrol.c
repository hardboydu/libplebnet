/*-
 * Copyright (c) 1994-1996 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
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
 */

#ifndef lint
static const char rcsid[] =
	"$Id: vidcontrol.c,v 1.23 1998/09/24 01:36:36 gpalmer Exp $";
#endif /* not lint */

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <machine/console.h>
#include <sys/errno.h>
#include "path.h"
#include "decode.h"

char 	legal_colors[16][16] = {
	"black", "blue", "green", "cyan",
	"red", "magenta", "brown", "white",
	"grey", "lightblue", "lightgreen", "lightcyan",
	"lightred", "lightmagenta", "yellow", "lightwhite"
};
int 	hex = 0;
int 	number;
char 	letter;
struct 	vid_info info;


static void
usage()
{
	fprintf(stderr, "%s\n%s\n%s\n",
"usage: vidcontrol [-r fg bg] [-b color] [-c appearance] [-d] [-l scrmap]",
"                  [-i adapter | mode] [-L] [-m on|off] [-f size file]",
"                  [-s number] [-t N|off] [-x] [mode] [fgcol [bgcol]] [show]");
	exit(1);
}

char *
nextarg(int ac, char **av, int *indp, int oc)
{
	if (*indp < ac)
		return(av[(*indp)++]);
	errx(1, "option requires two arguments -- %c", oc);
	return("");
}

char *
mkfullname(const char *s1, const char *s2, const char *s3)
{
	static char *buf = NULL;
	static int bufl = 0;
	int f;

	f = strlen(s1) + strlen(s2) + strlen(s3) + 1;
	if (f > bufl)
		if (buf)
			buf = (char *)realloc(buf, f);
		else
			buf = (char *)malloc(f);
	if (!buf) {
		bufl = 0;
		return(NULL);
	}

	bufl = f;
	strcpy(buf, s1);
	strcat(buf, s2);
	strcat(buf, s3);
	return(buf);
}

void
load_scrnmap(char *filename)
{
	FILE *fd = 0;
	int i, size;
	char *name;
	scrmap_t scrnmap;
	char *prefix[]  = {"", "", SCRNMAP_PATH, SCRNMAP_PATH, NULL};
	char *postfix[] = {"", ".scm", "", ".scm"};

	for (i=0; prefix[i]; i++) {
		name = mkfullname(prefix[i], filename, postfix[i]);
		fd = fopen(name, "r");
		if (fd)
			break;
	}
	if (fd == NULL) {
		warn("screenmap file not found");
		return;
	}
	size = sizeof(scrnmap);
	if (decode(fd, (char *)&scrnmap) != size) {
		rewind(fd);
		if (fread(&scrnmap, 1, size, fd) != size) {
			warnx("bad screenmap file");
			fclose(fd);
			return;
		}
	}
	if (ioctl(0, PIO_SCRNMAP, &scrnmap) < 0)
		warn("can't load screenmap");
	fclose(fd);
}

void
load_default_scrnmap()
{
	scrmap_t scrnmap;
	int i;

	for (i=0; i<256; i++)
		*((char*)&scrnmap + i) = i;
	if (ioctl(0, PIO_SCRNMAP, &scrnmap) < 0)
		warn("can't load default screenmap");
}

void
print_scrnmap()
{
	unsigned char map[256];
	int i;

	if (ioctl(0, GIO_SCRNMAP, &map) < 0) {
		warn("getting screenmap");
		return;
	}
	for (i=0; i<sizeof(map); i++) {
		if (i > 0 && i % 16 == 0)
			fprintf(stdout, "\n");
		if (hex)
			fprintf(stdout, " %02x", map[i]);
		else
			fprintf(stdout, " %03d", map[i]);
	}
	fprintf(stdout, "\n");

}

void
load_font(char *type, char *filename)
{
	FILE	*fd = 0;
	int	i, size;
	unsigned long io;
	char	*name, *fontmap;
	char	*prefix[]  = {"", "", FONT_PATH, FONT_PATH, NULL};
	char	*postfix[] = {"", ".fnt", "", ".fnt"};

	for (i=0; prefix[i]; i++) {
		name = mkfullname(prefix[i], filename, postfix[i]);
		fd = fopen(name, "r");
		if (fd)
			break;
	}
	if (fd == NULL) {
		warn("font file not found");
		return;
	}
	if (!strcmp(type, "8x8")) {
		size = 8*256;
		io = PIO_FONT8x8;
	}
	else if (!strcmp(type, "8x14")) {
		size = 14*256;
		io = PIO_FONT8x14;
	}
	else if (!strcmp(type, "8x16")) {
		size = 16*256;
		io = PIO_FONT8x16;
	}
	else {
		warn("bad font size specification");
		fclose(fd);
		return;
	}
	fontmap = (char*) malloc(size);
	if (decode(fd, fontmap) != size) {
		rewind(fd);
		if (fread(fontmap, 1, size, fd) != size) {
			warnx("bad font file");
			fclose(fd);
			free(fontmap);
			return;
		}
	}
	if (ioctl(0, io, fontmap) < 0)
		warn("can't load font");
	fclose(fd);
	free(fontmap);
}

void
set_screensaver_timeout(char *arg)
{
	int nsec;

	if (!strcmp(arg, "off"))
		nsec = 0;
	else {
		nsec = atoi(arg);
		if ((*arg == '\0') || (nsec < 1)) {
			warnx("argument must be a positive number");
			return;
		}
	}
	if (ioctl(0, CONS_BLANKTIME, &nsec) == -1)
		warn("setting screensaver period");
}

void
set_cursor_type(char *appearence)
{
	int type;

	if (!strcmp(appearence, "normal"))
		type = 0;
	else if (!strcmp(appearence, "blink"))
		type = 1;
	else if (!strcmp(appearence, "destructive"))
		type = 3;
	else {
		warnx("argument to -c must be normal, blink or destructive");
		return;
	}
	ioctl(0, CONS_CURSORTYPE, &type);
}

void
video_mode(int argc, char **argv, int *index)
{
	static struct {
		char *name;
		unsigned long mode;
	} modes[] = {
#ifdef SW_TEXT_80x25
		{ "80x25",		SW_TEXT_80x25 },
		{ "80x30",		SW_TEXT_80x30 },
		{ "80x43",		SW_TEXT_80x43 },
		{ "80x50",		SW_TEXT_80x50 },
		{ "80x60",		SW_TEXT_80x60 },
		{ "132x25",		SW_TEXT_132x25 },
		{ "132x30",		SW_TEXT_132x30 },
		{ "132x43",		SW_TEXT_132x43 },
		{ "132x50",		SW_TEXT_132x50 },
		{ "132x60",		SW_TEXT_132x60 },
#endif
		{ "VGA_40x25",		SW_VGA_C40x25 },
		{ "VGA_80x25",		SW_VGA_C80x25 },
		{ "VGA_80x30",		SW_VGA_C80x30 },
		{ "VGA_80x50",		SW_VGA_C80x50 },
		{ "VGA_80x60",		SW_VGA_C80x60 },
		{ "VGA_320x200",	SW_VGA_CG320 },
		{ "EGA_80x25",		SW_ENH_C80x25 },
		{ "EGA_80x43",		SW_ENH_C80x43 },
		{ "VESA_132x25",	SW_VESA_C132x25 },
		{ "VESA_132x43",	SW_VESA_C132x43 },
		{ "VESA_132x50",	SW_VESA_C132x50 },
		{ "VESA_132x60",	SW_VESA_C132x60 },
		{ "VESA_800x600",	SW_VESA_800x600 },
		{ NULL },
	};
	unsigned long mode;
	int size[3];
	int i;

	if (*index < argc) {
		for (i = 0; modes[i].name != NULL; ++i) {
			if (!strcmp(argv[*index], modes[i].name)) {
				mode = modes[i].mode;
				break;
			}
		}
		if (modes[i].name == NULL)
			return;
		if (ioctl(0, mode, NULL) < 0)
			warn("cannot set videomode");
		if (mode == SW_VESA_800x600) {
			size[0] = 80;	/* columns */
			size[1] = 25;	/* rows */
			size[2] = 16;	/* font size */
			if (ioctl(0, KDRASTER, size))
				warn("cannot activate raster display");
		}
		(*index)++;
	}
	return;
}

int
get_color_number(char *color)
{
	int i;

	for (i=0; i<16; i++)
		if (!strcmp(color, legal_colors[i]))
			return i;
	return -1;
}

void
set_normal_colors(int argc, char **argv, int *index)
{
	int color;

	if (*index < argc && (color = get_color_number(argv[*index])) != -1) {
		(*index)++;
		fprintf(stderr, "[=%dF", color);
		if (*index < argc
		    && (color = get_color_number(argv[*index])) != -1
		    && color < 8) {
			(*index)++;
			fprintf(stderr, "[=%dG", color);
		}
	}
}

void
set_reverse_colors(int argc, char **argv, int *index)
{
	int color;

	if ((color = get_color_number(argv[*(index)-1])) != -1) {
		fprintf(stderr, "[=%dH", color);
		if (*index < argc
		    && (color = get_color_number(argv[*index])) != -1
		    && color < 8) {
			(*index)++;
			fprintf(stderr, "[=%dI", color);
		}
	}
}

void
set_console(char *arg)
{
	int n;

	if( !arg || strspn(arg,"0123456789") != strlen(arg)) {
		warnx("bad console number");
		return;
	}

	n = atoi(arg);
	if (n < 1 || n > 12) {
		warnx("console number out of range");
	} else if (ioctl(0,VT_ACTIVATE,(char *)n) == -1)
		warn("ioctl(VT_ACTIVATE)");
}

void
set_border_color(char *arg)
{
	int color;

	if ((color = get_color_number(arg)) != -1) {
		fprintf(stderr, "[=%dA", color);
	}
	else
		usage();
}

void
set_mouse(char *arg)
{
	struct mouse_info mouse;

	if (!strcmp(arg, "on"))
		mouse.operation = MOUSE_SHOW;
	else if (!strcmp(arg, "off"))
		mouse.operation = MOUSE_HIDE;
	else {
		warnx("argument to -m must either on or off");
		return;
	}
	ioctl(0, CONS_MOUSECTL, &mouse);
}

static char
*adapter_name(int type)
{
    static struct {
	int type;
	char *name;
    } names[] = {
	{ KD_MONO,	"MDA" },
	{ KD_HERCULES,	"Hercules" },
	{ KD_CGA,	"CGA" },
	{ KD_EGA,	"EGA" },
	{ KD_VGA,	"VGA" },
	{ KD_PC98,	"PC-98xx" },
	{ -1,		"Unknown" },
    };
    int i;

    for (i = 0; names[i].type != -1; ++i)
	if (names[i].type == type)
	    break;
    return names[i].name;
}

void
show_adapter_info(void)
{
	struct video_adapter ad;

	ad.va_index = 0;
	if (ioctl(0, CONS_ADPINFO, &ad)) {
		warn("failed to obtain adapter information");
		return;
	}

	printf("adapter %d:\n", ad.va_index);
	printf("    type:%s%s (%d), flags:0x%08x, CRTC:0x%x\n", 
	       (ad.va_flags & V_ADP_VESA) ? "VESA " : "",
	       adapter_name(ad.va_type), ad.va_type, 
	       ad.va_flags, ad.va_crtc_addr);
	printf("    initial mode:%d, current mode:%d, BIOS mode:%d\n",
	       ad.va_initial_mode, ad.va_mode, ad.va_initial_bios_mode);
}

void
show_mode_info(void)
{
	struct video_info info;
	char buf[80];
	int mode;
	int c;

	printf("    mode#     flags   type    size       "
	       "font      window      linear buffer\n");
	printf("---------------------------------------"
	       "---------------------------------------\n");
	for (mode = 0; mode < M_VESA_MODE_MAX; ++mode) {
		info.vi_mode = mode;
		if (ioctl(0, CONS_MODEINFO, &info))
			continue;

		printf("%3d (0x%03x)", mode, mode);
    		printf(" 0x%08x", info.vi_flags);
		if (info.vi_flags & V_INFO_GRAPHICS) {
			c = 'G';
			snprintf(buf, sizeof(buf), "%dx%dx%d %d",
				 info.vi_width, info.vi_height, 
				 info.vi_depth, info.vi_planes);
		} else {
			c = 'T';
			snprintf(buf, sizeof(buf), "%dx%d",
				 info.vi_width, info.vi_height);
		}
		printf(" %c %-15s", c, buf);
		snprintf(buf, sizeof(buf), "%dx%d", 
			 info.vi_cwidth, info.vi_cheight); 
		printf(" %-5s", buf);
    		printf(" 0x%05x %2dk %2dk", 
		       info.vi_window, info.vi_window_size/1024, 
		       info.vi_window_gran/1024);
    		printf(" 0x%08x %2dk\n",
		       info.vi_buffer, info.vi_buffer_size/1024);
	}
}

void
show_info(char *arg)
{
	if (!strcmp(arg, "adapter"))
		show_adapter_info();
	else if (!strcmp(arg, "mode"))
		show_mode_info();
	else {
		warnx("argument to -i must either adapter or mode");
		return;
	}
}

void
test_frame()
{
	int i;

	fprintf(stdout, "[=0G\n\n");
	for (i=0; i<8; i++) {
		fprintf(stdout, "[=15F[=0G        %2d [=%dF%-16s"
				"[=15F[=0G        %2d [=%dF%-16s        "
				"[=15F %2d [=%dGBACKGROUND[=0G\n",
			i, i, legal_colors[i], i+8, i+8,
			legal_colors[i+8], i, i);
	}
	fprintf(stdout, "[=%dF[=%dG[=%dH[=%dI\n",
		info.mv_norm.fore, info.mv_norm.back,
		info.mv_rev.fore, info.mv_rev.back);
}

int
main(int argc, char **argv)
{
	int		opt;


	info.size = sizeof(info);
	if (ioctl(0, CONS_GETINFO, &info) < 0)
		err(1, "must be on a virtual console");
	while((opt = getopt(argc, argv, "b:c:df:i:l:Lm:r:s:t:x")) != -1)
		switch(opt) {
			case 'b':
				set_border_color(optarg);
				break;
			case 'c':
				set_cursor_type(optarg);
				break;
			case 'd':
				print_scrnmap();
				break;
			case 'f':
				load_font(optarg,
					nextarg(argc, argv, &optind, 'f'));
				break;
			case 'i':
				show_info(optarg);
				break;
			case 'l':
				load_scrnmap(optarg);
				break;
			case 'L':
				load_default_scrnmap();
				break;
			case 'm':
				set_mouse(optarg);
				break;
			case 'r':
				set_reverse_colors(argc, argv, &optind);
				break;
			case 's':
				set_console(optarg);
				break;
			case 't':
				set_screensaver_timeout(optarg);
				break;
			case 'x':
				hex = 1;
				break;
			default:
				usage();
		}
	video_mode(argc, argv, &optind);
	set_normal_colors(argc, argv, &optind);
	if (optind < argc && !strcmp(argv[optind], "show")) {
		test_frame();
		optind++;
	}
	if ((optind != argc) || (argc == 1))
		usage();
	return 0;
}

