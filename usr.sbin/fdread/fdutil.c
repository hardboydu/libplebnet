/*
 * Copyright (c) 2001 Joerg Wunsch
 *
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
 * THIS SOFTWARE IS PROVIDED BY THE DEVELOPERS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE DEVELOPERS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <dev/ic/nec765.h>

#include <sys/fdcio.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "fdutil.h"

/*
 * Decode the FDC status pointed to by `fdcsp', and print a textual
 * translation to stderr.  If `terse' is false, the numerical FDC
 * register status is printed, too.
 */
void
printstatus(struct fdc_status *fdcsp, int terse)
{
	char msgbuf[100];

	if (!terse)
		fprintf(stderr,
		"\nFDC status ST0=%#x ST1=%#x ST2=%#x C=%u H=%u R=%u N=%u:\n",
			fdcsp->status[0] & 0xff,
			fdcsp->status[1] & 0xff,
			fdcsp->status[2] & 0xff,
			fdcsp->status[3] & 0xff,
			fdcsp->status[4] & 0xff,
			fdcsp->status[5] & 0xff,
			fdcsp->status[6] & 0xff);

	if ((fdcsp->status[0] & NE7_ST0_IC_RC) != NE7_ST0_IC_AT) {
		sprintf(msgbuf, "unexcpted interrupt code %#x",
			fdcsp->status[0] & NE7_ST0_IC_RC);
	} else {
		strcpy(msgbuf, "unexpected error code in ST1/ST2");

		if (fdcsp->status[1] & NE7_ST1_EN)
			strcpy(msgbuf, "end of cylinder (wrong format)");
		else if (fdcsp->status[1] & NE7_ST1_DE) {
			if (fdcsp->status[2] & NE7_ST2_DD)
				strcpy(msgbuf, "CRC error in data field");
			else
				strcpy(msgbuf, "CRC error in ID field");
		} else if (fdcsp->status[1] & NE7_ST1_MA) {
			if (fdcsp->status[2] & NE7_ST2_MD)
				strcpy(msgbuf, "no address mark in data field");
			else
				strcpy(msgbuf, "no address mark in ID field");
		} else if (fdcsp->status[2] & NE7_ST2_WC)
			strcpy(msgbuf, "wrong cylinder (format mismatch)");
		else if (fdcsp->status[1] & NE7_ST1_ND)
			strcpy(msgbuf, "no data (sector not found)");
	}
	fputs(msgbuf, stderr);
}

static struct fd_type fd_types_auto[1];

#ifdef PC98

static struct fd_type fd_types_12m[] = {
{ 15,2,0xFF,0x1B,80,2400,0,2,0x54,1,0,FL_MFM },	/* 1.2M */
#if 0
{ 10,2,0xFF,0x10,82,1640,1,2,0x30,1,0,FL_MFM },	/* 820K */
{ 10,2,0xFF,0x10,80,1600,1,2,0x30,1,0,FL_MFM },	/* 800K */
#endif
{  9,2,0xFF,0x20,80,1440,1,2,0x50,1,0,FL_MFM },	/* 720K */
{  9,2,0xFF,0x20,40, 720,1,2,0x50,1,0,FL_MFM|FL_2STEP },/* 360K */
{  8,2,0xFF,0x2A,80,1280,1,2,0x50,1,0,FL_MFM },	/* 640K */
{  8,3,0xFF,0x35,77,1232,0,2,0x74,1,0,FL_MFM },	/* 1.23M 1024/sec */
#if 0
{  8,3,0xFF,0x35,80,1280,0,2,0x74,1,0,FL_MFM },	/* 1.28M 1024/sec */
#endif
};

static struct fd_type fd_types_144m[] = {
#if 0
{ 21,2,0xFF,0x04,82,3444,2,2,0x0C,2,0,FL_MFM },	/* 1.72M in 3mode */
{ 18,2,0xFF,0x1B,82,2952,2,2,0x54,1,0,FL_MFM },	/* 1.48M in 3mode */
#endif
{ 18,2,0xFF,0x1B,80,2880,2,2,0x54,1,0,FL_MFM },	/* 1.44M in 3mode */
{ 15,2,0xFF,0x1B,80,2400,0,2,0x54,1,0,FL_MFM },	/* 1.2M */
#if 0
{ 10,2,0xFF,0x10,82,1640,1,2,0x30,1,0,FL_MFM },	/* 820K */
{ 10,2,0xFF,0x10,80,1600,1,2,0x30,1,0,FL_MFM },	/* 800K */
#endif
{  9,2,0xFF,0x20,80,1440,1,2,0x50,1,0,FL_MFM },	/* 720K */
{  9,2,0xFF,0x20,40, 720,1,2,0x50,1,0,FL_MFM|FL_2STEP },/* 360K */
{  8,2,0xFF,0x2A,80,1280,1,2,0x50,1,0,FL_MFM },	/* 640K */
{  8,3,0xFF,0x35,77,1232,0,2,0x74,1,0,FL_MFM },	/* 1.23M 1024/sec */
#if 0
{  8,3,0xFF,0x35,80,1280,0,2,0x74,1,0,FL_MFM },	/* 1.28M 1024/sec */
{  9,3,0xFF,0x35,82,1476,0,2,0x47,1,0,FL_MFM },	/* 1.48M 1024/sec 9sec */
{ 10,3,0xFF,0x1B,82,1640,2,2,0x54,1,0,FL_MFM },	/* 1.64M in 3mode - Reserve */
#endif
};

#else /* PC98 */

static struct fd_type fd_types_288m[] =
{
#if 0
{ 36,2,0xFF,0x1B,80,5760,FDC_1MBPS,  2,0x4C,1,1,FL_MFM|FL_PERPND } /*2.88M*/
#endif
{ 21,2,0xFF,0x04,82,3444,FDC_500KBPS,2,0x0C,2,0,FL_MFM }, /* 1.72M */
{ 18,2,0xFF,0x1B,82,2952,FDC_500KBPS,2,0x6C,1,0,FL_MFM }, /* 1.48M */
{ 18,2,0xFF,0x1B,80,2880,FDC_500KBPS,2,0x6C,1,0,FL_MFM }, /* 1.44M */
{ 15,2,0xFF,0x1B,80,2400,FDC_500KBPS,2,0x54,1,0,FL_MFM }, /*  1.2M */
{ 10,2,0xFF,0x10,82,1640,FDC_250KBPS,2,0x2E,1,0,FL_MFM }, /*  820K */
{ 10,2,0xFF,0x10,80,1600,FDC_250KBPS,2,0x2E,1,0,FL_MFM }, /*  800K */
{  9,2,0xFF,0x20,80,1440,FDC_250KBPS,2,0x50,1,0,FL_MFM }, /*  720K */
};

static struct fd_type fd_types_144m[] =
{
{ 21,2,0xFF,0x04,82,3444,FDC_500KBPS,2,0x0C,2,0,FL_MFM }, /* 1.72M */
{ 18,2,0xFF,0x1B,82,2952,FDC_500KBPS,2,0x6C,1,0,FL_MFM }, /* 1.48M */
{ 18,2,0xFF,0x1B,80,2880,FDC_500KBPS,2,0x6C,1,0,FL_MFM }, /* 1.44M */
{ 15,2,0xFF,0x1B,80,2400,FDC_500KBPS,2,0x54,1,0,FL_MFM }, /*  1.2M */
{ 10,2,0xFF,0x10,82,1640,FDC_250KBPS,2,0x2E,1,0,FL_MFM }, /*  820K */
{ 10,2,0xFF,0x10,80,1600,FDC_250KBPS,2,0x2E,1,0,FL_MFM }, /*  800K */
{  9,2,0xFF,0x20,80,1440,FDC_250KBPS,2,0x50,1,0,FL_MFM }, /*  720K */
};

static struct fd_type fd_types_12m[] =
{
{ 15,2,0xFF,0x1B,80,2400,FDC_500KBPS,2,0x54,1,0,FL_MFM }, /*  1.2M */
{  8,3,0xFF,0x35,77,1232,FDC_500KBPS,2,0x74,1,0,FL_MFM }, /* 1.23M */
{ 18,2,0xFF,0x02,82,2952,FDC_500KBPS,2,0x02,2,0,FL_MFM }, /* 1.48M */
{ 18,2,0xFF,0x02,80,2880,FDC_500KBPS,2,0x02,2,0,FL_MFM }, /* 1.44M */
{ 10,2,0xFF,0x10,82,1640,FDC_300KBPS,2,0x2E,1,0,FL_MFM }, /*  820K */
{ 10,2,0xFF,0x10,80,1600,FDC_300KBPS,2,0x2E,1,0,FL_MFM }, /*  800K */
{  9,2,0xFF,0x20,80,1440,FDC_300KBPS,2,0x50,1,0,FL_MFM }, /*  720K */
{  9,2,0xFF,0x23,40, 720,FDC_300KBPS,2,0x50,1,0,FL_MFM|FL_2STEP }, /* 360K */
{  8,2,0xFF,0x2A,80,1280,FDC_300KBPS,2,0x50,1,0,FL_MFM }, /*  640K */
};

static struct fd_type fd_types_720k[] =
{
{  9,2,0xFF,0x20,80,1440,FDC_250KBPS,2,0x50,1,0,FL_MFM }, /*  720K */
};

static struct fd_type fd_types_360k[] =
{
{  9,2,0xFF,0x2A,40, 720,FDC_250KBPS,2,0x50,1,0,FL_MFM }, /*  360K */
};

#endif /* PC98 */

/*
 * Parse a format string, and fill in the parameter pointed to by `out'.
 *
 * sectrac,secsize,datalen,gap,ncyls,speed,heads,f_gap,f_inter,offs2,flags[...]
 *
 * sectrac = sectors per track
 * secsize = sector size in bytes
 * datalen = length of sector if secsize == 128
 * gap     = gap length when reading
 * ncyls   = number of cylinders
 * speed   = transfer speed 250/300/500/1000 KB/s
 * heads   = number of heads
 * f_gap   = gap length when formatting
 * f_inter = sector interleave when formatting
 * offs2   = offset of sectors on side 2
 * flags   = +/-mfm | +/-2step | +/-perpend
 *             mfm - use MFM recording
 *             2step - use 2 steps between cylinders
 *             perpend - user perpendicular (vertical) recording
 *
 * Any omitted value will be passed on from parameter `in'.
 */
void
parse_fmt(const char *s, enum fd_drivetype type,
	  struct fd_type in, struct fd_type *out)
{
	int i, j;
	const char *cp;
	char *s1;

	*out = in;

	for (i = 0;; i++) {
		if (s == 0)
			break;

		if ((cp = strchr(s, ',')) == 0) {
			s1 = strdup(s);
			if (s1 == NULL)
				abort();
			s = 0;
		} else {
			s1 = malloc(cp - s + 1);
			if (s1 == NULL)
				abort();
			memcpy(s1, s, cp - s);
			s1[cp - s] = 0;

			s = cp + 1;
		}
		if (strlen(s1) == 0) {
			free(s1);
			continue;
		}

		switch (i) {
		case 0:		/* sectrac */
			if (getnum(s1, &out->sectrac))
				errx(EX_USAGE,
				     "bad numeric value for sectrac: %s", s1);
			break;

		case 1:		/* secsize */
			if (getnum(s1, &j))
				errx(EX_USAGE,
				     "bad numeric value for secsize: %s", s1);
			if (j == 128) out->secsize = 0;
			else if (j == 256) out->secsize = 1;
			else if (j == 512) out->secsize = 2;
			else if (j == 1024) out->secsize = 3;
			else
				errx(EX_USAGE, "bad sector size %d", j);
			break;

		case 2:		/* datalen */
			if (getnum(s1, &j))
				errx(EX_USAGE,
				     "bad numeric value for datalen: %s", s1);
			if (j >= 256)
				errx(EX_USAGE, "bad datalen %d", j);
			out->datalen = j;
			break;

		case 3:		/* gap */
			if (getnum(s1, &out->gap))
				errx(EX_USAGE,
				     "bad numeric value for gap: %s", s1);
			break;

		case 4:		/* ncyls */
			if (getnum(s1, &j))
				errx(EX_USAGE,
				     "bad numeric value for ncyls: %s", s1);
			if (j > 85)
				errx(EX_USAGE, "bad # of cylinders %d", j);
			out->tracks = j;
			break;

		case 5:		/* speed */
			if (getnum(s1, &j))
				errx(EX_USAGE,
				     "bad numeric value for speed: %s", s1);
			switch (type) {
			default:
				abort(); /* paranoia */

#ifndef PC98
			case FDT_360K:
			case FDT_720K:
				if (j == 250)
					out->trans = FDC_250KBPS;
				else
					errx(EX_USAGE, "bad speed %d", j);
				break;
#endif

			case FDT_12M:
				if (j == 300)
					out->trans = FDC_300KBPS;
				else if (j == 500)
					out->trans = FDC_500KBPS;
				else
					errx(EX_USAGE, "bad speed %d", j);
				break;

#ifndef PC98
			case FDT_288M:
				if (j == 1000)
					out->trans = FDC_1MBPS;
				/* FALLTHROUGH */
#endif
			case FDT_144M:
				if (j == 250)
					out->trans = FDC_250KBPS;
				else if (j == 500)
					out->trans = FDC_500KBPS;
				else
					errx(EX_USAGE, "bad speed %d", j);
				break;
			}
			break;

		case 6:		/* heads */
			if (getnum(s1, &j))
				errx(EX_USAGE,
				     "bad numeric value for heads: %s", s1);
			if (j == 1 || j == 2)
				out->heads = j;
			else
				errx(EX_USAGE, "bad # of heads %d", j);
			break;

		case 7:		/* f_gap */
			if (getnum(s1, &out->f_gap))
				errx(EX_USAGE,
				     "bad numeric value for f_gap: %s", s1);
			break;

		case 8:		/* f_inter */
			if (getnum(s1, &out->f_inter))
				errx(EX_USAGE,
				     "bad numeric value for f_inter: %s", s1);
			break;

		case 9:		/* offs2 */
			if (getnum(s1, &out->offset_side2))
				errx(EX_USAGE,
				     "bad numeric value for offs2: %s", s1);
			break;

		default:
			if (strcmp(s1, "+mfm") == 0)
				out->flags |= FL_MFM;
			else if (strcmp(s1, "-mfm") == 0)
				out->flags &= ~FL_MFM;
			else if (strcmp(s1, "+2step") == 0)
				out->flags |= FL_2STEP;
			else if (strcmp(s1, "-2step") == 0)
				out->flags &= ~FL_2STEP;
			else if (strcmp(s1, "+perpnd") == 0)
				out->flags |= FL_PERPND;
			else if (strcmp(s1, "-perpnd") == 0)
				out->flags &= ~FL_PERPND;
			else
				errx(EX_USAGE, "bad flag: %s", s1);
			break;
		}
		free(s1);
	}

	out->size = out->tracks * out->heads * out->sectrac;
}

/*
 * Print a textual translation of the drive (density) type described
 * by `in' to stdout.  The string uses the same form that is parseable
 * by parse_fmt().
 */
void
print_fmt(struct fd_type in)
{
	int secsize, speed;

	secsize = 128 << in.secsize;
	switch (in.trans) {
	case FDC_250KBPS:	speed = 250; break;
	case FDC_300KBPS:	speed = 300; break;
	case FDC_500KBPS:	speed = 500; break;
	case FDC_1MBPS:		speed = 1000; break;
	default:		speed = 1; break;
	}

	printf("%d,%d,%#x,%#x,%d,%d,%d,%#x,%d,%d",
	       in.sectrac, secsize, in.datalen, in.gap, in.tracks,
	       speed, in.heads, in.f_gap, in.f_inter, in.offset_side2);
	if (in.flags & FL_MFM)
		printf(",+mfm");
	if (in.flags & FL_2STEP)
		printf(",+2step");
	if (in.flags & FL_PERPND)
		printf(",+perpnd");
	putc('\n', stdout);
}

/*
 * Based on `size' (in kilobytes), walk through the table of known
 * densities for drive type `type' and see if we can find one.  If
 * found, return it (as a pointer to static storage), otherwise return
 * NULL.
 */
struct fd_type *
get_fmt(int size, enum fd_drivetype type)
{
	int i, n;
	struct fd_type *fdtp;

	switch (type) {
	default:
		return (0);

#ifndef PC98
	case FDT_360K:
		fdtp = fd_types_360k;
		n = sizeof fd_types_360k / sizeof(struct fd_type);
		break;

	case FDT_720K:
		fdtp = fd_types_720k;
		n = sizeof fd_types_720k / sizeof(struct fd_type);
		break;
#endif

	case FDT_12M:
		fdtp = fd_types_12m;
		n = sizeof fd_types_12m / sizeof(struct fd_type);
		break;

	case FDT_144M:
		fdtp = fd_types_144m;
		n = sizeof fd_types_144m / sizeof(struct fd_type);
		break;

#ifndef PC98
	case FDT_288M:
		fdtp = fd_types_288m;
		n = sizeof fd_types_288m / sizeof(struct fd_type);
		break;
#endif
	}

	if (size == -1)
		return fd_types_auto;

	for (i = 0; i < n; i++, fdtp++)
#ifdef PC98
		if (((128 << fdtp->secsize) * fdtp->size / 1024) == size)
			return (fdtp);
#else
		if (fdtp->size / 2 == size)
			return (fdtp);
#endif

	return (0);
}

/*
 * Parse a number from `s'.  If the string cannot be converted into a
 * number completely, return -1, otherwise 0.  The result is returned
 * in `*res'.
 */
int
getnum(const char *s, int *res)
{
	unsigned long ul;
	char *cp;

	ul = strtoul(s, &cp, 0);
	if (*cp != '\0')
	  return (-1);

	*res = (int)ul;
	return (0);
}

/*
 * Return a short name and a verbose description for the drive
 * described by `t'.
 */
void
getname(enum fd_drivetype t, const char **name, const char **descr)
{

	switch (t) {
	default:
		*name = "unknown";
		*descr = "unknown drive type";
		break;

#ifndef PC98
	case FDT_360K:
		*name = "360K";
		*descr = "5.25\" double-density";
		break;
#endif

	case FDT_12M:
		*name = "1.2M";
		*descr = "5.25\" high-density";
		break;

#ifndef PC98
	case FDT_720K:
		*name = "720K";
		*descr = "3.5\" double-density";
		break;
#endif

	case FDT_144M:
		*name = "1.44M";
		*descr = "3.5\" high-density";
		break;

#ifndef PC98
	case FDT_288M:
		*name = "2.88M";
		*descr = "3.5\" extra-density";
		break;
#endif
	}
}
