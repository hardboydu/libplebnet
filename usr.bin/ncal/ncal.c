/*-
 * Copyright (c) 1997 Wolfgang Helbig
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
 */

#ifndef lint
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

#include <calendar.h>
#include <ctype.h>
#include <err.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>
#include <term.h>
#undef lines			/* term.h defines this */

/* Width of one month with backward compatibility and in regular mode*/
#define MONTH_WIDTH_B_J 27
#define MONTH_WIDTH_B 20

#define MONTH_WIDTH_R_J 24
#define MONTH_WIDTH_R 18

#define MAX_WIDTH 64

typedef struct date date;

struct monthlines {
	wchar_t name[MAX_WIDTH + 1];
	char lines[7][MAX_WIDTH + 1];
	char weeks[MAX_WIDTH + 1];
	unsigned int linelen[7];
};

struct weekdays {
	wchar_t names[7][4];
};

/* The switches from Julian to Gregorian in some countries */
static struct djswitch {
	const char *cc;	/* Country code according to ISO 3166 */
	const char *nm;	/* Name of country */
	date dt;	/* Last day of Julian calendar */
} switches[] = {
	{"AL", "Albania",       {1912, 11, 30}},
	{"AT", "Austria",       {1583, 10,  5}},
	{"AU", "Australia",     {1752,  9,  2}},
	{"BE", "Belgium",       {1582, 12, 14}},
	{"BG", "Bulgaria",      {1916,  3, 18}},
	{"CA", "Canada",        {1752,  9,  2}},
	{"CH", "Switzerland",   {1655,  2, 28}},
	{"CN", "China",         {1911, 12, 18}},
	{"CZ", "Czech Republic",{1584,  1,  6}},
	{"DE", "Germany",       {1700,  2, 18}},
	{"DK", "Denmark",       {1700,  2, 18}},
	{"ES", "Spain",         {1582, 10,  4}},
	{"FI", "Finland",       {1753,  2, 17}},
	{"FR", "France",        {1582, 12,  9}},
	{"GB", "United Kingdom",{1752,  9,  2}},
	{"GR", "Greece",        {1924,  3,  9}},
	{"HU", "Hungary",       {1587, 10, 21}},
	{"IS", "Iceland",       {1700, 11, 16}},
	{"IT", "Italy",         {1582, 10,  4}},
	{"JP", "Japan",         {1918, 12, 18}},
	{"LI", "Lithuania",     {1918,  2,  1}},
	{"LN", "Latin",         {9999, 05, 31}},
	{"LU", "Luxembourg",    {1582, 12, 14}},
	{"LV", "Latvia",        {1918,  2,  1}},
	{"NL", "Netherlands",   {1582, 12, 14}},
	{"NO", "Norway",        {1700,  2, 18}},
	{"PL", "Poland",        {1582, 10,  4}},
	{"PT", "Portugal",      {1582, 10,  4}},
	{"RO", "Romania",       {1919,  3, 31}},
	{"RU", "Russia",        {1918,  1, 31}},
	{"SI", "Slovenia",      {1919,  3,  4}},
	{"SW", "Sweden",        {1753,  2, 17}},
	{"TR", "Turkey",        {1926, 12, 18}},
	{"US", "United States", {1752,  9,  2}},
	{"YU", "Yugoslavia",    {1919,  3,  4}}
};

struct djswitch *dftswitch =
    switches + sizeof(switches) / sizeof(struct djswitch) - 2;
    /* default switch (should be "US") */

/* Table used to print day of month and week numbers */
char daystr[] = "     1  2  3  4  5  6  7  8  9 10 11 12 13 14 15"
		" 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31"
		" 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47"
		" 48 49 50 51 52 53";

/* Table used to print day of year and week numbers */
char jdaystr[] = "       1   2   3   4   5   6   7   8   9"
		 "  10  11  12  13  14  15  16  17  18  19"
		 "  20  21  22  23  24  25  26  27  28  29"
		 "  30  31  32  33  34  35  36  37  38  39"
		 "  40  41  42  43  44  45  46  47  48  49"
		 "  50  51  52  53  54  55  56  57  58  59"
		 "  60  61  62  63  64  65  66  67  68  69"
		 "  70  71  72  73  74  75  76  77  78  79"
		 "  80  81  82  83  84  85  86  87  88  89"
		 "  90  91  92  93  94  95  96  97  98  99"
		 " 100 101 102 103 104 105 106 107 108 109"
		 " 110 111 112 113 114 115 116 117 118 119"
		 " 120 121 122 123 124 125 126 127 128 129"
		 " 130 131 132 133 134 135 136 137 138 139"
		 " 140 141 142 143 144 145 146 147 148 149"
		 " 150 151 152 153 154 155 156 157 158 159"
		 " 160 161 162 163 164 165 166 167 168 169"
		 " 170 171 172 173 174 175 176 177 178 179"
		 " 180 181 182 183 184 185 186 187 188 189"
		 " 190 191 192 193 194 195 196 197 198 199"
		 " 200 201 202 203 204 205 206 207 208 209"
		 " 210 211 212 213 214 215 216 217 218 219"
		 " 220 221 222 223 224 225 226 227 228 229"
		 " 230 231 232 233 234 235 236 237 238 239"
		 " 240 241 242 243 244 245 246 247 248 249"
		 " 250 251 252 253 254 255 256 257 258 259"
		 " 260 261 262 263 264 265 266 267 268 269"
		 " 270 271 272 273 274 275 276 277 278 279"
		 " 280 281 282 283 284 285 286 287 288 289"
		 " 290 291 292 293 294 295 296 297 298 299"
		 " 300 301 302 303 304 305 306 307 308 309"
		 " 310 311 312 313 314 315 316 317 318 319"
		 " 320 321 322 323 324 325 326 327 328 329"
		 " 330 331 332 333 334 335 336 337 338 339"
		 " 340 341 342 343 344 345 346 347 348 349"
		 " 350 351 352 353 354 355 356 357 358 359"
		 " 360 361 362 363 364 365 366";

int     flag_weeks;		/* user wants number of week */
int     nswitch;		/* user defined switch date */
int	nswitchb;		/* switch date for backward compatibility */
const char	*term_so, *term_se;
int	today;

char	*center(char *s, char *t, int w);
wchar_t *wcenter(wchar_t *s, wchar_t *t, int w);
void	mkmonthr(int year, int month, int jd_flag, struct monthlines * monthl);
void	mkmonthb(int year, int month, int jd_flag, struct monthlines * monthl);
void	mkweekdays(struct weekdays * wds);
int	parsemonth(const char *s, int *m, int *y);
void	printcc(void);
void	printeaster(int year, int julian, int orthodox);
int	firstday(int y, int m);
date	*sdater(int ndays, struct date * d);
date	*sdateb(int ndays, struct date * d);
int	sndaysr(struct date * d);
int	sndaysb(struct date * d);
static void	usage(void);
void	monthranger(int year, int jd_flag, int m, int before, int after);
void	monthrangeb(int year, int jd_flag, int m, int before, int after);

int
main(int argc, char *argv[])
{
	struct  djswitch *p, *q;	/* to search user defined switch date */
	date	never = {10000, 1, 1};	/* outside valid range of dates */
	date	ukswitch = {1752, 9, 2};/* switch date for Great Britain */
	date	dt;
	int     ch;			/* holds the option character */
	int     m = 0;			/* month */
	int	y = 0;			/* year */
	int     flag_backward = 0;	/* user called cal--backward compat. */
	int     flag_hole_year = 0;	/* user wants the whole year */
	int	flag_julian_cal = 0;	/* user wants Julian Calendar */
	int     flag_julian_day = 0;	/* user wants the Julian day
					 * numbers */
	int	flag_orthodox = 0;	/* use wants Orthodox easter */
	int	flag_easter = 0;	/* use wants easter date */
	char	*cp;			/* character pointer */
	char	*flag_month = NULL;	/* requested month as string */
	char	*flag_highlightdate = NULL;
	int	before, after;
	const char    *locale;		/* locale to get country code */
	char tbuf[1024], cbuf[512], *b;

	/* On how to highlight on this terminal */
	term_se = term_so = NULL;
	if (isatty(STDOUT_FILENO) && tgetent(tbuf, NULL) == 1) {
		b = cbuf;
		term_so = tgetstr("so", &b);
		term_se = tgetstr("se", &b);
	}

	/*
	 * Use locale to determine the country code,
	 * and use the country code to determine the default
	 * switchdate and date format from the switches table.
	 */
	if (setlocale(LC_ALL, "") == NULL)
		warn("setlocale");
	locale = setlocale(LC_TIME, NULL);
	if (locale == NULL ||
	    strcmp(locale, "C") == 0 ||
	    strcmp(locale, "POSIX") == 0 ||
	    strcmp(locale, "ASCII") == 0 ||
	    strcmp(locale, "US-ASCII") == 0)
		locale = "_US";
	q = switches + sizeof(switches) / sizeof(struct djswitch);
	for (p = switches; p != q; p++)
		if ((cp = strstr(locale, p->cc)) != NULL && *(cp - 1) == '_')
			break;
	if (p == q) {
		nswitch = ndaysj(&dftswitch->dt);
	} else {
		nswitch = ndaysj(&p->dt);
		dftswitch = p;
	}


	/*
	 * Get the filename portion of argv[0] and set flag_backward if
	 * this program is called "cal".
	 */
	cp = strrchr(argv[0], '/');
	cp = (cp == NULL) ? argv[0] : cp + 1;
	if (strcmp("cal", cp) == 0)
		flag_backward = 1;

	/* Set the switch date to United Kingdom if backwards compatible */
	if (flag_backward)
		nswitchb = ndaysj(&ukswitch);

	before = after = -1;

	while ((ch = getopt(argc, argv, "A:B:3Jbd:ehjm:ops:wy")) != -1)
		switch (ch) {
		case '3':
			before = after = 1;
			break;
		case 'A':
			after = strtol(optarg, NULL, 10);
			if (after < 0)
				errx(1, "Argument to -A must be positive");
			break;
		case 'B':
			before = strtol(optarg, NULL, 10);
			if (before < 0)
				errx(1, "Argument to -B must be positive");
			break;
		case 'J':
			if (flag_backward)
				usage();
			nswitch = ndaysj(&never);
			flag_julian_cal = 1;
			break;
		case 'b':
			flag_backward = 1;
			break;
		case 'd':
			flag_highlightdate = optarg;
			break;
		case 'h':
			term_so = term_se = NULL;
			break;
		case 'e':
			if (flag_backward)
				usage();
			flag_easter = 1;
			break;
		case 'j':
			flag_julian_day = 1;
			break;
		case 'm':
			flag_month = optarg;
			break;
		case 'o':
			if (flag_backward)
				usage();
			flag_orthodox = 1;
			flag_easter = 1;
			break;
		case 'p':
			if (flag_backward)
				usage();
			printcc();
			return (0);
			break;
		case 's':
			if (flag_backward)
				usage();
			q = switches +
			    sizeof(switches) / sizeof(struct djswitch);
			for (p = switches;
			     p != q && strcmp(p->cc, optarg) != 0; p++)
				;
			if (p == q)
				errx(EX_USAGE,
				    "%s: invalid country code", optarg);
			nswitch = ndaysj(&(p->dt));
			break;
		case 'w':
			if (flag_backward)
				usage();
			flag_weeks = 1;
			break;
		case 'y':
			flag_hole_year = 1;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 2:
		if (flag_easter)
			usage();
		flag_month = *argv++;
		/* FALLTHROUGH */
	case 1:
		y = atoi(*argv++);
		if (y < 1 || y > 9999)
			errx(EX_USAGE, "year %d not in range 1..9999", y);
		before = 0;
		after = 11;
		m = 1;
		break;
	case 0:
		{
			time_t t;
			struct tm *tm;

			t = time(NULL);
			tm = localtime(&t);
			y = tm->tm_year + 1900;
			m = tm->tm_mon + 1;
			if (before == -1)
				before = 0;
			if (after == -1)
				after = 0;
		}
		break;
	default:
		usage();
	}

	if (flag_month != NULL) {
		if (parsemonth(flag_month, &m, &y)) {
			errx(EX_USAGE,
			    "%s is neither a month number (1..12) nor a name",
			    flag_month);
		}
	}

	if (flag_highlightdate != NULL) {
		dt.y = strtol(flag_highlightdate, NULL, 10);
		dt.m = strtol(flag_highlightdate + 5, NULL, 10);
		dt.d = strtol(flag_highlightdate + 8, NULL, 10);
	} else {
		time_t t;
		struct tm *tm1;

		t = time(NULL);
		tm1 = localtime(&t);
		dt.y = tm1->tm_year + 1900;
		dt.m = tm1->tm_mon + 1;
		dt.d = tm1->tm_mday;
	}
	today = sndaysb(&dt);

	if (flag_easter)
		printeaster(y, flag_julian_cal, flag_orthodox);
	else
		if (flag_backward)
			monthrangeb(y, flag_julian_day, m, before, after);
		else
			monthranger(y, flag_julian_day, m, before, after);
	return (0);
}

static void
usage(void)
{

	fputs(
	    "usage: cal [-hjy] [[month] year]\n"
	    "       cal [-hj] [-m month] [year]\n"
	    "       ncal [-hJjpwy] [-s country_code] [[month] year]\n"
	    "       ncal [-hJeo] [year]\n"
	    "for debug the highlighting: [-b] [-d yyyy-mm-dd]\n",
	    stderr);
	exit(EX_USAGE);
}

/* print the assumed switches for all countries */
void
printcc(void)
{
	struct djswitch *p;
	int n;	/* number of lines to print */
	int m;	/* offset from left to right table entry on the same line */

#define FSTR "%c%s %-15s%4d-%02d-%02d"
#define DFLT(p) ((p) == dftswitch ? '*' : ' ')
#define FSTRARG(p) DFLT(p), (p)->cc, (p)->nm, (p)->dt.y, (p)->dt.m, (p)->dt.d

	n = sizeof(switches) / sizeof(struct djswitch);
	m = (n + 1) / 2;
	n /= 2;
	for (p = switches; p != switches + n; p++)
		printf(FSTR"     "FSTR"\n", FSTRARG(p), FSTRARG(p+m));
	if (m != n)
		printf(FSTR"\n", FSTRARG(p));
}

/* print the date of easter sunday */
void
printeaster(int y, int julian, int orthodox)
{
	date    dt;
	struct tm tm;
	char    buf[MAX_WIDTH];
	static int d_first = -1;

	if (d_first < 0)
		d_first = (*nl_langinfo(D_MD_ORDER) == 'd');
	/* force orthodox easter for years before 1583 */
	if (y < 1583)
		orthodox = 1;

	if (orthodox)
		if (julian)
			easteroj(y, &dt);
		else
			easterog(y, &dt);
	else
		easterg(y, &dt);

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = dt.y - 1900;
	tm.tm_mon  = dt.m - 1;
	tm.tm_mday = dt.d;
	strftime(buf, sizeof(buf), d_first ? "%e %B %Y" : "%B %e %Y",  &tm);
	printf("%s\n", buf);
}

#define MW(mw, ms, ml) \
	strlen(ms) > (ml) ? (mw) + 9 : (mw)
#define	DECREASEMONTH(m, y) 		\
		if (--m == 0) {		\
			m = 12;		\
			y--;		\
		}
#define	INCREASEMONTH(m, y)		\
		if (++(m) == 13) {	\
			(m) = 1;	\
			(y)++;		\
		}
#define	M2Y(m)	((m) / 12)
#define	M2M(m)	(1 + (m) % 12) 

void
monthrangeb(int y, int jd_flag, int m, int before, int after)
{
	struct monthlines year[12];
	struct weekdays wds;
	char	s[MAX_WIDTH], t[MAX_WIDTH];
	wchar_t	ws[MAX_WIDTH], ws1[MAX_WIDTH];
	const char	*wdss;
	int     i, j;
	int     mpl;
	int     mw;
	int	m1, m2;
	int	printyearheader;
	int	prevyear = -1;

	mpl = jd_flag ? 2 : 3;
	mw = jd_flag ? MONTH_WIDTH_B_J : MONTH_WIDTH_B;
	wdss = (mpl == 2) ? " " : "";

	while (before != 0) {
		DECREASEMONTH(m, y);
		before--;
		after++;
	}
	m1 = y * 12 + m - 1;
	m2 = m1 + after;

	mkweekdays(&wds);

	/*
	 * The year header is printed when there are more than 'mpl' months
	 * and if the first month is a multitude of 'mpl'.
	 * If not, it will print the year behind every month.
	 */
	printyearheader = (after >= mpl - 1) && (M2M(m1) - 1) % mpl == 0;

	m = m1;
	while (m <= m2) {
		int count = 0;
		for (i = 0; i != mpl && m + i <= m2; i++) {
			mkmonthb(M2Y(m + i), M2M(m + i) - 1, jd_flag, year + i);
			count++;
		}

		/* Empty line between two rows of months */
		if (m != m1)
			printf("\n");

		/* Year at the top */
		if (printyearheader && M2Y(m) != prevyear) {
			sprintf(s, "%d", M2Y(m));
			printf("%s\n", center(t, s, mpl * mw));
			prevyear = M2Y(m);
		}

		/* Month names */
		for (i = 0; i < count; i++)
			if (printyearheader)
				wprintf(L"%-*ls  ",
				    mw, wcenter(ws, year[i].name, mw));
			else {
				swprintf(ws, sizeof(ws), L"%-ls %d",
				    year[i].name, M2Y(m + i));
				wprintf(L"%-*ls  ", mw, wcenter(ws1, ws, mw));
			}
		printf("\n");

		/* Day of the week names */
		for (i = 0; i < count; i++) {
			wprintf(L"%s%ls%s%ls%s%ls%s%ls%s%ls%s%ls%s%ls ",
				wdss, wds.names[6], wdss, wds.names[0],
				wdss, wds.names[1], wdss, wds.names[2],
				wdss, wds.names[3], wdss, wds.names[4],
				wdss, wds.names[5]);
		}
		printf("\n");

		for (i = 0; i != 6; i++) {
			for (j = 0; j < count; j++)
				printf("%-*s  ", mw, year[j].lines[i]+1);
			printf("\n");
		}

		m += mpl;
	}
}

void
monthranger(int y, int jd_flag, int m, int before, int after)
{
	struct monthlines year[12];
	struct weekdays wds;
	char    s[MAX_WIDTH], t[MAX_WIDTH];
	int     i, j;
	int     mpl;
	int     mw;
	int	m1, m2;
	int	prevyear = -1;
	int	printyearheader;

	mpl = jd_flag ? 3 : 4;
	mw = jd_flag ? MONTH_WIDTH_R_J : MONTH_WIDTH_R;

	while (before != 0) {
		DECREASEMONTH(m, y);
		before--;
		after++;
	}
	m1 = y * 12 + m - 1;
	m2 = m1 + after;

	mkweekdays(&wds);

	/*
	 * The year header is printed when there are more than 'mpl' months
	 * and if the first month is a multitude of 'mpl'.
	 * If not, it will print the year behind every month.
	 */
	printyearheader = (after >= mpl - 1) && (M2M(m1) - 1) % mpl == 0;

	m = m1;
	while (m <= m2) {
		int count = 0;
		for (i = 0; i != mpl && m + i <= m2; i++) {
			mkmonthr(M2Y(m + i), M2M(m + i) - 1, jd_flag, year + i);
			count++;
		}

		/* Empty line between two rows of months */
		if (m != m1)
			printf("\n");

		/* Year at the top */
		if (printyearheader && M2Y(m) != prevyear) {
			sprintf(s, "%d", M2Y(m));
			printf("%s\n", center(t, s, mpl * mw));
			prevyear = M2Y(m);
		}

		/* Month names */
		wprintf(L"    ");
		for (i = 0; i < count; i++)
			if (printyearheader)
				wprintf(L"%-*ls", mw, year[i].name);
			else
				wprintf(L"%-ls %-*d", year[i].name,
				    mw - wcslen(year[i].name) - 1, M2Y(m + i));
		printf("\n");

		for (i = 0; i != 7; i++) {
			/* Week day */
			wprintf(L"%.2ls", wds.names[i]);

			/* Full months */
			for (j = 0; j < count; j++)
				printf("%-*s",
				    MW(mw, year[j].lines[i],
					year[j].linelen[i]), year[j].lines[i]);
			printf("\n");
		}

		if (flag_weeks) {
			printf("  ");
			for (i = 0; i < count; i++)
				printf("%-*s", mw, year[i].weeks);
			printf("\n");
		}

		m += mpl;
	}
	return;
}

void
mkmonthr(int y, int m, int jd_flag, struct monthlines *mlines)
{

	struct tm tm;		/* for strftime printing local names of
				 * months */
	date    dt;		/* handy date */
	int     dw;		/* width of numbers */
	int     first;		/* first day of month */
	int     firstm;		/* first day of first week of month */
	int     i, j, k, l;	/* just indices */
	int     last;		/* the first day of next month */
	int     jan1 = 0;	/* the first day of this year */
	char   *ds;		/* pointer to day strings (daystr or
				 * jdaystr) */

	/* Set name of month. */
	memset(&tm, 0, sizeof(tm));
	tm.tm_mon = m;
	wcsftime(mlines->name, sizeof(mlines->name) / sizeof(mlines->name[0]),
		 L"%OB", &tm);
	mlines->name[0] = towupper(mlines->name[0]);

	/*
	 * Set first and last to the day number of the first day of this
	 * month and the first day of next month respectively. Set jan1 to
	 * the day number of the first day of this year.
	 */
	first = firstday(y, m + 1);
	if (m == 11)
		last = firstday(y + 1, 1);
	else
		last = firstday(y, m + 2);

	if (jd_flag)
		jan1 = firstday(y, 1);

	/*
	 * Set firstm to the day number of monday of the first week of
	 * this month. (This might be in the last month)
	 */
	firstm = first - weekday(first);

	/* Set ds (daystring) and dw (daywidth) according to the jd_flag */
	if (jd_flag) {
		ds = jdaystr;
		dw = 4;
	} else {
		ds = daystr;
		dw = 3;
	}

	/*
	 * Fill the lines with day of month or day of year (julian day)
	 * line index: i, each line is one weekday. column index: j, each
	 * column is one day number. print column index: k.
	 */
	for (i = 0; i != 7; i++) {
		l = 0;
		for (j = firstm + i, k = 0; j < last; j += 7, k += dw) {
			if (j == today &&
			    (term_so != NULL && term_se != NULL)) {
				l = strlen(term_so);
				if (jd_flag)
					dt.d = j - jan1 + 1;
				else
					sdateb(j, &dt);
				/* separator */
				mlines->lines[i][k] = ' ';
				/* the actual text */
				memcpy(mlines->lines[i] + k + l,
				    ds + dt.d * dw, dw);
				/* highlight on */
				memcpy(mlines->lines[i] + k + 1, term_so, l);
				/* highlight off */
				memcpy(mlines->lines[i] + k + l + dw, term_se,
				    strlen(term_se));
				l = strlen(term_se) + strlen(term_so);
				continue;
			}
			if (j >= first) {
				if (jd_flag)
					dt.d = j - jan1 + 1;
				else
					sdater(j, &dt);
				memcpy(mlines->lines[i] + k + l,
				       ds + dt.d * dw, dw);
			} else
				memcpy(mlines->lines[i] + k + l, "    ", dw);
		}
		mlines->lines[i][k + l] = '\0';
		mlines->linelen[i] = k;
	}

	/* fill the weeknumbers */
	if (flag_weeks) {
		for (j = firstm, k = 0; j < last;  k += dw, j += 7)
			if (j <= nswitch)
				memset(mlines->weeks + k, ' ', dw);
			else
				memcpy(mlines->weeks + k,
				    ds + week(j, &i)*dw, dw);
		mlines->weeks[k] = '\0';
	}
}

void
mkmonthb(int y, int m, int jd_flag, struct monthlines *mlines)
{

	struct tm tm;		/* for strftime printing local names of
				 * months */
	date    dt;		/* handy date */
	int     dw;		/* width of numbers */
	int     first;		/* first day of month */
	int     firsts;		/* sunday of first week of month */
	int     i, j, k, l;	/* just indices */
	int     jan1 = 0;	/* the first day of this year */
	int     last;		/* the first day of next month */
	char   *ds;		/* pointer to day strings (daystr or
				 * jdaystr) */

	/* Set ds (daystring) and dw (daywidth) according to the jd_flag */
	if (jd_flag) {
		ds = jdaystr;
		dw = 4;
	} else {
		ds = daystr;
		dw = 3;
	}

	/* Set name of month centered */
	memset(&tm, 0, sizeof(tm));
	tm.tm_mon = m;
	wcsftime(mlines->name, sizeof(mlines->name) / sizeof(mlines->name[0]),
		 L"%OB", &tm);
	mlines->name[0] = towupper(mlines->name[0]);

	/*
	 * Set first and last to the day number of the first day of this
	 * month and the first day of next month respectively. Set jan1 to
	 * the day number of Jan 1st of this year.
	 */
	dt.y = y;
	dt.m = m + 1;
	dt.d = 1;
	first = sndaysb(&dt);
	if (m == 11) {
		dt.y = y + 1;
		dt.m = 1;
		dt.d = 1;
	} else {
		dt.y = y;
		dt.m = m + 2;
		dt.d = 1;
	}
	last = sndaysb(&dt);

	if (jd_flag) {
		dt.y = y;
		dt.m = 1;
		dt.d = 1;
		jan1 = sndaysb(&dt);
	}

	/*
	 * Set firsts to the day number of sunday of the first week of
	 * this month. (This might be in the last month)
	 */
	firsts = first - (weekday(first)+1) % 7;

	/*
	 * Fill the lines with day of month or day of year (Julian day)
	 * line index: i, each line is one week. column index: j, each
	 * column is one day number. print column index: k.
	 */
	for (i = 0; i != 6; i++) {
		l = 0;
		for (j = firsts + 7 * i, k = 0; j < last && k != dw * 7;
		    j++, k += dw) { 
			if (j == today &&
			    (term_so != NULL && term_se != NULL)) {
				l = strlen(term_so);
				if (jd_flag)
					dt.d = j - jan1 + 1;
				else
					sdateb(j, &dt);
				/* separator */
				mlines->lines[i][k] = ' ';
				/* the actual text */
				memcpy(mlines->lines[i] + k + l,
				    ds + dt.d * dw, dw);
				/* highlight on */
				memcpy(mlines->lines[i] + k + 1, term_so, l);
				/* highlight off */
				memcpy(mlines->lines[i] + k + l + dw, term_se,
				    strlen(term_se));
				l = strlen(term_se) + strlen(term_so);
				continue;
			}
			if (j >= first) {
				if (jd_flag)
					dt.d = j - jan1 + 1;
				else
					sdateb(j, &dt);
				memcpy(mlines->lines[i] + k + l,
				       ds + dt.d * dw, dw);
			} else
				memcpy(mlines->lines[i] + k + l, "    ", dw);
		}
		if (k == 0)
			mlines->lines[i][1] = '\0';
		else
			mlines->lines[i][k + l] = '\0';
	}
}

/* Put the local names of weekdays into the wds */
void
mkweekdays(struct weekdays *wds)
{
	int i, len, width = 0;
	struct tm tm;
	wchar_t buf[20];

	memset(&tm, 0, sizeof(tm));

	for (i = 0; i != 7; i++) {
		tm.tm_wday = (i+1) % 7;
		wcsftime(buf, sizeof(buf), L"%a", &tm);
		for (len = 2; len > 0; --len) {
			if ((width = wcswidth(buf, len)) <= 2)
				break;
		}
		wmemset(wds->names[i], L'\0', 4);
		if (width == 1)
			wds->names[i][0] = L' ';
		wcsncat(wds->names[i], buf, len);
		wcsncat(wds->names[i], L" ", 1);
	}
}

/*
 * Compute the day number of the first
 * existing date after the first day in month.
 * (the first day in month and even the month might not exist!)
 */
int
firstday(int y, int m)
{
	date dt;
	int nd;

	dt.y = y;
	dt.m = m;
	dt.d = 1;
	nd = sndaysr(&dt);
	for (;;) {
		sdater(nd, &dt);
		if ((dt.m >= m && dt.y == y) || dt.y > y)
			return (nd);
		else
			nd++;
	}
	/* NEVER REACHED */
}

/*
 * Compute the number of days from date, obey the local switch from
 * Julian to Gregorian if specified by the user.
 */
int
sndaysr(struct date *d)
{

	if (nswitch != 0)
		if (nswitch < ndaysj(d))
			return (ndaysg(d));
		else
			return (ndaysj(d));
	else
		return ndaysg(d);
}

/*
 * Compute the number of days from date, obey the switch from
 * Julian to Gregorian as used by UK and her colonies.
 */
int
sndaysb(struct date *d)
{

	if (nswitchb < ndaysj(d))
		return (ndaysg(d));
	else
		return (ndaysj(d));
}

/* Inverse of sndays */
struct date *
sdater(int nd, struct date *d)
{

	if (nswitch < nd)
		return (gdate(nd, d));
	else
		return (jdate(nd, d));
}

/* Inverse of sndaysb */
struct date *
sdateb(int nd, struct date *d)
{

	if (nswitchb < nd)
		return (gdate(nd, d));
	else
		return (jdate(nd, d));
}

/* Center string t in string s of length w by putting enough leading blanks */
char *
center(char *s, char *t, int w)
{
	char blanks[MAX_WIDTH];

	memset(blanks, ' ', sizeof(blanks));
	sprintf(s, "%.*s%s", (int)(w - strlen(t)) / 2, blanks, t);
	return (s);
}

/* Center string t in string s of length w by putting enough leading blanks */
wchar_t *
wcenter(wchar_t *s, wchar_t *t, int w)
{
	char blanks[MAX_WIDTH];

	memset(blanks, ' ', sizeof(blanks));
	swprintf(s, MAX_WIDTH, L"%.*s%ls", (int)(w - wcslen(t)) / 2, blanks, t);
	return (s);
}

int
parsemonth(const char *s, int *m, int *y)
{
	int nm, ny;
	char *cp;
	struct tm tm;

	nm = (int)strtol(s, &cp, 10);
	if (cp != s) {
		ny = *y;
		if (*cp == '\0') {
			;	/* no special action */
		} else if (*cp == 'f' || *cp == 'F') {
			if (nm <= *m)
				ny++;
		} else if (*cp == 'p' || *cp == 'P') {
			if (nm >= *m)
				ny--;
		} else
			return (1);
		if (nm < 1 || nm > 12)
			return 1;
		*m = nm;
		*y = ny;
		return (0);
	}
	if (strptime(s, "%B", &tm) != NULL || strptime(s, "%b", &tm) != NULL) {
		*m = tm.tm_mon + 1;
		return (0);
	}
	return (1);
}
