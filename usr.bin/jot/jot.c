/*-
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)jot.c	8.1 (Berkeley) 6/6/93";
#endif
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

/*
 * jot - print sequential or random data
 *
 * Author:  John Kunze, Office of Comp. Affairs, UCB
 */

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	REPS_DEF	100
#define	BEGIN_DEF	1
#define	ENDER_DEF	100
#define	STEP_DEF	1

#define	isdefault(s)	(strcmp((s), "-") == 0)

double	begin;
double	ender;
double	s;
long	reps;
int	randomize;
int	infinity;
int	boring;
int	prec;
int	intdata;
int	chardata;
int	nosign;
int	nofinalnl;
int	oflowlen;
char	*oflowstr;
char	*sepstring = "\n";
char	format[BUFSIZ];
struct sigaction act, oact;

void	arith_oflow __P((int));
void	getargs __P((int, char *[]));
void	getformat __P((void));
int		getprec __P((char *));
void	putdata __P((double, long));
static void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	double	xd, yd;
	long	id;
	register double	*x = &xd;
	register double	*y = &yd;
	register long	*i = &id;

	act.sa_handler = arith_oflow;
	act.sa_flags = 0;
	sigfillset(&act.sa_mask);
	oflowstr = "caught SIGFPE: arithmetic overflow\n";
	oflowlen = strlen(oflowstr);
	if (sigaction(SIGFPE, &act, &oact))
		err(1, "loading SIGFPE handler");
	getargs(argc, argv);
	if (randomize) {
		*x = (ender - begin) * (ender > begin ? 1 : -1);
		for (*i = 1; *i <= reps || infinity; (*i)++) {
			*y = (double) arc4random() / ULONG_MAX;
			putdata(*y * *x + begin, reps - *i);
		}
	} else
		for (*i = 1, *x = begin; *i <= reps || infinity; (*i)++, *x += s)
			putdata(*x, reps - *i);
	if (!nofinalnl)
		putchar('\n');
	exit(0);
}

void
getargs(ac, av)
	int ac;
	char *av[];
{
	register unsigned int	mask = 0;
	register int		n = 0;

	while (--ac && **++av == '-' && !isdefault(*av))
		switch ((*av)[1]) {
		case 'r':
			randomize = 1;
			break;
		case 'c':
			chardata = 1;
			break;
		case 'n':
			nofinalnl = 1;
			break;
		case 'b':
			boring = 1;
		case 'w':
			if ((*av)[2])
				strcpy(format, *av + 2);
			else if (!--ac)
				errx(1, "need context word after -w or -b");
			else
				strcpy(format, *++av);
			break;
		case 's':
			if ((*av)[2])
				sepstring = *av + 2;
			else if (!--ac)
				errx(1, "need string after -s");
			else
				sepstring = *++av;
			break;
		case 'p':
			if ((*av)[2])
				prec = atoi(*av + 2);
			else if (!--ac)
				errx(1, "need number after -p");
			else
				prec = atoi(*++av);
			if (prec <= 0)
				errx(1, "bad precision value");
			break;
		default:
			usage();
		}

	switch (ac) {	/* examine args right to left, falling thru cases */
	case 4:
		if (!isdefault(av[3])) {
			if (!sscanf(av[3], "%lf", &s))
				errx(1, "bad s value: %s", av[3]);
			mask |= 01;
		}
	case 3:
		if (!isdefault(av[2])) {
			if (!sscanf(av[2], "%lf", &ender))
				ender = av[2][strlen(av[2])-1];
			mask |= 02;
			if (!prec)
				n = getprec(av[2]);
		}
	case 2:
		if (!isdefault(av[1])) {
			if (!sscanf(av[1], "%lf", &begin))
				begin = av[1][strlen(av[1])-1];
			mask |= 04;
			if (!prec)
				prec = getprec(av[1]);
			if (n > prec)		/* maximum precision */
				prec = n;
		}
	case 1:
		if (!isdefault(av[0])) {
			if (!sscanf(av[0], "%ld", &reps))
				errx(1, "bad reps value: %s", av[0]);
			mask |= 010;
		}
		break;
	case 0:
		usage();
	default:
		errx(1, "too many arguments. What do you mean by %s?", av[4]);
	}
	getformat();
	while (mask)	/* 4 bit mask has 1's where last 4 args were given */
		switch (mask) {	/* fill in the 0's by default or computation */
		case 001:
			reps = REPS_DEF;
			mask = 011;
			break;
		case 002:
			reps = REPS_DEF;
			mask = 012;
			break;
		case 003:
			reps = REPS_DEF;
			mask = 013;
			break;
		case 004:
			reps = REPS_DEF;
			mask = 014;
			break;
		case 005:
			reps = REPS_DEF;
			mask = 015;
			break;
		case 006:
			reps = REPS_DEF;
			mask = 016;
			break;
		case 007:
			if (randomize) {
				reps = REPS_DEF;
				mask = 0;
				break;
			}
			if (s == 0.0) {
				reps = 0;
				mask = 0;
				break;
			}
			reps = (ender - begin + s) / s;
			if (reps <= 0)
				errx(1, "impossible stepsize");
			mask = 0;
			break;
		case 010:
			begin = BEGIN_DEF;
			mask = 014;
			break;
		case 011:
			begin = BEGIN_DEF;
			mask = 015;
			break;
		case 012:
			s = (randomize ? -1.0 : STEP_DEF);
			mask = 013;
			break;
		case 013:
			if (randomize)
				begin = BEGIN_DEF;
			else if (reps == 0)
				errx(1, "must specify begin if reps == 0");
			else
				begin = ender - reps * s + s;
			mask = 0;
			break;
		case 014:
			s = (randomize ? -1.0 : STEP_DEF);
			mask = 015;
			break;
		case 015:
			if (randomize)
				ender = ENDER_DEF;
			else
				ender = begin + reps * s - s;
			mask = 0;
			break;
		case 016:
			if (randomize)
				s = -1.0;
			else if (reps == 0)
				errx(1, "infinite sequences cannot be bounded");
			else if (reps == 1)
				s = 0.0;
			else
				s = (ender - begin) / (reps - 1);
			mask = 0;
			break;
		case 017:		/* if reps given and implied, */
			if (!randomize && s != 0.0) {
				long t = (ender - begin + s) / s;
				if (t <= 0)
					errx(1, "impossible stepsize");
				if (t < reps)		/* take lesser */
					reps = t;
			}
			mask = 0;
			break;
		default:
			errx(1, "bad mask");
		}
	if (reps == 0)
		infinity = 1;
}

void
putdata(x, notlast)
	double x;
	long notlast;
{

	if (boring)				/* repeated word */
		printf(format);
	else if (chardata)			/* character representation */
		printf(format, (int)x);
	else if (intdata && nosign)		/* scalar */
		printf(format, (unsigned long)x);
	else if (intdata)
		printf(format, (long)x);
	else					/* real */
		printf(format, x);
	if (notlast != 0)
		fputs(sepstring, stdout);
}

static void
usage()
{
	fprintf(stderr, "%s\n%s\n",
	"usage: jot [-cnr] [-b word] [-w word] [-s string] [-p precision]",
	"           [reps [begin [end [s]]]]");
	exit(1);
}

int
getprec(s)
	char *s;
{
	register char	*p;
	register char	*q;

	for (p = s; *p; p++)
		if (*p == '.')
			break;
	if (!*p)
		return (0);
	for (q = ++p; *p; p++)
		if (!isdigit(*p))
			break;
	return (p - q);
}

void
getformat()
{
	register char	*p;
	int dot, hash, space, sign, numbers, islong = 0;
	char *s;

	if (boring)				/* no need to bother */
		return;
	for (p = format; *p; p++)		/* look for '%' */
		if (*p == '%' && *(p+1) != '%')	/* leave %% alone */
			break;
	if (!*p && !chardata)
		sprintf(p, "%%.%df", prec);
	else if (!*p && chardata) {
		strcpy(p, "%c");
		intdata = 1;
	} else if (!*(p+1))
		strcat(format, "%");		/* cannot end in single '%' */
	else {
		/*
		 * Allow conversion format specifiers of the form
		 * %[#][ ][{+,-}][0-9]*[.[0-9]*]? where ? must be one of
		 * [l]{d,i,o,u,x} or {f,e,g,E,G,d,o,x,D,O,U,X,c,u}
		 */
		s = p++;
		dot = hash = space = sign = numbers = 0;
		while (!isalpha(*p)) {
			if (isdigit(*p)) {
				numbers++;
				p++;
			} else if ((*p == '#' && !(numbers|dot|sign|space|
			    hash++)) ||
			    (*p == ' ' && !(numbers|dot|space++)) ||
			    ((*p == '+' || *p == '-') && !(numbers|dot|sign++))
			    || (*p == '.' && !(dot++)))
				p++;
			else if (*p == '$' || *p == '*')
				errx(1, "unsupported format character %c", *p);
			else if (*p == '\0')
				errx(1, "missing format character");
			else
				errx(1, "illegal format character %c", *p);
		}
		switch (*p) {
		case 'l':
			islong = 1;
			p++;
			/* FALLTHROUGH */
		case 'o': case 'u': case 'x': case 'X':
			intdata = nosign = 1;
			break;
		case 'd': case 'i':
			intdata = 1;
			break;
		case 'D':
			if (!islong) {
				intdata = 1;
				break;
			}
		case 'O': case 'U':
			if (!islong) {
				intdata = nosign = 1;
				break;
			}
		case 'c':
			if (!(intdata | islong)) {
				chardata = 1;
				break;
			}
		case 's':
			errx(1, "cannot convert numeric data to strings");
			break;
		case 'h': case 'n': case 'p': case 'q': case 'L':
		case '$': case '*':
			errx(1, "unsupported format character %c", *p);
			/* NOTREACHED */
		case 'f': case 'e': case 'g': case 'E': case 'G':
			if (!islong)
				break;
			/* FALLTHROUGH */
		default:
			*++p = '\0';
			errx(1, "illegal or unsupported format '%s'", s);
			/* NOTREACHED */
		}
		while (*++p)
			if (*p == '%' && *(p+1) && *(p+1) != '%')
				errx(1, "too many conversions");
			else if (*p == '%' && *(p+1) == '%')
				p++;
			else if (*p == '%' && !*(p+1)) {
				strcat(format, "%");
				break;
			}
	}
}

void
arith_oflow(int sig)
{

	write(STDERR_FILENO, oflowstr, oflowlen);
	_exit(sig);
}
