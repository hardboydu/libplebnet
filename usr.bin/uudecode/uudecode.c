/*-
 * Copyright (c) 1983, 1993
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
char copyright[] =
"@(#) Copyright (c) 1983, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)uudecode.c	8.2 (Berkeley) 4/2/94";
#endif /* not lint */

/*
 * uudecode [file ...]
 *
 * create the specified file, decoding as you go.
 * used with uuencode.
 */
#include <sys/param.h>
#include <sys/stat.h>

#include <fnmatch.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *filename;
int cflag, pflag;

void    usage __P((void));
int	decode __P((void));
int	decode2 __P((int));

extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	extern int errno;
	int rval, ch;

	while ((ch = getopt(argc, argv, "cp")) != -1) {
		switch(ch) {
		case 'c':
			cflag = 1; /* multiple uudecode'd files */
			break;
		case 'p':
			pflag = 1; /* print output to stdout */
			break;
		default:
			(void)usage();
		}
	}
        argc -= optind;
        argv += optind;

			
	if (*argv) {
		rval = 0;
		do {
			if (!freopen(filename = *argv, "r", stdin)) {
				(void)fprintf(stderr, "uudecode: %s: %s\n",
				    *argv, strerror(errno));
				rval = 1;
				continue;
			}
			rval |= decode();
		} while (*++argv);
	} else {
		filename = "stdin";
		rval = decode();
	}
	exit(rval);
}

int
decode ()
{
	int flag;

	/* decode only one file per input stream */
	if (!cflag) 
		return(decode2(0));

	/* multiple uudecode'd files */
	for (flag = 0; ; flag++)
		if (decode2(flag))
			return(1);
		else if (feof(stdin))
			break;

	return(0);
}

int
decode2(flag)
	int flag;
{
	extern int errno;
	struct passwd *pw;
	register int n;
	register char ch, *p;
	int mode, n1;
	char buf[MAXPATHLEN];
	char buffn[MAXPATHLEN]; /* file name buffer */

	
	/* search for header line */
	do {
		if (!fgets(buf, sizeof(buf), stdin)) {
			if (flag) /* no error */
				return(0);

			(void)fprintf(stderr,
			    "uudecode: %s: no \"begin\" line\n", filename);
			return(1);
		}
	} while (strncmp(buf, "begin ", 6) || 
		 fnmatch("begin [0-7]* *", buf, 0));

	(void)sscanf(buf, "begin %o %s", &mode, buf);

	/* handle ~user/file format */
	if (buf[0] == '~') {
		if (!(p = index(buf, '/'))) {
			(void)fprintf(stderr, "uudecode: %s: illegal ~user.\n",
			    filename);
			return(1);
		}
		*p++ = NULL;
		if (!(pw = getpwnam(buf + 1))) {
			(void)fprintf(stderr, "uudecode: %s: no user %s.\n",
			    filename, buf);
			return(1);
		}
		n = strlen(pw->pw_dir);
		n1 = strlen(p);
		if (n + n1 + 2 > MAXPATHLEN) {
			(void)fprintf(stderr, "uudecode: %s: path too long.\n",
			    filename);
			return(1);
		}
		bcopy(p, buf + n + 1, n1 + 1);
		bcopy(pw->pw_dir, buf, n);
		buf[n] = '/';
	}

	/* create output file, set mode */
	if (pflag)
		; /* print to stdout */

	else if (!freopen(buf, "w", stdout) ||
	    fchmod(fileno(stdout), mode&0666)) {
		(void)fprintf(stderr, "uudecode: %s: %s: %s\n", buf,
		    filename, strerror(errno));
		return(1);
	}
	strcpy(buffn, buf); /* store file name from header line */

	/* for each input line */
	for (;;) {
		if (!fgets(p = buf, sizeof(buf), stdin)) {
			(void)fprintf(stderr, "uudecode: %s: short file.\n",
			    filename);
			return(1);
		}
#define	DEC(c)	(((c) - ' ') & 077)		/* single character decode */
#define IS_DEC(c) ( (((c) - ' ') >= 0) &&  (((c) - ' ') <= 077 + 1) )
/* #define IS_DEC(c) (1) */

#define OUT_OF_RANGE \
{	\
    (void)fprintf(stderr, \
	"uudecode:\n\tinput file: %s\n\tencoded file: %s\n\t%s: [%d-%d]\n", \
 	filename, buffn, "character out of range",  1 + ' ', 077 + ' ' + 1); \
        return(1); \
}


		/*
		 * `n' is used to avoid writing out all the characters
		 * at the end of the file.
		 */
		if ((n = DEC(*p)) <= 0)
			break;
		for (++p; n > 0; p += 4, n -= 3)
			if (n >= 3) {
				if (!(IS_DEC(*p) && IS_DEC(*(p + 1)) && 
				     IS_DEC(*(p + 2)) && IS_DEC(*(p + 3))))
                                	OUT_OF_RANGE

				ch = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
				putchar(ch);
				ch = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
				putchar(ch);
				ch = DEC(p[2]) << 6 | DEC(p[3]);
				putchar(ch);
				
			}
			else {
				if (n >= 1) {
					if (!(IS_DEC(*p) && IS_DEC(*(p + 1))))
	                                	OUT_OF_RANGE
					ch = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
					putchar(ch);
				}
				if (n >= 2) {
					if (!(IS_DEC(*(p + 1)) && 
						IS_DEC(*(p + 2))))
		                                OUT_OF_RANGE

					ch = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
					putchar(ch);
				}
				if (n >= 3) {
					if (!(IS_DEC(*(p + 2)) && 
						IS_DEC(*(p + 3))))
		                                OUT_OF_RANGE
					ch = DEC(p[2]) << 6 | DEC(p[3]);
					putchar(ch);
				}
			}
	}
	if (fgets(buf, sizeof(buf), stdin) == NULL || 
	    (strcmp(buf, "end") && strcmp(buf, "end\n") &&
	     strcmp(buf, "end\r\n"))) {
		(void)fprintf(stderr, "uudecode: %s: no \"end\" line.\n",
		    filename);
		return(1);
	}
	return(0);
}

void
usage()
{
	(void)fprintf(stderr, "usage: uudecode [-cp] [file ...]\n");
	exit(1);
}
