/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Tony Nardo of the Johns Hopkins University/Applied Physics Lab.
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

/*
 * Luke Mewburn <lm@rmit.edu.au> added the following on 940622:
 *    - mail status ("No Mail", "Mail read:...", or "New Mail ...,
 *	Unread since ...".)
 *    - 4 digit phone extensions (3210 is printed as x3210.)
 *    - host/office toggling in short format with -h & -o.
 *    - short day names (`Tue' printed instead of `Jun 21' if the
 *	login time is < 6 days.
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 1989, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)finger.c	8.2 (Berkeley) 9/30/93";
#endif /* not lint */

/*
 * Finger prints out information about users.  It is not portable since
 * certain fields (e.g. the full user name, office, and phone numbers) are
 * extracted from the gecos field of the passwd file which other UNIXes
 * may not have or may use for other things.
 *
 * There are currently two output formats; the short format is one line
 * per user and displays login name, tty, login time, real name, idle time,
 * and either remote host information (default) or office location/phone
 * number, depending on if -h or -o is used respectively.
 * The long format gives the same information (in a more legible format) as
 * well as home directory, shell, mail info, and .plan/.project files.
 */

#include <sys/param.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <utmp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <db.h>
#include <locale.h>
#include "finger.h"

DB *db;
time_t now;
int entries, lflag, mflag, pplan, sflag, oflag;
char tbuf[1024];

static void loginlist __P((void));
static void userlist __P((int, char **));

int
option(argc, argv)
	int argc;
	char **argv;
{
	int ch;

	optind = 1;		/* reset getopt */

	while ((ch = getopt(argc, argv, "lmpsho")) != EOF)
		switch(ch) {
		case 'l':
			lflag = 1;		/* long format */
			break;
		case 'm':
			mflag = 1;		/* force exact match of names */
			break;
		case 'p':
			pplan = 1;		/* don't show .plan/.project */
			break;
		case 's':
			sflag = 1;		/* short format */
			break;
		case 'h':
			oflag = 0;		/* remote host info */
			break;
		case 'o':
			oflag = 1;		/* office info */
			break;
		case '?':
		default:
			(void)fprintf(stderr,
			    "usage: finger [-lmpsho] [login ...]\n");
			exit(1);
		}

	return optind;
}

main(argc, argv)
	int argc;
	char **argv;
{
	int ch, envargc, argcnt;
	char *envargv[3];

	(void) setlocale(LC_TIME|LC_CTYPE, "");

				/* remove this line to get remote host */
	oflag = 1;		/* default to old "office" behavior */

	/*
	 * Process environment variables followed by command line arguments.
	 */
	if ((envargv[1] = getenv("FINGER"))) {
		envargc = 2;
		envargv[0] = "finger";
		envargv[2] = NULL;
		(void) option(envargc, envargv);
	}

	argcnt = option(argc, argv);
	argc -= argcnt;
	argv += argcnt;

	(void)time(&now);
	setpassent(1);
	if (!*argv) {
		/*
		 * Assign explicit "small" format if no names given and -l
		 * not selected.  Force the -s BEFORE we get names so proper
		 * screening will be done.
		 */
		if (!lflag)
			sflag = 1;	/* if -l not explicit, force -s */
		loginlist();
		if (entries == 0)
			(void)printf("No one logged on.\n");
	} else {
		userlist(argc, argv);
		/*
		 * Assign explicit "large" format if names given and -s not
		 * explicitly stated.  Force the -l AFTER we get names so any
		 * remote finger attempts specified won't be mishandled.
		 */
		if (!sflag)
			lflag = 1;	/* if -s not explicit, force -l */
	}
	if (entries)
		if (lflag)
			lflag_print();
		else
			sflag_print();
	exit(0);
}

static void
loginlist()
{
	register PERSON *pn;
	DBT data, key;
	struct passwd *pw;
	struct utmp user;
	int r, sflag;
	char name[UT_NAMESIZE + 1];

	if (!freopen(_PATH_UTMP, "r", stdin))
		err("%s: %s", _PATH_UTMP, strerror(errno));
	name[UT_NAMESIZE] = NULL;
	while (fread((char *)&user, sizeof(user), 1, stdin) == 1) {
		if (!user.ut_name[0])
			continue;
		if ((pn = find_person(user.ut_name)) == NULL) {
			bcopy(user.ut_name, name, UT_NAMESIZE);
			if ((pw = getpwnam(name)) == NULL)
				continue;
			if (hide(pw))
				continue;
			pn = enter_person(pw);
		}
		enter_where(&user, pn);
	}
	if (db && lflag)
		for (sflag = R_FIRST;; sflag = R_NEXT) {
			r = (*db->seq)(db, &key, &data, sflag);
			if (r == -1)
				err("db seq: %s", strerror(errno));
			if (r == 1)
				break;
			enter_lastlog(*(PERSON **)data.data);
		}
}

static void
userlist(argc, argv)
	register int argc;
	register char **argv;
{
	register PERSON *pn;
	DBT data, key;
	struct utmp user;
	struct passwd *pw;
	int r, sflag, *used, *ip;
	char **ap, **nargv, **np, **p;

	if ((nargv = malloc((argc+1) * sizeof(char *))) == NULL ||
	    (used = calloc(argc, sizeof(int))) == NULL)
		err("%s", strerror(errno));

	/* Pull out all network requests. */
	for (ap = p = argv, np = nargv; *p; ++p)
		if (index(*p, '@'))
			*np++ = *p;
		else
			*ap++ = *p;

	*np++ = NULL;
	*ap++ = NULL;

	if (!*argv)
		goto net;

	/*
	 * Traverse the list of possible login names and check the login name
	 * and real name against the name specified by the user.
	 */
	if (mflag)
		for (p = argv; *p; ++p)
			if ((pw = getpwnam(*p)) && !hide(pw))
				enter_person(pw);
			else
				(void)fprintf(stderr,
				    "finger: %s: no such user\n", *p);
	else {
		while (pw = getpwent()) {
			for (p = argv, ip = used; *p; ++p, ++ip)
				if (match(pw, *p) && !hide(pw)) {
					enter_person(pw);
					*ip = 1;
				}
		}
		for (p = argv, ip = used; *p; ++p, ++ip)
			if (!*ip)
				(void)fprintf(stderr,
				    "finger: %s: no such user\n", *p);
	}

	/* Handle network requests. */
net:	for (p = nargv; *p;) {
		netfinger(*p++);
		if (*p || entries)
		    printf("\n");
	}

	if (entries == 0)
		return;

	/*
	 * Scan thru the list of users currently logged in, saving
	 * appropriate data whenever a match occurs.
	 */
	if (!freopen(_PATH_UTMP, "r", stdin))
		err("%s: %s", _PATH_UTMP, strerror(errno));
	while (fread((char *)&user, sizeof(user), 1, stdin) == 1) {
		if (!user.ut_name[0])
			continue;
		if ((pn = find_person(user.ut_name)) == NULL)
			continue;
		enter_where(&user, pn);
	}
	if (db)
		for (sflag = R_FIRST;; sflag = R_NEXT) {
			r = (*db->seq)(db, &key, &data, sflag);
			if (r == -1)
				err("db seq: %s", strerror(errno));
			if (r == 1)
				break;
			enter_lastlog(*(PERSON **)data.data);
		}
}
