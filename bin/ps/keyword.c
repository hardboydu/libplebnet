/*-
 * Copyright (c) 1990, 1993, 1994
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

#include <sys/cdefs.h>

__FBSDID("$FreeBSD$");

#if 0
#ifndef lint
static char sccsid[] = "@(#)keyword.c	8.5 (Berkeley) 4/2/94";
#endif /* not lint */
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utmp.h>

#include "ps.h"

static VAR *findvar(char *);
static int  vcmp(const void *, const void *);

#ifdef NOTINUSE
int	utime(), stime(), ixrss(), idrss(), isrss();
	{{"utime"}, "UTIME", USER, utime, NULL, 4},
	{{"stime"}, "STIME", USER, stime, NULL, 4},
	{{"ixrss"}, "IXRSS", USER, ixrss, NULL, 4},
	{{"idrss"}, "IDRSS", USER, idrss, NULL, 4},
	{{"isrss"}, "ISRSS", USER, isrss, NULL, 4},
#endif

/* Compute offset in common structures. */
#define	KOFF(x)	offsetof(struct kinfo_proc, x)
#define	ROFF(x)	offsetof(struct rusage, x)

#define	UIDFMT	"u"
#define	UIDLEN	5
#define	PIDFMT	"d"
#define	PIDLEN	5
#define USERLEN UT_NAMESIZE

static VAR var[] = {
	{"%cpu", "%CPU", NULL, 0, pcpu, NULL, 4, 0, CHAR, NULL, 0},
	{"%mem", "%MEM", NULL, 0, pmem, NULL, 4, 0, CHAR, NULL, 0},
	{"acflag", "ACFLG", NULL, 0, kvar, NULL, 3, KOFF(ki_acflag), USHORT,
		"x", 0},
	{"acflg", "", "acflag", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"blocked", "", "sigmask", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"caught", "", "sigcatch", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"command", "COMMAND", NULL, COMM|LJUST|USER, command, NULL, 16,
		0, CHAR, NULL, 0},
	{"cpu", "CPU", NULL, 0, kvar, NULL, 3, KOFF(ki_estcpu), UINT, "d",
		0},
	{"cputime", "", "time", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"f", "F", NULL, 0, kvar, NULL, 7, KOFF(ki_flag), INT, "x", 0},
	{"flags", "", "f", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"ignored", "", "sigignore", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"inblk", "INBLK", NULL, USER, rvar, NULL, 4, ROFF(ru_inblock), LONG,
		"ld", 0},
	{"inblock", "", "inblk", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"jobc", "JOBC", NULL, 0, kvar, NULL, 4, KOFF(ki_jobc), SHORT, "d",
		0},
	{"ktrace", "KTRACE", NULL, 0, kvar, NULL, 8, KOFF(ki_traceflag), INT,
		"x", 0},
	{"lim", "LIM", NULL, 0, maxrss, NULL, 5, 0, CHAR, NULL, 0},
	{"login", "LOGIN", NULL, LJUST, logname, NULL, MAXLOGNAME-1, 0, CHAR,
		NULL, 0},
	{"logname", "", "login", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"lstart", "STARTED", NULL, LJUST|USER, lstarted, NULL, 28, 0, CHAR,
		NULL, 0},
	{"lvl", "LVL", NULL, LJUST, lattr, NULL, 3, 0, CHAR, NULL, 0},
	{"majflt", "MAJFLT", NULL, USER, rvar, NULL, 4, ROFF(ru_majflt),
		LONG, "ld", 0},
	{"minflt", "MINFLT", NULL, USER, rvar, NULL, 4, ROFF(ru_minflt),
		LONG, "ld", 0},
	{"msgrcv", "MSGRCV", NULL, USER, rvar, NULL, 4, ROFF(ru_msgrcv),
		LONG, "ld", 0},
	{"msgsnd", "MSGSND", NULL, USER, rvar, NULL, 4, ROFF(ru_msgsnd),
		LONG, "ld", 0},
	{"mtxname", "MUTEX", NULL, LJUST, mtxname, NULL, 6, 0, CHAR, NULL,
		0},
	{"mwchan", "MWCHAN", NULL, LJUST, mwchan, NULL, 6, 0, CHAR, NULL, 0},
	{"ni", "", "nice", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"nice", "NI", NULL, 0, kvar, NULL, 2, KOFF(ki_nice), CHAR, "d",
		0},
	{"nivcsw", "NIVCSW", NULL, USER, rvar, NULL, 5, ROFF(ru_nivcsw),
		LONG, "ld", 0},
	{"nsignals", "", "nsigs", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"nsigs", "NSIGS", NULL, USER, rvar, NULL, 4, ROFF(ru_nsignals),
		LONG, "ld", 0},
	{"nswap", "NSWAP", NULL, USER, rvar, NULL, 4, ROFF(ru_nswap),
		LONG, "ld", 0},
	{"nvcsw", "NVCSW", NULL, USER, rvar, NULL, 5, ROFF(ru_nvcsw),
		LONG, "ld", 0},
	{"oublk", "OUBLK", NULL, USER, rvar, NULL, 4, ROFF(ru_oublock),
		LONG, "ld", 0},
	{"oublock", "", "oublk", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"paddr", "PADDR", NULL, 0, kvar, NULL, 8, KOFF(ki_paddr), KPTR,
		"lx", 0},
	{"pagein", "PAGEIN", NULL, USER, pagein, NULL, 6, 0, CHAR, NULL, 0},
	{"pcpu", "", "%cpu", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"pending", "", "sig", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"pgid", "PGID", NULL, 0, kvar, NULL, PIDLEN, KOFF(ki_pgid), UINT,
		PIDFMT, 0},
	{"pid", "PID", NULL, 0, kvar, NULL, PIDLEN, KOFF(ki_pid), UINT,
		PIDFMT, 0},
	{"pmem", "", "%mem", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"ppid", "PPID", NULL, 0, kvar, NULL, PIDLEN, KOFF(ki_ppid), UINT,
		PIDFMT, 0},
	{"pri", "PRI", NULL, 0, pri, NULL, 3, 0, CHAR, NULL, 0},
	{"re", "RE", NULL, 0, kvar, NULL, 3, KOFF(ki_swtime), UINT, "d",
		0},
	{"rgid", "RGID", NULL, 0, kvar, NULL, UIDLEN, KOFF(ki_rgid),
		UINT, UIDFMT, 0},
	{"rss", "RSS", NULL, 0, kvar, NULL, 4, KOFF(ki_rssize), UINT, "d",
		0},
	{"rtprio", "RTPRIO", NULL, 0, priorityr, NULL, 7, KOFF(ki_pri), CHAR,
		NULL, 0},
	{"ruid", "RUID", NULL, 0, kvar, NULL, UIDLEN, KOFF(ki_ruid),
		UINT, UIDFMT, 0},
	{"ruser", "RUSER", NULL, LJUST|DSIZ, runame, s_runame, USERLEN,
		0, CHAR, NULL, 0},
	{"sid", "SID", NULL, 0, kvar, NULL, PIDLEN, KOFF(ki_sid), UINT,
		PIDFMT, 0},
	{"sig", "PENDING", NULL, 0, kvar, NULL, 8, KOFF(ki_siglist), INT,
		"x", 0},
	{"sigcatch", "CAUGHT", NULL, 0, kvar, NULL, 8, KOFF(ki_sigcatch),
		UINT, "x", 0},
	{"sigignore", "IGNORED", NULL, 0, kvar, NULL, 8, KOFF(ki_sigignore),
		UINT, "x", 0},
	{"sigmask", "BLOCKED", NULL, 0, kvar, NULL, 8, KOFF(ki_sigmask),
		UINT, "x", 0},
	{"sl", "SL", NULL, 0, kvar, NULL, 3, KOFF(ki_slptime), UINT, "d",
		0},
	{"start", "STARTED", NULL, LJUST|USER, started, NULL, 7, 0, CHAR, NULL,
		0},
	{"stat", "", "state", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"state", "STAT", NULL, 0, state, NULL, 4, 0, CHAR, NULL, 0},
	{"svgid", "SVGID", NULL, 0, kvar, NULL, UIDLEN, KOFF(ki_svgid),
		UINT, UIDFMT, 0},
	{"svuid", "SVUID", NULL, 0, kvar, NULL, UIDLEN, KOFF(ki_svuid),
		UINT, UIDFMT, 0},
	{"tdev", "TDEV", NULL, 0, tdev, NULL, 4, 0, CHAR, NULL, 0},
	{"time", "TIME", NULL, USER, cputime, NULL, 9, 0, CHAR, NULL, 0},
	{"tpgid", "TPGID", NULL, 0, kvar, NULL, 4, KOFF(ki_tpgid), UINT,
		PIDFMT, 0},
	{"tsid", "TSID", NULL, 0, kvar, NULL, PIDLEN, KOFF(ki_tsid), UINT,
		PIDFMT, 0},
	{"tsiz", "TSIZ", NULL, 0, tsize, NULL, 4, 0, CHAR, NULL, 0},
	{"tt", "TT ", NULL, 0, tname, NULL, 4, 0, CHAR, NULL, 0},
	{"tty", "TTY", NULL, LJUST, longtname, NULL, 8, 0, CHAR, NULL, 0},
	{"ucomm", "UCOMM", NULL, LJUST, ucomm, NULL, MAXCOMLEN, 0, CHAR, NULL,
		0},
	{"uid", "UID", NULL, 0, kvar, NULL, UIDLEN, KOFF(ki_uid), UINT,
		UIDFMT, 0},
	{"upr", "UPR", NULL, 0, kvar, NULL, 3, KOFF(ki_pri.pri_user), UCHAR,
		"d", 0},
	{"user", "USER", NULL, LJUST|DSIZ, uname, s_uname, USERLEN, 0, CHAR,
		NULL, 0},
	{"usrpri", "", "upr", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"vsize", "", "vsz", 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
	{"vsz", "VSZ", NULL, 0, vsize, NULL, 5, 0, CHAR, NULL, 0},
	{"wchan", "WCHAN", NULL, LJUST, wchan, NULL, 6, 0, CHAR, NULL, 0},
	{"xstat", "XSTAT", NULL, 0, kvar, NULL, 4, KOFF(ki_xstat), USHORT,
		"x", 0},
	{"", NULL, NULL, 0, NULL, NULL, 0, 0, CHAR, NULL, 0},
};

void
showkey(void)
{
	VAR *v;
	int i;
	const char *p, *sep;

	i = 0;
	sep = "";
	for (v = var; *(p = v->name); ++v) {
		int len = strlen(p);
		if (termwidth && (i += len + 1) > termwidth) {
			i = len;
			sep = "\n";
		}
		(void) printf("%s%s", sep, p);
		sep = " ";
	}
	(void) printf("\n");
}

void
parsefmt(const char *p)
{
	static struct varent *vtail;
	char *tempstr, *tempstr1;

#define	FMTSEP	" \t,\n"
	tempstr1 = tempstr = strdup(p);
	while (tempstr && *tempstr) {
		char *cp;
		VAR *v;
		struct varent *vent;

		while ((cp = strsep(&tempstr, FMTSEP)) != NULL && *cp == '\0')
			/* void */;
		if (cp == NULL || !(v = findvar(cp)))
			continue;
		if ((vent = malloc(sizeof(struct varent))) == NULL)
			err(1, NULL);
		vent->var = v;
		vent->next = NULL;
		if (vhead == NULL)
			vhead = vtail = vent;
		else {
			vtail->next = vent;
			vtail = vent;
		}
	}
	free(tempstr1);
	if (!vhead)
		errx(1, "no valid keywords");
}

static VAR *
findvar(char *p)
{
	VAR *v, key;
	char *hp;

	hp = strchr(p, '=');
	if (hp)
		*hp++ = '\0';

	key.name = p;
	v = bsearch(&key, var, sizeof(var)/sizeof(VAR) - 1, sizeof(VAR), vcmp);

	if (v && v->alias) {
		if (hp) {
			warnx("%s: illegal keyword specification", p);
			eval = 1;
		}
		parsefmt(v->alias);
		return ((VAR *)NULL);
	}
	if (!v) {
		warnx("%s: keyword not found", p);
		eval = 1;
	} else if (hp)
		v->header = hp;
	return (v);
}

static int
vcmp(const void *a, const void *b)
{
        return (strcmp(((const VAR *)a)->name, ((const VAR *)b)->name));
}
