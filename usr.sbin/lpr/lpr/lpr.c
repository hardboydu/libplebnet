/*
 * Copyright (c) 1983, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
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
"@(#) Copyright (c) 1983, 1989, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)from: lpr.c	8.4 (Berkeley) 4/28/95";
#endif
static const char rcsid[] =
	"$Id: lpr.c,v 1.24 1998/04/17 17:25:49 obrien Exp $";
#endif /* not lint */

/*
 *      lpr -- off line print
 *
 * Allows multiple printers and printers on remote machines by
 * using information from a printer data base.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <a.out.h>
#include <err.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "lp.h"
#include "lp.local.h"
#include "pathnames.h"

static char	*cfname;	/* daemon control files, linked from tf's */
static char	*class = host;	/* class title on header page */
static char	*dfname;	/* data files */
static char	*fonts[4];	/* troff font names */
static char	 format = 'f';	/* format char for printing files */
static int	 hdr = 1;	/* print header or not (default is yes) */
static int	 iflag;		/* indentation wanted */
static int	 inchar;	/* location to increment char in file names */
static int	 indent;	/* amount to indent */
static char	*jobname;	/* job name on header page */
static int	 mailflg;	/* send mail */
static int	 nact;		/* number of jobs to act on */
static int	 ncopies = 1;	/* # of copies to make */
static char	*person;	/* user name */
static int	 qflag;		/* q job, but don't exec daemon */
static int	 rflag;		/* remove files upon completion */
static int	 sflag;		/* symbolic link flag */
static int	 tfd;		/* control file descriptor */
static char	*tfname;	/* tmp copy of cf before linking */
static char	*title;		/* pr'ing title */
static int	 userid;	/* user id */
static char	*width;		/* width for versatec printing */

static struct stat statb;

static void	 card __P((int, char *));
static int	 checkwriteperm __P((char*, char *));
static void	 chkprinter __P((char *printer, struct printer *pp));
static void	 cleanup __P((int));
static void	 copy __P((const struct printer *, int, char []));
static char	*itoa __P((int));
static char	*linked __P((char *));
int		 main __P((int, char **));
static char	*lmktemp __P((const struct printer *pp, char *, int, int));
static void	 mktemps __P((const struct printer *pp));
static int	 nfile __P((char *));
static int	 test __P((char *));
static void	 usage __P((void));

uid_t	uid, euid;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct passwd *pw;
	struct group *gptr;
	char *arg, *cp, *printer;
	char buf[BUFSIZ];
	int c, i, f, errs;
	struct stat stb;
	struct printer myprinter, *pp = &myprinter;

	printer = NULL;
	euid = geteuid();
	uid = getuid();
	seteuid(uid);
	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
		signal(SIGHUP, cleanup);
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		signal(SIGINT, cleanup);
	if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		signal(SIGQUIT, cleanup);
	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
		signal(SIGTERM, cleanup);

	name = argv[0];
	gethostname(host, sizeof(host));
	openlog("lpd", 0, LOG_LPR);

	errs = 0;
	while ((c = getopt(argc, argv,
			   ":#:1:2:3:4:C:J:P:T:U:cdfghi:lnmprstvw:")) != -1)
		switch (c) {
		case '#':		/* n copies */
			i = atoi(optarg);
			if (i > 0)
				ncopies = i;
			break;

		case '1':		/* troff fonts */
		case '2':
		case '3':
		case '4':
			fonts[optopt - '1'] = optarg;
			break;

		case 'C':		/* classification spec */
			hdr++;
			class = optarg;
			break;

		case 'J':		/* job name */
			hdr++;
			jobname = optarg;
			break;

		case 'P':		/* specifiy printer name */
			printer = optarg;
			break;

		case 'T':		/* pr's title line */
			title = optarg;
			break;

		case 'U':		/* user name */
			hdr++;
			person = optarg;
			break;

		case 'c':		/* print cifplot output */
		case 'd':		/* print tex output (dvi files) */
		case 'g':		/* print graph(1G) output */
		case 'l':		/* literal output */
		case 'n':		/* print ditroff output */
		case 't':		/* print troff output (cat files) */
		case 'p':		/* print using ``pr'' */
		case 'v':		/* print vplot output */
			format = optopt;
			break;

		case 'f':		/* print fortran output */
			format = 'r';
			break;

		case 'h':		/* nulifiy header page */
			hdr = 0;
			break;

		case 'i':		/* indent output */
			iflag++;
			indent = atoi(optarg);
			break;

		case 'm':		/* send mail when done */
			mailflg++;
			break;

		case 'q':		/* just queue job */
			qflag++;
			break;

		case 'r':		/* remove file when done */
			rflag++;
			break;

		case 's':		/* try to link files */
			sflag++;
			break;

		case 'w':		/* versatec page width */
			width = optarg;
			break;

		case ':':		/* catch "missing argument" error */
			if (optopt == 'i') {
				iflag++; /* -i without args is valid */
				indent = 8;
			} else
				errs++;
			break;

		default:
			errs++;
		}
	argc -= optind;
	argv += optind;
	if (errs)
		usage();
	if (printer == NULL && (printer = getenv("PRINTER")) == NULL)
		printer = DEFLP;
	chkprinter(printer, pp);
	if (pp->no_copies && ncopies > 1)
		errx(1, "multiple copies are not allowed");
	if (pp->max_copies > 0 && ncopies > pp->max_copies)
		errx(1, "only %ld copies are allowed", pp->max_copies);
	/*
	 * Get the identity of the person doing the lpr using the same
	 * algorithm as lprm.  Actually, not quite -- lprm will override
	 * the login name with "root" if the user is running as root;
	 * the daemon actually checks for the string "root" in its
	 * permission checking.  Sigh.
	 */
	if ((person = getlogin()) == NULL) {
		userid = getuid();
		if (userid != pp->daemon_user || person == 0) {
			if ((pw = getpwuid(userid)) == NULL)
				errx(1, "Who are you?");
			person = pw->pw_name;
		}
	}
	/*
	 * Check for restricted group access.
	 */
	if (pp->restrict_grp != NULL && userid != pp->daemon_user) {
		if ((gptr = getgrnam(pp->restrict_grp)) == NULL)
			errx(1, "Restricted group specified incorrectly");
		if (gptr->gr_gid != getgid()) {
			while (*gptr->gr_mem != NULL) {
				if ((strcmp(person, *gptr->gr_mem)) == 0)
					break;
				gptr->gr_mem++;
			}
			if (*gptr->gr_mem == NULL)
				errx(1, "Not a member of the restricted group");
		}
	}
	/*
	 * Check to make sure queuing is enabled if userid is not root.
	 */
	lock_file_name(pp, buf, sizeof buf);
	if (userid && stat(buf, &stb) == 0 && (stb.st_mode & LFM_QUEUE_DIS))
		errx(1, "Printer queue is disabled");
	/*
	 * Initialize the control file.
	 */
	mktemps(pp);
	tfd = nfile(tfname);
	seteuid(euid);
	(void) fchown(tfd, pp->daemon_user, -1);
	/* owned by daemon for protection */
	seteuid(uid);
	card('H', host);
	card('P', person);
	if (hdr) {
		if (jobname == NULL) {
			if (argc == 0)
				jobname = "stdin";
			else
				jobname = ((arg = strrchr(argv[0], '/'))
					   ? arg + 1 : argv[0]);
		}
		card('J', jobname);
		card('C', class);
		card('L', person);
	}
	if (iflag)
		card('I', itoa(indent));
	if (mailflg)
		card('M', person);
	if (format == 't' || format == 'n' || format == 'd')
		for (i = 0; i < 4; i++)
			if (fonts[i] != NULL)
				card('1'+i, fonts[i]);
	if (width != NULL)
		card('W', width);

	/*
	 * Read the files and spool them.
	 */
	if (argc == 0)
		copy(pp, 0, " ");
	else while (argc--) {
		if (argv[0][0] == '-' && argv[0][1] == '\0') {
			/* use stdin */
			copy(pp, 0, " ");
			argv++;
			continue;
		}
		if ((f = test(arg = *argv++)) < 0)
			continue;	/* file unreasonable */

		if (sflag && (cp = linked(arg)) != NULL) {
			(void) snprintf(buf, sizeof(buf), "%d %d", statb.st_dev,
				statb.st_ino);
			card('S', buf);
			if (format == 'p')
				card('T', title ? title : arg);
			for (i = 0; i < ncopies; i++)
				card(format, &dfname[inchar-2]);
			card('U', &dfname[inchar-2]);
			if (f)
				card('U', cp);
			card('N', arg);
			dfname[inchar]++;
			nact++;
			continue;
		}
		if (sflag)
			printf("%s: %s: not linked, copying instead\n", name, arg);
		if ((i = open(arg, O_RDONLY)) < 0) {
			printf("%s: cannot open %s\n", name, arg);
		} else {
			copy(pp, i, arg);
			(void) close(i);
			if (f && unlink(arg) < 0)
				printf("%s: %s: not removed\n", name, arg);
		}
	}

	if (nact) {
		(void) close(tfd);
		tfname[inchar]--;
		/*
		 * Touch the control file to fix position in the queue.
		 */
		seteuid(euid);
		if ((tfd = open(tfname, O_RDWR)) >= 0) {
			char c;

			if (read(tfd, &c, 1) == 1 &&
			    lseek(tfd, (off_t)0, 0) == 0 &&
			    write(tfd, &c, 1) != 1) {
				printf("%s: cannot touch %s\n", name, tfname);
				tfname[inchar]++;
				cleanup(0);
			}
			(void) close(tfd);
		}
		if (link(tfname, cfname) < 0) {
			printf("%s: cannot rename %s\n", name, cfname);
			tfname[inchar]++;
			cleanup(0);
		}
		unlink(tfname);
		seteuid(uid);
		if (qflag)		/* just q things up */
			exit(0);
		if (!startdaemon(pp))
			printf("jobs queued, but cannot start daemon.\n");
		exit(0);
	}
	cleanup(0);
	return (1);
	/* NOTREACHED */
}

/*
 * Create the file n and copy from file descriptor f.
 */
static void
copy(pp, f, n)
	const struct printer *pp;
	int f;
	char n[];
{
	register int fd, i, nr, nc;
	char buf[BUFSIZ];

	if (format == 'p')
		card('T', title ? title : n);
	for (i = 0; i < ncopies; i++)
		card(format, &dfname[inchar-2]);
	card('U', &dfname[inchar-2]);
	card('N', n);
	fd = nfile(dfname);
	nr = nc = 0;
	while ((i = read(f, buf, BUFSIZ)) > 0) {
		if (write(fd, buf, i) != i) {
			printf("%s: %s: temp file write error\n", name, n);
			break;
		}
		nc += i;
		if (nc >= BUFSIZ) {
			nc -= BUFSIZ;
			nr++;
			if (pp->max_blocks > 0 && nr > pp->max_blocks) {
				printf("%s: %s: copy file is too large\n",
				       name, n);
				break;
			}
		}
	}
	(void) close(fd);
	if (nc==0 && nr==0)
		printf("%s: %s: empty input file\n", name, f ? n : "stdin");
	else
		nact++;
}

/*
 * Try and link the file to dfname. Return a pointer to the full
 * path name if successful.
 */
static char *
linked(file)
	register char *file;
{
	register char *cp;
	static char buf[MAXPATHLEN];
	register int ret;

	if (*file != '/') {
		if (getcwd(buf, sizeof(buf)) == NULL)
			return(NULL);
		while (file[0] == '.') {
			switch (file[1]) {
			case '/':
				file += 2;
				continue;
			case '.':
				if (file[2] == '/') {
					if ((cp = strrchr(buf, '/')) != NULL)
						*cp = '\0';
					file += 3;
					continue;
				}
			}
			break;
		}
		strncat(buf, "/", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, file, sizeof(buf) - strlen(buf) - 1);
		file = buf;
	}
	seteuid(euid);
	ret = symlink(file, dfname);
	seteuid(uid);
	return(ret ? NULL : file);
}

/*
 * Put a line into the control file.
 */
static void
card(c, p2)
	register int c;
	register char *p2;
{
	char buf[BUFSIZ];
	register char *p1 = buf;
	register int len = 2;

	*p1++ = c;
	while ((c = *p2++) != '\0' && len < sizeof(buf)) {
		*p1++ = (c == '\n') ? ' ' : c;
		len++;
	}
	*p1++ = '\n';
	write(tfd, buf, len);
}

/*
 * Create a new file in the spool directory.
 */
static int
nfile(n)
	char *n;
{
	register int f;
	int oldumask = umask(0);		/* should block signals */

	seteuid(euid);
	f = open(n, O_WRONLY | O_EXCL | O_CREAT, FILMOD);
	(void) umask(oldumask);
	if (f < 0) {
		printf("%s: cannot create %s\n", name, n);
		cleanup(0);
	}
	if (fchown(f, userid, -1) < 0) {
		printf("%s: cannot chown %s\n", name, n);
		cleanup(0);	/* cleanup does exit */
	}
	seteuid(uid);
	if (++n[inchar] > 'z') {
		if (++n[inchar-2] == 't') {
			printf("too many files - break up the job\n");
			cleanup(0);
		}
		n[inchar] = 'A';
	} else if (n[inchar] == '[')
		n[inchar] = 'a';
	return(f);
}

/*
 * Cleanup after interrupts and errors.
 */
static void
cleanup(signo)
	int signo;
{
	register int i;

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	i = inchar;
	seteuid(euid);
	if (tfname)
		do
			unlink(tfname);
		while (tfname[i]-- != 'A');
	if (cfname)
		do
			unlink(cfname);
		while (cfname[i]-- != 'A');
	if (dfname)
		do {
			do
				unlink(dfname);
			while (dfname[i]-- != 'A');
			dfname[i] = 'z';
		} while (dfname[i-2]-- != 'd');
	exit(1);
}

/*
 * Test to see if this is a printable file.
 * Return -1 if it is not, 0 if its printable, and 1 if
 * we should remove it after printing.
 */
static int
test(file)
	char *file;
{
	struct exec execb;
	char	*path;
	register int fd;
	register char *cp;

	if (access(file, 4) < 0) {
		printf("%s: cannot access %s\n", name, file);
		return(-1);
	}
	if (stat(file, &statb) < 0) {
		printf("%s: cannot stat %s\n", name, file);
		return(-1);
	}
	if ((statb.st_mode & S_IFMT) == S_IFDIR) {
		printf("%s: %s is a directory\n", name, file);
		return(-1);
	}
	if (statb.st_size == 0) {
		printf("%s: %s is an empty file\n", name, file);
		return(-1);
 	}
	if ((fd = open(file, O_RDONLY)) < 0) {
		printf("%s: cannot open %s\n", name, file);
		return(-1);
	}
	/*
	 * XXX Shall we add a similar test for ELF?
	 */
	if (read(fd, &execb, sizeof(execb)) == sizeof(execb) &&
	    !N_BADMAG(execb)) {
		printf("%s: %s is an executable program", name, file);
		goto error1;
	}
	(void) close(fd);
	if (rflag) {
		if ((cp = strrchr(file, '/')) == NULL) {
			if (checkwriteperm(file,".") == 0)
				return(1);
		} else {
			if (cp == file) {
				fd = checkwriteperm(file,"/");
			} else {
				path = alloca(strlen(file) + 1);
				strcpy(path,file);
				*cp = '\0';
				fd = checkwriteperm(path,file);
				*cp = '/';
			}
			if (fd == 0)
				return(1);
		}
		printf("%s: %s: is not removable by you\n", name, file);
	}
	return(0);

error1:
	printf(" and is unprintable\n");
	(void) close(fd);
	return(-1);
}

static int
checkwriteperm(file, directory)
	char *file, *directory;
{
	struct	stat	stats;
	if (access(directory, W_OK) == 0) {
		stat(directory, &stats);
		if (stats.st_mode & S_ISVTX) {
			stat(file, &stats);
			if(stats.st_uid == userid) {
				return(0);
			}
		} else return(0);
	}
	return(-1);
}

/*
 * itoa - integer to string conversion
 */
static char *
itoa(i)
	register int i;
{
	static char b[10] = "########";
	register char *p;

	p = &b[8];
	do
		*p-- = i%10 + '0';
	while (i /= 10);
	return(++p);
}

/*
 * Perform lookup for printer name or abbreviation --
 */
static void
chkprinter(s, pp)
	char *s;
	struct printer *pp;
{
	int status;

	init_printer(pp);
	status = getprintcap(s, pp);
	switch(status) {
	case PCAPERR_OSERR:
	case PCAPERR_TCLOOP:
		errx(1, "%s: %s", s, pcaperr(status));
	case PCAPERR_NOTFOUND:
		errx(1, "%s: unknown printer", s);
	case PCAPERR_TCOPEN:
		warnx("%s: unresolved tc= reference(s)", s);
	}
}

/*
 * Tell the user what we wanna get.
 */
static void
usage()
{
	fprintf(stderr, "%s\n%s\n",
"usage: lpr [-Pprinter] [-#num] [-C class] [-J job] [-T title] [-U user]",
"[-i[numcols]] [-1234 font] [-wnum] [-cdfghlnmprstv] [name ...]");
	exit(1);
}


/*
 * Make the temp files.
 */
static void
mktemps(pp)
	const struct printer *pp;
{
	register int len, fd, n;
	register char *cp;
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof(buf), "%s/.seq", pp->spool_dir);
	seteuid(euid);
	if ((fd = open(buf, O_RDWR|O_CREAT, 0661)) < 0) {
		printf("%s: cannot create %s\n", name, buf);
		exit(1);
	}
	if (flock(fd, LOCK_EX)) {
		printf("%s: cannot lock %s\n", name, buf);
		exit(1);
	}
	seteuid(uid);
	n = 0;
	if ((len = read(fd, buf, sizeof(buf))) > 0) {
		for (cp = buf; len--; ) {
			if (*cp < '0' || *cp > '9')
				break;
			n = n * 10 + (*cp++ - '0');
		}
	}
	len = strlen(pp->spool_dir) + strlen(host) + 8;
	tfname = lmktemp(pp, "tf", n, len);
	cfname = lmktemp(pp, "cf", n, len);
	dfname = lmktemp(pp, "df", n, len);
	inchar = strlen(pp->spool_dir) + 3;
	n = (n + 1) % 1000;
	(void) lseek(fd, (off_t)0, 0);
	snprintf(buf, sizeof(buf), "%03d\n", n);
	(void) write(fd, buf, strlen(buf));
	(void) close(fd);	/* unlocks as well */
}

/*
 * Make a temp file name.
 */
static char *
lmktemp(pp, id, num, len)
	const struct printer *pp;
	char	*id;
	int	num, len;
{
	register char *s;

	if ((s = malloc(len)) == NULL)
		errx(1, "out of memory");
	(void) snprintf(s, len, "%s/%sA%03d%s", pp->spool_dir, id, num, host);
	return(s);
}
