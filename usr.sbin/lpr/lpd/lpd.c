/*
 * Copyright (c) 1983, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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
"@(#) Copyright (c) 1983, 1993, 1994\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)lpd.c	8.7 (Berkeley) 5/10/95";
#endif
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

/*
 * lpd -- line printer daemon.
 *
 * Listen for a connection and perform the requested operation.
 * Operations are:
 *	\1printer\n
 *		check the queue for jobs and print any found.
 *	\2printer\n
 *		receive a job from another machine and queue it.
 *	\3printer [users ...] [jobs ...]\n
 *		return the current state of the queue (short form).
 *	\4printer [users ...] [jobs ...]\n
 *		return the current state of the queue (long form).
 *	\5printer person [users ...] [jobs ...]\n
 *		remove jobs from the queue.
 *
 * Strategy to maintain protected spooling area:
 *	1. Spooling area is writable only by daemon and spooling group
 *	2. lpr runs setuid root and setgrp spooling group; it uses
 *	   root to access any file it wants (verifying things before
 *	   with an access call) and group id to know how it should
 *	   set up ownership of files in the spooling area.
 *	3. Files in spooling area are owned by root, group spooling
 *	   group, with mode 660.
 *	4. lpd, lpq and lprm run setuid daemon and setgrp spooling group to
 *	   access files and printer.  Users can't get to anything
 *	   w/o help of lpq and lprm programs.
 */

#include <sys/param.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <ctype.h>
#include "lp.h"
#include "lp.local.h"
#include "pathnames.h"
#include "extern.h"

int	lflag;				/* log requests flag */
int	pflag;				/* no incoming port flag */
int	from_remote;			/* from remote socket */

int		  main __P((int, char **));
static void       reapchild __P((int));
static void       mcleanup __P((int));
static void       doit __P((void));
static void       startup __P((void));
static void       chkhost __P((struct sockaddr *));
static int	  ckqueue __P((struct printer *));
static void	  usage __P((void));
static int	  *socksetup __P((int, int));

/* XXX from libc/net/rcmd.c */
extern int __ivaliduser_sa __P((FILE *, struct sockaddr *, socklen_t,
				const char *, const char *));

uid_t	uid, euid;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int errs, f, funix, *finet, fromlen, i, options, socket_debug;
	fd_set defreadfds;
	struct sockaddr_un un, fromunix;
	struct sockaddr_storage frominet;
	int lfd;
	sigset_t omask, nmask;
	struct servent *sp, serv;
	int inet_flag = 0, inet6_flag = 0;

	euid = geteuid();	/* these shouldn't be different */
	uid = getuid();
	socket_debug = 0;
	gethostname(host, sizeof(host));

	name = "lpd";

	if (euid != 0)
		errx(EX_NOPERM,"must run as root");

	errs = 0;
	while ((i = getopt(argc, argv, "dlp46")) != -1)
		switch (i) {
		case 'd':
			socket_debug++;
			break;
		case 'l':
			lflag++;
			break;
		case 'p':
			pflag++;
			break;
		case '4':
			family = PF_INET;
			inet_flag++;
			break;
		case '6':
#ifdef INET6
			family = PF_INET6;
			inet6_flag++;
#else
			errx(EX_USAGE, "lpd compiled sans INET6 (IPv6 support)");
#endif
			break;
		default:
			errs++;
		}
	if (inet_flag && inet6_flag)
		family = PF_UNSPEC;
	argc -= optind;
	argv += optind;
	if (errs)
		usage();

	if (argc == 1) {
		if ((i = atoi(argv[0])) == 0)
			usage();
		if (i < 0 || i > USHRT_MAX)
			errx(EX_USAGE, "port # %d is invalid", i);

		serv.s_port = htons(i);
		sp = &serv;
		argc--;
	} else {
		sp = getservbyname("printer", "tcp");
		if (sp == NULL)
			errx(EX_OSFILE, "printer/tcp: unknown service");
	}

	if (argc != 0)
		usage();

	/*
	 * We run chkprintcap right away to catch any errors and blat them
	 * to stderr while we still have it open, rather than sending them
	 * to syslog and leaving the user wondering why lpd started and
	 * then stopped.  There should probably be a command-line flag to
	 * ignore errors from chkprintcap.
	 */
	{
		pid_t pid;
		int status;
		pid = fork();
		if (pid < 0) {
			err(EX_OSERR, "cannot fork");
		} else if (pid == 0) {	/* child */
			execl(_PATH_CHKPRINTCAP, _PATH_CHKPRINTCAP, (char *)0);
			err(EX_OSERR, "cannot execute %s", _PATH_CHKPRINTCAP);
		}
		if (waitpid(pid, &status, 0) < 0) {
			err(EX_OSERR, "cannot wait");
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			errx(EX_OSFILE, "%d errors in printcap file, exiting",
			     WEXITSTATUS(status));
	}

#ifndef DEBUG
	/*
	 * Set up standard environment by detaching from the parent.
	 */
	daemon(0, 0);
#endif

	openlog("lpd", LOG_PID, LOG_LPR);
	syslog(LOG_INFO, "lpd startup: logging=%d%s", lflag,
	    socket_debug ? " dbg" : "");
	(void) umask(0);
	/*
	 * NB: This depends on O_NONBLOCK semantics doing the right thing;
	 * i.e., applying only to the O_EXLOCK and not to the rest of the
	 * open/creation.  As of 1997-12-02, this is the case for commonly-
	 * used filesystems.  There are other places in this code which
	 * make the same assumption.
	 */
	lfd = open(_PATH_MASTERLOCK, O_WRONLY|O_CREAT|O_EXLOCK|O_NONBLOCK,
		   LOCK_FILE_MODE);
	if (lfd < 0) {
		if (errno == EWOULDBLOCK)	/* active deamon present */
			exit(0);
		syslog(LOG_ERR, "%s: %m", _PATH_MASTERLOCK);
		exit(1);
	}
	fcntl(lfd, F_SETFL, 0);	/* turn off non-blocking mode */
	ftruncate(lfd, 0);
	/*
	 * write process id for others to know
	 */
	sprintf(line, "%u\n", getpid());
	f = strlen(line);
	if (write(lfd, line, f) != f) {
		syslog(LOG_ERR, "%s: %m", _PATH_MASTERLOCK);
		exit(1);
	}
	signal(SIGCHLD, reapchild);
	/*
	 * Restart all the printers.
	 */
	startup();
	(void) unlink(_PATH_SOCKETNAME);
	funix = socket(AF_UNIX, SOCK_STREAM, 0);
	if (funix < 0) {
		syslog(LOG_ERR, "socket: %m");
		exit(1);
	}

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGHUP);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGQUIT);
	sigaddset(&nmask, SIGTERM);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	(void) umask(07);
	signal(SIGHUP, mcleanup);
	signal(SIGINT, mcleanup);
	signal(SIGQUIT, mcleanup);
	signal(SIGTERM, mcleanup);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, _PATH_SOCKETNAME);
#ifndef SUN_LEN
#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
#endif
	if (bind(funix, (struct sockaddr *)&un, SUN_LEN(&un)) < 0) {
		syslog(LOG_ERR, "ubind: %m");
		exit(1);
	}
	(void) umask(0);
	sigprocmask(SIG_SETMASK, &omask, (sigset_t *)0);
	FD_ZERO(&defreadfds);
	FD_SET(funix, &defreadfds);
	listen(funix, 5);
	if (pflag == 0) {
		options = SO_REUSEADDR;
		if (socket_debug)
			options |= SO_DEBUG;
		finet = socksetup(family, options);
	} else
		finet = NULL;	/* pretend we couldn't open TCP socket. */
	if (finet) {
		for (i = 1; i <= *finet; i++) {
			FD_SET(finet[i], &defreadfds);
			listen(finet[i], 5);
		}
	}
	/*
	 * Main loop: accept, do a request, continue.
	 */
	memset(&frominet, 0, sizeof(frominet));
	memset(&fromunix, 0, sizeof(fromunix));
	if (lflag)
		syslog(LOG_INFO, "lpd startup: ready to accept requests");
	/*
	 * XXX - should be redone for multi-protocol
	 */
	for (;;) {
		int domain = -1, nfds, s = -1;
		fd_set readfds;

		FD_COPY(&defreadfds, &readfds);
		nfds = select(20, &readfds, 0, 0, 0);
		if (nfds <= 0) {
			if (nfds < 0 && errno != EINTR)
				syslog(LOG_WARNING, "select: %m");
			continue;
		}
		domain = 0;			/* avoid compile-time warning */
		s = 0;				/* avoid compile-time warning */
		if (FD_ISSET(funix, &readfds)) {
			domain = AF_UNIX, fromlen = sizeof(fromunix);
			s = accept(funix,
			    (struct sockaddr *)&fromunix, &fromlen);
 		} else {
                        for (i = 1; i <= *finet; i++) 
				if (FD_ISSET(finet[i], &readfds)) {
					domain = AF_INET;
					fromlen = sizeof(frominet);
					s = accept(finet[i],
					    (struct sockaddr *)&frominet,
					    &fromlen);
				}
		}
		if (s < 0) {
			if (errno != EINTR)
				syslog(LOG_WARNING, "accept: %m");
			continue;
		}
		if (fork() == 0) {
			signal(SIGCHLD, SIG_IGN);
			signal(SIGHUP, SIG_IGN);
			signal(SIGINT, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
			signal(SIGTERM, SIG_IGN);
			(void) close(funix);
			if (pflag == 0 && finet) {
                        	for (i = 1; i <= *finet; i++) 
					(void)close(finet[i]);
			}
			dup2(s, 1);
			(void) close(s);
			if (domain == AF_INET) {
				/* for both AF_INET and AF_INET6 */
				from_remote = 1;
 				chkhost((struct sockaddr *)&frominet);
			} else
				from_remote = 0;
			doit();
			exit(0);
		}
		(void) close(s);
	}
}

static void
reapchild(signo)
	int signo;
{
	union wait status;

	while (wait3((int *)&status, WNOHANG, 0) > 0)
		;
}

static void
mcleanup(signo)
	int signo;
{
	/*
	 * XXX syslog(3) is not signal-safe.
	 */
	if (lflag) {
		if (signo)
			syslog(LOG_INFO, "exiting on signal %d", signo);
		else
			syslog(LOG_INFO, "exiting");
	}
	unlink(_PATH_SOCKETNAME);
	exit(0);
}

/*
 * Stuff for handling job specifications
 */
char	*user[MAXUSERS];	/* users to process */
int	users;			/* # of users in user array */
int	requ[MAXREQUESTS];	/* job number of spool entries */
int	requests;		/* # of spool requests */
char	*person;		/* name of person doing lprm */

char	fromb[MAXHOSTNAMELEN];	/* buffer for client's machine name */
char	cbuf[BUFSIZ];		/* command line buffer */
char	*cmdnames[] = {
	"null",
	"printjob",
	"recvjob",
	"displayq short",
	"displayq long",
	"rmjob"
};

static void
doit()
{
	char *cp, *printer;
	int n;
	int status;
	struct printer myprinter, *pp = &myprinter;

	init_printer(&myprinter);

	for (;;) {
		cp = cbuf;
		do {
			if (cp >= &cbuf[sizeof(cbuf) - 1])
				fatal(0, "Command line too long");
			if ((n = read(1, cp, 1)) != 1) {
				if (n < 0)
					fatal(0, "Lost connection");
				return;
			}
		} while (*cp++ != '\n');
		*--cp = '\0';
		cp = cbuf;
		if (lflag) {
			if (*cp >= '\1' && *cp <= '\5')
				syslog(LOG_INFO, "%s requests %s %s",
					from, cmdnames[(u_char)*cp], cp+1);
			else
				syslog(LOG_INFO, "bad request (%d) from %s",
					*cp, from);
		}
		switch (*cp++) {
		case CMD_CHECK_QUE: /* check the queue, print any jobs there */
			startprinting(cp);
			break;
		case CMD_TAKE_THIS: /* receive files to be queued */
			if (!from_remote) {
				syslog(LOG_INFO, "illegal request (%d)", *cp);
				exit(1);
			}
			recvjob(cp);
			break;
		case CMD_SHOWQ_SHORT: /* display the queue (short form) */
		case CMD_SHOWQ_LONG: /* display the queue (long form) */
			/* XXX - this all needs to be redone. */
			printer = cp;
			while (*cp) {
				if (*cp != ' ') {
					cp++;
					continue;
				}
				*cp++ = '\0';
				while (isspace(*cp))
					cp++;
				if (*cp == '\0')
					break;
				if (isdigit(*cp)) {
					if (requests >= MAXREQUESTS)
						fatal(0, "Too many requests");
					requ[requests++] = atoi(cp);
				} else {
					if (users >= MAXUSERS)
						fatal(0, "Too many users");
					user[users++] = cp;
				}
			}
			status = getprintcap(printer, pp);
			if (status < 0)
				fatal(pp, pcaperr(status));
			displayq(pp, cbuf[0] == CMD_SHOWQ_LONG);
			exit(0);
		case CMD_RMJOB:	/* remove a job from the queue */
			if (!from_remote) {
				syslog(LOG_INFO, "illegal request (%d)", *cp);
				exit(1);
			}
			printer = cp;
			while (*cp && *cp != ' ')
				cp++;
			if (!*cp)
				break;
			*cp++ = '\0';
			person = cp;
			while (*cp) {
				if (*cp != ' ') {
					cp++;
					continue;
				}
				*cp++ = '\0';
				while (isspace(*cp))
					cp++;
				if (*cp == '\0')
					break;
				if (isdigit(*cp)) {
					if (requests >= MAXREQUESTS)
						fatal(0, "Too many requests");
					requ[requests++] = atoi(cp);
				} else {
					if (users >= MAXUSERS)
						fatal(0, "Too many users");
					user[users++] = cp;
				}
			}
			rmjob(printer);
			break;
		}
		fatal(0, "Illegal service request");
	}
}

/*
 * Make a pass through the printcap database and start printing any
 * files left from the last time the machine went down.
 */
static void
startup()
{
	int pid, status, more;
	struct printer myprinter, *pp = &myprinter;

	more = firstprinter(pp, &status);
	if (status)
		goto errloop;
	while (more) {
		if (ckqueue(pp) <= 0) {
			goto next;
		}
		if (lflag)
			syslog(LOG_INFO, "lpd startup: work for %s",
			    pp->printer);
		if ((pid = fork()) < 0) {
			syslog(LOG_WARNING, "lpd startup: cannot fork for %s",
			    pp->printer);
			mcleanup(0);
		}
		if (pid == 0) {
			lastprinter();
			printjob(pp);
			/* NOTREACHED */
		}
		do {
next:
			more = nextprinter(pp, &status);
errloop:
			if (status)
				syslog(LOG_WARNING, 
				    "lpd startup: printcap entry for %s has errors, skipping",
				    pp->printer ? pp->printer : "<???>");
		} while (more && status);
	}
}

/*
 * Make sure there's some work to do before forking off a child
 */
static int
ckqueue(pp)
	struct printer *pp;
{
	register struct dirent *d;
	DIR *dirp;
	char *spooldir;

	spooldir = pp->spool_dir;
	if ((dirp = opendir(spooldir)) == NULL)
		return (-1);
	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] != 'c' || d->d_name[1] != 'f')
			continue;	/* daemon control files only */
		closedir(dirp);
		return (1);		/* found something */
	}
	closedir(dirp);
	return (0);
}

#define DUMMY ":nobody::"

/*
 * Check to see if the from host has access to the line printer.
 */
static void
chkhost(f)
	struct sockaddr *f;
{
	struct addrinfo hints, *res, *r;
	register FILE *hostf;
	int first = 1;
	int good = 0;
	char host[NI_MAXHOST], ip[NI_MAXHOST];
	char serv[NI_MAXSERV];
	int error, addrlen;
	caddr_t addr;

	error = getnameinfo(f, f->sa_len, NULL, 0, serv, sizeof(serv),
			    NI_NUMERICSERV);
	if (error || atoi(serv) >= IPPORT_RESERVED)
		fatal(0, "Malformed from address");

	/* Need real hostname for temporary filenames */
	error = getnameinfo(f, f->sa_len, host, sizeof(host), NULL, 0,
			    NI_NAMEREQD);
	if (error) {
		error = getnameinfo(f, f->sa_len, host, sizeof(host), NULL, 0,
				    NI_NUMERICHOST | NI_WITHSCOPEID);
		if (error)
			fatal(0, "Host name for your address unknown");
		else
			fatal(0, "Host name for your address (%s) unknown",
			      host);
	}

	(void)strncpy(fromb, host, sizeof(fromb) - 1);
	fromb[sizeof(fromb) - 1] = '\0';
	from = fromb;

	/* Need address in stringform for comparison (no DNS lookup here) */
	error = getnameinfo(f, f->sa_len, host, sizeof(host), NULL, 0,
			    NI_NUMERICHOST | NI_WITHSCOPEID);
	if (error)
		fatal(0, "Cannot print address");
	strncpy(from_ip, host, NI_MAXHOST);
	from_ip[sizeof(from_ip) - 1] = '\0';

	/* Reject numeric addresses */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
	if (getaddrinfo(fromb, NULL, &hints, &res) == 0) {
		freeaddrinfo(res);
		fatal(0, "reverse lookup results in non-FQDN %s", fromb);
	}

	/* Check for spoof, ala rlogind */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	error = getaddrinfo(fromb, NULL, &hints, &res);
	if (error) {
		fatal(0, "hostname for your address (%s) unknown: %s", from_ip,
		      gai_strerror(error));
	}
	good = 0;
	for (r = res; good == 0 && r; r = r->ai_next) {
		error = getnameinfo(r->ai_addr, r->ai_addrlen, ip, sizeof(ip),
				    NULL, 0, NI_NUMERICHOST | NI_WITHSCOPEID);
		if (!error && !strcmp(from_ip, ip))
			good = 1;
	}
	if (res)
		freeaddrinfo(res);
	if (good == 0)
		fatal(0, "address for your hostname (%s) not matched",
		    from_ip);

	hostf = fopen(_PATH_HOSTSEQUIV, "r");
again:
	if (hostf) {
		if (__ivaliduser_sa(hostf, f, f->sa_len, DUMMY, DUMMY) == 0) {
			(void) fclose(hostf);
			return;
		}
		(void) fclose(hostf);
	}
	if (first == 1) {
		first = 0;
		hostf = fopen(_PATH_HOSTSLPD, "r");
		goto again;
	}
	fatal(0, "Your host does not have line printer access");
	/*NOTREACHED*/
}

/* setup server socket for specified address family */
/* if af is PF_UNSPEC more than one socket may be returned */
/* the returned list is dynamically allocated, so caller needs to free it */
static int *
socksetup(af, options)
        int af, options;
{
	struct addrinfo hints, *res, *r;
	int error, maxs, *s, *socks;
	const int on = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(NULL, "printer", &hints, &res);
	if (error) {
		syslog(LOG_ERR, "%s", gai_strerror(error));
		mcleanup(0);
	}

	/* Count max number of sockets we may open */
	for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
		;
	socks = malloc((maxs + 1) * sizeof(int));
	if (!socks) {
		syslog(LOG_ERR, "couldn't allocate memory for sockets");
		mcleanup(0);
	}

	*socks = 0;   /* num of sockets counter at start of array */
	s = socks + 1;
	for (r = res; r; r = r->ai_next) {
		*s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (*s < 0) {
			syslog(LOG_DEBUG, "socket(): %m");
			continue;
		}
		if (options & SO_REUSEADDR)
			if (setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, &on,
				       sizeof(on)) < 0) {
				syslog(LOG_ERR, "setsockopt(SO_REUSEADDR): %m");
				close(*s);
				continue;
			}
		if (options & SO_DEBUG)
			if (setsockopt(*s, SOL_SOCKET, SO_DEBUG,
				       &on, sizeof(on)) < 0) {
				syslog(LOG_ERR, "setsockopt (SO_DEBUG): %m");
				close(*s);
				continue;
			}
#ifdef IPV6_BINDV6ONLY
		if (r->ai_family == AF_INET6) {
			if (setsockopt(*s, IPPROTO_IPV6, IPV6_BINDV6ONLY,
				       &on, sizeof(on)) < 0) {
				syslog(LOG_ERR,
				       "setsockopt (IPV6_BINDV6ONLY): %m");
				close(*s);
				continue;
			}
		}
#endif
		if (bind(*s, r->ai_addr, r->ai_addrlen) < 0) {
			syslog(LOG_DEBUG, "bind(): %m");
			close(*s);
			continue;
		}
		(*socks)++;
		s++;
	}

	if (res)
		freeaddrinfo(res);

	if (*socks == 0) {
		syslog(LOG_ERR, "Couldn't bind to any socket");
		free(socks);
		mcleanup(0);
	}
	return(socks);
}

static void
usage()
{
#ifdef INET6
	fprintf(stderr, "usage: lpd [-dlp46] [port#]\n");
#else
	fprintf(stderr, "usage: lpd [-dlp] [port#]\n");
#endif
	exit(EX_USAGE);
}
