/*
 * Copyright (c) 1983, 1993, 1994
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
 *
 * $FreeBSD$
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)rcmd.c	8.3 (Berkeley) 3/26/94";
#endif /* LIBC_SCCS and not lint */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifdef YP
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#endif
#include <arpa/nameser.h>

/* wrapper for KAME-special getnameinfo() */
#ifndef NI_WITHSCOPEID
#define NI_WITHSCOPEID	0
#endif

extern int innetgr __P(( const char *, const char *, const char *, const char * ));

#define max(a, b)	((a > b) ? a : b)

static int __iruserok_af __P((void *, int, const char *, const char *, int));
int	__ivaliduser __P((FILE *, u_int32_t, const char *, const char *));
static int __icheckhost __P((void *, char *, int, int));

char paddr[INET6_ADDRSTRLEN];

int
rcmd(ahost, rport, locuser, remuser, cmd, fd2p)
	char **ahost;
	u_short rport;
	const char *locuser, *remuser, *cmd;
	int *fd2p;
{
	return rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p, AF_INET);
}

int
rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p, af)
	char **ahost;
	u_short rport;
	const char *locuser, *remuser, *cmd;
	int *fd2p;
	int af;
{
	struct addrinfo hints, *res, *ai;
	struct sockaddr_storage from;
	fd_set reads;
	long oldmask;
	pid_t pid;
	int s, aport, lport, timo, error;
	char c;
	int refused;
	char num[8];
	static char canonnamebuf[MAXDNAME];	/* is it proper here? */

	pid = getpid();

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	(void)snprintf(num, sizeof(num), "%d", ntohs(rport));
	error = getaddrinfo(*ahost, num, &hints, &res);
	if (error) {
		fprintf(stderr, "rcmd: getaddrinfo: %s\n",
			gai_strerror(error));
		if (error == EAI_SYSTEM)
			fprintf(stderr, "rcmd: getaddrinfo: %s\n",
				strerror(errno));
		return (-1);
	}

	if (res->ai_canonname
	 && strlen(res->ai_canonname) + 1 < sizeof(canonnamebuf)) {
		strncpy(canonnamebuf, res->ai_canonname, sizeof(canonnamebuf));
		*ahost = canonnamebuf;
	}
	ai = res;
	refused = 0;
	oldmask = sigblock(sigmask(SIGURG));
	for (timo = 1, lport = IPPORT_RESERVED - 1;;) {
		s = rresvport_af(&lport, ai->ai_family);
		if (s < 0) {
			if (errno != EAGAIN && ai->ai_next) {
				ai = ai->ai_next;
				continue;
			}
			if (errno == EAGAIN)
				(void)fprintf(stderr,
				    "rcmd: socket: All ports in use\n");
			else
				(void)fprintf(stderr, "rcmd: socket: %s\n",
				    strerror(errno));
			freeaddrinfo(res);
			sigsetmask(oldmask);
			return (-1);
		}
		_fcntl(s, F_SETOWN, pid);
		if (connect(s, ai->ai_addr, ai->ai_addrlen) >= 0)
			break;
		(void)_close(s);
		if (errno == EADDRINUSE) {
			lport--;
			continue;
		}
		if (errno == ECONNREFUSED)
			refused = 1;
		if (ai->ai_next != NULL) {
			int oerrno = errno;

			getnameinfo(ai->ai_addr, ai->ai_addrlen,
				    paddr, sizeof(paddr),
				    NULL, 0,
				    NI_NUMERICHOST|NI_WITHSCOPEID);
			(void)fprintf(stderr, "connect to address %s: ",
				      paddr);
			errno = oerrno;
			perror(0);
			ai = ai->ai_next;
			getnameinfo(ai->ai_addr, ai->ai_addrlen,
				    paddr, sizeof(paddr),
				    NULL, 0,
				    NI_NUMERICHOST|NI_WITHSCOPEID);
			fprintf(stderr, "Trying %s...\n", paddr);
			continue;
		}
		if (refused && timo <= 16) {
			struct timespec time_to_sleep, time_remaining;

			time_to_sleep.tv_sec = timo;
			time_to_sleep.tv_nsec = 0;
			(void)_nanosleep(&time_to_sleep, &time_remaining);
			
			timo *= 2;
			ai = res;
			refused = 0;
			continue;
		}
		(void)fprintf(stderr, "%s: %s\n", *ahost, strerror(errno));
		freeaddrinfo(res);
		sigsetmask(oldmask);
		return (-1);
	}
	lport--;
	if (fd2p == 0) {
		_write(s, "", 1);
		lport = 0;
	} else {
		char num[8];
		int s2 = rresvport_af(&lport, ai->ai_family), s3;
		int len = ai->ai_addrlen;
		int nfds;

		if (s2 < 0)
			goto bad;
		listen(s2, 1);
		(void)snprintf(num, sizeof(num), "%d", lport);
		if (_write(s, num, strlen(num)+1) != strlen(num)+1) {
			(void)fprintf(stderr,
			    "rcmd: write (setting up stderr): %s\n",
			    strerror(errno));
			(void)_close(s2);
			goto bad;
		}
		nfds = max(s, s2)+1;
		if(nfds > FD_SETSIZE) {
			fprintf(stderr, "rcmd: too many files\n");
			(void)_close(s2);
			goto bad;
		}
again:
		FD_ZERO(&reads);
		FD_SET(s, &reads);
		FD_SET(s2, &reads);
		errno = 0;
		if (select(nfds, &reads, 0, 0, 0) < 1 || !FD_ISSET(s2, &reads)){
			if (errno != 0)
				(void)fprintf(stderr,
				    "rcmd: select (setting up stderr): %s\n",
				    strerror(errno));
			else
				(void)fprintf(stderr,
				"select: protocol failure in circuit setup\n");
			(void)_close(s2);
			goto bad;
		}
		s3 = accept(s2, (struct sockaddr *)&from, &len);
		switch (from.ss_family) {
		case AF_INET:
			aport = ntohs(((struct sockaddr_in *)&from)->sin_port);
			break;
#ifdef INET6
		case AF_INET6:
			aport = ntohs(((struct sockaddr_in6 *)&from)->sin6_port);
			break;
#endif
		default:
			aport = 0;	/* error */
			break;
		}
		/*
		 * XXX careful for ftp bounce attacks. If discovered, shut them
		 * down and check for the real auxiliary channel to connect.
		 */
		if (aport == 20) {
			_close(s3);
			goto again;
		}
		(void)_close(s2);
		if (s3 < 0) {
			(void)fprintf(stderr,
			    "rcmd: accept: %s\n", strerror(errno));
			lport = 0;
			goto bad;
		}
		*fd2p = s3;
		if (aport >= IPPORT_RESERVED || aport < IPPORT_RESERVED / 2) {
			(void)fprintf(stderr,
			    "socket: protocol failure in circuit setup.\n");
			goto bad2;
		}
	}
	(void)_write(s, locuser, strlen(locuser)+1);
	(void)_write(s, remuser, strlen(remuser)+1);
	(void)_write(s, cmd, strlen(cmd)+1);
	if (_read(s, &c, 1) != 1) {
		(void)fprintf(stderr,
		    "rcmd: %s: %s\n", *ahost, strerror(errno));
		goto bad2;
	}
	if (c != 0) {
		while (_read(s, &c, 1) == 1) {
			(void)_write(STDERR_FILENO, &c, 1);
			if (c == '\n')
				break;
		}
		goto bad2;
	}
	sigsetmask(oldmask);
	freeaddrinfo(res);
	return (s);
bad2:
	if (lport)
		(void)_close(*fd2p);
bad:
	(void)_close(s);
	sigsetmask(oldmask);
	freeaddrinfo(res);
	return (-1);
}

int
rresvport(port)
	int *port;
{
	return rresvport_af(port, AF_INET);
}

int
rresvport_af(alport, family)
	int *alport, family;
{
	int i, s, len, err;
	struct sockaddr_storage ss;
	u_short *sport;

	memset(&ss, 0, sizeof(ss));
	ss.ss_family = family;
	switch (family) {
	case AF_INET:
		((struct sockaddr *)&ss)->sa_len = sizeof(struct sockaddr_in);
		sport = &((struct sockaddr_in *)&ss)->sin_port;
		((struct sockaddr_in *)&ss)->sin_addr.s_addr = INADDR_ANY;
		break;
#ifdef INET6
	case AF_INET6:
		((struct sockaddr *)&ss)->sa_len = sizeof(struct sockaddr_in6);
		sport = &((struct sockaddr_in6 *)&ss)->sin6_port;
		((struct sockaddr_in6 *)&ss)->sin6_addr = in6addr_any;
		break;
#endif
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	s = socket(ss.ss_family, SOCK_STREAM, 0);
	if (s < 0)
		return (-1);
#if 0 /* compat_exact_traditional_rresvport_semantics */
	sin.sin_port = htons((u_short)*alport);
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) >= 0)
		return (s);
	if (errno != EADDRINUSE) {
		(void)_close(s);
		return (-1);
	}
#endif
	*sport = 0;
	if (bindresvport_sa(s, (struct sockaddr *)&ss) == -1) {
		(void)_close(s);
		return (-1);
	}
	*alport = (int)ntohs(*sport);
	return (s);
}

int	__check_rhosts_file = 1;
char	*__rcmd_errstr;

int
ruserok(rhost, superuser, ruser, luser)
	const char *rhost, *ruser, *luser;
	int superuser;
{
	struct addrinfo hints, *res, *r;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	error = getaddrinfo(rhost, "0", &hints, &res);
	if (error)
		return (-1);

	for (r = res; r; r = r->ai_next) {
		if (iruserok_sa(r->ai_addr, r->ai_addrlen, superuser, ruser,
		    luser) == 0) {
			freeaddrinfo(res);
			return (0);
		}
	}
	freeaddrinfo(res);
	return (-1);
}

/*
 * New .rhosts strategy: We are passed an ip address. We spin through
 * hosts.equiv and .rhosts looking for a match. When the .rhosts only
 * has ip addresses, we don't have to trust a nameserver.  When it
 * contains hostnames, we spin through the list of addresses the nameserver
 * gives us and look for a match.
 *
 * Returns 0 if ok, -1 if not ok.
 */
int
iruserok(raddr, superuser, ruser, luser)
	unsigned long raddr;
	int superuser;
	const char *ruser, *luser;
{
	return __iruserok_af(&raddr, superuser, ruser, luser, AF_INET);
}

/* Other AF support extension of iruserok. */
static int
__iruserok_af(raddr, superuser, ruser, luser, af)
	void *raddr;
	int superuser;
	const char *ruser, *luser;
	int af;
{
	register char *cp;
	struct stat sbuf;
	struct passwd *pwd;
	FILE *hostf;
	uid_t uid;
	int first;
	char pbuf[MAXPATHLEN];
	int len = 0;

	switch (af) {
	case AF_INET:
		len = sizeof(struct in_addr);
		break;
#ifdef INET6
	case AF_INET6:
		len = sizeof(struct in6_addr);
		break;
#endif
	}

	first = 1;
	hostf = superuser ? NULL : fopen(_PATH_HEQUIV, "r");
again:
	if (hostf) {
		if (__ivaliduser_af(hostf, raddr, luser, ruser, af, len)
		    == 0) {
			(void)fclose(hostf);
			return (0);
		}
		(void)fclose(hostf);
	}
	if (first == 1 && (__check_rhosts_file || superuser)) {
		first = 0;
		if ((pwd = getpwnam(luser)) == NULL)
			return (-1);
		(void)strcpy(pbuf, pwd->pw_dir);
		(void)strcat(pbuf, "/.rhosts");

		/*
		 * Change effective uid while opening .rhosts.  If root and
		 * reading an NFS mounted file system, can't read files that
		 * are protected read/write owner only.
		 */
		uid = geteuid();
		(void)seteuid(pwd->pw_uid);
		hostf = fopen(pbuf, "r");
		(void)seteuid(uid);

		if (hostf == NULL)
			return (-1);
		/*
		 * If not a regular file, or is owned by someone other than
		 * user or root or if writeable by anyone but the owner, quit.
		 */
		cp = NULL;
		if (lstat(pbuf, &sbuf) < 0)
			cp = ".rhosts lstat failed";
		else if (!S_ISREG(sbuf.st_mode))
			cp = ".rhosts not regular file";
		else if (fstat(fileno(hostf), &sbuf) < 0)
			cp = ".rhosts fstat failed";
		else if (sbuf.st_uid && sbuf.st_uid != pwd->pw_uid)
			cp = "bad .rhosts owner";
		else if (sbuf.st_mode & (S_IWGRP|S_IWOTH))
			cp = ".rhosts writeable by other than owner";
		/* If there were any problems, quit. */
		if (cp) {
			__rcmd_errstr = cp;
			(void)fclose(hostf);
			return (-1);
		}
		goto again;
	}
	return (-1);
}

/*
 * AF independent extension of iruserok. We are passed an sockaddr, and
 * then call iruserok_af() as the type of sockaddr.
 *
 * Returns 0 if ok, -1 if not ok.
 */
int
iruserok_sa(addr, addrlen, superuser, ruser, luser)
	const void *addr;
	int addrlen;
	int superuser;
	const char *ruser, *luser;
{
	struct sockaddr *sa;
	void *raddr = NULL;

	sa = (struct sockaddr *)addr;
	switch (sa->sa_family) {
	case AF_INET:
		raddr = &((struct sockaddr_in *)sa)->sin_addr;
		break;
#ifdef INET6
	case AF_INET6:
		raddr = &((struct sockaddr_in6 *)sa)->sin6_addr;
		break;
#endif
	}

	__iruserok_af(raddr, superuser, ruser, luser, sa->sa_family);
}

/*
 * XXX
 * Don't make static, used by lpd(8).
 *
 * Returns 0 if ok, -1 if not ok.
 */
int
__ivaliduser(hostf, raddr, luser, ruser)
	FILE *hostf;
	u_int32_t raddr;
	const char *luser, *ruser;
{
	return __ivaliduser_af(hostf, &raddr, luser, ruser, AF_INET,
			       sizeof(raddr));
}

int
__ivaliduser_af(hostf, raddr, luser, ruser, af, len)
	FILE *hostf;
	void *raddr;
	const char *luser, *ruser;
	int af, len;
{
	register char *user, *p;
	int ch;
	char buf[MAXHOSTNAMELEN + 128];		/* host + login */
	char hname[MAXHOSTNAMELEN];
	struct hostent *hp;
	/* Presumed guilty until proven innocent. */
	int userok = 0, hostok = 0;
	int h_error;
#ifdef YP
	char *ypdomain;

	if (yp_get_default_domain(&ypdomain))
		ypdomain = NULL;
#else
#define	ypdomain NULL
#endif
	/* We need to get the damn hostname back for netgroup matching. */
	if ((hp = getipnodebyaddr((char *)raddr, len, af, &h_error)) == NULL)
		return (-1);
	strncpy(hname, hp->h_name, sizeof(hname));
	hname[sizeof(hname) - 1] = '\0';
	freehostent(hp);

	while (fgets(buf, sizeof(buf), hostf)) {
		p = buf;
		/* Skip lines that are too long. */
		if (strchr(p, '\n') == NULL) {
			while ((ch = getc(hostf)) != '\n' && ch != EOF);
			continue;
		}
		if (*p == '\n' || *p == '#') {
			/* comment... */
			continue;
		}
		while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0') {
			*p = isupper((unsigned char)*p) ? tolower((unsigned char)*p) : *p;
			p++;
		}
		if (*p == ' ' || *p == '\t') {
			*p++ = '\0';
			while (*p == ' ' || *p == '\t')
				p++;
			user = p;
			while (*p != '\n' && *p != ' ' &&
			    *p != '\t' && *p != '\0')
				p++;
		} else
			user = p;
		*p = '\0';
		/*
		 * Do +/- and +@/-@ checking. This looks really nasty,
		 * but it matches SunOS's behavior so far as I can tell.
		 */
		switch(buf[0]) {
		case '+':
			if (!buf[1]) {     /* '+' matches all hosts */
				hostok = 1;
				break;
			}
			if (buf[1] == '@')  /* match a host by netgroup */
				hostok = innetgr((char *)&buf[2],
					(char *)&hname, NULL, ypdomain);
			else		/* match a host by addr */
				hostok = __icheckhost(raddr,(char *)&buf[1],
						      af, len);
			break;
		case '-':     /* reject '-' hosts and all their users */
			if (buf[1] == '@') {
				if (innetgr((char *)&buf[2],
					      (char *)&hname, NULL, ypdomain))
					return(-1);
			} else {
				if (__icheckhost(raddr,(char *)&buf[1],af,len))
					return(-1);
			}
			break;
		default:  /* if no '+' or '-', do a simple match */
			hostok = __icheckhost(raddr, buf, af, len);
			break;
		}
		switch(*user) {
		case '+':
			if (!*(user+1)) {      /* '+' matches all users */
				userok = 1;
				break;
			}
			if (*(user+1) == '@')  /* match a user by netgroup */
				userok = innetgr(user+2, NULL, ruser, ypdomain);
			else	   /* match a user by direct specification */
				userok = !(strcmp(ruser, user+1));
			break;
		case '-': 		/* if we matched a hostname, */
			if (hostok) {   /* check for user field rejections */
				if (!*(user+1))
					return(-1);
				if (*(user+1) == '@') {
					if (innetgr(user+2, NULL,
							ruser, ypdomain))
						return(-1);
				} else {
					if (!strcmp(ruser, user+1))
						return(-1);
				}
			}
			break;
		default:	/* no rejections: try to match the user */
			if (hostok)
				userok = !(strcmp(ruser,*user ? user : luser));
			break;
		}
		if (hostok && userok)
			return(0);
	}
	return (-1);
}

/*
 * Returns "true" if match, 0 if no match.
 */
static int
__icheckhost(raddr, lhost, af, len)
	void *raddr;
	register char *lhost;
	int af, len;
{
	register struct hostent *hp;
	char laddr[BUFSIZ]; /* xxx */
	register char **pp;
	int h_error;
	int match;

	/* Try for raw ip address first. */
	if (inet_pton(af, lhost, laddr) == 1) {
		if (memcmp(raddr, laddr, len) == 0)
			return (1);
		else
			return (0);
	}

	/* Better be a hostname. */
	if ((hp = getipnodebyname(lhost, af, AI_ALL|AI_DEFAULT, &h_error))
	    == NULL)
		return (0);

	/* Spin through ip addresses. */
	match = 0;
	for (pp = hp->h_addr_list; *pp; ++pp)
		if (!bcmp(raddr, *pp, len)) {
			match = 1;
			break;
		}

	freehostent(hp);
	return (match);
}
