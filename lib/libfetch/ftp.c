/*-
 * Copyright (c) 1998 Dag-Erling Co�dan Sm�rgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
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
 *
 * $FreeBSD$
 */

/*
 * Portions of this code were taken from or based on ftpio.c:
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Major Changelog:
 *
 * Dag-Erling Co�dan Sm�rgrav
 * 9 Jun 1998
 *
 * Incorporated into libfetch
 *
 * Jordan K. Hubbard
 * 17 Jan 1996
 *
 * Turned inside out. Now returns xfers as new file ids, not as a special
 * `state' of FTP_t
 *
 * $ftpioId: ftpio.c,v 1.30 1998/04/11 07:28:53 phk Exp $
 *
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fetch.h"
#include "common.h"
#include "ftperr.h"

#define FTP_ANONYMOUS_USER	"ftp"
#define FTP_ANONYMOUS_PASSWORD	"ftp"
#define FTP_DEFAULT_PORT 21

#define FTP_OPEN_DATA_CONNECTION	150
#define FTP_OK				200
#define FTP_FILE_STATUS			213
#define FTP_SERVICE_READY		220
#define FTP_PASSIVE_MODE		227
#define FTP_LPASSIVE_MODE		228
#define FTP_EPASSIVE_MODE		229
#define FTP_LOGGED_IN			230
#define FTP_FILE_ACTION_OK		250
#define FTP_NEED_PASSWORD		331
#define FTP_NEED_ACCOUNT		332
#define FTP_FILE_OK			350
#define FTP_SYNTAX_ERROR		500

static char ENDL[2] = "\r\n";

static struct url cached_host;
static int cached_socket;

static char *last_reply;
static size_t lr_size, lr_length;
static int last_code;

#define isftpreply(foo) (isdigit(foo[0]) && isdigit(foo[1]) \
			 && isdigit(foo[2]) \
                         && (foo[3] == ' ' || foo[3] == '\0'))
#define isftpinfo(foo) (isdigit(foo[0]) && isdigit(foo[1]) \
			&& isdigit(foo[2]) && foo[3] == '-')

/* translate IPv4 mapped IPv6 address to IPv4 address */
static void
unmappedaddr(struct sockaddr_in6 *sin6)
{
    struct sockaddr_in *sin4;
    u_int32_t addr;
    int port;

    if (sin6->sin6_family != AF_INET6 ||
	!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
	return;
    sin4 = (struct sockaddr_in *)sin6;
    addr = *(u_int32_t *)&sin6->sin6_addr.s6_addr[12];
    port = sin6->sin6_port;
    memset(sin4, 0, sizeof(struct sockaddr_in));
    sin4->sin_addr.s_addr = addr;
    sin4->sin_port = port;
    sin4->sin_family = AF_INET;
    sin4->sin_len = sizeof(struct sockaddr_in);
}

/*
 * Get server response
 */
static int
_ftp_chkerr(int cd)
{
    do {
	if (_fetch_getln(cd, &last_reply, &lr_size, &lr_length) == -1) {
	    _fetch_syserr();
	    return -1;
	}
#ifndef NDEBUG
	_fetch_info("got reply '%.*s'", lr_length - 2, last_reply);
#endif
    } while (isftpinfo(last_reply));

    while (lr_length && isspace(last_reply[lr_length-1]))
	lr_length--;
    last_reply[lr_length] = 0;
    
    if (!isftpreply(last_reply)) {
	_ftp_seterr(999);
	return -1;
    }

    last_code = (last_reply[0] - '0') * 100
	+ (last_reply[1] - '0') * 10
	+ (last_reply[2] - '0');

    return last_code;
}

/*
 * Send a command and check reply
 */
static int
_ftp_cmd(int cd, char *fmt, ...)
{
    va_list ap;
    struct iovec iov[2];
    char *msg;
    int r;

    va_start(ap, fmt);
    vasprintf(&msg, fmt, ap);
    va_end(ap);
    
    if (msg == NULL) {
	errno = ENOMEM;
	_fetch_syserr();
	return -1;
    }
#ifndef NDEBUG
    _fetch_info("sending '%s'", msg);
#endif
    iov[0].iov_base = msg;
    iov[0].iov_len = strlen(msg);
    iov[1].iov_base = ENDL;
    iov[1].iov_len = sizeof ENDL;
    r = writev(cd, iov, 2);
    free(msg);
    if (r == -1) {
	_fetch_syserr();
	return -1;
    }
    
    return _ftp_chkerr(cd);
}

/*
 * Transfer file
 */
static FILE *
_ftp_transfer(int cd, char *oper, char *file,
	      char *mode, off_t offset, char *flags)
{
    struct sockaddr_storage sin;
    struct sockaddr_in6 *sin6;
    struct sockaddr_in *sin4;
    int pasv, high, verbose;
    int e, sd = -1;
    socklen_t l;
    char *s;
    FILE *df;

    /* check flags */
    pasv = (flags && strchr(flags, 'p'));
    high = (flags && strchr(flags, 'h'));
    verbose = (flags && strchr(flags, 'v'));

    /* passive mode */
    if (!pasv && (s = getenv("FTP_PASSIVE_MODE")) != NULL)
	pasv = (strncasecmp(s, "no", 2) != 0);

    /* change directory */
    if (((s = strrchr(file, '/')) != NULL) && (s != file)) {
	*s = 0;
	if (verbose)
	    _fetch_info("changing directory to %s", file);
	if ((e = _ftp_cmd(cd, "CWD %s", file)) != FTP_FILE_ACTION_OK) {
	    *s = '/';
	    if (e != -1)
		_ftp_seterr(e);
	    return NULL;
	}
	*s++ = '/';
    } else {
	if (verbose)
	    _fetch_info("changing directory to /");
	if ((e = _ftp_cmd(cd, "CWD /")) != FTP_FILE_ACTION_OK) {
	    if (e != -1)
		_ftp_seterr(e);
	    return NULL;
	}
    }

    /* s now points to file name */

    /* find our own address, bind, and listen */
    l = sizeof sin;
    if (getsockname(cd, (struct sockaddr *)&sin, &l) == -1)
	goto sysouch;
    if (sin.ss_family == AF_INET6)
	unmappedaddr((struct sockaddr_in6 *)&sin);

    /* open data socket */
    if ((sd = socket(sin.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	_fetch_syserr();
	return NULL;
    }
    
    if (pasv) {
	u_char addr[64];
	char *ln, *p;
	int i;
	int port;
	
	/* send PASV command */
	if (verbose)
	    _fetch_info("setting passive mode");
	switch (sin.ss_family) {
	case AF_INET:
	    if ((e = _ftp_cmd(cd, "PASV")) != FTP_PASSIVE_MODE)
		goto ouch;
	    break;
	case AF_INET6:
	    if ((e = _ftp_cmd(cd, "EPSV")) != FTP_EPASSIVE_MODE) {
		if (e == -1)
		    goto ouch;
		if ((e = _ftp_cmd(cd, "LPSV")) != FTP_LPASSIVE_MODE)
		    goto ouch;
	    }
	    break;
	default:
	    e = 999;		/* XXX: error code should be prepared */
	    goto ouch;
	}

	/*
	 * Find address and port number. The reply to the PASV command
         * is IMHO the one and only weak point in the FTP protocol.
	 */
	ln = last_reply;
	for (p = ln + 3; *p && *p != '('; p++)
	    /* nothing */ ;
	if (!*p) {
	    e = 999;
	    goto ouch;
	}
	p++;
	switch (e) {
	case FTP_PASSIVE_MODE:
	case FTP_LPASSIVE_MODE:
	    l = (e == FTP_PASSIVE_MODE ? 6 : 21);
	    for (i = 0; *p && i < l; i++, p++)
		addr[i] = strtol(p, &p, 10);
	    if (i < l) {
		e = 999;
		goto ouch;
	    }
	    break;
	case FTP_EPASSIVE_MODE:
	    if (sscanf(p, "%c%c%c%d%c", &addr[0], &addr[1], &addr[2],
		       &port, &addr[3]) != 5 ||
		addr[0] != addr[1] ||
		addr[0] != addr[2] || addr[0] != addr[3]) {
		e = 999;
		goto ouch;
	    }
	    break;
	}

	/* seek to required offset */
	if (offset)
	    if (_ftp_cmd(cd, "REST %lu", (u_long)offset) != FTP_FILE_OK)
		goto sysouch;
	
	/* construct sockaddr for data socket */
	l = sizeof sin;
	if (getpeername(cd, (struct sockaddr *)&sin, &l) == -1)
	    goto sysouch;
	if (sin.ss_family == AF_INET6)
	    unmappedaddr((struct sockaddr_in6 *)&sin);
	switch (sin.ss_family) {
	case AF_INET6:
	    sin6 = (struct sockaddr_in6 *)&sin;
	    if (e == FTP_EPASSIVE_MODE)
		sin6->sin6_port = htons(port);
	    else {
		bcopy(addr + 2, (char *)&sin6->sin6_addr, 16);
		bcopy(addr + 19, (char *)&sin6->sin6_port, 2);
	    }
	    break;
	case AF_INET:
	    sin4 = (struct sockaddr_in *)&sin;
	    if (e == FTP_EPASSIVE_MODE)
		sin4->sin_port = htons(port);
	    else {
		bcopy(addr, (char *)&sin4->sin_addr, 4);
		bcopy(addr + 4, (char *)&sin4->sin_port, 2);
	    }
	    break;
	default:
	    e = 999;		/* XXX: error code should be prepared */
	    break;
	}

	/* connect to data port */
	if (verbose)
	    _fetch_info("opening data connection");
	if (connect(sd, (struct sockaddr *)&sin, sin.ss_len) == -1)
	    goto sysouch;

	/* make the server initiate the transfer */
	if (verbose)
	    _fetch_info("initiating transfer");
	e = _ftp_cmd(cd, "%s %s", oper, s);
	if (e != FTP_OPEN_DATA_CONNECTION)
	    goto ouch;
	
    } else {
	u_int32_t a;
	u_short p;
	int arg, d;
	char *ap;
	char hname[INET6_ADDRSTRLEN];
	
	switch (sin.ss_family) {
	case AF_INET6:
	    ((struct sockaddr_in6 *)&sin)->sin6_port = 0;
#ifdef IPV6_PORTRANGE
	    arg = high ? IPV6_PORTRANGE_HIGH : IPV6_PORTRANGE_DEFAULT;
	    if (setsockopt(sd, IPPROTO_IPV6, IPV6_PORTRANGE,
			   (char *)&arg, sizeof(arg)) == -1)
		goto sysouch;
#endif
	    break;
	case AF_INET:
	    ((struct sockaddr_in *)&sin)->sin_port = 0;
	    arg = high ? IP_PORTRANGE_HIGH : IP_PORTRANGE_DEFAULT;
	    if (setsockopt(sd, IPPROTO_IP, IP_PORTRANGE,
			   (char *)&arg, sizeof arg) == -1)
		goto sysouch;
	    break;
	}
	if (verbose)
	    _fetch_info("binding data socket");
	if (bind(sd, (struct sockaddr *)&sin, sin.ss_len) == -1)
	    goto sysouch;
	if (listen(sd, 1) == -1)
	    goto sysouch;

	/* find what port we're on and tell the server */
	if (getsockname(sd, (struct sockaddr *)&sin, &l) == -1)
	    goto sysouch;
	switch (sin.ss_family) {
	case AF_INET:
	    sin4 = (struct sockaddr_in *)&sin;
	    a = ntohl(sin4->sin_addr.s_addr);
	    p = ntohs(sin4->sin_port);
	    e = _ftp_cmd(cd, "PORT %d,%d,%d,%d,%d,%d",
			 (a >> 24) & 0xff, (a >> 16) & 0xff,
			 (a >> 8) & 0xff, a & 0xff,
			 (p >> 8) & 0xff, p & 0xff);
	    break;
	case AF_INET6:
#define UC(b)	(((int)b)&0xff)
	    e = -1;
	    sin6 = (struct sockaddr_in6 *)&sin;
	    if (getnameinfo((struct sockaddr *)&sin, sin.ss_len,
			    hname, sizeof(hname),
			    NULL, 0, NI_NUMERICHOST) == 0) {
		e = _ftp_cmd(cd, "EPRT |%d|%s|%d|", 2, hname,
			     htons(sin6->sin6_port));
		if (e == -1)
		    goto ouch;
	    }
	    if (e != FTP_OK) {
		ap = (char *)&sin6->sin6_addr;
		e = _ftp_cmd(cd,
     "LPRT %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
			     6, 16,
			     UC(ap[0]), UC(ap[1]), UC(ap[2]), UC(ap[3]),
			     UC(ap[4]), UC(ap[5]), UC(ap[6]), UC(ap[7]),
			     UC(ap[8]), UC(ap[9]), UC(ap[10]), UC(ap[11]),
			     UC(ap[12]), UC(ap[13]), UC(ap[14]), UC(ap[15]),
			     2,
			     (ntohs(sin6->sin6_port) >> 8) & 0xff,
			     ntohs(sin6->sin6_port)        & 0xff);
	    }
	    break;
	default:
	    e = 999;		/* XXX: error code should be prepared */
	    goto ouch;
	}
	if (e != FTP_OK)
	    goto ouch;

	/* make the server initiate the transfer */
	if (verbose)
	    _fetch_info("initiating transfer");
	e = _ftp_cmd(cd, "%s %s", oper, s);
	if (e != FTP_OPEN_DATA_CONNECTION)
	    goto ouch;
	
	/* accept the incoming connection and go to town */
	if ((d = accept(sd, NULL, NULL)) == -1)
	    goto sysouch;
	close(sd);
	sd = d;
    }

    if ((df = fdopen(sd, mode)) == NULL)
	goto sysouch;
    return df;

sysouch:
    _fetch_syserr();
    if (sd >= 0)
	close(sd);
    return NULL;

ouch:
    if (e != -1)
	_ftp_seterr(e);
    if (sd >= 0)
	close(sd);
    return NULL;
}

/*
 * Log on to FTP server
 */
static int
_ftp_connect(char *host, int port, char *user, char *pwd, char *flags)
{
    int cd, e, pp = 0, direct, verbose;
#ifdef INET6
    int af = AF_UNSPEC;
#else
    int af = AF_INET;
#endif
    char *p, *q;
    const char *logname;
    char localhost[MAXHOSTNAMELEN];
    char pbuf[MAXHOSTNAMELEN + MAXLOGNAME + 1];

    direct = (flags && strchr(flags, 'd'));
    verbose = (flags && strchr(flags, 'v'));
    if ((flags && strchr(flags, '4')))
	af = AF_INET;
    else if ((flags && strchr(flags, '6')))
	af = AF_INET6;

    /* check for proxy */
    if (!direct && (p = getenv("FTP_PROXY")) != NULL) {
	char c = 0;

#ifdef INET6
	if (*p != '[' || (q = strchr(p + 1, ']')) == NULL ||
	    (*++q != '\0' && *q != ':'))
#endif
	    q = strchr(p, ':');
	if (q != NULL && *q == ':') {
	    if (strspn(q+1, "0123456789") != strlen(q+1) || strlen(q+1) > 5) {
		/* XXX we should emit some kind of warning */
	    }
	    pp = atoi(q+1);
	    if (pp < 1 || pp > 65535) {
		/* XXX we should emit some kind of warning */
	    }
	}
	if (!pp) {
	    struct servent *se;
	    
	    if ((se = getservbyname("ftp", "tcp")) != NULL)
		pp = ntohs(se->s_port);
	    else
		pp = FTP_DEFAULT_PORT;
	}
	if (q) {
#ifdef INET6
	    if (q > p && *p == '[' && *(q - 1) == ']') {
		p++;
		q--;
	    }
#endif
	    c = *q;
	    *q = 0;
	}
	cd = _fetch_connect(p, pp, af, verbose);
	if (q)
	    *q = c;
    } else {
	/* no proxy, go straight to target */
	cd = _fetch_connect(host, port, af, verbose);
	p = NULL;
    }

    /* check connection */
    if (cd == -1) {
	_fetch_syserr();
	return NULL;
    }

    /* expect welcome message */
    if ((e = _ftp_chkerr(cd)) != FTP_SERVICE_READY)
	goto fouch;
    
    /* send user name and password */
    if (!user || !*user)
	user = FTP_ANONYMOUS_USER;
    e = p ? _ftp_cmd(cd, "USER %s@%s@%d", user, host, port)
	  : _ftp_cmd(cd, "USER %s", user);
    
    /* did the server request a password? */
    if (e == FTP_NEED_PASSWORD) {
	if (!pwd || !*pwd)
	    pwd = getenv("FTP_PASSWORD");
	if (!pwd || !*pwd) {
	    if ((logname = getlogin()) == 0)
		logname = FTP_ANONYMOUS_PASSWORD;
	    gethostname(localhost, sizeof localhost);
	    snprintf(pbuf, sizeof pbuf, "%s@%s", logname, localhost);
	    pwd = pbuf;
	}
	e = _ftp_cmd(cd, "PASS %s", pwd);
    }

    /* did the server request an account? */
    if (e == FTP_NEED_ACCOUNT)
	goto fouch;
    
    /* we should be done by now */
    if (e != FTP_LOGGED_IN)
	goto fouch;

    /* might as well select mode and type at once */
#ifdef FTP_FORCE_STREAM_MODE
    if ((e = _ftp_cmd(cd, "MODE S")) != FTP_OK) /* default is S */
	goto fouch;
#endif
    if ((e = _ftp_cmd(cd, "TYPE I")) != FTP_OK) /* default is A */
	goto fouch;

    /* done */
    return cd;
    
fouch:
    if (e != -1)
	_ftp_seterr(e);
    close(cd);
    return NULL;
}

/*
 * Disconnect from server
 */
static void
_ftp_disconnect(int cd)
{
    (void)_ftp_cmd(cd, "QUIT");
    close(cd);
}

/*
 * Check if we're already connected
 */
static int
_ftp_isconnected(struct url *url)
{
    return (cached_socket
	    && (strcmp(url->host, cached_host.host) == 0)
	    && (strcmp(url->user, cached_host.user) == 0)
	    && (strcmp(url->pwd, cached_host.pwd) == 0)
	    && (url->port == cached_host.port));
}

/*
 * Check the cache, reconnect if no luck
 */
static int
_ftp_cached_connect(struct url *url, char *flags)
{
    int e, cd;

    cd = -1;
    
    /* set default port */
    if (!url->port) {
	struct servent *se;
	
	if ((se = getservbyname("ftp", "tcp")) != NULL)
	    url->port = ntohs(se->s_port);
	else
	    url->port = FTP_DEFAULT_PORT;
    }
    
    /* try to use previously cached connection */
    if (_ftp_isconnected(url)) {
	e = _ftp_cmd(cached_socket, "NOOP");
	if (e == FTP_OK || e == FTP_SYNTAX_ERROR)
	    cd = cached_socket;
    }

    /* connect to server */
    if (cd == -1) {
	cd = _ftp_connect(url->host, url->port, url->user, url->pwd, flags);
	if (cd == -1)
	    return -1;
	if (cached_socket)
	    _ftp_disconnect(cached_socket);
	cached_socket = cd;
	memcpy(&cached_host, url, sizeof *url);
    }

    return cd;
}

/*
 * Get file
 */
FILE *
fetchGetFTP(struct url *url, char *flags)
{
    int cd;
    
    /* connect to server */
    if ((cd = _ftp_cached_connect(url, flags)) == NULL)
	return NULL;
    
    /* initiate the transfer */
    return _ftp_transfer(cd, "RETR", url->doc, "r", url->offset, flags);
}

/*
 * Put file
 */
FILE *
fetchPutFTP(struct url *url, char *flags)
{
    int cd;

    /* connect to server */
    if ((cd = _ftp_cached_connect(url, flags)) == NULL)
	return NULL;
    
    /* initiate the transfer */
    return _ftp_transfer(cd, (flags && strchr(flags, 'a')) ? "APPE" : "STOR",
			 url->doc, "w", url->offset, flags);
}

/*
 * Get file stats
 */
int
fetchStatFTP(struct url *url, struct url_stat *us, char *flags)
{
    char *ln, *s;
    struct tm tm;
    time_t t;
    int e, cd;

    us->size = -1;
    us->atime = us->mtime = 0;
    
    /* connect to server */
    if ((cd = _ftp_cached_connect(url, flags)) == NULL)
	return -1;

    /* change directory */
    if (((s = strrchr(url->doc, '/')) != NULL) && (s != url->doc)) {
	*s = 0;
	if ((e = _ftp_cmd(cd, "CWD %s", url->doc)) != FTP_FILE_ACTION_OK) {
	    *s = '/';
	    goto ouch;
	}
	*s++ = '/';
    } else {
	if ((e = _ftp_cmd(cd, "CWD /")) != FTP_FILE_ACTION_OK)
	    goto ouch;
    }

    /* s now points to file name */
    
    if (_ftp_cmd(cd, "SIZE %s", s) != FTP_FILE_STATUS)
	goto ouch;
    for (ln = last_reply + 4; *ln && isspace(*ln); ln++)
	/* nothing */ ;
    for (us->size = 0; *ln && isdigit(*ln); ln++)
	us->size = us->size * 10 + *ln - '0';
    if (*ln && !isspace(*ln)) {
	_ftp_seterr(999);
	return -1;
    }
    DEBUG(fprintf(stderr, "size: [\033[1m%lld\033[m]\n", us->size));

    if ((e = _ftp_cmd(cd, "MDTM %s", s)) != FTP_FILE_STATUS)
	goto ouch;
    for (ln = last_reply + 4; *ln && isspace(*ln); ln++)
	/* nothing */ ;
    e = 999;
    switch (strspn(ln, "0123456789")) {
    case 14:
	break;
    case 15:
	ln++;
	ln[0] = '2';
	ln[1] = '0';
	break;
    default:
	goto ouch;
    }
    if (sscanf(ln, "%04d%02d%02d%02d%02d%02d",
	       &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
	       &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
	goto ouch;
    tm.tm_mon--;
    tm.tm_year -= 1900;
    tm.tm_isdst = -1;
    t = timegm(&tm);
    if (t == (time_t)-1)
	t = time(NULL);
    us->mtime = t;
    us->atime = t;
    DEBUG(fprintf(stderr, "last modified: [\033[1m%04d-%02d-%02d "
		  "%02d:%02d:%02d\033[m]\n",
		  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		  tm.tm_hour, tm.tm_min, tm.tm_sec));
    return 0;

ouch:
    if (e != -1)
	_ftp_seterr(e);
    return -1;
}

/*
 * List a directory
 */
extern void warnx(char *, ...);
struct url_ent *
fetchListFTP(struct url *url, char *flags)
{
    warnx("fetchListFTP(): not implemented");
    return NULL;
}
