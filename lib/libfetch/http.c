/*-
 * Copyright (c) 2000 Dag-Erling Co�dan Sm�rgrav
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
 *    derived from this software without specific prior written permission.
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
 *      $FreeBSD$
 */

/*
 * The following copyright applies to the base64 code:
 *
 *-
 * Copyright 1997 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fetch.h"
#include "common.h"
#include "httperr.h"

extern char *__progname; /* XXX not portable */

/* Maximum number of redirects to follow */
#define MAX_REDIRECT 5

/* Symbolic names for reply codes we care about */
#define HTTP_OK			200
#define HTTP_PARTIAL		206
#define HTTP_MOVED_PERM		301
#define HTTP_MOVED_TEMP		302
#define HTTP_SEE_OTHER		303
#define HTTP_NEED_AUTH		401
#define HTTP_NEED_PROXY_AUTH	403
#define HTTP_PROTOCOL_ERROR	999

#define HTTP_REDIRECT(xyz) ((xyz) == HTTP_MOVED_PERM \
                            || (xyz) == HTTP_MOVED_TEMP \
                            || (xyz) == HTTP_SEE_OTHER)



/*****************************************************************************
 * I/O functions for decoding chunked streams
 */

struct cookie
{
    int		 fd;
    char	*buf;
    size_t	 b_size;
    size_t	 b_len;
    int		 b_pos;
    int		 eof;
    int		 error;
    long	 chunksize;
#ifdef DEBUG
    long	 total;
#endif
};

/*
 * Get next chunk header
 */
static int
_http_new_chunk(struct cookie *c)
{
    char *p;
    
    if (_fetch_getln(c->fd, &c->buf, &c->b_size, &c->b_len) == -1)
	return -1;
    
    if (c->b_len < 2 || !ishexnumber(*c->buf))
	return -1;
    
    for (p = c->buf; !isspace(*p) && *p != ';' && p < c->buf + c->b_len; ++p)
	if (!ishexnumber(*p))
	    return -1;
	else if (isdigit(*p))
	    c->chunksize = c->chunksize * 16 + *p - '0';
	else
	    c->chunksize = c->chunksize * 16 + 10 + tolower(*p) - 'a';
    
#ifdef DEBUG
    c->total += c->chunksize;
    if (c->chunksize == 0)
	fprintf(stderr, "\033[1m_http_fillbuf(): "
		"end of last chunk\033[m\n");
    else
	fprintf(stderr, "\033[1m_http_fillbuf(): "
		"new chunk: %ld (%ld)\033[m\n", c->chunksize, c->total);
#endif
    
    return c->chunksize;
}

/*
 * Fill the input buffer, do chunk decoding on the fly
 */
static int
_http_fillbuf(struct cookie *c)
{
    if (c->error)
	return -1;
    if (c->eof)
	return 0;
    
    if (c->chunksize == 0) {
	switch (_http_new_chunk(c)) {
	case -1:
	    c->error = 1;
	    return -1;
	case 0:
	    c->eof = 1;
	    return 0;
	}
    }

    if (c->b_size < c->chunksize) {
	char *tmp;

	if ((tmp = realloc(c->buf, c->chunksize)) == NULL)
	    return -1;
	c->buf = tmp;
	c->b_size = c->chunksize;
    }
    
    if ((c->b_len = read(c->fd, c->buf, c->chunksize)) == -1)
	return -1;
    c->chunksize -= c->b_len;
    
    if (c->chunksize == 0) {
	char endl[2];
	read(c->fd, endl, 2);
    }
    
    c->b_pos = 0;
    
    return c->b_len;
}

/*
 * Read function
 */
static int
_http_readfn(void *v, char *buf, int len)
{
    struct cookie *c = (struct cookie *)v;
    int l, pos;

    if (c->error)
	return -1;
    if (c->eof)
	return 0;

    for (pos = 0; len > 0; pos += l, len -= l) {
	/* empty buffer */
	if (!c->buf || c->b_pos == c->b_len)
	    if (_http_fillbuf(c) < 1)
		break;
	l = c->b_len - c->b_pos;
	if (len < l)
	    l = len;
	bcopy(c->buf + c->b_pos, buf + pos, l);
	c->b_pos += l;
    }

    if (!pos && c->error)
	return -1;
    return pos;
}

/*
 * Write function
 */
static int
_http_writefn(void *v, const char *buf, int len)
{
    struct cookie *c = (struct cookie *)v;
    
    return write(c->fd, buf, len);
}

/*
 * Close function
 */
static int
_http_closefn(void *v)
{
    struct cookie *c = (struct cookie *)v;
    int r;

    r = close(c->fd);
    if (c->buf)
	free(c->buf);
    free(c);
    return r;
}

/*
 * Wrap a file descriptor up
 */
static FILE *
_http_funopen(int fd)
{
    struct cookie *c;
    FILE *f;

    if ((c = calloc(1, sizeof *c)) == NULL) {
	_fetch_syserr();
	return NULL;
    }
    c->fd = fd;
    if (!(f = funopen(c, _http_readfn, _http_writefn, NULL, _http_closefn))) {
	_fetch_syserr();
	free(c);
	return NULL;
    }
    return f;
}


/*****************************************************************************
 * Helper functions for talking to the server and parsing its replies
 */

/* Header types */
typedef enum {
    hdr_syserror = -2,
    hdr_error = -1,
    hdr_end = 0,
    hdr_unknown = 1,
    hdr_content_length,
    hdr_content_range,
    hdr_last_modified,
    hdr_location,
    hdr_transfer_encoding
} hdr;

/* Names of interesting headers */
static struct {
    hdr		 num;
    char	*name;
} hdr_names[] = {
    { hdr_content_length,	"Content-Length" },
    { hdr_content_range,	"Content-Range" },
    { hdr_last_modified,	"Last-Modified" },
    { hdr_location,		"Location" },
    { hdr_transfer_encoding,	"Transfer-Encoding" },
    { hdr_unknown,		NULL },
};

static char	*reply_buf;
static size_t	 reply_size;
static size_t	 reply_length;

/*
 * Send a formatted line; optionally echo to terminal
 */
static int
_http_cmd(int fd, char *fmt, ...)
{
    va_list ap;
    size_t len;
    char *msg;
    int r;

    va_start(ap, fmt);
    len = vasprintf(&msg, fmt, ap);
    va_end(ap);
    
    if (msg == NULL) {
	errno = ENOMEM;
	_fetch_syserr();
	return -1;
    }
    
    r = _fetch_putln(fd, msg, len);
    free(msg);
    
    if (r == -1) {
	_fetch_syserr();
	return -1;
    }
    
    return 0;
}

/*
 * Get and parse status line
 */
static int
_http_get_reply(int fd)
{
    if (_fetch_getln(fd, &reply_buf, &reply_size, &reply_length) == -1)
	return -1;
    /*
     * A valid status line looks like "HTTP/m.n xyz reason" where m
     * and n are the major and minor protocol version numbers and xyz
     * is the reply code.
     * We grok HTTP 1.0 and 1.1, so m must be 1 and n must be 0 or 1.
     * We don't care about the reason phrase.
     */
    if (strncmp(reply_buf, "HTTP/1.", 7) != 0
	|| (reply_buf[7] != '0' && reply_buf[7] != '1') || reply_buf[8] != ' '
	|| !isdigit(reply_buf[9])
	|| !isdigit(reply_buf[10])
	|| !isdigit(reply_buf[11]))
	return HTTP_PROTOCOL_ERROR;
    
    return ((reply_buf[9] - '0') * 100
	    + (reply_buf[10] - '0') * 10
	    + (reply_buf[11] - '0'));
}

/*
 * Check a header; if the type matches the given string, return a
 * pointer to the beginning of the value.
 */
static char *
_http_match(char *str, char *hdr)
{
    while (*str && *hdr && tolower(*str++) == tolower(*hdr++))
	/* nothing */;
    if (*str || *hdr != ':')
	return NULL;
    while (*hdr && isspace(*++hdr))
	/* nothing */;
    return hdr;
}

/*
 * Get the next header and return the appropriate symbolic code.
 */
static hdr
_http_next_header(int fd, char **p)
{
    int i;
    
    if (_fetch_getln(fd, &reply_buf, &reply_size, &reply_length) == -1)
	return hdr_syserror;
    while (reply_length && isspace(reply_buf[reply_length-1]))
	reply_length--;
    reply_buf[reply_length] = 0;
    if (reply_length == 0)
	return hdr_end;
    /*
     * We could check for malformed headers but we don't really care.
     * A valid header starts with a token immediately followed by a
     * colon; a token is any sequence of non-control, non-whitespace
     * characters except "()<>@,;:\\\"{}".
     */
    for (i = 0; hdr_names[i].num != hdr_unknown; i++)
	if ((*p = _http_match(hdr_names[i].name, reply_buf)) != NULL)
	    return hdr_names[i].num;
    return hdr_unknown;
}

/*
 * Parse a last-modified header
 */
static time_t
_http_parse_mtime(char *p)
{
    char locale[64];
    struct tm tm;

    strncpy(locale, setlocale(LC_TIME, NULL), sizeof locale);
    setlocale(LC_TIME, "C");
    strptime(p, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    /* XXX should add support for date-2 and date-3 */
    setlocale(LC_TIME, locale);
    DEBUG(fprintf(stderr, "last modified: [\033[1m%04d-%02d-%02d "
		  "%02d:%02d:%02d\033[m]\n",
		  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		  tm.tm_hour, tm.tm_min, tm.tm_sec));
    return timegm(&tm);
}

/*
 * Parse a content-length header
 */
static off_t
_http_parse_length(char *p)
{
    off_t len;
    
    for (len = 0; *p && isdigit(*p); ++p)
	len = len * 10 + (*p - '0');
    DEBUG(fprintf(stderr, "content length: [\033[1m%lld\033[m]\n", len));
    return len;
}

/*
 * Parse a content-range header
 */
static off_t
_http_parse_range(char *p)
{
    off_t off;
    
    if (strncasecmp(p, "bytes ", 6) != 0)
	return -1;
    for (p += 6, off = 0; *p && isdigit(*p); ++p)
	off = off * 10 + *p - '0';
    if (*p != '-')
	return -1;
    DEBUG(fprintf(stderr, "content range: [\033[1m%lld-\033[m]\n", off));
    return off;
}


/*****************************************************************************
 * Helper functions for authorization
 */

/*
 * Base64 encoding
 */
static char *
_http_base64(char *src)
{
    static const char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";
    char *str, *dst;
    size_t l;
    int t, r;

    l = strlen(src);
    if ((str = malloc(((l + 2) / 3) * 4)) == NULL)
	return NULL;
    dst = str;
    r = 0;
    
    while (l >= 3) {
	t = (src[0] << 16) | (src[1] << 8) | src[2];
	dst[0] = base64[(t >> 18) & 0x3f];
	dst[1] = base64[(t >> 12) & 0x3f];
	dst[2] = base64[(t >> 6) & 0x3f];
	dst[3] = base64[(t >> 0) & 0x3f];
	src += 3; l -= 3;
	dst += 4; r += 4;
    }

    switch (l) {
    case 2:
	t = (src[0] << 16) | (src[1] << 8);
	dst[0] = base64[(t >> 18) & 0x3f];
	dst[1] = base64[(t >> 12) & 0x3f];
	dst[2] = base64[(t >> 6) & 0x3f];
	dst[3] = '=';
	dst += 4;
	r += 4;
	break;
    case 1:
	t = src[0] << 16;
	dst[0] = base64[(t >> 18) & 0x3f];
	dst[1] = base64[(t >> 12) & 0x3f];
	dst[2] = dst[3] = '=';
	dst += 4;
	r += 4;
	break;
    case 0:
	break;
    }

    *dst = 0;
    return str;
}

/*
 * Encode username and password
 */
static int
_http_basic_auth(int fd, char *hdr, char *usr, char *pwd)
{
    char *upw, *auth;
    int r;

    if (asprintf(&upw, "%s:%s", usr, pwd) == -1)
	return -1;
    auth = _http_base64(upw);
    free(upw);
    if (auth == NULL)
	return -1;
    r = _http_cmd(fd, "%s: Basic %s", hdr, auth);
    free(auth);
    return r;
}

/*
 * Send an authorization header
 */
static int
_http_authorize(int fd, char *hdr, char *p)
{
    /* basic authorization */
    if (strncasecmp(p, "basic:", 6) == 0) {
	char *user, *pwd, *str;
	int r;

	/* skip realm */
	for (p += 6; *p && *p != ':'; ++p)
	    /* nothing */ ;
	if (!*p || strchr(++p, ':') == NULL)
	    return -1;
	if ((str = strdup(p)) == NULL)
	    return -1; /* XXX */
	user = str;
	pwd = strchr(str, ':');
	*pwd++ = '\0';
	r = _http_basic_auth(fd, hdr, user, pwd);
	free(str);
	return r;
    }
    return -1;
}


/*****************************************************************************
 * Helper functions for connecting to a server or proxy
 */

/*
 * Connect to the specified HTTP proxy server.
 */
static int
_http_proxy_connect(char *proxy, int af, int verbose)
{
    char *hostname, *p;
    int fd, port;

    /* get hostname */
    hostname = NULL;
#ifdef INET6
    /* host part can be an IPv6 address enclosed in square brackets */
    if (*proxy == '[') {
	if ((p = strchr(proxy, ']')) == NULL) {
	    /* no terminating bracket */
	    /* XXX should set an error code */
	    goto ouch;
	}
	if (p[1] != '\0' && p[1] != ':') {
	    /* garbage after address */
	    /* XXX should set an error code */
	    goto ouch;
	}
	if ((hostname = malloc(p - proxy)) == NULL) {
	    errno = ENOMEM;
	    _fetch_syserr();
	    goto ouch;
	}
	strncpy(hostname, proxy + 1, p - proxy - 1);
	hostname[p - proxy - 1] = '\0';
	++p;
    } else {
#endif /* INET6 */
	if ((p = strchr(proxy, ':')) == NULL)
	    p = strchr(proxy, '\0');
	if ((hostname = malloc(p - proxy + 1)) == NULL) {
	    errno = ENOMEM;
	    _fetch_syserr();
	    goto ouch;
	}
	strncpy(hostname, proxy, p - proxy);
	hostname[p - proxy] = '\0';
#ifdef INET6
    }
#endif /* INET6 */
    DEBUG(fprintf(stderr, "proxy name: [%s]\n", hostname));
    
    /* get port number */
    port = 0;
    if (*p == ':') {
	++p;
	if (strspn(p, "0123456789") != strlen(p) || strlen(p) > 5) {
	    /* port number is non-numeric or too long */
	    /* XXX should set an error code */
	    goto ouch;
	}
	port = atoi(p);
	if (port < 1 || port > 65535) {
	    /* port number is out of range */
	    /* XXX should set an error code */
	    goto ouch;
	}
    }
    
    if (!port) {
#if 0
	/*
	 * commented out, since there is currently no service name
	 * for HTTP proxies
	 */
	struct servent *se;
	
	if ((se = getservbyname("xxxx", "tcp")) != NULL)
	    port = ntohs(se->s_port);
	else
#endif
	    port = 3128;
    }
    DEBUG(fprintf(stderr, "proxy port: %d\n", port));
	
    /* connect */
    if ((fd = _fetch_connect(hostname, port, af, verbose)) == -1)
	_fetch_syserr();
    return fd;
    
 ouch:
    if (hostname)
	free(hostname);
    return -1;
}

/*
 * Connect to the correct HTTP server or proxy. 
 */
static int
_http_connect(struct url *URL, int *proxy, char *flags)
{
    int direct, verbose;
    int af, fd;
    char *p;
    
#ifdef INET6
    af = AF_UNSPEC;
#else
    af = AF_INET;
#endif

    direct = (flags && strchr(flags, 'd'));
    verbose = (flags && strchr(flags, 'v'));
    if (flags && strchr(flags, '4'))
	af = AF_INET;
    else if (flags && strchr(flags, '6'))
	af = AF_INET6;
    
    /* check port */
    if (!URL->port) {
	struct servent *se;

	/* Scheme can be ftp if we're using a proxy */
	if (strcasecmp(URL->scheme, "ftp") == 0)
	    if ((se = getservbyname("ftp", "tcp")) != NULL)
		URL->port = ntohs(se->s_port);
	    else
		URL->port = 21;
	else
	    if ((se = getservbyname("http", "tcp")) != NULL)
		URL->port = ntohs(se->s_port);
	    else
		URL->port = 80;
    }
    
    if (!direct && (p = getenv("HTTP_PROXY")) != NULL) {
	/* attempt to connect to proxy server */
	if ((fd = _http_proxy_connect(p, af, verbose)) == -1)
	    return -1;
	*proxy = 1;
    } else {
	/* if no proxy is configured, try direct */
	if (strcasecmp(URL->scheme, "ftp") == 0) {
	    /* can't talk http to an ftp server */
	    /* XXX should set an error code */
	    return -1;
	}
	if ((fd = _fetch_connect(URL->host, URL->port, af, verbose)) == -1)
	    /* _fetch_connect() has already set an error code */
	    return -1;
	*proxy = 0;
    }

    return fd;
}


/*****************************************************************************
 * Core
 */

/*
 * Send a request and process the reply
 */
static FILE *
_http_request(struct url *URL, char *op, struct url_stat *us, char *flags)
{
    struct url *url, *new;
    int chunked, need_auth, noredirect, proxy, verbose;
    int code, fd, i, n;
    off_t offset;
    char *p;
    FILE *f;
    hdr h;
    char *host;
#ifdef INET6
    char hbuf[MAXHOSTNAMELEN + 1];
#endif

    noredirect = (flags && strchr(flags, 'A'));
    verbose = (flags && strchr(flags, 'v'));

    n = noredirect ? 1 : MAX_REDIRECT;

    /* just to appease compiler warnings */
    code = HTTP_PROTOCOL_ERROR;
    chunked = 0;
    offset = 0;
    fd = -1;
    
    for (url = URL, i = 0; i < n; ++i) {
	new = NULL;
	us->size = -1;
	us->atime = us->mtime = 0;
	chunked = 0;
	need_auth = 0;
	offset = 0;
	fd = -1;
    retry:
	/* connect to server or proxy */
	if ((fd = _http_connect(url, &proxy, flags)) == -1)
	    goto ouch;

	host = url->host;
#ifdef INET6
	if (strchr(url->host, ':')) {
	    snprintf(hbuf, sizeof(hbuf), "[%s]", url->host);
	    host = hbuf;
	}
#endif

	/* send request */
	if (verbose)
	    _fetch_info("requesting %s://%s:%d%s",
			url->scheme, host, url->port, url->doc);
	if (proxy) {
	    _http_cmd(fd, "%s %s://%s:%d%s HTTP/1.1",
		      op, url->scheme, host, url->port, url->doc);
	} else {
	    _http_cmd(fd, "%s %s HTTP/1.1",
		      op, url->doc);
	}

	/* proxy authorization */
	if (proxy && (p = getenv("HTTP_PROXY_AUTH")) != NULL)
	    _http_authorize(fd, "Proxy-Authorization", p);
	
	/* server authorization */
	if (need_auth) {
	    if (*url->user || *url->pwd)
		_http_basic_auth(fd, "Authorization",
				 url->user ? url->user : "",
				 url->pwd ? url->pwd : "");
	    else if ((p = getenv("HTTP_AUTH")) != NULL)
		_http_authorize(fd, "Authorization", p);
	    else {
		_http_seterr(HTTP_NEED_AUTH);
		goto ouch;
	    }
	}

	/* other headers */
	_http_cmd(fd, "Host: %s:%d", host, url->port);
	_http_cmd(fd, "User-Agent: %s " _LIBFETCH_VER, __progname);
	if (URL->offset)
	    _http_cmd(fd, "Range: bytes=%lld-", url->offset);
	_http_cmd(fd, "Connection: close");
	_http_cmd(fd, "");

	/* get reply */
	switch ((code = _http_get_reply(fd))) {
	case HTTP_OK:
	case HTTP_PARTIAL:
	    /* fine */
	    break;
	case HTTP_MOVED_PERM:
	case HTTP_MOVED_TEMP:
	    /*
	     * Not so fine, but we still have to read the headers to
	     * get the new location.
	     */
	    break;
	case HTTP_NEED_AUTH:
	    if (need_auth) {
		/*
		 * We already sent out authorization code, so there's
		 * nothing more we can do.
		 */
		_http_seterr(code);
		goto ouch;
	    }
	    /* try again, but send the password this time */
	    if (verbose)
		_fetch_info("server requires authorization");
	    need_auth = 1;
	    close(fd);
	    goto retry;
	case HTTP_NEED_PROXY_AUTH:
	    /*
	     * If we're talking to a proxy, we already sent our proxy
	     * authorization code, so there's nothing more we can do.
	     */
	    _http_seterr(code);
	    goto ouch;
	case HTTP_PROTOCOL_ERROR:
	    /* fall through */
	case -1:
	    _fetch_syserr();
	    goto ouch;
	default:
	    _http_seterr(code);
	    goto ouch;
	}
	
	/* get headers */
	do {
	    switch ((h = _http_next_header(fd, &p))) {
	    case hdr_syserror:
		_fetch_syserr();
		goto ouch;
	    case hdr_error:
		_http_seterr(HTTP_PROTOCOL_ERROR);
		goto ouch;
	    case hdr_content_length:
		us->size = _http_parse_length(p);
		break;
	    case hdr_content_range:
		offset = _http_parse_range(p);
		break;
	    case hdr_last_modified:
		us->atime = us->mtime = _http_parse_mtime(p);
		break;
	    case hdr_location:
		if (!HTTP_REDIRECT(code))
		    break;
		if (new)
		    free(new);
		if (verbose)
		    _fetch_info("%d redirect to %s", code, p);
		if (*p == '/')
		    /* absolute path */
		    new = fetchMakeURL(url->scheme, url->host, url->port, p,
				       url->user, url->pwd);
		else
		    new = fetchParseURL(p);
		if (new == NULL) {
		    /* XXX should set an error code */
		    DEBUG(fprintf(stderr, "failed to parse new URL\n"));
		    goto ouch;
		}
		if (!*new->user && !*new->pwd) {
		    strcpy(new->user, url->user);
		    strcpy(new->pwd, url->pwd);
		}
		new->offset = url->offset;
		new->length = url->length;
		break;
	    case hdr_transfer_encoding:	
		/* XXX weak test*/
		chunked = (strcasecmp(p, "chunked") == 0);
		break;
	    case hdr_end:
		/* fall through */
	    case hdr_unknown:
		/* ignore */
		break;
	    }
	} while (h > hdr_end);

	/* we either have a hit, or a redirect with no Location: header */
	if (code == HTTP_OK || code == HTTP_PARTIAL || !new)
	    break;

	/* we have a redirect */
	close(fd);
	if (url != URL)
	    fetchFreeURL(url);
	url = new;
    }

    /* no success */
    if (fd == -1) {
	_http_seterr(code);
	goto ouch;
    }

    /* wrap it up in a FILE */
    if ((f = chunked ? _http_funopen(fd) : fdopen(fd, "r")) == NULL) {
	_fetch_syserr();
	goto ouch;
    }

    while (offset++ < url->offset)
	if (fgetc(f) == EOF) {
	    _fetch_syserr();
	    fclose(f);
	    f = NULL;
	}
    
    if (url != URL)
	fetchFreeURL(url);
    
    return f;

 ouch:
    if (url != URL)
	fetchFreeURL(url);
    if (fd != -1)
	close(fd);
    return NULL;
}


/*****************************************************************************
 * Entry points
 */

/*
 * Retrieve a file by HTTP
 */
FILE *
fetchGetHTTP(struct url *URL, char *flags)
{
    struct url_stat us;
    
    return _http_request(URL, "GET", &us, flags);
}

FILE *
fetchPutHTTP(struct url *URL, char *flags)
{
    warnx("fetchPutHTTP(): not implemented");
    return NULL;
}

/*
 * Get an HTTP document's metadata
 */
int
fetchStatHTTP(struct url *URL, struct url_stat *us, char *flags)
{
    FILE *f;
    
    if ((f = _http_request(URL, "HEAD", us, flags)) == NULL)
	return -1;
    fclose(f);
    return 0;
}

/*
 * List a directory
 */
struct url_ent *
fetchListHTTP(struct url *url, char *flags)
{
    warnx("fetchListHTTP(): not implemented");
    return NULL;
}
