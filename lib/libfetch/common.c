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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <ctype.h> /* XXX */
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fetch.h"
#include "common.h"


/*** Local data **************************************************************/

/*
 * Error messages for resolver errors
 */
static struct fetcherr _netdb_errlist[] = {
	{ EAI_NODATA,	FETCH_RESOLV,	"Host not found" },
	{ EAI_AGAIN,	FETCH_TEMP,	"Transient resolver failure" },
	{ EAI_FAIL,	FETCH_RESOLV,	"Non-recoverable resolver failure" },
	{ EAI_NONAME,	FETCH_RESOLV,	"No address record" },
	{ -1,		FETCH_UNKNOWN,	"Unknown resolver error" }
};

/* End-of-Line */
static const char ENDL[2] = "\r\n";


/*** Error-reporting functions ***********************************************/

/*
 * Map error code to string
 */
static struct fetcherr *
_fetch_finderr(struct fetcherr *p, int e)
{
	while (p->num != -1 && p->num != e)
		p++;
	return (p);
}

/*
 * Set error code
 */
void
_fetch_seterr(struct fetcherr *p, int e)
{
	p = _fetch_finderr(p, e);
	fetchLastErrCode = p->cat;
	snprintf(fetchLastErrString, MAXERRSTRING, "%s", p->string);
}

/*
 * Set error code according to errno
 */
void
_fetch_syserr(void)
{
	switch (errno) {
	case 0:
		fetchLastErrCode = FETCH_OK;
		break;
	case EPERM:
	case EACCES:
	case EROFS:
	case EAUTH:
	case ENEEDAUTH:
		fetchLastErrCode = FETCH_AUTH;
		break;
	case ENOENT:
	case EISDIR: /* XXX */
		fetchLastErrCode = FETCH_UNAVAIL;
		break;
	case ENOMEM:
		fetchLastErrCode = FETCH_MEMORY;
		break;
	case EBUSY:
	case EAGAIN:
		fetchLastErrCode = FETCH_TEMP;
		break;
	case EEXIST:
		fetchLastErrCode = FETCH_EXISTS;
		break;
	case ENOSPC:
		fetchLastErrCode = FETCH_FULL;
		break;
	case EADDRINUSE:
	case EADDRNOTAVAIL:
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case EHOSTUNREACH:
		fetchLastErrCode = FETCH_NETWORK;
		break;
	case ECONNABORTED:
	case ECONNRESET:
		fetchLastErrCode = FETCH_ABORT;
		break;
	case ETIMEDOUT:
		fetchLastErrCode = FETCH_TIMEOUT;
		break;
	case ECONNREFUSED:
	case EHOSTDOWN:
		fetchLastErrCode = FETCH_DOWN;
		break;
default:
		fetchLastErrCode = FETCH_UNKNOWN;
	}
	snprintf(fetchLastErrString, MAXERRSTRING, "%s", strerror(errno));
}


/*
 * Emit status message
 */
void
_fetch_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}


/*** Network-related utility functions ***************************************/

/*
 * Return the default port for a scheme
 */
int
_fetch_default_port(const char *scheme)
{
	struct servent *se;

	if ((se = getservbyname(scheme, "tcp")) != NULL)
		return (ntohs(se->s_port));
	if (strcasecmp(scheme, SCHEME_FTP) == 0)
		return (FTP_DEFAULT_PORT);
	if (strcasecmp(scheme, SCHEME_HTTP) == 0)
		return (HTTP_DEFAULT_PORT);
	return (0);
}

/*
 * Return the default proxy port for a scheme
 */
int
_fetch_default_proxy_port(const char *scheme)
{
	if (strcasecmp(scheme, SCHEME_FTP) == 0)
		return (FTP_DEFAULT_PROXY_PORT);
	if (strcasecmp(scheme, SCHEME_HTTP) == 0)
		return (HTTP_DEFAULT_PROXY_PORT);
	return (0);
}

/*
 * Create a connection for an existing descriptor.
 */
conn_t *
_fetch_reopen(int sd)
{
	conn_t *conn;

	/* allocate and fill connection structure */
	if ((conn = calloc(1, sizeof *conn)) == NULL)
		return (NULL);
	conn->sd = sd;
	return (conn);
}


/*
 * Establish a TCP connection to the specified port on the specified host.
 */
conn_t *
_fetch_connect(const char *host, int port, int af, int verbose)
{
	conn_t *conn;
	char pbuf[10];
	struct addrinfo hints, *res, *res0;
	int sd, err;

	DEBUG(fprintf(stderr, "---> %s:%d\n", host, port));

	if (verbose)
		_fetch_info("looking up %s", host);

	/* look up host name and set up socket address structure */
	snprintf(pbuf, sizeof(pbuf), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	if ((err = getaddrinfo(host, pbuf, &hints, &res0)) != 0) {
		_netdb_seterr(err);
		return (NULL);
	}

	if (verbose)
		_fetch_info("connecting to %s:%d", host, port);

	/* try to connect */
	for (sd = -1, res = res0; res; res = res->ai_next) {
		if ((sd = socket(res->ai_family, res->ai_socktype,
			 res->ai_protocol)) == -1)
			continue;
		if (connect(sd, res->ai_addr, res->ai_addrlen) != -1)
			break;
		close(sd);
		sd = -1;
	}
	freeaddrinfo(res0);
	if (sd == -1) {
		_fetch_syserr();
		return (NULL);
	}

	if ((conn = _fetch_reopen(sd)) == NULL)
		close(sd);
	return (conn);
}


/*
 * Read a character from a connection w/ timeout
 */
ssize_t
_fetch_read(conn_t *conn, char *buf, size_t len)
{
	struct timeval now, timeout, wait;
	fd_set readfds;
	ssize_t rlen, total;
	int r;

	if (fetchTimeout) {
		FD_ZERO(&readfds);
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
	}

	total = 0;
	while (len > 0) {
		while (fetchTimeout && !FD_ISSET(conn->sd, &readfds)) {
			FD_SET(conn->sd, &readfds);
			gettimeofday(&now, NULL);
			wait.tv_sec = timeout.tv_sec - now.tv_sec;
			wait.tv_usec = timeout.tv_usec - now.tv_usec;
			if (wait.tv_usec < 0) {
				wait.tv_usec += 1000000;
				wait.tv_sec--;
			}
			if (wait.tv_sec < 0)
				return (rlen);
			errno = 0;
			r = select(conn->sd + 1, &readfds, NULL, NULL, &wait);
			if (r == -1) {
				if (errno == EINTR && fetchRestartCalls)
					continue;
				return (-1);
			}
		}
		if (conn->ssl != NULL)
			rlen = SSL_read(conn->ssl, buf, len);
		else
			rlen = read(conn->sd, buf, len);
		if (rlen == 0)
			break;
		if (rlen < 0) {
			if (errno == EINTR && fetchRestartCalls)
				continue;
			return (-1);
		}
		len -= rlen;
		buf += rlen;
		total += rlen;
	}
	return (total);
}

/*
 * Read a line of text from a connection w/ timeout
 */
#define MIN_BUF_SIZE 1024

int
_fetch_getln(conn_t *conn)
{
	char *tmp;
	size_t tmpsize;
	char c;

	if (conn->buf == NULL) {
		if ((conn->buf = malloc(MIN_BUF_SIZE)) == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		conn->bufsize = MIN_BUF_SIZE;
	}

	conn->buf[0] = '\0';
	conn->buflen = 0;

	do {
		if (_fetch_read(conn, &c, 1) == -1)
			return (-1);
		conn->buf[conn->buflen++] = c;
		if (conn->buflen == conn->bufsize) {
			tmp = conn->buf;
			tmpsize = conn->bufsize * 2 + 1;
			if ((tmp = realloc(tmp, tmpsize)) == NULL) {
				errno = ENOMEM;
				return (-1);
			}
			conn->buf = tmp;
			conn->bufsize = tmpsize;
		}
	} while (c != '\n');

	conn->buf[conn->buflen] = '\0';
	DEBUG(fprintf(stderr, "<<< %s", conn->buf));
	return (0);
}


/*
 * Write to a connection w/ timeout
 */
ssize_t
_fetch_write(conn_t *conn, const char *buf, size_t len)
{
	struct timeval now, timeout, wait;
	fd_set writefds;
	ssize_t wlen, total;
	int r;

	if (fetchTimeout) {
		FD_ZERO(&writefds);
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
	}

	while (len > 0) {
		while (fetchTimeout && !FD_ISSET(conn->sd, &writefds)) {
			FD_SET(conn->sd, &writefds);
			gettimeofday(&now, NULL);
			wait.tv_sec = timeout.tv_sec - now.tv_sec;
			wait.tv_usec = timeout.tv_usec - now.tv_usec;
			if (wait.tv_usec < 0) {
				wait.tv_usec += 1000000;
				wait.tv_sec--;
			}
			if (wait.tv_sec < 0) {
				errno = ETIMEDOUT;
				return (-1);
			}
			errno = 0;
			r = select(conn->sd + 1, NULL, &writefds, NULL, &wait);
			if (r == -1) {
				if (errno == EINTR && fetchRestartCalls)
					continue;
				return (-1);
			}
		}
		errno = 0;
		if (conn->ssl != NULL)
			wlen = SSL_write(conn->ssl, buf, len);
		else
			wlen = write(conn->sd, buf, len);
		if (wlen == 0)
			/* we consider a short write a failure */
			return (-1);
		if (wlen < 0) {
			if (errno == EINTR && fetchRestartCalls)
				continue;
			return (-1);
		}
		len -= wlen;
		buf += wlen;
		total += wlen;
	}
	return (total);
}

/*
 * Write a line of text to a connection w/ timeout
 */
int
_fetch_putln(conn_t *conn, const char *str, size_t len)
{
	if (_fetch_write(conn, str, len) == -1 ||
	    _fetch_write(conn, ENDL, sizeof ENDL) == -1)
		return (-1);
	return (0);
}


/*
 * Close connection
 */
int
_fetch_close(conn_t *conn)
{
	int ret;

	ret = close(conn->sd);
	free(conn);
	return (ret);
}


/*** Directory-related utility functions *************************************/

int
_fetch_add_entry(struct url_ent **p, int *size, int *len,
    const char *name, struct url_stat *us)
{
	struct url_ent *tmp;

	if (*p == NULL) {
		*size = 0;
		*len = 0;
	}

	if (*len >= *size - 1) {
		tmp = realloc(*p, (*size * 2 + 1) * sizeof **p);
		if (tmp == NULL) {
			errno = ENOMEM;
			_fetch_syserr();
			return (-1);
		}
		*size = (*size * 2 + 1);
		*p = tmp;
	}

	tmp = *p + *len;
	snprintf(tmp->name, PATH_MAX, "%s", name);
	bcopy(us, &tmp->stat, sizeof *us);

	(*len)++;
	(++tmp)->name[0] = 0;

	return (0);
}
