/*
 * Copyright (c) 1995
 *	Bill Paul <wpaul@ctr.columbia.edu>. All rights reserved.
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
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: yp_dnslookup.c,v 1.5 1996/12/22 15:45:33 wpaul Exp $
 */

/*
 * Do standard and reverse DNS lookups using the resolver library.
 * Take care of all the dirty work here so the main program only has to
 * pass us a pointer to an array of characters.
 *
 * We have to use direct resolver calls here otherwise the YP server
 * could end up looping by calling itself over and over again until
 * it disappeared up its own belly button.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <stdio.h>
#include <ctype.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <rpcsvc/yp.h>
#include "yp_extern.h"

#ifndef lint
static const char rcsid[] = "$Id: yp_dnslookup.c,v 1.5 1996/12/22 15:45:33 wpaul Exp $";
#endif

static char *parse(hp)
	struct hostent *hp;
{
	static char result[MAXHOSTNAMELEN * 2];
	int len,i;
	struct in_addr addr;

	if (hp == NULL)
		return(NULL);

	len = 16 + strlen(hp->h_name);
	for (i = 0; hp->h_aliases[i]; i++)
		len += strlen(hp->h_aliases[i]) + 1;

	bzero(result, sizeof(result));

	bcopy(hp->h_addr, &addr, sizeof(struct in_addr));
	snprintf(result, sizeof(result), "%s %s", inet_ntoa(addr), hp->h_name);

	for (i = 0; hp->h_aliases[i]; i++) {
		strcat(result, " ");
		strcat(result, hp->h_aliases[i]);
	}

	return ((char *)&result);
}

#define MAXPACKET 1024
#define DEF_TTL 50

extern struct hostent *__dns_getanswer __P((char *, int, char *, int));

static CIRCLEQ_HEAD(dns_qhead, circleq_dnsentry) qhead;

struct circleq_dnsentry {
	SVCXPRT *xprt;
	unsigned long xid;
	struct sockaddr_in client_addr;
	unsigned long id;
	unsigned long ttl;
	unsigned long sent;
	unsigned long type;
	char **domain;
	char *name;
	struct in_addr addr;
	CIRCLEQ_ENTRY(circleq_dnsentry) links;
};

static int pending = 0;

int yp_init_resolver()
{
	CIRCLEQ_INIT(&qhead);
	if (!(_res.options & RES_INIT) && res_init() == -1) {
		yp_error("res_init failed");
		return(1);
	}
	if ((resfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		yp_error("couldn't create socket");
		return(1);
	}
	if (fcntl(resfd, F_SETFL, O_NONBLOCK) == -1) {
		yp_error("couldn't make resolver socket non-blocking");
		return(1);
	}
	return(0);
}

int yp_dnsq_pending()
{
	return(pending);
}

static struct circleq_dnsentry *yp_malloc_dnsent()
{
	register struct circleq_dnsentry *q;

	q = (struct circleq_dnsentry *)malloc(sizeof(struct circleq_dnsentry));

	if (q == NULL) {
		yp_error("failed to malloc() circleq dns entry: %s",
							strerror(errno));
		return(NULL);
	}

	return(q);
}

/*
 * Transmit a query.
 */
static unsigned long yp_send_dns_query(name, type)
	char *name;
	int type;
{
	char buf[MAXPACKET];
	int n;
	HEADER *hptr;
	int ns;
	int rval;
	unsigned long id;

	bzero(buf, sizeof(buf));

	n = res_mkquery(QUERY,name,C_IN,type,NULL,0,NULL,buf,sizeof(buf));

	if (n <= 0) {
		yp_error("res_mkquery failed");
		return(0);
	}

	hptr = (HEADER *)&buf;
	id = ntohs(hptr->id);

	for (ns = 0; ns < _res.nscount; ns++) {
		rval = sendto(resfd, buf, n, 0,
			(struct sockaddr *)&_res.nsaddr_list[ns],
				sizeof(struct sockaddr));
		if (rval == -1) {
			yp_error("sendto failed");
			return(0);
		}
	}

	return(id);
}

static struct circleq_dnsentry *yp_find_dnsqent(id)
	unsigned long id;
{
	register struct circleq_dnsentry *q;

	for (q = qhead.cqh_first; q != (void *)&qhead; q = q->links.cqe_next) {
		if (q->id == id)
			return(q);
	}
	return (NULL);
}

static void yp_send_dns_reply(q, buf)
	struct circleq_dnsentry *q;
	char *buf;
{
	ypresp_val result;
	unsigned long xid;
	struct sockaddr_in client_addr;

	bzero((char *)&result, sizeof(result));

	if (buf == NULL)
		result.stat = YP_NOKEY;
	else {
		result.val.valdat_len = strlen(buf);
		result.val.valdat_val = buf;
		result.stat = YP_TRUE;
	}

	if (debug)
		yp_error("Sending dns reply to %s (%lu)",
					inet_ntoa(q->client_addr.sin_addr),
					q->id);

	/*
	 * XXX This is disgusting. There's basically one transport
	 * handle for UDP, but we're holding off on replying to a
	 * client until we're ready, by which time we may have received
	 * several other queries from other clients with different
	 * transaction IDs. So to make the delayed response thing work,
	 * we have to save the transaction ID and client address of
	 * each request, then jam them into the transport handle when
	 * we're ready to send a reply. Then after we've send the reply,
	 * we put the old transaction ID and remote address back the
	 * way we found 'em. This is _INCREDIBLY_ non-portable; it's
	 * not even supported by the RPC library.
	 */
	xid = svcudp_set_xid(q->xprt, q->xid);
	client_addr = q->xprt->xp_raddr;
	q->xprt->xp_raddr = q->client_addr;
	if (!svc_sendreply(q->xprt, xdr_ypresp_val, (char *)&result))
		yp_error("svc_sendreply failed");
	svcudp_set_xid(q->xprt, xid);
	q->xprt->xp_raddr = client_addr;
	return;
}

void yp_prune_dnsq()
{
	register struct circleq_dnsentry *q;

	for (q = qhead.cqh_first; q != (void *)&qhead; q = q->links.cqe_next) {
		q->ttl--;
		if (!q->ttl) {
			CIRCLEQ_REMOVE(&qhead, q, links);
			free(q->name);
			free(q);
			pending--;
		}
	}

	if (pending < 0)
		pending = 0;

	return;
}

void yp_run_dnsq()
{
	register struct circleq_dnsentry *q;
	char buf[sizeof(HEADER) + MAXPACKET];
	struct sockaddr_in sin;
	int rval;
	int len;
	HEADER *hptr;
	struct hostent *hent;

	if (debug)
		yp_error("Running dns queue");

	bzero(buf, sizeof(buf));

	len = sizeof(struct sockaddr_in);
	rval = recvfrom(resfd, buf, sizeof(buf), 0,
			(struct sockaddr *)&sin, &len);

	if (rval == -1) {
		yp_error("recvfrom failed: %s", strerror(errno));
		return;
	}

	hptr = (HEADER *)&buf;
	if ((q = yp_find_dnsqent(ntohs(hptr->id))) == NULL) {
		/* bogus id -- ignore */
		return;
	}

	if (debug)
		yp_error("Got dns reply from %s", inet_ntoa(sin.sin_addr));

	hent = __dns_getanswer(buf, rval, q->name, q->type);

	if (hent == NULL) {
		char retrybuf[MAXHOSTNAMELEN];

		if (q->domain && *q->domain) {
			snprintf(retrybuf, sizeof(retrybuf), "%s.%s",
						q->name, *q->domain);
			if (debug)
				yp_error("Retrying with: %s", retrybuf);
			q->id = yp_send_dns_query(retrybuf, q->type);
			q->ttl = DEF_TTL;
			q->domain++;
			return;
		}
	}

	if (q->type == T_PTR) {
		hent->h_addr = (char *)&q->addr.s_addr;
		hent->h_length = sizeof(struct in_addr);
	}
	yp_send_dns_reply(q, parse(hent));

	pending--;
	CIRCLEQ_REMOVE(&qhead, q, links);
	free(q->name);
	free(q);

	yp_prune_dnsq();

	return;
}

ypstat yp_async_lookup_name(xprt, name)
	SVCXPRT	*xprt;
	char *name;
{
	register struct circleq_dnsentry *q;

	if ((q = yp_malloc_dnsent()) == NULL)
		return(YP_YPERR);

	q->type = T_A;
	q->ttl = DEF_TTL;
	q->sent = 1;
	q->xprt = xprt;
	q->xid = svcudp_get_xid(xprt);
	q->client_addr = xprt->xp_raddr;
	if (!strchr(name, '.'))
		q->domain = _res.dnsrch;
	else
		q->domain = NULL;
	q->id = yp_send_dns_query(name, q->type);

	if (q->id == 0) {
		yp_error("DNS query failed");
		free(q);
		return(YP_YPERR);
	}

	q->name = strdup(name);
	CIRCLEQ_INSERT_HEAD(&qhead, q, links);
	pending++;

	if (debug)
		yp_error("Queueing async DNS name lookup (%d)", q->id);

	return(YP_TRUE);
}

ypstat yp_async_lookup_addr(xprt, addr)
	SVCXPRT *xprt;
	char *addr;
{
	register struct circleq_dnsentry *q;
	char buf[MAXHOSTNAMELEN];
	int a, b, c, d;

	if ((q = yp_malloc_dnsent()) == NULL)
		return(YP_YPERR);

	if (sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
		return(YP_NOKEY);

	snprintf(buf, sizeof(buf), "%d.%d.%d.%d.in-addr.arpa",
					d, c, b, a, addr);

	if (debug)
		yp_error("DNS address is: %s", buf);

	q->type = T_PTR;
	q->ttl = DEF_TTL;
	q->sent = 1;
	q->xprt = xprt;
	q->domain = NULL;
	q->xid = svcudp_get_xid(xprt);
	q->client_addr = xprt->xp_raddr;
	q->id = yp_send_dns_query(buf, q->type);

	if (q->id == 0) {
		yp_error("DNS query failed");
		free(q);
		return(YP_YPERR);
	}

	inet_aton(addr, &q->addr);
	q->name = strdup(buf);
	CIRCLEQ_INSERT_HEAD(&qhead, q, links);
	pending++;

	if (debug)
		yp_error("Queueing async DNS address lookup (%d)", q->id);

	return(YP_TRUE);
}
