/*
 * Copyright (c) 1983, 1988, 1993
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
#if 0
static char sccsid[] = "@(#)mbuf.c	8.1 (Berkeley) 6/6/93";
#endif
static const char rcsid[] =
	"$Id: mbuf.c,v 1.11 1998/05/15 20:19:18 wollman Exp $";
#endif /* not lint */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <err.h>
#include <stdio.h>
#include "netstat.h"

#define	YES	1
typedef int bool;

struct	mbstat mbstat;

static struct mbtypes {
	int	mt_type;
	char	*mt_name;
} mbtypes[] = {
	{ MT_DATA,	"data" },
	{ MT_OOBDATA,	"oob data" },
	{ MT_CONTROL,	"ancillary data" },
	{ MT_HEADER,	"packet headers" },
#ifdef MT_SOCKET
	{ MT_SOCKET,	"socket structures" },			/* XXX */
#endif
#ifdef MT_PCB
	{ MT_PCB,	"protocol control blocks" },		/* XXX */
#endif
	{ MT_RTABLE,	"routing table entries" },		/* XXX */
#ifdef MT_HTABLE
	{ MT_HTABLE,	"IMP host table entries" },		/* XXX */
#endif
#ifdef MT_ATABLE
	{ MT_ATABLE,	"address resolution tables" },
#endif
	{ MT_FTABLE,	"fragment reassembly queue headers" },	/* XXX */
	{ MT_SONAME,	"socket names and addresses" },
	{ MT_SOOPTS,	"socket options" },
#ifdef MT_RIGHTS
	{ MT_RIGHTS,	"access rights" },
#endif
#ifdef MT_IFADDR
	{ MT_IFADDR,	"interface addresses" },		/* XXX */
#endif
	{ 0, 0 }
};

int nmbtypes = sizeof(mbstat.m_mtypes) / sizeof(short);
bool seen[256];			/* "have we seen this type yet?" */

/*
 * Print mbuf statistics.
 */
void
mbpr()
{
	register int totmem, totfree, totmbufs;
	register int i;
	register struct mbtypes *mp;
	int name[3], nmbclusters, nmbclen;
	size_t mbstatlen;

	name[0] = CTL_KERN;
	name[1] = KERN_IPC;
	name[2] = KIPC_MBSTAT;
	mbstatlen = sizeof mbstat;
	if (sysctl(name, 3, &mbstat, &mbstatlen, 0, 0) < 0) {
		warn("sysctl: retrieving mbstat");
		return;
	}

	name[2] = KIPC_NMBCLUSTERS;
	nmbclen = sizeof(int);
	if (sysctl(name, 3, &nmbclusters, &nmbclen, 0, 0) < 0) {
		warn("sysctl: retrieving nmbclusters");
		return;
	}
#undef MSIZE
#define MSIZE		(mbstat.m_msize)
#undef MCLBYTES
#define	MCLBYTES	(mbstat.m_mclbytes)

	if (nmbtypes != 256) {
		warnx("unexpected change to mbstat; check source");
		return;
	}

	totmbufs = 0;
	for (mp = mbtypes; mp->mt_name; mp++)
		totmbufs += mbstat.m_mtypes[mp->mt_type];
	printf("%u/%lu mbufs in use:\n", totmbufs, mbstat.m_mbufs);
	for (mp = mbtypes; mp->mt_name; mp++)
		if (mbstat.m_mtypes[mp->mt_type]) {
			seen[mp->mt_type] = YES;
			printf("\t%u mbufs allocated to %s\n",
			    mbstat.m_mtypes[mp->mt_type], mp->mt_name);
		}
	seen[MT_FREE] = YES;
	for (i = 0; i < nmbtypes; i++)
		if (!seen[i] && mbstat.m_mtypes[i]) {
			printf("\t%u mbufs allocated to <mbuf type %d>\n",
			    mbstat.m_mtypes[i], i);
		}
	printf("%lu/%lu/%u mbuf clusters in use (current/peak/max)\n",
		mbstat.m_clusters - mbstat.m_clfree, mbstat.m_clusters,
		nmbclusters);
	totmem = mbstat.m_mbufs * MSIZE + mbstat.m_clusters * MCLBYTES;
	totfree = mbstat.m_clfree * MCLBYTES + 
		MSIZE * (mbstat.m_mbufs - totmbufs);
	printf("%u Kbytes allocated to network (%d%% in use)\n",
		totmem / 1024, (unsigned) (totmem - totfree) * 100 / totmem);
	printf("%lu requests for memory denied\n", mbstat.m_drops);
	printf("%lu requests for memory delayed\n", mbstat.m_wait);
	printf("%lu calls to protocol drain routines\n", mbstat.m_drain);
}
