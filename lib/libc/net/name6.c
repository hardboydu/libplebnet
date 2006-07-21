/*	$KAME: name6.c,v 1.25 2000/06/26 16:44:40 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * ++Copyright++ 1985, 1988, 1993
 * -
 * Copyright (c) 1985, 1988, 1993
 *    The Regents of the University of California.  All rights reserved.
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
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
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
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

/*
 *	Atsushi Onoe <onoe@sm.sony.co.jp>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "namespace.h"
#ifdef ICMPNL
#include "reentrant.h"
#endif
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <netinet/in.h>
#ifdef INET6
#include <net/if.h>
#include <net/if_var.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <netinet6/in6_var.h>	/* XXX */
#endif

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <nsswitch.h>
#include <unistd.h>
#include "un-namespace.h"
#include "netdb_private.h"
#include "res_config.h"
#include "res_private.h"
#ifdef NS_CACHING
#include "nscache.h"
#endif

#ifndef _PATH_HOSTS
#define	_PATH_HOSTS	"/etc/hosts"
#endif

#ifndef MAXALIASES
#define	MAXALIASES	10
#endif
#ifndef	MAXADDRS
#define	MAXADDRS	20
#endif
#ifndef MAXDNAME
#define	MAXDNAME	1025
#endif

#ifdef INET6
#define	ADDRLEN(af)	((af) == AF_INET6 ? sizeof(struct in6_addr) : \
					    sizeof(struct in_addr))
#else
#define	ADDRLEN(af)	sizeof(struct in_addr)
#endif

#define	MAPADDR(ab, ina) \
do {									\
	memcpy(&(ab)->map_inaddr, ina, sizeof(struct in_addr));		\
	memset((ab)->map_zero, 0, sizeof((ab)->map_zero));		\
	memset((ab)->map_one, 0xff, sizeof((ab)->map_one));		\
} while (0)
#define	MAPADDRENABLED(flags) \
	(((flags) & AI_V4MAPPED) || \
	 (((flags) & AI_V4MAPPED_CFG) && _mapped_addr_enabled()))

union inx_addr {
	struct in_addr	in_addr;
#ifdef INET6
	struct in6_addr	in6_addr;
#endif
	struct {
		u_char	mau_zero[10];
		u_char	mau_one[2];
		struct in_addr mau_inaddr;
	}		map_addr_un;
#define	map_zero	map_addr_un.mau_zero
#define	map_one		map_addr_un.mau_one
#define	map_inaddr	map_addr_un.mau_inaddr
};

struct policyqueue {
	TAILQ_ENTRY(policyqueue) pc_entry;
#ifdef INET6
	struct in6_addrpolicy pc_policy;
#endif
};
TAILQ_HEAD(policyhead, policyqueue);

#define AIO_SRCFLAG_DEPRECATED	0x1

struct hp_order {
	union {
		struct sockaddr_storage aiou_ss;
		struct sockaddr aiou_sa;
	} aio_src_un;
#define aio_srcsa aio_src_un.aiou_sa
	u_int32_t aio_srcflag;
	int aio_srcscope;
	int aio_dstscope;
	struct policyqueue *aio_srcpolicy;
	struct policyqueue *aio_dstpolicy;
	union {
		struct sockaddr_storage aiou_ss;
		struct sockaddr aiou_sa;
	} aio_un;
#define aio_sa aio_un.aiou_sa
	int aio_matchlen;
	char *aio_h_addr;
};

static struct	 hostent *_hpcopy(struct hostent *, int *);
static struct	 hostent *_hpaddr(int, const char *, void *, int *);
static struct	 hostent *_hpmerge(struct hostent *, struct hostent *, int *);
#ifdef INET6
static struct	 hostent *_hpmapv6(struct hostent *, int *);
#endif
static struct	 hostent *_hpsort(struct hostent *, res_state);
static struct	 hostent *_ghbyname(const char *, int, int, int *);
static char	*_hgetword(char **);
static int	 _mapped_addr_enabled(void);

static struct	 hostent *_hpreorder(struct hostent *);
static int	 get_addrselectpolicy(struct policyhead *);
static void	 free_addrselectpolicy(struct policyhead *);
static struct	 policyqueue *match_addrselectpolicy(struct sockaddr *,
	struct policyhead *);
static void	 set_source(struct hp_order *, struct policyhead *);
static int	 matchlen(struct sockaddr *, struct sockaddr *);
static int	 comp_dst(const void *, const void *);
static int	 gai_addr2scopetype(struct sockaddr *);

static FILE	*_files_open(int *);
static int	 _files_ghbyname(void *, void *, va_list);
static int	 _files_ghbyaddr(void *, void *, va_list);
#ifdef YP
static int	 _nis_ghbyname(void *, void *, va_list);
static int	 _nis_ghbyaddr(void *, void *, va_list);
#endif
static int	 _dns_ghbyname(void *, void *, va_list);
static int	 _dns_ghbyaddr(void *, void *, va_list);
static void	 _dns_shent(int) __unused;
static void	 _dns_ehent(void) __unused;
#ifdef ICMPNL
static int	 _icmp_ghbyaddr(void *, void *, va_list);
#endif /* ICMPNL */
#ifdef NS_CACHING
static int ipnode_id_func(char *, size_t *, va_list, void *);
static int ipnode_marshal_func(char *, size_t *, void *, va_list, void *);
static int ipnode_unmarshal_func(char *, size_t, void *, va_list, void *);
#endif

#ifdef ICMPNL
static mutex_t _getipnodeby_thread_lock = MUTEX_INITIALIZER;
#define THREAD_LOCK()	mutex_lock(&_getipnodeby_thread_lock);
#define THREAD_UNLOCK()	mutex_unlock(&_getipnodeby_thread_lock);
#endif

/* Host lookup order if nsswitch.conf is broken or nonexistant */
static const ns_src default_src[] = {
	{ NSSRC_FILES, NS_SUCCESS },
	{ NSSRC_DNS, NS_SUCCESS },
#ifdef ICMPNL
#define NSSRC_ICMP "icmp"
	{ NSSRC_ICMP, NS_SUCCESS },
#endif
	{ 0 }
};

/*
 * Check if kernel supports mapped address.
 *	implementation dependent
 */
#ifdef __KAME__
#include <sys/sysctl.h>
#endif /* __KAME__ */

static int
_mapped_addr_enabled(void)
{
	/* implementation dependent check */
#if defined(__KAME__) && defined(IPV6CTL_MAPPED_ADDR)
	int mib[4];
	size_t len;
	int val;

	mib[0] = CTL_NET;
	mib[1] = PF_INET6;
	mib[2] = IPPROTO_IPV6;
	mib[3] = IPV6CTL_MAPPED_ADDR;
	len = sizeof(val);
	if (sysctl(mib, 4, &val, &len, 0, 0) == 0 && val != 0)
		return 1;
#endif /* __KAME__ && IPV6CTL_MAPPED_ADDR */
	return 0;
}

#ifdef NS_CACHING
static int
ipnode_id_func(char *buffer, size_t *buffer_size, va_list ap,
    void *cache_mdata)
{
	res_state statp;
	u_long res_options;

	const int op_id = 2;
	char *name;
	int af;
	size_t len;
	void *src;

	char *p;
	size_t desired_size, size;
	enum nss_lookup_type lookup_type;
	int res = NS_UNAVAIL;

	statp = __res_state();
	res_options = statp->options & (RES_RECURSE | RES_DEFNAMES |
	    RES_DNSRCH | RES_NOALIASES | RES_USE_INET6);

	lookup_type = (enum nss_lookup_type)cache_mdata;
	switch (lookup_type) {
	case nss_lt_name:
		name = va_arg(ap, char *);
		af = va_arg(ap, int);

		size = strlen(name);
		desired_size = sizeof(res_options) + sizeof(int) +
		    sizeof(enum nss_lookup_type) + sizeof(int) + size + 1;

		if (desired_size > *buffer_size) {
			res = NS_RETURN;
			goto fin;
		}

		p = buffer;
		memcpy(p, &res_options, sizeof(res_options));
		p += sizeof(res_options);

		memcpy(p, &op_id, sizeof(int));
		p += sizeof(int);

		memcpy(p, &lookup_type, sizeof(enum nss_lookup_type));
		p += sizeof(enum nss_lookup_type);

		memcpy(p, &af, sizeof(int));
		p += sizeof(int);

		memcpy(p, name, size + 1);

		res = NS_SUCCESS;
		break;
	case nss_lt_id:
		src = va_arg(ap, void *);
		len = va_arg(ap, size_t);
		af = va_arg(ap, int);

		desired_size = sizeof(res_options) + sizeof(int) +
		    sizeof(enum nss_lookup_type) + sizeof(int) +
		    sizeof(size_t) + len;

		if (desired_size > *buffer_size) {
			res = NS_RETURN;
			goto fin;
		}

		p = buffer;
		memcpy(p, &res_options, sizeof(res_options));
		p += sizeof(res_options);

		memcpy(p, &op_id, sizeof(int));
		p += sizeof(int);

		memcpy(p, &lookup_type, sizeof(enum nss_lookup_type));
		p += sizeof(enum nss_lookup_type);

		memcpy(p, &af, sizeof(int));
		p += sizeof(int);

		memcpy(p, &len, sizeof(size_t));
		p += sizeof(size_t);

		memcpy(p, src, len);

		res = NS_SUCCESS;
		break;
	default:
		/* should be unreachable */
		return (NS_UNAVAIL);
	}

fin:
	*buffer_size = desired_size;
	return (res);
}

static int
ipnode_marshal_func(char *buffer, size_t *buffer_size, void *retval,
    va_list ap, void *cache_mdata)
{
	struct hostent *ht;

	struct hostent new_ht;
	size_t desired_size, aliases_size, addr_size, size;
	char *p, **iter;

	ht = *((struct hostent **)retval);

	desired_size = _ALIGNBYTES + sizeof(struct hostent) + sizeof(char *);
	if (ht->h_name != NULL)
		desired_size += strlen(ht->h_name) + 1;

	if (ht->h_aliases != NULL) {
		aliases_size = 0;
		for (iter = ht->h_aliases; *iter; ++iter) {
			desired_size += strlen(*iter) + 1;
			++aliases_size;
		}

		desired_size += _ALIGNBYTES +
		    (aliases_size + 1) * sizeof(char *);
	}

	if (ht->h_addr_list != NULL) {
		addr_size = 0;
		for (iter = ht->h_addr_list; *iter; ++iter)
			++addr_size;

		desired_size += addr_size * _ALIGN(ht->h_length);
		desired_size += _ALIGNBYTES + (addr_size + 1) * sizeof(char *);
	}

	if (desired_size > *buffer_size) {
		/* this assignment is here for future use */
		*buffer_size = desired_size;
		return (NS_RETURN);
	}

	memcpy(&new_ht, ht, sizeof(struct hostent));
	memset(buffer, 0, desired_size);

	*buffer_size = desired_size;
	p = buffer + sizeof(struct hostent) + sizeof(char *);
	memcpy(buffer + sizeof(struct hostent), &p, sizeof(char *));
	p = (char *)_ALIGN(p);

	if (new_ht.h_name != NULL) {
		size = strlen(new_ht.h_name);
		memcpy(p, new_ht.h_name, size);
		new_ht.h_name = p;
		p += size + 1;
	}

	if (new_ht.h_aliases != NULL) {
		p = (char *)_ALIGN(p);
		memcpy(p, new_ht.h_aliases, sizeof(char *) * aliases_size);
		new_ht.h_aliases = (char **)p;
		p += sizeof(char *) * (aliases_size + 1);

		for (iter = new_ht.h_aliases; *iter; ++iter) {
			size = strlen(*iter);
			memcpy(p, *iter, size);
			*iter = p;
			p += size + 1;
		}
	}

	if (new_ht.h_addr_list != NULL) {
		p = (char *)_ALIGN(p);
		memcpy(p, new_ht.h_addr_list, sizeof(char *) * addr_size);
		new_ht.h_addr_list = (char **)p;
		p += sizeof(char *) * (addr_size + 1);

		size = _ALIGN(new_ht.h_length);
		for (iter = new_ht.h_addr_list; *iter; ++iter) {
			memcpy(p, *iter, size);
			*iter = p;
			p += size + 1;
		}
	}
	memcpy(buffer, &new_ht, sizeof(struct hostent));
	return (NS_SUCCESS);
}

static int
ipnode_unmarshal_func(char *buffer, size_t buffer_size, void *retval,
    va_list ap, void *cache_mdata)
{
	struct hostent new_ht;
	struct hostent *ht;

	char *p;
	char **iter;
	char *orig_buf;
	int err;

	ht = &new_ht;

	memcpy(ht, buffer, sizeof(struct hostent));
	memcpy(&p, buffer + sizeof(struct hostent), sizeof(char *));

	orig_buf = buffer + sizeof(struct hostent) + sizeof(char *) +
	    _ALIGN(p) - (size_t)p;
	p = (char *)_ALIGN(p);


	NS_APPLY_OFFSET(ht->h_name, orig_buf, p, char *);
	if (ht->h_aliases != NULL) {
		NS_APPLY_OFFSET(ht->h_aliases, orig_buf, p, char **);

		for (iter = ht->h_aliases; *iter; ++iter)
			NS_APPLY_OFFSET(*iter, orig_buf, p, char *);
	}

	if (ht->h_addr_list != NULL) {
		NS_APPLY_OFFSET(ht->h_addr_list, orig_buf, p, char **);

		for (iter = ht->h_addr_list; *iter; ++iter)
			NS_APPLY_OFFSET(*iter, orig_buf, p, char *);
	}

	ht = _hpcopy(ht, &err);
	if (ht == NULL)
		return (NS_UNAVAIL);

	*((struct hostent **)retval) = ht;
	return (NS_SUCCESS);
}
#endif

/*
 * Functions defined in RFC2553
 *	getipnodebyname, getipnodebyaddr, freehostent
 */

static struct hostent *
_ghbyname(const char *name, int af, int flags, int *errp)
{
	struct hostent *hp;
	int rval;

#ifdef NS_CACHING
	static const nss_cache_info cache_info =
	NS_COMMON_CACHE_INFO_INITIALIZER(
		hosts, (void *)nss_lt_name,
		ipnode_id_func, ipnode_marshal_func, ipnode_unmarshal_func);
#endif
	static const ns_dtab dtab[] = {
		NS_FILES_CB(_files_ghbyname, NULL)
		{ NSSRC_DNS, _dns_ghbyname, NULL },
		NS_NIS_CB(_nis_ghbyname, NULL)
#ifdef NS_CACHING
		NS_CACHE_CB(&cache_info)
#endif
		{ 0 }
	};

	if (flags & AI_ADDRCONFIG) {
		int s;

		if ((s = _socket(af, SOCK_DGRAM, 0)) < 0)
			return NULL;
		/*
		 * TODO:
		 * Note that implementation dependent test for address
		 * configuration should be done everytime called
		 * (or apropriate interval),
		 * because addresses will be dynamically assigned or deleted.
		 */
		_close(s);
	}

	rval = _nsdispatch(&hp, dtab, NSDB_HOSTS, "ghbyname", default_src,
			  name, af, errp);
	return (rval == NS_SUCCESS) ? hp : NULL;
}

struct hostent *
getipnodebyname(const char *name, int af, int flags, int *errp)
{
	struct hostent *hp;
	union inx_addr addrbuf;
	res_state statp;

	switch (af) {
	case AF_INET:
#ifdef INET6
	case AF_INET6:
#endif
		break;
	default:
		*errp = NO_RECOVERY;
		return NULL;
	}

#ifdef INET6
	/* special case for literal address */
	if (inet_pton(AF_INET6, name, &addrbuf) == 1) {
		if (af != AF_INET6) {
			*errp = HOST_NOT_FOUND;
			return NULL;
		}
		return _hpaddr(af, name, &addrbuf, errp);
	}
#endif
	if (inet_aton(name, (struct in_addr *)&addrbuf) == 1) {
		if (af != AF_INET) {
			if (MAPADDRENABLED(flags)) {
				MAPADDR(&addrbuf, &addrbuf.in_addr);
			} else {
				*errp = HOST_NOT_FOUND;
				return NULL;
			}
		}
		return _hpaddr(af, name, &addrbuf, errp);
	}

	statp = __res_state();
	if ((statp->options & RES_INIT) == 0) {
		if (res_ninit(statp) < 0) {
			*errp = NETDB_INTERNAL;
			return NULL;
		}
	}

	*errp = HOST_NOT_FOUND;
	hp = _ghbyname(name, af, flags, errp);

#ifdef INET6
	if (af == AF_INET6 && ((flags & AI_ALL) || hp == NULL) &&
	    MAPADDRENABLED(flags)) {
		struct hostent *hp2 = _ghbyname(name, AF_INET, flags, errp);
		if (hp == NULL)
			hp = _hpmapv6(hp2, errp);
		else {
			if (hp2 && strcmp(hp->h_name, hp2->h_name) != 0) {
				freehostent(hp2);
				hp2 = NULL;
			}
			hp = _hpmerge(hp, hp2, errp);
		}
	}
#endif
	return _hpreorder(_hpsort(hp, statp));
}

struct hostent *
getipnodebyaddr(const void *src, size_t len, int af, int *errp)
{
	struct hostent *hp;
	int rval;
#ifdef INET6
	struct in6_addr addrbuf;
#else
	struct in_addr addrbuf;
#endif

#ifdef NS_CACHING
	static const nss_cache_info cache_info =
	NS_COMMON_CACHE_INFO_INITIALIZER(
		hosts, (void *)nss_lt_id,
		ipnode_id_func, ipnode_marshal_func, ipnode_unmarshal_func);
#endif
	static const ns_dtab dtab[] = {
		NS_FILES_CB(_files_ghbyaddr, NULL)
		{ NSSRC_DNS, _dns_ghbyaddr, NULL },
		NS_NIS_CB(_nis_ghbyaddr, NULL)
#ifdef ICMPNL
		{ NSSRC_ICMP, _icmp_ghbyaddr, NULL },
#endif
#ifdef NS_CACHING
		NS_CACHE_CB(&cache_info)
#endif
		{ 0 }
	};

	*errp = HOST_NOT_FOUND;

	switch (af) {
	case AF_INET:
		if (len != sizeof(struct in_addr)) {
			*errp = NO_RECOVERY;
			return NULL;
		}
		if ((long)src & ~(sizeof(struct in_addr) - 1)) {
			memcpy(&addrbuf, src, len);
			src = &addrbuf;
		}
		if (((struct in_addr *)src)->s_addr == 0)
			return NULL;
		break;
#ifdef INET6
	case AF_INET6:
		if (len != sizeof(struct in6_addr)) {
			*errp = NO_RECOVERY;
			return NULL;
		}
		if ((long)src & ~(sizeof(struct in6_addr) / 2 - 1)) {	/*XXX*/
			memcpy(&addrbuf, src, len);
			src = &addrbuf;
		}
		if (IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)src))
			return NULL;
		if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)src)
		||  IN6_IS_ADDR_V4COMPAT((struct in6_addr *)src)) {
			src = (char *)src +
			    (sizeof(struct in6_addr) - sizeof(struct in_addr));
			af = AF_INET;
			len = sizeof(struct in_addr);
		}
		break;
#endif
	default:
		*errp = NO_RECOVERY;
		return NULL;
	}

	rval = _nsdispatch(&hp, dtab, NSDB_HOSTS, "ghbyaddr", default_src,
			  src, len, af, errp);
	return (rval == NS_SUCCESS) ? hp : NULL;
}

void
freehostent(struct hostent *ptr)
{
	free(ptr);
}

/*
 * Private utility functions
 */

/*
 * _hpcopy: allocate and copy hostent structure
 */
static struct hostent *
_hpcopy(struct hostent *hp, int *errp)
{
	struct hostent *nhp;
	char *cp, **pp;
	int size, addrsize;
	int nalias = 0, naddr = 0;
	int al_off;
	int i;

	if (hp == NULL)
		return hp;

	/* count size to be allocated */
	size = sizeof(struct hostent);
	if (hp->h_name != NULL)
		size += strlen(hp->h_name) + 1;
	if ((pp = hp->h_aliases) != NULL) {
		for (i = 0; *pp != NULL; i++, pp++) {
			if (**pp != '\0') {
				size += strlen(*pp) + 1;
				nalias++;
			}
		}
	}
	/* adjust alignment */
	size = ALIGN(size);
	al_off = size;
	size += sizeof(char *) * (nalias + 1);
	addrsize = ALIGN(hp->h_length);
	if ((pp = hp->h_addr_list) != NULL) {
		while (*pp++ != NULL)
			naddr++;
	}
	size += addrsize * naddr;
	size += sizeof(char *) * (naddr + 1);

	/* copy */
	if ((nhp = (struct hostent *)malloc(size)) == NULL) {
		*errp = TRY_AGAIN;
		return NULL;
	}
	cp = (char *)&nhp[1];
	if (hp->h_name != NULL) {
		nhp->h_name = cp;
		strcpy(cp, hp->h_name);
		cp += strlen(cp) + 1;
	} else
		nhp->h_name = NULL;
	nhp->h_aliases = (char **)((char *)nhp + al_off);
	if ((pp = hp->h_aliases) != NULL) {
		for (i = 0; *pp != NULL; pp++) {
			if (**pp != '\0') {
				nhp->h_aliases[i++] = cp;
				strcpy(cp, *pp);
				cp += strlen(cp) + 1;
			}
		}
	}
	nhp->h_aliases[nalias] = NULL;
	cp = (char *)&nhp->h_aliases[nalias + 1];
	nhp->h_addrtype = hp->h_addrtype;
	nhp->h_length = hp->h_length;
	nhp->h_addr_list = (char **)cp;
	if ((pp = hp->h_addr_list) != NULL) {
		cp = (char *)&nhp->h_addr_list[naddr + 1];
		for (i = 0; *pp != NULL; pp++) {
			nhp->h_addr_list[i++] = cp;
			memcpy(cp, *pp, hp->h_length);
			cp += addrsize;
		}
	}
	nhp->h_addr_list[naddr] = NULL;
	return nhp;
}

/*
 * _hpaddr: construct hostent structure with one address
 */
static struct hostent *
_hpaddr(int af, const char *name, void *addr, int *errp)
{
	struct hostent *hp, hpbuf;
	char *addrs[2];

	hp = &hpbuf;
	hp->h_name = (char *)name;
	hp->h_aliases = NULL;
	hp->h_addrtype = af;
	hp->h_length = ADDRLEN(af);
	hp->h_addr_list = addrs;
	addrs[0] = (char *)addr;
	addrs[1] = NULL;
	return _hpcopy(hp, errp);
}

/*
 * _hpmerge: merge 2 hostent structure, arguments will be freed
 */
static struct hostent *
_hpmerge(struct hostent *hp1, struct hostent *hp2, int *errp)
{
	int i, j;
	int naddr, nalias;
	char **pp;
	struct hostent *hp, hpbuf;
	char *aliases[MAXALIASES + 1], *addrs[MAXADDRS + 1];
	union inx_addr addrbuf[MAXADDRS];

	if (hp1 == NULL)
		return hp2;
	if (hp2 == NULL)
		return hp1;

#define	HP(i)	(i == 1 ? hp1 : hp2)
	hp = &hpbuf;
	hp->h_name = (hp1->h_name != NULL ? hp1->h_name : hp2->h_name);
	hp->h_aliases = aliases;
	nalias = 0;
	for (i = 1; i <= 2; i++) {
		if ((pp = HP(i)->h_aliases) == NULL)
			continue;
		for (; nalias < MAXALIASES && *pp != NULL; pp++) {
			/* check duplicates */
			for (j = 0; j < nalias; j++)
				if (strcasecmp(*pp, aliases[j]) == 0)
					break;
			if (j == nalias)
				aliases[nalias++] = *pp;
		}
	}
	aliases[nalias] = NULL;
#ifdef INET6
	if (hp1->h_length != hp2->h_length) {
		hp->h_addrtype = AF_INET6;
		hp->h_length = sizeof(struct in6_addr);
	} else {
#endif
		hp->h_addrtype = hp1->h_addrtype;
		hp->h_length = hp1->h_length;
#ifdef INET6
	}
#endif
	hp->h_addr_list = addrs;
	naddr = 0;
	for (i = 1; i <= 2; i++) {
		if ((pp = HP(i)->h_addr_list) == NULL)
			continue;
		if (HP(i)->h_length == hp->h_length) {
			while (naddr < MAXADDRS && *pp != NULL)
				addrs[naddr++] = *pp++;
		} else {
			/* copy IPv4 addr as mapped IPv6 addr */
			while (naddr < MAXADDRS && *pp != NULL) {
				MAPADDR(&addrbuf[naddr], *pp++);
				addrs[naddr] = (char *)&addrbuf[naddr];
				naddr++;
			}
		}
	}
	addrs[naddr] = NULL;
	hp = _hpcopy(hp, errp);
	freehostent(hp1);
	freehostent(hp2);
	return hp;
}

/*
 * _hpmapv6: convert IPv4 hostent into IPv4-mapped IPv6 addresses
 */
#ifdef INET6
static struct hostent *
_hpmapv6(struct hostent *hp, int *errp)
{
	struct hostent *hp6;

	if (hp == NULL)
		return NULL;
	if (hp->h_addrtype == AF_INET6)
		return hp;

	/* make dummy hostent to convert IPv6 address */
	if ((hp6 = (struct hostent *)malloc(sizeof(struct hostent))) == NULL) {
		*errp = TRY_AGAIN;
		return NULL;
	}
	hp6->h_name = NULL;
	hp6->h_aliases = NULL;
	hp6->h_addrtype = AF_INET6;
	hp6->h_length = sizeof(struct in6_addr);
	hp6->h_addr_list = NULL;
	return _hpmerge(hp6, hp, errp);
}
#endif

/*
 * _hpsort: sort address by sortlist
 */
static struct hostent *
_hpsort(struct hostent *hp, res_state statp)
{
	int i, j, n;
	u_char *ap, *sp, *mp, **pp;
	char t;
	char order[MAXADDRS];
	int nsort = statp->nsort;

	if (hp == NULL || hp->h_addr_list[1] == NULL || nsort == 0)
		return hp;
	for (i = 0; (ap = (u_char *)hp->h_addr_list[i]); i++) {
		for (j = 0; j < nsort; j++) {
#ifdef INET6
			if (statp->_u._ext.ext->sort_list[j].af !=
			    hp->h_addrtype)
				continue;
			sp = (u_char *)&statp->_u._ext.ext->sort_list[j].addr;
			mp = (u_char *)&statp->_u._ext.ext->sort_list[j].mask;
#else
			sp = (u_char *)&statp->sort_list[j].addr;
			mp = (u_char *)&statp->sort_list[j].mask;
#endif
			for (n = 0; n < hp->h_length; n++) {
				if ((ap[n] & mp[n]) != sp[n])
					break;
			}
			if (n == hp->h_length)
				break;
		}
		order[i] = j;
	}
	n = i;
	pp = (u_char **)hp->h_addr_list;
	for (i = 0; i < n - 1; i++) {
		for (j = i + 1; j < n; j++) {
			if (order[i] > order[j]) {
				ap = pp[i];
				pp[i] = pp[j];
				pp[j] = ap;
				t = order[i];
				order[i] = order[j];
				order[j] = t;
			}
		}
	}
	return hp;
}

static char *
_hgetword(char **pp)
{
	char c, *p, *ret;
	const char *sp;
	static const char sep[] = "# \t\n";

	ret = NULL;
	for (p = *pp; (c = *p) != '\0'; p++) {
		for (sp = sep; *sp != '\0'; sp++) {
			if (c == *sp)
				break;
		}
		if (c == '#')
			p[1] = '\0';	/* ignore rest of line */
		if (ret == NULL) {
			if (*sp == '\0')
				ret = p;
		} else {
			if (*sp != '\0') {
				*p++ = '\0';
				break;
			}
		}
	}
	*pp = p;
	if (ret == NULL || *ret == '\0')
		return NULL;
	return ret;
}

/*
 * _hpreorder: sort address by default address selection
 */
static struct hostent *
_hpreorder(struct hostent *hp)
{
	struct hp_order *aio;
	int i, n;
	char *ap;
	struct sockaddr *sa;
	struct policyhead policyhead;

	if (hp == NULL)
		return hp;

	switch (hp->h_addrtype) {
	case AF_INET:
#ifdef INET6
	case AF_INET6:
#endif
		break;
	default:
		free_addrselectpolicy(&policyhead);
		return hp;
	}

	/* count the number of addrinfo elements for sorting. */
	for (n = 0; hp->h_addr_list[n] != NULL; n++)
		;

	/*
	 * If the number is small enough, we can skip the reordering process.
	 */
	if (n <= 1)
		return hp;

	/* allocate a temporary array for sort and initialization of it. */
	if ((aio = malloc(sizeof(*aio) * n)) == NULL)
		return hp;	/* give up reordering */
	memset(aio, 0, sizeof(*aio) * n);

	/* retrieve address selection policy from the kernel */
	TAILQ_INIT(&policyhead);
	if (!get_addrselectpolicy(&policyhead)) {
		/* no policy is installed into kernel, we don't sort. */
		free(aio);
		return hp;
	}

	for (i = 0; i < n; i++) {
		ap = hp->h_addr_list[i];
		aio[i].aio_h_addr = ap;
		sa = &aio[i].aio_sa;
		switch (hp->h_addrtype) {
		case AF_INET:
			sa->sa_family = AF_INET;
			sa->sa_len = sizeof(struct sockaddr_in);
			memcpy(&((struct sockaddr_in *)sa)->sin_addr, ap,
			    sizeof(struct in_addr));
			break;
#ifdef INET6
		case AF_INET6:
			if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)ap)) {
				sa->sa_family = AF_INET;
				sa->sa_len = sizeof(struct sockaddr_in);
				memcpy(&((struct sockaddr_in *)sa)->sin_addr,
				    &ap[12], sizeof(struct in_addr));
			} else {
				sa->sa_family = AF_INET6;
				sa->sa_len = sizeof(struct sockaddr_in6);
				memcpy(&((struct sockaddr_in6 *)sa)->sin6_addr,
				    ap, sizeof(struct in6_addr));
			}
			break;
#endif
		}
		aio[i].aio_dstscope = gai_addr2scopetype(sa);
		aio[i].aio_dstpolicy = match_addrselectpolicy(sa, &policyhead);
		set_source(&aio[i], &policyhead);
	}

	/* perform sorting. */
	qsort(aio, n, sizeof(*aio), comp_dst);

	/* reorder the h_addr_list. */
	for (i = 0; i < n; i++)
		hp->h_addr_list[i] = aio[i].aio_h_addr;

	/* cleanup and return */
	free(aio);
	free_addrselectpolicy(&policyhead);
	return hp;
}

static int
get_addrselectpolicy(struct policyhead *head)
{
#ifdef INET6
	int mib[] = { CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_ADDRCTLPOLICY };
	size_t l;
	char *buf;
	struct in6_addrpolicy *pol, *ep;

	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &l, NULL, 0) < 0)
		return (0);
	if ((buf = malloc(l)) == NULL)
		return (0);
	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &l, NULL, 0) < 0) {
		free(buf);
		return (0);
	}

	ep = (struct in6_addrpolicy *)(buf + l);
	for (pol = (struct in6_addrpolicy *)buf; pol + 1 <= ep; pol++) {
		struct policyqueue *new;

		if ((new = malloc(sizeof(*new))) == NULL) {
			free_addrselectpolicy(head); /* make the list empty */
			break;
		}
		new->pc_policy = *pol;
		TAILQ_INSERT_TAIL(head, new, pc_entry);
	}

	free(buf);
	return (1);
#else
	return (0);
#endif
}

static void
free_addrselectpolicy(struct policyhead *head)
{
	struct policyqueue *ent, *nent;

	for (ent = TAILQ_FIRST(head); ent; ent = nent) {
		nent = TAILQ_NEXT(ent, pc_entry);
		TAILQ_REMOVE(head, ent, pc_entry);
		free(ent);
	}
}

static struct policyqueue *
match_addrselectpolicy(struct sockaddr *addr, struct policyhead *head)
{
#ifdef INET6
	struct policyqueue *ent, *bestent = NULL;
	struct in6_addrpolicy *pol;
	int matchlen, bestmatchlen = -1;
	u_char *mp, *ep, *k, *p, m;
	struct sockaddr_in6 key;

	switch(addr->sa_family) {
	case AF_INET6:
		key = *(struct sockaddr_in6 *)addr;
		break;
	case AF_INET:
		/* convert the address into IPv4-mapped IPv6 address. */
		memset(&key, 0, sizeof(key));
		key.sin6_family = AF_INET6;
		key.sin6_len = sizeof(key);
		key.sin6_addr.s6_addr[10] = 0xff;
		key.sin6_addr.s6_addr[11] = 0xff;
		memcpy(&key.sin6_addr.s6_addr[12],
		       &((struct sockaddr_in *)addr)->sin_addr, 4);
		break;
	default:
		return(NULL);
	}

	for (ent = TAILQ_FIRST(head); ent; ent = TAILQ_NEXT(ent, pc_entry)) {
		pol = &ent->pc_policy;
		matchlen = 0;

		mp = (u_char *)&pol->addrmask.sin6_addr;
		ep = mp + 16;	/* XXX: scope field? */
		k = (u_char *)&key.sin6_addr;
		p = (u_char *)&pol->addr.sin6_addr;
		for (; mp < ep && *mp; mp++, k++, p++) {
			m = *mp;
			if ((*k & m) != *p)
				goto next; /* not match */
			if (m == 0xff) /* short cut for a typical case */
				matchlen += 8;
			else {
				while (m >= 0x80) {
					matchlen++;
					m <<= 1;
				}
			}
		}

		/* matched.  check if this is better than the current best. */
		if (matchlen > bestmatchlen) {
			bestent = ent;
			bestmatchlen = matchlen;
		}

	  next:
		continue;
	}

	return(bestent);
#else
	return(NULL);
#endif

}

static void
set_source(struct hp_order *aio, struct policyhead *ph)
{
	struct sockaddr_storage ss = aio->aio_un.aiou_ss;
	socklen_t srclen;
	int s;

	/* set unspec ("no source is available"), just in case */
	aio->aio_srcsa.sa_family = AF_UNSPEC;
	aio->aio_srcscope = -1;

	switch(ss.ss_family) {
	case AF_INET:
		((struct sockaddr_in *)&ss)->sin_port = htons(1);
		break;
#ifdef INET6
	case AF_INET6:
		((struct sockaddr_in6 *)&ss)->sin6_port = htons(1);
		break;
#endif
	default:		/* ignore unsupported AFs explicitly */
		return;
	}

	/* open a socket to get the source address for the given dst */
	if ((s = _socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return;		/* give up */
	if (_connect(s, (struct sockaddr *)&ss, ss.ss_len) < 0)
		goto cleanup;
	srclen = ss.ss_len;
	if (_getsockname(s, &aio->aio_srcsa, &srclen) < 0) {
		aio->aio_srcsa.sa_family = AF_UNSPEC;
		goto cleanup;
	}
	aio->aio_srcscope = gai_addr2scopetype(&aio->aio_srcsa);
	aio->aio_srcpolicy = match_addrselectpolicy(&aio->aio_srcsa, ph);
	aio->aio_matchlen = matchlen(&aio->aio_srcsa, (struct sockaddr *)&ss);
#ifdef INET6
	if (ss.ss_family == AF_INET6) {
		struct in6_ifreq ifr6;
		u_int32_t flags6;

		/* XXX: interface name should not be hardcoded */
		strncpy(ifr6.ifr_name, "lo0", sizeof(ifr6.ifr_name));
		memset(&ifr6, 0, sizeof(ifr6));
		memcpy(&ifr6.ifr_addr, &ss, ss.ss_len);
		if (_ioctl(s, SIOCGIFAFLAG_IN6, &ifr6) == 0) {
			flags6 = ifr6.ifr_ifru.ifru_flags6;
			if ((flags6 & IN6_IFF_DEPRECATED))
				aio->aio_srcflag |= AIO_SRCFLAG_DEPRECATED;
		}
	}
#endif

  cleanup:
	_close(s);
	return;
}

static int
matchlen(struct sockaddr *src, struct sockaddr *dst)
{
	int match = 0;
	u_char *s, *d;
	u_char *lim, r;
	int addrlen;

	switch (src->sa_family) {
#ifdef INET6
	case AF_INET6:
		s = (u_char *)&((struct sockaddr_in6 *)src)->sin6_addr;
		d = (u_char *)&((struct sockaddr_in6 *)dst)->sin6_addr;
		addrlen = sizeof(struct in6_addr);
		lim = s + addrlen;
		break;
#endif
	case AF_INET:
		s = (u_char *)&((struct sockaddr_in *)src)->sin_addr;
		d = (u_char *)&((struct sockaddr_in *)dst)->sin_addr;
		addrlen = sizeof(struct in_addr);
		lim = s + addrlen;
		break;
	default:
		return(0);
	}

	while (s < lim)
		if ((r = (*d++ ^ *s++)) != 0) {
			while (r < addrlen * 8) {
				match++;
				r <<= 1;
			}
			break;
		} else
			match += 8;
	return(match);
}

static int
comp_dst(const void *arg1, const void *arg2)
{
	const struct hp_order *dst1 = arg1, *dst2 = arg2;

	/*
	 * Rule 1: Avoid unusable destinations.
	 * XXX: we currently do not consider if an appropriate route exists.
	 */
	if (dst1->aio_srcsa.sa_family != AF_UNSPEC &&
	    dst2->aio_srcsa.sa_family == AF_UNSPEC) {
		return(-1);
	}
	if (dst1->aio_srcsa.sa_family == AF_UNSPEC &&
	    dst2->aio_srcsa.sa_family != AF_UNSPEC) {
		return(1);
	}

	/* Rule 2: Prefer matching scope. */
	if (dst1->aio_dstscope == dst1->aio_srcscope &&
	    dst2->aio_dstscope != dst2->aio_srcscope) {
		return(-1);
	}
	if (dst1->aio_dstscope != dst1->aio_srcscope &&
	    dst2->aio_dstscope == dst2->aio_srcscope) {
		return(1);
	}

	/* Rule 3: Avoid deprecated addresses. */
	if (dst1->aio_srcsa.sa_family != AF_UNSPEC &&
	    dst2->aio_srcsa.sa_family != AF_UNSPEC) {
		if (!(dst1->aio_srcflag & AIO_SRCFLAG_DEPRECATED) &&
		    (dst2->aio_srcflag & AIO_SRCFLAG_DEPRECATED)) {
			return(-1);
		}
		if ((dst1->aio_srcflag & AIO_SRCFLAG_DEPRECATED) &&
		    !(dst2->aio_srcflag & AIO_SRCFLAG_DEPRECATED)) {
			return(1);
		}
	}

	/* Rule 4: Prefer home addresses. */
	/* XXX: not implemented yet */

	/* Rule 5: Prefer matching label. */
#ifdef INET6
	if (dst1->aio_srcpolicy && dst1->aio_dstpolicy &&
	    dst1->aio_srcpolicy->pc_policy.label ==
	    dst1->aio_dstpolicy->pc_policy.label &&
	    (dst2->aio_srcpolicy == NULL || dst2->aio_dstpolicy == NULL ||
	     dst2->aio_srcpolicy->pc_policy.label !=
	     dst2->aio_dstpolicy->pc_policy.label)) {
		return(-1);
	}
	if (dst2->aio_srcpolicy && dst2->aio_dstpolicy &&
	    dst2->aio_srcpolicy->pc_policy.label ==
	    dst2->aio_dstpolicy->pc_policy.label &&
	    (dst1->aio_srcpolicy == NULL || dst1->aio_dstpolicy == NULL ||
	     dst1->aio_srcpolicy->pc_policy.label !=
	     dst1->aio_dstpolicy->pc_policy.label)) {
		return(1);
	}
#endif

	/* Rule 6: Prefer higher precedence. */
#ifdef INET6
	if (dst1->aio_dstpolicy &&
	    (dst2->aio_dstpolicy == NULL ||
	     dst1->aio_dstpolicy->pc_policy.preced >
	     dst2->aio_dstpolicy->pc_policy.preced)) {
		return(-1);
	}
	if (dst2->aio_dstpolicy &&
	    (dst1->aio_dstpolicy == NULL ||
	     dst2->aio_dstpolicy->pc_policy.preced >
	     dst1->aio_dstpolicy->pc_policy.preced)) {
		return(1);
	}
#endif

	/* Rule 7: Prefer native transport. */
	/* XXX: not implemented yet */

	/* Rule 8: Prefer smaller scope. */
	if (dst1->aio_dstscope >= 0 &&
	    dst1->aio_dstscope < dst2->aio_dstscope) {
		return(-1);
	}
	if (dst2->aio_dstscope >= 0 &&
	    dst2->aio_dstscope < dst1->aio_dstscope) {
		return(1);
	}

	/*
	 * Rule 9: Use longest matching prefix.
	 * We compare the match length in a same AF only.
	 */
	if (dst1->aio_sa.sa_family == dst2->aio_sa.sa_family) {
		if (dst1->aio_matchlen > dst2->aio_matchlen) {
			return(-1);
		}
		if (dst1->aio_matchlen < dst2->aio_matchlen) {
			return(1);
		}
	}

	/* Rule 10: Otherwise, leave the order unchanged. */
	return(-1);
}

/*
 * Copy from scope.c.
 * XXX: we should standardize the functions and link them as standard
 * library.
 */
static int
gai_addr2scopetype(struct sockaddr *sa)
{
#ifdef INET6
	struct sockaddr_in6 *sa6;
#endif
	struct sockaddr_in *sa4;

	switch(sa->sa_family) {
#ifdef INET6
	case AF_INET6:
		sa6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) {
			/* just use the scope field of the multicast address */
			return(sa6->sin6_addr.s6_addr[2] & 0x0f);
		}
		/*
		 * Unicast addresses: map scope type to corresponding scope
		 * value defined for multcast addresses.
		 * XXX: hardcoded scope type values are bad...
		 */
		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			return(1); /* node local scope */
		if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr))
			return(2); /* link-local scope */
		if (IN6_IS_ADDR_SITELOCAL(&sa6->sin6_addr))
			return(5); /* site-local scope */
		return(14);	/* global scope */
		break;
#endif
	case AF_INET:
		/*
		 * IPv4 pseudo scoping according to RFC 3484.
		 */
		sa4 = (struct sockaddr_in *)sa;
		/* IPv4 autoconfiguration addresses have link-local scope. */
		if (((u_char *)&sa4->sin_addr)[0] == 169 &&
		    ((u_char *)&sa4->sin_addr)[1] == 254)
			return(2);
		/* Private addresses have site-local scope. */
		if (((u_char *)&sa4->sin_addr)[0] == 10 ||
		    (((u_char *)&sa4->sin_addr)[0] == 172 &&
		     (((u_char *)&sa4->sin_addr)[1] & 0xf0) == 16) ||
		    (((u_char *)&sa4->sin_addr)[0] == 192 &&
		     ((u_char *)&sa4->sin_addr)[1] == 168))
			return(14);	/* XXX: It should be 5 unless NAT */
		/* Loopback addresses have link-local scope. */
		if (((u_char *)&sa4->sin_addr)[0] == 127)
			return(2);
		return(14);
		break;
	default:
		errno = EAFNOSUPPORT; /* is this a good error? */
		return(-1);
	}
}

/*
 * FILES (/etc/hosts)
 */

static FILE *
_files_open(int *errp)
{
	FILE *fp;
	fp = fopen(_PATH_HOSTS, "r");
	if (fp == NULL)
		*errp = NO_RECOVERY;
	return fp;
}

static int
_files_ghbyname(void *rval, void *cb_data, va_list ap)
{
	const char *name;
	int af;
	int *errp;
	int match, nalias;
	char *p, *line, *addrstr, *cname;
	FILE *fp;
	struct hostent *rethp, *hp, hpbuf;
	char *aliases[MAXALIASES + 1], *addrs[2];
	union inx_addr addrbuf;
	char buf[BUFSIZ];

	name = va_arg(ap, const char *);
	af = va_arg(ap, int);
	errp = va_arg(ap, int *);

	*(struct hostent **)rval = NULL;

	if ((fp = _files_open(errp)) == NULL)
		return NS_UNAVAIL;
	rethp = hp = NULL;

	while (fgets(buf, sizeof(buf), fp)) {
		line = buf;
		if ((addrstr = _hgetword(&line)) == NULL
		||  (cname = _hgetword(&line)) == NULL)
			continue;
		match = (strcasecmp(cname, name) == 0);
		nalias = 0;
		while ((p = _hgetword(&line)) != NULL) {
			if (!match)
				match = (strcasecmp(p, name) == 0);
			if (nalias < MAXALIASES)
				aliases[nalias++] = p;
		}
		if (!match)
			continue;
		switch (af) {
		case AF_INET:
			if (inet_aton(addrstr, (struct in_addr *)&addrbuf)
			    != 1) {
				*errp = NO_DATA;	/* name found */
				continue;
			}
			break;
#ifdef INET6
		case AF_INET6:
			if (inet_pton(af, addrstr, &addrbuf) != 1) {
				*errp = NO_DATA;	/* name found */
				continue;
			}
			break;
#endif
		}
		hp = &hpbuf;
		hp->h_name = cname;
		hp->h_aliases = aliases;
		aliases[nalias] = NULL;
		hp->h_addrtype = af;
		hp->h_length = ADDRLEN(af);
		hp->h_addr_list = addrs;
		addrs[0] = (char *)&addrbuf;
		addrs[1] = NULL;
		hp = _hpcopy(hp, errp);
		rethp = _hpmerge(rethp, hp, errp);
	}
	fclose(fp);
	*(struct hostent **)rval = rethp;
	return (rethp != NULL) ? NS_SUCCESS : NS_NOTFOUND;
}

static int
_files_ghbyaddr(void *rval, void *cb_data, va_list ap)
{
	const void *addr;
	int addrlen;
	int af;
	int *errp;
	int nalias;
	char *p, *line;
	FILE *fp;
	struct hostent *hp, hpbuf;
	char *aliases[MAXALIASES + 1], *addrs[2];
	union inx_addr addrbuf;
	char buf[BUFSIZ];

	addr = va_arg(ap, const void *);
	addrlen = va_arg(ap, int);
	af = va_arg(ap, int);
	errp = va_arg(ap, int *);

	*(struct hostent**)rval = NULL;

	if ((fp = _files_open(errp)) == NULL)
		return NS_UNAVAIL;
	hp = NULL;
	while (fgets(buf, sizeof(buf), fp)) {
		line = buf;
		if ((p = _hgetword(&line)) == NULL
		||  (af == AF_INET
		     ? inet_aton(p, (struct in_addr *)&addrbuf)
		     : inet_pton(af, p, &addrbuf)) != 1
		||  memcmp(addr, &addrbuf, addrlen) != 0
		||  (p = _hgetword(&line)) == NULL)
			continue;
		hp = &hpbuf;
		hp->h_name = p;
		hp->h_aliases = aliases;
		nalias = 0;
		while ((p = _hgetword(&line)) != NULL) {
			if (nalias < MAXALIASES)
				aliases[nalias++] = p;
		}
		aliases[nalias] = NULL;
		hp->h_addrtype = af;
		hp->h_length = addrlen;
		hp->h_addr_list = addrs;
		addrs[0] = (char *)&addrbuf;
		addrs[1] = NULL;
		hp = _hpcopy(hp, errp);
		break;
	}
	fclose(fp);
	*(struct hostent **)rval = hp;
	return (hp != NULL) ? NS_SUCCESS : NS_NOTFOUND;
}

#ifdef YP
/*
 * NIS
 *
 * XXX actually a hack.
 */
static int
_nis_ghbyname(void *rval, void *cb_data, va_list ap)
{
	const char *name;
	int af;
	int *errp;
	struct hostent *hp = NULL;

	name = va_arg(ap, const char *);
	af = va_arg(ap, int);
	errp = va_arg(ap, int *);

	hp = _gethostbynisname(name, af);
	if (hp != NULL)
		hp = _hpcopy(hp, errp);

	*(struct hostent **)rval = hp;
	return (hp != NULL) ? NS_SUCCESS : NS_NOTFOUND;
}

static int
_nis_ghbyaddr(void *rval, void *cb_data, va_list ap)
{
	const void *addr;
	int addrlen;
	int af;
	int *errp;
	struct hostent *hp = NULL;

	addr = va_arg(ap, const void *);
	addrlen = va_arg(ap, int);
	af = va_arg(ap, int);

	hp = _gethostbynisaddr(addr, addrlen, af);
	if (hp != NULL)
		hp = _hpcopy(hp, errp);
	*(struct hostent **)rval = hp;
	return (hp != NULL) ? NS_SUCCESS : NS_NOTFOUND;
}
#endif

#define	MAXPACKET	(64*1024)

typedef union {
	HEADER hdr;
	u_char buf[MAXPACKET];
} querybuf;

static struct hostent *getanswer(const querybuf *, int, const char *, int,
	    struct hostent *, int *);

/*
 * we don't need to take care about sorting, nor IPv4 mapped address here.
 */
static struct hostent *
getanswer(const querybuf *answer, int anslen, const char *qname, int qtype,
    struct hostent *template, int *errp)
{
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom, *erdata;
	char *bp, *ep, **ap, **hap;
	int type, class, ancount, qdcount;
	int haveanswer, had_error;
	char tbuf[MAXDNAME];
	const char *tname;
	int (*name_ok)(const char *);
	static char *h_addr_ptrs[MAXADDRS + 1];
	static char *host_aliases[MAXALIASES];
	static char hostbuf[8*1024];

#define BOUNDED_INCR(x) \
	do { \
		cp += x; \
		if (cp > eom) { \
			*errp = NO_RECOVERY; \
			return (NULL); \
		} \
	} while (0)

#define BOUNDS_CHECK(ptr, count) \
	do { \
		if ((ptr) + (count) > eom) { \
			*errp = NO_RECOVERY; \
			return (NULL); \
		} \
	} while (0)

/* XXX do {} while (0) cannot be put here */
#define DNS_ASSERT(x) \
	{				\
		if (!(x)) {		\
			cp += n;	\
			continue;	\
		}			\
	}

/* XXX do {} while (0) cannot be put here */
#define DNS_FATAL(x) \
	{				\
		if (!(x)) {		\
			had_error++;	\
			continue;	\
		}			\
	}

	tname = qname;
	template->h_name = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
		name_ok = res_hnok;
		break;
	case T_PTR:
		name_ok = res_dnok;
		break;
	default:
		return (NULL);	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer->buf;
	BOUNDED_INCR(HFIXEDSZ);
	if (qdcount != 1) {
		*errp = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		*errp = NO_RECOVERY;
		return (NULL);
	}
	BOUNDED_INCR(n + QFIXEDSZ);
	if (qtype == T_A || qtype == T_AAAA) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			*errp = NO_RECOVERY;
			return (NULL);
		}
		template->h_name = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = template->h_name;
	}
	ap = host_aliases;
	*ap = NULL;
	template->h_aliases = host_aliases;
	hap = h_addr_ptrs;
	*hap = NULL;
	template->h_addr_list = h_addr_ptrs;
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		DNS_FATAL(n >= 0);
		DNS_FATAL((*name_ok)(bp));
		cp += n;			/* name */
		BOUNDS_CHECK(cp, 3 * INT16SZ + INT32SZ);
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		BOUNDS_CHECK(cp, n);
		erdata = cp + n;
		DNS_ASSERT(class == C_IN);
		if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME) {
			if (ap >= &host_aliases[MAXALIASES-1])
				continue;
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			DNS_FATAL(n >= 0);
			DNS_FATAL((*name_ok)(tbuf));
			cp += n;
			if (cp != erdata) {
				*errp = NO_RECOVERY;
				return (NULL);
			}
			/* Store alias. */
			*ap++ = bp;
			n = strlen(bp) + 1;	/* for the \0 */
			DNS_FATAL(n < MAXHOSTNAMELEN);
			bp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			DNS_FATAL(n <= ep - bp);
			DNS_FATAL(n < MAXHOSTNAMELEN);
			strcpy(bp, tbuf);
			template->h_name = bp;
			bp += n;
			continue;
		}
		if (qtype == T_PTR && type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if (n < 0 || !res_dnok(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			if (cp != erdata) {
				*errp = NO_RECOVERY;
				return (NULL);
			}
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			tname = bp;
			bp += n;
			continue;
		}
		DNS_ASSERT(type == qtype);
		switch (type) {
		case T_PTR:
			DNS_ASSERT(strcasecmp(tname, bp) == 0);
			n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
			DNS_FATAL(n >= 0);
			DNS_FATAL(res_hnok(bp));
#if MULTI_PTRS_ARE_ALIASES
			cp += n;
			if (cp != erdata) {
				*errp = NO_RECOVERY;
				return (NULL);
			}
			if (!haveanswer)
				template->h_name = bp;
			else if (ap < &host_aliases[MAXALIASES-1])
				*ap++ = bp;
			else
				n = -1;
			if (n != -1) {
				n = strlen(bp) + 1;	/* for the \0 */
				if (n >= MAXHOSTNAMELEN) {
					had_error++;
					break;
				}
				bp += n;
			}
			break;
#else
			template->h_name = bp;
			*errp = NETDB_SUCCESS;
			return (template);
#endif
		case T_A:
		case T_AAAA:
			DNS_ASSERT(strcasecmp(template->h_name, bp) == 0);
			DNS_ASSERT(n == template->h_length);
			if (!haveanswer) {
				int nn;

				template->h_name = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}
			bp = (char *)ALIGN(bp);

			DNS_FATAL(bp + n < ep);
			DNS_ASSERT(hap < &h_addr_ptrs[MAXADDRS-1]);
#ifdef FILTER_V4MAPPED
			if (type == T_AAAA) {
				struct in6_addr in6;
				memcpy(&in6, cp, sizeof(in6));
				DNS_ASSERT(IN6_IS_ADDR_V4MAPPED(&in6) == 0);
			}
#endif
			bcopy(cp, *hap++ = bp, n);
			bp += n;
			cp += n;
			if (cp != erdata) {
				*errp = NO_RECOVERY;
				return (NULL);
			}
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		*ap = NULL;
		*hap = NULL;
		if (!template->h_name) {
			n = strlen(qname) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN)
				goto no_recovery;
			strcpy(bp, qname);
			template->h_name = bp;
			bp += n;
		}
		*errp = NETDB_SUCCESS;
		return (template);
	}
 no_recovery:
	*errp = NO_RECOVERY;
	return (NULL);

#undef BOUNDED_INCR
#undef BOUNDS_CHECK
#undef DNS_ASSERT
#undef DNS_FATAL
}

static int
_dns_ghbyname(void *rval, void *cb_data, va_list ap)
{
	const char *name;
	int af;
	int *errp;
	int n;
	struct hostent *hp;
	int qtype;
	struct hostent hbuf;
	querybuf *buf;
	res_state statp;

	name = va_arg(ap, const char *);
	af = va_arg(ap, int);
	errp = va_arg(ap, int *);

	statp = __res_state();

	memset(&hbuf, 0, sizeof(hbuf));
	hbuf.h_addrtype = af;
	hbuf.h_length = ADDRLEN(af);

	switch (af) {
#ifdef INET6
	case AF_INET6:
		qtype = T_AAAA;
		break;
#endif
	case AF_INET:
		qtype = T_A;
		break;
	default:
		*errp = NO_RECOVERY;
		return NS_NOTFOUND;
	}
	buf = malloc(sizeof(*buf));
	if (buf == NULL) {
		*errp = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}
	n = res_nsearch(statp, name, C_IN, qtype, buf->buf, sizeof(buf->buf));
	if (n < 0) {
		free(buf);
		*errp = statp->res_h_errno;
		return NS_UNAVAIL;
	}
	hp = getanswer(buf, n, name, qtype, &hbuf, errp);
	free(buf);
	if (!hp) {
		*errp = NO_RECOVERY;
		return NS_NOTFOUND;
	}
	*(struct hostent **)rval = _hpcopy(&hbuf, errp);
	if (*(struct hostent **)rval != NULL)
		return NS_SUCCESS;
	else if (*errp == TRY_AGAIN)
		return NS_TRYAGAIN;
	else
		return NS_NOTFOUND;
}

static int
_dns_ghbyaddr(void *rval, void *cb_data, va_list ap)
{
	const void *addr;
	int addrlen;
	int af;
	int *errp;
	int n;
	int err;
	struct hostent *hp;
	u_char c, *cp;
	char *bp;
	struct hostent hbuf;
#ifdef INET6
	static const char hex[] = "0123456789abcdef";
#endif
	querybuf *buf;
	char qbuf[MAXDNAME+1];
	char *hlist[2];
	char *tld6[] = { "ip6.arpa", NULL };
	char *tld4[] = { "in-addr.arpa", NULL };
	char **tld;
	res_state statp;

	addr = va_arg(ap, const void *);
	addrlen = va_arg(ap, int);
	af = va_arg(ap, int);
	errp = va_arg(ap, int *);

	*(struct hostent **)rval = NULL;

#ifdef INET6
	/* XXX */
	if (af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)addr))
		return NS_NOTFOUND;
#endif

	switch (af) {
#ifdef INET6
	case AF_INET6:
		tld = tld6;
		break;
#endif
	case AF_INET:
		tld = tld4;
		break;
	default:
		return NS_NOTFOUND;
	}

	statp = __res_state();
	if ((statp->options & RES_INIT) == 0) {
		if (res_ninit(statp) < 0) {
			*errp = NETDB_INTERNAL;
			return NS_UNAVAIL;
		}
	}
	memset(&hbuf, 0, sizeof(hbuf));
	hbuf.h_name = NULL;
	hbuf.h_addrtype = af;
	hbuf.h_length = addrlen;

	buf = malloc(sizeof(*buf));
	if (buf == NULL) {
		*errp = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}
	err = NS_SUCCESS;
	for (/* nothing */; *tld; tld++) {
		/*
		 * XXX assumes that MAXDNAME is big enough - error checks
		 * has been made by callers
		 */
		n = 0;
		bp = qbuf;
		cp = (u_char *)addr+addrlen-1;
		switch (af) {
#ifdef INET6
		case AF_INET6:
			for (; n < addrlen; n++, cp--) {
				c = *cp;
				*bp++ = hex[c & 0xf];
				*bp++ = '.';
				*bp++ = hex[c >> 4];
				*bp++ = '.';
			}
			strcpy(bp, *tld);
			break;
#endif
		case AF_INET:
			for (; n < addrlen; n++, cp--) {
				c = *cp;
				if (c >= 100)
					*bp++ = '0' + c / 100;
				if (c >= 10)
					*bp++ = '0' + (c % 100) / 10;
				*bp++ = '0' + c % 10;
				*bp++ = '.';
			}
			strcpy(bp, *tld);
			break;
		}

		n = res_nquery(statp, qbuf, C_IN, T_PTR, buf->buf,
		    sizeof buf->buf);
		if (n < 0) {
			*errp = statp->res_h_errno;
			err = NS_UNAVAIL;
			continue;
		} else if (n > sizeof(buf->buf)) {
#if 0
			errno = ERANGE; /* XXX is it OK to set errno here? */
#endif
			*errp = NETDB_INTERNAL;
			err = NS_UNAVAIL;
			continue;
		}
		hp = getanswer(buf, n, qbuf, T_PTR, &hbuf, errp);
		if (!hp) {
			err = NS_NOTFOUND;
			continue;
		}
		free(buf);
		hbuf.h_addrtype = af;
		hbuf.h_length = addrlen;
		hbuf.h_addr_list = hlist;
		hlist[0] = (char *)addr;
		hlist[1] = NULL;
		*(struct hostent **)rval = _hpcopy(&hbuf, errp);
		return NS_SUCCESS;
	}
	free(buf);
	return err;
}

static void
_dns_shent(int stayopen)
{
	res_state statp;

	statp = __res_state();
	if ((statp->options & RES_INIT) == 0) {
		if (res_ninit(statp) < 0)
			return;
	}
	if (stayopen)
		statp->options |= RES_STAYOPEN | RES_USEVC;
}

static void
_dns_ehent(void)
{
	res_state statp;

	statp = __res_state();
	statp->options &= ~(RES_STAYOPEN | RES_USEVC);
	res_nclose(statp);
}

#ifdef ICMPNL

/*
 * experimental:
 *	draft-ietf-ipngwg-icmp-namelookups-09.txt
 *	ifindex is assumed to be encoded in addr.
 */
#include <sys/uio.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <ctype.h>

#ifndef NI_QTYPE_NODENAME
#define NI_QTYPE_NODENAME	NI_QTYPE_DNSNAME
#endif

static char *
dnsdecode(sp, ep, base, buf, bufsiz)
	const u_char **sp;
	const u_char *ep;
	const u_char *base;	/*base for compressed name*/
	u_char *buf;
	size_t bufsiz;
{
	int i;
	const u_char *cp;
	char cresult[MAXDNAME + 1];
	const u_char *comp;
	int l;

	cp = *sp;
	*buf = '\0';

	if (cp >= ep)
		return NULL;
	while (cp < ep) {
		i = *cp;
		if (i == 0 || cp != *sp) {
			if (strlcat(buf, ".", bufsiz) >= bufsiz)
				return NULL;	/* result overrun */
		}
		if (i == 0)
			break;
		cp++;

		if ((i & 0xc0) == 0xc0 && cp - base > (i & 0x3f)) {
			/* DNS compression */
			if (!base)
				return NULL;

			comp = base + (i & 0x3f);
			if (dnsdecode(&comp, cp, base, cresult,
			    sizeof(cresult)) == NULL)
				return NULL;
			if (strlcat(buf, cresult, bufsiz) >= bufsiz)
				return NULL;	/* result overrun */
			break;
		} else if ((i & 0x3f) == i) {
			if (i > ep - cp)
				return NULL;	/* source overrun */
			while (i-- > 0 && cp < ep) {
				l = snprintf(cresult, sizeof(cresult),
				    isprint(*cp) ? "%c" : "\\%03o", *cp & 0xff);
				if (l >= sizeof(cresult) || l < 0)
					return NULL;
				if (strlcat(buf, cresult, bufsiz) >= bufsiz)
					return NULL;	/* result overrun */
				cp++;
			}
		} else
			return NULL;	/* invalid label */
	}
	if (i != 0)
		return NULL;	/* not terminated */
	cp++;
	*sp = cp;
	return buf;
}

static char *
_icmp_nodeinfo_query(const struct in6_addr *addr, int ifindex)
{
	int s;
	struct icmp6_filter filter;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pkt;
	char cbuf[256], buf[1024], *cp, *end;
	int cc;
	struct icmp6_nodeinfo niq, *nir;
	struct sockaddr_in6 sin6;
	struct iovec iov;
	fd_set s_fds, fds;
	struct timeval tout;
	int len;
	static int pid;
	static char dnsname[MAXDNAME + 1]; /* XXX: thread unsafe */
	u_int32_t r1, r2;

	if (pid == 0)
		pid = getpid();

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_NI_REPLY, &filter);

	FD_ZERO(&s_fds);
	tout.tv_sec = 0;
	tout.tv_usec = 500000;	/* 500ms */

	memset(&niq, 0, sizeof(niq));
	niq.ni_type = ICMP6_NI_QUERY;
	niq.ni_code = ICMP6_NI_SUBJ_IPV6;
	niq.ni_qtype = htons(NI_QTYPE_NODENAME);
	niq.ni_flags = 0;
	r1 = arc4random();
	r2 = arc4random();
	memcpy(&niq.icmp6_ni_nonce[0], &r1, sizeof(r1));
	memcpy(&niq.icmp6_ni_nonce[4], &r2, sizeof(r2));

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *addr;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (caddr_t)&sin6;
	msg.msg_namelen = sizeof(sin6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	iov.iov_base = (caddr_t)&niq;
	iov.iov_len = sizeof(struct icmp6_nodeinfo);

	if (ifindex) {
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		pkt = (struct in6_pktinfo *)&cmsg[1];
		memset(&pkt->ipi6_addr, 0, sizeof(struct in6_addr));
		pkt->ipi6_ifindex = ifindex;
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		msg.msg_controllen = (char *)cmsg - cbuf;
	}

	/* XXX: we need root privilege here */
	if ((s = _socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
		return NULL;
	(void)_setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER,
			 (char *)&filter, sizeof(filter));
	cc = _sendmsg(s, &msg, 0);
	if (cc < 0) {
		_close(s);
		return (NULL);
	}
	FD_SET(s, &s_fds);
	for (;;) {
		fds = s_fds;
		if (_select(s + 1, &fds, NULL, NULL, &tout) <= 0) {
			_close(s);
			return (NULL);
		}
		len = sizeof(sin6);
		cc = _recvfrom(s, buf, sizeof(buf), 0,
			      (struct sockaddr *)&sin6, &len);
		if (cc <= 0) {
			_close(s);
			return (NULL);
		}
		if (cc < sizeof(struct icmp6_hdr))
			continue;
		nir = (struct icmp6_nodeinfo *)buf;
		if (nir->ni_type != ICMP6_NI_REPLY)
			continue;
		if (nir->ni_qtype != htons(NI_QTYPE_NODENAME))
			continue;
		if (memcmp(nir->icmp6_ni_nonce, niq.icmp6_ni_nonce,
		    sizeof(nir->icmp6_ni_nonce)) != 0) {
			continue;
		}
		if (nir->ni_code != htons(ICMP6_NI_SUCCESS))
			continue; /* or should we fail? */

		/* this is an expected reply. */
		break;
	}
	_close(s);

	memset(dnsname, 0, sizeof(dnsname));
	cp = (char *)(nir + 1);
	end = ((char *)nir) + cc;
	if (end - cp < sizeof(int32_t))	/* for TTL.  we don't use it. */
		return (NULL);
	cp += sizeof(int32_t);
	if (*cp == end - cp - 1) { /* an old version */
		int nlen;

		cp++;	/* skip length */
		nlen = end - cp;
		if (nlen > MAXDNAME)
			return (NULL); /* XXX: use it anyway? */
		memcpy(dnsname, cp, nlen);
	} else {
		/* XXX: should we use a generic function? */
		if (dnsdecode((const u_char **)(void *)&cp, end,
		    (const u_char *)(nir + 1), dnsname, sizeof(dnsname))
		    == NULL) {
			return (NULL); /* bogus name */
		}
		/* Name-lookup special handling for truncated name. */
		if (cp + 1 <= end && !*cp && strlen(dnsname) > 0)
			dnsname[strlen(dnsname) - 1] = '\0';

		/* There may be other names, but we ignore them. */
	}

	return (dnsname);
}

static int
_icmp_ghbyaddr(void *rval, void *cb_data, va_list ap)
{
	const void *addr;
	int addrlen;
	int af;
	int *errp;
	char *hname;
	int ifindex = 0;
	struct in6_addr addr6;

	addr = va_arg(ap, const void *);
	addrlen = va_arg(ap, int);
	af = va_arg(ap, int);
	errp = va_arg(ap, int *);

	*(struct hostent **)rval = NULL;

	if (af != AF_INET6 || addrlen != sizeof(addr6)) {
		/*
		 * Note: rfc1788 defines Who Are You for IPv4,
		 * but no one implements it.
		 */
		return (NS_NOTFOUND);
	}

	memcpy(&addr6, addr, addrlen);
	if (IN6_IS_ADDR_LINKLOCAL(&addr6)) {
		ifindex = (addr6.s6_addr[2] << 8) | addr6.s6_addr[3];
		addr6.s6_addr[2] = addr6.s6_addr[3] = 0;
	}

	THREAD_LOCK();
	if ((hname = _icmp_nodeinfo_query(&addr6, ifindex)) == NULL) {
		THREAD_UNLOCK();
		return (NS_NOTFOUND);
	}
	*(struct hostent **)rval =_hpaddr(af, hname, &addr6, errp);
	THREAD_UNLOCK();
	return (NS_SUCCESS);
}
#endif /* ICMPNL */
