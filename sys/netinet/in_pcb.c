/*
 * Copyright (c) 1982, 1986, 1991, 1993, 1995
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
 *	@(#)in_pcb.c	8.4 (Berkeley) 5/24/95
 * $FreeBSD$
 */

#include "opt_ipsec.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <vm/uma.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif /* INET6 */

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /* IPSEC */

#ifdef FAST_IPSEC
#if defined(IPSEC) || defined(IPSEC_ESP)
#error "Bad idea: don't compile with both IPSEC and FAST_IPSEC!"
#endif

#include <netipsec/ipsec.h>
#include <netipsec/key.h>
#define	IPSEC
#endif /* FAST_IPSEC */

struct	in_addr zeroin_addr;

/*
 * These configure the range of local port addresses assigned to
 * "unspecified" outgoing connections/packets/whatever.
 */
int	ipport_lowfirstauto  = IPPORT_RESERVED - 1;	/* 1023 */
int	ipport_lowlastauto = IPPORT_RESERVEDSTART;	/* 600 */
int	ipport_firstauto = IPPORT_HIFIRSTAUTO;		/* 49152 */
int	ipport_lastauto  = IPPORT_HILASTAUTO;		/* 65535 */
int	ipport_hifirstauto = IPPORT_HIFIRSTAUTO;	/* 49152 */
int	ipport_hilastauto  = IPPORT_HILASTAUTO;		/* 65535 */

/*
 * Reserved ports accessible only to root. There are significant
 * security considerations that must be accounted for when changing these,
 * but the security benefits can be great. Please be careful.
 */
int	ipport_reservedhigh = IPPORT_RESERVED - 1;	/* 1023 */
int	ipport_reservedlow = 0;

#define RANGECHK(var, min, max) \
	if ((var) < (min)) { (var) = (min); } \
	else if ((var) > (max)) { (var) = (max); }

static int
sysctl_net_ipport_check(SYSCTL_HANDLER_ARGS)
{
	int error = sysctl_handle_int(oidp,
		oidp->oid_arg1, oidp->oid_arg2, req);
	if (!error) {
		RANGECHK(ipport_lowfirstauto, 1, IPPORT_RESERVED - 1);
		RANGECHK(ipport_lowlastauto, 1, IPPORT_RESERVED - 1);
		RANGECHK(ipport_firstauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_lastauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_hifirstauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_hilastauto, IPPORT_RESERVED, USHRT_MAX);
	}
	return error;
}

#undef RANGECHK

SYSCTL_NODE(_net_inet_ip, IPPROTO_IP, portrange, CTLFLAG_RW, 0, "IP Ports");

SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, lowfirst, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_lowfirstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, lowlast, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_lowlastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, first, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_firstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, last, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_lastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, hifirst, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_hifirstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, hilast, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_hilastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_INT(_net_inet_ip_portrange, OID_AUTO, reservedhigh,
	   CTLFLAG_RW|CTLFLAG_SECURE, &ipport_reservedhigh, 0, "");
SYSCTL_INT(_net_inet_ip_portrange, OID_AUTO, reservedlow,
	   CTLFLAG_RW|CTLFLAG_SECURE, &ipport_reservedlow, 0, "");

/*
 * in_pcb.c: manage the Protocol Control Blocks.
 *
 * NOTE: It is assumed that most of these functions will be called at
 * splnet(). XXX - There are, unfortunately, a few exceptions to this
 * rule that should be fixed.
 */

/*
 * Allocate a PCB and associate it with the socket.
 */
int
in_pcballoc(so, pcbinfo, td)
	struct socket *so;
	struct inpcbinfo *pcbinfo;
	struct thread *td;
{
	register struct inpcb *inp;
#ifdef IPSEC
	int error;
#endif
	inp = uma_zalloc(pcbinfo->ipi_zone, M_NOWAIT | M_ZERO);
	if (inp == NULL)
		return (ENOBUFS);
	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	inp->inp_pcbinfo = pcbinfo;
	inp->inp_socket = so;
#ifdef IPSEC
	error = ipsec_init_policy(so, &inp->inp_sp);
	if (error != 0) {
		uma_zfree(pcbinfo->ipi_zone, inp);
		return error;
	}
#endif /*IPSEC*/
#if defined(INET6)
	if (INP_SOCKAF(so) == AF_INET6) {
		inp->inp_vflag |= INP_IPV6PROTO;
		if (ip6_v6only)
			inp->inp_flags |= IN6P_IPV6_V6ONLY;
	}
#endif
	LIST_INSERT_HEAD(pcbinfo->listhead, inp, inp_list);
	pcbinfo->ipi_count++;
	so->so_pcb = (caddr_t)inp;
	INP_LOCK_INIT(inp, "inp");
#ifdef INET6
	if (ip6_auto_flowlabel)
		inp->inp_flags |= IN6P_AUTOFLOWLABEL;
#endif
	return (0);
}

int
in_pcbbind(inp, nam, td)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct thread *td;
{
	int anonport, error;

	if (inp->inp_lport != 0 || inp->inp_laddr.s_addr != INADDR_ANY)
		return (EINVAL);
	anonport = inp->inp_lport == 0 && (nam == NULL ||
	    ((struct sockaddr_in *)nam)->sin_port == 0);
	error = in_pcbbind_setup(inp, nam, &inp->inp_laddr.s_addr,
	    &inp->inp_lport, td);
	if (error)
		return (error);
	if (in_pcbinshash(inp) != 0) {
		inp->inp_laddr.s_addr = INADDR_ANY;
		inp->inp_lport = 0;
		return (EAGAIN);
	}
	if (anonport)
		inp->inp_flags |= INP_ANONPORT;
	return (0);
}

/*
 * Set up a bind operation on a PCB, performing port allocation
 * as required, but do not actually modify the PCB. Callers can
 * either complete the bind by setting inp_laddr/inp_lport and
 * calling in_pcbinshash(), or they can just use the resulting
 * port and address to authorise the sending of a once-off packet.
 *
 * On error, the values of *laddrp and *lportp are not changed.
 */
int
in_pcbbind_setup(inp, nam, laddrp, lportp, td)
	struct inpcb *inp;
	struct sockaddr *nam;
	in_addr_t *laddrp;
	u_short *lportp;
	struct thread *td;
{
	struct socket *so = inp->inp_socket;
	unsigned short *lastport;
	struct sockaddr_in *sin;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct in_addr laddr;
	u_short lport = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);
	int error, prison = 0;

	if (TAILQ_EMPTY(&in_ifaddrhead)) /* XXX broken! */
		return (EADDRNOTAVAIL);
	laddr.s_addr = *laddrp;
	if (nam != NULL && laddr.s_addr != INADDR_ANY)
		return (EINVAL);
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;
	if (nam) {
		sin = (struct sockaddr_in *)nam;
		if (nam->sa_len != sizeof (*sin))
			return (EINVAL);
#ifdef notdef
		/*
		 * We should check the family, but old programs
		 * incorrectly fail to initialize it.
		 */
		if (sin->sin_family != AF_INET)
			return (EAFNOSUPPORT);
#endif
		if (sin->sin_addr.s_addr != INADDR_ANY)
			if (prison_ip(td->td_ucred, 0, &sin->sin_addr.s_addr))
				return(EINVAL);
		if (sin->sin_port != *lportp) {
			/* Don't allow the port to change. */
			if (*lportp != 0)
				return (EINVAL);
			lport = sin->sin_port;
		}
		/* NB: lport is left as 0 if the port isn't being changed. */
		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
			/*
			 * Treat SO_REUSEADDR as SO_REUSEPORT for multicast;
			 * allow complete duplication of binding if
			 * SO_REUSEPORT is set, or if SO_REUSEADDR is set
			 * and a multicast address is bound on both
			 * new and duplicated sockets.
			 */
			if (so->so_options & SO_REUSEADDR)
				reuseport = SO_REUSEADDR|SO_REUSEPORT;
		} else if (sin->sin_addr.s_addr != INADDR_ANY) {
			sin->sin_port = 0;		/* yech... */
			bzero(&sin->sin_zero, sizeof(sin->sin_zero));
			if (ifa_ifwithaddr((struct sockaddr *)sin) == 0)
				return (EADDRNOTAVAIL);
		}
		laddr = sin->sin_addr;
		if (lport) {
			struct inpcb *t;
			/* GROSS */
			if (ntohs(lport) <= ipport_reservedhigh &&
			    ntohs(lport) >= ipport_reservedlow &&
			    td && suser_cred(td->td_ucred, PRISON_ROOT))
				return (EACCES);
			if (td && jailed(td->td_ucred))
				prison = 1;
			if (so->so_cred->cr_uid != 0 &&
			    !IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
				t = in_pcblookup_local(inp->inp_pcbinfo,
				    sin->sin_addr, lport,
				    prison ? 0 :  INPLOOKUP_WILDCARD);
	/*
	 * XXX
	 * This entire block sorely needs a rewrite.
	 */
				if (t && (t->inp_vflag & INP_TIMEWAIT)) {
					if ((ntohl(sin->sin_addr.s_addr) != INADDR_ANY ||
					    ntohl(t->inp_laddr.s_addr) != INADDR_ANY ||
					    (intotw(t)->tw_so_options & SO_REUSEPORT) == 0) &&
					    (so->so_cred->cr_uid != intotw(t)->tw_cred->cr_uid))
						return (EADDRINUSE);
				} else
				if (t &&
				    (ntohl(sin->sin_addr.s_addr) != INADDR_ANY ||
				     ntohl(t->inp_laddr.s_addr) != INADDR_ANY ||
				     (t->inp_socket->so_options &
					 SO_REUSEPORT) == 0) &&
				    (so->so_cred->cr_uid !=
				     t->inp_socket->so_cred->cr_uid)) {
#if defined(INET6)
					if (ntohl(sin->sin_addr.s_addr) !=
					    INADDR_ANY ||
					    ntohl(t->inp_laddr.s_addr) !=
					    INADDR_ANY ||
					    INP_SOCKAF(so) ==
					    INP_SOCKAF(t->inp_socket))
#endif /* defined(INET6) */
					return (EADDRINUSE);
				}
			}
			if (prison &&
			    prison_ip(td->td_ucred, 0, &sin->sin_addr.s_addr))
				return (EADDRNOTAVAIL);
			t = in_pcblookup_local(pcbinfo, sin->sin_addr,
			    lport, prison ? 0 : wild);
			if (t && (t->inp_vflag & INP_TIMEWAIT)) {
				if ((reuseport & intotw(t)->tw_so_options) == 0)
					return (EADDRINUSE);
			} else
			if (t &&
			    (reuseport & t->inp_socket->so_options) == 0) {
#if defined(INET6)
				if (ntohl(sin->sin_addr.s_addr) !=
				    INADDR_ANY ||
				    ntohl(t->inp_laddr.s_addr) !=
				    INADDR_ANY ||
				    INP_SOCKAF(so) ==
				    INP_SOCKAF(t->inp_socket))
#endif /* defined(INET6) */
				return (EADDRINUSE);
			}
		}
	}
	if (*lportp != 0)
		lport = *lportp;
	if (lport == 0) {
		u_short first, last;
		int count;

		if (laddr.s_addr != INADDR_ANY)
			if (prison_ip(td->td_ucred, 0, &laddr.s_addr))
				return (EINVAL);

		if (inp->inp_flags & INP_HIGHPORT) {
			first = ipport_hifirstauto;	/* sysctl */
			last  = ipport_hilastauto;
			lastport = &pcbinfo->lasthi;
		} else if (inp->inp_flags & INP_LOWPORT) {
			if (td && (error = suser_cred(td->td_ucred,
			    PRISON_ROOT)) != 0)
				return error;
			first = ipport_lowfirstauto;	/* 1023 */
			last  = ipport_lowlastauto;	/* 600 */
			lastport = &pcbinfo->lastlow;
		} else {
			first = ipport_firstauto;	/* sysctl */
			last  = ipport_lastauto;
			lastport = &pcbinfo->lastport;
		}
		/*
		 * Simple check to ensure all ports are not used up causing
		 * a deadlock here.
		 *
		 * We split the two cases (up and down) so that the direction
		 * is not being tested on each round of the loop.
		 */
		if (first > last) {
			/*
			 * counting down
			 */
			count = first - last;

			do {
				if (count-- < 0)	/* completely used? */
					return (EADDRNOTAVAIL);
				--*lastport;
				if (*lastport > first || *lastport < last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local(pcbinfo, laddr, lport,
			    wild));
		} else {
			/*
			 * counting up
			 */
			count = last - first;

			do {
				if (count-- < 0)	/* completely used? */
					return (EADDRNOTAVAIL);
				++*lastport;
				if (*lastport < first || *lastport > last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local(pcbinfo, laddr, lport,
			    wild));
		}
	}
	if (prison_ip(td->td_ucred, 0, &laddr.s_addr))
		return (EINVAL);
	*laddrp = laddr.s_addr;
	*lportp = lport;
	return (0);
}

/*
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 */
int
in_pcbconnect(inp, nam, td)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct thread *td;
{
	u_short lport, fport;
	in_addr_t laddr, faddr;
	int anonport, error;

	lport = inp->inp_lport;
	laddr = inp->inp_laddr.s_addr;
	anonport = (lport == 0);
	error = in_pcbconnect_setup(inp, nam, &laddr, &lport, &faddr, &fport,
	    NULL, td);
	if (error)
		return (error);

	/* Do the initial binding of the local address if required. */
	if (inp->inp_laddr.s_addr == INADDR_ANY && inp->inp_lport == 0) {
		inp->inp_lport = lport;
		inp->inp_laddr.s_addr = laddr;
		if (in_pcbinshash(inp) != 0) {
			inp->inp_laddr.s_addr = INADDR_ANY;
			inp->inp_lport = 0;
			return (EAGAIN);
		}
	}

	/* Commit the remaining changes. */
	inp->inp_lport = lport;
	inp->inp_laddr.s_addr = laddr;
	inp->inp_faddr.s_addr = faddr;
	inp->inp_fport = fport;
	in_pcbrehash(inp);
	if (anonport)
		inp->inp_flags |= INP_ANONPORT;
	return (0);
}

/*
 * Set up for a connect from a socket to the specified address.
 * On entry, *laddrp and *lportp should contain the current local
 * address and port for the PCB; these are updated to the values
 * that should be placed in inp_laddr and inp_lport to complete
 * the connect.
 *
 * On success, *faddrp and *fportp will be set to the remote address
 * and port. These are not updated in the error case.
 *
 * If the operation fails because the connection already exists,
 * *oinpp will be set to the PCB of that connection so that the
 * caller can decide to override it. In all other cases, *oinpp
 * is set to NULL.
 */
int
in_pcbconnect_setup(inp, nam, laddrp, lportp, faddrp, fportp, oinpp, td)
	register struct inpcb *inp;
	struct sockaddr *nam;
	in_addr_t *laddrp;
	u_short *lportp;
	in_addr_t *faddrp;
	u_short *fportp;
	struct inpcb **oinpp;
	struct thread *td;
{
	struct sockaddr_in *sin = (struct sockaddr_in *)nam;
	struct in_ifaddr *ia;
	struct sockaddr_in sa;
	struct ucred *cred;
	struct inpcb *oinp;
	struct in_addr laddr, faddr;
	u_short lport, fport;
	int error;

	if (oinpp != NULL)
		*oinpp = NULL;
	if (nam->sa_len != sizeof (*sin))
		return (EINVAL);
	if (sin->sin_family != AF_INET)
		return (EAFNOSUPPORT);
	if (sin->sin_port == 0)
		return (EADDRNOTAVAIL);
	laddr.s_addr = *laddrp;
	lport = *lportp;
	faddr = sin->sin_addr;
	fport = sin->sin_port;
	cred = inp->inp_socket->so_cred;
	if (laddr.s_addr == INADDR_ANY && jailed(cred)) {
		bzero(&sa, sizeof(sa));
		sa.sin_addr.s_addr = htonl(prison_getip(cred));
		sa.sin_len = sizeof(sa);
		sa.sin_family = AF_INET;
		error = in_pcbbind_setup(inp, (struct sockaddr *)&sa,
		    &laddr.s_addr, &lport, td);
		if (error)
			return (error);
	}

	if (!TAILQ_EMPTY(&in_ifaddrhead)) {
		/*
		 * If the destination address is INADDR_ANY,
		 * use the primary local address.
		 * If the supplied address is INADDR_BROADCAST,
		 * and the primary interface supports broadcast,
		 * choose the broadcast address for that interface.
		 */
		if (faddr.s_addr == INADDR_ANY)
			faddr = IA_SIN(TAILQ_FIRST(&in_ifaddrhead))->sin_addr;
		else if (faddr.s_addr == (u_long)INADDR_BROADCAST &&
		    (TAILQ_FIRST(&in_ifaddrhead)->ia_ifp->if_flags &
		    IFF_BROADCAST))
			faddr = satosin(&TAILQ_FIRST(
			    &in_ifaddrhead)->ia_broadaddr)->sin_addr;
	}
	if (laddr.s_addr == INADDR_ANY) {
		register struct route *ro;

		ia = (struct in_ifaddr *)0;
		/*
		 * If route is known or can be allocated now,
		 * our src addr is taken from the i/f, else punt.
		 * Note that we should check the address family of the cached
		 * destination, in case of sharing the cache with IPv6.
		 */
		ro = &inp->inp_route;
		if (ro->ro_rt &&
		    (ro->ro_dst.sa_family != AF_INET ||
		     satosin(&ro->ro_dst)->sin_addr.s_addr != faddr.s_addr ||
		     inp->inp_socket->so_options & SO_DONTROUTE)) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)0;
		}
		if ((inp->inp_socket->so_options & SO_DONTROUTE) == 0 && /*XXX*/
		    (ro->ro_rt == (struct rtentry *)0 ||
		    ro->ro_rt->rt_ifp == (struct ifnet *)0)) {
			/* No route yet, so try to acquire one */
			bzero(&ro->ro_dst, sizeof(struct sockaddr_in));
			ro->ro_dst.sa_family = AF_INET;
			ro->ro_dst.sa_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)&ro->ro_dst)->sin_addr = faddr;
			rtalloc(ro);
		}
		/*
		 * If we found a route, use the address
		 * corresponding to the outgoing interface
		 * unless it is the loopback (in case a route
		 * to our address on another net goes to loopback).
		 */
		if (ro->ro_rt && !(ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK))
			ia = ifatoia(ro->ro_rt->rt_ifa);
		if (ia == 0) {
			bzero(&sa, sizeof(sa));
			sa.sin_addr = faddr;
			sa.sin_len = sizeof(sa);
			sa.sin_family = AF_INET;

			ia = ifatoia(ifa_ifwithdstaddr(sintosa(&sa)));
			if (ia == 0)
				ia = ifatoia(ifa_ifwithnet(sintosa(&sa)));
			if (ia == 0)
				ia = TAILQ_FIRST(&in_ifaddrhead);
			if (ia == 0)
				return (EADDRNOTAVAIL);
		}
		/*
		 * If the destination address is multicast and an outgoing
		 * interface has been set as a multicast option, use the
		 * address of that interface as our source address.
		 */
		if (IN_MULTICAST(ntohl(faddr.s_addr)) &&
		    inp->inp_moptions != NULL) {
			struct ip_moptions *imo;
			struct ifnet *ifp;

			imo = inp->inp_moptions;
			if (imo->imo_multicast_ifp != NULL) {
				ifp = imo->imo_multicast_ifp;
				TAILQ_FOREACH(ia, &in_ifaddrhead, ia_link)
					if (ia->ia_ifp == ifp)
						break;
				if (ia == 0)
					return (EADDRNOTAVAIL);
			}
		}
		laddr = ia->ia_addr.sin_addr;
	}

	oinp = in_pcblookup_hash(inp->inp_pcbinfo, faddr, fport, laddr, lport,
	    0, NULL);
	if (oinp != NULL) {
		if (oinpp != NULL)
			*oinpp = oinp;
		return (EADDRINUSE);
	}
	if (lport == 0) {
		error = in_pcbbind_setup(inp, NULL, &laddr.s_addr, &lport, td);
		if (error)
			return (error);
	}
	*laddrp = laddr.s_addr;
	*lportp = lport;
	*faddrp = faddr.s_addr;
	*fportp = fport;
	return (0);
}

void
in_pcbdisconnect(inp)
	struct inpcb *inp;
{

	inp->inp_faddr.s_addr = INADDR_ANY;
	inp->inp_fport = 0;
	in_pcbrehash(inp);
	if (inp->inp_socket->so_state & SS_NOFDREF)
		in_pcbdetach(inp);
}

void
in_pcbdetach(inp)
	struct inpcb *inp;
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

#ifdef IPSEC
	ipsec4_delete_pcbpolicy(inp);
#endif /*IPSEC*/
	inp->inp_gencnt = ++ipi->ipi_gencnt;
	in_pcbremlists(inp);
	if (so) {
		so->so_pcb = 0;
		sotryfree(so);
	}
	if (inp->inp_options)
		(void)m_free(inp->inp_options);
	if (inp->inp_route.ro_rt)
		RTFREE(inp->inp_route.ro_rt);
	ip_freemoptions(inp->inp_moptions);
	inp->inp_vflag = 0;
	INP_LOCK_DESTROY(inp);
	uma_zfree(ipi->ipi_zone, inp);
}

struct sockaddr *
in_sockaddr(port, addr_p)
	in_port_t port;
	struct in_addr *addr_p;
{
	struct sockaddr_in *sin;

	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME,
		M_WAITOK | M_ZERO);
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	sin->sin_addr = *addr_p;
	sin->sin_port = port;

	return (struct sockaddr *)sin;
}

/*
 * The wrapper function will pass down the pcbinfo for this function to lock.
 * The socket must have a valid
 * (i.e., non-nil) PCB, but it should be impossible to get an invalid one
 * except through a kernel programming error, so it is acceptable to panic
 * (or in this case trap) if the PCB is invalid.  (Actually, we don't trap
 * because there actually /is/ a programming error somewhere... XXX)
 */
int
in_setsockaddr(so, nam, pcbinfo)
	struct socket *so;
	struct sockaddr **nam;
	struct inpcbinfo *pcbinfo;
{
	int s;
	register struct inpcb *inp;
	struct in_addr addr;
	in_port_t port;

	s = splnet();
	INP_INFO_RLOCK(pcbinfo);
	inp = sotoinpcb(so);
	if (!inp) {
		INP_INFO_RUNLOCK(pcbinfo);
		splx(s);
		return ECONNRESET;
	}
	INP_LOCK(inp);
	port = inp->inp_lport;
	addr = inp->inp_laddr;
	INP_UNLOCK(inp);
	INP_INFO_RUNLOCK(pcbinfo);
	splx(s);

	*nam = in_sockaddr(port, &addr);
	return 0;
}

/*
 * The wrapper function will pass down the pcbinfo for this function to lock.
 */
int
in_setpeeraddr(so, nam, pcbinfo)
	struct socket *so;
	struct sockaddr **nam;
	struct inpcbinfo *pcbinfo;
{
	int s;
	register struct inpcb *inp;
	struct in_addr addr;
	in_port_t port;

	s = splnet();
	INP_INFO_RLOCK(pcbinfo);
	inp = sotoinpcb(so);
	if (!inp) {
		INP_INFO_RUNLOCK(pcbinfo);
		splx(s);
		return ECONNRESET;
	}
	INP_LOCK(inp);
	port = inp->inp_fport;
	addr = inp->inp_faddr;
	INP_UNLOCK(inp);
	INP_INFO_RUNLOCK(pcbinfo);
	splx(s);

	*nam = in_sockaddr(port, &addr);
	return 0;
}

void
in_pcbnotifyall(pcbinfo, faddr, errno, notify)
	struct inpcbinfo *pcbinfo;
	struct in_addr faddr;
	int errno;
	struct inpcb *(*notify)(struct inpcb *, int);
{
	struct inpcb *inp, *ninp;
	struct inpcbhead *head;
	int s;

	s = splnet();
	INP_INFO_WLOCK(pcbinfo);
	head = pcbinfo->listhead;
	for (inp = LIST_FIRST(head); inp != NULL; inp = ninp) {
		INP_LOCK(inp);
		ninp = LIST_NEXT(inp, inp_list);
#ifdef INET6
		if ((inp->inp_vflag & INP_IPV4) == 0) {
			INP_UNLOCK(inp);
			continue;
		}
#endif
		if (inp->inp_faddr.s_addr != faddr.s_addr ||
		    inp->inp_socket == NULL) {
			INP_UNLOCK(inp);
			continue;
		}
		if ((*notify)(inp, errno))
			INP_UNLOCK(inp);
	}
	INP_INFO_WUNLOCK(pcbinfo);
	splx(s);
}

void
in_pcbpurgeif0(pcbinfo, ifp)
	struct inpcbinfo *pcbinfo;
	struct ifnet *ifp;
{
	struct inpcb *inp;
	struct ip_moptions *imo;
	int i, gap;

	/* why no splnet here? XXX */
	INP_INFO_RLOCK(pcbinfo);
	LIST_FOREACH(inp, pcbinfo->listhead, inp_list) {
		INP_LOCK(inp);
		imo = inp->inp_moptions;
		if ((inp->inp_vflag & INP_IPV4) &&
		    imo != NULL) {
			/*
			 * Unselect the outgoing interface if it is being
			 * detached.
			 */
			if (imo->imo_multicast_ifp == ifp)
				imo->imo_multicast_ifp = NULL;

			/*
			 * Drop multicast group membership if we joined
			 * through the interface being detached.
			 */
			for (i = 0, gap = 0; i < imo->imo_num_memberships;
			    i++) {
				if (imo->imo_membership[i]->inm_ifp == ifp) {
					in_delmulti(imo->imo_membership[i]);
					gap++;
				} else if (gap != 0)
					imo->imo_membership[i - gap] =
					    imo->imo_membership[i];
			}
			imo->imo_num_memberships -= gap;
		}
		INP_UNLOCK(inp);
	}
	INP_INFO_RUNLOCK(pcbinfo);
}

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in_losing(inp)
	struct inpcb *inp;
{
	register struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = inp->inp_route.ro_rt)) {
		RT_LOCK(rt);
		inp->inp_route.ro_rt = NULL;
		bzero((caddr_t)&info, sizeof(info));
		info.rti_flags = rt->rt_flags;
		info.rti_info[RTAX_DST] = rt_key(rt);
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC) {
			RT_UNLOCK(rt);		/* XXX refcnt? */
			(void) rtrequest1(RTM_DELETE, &info, NULL);
		} else
			rtfree(rt);
		/*
		 * A new route can be allocated
		 * the next time output is attempted.
		 */
	}
}

/*
 * After a routing change, flush old routing
 * and allocate a (hopefully) better one.
 */
struct inpcb *
in_rtchange(inp, errno)
	register struct inpcb *inp;
	int errno;
{
	if (inp->inp_route.ro_rt) {
		RTFREE(inp->inp_route.ro_rt);
		inp->inp_route.ro_rt = 0;
		/*
		 * A new route can be allocated the next time
		 * output is attempted.
		 */
	}
	return inp;
}

/*
 * Lookup a PCB based on the local address and port.
 */
struct inpcb *
in_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay)
	struct inpcbinfo *pcbinfo;
	struct in_addr laddr;
	u_int lport_arg;
	int wild_okay;
{
	register struct inpcb *inp;
	int matchwild = 3, wildcard;
	u_short lport = lport_arg;

	if (!wild_okay) {
		struct inpcbhead *head;
		/*
		 * Look for an unconnected (wildcard foreign addr) PCB that
		 * matches the local address and port we're looking for.
		 */
		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0, pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
#ifdef INET6
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
			if (inp->inp_faddr.s_addr == INADDR_ANY &&
			    inp->inp_laddr.s_addr == laddr.s_addr &&
			    inp->inp_lport == lport) {
				/*
				 * Found.
				 */
				return (inp);
			}
		}
		/*
		 * Not found.
		 */
		return (NULL);
	} else {
		struct inpcbporthead *porthash;
		struct inpcbport *phd;
		struct inpcb *match = NULL;
		/*
		 * Best fit PCB lookup.
		 *
		 * First see if this local port is in use by looking on the
		 * port hash list.
		 */
		porthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(lport,
		    pcbinfo->porthashmask)];
		LIST_FOREACH(phd, porthash, phd_hash) {
			if (phd->phd_port == lport)
				break;
		}
		if (phd != NULL) {
			/*
			 * Port is in use by one or more PCBs. Look for best
			 * fit.
			 */
			LIST_FOREACH(inp, &phd->phd_pcblist, inp_portlist) {
				wildcard = 0;
#ifdef INET6
				if ((inp->inp_vflag & INP_IPV4) == 0)
					continue;
#endif
				if (inp->inp_faddr.s_addr != INADDR_ANY)
					wildcard++;
				if (inp->inp_laddr.s_addr != INADDR_ANY) {
					if (laddr.s_addr == INADDR_ANY)
						wildcard++;
					else if (inp->inp_laddr.s_addr != laddr.s_addr)
						continue;
				} else {
					if (laddr.s_addr != INADDR_ANY)
						wildcard++;
				}
				if (wildcard < matchwild) {
					match = inp;
					matchwild = wildcard;
					if (matchwild == 0) {
						break;
					}
				}
			}
		}
		return (match);
	}
}

/*
 * Lookup PCB in hash list.
 */
struct inpcb *
in_pcblookup_hash(pcbinfo, faddr, fport_arg, laddr, lport_arg, wildcard,
		  ifp)
	struct inpcbinfo *pcbinfo;
	struct in_addr faddr, laddr;
	u_int fport_arg, lport_arg;
	int wildcard;
	struct ifnet *ifp;
{
	struct inpcbhead *head;
	register struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->hashbase[INP_PCBHASH(faddr.s_addr, lport, fport, pcbinfo->hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
#ifdef INET6
		if ((inp->inp_vflag & INP_IPV4) == 0)
			continue;
#endif
		if (inp->inp_faddr.s_addr == faddr.s_addr &&
		    inp->inp_laddr.s_addr == laddr.s_addr &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
			 * Found.
			 */
			return (inp);
		}
	}
	if (wildcard) {
		struct inpcb *local_wild = NULL;
#if defined(INET6)
		struct inpcb *local_wild_mapped = NULL;
#endif /* defined(INET6) */

		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0, pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
#ifdef INET6
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
			if (inp->inp_faddr.s_addr == INADDR_ANY &&
			    inp->inp_lport == lport) {
				if (ifp && ifp->if_type == IFT_FAITH &&
				    (inp->inp_flags & INP_FAITH) == 0)
					continue;
				if (inp->inp_laddr.s_addr == laddr.s_addr)
					return (inp);
				else if (inp->inp_laddr.s_addr == INADDR_ANY) {
#if defined(INET6)
					if (INP_CHECK_SOCKAF(inp->inp_socket,
							     AF_INET6))
						local_wild_mapped = inp;
					else
#endif /* defined(INET6) */
					local_wild = inp;
				}
			}
		}
#if defined(INET6)
		if (local_wild == NULL)
			return (local_wild_mapped);
#endif /* defined(INET6) */
		return (local_wild);
	}

	/*
	 * Not found.
	 */
	return (NULL);
}

/*
 * Insert PCB onto various hash lists.
 */
int
in_pcbinshash(inp)
	struct inpcb *inp;
{
	struct inpcbhead *pcbhash;
	struct inpcbporthead *pcbporthash;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbport *phd;
	u_int32_t hashkey_faddr;

#ifdef INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	pcbhash = &pcbinfo->hashbase[INP_PCBHASH(hashkey_faddr,
		 inp->inp_lport, inp->inp_fport, pcbinfo->hashmask)];

	pcbporthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(inp->inp_lport,
	    pcbinfo->porthashmask)];

	/*
	 * Go through port list and look for a head for this lport.
	 */
	LIST_FOREACH(phd, pcbporthash, phd_hash) {
		if (phd->phd_port == inp->inp_lport)
			break;
	}
	/*
	 * If none exists, malloc one and tack it on.
	 */
	if (phd == NULL) {
		MALLOC(phd, struct inpcbport *, sizeof(struct inpcbport), M_PCB, M_NOWAIT);
		if (phd == NULL) {
			return (ENOBUFS); /* XXX */
		}
		phd->phd_port = inp->inp_lport;
		LIST_INIT(&phd->phd_pcblist);
		LIST_INSERT_HEAD(pcbporthash, phd, phd_hash);
	}
	inp->inp_phd = phd;
	LIST_INSERT_HEAD(&phd->phd_pcblist, inp, inp_portlist);
	LIST_INSERT_HEAD(pcbhash, inp, inp_hash);
	return (0);
}

/*
 * Move PCB to the proper hash bucket when { faddr, fport } have  been
 * changed. NOTE: This does not handle the case of the lport changing (the
 * hashed port list would have to be updated as well), so the lport must
 * not change after in_pcbinshash() has been called.
 */
void
in_pcbrehash(inp)
	struct inpcb *inp;
{
	struct inpcbhead *head;
	u_int32_t hashkey_faddr;

#ifdef INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	head = &inp->inp_pcbinfo->hashbase[INP_PCBHASH(hashkey_faddr,
		inp->inp_lport, inp->inp_fport, inp->inp_pcbinfo->hashmask)];

	LIST_REMOVE(inp, inp_hash);
	LIST_INSERT_HEAD(head, inp, inp_hash);
}

/*
 * Remove PCB from various lists.
 */
void
in_pcbremlists(inp)
	struct inpcb *inp;
{
	inp->inp_gencnt = ++inp->inp_pcbinfo->ipi_gencnt;
	if (inp->inp_lport) {
		struct inpcbport *phd = inp->inp_phd;

		LIST_REMOVE(inp, inp_hash);
		LIST_REMOVE(inp, inp_portlist);
		if (LIST_FIRST(&phd->phd_pcblist) == NULL) {
			LIST_REMOVE(phd, phd_hash);
			free(phd, M_PCB);
		}
	}
	LIST_REMOVE(inp, inp_list);
	inp->inp_pcbinfo->ipi_count--;
}

int
prison_xinpcb(struct thread *td, struct inpcb *inp)
{
	if (!jailed(td->td_ucred))
		return (0);
	if (ntohl(inp->inp_laddr.s_addr) == prison_getip(td->td_ucred))
		return (0);
	return (1);
}
