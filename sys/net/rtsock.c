/*
 * Copyright (c) 1988, 1991, 1993
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
 *	@(#)rtsock.c	8.7 (Berkeley) 10/12/95
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/raw_cb.h>
#include <net/route.h>

MALLOC_DEFINE(M_RTABLE, "routetbl", "routing tables");

/* NB: these are not modified */
static struct	sockaddr route_dst = { 2, PF_ROUTE, };
static struct	sockaddr route_src = { 2, PF_ROUTE, };
static struct	sockaddr sa_zero   = { sizeof(sa_zero), AF_INET, };

static struct {
	int	ip_count;	/* attacked w/ AF_INET */
	int	ip6_count;	/* attached w/ AF_INET6 */
	int	ipx_count;	/* attached w/ AF_IPX */
	int	any_count;	/* total attached */
} route_cb;

struct mtx rtsock_mtx;
MTX_SYSINIT(rtsock, &rtsock_mtx, "rtsock route_cb lock", MTX_DEF);

#define	RTSOCK_LOCK()	mtx_lock(&rtsock_mtx)
#define	RTSOCK_UNLOCK()	mtx_unlock(&rtsock_mtx)
#define	RTSOCK_LOCK_ASSERT()	mtx_assert(&rtsock_mtx, MA_OWNED)

struct walkarg {
	int	w_tmemsize;
	int	w_op, w_arg;
	caddr_t	w_tmem;
	struct sysctl_req *w_req;
};

static struct mbuf *rt_msg1(int, struct rt_addrinfo *);
static int	rt_msg2(int, struct rt_addrinfo *, caddr_t, struct walkarg *);
static int	rt_xaddrs(caddr_t, caddr_t, struct rt_addrinfo *);
static int	sysctl_dumpentry(struct radix_node *rn, void *vw);
static int	sysctl_iflist(int af, struct walkarg *w);
static int	sysctl_ifmalist(int af, struct walkarg *w);
static int	route_output(struct mbuf *, struct socket *);
static void	rt_setmetrics(u_long, struct rt_metrics *, struct rt_metrics_lite *);
static void	rt_getmetrics(struct rt_metrics_lite *, struct rt_metrics *);
static void	rt_dispatch(struct mbuf *, struct sockaddr *);

/*
 * It really doesn't make any sense at all for this code to share much
 * with raw_usrreq.c, since its functionality is so restricted.  XXX
 */
static int
rts_abort(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_abort(so);
	splx(s);
	return error;
}

/* pru_accept is EOPNOTSUPP */

static int
rts_attach(struct socket *so, int proto, struct thread *td)
{
	struct rawcb *rp;
	int s, error;

	if (sotorawcb(so) != 0)
		return EISCONN;	/* XXX panic? */
	/* XXX */
	MALLOC(rp, struct rawcb *, sizeof *rp, M_PCB, M_WAITOK | M_ZERO);
	if (rp == 0)
		return ENOBUFS;

	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications (like RTM_REDIRECT or RTM_LOSING) while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)rp;
	error = raw_attach(so, proto);
	rp = sotorawcb(so);
	if (error) {
		splx(s);
		so->so_pcb = NULL;
		free(rp, M_PCB);
		return error;
	}
	RTSOCK_LOCK();
	switch(rp->rcb_proto.sp_protocol) {
	case AF_INET:
		route_cb.ip_count++;
		break;
	case AF_INET6:
		route_cb.ip6_count++;
		break;
	case AF_IPX:
		route_cb.ipx_count++;
		break;
	}
	rp->rcb_faddr = &route_src;
	route_cb.any_count++;
	RTSOCK_UNLOCK();
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;
	splx(s);
	return 0;
}

static int
rts_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_bind(so, nam, td); /* xxx just EINVAL */
	splx(s);
	return error;
}

static int
rts_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_connect(so, nam, td); /* XXX just EINVAL */
	splx(s);
	return error;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
rts_detach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);
	int s, error;

	s = splnet();
	if (rp != 0) {
		RTSOCK_LOCK();
		switch(rp->rcb_proto.sp_protocol) {
		case AF_INET:
			route_cb.ip_count--;
			break;
		case AF_INET6:
			route_cb.ip6_count--;
			break;
		case AF_IPX:
			route_cb.ipx_count--;
			break;
		}
		route_cb.any_count--;
		RTSOCK_UNLOCK();
	}
	error = raw_usrreqs.pru_detach(so);
	splx(s);
	return error;
}

static int
rts_disconnect(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_disconnect(so);
	splx(s);
	return error;
}

/* pru_listen is EOPNOTSUPP */

static int
rts_peeraddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_peeraddr(so, nam);
	splx(s);
	return error;
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
rts_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct thread *td)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_send(so, flags, m, nam, control, td);
	splx(s);
	return error;
}

/* pru_sense is null */

static int
rts_shutdown(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_shutdown(so);
	splx(s);
	return error;
}

static int
rts_sockaddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_sockaddr(so, nam);
	splx(s);
	return error;
}

static struct pr_usrreqs route_usrreqs = {
	rts_abort, pru_accept_notsupp, rts_attach, rts_bind, rts_connect,
	pru_connect2_notsupp, pru_control_notsupp, rts_detach, rts_disconnect,
	pru_listen_notsupp, rts_peeraddr, pru_rcvd_notsupp, pru_rcvoob_notsupp,
	rts_send, pru_sense_null, rts_shutdown, rts_sockaddr,
	sosend, soreceive, sopoll, pru_sosetlabel_null
};

/*ARGSUSED*/
static int
route_output(m, so)
	register struct mbuf *m;
	struct socket *so;
{
#define	sa_equal(a1, a2) (bcmp((a1), (a2), (a1)->sa_len) == 0)
	register struct rt_msghdr *rtm = 0;
	register struct rtentry *rt = 0;
	struct radix_node_head *rnh;
	struct rt_addrinfo info;
	int len, error = 0;
	struct ifnet *ifp = 0;
	struct ifaddr *ifa = 0;

#define senderr(e) { error = e; goto flush;}
	if (m == 0 || ((m->m_len < sizeof(long)) &&
		       (m = m_pullup(m, sizeof(long))) == 0))
		return (ENOBUFS);
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("route_output");
	len = m->m_pkthdr.len;
	if (len < sizeof(*rtm) ||
	    len != mtod(m, struct rt_msghdr *)->rtm_msglen) {
		info.rti_info[RTAX_DST] = 0;
		senderr(EINVAL);
	}
	R_Malloc(rtm, struct rt_msghdr *, len);
	if (rtm == 0) {
		info.rti_info[RTAX_DST] = 0;
		senderr(ENOBUFS);
	}
	m_copydata(m, 0, len, (caddr_t)rtm);
	if (rtm->rtm_version != RTM_VERSION) {
		info.rti_info[RTAX_DST] = 0;
		senderr(EPROTONOSUPPORT);
	}
	rtm->rtm_pid = curproc->p_pid;
	bzero(&info, sizeof(info));
	info.rti_addrs = rtm->rtm_addrs;
	if (rt_xaddrs((caddr_t)(rtm + 1), len + (caddr_t)rtm, &info)) {
		info.rti_info[RTAX_DST] = 0;
		senderr(EINVAL);
	}
	info.rti_flags = rtm->rtm_flags;
	if (info.rti_info[RTAX_DST] == 0 ||
	    info.rti_info[RTAX_DST]->sa_family >= AF_MAX ||
	    (info.rti_info[RTAX_GATEWAY] != 0 &&
	     info.rti_info[RTAX_GATEWAY]->sa_family >= AF_MAX))
		senderr(EINVAL);
	if (info.rti_info[RTAX_GENMASK]) {
		struct radix_node *t;
		t = rn_addmask((caddr_t) info.rti_info[RTAX_GENMASK], 0, 1);
		if (t && Bcmp((caddr_t *) info.rti_info[RTAX_GENMASK] + 1,
			      (caddr_t *)t->rn_key + 1,
			      *(u_char *)t->rn_key - 1) == 0)
			info.rti_info[RTAX_GENMASK] =
				(struct sockaddr *)(t->rn_key);
		else
			senderr(ENOBUFS);
	}

	/*
	 * Verify that the caller has the appropriate privilege; RTM_GET
	 * is the only operation the non-superuser is allowed.
	 */
	if (rtm->rtm_type != RTM_GET && (error = suser(curthread)) != 0)
		senderr(error);

	switch (rtm->rtm_type) {
		struct rtentry *saved_nrt;

	case RTM_ADD:
		if (info.rti_info[RTAX_GATEWAY] == 0)
			senderr(EINVAL);
		saved_nrt = 0;
		error = rtrequest1(RTM_ADD, &info, &saved_nrt);
		if (error == 0 && saved_nrt) {
			RT_LOCK(saved_nrt);
			rt_setmetrics(rtm->rtm_inits,
				&rtm->rtm_rmx, &saved_nrt->rt_rmx);
			RT_REMREF(saved_nrt);
			saved_nrt->rt_genmask = info.rti_info[RTAX_GENMASK];
			RT_UNLOCK(saved_nrt);
		}
		break;

	case RTM_DELETE:
		saved_nrt = 0;
		error = rtrequest1(RTM_DELETE, &info, &saved_nrt);
		if (error == 0) {
			RT_LOCK(saved_nrt);
			rt = saved_nrt;
			goto report;
		}
		break;

	case RTM_GET:
	case RTM_CHANGE:
	case RTM_LOCK:
		rnh = rt_tables[info.rti_info[RTAX_DST]->sa_family];
		if (rnh == 0)
			senderr(EAFNOSUPPORT);
		RADIX_NODE_HEAD_LOCK(rnh);
		rt = (struct rtentry *) rnh->rnh_lookup(info.rti_info[RTAX_DST],
			info.rti_info[RTAX_NETMASK], rnh);
		RADIX_NODE_HEAD_UNLOCK(rnh);
		if (rt == NULL)		/* XXX looks bogus */
			senderr(ESRCH);
		RT_LOCK(rt);
		RT_ADDREF(rt);

		switch(rtm->rtm_type) {

		case RTM_GET:
		report:
			RT_LOCK_ASSERT(rt);
			info.rti_info[RTAX_DST] = rt_key(rt);
			info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
			info.rti_info[RTAX_NETMASK] = rt_mask(rt);
			info.rti_info[RTAX_GENMASK] = rt->rt_genmask;
			if (rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) {
				ifp = rt->rt_ifp;
				if (ifp) {
					info.rti_info[RTAX_IFP] = TAILQ_FIRST(&ifp->if_addrhead)->ifa_addr;
					info.rti_info[RTAX_IFA] =
						rt->rt_ifa->ifa_addr;
					if (ifp->if_flags & IFF_POINTOPOINT)
						 info.rti_info[RTAX_BRD] =
							rt->rt_ifa->ifa_dstaddr;
					rtm->rtm_index = ifp->if_index;
				} else {
					info.rti_info[RTAX_IFP] = 0;
					info.rti_info[RTAX_IFA] = 0;
				}
			}
			len = rt_msg2(rtm->rtm_type, &info, (caddr_t)0,
				(struct walkarg *)0);
			if (len > rtm->rtm_msglen) {
				struct rt_msghdr *new_rtm;
				R_Malloc(new_rtm, struct rt_msghdr *, len);
				if (new_rtm == 0) {
					RT_UNLOCK(rt);
					senderr(ENOBUFS);
				}
				Bcopy(rtm, new_rtm, rtm->rtm_msglen);
				Free(rtm); rtm = new_rtm;
			}
			(void)rt_msg2(rtm->rtm_type, &info, (caddr_t)rtm,
				(struct walkarg *)0);
			rtm->rtm_flags = rt->rt_flags;
			rt_getmetrics(&rt->rt_rmx, &rtm->rtm_rmx);
			rtm->rtm_addrs = info.rti_addrs;
			break;

		case RTM_CHANGE:
			/*
			 * New gateway could require new ifaddr, ifp;
			 * flags may also be different; ifp may be specified
			 * by ll sockaddr when protocol address is ambiguous
			 */
			if (((rt->rt_flags & RTF_GATEWAY) &&
			     info.rti_info[RTAX_GATEWAY] != NULL) ||
			    info.rti_info[RTAX_IFP] != NULL ||
			    (info.rti_info[RTAX_IFA] != NULL &&
			     !sa_equal(info.rti_info[RTAX_IFA],
				       rt->rt_ifa->ifa_addr))) {
				if ((error = rt_getifa(&info)) != 0) {
					RT_UNLOCK(rt);
					senderr(error);
				}
			}
			if (info.rti_info[RTAX_GATEWAY] != NULL &&
			    (error = rt_setgate(rt, rt_key(rt),
					info.rti_info[RTAX_GATEWAY])) != 0) {
				RT_UNLOCK(rt);
				senderr(error);
			}
			if ((ifa = info.rti_ifa) != NULL) {
				struct ifaddr *oifa = rt->rt_ifa;
				if (oifa != ifa) {
					if (oifa) {
						if (oifa->ifa_rtrequest)
							oifa->ifa_rtrequest(
								RTM_DELETE, rt,
								&info);
						IFAFREE(oifa);
					}
				        IFAREF(ifa);
				        rt->rt_ifa = ifa;
				        rt->rt_ifp = info.rti_ifp;
				}
			}
			rt_setmetrics(rtm->rtm_inits, &rtm->rtm_rmx,
					&rt->rt_rmx);
			if (rt->rt_ifa && rt->rt_ifa->ifa_rtrequest)
			       rt->rt_ifa->ifa_rtrequest(RTM_ADD, rt, &info);
			if (info.rti_info[RTAX_GENMASK])
				rt->rt_genmask = info.rti_info[RTAX_GENMASK];
			/* FALLTHROUGH */
		case RTM_LOCK:
			/* We don't support locks anymore */
			break;
		}
		RT_UNLOCK(rt);
		break;

	default:
		senderr(EOPNOTSUPP);
	}

flush:
	if (rtm) {
		if (error)
			rtm->rtm_errno = error;
		else
			rtm->rtm_flags |= RTF_DONE;
	}
	if (rt)		/* XXX can this be true? */
		RTFREE(rt);
    {
	register struct rawcb *rp = 0;
	/*
	 * Check to see if we don't want our own messages.
	 */
	if ((so->so_options & SO_USELOOPBACK) == 0) {
		if (route_cb.any_count <= 1) {
			if (rtm)
				Free(rtm);
			m_freem(m);
			return (error);
		}
		/* There is another listener, so construct message */
		rp = sotorawcb(so);
	}
	if (rtm) {
		m_copyback(m, 0, rtm->rtm_msglen, (caddr_t)rtm);
		if (m->m_pkthdr.len < rtm->rtm_msglen) {
			m_freem(m);
			m = NULL;
		} else if (m->m_pkthdr.len > rtm->rtm_msglen)
			m_adj(m, rtm->rtm_msglen - m->m_pkthdr.len);
		Free(rtm);
	}
	if (m) {
		if (rp) {
			/*
			 * XXX insure we don't get a copy by
			 * invalidating our protocol
			 */
			unsigned short family = rp->rcb_proto.sp_family;
			rp->rcb_proto.sp_family = 0;
			rt_dispatch(m, info.rti_info[RTAX_DST]);
			rp->rcb_proto.sp_family = family;
		} else
			rt_dispatch(m, info.rti_info[RTAX_DST]);
	}
    }
	return (error);
#undef	sa_equal
}

static void
rt_setmetrics(u_long which, struct rt_metrics *in, struct rt_metrics_lite *out)
{
#define metric(f, e) if (which & (f)) out->e = in->e;
	/*
	 * Only these are stored in the routing entry since introduction
	 * of tcp hostcache. The rest is ignored.
	 */
	metric(RTV_MTU, rmx_mtu);
	metric(RTV_EXPIRE, rmx_expire);
#undef metric
}

static void
rt_getmetrics(struct rt_metrics_lite *in, struct rt_metrics *out)
{
#define metric(e) out->e = in->e;
	bzero(out, sizeof(*out));
	metric(rmx_mtu);
	metric(rmx_expire);
#undef metric
}

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/*
 * Extract the addresses of the passed sockaddrs.
 * Do a little sanity checking so as to avoid bad memory references.
 * This data is derived straight from userland.
 */
static int
rt_xaddrs(caddr_t cp, caddr_t cplim, struct rt_addrinfo *rtinfo)
{
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
	register struct sockaddr *sa;
	register int i;

	for (i = 0; i < RTAX_MAX && cp < cplim; i++) {
		if ((rtinfo->rti_addrs & (1 << i)) == 0)
			continue;
		sa = (struct sockaddr *)cp;
		/*
		 * It won't fit.
		 */
		if (cp + sa->sa_len > cplim)
			return (EINVAL);
		/*
		 * there are no more.. quit now
		 * If there are more bits, they are in error.
		 * I've seen this. route(1) can evidently generate these. 
		 * This causes kernel to core dump.
		 * for compatibility, If we see this, point to a safe address.
		 */
		if (sa->sa_len == 0) {
			rtinfo->rti_info[i] = &sa_zero;
			return (0); /* should be EINVAL but for compat */
		}
		/* accept it */
		rtinfo->rti_info[i] = sa;
		ADVANCE(cp, sa);
	}
	return (0);
#undef ADVANCE
}

static struct mbuf *
rt_msg1(int type, struct rt_addrinfo *rtinfo)
{
	register struct rt_msghdr *rtm;
	register struct mbuf *m;
	register int i;
	register struct sockaddr *sa;
	int len, dlen;

	switch (type) {

	case RTM_DELADDR:
	case RTM_NEWADDR:
		len = sizeof(struct ifa_msghdr);
		break;

	case RTM_DELMADDR:
	case RTM_NEWMADDR:
		len = sizeof(struct ifma_msghdr);
		break;

	case RTM_IFINFO:
		len = sizeof(struct if_msghdr);
		break;

	case RTM_IFANNOUNCE:
		len = sizeof(struct if_announcemsghdr);
		break;

	default:
		len = sizeof(struct rt_msghdr);
	}
	if (len > MCLBYTES)
		panic("rt_msg1");
	m = m_gethdr(M_DONTWAIT, MT_DATA);
	if (m && len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == 0)
		return (m);
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = 0;
	rtm = mtod(m, struct rt_msghdr *);
	bzero((caddr_t)rtm, len);
	for (i = 0; i < RTAX_MAX; i++) {
		if ((sa = rtinfo->rti_info[i]) == NULL)
			continue;
		rtinfo->rti_addrs |= (1 << i);
		dlen = ROUNDUP(sa->sa_len);
		m_copyback(m, len, dlen, (caddr_t)sa);
		len += dlen;
	}
	if (m->m_pkthdr.len != len) {
		m_freem(m);
		return (NULL);
	}
	rtm->rtm_msglen = len;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = type;
	return (m);
}

static int
rt_msg2(int type, struct rt_addrinfo *rtinfo, caddr_t cp, struct walkarg *w)
{
	register int i;
	int len, dlen, second_time = 0;
	caddr_t cp0;

	rtinfo->rti_addrs = 0;
again:
	switch (type) {

	case RTM_DELADDR:
	case RTM_NEWADDR:
		len = sizeof(struct ifa_msghdr);
		break;

	case RTM_IFINFO:
		len = sizeof(struct if_msghdr);
		break;

	case RTM_NEWMADDR:
		len = sizeof(struct ifma_msghdr);
		break;

	default:
		len = sizeof(struct rt_msghdr);
	}
	cp0 = cp;
	if (cp0)
		cp += len;
	for (i = 0; i < RTAX_MAX; i++) {
		register struct sockaddr *sa;

		if ((sa = rtinfo->rti_info[i]) == 0)
			continue;
		rtinfo->rti_addrs |= (1 << i);
		dlen = ROUNDUP(sa->sa_len);
		if (cp) {
			bcopy((caddr_t)sa, cp, (unsigned)dlen);
			cp += dlen;
		}
		len += dlen;
	}
	len = ALIGN(len);
	if (cp == 0 && w != NULL && !second_time) {
		register struct walkarg *rw = w;

		if (rw->w_req) {
			if (rw->w_tmemsize < len) {
				if (rw->w_tmem)
					free(rw->w_tmem, M_RTABLE);
				rw->w_tmem = (caddr_t)
					malloc(len, M_RTABLE, M_NOWAIT);
				if (rw->w_tmem)
					rw->w_tmemsize = len;
			}
			if (rw->w_tmem) {
				cp = rw->w_tmem;
				second_time = 1;
				goto again;
			}
		}
	}
	if (cp) {
		register struct rt_msghdr *rtm = (struct rt_msghdr *)cp0;

		rtm->rtm_version = RTM_VERSION;
		rtm->rtm_type = type;
		rtm->rtm_msglen = len;
	}
	return (len);
}

/*
 * This routine is called to generate a message from the routing
 * socket indicating that a redirect has occured, a routing lookup
 * has failed, or that a protocol has detected timeouts to a particular
 * destination.
 */
void
rt_missmsg(int type, struct rt_addrinfo *rtinfo, int flags, int error)
{
	struct rt_msghdr *rtm;
	struct mbuf *m;
	struct sockaddr *sa = rtinfo->rti_info[RTAX_DST];

	if (route_cb.any_count == 0)
		return;
	m = rt_msg1(type, rtinfo);
	if (m == 0)
		return;
	rtm = mtod(m, struct rt_msghdr *);
	rtm->rtm_flags = RTF_DONE | flags;
	rtm->rtm_errno = error;
	rtm->rtm_addrs = rtinfo->rti_addrs;
	rt_dispatch(m, sa);
}

/*
 * This routine is called to generate a message from the routing
 * socket indicating that the status of a network interface has changed.
 */
void
rt_ifmsg(struct ifnet *ifp)
{
	struct if_msghdr *ifm;
	struct mbuf *m;
	struct rt_addrinfo info;

	if (route_cb.any_count == 0)
		return;
	bzero((caddr_t)&info, sizeof(info));
	m = rt_msg1(RTM_IFINFO, &info);
	if (m == 0)
		return;
	ifm = mtod(m, struct if_msghdr *);
	ifm->ifm_index = ifp->if_index;
	ifm->ifm_flags = ifp->if_flags;
	ifm->ifm_data = ifp->if_data;
	ifm->ifm_addrs = 0;
	rt_dispatch(m, NULL);
}

/*
 * This is called to generate messages from the routing socket
 * indicating a network interface has had addresses associated with it.
 * if we ever reverse the logic and replace messages TO the routing
 * socket indicate a request to configure interfaces, then it will
 * be unnecessary as the routing socket will automatically generate
 * copies of it.
 */
void
rt_newaddrmsg(int cmd, struct ifaddr *ifa, int error, struct rtentry *rt)
{
	struct rt_addrinfo info;
	struct sockaddr *sa = 0;
	int pass;
	struct mbuf *m = 0;
	struct ifnet *ifp = ifa->ifa_ifp;

	if (route_cb.any_count == 0)
		return;
	for (pass = 1; pass < 3; pass++) {
		bzero((caddr_t)&info, sizeof(info));
		if ((cmd == RTM_ADD && pass == 1) ||
		    (cmd == RTM_DELETE && pass == 2)) {
			register struct ifa_msghdr *ifam;
			int ncmd = cmd == RTM_ADD ? RTM_NEWADDR : RTM_DELADDR;

			info.rti_info[RTAX_IFA] = sa = ifa->ifa_addr;
			info.rti_info[RTAX_IFP] = TAILQ_FIRST(&ifp->if_addrhead)->ifa_addr;
			info.rti_info[RTAX_NETMASK] = ifa->ifa_netmask;
			info.rti_info[RTAX_BRD] = ifa->ifa_dstaddr;
			if ((m = rt_msg1(ncmd, &info)) == NULL)
				continue;
			ifam = mtod(m, struct ifa_msghdr *);
			ifam->ifam_index = ifp->if_index;
			ifam->ifam_metric = ifa->ifa_metric;
			ifam->ifam_flags = ifa->ifa_flags;
			ifam->ifam_addrs = info.rti_addrs;
		}
		if ((cmd == RTM_ADD && pass == 2) ||
		    (cmd == RTM_DELETE && pass == 1)) {
			register struct rt_msghdr *rtm;

			if (rt == 0)
				continue;
			info.rti_info[RTAX_NETMASK] = rt_mask(rt);
			info.rti_info[RTAX_DST] = sa = rt_key(rt);
			info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
			if ((m = rt_msg1(cmd, &info)) == NULL)
				continue;
			rtm = mtod(m, struct rt_msghdr *);
			rtm->rtm_index = ifp->if_index;
			rtm->rtm_flags |= rt->rt_flags;
			rtm->rtm_errno = error;
			rtm->rtm_addrs = info.rti_addrs;
		}
		rt_dispatch(m, sa);
	}
}

/*
 * This is the analogue to the rt_newaddrmsg which performs the same
 * function but for multicast group memberhips.  This is easier since
 * there is no route state to worry about.
 */
void
rt_newmaddrmsg(int cmd, struct ifmultiaddr *ifma)
{
	struct rt_addrinfo info;
	struct mbuf *m = 0;
	struct ifnet *ifp = ifma->ifma_ifp;
	struct ifma_msghdr *ifmam;

	if (route_cb.any_count == 0)
		return;

	bzero((caddr_t)&info, sizeof(info));
	info.rti_info[RTAX_IFA] = ifma->ifma_addr;
	if (ifp && TAILQ_FIRST(&ifp->if_addrhead))
		info.rti_info[RTAX_IFP] =
			TAILQ_FIRST(&ifp->if_addrhead)->ifa_addr;
	else
		info.rti_info[RTAX_IFP] = NULL;
	/*
	 * If a link-layer address is present, present it as a ``gateway''
	 * (similarly to how ARP entries, e.g., are presented).
	 */
	info.rti_info[RTAX_GATEWAY] = ifma->ifma_lladdr;
	m = rt_msg1(cmd, &info);
	if (m == NULL)
		return;
	ifmam = mtod(m, struct ifma_msghdr *);
	ifmam->ifmam_index = ifp->if_index;
	ifmam->ifmam_addrs = info.rti_addrs;
	rt_dispatch(m, ifma->ifma_addr);
}

/*
 * This is called to generate routing socket messages indicating
 * network interface arrival and departure.
 */
void
rt_ifannouncemsg(struct ifnet *ifp, int what)
{
	struct if_announcemsghdr *ifan;
	struct mbuf *m;
	struct rt_addrinfo info;

	if (route_cb.any_count == 0)
		return;
	bzero((caddr_t)&info, sizeof(info));
	m = rt_msg1(RTM_IFANNOUNCE, &info);
	if (m == NULL)
		return;
	ifan = mtod(m, struct if_announcemsghdr *);
	ifan->ifan_index = ifp->if_index;
	strlcpy(ifan->ifan_name, ifp->if_xname, sizeof(ifan->ifan_name));
	ifan->ifan_what = what;
	rt_dispatch(m, NULL);
 }

static void
rt_dispatch(struct mbuf *m, struct sockaddr *sa)
{
	struct sockproto route_proto;

	route_proto.sp_family = PF_ROUTE;
	route_proto.sp_protocol = sa ?  sa->sa_family : 0;
	raw_input(m, &route_proto, &route_src, &route_dst);
}

/*
 * This is used in dumping the kernel table via sysctl().
 */
static int
sysctl_dumpentry(struct radix_node *rn, void *vw)
{
	struct walkarg *w = vw;
	struct rtentry *rt = (struct rtentry *)rn;
	int error = 0, size;
	struct rt_addrinfo info;

	if (w->w_op == NET_RT_FLAGS && !(rt->rt_flags & w->w_arg))
		return 0;
	bzero((caddr_t)&info, sizeof(info));
	info.rti_info[RTAX_DST] = rt_key(rt);
	info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
	info.rti_info[RTAX_NETMASK] = rt_mask(rt);
	info.rti_info[RTAX_GENMASK] = rt->rt_genmask;
	if (rt->rt_ifp) {
		info.rti_info[RTAX_IFP] =
			TAILQ_FIRST(&rt->rt_ifp->if_addrhead)->ifa_addr;
		info.rti_info[RTAX_IFA] = rt->rt_ifa->ifa_addr;
		if (rt->rt_ifp->if_flags & IFF_POINTOPOINT)
			info.rti_info[RTAX_BRD] = rt->rt_ifa->ifa_dstaddr;
	}
	size = rt_msg2(RTM_GET, &info, 0, w);
	if (w->w_req && w->w_tmem) {
		struct rt_msghdr *rtm = (struct rt_msghdr *)w->w_tmem;

		rtm->rtm_flags = rt->rt_flags;
		rtm->rtm_use = rt->rt_rmx.rmx_pksent;
		rt_getmetrics(&rt->rt_rmx, &rtm->rtm_rmx);
		rtm->rtm_index = rt->rt_ifp->if_index;
		rtm->rtm_errno = rtm->rtm_pid = rtm->rtm_seq = 0;
		rtm->rtm_addrs = info.rti_addrs;
		error = SYSCTL_OUT(w->w_req, (caddr_t)rtm, size);
		return (error);
	}
	return (error);
}

static int
sysctl_iflist(int af, struct walkarg *w)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct rt_addrinfo info;
	int len, error = 0;

	bzero((caddr_t)&info, sizeof(info));
	/* IFNET_RLOCK(); */		/* could sleep XXX */
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (w->w_arg && w->w_arg != ifp->if_index)
			continue;
		ifa = TAILQ_FIRST(&ifp->if_addrhead);
		info.rti_info[RTAX_IFP] = ifa->ifa_addr;
		len = rt_msg2(RTM_IFINFO, &info, (caddr_t)0, w);
		info.rti_info[RTAX_IFP] = 0;
		if (w->w_req && w->w_tmem) {
			struct if_msghdr *ifm;

			ifm = (struct if_msghdr *)w->w_tmem;
			ifm->ifm_index = ifp->if_index;
			ifm->ifm_flags = ifp->if_flags;
			ifm->ifm_data = ifp->if_data;
			ifm->ifm_addrs = info.rti_addrs;
			error = SYSCTL_OUT(w->w_req,(caddr_t)ifm, len);
			if (error)
				goto done;
		}
		while ((ifa = TAILQ_NEXT(ifa, ifa_link)) != 0) {
			if (af && af != ifa->ifa_addr->sa_family)
				continue;
			if (jailed(curthread->td_ucred) &&
			    prison_if(curthread->td_ucred, ifa->ifa_addr))
				continue;
			info.rti_info[RTAX_IFA] = ifa->ifa_addr;
			info.rti_info[RTAX_NETMASK] = ifa->ifa_netmask;
			info.rti_info[RTAX_BRD] = ifa->ifa_dstaddr;
			len = rt_msg2(RTM_NEWADDR, &info, 0, w);
			if (w->w_req && w->w_tmem) {
				struct ifa_msghdr *ifam;

				ifam = (struct ifa_msghdr *)w->w_tmem;
				ifam->ifam_index = ifa->ifa_ifp->if_index;
				ifam->ifam_flags = ifa->ifa_flags;
				ifam->ifam_metric = ifa->ifa_metric;
				ifam->ifam_addrs = info.rti_addrs;
				error = SYSCTL_OUT(w->w_req, w->w_tmem, len);
				if (error)
					goto done;
			}
		}
		info.rti_info[RTAX_IFA] = info.rti_info[RTAX_NETMASK] =
			info.rti_info[RTAX_BRD] = 0;
	}
done:
	/* IFNET_RUNLOCK(); */ /* XXX */
	return (error);
}

int
sysctl_ifmalist(af, w)
	int	af;
	register struct	walkarg *w;
{
	register struct ifnet *ifp;
	struct ifmultiaddr *ifma;
	struct	rt_addrinfo info;
	int	len, error = 0;

	bzero((caddr_t)&info, sizeof(info));
	/* IFNET_RLOCK(); */		/* could sleep XXX */
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (w->w_arg && w->w_arg != ifp->if_index)
			continue;
		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (af && af != ifma->ifma_addr->sa_family)
				continue;
			if (jailed(curproc->p_ucred) &&
			    prison_if(curproc->p_ucred, ifma->ifma_addr))
				continue;
			info.rti_addrs = RTA_IFA;
			info.rti_info[RTAX_IFA] = ifma->ifma_addr;
			if (TAILQ_FIRST(&ifp->if_addrhead)) {
				info.rti_addrs |= RTA_IFP;
				info.rti_info[RTAX_IFP] =
				    TAILQ_FIRST(&ifp->if_addrhead)->ifa_addr;
			} else
				info.rti_info[RTAX_IFP] = NULL;

			if (ifma->ifma_addr->sa_family != AF_LINK) {
				info.rti_addrs |= RTA_GATEWAY;
				info.rti_info[RTAX_GATEWAY] = ifma->ifma_lladdr;
			} else
				info.rti_info[RTAX_GATEWAY] = NULL;

			len = rt_msg2(RTM_NEWMADDR, &info, 0, w);
			if (w->w_req && w->w_tmem) {
				register struct ifma_msghdr *ifmam;

				ifmam = (struct ifma_msghdr *)w->w_tmem;
				ifmam->ifmam_index = ifma->ifma_ifp->if_index;
				ifmam->ifmam_flags = 0;
				ifmam->ifmam_addrs = info.rti_addrs;
				error = SYSCTL_OUT(w->w_req, w->w_tmem, len);
				if (error)
					goto done;
			}
		}
	}
done:
	/* IFNET_RUNLOCK(); */ /* XXX */
	return (error);
}

static int
sysctl_rtsock(SYSCTL_HANDLER_ARGS)
{
	int	*name = (int *)arg1;
	u_int	namelen = arg2;
	struct radix_node_head *rnh;
	int	i, lim, s, error = EINVAL;
	u_char	af;
	struct	walkarg w;

	name ++;
	namelen--;
	if (req->newptr)
		return (EPERM);
	if (namelen != 3)
		return ((namelen < 3) ? EISDIR : ENOTDIR);
	af = name[0];
	if (af > AF_MAX)
		return (EINVAL);
	Bzero(&w, sizeof(w));
	w.w_op = name[1];
	w.w_arg = name[2];
	w.w_req = req;

	s = splnet();
	switch (w.w_op) {

	case NET_RT_DUMP:
	case NET_RT_FLAGS:
		if (af == 0) {			/* dump all tables */
			i = 1;
			lim = AF_MAX;
		} else				/* dump only one table */
			i = lim = af;
		for (error = 0; error == 0 && i <= lim; i++)
			if ((rnh = rt_tables[i]) != NULL) {
				/* RADIX_NODE_HEAD_LOCK(rnh); */
			    	error = rnh->rnh_walktree(rnh,
				    sysctl_dumpentry, &w);/* could sleep XXX */
				/* RADIX_NODE_HEAD_UNLOCK(rnh); */
			} else if (af != 0)
				error = EAFNOSUPPORT;
		break;

	case NET_RT_IFLIST:
		error = sysctl_iflist(af, &w);
		break;

	case NET_RT_IFMALIST:
		error = sysctl_ifmalist(af, &w);
		break;
	}
	splx(s);
	if (w.w_tmem)
		free(w.w_tmem, M_RTABLE);
	return (error);
}

SYSCTL_NODE(_net, PF_ROUTE, routetable, CTLFLAG_RD, sysctl_rtsock, "");

/*
 * Definitions of protocols supported in the ROUTE domain.
 */

extern struct domain routedomain;		/* or at least forward */

static struct protosw routesw[] = {
{ SOCK_RAW,	&routedomain,	0,		PR_ATOMIC|PR_ADDR,
  0,		route_output,	raw_ctlinput,	0,
  0,
  raw_init,	0,		0,		0,
  &route_usrreqs
}
};

static struct domain routedomain =
    { PF_ROUTE, "route", 0, 0, 0,
      routesw, &routesw[sizeof(routesw)/sizeof(routesw[0])] };

DOMAIN_SET(route);
