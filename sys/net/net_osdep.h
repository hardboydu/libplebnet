/*	$FreeBSD$	*/
/*	$KAME: net_osdep.h,v 1.22 2000/08/15 07:23:10 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * glue for kernel code programming differences.
 */

/*
 * OS dependencies:
 *
 * - struct rt_addrinfo
 *   all *BSDs except bsdi4 only have two members; rti_addrs and rti_info[].
 *   bsdi4 has additional members; rti_flags, rti_ifa, rti_ifp, and rti_rtm.
 *
 * - side effects of rtrequest[1](RTM_DELETE)
 *	BSDI[34]: delete all cloned routes underneath the route.
 *	FreeBSD[234]: delete all protocol-cloned routes underneath the route.
 *		      note that cloned routes from an interface direct route
 *		      still remain.
 *	NetBSD, OpenBSD: no side effects.
 * - privileged process
 *	NetBSD, FreeBSD 3
 *		struct proc *p;
 *		if (p && !suser(p->p_ucred, &p->p_acflag))
 *			privileged;
 *	FreeBSD 4
 *		struct proc *p;
 *		if (p && !suser(p))
 *			privileged;
 *	OpenBSD, BSDI [34], FreeBSD 2
 *		struct socket *so;
 *		if (so->so_state & SS_PRIV)
 *			privileged;
 * - foo_control
 *	NetBSD, FreeBSD 3
 *		needs to give struct proc * as argument
 *	OpenBSD, BSDI [34], FreeBSD 2
 *		do not need struct proc *
 * - bpf:
 *	OpenBSD, NetBSD, BSDI [34]
 *		need caddr_t * (= if_bpf **) and struct ifnet *
 *	FreeBSD 2, FreeBSD 3
 *		need only struct ifnet * as argument
 * - struct ifnet
 *			use queue.h?	member names	if name
 *			---		---		---
 *	FreeBSD 2	no		old standard	if_name+unit
 *	FreeBSD 3	yes		strange		if_name+unit
 *	OpenBSD		yes		standard	if_xname
 *	NetBSD		yes		standard	if_xname
 *	BSDI [34]	no		old standard	if_name+unit
 * - usrreq
 *	NetBSD, OpenBSD, BSDI [34], FreeBSD 2
 *		single function with PRU_xx, arguments are mbuf
 *	FreeBSD 3
 *		separates functions, non-mbuf arguments
 * - {set,get}sockopt
 *	NetBSD, OpenBSD, BSDI [34], FreeBSD 2
 *		manipulation based on mbuf
 *	FreeBSD 3
 *		non-mbuf manipulation using sooptcopy{in,out}()
 * - timeout() and untimeout()
 *	NetBSD, OpenBSD, BSDI [34], FreeBSD 2
 *		timeout() is a void function
 *	FreeBSD 3
 *		timeout() is non-void, must keep returned value for untimeout()
 * - sysctl
 *	NetBSD, OpenBSD
 *		foo_sysctl()
 *	BSDI [34]
 *		foo_sysctl() but with different style
 *	FreeBSD 2, FreeBSD 3
 *		linker hack
 *
 * - if_ioctl
 *	NetBSD, FreeBSD 3, BSDI [34]
 *		2nd argument is u_long cmd
 *	FreeBSD 2
 *		2nd argument is int cmd
 * - if attach routines
 *	NetBSD
 *		void xxattach(int);
 *	FreeBSD 2, FreeBSD 3
 *		void xxattach(void *);
 *		PSEUDO_SET(xxattach, if_xx);
 *
 * - ovbcopy()
 *	in NetBSD 1.4 or later, ovbcopy() is not supplied in the kernel.
 *	bcopy() is safe against overwrites.
 * - splnet()
 *	NetBSD 1.4 or later requires splsoftnet().
 *	other operating systems use splnet().
 *
 * - dtom()
 *	NEVER USE IT!
 *
 * - struct ifnet for loopback interface
 *	BSDI3: struct ifnet loif;
 *	BSDI4: struct ifnet *loifp;
 *	NetBSD, OpenBSD, FreeBSD2: struct ifnet loif[NLOOP];
 *
 *	odd thing is that many of them refers loif as ifnet *loif,
 *	not loif[NLOOP], from outside of if_loop.c.
 *
 * - number of bpf pseudo devices
 *	others: bpfilter.h, NBPFILTER
 *	FreeBSD4: bpf.h, NBPF
 *	solution:
 *		#if defined(__FreeBSD__) && __FreeBSD__ >= 4
 *		#include "bpf.h"
 *		#define NBPFILTER	NBPF
 *		#else
 *		#include "bpfilter.h"
 *		#endif
 *
 * - protosw for IPv4 (sys/netinet)
 *	FreeBSD4: struct ipprotosw in netinet/ipprotosw.h
 *	others: struct protosw in sys/protosw.h
 *
 * - header files with defopt (opt_xx.h)
 *	FreeBSD3: opt_{inet,ipsec,ip6fw,altq}.h
 *	FreeBSD4: opt_{inet,inet6,ipsec,ip6fw,altq}.h
 *	NetBSD: opt_{inet,ipsec,altq}.h
 *	others: does not use defopt
 *
 * - IN_MULTICAST/IN_CLASS[A-D] macro.
 *	OpenBSD and NetBSD: net endian (kernel) or host endian (userland)
 *	others: always host endian
 */

#ifndef __NET_NET_OSDEP_H_DEFINED_
#define __NET_NET_OSDEP_H_DEFINED_
#ifdef _KERNEL

struct ifnet;
extern const char *if_name __P((struct ifnet *));

#define HAVE_OLD_BPF

/*
 * Deprecated.
 */
#include <sys/module.h>
#define	PSEUDO_SET(sym, name) \
	static int name ## _modevent(module_t mod, int type, void *data) \
	{ \
		void (*initfunc)(void *) = (void (*)(void *))data; \
		switch (type) { \
		case MOD_LOAD: \
			/* printf(#name " module load\n"); */ \
			initfunc(NULL); \
			break; \
		case MOD_UNLOAD: \
			printf(#name " module unload - not possible for this module type\n"); \
			return EINVAL; \
		} \
		return 0; \
	} \
	static moduledata_t name ## _mod = { \
		#name, \
		name ## _modevent, \
		(void *)sym \
	}; \
	DECLARE_MODULE(name, name ## _mod, SI_SUB_PSEUDO, SI_ORDER_ANY)

#endif /*_KERNEL*/
#endif /*__NET_NET_OSDEP_H_DEFINED_ */
