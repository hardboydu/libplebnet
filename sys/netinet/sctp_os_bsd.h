/*-
 * Copyright (c) 2006-2007, Cisco Systems, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#ifndef __sctp_os_bsd_h__
#define __sctp_os_bsd_h__
/*
 * includes
 */
#include "opt_ipsec.h"
#include "opt_compat.h"
#include "opt_inet6.h"
#include "opt_inet.h"
#include "opt_sctp.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/resourcevar.h>
#include <sys/uio.h>
#include <sys/kthread.h>
#include <sys/priv.h>
#include <sys/random.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <machine/cpu.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>


#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif				/* IPSEC */

#ifdef INET6
#include <sys/domain.h>
#ifdef IPSEC
#include <netinet6/ipsec6.h>
#endif
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#endif				/* INET6 */



#include <netinet/ip_options.h>


#ifndef in6pcb
#define in6pcb		inpcb
#endif



/*
 *
 */
#define USER_ADDR_NULL	(NULL)	/* FIX ME: temp */
#define SCTP_LIST_EMPTY(list)	LIST_EMPTY(list)

/*
 * Local address and interface list handling
 */
#define SCTP_MAX_VRF_ID 0
#define SCTP_SIZE_OF_VRF_HASH 3
#define SCTP_IFNAMSIZ IFNAMSIZ
#define SCTP_DEFAULT_VRFID 0
#define SCTP_VRF_HASH_SIZE 16


#define SCTP_IFN_IS_IFT_LOOP(ifn) ((ifn)->ifn_type == IFT_LOOP)

/*
 * Access to IFN's to help with src-addr-selection
 */
/* This could return VOID if the index works but for BSD we provide both. */
#define SCTP_GET_IFN_VOID_FROM_ROUTE(ro) (void *)ro->ro_rt->rt_ifp
#define SCTP_GET_IF_INDEX_FROM_ROUTE(ro) ro->ro_rt->rt_ifp->if_index

/*
 * general memory allocation
 */
#define SCTP_MALLOC(var, type, size, name) \
    do { \
	MALLOC(var, type, size, M_PCB, M_NOWAIT); \
    } while (0)

#define SCTP_FREE(var)	FREE(var, M_PCB)

#define SCTP_MALLOC_SONAME(var, type, size) \
    do { \
	MALLOC(var, type, size, M_SONAME, M_WAITOK | M_ZERO); \
    } while (0)

#define SCTP_FREE_SONAME(var)	FREE(var, M_SONAME)

#define SCTP_PROCESS_STRUCT struct proc *

/*
 * zone allocation functions
 */
#include <vm/uma.h>
/* SCTP_ZONE_INIT: initialize the zone */
typedef struct uma_zone *sctp_zone_t;

#define UMA_ZFLAG_FULL	0x0020
#define SCTP_ZONE_INIT(zone, name, size, number) { \
	zone = uma_zcreate(name, size, NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,\
		UMA_ZFLAG_FULL); \
	uma_zone_set_max(zone, number); \
}

/* SCTP_ZONE_GET: allocate element from the zone */
#define SCTP_ZONE_GET(zone, type) \
	(type *)uma_zalloc(zone, M_NOWAIT);

/* SCTP_ZONE_FREE: free element from the zone */
#define SCTP_ZONE_FREE(zone, element) \
	uma_zfree(zone, element);
#define SCTP_HASH_INIT(size, hashmark) hashinit_flags(size, M_PCB, hashmark, HASH_NOWAIT)
#define SCTP_HASH_FREE(table, hashmark) hashdestroy(table, M_PCB, hashmark)

#define SCTP_M_COPYM	m_copym

/*
 * timers
 */
#include <sys/callout.h>
typedef struct callout sctp_os_timer_t;

#define SCTP_OS_TIMER_INIT(tmr)	callout_init(tmr, 1)
#define SCTP_OS_TIMER_START	callout_reset
#define SCTP_OS_TIMER_STOP	callout_stop
#define SCTP_OS_TIMER_STOP_DRAIN callout_drain
#define SCTP_OS_TIMER_PENDING	callout_pending
#define SCTP_OS_TIMER_ACTIVE	callout_active
#define SCTP_OS_TIMER_DEACTIVATE callout_deactivate

/*
 * Functions
 */
/* Mbuf manipulation and access macros  */
#define SCTP_BUF_LEN(m) (m->m_len)
#define SCTP_BUF_NEXT(m) (m->m_next)
#define SCTP_BUF_NEXT_PKT(m) (m->m_nextpkt)
#define SCTP_BUF_RESV_UF(m, size) m->m_data += size
#define SCTP_BUF_AT(m, size) m->m_data + size
#define SCTP_BUF_IS_EXTENDED(m) (m->m_flags & M_EXT)
#define SCTP_BUF_EXTEND_SIZE(m) (m->m_ext.ext_size)
#define SCTP_BUF_TYPE(m) (m->m_type)
#define SCTP_BUF_RECVIF(m) (m->m_pkthdr.rcvif)
#define SCTP_BUF_PREPEND	M_PREPEND

#define SCTP_ALIGN_TO_END(m, len) if(m->m_flags & M_PKTHDR) { \
                                     MH_ALIGN(m, len); \
                                  } else if ((m->m_flags & M_EXT) == 0) { \
                                     M_ALIGN(m, len); \
                                  }

/*************************/
/* These are for logging */
/*************************/
/* return the base ext data pointer */
#define SCTP_BUF_EXTEND_BASE(m) (m->m_ext.ext_buf)
 /* return the refcnt of the data pointer */
#define SCTP_BUF_EXTEND_REFCNT(m) (*m->m_ext.ref_cnt)
/* return any buffer related flags, this is
 * used beyond logging for apple only.
 */
#define SCTP_BUF_GET_FLAGS(m) (m->m_flags)

/* For BSD this just accesses the M_PKTHDR length
 * so it operates on an mbuf with hdr flag. Other
 * O/S's may have seperate packet header and mbuf
 * chain pointers.. thus the macro.
 */
#define SCTP_HEADER_TO_CHAIN(m) (m)
#define SCTP_HEADER_LEN(m) (m->m_pkthdr.len)
#define SCTP_GET_HEADER_FOR_OUTPUT(len) sctp_get_mbuf_for_msg(len, 1, M_DONTWAIT, 1, MT_DATA)

/* Attach the chain of data into the sendable packet. */
#define SCTP_ATTACH_CHAIN(pak, m, packet_length) do { \
                                                 pak->m_next = m; \
                                                 pak->m_pkthdr.len = packet_length; \
                         } while(0)

/* Other m_pkthdr type things */
#define SCTP_IS_IT_BROADCAST(dst, m) in_broadcast(dst, m->m_pkthdr.rcvif)
#define SCTP_IS_IT_LOOPBACK(m) ((m->m_pkthdr.rcvif == NULL) ||(m->m_pkthdr.rcvif->if_type == IFT_LOOP))


/* This converts any input packet header
 * into the chain of data holders, for BSD
 * its a NOP.
 */
#define SCTP_PAK_TO_BUF(i_pak) (i_pak)

/* Macro's for getting length from V6/V4 header */
#define SCTP_GET_IPV4_LENGTH(iph) (iph->ip_len)
#define SCTP_GET_IPV6_LENGTH(ip6) (ntohs(ip6->ip6_plen))

/* is the endpoint v6only? */
#define SCTP_IPV6_V6ONLY(inp)	(((struct inpcb *)inp)->inp_flags & IN6P_IPV6_V6ONLY)
/* is the socket non-blocking? */
#define SCTP_SO_IS_NBIO(so)	((so)->so_state & SS_NBIO)
#define SCTP_SET_SO_NBIO(so)	((so)->so_state |= SS_NBIO)
#define SCTP_CLEAR_SO_NBIO(so)	((so)->so_state &= ~SS_NBIO)
/* get the socket type */
#define SCTP_SO_TYPE(so)	((so)->so_type)
/* reserve sb space for a socket */
#define SCTP_SORESERVE(so, send, recv)	soreserve(so, send, recv)
/* clear the socket buffer state */
#define SCTP_SB_CLEAR(sb)	\
	(sb).sb_cc = 0;		\
	(sb).sb_mb = NULL;	\
	(sb).sb_mbcnt = 0;

#define SCTP_SB_LIMIT_RCV(so) so->so_rcv.sb_hiwat
#define SCTP_SB_LIMIT_SND(so) so->so_snd.sb_hiwat

/*
 * SCTP AUTH
 */
#define HAVE_SHA2

#define SCTP_READ_RANDOM(buf, len)	read_random(buf, len)

#ifdef USE_SCTP_SHA1
#include <netinet/sctp_sha1.h>
#else
#include <crypto/sha1.h>
/* map standard crypto API names */
#define SHA1_Init	SHA1Init
#define SHA1_Update	SHA1Update
#define SHA1_Final(x,y)	SHA1Final((caddr_t)x, y)
#endif

#if defined(HAVE_SHA2)
#include <crypto/sha2/sha2.h>
#endif

#include <sys/md5.h>
/* map standard crypto API names */
#define MD5_Init	MD5Init
#define MD5_Update	MD5Update
#define MD5_Final	MD5Final

#endif
