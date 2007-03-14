/**************************************************************************

Copyright (c) 2007, Chelsio Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 3. Neither the name of the Chelsio Corporation nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***************************************************************************/

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus_dma.h>
#include <sys/rman.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <dev/cxgb/cxgb_osdep.h>
#include <dev/cxgb/common/cxgb_common.h>
#include <dev/cxgb/common/cxgb_t3_cpl.h>

#include <machine/in_cksum.h>


#ifndef M_LRO
#define M_LRO    0x0200
#endif

#ifdef DEBUG
#define MBUF_HEADER_CHECK(mh) do { \
	struct mbuf *head = mh->mh_head; \
	struct mbuf *tail = mh->mh_tail; \
	if (head->m_len == 0 || head->m_pkthdr.len == 0 \
	    || (head->m_flags & M_PKTHDR) == 0) 			\
		panic("lro_flush_session - mbuf len=%d pktlen=%d flags=0x%x\n", \
		    head->m_len, head->m_pkthdr.len, head->m_flags); \
	if ((head->m_flags & M_PKTHDR) == 0) \
		panic("first mbuf is not packet header - flags=0x%x\n", \
		    head->m_flags);  \
	if ((head == tail && head->m_len != head->m_pkthdr.len)) \
		panic("len=%d pktlen=%d mismatch\n", \
		    head->m_len, head->m_pkthdr.len);			\
	if (head->m_len < ETHER_HDR_LEN || head->m_pkthdr.len < ETHER_HDR_LEN) \
		panic("packet too small len=%d pktlen=%d\n", \
		    head->m_len, head->m_pkthdr.len);\
} while (0)
#else
#define MBUF_HEADER_CHECK(m)
#endif	  

#define IPH_OFFSET (2 + sizeof (struct cpl_rx_pkt) + ETHER_HDR_LEN)
#define LRO_SESSION_IDX_HINT_HASH(hash) (hash & (MAX_LRO_PER_QSET - 1))
#define LRO_IDX_INC(idx) idx = (idx + 1) & (MAX_LRO_PER_QSET - 1)

static __inline struct sge_lro_session *
lro_session(struct sge_lro *l, int idx)
{
	return l->s + idx;
}

static __inline int
lro_match_session(struct sge_lro_session *s, 
    struct ip *ih, struct tcphdr *th)
{
	struct ip *sih = (struct ip *)(s->mh.mh_head->m_data + IPH_OFFSET);
	struct tcphdr *sth = (struct tcphdr *) (sih + 1);

	/*
	 * Linux driver doesn't include destination port check --
	 * need to find out why XXX
	 */
	return (*(uint32_t *)&th->th_sport == *(uint32_t *)&sth->th_sport &&
	    *(uint32_t *)&th->th_dport == *(uint32_t *)&sth->th_dport &&
	    ih->ip_src.s_addr == ih->ip_src.s_addr &&
	    ih->ip_dst.s_addr == sih->ip_dst.s_addr);
}

static __inline struct sge_lro_session *
lro_find_session(struct sge_lro *l, int idx, struct ip *ih, struct tcphdr *th)
{
	struct sge_lro_session *s;
	int active = 0;

	while (active < l->num_active) {
		s = lro_session(l, idx); 
		if (s->mh.mh_head) {
			if (lro_match_session(s, ih, th)) {
				l->last_s = s;
				return s;
			}
			active++;
		}
		LRO_IDX_INC(idx);
	}

	return NULL;
}

static __inline int
can_lro_packet(struct cpl_rx_pkt *cpl, unsigned int rss_hi)
{
	struct ether_header *eh = (struct ether_header *)(cpl + 1);
	struct ip *ih = (struct ip *)(eh + 1);

	/* 
	 * XXX VLAN support?
	 */
	if (__predict_false(G_HASHTYPE(ntohl(rss_hi)) != RSS_HASH_4_TUPLE ||
		     (*((uint8_t *)cpl + 1) & 0x90) != 0x10 || 
		     cpl->csum != 0xffff || eh->ether_type != ntohs(ETHERTYPE_IP) ||
		     ih->ip_hl != (sizeof (*ih) >> 2))) {
		return 0;
	}

	return 1;
}

static int
can_lro_tcpsegment(struct tcphdr *th)
{
	int olen = (th->th_off << 2) - sizeof (*th);
	u8 control_bits = *((u8 *)th + 13);

	if (__predict_false((control_bits & 0xB7) != 0x10))
		goto no_lro;

	if (olen) {
		uint32_t *ptr = (u32 *)(th + 1);
		if (__predict_false(olen != TCPOLEN_TSTAMP_APPA || 
			     *ptr != ntohl((TCPOPT_NOP << 24) | 
					   (TCPOPT_NOP << 16) | 
					   (TCPOPT_TIMESTAMP << 8) | 
					    TCPOLEN_TIMESTAMP)))
			goto no_lro;
	}

	return 1;

 no_lro:
	return 0;	
}

static __inline void
lro_new_session_init(struct sge_lro_session *s, struct t3_mbuf_hdr *mh)
{
	struct ip *ih = (struct ip *)(mh->mh_head->m_data + IPH_OFFSET);
	struct tcphdr *th = (struct tcphdr *) (ih + 1);
	int ip_len = ntohs(ih->ip_len);

	DPRINTF("%s(s=%p, mh->mh_head=%p, mh->mh_tail=%p)\n", __FUNCTION__,
	    s, mh->mh_head, mh->mh_tail);
	
	*&(s->mh) = *mh;

	MBUF_HEADER_CHECK(mh);
	s->ip_len = ip_len;
	s->seq = ntohl(th->th_seq) + ip_len - sizeof(*ih) - (th->th_off << 2);

} 

static void
lro_flush_session(struct sge_qset *qs, struct sge_lro_session *s, struct t3_mbuf_hdr *mh)
{
	struct sge_lro *l = &qs->lro;
	struct t3_mbuf_hdr *smh = &s->mh;
	struct ip *ih = (struct ip *)(smh->mh_head->m_data + IPH_OFFSET);

	
	DPRINTF("%s(qs=%p, s=%p, ", __FUNCTION__,
	    qs, s);

	if (mh)
		DPRINTF("mh->mh_head=%p, mh->mh_tail=%p)\n",
		    mh->mh_head, mh->mh_tail);
	else
		DPRINTF("mh=NULL)\n");
	
	ih->ip_len = htons(s->ip_len);
	ih->ip_sum = 0;
	ih->ip_sum = in_cksum_hdr(ih);

	MBUF_HEADER_CHECK(smh);
	
	smh->mh_head->m_flags |= M_LRO;
	t3_rx_eth(qs->port, &qs->rspq, smh->mh_head, 2);
	
	if (mh) {
		*smh = *mh;
		lro_new_session_init(s, mh);
	} else {
		smh->mh_head = NULL;
		smh->mh_tail = NULL;
		l->num_active--;
	}

	qs->port_stats[SGE_PSTATS_LRO_FLUSHED]++;
}

static __inline struct sge_lro_session *
lro_new_session(struct sge_qset *qs, struct t3_mbuf_hdr *mh, uint32_t rss_hash)
{
	struct sge_lro *l = &qs->lro;
	int idx = LRO_SESSION_IDX_HINT_HASH(rss_hash); 
	struct sge_lro_session *s = lro_session(l, idx);

	DPRINTF("%s(qs=%p,  mh->mh_head=%p, mh->mh_tail=%p, rss_hash=0x%x)\n", __FUNCTION__,
	    qs, mh->mh_head, mh->mh_tail, rss_hash);
	
	if (__predict_true(!s->mh.mh_head))
		goto done;

	if (l->num_active > MAX_LRO_PER_QSET)
		panic("MAX_LRO_PER_QSET exceeded");
	
	if (l->num_active == MAX_LRO_PER_QSET) {
		lro_flush_session(qs, s, mh);
		qs->port_stats[SGE_PSTATS_LRO_X_STREAMS]++;
		return s;
	}

	while (1) {
		LRO_IDX_INC(idx);
		s = lro_session(l, idx);
		if (!s->mh.mh_head)
			break;
	}
done:
	lro_new_session_init(s, mh);

	l->num_active++;

	return s;	

}

static __inline int
lro_update_session(struct sge_lro_session *s, struct t3_mbuf_hdr *mh)
{
	struct mbuf *m = mh->mh_head;
	struct t3_mbuf_hdr *smh = &s->mh;
	struct cpl_rx_pkt *cpl = (struct cpl_rx_pkt *)(smh->mh_head->m_data + 2);
	struct cpl_rx_pkt *ncpl = (struct cpl_rx_pkt *)(m->m_data + 2);
	struct ip *nih = (struct ip *)(m->m_data + IPH_OFFSET);
	struct tcphdr *th, *nth = (struct tcphdr *)(nih + 1);
	uint32_t seq = ntohl(nth->th_seq);
	int plen, tcpiphlen, olen = (nth->th_off << 2) - sizeof (*nth);
	
	
	DPRINTF("%s(s=%p,  mh->mh_head=%p, mh->mh_tail=%p)\n", __FUNCTION__,
	    s, mh->mh_head, mh->mh_tail);	
	if (cpl->vlan_valid && cpl->vlan != ncpl->vlan) {
		return -1;
	}
	if (__predict_false(seq != s->seq)) {
		DPRINTF("sequence mismatch\n");
		return -1;
	}

	MBUF_HEADER_CHECK(smh);
	th = (struct tcphdr *)(smh->mh_head->m_data + IPH_OFFSET + sizeof (struct ip));

	if (olen) {
		uint32_t *ptr = (uint32_t *)(th + 1);
		uint32_t *nptr = (uint32_t *)(nth + 1);

		if (__predict_false(ntohl(*(ptr + 1)) > ntohl(*(nptr + 1)) || 
			     !*(nptr + 2))) {
			return -1;
		}
		*(ptr + 1) = *(nptr + 1);
		*(ptr + 2) = *(nptr + 2);
	}
	th->th_ack = nth->th_ack;
	th->th_win = nth->th_win;

	tcpiphlen = (nth->th_off << 2) + sizeof (*nih);
	plen = ntohs(nih->ip_len) - tcpiphlen;
	s->seq += plen;
	s->ip_len += plen;
	smh->mh_head->m_pkthdr.len += plen;

#if 0
	/* XXX this I *do not* understand */
	if (plen > skb_shinfo(s->skb)->gso_size)
		skb_shinfo(s->skb)->gso_size = plen;
#endif
#if __FreeBSD_version > 700000	
	if (plen > smh->mh_head->m_pkthdr.tso_segsz)
		smh->mh_head->m_pkthdr.tso_segsz = plen;
#endif
	DPRINTF("m_adj(%d)\n", (int)(IPH_OFFSET + tcpiphlen));
	m_adj(m, IPH_OFFSET + tcpiphlen);
#if 0 
	if (__predict_false(!skb_shinfo(s->skb)->frag_list))
		skb_shinfo(s->skb)->frag_list = skb;

#endif
	mh->mh_head->m_flags &= ~M_PKTHDR;
	smh->mh_tail->m_next = mh->mh_head;
	smh->mh_tail = mh->mh_tail;
#if 0
	
	/* 
	 * XXX we really need to be able to
	 * support vectors of buffers in FreeBSD
	 */
	int nr = skb_shinfo(s->skb)->nr_frags;
	skb_shinfo(s->skb)->frags[nr].page = frag->page;
	skb_shinfo(s->skb)->frags[nr].page_offset = 
	    frag->page_offset + IPH_OFFSET + tcpiphlen;
	skb_shinfo(s->skb)->frags[nr].size = plen; 
	skb_shinfo(s->skb)->nr_frags = ++nr;
		
#endif
	return (0);
}

void
t3_rx_eth_lro(adapter_t *adap, struct sge_rspq *rq, struct t3_mbuf_hdr *mh,
    int ethpad, uint32_t rss_hash, uint32_t rss_csum, int lro)
{
	struct mbuf *m = mh->mh_head;
	struct sge_qset *qs = rspq_to_qset(rq);
	struct cpl_rx_pkt *cpl = (struct cpl_rx_pkt *)(m->m_data + ethpad);
	struct ether_header *eh = (struct ether_header *)(cpl + 1);
	struct ip *ih;
	struct tcphdr *th; 
	struct sge_lro_session *s = NULL;
	struct port_info *pi = qs->port;
	
	if (lro == 0)
		goto no_lro;

	if (!can_lro_packet(cpl, rss_csum))
		goto no_lro;
	
	if (&adap->port[cpl->iff] != pi)
		panic("bad port index %d\n", cpl->iff);

	ih = (struct ip *)(eh + 1);
	th = (struct tcphdr *)(ih + 1);
	
	s = lro_find_session(&qs->lro,
	    LRO_SESSION_IDX_HINT_HASH(rss_hash), ih, th);
	
	if (__predict_false(!can_lro_tcpsegment(th))) {
		goto no_lro;
	} else if (__predict_false(!s)) {
		s = lro_new_session(qs, mh, rss_hash);
	} else {
		if (lro_update_session(s, mh)) {
			lro_flush_session(qs, s, mh);
		}
		if (__predict_false(s->mh.mh_head->m_pkthdr.len + pi->ifp->if_mtu > 65535)) {
			lro_flush_session(qs, s, NULL);
		}		
	}

	qs->port_stats[SGE_PSTATS_LRO_QUEUED]++;
	return;
no_lro:
	if (s)
		lro_flush_session(qs, s, NULL);
	
	if (m->m_len == 0 || m->m_pkthdr.len == 0 || (m->m_flags & M_PKTHDR) == 0)
		DPRINTF("rx_eth_lro mbuf len=%d pktlen=%d flags=0x%x\n",
		    m->m_len, m->m_pkthdr.len, m->m_flags);
	t3_rx_eth(pi, rq, m, ethpad);
}

void
t3_sge_lro_flush_all(adapter_t *adap, struct sge_qset *qs)
{
	struct sge_lro *l = &qs->lro;
	struct sge_lro_session *s = l->last_s; 
	int active = 0, idx = 0, num_active = l->num_active;

	if (__predict_false(!s))
		s = lro_session(l, idx);

	while (active < num_active) {
		if (s->mh.mh_head) {
			lro_flush_session(qs, s, NULL);
			active++;
		}
		LRO_IDX_INC(idx);
		s = lro_session(l, idx);
	}
}
