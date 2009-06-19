/**************************************************************************
 *
 * Copyright (c) 2007,2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 ***************************************************************************/

#ifndef _MVEC_H_
#define _MVEC_H_
#include <machine/bus.h>

#define	M_DDP		0x200000	/* direct data placement mbuf */
#define	EXT_PHYS	10		/* physical/bus address  */

#define m_cur_offset	m_ext.ext_size		/* override to provide ddp offset */
#define m_seq		m_pkthdr.csum_data	/* stored sequence */
#define m_ddp_gl	m_ext.ext_buf		/* ddp list	*/
#define m_ddp_flags	m_pkthdr.csum_flags	/* ddp flags	*/
#define m_ulp_mode	m_pkthdr.tso_segsz	/* upper level protocol	*/

static __inline void
busdma_map_mbuf_fast(struct sge_txq *txq, struct tx_sw_desc *txsd,
    struct mbuf *m, bus_dma_segment_t *seg)
{
#if defined(__i386__) || defined(__amd64__)
	seg->ds_addr = pmap_kextract(mtod(m, vm_offset_t));
	seg->ds_len = m->m_len;
#else
	int nsegstmp;

	bus_dmamap_load_mbuf_sg(txq->entry_tag, txsd->map, m, seg,
		    &nsegstmp, 0);
#endif
}

int busdma_map_sg_collapse(struct sge_txq *txq, struct tx_sw_desc *txsd,
    struct mbuf **m, bus_dma_segment_t *segs, int *nsegs);
void busdma_map_sg_vec(struct sge_txq *txq, struct tx_sw_desc *txsd, struct mbuf *m, bus_dma_segment_t *segs, int *nsegs);
static __inline int
busdma_map_sgl(bus_dma_segment_t *vsegs, bus_dma_segment_t *segs, int count) 
{
	while (count--) {
		segs->ds_addr = pmap_kextract((vm_offset_t)vsegs->ds_addr);
		segs->ds_len = vsegs->ds_len;
		segs++;
		vsegs++;
	}
	return (0);
}

static __inline void
m_freem_list(struct mbuf *m)
{
	struct mbuf *n; 

	while (m != NULL) {
		n = m->m_nextpkt;
		if (n != NULL)
			prefetch(n);
		m_freem(m);
		m = n;
	}	
}


#endif /* _MVEC_H_ */
