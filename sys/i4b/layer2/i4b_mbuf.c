/*
 * Copyright (c) 1997, 1999 Hellmuth Michaelis. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *---------------------------------------------------------------------------
 *
 *	i4b - mbuf handling support routines
 *	------------------------------------
 *
 *	$Id: i4b_mbuf.c,v 1.11 1999/02/14 09:45:00 hm Exp $ 
 *
 *      last edit-date: [Sun Feb 14 10:32:00 1999]
 *
 *---------------------------------------------------------------------------*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/ioccom.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <net/if.h>

#include <i4b/include/i4b_mbuf.h>
#include <i4b/include/i4b_global.h>

#define I4B_MBUF_DEBUG
#undef I4B_MBUF_TYPE_DEBUG

#ifdef I4B_MBUF_TYPE_DEBUG

#ifdef  __FreeBSD__

#define MT_DCHAN	42
#define MT_BCHAN	43

#else /* NetBSD */

#define MT_DCHAN        MT_DATA
#define MT_BCHAN        MT_DATA

#endif

#define MT_I4B_D	MT_DCHAN
#define MT_I4B_B	MT_BCHAN

#else /* ! I4B_MBUF_TYPE_DEBUG */

#define MT_I4B_D	MT_DATA
#define MT_I4B_B	MT_DATA

#endif /* I4B_MBUF_TYPE_DEBUG */

/*---------------------------------------------------------------------------*
 *	allocate D-channel mbuf space
 *---------------------------------------------------------------------------*/
struct mbuf*
i4b_Dgetmbuf(int len)
{
	struct mbuf *m;

	if(len > MCLBYTES)	/* if length > max extension size */
	{

#ifdef I4B_MBUF_DEBUG
		printf("i4b_getmbuf: error - len(%d) > MCLBYTES(%d)\n",
					len, MCLBYTES);
#endif
		
		return(NULL);
	}

	MGETHDR(m, M_DONTWAIT, MT_I4B_D);	/* get mbuf with pkthdr */

	/* did we actually get the mbuf ? */

	if(!m)	
	{

#ifdef I4B_MBUF_DEBUG
		printf("i4b_getbuf: error - MGETHDR failed!\n");
#endif

		return(NULL);
	}

	if(len >= MHLEN)
	{
		MCLGET(m, M_DONTWAIT);

		if(!(m->m_flags & M_EXT))
		{
			m_freem(m);

#ifdef I4B_MBUF_DEBUG
			printf("i4b_getbuf: error - MCLGET failed, len(%d)\n", len);
#endif
			
			return (NULL);
		}
	}

	m->m_len = len;

	return(m);
}

/*---------------------------------------------------------------------------*
 *	free a D-channel mbuf
 *---------------------------------------------------------------------------*/
void
i4b_Dfreembuf(struct mbuf *m)
{
	if(m)
		m_freem(m);
}

/*---------------------------------------------------------------------------*
 *	clear a D-channel ifqueue from data
 *---------------------------------------------------------------------------*/
void
i4b_Dcleanifq(struct ifqueue *ifq)
{
	struct mbuf *m;
	int x = splimp();
	
	while(!IF_QEMPTY(ifq))
	{
		IF_DEQUEUE(ifq, m);
		i4b_Dfreembuf(m);
	}

	splx(x);
}

/*---------------------------------------------------------------------------*
 *	allocate B-channel mbuf space
 *---------------------------------------------------------------------------*/
struct mbuf*
i4b_Bgetmbuf(int len)
{
	struct mbuf *m;

	if(len > MCLBYTES)	/* if length > max extension size */
	{

#ifdef I4B_MBUF_DEBUG
		printf("i4b_getmbuf: error - len(%d) > MCLBYTES(%d)\n",
					len, MCLBYTES);
#endif
		
		return(NULL);
	}

	MGETHDR(m, M_DONTWAIT, MT_I4B_B);	/* get mbuf with pkthdr */

	/* did we actually get the mbuf ? */

	if(!m)	
	{

#ifdef I4B_MBUF_DEBUG
		printf("i4b_getbuf: error - MGETHDR failed!\n");
#endif

		return(NULL);
	}

	if(len >= MHLEN)
	{
		MCLGET(m, M_DONTWAIT);

		if(!(m->m_flags & M_EXT))
		{
			m_freem(m);

#ifdef I4B_MBUF_DEBUG
			printf("i4b_getbuf: error - MCLGET failed, len(%d)\n", len);
#endif
			
			return (NULL);
		}
	}

	m->m_len = len;

	return(m);
}

/*---------------------------------------------------------------------------*
 *	free a B-channel mbuf
 *---------------------------------------------------------------------------*/
void
i4b_Bfreembuf(struct mbuf *m)
{
	if(m)
		m_freem(m);
}

/*---------------------------------------------------------------------------*
 *	clear a B-channel ifqueue from data
 *---------------------------------------------------------------------------*/
void
i4b_Bcleanifq(struct ifqueue *ifq)
{
	struct mbuf *m;
	int x = splimp();
	
	while(!IF_QEMPTY(ifq))
	{
		IF_DEQUEUE(ifq, m);
		i4b_Bfreembuf(m);
	}

	splx(x);
}

/* EOF */
