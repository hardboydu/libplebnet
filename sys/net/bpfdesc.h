/*-
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
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
 *      @(#)bpfdesc.h	8.1 (Berkeley) 6/10/93
 *
 * $FreeBSD$
 */

#ifndef _NET_BPFDESC_H_
#define _NET_BPFDESC_H_

#include <sys/callout.h>
#include <sys/selinfo.h>
#include <sys/queue.h>
#include <sys/conf.h>
#include <net/if.h>

/*
 * Descriptor associated with each open bpf file.
 */
struct zbuf;
struct bpf_d {
	LIST_ENTRY(bpf_d) bd_next;	/* Linked list of descriptors */
	/*
	 * Buffer slots: two memory buffers store the incoming packets.
	 *   The model has three slots.  Sbuf is always occupied.
	 *   sbuf (store) - Receive interrupt puts packets here.
	 *   hbuf (hold) - When sbuf is full, put buffer here and
	 *                 wakeup read (replace sbuf with fbuf).
	 *   fbuf (free) - When read is done, put buffer here.
	 * On receiving, if sbuf is full and fbuf is 0, packet is dropped.
	 */
	caddr_t		bd_sbuf;	/* store slot */
	caddr_t		bd_hbuf;	/* hold slot */
	caddr_t		bd_fbuf;	/* free slot */
	int 		bd_slen;	/* current length of store buffer */
	int 		bd_hlen;	/* current length of hold buffer */

	int		bd_bufsize;	/* absolute length of buffers */

	struct bpf_if *	bd_bif;		/* interface descriptor */
	u_long		bd_rtout;	/* Read timeout in 'ticks' */
	struct bpf_insn *bd_rfilter; 	/* read filter code */
	struct bpf_insn *bd_wfilter;	/* write filter code */
	void		*bd_bfilter;	/* binary filter code */
	u_int64_t	bd_rcount;	/* number of packets received */
	u_int64_t	bd_dcount;	/* number of packets dropped */

	u_char		bd_state;	/* idle, waiting, or timed out */
	int		bd_flags;	/* bpf device options */
	int		bd_hdrcmplt;	/* false to fill in src lladdr automatically */
	int		bd_direction;	/* select packet direction */
	int		bd_tstamp;	/* select time stamping function */

	int		bd_sig;		/* signal to send upon packet reception */
	struct sigio *	bd_sigio;	/* information for async I/O */
	struct selinfo	bd_sel;		/* bsd select info */
	struct mtx	bd_mtx;		/* mutex for this descriptor */
	struct callout	bd_callout;	/* for BPF timeouts with select */
	struct label	*bd_label;	/* MAC label for descriptor */
	u_int64_t	bd_fcount;	/* number of packets which matched filter */
	pid_t		bd_pid;		/* PID which created descriptor */
	u_int		bd_bufmode;	/* Current buffer mode. */
	u_int64_t	bd_wcount;	/* number of packets written */
	u_int64_t	bd_wfcount;	/* number of packets that matched write filter */
	u_int64_t	bd_wdcount;	/* number of packets dropped during a write */
	u_int64_t	bd_zcopy;	/* number of zero copy operations */
};

#define	BPFF_ASYNC	0x0001		/* packet reception should generate signal */
#define	BPFF_FEEDBACK	0x0002		/* feed back sent packets */
#define	BPFF_IMMEDIATE	0x0004		/* return on packet arrival */
#define	BPFF_PROMISC	0x0008		/* listening promiscuously */
#define	BPFF_COMPAT32	0x0010		/* 32-bit stream on LP64 system */
#define	BPFF_LOCKED	0x0020		/* descriptor is locked */
#define	BPFF_DROPMATCH	0x0040		/* don't pass matching packets on to host */
#define	BPFF_NOPRIVS	0x0080
#define	BPFF_FILTSET	0x0100

#define	BD_ASYNC(d)	(!!((d)->bd_flags & BPFF_ASYNC))
#define	BD_FEEDBACK(d)	(!!((d)->bd_flags & BPFF_FEEDBACK))
#define	BD_IMMEDIATE(d)	(!!((d)->bd_flags & BPFF_IMMEDIATE))
#define	BD_PROMISC(d)	(!!((d)->bd_flags & BPFF_PROMISC))
#define	BD_COMPAT32(d)	(!!((d)->bd_flags & BPFF_COMPAT32))
#define	BD_LOCKED(d)	(!!((d)->bd_flags & BPFF_LOCKED))
#define	BD_DROPMATCH(d)	(!!((d)->bd_flags & BPFF_DROPMATCH))
#define	BD_NOPRIVS(d)	(!!((d)->bd_flags & BPFF_NOPRIVS))

#define	UBPF_UNCONFIGURED(d)					\
	(((d)->bd_flags & (BPFF_NOPRIVS|BPFF_FILTSET)) == BPFF_NOPRIVS)



/* Values for bd_state */
#define BPF_IDLE	0		/* no select in progress */
#define BPF_WAITING	1		/* waiting for read timeout in select */
#define BPF_TIMED_OUT	2		/* read timeout has expired in select */

#define BPFD_LOCK(bd)		mtx_lock(&(bd)->bd_mtx)
#define BPFD_UNLOCK(bd)		mtx_unlock(&(bd)->bd_mtx)
#define BPFD_LOCK_ASSERT(bd)	mtx_assert(&(bd)->bd_mtx, MA_OWNED)

/*
 * External representation of the bpf descriptor
 */
struct xbpf_d {
	u_int		bd_structsize;	/* Size of this structure. */
	u_char		bd_promisc;
	u_char		bd_immediate;
	u_char		__bd_pad[6];
	int		bd_hdrcmplt;
	int		bd_direction;
	int		bd_feedback;
	int		bd_async;
	u_int64_t	bd_rcount;
	u_int64_t	bd_dcount;
	u_int64_t	bd_fcount;
	int		bd_sig;
	int		bd_slen;
	int		bd_hlen;
	int		bd_bufsize;
	pid_t		bd_pid;
	char		bd_ifname[IFNAMSIZ];
	int		bd_locked;
	u_int64_t	bd_wcount;
	u_int64_t	bd_wfcount;
	u_int64_t	bd_wdcount;
	u_int64_t	bd_zcopy;
	int		bd_bufmode;
	/*
	 * Allocate 4 64 bit unsigned integers for future expansion so we do
	 * not have to worry about breaking the ABI.
	 */
	u_int64_t	bd_spare[4];
};

#define BPFIF_LOCK(bif)		mtx_lock(&(bif)->bif_mtx)
#define BPFIF_UNLOCK(bif)	mtx_unlock(&(bif)->bif_mtx)

#endif
