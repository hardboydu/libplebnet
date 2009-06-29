/*-
 * Copyright (c) 2006-2008 University of Zagreb
 * Copyright (c) 2006-2008 FreeBSD Foundation
 *
 * This software was developed by the University of Zagreb and the
 * FreeBSD Foundation under sponsorship by the Stichting NLnet and the
 * FreeBSD Foundation.
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
 * $FreeBSD$
 */

#ifndef _NET_VNET_H_
#define	_NET_VNET_H_

#include <net/if_var.h>

struct ifindex_entry;

struct vnet_net {
	int			_if_index;
	struct ifindex_entry *	_ifindex_table;
	struct ifnethead	_ifnet;
	struct ifgrouphead	_ifg_head;

	int			_if_indexlim;

	struct ifnet *		_loif;
	struct if_clone *	_lo_cloner;
	struct ifc_simple_data *_lo_cloner_data;

	LIST_HEAD(, rawcb)	_rawcb_list;

	LIST_HEAD(, if_clone)	_if_cloners;
	int			_if_cloners_count;

	int			_ether_ipfw;
};

/* Size guard. See sys/vimage.h. */
VIMAGE_CTASSERT(SIZEOF_vnet_net, sizeof(struct vnet_net));

#ifndef VIMAGE
#ifndef VIMAGE_GLOBALS
extern struct vnet_net vnet_net_0;
#endif
#endif

/*
 * Symbol translation macros
 */
#define	INIT_VNET_NET(vnet) \
	INIT_FROM_VNET(vnet, VNET_MOD_NET, struct vnet_net, vnet_net)

#define	VNET_NET(sym)	VSYM(vnet_net, sym)

#define	V_ether_ipfw		VNET_NET(ether_ipfw)
#define	V_if_index		VNET_NET(if_index)
#define	V_if_indexlim		VNET_NET(if_indexlim)
#define	V_if_cloners		VNET_NET(if_cloners)
#define	V_if_cloners_count	VNET_NET(if_cloners_count)
#define	V_ifg_head		VNET_NET(ifg_head)
#define	V_ifindex_table		VNET_NET(ifindex_table)
#define	V_ifklist		VNET_NET(ifklist)
#define	V_ifnet			VNET_NET(ifnet)
#define	V_lo_cloner		VNET_NET(lo_cloner)
#define	V_lo_cloner_data	VNET_NET(lo_cloner_data)
#define	V_loif			VNET_NET(loif)
#define	V_rawcb_list		VNET_NET(rawcb_list)

#endif /* !_NET_VNET_H_ */
