/*-
 * Copyright (c) 2007, by Cisco Systems, Inc. All rights reserved.
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

#include <netinet/sctp_os.h>
#include <netinet/sctp_constants.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>

/*
 * sysctl tunable variables
 */
uint32_t sctp_sendspace = (128 * 1024);
uint32_t sctp_recvspace = 128 * (1024 +
#ifdef INET6
    sizeof(struct sockaddr_in6)
#else
    sizeof(struct sockaddr_in)
#endif
);
uint32_t sctp_mbuf_threshold_count = SCTP_DEFAULT_MBUFS_IN_CHAIN;
uint32_t sctp_auto_asconf = SCTP_DEFAULT_AUTO_ASCONF;
uint32_t sctp_ecn_enable = 1;
uint32_t sctp_ecn_nonce = 0;
uint32_t sctp_strict_sacks = 0;
uint32_t sctp_no_csum_on_loopback = 1;
uint32_t sctp_strict_init = 1;
uint32_t sctp_abort_if_one_2_one_hits_limit = 0;
uint32_t sctp_strict_data_order = 0;

uint32_t sctp_peer_chunk_oh = sizeof(struct mbuf);
uint32_t sctp_max_burst_default = SCTP_DEF_MAX_BURST;
uint32_t sctp_use_cwnd_based_maxburst = 1;
uint32_t sctp_do_drain = 1;
uint32_t sctp_hb_maxburst = SCTP_DEF_MAX_BURST;

uint32_t sctp_max_chunks_on_queue = SCTP_ASOC_MAX_CHUNKS_ON_QUEUE;
uint32_t sctp_delayed_sack_time_default = SCTP_RECV_MSEC;
uint32_t sctp_sack_freq_default = SCTP_DEFAULT_SACK_FREQ;
uint32_t sctp_heartbeat_interval_default = SCTP_HB_DEFAULT_MSEC;
uint32_t sctp_pmtu_raise_time_default = SCTP_DEF_PMTU_RAISE_SEC;
uint32_t sctp_shutdown_guard_time_default = SCTP_DEF_MAX_SHUTDOWN_SEC;
uint32_t sctp_secret_lifetime_default = SCTP_DEFAULT_SECRET_LIFE_SEC;
uint32_t sctp_rto_max_default = SCTP_RTO_UPPER_BOUND;
uint32_t sctp_rto_min_default = SCTP_RTO_LOWER_BOUND;
uint32_t sctp_rto_initial_default = SCTP_RTO_INITIAL;
uint32_t sctp_init_rto_max_default = SCTP_RTO_UPPER_BOUND;
uint32_t sctp_valid_cookie_life_default = SCTP_DEFAULT_COOKIE_LIFE;
uint32_t sctp_init_rtx_max_default = SCTP_DEF_MAX_INIT;
uint32_t sctp_assoc_rtx_max_default = SCTP_DEF_MAX_SEND;
uint32_t sctp_path_rtx_max_default = SCTP_DEF_MAX_PATH_RTX;
uint32_t sctp_nr_outgoing_streams_default = SCTP_OSTREAM_INITIAL;
uint32_t sctp_add_more_threshold = SCTP_DEFAULT_ADD_MORE;
uint32_t sctp_asoc_free_resc_limit = SCTP_DEF_ASOC_RESC_LIMIT;
uint32_t sctp_system_free_resc_limit = SCTP_DEF_SYSTEM_RESC_LIMIT;

uint32_t sctp_min_split_point = SCTP_DEFAULT_SPLIT_POINT_MIN;
uint32_t sctp_pcbtblsize = SCTP_PCBHASHSIZE;
uint32_t sctp_hashtblsize = SCTP_TCBHASHSIZE;
uint32_t sctp_chunkscale = SCTP_CHUNKQUEUE_SCALE;

uint32_t sctp_cmt_on_off = 0;
uint32_t sctp_cmt_use_dac = 0;
uint32_t sctp_max_retran_chunk = SCTPCTL_MAX_RETRAN_CHUNK_DEFAULT;


uint32_t sctp_L2_abc_variable = 1;
uint32_t sctp_early_fr = 0;
uint32_t sctp_early_fr_msec = SCTP_MINFR_MSEC_TIMER;
uint32_t sctp_says_check_for_deadlock = 0;
uint32_t sctp_asconf_auth_nochk = 0;
uint32_t sctp_auth_disable = 0;
uint32_t sctp_nat_friendly = 1;
uint32_t sctp_min_residual = SCTPCTL_MIN_RESIDUAL_DEFAULT;;


struct sctpstat sctpstat;

#ifdef SCTP_DEBUG
uint32_t sctp_debug_on = 0;

#endif


/*
 * sysctl functions
 */
static int
sctp_assoclist(SYSCTL_HANDLER_ARGS)
{
	unsigned int number_of_endpoints;
	unsigned int number_of_local_addresses;
	unsigned int number_of_associations;
	unsigned int number_of_remote_addresses;
	unsigned int n;
	int error;
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;
	struct sctp_nets *net;
	struct sctp_laddr *laddr;
	struct xsctp_inpcb xinpcb;
	struct xsctp_tcb xstcb;

/*	struct xsctp_laddr xladdr; */
	struct xsctp_raddr xraddr;

	number_of_endpoints = 0;
	number_of_local_addresses = 0;
	number_of_associations = 0;
	number_of_remote_addresses = 0;

	SCTP_INP_INFO_RLOCK();
	if (req->oldptr == USER_ADDR_NULL) {
		LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
			SCTP_INP_RLOCK(inp);
			number_of_endpoints++;
			/* FIXME MT */
			LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
				number_of_local_addresses++;
			}
			LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
				number_of_associations++;
				TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
					number_of_remote_addresses++;
				}
			}
			SCTP_INP_RUNLOCK(inp);
		}
		SCTP_INP_INFO_RUNLOCK();
		n = (number_of_endpoints + 1) * sizeof(struct xsctp_inpcb) +
		    number_of_local_addresses * sizeof(struct xsctp_laddr) +
		    number_of_associations * sizeof(struct xsctp_tcb) +
		    number_of_remote_addresses * sizeof(struct xsctp_raddr);
#ifdef SCTP_DEBUG
		printf("inps = %u, stcbs = %u, laddrs = %u, raddrs = %u\n",
		    number_of_endpoints, number_of_associations,
		    number_of_local_addresses, number_of_remote_addresses);
#endif
		/* request some more memory than needed */
		req->oldidx = (n + n / 8);
		return 0;
	}
	if (req->newptr != USER_ADDR_NULL) {
		SCTP_INP_INFO_RUNLOCK();
		return EPERM;
	}
	LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
		SCTP_INP_RLOCK(inp);
		number_of_local_addresses = 0;
		number_of_associations = 0;
		/*
		 * LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr)
		 * { number_of_local_addresses++; }
		 */
		LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
			number_of_associations++;
		}
		xinpcb.last = 0;
		xinpcb.local_port = ntohs(inp->sctp_lport);
		xinpcb.number_local_addresses = number_of_local_addresses;
		xinpcb.number_associations = number_of_associations;
		xinpcb.flags = inp->sctp_flags;
		xinpcb.features = inp->sctp_features;
		xinpcb.total_sends = inp->total_sends;
		xinpcb.total_recvs = inp->total_recvs;
		xinpcb.total_nospaces = inp->total_nospaces;
		xinpcb.fragmentation_point = inp->sctp_frag_point;
		if (inp->sctp_socket != NULL) {
			sotoxsocket(inp->sctp_socket, &xinpcb.xsocket);
		} else {
			bzero(&xinpcb.xsocket, sizeof xinpcb.xsocket);
			xinpcb.xsocket.xso_protocol = IPPROTO_SCTP;
		}
		SCTP_INP_INCR_REF(inp);
		SCTP_INP_RUNLOCK(inp);
		SCTP_INP_INFO_RUNLOCK();
		error = SYSCTL_OUT(req, &xinpcb, sizeof(struct xsctp_inpcb));
		if (error) {
			return error;
		}
		SCTP_INP_INFO_RLOCK();
		SCTP_INP_RLOCK(inp);
		/* FIXME MT */
		/*
		 * LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr)
		 * { error = SYSCTL_OUT(req, &xladdr, sizeof(struct
		 * xsctp_laddr)); if (error) { #if
		 * defined(SCTP_PER_SOCKET_LOCKING)
		 * SCTP_SOCKET_UNLOCK(SCTP_INP_SO(inp), 1);
		 * SCTP_UNLOCK_SHARED(sctppcbinfo.ipi_ep_mtx); #endif
		 * SCTP_INP_RUNLOCK(inp); SCTP_INP_INFO_RUNLOCK(); return
		 * error; }			}
		 */
		LIST_FOREACH(stcb, &inp->sctp_asoc_list, sctp_tcblist) {
			SCTP_TCB_LOCK(stcb);
			atomic_add_int(&stcb->asoc.refcnt, 1);
			SCTP_TCB_UNLOCK(stcb);
			number_of_local_addresses = 0;
			number_of_remote_addresses = 0;
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				number_of_remote_addresses++;
			}
			xstcb.LocalPort = ntohs(inp->sctp_lport);
			xstcb.RemPort = ntohs(stcb->rport);
			if (stcb->asoc.primary_destination != NULL)
				xstcb.RemPrimAddr = stcb->asoc.primary_destination->ro._l_addr;
			xstcb.HeartBeatInterval = stcb->asoc.heart_beat_delay;
			xstcb.State = SCTP_GET_STATE(&stcb->asoc);	/* FIXME */
			xstcb.InStreams = stcb->asoc.streamincnt;
			xstcb.OutStreams = stcb->asoc.streamoutcnt;
			xstcb.MaxRetr = stcb->asoc.overall_error_count;
			xstcb.PrimProcess = 0;	/* not really supported yet */
			xstcb.T1expireds = stcb->asoc.timoinit + stcb->asoc.timocookie;
			xstcb.T2expireds = stcb->asoc.timoshutdown + stcb->asoc.timoshutdownack;
			xstcb.RtxChunks = stcb->asoc.marked_retrans;
			xstcb.StartTime = stcb->asoc.start_time;
			xstcb.DiscontinuityTime = stcb->asoc.discontinuity_time;

			xstcb.number_local_addresses = number_of_local_addresses;
			xstcb.number_remote_addresses = number_of_remote_addresses;
			xstcb.total_sends = stcb->total_sends;
			xstcb.total_recvs = stcb->total_recvs;
			xstcb.local_tag = stcb->asoc.my_vtag;
			xstcb.remote_tag = stcb->asoc.peer_vtag;
			xstcb.initial_tsn = stcb->asoc.init_seq_number;
			xstcb.highest_tsn = stcb->asoc.sending_seq - 1;
			xstcb.cumulative_tsn = stcb->asoc.last_acked_seq;
			xstcb.cumulative_tsn_ack = stcb->asoc.cumulative_tsn;
			xstcb.mtu = stcb->asoc.smallest_mtu;
			SCTP_INP_RUNLOCK(inp);
			SCTP_INP_INFO_RUNLOCK();
			error = SYSCTL_OUT(req, &xstcb, sizeof(struct xsctp_tcb));
			if (error) {
				atomic_add_int(&stcb->asoc.refcnt, -1);
				return error;
			}
			TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
				xraddr.RemAddr = net->ro._l_addr;
				xraddr.RemAddrActive = ((net->dest_state & SCTP_ADDR_REACHABLE) == SCTP_ADDR_REACHABLE);
				xraddr.RemAddrConfirmed = ((net->dest_state & SCTP_ADDR_UNCONFIRMED) == 0);
				xraddr.RemAddrHBActive = ((net->dest_state & SCTP_ADDR_NOHB) == 0);
				xraddr.RemAddrRTO = net->RTO;
				xraddr.RemAddrMaxPathRtx = net->failure_threshold;
				xraddr.RemAddrRtx = net->marked_retrans;
				xraddr.RemAddrErrorCounter = net->error_count;
				xraddr.RemAddrCwnd = net->cwnd;
				xraddr.RemAddrFlightSize = net->flight_size;
				xraddr.RemAddrStartTime = net->start_time;
				xraddr.RemAddrMTU = net->mtu;
				error = SYSCTL_OUT(req, &xraddr, sizeof(struct xsctp_raddr));
				if (error) {
					atomic_add_int(&stcb->asoc.refcnt, -1);
					return error;
				}
			}
			atomic_add_int(&stcb->asoc.refcnt, -1);
			SCTP_INP_INFO_RLOCK();
			SCTP_INP_RLOCK(inp);
		}
		SCTP_INP_DECR_REF(inp);
		SCTP_INP_RUNLOCK(inp);
	}
	SCTP_INP_INFO_RUNLOCK();

	xinpcb.last = 1;
	xinpcb.local_port = 0;
	xinpcb.number_local_addresses = 0;
	xinpcb.number_associations = 0;
	xinpcb.flags = 0;
	xinpcb.features = 0;
	error = SYSCTL_OUT(req, &xinpcb, sizeof(struct xsctp_inpcb));
	return error;
}


/*
 * sysctl definitions
 */

SYSCTL_INT(_net_inet_sctp, OID_AUTO, sendspace, CTLFLAG_RW,
    &sctp_sendspace, 0, "Maximum outgoing SCTP buffer size");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, recvspace, CTLFLAG_RW,
    &sctp_recvspace, 0, "Maximum incoming SCTP buffer size");

#if defined(__FreeBSD__) || defined(SCTP_APPLE_AUTO_ASCONF)
SYSCTL_INT(_net_inet_sctp, OID_AUTO, auto_asconf, CTLFLAG_RW,
    &sctp_auto_asconf, 0, "Enable SCTP Auto-ASCONF");
#endif

SYSCTL_INT(_net_inet_sctp, OID_AUTO, ecn_enable, CTLFLAG_RW,
    &sctp_ecn_enable, 0, "Enable SCTP ECN");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, ecn_nonce, CTLFLAG_RW,
    &sctp_ecn_nonce, 0, "Enable SCTP ECN Nonce");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, strict_sacks, CTLFLAG_RW,
    &sctp_strict_sacks, 0, "Enable SCTP Strict SACK checking");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, loopback_nocsum, CTLFLAG_RW,
    &sctp_no_csum_on_loopback, 0,
    "Enable NO Csum on packets sent on loopback");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, strict_init, CTLFLAG_RW,
    &sctp_strict_init, 0,
    "Enable strict INIT/INIT-ACK singleton enforcement");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, peer_chkoh, CTLFLAG_RW,
    &sctp_peer_chunk_oh, 0,
    "Amount to debit peers rwnd per chunk sent");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, maxburst, CTLFLAG_RW,
    &sctp_max_burst_default, 0,
    "Default max burst for sctp endpoints");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, maxchunks, CTLFLAG_RW,
    &sctp_max_chunks_on_queue, 0,
    "Default max chunks on queue per asoc");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, tcbhashsize, CTLFLAG_RW,
    &sctp_hashtblsize, 0,
    "Tuneable for Hash table sizes");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, min_split_point, CTLFLAG_RW,
    &sctp_min_split_point, 0,
    "Minimum size when splitting a chunk");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, pcbhashsize, CTLFLAG_RW,
    &sctp_pcbtblsize, 0,
    "Tuneable for PCB Hash table sizes");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, sys_resource, CTLFLAG_RW,
    &sctp_system_free_resc_limit, 0,
    "Max number of cached resources in the system");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, asoc_resource, CTLFLAG_RW,
    &sctp_asoc_free_resc_limit, 0,
    "Max number of cached resources in an asoc");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, chunkscale, CTLFLAG_RW,
    &sctp_chunkscale, 0,
    "Tuneable for Scaling of number of chunks and messages");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, delayed_sack_time, CTLFLAG_RW,
    &sctp_delayed_sack_time_default, 0,
    "Default delayed SACK timer in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, sack_freq, CTLFLAG_RW,
    &sctp_sack_freq_default, 0,
    "Default SACK frequency");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, heartbeat_interval, CTLFLAG_RW,
    &sctp_heartbeat_interval_default, 0,
    "Default heartbeat interval in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, pmtu_raise_time, CTLFLAG_RW,
    &sctp_pmtu_raise_time_default, 0,
    "Default PMTU raise timer in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, shutdown_guard_time, CTLFLAG_RW,
    &sctp_shutdown_guard_time_default, 0,
    "Default shutdown guard timer in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, secret_lifetime, CTLFLAG_RW,
    &sctp_secret_lifetime_default, 0,
    "Default secret lifetime in sec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, rto_max, CTLFLAG_RW,
    &sctp_rto_max_default, 0,
    "Default maximum retransmission timeout in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, rto_min, CTLFLAG_RW,
    &sctp_rto_min_default, 0,
    "Default minimum retransmission timeout in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, rto_initial, CTLFLAG_RW,
    &sctp_rto_initial_default, 0,
    "Default initial retransmission timeout in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, init_rto_max, CTLFLAG_RW,
    &sctp_init_rto_max_default, 0,
    "Default maximum retransmission timeout during association setup in msec");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, valid_cookie_life, CTLFLAG_RW,
    &sctp_valid_cookie_life_default, 0,
    "Default cookie lifetime in ticks");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, init_rtx_max, CTLFLAG_RW,
    &sctp_init_rtx_max_default, 0,
    "Default maximum number of retransmission for INIT chunks");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, assoc_rtx_max, CTLFLAG_RW,
    &sctp_assoc_rtx_max_default, 0,
    "Default maximum number of retransmissions per association");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, path_rtx_max, CTLFLAG_RW,
    &sctp_path_rtx_max_default, 0,
    "Default maximum of retransmissions per path");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, add_more_on_output, CTLFLAG_RW,
    &sctp_add_more_threshold, 0,
    "When space wise is it worthwhile to try to add more to a socket send buffer");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, outgoing_streams, CTLFLAG_RW,
    &sctp_nr_outgoing_streams_default, 0,
    "Default number of outgoing streams");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, cmt_on_off, CTLFLAG_RW,
    &sctp_cmt_on_off, 0,
    "CMT ON/OFF flag");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, cwnd_maxburst, CTLFLAG_RW,
    &sctp_use_cwnd_based_maxburst, 0,
    "Use a CWND adjusting maxburst");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, early_fast_retran, CTLFLAG_RW,
    &sctp_early_fr, 0,
    "Early Fast Retransmit with timer");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, deadlock_detect, CTLFLAG_RW,
    &sctp_says_check_for_deadlock, 0,
    "SMP Deadlock detection on/off");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, early_fast_retran_msec, CTLFLAG_RW,
    &sctp_early_fr_msec, 0,
    "Early Fast Retransmit minimum timer value");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, asconf_auth_nochk, CTLFLAG_RW,
    &sctp_asconf_auth_nochk, 0,
    "Disable SCTP ASCONF AUTH requirement");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, auth_disable, CTLFLAG_RW,
    &sctp_auth_disable, 0,
    "Disable SCTP AUTH function");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, nat_friendly, CTLFLAG_RW,
    &sctp_nat_friendly, 0,
    "SCTP NAT friendly operation");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, abc_l_var, CTLFLAG_RW,
    &sctp_L2_abc_variable, 0,
    "SCTP ABC max increase per SACK (L)");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, max_chained_mbufs, CTLFLAG_RW,
    &sctp_mbuf_threshold_count, 0,
    "Default max number of small mbufs on a chain");

SYSCTL_UINT(_net_inet_sctp, OID_AUTO, cmt_use_dac, CTLFLAG_RW,
    &sctp_cmt_use_dac, 0,
    "CMT DAC ON/OFF flag");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, do_sctp_drain, CTLFLAG_RW,
    &sctp_do_drain, 0,
    "Should SCTP respond to the drain calls");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, hb_max_burst, CTLFLAG_RW,
    &sctp_hb_maxburst, 0,
    "Confirmation Heartbeat max burst?");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, abort_at_limit, CTLFLAG_RW,
    &sctp_abort_if_one_2_one_hits_limit, 0,
    "When one-2-one hits qlimit abort");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, strict_data_order, CTLFLAG_RW,
    &sctp_strict_data_order, 0,
    "Enforce strict data ordering, abort if control inside data");

SYSCTL_STRUCT(_net_inet_sctp, OID_AUTO, stats, CTLFLAG_RW,
    &sctpstat, sctpstat,
    "SCTP statistics (struct sctps_stat, netinet/sctp.h");

SYSCTL_PROC(_net_inet_sctp, OID_AUTO, assoclist, CTLFLAG_RD,
    0, 0, sctp_assoclist,
    "S,xassoc", "List of active SCTP associations");

SYSCTL_INT(_net_inet_sctp, OID_AUTO, min_residual, CTLFLAG_RW,
    &sctp_min_residual, 0,
    SCTPCTL_MIN_RESIDUAL_DESC);

SYSCTL_INT(_net_inet_sctp, OID_AUTO, max_retran_chunk, CTLFLAG_RW,
    &sctp_max_retran_chunk, 0,
    SCTPCTL_MAX_RETRAN_CHUNK_DESC);

#ifdef SCTP_DEBUG
SYSCTL_INT(_net_inet_sctp, OID_AUTO, debug, CTLFLAG_RW,
    &sctp_debug_on, 0, "Configure debug output");
#endif				/* SCTP_DEBUG */
