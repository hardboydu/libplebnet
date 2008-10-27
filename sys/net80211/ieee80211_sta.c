/*-
 * Copyright (c) 2007-2008 Sam Leffler, Errno Consulting
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifdef __FreeBSD__
__FBSDID("$FreeBSD$");
#endif

/*
 * IEEE 802.11 Station mode support.
 */
#include "opt_inet.h"
#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/systm.h> 
#include <sys/mbuf.h>   
#include <sys/malloc.h>
#include <sys/kernel.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/if_llc.h>
#include <net/ethernet.h>

#include <net/bpf.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_sta.h>
#include <net80211/ieee80211_input.h>

#define	IEEE80211_RATE2MBS(r)	(((r) & IEEE80211_RATE_VAL) / 2)

static	void sta_vattach(struct ieee80211vap *);
static	void sta_beacon_miss(struct ieee80211vap *);
static	int sta_newstate(struct ieee80211vap *, enum ieee80211_state, int);
static	int sta_input(struct ieee80211_node *, struct mbuf *,
	    int rssi, int noise, uint32_t rstamp);
static void sta_recv_mgmt(struct ieee80211_node *, struct mbuf *,
	    int subtype, int rssi, int noise, uint32_t rstamp);

void
ieee80211_sta_attach(struct ieee80211com *ic)
{
	ic->ic_vattach[IEEE80211_M_STA] = sta_vattach;
}

void
ieee80211_sta_detach(struct ieee80211com *ic)
{
}

static void
sta_vdetach(struct ieee80211vap *vap)
{
}

static void
sta_vattach(struct ieee80211vap *vap)
{
	vap->iv_newstate = sta_newstate;
	vap->iv_input = sta_input;
	vap->iv_recv_mgmt = sta_recv_mgmt;
	vap->iv_opdetach = sta_vdetach;
	vap->iv_bmiss = sta_beacon_miss;
}

/*
 * Handle a beacon miss event.  The common code filters out
 * spurious events that can happen when scanning and/or before
 * reaching RUN state.
 */
static void
sta_beacon_miss(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;

	KASSERT((ic->ic_flags & IEEE80211_F_SCAN) == 0, ("scanning"));
	KASSERT(vap->iv_state == IEEE80211_S_RUN,
	    ("wrong state %d", vap->iv_state));

	IEEE80211_DPRINTF(vap,
		IEEE80211_MSG_STATE | IEEE80211_MSG_DEBUG,
		"beacon miss, mode %u state %s\n",
		vap->iv_opmode, ieee80211_state_name[vap->iv_state]);

	if (++vap->iv_bmiss_count < vap->iv_bmiss_max) {
		/*
		 * Send a directed probe req before falling back to a
		 * scan; if we receive a response ic_bmiss_count will
		 * be reset.  Some cards mistakenly report beacon miss
		 * so this avoids the expensive scan if the ap is
		 * still there.
		 */
		ieee80211_send_probereq(vap->iv_bss, vap->iv_myaddr,
			vap->iv_bss->ni_bssid, vap->iv_bss->ni_bssid,
			vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);
		return;
	}
	vap->iv_bmiss_count = 0;
	vap->iv_stats.is_beacon_miss++;
	if (vap->iv_roaming == IEEE80211_ROAMING_AUTO) {
		/*
		 * If we receive a beacon miss interrupt when using
		 * dynamic turbo, attempt to switch modes before
		 * reassociating.
		 */
		if (IEEE80211_ATH_CAP(vap, vap->iv_bss, IEEE80211_NODE_TURBOP))
			ieee80211_dturbo_switch(vap,
			    ic->ic_bsschan->ic_flags ^ IEEE80211_CHAN_TURBO);
		/*
		 * Try to reassociate before scanning for a new ap.
		 */
		ieee80211_new_state(vap, IEEE80211_S_ASSOC, 1);
	} else {
		/*
		 * Somebody else is controlling state changes (e.g.
		 * a user-mode app) don't do anything that would
		 * confuse them; just drop into scan mode so they'll
		 * notified of the state change and given control.
		 */
		ieee80211_new_state(vap, IEEE80211_S_SCAN, 0);
	}
}

/*
 * Handle deauth with reason.  We retry only for
 * the cases where we might succeed.  Otherwise
 * we downgrade the ap and scan.
 */
static void
sta_authretry(struct ieee80211vap *vap, struct ieee80211_node *ni, int reason)
{
	switch (reason) {
	case IEEE80211_STATUS_SUCCESS:		/* NB: MLME assoc */
	case IEEE80211_STATUS_TIMEOUT:
	case IEEE80211_REASON_ASSOC_EXPIRE:
	case IEEE80211_REASON_NOT_AUTHED:
	case IEEE80211_REASON_NOT_ASSOCED:
	case IEEE80211_REASON_ASSOC_LEAVE:
	case IEEE80211_REASON_ASSOC_NOT_AUTHED:
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_AUTH, 1);
		break;
	default:
		ieee80211_scan_assoc_fail(vap, vap->iv_bss->ni_macaddr, reason);
		if (vap->iv_roaming == IEEE80211_ROAMING_AUTO)
			ieee80211_check_scan_current(vap);
		break;
	}
}

/*
 * IEEE80211_M_STA vap state machine handler.
 * This routine handles the main states in the 802.11 protocol.
 */
static int
sta_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni;
	enum ieee80211_state ostate;

	IEEE80211_LOCK_ASSERT(ic);

	ostate = vap->iv_state;
	IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE, "%s: %s -> %s (%d)\n",
	    __func__, ieee80211_state_name[ostate],
	    ieee80211_state_name[nstate], arg);
	vap->iv_state = nstate;			/* state transition */
	callout_stop(&vap->iv_mgtsend);		/* XXX callout_drain */
	if (ostate != IEEE80211_S_SCAN)
		ieee80211_cancel_scan(vap);	/* background scan */
	ni = vap->iv_bss;			/* NB: no reference held */
	if (vap->iv_flags_ext & IEEE80211_FEXT_SWBMISS)
		callout_stop(&vap->iv_swbmiss);
	switch (nstate) {
	case IEEE80211_S_INIT:
		switch (ostate) {
		case IEEE80211_S_SLEEP:
			/* XXX wakeup */
		case IEEE80211_S_RUN:
			IEEE80211_SEND_MGMT(ni,
			    IEEE80211_FC0_SUBTYPE_DISASSOC,
			    IEEE80211_REASON_ASSOC_LEAVE);
			ieee80211_sta_leave(ni);
			break;
		case IEEE80211_S_ASSOC:
			IEEE80211_SEND_MGMT(ni,
			    IEEE80211_FC0_SUBTYPE_DEAUTH,
			    IEEE80211_REASON_AUTH_LEAVE);
			break;
		case IEEE80211_S_SCAN:
			ieee80211_cancel_scan(vap);
			break;
		default:
			goto invalid;
		}
		if (ostate != IEEE80211_S_INIT) {
			/* NB: optimize INIT -> INIT case */
			ieee80211_reset_bss(vap);
		}
		if (vap->iv_auth->ia_detach != NULL)
			vap->iv_auth->ia_detach(vap);
		break;
	case IEEE80211_S_SCAN:
		switch (ostate) {
		case IEEE80211_S_INIT:
			/*
			 * Initiate a scan.  We can come here as a result
			 * of an IEEE80211_IOC_SCAN_REQ too in which case
			 * the vap will be marked with IEEE80211_FEXT_SCANREQ
			 * and the scan request parameters will be present
			 * in iv_scanreq.  Otherwise we do the default.
			 */
			if (vap->iv_flags_ext & IEEE80211_FEXT_SCANREQ) {
				ieee80211_check_scan(vap,
				    vap->iv_scanreq_flags,
				    vap->iv_scanreq_duration,
				    vap->iv_scanreq_mindwell,
				    vap->iv_scanreq_maxdwell,
				    vap->iv_scanreq_nssid, vap->iv_scanreq_ssid);
				vap->iv_flags_ext &= ~IEEE80211_FEXT_SCANREQ;
			} else
				ieee80211_check_scan_current(vap);
			break;
		case IEEE80211_S_SCAN:
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			/*
			 * These can happen either because of a timeout
			 * on an assoc/auth response or because of a
			 * change in state that requires a reset.  For
			 * the former we're called with a non-zero arg
			 * that is the cause for the failure; pass this
			 * to the scan code so it can update state.
			 * Otherwise trigger a new scan unless we're in
			 * manual roaming mode in which case an application
			 * must issue an explicit scan request.
			 */
			if (arg != 0)
				ieee80211_scan_assoc_fail(vap,
					vap->iv_bss->ni_macaddr, arg);
			if (vap->iv_roaming == IEEE80211_ROAMING_AUTO)
				ieee80211_check_scan_current(vap);
			break;
		case IEEE80211_S_RUN:		/* beacon miss */
			/*
			 * Beacon miss.  Notify user space and if not
			 * under control of a user application (roaming
			 * manual) kick off a scan to re-connect.
			 */
			ieee80211_sta_leave(ni);
			if (vap->iv_roaming == IEEE80211_ROAMING_AUTO)
				ieee80211_check_scan_current(vap);
			break;
		default:
			goto invalid;
		}
		break;
	case IEEE80211_S_AUTH:
		switch (ostate) {
		case IEEE80211_S_INIT:
		case IEEE80211_S_SCAN:
			IEEE80211_SEND_MGMT(ni,
			    IEEE80211_FC0_SUBTYPE_AUTH, 1);
			break;
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			switch (arg & 0xff) {
			case IEEE80211_FC0_SUBTYPE_AUTH:
				/* ??? */
				IEEE80211_SEND_MGMT(ni,
				    IEEE80211_FC0_SUBTYPE_AUTH, 2);
				break;
			case IEEE80211_FC0_SUBTYPE_DEAUTH:
				sta_authretry(vap, ni, arg>>8);
				break;
			}
			break;
		case IEEE80211_S_RUN:
			switch (arg & 0xff) {
			case IEEE80211_FC0_SUBTYPE_AUTH:
				IEEE80211_SEND_MGMT(ni,
				    IEEE80211_FC0_SUBTYPE_AUTH, 2);
				vap->iv_state = ostate;	/* stay RUN */
				break;
			case IEEE80211_FC0_SUBTYPE_DEAUTH:
				ieee80211_sta_leave(ni);
				if (vap->iv_roaming == IEEE80211_ROAMING_AUTO) {
					/* try to reauth */
					IEEE80211_SEND_MGMT(ni,
					    IEEE80211_FC0_SUBTYPE_AUTH, 1);
				}
				break;
			}
			break;
		default:
			goto invalid;
		}
		break;
	case IEEE80211_S_ASSOC:
		switch (ostate) {
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			IEEE80211_SEND_MGMT(ni,
			    IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 0);
			break;
		case IEEE80211_S_SLEEP:		/* cannot happen */
		case IEEE80211_S_RUN:
			ieee80211_sta_leave(ni);
			if (vap->iv_roaming == IEEE80211_ROAMING_AUTO) {
				IEEE80211_SEND_MGMT(ni, arg ?
				    IEEE80211_FC0_SUBTYPE_REASSOC_REQ :
				    IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 0);
			}
			break;
		default:
			goto invalid;
		}
		break;
	case IEEE80211_S_RUN:
		if (vap->iv_flags & IEEE80211_F_WPA) {
			/* XXX validate prerequisites */
		}
		switch (ostate) {
		case IEEE80211_S_RUN:
			break;
		case IEEE80211_S_AUTH:		/* when join is done in fw */
		case IEEE80211_S_ASSOC:
#ifdef IEEE80211_DEBUG
			if (ieee80211_msg_debug(vap)) {
				ieee80211_note(vap, "%s with %s ssid ",
				    (vap->iv_opmode == IEEE80211_M_STA ?
				    "associated" : "synchronized"),
				    ether_sprintf(ni->ni_bssid));
				ieee80211_print_essid(vap->iv_bss->ni_essid,
				    ni->ni_esslen);
				/* XXX MCS/HT */
				printf(" channel %d start %uMb\n",
				    ieee80211_chan2ieee(ic, ic->ic_curchan),
				    IEEE80211_RATE2MBS(ni->ni_txrate));
			}
#endif
			ieee80211_scan_assoc_success(vap, ni->ni_macaddr);
			ieee80211_notify_node_join(ni, 
			    arg == IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
			break;
		case IEEE80211_S_SLEEP:
			ieee80211_sta_pwrsave(vap, 0);
			break;
		default:
			goto invalid;
		}
		ieee80211_sync_curchan(ic);
		if (ostate != IEEE80211_S_RUN &&
		    (vap->iv_flags_ext & IEEE80211_FEXT_SWBMISS)) {
			/*
			 * Start s/w beacon miss timer for devices w/o
			 * hardware support.  We fudge a bit here since
			 * we're doing this in software.
			 */
			vap->iv_swbmiss_period = IEEE80211_TU_TO_TICKS(
				2 * vap->iv_bmissthreshold * ni->ni_intval);
			vap->iv_swbmiss_count = 0;
			callout_reset(&vap->iv_swbmiss, vap->iv_swbmiss_period,
				ieee80211_swbmiss, vap);
		}
		/*
		 * When 802.1x is not in use mark the port authorized
		 * at this point so traffic can flow.
		 */
		if (ni->ni_authmode != IEEE80211_AUTH_8021X)
			ieee80211_node_authorize(ni);
		/*
		 * Fake association when joining an existing bss.
		 */
		if (ic->ic_newassoc != NULL)
			ic->ic_newassoc(vap->iv_bss, ostate != IEEE80211_S_RUN);
		break;
	case IEEE80211_S_SLEEP:
		ieee80211_sta_pwrsave(vap, 0);
		break;
	default:
	invalid:
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
		    "%s: unexpected state transition %s -> %s\n", __func__,
		    ieee80211_state_name[ostate], ieee80211_state_name[nstate]);
		break;
	}
	return 0;
}

/*
 * Return non-zero if the frame is an echo of a multicast
 * frame sent by ourself.  The dir is known to be DSTODS.
 */
static __inline int
isdstods_mcastecho(struct ieee80211vap *vap, const struct ieee80211_frame *wh)
{
#define	QWH4(wh)	((const struct ieee80211_qosframe_addr4 *)wh)
#define	WH4(wh)		((const struct ieee80211_frame_addr4 *)wh)
	const uint8_t *sa;

	KASSERT(vap->iv_opmode == IEEE80211_M_STA, ("wrong mode"));

	if (!IEEE80211_IS_MULTICAST(wh->i_addr3))
		return 0;
	sa = IEEE80211_QOS_HAS_SEQ(wh) ? QWH4(wh)->i_addr4 : WH4(wh)->i_addr4;
	return IEEE80211_ADDR_EQ(sa, vap->iv_myaddr);
#undef WH4
#undef QWH4
}

/*
 * Return non-zero if the frame is an echo of a multicast
 * frame sent by ourself.  The dir is known to be FROMDS.
 */
static __inline int
isfromds_mcastecho(struct ieee80211vap *vap, const struct ieee80211_frame *wh)
{
	KASSERT(vap->iv_opmode == IEEE80211_M_STA, ("wrong mode"));

	if (!IEEE80211_IS_MULTICAST(wh->i_addr1))
		return 0;
	return IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_myaddr);
}

/*
 * Decide if a received management frame should be
 * printed when debugging is enabled.  This filters some
 * of the less interesting frames that come frequently
 * (e.g. beacons).
 */
static __inline int
doprint(struct ieee80211vap *vap, int subtype)
{
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_BEACON:
		return (vap->iv_ic->ic_flags & IEEE80211_F_SCAN);
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		return 0;
	}
	return 1;
}

/*
 * Process a received frame.  The node associated with the sender
 * should be supplied.  If nothing was found in the node table then
 * the caller is assumed to supply a reference to iv_bss instead.
 * The RSSI and a timestamp are also supplied.  The RSSI data is used
 * during AP scanning to select a AP to associate with; it can have
 * any units so long as values have consistent units and higher values
 * mean ``better signal''.  The receive timestamp is currently not used
 * by the 802.11 layer.
 */
static int
sta_input(struct ieee80211_node *ni, struct mbuf *m,
	int rssi, int noise, uint32_t rstamp)
{
#define	SEQ_LEQ(a,b)	((int)((a)-(b)) <= 0)
#define	HAS_SEQ(type)	((type & 0x4) == 0)
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	struct ifnet *ifp = vap->iv_ifp;
	struct ieee80211_frame *wh;
	struct ieee80211_key *key;
	struct ether_header *eh;
	int hdrspace, need_tap;
	uint8_t dir, type, subtype, qos;
	uint8_t *bssid;
	uint16_t rxseq;

	if (m->m_flags & M_AMPDU_MPDU) {
		/*
		 * Fastpath for A-MPDU reorder q resubmission.  Frames
		 * w/ M_AMPDU_MPDU marked have already passed through
		 * here but were received out of order and been held on
		 * the reorder queue.  When resubmitted they are marked
		 * with the M_AMPDU_MPDU flag and we can bypass most of
		 * the normal processing.
		 */
		wh = mtod(m, struct ieee80211_frame *);
		type = IEEE80211_FC0_TYPE_DATA;
		dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
		subtype = IEEE80211_FC0_SUBTYPE_QOS;
		hdrspace = ieee80211_hdrspace(ic, wh);	/* XXX optimize? */
		goto resubmit_ampdu;
	}

	KASSERT(ni != NULL, ("null node"));
	ni->ni_inact = ni->ni_inact_reload;

	need_tap = 1;			/* mbuf need to be tapped. */
	type = -1;			/* undefined */

	if (m->m_pkthdr.len < sizeof(struct ieee80211_frame_min)) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_ANY,
		    ni->ni_macaddr, NULL,
		    "too short (1): len %u", m->m_pkthdr.len);
		vap->iv_stats.is_rx_tooshort++;
		goto out;
	}
	/*
	 * Bit of a cheat here, we use a pointer for a 3-address
	 * frame format but don't reference fields past outside
	 * ieee80211_frame_min w/o first validating the data is
	 * present.
	 */
	wh = mtod(m, struct ieee80211_frame *);

	if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) !=
	    IEEE80211_FC0_VERSION_0) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_ANY,
		    ni->ni_macaddr, NULL, "wrong version %x", wh->i_fc[0]);
		vap->iv_stats.is_rx_badversion++;
		goto err;
	}

	dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	if ((ic->ic_flags & IEEE80211_F_SCAN) == 0) {
		bssid = wh->i_addr2;
		if (!IEEE80211_ADDR_EQ(bssid, ni->ni_bssid)) {
			/* not interested in */
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			    bssid, NULL, "%s", "not to bss");
			vap->iv_stats.is_rx_wrongbss++;
			goto out;
		}
		IEEE80211_RSSI_LPF(ni->ni_avgrssi, rssi);
		ni->ni_noise = noise;
		ni->ni_rstamp = rstamp;
		if (HAS_SEQ(type)) {
			uint8_t tid = ieee80211_gettid(wh);
			if (IEEE80211_QOS_HAS_SEQ(wh) &&
			    TID_TO_WME_AC(tid) >= WME_AC_VI)
				ic->ic_wme.wme_hipri_traffic++;
			rxseq = le16toh(*(uint16_t *)wh->i_seq);
			if ((ni->ni_flags & IEEE80211_NODE_HT) == 0 &&
			    (wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
			    SEQ_LEQ(rxseq, ni->ni_rxseqs[tid])) {
				/* duplicate, discard */
				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				    bssid, "duplicate",
				    "seqno <%u,%u> fragno <%u,%u> tid %u",
				    rxseq >> IEEE80211_SEQ_SEQ_SHIFT,
				    ni->ni_rxseqs[tid] >>
					IEEE80211_SEQ_SEQ_SHIFT,
				    rxseq & IEEE80211_SEQ_FRAG_MASK,
				    ni->ni_rxseqs[tid] &
					IEEE80211_SEQ_FRAG_MASK,
				    tid);
				vap->iv_stats.is_rx_dup++;
				IEEE80211_NODE_STAT(ni, rx_dup);
				goto out;
			}
			ni->ni_rxseqs[tid] = rxseq;
		}
	}

	switch (type) {
	case IEEE80211_FC0_TYPE_DATA:
		hdrspace = ieee80211_hdrspace(ic, wh);
		if (m->m_len < hdrspace &&
		    (m = m_pullup(m, hdrspace)) == NULL) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_ANY,
			    ni->ni_macaddr, NULL,
			    "data too short: expecting %u", hdrspace);
			vap->iv_stats.is_rx_tooshort++;
			goto out;		/* XXX */
		}
		/*
		 * Handle A-MPDU re-ordering.  If the frame is to be
		 * processed directly then ieee80211_ampdu_reorder
		 * will return 0; otherwise it has consumed the mbuf
		 * and we should do nothing more with it.
		 */
		if ((m->m_flags & M_AMPDU) &&
		    (dir == IEEE80211_FC1_DIR_FROMDS ||
		     dir == IEEE80211_FC1_DIR_DSTODS) &&
		    ieee80211_ampdu_reorder(ni, m) != 0) {
			m = NULL;
			goto out;
		}
	resubmit_ampdu:
		if (dir == IEEE80211_FC1_DIR_FROMDS) {
			if ((ifp->if_flags & IFF_SIMPLEX) &&
			    isfromds_mcastecho(vap, wh)) {
				/*
				 * In IEEE802.11 network, multicast
				 * packets sent from "me" are broadcast
				 * from the AP; silently discard for
				 * SIMPLEX interface.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				    wh, "data", "%s", "multicast echo");
				vap->iv_stats.is_rx_mcastecho++;
				goto out;
			}
			if ((vap->iv_flags & IEEE80211_F_DWDS) &&
			    IEEE80211_IS_MULTICAST(wh->i_addr1)) {
				/*
				 * DWDS sta's must drop 3-address mcast frames
				 * as they will be sent separately as a 4-addr
				 * frame.  Accepting the 3-addr frame will
				 * confuse the bridge into thinking the sending
				 * sta is located at the end of WDS link.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
				    "3-address data", "%s", "DWDS enabled");
				vap->iv_stats.is_rx_mcastecho++;
				goto out;
			}
		} else if (dir == IEEE80211_FC1_DIR_DSTODS) {
			if ((vap->iv_flags & IEEE80211_F_DWDS) == 0) {
				IEEE80211_DISCARD(vap,
				    IEEE80211_MSG_INPUT, wh, "4-address data",
				    "%s", "DWDS not enabled");
				vap->iv_stats.is_rx_wrongdir++;
				goto out;
			}
			if ((ifp->if_flags & IFF_SIMPLEX) &&
			    isdstods_mcastecho(vap, wh)) {
				/*
				 * In IEEE802.11 network, multicast
				 * packets sent from "me" are broadcast
				 * from the AP; silently discard for
				 * SIMPLEX interface.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
				    "4-address data", "%s", "multicast echo");
				vap->iv_stats.is_rx_mcastecho++;
				goto out;
			}
		} else {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
			    "data", "incorrect dir 0x%x", dir);
			vap->iv_stats.is_rx_wrongdir++;
			goto out;
		}

		/*
		 * Handle privacy requirements.  Note that we
		 * must not be preempted from here until after
		 * we (potentially) call ieee80211_crypto_demic;
		 * otherwise we may violate assumptions in the
		 * crypto cipher modules used to do delayed update
		 * of replay sequence numbers.
		 */
		if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
			if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0) {
				/*
				 * Discard encrypted frames when privacy is off.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				    wh, "WEP", "%s", "PRIVACY off");
				vap->iv_stats.is_rx_noprivacy++;
				IEEE80211_NODE_STAT(ni, rx_noprivacy);
				goto out;
			}
			key = ieee80211_crypto_decap(ni, m, hdrspace);
			if (key == NULL) {
				/* NB: stats+msgs handled in crypto_decap */
				IEEE80211_NODE_STAT(ni, rx_wepfail);
				goto out;
			}
			wh = mtod(m, struct ieee80211_frame *);
			wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
		} else {
			/* XXX M_WEP and IEEE80211_F_PRIVACY */
			key = NULL;
		}

		/*
		 * Save QoS bits for use below--before we strip the header.
		 */
		if (subtype == IEEE80211_FC0_SUBTYPE_QOS) {
			qos = (dir == IEEE80211_FC1_DIR_DSTODS) ?
			    ((struct ieee80211_qosframe_addr4 *)wh)->i_qos[0] :
			    ((struct ieee80211_qosframe *)wh)->i_qos[0];
		} else
			qos = 0;

		/*
		 * Next up, any fragmentation.
		 */
		if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
			m = ieee80211_defrag(ni, m, hdrspace);
			if (m == NULL) {
				/* Fragment dropped or frame not complete yet */
				goto out;
			}
		}
		wh = NULL;		/* no longer valid, catch any uses */

		/*
		 * Next strip any MSDU crypto bits.
		 */
		if (key != NULL && !ieee80211_crypto_demic(vap, key, m, 0)) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			    ni->ni_macaddr, "data", "%s", "demic error");
			vap->iv_stats.is_rx_demicfail++;
			IEEE80211_NODE_STAT(ni, rx_demicfail);
			goto out;
		}

		/* copy to listener after decrypt */
		if (bpf_peers_present(vap->iv_rawbpf))
			bpf_mtap(vap->iv_rawbpf, m);
		need_tap = 0;

		/*
		 * Finally, strip the 802.11 header.
		 */
		m = ieee80211_decap(vap, m, hdrspace);
		if (m == NULL) {
			/* XXX mask bit to check for both */
			/* don't count Null data frames as errors */
			if (subtype == IEEE80211_FC0_SUBTYPE_NODATA ||
			    subtype == IEEE80211_FC0_SUBTYPE_QOS_NULL)
				goto out;
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			    ni->ni_macaddr, "data", "%s", "decap error");
			vap->iv_stats.is_rx_decap++;
			IEEE80211_NODE_STAT(ni, rx_decap);
			goto err;
		}
		eh = mtod(m, struct ether_header *);
		if (!ieee80211_node_is_authorized(ni)) {
			/*
			 * Deny any non-PAE frames received prior to
			 * authorization.  For open/shared-key
			 * authentication the port is mark authorized
			 * after authentication completes.  For 802.1x
			 * the port is not marked authorized by the
			 * authenticator until the handshake has completed.
			 */
			if (eh->ether_type != htons(ETHERTYPE_PAE)) {
				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				    eh->ether_shost, "data",
				    "unauthorized port: ether type 0x%x len %u",
				    eh->ether_type, m->m_pkthdr.len);
				vap->iv_stats.is_rx_unauth++;
				IEEE80211_NODE_STAT(ni, rx_unauth);
				goto err;
			}
		} else {
			/*
			 * When denying unencrypted frames, discard
			 * any non-PAE frames received without encryption.
			 */
			if ((vap->iv_flags & IEEE80211_F_DROPUNENC) &&
			    (key == NULL && (m->m_flags & M_WEP) == 0) &&
			    eh->ether_type != htons(ETHERTYPE_PAE)) {
				/*
				 * Drop unencrypted frames.
				 */
				vap->iv_stats.is_rx_unencrypted++;
				IEEE80211_NODE_STAT(ni, rx_unencrypted);
				goto out;
			}
		}
		/* XXX require HT? */
		if (qos & IEEE80211_QOS_AMSDU) {
			m = ieee80211_decap_amsdu(ni, m);
			if (m == NULL)
				return IEEE80211_FC0_TYPE_DATA;
		} else if ((ni->ni_ath_flags & IEEE80211_NODE_FF) &&
#define	FF_LLC_SIZE	(sizeof(struct ether_header) + sizeof(struct llc))
		    m->m_pkthdr.len >= 3*FF_LLC_SIZE) {
			struct llc *llc;

			/*
			 * Check for fast-frame tunnel encapsulation.
			 */
			if (m->m_len < FF_LLC_SIZE &&
			    (m = m_pullup(m, FF_LLC_SIZE)) == NULL) {
				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_ANY,
				    ni->ni_macaddr, "fast-frame",
				    "%s", "m_pullup(llc) failed");
				vap->iv_stats.is_rx_tooshort++;
				return IEEE80211_FC0_TYPE_DATA;
			}
			llc = (struct llc *)(mtod(m, uint8_t *) + 
				sizeof(struct ether_header));
			if (llc->llc_snap.ether_type == htons(ATH_FF_ETH_TYPE)) {
				m_adj(m, FF_LLC_SIZE);
				m = ieee80211_decap_fastframe(ni, m);
				if (m == NULL)
					return IEEE80211_FC0_TYPE_DATA;
			}
		}
#undef FF_LLC_SIZE
		ieee80211_deliver_data(vap, ni, m);
		return IEEE80211_FC0_TYPE_DATA;

	case IEEE80211_FC0_TYPE_MGT:
		vap->iv_stats.is_rx_mgmt++;
		IEEE80211_NODE_STAT(ni, rx_mgmt);
		if (dir != IEEE80211_FC1_DIR_NODS) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			    wh, "data", "incorrect dir 0x%x", dir);
			vap->iv_stats.is_rx_wrongdir++;
			goto err;
		}
		if (m->m_pkthdr.len < sizeof(struct ieee80211_frame)) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_ANY,
			    ni->ni_macaddr, "mgt", "too short: len %u",
			    m->m_pkthdr.len);
			vap->iv_stats.is_rx_tooshort++;
			goto out;
		}
#ifdef IEEE80211_DEBUG
		if ((ieee80211_msg_debug(vap) && doprint(vap, subtype)) ||
		    ieee80211_msg_dumppkts(vap)) {
			if_printf(ifp, "received %s from %s rssi %d\n",
			    ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
			    ether_sprintf(wh->i_addr2), rssi);
		}
#endif
		if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
			if (subtype != IEEE80211_FC0_SUBTYPE_AUTH) {
				/*
				 * Only shared key auth frames with a challenge
				 * should be encrypted, discard all others.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				    wh, ieee80211_mgt_subtype_name[subtype >>
					IEEE80211_FC0_SUBTYPE_SHIFT],
				    "%s", "WEP set but not permitted");
				vap->iv_stats.is_rx_mgtdiscard++; /* XXX */
				goto out;
			}
			if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0) {
				/*
				 * Discard encrypted frames when privacy is off.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				    wh, "mgt", "%s", "WEP set but PRIVACY off");
				vap->iv_stats.is_rx_noprivacy++;
				goto out;
			}
			hdrspace = ieee80211_hdrspace(ic, wh);
			key = ieee80211_crypto_decap(ni, m, hdrspace);
			if (key == NULL) {
				/* NB: stats+msgs handled in crypto_decap */
				goto out;
			}
			wh = mtod(m, struct ieee80211_frame *);
			wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
		}
		if (bpf_peers_present(vap->iv_rawbpf))
			bpf_mtap(vap->iv_rawbpf, m);
		vap->iv_recv_mgmt(ni, m, subtype, rssi, noise, rstamp);
		m_freem(m);
		return IEEE80211_FC0_TYPE_MGT;

	case IEEE80211_FC0_TYPE_CTL:
		vap->iv_stats.is_rx_ctl++;
		IEEE80211_NODE_STAT(ni, rx_ctrl);
		goto out;
	default:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
		    wh, NULL, "bad frame type 0x%x", type);
		/* should not come here */
		break;
	}
err:
	ifp->if_ierrors++;
out:
	if (m != NULL) {
		if (bpf_peers_present(vap->iv_rawbpf) && need_tap)
			bpf_mtap(vap->iv_rawbpf, m);
		m_freem(m);
	}
	return type;
#undef SEQ_LEQ
}

static void
sta_auth_open(struct ieee80211_node *ni, struct ieee80211_frame *wh,
    int rssi, int noise, uint32_t rstamp, uint16_t seq, uint16_t status)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (ni->ni_authmode == IEEE80211_AUTH_SHARED) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
		    ni->ni_macaddr, "open auth",
		    "bad sta auth mode %u", ni->ni_authmode);
		vap->iv_stats.is_rx_bad_auth++;	/* XXX */
		return;
	}
	if (vap->iv_state != IEEE80211_S_AUTH ||
	    seq != IEEE80211_AUTH_OPEN_RESPONSE) {
		vap->iv_stats.is_rx_bad_auth++;
		return;
	}
	if (status != 0) {
		IEEE80211_NOTE(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH,
		    ni, "open auth failed (reason %d)", status);
		vap->iv_stats.is_rx_auth_fail++;
		vap->iv_stats.is_rx_authfail_code = status;
		ieee80211_new_state(vap, IEEE80211_S_SCAN,
		    IEEE80211_SCAN_FAIL_STATUS);
	} else
		ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
}

static void
sta_auth_shared(struct ieee80211_node *ni, struct ieee80211_frame *wh,
    uint8_t *frm, uint8_t *efrm, int rssi, int noise, uint32_t rstamp,
    uint16_t seq, uint16_t status)
{
	struct ieee80211vap *vap = ni->ni_vap;
	uint8_t *challenge;
	int estatus;

	/*
	 * NB: this can happen as we allow pre-shared key
	 * authentication to be enabled w/o wep being turned
	 * on so that configuration of these can be done
	 * in any order.  It may be better to enforce the
	 * ordering in which case this check would just be
	 * for sanity/consistency.
	 */
	if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
		    ni->ni_macaddr, "shared key auth",
		    "%s", " PRIVACY is disabled");
		estatus = IEEE80211_STATUS_ALG;
		goto bad;
	}
	/*
	 * Pre-shared key authentication is evil; accept
	 * it only if explicitly configured (it is supported
	 * mainly for compatibility with clients like OS X).
	 */
	if (ni->ni_authmode != IEEE80211_AUTH_AUTO &&
	    ni->ni_authmode != IEEE80211_AUTH_SHARED) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
		    ni->ni_macaddr, "shared key auth",
		    "bad sta auth mode %u", ni->ni_authmode);
		vap->iv_stats.is_rx_bad_auth++;	/* XXX maybe a unique error? */
		estatus = IEEE80211_STATUS_ALG;
		goto bad;
	}

	challenge = NULL;
	if (frm + 1 < efrm) {
		if ((frm[1] + 2) > (efrm - frm)) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			    ni->ni_macaddr, "shared key auth",
			    "ie %d/%d too long",
			    frm[0], (frm[1] + 2) - (efrm - frm));
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_CHALLENGE;
			goto bad;
		}
		if (*frm == IEEE80211_ELEMID_CHALLENGE)
			challenge = frm;
		frm += frm[1] + 2;
	}
	switch (seq) {
	case IEEE80211_AUTH_SHARED_CHALLENGE:
	case IEEE80211_AUTH_SHARED_RESPONSE:
		if (challenge == NULL) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			    ni->ni_macaddr, "shared key auth",
			    "%s", "no challenge");
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_CHALLENGE;
			goto bad;
		}
		if (challenge[1] != IEEE80211_CHALLENGE_LEN) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			    ni->ni_macaddr, "shared key auth",
			    "bad challenge len %d", challenge[1]);
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_CHALLENGE;
			goto bad;
		}
	default:
		break;
	}
	if (vap->iv_state != IEEE80211_S_AUTH)
		return;
	switch (seq) {
	case IEEE80211_AUTH_SHARED_PASS:
		if (ni->ni_challenge != NULL) {
			FREE(ni->ni_challenge, M_80211_NODE);
			ni->ni_challenge = NULL;
		}
		if (status != 0) {
			IEEE80211_NOTE_FRAME(vap,
			    IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, wh,
			    "shared key auth failed (reason %d)", status);
			vap->iv_stats.is_rx_auth_fail++;
			vap->iv_stats.is_rx_authfail_code = status;
			return;
		}
		ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
		break;
	case IEEE80211_AUTH_SHARED_CHALLENGE:
		if (!ieee80211_alloc_challenge(ni))
			return;
		/* XXX could optimize by passing recvd challenge */
		memcpy(ni->ni_challenge, &challenge[2], challenge[1]);
		IEEE80211_SEND_MGMT(ni,
			IEEE80211_FC0_SUBTYPE_AUTH, seq + 1);
		break;
	default:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
		    wh, "shared key auth", "bad seq %d", seq);
		vap->iv_stats.is_rx_bad_auth++;
		return;
	}
	return;
bad:
	/*
	 * Kick the state machine.  This short-circuits
	 * using the mgt frame timeout to trigger the
	 * state transition.
	 */
	if (vap->iv_state == IEEE80211_S_AUTH)
		ieee80211_new_state(vap, IEEE80211_S_SCAN,
		    IEEE80211_SCAN_FAIL_STATUS);
}

static int
ieee80211_parse_wmeparams(struct ieee80211vap *vap, uint8_t *frm,
	const struct ieee80211_frame *wh)
{
#define	MS(_v, _f)	(((_v) & _f) >> _f##_S)
	struct ieee80211_wme_state *wme = &vap->iv_ic->ic_wme;
	u_int len = frm[1], qosinfo;
	int i;

	if (len < sizeof(struct ieee80211_wme_param)-2) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WME,
		    wh, "WME", "too short, len %u", len);
		return -1;
	}
	qosinfo = frm[__offsetof(struct ieee80211_wme_param, param_qosInfo)];
	qosinfo &= WME_QOSINFO_COUNT;
	/* XXX do proper check for wraparound */
	if (qosinfo == wme->wme_wmeChanParams.cap_info)
		return 0;
	frm += __offsetof(struct ieee80211_wme_param, params_acParams);
	for (i = 0; i < WME_NUM_AC; i++) {
		struct wmeParams *wmep =
			&wme->wme_wmeChanParams.cap_wmeParams[i];
		/* NB: ACI not used */
		wmep->wmep_acm = MS(frm[0], WME_PARAM_ACM);
		wmep->wmep_aifsn = MS(frm[0], WME_PARAM_AIFSN);
		wmep->wmep_logcwmin = MS(frm[1], WME_PARAM_LOGCWMIN);
		wmep->wmep_logcwmax = MS(frm[1], WME_PARAM_LOGCWMAX);
		wmep->wmep_txopLimit = LE_READ_2(frm+2);
		frm += 4;
	}
	wme->wme_wmeChanParams.cap_info = qosinfo;
	return 1;
#undef MS
}

static int
ieee80211_parse_athparams(struct ieee80211_node *ni, uint8_t *frm,
	const struct ieee80211_frame *wh)
{
	struct ieee80211vap *vap = ni->ni_vap;
	const struct ieee80211_ath_ie *ath;
	u_int len = frm[1];
	int capschanged;
	uint16_t defkeyix;

	if (len < sizeof(struct ieee80211_ath_ie)-2) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_SUPERG,
		    wh, "Atheros", "too short, len %u", len);
		return -1;
	}
	ath = (const struct ieee80211_ath_ie *)frm;
	capschanged = (ni->ni_ath_flags != ath->ath_capability);
	defkeyix = LE_READ_2(ath->ath_defkeyix);
	if (capschanged || defkeyix != ni->ni_ath_defkeyix) {
		ni->ni_ath_flags = ath->ath_capability;
		ni->ni_ath_defkeyix = defkeyix;
		IEEE80211_NOTE(vap, IEEE80211_MSG_SUPERG, ni,
		    "ath ie change: new caps 0x%x defkeyix 0x%x",
		    ni->ni_ath_flags, ni->ni_ath_defkeyix);
	}
	if (IEEE80211_ATH_CAP(vap, ni, ATHEROS_CAP_TURBO_PRIME)) {
		uint16_t curflags, newflags;

		/*
		 * Check for turbo mode switch.  Calculate flags
		 * for the new mode and effect the switch.
		 */
		newflags = curflags = vap->iv_ic->ic_bsschan->ic_flags;
		/* NB: BOOST is not in ic_flags, so get it from the ie */
		if (ath->ath_capability & ATHEROS_CAP_BOOST) 
			newflags |= IEEE80211_CHAN_TURBO;
		else
			newflags &= ~IEEE80211_CHAN_TURBO;
		if (newflags != curflags)
			ieee80211_dturbo_switch(vap, newflags);
	}
	return capschanged;
}

/*
 * Return non-zero if a background scan may be continued:
 * o bg scan is active
 * o no channel switch is pending
 * o there has not been any traffic recently
 *
 * Note we do not check if there is an administrative enable;
 * this is only done to start the scan.  We assume that any
 * change in state will be accompanied by a request to cancel
 * active scans which will otherwise cause this test to fail.
 */
static __inline int
contbgscan(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;

	return ((ic->ic_flags_ext & IEEE80211_FEXT_BGSCAN) &&
	    (ic->ic_flags & IEEE80211_F_CSAPENDING) == 0 &&
	    vap->iv_state == IEEE80211_S_RUN &&		/* XXX? */
	    time_after(ticks, ic->ic_lastdata + vap->iv_bgscanidle));
}

/*
 * Return non-zero if a backgrond scan may be started:
 * o bg scanning is administratively enabled
 * o no channel switch is pending
 * o we are not boosted on a dynamic turbo channel
 * o there has not been a scan recently
 * o there has not been any traffic recently
 */
static __inline int
startbgscan(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;

	return ((vap->iv_flags & IEEE80211_F_BGSCAN) &&
	    (ic->ic_flags & IEEE80211_F_CSAPENDING) == 0 &&
	    !IEEE80211_IS_CHAN_DTURBO(ic->ic_curchan) &&
	    time_after(ticks, ic->ic_lastscan + vap->iv_bgscanintvl) &&
	    time_after(ticks, ic->ic_lastdata + vap->iv_bgscanidle));
}

static void
sta_recv_mgmt(struct ieee80211_node *ni, struct mbuf *m0,
	int subtype, int rssi, int noise, uint32_t rstamp)
{
#define	ISPROBE(_st)	((_st) == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
#define	ISREASSOC(_st)	((_st) == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_frame *wh;
	uint8_t *frm, *efrm;
	uint8_t *rates, *xrates, *wme, *htcap, *htinfo;
	uint8_t rate;

	wh = mtod(m0, struct ieee80211_frame *);
	frm = (uint8_t *)&wh[1];
	efrm = mtod(m0, uint8_t *) + m0->m_len;
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
	case IEEE80211_FC0_SUBTYPE_BEACON: {
		struct ieee80211_scanparams scan;
		/*
		 * We process beacon/probe response frames:
		 *    o when scanning, or
		 *    o station mode when associated (to collect state
		 *      updates such as 802.11g slot time), or
		 * Frames otherwise received are discarded.
		 */ 
		if (!((ic->ic_flags & IEEE80211_F_SCAN) || ni->ni_associd)) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}
		/* XXX probe response in sta mode when !scanning? */
		if (ieee80211_parse_beacon(ni, m0, &scan) != 0)
			return;
		/*
		 * Count frame now that we know it's to be processed.
		 */
		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
			vap->iv_stats.is_rx_beacon++;		/* XXX remove */
			IEEE80211_NODE_STAT(ni, rx_beacons);
		} else
			IEEE80211_NODE_STAT(ni, rx_proberesp);
		/*
		 * When operating in station mode, check for state updates.
		 * Be careful to ignore beacons received while doing a
		 * background scan.  We consider only 11g/WMM stuff right now.
		 */
		if (ni->ni_associd != 0 &&
		    ((ic->ic_flags & IEEE80211_F_SCAN) == 0 ||
		     IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid))) {
			/* record tsf of last beacon */
			memcpy(ni->ni_tstamp.data, scan.tstamp,
				sizeof(ni->ni_tstamp));
			/* count beacon frame for s/w bmiss handling */
			vap->iv_swbmiss_count++;
			vap->iv_bmiss_count = 0;
			if (ni->ni_erp != scan.erp) {
				IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC,
				    wh->i_addr2,
				    "erp change: was 0x%x, now 0x%x",
				    ni->ni_erp, scan.erp);
				if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) &&
				    (ni->ni_erp & IEEE80211_ERP_USE_PROTECTION))
					ic->ic_flags |= IEEE80211_F_USEPROT;
				else
					ic->ic_flags &= ~IEEE80211_F_USEPROT;
				ni->ni_erp = scan.erp;
				/* XXX statistic */
				/* XXX driver notification */
			}
			if ((ni->ni_capinfo ^ scan.capinfo) & IEEE80211_CAPINFO_SHORT_SLOTTIME) {
				IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC,
				    wh->i_addr2,
				    "capabilities change: was 0x%x, now 0x%x",
				    ni->ni_capinfo, scan.capinfo);
				/*
				 * NB: we assume short preamble doesn't
				 *     change dynamically
				 */
				ieee80211_set_shortslottime(ic,
					IEEE80211_IS_CHAN_A(ic->ic_bsschan) ||
					(scan.capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
				ni->ni_capinfo = (ni->ni_capinfo &~ IEEE80211_CAPINFO_SHORT_SLOTTIME)
					       | (scan.capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME);
				/* XXX statistic */
			}
			if (scan.wme != NULL &&
			    (ni->ni_flags & IEEE80211_NODE_QOS) &&
			    ieee80211_parse_wmeparams(vap, scan.wme, wh) > 0)
				ieee80211_wme_updateparams(vap);
			if (scan.ath != NULL)
				ieee80211_parse_athparams(ni, scan.ath, wh);
			if (scan.htcap != NULL && scan.htinfo != NULL &&
			    (vap->iv_flags_ext & IEEE80211_FEXT_HT)) {
				ieee80211_ht_updateparams(ni,
				    scan.htcap, scan.htinfo);
				/* XXX state changes? */
			}
			if (scan.tim != NULL) {
				struct ieee80211_tim_ie *tim =
				    (struct ieee80211_tim_ie *) scan.tim;
#if 0
				int aid = IEEE80211_AID(ni->ni_associd);
				int ix = aid / NBBY;
				int min = tim->tim_bitctl &~ 1;
				int max = tim->tim_len + min - 4;
				if ((tim->tim_bitctl&1) ||
				    (min <= ix && ix <= max &&
				     isset(tim->tim_bitmap - min, aid))) {
					/* 
					 * XXX Do not let bg scan kick off
					 * we are expecting data.
					 */
					ic->ic_lastdata = ticks;
					ieee80211_sta_pwrsave(vap, 0);
				}
#endif
				ni->ni_dtim_count = tim->tim_count;
				ni->ni_dtim_period = tim->tim_period;
			}
			/*
			 * If scanning, pass the info to the scan module.
			 * Otherwise, check if it's the right time to do
			 * a background scan.  Background scanning must
			 * be enabled and we must not be operating in the
			 * turbo phase of dynamic turbo mode.  Then,
			 * it's been a while since the last background
			 * scan and if no data frames have come through
			 * recently, kick off a scan.  Note that this
			 * is the mechanism by which a background scan
			 * is started _and_ continued each time we
			 * return on-channel to receive a beacon from
			 * our ap.
			 */
			if (ic->ic_flags & IEEE80211_F_SCAN) {
				ieee80211_add_scan(vap, &scan, wh,
					subtype, rssi, noise, rstamp);
			} else if (contbgscan(vap)) {
				ieee80211_bg_scan(vap, 0);
			} else if (startbgscan(vap)) {
				vap->iv_stats.is_scan_bg++;
#if 0
				/* wakeup if we are sleeing */
				ieee80211_set_pwrsave(vap, 0);
#endif
				ieee80211_bg_scan(vap, 0);
			}
			return;
		}
		/*
		 * If scanning, just pass information to the scan module.
		 */
		if (ic->ic_flags & IEEE80211_F_SCAN) {
			if (ic->ic_flags_ext & IEEE80211_FEXT_PROBECHAN) {
				/*
				 * Actively scanning a channel marked passive;
				 * send a probe request now that we know there
				 * is 802.11 traffic present.
				 *
				 * XXX check if the beacon we recv'd gives
				 * us what we need and suppress the probe req
				 */
				ieee80211_probe_curchan(vap, 1);
				ic->ic_flags_ext &= ~IEEE80211_FEXT_PROBECHAN;
			}
			ieee80211_add_scan(vap, &scan, wh,
				subtype, rssi, noise, rstamp);
			return;
		}
		break;
	}

	case IEEE80211_FC0_SUBTYPE_AUTH: {
		uint16_t algo, seq, status;
		/*
		 * auth frame format
		 *	[2] algorithm
		 *	[2] sequence
		 *	[2] status
		 *	[tlv*] challenge
		 */
		IEEE80211_VERIFY_LENGTH(efrm - frm, 6, return);
		algo   = le16toh(*(uint16_t *)frm);
		seq    = le16toh(*(uint16_t *)(frm + 2));
		status = le16toh(*(uint16_t *)(frm + 4));
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
		    "recv auth frame with algorithm %d seq %d", algo, seq);

		if (vap->iv_flags & IEEE80211_F_COUNTERM) {
			IEEE80211_DISCARD(vap,
			    IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
			    wh, "auth", "%s", "TKIP countermeasures enabled");
			vap->iv_stats.is_rx_auth_countermeasures++;
			if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
				ieee80211_send_error(ni, wh->i_addr2,
					IEEE80211_FC0_SUBTYPE_AUTH,
					IEEE80211_REASON_MIC_FAILURE);
			}
			return;
		}
		if (algo == IEEE80211_AUTH_ALG_SHARED)
			sta_auth_shared(ni, wh, frm + 6, efrm, rssi,
			    noise, rstamp, seq, status);
		else if (algo == IEEE80211_AUTH_ALG_OPEN)
			sta_auth_open(ni, wh, rssi, noise, rstamp,
			    seq, status);
		else {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
			    wh, "auth", "unsupported alg %d", algo);
			vap->iv_stats.is_rx_auth_unsupported++;
			return;
		} 
		break;
	}

	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
	case IEEE80211_FC0_SUBTYPE_REASSOC_RESP: {
		uint16_t capinfo, associd;
		uint16_t status;

		if (vap->iv_state != IEEE80211_S_ASSOC) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}

		/*
		 * asresp frame format
		 *	[2] capability information
		 *	[2] status
		 *	[2] association ID
		 *	[tlv] supported rates
		 *	[tlv] extended supported rates
		 *	[tlv] WME
		 *	[tlv] HT capabilities
		 *	[tlv] HT info
		 */
		IEEE80211_VERIFY_LENGTH(efrm - frm, 6, return);
		ni = vap->iv_bss;
		capinfo = le16toh(*(uint16_t *)frm);
		frm += 2;
		status = le16toh(*(uint16_t *)frm);
		frm += 2;
		if (status != 0) {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC,
			    wh->i_addr2, "%sassoc failed (reason %d)",
			    ISREASSOC(subtype) ?  "re" : "", status);
			vap->iv_stats.is_rx_auth_fail++;	/* XXX */
			return;
		}
		associd = le16toh(*(uint16_t *)frm);
		frm += 2;

		rates = xrates = wme = htcap = htinfo = NULL;
		while (efrm - frm > 1) {
			IEEE80211_VERIFY_LENGTH(efrm - frm, frm[1] + 2, return);
			switch (*frm) {
			case IEEE80211_ELEMID_RATES:
				rates = frm;
				break;
			case IEEE80211_ELEMID_XRATES:
				xrates = frm;
				break;
			case IEEE80211_ELEMID_HTCAP:
				htcap = frm;
				break;
			case IEEE80211_ELEMID_HTINFO:
				htinfo = frm;
				break;
			case IEEE80211_ELEMID_VENDOR:
				if (iswmeoui(frm))
					wme = frm;
				else if (vap->iv_flags_ext & IEEE80211_FEXT_HTCOMPAT) {
					/*
					 * Accept pre-draft HT ie's if the
					 * standard ones have not been seen.
					 */
					if (ishtcapoui(frm)) {
						if (htcap == NULL)
							htcap = frm;
					} else if (ishtinfooui(frm)) {
						if (htinfo == NULL)
							htcap = frm;
					}
				}
				/* XXX Atheros OUI support */
				break;
			}
			frm += frm[1] + 2;
		}

		IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE, return);
		if (xrates != NULL)
			IEEE80211_VERIFY_ELEMENT(xrates,
				IEEE80211_RATE_MAXSIZE - rates[1], return);
		rate = ieee80211_setup_rates(ni, rates, xrates,
				IEEE80211_F_JOIN |
				IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
				IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
		if (rate & IEEE80211_RATE_BASIC) {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC,
			    wh->i_addr2,
			    "%sassoc failed (rate set mismatch)",
			    ISREASSOC(subtype) ?  "re" : "");
			vap->iv_stats.is_rx_assoc_norate++;
			ieee80211_new_state(vap, IEEE80211_S_SCAN,
			    IEEE80211_SCAN_FAIL_STATUS);
			return;
		}

		ni->ni_capinfo = capinfo;
		ni->ni_associd = associd;
		if (ni->ni_jointime == 0)
			ni->ni_jointime = time_uptime;
		if (wme != NULL &&
		    ieee80211_parse_wmeparams(vap, wme, wh) >= 0) {
			ni->ni_flags |= IEEE80211_NODE_QOS;
			ieee80211_wme_updateparams(vap);
		} else
			ni->ni_flags &= ~IEEE80211_NODE_QOS;
		/*
		 * Setup HT state according to the negotiation.
		 *
		 * NB: shouldn't need to check if HT use is enabled but some
		 *     ap's send back HT ie's even when we don't indicate we
		 *     are HT capable in our AssocReq.
		 */
		if (htcap != NULL && htinfo != NULL &&
		    (vap->iv_flags_ext & IEEE80211_FEXT_HT)) {
			ieee80211_ht_node_init(ni);
			ieee80211_ht_updateparams(ni, htcap, htinfo);
			ieee80211_setup_htrates(ni, htcap,
			     IEEE80211_F_JOIN | IEEE80211_F_DOBRS);
			ieee80211_setup_basic_htrates(ni, htinfo);
		}
		/*
		 * Configure state now that we are associated.
		 *
		 * XXX may need different/additional driver callbacks?
		 */
		if (IEEE80211_IS_CHAN_A(ic->ic_curchan) ||
		    (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
			ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
			ic->ic_flags &= ~IEEE80211_F_USEBARKER;
		} else {
			ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;
			ic->ic_flags |= IEEE80211_F_USEBARKER;
		}
		ieee80211_set_shortslottime(ic,
			IEEE80211_IS_CHAN_A(ic->ic_curchan) ||
			(ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
		/*
		 * Honor ERP protection.
		 *
		 * NB: ni_erp should zero for non-11g operation.
		 */
		if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) &&
		    (ni->ni_erp & IEEE80211_ERP_USE_PROTECTION))
			ic->ic_flags |= IEEE80211_F_USEPROT;
		else
			ic->ic_flags &= ~IEEE80211_F_USEPROT;
		IEEE80211_NOTE_MAC(vap,
		    IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG, wh->i_addr2,
		    "%sassoc success at aid %d: %s preamble, %s slot time%s%s%s%s%s%s%s%s",
		    ISREASSOC(subtype) ? "re" : "",
		    IEEE80211_NODE_AID(ni),
		    ic->ic_flags&IEEE80211_F_SHPREAMBLE ? "short" : "long",
		    ic->ic_flags&IEEE80211_F_SHSLOT ? "short" : "long",
		    ic->ic_flags&IEEE80211_F_USEPROT ? ", protection" : "",
		    ni->ni_flags & IEEE80211_NODE_QOS ? ", QoS" : "",
		    ni->ni_flags & IEEE80211_NODE_HT ?
			(ni->ni_chw == 40 ? ", HT40" : ", HT20") : "",
		    ni->ni_flags & IEEE80211_NODE_AMPDU ? " (+AMPDU)" : "",
		    ni->ni_flags & IEEE80211_NODE_MIMO_RTS ? " (+SMPS-DYN)" :
			ni->ni_flags & IEEE80211_NODE_MIMO_PS ? " (+SMPS)" : "",
		    ni->ni_flags & IEEE80211_NODE_RIFS ? " (+RIFS)" : "",
		    IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_FF) ?
			", fast-frames" : "",
		    IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_TURBOP) ?
			", turbo" : ""
		);
		ieee80211_new_state(vap, IEEE80211_S_RUN, subtype);
		break;
	}

	case IEEE80211_FC0_SUBTYPE_DEAUTH: {
		uint16_t reason;

		if (vap->iv_state == IEEE80211_S_SCAN) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}
		if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
			/* NB: can happen when in promiscuous mode */
			vap->iv_stats.is_rx_mgtdiscard++;
			break;
		}

		/*
		 * deauth frame format
		 *	[2] reason
		 */
		IEEE80211_VERIFY_LENGTH(efrm - frm, 2, return);
		reason = le16toh(*(uint16_t *)frm);

		vap->iv_stats.is_rx_deauth++;
		vap->iv_stats.is_rx_deauth_code = reason;
		IEEE80211_NODE_STAT(ni, rx_deauth);

		IEEE80211_NOTE(vap, IEEE80211_MSG_AUTH, ni,
		    "recv deauthenticate (reason %d)", reason);
		ieee80211_new_state(vap, IEEE80211_S_AUTH,
		    (reason << 8) | IEEE80211_FC0_SUBTYPE_DEAUTH);
		break;
	}

	case IEEE80211_FC0_SUBTYPE_DISASSOC: {
		uint16_t reason;

		if (vap->iv_state != IEEE80211_S_RUN &&
		    vap->iv_state != IEEE80211_S_ASSOC &&
		    vap->iv_state != IEEE80211_S_AUTH) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}
		if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
			/* NB: can happen when in promiscuous mode */
			vap->iv_stats.is_rx_mgtdiscard++;
			break;
		}

		/*
		 * disassoc frame format
		 *	[2] reason
		 */
		IEEE80211_VERIFY_LENGTH(efrm - frm, 2, return);
		reason = le16toh(*(uint16_t *)frm);

		vap->iv_stats.is_rx_disassoc++;
		vap->iv_stats.is_rx_disassoc_code = reason;
		IEEE80211_NODE_STAT(ni, rx_disassoc);

		IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
		    "recv disassociate (reason %d)", reason);
		ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
		break;
	}

	case IEEE80211_FC0_SUBTYPE_ACTION:
		if (vap->iv_state == IEEE80211_S_RUN) {
			if (ieee80211_parse_action(ni, m0) == 0)
				ic->ic_recv_action(ni, frm, efrm);
		} else
			vap->iv_stats.is_rx_mgtdiscard++;
		break;

	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
	case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	default:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
		     wh, "mgt", "subtype 0x%x not handled", subtype);
		vap->iv_stats.is_rx_badsubtype++;
		break;
	}
#undef ISREASSOC
#undef ISPROBE
}
