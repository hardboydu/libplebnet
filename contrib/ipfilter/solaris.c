/*
 * Copyright (C) 1993-1998 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 */
/* #pragma ident   "@(#)solaris.c	1.12 6/5/96 (C) 1995 Darren Reed"*/
#pragma ident "@(#)$Id: solaris.c,v 2.1.2.5 1999/10/15 13:49:44 darrenr Exp $";

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/stream.h>
#include <sys/poll.h>
#include <sys/autoconf.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/af.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/tcpip.h>
#include <netinet/ip_icmp.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include "ip_compat.h"
#include "ipl.h"
#include "ip_fil.h"
#include "ip_nat.h"


char	_depends_on[] = "drv/ip";


void	solipdrvattach __P((void));
int	solipdrvdetach __P((void));

void	solattach __P((void));
int	soldetach __P((void));

extern	struct	filterstats	frstats[];
extern	KRWLOCK_T	ipf_mutex, ipfs_mutex, ipf_nat, ipf_solaris;
extern	kmutex_t	ipf_rw;
extern	int	fr_running;
extern	int	fr_flags;

extern ipnat_t *nat_list;

static	qif_t	*qif_head = NULL;
static	int	ipf_getinfo __P((dev_info_t *, ddi_info_cmd_t,
				 void *, void **));
static	int	ipf_probe __P((dev_info_t *));
static	int	ipf_identify __P((dev_info_t *));
static	int	ipf_attach __P((dev_info_t *, ddi_attach_cmd_t));
static	int	ipf_detach __P((dev_info_t *, ddi_detach_cmd_t));
static	qif_t	*qif_from_queue __P((queue_t *));
static	void	fr_donotip __P((int, qif_t *, queue_t *, mblk_t *,
				mblk_t *, ip_t *, size_t));
static	char	*ipf_devfiles[] = { IPL_NAME, IPL_NAT, IPL_STATE, IPL_AUTH,
				    NULL };
static	int	(*ipf_ip_inp) __P((queue_t *, mblk_t *)) = NULL;


#if SOLARIS2 >= 7
extern	void	ipfr_slowtimer __P((void *));
timeout_id_t	ipfr_timer_id;
static	timeout_id_t	synctimeoutid = 0;
#else
extern	void	ipfr_slowtimer __P((void));
int	ipfr_timer_id;
static	int	synctimeoutid = 0;
#endif

#ifdef	IPFDEBUG
void	printire __P((ire_t *));
#endif
static int	fr_precheck __P((mblk_t **, queue_t *, qif_t *, int));


static struct cb_ops ipf_cb_ops = {
	iplopen,
	iplclose,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	iplread,
	nodev,		/* write */
	iplioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_MTSAFE,
#if SOLARIS2 > 4
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
#endif
};

static struct dev_ops ipf_ops = {
	DEVO_REV,
	0,
	ipf_getinfo,
	ipf_identify,
	ipf_probe,
	ipf_attach,
	ipf_detach,
	nodev,		/* reset */
	&ipf_cb_ops,
	(struct bus_ops *)0
};

extern struct mod_ops mod_driverops;
static struct modldrv iplmod = {
	&mod_driverops, IPL_VERSION, &ipf_ops };
static struct modlinkage modlink1 = { MODREV_1, &iplmod, NULL };


static dev_info_t *ipf_dev_info = NULL;


int _init()
{
	int ipfinst;

	if (fr_running < 0)
		return -1;
	ipfinst = mod_install(&modlink1);
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: _init() = %d\n", ipfinst);
#endif
	return ipfinst;
}


int _fini(void)
{
	int ipfinst;

	if (fr_running < 0)
		return -1;
	ipfinst = mod_remove(&modlink1);
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: _fini() = %d\n", ipfinst);
#endif
	return ipfinst;
}


int _info(modinfop)
struct modinfo *modinfop;
{
	int ipfinst;

	if (fr_running < 0)
		return -1;
	ipfinst = mod_info(&modlink1, modinfop);
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: _info(%x) = %x\n", modinfop, ipfinst);
#endif
	if (fr_running > 0)
		ipfsync();
	return ipfinst;
}


static int ipf_probe(dip)
dev_info_t *dip;
{
	if (fr_running < 0)
		return DDI_PROBE_FAILURE;
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_probe(%x)", dip);
#endif
	return DDI_PROBE_SUCCESS;
}


static int ipf_identify(dip)
dev_info_t *dip;
{
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_identify(%x)", dip);
#endif
	if (strcmp(ddi_get_name(dip), "ipf") == 0)
		return (DDI_IDENTIFIED);
	return (DDI_NOT_IDENTIFIED);
}


static int ipf_attach(dip, cmd)
dev_info_t *dip;
ddi_attach_cmd_t cmd;
{
#ifdef	IPFDEBUG
	int instance;

	cmn_err(CE_NOTE, "IP Filter: ipf_attach(%x,%x)", dip, cmd);
#endif
	switch (cmd) {
	case DDI_ATTACH:
		if (fr_running < 0)
			break;
#ifdef	IPFDEBUG
		instance = ddi_get_instance(dip);

		cmn_err(CE_NOTE, "IP Filter: attach ipf instance %d", instance);
#endif
		if (ddi_create_minor_node(dip, "ipf", S_IFCHR, IPL_LOGIPF,
					  DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			goto attach_failed;
		}
		if (ddi_create_minor_node(dip, "ipnat", S_IFCHR, IPL_LOGNAT,
					  DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			goto attach_failed;
		}
		if (ddi_create_minor_node(dip, "ipstate", S_IFCHR,IPL_LOGSTATE,
					  DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			goto attach_failed;
		}
		if (ddi_create_minor_node(dip, "ipauth", S_IFCHR, IPL_LOGAUTH,
					  DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			goto attach_failed;
		}
		ipf_dev_info = dip;
		sync();
		/*
		 * Initialize mutex's
		 */
		if (iplattach() == -1)
			goto attach_failed;
		/*
		 * Lock people out while we set things up.
		 */
		WRITE_ENTER(&ipf_solaris);
		solattach();
		solipdrvattach();
		RWLOCK_EXIT(&ipf_solaris);
		cmn_err(CE_CONT, "%s, attaching complete.\n", ipfilter_version);
		sync();
		if (fr_running == 0)
			fr_running = 1;
		if (ipfr_timer_id == 0)
			ipfr_timer_id = timeout(ipfr_slowtimer, NULL,
						drv_usectohz(500000));
		if (fr_running == 1)
			return DDI_SUCCESS;
	default:
		return DDI_FAILURE;
	}

attach_failed:
	cmn_err(CE_NOTE, "IP Filter: failed to attach\n");
	/*
	 * Use our own detach routine to toss
	 * away any stuff we allocated above.
	 */
	(void) ipf_detach(dip, DDI_DETACH);
	return DDI_FAILURE;
}


static int ipf_detach(dip, cmd)
dev_info_t *dip;
ddi_detach_cmd_t cmd;
{
	int i;

#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_detach(%x,%x)", dip, cmd);
#endif
	switch (cmd) {
	case DDI_DETACH:
		if (fr_running <= 0)
			break;
		/*
		 * Make sure we're the only one's modifying things.  With
		 * this lock others should just fall out of the loop.
		 */
		mutex_enter(&ipf_rw);
		if (ipfr_timer_id != 0) {
			untimeout(ipfr_timer_id);
			ipfr_timer_id = 0;
		}
		mutex_exit(&ipf_rw);
		WRITE_ENTER(&ipf_solaris);
		mutex_enter(&ipf_rw);
		if (fr_running <= 0) {
			mutex_exit(&ipf_rw);
			return DDI_FAILURE;
		}
		fr_running = -1;
		mutex_exit(&ipf_rw);
		/* NOTE: ipf_solaris rwlock is released in ipldetach */

		/*
		 * Undo what we did in ipf_attach, freeing resources
		 * and removing things we installed.  The system
		 * framework guarantees we are not active with this devinfo
		 * node in any other entry points at this time.
		 */
		ddi_prop_remove_all(dip);
		i = ddi_get_instance(dip);
		ddi_remove_minor_node(dip, NULL);
		sync();
		i = solipdrvdetach();
		if (i > 0) {
			cmn_err(CE_CONT, "IP Filter: still attached (%d)\n", i);
			return DDI_FAILURE;
		}
		if (!soldetach()) {
			cmn_err(CE_CONT, "IP Filter: detached\n");
			return (DDI_SUCCESS);
		}
	default:
		return (DDI_FAILURE);
	}
	return DDI_FAILURE;
}


static int ipf_getinfo(dip, infocmd, arg, result)
dev_info_t *dip;
ddi_info_cmd_t infocmd;
void *arg, **result;
{
	int error;

	if (fr_running <= 0)
		return DDI_FAILURE;
	error = DDI_FAILURE;
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_getinfo(%x,%x,%x)", dip, infocmd, arg);
#endif
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = ipf_dev_info;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)getminor((dev_t) arg);
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (error);
}

/*
 * find the filter structure setup for this queue
 */
static qif_t *qif_from_queue(q)
queue_t *q;
{
	qif_t *qif;

	for (qif = qif_head; qif; qif = qif->qf_next)
		if ((qif->qf_iptr == q->q_ptr) || (qif->qf_optr == q->q_ptr))
			break;
	return qif;
}


/*
 * OK, this is pretty scrappy code, but then it's essentially just here for
 * debug purposes and that's it.  Packets should not normally come through
 * here, and if they do, well, we would like to see as much information as
 * possible about them and what they claim to hold.
 */
void fr_donotip(out, qif, q, m, mt, ip, off)
int out;
qif_t *qif;
queue_t *q;
mblk_t *m, *mt;
ip_t *ip;
size_t off;
{
	u_char *s, outb[256], *t;
	int i;

	outb[0] = '\0';
	outb[1] = '\0';
	outb[2] = '\0';
	outb[3] = '\0';
	s = ip ? (u_char *)ip : outb;
	if (!ip && (m == mt) && m->b_cont && (MTYPE(m) != M_DATA))
		m = m->b_cont;

	printf("!IP %s:%d %d %p %p %p %d %p/%d %p/%d %p %d %d %p\n",
		qif ? qif->qf_name : "?", out, qif->qf_hl, q,
		q ? q->q_ptr : NULL, q ? q->q_qinfo : NULL,
		mt->b_wptr - mt->b_rptr, m, MTYPE(m), mt, MTYPE(mt), m->b_rptr,
		m->b_wptr - m->b_rptr, off, ip);
	printf("%02x%02x%02x%02x\n", *s, *(s+1), *(s+2), *(s+3));
	while (m != mt) {
		i = 0;
		t = outb;
		s = mt->b_rptr;
		sprintf((char *)t, "%d:", MTYPE(mt));
		t += strlen((char *)t);
		for (; (i < 100) && (s < mt->b_wptr); i++) {
			sprintf((char *)t, "%02x%s", *s++,
				((i & 3) == 3) ? " " : "");
			t += ((i & 3) == 3) ? 3 : 2;
		}
		*t++ = '\n';
		*t = '\0';
		printf("%s", outb);
		mt = mt->b_cont;
	}
	i = 0;
	t = outb;
	s = m->b_rptr;
	sprintf((char *)t, "%d:", MTYPE(m));
	t += strlen((char *)t);
	for (; (i < 100) && (s < m->b_wptr); i++) {
		sprintf((char *)t, "%02x%s", *s++, ((i & 3) == 3) ? " " : "");
		t += ((i & 3) == 3) ? 3 : 2;
	}
	*t++ = '\n';
	*t = '\0';
	printf("%s", outb);
}


/*
 * find the first data mblk, if present, in the chain we're processing.  Also
 * make a few sanity checks to try prevent the filter from causing a panic -
 * none of the nice IP sanity checks (including checksumming) should have been
 * done yet (for incoming packets) - dangerous!
 */
static int fr_precheck(mp, q, qif, out)
mblk_t **mp;
queue_t *q;
qif_t *qif;
int out;
{
	register mblk_t *m, *mt = *mp;
	register ip_t *ip;
	size_t hlen, len, off, mlen, iphlen;
	int err, synced = 0;
	u_char *bp;
#ifndef	sparc
	u_short __iplen, __ipoff;
#endif
tryagain:
	/*
	 * If there is only M_DATA for a packet going out, then any header
	 * information (which would otherwise appear in an M_PROTO mblk before
	 * the M_DATA) is prepended before the IP header.  We need to set the
	 * offset to account for this. - see MMM
	 */
	off = (out) ? qif->qf_hl : 0;

	/*
	 * If the message protocol block indicates that there isn't a data
	 * block following it, just return back.
	 */
	bp = (u_char *)ALIGN32(mt->b_rptr);
	if (MTYPE(mt) == M_PROTO || MTYPE(mt) == M_PCPROTO) {
		dl_unitdata_ind_t *dl = (dl_unitdata_ind_t *)bp;
		if (dl->dl_primitive != DL_UNITDATA_IND &&
		    dl->dl_primitive != DL_UNITDATA_REQ) {
			frstats[out].fr_notdata++;
			return 0;
		}
	}

	/*
	 * Find the first data block, count the data blocks in this chain and
	 * the total amount of data.
	 */
	for (m = mt; m && (MTYPE(m) != M_DATA); m = m->b_cont)
		off = 0;	/* Any non-M_DATA cancels the offset */

	if (!m) {
		frstats[out].fr_nodata++;
		return 0;	/* No data blocks */
	}

	/*
	 * This is a complete kludge to try and work around some bizarre
	 * packets which drop through into fr_donotip.
	 */
	if ((mt != m) && (MTYPE(mt) == M_PROTO || MTYPE(mt) == M_PCPROTO)) {
		dl_unitdata_ind_t *dl = (dl_unitdata_ind_t *)bp;
		if ((dl->dl_primitive == DL_UNITDATA_IND) &&
		    (dl->dl_group_address == 1))
			if (((*((u_char *)m->b_rptr) == 0x0) &&
			    ((*((u_char *)m->b_rptr + 2) == 0x45))))
				off += 2;
	}

	ip = (ip_t *)(m->b_rptr + off);		/* MMM */

	/*
	 * We might have a 1st data block which is really M_PROTO, i.e. it is
	 * only big enough for the link layer header
	 */
	while ((u_char *)ip >= m->b_wptr) {
		len = (u_char *)ip - m->b_wptr;
		m = m->b_cont;
		if (m == NULL)
			return 0;	/* not enough data for IP */
		ip = (ip_t *)(m->b_rptr + len);
	}
	off = (u_char *)ip - m->b_rptr;
	if (off != 0)
		m->b_rptr = (u_char *)ip;
	mlen = msgdsize(m);

	len = m->b_wptr - m->b_rptr;
	if (m->b_wptr < m->b_rptr) {
		cmn_err(CE_NOTE, "IP Filter: Bad packet: wptr %p < rptr %p",
			m->b_wptr, m->b_rptr);
		frstats[out].fr_bad++;
		return -1;
	}
	/*
	 * Ok, the IP header isn't on a 32bit aligned address so junk it.
	 */
	if (((u_int)ip & 0x3) || (len < sizeof(*ip))) {
		/*
		 * We have link layer header and IP header in the same mbuf,
		 * problem being that a pullup without adjusting b_rptr will
		 * bring us back here again as it's likely that the start of
		 * the databuffer (b_datab->db_base) is already aligned.  Hmm,
		 * should we pull it all up (length of -1 to pullupmsg) if we
		 * can, now ?
		 */
fixalign:
		if (off == (u_char *)ip - m->b_rptr) {
			m->b_rptr += off;
			off = 0;
		}
		if (!pullupmsg(m, sizeof(ip_t) + off)) {
			cmn_err(CE_NOTE, "pullupmsg failed\n");
			frstats[out].fr_pull[1]++;
			return -1;
		}
		frstats[out].fr_pull[0]++;
		synced = 1;
		off = 0;
		goto tryagain;

	}
	if (ip->ip_v != IPVERSION) {
		m->b_rptr -= off;
		if (!synced) {
			synced = 1;
			RWLOCK_EXIT(&ipfs_mutex);
			ipfsync();
			READ_ENTER(&ipfs_mutex);
			goto tryagain;
		}
		fr_donotip(out, qif, q, m, mt, ip, off);
		frstats[out].fr_notip++;
		return (fr_flags & FF_BLOCKNONIP) ? -1 : 0;
	}

#ifndef	sparc
	__iplen = (u_short)ip->ip_len,
	__ipoff = (u_short)ip->ip_off;

	ip->ip_len = ntohs(__iplen);
	ip->ip_off = ntohs(__ipoff);
#endif

	hlen = iphlen = ip->ip_hl << 2;

	if ((iphlen < sizeof(ip_t)) || (iphlen > (u_short)ip->ip_len) ||
	    (mlen < (u_short)ip->ip_len)) {
		/*
		 * Bad IP packet or not enough data/data length mismatches
		 */
		cmn_err(CE_NOTE,
			"IP Filter: Bad packet: iphlen %u ip_len %u mlen %u",
			iphlen, ip->ip_len, mlen);
#ifndef	sparc
		__iplen = (u_short)ip->ip_len,
		__ipoff = (u_short)ip->ip_off;

		ip->ip_len = htons(__iplen);
		ip->ip_off = htons(__ipoff);
#endif
		m->b_rptr -= off;
		frstats[out].fr_bad++;
		return -1;
	}

	/*
	 * Make hlen the total size of the IP header plus TCP/UDP/ICMP header
	 * (if it is one of these three).
	 */
	if ((ip->ip_off & IP_OFFMASK) == 0)
		switch (ip->ip_p)
		{
		case IPPROTO_TCP :
			hlen += sizeof(tcphdr_t);
			break;
		case IPPROTO_UDP :
			hlen += sizeof(udphdr_t);
			break;
		case IPPROTO_ICMP :
			/* 76 bytes is enough for a complete ICMP error. */
			hlen += 76 + sizeof(icmphdr_t);
			break;
		default :
			break;
		}

	if (hlen > mlen)
		hlen = mlen;

	/*
	 * If we don't have enough data in the mblk or we haven't yet copied
	 * enough (above), then copy some more.
	 */
	if ((hlen > len)) {
		if (!pullupmsg(m, (int)hlen)) {
			cmn_err(CE_NOTE, "pullupmsg failed\n");
			frstats[out].fr_pull[1]++;
			return -1;
		}
		frstats[out].fr_pull[0]++;
		ip = (ip_t *)ALIGN32(m->b_rptr);
	}
	qif->qf_m = m;
	qif->qf_q = q;
	qif->qf_off = off;
	qif->qf_len = len;
	err = fr_check(ip, iphlen, qif->qf_ill, out, qif, mp);
	if (err == 2)
		goto fixalign;
	/*
	 * Copy back the ip header data if it was changed, we haven't yet
	 * freed the message and we aren't going to drop the packet.
	 * BUT only do this if there were no changes to the buffer, else
	 * we can't be sure that the ip pointer is still correct!
	 */
	if (*mp != NULL) {
		if (*mp == mt) {
			m->b_rptr -= off;
#ifndef	sparc
			__iplen = (u_short)ip->ip_len,
			__ipoff = (u_short)ip->ip_off;

			ip->ip_len = htons(__iplen);
			ip->ip_off = htons(__ipoff);
#endif
		} else
			cmn_err(CE_NOTE,
				"IP Filter: *mp %p mt %p %s\n", *mp, mt,
				"mblk changed, cannot revert ip_len, ip_off");
	}
	return err;
}


int fr_qin(q, mb)
queue_t *q;
mblk_t *mb;
{
	int (*pnext) __P((queue_t *, mblk_t *)), type, synced = 0, err = 0;
	qif_t qf, *qif;

	if (fr_running <= 0) {
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}

	READ_ENTER(&ipf_solaris);
again:
	if (fr_running <= 0) {
		RWLOCK_EXIT(&ipf_solaris);
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}
	READ_ENTER(&ipfs_mutex);
	if (!(qif = qif_from_queue(q))) {
		for (qif = qif_head; qif; qif = qif->qf_next)
			if (&qif->qf_rqinit == q->q_qinfo && qif->qf_rqinfo &&
					qif->qf_rqinfo->qi_putp) {
				pnext = qif->qf_rqinfo->qi_putp;
				frstats[0].fr_notip++;
				RWLOCK_EXIT(&ipfs_mutex);
				if (!synced) {
					ipfsync();
					synced = 1;
					goto again;
				}
				RWLOCK_EXIT(&ipf_solaris);
				/* fr_donotip(0, NULL, q, mb, mb, NULL, 0); */
				return (*pnext)(q, mb);
			}
		RWLOCK_EXIT(&ipfs_mutex);
		if (!synced) {
			ipfsync();
			synced = 1;
			goto again;
		}
		cmn_err(CE_WARN,
			"IP Filter: dropped: fr_qin(%x,%x): type %x qif %x",
			q, mb, MTYPE(mb), qif);
		cmn_err(CE_CONT,
			"IP Filter: info %x next %x ptr %x fsrv %x bsrv %x\n",
			q->q_qinfo, q->q_next, q->q_ptr, q->q_nfsrv,
			q->q_nbsrv);
		cmn_err(CE_CONT, "IP Filter: info: putp %x srvp %x info %x\n",
			q->q_qinfo->qi_putp, q->q_qinfo->qi_srvp,
#if SOLARIS > 3
			q->q_qinfo->qi_infop
#else
			0
#endif
			);
		frstats[0].fr_drop++;
		RWLOCK_EXIT(&ipf_solaris);
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}

	bcopy((char *)qif, (char *)&qf, sizeof(qf));
	qif = &qf;
	type = MTYPE(mb);
	pnext = qif->qf_rqinfo->qi_putp;

	if (datamsg(type) || (type == M_BREAK))
		err = fr_precheck(&mb, q, qif, 0);

	RWLOCK_EXIT(&ipfs_mutex);
	RWLOCK_EXIT(&ipf_solaris);

	if ((err == 0) && (mb != NULL)) {
		if (pnext)
			return (*pnext)(q, mb);

		cmn_err(CE_WARN, "IP Filter: inp NULL: qif %x q %x info %x",
			qif, q, q->q_qinfo);
	}
	if (mb) {
		mb->b_prev = NULL;
		freemsg(mb);
	}
	return 0;
}


int fr_qout(q, mb)
queue_t *q;
mblk_t *mb;
{
	int (*pnext) __P((queue_t *, mblk_t *)), type, synced = 0, err = 0;
	qif_t qf, *qif;

	if (fr_running <= 0) {
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}

	READ_ENTER(&ipf_solaris);
again:
	if (fr_running <= 0) {
		RWLOCK_EXIT(&ipf_solaris);
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}
	READ_ENTER(&ipfs_mutex);
	if (!(qif = qif_from_queue(q))) {
		for (qif = qif_head; qif; qif = qif->qf_next)
			if (&qif->qf_wqinit == q->q_qinfo && qif->qf_wqinfo &&
					qif->qf_wqinfo->qi_putp) {
				pnext = qif->qf_wqinfo->qi_putp;
				RWLOCK_EXIT(&ipfs_mutex);
				frstats[1].fr_notip++;
				if (!synced) {
					ipfsync();
					synced = 1;
					goto again;
				}
				/* fr_donotip(0, NULL, q, mb, mb, NULL, 0); */
				RWLOCK_EXIT(&ipf_solaris);
				return (*pnext)(q, mb);
			}
		RWLOCK_EXIT(&ipfs_mutex);
		if (!synced) {
			ipfsync();
			synced = 1;
			goto again;
		}
		cmn_err(CE_WARN,
			"IP Filter: dropped: fr_qout(%x,%x): type %x: qif %x",
			q, mb, MTYPE(mb), qif);
		cmn_err(CE_CONT,
			"IP Filter: info %x next %x ptr %x fsrv %x bsrv %x\n",
			q->q_qinfo, q->q_next, q->q_ptr, q->q_nfsrv,
			q->q_nbsrv);
		cmn_err(CE_CONT, "IP Filter: info: putp %x srvp %x info %x\n",
			q->q_qinfo->qi_putp, q->q_qinfo->qi_srvp,
#if SOLARIS > 3
			q->q_qinfo->qi_infop
#else
			0
#endif
			);
		if (q->q_nfsrv)
			cmn_err(CE_CONT,
				"IP Filter: nfsrv: info %x next %x ptr %x\n",
				q->q_nfsrv->q_qinfo, q->q_nfsrv->q_next,
				q->q_nfsrv->q_ptr);
		if (q->q_nbsrv)
			cmn_err(CE_CONT,
				"IP Filter: nbsrv: info %x next %x ptr %x\n",
				q->q_nbsrv->q_qinfo, q->q_nbsrv->q_next,
				q->q_nbsrv->q_ptr);
		frstats[1].fr_drop++;
		RWLOCK_EXIT(&ipf_solaris);
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}

	bcopy((char *)qif, (char *)&qf, sizeof(qf));
	qif = &qf;
	type = MTYPE(mb);
	pnext = qif->qf_wqinfo->qi_putp;

	if (datamsg(type) || (type == M_BREAK))
		err = fr_precheck(&mb, q, qif, 1);

	RWLOCK_EXIT(&ipfs_mutex);
	RWLOCK_EXIT(&ipf_solaris);

	if ((err == 0) && (mb != NULL)) {
		if (pnext)
			return (*pnext)(q, mb);

		cmn_err(CE_WARN, "IP Filter: outp NULL: qif %x %s q %x info %x",
			qif, qif->qf_name, q, q->q_qinfo);
	}
	if (mb) {
		mb->b_prev = NULL;
		freemsg(mb);
	}
	return 0;
}


void ipf_synctimeout(arg)
void *arg;
{
	READ_ENTER(&ipf_solaris);
	ipfsync();
	WRITE_ENTER(&ipfs_mutex);
	synctimeoutid = 0;
	RWLOCK_EXIT(&ipfs_mutex);
	RWLOCK_EXIT(&ipf_solaris);
}

static int ipf_ip_qin(q, mb)
queue_t *q;
mblk_t *mb;
{
	struct iocblk *ioc;
	int ret;

	if (fr_running <= 0) {
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}
 
	if (MTYPE(mb) != M_IOCTL)
		return (*ipf_ip_inp)(q, mb);

	READ_ENTER(&ipf_solaris);
	if (fr_running <= 0) {
		RWLOCK_EXIT(&ipf_solaris);
		mb->b_prev = NULL;
		freemsg(mb);
		return 0;
	}
	ioc = (struct iocblk *)mb->b_rptr;

	switch (ioc->ioc_cmd) {
	case I_LINK:
	case I_UNLINK:
	case SIOCSIFADDR:
	case SIOCSIFFLAGS:
#ifdef	IPFDEBUG
		cmn_err(CE_NOTE, "IP Filter: ipf_ip_qin() M_IOCTL type=0x%x\n", ioc->ioc_cmd);
#endif
		ret = (*ipf_ip_inp)(q, mb);

		WRITE_ENTER(&ipfs_mutex);
		if (synctimeoutid == 0) {
			synctimeoutid = timeout(ipf_synctimeout,
						NULL,
						drv_usectohz(1000000) /*1 sec*/
					);
		}

		RWLOCK_EXIT(&ipfs_mutex);
		break;
	default:
		ret = (*ipf_ip_inp)(q, mb);
	}
	RWLOCK_EXIT(&ipf_solaris);
	return ret;
}

static int ipdrvattcnt = 0;
extern struct streamtab ipinfo;

void solipdrvattach()
{
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: solipdrvattach() %d ipinfo=0x%lx\n",
		ipdrvattcnt, &ipinfo);
#endif

	if (++ipdrvattcnt == 1) {
		if (ipf_ip_inp == NULL) {
			ipf_ip_inp = ipinfo.st_wrinit->qi_putp;
			ipinfo.st_wrinit->qi_putp = ipf_ip_qin;
		}
	}
}

int solipdrvdetach()
{
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: solipdrvdetach() %d ipinfo=0x%lx\n",
		ipdrvattcnt, &ipinfo);
#endif

	WRITE_ENTER(&ipfs_mutex);
	if (--ipdrvattcnt <= 0) {
		if (ipf_ip_inp && (ipinfo.st_wrinit->qi_putp == ipf_ip_qin)) {
			ipinfo.st_wrinit->qi_putp = ipf_ip_inp;
			ipf_ip_inp = NULL;
		}
		if (synctimeoutid) {
			untimeout(synctimeoutid);
			synctimeoutid = 0;
		}
	}
	RWLOCK_EXIT(&ipfs_mutex);
	return ipdrvattcnt;
}

/*
 * attach the packet filter to each interface that is defined as having an
 * IP address associated with it and save some of the info. for that struct
 * so we're not out of date as soon as the ill disappears - but we must sync
 * to be correct!
 */
void solattach()
{
	queue_t *in, *out;
	struct frentry *f;
	qif_t *qif, *qf2;
	ipnat_t *np;
	size_t len;
	ill_t *il;

	for (il = ill_g_head; il; il = il->ill_next) {
		in = il->ill_rq;
		if (!in || !il->ill_wq)
			continue;

		out = il->ill_wq->q_next;

		WRITE_ENTER(&ipfs_mutex);
		/*
		 * Look for entry already setup for this device
		 */
		for (qif = qif_head; qif; qif = qif->qf_next)
			if (qif->qf_iptr == in->q_ptr &&
			    qif->qf_optr == out->q_ptr)
				break;
		if (qif) {
			RWLOCK_EXIT(&ipfs_mutex);
			continue;
		}
#ifdef	IPFDEBUG
		cmn_err(CE_NOTE,
			"IP Filter: il %x ipt %x opt %x ipu %x opu %x i %x/%x",
			il, in->q_ptr,  out->q_ptr, in->q_qinfo->qi_putp,
			out->q_qinfo->qi_putp, out->q_qinfo, in->q_qinfo);
#endif
		KMALLOC(qif, qif_t *);
		if (!qif) {
			cmn_err(CE_NOTE,
				"IP Filter: malloc(%d) for qif_t failed\n",
				sizeof(qif_t));
			RWLOCK_EXIT(&ipfs_mutex);
			continue;
		}

		if (in->q_qinfo->qi_putp == fr_qin) {
			for (qf2 = qif_head; qf2; qf2 = qf2->qf_next)
				if (&qf2->qf_rqinit == in->q_qinfo) {
					qif->qf_rqinfo = qf2->qf_rqinfo;
					break;
				}
			if (!qf2) {
#ifdef	IPFDEBUG
				cmn_err(CE_WARN,
					"IP Filter: rq:%s put %x qi %x",
					il->ill_name, in->q_qinfo->qi_putp,
					in->q_qinfo);
#endif
				RWLOCK_EXIT(&ipfs_mutex);
				KFREE(qif);
				continue;
			}
		} else
			qif->qf_rqinfo = in->q_qinfo;

		if (out->q_qinfo->qi_putp == fr_qout) {
			for (qf2 = qif_head; qf2; qf2 = qf2->qf_next)
				if (&qf2->qf_wqinit == out->q_qinfo) {
					qif->qf_wqinfo = qf2->qf_wqinfo;
					break;
				}
			if (!qf2) {
#ifdef	IPFDEBUG
				cmn_err(CE_WARN,
					"IP Filter: wq:%s put %x qi %x",
					il->ill_name, out->q_qinfo->qi_putp,
					out->q_qinfo);
#endif
				RWLOCK_EXIT(&ipfs_mutex);
				KFREE(qif);
				continue;
			}
		} else
			qif->qf_wqinfo = out->q_qinfo;

		qif->qf_ill = il;
		qif->qf_in = in;
		qif->qf_out = out;
		qif->qf_iptr = in->q_ptr;
		qif->qf_optr = out->q_ptr;
		qif->qf_hl = il->ill_hdr_length;
		strncpy(qif->qf_name, il->ill_name, sizeof(qif->qf_name));
		qif->qf_name[sizeof(qif->qf_name) - 1] = '\0';

		qif->qf_next = qif_head;
		qif_head = qif;

		/*
		 * Activate any rules directly associated with this interface
		 */
		WRITE_ENTER(&ipf_mutex);
		for (f = ipfilter[0][fr_active]; f; f = f->fr_next) {
			if ((f->fr_ifa == (struct ifnet *)-1)) {
				len = strlen(f->fr_ifname) + 1;
				if ((len != 0) &&
				    (len == (size_t)il->ill_name_length) &&
				    !strncmp(il->ill_name, f->fr_ifname, len))
					f->fr_ifa = il;
			}
		}
		for (f = ipfilter[1][fr_active]; f; f = f->fr_next) {
			if ((f->fr_ifa == (struct ifnet *)-1)) {
				len = strlen(f->fr_ifname) + 1;
				if ((len != 0) &&
				    (len == (size_t)il->ill_name_length) &&
				    !strncmp(il->ill_name, f->fr_ifname, len))
					f->fr_ifa = il;
			}
		}
		RWLOCK_EXIT(&ipf_mutex);
		WRITE_ENTER(&ipf_nat);
		for (np = nat_list; np; np = np->in_next) {
			if ((np->in_ifp == (struct ifnet *)-1)) {
				len = strlen(np->in_ifname) + 1;
				if ((len != 0) &&
				    (len == (size_t)il->ill_name_length) &&
				    !strncmp(il->ill_name, np->in_ifname, len))
					np->in_ifp = il;
			}
		}
		RWLOCK_EXIT(&ipf_nat);

		bcopy((caddr_t)qif->qf_rqinfo, (caddr_t)&qif->qf_rqinit,
		      sizeof(struct qinit));
		qif->qf_rqinit.qi_putp = fr_qin;
#ifdef	IPFDEBUG
		cmn_err(CE_NOTE,
			"IP Filter: solattach: in queue(%lx)->q_qinfo FROM %lx TO %lx",
			in, in->q_qinfo, &qif->qf_rqinit
			);
#endif
		in->q_qinfo = &qif->qf_rqinit;

		bcopy((caddr_t)qif->qf_wqinfo, (caddr_t)&qif->qf_wqinit,
		      sizeof(struct qinit));
		qif->qf_wqinit.qi_putp = fr_qout;
#ifdef	IPFDEBUG
		cmn_err(CE_NOTE,
			"IP Filter: solattach: out queue(%lx)->q_qinfo FROM %lx TO %lx",
			out, out->q_qinfo, &qif->qf_wqinit
			);
#endif
		out->q_qinfo = &qif->qf_wqinit;

		RWLOCK_EXIT(&ipfs_mutex);
		cmn_err(CE_CONT, "IP Filter: attach to [%s,%d]\n",
			qif->qf_name, il->ill_ppa);
	}
	if (!qif_head)
		cmn_err(CE_CONT, "IP Filter: not attached to any interfaces\n");
	return;
}


/*
 * look for bad consistancies between the list of interfaces the filter knows
 * about and those which are currently configured.
 */
int ipfsync()
{
	register struct frentry *f;
	register ipnat_t *np;
	register qif_t *qif, **qp;
	register ill_t *il;
	queue_t *in, *out;

	WRITE_ENTER(&ipfs_mutex);
	for (qp = &qif_head; (qif = *qp); ) {
		for (il = ill_g_head; il; il = il->ill_next)
			if ((qif->qf_ill == il) &&
			    !strcmp(qif->qf_name, il->ill_name)) {
				mblk_t	*m = il->ill_hdr_mp;

				qif->qf_hl = il->ill_hdr_length;
				if (m && qif->qf_hl != (m->b_wptr - m->b_rptr))
					cmn_err(CE_NOTE,
						"IP Filter: ILL Header Length Mismatch\n");
				break;
			}
		if (il) {
			qp = &qif->qf_next;
			continue;
		}
		cmn_err(CE_CONT, "IP Filter: detaching [%s]\n", qif->qf_name);
		*qp = qif->qf_next;

		/*
		 * Disable any rules directly associated with this interface
		 */
		WRITE_ENTER(&ipf_nat);
		for (np = nat_list; np; np = np->in_next)
			if (np->in_ifp == (void *)qif->qf_ill)
				np->in_ifp = (struct ifnet *)-1;
		RWLOCK_EXIT(&ipf_nat);
		WRITE_ENTER(&ipf_mutex);
		for (f = ipfilter[0][fr_active]; f; f = f->fr_next)
			if (f->fr_ifa == (void *)qif->qf_ill)
				f->fr_ifa = (struct ifnet *)-1;
		for (f = ipfilter[1][fr_active]; f; f = f->fr_next)
			if (f->fr_ifa == (void *)qif->qf_ill)
				f->fr_ifa = (struct ifnet *)-1;

#if 0 /* XXX */
		/*
		 * As well as the ill disappearing when a device is unplumb'd,
		 * it also appears that the associated queue structures also
		 * disappear - at least in the case of ppp, which is the most
		 * volatile here.  Thanks to Greg for finding this problem.
		 */
		/*
		 * Restore q_qinfo pointers in interface queues
		 */
		out = qif->qf_out;
		in = qif->qf_in;
		if (in) {
# ifdef	IPFDEBUG
			cmn_err(CE_NOTE,
				"IP Filter: ipfsync: in queue(%lx)->q_qinfo FROM %lx TO %lx",
				in, in->q_qinfo, qif->qf_rqinfo
				);
# endif
			in->q_qinfo = qif->qf_rqinfo;
		}
		if (out) {
# ifdef	IPFDEBUG
			cmn_err(CE_NOTE,
				"IP Filter: ipfsync: out queue(%lx)->q_qinfo FROM %lx TO %lx",
				out, out->q_qinfo, qif->qf_wqinfo
				);
# endif
			out->q_qinfo = qif->qf_wqinfo;
		}
#endif /* XXX */
		RWLOCK_EXIT(&ipf_mutex);
		KFREE(qif);
		qif = *qp;
	}
	RWLOCK_EXIT(&ipfs_mutex);
	solattach();

	/*
	 * Resync. any NAT `connections' using this interface and its IP #.
	 */
	for (il = ill_g_head; il; il = il->ill_next)
		ip_natsync((void *)il);
	return 0;
}


/*
 * unhook the IP filter from all defined interfaces with IP addresses
 */
int soldetach()
{
	queue_t *in, *out;
	qif_t *qif, **qp;
	ill_t *il;

	WRITE_ENTER(&ipfs_mutex);
	/*
	 * Make two passes, first get rid of all the unknown devices, next
	 * unlink known devices.
	 */
	for (qp = &qif_head; (qif = *qp); ) {
		for (il = ill_g_head; il; il = il->ill_next)
			if (qif->qf_ill == il)
				break;
		if (il) {
			qp = &qif->qf_next;
			continue;
		}
		cmn_err(CE_CONT, "IP Filter: removing [%s]\n", qif->qf_name);
		*qp = qif->qf_next;
		KFREE(qif);
	}

	while ((qif = qif_head)) {
		qif_head = qif->qf_next;
		for (il = ill_g_head; il; il = il->ill_next)
			if (qif->qf_ill == il)
				break;
		if (il) {
			in = qif->qf_in;
			out = qif->qf_out;
			cmn_err(CE_CONT, "IP Filter: detaching [%s,%d]\n",
				qif->qf_name, il->ill_ppa);

#ifdef	IPFDEBUG
			cmn_err(CE_NOTE,
				"IP Filter: soldetach: in queue(%lx)->q_qinfo FROM %lx TO %lx",
				in, in->q_qinfo, qif->qf_rqinfo);
#endif
			in->q_qinfo = qif->qf_rqinfo;

			/*
			 * and the write queue...
			 */
#ifdef	IPFDEBUG
			cmn_err(CE_NOTE,
				"IP Filter: soldetach: out queue(%lx)->q_qinfo FROM %lx TO %lx",
				out, out->q_qinfo, qif->qf_wqinfo);
#endif
			out->q_qinfo = qif->qf_wqinfo;
		}
		KFREE(qif);
	}
	RWLOCK_EXIT(&ipfs_mutex);
	return ipldetach();
}


#ifdef	IPFDEBUG
void printire(ire)
ire_t *ire;
{
	printf("ire: ll_hdr_mp %p rfq %p stq %p src_addr %x max_frag %d\n",
		ire->ire_ll_hdr_mp, ire->ire_rfq, ire->ire_stq,
		ire->ire_src_addr, ire->ire_max_frag);
	printf("ire: mask %x addr %x gateway_addr %x type %d\n",
		ire->ire_mask, ire->ire_addr, ire->ire_gateway_addr,
		ire->ire_type);
	printf("ire: ll_hdr_length %d ll_hdr_saved_mp %p\n",
		ire->ire_ll_hdr_length, ire->ire_ll_hdr_saved_mp);
}
#endif


int ipfr_fastroute(qf, ip, mb, mpp, fin, fdp)
qif_t *qf;
ip_t *ip;
mblk_t *mb, **mpp;
fr_info_t *fin;
frdest_t *fdp;
{
	ire_t *ir, *dir, *gw;
	struct in_addr dst;
	queue_t *q = NULL;
	mblk_t *mp = NULL;
	size_t hlen = 0;
	frentry_t *fr;
	void *ifp;
	u_char *s;

#ifndef	sparc
	u_short __iplen, __ipoff;
#endif
	/*
	 * If this is a duplicate mblk then we want ip to point at that
	 * data, not the original, if and only if it is already pointing at
	 * the current mblk data.
	 */
	if (ip == (ip_t *)qf->qf_m->b_rptr && qf->qf_m != mb)
		ip = (ip_t *)mb->b_rptr;

	/*
	 * If there is another M_PROTO, we don't want it
	 */
	if (*mpp != mb) {
		(*mpp)->b_cont = NULL;
		(*mpp)->b_prev = NULL;
		freemsg(*mpp);
	}

	ir = (ire_t *)fdp->fd_ifp;

	if (fdp->fd_ip.s_addr)
		dst = fdp->fd_ip;
	else
		dst = fin->fin_fi.fi_dst;

#if SOLARIS2 > 5
	gw = NULL;
	dir = ire_route_lookup(dst.s_addr, 0xffffffff, 0, 0, NULL, &gw, NULL,
				MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|
				MATCH_IRE_RECURSIVE);
#else
	dir = ire_lookup(dst.s_addr);
#endif
	if (dir)
		if (!dir->ire_ll_hdr_mp || !dir->ire_ll_hdr_length)
			dir = NULL;

	if (!ir)
		ir = dir;

	if (ir && dir) {
		ifp = ire_to_ill(ir);
		fr = fin->fin_fr;
		/*
		 * In case we're here due to "to <if>" being used with
		 * "keep state", check that we're going in the correct
		 * direction.
		 */
		if ((fr != NULL) && (fdp->fd_ifp != NULL) &&
		    (fin->fin_rev != 0) && (fdp == &fr->fr_tif))
			return -1;

		fin->fin_ifp == ifp;
		if (fin->fin_out == 0) {
			fin->fin_fr = ipacct[1][fr_active];
			if ((fin->fin_fr != NULL) &&
			    (fr_scanlist(FR_NOMATCH, ip, fin, mb)&FR_ACCOUNT)){
				ATOMIC_INC(frstats[1].fr_acct);
			}
			fin->fin_fr = NULL;
			(void) fr_checkstate(ip, fin);
			(void) ip_natout(ip, fin);
		}       
#ifndef	sparc
		__iplen = (u_short)ip->ip_len,
		__ipoff = (u_short)ip->ip_off;

		ip->ip_len = htons(__iplen);
		ip->ip_off = htons(__ipoff);
#endif

		if ((mp = dir->ire_ll_hdr_mp)) {
			hlen = dir->ire_ll_hdr_length;

			s = mb->b_rptr;
			if (hlen && (s - mb->b_datap->db_base) >= hlen) {
				s -= hlen;
				mb->b_rptr = (u_char *)s;
				bcopy((char *)mp->b_rptr, (char *)s, hlen);
			} else {
				mblk_t	*mp2;

				mp2 = copyb(mp);
				if (!mp2)
					goto bad_fastroute;
				mp2->b_cont = mb;
				mb = mp2;
			}
		}

		if (ir->ire_stq)
			q = ir->ire_stq;
		else if (ir->ire_rfq)
			q = WR(ir->ire_rfq);
		if (q) {
			mb->b_prev = NULL;
			RWLOCK_EXIT(&ipfs_mutex);
			RWLOCK_EXIT(&ipf_solaris);
			putnext(q, mb);
			READ_ENTER(&ipf_solaris);
			READ_ENTER(&ipfs_mutex);
			ipl_frouteok[0]++;
			return 0;
		}
	}
bad_fastroute:
	mb->b_prev = NULL;
	freemsg(mb);
	ipl_frouteok[1]++;
	return -1;
}


void copyout_mblk(m, off, len, buf)
mblk_t *m;
size_t off, len;
char *buf;
{
	u_char *s, *bp = (u_char *)buf;
	size_t mlen, olen, clen;

	for (; m && len; m = m->b_cont) {
		if (MTYPE(m) != M_DATA)
			continue;
		s = m->b_rptr;
		mlen = m->b_wptr - s;
		olen = MIN(off, mlen);
		if ((olen == mlen) || (olen < off)) {
			off -= olen;
			continue;
		} else if (olen) {
			off -= olen;
			s += olen;
			mlen -= olen;
		}
		clen = MIN(mlen, len);
		bcopy(s, bp, clen);
		len -= clen;
		bp += clen;
	}
}


void copyin_mblk(m, off, len, buf)
mblk_t *m;
size_t off, len;
char *buf;
{
	u_char *s, *bp = (u_char *)buf;
	size_t mlen, olen, clen;

	for (; m && len; m = m->b_cont) {
		if (MTYPE(m) != M_DATA)
			continue;
		s = m->b_rptr;
		mlen = m->b_wptr - s;
		olen = MIN(off, mlen);
		if ((olen == mlen) || (olen < off)) {
			off -= olen;
			continue;
		} else if (olen) {
			off -= olen;
			s += olen;
			mlen -= olen;
		}
		clen = MIN(mlen, len);
		bcopy(bp, s, clen);
		len -= clen;
		bp += clen;
	}
}
