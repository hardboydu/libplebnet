
/*
 * ng_pppoe.c
 *
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
 * All rights reserved.
 * 
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 * 
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Julian Elischer <julian@whistle.com>
 *
 * $FreeBSD$
 * $Whistle: ng_pppoe.c,v 1.7 1999/10/16 10:16:43 julian Exp $
 */
#if 0
#define AAA printf("pppoe: %s\n", __FUNCTION__ );
#define BBB printf("-%d-", __LINE__ );
#else
#define AAA
#define BBB
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <net/ethernet.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_pppoe.h>

/*
 * This section contains the netgraph method declarations for the
 * sample node. These methods define the netgraph 'type'.
 */

static int	ng_PPPoE_constructor(node_p *node);
static int	ng_PPPoE_rcvmsg(node_p node, struct ng_mesg *msg,
		  const char *retaddr, struct ng_mesg **resp);
static int	ng_PPPoE_rmnode(node_p node);
static int	ng_PPPoE_newhook(node_p node, hook_p hook, const char *name);
static int	ng_PPPoE_connect(hook_p hook);
static int	ng_PPPoE_rcvdata(hook_p hook, struct mbuf *m, meta_p meta);
static int	ng_PPPoE_disconnect(hook_p hook);

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	NG_VERSION,
	NG_PPPOE_NODE_TYPE,
	NULL,
	ng_PPPoE_constructor,
	ng_PPPoE_rcvmsg,
	ng_PPPoE_rmnode,
	ng_PPPoE_newhook,
	NULL,
	ng_PPPoE_connect,
	ng_PPPoE_rcvdata,
	ng_PPPoE_rcvdata,
	ng_PPPoE_disconnect
};
NETGRAPH_INIT(PPPoE, &typestruct);

/*
 * States for the session state machine.
 * These have no meaning if there is no hook attached yet.
 */
enum state {
    PPPOE_SNONE=0,	/* [both] Initial state */
    PPPOE_SINIT,	/* [Client] Sent discovery initiation */
    PPPOE_PRIMED,	/* [Server] Sent offer message */
    PPPOE_SOFFER,	/* [Server] Sent offer message */
    PPPOE_SREQ,		/* [Client] Sent a Request */
    PPPOE_LISTENING,	/* [Server] Listening for discover initiation msg */
    PPPOE_NEWCONNECTED,	/* [Both] Connection established, No data received */
    PPPOE_CONNECTED,	/* [Both] Connection established, Data received */
    PPPOE_DEAD		/* [Both] */
};

#define NUMTAGS 20 /* number of tags we are set up to work with */

/*
 * Information we store for each hook on each node for negotiating the 
 * session. The mbuf and cluster are freed once negotiation has completed.
 * The whole negotiation block is then discarded.
 */

struct sess_neg {
	struct mbuf 		*m; /* holds cluster with last sent packet */
	union	packet		*pkt; /* points within the above cluster */
	struct callout_handle	timeout_handle;   /* see timeout(9) */
	u_int			timeout; /* 0,1,2,4,8,16 etc. seconds */
	u_int			numtags;
	struct pppoe_tag	*tags[NUMTAGS];
	u_int			service_len;
	u_int			ac_name_len;

	struct datatag		service;
	struct datatag		ac_name;
};
typedef struct sess_neg *negp;

/*
 * Session information that is needed after connection.
 */
struct session {
	hook_p  		hook;
	u_int16_t		Session_ID;
	struct session		*hash_next; /* not yet uesed */
	enum state		state;
	char			creator[NG_NODELEN + 1]; /* who to notify */
	struct pppoe_full_hdr	pkt_hdr;	/* used when connected */
	negp			neg;		/* used when negotiating */
};
typedef struct session *sessp;

/*
 * Information we store for each node
 */
struct PPPOE {
	node_p		node;		/* back pointer to node */
	hook_p  	ethernet_hook;
	hook_p  	debug_hook;
	u_int   	packets_in;	/* packets in from ethernet */
	u_int   	packets_out;	/* packets out towards ethernet */
	u_int32_t	flags;
	/*struct session *buckets[HASH_SIZE];*/	/* not yet used */
};
typedef struct PPPOE *priv_p;

const struct ether_header eh_prototype =
	{{0xff,0xff,0xff,0xff,0xff,0xff},
	 {0x00,0x00,0x00,0x00,0x00,0x00},
	 ETHERTYPE_PPPOE_DISC};

union uniq {
	char bytes[sizeof(void *)];
	void * pointer;
	};

#define	LEAVE(x) do { error = x; goto quit; } while(0)
static void	pppoe_start(sessp sp);
static void	sendpacket(sessp sp);
static void	pppoe_ticker(void *arg);
static struct pppoe_tag* scan_tags(sessp	sp, struct pppoe_hdr* ph);
static	int	pppoe_send_event(sessp sp, enum cmd cmdid);

/*************************************************************************
 * Some basic utilities  from the Linux version with author's permission.*
 * Author:	Michal Ostrowski <mostrows@styx.uwaterloo.ca>		 *
 ************************************************************************/

/*
 * Generate a new session id
 * XXX find out the freeBSD locking scheme.
 */
static u_int16_t
get_new_sid(node_p node)
{
	static int pppoe_sid = 10;
	sessp sp;
	hook_p	hook;
	u_int16_t val; 
	priv_p privp = node->private;

AAA
restart:
	val = pppoe_sid++;
	/*
	 * Spec says 0xFFFF is reserved.
	 * Also don't use 0x0000
	 */
	if (val == 0xffff) {
		pppoe_sid = 20;
		goto restart;
	}

	/* Check it isn't already in use */
	LIST_FOREACH(hook, &node->hooks, hooks) {
		/* don't check special hooks */
		if ((hook->private == &privp->debug_hook)
		||  (hook->private == &privp->ethernet_hook)) 
			continue;
		sp = hook->private;
		if (sp->Session_ID == val)
			goto restart;
	}

	return val;
}


/*
 * Return the location where the next tag can be put 
 */
static __inline struct pppoe_tag*
next_tag(struct pppoe_hdr* ph)
{
	return (struct pppoe_tag*)(((char*)&ph->tag[0]) + ntohs(ph->length));
}

/*
 * Look for a tag of a specific type
 * Don't trust any length the other end says.
 * but assume we already sanity checked ph->length.
 */
static struct pppoe_tag*
get_tag(struct pppoe_hdr* ph, u_int16_t idx)
{
	char *end = (char *)next_tag(ph);
	char *ptn;
	struct pppoe_tag *pt = &ph->tag[0];
	/*
	 * Keep processing tags while a tag header will still fit.
	 */
AAA
	while((char*)(pt + 1) <= end) {
	    /*
	     * If the tag data would go past the end of the packet, abort.
	     */
	    ptn = (((char *)(pt + 1)) + ntohs(pt->tag_len));
	    if(ptn > end)
		return NULL;

	    if(pt->tag_type == idx)
		return pt;

	    pt = (struct pppoe_tag*)ptn;
	}
	return NULL;
}

/**************************************************************************
 * inlines to initialise or add tags to a session's tag list,
 **************************************************************************/
/*
 * Initialise the session's tag list
 */
static void
init_tags(sessp sp)
{
AAA
	if(sp->neg == NULL) {
		printf("pppoe: asked to init NULL neg pointer\n");
		return;
	}
	sp->neg->numtags = 0;
}

static void
insert_tag(sessp sp, struct pppoe_tag *tp)
{
	int	i;
	negp neg;

AAA
	if((neg = sp->neg) == NULL) {
		printf("pppoe: asked to use NULL neg pointer\n");
		return;
	}
	if ((i = neg->numtags++) < NUMTAGS) {
		neg->tags[i] = tp;
	} else {
		printf("pppoe: asked to add too many tags to packet\n");
	}
}

/*
 * Make up a packet, using the tags filled out for the session.
 *
 * Assume that the actual pppoe header and ethernet header 
 * are filled out externally to this routine.
 * Also assume that neg->wh points to the correct 
 * location at the front of the buffer space.
 */
static void
make_packet(sessp sp) {
	struct pppoe_full_hdr *wh = &sp->neg->pkt->pkt_header;
	struct pppoe_tag **tag;
	char *dp;
	int count;
	int tlen;
	u_int16_t length = 0;

AAA
	if ((sp->neg == NULL) || (sp->neg->m == NULL)) {
		printf("pppoe: make_packet called from wrong state\n");
	}
	dp = (char *)wh->ph.tag;
	for (count = 0, tag = sp->neg->tags;
	    ((count < sp->neg->numtags) && (count < NUMTAGS)); 
	    tag++, count++) {
		tlen = ntohs((*tag)->tag_len) + sizeof(**tag);
		if ((length + tlen) > (ETHER_MAX_LEN - 4 - sizeof(*wh))) {
			printf("pppoe: tags too long\n");
			sp->neg->numtags = count;
			break;	/* XXX chop off what's too long */
		}
		bcopy((char *)*tag, (char *)dp, tlen);
		length += tlen;
		dp += tlen;
	}
 	wh->ph.length = htons(length);
	sp->neg->m->m_len = length + sizeof(*wh);
	sp->neg->m->m_pkthdr.len = length + sizeof(*wh);
}

/**************************************************************************
 * Routine to match a service offered					  *
 **************************************************************************/
/* 
 * Find a hook that has a service string that matches that
 * we are seeking. for now use a simple string.
 * In the future we may need something like regexp().
 * for testing allow a null string to match 1st found and a null service
 * to match all requests. Also make '*' do the same.
 */
static hook_p
pppoe_match_svc(node_p node, char *svc_name, int svc_len)
{
	sessp	sp	= NULL;
	negp	neg	= NULL;
	priv_p	privp	= node->private;
	hook_p hook;

AAA
	LIST_FOREACH(hook, &node->hooks, hooks) {

		/* skip any hook that is debug or ethernet */
		if ((hook->private == &privp->debug_hook)
		||  (hook->private == &privp->ethernet_hook))
			continue;
		sp = hook->private;

		/* Skip any sessions which are not in LISTEN mode. */
		if ( sp->state != PPPOE_LISTENING)
			continue;

		neg = sp->neg;
		/* XXX check validity of this */
		/* special case, NULL request. match 1st found. */
		if (svc_len == 0)
			break;

		/* XXX check validity of this */
		/* Special case for a blank or "*" service name (wildcard) */
		if ((neg->service_len == 0)
		||  ((neg->service_len == 1)
		  && (neg->service.data[0] == '*'))) {
			break;
		}

		/* If the lengths don't match, that aint it. */
		if (neg->service_len != svc_len)
			continue;

		/* An exact match? */
		if (strncmp(svc_name, neg->service.data, svc_len) == 0)
			break;
	}
	return (hook);
}
/**************************************************************************
 * Routine to find a particular session that matches an incoming packet	  *
 **************************************************************************/
static hook_p
pppoe_findsession(node_p node, struct pppoe_full_hdr *wh)
{
	sessp	sp = NULL;
	hook_p hook = NULL;
	priv_p	privp = node->private;
	u_int16_t	session = ntohs(wh->ph.sid);

	/*
	 * find matching peer/session combination.
	 */
AAA
	LIST_FOREACH(hook, &node->hooks, hooks) {
		/* don't check special hooks */
		if ((hook->private == &privp->debug_hook)
		||  (hook->private == &privp->ethernet_hook)) {
			continue;
		}
		sp = hook->private;
		if ( ( (sp->state == PPPOE_CONNECTED)
		    || (sp->state == PPPOE_NEWCONNECTED) )
		&& (sp->Session_ID == session)
		&& (bcmp(sp->pkt_hdr.eh.ether_dhost,
		    wh->eh.ether_shost,
		    ETHER_ADDR_LEN)) == 0) {
			break;
		}
	}
	return (hook);
}

static hook_p
pppoe_finduniq(node_p node, struct pppoe_tag *tag)
{
	hook_p hook = NULL;
	priv_p	privp = node->private;
	union uniq		uniq;

AAA
	bcopy(tag->tag_data, uniq.bytes, sizeof(void *));
	/* cycle through all known hooks */
	LIST_FOREACH(hook, &node->hooks, hooks) {
		/* don't check special hooks */
		if ((hook->private == &privp->debug_hook)
		||  (hook->private == &privp->ethernet_hook)) 
			continue;
		if (uniq.pointer == hook->private)
			break;
	}
	return (hook);
}

/**************************************************************************
 * start of Netgraph entrypoints					  *
 **************************************************************************/

/*
 * Allocate the private data structure and the generic node
 * and link them together.
 *
 * ng_make_node_common() returns with a generic node struct
 * with a single reference for us.. we transfer it to the
 * private structure.. when we free the private struct we must
 * unref the node so it gets freed too.
 *
 * If this were a device node than this work would be done in the attach()
 * routine and the constructor would return EINVAL as you should not be able
 * to creatednodes that depend on hardware (unless you can add the hardware :)
 */
static int
ng_PPPoE_constructor(node_p *nodep)
{
	priv_p privdata;
	int error;

AAA
	/* Initialize private descriptor */
	MALLOC(privdata, priv_p, sizeof(*privdata), M_NETGRAPH, M_WAITOK);
	if (privdata == NULL)
		return (ENOMEM);
	bzero(privdata, sizeof(*privdata));

	/* Call the 'generic' (ie, superclass) node constructor */
	if ((error = ng_make_node_common(&typestruct, nodep))) {
		FREE(privdata, M_NETGRAPH);
		return (error);
	}

	/* Link structs together; this counts as our one reference to *nodep */
	(*nodep)->private = privdata;
	privdata->node = *nodep;
	return (0);
}

/*
 * Give our ok for a hook to be added...
 * point the hook's private info to the hook structure.
 *
 * The following hook names are special:
 *  Ethernet:  the hook that should be connected to a NIC.
 *  debug:	copies of data sent out here  (when I write the code).
 */
static int
ng_PPPoE_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p privp = node->private;
	sessp sp;

AAA
	if (strcmp(name, NG_PPPOE_HOOK_ETHERNET) == 0) {
		privp->ethernet_hook = hook;
		hook->private = &privp->ethernet_hook;
	} else if (strcmp(name, NG_PPPOE_HOOK_DEBUG) == 0) {
		privp->debug_hook = hook;
		hook->private = &privp->debug_hook;
	} else {
		/*
		 * Any other unique name is OK.
		 * The infrastructure has already checked that it's unique,
		 * so just allocate it and hook it in.
		 */
		MALLOC(sp, sessp, sizeof(*sp), M_NETGRAPH, M_WAITOK);
		if (sp == NULL) {
				return (ENOMEM);
		}
		bzero(sp, sizeof(*sp));

		hook->private = sp;
		sp->hook = hook;
	}
	return(0);
}

/*
 * Get a netgraph control message.
 * Check it is one we understand. If needed, send a response.
 * We sometimes save the address for an async action later.
 * Always free the message.
 */
static int
ng_PPPoE_rcvmsg(node_p node,
	   struct ng_mesg *msg, const char *retaddr, struct ng_mesg **rptr)
{
	priv_p privp = node->private;
	struct ngPPPoE_init_data *ourmsg = NULL;
	struct ng_mesg *resp = NULL;
	int error = 0;
	hook_p hook = NULL;
	sessp sp = NULL;
	negp neg = NULL;

AAA
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_PPPOE_COOKIE: 
		switch (msg->header.cmd) {
		case NGM_PPPOE_CONNECT:
		case NGM_PPPOE_LISTEN: 
		case NGM_PPPOE_OFFER: 
			ourmsg = (struct ngPPPoE_init_data *)msg->data;
			if (( sizeof(*ourmsg) > msg->header.arglen)
			|| ((sizeof(*ourmsg) + ourmsg->data_len)
			    > msg->header.arglen)) {
				printf("PPPoE_rcvmsg: bad arg size");
				LEAVE(EMSGSIZE);
			}
			if (ourmsg->data_len > PPPOE_SERVICE_NAME_SIZE) {
				printf("pppoe: init data too long (%d)\n",
							ourmsg->data_len);
				LEAVE(EMSGSIZE);
			}
			/* make sure strcmp will terminate safely */
			ourmsg->hook[sizeof(ourmsg->hook) - 1] = '\0';

			/* cycle through all known hooks */
			LIST_FOREACH(hook, &node->hooks, hooks) {
				if (hook->name
				&& strcmp(hook->name, ourmsg->hook) == 0)
					break;
			}
			if (hook == NULL) {
				LEAVE(ENOENT);
			}
			if ((hook->private == &privp->debug_hook)
			||  (hook->private == &privp->ethernet_hook)) {
				LEAVE(EINVAL);
			}
			sp = hook->private;
			if (sp->state |= PPPOE_SNONE) {
				printf("pppoe: Session already active\n");
				LEAVE(EISCONN);
			}

			/*
			 * set up prototype header
			 */
			MALLOC(neg, negp, sizeof(*neg), M_NETGRAPH, M_WAITOK);

			if (neg == NULL) {
				printf("pppoe: Session out of memory\n");
				LEAVE(ENOMEM);
			}
			bzero(neg, sizeof(*neg));
			MGETHDR(neg->m, M_DONTWAIT, MT_DATA);
			if(neg->m == NULL) {
				printf("pppoe: Session out of mbufs\n");
				FREE(neg, M_NETGRAPH);
				LEAVE(ENOBUFS);
			}
			neg->m->m_pkthdr.rcvif = NULL;
			MCLGET(neg->m, M_DONTWAIT);
			if ((neg->m->m_flags & M_EXT) == 0) {
				printf("pppoe: Session out of mcls\n");
				m_freem(neg->m);
				FREE(neg, M_NETGRAPH);
				LEAVE(ENOBUFS);
			}
			sp->neg = neg;
			callout_handle_init( &neg->timeout_handle);
			neg->m->m_len = sizeof(struct pppoe_full_hdr);
			neg->pkt = mtod(neg->m, union packet*);
			neg->pkt->pkt_header.eh = eh_prototype;
			neg->pkt->pkt_header.ph.ver = 0x1;
			neg->pkt->pkt_header.ph.type = 0x1;
			neg->pkt->pkt_header.ph.sid = 0x0000;
			neg->timeout = 0;

			strncpy(sp->creator, retaddr, NG_NODELEN);
			sp->creator[NG_NODELEN] = '\0';
		}
		switch (msg->header.cmd) {
		case NGM_PPPOE_GET_STATUS:
		    {
			struct ngPPPoEstat *stats;

			NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
			if (!resp) {
				LEAVE(ENOMEM);
			}
			stats = (struct ngPPPoEstat *) resp->data;
			stats->packets_in = privp->packets_in;
			stats->packets_out = privp->packets_out;
			break;
		    }
		case NGM_PPPOE_CONNECT:
			/*
			 * Check the hook exists and is Uninitialised.
			 * Send a PADI request, and start the timeout logic.
			 * Store the originator of this message so we can send
			 * a success of fail message to them later.
			 * Move the session to SINIT
			 * Set up the session to the correct state and
			 * start it.
			 */
			neg->service.hdr.tag_type = PTT_SRV_NAME;
			neg->service.hdr.tag_len =
					htons((u_int16_t)ourmsg->data_len);
			if (ourmsg->data_len) {
				bcopy(ourmsg->data,
					neg->service.data, ourmsg->data_len);
			}
			neg->service_len = ourmsg->data_len;
			pppoe_start(sp);
			break;
		case NGM_PPPOE_LISTEN:
			/*
			 * Check the hook exists and is Uninitialised.
			 * Install the service matching string.
			 * Store the originator of this message so we can send
			 * a success of fail message to them later.
			 * Move the hook to 'LISTENING'

			 */
			neg->service.hdr.tag_type = PTT_SRV_NAME;
			neg->service.hdr.tag_len =
					htons((u_int16_t)ourmsg->data_len);

			if (ourmsg->data_len) {
				bcopy(ourmsg->data,
					neg->service.data, ourmsg->data_len);
			}
			neg->service_len = ourmsg->data_len;
			neg->pkt->pkt_header.ph.code = PADT_CODE;
			/*
			 * wait for PADI packet coming from ethernet
			 */
			sp->state = PPPOE_LISTENING;
			break;
		case NGM_PPPOE_OFFER:
			/*
			 * Check the hook exists and is Uninitialised.
			 * Store the originator of this message so we can send
			 * a success of fail message to them later.
			 * Store the AC-Name given and go to PRIMED.
			 */
			neg->ac_name.hdr.tag_type = PTT_AC_NAME;
			neg->ac_name.hdr.tag_len =
					htons((u_int16_t)ourmsg->data_len);
			if (ourmsg->data_len) {
				bcopy(ourmsg->data,
					neg->ac_name.data, ourmsg->data_len);
			}
			neg->ac_name_len = ourmsg->data_len;
			neg->pkt->pkt_header.ph.code = PADO_CODE;
			/*
			 * Wait for PADI packet coming from hook
			 */
			sp->state = PPPOE_PRIMED;
			break;
		default:
			LEAVE(EINVAL);
		}
		break;
	default:
		LEAVE(EINVAL);
	}

	/* Take care of synchronous response, if any */
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);

	/* Free the message and return */
quit:
	FREE(msg, M_NETGRAPH);
	return(error);
}

/*
 * Start a client into the first state. A separate function because
 * it can be needed if the negotiation times out.
 */
static void
pppoe_start(sessp sp)
{
	struct {
		struct pppoe_tag hdr;
		union	uniq	data;
	} uniqtag;

	/* 
	 * kick the state machine into starting up
	 */
AAA
	sp->state = PPPOE_SINIT;
	/* reset the packet header to broadcast */
	sp->neg->pkt->pkt_header.eh = eh_prototype;
	sp->neg->pkt->pkt_header.ph.code = PADI_CODE;
	uniqtag.hdr.tag_type = PTT_HOST_UNIQ;
	uniqtag.hdr.tag_len = htons((u_int16_t)sizeof(uniqtag.data));
	uniqtag.data.pointer = sp;
	init_tags(sp);
	insert_tag(sp, &uniqtag.hdr);
	insert_tag(sp, &sp->neg->service.hdr);
	make_packet(sp);
	sendpacket(sp);
}

/*
 * Receive data, and do something with it.
 * The caller will never free m or meta, so
 * if we use up this data or abort we must free BOTH of these.
 */
static int
ng_PPPoE_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	node_p			node = hook->node;
	const priv_p		privp = node->private;
	sessp			sp = hook->private;
	struct pppoe_full_hdr	*wh;
	struct pppoe_hdr	*ph;
	int			error = 0;
	u_int16_t		session;
	u_int16_t		length;
	u_int8_t		code;
	struct pppoe_tag	*tag = NULL;
	hook_p 			sendhook;
	struct {
		struct pppoe_tag hdr;
		union	uniq	data;
	} uniqtag;
	negp			neg = NULL;

AAA
	if (hook->private == &privp->debug_hook) {
		/*
		 * Data from the debug hook gets sent without modification
		 * straight to the ethernet. 
		 */
		NG_SEND_DATA( error, privp->ethernet_hook, m, meta);
	 	privp->packets_out++;
	} else if (hook->private == &privp->ethernet_hook) {
		/*
		 * Incoming data. 
		 * Dig out various fields from the packet.
		 * use them to decide where to send it.
		 */
		
 		privp->packets_in++;
		if( m->m_len < sizeof(*wh)) {
			m = m_pullup(m, sizeof(*wh)); /* Checks length */
			if (m == NULL) {
				printf("couldn't m_pullup\n");
				LEAVE(ENOBUFS);
			}
		}
BBB
		wh = mtod(m, struct pppoe_full_hdr *);
		ph = &wh->ph;
		session = ntohs(wh->ph.sid);
		length = ntohs(wh->ph.length);
		code = wh->ph.code; 
BBB
		switch(wh->eh.ether_type) {
		case	ETHERTYPE_PPPOE_DISC:
			/*
			 * We need to try make sure that the tag area
			 * is contiguous, or we could wander of the end
			 * of a buffer and make a mess. 
			 * (Linux wouldn't have this problem).
			 */
BBB
/*XXX fix this mess */
			
			if (m->m_pkthdr.len <= MHLEN) {
				if( m->m_len < m->m_pkthdr.len) {
					m = m_pullup(m, m->m_pkthdr.len);
					if (m == NULL) {
						printf("couldn't m_pullup\n");
						LEAVE(ENOBUFS);
					}
				}
			}
			if (m->m_len != m->m_pkthdr.len) {
				/*
				 * It's not all in one piece.
				 * We need to do extra work.
				 */
				printf("packet fragmented\n");
				LEAVE(EMSGSIZE);
			 }

BBB
			switch(code) {
			case	PADI_CODE:
BBB
				/*
				 * We are a server:
				 * Look for a hook with the required service
				 * and send the ENTIRE packet up there.
				 * It should come back to a new hook in 
				 * PRIMED state. Look there for further
				 * processing.
				 */
				tag = get_tag(ph, PTT_SRV_NAME);
				if (tag == NULL) {
					printf("no service tag\n");
					LEAVE(ENETUNREACH);
				}
BBB
				sendhook = pppoe_match_svc(hook->node,
			    		tag->tag_data, ntohs(tag->tag_len));
				if (sendhook) {
					NG_SEND_DATA(error, sendhook, m, meta);
				} else {
					printf("no such service\n");
					LEAVE(ENETUNREACH);
				}
BBB
				break;
			case	PADO_CODE:
				/*
				 * We are a client:
				 * Use the host_uniq tag to find the 
				 * hook this is in response to.
				 * Received #2, now send #3
				 * For now simply accept the first we receive.
				 */
BBB
				tag = get_tag(ph, PTT_HOST_UNIQ);
				if ((tag == NULL)
				|| (ntohs(tag->tag_len) != sizeof(sp))) {
					printf("no host unique field\n");
					LEAVE(ENETUNREACH);
				}
BBB

				sendhook = pppoe_finduniq(node, tag);
				if (sendhook == NULL) {
					printf("no matching session\n");
					LEAVE(ENETUNREACH);
				}
BBB

				/*
				 * Check the session is in the right state.
				 * It needs to be in PPPOE_SINIT.
				 */
				sp = sendhook->private;
				if (sp->state != PPPOE_SINIT) {
					printf("session in wrong state\n");
					LEAVE(ENETUNREACH);
				}
				neg = sp->neg;
BBB
				untimeout(pppoe_ticker, sendhook,
				    neg->timeout_handle);

				/*
				 * This is the first time we hear
				 * from the server, so note it's
				 * unicast address, replacing the
				 * broadcast address .
				 */
BBB
				bcopy(wh->eh.ether_shost,
					neg->pkt->pkt_header.eh.ether_dhost,
					ETHER_ADDR_LEN);
				neg->timeout = 0;
				neg->pkt->pkt_header.ph.code = PADR_CODE;
BBB
				init_tags(sp);
BBB
				insert_tag(sp, &neg->service.hdr); /* Service */
BBB
				insert_tag(sp, tag);	      /* Host Unique */
BBB
				tag = get_tag(ph, PTT_AC_COOKIE);
				if (tag)
					insert_tag(sp, tag); /* return cookie */
				scan_tags(sp, ph);
BBB
				make_packet(sp);
				sp->state = PPPOE_SREQ;
BBB
				sendpacket(sp);
BBB
				break;
			case	PADR_CODE:

BBB
				/*
				 * We are a server:
				 * Use the ac_cookie tag to find the 
				 * hook this is in response to.
				 */
				tag = get_tag(ph, PTT_AC_COOKIE);
				if ((tag == NULL)
				|| (ntohs(tag->tag_len) != sizeof(sp))) {
					LEAVE(ENETUNREACH);
				}

BBB
				sendhook = pppoe_finduniq(node, tag);
				if (sendhook == NULL) {
					LEAVE(ENETUNREACH);
				}

BBB
				/*
				 * Check the session is in the right state.
				 * It needs to be in PPPOE_SOFFER
				 * or PPPOE_NEWCONNECTED. If the latter,
				 * then this is a retry by the client.
				 * so be nice, and resend.
				 */
				sp = sendhook->private;
				if (sp->state == PPPOE_NEWCONNECTED) {
					/*
					 * Whoa! drop back to resend that 
					 * PADS packet.
					 * We should still have a copy of it.
					 */
BBB
					sp->state = PPPOE_SOFFER;
				}
BBB
				if (sp->state != PPPOE_SOFFER) {
					LEAVE (ENETUNREACH);
					break;
				}
				neg = sp->neg;
BBB
				untimeout(pppoe_ticker, sendhook,
				    neg->timeout_handle);
				neg->pkt->pkt_header.ph.code = PADS_CODE;
				if (sp->Session_ID == 0)
					neg->pkt->pkt_header.ph.sid =
					    htons(sp->Session_ID
						= get_new_sid(node));
				neg->timeout = 0;
BBB
				/*
				 * start working out the tags to respond with.
				 */
				init_tags(sp);
BBB
				insert_tag(sp, &neg->ac_name.hdr); /* AC_NAME */
				insert_tag(sp, tag);	/* ac_cookie */
				tag = get_tag(ph, PTT_SRV_NAME);
				insert_tag(sp, tag);	/* returned service */
				tag = get_tag(ph, PTT_HOST_UNIQ);
				insert_tag(sp, tag);    /* returned hostuniq */
BBB
				scan_tags(sp, ph);
				make_packet(sp);
				sp->state = PPPOE_NEWCONNECTED;
BBB
				sendpacket(sp);
BBB
				pppoe_send_event(sp, NGM_PPPOE_SUCCESS);
BBB
				/*
				 * Having sent the last Negotiation header,
				 * Set up the stored packet header to 
				 * be correct for the actual session.
				 * But keep the negotialtion stuff
				 * around in case we need to resend this last 
				 * packet. We'll discard it when we move
				 * from NEWCONNECTED to CONNECTED
				 */
				sp->pkt_hdr = neg->pkt->pkt_header;
BBB
				sp->pkt_hdr.eh.ether_type
						= ETHERTYPE_PPPOE_SESS;
				sp->pkt_hdr.ph.code = 0;
				pppoe_send_event(sp, NGM_PPPOE_SUCCESS);
				break;
			case	PADS_CODE:
				/*
				 * We are a client:
				 * Use the host_uniq tag to find the 
				 * hook this is in response to.
				 * take the session ID and store it away.
				 * Also make sure the pre-made header is
				 * correct and set us into Session mode.
				 */
BBB
				tag = get_tag(ph, PTT_HOST_UNIQ);
				if ((tag == NULL)
				|| (ntohs(tag->tag_len) != sizeof(sp))) {
					LEAVE (ENETUNREACH);
					break;
				}
BBB

				sendhook = pppoe_finduniq(node, tag);
				if (sendhook == NULL) {
					LEAVE(ENETUNREACH);
				}

				/*
				 * Check the session is in the right state.
				 * It needs to be in PPPOE_SREQ.
				 */
				sp = sendhook->private;
				if (sp->state != PPPOE_SREQ) {
					LEAVE(ENETUNREACH);
				}
				neg = sp->neg;
BBB
				untimeout(pppoe_ticker, sendhook,
				    neg->timeout_handle);
				sp->Session_ID = ntohs(wh->ph.sid);
				neg->timeout = 0;
				sp->state = PPPOE_CONNECTED;
				sendpacket(sp);
				/*
				 * Now we have gone to Connected mode, 
				 * Free all resources needed for 
				 * negotiation.
				 * Keep a copy of the header we will be using.
				 */
BBB
				sp->pkt_hdr = neg->pkt->pkt_header;
				sp->pkt_hdr.eh.ether_type
						= ETHERTYPE_PPPOE_SESS;
				sp->pkt_hdr.ph.code = 0;
				m_freem(neg->m);
				FREE(sp->neg, M_NETGRAPH);
				sp->neg = NULL;
				pppoe_send_event(sp, NGM_PPPOE_SUCCESS);
				break;
			case	PADT_CODE:
				/*
				 * Send a 'close' message to the controlling
				 * process (the one that set us up);
				 * And then tear everything down.
				 *
				 * Find matching peer/session combination.
				 */
				sendhook = pppoe_findsession(node, wh);
				NG_FREE_DATA(m, meta); /* no longer needed */
				if (sendhook == NULL) {
					LEAVE(ENETUNREACH);
				}
				/* send message to creator */
				/* close hook */
				if (sendhook) {
					ng_destroy_hook(sendhook);
				}
				break;
			default:
				LEAVE(EPFNOSUPPORT);
			}
			break;
		case	ETHERTYPE_PPPOE_SESS:
			/*
			 * find matching peer/session combination.
			 */
			sendhook = pppoe_findsession(node, wh);
			if (sendhook == NULL) {
				LEAVE (ENETUNREACH);
				break;
			}
			m_adj(m, sizeof(*wh));
			if (m->m_pkthdr.len < length) {
				/* Packet too short, dump it */
				LEAVE(EMSGSIZE);
			}
			/* XXX also need to trim excess at end I should think */
			if ( sp->state != PPPOE_CONNECTED) {
				if (sp->state == PPPOE_NEWCONNECTED) {
					sp->state = PPPOE_CONNECTED;
					/*
					 * Now we have gone to Connected mode, 
					 * Free all resources needed for 
					 * negotiation.
					 */
					m_freem(sp->neg->m);
					FREE(sp->neg, M_NETGRAPH);
					sp->neg = NULL;
				} else {
					LEAVE (ENETUNREACH);
					break;
				}
			}
			NG_SEND_DATA( error, sendhook, m, meta);
			break;
		default:
BBB			LEAVE(EPFNOSUPPORT);
		}
	} else {
		/*
		 * 	Not ethernet or debug hook..
		 *
		 * The packet has come in on a normal hook.
		 * We need to find out what kind of hook,
		 * So we can decide how to handle it.
		 * Check the hook's state.
		 */
		sp = hook->private;
		switch (sp->state) {
		case	PPPOE_NEWCONNECTED:
		case	PPPOE_CONNECTED: {
			struct pppoe_full_hdr *wh;
			/*
			 * Bang in a pre-made header, and set the length up
			 * to be correct. Then send it to the ethernet driver.
			 */
			M_PREPEND(m, sizeof(*wh), M_DONTWAIT);
			if (m == NULL) {
				LEAVE(ENOBUFS);
			}
			wh = mtod(m, struct pppoe_full_hdr *);
			bcopy(&sp->pkt_hdr, wh, sizeof(*wh));
			wh->ph.length = htons((short)(m->m_pkthdr.len));
			NG_SEND_DATA( error, privp->ethernet_hook, m, meta);
			privp->packets_out++;
			break;
			}
		case	PPPOE_PRIMED:
			/*
			 * A PADI packet is being returned by the application
			 * that has set up this hook. This indicates that it 
			 * wants us to offer service.
			 */
			neg = sp->neg;
			m_pullup(m, sizeof(*wh)); /* Checks length */
			if (m == NULL) {
				LEAVE(ENOBUFS);
			}
			wh = mtod(m, struct pppoe_full_hdr *);
			ph = &wh->ph;
			session = ntohs(wh->ph.sid);
			length = ntohs(wh->ph.length);
			code = wh->ph.code; 
			if ( code != PADI_CODE) {
				LEAVE(EINVAL);
			};
			untimeout(pppoe_ticker, hook,
				    neg->timeout_handle);

			/*
			 * This is the first time we hear
			 * from the client, so note it's
			 * unicast address, replacing the
			 * broadcast address .
			 */
			bcopy(wh->eh.ether_shost,
				neg->pkt->pkt_header.eh.ether_dhost,
				ETHER_ADDR_LEN);
			sp->state = PPPOE_SOFFER;
			neg->timeout = 0;
			neg->pkt->pkt_header.ph.code = PADO_CODE;

			/*
			 * start working out the tags to respond with.
			 */
			uniqtag.hdr.tag_type = PTT_AC_COOKIE;
			uniqtag.hdr.tag_len = htons((u_int16_t)sizeof(sp));
			uniqtag.data.pointer = sp;
			init_tags(sp);
			insert_tag(sp, &neg->ac_name.hdr); /* AC_NAME */
			insert_tag(sp, tag);	      /* returned hostunique */
			insert_tag(sp, &uniqtag.hdr);      /* AC cookie */
			tag = get_tag(ph, PTT_SRV_NAME);
			insert_tag(sp, tag);	      /* returned service */
			/* XXX maybe put the tag in the session store */
			scan_tags(sp, ph);
			make_packet(sp);
			sendpacket(sp);
			break;

		/*
		 * Packets coming from the hook make no sense
		 * to sessions in these states. Throw them away.
		 */
		case	PPPOE_SINIT:
		case	PPPOE_SREQ:
		case	PPPOE_SOFFER:
		case	PPPOE_SNONE:
		case	PPPOE_LISTENING:
		case	PPPOE_DEAD:
		default:
			LEAVE(ENETUNREACH);
		}
	}
quit:
	NG_FREE_DATA(m, meta);
	return error;
}

/*
 * Do local shutdown processing..
 * If we are a persistant device, we might refuse to go away, and
 * we'd only remove our links and reset ourself.
 */
static int
ng_PPPoE_rmnode(node_p node)
{
	const priv_p privdata = node->private;

AAA
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);
	node->private = NULL;
	ng_unref(privdata->node);
	FREE(privdata, M_NETGRAPH);
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_PPPoE_connect(hook_p hook)
{
	/* be really amiable and just say "YUP that's OK by me! " */
	return (0);
}

/*
 * Hook disconnection
 *
 * Clean up all dangling links and infirmation about the session/hook.
 * For this type, removal of the last link destroys the node
 */
static int
ng_PPPoE_disconnect(hook_p hook)
{
	node_p node = hook->node;
	priv_p privp = node->private;
	sessp	sp;

AAA
	if (hook->private == &privp->debug_hook) {
		privp->debug_hook = NULL;
	} else if (hook->private == &privp->ethernet_hook) {
		privp->ethernet_hook = NULL;
	} else {
		sp = hook->private;
		if (sp->state != PPPOE_SNONE ) {
			pppoe_send_event(sp, NGM_PPPOE_CLOSE);
		}
		if (sp->neg) {
			untimeout(pppoe_ticker, hook, sp->neg->timeout_handle);
			if (sp->neg->m)
				m_freem(sp->neg->m);
			FREE(sp->neg, M_NETGRAPH);
		}
		FREE(sp, M_NETGRAPH);
		hook->private = NULL;
	}
	if (node->numhooks == 0)
		ng_rmnode(node);
	return (0);
}

/*
 * timeouts come here.
 */
static void
pppoe_ticker(void *arg)
{
	int s = splnet();
	hook_p hook = arg;
	sessp	sp = hook->private;
	negp	neg = sp->neg;
	int	error = 0;
	struct mbuf *m0 = NULL;
	priv_p privp = hook->node->private;
	meta_p dummy = NULL;

AAA
	switch(sp->state) {
		/*
		 * resend the last packet, using an exponential backoff.
		 * After a period of time, stop growing the backoff,
		 * and either leave it, or reverst to the start.
		 */
	case	PPPOE_SINIT:
	case	PPPOE_SREQ:
		/* timeouts on these produce resends */
		m0 = m_copypacket(sp->neg->m, M_DONTWAIT);
		NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
		neg->timeout_handle = timeout(pppoe_ticker,
					hook, neg->timeout * hz);
		if ((neg->timeout <<= 1) > PPPOE_TIMEOUT_LIMIT) {
			if (sp->state == PPPOE_SREQ) {
				/* revert to SINIT mode */
				pppoe_start(sp);
			} else {
				neg->timeout = PPPOE_TIMEOUT_LIMIT;
			}
		}
		break;
	case	PPPOE_PRIMED:
	case	PPPOE_SOFFER:
		/* a timeout on these says "give up" */
		ng_destroy_hook(hook);
		break;
	default:
		/* timeouts have no meaning in other states */
		printf("pppoe: unexpected timeout\n");
	}
	splx(s);
}


static void
sendpacket(sessp sp)
{
	int	error = 0;
	struct mbuf *m0 = NULL;
	hook_p hook = sp->hook;
	negp	neg = sp->neg;
	priv_p	privp = hook->node->private;
	meta_p dummy = NULL;

AAA
	switch(sp->state) {
	case	PPPOE_LISTENING:
	case	PPPOE_DEAD:
	case	PPPOE_SNONE:
	case	PPPOE_NEWCONNECTED:
	case	PPPOE_CONNECTED:
		printf("pppoe: sendpacket: unexpected state\n");
		break;

	case	PPPOE_PRIMED:
		/* No packet to send, but set up the timeout */
		neg->timeout_handle = timeout(pppoe_ticker,
					hook, PPPOE_OFFER_TIMEOUT * hz);
		break;

	case	PPPOE_SOFFER:
		/*
		 * send the offer but if they don't respond
		 * in PPPOE_OFFER_TIMEOUT seconds, forget about it.
		 */
		m0 = m_copypacket(sp->neg->m, M_DONTWAIT);
		NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
		neg->timeout_handle = timeout(pppoe_ticker,
					hook, PPPOE_OFFER_TIMEOUT * hz);
		break;

	case	PPPOE_SINIT:
	case	PPPOE_SREQ:
		m0 = m_copypacket(sp->neg->m, M_DONTWAIT);
		NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
		neg->timeout_handle = timeout(pppoe_ticker, hook, hz);
		neg->timeout = 2;
		break;

	default:
		error = EINVAL;
		printf("pppoe: timeout: bad state\n");
	}
	/* return (error); */
}

/*
 * Parse an incoming packet to see if any tags should be copied to the
 * output packet. DOon't do any tags that are likely to have been
 * handles a the main state machine.
 */
static struct pppoe_tag* 
scan_tags(sessp	sp, struct pppoe_hdr* ph)
{
	char *end = (char *)next_tag(ph);
	char *ptn;
	struct pppoe_tag *pt = &ph->tag[0];
	/*
	 * Keep processing tags while a tag header will still fit.
	 */
AAA
	while((char*)(pt + 1) <= end) {
		/*
		 * If the tag data would go past the end of the packet, abort.
		 */
		ptn = (((char *)(pt + 1)) + ntohs(pt->tag_len));
		if(ptn > end)
			return NULL;

		switch (pt->tag_type) {
		case	PTT_RELAY_SID:
			insert_tag(sp, pt);
			break;
		case	PTT_EOL:
			return NULL;
		case	PTT_SRV_NAME:
		case	PTT_AC_NAME:
		case	PTT_HOST_UNIQ:
		case	PTT_AC_COOKIE:
		case	PTT_VENDOR:
		case	PTT_SRV_ERR:
		case	PTT_SYS_ERR:
		case	PTT_GEN_ERR:
			break;
		}
		pt = (struct pppoe_tag*)ptn;
	}
	return NULL;
}
	
static	int
pppoe_send_event(sessp sp, enum cmd cmdid)
{
	int error;
	struct ng_mesg *msg;
	struct ngPPPoE_sts *sts;

AAA
	NG_MKMESSAGE(msg, NGM_PPPOE_COOKIE, cmdid,
			sizeof(struct ngPPPoE_sts), M_NOWAIT);
	sts = (struct ngPPPoE_sts *)msg->data;
	strncpy(sts->hook, sp->hook->name, NG_HOOKLEN + 1);
	error = ng_send_msg(sp->hook->node, msg, sp->creator, NULL);
	return (error);
}
