
/*
 * ng_hole.c
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
 * Author: Julian Elisher <julian@freebsd.org>
 *
 * $FreeBSD$
 * $Whistle: ng_hole.c,v 1.10 1999/11/01 09:24:51 julian Exp $
 */

/*
 * This node is a 'black hole' that simply discards everything it receives
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_hole.h>

/* Netgraph methods */
static ng_constructor_t	ngh_cons;
static ng_rcvdata_t	ngh_rcvdata;
static ng_disconnect_t	ngh_disconnect;

static struct ng_type typestruct = {
	NG_ABI_VERSION,
	NG_HOLE_NODE_TYPE,
	NULL,		/* modeventhand_t */
	ngh_cons,	/* ng_constructor_t */
	NULL,		/* ng_rcvmsg_t */
	NULL,		/* ng_shutdown_t */
	NULL,		/* ng_newhook_t */
	NULL,		/* ng_findhook_t */
	NULL,		/* ng_connect_t */
	ngh_rcvdata,	/* ng_rcvdata_t */
	ngh_disconnect,	/* ng_disconnect_t */
	NULL		/* ng_cmdlist */
};
NETGRAPH_INIT(hole, &typestruct);

/* 
 * Be obliging. but no work to do.
 */
static int
ngh_cons(node_p node)
{
	return(0);
}

/*
 * Receive data
 */
static int
ngh_rcvdata(hook_p hook, item_p item)
{
	NG_FREE_ITEM(item);
	return 0;
}

/*
 * Hook disconnection
 */
static int
ngh_disconnect(hook_p hook)
{
	if (hook->node->numhooks == 0)
		ng_rmnode_self(hook->node);
	return (0);
}
