/*
 * netgraph.h
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
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD$
 * $Whistle: netgraph.h,v 1.29 1999/11/01 07:56:13 julian Exp $
 */

#ifndef _NETGRAPH_NETGRAPH_H_
#define _NETGRAPH_NETGRAPH_H_ 1

#ifndef _KERNEL
#error "This file should not be included in user level programs"
#endif

#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
/* debugging options */
#define NETGRAPH_DEBUG 
#define NG_SEPARATE_MALLOC	/* make modules use their own malloc types */

/*
 * This defines the in-kernel binary interface version.
 * It is possible to change this but leave the external message
 * API the same. Each type also has it's own cookies for versioning as well.
 * Change it for NETGRAPH_DEBUG version so we cannot mix debug and non debug
 * modules.
 */
#define _NG_ABI_VERSION 5
#ifdef	NETGRAPH_DEBUG /*----------------------------------------------*/
#define NG_ABI_VERSION	(_NG_ABI_VERSION + 0x10000)
#else	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/
#define NG_ABI_VERSION	_NG_ABI_VERSION
#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/


/*
 * Forward references for the basic structures so we can
 * define the typedefs and use them in the structures themselves.
 */
struct ng_hook ;
struct ng_node ;
struct ng_item ;
typedef	struct ng_item *item_p;
typedef struct ng_node *node_p;
typedef struct ng_hook *hook_p;

/***********************************************************************
 ***************** Hook Structure and Methods **************************
 ***********************************************************************
 *
 * Structure of a hook
 */
struct ng_hook {
	char	hk_name[NG_HOOKLEN+1];	/* what this node knows this link as */
	void   *hk_private;		/* node dependant ID for this hook */
	int	hk_flags;		/* info about this hook/link */
	int	hk_refs;		/* dont actually free this till 0 */
	struct	ng_hook *hk_peer;	/* the other end of this link */
	struct	ng_node *hk_node;	/* The node this hook is attached to */
	LIST_ENTRY(ng_hook) hk_hooks;	/* linked list of all hooks on node */
#ifdef	NETGRAPH_DEBUG /*----------------------------------------------*/
#define HK_MAGIC 0x78573011
	int	hk_magic;
	char	*lastfile;
	int	lastline;
	SLIST_ENTRY(ng_hook)	  hk_all;		/* all existing items */
#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/
};
/* Flags for a hook */
#define HK_INVALID		0x0001	/* don't trust it! */
#define HK_QUEUE		0x0002	/* queue for later delivery */
#define HK_FORCE_WRITER		0x0004	/* Incoming data queued as a writer */

/*
 * Public Methods for hook
 * If you can't do it with these you probably shouldn;t be doing it.
 */
void ng_unref_hook(hook_p hook); /* don't move this */
#define	_NG_HOOK_REF(hook)	atomic_add_int(&(hook)->hk_refs, 1)
#define _NG_HOOK_NAME(hook)	((hook)->hk_name)
#define _NG_HOOK_UNREF(hook)	ng_unref_hook(hook)
#define	_NG_HOOK_SET_PRIVATE(hook, val)	do {(hook)->hk_private = val;} while (0)
#define	_NG_HOOK_PRIVATE(hook)	((hook)->hk_private)
#define _NG_HOOK_NOT_VALID(hook)	((hook)->hk_flags & HK_INVALID)
#define _NG_HOOK_IS_VALID(hook)	(!(hook)->hk_flags & HK_INVALID)
#define _NG_HOOK_NODE(hook)	((hook)->hk_node) /* only rvalue! */
#define _NG_HOOK_PEER(hook)	((hook)->hk_peer) /* only rvalue! */
#define _NG_HOOK_FORCE_WRITER(hook)				\
		do { hook->hk_flags |= HK_FORCE_WRITER; } while (0)
#define _NG_HOOK_FORCE_QUEUE(hook) do { hook->hk_flags |= HK_QUEUE; } while (0)

/* Some shortcuts */
#define NG_PEER_NODE(hook)	NG_HOOK_NODE(NG_HOOK_PEER(hook))
#define NG_PEER_HOOK_NAME(hook)	NG_HOOK_NAME(NG_HOOK_PEER(hook))
#define NG_PEER_NODE_NAME(hook)	NG_NODE_NAME(NG_PEER_NODE(hook))

#ifdef	NETGRAPH_DEBUG /*----------------------------------------------*/
#define _NN_ __FILE__,__LINE__
void	dumphook (hook_p hook, char *file, int line);
static __inline void	_chkhook(hook_p hook, char *file, int line);
static __inline void	_ng_hook_ref(hook_p hook, char * file, int line);
static __inline char *	_ng_hook_name(hook_p hook, char * file, int line);
static __inline void	_ng_hook_unref(hook_p hook, char * file, int line);
static __inline void	_ng_hook_set_private(hook_p hook,
					void * val, char * file, int line);
static __inline void *	_ng_hook_private(hook_p hook, char * file, int line);
static __inline int	_ng_hook_not_valid(hook_p hook, char * file, int line);
static __inline int	_ng_hook_is_valid(hook_p hook, char * file, int line);
static __inline node_p	_ng_hook_node(hook_p hook, char * file, int line);
static __inline hook_p	_ng_hook_peer(hook_p hook, char * file, int line);
static __inline void	_ng_hook_force_writer(hook_p hook, char * file,
					int line);
static __inline void	_ng_hook_force_queue(hook_p hook, char * file, int line);

static void __inline 
_chkhook(hook_p hook, char *file, int line)
{
	if (hook->hk_magic != HK_MAGIC) {
		printf("Accessing freed hook ");
		dumphook(hook, file, line);
	}
	hook->lastline = line;
	hook->lastfile = file;
}

static __inline void
_ng_hook_ref(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	_NG_HOOK_REF(hook);
} 

static __inline char *
_ng_hook_name(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	return (_NG_HOOK_NAME(hook));
} 

static __inline void
_ng_hook_unref(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	_NG_HOOK_UNREF(hook);
} 

static __inline void
_ng_hook_set_private(hook_p hook, void *val, char * file, int line)
{
	_chkhook(hook, file, line);
	_NG_HOOK_SET_PRIVATE(hook, val);
} 

static __inline void *
_ng_hook_private(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	return (_NG_HOOK_PRIVATE(hook));
} 

static __inline int
_ng_hook_not_valid(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	return (_NG_HOOK_NOT_VALID(hook));
} 

static __inline int
_ng_hook_is_valid(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	return (_NG_HOOK_IS_VALID(hook));
} 

static __inline node_p
_ng_hook_node(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	return (_NG_HOOK_NODE(hook));
} 

static __inline hook_p
_ng_hook_peer(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	return (_NG_HOOK_PEER(hook));
} 

static __inline void
_ng_hook_force_writer(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	_NG_HOOK_FORCE_WRITER(hook);
} 

static __inline void
_ng_hook_force_queue(hook_p hook, char * file, int line)
{
	_chkhook(hook, file, line);
	_NG_HOOK_FORCE_QUEUE(hook);
} 


#define	NG_HOOK_REF(hook)		_ng_hook_ref(hook, _NN_)
#define NG_HOOK_NAME(hook)		_ng_hook_name(hook, _NN_)
#define NG_HOOK_UNREF(hook)		_ng_hook_unref(hook, _NN_)
#define	NG_HOOK_SET_PRIVATE(hook, val)	_ng_hook_set_private(hook, val, _NN_)
#define	NG_HOOK_PRIVATE(hook)		_ng_hook_private(hook, _NN_)
#define NG_HOOK_NOT_VALID(hook)		_ng_hook_not_valid(hook, _NN_)
#define NG_HOOK_IS_VALID(hook)		_ng_hook_is_valid(hook, _NN_)
#define NG_HOOK_NODE(hook)		_ng_hook_node(hook, _NN_)
#define NG_HOOK_PEER(hook)		_ng_hook_peer(hook, _NN_)
#define NG_HOOK_FORCE_WRITER(hook)	_ng_hook_force_writer(hook, _NN_)
#define NG_HOOK_FORCE_QUEUE(hook)	_ng_hook_force_queue(hook, _NN_)

#else	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/

#define	NG_HOOK_REF(hook)		_NG_HOOK_REF(hook)
#define NG_HOOK_NAME(hook)		_NG_HOOK_NAME(hook)
#define NG_HOOK_UNREF(hook)		_NG_HOOK_UNREF(hook)
#define	NG_HOOK_SET_PRIVATE(hook, val)	_NG_HOOK_SET_PRIVATE(hook, val)
#define	NG_HOOK_PRIVATE(hook)		_NG_HOOK_PRIVATE(hook)
#define NG_HOOK_NOT_VALID(hook)		_NG_HOOK_NOT_VALID(hook)
#define NG_HOOK_IS_VALID(hook)		_NG_HOOK_IS_VALID(hook)
#define NG_HOOK_NODE(hook)		_NG_HOOK_NODE(hook)
#define NG_HOOK_PEER(hook)		_NG_HOOK_PEER(hook)
#define NG_HOOK_FORCE_WRITER(hook)	_NG_HOOK_FORCE_WRITER(hook)
#define NG_HOOK_FORCE_QUEUE(hook)	_NG_HOOK_FORCE_QUEUE(hook)

#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/

/***********************************************************************
 ***************** Node Structure and Methods **************************
 ***********************************************************************
 * Structure of a node
 * including the eembedded queue structure.
 *
 * The structure for queueing Netgraph request items 
 * embedded in the node structure
 */
struct ng_queue {
	u_long          q_flags;
	struct mtx      q_mtx;
	item_p queue;
	item_p *last;
	struct ng_node *q_node;		/* find the front of the node.. */
};

struct ng_node {
	char	nd_name[NG_NODELEN+1];	/* optional globally unique name */
	struct	ng_type *nd_type;	/* the installed 'type' */
	int	nd_flags;		/* see below for bit definitions */
	int	nd_refs;		/* # of references to this node */
	int	nd_numhooks;		/* number of hooks */
	void   *nd_private;		/* node type dependant node ID */
	ng_ID_t	nd_ID;			/* Unique per node */
	LIST_HEAD(hooks, ng_hook) nd_hooks;	/* linked list of node hooks */
	LIST_ENTRY(ng_node)	  nd_nodes;	/* linked list of all nodes */
	LIST_ENTRY(ng_node)	  nd_idnodes;	/* ID hash collision list */
	TAILQ_ENTRY(ng_node)	  nd_work;	/* nodes with work to do */
	struct	ng_queue	  nd_input_queue; /* input queue for locking */
#ifdef	NETGRAPH_DEBUG /*----------------------------------------------*/
#define ND_MAGIC 0x59264837
	int	nd_magic;
	char	*lastfile;
	int	lastline;
	SLIST_ENTRY(ng_node)	  nd_all;	/* all existing nodes */
#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/
};

/* Flags for a node */
#define NG_INVALID	0x00000001	/* free when refs go to 0 */
#define NG_WORKQ	0x00000002	/* node is on the work queue */
#define NG_FORCE_WRITER	0x00000004	/* Never multithread this node */
#define NG_CLOSING	0x00000008	/* ng_rmnode() at work */
#define NGF_TYPE1	0x10000000	/* reserved for type specific storage */
#define NGF_TYPE2	0x20000000	/* reserved for type specific storage */
#define NGF_TYPE3	0x40000000	/* reserved for type specific storage */
#define NGF_TYPE4	0x80000000	/* reserved for type specific storage */

/*
 * Public methods for nodes.
 * If you can't do it with these you probably shouldn't be doing it.
 */
void	ng_unref_node(node_p node); /* don't move this */
#define _NG_NODE_NAME(node)	((node)->nd_name + 0)
#define _NG_NODE_HAS_NAME(node)	((node)->nd_name[0] + 0)
#define _NG_NODE_ID(node)	((node)->nd_ID + 0)
#define	_NG_NODE_REF(node)	atomic_add_int(&(node)->nd_refs, 1)
#define	_NG_NODE_UNREF(node)	ng_unref_node(node)
#define	_NG_NODE_SET_PRIVATE(node, val)	do {(node)->nd_private = val;} while (0)
#define	_NG_NODE_PRIVATE(node)	((node)->nd_private)
#define _NG_NODE_IS_VALID(node)	(!((node)->nd_flags & NG_INVALID))
#define _NG_NODE_NOT_VALID(node)	((node)->nd_flags & NG_INVALID)
#define _NG_NODE_NUMHOOKS(node)	((node)->nd_numhooks + 0) /* rvalue */
#define _NG_NODE_FORCE_WRITER(node)					\
	do{ node->nd_flags |= NG_FORCE_WRITER; }while (0)
/*
 * The hook iterator.
 * This macro will call a function of type ng_fn_eachhook for each
 * hook attached to the node. If the function returns 0, then the
 * iterator will stop and return a pointer to the hook that returned 0.
 */
typedef	int	ng_fn_eachhook(hook_p hook, void* arg);
#define _NG_NODE_FOREACH_HOOK(node, fn, arg, rethook)			\
	do {								\
		hook_p hook;						\
		LIST_FOREACH(hook, &((node)->nd_hooks), hk_hooks) {	\
			if ((fn)(hook, arg) == 0) {			\
				(rethook) = hook;			\
				break;					\
			}						\
		}							\
	} while (0)

#ifdef	NETGRAPH_DEBUG /*----------------------------------------------*/
void	dumpnode(node_p node, char *file, int line);
static void __inline _chknode(node_p node, char *file, int line);
static __inline char * _ng_node_name(node_p node, char *file, int line);
static __inline int _ng_node_has_name(node_p node, char *file, int line);
static __inline ng_ID_t _ng_node_id(node_p node, char *file, int line);
static __inline void _ng_node_ref(node_p node, char *file, int line);
static __inline void _ng_node_unref(node_p node, char *file, int line);
static __inline void _ng_node_set_private(node_p node, void * val,
							char *file, int line);
static __inline void * _ng_node_private(node_p node, char *file, int line);
static __inline int _ng_node_is_valid(node_p node, char *file, int line);
static __inline int _ng_node_not_valid(node_p node, char *file, int line);
static __inline int _ng_node_numhooks(node_p node, char *file, int line);
static __inline void _ng_node_force_writer(node_p node, char *file, int line);
static __inline hook_p _ng_node_foreach_hook(node_p node,
			ng_fn_eachhook *fn, void *arg, char *file, int line);

static void __inline 
_chknode(node_p node, char *file, int line)
{
	if (node->nd_magic != ND_MAGIC) {
		printf("Accessing freed node ");
		dumpnode(node, file, line);
	}
	node->lastline = line;
	node->lastfile = file;
}

static __inline char *
_ng_node_name(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return(_NG_NODE_NAME(node));
}

static __inline int 
_ng_node_has_name(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return(_NG_NODE_HAS_NAME(node));
}

static __inline ng_ID_t
_ng_node_id(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return(_NG_NODE_ID(node));
}

static __inline void 
_ng_node_ref(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	_NG_NODE_REF(node);
}

static __inline void
_ng_node_unref(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	_NG_NODE_UNREF(node);
}

static __inline void
_ng_node_set_private(node_p node, void * val, char *file, int line)
{
	_chknode(node, file, line);
	_NG_NODE_SET_PRIVATE(node, val);
}

static __inline void *
_ng_node_private(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return (_NG_NODE_PRIVATE(node));
}

static __inline int
_ng_node_is_valid(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return(_NG_NODE_IS_VALID(node));
}

static __inline int
_ng_node_not_valid(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return(_NG_NODE_NOT_VALID(node));
}

static __inline int
_ng_node_numhooks(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	return(_NG_NODE_NUMHOOKS(node));
}

static __inline void
_ng_node_force_writer(node_p node, char *file, int line)
{
	_chknode(node, file, line);
	_NG_NODE_FORCE_WRITER(node);
}

static __inline hook_p
_ng_node_foreach_hook(node_p node, ng_fn_eachhook *fn, void *arg,
						char *file, int line)
{
	hook_p hook;
	_chknode(node, file, line);
	_NG_NODE_FOREACH_HOOK(node, fn, arg, hook);
	return (hook);
}

#define NG_NODE_NAME(node)		_ng_node_name(node, _NN_)	
#define NG_NODE_HAS_NAME(node)		_ng_node_has_name(node, _NN_)	
#define NG_NODE_ID(node)		_ng_node_id(node, _NN_)
#define NG_NODE_REF(node)		_ng_node_ref(node, _NN_)
#define	NG_NODE_UNREF(node)		_ng_node_unref(node, _NN_)
#define	NG_NODE_SET_PRIVATE(node, val)	_ng_node_set_private(node, val, _NN_)
#define	NG_NODE_PRIVATE(node)		_ng_node_private(node, _NN_)
#define NG_NODE_IS_VALID(node)		_ng_node_is_valid(node, _NN_)
#define NG_NODE_NOT_VALID(node)		_ng_node_not_valid(node, _NN_)
#define NG_NODE_FORCE_WRITER(node) 	_ng_node_force_writer(node, _NN_)
#define NG_NODE_NUMHOOKS(node)		_ng_node_numhooks(node, _NN_)
#define NG_NODE_FOREACH_HOOK(node, fn, arg, rethook)			      \
	do {								      \
		rethook = _ng_node_foreach_hook(node, fn, (void *)arg, _NN_); \
	} while (0)

#else	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/

#define NG_NODE_NAME(node)		_NG_NODE_NAME(node)	
#define NG_NODE_HAS_NAME(node)		_NG_NODE_HAS_NAME(node)	
#define NG_NODE_ID(node)		_NG_NODE_ID(node)	
#define	NG_NODE_REF(node)		_NG_NODE_REF(node)	
#define	NG_NODE_UNREF(node)		_NG_NODE_UNREF(node)	
#define	NG_NODE_SET_PRIVATE(node, val)	_NG_NODE_SET_PRIVATE(node, val)	
#define	NG_NODE_PRIVATE(node)		_NG_NODE_PRIVATE(node)	
#define NG_NODE_IS_VALID(node)		_NG_NODE_IS_VALID(node)	
#define NG_NODE_NOT_VALID(node)		_NG_NODE_NOT_VALID(node)	
#define NG_NODE_FORCE_WRITER(node) 	_NG_NODE_FORCE_WRITER(node)
#define NG_NODE_NUMHOOKS(node)		_NG_NODE_NUMHOOKS(node)	
#define NG_NODE_FOREACH_HOOK(node, fn, arg, rethook)			\
		_NG_NODE_FOREACH_HOOK(node, fn, arg, rethook)
#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/

/***********************************************************************
 ***************** Meta Data Structures and Methods ********************
 ***********************************************************************
 *
 * The structure that holds meta_data about a data packet (e.g. priority)
 * Nodes might add or subtract options as needed if there is room.
 * They might reallocate the struct to make more room if they need to.
 * Meta-data is still experimental.
 */
struct meta_field_header {
	u_long	cookie;		/* cookie for the field. Skip fields you don't
				 * know about (same cookie as in messgaes) */
	u_short type;		/* field ID */
	u_short len;		/* total len of this field including extra
				 * data */
	char	data[0];	/* data starts here */
};

/* To zero out an option 'in place' set it's cookie to this */
#define NGM_INVALID_COOKIE	865455152

/* This part of the metadata is always present if the pointer is non NULL */
struct ng_meta {
	char	priority;	/* -ve is less priority,  0 is default */
	char	discardability; /* higher is less valuable.. discard first */
	u_short allocated_len;	/* amount malloc'd */
	u_short used_len;	/* sum of all fields, options etc. */
	u_short flags;		/* see below.. generic flags */
	struct meta_field_header options[0];	/* add as (if) needed */
};
typedef struct ng_meta *meta_p;

/* Flags for meta-data */
#define NGMF_TEST	0x01	/* discard at the last moment before sending */
#define NGMF_TRACE	0x02	/* trace when handing this data to a node */

/***********************************************************************
 ************* Node Queue and Item Structures and Methods **************
 ***********************************************************************
 *
 */
struct ng_item {
	u_long	el_flags;
	item_p	el_next;
	node_p	el_dest; /* The node it will be applied against (or NULL) */
	hook_p	el_hook; /* Entering hook. Optional in Control messages */
	union {
		struct {
			struct mbuf	*da_m;
			meta_p		da_meta;
		} data;
		struct {
			struct ng_mesg	*msg_msg;
			ng_ID_t		msg_retaddr;
		} msg;
	} body;
#ifdef	NETGRAPH_DEBUG /*----------------------------------------------*/
	char *lastfile;
	int  lastline;
	TAILQ_ENTRY(ng_item)	  all;		/* all existing items */
#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/
};
#define NGQF_D_M	0x01		/* MASK of data/message */
#define NGQF_DATA	0x01		/* the queue element is data */
#define NGQF_MESG	0x00		/* the queue element is a message */
#define NGQF_TYPE	0x02		/*  MASK for queue entry type */
#define NGQF_READER	0x02		/* queued as a reader */
#define NGQF_WRITER	0x00		/* queued as a writer */
#define NGQF_FREE	0x04

/*
 * Get the mbuf (etc) out of an item.
 * Sets the value in the item to NULL in case we need to call NG_FREE_ITEM()
 * with it, (to avoid freeing the things twice).
 * If you don't want to zero out the item then realise that the
 * item still owns it.
 * Retaddr is different. There are no references on that. It's just a number.
 * The debug versions must be either all used everywhere or not at all.
 */

#define _NGI_M(i) ((i)->body.data.da_m)
#define _NGI_META(i) ((i)->body.data.da_meta)
#define _NGI_MSG(i) ((i)->body.msg.msg_msg)
#define _NGI_RETADDR(i) ((i)->body.msg.msg_retaddr)

#ifdef NETGRAPH_DEBUG /*----------------------------------------------*/
void				dumpitem(item_p item, char *file, int line);
static __inline void		_ngi_check(item_p item, char *file, int line) ;
static __inline struct mbuf **	_ngi_m(item_p item, char *file, int line) ;
static __inline meta_p *	_ngi_meta(item_p item, char *file, int line) ;
static __inline ng_ID_t *	_ngi_retaddr(item_p item, char *file,
							int line) ;
static __inline struct ng_mesg **	_ngi_msg(item_p item, char *file,
							int line) ;

static __inline void
_ngi_check(item_p item, char *file, int line) 
{
	if (item->el_flags & NGQF_FREE) {
		dumpitem(item, file, line);
		panic ("free item!");
	}
	(item)->lastline = line;
	(item)->lastfile = file;
}

static __inline struct mbuf **
_ngi_m(item_p item, char *file, int line) 
{
	_ngi_check(item, file, line);
	return (&_NGI_M(item));
}

static __inline meta_p *
_ngi_meta(item_p item, char *file, int line) 
{
	_ngi_check(item, file, line);
	return (&_NGI_META(item));
}

static __inline struct ng_mesg **
_ngi_msg(item_p item, char *file, int line) 
{
	_ngi_check(item, file, line);
	return (&_NGI_MSG(item));
}

static __inline ng_ID_t *
_ngi_retaddr(item_p item, char *file, int line) 
{
	_ngi_check(item, file, line);
	return (&_NGI_RETADDR(item));
}

#define NGI_M(i) (*_ngi_m(i, _NN_))

#define NGI_META(i) (*_ngi_meta(i, _NN_))

#define NGI_MSG(i) (*_ngi_msg(i, _NN_))

#define NGI_RETADDR(i) (*_ngi_retaddr(i, _NN_))

#define NGI_GET_M(i,m)							\
	do {								\
		m = NGI_M(i);						\
		_NGI_M(i) = NULL;					\
	} while (0)

#define NGI_GET_META(i,m)						\
	do {								\
		m = NGI_META(i);					\
		_NGI_META(i) = NULL;					\
	} while (0)

#define NGI_GET_MSG(i,m)						\
	do {								\
		m = NGI_MSG(i);						\
		_NGI_MSG(i) = NULL;					\
	} while (0)

#define NG_FREE_ITEM(item)						\
	do {								\
		_ngi_check(item, _NN_);					\
		ng_free_item((item));					\
	} while (0)

#define	SAVE_LINE(item)							\
	do {								\
		(item)->lastline = __LINE__;				\
		(item)->lastfile = __FILE__;				\
	} while (0)

#else	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/

#define NGI_M(i)	_NGI_M(i)
#define NGI_META(i)	_NGI_META(i)
#define NGI_MSG(i)	_NGI_MSG(i)
#define NGI_RETADDR(i)	_NGI_RETADDR(i)

#define NGI_GET_M(i,m)       do {m = NGI_M(i); NGI_M(i) = NULL;      } while (0)
#define NGI_GET_META(i,m)    do {m = NGI_META(i); NGI_META(i) = NULL;} while (0)
#define NGI_GET_MSG(i,m)     do {m = NGI_MSG(i); NGI_MSG(i) = NULL;  } while (0)

#define	NG_FREE_ITEM(item)	ng_free_item((item))
#define	SAVE_LINE(item)		do {} while (0)

#endif	/* NETGRAPH_DEBUG */ /*----------------------------------------------*/
	
/**********************************************************************
* Data macros.  Send, manipulate and free.
**********************************************************************/
/* Send previously unpackeged data and metadata. */
#define NG_SEND_DATA(error, hook, m, meta)				\
	do {								\
		item_p item;						\
		if ((item = ng_package_data((m), (meta)))) {		\
			if (!((error) = ng_address_hook(NULL, item,	\
							hook, NULL))) {	\
				SAVE_LINE(item);			\
				(error) = ng_snd_item((item), 0);	\
			}						\
		} else {						\
			(error) = ENOMEM;				\
		}							\
		(m) = NULL;						\
		(meta) = NULL;						\
	} while (0)

/* Send a previously unpackaged mbuf when we have no metadata to send */
#define NG_SEND_DATA_ONLY(error, hook, m)				\
	do {								\
		item_p item;						\
		if ((item = ng_package_data((m), NULL))) {		\
			if (!((error) = ng_address_hook(NULL, item,	\
							hook, NULL))) {	\
				SAVE_LINE(item);			\
				(error) = ng_snd_item((item), 0);	\
			}						\
		} else {						\
			(error) = ENOMEM;				\
		}							\
		(m) = NULL;						\
	} while (0)

/*
 * Forward a data packet with no new meta-data.
 * old metadata is passed along without change.
 * Mbuf pointer is updated to new value. We presume you dealt with the
 * old one when you update it to the new one (or it maybe the old one).
 * We got a packet and possibly had to modify the mbuf.
 * You should probably use NGI_GET_M() if you are going to use this too
 */
#define NG_FWD_NEW_DATA(error, item, hook, m)				\
	do {								\
		NGI_M(item) = m;					\
		if (!((error) = ng_address_hook(NULL, (item),		\
						(hook), NULL))) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 0);		\
		}							\
		(item) = NULL;						\
		(m) = NULL;						\
	} while (0)

/*
 * Assuming the data is already ok, just set the new address and send
 */
#define NG_FWD_ITEM_HOOK(error, item, hook)				\
	do {								\
		if (!((error) = ng_address_hook(NULL, (item),		\
						(hook), NULL))) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 0);		\
		} else {						\
			(error) = ENXIO;				\
		}							\
		(item) = NULL;						\
	} while (0)


/* Note that messages can be static (e.g. in ng_rmnode_self()) */
/* XXX flag should not be user visible  */
#define NG_FREE_MSG(msg)						\
	do {								\
		if ((msg)) {						\
			if ((msg->header.flags & NGF_STATIC) == 0) {	\
				FREE((msg), M_NETGRAPH_MSG);		\
			}						\
			(msg) = NULL;					\
		}	 						\
	} while (0)

#define NG_FREE_META(meta)						\
	do {								\
		if ((meta)) {						\
			FREE((meta), M_NETGRAPH_META);			\
			(meta) = NULL;					\
		}	 						\
	} while (0)

#define NG_FREE_M(m)							\
	do {								\
		if ((m)) {						\
			m_freem((m));					\
			(m) = NULL;					\
		}							\
	} while (0)

/*****************************************
* Message macros
*****************************************/

#define NG_SEND_MSG_HOOK(error, here, msg, hook, retaddr)		\
	do {								\
		item_p item;						\
		if ((item = ng_package_msg(msg)) == NULL) {		\
			(msg) = NULL;					\
			(error) = ENOMEM;				\
			break;						\
		}							\
		if (((error) = ng_address_hook((here), (item),		\
					(hook), (retaddr))) == 0) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 0);		\
		}							\
		(msg) = NULL;						\
	} while (0)

#define NG_SEND_MSG_PATH(error, here, msg, path, retaddr)		\
	do {								\
		item_p item;						\
		if ((item = ng_package_msg(msg)) == NULL) {		\
			(msg) = NULL;					\
			(error) = ENOMEM;				\
			break;						\
		}							\
		if (((error) = ng_address_path((here), (item),		\
					(path), (retaddr))) == 0) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 0);		\
		}							\
		(msg) = NULL;						\
	} while (0)

#define NG_SEND_MSG_ID(error, here, msg, ID, retaddr)			\
	do {								\
		item_p item;						\
		if ((item = ng_package_msg(msg)) == NULL) {		\
			(msg) = NULL;					\
			(error) = ENOMEM;				\
			break;						\
		}							\
		if (((error) = ng_address_ID((here), (item),		\
					(ID), (retaddr))) == 0) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 0);		\
		}							\
		(msg) = NULL;						\
	} while (0)

#define NG_QUEUE_MSG(error, here, msg, path, retaddr)			\
	do {								\
		item_p item;						\
		if ((item = ng_package_msg(msg)) == NULL) {		\
			(msg) = NULL;					\
			(error) = ENOMEM;				\
			break;						\
		}							\
		if (((error) = ng_address_path((here), (item),		\
					(path), (retaddr))) == 0) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 1);		\
		}							\
		(msg) = NULL;						\
	} while (0)

/*
 * Redirect the message to the next hop using the given hook.
 * ng_retarget_msg() frees the item if there is an error
 * and returns an error code.  It returns 0 on success.
 */
#define NG_FWD_MSG_HOOK(error, here, item, hook, retaddr)		\
	do {								\
		if (((error) = ng_address_hook((here), (item),		\
					(hook), (retaddr))) == 0) {	\
			SAVE_LINE(item);				\
			(error) = ng_snd_item((item), 0);		\
		}							\
		(item) = NULL;						\
	} while (0)

/*
 * Send a queue item back to it's originator with a response message.
 * Assume original message was removed and freed separatly.
 */
#define NG_RESPOND_MSG(error, here, item, resp)				\
	do {								\
		if (resp) {						\
			ng_ID_t dest = NGI_RETADDR(item);		\
			NGI_RETADDR(item) = NULL;			\
			NGI_MSG(item) = resp;				\
			if ((ng_address_ID((here), (item),		\
					dest, NULL )) == 0) {		\
				SAVE_LINE(item);			\
				(error) = ng_snd_item((item), 1);	\
			} else {					\
				(error) = EINVAL;			\
			}						\
		} else {						\
			NG_FREE_ITEM(item);				\
		}							\
		(item) = NULL;						\
	} while (0)


/***********************************************************************
 ******** Structures Definitions and Macros for defining a node  *******
 ***********************************************************************
 * 
 * Here we define the structures needed to actually define a new node
 * type.
 */

/* node method definitions */
typedef	int	ng_constructor_t(node_p node);
typedef	int	ng_rcvmsg_t(node_p node, item_p item, hook_p lasthook);
typedef	int	ng_shutdown_t(node_p node);
typedef	int	ng_newhook_t(node_p node, hook_p hook, const char *name);
typedef	hook_p	ng_findhook_t(node_p node, const char *name);
typedef	int	ng_connect_t(hook_p hook);
typedef	int	ng_rcvdata_t(hook_p hook, item_p item);
typedef	int	ng_disconnect_t(hook_p hook);
typedef	int	ng_rcvitem (node_p node, hook_p hook, item_p item);
/*
 * Command list -- each node type specifies the command that it knows
 * how to convert between ASCII and binary using an array of these.
 * The last element in the array must be a terminator with cookie=0.
 */

struct ng_cmdlist {
	u_int32_t			cookie;		/* command typecookie */
	int				cmd;		/* command number */
	const char			*name;		/* command name */
	const struct ng_parse_type	*mesgType;	/* args if !NGF_RESP */
	const struct ng_parse_type	*respType;	/* args if NGF_RESP */
};

/*
 * Structure of a node type
 * If data is sent to the "rcvdata()" entrypoint then the system
 * may decide to defer it until later by queing it with the normal netgraph
 * input queuing system.  This is decidde by the HK_QUEUE flag being set in
 * the flags word of the peer (receiving) hook. The dequeuing mechanism will
 * ensure it is not requeued again.
 * Note the input queueing system is to allow modules
 * to 'release the stack' or to pass data across spl layers.
 * The data will be redelivered as soon as the NETISR code runs
 * which may be almost immediatly.  A node may also do it's own queueing
 * for other reasons (e.g. device output queuing).
 */
struct ng_type {

	u_int32_t	version; 	/* must equal NG_API_VERSION */
	const char	*name;		/* Unique type name */
	modeventhand_t	mod_event;	/* Module event handler (optional) */
	ng_constructor_t *constructor;	/* Node constructor */
	ng_rcvmsg_t	*rcvmsg;	/* control messages come here */
	ng_shutdown_t	*shutdown;	/* reset, and free resources */
	ng_newhook_t	*newhook;	/* first notification of new hook */
	ng_findhook_t	*findhook;	/* only if you have lots of hooks */
	ng_connect_t	*connect;	/* final notification of new hook */
	ng_rcvdata_t	*rcvdata;	/* data comes here */
	ng_disconnect_t	*disconnect;	/* notify on disconnect */

	const struct	ng_cmdlist *cmdlist;	/* commands we can convert */

	/* R/W data private to the base netgraph code DON'T TOUCH! */
	LIST_ENTRY(ng_type) types;		/* linked list of all types */
	int		    refs;		/* number of instances */
};

/*
 * Use the NETGRAPH_INIT() macro to link a node type into the
 * netgraph system. This works for types compiled into the kernel
 * as well as KLD modules. The first argument should be the type
 * name (eg, echo) and the second a pointer to the type struct.
 *
 * If a different link time is desired, e.g., a device driver that
 * needs to install its netgraph type before probing, use the
 * NETGRAPH_INIT_ORDERED() macro instead. Deivce drivers probably
 * want to use SI_SUB_DRIVERS instead of SI_SUB_PSEUDO.
 */

#define NETGRAPH_INIT_ORDERED(typename, typestructp, sub, order)	\
static moduledata_t ng_##typename##_mod = {				\
	"ng_" #typename,						\
	ng_mod_event,							\
	(typestructp)							\
};									\
DECLARE_MODULE(ng_##typename, ng_##typename##_mod, sub, order);		\
MODULE_DEPEND(ng_##typename, netgraph, 1, 1, 1)

#define NETGRAPH_INIT(tn, tp)						\
	NETGRAPH_INIT_ORDERED(tn, tp, SI_SUB_PSEUDO, SI_ORDER_ANY)

/* Special malloc() type for netgraph structs and ctrl messages */
/* Only these two types should be visible to nodes */ 
MALLOC_DECLARE(M_NETGRAPH);
MALLOC_DECLARE(M_NETGRAPH_MSG);
MALLOC_DECLARE(M_NETGRAPH_META);



/*
 * Methods that the nodes can use.
 * Many of these methods should usually NOT be used directly but via 
 * Macros above.
 */
int	ng_address_ID(node_p here, item_p item, ng_ID_t ID, ng_ID_t retaddr);
int	ng_address_hook(node_p here, item_p item, hook_p hook, ng_ID_t retaddr);
int	ng_address_path(node_p here, item_p item, char *address, ng_ID_t raddr);
meta_p	ng_copy_meta(meta_p meta);
hook_p	ng_findhook(node_p node, const char *name);
int	ng_make_node_common(struct ng_type *typep, node_p *nodep);
int	ng_name_node(node_p node, const char *name);
int	ng_newtype(struct ng_type *tp);
ng_ID_t ng_node2ID(node_p node);
item_p	ng_package_data(struct mbuf *m, meta_p meta);
item_p	ng_package_msg(struct ng_mesg *msg);
item_p	ng_package_msg_self(node_p here, hook_p hook, struct ng_mesg *msg);
void	ng_replace_retaddr(node_p here, item_p item, ng_ID_t retaddr);
int	ng_rmnode_self(node_p here);
int	ng_snd_item(item_p item, int queue);

/*
 * prototypes the user should DEFINITLY not use directly
 */
void	ng_free_item(item_p item); /* Use NG_FREE_ITEM instead */
int	ng_mod_event(module_t mod, int what, void *arg);

#endif /* _NETGRAPH_NETGRAPH_H_ */

