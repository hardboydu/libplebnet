/*
 * Copyright (c) 2002 Mark Santcroos <marks@ripe.net>
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
 *
 * Netgraph "device" node
 *
 * This node presents a /dev/ngd%d device that interfaces to an other
 * netgraph node.
 *
 * $FreeBSD$
 *
 */

#if 0
#define AAA printf("ng_device: %s\n", __func__ );
#else
#define AAA
#endif

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_device.h>

#define	ERROUT(x) do { error = (x); goto done; } while (0)

/* Netgraph methods */
static ng_constructor_t	ng_device_constructor;
static ng_rcvmsg_t	ng_device_rcvmsg;
static ng_shutdown_t	ng_device_shutdown;
static ng_newhook_t	ng_device_newhook;
static ng_rcvdata_t	ng_device_rcvdata;
static ng_disconnect_t	ng_device_disconnect;

/* Netgraph type */
static struct ng_type ngd_typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_DEVICE_NODE_TYPE,
	.constructor =	ng_device_constructor,
	.rcvmsg	=	ng_device_rcvmsg,
	.shutdown = 	ng_device_shutdown,
	.newhook =	ng_device_newhook,
	.rcvdata =	ng_device_rcvdata,
	.disconnect =	ng_device_disconnect,
};
NETGRAPH_INIT(device, &ngd_typestruct);

/* per node data */
struct ngd_private {
	struct	ifqueue	readq;
	SLIST_ENTRY(ngd_private) links;
	struct	ng_node	*node;
	struct	ng_hook	*hook;
	struct	cdev	*ngddev;
	struct	mtx	ngd_mtx;
	int 		unit;
	uint16_t	flags;
#define	NGDF_OPEN	0x0001
#define	NGDF_RWAIT	0x0002
};
typedef struct ngd_private *priv_p;

/* List of all active nodes and mutex to protect it */
static SLIST_HEAD(, ngd_private) ngd_nodes = SLIST_HEAD_INITIALIZER(ngd_nodes);
static struct mtx	ng_device_mtx;
MTX_SYSINIT(ng_device, &ng_device_mtx, "ng_device", MTX_DEF);

/* Maximum number of NGD devices */
#define MAX_NGD	25	/* should be more than enough for now */

static d_close_t ngdclose;
static d_open_t ngdopen;
static d_read_t ngdread;
static d_write_t ngdwrite;
#if 0
static d_ioctl_t ngdioctl;
#endif
static d_poll_t ngdpoll;

static struct cdevsw ngd_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	ngdopen,
	.d_close =	ngdclose,
	.d_read =	ngdread,
	.d_write =	ngdwrite,
#if 0
	.d_ioctl =	ngdioctl,
#endif
	.d_poll =	ngdpoll,
	.d_name =	NG_DEVICE_DEVNAME,
};

/* Helper functions */
static int get_free_unit(void);

/******************************************************************************
 *  Netgraph methods
 ******************************************************************************/

/*
 * create new node
 */
static int
ng_device_constructor(node_p node)
{
	priv_p	priv;

AAA

	MALLOC(priv, priv_p, sizeof(*priv), M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (priv == NULL)
		return (ENOMEM);

	mtx_init(&priv->ngd_mtx, "ng_device", NULL, MTX_DEF);
	mtx_lock(&priv->ngd_mtx);

	mtx_lock(&ng_device_mtx);

	priv->unit = get_free_unit();
	if(priv->unit < 0) {
		printf("%s: No free unit found by get_free_unit(), "
				"increase MAX_NGD\n",__func__);
		mtx_unlock(&ng_device_mtx);
		mtx_destroy(&priv->ngd_mtx);
		FREE(priv, M_NETGRAPH);
		return(EINVAL);
	}

	priv->ngddev = make_dev(&ngd_cdevsw, unit2minor(priv->unit), UID_ROOT,
	    GID_WHEEL, 0600, NG_DEVICE_DEVNAME "%d", priv->unit);
	if(priv->ngddev == NULL) {
		printf("%s(): make_dev() failed\n",__func__);
		mtx_unlock(&ng_device_mtx);
		mtx_destroy(&priv->ngd_mtx);
		FREE(priv, M_NETGRAPH);
		return(EINVAL);
	}

	SLIST_INSERT_HEAD(&ngd_nodes, priv, links);

	mtx_unlock(&ng_device_mtx);

	mtx_init(&priv->readq.ifq_mtx, "ng_device queue", NULL, MTX_DEF);
	IFQ_SET_MAXLEN(&priv->readq, ifqmaxlen);

	/* Link everything together */
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;
	priv->ngddev->si_drv1 = priv;
	
	mtx_unlock(&priv->ngd_mtx);

	return(0);
}

/*
 * Process control message.
 */

static int
ng_device_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *msg;
	struct ng_mesg *resp = NULL;
	int error = 0;

	NGI_GET_MSG(item, msg);

	if (msg->header.typecookie == NGM_DEVICE_COOKIE) {
		switch (msg->header.cmd) {
		case NGM_DEVICE_GET_DEVNAME:
			/* XXX: Fix when NGD_MAX us bigger */
			NG_MKRESPONSE(resp, msg,
			    strlen(NG_DEVICE_DEVNAME) + 3, M_NOWAIT);

			if (resp == NULL)
				ERROUT(ENOMEM);

			strlcpy((char *)resp->data, priv->ngddev->si_name,
			    strlen(priv->ngddev->si_name) + 1);
			break;

		default:
			error = EINVAL;
			break;
		}
	} else
		error = EINVAL;

done:
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	return (error);
}

/*
 * Accept incoming hook. We support only one hook per node.
 */
static int
ng_device_newhook(node_p node, hook_p hook, const char *name)
{
	priv_p priv = NG_NODE_PRIVATE(node);

AAA

	/* We have only one hook per node */
	if (priv->hook != NULL)
		return (EISCONN);

	priv->hook = hook;

	return(0);
}

/*
 * Receive data from hook, write it to device.
 */
static int
ng_device_rcvdata(hook_p hook, item_p item)
{
	priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct mbuf *m;

AAA

	NGI_GET_M(item, m);
	NG_FREE_ITEM(item);

	IF_LOCK(&priv->readq);
	if (_IF_QFULL(&priv->readq)) {
		_IF_DROP(&priv->readq);
		IF_UNLOCK(&priv->readq);
		NG_FREE_M(m);
		return (ENOBUFS);
	}

	_IF_ENQUEUE(&priv->readq, m);
	IF_UNLOCK(&priv->readq);
	mtx_lock(&priv->ngd_mtx);
	if (priv->flags & NGDF_RWAIT) {
		priv->flags &= ~NGDF_RWAIT;
		wakeup(priv);
	}
	mtx_unlock(&priv->ngd_mtx);

	return(0);
}

/*
 * Removal of the hook destroys the node.
 */
static int
ng_device_disconnect(hook_p hook)
{
	priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));

AAA

	destroy_dev(priv->ngddev);
	mtx_destroy(&priv->ngd_mtx);

	mtx_lock(&ng_device_mtx);
	SLIST_REMOVE(&ngd_nodes, priv, ngd_private, links);
	mtx_unlock(&ng_device_mtx);

	IF_DRAIN(&priv->readq);
	mtx_destroy(&(priv)->readq.ifq_mtx);

	FREE(priv, M_NETGRAPH);

	ng_rmnode_self(NG_HOOK_NODE(hook));

	return(0);
}

/*
 * Node shutdown. Everything is already done in disconnect method.
 */
static int
ng_device_shutdown(node_p node)
{
	NG_NODE_UNREF(node);
	return (0);
}

/******************************************************************************
 *  Device methods
 ******************************************************************************/

/*
 * the device is opened
 */
static int
ngdopen(struct cdev *dev, int flag, int mode, struct thread *td)
{
	priv_p	priv = (priv_p )dev->si_drv1;

AAA
	mtx_lock(&priv->ngd_mtx);
	priv->flags |= NGDF_OPEN;
	mtx_unlock(&priv->ngd_mtx);

	return(0);
}

/*
 * the device is closed
 */
static int
ngdclose(struct cdev *dev, int flag, int mode, struct thread *td)
{
	priv_p	priv = (priv_p )dev->si_drv1;

AAA
	mtx_lock(&priv->ngd_mtx);
	priv->flags &= ~NGDF_OPEN;
	mtx_unlock(&priv->ngd_mtx);

	return(0);
}

#if 0	/*
	 * The ioctl is transformed into netgraph control message.
	 * We do not process them, yet.
	 */
/*
 * process ioctl
 *
 * they are translated into netgraph messages and passed on
 *
 */
static int
ngdioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flag, struct thread *td)
{
	struct ngd_softc *sc = &ngd_softc;
	struct ngd_connection * connection = NULL;
	struct ngd_connection * tmp;
	int error = 0;
	struct ng_mesg *msg;
	struct ngd_param_s * datap;

AAA

	SLIST_FOREACH(tmp,&sc->head,links) {
		if(tmp->ngddev == dev) {
			connection = tmp;
		}
	}
	if(connection == NULL) {
		printf("%s(): connection is still NULL, no dev found\n",__func__);
		return(-1);
	}

	NG_MKMESSAGE(msg, NGM_DEVICE_COOKIE, cmd, sizeof(struct ngd_param_s),
			M_NOWAIT);
	if (msg == NULL) {
		printf("%s(): msg == NULL\n",__func__);
		goto nomsg;
	}

	/* pass the ioctl data into the ->data area */
	datap = (struct ngd_param_s *)msg->data;
	datap->p = addr;

	NG_SEND_MSG_HOOK(error, sc->node, msg, connection->active_hook, 0);
	if(error)
		printf("%s(): NG_SEND_MSG_HOOK error: %d\n",__func__,error);

nomsg:

	return(0);
}
#endif /* if 0 */

/*
 * This function is called when a read(2) is done to our device.
 * We process one mbuf from queue.
 */
static int
ngdread(struct cdev *dev, struct uio *uio, int flag)
{
	priv_p	priv = (priv_p )dev->si_drv1;
	struct mbuf *m;
	int len, error = 0;

AAA

	/* get an mbuf */
	do {
		IF_DEQUEUE(&priv->readq, m);
		if (m == NULL) {
			if (flag & IO_NDELAY)
				return (EWOULDBLOCK);
			mtx_lock(&priv->ngd_mtx);
			priv->flags |= NGDF_RWAIT;
			mtx_unlock(&priv->ngd_mtx);
			if ((error = tsleep(priv, PCATCH | (PZERO + 1),
			    "ngdread", 0)) != 0)
				return (error);
		}
	} while (m == NULL);

	while (m && uio->uio_resid > 0 && error == 0) {
		len = MIN(uio->uio_resid, m->m_len);
		if (len != 0)
			error = uiomove(mtod(m, void *), len, uio);
		m = m_free(m);
	}

	if (m)
		m_freem(m);

	return (error);
}


/*
 * This function is called when our device is written to.
 * We read the data from userland into mbuf chain and pass it to the remote hook.
 *
 */
static int
ngdwrite(struct cdev *dev, struct uio *uio, int flag)
{
	priv_p	priv = (priv_p )dev->si_drv1;
	struct mbuf *m;
	int error = 0;

AAA

	if (uio->uio_resid == 0)
		return (0);

	if (uio->uio_resid < 0 || uio->uio_resid > IP_MAXPACKET)
		return (EIO);

	if ((m = m_uiotombuf(uio, M_DONTWAIT, 0)) == NULL)
		return (ENOBUFS);

	NG_SEND_DATA_ONLY(error, priv->hook, m);

	return (error);
}

/*
 * we are being polled/selected
 * check if there is data available for read
 */
static int
ngdpoll(struct cdev *dev, int events, struct thread *td)
{
	priv_p	priv = (priv_p )dev->si_drv1;
	int revents = 0;

	if (events & (POLLIN | POLLRDNORM) &&
	    !IFQ_IS_EMPTY(&priv->readq))
		revents |= events & (POLLIN | POLLRDNORM);

	return (revents);
}

/******************************************************************************
 *  Helper subroutines
 ******************************************************************************/

static int
get_free_unit()
{
	struct ngd_private *priv = NULL;
	int n = 0;
	int unit = -1;

AAA

	mtx_assert(&ng_device_mtx, MA_OWNED);

	/* When there is no list yet, the first device unit is always 0. */
	if SLIST_EMPTY(&ngd_nodes)
		return(0);

	/* Just do a brute force loop to find the first free unit that is
	 * smaller than MAX_NGD.
	 * Set MAX_NGD to a large value, doesn't impact performance.
	 */
	for(n = 0; n<MAX_NGD && unit == -1; n++) {
		SLIST_FOREACH(priv, &ngd_nodes, links) {

			if(priv->unit == n) {
				unit = -1;
				break;
			}
			unit = n;
		}
	}

	return (unit);
}
