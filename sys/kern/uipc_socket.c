/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2004 The FreeBSD Foundation
 * Copyright (c) 2004-2006 Robert N. M. Watson
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
 *	@(#)uipc_socket.c	8.3 (Berkeley) 4/15/94
 */

/*
 * Comments on the socket life cycle:
 *
 * soalloc() sets of socket layer state for a socket, called only by
 * socreate() and sonewconn().  Socket layer private.
 *
 * sodealloc() tears down socket layer state for a socket, called only by
 * sofree() and sonewconn().  Socket layer private.
 *
 * pru_attach() associates protocol layer state with an allocated socket;
 * called only once, may fail, aborting socket allocation.  This is called
 * from socreate() and sonewconn().  Socket layer private.
 *
 * pru_detach() disassociates protocol layer state from an attached socket,
 * and will be called exactly once for sockets in which pru_attach() has
 * been successfully called.  If pru_attach() returned an error,
 * pru_detach() will not be called.  Socket layer private.
 *
 * pru_abort() and pru_close() notify the protocol layer that the last
 * consumer of a socket is starting to tear down the socket, and that the
 * protocol should terminate the connection.  Historically, pru_abort() also
 * detached protocol state from the socket state, but this is no longer the
 * case.
 *
 * socreate() creates a socket and attaches protocol state.  This is a public
 * interface that may be used by socket layer consumers to create new
 * sockets.
 *
 * sonewconn() creates a socket and attaches protocol state.  This is a
 * public interface  that may be used by protocols to create new sockets when
 * a new connection is received and will be available for accept() on a
 * listen socket.
 *
 * soclose() destroys a socket after possibly waiting for it to disconnect.
 * This is a public interface that socket consumers should use to close and
 * release a socket when done with it.
 *
 * soabort() destroys a socket without waiting for it to disconnect (used
 * only for incoming connections that are already partially or fully
 * connected).  This is used internally by the socket layer when clearing
 * listen socket queues (due to overflow or close on the listen socket), but
 * is also a public interface protocols may use to abort connections in
 * their incomplete listen queues should they no longer be required.  Sockets
 * placed in completed connection listen queues should not be aborted for
 * reasons described in the comment above the soclose() implementation.  This
 * is not a general purpose close routine, and except in the specific
 * circumstances described here, should not be used.
 *
 * sofree() will free a socket and its protocol state if all references on
 * the socket have been released, and is the public interface to attempt to
 * free a socket when a reference is removed.  This is a socket layer private
 * interface.
 *
 * NOTE: In addition to socreate() and soclose(), which provide a single
 * socket reference to the consumer to be managed as required, there are two
 * calls to explicitly manage socket references, soref(), and sorele().
 * Currently, these are generally required only when transitioning a socket
 * from a listen queue to a file descriptor, in order to prevent garbage
 * collection of the socket at an untimely moment.  For a number of reasons,
 * these interfaces are not preferred, and should be avoided.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_mac.h"
#include "opt_zero.h"
#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/domain.h>
#include <sys/file.h>			/* for struct knote */
#include <sys/kernel.h>
#include <sys/event.h>
#include <sys/eventhandler.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/jail.h>

#include <security/mac/mac_framework.h>

#include <vm/uma.h>

#ifdef COMPAT_IA32
#include <sys/mount.h>
#include <compat/freebsd32/freebsd32.h>

extern struct sysentvec ia32_freebsd_sysvec;
#endif

static int	soreceive_rcvoob(struct socket *so, struct uio *uio,
		    int flags);

static void	filt_sordetach(struct knote *kn);
static int	filt_soread(struct knote *kn, long hint);
static void	filt_sowdetach(struct knote *kn);
static int	filt_sowrite(struct knote *kn, long hint);
static int	filt_solisten(struct knote *kn, long hint);

static struct filterops solisten_filtops =
	{ 1, NULL, filt_sordetach, filt_solisten };
static struct filterops soread_filtops =
	{ 1, NULL, filt_sordetach, filt_soread };
static struct filterops sowrite_filtops =
	{ 1, NULL, filt_sowdetach, filt_sowrite };

uma_zone_t socket_zone;
so_gen_t	so_gencnt;	/* generation count for sockets */

int	maxsockets;

MALLOC_DEFINE(M_SONAME, "soname", "socket name");
MALLOC_DEFINE(M_PCB, "pcb", "protocol control block");

static int somaxconn = SOMAXCONN;
static int somaxconn_sysctl(SYSCTL_HANDLER_ARGS);
/* XXX: we dont have SYSCTL_USHORT */
SYSCTL_PROC(_kern_ipc, KIPC_SOMAXCONN, somaxconn, CTLTYPE_UINT | CTLFLAG_RW,
    0, sizeof(int), somaxconn_sysctl, "I", "Maximum pending socket connection "
    "queue size");
static int numopensockets;
SYSCTL_INT(_kern_ipc, OID_AUTO, numopensockets, CTLFLAG_RD,
    &numopensockets, 0, "Number of open sockets");
#ifdef ZERO_COPY_SOCKETS
/* These aren't static because they're used in other files. */
int so_zero_copy_send = 1;
int so_zero_copy_receive = 1;
SYSCTL_NODE(_kern_ipc, OID_AUTO, zero_copy, CTLFLAG_RD, 0,
    "Zero copy controls");
SYSCTL_INT(_kern_ipc_zero_copy, OID_AUTO, receive, CTLFLAG_RW,
    &so_zero_copy_receive, 0, "Enable zero copy receive");
SYSCTL_INT(_kern_ipc_zero_copy, OID_AUTO, send, CTLFLAG_RW,
    &so_zero_copy_send, 0, "Enable zero copy send");
#endif /* ZERO_COPY_SOCKETS */

/*
 * accept_mtx locks down per-socket fields relating to accept queues.  See
 * socketvar.h for an annotation of the protected fields of struct socket.
 */
struct mtx accept_mtx;
MTX_SYSINIT(accept_mtx, &accept_mtx, "accept", MTX_DEF);

/*
 * so_global_mtx protects so_gencnt, numopensockets, and the per-socket
 * so_gencnt field.
 */
static struct mtx so_global_mtx;
MTX_SYSINIT(so_global_mtx, &so_global_mtx, "so_glabel", MTX_DEF);

/*
 * General IPC sysctl name space, used by sockets and a variety of other IPC
 * types.
 */
SYSCTL_NODE(_kern, KERN_IPC, ipc, CTLFLAG_RW, 0, "IPC");

/*
 * Sysctl to get and set the maximum global sockets limit.  Notify protocols
 * of the change so that they can update their dependent limits as required.
 */
static int
sysctl_maxsockets(SYSCTL_HANDLER_ARGS)
{
	int error, newmaxsockets;

	newmaxsockets = maxsockets;
	error = sysctl_handle_int(oidp, &newmaxsockets, sizeof(int), req);
	if (error == 0 && req->newptr) {
		if (newmaxsockets > maxsockets) {
			maxsockets = newmaxsockets;
			if (maxsockets > ((maxfiles / 4) * 3)) {
				maxfiles = (maxsockets * 5) / 4;
				maxfilesperproc = (maxfiles * 9) / 10;
			}
			EVENTHANDLER_INVOKE(maxsockets_change);
		} else
			error = EINVAL;
	}
	return (error);
}

SYSCTL_PROC(_kern_ipc, OID_AUTO, maxsockets, CTLTYPE_INT|CTLFLAG_RW,
    &maxsockets, 0, sysctl_maxsockets, "IU",
    "Maximum number of sockets avaliable");

/*
 * Initialise maxsockets.
 */
static void init_maxsockets(void *ignored)
{
	TUNABLE_INT_FETCH("kern.ipc.maxsockets", &maxsockets);
	maxsockets = imax(maxsockets, imax(maxfiles, nmbclusters));
}
SYSINIT(param, SI_SUB_TUNABLES, SI_ORDER_ANY, init_maxsockets, NULL);

/*
 * Socket operation routines.  These routines are called by the routines in
 * sys_socket.c or from a system process, and implement the semantics of
 * socket operations by switching out to the protocol specific routines.
 */

/*
 * Get a socket structure from our zone, and initialize it.  Note that it
 * would probably be better to allocate socket and PCB at the same time, but
 * I'm not convinced that all the protocols can be easily modified to do
 * this.
 *
 * soalloc() returns a socket with a ref count of 0.
 */
static struct socket *
soalloc(int mflags)
{
	struct socket *so;

	so = uma_zalloc(socket_zone, mflags | M_ZERO);
	if (so == NULL)
		return (NULL);
#ifdef MAC
	if (mac_init_socket(so, mflags) != 0) {
		uma_zfree(socket_zone, so);
		return (NULL);
	}
#endif
	SOCKBUF_LOCK_INIT(&so->so_snd, "so_snd");
	SOCKBUF_LOCK_INIT(&so->so_rcv, "so_rcv");
	TAILQ_INIT(&so->so_aiojobq);
	mtx_lock(&so_global_mtx);
	so->so_gencnt = ++so_gencnt;
	++numopensockets;
	mtx_unlock(&so_global_mtx);
	return (so);
}

/*
 * Free the storage associated with a socket at the socket layer, tear down
 * locks, labels, etc.  All protocol state is assumed already to have been
 * torn down (and possibly never set up) by the caller.
 */
static void
sodealloc(struct socket *so)
{

	KASSERT(so->so_count == 0, ("sodealloc(): so_count %d", so->so_count));
	KASSERT(so->so_pcb == NULL, ("sodealloc(): so_pcb != NULL"));

	mtx_lock(&so_global_mtx);
	so->so_gencnt = ++so_gencnt;
	--numopensockets;	/* Could be below, but faster here. */
	mtx_unlock(&so_global_mtx);
	if (so->so_rcv.sb_hiwat)
		(void)chgsbsize(so->so_cred->cr_uidinfo,
		    &so->so_rcv.sb_hiwat, 0, RLIM_INFINITY);
	if (so->so_snd.sb_hiwat)
		(void)chgsbsize(so->so_cred->cr_uidinfo,
		    &so->so_snd.sb_hiwat, 0, RLIM_INFINITY);
#ifdef INET
	/* remove acccept filter if one is present. */
	if (so->so_accf != NULL)
		do_setopt_accept_filter(so, NULL);
#endif
#ifdef MAC
	mac_destroy_socket(so);
#endif
	crfree(so->so_cred);
	SOCKBUF_LOCK_DESTROY(&so->so_snd);
	SOCKBUF_LOCK_DESTROY(&so->so_rcv);
	uma_zfree(socket_zone, so);
}

/*
 * socreate returns a socket with a ref count of 1.  The socket should be
 * closed with soclose().
 */
int
socreate(dom, aso, type, proto, cred, td)
	int dom;
	struct socket **aso;
	int type;
	int proto;
	struct ucred *cred;
	struct thread *td;
{
	struct protosw *prp;
	struct socket *so;
	int error;

	if (proto)
		prp = pffindproto(dom, proto, type);
	else
		prp = pffindtype(dom, type);

	if (prp == NULL || prp->pr_usrreqs->pru_attach == NULL ||
	    prp->pr_usrreqs->pru_attach == pru_attach_notsupp)
		return (EPROTONOSUPPORT);

	if (jailed(cred) && jail_socket_unixiproute_only &&
	    prp->pr_domain->dom_family != PF_LOCAL &&
	    prp->pr_domain->dom_family != PF_INET &&
	    prp->pr_domain->dom_family != PF_ROUTE) {
		return (EPROTONOSUPPORT);
	}

	if (prp->pr_type != type)
		return (EPROTOTYPE);
	so = soalloc(M_WAITOK);
	if (so == NULL)
		return (ENOBUFS);

	TAILQ_INIT(&so->so_incomp);
	TAILQ_INIT(&so->so_comp);
	so->so_type = type;
	so->so_cred = crhold(cred);
	so->so_proto = prp;
#ifdef MAC
	mac_create_socket(cred, so);
#endif
	knlist_init(&so->so_rcv.sb_sel.si_note, SOCKBUF_MTX(&so->so_rcv),
	    NULL, NULL, NULL);
	knlist_init(&so->so_snd.sb_sel.si_note, SOCKBUF_MTX(&so->so_snd),
	    NULL, NULL, NULL);
	so->so_count = 1;
	error = (*prp->pr_usrreqs->pru_attach)(so, proto, td);
	if (error) {
		KASSERT(so->so_count == 1, ("socreate: so_count %d",
		    so->so_count));
		so->so_count = 0;
		sodealloc(so);
		return (error);
	}
	*aso = so;
	return (0);
}

#ifdef REGRESSION
static int regression_sonewconn_earlytest = 1;
SYSCTL_INT(_regression, OID_AUTO, sonewconn_earlytest, CTLFLAG_RW,
    &regression_sonewconn_earlytest, 0, "Perform early sonewconn limit test");
#endif

/*
 * When an attempt at a new connection is noted on a socket which accepts
 * connections, sonewconn is called.  If the connection is possible (subject
 * to space constraints, etc.) then we allocate a new structure, propoerly
 * linked into the data structure of the original socket, and return this.
 * Connstatus may be 0, or SO_ISCONFIRMING, or SO_ISCONNECTED.
 *
 * Note: the ref count on the socket is 0 on return.
 */
struct socket *
sonewconn(head, connstatus)
	register struct socket *head;
	int connstatus;
{
	register struct socket *so;
	int over;

	ACCEPT_LOCK();
	over = (head->so_qlen > 3 * head->so_qlimit / 2);
	ACCEPT_UNLOCK();
#ifdef REGRESSION
	if (regression_sonewconn_earlytest && over)
#else
	if (over)
#endif
		return (NULL);
	so = soalloc(M_NOWAIT);
	if (so == NULL)
		return (NULL);
	if ((head->so_options & SO_ACCEPTFILTER) != 0)
		connstatus = 0;
	so->so_head = head;
	so->so_type = head->so_type;
	so->so_options = head->so_options &~ SO_ACCEPTCONN;
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF;
	so->so_proto = head->so_proto;
	so->so_cred = crhold(head->so_cred);
#ifdef MAC
	SOCK_LOCK(head);
	mac_create_socket_from_socket(head, so);
	SOCK_UNLOCK(head);
#endif
	knlist_init(&so->so_rcv.sb_sel.si_note, SOCKBUF_MTX(&so->so_rcv),
	    NULL, NULL, NULL);
	knlist_init(&so->so_snd.sb_sel.si_note, SOCKBUF_MTX(&so->so_snd),
	    NULL, NULL, NULL);
	if (soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat) ||
	    (*so->so_proto->pr_usrreqs->pru_attach)(so, 0, NULL)) {
		sodealloc(so);
		return (NULL);
	}
	so->so_rcv.sb_lowat = head->so_rcv.sb_lowat;
	so->so_snd.sb_lowat = head->so_snd.sb_lowat;
	so->so_rcv.sb_timeo = head->so_rcv.sb_timeo;
	so->so_snd.sb_timeo = head->so_snd.sb_timeo;
	so->so_state |= connstatus;
	ACCEPT_LOCK();
	if (connstatus) {
		TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
		so->so_qstate |= SQ_COMP;
		head->so_qlen++;
	} else {
		/*
		 * Keep removing sockets from the head until there's room for
		 * us to insert on the tail.  In pre-locking revisions, this
		 * was a simple if(), but as we could be racing with other
		 * threads and soabort() requires dropping locks, we must
		 * loop waiting for the condition to be true.
		 */
		while (head->so_incqlen > head->so_qlimit) {
			struct socket *sp;
			sp = TAILQ_FIRST(&head->so_incomp);
			TAILQ_REMOVE(&head->so_incomp, sp, so_list);
			head->so_incqlen--;
			sp->so_qstate &= ~SQ_INCOMP;
			sp->so_head = NULL;
			ACCEPT_UNLOCK();
			soabort(sp);
			ACCEPT_LOCK();
		}
		TAILQ_INSERT_TAIL(&head->so_incomp, so, so_list);
		so->so_qstate |= SQ_INCOMP;
		head->so_incqlen++;
	}
	ACCEPT_UNLOCK();
	if (connstatus) {
		sorwakeup(head);
		wakeup_one(&head->so_timeo);
	}
	return (so);
}

int
sobind(so, nam, td)
	struct socket *so;
	struct sockaddr *nam;
	struct thread *td;
{

	return ((*so->so_proto->pr_usrreqs->pru_bind)(so, nam, td));
}

/*
 * solisten() transitions a socket from a non-listening state to a listening
 * state, but can also be used to update the listen queue depth on an
 * existing listen socket.  The protocol will call back into the sockets
 * layer using solisten_proto_check() and solisten_proto() to check and set
 * socket-layer listen state.  Call backs are used so that the protocol can
 * acquire both protocol and socket layer locks in whatever order is required
 * by the protocol.
 *
 * Protocol implementors are advised to hold the socket lock across the
 * socket-layer test and set to avoid races at the socket layer.
 */
int
solisten(so, backlog, td)
	struct socket *so;
	int backlog;
	struct thread *td;
{

	return ((*so->so_proto->pr_usrreqs->pru_listen)(so, backlog, td));
}

int
solisten_proto_check(so)
	struct socket *so;
{

	SOCK_LOCK_ASSERT(so);

	if (so->so_state & (SS_ISCONNECTED | SS_ISCONNECTING |
	    SS_ISDISCONNECTING))
		return (EINVAL);
	return (0);
}

void
solisten_proto(so, backlog)
	struct socket *so;
	int backlog;
{

	SOCK_LOCK_ASSERT(so);

	if (backlog < 0 || backlog > somaxconn)
		backlog = somaxconn;
	so->so_qlimit = backlog;
	so->so_options |= SO_ACCEPTCONN;
}

/*
 * Attempt to free a socket.  This should really be sotryfree().
 *
 * sofree() will succeed if:
 *
 * - There are no outstanding file descriptor references or related consumers
 *   (so_count == 0).
 *
 * - The socket has been closed by user space, if ever open (SS_NOFDREF).
 *
 * - The protocol does not have an outstanding strong reference on the socket
 *   (SS_PROTOREF).
 *
 * - The socket is not in a completed connection queue, so a process has been
 *   notified that it is present.  If it is removed, the user process may
 *   block in accept() despite select() saying the socket was ready.
 *
 * Otherwise, it will quietly abort so that a future call to sofree(), when
 * conditions are right, can succeed.
 */
void
sofree(so)
	struct socket *so;
{
	struct protosw *pr = so->so_proto;
	struct socket *head;

	ACCEPT_LOCK_ASSERT();
	SOCK_LOCK_ASSERT(so);

	if ((so->so_state & SS_NOFDREF) == 0 || so->so_count != 0 ||
	    (so->so_state & SS_PROTOREF) || (so->so_qstate & SQ_COMP)) {
		SOCK_UNLOCK(so);
		ACCEPT_UNLOCK();
		return;
	}

	head = so->so_head;
	if (head != NULL) {
		KASSERT((so->so_qstate & SQ_COMP) != 0 ||
		    (so->so_qstate & SQ_INCOMP) != 0,
		    ("sofree: so_head != NULL, but neither SQ_COMP nor "
		    "SQ_INCOMP"));
		KASSERT((so->so_qstate & SQ_COMP) == 0 ||
		    (so->so_qstate & SQ_INCOMP) == 0,
		    ("sofree: so->so_qstate is SQ_COMP and also SQ_INCOMP"));
		TAILQ_REMOVE(&head->so_incomp, so, so_list);
		head->so_incqlen--;
		so->so_qstate &= ~SQ_INCOMP;
		so->so_head = NULL;
	}
	KASSERT((so->so_qstate & SQ_COMP) == 0 &&
	    (so->so_qstate & SQ_INCOMP) == 0,
	    ("sofree: so_head == NULL, but still SQ_COMP(%d) or SQ_INCOMP(%d)",
	    so->so_qstate & SQ_COMP, so->so_qstate & SQ_INCOMP));
	SOCK_UNLOCK(so);
	ACCEPT_UNLOCK();

	/*
	 * From this point on, we assume that no other references to this
	 * socket exist anywhere else in the stack.  Therefore, no locks need
	 * to be acquired or held.
	 *
	 * We used to do a lot of socket buffer and socket locking here, as
	 * well as invoke sorflush() and perform wakeups.  The direct call to
	 * dom_dispose() and sbrelease_internal() are an inlining of what was
	 * necessary from sorflush().
	 *
	 * Notice that the socket buffer and kqueue state are torn down
	 * before calling pru_detach.  This means that protocols shold not
	 * assume they can perform socket wakeups, etc, in their detach
	 * code.
	 */
	KASSERT((so->so_snd.sb_flags & SB_LOCK) == 0, ("sofree: snd sblock"));
	KASSERT((so->so_rcv.sb_flags & SB_LOCK) == 0, ("sofree: rcv sblock"));
	sbdestroy(&so->so_snd, so);
	if (pr->pr_flags & PR_RIGHTS && pr->pr_domain->dom_dispose != NULL)
		(*pr->pr_domain->dom_dispose)(so->so_rcv.sb_mb);
	sbdestroy(&so->so_rcv, so);
	if (pr->pr_usrreqs->pru_detach != NULL)
		(*pr->pr_usrreqs->pru_detach)(so);
	knlist_destroy(&so->so_rcv.sb_sel.si_note);
	knlist_destroy(&so->so_snd.sb_sel.si_note);
	sodealloc(so);
}

/*
 * Close a socket on last file table reference removal.  Initiate disconnect
 * if connected.  Free socket when disconnect complete.
 *
 * This function will sorele() the socket.  Note that soclose() may be called
 * prior to the ref count reaching zero.  The actual socket structure will
 * not be freed until the ref count reaches zero.
 */
int
soclose(so)
	struct socket *so;
{
	int error = 0;

	KASSERT(!(so->so_state & SS_NOFDREF), ("soclose: SS_NOFDREF on enter"));

	funsetown(&so->so_sigio);
	if (so->so_options & SO_ACCEPTCONN) {
		struct socket *sp;
		ACCEPT_LOCK();
		while ((sp = TAILQ_FIRST(&so->so_incomp)) != NULL) {
			TAILQ_REMOVE(&so->so_incomp, sp, so_list);
			so->so_incqlen--;
			sp->so_qstate &= ~SQ_INCOMP;
			sp->so_head = NULL;
			ACCEPT_UNLOCK();
			soabort(sp);
			ACCEPT_LOCK();
		}
		while ((sp = TAILQ_FIRST(&so->so_comp)) != NULL) {
			TAILQ_REMOVE(&so->so_comp, sp, so_list);
			so->so_qlen--;
			sp->so_qstate &= ~SQ_COMP;
			sp->so_head = NULL;
			ACCEPT_UNLOCK();
			soabort(sp);
			ACCEPT_LOCK();
		}
		ACCEPT_UNLOCK();
	}
	if (so->so_state & SS_ISCONNECTED) {
		if ((so->so_state & SS_ISDISCONNECTING) == 0) {
			error = sodisconnect(so);
			if (error)
				goto drop;
		}
		if (so->so_options & SO_LINGER) {
			if ((so->so_state & SS_ISDISCONNECTING) &&
			    (so->so_state & SS_NBIO))
				goto drop;
			while (so->so_state & SS_ISCONNECTED) {
				error = tsleep(&so->so_timeo,
				    PSOCK | PCATCH, "soclos", so->so_linger * hz);
				if (error)
					break;
			}
		}
	}

drop:
	if (so->so_proto->pr_usrreqs->pru_close != NULL)
		(*so->so_proto->pr_usrreqs->pru_close)(so);
	ACCEPT_LOCK();
	SOCK_LOCK(so);
	KASSERT((so->so_state & SS_NOFDREF) == 0, ("soclose: NOFDREF"));
	so->so_state |= SS_NOFDREF;
	sorele(so);
	return (error);
}

/*
 * soabort() is used to abruptly tear down a connection, such as when a
 * resource limit is reached (listen queue depth exceeded), or if a listen
 * socket is closed while there are sockets waiting to be accepted.
 *
 * This interface is tricky, because it is called on an unreferenced socket,
 * and must be called only by a thread that has actually removed the socket
 * from the listen queue it was on, or races with other threads are risked.
 *
 * This interface will call into the protocol code, so must not be called
 * with any socket locks held.  Protocols do call it while holding their own
 * recursible protocol mutexes, but this is something that should be subject
 * to review in the future.
 */
void
soabort(so)
	struct socket *so;
{

	/*
	 * In as much as is possible, assert that no references to this
	 * socket are held.  This is not quite the same as asserting that the
	 * current thread is responsible for arranging for no references, but
	 * is as close as we can get for now.
	 */
	KASSERT(so->so_count == 0, ("soabort: so_count"));
	KASSERT((so->so_state & SS_PROTOREF) == 0, ("soabort: SS_PROTOREF"));
	KASSERT(so->so_state & SS_NOFDREF, ("soabort: !SS_NOFDREF"));
	KASSERT((so->so_state & SQ_COMP) == 0, ("soabort: SQ_COMP"));
	KASSERT((so->so_state & SQ_INCOMP) == 0, ("soabort: SQ_INCOMP"));

	if (so->so_proto->pr_usrreqs->pru_abort != NULL)
		(*so->so_proto->pr_usrreqs->pru_abort)(so);
	ACCEPT_LOCK();
	SOCK_LOCK(so);
	sofree(so);
}

int
soaccept(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	int error;

	SOCK_LOCK(so);
	KASSERT((so->so_state & SS_NOFDREF) != 0, ("soaccept: !NOFDREF"));
	so->so_state &= ~SS_NOFDREF;
	SOCK_UNLOCK(so);
	error = (*so->so_proto->pr_usrreqs->pru_accept)(so, nam);
	return (error);
}

int
soconnect(so, nam, td)
	struct socket *so;
	struct sockaddr *nam;
	struct thread *td;
{
	int error;

	if (so->so_options & SO_ACCEPTCONN)
		return (EOPNOTSUPP);
	/*
	 * If protocol is connection-based, can only connect once.
	 * Otherwise, if connected, try to disconnect first.  This allows
	 * user to disconnect by connecting to, e.g., a null address.
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnect(so)))) {
		error = EISCONN;
	} else {
		/*
		 * Prevent accumulated error from previous connection from
		 * biting us.
		 */
		so->so_error = 0;
		error = (*so->so_proto->pr_usrreqs->pru_connect)(so, nam, td);
	}

	return (error);
}

int
soconnect2(so1, so2)
	struct socket *so1;
	struct socket *so2;
{

	return ((*so1->so_proto->pr_usrreqs->pru_connect2)(so1, so2));
}

int
sodisconnect(so)
	struct socket *so;
{
	int error;

	if ((so->so_state & SS_ISCONNECTED) == 0)
		return (ENOTCONN);
	if (so->so_state & SS_ISDISCONNECTING)
		return (EALREADY);
	error = (*so->so_proto->pr_usrreqs->pru_disconnect)(so);
	return (error);
}

#ifdef ZERO_COPY_SOCKETS
struct so_zerocopy_stats{
	int size_ok;
	int align_ok;
	int found_ifp;
};
struct so_zerocopy_stats so_zerocp_stats = {0,0,0};
#include <netinet/in.h>
#include <net/route.h>
#include <netinet/in_pcb.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#endif /*ZERO_COPY_SOCKETS*/

/*
 * sosend_copyin() accepts a uio and prepares an mbuf chain holding part or
 * all of the data referenced by the uio.  If desired, it uses zero-copy.
 * *space will be updated to reflect data copied in.
 *
 * NB: If atomic I/O is requested, the caller must already have checked that
 * space can hold resid bytes.
 *
 * NB: In the event of an error, the caller may need to free the partial
 * chain pointed to by *mpp.  The contents of both *uio and *space may be
 * modified even in the case of an error.
 */
static int
sosend_copyin(struct uio *uio, struct mbuf **retmp, int atomic, long *space,
    int flags)
{
	struct mbuf *m, **mp, *top;
	long len, resid;
	int error;
#ifdef ZERO_COPY_SOCKETS
	int cow_send;
#endif

	*retmp = top = NULL;
	mp = &top;
	len = 0;
	resid = uio->uio_resid;
	error = 0;
	do {
#ifdef ZERO_COPY_SOCKETS
		cow_send = 0;
#endif /* ZERO_COPY_SOCKETS */
		if (resid >= MINCLSIZE) {
#ifdef ZERO_COPY_SOCKETS
			if (top == NULL) {
				MGETHDR(m, M_TRYWAIT, MT_DATA);
				if (m == NULL) {
					error = ENOBUFS;
					goto out;
				}
				m->m_pkthdr.len = 0;
				m->m_pkthdr.rcvif = NULL;
			} else {
				MGET(m, M_TRYWAIT, MT_DATA);
				if (m == NULL) {
					error = ENOBUFS;
					goto out;
				}
			}
			if (so_zero_copy_send &&
			    resid>=PAGE_SIZE &&
			    *space>=PAGE_SIZE &&
			    uio->uio_iov->iov_len>=PAGE_SIZE) {
				so_zerocp_stats.size_ok++;
				so_zerocp_stats.align_ok++;
				cow_send = socow_setup(m, uio);
				len = cow_send;
			}
			if (!cow_send) {
				MCLGET(m, M_TRYWAIT);
				if ((m->m_flags & M_EXT) == 0) {
					m_free(m);
					m = NULL;
				} else {
					len = min(min(MCLBYTES, resid),
					    *space);
				}
			}
#else /* ZERO_COPY_SOCKETS */
			if (top == NULL) {
				m = m_getcl(M_TRYWAIT, MT_DATA, M_PKTHDR);
				m->m_pkthdr.len = 0;
				m->m_pkthdr.rcvif = NULL;
			} else
				m = m_getcl(M_TRYWAIT, MT_DATA, 0);
			len = min(min(MCLBYTES, resid), *space);
#endif /* ZERO_COPY_SOCKETS */
		} else {
			if (top == NULL) {
				m = m_gethdr(M_TRYWAIT, MT_DATA);
				m->m_pkthdr.len = 0;
				m->m_pkthdr.rcvif = NULL;

				len = min(min(MHLEN, resid), *space);
				/*
				 * For datagram protocols, leave room
				 * for protocol headers in first mbuf.
				 */
				if (atomic && m && len < MHLEN)
					MH_ALIGN(m, len);
			} else {
				m = m_get(M_TRYWAIT, MT_DATA);
				len = min(min(MLEN, resid), *space);
			}
		}
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}

		*space -= len;
#ifdef ZERO_COPY_SOCKETS
		if (cow_send)
			error = 0;
		else
#endif /* ZERO_COPY_SOCKETS */
		error = uiomove(mtod(m, void *), (int)len, uio);
		resid = uio->uio_resid;
		m->m_len = len;
		*mp = m;
		top->m_pkthdr.len += len;
		if (error)
			goto out;
		mp = &m->m_next;
		if (resid <= 0) {
			if (flags & MSG_EOR)
				top->m_flags |= M_EOR;
			break;
		}
	} while (*space > 0 && atomic);
out:
	*retmp = top;
	return (error);
}

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? M_NOWAIT : M_WAITOK)

int
sosend_dgram(so, addr, uio, top, control, flags, td)
	struct socket *so;
	struct sockaddr *addr;
	struct uio *uio;
	struct mbuf *top;
	struct mbuf *control;
	int flags;
	struct thread *td;
{
	long space, resid;
	int clen = 0, error, dontroute;
	int atomic = sosendallatonce(so) || top;

	KASSERT(so->so_type == SOCK_DGRAM, ("sodgram_send: !SOCK_DGRAM"));
	KASSERT(so->so_proto->pr_flags & PR_ATOMIC,
	    ("sodgram_send: !PR_ATOMIC"));

	if (uio != NULL)
		resid = uio->uio_resid;
	else
		resid = top->m_pkthdr.len;
	/*
	 * In theory resid should be unsigned.  However, space must be
	 * signed, as it might be less than 0 if we over-committed, and we
	 * must use a signed comparison of space and resid.  On the other
	 * hand, a negative resid causes us to loop sending 0-length
	 * segments to the protocol.
	 *
	 * Also check to make sure that MSG_EOR isn't used on SOCK_STREAM
	 * type sockets since that's an error.
	 */
	if (resid < 0) {
		error = EINVAL;
		goto out;
	}

	dontroute =
	    (flags & MSG_DONTROUTE) && (so->so_options & SO_DONTROUTE) == 0;
	if (td != NULL)
		td->td_proc->p_stats->p_ru.ru_msgsnd++;
	if (control != NULL)
		clen = control->m_len;

	SOCKBUF_LOCK(&so->so_snd);
	if (so->so_snd.sb_state & SBS_CANTSENDMORE) {
		SOCKBUF_UNLOCK(&so->so_snd);
		error = EPIPE;
		goto out;
	}
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		SOCKBUF_UNLOCK(&so->so_snd);
		goto out;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		/*
		 * `sendto' and `sendmsg' is allowed on a connection-based
		 * socket if it supports implied connect.  Return ENOTCONN if
		 * not connected and no address is supplied.
		 */
		if ((so->so_proto->pr_flags & PR_CONNREQUIRED) &&
		    (so->so_proto->pr_flags & PR_IMPLOPCL) == 0) {
			if ((so->so_state & SS_ISCONFIRMING) == 0 &&
			    !(resid == 0 && clen != 0)) {
				SOCKBUF_UNLOCK(&so->so_snd);
				error = ENOTCONN;
				goto out;
			}
		} else if (addr == NULL) {
			if (so->so_proto->pr_flags & PR_CONNREQUIRED)
				error = ENOTCONN;
			else
				error = EDESTADDRREQ;
			SOCKBUF_UNLOCK(&so->so_snd);
			goto out;
		}
	}

	/*
	 * Do we need MSG_OOB support in SOCK_DGRAM?  Signs here may be a
	 * problem and need fixing.
	 */
	space = sbspace(&so->so_snd);
	if (flags & MSG_OOB)
		space += 1024;
	space -= clen;
	SOCKBUF_UNLOCK(&so->so_snd);
	if (resid > space) {
		error = EMSGSIZE;
		goto out;
	}
	if (uio == NULL) {
		resid = 0;
		if (flags & MSG_EOR)
			top->m_flags |= M_EOR;
	} else {
		error = sosend_copyin(uio, &top, atomic, &space, flags);
		if (error)
			goto out;
		resid = uio->uio_resid;
	}
	KASSERT(resid == 0, ("sosend_dgram: resid != 0"));
	/*
	 * XXXRW: Frobbing SO_DONTROUTE here is even worse without sblock
	 * than with.
	 */
	if (dontroute) {
		SOCK_LOCK(so);
		so->so_options |= SO_DONTROUTE;
		SOCK_UNLOCK(so);
	}
	/*
	 * XXX all the SBS_CANTSENDMORE checks previously done could be out
	 * of date.  We could have recieved a reset packet in an interrupt or
	 * maybe we slept while doing page faults in uiomove() etc.  We could
	 * probably recheck again inside the locking protection here, but
	 * there are probably other places that this also happens.  We must
	 * rethink this.
	 */
	error = (*so->so_proto->pr_usrreqs->pru_send)(so,
	    (flags & MSG_OOB) ? PRUS_OOB :
	/*
	 * If the user set MSG_EOF, the protocol understands this flag and
	 * nothing left to send then use PRU_SEND_EOF instead of PRU_SEND.
	 */
	    ((flags & MSG_EOF) &&
	     (so->so_proto->pr_flags & PR_IMPLOPCL) &&
	     (resid <= 0)) ?
		PRUS_EOF :
		/* If there is more to send set PRUS_MORETOCOME */
		(resid > 0 && space > 0) ? PRUS_MORETOCOME : 0,
		top, addr, control, td);
	if (dontroute) {
		SOCK_LOCK(so);
		so->so_options &= ~SO_DONTROUTE;
		SOCK_UNLOCK(so);
	}
	clen = 0;
	control = NULL;
	top = NULL;
out:
	if (top != NULL)
		m_freem(top);
	if (control != NULL)
		m_freem(control);
	return (error);
}

/*
 * Send on a socket.  If send must go all at once and message is larger than
 * send buffering, then hard error.  Lock against other senders.  If must go
 * all at once and not enough room now, then inform user that this would
 * block and do nothing.  Otherwise, if nonblocking, send as much as
 * possible.  The data to be sent is described by "uio" if nonzero, otherwise
 * by the mbuf chain "top" (which must be null if uio is not).  Data provided
 * in mbuf chain must be small enough to send all at once.
 *
 * Returns nonzero on error, timeout or signal; callers must check for short
 * counts if EINTR/ERESTART are returned.  Data and control buffers are freed
 * on return.
 */
#define	snderr(errno)	{ error = (errno); goto release; }
int
sosend_generic(so, addr, uio, top, control, flags, td)
	struct socket *so;
	struct sockaddr *addr;
	struct uio *uio;
	struct mbuf *top;
	struct mbuf *control;
	int flags;
	struct thread *td;
{
	long space, resid;
	int clen = 0, error, dontroute;
	int atomic = sosendallatonce(so) || top;

	if (uio != NULL)
		resid = uio->uio_resid;
	else
		resid = top->m_pkthdr.len;
	/*
	 * In theory resid should be unsigned.  However, space must be
	 * signed, as it might be less than 0 if we over-committed, and we
	 * must use a signed comparison of space and resid.  On the other
	 * hand, a negative resid causes us to loop sending 0-length
	 * segments to the protocol.
	 *
	 * Also check to make sure that MSG_EOR isn't used on SOCK_STREAM
	 * type sockets since that's an error.
	 */
	if (resid < 0 || (so->so_type == SOCK_STREAM && (flags & MSG_EOR))) {
		error = EINVAL;
		goto out;
	}

	dontroute =
	    (flags & MSG_DONTROUTE) && (so->so_options & SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	if (td != NULL)
		td->td_proc->p_stats->p_ru.ru_msgsnd++;
	if (control != NULL)
		clen = control->m_len;

	SOCKBUF_LOCK(&so->so_snd);
restart:
	SOCKBUF_LOCK_ASSERT(&so->so_snd);
	error = sblock(&so->so_snd, SBLOCKWAIT(flags));
	if (error)
		goto out_locked;
	do {
		SOCKBUF_LOCK_ASSERT(&so->so_snd);
		if (so->so_snd.sb_state & SBS_CANTSENDMORE)
			snderr(EPIPE);
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			goto release;
		}
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			/*
			 * `sendto' and `sendmsg' is allowed on a connection-
			 * based socket if it supports implied connect.
			 * Return ENOTCONN if not connected and no address is
			 * supplied.
			 */
			if ((so->so_proto->pr_flags & PR_CONNREQUIRED) &&
			    (so->so_proto->pr_flags & PR_IMPLOPCL) == 0) {
				if ((so->so_state & SS_ISCONFIRMING) == 0 &&
				    !(resid == 0 && clen != 0))
					snderr(ENOTCONN);
			} else if (addr == NULL)
			    snderr(so->so_proto->pr_flags & PR_CONNREQUIRED ?
				   ENOTCONN : EDESTADDRREQ);
		}
		space = sbspace(&so->so_snd);
		if (flags & MSG_OOB)
			space += 1024;
		if ((atomic && resid > so->so_snd.sb_hiwat) ||
		    clen > so->so_snd.sb_hiwat)
			snderr(EMSGSIZE);
		if (space < resid + clen &&
		    (atomic || space < so->so_snd.sb_lowat || space < clen)) {
			if ((so->so_state & SS_NBIO) || (flags & MSG_NBIO))
				snderr(EWOULDBLOCK);
			sbunlock(&so->so_snd);
			error = sbwait(&so->so_snd);
			if (error)
				goto out_locked;
			goto restart;
		}
		SOCKBUF_UNLOCK(&so->so_snd);
		space -= clen;
		do {
			if (uio == NULL) {
				resid = 0;
				if (flags & MSG_EOR)
					top->m_flags |= M_EOR;
			} else {
				error = sosend_copyin(uio, &top, atomic,
				    &space, flags);
				if (error != 0) {
					SOCKBUF_LOCK(&so->so_snd);
					goto release;
				}
				resid = uio->uio_resid;
			}
			if (dontroute) {
				SOCK_LOCK(so);
				so->so_options |= SO_DONTROUTE;
				SOCK_UNLOCK(so);
			}
			/*
			 * XXX all the SBS_CANTSENDMORE checks previously
			 * done could be out of date.  We could have recieved
			 * a reset packet in an interrupt or maybe we slept
			 * while doing page faults in uiomove() etc.  We
			 * could probably recheck again inside the locking
			 * protection here, but there are probably other
			 * places that this also happens.  We must rethink
			 * this.
			 */
			error = (*so->so_proto->pr_usrreqs->pru_send)(so,
			    (flags & MSG_OOB) ? PRUS_OOB :
			/*
			 * If the user set MSG_EOF, the protocol understands
			 * this flag and nothing left to send then use
			 * PRU_SEND_EOF instead of PRU_SEND.
			 */
			    ((flags & MSG_EOF) &&
			     (so->so_proto->pr_flags & PR_IMPLOPCL) &&
			     (resid <= 0)) ?
				PRUS_EOF :
			/* If there is more to send set PRUS_MORETOCOME. */
			    (resid > 0 && space > 0) ? PRUS_MORETOCOME : 0,
			    top, addr, control, td);
			if (dontroute) {
				SOCK_LOCK(so);
				so->so_options &= ~SO_DONTROUTE;
				SOCK_UNLOCK(so);
			}
			clen = 0;
			control = NULL;
			top = NULL;
			if (error) {
				SOCKBUF_LOCK(&so->so_snd);
				goto release;
			}
		} while (resid && space > 0);
		SOCKBUF_LOCK(&so->so_snd);
	} while (resid);

release:
	SOCKBUF_LOCK_ASSERT(&so->so_snd);
	sbunlock(&so->so_snd);
out_locked:
	SOCKBUF_LOCK_ASSERT(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);
out:
	if (top != NULL)
		m_freem(top);
	if (control != NULL)
		m_freem(control);
	return (error);
}
#undef snderr

int
sosend(so, addr, uio, top, control, flags, td)
	struct socket *so;
	struct sockaddr *addr;
	struct uio *uio;
	struct mbuf *top;
	struct mbuf *control;
	int flags;
	struct thread *td;
{

	/* XXXRW: Temporary debugging. */
	KASSERT(so->so_proto->pr_usrreqs->pru_sosend != sosend,
	    ("sosend: protocol calls sosend"));

	return (so->so_proto->pr_usrreqs->pru_sosend(so, addr, uio, top,
	    control, flags, td));
}

/*
 * The part of soreceive() that implements reading non-inline out-of-band
 * data from a socket.  For more complete comments, see soreceive(), from
 * which this code originated.
 *
 * Note that soreceive_rcvoob(), unlike the remainder of soreceive(), is
 * unable to return an mbuf chain to the caller.
 */
static int
soreceive_rcvoob(so, uio, flags)
	struct socket *so;
	struct uio *uio;
	int flags;
{
	struct protosw *pr = so->so_proto;
	struct mbuf *m;
	int error;

	KASSERT(flags & MSG_OOB, ("soreceive_rcvoob: (flags & MSG_OOB) == 0"));

	m = m_get(M_TRYWAIT, MT_DATA);
	if (m == NULL)
		return (ENOBUFS);
	error = (*pr->pr_usrreqs->pru_rcvoob)(so, m, flags & MSG_PEEK);
	if (error)
		goto bad;
	do {
#ifdef ZERO_COPY_SOCKETS
		if (so_zero_copy_receive) {
			int disposable;

			if ((m->m_flags & M_EXT)
			 && (m->m_ext.ext_type == EXT_DISPOSABLE))
				disposable = 1;
			else
				disposable = 0;

			error = uiomoveco(mtod(m, void *),
					  min(uio->uio_resid, m->m_len),
					  uio, disposable);
		} else
#endif /* ZERO_COPY_SOCKETS */
		error = uiomove(mtod(m, void *),
		    (int) min(uio->uio_resid, m->m_len), uio);
		m = m_free(m);
	} while (uio->uio_resid && error == 0 && m);
bad:
	if (m != NULL)
		m_freem(m);
	return (error);
}

/*
 * Following replacement or removal of the first mbuf on the first mbuf chain
 * of a socket buffer, push necessary state changes back into the socket
 * buffer so that other consumers see the values consistently.  'nextrecord'
 * is the callers locally stored value of the original value of
 * sb->sb_mb->m_nextpkt which must be restored when the lead mbuf changes.
 * NOTE: 'nextrecord' may be NULL.
 */
static __inline void
sockbuf_pushsync(struct sockbuf *sb, struct mbuf *nextrecord)
{

	SOCKBUF_LOCK_ASSERT(sb);
	/*
	 * First, update for the new value of nextrecord.  If necessary, make
	 * it the first record.
	 */
	if (sb->sb_mb != NULL)
		sb->sb_mb->m_nextpkt = nextrecord;
	else
		sb->sb_mb = nextrecord;

        /*
         * Now update any dependent socket buffer fields to reflect the new
         * state.  This is an expanded inline of SB_EMPTY_FIXUP(), with the
	 * addition of a second clause that takes care of the case where
	 * sb_mb has been updated, but remains the last record.
         */
        if (sb->sb_mb == NULL) {
                sb->sb_mbtail = NULL;
                sb->sb_lastrecord = NULL;
        } else if (sb->sb_mb->m_nextpkt == NULL)
                sb->sb_lastrecord = sb->sb_mb;
}


/*
 * Implement receive operations on a socket.  We depend on the way that
 * records are added to the sockbuf by sbappend.  In particular, each record
 * (mbufs linked through m_next) must begin with an address if the protocol
 * so specifies, followed by an optional mbuf or mbufs containing ancillary
 * data, and then zero or more mbufs of data.  In order to allow parallelism
 * between network receive and copying to user space, as well as avoid
 * sleeping with a mutex held, we release the socket buffer mutex during the
 * user space copy.  Although the sockbuf is locked, new data may still be
 * appended, and thus we must maintain consistency of the sockbuf during that
 * time.
 *
 * The caller may receive the data as a single mbuf chain by supplying an
 * mbuf **mp0 for use in returning the chain.  The uio is then used only for
 * the count in uio_resid.
 */
int
soreceive_generic(so, psa, uio, mp0, controlp, flagsp)
	struct socket *so;
	struct sockaddr **psa;
	struct uio *uio;
	struct mbuf **mp0;
	struct mbuf **controlp;
	int *flagsp;
{
	struct mbuf *m, **mp;
	int flags, len, error, offset;
	struct protosw *pr = so->so_proto;
	struct mbuf *nextrecord;
	int moff, type = 0;
	int mbuf_removed = 0;
	int orig_resid = uio->uio_resid;

	mp = mp0;
	if (psa != NULL)
		*psa = NULL;
	if (controlp != NULL)
		*controlp = NULL;
	if (flagsp != NULL)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;
	if (flags & MSG_OOB)
		return (soreceive_rcvoob(so, uio, flags));
	if (mp != NULL)
		*mp = NULL;
	if ((pr->pr_flags & PR_WANTRCVD) && (so->so_state & SS_ISCONFIRMING)
	    && uio->uio_resid)
		(*pr->pr_usrreqs->pru_rcvd)(so, 0);

	SOCKBUF_LOCK(&so->so_rcv);
restart:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	error = sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error)
		goto out;

	m = so->so_rcv.sb_mb;
	/*
	 * If we have less data than requested, block awaiting more (subject
	 * to any timeout) if:
	 *   1. the current count is less than the low water mark, or
	 *   2. MSG_WAITALL is set, and it is possible to do the entire
	 *	receive operation at once if we block (resid <= hiwat).
	 *   3. MSG_DONTWAIT is not set
	 * If MSG_WAITALL is set but resid is larger than the receive buffer,
	 * we have to do the receive in sections, and thus risk returning a
	 * short count if a timeout or signal occurs after we start.
	 */
	if (m == NULL || (((flags & MSG_DONTWAIT) == 0 &&
	    so->so_rcv.sb_cc < uio->uio_resid) &&
	    (so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & MSG_WAITALL) && uio->uio_resid <= so->so_rcv.sb_hiwat)) &&
	    m->m_nextpkt == NULL && (pr->pr_flags & PR_ATOMIC) == 0)) {
		KASSERT(m != NULL || !so->so_rcv.sb_cc,
		    ("receive: m == %p so->so_rcv.sb_cc == %u",
		    m, so->so_rcv.sb_cc));
		if (so->so_error) {
			if (m != NULL)
				goto dontblock;
			error = so->so_error;
			if ((flags & MSG_PEEK) == 0)
				so->so_error = 0;
			goto release;
		}
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
			if (m)
				goto dontblock;
			else
				goto release;
		}
		for (; m != NULL; m = m->m_next)
			if (m->m_type == MT_OOBDATA  || (m->m_flags & M_EOR)) {
				m = so->so_rcv.sb_mb;
				goto dontblock;
			}
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
		    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
			error = ENOTCONN;
			goto release;
		}
		if (uio->uio_resid == 0)
			goto release;
		if ((so->so_state & SS_NBIO) ||
		    (flags & (MSG_DONTWAIT|MSG_NBIO))) {
			error = EWOULDBLOCK;
			goto release;
		}
		SBLASTRECORDCHK(&so->so_rcv);
		SBLASTMBUFCHK(&so->so_rcv);
		sbunlock(&so->so_rcv);
		error = sbwait(&so->so_rcv);
		if (error)
			goto out;
		goto restart;
	}
dontblock:
	/*
	 * From this point onward, we maintain 'nextrecord' as a cache of the
	 * pointer to the next record in the socket buffer.  We must keep the
	 * various socket buffer pointers and local stack versions of the
	 * pointers in sync, pushing out modifications before dropping the
	 * socket buffer mutex, and re-reading them when picking it up.
	 *
	 * Otherwise, we will race with the network stack appending new data
	 * or records onto the socket buffer by using inconsistent/stale
	 * versions of the field, possibly resulting in socket buffer
	 * corruption.
	 *
	 * By holding the high-level sblock(), we prevent simultaneous
	 * readers from pulling off the front of the socket buffer.
	 */
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	if (uio->uio_td)
		uio->uio_td->td_proc->p_stats->p_ru.ru_msgrcv++;
	KASSERT(m == so->so_rcv.sb_mb, ("soreceive: m != so->so_rcv.sb_mb"));
	SBLASTRECORDCHK(&so->so_rcv);
	SBLASTMBUFCHK(&so->so_rcv);
	nextrecord = m->m_nextpkt;
	if (pr->pr_flags & PR_ADDR) {
		KASSERT(m->m_type == MT_SONAME,
		    ("m->m_type == %d", m->m_type));
		orig_resid = 0;
		if (psa != NULL)
			*psa = sodupsockaddr(mtod(m, struct sockaddr *),
			    M_NOWAIT);
		if (flags & MSG_PEEK) {
			m = m->m_next;
		} else {
			sbfree(&so->so_rcv, m);
			mbuf_removed = 1;
			so->so_rcv.sb_mb = m_free(m);
			m = so->so_rcv.sb_mb;
			sockbuf_pushsync(&so->so_rcv, nextrecord);
		}
	}

	/*
	 * Process one or more MT_CONTROL mbufs present before any data mbufs
	 * in the first mbuf chain on the socket buffer.  If MSG_PEEK, we
	 * just copy the data; if !MSG_PEEK, we call into the protocol to
	 * perform externalization (or freeing if controlp == NULL).
	 */
	if (m != NULL && m->m_type == MT_CONTROL) {
		struct mbuf *cm = NULL, *cmn;
		struct mbuf **cme = &cm;

		do {
			if (flags & MSG_PEEK) {
				if (controlp != NULL) {
					*controlp = m_copy(m, 0, m->m_len);
					controlp = &(*controlp)->m_next;
				}
				m = m->m_next;
			} else {
				sbfree(&so->so_rcv, m);
				mbuf_removed = 1;
				so->so_rcv.sb_mb = m->m_next;
				m->m_next = NULL;
				*cme = m;
				cme = &(*cme)->m_next;
				m = so->so_rcv.sb_mb;
			}
		} while (m != NULL && m->m_type == MT_CONTROL);
		if ((flags & MSG_PEEK) == 0)
			sockbuf_pushsync(&so->so_rcv, nextrecord);
		while (cm != NULL) {
			cmn = cm->m_next;
			cm->m_next = NULL;
			if (pr->pr_domain->dom_externalize != NULL) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				error = (*pr->pr_domain->dom_externalize)
				    (cm, controlp);
				SOCKBUF_LOCK(&so->so_rcv);
			} else if (controlp != NULL)
				*controlp = cm;
			else
				m_freem(cm);
			if (controlp != NULL) {
				orig_resid = 0;
				while (*controlp != NULL)
					controlp = &(*controlp)->m_next;
			}
			cm = cmn;
		}
		if (m != NULL)
			nextrecord = so->so_rcv.sb_mb->m_nextpkt;
		else
			nextrecord = so->so_rcv.sb_mb;
		orig_resid = 0;
	}
	if (m != NULL) {
		if ((flags & MSG_PEEK) == 0) {
			KASSERT(m->m_nextpkt == nextrecord,
			    ("soreceive: post-control, nextrecord !sync"));
			if (nextrecord == NULL) {
				KASSERT(so->so_rcv.sb_mb == m,
				    ("soreceive: post-control, sb_mb!=m"));
				KASSERT(so->so_rcv.sb_lastrecord == m,
				    ("soreceive: post-control, lastrecord!=m"));
			}
		}
		type = m->m_type;
		if (type == MT_OOBDATA)
			flags |= MSG_OOB;
	} else {
		if ((flags & MSG_PEEK) == 0) {
			KASSERT(so->so_rcv.sb_mb == nextrecord,
			    ("soreceive: sb_mb != nextrecord"));
			if (so->so_rcv.sb_mb == NULL) {
				KASSERT(so->so_rcv.sb_lastrecord == NULL,
				    ("soreceive: sb_lastercord != NULL"));
			}
		}
	}
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	SBLASTRECORDCHK(&so->so_rcv);
	SBLASTMBUFCHK(&so->so_rcv);

	/*
	 * Now continue to read any data mbufs off of the head of the socket
	 * buffer until the read request is satisfied.  Note that 'type' is
	 * used to store the type of any mbuf reads that have happened so far
	 * such that soreceive() can stop reading if the type changes, which
	 * causes soreceive() to return only one of regular data and inline
	 * out-of-band data in a single socket receive operation.
	 */
	moff = 0;
	offset = 0;
	while (m != NULL && uio->uio_resid > 0 && error == 0) {
		/*
		 * If the type of mbuf has changed since the last mbuf
		 * examined ('type'), end the receive operation.
	 	 */
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (m->m_type == MT_OOBDATA) {
			if (type != MT_OOBDATA)
				break;
		} else if (type == MT_OOBDATA)
			break;
		else
		    KASSERT(m->m_type == MT_DATA,
			("m->m_type == %d", m->m_type));
		so->so_rcv.sb_state &= ~SBS_RCVATMARK;
		len = uio->uio_resid;
		if (so->so_oobmark && len > so->so_oobmark - offset)
			len = so->so_oobmark - offset;
		if (len > m->m_len - moff)
			len = m->m_len - moff;
		/*
		 * If mp is set, just pass back the mbufs.  Otherwise copy
		 * them out via the uio, then free.  Sockbuf must be
		 * consistent here (points to current mbuf, it points to next
		 * record) when we drop priority; we must note any additions
		 * to the sockbuf when we block interrupts again.
		 */
		if (mp == NULL) {
			SOCKBUF_LOCK_ASSERT(&so->so_rcv);
			SBLASTRECORDCHK(&so->so_rcv);
			SBLASTMBUFCHK(&so->so_rcv);
			SOCKBUF_UNLOCK(&so->so_rcv);
#ifdef ZERO_COPY_SOCKETS
			if (so_zero_copy_receive) {
				int disposable;

				if ((m->m_flags & M_EXT)
				 && (m->m_ext.ext_type == EXT_DISPOSABLE))
					disposable = 1;
				else
					disposable = 0;

				error = uiomoveco(mtod(m, char *) + moff,
						  (int)len, uio,
						  disposable);
			} else
#endif /* ZERO_COPY_SOCKETS */
			error = uiomove(mtod(m, char *) + moff, (int)len, uio);
			SOCKBUF_LOCK(&so->so_rcv);
			if (error) {
				/*
				 * If any part of the record has been removed
				 * (such as the MT_SONAME mbuf, which will
				 * happen when PR_ADDR, and thus also
				 * PR_ATOMIC, is set), then drop the entire
				 * record to maintain the atomicity of the
				 * receive operation.
				 */
				if (m && mbuf_removed &&
				    (pr->pr_flags & PR_ATOMIC))
					(void)sbdroprecord_locked(&so->so_rcv);
				goto release;
			}
		} else
			uio->uio_resid -= len;
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (len == m->m_len - moff) {
			if (m->m_flags & M_EOR)
				flags |= MSG_EOR;
			if (flags & MSG_PEEK) {
				m = m->m_next;
				moff = 0;
			} else {
				nextrecord = m->m_nextpkt;
				sbfree(&so->so_rcv, m);
				if (mp != NULL) {
					*mp = m;
					mp = &m->m_next;
					so->so_rcv.sb_mb = m = m->m_next;
					*mp = NULL;
				} else {
					so->so_rcv.sb_mb = m_free(m);
					m = so->so_rcv.sb_mb;
				}
				sockbuf_pushsync(&so->so_rcv, nextrecord);
				SBLASTRECORDCHK(&so->so_rcv);
				SBLASTMBUFCHK(&so->so_rcv);
			}
		} else {
			if (flags & MSG_PEEK)
				moff += len;
			else {
				if (mp != NULL) {
					int copy_flag;

					if (flags & MSG_DONTWAIT)
						copy_flag = M_DONTWAIT;
					else
						copy_flag = M_TRYWAIT;
					if (copy_flag == M_TRYWAIT)
						SOCKBUF_UNLOCK(&so->so_rcv);
					*mp = m_copym(m, 0, len, copy_flag);
					if (copy_flag == M_TRYWAIT)
						SOCKBUF_LOCK(&so->so_rcv);
 					if (*mp == NULL) {
 						/*
 						 * m_copym() couldn't
						 * allocate an mbuf.  Adjust
						 * uio_resid back (it was
						 * adjusted down by len
						 * bytes, which we didn't end
						 * up "copying" over).
 						 */
 						uio->uio_resid += len;
 						break;
 					}
				}
				m->m_data += len;
				m->m_len -= len;
				so->so_rcv.sb_cc -= len;
			}
		}
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (so->so_oobmark) {
			if ((flags & MSG_PEEK) == 0) {
				so->so_oobmark -= len;
				if (so->so_oobmark == 0) {
					so->so_rcv.sb_state |= SBS_RCVATMARK;
					break;
				}
			} else {
				offset += len;
				if (offset == so->so_oobmark)
					break;
			}
		}
		if (flags & MSG_EOR)
			break;
		/*
		 * If the MSG_WAITALL flag is set (for non-atomic socket), we
		 * must not quit until "uio->uio_resid == 0" or an error
		 * termination.  If a signal/timeout occurs, return with a
		 * short count but without error.  Keep sockbuf locked
		 * against other readers.
		 */
		while (flags & MSG_WAITALL && m == NULL && uio->uio_resid > 0 &&
		    !sosendallatonce(so) && nextrecord == NULL) {
			SOCKBUF_LOCK_ASSERT(&so->so_rcv);
			if (so->so_error || so->so_rcv.sb_state & SBS_CANTRCVMORE)
				break;
			/*
			 * Notify the protocol that some data has been
			 * drained before blocking.
			 */
			if (pr->pr_flags & PR_WANTRCVD) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				(*pr->pr_usrreqs->pru_rcvd)(so, flags);
				SOCKBUF_LOCK(&so->so_rcv);
			}
			SBLASTRECORDCHK(&so->so_rcv);
			SBLASTMBUFCHK(&so->so_rcv);
			error = sbwait(&so->so_rcv);
			if (error)
				goto release;
			m = so->so_rcv.sb_mb;
			if (m != NULL)
				nextrecord = m->m_nextpkt;
		}
	}

	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	if (m != NULL && pr->pr_flags & PR_ATOMIC) {
		flags |= MSG_TRUNC;
		if ((flags & MSG_PEEK) == 0)
			(void) sbdroprecord_locked(&so->so_rcv);
	}
	if ((flags & MSG_PEEK) == 0) {
		if (m == NULL) {
			/*
			 * First part is an inline SB_EMPTY_FIXUP().  Second
			 * part makes sure sb_lastrecord is up-to-date if
			 * there is still data in the socket buffer.
			 */
			so->so_rcv.sb_mb = nextrecord;
			if (so->so_rcv.sb_mb == NULL) {
				so->so_rcv.sb_mbtail = NULL;
				so->so_rcv.sb_lastrecord = NULL;
			} else if (nextrecord->m_nextpkt == NULL)
				so->so_rcv.sb_lastrecord = nextrecord;
		}
		SBLASTRECORDCHK(&so->so_rcv);
		SBLASTMBUFCHK(&so->so_rcv);
		/*
		 * If soreceive() is being done from the socket callback,
		 * then don't need to generate ACK to peer to update window,
		 * since ACK will be generated on return to TCP.
		 */
		if (!(flags & MSG_SOCALLBCK) &&
		    (pr->pr_flags & PR_WANTRCVD)) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			(*pr->pr_usrreqs->pru_rcvd)(so, flags);
			SOCKBUF_LOCK(&so->so_rcv);
		}
	}
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	if (orig_resid == uio->uio_resid && orig_resid &&
	    (flags & MSG_EOR) == 0 && (so->so_rcv.sb_state & SBS_CANTRCVMORE) == 0) {
		sbunlock(&so->so_rcv);
		goto restart;
	}

	if (flagsp != NULL)
		*flagsp |= flags;
release:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	sbunlock(&so->so_rcv);
out:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	SOCKBUF_UNLOCK(&so->so_rcv);
	return (error);
}

int
soreceive(so, psa, uio, mp0, controlp, flagsp)
	struct socket *so;
	struct sockaddr **psa;
	struct uio *uio;
	struct mbuf **mp0;
	struct mbuf **controlp;
	int *flagsp;
{

	/* XXXRW: Temporary debugging. */
	KASSERT(so->so_proto->pr_usrreqs->pru_soreceive != soreceive,
	    ("soreceive: protocol calls soreceive"));

	return (so->so_proto->pr_usrreqs->pru_soreceive(so, psa, uio, mp0,
	    controlp, flagsp));
}

int
soshutdown(so, how)
	struct socket *so;
	int how;
{
	struct protosw *pr = so->so_proto;

	if (!(how == SHUT_RD || how == SHUT_WR || how == SHUT_RDWR))
		return (EINVAL);

	if (how != SHUT_WR)
		sorflush(so);
	if (how != SHUT_RD)
		return ((*pr->pr_usrreqs->pru_shutdown)(so));
	return (0);
}

void
sorflush(so)
	struct socket *so;
{
	struct sockbuf *sb = &so->so_rcv;
	struct protosw *pr = so->so_proto;
	struct sockbuf asb;

	/*
	 * XXXRW: This is quite ugly.  Previously, this code made a copy of
	 * the socket buffer, then zero'd the original to clear the buffer
	 * fields.  However, with mutexes in the socket buffer, this causes
	 * problems.  We only clear the zeroable bits of the original;
	 * however, we have to initialize and destroy the mutex in the copy
	 * so that dom_dispose() and sbrelease() can lock t as needed.
	 */
	SOCKBUF_LOCK(sb);
	sb->sb_flags |= SB_NOINTR;
	(void) sblock(sb, M_WAITOK);
	/*
	 * socantrcvmore_locked() drops the socket buffer mutex so that it
	 * can safely perform wakeups.  Re-acquire the mutex before
	 * continuing.
	 */
	socantrcvmore_locked(so);
	SOCKBUF_LOCK(sb);
	sbunlock(sb);
	/*
	 * Invalidate/clear most of the sockbuf structure, but leave selinfo
	 * and mutex data unchanged.
	 */
	bzero(&asb, offsetof(struct sockbuf, sb_startzero));
	bcopy(&sb->sb_startzero, &asb.sb_startzero,
	    sizeof(*sb) - offsetof(struct sockbuf, sb_startzero));
	bzero(&sb->sb_startzero,
	    sizeof(*sb) - offsetof(struct sockbuf, sb_startzero));
	SOCKBUF_UNLOCK(sb);

	SOCKBUF_LOCK_INIT(&asb, "so_rcv");
	if (pr->pr_flags & PR_RIGHTS && pr->pr_domain->dom_dispose != NULL)
		(*pr->pr_domain->dom_dispose)(asb.sb_mb);
	sbrelease(&asb, so);
	SOCKBUF_LOCK_DESTROY(&asb);
}

/*
 * Perhaps this routine, and sooptcopyout(), below, ought to come in an
 * additional variant to handle the case where the option value needs to be
 * some kind of integer, but not a specific size.  In addition to their use
 * here, these functions are also called by the protocol-level pr_ctloutput()
 * routines.
 */
int
sooptcopyin(sopt, buf, len, minlen)
	struct	sockopt *sopt;
	void	*buf;
	size_t	len;
	size_t	minlen;
{
	size_t	valsize;

	/*
	 * If the user gives us more than we wanted, we ignore it, but if we
	 * don't get the minimum length the caller wants, we return EINVAL.
	 * On success, sopt->sopt_valsize is set to however much we actually
	 * retrieved.
	 */
	if ((valsize = sopt->sopt_valsize) < minlen)
		return EINVAL;
	if (valsize > len)
		sopt->sopt_valsize = valsize = len;

	if (sopt->sopt_td != NULL)
		return (copyin(sopt->sopt_val, buf, valsize));

	bcopy(sopt->sopt_val, buf, valsize);
	return (0);
}

/*
 * Kernel version of setsockopt(2).
 *
 * XXX: optlen is size_t, not socklen_t
 */
int
so_setsockopt(struct socket *so, int level, int optname, void *optval,
    size_t optlen)
{
	struct sockopt sopt;

	sopt.sopt_level = level;
	sopt.sopt_name = optname;
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_val = optval;
	sopt.sopt_valsize = optlen;
	sopt.sopt_td = NULL;
	return (sosetopt(so, &sopt));
}

int
sosetopt(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
	u_long  val;
#ifdef MAC
	struct mac extmac;
#endif

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput)
			return ((*so->so_proto->pr_ctloutput)
				  (so, sopt));
		error = ENOPROTOOPT;
	} else {
		switch (sopt->sopt_name) {
#ifdef INET
		case SO_ACCEPTFILTER:
			error = do_setopt_accept_filter(so, sopt);
			if (error)
				goto bad;
			break;
#endif
		case SO_LINGER:
			error = sooptcopyin(sopt, &l, sizeof l, sizeof l);
			if (error)
				goto bad;

			SOCK_LOCK(so);
			so->so_linger = l.l_linger;
			if (l.l_onoff)
				so->so_options |= SO_LINGER;
			else
				so->so_options &= ~SO_LINGER;
			SOCK_UNLOCK(so);
			break;

		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_USELOOPBACK:
		case SO_BROADCAST:
		case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_OOBINLINE:
		case SO_TIMESTAMP:
		case SO_BINTIME:
		case SO_NOSIGPIPE:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				goto bad;
			SOCK_LOCK(so);
			if (optval)
				so->so_options |= sopt->sopt_name;
			else
				so->so_options &= ~sopt->sopt_name;
			SOCK_UNLOCK(so);
			break;

		case SO_SNDBUF:
		case SO_RCVBUF:
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				goto bad;

			/*
			 * Values < 1 make no sense for any of these options,
			 * so disallow them.
			 */
			if (optval < 1) {
				error = EINVAL;
				goto bad;
			}

			switch (sopt->sopt_name) {
			case SO_SNDBUF:
			case SO_RCVBUF:
				if (sbreserve(sopt->sopt_name == SO_SNDBUF ?
				    &so->so_snd : &so->so_rcv, (u_long)optval,
				    so, curthread) == 0) {
					error = ENOBUFS;
					goto bad;
				}
				break;

			/*
			 * Make sure the low-water is never greater than the
			 * high-water.
			 */
			case SO_SNDLOWAT:
				SOCKBUF_LOCK(&so->so_snd);
				so->so_snd.sb_lowat =
				    (optval > so->so_snd.sb_hiwat) ?
				    so->so_snd.sb_hiwat : optval;
				SOCKBUF_UNLOCK(&so->so_snd);
				break;
			case SO_RCVLOWAT:
				SOCKBUF_LOCK(&so->so_rcv);
				so->so_rcv.sb_lowat =
				    (optval > so->so_rcv.sb_hiwat) ?
				    so->so_rcv.sb_hiwat : optval;
				SOCKBUF_UNLOCK(&so->so_rcv);
				break;
			}
			break;

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
#ifdef COMPAT_IA32
			if (curthread->td_proc->p_sysent == &ia32_freebsd_sysvec) {
				struct timeval32 tv32;

				error = sooptcopyin(sopt, &tv32, sizeof tv32,
				    sizeof tv32);
				CP(tv32, tv, tv_sec);
				CP(tv32, tv, tv_usec);
			} else
#endif
				error = sooptcopyin(sopt, &tv, sizeof tv,
				    sizeof tv);
			if (error)
				goto bad;

			/* assert(hz > 0); */
			if (tv.tv_sec < 0 || tv.tv_sec > INT_MAX / hz ||
			    tv.tv_usec < 0 || tv.tv_usec >= 1000000) {
				error = EDOM;
				goto bad;
			}
			/* assert(tick > 0); */
			/* assert(ULONG_MAX - INT_MAX >= 1000000); */
			val = (u_long)(tv.tv_sec * hz) + tv.tv_usec / tick;
			if (val > INT_MAX) {
				error = EDOM;
				goto bad;
			}
			if (val == 0 && tv.tv_usec != 0)
				val = 1;

			switch (sopt->sopt_name) {
			case SO_SNDTIMEO:
				so->so_snd.sb_timeo = val;
				break;
			case SO_RCVTIMEO:
				so->so_rcv.sb_timeo = val;
				break;
			}
			break;

		case SO_LABEL:
#ifdef MAC
			error = sooptcopyin(sopt, &extmac, sizeof extmac,
			    sizeof extmac);
			if (error)
				goto bad;
			error = mac_setsockopt_label(sopt->sopt_td->td_ucred,
			    so, &extmac);
#else
			error = EOPNOTSUPP;
#endif
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0 && so->so_proto != NULL &&
		    so->so_proto->pr_ctloutput != NULL) {
			(void) ((*so->so_proto->pr_ctloutput)
				  (so, sopt));
		}
	}
bad:
	return (error);
}

/*
 * Helper routine for getsockopt.
 */
int
sooptcopyout(struct sockopt *sopt, const void *buf, size_t len)
{
	int	error;
	size_t	valsize;

	error = 0;

	/*
	 * Documented get behavior is that we always return a value, possibly
	 * truncated to fit in the user's buffer.  Traditional behavior is
	 * that we always tell the user precisely how much we copied, rather
	 * than something useful like the total amount we had available for
	 * her.  Note that this interface is not idempotent; the entire
	 * answer must generated ahead of time.
	 */
	valsize = min(len, sopt->sopt_valsize);
	sopt->sopt_valsize = valsize;
	if (sopt->sopt_val != NULL) {
		if (sopt->sopt_td != NULL)
			error = copyout(buf, sopt->sopt_val, valsize);
		else
			bcopy(buf, sopt->sopt_val, valsize);
	}
	return (error);
}

int
sogetopt(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
#ifdef MAC
	struct mac extmac;
#endif

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			return ((*so->so_proto->pr_ctloutput)
				  (so, sopt));
		} else
			return (ENOPROTOOPT);
	} else {
		switch (sopt->sopt_name) {
#ifdef INET
		case SO_ACCEPTFILTER:
			error = do_getopt_accept_filter(so, sopt);
			break;
#endif
		case SO_LINGER:
			SOCK_LOCK(so);
			l.l_onoff = so->so_options & SO_LINGER;
			l.l_linger = so->so_linger;
			SOCK_UNLOCK(so);
			error = sooptcopyout(sopt, &l, sizeof l);
			break;

		case SO_USELOOPBACK:
		case SO_DONTROUTE:
		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_BROADCAST:
		case SO_OOBINLINE:
		case SO_ACCEPTCONN:
		case SO_TIMESTAMP:
		case SO_BINTIME:
		case SO_NOSIGPIPE:
			optval = so->so_options & sopt->sopt_name;
integer:
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;

		case SO_TYPE:
			optval = so->so_type;
			goto integer;

		case SO_ERROR:
			SOCK_LOCK(so);
			optval = so->so_error;
			so->so_error = 0;
			SOCK_UNLOCK(so);
			goto integer;

		case SO_SNDBUF:
			optval = so->so_snd.sb_hiwat;
			goto integer;

		case SO_RCVBUF:
			optval = so->so_rcv.sb_hiwat;
			goto integer;

		case SO_SNDLOWAT:
			optval = so->so_snd.sb_lowat;
			goto integer;

		case SO_RCVLOWAT:
			optval = so->so_rcv.sb_lowat;
			goto integer;

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			optval = (sopt->sopt_name == SO_SNDTIMEO ?
				  so->so_snd.sb_timeo : so->so_rcv.sb_timeo);

			tv.tv_sec = optval / hz;
			tv.tv_usec = (optval % hz) * tick;
#ifdef COMPAT_IA32
			if (curthread->td_proc->p_sysent == &ia32_freebsd_sysvec) {
				struct timeval32 tv32;

				CP(tv, tv32, tv_sec);
				CP(tv, tv32, tv_usec);
				error = sooptcopyout(sopt, &tv32, sizeof tv32);
			} else
#endif
				error = sooptcopyout(sopt, &tv, sizeof tv);
			break;

		case SO_LABEL:
#ifdef MAC
			error = sooptcopyin(sopt, &extmac, sizeof(extmac),
			    sizeof(extmac));
			if (error)
				return (error);
			error = mac_getsockopt_label(sopt->sopt_td->td_ucred,
			    so, &extmac);
			if (error)
				return (error);
			error = sooptcopyout(sopt, &extmac, sizeof extmac);
#else
			error = EOPNOTSUPP;
#endif
			break;

		case SO_PEERLABEL:
#ifdef MAC
			error = sooptcopyin(sopt, &extmac, sizeof(extmac),
			    sizeof(extmac));
			if (error)
				return (error);
			error = mac_getsockopt_peerlabel(
			    sopt->sopt_td->td_ucred, so, &extmac);
			if (error)
				return (error);
			error = sooptcopyout(sopt, &extmac, sizeof extmac);
#else
			error = EOPNOTSUPP;
#endif
			break;

		case SO_LISTENQLIMIT:
			optval = so->so_qlimit;
			goto integer;

		case SO_LISTENQLEN:
			optval = so->so_qlen;
			goto integer;

		case SO_LISTENINCQLEN:
			optval = so->so_incqlen;
			goto integer;

		default:
			error = ENOPROTOOPT;
			break;
		}
		return (error);
	}
}

/* XXX; prepare mbuf for (__FreeBSD__ < 3) routines. */
int
soopt_getm(struct sockopt *sopt, struct mbuf **mp)
{
	struct mbuf *m, *m_prev;
	int sopt_size = sopt->sopt_valsize;

	MGET(m, sopt->sopt_td ? M_TRYWAIT : M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return ENOBUFS;
	if (sopt_size > MLEN) {
		MCLGET(m, sopt->sopt_td ? M_TRYWAIT : M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return ENOBUFS;
		}
		m->m_len = min(MCLBYTES, sopt_size);
	} else {
		m->m_len = min(MLEN, sopt_size);
	}
	sopt_size -= m->m_len;
	*mp = m;
	m_prev = m;

	while (sopt_size) {
		MGET(m, sopt->sopt_td ? M_TRYWAIT : M_DONTWAIT, MT_DATA);
		if (m == NULL) {
			m_freem(*mp);
			return ENOBUFS;
		}
		if (sopt_size > MLEN) {
			MCLGET(m, sopt->sopt_td != NULL ? M_TRYWAIT :
			    M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_freem(m);
				m_freem(*mp);
				return ENOBUFS;
			}
			m->m_len = min(MCLBYTES, sopt_size);
		} else {
			m->m_len = min(MLEN, sopt_size);
		}
		sopt_size -= m->m_len;
		m_prev->m_next = m;
		m_prev = m;
	}
	return (0);
}

/* XXX; copyin sopt data into mbuf chain for (__FreeBSD__ < 3) routines. */
int
soopt_mcopyin(struct sockopt *sopt, struct mbuf *m)
{
	struct mbuf *m0 = m;

	if (sopt->sopt_val == NULL)
		return (0);
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_td != NULL) {
			int error;

			error = copyin(sopt->sopt_val, mtod(m, char *),
				       m->m_len);
			if (error != 0) {
				m_freem(m0);
				return(error);
			}
		} else
			bcopy(sopt->sopt_val, mtod(m, char *), m->m_len);
		sopt->sopt_valsize -= m->m_len;
		sopt->sopt_val = (char *)sopt->sopt_val + m->m_len;
		m = m->m_next;
	}
	if (m != NULL) /* should be allocated enoughly at ip6_sooptmcopyin() */
		panic("ip6_sooptmcopyin");
	return (0);
}

/* XXX; copyout mbuf chain data into soopt for (__FreeBSD__ < 3) routines. */
int
soopt_mcopyout(struct sockopt *sopt, struct mbuf *m)
{
	struct mbuf *m0 = m;
	size_t valsize = 0;

	if (sopt->sopt_val == NULL)
		return (0);
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_td != NULL) {
			int error;

			error = copyout(mtod(m, char *), sopt->sopt_val,
				       m->m_len);
			if (error != 0) {
				m_freem(m0);
				return(error);
			}
		} else
			bcopy(mtod(m, char *), sopt->sopt_val, m->m_len);
	       sopt->sopt_valsize -= m->m_len;
	       sopt->sopt_val = (char *)sopt->sopt_val + m->m_len;
	       valsize += m->m_len;
	       m = m->m_next;
	}
	if (m != NULL) {
		/* enough soopt buffer should be given from user-land */
		m_freem(m0);
		return(EINVAL);
	}
	sopt->sopt_valsize = valsize;
	return (0);
}

/*
 * sohasoutofband(): protocol notifies socket layer of the arrival of new
 * out-of-band data, which will then notify socket consumers.
 */
void
sohasoutofband(so)
	struct socket *so;
{
	if (so->so_sigio != NULL)
		pgsigio(&so->so_sigio, SIGURG, 0);
	selwakeuppri(&so->so_rcv.sb_sel, PSOCK);
}

int
sopoll(struct socket *so, int events, struct ucred *active_cred,
    struct thread *td)
{

	/* XXXRW: Temporary debugging. */
	KASSERT(so->so_proto->pr_usrreqs->pru_sopoll != sopoll,
	    ("sopoll: protocol calls sopoll"));

	return (so->so_proto->pr_usrreqs->pru_sopoll(so, events, active_cred,
	    td));
}

int
sopoll_generic(struct socket *so, int events, struct ucred *active_cred,
    struct thread *td)
{
	int revents = 0;

	SOCKBUF_LOCK(&so->so_snd);
	SOCKBUF_LOCK(&so->so_rcv);
	if (events & (POLLIN | POLLRDNORM))
		if (soreadable(so))
			revents |= events & (POLLIN | POLLRDNORM);

	if (events & POLLINIGNEOF)
		if (so->so_rcv.sb_cc >= so->so_rcv.sb_lowat ||
		    !TAILQ_EMPTY(&so->so_comp) || so->so_error)
			revents |= POLLINIGNEOF;

	if (events & (POLLOUT | POLLWRNORM))
		if (sowriteable(so))
			revents |= events & (POLLOUT | POLLWRNORM);

	if (events & (POLLPRI | POLLRDBAND))
		if (so->so_oobmark || (so->so_rcv.sb_state & SBS_RCVATMARK))
			revents |= events & (POLLPRI | POLLRDBAND);

	if (revents == 0) {
		if (events &
		    (POLLIN | POLLINIGNEOF | POLLPRI | POLLRDNORM |
		     POLLRDBAND)) {
			selrecord(td, &so->so_rcv.sb_sel);
			so->so_rcv.sb_flags |= SB_SEL;
		}

		if (events & (POLLOUT | POLLWRNORM)) {
			selrecord(td, &so->so_snd.sb_sel);
			so->so_snd.sb_flags |= SB_SEL;
		}
	}

	SOCKBUF_UNLOCK(&so->so_rcv);
	SOCKBUF_UNLOCK(&so->so_snd);
	return (revents);
}

int
soo_kqfilter(struct file *fp, struct knote *kn)
{
	struct socket *so = kn->kn_fp->f_data;
	struct sockbuf *sb;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (so->so_options & SO_ACCEPTCONN)
			kn->kn_fop = &solisten_filtops;
		else
			kn->kn_fop = &soread_filtops;
		sb = &so->so_rcv;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &sowrite_filtops;
		sb = &so->so_snd;
		break;
	default:
		return (EINVAL);
	}

	SOCKBUF_LOCK(sb);
	knlist_add(&sb->sb_sel.si_note, kn, 1);
	sb->sb_flags |= SB_KNOTE;
	SOCKBUF_UNLOCK(sb);
	return (0);
}

static void
filt_sordetach(struct knote *kn)
{
	struct socket *so = kn->kn_fp->f_data;

	SOCKBUF_LOCK(&so->so_rcv);
	knlist_remove(&so->so_rcv.sb_sel.si_note, kn, 1);
	if (knlist_empty(&so->so_rcv.sb_sel.si_note))
		so->so_rcv.sb_flags &= ~SB_KNOTE;
	SOCKBUF_UNLOCK(&so->so_rcv);
}

/*ARGSUSED*/
static int
filt_soread(struct knote *kn, long hint)
{
	struct socket *so;

	so = kn->kn_fp->f_data;
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	kn->kn_data = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;
	if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
		kn->kn_flags |= EV_EOF;
		kn->kn_fflags = so->so_error;
		return (1);
	} else if (so->so_error)	/* temporary udp error */
		return (1);
	else if (kn->kn_sfflags & NOTE_LOWAT)
		return (kn->kn_data >= kn->kn_sdata);
	else
		return (so->so_rcv.sb_cc >= so->so_rcv.sb_lowat);
}

static void
filt_sowdetach(struct knote *kn)
{
	struct socket *so = kn->kn_fp->f_data;

	SOCKBUF_LOCK(&so->so_snd);
	knlist_remove(&so->so_snd.sb_sel.si_note, kn, 1);
	if (knlist_empty(&so->so_snd.sb_sel.si_note))
		so->so_snd.sb_flags &= ~SB_KNOTE;
	SOCKBUF_UNLOCK(&so->so_snd);
}

/*ARGSUSED*/
static int
filt_sowrite(struct knote *kn, long hint)
{
	struct socket *so;

	so = kn->kn_fp->f_data;
	SOCKBUF_LOCK_ASSERT(&so->so_snd);
	kn->kn_data = sbspace(&so->so_snd);
	if (so->so_snd.sb_state & SBS_CANTSENDMORE) {
		kn->kn_flags |= EV_EOF;
		kn->kn_fflags = so->so_error;
		return (1);
	} else if (so->so_error)	/* temporary udp error */
		return (1);
	else if (((so->so_state & SS_ISCONNECTED) == 0) &&
	    (so->so_proto->pr_flags & PR_CONNREQUIRED))
		return (0);
	else if (kn->kn_sfflags & NOTE_LOWAT)
		return (kn->kn_data >= kn->kn_sdata);
	else
		return (kn->kn_data >= so->so_snd.sb_lowat);
}

/*ARGSUSED*/
static int
filt_solisten(struct knote *kn, long hint)
{
	struct socket *so = kn->kn_fp->f_data;

	kn->kn_data = so->so_qlen;
	return (! TAILQ_EMPTY(&so->so_comp));
}

int
socheckuid(struct socket *so, uid_t uid)
{

	if (so == NULL)
		return (EPERM);
	if (so->so_cred->cr_uid != uid)
		return (EPERM);
	return (0);
}

static int
somaxconn_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error;
	int val;

	val = somaxconn;
	error = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (error || !req->newptr )
		return (error);

	if (val < 1 || val > USHRT_MAX)
		return (EINVAL);

	somaxconn = val;
	return (0);
}
