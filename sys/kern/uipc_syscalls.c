/*
 * Copyright (c) 1982, 1986, 1989, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * sendfile(2) and related extensions:
 * Copyright (c) 1998, David Greenman. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *	@(#)uipc_syscalls.c	8.4 (Berkeley) 2/21/94
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"
#include "opt_ktrace.h"
#include "opt_mac.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/filedesc.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/mount.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/sf_buf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>

static int sendit(struct thread *td, int s, struct msghdr *mp, int flags);
static int recvit(struct thread *td, int s, struct msghdr *mp, void *namelenp);

static int accept1(struct thread *td, struct accept_args *uap, int compat);
static int do_sendfile(struct thread *td, struct sendfile_args *uap, int compat);
static int getsockname1(struct thread *td, struct getsockname_args *uap,
			int compat);
static int getpeername1(struct thread *td, struct getpeername_args *uap,
			int compat);

/*
 * System call interface to the socket abstraction.
 */
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
#define COMPAT_OLDSOCK
#endif

/*
 * MPSAFE
 */
int
socket(td, uap)
	struct thread *td;
	register struct socket_args /* {
		int	domain;
		int	type;
		int	protocol;
	} */ *uap;
{
	struct filedesc *fdp;
	struct socket *so;
	struct file *fp;
	int fd, error;

	fdp = td->td_proc->p_fd;
	error = falloc(td, &fp, &fd);
	if (error)
		goto done2;
	/* An extra reference on `fp' has been held for us by falloc(). */
	mtx_lock(&Giant);
	error = socreate(uap->domain, &so, uap->type, uap->protocol,
	    td->td_ucred, td);
	mtx_unlock(&Giant);
	FILEDESC_LOCK(fdp);
	if (error) {
		if (fdp->fd_ofiles[fd] == fp) {
			fdp->fd_ofiles[fd] = NULL;
			fdunused(fdp, fd);
			FILEDESC_UNLOCK(fdp);
			fdrop(fp, td);
		} else {
			FILEDESC_UNLOCK(fdp);
		}
	} else {
		fp->f_data = so;	/* already has ref count */
		fp->f_flag = FREAD|FWRITE;
		fp->f_ops = &socketops;
		fp->f_type = DTYPE_SOCKET;
		FILEDESC_UNLOCK(fdp);
		td->td_retval[0] = fd;
	}
	fdrop(fp, td);
done2:
	return (error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
bind(td, uap)
	struct thread *td;
	register struct bind_args /* {
		int	s;
		caddr_t	name;
		int	namelen;
	} */ *uap;
{
	struct sockaddr *sa;
	int error;

	if ((error = getsockaddr(&sa, uap->name, uap->namelen)) != 0)
		return (error);

	return (kern_bind(td, uap->s, sa));
}

int
kern_bind(td, fd, sa)
	struct thread *td;
	int fd;
	struct sockaddr *sa;
{
	struct socket *so;
	int error;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, fd, &so, NULL)) != 0)
		goto done2;
#ifdef MAC
	error = mac_check_socket_bind(td->td_ucred, so, sa);
	if (error)
		goto done1;
#endif
	error = sobind(so, sa, td);
#ifdef MAC
done1:
#endif
	fputsock(so);
done2:
	mtx_unlock(&Giant);
	FREE(sa, M_SONAME);
	return (error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
listen(td, uap)
	struct thread *td;
	register struct listen_args /* {
		int	s;
		int	backlog;
	} */ *uap;
{
	struct socket *so;
	int error;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, uap->s, &so, NULL)) == 0) {
#ifdef MAC
		error = mac_check_socket_listen(td->td_ucred, so);
		if (error)
			goto done;
#endif
		error = solisten(so, uap->backlog, td);
#ifdef MAC
done:
#endif
		fputsock(so);
	}
	mtx_unlock(&Giant);
	return(error);
}

/*
 * accept1()
 * MPSAFE
 */
static int
accept1(td, uap, compat)
	struct thread *td;
	register struct accept_args /* {
		int	s;
		struct sockaddr	* __restrict name;
		socklen_t	* __restrict anamelen;
	} */ *uap;
	int compat;
{
	struct filedesc *fdp;
	struct file *nfp = NULL;
	struct sockaddr *sa;
	socklen_t namelen;
	int error, s;
	struct socket *head, *so;
	int fd;
	u_int fflag;
	pid_t pgid;
	int tmp;

	fdp = td->td_proc->p_fd;
	if (uap->name) {
		error = copyin(uap->anamelen, &namelen, sizeof (namelen));
		if(error)
			goto done3;
		if (namelen < 0) {
			error = EINVAL;
			goto done3;
		}
	}
	mtx_lock(&Giant);
	error = fgetsock(td, uap->s, &head, &fflag);
	if (error)
		goto done2;
	s = splnet();
	if ((head->so_options & SO_ACCEPTCONN) == 0) {
		splx(s);
		error = EINVAL;
		goto done;
	}
	while (TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_state & SS_CANTRCVMORE) {
			head->so_error = ECONNABORTED;
			break;
		}
		if ((head->so_state & SS_NBIO) != 0) {
			head->so_error = EWOULDBLOCK;
			break;
		}
		error = tsleep(&head->so_timeo, PSOCK | PCATCH,
		    "accept", 0);
		if (error) {
			splx(s);
			goto done;
		}
	}
	if (head->so_error) {
		error = head->so_error;
		head->so_error = 0;
		splx(s);
		goto done;
	}

	/*
	 * At this point we know that there is at least one connection
	 * ready to be accepted. Remove it from the queue prior to
	 * allocating the file descriptor for it since falloc() may
	 * block allowing another process to accept the connection
	 * instead.
	 */
	so = TAILQ_FIRST(&head->so_comp);
	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;

	error = falloc(td, &nfp, &fd);
	if (error) {
		/*
		 * Probably ran out of file descriptors. Put the
		 * unaccepted connection back onto the queue and
		 * do another wakeup so some other process might
		 * have a chance at it.
		 */
		TAILQ_INSERT_HEAD(&head->so_comp, so, so_list);
		head->so_qlen++;
		wakeup_one(&head->so_timeo);
		splx(s);
		goto done;
	}
	/* An extra reference on `nfp' has been held for us by falloc(). */
	td->td_retval[0] = fd;

	/* connection has been removed from the listen queue */
	KNOTE(&head->so_rcv.sb_sel.si_note, 0);

	so->so_state &= ~SS_COMP;
	so->so_head = NULL;
	pgid = fgetown(&head->so_sigio);
	if (pgid != 0)
		fsetown(pgid, &so->so_sigio);

	FILE_LOCK(nfp);
	soref(so);			/* file descriptor reference */
	nfp->f_data = so;	/* nfp has ref count from falloc */
	nfp->f_flag = fflag;
	nfp->f_ops = &socketops;
	nfp->f_type = DTYPE_SOCKET;
	FILE_UNLOCK(nfp);
	/* Sync socket nonblocking/async state with file flags */
	tmp = fflag & FNONBLOCK;
	(void) fo_ioctl(nfp, FIONBIO, &tmp, td->td_ucred, td);
	tmp = fflag & FASYNC;
	(void) fo_ioctl(nfp, FIOASYNC, &tmp, td->td_ucred, td);
	sa = 0;
	error = soaccept(so, &sa);
	if (error) {
		/*
		 * return a namelen of zero for older code which might
		 * ignore the return value from accept.
		 */
		if (uap->name != NULL) {
			namelen = 0;
			(void) copyout(&namelen,
			    uap->anamelen, sizeof(*uap->anamelen));
		}
		goto noconnection;
	}
	if (sa == NULL) {
		namelen = 0;
		if (uap->name)
			goto gotnoname;
		splx(s);
		error = 0;
		goto done;
	}
	if (uap->name) {
		/* check sa_len before it is destroyed */
		if (namelen > sa->sa_len)
			namelen = sa->sa_len;
#ifdef COMPAT_OLDSOCK
		if (compat)
			((struct osockaddr *)sa)->sa_family =
			    sa->sa_family;
#endif
		error = copyout(sa, uap->name, (u_int)namelen);
		if (!error)
gotnoname:
			error = copyout(&namelen,
			    uap->anamelen, sizeof (*uap->anamelen));
	}
noconnection:
	if (sa)
		FREE(sa, M_SONAME);

	/*
	 * close the new descriptor, assuming someone hasn't ripped it
	 * out from under us.
	 */
	if (error) {
		FILEDESC_LOCK(fdp);
		if (fdp->fd_ofiles[fd] == nfp) {
			fdp->fd_ofiles[fd] = NULL;
			fdunused(fdp, fd);
			FILEDESC_UNLOCK(fdp);
			fdrop(nfp, td);
		} else {
			FILEDESC_UNLOCK(fdp);
		}
	}
	splx(s);

	/*
	 * Release explicitly held references before returning.
	 */
done:
	if (nfp != NULL)
		fdrop(nfp, td);
	fputsock(head);
done2:
	mtx_unlock(&Giant);
done3:
	return (error);
}

/*
 * MPSAFE (accept1() is MPSAFE)
 */
int
accept(td, uap)
	struct thread *td;
	struct accept_args *uap;
{

	return (accept1(td, uap, 0));
}

#ifdef COMPAT_OLDSOCK
/*
 * MPSAFE (accept1() is MPSAFE)
 */
int
oaccept(td, uap)
	struct thread *td;
	struct accept_args *uap;
{

	return (accept1(td, uap, 1));
}
#endif /* COMPAT_OLDSOCK */

/*
 * MPSAFE
 */
/* ARGSUSED */
int
connect(td, uap)
	struct thread *td;
	register struct connect_args /* {
		int	s;
		caddr_t	name;
		int	namelen;
	} */ *uap;
{
	struct sockaddr *sa;
	int error;

	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error)
		return (error);

	return (kern_connect(td, uap->s, sa));
}


int
kern_connect(td, fd, sa)
	struct thread *td;
	int fd;
	struct sockaddr *sa;
{
	struct socket *so;
	int error, s;
	int interrupted = 0;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, fd, &so, NULL)) != 0)
		goto done2;
	if (so->so_state & SS_ISCONNECTING) {
		error = EALREADY;
		goto done1;
	}
#ifdef MAC
	error = mac_check_socket_connect(td->td_ucred, so, sa);
	if (error)
		goto bad;
#endif
	error = soconnect(so, sa, td);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		error = EINPROGRESS;
		goto done1;
	}
	s = splnet();
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = tsleep(&so->so_timeo, PSOCK | PCATCH, "connec", 0);
		if (error) {
			if (error == EINTR || error == ERESTART)
				interrupted = 1;
			break;
		}
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	splx(s);
bad:
	if (!interrupted)
		so->so_state &= ~SS_ISCONNECTING;
	if (error == ERESTART)
		error = EINTR;
done1:
	fputsock(so);
done2:
	mtx_unlock(&Giant);
	FREE(sa, M_SONAME);
	return (error);
}

/*
 * MPSAFE
 */
int
socketpair(td, uap)
	struct thread *td;
	register struct socketpair_args /* {
		int	domain;
		int	type;
		int	protocol;
		int	*rsv;
	} */ *uap;
{
	register struct filedesc *fdp = td->td_proc->p_fd;
	struct file *fp1, *fp2;
	struct socket *so1, *so2;
	int fd, error, sv[2];

	mtx_lock(&Giant);
	error = socreate(uap->domain, &so1, uap->type, uap->protocol,
	    td->td_ucred, td);
	if (error)
		goto done2;
	error = socreate(uap->domain, &so2, uap->type, uap->protocol,
	    td->td_ucred, td);
	if (error)
		goto free1;
	/* On success extra reference to `fp1' and 'fp2' is set by falloc. */
	error = falloc(td, &fp1, &fd);
	if (error)
		goto free2;
	sv[0] = fd;
	fp1->f_data = so1;	/* so1 already has ref count */
	error = falloc(td, &fp2, &fd);
	if (error)
		goto free3;
	fp2->f_data = so2;	/* so2 already has ref count */
	sv[1] = fd;
	error = soconnect2(so1, so2);
	if (error)
		goto free4;
	if (uap->type == SOCK_DGRAM) {
		/*
		 * Datagram socket connection is asymmetric.
		 */
		 error = soconnect2(so2, so1);
		 if (error)
			goto free4;
	}
	FILE_LOCK(fp1);
	fp1->f_flag = FREAD|FWRITE;
	fp1->f_ops = &socketops;
	fp1->f_type = DTYPE_SOCKET;
	FILE_UNLOCK(fp1);
	FILE_LOCK(fp2);
	fp2->f_flag = FREAD|FWRITE;
	fp2->f_ops = &socketops;
	fp2->f_type = DTYPE_SOCKET;
	FILE_UNLOCK(fp2);
	error = copyout(sv, uap->rsv, 2 * sizeof (int));
	fdrop(fp1, td);
	fdrop(fp2, td);
	goto done2;
free4:
	FILEDESC_LOCK(fdp);
	if (fdp->fd_ofiles[sv[1]] == fp2) {
		fdp->fd_ofiles[sv[1]] = NULL;
		fdunused(fdp, sv[1]);
		FILEDESC_UNLOCK(fdp);
		fdrop(fp2, td);
	} else {
		FILEDESC_UNLOCK(fdp);
	}
	fdrop(fp2, td);
free3:
	FILEDESC_LOCK(fdp);
	if (fdp->fd_ofiles[sv[0]] == fp1) {
		fdp->fd_ofiles[sv[0]] = NULL;
		fdunused(fdp, sv[0]);
		FILEDESC_UNLOCK(fdp);
		fdrop(fp1, td);
	} else {
		FILEDESC_UNLOCK(fdp);
	}
	fdrop(fp1, td);
free2:
	(void)soclose(so2);
free1:
	(void)soclose(so1);
done2:
	mtx_unlock(&Giant);
	return (error);
}

static int
sendit(td, s, mp, flags)
	register struct thread *td;
	int s;
	register struct msghdr *mp;
	int flags;
{
	struct mbuf *control;
	struct sockaddr *to;
	int error;

	if (mp->msg_name != NULL) {
		error = getsockaddr(&to, mp->msg_name, mp->msg_namelen);
		if (error) {
			to = NULL;
			goto bad;
		}
		mp->msg_name = to;
	} else {
		to = NULL;
	}

	if (mp->msg_control) {
		if (mp->msg_controllen < sizeof(struct cmsghdr)
#ifdef COMPAT_OLDSOCK
		    && mp->msg_flags != MSG_COMPAT
#endif
		) {
			error = EINVAL;
			goto bad;
		}
		error = sockargs(&control, mp->msg_control,
		    mp->msg_controllen, MT_CONTROL);
		if (error)
			goto bad;
#ifdef COMPAT_OLDSOCK
		if (mp->msg_flags == MSG_COMPAT) {
			register struct cmsghdr *cm;

			M_PREPEND(control, sizeof(*cm), M_TRYWAIT);
			if (control == 0) {
				error = ENOBUFS;
				goto bad;
			} else {
				cm = mtod(control, struct cmsghdr *);
				cm->cmsg_len = control->m_len;
				cm->cmsg_level = SOL_SOCKET;
				cm->cmsg_type = SCM_RIGHTS;
			}
		}
#endif
	} else {
		control = NULL;
	}

	error = kern_sendit(td, s, mp, flags, control);

bad:
	if (to)
		FREE(to, M_SONAME);
	return (error);
}

int
kern_sendit(td, s, mp, flags, control)
	struct thread *td;
	int s;
	struct msghdr *mp;
	int flags;
	struct mbuf *control;
{
	struct uio auio;
	struct iovec *iov;
	struct socket *so;
	int i;
	int len, error;
#ifdef KTRACE
	struct iovec *ktriov = NULL;
	struct uio ktruio;
	int iovlen;
#endif

	mtx_lock(&Giant);
	if ((error = fgetsock(td, s, &so, NULL)) != 0)
		goto bad2;

#ifdef MAC
	error = mac_check_socket_send(td->td_ucred, so);
	if (error)
		goto bad;
#endif

	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if ((auio.uio_resid += iov->iov_len) < 0) {
			error = EINVAL;
			goto bad;
		}
	}
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO)) {
		iovlen = auio.uio_iovcnt * sizeof (struct iovec);
		MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
		bcopy(auio.uio_iov, ktriov, iovlen);
		ktruio = auio;
	}
#endif
	len = auio.uio_resid;
	error = so->so_proto->pr_usrreqs->pru_sosend(so, mp->msg_name, &auio,
	    0, control, flags, td);
	if (error) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* Generation of SIGPIPE can be controlled per socket */
		if (error == EPIPE && !(so->so_options & SO_NOSIGPIPE)) {
			PROC_LOCK(td->td_proc);
			psignal(td->td_proc, SIGPIPE);
			PROC_UNLOCK(td->td_proc);
		}
	}
	if (error == 0)
		td->td_retval[0] = len - auio.uio_resid;
#ifdef KTRACE
	if (ktriov != NULL) {
		if (error == 0) {
			ktruio.uio_iov = ktriov;
			ktruio.uio_resid = td->td_retval[0];
			ktrgenio(s, UIO_WRITE, &ktruio, error);
		}
		FREE(ktriov, M_TEMP);
	}
#endif
bad:
	fputsock(so);
bad2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * MPSAFE
 */
int
sendto(td, uap)
	struct thread *td;
	register struct sendto_args /* {
		int	s;
		caddr_t	buf;
		size_t	len;
		int	flags;
		caddr_t	to;
		int	tolen;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	msg.msg_name = uap->to;
	msg.msg_namelen = uap->tolen;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = 0;
#endif
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	error = sendit(td, uap->s, &msg, uap->flags);
	return (error);
}

#ifdef COMPAT_OLDSOCK
/*
 * MPSAFE
 */
int
osend(td, uap)
	struct thread *td;
	register struct osend_args /* {
		int	s;
		caddr_t	buf;
		int	len;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = 0;
	error = sendit(td, uap->s, &msg, uap->flags);
	return (error);
}

/*
 * MPSAFE
 */
int
osendmsg(td, uap)
	struct thread *td;
	register struct osendmsg_args /* {
		int	s;
		caddr_t	msg;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	error = copyin(uap->msg, &msg, sizeof (struct omsghdr));
	if (error)
		goto done2;
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV) {
			error = EMSGSIZE;
			goto done2;
		}
		MALLOC(iov, struct iovec *,
		      sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		      M_WAITOK);
	} else {
		iov = aiov;
	}
	error = copyin(msg.msg_iov, iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)));
	if (error)
		goto done;
	msg.msg_flags = MSG_COMPAT;
	msg.msg_iov = iov;
	error = sendit(td, uap->s, &msg, uap->flags);
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
done2:
	return (error);
}
#endif

/*
 * MPSAFE
 */
int
sendmsg(td, uap)
	struct thread *td;
	register struct sendmsg_args /* {
		int	s;
		caddr_t	msg;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	error = copyin(uap->msg, &msg, sizeof (msg));
	if (error)
		goto done2;
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV) {
			error = EMSGSIZE;
			goto done2;
		}
		MALLOC(iov, struct iovec *,
		       sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		       M_WAITOK);
	} else {
		iov = aiov;
	}
	if (msg.msg_iovlen &&
	    (error = copyin(msg.msg_iov, iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)))))
		goto done;
	msg.msg_iov = iov;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = 0;
#endif
	error = sendit(td, uap->s, &msg, uap->flags);
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
done2:
	return (error);
}

static int
recvit(td, s, mp, namelenp)
	register struct thread *td;
	int s;
	register struct msghdr *mp;
	void *namelenp;
{
	struct uio auio;
	register struct iovec *iov;
	register int i;
	socklen_t len;
	int error;
	struct mbuf *m, *control = 0;
	caddr_t ctlbuf;
	struct socket *so;
	struct sockaddr *fromsa = 0;
#ifdef KTRACE
	struct iovec *ktriov = NULL;
	struct uio ktruio;
	int iovlen;
#endif

	mtx_lock(&Giant);
	if ((error = fgetsock(td, s, &so, NULL)) != 0) {
		mtx_unlock(&Giant);
		return (error);
	}

#ifdef MAC
	error = mac_check_socket_receive(td->td_ucred, so);
	if (error) {
		fputsock(so);
		mtx_unlock(&Giant);
		return (error);
	}
#endif

	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if ((auio.uio_resid += iov->iov_len) < 0) {
			fputsock(so);
			return (EINVAL);
		}
	}
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO)) {
		iovlen = auio.uio_iovcnt * sizeof (struct iovec);
		MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
		bcopy(auio.uio_iov, ktriov, iovlen);
		ktruio = auio;
	}
#endif
	len = auio.uio_resid;
	error = so->so_proto->pr_usrreqs->pru_soreceive(so, &fromsa, &auio,
	    (struct mbuf **)0, mp->msg_control ? &control : (struct mbuf **)0,
	    &mp->msg_flags);
	if (error) {
		if (auio.uio_resid != (int)len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
#ifdef KTRACE
	if (ktriov != NULL) {
		if (error == 0) {
			ktruio.uio_iov = ktriov;
			ktruio.uio_resid = (int)len - auio.uio_resid;
			ktrgenio(s, UIO_READ, &ktruio, error);
		}
		FREE(ktriov, M_TEMP);
	}
#endif
	if (error)
		goto out;
	td->td_retval[0] = (int)len - auio.uio_resid;
	if (mp->msg_name) {
		len = mp->msg_namelen;
		if (len <= 0 || fromsa == 0)
			len = 0;
		else {
			/* save sa_len before it is destroyed by MSG_COMPAT */
			len = MIN(len, fromsa->sa_len);
#ifdef COMPAT_OLDSOCK
			if (mp->msg_flags & MSG_COMPAT)
				((struct osockaddr *)fromsa)->sa_family =
				    fromsa->sa_family;
#endif
			error = copyout(fromsa, mp->msg_name, (unsigned)len);
			if (error)
				goto out;
		}
		mp->msg_namelen = len;
		if (namelenp &&
		    (error = copyout(&len, namelenp, sizeof (socklen_t)))) {
#ifdef COMPAT_OLDSOCK
			if (mp->msg_flags & MSG_COMPAT)
				error = 0;	/* old recvfrom didn't check */
			else
#endif
			goto out;
		}
	}
	if (mp->msg_control) {
#ifdef COMPAT_OLDSOCK
		/*
		 * We assume that old recvmsg calls won't receive access
		 * rights and other control info, esp. as control info
		 * is always optional and those options didn't exist in 4.3.
		 * If we receive rights, trim the cmsghdr; anything else
		 * is tossed.
		 */
		if (control && mp->msg_flags & MSG_COMPAT) {
			if (mtod(control, struct cmsghdr *)->cmsg_level !=
			    SOL_SOCKET ||
			    mtod(control, struct cmsghdr *)->cmsg_type !=
			    SCM_RIGHTS) {
				mp->msg_controllen = 0;
				goto out;
			}
			control->m_len -= sizeof (struct cmsghdr);
			control->m_data += sizeof (struct cmsghdr);
		}
#endif
		len = mp->msg_controllen;
		m = control;
		mp->msg_controllen = 0;
		ctlbuf = mp->msg_control;

		while (m && len > 0) {
			unsigned int tocopy;

			if (len >= m->m_len)
				tocopy = m->m_len;
			else {
				mp->msg_flags |= MSG_CTRUNC;
				tocopy = len;
			}

			if ((error = copyout(mtod(m, caddr_t),
					ctlbuf, tocopy)) != 0)
				goto out;

			ctlbuf += tocopy;
			len -= tocopy;
			m = m->m_next;
		}
		mp->msg_controllen = ctlbuf - (caddr_t)mp->msg_control;
	}
out:
	fputsock(so);
	mtx_unlock(&Giant);
	if (fromsa)
		FREE(fromsa, M_SONAME);
	if (control)
		m_freem(control);
	return (error);
}

/*
 * MPSAFE
 */
int
recvfrom(td, uap)
	struct thread *td;
	register struct recvfrom_args /* {
		int	s;
		caddr_t	buf;
		size_t	len;
		int	flags;
		struct sockaddr * __restrict	from;
		socklen_t * __restrict fromlenaddr;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	if (uap->fromlenaddr) {
		error = copyin(uap->fromlenaddr,
		    &msg.msg_namelen, sizeof (msg.msg_namelen));
		if (error)
			goto done2;
	} else {
		msg.msg_namelen = 0;
	}
	msg.msg_name = uap->from;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	error = recvit(td, uap->s, &msg, uap->fromlenaddr);
done2:
	return(error);
}

#ifdef COMPAT_OLDSOCK
/*
 * MPSAFE
 */
int
orecvfrom(td, uap)
	struct thread *td;
	struct recvfrom_args *uap;
{

	uap->flags |= MSG_COMPAT;
	return (recvfrom(td, uap));
}
#endif


#ifdef COMPAT_OLDSOCK
/*
 * MPSAFE
 */
int
orecv(td, uap)
	struct thread *td;
	register struct orecv_args /* {
		int	s;
		caddr_t	buf;
		int	len;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	error = recvit(td, uap->s, &msg, NULL);
	return (error);
}

/*
 * Old recvmsg.  This code takes advantage of the fact that the old msghdr
 * overlays the new one, missing only the flags, and with the (old) access
 * rights where the control fields are now.
 *
 * MPSAFE
 */
int
orecvmsg(td, uap)
	struct thread *td;
	register struct orecvmsg_args /* {
		int	s;
		struct	omsghdr *msg;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	error = copyin(uap->msg, &msg, sizeof (struct omsghdr));
	if (error)
		return (error);

	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV) {
			error = EMSGSIZE;
			goto done2;
		}
		MALLOC(iov, struct iovec *,
		      sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		      M_WAITOK);
	} else {
		iov = aiov;
	}
	msg.msg_flags = uap->flags | MSG_COMPAT;
	error = copyin(msg.msg_iov, iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)));
	if (error)
		goto done;
	msg.msg_iov = iov;
	error = recvit(td, uap->s, &msg, &uap->msg->msg_namelen);

	if (msg.msg_controllen && error == 0)
		error = copyout(&msg.msg_controllen,
		    &uap->msg->msg_accrightslen, sizeof (int));
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
done2:
	return (error);
}
#endif

/*
 * MPSAFE
 */
int
recvmsg(td, uap)
	struct thread *td;
	register struct recvmsg_args /* {
		int	s;
		struct	msghdr *msg;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *uiov, *iov;
	register int error;

	error = copyin(uap->msg, &msg, sizeof (msg));
	if (error)
		goto done2;
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV) {
			error = EMSGSIZE;
			goto done2;
		}
		MALLOC(iov, struct iovec *,
		       sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		       M_WAITOK);
	} else {
		iov = aiov;
	}
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = uap->flags &~ MSG_COMPAT;
#else
	msg.msg_flags = uap->flags;
#endif
	uiov = msg.msg_iov;
	msg.msg_iov = iov;
	error = copyin(uiov, iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)));
	if (error)
		goto done;
	error = recvit(td, uap->s, &msg, NULL);
	if (!error) {
		msg.msg_iov = uiov;
		error = copyout(&msg, uap->msg, sizeof(msg));
	}
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
done2:
	return (error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
shutdown(td, uap)
	struct thread *td;
	register struct shutdown_args /* {
		int	s;
		int	how;
	} */ *uap;
{
	struct socket *so;
	int error;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, uap->s, &so, NULL)) == 0) {
		error = soshutdown(so, uap->how);
		fputsock(so);
	}
	mtx_unlock(&Giant);
	return(error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
setsockopt(td, uap)
	struct thread *td;
	register struct setsockopt_args /* {
		int	s;
		int	level;
		int	name;
		caddr_t	val;
		int	valsize;
	} */ *uap;
{
	struct socket *so;
	struct sockopt sopt;
	int error;

	if (uap->val == 0 && uap->valsize != 0)
		return (EFAULT);
	if (uap->valsize < 0)
		return (EINVAL);

	mtx_lock(&Giant);
	if ((error = fgetsock(td, uap->s, &so, NULL)) == 0) {
		sopt.sopt_dir = SOPT_SET;
		sopt.sopt_level = uap->level;
		sopt.sopt_name = uap->name;
		sopt.sopt_val = uap->val;
		sopt.sopt_valsize = uap->valsize;
		sopt.sopt_td = td;
		error = sosetopt(so, &sopt);
		fputsock(so);
	}
	mtx_unlock(&Giant);
	return(error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
getsockopt(td, uap)
	struct thread *td;
	register struct getsockopt_args /* {
		int	s;
		int	level;
		int	name;
		void * __restrict	val;
		socklen_t * __restrict avalsize;
	} */ *uap;
{
	socklen_t valsize;
	int	error;
	struct  socket *so;
	struct	sockopt sopt;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, uap->s, &so, NULL)) != 0)
		goto done2;
	if (uap->val) {
		error = copyin(uap->avalsize, &valsize, sizeof (valsize));
		if (error)
			goto done1;
		if (valsize < 0) {
			error = EINVAL;
			goto done1;
		}
	} else {
		valsize = 0;
	}

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = uap->level;
	sopt.sopt_name = uap->name;
	sopt.sopt_val = uap->val;
	sopt.sopt_valsize = (size_t)valsize; /* checked non-negative above */
	sopt.sopt_td = td;

	error = sogetopt(so, &sopt);
	if (error == 0) {
		valsize = sopt.sopt_valsize;
		error = copyout(&valsize, uap->avalsize, sizeof (valsize));
	}
done1:
	fputsock(so);
done2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * getsockname1() - Get socket name.
 *
 * MPSAFE
 */
/* ARGSUSED */
static int
getsockname1(td, uap, compat)
	struct thread *td;
	register struct getsockname_args /* {
		int	fdes;
		struct sockaddr * __restrict asa;
		socklen_t * __restrict alen;
	} */ *uap;
	int compat;
{
	struct socket *so;
	struct sockaddr *sa;
	socklen_t len;
	int error;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, uap->fdes, &so, NULL)) != 0)
		goto done2;
	error = copyin(uap->alen, &len, sizeof (len));
	if (error)
		goto done1;
	if (len < 0) {
		error = EINVAL;
		goto done1;
	}
	sa = 0;
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}

	len = MIN(len, sa->sa_len);
#ifdef COMPAT_OLDSOCK
	if (compat)
		((struct osockaddr *)sa)->sa_family = sa->sa_family;
#endif
	error = copyout(sa, uap->asa, (u_int)len);
	if (error == 0)
gotnothing:
		error = copyout(&len, uap->alen, sizeof (len));
bad:
	if (sa)
		FREE(sa, M_SONAME);
done1:
	fputsock(so);
done2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * MPSAFE
 */
int
getsockname(td, uap)
	struct thread *td;
	struct getsockname_args *uap;
{

	return (getsockname1(td, uap, 0));
}

#ifdef COMPAT_OLDSOCK
/*
 * MPSAFE
 */
int
ogetsockname(td, uap)
	struct thread *td;
	struct getsockname_args *uap;
{

	return (getsockname1(td, uap, 1));
}
#endif /* COMPAT_OLDSOCK */

/*
 * getpeername1() - Get name of peer for connected socket.
 *
 * MPSAFE
 */
/* ARGSUSED */
static int
getpeername1(td, uap, compat)
	struct thread *td;
	register struct getpeername_args /* {
		int	fdes;
		struct sockaddr * __restrict	asa;
		socklen_t * __restrict	alen;
	} */ *uap;
	int compat;
{
	struct socket *so;
	struct sockaddr *sa;
	socklen_t len;
	int error;

	mtx_lock(&Giant);
	if ((error = fgetsock(td, uap->fdes, &so, NULL)) != 0)
		goto done2;
	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONFIRMING)) == 0) {
		error = ENOTCONN;
		goto done1;
	}
	error = copyin(uap->alen, &len, sizeof (len));
	if (error)
		goto done1;
	if (len < 0) {
		error = EINVAL;
		goto done1;
	}
	sa = 0;
	error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, &sa);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}
	len = MIN(len, sa->sa_len);
#ifdef COMPAT_OLDSOCK
	if (compat)
		((struct osockaddr *)sa)->sa_family =
		    sa->sa_family;
#endif
	error = copyout(sa, uap->asa, (u_int)len);
	if (error)
		goto bad;
gotnothing:
	error = copyout(&len, uap->alen, sizeof (len));
bad:
	if (sa)
		FREE(sa, M_SONAME);
done1:
	fputsock(so);
done2:
	mtx_unlock(&Giant);
	return (error);
}

/*
 * MPSAFE
 */
int
getpeername(td, uap)
	struct thread *td;
	struct getpeername_args *uap;
{

	return (getpeername1(td, uap, 0));
}

#ifdef COMPAT_OLDSOCK
/*
 * MPSAFE
 */
int
ogetpeername(td, uap)
	struct thread *td;
	struct ogetpeername_args *uap;
{

	/* XXX uap should have type `getpeername_args *' to begin with. */
	return (getpeername1(td, (struct getpeername_args *)uap, 1));
}
#endif /* COMPAT_OLDSOCK */

int
sockargs(mp, buf, buflen, type)
	struct mbuf **mp;
	caddr_t buf;
	int buflen, type;
{
	register struct sockaddr *sa;
	register struct mbuf *m;
	int error;

	if ((u_int)buflen > MLEN) {
#ifdef COMPAT_OLDSOCK
		if (type == MT_SONAME && (u_int)buflen <= 112)
			buflen = MLEN;		/* unix domain compat. hack */
		else
#endif
		return (EINVAL);
	}
	m = m_get(M_TRYWAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	m->m_len = buflen;
	error = copyin(buf, mtod(m, caddr_t), (u_int)buflen);
	if (error)
		(void) m_free(m);
	else {
		*mp = m;
		if (type == MT_SONAME) {
			sa = mtod(m, struct sockaddr *);

#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
			if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
				sa->sa_family = sa->sa_len;
#endif
			sa->sa_len = buflen;
		}
	}
	return (error);
}

int
getsockaddr(namp, uaddr, len)
	struct sockaddr **namp;
	caddr_t uaddr;
	size_t len;
{
	struct sockaddr *sa;
	int error;

	if (len > SOCK_MAXADDRLEN)
		return (ENAMETOOLONG);
	if (len < offsetof(struct sockaddr, sa_data[0]))
		return (EINVAL);
	MALLOC(sa, struct sockaddr *, len, M_SONAME, M_WAITOK);
	error = copyin(uaddr, sa, len);
	if (error) {
		FREE(sa, M_SONAME);
	} else {
#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
		if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
			sa->sa_family = sa->sa_len;
#endif
		sa->sa_len = len;
		*namp = sa;
	}
	return (error);
}

/*
 * sendfile(2)
 *
 * MPSAFE
 *
 * int sendfile(int fd, int s, off_t offset, size_t nbytes,
 *	 struct sf_hdtr *hdtr, off_t *sbytes, int flags)
 *
 * Send a file specified by 'fd' and starting at 'offset' to a socket
 * specified by 's'. Send only 'nbytes' of the file or until EOF if
 * nbytes == 0. Optionally add a header and/or trailer to the socket
 * output. If specified, write the total number of bytes sent into *sbytes.
 *
 */
int
sendfile(struct thread *td, struct sendfile_args *uap)
{

	return (do_sendfile(td, uap, 0));
}

#ifdef COMPAT_FREEBSD4
int
freebsd4_sendfile(struct thread *td, struct freebsd4_sendfile_args *uap)
{
	struct sendfile_args args;

	args.fd = uap->fd;
	args.s = uap->s;
	args.offset = uap->offset;
	args.nbytes = uap->nbytes;
	args.hdtr = uap->hdtr;
	args.sbytes = uap->sbytes;
	args.flags = uap->flags;

	return (do_sendfile(td, &args, 1));
}
#endif /* COMPAT_FREEBSD4 */

static int
do_sendfile(struct thread *td, struct sendfile_args *uap, int compat)
{
	struct vnode *vp;
	struct vm_object *obj;
	struct socket *so = NULL;
	struct mbuf *m, *m_header = NULL;
	struct sf_buf *sf;
	struct vm_page *pg;
	struct writev_args nuap;
	struct sf_hdtr hdtr;
	struct uio hdr_uio;
	off_t off, xfsize, hdtr_size, sbytes = 0;
	int error, s, headersize = 0, headersent = 0;
	struct iovec *hdr_iov = NULL;

	mtx_lock(&Giant);

	hdtr_size = 0;

	/*
	 * The descriptor must be a regular file and have a backing VM object.
	 */
	if ((error = fgetvp_read(td, uap->fd, &vp)) != 0)
		goto done;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, td);
	if (vp->v_type != VREG || VOP_GETVOBJECT(vp, &obj) != 0) {
		error = EINVAL;
		VOP_UNLOCK(vp, 0, td);
		goto done;
	}
	VOP_UNLOCK(vp, 0, td);
	if ((error = fgetsock(td, uap->s, &so, NULL)) != 0)
		goto done;
	if (so->so_type != SOCK_STREAM) {
		error = EINVAL;
		goto done;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		error = ENOTCONN;
		goto done;
	}
	if (uap->offset < 0) {
		error = EINVAL;
		goto done;
	}

#ifdef MAC
	error = mac_check_socket_send(td->td_ucred, so);
	if (error)
		goto done;
#endif

	/*
	 * If specified, get the pointer to the sf_hdtr struct for
	 * any headers/trailers.
	 */
	if (uap->hdtr != NULL) {
		error = copyin(uap->hdtr, &hdtr, sizeof(hdtr));
		if (error)
			goto done;
		/*
		 * Send any headers.
		 */
		if (hdtr.headers != NULL) {
			hdr_uio.uio_td = td;
			hdr_uio.uio_rw = UIO_WRITE;
			error = uiofromiov(hdtr.headers, hdtr.hdr_cnt,
				&hdr_uio);
			if (error)
				goto done;
			/* Cache hdr_iov, m_uiotombuf may change it. */
			hdr_iov = hdr_uio.uio_iov;
			if (hdr_uio.uio_resid > 0) {
				m_header = m_uiotombuf(&hdr_uio, M_DONTWAIT, 0);
				if (m_header == NULL)
					goto done;
				headersize = m_header->m_pkthdr.len;
				if (compat)
					sbytes += headersize;
			}
		}
	}

	/*
	 * Protect against multiple writers to the socket.
	 */
	(void) sblock(&so->so_snd, M_WAITOK);

	/*
	 * Loop through the pages in the file, starting with the requested
	 * offset. Get a file page (do I/O if necessary), map the file page
	 * into an sf_buf, attach an mbuf header to the sf_buf, and queue
	 * it on the socket.
	 */
	for (off = uap->offset; ; off += xfsize, sbytes += xfsize) {
		vm_pindex_t pindex;
		vm_offset_t pgoff;

		pindex = OFF_TO_IDX(off);
		VM_OBJECT_LOCK(obj);
retry_lookup:
		/*
		 * Calculate the amount to transfer. Not to exceed a page,
		 * the EOF, or the passed in nbytes.
		 */
		xfsize = obj->un_pager.vnp.vnp_size - off;
		VM_OBJECT_UNLOCK(obj);
		if (xfsize > PAGE_SIZE)
			xfsize = PAGE_SIZE;
		pgoff = (vm_offset_t)(off & PAGE_MASK);
		if (PAGE_SIZE - pgoff < xfsize)
			xfsize = PAGE_SIZE - pgoff;
		if (uap->nbytes && xfsize > (uap->nbytes - sbytes))
			xfsize = uap->nbytes - sbytes;
		if (xfsize <= 0)
			break;
		/*
		 * Optimize the non-blocking case by looking at the socket space
		 * before going to the extra work of constituting the sf_buf.
		 */
		if ((so->so_state & SS_NBIO) && sbspace(&so->so_snd) <= 0) {
			if (so->so_state & SS_CANTSENDMORE)
				error = EPIPE;
			else
				error = EAGAIN;
			sbunlock(&so->so_snd);
			goto done;
		}
		VM_OBJECT_LOCK(obj);
		/*
		 * Attempt to look up the page.
		 *
		 *	Allocate if not found
		 *
		 *	Wait and loop if busy.
		 */
		pg = vm_page_lookup(obj, pindex);

		if (pg == NULL) {
			pg = vm_page_alloc(obj, pindex,
			    VM_ALLOC_NORMAL | VM_ALLOC_WIRED);
			if (pg == NULL) {
				VM_OBJECT_UNLOCK(obj);
				VM_WAIT;
				VM_OBJECT_LOCK(obj);
				goto retry_lookup;
			}
			vm_page_lock_queues();
			vm_page_wakeup(pg);
		} else {
			vm_page_lock_queues();
			if (vm_page_sleep_if_busy(pg, TRUE, "sfpbsy"))
				goto retry_lookup;
			/*
			 * Wire the page so it does not get ripped out from
			 * under us.
			 */
			vm_page_wire(pg);
		}

		/*
		 * If page is not valid for what we need, initiate I/O
		 */

		if (pg->valid && vm_page_is_valid(pg, pgoff, xfsize)) {
			VM_OBJECT_UNLOCK(obj);
		} else if (uap->flags & SF_NODISKIO) {
			error = EBUSY;
		} else {
			int bsize, resid;

			/*
			 * Ensure that our page is still around when the I/O
			 * completes.
			 */
			vm_page_io_start(pg);
			vm_page_unlock_queues();
			VM_OBJECT_UNLOCK(obj);

			/*
			 * Get the page from backing store.
			 */
			bsize = vp->v_mount->mnt_stat.f_iosize;
			vn_lock(vp, LK_SHARED | LK_NOPAUSE | LK_RETRY, td);
			/*
			 * XXXMAC: Because we don't have fp->f_cred here,
			 * we pass in NOCRED.  This is probably wrong, but
			 * is consistent with our original implementation.
			 */
			error = vn_rdwr(UIO_READ, vp, NULL, MAXBSIZE,
			    trunc_page(off), UIO_NOCOPY, IO_NODELOCKED |
			    IO_VMIO | ((MAXBSIZE / bsize) << IO_SEQSHIFT),
			    td->td_ucred, NOCRED, &resid, td);
			VOP_UNLOCK(vp, 0, td);
			if (error)
				VM_OBJECT_LOCK(obj);
			vm_page_lock_queues();
			vm_page_flag_clear(pg, PG_ZERO);
			vm_page_io_finish(pg);
			mbstat.sf_iocnt++;
		}
	
		if (error) {
			vm_page_unwire(pg, 0);
			/*
			 * See if anyone else might know about this page.
			 * If not and it is not valid, then free it.
			 */
			if (pg->wire_count == 0 && pg->valid == 0 &&
			    pg->busy == 0 && !(pg->flags & PG_BUSY) &&
			    pg->hold_count == 0) {
				vm_page_busy(pg);
				vm_page_free(pg);
			}
			vm_page_unlock_queues();
			VM_OBJECT_UNLOCK(obj);
			sbunlock(&so->so_snd);
			goto done;
		}
		vm_page_unlock_queues();

		/*
		 * Get a sendfile buf. We usually wait as long as necessary,
		 * but this wait can be interrupted.
		 */
		if ((sf = sf_buf_alloc(pg)) == NULL) {
			mbstat.sf_allocfail++;
			vm_page_lock_queues();
			vm_page_unwire(pg, 0);
			if (pg->wire_count == 0 && pg->object == NULL)
				vm_page_free(pg);
			vm_page_unlock_queues();
			sbunlock(&so->so_snd);
			error = EINTR;
			goto done;
		}

		/*
		 * Get an mbuf header and set it up as having external storage.
		 */
		if (m_header)
			MGET(m, M_TRYWAIT, MT_DATA);
		else
			MGETHDR(m, M_TRYWAIT, MT_DATA);
		if (m == NULL) {
			error = ENOBUFS;
			sf_buf_free((void *)sf_buf_kva(sf), sf);
			sbunlock(&so->so_snd);
			goto done;
		}
		/*
		 * Setup external storage for mbuf.
		 */
		MEXTADD(m, sf_buf_kva(sf), PAGE_SIZE, sf_buf_free, sf, M_RDONLY,
		    EXT_SFBUF);
		m->m_data = (char *)sf_buf_kva(sf) + pgoff;
		m->m_pkthdr.len = m->m_len = xfsize;

		if (m_header) {
			m_cat(m_header, m);
			m = m_header;
			m_header = NULL;
			m_fixhdr(m);
		}

		/*
		 * Add the buffer to the socket buffer chain.
		 */
		s = splnet();
retry_space:
		/*
		 * Make sure that the socket is still able to take more data.
		 * CANTSENDMORE being true usually means that the connection
		 * was closed. so_error is true when an error was sensed after
		 * a previous send.
		 * The state is checked after the page mapping and buffer
		 * allocation above since those operations may block and make
		 * any socket checks stale. From this point forward, nothing
		 * blocks before the pru_send (or more accurately, any blocking
		 * results in a loop back to here to re-check).
		 */
		if ((so->so_state & SS_CANTSENDMORE) || so->so_error) {
			if (so->so_state & SS_CANTSENDMORE) {
				error = EPIPE;
			} else {
				error = so->so_error;
				so->so_error = 0;
			}
			m_freem(m);
			sbunlock(&so->so_snd);
			splx(s);
			goto done;
		}
		/*
		 * Wait for socket space to become available. We do this just
		 * after checking the connection state above in order to avoid
		 * a race condition with sbwait().
		 */
		if (sbspace(&so->so_snd) < so->so_snd.sb_lowat) {
			if (so->so_state & SS_NBIO) {
				m_freem(m);
				sbunlock(&so->so_snd);
				splx(s);
				error = EAGAIN;
				goto done;
			}
			error = sbwait(&so->so_snd);
			/*
			 * An error from sbwait usually indicates that we've
			 * been interrupted by a signal. If we've sent anything
			 * then return bytes sent, otherwise return the error.
			 */
			if (error) {
				m_freem(m);
				sbunlock(&so->so_snd);
				splx(s);
				goto done;
			}
			goto retry_space;
		}
		error = (*so->so_proto->pr_usrreqs->pru_send)(so, 0, m, 0, 0, td);
		splx(s);
		if (error) {
			sbunlock(&so->so_snd);
			goto done;
		}
		headersent = 1;
	}
	sbunlock(&so->so_snd);

	/*
	 * Send trailers. Wimp out and use writev(2).
	 */
	if (uap->hdtr != NULL && hdtr.trailers != NULL) {
			nuap.fd = uap->s;
			nuap.iovp = hdtr.trailers;
			nuap.iovcnt = hdtr.trl_cnt;
			error = writev(td, &nuap);
			if (error)
				goto done;
			if (compat)
				sbytes += td->td_retval[0];
			else
				hdtr_size += td->td_retval[0];
	}

done:
	if (headersent) {
		if (!compat)
			hdtr_size += headersize;
	} else {
		if (compat)
			sbytes -= headersize;
	}
	/*
	 * If there was no error we have to clear td->td_retval[0]
	 * because it may have been set by writev.
	 */
	if (error == 0) {
		td->td_retval[0] = 0;
	}
	if (uap->sbytes != NULL) {
		if (!compat)
			sbytes += hdtr_size;
		copyout(&sbytes, uap->sbytes, sizeof(off_t));
	}
	if (vp)
		vrele(vp);
	if (so)
		fputsock(so);
	if (hdr_iov)
		FREE(hdr_iov, M_IOV);
	if (m_header)
		m_freem(m_header);

	mtx_unlock(&Giant);

	if (error == ERESTART)
		error = EINTR;

	return (error);
}
