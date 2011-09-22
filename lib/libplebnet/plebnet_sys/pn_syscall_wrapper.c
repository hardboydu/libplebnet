/*-
 * Copyright (c) 2011 Kip Macy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
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

#undef _KERNEL
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>

#define _KERNEL
#include <sys/uio.h>
#undef _KERNEL


#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/module.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>

#include <sys/param.h>
#define _KERNEL
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/event.h>
#undef _KERNEL
#include <sys/kernel.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>


#include <pn_private.h>
#include <pn_kern_subr.h>

#include <string.h>

#include <sys/pcpu.h> /* curthread */

static __inline int imin(int a, int b) { return (a < b ? a : b); }

int _socket(int domain, int type, int protocol);
int _setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);
int _getsockopt(int s, int level, int optname, void * restrict optval,
    socklen_t * restrict optlen);
int _ioctl(int fd, unsigned long request, ...);
int _close(int fd);
int _open(const char *path, int flags, ...);
int _openat(int fd, const char *path, int flags, ...);
ssize_t _read(int d, void *buf, size_t nbytes);
ssize_t _readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t _write(int fd, const void *buf, size_t nbytes);
ssize_t _writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t _sendto(int s, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen);
ssize_t _sendmsg(int s, const struct msghdr *msg, int flags);
ssize_t _recvfrom(int s, void * restrict buf, size_t len, int flags,
    struct sockaddr * restrict from, socklen_t * restrict fromlen);
ssize_t _recvmsg(int s, struct msghdr *msg, int flags);
int _select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout);
int _fcntl(int fd, int cmd, ...);
int _dup(int oldd);
int _dup2(int oldd, int newd);
int _pipe(int fildes[2]);
int _socketpair(int domain, int type, int protocol, int *sv);
int _poll(struct pollfd fds[], nfds_t nfds, int timeout);
int _accept(int s, struct sockaddr * restrict addr,
    socklen_t * restrict addrlen);
int _listen(int s, int backlog);
int _bind(int s, const struct sockaddr *addr, socklen_t addrlen);
int _connect(int s, const struct sockaddr *name, socklen_t namelen);
int _getpeername(int s, struct sockaddr * restrict name,
    socklen_t * restrict namelen);
int _getsockname(int s, struct sockaddr * restrict name,
    socklen_t * restrict namelen);
int _shutdown(int s, int how);
int _pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg);
int __sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

static int
pleb_userfd_isset(int nfds, fd_set *set)
{
	int i, words, found;

	words = imin(_howmany(FD_SETSIZE, _NFDBITS),
	    _howmany(nfds, _NFDBITS));
	found = 0;
	while (words--) {
		if (set->__fds_bits[words] == 0)
			continue;
		for (i = 0; i < _NFDBITS; i++)
			if ((set->__fds_bits[words] &
			    (1<<i)) &&
			    user_fdisused(words*_NFDBITS + i)) {
				found = 1;
				goto done;
			}
	}
done:
	return (found);
}

static int
pleb_kernfd_isset(int nfds, fd_set *set)
{
	return (0); /* XXX FIXME */
}

int
socket(int domain, int type, int protocol)
{
	int rc;
	/* XXX want this check to be based on support compiled in */
	if (domain != PF_INET && domain != PF_INET6 && domain != PF_ROUTE) {
		rc = _socket(domain, type, protocol);
		/* track value */
	} else {
		if ((rc = kern_socket(curthread, domain, type, protocol)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	}

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
getsockopt(int s, int level, int optname, void * restrict optval,
    socklen_t * restrict optlen)
{
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_getsockopt(curthread, s, level, optname, 
			    optval, UIO_SYSSPACE, optlen)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else 
		rc = _getsockopt(s, level, optname, optval, optlen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen)
{
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_setsockopt(curthread, s, level, optname, 
			    __DECONST(void *, optval), UIO_SYSSPACE, optlen)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else 
		rc = _setsockopt(s, level, optname, optval, optlen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

/*
 * XXX may need to eventually support ioctls that take 4 arguments
 */
int
ioctl(int fd, unsigned long request, ...)
{
	int rc;
	va_list ap;
	caddr_t argp;

	va_start(ap, request);

	argp = va_arg(ap, caddr_t);
	va_end(ap);	
	if (user_fdisused(fd)) {
		if ((rc = kern_ioctl(curthread, fd, request, argp)))
			goto kern_fail;
	} else
		rc = _ioctl(fd, request, argp);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
close(int fd)
{
	int rc;

	if (user_fdisused(fd)) {
		if ((rc = kern_close(curthread, fd))) 
			goto kern_fail;
	} else
		rc = _close(fd);
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
open(const char *path, int flags, ...)
{
	int rc;
	va_list ap;
	int mode;

	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
		rc = _open(path, flags, mode);
	} else
		rc = _open(path, flags);

	if (rc >= 0)
		; /* track kernel descriptor */

	return (rc);
}

int
openat(int fd, const char *path, int flags, ...)
{
	int rc;
	va_list ap;
	int mode;

	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
		rc = _openat(fd, path, flags, mode);
	} else
		rc = _openat(fd, path, flags);

	if (rc >= 0)
		; /* track kernel descriptor */

	return (rc);
}

ssize_t
read(int fd, void *buf, size_t nbytes)
{	
	struct uio auio;
	struct iovec aiov;
	int rc;
	
	if (nbytes > INT_MAX) {
		rc = EINVAL;
		goto kern_fail;
	}

	if (user_fdisused(fd)) {
		aiov.iov_base = buf;
		aiov.iov_len = nbytes;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_resid = nbytes;
		auio.uio_segflg = UIO_SYSSPACE;
		if ((rc = kern_readv(curthread, fd, &auio)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else
		rc = _read(fd, buf, nbytes);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
readv(int fd, struct iovec *iov, int iovcnt)
{
	struct uio auio;
	int rc, len, i;

	if (user_fdisused(fd)) {
		len = 0;
		for (i = 0; i < iovcnt; i++)
			len += iov[i].iov_len;
		auio.uio_iov = iov;
		auio.uio_iovcnt = iovcnt;
		auio.uio_resid = len;
		auio.uio_segflg = UIO_SYSSPACE;

		if ((rc = kern_readv(curthread, fd, &auio)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else
		rc = _readv(fd, iov, iovcnt);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
write(int fd, const void *buf, size_t nbytes)
{
	struct uio auio;
	struct iovec aiov;
	int rc;

	if (nbytes > INT_MAX) {
		rc = EINVAL;
		goto kern_fail;
	}

	if (user_fdisused(fd)) {
		aiov.iov_base = (void *)(uintptr_t)buf;
		aiov.iov_len = nbytes;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_resid = nbytes;
		auio.uio_segflg = UIO_SYSSPACE;
		if ((rc = kern_writev(curthread, fd, &auio)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else
		rc = _write(fd, buf, nbytes);
	
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
writev(int fd, struct iovec *iov, int iovcnt)
{
	struct uio auio;
	int i, rc, len;

	if (user_fdisused(fd)) {
		len = 0;
		for (i = 0; i < iovcnt; i++)
			len += iov[i].iov_len;
		auio.uio_iov = iov;
		auio.uio_iovcnt = iovcnt;
		auio.uio_resid = len;
		auio.uio_segflg = UIO_SYSSPACE;
		if ((rc = kern_writev(curthread, fd, &auio)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else {
		rc = _writev(fd, iov, iovcnt);
	}
	
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
send(int s, const void *buf, size_t len, int flags)
{
	
	return (sendto(s, buf, len, flags, NULL, 0));
}

ssize_t
sendto(int s, const void *buf, size_t len, int flags,
         const struct sockaddr *to, socklen_t tolen)
{
	struct msghdr msg;
	struct iovec aiov;
	int rc;

	if (user_fdisused(s)) {
		msg.msg_name = __DECONST(struct sockaddr *, to);
		msg.msg_namelen = tolen;
		msg.msg_iov = &aiov;
		msg.msg_iovlen = 1;
		msg.msg_control = 0;
		aiov.iov_base = __DECONST(void *, to);
		aiov.iov_len = len;
		if ((rc = sendit(curthread, s, &msg, flags)))
			goto kern_fail;

		rc = curthread->td_retval[0];
	} else 
		rc = _sendto(s, buf, len, flags, to, tolen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
sendmsg(int s, const struct msghdr *msg, int flags)
{
	int rc;

	if (user_fdisused(s)) {
		if ((rc = sendit(curthread, s, __DECONST(struct msghdr *, msg), flags)))
			goto kern_fail;
	} else 
		rc = _sendmsg(s, msg, flags);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}


ssize_t
recv(int s, void *buf, size_t len, int flags)
{

	return (recvfrom(s, buf, len, flags, NULL, 0));
}

ssize_t
recvfrom(int s, void * restrict buf, size_t len, int flags,
    struct sockaddr * restrict from, socklen_t * restrict fromlen)
{
	struct msghdr msg;
	struct iovec aiov;
	int rc;

	if (user_fdisused(s)) {
		if (fromlen != NULL)
			msg.msg_namelen = *fromlen;
		else
			msg.msg_namelen = 0;

		msg.msg_name = from;
		msg.msg_iov = &aiov;
		msg.msg_iovlen = 1;
		aiov.iov_base = buf;
		aiov.iov_len = len;
		msg.msg_control = 0;
		msg.msg_flags = flags;
		if ((rc = kern_recvit(curthread, s, &msg, UIO_SYSSPACE, NULL)))
			goto kern_fail;
		rc = curthread->td_retval[0];
		if (fromlen != NULL)
			*fromlen = msg.msg_namelen;
	} else 
		rc = _recvfrom(s, buf, len, flags, from, fromlen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
recvmsg(int s, struct msghdr *msg, int flags)
{
	int rc, oldflags;

	if (user_fdisused(s)) {
		oldflags = msg->msg_flags;
		msg->msg_flags = flags;

		if ((rc = kern_recvit(curthread, s, msg, UIO_SYSSPACE, NULL))) {
			msg->msg_flags = oldflags;
			goto kern_fail;
		}
		rc = curthread->td_retval[0];
	} else
		rc = _recvmsg(s, msg, flags);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
fcntl(int fd, int cmd, ...)
{
	int rc;
	va_list ap;
	uintptr_t argp;

	va_start(ap, cmd);

	argp = va_arg(ap, uintptr_t);
	va_end(ap);	

	if (user_fdisused(fd)) {
		if ((rc = kern_fcntl(curthread, fd, cmd, argp)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else {
		rc = _fcntl(fd, cmd, argp);
		if (rc < 0)
			return (rc);
		switch (cmd){
		case F_DUPFD:
		case F_DUP2FD:
			/* track rc as it is another fd */
			break;
		}
	}
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
dup(int oldd)
{
	int rc;

	if (user_fdisused(oldd)) {
		if ((rc = do_dup(curthread, 0, (int)oldd, 0, curthread->td_retval)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else
		rc = _dup(oldd);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
dup2(int oldd, int newd)
{
	int rc;

	if (user_fdisused(oldd)) {
		if ((rc = do_dup(curthread, DUP_FIXED, oldd, newd, curthread->td_retval)))
			goto kern_fail;
	        rc = curthread->td_retval[0];
	} else
		rc = _dup2(oldd, newd);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
pipe(int fildes[2])
{
	int rc;

	rc = _pipe(fildes);
	if (rc == 0) 
		; /* track fd */

	return (rc);
}

int
socketpair(int domain, int type, int protocol, int *sv)
{
	int rc;

	/* don't see any value in talking to ourselves over the stack */
	rc = _socketpair(domain, type, protocol, sv);

	if (rc == 0)
		; /* track allocated descriptors */

	return (rc);
}

int
accept(int s, struct sockaddr * restrict addr,
    socklen_t * restrict addrlen)
{
	int rc;
	struct file *fp;
	struct sockaddr *name;

	if (user_fdisused(s)) {
		if (name == NULL && (rc = kern_accept(curthread, s, NULL, NULL, NULL)))
			goto kern_fail;
		if (name != NULL && (rc = kern_accept(curthread, s, &name, addrlen, &fp)))
			goto kern_fail;
		rc = curthread->td_retval[0];
		bcopy(name, addr, *addrlen);
		fdrop(fp, curthread);
		free(name, M_SONAME);
	} else {
		rc = _accept(s, addr, addrlen);
		if (rc > 0) 
			; /* track allocated socket */
	}

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
listen(int s, int backlog)
{
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_listen(curthread, s, backlog)))
			goto kern_fail;
	} else
		rc = _listen(s, backlog);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr *sa;
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_bind(curthread, s, sa)))
			goto kern_fail;
	} else		
		rc = _bind(s, addr, addrlen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_connect(curthread, s, __DECONST(struct sockaddr *, name))))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else
		rc = _connect(s, name, namelen);
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
getpeername(int s, struct sockaddr * restrict name,
    socklen_t * restrict namelen)
{
	int rc;
	struct sockaddr *nametmp;

	if (user_fdisused(s)) {
		if ((rc = kern_getpeername(curthread, s, &nametmp, namelen)))
			goto kern_fail;
		bcopy(nametmp, name, *namelen);
		free(nametmp, M_SONAME);
	} else
		rc = _getpeername(s, name, namelen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
getsockname(int s, struct sockaddr * restrict name,
    socklen_t * restrict namelen)
{
	struct sockaddr *sa;
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_getsockname(curthread, s, &sa, namelen)))
			goto kern_fail;
		bcopy(sa, name, *namelen);
		free(sa, M_SONAME);
	} else
		rc = _getsockname(s, name, namelen);

	return (rc);

kern_fail:
	errno = rc;
	return (-1);
}

int	
shutdown(int s, int how)
{
	int rc;

	if (user_fdisused(s)) {
		if ((rc = kern_shutdown(curthread, s, how)))
			goto kern_fail;
	} else
		rc = _shutdown(s, how);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

extern struct	proc	proc0;

struct pthread_start_args 
{
	struct thread *psa_td;
	void *(*psa_start_routine)(void *);
	void *psa_arg;
};

static void *
pthread_start_routine(void *arg)
{
	struct pthread_start_args *psa = arg;
	void *retval;

	pcurthread = psa->psa_td;
	pcurthread->td_proc = &proc0;
	retval = psa->psa_start_routine(psa->psa_arg);
	free(psa, M_DEVBUF);

	return (retval);
}

int
pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg)
{
	
	int error;
	struct pthread_start_args *psa;
	struct thread *td;

	td = malloc(sizeof(struct thread), M_DEVBUF, M_ZERO);
	psa = malloc(sizeof(struct pthread_start_args), M_DEVBUF, M_ZERO);
	psa->psa_start_routine = start_routine;
	psa->psa_arg = arg;
	psa->psa_td = td;
	
	error = _pthread_create(thread, attr, pthread_start_routine, psa);

	return (error);	
}

int
sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
         const void *newp, size_t newlen)
{
	int rc;
	size_t retval;

	if (name[0] == CTL_USER)
		return (user_sysctl(name, namelen, oldp, oldlenp, newp, newlen));

	if (name[0] != CTL_NET)
		return (__sysctl(name, namelen, oldp, oldlenp, newp, newlen));

	rc = userland_sysctl(curthread, __DECONST(int *, name), namelen, oldp, oldlenp, 
	    1, __DECONST(void *, newp), newlen, &retval, 0);
	if (rc)
		goto kern_fail;
	if (oldlenp)
		*oldlenp = retval;
	return (0);
kern_fail:
	errno = rc;
	return (-1);
}

int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)

{
	int rc, kernfd, userfd;

	rc = kernfd = userfd = 0;
	if (readfds != NULL)
		userfd = pleb_userfd_isset(nfds, readfds);
	if (writefds != NULL)
		userfd |= pleb_userfd_isset(nfds, writefds);
	if (exceptfds != NULL)
		userfd |= pleb_userfd_isset(nfds, exceptfds);

	if (readfds != NULL)
		kernfd = pleb_kernfd_isset(nfds, readfds);
	if (writefds != NULL)
		kernfd |= pleb_kernfd_isset(nfds, writefds);
	if (exceptfds != NULL)
		kernfd |= pleb_kernfd_isset(nfds, exceptfds);

	if (!userfd && kernfd)
		return _select(nfds, readfds, writefds, exceptfds, timeout);
	else if (userfd && !kernfd) {
		rc = kern_select(curthread, nfds, readfds, writefds, exceptfds, timeout, 1024/* XXX abi_nfdbits */);
		if (rc)
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else if (userfd && kernfd) {

		/* :(  :(   :( */
		/* XXX need to create two separate fd sets 
		 * one that is entirely user and one that
		 * is entirely kernel
		 */

	}

	return (rc);
kern_fail:
	errno = rc;
	return (-1);

}

int
poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	int i, rc, kernfd, userfd;
	
	rc = kernfd = userfd = 0;
	for (i = 0; i < nfds; i++) {
		kernfd |= kernel_fdisused(fds[i].fd);
		userfd |= user_fdisused(fds[i].fd);
	}

	if (kernfd && !userfd)
		rc = _poll(fds, nfds, timeout);
	else if (!kernfd && userfd) {
		if ((rc = kern_poll(curthread, fds, nfds, timeout)))
			goto kern_fail;
		rc = curthread->td_retval[0];
	} else if (kernfd && userfd) {

	}
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
kqueue(void)
{

	return (kern_kqueue(curthread));
}

#ifndef _SYS_SYSPROTO_H_
struct sys_kevent_args {
	int	fd;
	const struct kevent *changelist;
	int	nchanges;
	struct	kevent *eventlist;
	int	nevents;
	const struct timespec *timeout;
};
#endif

struct kevent_copyops {
	void	*arg;
	int	(*k_copyout)(void *arg, struct kevent *kevp, int count);
	int	(*k_copyin)(void *arg, struct kevent *kevp, int count);
};

static int
kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct sys_kevent_args *uap;

	uap = (struct sys_kevent_args *)arg;
	bcopy(kevp, uap->eventlist, count * sizeof *kevp);
	return (0);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct sys_kevent_args *uap;

	uap = (struct sys_kevent_args *)arg;
	bcopy(uap->changelist, kevp, count * sizeof *kevp);
	return (0);
}

int
kevent(int kq, const struct kevent *changelist, int nchanges, 
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;
	struct sys_kevent_args ska = { kq,
				       changelist,
				       nchanges,
				       eventlist,
				       nevents,
				       timeout};
	struct kevent_copyops k_ops = { &ska,
					kevent_copyout,
					kevent_copyin};
	/*
	 * since kq is a user-level descriptor, if we get passed any
	 * kernel descriptors we'll need to allocate a kernel descriptor
	 * and associate it with the user descriptor
	 */

	if ((rc = kern_kevent(curthread, kq, nchanges, nevents, &k_ops, 
		    timeout)))
		goto kern_fail;
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}
