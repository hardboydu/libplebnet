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

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <sys/ioctl.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>


int _socket(int domain, int type, int protocol);
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

int
socket(int domain, int type, int protocol)
{
	int rc;

	if (domain != PF_INET) {
		rc = _socket(domain, type, protocol);
		/* track value */
	} else {
		if ((rc = kern_socket(curthread, domain, type, protocol)))
			goto kern_fail;
		rc = td->td_retval[0];
	}

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
ioctl(int fd, unsigned long request, ...)
{
	
kern_fail:
	errno = rc;
	return (-1);
}

int
close(int fd)
{
	int rc;

	if (/* XXX fd is ours */) 
		if ((rc = kern_close(curthread, fd))) 
			goto kern_fail;			
	else
		rc = _close(fd);
	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

int
open(const char *path, int flags, ...)
{

kern_fail:
	errno = rc;
	return (-1);
}

int
openat(int fd, const char *path, int flags, ...)
{

kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
read(int d, void *buf, size_t nbytes)
{	
	struct uio auio;
	struct iovec aiov;
	int rc;
	
	if (nbytes > INT_MAX) {
		rc = EINVAL;
		goto kern_fail;
	}


	if (/* XXX fd is ours */) {
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
		rc = _read(d, buf, nbytes);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
	struct uio auio;
	int rc, len, i;

	if (/* XXX fd is ours */) {
		len = 0;
		for (i = 0; i < iovcnt)
			len += iov[i].iov_len;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = iovcnt;
		auio.uio_resid = len;
		auio.uio_segflg = UIO_SYSSPACE;

		if ((rc = kern_readv(curthread, fd, auio)))
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

	if (/* fd is ours */) {
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
writev(int fd, const struct iovec *iov, int iovcnt)
{
	struct uio auio;
	int i, rc, len;

	if (/* fd is ours */) {
		len = 0;
		for (i = 0; i < iovcnt; i++)
			len += iov[i].iov_len;
		auio.uio_iov = iov;
		auio.uio_iovcnt = iovcnt;
		auio.uio_resid = len;
		auio.uio_segflg = UIO_SYSSPACE;
		if ((rc = kern_writev(curthread, fd, auio)))
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

	if (/* descriptor is ours */) {
		msg.msg_name = to;
		msg.msg_namelen = tolen;
		msg.msg_iov = &aiov;
		msg.msg_iovlen = 1;
		msg.msg_control = 0;
		aiov.iov_base = buf;
		aiov.iov_len = len;
		if ((rc = sendit(curthread, s, &msg, flags)))
			goto kern_fail;

		rc = curthread->td_retval[0];
	} else 
		rc = _sendto(s, msg, len, flags, to, tolen);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}

ssize_t
sendmsg(int s, const struct msghdr *msg, int flags)
{
	int rc;

	if (/* descriptor is ours */) {
		if ((rc = sendit(curthread, s, msg, flags)))
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

	if (/* descriptor is ours */) {
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
		if ((rc = recvit(curthread, s, &msg, fromlen)))
			goto kern_fail;
		rc = curthread->td_retval[0];
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

	if (/* descriptor is ours */) {
		oldflags = msg->msg_flags;
		msg->msg_flags = flags;

		if ((rc = recvit(curthread, s, msg, NULL))) {
			msg->flags = oldflags;
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
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)

{
	
	/* :(  :(   :( */
	/*
	  need to check for the presence of kernel descriptors
	  if it is entirely user or entirely kernel there is no work to be done
	  but if we have both user and kernel it isn't entirely clear how 
	  to proceed without using some form of asynchronous notifications for 
	  kernel descriptors	  
	*/
	

}

int
fcntl(int fd, int cmd, ...)
{

kern_fail:
	errno = rc;
	return (-1);
}

int
dup(int oldd)
{
	int rc;

	if (/* fd is ours */) {
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

	if (/* fd is ours */) {
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
}

int
poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	/* :(   :(   :(  */
}

int
accept(int s, struct sockaddr * restrict addr,
    socklen_t * restrict addrlen)
{
	int rc;

	if (/* s is one of ours */) {


	} else {
		rc = _accept(s, addr, addrlen);
		if (rc > 0) 
			; /* track allocated socket */
	}

	return (rc);
}

int
listen(int s, int backlog)
{
	int rc;

	if (/* s is one of ours */) {
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
	int erro;

	if (/* s is one of ours */) {
		if ((rc = getsockaddr(&sa, addr, addrlen)) != 0)
			goto kern_fail;
		rc = kern_bind(curthread, s, sa);
		free(sa, M_SONAME);
		if (rc) 
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
	struct sockaddr *sa;
	int rc;

	if (/* s is one of ours */) {
		if ((rc = getsockaddr(&sa, name, namelen)) != 0)
			goto kern_fail;
		rc = kern_connect(curthread, s, sa);
		free(sa, M_SONAME);
		if (rc)
			goto kern_fail;

		rc = curthread->td_retval[0];
	} else {
		rc = _connect(s, name, namelen);
	}
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

	if (/* s is ours */) {
		if ((rc = kern_getpeername(curthread, s, name, namelen)))
			goto kern_fail;
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

	if (/* s is ours */) {
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

	if (/* s is ours */) {
		if ((rc = kern_shutdown(curthread, s, how)))
			goto kern_fail;
	} else
		rc = _shutdown(s, how);

	return (rc);
kern_fail:
	errno = rc;
	return (-1);
}
