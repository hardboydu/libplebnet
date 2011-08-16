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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <sys/syscall.h>

#include <sys/proc.h>


#include <sys/ioctl.h>
#include <net/if.h>


#include <netinet/in.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/uio.h>


#define _WITH_DPRINTF
#include <stdio.h>

#include <ifmsg.h>
#include <pn_kern_subr.h>
#include <pthread.h>


static int target_fd;
struct thread;
int _socket(int domain, int type, int protocol);
int _bind(int s, const struct sockaddr *addr, socklen_t addrlen);
int _listen(int s, int backlog);

static int dispatch_table_size = SYS_MAXSYSCALL;

typedef int (*dispatch_func)(struct thread *, int, int);

static int dispatch_socket(struct thread *td, int fd, int size);
static int dispatch_ioctl(struct thread *td, int fd, int size);


dispatch_func dispatch_table[SYS_MAXSYSCALL];


static void 
target_bind(void)
{
	struct sockaddr_un addr;
	char buffer[16];

	sprintf(buffer, "/tmp/%d", getpid());

	target_fd = _socket(PF_LOCAL, SOCK_STREAM, 0);

	addr.sun_family = PF_LOCAL;
	strcpy(addr.sun_path, buffer);
	if(_bind(target_fd, (struct sockaddr *)&addr,
		   sizeof(addr)))
		exit(1);

	dispatch_table[SYS_socket] = dispatch_socket;
	dispatch_table[SYS_ioctl] = dispatch_ioctl;
	_listen(target_fd, 10);
}

int
handle_call_msg(int fd, int *size)
{
	struct call_msg cm;
	struct return_msg rm;
	int err;

	err = read(fd, &cm, sizeof(cm));
	if (cm.cm_id > dispatch_table_size || 
	    dispatch_table[cm.cm_id] == NULL) {
		rm.rm_size = 0;
		rm.rm_errno = ENOSYS;
		write(fd, &rm, sizeof(rm));
		return (-1);
	}
	*size = cm.cm_size;

	return (cm.cm_id);
}

int
dispatch(struct thread *td, int fd)
{
	int rc, size;

	rc = handle_call_msg(fd, &size);

	if (rc < 0)
		return (rc);

	rc = dispatch_table[rc](td, fd, size);
	/* check rc for closed socket */

	return (rc);
}

void *
syscall_server(void *arg)
{
	int fd;
	struct sockaddr_un addr;
	int len;
	struct thread tds, *td;


	target_bind();

	td = &tds;
	len = sizeof(addr);
	while (1) {
		fd = accept(target_fd, (struct sockaddr *)&addr, &len);
		while (dispatch(td, fd) >= 0)
			;
		
	}
}

void
start_server_syscalls(void)
{
	pthread_t server;

	pthread_create(&server, NULL, syscall_server, NULL);
}

static int
dispatch_socket(struct thread *td, int fd, int size)
{
	int i, err, rc, osize, iovcnt;
	struct socket_call_msg scm;
	struct iovec iov[3];

	err = osize = 0;
	iovcnt = 2;

	if (size != sizeof(scm))
		err = EINVAL;
	else if (read(fd, &scm, sizeof(scm)) < 0) {
		err = errno;
	} else if ((rc = socket(scm.scm_domain, scm.scm_type, 
				 scm.scm_protocol)) > 0) {
		osize = sizeof(int);
		iovcnt = 3;
		iov[2].iov_base = &rc;
	}

	iov[0].iov_base = &osize;
	iov[1].iov_base = &err;

	for (i = 0; i < 3; i++)
		iov[i].iov_len = sizeof(int);

	return writev(fd, iov, iovcnt);
}


static int
dispatch_ioctl(struct thread *td, int fd, int size)
{
	int err, rc, iovcnt;
	void *argp, *datap = NULL, *msgp = NULL;
	struct return_msg rm;
	struct ioctl_call_msg *ioctl_cm;
	struct ifreq_call_msg *ifreq_cm;
	struct ifmediareq *ifmr;
	struct ifreq *ifr;
	struct ifconf ifc;
	struct if_clonereq ifcr;
	unsigned long request;
	struct iovec iov[4];

	err = 0;

	if ((msgp = malloc(size)) == NULL)
		err = ENOMEM;
	else if ((rc = read(fd, msgp, size)) < 0)
		err = errno;
	else if (rc < size) 
		err = EINVAL;

	if (err) {
		if (argp != NULL)
			free(msgp);
		rm.rm_size = 0;
		rm.rm_errno = err;
		return write(fd, &rm, sizeof(struct return_msg));
		
	}

	ioctl_cm = msgp;
	request = ioctl_cm->icm_request;

	switch (request) {	
		/* ifreq */
	case SIOCSIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCGIFDSTADDR:
	case SIOCSIFFLAGS:
	case SIOCGIFFLAGS:
	case SIOCGIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case SIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCGIFMETRIC:
	case SIOCSIFMETRIC:
	case SIOCDIFADDR:
	case SIOCGIFCAP:
	case SIOCGIFINDEX:
	case SIOCGIFMAC:
	case SIOCSIFMAC:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCGIFMTU:
	case SIOCSIFMTU:
	case SIOCGIFPHYS:
	case SIOCSIFPHYS:
	case SIOCSIFMEDIA:
	case SIOCSIFGENERIC:
	case SIOCGIFGENERIC:
	case SIOCSIFLLADDR:
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCDIFPHYADDR:
	case SIOCIFCREATE:
		argp = &ioctl_cm->icm_data[0];
		break;
	case SIOCGIFDESCR:
		ifreq_cm = msgp;
		argp = ifr = &ifreq_cm->icm_ifr;
		datap = ifr->ifr_buffer.buffer = 
			malloc(ifr->ifr_buffer.length);
		break;
	case SIOCSIFDESCR:
		ifreq_cm = msgp;
		argp = ifr = &ifreq_cm->icm_ifr;
		ifr->ifr_buffer.buffer = &ifreq_cm->icm_ifr_data[0];
		break;
	case SIOCSIFNAME:
		ifreq_cm = msgp;
		argp = ifr = &ifreq_cm->icm_ifr;
		ifr->ifr_data = &ifreq_cm->icm_ifr_data[0];
		break;
	case SIOCGIFCONF:
		ifc.ifc_len = *(int *)&ioctl_cm->icm_data[0];
		datap = ifc.ifc_buf = malloc(ifc.ifc_len);
		argp = &ifc;
		break;
	case SIOCIFGCLONERS:
		ifcr.ifcr_count = *(int *)&ioctl_cm->icm_data[0];
		datap = ifcr.ifcr_buffer = malloc(ifcr.ifcr_count*IFNAMSIZ);
		argp = &ifcr;
		break;
	case SIOCGIFMEDIA:
		argp = ifmr = (struct ifmediareq *)&ioctl_cm->icm_data[0];
		if (ifmr->ifm_ulist != NULL)
			datap = ifmr->ifm_ulist = 
				malloc(ifmr->ifm_count*sizeof(int));
		break;
	default:
		/* XXX unsupported ioctl */
		break;
	}
	err = kern_ioctl(td, ioctl_cm->icm_fd, request, argp);
	size = 0;
	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(int);
	iov[1].iov_base = &err;
	iov[1].iov_len = sizeof(int);
	if (err != 0) {
		free(msgp);
		if (datap != NULL)
			free(datap);
		return writev(fd, iov, 2);
	}

	switch (request) {
	case SIOCGIFCONF:
		iov[2].iov_base = (void *)&ifc.ifc_len;
		iov[2].iov_len = sizeof(int);
		iov[3].iov_base = ifc.ifc_buf;
		iov[3].iov_len = ifc.ifc_len;
		iovcnt = 4;
		break;
	case SIOCGIFDESCR:
		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		iov[3].iov_base = datap;
		iov[3].iov_len = ifr->ifr_buffer.length;
		iovcnt = 4;
		break;
	case SIOCIFGCLONERS:
		iov[2].iov_base = &ifcr.ifcr_total;
		iov[2].iov_len = sizeof(ifcr.ifcr_total);
		iov[3].iov_base = datap;
		iov[3].iov_len = ifcr.ifcr_count*IFNAMSIZ;
		iovcnt = 2;
	case SIOCGIFMEDIA:
		iov[2].iov_base = ifmr;
		iov[2].iov_len = sizeof(struct ifmediareq);
		iovcnt = 3;
		if (ifmr->ifm_ulist != NULL) {
			datap = iov[3].iov_base = ifmr->ifm_ulist;
			iov[3].iov_len = ifmr->ifm_count*sizeof(int);
			iovcnt = 4;
		}
	default:
		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		iovcnt = 3;
	}

	rc = writev(fd, iov, iovcnt);

	free(msgp);
	if (datap != NULL)
		free(datap);

	return (rc);
}
	

