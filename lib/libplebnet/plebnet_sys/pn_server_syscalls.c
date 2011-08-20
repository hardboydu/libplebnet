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
#include <sys/sysctl.h>


#define _WITH_DPRINTF
#include <stdio.h>

#include <ifmsg.h>
#include <pn_kern_subr.h>
#include <pthread.h>
#include <sys/pcpu.h> /* curthread */
#include <pn_private.h>

static int target_fd;
struct thread;
struct	filedesc *fdinit(struct filedesc *fdp);
struct ucred	*crget(void);
struct ucred	*crhold(struct ucred *cr);
extern struct proc proc0;

static int dispatch_table_size = SYS_MAXSYSCALL;

typedef int (*dispatch_func)(struct thread *, int, int);

static int dispatch_socket(struct thread *td, int fd, int size);
static int dispatch_ioctl(struct thread *td, int fd, int size);
static int dispatch_sysctl(struct thread *td, int fd, int size);
static struct proc server_proc;

dispatch_func dispatch_table[SYS_MAXSYSCALL];

static void
cleanup(void)
{
	char buffer[16];

	sprintf(buffer, "/tmp/%d", getpid());
	unlink(buffer);
}

static void 
target_bind(void)
{
	struct sockaddr_un addr;
	char buffer[16];

	sprintf(buffer, "/tmp/%d", getpid());

	target_fd = socket(PF_LOCAL, SOCK_STREAM, 0);

	addr.sun_family = PF_LOCAL;
	strcpy(addr.sun_path, buffer);
	printf("bound to %s\n", buffer);
	if(bind(target_fd, (struct sockaddr *)&addr,
		   sizeof(addr)))
		exit(1);

	atexit(cleanup);
	dispatch_table[SYS_socket] = dispatch_socket;
	dispatch_table[SYS_ioctl] = dispatch_ioctl;
	dispatch_table[SYS___sysctl] = dispatch_sysctl;
	listen(target_fd, 10);
	printf("listening\n");
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
	if (cm.cm_id == SYS_close) {
		close(fd);
		return (-1);
	}
	*size = cm.cm_size;

	return (cm.cm_id);
}

static int
recv_client_msg(int fd, void **msgp, int size)
{
	int rc, err = 0;
	struct return_msg rm;

	printf("receiving %d bytes\n", size);
	if (size == 0) {
		close(fd);
		return (EPIPE);
	}
	if (*msgp == NULL && (*msgp = malloc(size)) == NULL)
		err = ENOMEM;
	else if ((rc = read(fd, *msgp, size)) < 0)
		err = errno;
	else if (rc < size) 
		err = EINVAL;

	if (err && msgp != NULL && *msgp != NULL)
		free(*msgp);
	if (err) {
		rm.rm_size = 0;
		rm.rm_errno = err;
		/*
		 * There is no point to overwriting an existing
		 * error if the write fails.
		 */
		write(fd, &rm, sizeof(struct return_msg));
	}
	return (err);
}

static int
send_return_msg(int fd, int error, int size) 
{
	struct return_msg rm;

	rm.rm_size = size;
	rm.rm_errno = error;
	if (write(fd, &rm, sizeof(rm)) < 0)
		return (errno);
	return (0);
}

int
dispatch(struct thread *td, int fd)
{
	int rc, size, funcid;

	funcid = handle_call_msg(fd, &size);

	if (funcid < 0)
		return (errno);

	rc = dispatch_table[funcid](td, fd, size);
	/* check rc for closed socket */
	if (rc != 0)
		printf("%p returned %d\n", dispatch_table[funcid], rc);
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
	td->td_proc = &server_proc;
	/* Create the file descriptor table. */
	server_proc.p_ucred = proc0.p_ucred;
	server_proc.p_limit = proc0.p_limit;
	server_proc.p_sysent = proc0.p_sysent;
	td->td_ucred = crhold(server_proc.p_ucred);
	td->td_proc->p_fd = fdinit(NULL);
	td->td_proc->p_fdtol = NULL;
	len = sizeof(addr);
	while (1) {
		fd = accept(target_fd, (struct sockaddr *)&addr, &len);
		while (dispatch(td, fd) == 0)
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
	struct thread *orig;

	err = osize = 0;
	iovcnt = 2;

	if (size != sizeof(scm))
		err = EINVAL;
	else if (read(fd, &scm, sizeof(scm)) < 0) {
		err = errno;
	} else {
		orig = pcurthread;
		pcurthread = td;
		if (scm.scm_domain == PF_LOCAL)
			scm.scm_domain = PF_INET;
		if ((rc = socket(scm.scm_domain, scm.scm_type, 
			    scm.scm_protocol)) >= 0) {
			osize = sizeof(int);
			iovcnt = 3;
			iov[2].iov_base = &rc;
		}
		pcurthread = orig;
	}
	iov[0].iov_base = &osize;
	iov[1].iov_base = &err;

	for (i = 0; i < 3; i++)
		iov[i].iov_len = sizeof(int);

	rc = writev(fd, iov, iovcnt);
	if (rc < 0)
		return (errno);
	return (0);
}


static int
dispatch_sysctl(struct thread *td, int fd, int msgsize)
{
	int i, err, rc, iovcnt, size;
	size_t oldlen;
	struct sysctl_call_msg *scm;
	struct iovec iov[3];
	struct thread *orig;
	caddr_t datap;
	void *newp, *oldp;
	int mib[6];

	size = oldlen = err = 0;
	iovcnt = 1;
	oldp = newp = NULL;
	scm = NULL;
	if ((err = recv_client_msg(fd, (void **)&scm, msgsize))) {
		return (err);
	} else {
		datap = (caddr_t)&scm->scm_data;
		oldlen = scm->scm_oldlen;
		if (scm->scm_miblen <= 6) {
			bcopy(datap, mib, scm->scm_miblen*sizeof(int));
			datap += scm->scm_miblen*sizeof(int);
		}
		for (i = 0; i < scm->scm_miblen; i++)
			printf("mib[%d]=%d ", i, mib[i]);
		printf("oldlen=%zd newlen=%zd\n", scm->scm_oldlen, 
		    scm->scm_newlen);
		printf("\n");
		if (scm->scm_newlen != 0)
			newp = datap;
		if (oldlen != 0) {
			if ((oldp = malloc(oldlen)) == NULL)
				return (send_return_msg(fd, ENOMEM, 0));
		}
		orig = pcurthread;
		pcurthread = td;
		if ((rc = sysctl(mib, scm->scm_miblen, oldp, &oldlen, newp, 
			    scm->scm_newlen)) < 0) {
		}
		pcurthread = orig;
	}
	printf("rc=%d oldlen=%zd\n", rc, oldlen);
	free(scm);
	if (rc && oldp != NULL)
		free(oldp);
	if (rc)
		rc = errno;
	else if (oldp == NULL)
		size = sizeof(oldlen);
	else 
		size = oldlen + sizeof(oldlen);
	rc = send_return_msg(fd, rc, size);
	if (size == 0 || rc)
		return (rc);

	iov[0].iov_base = &oldlen;
	iov[0].iov_len = sizeof(oldlen);
	if (size > sizeof(oldlen)) {
		iov[1].iov_base = oldp;
		iov[1].iov_len = size;
		iovcnt = 2;
	}

	rc = writev(fd, iov, iovcnt);
	if (oldp)
		free(oldp);
	if (rc < 0)
		return (errno);
	return (0);
}

static int
dispatch_ioctl(struct thread *td, int fd, int msgsize)
{
	int err, rc, iovcnt, size;
	void *argp, *datap = NULL, *msgp = NULL;
	struct ioctl_call_msg *ioctl_cm;
	struct ifreq_call_msg *ifreq_cm;
	struct ifmediareq *ifmr;
	struct ifreq *ifr;
	struct ifconf ifc;
	struct if_clonereq ifcr;
	unsigned long request;
	struct iovec iov[4];

	if ((err = recv_client_msg(fd, &msgp, msgsize)))
		return (err);

	ioctl_cm = msgp;
	request = ioctl_cm->icm_request;
	datap = NULL;

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
		size = sizeof(struct ifreq);
		break;
	case SIOCGIFDESCR:
		ifreq_cm = msgp;
		argp = ifr = &ifreq_cm->icm_ifr;
		datap = ifr->ifr_buffer.buffer = 
			malloc(ifr->ifr_buffer.length);
		size = sizeof(struct ifreq) + ifr->ifr_buffer.length;
		break;
	case SIOCSIFDESCR:
		ifreq_cm = msgp;
		argp = ifr = &ifreq_cm->icm_ifr;
		ifr->ifr_buffer.buffer = &ifreq_cm->icm_ifr_data[0];
		size = sizeof(struct ifreq);
		break;
	case SIOCSIFNAME:
		ifreq_cm = msgp;
		argp = ifr = &ifreq_cm->icm_ifr;
		ifr->ifr_data = &ifreq_cm->icm_ifr_data[0];
		size = sizeof(struct ifreq);
		break;
	case SIOCGIFCONF:
		ifc.ifc_len = *(int *)&ioctl_cm->icm_data[0];
		datap = ifc.ifc_buf = malloc(ifc.ifc_len);
		argp = &ifc;
		size = ifc.ifc_len + sizeof(int);
		break;
	case SIOCIFGCLONERS:
		ifcr.ifcr_count = *(int *)&ioctl_cm->icm_data[0];
		datap = ifcr.ifcr_buffer = malloc(ifcr.ifcr_count*IFNAMSIZ);
		argp = &ifcr;
		size = sizeof(int) + ifcr.ifcr_count*IFNAMSIZ;
		break;
	case SIOCGIFMEDIA:
		argp = ifmr = (struct ifmediareq *)&ioctl_cm->icm_data[0];
		if (ifmr->ifm_ulist != NULL) {
			datap = ifmr->ifm_ulist = 
				malloc(ifmr->ifm_count*sizeof(int));
			size = sizeof(struct ifmediareq) +
				ifmr->ifm_count*sizeof(int);
		} else
			size = sizeof(struct ifmediareq);
		break;
	default:
		printf("unsupported ioctl! %lx\n", request);
		err = EINVAL;
		free(msgp);
		if (datap != NULL)
			free(datap);
		return (send_return_msg(fd, err, 0));
		/* XXX unsupported ioctl */
		break;
	}
	err = kern_ioctl(td, ioctl_cm->icm_fd, request, argp);
	if (err != 0) {
		size = 0;
		free(msgp);
		if (datap != NULL)
			free(datap);
	}
	rc = send_return_msg(fd, err, size);
	if (err || rc) {
		free(msgp);
		if (datap != NULL)
			free(datap);
		if (rc)
			return (rc);
		return (0);
	}
	switch (request) {
	case SIOCGIFCONF:
		iov[0].iov_base = (void *)&ifc.ifc_len;
		iov[0].iov_len = sizeof(int);
		iov[1].iov_base = ifc.ifc_buf;
		iov[1].iov_len = ifc.ifc_len;
		iovcnt = 2;
		break;
	case SIOCGIFDESCR:
		iov[0].iov_base = ifr;
		iov[0].iov_len = sizeof(struct ifreq);
		iov[1].iov_base = datap;
		iov[1].iov_len = ifr->ifr_buffer.length;
		iovcnt = 2;
		break;
	case SIOCIFGCLONERS:
		iov[0].iov_base = &ifcr.ifcr_total;
		iov[0].iov_len = sizeof(ifcr.ifcr_total);
		iov[1].iov_base = datap;
		iov[1].iov_len = ifcr.ifcr_count*IFNAMSIZ;
		iovcnt = 2;
	case SIOCGIFMEDIA:
		iov[0].iov_base = ifmr;
		iov[0].iov_len = sizeof(struct ifmediareq);
		iovcnt = 1;
		if (ifmr->ifm_ulist != NULL) {
			datap = iov[1].iov_base = ifmr->ifm_ulist;
			iov[1].iov_len = ifmr->ifm_count*sizeof(int);
			iovcnt = 2;
		}
	default:
		iov[0].iov_base = ifr;
		iov[0].iov_len = sizeof(struct ifreq);
		iovcnt = 1;
	}

	rc = writev(fd, iov, iovcnt);

	free(msgp);
	if (datap != NULL)
		free(datap);
	if (rc < 0)
		return (errno);

	return (0);
}
	

