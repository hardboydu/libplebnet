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
#include <sys/linker.h>
#include <sys/module.h>

#include <sys/ioctl.h>
#include <net/if.h>


#include <netinet/in.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/uio.h>
#include <sys/sysctl.h>
#include <sys/module.h>


#define _WITH_DPRINTF
#include <stdio.h>

#include <net/if_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <ifmsg.h>
#include <pn_kern_subr.h>
#include <pthread.h>
#include <sys/pcpu.h> /* curthread */
#include <pn_private.h>

extern pthread_mutex_t init_lock;
extern pthread_cond_t init_cond;


#define BYTES_RECEIVED

static int target_fd;
struct thread;
struct	filedesc *fdinit(struct filedesc *fdp);
struct ucred	*crget(void);
struct ucred	*crhold(struct ucred *cr);
extern struct proc proc0;

static int dispatch_table_size = SYS_MAXSYSCALL;

typedef int (*dispatch_func)(struct thread *, int, int, int);

static int dispatch_socket(struct thread *td, int fd, int size, int id);
static int dispatch_ioctl(struct thread *td, int fd, int size, int id);
static int dispatch_sysctl(struct thread *td, int fd, int size, int id);
static int dispatch_write(struct thread *td, int fd, int size, int id);
static int dispatch_shutdown(struct thread *td, int fd, int size, int id);
static int dispatch_kldhandler(struct thread *td, int fd, int size, int id);

static struct proc server_proc;
dispatch_func dispatch_table[SYS_MAXSYSCALL];

static void
cleanup(void)
{
	char buffer[16];

	sprintf(buffer, "/tmp/%d", getpid());
	close(target_fd);
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
	dispatch_table[SYS_write] = dispatch_write;
	dispatch_table[SYS_shutdown] = dispatch_shutdown;
	dispatch_table[SYS___sysctl] = dispatch_sysctl;

	dispatch_table[SYS_kldload] = dispatch_kldhandler;
	dispatch_table[SYS_kldunload] = dispatch_kldhandler;
	dispatch_table[SYS_kldfind] = dispatch_kldhandler;
	dispatch_table[SYS_kldnext] = dispatch_kldhandler;
	dispatch_table[SYS_kldstat] = dispatch_kldhandler;
	dispatch_table[SYS_kldunloadf] = dispatch_kldhandler;
	dispatch_table[SYS_modnext] = dispatch_kldhandler;
	dispatch_table[SYS_modfnext] = dispatch_kldhandler;
	dispatch_table[SYS_modstat] = dispatch_kldhandler;
	dispatch_table[SYS_kldfirstmod] = dispatch_kldhandler;

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
	if (err == 0) {
		errno = EPIPE;
		return (-1);
	}
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

static int
recv_client_msg(int fd, void **msgp, int size)
{
	int rc, err = 0;
	struct return_msg rm;
#ifdef BYTES_RECEIVED
	printf("receiving %d bytes\n", size);
#endif
	if (size == 0) {
		printf("closing fd\n");
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
	printf("sending message err=%d size=%d\n", error, size);
	return (0);
}

int
dispatch(struct thread *td, int fd)
{
	int rc, size, funcid;
	struct thread *orig;

	funcid = handle_call_msg(fd, &size);

	if (funcid == 0)
		return (0);
	if (funcid < 0)
		return (errno);
	
	orig = pcurthread;
	pcurthread = td;
	rc = dispatch_table[funcid](td, fd, size, funcid);
	pcurthread = orig;
	/* check rc for closed socket */
	if (rc != 0)
		printf("%p returned %d\n", dispatch_table[funcid], rc);
	return (rc);
}



void *
dispatch_server(void *arg)
{
	int fd;
	struct thread *td;

	fd = (uintptr_t)arg;
	td = curthread;
	td->td_ucred = crhold(server_proc.p_ucred);
	td->td_proc->p_fd = fdinit(NULL);
	td->td_proc->p_fdtol = NULL;

	while (dispatch(td, fd) == 0)
			;

	return (NULL);
}

void *
syscall_server(void *arg)
{
	int fd;
	struct sockaddr_un addr;
	int len;
	struct thread *td;
	pthread_t handler;

	target_bind();

	td = curthread;
	td->td_proc = &server_proc;
	/* Create the file descriptor table. */
	server_proc.p_ucred = proc0.p_ucred;
	server_proc.p_limit = proc0.p_limit;
	server_proc.p_sysent = proc0.p_sysent;
	td->td_ucred = crhold(server_proc.p_ucred);
	td->td_proc->p_fd = fdinit(NULL);
	td->td_proc->p_fdtol = NULL;
	fdused_range(td->td_proc->p_fd, 32);
	len = sizeof(addr);
	pthread_mutex_lock(&init_lock);
	pthread_cond_signal(&init_cond);
	pthread_mutex_unlock(&init_lock);
	while (1) {
		fd = accept(target_fd, (struct sockaddr *)&addr, &len);
		pthread_create(&handler, NULL, dispatch_server, (void *)(uintptr_t)fd);
	}
	
	return (NULL);
}

void
start_server_syscalls(void)
{
	pthread_t server;

	pthread_create(&server, NULL, syscall_server, NULL);
}

static int
dispatch_socket(struct thread *td, int fd, int size, int id)
{
	int err, rc, osize, newfd;
	struct socket_call_msg scm;

	err = osize = 0;

	if (size != sizeof(scm))
		err = EINVAL;
	else if (read(fd, &scm, sizeof(scm)) < 0) {
		err = errno;
	} else {
		if (scm.scm_domain == PF_LOCAL)
			scm.scm_domain = PF_INET;
		if ((newfd = socket(scm.scm_domain, scm.scm_type, 
			    scm.scm_protocol)) >= 0) {
			osize = sizeof(int);
		}
		printf("newfd=%d\n", newfd);
	}
	if ((rc = send_return_msg(fd, err, osize)))
		return (rc);

	if (osize && (write(fd, &newfd, sizeof(newfd)) < 0))
		return (errno);

	return (0);
}

static int
dispatch_shutdown(struct thread *td, int fd, int size, int id)
{
	int err, rc;
	struct shutdown_call_msg scm;

	err = 0;

	if (size != sizeof(scm))
		err = EINVAL;
	else if (read(fd, &scm, sizeof(scm)) < 0) {
		err = errno;
	} else if (shutdown(scm.scm_fd, scm.scm_how) < 0) {
		err = errno;
	}
	if ((rc = send_return_msg(fd, err, 0)))
		return (rc);
	return (0);
}

static int
dispatch_write(struct thread *td, int fd, int size, int id)
{
	int err, rc, osize;
	size_t bytes_written;
	struct write_call_msg *wcm = NULL;

	osize = err = 0;
	if ((err = recv_client_msg(fd, (void **)&wcm, size)))
		return (err);
	else {
		bytes_written = write(wcm->wcm_fd, &wcm->wcm_data[0], 
		    size - sizeof(wcm->wcm_fd));
		if (bytes_written < 0)
			err = errno;
		else
			osize = sizeof(bytes_written);
	}
	if ((rc = send_return_msg(fd, err, osize)))
		return (rc);

	if (osize && (write(fd, &bytes_written, sizeof(size_t)) < 0))
		return (errno);

	return (0);
}


static int
dispatch_sysctl(struct thread *td, int fd, int msgsize, int id)
{
	int i, err, rc, iovcnt, size;
	size_t oldlen;
	struct sysctl_call_msg *scm = NULL;
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
	printf("rc=%d oldlen=%zd ", rc, oldlen);
	free(scm);
	if (rc && oldp != NULL)
		free(oldp);
	if (rc)
		rc = errno;
	else if (oldp == NULL)
		size = sizeof(oldlen);
	else 
		size = oldlen + sizeof(oldlen);
	printf(" ...rc=%d, size=%d\n", rc, size);
	rc = send_return_msg(fd, rc, size);
	if (size == 0 || rc)
		return (rc);

	iov[0].iov_base = &oldlen;
	iov[0].iov_len = sizeof(oldlen);
	if (size > sizeof(oldlen)) {
		iov[1].iov_base = oldp;
		iov[1].iov_len = oldlen;
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
dispatch_ioctl(struct thread *td, int fd, int msgsize, int id)
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
		ifr = argp = &ioctl_cm->icm_data[0];
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
	case SIOCGDEFIFACE_IN6:
	case SIOCSDEFIFACE_IN6:
	case SIOCGIFINFO_IN6:
		argp = &ioctl_cm->icm_data[0];
		size = sizeof(struct in6_ndireq);
		break;
	case SIOCGIFALIFETIME_IN6:
	case SIOCGIFAFLAG_IN6:
		argp = &ioctl_cm->icm_data[0];
		size = sizeof(struct in6_ifreq);
	case SIOCAIFADDR:
		argp = &ioctl_cm->icm_data[0];
		size = 0;
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
	if (err != 0)
		size = 0;
	rc = send_return_msg(fd, err, size);
	if (err || rc || size == 0) {
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
	case SIOCGDEFIFACE_IN6:
	case SIOCSDEFIFACE_IN6:
	case SIOCGIFINFO_IN6:
		iov[0].iov_base = argp;
		iov[0].iov_len = sizeof(struct in6_ndireq);
		iovcnt = 1;
		break;
	case SIOCGIFALIFETIME_IN6:
	case SIOCGIFAFLAG_IN6:
		iov[0].iov_base = argp;
		iov[0].iov_len = sizeof(struct in6_ifreq);
		iovcnt = 1;
		break;
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

static int 
dispatch_kldhandler(struct thread *td, int fd, int size, int id)
{
	char *file;
	int err, fileid, *fileidp;
	struct kldunloadf_call_msg *kucm;
	struct kld_file_stat kstat;
	struct module_stat mstat;

	file = NULL;
	kucm = NULL;
	switch (id) {
	case SYS_kldload:
	case SYS_kldfind:
		if ((err = recv_client_msg(fd, (void **)&file, size)))
			return (err);
		break;
	case SYS_kldunload:
	case SYS_kldfirstmod:
	case SYS_kldnext:
	case SYS_kldstat:
	case SYS_modstat:
	case SYS_modnext:
	case SYS_modfnext:
		fileidp = &fileid;
		if ((err = recv_client_msg(fd, (void **)&fileidp, size)))
			return (err);
		break;
	case SYS_kldunloadf:
		if ((err = recv_client_msg(fd, (void **)&kucm, size)))
			return (err);
		break;
	default:
		send_return_msg(fd, ENOSYS, 0);
		return (0);
		break;
	}

	switch (id) {
	case SYS_kldload:
		err = kern_kldload(td, file, &fileid);
		break;
	case SYS_kldfind:
		err = kern_kldfind(td, file);
		break;
	case SYS_kldunload:
		err = kern_kldunload(td, fileid, 0);
		break;
	case SYS_kldnext:
		err = sys_kldnext(td, &fileid);
		fileid = td->td_retval[0];
		break;
	case SYS_kldstat:
		err = kern_kldstat(td, fileid, &kstat);
		size = sizeof(kstat);
		break;
	case SYS_kldunloadf:
		err = kern_kldunload(td, kucm->kucm_fileid, kucm->kucm_flags);
		break;
	case SYS_kldfirstmod:
		err = sys_kldfirstmod(td, &fileid);
		fileid = td->td_retval[0];
		break;
	case SYS_modnext:
		err = sys_modnext(td, &fileid);
		fileid = td->td_retval[0];
		break;
	case SYS_modfnext:
		err = sys_modfnext(td, &fileid);
		fileid = td->td_retval[0];
		break;
	case SYS_modstat:
		err = kern_modstat(fileid, &mstat);
		size = sizeof(mstat);
		break;
	default:
		break;
	}

	if (err)
		size = 0;
	send_return_msg(fd, err, size);
	if (size == 0)
		goto out;
		
	switch (id) {
	case SYS_kldload:
	case SYS_kldfind:
	case SYS_kldnext:
	case SYS_kldfirstmod:
	case SYS_modnext:
	case SYS_modfnext:
		if ((err = write(fd, &fileid, sizeof(fileid))) < 0)
			return (errno);
		break;
	case SYS_kldstat:
		if ((err = write(fd, &kstat, sizeof(kstat))) < 0)
			return (errno);
		break;
	case SYS_modstat:
		if ((err = write(fd, &mstat, sizeof(mstat))) < 0)
			return (errno);
		break;
	default:
		break;
	}

out:
	if (file != NULL)
		free(file);
	if (kucm != NULL)
		free(kucm);

	return (0);
}
