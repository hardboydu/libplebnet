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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <sys/syscall.h>

#include <sys/proc.h>


#include <net/if.h>


#include <netinet/in.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/uio.h>

#define _WITH_DPRINTF
#include <stdio.h>

#include <ifmsg.h>

#include <sys/ioctl.h>
#include <stdarg.h>

static int target_fd; 

int _socket(int domain, int type, int protocol);
int _connect(int s, const struct sockaddr *name, socklen_t namelen);
void target_connect(void) __attribute__((constructor));

static void 
client_fini(void)
{
	printf("closing target fd");
	close(target_fd);
}

void 
target_connect(void)
{
	char *pidstr;
	struct sockaddr_un addr;
	char buffer[16];

	if (target_fd != 0)
		return;

	pidstr = getenv("TARGET_PID");
	if (pidstr == NULL || strlen(pidstr) == 0) {
		printf("failed to find target pid set, proxied calls will not work");
		return;
	}

	target_fd = _socket(PF_LOCAL, SOCK_STREAM, 0);

	atexit(client_fini);

	addr.sun_family = PF_LOCAL;
	strcpy(buffer, "/tmp/");
	strcat(buffer, pidstr);
	strcpy(addr.sun_path, buffer);
	if(_connect(target_fd, (struct sockaddr *)&addr,
		SUN_LEN(&addr))) {
		printf("failed to connect to target pid %s, proxied calls will not work", pidstr);
	}
}

int
handle_return_msg(int fd, int *size)
{
	int rc, err;
	struct iovec iov[2];
	iov[0].iov_base = size;
	iov[0].iov_len = sizeof(int);
	iov[1].iov_base = &err;
	iov[1].iov_len = sizeof(int);

	rc = readv(fd, iov, 2);
	
	return ((rc < 0) ? errno : (err ? err : 0));
}

int
socket(int domain, int type, int protocol)
{
	
	struct iovec iov[2];
	struct call_msg cm;
	struct socket_call_msg scm;
	int size, err, fd;
	

	cm.cm_size = sizeof(struct socket_call_msg);
	cm.cm_id = SYS_socket;
	scm.scm_domain = domain;
	scm.scm_type = type;
	scm.scm_protocol = protocol;
	
	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &scm;
	iov[1].iov_len = sizeof(struct socket_call_msg);
	
	writev(target_fd, iov, 2);
	
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}

	if ((err = read(target_fd, &fd, sizeof(int))) != sizeof(int)) {
		errno = EINTR;
		return (-1);
	}

	return (fd);
}

static int
ioctl_internal(int fd, unsigned long request, uintptr_t argp)
{	
	int size, iovcnt, retval;
	struct iovec iov[4];
	struct ifreq *ifr = NULL;
	struct ifconf *ifc = NULL;
	struct ifmediareq *ifmr = NULL;
	struct if_clonereq *ifcr = NULL;
	void *datap = NULL;
	struct call_msg cm;
	struct ifreq_call_msg ifr_cm;
	struct ifconf_call_msg ifc_cm;
	struct ifclonereq_call_msg ifcr_cm;
	struct ifmediareq_call_msg ifmr_cm;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(cm);
	cm.cm_id = SYS_ioctl;
	cm.cm_size = 0;
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
	case SIOCGIFDESCR:
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
		ifr_cm.icm_fd = fd;
		ifr_cm.icm_request = request;
		ifr_cm.icm_ifr = *(struct ifreq *)argp;
		iov[1].iov_base = &ifr_cm;
		cm.cm_size = iov[1].iov_len = sizeof(ifr_cm);
		iovcnt = 2;

		break;
/* deep copy needed */
	case SIOCSIFDESCR:
		ifr_cm.icm_fd = fd;
		ifr_cm.icm_request = request;
		ifr_cm.icm_ifr = *(struct ifreq *)argp;
		iov[1].iov_base = &ifr_cm;
		cm.cm_size = iov[1].iov_len = sizeof(ifr_cm);

		datap = ifr_cm.icm_ifr.ifr_buffer.buffer;

		iov[2].iov_base = ifr_cm.icm_ifr.ifr_buffer.buffer;
		iov[2].iov_len = ifr_cm.icm_ifr.ifr_buffer.length;
		cm.cm_size += ifr_cm.icm_ifr.ifr_buffer.length;

		iovcnt = 3;
		break;
	case SIOCSIFNAME:
		ifr_cm.icm_fd = fd;
		ifr_cm.icm_request = request;
		ifr_cm.icm_ifr = *(struct ifreq *)argp;
		iov[1].iov_base = &ifr_cm;
		cm.cm_size = iov[1].iov_len = sizeof(ifr_cm);

		datap = ifr_cm.icm_ifr.ifr_data;

		iov[2].iov_base = datap;
		iov[2].iov_len = IFNAMSIZ;
		cm.cm_size += IFNAMSIZ;
		iovcnt = 3;
		break;
	case SIOCGIFCONF:
		ifc = (struct ifconf *)argp;
		ifc_cm.icm_fd = fd;
		ifc_cm.icm_request = request;
		ifc_cm.icm_ifc_len = ifc->ifc_len;
		iov[1].iov_base = &ifc_cm;
		cm.cm_size = iov[1].iov_len = sizeof(ifc_cm);
		iovcnt = 2;
		break;
	case SIOCIFGCLONERS:
		ifcr = (struct if_clonereq *)argp;
		ifcr_cm.icm_fd = fd;
		ifcr_cm.icm_request = request;
		ifcr_cm.icm_ifcr_count = ifcr->ifcr_count;
		iov[1].iov_base = &ifcr_cm;
		cm.cm_size = iov[1].iov_len = sizeof(ifcr_cm);
		iovcnt = 2;
		break;
	case SIOCGIFMEDIA:
		ifmr = (struct ifmediareq *)argp;
		bcopy(ifmr, &ifmr_cm.icm_ifmr, sizeof(ifmr_cm));
		ifmr_cm.icm_fd = fd;
		ifmr_cm.icm_request = request;
		iov[1].iov_base = &ifmr_cm;
		cm.cm_size = iov[1].iov_len = sizeof(ifmr_cm);
		iovcnt = 2;
		break;
	case SIOCIFCREATE2:
		/* ifr_data is a sub-system specific opaque blob
		 * so we need sub-system specif hackery 
		 * ... punting for now
		 */
	default:
		printf("unknown or unsupported ioctl: %lx\n", request);
		return (EINVAL);
	}

	retval = writev(target_fd, iov, iovcnt);

	if ((retval = handle_return_msg(target_fd, &size)))
		return (retval);

	switch (request) {
	case SIOCGIFCONF:
		iov[0].iov_base = (void *)&ifc->ifc_len;
		iov[0].iov_len = sizeof(int);
		iov[1].iov_base = ifc->ifc_buf;
		iov[1].iov_len = size - sizeof(int);
		iovcnt = 2;
		break;
	case SIOCGIFDESCR:
		datap = ifr->ifr_buffer.buffer;
		iov[0].iov_base = ifr;
		iov[0].iov_len = sizeof(struct ifreq);
		iov[1].iov_base = datap;
		iov[1].iov_len = size - sizeof(struct ifreq);
		iovcnt = 2;
		break;
	case SIOCIFGCLONERS:
		iov[0].iov_base = &ifcr->ifcr_total;
		iov[0].iov_len = sizeof(ifcr->ifcr_total);
		iov[1].iov_base = ifcr->ifcr_buffer;
		iov[1].iov_len = size - sizeof(int);
		iovcnt = 2;

	case SIOCGIFMEDIA:
		iov[0].iov_base = ifmr;
		iov[0].iov_len = sizeof(struct ifmediareq);
		iovcnt = 1;
		if (ifmr->ifm_ulist != NULL) {
			datap = iov[1].iov_base = ifmr->ifm_ulist;
			iov[1].iov_len = size - sizeof(struct ifmediareq);
			iovcnt = 2;
		}
	default:
		iov[0].iov_base = ifr;
		iov[0].iov_len = sizeof(struct ifreq);
		iovcnt = 1;

	}

	retval = readv(target_fd, iov, iovcnt);

	switch (request) {
	case SIOCGIFDESCR:
		ifr->ifr_buffer.buffer = datap;
		break;
	case SIOCSIFNAME:
		ifr->ifr_data = datap;
		break;
	case SIOCGIFMEDIA:
		ifmr->ifm_ulist = datap;
	default:
		break;
		/* do nothing */
	}
	
	return (0);
}

int
ioctl(int d, unsigned long request, ...)
{
	va_list ap;
	uintptr_t argp;

	va_start(ap, request);

	argp = va_arg(ap, uintptr_t);
	va_end(ap);

	return (ioctl_internal(d, request, argp));
}

