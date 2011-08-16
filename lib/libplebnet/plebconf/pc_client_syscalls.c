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
	struct iovec iov[5];
	int size, code, i, err, fd;

	size = 3*sizeof(int);
	code = SYS_socket;

	iov[0].iov_base = &size;
	iov[1].iov_base = &code;
	iov[2].iov_base = &domain;
	iov[3].iov_base = &type;
	iov[4].iov_base = &protocol;

	for (i = 0; i < 5; i++)
		iov[i].iov_len = sizeof(int);
	
	writev(target_fd, iov, 5);
	
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


struct ioctl_call {
	int ic_id;
	unsigned long ic_request;
};


static int
ioctl_internal(int d, unsigned long request, uintptr_t argp)
{	
	int size, iovcnt, retval;
	struct iovec iov[4];
	struct ioctl_call ic;
	struct ifreq *ifr = NULL;
	struct ifconf *ifc = NULL;
	struct ifmediareq *ifmr = NULL;
	struct if_clonereq *ifcr = NULL;
	void *datap = NULL;

	ic.ic_id = SYS_ioctl;
	ic.ic_request = request;
	iov[1].iov_base = &ic;
	iov[1].iov_len = sizeof(ic);
	size = sizeof(request);

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
		ifr = (struct ifreq *)argp;

		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		size += sizeof(struct ifreq);

		iovcnt = 3;

		break;
/* deep copy needed */
	case SIOCSIFDESCR:
		ifr = (struct ifreq *)argp;

		datap = ifr->ifr_buffer.buffer;

		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		size += sizeof(struct ifreq);

		iov[3].iov_base = ifr->ifr_buffer.buffer;
		iov[3].iov_len = ifr->ifr_buffer.length;
		size += ifr->ifr_buffer.length;

		iovcnt = 4;
		break;
	case SIOCSIFNAME:
		ifr = (struct ifreq *)argp;

		datap = ifr->ifr_data;

		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		size += sizeof(struct ifreq);

		iov[3].iov_base = ifr->ifr_data;
		iov[3].iov_len = IFNAMSIZ;
		size += IFNAMSIZ;

		iovcnt = 4;
		break;
	case SIOCGIFCONF:
		ifc = (struct ifconf *)argp;
		
		iov[2].iov_base = (void *) &ifc->ifc_len;
		iov[2].iov_len = sizeof(int);
		size += sizeof(int);

		break;
	case SIOCIFGCLONERS:
		ifcr = (struct if_clonereq *)argp;
		
		iov[2].iov_base = (void *) &ifcr->ifcr_total;
		iov[2].iov_len = sizeof(int);
		size += sizeof(int);

		iovcnt = 3;
		break;
	case SIOCGIFMEDIA:
		ifmr = (struct ifmediareq *)argp;
		
		iov[2].iov_base = ifmr;
		iov[2].iov_len = sizeof(struct ifmediareq);
		size += sizeof(struct ifreq);
		
		iovcnt = 3;
		break;
	case SIOCIFCREATE2:
		/* ifr_data is a sub-system specific opaque blob
		 * so we need sub-system specif hackery 
		 * ... punting for now
		 */
	default:
		printf("unknown or unsupported ioctl");
		return (ENOTSUP);
	}
	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(size);


	retval = writev(target_fd, iov, iovcnt);

	retval = handle_return_msg(target_fd, &size);
	
	/* XXX check err  */


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

