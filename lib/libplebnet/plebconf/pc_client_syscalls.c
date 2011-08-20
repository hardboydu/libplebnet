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
#include <sys/sysctl.h>

#include <sys/uio.h>

#define _WITH_DPRINTF
#include <stdio.h>


#include <sys/ioctl.h>
#include <stdarg.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_lagg.h>
#include <net/if_gre.h>
#include <net/if_gif.h>
#include <net80211/ieee80211_ioctl.h>

#include <netinet/in.h>
#include <netinet/ip_carp.h>


#include <net/pfvar.h>
#include <net/if_pfsync.h>


#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <ifmsg.h>


static int target_fd; 

void target_connect(void) __attribute__((constructor));
int __sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);
int user_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);
int _socket(int domain, int type, int protocol);


#ifdef UNSUPPORTED_IOCTL
#define IPRINTF printf
#else
#define IPRINTF(...)
#endif

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
#ifdef DEBUG_CONNECT
	printf("attempting to connect ...");
	if(connect(target_fd, (struct sockaddr *)&addr,
		SUN_LEN(&addr))) {
		printf("failed to connect to target pid %s, proxied calls will not work", pidstr);
	} else 
		printf("connected to %s", pidstr);
#else
	if(connect(target_fd, (struct sockaddr *)&addr,
		SUN_LEN(&addr))) 
		printf("failed to connect to target pid %s, proxied calls will not work", pidstr);
#endif
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
	struct in6_ndireq *ndi = NULL;
	void *datap = NULL;
	struct call_msg cm;
	struct ioctl_call_msg i_cm;
	struct ifclonereq_call_msg ifcr_cm;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(cm);
	cm.cm_id = SYS_ioctl;
	cm.cm_size = 0;

	i_cm.icm_fd = fd;
	i_cm.icm_request = request;
	iov[1].iov_base = &i_cm;
	cm.cm_size = iov[1].iov_len = sizeof(i_cm);


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
		cm.cm_size += sizeof(struct ifreq);
		iovcnt = 3;
		break;
/* deep copy needed */
	case SIOCSIFDESCR:
		ifr = (struct ifreq *)argp;
		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		cm.cm_size += sizeof(struct ifreq);

		datap = ifr->ifr_buffer.buffer;

		iov[3].iov_base = ifr->ifr_buffer.buffer;
		iov[3].iov_len = ifr->ifr_buffer.length;
		cm.cm_size += ifr->ifr_buffer.length;

		iovcnt = 4;
		break;
	case SIOCSIFNAME:
		ifr = (struct ifreq *)argp;
		iov[2].iov_base = ifr;
		iov[2].iov_len = sizeof(struct ifreq);
		cm.cm_size += sizeof(struct ifreq);

		datap = ifr->ifr_data;

		iov[3].iov_base = datap;
		iov[3].iov_len = IFNAMSIZ;
		cm.cm_size += IFNAMSIZ;
		iovcnt = 3;
		break;
	case SIOCGIFCONF:
		ifc = (struct ifconf *)argp;
		iov[2].iov_base = &ifc->ifc_len;
		iov[2].iov_len = sizeof(ifc->ifc_len);
		cm.cm_size += sizeof(ifc->ifc_len);
		iovcnt = 2;
		break;
	case SIOCIFGCLONERS:
		/* XXX fix */
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
		iov[2].iov_base = ifmr;
		iov[2].iov_len = sizeof(struct ifmediareq);
		cm.cm_size += sizeof(struct ifmediareq);

		iovcnt = 3;
		break;
	case SIOCGIFINFO_IN6:
		ndi = (struct in6_ndireq *)argp;
		iov[2].iov_base = ndi;
		iov[2].iov_len = sizeof(struct in6_ndireq);
		cm.cm_size += sizeof(struct in6_ndireq);
		iovcnt = 3;
		break;
	case SIOCGETPFSYNC:
		IPRINTF("SIOCGETPFSYNC unsupported\n");
		return (EINVAL);
		break;
	case SIOCGVH:
		IPRINTF("SIOCGVH unsupported\n");
		return (EINVAL);
		break;
	case SIOCGDRVSPEC:
		IPRINTF("SIOCGDRVSPEC unsupported\n");
		return (EINVAL);
		break;
	case SIOCGIFPSRCADDR_IN6:
	case SIOCGDEFIFACE_IN6:
	case SIOCGIFAFLAG_IN6:
	case SIOCGIFALIFETIME_IN6:
		IPRINTF("IPv6 unsupported\n");
		return (ENOSYS);
		break;
	case SIOCG80211:
		IPRINTF("SIOCG80211 unsupported\n");
		return (EINVAL);
		break;
	case SIOCGIFSTATUS:
		IPRINTF("SIOCGIFSTATUS unsupported\n");
		return (EINVAL);
		break;
	case SIOCGIFFIB:
		IPRINTF("SIOCGIFFIB unsupported\n");
		return (EINVAL);
		break;
	case SIOCGLAGG:
		IPRINTF("SIOCLAGG unsupported\n");
		return (EINVAL);
		break;
	case SIOCGLAGGPORT:
		IPRINTF("SIOCLAGGPORT unsupported\n");
		return (EINVAL);
		break;
	case GREGKEY:
		IPRINTF("SIOCREGKEY unsupported\n");
		return (EINVAL);
		break;
	case GIFGOPTS:
		IPRINTF("SIOCGIFGOPTS unsupported\n");
		return (EINVAL);
		break;
	case SIOCIFCREATE2:
		/* ifr_data is a sub-system specific opaque blob
		 * so we need sub-system specif hackery 
		 * ... punting for now
		 */
		IPRINTF("SIOCIFCREATE2 unsupported\n");
		return (EINVAL);
		break;
	default:
		printf("unknown ioctl: %lx\n", request);
		return (EINVAL);
	}	
#ifdef BYTES_SENT
	if (cm.cm_size != 0) 
		printf("sending %d bytes\n", cm.cm_size);
#endif

	retval = writev(target_fd, iov, iovcnt);
	if (retval != cm.cm_size + sizeof(cm))
		printf("size mismatch %ld\n", retval - sizeof(cm));

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
	case SIOCGIFINFO_IN6:
		iov[0].iov_base = ndi;
		iov[0].iov_len = sizeof(struct in6_ndireq);
		iovcnt = 1;
		break;
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
	int err;

	va_start(ap, request);

	argp = va_arg(ap, uintptr_t);
	va_end(ap);

	err = ioctl_internal(d, request, argp);
	if (err) {
		errno = err;
		return (-1);
	}
	return (0);
}

int
sysctl_internal(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
         const void *newp, size_t newlen)
{
	struct call_msg cm;
	struct sysctl_call_msg scm;
	struct iovec iov[4];
	int iovcnt, size, rc;

	cm.cm_id = SYS___sysctl;
	cm.cm_size = sizeof(scm) + namelen*sizeof(int) + newlen;
	scm.scm_miblen = namelen;
	scm.scm_newlen = newlen;
	scm.scm_oldlen = 0;
	if (oldp != NULL && oldlenp != NULL)
		scm.scm_oldlen = *oldlenp;

	iovcnt = 3;
	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(cm);
	iov[1].iov_base = &scm;
	iov[1].iov_len = sizeof(scm);
	iov[2].iov_base = __DECONST(int *, name);
	iov[2].iov_len = namelen*sizeof(int);

#ifdef DEBUG_SYSCTL
	{
		int i;
		for (i = 0; i < namelen; i++)
			printf("mib[%d]=%d ", i, name[i]);
	}
	printf("oldp=%p, oldlenp=%p oldlen=%zd newlen=%zd\n", oldp, oldlenp, 
	    oldlenp ? *oldlenp : 0, newlen);
	printf("\n");
#endif
	if (newlen > 0 && newp != NULL) {
		iovcnt = 4;
		iov[3].iov_base = __DECONST(void *, newp);
		iov[3].iov_len = newlen;
	}


	writev(target_fd, iov, iovcnt);
	if ((rc = handle_return_msg(target_fd, &size))) {
		errno = rc;
		return (-1);
	}
	
	if (size == 0)
		return (0);

	iov[0].iov_base = oldlenp;
	iov[0].iov_len = sizeof(size_t);
	iov[1].iov_base = oldp;
	iov[1].iov_len = size - sizeof(size_t);
	if ((readv(target_fd, iov, 2) < 0))
		return (-1);		    

	return (0);
}

int
sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
         const void *newp, size_t newlen)
{
	if (name[0] == CTL_USER)
		return (user_sysctl(name, namelen, oldp, oldlenp, newp, newlen));

	if (name[0] != CTL_NET)
		return (__sysctl(name, namelen, oldp, oldlenp, newp, newlen));

	return (sysctl_internal(name, namelen, oldp, oldlenp, newp, newlen));
}
