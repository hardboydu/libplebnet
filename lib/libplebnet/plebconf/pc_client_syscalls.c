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
#include <sys/linker.h>
#include <sys/module.h>

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
static int total_bytes_read;
static int total_bytes_written;
static int debug;

void target_connect(void) __attribute__((constructor));
int __sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);
int user_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);
int _socket(int domain, int type, int protocol);
ssize_t _write(int fd, const void *buf, size_t nbytes);
int _ioctl(int d, unsigned long request, ...);

#define BYTES_SENT
#define DEBUG_SYSCTL

#ifdef UNSUPPORTED_IOCTL
#define IPRINTF printf
#else
#define IPRINTF(...)
#endif

#define DEBUG_PRINTF(msg) if (debug) printf msg

static void 
client_fini(void)
{
	close(target_fd);
	if (debug == 0)
		return;
	printf("closing target fd bytes_read=%d bytes_written=%d", 
	    total_bytes_read, total_bytes_written);
	abort();
}

void 
target_connect(void)
{
	char *str;
	struct sockaddr_un addr;
	char buffer[16];

	if (target_fd != 0)
		return;

	str = getenv("PC_CLIENT_DEBUG");
	if (str != NULL)
		debug = !strcmp(str, "verbose");
	str = getenv("TARGET_PID");
	if (str == NULL || strlen(str) == 0) {
		printf("failed to find target pid set, proxied calls will not work");
		return;
	} 

	target_fd = _socket(PF_LOCAL, SOCK_STREAM, 0);

	atexit(client_fini);

	addr.sun_family = PF_LOCAL;
	strcpy(buffer, "/tmp/");
	strcat(buffer, str);
	strcpy(addr.sun_path, buffer);
#ifdef DEBUG_CONNECT
	printf("attempting to connect ...");
	if(connect(target_fd, (struct sockaddr *)&addr,
		SUN_LEN(&addr))) {
		printf("failed to connect to target pid %s, proxied calls will not work", str);
	} else 
		printf("connected to %s", str);
#else
	if(connect(target_fd, (struct sockaddr *)&addr,
		SUN_LEN(&addr))) 
		printf("failed to connect to target pid %s, proxied calls will not work", str);
#endif
	if (debug == 0)
		return;
	printf("pid=%d\n", getpid());
	sleep(15);
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
	DEBUG_PRINTF(("receiving %d bytes\n", *size));
	total_bytes_read += rc;
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
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}

	if ((err = read(target_fd, &fd, sizeof(int))) != sizeof(int)) {
		errno = EINTR;
		return (-1);
	}
	total_bytes_read += err;
	return (fd);
}

int
shutdown(int fd, int how)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct shutdown_call_msg scm;
	int size, err;

	cm.cm_size = sizeof(struct shutdown_call_msg);
	cm.cm_id = SYS_shutdown;
	scm.scm_fd = fd;
	scm.scm_how = how;
	
	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &scm;
	iov[1].iov_len = sizeof(struct shutdown_call_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	return (0);
}

ssize_t
write(int fd, const void *buf, size_t nbytes)
{
	struct iovec iov[4];
	struct call_msg cm;
	struct write_call_msg wcm;
	int size, err;
	size_t bytes_written;

	/*
	 * XXX Evil HACK
	 */
	if (fd < 16)
		return (_write(fd, buf, nbytes));

	cm.cm_size = sizeof(struct write_call_msg) + nbytes;
	cm.cm_id = SYS_write;
	wcm.wcm_fd = fd;
	
	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &wcm;
	iov[1].iov_len = sizeof(struct write_call_msg);
	iov[2].iov_base = __DECONST(void *, buf);
	iov[2].iov_len = nbytes;
	
	err = writev(target_fd, iov, 3);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}

	if ((err = read(target_fd, &bytes_written, sizeof(size_t))) != sizeof(size_t)) {
		errno = EINTR;
		return (-1);
	}
	return (bytes_written);
}


static int
ioctl_internal(int fd, unsigned long request, void *argp)
{	
	int size, iovcnt, retval;
	struct iovec iov[4];
	struct ifreq *ifr = NULL;
	struct ifconf *ifc = NULL;
	struct ifmediareq *ifmr = NULL;
	struct if_clonereq *ifcr = NULL;
	void *datap = NULL;
	struct call_msg cm;
	struct ioctl_call_msg i_cm;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(cm);
	cm.cm_id = SYS_ioctl;
	cm.cm_size = 0;

	i_cm.icm_fd = fd;
	i_cm.icm_request = request;
	iov[1].iov_base = &i_cm;
	cm.cm_size = iov[1].iov_len = sizeof(i_cm);
	iovcnt = 3;

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
		iov[2].iov_base = argp;
		iov[2].iov_len = sizeof(struct ifreq);
		cm.cm_size += sizeof(struct ifreq);
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
		iovcnt = 4;
		break;
	case SIOCGIFCONF:
		ifc = (struct ifconf *)argp;
		iov[2].iov_base = &ifc->ifc_len;
		iov[2].iov_len = sizeof(ifc->ifc_len);
		cm.cm_size += sizeof(ifc->ifc_len);
		break;
	case SIOCIFGCLONERS:
		ifcr = (struct if_clonereq *)argp;
		iov[2].iov_base = &ifcr->ifcr_count;
		iov[2].iov_len = sizeof(ifcr->ifcr_count);
		cm.cm_size += sizeof(ifcr->ifcr_count);
		break;
	case SIOCGIFMEDIA:
		iov[2].iov_base = argp;
		iov[2].iov_len = sizeof(struct ifmediareq);
		cm.cm_size += sizeof(struct ifmediareq);
		break;
	case SIOCAIFADDR:
		iov[2].iov_base = argp;
		iov[2].iov_len = sizeof(struct ifaliasreq);
		cm.cm_size += sizeof(struct ifaliasreq);
		break;
	case SIOCGDEFIFACE_IN6:
	case SIOCSDEFIFACE_IN6:
	case SIOCGIFINFO_IN6:
		iov[2].iov_base = argp;
		iov[2].iov_len = sizeof(struct in6_ndireq);
		cm.cm_size += sizeof(struct in6_ndireq);
		break;
	case SIOCGIFALIFETIME_IN6:
	case SIOCGIFAFLAG_IN6:
		iov[2].iov_base = argp;
		iov[2].iov_len = sizeof(struct in6_ifreq);
		cm.cm_size += sizeof(struct in6_ifreq);
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
		DEBUG_PRINTF(("sending %d bytes\n", cm.cm_size));
#endif

	retval = writev(target_fd, iov, iovcnt);

	if (retval == -1) {
		char *str = strerror(errno);
		printf("writev failed: %s target_fd=%d\n\n\n\n\n\n", str, target_fd);
		sleep(60);
		abort();
		return (errno);
	}
	if (retval != cm.cm_size + sizeof(cm)) {
		printf("size mismatch %ld\n", retval - sizeof(cm));
		abort();
	}

	total_bytes_written += retval;
	if ((retval = handle_return_msg(target_fd, &size)))
		return (retval);

	if (size == 0)
		return (0);

	switch (request) {
	case SIOCGIFCONF:
		iov[0].iov_base = (void *)&ifc->ifc_len;
		iov[0].iov_len = sizeof(int);
		iov[1].iov_base = ifc->ifc_buf;
		iov[1].iov_len = size - sizeof(int);
		iovcnt = 2;
		break;
	case SIOCGIFDESCR:
		ifr = (struct ifreq *)argp;
		datap = ifr->ifr_buffer.buffer;
		iov[0].iov_base = argp;
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
		break;
	case SIOCGIFMEDIA:
		ifmr = (struct ifmediareq *)argp;
		iov[0].iov_base = argp;
		iov[0].iov_len = sizeof(struct ifmediareq);
		iovcnt = 1;
		if (ifmr->ifm_ulist != NULL) {
			datap = iov[1].iov_base = ifmr->ifm_ulist;
			iov[1].iov_len = size - sizeof(struct ifmediareq);
			iovcnt = 2;
		}
		break;
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
		iov[0].iov_base = argp;
		iov[0].iov_len = sizeof(struct ifreq);
		iovcnt = 1;
		break;
	}

	retval = readv(target_fd, iov, iovcnt);

	total_bytes_read += retval;
	switch (request) {
	case SIOCGIFDESCR:
		ifr->ifr_buffer.buffer = datap;
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

	err = ioctl_internal(d, request, (void *)argp);
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
	else if (oldp == NULL && oldlenp != NULL)
		*oldlenp = 0;

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
			DEBUG_PRINTF(("mib[%d]=%d ", i, name[i]));
	}
	DEBUG_PRINTF(("oldp=%p, oldlen=%zd, newlen=%zd\n", oldp,
		oldp ? *oldlenp : 0, newlen));
	DEBUG_PRINTF(("\n"));
#endif
	if (newlen > 0 && newp != NULL) {
		iovcnt = 4;
		iov[3].iov_base = __DECONST(void *, newp);
		iov[3].iov_len = newlen;
	}
	rc = writev(target_fd, iov, iovcnt);
	total_bytes_written += rc;

	if ((rc = handle_return_msg(target_fd, &size))) {
		errno = rc;
		return (-1);
	}
	
	if (size == 0) {
		DEBUG_PRINTF(("total_bytes_read=%d size == 0\n", total_bytes_read));
		return (0);
	}

	iovcnt = 1;
	iov[0].iov_base = oldlenp;
	iov[0].iov_len = sizeof(size_t);
	iov[1].iov_base = oldp;
	iov[1].iov_len = size - sizeof(size_t);
	if (size > sizeof(size_t))
		iovcnt = 2;
	if ((rc = readv(target_fd, iov, iovcnt)) < 0)
		return (-1);
	total_bytes_read += rc;
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

/*
 * Route and friends think that they know better than us,
 * don't let them interfere.
 */
uid_t
geteuid(void)
{
	
	return (0);
}

int 
kldnext(int fileid)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldid_msg kim;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldid_msg);
	cm.cm_id = SYS_kldnext;
	kim.kim_fileid = fileid;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kim;
	iov[1].iov_len = sizeof(struct kldid_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(int))
		read(target_fd, &nextfileid, sizeof(int));

	return (nextfileid);
}


int 
kldfirstmod(int fileid)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldid_msg kim;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldid_msg);
	cm.cm_id = SYS_kldfirstmod;
	kim.kim_fileid = fileid;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kim;
	iov[1].iov_len = sizeof(struct kldid_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(int))
		read(target_fd, &nextfileid, sizeof(int));

	return (nextfileid);
}

int 
kldload(const char *file)
{
	struct iovec iov[2];
	struct call_msg cm;

	int size, err, fileid;

	cm.cm_size = strlen(file) + 1;
	cm.cm_id = SYS_kldload;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = __DECONST(char *, file);
	iov[1].iov_len = cm.cm_size;
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(int))
		read(target_fd, &fileid, sizeof(int));
	else
		fileid = -1;

	return (fileid);
}

int 
kldstat(int fileid, struct kld_file_stat* stat)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldid_msg kim;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldid_msg);
	cm.cm_id = SYS_kldnext;
	kim.kim_fileid = fileid;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kim;
	iov[1].iov_len = sizeof(struct kldid_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(struct kld_file_stat))
		read(target_fd, stat, sizeof(struct kld_file_stat));

	return (nextfileid);
}

int 
kldfind(const char *file)
{
	struct iovec iov[2];
	struct call_msg cm;

	int size, err, fileid;

	cm.cm_size = strlen(file) + 1;
	cm.cm_id = SYS_kldfind;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = __DECONST(char *, file);
	iov[1].iov_len = cm.cm_size;
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(int))
		read(target_fd, &fileid, sizeof(int));
	else 
		fileid = -1;

	return (fileid);
}

int 
kldunloadf(int fileid, int flags)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldunloadf_call_msg kucm;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldunloadf_call_msg);
	cm.cm_id = SYS_kldunloadf;
	kucm.kucm_fileid = fileid;
	kucm.kucm_flags = flags;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kucm;
	iov[1].iov_len = cm.cm_size;
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}

	return (0);
}

int
modstat(int modid, struct module_stat *stat)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldid_msg kim;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldid_msg);
	cm.cm_id = SYS_modstat;
	kim.kim_fileid = modid;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kim;
	iov[1].iov_len = sizeof(struct kldid_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(struct module_stat))
		read(target_fd, stat, sizeof(struct module_stat));

	return (nextfileid);
}

int
modnext(int modid)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldid_msg kim;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldid_msg);
	cm.cm_id = SYS_modnext;
	kim.kim_fileid = modid;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kim;
	iov[1].iov_len = sizeof(struct kldid_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(int))
		read(target_fd, &nextfileid, sizeof(int));

	return (nextfileid);
}

int
modfnext(int modid)
{
	struct iovec iov[2];
	struct call_msg cm;
	struct kldid_msg kim;
	int size, err, nextfileid;

	cm.cm_size = sizeof(struct kldid_msg);
	cm.cm_id = SYS_modfnext;
	kim.kim_fileid = modid;
	nextfileid = 0;

	iov[0].iov_base = &cm;
	iov[0].iov_len = sizeof(struct call_msg);
	iov[1].iov_base = &kim;
	iov[1].iov_len = sizeof(struct kldid_msg);
	
	err = writev(target_fd, iov, 2);
	total_bytes_written += err;
	if ((err = handle_return_msg(target_fd, &size)) != 0) {
		errno = err;
		return (-1);
	}
	if (size == sizeof(int))
		read(target_fd, &nextfileid, sizeof(int));

	return (nextfileid);
}
