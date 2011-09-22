/*-
 * Copyright (c) 2010 Kip Macy
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

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/kernel.h>


#undef _KERNEL
#include <errno.h>
#define _KERNEL

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_tap.h>
#include <net/if_dl.h>
#undef _KERNEL
#undef gets
#undef pause
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <pthread.h>

extern ssize_t	read(int d, void *buf, size_t nbytes);
extern void	perror(const char *string);
extern uid_t	geteuid(void);
extern char *	getenv(const char *name);
extern int	close(int d);


struct pnv_softc {
	struct ifnet *ifp;
	int fd;
	uid_t euid;
	uint8_t addr[6];
	struct mtx lock;
};

static int veth_attach(void);

static int
veth_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		return (veth_attach());
		break;

	case MOD_UNLOAD:
		printf("veth module unload - not possible for this module type\n");
		return (EINVAL);

	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t veth_mod = {
	"if_veth",
	veth_modevent,
	0
};

DECLARE_MODULE(if_veth, veth_mod, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY);


static int bpfbufsize = 256*1024;

static int pnv_setup_interface(struct pnv_softc *sc);

static int
veth_attach(void)
{
	struct pnv_softc *sc;
	struct ifreq ifr;
	int fd, error, val;
	char *ifname; /* get from environment */
	char *fdev = "/dev/ubpf";

	ifname = getenv("BPFIF");

	if (ifname == NULL || strlen(ifname) < 3) {
		printf("BPFIF needs to be set to determine interface to use %s\n", ifname);
		return (ENXIO);
	}
	sc = malloc(sizeof(struct pnv_softc), M_DEVBUF, M_WAITOK);
	sc->euid = geteuid();
	if (sc->euid == 0)
		fdev = "/dev/bpf";

	fd = open(fdev, O_RDWR);
	if (fd < 0) {
		perror("ubpf open failed");
		return (ENXIO);
	}
	bzero(&ifr, sizeof(ifr));
	memcpy(&ifr.ifr_name, ifname, strlen(ifname));
	val = bpfbufsize;
	if ((error = ioctl(fd, BIOCSBLEN, &val))) {
		perror("BIOCSBLEN:");
		return (ENXIO);
	}
	if ((error = ioctl(fd, BIOCSETIF, &ifr))) {
		perror("BIOCSETIF:");
		return (ENXIO);
	}
	bzero(&ifr.ifr_name, strlen(ifname));
	if ((error = ioctl(fd, BIOCGETIF, &ifr))) {
		perror("BIOCSETIF:");
		return (ENXIO);
	}
	if ((error = ioctl(fd, SIOCGIFADDR, &ifr))) {
		perror("SIOCGIFADDR:");
		return (ENXIO);
	}
	memcpy(sc->addr, &ifr.ifr_addr.sa_data[0], ETHER_ADDR_LEN);
	val = 1;
	if ((error = ioctl(fd, BIOCIMMEDIATE, &val))) {
		perror("BIOCIMMEDIATE:");
		return (ENXIO);
	}
	if ((error = ioctl(fd, BIOCFEEDBACK, &val))) {
		perror("BIOCFEEDBACK:");
		return (ENXIO);
	}
	sc->fd = fd;
	return (pnv_setup_interface(sc));
}

static void
pnv_start(struct ifnet *ifp)
{
	struct mbuf *m_head, *m;
	struct iovec iov[4];
	struct pnv_softc *sc = ifp->if_softc;
	int i;

	while (!IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {
		IFQ_DRV_DEQUEUE(&ifp->if_snd, m_head);
		if (m_head == NULL)
			break;

		/*
		 * Encapsulation
		 */
		for (i = 0, m = m_head; m != NULL && i < 4; m = m->m_next, i++) {
			iov[i].iov_base = mtod(m, caddr_t);
			iov[i].iov_len = m->m_len;
		}
		writev(sc->fd, iov, i);
		
		m_free(m_head);
	}
}

static void
pnv_free(void *arg1, void *arg2)
{

	free(arg1, M_DEVBUF);
}


static void *
pnv_decap(void *arg)
{
	struct pnv_softc *sc = arg;
	caddr_t data;
	u_int *refcnt;
	struct mbuf *m, *tail, *head;
	struct ifnet *ifp;
	struct bpf_xhdr *xhdr;
	int size;

	ifp = sc->ifp;
	while (1) {
		tail = head = NULL;
		refcnt = malloc(bpfbufsize + sizeof(u_int), M_DEVBUF, 0);
		data = (caddr_t)(refcnt + 1);
		size = read(sc->fd, data, bpfbufsize);
		xhdr = (struct bpf_xhdr *)data;
		if (xhdr->bh_datalen > size) {
			free(data, M_DEVBUF);
			continue;
		}
		*refcnt = 0;
		while (size > 0 && size >= xhdr->bh_datalen + xhdr->bh_hdrlen) {
			data = ((caddr_t)xhdr) + xhdr->bh_hdrlen;
			m = m_gethdr(M_NOWAIT, MT_DATA);
			if (m == NULL) 
				break;
			size -= (xhdr->bh_datalen + xhdr->bh_hdrlen);
			m->m_data = data;
			m->m_pkthdr.len = m->m_len = 
				xhdr->bh_caplen + xhdr->bh_hdrlen;
			m->m_pkthdr.rcvif = ifp;
			m->m_flags |= M_EXT;
			m->m_ext.ext_buf = (void *)refcnt; /* start of buffer */
			m->m_ext.ext_free = pnv_free;
			m->m_ext.ext_arg1 = refcnt;
			m->m_ext.ext_size = bpfbufsize;
			m->m_ext.ref_cnt = refcnt;
			m->m_ext.ext_type = EXT_EXTREF;
			(*refcnt)++;

			if (tail)
				tail->m_nextpkt = m;
			else
				head = tail = m;

			xhdr = (struct bpf_xhdr *)(data + xhdr->bh_datalen);
		}
		while (head != NULL) {
			m = head;
			head = head->m_nextpkt;
			m->m_nextpkt = NULL;
			ifp->if_input(ifp, m);
		}
	}
	
	return (NULL);
}

static void
pnv_init(void *arg)
{
	struct pnv_softc *sc = arg;
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}

static void
pnv_stop(struct pnv_softc *sc)
{
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
}

static int
pnv_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int error = 0;
	struct pnv_softc *sc = ifp->if_softc;
	struct ifreq *ifr;
	struct sockaddr_in *sin;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			pnv_init(sc);
		else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			pnv_stop(sc);
		break;
	case SIOCSIFADDR:
		ifr = (struct ifreq *)data;
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		/* set IP on bpf */
	if (sc->euid != 0 && (error = ioctl(sc->fd, BIOCSADDR_INET, sin))) {
		perror("BIOCSADDR_INET:");
		return (ENXIO);
	}
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}

static int
pnv_setup_interface(struct pnv_softc *sc)
{
	struct ifnet *ifp;
	pthread_t ithread;

	ifp = sc->ifp = if_alloc(IFT_ETHER);

	ifp->if_init =  pnv_init;
	ifp->if_softc = sc;
	if_initname(ifp, "veth", 0);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = pnv_ioctl;
	ifp->if_start = pnv_start;
	IFQ_SET_MAXLEN(&ifp->if_snd, 50);
	ifp->if_snd.ifq_drv_maxlen = 50;
	IFQ_SET_READY(&ifp->if_snd);

	ether_ifattach(ifp, sc->addr);
	ifp->if_capabilities = ifp->if_capenable = 0;

	pthread_create(&ithread, NULL, pnv_decap, sc);
	return (0);
}
