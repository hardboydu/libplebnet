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
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_tap.h>
#undef _KERNEL
#undef gets
#undef pause
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>


ssize_t     read(int d, void *buf, size_t nbytes);
extern void perror(const char *string);


struct pnv_softc {
	struct ifnet *ifp;
	int fd;
	uint8_t addr[6];
	struct mtx lock;
};

static int pnv_setup_interface(struct pnv_softc *sc);

int
pn_veth_attach(void)
{
	struct pnv_softc *sc;
	int fd;

	sc = malloc(sizeof(struct pnv_softc), M_DEVBUF, M_WAITOK);
	fd = open("/dev/tap0", O_RDWR);
	if (fd < 0) {
		perror("tap open failed");
		return (ENXIO);
	}

	ioctl(fd, SIOCGIFADDR, &sc->addr);
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

static void *
pnv_decap(void *arg)
{
	struct pnv_softc *sc = arg;
	struct ifnet *ifp = sc->ifp;
	struct mbuf *m;
	caddr_t data;
	int size;

	while (1) {
		m = m_getjcl(M_WAITOK, MT_DATA,
		    M_PKTHDR, MCLBYTES);
		data = mtod(m, caddr_t);

		size = read(sc->fd, data, MCLBYTES);
		m->m_pkthdr.len = m->m_len = size;
		m->m_pkthdr.rcvif = ifp;
		ifp->if_input(ifp, m);
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

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			pnv_init(sc);
		else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			pnv_stop(sc);
		break;
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
