/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001, 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by NAI Labs,
 * the Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Developed by the TrustedBSD Project.
 * Generic mandatory access module that does nothing.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/acl.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <fs/devfs/devfs.h>

#include <net/bpfdesc.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <vm/vm.h>

#include <sys/mac_policy.h>

SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, test, CTLFLAG_RW, 0,
    "TrustedBSD mac_test policy controls");

static int	mac_test_enabled = 0;
SYSCTL_INT(_security_mac_test, OID_AUTO, enabled, CTLFLAG_RW,
    &mac_test_enabled, 0, "Enforce test policy");

#define	BPFMAGIC	0xfe1ad1b6
#define	DEVFSMAGIC	0x9ee79c32
#define	IFNETMAGIC	0xc218b120
#define	IPQMAGIC	0x206188ef
#define	MBUFMAGIC	0xbbefa5bb
#define	MOUNTMAGIC	0xc7c46e47
#define	SOCKETMAGIC	0x9199c6cd
#define	PIPEMAGIC	0xdc6c9919
#define	CREDMAGIC	0x9a5a4987
#define	TEMPMAGIC	0x70336678
#define	VNODEMAGIC	0x1a67a45c
#define	EXMAGIC		0x849ba1fd

#define	SLOT(x)	LABEL_TO_SLOT((x), test_slot).l_long
static int	test_slot;
SYSCTL_INT(_security_mac_test, OID_AUTO, slot, CTLFLAG_RD,
    &test_slot, 0, "Slot allocated by framework");

static int	init_count_bpfdesc;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_bpfdesc, CTLFLAG_RD,
    &init_count_bpfdesc, 0, "bpfdesc init calls");
static int	init_count_cred;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_cred, CTLFLAG_RD,
    &init_count_cred, 0, "cred init calls");
static int	init_count_devfsdirent;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_devfsdirent, CTLFLAG_RD,
    &init_count_devfsdirent, 0, "devfsdirent init calls");
static int	init_count_ifnet;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_ifnet, CTLFLAG_RD,
    &init_count_ifnet, 0, "ifnet init calls");
static int	init_count_ipq;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_ipq, CTLFLAG_RD,
    &init_count_ipq, 0, "ipq init calls");
static int	init_count_mbuf;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_mbuf, CTLFLAG_RD,
    &init_count_mbuf, 0, "mbuf init calls");
static int	init_count_mount;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_mount, CTLFLAG_RD,
    &init_count_mount, 0, "mount init calls");
static int	init_count_socket;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_socket, CTLFLAG_RD,
    &init_count_socket, 0, "socket init calls");
static int	init_count_pipe;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_pipe, CTLFLAG_RD,
    &init_count_pipe, 0, "pipe init calls");
static int	init_count_temp;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_temp, CTLFLAG_RD,
    &init_count_temp, 0, "temp init calls");
static int	init_count_vnode;
SYSCTL_INT(_security_mac_test, OID_AUTO, init_count_vnode, CTLFLAG_RD,
    &init_count_vnode, 0, "vnode init calls");

static int	destroy_count_bpfdesc;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_bpfdesc, CTLFLAG_RD,
    &destroy_count_bpfdesc, 0, "bpfdesc destroy calls");
static int	destroy_count_cred;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_cred, CTLFLAG_RD,
    &destroy_count_cred, 0, "cred destroy calls");
static int	destroy_count_devfsdirent;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_devfsdirent, CTLFLAG_RD,
    &destroy_count_devfsdirent, 0, "devfsdirent destroy calls");
static int	destroy_count_ifnet;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_ifnet, CTLFLAG_RD,
    &destroy_count_ifnet, 0, "ifnet destroy calls");
static int	destroy_count_ipq;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_ipq, CTLFLAG_RD,
    &destroy_count_ipq, 0, "ipq destroy calls");
static int      destroy_count_mbuf;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_mbuf, CTLFLAG_RD,
    &destroy_count_mbuf, 0, "mbuf destroy calls");
static int      destroy_count_mount;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_mount, CTLFLAG_RD,
    &destroy_count_mount, 0, "mount destroy calls");
static int      destroy_count_socket;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_socket, CTLFLAG_RD,
    &destroy_count_socket, 0, "socket destroy calls");
static int      destroy_count_pipe;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_pipe, CTLFLAG_RD,
    &destroy_count_pipe, 0, "pipe destroy calls");
static int      destroy_count_temp;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_temp, CTLFLAG_RD,
    &destroy_count_temp, 0, "temp destroy calls");
static int      destroy_count_vnode;
SYSCTL_INT(_security_mac_test, OID_AUTO, destroy_count_vnode, CTLFLAG_RD,
    &destroy_count_vnode, 0, "vnode destroy calls");

static int externalize_count;
SYSCTL_INT(_security_mac_test, OID_AUTO, externalize_count, CTLFLAG_RD,
    &externalize_count, 0, "Subject/object externalize calls");
static int internalize_count;
SYSCTL_INT(_security_mac_test, OID_AUTO, internalize_count, CTLFLAG_RD,
    &internalize_count, 0, "Subject/object internalize calls");

/*
 * Policy module operations.
 */
static void
mac_test_destroy(struct mac_policy_conf *conf)
{

}

static void
mac_test_init(struct mac_policy_conf *conf)
{

}

/*
 * Label operations.
 */
static void
mac_test_init_bpfdesc(struct bpf_d *bpf_d, struct label *label)
{

	SLOT(label) = BPFMAGIC;
	atomic_add_int(&init_count_bpfdesc, 1);
}

static void
mac_test_init_cred(struct ucred *ucred, struct label *label)
{

	SLOT(label) = CREDMAGIC;
	atomic_add_int(&init_count_cred, 1);
}

static void
mac_test_init_devfsdirent(struct devfs_dirent *devfs_dirent,
    struct label *label)
{

	SLOT(label) = DEVFSMAGIC;
	atomic_add_int(&init_count_devfsdirent, 1);
}

static void
mac_test_init_ifnet(struct ifnet *ifnet, struct label *label)
{

	SLOT(label) = IFNETMAGIC;
	atomic_add_int(&init_count_ifnet, 1);
}

static void
mac_test_init_ipq(struct ipq *ipq, struct label *label)
{

	SLOT(label) = IPQMAGIC;
	atomic_add_int(&init_count_ipq, 1);
}

static int
mac_test_init_mbuf(struct mbuf *mbuf, int how, struct label *label)
{

	SLOT(label) = MBUFMAGIC;
	atomic_add_int(&init_count_mbuf, 1);
	return (0);
}

static void
mac_test_init_mount(struct mount *mount, struct label *mntlabel,
    struct label *fslabel)
{

	SLOT(mntlabel) = MOUNTMAGIC;
	SLOT(fslabel) = MOUNTMAGIC;
	atomic_add_int(&init_count_mount, 1);
}

static void
mac_test_init_socket(struct socket *socket, struct label *label,
    struct label *peerlabel)
{

	SLOT(label) = SOCKETMAGIC;
	SLOT(peerlabel) = SOCKETMAGIC;
	atomic_add_int(&init_count_socket, 1);
}

static void
mac_test_init_pipe(struct pipe *pipe, struct label *label)
{

	SLOT(label) = PIPEMAGIC;
	atomic_add_int(&init_count_pipe, 1);
}

static void
mac_test_init_temp(struct label *label)
{

	SLOT(label) = TEMPMAGIC;
	atomic_add_int(&init_count_temp, 1);
}

static void
mac_test_init_vnode(struct vnode *vp, struct label *label)
{

	SLOT(label) = VNODEMAGIC;
	atomic_add_int(&init_count_vnode, 1);
}

static void
mac_test_destroy_bpfdesc(struct bpf_d *bpf_d, struct label *label)
{

	if (SLOT(label) == BPFMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_bpfdesc, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_bpfdesc: dup destroy");
	} else {
		Debugger("mac_test_destroy_bpfdesc: corrupted label");
	}
}

static void
mac_test_destroy_cred(struct ucred *ucred, struct label *label)
{

	if (SLOT(label) == CREDMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_cred, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_cred: dup destroy");
	} else {
		Debugger("mac_test_destroy_cred: corrupted label");
	}
}

static void
mac_test_destroy_devfsdirent(struct devfs_dirent *devfs_dirent,
    struct label *label)
{

	if (SLOT(label) == DEVFSMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_devfsdirent, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_devfsdirent: dup destroy");
	} else {
		Debugger("mac_test_destroy_devfsdirent: corrupted label");
	}
}

static void
mac_test_destroy_ifnet(struct ifnet *ifnet, struct label *label)
{

	if (SLOT(label) == IFNETMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_ifnet, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_ifnet: dup destroy");
	} else {
		Debugger("mac_test_destroy_ifnet: corrupted label");
	}
}

static void
mac_test_destroy_ipq(struct ipq *ipq, struct label *label)
{

	if (SLOT(label) == IPQMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_ipq, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_ipq: dup destroy");
	} else {
		Debugger("mac_test_destroy_ipq: corrupted label");
	}
}

static void
mac_test_destroy_mbuf(struct mbuf *mbuf, struct label *label)
{

	if (SLOT(label) == MBUFMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_mbuf, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_mbuf: dup destroy");
	} else {
		Debugger("mac_test_destroy_mbuf: corrupted label");
	}
}

static void
mac_test_destroy_mount(struct mount *mount, struct label *mntlabel,
    struct label *fslabel)
{

	if ((SLOT(mntlabel) == MOUNTMAGIC || SLOT(mntlabel) == 0) &&
	    (SLOT(fslabel) == MOUNTMAGIC || SLOT(fslabel) == 0)) {
		atomic_add_int(&destroy_count_mount, 1);
		SLOT(mntlabel) = EXMAGIC;
		SLOT(fslabel) = EXMAGIC;
	} else if (SLOT(mntlabel) == EXMAGIC || SLOT(fslabel) == EXMAGIC) {
		Debugger("mac_test_destroy_mount: dup destroy");
	} else {
		Debugger("mac_test_destroy_mount: corrupted label");
	}
}

static void
mac_test_destroy_socket(struct socket *socket, struct label *label,
    struct label *peerlabel)
{

	if ((SLOT(label) == SOCKETMAGIC || SLOT(label) == 0) &&
	    (SLOT(peerlabel) == SOCKETMAGIC || SLOT(peerlabel) == 0)) {
		atomic_add_int(&destroy_count_socket, 1);
		SLOT(label) = EXMAGIC;
		SLOT(peerlabel) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC || SLOT(peerlabel) == EXMAGIC) {
		Debugger("mac_test_destroy_socket: dup destroy");
	} else {
		Debugger("mac_test_destroy_socket: corrupted label");
	}
}
static void
mac_test_destroy_pipe(struct pipe *pipe, struct label *label)
{

	if ((SLOT(label) == PIPEMAGIC || SLOT(label) == 0)) {
		atomic_add_int(&destroy_count_pipe, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_pipe: dup destroy");
	} else {
		Debugger("mac_test_destroy_pipe: corrupted label");
	}
}

static void
mac_test_destroy_temp(struct label *label)
{

	if (SLOT(label) == TEMPMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_temp, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_temp: dup destroy");
	} else {
		Debugger("mac_test_destroy_temp: corrupted label");
	}
}

static void
mac_test_destroy_vnode(struct vnode *vp, struct label *label)
{

	if (SLOT(label) == VNODEMAGIC || SLOT(label) == 0) {
		atomic_add_int(&destroy_count_vnode, 1);
		SLOT(label) = EXMAGIC;
	} else if (SLOT(label) == EXMAGIC) {
		Debugger("mac_test_destroy_vnode: dup destroy");
	} else {
		Debugger("mac_test_destroy_vnode: corrupted label");
	}
}

static int
mac_test_externalize(struct label *label, struct mac *extmac)
{

	atomic_add_int(&externalize_count, 1);

	return (0);
}

static int
mac_test_internalize(struct label *label, struct mac *extmac)
{

	atomic_add_int(&internalize_count, 1);

	return (0);
}

/*
 * Labeling event operations: file system objects, and things that look
 * a lot like file system objects.
 */
static void
mac_test_create_devfs_device(dev_t dev, struct devfs_dirent *devfs_dirent,
    struct label *label)
{

}

static void
mac_test_create_devfs_directory(char *dirname, int dirnamelen,
    struct devfs_dirent *devfs_dirent, struct label *label)
{

}

static void
mac_test_create_devfs_vnode(struct devfs_dirent *devfs_dirent,
    struct label *direntlabel, struct vnode *vp, struct label *vnodelabel)
{

}

static void
mac_test_create_vnode(struct ucred *cred, struct vnode *parent,
    struct label *parentlabel, struct vnode *child, struct label *childlabel)
{

}

static void
mac_test_create_mount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct label *fslabel)
{

}

static void
mac_test_create_root_mount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct label *fslabel)
{

}

static void
mac_test_relabel_vnode(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *label)
{

}

static void
mac_test_update_devfsdirent(struct devfs_dirent *devfs_dirent,
    struct vnode *vp)
{

}

static void
mac_test_update_procfsvnode(struct vnode *vp, struct label *vnodelabel,
    struct ucred *cred)
{

}

static int
mac_test_update_vnode_from_externalized(struct vnode *vp,
    struct label *vnodelabel, struct mac *extmac)
{

	return (0);
}

static void
mac_test_update_vnode_from_mount(struct vnode *vp, struct label *vnodelabel,
    struct mount *mp, struct label *fslabel)
{

}

/*
 * Labeling event operations: IPC object.
 */
static void
mac_test_create_mbuf_from_socket(struct socket *so, struct label *socketlabel,
    struct mbuf *m, struct label *mbuflabel)
{

}

static void
mac_test_create_socket(struct ucred *cred, struct socket *socket,
   struct label *socketlabel)
{

}

static void
mac_test_create_pipe(struct ucred *cred, struct pipe *pipe,
   struct label *pipelabel)
{

}

static void
mac_test_create_socket_from_socket(struct socket *oldsocket,
    struct label *oldsocketlabel, struct socket *newsocket,
    struct label *newsocketlabel)
{

}

static void
mac_test_relabel_socket(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct label *newlabel)
{

}

static void
mac_test_relabel_pipe(struct ucred *cred, struct pipe *pipe,
    struct label *pipelabel, struct label *newlabel)
{

}

static void
mac_test_set_socket_peer_from_mbuf(struct mbuf *mbuf, struct label *mbuflabel,
    struct socket *socket, struct label *socketpeerlabel)
{

}

/*
 * Labeling event operations: network objects.
 */
static void
mac_test_set_socket_peer_from_socket(struct socket *oldsocket,
    struct label *oldsocketlabel, struct socket *newsocket,
    struct label *newsocketpeerlabel)
{

}

static void
mac_test_create_bpfdesc(struct ucred *cred, struct bpf_d *bpf_d,
    struct label *bpflabel)
{

}

static void
mac_test_create_datagram_from_ipq(struct ipq *ipq, struct label *ipqlabel,
    struct mbuf *datagram, struct label *datagramlabel)
{

}

static void
mac_test_create_fragment(struct mbuf *datagram, struct label *datagramlabel,
    struct mbuf *fragment, struct label *fragmentlabel)
{

}

static void
mac_test_create_ifnet(struct ifnet *ifnet, struct label *ifnetlabel)
{

}

static void
mac_test_create_ipq(struct mbuf *fragment, struct label *fragmentlabel,
    struct ipq *ipq, struct label *ipqlabel)
{

}

static void
mac_test_create_mbuf_from_mbuf(struct mbuf *oldmbuf,
    struct label *oldmbuflabel, struct mbuf *newmbuf,
    struct label *newmbuflabel)
{

}

static void
mac_test_create_mbuf_linklayer(struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *mbuf, struct label *mbuflabel)
{

}

static void
mac_test_create_mbuf_from_bpfdesc(struct bpf_d *bpf_d, struct label *bpflabel,
    struct mbuf *mbuf, struct label *mbuflabel)
{

}

static void
mac_test_create_mbuf_from_ifnet(struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *m, struct label *mbuflabel)
{

}

static void
mac_test_create_mbuf_multicast_encap(struct mbuf *oldmbuf,
    struct label *oldmbuflabel, struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *newmbuf, struct label *newmbuflabel)
{

}

static void
mac_test_create_mbuf_netlayer(struct mbuf *oldmbuf,
    struct label *oldmbuflabel, struct mbuf *newmbuf,
    struct label *newmbuflabel)
{

}

static int
mac_test_fragment_match(struct mbuf *fragment, struct label *fragmentlabel,
    struct ipq *ipq, struct label *ipqlabel)
{

	return (1);
}

static void
mac_test_relabel_ifnet(struct ucred *cred, struct ifnet *ifnet,
    struct label *ifnetlabel, struct label *newlabel)
{

}

static void
mac_test_update_ipq(struct mbuf *fragment, struct label *fragmentlabel,
    struct ipq *ipq, struct label *ipqlabel)
{

}

/*
 * Labeling event operations: processes.
 */
static void
mac_test_create_cred(struct ucred *cred_parent, struct ucred *cred_child)
{

}

static void
mac_test_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *filelabel)
{

}

static int
mac_test_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *filelabel)
{

	return (0);
}

static void
mac_test_create_proc0(struct ucred *cred)
{

}

static void
mac_test_create_proc1(struct ucred *cred)
{

}

static void
mac_test_relabel_cred(struct ucred *cred, struct label *newlabel)
{

}

/*
 * Access control checks.
 */
static int
mac_test_check_bpfdesc_receive(struct bpf_d *bpf_d, struct label *bpflabel,
    struct ifnet *ifnet, struct label *ifnetlabel)
{

	return (0);
}

static int
mac_test_check_cred_relabel(struct ucred *cred, struct label *newlabel)
{

	return (0);
}

static int
mac_test_check_cred_visible(struct ucred *u1, struct ucred *u2)
{

	return (0);
}

static int
mac_test_check_ifnet_relabel(struct ucred *cred, struct ifnet *ifnet,
    struct label *ifnetlabel, struct label *newlabel)
{

	return (0);
}

static int
mac_test_check_ifnet_transmit(struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *m, struct label *mbuflabel)
{

	return (0);
}

static int
mac_test_check_mount_stat(struct ucred *cred, struct mount *mp,
    struct label *mntlabel)
{

	return (0);
}

static int
mac_test_check_pipe_ioctl(struct ucred *cred, struct pipe *pipe,
    struct label *pipelabel, unsigned long cmd, void /* caddr_t */ *data)
{

	return (0);
}

static int
mac_test_check_pipe_op(struct ucred *cred, struct pipe *pipe,
    struct label *pipelabel, int op)
{

	return (0);
}

static int
mac_test_check_pipe_relabel(struct ucred *cred, struct pipe *pipe,
    struct label *pipelabel, struct label *newlabel)
{

	return (0);
}

static int
mac_test_check_proc_debug(struct ucred *cred, struct proc *proc)
{

	return (0);
}

static int
mac_test_check_proc_sched(struct ucred *cred, struct proc *proc)
{

	return (0);
}

static int
mac_test_check_proc_signal(struct ucred *cred, struct proc *proc)
{

	return (0);
}

static int
mac_test_check_socket_bind(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct sockaddr *sockaddr)
{

	return (0);
}

static int
mac_test_check_socket_connect(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct sockaddr *sockaddr)
{

	return (0);
}

static int
mac_test_check_socket_listen(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct sockaddr *sockaddr)
{

	return (0);
}

static int
mac_test_check_socket_receive(struct socket *socket, struct label *socketlabel,
    struct mbuf *m, struct label *mbuflabel)
{

	return (0);
}

static int
mac_test_check_socket_visible(struct ucred *cred, struct socket *socket,
    struct label *socketlabel)
{

	return (0);
}

static int
mac_test_check_socket_relabel(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct label *newlabel)
{

	return (0);
}

static int
mac_test_check_vnode_access(struct ucred *cred, struct vnode *vp,
    struct label *label, mode_t flags)
{

	return (0);
}

static int
mac_test_check_vnode_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{

	return (0);
}

static int
mac_test_check_vnode_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{

	return (0);
}

static int
mac_test_check_vnode_create(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp, struct vattr *vap)
{

	return (0);
}

static int
mac_test_check_vnode_delete(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{

	return (0);
}

static int
mac_test_check_vnode_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *label, acl_type_t type)
{

	return (0);
}

static int
mac_test_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label)
{

	return (0);
}

static int
mac_test_check_vnode_getacl(struct ucred *cred, struct vnode *vp,
    struct label *label, acl_type_t type)
{

	return (0);
}

static int
mac_test_check_vnode_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{

	return (0);
}

static int
mac_test_check_vnode_lookup(struct ucred *cred, struct vnode *dvp, 
    struct label *dlabel, struct componentname *cnp)
{
 
	return (0);
} 

static int
mac_test_check_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *filelabel, mode_t acc_mode)
{

	return (0);
}

static int
mac_test_check_vnode_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{

	return (0);
}

static int
mac_test_check_vnode_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel)
{

	return (0);
}

static int
mac_test_check_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *newlabel)
{

	return (0);
}

static int
mac_test_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{

	return (0);
}

static int
mac_test_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label, int samedir,
    struct componentname *cnp)
{

	return (0);
}

static int
mac_test_check_vnode_revoke(struct ucred *cred, struct vnode *vp,
    struct label *label)
{

	return (0);
}

static int
mac_test_check_vnode_setacl(struct ucred *cred, struct vnode *vp,
    struct label *label, acl_type_t type, struct acl *acl)
{

	return (0);
}

static int
mac_test_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{

	return (0);
}

static int
mac_test_check_vnode_setflags(struct ucred *cred, struct vnode *vp,
    struct label *label, u_long flags)
{

	return (0);
}

static int
mac_test_check_vnode_setmode(struct ucred *cred, struct vnode *vp,
    struct label *label, mode_t mode)
{

	return (0);
}

static int
mac_test_check_vnode_setowner(struct ucred *cred, struct vnode *vp,
    struct label *label, uid_t uid, gid_t gid)
{

	return (0);
}

static int
mac_test_check_vnode_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *label, struct timespec atime, struct timespec mtime)
{

	return (0);
}

static int
mac_test_check_vnode_stat(struct ucred *cred, struct vnode *vp,
    struct label *label)
{

	return (0);
}

static struct mac_policy_op_entry mac_test_ops[] =
{
	{ MAC_DESTROY,
	    (macop_t)mac_test_destroy },
	{ MAC_INIT,
	    (macop_t)mac_test_init },
	{ MAC_INIT_BPFDESC,
	    (macop_t)mac_test_init_bpfdesc },
	{ MAC_INIT_CRED,
	    (macop_t)mac_test_init_cred },
	{ MAC_INIT_DEVFSDIRENT,
	    (macop_t)mac_test_init_devfsdirent },
	{ MAC_INIT_IFNET,
	    (macop_t)mac_test_init_ifnet },
	{ MAC_INIT_IPQ,
	    (macop_t)mac_test_init_ipq },
	{ MAC_INIT_MBUF,
	    (macop_t)mac_test_init_mbuf },
	{ MAC_INIT_MOUNT,
	    (macop_t)mac_test_init_mount },
	{ MAC_INIT_PIPE,
	    (macop_t)mac_test_init_pipe },
	{ MAC_INIT_SOCKET,
	    (macop_t)mac_test_init_socket },
	{ MAC_INIT_TEMP,
	    (macop_t)mac_test_init_temp },
	{ MAC_INIT_VNODE,
	    (macop_t)mac_test_init_vnode },
	{ MAC_DESTROY_BPFDESC,
	    (macop_t)mac_test_destroy_bpfdesc },
	{ MAC_DESTROY_CRED,
	    (macop_t)mac_test_destroy_cred },
	{ MAC_DESTROY_DEVFSDIRENT,
	    (macop_t)mac_test_destroy_devfsdirent },
	{ MAC_DESTROY_IFNET,
	    (macop_t)mac_test_destroy_ifnet },
	{ MAC_DESTROY_IPQ,
	    (macop_t)mac_test_destroy_ipq },
	{ MAC_DESTROY_MBUF,
	    (macop_t)mac_test_destroy_mbuf },
	{ MAC_DESTROY_MOUNT,
	    (macop_t)mac_test_destroy_mount },
	{ MAC_DESTROY_PIPE,
	    (macop_t)mac_test_destroy_pipe },
	{ MAC_DESTROY_SOCKET,
	    (macop_t)mac_test_destroy_socket },
	{ MAC_DESTROY_TEMP,
	    (macop_t)mac_test_destroy_temp },
	{ MAC_DESTROY_VNODE,
	    (macop_t)mac_test_destroy_vnode },
	{ MAC_EXTERNALIZE,
	    (macop_t)mac_test_externalize },
	{ MAC_INTERNALIZE,
	    (macop_t)mac_test_internalize },
	{ MAC_CREATE_DEVFS_DEVICE,
	    (macop_t)mac_test_create_devfs_device },
	{ MAC_CREATE_DEVFS_DIRECTORY,
	    (macop_t)mac_test_create_devfs_directory },
	{ MAC_CREATE_DEVFS_VNODE,
	    (macop_t)mac_test_create_devfs_vnode },
	{ MAC_CREATE_VNODE,
	    (macop_t)mac_test_create_vnode },
	{ MAC_CREATE_MOUNT,
	    (macop_t)mac_test_create_mount },
	{ MAC_CREATE_ROOT_MOUNT,
	    (macop_t)mac_test_create_root_mount },
	{ MAC_RELABEL_VNODE,
	    (macop_t)mac_test_relabel_vnode },
	{ MAC_UPDATE_DEVFSDIRENT,
	    (macop_t)mac_test_update_devfsdirent },
	{ MAC_UPDATE_PROCFSVNODE,
	    (macop_t)mac_test_update_procfsvnode },
	{ MAC_UPDATE_VNODE_FROM_EXTERNALIZED,
	    (macop_t)mac_test_update_vnode_from_externalized },
	{ MAC_UPDATE_VNODE_FROM_MOUNT,
	    (macop_t)mac_test_update_vnode_from_mount },
	{ MAC_CREATE_MBUF_FROM_SOCKET,
	    (macop_t)mac_test_create_mbuf_from_socket },
	{ MAC_CREATE_PIPE,
	    (macop_t)mac_test_create_pipe },
	{ MAC_CREATE_SOCKET,
	    (macop_t)mac_test_create_socket },
	{ MAC_CREATE_SOCKET_FROM_SOCKET,
	    (macop_t)mac_test_create_socket_from_socket },
	{ MAC_RELABEL_PIPE,
	    (macop_t)mac_test_relabel_pipe },
	{ MAC_RELABEL_SOCKET,
	    (macop_t)mac_test_relabel_socket },
	{ MAC_SET_SOCKET_PEER_FROM_MBUF,
	    (macop_t)mac_test_set_socket_peer_from_mbuf },
	{ MAC_SET_SOCKET_PEER_FROM_SOCKET,
	    (macop_t)mac_test_set_socket_peer_from_socket },
	{ MAC_CREATE_BPFDESC,
	    (macop_t)mac_test_create_bpfdesc },
	{ MAC_CREATE_IFNET,
	    (macop_t)mac_test_create_ifnet },
	{ MAC_CREATE_DATAGRAM_FROM_IPQ,
	    (macop_t)mac_test_create_datagram_from_ipq },
	{ MAC_CREATE_FRAGMENT,
	    (macop_t)mac_test_create_fragment },
	{ MAC_CREATE_IPQ,
	    (macop_t)mac_test_create_ipq },
	{ MAC_CREATE_MBUF_FROM_MBUF,
	    (macop_t)mac_test_create_mbuf_from_mbuf },
	{ MAC_CREATE_MBUF_LINKLAYER,
	    (macop_t)mac_test_create_mbuf_linklayer },
	{ MAC_CREATE_MBUF_FROM_BPFDESC,
	    (macop_t)mac_test_create_mbuf_from_bpfdesc },
	{ MAC_CREATE_MBUF_FROM_IFNET,
	    (macop_t)mac_test_create_mbuf_from_ifnet },
	{ MAC_CREATE_MBUF_MULTICAST_ENCAP,
	    (macop_t)mac_test_create_mbuf_multicast_encap },
	{ MAC_CREATE_MBUF_NETLAYER,
	    (macop_t)mac_test_create_mbuf_netlayer },
	{ MAC_FRAGMENT_MATCH,
	    (macop_t)mac_test_fragment_match },
	{ MAC_RELABEL_IFNET,
	    (macop_t)mac_test_relabel_ifnet },
	{ MAC_UPDATE_IPQ,
	    (macop_t)mac_test_update_ipq },
	{ MAC_CREATE_CRED,
	    (macop_t)mac_test_create_cred },
	{ MAC_EXECVE_TRANSITION,
	    (macop_t)mac_test_execve_transition },
	{ MAC_EXECVE_WILL_TRANSITION,
	    (macop_t)mac_test_execve_will_transition },
	{ MAC_CREATE_PROC0,
	    (macop_t)mac_test_create_proc0 },
	{ MAC_CREATE_PROC1,
	    (macop_t)mac_test_create_proc1 },
	{ MAC_RELABEL_CRED,
	    (macop_t)mac_test_relabel_cred },
	{ MAC_CHECK_BPFDESC_RECEIVE,
	    (macop_t)mac_test_check_bpfdesc_receive },
	{ MAC_CHECK_CRED_RELABEL,
	    (macop_t)mac_test_check_cred_relabel },
	{ MAC_CHECK_CRED_VISIBLE,
	    (macop_t)mac_test_check_cred_visible },
	{ MAC_CHECK_IFNET_RELABEL,
	    (macop_t)mac_test_check_ifnet_relabel },
	{ MAC_CHECK_IFNET_TRANSMIT,
	    (macop_t)mac_test_check_ifnet_transmit },
	{ MAC_CHECK_MOUNT_STAT,
	    (macop_t)mac_test_check_mount_stat },
	{ MAC_CHECK_PIPE_IOCTL,
	    (macop_t)mac_test_check_pipe_ioctl },
	{ MAC_CHECK_PIPE_OP,
	    (macop_t)mac_test_check_pipe_op },
	{ MAC_CHECK_PIPE_RELABEL,
	    (macop_t)mac_test_check_pipe_relabel },
	{ MAC_CHECK_PROC_DEBUG,
	    (macop_t)mac_test_check_proc_debug },
	{ MAC_CHECK_PROC_SCHED,
	    (macop_t)mac_test_check_proc_sched },
	{ MAC_CHECK_PROC_SIGNAL,
	    (macop_t)mac_test_check_proc_signal },
	{ MAC_CHECK_SOCKET_BIND,
	    (macop_t)mac_test_check_socket_bind },
	{ MAC_CHECK_SOCKET_CONNECT,
	    (macop_t)mac_test_check_socket_connect },
	{ MAC_CHECK_SOCKET_LISTEN,
	    (macop_t)mac_test_check_socket_listen },
	{ MAC_CHECK_SOCKET_RECEIVE,
	    (macop_t)mac_test_check_socket_receive },
	{ MAC_CHECK_SOCKET_RELABEL,
	    (macop_t)mac_test_check_socket_relabel },
	{ MAC_CHECK_SOCKET_VISIBLE,
	    (macop_t)mac_test_check_socket_visible },
	{ MAC_CHECK_VNODE_ACCESS,
	    (macop_t)mac_test_check_vnode_access },
	{ MAC_CHECK_VNODE_CHDIR,
	    (macop_t)mac_test_check_vnode_chdir },
	{ MAC_CHECK_VNODE_CHROOT,
	    (macop_t)mac_test_check_vnode_chroot },
	{ MAC_CHECK_VNODE_CREATE,
	    (macop_t)mac_test_check_vnode_create },
	{ MAC_CHECK_VNODE_DELETE,
	    (macop_t)mac_test_check_vnode_delete },
	{ MAC_CHECK_VNODE_DELETEACL,
	    (macop_t)mac_test_check_vnode_deleteacl },
	{ MAC_CHECK_VNODE_EXEC,
	    (macop_t)mac_test_check_vnode_exec },
	{ MAC_CHECK_VNODE_GETACL,
	    (macop_t)mac_test_check_vnode_getacl },
	{ MAC_CHECK_VNODE_GETEXTATTR,
	    (macop_t)mac_test_check_vnode_getextattr },
	{ MAC_CHECK_VNODE_LOOKUP,
	    (macop_t)mac_test_check_vnode_lookup },
	{ MAC_CHECK_VNODE_OPEN,
	    (macop_t)mac_test_check_vnode_open },
	{ MAC_CHECK_VNODE_READDIR,
	    (macop_t)mac_test_check_vnode_readdir },
	{ MAC_CHECK_VNODE_READLINK,
	    (macop_t)mac_test_check_vnode_readlink },
	{ MAC_CHECK_VNODE_RELABEL,
	    (macop_t)mac_test_check_vnode_relabel },
	{ MAC_CHECK_VNODE_RENAME_FROM,
	    (macop_t)mac_test_check_vnode_rename_from },
	{ MAC_CHECK_VNODE_RENAME_TO,
	    (macop_t)mac_test_check_vnode_rename_to },
	{ MAC_CHECK_VNODE_REVOKE,
	    (macop_t)mac_test_check_vnode_revoke },
	{ MAC_CHECK_VNODE_SETACL,
	    (macop_t)mac_test_check_vnode_setacl },
	{ MAC_CHECK_VNODE_SETEXTATTR,
	    (macop_t)mac_test_check_vnode_setextattr },
	{ MAC_CHECK_VNODE_SETFLAGS,
	    (macop_t)mac_test_check_vnode_setflags },
	{ MAC_CHECK_VNODE_SETMODE,
	    (macop_t)mac_test_check_vnode_setmode },
	{ MAC_CHECK_VNODE_SETOWNER,
	    (macop_t)mac_test_check_vnode_setowner },
	{ MAC_CHECK_VNODE_SETUTIMES,
	    (macop_t)mac_test_check_vnode_setutimes },
	{ MAC_CHECK_VNODE_STAT,
	    (macop_t)mac_test_check_vnode_stat },
	{ MAC_OP_LAST, NULL }
};

MAC_POLICY_SET(mac_test_ops, trustedbsd_mac_test, "TrustedBSD MAC/Test",
    MPC_LOADTIME_FLAG_UNLOADOK, &test_slot);
