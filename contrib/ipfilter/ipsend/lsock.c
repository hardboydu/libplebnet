/*
 * lsock.c (C) 1995 Darren Reed
 *
 * The author provides this program as-is, with no gaurantee for its
 * suitability for any specific purpose.  The author takes no responsibility
 * for the misuse/abuse of this program and provides it for the sole purpose
 * of testing packet filter policies.  This file maybe distributed freely
 * providing it is not modified and that this notice remains in tact.
 */
#if !defined(lint) && defined(LIBC_SCCS)
static	char	sccsid[] = "@(#)lsock.c	1.2 1/11/96 (C)1995 Darren Reed";
#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/dir.h>
#define	__KERNEL__
#if LINUX >= 0200
# undef UINT_MAX
# undef INT_MAX
# undef ULONG_MAX
# undef LONG_MAX
# include <linux/notifier.h>
#endif
#include <linux/fs.h>
#if LINUX >= 0200
#include "linux/netdevice.h"
#include "net/sock.h"
#endif
#undef	__KERNEL__
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <nlist.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#if LINUX < 0103
#include <net/inet/sock.h>
#endif
#include "ip_compat.h"
#include "tcpip.h"

int	nproc;
struct	task_struct	*proc;

#ifndef	KMEM
# ifdef	_PATH_KMEM
#  define	KMEM	_PATH_KMEM
# endif
#endif
#ifndef	KMEM
# define	KMEM	"/dev/kmem"
#endif
#ifndef	KERNEL
# define	KERNEL	"/System.map"
#endif

int	kmemcpy(buf, pos, n)
char	*buf;
void	*pos;
int	n;
{
	static	int	kfd = -1;

	if (kfd == -1)
		kfd = open(KMEM, O_RDONLY);

	if (lseek(kfd, (off_t)pos, SEEK_SET) == -1)
	    {
		perror("lseek");
		return -1;
	    }
	if (read(kfd, buf, n) == -1)
	    {
		perror("read");
		return -1;
	    }
	return n;
}

struct	nlist	names[3] = {
	{ "_task" },
	{ "_nr_tasks" },
	{ NULL }
	};

struct	task_struct	*getproc()
{
	struct	task_struct	*p, **pp;
	void	*v;
	pid_t	pid = getpid();
	int	siz, n;

	n = nlist(KERNEL, names);
	if (n != 0)
	    {
		fprintf(stderr, "nlist(%#x) == %d\n", names, n);
		return NULL;
	    }
	if (kmemcpy((char *)&nproc, (void *)names[1].n_value,
		    sizeof(nproc)) == -1)
	    {
		fprintf(stderr, "read nproc (%#x)\n", names[1].n_value);
		return NULL;
	    }
	siz = nproc * sizeof(struct task_struct *);
	if (kmemcpy((char *)&v, (void *)names[0].n_value, sizeof(v)) == -1)
	    {
		fprintf(stderr, "read(%#x,%#x,%d) proc\n",
			names[0].n_value, &v, sizeof(v));
		return NULL;
	    }
	pp = (struct task_struct **)malloc(siz);
	if (kmemcpy((char *)pp, (void *)v, siz) == -1)
	    {
		fprintf(stderr, "read(%#x,%#x,%d) proc\n",
			v, pp, siz);
		return NULL;
	    }
	proc = (struct task_struct *)malloc(siz);
	for (n = 0; n < NR_TASKS; n++)
	    {
		if (kmemcpy((char *)(proc + n), (void *)pp[n],
			    sizeof(*proc)) == -1)
		    {
			fprintf(stderr, "read(%#x,%#x,%d) proc\n",
				pp[n], proc + n, sizeof(*proc));
			return NULL;
		    }
	    }

	p = proc;

	for (n = NR_TASKS; n; n--, p++)
		if (p->pid == pid)
			break;
	if (!n)
		return NULL;

	return p;
}


struct	sock	*find_tcp(fd, ti)
int	fd;
struct	tcpiphdr *ti;
{
	struct	sock	*s;
	struct	inode	*i;
	struct	files_struct	*fs;
	struct	task_struct	*p;
	struct	file	*f, **o;

	if (!(p = getproc()))
		return NULL;

	fs = p->files;
	o = (struct file **)calloc(1, sizeof(*o) * (fs->count + 1));
	if (kmemcpy((char *)o, (void *)fs->fd,
		    (fs->count + 1) * sizeof(*o)) == -1)
	    {
		fprintf(stderr, "read(%#x,%#x,%d) - fd - failed\n",
			fs->fd, o, sizeof(*o));
		return NULL;
	    }
	f = (struct file *)calloc(1, sizeof(*f));
	if (kmemcpy((char *)f, (void *)o[fd], sizeof(*f)) == -1)
	    {
		fprintf(stderr, "read(%#x,%#x,%d) - o[fd] - failed\n",
			o[fd], f, sizeof(*f));
		return NULL;
	    }

	i = (struct inode *)calloc(1, sizeof(*i));
	if (kmemcpy((char *)i, (void *)f->f_inode, sizeof(*i)) == -1)
	    {
		fprintf(stderr, "read(%#x,%#x,%d) - f_inode - failed\n",
			f->f_inode, i, sizeof(*i));
		return NULL;
	    }
	return i->u.socket_i.data;
}

int	do_socket(dev, mtu, ti, gwip, flags)
char	*dev;
int	mtu;
struct	tcpiphdr *ti;
struct	in_addr	gwip;
int	flags;
{
	struct	sockaddr_in	rsin, lsin;
	struct	sock	*s, sk;
	int	fd, nfd, len;

	printf("Dest. Port: %d\n", ti->ti_dport);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
	    {
		perror("socket");
		return -1;
	    }

	if (fcntl(fd, F_SETFL, FNDELAY) == -1)
	    {
		perror("fcntl");
		return -1;
	    }

	bzero((char *)&lsin, sizeof(lsin));
	lsin.sin_family = AF_INET;
	bcopy((char *)&ti->ti_src, (char *)&lsin.sin_addr,
	      sizeof(struct in_addr));
	if (bind(fd, (struct sockaddr *)&lsin, sizeof(lsin)) == -1)
	    {
		perror("bind");
		return -1;
	    }
	len = sizeof(lsin);
	(void) getsockname(fd, (struct sockaddr *)&lsin, &len);
	ti->ti_sport = lsin.sin_port;
	printf("sport %d\n", ntohs(lsin.sin_port));
	nfd = initdevice(dev, ntohs(lsin.sin_port));

	if (!(s = find_tcp(fd, ti)))
		return -1;

	bzero((char *)&rsin, sizeof(rsin));
	rsin.sin_family = AF_INET;
	bcopy((char *)&ti->ti_dst, (char *)&rsin.sin_addr,
	      sizeof(struct in_addr));
	rsin.sin_port = ti->ti_dport;
	if (connect(fd, (struct sockaddr *)&rsin, sizeof(rsin)) == -1 &&
	    errno != EINPROGRESS)
	    {
		perror("connect");
		return -1;
	    }
	kmemcpy((char*)&sk, (void *)s, sizeof(sk));
	ti->ti_win = sk.window;
	ti->ti_seq = sk.sent_seq - 1;
	ti->ti_ack = sk.rcv_ack_seq;

	if (send_tcp(nfd, mtu, ti, gwip, TH_SYN) == -1)
		return -1;
	(void)write(fd, "Hello World\n", 12);
	sleep(2);
	close(fd);
	return 0;
}
