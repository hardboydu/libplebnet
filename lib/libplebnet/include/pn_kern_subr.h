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

#ifndef	_PLEBNET_PN_KERN_SUBR_H_
#define	_PLEBNET_PN_KERN_SUBR_H_

struct pollfd;

int kern_ioctl(struct thread *td, int fd, u_long com, caddr_t data);
int kern_socket(struct thread *td, int domain, int type, int protocol);
int sendit(struct thread *td, int s, struct msghdr *mp, int flags);
#define DUP_FIXED	0x1	/* Force fixed allocation */
#define DUP_FCNTL	0x2	/* fcntl()-style errors */
int do_dup(struct thread *td, int flags, int old, int new,
    register_t *retval);
int kern_poll(struct thread *td, struct pollfd *fds, u_int	nfds,
	      int	timeout);
int kern_listen(struct thread *td, int s, int backlog);
int sys_fcntl(struct thread *td, int fd, int cmd, intptr_t arg);
int kern_shutdown(struct thread *td, int s, int how);
int kern_kldload(struct thread *td, const char *, int *fileid);
int kern_kldfind(struct thread *td, const char *);
int kern_kldunload(struct thread *td, int fileid, int flags);
int kern_kldnext(struct thread *td, int fileid);
int kern_kldstat(struct thread *td, int fileid, struct kld_file_stat *);
int sys_kldnext(struct thread *td, int *fileid);
int sys_kldfirstmod(struct thread *td, int *fileid);
int sys_modnext(struct thread *td, int *modid);
int sys_modfnext(struct thread *td, int *modid);
int kern_modstat(int modid, struct module_stat *stat);


struct file {
	void		*f_data;	/* file descriptor specific data */
	struct fileops	*f_ops;		/* File operations */
	struct ucred	*f_cred;	/* associated credentials. */
	void 	*f_vnode;	/* NULL or applicable vnode */
	short		f_type;		/* descriptor type */
	short		f_vnread_flags; /* (f) Sleep lock for f_offset */
	volatile u_int	f_flag;		/* see fcntl.h */
	volatile u_int 	f_count;	/* reference count */
	/*
	 *  DTYPE_VNODE specific fields.
	 */
	int		f_seqcount;	/* Count of sequential accesses. */
	off_t		f_nextoff;	/* next expected read/write offset. */
	struct cdev_privdata *f_cdevpriv; /* (d) Private data for the cdev. */
	/*
	 *  DFLAG_SEEKABLE specific fields
	 */
	off_t		f_offset;
	/*
	 * Mandatory Access control information.
	 */
	void		*f_label;	/* Place-holder for MAC label. */
};

int _fdrop(struct file *fp, struct thread *td);
static __inline int
_fnoop(void)
{

	return (0);
}

#define	fhold(fp)							\
	(refcount_acquire(&(fp)->f_count))
#define	fdrop(fp, td)							\
	(refcount_release(&(fp)->f_count) ? _fdrop((fp), (td)) : _fnoop())

int kernel_sysctl(struct thread *td, int *name, u_int namelen, void *old,
		  size_t *oldlenp, void *new, size_t newlen, size_t *retval, int flags);


int userland_sysctl(struct thread *td, int *name, u_int namelen, void *old,
    size_t *oldlenp, int inkernel, void *new, size_t newlen, size_t *retval,
    int flags);

#endif
