/*
 * Copyright (c) 1996 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Absolutely no warranty of function or purpose is made by the author
 *    John S. Dyson.
 * 4. Modifications may be freely made to this file if the above conditions
 *    are met.
 */

/*
 * This file contains a high-performance replacement for the socket-based
 * pipes scheme originally used in FreeBSD/4.4Lite.  It does not support
 * all features of sockets, but does do everything that pipes normally
 * do.
 */

/*
 * This code has two modes of operation, a small write mode and a large
 * write mode.  The small write mode acts like conventional pipes with
 * a kernel buffer.  If the buffer is less than PIPE_MINDIRECT, then the
 * "normal" pipe buffering is done.  If the buffer is between PIPE_MINDIRECT
 * and PIPE_SIZE in size, it is fully mapped and wired into the kernel, and
 * the receiving process can copy it directly from the pages in the sending
 * process.
 *
 * If the sending process receives a signal, it is possible that it will
 * go away, and certainly its address space can change, because control
 * is returned back to the user-mode side.  In that case, the pipe code
 * arranges to copy the buffer supplied by the user process, to a pageable
 * kernel buffer, and the receiving process will grab the data from the
 * pageable kernel buffer.  Since signals don't happen all that often,
 * the copy operation is normally eliminated.
 *
 * The constant PIPE_MINDIRECT is chosen to make sure that buffering will
 * happen for small transfers so that the system will not spend all of
 * its time context switching.
 *
 * In order to limit the resource use of pipes, two sysctls exist:
 *
 * kern.ipc.maxpipekva - This is a hard limit on the amount of pageable
 * address space available to us in pipe_map.  Whenever the amount in use
 * exceeds half of this value, all new pipes will be created with size
 * SMALL_PIPE_SIZE, rather than PIPE_SIZE.  Big pipe creation will be limited
 * as well.  This value is loader tunable only.
 *
 * kern.ipc.maxpipekvawired - This value limits the amount of memory that may
 * be wired in order to facilitate direct copies using page flipping.
 * Whenever this value is exceeded, pipes will fall back to using regular
 * copies.  This value is sysctl controllable at all times.
 *
 * These values are autotuned in subr_param.c.
 *
 * Memory usage may be monitored through the sysctls
 * kern.ipc.pipes, kern.ipc.pipekva and kern.ipc.pipekvawired.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/mutex.h>
#include <sys/ttycom.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/pipe.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/event.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/uma.h>

/*
 * Use this define if you want to disable *fancy* VM things.  Expect an
 * approx 30% decrease in transfer rate.  This could be useful for
 * NetBSD or OpenBSD.
 */
/* #define PIPE_NODIRECT */

/*
 * interfaces to the outside world
 */
static fo_rdwr_t	pipe_read;
static fo_rdwr_t	pipe_write;
static fo_ioctl_t	pipe_ioctl;
static fo_poll_t	pipe_poll;
static fo_kqfilter_t	pipe_kqfilter;
static fo_stat_t	pipe_stat;
static fo_close_t	pipe_close;

static struct fileops pipeops = {
	.fo_read = pipe_read,
	.fo_write = pipe_write,
	.fo_ioctl = pipe_ioctl,
	.fo_poll = pipe_poll,
	.fo_kqfilter = pipe_kqfilter,
	.fo_stat = pipe_stat,
	.fo_close = pipe_close,
	.fo_flags = DFLAG_PASSABLE
};

static void	filt_pipedetach(struct knote *kn);
static int	filt_piperead(struct knote *kn, long hint);
static int	filt_pipewrite(struct knote *kn, long hint);

static struct filterops pipe_rfiltops =
	{ 1, NULL, filt_pipedetach, filt_piperead };
static struct filterops pipe_wfiltops =
	{ 1, NULL, filt_pipedetach, filt_pipewrite };

/*
 * Default pipe buffer size(s), this can be kind-of large now because pipe
 * space is pageable.  The pipe code will try to maintain locality of
 * reference for performance reasons, so small amounts of outstanding I/O
 * will not wipe the cache.
 */
#define MINPIPESIZE (PIPE_SIZE/3)
#define MAXPIPESIZE (2*PIPE_SIZE/3)

/*
 * Limit the number of "big" pipes
 */
#define LIMITBIGPIPES	32
static int nbigpipe;

static int amountpipes;
static int amountpipekva;
static int amountpipekvawired;

SYSCTL_DECL(_kern_ipc);

SYSCTL_INT(_kern_ipc, OID_AUTO, maxpipekva, CTLFLAG_RDTUN,
	   &maxpipekva, 0, "Pipe KVA limit");
SYSCTL_INT(_kern_ipc, OID_AUTO, maxpipekvawired, CTLFLAG_RW,
	   &maxpipekvawired, 0, "Pipe KVA wired limit");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipes, CTLFLAG_RD,
	   &amountpipes, 0, "Current # of pipes");
SYSCTL_INT(_kern_ipc, OID_AUTO, bigpipes, CTLFLAG_RD,
	   &nbigpipe, 0, "Current # of big pipes");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipekva, CTLFLAG_RD,
	   &amountpipekva, 0, "Pipe KVA usage");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipekvawired, CTLFLAG_RD,
	   &amountpipekvawired, 0, "Pipe wired KVA usage");

static void pipeinit(void *dummy __unused);
static void pipeclose(struct pipe *cpipe);
static void pipe_free_kmem(struct pipe *cpipe);
static int pipe_create(struct pipe *pipe);
static __inline int pipelock(struct pipe *cpipe, int catch);
static __inline void pipeunlock(struct pipe *cpipe);
static __inline void pipeselwakeup(struct pipe *cpipe);
#ifndef PIPE_NODIRECT
static int pipe_build_write_buffer(struct pipe *wpipe, struct uio *uio);
static void pipe_destroy_write_buffer(struct pipe *wpipe);
static int pipe_direct_write(struct pipe *wpipe, struct uio *uio);
static void pipe_clone_write_buffer(struct pipe *wpipe);
#endif
static int pipespace(struct pipe *cpipe, int size);

static void	pipe_zone_ctor(void *mem, int size, void *arg);
static void	pipe_zone_dtor(void *mem, int size, void *arg);
static void	pipe_zone_init(void *mem, int size);
static void	pipe_zone_fini(void *mem, int size);

static uma_zone_t pipe_zone;

SYSINIT(vfs, SI_SUB_VFS, SI_ORDER_ANY, pipeinit, NULL);

static void
pipeinit(void *dummy __unused)
{

	pipe_zone = uma_zcreate("PIPE", sizeof(struct pipepair),
	    pipe_zone_ctor, pipe_zone_dtor, pipe_zone_init, pipe_zone_fini,
	    UMA_ALIGN_PTR, 0);
	KASSERT(pipe_zone != NULL, ("pipe_zone not initialized"));
}

static void
pipe_zone_ctor(void *mem, int size, void *arg)
{
	struct pipepair *pp;
	struct pipe *rpipe, *wpipe;

	KASSERT(size == sizeof(*pp), ("pipe_zone_ctor: wrong size"));

	pp = (struct pipepair *)mem;

	/*
	 * We zero both pipe endpoints to make sure all the kmem pointers
	 * are NULL, flag fields are zero'd, etc.  We timestamp both
	 * endpoints with the same time.
	 */
	rpipe = &pp->pp_rpipe;
	bzero(rpipe, sizeof(*rpipe));
	vfs_timestamp(&rpipe->pipe_ctime);
	rpipe->pipe_atime = rpipe->pipe_mtime = rpipe->pipe_ctime;

	wpipe = &pp->pp_wpipe;
	bzero(wpipe, sizeof(*wpipe));
	wpipe->pipe_ctime = rpipe->pipe_ctime;
	wpipe->pipe_atime = wpipe->pipe_mtime = rpipe->pipe_ctime;

	rpipe->pipe_peer = wpipe;
	rpipe->pipe_pair = pp;
	wpipe->pipe_peer = rpipe;
	wpipe->pipe_pair = pp;

	/*
	 * Mark both endpoints as present; they will later get free'd
	 * one at a time.  When both are free'd, then the whole pair
	 * is released.
	 */
	rpipe->pipe_present = 1;
	wpipe->pipe_present = 1;

	/*
	 * Eventually, the MAC Framework may initialize the label
	 * in ctor or init, but for now we do it elswhere to avoid
	 * blocking in ctor or init.
	 */
	pp->pp_label = NULL;

	atomic_add_int(&amountpipes, 2);
}

static void
pipe_zone_dtor(void *mem, int size, void *arg)
{
	struct pipepair *pp;

	KASSERT(size == sizeof(*pp), ("pipe_zone_dtor: wrong size"));

	pp = (struct pipepair *)mem;

	atomic_subtract_int(&amountpipes, 2);
}

static void
pipe_zone_init(void *mem, int size)
{
	struct pipepair *pp;

	KASSERT(size == sizeof(*pp), ("pipe_zone_init: wrong size"));

	pp = (struct pipepair *)mem;

	mtx_init(&pp->pp_mtx, "pipe mutex", NULL, MTX_DEF | MTX_RECURSE);
}

static void
pipe_zone_fini(void *mem, int size)
{
	struct pipepair *pp;

	KASSERT(size == sizeof(*pp), ("pipe_zone_fini: wrong size"));

	pp = (struct pipepair *)mem;

	mtx_destroy(&pp->pp_mtx);
}

/*
 * The pipe system call for the DTYPE_PIPE type of pipes.  If we fail,
 * let the zone pick up the pieces via pipeclose().
 */

/* ARGSUSED */
int
pipe(td, uap)
	struct thread *td;
	struct pipe_args /* {
		int	dummy;
	} */ *uap;
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct file *rf, *wf;
	struct pipepair *pp;
	struct pipe *rpipe, *wpipe;
	int fd, error;

	pp = uma_zalloc(pipe_zone, M_WAITOK);
#ifdef MAC
	/*
	 * struct pipe represents a pipe endpoint.  The MAC label is shared
	 * between the connected endpoints.  As a result mac_init_pipe() and
	 * mac_create_pipe() should only be called on one of the endpoints
	 * after they have been connected.
	 */
	mac_init_pipe(pp);
	mac_create_pipe(td->td_ucred, pp);
#endif
	rpipe = &pp->pp_rpipe;
	wpipe = &pp->pp_wpipe;

	if (pipe_create(rpipe) || pipe_create(wpipe)) {
		pipeclose(rpipe);
		pipeclose(wpipe);
		return (ENFILE);
	}

	rpipe->pipe_state |= PIPE_DIRECTOK;
	wpipe->pipe_state |= PIPE_DIRECTOK;

	error = falloc(td, &rf, &fd);
	if (error) {
		pipeclose(rpipe);
		pipeclose(wpipe);
		return (error);
	}
	/* An extra reference on `rf' has been held for us by falloc(). */
	td->td_retval[0] = fd;

	/*
	 * Warning: once we've gotten past allocation of the fd for the
	 * read-side, we can only drop the read side via fdrop() in order
	 * to avoid races against processes which manage to dup() the read
	 * side while we are blocked trying to allocate the write side.
	 */
	FILE_LOCK(rf);
	rf->f_flag = FREAD | FWRITE;
	rf->f_type = DTYPE_PIPE;
	rf->f_data = rpipe;
	rf->f_ops = &pipeops;
	FILE_UNLOCK(rf);
	error = falloc(td, &wf, &fd);
	if (error) {
		FILEDESC_LOCK(fdp);
		if (fdp->fd_ofiles[td->td_retval[0]] == rf) {
			fdp->fd_ofiles[td->td_retval[0]] = NULL;
			fdunused(fdp, td->td_retval[0]);
			FILEDESC_UNLOCK(fdp);
			fdrop(rf, td);
		} else {
			FILEDESC_UNLOCK(fdp);
		}
		fdrop(rf, td);
		/* rpipe has been closed by fdrop(). */
		pipeclose(wpipe);
		return (error);
	}
	/* An extra reference on `wf' has been held for us by falloc(). */
	FILE_LOCK(wf);
	wf->f_flag = FREAD | FWRITE;
	wf->f_type = DTYPE_PIPE;
	wf->f_data = wpipe;
	wf->f_ops = &pipeops;
	FILE_UNLOCK(wf);
	fdrop(wf, td);
	td->td_retval[1] = fd;
	fdrop(rf, td);

	return (0);
}

/*
 * Allocate kva for pipe circular buffer, the space is pageable
 * This routine will 'realloc' the size of a pipe safely, if it fails
 * it will retain the old buffer.
 * If it fails it will return ENOMEM.
 */
static int
pipespace(cpipe, size)
	struct pipe *cpipe;
	int size;
{
	caddr_t buffer;
	int error;
	static int curfail = 0;
	static struct timeval lastfail;

	KASSERT(!mtx_owned(PIPE_MTX(cpipe)), ("pipespace: pipe mutex locked"));

	size = round_page(size);
	/*
	 * XXX -- minor change needed here for NetBSD/OpenBSD VM systems.
	 */
	buffer = (caddr_t) vm_map_min(pipe_map);

	/*
	 * The map entry is, by default, pageable.
	 * XXX -- minor change needed here for NetBSD/OpenBSD VM systems.
	 */
	error = vm_map_find(pipe_map, NULL, 0,
		(vm_offset_t *) &buffer, size, 1,
		VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error != KERN_SUCCESS) {
		if (ppsratecheck(&lastfail, &curfail, 1))
			printf("kern.ipc.maxpipekva exceeded; see tuning(7)\n");
		return (ENOMEM);
	}

	/* free old resources if we're resizing */
	pipe_free_kmem(cpipe);
	cpipe->pipe_buffer.buffer = buffer;
	cpipe->pipe_buffer.size = size;
	cpipe->pipe_buffer.in = 0;
	cpipe->pipe_buffer.out = 0;
	cpipe->pipe_buffer.cnt = 0;
	atomic_add_int(&amountpipekva, cpipe->pipe_buffer.size);
	return (0);
}

/*
 * lock a pipe for I/O, blocking other access
 */
static __inline int
pipelock(cpipe, catch)
	struct pipe *cpipe;
	int catch;
{
	int error;

	PIPE_LOCK_ASSERT(cpipe, MA_OWNED);
	while (cpipe->pipe_state & PIPE_LOCKFL) {
		cpipe->pipe_state |= PIPE_LWANT;
		error = msleep(cpipe, PIPE_MTX(cpipe),
		    catch ? (PRIBIO | PCATCH) : PRIBIO,
		    "pipelk", 0);
		if (error != 0)
			return (error);
	}
	cpipe->pipe_state |= PIPE_LOCKFL;
	return (0);
}

/*
 * unlock a pipe I/O lock
 */
static __inline void
pipeunlock(cpipe)
	struct pipe *cpipe;
{

	PIPE_LOCK_ASSERT(cpipe, MA_OWNED);
	cpipe->pipe_state &= ~PIPE_LOCKFL;
	if (cpipe->pipe_state & PIPE_LWANT) {
		cpipe->pipe_state &= ~PIPE_LWANT;
		wakeup(cpipe);
	}
}

static __inline void
pipeselwakeup(cpipe)
	struct pipe *cpipe;
{

	if (cpipe->pipe_state & PIPE_SEL) {
		cpipe->pipe_state &= ~PIPE_SEL;
		selwakeuppri(&cpipe->pipe_sel, PSOCK);
	}
	if ((cpipe->pipe_state & PIPE_ASYNC) && cpipe->pipe_sigio)
		pgsigio(&cpipe->pipe_sigio, SIGIO, 0);
	KNOTE(&cpipe->pipe_sel.si_note, 0);
}

/*
 * Initialize and allocate VM and memory for pipe.  The structure
 * will start out zero'd from the ctor, so we just manage the kmem.
 */
static int
pipe_create(pipe)
	struct pipe *pipe;
{
	int error;

	PIPE_LOCK(pipe);
	pipelock(pipe, 0);
	PIPE_UNLOCK(pipe);
	/*
	 * Reduce to 1/4th pipe size if we're over our global max.
	 */
	if (amountpipekva > maxpipekva / 2)
		error = pipespace(pipe, SMALL_PIPE_SIZE);
	else
		error = pipespace(pipe, PIPE_SIZE);
	PIPE_LOCK(pipe);
	pipeunlock(pipe);
	PIPE_UNLOCK(pipe);
	if (error)
		return (error);

	return (0);
}

/* ARGSUSED */
static int
pipe_read(fp, uio, active_cred, flags, td)
	struct file *fp;
	struct uio *uio;
	struct ucred *active_cred;
	struct thread *td;
	int flags;
{
	struct pipe *rpipe = fp->f_data;
	int error;
	int nread = 0;
	u_int size;

	PIPE_LOCK(rpipe);
	++rpipe->pipe_busy;
	error = pipelock(rpipe, 1);
	if (error)
		goto unlocked_error;

#ifdef MAC
	error = mac_check_pipe_read(active_cred, rpipe->pipe_pair);
	if (error)
		goto locked_error;
#endif

	while (uio->uio_resid) {
		/*
		 * normal pipe buffer receive
		 */
		if (rpipe->pipe_buffer.cnt > 0) {
			size = rpipe->pipe_buffer.size - rpipe->pipe_buffer.out;
			if (size > rpipe->pipe_buffer.cnt)
				size = rpipe->pipe_buffer.cnt;
			if (size > (u_int) uio->uio_resid)
				size = (u_int) uio->uio_resid;

			PIPE_UNLOCK(rpipe);
			error = uiomove(
			    &rpipe->pipe_buffer.buffer[rpipe->pipe_buffer.out],
			    size, uio);
			PIPE_LOCK(rpipe);
			if (error)
				break;

			rpipe->pipe_buffer.out += size;
			if (rpipe->pipe_buffer.out >= rpipe->pipe_buffer.size)
				rpipe->pipe_buffer.out = 0;

			rpipe->pipe_buffer.cnt -= size;

			/*
			 * If there is no more to read in the pipe, reset
			 * its pointers to the beginning.  This improves
			 * cache hit stats.
			 */
			if (rpipe->pipe_buffer.cnt == 0) {
				rpipe->pipe_buffer.in = 0;
				rpipe->pipe_buffer.out = 0;
			}
			nread += size;
#ifndef PIPE_NODIRECT
		/*
		 * Direct copy, bypassing a kernel buffer.
		 */
		} else if ((size = rpipe->pipe_map.cnt) &&
			   (rpipe->pipe_state & PIPE_DIRECTW)) {
			caddr_t	va;
			if (size > (u_int) uio->uio_resid)
				size = (u_int) uio->uio_resid;

			va = (caddr_t) rpipe->pipe_map.kva +
			    rpipe->pipe_map.pos;
			PIPE_UNLOCK(rpipe);
			error = uiomove(va, size, uio);
			PIPE_LOCK(rpipe);
			if (error)
				break;
			nread += size;
			rpipe->pipe_map.pos += size;
			rpipe->pipe_map.cnt -= size;
			if (rpipe->pipe_map.cnt == 0) {
				rpipe->pipe_state &= ~PIPE_DIRECTW;
				wakeup(rpipe);
			}
#endif
		} else {
			/*
			 * detect EOF condition
			 * read returns 0 on EOF, no need to set error
			 */
			if (rpipe->pipe_state & PIPE_EOF)
				break;

			/*
			 * If the "write-side" has been blocked, wake it up now.
			 */
			if (rpipe->pipe_state & PIPE_WANTW) {
				rpipe->pipe_state &= ~PIPE_WANTW;
				wakeup(rpipe);
			}

			/*
			 * Break if some data was read.
			 */
			if (nread > 0)
				break;

			/*
			 * Unlock the pipe buffer for our remaining processing.
			 * We will either break out with an error or we will
			 * sleep and relock to loop.
			 */
			pipeunlock(rpipe);

			/*
			 * Handle non-blocking mode operation or
			 * wait for more data.
			 */
			if (fp->f_flag & FNONBLOCK) {
				error = EAGAIN;
			} else {
				rpipe->pipe_state |= PIPE_WANTR;
				if ((error = msleep(rpipe, PIPE_MTX(rpipe),
				    PRIBIO | PCATCH,
				    "piperd", 0)) == 0)
					error = pipelock(rpipe, 1);
			}
			if (error)
				goto unlocked_error;
		}
	}
#ifdef MAC
locked_error:
#endif
	pipeunlock(rpipe);

	/* XXX: should probably do this before getting any locks. */
	if (error == 0)
		vfs_timestamp(&rpipe->pipe_atime);
unlocked_error:
	--rpipe->pipe_busy;

	/*
	 * PIPE_WANT processing only makes sense if pipe_busy is 0.
	 */
	if ((rpipe->pipe_busy == 0) && (rpipe->pipe_state & PIPE_WANT)) {
		rpipe->pipe_state &= ~(PIPE_WANT|PIPE_WANTW);
		wakeup(rpipe);
	} else if (rpipe->pipe_buffer.cnt < MINPIPESIZE) {
		/*
		 * Handle write blocking hysteresis.
		 */
		if (rpipe->pipe_state & PIPE_WANTW) {
			rpipe->pipe_state &= ~PIPE_WANTW;
			wakeup(rpipe);
		}
	}

	if ((rpipe->pipe_buffer.size - rpipe->pipe_buffer.cnt) >= PIPE_BUF)
		pipeselwakeup(rpipe);

	PIPE_UNLOCK(rpipe);
	return (error);
}

#ifndef PIPE_NODIRECT
/*
 * Map the sending processes' buffer into kernel space and wire it.
 * This is similar to a physical write operation.
 */
static int
pipe_build_write_buffer(wpipe, uio)
	struct pipe *wpipe;
	struct uio *uio;
{
	pmap_t pmap;
	u_int size;
	int i, j;
	vm_offset_t addr, endaddr;

	PIPE_LOCK_ASSERT(wpipe, MA_NOTOWNED);

	size = (u_int) uio->uio_iov->iov_len;
	if (size > wpipe->pipe_buffer.size)
		size = wpipe->pipe_buffer.size;

	pmap = vmspace_pmap(curproc->p_vmspace);
	endaddr = round_page((vm_offset_t)uio->uio_iov->iov_base + size);
	addr = trunc_page((vm_offset_t)uio->uio_iov->iov_base);
	for (i = 0; addr < endaddr; addr += PAGE_SIZE, i++) {
		/*
		 * vm_fault_quick() can sleep.  Consequently,
		 * vm_page_lock_queue() and vm_page_unlock_queue()
		 * should not be performed outside of this loop.
		 */
	race:
		if (vm_fault_quick((caddr_t)addr, VM_PROT_READ) < 0) {
			vm_page_lock_queues();
			for (j = 0; j < i; j++)
				vm_page_unhold(wpipe->pipe_map.ms[j]);
			vm_page_unlock_queues();
			return (EFAULT);
		}
		wpipe->pipe_map.ms[i] = pmap_extract_and_hold(pmap, addr,
		    VM_PROT_READ);
		if (wpipe->pipe_map.ms[i] == NULL)
			goto race;
	}

/*
 * set up the control block
 */
	wpipe->pipe_map.npages = i;
	wpipe->pipe_map.pos =
	    ((vm_offset_t) uio->uio_iov->iov_base) & PAGE_MASK;
	wpipe->pipe_map.cnt = size;

/*
 * and map the buffer
 */
	if (wpipe->pipe_map.kva == 0) {
		/*
		 * We need to allocate space for an extra page because the
		 * address range might (will) span pages at times.
		 */
		wpipe->pipe_map.kva = kmem_alloc_nofault(kernel_map,
			wpipe->pipe_buffer.size + PAGE_SIZE);
		atomic_add_int(&amountpipekvawired,
		    wpipe->pipe_buffer.size + PAGE_SIZE);
	}
	pmap_qenter(wpipe->pipe_map.kva, wpipe->pipe_map.ms,
		wpipe->pipe_map.npages);

/*
 * and update the uio data
 */

	uio->uio_iov->iov_len -= size;
	uio->uio_iov->iov_base = (char *)uio->uio_iov->iov_base + size;
	if (uio->uio_iov->iov_len == 0)
		uio->uio_iov++;
	uio->uio_resid -= size;
	uio->uio_offset += size;
	return (0);
}

/*
 * unmap and unwire the process buffer
 */
static void
pipe_destroy_write_buffer(wpipe)
	struct pipe *wpipe;
{
	int i;

	PIPE_LOCK_ASSERT(wpipe, MA_NOTOWNED);
	if (wpipe->pipe_map.kva) {
		pmap_qremove(wpipe->pipe_map.kva, wpipe->pipe_map.npages);

		if (amountpipekvawired > maxpipekvawired / 2) {
			/* Conserve address space */
			vm_offset_t kva = wpipe->pipe_map.kva;
			wpipe->pipe_map.kva = 0;
			kmem_free(kernel_map, kva,
			    wpipe->pipe_buffer.size + PAGE_SIZE);
			atomic_subtract_int(&amountpipekvawired,
			    wpipe->pipe_buffer.size + PAGE_SIZE);
		}
	}
	vm_page_lock_queues();
	for (i = 0; i < wpipe->pipe_map.npages; i++) {
		vm_page_unhold(wpipe->pipe_map.ms[i]);
	}
	vm_page_unlock_queues();
	wpipe->pipe_map.npages = 0;
}

/*
 * In the case of a signal, the writing process might go away.  This
 * code copies the data into the circular buffer so that the source
 * pages can be freed without loss of data.
 */
static void
pipe_clone_write_buffer(wpipe)
	struct pipe *wpipe;
{
	int size;
	int pos;

	PIPE_LOCK_ASSERT(wpipe, MA_OWNED);
	size = wpipe->pipe_map.cnt;
	pos = wpipe->pipe_map.pos;

	wpipe->pipe_buffer.in = size;
	wpipe->pipe_buffer.out = 0;
	wpipe->pipe_buffer.cnt = size;
	wpipe->pipe_state &= ~PIPE_DIRECTW;

	PIPE_UNLOCK(wpipe);
	bcopy((caddr_t) wpipe->pipe_map.kva + pos,
	    wpipe->pipe_buffer.buffer, size);
	pipe_destroy_write_buffer(wpipe);
	PIPE_LOCK(wpipe);
}

/*
 * This implements the pipe buffer write mechanism.  Note that only
 * a direct write OR a normal pipe write can be pending at any given time.
 * If there are any characters in the pipe buffer, the direct write will
 * be deferred until the receiving process grabs all of the bytes from
 * the pipe buffer.  Then the direct mapping write is set-up.
 */
static int
pipe_direct_write(wpipe, uio)
	struct pipe *wpipe;
	struct uio *uio;
{
	int error;

retry:
	PIPE_LOCK_ASSERT(wpipe, MA_OWNED);
	while (wpipe->pipe_state & PIPE_DIRECTW) {
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
		wpipe->pipe_state |= PIPE_WANTW;
		error = msleep(wpipe, PIPE_MTX(wpipe),
		    PRIBIO | PCATCH, "pipdww", 0);
		if (error)
			goto error1;
		if (wpipe->pipe_state & PIPE_EOF) {
			error = EPIPE;
			goto error1;
		}
	}
	wpipe->pipe_map.cnt = 0;	/* transfer not ready yet */
	if (wpipe->pipe_buffer.cnt > 0) {
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}

		wpipe->pipe_state |= PIPE_WANTW;
		error = msleep(wpipe, PIPE_MTX(wpipe),
		    PRIBIO | PCATCH, "pipdwc", 0);
		if (error)
			goto error1;
		if (wpipe->pipe_state & PIPE_EOF) {
			error = EPIPE;
			goto error1;
		}
		goto retry;
	}

	wpipe->pipe_state |= PIPE_DIRECTW;

	pipelock(wpipe, 0);
	if (wpipe->pipe_state & PIPE_EOF) {
		error = EPIPE;
		goto error2;
	}
	PIPE_UNLOCK(wpipe);
	error = pipe_build_write_buffer(wpipe, uio);
	PIPE_LOCK(wpipe);
	pipeunlock(wpipe);
	if (error) {
		wpipe->pipe_state &= ~PIPE_DIRECTW;
		goto error1;
	}

	error = 0;
	while (!error && (wpipe->pipe_state & PIPE_DIRECTW)) {
		if (wpipe->pipe_state & PIPE_EOF) {
			pipelock(wpipe, 0);
			PIPE_UNLOCK(wpipe);
			pipe_destroy_write_buffer(wpipe);
			PIPE_LOCK(wpipe);
			pipeselwakeup(wpipe);
			pipeunlock(wpipe);
			error = EPIPE;
			goto error1;
		}
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
		pipeselwakeup(wpipe);
		error = msleep(wpipe, PIPE_MTX(wpipe), PRIBIO | PCATCH,
		    "pipdwt", 0);
	}

	pipelock(wpipe,0);
	if (wpipe->pipe_state & PIPE_EOF)
		error = EPIPE;
	if (wpipe->pipe_state & PIPE_DIRECTW) {
		/*
		 * this bit of trickery substitutes a kernel buffer for
		 * the process that might be going away.
		 */
		pipe_clone_write_buffer(wpipe);
	} else {
		PIPE_UNLOCK(wpipe);
		pipe_destroy_write_buffer(wpipe);
		PIPE_LOCK(wpipe);
	}
error2:
	pipeunlock(wpipe);
	return (error);

error1:
	wakeup(wpipe);
	return (error);
}
#endif

static int
pipe_write(fp, uio, active_cred, flags, td)
	struct file *fp;
	struct uio *uio;
	struct ucred *active_cred;
	struct thread *td;
	int flags;
{
	int error = 0;
	int orig_resid;
	struct pipe *wpipe, *rpipe;

	rpipe = fp->f_data;
	wpipe = rpipe->pipe_peer;

	PIPE_LOCK(rpipe);
	/*
	 * detect loss of pipe read side, issue SIGPIPE if lost.
	 */
	if ((!wpipe->pipe_present) || (wpipe->pipe_state & PIPE_EOF)) {
		PIPE_UNLOCK(rpipe);
		return (EPIPE);
	}
#ifdef MAC
	error = mac_check_pipe_write(active_cred, wpipe->pipe_pair);
	if (error) {
		PIPE_UNLOCK(rpipe);
		return (error);
	}
#endif
	++wpipe->pipe_busy;

	/*
	 * If it is advantageous to resize the pipe buffer, do
	 * so.
	 */
	if ((uio->uio_resid > PIPE_SIZE) &&
		(amountpipekva < maxpipekva / 2) &&
		(nbigpipe < LIMITBIGPIPES) &&
		(wpipe->pipe_state & PIPE_DIRECTW) == 0 &&
		(wpipe->pipe_buffer.size <= PIPE_SIZE) &&
		(wpipe->pipe_buffer.cnt == 0)) {

		if ((error = pipelock(wpipe, 1)) == 0) {
			if (wpipe->pipe_state & PIPE_EOF)
				error = EPIPE;
			else {
				PIPE_UNLOCK(wpipe);
				if (pipespace(wpipe, BIG_PIPE_SIZE) == 0)
					atomic_add_int(&nbigpipe, 1);
				PIPE_LOCK(wpipe);
			}
			pipeunlock(wpipe);
		}
	}

	/*
	 * If an early error occured unbusy and return, waking up any pending
	 * readers.
	 */
	if (error) {
		--wpipe->pipe_busy;
		if ((wpipe->pipe_busy == 0) &&
		    (wpipe->pipe_state & PIPE_WANT)) {
			wpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTR);
			wakeup(wpipe);
		}
		PIPE_UNLOCK(rpipe);
		return(error);
	}

	orig_resid = uio->uio_resid;

	while (uio->uio_resid) {
		int space;

#ifndef PIPE_NODIRECT
		/*
		 * If the transfer is large, we can gain performance if
		 * we do process-to-process copies directly.
		 * If the write is non-blocking, we don't use the
		 * direct write mechanism.
		 *
		 * The direct write mechanism will detect the reader going
		 * away on us.
		 */
		if ((uio->uio_iov->iov_len >= PIPE_MINDIRECT) &&
		    (fp->f_flag & FNONBLOCK) == 0 &&
		    amountpipekvawired + uio->uio_resid < maxpipekvawired) {
			error = pipe_direct_write(wpipe, uio);
			if (error)
				break;
			continue;
		}
#endif

		/*
		 * Pipe buffered writes cannot be coincidental with
		 * direct writes.  We wait until the currently executing
		 * direct write is completed before we start filling the
		 * pipe buffer.  We break out if a signal occurs or the
		 * reader goes away.
		 */
	retrywrite:
		while (wpipe->pipe_state & PIPE_DIRECTW) {
			if (wpipe->pipe_state & PIPE_WANTR) {
				wpipe->pipe_state &= ~PIPE_WANTR;
				wakeup(wpipe);
			}
			error = msleep(wpipe, PIPE_MTX(rpipe), PRIBIO | PCATCH,
			    "pipbww", 0);
			if (wpipe->pipe_state & PIPE_EOF) {
				error = EPIPE;
				break;
			}
			if (error)
				break;
		}

		space = wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt;

		/* Writes of size <= PIPE_BUF must be atomic. */
		if ((space < uio->uio_resid) && (orig_resid <= PIPE_BUF))
			space = 0;

		if (space > 0) {
			if ((error = pipelock(wpipe,1)) == 0) {
				int size;	/* Transfer size */
				int segsize;	/* first segment to transfer */

				/*
				 * It is possible for a direct write/EOF to
				 * slip in on us... handle them here...
				 */
				if (wpipe->pipe_state & PIPE_EOF)
					goto lost_wpipe;
				if (wpipe->pipe_state & PIPE_DIRECTW) {
					pipeunlock(wpipe);
					goto retrywrite;
				}
				/*
				 * If a process blocked in uiomove, our
				 * value for space might be bad.
				 *
				 * XXX will we be ok if the reader has gone
				 * away here?
				 */
				if (space > wpipe->pipe_buffer.size -
				    wpipe->pipe_buffer.cnt) {
					pipeunlock(wpipe);
					goto retrywrite;
				}

				/*
				 * Transfer size is minimum of uio transfer
				 * and free space in pipe buffer.
				 */
				if (space > uio->uio_resid)
					size = uio->uio_resid;
				else
					size = space;
				/*
				 * First segment to transfer is minimum of
				 * transfer size and contiguous space in
				 * pipe buffer.  If first segment to transfer
				 * is less than the transfer size, we've got
				 * a wraparound in the buffer.
				 */
				segsize = wpipe->pipe_buffer.size -
					wpipe->pipe_buffer.in;
				if (segsize > size)
					segsize = size;

				/* Transfer first segment */

				PIPE_UNLOCK(rpipe);
				error = uiomove(&wpipe->pipe_buffer.buffer[wpipe->pipe_buffer.in],
						segsize, uio);
				PIPE_LOCK(rpipe);

				if (error == 0 && segsize < size) {
					/*
					 * Transfer remaining part now, to
					 * support atomic writes.  Wraparound
					 * happened.
					 */
					if (wpipe->pipe_buffer.in + segsize !=
					    wpipe->pipe_buffer.size)
						panic("Expected pipe buffer "
						    "wraparound disappeared");

					PIPE_UNLOCK(rpipe);
					error = uiomove(
					    &wpipe->pipe_buffer.buffer[0],
					    size - segsize, uio);
					PIPE_LOCK(rpipe);
				}
				if (error == 0) {
					wpipe->pipe_buffer.in += size;
					if (wpipe->pipe_buffer.in >=
					    wpipe->pipe_buffer.size) {
						if (wpipe->pipe_buffer.in !=
						    size - segsize +
						    wpipe->pipe_buffer.size)
							panic("Expected "
							    "wraparound bad");
						wpipe->pipe_buffer.in = size -
						    segsize;
					}

					wpipe->pipe_buffer.cnt += size;
					if (wpipe->pipe_buffer.cnt >
					    wpipe->pipe_buffer.size)
						panic("Pipe buffer overflow");

				}
lost_wpipe:
				pipeunlock(wpipe);
			}
			if (error)
				break;

		} else {
			/*
			 * If the "read-side" has been blocked, wake it up now.
			 */
			if (wpipe->pipe_state & PIPE_WANTR) {
				wpipe->pipe_state &= ~PIPE_WANTR;
				wakeup(wpipe);
			}

			/*
			 * don't block on non-blocking I/O
			 */
			if (fp->f_flag & FNONBLOCK) {
				error = EAGAIN;
				break;
			}

			/*
			 * We have no more space and have something to offer,
			 * wake up select/poll.
			 */
			pipeselwakeup(wpipe);

			wpipe->pipe_state |= PIPE_WANTW;
			error = msleep(wpipe, PIPE_MTX(rpipe),
			    PRIBIO | PCATCH, "pipewr", 0);
			if (error != 0)
				break;
			/*
			 * If read side wants to go away, we just issue a signal
			 * to ourselves.
			 */
			if (wpipe->pipe_state & PIPE_EOF) {
				error = EPIPE;
				break;
			}
		}
	}

	--wpipe->pipe_busy;

	if ((wpipe->pipe_busy == 0) && (wpipe->pipe_state & PIPE_WANT)) {
		wpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTR);
		wakeup(wpipe);
	} else if (wpipe->pipe_buffer.cnt > 0) {
		/*
		 * If we have put any characters in the buffer, we wake up
		 * the reader.
		 */
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
	}

	/*
	 * Don't return EPIPE if I/O was successful
	 */
	if ((wpipe->pipe_buffer.cnt == 0) &&
	    (uio->uio_resid == 0) &&
	    (error == EPIPE)) {
		error = 0;
	}

	if (error == 0)
		vfs_timestamp(&wpipe->pipe_mtime);

	/*
	 * We have something to offer,
	 * wake up select/poll.
	 */
	if (wpipe->pipe_buffer.cnt)
		pipeselwakeup(wpipe);

	PIPE_UNLOCK(rpipe);
	return (error);
}

/*
 * we implement a very minimal set of ioctls for compatibility with sockets.
 */
static int
pipe_ioctl(fp, cmd, data, active_cred, td)
	struct file *fp;
	u_long cmd;
	void *data;
	struct ucred *active_cred;
	struct thread *td;
{
	struct pipe *mpipe = fp->f_data;
#ifdef MAC
	int error;
#endif

	PIPE_LOCK(mpipe);

#ifdef MAC
	error = mac_check_pipe_ioctl(active_cred, mpipe->pipe_pair, cmd, data);
	if (error) {
		PIPE_UNLOCK(mpipe);
		return (error);
	}
#endif

	switch (cmd) {

	case FIONBIO:
		PIPE_UNLOCK(mpipe);
		return (0);

	case FIOASYNC:
		if (*(int *)data) {
			mpipe->pipe_state |= PIPE_ASYNC;
		} else {
			mpipe->pipe_state &= ~PIPE_ASYNC;
		}
		PIPE_UNLOCK(mpipe);
		return (0);

	case FIONREAD:
		if (mpipe->pipe_state & PIPE_DIRECTW)
			*(int *)data = mpipe->pipe_map.cnt;
		else
			*(int *)data = mpipe->pipe_buffer.cnt;
		PIPE_UNLOCK(mpipe);
		return (0);

	case FIOSETOWN:
		PIPE_UNLOCK(mpipe);
		return (fsetown(*(int *)data, &mpipe->pipe_sigio));

	case FIOGETOWN:
		PIPE_UNLOCK(mpipe);
		*(int *)data = fgetown(&mpipe->pipe_sigio);
		return (0);

	/* This is deprecated, FIOSETOWN should be used instead. */
	case TIOCSPGRP:
		PIPE_UNLOCK(mpipe);
		return (fsetown(-(*(int *)data), &mpipe->pipe_sigio));

	/* This is deprecated, FIOGETOWN should be used instead. */
	case TIOCGPGRP:
		PIPE_UNLOCK(mpipe);
		*(int *)data = -fgetown(&mpipe->pipe_sigio);
		return (0);

	}
	PIPE_UNLOCK(mpipe);
	return (ENOTTY);
}

static int
pipe_poll(fp, events, active_cred, td)
	struct file *fp;
	int events;
	struct ucred *active_cred;
	struct thread *td;
{
	struct pipe *rpipe = fp->f_data;
	struct pipe *wpipe;
	int revents = 0;
#ifdef MAC
	int error;
#endif

	wpipe = rpipe->pipe_peer;
	PIPE_LOCK(rpipe);
#ifdef MAC
	error = mac_check_pipe_poll(active_cred, rpipe->pipe_pair);
	if (error)
		goto locked_error;
#endif
	if (events & (POLLIN | POLLRDNORM))
		if ((rpipe->pipe_state & PIPE_DIRECTW) ||
		    (rpipe->pipe_buffer.cnt > 0) ||
		    (rpipe->pipe_state & PIPE_EOF))
			revents |= events & (POLLIN | POLLRDNORM);

	if (events & (POLLOUT | POLLWRNORM))
		if (!wpipe->pipe_present || (wpipe->pipe_state & PIPE_EOF) ||
		    (((wpipe->pipe_state & PIPE_DIRECTW) == 0) &&
		     (wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt) >= PIPE_BUF))
			revents |= events & (POLLOUT | POLLWRNORM);

	if ((rpipe->pipe_state & PIPE_EOF) ||
	    (!wpipe->pipe_present) ||
	    (wpipe->pipe_state & PIPE_EOF))
		revents |= POLLHUP;

	if (revents == 0) {
		if (events & (POLLIN | POLLRDNORM)) {
			selrecord(td, &rpipe->pipe_sel);
			rpipe->pipe_state |= PIPE_SEL;
		}

		if (events & (POLLOUT | POLLWRNORM)) {
			selrecord(td, &wpipe->pipe_sel);
			wpipe->pipe_state |= PIPE_SEL;
		}
	}
#ifdef MAC
locked_error:
#endif
	PIPE_UNLOCK(rpipe);

	return (revents);
}

/*
 * We shouldn't need locks here as we're doing a read and this should
 * be a natural race.
 */
static int
pipe_stat(fp, ub, active_cred, td)
	struct file *fp;
	struct stat *ub;
	struct ucred *active_cred;
	struct thread *td;
{
	struct pipe *pipe = fp->f_data;
#ifdef MAC
	int error;

	PIPE_LOCK(pipe);
	error = mac_check_pipe_stat(active_cred, pipe->pipe_pair);
	PIPE_UNLOCK(pipe);
	if (error)
		return (error);
#endif
	bzero(ub, sizeof(*ub));
	ub->st_mode = S_IFIFO;
	ub->st_blksize = pipe->pipe_buffer.size;
	ub->st_size = pipe->pipe_buffer.cnt;
	ub->st_blocks = (ub->st_size + ub->st_blksize - 1) / ub->st_blksize;
	ub->st_atimespec = pipe->pipe_atime;
	ub->st_mtimespec = pipe->pipe_mtime;
	ub->st_ctimespec = pipe->pipe_ctime;
	ub->st_uid = fp->f_cred->cr_uid;
	ub->st_gid = fp->f_cred->cr_gid;
	/*
	 * Left as 0: st_dev, st_ino, st_nlink, st_rdev, st_flags, st_gen.
	 * XXX (st_dev, st_ino) should be unique.
	 */
	return (0);
}

/* ARGSUSED */
static int
pipe_close(fp, td)
	struct file *fp;
	struct thread *td;
{
	struct pipe *cpipe = fp->f_data;

	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	funsetown(&cpipe->pipe_sigio);
	pipeclose(cpipe);
	return (0);
}

static void
pipe_free_kmem(cpipe)
	struct pipe *cpipe;
{

	KASSERT(!mtx_owned(PIPE_MTX(cpipe)),
	    ("pipe_free_kmem: pipe mutex locked"));

	if (cpipe->pipe_buffer.buffer != NULL) {
		if (cpipe->pipe_buffer.size > PIPE_SIZE)
			atomic_subtract_int(&nbigpipe, 1);
		atomic_subtract_int(&amountpipekva, cpipe->pipe_buffer.size);
		vm_map_remove(pipe_map,
		    (vm_offset_t)cpipe->pipe_buffer.buffer,
		    (vm_offset_t)cpipe->pipe_buffer.buffer + cpipe->pipe_buffer.size);
		cpipe->pipe_buffer.buffer = NULL;
	}
#ifndef PIPE_NODIRECT
	if (cpipe->pipe_map.kva != 0) {
		atomic_subtract_int(&amountpipekvawired,
		    cpipe->pipe_buffer.size + PAGE_SIZE);
		kmem_free(kernel_map,
			cpipe->pipe_map.kva,
			cpipe->pipe_buffer.size + PAGE_SIZE);
		cpipe->pipe_map.cnt = 0;
		cpipe->pipe_map.kva = 0;
		cpipe->pipe_map.pos = 0;
		cpipe->pipe_map.npages = 0;
	}
#endif
}

/*
 * shutdown the pipe
 */
static void
pipeclose(cpipe)
	struct pipe *cpipe;
{
	struct pipepair *pp;
	struct pipe *ppipe;
	int hadpeer;

	KASSERT(cpipe != NULL, ("pipeclose: cpipe == NULL"));

	hadpeer = 0;
	PIPE_LOCK(cpipe);
	pp = cpipe->pipe_pair;

	pipeselwakeup(cpipe);

	/*
	 * If the other side is blocked, wake it up saying that
	 * we want to close it down.
	 */
	cpipe->pipe_state |= PIPE_EOF;
	while (cpipe->pipe_busy) {
		wakeup(cpipe);
		cpipe->pipe_state |= PIPE_WANT;
		msleep(cpipe, PIPE_MTX(cpipe), PRIBIO, "pipecl", 0);
	}


	/*
	 * Disconnect from peer, if any.
	 */
	ppipe = cpipe->pipe_peer;
	if (ppipe->pipe_present != 0) {
		hadpeer++;
		pipeselwakeup(ppipe);

		ppipe->pipe_state |= PIPE_EOF;
		wakeup(ppipe);
		KNOTE(&ppipe->pipe_sel.si_note, 0);
	}

	/*
	 * Mark this endpoint as free.  Release kmem resources.  We
	 * don't mark this endpoint as unused until we've finished
	 * doing that, or the pipe might disappear out from under
	 * us.
	 */
	pipelock(cpipe, 0);
	PIPE_UNLOCK(cpipe);
	pipe_free_kmem(cpipe);
	PIPE_LOCK(cpipe);
	cpipe->pipe_present = 0;
	pipeunlock(cpipe);

	/*
	 * If both endpoints are now closed, release the memory for the
	 * pipe pair.  If not, unlock.
	 */
	if (ppipe->pipe_present == 0) {
		PIPE_UNLOCK(cpipe);
#ifdef MAC
		mac_destroy_pipe(pp);
#endif
		uma_zfree(pipe_zone, cpipe->pipe_pair);
	} else
		PIPE_UNLOCK(cpipe);
}

/*ARGSUSED*/
static int
pipe_kqfilter(struct file *fp, struct knote *kn)
{
	struct pipe *cpipe;

	cpipe = kn->kn_fp->f_data;
	PIPE_LOCK(cpipe);
	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &pipe_rfiltops;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &pipe_wfiltops;
		if (!cpipe->pipe_peer->pipe_present) {
			/* other end of pipe has been closed */
			PIPE_UNLOCK(cpipe);
			return (EPIPE);
		}
		cpipe = cpipe->pipe_peer;
		break;
	default:
		PIPE_UNLOCK(cpipe);
		return (1);
	}

	SLIST_INSERT_HEAD(&cpipe->pipe_sel.si_note, kn, kn_selnext);
	PIPE_UNLOCK(cpipe);
	return (0);
}

static void
filt_pipedetach(struct knote *kn)
{
	struct pipe *cpipe = (struct pipe *)kn->kn_fp->f_data;

	PIPE_LOCK(cpipe);
	if (kn->kn_filter == EVFILT_WRITE) {
		if (!cpipe->pipe_peer->pipe_present) {
			PIPE_UNLOCK(cpipe);
			return;
		}
		cpipe = cpipe->pipe_peer;
	}
	SLIST_REMOVE(&cpipe->pipe_sel.si_note, kn, knote, kn_selnext);
	PIPE_UNLOCK(cpipe);
}

/*ARGSUSED*/
static int
filt_piperead(struct knote *kn, long hint)
{
	struct pipe *rpipe = kn->kn_fp->f_data;
	struct pipe *wpipe = rpipe->pipe_peer;

	PIPE_LOCK(rpipe);
	kn->kn_data = rpipe->pipe_buffer.cnt;
	if ((kn->kn_data == 0) && (rpipe->pipe_state & PIPE_DIRECTW))
		kn->kn_data = rpipe->pipe_map.cnt;

	if ((rpipe->pipe_state & PIPE_EOF) ||
	    (!wpipe->pipe_present) || (wpipe->pipe_state & PIPE_EOF)) {
		kn->kn_flags |= EV_EOF;
		PIPE_UNLOCK(rpipe);
		return (1);
	}
	PIPE_UNLOCK(rpipe);
	return (kn->kn_data > 0);
}

/*ARGSUSED*/
static int
filt_pipewrite(struct knote *kn, long hint)
{
	struct pipe *rpipe = kn->kn_fp->f_data;
	struct pipe *wpipe = rpipe->pipe_peer;

	PIPE_LOCK(rpipe);
	if ((!wpipe->pipe_present) || (wpipe->pipe_state & PIPE_EOF)) {
		kn->kn_data = 0;
		kn->kn_flags |= EV_EOF;
		PIPE_UNLOCK(rpipe);
		return (1);
	}
	kn->kn_data = wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt;
	if (wpipe->pipe_state & PIPE_DIRECTW)
		kn->kn_data = 0;

	PIPE_UNLOCK(rpipe);
	return (kn->kn_data >= PIPE_BUF);
}
