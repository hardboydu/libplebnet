/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_subr.c	8.3 (Berkeley) 1/21/94
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

SYSCTL_INT(_kern, KERN_IOV_MAX, iov_max, CTLFLAG_RD, NULL, UIO_MAXIOV, 
	"Maximum number of elements in an I/O vector; sysconf(_SC_IOV_MAX)");

int
uiomove(cp, n, uio)
	register caddr_t cp;
	register int n;
	register struct uio *uio;
{
	struct thread *td = curthread;
	register struct iovec *iov;
	u_int cnt;
	int error = 0;
	int save = 0;

	KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
	    ("uiomove: mode"));
	KASSERT(uio->uio_segflg != UIO_USERSPACE || uio->uio_td == curthread,
	    ("uiomove proc"));

	if (td) {
		mtx_lock_spin(&sched_lock);
		save = td->td_flags & TDF_DEADLKTREAT;
		td->td_flags |= TDF_DEADLKTREAT;
		mtx_unlock_spin(&sched_lock);
	}

	while (n > 0 && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > n)
			cnt = n;

		switch (uio->uio_segflg) {

		case UIO_USERSPACE:
			if (ticks - PCPU_GET(switchticks) >= hogticks)
				uio_yield();
			if (uio->uio_rw == UIO_READ)
				error = copyout(cp, iov->iov_base, cnt);
			else
				error = copyin(iov->iov_base, cp, cnt);
			if (error)
				goto out;
			break;

		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				bcopy((caddr_t)cp, iov->iov_base, cnt);
			else
				bcopy(iov->iov_base, (caddr_t)cp, cnt);
			break;
		case UIO_NOCOPY:
			break;
		}
		iov->iov_base += cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_offset += cnt;
		cp += cnt;
		n -= cnt;
	}
out:
	if (td != curthread) printf("uiomove: IT CHANGED!");
	td = curthread;	/* Might things have changed in copyin/copyout? */
	if (td) {
		mtx_lock_spin(&sched_lock);
		td->td_flags = (td->td_flags & ~TDF_DEADLKTREAT) | save;
		mtx_unlock_spin(&sched_lock);
	}
	return (error);
}

#ifdef ENABLE_VFS_IOOPT
/*
 * Experimental support for zero-copy I/O
 */
int
uiomoveco(cp, n, uio, obj)
	caddr_t cp;
	int n;
	struct uio *uio;
	struct vm_object *obj;
{
	struct iovec *iov;
	u_int cnt;
	int error;

	KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
	    ("uiomoveco: mode"));
	KASSERT(uio->uio_segflg != UIO_USERSPACE || uio->uio_td == curthread,
	    ("uiomoveco proc"));

	while (n > 0 && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > n)
			cnt = n;

		switch (uio->uio_segflg) {

		case UIO_USERSPACE:
			if (ticks - PCPU_GET(switchticks) >= hogticks)
				uio_yield();
			if (uio->uio_rw == UIO_READ) {
#ifdef ENABLE_VFS_IOOPT
				if (vfs_ioopt && ((cnt & PAGE_MASK) == 0) &&
					((((intptr_t) iov->iov_base) & PAGE_MASK) == 0) &&
					((uio->uio_offset & PAGE_MASK) == 0) &&
					((((intptr_t) cp) & PAGE_MASK) == 0)) {
						error = vm_uiomove(&curproc->p_vmspace->vm_map, obj,
								uio->uio_offset, cnt,
								(vm_offset_t) iov->iov_base, NULL);
				} else
#endif
				{
					error = copyout(cp, iov->iov_base, cnt);
				}
			} else {
				error = copyin(iov->iov_base, cp, cnt);
			}
			if (error)
				return (error);
			break;

		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				bcopy((caddr_t)cp, iov->iov_base, cnt);
			else
				bcopy(iov->iov_base, (caddr_t)cp, cnt);
			break;
		case UIO_NOCOPY:
			break;
		}
		iov->iov_base += cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_offset += cnt;
		cp += cnt;
		n -= cnt;
	}
	return (0);
}

/*
 * Experimental support for zero-copy I/O
 */
int
uioread(n, uio, obj, nread)
	int n;
	struct uio *uio;
	struct vm_object *obj;
	int *nread;
{
	int npagesmoved;
	struct iovec *iov;
	u_int cnt, tcnt;
	int error;

	*nread = 0;
	if (vfs_ioopt < 2)
		return 0;

	error = 0;

	while (n > 0 && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > n)
			cnt = n;

		if ((uio->uio_segflg == UIO_USERSPACE) &&
			((((intptr_t) iov->iov_base) & PAGE_MASK) == 0) &&
				 ((uio->uio_offset & PAGE_MASK) == 0) ) {

			if (cnt < PAGE_SIZE)
				break;

			cnt &= ~PAGE_MASK;

			if (ticks - PCPU_GET(switchticks) >= hogticks)
				uio_yield();
			error = vm_uiomove(&curproc->p_vmspace->vm_map, obj,
						uio->uio_offset, cnt,
						(vm_offset_t) iov->iov_base, &npagesmoved);

			if (npagesmoved == 0)
				break;

			tcnt = npagesmoved * PAGE_SIZE;
			cnt = tcnt;

			if (error)
				break;

			iov->iov_base += cnt;
			iov->iov_len -= cnt;
			uio->uio_resid -= cnt;
			uio->uio_offset += cnt;
			*nread += cnt;
			n -= cnt;
		} else {
			break;
		}
	}
	return error;
}
#endif

/*
 * Give next character to user as result of read.
 */
int
ureadc(c, uio)
	register int c;
	register struct uio *uio;
{
	register struct iovec *iov;

again:
	if (uio->uio_iovcnt == 0 || uio->uio_resid == 0)
		panic("ureadc");
	iov = uio->uio_iov;
	if (iov->iov_len == 0) {
		uio->uio_iovcnt--;
		uio->uio_iov++;
		goto again;
	}
	switch (uio->uio_segflg) {

	case UIO_USERSPACE:
		if (subyte(iov->iov_base, c) < 0)
			return (EFAULT);
		break;

	case UIO_SYSSPACE:
		*iov->iov_base = c;
		break;

	case UIO_NOCOPY:
		break;
	}
	iov->iov_base++;
	iov->iov_len--;
	uio->uio_resid--;
	uio->uio_offset++;
	return (0);
}

/*
 * General routine to allocate a hash table.
 */
void *
hashinit(elements, type, hashmask)
	int elements;
	struct malloc_type *type;
	u_long *hashmask;
{
	long hashsize;
	LIST_HEAD(generic, generic) *hashtbl;
	int i;

	if (elements <= 0)
		panic("hashinit: bad elements");
	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;
	hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl), type, M_WAITOK);
	for (i = 0; i < hashsize; i++)
		LIST_INIT(&hashtbl[i]);
	*hashmask = hashsize - 1;
	return (hashtbl);
}

static int primes[] = { 1, 13, 31, 61, 127, 251, 509, 761, 1021, 1531, 2039,
			2557, 3067, 3583, 4093, 4603, 5119, 5623, 6143, 6653,
			7159, 7673, 8191, 12281, 16381, 24571, 32749 };
#define NPRIMES (sizeof(primes) / sizeof(primes[0]))

/*
 * General routine to allocate a prime number sized hash table.
 */
void *
phashinit(elements, type, nentries)
	int elements;
	struct malloc_type *type;
	u_long *nentries;
{
	long hashsize;
	LIST_HEAD(generic, generic) *hashtbl;
	int i;

	if (elements <= 0)
		panic("phashinit: bad elements");
	for (i = 1, hashsize = primes[1]; hashsize <= elements;) {
		i++;
		if (i == NPRIMES)
			break;
		hashsize = primes[i];
	}
	hashsize = primes[i - 1];
	hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl), type, M_WAITOK);
	for (i = 0; i < hashsize; i++)
		LIST_INIT(&hashtbl[i]);
	*nentries = hashsize;
	return (hashtbl);
}

void
uio_yield()
{
	struct thread *td;

	td = curthread;
	mtx_lock_spin(&sched_lock);
	DROP_GIANT();
	td->td_priority = td->td_ksegrp->kg_user_pri; /* XXXKSE */
	setrunqueue(td);
	td->td_proc->p_stats->p_ru.ru_nivcsw++;
	mi_switch();
	mtx_unlock_spin(&sched_lock);
	PICKUP_GIANT();
}

int
copyinfrom(const void *src, void *dst, size_t len, int seg)
{
	int error = 0;

	switch (seg) {
	case UIO_USERSPACE:
		error = copyin(src, dst, len);
		break;
	case UIO_SYSSPACE:
		bcopy(src, dst, len);
		break;
	default:
		panic("copyinfrom: bad seg %d\n", seg);
	}
	return (error);
}

int
copyinstrfrom(const void *src, void *dst, size_t len, size_t *copied, int seg)
{
	int error = 0;

	switch (seg) {
	case UIO_USERSPACE:
		error = copyinstr(src, dst, len, copied);
		break;
	case UIO_SYSSPACE:
		error = copystr(src, dst, len, copied);
		break;
	default:
		panic("copyinstrfrom: bad seg %d\n", seg);
	}
	return (error);
}
