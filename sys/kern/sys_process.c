/*
 * Copyright (c) 1994, Sean Eric Fagan
 * All rights reserved.
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
 *	This product includes software developed by Sean Eric Fagan.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/ptrace.h>
#include <sys/sx.h>
#include <sys/user.h>

#include <machine/reg.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <fs/procfs/procfs.h>

/* use the equivalent procfs code */
#if 0
static int
pread(struct proc *procp, unsigned int addr, unsigned int *retval)
{
	int		rv;
	vm_map_t	map, tmap;
	vm_object_t	object;
	vm_offset_t	kva = 0;
	int		page_offset;	/* offset into page */
	vm_offset_t	pageno;		/* page number */
	vm_map_entry_t	out_entry;
	vm_prot_t	out_prot;
	boolean_t	wired;
	vm_pindex_t	pindex;

	/* Map page into kernel space */

	map = &procp->p_vmspace->vm_map;

	page_offset = addr - trunc_page(addr);
	pageno = trunc_page(addr);

	tmap = map;
	rv = vm_map_lookup(&tmap, pageno, VM_PROT_READ, &out_entry,
	    &object, &pindex, &out_prot, &wired);

	if (rv != KERN_SUCCESS)
		return (EINVAL);

	vm_map_lookup_done(tmap, out_entry);

	/* Find space in kernel_map for the page we're interested in */
	rv = vm_map_find(kernel_map, object, IDX_TO_OFF(pindex),
	    &kva, PAGE_SIZE, 0, VM_PROT_ALL, VM_PROT_ALL, 0);

	if (!rv) {
		vm_object_reference(object);

		rv = vm_map_pageable(kernel_map, kva, kva + PAGE_SIZE, 0);
		if (!rv) {
			*retval = 0;
			bcopy((caddr_t)kva + page_offset,
			    retval, sizeof *retval);
		}
		vm_map_remove(kernel_map, kva, kva + PAGE_SIZE);
	}

	return (rv);
}

static int
pwrite(struct proc *procp, unsigned int addr, unsigned int datum)
{
	int		rv;
	vm_map_t	map, tmap;
	vm_object_t	object;
	vm_offset_t	kva = 0;
	int		page_offset;	/* offset into page */
	vm_offset_t	pageno;		/* page number */
	vm_map_entry_t	out_entry;
	vm_prot_t	out_prot;
	boolean_t	wired;
	vm_pindex_t	pindex;
	boolean_t	fix_prot = 0;

	/* Map page into kernel space */

	map = &procp->p_vmspace->vm_map;

	page_offset = addr - trunc_page(addr);
	pageno = trunc_page(addr);

	/*
	 * Check the permissions for the area we're interested in.
	 */

	if (vm_map_check_protection(map, pageno, pageno + PAGE_SIZE,
	    VM_PROT_WRITE) == FALSE) {
		/*
		 * If the page was not writable, we make it so.
		 * XXX It is possible a page may *not* be read/executable,
		 * if a process changes that!
		 */
		fix_prot = 1;
		/* The page isn't writable, so let's try making it so... */
		if ((rv = vm_map_protect(map, pageno, pageno + PAGE_SIZE,
		    VM_PROT_ALL, 0)) != KERN_SUCCESS)
			return (EFAULT);	/* I guess... */
	}

	/*
	 * Now we need to get the page.  out_entry, out_prot, wired, and
	 * single_use aren't used.  One would think the vm code would be
	 * a *bit* nicer...  We use tmap because vm_map_lookup() can
	 * change the map argument.
	 */

	tmap = map;
	rv = vm_map_lookup(&tmap, pageno, VM_PROT_WRITE, &out_entry,
	    &object, &pindex, &out_prot, &wired);
	if (rv != KERN_SUCCESS) {
		return (EINVAL);
	}

	/*
	 * Okay, we've got the page.  Let's release tmap.
	 */

	vm_map_lookup_done(tmap, out_entry);

	/*
	 * Fault the page in...
	 */

	rv = vm_fault(map, pageno, VM_PROT_WRITE|VM_PROT_READ, FALSE);
	if (rv != KERN_SUCCESS)
		return (EFAULT);

	/* Find space in kernel_map for the page we're interested in */
	rv = vm_map_find(kernel_map, object, IDX_TO_OFF(pindex),
	    &kva, PAGE_SIZE, 0,
	    VM_PROT_ALL, VM_PROT_ALL, 0);
	if (!rv) {
		vm_object_reference(object);

		rv = vm_map_pageable(kernel_map, kva, kva + PAGE_SIZE, 0);
		if (!rv) {
			bcopy(&datum, (caddr_t)kva + page_offset, sizeof datum);
		}
		vm_map_remove(kernel_map, kva, kva + PAGE_SIZE);
	}

	if (fix_prot)
		vm_map_protect(map, pageno, pageno + PAGE_SIZE,
		    VM_PROT_READ|VM_PROT_EXECUTE, 0);
	return (rv);
}
#endif

/*
 * Process debugging system call.
 */
#ifndef _SYS_SYSPROTO_H_
struct ptrace_args {
	int	req;
	pid_t	pid;
	caddr_t	addr;
	int	data;
};
#endif

int
ptrace(td, uap)
	struct thread *td;
	struct ptrace_args *uap;
{
	struct proc *curp = td->td_proc;
	struct proc *p;
	struct iovec iov;
	struct uio uio;
	int error = 0;
	int write;

	write = 0;
	if (uap->req == PT_TRACE_ME) {
		p = curp;
		PROC_LOCK(p);
	} else {
		if ((p = pfind(uap->pid)) == NULL)
			return (ESRCH);
	}
	if (p_cansee(curp, p)) {
		PROC_UNLOCK(p);
		return (ESRCH);
	}

	/*
	 * Permissions check
	 */
	switch (uap->req) {
	case PT_TRACE_ME:
		/* Always legal. */
		break;

	case PT_ATTACH:
		/* Self */
		if (p->p_pid == curp->p_pid) {
			PROC_UNLOCK(p);
			return (EINVAL);
		}

		/* Already traced */
		if (p->p_flag & P_TRACED) {
			PROC_UNLOCK(p);
			return (EBUSY);
		}

		if ((error = p_candebug(curp, p))) {
			PROC_UNLOCK(p);
			return (error);
		}

		/* OK */
		break;

	case PT_READ_I:
	case PT_READ_D:
	case PT_WRITE_I:
	case PT_WRITE_D:
	case PT_CONTINUE:
	case PT_KILL:
	case PT_STEP:
	case PT_DETACH:
#ifdef PT_GETREGS
	case PT_GETREGS:
#endif
#ifdef PT_SETREGS
	case PT_SETREGS:
#endif
#ifdef PT_GETFPREGS
	case PT_GETFPREGS:
#endif
#ifdef PT_SETFPREGS
	case PT_SETFPREGS:
#endif
#ifdef PT_GETDBREGS
	case PT_GETDBREGS:
#endif
#ifdef PT_SETDBREGS
	case PT_SETDBREGS:
#endif
		/* not being traced... */
		if ((p->p_flag & P_TRACED) == 0) {
			PROC_UNLOCK(p);
			return (EPERM);
		}

		/* not being traced by YOU */
		if (p->p_pptr != curp) {
			PROC_UNLOCK(p);
			return (EBUSY);
		}

		/* not currently stopped */
		mtx_lock_spin(&sched_lock);
		if (p->p_stat != SSTOP || (p->p_flag & P_WAITED) == 0) {
			mtx_unlock_spin(&sched_lock);
			PROC_UNLOCK(p);
			return (EBUSY);
		}
		mtx_unlock_spin(&sched_lock);

		/* OK */
		break;

	default:
		PROC_UNLOCK(p);
		return (EINVAL);
	}

	PROC_UNLOCK(p);
#ifdef FIX_SSTEP
	/*
	 * Single step fixup ala procfs
	 */
	FIX_SSTEP(&p->p_thread);	/* XXXKSE */
#endif

	/*
	 * Actually do the requests
	 */

	td->td_retval[0] = 0;

	switch (uap->req) {
	case PT_TRACE_ME:
		/* set my trace flag and "owner" so it can read/write me */
		sx_xlock(&proctree_lock);
		PROC_LOCK(p);
		p->p_flag |= P_TRACED;
		p->p_oppid = p->p_pptr->p_pid;
		PROC_UNLOCK(p);
		sx_xunlock(&proctree_lock);
		return (0);

	case PT_ATTACH:
		/* security check done above */
		sx_xlock(&proctree_lock);
		PROC_LOCK(p);
		p->p_flag |= P_TRACED;
		p->p_oppid = p->p_pptr->p_pid;
		if (p->p_pptr != curp)
			proc_reparent(p, curp);
		PROC_UNLOCK(p);
		sx_xunlock(&proctree_lock);
		uap->data = SIGSTOP;
		goto sendsig;	/* in PT_CONTINUE below */

	case PT_STEP:
	case PT_CONTINUE:
	case PT_DETACH:
		if ((uap->req != PT_STEP) && ((unsigned)uap->data >= NSIG))
			return (EINVAL);

		PHOLD(p);

		if (uap->req == PT_STEP) {
			if ((error = ptrace_single_step(&p->p_thread))) {
				PRELE(p);
				return (error);
			}
		}

		if (uap->addr != (caddr_t)1) {
			fill_kinfo_proc(p, &p->p_uarea->u_kproc);
			if ((error = ptrace_set_pc(&p->p_thread,
			    (u_long)(uintfptr_t)uap->addr))) {
				PRELE(p);
				return (error);
			}
		}
		PRELE(p);

		if (uap->req == PT_DETACH) {
			/* reset process parent */
			sx_xlock(&proctree_lock);
			if (p->p_oppid != p->p_pptr->p_pid) {
				struct proc *pp;

				pp = pfind(p->p_oppid);
				if (pp != NULL)
					PROC_UNLOCK(pp);
				else
					pp = initproc;
				PROC_LOCK(p);
				proc_reparent(p, pp);
			} else
				PROC_LOCK(p);
			p->p_flag &= ~(P_TRACED | P_WAITED);
			p->p_oppid = 0;

			PROC_UNLOCK(p);
			sx_xunlock(&proctree_lock);

			/* should we send SIGCHLD? */

		}

	sendsig:
		/* deliver or queue signal */
		PROC_LOCK(p);
		mtx_lock_spin(&sched_lock);
		if (p->p_stat == SSTOP) {
			p->p_xstat = uap->data;
			setrunnable(&p->p_thread); /* XXXKSE */
			mtx_unlock_spin(&sched_lock);
		} else {
			mtx_unlock_spin(&sched_lock);
			if (uap->data)		      
				psignal(p, uap->data);

		}
		PROC_UNLOCK(p);
		return (0);

	case PT_WRITE_I:
	case PT_WRITE_D:
		write = 1;
		/* fallthrough */
	case PT_READ_I:
	case PT_READ_D:
		/* write = 0 set above */
		iov.iov_base = write ? (caddr_t)&uap->data :
		    (caddr_t)td->td_retval;
		iov.iov_len = sizeof(int);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = (off_t)(uintptr_t)uap->addr;
		uio.uio_resid = sizeof(int);
		uio.uio_segflg = UIO_SYSSPACE;	/* ie: the uap */
		uio.uio_rw = write ? UIO_WRITE : UIO_READ;
		uio.uio_td = td;
		error = procfs_domem(curp, p, NULL, &uio);
		if (uio.uio_resid != 0) {
			/*
			 * XXX procfs_domem() doesn't currently return ENOSPC,
			 * so I think write() can bogusly return 0.
			 * XXX what happens for short writes?  We don't want
			 * to write partial data.
			 * XXX procfs_domem() returns EPERM for other invalid
			 * addresses.  Convert this to EINVAL.  Does this
			 * clobber returns of EPERM for other reasons?
			 */
			if (error == 0 || error == ENOSPC || error == EPERM)
				error = EINVAL;	/* EOF */
		}
		return (error);

	case PT_KILL:
		uap->data = SIGKILL;
		goto sendsig;	/* in PT_CONTINUE above */

#ifdef PT_SETREGS
	case PT_SETREGS:
		write = 1;
		/* fallthrough */
#endif /* PT_SETREGS */
#ifdef PT_GETREGS
	case PT_GETREGS:
		/* write = 0 above */
#endif /* PT_SETREGS */
#if defined(PT_SETREGS) || defined(PT_GETREGS)
		if (!procfs_validregs(td))	/* no P_SYSTEM procs please */
			return (EINVAL);
		else {
			iov.iov_base = uap->addr;
			iov.iov_len = sizeof(struct reg);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = sizeof(struct reg);
			uio.uio_segflg = UIO_USERSPACE;
			uio.uio_rw = write ? UIO_WRITE : UIO_READ;
			uio.uio_td = td;
			return (procfs_doregs(curp, p, NULL, &uio));
		}
#endif /* defined(PT_SETREGS) || defined(PT_GETREGS) */

#ifdef PT_SETFPREGS
	case PT_SETFPREGS:
		write = 1;
		/* fallthrough */
#endif /* PT_SETFPREGS */
#ifdef PT_GETFPREGS
	case PT_GETFPREGS:
		/* write = 0 above */
#endif /* PT_SETFPREGS */
#if defined(PT_SETFPREGS) || defined(PT_GETFPREGS)
		if (!procfs_validfpregs(td))	/* no P_SYSTEM procs please */
			return (EINVAL);
		else {
			iov.iov_base = uap->addr;
			iov.iov_len = sizeof(struct fpreg);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = sizeof(struct fpreg);
			uio.uio_segflg = UIO_USERSPACE;
			uio.uio_rw = write ? UIO_WRITE : UIO_READ;
			uio.uio_td = td;
			return (procfs_dofpregs(curp, p, NULL, &uio));
		}
#endif /* defined(PT_SETFPREGS) || defined(PT_GETFPREGS) */

#ifdef PT_SETDBREGS
	case PT_SETDBREGS:
		write = 1;
		/* fallthrough */
#endif /* PT_SETDBREGS */
#ifdef PT_GETDBREGS
	case PT_GETDBREGS:
		/* write = 0 above */
#endif /* PT_SETDBREGS */
#if defined(PT_SETDBREGS) || defined(PT_GETDBREGS)
		if (!procfs_validdbregs(td))	/* no P_SYSTEM procs please */
			return (EINVAL);
		else {
			iov.iov_base = uap->addr;
			iov.iov_len = sizeof(struct dbreg);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = sizeof(struct dbreg);
			uio.uio_segflg = UIO_USERSPACE;
			uio.uio_rw = write ? UIO_WRITE : UIO_READ;
			uio.uio_td = td;
			return (procfs_dodbregs(curp, p, NULL, &uio));
		}
#endif /* defined(PT_SETDBREGS) || defined(PT_GETDBREGS) */

	default:
		break;
	}

	return (0);
}

int
trace_req(p)
	struct proc *p;
{
	return (1);
}

/*
 * stopevent()
 * Stop a process because of a procfs event;
 * stay stopped until p->p_step is cleared
 * (cleared by PIOCCONT in procfs).
 *
 * Must be called with the proc struct mutex held.
 */

void
stopevent(p, event, val)
	struct proc *p;
	unsigned int event;
	unsigned int val;
{

	PROC_LOCK_ASSERT(p, MA_OWNED | MA_NOTRECURSED);
	p->p_step = 1;

	do {
		p->p_xstat = val;
		p->p_stype = event;	/* Which event caused the stop? */
		wakeup(&p->p_stype);	/* Wake up any PIOCWAIT'ing procs */
		msleep(&p->p_step, &p->p_mtx, PWAIT, "stopevent", 0);
	} while (p->p_step);
}
