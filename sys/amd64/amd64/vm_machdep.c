/*-
 * Copyright (c) 1982, 1986 The Regents of the University of California.
 * Copyright (c) 1989, 1990 William Jolitz
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department, and William Jolitz.
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
 *	from: @(#)vm_machdep.c	7.3 (Berkeley) 5/13/91
 *	Utah $Hdr: vm_machdep.c 1.16.1.1 89/06/23$
 *	$Id: vm_machdep.c,v 1.15 1994/03/24 23:12:35 davidg Exp $
 */

#include "npx.h"
#include "param.h"
#include "systm.h"
#include "proc.h"
#include "malloc.h"
#include "buf.h"
#include "user.h"

#include "../include/cpu.h"

#include "vm/vm.h"
#include "vm/vm_kern.h"

#ifndef NOBOUNCE

caddr_t		bouncememory;
vm_offset_t	bouncepa, bouncepaend;
int		bouncepages, bpwait;
vm_map_t	bounce_map;
int		bmwait, bmfreeing;

#define BITS_IN_UNSIGNED (8*sizeof(unsigned))
int		bounceallocarraysize;
unsigned	*bounceallocarray;
int		bouncefree;

#define SIXTEENMEG (4096*4096)
#define MAXBKVA 512

/* special list that can be used at interrupt time for eventual kva free */
struct kvasfree {
	vm_offset_t addr;
	vm_offset_t size;
} kvaf[MAXBKVA];

int		kvasfreecnt;

/*
 * get bounce buffer pages (count physically contiguous)
 * (only 1 inplemented now)
 */
vm_offset_t
vm_bounce_page_find(count)
	int count;
{
	int bit;
	int s,i;

	if (count != 1)
		panic("vm_bounce_page_find -- no support for > 1 page yet!!!");

	s = splbio();
retry:
	for (i = 0; i < bounceallocarraysize; i++) {
		if (bounceallocarray[i] != 0xffffffff) {
			if (bit = ffs(~bounceallocarray[i])) {
				bounceallocarray[i] |= 1 << (bit - 1) ;
				bouncefree -= count;
				splx(s);
				return bouncepa + (i * BITS_IN_UNSIGNED + (bit - 1)) * NBPG;
			}
		}
	}
	bpwait = 1;
	tsleep((caddr_t) &bounceallocarray, PRIBIO, "bncwai", 0);
	goto retry;
}

/*
 * free count bounce buffer pages
 */
void
vm_bounce_page_free(pa, count)
	vm_offset_t pa;
	int count;
{
	int allocindex;
	int index;
	int bit;

	if (count != 1)
		panic("vm_bounce_page_free -- no support for > 1 page yet!!!\n");

	index = (pa - bouncepa) / NBPG;

	if ((index < 0) || (index >= bouncepages))
		panic("vm_bounce_page_free -- bad index\n");

	allocindex = index / BITS_IN_UNSIGNED;
	bit = index % BITS_IN_UNSIGNED;

	bounceallocarray[allocindex] &= ~(1 << bit);

	bouncefree += count;
	if (bpwait) {
		bpwait = 0;
		wakeup((caddr_t) &bounceallocarray);
	}
}

/*
 * allocate count bounce buffer kva pages
 */
vm_offset_t
vm_bounce_kva(count)
	int count;
{
	int tofree;
	int i;
	int startfree;
	vm_offset_t kva = 0;
	int s = splbio();
	int size = count*NBPG;
	startfree = 0;
more:
	if (!bmfreeing && (tofree = kvasfreecnt)) {
		bmfreeing = 1;
more1:
		for (i = startfree; i < kvasfreecnt; i++) {
			/*
			 * if we have a kva of the right size, no sense
			 * in freeing/reallocating...
			 * might affect fragmentation short term, but
			 * as long as the amount of bounce_map is
			 * significantly more than the maximum transfer
			 * size, I don't think that it is a problem.
			 */
			pmap_remove(kernel_pmap,
				kvaf[i].addr, kvaf[i].addr + kvaf[i].size);
			if( !kva && kvaf[i].size == size) {
				kva = kvaf[i].addr;
			} else {
				kmem_free_wakeup(bounce_map, kvaf[i].addr,
					kvaf[i].size);
			}
		}
		if (kvasfreecnt != tofree) {
			startfree = i;
			bmfreeing = 0;
			goto more;
		}
		kvasfreecnt = 0;
		bmfreeing = 0;
	}

	if (!kva && !(kva = kmem_alloc_pageable(bounce_map, size))) {
		bmwait = 1;
		tsleep((caddr_t) bounce_map, PRIBIO, "bmwait", 0);
		goto more;
	}
	splx(s);

	return kva;
}

/*
 * init the bounce buffer system
 */
void
vm_bounce_init()
{
	vm_offset_t minaddr, maxaddr;

	if (bouncepages == 0)
		return;
	
	bounceallocarraysize = (bouncepages + BITS_IN_UNSIGNED - 1) / BITS_IN_UNSIGNED;
	bounceallocarray = malloc(bounceallocarraysize * sizeof(unsigned), M_TEMP, M_NOWAIT);

	if (!bounceallocarray)
		panic("Cannot allocate bounce resource array\n");

	bzero(bounceallocarray, bounceallocarraysize * sizeof(long));

	bounce_map = kmem_suballoc(kernel_map, &minaddr, &maxaddr, MAXBKVA * NBPG, FALSE);

	bouncepa = pmap_kextract((vm_offset_t) bouncememory);
	bouncepaend = bouncepa + bouncepages * NBPG;
	bouncefree = bouncepages;
	kvasfreecnt = 0;
}

/*
 * do the things necessary to the struct buf to implement
 * bounce buffers...  inserted before the disk sort
 */
void
vm_bounce_alloc(bp)
	struct buf *bp;
{
	int countvmpg;
	vm_offset_t vastart, vaend;
	vm_offset_t vapstart, vapend;
	vm_offset_t va, kva;
	vm_offset_t pa;
	int dobounceflag = 0;
	int bounceindex;
	int i;
	int s;

	if (bouncepages == 0)
		return;

	vastart = (vm_offset_t) bp->b_un.b_addr;
	vaend = (vm_offset_t) bp->b_un.b_addr + bp->b_bcount;

	vapstart = i386_trunc_page(vastart);
	vapend = i386_round_page(vaend);
	countvmpg = (vapend - vapstart) / NBPG;

/*
 * if any page is above 16MB, then go into bounce-buffer mode
 */
	va = vapstart;
	for (i = 0; i < countvmpg; i++) {
		pa = pmap_kextract(va);
		if (pa >= SIXTEENMEG)
			++dobounceflag;
		va += NBPG;
	}
	if (dobounceflag == 0)
		return;

	if (bouncepages < dobounceflag) 
		panic("Not enough bounce buffers!!!");

/*
 * allocate a replacement kva for b_addr
 */
	kva = vm_bounce_kva(countvmpg);
	va = vapstart;
	for (i = 0; i < countvmpg; i++) {
		pa = pmap_kextract(va);
		if (pa >= SIXTEENMEG) {
			/*
			 * allocate a replacement page
			 */
			vm_offset_t bpa = vm_bounce_page_find(1);
			pmap_kenter(kva + (NBPG * i), bpa);
			/*
			 * if we are writing, the copy the data into the page
			 */
			if ((bp->b_flags & B_READ) == 0)
				bcopy((caddr_t) va, (caddr_t) kva + (NBPG * i), NBPG);
		} else {
			/*
			 * use original page
			 */
			pmap_kenter(kva + (NBPG * i), pa);
		}
		va += NBPG;
	}
	pmap_update();

/*
 * flag the buffer as being bounced
 */
	bp->b_flags |= B_BOUNCE;
/*
 * save the original buffer kva
 */
	bp->b_savekva = bp->b_un.b_addr;
/*
 * put our new kva into the buffer (offset by original offset)
 */
	bp->b_un.b_addr = (caddr_t) (((vm_offset_t) kva) |
				((vm_offset_t) bp->b_savekva & (NBPG - 1)));
	return;
}

/*
 * hook into biodone to free bounce buffer
 */
void
vm_bounce_free(bp)
	struct buf *bp;
{
	int i;
	vm_offset_t origkva, bouncekva;
	vm_offset_t vastart, vaend;
	vm_offset_t vapstart, vapend;
	int countbounce = 0;
	vm_offset_t firstbouncepa = 0;
	int firstbounceindex;
	int countvmpg;
	vm_offset_t bcount;
	int s;

/*
 * if this isn't a bounced buffer, then just return
 */
	if ((bp->b_flags & B_BOUNCE) == 0)
		return;

	origkva = (vm_offset_t) bp->b_savekva;
	bouncekva = (vm_offset_t) bp->b_un.b_addr;

	vastart = bouncekva;
	vaend = bouncekva + bp->b_bcount;
	bcount = bp->b_bcount;
	
	vapstart = i386_trunc_page(vastart);
	vapend = i386_round_page(vaend);

	countvmpg = (vapend - vapstart) / NBPG;

/*
 * check every page in the kva space for b_addr
 */
	for (i = 0; i < countvmpg; i++) {
		vm_offset_t mybouncepa;
		vm_offset_t copycount;

		copycount = i386_round_page(bouncekva + 1) - bouncekva;
		mybouncepa = pmap_kextract(i386_trunc_page(bouncekva));

/*
 * if this is a bounced pa, then process as one
 */
		if ((mybouncepa >= bouncepa) && (mybouncepa < bouncepaend)) {
			if (copycount > bcount)
				copycount = bcount;
/*
 * if this is a read, then copy from bounce buffer into original buffer
 */
			if (bp->b_flags & B_READ)
				bcopy((caddr_t) bouncekva, (caddr_t) origkva, copycount);
/*
 * free the bounce allocation
 */
			vm_bounce_page_free(i386_trunc_page(mybouncepa), 1);
		}

		origkva += copycount;
		bouncekva += copycount;
		bcount -= copycount;
	}

/*
 * add the old kva into the "to free" list
 */
	bouncekva = i386_trunc_page((vm_offset_t) bp->b_un.b_addr);
	kvaf[kvasfreecnt].addr = bouncekva;
	kvaf[kvasfreecnt++].size = countvmpg * NBPG;
	if (bmwait) {
		/*
		 * if anyone is waiting on the bounce-map, then wakeup
		 */
		wakeup((caddr_t) bounce_map);
		bmwait = 0;
	}

	bp->b_un.b_addr = bp->b_savekva;
	bp->b_savekva = 0;
	bp->b_flags &= ~B_BOUNCE;

	return;
}

#endif /* NOBOUNCE */

/*
 * Finish a fork operation, with process p2 nearly set up.
 * Copy and update the kernel stack and pcb, making the child
 * ready to run, and marking it so that it can return differently
 * than the parent.  Returns 1 in the child process, 0 in the parent.
 * We currently double-map the user area so that the stack is at the same
 * address in each process; in the future we will probably relocate
 * the frame pointers on the stack after copying.
 */
int
cpu_fork(p1, p2)
	register struct proc *p1, *p2;
{
	register struct user *up = p2->p_addr;
	int foo, offset, addr, i;
	extern char kstack[];
	extern int mvesp();

	/*
	 * Copy pcb and stack from proc p1 to p2. 
	 * We do this as cheaply as possible, copying only the active
	 * part of the stack.  The stack and pcb need to agree;
	 * this is tricky, as the final pcb is constructed by savectx,
	 * but its frame isn't yet on the stack when the stack is copied.
	 * swtch compensates for this when the child eventually runs.
	 * This should be done differently, with a single call
	 * that copies and updates the pcb+stack,
	 * replacing the bcopy and savectx.
	 */
	p2->p_addr->u_pcb = p1->p_addr->u_pcb;
	offset = mvesp() - (int)kstack;
	bcopy((caddr_t)kstack + offset, (caddr_t)p2->p_addr + offset,
	    (unsigned) ctob(UPAGES) - offset);
	p2->p_regs = p1->p_regs;

	/*
	 * Wire top of address space of child to it's kstack.
	 * First, fault in a page of pte's to map it.
	 */
#if 0
        addr = trunc_page((u_int)vtopte(kstack));
	vm_map_pageable(&p2->p_vmspace->vm_map, addr, addr+NBPG, FALSE);
	for (i=0; i < UPAGES; i++)
		pmap_enter(&p2->p_vmspace->vm_pmap, kstack+i*NBPG,
			   pmap_extract(kernel_pmap, ((int)p2->p_addr)+i*NBPG),
			   /*
			    * The user area has to be mapped writable because
			    * it contains the kernel stack (when CR0_WP is on
			    * on a 486 there is no user-read/kernel-write
			    * mode).  It is protected from user mode access
			    * by the segment limits.
			    */
			   VM_PROT_READ|VM_PROT_WRITE, TRUE);
#endif
	pmap_activate(&p2->p_vmspace->vm_pmap, &up->u_pcb);

	/*
	 * 
	 * Arrange for a non-local goto when the new process
	 * is started, to resume here, returning nonzero from setjmp.
	 */
	if (savectx(up, 1)) {
		/*
		 * Return 1 in child.
		 */
		return (1);
	}
	return (0);
}

#ifdef notyet
/*
 * cpu_exit is called as the last action during exit.
 *
 * We change to an inactive address space and a "safe" stack,
 * passing thru an argument to the new stack. Now, safely isolated
 * from the resources we're shedding, we release the address space
 * and any remaining machine-dependent resources, including the
 * memory for the user structure and kernel stack.
 *
 * Next, we assign a dummy context to be written over by swtch,
 * calling it to send this process off to oblivion.
 * [The nullpcb allows us to minimize cost in swtch() by not having
 * a special case].
 */
struct proc *swtch_to_inactive();
volatile void
cpu_exit(p)
	register struct proc *p;
{
	static struct pcb nullpcb;	/* pcb to overwrite on last swtch */

#if NNPX > 0
	npxexit(p);
#endif	/* NNPX */

	/* move to inactive space and stack, passing arg accross */
	p = swtch_to_inactive(p);

	/* drop per-process resources */
	vmspace_free(p->p_vmspace);
	kmem_free(kernel_map, (vm_offset_t)p->p_addr, ctob(UPAGES));

	p->p_addr = (struct user *) &nullpcb;
	splclock();
	swtch();
	/* NOTREACHED */
}
#else
void
cpu_exit(p)
	register struct proc *p;
{
	
#if NNPX > 0
	npxexit(p);
#endif	/* NNPX */
	splclock();
	curproc = 0;
	swtch();
	/* 
	 * This is to shutup the compiler, and if swtch() failed I suppose
	 * this would be a good thing.  This keeps gcc happy because panic
	 * is a volatile void function as well.
	 */
	panic("cpu_exit");
}

void
cpu_wait(p) struct proc *p; {
/*	extern vm_map_t upages_map; */
	extern char kstack[];

	/* drop per-process resources */
 	pmap_remove(vm_map_pmap(kernel_map), (vm_offset_t) p->p_addr,
		((vm_offset_t) p->p_addr) + ctob(UPAGES));
	kmem_free(kernel_map, (vm_offset_t)p->p_addr, ctob(UPAGES));
	vmspace_free(p->p_vmspace);
}
#endif

/*
 * Set a red zone in the kernel stack after the u. area.
 */
void
setredzone(pte, vaddr)
	u_short *pte;
	caddr_t vaddr;
{
/* eventually do this by setting up an expand-down stack segment
   for ss0: selector, allowing stack access down to top of u.
   this means though that protection violations need to be handled
   thru a double fault exception that must do an integral task
   switch to a known good context, within which a dump can be
   taken. a sensible scheme might be to save the initial context
   used by sched (that has physical memory mapped 1:1 at bottom)
   and take the dump while still in mapped mode */
}

/*
 * Convert kernel VA to physical address
 */
u_long
kvtop(void *addr)
{
	vm_offset_t va;

	va = pmap_kextract((vm_offset_t)addr);
	if (va == 0)
		panic("kvtop: zero page frame");
	return((int)va);
}

extern vm_map_t phys_map;

/*
 * Map an IO request into kernel virtual address space.  Requests fall into
 * one of five catagories:
 *
 *	B_PHYS|B_UAREA:	User u-area swap.
 *			Address is relative to start of u-area (p_addr).
 *	B_PHYS|B_PAGET:	User page table swap.
 *			Address is a kernel VA in usrpt (Usrptmap).
 *	B_PHYS|B_DIRTY:	Dirty page push.
 *			Address is a VA in proc2's address space.
 *	B_PHYS|B_PGIN:	Kernel pagein of user pages.
 *			Address is VA in user's address space.
 *	B_PHYS:		User "raw" IO request.
 *			Address is VA in user's address space.
 *
 * All requests are (re)mapped into kernel VA space via the useriomap
 * (a name with only slightly more meaning than "kernelmap")
 */
void
vmapbuf(bp)
	register struct buf *bp;
{
	register int npf;
	register caddr_t addr;
	register long flags = bp->b_flags;
	struct proc *p;
	int off;
	vm_offset_t kva;
	register vm_offset_t pa;

	if ((flags & B_PHYS) == 0)
		panic("vmapbuf");
	addr = bp->b_saveaddr = bp->b_un.b_addr;
	off = (int)addr & PGOFSET;
	p = bp->b_proc;
	npf = btoc(round_page(bp->b_bcount + off));
	kva = kmem_alloc_wait(phys_map, ctob(npf));
	bp->b_un.b_addr = (caddr_t) (kva + off);
	while (npf--) {
		pa = pmap_extract(&p->p_vmspace->vm_pmap, (vm_offset_t)addr);
		if (pa == 0)
			panic("vmapbuf: null page frame");
		pmap_kenter(kva, trunc_page(pa));
		addr += PAGE_SIZE;
		kva += PAGE_SIZE;
	}
	pmap_update();
}

/*
 * Free the io map PTEs associated with this IO operation.
 * We also invalidate the TLB entries and restore the original b_addr.
 */
void
vunmapbuf(bp)
	register struct buf *bp;
{
	register int npf;
	register caddr_t addr = bp->b_un.b_addr;
	vm_offset_t kva;

	if ((bp->b_flags & B_PHYS) == 0)
		panic("vunmapbuf");
	npf = btoc(round_page(bp->b_bcount + ((int)addr & PGOFSET)));
	kva = (vm_offset_t)((int)addr & ~PGOFSET);
	kmem_free_wakeup(phys_map, kva, ctob(npf));
	bp->b_un.b_addr = bp->b_saveaddr;
	bp->b_saveaddr = NULL;
}

/*
 * Force reset the processor by invalidating the entire address space!
 */
void
cpu_reset() {

	/* force a shutdown by unmapping entire address space ! */
	bzero((caddr_t) PTD, NBPG);

	/* "good night, sweet prince .... <THUNK!>" */
	tlbflush(); 
	/* NOTREACHED */
	while(1);
}

/*
 * Grow the user stack to allow for 'sp'. This version grows the stack in
 *	chunks of SGROWSIZ.
 */
int
grow(p, sp)
	struct proc *p;
	int sp;
{
	unsigned int nss;
	caddr_t v;
	struct vmspace *vm = p->p_vmspace;

	if ((caddr_t)sp <= vm->vm_maxsaddr || (unsigned)sp >= (unsigned)USRSTACK)
	    return (1);

	nss = roundup(USRSTACK - (unsigned)sp, PAGE_SIZE);

	if (nss > p->p_rlimit[RLIMIT_STACK].rlim_cur)
		return (0);

	if (vm->vm_ssize && roundup(vm->vm_ssize << PAGE_SHIFT,
	    SGROWSIZ) < nss) {
		int grow_amount;
		/*
		 * If necessary, grow the VM that the stack occupies
		 * to allow for the rlimit. This allows us to not have
		 * to allocate all of the VM up-front in execve (which
		 * is expensive).
		 * Grow the VM by the amount requested rounded up to
		 * the nearest SGROWSIZ to provide for some hysteresis.
		 */
		grow_amount = roundup((nss - (vm->vm_ssize << PAGE_SHIFT)), SGROWSIZ);
		v = (char *)USRSTACK - roundup(vm->vm_ssize << PAGE_SHIFT,
		    SGROWSIZ) - grow_amount;
		/*
		 * If there isn't enough room to extend by SGROWSIZ, then
		 * just extend to the maximum size
		 */
		if (v < vm->vm_maxsaddr) {
			v = vm->vm_maxsaddr;
			grow_amount = MAXSSIZ - (vm->vm_ssize << PAGE_SHIFT);
		}
		if (vm_allocate(&vm->vm_map, (vm_offset_t *)&v,
		    grow_amount, FALSE) != KERN_SUCCESS) {
			return (0);
		}
		vm->vm_ssize += grow_amount >> PAGE_SHIFT;
	}

	return (1);
}
