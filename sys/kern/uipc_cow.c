/*-
 * Copyright (c) 1997, Duke University
 * All rights reserved.
 *
 * Author:
 *         Andrew Gallatin <gallatin@cs.duke.edu>  
 *            
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of Duke University may not be used to endorse or promote 
 *    products derived from this software without specific prior written 
 *    permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY DUKE UNIVERSITY ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DUKE UNIVERSITY BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITSOR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  
 */

/*
 * This is a set of routines for enabling and disabling copy on write
 * protection for data written into sockets.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/sf_buf.h>
#include <sys/socketvar.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>


struct netsend_cow_stats {
	int attempted;
	int fail_not_mapped;
	int fail_sf_buf;
	int success;
	int iodone;
};

static struct netsend_cow_stats socow_stats;

static void socow_iodone(void *addr, void *args);

static void
socow_iodone(void *addr, void *args)
{	
	int s;
	struct sf_buf *sf;
	vm_page_t pp;

	sf = args;
	pp = sf_buf_page(sf);
	s = splvm();
	/* remove COW mapping  */
	vm_page_lock_queues();
	vm_page_cowclear(pp);
	vm_page_unlock_queues();
	splx(s);
	/* note that sf_buf_free() unwires the page for us*/
	sf_buf_free(addr, args);
	socow_stats.iodone++;
}

int
socow_setup(struct mbuf *m0, struct uio *uio)
{
	struct sf_buf *sf;
	vm_page_t pp;
	vm_paddr_t pa;
	struct iovec *iov;
	struct vmspace *vmspace;
	struct vm_map *map;
	vm_offset_t uva;
	int s;

	vmspace = curproc->p_vmspace;
	map = &vmspace->vm_map;
	uva = (vm_offset_t) uio->uio_iov->iov_base;

	s = splvm();

       /* 
	* verify page is mapped & not already wired for i/o
	*/
	socow_stats.attempted++;
	pa=pmap_extract(map->pmap, uva);
	if(!pa) {
		socow_stats.fail_not_mapped++;
		splx(s);
		return(0);
	}
	pp = PHYS_TO_VM_PAGE(pa);

	/* 
	 * set up COW
	 */
	vm_page_lock_queues();
	vm_page_cowsetup(pp);

	/*
	 * wire the page for I/O
	 */
	vm_page_wire(pp);
	vm_page_unlock_queues();

	/*
	 * Allocate an sf buf
	 */
	sf = sf_buf_alloc(pp);
	if (!sf) {
		vm_page_lock_queues();
		vm_page_cowclear(pp);
		vm_page_unwire(pp, 0);
		/*
		 * Check for the object going away on us. This can
		 * happen since we don't hold a reference to it.
		 * If so, we're responsible for freeing the page.
		 */
		if (pp->wire_count == 0 && pp->object == NULL)
			vm_page_free(pp);
		vm_page_unlock_queues();
		socow_stats.fail_sf_buf++;
		splx(s);
		return(0);
	}
	/* 
	 * attach to mbuf
	 */
	m0->m_data = (caddr_t)sf_buf_kva(sf);
	m0->m_len = PAGE_SIZE;
	MEXTADD(m0, sf_buf_kva(sf), PAGE_SIZE, socow_iodone, sf, M_RDONLY,
	    EXT_SFBUF);
	socow_stats.success++;

	iov = uio->uio_iov;
	iov->iov_base = (char *)iov->iov_base + PAGE_SIZE;
	iov->iov_len -= PAGE_SIZE;
	uio->uio_resid -= PAGE_SIZE;
	uio->uio_offset += PAGE_SIZE;
	if (iov->iov_len == 0) {
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}

	splx(s);
	return(1);
}
