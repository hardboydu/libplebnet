/*-
 * Copyright (c) 1994-1995 S�ren Schmidt
 * All rights reserved.
 *
 * Based heavily on /sys/kern/imgact_aout.c which is:
 * Copyright (c) 1993, David Greenman
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer 
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
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
 *
 *	$Id: imgact_linux.c,v 1.1 1995/06/25 17:32:32 sos Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/exec.h>
#include <sys/mman.h>
#include <sys/imgact.h>
#include <sys/imgact_aout.h>
#include <sys/kernel.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>

int
exec_linux_imgact(iparams)
    struct image_params *iparams;
{
    struct exec *a_out = (struct exec *) iparams->image_header;
    struct vmspace *vmspace = iparams->proc->p_vmspace;
    unsigned long vmaddr, virtual_offset, file_offset;
    unsigned long buffer, bss_size;
    int error;
    extern struct sysentvec linux_sysvec;

    if (((a_out->a_magic >> 16) & 0xff) != 0x64)
	return -1;

    /*
     * Set file/virtual offset based on a.out variant.
     */
    switch ((int)(a_out->a_magic & 0xffff)) {
    case 0413:
	virtual_offset = 0;
	file_offset = 1024;
	break;
    case 0314:
	virtual_offset = 4096;
	file_offset = 0;
	break;
    default:
	return (-1);
    }
    bss_size = round_page(a_out->a_bss);

    /*
     * Check various fields in header for validity/bounds.
     */
    if (a_out->a_entry < virtual_offset ||
	a_out->a_entry >= virtual_offset + a_out->a_text ||
	a_out->a_text % NBPG || a_out->a_data % NBPG)
	return (-1);

    /* text + data can't exceed file size */
    if (a_out->a_data + a_out->a_text > iparams->attr->va_size)
	return (EFAULT);
    /*
     * text/data/bss must not exceed limits
     */
    if (a_out->a_text > MAXTSIZ || a_out->a_data + bss_size > MAXDSIZ ||
	a_out->a_data+bss_size > iparams->proc->p_rlimit[RLIMIT_DATA].rlim_cur)
	return (ENOMEM);

    /* copy in arguments and/or environment from old process */
    error = exec_extract_strings(iparams);
    if (error)
	return (error);

    /*
     * Destroy old process VM and create a new one (with a new stack)
     */
    exec_new_vmspace(iparams);

    /*
     * Check if file_offset page aligned,.
     * Currently we cannot handle misalinged file offsets,
     * and so we read in the entire image (what a waste).
     */
    if (file_offset & PGOFSET) {
#ifdef DEBUG
	printf("imgact: Non page aligned binary %d\n", file_offset);
#endif
	/*
	 * Map text read/execute
	 */
	vmaddr = virtual_offset;
	error = vm_map_find(&vmspace->vm_map, NULL, 0, &vmaddr,
		    	    round_page(a_out->a_text), FALSE);
	if (error)
	    return error;

	error = vm_mmap(kernel_map, &buffer,
			round_page(a_out->a_text + file_offset),
			VM_PROT_READ, VM_PROT_READ, MAP_FILE,
			(caddr_t) iparams->vnodep, trunc_page(file_offset));
	if (error)
	    return error;

	error = copyout((caddr_t)(buffer + file_offset), (caddr_t)vmaddr, 
			a_out->a_text);
	if (error)
	    return error;

	vm_map_remove(kernel_map, trunc_page(vmaddr),
		      round_page(a_out->a_text + file_offset));

	error = vm_map_protect(&vmspace->vm_map, vmaddr,
		   	       round_page(a_out->a_text),
		   	       VM_PROT_EXECUTE|VM_PROT_READ, TRUE);
	if (error)
	    return error;
	/*
	 * Map data read/write 
	 */
	vmaddr = virtual_offset + a_out->a_text;
	error = vm_map_find(&vmspace->vm_map, NULL, 0, &vmaddr,
		      	    round_page(a_out->a_data + bss_size), FALSE);
	if (error)
	    return error;

	error = vm_mmap(kernel_map, &buffer,
			round_page(a_out->a_data + file_offset),
			VM_PROT_READ, VM_PROT_READ, MAP_FILE,
			(caddr_t) iparams->vnodep,
			trunc_page(a_out->a_text + file_offset));
	if (error)
	    return error;

	error = copyout((caddr_t)(buffer + file_offset), 
			(caddr_t)vmaddr, 
			a_out->a_data);
	if (error)
	    return error;

	vm_map_remove(kernel_map, trunc_page(vmaddr),
		      round_page(a_out->a_data + file_offset));

	error = vm_map_protect(&vmspace->vm_map, vmaddr,
		   	       round_page(a_out->a_data + bss_size),
		   	       VM_PROT_WRITE|VM_PROT_READ, TRUE);
	if (error)
	    return error;
    }
    else {
#ifdef DEBUG
	printf("imgact: Page aligned binary %d\n", file_offset);
#endif
	/*
	 * Map text read/execute
	 */
	vmaddr = virtual_offset;
	error = vm_mmap(&vmspace->vm_map, &vmaddr, a_out->a_text,
	    		VM_PROT_READ | VM_PROT_EXECUTE,
	    		VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE,
	    		MAP_PRIVATE | MAP_FIXED,
	    		(caddr_t)iparams->vnodep, file_offset);
	if (error)
	    return (error);
    
	/*
	 * Map data read/write 
	 */
	vmaddr = virtual_offset + a_out->a_text;
	error = vm_mmap(&vmspace->vm_map, &vmaddr, a_out->a_data,
			VM_PROT_READ | VM_PROT_WRITE,
			VM_PROT_ALL, MAP_PRIVATE | MAP_FIXED,
			(caddr_t)iparams->vnodep, file_offset + a_out->a_text);
	if (error)
	    return (error);
    
	/*
	 * Allocate demand-zeroed area for uninitialized data
	 */
	if (bss_size != 0) {
	    vmaddr = virtual_offset + a_out->a_text + a_out->a_data;
	    error = vm_map_find(&vmspace->vm_map, NULL, 0, &vmaddr, 
				bss_size, FALSE);
	    if (error)
		return (error);
	}
	/* Indicate that this file should not be modified */
	iparams->vnodep->v_flag |= VTEXT;
    }
    /* Fill in process VM information */
    vmspace->vm_tsize = round_page(a_out->a_text) >> PAGE_SHIFT;
    vmspace->vm_dsize = round_page(a_out->a_data + bss_size) >> PAGE_SHIFT;
    vmspace->vm_taddr = (caddr_t)virtual_offset;
    vmspace->vm_daddr = (caddr_t)virtual_offset + a_out->a_text;

    /* Fill in image_params */
    iparams->interpreted = 0;
    iparams->entry_addr = a_out->a_entry;
    
    iparams->proc->p_sysent = &linux_sysvec;
    return (0);
}

/*
 * Tell kern_execve.c about it, with a little help from the linker.
 * Since `const' objects end up in the text segment, TEXT_SET is the
 * correct directive to use.
 */
const struct execsw linux_execsw = { exec_linux_imgact, "linux" };
TEXT_SET(execsw_set, linux_execsw);

