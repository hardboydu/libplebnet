/*-
 * Copyright (c) 1997, 1998
 *	Nan Yang Computer Services Limited.  All rights reserved.
 *
 *  This software is distributed under the so-called ``Berkeley
 *  License'':
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
 *	This product includes software developed by Nan Yang Computer
 *      Services Limited.
 * 4. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *  
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even if
 * advised of the possibility of such damage.
 *
 */

/* Header files used by all modules */
/* $Id: vinumhdr.h,v 1.1.1.1 1998/09/16 05:56:21 grog Exp $ */

#ifdef KERNEL
#define REALLYKERNEL
#endif
#include <sys/param.h>
#ifdef REALLYKERNEL
#include <sys/systm.h>
#include <sys/kernel.h>
#endif
#ifdef DEVFS
#error "DEVFS code not complete yet"
#include <sys/devfsext.h>
#endif /*DEVFS */
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/dkstat.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/namei.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/disklabel.h>
#include <ufs/ffs/fs.h>
#include <sys/mount.h>
#include <sys/device.h>
#undef KERNEL						    /* XXX */
#include <sys/disk.h>
#ifdef REALLYKERNEL
#define KERNEL
#endif
#include <sys/syslog.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/dkbad.h>
#include <setjmp.h>
#include <stdarg.h>
#include <vm/vm.h>
#ifdef USES_VM
/* XXX Do we need this? */
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_prot.h>
/* #include <vm/vm_page.h> */
#include <sys/vmmeter.h>
/* #include <machine/pmap.h> */
#endif							    /* USES_VM */
#include <vinumvar.h>
#include <vinumio.h>
#include "vinumkw.h"
#include "vinumext.h"

#undef Free						    /* defined in some funny net stuff */
#ifdef REALLYKERNEL
#define Malloc(x)  MMalloc ((x), __FILE__, __LINE__)	    /* show where we came from */
#define Free(x)	   FFree ((x), __FILE__, __LINE__)	    /* show where we came from */
caddr_t MMalloc (int size, char *, int);
void FFree (void *mem, char *, int);
#else
#define Malloc(x)  malloc ((x))				    /* just the size */
#define Free(x)	   free ((x))				    /* just the address */
#endif

