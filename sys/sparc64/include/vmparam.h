/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 *	from: @(#)vmparam.h     5.9 (Berkeley) 5/12/91
 *	from: FreeBSD: src/sys/i386/include/vmparam.h,v 1.33 2000/03/30
 * $FreeBSD$
 */


#ifndef	_MACHINE_VMPARAM_H_
#define	_MACHINE_VMPARAM_H_

/*
 * Virtual memory related constants, all in bytes
 */
#ifndef MAXTSIZ
#define	MAXTSIZ		(1*1024*1024*1024)	/* max text size */
#endif
#ifndef DFLDSIZ
#define	DFLDSIZ		(128*1024*1024)		/* initial data size limit */
#endif
#ifndef MAXDSIZ
#define	MAXDSIZ		(1*1024*1024*1024)	/* max data size */
#endif
#ifndef	DFLSSIZ
#define	DFLSSIZ		(128*1024*1024)		/* initial stack size limit */
#endif
#ifndef	MAXSSIZ
#define	MAXSSIZ		(1*1024*1024*1024)	/* max stack size */
#endif
#ifndef	SGROWSIZ
#define	SGROWSIZ	(128*1024)		/* amount to grow stack */
#endif

/*
 * The time for a process to be blocked before being very swappable.
 * This is a number of seconds which the system takes as being a non-trivial
 * amount of real time.  You probably shouldn't change this;
 * it is used in subtle ways (fractions and multiples of it are, that is, like
 * half of a ``long time'', almost a long time, etc.)
 * It is related to human patience and other factors which don't really
 * change over time.
 */
#define	MAXSLP			20

#define	VM_MAXUSER_ADDRESS	(0x7fe00000000)

#define	USRSTACK		VM_MAXUSER_ADDRESS

#define	VM_MIN_ADDRESS		(0x100000)

/*
 * Virtual size (bytes) for various kernel submaps.
 */
#ifndef	VM_KMEM_SIZE
#define	VM_KMEM_SIZE		(12*1024*1024)
#endif

#define	VM_MIN_KERNEL_ADDRESS	(0x400000)
#define	VM_MAX_KERNEL_ADDRESS	(0xd0000000)

#define	KERNBASE		(0x400000)

/*
 * Initial pagein size of beginning of executable file.
 */
#ifndef	VM_INITIAL_PAGEIN
#define	VM_INITIAL_PAGEIN	16
#endif

#endif /* !_MACHINE_VMPARAM_H_ */
