/*-
 * Copyright (c) 1993 The Regents of the University of California.
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
 *	$Id: sysarch.h,v 1.8 1998/02/03 20:46:18 bde Exp $
 */

/*
 * Architecture specific syscalls (i386)
 */
#ifndef _MACHINE_SYSARCH_H_
#define _MACHINE_SYSARCH_H_

#define I386_GET_LDT	0
#define I386_SET_LDT	1
				/* I386_IOPL */
#define I386_GET_IOPERM	3
#define I386_SET_IOPERM	4
				/* xxxxx */
#define I386_VM86	6

#ifndef KERNEL
#include <sys/cdefs.h>

union descriptor;

__BEGIN_DECLS
int i386_get_ldt __P((int, union descriptor *, int));
int i386_set_ldt __P((int, union descriptor *, int));
int i386_get_ioperm __P((u_int, u_int *, int *));
int i386_set_ioperm __P((u_int, u_int, int));
int i386_vm86 __P((int, void *));
__END_DECLS
#endif /* !KERNEL */

#endif /* !_MACHINE_SYSARCH_H_ */
