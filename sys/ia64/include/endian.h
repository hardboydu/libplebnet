/*-
 * Copyright (c) 1987, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)endian.h	8.1 (Berkeley) 6/10/93
 *	$NetBSD: endian.h,v 1.5 1997/10/09 15:42:19 bouyer Exp $
 * $FreeBSD$
 */

#ifndef _MACHINE_ENDIAN_H_
#define	_MACHINE_ENDIAN_H_

#include <sys/cdefs.h>
#include <machine/ansi.h>

/*
 * Define the order of 32-bit words in 64-bit words.
 */
#define _QUAD_HIGHWORD 1
#define _QUAD_LOWWORD 0

/*
 * Definitions for byte order, according to byte significance from low
 * address to high.
 */
#ifndef _POSIX_SOURCE
#define	LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#define	BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */
#define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in long */

#define	BYTE_ORDER	LITTLE_ENDIAN
#endif /* !_POSIX_SOURCE */

#ifdef _KERNEL
#ifdef __GNUC__

#define	_BSWAP64_DEFINED
static __inline __uint64_t
__bswap64(__uint64_t __x)
{
	__uint64_t __r;
	__asm __volatile("mux1 %0=%1,@rev"
			 : "=r" (__r) : "r"(__x));
	return __r;
}

#define	_BSWAP32_DEFINED
static __inline __uint32_t
__bswap32(__uint32_t __x)
{

	return (__bswap64(__x) >> 32);
}

#define	_BSWAP16_DEFINED
static __inline __uint16_t
__bswap16(__uint16_t __x)
{

	return (__bswap64(__x) >> 48);
}

#else /* !__GNUC__ */
/* XXX: use the libkern versions for now; these might go away soon. */
#define	_BSWAP16_DEFINED
__uint16_t __bswap16(__uint16_t);
#define	_BSWAP32_DEFINED
__uint32_t __bswap32(__uint32_t);
#endif /* __GNUC__ */

#endif /* _KERNEL */

#endif /* !_MACHINE_ENDIAN_H_ */
