/*-
 * Copyright (c) 2002-2004 Tim J. Robbins. All rights reserved.
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
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
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)big5.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/param.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <runetype.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

extern size_t (*__mbrtowc)(wchar_t * __restrict, const char * __restrict,
    size_t, mbstate_t * __restrict);
extern int (*__mbsinit)(const mbstate_t *);
extern size_t (*__wcrtomb)(char * __restrict, wchar_t, mbstate_t * __restrict);

int	_BIG5_init(_RuneLocale *);
size_t	_BIG5_mbrtowc(wchar_t * __restrict, const char * __restrict, size_t,
	    mbstate_t * __restrict);
int	_BIG5_mbsinit(const mbstate_t *);
size_t	_BIG5_wcrtomb(char * __restrict, wchar_t, mbstate_t * __restrict);

typedef struct {
	int	count;
	u_char	bytes[2];
} _BIG5State;

int
_BIG5_init(_RuneLocale *rl)
{

	__mbrtowc = _BIG5_mbrtowc;
	__wcrtomb = _BIG5_wcrtomb;
	__mbsinit = _BIG5_mbsinit;
	_CurrentRuneLocale = rl;
	__mb_cur_max = 2;
	return (0);
}

int
_BIG5_mbsinit(const mbstate_t *ps)
{

	return (ps == NULL || ((const _BIG5State *)ps)->count == 0);
}

static __inline int
_big5_check(u_int c)
{

	c &= 0xff;
	return ((c >= 0xa1 && c <= 0xfe) ? 2 : 1);
}

size_t
_BIG5_mbrtowc(wchar_t * __restrict pwc, const char * __restrict s, size_t n,
    mbstate_t * __restrict ps)
{
	_BIG5State *bs;
	wchar_t wc;
	int i, len, ocount;
	size_t ncopy;

	bs = (_BIG5State *)ps;

	if (bs->count < 0 || bs->count > sizeof(bs->bytes)) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (s == NULL) {
		s = "";
		n = 1;
		pwc = NULL;
	}

	ncopy = MIN(MIN(n, MB_CUR_MAX), sizeof(bs->bytes) - bs->count);
	memcpy(bs->bytes + bs->count, s, ncopy);
	ocount = bs->count;
	bs->count += ncopy;
	s = (char *)bs->bytes;
	n = bs->count;

	if (n == 0 || (size_t)(len = _big5_check(*s)) > n)
		/* Incomplete multibyte sequence */
		return ((size_t)-2);
	wc = 0;
	i = len;
	while (i-- > 0)
		wc = (wc << 8) | (unsigned char)*s++;
	if (pwc != NULL)
		*pwc = wc;
	bs->count = 0;
	return (wc == L'\0' ? 0 : len - ocount);
}

size_t
_BIG5_wcrtomb(char * __restrict s, wchar_t wc, mbstate_t * __restrict ps)
{
	_BIG5State *bs;

	bs = (_BIG5State *)ps;

	if (bs->count != 0) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (s == NULL)
		/* Reset to initial shift state (no-op) */
		return (1);
	if (wc & 0x8000) {
		*s++ = (wc >> 8) & 0xff;
		*s = wc & 0xff;
		return (2);
	}
	*s = wc & 0xff;
	return (1);
}
