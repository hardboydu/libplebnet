/*-
 * Copyright (c) 1998 Dag-Erling Co�dan Sm�rgrav
 * All rights reserved.
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
 *    derived from this software without specific prior written permission
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
 *	$Id: common.h,v 1.1 1998/11/05 19:48:16 des Exp $
 */

#ifndef _COMMON_H_INCLUDED
#define _COMMON_H_INCLUDED

/* Structure used for error message lists */
#define ERRCAT_
struct fetcherr {  
    const int num, cat;
    const char *string;
};

void		 _fetch_seterr(struct fetcherr *, int);
void		 _fetch_syserr(void);
int		 fetchConnect(char *, int);
    
#define _ftp_seterr(n)	 _fetch_seterr(_ftp_errlist, n)
#define _http_seterr(n)	 _fetch_seterr(_http_errlist, n)
#define _netdb_seterr(n) _fetch_seterr(_netdb_errlist, n)
#define _url_seterr(n)	 _fetch_seterr(_url_errlist, n)

#ifndef NDEBUG
#define DEBUG(x) do x; while (0)
#else
#define DEBUG(x) do { } while (0)
#endif

#endif
