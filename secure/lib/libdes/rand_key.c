/* crypto/des/rand_key.c */
/* Copyright (C) 1995-1996 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 * 
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
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
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "des_locl.h"
#include <time.h>

static int seed=0;
static des_cblock init;

void des_random_seed(key)
des_cblock key;
	{
	memcpy(init,key,sizeof(des_cblock));
	seed=1;
	}

void des_random_key(ret)
unsigned char *ret;
	{
	des_key_schedule ks;
	static DES_LONG c=0;
	static unsigned short pid=0;
	static des_cblock data={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	des_cblock key;
	unsigned char *p;
	DES_LONG t;
	int i;

#ifdef MSDOS
	pid=1;
#else
	if (!pid) pid=getpid();
#endif
	p=key;
	if (seed)
		{
		for (i=0; i<8; i++)
			{
			data[i] ^= init[i];
			init[i]=0;
			}
		seed=0;
		}
	t=(DES_LONG)time(NULL);
	l2c(t,p);
	t=(DES_LONG)((pid)|((c++)<<16));
	l2c(t,p);

	des_set_odd_parity((des_cblock *)data);
	des_set_key((des_cblock *)data,ks);
	des_cbc_cksum((des_cblock *)key,(des_cblock *)key,
		(long)sizeof(key),ks,(des_cblock *)data);

	des_set_odd_parity((des_cblock *)key);
	des_set_key((des_cblock *)key,ks);
	des_cbc_cksum((des_cblock *)key,(des_cblock *)data,
		(long)sizeof(key),ks,(des_cblock *)key);

	memcpy(ret,data,sizeof(key));
	memset(key,0,sizeof(key));
	memset(ks,0,sizeof(ks));
	t=0;
	}
