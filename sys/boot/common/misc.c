/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 *	$Id: misc.c,v 1.1.1.1 1998/08/21 03:17:41 msmith Exp $
 */

#include <string.h>
#include <stand.h>
#include <bootstrap.h>

/*
 * Concatenate the (argc) elements of (argv) into a single string, and return
 * a copy of same.
 */
char *
unargv(int argc, char *argv[])
{
    size_t	hlong;
    int		i;
    char	*cp;

    for (hlong = 0, i = 0, hlong = 0; i < argc; i++)
	hlong += strlen(argv[i]) + 1;

    if(hlong == 0)
	return(NULL);

    cp = malloc(hlong);
    cp[0] = 0;
    for (i = 0; i < argc; i++)
	strcat(cp, argv[i]);
    return(cp);
}

/*
 * Get the length of a string in kernel space
 */
size_t
strlenout(vm_offset_t src)
{
    char	c;
    size_t	len;
    
    for (len = 0; ; len++) {
	archsw.arch_copyout(src++, &c, 1);
	if (c == 0)
	    break;
    }
    return(len);
}

/*
 * Make a duplicate copy of a string in kernel space
 */
char *
strdupout(vm_offset_t str)
{
    char	*result, *cp;
    
    result = malloc(strlenout(str) + 1);
    for (cp = result; ;cp++) {
	archsw.arch_copyout(str++, cp, 1);
	if (*cp == 0)
	    break;
    }
    return(result);
}
