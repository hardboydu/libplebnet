/*
 * Copyright (c) 1999 - 2000 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "krb5_locl.h"

RCSID("$Id: expand_hostname.c,v 1.5 2000/01/08 08:07:18 assar Exp $");

static krb5_error_code
copy_hostname(krb5_context context,
	      const char *orig_hostname,
	      char **new_hostname)
{
    *new_hostname = strdup (orig_hostname);
    if (*new_hostname == NULL)
	return ENOMEM;
    return 0;
}

/*
 * Try to make `orig_hostname' into a more canonical one in the newly
 * allocated space returned in `new_hostname'.
 */

krb5_error_code
krb5_expand_hostname (krb5_context context,
		      const char *orig_hostname,
		      char **new_hostname)
{
    struct addrinfo *ai, *a, hints;
    int error;

    memset (&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;

    error = getaddrinfo (orig_hostname, NULL, &hints, &ai);
    if (error)
	return copy_hostname (context, orig_hostname, new_hostname);
    for (a = ai; a != NULL; a = a->ai_next) {
	if (a->ai_canonname != NULL) {
	    *new_hostname = strdup (a->ai_canonname);
	    freeaddrinfo (ai);
	    if (*new_hostname == NULL)
		return ENOMEM;
	    else
		return 0;
	}
    }
    freeaddrinfo (ai);
    return copy_hostname (context, orig_hostname, new_hostname);
}
