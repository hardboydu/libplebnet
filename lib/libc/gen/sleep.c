/*
 * Copyright (c) 1989, 1993
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
 */

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)sleep.c	8.1 (Berkeley) 6/4/93";
#endif
static char rcsid[] =
	"$Id: sleep.c,v 1.23 1998/09/05 08:01:26 jb Exp $";
#endif /* LIBC_SCCS and not lint */

#include <errno.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

/*
 * sleep() -	attempt to sleep the specified number of seconds, returning
 *		any remaining unslept time if interrupted or 0 if the entire
 *		sleep completes without being interrupted.  Avoid seconds vs
 *		time_t typing problems by breaking down large times with a
 *		loop.
 */

unsigned int
sleep(seconds)
	unsigned int seconds;
{
	while (seconds != 0) {
		struct timespec time_to_sleep;
		struct timespec time_remaining;

		time_to_sleep.tv_sec  = (seconds > INT_MAX) ? INT_MAX : seconds;
		time_to_sleep.tv_nsec = 0;

		if (nanosleep(&time_to_sleep, &time_remaining) == -1) {
			/*
			 * time_remaining only valid if EINTR, else assume no
			 * time elapsed.
			 */
			if (errno == EINTR)
				seconds -= time_to_sleep.tv_sec - time_remaining.tv_sec;
			if (time_remaining.tv_nsec)
				++seconds;
			break;
		}
		seconds -= time_to_sleep.tv_sec;
	}
	return(seconds);
}

