/*-
 * Copyright (c) 2003-2004 Tim Kientzle
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#ifdef DMALLOC
#include <dmalloc.h>
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "archive_private.h"

static void
diediedie(void)
{
	*(char *)0 = 1;	/* Deliberately segfault and force a coredump. */
	_exit(1);	/* If that didn't work, just exit with an error. */
}

static const char *
state_name(unsigned s)
{
	switch (s) {
	case ARCHIVE_STATE_NEW:		return ("new");
	case ARCHIVE_STATE_HEADER:	return ("header");
	case ARCHIVE_STATE_DATA:	return ("data");
	case ARCHIVE_STATE_EOF:		return ("eof");
	case ARCHIVE_STATE_CLOSED:	return ("closed");
	case ARCHIVE_STATE_FATAL:	return ("fatal");
	default:			return ("??");
	}
}


static void
write_all_states(FILE *f, int states)
{
	unsigned lowbit;

	/* A trick for computing the lowest set bit. */
	while ((lowbit = states & (-states)) != 0) {
		states &= ~lowbit;		/* Clear the low bit. */
		fprintf(f, "%s%s", state_name(lowbit),
		    (states != 0) ? "/" : "");
	}
}

/*
 * Check magic value and current state; bail if it isn't valid.
 *
 * This is designed to catch serious programming errors that violate
 * the libarchive API.
 */
void
__archive_check_magic(struct archive *a, unsigned magic, unsigned state,
    const char *function)
{
	if (a->magic != magic) {
		fprintf(stderr, "INTERNAL ERROR: Function %s invoked"
		    " with invalid struct archive structure.\n", function);
		diediedie();
	}

	if (state == ARCHIVE_STATE_ANY)
		return;

	if ((a->state & state) == 0) {
		fprintf(stderr, "INTERNAL ERROR: Function '%s' invoked"
		    " with archive structure in state '", function);
		write_all_states(stderr, a->state);
		fprintf(stderr,"', should be in state '");
		write_all_states(stderr, state);
		fprintf(stderr, "'\n");
		diediedie();
	}
}
