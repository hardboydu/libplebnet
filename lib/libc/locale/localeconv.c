/*
 * Copyright (c) 2001 Alexey Zelkin
 * Copyright (c) 1991, 1993
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
static char sccsid[] = "@(#)localeconv.c	8.1 (Berkeley) 6/4/93";
#endif
static char rcsid[] = "$FreeBSD$";
#endif /* LIBC_SCCS and not lint */

#include <locale.h>
#include <stdlib.h>
#include <limits.h>
#include "lmonetary.h"
#include "lnumeric.h"

/* 
 * The localeconv() function constructs a struct lconv from the current
 * monetary and numeric locales.
 *
 * Because localeconv() may be called many times (especially by library
 * routines like printf() & strtod()), the approprate members of the 
 * lconv structure are computed only when the monetary or numeric 
 * locale has been changed.
 */
int __mlocale_changed = 1;
int __nlocale_changed = 1;

/* XXX: FIXME! */
/* Numbers separated by ";" must be parsed into byte array. */
static char nogrouping[] = { CHAR_MAX, '\0' };

static char
cnv(char *str) {
	int i = strtol(str, NULL, 10);
	if (i == -1)
		i = CHAR_MAX;
	return (char)i;
}

/*
 * Return the current locale conversion.
 */
struct lconv *
localeconv()
{
    static struct lconv ret;

    if (__mlocale_changed) {
	/* LC_MONETARY part */
        struct lc_monetary_T * mptr; 

#define M_ASSIGN_STR(NAME) (ret.NAME = (char*)mptr->NAME)
#define M_ASSIGN_CHAR(NAME) (ret.NAME = cnv((char*)mptr->NAME))

	mptr = __get_current_monetary_locale();
	M_ASSIGN_STR(int_curr_symbol);
	M_ASSIGN_STR(currency_symbol);
	M_ASSIGN_STR(mon_decimal_point);
	M_ASSIGN_STR(mon_thousands_sep);
	/* XXX: FIXME! */
	/* Numbers separated by ";" must be parsed into byte array. */
	ret.mon_grouping = nogrouping;
	M_ASSIGN_STR(positive_sign);
	M_ASSIGN_STR(negative_sign);
	M_ASSIGN_CHAR(int_frac_digits);
	M_ASSIGN_CHAR(frac_digits);
	M_ASSIGN_CHAR(p_cs_precedes);
	M_ASSIGN_CHAR(p_sep_by_space);
	M_ASSIGN_CHAR(n_cs_precedes);
	M_ASSIGN_CHAR(n_sep_by_space);
	M_ASSIGN_CHAR(p_sign_posn);
	M_ASSIGN_CHAR(n_sign_posn);
	__mlocale_changed = 0;
    }

    if (__nlocale_changed) {
	/* LC_NUMERIC part */
        struct lc_numeric_T * nptr; 

#define N_ASSIGN_STR(NAME) (ret.NAME = (char*)nptr->NAME)

	nptr = __get_current_numeric_locale();
	N_ASSIGN_STR(decimal_point);
	N_ASSIGN_STR(thousands_sep);
	/* XXX: FIXME! */
	/* Numbers separated by ";" must be parsed into byte array. */
	ret.grouping = nogrouping;
	__nlocale_changed = 0;
    }

    return (&ret);
}
