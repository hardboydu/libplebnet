/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id: hesiod_p.h,v 1.2.18.1 2005/04/27 05:00:59 sra Exp $
 */

#ifndef _HESIOD_P_H_INCLUDED
#define _HESIOD_P_H_INCLUDED

/** \file
 * \brief
 * hesiod_p.h -- private definitions for the hesiod library.
 *
 * \author
 * This file is primarily maintained by tytso@mit.edu and ghudson@mit.edu.
 */

#define DEF_RHS		".Athena.MIT.EDU"	/*%< Defaults if HESIOD_CONF */
#define DEF_LHS		".ns"			/*%<    file is not */
						/*%<    present. */
struct hesiod_p {
	char *		LHS;		/*%< normally ".ns" */
	char *		RHS;		/*%< AKA the default hesiod domain */
	struct __res_state * res;	/*%< resolver context */
	void		(*free_res)(void *);
	void		(*res_set)(struct hesiod_p *, struct __res_state *,
				   void (*)(void *));
	struct __res_state * (*res_get)(struct hesiod_p *);
};

#define MAX_HESRESP	1024

#endif /*_HESIOD_P_H_INCLUDED*/
