/*
 * Copyright (c) 1994, 1995 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Chris G. Demetriou
 * 
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" 
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND 
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 *	$NetBSD: isinf.c,v 1.1 1995/02/10 17:50:23 cgd Exp $
 */

/* For binary compat; to be removed in FreeBSD 6.0. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <machine/ieee.h>
#include <math.h>

#undef isnan
#undef isinf

int
isnan(d)
	double d;
{
	union {
		double v;
		struct ieee_double s;
	} u;

	u.v = d;
	return (u.s.dbl_exp == DBL_EXP_INFNAN &&
	    (u.s.dbl_frach || u.s.dbl_fracl));
}

int
isinf(d)
	double d;
{
	union {
		double v;
		struct ieee_double s;
	} u;

	u.v = d;
	return (u.s.dbl_exp == DBL_EXP_INFNAN &&
	    !u.s.dbl_frach && !u.s.dbl_fracl);
}
