/*
 *	    Written by Toshiharu OHNO (tony-o@iij.ad.jp)
 *
 *   Copyright (C) 1993, Internet Initiative Japan, Inc. All rights reserverd.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Internet Initiative Japan.  The name of the
 * IIJ may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id: cdefs.h,v 1.3 1997/02/22 16:10:04 peter Exp $
 *
 *	TODO:
 */

#ifndef __P
#if defined(__bsdi__) || defined(__FreeBSD__)
#include <sys/cdefs.h>
#else
#ifdef __STDC__
#define __P(arg) arg
#else
#define __P(arg) ()
#endif /* __STDC__ */
#endif /* __bsdi__ */
#endif /* __P */
