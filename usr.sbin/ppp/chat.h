/*
 *	    Written by Toshiharu OHNO (tony-o@iij.ad.jp)
 *
 *   Copyright (C) 1993, Internet Initiative Japan, Inc. All rights reserverd.
 *
 *  Most of codes are derived from chat.c by Karl Fox (karl@MorningStar.Com).
 *
 *	Chat -- a program for automatic session establishment (i.e. dial
 *		the phone and log in).
 *
 *	This software is in the public domain.
 *
 *	Please send all bug reports, requests for information, etc. to:
 *
 *		Karl Fox <karl@MorningStar.Com>
 *		Morning Star Technologies, Inc.
 *		1760 Zollinger Road
 *		Columbus, OH  43221
 *		(614)451-1883
 *
 * $Id: chat.h,v 1.7 1997/08/25 00:29:07 brian Exp $
 *
 */

#define	VECSIZE(v)	(sizeof(v) / sizeof(v[0]))

extern char *ExpandString(char *, char *, int, int);
extern int MakeArgs(char *, char **, int);
extern int DoChat(char *);
