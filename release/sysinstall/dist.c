/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: dist.c,v 1.120 1997/10/13 12:12:14 jkh Exp $
 *
 * Copyright (c) 1995
 *	Jordan Hubbard.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    verbatim and that no modifications are made prior to this
 *    point in the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY JORDAN HUBBARD ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JORDAN HUBBARD OR HIS PETS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, LIFE OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "sysinstall.h"
#include <sys/time.h>
#include <signal.h>

unsigned int Dists;
unsigned int DESDists;
unsigned int SrcDists;
#ifndef USE_XIG_ENVIRONMENT
unsigned int XF86Dists;
unsigned int XF86ServerDists;
unsigned int XF86FontDists;
#endif

typedef struct _dist {
    char *my_name;
    char *my_dir;
    unsigned int *my_mask;
    unsigned int my_bit;
    struct _dist *my_dist;
} Distribution;

extern Distribution DistTable[];
extern Distribution DESDistTable[];
extern Distribution SrcDistTable[];
#ifndef USE_XIG_ENVIRONMENT
extern Distribution XF86DistTable[];
extern Distribution XF86FontDistTable[];
extern Distribution XF86ServerDistTable[];
#endif

/* The top-level distribution categories */
static Distribution DistTable[] = {
{ "bin",	"/",			&Dists,		DIST_BIN,		NULL		},
{ "doc",	"/",			&Dists,		DIST_DOC,		NULL		},
{ "games",	"/",			&Dists,		DIST_GAMES,		NULL		},
{ "manpages",	"/",			&Dists,		DIST_MANPAGES,		NULL		},
{ "catpages",	"/",			&Dists,		DIST_CATPAGES,		NULL		},
{ "proflibs",	"/",			&Dists,		DIST_PROFLIBS,		NULL		},
{ "dict",	"/",			&Dists,		DIST_DICT,		NULL		},
{ "info",	"/",			&Dists,		DIST_INFO,		NULL		},
{ "src",	"/",			&Dists,		DIST_SRC,		SrcDistTable	},
{ "des",	"/",			&Dists,		DIST_DES,		DESDistTable	},
{ "compat1x",	"/",			&Dists,		DIST_COMPAT1X,		NULL		},
{ "compat20",	"/",			&Dists,		DIST_COMPAT20,		NULL		},
{ "compat21",	"/",			&Dists,		DIST_COMPAT21,		NULL		},
{ "ports",	"/usr",			&Dists,		DIST_PORTS,		NULL		},
#ifdef USE_XIG_ENVIRONMENT
{ "accelx",	"/usr/X11R6/lib/X11",	&Dists,		DIST_XIG_SERVER,	NULL		},
#else
{ "XF86331",	"/usr",			&Dists,		DIST_XF86,		XF86DistTable	},
#endif
{ NULL },
};

/* The DES distribution (not for export!) */
static Distribution DESDistTable[] = {
{ "des",        "/",                    &DESDists,	DIST_DES_DES,		NULL		},
{ "krb",	"/",			&DESDists,	DIST_DES_KERBEROS,	NULL		},
{ "ssecure",	"/usr/src",		&DESDists,	DIST_DES_SSECURE,	NULL		},
{ "scrypto",	"/usr/src",		&DESDists,	DIST_DES_SCRYPTO,	NULL		},
{ "skerbero",	"/usr/src",		&DESDists,	DIST_DES_SKERBEROS,	NULL		},
{ NULL },
};

/* The /usr/src distribution */
static Distribution SrcDistTable[] = {
{ "sbase",	"/usr/src",		&SrcDists,	DIST_SRC_BASE,		NULL		},
{ "scontrib",	"/usr/src",		&SrcDists,	DIST_SRC_CONTRIB,	NULL		},
{ "sgnu",	"/usr/src",		&SrcDists,	DIST_SRC_GNU,		NULL		},
{ "setc",	"/usr/src",		&SrcDists,	DIST_SRC_ETC,		NULL		},
{ "sgames",	"/usr/src",		&SrcDists,	DIST_SRC_GAMES,		NULL		},
{ "sinclude",	"/usr/src",		&SrcDists,	DIST_SRC_INCLUDE,	NULL		},
{ "slib",	"/usr/src",		&SrcDists,	DIST_SRC_LIB,		NULL		},
{ "slibexec",	"/usr/src",		&SrcDists,	DIST_SRC_LIBEXEC,	NULL		},
{ "slkm",	"/usr/src",		&SrcDists,	DIST_SRC_LKM,		NULL		},
{ "srelease",	"/usr/src",		&SrcDists,	DIST_SRC_RELEASE,	NULL		},
{ "sbin",	"/usr/src",		&SrcDists,	DIST_SRC_BIN,		NULL		},
{ "ssbin",	"/usr/src",		&SrcDists,	DIST_SRC_SBIN,		NULL		},
{ "sshare",	"/usr/src",		&SrcDists,	DIST_SRC_SHARE,		NULL		},
{ "ssys",	"/usr/src",		&SrcDists,	DIST_SRC_SYS,		NULL		},
{ "subin",	"/usr/src",		&SrcDists,	DIST_SRC_UBIN,		NULL		},
{ "susbin",	"/usr/src",		&SrcDists,	DIST_SRC_USBIN,		NULL		},
{ "ssmailcf",	"/usr/src",		&SrcDists,	DIST_SRC_SMAILCF,	NULL		},
{ NULL },
};

#ifndef USE_XIG_ENVIRONMENT
/* The XFree86 distribution */
static Distribution XF86DistTable[] = {
{ "XF86331",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_FONTS,	XF86FontDistTable },
{ "XF86331",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_SERVER,	XF86ServerDistTable },
{ "X331src-1",	"/usr/X11R6/src",	&XF86Dists,	DIST_XF86_SRC,		NULL		},
{ "X331contrib", "/usr/X11R6/src",	&XF86Dists,	DIST_XF86_CSRC,		NULL		},
{ "X331bin",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_BIN,		NULL		},
{ "X331cfg",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_CFG,		NULL		},
{ "X331doc",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_DOC,		NULL		},
{ "X331html",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_HTML,		NULL		},
{ "X331lib",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_LIB,		NULL		},
{ "X331lk98",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_LKIT98,	NULL		},
{ "X331lkit",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_LKIT,		NULL		},
{ "X331man",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_MAN,		NULL		},
{ "X331prog",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_PROG,		NULL		},
{ "X331ps",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_PS,		NULL		},
{ "X331set",	"/usr/X11R6",		&XF86Dists,	DIST_XF86_SET,		NULL		},
{ NULL },
};

/* The XFree86 server distribution */
static Distribution XF86ServerDistTable[] = {
{ "X3318514",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_8514,	NULL		},
{ "X3319480",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9480,	NULL		},
{ "X3319EGC",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9EGC,	NULL		},
{ "X3319GA9",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9GA9,	NULL		},
{ "X3319GAN",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9GAN,	NULL		},
{ "X3319LPW",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9LPW,	NULL		},
{ "X3319NKV",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9NKV,	NULL		},
{ "X3319NS3",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9NS3,	NULL		},
{ "X3319SPW",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9SPW,	NULL		},
{ "X3319TGU",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9TGU,	NULL		},
{ "X3319WEP",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9WEP,	NULL		},
{ "X3319WS",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9WS,	NULL		},
{ "X3319WSN",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_9WSN,	NULL		},
{ "X331AGX",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_AGX,	NULL		},
{ "X331I128",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_I128,	NULL		},
{ "X331Ma8",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_MACH8,	NULL		},
{ "X331Ma32",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_MACH32,NULL		},
{ "X331Ma64",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_MACH64,NULL		},
{ "X331Mono",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_MONO,	NULL		},
{ "X331P9K",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_P9000,	NULL		},
{ "X331S3",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_S3,	NULL		},
{ "X331S3V",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_S3V,	NULL		},
{ "X331SVGA",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_SVGA,	NULL		},
{ "X331VG16",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_VGA16,	NULL		},
{ "X331W32",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_W32,	NULL		},
{ "X331nest",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_NEST,	NULL		},
{ "X331vfb",	"/usr/X11R6",		&XF86ServerDists,	DIST_XF86_SERVER_VFB,	NULL		},
{ NULL },
};

/* The XFree86 font distribution */
static Distribution XF86FontDistTable[] = {
{ "X331fnts",	"/usr/X11R6",		&XF86FontDists,		DIST_XF86_FONTS_MISC,	NULL		},
{ "X331f100",	"/usr/X11R6",		&XF86FontDists,		DIST_XF86_FONTS_100,	NULL		},
{ "X331fcyr",	"/usr/X11R6",		&XF86FontDists,		DIST_XF86_FONTS_CYR,	NULL		},
{ "X331fscl",	"/usr/X11R6",		&XF86FontDists,		DIST_XF86_FONTS_SCALE,	NULL		},
{ "X331fnon",	"/usr/X11R6",		&XF86FontDists,		DIST_XF86_FONTS_NON,	NULL		},
{ "X331fsrv",	"/usr/X11R6",		&XF86FontDists,		DIST_XF86_FONTS_SERVER,	NULL		},
{ NULL },
};
#endif	/* !USE_XIG_ENVIRONMENT */

static int	distMaybeSetDES(dialogMenuItem *self);
static int	distMaybeSetPorts(dialogMenuItem *self);


static void
distVerifyFlags(void)
{
    if (SrcDists)
	Dists |= DIST_SRC;
    if (DESDists) {
	if (DESDists & DIST_DES_KERBEROS)
	    DESDists |= DIST_DES_DES;
	Dists |= DIST_DES;
    }
#ifndef USE_XIG_ENVIRONMENT
    if (XF86Dists & DIST_XF86_SET)
	XF86ServerDists |= DIST_XF86_SERVER_VGA16;
    if (XF86ServerDists)
	XF86Dists |= DIST_XF86_SERVER;
    if (XF86FontDists)
	XF86Dists |= DIST_XF86_FONTS;
    if (XF86Dists)
	Dists |= (DIST_XF86 | DIST_COMPAT21);
#endif
    if (isDebug())
	msgDebug("Dist Masks: Dists: %0x, DES: %0x, Srcs: %0x\nXServer: %0x, XFonts: %0x, XDists: %0x\n",
		 Dists, DESDists, SrcDists, XF86ServerDists, XF86FontDists, XF86Dists);
}

int
distReset(dialogMenuItem *self)
{
    Dists = 0;
    DESDists = 0;
    SrcDists = 0;
#ifndef USE_XIG_ENVIRONMENT
    XF86Dists = 0;
    XF86ServerDists = 0;
    XF86FontDists = 0;
#endif
    return DITEM_SUCCESS | DITEM_REDRAW;
}

int
distConfig(dialogMenuItem *self)
{
    char *cp;

    distReset(NULL);

    if ((cp = variable_get(VAR_DIST_MAIN)) != NULL)
	Dists = atoi(cp);

    if ((cp = variable_get(VAR_DIST_DES)) != NULL)
	DESDists = atoi(cp);

    if ((cp = variable_get(VAR_DIST_SRC)) != NULL)
	SrcDists = atoi(cp);

#ifndef	USE_XIG_ENVIRONMENT
    if ((cp = variable_get(VAR_DIST_X11)) != NULL)
	XF86Dists = atoi(cp);

    if ((cp = variable_get(VAR_DIST_XSERVER)) != NULL)
	XF86ServerDists = atoi(cp);

    if ((cp = variable_get(VAR_DIST_XFONTS)) != NULL)
	XF86FontDists = atoi(cp);
#endif
    distVerifyFlags();
    return DITEM_SUCCESS | DITEM_REDRAW;
}

int
distSetDeveloper(dialogMenuItem *self)
{
    int i;

    distReset(NULL);
    Dists = _DIST_DEVELOPER;
    SrcDists = DIST_SRC_ALL;
    i = distMaybeSetDES(self) | distMaybeSetPorts(self);
    distVerifyFlags();
    return i;
}

int
distSetXDeveloper(dialogMenuItem *self)
{
    int i;

    distReset(NULL);
    Dists = _DIST_DEVELOPER;
    SrcDists = DIST_SRC_ALL;
#ifdef USE_XIG_ENVIRONMENT
    Dists |= (DIST_XIG_SERVER | DIST_COMPAT21);
#else
    XF86Dists = DIST_XF86_BIN | DIST_COMPAT21 | DIST_XF86_SET | DIST_XF86_CFG | DIST_XF86_LIB | DIST_XF86_PROG | DIST_XF86_MAN | DIST_XF86_SERVER | DIST_XF86_FONTS;
    XF86ServerDists = DIST_XF86_SERVER_SVGA | DIST_XF86_SERVER_VGA16;
    XF86FontDists = DIST_XF86_FONTS_MISC;
#endif
    i = distSetXF86(NULL) | distMaybeSetDES(self) | distMaybeSetPorts(self);
    distVerifyFlags();
    return i;
}

int
distSetKernDeveloper(dialogMenuItem *self)
{
    int i;

    distReset(NULL);
    Dists = _DIST_DEVELOPER;
    SrcDists = DIST_SRC_SYS;
    i = distMaybeSetDES(self) | distMaybeSetPorts(self);
    distVerifyFlags();
    return i;
}

int
distSetUser(dialogMenuItem *self)
{
    int i;

    distReset(NULL);
    Dists = _DIST_USER;
    i = distMaybeSetDES(self) | distMaybeSetPorts(self);
    distVerifyFlags();
    return i;
}

int
distSetXUser(dialogMenuItem *self)
{
    int i;

    distReset(NULL);
    Dists = _DIST_USER;
#ifdef USE_XIG_ENVIRONMENT
    Dists |= (DIST_XIG_SERVER | DIST_COMPAT21);
#else
    XF86ServerDists = DIST_XF86_SERVER_SVGA | DIST_XF86_SERVER_VGA16;
    XF86Dists = DIST_XF86_BIN | DIST_COMPAT21 | DIST_XF86_SET | DIST_XF86_CFG | DIST_XF86_LIB | DIST_XF86_MAN | DIST_XF86_SERVER | DIST_XF86_FONTS;
    XF86FontDists = DIST_XF86_FONTS_MISC;
#endif
    i = distSetXF86(NULL) | distMaybeSetDES(self) | distMaybeSetPorts(self);
    distVerifyFlags();
    return i;
}

int
distSetMinimum(dialogMenuItem *self)
{
    distReset(NULL);
    Dists = DIST_BIN;
    return DITEM_SUCCESS | DITEM_REDRAW;
}

int
distSetEverything(dialogMenuItem *self)
{
    int i;

    Dists = DIST_ALL;
    SrcDists = DIST_SRC_ALL;
#ifdef USE_XIG_ENVIRONMENT
    Dists |= (DIST_XIG_SERVER | DIST_COMPAT21);
#else
    XF86Dists = DIST_XF86_ALL;
    XF86ServerDists = DIST_XF86_SERVER_ALL;
    XF86FontDists = DIST_XF86_FONTS_ALL;
#endif
    i = distMaybeSetDES(self) | distMaybeSetPorts(self);
    distVerifyFlags();
    return i;
}

int
distSetDES(dialogMenuItem *self)
{
    int i;
 
    if (!dmenuOpenSimple(&MenuDESDistributions, FALSE))
	i = DITEM_FAILURE;
    else
	i = DITEM_SUCCESS;
    distVerifyFlags();
    return i | DITEM_RESTORE;
}

static int
distMaybeSetDES(dialogMenuItem *self)
{
    int i = DITEM_SUCCESS;

    dialog_clear_norefresh();
    if (!msgYesNo("Do wish to install DES cryptographic software?\n\n"
		  "If you choose No, FreeBSD will use an MD5 based password scheme which,\n"
		  "while perhaps more secure, is not interoperable with the traditional\n"
		  "UNIX DES passwords on other non-FreeBSD systems.\n\n"
		  "Please do NOT choose Yes at this point if you are outside the\n"
		  "United States and Canada yet are installing from a U.S. FTP server.\n"
		  "This will violate U.S. export restrictions and possibly get the\n"
		  "server site into trouble!  In such cases, install everything but the\n"
		  "DES distribution from the U.S. server then switch your media type to\n"
		  "point to an international FTP server, using the Custom installation\n"
		  "option to select and extract the DES distribution in a second pass.")) {
	if (!dmenuOpenSimple(&MenuDESDistributions, FALSE))
	    i = DITEM_FAILURE;
    }
    distVerifyFlags();
    return i | DITEM_RESTORE;
}

static int
distMaybeSetPorts(dialogMenuItem *self)
{
    dialog_clear_norefresh();
    if (!msgYesNo("Would you like to install the FreeBSD ports collection?\n\n"
		  "This will give you ready access to over 1000 ported software packages,\n"
		  "though at a cost of around 35MB of disk space when \"clean\" and possibly\n"
		  "much more than that if a lot of the distribution tarballs are loaded\n"
		  "(unless you have the 2nd CD from a FreeBSD CDROM distribution available\n"
		  "and can mount it on /cdrom, in which case this is far less of a problem).\n\n"
		  "The ports collection is a very valuable resource and, if you have at least\n"
		  "100MB to spare in your /usr partition, well worth having around.\n\n"
		  "For more information on the ports collection & the latest ports, visit:\n"
		  "    http://www.freebsd.org/ports\n"))
	Dists |= DIST_PORTS;
    else
	Dists &= ~DIST_PORTS;
    return DITEM_SUCCESS | DITEM_RESTORE;
}

static Boolean
distSetByName(Distribution *dist, char *name)
{
    int i, status = FALSE;
    
    /* Loop through current set */
    for (i = 0; dist[i].my_name; i++) {
	/* This is shorthand for "dist currently disabled" */
	if (!dist[i].my_dir)
	    continue;
	if (!strcmp(dist[i].my_name, name)) {
	    *(dist[i].my_mask) |= dist[i].my_bit;
	    status = TRUE;
	}
	if (dist[i].my_dist) {
	    if (distSetByName(dist[i].my_dist, name)) {
		status = TRUE;
	    }
	}
    }
    distVerifyFlags();
    return status;
}

/* Just for the dispatch stuff */
int
distSetCustom(dialogMenuItem *self)
{
    char *cp, *cp2, *tmp;

    if (!(tmp = variable_get(VAR_DISTS))) {
	msgDebug("distSetCustom() called without %s variable set.\n", VAR_DISTS);
	return DITEM_FAILURE;
    }

    cp = alloca(strlen(tmp) + 1);
    if (!cp)
	msgFatal("Couldn't alloca() %d bytes!\n", strlen(tmp) + 1);
    strcpy(cp, tmp);
    while (cp) {
	if ((cp2 = index(cp, ' ')) != NULL)
	    *(cp2++) = '\0';
	if (!distSetByName(DistTable, cp))
	    msgDebug("distSetCustom: Warning, no such release \"%s\"\n", cp);
	cp = cp2;
    }
    distVerifyFlags();
    return DITEM_SUCCESS;
}
    
int
distSetSrc(dialogMenuItem *self)
{
    int i;

    if (!dmenuOpenSimple(&MenuSrcDistributions, FALSE))
	i = DITEM_FAILURE;
    else
	i = DITEM_SUCCESS;
    distVerifyFlags();
    return i | DITEM_RESTORE;
}

int
distSetXF86(dialogMenuItem *self)
{
    int i = DITEM_SUCCESS;

#ifdef USE_XIG_ENVIRONMENT
    Dists |= (DIST_XIG_SERVER | DIST_COMPAT21);
#else
    if (!dmenuOpenSimple(&MenuXF86Select, FALSE))
	i = DITEM_FAILURE;
#endif
    distVerifyFlags();
    return i | DITEM_RESTORE;
}

static Boolean got_intr = FALSE;

/* timeout handler */
static void
handle_intr(int sig)
{
    msgDebug("User generated interrupt.\n");
    got_intr = TRUE;
}

static int
check_for_interrupt(void)
{
    if (got_intr) {
	got_intr = FALSE;
	return TRUE;
    }
    return FALSE;
}

static Boolean
distExtract(char *parent, Distribution *me)
{
    int i, status, total, intr;
    int cpid, zpid, fd2, chunk, numchunks;
    char *path, *dist, buf[BUFSIZ];
    const char *tmp;
    FILE *fp;
    WINDOW *w = savescr();
    struct timeval start, stop;
    struct sigaction old, new;

    status = TRUE;
    dialog_clear_norefresh();
    if (isDebug())
	msgDebug("distExtract: parent: %s, me: %s\n", parent ? parent : "(none)", me->my_name);

    /* Make ^C fake a sudden timeout */
    new.sa_handler = handle_intr;
    new.sa_flags = 0;
    new.sa_mask = 0;
    sigaction(SIGINT, &new, &old);

    /* Loop through to see if we're in our parent's plans */
    for (i = 0; me[i].my_name; i++) {
	dist = me[i].my_name;
	path = parent ? parent : dist;

	/* If our bit isn't set, go to the next */
	if (!(me[i].my_bit & *(me[i].my_mask)))
	    continue;

	/* This is shorthand for "dist currently disabled" */
	if (!me[i].my_dir) {
	    *(me[i].my_mask) &= ~(me[i].my_bit);
	    continue;
	}

	/* Recurse if we actually have a sub-distribution */
	if (me[i].my_dist) {
	    if ((status = distExtract(dist, me[i].my_dist)) == TRUE)
		*(me[i].my_mask) &= ~(me[i].my_bit);
	    goto done;
	}

	/*
	 * Try to get distribution as multiple pieces, locating and parsing an
	 * info file which tells us how many we need for this distribution.
	 */
	numchunks = 0;
	snprintf(buf, sizeof buf, "%s/%s.inf", path, dist);

    getinfo:
	fp = mediaDevice->get(mediaDevice, buf, TRUE);
	intr = check_for_interrupt();
	if (fp == (FILE *)IO_ERROR || intr) {	/* Hard error, can't continue */
	    if (!msgYesNo("Unable to open %s: %s.\nReinitialize media?",
			  buf, !intr ? "I/O error." : "User interrupt.")) {
		mediaDevice->shutdown(mediaDevice);
		if (!mediaDevice->init(mediaDevice)) {
		    status = FALSE;
		    goto done;
		}
		else
		    goto getinfo;
	    }
	    else {
		status = FALSE;
		goto done;
	    }
	}
	else if (fp > 0) {
	    int status;
	    Attribs *dist_attr;

	    if (isDebug())
		msgDebug("Parsing attributes file for distribution %s\n", dist);
	    dist_attr = alloca(sizeof(Attribs) * MAX_ATTRIBS);

	    status = attr_parse(dist_attr, fp);
	    intr = check_for_interrupt();
	    if (intr || DITEM_STATUS(status) == DITEM_FAILURE)
		msgConfirm("Cannot parse information file for the %s distribution: %s\n"
			   "Please verify that your media is valid and try again.",
			   dist, !intr ? "I/O error" : "User interrupt");
	    else {
		tmp = attr_match(dist_attr, "pieces");
		if (tmp)
		    numchunks = strtol(tmp, 0, 0);
	    }
	    fclose(fp);
	    if (!numchunks)
		continue;
	}
	else {
	    /* Try to get the distribution as a single file */
	    snprintf(buf, sizeof buf, "%s/%s.tgz", path, dist);
	    /*
	     * Passing TRUE as 3rd parm to get routine makes this a "probing" get, for which errors
	     * are not considered too significant.
	     */
	getsingle:
	    fp = mediaDevice->get(mediaDevice, buf, TRUE);
	    intr = check_for_interrupt();
	    if (fp == (FILE *)IO_ERROR || intr) {	/* Hard error, can't continue */
		if (intr)	/* result of an interrupt */
		    msgConfirm("Unable to open %s: User interrupt", buf);
		else
		    msgConfirm("Unable to open %s: I/O error", buf);
		mediaDevice->shutdown(mediaDevice);
		if (!mediaDevice->init(mediaDevice)) {
		    status = FALSE;
		    goto done;
		}
		else
		    goto getsingle;
	    }
	    else if (fp > 0) {
		char *dir = root_bias(me[i].my_dir);

		msgNotify("Extracting %s into %s directory...", dist, dir);
		status = mediaExtractDist(dir, dist, fp);
		fclose(fp);
		goto done;
	    }
	    else
		numchunks = 0;
	}

	/* Fall through from "we got the attribute file, now get the pieces" step */
	if (!numchunks)
	    continue;

	if (isDebug())
	    msgDebug("Attempting to extract distribution from %u chunks.\n", numchunks);

	total = 0;
	(void)gettimeofday(&start, (struct timezone *)0);

	/* We have one or more chunks, initialize unpackers... */
	mediaExtractDistBegin(root_bias(me[i].my_dir), &fd2, &zpid, &cpid);

	/* And go for all the chunks */
	for (chunk = 0; chunk < numchunks; chunk++) {
	    int n, retval, last_msg;
	    char prompt[80];

	    last_msg = 0;

	getchunk:
	    snprintf(buf, sizeof buf, "%s/%s.%c%c", path, dist, (chunk / 26) + 'a', (chunk % 26) + 'a');
	    if (isDebug())
		msgDebug("trying for piece %d of %d: %s\n", chunk + 1, numchunks, buf);
	    fp = mediaDevice->get(mediaDevice, buf, FALSE);
	    intr = check_for_interrupt();
	    if (fp <= (FILE *)0 || intr) {
		if (fp == (FILE *)0)
		    msgConfirm("Failed to find %s on this media.  Reinitializing media.", buf);
		else
		    msgConfirm("failed to retreive piece file %s.\n"
			       "%s: Reinitializing media.", buf, !intr ? "I/O error" : "User interrupt");
		mediaDevice->shutdown(mediaDevice);
		if (!mediaDevice->init(mediaDevice))
		    goto punt;
		else
		    goto getchunk;
	    }

	    snprintf(prompt, sizeof prompt, "Extracting %s into %s directory...", dist, root_bias(me[i].my_dir));
	    dialog_gauge("Progress", prompt, 8, 15, 6, 50, (int)((float)(chunk + 1) / numchunks * 100));

	    while (1) {
		int seconds;

		n = fread(buf, 1, BUFSIZ, fp);
		if (check_for_interrupt()) {
		    msgConfirm("Media read error:  User interrupt.");
		    fclose(fp);
		    goto punt;
		}
		else if (n <= 0)
		    break;
		total += n;

		/* Print statistics about how we're doing */
		(void) gettimeofday(&stop, (struct timezone *)0);
		stop.tv_sec = stop.tv_sec - start.tv_sec;
		stop.tv_usec = stop.tv_usec - start.tv_usec;
		if (stop.tv_usec < 0)
		    stop.tv_sec--, stop.tv_usec += 1000000;
		seconds = stop.tv_sec + (stop.tv_usec / 1000000.0);
		if (!seconds)
		    seconds = 1;

		if (seconds != last_msg) {
		    last_msg = seconds;
		    msgInfo("%10d bytes read from %s dist, chunk %2d of %2d @ %.1f KB/sec.",
			    total, dist, chunk + 1, numchunks, (total / seconds) / 1024.0);
		}
		retval = write(fd2, buf, n);
		if (retval != n) {
		    fclose(fp);
		    dialog_clear_norefresh();
		    msgConfirm("Write failure on transfer! (wrote %d bytes of %d bytes)", retval, n);
		    goto punt;
		}
	    }
	    fclose(fp);
	}
	close(fd2);
	status = mediaExtractDistEnd(zpid, cpid);
        goto done;

    punt:
	close(fd2);
	mediaExtractDistEnd(zpid, cpid);
	status = FALSE;

    done:
	if (!status) {
	    if (me[i].my_dist) {
		msgConfirm("Unable to transfer all components of the %s distribution.\n"
			   "If this is a CDROM install, it may be because export restrictions prohibit\n"
			   "DES code from being shipped from the U.S.  Try to get this code from a\n"
			   "local FTP site instead!", me[i].my_name);
	    }
	    else {
		status = msgYesNo("Unable to transfer the %s distribution from\n%s.\n\n"
				  "Do you want to try to retrieve it again?",
				  me[i].my_name, mediaDevice->name);
		if (!status)
		    --i;
		dialog_clear();
	    }
	}
	/* If extract was successful, remove ourselves from further consideration */
	if (status)
	    *(me[i].my_mask) &= ~(me[i].my_bit);
	else
	    continue;
    }
    sigaction(SIGINT, &old, NULL);	/* Restore signal handler */
    restorescr(w);
    return status;
}

static void
printSelected(char *buf, int selected, Distribution *me, int *col)
{
    int i;

    /* Loop through to see if we're in our parent's plans */
    for (i = 0; me[i].my_name; i++) {

	/* If our bit isn't set, go to the next */
	if (!(me[i].my_bit & selected))
	    continue;

	/* This is shorthand for "dist currently disabled" */
	if (!me[i].my_dir)
	    continue;

	*col += strlen(me[i].my_name);
	if (*col > 50) {
	    *col = 0;
	    strcat(buf, "\n");
	}
	sprintf(&buf[strlen(buf)], " %s", me[i].my_name);
	/* Recurse if have a sub-distribution */
	if (me[i].my_dist)
	    printSelected(buf, *(me[i].my_mask), me[i].my_dist, col);
    }
}

int
distExtractAll(dialogMenuItem *self)
{
    int retries = 0;
    char buf[512];

    /* paranoia */
    if (!Dists) {
	if (!dmenuOpenSimple(&MenuSubDistributions, FALSE) || !Dists)
	    return DITEM_FAILURE | DITEM_RESTORE;
    }

    if (!mediaVerify() || !mediaDevice->init(mediaDevice))
	return DITEM_FAILURE;

    dialog_clear_norefresh();
    msgNotify("Attempting to install all selected distributions..");
    /* Try for 3 times around the loop, then give up. */
    while (Dists && ++retries < 3)
	distExtract(NULL, DistTable);

    if (Dists) {
	int col = 0;

	buf[0] = '\0';
	printSelected(buf, Dists, DistTable, &col);
	dialog_clear_norefresh();
	msgConfirm("Couldn't extract the following distributions.  This may\n"
		   "be because they were not available on the installation\n"
		   "media you've chosen:\n\n\t%s", buf);
	return DITEM_SUCCESS | DITEM_RESTORE;
    }
    return DITEM_SUCCESS;
}
