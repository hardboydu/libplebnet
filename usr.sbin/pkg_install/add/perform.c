#ifndef lint
static const char *rcsid = "$Id: perform.c,v 1.7 1993/08/26 08:46:55 jkh Exp $";
#endif

/*
 * FreeBSD install - a package for the installation and maintainance
 * of non-core utilities.
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
 * Jordan K. Hubbard
 * 18 July 1993
 *
 * This is the main body of the add module.
 *
 */

#include "lib.h"
#include "add.h"

#include <signal.h>

static int pkg_do(char *);
static char *find_name(Package *);
static int sanity_check(char *);
static char LogDir[FILENAME_MAX];


int
pkg_perform(char **pkgs)
{
    int i, err_cnt = 0;

    signal(SIGINT, cleanup);
    signal(SIGHUP, cleanup);

    for (i = 0; pkgs[i]; i++)
	err_cnt += pkg_do(pkgs[i]);
    return err_cnt;
}

static Package Plist;

/* This is seriously ugly code following.  Written very fast! */
static int
pkg_do(char *pkg)
{
    char pkg_fullname[FILENAME_MAX];
    FILE *cfile;
    char *home;
    int code = 0;

    /* Reset some state */
    if (Plist.head)
	free_plist(&Plist);
    LogDir[0] = '\0';
    home = make_playpen();
    if (pkg[0] == '/')	/* full pathname? */
	strcpy(pkg_fullname, pkg);
    else
	sprintf(pkg_fullname, "%s/%s", home, pkg);
    if (!fexists(pkg_fullname)) {
	whinge("Can't open package '%s'.", pkg_fullname);
	return 1;
    }

    if (unpack(pkg_fullname, NULL))
	return 1;

    if (sanity_check(pkg_fullname))
	return 1;

    cfile = fopen(CONTENTS_FNAME, "r");
    if (!cfile) {
	whinge("Unable to open %s file.", CONTENTS_FNAME);
	goto fail;
    }
    /* If we have a prefix, add it now */
    if (Prefix)
	add_plist(&Plist, PLIST_CWD, Prefix);
    else
	add_plist(&Plist, PLIST_CWD, home);
    read_plist(&Plist, cfile);
    fclose(cfile);
    PkgName = find_name(&Plist);
    if (fexists(REQUIRE_FNAME)) {
	vsystem("chmod +x %s", REQUIRE_FNAME);	/* be sure */
	if (Verbose)
	    printf("Running requirements file first for %s..\n", PkgName);
	if (vsystem("%s %s INSTALL", REQUIRE_FNAME, PkgName)) {
	    whinge("Package %s fails requirements - not installed.",
		   pkg_fullname);
	    goto fail;
	}
    }
    if (!NoInstall && fexists(INSTALL_FNAME)) {
	vsystem("chmod +x %s", INSTALL_FNAME);	/* make sure */
	if (Verbose)
	    printf("Running install with PRE-INSTALL for %s..\n", PkgName);
	if (vsystem("%s %s PRE-INSTALL", INSTALL_FNAME, PkgName)) {
	    whinge("Install script returned error status.");
	    goto fail;
	}
    }
    extract_plist(home, &Plist);
    if (!NoInstall && fexists(INSTALL_FNAME)) {
	if (Verbose)
	    printf("Running install with POST-INSTALL for %s..\n", PkgName);
	if (vsystem("%s %s POST-INSTALL", INSTALL_FNAME, PkgName)) {
	    whinge("Install script returned error status.");
	    goto fail;
	}
    }
    if (!NoRecord && !Fake) {
	if (getuid() != 0)
	    whinge("Not running as root - trying to record install anyway.");
	if (!PkgName) {
	    whinge("No package name!  Can't record package, sorry.");
	    code = 1;
	    goto success;	/* well, partial anyway */
	}
	sprintf(LogDir, "%s/%s", LOG_DIR, PkgName);
	if (Verbose)
	    printf("Attempting to record package into %s..\n", LogDir);
	if (make_hierarchy(LogDir)) {
	    whinge("Can't record package into '%s', you're on your own!",
		   LogDir);
	    bzero(LogDir, FILENAME_MAX);
	    code = 1;
	    goto success;	/* close enough for government work */
	}
	if (fexists(DEINSTALL_FNAME))
	    copy_file(".", DEINSTALL_FNAME, LogDir);
	if (fexists(REQUIRE_FNAME))
	    copy_file(".", REQUIRE_FNAME, LogDir);
	copy_file(".", CONTENTS_FNAME, LogDir);
	copy_file(".", DESC_FNAME, LogDir);
	copy_file(".", COMMENT_FNAME, LogDir);
	if (Verbose)
	    printf("Package %s registered in %s\n", PkgName, LogDir);
    }
    goto success;

 fail:
    /* Nuke the whole (installed) show */
    if (!Fake)
	delete_package(FALSE, &Plist);

 success:
    /* delete the packing list contents */
    leave_playpen();

    return code;
}

static int
sanity_check(char *pkg)
{
    if (!fexists(CONTENTS_FNAME)) {
	whinge("Package %s has no CONTENTS file!", pkg);
	return 1;
    }
    if (!fexists(COMMENT_FNAME)) {
	whinge("Package %s has no COMMENT file!", pkg);
	return 1;
    }
    if (!fexists(DESC_FNAME)) {
	whinge("Package %s has no DESC file!", pkg);
	return 1;
    }
    return 0;
}

static char *
find_name(Package *pkg)
{
    PackingList p = pkg->head;

    while (p) {
	if (p->type == PLIST_NAME)
	    return p->name;
	p = p->next;
    }
    return "anonymous";
}

void
cleanup(int signo)
{
    if (Plist.head) {
	if (!Fake)
	    delete_package(FALSE, &Plist);
	free_plist(&Plist);
    }
    if (!Fake && LogDir[0])
	vsystem("%s -rf %s", REMOVE_CMD, LogDir);
    leave_playpen();
}
