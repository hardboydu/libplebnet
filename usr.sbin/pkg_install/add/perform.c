#ifndef lint
static const char *rcsid = "$Id: perform.c,v 1.11 1994/10/14 05:43:41 jkh Exp $";
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
static int sanity_check(char *);
static char LogDir[FILENAME_MAX];


int
pkg_perform(char **pkgs)
{
    int i, err_cnt = 0;

    signal(SIGINT, cleanup);
    signal(SIGHUP, cleanup);

    if (AddMode == SLAVE)
	err_cnt = pkg_do(NULL);
    else {
	for (i = 0; pkgs[i]; i++)
	    err_cnt += pkg_do(pkgs[i]);
    }
    return err_cnt;
}

static Package Plist;

/* This is seriously ugly code following.  Written very fast! */
static int
pkg_do(char *pkg)
{
    char pkg_fullname[FILENAME_MAX];
    char home[FILENAME_MAX];
    FILE *cfile;
    int code = 0;
    PackingList p;
    struct stat sb;

    /* Reset some state */
    if (Plist.head)
	free_plist(&Plist);
    LogDir[0] = '\0';
    if (AddMode == SLAVE) {
	char tmp_dir[FILENAME_MAX];

	fgets(tmp_dir, FILENAME_MAX, stdin);
	tmp_dir[strlen(tmp_dir) - 1] = '\0'; /* pesky newline! */
	if (chdir(tmp_dir) == FAIL) {
	    whinge("pkg_add in SLAVE mode can't chdir to %s.", tmp_dir);
	    return 1;
	}
	read_plist(&Plist, stdin);
    }
    else {
	if (!getcwd(home, FILENAME_MAX))
	    upchuck("getcwd"); 

	if (pkg[0] == '/')	/* full pathname? */
	    strcpy(pkg_fullname, pkg);
	else
	    sprintf(pkg_fullname, "%s/%s", home, pkg);
	if (!fexists(pkg_fullname)) {
	    whinge("Can't find package '%s'.", pkg_fullname);
	    return 1;
	}
	/*
	 * Apply a crude heuristic to see how much space the package will
	 * take up once it's unpacked.  I've noticed that most packages
	 * compress an average of 75%, so multiply by 4 for good measure.
	 */
	if (stat(pkg_fullname, &sb) == FAIL) {
	    whinge("Can't stat package file '%s'.", pkg_fullname);
	    return 1;
	}
	sb.st_size *= 4;
	(void)make_playpen(PlayPen, sb.st_size);
	if (unpack(pkg_fullname, NULL))
	    return 1;

	if (sanity_check(pkg_fullname))
	    return 1;

	cfile = fopen(CONTENTS_FNAME, "r");
	if (!cfile) {
	    whinge("Unable to open %s file.", CONTENTS_FNAME);
	    goto fail;
	}
	read_plist(&Plist, cfile);
	fclose(cfile);
	if (Prefix) {
	    /*
	     * If we have a prefix, delete the first one we see and add this
	     * one in place of it.
	     */
	    delete_plist(&Plist, FALSE, PLIST_CWD, NULL);
	    add_plist_top(&Plist, PLIST_CWD, Prefix);
	}
	/* If we're running in MASTER mode, just output the plist and return */
	if (AddMode == MASTER) {
	    printf("%s\n", where_playpen());
	    write_plist(&Plist, stdout);
	    return 0;
	}
    }
    setenv(PKG_PREFIX_VNAME,
	   (p = find_plist(&Plist, PLIST_CWD)) ? p->name : NULL, 1);
    PkgName = (p = find_plist(&Plist, PLIST_NAME)) ? p->name : "anonymous";
    if (fexists(REQUIRE_FNAME)) {
	vsystem("chmod +x %s", REQUIRE_FNAME);	/* be sure */
	if (Verbose)
	    printf("Running requirements file first for %s..\n", PkgName);
	if (!Fake && vsystem("./%s %s INSTALL", REQUIRE_FNAME, PkgName)) {
	    whinge("Package %s fails requirements - not installed.",
		   pkg_fullname);
	    return 1;
	}
    }
    if (!NoInstall && fexists(INSTALL_FNAME)) {
	vsystem("chmod +x %s", INSTALL_FNAME);	/* make sure */
	if (Verbose)
	    printf("Running install with PRE-INSTALL for %s..\n", PkgName);
	if (!Fake && vsystem("./%s %s PRE-INSTALL", INSTALL_FNAME, PkgName)) {
	    whinge("Install script returned error status.");
	    goto fail;
	}
    }
    extract_plist(home, &Plist);
    if (!NoInstall && fexists(INSTALL_FNAME)) {
	if (Verbose)
	    printf("Running install with POST-INSTALL for %s..\n", PkgName);
	if (!Fake && vsystem("./%s %s POST-INSTALL", INSTALL_FNAME, PkgName)) {
	    whinge("Install script returned error status.");
	    goto fail;
	}
    }
    if (!NoRecord && !Fake) {
	char contents[FILENAME_MAX];
	FILE *cfile;

	if (getuid() != 0)
	    whinge("Not running as root - trying to record install anyway.");
	if (!PkgName) {
	    whinge("No package name!  Can't record package, sorry.");
	    code = 1;
	    goto success;	/* well, partial anyway */
	}
	/* Protect against old packages with bogus @name fields */
	sprintf(LogDir, "%s/%s", LOG_DIR, basename_of(PkgName));
	if (Verbose)
	    printf("Attempting to record package into %s..\n", LogDir);
	if (make_hierarchy(LogDir)) {
	    whinge("Can't record package into '%s', you're on your own!",
		   LogDir);
	    bzero(LogDir, FILENAME_MAX);
	    code = 1;
	    goto success;	/* close enough for government work */
	}
	/* Make sure pkg_info can read the entry */
	vsystem("chmod a+rx %s", LogDir);
	if (fexists(DEINSTALL_FNAME))
	    copy_file(".", DEINSTALL_FNAME, LogDir);
	if (fexists(REQUIRE_FNAME))
	    copy_file(".", REQUIRE_FNAME, LogDir);
	sprintf(contents, "%s/%s", LogDir, CONTENTS_FNAME);
	cfile = fopen(contents, "w");
	if (!cfile) {
	    whinge("Can't open new contents file '%s'!  Can't register pkg.",
		   contents);
	    goto success; /* can't log, but still keep pkg */
	}
	write_plist(&Plist, cfile);
	fclose(cfile);
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

void
cleanup(int signo)
{
    if (signo)
	printf("Signal %d received, cleaning up..\n", signo);
    if (Plist.head) {
	if (!Fake)
	    delete_package(FALSE, &Plist);
	free_plist(&Plist);
    }
    if (!Fake && LogDir[0])
	vsystem("%s -rf %s", REMOVE_CMD, LogDir);
    leave_playpen();
}
