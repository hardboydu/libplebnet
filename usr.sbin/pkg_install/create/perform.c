#ifndef lint
static const char *rcsid = "$Id: perform.c,v 1.21 1995/04/22 14:55:07 jkh Exp $";
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
 * This is the main body of the create module.
 *
 */

#include "lib.h"
#include "create.h"

#include <signal.h>
#include <sys/syslimits.h>

static void sanity_check(void);
static void make_dist(char *, char *, char *, Package *);

int
pkg_perform(char **pkgs)
{
    char *pkg = *pkgs;		/* Only one arg to create */
    char *home, *cp;
    FILE *pkg_in, *fp;
    Package plist;
    char *suffix;  /* What we tack on to the end of the finished package */

    /* Preliminary setup */
    sanity_check();
    if (Verbose && !PlistOnly)
	printf("Creating package %s\n", pkg);
    get_dash_string(&Comment);
    get_dash_string(&Desc);
    if (!strcmp(Contents, "-"))
	pkg_in = stdin;
    else {
	pkg_in = fopen(Contents, "r");
	if (!pkg_in)
	    barf("Unable to open contents file '%s' for input.", Contents);
    }
    plist.head = plist.tail = NULL;

    /* Break the package name into base and desired suffix (if any) */
    if ((cp = rindex(pkg, '.')) != NULL) {
	suffix = cp + 1;
	*cp = '\0';
    }
    else
	suffix = "tgz";

    /* Stick the dependencies, if any, at the top */
    if (Pkgdeps) {
	if (Verbose && !PlistOnly)
	    printf("Registering depends:");
	while (Pkgdeps) {
	    cp = strsep(&Pkgdeps, " \t\n");
	    if (*cp) {
		add_plist(&plist, PLIST_PKGDEP, cp);
		if (Verbose && !PlistOnly)
		    printf(" %s", cp);
	    }
	}
	if (Verbose && !PlistOnly)
	    printf(".\n");
    }
    /* Slurp in the packing list */
    read_plist(&plist, pkg_in);

    /* Prefix should override the packing list */
    if (Prefix) {
	delete_plist(&plist, FALSE, PLIST_CWD, NULL);
	add_plist_top(&plist, PLIST_CWD, Prefix);
    }
    /*
     * Run down the list and see if we've named it, if not stick in a name
     * at the top.
     */
    if (find_plist(&plist, PLIST_NAME) == NULL)
	add_plist_top(&plist, PLIST_NAME, basename_of(pkg));

    /*
     * We're just here for to dump out a revised plist for the FreeBSD ports
     * hack.  It's not a real create in progress.
     */
    if (PlistOnly) {
	write_plist(&plist, stdout);
	exit(0);
    }

    /* Make a directory to stomp around in */
    home = make_playpen(PlayPen, 0);
    signal(SIGINT, cleanup);
    signal(SIGHUP, cleanup);

    /* Make first "real contents" pass over it */
    check_list(home, &plist);
    (void) umask(022);	/* make sure gen'ed directories, files don't have
			   group or other write bits. */
    /* copy_plist(home, &plist); */
    /* mark_plist(&plist); */

    /* Now put the release specific items in */
    add_plist(&plist, PLIST_CWD, ".");
    write_file(COMMENT_FNAME, Comment);
    add_plist(&plist, PLIST_IGNORE, NULL);
    add_plist(&plist, PLIST_FILE, COMMENT_FNAME);
    write_file(DESC_FNAME, Desc);
    add_plist(&plist, PLIST_IGNORE, NULL);
    add_plist(&plist, PLIST_FILE, DESC_FNAME);

    if (Install) {
	copy_file(home, Install, INSTALL_FNAME);
	add_plist(&plist, PLIST_IGNORE, NULL);
	add_plist(&plist, PLIST_FILE, INSTALL_FNAME);
    }
    if (DeInstall) {
	copy_file(home, DeInstall, DEINSTALL_FNAME);
	add_plist(&plist, PLIST_IGNORE, NULL);
	add_plist(&plist, PLIST_FILE, DEINSTALL_FNAME);
    }
    if (Require) {
	copy_file(home, Require, REQUIRE_FNAME);
	add_plist(&plist, PLIST_IGNORE, NULL);
	add_plist(&plist, PLIST_FILE, REQUIRE_FNAME);
    }
    if (Display) {
	copy_file(home, Display, DISPLAY_FNAME);
	add_plist(&plist, PLIST_IGNORE, NULL);
	add_plist(&plist, PLIST_FILE, DISPLAY_FNAME);
	add_plist(&plist, PLIST_DISPLAY, DISPLAY_FNAME);
    }
    if (Mtree) {
	copy_file(home, Mtree, MTREE_FNAME);
	add_plist(&plist, PLIST_IGNORE, NULL);
	add_plist(&plist, PLIST_FILE, MTREE_FNAME);
	add_plist(&plist, PLIST_MTREE, MTREE_FNAME);
    }

    /* Run through the list again, picking up extra "local" items */
    /* check_list(".", &plist); */
    /* copy_plist(".", &plist); */
    /* mark_plist(&plist); */

    /* Finally, write out the packing list */
    fp = fopen(CONTENTS_FNAME, "w");
    if (!fp)
	barf("Can't open file %s for writing.", CONTENTS_FNAME);
    write_plist(&plist, fp);
    if (fclose(fp))
	barf("Error while closing %s.", CONTENTS_FNAME);

    /* And stick it into a tar ball */
    make_dist(home, pkg, suffix, &plist);

    /* Cleanup */
    free(Comment);
    free(Desc);
    free_plist(&plist);
    cleanup(0);
    return TRUE;	/* Success */
}

static void
make_dist(char *home, char *pkg, char *suffix, Package *plist)
{
    char tball[FILENAME_MAX];
    char cmd[ARG_MAX];
    int ret;
    PackingList p;

    strcpy(cmd, "tar ");
    if (*pkg == '/')
	sprintf(tball, "%s.%s", pkg, suffix);
    else
	sprintf(tball, "%s/%s.%s", home, pkg, suffix);
    if (index(suffix, 'z'))	/* Compress/gzip? */
	strcat(cmd, "-z");
    if (Dereference)
	strcat(cmd, "h");
    if (Verbose)
	printf("Creating gzip'd tar ball in '%s'\n", tball);
    strcat(cmd, "cf ");
    strcat(cmd, tball);
    if (ExcludeFrom)
	sprintf(&cmd[strlen(cmd)], " -X %s", ExcludeFrom);
    sprintf(&cmd[strlen(cmd)], " %s %s %s", CONTENTS_FNAME,
    	    COMMENT_FNAME, DESC_FNAME);
    if (Install)
	sprintf(&cmd[strlen(cmd)], " %s", INSTALL_FNAME);
    if (DeInstall)
	sprintf(&cmd[strlen(cmd)], " %s", DEINSTALL_FNAME);
    if (Require)
	sprintf(&cmd[strlen(cmd)], " %s", REQUIRE_FNAME);
    if (Display)
	sprintf(&cmd[strlen(cmd)], " %s", DISPLAY_FNAME);
    if (Mtree)
	sprintf(&cmd[strlen(cmd)], " %s", MTREE_FNAME);
    for (p = plist->head; p; p = p->next) {
	if (p->type == PLIST_FILE)
	    sprintf(&cmd[strlen(cmd)], " %s", p->name);
	else if (p->type == PLIST_CWD)
	    sprintf(&cmd[strlen(cmd)], " -C %s", p->name);
	else if (p->type == PLIST_SRC)
	    sprintf(&cmd[strlen(cmd)], " -C %s", p->name);
	else if (p->type == PLIST_IGNORE)
	     p = p->next;
    }
    ret = vsystem(cmd);
    if (ret)
	barf("tar command `%s' failed with code %d", cmd, ret);
}

static void
sanity_check()
{
    if (!Comment)
	barf("Required package comment string is missing (-c comment).");
    if (!Desc)
	barf("Required package description string is missing (-d desc).");
    if (!Contents)
	barf("Required package contents list is missing (-f [-]file).");
}


/* Clean up those things that would otherwise hang around */
void
cleanup(int sig)
{
    leave_playpen();
}
