#ifndef lint
static const char *rcsid = "$Id: pen.c,v 1.1 1993/08/24 09:24:08 jkh Exp $";
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
 * Routines for managing the "play pen".
 *
 */

#include "lib.h"

/* For keeping track of where we are */
static char Cwd[FILENAME_MAX];
static char Pen[FILENAME_MAX];


/*
 * Make a temporary directory to play in and chdir() to it, returning
 * pathname of previous working directory.
 */
char *
make_playpen(void)
{
    if (!getcwd(Cwd, FILENAME_MAX))
	upchuck("getcwd");
    strcpy(Pen, "/tmp/instmp.XXXXXX");
    if (!mktemp(Pen))
	barf("Can't mktemp '%s'.", Pen);
    if (mkdir(Pen, 0755) == FAIL)
	barf("Can't mkdir '%s'.", Pen);
    if (chdir(Pen) == FAIL)
	barf("Can't chdir to '%s'.", Pen);
    return Cwd;
}

/* Convenience routine for getting out of playpen */
void
leave_playpen(void)
{
    if (Cwd[0]) {
	if (chdir(Cwd) == FAIL)
	    barf("Can't chdir back to '%s'.", Cwd);
	if (vsystem("rm -rf %s", Pen))
	    fprintf(stderr, "Couldn't remove temporary dir '%s'\n", Pen);
	Cwd[0] = '\0';
    }
}

