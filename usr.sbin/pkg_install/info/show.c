#ifndef lint
static const char *rcsid = "$Id: show.c,v 1.4 1993/09/04 05:06:44 jkh Exp $";
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
 * 23 Aug 1993
 *
 * Various display routines for the info module.
 *
 */

#include "lib.h"
#include "info.h"

void
show_file(char *title, char *fname)
{
    FILE *fp;
    char line[1024];
    int n;

    if (!Quiet)
	printf("%s%s", InfoPrefix, title);
    fp = fopen(fname, "r");
    if (!fp) {
	whinge("show_file: Can't open '%s' for reading.", fname);
	return;
    }
    while (n = fread(line, 1, 1024, fp))
	fwrite(line, 1, n, stdout);
    fclose(fp);
    printf("\n");	/* just in case */
}

/* Show a packing list item type.  If type is -1, show all */
void
show_plist(char *title, Package *plist, plist_t type)
{
    PackingList p;
    Boolean ign = FALSE;

    if (!Quiet)
	printf("%s%s", InfoPrefix, title);
    p = plist->head;
    while (p) {
	if (p->type != type && type != -1) {
	    p = p->next;
	    continue;
	}
	switch(p->type) {
	case PLIST_FILE:
	    if (ign) {
		printf(Quiet ? "%s\n" : "File: %s (ignored)\n", p->name);
		ign = FALSE;
	    }
	    else
		printf(Quiet ? "%s\n" : "File: %s\n", p->name);
	    break;
	    
	case PLIST_CWD:
	    printf(Quiet ? "@cwd %s\n" : "\tCWD to %s\n", p->name);
	    break;

	case PLIST_CMD:
	    printf(Quiet ? "@exec %s\n" : "\tEXEC '%s'\n", p->name);
	    break;

	case PLIST_CHMOD:
	    printf(Quiet ? "@chmod %s\n" : "\tCHMOD to %s\n",
		   p->name ? p->name : "(clear default)");
	    break;

	case PLIST_CHOWN:
	    printf(Quiet ? "@chown %s\n" : "\tCHOWN to %s\n",
		   p->name ? p->name : "(clear default)");
	    break;

	case PLIST_CHGRP:
	    printf(Quiet ? "@chgrp %s\n" : "\tCHGRP to %s\n",
		   p->name ? p->name : "(clear default)");
	    break;

	case PLIST_COMMENT:
	    printf(Quiet ? "@comment %s\n" : "\tComment: %s\n", p->name);
	    break;

	case PLIST_IGNORE:
	    ign = TRUE;
	    break;

	case PLIST_NAME:
	    printf(Quiet ? "@name %s\n" : "\tPackage name: %s\n", p->name);
	    break;

	default:
	    barf("Unknown command type %d (%s)\n", p->type, p->name);
	    break;
	}
	p = p->next;
    }
}

/* Show all files in the packing list (except ignored ones) */
void
show_files(char *title, Package *plist)
{
    PackingList p;
    Boolean ign = FALSE;
    char *dir = ".";

    if (!Quiet)
	printf("%s%s", InfoPrefix, title);
    p = plist->head;
    while (p) {
	switch(p->type) {
	case PLIST_FILE:
	    if (!ign)
		printf("%s/%s\n", dir, p->name);
	    ign = FALSE;
	    break;
	    
	case PLIST_CWD:
	    dir = p->name;
	    break;

	case PLIST_IGNORE:
	    ign = TRUE;
	    break;
	}
	p = p->next;
    }
}
