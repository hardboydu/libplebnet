/*
 * Miscellaneous support routines..
 *
 * $Id: misc.c,v 1.4 1995/05/08 21:39:39 jkh Exp $
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jordan Hubbard
 *	for the FreeBSD Project.
 * 4. The name of Jordan Hubbard or the FreeBSD project may not be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
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
#include <ctype.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/dkbad.h>
#include <sys/disklabel.h>

/* Quick check to see if a file is readable */
Boolean
file_readable(char *fname)
{
    if (!access(fname, F_OK))
	return TRUE;
    return FALSE;
}

/* Quick check to see if a file is executable */
Boolean
file_executable(char *fname)
{
    if (!access(fname, X_OK))
	return TRUE;
    return FALSE;
}

/* Concatenate two strings into static storage */
char *
string_concat(char *one, char *two)
{
    static char tmp[FILENAME_MAX];

    strcpy(tmp, one);
    strcat(tmp, two);
    return tmp;
}

/* Clip the whitespace off the end of a string */
char *
string_prune(char *str)
{
    int len = str ? strlen(str) : 0;

    while (len && isspace(str[len - 1]))
	str[--len] = '\0';
    return str;
}

/* run the whitespace off the front of a string */
char *
string_skipwhite(char *str)
{
    while (*str && isspace(*str))
	++str;
    return str;
}

/* A free guaranteed to take NULL ptrs */
void
safe_free(void *ptr)
{
    if (ptr)
	free(ptr);
}

/* A malloc that checks errors */
void *
safe_malloc(size_t size)
{
    void *ptr;

    if (size <= 0)
	msgFatal("Invalid malloc size of %d!", size);
    ptr = malloc(size);
    if (!ptr)
	msgFatal("Out of memory!");
    return ptr;
}

/* A realloc that checks errors */
void *
safe_realloc(void *orig, size_t size)
{
    void *ptr;

    if (size <= 0)
	msgFatal("Invalid realloc size of %d!", size);
    ptr = realloc(orig, size);
    if (!ptr)
	msgFatal("Out of memory!");
    return ptr;
}

/*
 * These next routines are kind of specialized just for building string lists
 * for dialog_menu().
 */

/* Add a string to an item list */
char **
item_add(char **list, char *item, int *curr, int *max)
{

    if (*curr == *max) {
	*max += 20;
	list = (char **)realloc(list, sizeof(char *) * *max);
    }
    list[(*curr)++] = item;
    return list;
}

/* Add a pair of items to an item list (more the usual case) */
char **
item_add_pair(char **list, char *item1, char *item2, int *curr, int *max)
{
    list = item_add(list, item1, curr, max);
    list = item_add(list, item2, curr, max);
    return list;
}

/* Toss the items out */
void
items_free(char **list, int *curr, int *max)
{
    safe_free(list);
    *curr = *max = 0;
}

int
Mkdir(char *ipath, void *data)
{
    struct stat sb;
    int final=0;
    char *p, *path = strdup(ipath);

    msgDebug("mkdir(%s)\n", path);
    p = path;
    if (p[0] == '/')		/* Skip leading '/'. */
	++p;
    for (;!final; ++p) {
	if (p[0] == '\0' || (p[0] == '/' && p[1] == '\0'))
	    final++;
	else if (p[0] != '/')
	    continue;
	*p = '\0';
	if (stat(path, &sb)) {
	    if (errno != ENOENT) {
		msgConfirm("Couldn't stat directory %s: %s", path, strerror(errno));
		return 1;
	    }
	    msgDebug("mkdir(%s..)\n", path);
	    if (mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) < 0) {
		msgConfirm("Couldn't create directory %s: %s", path,strerror(errno));
		return 1;
	    }
	}
	*p = '/';
    }
    free(path);
    return 0;
}

int
Mount(char *device, void *data)
{
    struct ufs_args ufsargs;
    char mountpoint[FILENAME_MAX];

    strcpy(mountpoint, "/mnt");
    if (data)
	sprintf(mountpoint + 4, "/%s", (char *)data);

    memset(&ufsargs,0,sizeof ufsargs);

    if (access(mountpoint, R_OK))
	Mkdir(mountpoint, NULL);

    msgDebug("mount %s %s\n", device, mountpoint); 
    ufsargs.fspec = device;
    if (mount(MOUNT_UFS, mountpoint, 0, (caddr_t)&ufsargs) == -1) {
	msgConfirm("Error mounting %s on %s : %s\n",
		   device, mountpoint, strerror(errno));
	return 1;
    }
    return 0;
}

