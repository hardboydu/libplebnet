/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: decode.c,v 1.4 1995/05/17 14:39:35 jkh Exp $
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

DMenuItem *
decode(DMenu *menu, char *name)
{
    DMenuItem *tmp;

    for (tmp = menu->items; tmp->title; tmp++)
	if (!strcmp(name, (*tmp->title == '*') ? tmp->title + 1 : tmp->title))
	    break;
    if (!tmp->title)
	return NULL;
    return tmp;
}

Boolean
dispatch(DMenuItem *tmp, char *name)
{
    Boolean failed = FALSE;

    switch (tmp->type) {
	/* User whapped ESC twice and wants a sub-shell */
    case DMENU_SHELL_ESCAPE:
	systemShellEscape();
	break;

	/* We want to simply display a file */
    case DMENU_DISPLAY_FILE:
	systemDisplayFile((char *)tmp->ptr);
	break;

	/* It's a sub-menu; recurse on it */
    case DMENU_SUBMENU:
	dmenuOpenSimple((DMenu *)tmp->ptr);
	break;

	/* Execute it as a system command */
    case DMENU_SYSTEM_COMMAND:
	(void)systemExecute((char *)tmp->ptr);
	break;

	/* Same as above, but execute it in a prgbox */
    case DMENU_SYSTEM_COMMAND_BOX:
	use_helpfile(NULL);
	use_helpline("Select OK to dismiss this dialog");
	dialog_prgbox(tmp->title, (char *)tmp->ptr, 22, 76, 1, 1);
	dialog_clear();
	break;

    case DMENU_CALL:
	failed = (((int (*)())tmp->ptr)(name));
	break;

    case DMENU_CANCEL:
	return TRUE;

    case DMENU_SET_VARIABLE:
	variable_set((char *)tmp->ptr);
	break;

    case DMENU_SET_FLAG:
	*((unsigned int *)tmp->ptr) |= tmp->parm;
	break;

    case DMENU_NOP:
	break;

    default:
	msgFatal("Don't know how to deal with menu type %d", tmp->type);
    }
    return failed;
}

Boolean
decode_and_dispatch_multiple(DMenu *menu, char *names)
{
    DMenuItem *tmp;
    int errors = 0;

    string_prune(names);
    names = string_skipwhite(names);
    while (names) {
	char *cp;

	cp = index(names, '\n');
	if (cp)
	   *cp++ = 0;
	/* Were no options actually selected? */
	if (!*names)
	    return FALSE;
	if ((tmp = decode(menu, names)) != NULL) {
	    if (dispatch(tmp, names))
		++errors;
	}
	else
	    msgFatal("Couldn't find a handler for item `%s' in menu `%s'!",
		     names, menu->title);
	names = cp;
    }
    return errors ? TRUE : FALSE;
}

