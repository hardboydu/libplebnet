/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: command.c,v 1.9 1995/05/20 13:24:33 jkh Exp $
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

#define MAX_NUM_COMMANDS	10

typedef struct {
    char key[FILENAME_MAX];
    struct {
	enum { CMD_SHELL, CMD_FUNCTION } type;
	void *ptr, *data;
    } cmds[MAX_NUM_COMMANDS];
    int ncmds;
} Command;

#define MAX_CMDS	200
static Command *commandStack[MAX_CMDS];
int numCommands;

/* Nuke the command stack */
void
command_clear(void)
{
    int i, j;

    for (i = 0; i < numCommands; i++)
	for (j = 0; j < commandStack[i]->ncmds; j++)
	    if (commandStack[i]->cmds[j].type == CMD_SHELL)
		free(commandStack[i]->cmds[j].ptr);
    free(commandStack[i]);
    numCommands = 0;
}

/* Add a shell command under a given key */
void
command_shell_add(char *key, char *fmt, ...)
{
    va_list args;
    char *cmd;
    int i;

    cmd = (char *)safe_malloc(1024);
    va_start(args, fmt);
    vsnprintf(cmd, 1024, fmt, args);
    va_end(args);

    /* First, look for the key already present and add a command to it */
    for (i = 0; i < numCommands; i++) {
	if (!strcmp(commandStack[i]->key, key)) {
	    if (commandStack[i]->ncmds == MAX_NUM_COMMANDS)
		msgFatal("More than %d commands stacked up behind %s??",
			 MAX_NUM_COMMANDS, key);
	    commandStack[i]->cmds[commandStack[i]->ncmds].type = CMD_SHELL;
	    commandStack[i]->cmds[commandStack[i]->ncmds].ptr = (void *)cmd;
	    commandStack[i]->cmds[commandStack[i]->ncmds].data = NULL;
	    ++(commandStack[i]->ncmds);
	    return;
	}
    }
    if (numCommands == MAX_CMDS)
	msgFatal("More than %d commands accumulated??", MAX_CMDS);

    /* If we fell to here, it's a new key */
    commandStack[numCommands] = safe_malloc(sizeof(Command));
    strcpy(commandStack[numCommands]->key, key);
    commandStack[numCommands]->ncmds = 1;
    commandStack[numCommands]->cmds[0].type = CMD_SHELL;
    commandStack[numCommands]->cmds[0].ptr = (void *)cmd;
    commandStack[numCommands++]->cmds[0].data = NULL;
}

/* Add a shell command under a given key */
void
command_func_add(char *key, commandFunc func, void *data)
{
    int i;

    /* First, look for the key already present and add a command to it */
    for (i = 0; i < numCommands; i++) {
	if (!strcmp(commandStack[i]->key, key)) {
	    if (commandStack[i]->ncmds == MAX_NUM_COMMANDS)
		msgFatal("More than %d commands stacked up behind %s??",
			 MAX_NUM_COMMANDS, key);
	    commandStack[i]->cmds[commandStack[i]->ncmds].type = CMD_FUNCTION;
	    commandStack[i]->cmds[commandStack[i]->ncmds].ptr = (void *)func;
	    commandStack[i]->cmds[commandStack[i]->ncmds].data = data;
	    ++(commandStack[i]->ncmds);
	    return;
	}
    }
    if (numCommands == MAX_CMDS)
	msgFatal("More than %d commands accumulated??", MAX_CMDS);

    /* If we fell to here, it's a new key */
    commandStack[numCommands] = safe_malloc(sizeof(Command));
    strcpy(commandStack[numCommands]->key, key);
    commandStack[numCommands]->ncmds = 1;
    commandStack[numCommands]->cmds[0].type = CMD_FUNCTION;
    commandStack[numCommands]->cmds[0].ptr = (void *)func;
    commandStack[numCommands++]->cmds[0].data = data;
}

/* arg to sort */
static int
sort_compare(const void *p1, const void *p2)
{
    return strcmp(((Command *)p1)->key, ((Command *)p2)->key);
}

void
command_sort(void)
{
    qsort(commandStack, numCommands, sizeof(Command *), sort_compare);
}

/* Run all accumulated commands in sorted order */
void
command_execute(void)
{
    int i, j, ret;
    commandFunc func;

    for (i = 0; i < numCommands; i++) {
	for (j = 0; j < commandStack[i]->ncmds; j++) {
	    /* If it's a shell command, run system on it */
	    if (commandStack[i]->cmds[j].type == CMD_SHELL) {
		msgNotify("Doing %s", commandStack[i]->cmds[j].ptr);
		ret = vsystem((char *)commandStack[i]->cmds[j].ptr);
		if (isDebug())
		    msgDebug("Command `%s' returns status %d\n", commandStack[i]->cmds[j].ptr, ret);
	    }
	    else {
		/* It's a function pointer - call it with the key and the data */
		func = (commandFunc)commandStack[i]->cmds[j].ptr;
		msgNotify("%x: Execute(%s, %s)", func, commandStack[i]->key, commandStack[i]->cmds[j].data);
		ret = (*func)(commandStack[i]->key, commandStack[i]->cmds[j].data);
		if (isDebug())
		    msgDebug("Function @ %x returns status %d\n", commandStack[i]->cmds[j].ptr, ret);
	    }
	}
    }
}
