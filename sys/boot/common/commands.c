/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: commands.c,v 1.3 1998/09/18 02:01:38 msmith Exp $
 */

#include <stand.h>
#include <string.h>
#include <sys/reboot.h>

#include "bootstrap.h"

char		*command_errmsg;
char		command_errbuf[256];	/* XXX should have procedural interface for setting, size limit? */
    
COMMAND_SET(help, "help", "detailed help", command_help);

static int
command_help(int argc, char *argv[])
{
    char	helppath[80];	/* XXX buffer size? */

    /* page the help text from our load path */
    sprintf(helppath, "%s/boot/boot.help", getenv("loaddev"));
    printf("%s\n", helppath);
    if (pager_file(helppath) == -1)
	printf("Verbose help not available, use '?' to list commands\n");
    return(CMD_OK);
}

COMMAND_SET(commandlist, "?", "list commands", command_commandlist);

static int
command_commandlist(int argc, char *argv[])
{
    struct bootblk_command	**cmdp;
    int				i;
    
    printf("Available commands:\n");
    cmdp = (struct bootblk_command **)Xcommand_set.ls_items;
    for (i = 0; i < Xcommand_set.ls_length; i++)
	if ((cmdp[i]->c_name != NULL) && (cmdp[i]->c_desc != NULL))
	    printf("  %-15s  %s\n", cmdp[i]->c_name, cmdp[i]->c_desc);
    return(CMD_OK);
}

/*
 * XXX set/show should become set/echo if we have variable
 * substitution happening.
 */

COMMAND_SET(show, "show", "show variable(s)", command_show);

static int
command_show(int argc, char *argv[])
{
    struct env_var	*ev;
    char		*cp;

    if (argc < 2) {
	/* 
	 * With no arguments, print everything.
	 */
	pager_open();
	for (ev = environ; ev != NULL; ev = ev->ev_next) {
	    pager_output(ev->ev_name);
	    cp = getenv(ev->ev_name);
	    if (cp != NULL) {
		pager_output("=");
		pager_output(cp);
	    }
	    pager_output("\n");
	}
	pager_close();
    } else {
	if ((cp = getenv(argv[1])) != NULL) {
	    printf("%s\n", cp);
	} else {
	    sprintf(command_errbuf, "variable '%s' not found", argv[1]);
	    return(CMD_ERROR);
	}
    }
    return(CMD_OK);
}

COMMAND_SET(set, "set", "set a variable", command_set);

static int
command_set(int argc, char *argv[])
{
    int		err;
    
    if (argc != 2) {
	command_errmsg = "wrong number of arguments";
	return(CMD_ERROR);
    } else {
	if ((err = putenv(argv[1])) != 0) {
	    command_errmsg = strerror(err);
	    return(CMD_ERROR);
	}
    }
    return(CMD_OK);
}

COMMAND_SET(unset, "unset", "unset a variable", command_unset);

static int
command_unset(int argc, char *argv[]) 
{
    int		err;
    
    if (argc != 2) {
	command_errmsg = "wrong number of arguments";
	return(CMD_ERROR);
    } else {
	if ((err = unsetenv(argv[1])) != 0) {
	    command_errmsg = strerror(err);
	    return(CMD_ERROR);
	}
    }
    return(CMD_OK);
}

COMMAND_SET(echo, "echo", NULL, command_echo);

static int
command_echo(int argc, char *argv[])
{
    char	*s;
    int		nl, ch;
    
    nl = 0;
    optind = 1;
    while ((ch = getopt(argc, argv, "n")) != -1) {
	switch(ch) {
	case 'n':
	    nl = 1;
	    break;
	case '?':
	default:
	    /* getopt has already reported an error */
	    return(CMD_OK);
	}
    }
    argv += (optind);
    argc -= (optind);

    s = unargv(argc, argv);
    if (s != NULL) {
	printf(s);
	free(s);
    }
    if (!nl)
	printf("\n");
    return(CMD_OK);
}

/*
 * A passable emulation of the sh(1) command of the same name.
 */

COMMAND_SET(read, "read", NULL, command_read);

static int
command_read(int argc, char *argv[])
{
    char	*prompt;
    int		timeout;
    time_t	when;
    char	*cp;
    char	*name;
    char	buf[256];		/* XXX size? */
    int		c;
    
    timeout = -1;
    prompt = NULL;
    optind = 1;
    while ((c = getopt(argc, argv, "p:t:")) != -1) {
	switch(c) {
	    
	case 'p':
	    prompt = optarg;
	    break;
	case 't':
	    timeout = strtol(optarg, &cp, 0);
	    if (cp == optarg) {
		sprintf(command_errbuf, "bad timeout '%s'", optarg);
		return(CMD_ERROR);
	    }
	    break;
	default:
	    return(CMD_OK);
	}
    }

    argv += (optind);
    argc -= (optind);
    name = (argc > 0) ? argv[0]: NULL;
	
    if (prompt != NULL)
	printf(prompt);
    if (timeout >= 0) {
	when = time(NULL) + timeout;
	while (!ischar())
	    if (time(NULL) >= when)
		return(CMD_OK);		/* is timeout an error? */
    }

    ngets(buf, sizeof(buf));

    printf("read name '%s' value '%s'\n", name, buf);

    if (name != NULL)
	setenv(name, buf, 1);
    return(CMD_OK);
}
