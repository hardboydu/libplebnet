%{
/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <pjdlog.h>

#include "hast.h"

extern int depth;
extern int lineno;

extern FILE *yyin;
extern char *yytext;

static struct hastd_config *lconfig;
static struct hast_resource *curres;
static bool mynode;

static char depth0_control[HAST_ADDRSIZE];
static char depth0_listen[HAST_ADDRSIZE];
static int depth0_replication;
static int depth0_timeout;
static char depth0_exec[PATH_MAX];

static char depth1_provname[PATH_MAX];
static char depth1_localpath[PATH_MAX];

extern void yyrestart(FILE *);

static int
isitme(const char *name)
{
	char buf[MAXHOSTNAMELEN];
	char *pos;
	size_t bufsize;

	/*
	 * First check if the give name matches our full hostname.
	 */
	if (gethostname(buf, sizeof(buf)) < 0) {
		pjdlog_errno(LOG_ERR, "gethostname() failed");
		return (-1);
	}
	if (strcmp(buf, name) == 0)
		return (1);

	/*
	 * Now check if it matches first part of the host name.
	 */
	pos = strchr(buf, '.');
	if (pos != NULL && pos != buf && strncmp(buf, name, pos - buf) == 0)
		return (1);

	/*
	 * At the end check if name is equal to our host's UUID.
	 */
	bufsize = sizeof(buf);
	if (sysctlbyname("kern.hostuuid", buf, &bufsize, NULL, 0) < 0) {
		pjdlog_errno(LOG_ERR, "sysctlbyname(kern.hostuuid) failed");
		return (-1);
	}
	if (strcasecmp(buf, name) == 0)
		return (1);

	/*
	 * Looks like this isn't about us.
	 */
	return (0);
}

void
yyerror(const char *str)
{

	pjdlog_error("Unable to parse configuration file at line %d near '%s': %s",
	    lineno, yytext, str);
}

struct hastd_config *
yy_config_parse(const char *config, bool exitonerror)
{
	int ret;

	curres = NULL;
	mynode = false;
	depth = 0;
	lineno = 0;

	depth0_timeout = HAST_TIMEOUT;
	depth0_replication = HAST_REPLICATION_MEMSYNC;
	strlcpy(depth0_control, HAST_CONTROL, sizeof(depth0_control));
	strlcpy(depth0_listen, HASTD_LISTEN, sizeof(depth0_listen));
	depth0_exec[0] = '\0';

	lconfig = calloc(1, sizeof(*lconfig));
	if (lconfig == NULL) {
		pjdlog_error("Unable to allocate memory for configuration.");
		if (exitonerror)
			exit(EX_TEMPFAIL);
		return (NULL);
	}

	TAILQ_INIT(&lconfig->hc_resources);

	yyin = fopen(config, "r");
	if (yyin == NULL) {
		pjdlog_errno(LOG_ERR, "Unable to open configuration file %s",
		    config);
		yy_config_free(lconfig);
		if (exitonerror)
			exit(EX_OSFILE);
		return (NULL);
	}
	yyrestart(yyin);
	ret = yyparse();
	fclose(yyin);
	if (ret != 0) {
		yy_config_free(lconfig);
		if (exitonerror)
			exit(EX_CONFIG);
		return (NULL);
	}

	/*
	 * Let's see if everything is set up.
	 */
	if (lconfig->hc_controladdr[0] == '\0') {
		strlcpy(lconfig->hc_controladdr, depth0_control,
		    sizeof(lconfig->hc_controladdr));
	}
	if (lconfig->hc_listenaddr[0] == '\0') {
		strlcpy(lconfig->hc_listenaddr, depth0_listen,
		    sizeof(lconfig->hc_listenaddr));
	}
	TAILQ_FOREACH(curres, &lconfig->hc_resources, hr_next) {
		assert(curres->hr_provname[0] != '\0');
		assert(curres->hr_localpath[0] != '\0');
		assert(curres->hr_remoteaddr[0] != '\0');

		if (curres->hr_replication == -1) {
			/*
			 * Replication is not set at resource-level.
			 * Use global or default setting.
			 */
			curres->hr_replication = depth0_replication;
		}
		if (curres->hr_timeout == -1) {
			/*
			 * Timeout is not set at resource-level.
			 * Use global or default setting.
			 */
			curres->hr_timeout = depth0_timeout;
		}
		if (curres->hr_exec[0] == '\0') {
			/*
			 * Exec is not set at resource-level.
			 * Use global or default setting.
			 */
			strlcpy(curres->hr_exec, depth0_exec,
			    sizeof(curres->hr_exec));
		}
	}

	return (lconfig);
}

void
yy_config_free(struct hastd_config *config)
{
	struct hast_resource *res;

	while ((res = TAILQ_FIRST(&config->hc_resources)) != NULL) {
		TAILQ_REMOVE(&config->hc_resources, res, hr_next);
		free(res);
	}
	free(config);
}
%}

%token CONTROL LISTEN PORT REPLICATION TIMEOUT EXEC EXTENTSIZE RESOURCE NAME LOCAL REMOTE ON
%token FULLSYNC MEMSYNC ASYNC
%token NUM STR OB CB

%type <num> replication_type

%union
{
	int num;
	char *str;
}

%token <num> NUM
%token <str> STR

%%

statements:
	|
	statements statement
	;

statement:
	control_statement
	|
	listen_statement
	|
	replication_statement
	|
	timeout_statement
	|
	exec_statement
	|
	node_statement
	|
	resource_statement
	;

control_statement:	CONTROL STR
	{
		switch (depth) {
		case 0:
			if (strlcpy(depth0_control, $2,
			    sizeof(depth0_control)) >=
			    sizeof(depth0_control)) {
				pjdlog_error("control argument is too long.");
				return (1);
			}
			break;
		case 1:
			if (!mynode)
				break;
			if (strlcpy(lconfig->hc_controladdr, $2,
			    sizeof(lconfig->hc_controladdr)) >=
			    sizeof(lconfig->hc_controladdr)) {
				pjdlog_error("control argument is too long.");
				return (1);
			}
			break;
		default:
			assert(!"control at wrong depth level");
		}
	}
	;

listen_statement:	LISTEN STR
	{
		switch (depth) {
		case 0:
			if (strlcpy(depth0_listen, $2,
			    sizeof(depth0_listen)) >=
			    sizeof(depth0_listen)) {
				pjdlog_error("listen argument is too long.");
				return (1);
			}
			break;
		case 1:
			if (!mynode)
				break;
			if (strlcpy(lconfig->hc_listenaddr, $2,
			    sizeof(lconfig->hc_listenaddr)) >=
			    sizeof(lconfig->hc_listenaddr)) {
				pjdlog_error("listen argument is too long.");
				return (1);
			}
			break;
		default:
			assert(!"listen at wrong depth level");
		}
	}
	;

replication_statement:	REPLICATION replication_type
	{
		switch (depth) {
		case 0:
			depth0_replication = $2;
			break;
		case 1:
			if (curres != NULL)
				curres->hr_replication = $2;
			break;
		default:
			assert(!"replication at wrong depth level");
		}
	}
	;

replication_type:
	FULLSYNC	{ $$ = HAST_REPLICATION_FULLSYNC; }
	|
	MEMSYNC		{ $$ = HAST_REPLICATION_MEMSYNC; }
	|
	ASYNC		{ $$ = HAST_REPLICATION_ASYNC; }
	;

timeout_statement:	TIMEOUT NUM
	{
		switch (depth) {
		case 0:
			depth0_timeout = $2;
			break;
		case 1:
			if (curres != NULL)
				curres->hr_timeout = $2;
			break;
		default:
			assert(!"timeout at wrong depth level");
		}
	}
	;

exec_statement:		EXEC STR
	{
		switch (depth) {
		case 0:
			if (strlcpy(depth0_exec, $2, sizeof(depth0_exec)) >=
			    sizeof(depth0_exec)) {
				pjdlog_error("Exec path is too long.");
				return (1);
			}
			break;
		case 1:
			if (curres == NULL)
				break;
			if (strlcpy(curres->hr_exec, $2,
			    sizeof(curres->hr_exec)) >=
			    sizeof(curres->hr_exec)) {
				pjdlog_error("Exec path is too long.");
				return (1);
			}
			break;
		default:
			assert(!"exec at wrong depth level");
		}
	}
	;

node_statement:		ON node_start OB node_entries CB
	{
		mynode = false;
	}
	;

node_start:	STR
	{
		switch (isitme($1)) {
		case -1:
			return (1);
		case 0:
			break;
		case 1:
			mynode = true;
			break;
		default:
			assert(!"invalid isitme() return value");
		}
	}
	;

node_entries:
	|
	node_entries node_entry
	;

node_entry:
	control_statement
	|
	listen_statement
	;

resource_statement:	RESOURCE resource_start OB resource_entries CB
	{
		if (curres != NULL) {
			/*
			 * Let's see there are some resource-level settings
			 * that we can use for node-level settings.
			 */
			if (curres->hr_provname[0] == '\0' &&
			    depth1_provname[0] != '\0') {
				/*
				 * Provider name is not set at node-level,
				 * but is set at resource-level, use it.
				 */
				strlcpy(curres->hr_provname, depth1_provname,
				    sizeof(curres->hr_provname));
			}
			if (curres->hr_localpath[0] == '\0' &&
			    depth1_localpath[0] != '\0') {
				/*
				 * Path to local provider is not set at
				 * node-level, but is set at resource-level,
				 * use it.
				 */
				strlcpy(curres->hr_localpath, depth1_localpath,
				    sizeof(curres->hr_localpath));
			}

			/*
			 * If provider name is not given, use resource name
			 * as provider name.
			 */
			if (curres->hr_provname[0] == '\0') {
				strlcpy(curres->hr_provname, curres->hr_name,
				    sizeof(curres->hr_provname));
			}

			/*
			 * Remote address has to be configured at this point.
			 */
			if (curres->hr_remoteaddr[0] == '\0') {
				pjdlog_error("Remote address not configured for resource %s.",
				    curres->hr_name);
				return (1);
			}
			/*
			 * Path to local provider has to be configured at this
			 * point.
			 */
			if (curres->hr_localpath[0] == '\0') {
				pjdlog_error("Path to local component not configured for resource %s.",
				    curres->hr_name);
				return (1);
			}

			/* Put it onto resource list. */
			TAILQ_INSERT_TAIL(&lconfig->hc_resources, curres, hr_next);
			curres = NULL;
		}
	}
	;

resource_start:	STR
	{
		/*
		 * Clear those, so we can tell if they were set at
		 * resource-level or not.
		 */
		depth1_provname[0] = '\0';
		depth1_localpath[0] = '\0';

		curres = calloc(1, sizeof(*curres));
		if (curres == NULL) {
			pjdlog_error("Unable to allocate memory for resource.");
			return (1);
		}
		if (strlcpy(curres->hr_name, $1,
		    sizeof(curres->hr_name)) >=
		    sizeof(curres->hr_name)) {
			pjdlog_error("Resource name is too long.");
			return (1);
		}
		curres->hr_role = HAST_ROLE_INIT;
		curres->hr_previous_role = HAST_ROLE_INIT;
		curres->hr_replication = -1;
		curres->hr_timeout = -1;
		curres->hr_exec[0] = '\0';
		curres->hr_provname[0] = '\0';
		curres->hr_localpath[0] = '\0';
		curres->hr_localfd = -1;
		curres->hr_remoteaddr[0] = '\0';
		curres->hr_ggateunit = -1;
	}
	;

resource_entries:
	|
	resource_entries resource_entry
	;

resource_entry:
	replication_statement
	|
	timeout_statement
	|
	exec_statement
	|
	name_statement
	|
	local_statement
	|
	resource_node_statement
	;

name_statement:		NAME STR
	{
		switch (depth) {
		case 1:
			if (strlcpy(depth1_provname, $2,
			    sizeof(depth1_provname)) >=
			    sizeof(depth1_provname)) {
				pjdlog_error("name argument is too long.");
				return (1);
			}
			break;
		case 2:
			if (!mynode)
				break;
			assert(curres != NULL);
			if (strlcpy(curres->hr_provname, $2,
			    sizeof(curres->hr_provname)) >=
			    sizeof(curres->hr_provname)) {
				pjdlog_error("name argument is too long.");
				return (1);
			}
			break;
		default:
			assert(!"name at wrong depth level");
		}
	}
	;

local_statement:	LOCAL STR
	{
		switch (depth) {
		case 1:
			if (strlcpy(depth1_localpath, $2,
			    sizeof(depth1_localpath)) >=
			    sizeof(depth1_localpath)) {
				pjdlog_error("local argument is too long.");
				return (1);
			}
			break;
		case 2:
			if (!mynode)
				break;
			assert(curres != NULL);
			if (strlcpy(curres->hr_localpath, $2,
			    sizeof(curres->hr_localpath)) >=
			    sizeof(curres->hr_localpath)) {
				pjdlog_error("local argument is too long.");
				return (1);
			}
			break;
		default:
			assert(!"local at wrong depth level");
		}
	}
	;

resource_node_statement:ON resource_node_start OB resource_node_entries CB
	{
		mynode = false;
	}
	;

resource_node_start:	STR
	{
		if (curres != NULL) {
			switch (isitme($1)) {
			case -1:
				return (1);
			case 0:
				break;
			case 1:
				mynode = true;
				break;
			default:
				assert(!"invalid isitme() return value");
			}
		}
	}
	;

resource_node_entries:
	|
	resource_node_entries resource_node_entry
	;

resource_node_entry:
	name_statement
	|
	local_statement
	|
	remote_statement
	;

remote_statement:	REMOTE STR
	{
		assert(depth == 2);
		if (mynode) {
			assert(curres != NULL);
			if (strlcpy(curres->hr_remoteaddr, $2,
			    sizeof(curres->hr_remoteaddr)) >=
			    sizeof(curres->hr_remoteaddr)) {
				pjdlog_error("remote argument is too long.");
				return (1);
			}
		}
	}
	;
