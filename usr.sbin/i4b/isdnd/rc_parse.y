/*
 *   Copyright (c) 1997 Joerg Wunsch. All rights reserved.
 *
 *   Copyright (c) 1997, 1998 Hellmuth Michaelis. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *   SUCH DAMAGE.
 *
 *---------------------------------------------------------------------------
 *
 *	i4b daemon - runtime configuration parser
 *	-----------------------------------------
 *
 *	$Id: rc_parse.y,v 1.15 1998/12/05 18:03:38 hm Exp $ 
 *
 *      last edit-date: [Sat Dec  5 18:12:26 1998]
 *
 *---------------------------------------------------------------------------*/

%{

/* #define YYDEBUG 1 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "monitor.h"	/* monitor access rights bit definitions */
#include "isdnd.h"

#ifndef FALSE
# define FALSE 0
#endif

#ifndef TRUE
# define TRUE 1
#endif

extern void 	cfg_setval(int keyword);
extern void	reset_scanner(FILE *infile);
extern void 	yyerror(const char *msg);
extern int	yylex();

extern int	lineno;
extern char	*yytext;
extern int	nentries;

int		saw_system = 0;
int		entrycount = -1;

%}

%token		ACCTALL
%token		ACCTFILE
%token		ALERT
%token		ALIASING
%token		ALIASFNAME
%token		ANSWERPROG
%token		B1PROTOCOL
%token		CALLBACKWAIT
%token		CALLEDBACKWAIT
%token		CONNECTPROG
%token		DIALRETRIES
%token		DIALRANDINCR
%token		DIALOUTTYPE
%token		DIRECTION
%token		DISCONNECTPROG
%token		DOWNTRIES
%token		DOWNTIME
%token		EARLYHANGUP
%token		ENTRY
%token		IDLETIME_IN
%token		IDLETIME_OUT
%token		ISDNCONTROLLER
%token		ISDNCHANNEL
%token		ISDNTIME
%token		ISDNTXDELIN
%token		ISDNTXDELOUT
%token		LOCAL_PHONE_DIALOUT
%token		LOCAL_PHONE_INCOMING
%token		MONITORSW
%token		MONITORPORT
%token		MONITOR
%token		MONITORACCESS
%token		FULLCMD
%token		RESTRICTEDCMD
%token		CHANNELSTATE
%token		CALLIN
%token		CALLOUT
%token		LOGEVENTS
%token		NAME
%token		NO
%token		OFF
%token		ON
%token		RATESFILE
%token 		RATETYPE
%token		REMOTE_NUMBERS_HANDLING
%token		REMOTE_PHONE_INCOMING
%token		REMOTE_PHONE_DIALOUT
%token		REACTION
%token		RECOVERYTIME
%token		REGEXPR
%token		REGPROG
%token		RTPRIO
%token		SYSTEM
%token		UNITLENGTH
%token		UNITLENGTHSRC
%token		USEACCTFILE
%token		USRDEVICENAME
%token		USRDEVICEUNIT
%token		USEDOWN
%token		YES

%token	<str>	NUMBERSTR

%token	<str>	STRING

%type	<booln>	boolean 

%type	<num>	sysfilekeyword sysnumkeyword sysstrkeyword sysboolkeyword
%type	<num>	numkeyword strkeyword boolkeyword monrights monright
%type	<str>	filename

%union {
	int 	booln;
	int	num;
	char 	*str;
}

%%

config:		sections
		;

sections:	possible_nullentries
		syssect
		entrysects
		;

possible_nullentries:
		/* lambda */
		| possible_nullentries error '\n'
		| possible_nullentries nullentry
		;

nullentry:	'\n'
		;

entrysects:	entrysect
		| entrysects entrysect
		;

syssect:	SYSTEM sysentries
		;

sysentries:	sysentry
			{ 
				saw_system = 1; 
				monitor_clear_rights();
			}
		| sysentries sysentry
		;

sysentry:	sysfileentry
		| sysboolentry
		| sysnumentry
		| sysstrentry
		| sysmonitorstart
		| sysmonitorrights
		| nullentry
		| error '\n'
		;

  
sysmonitorstart:
		MONITOR '=' STRING '\n'
			{
			    char *err = NULL;
			    switch (monitor_start_rights($3)) {
			    	case I4BMAR_OK:
			    		break;
			    	case I4BMAR_LENGTH:
			    		err = "local socket name too long: %s";
			    		break;
			    	case I4BMAR_DUP:
			    		err = "duplicate entry: %s";
			    		break;
			    	case I4BMAR_CIDR:
			    		err = "invalid CIDR specification: %s";
			    		break;
			    	case I4BMAR_NOIP:
			    		err = "could not resolve host or net specification: %s";
			    		break;
			    }
			    if (err) {
			    	char msg[1024];
		    		snprintf(msg, sizeof msg, err, $3);
		    		yyerror(msg);
		    	    }
			}
		;

sysmonitorrights:
		MONITORACCESS '=' monrights '\n'
			{ monitor_add_rights($3); }	
		;

monrights:	monrights ',' monright	{ $$ = $1 | $3; }
		| monright		{ $$ = $1; }
		;

monright:	FULLCMD			{ $$ = I4B_CA_COMMAND_FULL; }
		| RESTRICTEDCMD		{ $$ = I4B_CA_COMMAND_RESTRICTED; }
		| CHANNELSTATE		{ $$ = I4B_CA_EVNT_CHANSTATE; }
		| CALLIN		{ $$ = I4B_CA_EVNT_CALLIN; }
		| CALLOUT		{ $$ = I4B_CA_EVNT_CALLOUT; }
		| LOGEVENTS		{ $$ = I4B_CA_EVNT_I4B; }
		;

sysfileentry:	sysfilekeyword '=' filename '\n'
			{
			cfg_setval($1);
			}
		;

sysboolentry:	sysboolkeyword '=' boolean '\n'
			{
			yylval.booln = $3;
			cfg_setval($1);
			}
		;

sysnumentry:	sysnumkeyword '=' NUMBERSTR '\n'
			{ 
			yylval.num = atoi($3);
			cfg_setval($1);
			}
		;

sysstrentry:	  sysstrkeyword '=' STRING '\n'
			{ 
			cfg_setval($1);
			}
		| sysstrkeyword '=' NUMBERSTR '\n'
			{ 
			cfg_setval($1);
			}
		;

filename:	STRING		{
					if ($1[0] != '/') 
					{
						yyerror("filename doesn't start with a slash");
						YYERROR;
					}
					$$ = $1;
				}
		;

boolean:	  NO			{ $$ = FALSE; }
		| OFF			{ $$ = FALSE; }
		| ON			{ $$ = TRUE; }
		| YES			{ $$ = TRUE; }
		;

sysfilekeyword:	  RATESFILE		{ $$ = RATESFILE; }
		| ACCTFILE		{ $$ = ACCTFILE; }
		| ALIASFNAME		{ $$ = ALIASFNAME; }
		;

sysboolkeyword:	  USEACCTFILE		{ $$ = USEACCTFILE; }
		| ALIASING		{ $$ = ALIASING; }
		| ACCTALL		{ $$ = ACCTALL; }
		| ISDNTIME		{ $$ = ISDNTIME; }
		| MONITORSW		{ $$ = MONITORSW; }
		;

sysnumkeyword:	  MONITORPORT		{ $$ = MONITORPORT; }
		| RTPRIO		{ $$ = RTPRIO; }
		;

sysstrkeyword:	  REGEXPR		{ $$ = REGEXPR; }
		| REGPROG		{ $$ = REGPROG; }
		;

entrysect:	ENTRY
			{ 
				entrycount++;
				nentries++;
			}
		entries
		;

entries:	entry
		| entries entry
		;

entry:		strentry
		| numentry
		| boolentry
		| nullentry
		| error '\n'
		;

strentry:	strkeyword '=' STRING '\n'
			{ 
			cfg_setval($1);
			}
		| strkeyword '=' NUMBERSTR '\n'
			{ 
			cfg_setval($1);
			}
		;

boolentry:	boolkeyword '=' boolean '\n'
			{
			yylval.booln = $3;
			cfg_setval($1);
			}
		;

numentry:	numkeyword '=' NUMBERSTR '\n'
			{ 
			yylval.num = atoi($3);
			cfg_setval($1);
			}
		;

strkeyword:	  ANSWERPROG		{ $$ = ANSWERPROG; }
		| B1PROTOCOL		{ $$ = B1PROTOCOL; }
		| CONNECTPROG		{ $$ = CONNECTPROG; }
		| DIALOUTTYPE		{ $$ = DIALOUTTYPE; }
		| DIRECTION		{ $$ = DIRECTION; }
		| DISCONNECTPROG	{ $$ = DISCONNECTPROG; }
		| LOCAL_PHONE_INCOMING	{ $$ = LOCAL_PHONE_INCOMING; }
		| LOCAL_PHONE_DIALOUT	{ $$ = LOCAL_PHONE_DIALOUT; }
		| NAME			{ $$ = NAME; }		
		| REACTION		{ $$ = REACTION; }
		| REMOTE_NUMBERS_HANDLING { $$ = REMOTE_NUMBERS_HANDLING; }
		| REMOTE_PHONE_INCOMING	{ $$ = REMOTE_PHONE_INCOMING; }
		| REMOTE_PHONE_DIALOUT	{ $$ = REMOTE_PHONE_DIALOUT; }
		| UNITLENGTHSRC		{ $$ = UNITLENGTHSRC; }		
		| USRDEVICENAME		{ $$ = USRDEVICENAME; }
		;

numkeyword:	  ALERT			{ $$ = ALERT; }
		| CALLBACKWAIT		{ $$ = CALLBACKWAIT; }
		| CALLEDBACKWAIT	{ $$ = CALLEDBACKWAIT; }
		| DIALRETRIES		{ $$ = DIALRETRIES; }
		| EARLYHANGUP		{ $$ = EARLYHANGUP; }
		| IDLETIME_IN		{ $$ = IDLETIME_IN; }
		| IDLETIME_OUT		{ $$ = IDLETIME_OUT; }
		| ISDNCONTROLLER	{ $$ = ISDNCONTROLLER; }
		| ISDNCHANNEL		{ $$ = ISDNCHANNEL; }
		| ISDNTXDELIN		{ $$ = ISDNTXDELIN; }
		| ISDNTXDELOUT		{ $$ = ISDNTXDELOUT; }
		| RATETYPE		{ $$ = RATETYPE; }
		| RECOVERYTIME		{ $$ = RECOVERYTIME; }
		| UNITLENGTH		{ $$ = UNITLENGTH; }		
		| USRDEVICEUNIT		{ $$ = USRDEVICEUNIT; }
		| DOWNTIME		{ $$ = DOWNTIME; }
		| DOWNTRIES		{ $$ = DOWNTRIES; }
		;

boolkeyword:	  DIALRANDINCR		{ $$ = DIALRANDINCR; }
		| USEDOWN		{ $$ = USEDOWN; }
		;

%%
