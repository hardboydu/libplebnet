%{
/*-
 * Copyright (c) 1995 Alex Tatmanjants <alex@elvisti.kiev.ua>
 *		at Electronni Visti IA, Kiev, Ukraine.
 *			All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: parse.y,v 1.2 1995/01/24 11:15:47 alex Exp alex $
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include "collate.h"

extern int line_no;
extern FILE *yyin;

u_char __collate_charmap_table[UCHAR_MAX + 1][STR_LEN];
u_char __collate_substitute_table[UCHAR_MAX + 1][STR_LEN];
struct __collate_st_char_pri __collate_char_pri_table[UCHAR_MAX + 1];
struct __collate_st_name_pri __collate_name_pri_table[TABLE_SIZE];
struct __collate_st_chain_pri __collate_chain_pri_table[TABLE_SIZE];
int name_index, chain_index;
int prim_pri = 1, sec_pri = 1;
#ifdef COLLATE_DEBUG
int debug;
#endif

char *out_file = "LC_COLLATE";
%}
%union {
	u_char ch;
	u_char str[STR_LEN];
}
%token SUBSTITUTE WITH ORDER RANGE
%token <str> STRING
%token <str> NAME
%token <str> CHAIN
%token <ch> CHAR
%%
collate : statment_list
;
statment_list : statment
	| statment_list '\n' statment
;
statment :
	| charmap
	| substitute
	| order
;
charmap : CHAIN CHAR {
	strcpy(__collate_charmap_table[$2], $1);
}
	| CHAR CHAR {
	__collate_charmap_table[$2][0] = $1;
	__collate_charmap_table[$2][1] = '\0';
}
;
substitute : SUBSTITUTE STRING WITH STRING {
	strcpy(__collate_substitute_table[$2[0]], $4);
}
;
order : ORDER order_list {
	FILE *fp = fopen(out_file, "w");

	if(!fp)
		err(EX_UNAVAILABLE, "con't open destination file %s",
		    out_file);

	fwrite(__collate_charmap_table, sizeof(__collate_charmap_table), 1, fp);
	fwrite(__collate_substitute_table, sizeof(__collate_substitute_table), 1, fp);
	fwrite(__collate_char_pri_table, sizeof(__collate_char_pri_table), 1, fp);
	fwrite(__collate_chain_pri_table, sizeof(__collate_chain_pri_table), 1, fp);
	fwrite(__collate_name_pri_table, sizeof(__collate_name_pri_table), 1, fp);
#ifdef COLLATE_DEBUG
	if (debug)
		__collate_print_tables();
#endif
	exit(EX_OK);
}
;
order_list : item
	| order_list ';' item
;
item : CHAR { __collate_char_pri_table[$1].prim = prim_pri++; }
	| CHAIN {
	if (chain_index >= TABLE_SIZE - 1)
		yyerror("__collate_chain_pri_table overflow");
	strcpy(__collate_chain_pri_table[chain_index].str, $1);
	__collate_chain_pri_table[chain_index++].prim = prim_pri++;
}
	| NAME {
	if (name_index >= TABLE_SIZE - 1)
		yyerror("__collate_name_pri_table overflow");
	strcpy(__collate_name_pri_table[name_index].str, $1);
	__collate_name_pri_table[name_index++].prim = prim_pri++;
}
	| CHAR RANGE CHAR {
	u_int i;

	if ($3 <= $1)
		yyerror("Illegal range %c -- %c near line %d\n",
			$1, $3, line_no);

	for (i = $1; i <= $3; i++) {
		__collate_char_pri_table[(u_char)i].prim = prim_pri++;
	}
}
	| '{' prim_order_list '}' {
	prim_pri++;
}
	| '(' sec_order_list ')' {
	prim_pri++;
	sec_pri = 1;
}
;
prim_order_list : prim_sub_item
	| prim_order_list ',' prim_sub_item 
;
sec_order_list : sec_sub_item
	| sec_order_list ',' sec_sub_item 
;
prim_sub_item : CHAR {
	__collate_char_pri_table[$1].prim = prim_pri;
}
	| CHAR RANGE CHAR {
	u_int i;

	if ($3 <= $1)
		yyerror("Illegal range %c -- %c near line %d\n",
			$1, $3, line_no);

	for (i = $1; i <= $3; i++) {
		__collate_char_pri_table[(u_char)i].prim = prim_pri;
	}
}
	| NAME {
	if (name_index >= TABLE_SIZE - 1)
		yyerror("__collate_name_pri_table overflow");
	strcpy(__collate_name_pri_table[name_index].str, $1);
	__collate_name_pri_table[name_index++].prim = prim_pri;
}
	| CHAIN {
	if (chain_index >= TABLE_SIZE - 1)
		yyerror("__collate_chain_pri_table overflow");
	strcpy(__collate_chain_pri_table[chain_index].str, $1);
	__collate_chain_pri_table[chain_index++].prim = prim_pri;
}
;
sec_sub_item : CHAR {
	__collate_char_pri_table[$1].prim = prim_pri;
	__collate_char_pri_table[$1].sec = sec_pri++;
}
	| CHAR RANGE CHAR {
	u_int i;

	if ($3 <= $1)
		yyerror("Illegal range %c -- %c near line %d\n",
			$1, $3, line_no);

	for (i = $1; i <= $3; i++) {
		__collate_char_pri_table[(u_char)i].prim = prim_pri;
		__collate_char_pri_table[(u_char)i].sec = sec_pri++;
	}
}
	| NAME {
	if (name_index >= TABLE_SIZE - 1)
		yyerror("__collate_name_pri_table overflow");
	strcpy(__collate_name_pri_table[name_index].str, $1);
	__collate_name_pri_table[name_index].prim = prim_pri;
	__collate_name_pri_table[name_index++].sec = sec_pri++;
}
	| CHAIN {
	if (chain_index >= TABLE_SIZE - 1)
		yyerror("__collate_chain_pri_table overflow");
	strcpy(__collate_chain_pri_table[chain_index].str, $1);
	__collate_chain_pri_table[chain_index].prim = prim_pri;
	__collate_chain_pri_table[chain_index++].sec = sec_pri++;
}
;
%%
main(ac, av)
	char **av;
{
	int ch;

#ifdef COLLATE_DEBUG
	while((ch = getopt(ac, av, ":do:")) != EOF) {
#else
	while((ch = getopt(ac, av, ":o:")) != EOF) {
#endif
		switch (ch)
		{
#ifdef COLLATE_DEBUG
		  case 'd':
			debug++;
			break;
#endif
		  case 'o':
			out_file = optarg;
			break;

		  default:
			fprintf(stderr, "Usage: %s [-o out_file] [in_file]\n",
				av[0]);
			exit(EX_OK);
		}
	}
	ac -= optind;
	av += optind;
	if(ac > 0) {
		if((yyin = fopen(*av, "r")) == 0)
			err(EX_UNAVAILABLE, "can't open source file %s", *av);
	}
	for(ch = 0; ch <= UCHAR_MAX; ch++)
		__collate_substitute_table[ch][0] = ch;
	yyparse();
	return 0;
}

yyerror(msg)
	char *msg;
{
	errx(EX_UNAVAILABLE, "%s near line %d", msg, line_no);
}
