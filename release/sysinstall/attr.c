/*
 * The new sysinstall program.
 *
 * This is probably the last attempt in the `sysinstall' line, the next
 * generation being slated to essentially a complete rewrite.
 *
 * $Id: media_strategy.c,v 1.28 1995/05/26 20:30:59 jkh Exp $
 *
 * Copyright (c) 1995
 *	Jordan Hubbard.  All rights reserved.
 * Copyright (c) 1995
 * 	Gary J Palmer. All rights reserved.
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
#include <sys/errno.h>
static int		num_attribs;

int
attr_parse(Attribs **attr, char *file)
{
    char hold_n[MAX_NAME+1];
    char hold_v[MAX_VALUE+1];
    int n, v, ch = 0;
    enum { LOOK, COMMENT, NAME, VALUE, COMMIT } state;
    FILE *fp;
    static int 		lno;
    
    num_attribs = n = v = lno = 0;
    state = LOOK;
    
    if ((fp = fopen(file, "r")) == NULL) {
	msgConfirm("Cannot open the information file `%s': %s (%d)", file, strerror(errno), errno);
	return 0;
    }

    while (state == COMMIT || (ch = fgetc(fp)) != EOF) {
	/* Count lines */
	if (ch == '\n')
	    ++lno;
	switch(state) {
	case LOOK:
	    if (isspace(ch))
		continue;
	    /* Allow shell or lisp style comments */
	    else if (ch == '#' || ch == ';') {
		state = COMMENT;
		continue;
	    }
	    else if (isalpha(ch)) {
		hold_n[n++] = ch;
		state = NAME;
	    }
	    else
		msgFatal("Invalid character '%c' at line %d\n", ch, lno);
	    break;
	    
	case COMMENT:
	    if (ch == '\n')
		state = LOOK;
	    break;
	    
	case NAME:
	    if (ch == '\n') {
		hold_n[n] = '\0';
		hold_v[v = 0] = '\0';
		state = COMMIT;
	    }
	    else if (isspace(ch))
		continue;
	    else if (ch == '=') {
		hold_n[n] = '\0';
		state = VALUE;
	    }
	    else
		hold_n[n++] = ch;
	    break;
	    
	case VALUE:
	    if (v == 0 && isspace(ch))
		continue;
	    else if (ch == '{') {
		/* multiline value */
		while ((ch = fgetc(fp)) != '}') {
		    if (ch == EOF)
			msgFatal("Unexpected EOF on line %d", lno);
		    else {
		    	if (v == MAX_VALUE)
			    msgFatal("Value length overflow at line %d", lno);
		        hold_v[v++] = ch;
		    }
		}
		hold_v[v] = '\0';
		state = COMMIT;
	    }
	    else if (ch == '\n') {
		hold_v[v] = '\0';
		state = COMMIT;
	    }
	    else {
		if (v == MAX_VALUE)
		    msgFatal("Value length overflow at line %d", lno);
		else
		    hold_v[v++] = ch;
	    }
	    break;
	    
	case COMMIT:
	    (*attr)[num_attribs].name = strdup(hold_n);
	    (*attr)[num_attribs++].value = strdup(hold_v);
	    state = LOOK;
	    v = n = 0;
	    break;

	default:
	    msgFatal("Unknown state at line %d??\n", lno);
	}
    }
    fclose(fp);
    return 1;
}

const char *
attr_match(Attribs *attr, char *name)
{
    int n = 0;

    while((strcasecmp(attr[n].name, name)!=0) && (n < num_attribs) && (n < 20))
	n++;

    if (strcasecmp(attr[n].name, name)==0)
	return((const char *) attr[n].value);

    return NULL;
}
