
/* This work is copyrighted. See COPYRIGHT.OLD & COPYRIGHT.NEW for   *
*  details. If they are missing then this copy is in violation of    *
*  the copyright conditions.                                        */

/*-----------------------------------------------------------------
 *
 *	lib_doupdate.c
 *
 *	The routine doupdate() and its dependents
 *
 *-----------------------------------------------------------------*/
 
#include <stdlib.h>
#include <string.h>
#include "curses.priv.h"
#include <nterm.h>
#ifdef SVR4_ACTION
#define _POSIX_SOURCE
#endif
#include <signal.h>

static void ClrUpdate( WINDOW *scr );
static void TransformLine( int lineno );
static void NoIDcTransformLine( int lineno );
static void IDcTransformLine( int lineno );
static void ClearScreen( void );
static void InsStr( chtype *line, int count );
static void DelChar( int count );

static inline void PutAttrChar(chtype ch)
{
	if (curscr->_attrs != (ch & (chtype)A_ATTRIBUTES)) {
		curscr->_attrs = ch & (chtype)A_ATTRIBUTES;
		vidputs(curscr->_attrs, _outc);
	}
	putc(ch & A_CHARTEXT, SP->_ofp);
}

static int LRCORNER = FALSE;

static inline void PutChar(chtype ch)
{
	T(("puttin %x", ch));
	if (LRCORNER == TRUE) {
		if (SP->_curscol == columns-2) {
			PutAttrChar(newscr->_line[lines-1][columns-2]);
			SP->_curscol++;
			return;
		} else if (SP->_curscol == columns-1) {
		int i = lines;
		int j = columns -1;
			if (cursor_left)
				tputs(cursor_left, 1, _outc);
			else
				mvcur(-1, -1, i-1, j);
			if (enter_insert_mode && exit_insert_mode) {
				tputs(enter_insert_mode, 1, _outc);
				PutAttrChar(newscr->_line[i-1][j]);
				tputs(exit_insert_mode, 1, _outc);
			} else if (insert_character) {
				tputs(insert_character, 1, _outc);
				PutAttrChar(newscr->_line[i-1][j]);
			}
			return;
		}
	}
	PutAttrChar(ch);
	SP->_curscol++; 
	if (SP->_curscol >= columns) {
		if (auto_right_margin) {	 
			SP->_curscol = 0;	   
			SP->_cursrow++;		
		} else {
		 	SP->_curscol--;
		}
	}
}	

static inline void GoTo(int row, int col)
{
	mvcur(SP->_cursrow, SP->_curscol, row, col); 
	SP->_cursrow = row; 
	SP->_curscol = col; 
}

int _outc(char ch)
{
	putc(ch, SP->_ofp);
	return OK;
}

int doupdate(void)
{
int	i;
sigaction_t act, oact;
	
	T(("doupdate() called"));

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTSTP, &act, &oact);

	if (_isendwin == 1) {
		T(("coming back from shell mode"));
		reset_prog_mode();
		/* is this necessary? */
		if (enter_alt_charset_mode)
			init_acs();  
		newscr->_clear = TRUE;
		_isendwin = 0;
	}

	if (curscr->_clear) {		/* force refresh ? */
		T(("clearing and updating curscr"));
		ClrUpdate(curscr);		/* yes, clear all & update */
		curscr->_clear = FALSE;	/* reset flag */
	} else {
		if (newscr->_clear) {
			T(("clearing and updating newscr"));
			ClrUpdate(newscr);
			newscr->_clear = FALSE;
		} else {
			T(("Transforming lines"));
			for (i = 0; i < lines ; i++) {
				if(newscr->_firstchar[i] != _NOCHANGE)
					TransformLine(i);
			}
		}
	}
	T(("marking screen as updated"));
	for (i = 0; i < lines; i++) {
		newscr->_firstchar[i] = _NOCHANGE;
		newscr->_lastchar[i] = _NOCHANGE;
	}

	curscr->_curx = newscr->_curx;
	curscr->_cury = newscr->_cury;

	GoTo(curscr->_cury, curscr->_curx);
	
	/* perhaps we should turn attributes off here */

	if (!(curscr->_attrs & A_NORMAL))
		vidattr(curscr->_attrs = A_NORMAL);

	fflush(SP->_ofp);

	sigaction(SIGTSTP, &oact, NULL);

	return OK;
}

static int move_right_cost = -1;

static int countc(char c)
{
	return(move_right_cost++);
}

/*
**	ClrUpdate(scr)
**
**	Update by clearing and redrawing the entire screen.
**
*/

#define BLANK ' '|A_NORMAL

static void ClrUpdate(WINDOW *scr)
{
int	i = 0, j = 0;
int	lastNonBlank;
	
	T(("ClrUpdate(%x) called", scr));
	if (back_color_erase) {
		T(("back_color_erase, turning attributes off"));
		vidattr(A_NORMAL);
	}
	ClearScreen();

	if ((move_right_cost == -1) && parm_right_cursor) {
		move_right_cost = 0;
		tputs(tparm(parm_right_cursor, 10), 1, countc);
	}

	T(("updating screen from scratch"));
	for (i = 0; i < lines; i++) {
		LRCORNER = FALSE;
		lastNonBlank = columns - 1;
		
		while (scr->_line[i][lastNonBlank] == BLANK )
			lastNonBlank--;

		T(("updating line %d upto %d", i, lastNonBlank));

		/* check if we are at the lr corner */
		if (i == lines-1)
			if ((auto_right_margin) && !(eat_newline_glitch) &&
			    (lastNonBlank == columns-1) && !(scr->_scroll)) 
			{
				T(("Lower-right corner needs special handling"));
			    LRCORNER = TRUE;
			}

		for (j = 0; j <= lastNonBlank; j++) {
			if (parm_right_cursor) {
				static int inspace = 0;

				T(("trying to use parm_right_cursor"));
				if ((scr->_line[i][j]) == BLANK) {
					inspace++;
					continue;
				} else if(inspace) {
					if (inspace < move_right_cost) {
						for (; inspace > 0; inspace--)
							PutChar(scr->_line[i][j-1]);
					} else {
						tputs(tparm(parm_right_cursor, inspace), 1, _outc);
					}
					inspace = 0;
				}
			}
			PutChar(scr->_line[i][j]);
		}
		/* move cursor to the next line */
		if ((!auto_right_margin) || (lastNonBlank < columns - 1) ||
		    (auto_right_margin && eat_newline_glitch && lastNonBlank == columns-1))
		{
			SP->_curscol = (lastNonBlank < 0) ? 0 : lastNonBlank;
			SP->_cursrow++;
			GoTo(i+1, 0);
		}
	}


	if (scr != curscr) {
		for (i = 0; i < lines ; i++)
			for (j = 0; j < columns; j++)
				curscr->_line[i][j] = scr->_line[i][j];
	}
}

/*
**	TransformLine(lineno)
**
**	Call either IDcTransformLine or NoIDcTransformLine to do the
**	update, depending upon availability of insert/delete character.
*/

static void TransformLine(int lineno)
{

	T(("TransformLine(%d) called",lineno));

	if ( (insert_character  ||  (enter_insert_mode  &&  exit_insert_mode))
		 &&  delete_character)
		IDcTransformLine(lineno);
	else
		NoIDcTransformLine(lineno);
}



/*
**	NoIDcTransformLine(lineno)
**
**	Transform the given line in curscr to the one in newscr, without
**	using Insert/Delete Character.
**
**		firstChar = position of first different character in line
**		lastChar = position of last different character in line
**
**		overwrite all characters between firstChar and lastChar.
**
*/

static void NoIDcTransformLine(int lineno)
{
int	firstChar, lastChar;
chtype	*newLine = newscr->_line[lineno];
chtype	*oldLine = curscr->_line[lineno];
int	k;
int	attrchanged = 0;
	
	T(("NoIDcTransformLine(%d) called", lineno));

	firstChar = 0;
	while (firstChar < columns - 1 &&  newLine[firstChar] == oldLine[firstChar]) {
		if(ceol_standout_glitch) {
			if((newLine[firstChar] & (chtype)A_ATTRIBUTES) != (oldLine[firstChar] & (chtype)A_ATTRIBUTES))
			attrchanged = 1;
		}			
		firstChar++;
	}

	T(("first char at %d is %x", firstChar, newLine[firstChar]));
	if (firstChar > columns)
		return;

	if(ceol_standout_glitch && attrchanged) {
		firstChar = 0;
		lastChar = columns - 1;
		GoTo(lineno, firstChar);
		if(clr_eol) {
			if (back_color_erase) {
				T(("back_color_erase, turning attributes off"));
				vidattr(A_NORMAL);
			}
			tputs(clr_eol, 1, _outc);		
		}
	} else {
		lastChar = columns - 1;
		while (lastChar > firstChar  &&  newLine[lastChar] == oldLine[lastChar])
			lastChar--;
		GoTo(lineno, firstChar);
	}			

	/* check if we are at the lr corner */
	if (lineno == lines-1)
		if ((auto_right_margin) && !(eat_newline_glitch) &&
		    (lastChar == columns-1) && !(curscr->_scroll)) 
		{
			T(("Lower-right corner needs special handling"));
		    LRCORNER = TRUE;
		}

	T(("updating chars %d to %d", firstChar, lastChar));
	for (k = firstChar; k <= lastChar; k++) {
		PutChar(newLine[k]);
		oldLine[k] = newLine[k];
	}
}

/*
**	IDcTransformLine(lineno)
**
**	Transform the given line in curscr to the one in newscr, using
**	Insert/Delete Character.
**
**		firstChar = position of first different character in line
**		oLastChar = position of last different character in old line
**		nLastChar = position of last different character in new line
**
**		move to firstChar
**		overwrite chars up to min(oLastChar, nLastChar)
**		if oLastChar < nLastChar
**			insert newLine[oLastChar+1..nLastChar]
**		else
**			delete oLastChar - nLastChar spaces
*/

static void IDcTransformLine(int lineno)
{
int	firstChar, oLastChar, nLastChar;
chtype	*newLine = newscr->_line[lineno];
chtype	*oldLine = curscr->_line[lineno];
int	k, n;
int	attrchanged = 0;
	
	T(("IDcTransformLine(%d) called", lineno));

	if(ceol_standout_glitch && clr_eol) {
		firstChar = 0;
		while(firstChar < columns) {
			if((newLine[firstChar] & (chtype)A_ATTRIBUTES) != (oldLine[firstChar] & (chtype)A_ATTRIBUTES))
				attrchanged = 1;
			firstChar++;			
		}
	}
	
	firstChar = 0;
	
	if (attrchanged) {
		GoTo(lineno, firstChar);
		if (back_color_erase) {
			T(("back_color_erase, turning attributes off"));
			vidattr(A_NORMAL);
		}
		tputs(clr_eol, 1, _outc);		
		for( k = 0 ; k <= (columns-1) ; k++ )
			PutChar(newLine[k]);
	} else {
		while (firstChar < columns  &&
				newLine[firstChar] == oldLine[firstChar])
			firstChar++;
		
		if (firstChar >= columns)
			return;

		oLastChar = columns - 1;
		while (oLastChar > firstChar  &&  oldLine[oLastChar] == ' ')
			oLastChar--;
	
		nLastChar = columns - 1;
		while (nLastChar > firstChar  &&  newLine[nLastChar] == ' ')
			nLastChar--;

		if((nLastChar == firstChar) && clr_eol) {
			GoTo(lineno, firstChar);
			if (back_color_erase) {
				T(("back_color_erase, turning attributes off"));
				vidattr(A_NORMAL);
			}
			tputs(clr_eol,1,_outc);
			if(newLine[firstChar] != ' ' )
				PutChar(newLine[firstChar]);
		} else if( newLine[nLastChar] != oldLine[oLastChar] ) {
			n = max( nLastChar , oLastChar );

			GoTo(lineno, firstChar);

			for( k=firstChar ; k <= n ; k++ )
				PutChar(newLine[k]);
		} else {
			while (newLine[nLastChar] == oldLine[oLastChar]) {
				nLastChar--;
				oLastChar--;
			}
	
			n = min(oLastChar, nLastChar);

			GoTo(lineno, firstChar);
	
			for (k=firstChar; k <= n; k++)
				PutChar(newLine[k]);

			if (oLastChar < nLastChar)
				InsStr(&newLine[k], nLastChar - oLastChar);

			else if (oLastChar > nLastChar )
				DelChar(oLastChar - nLastChar);
		}
	}
	for (k = firstChar; k < columns; k++)
		oldLine[k] = newLine[k];
}

/*
**	ClearScreen()
**
**	Clear the physical screen and put cursor at home
**
*/

static void ClearScreen()
{

	T(("ClearScreen() called"));

	if (clear_screen) {
		tputs(clear_screen, 1, _outc);
		SP->_cursrow = SP->_curscol = 0;
	} else if (clr_eos) {
		SP->_cursrow = SP->_curscol = -1;
		GoTo(0,0);

		tputs(clr_eos, 1, _outc);
	} else if (clr_eol) {
		SP->_cursrow = SP->_curscol = -1;

		while (SP->_cursrow < lines) {
			GoTo(SP->_cursrow, 0);
			tputs(clr_eol, 1, _outc);
		}
		GoTo(0,0);
	}
	T(("screen cleared"));
}


/*
**	InsStr(line, count)
**
**	Insert the count characters pointed to by line.
**
*/

static void InsStr(chtype *line, int count)
{
	T(("InsStr(%x,%d) called", line, count));

	if (enter_insert_mode  &&  exit_insert_mode) {
		tputs(enter_insert_mode, 1, _outc);
		while (count) {
			PutChar(*line);
			line++;
			count--;
		}
		tputs(exit_insert_mode, 1, _outc);
	} else if (parm_ich) {
		tputs(tparm(parm_ich, count), 1, _outc);
		while (count) {
			PutChar(*line);
			line++;
			count--;
		}
	} else {
		while (count) {
			tputs(insert_character, 1, _outc);
			PutChar(*line);
			line++;
			count--;
		}
	}
}

/*
**	DelChar(count)
**
**	Delete count characters at current position
**
*/

static void DelChar(int count)
{
	T(("DelChar(%d) called", count));

	if (back_color_erase) {
		T(("back_color_erase, turning attributes off"));
		vidattr(A_NORMAL);
	}
	if (parm_dch) {
		tputs(tparm(parm_dch, count), 1, _outc);
	} else {
		while (count--)
			tputs(delete_character, 1, _outc);
	}
}

