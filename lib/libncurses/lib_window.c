
/* This work is copyrighted. See COPYRIGHT.OLD & COPYRIGHT.NEW for   *
*  details. If they are missing then this copy is in violation of    *
*  the copyright conditions.                                        */

/*
**	lib_window.c
**
**
*/

#include <string.h>
#include "curses.priv.h"

int mvder(WINDOW *win, int y, int x)
{

}

void wsyncup(WINDOW *win)
{

}

int syncok(WINDOW *win, bool bf)
{

}

void wcursyncup(WINDOW *win)
{

}

void wsyncdown(WINDOW *win)
{

}

WINDOW *dupwin(WINDOW *win)
{
WINDOW *nwin;
#ifdef TRACE
	if (_tracing)
		_tracef("dupwin(%x) called", win);
#endif

	if ((nwin = newwin(win->_maxy, win->_maxx, win->_bey, win->_begx)) == NULL)
		return NULL;

	nwin->_curx       = win->_curx;
	nwin->_cury       = win->_cury;
	nwin->_maxy       = win->_maxy;
	nwin->_maxx       = win->_maxx;       
	nwin->_begy       = win->_begy;
	nwin->_begx       = win->_begx;

	nwin->_flags      = win->_flags;
	nwin->_attrs      = win->_attrs;

	nwin->_clear      = win->_clear; 
	nwin->_scroll     = win->_scroll;
	nwin->_leave      = win->_leave;
	nwin->_use_keypad = win->_use_keypad;
	nwin->_use_meta   = win->_use_meta;
	nwin->_delay   	  = win->_delay;
	nwin->_immed	  = win->_immed;
	nwin->_sync	  = win->_sync;
	nwin->_parx	  = win->_parx;
	nwin->_pary	  = win->_pary;
	nwin->_parent	  = win->_parent; 

	nwin->_regtop     = win->_regtop;
	nwin->_regbottom  = win->_regbottom;

	for (i = 0; i < nwin->_cury; i++) {
		memcpy(nwin->_line[i], win->_line[i], win->_maxx * sizeof(chtype));
		nwin->_firstchar[i]  = win->_firstchar[i];
		nwin->_lastchar[i] = win->_lastchar[i];
	}

	return nwin;
}

