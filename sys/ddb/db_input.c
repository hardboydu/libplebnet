/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 *	$Id: db_input.c,v 1.13 1996/05/08 04:28:34 gpalmer Exp $
 */

/*
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include <machine/cons.h>

#include <ddb/ddb.h>
#include <ddb/db_output.h>

/*
 * Character input and editing.
 */

/*
 * We don't track output position while editing input,
 * since input always ends with a new-line.  We just
 * reset the line position at the end.
 */
static char *	db_lbuf_start;	/* start of input line buffer */
static char *	db_lbuf_end;	/* end of input line buffer */
static char *	db_lc;		/* current character */
static char *	db_le;		/* one past last character */

/*
 * Simple input line history support.
 */
static char *	db_lhistory;
static int	db_lhistlsize, db_lhistidx, db_lhistcur;
#define DB_LHIST_NLINES 10

#define	CTRL(c)		((c) & 0x1f)
#define	isspace(c)	((c) == ' ' || (c) == '\t')
#define	BLANK		' '
#define	BACKUP		'\b'

static int	cnmaygetc __P((void));
static void	db_delete __P((int n, int bwd));
static int	db_inputchar __P((int c));
static void	db_putnchars __P((int c, int count));
static void	db_putstring __P((char *s, int count));

void
db_putstring(s, count)
	char	*s;
	int	count;
{
	while (--count >= 0)
	    cnputc(*s++);
}

void
db_putnchars(c, count)
	int	c;
	int	count;
{
	while (--count >= 0)
	    cnputc(c);
}

/*
 * Delete N characters, forward or backward
 */
#define	DEL_FWD		0
#define	DEL_BWD		1
void
db_delete(n, bwd)
	int	n;
	int	bwd;
{
	register char *p;

	if (bwd) {
	    db_lc -= n;
	    db_putnchars(BACKUP, n);
	}
	for (p = db_lc; p < db_le-n; p++) {
	    *p = *(p+n);
	    cnputc(*p);
	}
	db_putnchars(BLANK, n);
	db_putnchars(BACKUP, db_le - db_lc);
	db_le -= n;
}

/* returns TRUE at end-of-line */
int
db_inputchar(c)
	int	c;
{
	switch (c) {
	    case CTRL('b'):
		/* back up one character */
		if (db_lc > db_lbuf_start) {
		    cnputc(BACKUP);
		    db_lc--;
		}
		break;
	    case CTRL('f'):
		/* forward one character */
		if (db_lc < db_le) {
		    cnputc(*db_lc);
		    db_lc++;
		}
		break;
	    case CTRL('a'):
		/* beginning of line */
		while (db_lc > db_lbuf_start) {
		    cnputc(BACKUP);
		    db_lc--;
		}
		break;
	    case CTRL('e'):
		/* end of line */
		while (db_lc < db_le) {
		    cnputc(*db_lc);
		    db_lc++;
		}
		break;
	    case CTRL('h'):
	    case 0177:
		/* erase previous character */
		if (db_lc > db_lbuf_start)
		    db_delete(1, DEL_BWD);
		break;
	    case CTRL('d'):
		/* erase next character */
		if (db_lc < db_le)
		    db_delete(1, DEL_FWD);
		break;
	    case CTRL('k'):
		/* delete to end of line */
		if (db_lc < db_le)
		    db_delete(db_le - db_lc, DEL_FWD);
		break;
	    case CTRL('t'):
		/* twiddle last 2 characters */
		if (db_lc >= db_lbuf_start + 2) {
		    c = db_lc[-2];
		    db_lc[-2] = db_lc[-1];
		    db_lc[-1] = c;
		    cnputc(BACKUP);
		    cnputc(BACKUP);
		    cnputc(db_lc[-2]);
		    cnputc(db_lc[-1]);
		}
		break;
	    case CTRL('r'):
		db_putstring("^R\n", 3);
	    redraw:
		if (db_le > db_lbuf_start) {
		    db_putstring(db_lbuf_start, db_le - db_lbuf_start);
		    db_putnchars(BACKUP, db_le - db_lc);
		}
		break;
	    case CTRL('p'):
		/* Make previous history line the active one. */
		if (db_lhistcur >= 0) {
		    bcopy(db_lhistory + db_lhistcur * db_lhistlsize,
			  db_lbuf_start, db_lhistlsize);
		    db_lhistcur--;
		    goto hist_redraw;
		}
		break;
	    case CTRL('n'):
		/* Make next history line the active one. */
		if (db_lhistcur < db_lhistidx - 1) {
		    db_lhistcur += 2;
		    bcopy(db_lhistory + db_lhistcur * db_lhistlsize,
			  db_lbuf_start, db_lhistlsize);
		} else {
		    /*
		     * ^N through tail of history, reset the
		     * buffer to zero length.
		     */
		    *db_lbuf_start = '\0';
		    db_lhistcur = db_lhistidx;
		}

	    hist_redraw:
		db_putnchars(BACKUP, db_le - db_lbuf_start);
		db_putnchars(BLANK, db_le - db_lbuf_start);
		db_putnchars(BACKUP, db_le - db_lbuf_start);
		db_le = index(db_lbuf_start, '\0');
		if (db_le[-1] == '\r' || db_le[-1] == '\n')
		    *--db_le = '\0';
		db_lc = db_le;
		goto redraw;

	    case '\n':
	    case '\r':
		*db_le++ = c;
		return (1);
	    default:
		if (db_le == db_lbuf_end) {
		    cnputc('\007');
		}
		else if (c >= ' ' && c <= '~') {
		    register char *p;

		    for (p = db_le; p > db_lc; p--)
			*p = *(p-1);
		    *db_lc++ = c;
		    db_le++;
		    cnputc(c);
		    db_putstring(db_lc, db_le - db_lc);
		    db_putnchars(BACKUP, db_le - db_lc);
		}
		break;
	}
	return (0);
}

int
cnmaygetc()
{
	return (-1);
}

int
db_readline(lstart, lsize)
	char *	lstart;
	int	lsize;
{
	if (db_lhistory && lsize != db_lhistlsize) {
		/* Should not happen, but to be sane, throw history away. */
		FREE(db_lhistory, M_TEMP);
		db_lhistory = 0;
	}
	if (db_lhistory == 0) {
		/* Initialize input line history. */
		db_lhistlsize = lsize;
		db_lhistidx = -1;
		MALLOC(db_lhistory, char *, lsize * DB_LHIST_NLINES,
		       M_TEMP, M_NOWAIT);
	}
	db_lhistcur = db_lhistidx;

	db_force_whitespace();	/* synch output position */

	db_lbuf_start = lstart;
	db_lbuf_end   = lstart + lsize;
	db_lc = lstart;
	db_le = lstart;

	while (!db_inputchar(cngetc()))
	    continue;

	db_printf("\n");	/* synch output position */
	*db_le = 0;

	if (db_le - db_lbuf_start > 1) {
	    /* Maintain input line history for non-empty lines. */
	    if (++db_lhistidx == DB_LHIST_NLINES) {
		/* Rotate history. */
		ovbcopy(db_lhistory + db_lhistlsize, db_lhistory,
			db_lhistlsize * (DB_LHIST_NLINES - 1));
		db_lhistidx--;
	    }
	    bcopy(lstart, db_lhistory + (db_lhistidx * db_lhistlsize),
		  db_lhistlsize);
	}

	return (db_le - db_lbuf_start);
}

void
db_check_interrupt()
{
	register int	c;

	c = cnmaygetc();
	switch (c) {
	    case -1:		/* no character */
		return;

	    case CTRL('c'):
		db_error((char *)0);
		/*NOTREACHED*/

	    case CTRL('s'):
		do {
		    c = cnmaygetc();
		    if (c == CTRL('c'))
			db_error((char *)0);
		} while (c != CTRL('q'));
		break;

	    default:
		/* drop on floor */
		break;
	}
}

/* called from kdb_trap in db_interface.c */
void
cnpollc (flag)
	int flag;
{
}
