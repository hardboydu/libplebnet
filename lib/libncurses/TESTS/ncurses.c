/****************************************************************************

NAME
   ncurses.c --- ncurses library exerciser

SYNOPSIS
   ncurses

DESCRIPTION
   An interactive test module for the ncurses library.

AUTHOR
   This software is Copyright (C) 1993 by Eric S. Raymond, all rights reserved.
It is issued with ncurses under the same terms and conditions as the ncurses
library source.

***************************************************************************/
/*LINTLIBRARY */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ncurses.h>

#define P(s)		printw("%s\n", s)
#ifndef CTRL
#define CTRL(x)		((x) & 0x1f)
#endif

/****************************************************************************
 *
 * Character input test
 *
 ****************************************************************************/

static void getch_test(void)
/* test the keypad feature */
{
    unsigned int c;
    int firsttime = 0;

    refresh();

    c = '?';
    do {
	if (firsttime++)
	{
	    printw("Key pressed: %04o ", c);
	    if (c >= KEY_MIN)
	    {
		(void) addstr(keyname(c));
		addch('\n');
	    }
	    else if (c > 0x80)
	    {
		if (isprint(c & ~0x80))
		    (void) printw("M-%c", c);
		else
		    (void) printw("M-%s", unctrl(c));
		addstr(" (high-half character)\n");
	    }
	    else
	    {
		if (isprint(c))
		    (void) printw("%c (ASCII printable character)\n", c);
		else
		    (void) printw("%s (ASCII control character)\n", unctrl(c));
	    }
	}
	if (c == 'x' || c == 'q')
	    break;
	if (c == '?')
	    addstr("Type any key to see its keypad value, `q' to quit, `?' for help.\n");
    } while
	((c = getch()) != EOF);

    erase();
    endwin();
}

static void attr_test(void)
/* test text attrivutes */
{
    refresh();

    mvaddstr(0, 20, "Character attribute test display");

    mvaddstr(2,8,"This is STANDOUT mode: ");
    attron(A_STANDOUT);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_STANDOUT);

    mvaddstr(4,8,"This is REVERSE mode: ");
    attron(A_REVERSE);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_REVERSE);

    mvaddstr(6,8,"This is BOLD mode: ");
    attron(A_BOLD);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_BOLD);

    mvaddstr(8,8,"This is UNDERLINE mode: ");
    attron(A_UNDERLINE);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_UNDERLINE);

    mvaddstr(10,8,"This is DIM mode: ");
    attron(A_DIM);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_DIM);

    mvaddstr(12,8,"This is BLINK mode: ");
    attron(A_BLINK);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_BLINK);

    mvaddstr(14,8,"This is BOLD UNDERLINE BLINK mode: ");
    attron(A_BOLD|A_BLINK|A_UNDERLINE);
    addstr("abcde fghij klmno pqrst uvwxy x");
    attroff(A_BOLD|A_BLINK|A_UNDERLINE);

    attrset(A_NORMAL);
    mvaddstr(16,8,"This is NORMAL mode: ");
    addstr("abcde fghij klmno pqrst uvwxy x");

    refresh();

    move(LINES - 1, 0);
    addstr("Press any key to continue... ");
    (void) getch();

    erase();
    endwin();
}

/****************************************************************************
 *
 * Color support tests
 *
 ****************************************************************************/

static char	*colors[] =
{
    "black", 
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white"
};

static void color_test(void)
/* generate a color test pattern */
{
    int i;

    refresh();
    (void) printw("There are %d color pairs\n", COLOR_PAIRS);

    (void) mvprintw(1, 0,
	 "%dx%d matrix of foreground/background colors, bright *off*\n",
	 COLORS, COLORS);
    for (i = 0; i < COLORS; i++)
	mvaddstr(2, (i+1) * 8, colors[i]);
    for (i = 0; i < COLORS; i++)
	mvaddstr(3 + i, 0, colors[i]);
    for (i = 1; i < COLOR_PAIRS; i++)
    {
	init_pair(i, i % COLORS, i / COLORS);
	attron(COLOR_PAIR(i));
	mvaddstr(3 + (i / COLORS), (i % COLORS + 1) * 8, "Hello");
	attrset(A_NORMAL);
    }

    (void) mvprintw(COLORS + 4, 0,
	   "%dx%d matrix of foreground/background colors, bright *on*\n",
    	   COLORS, COLORS);
    for (i = 0; i < COLORS; i++)
	mvaddstr(5 + COLORS, (i+1) * 8, colors[i]);
    for (i = 0; i < COLORS; i++)
	mvaddstr(6 + COLORS + i, 0, colors[i]);
    for (i = 1; i < COLOR_PAIRS; i++)
    {
	init_pair(i, i % COLORS, i / COLORS);
	attron(COLOR_PAIR(i) | A_BOLD);
	mvaddstr(6 + COLORS + (i / COLORS), (i % COLORS + 1) * 8, "Hello");
	attrset(A_NORMAL);
    }

    move(LINES - 1, 0);
    addstr("Press any key to continue... ");
    (void) getch();

    erase();
    endwin();
}

static void color_edit(void)
/* display the color test pattern, without trying to edit colors */
{
    int	i, c, value = 0, current = 0, field = 0, usebase = 0;

    refresh();

    for (i = 0; i < COLORS; i++)
	init_pair(i, COLOR_WHITE, i);

    do {
	short	red, green, blue;

	attron(A_BOLD);
	mvaddstr(0, 20, "Color RGB Value Editing");
	attroff(A_BOLD);

	for (i = 0; i < COLORS; i++)
        {
	    mvprintw(2 + i, 0, "%c %-8s:",
		     (i == current ? '>' : ' '), 
		     (i < sizeof(colors)/sizeof(colors[0]) ? colors[i] : ""));
	    attrset(COLOR_PAIR(i));
	    addstr("        ");
	    attrset(A_NORMAL);

	    /*
	     * Note: this refresh should *not* be necessary!  It works around
	     * a bug in attribute handling that apparently causes the A_NORMAL
	     * attribute sets to interfere with the actual emission of the
	     * color setting somehow.  This needs to be fixed.
	     */
	    refresh();

	    color_content(i, &red, &green, &blue);
	    addstr("   R = ");
	    if (current == i && field == 0) attron(A_STANDOUT);
	    printw("%04d", red);
	    if (current == i && field == 0) attrset(A_NORMAL);
	    addstr(", G = ");
	    if (current == i && field == 1) attron(A_STANDOUT);
	    printw("%04d", green);
	    if (current == i && field == 1) attrset(A_NORMAL);
	    addstr(", B = ");
	    if (current == i && field == 2) attron(A_STANDOUT);
	    printw("%04d", blue);
	    if (current == i && field == 2) attrset(A_NORMAL);
	    attrset(A_NORMAL);
	    addstr(")");
	}

	mvaddstr(COLORS + 3, 0,
	    "Use up/down to select a color, left/right to change fields.");
	mvaddstr(COLORS + 4, 0,
	    "Modify field by typing nnn=, nnn-, or nnn+.  ? for help.");

	move(2 + current, 0);

	switch (c = getch())
	{
	case KEY_UP:
	    current = (current == 0 ? (COLORS - 1) : current - 1);
	    value = 0;
	    break;

	case KEY_DOWN:
	    current = (current == (COLORS - 1) ? 0 : current + 1);
	    value = 0;
	    break;

	case KEY_RIGHT:
	    field = (field == 2 ? 0 : field + 1);
	    value = 0;
	    break;

	case KEY_LEFT:
	    field = (field == 0 ? 2 : field - 1);
	    value = 0;
	    break;

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	    do {
		value = value * 10 + (c - '0');
		c = getch();
	    } while
		(isdigit(c));
	    if (c != '+' && c != '-' && c != '=')
		beep();
	    else
		ungetch(c);
	    break;

	case '+':
	    usebase = 1;
	    goto changeit;

	case '-':
	    value = -value;
	    usebase = 1;
	    goto changeit;

	case '=':
	    usebase = 0; 
	changeit:
	    color_content(current, &red, &green, &blue);
	    if (field == 0)
		red = red * usebase + value;
	    else if (field == 1)
		green = green * usebase + value;
	    else if (field == 2)
		blue = blue * usebase + value;
	    init_color(current, red, green, blue);
	    break;

	case '?':
	    erase();
    P("                      RGB Value Editing Help");
    P("");
    P("You are in the RGB value editor.  Use the arrow keys to select one of");
    P("the fields in one of the RGB triples of the current colors; the one");
    P("currently selected will be reverse-video highlighted.");    
    P("");
    P("To change a field, enter the digits of the new value; they won't be");
    P("echoed.  Finish by typing `='; the change will take effect instantly.");
    P("To increment or decrement a value, use the same procedure, but finish");
    P("with a `+' or `-'.");
    P("");
    P("To quit, do `x' or 'q'");

	    move(LINES - 1, 0);
	    addstr("Press any key to continue... ");
	    (void) getch();
	    erase();
	    break;

	case 'x':
	case 'q':
	    break;

	default:
	    beep();
	    break;
	}
    } while
	(c != 'x' && c != 'q');

    erase();
    endwin();
}

/****************************************************************************
 *
 * Soft-key label test
 *
 ****************************************************************************/

static void slk_test(void)
/* exercise the soft keys */
{
    int	c, fmt = 1;
    char buf[9];

    c = CTRL('l');
    do {
	switch(c)
	{
	case CTRL('l'):
	    erase();
	    attron(A_BOLD);
	    mvaddstr(0, 20, "Soft Key Exerciser");
	    attroff(A_BOLD);

	    move(2, 0);
	    P("Available commands are:");
	    P("");
	    P("^L         -- refresh screen");
	    P("a          -- activate or restore soft keys");
	    P("d          -- disable soft keys");
	    P("c          -- set centered format for labels");
	    P("l          -- set left-justified format for labels");
	    P("r          -- set right-justified format for labels");
	    P("[12345678] -- set label; labels are numbered 1 through 8");
	    P("e          -- erase stdscr (should not erase labels)");
	    P("s          -- test scrolling of shortened screen");
	    P("x, q       -- return to main menu");
	    P("");
	    P("Note: if activating the soft keys causes your terminal to");
	    P("scroll up one line, your terminal auto-scrolls when anything");
	    P("is written to the last screen position.  The ncurses code");
	    P("does not yet handle this gracefully.");
	    refresh();
	    /* fall through */

	case 'a':
	    slk_restore();
	    break;

	case 'e':
	    wclear(stdscr);
	    break;

	case 's':
	    move(20, 0);
	    while ((c = getch()) != 'Q')
		addch(c);
	    break;

	case 'd':
	    slk_clear();
	    break;

	case 'l':
	    fmt = 0;
	    break;

	case 'c':
	    fmt = 1;
	    break;

	case 'r':
	    fmt = 2;
	    break;

	case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8':
	    (void) mvaddstr(20, 0, "Please enter the label value: ");
	    wgetnstr(stdscr, buf, 8);
	    slk_set((c - '0'), buf, fmt);
	    slk_refresh();
	    break;

	case 'x':
	case 'q':
	    goto done;

	default:
	    beep();
	}
    } while
	((c = getch()) != EOF);

 done:
    erase();
    endwin();
}

/****************************************************************************
 *
 * Alternate character-set stuff
 *
 ****************************************************************************/

static void acs_display()
/* display the ACS character set */
{
traceon();
    erase();
    attron(A_BOLD);
    mvaddstr(0, 20, "Display of the ACS Character Set");
    attroff(A_BOLD);
    refresh();

#define ACSY	5
    mvaddstr(ACSY + 0, 0, "ACS_ULCORNER: "); addch(ACS_ULCORNER);
    mvaddstr(ACSY + 1, 0, "ACS_LLCORNER: "); addch(ACS_LLCORNER);
    mvaddstr(ACSY + 2, 0, "ACS_URCORNER: "); addch(ACS_URCORNER);
    mvaddstr(ACSY + 3, 0, "ACS_LRCORNER: "); addch(ACS_LRCORNER);
    mvaddstr(ACSY + 4, 0, "ACS_RTEE: "); addch(ACS_RTEE);
    mvaddstr(ACSY + 5, 0, "ACS_LTEE: "); addch(ACS_LTEE);
    mvaddstr(ACSY + 6, 0, "ACS_BTEE: "); addch(ACS_BTEE);
    mvaddstr(ACSY + 7, 0, "ACS_TTEE: "); addch(ACS_TTEE);
    mvaddstr(ACSY + 8, 0, "ACS_HLINE: "); addch(ACS_HLINE);
    mvaddstr(ACSY + 9, 0, "ACS_VLINE: "); addch(ACS_VLINE);
    mvaddstr(ACSY + 10,0, "ACS_PLUS: "); addch(ACS_PLUS);
    mvaddstr(ACSY + 11,0, "ACS_S1: "); addch(ACS_S1);
    mvaddstr(ACSY + 12,0, "ACS_S9: "); addch(ACS_S9);

    mvaddstr(ACSY + 0, 40, "ACS_DIAMOND: "); addch(ACS_DIAMOND);
    mvaddstr(ACSY + 1, 40, "ACS_CKBOARD: "); addch(ACS_CKBOARD);
    mvaddstr(ACSY + 2, 40, "ACS_DEGREE: "); addch(ACS_DEGREE);
    mvaddstr(ACSY + 3, 40, "ACS_PLMINUS: "); addch(ACS_PLMINUS);
    mvaddstr(ACSY + 4, 40, "ACS_BULLET: "); addch(ACS_BULLET);
    mvaddstr(ACSY + 5, 40, "ACS_LARROW: "); addch(ACS_LARROW);
    mvaddstr(ACSY + 6, 40, "ACS_RARROW: "); addch(ACS_RARROW);
    mvaddstr(ACSY + 7, 40, "ACS_DARROW: "); addch(ACS_DARROW);
    mvaddstr(ACSY + 8, 40, "ACS_UARROW: "); addch(ACS_UARROW);
    mvaddstr(ACSY + 9, 40, "ACS_BOARD: "); addch(ACS_BOARD);
    mvaddstr(ACSY + 10,40, "ACS_LANTERN: "); addch(ACS_LANTERN);
    mvaddstr(ACSY + 11,40, "ACS_BLOCK: "); addch(ACS_BLOCK);

    move(LINES - 1, 0);
    addstr("Press any key to continue... ");
    (void) getch();

    erase();
    endwin();
}

/****************************************************************************
 *
 * Windows and scrolling tester.
 *
 ****************************************************************************/

typedef struct
{
    int y, x;
}
pair;

static void report(void)
/* report on the cursor's current position, then restore it */
{
    int y, x;

    getyx(stdscr, y, x);
    move(LINES - 1, COLS - 17);
    printw("Y = %2d X = %2d", y, x);
    move(y, x);
}

static pair *selectcell(uli, ulj, lri, lrj)
/* arrows keys move cursor, return location at current on non-arrow key */
int	uli, ulj, lri, lrj;	/* co-ordinates of corners */
{
    static pair	res;			/* result cell */
    int		si = lri - uli + 1;	/* depth of the select area */
    int		sj = lrj - ulj + 1;	/* width of the select area */
    int		i = 0, j = 0;		/* offsets into the select area */

    for (;;)
    {
	move(LINES - 1, COLS - 17);
	printw("Y = %2d X = %2d", uli + i, ulj + j);
	move(uli + i, ulj + j);

	switch(getch())
	{
	case KEY_UP:	i += si - 1; break;
	case KEY_DOWN:	i++; break;
	case KEY_LEFT:	j += sj - 1; break;
	case KEY_RIGHT:	j++; break;
	default:	res.y = uli + i; res.x = ulj + j; return(&res);
	}
	i %= si;
	j %= sj;
    }
}

static WINDOW *getwindow(void)
/* Ask user for a window definition */
{
    WINDOW	*rwindow, *bwindow;
    pair	ul, lr;

    move(0, 0); clrtoeol();
    addstr("Use arrows to move cursor, anything else to mark corner 1");
    refresh();
    memcpy(&ul, selectcell(1,    0,    LINES-1, COLS-1), sizeof(pair));
    addch(ACS_ULCORNER);
    move(0, 0); clrtoeol();
    addstr("Use arrows to move cursor, anything else to mark corner 2");
    refresh();
    memcpy(&lr, selectcell(ul.y, ul.x, LINES-1, COLS-1), sizeof(pair));

    rwindow = newwin(lr.y - ul.y + 1, lr.x - ul.x + 1, ul.y, ul.x);

    bwindow = newwin(lr.y - ul.y + 3, lr.x - ul.x + 3, ul.y - 1, ul.x - 1);
    wborder(bwindow, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE,
		0, 0, 0, 0);
    wrefresh(bwindow);
    delwin(bwindow);

    scrollok(rwindow, TRUE);
/*    immedok(rwindow);	*/
    wrefresh(rwindow);

    return(rwindow);
}

static void acs_and_scroll()
/* Demonstrate windows */
{
    int	c;
    struct frame
    {
        struct frame	*next, *last;
        WINDOW		*wind;
    }
    *oldw  = (struct frame *)NULL, *current = (struct frame *)NULL, *neww;

    refresh();
    mvaddstr(LINES - 2, 0,
	     "F1 = make new window, F2 = next window, F3 = previous window");
    mvaddstr(LINES - 1, 0,
	     "All other characters are echoed, windows should scroll.");

    c = KEY_F(1);
    do {
	report();
	if (current)
	    wrefresh(current->wind);

	switch(c)
	{
	case KEY_F(1):
	    neww = (struct frame *) malloc(sizeof(struct frame));
	    neww->wind = getwindow();
	    if (oldw == NULL)	/* First element,  */
	    {
		neww->next = neww; /*   so point it at itself */
		neww->last = neww;
		current = neww;
	    }
	    else
	    {
		neww->last = oldw;  oldw->next = neww;
		neww->next = current; current->last = neww;
	    }
	    oldw = neww;
	    keypad(neww->wind, TRUE);
	    break;

	case KEY_F(2):
	    current = current->next;
	    break;

	case KEY_F(3):
	    current = current->last;
	    break;

	case KEY_F(4):	/* undocumented --- use this to test area clears */
	    selectcell(0, 0, LINES - 1, COLS - 1);
	    clrtobot();
	    refresh();
	    break;

	case '\r':
	    c = '\n';
	    /* FALLTHROUGH */

	default:
	    waddch(current->wind, c);
	    break;
	}
	report();
	wrefresh(current->wind);
    } while
	((c = wgetch(current->wind)) != '\004');

    erase();
    endwin();
}

/****************************************************************************
 *
 * Tests from John Burnell's PDCurses tester
 *
 ****************************************************************************/

static void demo_pad(void)
/* Demonstrate pads. */
{
    WINDOW *pad;

    pad = newpad(50,100);
    mvwaddstr(pad, 5, 2, "This is a new pad");
    mvwaddstr(pad, 8, 0, "The end of this line should be truncated here:abcd");
    mvwaddstr(pad,11, 1, "This line should not appear.");
    wmove(pad, 10, 1);
    wclrtoeol(pad);
    mvwaddstr(pad, 10, 1, " Press any key to continue");
    prefresh(pad,0,0,0,0,10,45);
    keypad(pad, TRUE);
    wgetch(pad);

    mvwaddstr(pad, 35, 2, "This is displayed at line 35 in the pad");
    mvwaddstr(pad, 40, 1, " Press any key to continue");
    prefresh(pad,30,0,0,0,10,45);
    keypad(pad, TRUE);
    wgetch(pad);

    delwin(pad);
}

static void Continue (WINDOW *win)
{
    wmove(win, 10, 1);
    mvwaddstr(win, 10, 1, " Press any key to continue");
    wrefresh(win);
    wgetch(win);
}

static void input_test(WINDOW *win)
/* Input test, adapted from John Burnell's PDCurses tester */
{
    int w, h, bx, by, sw, sh, i, c,num;
    char buffer [80];
    WINDOW *subWin;
    wclear (win);

    w  = win->_maxx;
    h  = win->_maxy;
    bx = win->_begx;
    by = win->_begy;
    sw = w / 3;
    sh = h / 3;
    if((subWin = subwin(win, sh, sw, by + h - sh - 2, bx + w - sw - 2)) == NULL)
        return;

#ifdef A_COLOR
    if (has_colors())
    {
	init_pair(2,COLOR_CYAN,COLOR_BLUE);
	wattrset(subWin, COLOR_PAIR(2) | A_BOLD);
    }
    else
	wattrset(subWin, A_BOLD);
#else
    wattrset(subWin, A_BOLD);
#endif
    box(subWin, ACS_VLINE, ACS_HLINE);
    wrefresh(win);

    nocbreak();
    mvwaddstr(win, 2, 1, "Press some keys for 5 seconds");
    mvwaddstr(win, 1, 1, "Pressing ^C should do nothing");
    wrefresh(win);

    for (i = 0; i < 5; i++) {
	werase (subWin);
	box(subWin, ACS_VLINE, ACS_HLINE);
	mvwprintw (subWin, 1, 1, "Time = %d", i);
	wrefresh(subWin);
	sleep(1);
	flushinp();
    }

    delwin (subWin);
    werase(win);
    flash();
    wrefresh(win);
    sleep(1);

    mvwaddstr(win, 2, 1, "Press a key");
    wmove(win, 9, 10);
    wrefresh(win);
    echo();
    wgetch(win);
    flushinp();

    wmove(win, 9, 10);
    wdelch(win);
    mvwaddstr(win, 4, 1, "The character should now have been deleted");
    Continue(win);

    wclear (win);
    mvwaddstr(win, 2, 1, "Press a function key or an arrow key");
    wrefresh(win);
    keypad(win, TRUE);
    c = wgetch(win);

    nodelay(win, TRUE);
    wgetch(win);
    nodelay(win, FALSE);

    refresh();
    wclear (win);
    mvwaddstr(win, 3, 2, "The window should have moved");
    mvwaddstr(win, 4, 2, "This text should have appeared without you pressing a key");
    mvwprintw(win, 2, 2, "Keycode = %d", c);

#ifdef FOO
    /*
     * This test won't be portable until vsscanf() is
     */
    mvwaddstr(win, 6, 2, "Enter a number then a string separated by space");
    echo();
    mvwscanw(win, 7, 6, "%d %s", &num,buffer);
    mvwprintw(win, 8, 6, "String: %s Number: %d", buffer,num);
#endif /* FOO */

    Continue(win);
}

static void output_test (WINDOW *win)
{
    WINDOW *win1;
    char Buffer [80];
    chtype ch;

    wclear (win);
    mvwaddstr(win, 1, 1, "You should now have a screen in the upper left corner, and this text should have wrapped");
    mvwin(win, 2, 1);
    Continue(win);

	nl();
    wclear(win);
    mvwaddstr(win, 1, 1, "A new window will appear with this text in it");
    mvwaddstr(win, 8, 1, "Press any key to continue");
    wrefresh(win);
    wgetch(win);

    win1 = newwin(10, 50, 15, 25);
    if(win1 == NULL)
    {   endwin();
        return;
    }
#ifdef A_COLOR
    if (has_colors())
    {
	init_pair(3,COLOR_BLUE,COLOR_WHITE);
	wattrset(win1, COLOR_PAIR(3));
    }
    else
	wattrset(win1, A_NORMAL);
#else
    wattrset(win1, A_NORMAL);
#endif
    wclear (win1);
    mvwaddstr(win1, 5, 1, "This text should appear; using overlay option");
    copywin(win, win1,0,0,0,0,10,50,TRUE);

    box(win1,ACS_VLINE,ACS_HLINE);
    wmove(win1, 8, 26);
    wrefresh(win1);
    wgetch(win1);

    wclear(win1);
    wattron(win1, A_BLINK);
    mvwaddstr(win1, 4, 1, "This blinking text should appear in only the second window");
    wattroff(win1, A_BLINK);
    wrefresh(win1);
    wgetch(win1);
    delwin(win1);

    wclear(win);
    wrefresh(win);
    mvwaddstr(win, 6, 2, "This line shouldn't appear");
    mvwaddstr(win, 4, 2, "Only half of the next line is visible");
    mvwaddstr(win, 5, 2, "Only half of the next line is visible");
    wmove(win, 6, 1);
    wclrtobot (win);
    wmove(win, 5, 20);
    wclrtoeol (win);
    mvwaddstr(win, 8, 2, "This line also shouldn't appear");
    wmove(win, 8, 1);
    wdeleteln(win);
    Continue(win);
    traceoff();

    wmove (win, 5, 9);
    ch = winch (win);

    wclear(win);
    wmove (win, 6, 2);
    waddstr (win, "The next char should be l:  ");
    winsch (win, ch);
    Continue(win);

    wmove(win, 5, 1);
    winsertln (win);
    mvwaddstr(win, 5, 2, "The lines below should have moved down");
    Continue(win);

#ifdef FOO
    /*
     * This test won't be portable until vsscanf() is
     */
    wclear(win);
    wmove(win, 2, 2);
    wprintw(win, "This is a formatted string in a window: %d %s\n", 42, "is it");
    mvwaddstr(win, 10, 1, "Enter a string: ");
    wrefresh(win);
    echo();
    wscanw (win, "%s", Buffer);

    wclear(win);
    mvwaddstr(win, 10, 1, "Enter a string");
    wrefresh(win);
    clear();
    move(0,0);
    printw("This is a formatted string in stdscr: %d %s\n", 42, "is it");
    mvaddstr(10, 1, "Enter a string: ");
    refresh();
    echo();
    scanw ("%s", Buffer);
#endif /* FOO */

    wclear(win);
    curs_set(2);
    mvwaddstr(win, 1, 1, "The cursor should appear as a block");
    Continue(win);

    wclear(win);
    curs_set(0);
    mvwaddstr(win, 1, 1, "The cursor should have disappeared");
    Continue(win);

    wclear(win);
    curs_set(1);
    mvwaddstr(win, 1, 1, "The cursor should be an underline");
    Continue(win);
}

/****************************************************************************
 *
 * Main sequence
 *
 ****************************************************************************/

bool do_single_test(const char c)
/* perform a single specified test */
{
    switch (c)
    {
    case 'a':
	getch_test();
	return(TRUE);

    case 'b':
	attr_test();
	return(TRUE);

    case 'c':
	if (!has_colors())
	    (void) printf("This %s terminal does not support color.\n",
			  getenv("TERM"));
	else
	    color_test();
	return(TRUE);

    case 'd':
	if (!has_colors())
	    (void) printf("This %s terminal does not support color.\n",
			  getenv("TERM"));
	else if (!can_change_color())
	    (void) printf("This %s terminal has hardwired color values.\n",
			  getenv("TERM"));
	else
	    color_edit();
	return(TRUE);

    case 'e':
	slk_test();
	return(TRUE);

    case 'f':
	acs_display();
	return(TRUE);

    case 'g':
	acs_and_scroll();
	return(TRUE);

    case 'p':
	demo_pad();
	return(TRUE);

    case 'i':
	input_test(stdscr);
	return(TRUE);

    case 'o':
	output_test(stdscr);
	return(TRUE);

    case '?':
	(void) puts("This is the ncurses capability tester.");
	(void) puts("You may select a test from the main menu by typing the");
	(void) puts("key letter of the choice (the letter to left of the =)");
	(void) puts("at the > prompt.  The commands `x' or `q' will exit.");
	return(TRUE);
    }

    return(FALSE);
}

int main(const int argc, const char *argv[])
{
    char	buf[BUFSIZ];

    /* enable debugging */
    traceon();

    /* tell it we're going to play with soft keys */
    slk_init(1);

    /* we must initialize the curses data structure only once */
    initscr();

    /* tests, in general, will want these modes */
    start_color();
    cbreak();
    noecho();
    scrollok(stdscr, TRUE);
    keypad(stdscr, TRUE);

    /*
     * Return to terminal mode, so we're guaranteed of being able to
     * select terminal commands even if the capabilities are wrong.
     */
    endwin();

    (void) puts("Welcome to ncurses.  Press ? for help.");

    do {
	(void) puts("This is the ncurses main menu");
	(void) puts("a = character input test");
	(void) puts("b = character attribute test");
	(void) puts("c = color test pattern");
	(void) puts("d = edit RGB color values");
	(void) puts("e = exercise soft keys");
	(void) puts("f = display ACS characters");
	(void) puts("g = display windows and scrolling");
	(void) puts("p = exercise pad features");
	(void) puts("i = subwindow input test");
	(void) puts("o = output test");
	(void) puts("? = get help");

	(void) fputs("> ", stdout);
	(void) fgets(buf, BUFSIZ, stdin);

	if (do_single_test(buf[0])) {
		clear();
		refresh();
		endwin();
	    continue;
	}
    } while
	(buf[0] != 'q' && buf[0] != 'x');

    exit(0);
}

/* ncurses.c ends here */
