/*
 *  dialog.h -- common declarations for all dialog modules
 *
 *  AUTHOR: Savio Lam (lam836@cs.cuhk.hk)
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define HAVE_NCURSES

#ifdef HAVE_NCURSES
#include <ncurses.h>

#else

#ifdef ultrix
#include <cursesX.h>
#else
#include <curses.h>
#endif

#endif

#define VERSION "0.4"
#define MAX_LEN 2048

/* 
 * Attribute names
 */
#define screen_attr                   attributes[0]
#define shadow_attr                   attributes[1]
#define dialog_attr                   attributes[2]
#define title_attr                    attributes[3]
#define border_attr                   attributes[4]
#define button_active_attr            attributes[5]
#define button_inactive_attr          attributes[6]
#define button_key_active_attr        attributes[7]
#define button_key_inactive_attr      attributes[8]
#define button_label_active_attr      attributes[9]
#define button_label_inactive_attr    attributes[10]
#define inputbox_attr                 attributes[11]
#define inputbox_border_attr          attributes[12]
#define searchbox_attr                attributes[13]
#define searchbox_title_attr          attributes[14]
#define searchbox_border_attr         attributes[15]
#define position_indicator_attr       attributes[16]
#define menubox_attr                  attributes[17]
#define menubox_border_attr           attributes[18]
#define item_attr                     attributes[19]
#define item_selected_attr            attributes[20]
#define tag_attr                      attributes[21]
#define tag_selected_attr             attributes[22]
#define tag_key_attr                  attributes[23]
#define tag_key_selected_attr         attributes[24]
#define check_attr                    attributes[25]
#define check_selected_attr           attributes[26]
#define uarrow_attr                   attributes[27]
#define darrow_attr                   attributes[28]

/* number of attributes */
#define ATTRIBUTE_COUNT               29

extern chtype attributes[];

#ifdef HAVE_NCURSES
extern bool use_shadow;
void draw_shadow(WINDOW *win, int y, int x, int height, int width);
#endif
void draw_box(WINDOW *win, int y, int x, int height, int width, chtype box, chtype border);
int line_edit(WINDOW* dialog, int box_y, int box_x, int box_width, chtype attrs, int first, unsigned char *result);

void dialog_create_rc(unsigned char *filename);
int dialog_yesno(unsigned char *title, unsigned char *prompt, int height, int width);
int dialog_msgbox(unsigned char *title, unsigned char *prompt, int height, int width, int pause);
int dialog_textbox(unsigned char *title, unsigned char *file, int height, int width);
int dialog_menu(unsigned char *title, unsigned char *prompt, int height, int width, int menu_height, int item_no, unsigned char **items, unsigned char *result);
int dialog_checklist(unsigned char *title, unsigned char *prompt, int height, int width, int list_height, int item_no, unsigned char **items, unsigned char *result);
int dialog_radiolist(char *title, char *prompt, int height, int width, int list_height, int item_no, unsigned char **items, unsigned char *result);
int dialog_inputbox(unsigned char *title, unsigned char *prompt, int height, int width, unsigned char *result);
void dialog_clear(void);
void dialog_update(void);
void init_dialog(void);
void end_dialog(void);
