/* doc.c -- Generated structure containing function names and doc strings.

   This file was automatically made from various source files with the
   command "./makedoc".  DO NOT EDIT THIS FILE, only "./makedoc.c".
   Source files groveled to make this file include:

	./session.c
	./echo_area.c
	./infodoc.c
	./m-x.c
	./indices.c
	./nodemenu.c
	./footnotes.c
	./variables.c

   An entry in the array FUNCTION_DOC_ARRAY is made for each command
   found in the above files; each entry consists of a function pointer,
   a string which is the user-visible name of the function,
   and a string which documents its purpose. */

#include "doc.h"
#include "funs.h"

FUNCTION_DOC function_doc_array[] = {

/* Commands found in "./session.c". */
   { info_next_line, "next-line", "Move down to the next line" },
   { info_prev_line, "prev-line", "Move up to the previous line" },
   { info_end_of_line, "end-of-line", "Move to the end of the line" },
   { info_beginning_of_line, "beginning-of-line", "Move to the start of the line" },
   { info_forward_char, "forward-char", "Move forward a character" },
   { info_backward_char, "backward-char", "Move backward a character" },
   { info_forward_word, "forward-word", "Move forward a word" },
   { info_backward_word, "backward-word", "Move backward a word" },
   { info_global_next_node, "global-next-node", "Move forwards or down through node structure" },
   { info_global_prev_node, "global-prev-node", "Move backwards or up through node structure" },
   { info_scroll_forward, "scroll-forward", "Scroll forward in this window" },
   { info_scroll_backward, "scroll-backward", "Scroll backward in this window" },
   { info_beginning_of_node, "beginning-of-node", "Move to the start of this node" },
   { info_end_of_node, "end-of-node", "Move to the end of this node" },
   { info_next_window, "next-window", "Select the next window" },
   { info_prev_window, "prev-window", "Select the previous window" },
   { info_split_window, "split-window", "Split the current window" },
   { info_delete_window, "delete-window", "Delete the current window" },
   { info_keep_one_window, "keep-one-window", "Delete all other windows" },
   { info_scroll_other_window, "scroll-other-window", "Scroll the other window" },
   { info_grow_window, "grow-window", "Grow (or shrink) this window" },
   { info_tile_windows, "tile-windows", "Divide the available screen space among the visible windows" },
   { info_toggle_wrap, "toggle-wrap", "Toggle the state of line wrapping in the current window" },
   { info_next_node, "next-node", "Select the `Next' node" },
   { info_prev_node, "prev-node", "Select the `Prev' node" },
   { info_up_node, "up-node", "Select the `Up' node" },
   { info_last_node, "last-node", "Select the last node in this file" },
   { info_first_node, "first-node", "Select the first node in this file" },
   { info_history_node, "history-node", "Select the most recently selected node" },
   { info_last_menu_item, "last-menu-item", "Select the last item in this node's menu" },
   { info_menu_digit, "menu-digit", "Select this menu item" },
   { info_menu_item, "menu-item", "Read a menu item and select its node" },
   { info_xref_item, "xref-item", "Read a footnote or cross reference and select its node" },
   { info_find_menu, "find-menu", "Move to the start of this node's menu" },
   { info_visit_menu, "visit-menu", "Visit as many menu items at once as possible" },
   { info_goto_node, "goto-node", "Read a node name and select it" },
   { info_top_node, "top-node", "Select the node `Top' in this file" },
   { info_dir_node, "dir-node", "Select the node `(dir)'" },
   { info_kill_node, "kill-node", "Kill this node" },
   { info_view_file, "view-file", "Read the name of a file and select it" },
   { info_print_node, "print-node", "Pipe the contents of this node through INFO_PRINT_COMMAND" },
   { info_search, "search", "Read a string and search for it" },
   { isearch_forward, "isearch-forward", "Search interactively for a string as you type it" },
   { isearch_backward, "isearch-backward", "Search interactively for a string as you type it" },
   { info_move_to_prev_xref, "move-to-prev-xref", "Move to the previous cross reference" },
   { info_move_to_next_xref, "move-to-next-xref", "Move to the next cross reference" },
   { info_select_reference_this_line, "select-reference-this-line", "Select reference or menu item appearing on this line" },
   { info_abort_key, "abort-key", "Cancel current operation" },
   { info_move_to_window_line, "move-to-window-line", "Move to the cursor to a specific line of the window" },
   { info_redraw_display, "redraw-display", "Redraw the display" },
   { info_quit, "quit", "Quit using Info" },
   { info_do_lowercase_version, "do-lowercase-version", "" },
   { info_add_digit_to_numeric_arg, "add-digit-to-numeric-arg", "Add this digit to the current numeric argument" },
   { info_universal_argument, "universal-argument", "Start (or multiply by 4) the current numeric argument" },
   { info_numeric_arg_digit_loop, "numeric-arg-digit-loop", "" },
/* Commands found in "./echo_area.c". */
   { ea_forward, "echo-area-forward", "Move forward a character" },
   { ea_backward, "echo-area-backward", "Move backward a character" },
   { ea_beg_of_line, "echo-area-beg-of-line", "Move to the start of this line" },
   { ea_end_of_line, "echo-area-end-of-line", "Move to the end of this line" },
   { ea_forward_word, "echo-area-forward-word", "Move forward a word" },
   { ea_backward_word, "echo-area-backward-word", "Move backward a word" },
   { ea_delete, "echo-area-delete", "Delete the character under the cursor" },
   { ea_rubout, "echo-area-rubout", "Delete the character behind the cursor" },
   { ea_abort, "echo-area-abort", "Cancel or quit operation" },
   { ea_newline, "echo-area-newline", "Accept (or force completion of) this line" },
   { ea_quoted_insert, "echo-area-quoted-insert", "Insert next character verbatim" },
   { ea_insert, "echo-area-insert", "Insert this character" },
   { ea_tab_insert, "echo-area-tab-insert", "Insert a TAB character" },
   { ea_transpose_chars, "echo-area-transpose-chars", "Transpose characters at point" },
   { ea_yank, "echo-area-yank", "Yank back the contents of the last kill" },
   { ea_yank_pop, "echo-area-yank-pop", "Yank back a previous kill" },
   { ea_kill_line, "echo-area-kill-line", "Kill to the end of the line" },
   { ea_backward_kill_line, "echo-area-backward-kill-line", "Kill to the beginning of the line" },
   { ea_kill_word, "echo-area-kill-word", "Kill the word following the cursor" },
   { ea_backward_kill_word, "echo-area-backward-kill-word", "Kill the word preceding the cursor" },
   { ea_possible_completions, "echo-area-possible-completions", "List possible completions" },
   { ea_complete, "echo-area-complete", "Insert completion" },
   { ea_scroll_completions_window, "echo-area-scroll-completions-window", "Scroll the completions window" },
/* Commands found in "./infodoc.c". */
   { info_get_help_window, "get-help-window", "Display help message" },
   { info_get_info_help_node, "get-info-help-node", "Visit Info node `(info)Help'" },
   { describe_key, "describe-key", "Print documentation for KEY" },
   { info_where_is, "where-is", "Show what to type to execute a given command" },
/* Commands found in "./m-x.c". */
   { describe_command, "describe-command", "Read the name of an Info command and describe it" },
   { info_execute_command, "execute-command", "Read a command name in the echo area and execute it" },
   { set_screen_height, "set-screen-height", "Set the height of the displayed window" },
/* Commands found in "./indices.c". */
   { info_index_search, "index-search", "Look up a string in the index for this file" },
   { info_next_index_match, "next-index-match", "Go to the next matching index item from the last `\\[index-search]' command" },
   { info_index_apropos, "index-apropos", "Grovel all known info file's indices for a string and build a menu" },
/* Commands found in "./nodemenu.c". */
   { list_visited_nodes, "list-visited-nodes", "Make a window containing a menu of all of the currently visited nodes" },
   { select_visited_node, "select-visited-node", "Select a node which has been previously visited in a visible window" },
/* Commands found in "./footnotes.c". */
   { info_show_footnotes, "show-footnotes", "Show the footnotes associated with this node in another window" },
/* Commands found in "./variables.c". */
   { describe_variable, "describe-variable", "Explain the use of a variable" },
   { set_variable, "set-variable", "Set the value of an Info variable" },
   { (VFunction *)NULL, (char *)NULL, (char *)NULL }
};
