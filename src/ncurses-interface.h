/* ncurses_iallbacks.h
 * Definitions for the ncurses interfaces
 *
 * $Id: ncurses-interface.h 43 2007-04-27 11:07:17Z slay $ 
 *
 * Yersinia
 * By David Barroso <tomac@yersinia.net> and Alfredo Andres <slay@yersinia.net>
 * Copyright 2005, 2006, 2007 Alfredo Andres and David Barroso
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __NCURSES_INTERFACE_H__
#define __NCURSES_INTERFACE_H__

#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#include <ncurses.h>
#else
#include <curses.h>
#endif

#ifdef HAVE_PANEL_H
#include <panel.h>
#endif

#include <ctype.h>

#include "thread-util.h"
#include "terminal-defs.h"
#include "admin.h"
#include "interfaces.h"
#include "attack.h"

#include "parser.h"


#define ERRORMSG_SIZE   512
#define NCURSES_MIN_ROWS 25
#define NCURSES_MIN_COLS 80
#define NCURSES_REFRESH_TIME 2
#define NCURSES_BWINDOW_SIZE 7
#define NCURSES_MWINDOW_MAX_FIELD_LENGTH 16

#define NCURSES_KEY_TIMEOUT 250

#define KEY_CTRL_L 12

#define PARAM_SCREEN   10
#define LIST_FILECAPS  9
#define LIST_ATTACKS   8
#define IFACE_SCREEN   7
#define MAIN_SCREEN    6
#define SEC_SCREEN     5
#define ATTACK_SCREEN  4
#define INFO_SCREEN    3
#define HELP_SCREEN    2
#define SPLASH_SCREEN  1

#define INFO_HEIGHT    13 
#define INFO_WIDTH     44
#define MAX_PAD_HEIGHT 40 
#define MAX_PAD_WIDTH  70

#define NCURSES_DEFAULT_MODE PROTO_STP

#define VIEW_HEIGHT 15
#define VIEW_WIDTH 68

#if defined (TIOCGWINSZ) && defined (HAVE_NCURSES_RESIZETERM)
#define CAN_RESIZE 1
#endif

u_int8_t pointer[MAX_PROTOCOLS];
WINDOW *info_window;

int8_t  ncurses_i_init(WINDOW *[], PANEL *[], struct term_node *);
void    ncurses_i_add_node(void);
void ncurses_i_splash_screen(WINDOW *, PANEL *);
void ncurses_i_help_screen(u_int8_t, WINDOW *, PANEL *);
void ncurses_i_attack_screen(struct term_node *, u_int8_t, WINDOW *, PANEL *);
int8_t ncurses_i_attack_get_params(struct attack_param *, u_int8_t);
/*int8_t ncurses_i_update_fields(struct attack_param *, u_int8_t, int8_t, int8_t);*/
void ncurses_i_get_printable_store(struct attack_param *, u_int8_t);
void ncurses_i_ifaces_screen(struct term_node *, WINDOW *, PANEL *);
int8_t  ncurses_i_show_info(u_int8_t, WINDOW *, u_int8_t, struct term_node *);
int8_t  ncurses_i_view_packet(u_int8_t, WINDOW *, u_int8_t);
void    ncurses_i_list_attacks(WINDOW *, struct term_node *);
void    ncurses_i_list_filecaps(WINDOW *, struct term_node *);
int8_t  ncurses_i_error_window(u_int8_t, char *, ...);
int32_t ncurses_i_popup_window(WINDOW *, const struct tuple_type_desc *, u_int8_t);
int8_t  ncurses_i_edit_tlv(struct term_node *, u_int8_t);
int8_t  ncurses_i_add_selected_tlv_type(WINDOW *, struct term_node *, u_int8_t);
int8_t  ncurses_i_del_selected_tlv(struct term_node *, u_int8_t, u_int8_t);
int8_t  ncurses_i_getstring_window(struct term_node *, char *, char *, u_int16_t, char *);
int32_t ncurses_i_getconfirm(struct term_node *, char *, char *, char *);
int8_t  ncurses_i_get_mode(u_int8_t, WINDOW *);

void resizeHandler(int);

/* Global stuff */
extern void   thread_error(char *, int8_t);
extern u_int32_t uptime;
extern struct term_tty *tty_tmp;
extern int8_t parser_write_config_file(struct term_tty *);


extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);

/* Terminal stuff */
extern struct terminals *terms;
extern int8_t term_add_node(struct term_node **, int8_t, int32_t, pthread_t);

/* Attack stuff */
extern int8_t attack_stp_learn_packet(void);
extern int8_t attack_launch(struct term_node *, u_int16_t, u_int16_t, struct attack_param *, u_int8_t);
extern int8_t attack_kill_th(struct term_node *, pthread_t );
extern int8_t attack_init_params(struct term_node *, struct attack_param *, u_int8_t);
extern int8_t attack_filter_all_params(struct attack_param *, u_int8_t, u_int8_t *);
extern void   attack_free_params(struct attack_param *, u_int8_t);

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
