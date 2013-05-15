/* yersinia.h
 * Definitions for application main entry point and command line client
 *
 * $Id: yersinia.h 43 2007-04-27 11:07:17Z slay $ 
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

#ifndef __YERSINIA_H__
#define __YERSINIA_H__

#ifdef HAS_CURSES
#include "ncurses-gui.h"
#endif

#ifdef HAVE_GTK
#include "gtk-gui.h"
#endif

#include "interfaces.h"
#include "parser.h"
#include "terminal-defs.h"
#include "attack.h"
#include "global.h"

#ifdef MAX
#undef MAX
#endif 

#define MAX(x,y) ( ( x >= y) ? x : y )

struct term_tty *tty_tmp=NULL;
struct termios term_parent;

void  become_daemon(pid_t);
void  doloop(struct term_node *, int); 
void  sig_alarm( int );
void  handle_signals( void );
void  handle_signals_parent( void );
int   posix_signal( int, void (*handler)(int) );
void  final( int );
void  final_parent( int );
void  clean_exit(void);
void  g00dbye(void);
int8_t   init_attribs(struct term_node *);
void  go_out_error( int8_t *msg, int32_t );
void  go_out( char *msg, ... );
void  write_log( u_int16_t mode, char *msg, ... );
void  init_log(void);
void  finish_log(void);
void  init_socket(void);
void *th_tty_peer(void *);
void  th_tty_peer_exit(struct term_node *);
void *th_uptime(void *);
void  th_uptime_clean(void *);
void  th_uptime_exit(void);
int8_t show_vty_motd(void);


/* Extern variables...*/
extern struct term_types term_type[];
extern char *vty_motd[];

/* Extern functions...*/
extern int8_t term_motd(void);
extern int8_t term_init(void);
extern void term_destroy(void);   
extern void term_delete_all_tty(void);

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
