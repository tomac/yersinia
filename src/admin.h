/* admin.h
 * Definitions for network server thread
 *
 * $Id: admin.h 43 2007-04-27 11:07:17Z slay $ 
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

#ifndef __ADMIN_H__
#define __ADMIN_H__

#include "terminal-defs.h"
#include "interfaces.h"

/* Own functions... */
int8_t admin_init(struct term_tty *);
void   admin_exit(void);
void  *admin_th_listen(void *);
void   admin_th_listen_clean(void *);
void   admin_th_listen_exit(struct sockaddr *, int32_t);
void  *admin_th_network_peer(void *);
void   admin_th_network_peer_clean(void *);
void   admin_th_network_peer_exit(struct term_node *, int32_t);
int8_t admin_filter_ip(u_int32_t *, struct filter *);

/* Extern variables...*/
extern struct terminals *terms;
extern struct term_types term_type[];
extern struct term_states term_states[];
extern u_int32_t uptime;
extern int8_t bin_data[];


/* Extern functions...*/
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_kill_th(struct term_node *, pthread_t);
extern int8_t term_add_node(struct term_node **, int8_t, int32_t, pthread_t);
extern int8_t term_write(struct term_node *, char *, u_int16_t);
extern void   term_delete_all(void);
extern void   term_delete_node(struct term_node *, int8_t);
extern void   term_delete_all_vty(void);
extern int8_t term_vty_banner(struct term_node *);
extern int8_t term_vty_prompt(struct term_node *);
extern int8_t term_vty_motd(struct term_node *);
extern int8_t term_vty_negotiate(struct term_node *);
extern int8_t term_vty_history_add(struct term_node *, char *, u_int16_t);
extern int8_t term_vty_history_next(struct term_node *);
extern int8_t term_vty_history_prev(struct term_node *);
extern int8_t term_vty_mv_cursor_right(struct term_node *);
extern int8_t term_vty_mv_cursor_left(struct term_node *);
extern int8_t term_vty_mv_cursor_init(struct term_node *);
extern int8_t term_vty_mv_cursor_end(struct term_node *);
extern int8_t term_vty_supr(struct term_node *);
extern int8_t term_vty_do_command(struct term_node *);
extern int8_t term_vty_complete_command(struct term_node *);
extern int8_t term_vty_backspace(struct term_node *);
extern int8_t term_vty_help(struct term_node *);
extern int8_t term_vty_auth(int8_t, char *, char *);
extern int8_t term_vty_flush(struct term_node *);
extern int8_t term_vty_write(struct term_node *, char *, u_int16_t);
extern int8_t term_vty_clear_line(struct term_node *, u_int16_t);
extern void   term_vty_clear_command(struct term_node *);
extern int8_t term_vty_exit(struct term_node *);
extern int8_t term_vty_clear_screen(struct term_node *);
extern int8_t term_vty_clear_remote(struct term_node *);
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   thread_error(char *, int8_t);
extern int8_t thread_destroy_cancel(pthread_t);
extern void   thread_free_r(void *);
extern int8_t init_attribs(struct term_node *);

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
