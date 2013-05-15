/* commands.h
 * Definitions for Cisco CLI commands
 *
 * $Id: commands.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "terminal-defs.h"
#include "commands-struct.h"
#include "interfaces.h"
#include "attack.h"
#include "parser.h"

int8_t command_entry_point(struct term_node *, struct words_array *, int8_t, int8_t, int8_t);
int8_t command_main(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_list_help(struct term_node *, struct commands *, u_int8_t);
int8_t command_list_help2(struct term_node *, char *, struct commands *, u_int8_t *, 
                          u_int8_t *, u_int8_t *, u_int8_t *, int8_t);

int8_t command_bad_input(struct term_node *, int8_t);
int8_t command_proto_attacks(struct term_node *, u_int16_t);

int8_t command_run_attack(struct term_node *, u_int8_t, int8_t);
int8_t show_interface_data(struct term_node *, struct interface_data *);

extern struct terminals *terms;
extern struct term_types term_type[];
extern struct term_states term_states[];
extern u_int32_t uptime;

/* Extern functions...*/
extern int8_t term_vty_exit(struct term_node *);
extern int8_t term_vty_flush(struct term_node *);
extern int8_t term_vty_write(struct term_node *, char *, u_int16_t);
extern int8_t term_vty_tab_subst(struct term_node *, char *, char *);
extern int8_t attack_launch(struct term_node *, u_int16_t, u_int16_t, struct attack_param *, u_int8_t );
extern int8_t attack_init_params(struct term_node *, struct attack_param *, u_int8_t);
extern int8_t init_attribs(struct term_node *);
extern void   parser_str_tolower( char *);
extern int8_t parser_vrfy_mac( char *, u_int8_t * );
extern int8_t parser_vrfy_bridge_id( char *, u_int8_t * );
extern int8_t parser_filter_param(u_int8_t, void *, char *, u_int16_t, u_int16_t);
extern void   write_log( u_int16_t mode, char *msg, ... );

#endif

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
