/* attack.h
 * Definitions for attacks management core
 *
 * $Id: attack.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __ATTACK_H__
#define __ATTACK_H__

#include <libnet.h>
#include <pcap.h>

#include "thread-util.h"
#include "interfaces.h"
#include "terminal-defs.h"


int8_t attack_launch(struct term_node *, u_int16_t, u_int16_t, struct attack_param *, u_int8_t );
int8_t attack_kill_th(struct term_node *, pthread_t );
int8_t attack_th_exit(struct attacks *);
int8_t attack_init_params(struct term_node *, struct attack_param *, u_int8_t);
void   attack_free_params(struct attack_param *, u_int8_t);
int8_t attack_filter_all_params(struct attack_param *, u_int8_t, u_int8_t *);
void   attack_gen_mac(u_int8_t *);

extern int8_t thread_destroy(THREAD *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t parser_vrfy_mac( char *, u_int8_t *);
extern int8_t parser_vrfy_bridge_id( char *, u_int8_t *);
extern int8_t parser_get_inet_aton(char *, struct in_addr *);
extern int8_t parser_filter_param(u_int8_t, void *, char *, u_int16_t, u_int16_t);

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
