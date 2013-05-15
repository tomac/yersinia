/* parser.h
 * Definitions for command line parser and parser utilities
 *
 * $Id: parser.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __PARSER_H__
#define __PARSER_H__

#include "interfaces.h"
#include "terminal-defs.h"
#include "attack.h"

#define MIN2(a,b) ((a)<(b)?(a):(b))
#define MIN3(a,b,c) ((a)<(b)?(MIN2(a,c)):(MIN2(b,c)))
#define MAX2(a,b) ((a)<(b)?(b):(a))
#define MAX3(a,b,c) ((a)<(b)?(MAX2(b,c)):(MAX2(a,c))) 

/* 
 * Following struct is just for passing argv,argc and protocol from
 * parent process to command line thread peer because the firsts
 * arguments parsing is made within parent process context while the
 * protocol parsing is made within the command line thread.
 */
struct cl_args {
    struct term_tty tty;
    int16_t count; 
    char **argv_tmp; 
    int8_t proto_index;
};


int8_t parser_initial(struct term_tty *, struct cl_args *, int, char **);
int8_t parser_are_digits( int8_t *, int8_t );
void   parser_str_tolower( char *);
void   parser_help( void );
int8_t parser_vrfy_mac( char *, u_int8_t * );
int8_t parser_vrfy_bridge_id( char *, u_int8_t * );
int8_t parser_command2index(register const struct attack *, register int8_t);

int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
int8_t parser_get_formated_inet_address_fill(u_int32_t in, char *inet, u_int16_t inet_len, int8_t fill_up);

int8_t parser_get_inet_aton(char *, struct in_addr *);
int8_t parser_get_random_string(u_int8_t *, u_int8_t);
int8_t parser_get_random_int(u_int8_t);
int8_t parser_read_config_file(struct term_tty *, struct term_node *);
int8_t parser_write_config_file(struct term_tty *);
void   parser_basedisplay(u_int8_t, u_int8_t, char *, size_t );
int8_t parser_vrfy_ip2filter(char *, struct term_tty *);
int8_t parser_add_ip2filter(u_int32_t, u_int32_t, struct term_tty *, char *);
void   parser_free_ip2filter(struct filter *);
int8_t parser_filter_param(u_int8_t, void *, char *, u_int16_t, u_int16_t);
void   parser_cl_proto_help(u_int8_t, struct term_node *);
int8_t parser_cl_proto( struct term_node *, int8_t, char **, u_int8_t);
int8_t parser_binary2printable(u_int8_t, u_int8_t, void *, char *);
char  *parser_get_meaning(char *, const struct tuple_type_desc *);
u_int8_t parser_get_max_field_length(const struct tuple_type_desc *);

#if (defined(SOLARIS) && !defined(SOLARIS_27))
extern int inet_aton( char *, struct in_addr * );
#endif

extern struct terminals *terms;
extern int8_t bin_data[];

extern int8_t protocol_proto2index(char *);

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
