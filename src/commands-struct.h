/* commands.h
 * Definitions for Cisco CLI commands structures
 *
 * $Id: commands-struct.h 43 2007-04-27 11:07:17Z slay $ 
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

#ifndef __COMMANDS_STRUCT_H__
#define __COMMANDS_STRUCT_H__

#define ANY_PROTO  255
#define LIST_PROTO 254
#define LIST_PARAM 253

struct commands { 
   u_int8_t proto; /* Valid for what protocol? */
   char *s;  /* descr */
   int8_t states[5]; /* Valid for what state? */
   char *help;     /* Help text  */
   char *params;   /* Parameters */
   int8_t (*command)(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
   struct commands *strcom;
};


int8_t command_prueba(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_cls(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_exit(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_enable(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_disable(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);

int8_t command_run_proto(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_cancel_proto(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_clear_proto(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_set_proto(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);

int8_t command_show_attacks(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_history(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_users(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_interfaces(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_version(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_stats(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_proto_params(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_proto_stats(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
int8_t command_show_proto_attacks(struct term_node *, struct words_array *, int16_t, int8_t, int8_t, u_int8_t, struct commands *, int8_t);
 

struct commands comm_cancel[]={
 { ANY_PROTO,  "all", { 0, 0, 0, 1, 0 }, "Cancel all attacks", "<cr>", command_cancel_proto, NULL },  
 { LIST_PROTO, NULL,  { 0, 0, 0, 1, 0 }, "Cancel attacks for", NULL,   command_cancel_proto, NULL },
 { ANY_PROTO,  NULL,  { 0, 0, 0, 0, 0 },  NULL,                NULL,   NULL, NULL }
}; 

struct commands comm_clear[]={
 { ANY_PROTO,  "all", { 0, 0, 0, 1, 0 }, "Clear all stats", "<cr>", command_clear_proto, NULL },  
 { LIST_PROTO, NULL,  { 0, 0, 0, 1, 0 }, "Clear stats for", NULL,   command_clear_proto, NULL },
 { ANY_PROTO,  NULL,  { 0, 0, 0, 0, 0 },  NULL,             NULL,   NULL, NULL }
}; 

struct commands comm_run[]={
 { LIST_PROTO, NULL, { 0, 0, 0, 1, 0 }, "Run attacks for", NULL, command_run_proto, NULL },
 { ANY_PROTO,  NULL, { 0, 0, 0, 0, 0 },  NULL,             NULL, NULL, NULL } 
};

struct commands comm_set_proto[]={
 { LIST_PARAM, NULL, { 0, 0, 0, 1, 0 },  " ",  NULL, command_set_proto, NULL },
 { ANY_PROTO,  NULL, { 0, 0, 0, 0, 0 },  NULL, NULL, NULL, NULL } 
};

struct commands comm_set[]={
 { LIST_PROTO, NULL, { 0, 0, 0, 1, 0 }, "Set params for", NULL, NULL, comm_set_proto },
 { ANY_PROTO,  NULL, { 0, 0, 0, 0, 0 },  NULL,            NULL, NULL, NULL } 
};

struct commands comm_show_proto[]={
 { ANY_PROTO, "attacks", { 0, 0, 1, 1, 0 }, "Show running protocol attacks",    "<cr>", command_show_proto_attacks, NULL },
 { ANY_PROTO, "params",  { 0, 0, 0, 1, 0 }, "Show protocol params for attacks", "<cr>", command_show_proto_params,  NULL }, 
 { ANY_PROTO, "stats",   { 0, 0, 0, 1, 0 }, "Show protocol statistics",         "<cr>", command_show_proto_stats,   NULL },
 { ANY_PROTO, NULL,      { 0, 0, 0, 0, 0 },  NULL,                              NULL,  NULL, NULL }
};

struct commands comm_show[]={
 { ANY_PROTO, "attacks",    { 0, 0, 1, 1, 0 }, "Show running attacks",      "<cr>", command_show_attacks, NULL },
 { ANY_PROTO, "history",    { 0, 0, 1, 1, 0 }, "Display the session command history", "<cr>", command_show_history, NULL }, 
 { ANY_PROTO, "interfaces", { 0, 0, 1, 1, 0 }, "Interface status",          "<cr>", command_show_interfaces, NULL },  
 { ANY_PROTO, "stats",      { 0, 0, 1, 1, 0 }, "Show statistics",           "<cr>", command_show_stats, NULL },
 { ANY_PROTO, "users",      { 0, 0, 1, 1, 0 }, "Display information about terminal lines", "<cr>", command_show_users, NULL },
 { ANY_PROTO, "version",    { 0, 0, 1, 1, 0 }, "System hardware and software status", "<cr>", command_show_version, NULL },
 { LIST_PROTO, NULL,        { 0, 0, 0, 1, 0 }, "Show info for",             NULL,   NULL, comm_show_proto },
 { ANY_PROTO,  NULL,        { 0, 0, 0, 0, 0 },  NULL,                       NULL,   NULL, NULL }
};

struct commands comm_common[]={
 { ANY_PROTO, "cancel", { 0, 0, 0, 1, 0 }, "Cancel running attack",             NULL,   NULL, comm_cancel },
 { ANY_PROTO, "clear",  { 0, 0, 0, 1, 0 }, "Clear stats",                       NULL,   NULL, comm_clear  },
 { ANY_PROTO, "cls",    { 0, 0, 1, 1, 0 }, "Clear screen",                      "<cr>", command_cls,     NULL },
 { ANY_PROTO, "disable",{ 0, 0, 0, 1, 0 }, "Turn off privileged commands",      "<cr>", command_disable, NULL },
 { ANY_PROTO, "enable", { 0, 0, 1, 0, 0 }, "Go to administration level",        "<cr>", command_enable,  NULL },
 { ANY_PROTO, "exit",   { 0, 0, 1, 1, 0 }, "Exit from current level",           "<cr>", command_exit,    NULL },  
 { ANY_PROTO, "prueba", { 0, 0, 0, 1, 0 }, "Test command",                      "<cr>", command_prueba,  NULL },
 { ANY_PROTO, "run",    { 0, 0, 0, 1, 0 }, "Run attack",                        NULL,   NULL, comm_run  }, 
 { ANY_PROTO, "set",    { 0, 0, 0, 1, 0 }, "Set specific params for protocols", NULL,   NULL, comm_set  },
 { ANY_PROTO, "show",   { 0, 0, 1, 1, 0 }, "Show running system information",   NULL,   NULL, comm_show },
 { ANY_PROTO, NULL,     { 0, 0, 0, 0, 0,}, NULL,                                NULL,   NULL, NULL      }
};


#endif
