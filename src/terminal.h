/* terminal.h
 * Definitions for network terminal management
 *
 * $Id: terminal.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __TERMINAL_H__
#define __TERMINAL_H__

#include "terminal-defs.h"

struct telnet_option telnet_command[]={ 
       { COM_SE,   "Suboption_End",0      },
       { COM_NOP,  "NOP",0                },
       { COM_DM,   "Data_Mark",0          },
       { COM_BRK,  "Break",0              },
       { COM_IP,   "Interrupt_Process",0  },
       { COM_AO,   "Abort_Output",0       },
       { COM_AYT,  "Are_You_There",0      },
       { COM_EC,   "Escape_Character",0   },
       { COM_EL,   "Erase_Line",0         },
       { COM_GA,   "Go_Ahead",0           },
       { COM_SB,   "Suboption_Begin",0    },
       { COM_WILL, "Will",1               },
       { COM_WONT, "Won't",1              },
       { COM_DO,   "Do",1                 },
       { COM_DONT, "Don't",1              }, 
       { COM_IAC,  "Interpret_As_Command",0 } 

};

struct telnet_option telnet_option[]={
       { OPT_ECHO,    "Echo",0              },
       { OPT_SGAHEAD, "Supress_Go_Ahead",0  },
       { OPT_STATUS,  "Status",0            },
       { OPT_TMARK,   "Timing_Mark",0       },
       { OPT_TTYPE,   "Terminal_Type",0     },
       { OPT_WSIZE,   "Window_Size",0       },
       { OPT_TSPEED,  "Terminal_Speed",0    },
       { OPT_RFLOW,   "Remote_Flow",0       },
       { OPT_LMODE,   "Linemode",0          },
       { OPT_ENVIRON, "Environ_Variables",0 }
};

int8_t neg_default[]={  
       COM_IAC, COM_DONT, OPT_LMODE,   /* Don't Linemode */
       COM_IAC, COM_WILL, OPT_SGAHEAD, /* Will Supress Go Ahead */
       COM_IAC, COM_WILL, OPT_ECHO,    /* Will Echo */
       COM_IAC, COM_DO,   OPT_WSIZE,   /* Do Negotiate Window Size */
       COM_IAC, COM_DONT, OPT_TTYPE,   /* Don't Negotiate Terminal Type */
       COM_IAC, COM_DONT, OPT_ENVIRON, /* Don't send Environment Variables */
       COM_IAC, COM_DONT, OPT_RFLOW,   /* Don't Remote Flow Control */
       COM_IAC, COM_DONT, OPT_TSPEED,  /* Don't Terminal Speed */    
       COM_IAC, COM_DONT, OPT_STATUS   /* Don't Status */
};



char *vty_motd[]={
  "\r\n\r\nMOTD: Don't do it!! Don't do it!! Don't do it!!\r\n\t(Please DO IT)\r\n",
  "\r\n\r\nMOTD: Ghosts'n'Goblins, Trojan, Out Run, Bump'n'jump, Side Arms...\r\n",
  "\r\n\r\nMOTD: M4t30 31337 M4t30 31337 M4t30 31337 M4t30 31337 M4t30 31337\r\n",
  "\r\n\r\nMOTD: Be a good boy... (SSLBomb rulez)\r\n",
  "\r\n\r\nMOTD: I'm so 31337 that I can pronounce yersinia as yersiiiniiiiaaaa\r\n",
  "\r\n\r\nMOTD: Yersiiiiiiiiiiiniaaaa, you're breaking my heart!! - S&G (c) -\r\n",
  "\r\n\r\nMOTD: The nightly bird catches the worm ;)\r\n",
  "\r\n\r\nMOTD: Do you have an ISL capable Cisco switch? Share it!! ;)\r\n", 
  "\r\n\r\nMOTD: Do you have any Alcatel or Juniper switch? Share it!! ;)\r\n",    
  "\r\n\r\nMOTD: Do you have the new Denon AV amplifier with HDMI 1.3 support? Share it!! ;)\r\n",    
  "\r\n\r\nMOTD: Zaragoza, Palencia, Soria... Nice spanish cities to live in, give them a try!\r\n",
  "\r\n\r\nMOTD: I would like to see romanian wild boars, could you invite me? :)\r\n\tMail me at slay _at_ yersinia.net\r\n",   
  "\r\n\r\nMOTD: The world is waiting for... M-A-T-E-O!!!\r\n",
  "\r\n\r\nMOTD: Who dares wins\r\n",
  "\r\n\r\nMOTD: It's the voodoo who do what you don't dare to people!\r\n",
  "\r\n\r\nMOTD: Magic people, voodoo people!\r\n",
  "\r\n\r\nMOTD: Not one day goes by that I don't ride, 'til the infinite, the horse of my imagination\r\n",
  "\r\n\r\nMOTD: We need a fancy web, could you please help us?\r\n",
  "\r\n\r\nMOTD: Having lotto fun with my ProjectionDesign Action! Model Two... :)\r\n",
  "\r\n\r\nMOTD: Having lotto fun with my Audiovector Mi3 Avantgarde Arrete LE... :)\r\n",
  "\r\n\r\nMOTD: Having lotto fun with my Denon AVC-A11XVA... :)\r\n",
  "\r\n\r\nMOTD: My notebook is totally deprecated... gimme one!... :)\r\n",
  "\r\n\r\nMOTD: Kudos to daddy... wherever you are... :)\r\n",
  "\r\n\r\nMOTD: I'm waiting for the PS3 but i'm short of money... :'(\r\n",  
  "\r\n\r\nMOTD: The Hakin9 magazine owe money to us... 500 Euros\r\n",  
  "\r\n\r\nMOTD: Daniela blu-eyes... :)\r\n",  
  "\r\n\r\nMOTD: Kudos to daddy... wherever you are... :)\r\n",  
  "\r\n\r\nMOTD: Snowboard on the winter, MBK on the summer :)\r\n"
};


struct term_states term_states[] = { 
    { "LOGIN_STATE",     "\r\nlogin: ",    NULL,        0, 0, 0, 1, LOGIN_TIMEOUT },
    { "PASSWORD_STATE",  "password: ",     NULL,        0, 0, 0, 0, LOGIN_TIMEOUT },
    { "NORMAL_STATE",    "yersinia> ",     "Password:", 1, 1, 1, 1, TTY_TIMEOUT   },
    { "ENABLE_STATE",    "yersinia# ",     NULL,        1, 1, 1, 1, TTY_TIMEOUT   },
    { "PARAMS_STATE",    NULL        ,     NULL,        1, 0, 0, 1, TTY_TIMEOUT   },
    { "INTERFACE_STATE", "yersinia(if)# ", NULL,        1, 1, 1, 1, TTY_TIMEOUT   }
};



struct term_types term_type[] = {
       { "console", NULL, MAX_CON },
       { "tty",     NULL, MAX_TTY },
       { "vty",     NULL, MAX_VTY },
       { "unknown", NULL, 0       }
};

struct terminals *terms=NULL;


#ifdef HAVE_RAND_R
#ifdef SOLARIS
int rand_r(unsigned int *);
#endif
#endif

int8_t term_init(void);
void   term_destroy(void);
int8_t term_add_node(struct term_node **, int8_t, int32_t, pthread_t);
void   term_delete_node(struct term_node *, int8_t);
void   term_delete_all(void);
void   term_delete_all_console(void);
void   term_delete_all_tty(void);
void   term_delete_all_vty(void);
void   term_delete_class(struct term_node *, int8_t);
int8_t term_motd(void);
int8_t term_write(struct term_node *, char *, u_int16_t);
int8_t term_vty_banner(struct term_node *);
int8_t term_vty_prompt(struct term_node *);
int8_t term_vty_motd(struct term_node *);
int8_t term_vty_negotiate(struct term_node *);
int8_t term_vty_history_add(struct term_node *, char *, u_int16_t);
int8_t term_vty_history_next(struct term_node *);
int8_t term_vty_history_prev(struct term_node *);
int8_t term_vty_history_get_slot(char *[], int8_t, int8_t);
int8_t term_vty_mv_cursor_right(struct term_node *);
int8_t term_vty_mv_cursor_left(struct term_node *);
int8_t term_vty_mv_cursor_init(struct term_node *);
int8_t term_vty_mv_cursor_end(struct term_node *);
int8_t term_vty_supr(struct term_node *);
int8_t term_vty_do_command(struct term_node *);
int8_t term_vty_complete_command(struct term_node *);
int8_t term_vty_backspace(struct term_node *);
int8_t term_vty_help(struct term_node *);
int8_t term_vty_help_tab(struct term_node *, int8_t);

int8_t term_vty_auth(int8_t, char *, char *);
void   term_vty_clear_username(struct term_node *);
void   term_vty_clear_command(struct term_node *);
int8_t term_vty_clear_remote(struct term_node *);
int8_t term_vty_clear_line(struct term_node *, u_int16_t);
int8_t term_vty_clear_screen(struct term_node *);
int8_t term_vty_flush(struct term_node *);
int8_t term_vty_write(struct term_node *, char *, u_int16_t);
int8_t term_vty_more(struct term_node *node);
int8_t term_vty_buffer_add(struct term_node *, void *, u_int16_t);
int8_t term_vty_exit(struct term_node *);
int8_t term_vty_set_words(struct term_node *, struct words_array *);
void   term_vty_free_words(struct words_array *);
int8_t term_vty_tab_subst(struct term_node *, char *, char *);


/* Extern functions...*/
extern void  *admin_th_calloc_r(size_t);
extern void   admin_th_free_r(void *);
extern void   thread_error(char *, int8_t);
extern void  *thread_calloc_r(size_t);
extern void   thread_free_r(void *);
#ifdef HAVE_REMOTE_ADMIN
extern int8_t command_cls(struct term_node *, struct words_array *, int16_t, int8_t, int8_t);
extern int8_t command_entry_point(struct term_node *, struct words_array *, int8_t, int8_t, int8_t);
#endif
extern int8_t interfaces_pcap_file_open(struct term_node *, u_int8_t, u_int8_t *, u_int16_t);
extern int8_t interfaces_pcap_file_close(struct term_node *, u_int8_t);
extern void   attack_free_params(struct attack_param *, u_int8_t);
extern int8_t attack_launch(struct term_node *, u_int16_t, u_int16_t, struct attack_param *, u_int8_t );
extern int8_t parser_filter_param(u_int8_t, void *, char *, u_int16_t, int16_t);
extern int8_t interfaces_compare(void *, void *);

extern struct term_tty *tty_tmp;

#endif

