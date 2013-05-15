/* terminal-defs.h
 * Definitions for lot of things. It must be changed!! :(
 *
 * $Id: terminal-defs.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __TERMINAL_DEFS_H__
#define __TERMINAL_DEFS_H__

#include <pcap.h>

#include "protocols.h"
#include "thread-util.h"
#include "dlist.h"

#ifdef HAVE_GTK
#include <gtk/gtk.h>
#endif

#define SIZE_ARRAY(x)   ( (sizeof(x))/(sizeof(x[0])) )

#define LICENSE "Yersinia\
   \nBy David Barroso <tomac@yersinia.net> and Alfredo Andres <slay@yersinia.net>\
   \nCopyright 2005, 2006, 2007 Alfredo Andres and David Barroso \
   \n\nThis program is free software; you can redistribute it and/or \
   \nmodify it under the terms of the GNU General Public License \
   \nas published by the Free Software Foundation; either version 2 \
   \nof the License, or (at your option) any later version. \
   \n\nThis program is distributed in the hope that it will be useful, \
   \nbut WITHOUT ANY WARRANTY; without even the implied warranty of \
   \nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the \
   \nGNU General Public License for more details. \
   \n\nYou should have received a copy of the GNU General Public License \
   \nalong with this program; if not, write to the Free Software \
   \nFoundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA."

/* Keys bindings...*/
#define ESC1          27
#define ESC2          91
#define ESC3          50
#define TKEY_INIT     49
#define TKEY_SUPR     51
#define TKEY_END      52
#define TKEY_UP       65
#define TKEY_DOWN     66
#define TKEY_RIGHT    67
#define TKEY_LEFT     68
#define INSERT        126
#define BACKSPACE     127
#define BACKSPACE_WIN 8
#define CTRL_C        3
#define CTRL_D        4
#define CTRL_L        12
#define CTRL_U        21
#define DEL           8
#define BEL           7  
#define SPACE         32
#define DEL_BACK      "\x08 \x08"

#define CLEAR_SCREEN "\033[H\033[J"

 

/* Telnet commands... */
#define COM_SE   240
#define COM_NOP  241
#define COM_DM   242
#define COM_BRK  243
#define COM_IP   244
#define COM_AO   245
#define COM_AYT  246
#define COM_EC   247
#define COM_EL   248
#define COM_GA   249
#define COM_SB   250
#define COM_WILL 251
#define COM_WONT 252
#define COM_DO   253
#define COM_DONT 254
#define COM_IAC  0xFF

/* Telnet Options... */
#define OPT_ECHO    1
#define OPT_SGAHEAD 3
#define OPT_STATUS  5
#define OPT_TMARK   6
#define OPT_TTYPE   24
#define OPT_WSIZE   31
#define OPT_TSPEED  32
#define OPT_RFLOW   33
#define OPT_LMODE   34
#define OPT_ENVIRON 36

#define VTY_MORE "\r\n--More--\r"

#define KILL_THREAD   1
#define NOKILL_THREAD 0

#define MAX_HISTORY 4

#define HIST_INDEXING  0
#define HIST_UPDATING  1

#define MAX_LINE     128
#define MAX_COMMAND  48
#define MAX_USERNAME MAX_COMMAND
#define MAX_PASSWORD 8
#define MAX_FAILS 3
#define MAX_VTY   5
#define MAX_TTY   2
#define MAX_CON   1
#define MAX_TERMS (MAX_VTY + MAX_TTY + MAX_CON)


#define MIN_TERM_WIDTH  10
#define MID_TERM_WIDTH  128
#define MAX_TERM_WIDTH  500
#define MIN_TERM_HEIGHT 5
#define MID_TERM_HEIGHT 48
#define MAX_TERM_HEIGHT 500

#define VTY_USER   "root"
#define VTY_PASS   "root"
#define VTY_ENABLE "tomac"
#define VTY_PORT   12000


#define TTY_TIMEOUT    500
#define LOGIN_TIMEOUT  20

#define WELCOME "\r\nWelcome to "PACKAGE" version "VERSION".\r\nCopyright 2004-2007 Slay & Tomac.\r\n\r\n" 

#define VTY_TIMEOUT_BANNER "\r\nVty connection is timed out!!\r\n\r\n"

#define VTY_FAILED "Authentication failed!!\r\n"
#define VTY_GO_OUT "\r\nToo many attempts!!\r\n\r\n"


/* Terminal types...*/
#define TERM_CON    0
#define TERM_TTY    1
#define TERM_VTY    2
#define TERM_NOTYPE 3


/* Terminal states...*/
#define LOGIN_STATE     0
#define PASSWORD_STATE  1
#define NORMAL_STATE    2
#define ENABLE_STATE    3
#define PARAMS_STATE    4
#define INTERFACE_STATE 5


/* Ncurses field position */
#define FIELD_FIRST  0
#define FIELD_LAST   1
#define FIELD_NORMAL 2

#define ALL_ATTACK_THREADS 0

#define MAX_THREAD_ATTACK 5

#define MAX_TLV          20
#define MAX_VALUE_LENGTH 20
#define MAX_STRING_SIZE  64

#define TLV_DELETE   0
#define TLV_ADD      1

/* taken from tcpdump print-ascii.c 
 * http://www.tcpdump.org
 */
#define ASCII_LINELENGTH 300
#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
		(HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

#define DOS       1
#define NONDOS    0
#define SINGLE    0 
#define CONTINOUS 1 

#define MAX_WORDS 10
struct words_array { 
       u_int16_t nwords; /* How many words?   */
       u_int16_t indx;   /* Last treated word */
       char *word[MAX_WORDS+1];
};


struct attacks {
       u_int8_t  up;        /* active or not */
       THREAD    attack_th;
       THREAD    helper_th;
       u_int16_t attack;    /* attack number */
       list_t   *used_ints; /* interfaces used */
       u_int8_t  mac_spoofing;
       void     *data;      /* packet */
       void     *params;    /* Parameters */
       u_int8_t  nparams;   /* How many params */
};


struct attack_param {
       void     *value;  /* Value */
       char *desc;   /* Description */
       u_int16_t size;   /* Size */
       u_int8_t  type;   /* Type */
       u_int16_t size_print; /* Printable size */
       char  *print; /* Printable */
};

struct attack {
       int16_t v;        /* value       */
       char *s;          /* descr       */
       int8_t type;      /* DoS attack? */
       int8_t single;    /* Is only one packet or is a continous attack? */
       void (*attack_th_launch)(void *);
       const struct attack_param *param; /* Attack parameters */
       u_int8_t nparams; /* How many parameters */
};


struct pcap_file {
       char           *name;
       int             iflink;
       pcap_t         *pd;
       pcap_dumper_t  *pdumper;
       pthread_mutex_t mutex;
};


struct protocol {
       u_int16_t proto;                   /* Proto id */
       char      name[MAX_PROTO_NAME];    /* Proto name */
       struct    attacks attacks[MAX_THREAD_ATTACK]; /* Attacking threads */
       void     *tmp_data;                /* temporal packet struct */
       void     **commands_param;          /* struct for network interface and protocol fields */ 
       struct    pcap_file pcap_file;     /* Pcap file per protocol */
};


struct telnet_option {
       u_int8_t  code;
       char      *name;
       u_int8_t  negotiate;
};


struct term_vty {
       int32_t   sock;       /* Socket in use (if VTY)           */
       char     *history[MAX_HISTORY]; /* Command history        */
       u_int16_t index_history;        /* Command history index  */
       void     *buffer_tx;            /* What to send to client */
       u_int16_t buffer_tx_len;        /* Size of client buffer  */
       void      *more_tx;             /* Use it on more mode    */
       u_int16_t more_tx_len;          /* Size of more           */
       char      buf_command[MAX_COMMAND]; /* The command        */
       int8_t    repeat_command;      /* Repeat last command  */
       u_int16_t command_len;         /* Command Size         */
       u_int16_t command_cursor;      /* Where is the cursor  */
       u_int8_t  login_fails;         /* Failed login tries   */
       int8_t    clearmode;  /* Terminal in clear mode           */
       int8_t    escmode;    /* Terminal in Escape mode          */
       int8_t    insertmode; /* Terminal in INSERT mode          */
       int8_t    moremode;   /* Terminal in More mode            */
       u_int16_t height;     /* Telnet Terminal Height           */
       u_int16_t width;      /* Telnet Terminal Width            */
       u_int8_t  term_size[4]; /* Terminal temporary size */
       u_int8_t  term_size_index; 
       int8_t    iacmode;    /* Telnet Interpret As Command mode */
       int8_t    sbmode;     /* Telnet Suboption Begin mode      */
       int8_t    nwsmode;    /* Telnet Negotiating Window size   */
       int8_t    othermode;  /* Telnet other mode                */
       int8_t    authing;    /* We are authenticating            */
       u_int8_t  substate;   /* Needed for attack params         */
       u_int8_t  nparams;    /* How many params                  */
       u_int8_t  attack_proto;
       u_int8_t  attack_index;                 
       struct attack_param *attack_param; /* Attack params */
};

struct filter {
       char *expression;
       u_int32_t begin;
       u_int32_t end;
       struct filter *next;
};

struct term_tty {
      struct termios *term;
      int8_t daemonize;
      int8_t debug;
      int8_t interactive;
      int8_t gtk;
      int16_t attack;
      FILE *log_file;
      char config_file[FILENAME_MAX];
      int8_t mac_spoofing;
      int8_t splash;
      char username[MAX_USERNAME];
      char password[MAX_PASSWORD];
      char e_password[MAX_PASSWORD];
      u_int16_t port;
      struct filter *ip_filter;
#ifdef HAVE_GTK
	  GtkTextBuffer *buffer_log;
#endif
};


struct term_console {
#if defined (TIOCGWINSZ) && defined (HAVE_NCURSES_RESIZETERM)
       int8_t need_resize;
#endif                   
};


struct term_node { 
       u_int8_t  up;       /* Terminal slot is in use?           */
       u_int8_t  type;     /* Terminal type (CONSOLE, TTY, VTY)  */
       u_int16_t number;   /* Terminal number                    */
       u_int8_t  state;    /* Terminal state                     */
       u_int32_t timeout;    /* Timeout                          */
       char      username[MAX_USERNAME]; /* Username on terminal */
       char      since[26];   /* User is logged in since...      */
       char      from_ip[15]; /* IP user is connected from       */
       u_int16_t from_port;   /* Port user is connected from     */
       THREAD    thread;      /* Thread owner                    */
       struct    pcap_file pcap_file;  /* Pcap file for ALL protocols */
       list_t   *used_ints;
       struct    protocol protocol[MAX_PROTOCOLS];
       u_int8_t  mac_spoofing;
       void     *specific;
};

#define INITIAL 0
#define RUNNING 1
#define STOPPED 2

struct terminals {
       struct term_node list[MAX_TERMS];
       pthread_mutex_t mutex;
#ifndef HAVE_RAND_R
       pthread_mutex_t mutex_rand;
#endif
       u_int8_t work_state; 
       THREAD uptime_th;
       THREAD admin_listen_th;
       THREAD pcap_listen_th;
#ifdef HAS_CURSES
       THREAD gui_th;
#endif
#ifdef HAVE_GTK
       THREAD gui_gtk_th;
#endif
};


struct term_types { 
       char *name;
       struct term_node *list;
       u_int16_t max;
};


struct term_states { 
       char  *name;
       char  *prompt2;
       char  *prompt_authing;
       int8_t key_able;
       int8_t key_cursor;
       int8_t key_help;
       int8_t do_echo;
       u_int32_t timeout;            
};


struct tlv_options {
       u_int16_t type;
       u_int16_t length;
       u_int8_t value[MAX_VALUE_LENGTH];
};

#endif
