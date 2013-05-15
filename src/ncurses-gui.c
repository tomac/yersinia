/* ncurses-gui.c
 * Implementation for ncurses GUI
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

#ifndef lint
static const char rcsid[] =
"$Id: ncurses-gui.c 43 2007-04-27 11:07:17Z slay $";
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _REENTRANT

#include <stdio.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <sys/socket.h>       

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else
#ifdef HAVE_NETINET_IN_SYSTEM_H
#include <netinet/in_system.h>
#endif
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#endif

#include <stdarg.h>

#include <netinet/tcp.h>

#ifdef SOLARIS
#include <pthread.h>
#include <thread.h>
#else
#include <pthread.h>
#endif

#include "ncurses-gui.h"
#include "ncurses-interface.h"
#include "ncurses-callbacks.h"

/*
 * Initialization routines for the GUI
 */
void 
ncurses_gui(void *args)
{
    int tmp;
    WINDOW *my_wins[NCURSES_MAX_WINDOWS];
    PANEL  *my_panels[NCURSES_MAX_WINDOWS];
    struct term_node *term_node = NULL;
    time_t this_time;
    sigset_t mask;
    struct interface_data *iface_data=NULL, *iface;

    terms->work_state = RUNNING;

    pthread_mutex_lock(&terms->gui_th.finished);

    write_log(0,"\n ncurses_gui_th = %d\n",(int)pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("ncurses_gui_th pthread_sigmask()",errno);
       ncurses_gui_th_exit(NULL);
    }
 
    if (pthread_mutex_lock(&terms->mutex) != 0) {
        thread_error("ncurses_gui_th pthread_mutex_lock",errno);
        ncurses_gui_th_exit(NULL);
    }

    if (term_add_node(&term_node, TERM_CON, (int)NULL, pthread_self()) < 0)
    {
       if (pthread_mutex_unlock(&terms->mutex) != 0)
          thread_error("ncurses_gui_th pthread_mutex_unlock",errno);
       ncurses_gui_th_exit(NULL);
    }
    
    if (term_node == NULL)
    {
       write_log(0, "Ouch!! No more than %d %s accepted!!\n", 
               term_type[TERM_CON].max, term_type[TERM_CON].name);
       if (pthread_mutex_unlock(&terms->mutex) != 0)
          thread_error("ncurses_gui_th pthread_mutex_unlock",errno);
       ncurses_gui_th_exit(NULL);
    }

    this_time = time(NULL);

#ifdef HAVE_CTIME_R
#ifdef SOLARIS
    ctime_r(&this_time,term_node->since, sizeof(term_node->since));
#else
    ctime_r(&this_time,term_node->since);
#endif
#else
    pthread_mutex_lock(&mutex_ctime);
    strncpy(term_node->since, ctime(&this_time), sizeof(term_node->since));
    pthread_mutex_unlock(&mutex_ctime);
#endif

    /* Just to remove the cr+lf...*/
    term_node->since[sizeof(term_node->since)-2] = 0;

    /* This is a console so, man... ;) */
    strncpy(term_node->from_ip, "127.0.0.1", sizeof(term_node->from_ip));
   
   /* Parse config file */
   if (strlen(tty_tmp->config_file))
      if (parser_read_config_file(tty_tmp, term_node) < 0)
      {
         write_log(0, "Error reading configuration file\n");
/*         ncurses_gui_th_exit(term_node); */
      }

    if (pthread_mutex_unlock(&terms->mutex) != 0) {
        thread_error("ncurses_gui_th pthread_mutex_unlock",errno);
        ncurses_gui_th_exit(term_node);
    }

    if (ncurses_i_init(my_wins, my_panels, term_node) < 0)
       ncurses_gui_th_exit(term_node);
       
    if (interfaces->list)
       iface_data = dlist_data(interfaces->list);
    else {
       ncurses_i_error_window(0,
             "Hmm... you don't have any valid interface. \
             %s is useless. Go and get a life!", PACKAGE);
       ncurses_gui_th_exit(term_node);
    }

    /* take the first valid interface */
    if (strlen(iface_data->ifname)) {
       if (ncurses_i_error_window(0,
                "Warning: interface %s selected as the default one", 
                iface_data->ifname) < 0)
          ncurses_gui_th_exit(term_node);
       if ((tmp = interfaces_enable(iface_data->ifname)) == -1) {
          if (ncurses_i_error_window(1,
                   "Unable to use interface %s!! (Maybe nonexistent?)\n\n", 
                   iface_data->ifname) < 0)
             ncurses_gui_th_exit(term_node);
       } else {
          iface = (struct interface_data *) calloc(1, sizeof(struct interface_data));
          memcpy((void *)iface, (void *)iface_data, sizeof(struct interface_data));
          term_node->used_ints->list = dlist_append(term_node->used_ints->list, iface);
       }
     } else {
          if (ncurses_i_error_window(1,
                   "Hmm... you don't have any valid interface. \
                   %s is useless. Go and get a life!", PACKAGE) < 0)
             ncurses_gui_th_exit(term_node);
     }

    ncurses_c_engine(my_wins, my_panels, term_node);

    ncurses_gui_th_exit(term_node);
}


/* 
 * GUI destroy. End
 */
void
ncurses_gui_th_exit(struct term_node *term_node)
{
   dlist_t *p;
   struct interface_data *iface_data;

   if (endwin() == ERR)
      thread_error("Error in endwin", errno);

   write_log(0, "\n ncurses_gui_th_exit start...\n");

   if (term_node)
   {
      for (p = term_node->used_ints->list; p; p = dlist_next(term_node->used_ints->list, p)) {
         iface_data = (struct interface_data *) dlist_data(p);
         interfaces_disable(iface_data->ifname);
      }

      attack_kill_th(term_node,ALL_ATTACK_THREADS);

      if (pthread_mutex_lock(&terms->mutex) != 0)
         thread_error("ncurses_gui_th pthread_mutex_lock",errno);

      term_delete_node(term_node, NOKILL_THREAD);               

      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("ncurses_gui_th pthread_mutex_unlock",errno);
   }

   write_log(0," ncurses_gui_th_exit finish...\n");   

   if (pthread_mutex_unlock(&terms->gui_th.finished) != 0)
      thread_error("ncurses_gui_th pthread_mutex_unlock",errno);
   
   terms->work_state = STOPPED;

   terms->gui_th.id = 0;
   
   pthread_exit(NULL);
}
