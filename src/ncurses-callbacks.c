/* ncurses-callbacks.c
 * Implementation for ncurses callbacks
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
"$Id: ncurses-callbacks.c 46 2007-05-08 09:13:30Z slay $";
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
#include "ncurses-callbacks.h"
#include "ncurses-interface.h"

/*
 * Refresh main window
 */
void 
ncurses_c_refresh_mwindow(u_int8_t mode, WINDOW *mwindow, u_int8_t pointer, 
        struct term_node *node)
{
   u_int8_t i, row, col, j, offset, tlv, k, position, max_len;
   char *ptrtlv;
   char timebuf[19], **values, meaningbuf[NCURSES_MWINDOW_MAX_FIELD_LENGTH+1];
   struct term_console *term_console;
   struct tm *aux;
   struct tuple_type_desc *func;
   struct commands_param *params;
   struct commands_param_extra *extra_params=NULL;
   time_t this_time;

   tlv = 0;
   max_len = 0;
   values = NULL;
   func = NULL;

   term_console = node->specific;

   params = (struct commands_param *) protocols[mode].parameters;
   
//   if (protocols[mode].extra_nparams)
      extra_params = (struct commands_param_extra *) protocols[mode].extra_parameters;

   getmaxyx(stdscr,row,col);

#ifdef CAN_RESIZE
   if (term_console->need_resize) {
      /*        if (delwin(mwindow) == ERR)
                thread_error("Error in delwin", errno);
                if ((mwindow = newwin(row-5, col, 0, 0)) == NULL) 
                thread_error("Error in newwin", errno);*/
#ifdef HAVE_NCURSES_WRESIZE
      wresize(mwindow, row-NCURSES_BWINDOW_SIZE, col);
      werase(mwindow);
#endif
      term_console->need_resize--;
//      write_log(0, "Resize mwindow con %d row y %d col y resize es %d\n", row, col, term_console->need_resize);
   }
#endif

   offset = (col > NCURSES_MIN_COLS)? (col - NCURSES_MIN_COLS) / 2 : 0;

   wattron(mwindow, COLOR_PAIR(5) | A_BOLD);
   box(mwindow,ACS_VLINE,ACS_HLINE);

   this_time = time(NULL);

   aux = localtime(&this_time);

   if (aux != NULL)
      mvwprintw(mwindow, 0, col-11, "[%02d:%02d:%02d]", aux->tm_hour, aux->tm_min,
            aux->tm_sec);

   mvwprintw(mwindow, row-NCURSES_BWINDOW_SIZE-2, 1 + offset, " Total Packets: %d ", 
         packet_stats.global_counter.total_packets);
   mvwprintw(mwindow, row-NCURSES_BWINDOW_SIZE-2, 60 + offset, " MAC Spoofing [ ] ");
   if (node->mac_spoofing)
      mvwprintw(mwindow, row-NCURSES_BWINDOW_SIZE-2, 75 + offset, "X");

   mvwprintw(mwindow, 0, 3, " %s %s by Slay & tomac - %s mode ", 
         PACKAGE, VERSION, protocols[mode].namep);
   mvwprintw(mwindow, row-NCURSES_BWINDOW_SIZE-2, 30 + offset, " %s Packets: %d ", 
         protocols[mode].namep, protocols[mode].packets);
   wattroff(mwindow, COLOR_PAIR(5) | A_BOLD);

   wattron(mwindow, A_BOLD);

   position = 1;
   for (i = 0; i < protocols[mode].nparams; i++) {
      if (params[i].mwindow) {
         mvwprintw(mwindow, 1, position + offset, params[i].ldesc);
         if (params[i].meaning)
         {
            max_len = parser_get_max_field_length(params[i].meaning);
            position += (( MAX2(max_len, strlen(params[i].ldesc)) > NCURSES_MWINDOW_MAX_FIELD_LENGTH) ? 
                  NCURSES_MWINDOW_MAX_FIELD_LENGTH : MAX2(max_len, strlen(params[i].ldesc))) + 1;
         } else
            position += (params[i].size_print > strlen(params[i].ldesc) ? params[i].size_print : strlen(params[i].ldesc)) + 1;
      }
   }

   for (i = 0; i < protocols[mode].extra_nparams; i++) {
      if (extra_params[i].mwindow) {
         mvwprintw(mwindow, 1, position + offset, extra_params[i].ldesc);
         if (extra_params[i].meaning)
         {
            max_len = parser_get_max_field_length(extra_params[i].meaning);
            position += (( MAX2(max_len, strlen(params[i].ldesc)) > NCURSES_MWINDOW_MAX_FIELD_LENGTH) ? 
                  NCURSES_MWINDOW_MAX_FIELD_LENGTH : MAX2(max_len, strlen(params[i].ldesc))) + 1;
         } else
            position += (extra_params[i].size_print > strlen(extra_params[i].ldesc) ? extra_params[i].size_print : strlen(extra_params[i].ldesc)) + 1;
      }
   }

   mvwprintw(mwindow, 1, 58 + offset, "Iface");
   mvwprintw(mwindow, 1, 64 + offset, "Last seen");

   wattroff(mwindow, A_BOLD);

   for (i=0; i < MAX_PACKET_STATS; i++)
   {
      if (protocols[mode].stats[i].header->ts.tv_sec > 0) 
      {
         if (protocols[mode].get_printable_packet)
         {
            if ((values = (*protocols[mode].get_printable_packet)(&protocols[mode].stats[i])) == NULL) 
            {
               write_log(0, "Error in get_printable_packet (mode %d)\n", mode);
               wrefresh(mwindow);
               return;
            }
         }
         else
         {
            write_log(0, "Warning: there is no get_printable_packet for protocol %d\n", mode);
            wrefresh(mwindow);
            return;
         }

         if (i == pointer)
            wattron(mwindow, COLOR_PAIR(5) | A_BOLD);

         wmove(mwindow, i+2, 1);
         whline(mwindow, ' ', COLS-2);

         position = 1;
         k = 0;

         for (j = 0; j < protocols[mode].nparams; j++)
         {
            /*write_log(0, "param es %s\n", params[j].ldesc);*/
            if ((params[j].type != FIELD_IFACE) && (params[j].type != FIELD_DEFAULT) && (params[j].type != FIELD_EXTRA))
            {
               if (params[j].mwindow)
               {
                  /*write_log(0, "values es %s\n", values[k]);*/
                  if (params[j].meaning)
                  {
                     snprintf(meaningbuf, NCURSES_MWINDOW_MAX_FIELD_LENGTH + 1, "%s", parser_get_meaning(values[k], params[j].meaning));
                     if (strlen(meaningbuf) == NCURSES_MWINDOW_MAX_FIELD_LENGTH)
                        meaningbuf[NCURSES_MWINDOW_MAX_FIELD_LENGTH-1] = '|';
                     mvwprintw(mwindow, i + 2, position + offset, "%s", meaningbuf);

                     max_len = parser_get_max_field_length(params[j].meaning);
                     position += (( MAX2(max_len, strlen(params[j].ldesc)) > NCURSES_MWINDOW_MAX_FIELD_LENGTH) ? 
                          NCURSES_MWINDOW_MAX_FIELD_LENGTH : MAX2(max_len, strlen(params[j].ldesc))) + 1;
                  } else {
                     mvwprintw(mwindow, i + 2, position + offset, "%s", values[k]);
                     position += (params[j].size_print > strlen(params[j].ldesc) ? params[j].size_print : strlen(params[j].ldesc)) + 1;
                  }
               }
               k++;
            }
         }

         if ((protocols[mode].extra_nparams > 0))
         {
            tlv = k;
            for (j = 0; j < protocols[mode].extra_nparams; j++)
            {
               if (extra_params[j].mwindow)
               {
                  mvwprintw(mwindow, i + 2, position + offset, "%*c", extra_params[j].size_print, ' ');
                  ptrtlv = values[tlv];
                  while ((ptrtlv) && (strncmp((char *)ptrtlv, extra_params[j].ldesc, strlen(extra_params[j].ldesc)) != 0))
                  {
                     //write_log(0, "joe ptr es a%sa\n", ptrtlv);
                     ptrtlv += strlen((char *)ptrtlv) + 1;
                  }

                  if (ptrtlv) 
                  {

                     ptrtlv += strlen((char *)ptrtlv) + 1;
                     //write_log(0, "ptrtlv values es %s\n", ptrtlv);
                     if (extra_params[j].meaning)
                     {
                        //snprintf(meaningbuf, NCURSES_MWINDOW_MAX_FIELD_LENGTH, "%s %s", ptrtlv, parser_get_meaning(ptrtlv, extra_params[j].meaning));
                        snprintf(meaningbuf, NCURSES_MWINDOW_MAX_FIELD_LENGTH + 1, "%s", parser_get_meaning(ptrtlv, extra_params[j].meaning));
                        if (strlen(meaningbuf) == NCURSES_MWINDOW_MAX_FIELD_LENGTH)
                           meaningbuf[NCURSES_MWINDOW_MAX_FIELD_LENGTH-1] = '|';
                        mvwprintw(mwindow, i + 2, position + offset, "%s", meaningbuf);
                        max_len = parser_get_max_field_length(extra_params[j].meaning);
                        position += (( MAX2(max_len, strlen(params[j].ldesc)) > NCURSES_MWINDOW_MAX_FIELD_LENGTH) ? 
                             NCURSES_MWINDOW_MAX_FIELD_LENGTH : MAX2(max_len, strlen(params[j].ldesc))) + 1;
                     } 
                     else
                     {
                        mvwprintw(mwindow, i + 2, position + offset, "%s", ptrtlv);
                        position += (extra_params[j].size_print > strlen(extra_params[j].ldesc) ? extra_params[j].size_print : strlen(extra_params[j].ldesc)) + 1;
                     }
                  } 
                  else
                  {
                     mvwprintw(mwindow, i + 2, position + offset, "???");
                     position += (extra_params[j].size_print > strlen(extra_params[j].ldesc) ? extra_params[j].size_print : strlen(extra_params[j].ldesc)) + 1;
                     /* position += extra_params[j].size_print; */
                  }
               }
            }
         }

         mvwprintw(mwindow, i+2, 58 + offset, "%s", protocols[mode].stats[i].iface); 
         strftime(timebuf, 19, "%d %b %H:%M:%S", localtime((time_t *)&protocols[mode].stats[i].header->ts));

         mvwprintw(mwindow, i+2, 64 + offset, "%s", timebuf);

         if (i == pointer) 
            wattroff(mwindow, COLOR_PAIR(5) | A_BOLD);

         k = 0;

         /* Reset values */
         memset((void *)values, 0, sizeof(values));

         if (values) 
         {
            while(values[k]) 
            {
               free(values[k]);
               k++;
            }
            free(values);
         }

      } /* if (protocols->tv_sec) */


   } /* for i < MAX_PACKET_STATS */

   wrefresh(mwindow);
}


/*
 * Refresh panels
 */
void 
ncurses_c_refresh(void)
{
    /* refresh the panels */
    update_panels();

    /* Show it on the screen */
    doupdate();
}


/*
 * Main engine catching keystrokes
 */
void 
ncurses_c_engine(WINDOW *my_wins[], PANEL *my_panels[], struct term_node *node)
{
   int32_t key, key_pressed, ret, max, proto_key;
   u_int8_t end, i, j, k, secs, mode, used, keys[MAX_PROTOCOLS];
   struct term_console *term_console;
   fd_set read_set, rset;
   struct timeval timeout;
   dlist_t *p;
   struct interface_data *iface_data;

   term_console = node->specific;

   for (i = 0; i < MAX_PROTOCOLS; i++)
      pointer[i] = 0;

   end = 0;

   /* default initial mode */
   mode = NCURSES_DEFAULT_MODE;

   keypad(my_wins[MAIN_SCREEN], TRUE);

   secs = 0;
   j = 0;

   timeout.tv_sec  = 0;
   timeout.tv_usec = 0;
   FD_ZERO(&read_set);
   FD_SET(fileno(stdin), &read_set);

   while (!end && !terms->gui_th.stop)
   {
      max = 0;
      FD_ZERO(&rset);
      rset = read_set;

      if ((ret = select(max + 1, &rset, NULL, NULL, &timeout)) == -1) {
         thread_error("select", errno);
         timeout.tv_sec = 0;
         timeout.tv_usec = 500000;
         return;
      }

      if (!ret) /* Timeout...*/
      {
         if (j%2) /* 1 sec!! */
         {
            j=0;
            if (secs == NCURSES_REFRESH_TIME)
            {
               ncurses_c_refresh_bwindow(mode, my_wins[SEC_SCREEN], node);
               ncurses_c_refresh_mwindow(mode, my_wins[MAIN_SCREEN], 
                     pointer[mode], node); 
               secs = 0;
            }
            else
               secs++;
         }
         else
            j++;
      }
      else
      {
         key_pressed = wgetch(my_wins[MAIN_SCREEN]);

         switch(key_pressed)
         {
            /* Help screen */
            case '?':
            case 'H':
            case 'h':
               ncurses_i_help_screen(mode, my_wins[HELP_SCREEN], 
                     my_panels[HELP_SCREEN]);
               break;

               /* Edit BPDU fields */
            case 'E':
            case 'e':
               ncurses_c_edit_bwindow(mode, my_wins[MAIN_SCREEN], my_wins[SEC_SCREEN], node);
               break;

               /* About */
            case 'A':
            case 'a':
               ncurses_i_splash_screen(my_wins[SPLASH_SCREEN],
                     my_panels[SPLASH_SCREEN]);
               break; 

               /* List Attacks */
            case 'l':
               ncurses_i_list_attacks(my_wins[LIST_ATTACKS], node);
               break;

               /* List capture files */
            case 'f':
               ncurses_i_list_filecaps(my_wins[LIST_FILECAPS], node);
               break;

            case KEY_DOWN:
               if ( (pointer[mode] < MAX_PACKET_STATS - 1) && 
                     (protocols[mode].stats[pointer[mode] + 1].header->ts.tv_sec > 0)) 
               {
                  pointer[mode]++;
                  ncurses_c_refresh_mwindow(mode, my_wins[MAIN_SCREEN], pointer[mode], node);
               }
               break;

            case KEY_UP:
               if (pointer[mode] > 0) 
               {
                  pointer[mode]--;
                  ncurses_c_refresh_mwindow(mode, my_wins[MAIN_SCREEN], pointer[mode], node);
               }
               break; 

            case 'K':
               key = ncurses_i_getconfirm(node,
                     " Confirmation before nuclear war!!",
                     "You will kill *ALL* attacks from *ALL* protocols... Are you sure?",
                     " Killing attacks from ALL protocols ");
               if (key == 'y')
                  attack_kill_th(node, ALL_ATTACK_THREADS);
               break;

            case 'c':
               interfaces_clear_stats(mode);
               wclear(my_wins[MAIN_SCREEN]);
               pointer[mode] = 0;
               ncurses_c_set_status_line(" Clearing Mode stats... ");
               break;

            case 'C':
               interfaces_clear_stats(PROTO_ALL);
               wclear(my_wins[MAIN_SCREEN]);
               memset(pointer,0,sizeof(pointer));
               ncurses_c_set_status_line(" Clearing stats... ");
               break;

            case 'd':
               if (protocols[mode].init_attribs)
                  (*protocols[mode].init_attribs)(node);
               else {
                  write_log(0, "Warning: no init_attribs for mode %d\n", mode);
               }
            break;

               /* Set MAC Spoofing on/off */
            case 'M':
                  node->mac_spoofing = !node->mac_spoofing;
            break;

               /* Clear screen */
            case KEY_CTRL_L:
               clearok(stdscr, TRUE);
               clearok(my_wins[MAIN_SCREEN], TRUE);
               clearok(my_wins[SEC_SCREEN], TRUE);
            break;

               /* ENTER. Show info about the selected item */
            case 13:
               if (protocols[mode].packets)
                   ncurses_i_show_info(mode, my_wins[MAIN_SCREEN], 
                                       pointer[mode], node);
            break;

               /* View packet */
            case 'v':
               if (protocols[mode].packets)
                   ncurses_i_view_packet(mode, my_wins[MAIN_SCREEN], 
                                         pointer[mode]);
            break;

            case 'I':
            case 'i':
               ncurses_i_ifaces_screen(node, my_wins[IFACE_SCREEN], 
                     my_panels[IFACE_SCREEN]);
            break;

               /* Save data */
            case 'S':
               if (node->pcap_file.pdumper)
               {                
                  if (ncurses_i_error_window(1,
                           "Error: pcap_file is in use at %s", 
                           node->pcap_file.name) < 0)
                     ncurses_gui_th_exit(node);
               }
               else
               {
                  char *filename = (char *)calloc(1,FILENAME_MAX+1);
                  if (filename == NULL)
                  {
                     thread_error(" ncurses_engine calloc",errno);
                     ncurses_gui_th_exit(node);
                  }
                  if (ncurses_i_getstring_window(node, 
                           " Stealing data? Tsk, tsk...",
                           filename,
                           FILENAME_MAX,
                           " Enter pcap filename for ALL protocols") < 0)
                  {
                     free(filename);
                     ncurses_gui_th_exit(node);
                  }

                  /* Take the first active interface for saving data */
                  p = interfaces->list;
                  while(p) {
                     iface_data = (struct interface_data *) dlist_data(p);
                     if (iface_data->up) {
                        if (filename[0] && interfaces_pcap_file_open(node, PROTO_ALL, filename, iface_data->ifname) < 0)
                        {
                           free(filename);
                           ncurses_gui_th_exit(node);
                        }
                        break;
                     }
                     else
                        p = dlist_next(interfaces->list, p);
                  }

                  /* No interface found*/
                  if (p == NULL)
                     ncurses_i_error_window(1, "Error: there is no active interface");

                  if (filename)
                     free(filename);
               }
            break;

            case 's':
               if (node->protocol[mode].pcap_file.pdumper)
               {                
                  if (ncurses_i_error_window(1, "Error: pcap_file is in use at %s", 
                           node->protocol[mode].pcap_file.name) < 0)
                     ncurses_gui_th_exit(node);
               }
               else
               {
                  char *filename = (char *)calloc(1,FILENAME_MAX+1);
                  if (filename == NULL)
                  {
                     thread_error(" ncurses_engine calloc",errno);
                     ncurses_gui_th_exit(node);
                  }

                  if (ncurses_i_getstring_window(node, 
                           " Stealing data? Tsk, tsk...",
                           filename,
                           FILENAME_MAX,
                           " Enter pcap filename for current protocol") < 0)
                  {
                     free(filename);
                     ncurses_gui_th_exit(node);
                  }

                  /* Take the first valid interface for saving data */
                  p = interfaces->list;
                  while(p) {
                     iface_data = (struct interface_data *) dlist_data(p);
                     if (iface_data->up) {
                        if (filename[0] && interfaces_pcap_file_open(node, mode, filename, iface_data->ifname) < 0)
                        {
                           free(filename);
                           ncurses_gui_th_exit(node);
                        }
                        break;
                     }
                     else
                        p = dlist_next(interfaces->list, p);
                  }

                  /* No interface found*/
                  if (p == NULL)
                     ncurses_i_error_window(1, "Error: there is no active interface");

                  if (filename)
                     free(filename);
               }
               break;

               /* Learn da packet */
            case 'L':
               ncurses_c_learn_packet(mode, pointer[mode], node);
               break;

               /* Display implemented attacks */
            case 'X':
            case 'x':
               ncurses_i_attack_screen(node, mode, my_wins[ATTACK_SCREEN], 
                     my_panels[ATTACK_SCREEN]);
            break;

               /* Write configuration file */
            case 'W':
            case 'w':
               for (i = 0; i < MAX_PROTOCOLS; i++)
               {
                  if (protocols[i].visible)
                     memcpy((void *)protocols[i].default_values, 
                             (void *)node->protocol[i].tmp_data, 
                             protocols[i].size);
               }
               if (strlen(tty_tmp->config_file) == 0) 
               {
                  char *filename = (char *)calloc(1,FILENAME_MAX+1);
                  if (filename == NULL)
                  {
                     thread_error(" ncurses_engine calloc",errno);
                     ncurses_gui_th_exit(node);
                  }
                  if (ncurses_i_getstring_window(node, 
                           " Save the world ",
                           filename,
                           FILENAME_MAX,
                           " Enter configuration filename ") < 0)
                  {
                     free(filename);
                     ncurses_gui_th_exit(node);
                  }
                  if (strlen(filename)!=0)
                     strncpy(tty_tmp->config_file, filename, FILENAME_MAX);
                  else
                  {
                     free(filename);
                     break;
                  }
               }
               if (parser_write_config_file(tty_tmp) < 0)
                  ncurses_i_error_window(1, "Error opening config file %s", tty_tmp->config_file);
            break;

               /* Quit (bring da noize) */
            case 'Q':
            case 'q':
               end = 1;
            break;

            case KEY_F(1):
            case KEY_F(2):
            case KEY_F(3): 
            case KEY_F(4): 
            case KEY_F(5): 
            case KEY_F(6):
            case KEY_F(7):
            case KEY_F(8):
            case KEY_F(9):
            case KEY_F(10):
            case KEY_F(11):
            case KEY_F(12):
               for(used=0,k=0,i=0;i<MAX_PROTOCOLS;i++)
               {
                  if (protocols[i].visible)
                  {
                     keys[k]=i;
                     k++; used++;
                  }
               }
               if ( (key_pressed - KEY_F0 - 1) < used)
               {
                   proto_key = keys[key_pressed - KEY_F0 - 1];
                   if (mode != proto_key) 
                   {
                       mode = proto_key;
                       wclear(my_wins[MAIN_SCREEN]);
                       wclear(my_wins[SEC_SCREEN]);
                   }
               }
            break;

            case 'g':
               if ((ret = ncurses_i_get_mode(mode, my_wins[MAIN_SCREEN])) >= 0) {
                  mode = ret;
                  wclear(my_wins[MAIN_SCREEN]);
                  wclear(my_wins[SEC_SCREEN]);
               }
               break;
#ifdef KEY_RESIZE
            case KEY_RESIZE:
               ncurses_c_term_resize(node);
               break;
#endif
            case ERR:
               thread_error("Error in wgetch", errno);
               ncurses_gui_th_exit(NULL);
               break;

            default:
               break;
         }
      }

      ncurses_c_refresh_bwindow(mode, my_wins[SEC_SCREEN], node);
      ncurses_c_refresh_mwindow(mode, my_wins[MAIN_SCREEN], pointer[mode], node); 

      timeout.tv_sec = 0;
      timeout.tv_usec = 500000;
   } /* while */
}


/*
 * Refresh the fields window (Bottom window)
 */
void 
ncurses_c_refresh_bwindow(u_int8_t mode, WINDOW *bwindow, struct term_node *node)
{
   int32_t offset, row, col, position, lastposition;
   struct term_console *term_console;
   u_int8_t **store_values = NULL;
   u_int8_t i, k, lastusedrow;
   struct commands_param *params;

   term_console = node->specific;

   getmaxyx(stdscr,row,col);

#ifdef CAN_RESIZE
   if (term_console->need_resize) {
      /*        if (delwin(bwindow) == ERR)
                thread_error("Error in delwin", errno);
                if ((bwindow = newwin(5, col, row-5, 0)) == NULL)
                thread_error("Error in newwin", errno);*/
#ifdef HAVE_NCURSES_WRESIZE
      wresize(bwindow, NCURSES_BWINDOW_SIZE, col);
      mvwin(bwindow, row-NCURSES_BWINDOW_SIZE, 0);
      werase(bwindow); 
#endif
      term_console->need_resize--;
      //write_log(0, "Resize bwindow con %d row y %d col y resize es %d\n", row, col, term_console->need_resize);
   }
#endif

   offset = (col > NCURSES_MIN_COLS)? (col - NCURSES_MIN_COLS) / 2 : 0;

   if (protocols[mode].get_printable_store) {
      if ((store_values = (u_int8_t **)(*protocols[mode].get_printable_store)(node)) == NULL) {
         write_log(0, "Error in get_printable_store (mode %d)\n", mode);
         return;
      }
   }
   else {
      write_log(0, "Warning: there is no get_printable_store for protocol %d\n", mode);
      return;
   }

   wattron(bwindow, COLOR_PAIR(2));

   box(bwindow,ACS_VLINE,ACS_HLINE);
   mvwprintw(bwindow, 0, 3, " %s Fields ", protocols[mode].namep);

   params = (struct commands_param *) protocols[mode].parameters;

   lastusedrow = 1;
   lastposition = 0;
   /* We have 5 rows in the bwindow */
   for (row = 1; row <= 5; row++) 
   {
      position = 2;
      k = 0;
      for (i = 0; i < protocols[mode].nparams; i++)
      {
         if ((params[i].type != FIELD_IFACE) && (params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_EXTRA))
         {
            if (params[i].row == row)
            {
               lastusedrow = row;
               wattron(bwindow, COLOR_PAIR(2));
               mvwprintw(bwindow, row, position + offset, "%s", params[i].ldesc);
               position += strlen(params[i].ldesc) + 1;
               wattroff(bwindow, COLOR_PAIR(2));
               mvwprintw(bwindow, row, position + offset, "%s", store_values[k]);
               position += params[i].size_print + 1;
            }
            k++;
         }
      }

      /* No more rows */
      if (row != lastusedrow)
         break;

      lastposition = position;
   }

   /* Extra parameters */
   if (protocols[mode].extra_nparams > 0)
   {
      wattron(bwindow, COLOR_PAIR(2));
      mvwprintw(bwindow, lastusedrow, lastposition + offset, "Extra");
   }

   i = 0;

   while (store_values[i]) {
      free(store_values[i]);
      i++;
   }

   if (store_values)
      free(store_values);

   wrefresh(bwindow);
}


/*
 * Edit BPDU Fields
 */
void 
ncurses_c_edit_bwindow(u_int8_t mode, WINDOW *mwindow, WINDOW *bwindow, struct term_node *node)
{
   u_int8_t i, state;
   int32_t key_pressed, result;
   int8_t end_edit;
   u_int32_t y, x, col, row, offset, initial, start;
   struct commands_param *params;
   char buffer[1024], old_value;

   initial = 0;
   state = 0;
   start = 0;
   ncurses_c_set_status_line(" Edit those nasty fields; press 'x' for Extra values ");

   /* We want a BIG cursor */
   curs_set(1);

   getmaxyx(stdscr, row, col);
   offset = (col > NCURSES_MIN_COLS)? (col - NCURSES_MIN_COLS) / 2 : 0;

   params = protocols[mode].parameters;

   for (i = 0; i < protocols[mode].nparams; i++) 
   {
      if (params[i].row == 1) 
      {
         initial = strlen(params[i].ldesc) + offset + 2 + 1;
         start = initial;
         state = i;
         break;
      }
   }

   keypad(bwindow, TRUE);
   wmove(bwindow, 1, initial);
   wrefresh(bwindow);

   wtimeout(bwindow,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

   end_edit = 0;

   while (!end_edit && !terms->gui_th.stop)
   {
      do
      {
         key_pressed = wgetch(bwindow);
      } while ( (key_pressed == ERR) && !terms->gui_th.stop);

      if (terms->gui_th.stop)
         break;


      getyx(bwindow, y, x);
      switch(key_pressed)
      {
         case 27: /* ESC */
         case 13: /* ENTER */
            end_edit = 1;
            break;

         case KEY_UP:
            if (ncurses_c_north(mode, offset, &y, &x, &state, &start) == 0) {
               wmove(bwindow, y, x);
            }
         break;
         case KEY_DOWN:
            if (ncurses_c_south(mode, offset, &y, &x, &state, &start) == 0) {
               wmove(bwindow, y, x);
            }
         break;
         case KEY_RIGHT:
            if (ncurses_c_east(mode, offset, &y, &x, &state, &start) == 0) {
               wmove(bwindow, y, x);
            }
         break;
         case KEY_LEFT:
            if (ncurses_c_west(mode, offset, &y, &x, &state, &start) == 0) {
               wmove(bwindow, y, x);
            }
         break;

         case 'x':
            if (protocols[mode].extra_parameters > 0)
                ncurses_i_edit_tlv(node, mode);
         break;
         case 9: /* TAB */
            if (params[state].meaning)
            {
               curs_set(0);
               if ((result = ncurses_i_popup_window(bwindow, params[state].meaning, state)) != ERR) 
               {
                  snprintf(buffer, 1024, "%d", result);
                  parser_filter_param(params[state].type, node->protocol[mode].commands_param[state],
                     buffer, params[state].size_print, params[state].size);
               }
               curs_set(1);
               ncurses_c_refresh_bwindow(mode, bwindow, node);    
               /* fix to come back to the position */
               wmove(bwindow, y, x);
            }
            break;

         default:
            if ((params[state].type == FIELD_HEX) || (params[state].type == FIELD_MAC)
                  || (params[state].type == FIELD_BRIDGEID) || (params[state].type == FIELD_BYTES)) 
            {
               if (!isxdigit(key_pressed))
                  /* only hexadecimal characters are allowed */
                  break;
            } else if ((params[state].type == FIELD_DEC) || (params[state].type == FIELD_IP)) {
               if (!isdigit(key_pressed))
                  break;
            } else if (params[state].type == FIELD_STR) {
               if (!isascii(key_pressed))
                  break;
            } else /* FIELD_NONE */
               break;

            old_value = mvwinch(bwindow, y, x);
            mvwaddch(bwindow, y, x, toupper(key_pressed) | A_BOLD);
            memset((void *)&buffer, 0, 1024);
            mvwinnstr(bwindow, y, start, buffer, params[state].size_print);
            if (parser_filter_param(params[state].type, node->protocol[mode].commands_param[state],
                     buffer, params[state].size_print, params[state].size) < 0) {
               mvwaddch(bwindow, y, x, old_value);
               wmove(bwindow, y ,x);
            } else {
               if (ncurses_c_east(mode, offset, &y, &x, &state, &start) == 0) {
                  wmove(bwindow, y, x);
               }
            }

            break;
      }

      if (params[state].meaning)
      {
         ncurses_c_set_status_line(" Press TAB for available values ");
      }  else
         ncurses_c_set_status_line("");
   }

   keypad(bwindow, FALSE);

   /* Hide the cursor */
   curs_set(0);

   ncurses_c_set_status_line(" Edit mode is over ");
}


int8_t
ncurses_c_learn_packet(u_int8_t mode, u_int8_t pointer, struct term_node *node)
{
    ncurses_c_set_status_line(" Packet learnt. Ouch! ");

    if (protocols[mode].load_values)
        return (*protocols[mode].load_values)((struct pcap_data *)&protocols[mode].stats[pointer], 
                            node->protocol[mode].tmp_data);
    else 
    {
        write_log(0, "Warning: no load_values in protocol %d\n", mode);
        return -1;
    }
}


int8_t
ncurses_c_set_status_line(char *msg)
{
    u_int8_t row, col, size;

    getmaxyx(stdscr, row, col);
    size = strlen(msg);

    /* Clear the last status line */
    werase(info_window);

        //wmove(info_window, 0, 1);
    if (size) {
        wattron(info_window, COLOR_PAIR(3));

        if (size > row)
            mvwaddnstr(info_window, 0, 0, msg, row - 1);
        else 
            mvwaddnstr(info_window, 0, 0, msg, size);
    } 

    /* Nice */
    /* wmove(info_window, 0, 1);*/
    wrefresh(info_window);

    return 0;
}


int8_t
ncurses_c_term_resize(struct term_node *node)
{
#ifdef CAN_RESIZE
    struct winsize size;
    struct term_console *term_console;

    term_console = node->specific;

    if (ioctl(fileno(stdout), TIOCGWINSZ, &size) == 0) {
        if ((size.ws_row < NCURSES_MIN_ROWS) || (size.ws_col < NCURSES_MIN_COLS))
            ncurses_i_error_window(1, "Hmmm.. %d rows and %d cols are \
                    not supported for a proper display!!!!. You need at least \
                    %d rows and %d cols.", size.ws_row, size.ws_col, 
                    NCURSES_MIN_ROWS, NCURSES_MIN_COLS);
        else {
#ifdef HAVE_NCURSES_RESIZETERM
            resizeterm(size.ws_row, size.ws_col);
#else
            resize_term(size.ws_row, size.ws_col);
#endif
            resize_term(size.ws_row, size.ws_col);
            wrefresh(curscr);   /* Linux needs this */
            term_console->need_resize = 2;

        }
    } else
        thread_error("Error in ioctl", errno);

#endif

    return 0;
}


/* Functions needed for editing the bwindow values */
int8_t
ncurses_c_north(u_int8_t mode, u_int32_t offset, u_int32_t *row, u_int32_t *pos, u_int8_t *state, u_int32_t *start)
{
   struct commands_param *params;
   u_int8_t position, i, last_state;
   u_int32_t last;

   last = 0;
   last_state = 0;
   params = (struct commands_param *) protocols[mode].parameters;

   if (*row == 1)
      return -1;

   /* Up by one */
   (*row)--;

   position = offset + 2;
   for (i = 0; i < protocols[mode].nparams; i++)
   {
      if ((params[i].type != FIELD_IFACE) && (params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_EXTRA))
      {
         if (params[i].row == *row)
         {
            position += strlen(params[i].ldesc) + 1;
            *start = position;
            last = position;
            last_state = i;
            if (*pos < (position + params[i].size_print)) {
               *pos = position;
               *state = i;
               return 0;
            }
            position += params[i].size_print + 1;
         }
      }
   }

   *pos = last;
   *state = last_state;

   return 0;
}


int8_t
ncurses_c_south(u_int8_t mode, u_int32_t offset, u_int32_t *row, u_int32_t *pos, u_int8_t *state, u_int32_t *start)
{
   struct commands_param *params;
   u_int8_t position, i, last_valid;

   params = (struct commands_param *) protocols[mode].parameters;

   if (*row == 5)
      return -1;

   /* Down by one */
   (*row)++;

   last_valid = 0;
   position = offset + 2;
   for (i = 0; i < protocols[mode].nparams; i++)
   {
      if ((params[i].type != FIELD_IFACE) && (params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_EXTRA))
      {
         if (params[i].row == *row)
         {
            position += strlen(params[i].ldesc) + 1;
            *start = position;
            if (*pos < (position + params[i].size_print)) {
               *pos = position;
               *state = i;
               return 0;
            }
            last_valid = i;
            position += params[i].size_print + 1;
         }
      }
   }

   /* Are there rows in the next row? */
   if (position == (offset + 2)) 
   {
      (*row)--;
      return -1;
   }

   *pos = position - params[last_valid].size_print - 1;
   *state = last_valid;

   return 0;
}


int8_t
ncurses_c_east(u_int8_t mode, u_int32_t offset, u_int32_t *row, u_int32_t *pos, u_int8_t *state, u_int32_t *start)
{
   struct commands_param *params;
   u_int8_t position, i, next_state;

   next_state = 0;
   params = (struct commands_param *) protocols[mode].parameters;

   position = offset + 2;
   for (i = 0; i < protocols[mode].nparams; i++)
   {
      if ((params[i].type != FIELD_IFACE) && (params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_EXTRA))
      {
         if (params[i].row == *row)
         {
            position += strlen(params[i].ldesc) + 1;
            *start = position;
            if (next_state)
            {
               (*pos) = position;
               *state = i;
               return 0;
            }
            if ( (position < ((*pos) + 1) && (((*pos) + 1)) < (position + params[i].size_print))) {
               (*pos)++;
               if ((params[i].type ==FIELD_MAC) && (((*pos) - position + 1) % 3 == 0))
                  (*pos)++;
               else if ((params[i].type ==FIELD_BRIDGEID) && (((*pos) - position + 1) == 5))
                  (*pos)++;
               else if ((params[i].type ==FIELD_IP) && (((*pos) - position + 1) % 4 == 0))
                  (*pos)++;
               *state = i;
               return 0;
            }
            position += params[i].size_print + 1;

            if ( (*pos + 1) == (position - 1))
            {
               next_state = 1;
            }
         }
      }
   }

   return 0;
}


int8_t
ncurses_c_west(u_int8_t mode, u_int32_t offset, u_int32_t *row, u_int32_t *pos, u_int8_t *state, u_int32_t *start)
{
   struct commands_param *params;
   u_int8_t position, i, prev_state;
   u_int32_t prev_pos;

   prev_state = 0;
   prev_pos = 0;
   params = (struct commands_param *) protocols[mode].parameters;

   position = offset + 2;
   for (i = 0; i < protocols[mode].nparams; i++)
   {
      if ((params[i].type != FIELD_IFACE) && (params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_EXTRA))
      {
         if (params[i].row == *row)
         {
            position += strlen(params[i].ldesc) + 1;
            *start = position;

            if ( (*pos == position) && (prev_pos > 0))
            {
               *pos = prev_pos;
               *state = prev_state;
            }
              
            if ( (position <= ((*pos) - 1) && (((*pos) - 1)) < (position + params[i].size_print))) 
            {
               (*pos)--;
               if ((params[i].type ==FIELD_MAC) && (((*pos) - position + 1) % 3 == 0))
                  (*pos)--;
               else if ((params[i].type ==FIELD_BRIDGEID) && (((*pos) - position + 1) == 5))
                  (*pos)--;
               else if ((params[i].type ==FIELD_IP) && (((*pos) - position + 1) % 4 == 0))
                  (*pos)--;
               *state = i;
               return 0;
            }
            position += params[i].size_print + 1;
            prev_pos = position - 2;
            prev_state = i;
         }
      }
   }

   return 0;
}
