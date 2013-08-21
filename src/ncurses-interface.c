/* ncurses_interface.c
 * Implementation for ncurses interfaces
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
"$Id: ncurses-interface.c 46 2007-05-08 09:13:30Z slay $";
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

#include "ncurses-interface.h"
#include "ncurses-callbacks.h"


/*
 * Ncurses init
 */
int8_t
ncurses_i_init(WINDOW *my_wins[], PANEL *my_panels[], struct term_node *node)
{
   int32_t row, col;

   initscr();

   if (has_colors() == FALSE)
      write_log(0, " Warning: your terminal does not support color\n");
   else
      start_color();

   cbreak();
   nonl();
   noecho();

   init_pair(1, COLOR_RED, COLOR_BLACK);
   init_pair(2, COLOR_GREEN, COLOR_BLACK);
   init_pair(3, COLOR_BLUE, COLOR_BLACK);
   init_pair(4, COLOR_CYAN, COLOR_BLACK);
   init_pair(5, COLOR_YELLOW, COLOR_BLACK);
   init_pair(6, COLOR_BLACK, COLOR_BLUE);

   getmaxyx(stdscr,row,col);

   /* minimum rows & columns to display a proper GUI */
   if ((col < NCURSES_MIN_COLS) || (row < NCURSES_MIN_ROWS))
   {
      write_log(0, " Error: I need at least %d rows and %d columns \
            for a proper display!!\n", NCURSES_MIN_ROWS,
            NCURSES_MIN_COLS);

      printw(" Error: I need at least %d rows and %d columns for a proper display!!\n", 
            NCURSES_MIN_ROWS, NCURSES_MIN_COLS);
      printw("        I can't work with only %d rows and %d columns, who do you think I am?\n",
            row, col);
      printw("        Get a bigger window, press a key, and rerun yersinia :)");
      refresh();
      getch();
      return -1;
   }

   /* main window */
   my_wins[MAIN_SCREEN] = newwin(row- NCURSES_BWINDOW_SIZE - 1, col, 0, 0);
   /* secondary window */
   my_wins[SEC_SCREEN] = newwin(NCURSES_BWINDOW_SIZE, col, row-NCURSES_BWINDOW_SIZE, 0);

   /* Create windows for the panels */
   my_wins[LIST_FILECAPS] = newwin(20, 60, (row-20)/2, (col-60)/2);
   my_wins[LIST_ATTACKS] = newwin(20, 60, (row-20)/2, (col-60)/2);
   my_wins[IFACE_SCREEN] = newwin(10, 50, (row-10)/2, (col-50)/2);
   my_wins[ATTACK_SCREEN] = newwin(15, 50, (row-15)/2, (col-50)/2);
   /*    my_wins[INFO_SCREEN] = newwin(1, col, NCURSES_BWINDOW_SIZE - 1, 0);*/
   info_window = newwin(1, col, row - NCURSES_BWINDOW_SIZE - 1, 0);
   leaveok(info_window, TRUE);
   my_wins[HELP_SCREEN] = newwin(23, 42, (row-23)/2, (col-41)/2);
   my_wins[SPLASH_SCREEN] = newwin(19, 80, (row-19)/2, (col-80)/2);

   /* main window */
   my_panels[MAIN_SCREEN] = new_panel(my_wins[MAIN_SCREEN]);
   /* secondary window */
   my_panels[SEC_SCREEN] = new_panel(my_wins[SEC_SCREEN]);

   /* Attach a panel to each window */     /* Order is bottom up */
   my_panels[LIST_FILECAPS] = new_panel(my_wins[LIST_FILECAPS]); /* Push 0, order: stdscr-0 */
   my_panels[LIST_ATTACKS] = new_panel(my_wins[LIST_ATTACKS]);   /* Push 0, order: stdscr-0 */
   my_panels[IFACE_SCREEN] = new_panel(my_wins[IFACE_SCREEN]);   /* Push 0, order: stdscr-0 */
   my_panels[ATTACK_SCREEN] = new_panel(my_wins[ATTACK_SCREEN]); /* Push 0, order: stdscr-0 */
   /*    my_panels[INFO_SCREEN] = new_panel(my_wins[INFO_SCREEN]);   / Push 0, order: stdscr-0 /
         info_panel = new_panel(my_wins[INFO_SCREEN]);    Push 0, order: stdscr-0 */
   my_panels[HELP_SCREEN] = new_panel(my_wins[HELP_SCREEN]);   /* Push 2, order: stdscr-2 */
   my_panels[SPLASH_SCREEN] = new_panel(my_wins[SPLASH_SCREEN]);

   curs_set(0);

   if (tty_tmp->splash != 0)
   {
      ncurses_i_splash_screen(my_wins[SPLASH_SCREEN],NULL);
      show_panel(my_panels[SPLASH_SCREEN]);
      ncurses_c_refresh();

      /* Hmmm propaganda... */
      thread_usleep(900000);

      hide_panel(my_panels[SPLASH_SCREEN]);

      ncurses_c_refresh();
   }

   ncurses_c_refresh_mwindow(NCURSES_DEFAULT_MODE, my_wins[MAIN_SCREEN], 0, node);
   ncurses_c_refresh_bwindow(NCURSES_DEFAULT_MODE, my_wins[SEC_SCREEN], node);

   return 0;
}


/*
 * About panel
 */
void 
ncurses_i_splash_screen(WINDOW *splash_screen, PANEL *splash_panel)
{
   int32_t row, col, y, x;

   /* Check that the window is centered */
   getmaxyx(stdscr, row, col);
   getyx(splash_screen, y, x);
   if ((row - 19 != y) || (col - 80 != x))
      mvwin(splash_screen, (row - 19)/2, (col - 80)/2);

   wclear(splash_screen);

   wattron(splash_screen, COLOR_PAIR(3));
   box(splash_screen, 0, 0);
   mvwprintw(splash_screen, 1, 2, "    #²##²²#");
   mvwprintw(splash_screen, 2, 2, "   ²#°°°²²#²²");
   mvwprintw(splash_screen, 3, 2, " #²²²°###°²#²²");
   mvwprintw(splash_screen, 4, 2, "²²°²°#   #²°°²²²#");
   mvwprintw(splash_screen, 5, 2, "°²°°#      #²²°²²#");
   mvwprintw(splash_screen, 6, 2, "²°²°#       #°°²°²²");
   mvwprintw(splash_screen, 7, 2, "²²°°²#        #°²##²²²");                                                         
   mvwprintw(splash_screen, 8, 2, "#²²²°#         ##°²°##²²²");
   mvwprintw(splash_screen, 9, 2, " ²²²°²##          #°°²²°²²");
   mvwprintw(splash_screen,10, 2, " ²##°°²°#            #°²²#²²");
   mvwprintw(splash_screen,11, 2, "  #²²#²°°#             #²°°²²#");
   mvwprintw(splash_screen,12, 2, "     ²²#²°#              #°²°²#");
   mvwprintw(splash_screen,13, 2, "      #²°²²##            ###²#²");
   mvwprintw(splash_screen,14, 2, "       #²²°°²##          ##²°##");
   mvwprintw(splash_screen,15, 2, "         ²#²°²²°#        #²°#²²");
   mvwprintw(splash_screen,16, 2, "         ²#²²#°²°##### ##°²²²²");
   mvwprintw(splash_screen,17, 2, "             ²²#°°²²²°°²°°#²²");
   wattroff(splash_screen, COLOR_PAIR(3));

   mvwprintw(splash_screen, 4, 8, "±²±");
   mvwprintw(splash_screen, 5, 7, "±²±²²±");
   mvwprintw(splash_screen, 6, 7, "±²±±²²±");
   mvwprintw(splash_screen, 7, 8, "²²±²²±²±");                                                         
   mvwprintw(splash_screen, 8, 8, "±²²²±±²²±");
   mvwprintw(splash_screen, 9,10, "±²²²²²²²²±");
   mvwprintw(splash_screen,10,11, "±²²±±±²²²²²±");
   mvwprintw(splash_screen,11,12, "±²²²±±²²²²²²±");
   mvwprintw(splash_screen,12,13, "±±²²±±±±±±²²²±");
   mvwprintw(splash_screen,13,15, "±±±²²±±±±²²²");
   mvwprintw(splash_screen,14,17, "±±±²²²±²²²");
   mvwprintw(splash_screen,15,19, "±±±²²²²±");
   mvwprintw(splash_screen,16,24, "±");

   wattron(splash_screen, A_BOLD);
   mvwprintw(splash_screen, 2, 17, "Chaos Internetwork Operating System Software");
   mvwprintw(splash_screen, 3, 17, "%s (tm) Software (%s), Version %s, RELEASE SOFTWARE", 
         PACKAGE, INFO_PLATFORM, VERSION);
   mvwprintw(splash_screen, 4, 21, "Copyright (c) 2004-2007 by tomac & Slay, Inc.");
   mvwprintw(splash_screen, 5, 22, "Compiled %s by someone", INFO_DATE);
   if ( uptime < 60 )
      mvwprintw(splash_screen, 6, 23, "%s uptime is %02lu seconds", PACKAGE, uptime);
   else
   {
      if ( uptime < 3600 )
         mvwprintw(splash_screen, 6, 23, "%s uptime is %02lu minutes, %02lu seconds",
               PACKAGE, uptime / 60, uptime % 60);
      else
      {
         if ( uptime < (3600*24) )
         {
            mvwprintw(splash_screen, 6, 23, "%s uptime is %02lu hours, %02lu minutes, \
                  %02lu seconds", PACKAGE, uptime / 3600, (uptime % 3600) / 60, uptime % 60);
         }
         else
            mvwprintw(splash_screen, 6, 23, "%s uptime is %02lu days, %02lu hours, \
                  %02lu minutes, %02lu seconds", PACKAGE, uptime / (3600*24), 
                  (uptime % (3600*24)) / 3600, (uptime % 3600) / 60, uptime % 60);
      }
   }
   mvwprintw(splash_screen, 8, 29, "Running Multithreading Image on"); 
   mvwprintw(splash_screen, 9, 30, "%s %s supporting:", INFO_KERN, INFO_KERN_VER);
   mvwprintw(splash_screen, 11, 40, "%02d console terminal(s)", MAX_CON);
   mvwprintw(splash_screen, 12, 40, "%02d tty terminal(s)", MAX_TTY);
   mvwprintw(splash_screen, 13, 40, "%02d vty terminal(s)", MAX_VTY);
   wattron(splash_screen, A_BOLD | A_BLINK);
   wattroff(splash_screen, A_BOLD | A_BLINK);

   if (splash_panel)
   {
      wtimeout(splash_screen, NCURSES_KEY_TIMEOUT);
      while ((wgetch(splash_screen)==ERR) && !terms->gui_th.stop);
      hide_panel(splash_panel);
   }
}


/* 
 * Help panel
 */
void 
ncurses_i_help_screen(u_int8_t mode, WINDOW *help_screen, PANEL *help_panel)
{
   int32_t row, col, y, x;

   ncurses_c_set_status_line(" This is the help screen. ");

   /* Check that the window is centered */
   getmaxyx(stdscr, row, col);
   getyx(help_screen, y, x);
   if ((row - 24 != y) || (col - 41 != x))
      mvwin(help_screen, (row - 24)/2, (col - 41)/2);

   wattron(help_screen, COLOR_PAIR(2));
   box(help_screen, 0, 0);

   /* common help for all modes */
   mvwprintw(help_screen, 0, 13, " Available commands ");
   mvwprintw(help_screen, 1, 2, "h");
   mvwprintw(help_screen, 2, 2, "x");
   mvwprintw(help_screen, 3, 2, "i");
   mvwprintw(help_screen, 4, 2, "ENTER");
   mvwprintw(help_screen, 5, 2, "v");
   mvwprintw(help_screen, 6, 2, "d");
   mvwprintw(help_screen, 7, 2, "e");
   mvwprintw(help_screen, 8, 2, "f");
   mvwprintw(help_screen, 9, 2, "s");
   mvwprintw(help_screen, 10, 2, "S");
   mvwprintw(help_screen, 11, 2, "L");
   mvwprintw(help_screen, 12, 2, "M");
   mvwprintw(help_screen, 13, 2, "l");
   mvwprintw(help_screen, 14, 2, "K");
   mvwprintw(help_screen, 15, 2, "c");
   mvwprintw(help_screen, 16, 2, "C");
   mvwprintw(help_screen, 17, 2, "g");
   mvwprintw(help_screen, 18, 2, "Ctrl-L");
   mvwprintw(help_screen, 19, 2, "w");
   mvwprintw(help_screen, 20, 2, "a");
   mvwprintw(help_screen, 21, 2, "q");
   wattroff(help_screen, COLOR_PAIR(2));

   mvwprintw(help_screen, 1, 9, "Help screen");
   mvwprintw(help_screen, 2, 9, "eXecute attack");
   mvwprintw(help_screen, 3, 9, "edit Interfaces");
   mvwprintw(help_screen, 4, 9, "information about selected item");
   mvwprintw(help_screen, 5, 9, "View hex packet dump");
   mvwprintw(help_screen, 6, 9, "load protocol Default values");
   mvwprintw(help_screen, 7, 9, "Edit packet fields");
   mvwprintw(help_screen, 8, 9, "list capture Files");
   mvwprintw(help_screen, 9, 9, "Save packets from protocol");
   mvwprintw(help_screen, 10, 9, "Save packets from all protocols");
   mvwprintw(help_screen, 11, 9, "Learn packet from network");
   mvwprintw(help_screen, 12, 9, "set Mac spoofing on/off");
   mvwprintw(help_screen, 13, 9, "List running attacks");
   mvwprintw(help_screen, 14, 9, "Kill all running attacks");
   mvwprintw(help_screen, 15, 9, "Clear current protocol stats");
   mvwprintw(help_screen, 16, 9, "Clear all protocols stats");
   mvwprintw(help_screen, 17, 9, "Go to other protocol screen");
   mvwprintw(help_screen, 18, 9, "redraw screen");
   mvwprintw(help_screen, 19, 9, "Write configuration file");
   mvwprintw(help_screen, 20, 9, "About this proggie");
   mvwprintw(help_screen, 21, 9, "Quit (bring da noize)");

   wtimeout(help_screen,NCURSES_KEY_TIMEOUT);

   while ( (wgetch(help_screen)==ERR) && !terms->gui_th.stop);

   hide_panel(help_panel);

   ncurses_c_set_status_line("");
}


/* 
 * Attack information panel
 */
void 
ncurses_i_attack_screen(struct term_node *node, u_int8_t mode, 
        WINDOW *attack_screen, PANEL *attack_panel)
{
   int32_t i, key_pressed=0, j, row, col, y, x;
   u_int8_t field;
   int8_t ret;
   struct attack_param *attack_param = NULL;
   struct attack *theattack = NULL;

   ncurses_c_set_status_line(" Those strange attacks... ");

   /* Check that the window is centered */
   getmaxyx(stdscr, row, col);
   getyx(attack_screen, y, x);
   if ((row - 15 != y) || (col - 50 != x))
      mvwin(attack_screen, (row - 15)/2, (col - 50)/2);

   if (protocols[mode].attacks)
      theattack = protocols[mode].attacks;
   else {
      write_log(0, "Warning: no attacks for mode %d\n", mode);
      return;
   }

   i = 0;
   wclear(attack_screen);
   wattron(attack_screen, COLOR_PAIR(1));
   box(attack_screen, 0, 0);
   mvwprintw(attack_screen, 0, 18, " Attack Panel ");
   mvwprintw(attack_screen, 14, 5, " Select attack to launch ('q' to quit) ");
   mvwprintw(attack_screen, 1, 2, "No   DoS   Description");
   wattroff(attack_screen, COLOR_PAIR(1));

   while(theattack[i].s != NULL) 
   {
      mvwprintw(attack_screen, i+2, 2, "%d", i);
      mvwprintw(attack_screen, i+2, 7, "%c", (theattack[i].type == DOS) ? 'X' : ' ');
      mvwprintw(attack_screen, i+2, 13, "%s", theattack[i].s);
      i++;
   }

   wtimeout(attack_screen,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

   while ( (key_pressed !='Q') && (key_pressed != 'q') && !terms->gui_th.stop)
   {

      key_pressed = wgetch(attack_screen);
      switch (key_pressed) {
         case 'Q':
         case 'q':
            break;
         case '0':
         case '1':
         case '2':
         case '3':
         case '4':
         case '5':
         case '6':
         case '7':
         case '8':
         case '9':
            j = key_pressed - 48;
            if (j < i) 
            { /* does the attack exist? */

               if (theattack[j].nparams) /* Do we need parameters for attack? */
               {
                  if ((attack_param = calloc(1,
                              (sizeof(struct attack_param) * theattack[j].nparams))) == NULL)
                  {
                     thread_error(" ncurses_i_attack_screen attack_param calloc",errno);
                     key_pressed='Q';
                     break;
                  }
                  memcpy( attack_param, (void *)(theattack[j].param),
                        sizeof(struct attack_param) * theattack[j].nparams);
                  if (attack_init_params(node, attack_param, theattack[j].nparams) < 0)
                  {
                     free(attack_param);
                     key_pressed='Q';
                     break;
                  }

                  /* Hide the attack panel */
                  hide_panel(attack_panel);

                  /* Now we can ask for parameters... */
                  ncurses_i_get_printable_store(attack_param, theattack[j].nparams);

                  do {
                     if (ncurses_i_attack_get_params(attack_param, 
                              theattack[j].nparams) < 0) /* Q pressed */
                     {
                        attack_free_params(attack_param, theattack[j].nparams);
                        free(attack_param);
                        key_pressed='Q';
                        break;
                     }
                     ret = attack_filter_all_params(attack_param,theattack[j].nparams, &field);
                     if ( ret == -1) /* Error on data...*/
                     {
                        ncurses_i_error_window(1,
                              "Bad data on field '%s'!!",
                              attack_param[field].desc);
                     }
                  } while(ret==-1);

                  if (key_pressed == 'Q')
                  {
                     i = 0;
                     wclear(attack_screen);
                     wattron(attack_screen, COLOR_PAIR(1));
                     box(attack_screen, 0, 0);
                     mvwprintw(attack_screen, 0, 20, " Attack Panel ");
                     mvwprintw(attack_screen, 14, 5, " Select attack to launch ('q' to quit) ");
                     mvwprintw(attack_screen, 1, 2, "No   DoS   Description");
                     wattroff(attack_screen, COLOR_PAIR(1));

                     while(theattack[i].s != NULL) 
                     {
                        mvwprintw(attack_screen, i+2, 2, "%d", i);
                        mvwprintw(attack_screen, i+2, 7, "%c", (theattack[i].type == DOS) ? 'X' : ' ');
                        mvwprintw(attack_screen, i+2, 13, "%s", theattack[i].s);
                        i++;
                     }

                     key_pressed = 0;
                     continue;
                  }
               }

               wrefresh(attack_screen);
               show_panel(attack_panel);
               ncurses_c_refresh();

               if (attack_launch(node, mode, j, attack_param, theattack[j].nparams) < 0)
                  write_log(0, "Error launching attack %d", j);

               key_pressed='Q';
            }
            break;
      }
   }

   hide_panel(attack_panel);

   ncurses_c_set_status_line("");
}


/* 
 * Set interfaces panel
 */
void 
ncurses_i_ifaces_screen(struct term_node *node, WINDOW *ifaces_window, 
        PANEL *ifaces_panel)
{
   u_int8_t end, change;
   int32_t i, key_pressed, j;
   u_int8_t row, col, y, x;
   dlist_t *p;
   struct interface_data *iface_data, *iface_new;
   void *found;

   end = 0;
   change = 1;

   ncurses_c_set_status_line(" Interfaces to the world ");

   /* Check that the window is centered */
   getmaxyx(stdscr, row, col);
   getyx(ifaces_window, y, x);
   if ((row - 10 != y) || (col - 50 != x))
      mvwin(ifaces_window, (row - 10)/2, (col - 50)/2);

   wtimeout(ifaces_window, NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

   while(!end && !terms->gui_th.stop) 
   {
      i = 0;
      if (change) {
         wclear(ifaces_window);
         wattron(ifaces_window, COLOR_PAIR(4));
         box(ifaces_window, 0, 0);

         mvwprintw(ifaces_window, 0, 15, " Global Interfaces ");
         mvwprintw(ifaces_window, 9, 17, " Press q to exit ");
         for (p = interfaces->list; p; p = dlist_next(interfaces->list, p)) {
            iface_data = (struct interface_data *) dlist_data(p);
            found = dlist_search(node->used_ints->list, node->used_ints->cmp, (void *) iface_data->ifname);
            if (found) 
               wattron(ifaces_window, COLOR_PAIR(4));
            else
               wattroff(ifaces_window, COLOR_PAIR(4));
            mvwprintw(ifaces_window, i+2, 2, "%c) %s (%s)", i + 97, 
                  iface_data->ifname, found ? "ON" : "OFF");
            i++;
         }
         change = 0;
      }

      do
      {
         key_pressed = wgetch(ifaces_window);
      } while ( (key_pressed == ERR) && !terms->gui_th.stop);

      if (!terms->gui_th.stop)
      {
         switch(key_pressed) {
            case 27: /* ESC */
            case 'Q':
            case 'q':
               end = 1;
               break;
            default:
               j = key_pressed - 97;
               for (p = interfaces->list, i = 0; p && i < j; p = dlist_next(interfaces->list, p), i++);
               iface_data = (struct interface_data *) dlist_data(p);
               if (iface_data)
               {
                   if ((p = dlist_search(node->used_ints->list, 
                        node->used_ints->cmp, (void *)iface_data->ifname)) != NULL) 
                   { 
                      iface_data = (struct interface_data *) dlist_data(p);
                      interfaces_disable(iface_data->ifname);
                      node->used_ints->list = dlist_remove(node->used_ints->list, iface_data);
                      change = 1;
                   }
                   else 
                   {
                      interfaces_enable(iface_data->ifname);
                      iface_new = (struct interface_data *) calloc(1, sizeof(struct interface_data));
                      memcpy((void *)iface_new, (void *)iface_data, sizeof(struct interface_data));
                      node->used_ints->list = dlist_append(node->used_ints->list, (void *)iface_new);
                      change = 1;
                   }
               }
               break;
         }
      }
   } /* while...*/

   wattroff(ifaces_window, COLOR_PAIR(4));

   hide_panel(ifaces_panel);

   ncurses_c_set_status_line("");
}


/* 
 * Display information about the selected item
 */
int8_t
ncurses_i_show_info(u_int8_t mode, WINDOW *main_window, u_int8_t pointer, struct term_node *node)
{
   u_int8_t i, j, line, row, col, k;
   int32_t key_pressed;
   WINDOW *info_window;
   char **values, *ptrtlv;
   struct tuple_type_desc *func;
   struct commands_param *params;

   func = NULL;

   ncurses_c_set_status_line(" Information should be free ");

   getmaxyx(main_window,row,col);
   info_window = newpad(MAX_PAD_HEIGHT, MAX_PAD_WIDTH);
   keypad(info_window, TRUE);

   i = 0;
   line = 0;
   params = (struct commands_param *) protocols[mode].parameters;

   /* OK, I already know that this is a weird way to do it, but 
    * I do not have enough free time to fix it :P */
   wattron(info_window, COLOR_PAIR(4));
   wattron(main_window, COLOR_PAIR(4));
   mvwaddch(main_window, (row-INFO_HEIGHT)/2 - 1, (col-INFO_WIDTH)/2 - 1, ACS_ULCORNER);
   mvwaddch(main_window, (row-INFO_HEIGHT)/2 - 1, (col-INFO_WIDTH)/2 + INFO_WIDTH, ACS_URCORNER);
   mvwaddch(main_window, (row-INFO_HEIGHT)/2 + INFO_HEIGHT, (col-INFO_WIDTH)/2 + INFO_WIDTH, ACS_LRCORNER);
   mvwaddch(main_window, (row-INFO_HEIGHT)/2 + INFO_HEIGHT, (col-INFO_WIDTH)/2 - 1, ACS_LLCORNER);
   mvwaddch(main_window, (row-INFO_HEIGHT)/2 - 1, (col-INFO_WIDTH)/2 + INFO_WIDTH, ACS_URCORNER);
   mvwhline(main_window, (row-INFO_HEIGHT)/2 - 1, (col-INFO_WIDTH)/2, ACS_HLINE, INFO_WIDTH);
   mvwvline(main_window, (row-INFO_HEIGHT)/2, (col-INFO_WIDTH)/2 - 1, ACS_VLINE, INFO_HEIGHT);
   mvwhline(main_window, (row-INFO_HEIGHT)/2 + INFO_HEIGHT, (col-INFO_WIDTH)/2, ACS_HLINE, INFO_WIDTH);
   mvwvline(main_window, (row-INFO_HEIGHT)/2, (col-INFO_WIDTH)/2 + INFO_WIDTH, ACS_VLINE, INFO_HEIGHT);
   mvwprintw(main_window, (row-INFO_HEIGHT)/2 + INFO_HEIGHT, (col-INFO_WIDTH)/2 + 4 , " q,ENTER: exit  Up/Down: scrolling ");
   wrefresh(main_window);

   if (protocols[mode].get_printable_packet) {
      if ((values = (*protocols[mode].get_printable_packet)(&protocols[mode].stats[pointer])) == NULL) {
         write_log(0, "Error in get_printable_packet (mode %d)\n", mode);
         return -1;
      }
   }
   else {
      write_log(0, "Warning: there is no get_printable_packet for protocol %d\n", mode);
      return -1;
   }

   k = 0;
   for (j = 0; j < protocols[mode].nparams; j++)
   {
      if ((params[j].type != FIELD_IFACE) && (params[j].type != FIELD_DEFAULT) && (params[j].type != FIELD_EXTRA))
      {
         wattron(info_window, COLOR_PAIR(4));
         mvwprintw(info_window, k, 2, "%15s", params[j].ldesc);
         wattroff(info_window, COLOR_PAIR(4));
         mvwprintw(info_window, k, 19, "%s %s", values[k], params[j].meaning ? parser_get_meaning(values[k], params[j].meaning) : "");
         k++;
      }
   }

   ptrtlv = values[k];
   if (protocols[mode].extra_nparams > 0)
   {
      while ((ptrtlv) && (strlen((char *)ptrtlv) > 0))
      {
         mvwprintw(info_window, k, 2, "%15s", ptrtlv);
         //write_log(0, "msg es %s\n", ptrtlv);
         ptrtlv += strlen((char *)ptrtlv) + 1;

         if (ptrtlv)
         {
            mvwprintw(info_window, k, 19, "%s", ptrtlv);
            ptrtlv += strlen((char *)ptrtlv) + 1;
         }
         k++;
      }
   }

   wattron(info_window, COLOR_PAIR(4));
   mvwprintw(info_window, k, 2, "%15s", "Total");
   wattroff(info_window, COLOR_PAIR(4));
   mvwprintw(info_window, k++, 19,"%ld",  
         protocols[mode].stats[pointer].total);

   wattron(info_window, COLOR_PAIR(4));
   mvwprintw(info_window, k, 2, "%15s", "Interface");
   wattroff(info_window, COLOR_PAIR(4));
   mvwprintw(info_window, k++, 19,"%s",  
         protocols[mode].stats[pointer].iface);

   wtimeout(info_window,NCURSES_KEY_TIMEOUT); 

   do
   {
      prefresh(info_window, line, 0, (row-INFO_HEIGHT)/2, (col-INFO_WIDTH)/2, 
            (row-INFO_HEIGHT)/2 + INFO_HEIGHT - 1, (col-INFO_WIDTH)/2 + INFO_WIDTH - 1);
      do
      {
         key_pressed = wgetch(info_window);
      } while( (key_pressed == ERR) && !terms->gui_th.stop);

      switch(key_pressed) {
         case KEY_UP:
            if (line > 0) 
               line--;
            break;
         case KEY_DOWN:
            if (line < INFO_HEIGHT)
               line++;
            break;
      }

   } while(!terms->gui_th.stop && (key_pressed != 13) &&
         (key_pressed!='q') && (key_pressed!='Q'));

   delwin(info_window);
   wclear(main_window);

   ncurses_c_set_status_line("");

   return 0;
}

/* 
 * Display packet
 * Taken from print-ascii.c (tcpdump)
 * http://www.tcpdump.org
 */
int8_t
ncurses_i_view_packet(u_int8_t mode, WINDOW *main_window, u_int8_t pointer)
{
   u_int8_t *packet;
   u_int16_t length, oset;
   int32_t j, key_pressed, line, row, col;
   WINDOW *view_window;
   register u_int i;
   register int s1, s2;
   register int nshorts;
   char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
   char asciistuff[ASCII_LINELENGTH+1], *asp;
   u_int32_t maxlength = HEXDUMP_SHORTS_PER_LINE;

   ncurses_c_set_status_line(" Displaying packet ");

   getmaxyx(main_window,row,col);
   view_window = newpad(MAX_PAD_HEIGHT, MAX_PAD_WIDTH);
   keypad(view_window, TRUE);

   j = 0;
   line = 0;
   oset = 0;
   length = 0;
   packet = NULL;

   /* OK, I already know that this is a weird way to do it, but 
    * I do not have enough free time to fix it :P */
   wattron(info_window, COLOR_PAIR(4));
   wattron(main_window, COLOR_PAIR(4));
   mvwaddch(main_window, (row-VIEW_HEIGHT)/2 - 1, (col-VIEW_WIDTH)/2 - 1, ACS_ULCORNER);
   mvwaddch(main_window, (row-VIEW_HEIGHT)/2 - 1, (col-VIEW_WIDTH)/2 + VIEW_WIDTH, ACS_URCORNER);
   mvwaddch(main_window, (row-VIEW_HEIGHT)/2 + VIEW_HEIGHT, (col-VIEW_WIDTH)/2 + VIEW_WIDTH, ACS_LRCORNER);
   mvwaddch(main_window, (row-VIEW_HEIGHT)/2 + VIEW_HEIGHT, (col-VIEW_WIDTH)/2 - 1, ACS_LLCORNER);
   mvwaddch(main_window, (row-VIEW_HEIGHT)/2 - 1, (col-VIEW_WIDTH)/2 + VIEW_WIDTH, ACS_URCORNER);
   mvwhline(main_window, (row-VIEW_HEIGHT)/2 - 1, (col-VIEW_WIDTH)/2, ACS_HLINE, VIEW_WIDTH);
   mvwvline(main_window, (row-VIEW_HEIGHT)/2, (col-VIEW_WIDTH)/2 - 1, ACS_VLINE, VIEW_HEIGHT);
   mvwhline(main_window, (row-VIEW_HEIGHT)/2 + VIEW_HEIGHT, (col-VIEW_WIDTH)/2, ACS_HLINE, VIEW_WIDTH);
   mvwvline(main_window, (row-VIEW_HEIGHT)/2, (col-VIEW_WIDTH)/2 + VIEW_WIDTH, ACS_VLINE, VIEW_HEIGHT);
   mvwprintw(main_window, (row-VIEW_HEIGHT)/2 + VIEW_HEIGHT, (col-VIEW_WIDTH)/2 + 16 , " q,ENTER: exit  Up/Down: scrolling ");
   wrefresh(main_window);

   packet = protocols[mode].stats[pointer].packet;
   length = (protocols[mode].stats[pointer].header->len < SNAPLEN) ? protocols[mode].stats[pointer].header->len : SNAPLEN;

   nshorts = length / sizeof(u_int16_t);
   i = 0;
   hsp = hexstuff; asp = asciistuff;
   while (--nshorts >= 0) {
      s1 = *packet++;
      s2 = *packet++;

      (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
                     " %02x%02x", s1, s2);
      hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
      *(asp++) = (isgraph(s1) ? s1 : '.');
      *(asp++) = (isgraph(s2) ? s2 : '.');
      i++;

      if (i >= maxlength) {
         *hsp = *asp = '\0';
         mvwprintw(view_window, j, 1, "0x%04x: %-*s  %s",
               oset, HEXDUMP_HEXSTUFF_PER_LINE,
               hexstuff, asciistuff);
         i = 0; hsp = hexstuff; asp = asciistuff;
         oset += HEXDUMP_BYTES_PER_LINE;
         j++;
      }
   }

   if (length & 1) {
      s1 = *packet++;
      (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
                     " %02x", s1);
      hsp += 3;
      *(asp++) = (isgraph(s1) ? s1 : '.');
      ++i;
   }
   if (i > 0) {
      *hsp = *asp = '\0';
      (void)mvwprintw(view_window, j, 1, "0x%04x: %-*s  %s",
                      oset, HEXDUMP_HEXSTUFF_PER_LINE,
                      hexstuff, asciistuff);
   }

   wtimeout(view_window, NCURSES_KEY_TIMEOUT); 

   do
   {
      prefresh(view_window, line, 0, (row-VIEW_HEIGHT)/2, (col-VIEW_WIDTH)/2, (row-VIEW_HEIGHT)/2 + VIEW_HEIGHT - 1, (col-VIEW_WIDTH)/2 + VIEW_WIDTH - 1);
      do
      {
         key_pressed = wgetch(view_window);
      } while( (key_pressed == ERR) && !terms->gui_th.stop);

      switch(key_pressed) {
         case KEY_UP:
            if (line > 0) 
               line--;
            break;
         case KEY_DOWN:
            if (line < VIEW_HEIGHT)
               line++;
            break;
      }

   } while(!terms->gui_th.stop && (key_pressed != 13) &&
         (key_pressed!='q') && (key_pressed!='Q'));

   delwin(view_window);
   wclear(main_window);

   ncurses_c_set_status_line("");

   return 0;
}


/* 
 * List attack
 */
void 
ncurses_i_list_attacks(WINDOW *list_window, struct term_node *node)
{
   u_int8_t end, kill, j, pointer, a, i, used, indx=0, files[MAX_PROTOCOLS*MAX_THREAD_ATTACK][2];
   int32_t key_pressed;
   struct attack *theattack = NULL;

   used = 0; j = 0;

   for (a=0; a<MAX_PROTOCOLS; a++)
   {
      for (i=0; i<MAX_THREAD_ATTACK; i++)
      {
         if (node->protocol[a].attacks[i].up) 
         {
            files[j][0]=a; /* Protocol */
            files[j][1]=i; /* Attack used */
            j++;
            used++;
         }
      }
   }

   ncurses_c_set_status_line(" Listing current attacks... ");

   pointer = 0;
   kill = 0;
   end = 0;

   wclear(list_window);

   wattron(list_window, COLOR_PAIR(4));
   box(list_window, 0, 0);
   mvwprintw(list_window, 0, 2, " Running attacks ");
   mvwprintw(list_window, 2, 2, " Protocol  Type    Description");
   mvwprintw(list_window, 19, 2, " Press ENTER to cancel an attack or 'q' to quit");
   wattroff(list_window, COLOR_PAIR(4));

   keypad(list_window, TRUE);

   wtimeout(list_window,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

   while (!end && !terms->gui_th.stop) 
   {
      i = 0;
      while (!terms->gui_th.stop && (i < used)) 
      {
         /* Kill the attack thread selected */
         if (kill)
         {
            if (node->protocol[files[indx][0]].attacks[files[indx][1]].up)
            {
               attack_kill_th(node, node->protocol[files[indx][0]].attacks[files[indx][1]].attack_th.id);
               break;
            }
         }

         if (i == pointer)
         {
            wattron(list_window, COLOR_PAIR(1));
            indx=i;
         }
         else
            wattroff(list_window, COLOR_PAIR(1));

         if (node->protocol[files[i][0]].attacks[files[i][1]].up) 
         {
            theattack = protocols[files[i][0]].attacks;

            mvwprintw(list_window, i+4, 2, "%8s   %-2d      %s", 
                  protocols[files[i][0]].namep, 
                  node->protocol[files[i][0]].attacks[files[i][1]].attack, 
                  theattack[node->protocol[files[i][0]].attacks[files[i][1]].attack].s);
         }
         i++;
      }

      wrefresh(list_window);

      if (kill)
         break;  

      do
      {
         key_pressed = wgetch(list_window);
      } while( (key_pressed == ERR) && !terms->gui_th.stop);

      if (!terms->gui_th.stop)
      {
         switch(key_pressed) 
         {
            case KEY_DOWN:
               if ( pointer < (used-1)) 
                  pointer++;
               break;

            case KEY_UP:
               if (pointer > 0) 
                  pointer--;
               break; 

            case 'Q':
            case 'q':
               end = 1;
               break;
            case 13: /* ENTER */
               kill = 1;
               break;
         }
      }
   }

   ncurses_c_set_status_line("");
}


/* 
 * List capture files
 */
void 
ncurses_i_list_filecaps(WINDOW *list_window, struct term_node *node)
{
   int32_t key_pressed;
   u_int8_t end, kill, j, pointer, i, used, indx=0, files[MAX_PROTOCOLS+2];

   used = 0; j = 0;

   for (i=0; i<MAX_PROTOCOLS; i++)
   {
      if (node->protocol[i].pcap_file.pdumper)
      {
         files[j]=i;
         j++;
         used++;
      }
   }

   if (node->pcap_file.pdumper)
   {
      files[j]=PROTO_ALL;
      used++;
   }

   ncurses_c_set_status_line(" Listing current capture files... ");

   pointer = 0;
   kill = 0;
   end = 0;

   wclear(list_window);

   wattron(list_window, COLOR_PAIR(4));
   box(list_window, 0, 0);
   mvwprintw(list_window, 0, 2, " Capture files ");
   mvwprintw(list_window, 2, 2, "Protocol  Filename");
   mvwprintw(list_window, 19, 2, " Press ENTER to cancel a capture file or 'q' to quit");
   wattroff(list_window, COLOR_PAIR(4));

   keypad(list_window, TRUE);

   wtimeout(list_window,NCURSES_KEY_TIMEOUT);

   while (!end && !terms->gui_th.stop) 
   {
      i = 0;

      while (!terms->gui_th.stop && (i < used) ) 
      {
         if (kill)
         {
            if (files[indx] == PROTO_ALL)
               interfaces_pcap_file_close(node,PROTO_ALL);
            else
               interfaces_pcap_file_close(node,files[indx]);
            break;
         }        

         if (i == pointer)
         {
            wattron(list_window, COLOR_PAIR(1));
            indx=i;
         }
         else
            wattroff(list_window, COLOR_PAIR(1));

         if (files[i] == PROTO_ALL)
         {
            mvwprintw(list_window, i+4, 2, "  %-6s  %s", 
                  "ALL", 
                  node->pcap_file.name);
         }
         else
         {
            mvwprintw(list_window, i+4, 2, "  %-6s  %s", 
                  protocols[files[i]].namep, 
                  node->protocol[files[i]].pcap_file.name);
         } 
         i++;
      }

      wrefresh(list_window);

      if (kill)
         break;  

      do
      {
         key_pressed = wgetch(list_window);
      } while( (key_pressed == ERR) && !terms->gui_th.stop);

      if (!terms->gui_th.stop)
      {
         switch(key_pressed) 
         {
            case KEY_DOWN:
               if ( pointer < (used-1)) 
                  pointer++;
               break;

            case KEY_UP:
               if (pointer > 0) 
                  pointer--;
               break; 

            case 'Q':
            case 'q':
               end = 1;
               break;
            case 13: 
               kill = 1;
               break;
         }
      }
   }

   ncurses_c_set_status_line("");
}


int8_t
ncurses_i_error_window(u_int8_t mode, char *message, ...)
{
   int32_t row, col, i, message_s;
   int32_t max_y, max_x;
   va_list argp;
   WINDOW *my_window;
   PANEL *my_panel;
   char *ptr, *m_split;
   char *vmessage;

   ncurses_c_set_status_line(" You've got a message ");

   getmaxyx(stdscr,row,col);

   /* Max message size is ERRORMSG_SIZE bytes */
   if ((vmessage = (char *) malloc(ERRORMSG_SIZE)) == NULL) {
      thread_error("Error in malloc", errno);
      return -1;
   }

   memset(vmessage, 0, ERRORMSG_SIZE);
   va_start(argp, message);
   if (vsnprintf(vmessage,ERRORMSG_SIZE, message, argp) < 0) {
      thread_error("Error in vsprintf", errno);
      return -1;
   }
   va_end(argp);

   i = 1;
   ptr = vmessage;
   if ((message_s = strlen(vmessage)) > ERRORMSG_SIZE)
      return -1;
   /* by default half columns than terminal columns */
   max_y = col / 2;
   /* as many rows as needed to fit the message (estimated) */
   max_x = (message_s / (col / 2)) + 4;
   if ((m_split = (char *) malloc(max_y - 3)) == NULL) {
      thread_error("Error in malloc", errno);
      return -1;
   }
   my_window = newwin(max_x, max_y, (row-max_x)/2, (col-max_y)/2);
   my_panel = new_panel(my_window);

   wattron(my_window, COLOR_PAIR(3));
   box(my_window, 0, 0);
   switch(mode) {
      case 0:
         mvwprintw(my_window, 0, 2, " Notification window ");
         write_log(0, " Notification: %s\n", vmessage);
         break;
      case 1:
         mvwprintw(my_window, 0, 2, " Error window ");
         write_log(0, " Error: %s\n", vmessage);
         break;
   }

   mvwprintw(my_window, max_x - 1, 2, " Press any key to continue ");
   wattroff(my_window, COLOR_PAIR(3));
   while (message_s > 0) {
      /* split the message */
      if (message_s >= max_y - 4) {
         strncpy(m_split, ptr, max_y - 4);
         m_split[max_y-4] = '\0';
         mvwprintw(my_window, i, 2, m_split);
         message_s -= max_y - 4;
         ptr += max_y - 4;
         /* offset */
      } else {
         strncpy(m_split, ptr, message_s);
         m_split[message_s] = '\0';
         mvwprintw(my_window, i, 2, m_split);
         message_s = 0;
      }
      i++;
   }

   free(m_split);
   free(vmessage);

   update_panels();
   if (doupdate() == ERR)
      return -1;

   wtimeout(my_window, NCURSES_KEY_TIMEOUT);
   while ((wgetch(my_window)==ERR) && !terms->gui_th.stop);

   if (del_panel(my_panel) == ERR)
      return -1;
   if (delwin(my_window) == ERR)
      return -1;

   ncurses_c_set_status_line("");

   return 0;
}


int8_t
ncurses_i_getstring_window(struct term_node *term, char *status, char *data, u_int16_t max, char *message)
{
   int32_t row, col;
   int32_t max_y, max_x;
   WINDOW *my_window;
   PANEL *my_panel;

   ncurses_c_set_status_line(status);

   getmaxyx(stdscr,row,col);

   /* TODO: lateral scroll 
      max_y = max+3; */
   max_y = 64+3;
   max_x = 5;

   my_window = newwin(max_x, max_y, (row-max_x)/2, (col-max_y)/2);
   my_panel = new_panel(my_window);

   wattron(my_window, COLOR_PAIR(3));
   box(my_window, 0, 0);

   mvwprintw(my_window, 0, 2, message);

   mvwprintw(my_window, max_x - 1, 2, " Press Enter to continue ");
   wattroff(my_window, COLOR_PAIR(3));

   wmove(my_window, max_x - 3, 1);

   echo();
   curs_set(2);
   wgetnstr(my_window, data, max);
   noecho();
   curs_set(0);    

   update_panels();

   doupdate();
   del_panel(my_panel);
   delwin(my_window);

   ncurses_c_set_status_line("");

   return 0;
}


int32_t
ncurses_i_getconfirm(struct term_node *term, char *status, char *message, char *title)
{
   int32_t row, col, key_pressed=0, max_y, max_x;
   u_int8_t end=0;
   char *bottom = " 'Y' to confirm  -  'N' to abort ";
   WINDOW *my_window;
   PANEL *my_panel;

   ncurses_c_set_status_line(status);

   getmaxyx(stdscr,row,col);

   max_x = strlen(message)+2;

   if (strlen(bottom)>max_x)
      max_x = strlen(bottom);

   max_y = 5;

   my_window = newwin(max_y, max_x, (row-max_y)/2, (col-max_x)/2);
   my_panel = new_panel(my_window);

   noecho();
   curs_set(0);

   wattron(my_window, COLOR_PAIR(3));
   box(my_window, 0, 0);

   mvwprintw(my_window, 0, 2, title);

   mvwprintw(my_window, max_y - 1, 2, bottom);

   wattroff(my_window, COLOR_PAIR(3));

   mvwprintw(my_window, max_y - 3, 1, message);

   wtimeout(my_window,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

   while (!end && !terms->gui_th.stop)
   {
      do
      {
         key_pressed = wgetch(my_window);
      } while ( (key_pressed == ERR) && !terms->gui_th.stop);

      if (terms->gui_th.stop)
         break;

      switch(key_pressed)
      {
         case 'y':
         case 'Y':
            key_pressed = 'y';
            end=1;
            break;

         case 'n':
         case 'N':
            key_pressed = 'n';
            end = 1;
            break;
      }
   }

   update_panels();
   doupdate();
   del_panel(my_panel);
   delwin(my_window);

   ncurses_c_set_status_line("");

   return key_pressed;
}


int32_t 
ncurses_i_popup_window(WINDOW *bwindow, const struct tuple_type_desc *tuple, u_int8_t state)
{
   WINDOW *win;
   int32_t i, j, pointer, end, result, key_pressed, row, col;

   pointer = 0;
   end = 0;
   result = ERR;

   getmaxyx(stdscr, row, col);

   if ((win = derwin(stdscr, 5, 22, row-NCURSES_BWINDOW_SIZE, 20)) == NULL)
      return ERR;

   keypad(win, TRUE);
   /*    scrollok(win, TRUE);
         idlok(win, TRUE);*/

   while (!terms->gui_th.stop && !end) {
      j = 0;
      i = pointer;
      /* Show max 3 options */
      while(tuple[i].desc != NULL && j <= 2) {
         if (i == pointer)
            wattron(win, COLOR_PAIR(5) | A_BOLD);

         wmove(win, j+1, 1);
         whline(win, ' ', 20);

         mvwprintw(win, j+1, 1, "%s", tuple[i].desc);
         if (i == pointer)
            wattroff(win, A_BOLD);

         i++; j++;
      }

      box(win, 0, 0);
      wtimeout(win,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

      key_pressed = wgetch(win);
      switch(key_pressed) {
         case KEY_DOWN:
            pointer = (tuple[pointer+1].desc) ? (pointer+1) : pointer;
            break;
         case KEY_UP:
            pointer = (pointer > 0) ? (pointer-1) : 0;
            break;
         case 13: /* ENTER */
            result = tuple[pointer].type;
            end = 1;
            break;
         case 27: /* ESC */
            end = 1;
            break;
      }
      werase(win);
   }

   wrefresh(bwindow);

   if (delwin(win) == ERR)
      return ERR;

   return result;
}    



int8_t
ncurses_i_edit_tlv(struct term_node *node, u_int8_t mode)
{
   u_int8_t **values = NULL;
   WINDOW *win;
   int32_t pointer, end, key_pressed, row, col, modified;
   u_int8_t j, jfields, *ptrtlv, k;
   struct commands_param *params;

   pointer = 1;
   end = 0;
   modified = 1;

   getmaxyx(stdscr, row, col);

   if ((win = derwin(stdscr, 23, 41, (row-23)/2, (col-41)/2)) == NULL)
      return ERR;

   params = (struct commands_param *) protocols[mode].parameters;
   keypad(win, TRUE);
   curs_set(0);

   while (!terms->gui_th.stop && !end) {
      if (modified) {
         if ((values = (u_int8_t **)(*protocols[mode].get_printable_store)(node)) == NULL) {
            write_log(0, "Error in get_printable_store (mode %d)\n", mode);
            return -1;
         }

         modified = 0;
         wclear(win);
         wrefresh(win);
      }
      k = 0;
      for (j = 0; j < protocols[mode].nparams; j++)
      {
         if ((params[j].type != FIELD_IFACE) && (params[j].type != FIELD_DEFAULT) && (params[j].type != FIELD_EXTRA))
            k++;
      }

      ptrtlv = values[k];
      jfields = 1;
      if (protocols[mode].extra_nparams > 0)
      {
         while ((ptrtlv) && (strlen((char *)ptrtlv) > 0))
         {
            if (jfields == pointer) 
               wattron(win, COLOR_PAIR(4));
            else
               wattroff(win, COLOR_PAIR(4));

            mvwprintw(win, jfields, 2, "%15s", ptrtlv);
            ptrtlv += strlen((char *)ptrtlv) + 1;

            if (ptrtlv)
            {
               mvwprintw(win, jfields, 19, "%s", ptrtlv);
               ptrtlv += strlen((char *)ptrtlv) + 1;
            }
            jfields++;
         }
      }

      wattron(win, COLOR_PAIR(4));
      box(win, 0, 0);
      mvwprintw(win, 22, 7, "q: EXIT, a: ADD, d:DEL");
      wtimeout(win, NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

      key_pressed = wgetch(win);
      switch(key_pressed) {
         case KEY_DOWN:
            pointer = (pointer < jfields - 1) ? (pointer+1) : pointer;
            break;
         case KEY_UP:
            pointer = (pointer > 1) ? (pointer-1) : 1;
            break;
            /* Add TLV */
         case 'a':
         case 'A':
            ncurses_i_add_selected_tlv_type(win, node, mode); 
            modified = 1;
            break;
            /* Delete TLV */
         case 'd':
         case 'D':
            ncurses_i_del_selected_tlv(node, mode, pointer);
            modified = 1;
            break;
         case 'q':
         case 'Q':
            end = 1;
            break;
         case 27: /* ESC */
            end = 1;
            break;
      }

      if (modified && values) 
      {
         while(values[j]) 
         {
            free(values[j]);
            j++;
         }
         if (values)
            free(values);
      }
   }

   werase(win);

   j = 0;

   if (values) 
   {
      while(values[j]) 
      {
         free(values[j]);
         j++;
      }
      if (values)
         free(values);
   }

   if (delwin(win) == ERR)
      return ERR;

   return 0;
}

int8_t
ncurses_i_add_selected_tlv_type(WINDOW *win, struct term_node *node, u_int8_t mode)
{
   int32_t i, pointer, end, key_pressed;
   struct attack_param *attack_param;
   struct commands_param_extra_item *newitem;
   u_int32_t type;
   u_int8_t field;
   int8_t ret;
   void *extra;

   pointer = 0;
   end = 0;
   type = 0;
   i = 0;
   key_pressed = 0;
   attack_param = NULL;
   newitem = NULL;
   extra = NULL;

   while (!terms->gui_th.stop && !end) {
      werase(win);
      i = 0;
      for (i = 0; i < protocols[mode].extra_nparams; i++)
      {
         if (i == pointer)
            wattron(win, COLOR_PAIR(5) | A_BOLD);

         wmove(win, i+1, 1);
         whline(win, ' ', 20);

         mvwprintw(win, i+1, 1, "%s", protocols[mode].extra_parameters[i].ldesc);
         if (i == pointer)
            wattroff(win, A_BOLD);
      }

      box(win, 0, 0);
      mvwprintw(win, 22, 7, "Press ENTER to add the selected TYPE");
      wtimeout(win,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

      key_pressed = wgetch(win);
      switch(key_pressed) {
         case KEY_DOWN:
            pointer = (pointer < (i-1)) ? (pointer+1) : pointer;
            break;
         case KEY_UP:
            pointer = (pointer > 0) ? (pointer-1) : 0;
            break;
         case 13: /* ENTER */
            if ((newitem = (struct commands_param_extra_item *) calloc(1, sizeof(struct commands_param_extra_item))) == NULL)
            {
               write_log(0, "Error in calloc\n");
               return -1;
            }
            if ((newitem->value = (u_int8_t *) calloc(1, protocols[mode].extra_parameters[pointer].size)) == NULL)
            {
               write_log(0, "Error in calloc\n");
               return -1;
            }

            memcpy((void *)&newitem->id, (void *)&protocols[mode].extra_parameters[pointer].id, 4);
            end = 1;
            break;
         case 27: /* ESC */
            end = 1;
            break;
      }
   }

   /* Set up the param... */
   if (newitem) {
      if ((attack_param = (struct attack_param *) calloc(1, (sizeof(struct attack_param)))) == NULL)
      {
         thread_error(" ncurses_i_attack_screen attack_param calloc",errno);
         key_pressed='Q';
         return -1;
      }

      attack_param->desc = calloc(1, strlen(protocols[mode].extra_parameters[pointer].ldesc) + 1);
      strncpy(attack_param->desc, protocols[mode].extra_parameters[pointer].ldesc, strlen(protocols[mode].extra_parameters[pointer].ldesc));
      attack_param->size = protocols[mode].extra_parameters[pointer].size;
      attack_param->type = protocols[mode].extra_parameters[pointer].type;
      attack_param->size_print = protocols[mode].extra_parameters[pointer].size_print;

      if (attack_init_params(node, attack_param, 1) < 0)
      {
         free(attack_param);
         key_pressed='Q';
         return -1;
      }

      /* Now we can ask for parameters... */
      ncurses_i_get_printable_store(attack_param, 1);

      do {
         if (ncurses_i_attack_get_params(attack_param, 1) < 0) /* Q pressed */
         {
            attack_free_params(attack_param, 1);
            free(attack_param);
            key_pressed='Q';
            return -1;
         }

         ret = attack_filter_all_params(attack_param, 1, &field);
         if ( ret == -1) /* Error on data...*/
         {
            ncurses_i_error_window(1, "Bad data on field '%s'!!",
                  attack_param[field].desc);
         }
      } while(ret==-1);

      if (key_pressed == 'Q')
      {
         i = 0;
         wclear(win);
         wattron(win, COLOR_PAIR(1));
         box(win, 0, 0);
         key_pressed = 0;
      }
   }

   strncpy((char *)newitem->value, attack_param->print, attack_param->size_print);

   if (protocols[mode].get_extra_field)
   {
      extra = (*protocols[mode].get_extra_field)(node, NULL, 0);
      extra = dlist_append(extra, (void *)newitem);
      (*protocols[mode].get_extra_field)(node, extra, 1);
   }

   return 0;
}


int8_t
ncurses_i_del_selected_tlv(struct term_node *node, u_int8_t mode, u_int8_t pointer)
{
   void *extra;
   dlist_t *p;
   struct commands_param_extra *extrap;
   u_int8_t i;

   if (protocols[mode].get_extra_field)
   {
      extra = (*protocols[mode].get_extra_field)(node, NULL, 0);
      for (i=0,p=extra;p; i++,p = dlist_next(extra, p)) 
      {
         extrap = dlist_data(p);
         if (i == (pointer - 1))
         {
            extra = dlist_remove(extra, (void *)extrap);
            break;
         }
      }
      (*protocols[mode].get_extra_field)(node, extra, 1);
   }

   return 0;
}


void
ncurses_i_get_printable_store(struct attack_param *attack_param, u_int8_t nparams)
{
   u_int8_t i, *aux_char;
   u_int16_t *aux_short;
   u_int32_t *aux_long;

   for (i=0; i< nparams; i++)
   {
      switch(attack_param[i].type)
      {
         case FIELD_BRIDGEID:
            aux_char = (u_int8_t *)attack_param[i].value;
            snprintf(attack_param[i].print, 18, "%02X%02X.%02X%02X%02X%02X%02X%02X",
                  aux_char[0], aux_char[1], aux_char[2], aux_char[3],
                  aux_char[4], aux_char[5], aux_char[6], aux_char[7]);
            break;

         case FIELD_MAC:
            aux_char = (u_int8_t *)attack_param[i].value;
            snprintf(attack_param[i].print, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                  aux_char[0], aux_char[1], aux_char[2],
                  aux_char[3], aux_char[4], aux_char[5]); 
            break;

         case FIELD_HEX:
         case FIELD_DEC:
            switch(attack_param[i].size)
            {
               case 1:
                  aux_char = (u_int8_t *)attack_param[i].value;
                  if (attack_param[i].type == FIELD_HEX)
                     snprintf(attack_param[i].print, attack_param[i].size_print+1, "%02X", *(aux_char));
                  else
                     snprintf(attack_param[i].print, attack_param[i].size_print+1, "%02d", *(aux_char));
                  break;
               case 2:
                  aux_short = (u_int16_t *)attack_param[i].value;
                  if (attack_param[i].type == FIELD_HEX)                       
                     snprintf(attack_param[i].print, attack_param[i].size_print+1, "%04X", *(aux_short));
                  else
                     snprintf(attack_param[i].print, attack_param[i].size_print+1, "%04d", *(aux_short));
                  break;
               default:
                  aux_long = (u_int32_t *)attack_param[i].value;
                  if (attack_param[i].type == FIELD_HEX)
                     snprintf(attack_param[i].print, attack_param[i].size_print+1, "%0*X", 
                           attack_param[i].size_print, *(aux_long));
                  else
                     snprintf(attack_param[i].print, attack_param[i].size_print+1, "%0*d",
                           attack_param[i].size_print, *(aux_long));
                  break;
            }
            break;

         case FIELD_IP:
            aux_long = (u_int32_t *)attack_param[i].value;
            parser_get_formated_inet_address(*aux_long, attack_param[i].print, 16);
            break;

         case FIELD_STR:
            memcpy(attack_param[i].print, attack_param[i].value, attack_param[i].size_print);
            break;
      }
   }
}


/*
 * Get parameters for attack
 */
int8_t
ncurses_i_attack_get_params(struct attack_param *param, u_int8_t nparams)
{
   int32_t row, col;
   int32_t max_y, max_x, y, x;
   u_int8_t i, end_edit=0, offset_x=0, offset_y, origin_x, origin_y, max_print=0;
   int8_t ret=0;
   int32_t key_pressed;
   char *bottom = "ESC/Q to abort - ENTER to continue";
   WINDOW *my_window;
   PANEL *my_panel;

   for (i=0; i< nparams; i++)
   {
      if (strlen(param[i].desc) > offset_x)
         offset_x = strlen(param[i].desc);
      if (param[i].size_print > max_print)
         max_print = param[i].size_print;
   }

   offset_y = 2;

   getmaxyx(stdscr,row,col);

   if ((offset_x+max_print+3) > (strlen(bottom)+4))
      max_x = offset_x + max_print+3;
   else
      max_x = strlen(bottom)+4;

   max_y = nparams+4;

   my_window = newwin(max_y, max_x, (row-max_y)/2, (col-max_x)/2);
   my_panel = new_panel(my_window);

   wattron(my_window, COLOR_PAIR(3));
   box(my_window, 0, 0);

   mvwprintw(my_window, 0, 2, "Attack parameters");

   mvwprintw(my_window, max_y - 1, 2, bottom);
   wattroff(my_window, COLOR_PAIR(3));

   wmove(my_window, max_x - 3, 1);

   noecho();
   curs_set(0);

   for (i=0; i< nparams; i++)
   {
      wattron(my_window, COLOR_PAIR(2));
      mvwprintw(my_window, i+2, 1, "%*s", offset_x, param[i].desc); 
      wattroff(my_window, COLOR_PAIR(2));
      mvwprintw(my_window, i+2, 2+offset_x, "%s", param[i].print); 
   }

   origin_x = 2+offset_x;
   origin_y = 2;

   wmove(my_window, origin_y, origin_x);

   noecho();    
   curs_set(1);
   keypad(my_window, TRUE);

   wtimeout(my_window,NCURSES_KEY_TIMEOUT);

   end_edit = 0;

   while (!end_edit && !terms->gui_th.stop)
   {
      do
      {
         key_pressed = wgetch(my_window);
      } while ( (key_pressed == ERR) && !terms->gui_th.stop);

      if (terms->gui_th.stop)
         break;

      switch(key_pressed)
      {
         case 13: /* ENTER */
            end_edit = 1;
            ret = 0;
            break;

         case 27: /* ESC */
            end_edit = 1;
            ret = -1;
            break;

         case 9:  /* TAB */
         case KEY_DOWN:            
            getyx(my_window,y,x);
            if ( (y - offset_y) == (nparams-1))
               wmove(my_window, origin_y, origin_x);
            else
               wmove(my_window, y+1, origin_x);
            break;

         case KEY_UP:
            getyx(my_window,y,x);
            if ( (y - offset_y) == 0)
               wmove(my_window, origin_y+(nparams-1), origin_x);
            else
               wmove(my_window, y-1, origin_x);
            break;

         case KEY_RIGHT:
            getyx(my_window, y, x);
            /* jump to the next valid character */
            if ( x < (origin_x + param[y-offset_y].size_print - 1))
            {
               if ((param[y-offset_y].type == FIELD_MAC) && 
                     (((x - origin_x - 1) % 3) == 0)) 
                  wmove(my_window, y, x + 2); /* jump : */
               else 
                  if ((param[y-offset_y].type == FIELD_BRIDGEID) && 
                        ((x - origin_x) == 3)) 
                     wmove(my_window, y, x + 2); /* jump . */
                  else 
                     if ((param[y-offset_y].type == FIELD_IP) && 
                           (((x - origin_x-1 ) % 4) == 1)) 
                        wmove(my_window, y, x + 2); /* jump . */
                     else
                        wmove(my_window, y, x + 1);
            }                
            else /* jump to the next field */
            {
               if ((y-offset_y) == (nparams-1))
                  wmove(my_window, origin_y, origin_x);
               else
                  wmove(my_window, y+1, origin_x);
            }
            break;

         case KEY_LEFT:
            getyx(my_window, y, x);

            if (x  > origin_x)
            {
               if ((param[y-offset_y].type == FIELD_MAC) &&
                     (((x - origin_x) % 3) == 0) )
                  /* jump */
                  wmove(my_window, y, x - 2);
               else 
                  if ((param[y-offset_y].type == FIELD_BRIDGEID) && 
                        ((x - origin_x) == 5) ) 
                     /* jump */
                     wmove(my_window, y, x - 2);
                  else 
                     if ((param[y-offset_y].type == FIELD_IP) && 
                           (((x - origin_x) % 4) == 0) ) 
                        /* jump */
                        wmove(my_window, y, x - 2);
                     else
                        wmove(my_window, y, x - 1);
            }
            else 
            {
               if ( (y - offset_y) == 0)
                  wmove(my_window, origin_y+(nparams-1), 
                        origin_x+param[origin_y+(nparams-1)-offset_y].size_print-1);
               else
                  wmove(my_window, y-1, 
                        origin_x+param[y-1-offset_y].size_print-1);                
            }
            break;

         default:
            getyx(my_window, y, x);

            if ((key_pressed == 'Q' || key_pressed == 'q') && 
                  (param[y-offset_y].type != FIELD_STR) &&
                  (param[y-offset_y].type != FIELD_IFACE) )
            {
               end_edit = 1;
               ret = -1;
            }            

            if ((param[y-offset_y].type == FIELD_HEX) || 
                  (param[y-offset_y].type == FIELD_MAC) || 
                  (param[y-offset_y].type == FIELD_BRIDGEID)) 
            {
               if (!isxdigit(key_pressed))
                  /* only hexadecimal characters are allowed */
                  break;
            } 
            else 
               if ((param[y-offset_y].type == FIELD_DEC) || 
                     (param[y-offset_y].type == FIELD_IP)) 
               {
                  if (!isdigit(key_pressed))
                     break;
               } 
               else 
                  if ( (param[y-offset_y].type == FIELD_STR) ||
                        (param[y-offset_y].type == FIELD_IFACE) ) 
                  {
                     if (!isascii(key_pressed))
                        break;
                  } 
                  else /* FIELD_NONE */
                     break;

            waddch(my_window, key_pressed | A_BOLD);

            getyx(my_window, y, x);

            param[y-offset_y].print[x-origin_x-1] = key_pressed;

            if ( x >= (origin_x + param[y-offset_y].size_print ))
            {
               if ((y-offset_y) == (nparams-1))
                  wmove(my_window, origin_y, origin_x);
               else
                  wmove(my_window, y+1, origin_x);                    
            }
            else 
            {
               if ( (param[y-offset_y].type == FIELD_MAC) && 
                     (((x - origin_x + 1) % 3) == 0)) 
                  /* jump */
                  wmove(my_window, y, x + 1);
               else 
                  if ( (param[y-offset_y].type == FIELD_BRIDGEID) && 
                        ((x - origin_x) == 4)) 
                     /* jump */
                     wmove(my_window, y, x + 1);
                  else 
                     if ( (param[y-offset_y].type == FIELD_IP) && 
                           (((x - origin_x + 1) % 4) == 0)) 
                        /* jump */
                        wmove(my_window, y, x + 1);
            }
            break;

      }
   }

   keypad(my_window, FALSE);
   noecho();
   curs_set(0);    
   del_panel(my_panel);
   delwin(my_window);

   if (terms->gui_th.stop)
      return -1;

   return ret;
}


/* 
 * Display available modes and let the user choose one!
 */
int8_t
ncurses_i_get_mode(u_int8_t mode, WINDOW *main_window)
{
   WINDOW *win;
   u_int8_t pointer, i, j, aux[MAX_PROTOCOLS], used, end;
   int32_t key_pressed, row, col;
   int8_t result;

   pointer = 0; used = 0; j = 0;

   for (i=0; i<MAX_PROTOCOLS; i++)
   {
      if (protocols[i].visible)
      {
         aux[j]=i;
         if (i == mode)
            pointer = j;
         j++;
         used++;
      }
   }

   end = 0;
   result = ERR;

   ncurses_c_set_status_line(" Choose your life (mode) ");

   getmaxyx(main_window, row, col);

   if ((win = derwin(main_window, (used+3), 45, (row-(used+3))/2, (col-45)/2)) == NULL)
      return ERR;

   werase(win);
   keypad(win, TRUE);

   wattron(win, COLOR_PAIR(5));
   box(win, 0, 0);
   mvwprintw(win, 0, 2, " Choose protocol mode ");
   mvwprintw(win, used+2, 2, " ENTER to select  -  ESC/Q to quit ");
   wtimeout(win,NCURSES_KEY_TIMEOUT); /* Block for 100 millisecs...*/

   while (!terms->gui_th.stop && !end) 
   {
      i = 0;
      while (!terms->gui_th.stop && (i < used) )
      {
         if (i == pointer)
            wattron(win, COLOR_PAIR(5) | A_BOLD);
         else
            wattroff(win, COLOR_PAIR(5) | A_BOLD);
         wmove(win, i+1, 1);
         whline(win, ' ', 20);
         mvwprintw(win, i+1, 2, "%-6s %s", protocols[aux[i]].namep, protocols[aux[i]].description);
         if (i == pointer)
            wattroff(win, A_BOLD);

         i++;
      }

      wrefresh(win);

      do
      {
         key_pressed = wgetch(win);
      } while( (key_pressed == ERR) && !terms->gui_th.stop);

      if (!terms->gui_th.stop)
      {
         switch(key_pressed)
         {
            case KEY_DOWN:
               if ( pointer < (used-1))
                  pointer++;
               break;

            case KEY_UP:
               if (pointer > 0)
                  pointer--;
               break;

            case 'Q':
            case 'q':
            case 27:
               end = 1;
               break;
            case 13:
               result = aux[pointer];
               end = 1;
               break;
         }
      }
   }

   werase(win);
   wrefresh(main_window);

   if (delwin(win) == ERR)
      return ERR;

   ncurses_c_set_status_line("");

   return result;
} 
