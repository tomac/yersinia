/* terminal.c
 * Implementation of network terminal management
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
       "$Id: terminal.c 46 2007-05-08 09:13:30Z slay $";
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#define _REENTRANT

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
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

#ifdef SOLARIS
#include <pthread.h>
#include <thread.h>
#else
#include <pthread.h>
#endif


#include "terminal.h"



/*
 * Init terminal list with appropriate values...
 */
int8_t
term_init(void)
{
   int8_t i;
   
   terms = (struct terminals *)calloc(1,sizeof(struct terminals));

   if (terms == NULL)
   {
      thread_error("term_init calloc()", errno);
      return -1;
   }
   
   if (pthread_mutex_init(&terms->mutex, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex", errno);
      return -1;
   }

#ifndef HAVE_RAND_R
   if (pthread_mutex_init(&terms->mutex_rand, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex_rand", errno);
      return -1;
   }
#endif
    
   if (pthread_mutex_init(&terms->pcap_listen_th.finished, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex", errno);
      return -1;
   }

#ifdef HAS_CURSES
   if (pthread_mutex_init(&terms->gui_th.finished, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex", errno);
      return -1;
   }
#endif

#ifdef HAVE_GTK
   if (pthread_mutex_init(&terms->gui_gtk_th.finished, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex", errno);
      return -1;
   }
#endif

   if (pthread_mutex_init(&terms->admin_listen_th.finished, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex", errno);
      return -1;
   }

   if (pthread_mutex_init(&terms->uptime_th.finished, NULL) != 0)
   {
      thread_error("term_init pthread_mutex_init mutex", errno);
      return -1;
   }
   
   term_type[TERM_CON].list = terms->list;
   term_type[TERM_TTY].list = &terms->list[MAX_CON];
   term_type[TERM_VTY].list = &terms->list[MAX_CON+MAX_TTY];

   for (i=0; i<MAX_CON; i++)
   {
       (term_type[TERM_CON].list+i)->type = TERM_CON;
       (term_type[TERM_CON].list+i)->number = i;
   }
   
   for (i=0; i<MAX_TTY; i++)
   {
       (term_type[TERM_TTY].list+i)->type = TERM_TTY;
       (term_type[TERM_TTY].list+i)->number = i;
   }

   for (i=0; i<MAX_VTY; i++)
   {
       (term_type[TERM_VTY].list+i)->type = TERM_VTY;
       (term_type[TERM_VTY].list+i)->number = i;
   }
   
   return 0;
}


/* 
 * Destroy data initialized on term_init().
 * Use global variable terms.
 */
void
term_destroy(void)
{
#ifndef HAVE_RAND_R
   /* Destroy rand mutex used by the vty terms...*/
   pthread_mutex_destroy(&terms->mutex_rand);
#endif

   pthread_mutex_destroy(&terms->admin_listen_th.finished);
   pthread_mutex_destroy(&terms->gui_th.finished);
   pthread_mutex_destroy(&terms->pcap_listen_th.finished);
   pthread_mutex_destroy(&terms->uptime_th.finished);

   /* Destroy terminal list mutex... */
   pthread_mutex_destroy(&terms->mutex);
    
   thread_free_r(terms);
}


/*
 * Add a new terminal node.
 * Parameter '*node' will be NULL if no slots available.
 * Return -1 on error, 0 if Ok.
 * Use global array term_type[]
 */
int8_t
term_add_node(struct term_node **node,
        int8_t type, int32_t sock, pthread_t tid)
{
   int8_t i;
   struct term_vty *vty;
   struct term_console *console;
   struct term_tty *tty;
   struct term_node *new = term_type[type].list;
   
   for (i=0; (i < term_type[type].max) ; i++, new++)
   {
       if (!new->up)
       {  
          new->thread.id   = tid;  
          new->thread.stop = 0;
          if (pthread_mutex_init(&new->thread.finished, NULL) != 0)
          {
             thread_error("term_add_node pthread_mutex_init", errno);
             return -1;
          }
          new->state       = LOGIN_STATE;
		  /* Default value for MAC spoofing is ON (that's evil!) */
          new->mac_spoofing = (tty_tmp->mac_spoofing == -1) ? 1 : tty_tmp->mac_spoofing;
          new->pcap_file.name    = NULL;
          new->pcap_file.pd      = NULL;
          new->pcap_file.pdumper = NULL;          
          new->used_ints = (list_t *) calloc(1, sizeof(list_t));
          new->used_ints->cmp = interfaces_compare;
          
          switch(type)
          {
             case TERM_CON:
                 new->timeout = TTY_TIMEOUT;
                 new->specific = (void *) calloc(1,sizeof(struct term_console));
                 if (new->specific == NULL)
                 {
                    thread_error("term_add_node console calloc()",errno);
                    return -1;
                 }                       
                 console = new->specific;
#if defined (TIOCGWINSZ) && defined (HAVE_NCURSES_RESIZETERM)                       
                 console->need_resize = 0;
#endif
             break;
             
             case TERM_TTY:
                 new->timeout = TTY_TIMEOUT;
                 new->specific = (void *) calloc(1,sizeof(struct term_tty));
                 if (new->specific == NULL)
                 {
                    thread_error("term_add_node tty calloc()",errno);
                    return -1;
                 }
                 tty = new->specific;
                 tty->term = NULL;
                 tty->daemonize = 0;
                 tty->debug = 0;
                 tty->interactive = 0;
                 tty->gtk = 0;
                 tty->attack = -1;
                 tty->config_file[0] = '\0';
             break;
             
             case TERM_VTY:
                 new->timeout = term_states[LOGIN_STATE].timeout;
                 new->specific = (void *) calloc(1,sizeof(struct term_vty));
                 if (new->specific == NULL)
                 {
                    thread_error("term_add_node vty calloc()",errno);
                    return -1;
                 }                       
                 vty = new->specific;
                 vty->width  = MID_TERM_WIDTH;
                 vty->height = MID_TERM_HEIGHT;
                 vty->sock   = sock;
                 vty->insertmode = 1;
             break;
             
          }

          new->up = 1;

          /* initialize the tmp_data structure for each different protocol */
          for (i = 0; i < MAX_PROTOCOLS; i++) 
          {
              if (!protocols[i].visible) 
                 continue;
              new->protocol[i].pcap_file.name    = NULL;
              new->protocol[i].pcap_file.pd      = NULL;
              new->protocol[i].pcap_file.pdumper = NULL;
              strncpy(new->protocol[i].name, protocols[i].namep, MAX_PROTO_NAME);
              new->protocol[i].tmp_data = calloc(1, protocols[i].size);
              if (new->protocol[i].tmp_data == NULL)
              {
                  thread_error("term_add_node tmp_data calloc()", errno);
                  return -1;
              }

              /* Copy the default values */
              memcpy((void *)new->protocol[i].tmp_data, (void *)protocols[i].default_values, protocols[i].size);
              new->protocol[i].proto = protocols[i].proto;
              /* Initialize the default values */
             if (protocols[i].init_attribs)
                 protocols[i].init_attribs(new);
          }

          
          /* Initialize the commands_struct for each protocol */
          for (i = 0; i < MAX_PROTOCOLS; i++) 
          {
              if (!protocols[i].visible) 
                 continue;
              if (protocols[i].init_commands_struct)
              {
                  if ( protocols[i].init_commands_struct(new) == -1)
                      return -1;
              }
          }

          *node = new;
                    
          return 0;
       }
   } /* for...*/

   *node = NULL;
   
   return 0;
}


/*
 * Delete terminal from array.
 * Close peer socket, free command history and release the acquired slot.
 * Kill the thread if kill_th.
 */
void
term_delete_node(struct term_node *node, int8_t kill_th)
{
   int8_t i, type_aux,number_aux;
/*   struct term_console *console;
   struct term_tty *tty;*/
   struct term_vty *vty;

   if (node->up)
   {
      /* First, remove terminal specific data...*/
      switch(node->type)
      {
/*         case TERM_CON:
              console = node->specific;
         break;
         
         case TERM_TTY:
              tty = node->specific;
         break;
*/         
         case TERM_VTY:
              vty = node->specific;
              /* Free history...*/
              for(i=0; i<MAX_HISTORY; i++)
              {
                 if (vty->history[i] != NULL)
                    thread_free_r(vty->history[i]);
              }         

              close(vty->sock);
              
              /* Free transmission buffer...*/
              if (vty->buffer_tx)
                 thread_free_r(vty->buffer_tx);
                    
              if (kill_th == KILL_THREAD)
              {
                 thread_destroy(&node->thread);
              }

         break;
      }
   
      thread_free_r(node->specific);

      for (i = 0; i < MAX_PROTOCOLS; i++)
      {
          if (!protocols[i].visible)
             continue;
          if (node->protocol[i].pcap_file.pdumper)
             interfaces_pcap_file_close(node,i);
          thread_free_r(node->protocol[i].tmp_data);
      }   

      /* free the commands_struct for each protocol */
      for (i = 0; i < MAX_PROTOCOLS; i++) 
      {
          if (!protocols[i].visible)
             continue;
          if (protocols[i].init_commands_struct)
             thread_free_r(node->protocol[i].commands_param);
      }

      /* Preserve terminal type and number...*/
      type_aux = node->type;
      number_aux = node->number;

      dlist_delete(node->used_ints->list);
      if (node->used_ints)
         free(node->used_ints);

      memset(node,0,sizeof(struct term_node));
      
      node->type = type_aux;
      node->number = number_aux;
   } /* if (node->up) */
   
}


/*
 * Delete all terminals from array.
 */
void
term_delete_all(void)
{
   term_delete_all_console();
   term_delete_all_tty();
   term_delete_all_vty();
}


/*
 * Delete all consoles from array.
 * Be aware of using pthread_mutex_lock and unlock
 * before and after calling it!!
 */
void
term_delete_all_console(void)
{
   term_delete_class(term_type[TERM_CON].list, term_type[TERM_CON].max);
}


/*
 * Delete all tty terminals from array.
 * Be aware of using pthread_mutex_lock and unlock
 * before and after calling it!!
 */
void
term_delete_all_tty(void)
{
   term_delete_class(term_type[TERM_TTY].list, term_type[TERM_TTY].max);
}


/*
 * Delete all vty terminals from array.
 * Be aware of using pthread_mutex_lock and unlock
 * before and after calling it!!
 */
void
term_delete_all_vty(void)
{
   term_delete_class(term_type[TERM_VTY].list, term_type[TERM_VTY].max);
}


/*
 * Delete a group of 'max' terminals from array beginning at *cursor.
 * In fact this function just kill the thread associated with the terminal.
 * The thread will be who will delete the data so here we don't need to
 * acquire the terms mutex (each thread will acquire it).
 */
void
term_delete_class(struct term_node *cursor, int8_t max)
{
   int8_t i;

   for (i=0; i<max; i++)
      if (cursor[i].thread.id)
      {
         thread_destroy(&cursor[i].thread); 
         pthread_mutex_destroy(&cursor[i].thread.finished);
      }
}


/*
 * Show the vty banner... (be polite, plz)
 * Return -1 if error. 0 if Ok.
 */ 
int8_t 
term_vty_banner(struct term_node *node)
{
   return(term_vty_write(node, WELCOME, sizeof(WELCOME)) );
}


/*
 * Show the vty motd...)
 * Return -1 if error. 0 if Ok.
 */
int8_t 
term_vty_motd(struct term_node *node)
{
   int8_t j;
   
   j = term_motd();

   if (j < 0)
      return -1;
      
   if (term_vty_write(node, (void *)vty_motd[j], strlen(vty_motd[j])))
      return -1;
   
   return 0;
}



int8_t 
term_motd(void)
{
   int8_t j;
#ifdef HAVE_RAND_R
   unsigned int i=(int)time(NULL);

   j = rand_r(&i);
#else

   if (pthread_mutex_lock(&terms->mutex_rand) != 0)
   {
      thread_error("term_motd pthread_mutex_lock()",errno);
      return -1;
   }

   j=rand();
   
   if (pthread_mutex_unlock(&terms->mutex_rand) != 0)
   {
      thread_error("term_motd pthread_mutex_unlock()",errno);
      return -1;
   }

#endif
   
   j = j % SIZE_ARRAY(vty_motd);

   return j;
}


/*
 * Write the vty prompt.
 * Return -1 if error. 0 if Ok.
 */
int8_t
term_vty_prompt(struct term_node *node)
{
   struct term_vty *vty = node->specific;
   
   switch(node->state)
   {
      case LOGIN_STATE:
      case PASSWORD_STATE:
             return( term_vty_write(node, term_states[node->state].prompt2,
                       strlen(term_states[node->state].prompt2))
                   );
      break;
      
      case NORMAL_STATE:
             if (vty->authing)
                return(term_vty_write(node, term_states[node->state].prompt_authing,
                       strlen(term_states[node->state].prompt_authing)));
            
             return( term_vty_write(node, term_states[node->state].prompt2,
                       strlen(term_states[node->state].prompt2)));
      break;
      
      case ENABLE_STATE:
             if (vty->authing)
                return(term_vty_write(node, term_states[node->state].prompt_authing,
                       strlen(term_states[node->state].prompt_authing)));

             return( term_vty_write(node, term_states[node->state].prompt2,
                       strlen(term_states[node->state].prompt2))
                   );
      break;

      case PARAMS_STATE:
             if (term_vty_write(node,"[",1) < 0)
                return -1;
             if (term_vty_write(node, vty->attack_param[vty->substate].desc,
                                strlen(vty->attack_param[vty->substate].desc)) < 0)
                return -1;
             return (term_vty_write(node,"] ",2));
      break;
      
      case INTERFACE_STATE:
             return( term_vty_write(node, term_states[node->state].prompt2,
                 strlen(term_states[node->state].prompt2))
             );
      break;
   }
   
   return -1;
}



/*
 * Send the vty telnet negotiation.
 * Return -1 if error. Return 0 if Ok.
 */
int8_t
term_vty_negotiate(struct term_node *node)
{
   if (term_vty_write(node, (char *)neg_default, sizeof(neg_default)))
      return -1;
   
   return 0;
}


/*
 * Write to terminal.
 * Return -1 on error. Return 0 if OKk.
 */
int8_t
term_write(struct term_node *node, char *message, u_int16_t size)
{
   struct term_vty *vty = node->specific;

   switch(node->type)
   {
      case TERM_CON:
      break;
      
      case TERM_TTY:
      break;
      
      case TERM_VTY:
            if (write(vty->sock, message, size) <= 0 )
            {
               thread_error("term_write write()",errno);
               return -1;   
            }
      break;
      
      default:
      break;
   }
   
   return 0;
}


/*
 * Move cursor to beginning of line.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t
term_vty_mv_cursor_init(struct term_node *node)
{
   struct term_vty *vty = node->specific;

   int8_t control = DEL;
   
   if (!vty->command_cursor)
      return 0;
      
   while(vty->command_cursor)
   {
      if ( term_vty_write(node,(char *)&control,1) == -1)
         return -1;
      vty->command_cursor--;
   }
         
   return 0;
}


/*
 * Move cursor to the left.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t
term_vty_mv_cursor_left(struct term_node *node)
{
   struct term_vty *vty = node->specific;

   int8_t control = DEL;
   
   if (!vty->command_cursor)
      return 0;
      
   if ( term_vty_write(node,(char *)&control,1) )
      return -1;

   if (term_vty_flush(node))
      return -1;
      
   vty->command_cursor--;
         
   return 0;
}


/*
 * Move cursor to the right.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t
term_vty_mv_cursor_right(struct term_node *node)
{
   struct term_vty *vty = node->specific;

   if (!vty->command_len)
      return 0;
      
   if (vty->command_cursor == vty->command_len )
      return 0;
   
   if ( term_vty_write(node,(char *)&vty->buf_command[vty->command_cursor],
         1) )
      return -1;
      
   if ( term_vty_flush(node))
      return -1;

   vty->command_cursor++;

   return 0;
}


/*
 * Move cursor to end of line.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t
term_vty_mv_cursor_end(struct term_node *node)
{
   struct term_vty *vty = node->specific;
   
   if (!vty->command_len)
      return 0;
      
   if (vty->command_cursor == vty->command_len )
      return 0;

   while(vty->command_cursor != vty->command_len)
   {   
      if ( term_vty_write(node,
                       (char *)&vty->buf_command[vty->command_cursor],1) )
         return -1;
      vty->command_cursor++;
   }
   
   return 0;
}


/*
 * Delete the character on cursor.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t
term_vty_supr(struct term_node *node)
{
   struct term_vty *vty = node->specific;
    
   if (vty->command_len)
   {
      if (vty->command_cursor != vty->command_len )
      {
         u_int16_t len;
         char *auxstr, *message=NULL;
         
         if (vty->command_cursor == (vty->command_len - 1) )
            len=1;
         else
            len = vty->command_len - vty->command_cursor;

         if (vty->command_cursor == (vty->command_len - 1) )
            auxstr = strdup(&vty->buf_command[vty->command_cursor]);
         else
            auxstr = strdup(&vty->buf_command[vty->command_cursor+1]);

         memcpy( &vty->buf_command[vty->command_cursor], auxstr,  len);
         
         free(auxstr);
         
         vty->command_len--;
         vty->buf_command[vty->command_len]=0;

         if (term_states[node->state].do_echo)
         {               
             if (term_vty_clear_line(node,len) == -1)
                return -1;
             if (term_vty_write(node, &vty->buf_command[vty->command_cursor], len) == -1)
                return -1;
             if (len-1)
             {
                message = (char *)malloc(len-1); 
                memset(message, DEL, len-1);
                if (term_vty_write(node, message,len-1) == -1)
                {
                   free(message);
                   return -1;
                }
             }
             if (term_vty_flush(node) == -1)
             {
                if (message) 
                   free(message);
                return -1;
             }
             if (message)
                free(message);
         }
      }
   }

   return 0;
}


/*
 * Do command.
 * Return -1 on error. 0 if OK.
 */
int8_t
term_vty_do_command(struct term_node *node)
{
   int16_t i;
   int8_t gotit=0, fail=0;
   char msg[128];
   struct words_array *warray;
   struct term_vty *vty = node->specific;
   
   if (!vty->command_len && !vty->authing)
      return 0;
         
   vty->buf_command[vty->command_len]=0;

   switch(node->state)
   {
      case LOGIN_STATE: strncpy(node->username,vty->buf_command,
                                  sizeof(node->username));
                        node->state = PASSWORD_STATE;
                        vty->authing = 1;
      break;
      
      case PASSWORD_STATE:
                   if (term_vty_auth(PASSWORD_STATE, node->username,
                                      vty->buf_command) == -1)
                   {
                      vty->login_fails++;
                      if (term_vty_write(node,VTY_FAILED,sizeof(VTY_FAILED)) == -1)
                         return -1;
                      if (term_vty_flush(node) == -1)
                         return -1;
                      node->state = LOGIN_STATE;
                      vty->authing = 0;
                      term_vty_clear_username(node);
                      if (vty->login_fails == MAX_FAILS)
                      {  
                         if (term_vty_write(node,VTY_GO_OUT,sizeof(VTY_GO_OUT)) == -1)
                            return -1;
                         term_vty_flush(node);
                         return -1; 
                      }
                      return 0;
                   }
                   vty->login_fails = 0;
                   vty->authing = 0;
                   node->state = NORMAL_STATE;
                   node->timeout = term_states[NORMAL_STATE].timeout;
                   
                   if (term_vty_motd(node) == -1)
                      return -1;
                   if (term_vty_flush(node) == -1)
                      return -1;
      break;
      
      case NORMAL_STATE:
                         if (vty->authing)
                         {
                             if (term_vty_auth(NORMAL_STATE, NULL,
                                                vty->buf_command) == -1)
                             {
                                vty->login_fails++;
                                term_vty_clear_command(node);
                                if (vty->login_fails == MAX_FAILS)
                                {  
                                   vty->authing=0;
                                   vty->login_fails=0; 
                                }
                                return 0;
                             }
                             vty->login_fails = 0;
                             vty->authing = 0;
                             node->state = ENABLE_STATE;
                             break;
                         }

      case ENABLE_STATE: 
                         for(i=0;i<vty->command_len;i++)
                         {
                            if (*(vty->buf_command+i) != SPACE)
                            {
                               gotit=1;
                               break;
                            }
                         }
                           
                         if (!gotit)
                         {
                            term_vty_clear_command(node);
                            return 0;
                         }

                         if (term_vty_history_add(node, vty->buf_command, 
                                                  vty->command_len) == -1)
                            return -1;
               
                         vty->more_tx = vty->buffer_tx;
                         
                         warray = (struct words_array *)calloc(1,sizeof(struct words_array));
                         if (warray == NULL)
                            return -1;
                         if (term_vty_set_words(node, warray) == -1)
                         {
                            term_vty_free_words(warray);
                            return -1;
                         }
#ifdef HAVE_REMOTE_ADMIN                         
                         if (command_entry_point(node,warray,0,0,0) == -1)
                         {
                            term_vty_free_words(warray);
                            return -1;
                         }
#endif                         
                         term_vty_free_words(warray);

      break;
      
      case PARAMS_STATE:
                         for(i=0;i<vty->command_len;i++)
                         {
                            if (*(vty->buf_command+i) != SPACE)
                            {
                               gotit=1;
                               break;
                            }
                         }
                           
                         if (!gotit)
                         {
                            term_vty_clear_command(node);
                            return 0;
                         }

                         warray = (struct words_array *)calloc(1,sizeof(struct words_array));
                         if (warray == NULL)
                         {
                            thread_error("do_command warray calloc()", errno);
                            node->state = ENABLE_STATE;
                            attack_free_params(vty->attack_param, vty->nparams);
                            free(vty->attack_param);
                            vty->attack_param = NULL;
                            vty->nparams = 0;
                            return -1;
                         }
                         
                         if (term_vty_set_words(node, warray) == -1)
                         {
                            term_vty_free_words(warray);
                            node->state = ENABLE_STATE;
                            attack_free_params(vty->attack_param, vty->nparams);
                            free(vty->attack_param);
                            vty->attack_param = NULL;
                            vty->nparams = 0;
                            return -1;
                         }
                         if (warray->nwords != 1)
                         {
                             term_vty_free_words(warray);                         
                             snprintf(msg,sizeof(msg),"\r\n%% Invalid data!!\r\n");
                             fail = term_vty_write(node,msg, strlen(msg));
                             term_vty_clear_command(node);                             
                             node->state = ENABLE_STATE;
                             attack_free_params(vty->attack_param, vty->nparams);
                             free(vty->attack_param);
                             vty->attack_param = NULL;
                             vty->nparams = 0;
                             return fail;                         
                         }
                         
                         vty->attack_param[vty->substate].print = strdup(warray->word[0]);
                         
                         if (vty->attack_param[vty->substate].print == NULL)
                         {
                            thread_error("do_command strdup()", errno);
                            term_vty_free_words(warray);                         
                            term_vty_clear_command(node);                             
                            node->state = ENABLE_STATE;
                            attack_free_params(vty->attack_param, vty->nparams);
                            free(vty->attack_param);
                            vty->attack_param = NULL;
                            vty->nparams = 0;                            
                            return -1;                         
                         }
                         
                         if (parser_filter_param(vty->attack_param[vty->substate].type,
                                                 vty->attack_param[vty->substate].value,
                                                 vty->attack_param[vty->substate].print,
                                                 vty->attack_param[vty->substate].size_print,
                                                 vty->attack_param[vty->substate].size ) < 0 )

                         {
                             term_vty_free_words(warray);                         
                             snprintf(msg,sizeof(msg),"\r\n%% Invalid data!!\r\n");
                             fail = term_vty_write(node,msg, strlen(msg));
                             term_vty_clear_command(node);                             
                             free(vty->attack_param[vty->substate].print);
                             vty->attack_param[vty->substate].print = NULL;
                             return fail;
                         }
                         if ((vty->substate+1) == vty->nparams) /* Last parameter */
                         {
                            attack_launch(node, vty->attack_proto, vty->attack_index,
                                          vty->attack_param, vty->nparams);
                            node->state = ENABLE_STATE;
                            vty->attack_param = NULL;
                            vty->nparams = 0;
                         }
                         else
                         {
                            vty->substate++;
                         }
                         term_vty_free_words(warray);                         
      
      break;
      
      case INTERFACE_STATE: if (term_vty_history_add(node, vty->buf_command,
                                                          vty->command_len) == -1)
                            return -1;
                            vty->more_tx = vty->buffer_tx;
                            term_vty_write(node,"\r\n",2);
      break;
   }
   
   term_vty_clear_command(node);
   
   return 0;
}



void
term_vty_clear_username(struct term_node *node)
{
   
   memset(node->username,0,sizeof(node->username));
   
   term_vty_clear_command(node);
}


void
term_vty_clear_command(struct term_node *node)
{
   struct term_vty *vty = node->specific;
      
   memset(vty->buf_command, 0, MAX_COMMAND);
          
   vty->command_len = vty->command_cursor = 0;
}



int8_t
term_vty_exit(struct term_node *node)
{
   struct term_vty *vty = node->specific;

   switch(node->state)
   {
      case LOGIN_STATE:
      case PASSWORD_STATE:
      case NORMAL_STATE: /* Ok, exit from normal state is like going out...*/
            return -1;
      break;
      
      case ENABLE_STATE:
            node->state = NORMAL_STATE;
      break;

      case PARAMS_STATE:
            attack_free_params(vty->attack_param, vty->nparams);
            free(vty->attack_param);
            vty->attack_param = NULL;
            vty->nparams = 0;
            node->state = ENABLE_STATE;
      break;
                        
      case INTERFACE_STATE:
            node->state = ENABLE_STATE;
      break;
   }
   
   return 0;
}


int8_t
term_vty_clear_screen(struct term_node *node)
{
#ifdef HAVE_REMOTE_ADMIN
   return (command_cls(node, NULL, 0, 0, 0));
#else
   return 0;
#endif   
}


/*
 * Do vty auth.
 * Return -1 if error. Return 0 if auth Ok.
 */
int8_t
term_vty_auth(int8_t state, char *username, char *password)
{
  if ( state == PASSWORD_STATE) /* Normal? */
  {
     if ( ( strlen(username) == strlen(tty_tmp->username) ) && 
            !strcmp(username, tty_tmp->username) &&
          ( strlen(password) == strlen(tty_tmp->password) ) && 
            !strcmp(password, tty_tmp->password)
        )
        return 0;
     return -1;
  }
  
  if (state == NORMAL_STATE) /* Enable? */
  {
     if ( (strlen(password) == strlen(tty_tmp->e_password)) && 
          !strcmp(password, tty_tmp->e_password) )
        return 0;
     
     return -1;
  }

  return -1;
}


/*
 * Add command to history
 * Return -1 if error. Return 0 if OK.
 */
int8_t
term_vty_history_add(struct term_node *node, char *command, u_int16_t len)
{
   int8_t aux;
   struct term_vty *vty = node->specific;

   /* First ask for a free history slot (not updating)...*/
   aux = term_vty_history_get_slot(vty->history, HIST_INDEXING, MAX_HISTORY);
   
   if ( vty->history[aux] &&
        !strcmp(command, vty->history[aux]))
   {
      vty->index_history = aux;  
      return 0;
   }

   aux = term_vty_history_get_slot(vty->history, HIST_UPDATING, MAX_HISTORY);   

   vty->history[aux]=(char *)thread_calloc_r((len+1));

   if (vty->history[aux] == NULL)
   {
      thread_error("term_vty_history_add calloc()",errno);
      return -1;
   }

   memcpy(vty->history[aux],command,len);

   vty->index_history = aux;  
   
   return 0;
}


/*
 * Find a free history slot.
 * Return history slot index. 
 * If 'do_move' then we move the history array
 * freeing the first element.
 * If 'do_move==0' we return only the index and move/free nothing.
 */
int8_t
term_vty_history_get_slot(char *history[], int8_t do_move, int8_t max_index)
{
   int8_t i;
   
   for( i=0; i<max_index; i++)
   {
      if (history[i] == NULL)
         return i;
   }
   
   /* Ok. There is no free slot...*/
   /* Do we update the history or just return the index? */
   if (do_move)
   {
      /* Move history and free the first slot...*/
      thread_free_r(history[0]);

      for(i=0; i<max_index; i++)
      {
         if ( i == (max_index-1) ) /* Last slot?*/
            break;
         history[i] = history[i+1];
      }   

      history[i]=NULL;

      return i;
   }

   return (i-1);
}


/*
 * Arrow up!!
 * Return -1 on error. Return 0 if OK.
 */
int8_t 
term_vty_history_prev(struct term_node *node)
{
   struct term_vty *vty = node->specific;
   
   if ( vty->history[vty->index_history] == NULL )
      return 0;

   if ( !strcmp(vty->history[vty->index_history],vty->buf_command) &&
        !vty->index_history)
      return 0;

   if (term_vty_clear_remote(node) == -1)
      return -1;
    
   term_vty_clear_command(node); /* It's necessary?...*/
   
   /* From history buffer to command buffer...*/
   
   memcpy(vty->buf_command, vty->history[vty->index_history],
          strlen(vty->history[vty->index_history]));

   vty->command_len = strlen(vty->history[vty->index_history]);
   vty->command_cursor = strlen(vty->history[vty->index_history]);

   if ( term_vty_write(node, vty->history[vty->index_history],
             strlen(vty->history[vty->index_history])) == -1)
      return -1;
   
   if (term_vty_flush(node) == -1)
      return -1;
      
   if (vty->index_history)
      vty->index_history--;

   return 0;
}



/*
 * Arrow down...
 * Return -1 on error. Return 0 if OK.
 */
int8_t 
term_vty_history_next(struct term_node *node)
{
   int8_t aux;
   struct term_vty *vty = node->specific;
      
   aux = vty->index_history;
   
   if ( (vty->history[aux] == NULL) ||
        (aux == (MAX_HISTORY-1) ) )
   {
      if (vty->command_len)
      {
         if (term_vty_clear_remote(node) == -1)
            return -1;
         if (term_vty_flush(node) == -1)
            return -1;
      }
      term_vty_clear_command(node);

      return 0;
   }

   if ( !strcmp(vty->history[vty->index_history],vty->history[aux]))
      aux++;

   if ( (aux) < MAX_HISTORY )
   {
      if ( vty->history[aux] == NULL )
      {
         if (vty->command_len)
         {
            if (term_vty_clear_remote(node) == -1)
               return -1;
            if (term_vty_flush(node) == -1)
               return -1;
         }
         term_vty_clear_command(node);
         return 0;
      }

      if (term_vty_clear_remote(node) == -1)
         return -1;

      term_vty_clear_command(node); /* It's necessary?...*/

      /* From history buffer to command buffer...*/
      memcpy(vty->buf_command, vty->history[aux],
             strlen(vty->history[aux]));

      vty->command_len = vty->command_cursor = strlen(vty->history[aux]);

      if ( term_vty_write(node, vty->history[aux],
                strlen(vty->history[aux])) == -1)
         return -1;
      
      if (term_vty_flush(node) == -1)
         return -1;

      vty->index_history=aux;

   }

   return 0;   
}



/*
 * TAB pressed. Complete a command (not yet).
 * Return -1 if error. Return 0 if Ok.
 */
int8_t
term_vty_complete_command(struct term_node *node)
{
   int8_t fail;
   
   fail = term_vty_help_tab(node,1);
   
   return fail;
}


/*
 * backspace pressed.
 * Return -1 if error. Return 0 if Ok.
 */
int8_t
term_vty_backspace(struct term_node *node)
{
   struct term_vty *vty = node->specific;
    
   if (vty->command_len && vty->command_cursor)
   {
      if (vty->command_cursor == vty->command_len )
      {
          if (term_states[node->state].do_echo && !vty->authing)
          {      
             if (term_vty_write(node, DEL_BACK, sizeof(DEL_BACK)) == -1)
                return -1;
             if (term_vty_flush(node) == -1)
                return -1;
          }
          vty->buf_command[vty->command_len-1]=0;
          vty->command_len--;
          vty->command_cursor--;
      }
      else
      {
         u_int16_t len;
         char *message;
         
         len = vty->command_len - vty->command_cursor;
         memcpy( &vty->buf_command[vty->command_cursor-1],
                 &vty->buf_command[vty->command_cursor],  len);
         
         vty->buf_command[vty->command_len-1]=0;
         vty->command_len--;
         vty->command_cursor--;

         if (term_states[node->state].do_echo && !vty->authing)
         {               
             if (term_vty_clear_line(node,len) == -1)
                return -1;
             if (term_vty_write(node, DEL_BACK, sizeof(DEL_BACK)) == -1)
                return -1;
             if (term_vty_write(node, &vty->buf_command[vty->command_cursor], len) == -1)
                return -1;
             message = (char *)malloc(len);
             if (message == NULL)
             {
                thread_error("term_vty_backspace malloc()",errno);
                return -1;
             }
             memset(message, DEL, len);
             if (term_vty_write(node, message, len) == -1)
             {
                free(message);
                return -1;
             }
             if (term_vty_flush(node) == -1)
             {
                free(message);
                return -1;
             }
             free(message);
         }
      }
   }

   return 0;
}



/*
 * ? pressed. Show the help.
 * Return -1 if error. Return 0 if Ok.
 */
int8_t
term_vty_help(struct term_node *node)
{
   int8_t fail;
   
   fail = term_vty_help_tab(node,0);
   
   return fail;
}


int8_t
term_vty_help_tab(struct term_node *node, int8_t tab)
{
   int8_t ret;
   int8_t as_param=0;
   struct words_array *warray;
   struct term_vty *vty = node->specific;
   
   vty->buf_command[vty->command_len] = 0;
   
   if (vty->command_len)
   {
      if (vty->buf_command[vty->command_len-1] == SPACE)
         as_param = 1;
   }

   vty->command_cursor = vty->command_len;

   warray = (struct words_array *)calloc(1,sizeof(struct words_array));

   if (warray == NULL)
   {
      thread_error("term_vty_help_tab calloc()",errno);
      return -1;
   }
   
   if (term_vty_set_words(node, warray) == -1)
   {
      term_vty_free_words(warray);
      return -1;
   }

#ifdef HAVE_REMOTE_ADMIN
   if (tab)
      ret = command_entry_point(node,warray,0,as_param,1);
   else
      ret = command_entry_point(node,warray,1,as_param,0);   
#endif

   term_vty_free_words(warray);

   return ret;   
}


/*
 * Clear remote command buffer (that is, on client screen)
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
term_vty_clear_remote(struct term_node *node)
{
   char buf_tx[MAX_COMMAND*3];
   int16_t aux_len, len;
   struct term_vty *vty = node->specific;
      
   if (!vty->command_len)
      return 0;
   
   memset(buf_tx, DEL, (vty->command_len*3) );

   if (vty->command_len > vty->command_cursor)
      aux_len = vty->command_cursor;
   else
      aux_len = vty->command_len;
   
   len=aux_len;
   
   memset( (char *)&buf_tx[aux_len], SPACE, vty->command_len);

   len+=vty->command_len;
   len+=vty->command_len;

   if (term_vty_write(node, buf_tx, len) == -1)
      return -1;

   return 0;
}


/*
 * Clear a remote line screen.
 * Remote cursor must be at beginning of line and 'size' must be size of line.
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
term_vty_clear_line(struct term_node *node, u_int16_t size)
{
   char *buf_tx;
   
   buf_tx = (char *)calloc(1,(size*2));

   if (buf_tx == NULL)
   {
      thread_error("term_vty_clear_line malloc()",errno);
      return -1;
   }
   
   memset(buf_tx, SPACE, size);
   
   memset((buf_tx+size), DEL, size);

   if (term_vty_write(node, buf_tx, (size*2)) == -1)
   {
      thread_free_r(buf_tx);
      return -1;
   }
   
   thread_free_r(buf_tx);
   
   return 0;
}



/*
 * Flush the buffer_tx terminal
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
term_vty_flush(struct term_node *node)
{
   int8_t fail=0, more=0;
   void *aux;
   struct term_vty *vty = node->specific;
         
   if (!vty->buffer_tx || !vty->buffer_tx_len) 
      return 0;

   if ( (node->state == LOGIN_STATE) || (node->state == PASSWORD_STATE) )
   {
      fail = term_write(node,vty->buffer_tx,vty->buffer_tx_len);
      thread_free_r(vty->buffer_tx);
      vty->buffer_tx = NULL;
      vty->buffer_tx_len = 0;
      return fail;
   }
   
   if (vty->more_tx==NULL)
      aux = vty->buffer_tx;
   else
      aux = vty->more_tx;
         
   more = term_vty_more(node);

   if (vty->buffer_tx == vty->more_tx)
      fail = term_write(node, aux, vty->buffer_tx_len);
   else
      fail = term_write(node, aux, (vty->more_tx - aux));

   if (more)
   {   
      if (!fail)
         fail = term_write(node, VTY_MORE, strlen(VTY_MORE));
      vty->moremode = 1;
   }
   else
   {
      thread_free_r(vty->buffer_tx);
      vty->buffer_tx     = NULL;
      vty->more_tx       = NULL;
      vty->buffer_tx_len = 0;
      vty->more_tx_len   = 0;
      vty->moremode      = 0;   
   }
   
   return fail;
}



/*
 * Return -1 if buffer is greater than terminal (so use 'more' mode).
 * Return 0 otherwise.
 */
int8_t
term_vty_more(struct term_node *node)
{
   int16_t i,caracs=0, lines=0, buff_size;
   void *buffer, *buff_end;
   struct term_vty *vty = node->specific;
   
   buff_end = (vty->buffer_tx + vty->buffer_tx_len);
   
   if (vty->more_tx == NULL)
      vty->more_tx = vty->buffer_tx;
  
   buffer = vty->more_tx;
   buff_size = (buff_end-buffer);   
   
   for (i=0; i<buff_size; i++, buffer++)
   { 
      if (caracs && !(caracs%vty->width))
      {
         lines++;
         if (!(lines%vty->height))
         { 
            vty->moremode=1;
            vty->more_tx_len = (buffer - vty->more_tx);
            vty->more_tx = buffer; 
            return -1;
         }
         caracs=0;
         continue;
      }
      
      switch(* (char *)buffer)
      { 
         case '\n': lines++;
                    if (!(lines%vty->height))
                    {
                       vty->moremode=1;
                       vty->more_tx_len = (buffer - vty->more_tx);
                       vty->more_tx = buffer;
                       return -1;
                    }
                    caracs=0;
                    break;
         default: caracs++;
                  break;
      }
   }

   vty->more_tx_len = (buffer - vty->more_tx);
   vty->more_tx = buffer;

   return 0;
}



/*
 * Write data to vty.
 * Return -1 if error. Return 0 if Ok.
 */
int8_t
term_vty_write(struct term_node *node, char *message, u_int16_t size)
{
   if (term_vty_buffer_add(node, message, size) == -1)
      return -1;
      
   return 0;
}


/*
 * Add data to outgoing buffer.
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
term_vty_buffer_add(struct term_node *node, void *buffer, u_int16_t size)
{
   void *aux;
   struct term_vty *vty = node->specific;
   
   if (!buffer || !size)
      return 0;

   aux = calloc(1,(vty->buffer_tx_len+size));

   if (aux == NULL)
   {
      thread_error("term_vty_buffer_add calloc()",errno);
      return -1;
   }

   if (vty->buffer_tx_len)
      memcpy( aux, vty->buffer_tx, vty->buffer_tx_len );

   memcpy( (aux+vty->buffer_tx_len), buffer, size);

   vty->buffer_tx_len += size;

   thread_free_r(vty->buffer_tx);

   vty->buffer_tx = aux;

   return 0;
}



int8_t
term_vty_set_words(struct term_node *node, struct words_array *warray)
{
   struct term_vty *vty = node->specific;
   char *begin;   
   u_int16_t i, j, aux=0, indx=0;
   
   for(i=0;i<vty->command_len;i++)
   {
      if (*(vty->buf_command+i) != SPACE)
      {
         begin = vty->buf_command+i;
         j=0;
         while( (*(begin+j)!=SPACE) && *(begin+j))
           j++;
         if (*(begin+j) == SPACE)
         {
            aux=1;
            *(begin+j) = 0;
         }
         else
            aux=0;
         warray->nwords++;
         warray->word[indx]=strdup(begin);
         if (warray->word[indx]==NULL)
            return -1;
         if (warray->nwords == MAX_WORDS)
         {
            if (aux)
               *(begin+j) = SPACE;
            break;
         }            
         if (aux)
            *(begin+j) = SPACE;
         indx++;
         i+=j;
      }
   }

   return 0;   
}


/*
 * Free words array structure...
 */
void
term_vty_free_words(struct words_array *warray)
{
   u_int8_t i;
   
   for (i=0; i<warray->nwords; i++)
       if (warray->word[i])
          free(warray->word[i]);

   free(warray);
}



/*
 * Completion command for '*word'. Used if TAB pressed.
 */
int8_t
term_vty_tab_subst(struct term_node *node, char *word, char *comm)
{
   struct term_vty *vty = node->specific;
   char *aux, *aux2;
   u_int16_t i, spaces, diff;
   int16_t res;

   spaces = 0;
   i = vty->command_len-1;

   while(1)
   {
      if (*(vty->buf_command+i) != SPACE)
      {
         aux=(vty->buf_command+i);
         break;
      }
      spaces++;
      i--;
   }

   diff = (strlen(comm)-strlen(word));

   res = vty->command_len - spaces + diff + 1;

   if (diff == 0) /* Exact word, just add another ' ' */
   {
      if (res<MAX_COMMAND)
      {
         if (vty->command_len < res)
         {
             *(aux+1) = ' ';
            vty->command_len++;
            vty->command_cursor++;
            vty->buf_command[vty->command_len] = 0;
         }
      }
      return 0;
   }

   aux2 = (comm+strlen(word));

   if (res<MAX_COMMAND)
   {
      if (res > vty->command_len)
      {
         memcpy((aux+1),aux2,strlen(aux2));
         vty->buf_command[vty->command_len+strlen(aux2)] = ' ';
         vty->command_len+=strlen(aux2)+1;
         vty->command_cursor+=strlen(aux2)+1;
         vty->buf_command[vty->command_len] = 0;
         return 0;
      }
   }

   return 0;
}
