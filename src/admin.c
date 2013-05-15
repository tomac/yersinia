/* admin.c
 * Network server thread
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
       "$Id: admin.c 43 2007-04-27 11:07:17Z slay $";
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
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#endif

#include "admin.h"



int8_t 
admin_init(struct term_tty *node)
{
   if (thread_create(&terms->admin_listen_th.id, &admin_th_listen, 
        (void *)node) < 0)
      return -1;

   return 0;
}



/*
 * Thread that listen for peers connections.
 * Spawn a thread per peer...
 */ 
void *
admin_th_listen(void *arg)
{
   struct sockaddr *cliaddr=NULL;
   struct sockaddr_in server_address;
   struct timeval timeout;
   struct filter *ip_filter;
   struct term_tty *node;
   int32_t sock=0, sock2, on=1,n,ret;
   socklen_t clilen;
   pthread_t tid;
   sigset_t mask;
   fd_set read_set;
   
write_log(0,"\n admin_th_network_listen es %d\n",(int)pthread_self());

   pthread_mutex_lock(&terms->admin_listen_th.finished);

   sigfillset(&mask);

   if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
   {
      thread_error("th_listener pthread_sigmask()",errno);
      admin_th_listen_exit(NULL,0);
   }

   node = (struct term_tty *)arg;
   ip_filter = (struct filter *)node->ip_filter;
   
   if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
   {
      n=errno;   
      thread_error("Error on socket()",n);
      admin_th_listen_exit(NULL,0);
   }

   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,sizeof(on)) < 0)
   {
      n=errno;   
      thread_error("Error on setsockopt(SO_REUSEADDR)",n);
      admin_th_listen_exit(NULL,sock);
   }

#ifdef SO_REUSEPORT
   on=1;
   if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *) &on, sizeof (on)) 
       < 0)
   {
      n=errno;   
      thread_error("Error on setsockopt(SO_REUSEPORT)",n);
      admin_th_listen_exit(NULL,sock);
   }
#endif

   on=1;
   if (setsockopt (sock, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof (on))
         < 0)
   {
      n=errno;   
      thread_error("Error on setsockopt(TCP_NODELAY)",n);
      admin_th_listen_exit(NULL,sock);
   }

   server_address.sin_family      = AF_INET;
   server_address.sin_port        = htons(node->port);
   server_address.sin_addr.s_addr = htonl(INADDR_ANY);
          
   if ( bind( sock, (struct sockaddr *)&server_address,
              sizeof(server_address) ) == -1 )
   {
      n=errno;   
      thread_error("Error on bind()",n);
      admin_th_listen_exit(NULL,sock);
   }

   if (listen(sock,5) == -1)
   {
      n=errno;   
      thread_error("Error on listen",n);
      admin_th_listen_exit(NULL,sock);
   }

   cliaddr=(struct sockaddr *)malloc(sizeof(struct sockaddr));

   if (cliaddr == NULL)
   {
      n=errno;   
      thread_error("malloc()",n);
      admin_th_listen_exit(NULL,sock);
   }
   
   while(!terms->admin_listen_th.stop)
   {
      FD_ZERO(&read_set);
      FD_SET(sock,&read_set);
      timeout.tv_sec = 0;
      timeout.tv_usec= 250000;
      if ((ret = select(sock+1, &read_set, NULL, NULL, &timeout)) == -1)
      {
         n=errno;   
         thread_error("admin_listen select()",n);
         break;
      }
      if (ret)
      {
          struct in_addr *ip_addr;
          
          clilen=sizeof(struct sockaddr);
          if ( (sock2 = accept( sock, cliaddr, (socklen_t *)&clilen)) == -1)
          {
             n=errno;   
             thread_error("Error on accept",n);
             admin_th_listen_exit(cliaddr,sock);
          }

          ip_addr = (struct in_addr *)&cliaddr->sa_data[2];
          
          if (admin_filter_ip((u_int32_t *)&ip_addr->s_addr,ip_filter) < 0)
          {
             write_log(0,"\n Connection refused for %s!!\n", inet_ntoa(*ip_addr));
             close(sock2);
          }
          else
          {
              write_log(0,"\n Connection accepted for %s\n", inet_ntoa(*ip_addr));
              if (pthread_create(&tid, NULL, &admin_th_network_peer, 
                          (void *)sock2) < 0)
              {
                 n=errno;   
                 thread_error("pthread_create admin_th_listen",n);
                 admin_th_listen_exit(cliaddr,sock);
              }
          }
      }
   }

   admin_th_listen_exit(cliaddr, sock);
   
   pthread_exit(NULL);
}


int8_t
admin_filter_ip(u_int32_t *ip_addr, struct filter *ip_filter)
{
   struct filter *cursor;
   u_int32_t ipaddr;

   cursor = ip_filter;

   if (!cursor)
      return 0;   
   
   ipaddr = ntohl((*ip_addr));

   while(cursor)
   {
      if ( ( ipaddr >= cursor->begin) &&
          ( ipaddr <= cursor->end) )
      {
         write_log(0,"IP Matched between %08X and %08X...\n",cursor->begin, cursor->end);
         return 0;
      }
      cursor = cursor->next;
   }
   
   return -1;
}

/*
 * We arrived here due to normal termination
 * from thread listener main routine...
 * Release resources and delete all acquired network terminals...
 */
void
admin_th_listen_exit(struct sockaddr *cliaddr, int32_t sock)
{
   if (cliaddr)
      thread_free_r(cliaddr);

   term_delete_all_vty();
   
   if (sock)
      close(sock);
   
   terms->admin_listen_th.id = 0;

   if (!terms->admin_listen_th.stop)
   {
       /* Tell parent that we are going to die... */
      fatal_error--;
   }

   pthread_mutex_unlock(&terms->admin_listen_th.finished);
   
   pthread_exit(NULL); 
}



/*
 * Thread to communicate with peer
 */
void *
admin_th_network_peer(void *sock)
{
   int16_t  n, bytes, i, fail, quantum;
   int32_t ret;
   socklen_t len;
   u_char buf[MAX_LINE+2];
   time_t this_time;
   fd_set read_set;
   struct sockaddr_in name;
   struct timeval timeout;
   struct term_vty *vty;
   struct term_node *term_node=NULL;

   memset(buf, 0, MAX_LINE+2);

write_log(0,"vty peer %d mutex_lock terms \n",pthread_self());
   
   if (pthread_mutex_lock(&terms->mutex) != 0)
      thread_error("th_network_peer pthread_mutex_lock",errno);

   fail = term_add_node(&term_node, TERM_VTY, (int)sock, pthread_self());

   if (fail == -1)
   {
      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_network_peer pthread_mutex_unlock",errno);
      admin_th_network_peer_exit(term_node, (int32_t)sock);
   }
    
   if (term_node == NULL)
   {
      write_log(0,"Ouch!! No more than %d %s accepted!!\n", 
                  term_type[TERM_VTY].max, term_type[TERM_VTY].name);
      
      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_network_peer pthread_mutex_unlock",errno);
      admin_th_network_peer_exit(term_node, (int32_t)sock);
   }

   pthread_mutex_lock(&term_node->thread.finished);

   vty = term_node->specific;

   this_time = time(NULL);
   
#ifdef HAVE_CTIME_R
#ifdef SOLARIS
   ctime_r(&this_time,term_node->since, sizeof(term_node->since));
#else
   ctime_r(&this_time, term_node->since);
#endif
#else
   pthread_mutex_lock(&mutex_ctime);
   strncpy(term_node->since, ctime(&this_time), sizeof(term_node->since));
   pthread_mutex_unlock(&mutex_ctime);
#endif
                    
   /* Just to remove the cr+lf...*/
   term_node->since[sizeof(term_node->since)-2] = 0;
   
   len = sizeof(struct sockaddr);
   
   if ( getpeername(vty->sock, (struct sockaddr *)&name, &len) < 0)
   {
      thread_error("getpeername",errno);
      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_vty_peer pthread_mutex_unlock",errno);
      admin_th_network_peer_exit(term_node, (int32_t)sock);
   }

    if (init_attribs(term_node) < 0)
    {
       if (pthread_mutex_unlock(&terms->mutex) != 0)
           thread_error("th_vty_peer pthread_mutex_unlock",errno);
       admin_th_network_peer_exit(term_node, (int32_t)sock);
    }                               
   
   term_node->from_port = ntohs(name.sin_port);
   strncpy(term_node->from_ip,inet_ntoa(name.sin_addr),
            sizeof(term_node->from_ip));
   
   if (pthread_mutex_unlock(&terms->mutex) != 0)
      thread_error("th_network_peer pthread_mutex_unlock",errno);

write_log(0,"vty peer %d mutex_unlock terms \n",pthread_self());
   
   fail = 0;
   
   fail = term_vty_banner(term_node);

   if (!fail)
      fail = term_vty_negotiate(term_node);

   if (!fail)
      fail = term_vty_prompt(term_node);

   if (!fail)
      fail = term_vty_flush(term_node);
      
   vty->authing    = 0;
   timeout.tv_sec  = 0;
   timeout.tv_usec = 0;
   quantum         = 0;
   
   FD_ZERO(&read_set);
       
   while(!fail && !term_node->thread.stop)
   {
      FD_SET(vty->sock, &read_set);
                
      if ( (ret=select( vty->sock+1, &read_set, NULL, NULL, &timeout ) )
             == -1 )
      {
         n=errno;
         thread_error("admin_th_network_peer select()",n);
         timeout.tv_sec  = 0;
         timeout.tv_usec = 250000;
         continue;
      }

      if ( !ret )  /* Timeout, decrement timers... */
      {
          if (quantum%4) /* 1 sec...*/
          {
              quantum=0;
              if ( (term_node->timeout--) == 0 )
              {
                 write_log(0,"   Timer-> Cancelling %s%d  th_id(%d)...\n",
                            term_type[TERM_VTY].name, term_node->number,
                            (int)term_node->thread.id);
                 term_write(term_node, VTY_TIMEOUT_BANNER, 
                            sizeof(VTY_TIMEOUT_BANNER));
                 fail = 1; /* Die...*/
              }
          }
          else
             quantum++;
      }
      else
      {
          bytes = read (vty->sock, buf, MAX_LINE);

          if (!vty->authing) /* Update timeout...*/
             term_node->timeout = term_states[term_node->state].timeout;

          if (bytes <= 0)
             break;
          
          for (i=0; (i < bytes) && !fail; i++)
          {
             if (vty->sbmode)
             {
                switch(buf[i])
                {
                   case COM_IAC: vty->iacmode=1;
                                 continue;
                   break;

                   case COM_WILL:
                   case COM_WONT:
                   case COM_DO:
                   case COM_DONT:
                               vty->othermode=1;
                               continue;
                   break;
                                /* Suboption End...*/
                   case COM_SE: vty->sbmode=0;
                                vty->iacmode=0;
                                continue;
                   break;
                
                   case OPT_WSIZE: vty->nwsmode=1;
                                   continue;
                                   
                   default: if (vty->nwsmode)
                            {
                               if (vty->term_size_index > 3)
                               {
                                  vty->nwsmode=0;
                                  vty->iacmode=0;
                                  continue;
                               }
                               
                               vty->term_size[vty->term_size_index]=buf[i];

                               if (vty->term_size_index == 3)
                               {
                                  vty->width = ntohs(*((u_int16_t *)vty->term_size));
                                  vty->height = ntohs(*((u_int16_t *)&vty->term_size[2]));
                                  
                                  if (vty->width < MIN_TERM_WIDTH )
                                     vty->width = MIN_TERM_WIDTH;
                                  
                                  if (vty->width > MAX_TERM_WIDTH)
                                     vty->width = MAX_TERM_WIDTH;
                                  
                                  if (vty->height < MIN_TERM_HEIGHT)
                                     vty->height = MIN_TERM_HEIGHT;
                                  
                                  if (vty->height > MAX_TERM_HEIGHT)
                                     vty->height = MAX_TERM_HEIGHT;
                                     
                                  memset(vty->term_size,0,4);
                                  vty->term_size_index=0;
                                  vty->nwsmode=0;
                                  vty->iacmode=0;
                                  continue;
                               }
                               vty->term_size_index++;
                            }                           
                            vty->iacmode=0;
                            continue;
                }
             }

             if (buf[i] == COM_IAC)
             {
                vty->iacmode=1;
                continue;
             }

             if (vty->iacmode)
             {
                vty->iacmode=0;
                switch(buf[i])
                {
                   case COM_SB: vty->sbmode=1;
                                continue;
                   break;
                    
                   case COM_WILL:
                   case COM_WONT:
                   case COM_DO:
                   case COM_DONT:
                   default:
                               vty->othermode=1;
                               continue;
                   break;
                }
                continue;
             }

             if (vty->othermode)
             {
                vty->othermode=0;
                continue;
             }
             
             /* Are we in 'more' mode? */
             if (buf[i] && vty->moremode)
             {   /* Clearing...*/
                if (buf[i]=='q' || buf[i]=='Q' || buf[i]==CTRL_C ) 
                {
                   thread_free_r(vty->buffer_tx);
                   vty->buffer_tx     = NULL;
                   vty->more_tx       = NULL;
                   vty->buffer_tx_len = 0;
                   vty->more_tx_len   = 0;
                   vty->moremode      = 0;             
                   term_vty_clear_line(term_node,strlen(VTY_MORE));
                   fail=term_vty_prompt(term_node);
                   if (!fail)
                      fail=term_vty_flush(term_node);               
                }
                else
                { 
                   if (buf[i] == SPACE)
                      fail = term_vty_flush(term_node); /* Ok, flush it...*/
                   if (!vty->moremode)
                   { 
                      if (!fail)
                         fail=term_vty_flush(term_node);
                   }
                }

                continue;
             }
             
             /* ESC options begin...*/         
             if (buf[i] == ESC1)
             {
                vty->escmode = ESC1;
                continue;
             }
             
             if ( (vty->escmode == ESC1) && (buf[i] == ESC2))
             {
                vty->escmode = ESC2;
                continue;
             }
             
             if ( (vty->escmode == ESC2) && (buf[i]==ESC3) )
             {
                vty->escmode =ESC3;
                continue;
             }
             
             if (vty->escmode == ESC2)
             {
                if (!vty->authing)
                {
                   switch(buf[i])
                   {
                      case TKEY_SUPR: fail=term_vty_supr(term_node);
                      break;

                      case TKEY_INIT: fail=term_vty_mv_cursor_init(term_node);
                                     if (!fail)
                                        fail = term_vty_flush(term_node);
                      break;

                      case TKEY_END: fail=term_vty_mv_cursor_end(term_node);
                                    if (!fail)
                                       fail = term_vty_flush(term_node);
                      break;
                      
                      case TKEY_UP: if (term_states[term_node->state].key_cursor)
                                      fail=term_vty_history_prev(term_node);
                      break;
                      
                      case TKEY_DOWN: if (term_states[term_node->state].key_cursor)
                                        fail=term_vty_history_next(term_node); 
                      break;
                      
                      case TKEY_RIGHT: fail=term_vty_mv_cursor_right(term_node);
                      break;
                      
                      case TKEY_LEFT: fail=term_vty_mv_cursor_left(term_node);
                      break;
                   }
                   vty->escmode=0;
                   continue;
                }         
             }

             if ( (vty->escmode == ESC3) && (buf[i]==INSERT) )
             {
                vty->insertmode=!vty->insertmode;
                vty->escmode=0;
                continue;
             }

             /* Arrived here, not escape or telnet charac...*/
             switch(buf[i])
             {
                case '\n':continue;
                case '\r': fail = term_vty_do_command(term_node);
                              
                           if (!fail && !vty->moremode)
                           {
                              if (vty->clearmode)
                                 vty->clearmode=0;
                              else
                                 fail = term_vty_write(term_node, "\r\n", 2);
                              if (!fail)
                                 fail = term_vty_prompt(term_node);
                              if (!fail)
                                 fail = term_vty_flush(term_node);
                           }
                           continue;
                break;
                
                case '\t': if (term_states[term_node->state].key_able && 
                                !vty->authing)
                           {
                             fail = term_vty_write(term_node,"\r\n",2);
                             if (!fail)
                                fail = term_vty_complete_command(term_node);
                             if (!fail)
                                 fail = term_vty_prompt(term_node);
                             if (!fail && vty->repeat_command)
                               fail=term_vty_write(term_node, vty->buf_command,
                                                    vty->command_len);                                                         
                             if (!fail)
                                fail = term_vty_flush(term_node);
                             if (!vty->repeat_command)
                                term_vty_clear_command(term_node);
                             vty->repeat_command=0;                           
                              continue;
                           }            
                break;

                case '?': if (term_states[term_node->state].key_help && 
                              !vty->authing)
                          {
                             fail = term_vty_write(term_node,"\r\n",2);
                             if (!fail)
                                fail = term_vty_help(term_node);
                             if (!fail)
                                 fail = term_vty_prompt(term_node);
                             if (!fail && vty->repeat_command)
                               fail=term_vty_write(term_node, vty->buf_command,
                                                    vty->command_len);                                                         
                             if (!fail)
                                fail = term_vty_flush(term_node);
                             if (!vty->repeat_command)
                                term_vty_clear_command(term_node);
                             vty->repeat_command=0;
                             continue;
                          }
                break;

                case BACKSPACE:
                case BACKSPACE_WIN:
                           fail = term_vty_backspace(term_node);
                           if (!fail)
                              fail = term_vty_flush(term_node);
                           continue;
                break;

                case CTRL_C: if (term_states[term_node->state].key_able && 
                                 !vty->authing)
                             {
                                if (term_node->state == PARAMS_STATE)
                                {
                                   fail = term_vty_exit(term_node);
                                   if (fail)
                                      continue;
                                }
                                fail = term_vty_write(term_node,"\r\n",2);
                                if (!fail)
                                   fail = term_vty_prompt(term_node);
                                if (!fail)
                                   fail = term_vty_flush(term_node);
                                if (!fail)
                                   term_vty_clear_command(term_node);
                             }
                             continue;
                break;
                
                case CTRL_L: if (term_states[term_node->state].key_able && 
                                 !vty->authing)
                             {            
                                fail= term_vty_clear_screen(term_node);
                                if (!fail)
                                   fail=term_vty_prompt(term_node);
                                if (!fail)
                                   fail=term_vty_write(term_node,
                                        vty->buf_command, vty->command_len);                            
                                if (!fail)
                                   fail=term_vty_flush(term_node);
                                vty->clearmode=0;
                             }
                             continue;
                break;
                
                case CTRL_D: fail= term_vty_exit(term_node);
                             if (!fail)
                                fail=term_vty_write(term_node,"\r\n",2);
                             if (!fail)
                                fail=term_vty_prompt(term_node);
                             if (!fail)
                                fail=term_vty_flush(term_node);
                             if (!fail)
                                term_vty_clear_command(term_node);
                             continue;
                break;

                case CTRL_U: if (term_states[term_node->state].key_able && 
                                 !vty->authing)
                             {
                                fail=term_vty_clear_remote(term_node);
                                if (!fail)
                                   fail=term_vty_flush(term_node);
                                if (!fail)
                                   term_vty_clear_command(term_node);
                             }
                             continue;
                break;            
             }

               /* Ok, add to command buff...*/
             if (buf[i]>31 && buf[i]<123 && !fail)
             {
                if (vty->insertmode) /* Terminal in mode INSERT...*/
                {
                    if (vty->command_len == MAX_COMMAND)
                    {
                       fail=term_vty_write(term_node,"\x7",1);
                       if (!fail)
                          fail=term_vty_flush(term_node);
                    }
                    else
                    {
                       if (vty->command_len == vty->command_cursor) 
                       {
                          vty->buf_command[vty->command_cursor]=buf[i];
                          if (term_states[term_node->state].do_echo && 
                               !vty->authing)
                          {                  
                              fail = term_vty_write(term_node, (char *)&buf[i], 1);
                              if (!fail)
                                 fail=term_vty_flush(term_node);
                          }
                       }
                       else
                       {
                          u_int16_t len=0;
                          char *message, *auxstr;
                          len = vty->command_len - vty->command_cursor;
                          auxstr = strdup(&vty->buf_command[vty->command_cursor]);
                          if (auxstr == NULL)
                          {
                             write_log(0,"admin_th_netowrk_peer strdup == NULL");
                             fail = -1;
                             continue;
                          }
                          memcpy( &vty->buf_command[vty->command_cursor+1],
                                  auxstr, len);
                          free(auxstr);
                          vty->buf_command[vty->command_cursor]=buf[i];
                          if (term_states[term_node->state].do_echo && 
                                !vty->authing)
                          {
                              fail = term_vty_clear_line(term_node,len);
                              if (!fail)
                                 fail = term_vty_write(term_node, (char *)&buf[i],1);
                              fail = term_vty_write(term_node, 
                                     &vty->buf_command[vty->command_cursor+1], 
                                     len);
                              message = (char *)malloc(len);
                              if (message == NULL)
                              {
                                 thread_error("admin_th_network_peer malloc",errno);
                                 fail = -1;
                                 continue;
                              }
                              memset(message, DEL, len);
                              fail = term_vty_write(term_node, message, len);
                              free(message);
                              if (!fail)
                                 fail=term_vty_flush(term_node);
                          }                  
                       }
                       
                       vty->command_len++;
                       vty->command_cursor++;
                       vty->buf_command[vty->command_len] = 0;
                    } 
                } /* insert mode */
                else
                {
                    if (vty->command_len < MAX_COMMAND)
                    {
                       if (vty->command_len > vty->command_cursor)
                       {
                          vty->buf_command[vty->command_cursor]=buf[i];
                          vty->command_cursor++;
                       }
                       else
                       {
                          vty->buf_command[vty->command_len]=buf[i];
                          vty->command_len++;
                          vty->command_cursor++;
                       }
                       if (term_states[term_node->state].do_echo && 
                           !vty->authing)
                       {
                          fail=term_vty_write(term_node, (char *)&buf[i], 1);
                          if (!fail)
                             fail=term_vty_flush(term_node);
                       }
                    }
                    else 
                    {
                       if (vty->command_len > vty->command_cursor)
                       {
                          vty->buf_command[vty->command_cursor]=buf[i];
                          vty->command_cursor++;
                          if (term_states[term_node->state].do_echo)
                          {
                             fail=term_vty_write(term_node, (char *)&buf[i], 1);
                             if (!fail)
                                fail=term_vty_flush(term_node);
                          }
                       }
                       else
                       {
                          fail=term_vty_write(term_node,"\x7",1);
                          if (!fail)
                             fail=term_vty_flush(term_node);
                       }
                    }
                    vty->buf_command[vty->command_len] = 0;
                } /* insert mode */
             } /* if printable */
          }  /* Next char on buffer...*/          
      } /* if select */
      
      timeout.tv_sec  = 0;
      timeout.tv_usec = 250000;
   } /* While(!fail && !stop) */

   admin_th_network_peer_exit(term_node,0);
   
   return(NULL);
}


/*
 * We arrived here due to normal termination
 * from thread peer main routine...
 * Release resources and delete acquired terminal...
 */
void
admin_th_network_peer_exit(struct term_node *term_node, int32_t sock)
{
   dlist_t *p;
   struct interface_data *iface_data;

   if (term_node)
   {
      for (p = term_node->used_ints->list; p; p = dlist_next(term_node->used_ints->list, p))
       {
          iface_data = (struct interface_data *) dlist_data(p);
          interfaces_disable(iface_data->ifname);
       }

      attack_kill_th(term_node,ALL_ATTACK_THREADS);

      if (pthread_mutex_lock(&terms->mutex) != 0)
         thread_error("th_network_peer pthread_mutex_lock",errno);
      
      term_delete_node(term_node, NOKILL_THREAD);               

      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_network_peer pthread_mutex_unlock",errno);
      
      if (pthread_mutex_unlock(&term_node->thread.finished) != 0)
         thread_error("th_netowrk_peer pthread_mutex_unlock",errno);
   }
   else
   {
      if (sock)
         close(sock);
   }

   write_log(0," admin_peer_th %d finished...\n",(int)pthread_self());
   
   pthread_exit(NULL); 
}






/*
 * Turn down the network admin interface...
 * I'm unaware of handling errors 'cause we're going to die... 
 */ 
void
admin_exit(void)
{
#ifdef HAVE_REMOTE_ADMIN
   /* Kill the admin listener thread...                                 */
   /* In fact, the admin listener thread will kill all the peer threads */
   /* associated with the vty terminals, and each one will delete every */
   /* vty terminal.                                                     */
   if (terms->admin_listen_th.id)
      thread_destroy(&terms->admin_listen_th);
#endif
}

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
