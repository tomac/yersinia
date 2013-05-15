/* commands.c
 * Implementation of Cisco CLI commands
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
       "$Id: commands.c 46 2007-05-08 09:13:30Z slay $";
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

#ifdef SOLARIS
#include <pthread.h>
#include <thread.h>
#else
#include <pthread.h>
#endif


#include "commands.h"

int8_t
command_entry_point(struct term_node *node, struct words_array *warray, int8_t help, int8_t as_param, int8_t tab)
{
   int8_t fail;
   
   fail = command_main(node,warray,0,help,as_param,ANY_PROTO,comm_common,tab);
   
   return fail;
}


int8_t
command_main(struct term_node *node, struct words_array *warray, int16_t x,
             int8_t help, int8_t as_param, u_int8_t prot, 
             struct commands *aux_comm, int8_t tab)
{
   int8_t fail, params, last;
   char msg[128];
   u_int8_t last_proto, proto, j, gotit, par_comm;
   struct commands_param *prot_comms;
   struct term_vty *vty = node->specific;

   last_proto = prot;
   par_comm = 0;
   if (warray->word[warray->indx])
   {
       if (!(warray->word[warray->indx+1]))
       {
          params=0;
          last = 1;
       }
       else
       {
          params=1;
          last = 0;
       }
   }
   else
   {
      params = 0;
      last = 0;
   }
   
    if (!warray->word[warray->indx] && (help || tab)) /* We have just a help '?' or a TAB */
    {
        fail = command_list_help(node, aux_comm, prot);
        vty->repeat_command = 1;   
        return fail;
    }
   
    if (last && ( (help || tab) && !as_param)) /* Last word and  'set?' or 'set\t'*/
    {
        j = gotit = 0;
        if (last_proto<MAX_PROTOCOLS)
            proto = last_proto;
        else
            proto = ANY_PROTO;
        par_comm = 255;

        fail =  command_list_help2(node, warray->word[warray->indx],
                               aux_comm, &j, &gotit, &proto, &par_comm, 0);
        if (fail < 0)
           return -1;
           
        if (!gotit) /* Bad word!! */
        {
            snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
            fail = term_vty_write(node,msg, strlen(msg));
            vty->repeat_command = 0;
        }
        else
        {
            vty->repeat_command = 1;
            if (gotit>1)
                fail =  command_list_help2(node, warray->word[warray->indx],
                                       aux_comm, &j, &gotit, &proto, &par_comm, 1);
            else
            {
               if (gotit == 1)
               {
                  if (help)
                     fail =  command_list_help2(node, warray->word[warray->indx],
                                         aux_comm, &j, &gotit, &proto, &par_comm, 1);
                  else /* TAB */
                  {
                     if (aux_comm[j].proto == LIST_PARAM)
                     {
                        prot_comms = protocols[proto].parameters;
                        fail = term_vty_tab_subst(node, warray->word[warray->indx], prot_comms[par_comm].desc);
                     }
                     else
                     if (aux_comm[j].proto == ANY_PROTO)
                        fail = term_vty_tab_subst(node, warray->word[warray->indx], aux_comm[j].s);
                     else
                        fail = term_vty_tab_subst(node, warray->word[warray->indx], protocols[proto].name_comm);
                  }
               }
            }
        }
   
        return fail;
    }

    /* We don't have help and last word...*/

    if (!help && !tab && !warray->word[warray->indx])
    {
        snprintf(msg,sizeof(msg),"\r\n%% Incomplete command.");
        fail = term_vty_write(node,msg, strlen(msg));
        return fail;
    }

   j = gotit = 0;
    if (last_proto<MAX_PROTOCOLS)
        proto = last_proto;
    else
      proto = ANY_PROTO;
   par_comm = 255;
   
   fail =  command_list_help2(node, warray->word[warray->indx], aux_comm, &j, &gotit, &proto, &par_comm,0);
   
   if (fail < 0)
      return fail;

   if (!gotit) /* Bad word!! */
   {
      if (help || as_param)
      {
         snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
         fail = term_vty_write(node,msg, strlen(msg));
      }
      else
         fail = command_bad_input(node,warray->indx);

      vty->repeat_command = 1;   
   }
   else
   {
      if (gotit==1) /* Ok, execute command...*/
      {
         warray->indx++;
         if (last_proto < MAX_PROTOCOLS)
            proto = last_proto;
         if (!aux_comm[j].command)
         {
             fail = command_main(node, warray, j, help, as_param, proto, aux_comm[j].strcom, tab);
         }
         else
         {
            if (aux_comm[j].proto == LIST_PARAM)
               fail = (aux_comm[j].command(node, warray, par_comm, help, as_param, proto, aux_comm[j].strcom, tab));
            else
               fail = (aux_comm[j].command(node, warray, j, help, as_param, proto, aux_comm[j].strcom, tab));
         }
         vty->repeat_command= 1;
      }
      else /* More than 1 matching command...*/
      {
            vty->repeat_command= 0;
            if (help || tab)
            {
               fail =  command_list_help2(node, warray->word[warray->indx], aux_comm, &j, &gotit, &proto, &par_comm, 1);
               if (fail<0)
                  return -1;
               vty->repeat_command= 1;
            }
            else
               snprintf(msg,sizeof(msg),"\r\n%% Ambiguous command:  \"%s\"", vty->buf_command);
            fail = term_vty_write(node,msg, strlen(msg));
      }
   }

   return fail;
}



int8_t
command_list_help(struct term_node *node, struct commands *aux_comm, u_int8_t proto)
{
   char msg[128];
   u_int8_t i, j, k;
   struct commands_param *prot_comms;
   struct commands_param_extra *extra_comms;

   i = 0;
   
   while(aux_comm[i].help != NULL)
   {
      if (aux_comm[i].states[node->state])
      {   
          if (aux_comm[i].proto == LIST_PROTO)
          {
              for(k=0; k<MAX_PROTOCOLS; k++)
              {
                 if (protocols[k].visible)
                 {
                     snprintf(msg,sizeof(msg),"  %-10s %s %s\r\n", protocols[k].name_comm,aux_comm[i].help,
                                                                   protocols[k].description);
                     if (term_vty_write(node,msg,strlen(msg)) < 0)
                        return -1;
                 }
              }
          }
          else
          {
              if (aux_comm[i].proto == LIST_PARAM)
              {
                 prot_comms = protocols[proto].parameters;
                 for(j=0; j<protocols[proto].nparams; j++)
                 {
                    snprintf(msg,sizeof(msg),"  %-10s %-30s\r\n",
                                  prot_comms[protocols[proto].params_sort[j]].desc,
                                  prot_comms[protocols[proto].params_sort[j]].help);
                    if (term_vty_write(node,msg,strlen(msg)) < 0)
                       return -1;
                 }

                 /* Are there any other parameters? */
                 if ((extra_comms = protocols[proto].extra_parameters) != NULL) {
                    snprintf(msg, sizeof(msg), "\r\n  %s extra parameters\r\n\r\n", protocols[proto].namep);
                    if (term_vty_write(node,msg,strlen(msg)) < 0)
                       return -1;
                    for(j=0; j<protocols[proto].extra_nparams; j++)
                    {
                       snprintf(msg, sizeof(msg), "  %-10s %-30s\r\n", extra_comms[j].desc, extra_comms[j].help);
                       if (term_vty_write(node, msg, strlen(msg)) < 0)
                          return -1;
                    }
                 }
              }
              else
              {
                  snprintf(msg,sizeof(msg),"  %-10s %-30s\r\n",aux_comm[i].s,aux_comm[i].help);
                  if (term_vty_write(node,msg,strlen(msg)) < 0)
                     return -1;
              }
          }
      }
      i++;
   }
   return 0;
}


int8_t
command_list_help2(struct term_node *node, char *word, 
                   struct commands *aux_comm, u_int8_t *j, u_int8_t *gotit,
                   u_int8_t *proto, u_int8_t *param, int8_t print)
{
   char msg[128];
   u_int8_t i, k, go_out;
   struct commands_param *prot_comms;

   i = 0;

   while(aux_comm[i].help != NULL)
   {
      if (aux_comm[i].states[node->state])
      {   
          if ( (aux_comm[i].proto != LIST_PROTO) && (aux_comm[i].proto != LIST_PARAM))
          {
             if (!strncmp(aux_comm[i].s, word, strlen(word)))
             {
                if (print)
                {
                   snprintf(msg,sizeof(msg),"  %-10s %-30s\r\n",aux_comm[i].s,aux_comm[i].help);
                   if (term_vty_write(node,msg,strlen(msg)) < 0)
                      return -1;
                }
                if (strlen(word) == strlen(aux_comm[i].s))
                {
                   *gotit=1;
                   *j=i;
                   *proto = aux_comm[(*j)].proto;
                   break;
                }
                if (!(*j)) *j=i;
                (*gotit)++;
             }
          }
          else /* Verify the word against the list of available protocols */
          if (aux_comm[i].proto != LIST_PARAM)
          {
              go_out=0;
              for(k=0; k<MAX_PROTOCOLS; k++)
              {
                 if (protocols[k].visible && 
                       !strncmp(protocols[k].name_comm, word, strlen(word)))
                 {
                      *proto=k;
                      if (print)
                      {
                         snprintf(msg,sizeof(msg),"  %-10s %s %s\r\n", protocols[k].name_comm,aux_comm[i].help,
                                                                       protocols[k].description);
                         if ( term_vty_write(node,msg,strlen(msg)) < 0)
                            return -1;
                      }
                      if (strlen(word) == strlen(protocols[k].name_comm))
                      {
                         (*gotit)++;
                         *j=i;
                         *proto = k;
                         go_out = 1;
                         break;
                      }
                      if (!(*j)) *j=i;
                      (*gotit)++;
                 }
              }
              if (go_out)
                 break;
          }
          else /* Verify the word against the protocol params list */
          {
             go_out = 0;
             prot_comms = protocols[*proto].parameters;
             for(k=0; k<protocols[*proto].nparams;k++)
             {

                 if (!strncmp(prot_comms[protocols[*proto].params_sort[k]].desc, word, strlen(word)))
                 {
                    *param = protocols[*proto].params_sort[k];                 
                    if (print)
                    { 
                       snprintf(msg,sizeof(msg),"  %-10s %-30s\r\n",
                                  prot_comms[protocols[*proto].params_sort[k]].desc,
                                  prot_comms[protocols[*proto].params_sort[k]].help);
                       if (term_vty_write(node,msg,strlen(msg))<0)
                          return -1;
                    }
                    if (strlen(word) == strlen(prot_comms[protocols[*proto].params_sort[k]].desc))
                    {
                       (*gotit)++;
                       *j=i;
                       *param = protocols[*proto].params_sort[k];
                       go_out = 1;
                       break;
                    }
                    if (!(*j)) *j=i;
                    (*gotit)++;
                 }
             }
             if (go_out)
                break;
          }
      }
      i++;
   }

   return 0;
}


/*
 * Comando de prueba para probar el modo More... 
 */
int8_t
command_prueba(struct term_node *node, struct words_array *warray, int16_t j, int8_t help, 
               int8_t as_param, u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   int8_t fail;
   char msg[128];
   u_int8_t i;
   struct term_vty *vty = node->specific;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help || as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_common[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }
   
   fail = term_vty_write(node,"\r\n",2);

   if (fail == -1)
      return -1;
   
   for(i=0; i< 250; i++)
   {
      snprintf(msg,sizeof(msg),"%d - Esta es la linea %d\r\n",i,i);
      fail = term_vty_write(node,msg, strlen(msg));
      if (fail)
         break;
   }
   
   return fail;
}


/*
 * Clear client screen...
 * Return 0 if Ok. Return -1 if error.
 */
int8_t
command_cls(struct term_node *node, struct words_array *warray, int16_t j,
            int8_t help, int8_t as_param, u_int8_t proto, 
            struct commands *aux_comm, int8_t tab)
{
   int8_t fail;
   struct term_vty *vty = node->specific;
   char msg[128];
      
   if (warray && (warray->word[warray->indx]))
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help || as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_common[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   fail = term_vty_write(node,"\r\n",2);
   
   if (fail==-1)
      return -1;
   
   fail = term_vty_write(node,CLEAR_SCREEN,strlen(CLEAR_SCREEN));

   if (fail==-1)
      return -1;
   
   vty->clearmode=1;

   return 0;
}


/* 
 * Show global help
 */
int8_t
command_help(struct term_node *node)
{
  int8_t i, fail;
  char msg[128];
  
  i = 0;
  
  while(comm_common[i].s != NULL)
  {
     if (comm_common[i].states[node->state])
     {
        snprintf(msg,sizeof(msg),"  %-10s %-30s\r\n",comm_common[i].s,comm_common[i].help);
        fail=term_vty_write(node,msg,strlen(msg));
        if (fail==-1)
           return -1;
     }  
     i++;
  }

  return 0;
}


/*
 * Come back to previous level
 * Return 0 if Ok. Return -1 if error (or going to exit level).
 */
int8_t
command_disable(struct term_node *node, struct words_array *warray, int16_t j, int8_t help, 
int8_t as_param, u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   return (command_exit(node, warray, j, help, as_param, proto,aux_comm,tab));
}


/*
 * Come back to previous level
 * Return 0 if Ok. Return -1 if error (or going to exit level).
 */
int8_t
command_exit(struct term_node *node, struct words_array *warray, int16_t j, int8_t help, int8_t as_param, u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   int8_t fail;
   char msg[128];
   struct term_vty *vty = node->specific;

   if (warray && (warray->word[warray->indx]))
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help || as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_common[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   return (term_vty_exit(node));   
}




int8_t
command_enable(struct term_node *node, struct words_array *warray, int16_t j,
               int8_t help, int8_t as_param, u_int8_t proto, 
               struct commands *aux_comm, int8_t tab)
{
   int8_t fail;
   char msg[128];
   struct term_vty *vty = node->specific;
      
   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help || as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_common[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }
      
   vty->authing=1;
   
   return 0;
}



int8_t
command_cancel_proto(struct term_node *node, struct words_array *warray, 
                     int16_t x, int8_t help, int8_t as_param,
                     u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t fail=0, params, aux, j;

   if (warray->word[warray->indx])
   {
       if (!(warray->word[warray->indx+1]))
          params=0;
       else
          params=1;
   }
   else
      params=0;

   if (!warray->word[warray->indx] && (help || tab) )
   {
      snprintf(msg,sizeof(msg)," all       All %s running attacks\r\n", protocols[proto].name_comm);
      fail = term_vty_write(node,msg,strlen(msg));
      if (fail == -1)
         return -1;
      snprintf(msg,sizeof(msg)," <0-%d>     %s attack id\r\n", (MAX_THREAD_ATTACK-1),protocols[proto].name_comm);
      fail = term_vty_write(node,msg,strlen(msg));
      if (fail==-1)
         return -1;
      snprintf(msg,sizeof(msg)," <cr>\r\n");
      fail = term_vty_write(node,msg,strlen(msg));
      return fail;
   }

   if (proto == ANY_PROTO) /* 'all' attacks */
   {
       if (params)
       {
           if (help || tab)
              snprintf(msg,sizeof(msg),"%% Too many arguments\r\n");
           else
              fail = command_bad_input(node,warray->indx);
           fail = term_vty_write(node,msg, strlen(msg));
           return fail;
       }   
      fail = attack_kill_th(node, ALL_ATTACK_THREADS);
   }
   else
   {
       if (!warray->word[warray->indx])
       {  
          snprintf(msg,sizeof(msg),"\r\n%% Incomplete command.");
          fail = term_vty_write(node,msg, strlen(msg));
          return fail;
       }

       if (warray->nwords > (warray->indx+1))
       {
           if (help || tab)
              snprintf(msg,sizeof(msg),"%% Too many arguments\r\n");
           else
              fail = command_bad_input(node,warray->indx);
           fail = term_vty_write(node,msg, strlen(msg));
           return fail;
       }   
       if (help || tab)
       {
          snprintf(msg,sizeof(msg),"   <cr>\r\n");
          fail = term_vty_write(node,msg,strlen(msg));
          return fail;
       }
       /* Ok, now we have just 1 arg, begin parsing...*/
       aux = atoi(warray->word[warray->indx]);
       
       if (!strcmp(warray->word[warray->indx], "all"))
       {
          for(j=0; j<MAX_THREAD_ATTACK; j++)
          {
              if (node->protocol[proto].attacks[j].up)
              {
                 fail = attack_kill_th(node, node->protocol[proto].attacks[j].attack_th.id);
                 if (fail==-1)
                    return -1;
              }
          }
       }
       else
       {
           if ( (aux < 0) || (aux >= MAX_THREAD_ATTACK) )
              return (command_bad_input(node,warray->indx));

           /* Is running the attack?...*/
           if (!node->protocol[proto].attacks[aux].up)
           {
               snprintf(msg,sizeof(msg),"\r\n%% %s attack id \"%d\" not used",protocols[proto].namep,aux);
               fail = term_vty_write(node,msg, strlen(msg));
               return fail;
           }
           fail = attack_kill_th(node, node->protocol[proto].attacks[aux].attack_th.id);
       }
   }

   return fail;
}



/* 
 * Show users connected.
 * Use terms and term_type global pointer.
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
command_show_users(struct term_node *node, struct words_array *warray, int16_t j, int8_t help, int8_t as_param, u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t i, fail;
   struct term_node *term_cursor;
   struct term_vty *vty = node->specific;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
      return 0;

   if (as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_show[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   snprintf(msg,sizeof(msg),"\r\n   User         Terminal        From             Since\r\n");
   
   fail = term_vty_write(node,msg, strlen(msg));
   
   if (fail == -1)
      return -1;
      
   snprintf(msg,sizeof(msg),"   ----         --------        ----             -----\r\n");
   
   fail = term_vty_write(node,msg, strlen(msg));   
   
   if (fail == -1)
      return -1;
      
   term_cursor = terms->list;

   for(i=0; i<MAX_TERMS; i++)
   {  
      if (term_cursor->up)
      {
         if (term_cursor->thread.id == pthread_self())
         {
            snprintf(msg,sizeof(msg),"*  %-12s %7s%-2d %15s:%-5d  %4s\r\n",
                   term_cursor->username,  term_type[term_cursor->type].name,
                   term_cursor->number,    term_cursor->from_ip,
                   term_cursor->from_port, term_cursor->since); 
         }
         else
         {
            snprintf(msg,sizeof(msg),"   %-12s %7s%-2d %15s:%-5d  %4s\r\n",
                   term_cursor->username,  term_type[term_cursor->type].name,
                   term_cursor->number,    term_cursor->from_ip,
                   term_cursor->from_port, term_cursor->since); 
         }
         fail = term_vty_write(node,msg, strlen(msg));
         if (fail==-1)
            return -1;
      }
      term_cursor++;
   }

   return 0;
}


/* 
 * Show command line history.
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
command_show_history(struct term_node *node, struct words_array *warray, int16_t j, int8_t help, int8_t as_param, u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t i, fail;
   struct term_vty *vty = node->specific;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
      return 0;

   if (as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_show[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   for(i=0; i<MAX_HISTORY; i++)
   {
      if (vty->history[i] == NULL)
         break;
      snprintf(msg,sizeof(msg),"\r\n  %s",vty->history[i]);
      if (term_vty_write(node, msg, strlen(msg)) < 0)
         return -1;
   }   

   return 0;
}


/* 
 * Show all running attacks.
 * Return 0 if Ok. Return -1 on error.
 */
int8_t
command_show_attacks(struct term_node *node, struct words_array *warray, int16_t j, int8_t help, int8_t as_param, u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t fail;
   struct term_vty *vty = node->specific;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
      return 0;

   if (as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_show[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   fail = command_proto_attacks(node,6666);
   
   return fail;
}



/* 
 * Show active interfaces
 * Return -1 on error. Return 0 if Ok.
 * Use global interfaces list (interfaces).
 */
int8_t
command_show_interfaces(struct term_node *node, struct words_array *warray,
                        int16_t j, int8_t help, int8_t as_param, 
                        u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   int8_t fail;
   char msg[128];
   struct term_vty *vty = node->specific;   
   dlist_t *p;
   struct interface_data *iface_data;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",
                     vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
      return 0;

   if (as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_show[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   if (pthread_mutex_lock(&interfaces->mutex) != 0)
   {
      thread_error("command_show_ints pthread_mutex_lock",errno);
      return -1;
   }

   for (p = interfaces->list; p; p = dlist_next(interfaces->list, p))
   {
      iface_data = (struct interface_data *) dlist_data(p);
      if (show_interface_data(node, iface_data) < 0)
      {
         pthread_mutex_unlock(&interfaces->mutex);
         return -1;
      } 
   }
   
   if (pthread_mutex_unlock(&interfaces->mutex) != 0)
   {
      thread_error("command_show_ints pthread_mutex_unlock",errno);
      return -1;
   }
   
   return 0;
}


int8_t
show_interface_data(struct term_node *node, struct interface_data *iface)
{
   char msg[128];
   u_int8_t i;
   
   snprintf(msg, sizeof(msg), "\r\n%s is up, line protocol is %s\r\n   Hardware is %s (%s),",
               iface->ifname,
               (iface->up)?"up":"down",
               (iface->iflink_desc[0])?iface->iflink_desc:"*unknown*",
               (iface->iflink_name[0])?iface->iflink_name:"??" );
  
   if (term_vty_write(node, msg, strlen(msg)) < 0)
      return -1;
   
   if (!memcmp(iface->etheraddr,"\x0\x0\x0\x0\x0\x0",6))
      snprintf(msg, sizeof(msg), " no address suitable for this interface\r\n");
   else
      snprintf(msg, sizeof(msg), " address is %02x%02x.%02x%02x.%02x%02x (bia %02x%02x.%02x%02x.%02x%02x)\r\n",
             iface->etheraddr[0], iface->etheraddr[1],
             iface->etheraddr[2], iface->etheraddr[3],
             iface->etheraddr[4], iface->etheraddr[5],
             iface->etheraddr[0], iface->etheraddr[1],
             iface->etheraddr[2], iface->etheraddr[3],
             iface->etheraddr[4], iface->etheraddr[5]);
               
   if (term_vty_write(node, msg, strlen(msg)) < 0)
      return -1;
   
   if (iface->ipaddr[0]) /* Print IP data...*/
   {
      snprintf(msg, sizeof(msg), "   Internet address is %s/%s\r\n",
                 iface->ipaddr, iface->netmask);
      if (term_vty_write(node, msg, strlen(msg)) < 0)
         return -1;
      
      if (iface->broadcast[0])
         snprintf(msg, sizeof(msg), "   Broadcast address is %s\r\n",
                 iface->broadcast);
      else
         snprintf(msg, sizeof(msg), "   Broadcast address is not assigned\r\n");
      if (term_vty_write(node, msg, strlen(msg)) < 0)
          return -1;
    
      if (iface->ptpaddr[0])
      {            
         snprintf(msg, sizeof(msg), "   Point8_tto Point8_taddress is %s\r\n",
                 iface->ptpaddr);
         if (term_vty_write(node, msg, strlen(msg)) < 0)
             return -1;
      }
   }
   else
   {
      snprintf(msg, sizeof(msg), "   Internet address is not assigned\r\n");
      if (term_vty_write(node, msg, strlen(msg)) < 0)
          return -1;
   }
   
   snprintf(msg, sizeof(msg), "   Users using it %d\r\n",
             iface->users);
                     
   if (term_vty_write(node, msg, strlen(msg)) < 0)
      return -1;
   
   for(i=0; i< MAX_PROTOCOLS; i++)
   {
       if (!protocols[i].visible)
          continue;

       snprintf(msg, sizeof(msg),     "     %s stats:\r\n",
                protocols[i].description);
       if (term_vty_write(node, msg, strlen(msg)) < 0)
           return -1;

       if (iface->packets[i])
           snprintf(msg, sizeof(msg), "         %d input packets.\r\n",
                     iface->packets[i]);
       else
           snprintf(msg, sizeof(msg), "        input packets not seen yet\r\n");
                         
       if (term_vty_write(node, msg, strlen(msg)) < 0)
          return -1;

       if (iface->packets_out[i])
       {
           snprintf(msg, sizeof(msg), "         %d output packets.\r\n",
                 iface->packets_out[i]);
       }
       else
           snprintf(msg, sizeof(msg), "        output packets not seen yet\r\n");
          
       if (term_vty_write(node, msg, strlen(msg)) < 0)
          return -1;      
   }
   
   return 0;
}



int8_t
command_show_version(struct term_node *node, struct words_array *warray,
                     int16_t j, int8_t help, int8_t as_param, 
                     u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   int8_t fail;
   char msg[128];
   struct term_vty *vty = node->specific;   

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
   {
      return 0;
   }

   if (as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_show[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   snprintf(msg,sizeof(msg),"\r\nChaos Internetwork Operating System Software\r\n");
   if (term_vty_write(node,msg, strlen(msg))<0)
      return -1;

   snprintf(msg,sizeof(msg),""PACKAGE" (tm) Software ("INFO_PLATFORM"), Version "VERSION", RELEASE SOFTWARE\r\n");
   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;
   
   snprintf(msg,sizeof(msg),"Copyright (c) 2004-2006 by tomac & Slay, Inc.\r\n");
   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;

   snprintf(msg,sizeof(msg),"Compiled "INFO_DATE" by someone\r\n\r\n");
   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;

   if ( uptime < 60 )
      snprintf(msg,sizeof(msg),""PACKAGE" uptime is %02d seconds\r\n\r\n", uptime);
   else
   {
      if ( uptime < 3600 )
         snprintf(msg,sizeof(msg),""PACKAGE" uptime is %02d minutes, %02d seconds\r\n\r\n",
                      uptime / 60, uptime % 60);
      else
      {
         if ( uptime < (3600*24) )
         {
            snprintf(msg,sizeof(msg),""PACKAGE" uptime is %02d hours, %02d minutes, %02d seconds\r\n\r\n", 
                      uptime / 3600, (uptime % 3600) / 60, uptime % 60);
         }
         else
            snprintf(msg,sizeof(msg),""PACKAGE" uptime is %02d days, %02d hours, %02d minutes, %02d seconds\r\n\r\n",
                   uptime / (3600*24), (uptime % (3600*24)) / 3600, 
                   (uptime % 3600) / 60, uptime % 60);
      }
   }

   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;

   snprintf(msg,sizeof(msg),"Running Multithreading Image on "INFO_KERN" "INFO_KERN_VER" supporting:\r\n");
   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;

   snprintf(msg,sizeof(msg),"%02d console terminal(s)\r\n%02d tty terminal(s)\r\n%02d vty terminal(s)\r\n",
                             MAX_CON, MAX_TTY, MAX_VTY);
   fail = term_vty_write(node,msg, strlen(msg));
   
   return fail;
}


/*
 * Show statistics
 */
int8_t
command_show_stats(struct term_node *node, struct words_array *warray,
                   int16_t j, int8_t help, int8_t as_param, 
                   u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t i, fail;
   struct term_vty *vty = node->specific;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
      return 0;

   if (as_param)
   {
      snprintf(msg,sizeof(msg),"  %-10s\r\n",comm_show[j].params);
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   snprintf(msg, sizeof(msg),"\r\n");
   if (term_vty_write(node, msg, strlen(msg)) < 0)
       return -1;

   for(i=0; i< MAX_PROTOCOLS; i++)
   {
       if (!protocols[i].visible)
          continue;

       snprintf(msg, sizeof(msg),     "     %s stats:\r\n",
                protocols[i].description);
       if (term_vty_write(node, msg, strlen(msg)) < 0)
           return -1;

       if (protocols[i].packets)
       {
           snprintf(msg, sizeof(msg), "         %d input packets.\r\n",
                     protocols[i].packets);
       }
       else
           snprintf(msg, sizeof(msg), "        input packets not seen yet\r\n");
                         
       if (term_vty_write(node, msg, strlen(msg)) < 0)
          return -1;

       if (protocols[i].packets_out)
           snprintf(msg, sizeof(msg), "         %d output packets.\r\n",
                 protocols[i].packets_out);
       else
           snprintf(msg, sizeof(msg), "        output packets not seen yet\r\n");
          
       if (term_vty_write(node, msg, strlen(msg)) < 0)
          return -1;      
   }

   return 0;
}



/*
 * Show proto attacks
 */
int8_t
command_show_proto_attacks(struct term_node *node, struct words_array *warray,
                           int16_t j, int8_t help, int8_t as_param,
                           u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t fail;
   struct term_vty *vty = node->specific;
   
   if (warray->word[warray->indx])
   {
       if (help || tab)
       {
          snprintf(msg,sizeof(msg),"%% Too many arguments.\r\n");
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help || tab)
   {
      if (aux_comm)
         snprintf(msg,sizeof(msg),"  %-10s\r\n",aux_comm[j].params);
      else
         snprintf(msg,sizeof(msg),"  %-10s\r\n","<cr>");
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   fail = command_proto_attacks(node,proto);
   
   return fail;
}


/*
 * Show proto stats
 */
int8_t
command_show_proto_stats(struct term_node *node, struct words_array *warray,
                         int16_t j, int8_t help, int8_t as_param,
                         u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   return 0;
}


/*
 * Show protocol attack parameters
 */
int8_t
command_show_proto_params(struct term_node *node, struct words_array *warray, 
                          int16_t x, int8_t help, int8_t as_param,
                          u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   char new_msg[128];
   int8_t fail, i, first;
   struct commands_param *prot_params;
   struct term_vty *vty = node->specific;
   dlist_t *p;
   struct interface_data *iface_data;
   
   if (warray->word[warray->indx])
   {
       if (help || tab)
       {
          snprintf(msg,sizeof(msg),"%% Too many arguments.\r\n");
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help || tab)
   {
      if (aux_comm)
         snprintf(msg,sizeof(msg),"  %-10s\r\n",aux_comm[x].params);
      else
         snprintf(msg,sizeof(msg),"  %-10s\r\n","<cr>");
      fail = term_vty_write(node,msg,strlen(msg));
      vty->repeat_command= 1;
      return fail;
   }

   prot_params = protocols[proto].parameters;

   snprintf(msg, sizeof(msg), "\r\n");
   fail = term_vty_write(node,msg,strlen(msg));
   if (fail==-1)
      return -1;

   for (i=0; i<protocols[proto].nparams; i++)
   {
       parser_binary2printable(proto, 
                               protocols[proto].params_sort[i], 
                               node->protocol[proto].commands_param[protocols[proto].params_sort[i]], 
                               new_msg);

       switch(prot_params[protocols[proto].params_sort[i]].type)
       {
          case FIELD_IP:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",
                        prot_params[protocols[proto].params_sort[i]].desc,"IPv4");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
            snprintf(msg,sizeof(msg),"   %s",new_msg);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
          break;

          case FIELD_IFACE:
            first = 1;
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc, "INTERFACE");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
            for (p = node->used_ints->list; p; p = dlist_next(node->used_ints->list, p))
            {
               iface_data = (struct interface_data *) dlist_data(p);
                  if (first)
                  {
                     snprintf(msg,sizeof(msg),"   %s",iface_data->ifname);
                     first=0;
                  }
                  else
                     snprintf(msg,sizeof(msg),", %s",iface_data->ifname);                  
                  fail = term_vty_write(node,msg,strlen(msg));
                  if (fail==-1)
                     return -1;                 
            }
            if (first) /* We have no interface */
            {
                snprintf(msg,sizeof(msg),"   No defined");                  
                fail = term_vty_write(node,msg,strlen(msg));
                if (fail==-1)
                   return -1;                 
            }
                     
          break;
        
          case FIELD_HEX:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"HEXNUM");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;

            snprintf(msg,sizeof(msg),"   %s", new_msg);

            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
          break;

          case FIELD_DEC:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"DECNUM");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;

            snprintf(msg,sizeof(msg),"   %s", new_msg);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
          break;
        
          case FIELD_BRIDGEID:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"BRIDGEID");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;

            snprintf(msg,sizeof(msg),"   %s", new_msg);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
          break;
        
          case FIELD_MAC:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"MACADDR");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;

            snprintf(msg,sizeof(msg),"   %s", new_msg);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
          break;
        
          case FIELD_BYTES:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"BYTES");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;

            snprintf(msg,sizeof(msg),"   %s", new_msg);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
                return -1;
          break;
        
          case FIELD_STR:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"STRING");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
            snprintf(msg,sizeof(msg),"   %s", new_msg);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
                return -1;
          break;

          case FIELD_NONE:
            snprintf(msg,sizeof(msg),"  %-10s   %-9s",prot_params[protocols[proto].params_sort[i]].desc,"NOTYPE");
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail==-1)
               return -1;
          break;

          case FIELD_DEFAULT:
          break;

          case FIELD_EXTRA:
          break;
          
          default:
            write_log(0,"Ouch!! Unrecognized protocol(%s) param type %d!!!\n",
                     protocols[proto].namep,prot_params[protocols[proto].params_sort[i]].type);  
       }
       if ((prot_params[protocols[proto].params_sort[i]].type != FIELD_DEFAULT) && 
           (prot_params[protocols[proto].params_sort[i]].type != FIELD_EXTRA))
       {
           snprintf(msg, sizeof(msg), "\r\n");
           fail = term_vty_write(node,msg,strlen(msg));
           if (fail==-1)
              return -1;
       }
   }

   return 0;
}


/* 
 * Show active attacks.
 * If proto == 6666 show attacks from all protocols
 * Return 0 if Ok. Return -1 if error.
 */
int8_t
command_proto_attacks(struct term_node *node, u_int16_t proto)
{
   int8_t i,j;
   char msg[128];
   struct attack *theattack=NULL;
  
   snprintf(msg,sizeof(msg),"\r\n   No.    Protocol    Attack\r\n");
   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;
      
   snprintf(msg,sizeof(msg),"   ---    --------    ------");
   if (term_vty_write(node,msg, strlen(msg)) < 0)
      return -1;

   for (j=0; j < MAX_PROTOCOLS; j++)
   {
       if (proto != 6666)
          j=proto;
       if (protocols[j].visible)
       {
           theattack = protocols[j].attacks;
           for (i=0; i < MAX_THREAD_ATTACK; i++)
           {
               if (node->protocol[j].attacks[i].up)
               {
                   snprintf(msg,sizeof(msg), "\r\n    %-1d      %-8s   %s", i,
                            node->protocol[j].name,
                            theattack[node->protocol[j].attacks[i].attack].s);
                   if (term_vty_write(node,msg,strlen(msg)) < 0)
                      return -1;
               }
           }
       }
       if (proto != 6666)
          break;
   }                                                                    
   return 0;
}



/* 
 * Clear protocol stats
 */
int8_t
command_clear_proto(struct term_node *node, struct words_array *warray,
                    int16_t j, int8_t help, int8_t as_param,
                    u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t fail;
   struct term_vty *vty = node->specific;

   if (warray->word[warray->indx])
   {
       if (help || as_param)
       {
          snprintf(msg,sizeof(msg),"%% Unrecognized command:  \"%s\"\r\n",vty->buf_command);
          fail = term_vty_write(node,msg, strlen(msg));
       }
       else
          fail = command_bad_input(node,warray->indx);
       return fail;
   }
        
   if (help)
      return 0;

   if (proto == 255)
      fail = interfaces_clear_stats(PROTO_ALL);
   else
      fail = interfaces_clear_stats(proto);
   
   if (fail == -1)
      return -1;

   return 0;
}


/*
 * Entry point for command 'set protocol' 
 */
int8_t
command_set_proto(struct term_node *node, struct words_array *warray, 
                  int16_t x, int8_t help, int8_t as_param, u_int8_t proto,
                  struct commands *aux_comm, int8_t tab)
{
    char msg[128];
    int8_t fail;
/*    u_int32_t aux_long;*/
    struct term_vty *vty = node->specific;
    struct commands_param *prot_comms;
    dlist_t *p;
    struct interface_data *iface_data, *interface_new;

    prot_comms = protocols[proto].parameters;

    if (prot_comms[x].type == FIELD_DEFAULT) 
    {
        if (warray->word[warray->indx])
        {
            if (help || tab)
               snprintf(msg,sizeof(msg),"%% Too many arguments\r\n");
            else
               snprintf(msg,sizeof(msg),"\r\n%% Too many arguments");
            fail = term_vty_write(node,msg, strlen(msg));
            return fail;
        }
        
        if (help || tab)
        {
           snprintf(msg,sizeof(msg),"   <cr>\r\n");
           fail = term_vty_write(node,msg,strlen(msg));
           return fail;
        }

        /* Ok, now we can set the protocol defaults...*/
        fail = (*protocols[proto].init_attribs)(node);
    }
    else
    {
        if (!warray->word[warray->indx]) /* No data...*/
        {
            if (!help && !tab)
            {
               snprintf(msg,sizeof(msg),"\r\n%% Incomplete command.");
               fail = term_vty_write(node,msg, strlen(msg));
               return fail;
            }
            snprintf(msg,sizeof(msg),"  %-30s\r\n",prot_comms[x].param);
            fail = term_vty_write(node,msg,strlen(msg));
            if (fail == -1)
               return -1;
            snprintf(msg,sizeof(msg),"   <cr>\r\n");
            fail = term_vty_write(node,msg,strlen(msg));
            return fail;
         }

         if (warray->nwords > (warray->indx+1))
         {
             if (help || tab)
                snprintf(msg,sizeof(msg),"%% Too many arguments\r\n");
             else
                fail = command_bad_input(node,warray->indx);
             fail = term_vty_write(node,msg, strlen(msg));
             return fail;
         }   

         /* Ok, now we have just 1 arg, begin parsing...*/

         /* Command 'interface' is special because we need to do some things */   
         if (!strcmp("interface", prot_comms[x].desc))
         {
            p = dlist_search(interfaces->list, interfaces->cmp, (void *)warray->word[warray->indx]);
            iface_data = (struct interface_data *) dlist_data(p);

            if (p == NULL)
            {
               fail = command_bad_input(node, warray->indx);
               return fail;
            }
             /* Don't repeat interface...*/
            if (!dlist_search(node->used_ints->list, node->used_ints->cmp, (void *)warray->word[warray->indx]))
            {
                if (interfaces_enable(warray->word[warray->indx]) < 0 )
                {
                   fail = command_bad_input(node,warray->indx);
                   return fail;
                }
                interface_new = (struct interface_data *) calloc(1, sizeof(struct interface_data));
                memcpy((void *)interface_new, (void *) iface_data, sizeof(struct interface_data));
                node->used_ints->list = dlist_append(node->used_ints->list, (void *) interface_new);
            }
            return 0;
         }

         fail = parser_filter_param( prot_comms[x].type, 
                                     node->protocol[proto].commands_param[x], 
                                     warray->word[warray->indx], 
                                     prot_comms[x].size_print, 
                                     prot_comms[x].size);
         if (fail == -1)
             return (command_bad_input(node,warray->indx));

         /*
         if ( prot_comms[x].type == FIELD_IP)
         {
            memcpy((void *)&aux_long, node->protocol[proto].commands_param[x], 4);
            aux_long = ntohl(aux_long);
            memcpy((void *)node->protocol[proto].commands_param[x], (void *)&aux_long, 4);
         }*/
         
         if (prot_comms[x].filter) /* Use specific filter for this param */
         {
            fail = (prot_comms[x].filter((void *)node,node->protocol[proto].commands_param[x],warray->word[warray->indx]));
            if (fail == -1)
               return (command_bad_input(node,warray->indx));
         }
    }
    
    vty->repeat_command= 1;

    return fail;   
}



/*
 * Command run proto attack
 */
int8_t
command_run_proto(struct term_node *node, struct words_array *warray, int16_t x, int8_t help, int8_t as_param,
                    u_int8_t proto, struct commands *aux_comm, int8_t tab)
{
   char msg[128];
   int8_t i, fail, params, aux;
   struct attack *theattack = NULL;

   if (warray->word[warray->indx])
   {
       if (!(warray->word[warray->indx+1]))
          params=0;
       else
          params=1;
   }
   else
      params=0;
      
   if (warray->nwords > (warray->indx+2))
   {
       if (help || tab)
          snprintf(msg,sizeof(msg),"%% Too many arguments\r\n");
       else
          fail = command_bad_input(node,warray->indx+1);
       fail = term_vty_write(node,msg, strlen(msg));
       return fail;
   }   

   if ( (help || tab) && !warray->word[warray->indx])
   {
      theattack = protocols[proto].attacks;
      i=0;
      while(theattack[i].s != NULL)
      {
          snprintf(msg,sizeof(msg),"  <%d>   %s attack %s\r\n", i, 
                    (theattack[i].type == DOS) ? "DOS" : "NONDOS",
                       theattack[i].s);
          fail = term_vty_write(node,msg,strlen(msg));
          if (fail == -1)
             return -1;
          i++;
      }
             
      snprintf(msg,sizeof(msg),"  <cr>\r\n");
      fail = term_vty_write(node,msg,strlen(msg));
      return fail;
   }

   if (help || tab)
   {
      snprintf(msg,sizeof(msg),"   <cr>\r\n");
      fail = term_vty_write(node,msg,strlen(msg));
      return fail;
   }

   if (!warray->word[warray->indx])
   {
      snprintf(msg,sizeof(msg),"\r\n%% Incomplete command.");
      fail = term_vty_write(node,msg, strlen(msg));
      return fail;
   }

   if (!protocols[proto].attacks[0].s)
   {
      snprintf(msg,sizeof(msg),"\r\n%% Protocol %s has no attacks defined", protocols[proto].description);
      fail = term_vty_write(node,msg,strlen(msg));
      return fail;
   }

   /* Ok, now we have just 1 arg, begin parsing...*/
   aux = atoi(warray->word[warray->indx]);

    /* Dirty trick to take the max attack number... 
     * Man, i'm now in the plane flying to Madrid with
     * Ramon so don't be cruel! */
    theattack = protocols[proto].attacks;
    i=0;
    while(theattack[i].s != NULL)
        i++;
   
   if ( (aux < 0) || (aux > (i-1)) )
      return (command_bad_input(node,warray->indx));

   /* Ok, launch attack, plz...*/
   
   return (command_run_attack(node, proto, aux));
}


int8_t
command_run_attack(struct term_node *node, u_int8_t proto, int8_t aux)
{
   char msg[128];
   int8_t fail=1;
   struct attack_param *attack_param = NULL;
   struct attack *theattack = NULL;
   struct term_vty *vty = node->specific;

   if (dlist_data(node->used_ints->list))
      fail = 0;

   if (fail)
   {
       snprintf(msg,sizeof(msg),"\r\n%% Network interface not specified. Attack aborted.");
       fail = term_vty_write(node, msg, strlen(msg));
       return fail;
   }
   
   theattack = protocols[proto].attacks;
   
   if (theattack[aux].nparams) /* Do we need parameters for attack? */
   {
       if ((attack_param = calloc(1,
                  (sizeof(struct attack_param) * theattack[aux].nparams))) == NULL)
       {
          thread_error(" command_run_attack calloc",errno);
          return -1;
       }
       memcpy( attack_param, (void *)(theattack[aux].param),
               sizeof(struct attack_param) * theattack[aux].nparams);
       if (attack_init_params(node, attack_param, theattack[aux].nparams) < 0)
       {
          free(attack_param);
          return -1;
       }
       vty->substate = 0;
       vty->nparams = theattack[aux].nparams;
       vty->attack_param = attack_param;
       vty->attack_proto = proto;
       vty->attack_index = aux;
       node->state = PARAMS_STATE;
   }
   else
      attack_launch(node, proto, aux, NULL, 0);
   
   return 0;
}





int8_t
command_bad_input(struct term_node *node, int8_t badindex)
{
   char msg[128], *begin=NULL, *marker;
   int8_t fail, i, j, spaces, indx=0;
   struct term_vty *vty = node->specific;
   
   for(i=0;i<vty->command_len;i++)
   {
      if (*(vty->buf_command+i) != SPACE)
      {
         begin = vty->buf_command+i;
         j=0;
         while( (*(begin+j)!=SPACE) && *(begin+j))
           j++;
         if (indx == badindex) /* Gotit!!*/
            break;
         indx++;
         i+=j;
      }
   }
      
   if (term_vty_write(node,"\r\n", 2) < 0)
      return -1;
   
   /* Now the spaces...*/
   spaces = strlen(term_states[node->state].prompt2) + (begin-vty->buf_command);

   marker = (char *)calloc(1,(spaces+2));
   if ( marker == NULL)
      return -1;
   
   memset(marker,SPACE,spaces);
   
   *(marker+spaces) = '^';
      
   if (term_vty_write(node,marker,spaces+1) < 0)
   {
      free(marker);
      return -1;
   }
   
   snprintf(msg,sizeof(msg),"\r\n%% Invalid input detected at '^' marker.\r\n");
   
   fail = term_vty_write(node,msg, strlen(msg));
   
   free(marker);
   
   return fail;         
}

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */

