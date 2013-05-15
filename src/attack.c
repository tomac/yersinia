/* attack.c
 * Attacks management core
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
       "$Id: attack.c 46 2007-05-08 09:13:30Z slay $";
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

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else
#ifdef HAVE_NETINET_IN_SYSTEM_H
#include <netinet/in_system.h>
#endif
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
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

#include "attack.h"


/* Launch choosed attack... */
int8_t
attack_launch(struct term_node *node, u_int16_t proto, u_int16_t attack, 
              struct attack_param *attack_params, u_int8_t nparams)
{
    u_int16_t i = 0;
    dlist_t *p;
    void *value1, *value2;

    while (i < MAX_THREAD_ATTACK) 
    {
        if (node->protocol[proto].attacks[i].up == 0) 
        {
            node->protocol[proto].attacks[i].up = 1;
            node->protocol[proto].attacks[i].mac_spoofing = node->mac_spoofing;
            node->protocol[proto].attacks[i].attack  = attack;
            node->protocol[proto].attacks[i].params  = attack_params;
            node->protocol[proto].attacks[i].nparams = nparams;
            /* FIXME: temporal hasta ponerlo bien, pillamos para el ataque las interfaces del usuario */
            node->protocol[proto].attacks[i].used_ints = (list_t *) calloc(1, sizeof(list_t));
            for (p = node->used_ints->list; p; p = dlist_next(node->used_ints->list, p)) {
               value1 = dlist_data(p);
               value2 = (void *) calloc(1, sizeof(struct interface_data));
               memcpy((void *)value2, (void *)value1, sizeof(struct interface_data));
               node->protocol[proto].attacks[i].used_ints->list = 
                        dlist_append(node->protocol[proto].attacks[i].used_ints->list, value2); 
            }
            node->protocol[proto].attacks[i].used_ints->cmp = interfaces_compare;

            if ((node->protocol[proto].attacks[i].data = calloc(1, protocols[proto].size )) == NULL)
            {
                thread_error("attack_launch calloc",errno);
                node->protocol[proto].attacks[i].params  = NULL;
                node->protocol[proto].attacks[i].nparams = 0;
                node->protocol[proto].attacks[i].up = 0;
                return -1;
            }
            memcpy(node->protocol[proto].attacks[i].data, 
                   node->protocol[proto].tmp_data, protocols[proto].size );

            if (pthread_mutex_init(&node->protocol[proto].attacks[i].attack_th.finished, NULL) != 0)
            {
               thread_error("attack_launch pthread_mutex_init mutex", errno);
               free(node->protocol[proto].attacks[i].data);
               return -1;
            }

            if (pthread_mutex_init(&node->protocol[proto].attacks[i].helper_th.finished, NULL) != 0)
            {
               thread_error("attack_launch pthread_mutex_init mutex", errno);
               free(node->protocol[proto].attacks[i].data);
               return -1;
            }

            if (thread_create(&node->protocol[proto].attacks[i].attack_th.id, 
                             (*protocols[proto].attacks[attack].attack_th_launch), 
                             &node->protocol[proto].attacks[i]) < 0)
            {
                free(node->protocol[proto].attacks[i].data);
                node->protocol[proto].attacks[i].params  = NULL;
                node->protocol[proto].attacks[i].nparams = 0;
                node->protocol[proto].attacks[i].up      = 0;
                return -1;
            }
            write_log(0, " attack_launch: %d Attack thread %ld is born!!\n", (int)pthread_self(),
            (u_long) node->protocol[proto].attacks[i].attack_th.id);
            return 0;
        }
        i++;
    } /* while...*/

    return -1;
}


/* 
 * Kill attack thread pertaining to "node".
 * If "pid" == 0 then kill *ALL* node attack threads.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t
attack_kill_th(struct term_node *node, pthread_t pid)
{
    u_int16_t i, j;

    i = 0;

    while (i < MAX_PROTOCOLS) 
    {
        if (protocols[i].visible && node->protocol[i].attacks)
        {   
            j=0;
            while (j < MAX_THREAD_ATTACK) 
            {
                if (node->protocol[i].attacks[j].up == 1) 
                {
                    if (!pid || (node->protocol[i].attacks[j].attack_th.id == pid) ) 
                    {
                       thread_destroy(&node->protocol[i].attacks[j].attack_th);
                       pthread_mutex_destroy(&node->protocol[i].attacks[j].attack_th.finished);
                       if (pid)
                           return 0;
                    }
                }
                j++;
            }
        }
        i++;
    } /* while protocols...*/
    
    return 0;
}


int8_t 
attack_th_exit(struct attacks *attacks)
{
write_log(0," attack_th_exit -> attack_th.stop=%d   attack_th.id=%d....\n",attacks->attack_th.stop,
attacks->attack_th.id);

    if (attacks->attack_th.stop == 0)
       attacks->attack_th.id = 0;
    else
       attacks->attack_th.stop = 0;

    if (attacks->helper_th.id) 
    {
       write_log(0," attack_th_exit: %d thread_destroy helper %d...\n",
                 (int)pthread_self(), (int)attacks->helper_th.id);    
       thread_destroy(&attacks->helper_th);
    }    

    pthread_mutex_destroy(&attacks->helper_th.finished);

    if (attacks->data)
    {
        free(attacks->data);
    }
    
    if (attacks->params)
    {
       attack_free_params(attacks->params, attacks->nparams);
       free(attacks->params);
    }
    
    attacks->data   = NULL;
    attacks->params = NULL;
    attacks->up     = 0;

    dlist_delete(attacks->used_ints->list);

    if (attacks->used_ints)
       free(attacks->used_ints);

    write_log(0, " attack_th_exit: %d finished\n", (int) pthread_self());
    
    return 0;
}


/*
 *  macof.c
 *  gen_mac from Dug Song's macof-1.1 C port
 */
void
attack_gen_mac(u_int8_t *mac)
{
    *((in_addr_t *)mac) = libnet_get_prand(LIBNET_PRu32);
    *((u_int16_t *)(mac + 4)) = libnet_get_prand(LIBNET_PRu16);
}


int8_t
attack_init_params(struct term_node *node, struct attack_param *param, u_int8_t nparams)
{
   u_int8_t i, j, a;

   for (i=0; i < nparams; i++)
   {
       if ( (param[i].value = calloc(1, param[i].size) ) == NULL)
       {
           thread_error("attack_init_parameter calloc",errno);
           for (a=0; a<i; a++)
              free(param[a].value);
           return -1;
       }
   }
   
   if (node->type == TERM_CON)
   {
      for (j=0; j < nparams; j++)
      {
           if ( (param[j].print = calloc(1, param[j].size_print+1) ) == NULL)
           {
               thread_error("attack_init_parameter calloc",errno);
               for (a=0; a<j; a++)
                  free(param[a].print);
               for (a=0; a<i; a++)
                  free(param[a].value);
               return -1;
           }
       }
   }

   return 0;
}

void
attack_free_params(struct attack_param *param, u_int8_t nparams)
{
   u_int8_t i;

   for (i=0; i < nparams; i++)
   {
       if (param[i].value)
       {
          free(param[i].value);
       }
       if (param[i].print)
       {       
          free(param[i].print);
       }
   }
}


/*
 * Filter all attack parameters
 * On success Return 0.
 * On error Return -1 and error field number on "field".
 */
int8_t 
attack_filter_all_params(struct attack_param *attack_param, u_int8_t nparams, u_int8_t *field)
{
    u_int8_t j;

    for (j=0; j<nparams; j++)
    {
       if ( parser_filter_param(attack_param[j].type, 
                                attack_param[j].value,
                                attack_param[j].print,
                                attack_param[j].size_print,
                                attack_param[j].size ) < 0 )
       {
          *field = j;
          return -1;
       }
    }

    return 0;
}
