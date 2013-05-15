/* protocols.c
 * Protocols stuff
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
"$Id: protocols.c 43 2007-04-27 11:07:17Z slay $";
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

#include <ctype.h>

#include "protocols.h"

void
protocol_init(void)
{
    protocol_register_all();
}


int8_t
protocol_register(u_int8_t proto, const char *name, const char *desc,
      const char *name_comm, u_int16_t size, init_attribs_t init,
      learn_packet_t learn, get_printable_packet_t packet,
      get_printable_store_t store, 
      load_values_t load,
      struct attack *attacks, 
      update_field_t update_field, 
      struct proto_features *features, 
      struct commands_param *param, 
      u_int8_t nparams, 
      struct commands_param_extra *extra_parameters, 
      u_int8_t extra_nparams, get_extra_field_t extra,
      init_commands_struct_t init_commands, 
      u_int8_t visible, 
      end_t end)
{
   u_int8_t i;

   if (proto > MAX_PROTOCOLS)
      return -1;

   protocols[proto].proto = proto;
   strncpy(protocols[proto].namep, name, MAX_PROTO_NAME);
   strncpy(protocols[proto].description, desc, MAX_PROTO_DESCRIPTION);
   strncpy(protocols[proto].name_comm, name_comm, MAX_PROTO_NAME);
   protocols[proto].size = size;
   protocols[proto].active = 1;      /* default is active */
   protocols[proto].visible = visible;  
   protocols[proto].init_attribs = init;
   protocols[proto].learn_packet = learn;
   protocols[proto].get_printable_packet = packet;
   protocols[proto].get_printable_store = store;
   protocols[proto].load_values = load;
   protocols[proto].attacks = attacks;
   protocols[proto].update_field = update_field;
   protocols[proto].features = features;
   protocols[proto].parameters = param;
   protocols[proto].nparams = nparams;
   protocols[proto].extra_parameters = extra_parameters;
   protocols[proto].extra_nparams = extra_nparams;
   protocols[proto].get_extra_field = extra;
   protocols[proto].init_commands_struct = init_commands;
   protocols[proto].end = end;

   for (i = 0; i < MAX_PACKET_STATS; i++) {
      if ((protocols[proto].stats[i].header = (struct pcap_pkthdr *) calloc(1, sizeof(struct pcap_pkthdr))) == NULL)
         return -1;

      if ((protocols[proto].stats[i].packet = (u_char *) calloc(1, SNAPLEN)) == NULL)
         return -1;
   }

   protocols[proto].packets = 0;
   protocols[proto].packets_out = 0;

   /* Default values */
   if ((protocols[proto].default_values = calloc(1, size)) == NULL)
      return -1;
      
#ifdef HAVE_REMOTE_ADMIN
   /* Sorted CLI parameters...*/
   protocols[proto].params_sort = (u_int8_t *)calloc(1,nparams);

   if (protocols[proto].params_sort == NULL)
      return -1;

   for(i=0; i < nparams; i++)
     protocols[proto].params_sort[i] = i;
      
   protocol_sort_params(proto,protocols[proto].params_sort,nparams);
#endif

   return 0;
}






int8_t
protocol_register_tlv(u_int8_t proto, edit_tlv_t edit_tlv, const struct tuple_type_desc *ttd, 
      struct attack_param *tlv, u_int16_t params)
{
   if (proto > MAX_PROTOCOLS)
      return -1;

   protocols[proto].edit_tlv = edit_tlv;
   protocols[proto].ttd = ttd;
   protocols[proto].tlv = tlv;
   protocols[proto].tlv_params = params;

   return 0;
}


void
protocol_register_all(void)
{
    { extern void xstp_register(void);  xstp_register();  }
    { extern void cdp_register(void);   cdp_register();   }
    { extern void dtp_register(void);   dtp_register();   }
    { extern void dhcp_register(void);  dhcp_register();  }
    { extern void hsrp_register(void);  hsrp_register();  }
    { extern void dot1q_register(void); dot1q_register(); }
    { extern void isl_register(void);   isl_register();   }
    { extern void vtp_register(void);   vtp_register();   }
    { extern void arp_register(void);   arp_register();   }
    { extern void dot1x_register(void); dot1x_register(); }
    { extern void mpls_register(void);  mpls_register(); }
}


void
protocol_destroy(void)
{
   int8_t i, j;

   for (i = 0; i < MAX_PROTOCOLS; i++)
   {
      for (j = 0; j < MAX_PACKET_STATS; j++) 
      {
         if (protocols[i].stats[j].header)
            free(protocols[i].stats[j].header);
         if (protocols[i].stats[j].packet)
            free(protocols[i].stats[j].packet);
      }
      if (protocols[i].default_values)
         free(protocols[i].default_values);
#ifdef HAVE_REMOTE_ADMIN
       /* Ordered CLI parameters...*/
      if (protocols[i].params_sort)
         free(protocols[i].params_sort);
#endif
   }
}


char **
protocol_create_printable(u_int8_t size, struct commands_param *params)
{
   u_int8_t i, k;
   char **field_values;

   field_values = NULL;

   /* +2 for the extra values and the null */
   if ((field_values = (char **) calloc(1, (size+2)* sizeof(u_int8_t *))) == NULL) {
      printf("Error in calloc\n");
      return NULL;
   }

   k = 0;
   for (i = 0; i < size; i++)
   {
      if ((params[i].type != FIELD_IFACE) && (params[i].type != FIELD_DEFAULT) && (params[i].size_print > 0))
      {
/*         write_log(0, "Creando  i=%d   k=%d    %s   size_print=%d\n", i, k, params[i].ldesc, params[i].size_print); */
         if ((field_values[k] = (char *) calloc(1, (params[i].size_print + 1) * sizeof(char))) == NULL) {
            printf("Error in calloc\n");
            return NULL;
         }
         k++;
      }
   }

   return field_values;
}



/*
 * Return the index associated to the protocol 'name' being 'name' the name
 * used in the CLI and in command line.
 * The protocol must be a *VISIBLE* one.
 * Return -1 if protocol 'name' doesn't exist
 */
int8_t
protocol_proto2index(char *name)
{
   u_int8_t i=0;

   while (i < MAX_PROTOCOLS) 
   {
      if (protocols[i].visible)
      {
         if (!strcasecmp(protocols[i].name_comm, name))
            return (protocols[i].proto);
      }
      ++i;
   }
   return -1;
}

int8_t
protocol_extra_compare(void *data, void *pattern)
{
   struct commands_param_extra *extra;

   extra = (struct commands_param_extra *) data;
   write_log(0, "comparando %ld con %ld\n", extra->id, (*(u_int32_t *)pattern));
   return(memcmp(&extra->id, pattern, 4));
}

#ifdef HAVE_REMOTE_ADMIN
/*
 * Sort parameter list alphabetically
 */ 
void
protocol_sort_params(u_int8_t proto, u_int8_t *aux_comm, u_int8_t nparams)
{
   u_int8_t i, j, aux_data;
   char *aux;

   for(i=0; i < nparams; i++)
   { 
      for(j=nparams-1; j > i; --j) 
      {
          aux = protocol_sort_str(protocols[proto].parameters[aux_comm[j-1]].desc,
                                  protocols[proto].parameters[aux_comm[j]].desc);
          if (aux == protocols[proto].parameters[aux_comm[j-1]].desc)
          {
             aux_data = aux_comm[j-1];
             aux_comm[j-1] = aux_comm[j];
             aux_comm[j] = aux_data;
          }
      }
   }
}


char *
protocol_sort_str(char *s1, char *s2)
{
  int len, i;
  char c1, c2;

  if (strlen(s1)<strlen(s2))
     len = strlen(s1);
  else
     len = strlen(s2);

  for (i=0; i< len; i++)
  {
      c1 = tolower(*(s1+i));
      c2 = tolower(*(s2+i));  
      if (c1 > c2)
          return s1;
      if (c1 < c2)
          return s2;
  }
 
  if (strlen(s1)< strlen(s2))
     return s2;
     
  return s1;
}
#endif
