/* isl.c
 * Implementation and attacks for Inter-Switch Link Protocol
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
       "$Id: isl.c 43 2007-04-27 11:07:17Z slay $";
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

#include "isl.h"


void
isl_register(void)
{
   protocol_register(PROTO_ISL, "ISL", "Inter-Switch Link Protocol", "isl",
                     sizeof(struct isl_data), 
                     isl_init_attribs, 
                     NULL, 
                     isl_get_printable_packet, 
                     isl_get_printable_store, 
                     NULL, 
                     isl_attack, 
                     NULL, 
                     isl_features, 
                     isl_comm_params,
                     SIZE_ARRAY(isl_comm_params), 
                     NULL,
                     0, 
                     NULL,
                     isl_init_comms_struct, 
                     PROTO_VISIBLE, 
                     isl_end);
}

int8_t
isl_init_comms_struct(struct term_node *node)
{
    struct isl_data *isl_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(isl_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("isl_init_comms_struct calloc error",errno);
       return -1;
    }

    isl_data = node->protocol[PROTO_ISL].tmp_data;
    
    node->protocol[PROTO_ISL].commands_param = comm_param;
    
    comm_param[ISL_SMAC]     = &isl_data->mac_source; 
    comm_param[ISL_DMAC]     = &isl_data->mac_dest; 
    comm_param[ISL_TYPE]     = &isl_data->type; 
    comm_param[ISL_USER]     = &isl_data->user; 
    comm_param[ISL_LEN]      = &isl_data->len; 
    comm_param[ISL_SNAP]     = &isl_data->snap; 
    comm_param[ISL_HSA]      = &isl_data->hsa; 
    comm_param[ISL_VLAN]     = &isl_data->vlan; 
    comm_param[ISL_BPDU]     = &isl_data->bpdu; 
    comm_param[ISL_INDEX]    = &isl_data->index; 
    comm_param[ISL_RES]      = &isl_data->res; 
    comm_param[ISL_SRC_IP]   = &isl_data->src_ip; 
    comm_param[ISL_DST_IP]   = &isl_data->dst_ip; 
    comm_param[ISL_IP_PROTO] = &isl_data->ip_proto; 
    comm_param[14]           = NULL; 
    comm_param[15]           = NULL; 

    return 0;
}

/* 
 * Return formated strings of each ISL field
 */
char **
isl_get_printable_packet(struct pcap_data *data)
{
    char **field_values;
    u_int16_t aux_short;

    if (data && (data->header->caplen < (14+8+8)) ) /* Undersized packet!! */
       return NULL;

    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_ISL].nparams, protocols[PROTO_ISL].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    /* Source MAC */
    snprintf(field_values[ISL_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       data->packet[6], data->packet[7], data->packet[8],
       data->packet[9], data->packet[10], data->packet[11]);
    /* Destination MAC */
    snprintf(field_values[ISL_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
       data->packet[0], data->packet[1], data->packet[2],
       data->packet[3], data->packet[4], 0x00);
    
    snprintf(field_values[ISL_TYPE], 2, "%01X", (*(u_int8_t *)(data->packet+5) & 0xF0));

    snprintf(field_values[ISL_USER], 2, "%01X", (*(u_int8_t *)(data->packet+5) & 0x0F));

    snprintf(field_values[ISL_LEN], 5, "%04X", (ntohs(*((u_int16_t *)data->packet+12))));

    snprintf(field_values[ISL_SNAP], 7, "%02X%02X%02X", (*(u_int8_t *)(data->packet+14)), (*(u_int8_t *)(data->packet+15)), 
            (*(u_int8_t *)(data->packet + 16)));

    snprintf(field_values[ISL_HSA], 7, "%02X%02X%02X", (*(u_int8_t *)(data->packet+17)), (*(u_int8_t *)(data->packet+18)), 
            (*(u_int8_t *)(data->packet + 19)));

    aux_short = ntohs(*((u_int16_t *)(data->packet+20)));
    aux_short >>= 1;
    snprintf(field_values[ISL_VLAN], 5, "%04X", aux_short);

    snprintf(field_values[ISL_BPDU], 2, "%01d", (ntohs(*((u_int16_t *)(data->packet+20))) & 0x1));

    snprintf(field_values[ISL_INDEX], 5, "%04X", (ntohs(*((u_int16_t *)(data->packet+22)))));

    snprintf(field_values[ISL_RES], 5, "%04X", (ntohs(*((u_int16_t *)(data->packet+24)))));
    
    return (char **)field_values;    
}



char **
isl_get_printable_store(struct term_node *node)
{
    struct isl_data *isl_tmp;
    char **field_values;
#ifdef LBL_ALIGN
    u_int8_t *aux;
#endif
    
    if ((field_values = (char **) protocol_create_printable(protocols[PROTO_ISL].nparams, protocols[PROTO_ISL].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

	if (node == NULL)
		isl_tmp = protocols[PROTO_ISL].default_values;
	else
        isl_tmp = (struct isl_data *) node->protocol[PROTO_ISL].tmp_data;

    /* Source MAC */
    snprintf(field_values[ISL_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	    isl_tmp->mac_source[0], isl_tmp->mac_source[1],
	    isl_tmp->mac_source[2], isl_tmp->mac_source[3],
	    isl_tmp->mac_source[4], isl_tmp->mac_source[5]);

    /* Destination MAC */
    snprintf(field_values[ISL_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        isl_tmp->mac_dest[0], isl_tmp->mac_dest[1], isl_tmp->mac_dest[2],
        isl_tmp->mac_dest[3], isl_tmp->mac_dest[4], isl_tmp->mac_dest[5]);

    snprintf(field_values[ISL_TYPE], 2, "%01X", isl_tmp->type & 0x0F);

    snprintf(field_values[ISL_USER], 2, "%01X", isl_tmp->user & 0x0F);

    snprintf(field_values[ISL_LEN], 5, "%04X", isl_tmp->len);

    snprintf(field_values[ISL_SNAP], 7, "%02X%02X%02X", isl_tmp->snap[0], isl_tmp->snap[1],
            isl_tmp->snap[2]);

    snprintf(field_values[ISL_HSA], 7, "%02X%02X%02X", isl_tmp->hsa[0], isl_tmp->hsa[1],
            isl_tmp->hsa[2]);

    snprintf(field_values[ISL_VLAN], 5, "%04X", isl_tmp->vlan);

    snprintf(field_values[ISL_BPDU], 2, "%01d", isl_tmp->bpdu & 0x01);

    snprintf(field_values[ISL_INDEX], 5, "%04X", isl_tmp->index);
    
    snprintf(field_values[ISL_RES], 5, "%04X", isl_tmp->res);
               
    /* Source IP */
    parser_get_formated_inet_address(isl_tmp->src_ip, field_values[ISL_SRC_IP], 16);
    
    /* Destination IP */
    parser_get_formated_inet_address(isl_tmp->dst_ip, field_values[ISL_DST_IP], 16);

    /* IP protocol */
    snprintf(field_values[ISL_IP_PROTO], 3, "%02d",isl_tmp->ip_proto);

    return (char **)field_values;
}


int8_t
isl_init_attribs(struct term_node *node)
{
    struct isl_data *isl_data;

    isl_data = node->protocol[PROTO_ISL].tmp_data;

    attack_gen_mac(isl_data->mac_source);

    isl_data->mac_source[0] &= 0x0E; 
    
    parser_vrfy_mac(ISL_DFL_MAC_DST, isl_data->mac_dest);
    
    isl_data->type      = ISL_DFL_TYPE;
    isl_data->user      = 0x0;
    isl_data->len       = 0x0;
    memcpy((void *)isl_data->snap, (void *)ISL_DFL_SNAP, 3);
    memcpy((void *)isl_data->hsa, "\x00\x00\x00", 3);

    isl_data->vlan = libnet_get_prand(LIBNET_PRu16);

    isl_data->bpdu       = 0x0;
    isl_data->index      = 0x0;
    isl_data->res        = 0x0;

    isl_data->src_ip = ntohl(inet_addr("10.0.0.1"));
    isl_data->dst_ip = ntohl(inet_addr("255.255.255.255"));

    isl_data->ip_proto = 1;
    
    return 0;
}


int8_t
isl_end(struct term_node *node)
{
   return 0;
}
