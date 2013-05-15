/* dot1x.h
 * Definitions for IEEE 802.1X
 *
 * $Id: dot1x.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __DOT_1X_H
#define __DOT_1X_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"


struct dot1x_header {
    u_int8_t  version;
    u_int8_t  type;
    u_int16_t len;
};

struct eap_header {
    u_int8_t  code;
    u_int8_t  id;
    u_int16_t len;
};


#define DOT1X_DFL_MAC_DST  "01:80:C2:00:00:03"
#define DOT1X_DFL_VER      0x01
#define DOT1X_DFL_TYPE     0x00
#define DOT1X_DFL_EAP_TYPE 0x01
#define DOT1X_DFL_EAP_CODE 0x02
#define DOT1X_DFL_EAP_ID   0x00
#define DOT1X_DFL_EAP_INFO "Andrea Amati"

#define MAX_EAP_INFO 64


struct dot1x_data { 
     u_int8_t  mac_source[ETHER_ADDR_LEN];
     u_int8_t  mac_dest[ETHER_ADDR_LEN];
     u_int8_t  version;
     u_int8_t  type;
     u_int16_t len;
     u_int8_t  eap_code;
     u_int8_t  eap_id;
     u_int16_t eap_len;
     u_int8_t  eap_type;
     u_int8_t  eap_info[MAX_EAP_INFO+1];
     u_int8_t  eap_info_len;
};


#define DOT1X_TYPE_EAP  0x00

static const struct tuple_type_desc dot1x_type[] = {
     { DOT1X_TYPE_EAP, "EAP" },
     { 0,              NULL  }
};


#define DOT1X_EAP_REQUEST  0x01
#define DOT1X_EAP_RESPONSE 0x02
#define DOT1X_EAP_SUCCESS  0x03
#define DOT1X_EAP_FAILURE  0x04

static const struct tuple_type_desc dot1x_eap_code[] = {
     { DOT1X_EAP_REQUEST,  "REQUEST"  },
     { DOT1X_EAP_RESPONSE, "RESPONSE" },
     { DOT1X_EAP_SUCCESS,  "SUCCESS"  },
     { DOT1X_EAP_FAILURE,  "FAILURE"  },
     { 0,                  NULL       }
};

#define DOT1X_EAP_IDENTITY 0x01
static const struct tuple_type_desc dot1x_eap_type[] = {
     { 0x01, "Identity"     },
     { 0x02, "Notification" },
     { 0x0d, "TLS"          },
     { 0x04, "MD5"          },
     { 0x05, "OTP"          },
     { 0x06, "Token Card"   },
     { 0x11, "LEAP Cisco"   },
     { 0,    NULL           }
};

            
static struct proto_features dot1x_features[] = {
     { F_ETHERTYPE, ETHERTYPE_EAP },
     { -1, 0 }
};

#define DOT1X_SMAC     0
#define DOT1X_DMAC     1
#define DOT1X_VER      2
#define DOT1X_TYPE     3
#define DOT1X_EAP_CODE 4
#define DOT1X_EAP_ID   5
#define DOT1X_EAP_TYPE 6
#define DOT1X_EAP_INFO 7

/* Struct needed for using protocol fields within the network client */
struct commands_param dot1x_comm_params[] = {
    { DOT1X_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DOT1X_DMAC, "dest",      "Destination MAC", 6,FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DOT1X_VER, "version",   "Ver", 1, FIELD_HEX, "Set 802.1X version", 
                       " <00-FF>    802.1X version", 2, 2, 0, NULL, NULL },
    { DOT1X_TYPE, "type",      "Type", 1, FIELD_HEX, "Set 802.1X type", 
                       " <00-FF>    type", 2, 2, 1, NULL, dot1x_type },
    { DOT1X_EAP_CODE, "eapcode", "EAPCode", 1, FIELD_HEX, "Set 802.1X EAP code", 
                      " <00-FF>         EAP code", 2, 2, 1, NULL, dot1x_eap_code },
    { DOT1X_EAP_ID,   "eapid",   "EAPId", 1, FIELD_HEX, "Set 802.1X EAP id", 
                                        " <00-FF>         EAP id",   2, 2, 0, NULL, NULL },
    { DOT1X_EAP_TYPE, "eaptype", "EAPType", 1, FIELD_HEX, "Set 802.1X EAP type", 
                                        " <00-FF>         EAP type", 2, 2, 1, NULL, dot1x_eap_type },
    { DOT1X_EAP_INFO, "eapinfo", "EAPInfo", MAX_EAP_INFO, FIELD_STR, "Set 802.1X EAP identity info", 
                                        " WORD         ASCII info", MAX_EAP_INFO, 3, 1, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};


void dot1x_th_send(void *);
void dot1x_th_send_exit(struct attacks *);
void dot1x_th_mitm(void *);
void dot1x_th_mitm_exit(struct attacks *);


struct dot1x_mitm_ifaces {
   struct interface_data *auth;
   struct interface_data *supp;
   u_int8_t mac_auth[ETHER_ADDR_LEN];
   u_int8_t mac_supp[ETHER_ADDR_LEN];
};

#define DOT1X_MITM_IFACE_SUPP 0
#define DOT1X_MITM_IFACE_AUTH 1

static struct attack_param dot1x_mitm_params[] = {
    { NULL, "Supplicant interface",    1, FIELD_IFACE, IFNAMSIZ, NULL },
    { NULL, "Authenticator interface", 1, FIELD_IFACE, IFNAMSIZ, NULL },
};


#define DOT1X_ATTACK_SEND 0
#define DOT1X_ATTACK_MITM 1

static struct attack dot1x_attack[] = {
    { DOT1X_ATTACK_SEND, "sending 802.1X packet",         NONDOS, SINGLE,    dot1x_th_send, NULL, 0           },
    { DOT1X_ATTACK_MITM, "Mitm 802.1X with 2 interfaces", NONDOS, CONTINOUS, dot1x_th_mitm, dot1x_mitm_params,
              SIZE_ARRAY(dot1x_mitm_params) },
    { 0,                 NULL,                            0,      0,         NULL,          NULL, 0           }
};


void   dot1x_register(void);
int8_t dot1x_send(struct attacks *);
int8_t dot1x_send_raw(struct interface_data *, u_int8_t *, u_int16_t, u_int8_t *, u_int8_t *);
int8_t dot1x_init_attribs(struct term_node *);
int8_t dot1x_learn_packet(struct attacks *, char *, u_int8_t *,void *, struct pcap_pkthdr *);
char **dot1x_get_printable_packet(struct pcap_data *);
char **dot1x_get_printable_store(struct term_node *);
int8_t dot1x_load_values(struct pcap_data *, void *);
int8_t dot1x_update_field(int8_t, struct term_node *, void *);
int8_t dot1x_init_comms_struct(struct term_node *);
int8_t dot1x_end(struct term_node *);

extern void   thread_libnet_error( char *, libnet_t *);
extern int8_t vrfy_bridge_id( char *, u_int8_t * );
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern void   attack_gen_mac(u_int8_t *);
extern struct interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern int8_t parser_get_inet_aton(char *, struct in_addr *);
extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
extern int8_t parser_command2index(register const struct attack *, register int8_t);

extern struct terminals *terms;

extern int8_t bin_data[];

#endif
