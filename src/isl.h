/* isl.h
 * Definitions for ISL 
 *
 * $Id: isl.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __ISL_H
#define __ISL_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

 
#define ISL_TYPE_ETHERNET   0x00
#define ISL_TYPE_TOKEN_RING 0x10
#define ISL_TYPE_FDDI       0x20
#define ISL_TYPE_ATM        0x30

#define ISL_DFL_MAC_DST "01:00:0C:00:00:00"
#define ISL_DFL_TYPE    ISL_TYPE_ETHERNET 
#define ISL_DFL_USER    0x00
#define ISL_DFL_SNAP    "\xAA\xAA\x03"

struct isl_data { 
     u_int8_t  mac_source[ETHER_ADDR_LEN];
     u_int8_t  mac_dest[ETHER_ADDR_LEN];
     u_int8_t  type;
     u_int8_t  user;
     u_int16_t len;
     u_int8_t  snap[3];
     u_int8_t  hsa[3];
     u_int16_t vlan;
     u_int8_t  bpdu;
     u_int16_t index;
     u_int16_t res;
     u_int32_t src_ip;
     u_int32_t dst_ip;
     u_int8_t  ip_proto;
};



#define ISL_TYPE_ETHERNET   0x00
#define ISL_TYPE_TOKEN_RING 0x10
#define ISL_TYPE_FDDI       0x20
#define ISL_TYPE_ATM        0x30

static const struct tuple_type_desc isl_type[] = {
     { ISL_TYPE_ETHERNET,     "ETHERNET"   },
     { ISL_TYPE_TOKEN_RING,   "TOKEN RING" },
     { ISL_TYPE_FDDI,         "FDDI"       },
     { ISL_TYPE_ATM,          "ATM"        },
     { 0, NULL }
};

static struct proto_features isl_features[] = {
     { F_LLC_DSAP, 0xaa },
     { F_LLC_SSAP, 0xaa },
     { F_LLC_SNAP, 0x03 },
     { F_DMAC_1, 0x01 },
     { F_DMAC_2, 0x00 },
     { F_DMAC_3, 0x0C },
     { F_DMAC_4, 0x00 },
     { F_DMAC_5, 0x00 },
     { -1, 0 }
};

static const struct tuple_type_desc isl_proto[] = {
     { ETHERTYPE_IP,     "IP"   },
     { ETHERTYPE_VLAN,   ".1Q"  },
     { ETHERTYPE_ARP,    "ARP"  },
     { ETHERTYPE_REVARP, "RARP" },
     { 0x2000,           "CDP"  },
     { 0x2003,           "VTP"  },
     { 0x2004,           "DTP"  },
     { 0x9000,           "LOOP" },
     { 0x010b,           "PVST" },
     { 0x4242,           "STP" },
     { 0, NULL }
};

static const struct tuple_type_desc isl_ip_proto[] = {
     { 0x01,   "icmp" },
     { 0x06,   "tcp"  },
     { 0x11,   "udp"  },
     { 0x59,   "ospf" },
     { 0,      NULL   }
};


#define ISL_SMAC       0
#define ISL_DMAC       1
#define ISL_TYPE       2
#define ISL_USER       3
#define ISL_LEN        4
#define ISL_SNAP       5 
#define ISL_HSA        6 
#define ISL_VLAN       7
#define ISL_BPDU       8
#define ISL_INDEX      9
#define ISL_RES        10
#define ISL_SRC_IP     11
#define ISL_DST_IP     12
#define ISL_IP_PROTO   13



/* Struct needed for using protocol fields within the network client */
struct commands_param isl_comm_params[] = {
    { ISL_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { ISL_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { ISL_TYPE, "type",       "Type", 1,  FIELD_HEX, "Set ISL type", 
                                        " <0-FF>    Type", 1, 2, 0, NULL, isl_type },
    { ISL_USER, "user",       "User", 1,  FIELD_HEX, "Set ISL user", 
                                        " <0-FF>    User", 1, 2, 0, NULL, NULL },
    { ISL_LEN, "len",          "Len", 2,  FIELD_HEX, "Set ISL len", 
                                        " <0-FFFF>     Len", 4, 2, 0, NULL, NULL },
    { ISL_SNAP,   "snap",     "SNAP", 3,  FIELD_HEX, "Set ISL snap", 
                                        " <0-FFFFFF>    SNAP", 6, 2, 0, NULL, NULL },
    { ISL_HSA, "hsa",          "HSA", 3,  FIELD_HEX, "Set ISL hsa", 
                                        " <0-FFFFFF>    HSA", 6, 2, 0, NULL, NULL },
    { ISL_VLAN, "vlan",       "VLAN", 2,  FIELD_HEX, "Set ISL vlan", 
                                        " <0-FFFF>    VLAN", 4, 2, 1, NULL, NULL },
    { ISL_BPDU, "bpdu",       "BPDU", 1,  FIELD_HEX, "Set ISL bpdu", 
                                        " <0-FF>     BPDU", 1, 2, 0, NULL, NULL },
    { ISL_INDEX,   "index",  "Index", 2,  FIELD_HEX, "Set ISL index", 
                                        " <0-FFFF>    Index", 4, 2, 0, NULL, NULL },
    { ISL_RES,   "res",        "Res", 2,  FIELD_HEX, "Set ISL res", 
                                        " <0-FFFF>    Res", 4, 3, 0, NULL, NULL },
    { ISL_SRC_IP, "ipsource",  "Src IP", 4, FIELD_IP, "Set ISL IP source data address", 
                                        " A.A.A.A    IPv4 address", 15, 3, 1, NULL, NULL },                
    { ISL_DST_IP, "ipdest",    "Dst IP", 4, FIELD_IP, "Set ISL IP destination data address", 
                                        " A.A.A.A    IPv4 address", 15, 3, 1, NULL, NULL },                
    { ISL_IP_PROTO, "ipproto",  "Proto", 1, FIELD_HEX, "Set ISL IP protocol", 
                                        " <0-FF>     Proto", 2, 3, 1, NULL, isl_ip_proto },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};



static struct attack isl_attack[] = {
    { 0, NULL, 0, 0, NULL, NULL, 0 }
};

void   isl_register(void);
int8_t isl_init_comms_struct(struct term_node *);
char **isl_get_printable_packet(struct pcap_data *data);
char **isl_get_printable_store(struct term_node *);
int8_t isl_init_attribs(struct term_node *);
int8_t isl_end(struct term_node *);

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
extern void   parser_basedisplay(u_int8_t, u_int8_t, char *, size_t );

extern struct terminals *terms;

extern int8_t bin_data[];

#endif
