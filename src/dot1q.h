/* dot1q.h
 * Definitions for IEEE 802.1Q
 *
 * $Id: dot1q.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __DOT_1Q_H
#define __DOT_1Q_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define MAX_ICMP_PAYLOAD 16
 
#define DOT1Q_DFL_MAC_DST "FF:FF:FF:FF:FF:FF"
#define DOT1Q_DFL_TPI1    ETHERTYPE_VLAN
#define DOT1Q_DFL_PRIO1   0x007
#define DOT1Q_DFL_CFI1    0x000
#define DOT1Q_DFL_VLAN1   0x001
#define DOT1Q_DFL_TPI2    ETHERTYPE_IP
#define DOT1Q_DFL_PRIO2   0x007
#define DOT1Q_DFL_CFI2    0x000
#define DOT1Q_DFL_VLAN2   0x002
#define DOT1Q_DFL_TPI3    ETHERTYPE_IP
#define DOT1Q_DFL_DST_IP  0xffffffff
#define DOT1Q_DFL_PAYLOAD "YERSINIA"
#define DOT1Q_DFL_PAY_LEN 8

struct dot1q_data { 
     u_int8_t  mac_source[ETHER_ADDR_LEN];
     u_int8_t  mac_dest[ETHER_ADDR_LEN];
     u_int16_t tpi1;
     u_int8_t  priority1;
     u_int8_t  cfi1;
     u_int16_t vlan1;
     u_int16_t tpi2;
     u_int8_t  priority2;
     u_int8_t  cfi2;
     u_int16_t vlan2;
     u_int16_t tpi3;
     u_int32_t src_ip;
     u_int32_t dst_ip;
     u_int8_t  ip_proto;
     u_int8_t  icmp_payload[MAX_ICMP_PAYLOAD+1];
     u_int8_t  icmp_pay_len;
};


static const struct tuple_type_desc dot1q_tpi[] = {
     { ETHERTYPE_IP,     "IP"   },
     { ETHERTYPE_VLAN,   "802.1Q"  },
     { ETHERTYPE_ARP,    "ARP"  },
     { ETHERTYPE_REVARP, "RARP" },
     { 0x2000,           "CDP"  },
     { 0x2003,           "VTP"  },
     { 0x2004,           "DTP"  },
     { 0x9000,           "LOOP" },
     { 0x010b,           "PVST" },
     { 0, NULL }
};

static const struct tuple_type_desc dot1q_ip_proto[] = {
     { 0x01,   "icmp" },
     { 0x06,   "tcp"  },
     { 0x11,   "udp"  },
     { 89,     "ospf" },
     { 0,      NULL   }
};

static struct proto_features dot1q_features[] = {
     { F_ETHERTYPE, ETHERTYPE_VLAN },
     { -1, 0 }
};

#define DOT1Q_SMAC       0
#define DOT1Q_DMAC       1
#define DOT1Q_VLAN1      2 
#define DOT1Q_PRIORITY1  3
#define DOT1Q_CFI1       4
#define DOT1Q_TPI2       5
#define DOT1Q_VLAN2      6 
#define DOT1Q_PRIORITY2  7
#define DOT1Q_CFI2       8
#define DOT1Q_TPI3       9
#define DOT1Q_SRC_IP    10
#define DOT1Q_DST_IP    11
#define DOT1Q_IP_PROTO  12
#define DOT1Q_PAYLOAD   13


/* Struct needed for using protocol fields within the network client */
struct commands_param dot1q_comm_params[] = {
    { DOT1Q_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DOT1Q_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DOT1Q_VLAN1, "vlan1",     "VLAN", 2,  FIELD_DEC, "Set 802.1Q vlan1 (outer) ID", 
                                        " <0-4095>    Outer vlan id", 4, 2, 1, NULL, NULL },
    { DOT1Q_PRIORITY1, "priority1", "Priority", 1, FIELD_DEC, "Set 802.1Q vlan1 (outer) priority", 
                                        " <0-7>    Priority", 2, 2, 0, NULL, NULL },
    { DOT1Q_CFI1, "cfi1",      "CFI", 1, FIELD_HEX, "Set 802.1Q cfi1 (outer) ID", 
                                        " <0-FF>     CFI1 id", 2, 2, 0, NULL, NULL },
    { DOT1Q_TPI2,   "l2proto1",     "L2Proto1", 2, FIELD_HEX, "Set 802.1Q L2 protocol1", 
                                        " <0-FFFF>    Protocol", 4, 2, 1, NULL, dot1q_tpi },
    { DOT1Q_VLAN2, "vlan2",     "VLAN2", 2, FIELD_DEC, "Set 802.1Q vlan1 (outer) ID", 
                                        " <0-4095>    Inner vlan id", 4, 2, 0, NULL, NULL },
    { DOT1Q_PRIORITY2, "priority2", "Priority", 1, FIELD_DEC, "Set 802.1Q vlan2 (inner) priority", 
                                        " <0-7>    Priority", 2, 2, 0, NULL, NULL },
    { DOT1Q_CFI2, "cfi2",      "CFI", 1, FIELD_HEX, "Set 802.1Q cfi2 (inner) ID", 
                                        " <0-FF>     CFI2 id", 2, 2, 0, NULL, NULL },
    { DOT1Q_TPI3,   "l2proto2",     "L2Proto2", 2, FIELD_HEX, "Set 802.1Q L2 protocol2", 
                                        " <0-FFFF>    Protocol", 4, 3, 0, NULL, dot1q_tpi },
    { DOT1Q_SRC_IP, "ipsource",  "Src IP", 4, FIELD_IP, "Set 802.1Q IP source data address", 
                                        " A.A.A.A    IPv4 address", 15, 3, 1, NULL, NULL },                
    { DOT1Q_DST_IP, "ipdest",    "Dst IP", 4, FIELD_IP, "Set 802.1Q IP destination data address", 
                                        " A.A.A.A    IPv4 address", 15, 3, 1, NULL, NULL },                
    { DOT1Q_IP_PROTO, "ipproto",  "IP Prot", 1, FIELD_HEX, "Set 802.1Q IP protocols", 
                                        " <0-FF>     IP protocol", 2, 3, 1, NULL, dot1q_ip_proto },
    { DOT1Q_PAYLOAD, "payload",   "Payload", MAX_ICMP_PAYLOAD, FIELD_STR, "Set 802.1Q ICMP payload", 
                                        " WORD         ASCII payload", MAX_ICMP_PAYLOAD, 4, 0, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};


void dot1q_th_send(void *);
void dot1q_th_send_exit(struct attacks *);
void dot1q_double_th_send(void *);
void dot1q_double_th_send_exit(struct attacks *);
void dot1q_th_poison(void *);
void dot1q_th_poison_exit(struct attacks *);


#define DOT1Q_ARP_IP     0
#define DOT1Q_ARP_VLAN   1
#define DOT1Q_ARP_IP_SRC 2

static struct attack_param dot1q_arp_params[] = {
    { NULL, "IP to poison",  4, FIELD_IP,  15, NULL },
    { NULL, "IP VLAN",       2, FIELD_DEC,  4, NULL },
    { NULL, "ARP IP Source", 4, FIELD_IP,  15, NULL }
};


#define DOT1Q_ATTACK_SEND   0
#define DOT1Q_ATTACK_DOUBLE 1
#define DOT1Q_ATTACK_POISON 2

static struct attack dot1q_attack[] = {
    { DOT1Q_ATTACK_SEND,   "sending 802.1Q packet",             NONDOS, SINGLE,    dot1q_th_send,        NULL, 0           },
    { DOT1Q_ATTACK_DOUBLE, "sending 802.1Q double enc. packet", NONDOS, SINGLE,    dot1q_double_th_send, NULL, 0           },
    { DOT1Q_ATTACK_POISON, "sending 802.1Q arp poisoning",      DOS,    CONTINOUS, dot1q_th_poison,      dot1q_arp_params,
              SIZE_ARRAY(dot1q_arp_params) },
    { 0,                   NULL,                                0,      0,         NULL,                 NULL, 0           }
};


void dot1q_register(void);
int8_t dot1q_send_icmp(struct attacks *, u_int8_t);
void   dot1q_send_arp_poison(void *);
int8_t dot1q_send_arp(struct interface_data *, u_int16_t, u_int8_t *, u_int8_t *, u_int8_t *, u_int8_t *, u_int8_t *, u_int16_t, u_int8_t);
int8_t dot1q_learn_mac(struct attacks *, struct pcap_pkthdr *, u_int8_t *);
int8_t dot1q_return_mac(struct attacks *, u_int8_t *);
int8_t dot1q_init_attribs(struct term_node *);
int8_t dot1q_learn_packet(struct attacks *, char *, u_int8_t *,void *, struct pcap_pkthdr *);
char **dot1q_get_printable_packet(struct pcap_data *);
char **dot1q_get_printable_store(struct term_node *);
int8_t dot1q_load_values(struct pcap_data *, void *);
int8_t dot1q_update_data(int8_t, int8_t, int8_t, struct term_node *);
int8_t dot1q_update_field(int8_t, struct term_node *, void *);
int8_t dot1q_init_comms_struct(struct term_node *);
int8_t dot1q_end(struct term_node *);

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
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
