/* mpls.h
 * Definitions for MultiProtocol Label Switching
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

#ifndef __MPLS_H
#define __MPLS_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

static struct proto_features mpls_features[] = {
     { F_ETHERTYPE, ETHERTYPE_MPLS },
     { -1, 0 }
};

struct mpls_header {
    u_int8_t byte0;
    u_int8_t byte1;
    u_int8_t byte2;
    u_int8_t byte3;
};
 
#define MPLS_GET_LABEL(x)  ( ( ( ( (struct mpls_header *)(x))->byte0 ) <<  0x0C ) + \
                             ( ( ( (struct mpls_header *)(x))->byte1 ) <<  0x04 ) + \
                             ( ( ( ((struct mpls_header *)(x))->byte2 ) >> 0x04 ) & 0xFF) )
#define MPLS_GET_EXP(x)    ( ( ( ( (struct mpls_header *)(x))->byte2 ) >> 0x01 ) & 0x07 )
#define MPLS_GET_BOTTOM(x) ( ( ( ( (struct mpls_header *)(x))->byte2 ) &  0x01 ) )
#define MPLS_GET_TTL(x)    ( ( ( ( (struct mpls_header *)(x))->byte3 ) ) )
                                                                        

#define MAX_IP_PAYLOAD 16
 
#define MPLS_DFL_MAC_DST  "FF:FF:FF:FF:FF:FF"
#define MPLS_DFL_SRC_IP   "10.0.0.1"
#define MPLS_DFL_SRC_PORT 666
#define MPLS_DFL_DST_IP   "10.0.0.2"
#define MPLS_DFL_DST_PORT 1998
#define MPLS_DFL_PAYLOAD  "YERSINIA"
#define MPLS_DFL_PAY_LEN  8

struct mpls_data { 
     u_int8_t  mac_source[ETHER_ADDR_LEN];
     u_int8_t  mac_dest[ETHER_ADDR_LEN];
     u_int8_t  proto;
     u_int8_t  double_hdr;
     u_int32_t label1;
     u_int8_t  exp1;
     u_int8_t  bottom1;
     u_int8_t  ttl1;
     u_int32_t label2;
     u_int8_t  exp2;
     u_int8_t  bottom2;
     u_int8_t  ttl2;
     u_int32_t src_ip;
     u_int16_t src_port;
     u_int32_t dst_ip;
     u_int16_t dst_port;
     u_int8_t  ip_payload[MAX_IP_PAYLOAD+1];
     u_int8_t  ip_pay_len;
};


#define MPLS_SMAC      0
#define MPLS_DMAC      1
#define MPLS_LABEL1    2
#define MPLS_EXP1      3
#define MPLS_BOTTOM1   4
#define MPLS_TTL1      5
#define MPLS_LABEL2    6
#define MPLS_EXP2      7
#define MPLS_BOTTOM2   8
#define MPLS_TTL2      9
#define MPLS_SRC_IP    10
#define MPLS_SRC_PORT  11
#define MPLS_DST_IP    12
#define MPLS_DST_PORT  13
#define MPLS_PAYLOAD   14


struct commands_param mpls_comm_params[] = {
    { MPLS_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { MPLS_DMAC, "dest",    "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
                                        
    { MPLS_LABEL1, "label1","Label1", 4, FIELD_DEC, "Set MPLS label", 
                                        " <0-65535>    Label", 8, 2, 1, NULL, NULL },
    { MPLS_EXP1,   "exp1","Exp1", 1,  FIELD_DEC, "Set MPLS Experimental bits", 
                                        " <0-255>      Experimental bits", 3, 2, 0, NULL, NULL },
    { MPLS_BOTTOM1, "bottom1","Bottom1", 1, FIELD_DEC, "Set MPLS bottom stack flag", 
                                        " <0-1>        Bottom stack flag", 1, 2, 0, NULL, NULL },
    { MPLS_TTL1, "ttl1","TTL1", 1, FIELD_DEC, "Set MPLS Time To Live", 
                                        " <0-255>      Time To Live units", 3, 2, 0, NULL, NULL },

    { MPLS_LABEL2, "label2","Label2", 4,  FIELD_DEC, "Set MPLS label (second)", 
                                        " <0-65535>    Label", 8, 3, 1, NULL, NULL },
    { MPLS_EXP2, "exp2","Exp2", 1, FIELD_DEC, "Set MPLS Experimental bits (second)", 
                                        " <0-255>      Experimental bits", 3, 3, 0, NULL, NULL },
    { MPLS_BOTTOM2, "bottom2","Bottom2", 1, FIELD_DEC, "Set MPLS bottom stack flag (second)", 
                                        " <0-1>        Bottom stack flag", 1, 3, 0, NULL, NULL },
    { MPLS_TTL2, "ttl2","TTL2", 1, FIELD_DEC, "Set MPLS Time To Live (second)", 
                                        " <0-255>      Time To Live units", 3, 3, 0, NULL, NULL },
                                        
    { MPLS_SRC_IP, "ipsource",    "SrcIP", 4, FIELD_IP, "Set MPLS IP source data address", 
                                        " A.A.A.A    IPv4 address", 15, 4, 1, NULL, NULL },
    { MPLS_SRC_PORT, "portsource","SrcPort", 2, FIELD_DEC, "Set TCP/UDP source port", 
                                        " <0-65535>    TCP/UDP source port", 5, 4, 0, NULL, NULL },
    { MPLS_DST_IP,  "ipdest",     "DstIP", 4, FIELD_IP, "Set MPLS IP destination data address", 
                                        " A.A.A.A    IPv4 address", 15, 4, 1, NULL, NULL },                
    { MPLS_DST_PORT, "portdest",  "DstPort", 2, FIELD_DEC, "Set TCP/UDP destination port", 
                                        " <0-65535>    TCP/UDP destination port", 5, 4, 0, NULL, NULL },
    { MPLS_PAYLOAD, "payload",   "Payload", MAX_IP_PAYLOAD, FIELD_STR, "Set MPLS IP payload", 
                                        " WORD         ASCII payload", MAX_IP_PAYLOAD, 5, 0, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};

#define MPLS_ATTACK_SEND_TCP         0
#define MPLS_ATTACK_SEND_DOUBLE_TCP  1
#define MPLS_ATTACK_SEND_UDP         2
#define MPLS_ATTACK_SEND_DOUBLE_UDP  3
#define MPLS_ATTACK_SEND_ICMP        4
#define MPLS_ATTACK_SEND_DOUBLE_ICMP 5

void mpls_th_send_tcp(void *);
void mpls_th_send_double_tcp(void *);
void mpls_th_send_udp(void *);
void mpls_th_send_double_udp(void *);
void mpls_th_send_icmp(void *);
void mpls_th_send_double_icmp(void *);
void mpls_send(struct attacks *);
void mpls_th_send_exit(struct attacks *);

static struct attack mpls_attack[] = {
    { MPLS_ATTACK_SEND_TCP,        "sending TCP MPLS packet", NONDOS, SINGLE,             mpls_th_send_tcp, NULL, 0 },
    { MPLS_ATTACK_SEND_DOUBLE_TCP, "sending TCP MPLS with double header", NONDOS, SINGLE, mpls_th_send_double_tcp, NULL, 0 },
    { MPLS_ATTACK_SEND_UDP,        "sending UDP MPLS packet", NONDOS, SINGLE,             mpls_th_send_udp, NULL, 0 },
    { MPLS_ATTACK_SEND_DOUBLE_UDP, "sending UDP MPLS with double header", NONDOS, SINGLE, mpls_th_send_double_udp, NULL, 0 },
    { MPLS_ATTACK_SEND_ICMP,        "sending ICMP MPLS packet", NONDOS, SINGLE,             mpls_th_send_icmp, NULL, 0 },
    { MPLS_ATTACK_SEND_DOUBLE_ICMP, "sending ICMP MPLS with double header", NONDOS, SINGLE, mpls_th_send_double_icmp, NULL, 0 },
    { 0,                    NULL,                      0,      0,      NULL,             NULL, 0 }
};



void mpls_register(void);
int8_t mpls_init_attribs(struct term_node *);
int8_t mpls_init_comms_struct(struct term_node *);
int8_t mpls_end(struct term_node *);
int8_t mpls_update_field(int8_t state, struct term_node *node, void *value);
char **mpls_get_printable_store(struct term_node *node);
int8_t mpls_load_values(struct pcap_data *data, void *values);
int8_t mpls_learn_packet(struct attacks *attacks, char *iface, u_int8_t *stop, void *data, struct pcap_pkthdr *header);
char **mpls_get_printable_packet(struct pcap_data *data);


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
extern int8_t parser_get_formated_inet_address_fill(u_int32_t in, char *inet, u_int16_t inet_len, int8_t fill_up);

extern int8_t parser_command2index(register const struct attack *, register int8_t);



#endif

