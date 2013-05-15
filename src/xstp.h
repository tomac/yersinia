/* xstp.h
 * Definitions for Spanning Tree Protocol
 *
 * $Id: xstp.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __XSTP_H__
#define __XSTP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define BPDU_CONF_STP  0x00
#define BPDU_CONF_RSTP 0x02
#define BPDU_TCN       0x80


/* STP stuff */
#define STP_VERSION  0x00

#define STP_TOPOLOGY_CHANGE     0x01
#define STP_TOPOLOGY_CHANGE_ACK 0x80


/* RSTP stuff */
#define RSTP_VERSION 0x02

#define RSTP_NOFLAGS           0
#define RSTP_TOPOLOGY_CHANGE   0x01
#define RSTP_PROPOSAL          0x02
#define RSTP_LEARNING          0x10
#define RSTP_FORWARDING        0x20
#define RSTP_AGREEMENT         0x40

#define RSTP_PORT_ROLE_MASK    0x0C
#define RSTP_PORT_ROLE_SHIFT   0x02

#define RSTP_PORT_ROLE_UNKNOWN    0
#define RSTP_PORT_ROLE_BACKUP     0x04
#define RSTP_PORT_ROLE_ROOT       0x08
#define RSTP_PORT_ROLE_DESIGNATED 0x0C

#define RSTP_TOPOLOGY_CHANGE_ACK 0x80


/* MSTP stuff */
#define MSTP_VERSION     0x03


struct xstp_mitm_args {
       struct attacks *attacks;
       struct stp_data *stp_data2;
};


static const struct tuple_type_desc xstp_version[] = {
    { STP_VERSION,  "STP" },
    { RSTP_VERSION, "RSTP" },
    { MSTP_VERSION, "MSTP" },
    { 0, NULL }
};

static const struct tuple_type_desc xstp_type[] = {
    { BPDU_CONF_STP,  "Conf STP" },
    { BPDU_CONF_RSTP, "Conf (M|R)STP" },
    { BPDU_TCN,       "TCN" },
    { 0,              NULL }
};

static const struct tuple_type_desc xstp_flags[] = {
    { 0,                       "NO FLAGS" },
    { STP_TOPOLOGY_CHANGE,     "TC" },
    { STP_TOPOLOGY_CHANGE_ACK, "TC ACK" },
    { RSTP_PROPOSAL,           "Proposal" },
    { RSTP_LEARNING,           "Learning" },
    { RSTP_FORWARDING,         "Forwarding" },
    { RSTP_AGREEMENT,          "Agreement" },
    { 0, NULL }
};

static struct proto_features xstp_features[] = {
    { F_LLC_DSAP, LIBNET_SAP_STP },
    { -1, 0 }
};

/* Default values */
#define XSTP_DFL_PROTOCOL_ID  0x0000
#define XSTP_DFL_VERSION      STP_VERSION
#define XSTP_DFL_BPDU_TYPE    BPDU_CONF_STP
#define XSTP_DFL_PORT_ID      0x8002
#define XSTP_DFL_MSG_AGE      0
#define XSTP_DFL_MAX_AGE      20
#define XSTP_DFL_HELLO_TIME   2
#define XSTP_DFL_FORW_DELAY   15
#define XSTP_DFL_PORT_ROLE    RSTP_PORT_ROLE_UNKNOWN
#define XSTP_DFL_PORT_STATE   (RSTP_FORWARDING | RSTP_AGREEMENT)


#define XSTP_SMAC       0
#define XSTP_DMAC       1
#define XSTP_ID         2
#define XSTP_VER        3
#define XSTP_TYPE       4
#define XSTP_FLAGS      5
#define XSTP_ROOTID     6
#define XSTP_PATHCOST   7
#define XSTP_BRIDGEID   8
#define XSTP_PORTID     9
#define XSTP_AGE        10
#define XSTP_MAX        11
#define XSTP_HELLO      12
#define XSTP_FWD        13

int8_t xstp_com_version(void *, void *, char *);
int8_t xstp_com_type(void *, void *, char *);
int8_t xstp_com_other(void *, void *, char *);

/* Struct needed for using protocol fields within the network client */
struct commands_param xstp_comm_params[] = {
    { XSTP_SMAC, "source",    "Source MAC", 6,  FIELD_MAC, "Set source MAC address", 
                       " H:H:H:H:H:H    48 bit mac address", 17,  1, 0, NULL, NULL },
    { XSTP_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                       " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { XSTP_ID, "id",         "Id", 2, FIELD_HEX, "Set id", 
                       " <00-FFFF>    id", 4, 2, 0, NULL, NULL },
    { XSTP_VER, "version",   "Ver", 1, FIELD_HEX, "Set spanning tree version", 
                       " <00-FF>    Spannig tree version", 2, 2, 0, xstp_com_version, xstp_version },
    { XSTP_TYPE, "type",      "Type", 1, FIELD_HEX, "Set bpdu type", 
                       " <00-FF>    bpdu type", 2, 2, 0, xstp_com_type, xstp_type },
    { XSTP_FLAGS, "flags",     "Flags", 1,FIELD_HEX, "Set bpdu flags", 
                       " <00-FF>    bpdu flags", 2, 2, 0, NULL, xstp_flags },
    { XSTP_ROOTID, "rootid",    "RootId", 8, FIELD_BRIDGEID, "Set root id", 
                       " HH.HHHHHH    Root id", 17, 2, 1, NULL, NULL },
    { XSTP_PATHCOST, "cost",      "Pathcost", 4, FIELD_HEX, "Set the spanning tree root path cost", 
                       " <00-FFFFFFFF>    root path cost", 8,  2, 0, NULL, NULL },
    { XSTP_BRIDGEID, "bridgeid",  "BridgeId", 8, FIELD_BRIDGEID, "Set bridge id", 
                       " HH.HHHHHH    Bridge id", 17,  3, 1, NULL, NULL },
    { XSTP_PORTID, "portid",    "Port", 2, FIELD_HEX, "Set port id", 
                       " <00-FFFF>    port id", 4, 3, 1, NULL, NULL },
    { XSTP_AGE, "message",   "Age", 2, FIELD_HEX, "Set message age", 
                       " <00-FFFF>    Estimated time in seconds since the root transmitted its config message", 4, 3, 0, xstp_com_other, NULL },
    { XSTP_MAX, "max-age",   "Max", 2, FIELD_HEX, "Set the max age interval for the spanning tree", 
                       " <00-FFFF>    maximum number of seconds the information in a BPDU is valid", 4, 3, 0, xstp_com_other, NULL },
    { XSTP_HELLO, "hello",     "Hello", 2,  FIELD_HEX, "Set the hello interval for the spanning tree", 
                       " <00-FFFF>    number of seconds between generation of config BPDUs", 4,  3, 0, xstp_com_other, NULL },
    { XSTP_FWD, "forward",   "Fwd", 2, FIELD_HEX, "Set the forward delay for the spanning tree", 
                       " <00-FFFF>    number of seconds for the forward delay timer", 4, 3, 0, xstp_com_other, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                       " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                       " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};


/* XSTP mode stuff */
struct stp_data { /* STP and Ethernet fields*/
                 u_int8_t  mac_source[ETHER_ADDR_LEN];
                 u_int8_t  mac_dest[ETHER_ADDR_LEN];
                 u_int16_t id;
                 u_int8_t  version;
                 u_int8_t  bpdu_type;
                 u_int8_t  flags;
                 u_int8_t  root_id[8];
                 u_int32_t root_pc;
                 u_int8_t  bridge_id[8];
                 u_int16_t port_id;
                 u_int16_t message_age;
                 u_int16_t max_age;
                 u_int16_t hello_time;
                 u_int16_t forward_delay;
                 u_int8_t  *rstp_data;
                 u_int8_t  rstp_len;
                 int8_t    do_ack;        /* Do TOP_CHANGE_ACK */
};


void   xstp_th_send_bpdu_conf(void *);
void   xstp_th_send_bpdu_conf_exit(struct attacks *);
int8_t xstp_send_all_bpdu_conf(struct attacks *);
int8_t xstp_send_bpdu_conf(u_int8_t, struct stp_data *, struct interface_data *);
void   xstp_th_send_bpdu_tcn(void *);
void   xstp_th_send_bpdu_tcn_exit(struct attacks *);
int8_t xstp_send_all_bpdu_tcn(struct attacks *);
int8_t xstp_send_bpdu_tcn(u_int8_t, struct stp_data *, struct interface_data *);
void   xstp_th_dos_conf(void *);
void   xstp_th_dos_conf_exit(struct attacks *);
void   xstp_th_dos_tcn(void *);
void   xstp_th_dos_tcn_exit(struct attacks *);
void   xstp_th_nondos_role(void *);
void   xstp_th_nondos_role_exit(struct attacks *);
void   xstp_th_nondos_other_role(void *);
void   xstp_th_nondos_other_role_exit(struct attacks *);
void   xstp_th_dos_mitm(void *);
void   xstp_th_dos_mitm_exit(struct attacks *);

/*void xstp_dos_elect(void);
void xstp_nondos_main_read_pcap(void);
void xstp_pcap_callback(struct pcap_pkthdr *, const u_char *, int);*/

#define XSTP_MITM_IFACE1 0
#define XSTP_MITM_IFACE2 1

static struct attack_param xstp_mitm_params[] = {
    { NULL, "Interface 1", 1, FIELD_IFACE, IFNAMSIZ, NULL },
    { NULL, "Interface 2", 1, FIELD_IFACE, IFNAMSIZ, NULL }
};

#define STP_ATTACK_SEND_CONF  0
#define STP_ATTACK_SEND_TCN   1
#define STP_ATTACK_DOS_CONF   2 
#define STP_ATTACK_DOS_TCN    3
#define STP_ATTACK_NONDOS_RR  4
#define STP_ATTACK_NONDOS_OR  5
#define STP_ATTACK_RR_MITM    6
/*#define STP_ATTACK_DOS_ELECT    6
#define STP_ATTACK_DOS_DISSAP   7
*/

static struct attack stp_attack[] = {
  { STP_ATTACK_SEND_CONF, "sending conf BPDU",   NONDOS,  SINGLE,    xstp_th_send_bpdu_conf, NULL, 0    },
  { STP_ATTACK_SEND_TCN,  "sending tcn BPDU",    NONDOS,  SINGLE,    xstp_th_send_bpdu_tcn, NULL, 0     },
  { STP_ATTACK_DOS_CONF,  "sending conf BPDUs",  DOS,     CONTINOUS, xstp_th_dos_conf, NULL, 0          },
  { STP_ATTACK_DOS_TCN,   "sending tcn BPDUs",   DOS,     CONTINOUS, xstp_th_dos_tcn, NULL, 0           }, 
  { STP_ATTACK_NONDOS_RR, "Claiming Root Role",  NONDOS,  CONTINOUS, xstp_th_nondos_role, NULL, 0       },
  { STP_ATTACK_NONDOS_OR, "Claiming Other Role", NONDOS,  CONTINOUS, xstp_th_nondos_other_role, NULL, 0 },
  { STP_ATTACK_RR_MITM,   "Claiming Root Role with MiTM", DOS, CONTINOUS, xstp_th_dos_mitm, xstp_mitm_params,
               SIZE_ARRAY(xstp_mitm_params)                    },
/*       { STP_ATTACK_DOS_ELECT,   "Causing Eternal Root Elections", NONDOS, xstp_th_nondos_role, NULL, 0 },
       { STP_ATTACK_DOS_DISSAP,  "Causing Root Dissappearance", NONDOS, xstp_th_nondos_role, NULL, 0 },*/
  { 0,                    NULL,                  0,       0,         NULL, NULL, 0                   }
};


void    xstp_register(void);
void    xstp_send_hellos(void *);
void    xstp_send_hellos_mitm(void *);
int8_t  xstp_learn_packet(struct attacks *, char *, u_int8_t *, void *, struct pcap_pkthdr *);
int8_t  xstp_decrement_bridgeid(struct stp_data *);
int8_t  xstp_increment_bridgeid(struct stp_data *); 
char    **xstp_get_printable_packet(struct pcap_data *);
char    **xstp_get_printable_store(struct term_node *);
int8_t  xstp_update_field(int8_t, struct term_node *, void *);
int8_t  xstp_init_attribs(struct term_node *);
int8_t  xstp_load_values(struct pcap_data *, void *);
int8_t  xstp_init_comms_struct(struct term_node *);
int8_t  xstp_end(struct term_node *);

extern void   thread_libnet_error( char *, libnet_t *);
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern void   attack_gen_mac(u_int8_t *);
extern struct interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
extern int8_t parser_command2index(register const struct attack *, register int8_t);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern int8_t parser_vrfy_bridge_id(char *, u_int8_t * );
extern void   parser_str_tolower( char *);

extern struct terminals *terms;
extern int8_t bin_data[];

#endif

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
