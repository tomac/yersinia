/* hsrp.h
 * Definitions for Cisco Hot Standby Router Protocol
 *
 * $Id: hsrp.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __HSRP_H__
#define __HSRP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define HSRP_PACKET_SIZE 20

/* Version */
#define HSRP_VERSION 0x0

/* Opcode */
#define HSRP_TYPE_HELLO 0x0
#define HSRP_TYPE_COUP 0x1
#define HSRP_TYPE_RESIGN 0x2

/* State */
#define HSRP_STATE_INITIAL 0x0
#define HSRP_STATE_LEARN   0x1
#define HSRP_STATE_LISTEN  0x2
#define HSRP_STATE_SPEAK   0x4
#define HSRP_STATE_STANDBY 0x8
#define HSRP_STATE_ACTIVE  0x10

#define HSRP_AUTHDATA_LENGTH  8

/*
 *  HSRP header
 *  Static header size: 20 bytes
 */
struct hsrp_data
{
    u_int8_t version;           /* Version of the HSRP messages */
    u_int8_t opcode;            /* Type of message */
    u_int8_t state;            /* Current state of the router */
    u_int8_t hello_time;       /* Period in seconds between hello messages */
    u_int8_t hold_time;        /* Seconds that the current hello message is valid */
    u_int8_t priority;         /* Priority for the election proccess */
    u_int8_t group;            /* Standby group */
    u_int8_t reserved;         /* Reserved field */
    char authdata[HSRP_AUTHDATA_LENGTH]; /* Password */
    u_int32_t virtual_ip;      /* Virtual IP address */
    /* UDP Data */
    u_int16_t sport;
    u_int16_t dport;
    /* IP Data */
    u_int32_t sip;
    u_int32_t dip;
    /* Ethernet Data */
    u_int8_t mac_source[ETHER_ADDR_LEN];
    u_int8_t mac_dest[ETHER_ADDR_LEN];
};


/* Default values */
#define HSRP_DFL_VERSION    HSRP_VERSION
#define HSRP_DFL_TYPE       HSRP_TYPE_HELLO
#define HSRP_DFL_STATE      HSRP_STATE_INITIAL
#define HSRP_DFL_HELLO_TIME 3
#define HSRP_DFL_HOLD_TIME  10
#define HSRP_DFL_PRIORITY   0xFF
#define HSRP_DFL_GROUP      0x00
#define HSRP_DFL_RESERVED   0x00
#define HSRP_DFL_AUTHDATA   "cisco"
#define HSRP_DFL_PORT       1985

static const struct tuple_type_desc hsrp_opcode[] = {
    { HSRP_TYPE_HELLO, "HELLO" },
    { HSRP_TYPE_COUP, "COUP" },
    { HSRP_TYPE_RESIGN, "RESIGN" },
    { 0, NULL }
};

static const struct tuple_type_desc hsrp_state[] = {
    { HSRP_STATE_INITIAL, "INITIAL" },
    { HSRP_STATE_LEARN, "LEARN" },
    { HSRP_STATE_LISTEN, "LISTEN" },
    { HSRP_STATE_SPEAK, "SPEAK" },
    { HSRP_STATE_STANDBY, "STANDBY" },
    { HSRP_STATE_ACTIVE, "ACTIVE" },
    { 0, NULL }
};

static struct proto_features hsrp_features[] = {
    { F_UDP_PORT, HSRP_DFL_PORT },
    { -1, 0 }
};


#define HSRP_SMAC        0
#define HSRP_DMAC        1
#define HSRP_SIP         2
#define HSRP_DIP         3
#define HSRP_SPORT       4
#define HSRP_DPORT       5
#define HSRP_VER         6
#define HSRP_OPCODE      7
#define HSRP_STATE       8
#define HSRP_HELLO_TIME  9
#define HSRP_HOLD_TIME   10
#define HSRP_PRIORITY    11
#define HSRP_GROUP       12
#define HSRP_RESERVED    13
#define HSRP_AUTHDATA    14
#define HSRP_VIRTUALIP   15


/* Struct needed for using protocol fields within the network client */
struct commands_param hsrp_comm_params[] = {
   { HSRP_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
      " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
   { HSRP_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
      " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
   { HSRP_SIP, "ipsource",  "SIP", 4, FIELD_IP, "Set source IP address", 
      " A.A.A.A    IPv4 address", 15, 2, 1, NULL, NULL },                
   { HSRP_DIP, "ipdest",    "DIP", 4, FIELD_IP, "Set destination IP address", 
      " A.A.A.A    IPv4 address", 15, 2, 1, NULL, NULL },                
   { HSRP_SPORT, "sport",     "SPort", 2, FIELD_DEC, "Set UDP source port", 
      " <0-65535>    UDP source port", 5, 2, 0, NULL, NULL },
   { HSRP_DPORT, "dport",     "DPort", 2, FIELD_DEC, "Set UDP destination port", 
      " <0-65535>    UDP destination port", 5, 2, 0, NULL, NULL },
   { HSRP_VER, "version",   "Version", 1, FIELD_HEX, "Set hsrp version", 
      " <00-FF>    hot standby router version", 2, 3, 0, NULL, NULL },
   { HSRP_OPCODE, "opcode",    "Opcode", 1, FIELD_HEX, "Set hsrp operation code", 
      " <00-FF>    hot standby router operation code", 2, 3, 0, NULL, hsrp_opcode },
   { HSRP_STATE, "state",     "State", 1,  FIELD_HEX, "Set hsrp state", 
      " <00-FF>    hot standby router state", 2, 3, 0, NULL, hsrp_state },
   { HSRP_HELLO_TIME, "hello",     "Hello", 1, FIELD_HEX, "Set hsrp hello time", 
      " <00-FF>    HSRP group", 2, 3, 0, NULL, NULL },
   { HSRP_HOLD_TIME, "hold",      "Hold", 1, FIELD_HEX, "Set hsrp hold time", 
      " <00-FF>    HSRP group", 2, 3, 0, NULL, NULL },
   { HSRP_PRIORITY, "priority",  "Priority", 1, FIELD_HEX, "Set hsrp priority version", 
      " <00-FF>    hot standby router priority", 2, 3, 0, NULL, NULL },
   { HSRP_GROUP, "group",     "Group", 1, FIELD_DEC, "Set hsrp group", 
      " <0-255>    HSRP group", 3, 4, 0, NULL, NULL },
   { HSRP_RESERVED, "reserved",  "Reserved", 1, FIELD_HEX, "Set hsrp reserved", 
      " <00-FF>    hot standby router reserved", 2, 4, 0, NULL, NULL },
   { HSRP_AUTHDATA, "password",  "Auth", HSRP_AUTHDATA_LENGTH, FIELD_STR, "Set hsrp auth password", 
      " WORD         Auth password", HSRP_AUTHDATA_LENGTH, 4, 1, NULL, NULL },
   { HSRP_VIRTUALIP, "ipvirtual", "VIP", 4, FIELD_IP, "Set virtual IP address", 
      " A.A.A.A    IPv4 address", 15, 4, 1, NULL, NULL },                
   { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
      " <cr>", 0, 0, 0, NULL, NULL }, 
   { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
      " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};



/* true size + 1 extra element for '\0' */
struct hsrp_printable { /* HSRP and Ethernet fields*/
    u_int8_t version[3];
    u_int8_t opcode[3];
    u_int8_t state[3];
    u_int8_t hello_time[3];
    u_int8_t hold_time[3];
    u_int8_t priority[3];
    u_int8_t group[3];
    u_int8_t reserved[3];
    u_int8_t authdata[9];
    u_int8_t virtual_ip[16];
    /* UDP Data */
    u_int8_t sport[6];
    u_int8_t dport[6];
    /* IP Data */
    u_int8_t sip[16];
    u_int8_t dip[16];
    /* Ethernet Data */
    u_int8_t smac[18];
    u_int8_t dmac[18];
};

/* Attacks */
#define HSRP_ATTACK_SEND_RAW      0
#define HSRP_ATTACK_BECOME_ACTIVE 1
#define HSRP_ATTACK_MITM_BECOME_ACTIVE 2

#define HSRP_SOURCE_IP   0
static struct attack_param hsrp_active_params[] = {
  { NULL, "Source IP",  4, FIELD_IP, 15, NULL },
};

void hsrp_th_send_raw(void *);
void hsrp_th_send_raw_exit(struct attacks *);
void hsrp_th_become_active(void *);
void hsrp_th_become_active_exit(struct attacks *);

static struct attack hsrp_attack[] = {
  { HSRP_ATTACK_SEND_RAW,     "sending raw HSRP packet", NONDOS, SINGLE,    hsrp_th_send_raw, NULL, 0   },
  { HSRP_ATTACK_BECOME_ACTIVE, "becoming ACTIVE router", NONDOS, CONTINOUS, hsrp_th_become_active, hsrp_active_params, 
  SIZE_ARRAY(hsrp_active_params)    },
  { HSRP_ATTACK_MITM_BECOME_ACTIVE, "becoming ACTIVE router (MITM)", NONDOS, CONTINOUS, hsrp_th_become_active, NULL, 0   },
  { 0,                   NULL,                 0,      0,     NULL, NULL, 0                   }
};

void   hsrp_register(void);
void   hsrp_send_hellos(void *);
int8_t hsrp_send_packet(struct attacks *);
char   **hsrp_get_printable_packet(struct pcap_data *);
char   **hsrp_get_printable_store(struct term_node *);
int8_t hsrp_learn_packet(struct attacks *, char *, u_int8_t *, void *, struct pcap_pkthdr *, struct pcap_data *);
int8_t hsrp_load_values(struct pcap_data *, void *);
int8_t hsrp_init_attribs(struct term_node *);
int8_t hsrp_update_field(int8_t, struct term_node *, void *);
int8_t hsrp_init_comms_struct(struct term_node *);
int8_t hsrp_end(struct term_node *);

extern void   thread_libnet_error(char *, libnet_t *);
extern int8_t parser_vrfy_bridge_id(char *, u_int8_t * );
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern void   attack_gen_mac(u_int8_t *);
extern struct interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
extern int8_t parser_get_inet_aton(char *, struct in_addr *);
extern int8_t parser_command2index(register const struct attack *, register int8_t);

extern struct terminals *terms;
extern int8_t bin_data[];

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
