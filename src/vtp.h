/* vtp.h
 * Definitions for Cisco's VLAN Trunking Protocol
 *
 * $Id: vtp.h 46 2007-05-08 09:13:30Z slay $ 
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
 
#ifndef __VTP_H__
#define __VTP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define VTP_SUMM_ADVERT   0x01
#define VTP_SUBSET_ADVERT 0x02
#define VTP_REQUEST       0x03
#define VTP_JOIN          0x04

static const struct tuple_type_desc vtp_code[] = {
    { VTP_SUMM_ADVERT,   "SUMMARY" },
    { VTP_SUBSET_ADVERT, "SUBSET"  },
    { VTP_REQUEST,       "REQUEST" },
    { VTP_JOIN,          "JOIN"    },
    { 0, NULL }
};


#define VLAN_TYPE_ETHERNET 0x01
#define VLAN_TYPE_FDDI     0x02
#define VLAN_TYPE_TRCRF    0x03
#define VLAN_TYPE_FDDI_NET 0x04
#define VLAN_TYPE_TRBRF    0x05

static const struct tuple_type_desc vlan_type[] = {
    { VLAN_TYPE_ETHERNET, "Ethernet" },
    { VLAN_TYPE_FDDI,     "FDDI"     },
    { VLAN_TYPE_TRCRF,    "TRCRF"    },
    { VLAN_TYPE_FDDI_NET, "FDDI-NET" },
    { VLAN_TYPE_TRBRF,    "TRBRF"    },
    { 0, NULL }
};



/* Default values */
#define VTP_DFL_VERSION 0x01
#define VTP_DFL_DOMAIN  "\x0\x0\x0\x0\x0\x0\x0\x0"
#define VTP_DFL_DOM_LEN 0x08
#define VTP_DFL_CODE    VTP_REQUEST

#define VTP_TIMESTAMP_SIZE 12
#define VTP_DOMAIN_SIZE    32

#define VLAN_MAX       64
#define VLAN_NAME_SIZE 32
#define VLAN_ALIGNED_LEN(x)   (4*(((x)+3)/4) )

#define VTP_DOT10_BASE 0x100000

#define VTP_VLAN_ADD     0x00
#define VTP_VLAN_DEL     0x01
#define VTP_VLAN_DEL_ALL 0x02

static struct proto_features vtp_features[] = {
    { F_LLC_CISCO, 0x2003 },
    { -1, 0 }
};




struct vlan_info_print  {
     u_int8_t  type;
     u_int16_t id;
     u_int32_t dot10;
     u_int8_t  name[VLAN_NAME_SIZE+1];
};

struct vlan_info {
     u_int8_t  len;   
     u_int8_t  status;
     u_int8_t  type;  
     u_int8_t  name_len;
     u_int16_t id;     
     u_int16_t mtu;    
     u_int32_t dot10;   
};

struct vtp_summary {
     u_int8_t  version;         
     u_int8_t  code;            
     u_int8_t  followers;       
     u_int8_t  dom_len;         
     u_int8_t  domain[VTP_DOMAIN_SIZE]; 
     u_int32_t revision;                    
     u_int32_t updater;                     
     u_int8_t  timestamp[VTP_TIMESTAMP_SIZE];    
     u_int8_t  md5[16];
};

struct vtp_subset {
     u_int8_t  version;     
     u_int8_t  code;        
     u_int8_t  seq;    
     u_int8_t  dom_len;
     u_int8_t  domain[VTP_DOMAIN_SIZE];
     u_int32_t revision;       
};

struct vtp_request {
     u_int8_t  version; 
     u_int8_t  code;    
     u_int8_t  reserved;
     u_int8_t  dom_len;
     u_int8_t  domain[VTP_DOMAIN_SIZE];
     u_int16_t start_val;   
};

struct vtp_join {
     u_int8_t  version;             
     u_int8_t  code;                
     u_int8_t  maybe_reserved;
     u_int8_t  dom_len;        
     u_int8_t  domain[VTP_DOMAIN_SIZE]; 
     u_int32_t vlan;          
     u_int8_t  unknown[126];
};


/* VTP mode stuff */
struct vtp_data { 
     u_int8_t  mac_source[ETHER_ADDR_LEN];
     u_int8_t  mac_dest[ETHER_ADDR_LEN];
     u_int8_t  version;
     u_int8_t  code;
     u_int8_t  followers;
     u_int8_t  seq;
     char      domain[VTP_DOMAIN_SIZE+1];
     u_int8_t  dom_len;
     u_int16_t start_val;
     u_int32_t revision;
     u_int32_t updater;
     u_int8_t  timestamp[VTP_TIMESTAMP_SIZE+1];
     u_int8_t  md5[16];
     u_int16_t vlans_len;
     u_int8_t  *vlan_info;
     u_int8_t  options[MAX_TLV*MAX_VALUE_LENGTH];
     u_int16_t options_len;
};


#define VTP_SMAC        0
#define VTP_DMAC        1
#define VTP_VERSION     2 
#define VTP_CODE        3
#define VTP_DOMAIN      4
#define VTP_MD5         5
#define VTP_UPDATER     6
#define VTP_REVISION    7
#define VTP_TIMESTAMP   8
#define VTP_STARTVAL    9
#define VTP_FOLLOWERS  10
#define VTP_SEQ        11
#define VTP_VLAN       14

/* Struct needed for using protocol fields within the network client */
struct commands_param vtp_comm_params[] = {
    { VTP_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { VTP_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { VTP_VERSION, "version",   "Version", 1, FIELD_HEX, "Set vtp version", 
                                        " <00-FF>    virtual trunking version", 2, 2, 0, NULL, NULL },
    { VTP_CODE, "code",      "Code", 1, FIELD_HEX, "Set vtp code", 
                                        " <00-FF>    virtual trunking code", 2, 2, 1, NULL, vtp_code },
    { VTP_DOMAIN, "domain",    "Domain", VTP_DOMAIN_SIZE, FIELD_STR, "Set vtp domain name to use", 
                                        " WORD    Domain name", VTP_DOMAIN_SIZE, 2, 1, NULL, NULL },
    { VTP_MD5, "md5",       "MD5", 16, FIELD_BYTES, "Set vtp md5 hash", 
                                        " HHHHH...    MD5 hash", 32, 3, 1, NULL, NULL },
    { VTP_UPDATER, "updater",   "Updater", 4, FIELD_IP, "Set updater IP address", 
                                        " A.A.A.A    IPv4 address", 15, 3, 0, NULL, NULL },                
    { VTP_REVISION, "revision",  "Revision", 4, FIELD_DEC, "Set vtp revision number", 
                                        " <0-1999999999>    Revision number", 10, 4, 0, NULL, NULL },
    { VTP_TIMESTAMP, "timestamp", "Timestamp", VTP_TIMESTAMP_SIZE, FIELD_STR, "Set vtp timestamp", 
                                        " WORD    Timestamp text", VTP_TIMESTAMP_SIZE, 4, 0, NULL, NULL },
    { VTP_STARTVAL, "startval",  "Start value", 2, FIELD_DEC, "Set vtp start value", 
                                        " <0-65535>    Start value", 5, 4, 0, NULL, NULL },
    { VTP_FOLLOWERS, "followers", "Followers", 1,  FIELD_DEC, "Set vtp followers", 
                                        " <0-255>    Followers number", 3, 5, 0, NULL, NULL },
    { VTP_SEQ, "sequence",  "Sequence", 1, FIELD_DEC, "Set vtp sequence number", 
                                        " <0-255>    Sequence number", 3, 5, 0, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL },
    { VTP_VLAN, "vlan",     "VLAN", 0, FIELD_EXTRA, "", "", 0, 0, 0, NULL, NULL}
};


void vtp_th_send(void *);
void vtp_th_send_exit(struct attacks *);
void vtp_th_dos_del_all(void *);
void vtp_th_dos_del_all_exit(struct attacks *);
void vtp_th_dos_del(void *);
void vtp_th_dos_del_exit(struct attacks *);
void vtp_th_dos_add(void *);
void vtp_th_dos_add_exit(struct attacks *);
void vtp_th_dos_crash(void *);
void vtp_th_dos_crash_exit(struct attacks *);

#define VTP_PARAM_VLAN_ID    0
#define VTP_PARAM_VLAN_NAME  1

static struct attack_param vtp_vlan_add_param[] = {
    { NULL, "VLAN ID",   2,              FIELD_DEC, 4,              NULL },
    { NULL, "VLAN Name", VLAN_NAME_SIZE, FIELD_STR, VLAN_NAME_SIZE, NULL }
};

static struct attack_param vtp_vlan_del_param[] = {
    { NULL, "VLAN ID",   2, FIELD_DEC,  4, NULL }
};

#define VTP_ATTACK_SEND    0
#define VTP_ATTACK_DEL_ALL 1
#define VTP_ATTACK_DEL     2
#define VTP_ATTACK_ADD     3
#define VTP_ATTACK_CRASH   4


static struct attack vtp_attack[] = {
  { VTP_ATTACK_SEND,   "sending VTP packet",     NONDOS, SINGLE, vtp_th_send,        NULL,    0 },
  { VTP_ATTACK_DEL_ALL,"deleting all VTP vlans", DOS,    SINGLE, vtp_th_dos_del_all, NULL,    0 },
  { VTP_ATTACK_DEL,    "deleting one vlan",      DOS,    SINGLE, vtp_th_dos_del,     vtp_vlan_del_param,
                    SIZE_ARRAY(vtp_vlan_del_param) },
  { VTP_ATTACK_ADD,    "adding one vlan",        NONDOS, SINGLE, vtp_th_dos_add,     vtp_vlan_add_param,
                    SIZE_ARRAY(vtp_vlan_add_param) },
  { VTP_ATTACK_CRASH, "Catalyst zero day",       DOS,    SINGLE, vtp_th_dos_crash,   NULL,    0 },
  { 0,                  NULL,                    0,      0,      NULL,           NULL,    0 }
};



void    vtp_register(void);
int8_t  vtp_send(struct attacks *);
int8_t  vtp_init_attribs(struct term_node *);
int8_t  vtp_learn_packet(struct attacks *attacks, char *, u_int8_t *, void *, struct pcap_pkthdr *);
char    **vtp_get_printable_packet(struct pcap_data *);
char    **vtp_get_printable_store(struct term_node *);
int8_t  vtp_load_values(struct pcap_data *, void *);
int8_t  vtp_update_field(int8_t, struct term_node *, void *);
int8_t  vtp_generate_md5(char *, u_int32_t, u_int32_t, char *, u_int8_t, u_int8_t *, u_int16_t, u_int8_t *, u_int8_t);
int8_t  vtp_del_vlan(u_int16_t, u_int8_t *, u_int16_t *);
void    vtp_modify_vlan(u_int8_t, struct attacks *);
int8_t  vtp_add_vlan(u_int16_t, char *, u_int8_t **, u_int16_t *);
int8_t  vtp_init_comms_struct(struct term_node *);
int8_t  vtp_end(struct term_node *);

extern void   thread_libnet_error( char *, libnet_t *);
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern void   attack_gen_mac(u_int8_t *);
extern struct interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern int8_t parser_get_inet_aton(char *, struct in_addr *);
extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
extern void   md5_sum(const u_char *, size_t, u_char *);

extern int8_t parser_command2index(register const struct attack *, register int8_t);
extern struct terminals *terms;

extern int8_t bin_data[];

#endif

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
