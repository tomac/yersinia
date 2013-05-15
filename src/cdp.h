/* cdp.h
 * Definitions for Cisco Discovery Protocol
 * $Id: cdp.h 46 2007-05-08 09:13:30Z slay $ 
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
 
#ifndef __CDP_H__
#define __CDP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define CDP_VERSION                  0x01

#define CDP_TYPE_DEVID               0x0001
#define CDP_TYPE_ADDRESS             0x0002
#define CDP_TYPE_PORTID              0x0003
#define CDP_TYPE_CAPABILITY          0x0004
#define CDP_TYPE_VERSION             0x0005
#define CDP_TYPE_PLATFORM            0x0006
#define CDP_TYPE_IPPREFIX            0x0007
#define CDP_TYPE_PROTOCOL_HELLO      0x0008
#define CDP_TYPE_VTP_MGMT_DOMAIN     0x0009
#define CDP_TYPE_NATIVE_VLAN         0x000A
#define CDP_TYPE_DUPLEX              0x000B
#define CDP_TYPE_VOIP_VLAN_REPLY     0x000E
#define CDP_TYPE_VOIP_VLAN_QUERY     0x000F
#define CDP_TYPE_MTU                 0x0011
#define CDP_TYPE_TRUST_BITMAP        0x0012
#define CDP_TYPE_UNTRUSTED_COS       0x0013
#define CDP_TYPE_SYSTEM_NAME         0x0014
#define CDP_TYPE_SYSTEM_OID          0x0015
#define CDP_TYPE_MANAGEMENT_ADDR     0x0016
#define CDP_TYPE_LOCATION            0x0017

#define CDP_CAP_LEVEL3_ROUTING       0x01
#define CDP_CAP_LEVEL2_TRANS_BRIDGE  0x02
#define CDP_CAP_LEVEL2_SROUTE_BRIDGE 0x04
#define CDP_CAP_LEVEL2_SWITCH        0x08 /*without STP */
#define CDP_CAP_LEVEL3_ENABLE        0x10
#define CDP_CAP_NON_FORW_IGMP        0x20
#define CDP_CAP_LEVEL1               0x40

#define CDP_TLV_TYPE                 0

#define CDP_SMAC                     0
#define CDP_DMAC                     1
#define CDP_VER                      2
#define CDP_TTL                      3
#define CDP_CHECKSUM                 4 
#define CDP_TLV                      5


/* Default values */
#define CDP_DFL_VERSION  CDP_VERSION
#define CDP_DFL_TTL      3*60

/* CDP mode stuff */

struct cdp_data { /* CDP and Ethernet fields*/
                 u_int8_t  mac_source[ETHER_ADDR_LEN];
                 u_int8_t  mac_dest[ETHER_ADDR_LEN];
                 u_int8_t  version;
                 u_int8_t  ttl;
                 u_int16_t checksum;
/*                 u_int8_t  tlv_devid[MAX_VALUE_LENGTH+1];
                 u_int8_t  tlv_portid[MAX_VALUE_LENGTH+1];
                 u_int8_t  tlv_platform[MAX_VALUE_LENGTH+1];
                 u_int8_t  tlv_version[MAX_VALUE_LENGTH+1];
                 u_int32_t tlv_address;*/
                 u_int8_t  options[MAX_TLV*MAX_VALUE_LENGTH];
                 u_int16_t options_len;
                 void *extra;
};


static const struct tuple_type_desc cdp_type_desc[] = {
        { CDP_TYPE_DEVID,           "DevID" },
        { CDP_TYPE_ADDRESS,         "Addresses" },
        { CDP_TYPE_PORTID,          "Port ID" },
        { CDP_TYPE_CAPABILITY,      "Capabilities" },
        { CDP_TYPE_VERSION,         "Software version" },
        { CDP_TYPE_PLATFORM,        "Platform" },
        { CDP_TYPE_IPPREFIX,        "IP Prefix/Gateway" },
        { CDP_TYPE_PROTOCOL_HELLO,  "Protocol Hello" },
        { CDP_TYPE_VTP_MGMT_DOMAIN, "VTP Domain" },
        { CDP_TYPE_NATIVE_VLAN,     "Native VLAN" },
        { CDP_TYPE_DUPLEX,          "Duplex" },
        { CDP_TYPE_VOIP_VLAN_REPLY, "VoIP VLAN Reply" },
        { CDP_TYPE_VOIP_VLAN_QUERY, "VoIP VLAN Query" },
        { CDP_TYPE_MTU,             "MTU"},
        { CDP_TYPE_TRUST_BITMAP,    "Trust Bitmap" },
        { CDP_TYPE_UNTRUSTED_COS,   "Untrusted CoS" },
        { CDP_TYPE_SYSTEM_NAME,     "System Name" },
        { CDP_TYPE_SYSTEM_OID,      "System ObjectID" },
        { CDP_TYPE_MANAGEMENT_ADDR, "Management Addr" },
        { CDP_TYPE_LOCATION,        "Location" },
        { 0,                        NULL },
};

static struct attack_param cdp_tlv[] = {
    { NULL, "DevID",                   15,  FIELD_STR, 15, NULL },
    { NULL, "Addresses",               4,  FIELD_IP,  15, NULL },
    { NULL, "Port ID",                 15,  FIELD_STR, 15, NULL },
    { NULL, "Capabilities",            4,  FIELD_HEX,  8, NULL },
    { NULL, "Software version",        15, FIELD_STR, 15, NULL },
    { NULL, "Platform",                15, FIELD_STR, 15, NULL }
};


static struct proto_features cdp_features[] = {
    { F_LLC_CISCO, 0x2000 },
    { -1, 0 }
};

static const struct tuple_type_desc cdp_tlv_desc[] = {
    { 0,              NULL }
};


int8_t cdp_tlv_devid(void *, void *, char *);
int8_t cdp_tlv_platform(void *, void *, char *);
int8_t cdp_tlv_address(void *, void *, char *);
int8_t cdp_tlv_portid(void *, void *, char *);
int8_t cdp_tlv_version(void *, void *, char *);

/* Struct needed for using protocol fields within the network client */
struct commands_param cdp_comm_params[] = {
    { CDP_SMAC, "source",    "Source MAC", 6,  FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { CDP_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17,  1, 0, NULL, NULL },
    { CDP_VER, "version",   "Version", 1, FIELD_HEX, "Set cdp version", 
                                        " <0x00-0xFF>    cdp version", 2, 2, 0, NULL, NULL },
    { CDP_TTL, "ttl",       "TTL", 1, FIELD_HEX, "Set cdp ttl", 
                                        " <0x00-0xFF>    cdp Time To Live", 2, 2, 1, NULL, NULL },
    { CDP_CHECKSUM, "checksum",  "Checksum", 2, FIELD_HEX, "Set cdp checksum", 
                                        " <0x00-0xFFFF>    Packet checksum", 4,  2, 0, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL },
    { CDP_TLV, "tlv",       "TLV", 0, FIELD_EXTRA, "", "", 0, 0, 0, NULL, NULL}
};

struct commands_param_extra cdp_params_tlv[] = {
   { CDP_TYPE_DEVID,           "devid", "DevID",            MAX_STRING_SIZE, FIELD_STR, "Set Device ID", " WORD Device ID", MAX_STRING_SIZE, 1, NULL },
   { CDP_TYPE_ADDRESS,         "address", "Addresses",        4, FIELD_IP, "Set IP Address", " A.A.A.A   IPv4 address", 15, 0, NULL },
   { CDP_TYPE_PORTID,          "portid", "Port ID",          MAX_STRING_SIZE, FIELD_STR, "Set Port ID", " WORD Port ID", MAX_STRING_SIZE, 0, NULL },
   { CDP_TYPE_CAPABILITY,      "capab", "Capabilities",     4, FIELD_HEX, "Set Capabilities", " <0x00-0xFFFFFFFF>   Capabilities", 8, 0, NULL },
   { CDP_TYPE_VERSION,         "swversion", "Software version", MAX_STRING_SIZE, FIELD_STR, "Set SW Version", " WORD SW Version", MAX_STRING_SIZE, 0, NULL },
   { CDP_TYPE_PLATFORM,        "platform", "Platform",         MAX_STRING_SIZE, FIELD_STR, "Set Platform", " WORD Platform", MAX_STRING_SIZE, 0, NULL },
   { CDP_TYPE_IPPREFIX,        "gateway", "IP Prefix/Gateway", 4, FIELD_IP, "Set Gateway", " A.A.A.A   IPv4 address", 15, 0, NULL },
   /*        { CDP_TYPE_PROTOCOL_HELLO,  "Protocol Hello" },*/
   { CDP_TYPE_VTP_MGMT_DOMAIN, "vtpdomain", "VTP Domain",       MAX_STRING_SIZE, FIELD_STR, "Set VTP Domain", " WORD VTP Domain", MAX_STRING_SIZE, 0, NULL },
   /*        { CDP_TYPE_NATIVE_VLAN,     "Native VLAN" },
             { CDP_TYPE_DUPLEX,          "Duplex" },
             { CDP_TYPE_VOIP_VLAN_REPLY, "VoIP VLAN Reply" },
             { CDP_TYPE_VOIP_VLAN_QUERY, "VoIP VLAN Query" },
             { CDP_TYPE_MTU,             "MTU"},
             { CDP_TYPE_TRUST_BITMAP,    "Trust Bitmap" },
             { CDP_TYPE_UNTRUSTED_COS,   "Untrusted CoS" },*/
   { CDP_TYPE_SYSTEM_NAME,     "system", "System Name",  MAX_STRING_SIZE, FIELD_STR, "Set System Name", " WORD System Name", MAX_STRING_SIZE, 0, NULL }/*
             { CDP_TYPE_SYSTEM_OID,      "System ObjectID" },
             { CDP_TYPE_MANAGEMENT_ADDR, "Management Addr" },
             { CDP_TYPE_LOCATION,        "Location" },*/
};


#define CDP_ATTACK_SEND_CDP     0 
#define CDP_ATTACK_FLOOD_CDP    1 
#define CDP_ATTACK_VIRTUAL_DEVICE 2 

void      cdp_th_send_raw(void *);
void      cdp_th_send_raw_exit(struct attacks *);
void      cdp_th_flood(void *);
void      cdp_th_flood_exit(struct attacks *);
void      cdp_th_virtual_device(void *);
void      cdp_th_virtual_device_exit(struct attacks *);

static struct attack cdp_attack[] = {
  { CDP_ATTACK_SEND_CDP, "sending CDP packet",                NONDOS, SINGLE,    cdp_th_send_raw, NULL, 0 },
  { CDP_ATTACK_FLOOD_CDP, "flooding CDP table",               DOS,    CONTINOUS, cdp_th_flood, NULL, 0 },
  { CDP_ATTACK_VIRTUAL_DEVICE, "Setting up a virtual device", NONDOS, CONTINOUS, cdp_th_virtual_device, NULL, 0 },
  { 0,                   NULL,                                0,      0,         NULL, NULL, 0     }
};

void      cdp_register(void);
int8_t    cdp_send(struct attacks *);
void      cdp_send_hellos(void *);
int8_t    cdp_create_tlv_item(struct cdp_data *, u_int16_t, void *);
int8_t    cdp_update_tlv_item(struct cdp_data *, u_int16_t, char *);
int8_t    cdp_edit_tlv(struct term_node *, u_int8_t, u_int8_t, u_int16_t, u_int8_t *);
char      **cdp_get_printable_packet(struct pcap_data *);
char      **cdp_get_printable_store(struct term_node *);
int8_t    cdp_load_values(struct pcap_data *, void *);
int8_t    cdp_update_field(int8_t, struct term_node *, void *);
int8_t    cdp_init_attribs(struct term_node *);
void      *cdp_get_extra_field(struct term_node *, void *, u_int8_t);
void      cdp_send_exit(struct attacks *);
char *    cdp_get_type_info(u_int16_t);
u_int16_t cdp_chksum(u_int8_t *, u_int32_t);
int8_t    cdp_init_comms_struct(struct term_node *);
int8_t    cdp_end(struct term_node *);


extern void   thread_libnet_error( char *, libnet_t *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern void   attack_gen_mac(u_int8_t *);
extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
extern int8_t parser_get_inet_aton(char *, struct in_addr *);
extern int8_t parser_get_random_string(u_int8_t *, u_int8_t);
extern int8_t parser_get_random_int(u_int8_t);

extern int8_t  parser_command2index(register const struct attack *, register int8_t);

extern int8_t bin_data[];
#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
