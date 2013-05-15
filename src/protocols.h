/* protocols.h
 * Definitions for protocol stuff
 *
 * $Id: protocols.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __PROTOCOLS_H__
#define __PROTOCOLS_H__

#include <pcap.h>
#include <net/if.h>

#ifdef SOLARIS
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t  u_int8_t;
#endif


/* Protocols info */
#define PROTO_ARP    0
#define PROTO_CDP    1
#define PROTO_DHCP   2 
#define PROTO_DOT1Q  3
#define PROTO_DOT1X  4
#define PROTO_DTP    5
#define PROTO_HSRP   6
#define PROTO_ISL    7
#define PROTO_MPLS   8
#define PROTO_STP    9
#define PROTO_VTP   10


#define MAX_PROTOCOLS 11 

#define PROTO_VISIBLE 1
#define PROTO_NOVISIBLE 0

#define NO_PROTO -1 
#define ALL_PROTO 999
#define COMMON_TLV 69

/* Read the HGTTG */
#define PROTO_ALL      42 
#define SNAPLEN   1500

#define MAX_PROTO_NAME 8
#define MAX_PROTO_DESCRIPTION 64

/* different packets received for stats */
#define MAX_PACKET_STATS  10

/* Packets minimum size */
#define CDP_MIN_LENGTH        LIBNET_CDP_H + LIBNET_802_2SNAP_H + LIBNET_802_3_H 
#define DHCP_MIN_LENGTH       LIBNET_DHCPV4_H + LIBNET_UDP_H + LIBNET_IPV4_H + LIBNET_ETH_H
#define DOT1Q_MIN_LENGTH      LIBNET_802_1Q_H
#define DOT1X_MIN_LENGTH      LIBNET_802_1X_H
#define DTP_MIN_LENGTH        12 + LIBNET_802_2_H + LIBNET_802_3_H
#define HSRP_MIN_LENGTH       20 + LIBNET_UDP_H + LIBNET_IPV4_H + LIBNET_ETH_H
#define VTP_MIN_LENGTH        40 + LIBNET_802_2_H + LIBNET_802_3_H
#define STP_CONF_MIN_LENGTH   LIBNET_STP_CONF_H + LIBNET_802_2_H + LIBNET_802_3_H
#define STP_TCN_MIN_LENGTH    LIBNET_STP_TCN_H + LIBNET_802_2_H + LIBNET_802_3_H


struct term_node;
struct attacks;
struct attack;
struct pcap_pkthdr;
struct words_array;

struct pcap_data {
       struct pcap_pkthdr *header;
       u_int8_t *packet;
       char iface[IFNAMSIZ+1];
       u_int32_t total;
};

struct proto_features {
       int8_t field;
       u_int32_t value;
};

/* Parameters field types */
#define FIELD_NONE      0
#define FIELD_HEX       1
#define FIELD_DEC       2
#define FIELD_STR       3
#define FIELD_MAC       4
#define FIELD_BRIDGEID  5
#define FIELD_IP        6
#define FIELD_TLV       7
#define FIELD_IFACE     8
#define FIELD_BYTES     9
#define FIELD_DEFAULT   99
#define FIELD_EXTRA     100

/* struct used for protocol parameters */
struct commands_param {
       u_int8_t id;      /* ID */
       char     *desc;   /* Description */
       char     *ldesc;  /* Long description */
       u_int16_t size;   /* Size */
       u_int8_t  type;   /* Type */
       char     *help;   /* Help text */
       char     *param;  /* Param text */
       u_int16_t size_print; /* Allowed printable size */
       u_int8_t  row;    /* Row where the field is displayed (ncurses and GTK) */
       u_int8_t  mwindow; /* 1 if appears in mwindow, 0 if not */
       int8_t  (*filter)(void *, void *, char *); /* Filtering function specific for protocol */
       const struct tuple_type_desc *meaning; /* filed value description */
};

/* struct used for extra protocol parameters (TLV, VLANS, ...) */
struct commands_param_extra {
       u_int32_t id;
       char     *desc;   /* Description */
       char     *ldesc;  /* Long description */
       u_int16_t size;   /* Size */
       u_int8_t  type;   /* Type */
       char     *help;   /* Help text */
       char     *param;  /* Param text */
       u_int16_t size_print; /* Allowed printable size */
       u_int8_t  mwindow; /* 1 if appears in mwindow, 0 if not */
       const struct tuple_type_desc *meaning; /* field value description */
       /* int8_t  (*filter)(void *, void *, char *);*/ /* Filtering function specific for protocol */
};

/* Struct for the list of extra params */
struct commands_param_extra_item {
   u_int32_t id;
   u_int8_t  *value;
};
                         
/* struct needed for giving info about packet fields and 
 * letting the user to choose values when crafting the packet */
struct tuple_type_desc {
       u_int16_t type;
       char *desc;
};

struct tuple_tlv {
       u_int16_t type;
       u_int8_t format;
};

typedef int8_t  (*init_attribs_t)(struct term_node *);
typedef int8_t  (*learn_packet_t)(struct attacks *, char *, u_int8_t *, void *, struct pcap_pkthdr *);
typedef char    **(*get_printable_packet_t)(struct pcap_data *);
typedef char    **(*get_printable_store_t)(struct term_node *);
typedef int8_t  (*load_values_t)(struct pcap_data *, void *);
typedef int8_t  (*update_field_t)(int8_t, struct term_node *, void *);
typedef int8_t  (*edit_tlv_t)(struct term_node *, u_int8_t, u_int8_t, u_int16_t, u_int8_t *);
typedef int8_t  (*init_commands_struct_t)(struct term_node *);
typedef int8_t  (*end_t)(struct term_node *);
typedef void    *(*get_extra_field_t)(struct term_node *, void *, u_int8_t);


struct protocol_def {
       u_int8_t proto;              /* Proto id      */
       char namep[MAX_PROTO_NAME];   /* Proto name    */
       char description[MAX_PROTO_DESCRIPTION];   /* Proto description    */
       char name_comm[MAX_PROTO_NAME];  /* Protocol name for CLI interface */
       u_int8_t active;                 /* Active or not */
       u_int16_t size;                  /* Struct size   */
       init_attribs_t init_attribs;
       learn_packet_t learn_packet;
       get_printable_packet_t get_printable_packet;
       get_printable_store_t get_printable_store;
       load_values_t load_values;
       struct attack *attacks;
       struct pcap_data stats[MAX_PACKET_STATS];
       update_field_t update_field;
       edit_tlv_t edit_tlv;
       const struct tuple_type_desc *ttd;
       struct attack_param *tlv;
       u_int16_t tlv_params;
       u_int32_t packets;
       u_int32_t packets_out;
       struct proto_features *features;
       void *default_values;
       init_commands_struct_t init_commands_struct; /* Function for initialize commands struct */
       struct commands_param *parameters;
       u_int8_t nparams;
#ifdef HAVE_REMOTE_ADMIN
       u_int8_t *params_sort;
#endif
       struct commands_param_extra *extra_parameters;
       u_int8_t extra_nparams;
       get_extra_field_t get_extra_field;
       u_int8_t visible; /* Visible */
       end_t end;
};

struct protocol_def protocols[MAX_PROTOCOLS];

void   protocol_init(void);
int8_t protocol_register(u_int8_t, const char *, const char *, const char *,
                         u_int16_t, init_attribs_t, learn_packet_t, 
                         get_printable_packet_t, get_printable_store_t,
                         load_values_t, struct attack *, 
                         update_field_t, struct proto_features *, 
                         struct commands_param *, u_int8_t, 
                         struct commands_param_extra *, u_int8_t, get_extra_field_t,
                         init_commands_struct_t, u_int8_t, end_t);
int8_t protocol_register_tlv(u_int8_t, edit_tlv_t, const struct tuple_type_desc *, struct attack_param *, u_int16_t);

void   protocol_register_all(void);
void   protocol_destroy(void);
char **protocol_create_printable(u_int8_t, struct commands_param *);
int8_t protocol_extra_compare(void *, void *);
#ifdef HAVE_REMOTE_ADMIN
char  *protocol_sort_str(char *, char *);
void   protocol_sort_params(u_int8_t, u_int8_t *, u_int8_t);
#endif
extern void write_log( u_int16_t mode, char *msg, ... );

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
