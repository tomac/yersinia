/* dtp.h
 * Definitions for Cisco's Dynamic Trunking Protocol
 *
 * $Id: dtp.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __DTP_H__
#define __DTP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"


#define DTP_TYPE_DOMAIN   0x01
#define DTP_TYPE_STATUS   0x02
#define DTP_TYPE_TYPE     0x03
#define DTP_TYPE_NEIGHBOR 0x04


/* Status TOS/TAS */
#define DTP_ACCESS    0x00
#define DTP_TRUNK     0x80
#define DTP_ON        0x01
#define DTP_OFF       0x02
#define DTP_DESIRABLE 0x03
#define DTP_AUTO      0x04
#define DTP_UNKNOWN   0x05

/* Type TOT/TAT */
#define DTP_TOT_NATIVE     0x20
#define DTP_TOT_ISL        0x40
#define DTP_TOT_802_1Q     0xa0
#define DTP_TAT_NEGOTIATED 0x00
#define DTP_TAT_NATIVE     0x01
#define DTP_TAT_ISL        0x02
#define DTP_TAT_802_1Q     0x05

/* Default values */
#define DTP_DFL_VERSION 0x01
#define DTP_DFL_DOMAIN  "\x0\x0\x0\x0\x0\x0\x0\x0"
#define DTP_DFL_DOM_LEN 0x08
#define DTP_DFL_STATUS  (DTP_ACCESS | DTP_DESIRABLE)
#define DTP_DFL_TYPE    (DTP_TOT_802_1Q | DTP_TAT_802_1Q)

#define DTP_DOMAIN_SIZE 32

static const struct tuple_type_desc dtp_status[] = {
    { DTP_ACCESS|DTP_DESIRABLE, "ACCESS/DESIRABLE" },
    { DTP_ACCESS|DTP_ON,        "ACCESS/ON"        },
    { DTP_ACCESS|DTP_OFF,       "ACCESS/OFF"       },
    { DTP_ACCESS|DTP_AUTO,      "ACCESS/AUTO"      },
    { DTP_TRUNK|DTP_DESIRABLE,  "TRUNK/DESIRABLE"  },
    { DTP_TRUNK|DTP_ON,         "TRUNK/ON"         },
    { DTP_TRUNK|DTP_OFF,        "TRUNK/OFF"        },
    { DTP_TRUNK|DTP_AUTO,       "TRUNK/AUTO"       },
    { DTP_UNKNOWN, "UNKNOWN" },
    { 0, NULL }
};

static const struct tuple_type_desc dtp_type[] = {
    { DTP_TOT_802_1Q|DTP_TAT_802_1Q,     "802.1Q/802.1Q"     },
    { DTP_TOT_802_1Q|DTP_TAT_ISL,        "802.1Q/ISL"        },    
    { DTP_TOT_802_1Q|DTP_TAT_NATIVE,     "802.1Q/NATIVE"     },
    { DTP_TOT_802_1Q|DTP_TAT_NEGOTIATED, "802.1Q/NEGOTIATED" },
    { DTP_TOT_ISL|DTP_TAT_ISL,           "ISL/ISL"           },
    { DTP_TOT_ISL|DTP_TAT_802_1Q,        "ISL/802.1Q"        },
    { DTP_TOT_ISL|DTP_TAT_NATIVE,        "ISL/NATIVE"        },
    { DTP_TOT_ISL|DTP_TAT_NEGOTIATED,    "ISL/NEGOTIATED"    },
    { DTP_TOT_NATIVE|DTP_TAT_802_1Q,     "NATIVE/802.1Q"     },
    { DTP_TOT_NATIVE|DTP_TAT_ISL,        "NATIVE/ISL"        },
    { DTP_TOT_NATIVE|DTP_TAT_NATIVE,     "NATIVE/NATIVE"     },
    { DTP_TOT_NATIVE|DTP_TAT_NEGOTIATED, "NATIVE/NEGOTIATED" },
    { 0, NULL }
};

static struct proto_features dtp_features[] = {
    { F_LLC_CISCO, 0x2004 },
    { -1, 0}
};



/* DTP mode stuff */
struct dtp_data { 
     u_int8_t  mac_source[ETHER_ADDR_LEN];
     u_int8_t  mac_dest[ETHER_ADDR_LEN];
     u_int8_t  version;
     char      domain[DTP_DOMAIN_SIZE+1];
     u_int16_t dom_len;
     u_int8_t  status;
     u_int8_t  type;
     u_int8_t  neighbor[ETHER_ADDR_LEN];
     u_int8_t  state;
};


#define DTP_SMAC     0
#define DTP_DMAC     1
#define DTP_VERSION  2
#define DTP_NEIGH    3
#define DTP_STATUS   4
#define DTP_TYPE     5
#define DTP_DOMAIN   6

/* Struct needed for using protocol fields within the network client */
struct commands_param dtp_comm_params[] = {
    { DTP_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DTP_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DTP_VERSION, "version","Version", 1, FIELD_HEX, "Set dtp version", 
                                        " <0x00-0xFF>    dynamic trunking version", 2, 2, 0, NULL, NULL },
    { DTP_NEIGH, "neighbor", "Neighbor-ID", 6, FIELD_BYTES, "Set neighbor id", 
                                        " HHHHHH    48 bit neighbor address", 12, 2, 1, NULL, NULL },
    { DTP_STATUS, "status",  "Status", 1, FIELD_HEX, "Set trunking status", 
                                        " <0x00-0xFF>    dynamic trunking status", 2, 2, 1, NULL, dtp_status },
    { DTP_TYPE, "type",      "Type", 1, FIELD_HEX, "Set trunking type", 
                                        " <0x00-0xFF>    dynamic trunking type", 2, 2, 0, NULL, dtp_type },
    { DTP_DOMAIN, "domain",  "Domain", DTP_DOMAIN_SIZE, FIELD_STR, "Set vtp domain name to use", 
                                        " WORD    Domain name", DTP_DOMAIN_SIZE, 3, 1, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                             " <cr>", 0, 0, 0, NULL, NULL }, 
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL }
};

#define DTP_ATTACK_SEND     0
#define DTP_ATTACK_DO_TRUNK 1

void dtp_th_send(void *);
void dtp_th_send_exit(struct attacks *);
void dtp_th_nondos_do_trunk(void *);
void dtp_th_nondos_do_trunk_exit(struct attacks *);

static struct attack dtp_attack[] = {
    { DTP_ATTACK_SEND,     "sending DTP packet", NONDOS, SINGLE,    dtp_th_send, NULL, 0            },
    { DTP_ATTACK_DO_TRUNK, "enabling trunking",  NONDOS, CONTINOUS, dtp_th_nondos_do_trunk, NULL, 0 },
    { 0,                   NULL,                 0,      0,         NULL, NULL, 0                   }
};


void    dtp_register(void);
int8_t  dtp_send(struct attacks *);
int8_t  dtp_init_attribs(struct term_node *);
int8_t  dtp_learn_packet(struct attacks *, char *, u_int8_t *, void *, struct pcap_pkthdr *);
char    **dtp_get_printable_packet(struct pcap_data *);
char    **dtp_get_printable_store(struct term_node *);
int8_t  dtp_load_values(struct pcap_data *, void *);
void    dtp_send_negotiate(void *);
int8_t  dtp_update_data(int8_t, int8_t, int8_t, struct term_node *);
int8_t  dtp_update_field(int8_t, struct term_node *, void *);
int8_t  dtp_init_comms_struct(struct term_node *);
int8_t  dtp_end(struct term_node *);

extern void   thread_libnet_error( char *, libnet_t *);
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern void   attack_gen_mac(u_int8_t *);
extern struct interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern int8_t parser_filter_param(u_int8_t, void *, char *, u_int16_t, int32_t, int32_t);

extern int8_t parser_command2index(register const struct attack *, register int8_t);
extern struct terminals *terms;

extern int8_t bin_data[];

extern int8_t term_vty_write(struct term_node *, char *, u_int16_t);
extern int8_t command_bad_input(struct term_node *, int8_t);

#endif
