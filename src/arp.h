/* arp.h
 * Defintions for Address Resolution Protocol
 *
 * $Id: arp.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __ARP_H__
#define __ARP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define ARP_SMAC        0
#define ARP_DMAC        1
#define ARP_FORMATHW    2
#define ARP_FORMATPROTO 3
#define ARP_LENHW       4
#define ARP_LENPROTO    5
#define ARP_OP          6

/* ARP stuff */
struct arp_data { /* ARP and Ethernet fields*/
	u_int16_t formathw;
	u_int16_t formatproto;
	u_int8_t lenhw;
	u_int8_t lenproto;
	u_int16_t op;
    /* Ethernet Data */
    u_int8_t mac_source[ETHER_ADDR_LEN];
    u_int8_t mac_dest[ETHER_ADDR_LEN];
};

static struct proto_features arp_features[] = {
    { F_ETHERTYPE, ETHERTYPE_ARP || ETHERTYPE_REVARP},
    { -1, 0}
};

static struct attack arp_attack[] = {
  { 0,  NULL,  0, 0, NULL, NULL, 0  }
};

void   arp_register(void);

extern void   thread_libnet_error(char *, libnet_t *);
extern int8_t vrfy_bridge_id(char *, u_int8_t * );
extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
extern int8_t thread_create(pthread_t *, void *, void *);
extern void   write_log( u_int16_t mode, char *msg, ... );
extern int8_t attack_th_exit(struct attacks *);
extern void   attack_gen_mac(u_int8_t *);
extern struct interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
extern int8_t parser_vrfy_mac(char *, u_int8_t *);
extern int8_t parser_get_inet_aton(char *, struct in_addr *);

extern int8_t parser_command2index(register const struct attack *, register int8_t);
extern struct terminals *terms;

extern int8_t bin_data[];
#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
