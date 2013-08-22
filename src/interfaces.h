/* interfaces.h
 * Definitions for network interfaces and capturing packets
 *
 * $Id: interfaces.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __INTERFACES_H__
#define __INTERFACES_H__

#include <pcap.h>
#include <libnet.h>

#include "protocols.h"
#include "thread-util.h"
#include "terminal-defs.h"
#include "dlist.h"

#ifndef BPDU_TCN
#define BPDU_TCN  0x80
#endif

#define ALL_INTS -1

/* Max protocol queue size */
#define MAX_QUEUE 5

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define PCAP_DESC 16
#define IPADDRSIZ 46

#define PROMISC   1
#define TIMEOUT   500
#define FILTER    "stp || (udp and (port 1985 or port 68 or port 67)) || (ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000) || (ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2004) || (ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2003) || arp || vlan || (ether[14]=0xaa and ether[15]=0xaa and ether[0]=0x01 and ether[1]=0x00 and ether[2]=0x0c and ether[3]=0x00 and ether[4]=0x00) || (ether[0]=0x01 and ether[1]=0x80 and ether[2]=0xc2 and ether[12:2] = 0x888e) || mpls"

/* Fields for recognizing packets */
#define F_ETHERTYPE 1 
#define F_LLC_SSAP  2
#define F_LLC_DSAP  3
#define F_LLC_SNAP  4
#define F_LLC_CISCO 5
#define F_DMAC_1    6
#define F_DMAC_2    7
#define F_DMAC_3    8
#define F_DMAC_4    9
#define F_DMAC_5    10
#define F_DMAC_6    11
#define F_UDP_PORT  12

#define NO_TIMEOUT  0

list_t *interfaces;

struct interface_data {
       int8_t   up;                  /* is it active? */
       char     ifname[IFNAMSIZ+1];  /* Interface name */
       int      iflink;               /* Type of data link */
       char     iflink_name[PCAP_DESC+1];
       char     iflink_desc[PCAP_DESC+1];
       int8_t   desc[PCAP_DESC+1];
       u_int8_t etheraddr[ETHER_ADDR_LEN]; /* MAC Address */
       char     ipaddr[IPADDRSIZ+1];    /* IP address */
       char     netmask[IPADDRSIZ+1];   /* Netmask address */
       char     broadcast[IPADDRSIZ+1]; /* Broadcast address */
       char     ptpaddr[IPADDRSIZ+1];   /* Point-to-point (if suitable) */   
       pcap_t  *pcap_handler;     /* Libpcap handler */
       int      pcap_file;            /* Libpcap file handler */
       libnet_t *libnet_handler; /* Libnet handler */
       u_int16_t users;            /* number of clients using it */
       u_int32_t packets[MAX_PROTOCOLS];
       u_int32_t packets_out[MAX_PROTOCOLS];
};

struct counter_stats {
       u_int32_t total_packets;
       u_int32_t total_packets_out;
};


/*struct pcap_data {
                  struct pcap_pkthdr *header;
                  u_int8_t *packet;
                  u_int16_t iface;
};*/


struct packet_stats {
       struct counter_stats global_counter;
};

struct packet_queue {
       struct pcap_data data[MAX_QUEUE];
       pthread_mutex_t mutex;
       u_int16_t index;
};

int8_t  interfaces_init(THREAD *);
int8_t  interfaces_init_data(struct interface_data *);
int16_t interfaces_enable(char *);
int16_t interfaces_get(char *);
struct  interface_data *interfaces_get_struct(char *);
int8_t  interfaces_disable(char *);
int8_t  interfaces_init_pcap(char *);
int8_t  interfaces_init_libnet(char *);
void   *interfaces_th_pcap_listen(void *);
void    interfaces_th_pcap_listen_exit(THREAD *);
void    interfaces_th_pcap_listen_clean(void *);
struct  interface_data *interfaces_get_packet(list_t *, struct interface_data *, u_int8_t *stop, struct pcap_pkthdr *, u_int8_t *, u_int16_t, time_t);
int8_t  interfaces_clear_stats(int8_t);
int8_t  interfaces_destroy(THREAD *);
u_int16_t interfaces_update_stats(struct pcap_data *);
int8_t   interfaces_recognize_packet(u_int8_t *, struct pcap_pkthdr *);
int8_t   interfaces_pcap_file_open(struct term_node *, u_int8_t, char *, char *);
int8_t   interfaces_pcap_file_close(struct term_node *, u_int8_t);
u_int8_t interfaces_get_last_int(u_int8_t);
int8_t   interfaces_compare(void *, void *);

#ifndef HAVE_PCAP_DUMP_FLUSH
int8_t  pcap_dump_flush(pcap_dumper_t *);
#endif

/* External stuff */
extern pthread_mutex_t mutex_int;
extern struct  terminals *terms;
extern int8_t  fatal_error;
extern struct  packet_queue queue[];
extern struct  packet_stats packet_stats;
extern struct  packet_data packet_data;
extern FILE   *log_file;
extern void    thread_error(char *, int8_t);
extern int8_t  thread_destroy(THREAD *);

extern struct term_tty *tty_tmp;

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
