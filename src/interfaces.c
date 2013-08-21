/* interfaces.c
 * Network interface utilities and main core for capturing packets
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
"$Id: interfaces.c 46 2007-05-08 09:13:30Z slay $";
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

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#include <sys/ioctl.h>

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else
#ifdef HAVE_NETINET_IN_SYSTEM_H
#include <netinet/in_system.h>
#endif
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
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

#ifdef SOLARIS
#include <pthread.h>
#include <thread.h>
#else
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#endif

#ifdef HAVE_BPF
#include <net/bpf.h>
#endif

#include "interfaces.h"




////////////////////////////////////////////////////////////////////////////////////////////////////


int8_t
interfaces_init_data_pcap_addr( pcap_if_t *index, struct interface_data *iface_data )
{
    pcap_addr_t *pcap_addr;

    pcap_addr = index->addresses;

    while( pcap_addr )
    {
        if ( pcap_addr->addr && ( ( pcap_addr->addr->sa_family == AF_INET ) ||
                                  ( pcap_addr->addr->sa_family == AF_INET6 ) ) )
        {
            if ( ! inet_ntop( pcap_addr->addr->sa_family, (void *)&pcap_addr->addr->sa_data[2], 
                             iface_data->ipaddr, IPADDRSIZ ) ) 
                thread_error( "inet_ntop error", errno );
        }  
        
        if ( pcap_addr->netmask && ( ( pcap_addr->netmask->sa_family == AF_INET ) ||
                                     ( pcap_addr->netmask->sa_family == AF_INET6 ) ) )                  
        {
            if ( ! inet_ntop( pcap_addr->netmask->sa_family, (void *)&pcap_addr->netmask->sa_data[2],
                             iface_data->netmask, IPADDRSIZ ) ) 
                thread_error( "inet_ntop error", errno );
        }
        
        if ( pcap_addr->broadaddr && ( ( pcap_addr->broadaddr->sa_family == AF_INET ) ||
                                       ( pcap_addr->broadaddr->sa_family == AF_INET6 ) ) )                  
        {
            if ( ! inet_ntop( pcap_addr->broadaddr->sa_family, (void *)&pcap_addr->broadaddr->sa_data[2],
                             iface_data->broadcast, IPADDRSIZ ) ) 
                thread_error( "inet_ntop error", errno );
        }              
        
        if ( pcap_addr->dstaddr && ( ( pcap_addr->dstaddr->sa_family == AF_INET ) ||
                                     ( pcap_addr->dstaddr->sa_family == AF_INET6 ) ) )                                    
        {
            if ( ! inet_ntop( pcap_addr->dstaddr->sa_family, (void *)&pcap_addr->dstaddr->sa_data[2],
                             iface_data->ptpaddr, IPADDRSIZ ) ) 
                thread_error("inet_ntop error",errno);
        }
        
        pcap_addr = pcap_addr->next ;

    }

    return 0 ;
}


////////////////////////////////////////////////////////////////////////////////////////////////////


int8_t
interfaces_init_data_pcap( struct interface_data *iface_data, pcap_if_t *index )
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_hnd ;
    int8_t ret = -1 ;
    
    if ( ( pcap_hnd = pcap_open_live( iface_data->ifname, SNAPLEN, 0, 0, errbuf ) ) )
    {
        iface_data->iflink = pcap_datalink( pcap_hnd );

        pcap_close( pcap_hnd );
        
        if ( iface_data->iflink == DLT_EN10MB )
        {
            strncpy( iface_data->iflink_name, pcap_datalink_val_to_name( iface_data->iflink ), PCAP_DESC );
            strncpy( iface_data->iflink_desc, pcap_datalink_val_to_description( iface_data->iflink ), PCAP_DESC );
            
            write_log( 0, "\n %s iflinkname %s\n", iface_data->ifname, iface_data->iflink_name );
            write_log( 0, " %s iflinkdesc %s\n", iface_data->ifname, iface_data->iflink_desc );

            interfaces_init_data_pcap_addr( index, iface_data ) ;

            if (tty_tmp->debug )
            {
                write_log( 0," %s ip is %s\n",iface_data->ifname, iface_data->ipaddr);
                write_log( 0," %s mask is %s\n", iface_data->ifname, iface_data->netmask);
                write_log( 0," %s broadcast is %s\n", iface_data->ifname, iface_data->broadcast);
                write_log( 0," %s P-t-P is %s\n", iface_data->ifname, iface_data->ptpaddr );
            }

            ret = 0 ;
        }

    }
    else
    {
        write_log( 0, "pcap_open_live failed: %s\n", errbuf );
    }

    return ret;
}


////////////////////////////////////////////////////////////////////////////////////////////////////


int8_t
interfaces_init_data_libnet( struct interface_data *interface )
{
    char errbuflibnet[LIBNET_ERRBUF_SIZE];
    struct libnet_ether_addr *etheraddr;
    libnet_t *libnet_hnd;
    int8_t ret = -1 ;
    
    if ( ( libnet_hnd = libnet_init( LIBNET_LINK, interface->ifname, errbuflibnet ) ) )
    {
        etheraddr = libnet_get_hwaddr( libnet_hnd );

        if ( etheraddr && memcmp( (void *)etheraddr, "\x0\x0\x0\x0\x0\x0", 6 ) )
        {
            memcpy( (void *)interface->etheraddr, (void *)etheraddr, ETHER_ADDR_LEN );
        }
        
        libnet_destroy( libnet_hnd );

        write_log( 0," %s MAC = %02x%02x.%02x%02x.%02x%02x\n", interface->ifname, 
                   etheraddr->ether_addr_octet[0], etheraddr->ether_addr_octet[1],
                   etheraddr->ether_addr_octet[2], etheraddr->ether_addr_octet[3],
                   etheraddr->ether_addr_octet[4], etheraddr->ether_addr_octet[5]); 
        
        ret = 0;
    }
    else
    {
        write_log( 0, "libnet_init failed on %s -> %s\n", interface->ifname, errbuflibnet );
    }

    return ret ;
}


////////////////////////////////////////////////////////////////////////////////////////////////////


/*
 * Initialize global interfaces list (interfaces).
 */
int8_t 
interfaces_init( THREAD *pcap_th )
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct interface_data *iface_data;
    pcap_if_t *alldevs;
    pcap_if_t *index ;
    u_int16_t i, j;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        write_log(0,"interfaces_init pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    
    if (tty_tmp->debug)
        write_log(0,"\n interfaces_init start...\n");
    
    if ((interfaces = (list_t *) calloc(1, sizeof(list_t))) == NULL) {
       write_log(0, "interfaces_init calloc interfaces\n");
       return -1;
    }
    
    if (pthread_mutex_init(&interfaces->mutex, NULL) != 0)
    {
       thread_error("interfaces_init pthread_mutex_init interfaces->mutex", errno);
       return -1;
    }
    
    interfaces->cmp = interfaces_compare;
    
    index = (pcap_if_t *) alldevs;
    
    while( index )
    {
        if ( ( strncmp( index->name, "any", strlen( index->name ) ) ) && ( index->flags != PCAP_IF_LOOPBACK ) )
        {
            if ( ( iface_data = (struct interface_data *)calloc( 1, sizeof( struct interface_data ) ) ) ) 
            {
                strncpy( iface_data->ifname, index->name, IFNAMSIZ );

                write_log( 0, "Network Interface %s\n", index->name );

                if ( interfaces_init_data_pcap( iface_data, index ) != -1 )
                {
                    if ( interfaces_init_data_libnet( iface_data ) != -1 )
                    {
                        iface_data->up             = 0;
                        iface_data->pcap_handler   = NULL;
                        iface_data->pcap_file      = 0;
                        iface_data->libnet_handler = NULL;
                        iface_data->users          = 0;
                        
                        for ( j = 0; j < MAX_PROTOCOLS ; j++ ) 
                        {
                            iface_data->packets[j]     = 0 ;
                            iface_data->packets_out[j] = 0 ;
                        }
                        
                        interfaces->list = dlist_append( interfaces->list, (void *)iface_data );
                    }
                }
            }
            else
            {
                write_log( 0, "interfaces_init calloc iface_data\n" );
                return -1;
            }
        }

        index = index->next;
    }
    
    /* free alldevs memory */
    pcap_freealldevs(alldevs);
    
    packet_stats.global_counter.total_packets = 0;
    
    /* Initialize the packets queues...*/
    for ( i = 0 ; i < MAX_PROTOCOLS ; i++ )
    {
        queue[i].index = 0;
        if ( pthread_mutex_init(&queue[i].mutex, NULL) != 0)
        {
           thread_error("pthread_mutex_init",errno);
           return -1;
        }

        for ( j=0 ; j < MAX_QUEUE ; j++ )
        {
            if ( ( queue[i].data[j].packet = (u_char *) calloc( 1, SNAPLEN ) ) == NULL )
                return -1;

            if ( ( queue[i].data[j].header = (struct pcap_pkthdr *) calloc( 1, sizeof( struct pcap_pkthdr ) ) ) == NULL )
                return -1;
        }
    }
    
    if (thread_create(&pcap_th->id, &interfaces_th_pcap_listen, (void *)pcap_th) < 0)
        return -1;
    
    if (tty_tmp->debug)
        write_log(0,"\n interfaces_init finish...\n");
    
    dlist_t *p;

    for (p=interfaces->list;p; p = dlist_next(interfaces->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
    }
    
    return 0;
}


/* 
 * Enable a network interface in the global interfaces list
 * Return interface index or -1 on error.
 * Use global interfaces list (interfaces).
 */
int16_t 
interfaces_enable(char *iface)
{
   dlist_t *p;
   u_int16_t i;
   struct interface_data *iface_data;

   if (pthread_mutex_lock(&interfaces->mutex) != 0)
   {
      thread_error("interfaces_enable pthread_mutex_lock",errno);
      return -1;
   }

   for (i = 0, p = interfaces->list; p; i++, p = dlist_next(interfaces->list, p))
   {
      iface_data = (struct interface_data *) dlist_data(p);
      if ((strncmp(iface_data->ifname, iface, strlen(iface))) == 0) 
      {
         if (iface_data->users == 0) 
         {
            iface_data->up = 1;
            iface_data->users++;
            if (iface_data->pcap_handler == NULL) {
               if (interfaces_init_pcap(iface_data->ifname) == -1)
               {
                  if (pthread_mutex_unlock(&interfaces->mutex) != 0)
                     thread_error("interfaces_enable pthread_mutex_unlock",errno);
                  return -1;
               }
            }

            if (iface_data->libnet_handler == NULL) {
               if (interfaces_init_libnet(iface_data->ifname) == -1)
               {
                  if (pthread_mutex_unlock(&interfaces->mutex) != 0)
                     thread_error("interfaces_enable pthread_mutex_unlock",errno);
                  return -1;
               }
            }
         } 
         else
            iface_data->users++;

         if (pthread_mutex_unlock(&interfaces->mutex) != 0)
         {
            thread_error("interfaces_enable pthread_mutex_unlock",errno);
            return -1;
         }

         return i;
      }
   }                

   if (pthread_mutex_unlock(&interfaces->mutex) != 0)
      thread_error("interfaces_enable pthread_mutex_unlock",errno);

   return -1;
}


/*
 * Search for interface name.
 * Use global interfaces list (interfaces).
 * Return interface index on success.
 * Return -1 on error.
 */
int16_t 
interfaces_get(char *iface)
{
    dlist_t *p;
    u_int16_t i;
    struct interface_data *iface_data;

    if (pthread_mutex_lock(&interfaces->mutex) != 0)
    {
       thread_error("interfaces_get pthread_mutex_lock",errno);
       return -1;
    }

    for (i = 0, p = interfaces->list; p ; i++, p = dlist_next(interfaces->list, p))
    {
        iface_data = (struct interface_data *) dlist_data(p);
        if ((strncmp(iface_data->ifname, iface, strlen(iface))) == 0) 
        {
            if (pthread_mutex_unlock(&interfaces->mutex) != 0)
            {
               thread_error("interfaces_get pthread_mutex_unlock",errno);
               return -1;
            }
            return i;
        }
    }                

   if (pthread_mutex_unlock(&interfaces->mutex) != 0)
      thread_error("interfaces_get pthread_mutex_unlock",errno);
                
    return -1;
}


/*
 * Search for interface name.
 * Use global interfaces list (interfaces).
 * Return interface_data * on success.
 * Return NULL on error.
 */
struct interface_data * 
interfaces_get_struct(char *iface)
{
    dlist_t *p;
    u_int16_t i;
    struct interface_data *iface_data;

    if (pthread_mutex_lock(&interfaces->mutex) != 0)
    {
       thread_error("interfaces_get pthread_mutex_lock",errno);
       return NULL;
    }

    for (i = 0, p = interfaces->list; p ; i++, p = dlist_next(interfaces->list, p))
    {
        iface_data = (struct interface_data *) dlist_data(p);
        if ((strncmp(iface_data->ifname, iface, strlen(iface))) == 0) 
        {
            if (pthread_mutex_unlock(&interfaces->mutex) != 0)
            {
               thread_error("interfaces_get pthread_mutex_unlock",errno);
               return NULL;
            }
            return iface_data;
        }
    }                

   if (pthread_mutex_unlock(&interfaces->mutex) != 0)
      thread_error("interfaces_get pthread_mutex_unlock",errno);
                
    return NULL;
}



/* 
 * Disable a network interface from the global interfaces list
 * Return -1 on error, 0 on success.
 * Use global interfaces list (interfaces).
 */
int8_t 
interfaces_disable(char *iface)
{
    dlist_t *node;
    struct interface_data *iface_data;

    if (pthread_mutex_lock(&interfaces->mutex) != 0)
    {
       thread_error("interfaces_disable pthread_mutex_lock",errno);
       return -1;
    }

    if ((node = dlist_search(interfaces->list, interfaces->cmp, (void *)iface)) == NULL) {
       write_log(0, "Ohh I haven't found the interface %s\n", iface);
       return -1;
    }
    iface_data = (struct interface_data *) dlist_data(node);

    if (iface_data->users == 1) 
    {
       iface_data->up = 0;
       iface_data->users = 0;
    } 
    else
       iface_data->users--;

    if (pthread_mutex_unlock(&interfaces->mutex) != 0)
    {
       thread_error("interfaces_disable pthread_mutex_unlock",errno);
       return -1;
    }

    return 0;
}


int8_t
interfaces_init_pcap(char *iface)
{
    struct bpf_program filter_code;
    dlist_t *node;
    struct interface_data *iface_data;
    bpf_u_int32 local_net, netmask;
    char errbuf[PCAP_ERRBUF_SIZE];
#ifdef HAVE_BPF
    u_int8_t one;
#endif

    node = dlist_search(interfaces->list, interfaces->cmp, iface);
    if (!node)
       return -1;

    iface_data = (struct interface_data *) dlist_data(node);

    if ( (iface_data->pcap_handler = pcap_open_live(iface_data->ifname,
                    SNAPLEN, PROMISC, TIMEOUT, errbuf)) == NULL)
    {
        write_log(0, "pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    if ( pcap_lookupnet(iface_data->ifname, &local_net, &netmask, errbuf) == -1)
    {
        write_log(0, "pcap_lookupnet failed: %s\n", errbuf);
        /* Removed so we can sniff on interfaces without address... :) */
        /* return -1; */
    }

    if (pcap_compile(iface_data->pcap_handler, &filter_code, FILTER, 0, netmask) == -1 )
    {
        write_log(0, "pcap_compile failed: %s", pcap_geterr(iface_data->pcap_handler));
        return -1;
    }

    if (pcap_setfilter(iface_data->pcap_handler, &filter_code) == -1)
    {
        write_log(0, "pcap_setfilter failed: %s", pcap_geterr(iface_data->pcap_handler));
        return -1;
    }

    iface_data->pcap_file = pcap_fileno(iface_data->pcap_handler);
#ifdef HAVE_BPF
    one = 1;
    if (ioctl(iface_data->pcap_file, BIOCIMMEDIATE, &one) < 0)
    {
       write_log(0, "ioctl(): BIOCIMMEDIATE: %s", strerror(errno));
       return (-1);
    }
#endif

    return 0;
}


int8_t
interfaces_init_libnet(char *iface)
{
    char errbuf[LIBNET_ERRBUF_SIZE];
    dlist_t *node;
    struct interface_data *iface_data;

    node = dlist_search(interfaces->list, interfaces->cmp, (void *)iface);
    iface_data = dlist_data(node);

    iface_data->libnet_handler = libnet_init(LIBNET_LINK, iface_data->ifname, errbuf);

    if (iface_data->libnet_handler == NULL)
    {
       write_log(0,"libnet_init failed on %s -> %s\n", iface_data->ifname, errbuf);
       return -1;
    }
    
    write_log(0, " %s libnet_handler %X\n",iface_data->ifname,iface_data->libnet_handler);
    /* we need 'pseudorandom' numbers ;) */
    libnet_seed_prand(iface_data->libnet_handler);

    return 0;
}


/*
 * Thread body for listening in the network and serve the packets 
 * Use global struct 'queue'
 */
void *
interfaces_th_pcap_listen(void *arg)
{
   THREAD *pcap_th;
   int32_t ret, max;
   u_int16_t a;
   int8_t proto;
   fd_set read_set;
   struct timeval timeout;
   sigset_t mask;
   struct pcap_data packet_data;
   dlist_t *p;
   struct interface_data *iface_data;

   if (tty_tmp->debug)
      write_log(0,"\n interfaces_th_pcap_listen thread_id = %d\n",(int)pthread_self());

   pcap_th = (THREAD *)arg;

   pthread_mutex_lock(&pcap_th->finished);

   sigfillset(&mask);

   if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
   {
      thread_error("ints_th_pcap_listen pthread_sigmask()",errno);
      interfaces_th_pcap_listen_exit(pcap_th);
   }

   while(!pcap_th->stop)
   {
      max = 0;
      FD_ZERO(&read_set);
      p = interfaces->list;
      while(p)
      {
         iface_data = (struct interface_data *) dlist_data(p);
         if (iface_data->up == 1) {
            FD_SET( iface_data->pcap_file, &read_set );
            if (max < iface_data->pcap_file)
               max = iface_data->pcap_file;
         }
         p = dlist_next(interfaces->list, p);
      }

      if (!max) /* For avoiding 100% CPU */
         thread_usleep(150000);

      if (max && !pcap_th->stop)
      {
         timeout.tv_sec = 0;
         timeout.tv_usec = 500000;

         if ( (ret=select( max+1, &read_set, NULL, NULL, &timeout ) ) == -1 )
         {
            thread_error("interfaces_th_pcap_listen select()",errno);
            interfaces_th_pcap_listen_exit(pcap_th);
         }

         if ( ret )  /* Data on pcap... */
         {
            p = interfaces->list;
            while( (p) && !pcap_th->stop )
            {
               iface_data = (struct interface_data *) dlist_data(p);
               if (iface_data->up == 1) {
                  if (FD_ISSET( iface_data->pcap_file, &read_set ))
                  {
                     if ((ret = pcap_next_ex(iface_data->pcap_handler, &packet_data.header, 
                                 (const u_char **) &packet_data.packet)) < 0)
                     {
                        write_log(0, "interfaces_th_pcap_listen pcap_next_ex failed: (%d) %s",
                              ret, pcap_geterr(iface_data->pcap_handler));
                        interfaces_th_pcap_listen_exit(pcap_th);

                     }
                     if (!ret) /* pcap_next_ex timeout...*/
                        continue;
                  } else {
                     p = dlist_next(interfaces->list, p);
                     continue;
                  }

                  /* save the interface that has received the packet */
                  strncpy(packet_data.iface, iface_data->ifname, IFNAMSIZ);

                  /* update stats */
                  if (tty_tmp->debug)
                     write_log(0, "Updating packet stats in interface %s...\n", iface_data->ifname);

                  proto = interfaces_update_stats(&packet_data);

                  if (tty_tmp->debug)
                     write_log(0, "Packet stats updated!\n");

                  if (proto != NO_PROTO)
                  {   
                     /* update the user pcap_files...*/
                     if (pthread_mutex_lock(&terms->mutex) != 0)
                        thread_error("interfaces pthread_mutex_lock",errno);

                     for(a=0; a<MAX_TERMS; a++)
                     {
                        if (terms->list[a].up)
                        {
                           if (terms->list[a].pcap_file.pdumper && 
                                 (terms->list[a].pcap_file.iflink == iface_data->iflink) ) 
                              pcap_dump((u_char *)terms->list[a].pcap_file.pdumper, packet_data.header, packet_data.packet);
                           if (terms->list[a].protocol[proto].pcap_file.pdumper &&
                                 (terms->list[a].protocol[proto].pcap_file.iflink == iface_data->iflink) ) 
                              pcap_dump((u_char *)terms->list[a].protocol[proto].pcap_file.pdumper, packet_data.header, packet_data.packet);
                        }

                     }
                     if (pthread_mutex_unlock(&terms->mutex) != 0)
                        thread_error("ints_th_pcap_listen pthread_mutex_unlock",errno);

                     /* update the queue...*/
                     pthread_mutex_lock(&queue[proto].mutex);
                     memcpy(queue[proto].data[(queue[proto].index%MAX_QUEUE)].header,
                           packet_data.header, sizeof(struct pcap_pkthdr));
                     memcpy(queue[proto].data[(queue[proto].index%MAX_QUEUE)].packet,
                           packet_data.packet, packet_data.header->caplen);
                     strncpy(queue[proto].data[(queue[proto].index%MAX_QUEUE)].iface, packet_data.iface, IFNAMSIZ);
                     queue[proto].index++;
                     pthread_mutex_unlock(&queue[proto].mutex);
                  }
               } /* if interfaces.up */
               p = dlist_next(interfaces->list, p);
            } /* while */
         } 
      } /* if max */

   } /* while(!stop)*/ 

   pcap_th->id = 0;

   if (pthread_mutex_unlock(&pcap_th->finished) != 0)
      thread_error("ints_pcap_listen_exit mutex_unlock",errno);

   pthread_exit(NULL);
}


/*
 * We arrived here due to normal termination
 * from thread pcap listener main routine...
 * Release resources...
 */
void
interfaces_th_pcap_listen_exit(THREAD *pcap_th)
{

write_log(0,"\n ints_pcap_listen_exit started...\n");

   pcap_th->stop = 0;
   pcap_th->id = 0;

   /* Tell parent that we are going to die... */
   fatal_error--;

write_log(0,"\n ints_pcap_listen_exit finished...\n");
   
   if (pthread_mutex_unlock(&pcap_th->finished) != 0)
      thread_error("ints_pcap_listen_exit mutex_unlock",errno);
 
   pthread_exit(NULL); 
}


/*
 * Get a packet from the protocol queue
 * Use global struct 'queue'.
 * Return a pointer to the interface that has received the packet (struct
 * interface_data).
 */
struct interface_data *
interfaces_get_packet(list_t *used_ints, struct interface_data *iface,
                       u_int8_t *stop_attack, struct pcap_pkthdr *header, 
                       u_int8_t *packet, u_int16_t proto, time_t timeout)
{
  u_int8_t i;
  time_t initial, secs;
  dlist_t *p;
  
  secs = initial = time(NULL);
  while(!(*stop_attack) && ((secs - initial) <= timeout))
  { 
      pthread_mutex_lock(&queue[proto].mutex);
      for(i=0; i < MAX_QUEUE; i++)
      { 
         if ( (queue[proto].data[i].header->ts.tv_sec > header->ts.tv_sec) ||
              ( (queue[proto].data[i].header->ts.tv_sec == header->ts.tv_sec) &&
                (queue[proto].data[i].header->ts.tv_usec > header->ts.tv_usec) )
            )
         { 
            /* Only accept packets from this interface */
            if (iface) {
               if (strncmp(iface->ifname, queue[proto].data[i].iface, IFNAMSIZ) == 0) {
                  memcpy(header, queue[proto].data[i].header, sizeof(struct pcap_pkthdr));
                  memcpy(packet, queue[proto].data[i].packet, queue[proto].data[i].header->caplen);
                  pthread_mutex_unlock(&queue[proto].mutex);

                  return (struct interface_data *) iface;
               }
            } else {
               /* Accept packets from ALL intefarces used by the attack */
               p = dlist_search(used_ints->list, used_ints->cmp, queue[proto].data[i].iface);
               if (p) {
                  memcpy(header, queue[proto].data[i].header, sizeof(struct pcap_pkthdr));
                  memcpy(packet, queue[proto].data[i].packet, queue[proto].data[i].header->caplen);
                  pthread_mutex_unlock(&queue[proto].mutex);

                  return (struct interface_data *) dlist_data(p);
               }
            }
         }
      }
      pthread_mutex_unlock(&queue[proto].mutex);

      if (timeout)
          secs = time(NULL);
      thread_usleep(50000);
  }

  return NULL;
}


/*
 * Update protocol statistics.
 * Return protocol
 */
u_int16_t
interfaces_update_stats(struct pcap_data *packet_data)
{
    struct timeval time_tmp;
    struct pcap_data *thedata;
    u_int16_t i, j, min_len;
    u_int8_t found;
    int8_t proto;
    dlist_t *p;
    struct interface_data *iface_data;

    i = j = min_len = 0;
    found = 0;
    thedata = NULL;

    if ((proto = interfaces_recognize_packet(packet_data->packet, packet_data->header)) < 0)
        return -1;

    thedata = protocols[proto].stats;
    protocols[proto].packets++;
    if ((p = dlist_search(interfaces->list, interfaces->cmp, (void *)packet_data->iface)) == NULL)
       return -1;
    iface_data = (struct interface_data *) dlist_data(p);
    iface_data->packets[proto]++;
    memcpy(&time_tmp, &thedata[0].header->ts, sizeof(struct timeval));  

    /* Discard corrupt packets */
/*    if (packet_data->header->caplen < min_len) {
        write_log(0, "Error when receiving packet from protocol %d and size %d and the \
                minimum size is %d\n", proto, packet_data->header->caplen, min_len);
        return NO_PROTO;
    }*/
    
    /* find if there is a similar packet */
    while ((!found) && (i < MAX_PACKET_STATS)) {
        if ((memcmp(thedata[i].packet, packet_data->packet, packet_data->header->caplen) == 0)
             && (strncmp(thedata[i].iface, packet_data->iface, strlen(thedata[i].iface)) == 0)) {
            memcpy(thedata[i].header, packet_data->header, sizeof(struct pcap_pkthdr));
            found = 1;
            /* increase the count */
            thedata[i].total++;
        } else {
            if ( (thedata[i].header->ts.tv_sec < time_tmp.tv_sec)  ||
                 ( (thedata[i].header->ts.tv_sec == time_tmp.tv_sec) && (thedata[i].header->ts.tv_usec < time_tmp.tv_usec))
               )
            {
                memcpy(&time_tmp, &thedata[i].header->ts, sizeof(struct timeval));
                j = i;
            }
        }
        i++;
    }

    /* if not, remove the oldest one */
    if (!found) {
        memcpy(thedata[j].header, packet_data->header, sizeof(struct pcap_pkthdr));
        memcpy(thedata[j].packet, packet_data->packet, packet_data->header->caplen);
        strncpy(thedata[j].iface, packet_data->iface, IFNAMSIZ);
        thedata[j].total = 1;
    }

    /* temporal fix until ARP is supported (will be?) */
    if (proto != PROTO_ARP)
        packet_stats.global_counter.total_packets++;
/*    interfaces[packet_data->iface].total_packets++;*/
    
    return proto;
}


int8_t
interfaces_recognize_packet(u_int8_t *packet, struct pcap_pkthdr *header)
{
    u_int8_t i, j, *tmp1, isvalid;
    int8_t result;

    result = -1;
    for (i = 0; i < MAX_PROTOCOLS; i++) 
    {
        if (!protocols[i].active)
           continue;
           
        j = 0;
        isvalid = 1;
        while (protocols[i].features[j].field > 0) {
           switch(protocols[i].features[j].field) {
               case F_ETHERTYPE:
                   if (header->caplen >= 12) {
                       if (ntohs(*(u_int16_t *)(packet + 12)) == (u_int16_t)protocols[i].features[j].value)
                           result = protocols[i].proto;
                       else
                           isvalid = 0;
                   }
               break;
               case F_LLC_DSAP:
                   if (header->caplen >= LIBNET_802_3_H) {
                       if ((*(u_int8_t *)(packet + LIBNET_802_3_H)) == (u_int8_t)protocols[i].features[j].value)
                           result = protocols[i].proto;
                       else
                           isvalid = 0;
                   }
               break;
               case F_LLC_SSAP:
                   if (header->caplen >= LIBNET_802_3_H + 1) {
                       if ((*(u_int8_t *)(packet + LIBNET_802_3_H + 1)) == (u_int8_t)protocols[i].features[j].value)
                           result = protocols[i].proto;
                       else
                           isvalid = 0;
                   }
               break;
               case F_LLC_SNAP:
                   if (header->caplen >= LIBNET_802_3_H + 2) {
                       if ((*(u_int8_t *)(packet + LIBNET_802_3_H + 2)) == (u_int8_t)protocols[i].features[j].value)
                           result = protocols[i].proto;
                       else
                           isvalid = 0;
                   }
               break;
               case F_LLC_CISCO:
                  if (header->caplen >= 20) {
                      if (ntohs(*(u_int16_t *)(packet + 20)) == (u_int16_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_DMAC_1:
                  if (header->caplen >= 1) {
                      if ((*(u_int8_t *)(packet)) == (u_int8_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_DMAC_2:
                  if (header->caplen >= 2) {
                      if ((*(u_int8_t *)(packet + 1)) == (u_int8_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_DMAC_3:
                  if (header->caplen >= 3) {
                      if ((*(u_int8_t *)(packet+ 2)) == (u_int8_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_DMAC_4:
                  if (header->caplen >= 4) {
                      if ((*(u_int8_t *)(packet + 3)) == (u_int8_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_DMAC_5:
                  if (header->caplen >= 5) {
                      if ((*(u_int8_t *)(packet + 4)) == (u_int8_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_DMAC_6:
                  if (header->caplen >= 6) {
                      if ((*(u_int8_t *)(packet + 5)) == (u_int8_t)protocols[i].features[j].value)
                          result = protocols[i].proto;
                      else
                          isvalid = 0;
                  }
               break;
               case F_UDP_PORT:
                   if (header->caplen >= LIBNET_ETH_H + (((*(packet + LIBNET_ETH_H))&0x0F)*4)) {
                       /* IP */
                       if (ntohs(*(u_int16_t *)(packet + 12)) == 0x0800) {
                           /* UDP datagram */
                           if (*(packet + LIBNET_ETH_H + 9) == IPPROTO_UDP) {
                           /* take the ipv4 header length out */
                               tmp1 = (packet + LIBNET_ETH_H + (((*(packet + LIBNET_ETH_H))&0x0F)*4));
                               if ((ntohs(*(u_int16_t *)(tmp1)) == protocols[i].features[j].value) ||
                                       (ntohs(*(u_int16_t *)(tmp1 + 2)) == protocols[i].features[j].value))
                                   result = protocols[i].proto;
                               else
                                   isvalid = 0;
                           }
                       }
                   }
               break;
               default:
               break;
           }
           j++;
        }
        if ((isvalid) && (result >= 0))
            return result;
    }

    return -1;
}


int8_t
interfaces_clear_stats(int8_t stats)
{
    int8_t i, j;
    dlist_t *p;
    struct interface_data *iface_data;

    for (i = 0; i < MAX_PACKET_STATS; i++) 
    {
	if (stats == PROTO_ALL)
	    for (j = 0; j < MAX_PROTOCOLS; j++) {
          memset((void *)protocols[j].stats[i].header, 0, sizeof(struct pcap_pkthdr));
          memset((void *)protocols[j].stats[i].packet, 0, SNAPLEN);
	    } else {
          memset((void *)protocols[stats].stats[i].header, 0, sizeof(struct pcap_pkthdr));
          memset((void *)protocols[stats].stats[i].packet, 0, SNAPLEN);
        }
    }

    if (stats == PROTO_ALL)  {
        packet_stats.global_counter.total_packets = 0;
        for (i = 0; i < MAX_PROTOCOLS; i++)
           protocols[i].packets = 0;
    } else
        protocols[stats].packets = 0;

    for (p = interfaces->list; p; p = dlist_next(interfaces->list, p)) {
       iface_data = (struct interface_data *) dlist_data(p);
        if (stats == PROTO_ALL) {
/*            interfaces[i].total_packets = 0;*/
            for (j = 0; j < MAX_PROTOCOLS; j++) {
		         iface_data->packets[j] = 0;
		         iface_data->packets_out[j] = 0;
	         }
        } else {
	       iface_data->packets[stats] = 0;
	       iface_data->packets_out[stats] = 0;
	    }
    }

    write_log(0, "Clearing stats for protocol(s) %d...\n", stats);

    return 0;
}


int8_t 
interfaces_destroy(THREAD *pcap_th)
{
    u_int16_t i, j;
    dlist_t *p;
    struct interface_data *iface_data;

    write_log(0,"\n ints_destroy started...\n");

    if (pcap_th->id)
    {
       write_log(0," ints_destroy killing pcap_listener(%d)...\n", (int)pcap_th->id);
       thread_destroy(pcap_th);
    }

    for (i=0; i < MAX_PROTOCOLS; i++)
    {
        if (pthread_mutex_destroy(&queue[i].mutex) != 0)
           thread_error("pthread_mutex_destroy queue",errno);
        for (j=0; j < MAX_QUEUE; j++)
        {
            if (queue[i].data[j].packet)
               free(queue[i].data[j].packet);
            if (queue[i].data[j].header)
               free(queue[i].data[j].header);
        }
    }

    /* destroy'em all!! I mean the libnet and pcap handlers :) */
    for (p = interfaces->list; p; p = dlist_next(interfaces->list, p))
    {
       iface_data = (struct interface_data *) dlist_data(p);
       if (iface_data->libnet_handler)
          libnet_destroy(iface_data->libnet_handler);

       if (iface_data->pcap_handler)
          pcap_close(iface_data->pcap_handler);
    }

    
    dlist_delete(interfaces->list);

    if (interfaces)
    {
       pthread_mutex_destroy(&interfaces->mutex);
       free(interfaces);
    }
    
    write_log(0," ints_destroy finished...\n");

    return 0;
}


/*
 * Open a pcap file for writing 'proto' packets
 * If proto == PROTO_ALL write packets from all protocols
 */
int8_t
interfaces_pcap_file_open(struct term_node *node, u_int8_t proto, char *name, char *iface)
{
   dlist_t *p;
   struct interface_data *iface_data;

   if ((p = dlist_search(interfaces->list, interfaces->cmp, (void *)iface)) == NULL)
      return -1;
   iface_data = (struct interface_data *) dlist_data(p);

    if (proto != PROTO_ALL)
    {
        if (strlen(name)>= FILENAME_MAX)
        {
           node->protocol[proto].pcap_file.name = (char *)calloc(1,FILENAME_MAX+1);
           if (node->protocol[proto].pcap_file.name == NULL)
           {
               thread_error("interfaces_pcap_file_open calloc",errno);
               return -1;
           }
           memcpy(node->protocol[proto].pcap_file.name,name,FILENAME_MAX);
        }
        else
        {
           node->protocol[proto].pcap_file.name = (char *)calloc(1,strlen(name)+1);
           if (node->protocol[proto].pcap_file.name == NULL)
           {
               thread_error("interfaces_pcap_file_open calloc",errno);
               return -1;
           }
           memcpy(node->protocol[proto].pcap_file.name,name,strlen(name));
        }

        node->protocol[proto].pcap_file.pd = iface_data->pcap_handler;
        node->protocol[proto].pcap_file.pdumper = pcap_dump_open(node->protocol[proto].pcap_file.pd, 
                                                                  node->protocol[proto].pcap_file.name);
        node->protocol[proto].pcap_file.iflink = iface_data->iflink;
        
        if (node->protocol[proto].pcap_file.pdumper == NULL)
        {
            write_log(0,"pcap_dump_open: %s\n", pcap_geterr(node->protocol[proto].pcap_file.pd));
            node->protocol[proto].pcap_file.pd = NULL;
            free(node->protocol[proto].pcap_file.name);
            return -1;
        }
    }
    else
    {
        if (strlen(name)>= FILENAME_MAX)
        {
           node->pcap_file.name = (char *)calloc(1,FILENAME_MAX+1);
           if (node->pcap_file.name == NULL)
           {
               thread_error("interfaces_pcap_file_open calloc",errno);
               return -1;
           }
           memcpy(node->pcap_file.name,name,FILENAME_MAX);
        }
        else
        {
           node->pcap_file.name = (char *)calloc(1,strlen(name)+1);
           if (node->pcap_file.name == NULL)
           {
               thread_error("interfaces_pcap_file_open calloc",errno);
               return -1;
           }
           memcpy(node->pcap_file.name,name,strlen(name));
        }

        node->pcap_file.pd = iface_data->pcap_handler;
        node->pcap_file.pdumper = pcap_dump_open(node->pcap_file.pd, 
                                                 node->pcap_file.name);
        node->pcap_file.iflink = iface_data->iflink;
        
        if (node->pcap_file.pdumper == NULL)
        {
            write_log(0,"pcap_dump_open: %s\n", pcap_geterr(node->pcap_file.pd));
            node->pcap_file.pd = NULL;
            free(node->pcap_file.name);
            return -1;
        }    
    }
    
    return 0;
}


int8_t
interfaces_pcap_file_close(struct term_node *node, u_int8_t proto)
{
    if (proto != PROTO_ALL)
    {
        pcap_dump_flush(node->protocol[proto].pcap_file.pdumper);
        pcap_dump_close(node->protocol[proto].pcap_file.pdumper);

        node->protocol[proto].pcap_file.pdumper = NULL;
        node->protocol[proto].pcap_file.pd      = NULL;
        free(node->protocol[proto].pcap_file.name);
        node->protocol[proto].pcap_file.name = NULL;
    }
    else
    {
        pcap_dump_flush(node->pcap_file.pdumper);
        pcap_dump_close(node->pcap_file.pdumper);

        node->pcap_file.pdumper = NULL;
        node->pcap_file.pd      = NULL;
        free(node->pcap_file.name);
        node->pcap_file.name = NULL;
    }
    
    return 0;
}


#ifndef HAVE_PCAP_DUMP_FLUSH
int8_t
pcap_dump_flush(pcap_dumper_t *p)
{
    if (fflush((FILE *)p) == EOF)
       return (-1);
    else
       return (0);
}
#endif



/*
 * Get the last interface that has received a 'mode' packet.
 * If mode == PROTO_ALL take into account all the protocols.
 * Return 0 if no packet.
 */
u_int8_t
interfaces_get_last_int(u_int8_t mode)
{
   u_int8_t i, a, last=0, proto;
   u_int32_t sec=0, usec=0;
   
   for (a=0; a < MAX_PROTOCOLS; a++)
   {
       if (mode != PROTO_ALL)
          proto = mode;
       else
          proto = a;
       for (i=0; i < MAX_PACKET_STATS; i++)
       {
           if (protocols[proto].stats[i].header->ts.tv_sec > 0)
           {
               if ( (protocols[proto].stats[i].header->ts.tv_sec > sec) ||
                    ( (protocols[proto].stats[i].header->ts.tv_sec == sec) &&
                      (protocols[proto].stats[i].header->ts.tv_usec > usec) )
                  )
               {
                  sec  = protocols[proto].stats[i].header->ts.tv_sec;
                  usec = protocols[proto].stats[i].header->ts.tv_usec;
                  last = interfaces_get(protocols[proto].stats[i].iface);
               }
           }
       }
       if (mode != PROTO_ALL)
          break;
   }
   
   return last;
}


int8_t
interfaces_compare(void *data, void *pattern)
{
   struct interface_data *iface_data;

   iface_data = (struct interface_data *) data;
   return(strncmp((char *)iface_data->ifname, (char *)pattern, strlen((char *)iface_data->ifname)));
}
