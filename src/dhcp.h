/* dhcp.h
 * Definitions for Dynamic Host Configuration Protocol
 *
 * $Id: dhcp.h 46 2007-05-08 09:13:30Z slay $ 
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

#ifndef __DHCP_H__
#define __DHCP_H__

#include <libnet.h>

#include "terminal-defs.h"
#include "interfaces.h"

#define DHCP_HW_TYPE_E10MB 0x01
#define DHCP_HW_LEN_E10MB  0x06

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_MAX_OPTIONS 100

#define DHCP_SMAC        0
#define DHCP_DMAC        1
#define DHCP_SIP         2
#define DHCP_DIP         3
#define DHCP_SPORT       4
#define DHCP_DPORT       5
#define DHCP_OP          6
#define DHCP_HTYPE       7
#define DHCP_HLEN        8
#define DHCP_HOPS        9
#define DHCP_XID         10
#define DHCP_SECS        11
#define DHCP_FLAGS       12
#define DHCP_CIADDR      13
#define DHCP_YIADDR      14
#define DHCP_SIADDR      15
#define DHCP_GIADDR      16
#define DHCP_CHADDR      17
#define DHCP_TLV         18

#define DHCP_SNAME       20
#define DHCP_FILE        21
#define DHCP_OPTIONS     22
#define DHCP_MSG         23

/* Default values */
#define DHCP_DFL_OPCODE    LIBNET_DHCP_REQUEST
#define DHCP_DFL_HW_TYPE   DHCP_HW_TYPE_E10MB
#define DHCP_DFL_HW_LEN    DHCP_HW_LEN_E10MB
#define DHCP_DFL_MSG       LIBNET_DHCP_MSGDISCOVER
#define DHCP_DFL_HOPS      0
#define DHCP_DFL_SECS      0
#define DHCP_DFL_FLAGS     0x8000

static const struct tuple_type_desc dhcp_type_desc[] = {
    { LIBNET_DHCP_PAD,             "PAD" },           
    { LIBNET_DHCP_SUBNETMASK,      "SUBNETMASK" },     
    { LIBNET_DHCP_TIMEOFFSET,      "TIMEOFFSET" },     
    { LIBNET_DHCP_ROUTER,          "ROUTER" },         
    { LIBNET_DHCP_TIMESERVER,      "TIMESERVER" },    
    { LIBNET_DHCP_NAMESERVER,      "NAMESERVER" },     
    { LIBNET_DHCP_DNS,             "DNS" },            
    { LIBNET_DHCP_LOGSERV,         "LOGSERV" },        
    { LIBNET_DHCP_COOKIESERV,      "COOKIESERV" },     
    { LIBNET_DHCP_LPRSERV,         "LPRSERV" },        
    { LIBNET_DHCP_IMPSERV,         "IMPSERV" },        
    { LIBNET_DHCP_RESSERV,         "RESSERV" },        
    { LIBNET_DHCP_HOSTNAME,        "HOSTNAME" },       
    { LIBNET_DHCP_BOOTFILESIZE,    "BOOTFILESIZE" },   
    { LIBNET_DHCP_DUMPFILE,        "DUMPFILE" },       
    { LIBNET_DHCP_DOMAINNAME,      "DOMAINNAME" },     
    { LIBNET_DHCP_SWAPSERV,        "SWAPSERV" },       
    { LIBNET_DHCP_ROOTPATH,        "ROOTPATH" },       
    { LIBNET_DHCP_EXTENPATH,       "EXTENPATH" },      
    { LIBNET_DHCP_IPFORWARD,       "IPFORWARD" },      
    { LIBNET_DHCP_SRCROUTE,        "SRCROUTE" },       
    { LIBNET_DHCP_POLICYFILTER,    "POLICYFILTER" },   
    { LIBNET_DHCP_MAXASMSIZE,      "MAXASMSIZE" },     
    { LIBNET_DHCP_IPTTL,           "IPTTL" },          
    { LIBNET_DHCP_MTUTIMEOUT,      "MTUTIMEOUT" },     
    { LIBNET_DHCP_MTUTABLE,        "MTUTABLE" },       
    { LIBNET_DHCP_MTUSIZE,         "MTUSIZE" },        
    { LIBNET_DHCP_LOCALSUBNETS,    "LOCALSUBNETS" },   
    { LIBNET_DHCP_BROADCASTADDR,   "BROADCASTADDR" },  
    { LIBNET_DHCP_DOMASKDISCOV,    "DOMASKDISCOV" },   
    { LIBNET_DHCP_MASKSUPPLY,      "MASKSUPPLY" },     
    { LIBNET_DHCP_DOROUTEDISC,     "DOROUTEDISC" },    
    { LIBNET_DHCP_ROUTERSOLICIT,   "ROUTERSOLICIT" },  
    { LIBNET_DHCP_STATICROUTE,     "STATICROUTE" },    
    { LIBNET_DHCP_TRAILERENCAP,    "TRAILERENCAP" },   
    { LIBNET_DHCP_ARPTIMEOUT,      "ARPTIMEOUT" },     
    { LIBNET_DHCP_ETHERENCAP,      "ETHERENCAP" },    
    { LIBNET_DHCP_TCPTTL,          "TCPTTL" },        
    { LIBNET_DHCP_TCPKEEPALIVE,    "TCPKEEPALIVE" },  
    { LIBNET_DHCP_TCPALIVEGARBAGE, "TCPALIVEGARBAGE" },
    { LIBNET_DHCP_NISDOMAIN,       "NISDOMAIN" },      
    { LIBNET_DHCP_NISSERVERS,      "NISSERVERS" },    
    { LIBNET_DHCP_NISTIMESERV,     "NISTIMESERV" },   
    { LIBNET_DHCP_VENDSPECIFIC,    "VENDSPECIFIC" },  
    { LIBNET_DHCP_NBNS,            "NBNS" },          
    { LIBNET_DHCP_NBDD,            "NBDD" },          
    { LIBNET_DHCP_NBTCPIP,         "NBTCPIP" },       
    { LIBNET_DHCP_NBTCPSCOPE,      "NBTCPSCOPE" },    
    { LIBNET_DHCP_XFONT,           "XFONT" },         
    { LIBNET_DHCP_XDISPLAYMGR,     "XDISPLAYMGR" },   
    { LIBNET_DHCP_DISCOVERADDR,    "DISCOVERADDR" },  
    { LIBNET_DHCP_LEASETIME,       "LEASETIME" },     
    { LIBNET_DHCP_OPTIONOVERLOAD,  "OPTIONOVERLOAD" },
    { LIBNET_DHCP_MESSAGETYPE,     "MESSAGETYPE" },   
    { LIBNET_DHCP_SERVIDENT,       "SERVIDENT" },     
    { LIBNET_DHCP_PARAMREQUEST,    "PARAMREQUEST" },  
    { LIBNET_DHCP_MESSAGE,         "MESSAGE" },       
    { LIBNET_DHCP_MAXMSGSIZE,      "MAXMSGSIZE" },    
    { LIBNET_DHCP_RENEWTIME,       "RENEWTIME" },     
    { LIBNET_DHCP_REBINDTIME,      "REBINDTIME" },    
    { LIBNET_DHCP_CLASSSID,        "CLASSSID" },      
    { LIBNET_DHCP_CLIENTID,        "CLIENTID" },      
    { LIBNET_DHCP_NISPLUSDOMAIN,   "NISPLUSDOMAIN" }, 
    { LIBNET_DHCP_NISPLUSSERVERS,  "NISPLUSSERVERS" }, 
    { LIBNET_DHCP_MOBILEIPAGENT,   "MOBILEIPAGENT" }, 
    { LIBNET_DHCP_SMTPSERVER,      "SMTPSERVER" },    
    { LIBNET_DHCP_POP3SERVER,      "POP3SERVER" },    
    { LIBNET_DHCP_NNTPSERVER,      "NNTPSERVER" },    
    { LIBNET_DHCP_WWWSERVER,       "WWWSERVER" },     
    { LIBNET_DHCP_FINGERSERVER,    "FINGERSERVER" },  
    { LIBNET_DHCP_IRCSERVER,       "IRCSERVER" },     
    { LIBNET_DHCP_STSERVER,        "STSERVER" },      
    { LIBNET_DHCP_STDASERVER,      "STDASERVER" },    
    { LIBNET_DHCP_END,             "END" },
    { 0, NULL }
};

static struct attack_param dhcp_tlv[] = {
    { NULL, "SUBNETMASK",               4, FIELD_IP, 15, NULL },
    { NULL, "ROUTER",                   4, FIELD_IP, 15, NULL },
    { NULL, "DNS",                      4, FIELD_IP, 15, NULL },
    { NULL, "HOSTNAME",                 15, FIELD_STR, 15, NULL },
    { NULL, "DOMAINNAME",               15, FIELD_STR, 15, NULL },
    { NULL, "DISCOVERADDR",             4,  FIELD_IP, 15, NULL },
    { NULL, "LEASETIME",                4,  FIELD_HEX, 8, NULL },
    { NULL, "MESSAGETYPE",              1,  FIELD_HEX, 2, NULL },
    { NULL, "SERVIDENT",                4, FIELD_IP, 15, NULL },
    { NULL, "MESSAGE",                 15,  FIELD_STR, 15, NULL },
    { NULL, "RENEWTIME",                4,  FIELD_HEX, 8, NULL },
    { NULL, "REBINDTIME",               4,  FIELD_HEX, 8, NULL },
    { NULL, "CLASSID",                 15, FIELD_STR, 15, NULL },
    { NULL, "END",                      3, FIELD_STR, 3, NULL },
};

static const struct tuple_type_desc dhcp_opcode[] = {
    { LIBNET_DHCP_REQUEST, "REQUEST" },
    { LIBNET_DHCP_REPLY, "REPLY" },
    { 0, NULL }
};

static const struct tuple_type_desc dhcp_message[] = {
    { LIBNET_DHCP_MSGDISCOVER, "DISCOVER" },
    { LIBNET_DHCP_MSGOFFER,    "OFFER" },
    { LIBNET_DHCP_MSGREQUEST,  "REQUEST" },
    { LIBNET_DHCP_MSGDECLINE,  "DECLINE" },
    { LIBNET_DHCP_MSGACK,      "ACK" },     
    { LIBNET_DHCP_MSGNACK,     "NACK" },
    { LIBNET_DHCP_MSGRELEASE,  "RELEASE" },
    { LIBNET_DHCP_MSGINFORM,   "INFORM" },
    { 0,                       NULL }
};

static const struct tuple_type_desc dhcp_htype[] = {
    { DHCP_HW_TYPE_E10MB, "E10MB" },
    { 0,                  NULL }
};

static const struct tuple_type_desc dhcp_port[] = {
    { DHCP_CLIENT_PORT, "CLIENT" },
    { DHCP_SERVER_PORT, "SERVER" },
    { 0, NULL}
};

static struct proto_features dhcp_features[] = {
    { F_UDP_PORT, DHCP_CLIENT_PORT},
    { F_UDP_PORT, DHCP_SERVER_PORT},
    { -1, 0 }
};

#define MAX_SNAME 64
#define MAX_FNAME 128

/* DHCP stuff */
struct dhcp_data { /* DHCP and Ethernet fields*/
    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_int8_t chaddr[ETHER_ADDR_LEN];
    /*char sname[MAX_SNAME];
    char fname[MAX_FNAME]; */
    /* specific options */
    u_int8_t options[MAX_TLV*MAX_VALUE_LENGTH];
    u_int8_t options_len;
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

static const struct tuple_type_desc dhcp_tlv_desc[] = {
    { 0,              NULL }
};


/* Struct needed for using protocol fields within the network client */
struct commands_param dhcp_comm_params[] = {
    { DHCP_SMAC, "source",    "Source MAC", 6, FIELD_MAC, "Set source MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DHCP_DMAC, "dest",      "Destination MAC", 6, FIELD_MAC, "Set destination MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 1, 0, NULL, NULL },
    { DHCP_SIP, "ipsource",  "SIP", 4,  FIELD_IP, "Set source IP address", 
                                        " A.A.A.A    IPv4 address", 15, 2, 1, NULL, NULL },                
    { DHCP_DIP, "ipdest",    "DIP", 4,  FIELD_IP, "Set destination IP address", 
                                        " A.A.A.A    IPv4 address", 15, 2, 1, NULL, NULL },
    { DHCP_SPORT, "sport",     "SPort", 2,  FIELD_DEC, "Set UDP source port", 
                                        " <0-65535>    UDP source port", 5, 2, 0, NULL, dhcp_port },
    { DHCP_DPORT, "dport",     "DPort", 2,  FIELD_DEC, "Set UDP destination port", 
                                        " <0-65535>    UDP destination port", 5, 2, 0, NULL, dhcp_port },
    { DHCP_OP, "opcode",    "Op", 1,  FIELD_HEX, "Set dhcp operation code", 
                                        " <00-FF>    host dynamic configuration operation code", 2, 3, 0, NULL, NULL },
    { DHCP_HTYPE, "htype",     "Htype", 1, FIELD_HEX, "Set dhcp htype", 
                                        " <00-FF>    dhcp htype", 2, 3, 0, NULL, dhcp_htype },
    { DHCP_HLEN, "hlen",      "HLEN", 1,  FIELD_HEX, "Set dhcp hlen", 
                                        " <00-FF>    dhcp hlen", 2, 3, 0, NULL, NULL },
    { DHCP_HOPS, "hops",      "Hops", 1, FIELD_HEX, "Set dhcp hops", 
                                        " <00-FF>    dhcp hops", 2, 3, 0, NULL, NULL },
    { DHCP_XID, "xid",       "Xid", 4, FIELD_HEX, "Set dhcp xid", 
                                        " <00-FFFFFFFF>    dhcp xid", 8, 3, 0, NULL, NULL },
    { DHCP_SECS, "secs",      "Secs", 2,  FIELD_HEX, "Set dhcp secs", 
                                        " <00-FFFF>    dhcp secs", 4, 3, 0, NULL, NULL },
    { DHCP_FLAGS, "flags",     "Flags", 2,FIELD_HEX, "Set dhcp flags", 
                                        " <00-FFFF>    dhcp flags", 4, 3, 0, NULL, NULL },
    { DHCP_CIADDR, "ci",        "CI", 4, FIELD_IP, "Set ci IP address", 
                                        " A.A.A.A    IPv4 address", 15, 4, 0, NULL, NULL },                
    { DHCP_YIADDR, "yi",        "YI", 4, FIELD_IP, "Set yi IP address", 
                                        " A.A.A.A    IPv4 address", 15, 4, 0, NULL, NULL },
    { DHCP_SIADDR, "si",        "SI", 4, FIELD_IP, "Set si IP address", 
                                        " A.A.A.A    IPv4 address", 15, 4, 0, NULL, NULL },                
    { DHCP_GIADDR, "gi",        "GI", 4,  FIELD_IP, "Set gi IP address", 
                                        " A.A.A.A    IPv4 address", 15, 4, 0, NULL, NULL },                
    { DHCP_CHADDR, "ch",        "CH", 6,  FIELD_MAC, "Set ch MAC address", 
                                        " H:H:H:H:H:H    48 bit mac address", 17, 5, 0, NULL, NULL },
    { 0, "defaults",  NULL, 0, FIELD_DEFAULT, "Set all values to default", 
                                        " <cr>", 0, 0, 0, NULL, NULL }, 
    /* { "fname",     "Filename", MAX_FNAME,  FIELD_STR, "Set boot file name", 
                                        " WORD    Boot file name", MAX_FNAME, NULL },*/
    { 0, "interface", NULL, IFNAMSIZ, FIELD_IFACE, "Set network interface to use", 
                                        " WORD    Network interface", IFNAMSIZ, 0, 0, NULL, NULL },
    /* { "sname",     "Sname", MAX_SNAME, FIELD_STR, "Set server hostname", 
                                        " WORD    Server hostname", MAX_SNAME, NULL },*/
    { DHCP_TLV, "tlv",       "TLV", 0, FIELD_EXTRA, "", "", 0, 0, 0, NULL, NULL}
};

struct commands_param_extra dhcp_params_tlv[] = {
/*    { LIBNET_DHCP_PAD,             "PAD" },*/           
    { LIBNET_DHCP_SUBNETMASK,      "subnetmask", "SubnetMask", 4, FIELD_IP, "Set SubnetMaskr", " A.A.A.A IPv4 address", 15, 0, NULL },         
/*    { LIBNET_DHCP_TIMEOFFSET,      "TIMEOFFSET" },    */ 
    { LIBNET_DHCP_ROUTER,          "router", "Router", 4, FIELD_IP, "Set Router", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_TIMESERVER,      "timeserver", "TimeServer", 4, FIELD_IP, "Set TimeServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_NAMESERVER,      "namserver", "NameServer", 4, FIELD_IP, "Set NameServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_DNS,             "dns", "DNS", 4, FIELD_IP, "Set DNS", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_LOGSERV,         "logserver", "LogServer", 4, FIELD_IP, "Set LogServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_COOKIESERV,      "cookieserver", "CookieServer", 4, FIELD_IP, "Set CookieServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_LPRSERV,         "lprserver", "LPRServer", 4, FIELD_IP, "Set LPRServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_IMPSERV,         "impserver", "Impserver", 4, FIELD_IP, "Set ImpServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_RESSERV,         "resserver", "ResServer", 4, FIELD_IP, "Set ResServer", " A.A.A.A IPv4 address", 15, 0, NULL },         
    { LIBNET_DHCP_HOSTNAME,        "hostname", "HostName", MAX_STRING_SIZE, FIELD_STR, "Set HostName", " WORD HostName", MAX_STRING_SIZE, 0, NULL },     
/*    { LIBNET_DHCP_BOOTFILESIZE,    "BOOTFILESIZE" },   
    { LIBNET_DHCP_DUMPFILE,        "DUMPFILE" },      */ 
    { LIBNET_DHCP_DOMAINNAME,      "domainname", "DomainName", MAX_STRING_SIZE, FIELD_STR, "Set DomainName", " WORD DomainName", MAX_STRING_SIZE, 0, NULL },     
/*    { LIBNET_DHCP_SWAPSERV,        "SWAPSERV" },       
    { LIBNET_DHCP_ROOTPATH,        "ROOTPATH" },       
    { LIBNET_DHCP_EXTENPATH,       "EXTENPATH" },      
    { LIBNET_DHCP_IPFORWARD,       "IPFORWARD" },      
    { LIBNET_DHCP_SRCROUTE,        "SRCROUTE" },       
    { LIBNET_DHCP_POLICYFILTER,    "POLICYFILTER" },   
    { LIBNET_DHCP_MAXASMSIZE,      "MAXASMSIZE" },     
    { LIBNET_DHCP_IPTTL,           "IPTTL" },          
    { LIBNET_DHCP_MTUTIMEOUT,      "MTUTIMEOUT" },     
    { LIBNET_DHCP_MTUTABLE,        "MTUTABLE" },       
    { LIBNET_DHCP_MTUSIZE,         "MTUSIZE" },        
    { LIBNET_DHCP_LOCALSUBNETS,    "LOCALSUBNETS" },   
    { LIBNET_DHCP_BROADCASTADDR,   "BROADCASTADDR" },  
    { LIBNET_DHCP_DOMASKDISCOV,    "DOMASKDISCOV" },   
    { LIBNET_DHCP_MASKSUPPLY,      "MASKSUPPLY" },     
    { LIBNET_DHCP_DOROUTEDISC,     "DOROUTEDISC" },    
    { LIBNET_DHCP_ROUTERSOLICIT,   "ROUTERSOLICIT" },  
    { LIBNET_DHCP_STATICROUTE,     "STATICROUTE" },    
    { LIBNET_DHCP_TRAILERENCAP,    "TRAILERENCAP" },   
    { LIBNET_DHCP_ARPTIMEOUT,      "ARPTIMEOUT" },     
    { LIBNET_DHCP_ETHERENCAP,      "ETHERENCAP" },    
    { LIBNET_DHCP_TCPTTL,          "TCPTTL" },        
    { LIBNET_DHCP_TCPKEEPALIVE,    "TCPKEEPALIVE" },  
    { LIBNET_DHCP_TCPALIVEGARBAGE, "TCPALIVEGARBAGE" },
    { LIBNET_DHCP_NISDOMAIN,       "NISDOMAIN" },      
    { LIBNET_DHCP_NISSERVERS,      "NISSERVERS" },    
    { LIBNET_DHCP_NISTIMESERV,     "NISTIMESERV" },   
    { LIBNET_DHCP_VENDSPECIFIC,    "VENDSPECIFIC" },  
    { LIBNET_DHCP_NBNS,            "NBNS" },          
    { LIBNET_DHCP_NBDD,            "NBDD" },          
    { LIBNET_DHCP_NBTCPIP,         "NBTCPIP" },       
    { LIBNET_DHCP_NBTCPSCOPE,      "NBTCPSCOPE" },    
    { LIBNET_DHCP_XFONT,           "XFONT" },         
    { LIBNET_DHCP_XDISPLAYMGR,     "XDISPLAYMGR" },   
    { LIBNET_DHCP_DISCOVERADDR,    "DISCOVERADDR" }, */ 
    { LIBNET_DHCP_LEASETIME,       "leasetime", "LeaseTime", 4, FIELD_HEX, "Set LeaseTime", " <0x00000000 - 0xFFFFFFFF", 8, 0, NULL },     
/*    { LIBNET_DHCP_OPTIONOVERLOAD,  "OPTIONOVERLOAD" },*/
    { LIBNET_DHCP_MESSAGETYPE,     "messagetype", "MessageType", 1, FIELD_HEX, "Set MessageType", " <0x00 - 0xFF>", 2, 1, dhcp_message },
    { LIBNET_DHCP_SERVIDENT,       "servident", "ServIdent", 4, FIELD_IP, "Set ServIdent", " A.A.A.A IPv4 address", 15, 0, NULL },         
/*    { LIBNET_DHCP_PARAMREQUEST,    "PARAMREQUEST" },  
    { LIBNET_DHCP_MESSAGE,         "MESSAGE" },       
    { LIBNET_DHCP_MAXMSGSIZE,      "MAXMSGSIZE" },*/    
    { LIBNET_DHCP_RENEWTIME,       "renewtime", "RenewTime", 4, FIELD_HEX, "Set RenewTime", " <0x00000000 - 0xFFFFFFFF", 8, 0, NULL },     
    { LIBNET_DHCP_REBINDTIME,      "rebindtime", "RebindTime", 4, FIELD_HEX, "Set RebindTime", " <0x00000000 - 0xFFFFFFFF", 8, 0, NULL },     
    { LIBNET_DHCP_CLASSSID,         "classsid", "ClassSID", MAX_STRING_SIZE, FIELD_STR, "Set ClassSID", " WORD ClassSID", MAX_STRING_SIZE, 0, NULL },     
/*    { LIBNET_DHCP_CLIENTID,        "CLIENTID" },      
    { LIBNET_DHCP_NISPLUSDOMAIN,   "NISPLUSDOMAIN" }, 
    { LIBNET_DHCP_NISPLUSSERVERS,  "NISPLUSSERVERS" }, 
    { LIBNET_DHCP_MOBILEIPAGENT,   "MOBILEIPAGENT" }, 
    { LIBNET_DHCP_SMTPSERVER,      "SMTPSERVER" },    
    { LIBNET_DHCP_POP3SERVER,      "POP3SERVER" },    
    { LIBNET_DHCP_NNTPSERVER,      "NNTPSERVER" },    
    { LIBNET_DHCP_WWWSERVER,       "WWWSERVER" },     
    { LIBNET_DHCP_FINGERSERVER,    "FINGERSERVER" },  
    { LIBNET_DHCP_IRCSERVER,       "IRCSERVER" },     
    { LIBNET_DHCP_STSERVER,        "STSERVER" },      
    { LIBNET_DHCP_STDASERVER,      "STDASERVER" },   */ 
    { LIBNET_DHCP_END,             "end", "End", 0, FIELD_HEX, "Set End", "", 0, 0, NULL }
};


void   dhcp_th_send_raw(void *);
void   dhcp_th_send_raw_exit(struct attacks *);
void   dhcp_th_send_discover(void *);
void   dhcp_th_send_discover_exit(struct attacks *);
void   dhcp_th_send_inform(void *);
void   dhcp_th_send_inform_exit(struct attacks *);
void   dhcp_th_send_offer(void *);
void   dhcp_th_send_offer_exit(struct attacks *);
void   dhcp_th_send_request(void *);
void   dhcp_th_send_request_exit(struct attacks *);
void   dhcp_th_send_decline(void *);
void   dhcp_th_send_decline_exit(struct attacks *);
void   dhcp_th_dos_send_discover(void *);
void   dhcp_th_dos_send_discover_exit(struct attacks *);
void   dhcp_th_rogue_server(void *);
void   dhcp_th_rogue_server_exit(struct attacks *);
void   dhcp_th_dos_send_release(void *);
void   dhcp_th_dos_send_release_exit(struct attacks *);


#define DHCP_ROGUE_SERVER     0
#define DHCP_ROGUE_START_IP   1 
#define DHCP_ROGUE_END_IP     2 
#define DHCP_ROGUE_LEASE      3
#define DHCP_ROGUE_RENEW      4
#define DHCP_ROGUE_SUBNET     5
#define DHCP_ROGUE_ROUTER     6
#define DHCP_ROGUE_DNS        7
#define DHCP_ROGUE_DOMAIN     8

static struct attack_param dhcp_rogue_server_params[] = {
    { NULL, "Server ID",               4, FIELD_IP,  15, NULL },
    { NULL, "Start IP",                4, FIELD_IP,  15, NULL },
    { NULL, "End IP",                  4, FIELD_IP,  15, NULL },
    { NULL, "Lease Time (secs)",       4, FIELD_HEX,  8, NULL },
    { NULL, "Renew Time (secs)",       4, FIELD_HEX,  8, NULL },
    { NULL, "Subnet Mask",             4, FIELD_IP,  15, NULL },
    { NULL, "Router",                  4, FIELD_IP,  15, NULL },
    { NULL, "DNS Server",              4, FIELD_IP,  15, NULL },
    { NULL, "Domain",                  15, FIELD_STR, 15, NULL }
};

#define DHCP_DOS_SEND_RELEASE_SERVER     0
#define DHCP_DOS_SEND_RELEASE_START_IP   1 
#define DHCP_DOS_SEND_RELEASE_END_IP     2 

static struct attack_param dhcp_dos_send_release_params[] = {
    { NULL, "Server ID",               4, FIELD_IP,  15, NULL },
    { NULL, "Start IP",                4, FIELD_IP,  15, NULL },
    { NULL, "End IP",                  4, FIELD_IP,  15, NULL }
};

#define DHCP_ATTACK_SEND_RAW           0
#define DHCP_ATTACK_DOS_SEND_DISCOVER  1
#define DHCP_ATTACK_ROGUE_SERVER       2
#define DHCP_ATTACK_DOS_SEND_RELEASE   3

static struct attack dhcp_attack[] = {
  { DHCP_ATTACK_SEND_RAW,          "sending RAW packet",        NONDOS, SINGLE,    dhcp_th_send_raw,      NULL, 0 },
/*  { DHCP_ATTACK_SEND_DISCOVER,     "sending DISCOVER packet",   NONDOS, dhcp_th_send_discover, NULL, 0 },*/
  { DHCP_ATTACK_DOS_SEND_DISCOVER, "sending DISCOVER packet",   DOS,    CONTINOUS, dhcp_th_dos_send_discover,NULL, 0 },
/*  { DHCP_ATTACK_SEND_OFFER,        "sending OFFER packet",      NONDOS, dhcp_th_send_offer,    NULL, 0 },
  { DHCP_ATTACK_SEND_REQUEST,      "sending REQUEST packet",    NONDOS, dhcp_th_send_request,  NULL, 0 },
  { DHCP_ATTACK_SEND_DECLINE,      "sending DECLINE packet",    NONDOS, dhcp_th_send_decline,  NULL, 0 },
  { DHCP_ATTACK_SEND_INFORM,       "sending INFORM packet",     NONDOS, dhcp_th_send_inform,   NULL, 0 },*/
  { DHCP_ATTACK_ROGUE_SERVER,      "creating DHCP rogue server",NONDOS, CONTINOUS, dhcp_th_rogue_server,  dhcp_rogue_server_params,
                                                SIZE_ARRAY(dhcp_rogue_server_params) },
  { DHCP_ATTACK_DOS_SEND_RELEASE,  "sending RELEASE packet",    DOS,    CONTINOUS, dhcp_th_dos_send_release, dhcp_dos_send_release_params,
                                                SIZE_ARRAY(dhcp_dos_send_release_params) },
  { 0,                   NULL,              0,      0,    NULL, NULL, 0     }
};


void   dhcp_register(void);
int8_t dhcp_send_discover(struct attacks *);
int8_t dhcp_send_inform(struct attacks *);
int8_t dhcp_send_offer(struct attacks *);
int8_t dhcp_send_request(struct attacks *);
int8_t dhcp_send_release(struct attacks *, u_int32_t, u_int32_t, u_int8_t *, u_int8_t *);
int8_t dhcp_send_decline(struct attacks *);
int8_t dhcp_send_packet(struct attacks *);
int8_t dhcp_learn_offer(struct attacks *);
int8_t dhcp_load_values(struct pcap_data *, void *);
char **dhcp_get_printable_packet(struct pcap_data *);
char **dhcp_get_printable_store(struct term_node *);
int8_t dhcp_update_field(int8_t, struct term_node *, void *);
char  *dhcp_get_type_info(u_int16_t);
int8_t dhcp_init_attribs(struct term_node *);
int8_t dhcp_edit_tlv(struct term_node *, u_int8_t, u_int8_t, u_int16_t, u_int8_t *);
int8_t dhcp_send_arp_request(struct attacks *, u_int32_t);
int8_t dhcp_learn_mac(struct attacks *, u_int32_t, u_int8_t *);
int8_t dhcp_init_comms_struct(struct term_node *);
int8_t dhcp_end(struct term_node *);

extern void   thread_libnet_error( char *, libnet_t *);
extern int8_t vrfy_bridge_id( char *, u_int8_t * );
extern int8_t parser_get_formated_inet_address(u_int32_t, char *, u_int16_t);
extern int8_t parser_get_formated_inet_address_fill(u_int32_t, char *, u_int16_t, int8_t);
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
