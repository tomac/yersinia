/* parser.c
 * Main command line parser and parser utilities
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
"$Id: parser.c 46 2007-05-08 09:13:30Z slay $";
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
#include <netdb.h>

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

#include <limits.h>

#include <ctype.h>

#include "parser.h"

static u_int8_t valid_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";


/*
 * Initial command line arguments parser.
 * Return -1 on error. Return 0 if Ok.
 * Use global protocol_defs
 */
int8_t
parser_initial(struct term_tty *tty, struct cl_args *cl_args, int argc, char **argv)
{
    int8_t i;

    for (i=1; i<(argc); i++)
    {    
       if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help"))
       {
          parser_help();
          break;
       }
       else
       if (!strcmp(argv[i],"-V") || !strcmp(argv[i],"--Version"))
       {  
          printf("%s %s\n", PACKAGE, VERSION );
          return -1;
       }
       else
       if (!strcmp(argv[i],"-I") || !strcmp(argv[i],"--Interactive"))
       { 
#ifdef HAS_CURSES
          tty->interactive = 1;
#else
          printf("   Hmmm... it seems that you don't have ncurses support or Yersinia\n");
          printf("   has been configured with --disable-ncurses option...\n");
          printf("   Go and get it!!\n\n");
          return -1;
#endif
       }
       else
       if (!strcmp(argv[i],"-G") || !strcmp(argv[i],"--gtk"))
       { 
#ifdef HAVE_GTK
          tty->gtk = 1;
#else
          printf("   Hmmm... it seems that you don't have gtk support or Yersinia\n");
          printf("   has been configured with --disable-gtk option...\n");
          printf("   Go and get it!!\n\n");
          return -1;
#endif
       }
       else
       if (!strcmp(argv[i],"-D") || !strcmp(argv[i],"--Daemon"))
       {
#ifdef HAVE_REMOTE_ADMIN
          tty->daemonize = 1;
#else
          printf("   Hmmm... it seems that Yersinia has been configured with\n");
          printf("   the --disable-admin option...\n");
          printf("   Go and get it!!\n\n");
          return -1;
#endif
       }
       else
       if (!strcmp(argv[i],"-d") || !strcmp(argv[i],"--debug"))
       {
          tty->debug = 1;
       }
       else
       if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--conffile"))
       {
           i++;
           strncpy(tty->config_file, argv[i], sizeof(tty->config_file));
       }
       else
       if (!strcmp(argv[i],"-l") || !strcmp(argv[i],"--logfile")) 
       {
           i++;
           if ((tty->log_file = fopen(argv[i], "a+")) == NULL) 
           {
               printf("%s: Error opening logfile %s\n", argv[0], argv[i]);
               /* If the logfile cannot be opened, the default is yersinia.log */
               if ((tty->log_file = fopen("yersinia.log", "a+")) == NULL) 
               {
                   printf("%s: Error opening logfile 'yersinia.log'\n", argv[0]);
                   return -1;
               }
           }
       }
       else
       if (argv[i][0] != '-')/* Ok, it is a protocol...*/
       {   /* Nonexistant protocol (or not visible)...*/
           if (((cl_args->proto_index = protocol_proto2index(argv[i])) < 0)) 
           {
              printf("%s: Unknown protocol %s!!\n", argv[0], argv[i]);
              return -1;
           }
           cl_args->count = argc-i;
           cl_args->argv_tmp = &argv[i];
           break;
       }
       else
       {
           printf("%s: Unknown option %s!!\n", argv[0], argv[i]);
           return -1;
       } 
    } /* for...*/
    
    if (!tty->log_file) {
        if ((tty->log_file = fopen("yersinia.log", "a+")) == NULL) {
            printf("%s: Error opening logfile 'yersinia.log'\n", argv[0]);
            return -1;
        }
    }

    setvbuf(tty->log_file, NULL, _IONBF, 0);

    return 0;
}


/*
 * Look if *number* of the characters
 * are digits.
 * Return -1 on error. Return 0 if Ok.
 */
int8_t 
parser_are_digits( int8_t *charac, int8_t number )
{
    while (number > 0)
    {
        if ( !isdigit((int)*charac) )
            return -1;
        charac++;
        number--;
    }
    return 0;
}


/*
 * Convert a string to lowercase
 * Return nothing.
 */
void
parser_str_tolower( char *charac )
{
    while (*charac)
    {
        *charac = (char)tolower((int)*charac);
        charac++;
    }
}


/*
 * Verify a MAC address...
 * Return -1 if error
 */
int8_t
parser_vrfy_mac( char *address, u_int8_t *destination )
{
    char *substr, *aux;
    u_int8_t data[]={0,0,0};
    u_int16_t i=0, j;

    substr = address;
	/* trim left spaces (can exist in the configuration file) */
/*	while (*substr == ' ')
		substr++;*/

	aux = substr;

    while ( (substr = strchr(substr, ':') ))
    {
        if (substr == aux)
            return -1;

        if ( (substr-aux) > (sizeof(data)-1))
            return -1; /* Overflowed? */

        for(j=0; j<(substr-aux);j++)
        {   
            if ( !isxdigit((int)(*(aux+j))) )
                return -1;
            data[j]=*(aux+j);
        }
        data[j]=0;
        if ( strtol((char *)data, (char **)NULL, 16) > 255 || 
                strtol((char *)data, (char **)NULL, 16) < 0 )
            return -1;
        destination[i]=strtol((char *)data, (char **)NULL, 16);
        i++;
        if (i==6)
            return -1;
        substr++;
        aux=substr;
    }

    if (!*aux || (i<5) )
        return -1;

    for(j=0; *aux && !isspace(*aux); j++,aux++)
    {   
        if ( !isxdigit((int)(*aux)) )
            return -1;
        data[j]=*aux;
    }

    data[j]=0;
    if ( strtol((char *)data, (char **)NULL, 16) > 255 || 
            strtol((char *)data, (char **)NULL, 16) < 0 )
        return -1;

    destination[i] = strtol((char *)data, (char **)NULL, 16);

    return 0;
}


/*
 * Verify a bridge id
 * Return 1 if error 
 */
int8_t
parser_vrfy_bridge_id( char *address, u_int8_t *destination )
{
    char *substr, *aux;
    u_int8_t data[]={0,0,0};
    u_int16_t i, j, k=0;

    aux = substr = address;

    for (i=0; i<2; i++)
    {
        for(j=0; j<2;j++)
        {   
            if ( !isxdigit((int)(*(aux+j))) )
                return -1;
            data[j]=*(aux+j);
        }
        data[j]=0;
        if ( strtol((char *)data, (char **)NULL, 16) > 255 || 
                strtol((char *)data, (char **)NULL, 16) < 0 )
            return -1;
        destination[k]=strtol((char *)data, (char **)NULL, 16);
        k++;
        aux+= 2*sizeof(u_char);
    }

    if (*aux != '.')
        return -1;

	aux++;

    for (i=0; i<6; i++)
    {
        for(j=0; j<2;j++)
        {   
            if ( !isxdigit((int)(*(aux+j))) )
                return -1;
            data[j]=*(aux+j);
        }
        data[j]=0;
        if ( strtol((char *)data, (char **)NULL, 16) > 255 || 
                strtol((char *)data, (char **)NULL, 16) < 0 )
            return -1;
        destination[k]=strtol((char *)data, (char **)NULL, 16);
        k++;
        aux+= 2*sizeof(u_char);
    }

    return 0;
}


/*
 * Help function. What do you want to do today?
 */
void
parser_help(void)
{
    u_int8_t i, first=1;
    
    printf("%s\n", bin_data);
    printf("\nUsage: %s [-hVGIDd] [-l logfile] [-c conffile] protocol [protocol_options]\n", PACKAGE);
    printf("       -V   Program version.\n");
    printf("       -h   This help screen.\n");
    printf("       -G   Graphical mode (GTK).\n");
    printf("       -I   Interactive mode (ncurses).\n");
    printf("       -D   Daemon mode.\n");
    printf("       -d   Debug.\n");
    printf("       -l logfile   Select logfile.\n");
    printf("       -c conffile  Select config file.\n");
    printf("  protocol   One of the following:"); 
    
    for(i=0; i< MAX_PROTOCOLS; i++)
    {
       if (protocols[i].visible)
       {
          if (first)
          {
             printf(" %s",protocols[i].name_comm);
             first = 0;
          }
          else
             printf(", %s", protocols[i].name_comm);
       }
    }
    printf(".\n\nTry '%s protocol -h' to see protocol_options help\n\n", PACKAGE);
    printf("Please, see the man page for a full list of options and many examples.\n");
    printf("Send your bugs & suggestions to the Yersinia developers <yersinia@yersinia.net>\n\n");  
}


/*
 *
 */
int8_t
parser_command2index(register const struct attack *lp, register int8_t v)
{
    int i=0;

    while (lp->s != NULL) 
    {
        if (lp->v == v)
            return (i);
        ++lp;
        ++i;
    }
    return (i);
}


int8_t
parser_get_formated_inet_address(u_int32_t in, char *inet, u_int16_t inet_len)
{
    char *p;
    u_int32_t aux_long;

    aux_long = htonl(in);
    p = (char *)&aux_long;
        if (snprintf(inet, inet_len,"%03d.%03d.%03d.%03d",
            (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255)) < 0)
        return -1;
    return 0;
}

int8_t
parser_get_formated_inet_address_fill(u_int32_t in, char *inet, u_int16_t inet_len, int8_t fill_up)
{
    char *p;
    u_int32_t aux_long;

    aux_long = htonl(in);
    p = (char *)&aux_long;
    if (fill_up)
    {
        if (snprintf(inet, inet_len,"%03d.%03d.%03d.%03d",
            (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255)) < 0)
        return -1;
    }
    else
    {
        if (snprintf(inet, inet_len,"%d.%d.%d.%d",
            (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255)) < 0)
        return -1;
    }
    
    return 0;
}


int8_t
parser_get_inet_aton(char *inet, struct in_addr *in)
{
    char *stripped_ip, *tmp, dots=0;
    char st[4];
    char *save_pointer;
    u_int8_t i, j;

    if ( (strlen(inet) < 7) || (strlen(inet)>15) )
       return -1;
       
    if ( (inet[0] == '.') || (inet[strlen(inet)-1] == '.') ||
          (!isdigit(inet[0])) || (!isdigit(inet[strlen(inet)-1])) )
       return -1;
    
    for (i=1; i< (strlen(inet)-1); i++)
    {
       if (inet[i] == '.')
       {
          dots++;
          if (inet[i+1] == '.')
             return -1;
       }
       else
       {
          if (!isdigit(inet[i]))
             return -1;
       }
    }

    if (dots!=3)
       return -1;

    if ((stripped_ip = calloc(1, 16)) == NULL) {
        write_log(0, "Error in calloc");
        return -1;
    }

    memcpy((void *)stripped_ip, (void *)inet, strlen(inet));

    j = 0;

    tmp = strtok_r(stripped_ip, ".", &save_pointer);

    for (i=0; i < 4; i++) {
        if (tmp) {
            snprintf(st, 4, "%d", atoi(tmp));
            memcpy((void *)(stripped_ip + j), (void *)st, strlen(st));
            
            j += strlen(st);

            if (i < 3) {
                stripped_ip[j] = '.';
                j++;
            } else
                stripped_ip[j] = '\0';
            tmp = strtok_r(NULL, ".", &save_pointer);
        }
    }

    if (inet_aton(stripped_ip, in) <= 0) {
        free(stripped_ip);
        write_log(0, "Error in inet_aton\n");
        return -1;
    }

    free(stripped_ip);

    return 0;
}


int8_t
parser_get_random_string(u_int8_t *string, u_int8_t len)
{
    u_int8_t total, j;
    struct timeval tv;
#ifdef HAVE_RAND_R
    u_int32_t i;
#endif

    total = 0;

    if (!string)
        return -1;

    while (total < len-1) {
	if (gettimeofday(&tv, NULL) < 0) {
		thread_error("Error in gettimeofday", errno);
		return -1;
	}

#ifdef HAVE_RAND_R
       i = (u_int32_t)tv.tv_usec;
       j = rand_r(&i);
#else
       if (pthread_mutex_lock(&terms->mutex_rand) != 0)
       {
           thread_error("get_random_string pthread_mutex_lock()",errno);
           return -1;
       }

       j=rand();

       if (pthread_mutex_unlock(&terms->mutex_rand) != 0)
       {
           thread_error("get_random_string pthread_mutex_unlock()",errno);
           return -1;
       }
#endif
       j = j % (sizeof(valid_chars) - 1);
       string[total] = valid_chars[j];
       total++;
   }
    string[len-1] = '\0';

    return 0;
}


int8_t
parser_get_random_int(u_int8_t max)
{
    u_int8_t j;
    struct timeval tv;
#ifdef HAVE_RAND_R
    u_int32_t i; 
#endif

    if (gettimeofday(&tv, NULL) < 0) {
        thread_error("Error in gettimeofday", errno);
        return -1;
    }

#ifdef HAVE_RAND_R
    i = (u_int32_t)tv.tv_usec;
    j = rand_r(&i);
#else
    if (pthread_mutex_lock(&terms->mutex_rand) != 0)
    {
       thread_error("get_random_int pthread_mutex_lock()",errno);
       return -1;
    }

    j=rand();

    if (pthread_mutex_unlock(&terms->mutex_rand) != 0)
    {
       thread_error("get_random_int pthread_mutex_unlock()",errno);
       return -1;
    }
#endif
    j = j % max;

    return j;
}


int8_t
parser_read_config_file(struct term_tty *tty, struct term_node *node)
{
   FILE *file;
   char buffer[BUFSIZ], *ptr, *ptr2;
   u_int8_t state, i;
   int16_t proto, field;
   struct commands_param *params;

   params = NULL;
   state = 0;
   proto = -1;
   field = -1;

   if ((file = fopen(tty->config_file, "r")) == NULL) {
      write_log(1, "Error opening configuration file %s\n", tty->config_file);
      return -1;
   }

   while(fgets(buffer, BUFSIZ,file) != NULL)
   {
      /* trim any initial space */
      ptr = buffer;
      while((*ptr == ' ') || (*ptr == '\t'))
         ptr++;

      if ((*ptr == '\n') || (*ptr == '#')) /* Move to the next line */
         continue;

      switch(state)
      {
         case 0:
            /* State 0. Tokens allowed: global, protocol */
            if (strncmp(ptr, "<global>", 8) == 0)
            {
               /* Global options */
               proto = 666;
               state = 1;
            }
            else 
               if (strncmp(ptr, "<protocol", 9) == 0)
               {
                  /* Protocol options */
                  proto = -1;
                  for (i = 0; i < MAX_PROTOCOLS; i++)
                  {
                     if (protocols[i].visible)
                        if (strncasecmp(protocols[i].namep, 
                                 (ptr + 10), 
                                 strlen(protocols[i].namep)) == 0)
                        {
                           proto = protocols[i].proto;
                           params = (struct commands_param *) protocols[proto].parameters;
                        }

                  }
                  if (proto < 0) 
                  {
                     write_log(1, "Error when parsing file %s, there is no %s protocol (or not visible)!!\n", tty->config_file, (ptr + 10));
                     return -1;
                  }
                  state = 2;
               }
            break;
         case 1:
            /* State 1: global options */
            if (strncmp(ptr, "</global>", 9) == 0) {
               state = 0;
               continue;
            }

            if (strncmp(ptr, "mac_spoofing", 12) == 0)
            {
               ptr += strlen("mac_spoofing");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               tty->mac_spoofing = atoi(ptr + 1);
            }
            else if (strncmp(ptr, "splash", 6) == 0)
            {
               ptr += strlen("splash");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               tty->splash = atoi(ptr + 1);
            }
            else if (strncmp(ptr, "port", 4) == 0)
            {
               ptr += strlen("port");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               tty->port = atoi(ptr + 1);
            }
            else if (strncmp(ptr, "username", 8) == 0)
            {
               ptr += strlen("username");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               ptr++;

               /* Trim all the spaces */
               while(*ptr == ' ')
                  ptr++;

               /* Trim the \n */
               ptr2 = ptr;
               while (*ptr2 != '\0')
                  if (*ptr2 == '\n')
                     *ptr2 = '\0';
                  else
                     ptr2++;

               strncpy(tty->username, ptr, MAX_USERNAME);
            }
            else if (strncmp(ptr, "password", 8) == 0)
            {
               ptr += strlen("password");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               ptr++;
               /* Trim all the spaces */
               while(*ptr == ' ')
                  ptr++;

               /* Trim the \n */
               ptr2 = ptr;
               while (*ptr2 != '\0')
                  if (*ptr2 == '\n')
                     *ptr2 = '\0';
                  else
                     ptr2++;

               strncpy(tty->password, (ptr), MAX_PASSWORD);
            }
            else if (strncmp(ptr, "enable", 6) == 0)
            {
               ptr += strlen("enable");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               ptr++;
               /* Trim all the spaces */
               while(*ptr == ' ')
                  ptr++;

               /* Trim the \n */
               ptr2 = ptr;
               while (*ptr2 != '\0')
                  if (*ptr2 == '\n')
                     *ptr2 = '\0';
                  else
                     ptr2++;

               strncpy(tty->e_password, (ptr), MAX_PASSWORD);
            }
            else if (strncmp(ptr, "hosts", 5) == 0)
            {
               u_int8_t gotit=0;
               ptr += strlen("hosts");
               if ((ptr = strchr(ptr, '=')) == NULL) {
                  write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                  return -1;
               }

               ptr++;
               while(!gotit)
               {
                  /* Trim all the spaces */
                  while((*ptr == ' ')||(*ptr == '\t'))
                     ptr++;

                  ptr2 = ptr;
                  while ((*ptr != '\0') && (*ptr != ' ') && (*ptr != '\t'))
                  {
                     if (*ptr == '\n')
                     {
                        *ptr = '\0';
                        gotit=1;
                     }
                     else
                        ptr++;
                  }
                  if ((*ptr == ' ') || (*ptr == '\t'))
                  {
                     *ptr = '\0';
                     ptr++;
                  }
                  if (ptr != ptr2)
                     if (parser_vrfy_ip2filter(ptr2,tty) < 0 )
                     {
                        write_log(1,"Parse error: error parsing IP address '%s'\n",ptr2);
                        parser_free_ip2filter(tty->ip_filter);
                        return -1;
                     }
               }
            }
            else 
            {
               write_log(1, "Parse error: %s is not a global option\n", ptr);
               return -1;
            }
            break;

         case 2:
            /* State 2: protocol options */
            if (strncmp(ptr, "</protocol>", 11) == 0) {
               state = 0;
               continue;
            }

            /* Now find any possible field */
            i = 0;
            while(i < protocols[proto].nparams)
            {
               if (strncasecmp(params[i].ldesc, ptr, strlen(params[i].ldesc)) == 0)
               {
                  ptr += strlen(params[i].ldesc);
                  if ((ptr = strchr(ptr, '=')) == NULL) {
                     write_log(1, "Parse error: missing '=' (%s)\n", buffer);
                     return -1;
                  }
                  ptr++;
                  /* Trim all the spaces */
                  while(*ptr == ' ')
                     ptr++;

                  /* For the hex: if exists 0x, then delete! */
                  if ((*ptr == '0') && (*(ptr+1) == 'x'))
                  {
                     ptr++;
                     ptr++;
                  }

                  /* Trim the \n */
                  if (ptr[strlen(ptr) - 1] == '\n')
                     ptr[strlen(ptr) - 1] = '\0';
                  write_log(0, "tengo %s, %d, %s, %d\n", params[i].ldesc, params[i].type, ptr, params[i].size_print);
                  if ((strlen(ptr)) && 
                      (parser_filter_param(params[i].type, node->protocol[proto].commands_param[i], ptr, 
                                           params[i].size_print,params[i].size) < 0))
                  {
                     write_log(0, "Error when parsing %s: %s\n", params[i].ldesc, ptr);
                     return -1;
                  }

                  /* jump out */
                  break;
               }
               i++;
            }

            /* No success */
            if (i == protocols[proto].nparams) {
               write_log(1, "Parse error: there is no %s field in %s protocol\n", ptr, protocols[proto].namep);
               return -1;
            }
            break;
      }
   }

   if (fclose(file) != 0) {
      write_log(1, "Error closing configuration file %s\n", tty->config_file);
      return -1;
   }

   return 0;
}


int8_t
parser_write_config_file(struct term_tty *tty)
{
   FILE *file;
   u_int8_t i, j, k;
   char **values;
   char temp[6];
   struct filter *cursor;
   struct commands_param *params;

   if ((file = fopen(tty->config_file, "w+")) == NULL) {
      write_log(0, "Error opening configuration file %s\n", tty->config_file);
      return -1;
   }

   fputs("# $Id: parser.c 46 2007-05-08 09:13:30Z slay $\n", file);
   fputs("#\n", file);
   fputs("# Yersinia configuration file example\n", file);
   fputs("#\n", file);
   fputs("# Please read the README and the man page before complaining\n", file);
   fputs("\n", file);

   fputs("# Global options\n", file);
   fputs("<global>\n", file);
   fputs("# MAC Spoofing\n", file);

   fputs("mac_spoofing = 1\n", file);
   fputs("# Active interfaces\n", file);
   fputs("#interfaces = eth0, eth1\n", file);

   fputs("# Hosts allowed to connect to the network daemon\n", file);
   fputs("# Examples: www.microsoft.com 192.168.1.0/24 10.31-128.*.13 100.200.*.* 2-20.*.*.10-11\n",file);
   cursor = tty->ip_filter;
   if (!cursor)
      fputs("hosts = localhost", file);
   else
      fputs("hosts =", file);
   while(cursor)
   {
      fputs(" ",file);
      fputs(cursor->expression,file);
      cursor = cursor->next;
   }
   fputs("\n",file);
   fputs("# Propaganda. It's cool, so please, don't disable it!! :-P\n", file);
   fputs("splash = 1\n", file);
   fputs("# Username for the admin mode\n", file);
   fputs("username = ", file);
   fputs(tty->username, file);
   fputs("\n", file);
   fputs("# Password for the admin mode\n", file);
   fputs("password = ", file);
   fputs(tty->password, file);
   fputs("\n", file);
   fputs("# Enable password for the admin mode\n", file);
   fputs("enable = ", file);
   fputs(tty->e_password, file);
   fputs("\n", file);
   fputs("# Daemon port\n", file);
   fputs("port = ", file);
   snprintf(temp, 6, "%hd", tty->port);
   fputs(temp, file);
   fputs("\n", file);

   fputs("</global>\n\n", file);

   for (i = 0; i < MAX_PROTOCOLS; i++)
   {
      if (!protocols[i].visible)
         continue;

      params = (struct commands_param *) protocols[i].parameters;
      fputs("<protocol ", file);
      fputs(protocols[i].namep, file);
      fputs(">\n", file);

      if (protocols[i].get_printable_store == NULL) {
         write_log(0, "printable_store in protocol %d is NULL\n", i);
      }

      if (protocols[i].get_printable_store) {
         if ((values = (*protocols[i].get_printable_store)(NULL)) == NULL) {
            write_log(0, "Error in get_printable_store\n");
            return -1;
         }

         k = 0;
         for (j = 0; j < protocols[i].nparams; j++)
         {
            if ((params[j].type != FIELD_DEFAULT) && (params[j].type != FIELD_IFACE) && (params[j].type != FIELD_EXTRA))
            {
               fputs(params[j].ldesc, file);
               fputs(" = ", file);
               switch(params[j].type)
               {
                  case FIELD_HEX:
                     fputs("0x", file);
                     break;
                  default:
                     break;
               }

               fputs(values[k], file);
               fputs("\n", file);
               k++;
            }
         }
         fputs("</protocol>\n\n", file);

         j = 0;
         if (values)
            while(values[j]) {
               free(values[j]);
               j++;
            }

         free(values);
      } else
         fputs("</protocol>\n\n", file);
   }

   if (fclose(file) != 0) {
      write_log(1, "Error closing configuration file %s\n", tty->config_file);
      return -1;
   }

   return 0;
}


/* ============================================ */
/* Mask and convert digit to hex representation */
/* Output range is 0..9 and a..f only           */
int hexify(unsigned int value)
{
   int result;

   result = (value & 0x0f) + '0';
   if (result > '9')
      result = result + ('a' - '0' - 10);
   return result;

} /* hexify */

/* ========================================= */
/* convert number to string in various bases */
/* 2 <= base <= 16, controlled by hexify()   */
/* Output string has ls digit first.         */
void parser_basedisplay(u_int8_t number, u_int8_t base,
                 char * string, size_t maxlgh)
{
   /* assert (string[maxlgh]) is valid storage */
   if (!maxlgh) {
      *string = '\0';
      return;
   }
   else {
      *string = hexify(number % base);
      if (!number) *string = '\0';
      else {
         parser_basedisplay(number / base, base, &string[1], maxlgh - 1);
      }
   }

} /* basedisplay */

/* ======================= */
/* reverse string in place */
void revstring(char * string)
{
   char * last, temp;

   last = string + strlen(string); /* points to '\0' */
   while (last-- > string) {
      temp = *string; *string++ = *last; *last = temp;
   }

} /* revstring */ 

/*
 * Verify an expression in order to add it to
 * the linked list of ip filters
 * All data will be stored in Host Byte Order
 * Expressions allowed are:
 * 1- CIDR notation: 10.20.30.0/24
 * 2- Wildcard use: 10.20.30.*
 * 3- Range use: 10.20.30.0-255
 * 4- Range with wildcard: 10.20.20-30.*
 * 5- IP as usual: 10.20.30.40
 * 6- Hostname: www.bloblob.xx
 *
 * Return 0 on success. -1 on error
 */
int8_t
parser_vrfy_ip2filter(char *expr, struct term_tty *tty)
{
   union bla { u_int32_t all;
               u_int8_t byte[4];
   };
   union bla numbegin, numend;  
   char *expr2, *str[4], *ip, *aux, *aux2;
   u_int8_t bits, dots, name, wildcard;
   u_int32_t auxl, beginl, endl,i;
   
   numbegin.all = 0;
   numend.all = 0;
   
   expr2 = strdup(expr);
   if (expr2 == NULL)
   {
      write_log(1,"strdup error!!\n");
      return -1;
   }
   
   ip = expr2;
   aux = strchr(ip, '/');

   if (aux == NULL) /* No CIDR expression */
   {
      /* How many dots? */
      dots = 0;
      aux2 = ip;
      name = wildcard = 0;
      for (i=1; i< (strlen(aux2)-1); i++)
      {
         if (aux2[i] == '.')
         {
            dots++;
            if (aux2[i+1] == '.')
            {
               free(expr2);
               return -1;
            }
         }
         else
         {
            if (!isdigit(aux2[i]))
            {
               if ((aux2[i]=='*') || (aux2[i]=='-'))
                  wildcard = 1;
               else
               {
                  name=1;
                  break;
               }
            }
         }
      }
      
      if (name || (!name && !wildcard)) /* We have a name or a IP address */
      {
         struct hostent *namehost;
         namehost = gethostbyname(aux2);
         if (namehost == NULL)
         {
            write_log(1,"Parse error: Unable to resolve '%s'!! Anyway we'll go on with the rest of the addresses...\n",aux2);         
            free(expr2);
            return 0;
         }
         memcpy((char *)&auxl, namehost->h_addr_list[0], sizeof(struct in_addr));
         auxl = ntohl(auxl);
         beginl = endl = auxl;
      }
      else /* We have an expression with '*' or '-'*/
      {
         char *aux3=NULL, *aux4=NULL;
         if (dots!=3)
         { 
            free(expr2);
            return -1;
         }

         for(i=0; i< 4; i++)
         {
            aux3 = strchr(aux2,'.');
            if (aux3!=NULL)
              *aux3 = '\0';
            str[i] = aux2;
            if ( (strchr(str[i],'*') != NULL) && (strchr(str[i],'-') != NULL) )
            { 
               free(expr2);
               return -1;
            }
            if ( (aux4 = strchr(str[i],'*')) == NULL)
            {
               if ( (aux4 = strchr(str[i],'-')) == NULL)
               {
                  if (strlen(str[i]) > 3)
                  {
                     free(expr2);
                     return -1;
                  }
                  numbegin.byte[i] = atoi(str[i]);
                  numend.byte[i] = numbegin.byte[i];
               }
               else /* We have '-' token... */
               {
                  char *aux5=NULL;
                  if ( strlen(str[i]) > 7)
                  {
                     free(expr2);
                     return -1;
                  }
                  aux5 = str[i];
                  if (aux5 == aux4) /* Value = '-xxx' or '-' */
                  {
                     numbegin.byte[i] = 0;
                     if (strlen(aux5) == 1)
                        numend.byte[i] = 255;
                     else
                     {
                        aux4++;
                        numend.byte[i]=atoi(aux4);
                     }
                  }
                  else /* Value = 'x-' or 'x-x' */
                  {
                     if ( *(aux5+strlen(str[i])-1) == '-') /* Case 'x-' */
                     {
                        *aux4 = '\0';
                        numbegin.byte[i] = atoi(aux5);
                        numend.byte[i] = 255;
                     }
                     else /* Case 'x-x' */
                     {
                        *aux4 = '\0'; aux4++;
                        numbegin.byte[i] = atoi(aux5);
                        numend.byte[i] = atoi(aux4);
                     }
                  }
               }
            }
            else /* We have '*' token */
            {
               if (strlen(str[i]) > 1)
               {
                  free(expr2);
                  return -1;
               }
               numbegin.byte[i] = 0;
               numend.byte[i] = 255;
            }
            aux2 = ++aux3;
         } /* for...*/

         for(i=0;i<4;i++)
         {
            if (numbegin.byte[i] > numend.byte[i])
            {
               free(expr2);
               return -1;
            }
         }
         beginl = ntohl(numbegin.all);
         endl   = ntohl(numend.all);  
      }
   }
   else /* We have a CIDR expression */
   {
      *aux = '\0';
      aux++;
      if ((aux=='\0') || (strlen(aux)>2))
      {
         free(expr2);
         return -1;
      }
      bits = atoi(aux);
      if (bits>32)
      {
         free(expr2);
         return -1;
      }

      if (!inet_aton(ip, (struct in_addr *)&auxl))
      {
         free(expr2);
         return -1;
      }
      auxl   = ntohl(auxl);
      beginl = auxl & (unsigned long) (0 - (1<<(32 - bits)));
      endl   = auxl | (unsigned long) ((1<<(32 - bits)) - 1);
   }

/*   write_log(1,"IP Begin = %08X %s\n",beginl,inet_ntoa( (*((struct in_addr *)&beginl))   )  );
   write_log(1,"IP End   = %08X %s\n",endl,inet_ntoa( (*((struct in_addr *)&endl))   )  );
*/
   free(expr2);
   
   if (beginl > endl)
      return -1;
   
   if (parser_add_ip2filter(beginl,endl,tty,expr) < 0)
      return -1;
   
   return 0;
}

/*
 * Add an IPv4 range to the linked list of ip ranges
 * All data will be stored in Host Byte Order
 *
 * Return 0 on success. -1 on error
 */
int8_t
parser_add_ip2filter(u_int32_t begin, u_int32_t end, struct term_tty *tty, char *expr)
{
   struct filter *new, *cursor=NULL, *last=NULL;
   char *expr2=NULL;

   new = (struct filter *)calloc(1,sizeof(struct filter));
   if (new == NULL)
      return -1;
   
   if ( (expr2=strdup(expr)) == NULL)
   {
      free(new);
      return -1;
   }
   
   new->expression = expr2;
   new->begin = begin;
   new->end = end;
   new->next = NULL;
   
   if (!tty->ip_filter)
   {
      tty->ip_filter = new;
      return 0;
   }

   cursor = tty->ip_filter;
   
   while(cursor)
   {
      last = cursor;
      cursor = cursor->next;
   }

   last->next = new;
 
   return 0;
}

void 
parser_free_ip2filter(struct filter *ipfilter)
{
   struct filter *cursor, *aux;
   cursor = ipfilter;

   while(cursor)
   {
      aux = cursor->next;
      free(cursor->expression);
      free(cursor);
      cursor = aux;
   }
}


/*
 * Filter 1 parameter
 * Return -1 on error.
 * Return 0 on success.
 */
int8_t 
parser_filter_param(u_int8_t type, void *value, char *printable, 
                    u_int16_t size_print, u_int16_t size)
{
   u_int8_t i, *bytes, j;
   char tmp[3];
   char *temp;
//   int8_t iface;
   u_int16_t end, len, len2;
   u_int32_t aux_ip;
   struct in_addr addr;

//write_log(0, "tipe es %d, value %s, printable %s, size %d\n", type, value, printable, size_print);
   if (type == FIELD_TLV)
      return 0;

   if (!printable || !value || !strlen(printable) || (strlen(printable) > size_print) )
      return -1;

   switch(type)
   {
      case FIELD_BRIDGEID:
         if (strlen(printable) != 17)
            return -1;
         if (parser_vrfy_bridge_id(printable,(u_int8_t *)value))
            return -1;
         break;

      case FIELD_MAC:
         if (parser_vrfy_mac(printable,(u_int8_t *)value))
            return -1;
         break;

      case FIELD_HEX:
      case FIELD_DEC:
         end = strlen(printable);
         for(i=0; i<end; i++)
         {
            if ( (type == FIELD_HEX) &&
                  !isxdigit(printable[i]) )
               return -1;
            if ( (type == FIELD_DEC) &&
                  !isdigit(printable[i]) )
               return -1;
         }
         if (type == FIELD_HEX)
         {
            switch(size_print)
            {
               case 2:
                  *((u_int8_t *)(value)) = strtoul(printable, (char **)NULL, 16);
                  break;
               case 4:
                  *((u_int16_t *)(value)) = strtoul(printable, (char **)NULL, 16);
                  break;
               default:
                  *((u_int32_t *)(value)) = strtoul(printable, (char **)NULL, 16);
                  break;
            }
         }
         else
         {
            if (size==1)
            {
               *((u_int8_t *)(value)) = strtoul(printable, (char **)NULL, 10);
            }
            else
               if (size==2)
               {
                  *((u_int16_t *)(value)) = strtoul(printable, (char **)NULL, 10);
               }
               else
               {
                  *((u_int32_t *)(value)) = strtoul(printable, (char **)NULL, 10);
               }
         }
         break;

      case FIELD_IP:
         if (parser_get_inet_aton(printable, &addr) < 0) 
            return -1; 
         /* EVERYTHING is stored in host address format */
         aux_ip = ntohl(addr.s_addr);
         memcpy(value, (void *)&aux_ip, 4);
         break;

      case FIELD_STR:
         /* First remove everything */
         memset((void *)value, 0, strlen(value));

         end = strlen(printable);
         if (end > 0)
         {
           for(i=0; i<end; i++)
           {
              if ( !isascii(printable[i]) )
                 return -1;
           }
         }
         memcpy((void *)value, (void *)printable, end);
         break;

      case FIELD_IFACE:
         end = strlen(printable);
         for(i=0; i<end; i++)
         {
            if ( !isascii(printable[i]) )
               return -1;
         }
/*         iface = interfaces_get(printable);
         if (iface < 0)
            return -1;
         memcpy((void *)value, (void *)&iface, 1);
*/
         memset((void *)value, 0, strlen(value));
         memcpy((void *)value, (void *)printable, end);
         break;

      case FIELD_BYTES:
         len = strlen(printable);
         len2 = ((len % 2) ? len/2 + 1 : len/2);
         bytes = (u_int8_t *)calloc(1, len2);
         if (bytes == NULL)
         {
            thread_error("parser_filter_param calloc",errno);
            return -1;
         }
         temp = printable;
         for (j=0; j < len/2; j++) 
         {
            memcpy((void *)tmp, (void *)temp, 2);
            tmp[2] = '\0';
            bytes[j] = strtol(tmp, NULL, 16);
            temp+=2;
         }
         if (len % 2)
            bytes[j+1] = strtol(temp, NULL, 16);

         memcpy((void *)value, (void *)bytes, len2);

         free(bytes);
         break;
   }

   return 0;
}


/*
 * Command line help for all protocols
 */
void
parser_cl_proto_help(u_int8_t proto, struct term_node *node)
{
    u_int8_t i;
    struct commands_param *comm_par = protocols[proto].parameters;
    
    write_log(2,"%s\n", bin_data);
    write_log(2,"\nUsage: %s %s [-h -M] [-attack id] ", PACKAGE,protocols[proto].name_comm);
    for(i=0; i< protocols[proto].nparams; i++)
        if ((comm_par[i].type != FIELD_DEFAULT) && (comm_par[i].type != FIELD_EXTRA))
           write_log(2,"[-%s arg] ",comm_par[i].desc);
        
    write_log(2,"\n           -h    This help screen.\n");         
    write_log(2,"           -M    Disable MAC address spoofing.\n");         
    write_log(2,"\nUse '?' as parameter argument if you would like to display the parameter help.\n\n");
    write_log(2,"Please, see the man page for a full list of options and many examples.\n");
    write_log(2,"Send your bugs & suggestions to the Yersinia developers <yersinia@yersinia.net>\n\n");  
}


/*
 * Command line parser for all protocols
 */
int8_t 
parser_cl_proto( struct term_node *node, int8_t argc, char **args, u_int8_t proto)
{
    int8_t aux, tmp, ifaces, i, j, has_help, has_arg, fail, gotit;
    char *param;
    u_int32_t aux_long;
    struct term_tty *term_tty=NULL;
    struct attack *first_attack;
    struct commands_param *comm_par;
    dlist_t *p = NULL;
    struct interface_data *iface_data;

    char **aux_args = args;
        
    if (argc == 1)
    {
       write_log(2,"Ouch!! No arguments specified!!\n");
       return -1;
    }
    
    comm_par = protocols[proto].parameters;

    term_tty = node->specific;
    
    ifaces = 0; i = 0; aux_args++;
    
    while ( *aux_args != (char *)NULL )
    {
       if (*(aux_args+1) == NULL)
       {
          has_arg = 0;
          has_help = 0;
       }
       else
       {
          has_arg = 1;
          if (!strcmp("?", *(aux_args+1)) )
             has_help = 1;
          else
             has_help = 0;
       }
                         
       /* write_log(2,"argc=%d   arg(%d)=%s   has_help=%d  has_arg=%d\n",argc,i,*aux_args,has_help,has_arg);*/
       
       if ((strlen(*aux_args)==1) ||  ((**aux_args) != '-') )
       {
          write_log(2," Bad parameter '%s'!!\n",*aux_args);
          return -1;
       }
       if (!strcmp("-interface", *aux_args) || !strcmp("-i", *aux_args) )
       {
          if (!has_arg)
          {
             write_log(2,"Parameter 'interface' needs an argument!!\n");
             return -1;
          }
          if (has_help)
          {
             write_log(2,"    WORD    Network interface name\n");
             return -1;
          }
          aux_args++;
          if ((p = dlist_search(interfaces->list, interfaces->cmp, (*aux_args))) == NULL)
          {
             write_log(2,"Unable to use interface %s!! (Maybe nonexistent?)\n\n", *aux_args);
             return -1;
          }
           /* Don't repeat interface...*/
          if (!dlist_search(node->used_ints->list, node->used_ints->cmp, (*aux_args)))
          {
              if ((tmp = interfaces_enable(*aux_args)) == -1)
              {
                 write_log(2,"Unable to use interface %s!! (Maybe nonexistent?)\n\n",*aux_args);
                 return -1;
              }
              iface_data = (struct interface_data *) calloc(1, sizeof(struct interface_data));
              memcpy((void *)iface_data, (void *)dlist_data(p), sizeof(struct interface_data));
              node->used_ints->list = dlist_append(node->used_ints->list, (void *)iface_data);
              ifaces++;
          }
       }
       else
       if (!strcmp("-help", *aux_args) || !strcmp("-h", *aux_args) )
       {
          parser_cl_proto_help(proto,node);
          return -1;
       }
       else
       if (!strcmp("-M", *aux_args) )
       {
          if (has_help)
          {
             write_log(2,"    <cr>    Disable MAC address spoofing\n");
             return -1;
          }
          node->mac_spoofing = 0;
       }
       else 
       if (!strcmp("-attack", *aux_args) )
       {
          if (!has_arg)
          {
             write_log(2,"Parameter 'attack' needs an argument!!\n");
             return -1;
          }
          if (!protocols[proto].attacks)
          {
             write_log(2,"Ouch!! No attacks defined for protocol %s!!\n",protocols[proto].namep);
             return -1;
          }
          if (has_help)
          {
              first_attack =  protocols[proto].attacks;
              while (first_attack->s != NULL) 
              {
                  write_log(2,"    <%d>    %s attack %s\n",first_attack->v,
                            (first_attack->type)?"DOS":"NONDOS", 
                            first_attack->s);
                  ++first_attack;
              }
              return -1;
          }
          aux_args++;
          aux = atoi(*aux_args);
          first_attack =  protocols[proto].attacks;          
          j=0;
          while(first_attack[j].s != NULL)
                j++;
          if ( (aux < 0) || (aux > (j-1)) )
          {
              write_log(2," %s attacks id must be between 0 and %d!!\n",protocols[proto].namep,(j-1));
              return -1;
          }
          term_tty->attack = aux;
       }
       else /* Now we can compare all the protocol params */
       {
          gotit=0;
          comm_par = protocols[proto].parameters;
          param = *aux_args;
          param++; /* Avoid the '-' */
          for(j=0; j<protocols[proto].nparams;j++)
          {
              if ((comm_par[j].type == FIELD_DEFAULT) || (comm_par[j].type == FIELD_EXTRA)) 
                 /* We don't care about the 'default' command */
                 continue;

              if (!strcmp(comm_par[j].desc, param))
              {
                  if (has_help)
                  {
                     write_log(2,"\n %s, allowed values:\n\n",comm_par[j].help);
                     write_log(2," %s\n",comm_par[j].param);
                     return -1;
                  }
                  if (!has_arg)
                  {
                     write_log(2,"Parameter '%s' needs an argument!!\n",param);
                     return -1;
                  }
                  
                  fail = parser_filter_param( comm_par[j].type,
                                              node->protocol[proto].commands_param[j],
                                              *(aux_args+1),
                                              comm_par[j].size_print,
                                              comm_par[j].size);

                  if (fail == -1)
                  {
                     write_log(2," Bad value '%s' for parameter '%s'!!\n",*(aux_args+1),param);
                     return -1;
                  }

                  if (comm_par[j].type == FIELD_IP)
                  {
                     memcpy((void *)&aux_long, (void *)node->protocol[proto].commands_param[j], 4);
                     aux_long = ntohl(aux_long);
                     memcpy((void *)node->protocol[proto].commands_param[j], (void *)&aux_long, 4);
                  }

                 
                 if (comm_par[j].filter) /* Use specific filter for this param */
                 {

                    fail = (comm_par[j].filter((void *)node,node->protocol[proto].commands_param[j],*(aux_args+1)));
                    if (fail == -1)
                    {
                       write_log(2," Bad value '%s' for parameter '%s'!!\n",*(aux_args+1),param);
                       return -1;
                    }                    
                 }
                  
                  gotit=1;
                  aux_args++;
                  break;
              }
          } /* next protocol parameter */
          if (!gotit)
          {
             write_log(2," Unrecognized parameter '%s'!!!\n",*aux_args);
             return -1;
          }
       }
       aux_args++; 
       i++;
   } /* while */

    if (interfaces->list)
       iface_data = dlist_data(interfaces->list);
    else {
       write_log(0, "Hmm... you don't have any valid interface.\
             %s is useless. Go and get a life!\n", PACKAGE);
       return -1;
    }

    /* take the first valid interface */
    if (!ifaces) 
    {
       if (strlen(iface_data->ifname)) 
       {
           write_log(2,"Warning: interface %s selected as the default one\n", iface_data->ifname);
           if ((tmp = interfaces_enable(iface_data->ifname)) == -1) 
           {
               write_log(2,"Unable to use interface %s!! (Maybe nonexistent?)\n\n", iface_data->ifname);
               return -1;
           } 
           else 
           {
              iface_data = (struct interface_data *) calloc(1, sizeof(struct interface_data));
              memcpy((void *)iface_data, (void *)dlist_data(interfaces->list), 
                      sizeof(struct interface_data));
              node->used_ints->list = dlist_append(node->used_ints->list, (void *)iface_data);
              ifaces++;
           }
       } 
       else 
       {
            write_log(2,"Hmm... you don't have any valid interface. Go and get a life!\n");
            return -1;
       }
    }
    
   return 0;
}


int8_t
parser_binary2printable(u_int8_t proto, u_int8_t elem, void *value, char *msg)
{
   int8_t j;
   u_int8_t *aux8;
   u_int16_t *aux16;
   u_int32_t *aux32, auxip;
   struct commands_param *params;

   params = (struct commands_param *) protocols[proto].parameters;

   *msg = '\0';
   switch(params[elem].type)
   {
      case FIELD_IP:
         memcpy((void *)&auxip, value, 4);
         auxip = htonl(auxip);
         strncpy(msg, libnet_addr2name4(auxip, LIBNET_DONT_RESOLVE), 16);
         break;

      case FIELD_HEX:
         if (params[elem].size_print == 2)
         {
            aux8 = (u_int8_t *) value;
            snprintf(msg, 3,"%02hX",*aux8);
         }
         else
            if (params[elem].size_print == 4)
            {
               aux16 = (u_int16_t *) value;
               snprintf(msg, 5,"%04hX",*aux16);
            }
            else
            {
               aux32 = (u_int32_t *) value;
               snprintf(msg, 9,"%08hX",*aux32);
            }
         break;

      case FIELD_DEC:
         if (params[elem].size == 1)
         {
            aux8 = (u_int8_t *) value;
            snprintf(msg, 4 ,"%d",*aux8);
         }
         else
            if (params[elem].size == 2)
            {
               aux16 = (u_int16_t *) value;
               snprintf(msg, 6,"%d",*aux16);
            }
            else
            {
               aux32 = (u_int32_t *) value;
               snprintf(msg, 9,"%d",*aux32);
            }               
         break;

      case FIELD_BRIDGEID:
         aux8 =  value;
         snprintf(msg, 18, "%02X%02X.%02X%02X%02X%02X%02X%02X",
               *(aux8)&0xFF, *(aux8+1)&0xFF, *(aux8+2)&0xFF,
               *(aux8+3)&0xFF, *(aux8+4)&0xFF, *(aux8+5)&0xFF,
               *(aux8+6)&0xFF, *(aux8+7)&0xFF);
         break;

      case FIELD_MAC:
         aux8 = value;
         snprintf(msg, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
               aux8[0], aux8[1], aux8[2], aux8[3], aux8[4], aux8[5]);
         break;

      case FIELD_BYTES:
         aux8 = value;
         for(j=0; j<params[elem].size; j++, aux8++)
            snprintf((msg+j*2), 3, "%02X", *(aux8)&0xFF);
         break;

      case FIELD_STR:
         aux8 = value;
         snprintf(msg, params[elem].size_print, "%s", aux8);               
         break;

      case FIELD_NONE:
      case FIELD_DEFAULT:
      case FIELD_EXTRA:
      case FIELD_IFACE:
         break;

      default:
         write_log(0,"Ouch!! Unrecognized protocol(%s) param type %d!!!\n",
               protocols[proto].namep, params[elem].type);  
   }

   return 0;
}


char *
parser_get_meaning(char *value, const struct tuple_type_desc *tuple)
{
   u_int16_t i;

   i = 0;
   while(tuple[i].desc)
   {
      if (tuple[i].type == strtoul(value, NULL, 16))
         return tuple[i].desc;
      i++;
   }

   return "UKN";
}


u_int8_t
parser_get_max_field_length(const struct tuple_type_desc *tuple)
{
   u_int8_t max;
   u_int16_t i;

   max = 0;
   i = 0;
   while(tuple[i].desc)
   {
      if (strlen(tuple[i].desc) > max)
         max = strlen(tuple[i].desc);
      i++;
   }

   return max;
}

/* vim:set tabstop=3:set expandtab:set shiftwidth=3:set textwidth=78: */
