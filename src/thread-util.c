/* thread-util.c
 * Implementation of thread utilities
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
       "$Id: thread-util.c 43 2007-04-27 11:07:17Z slay $";
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

#include <stdarg.h>

#include "thread-util.h"

/*
 * Create a thread
 */
int8_t
thread_create(pthread_t *thread_id, void *thread_body , void *arg)
{
   if (pthread_create(thread_id, NULL, thread_body, arg) != 0) 
   {
      thread_error("pthread_create",errno);
      return -1;
   }
   
   return 0;
}

/*
 * Destroy a thread with cancellation...
 */
int8_t
thread_destroy_cancel(pthread_t thread_id)
{
   pthread_t id = thread_id;
   
   if (pthread_cancel(id) != 0) {
      thread_error(" thread_destroy_cancel pthread_cancel",errno);
      return -1;
   }

   if (pthread_join(id, NULL) != 0) {
      thread_error(" thread_destroy_cancel pthread_join",errno);
      return -1;
   }

   return 0;
}


/*
 * Destroy a thread with polling...
 */
int8_t
thread_destroy(THREAD *thread)
{
   pthread_t id = thread->id;
   
   write_log(0,"\n thread_destroy %d destroying %d...\n",(int)pthread_self(),
            (int)id);

   thread->stop = 1;

   if (PTHREAD_JOIN(thread) != 0) 
   {
      thread_error(" thread_destroy PTHREAD_JOIN",errno);
      return -1;
   }

   write_log(0," thread_destroy %d after PTHREAD_JOIN %d...\n",
            (int)pthread_self(), (int)id);

   thread->stop = 0;
   thread->id = 0;

   return 0;
}


int8_t
thread_create_condsem(struct condsem *condsem)
{
   if (pthread_mutex_init(&condsem->mutex, NULL) != 0)
   {
      thread_error("pthread_mutex_init",errno);
      return -1;
   }
   
   if (pthread_cond_init(&condsem->condvar, NULL) != 0)
   {
      thread_error("pthread_cond_init",errno);
      return -1;
   }
   
   condsem->value = 0;
   
   return 0;
}


void
thread_delete_condsem(struct condsem *condsem)
{
   if (pthread_mutex_destroy(&condsem->mutex) != 0)
      thread_error("pthread_mutex_destroy(&condsem->mutex)",errno);

   if (pthread_cond_destroy(&condsem->condvar) != 0)
      thread_error("pthread_cond_destroy(&condsem->condvar)",errno);        
}

  
int8_t
thread_wait_cond(struct condsem *condsem)
{
   if (pthread_mutex_lock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_lock",errno);
      return -1;
   }

   while (condsem->value <= 0)
   {
      if (pthread_cond_wait(&condsem->condvar, &condsem->mutex) != 0)
      {
         thread_error("pthread_cond_wait",errno);
         return -1;
      }
   }

   condsem->value--;

   if (pthread_mutex_unlock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_unlock",errno);
      return -1;
   }

   return 0;
}



/*
 * Wait for condition wariable with timeout.
 * Be aware of disabling cancellation before calling this function!!!
 * Return THREAD_TIMEOUT on timeout, -1 on error, 0 if Ok.
 */
int8_t
thread_wait_cond_timed(struct condsem *condsem, struct timeval *timeout)
{
   int ret=0;
   struct timeval now;
   struct timespec abstimeout;

   if (pthread_mutex_lock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_lock",errno);
      return -1;
   }

   gettimeofday(&now, NULL);
   
   abstimeout.tv_sec  = now.tv_sec + timeout->tv_sec;
   abstimeout.tv_nsec = (now.tv_usec + timeout->tv_usec) * 1000;

   if (abstimeout.tv_nsec > 999999999)
   {
      abstimeout.tv_sec  += (abstimeout.tv_nsec/1000000000);
      abstimeout.tv_nsec = (abstimeout.tv_nsec%1000000000);
   }

   while (condsem->value <= 0)
   {
      ret = pthread_cond_timedwait(&condsem->condvar, &condsem->mutex, 
                                    &abstimeout);
      if ( (ret == ETIMEDOUT) || (ret != 0) )
         break;
   }      

   if (ret == ETIMEDOUT)
   {
      pthread_mutex_unlock(&condsem->mutex);
      return THREAD_TIMEOUT;
   }
   else
   { 
      if (ret)
      {
         thread_error(" pthread_cond_timedwait()",ret);
         pthread_mutex_unlock(&condsem->mutex);
         return -1;
      }

      condsem->value--;
   }

   pthread_mutex_unlock(&condsem->mutex);

   return 0;
}


   

int8_t 
thread_signal_cond(struct condsem *condsem)
{
   if (pthread_mutex_lock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_lock",errno);
      return -1;
   }

   condsem->value++;

   if (pthread_mutex_unlock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_unlock",errno);
      return -1;
   }

   if (pthread_cond_signal(&condsem->condvar) != 0)
   {
      thread_error("pthread_cond_signal",errno);
      return -1;
   }
   
   return 0;
}


int8_t
thread_send_broadcast(struct condsem *condsem, int8_t total)
{
   if (pthread_mutex_lock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_lock",errno);
      return -1;
   }

   condsem->value += total;

   if (pthread_mutex_unlock(&condsem->mutex) != 0)
   {
      thread_error("pthread_mutex_unlock",errno);
      return -1;
   }

   if (pthread_cond_broadcast(&condsem->condvar) != 0)
   {
      thread_error("pthread_send_broadcast",errno);
      return -1;
   }
   
   return 0;
}


void
thread_error( char *msg, int8_t errn)
{
#ifdef HAVE_GLIBC_STRERROR_R
  /* At least on glibc >= 2.0 Can anybody confirm?... */
  char buf[64];
  
  write_log(0, "%s: (%d) %s -> %s\n", PACKAGE, (int)pthread_self(), msg, 
             strerror_r(errn, buf, sizeof(buf)));
#else

#ifdef HAVE_STRERROR
   write_log(0, "%s: (%d) %s -> %s\n", PACKAGE, (int)pthread_self(), msg, 
              strerror(errn) );
#else
   write_log(0, "%s: (%d) %s -> %s\n", PACKAGE, (int)pthread_self(), msg, 
              sys_errlist[errn] );
#endif

#endif

}


void
thread_libnet_error( char *msg, libnet_t *lhandler)
{
   write_log(0, "%s: (%d) %s -> %s\n", PACKAGE,  (int)pthread_self(), msg,
             libnet_geterror(lhandler));
}


/*
 * Our own calloc function.
 */ 
void *
thread_calloc_r(size_t size)
{
   void *aux;

#ifdef HAVE_CALLOC_R
   aux = calloc_r(1,size);
#else   
   aux = calloc(1,size);
#endif
   
   return aux;
}


void
thread_free_r(void *ptr)
{
#ifdef HAVE_FREE_R
   free_r(ptr);
#else
   free(ptr);
#endif
}


int
thread_usleep(unsigned long useconds)
{
   int ret;
#ifdef HAVE_NANOSLEEP
   struct timespec timeout;
#else
   struct timeval timeout;
#endif

   if (useconds > 999999)
      useconds = 999999;
      
   timeout.tv_sec  = 0;

#ifdef HAVE_NANOSLEEP                        
   timeout.tv_nsec = (useconds*1000); 
#else
   timeout.tv_usec = useconds;
#endif            
                     
#ifdef HAVE_NANOSLEEP                        
   ret = nanosleep(&timeout, NULL);
#else
   ret = select(0,NULL,NULL,NULL,&timeout);
#endif

   return ret;
}

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
