/* thread-util.h
 * Definitions for thread utils
 *
 * $Id: thread-util.h 43 2007-04-27 11:07:17Z slay $ 
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

#ifndef __THREAD_H__
#define __THREAD_H__

#include <libnet.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#define THREAD_TIMEOUT -2

struct condsem {
	pthread_mutex_t mutex;
	pthread_cond_t condvar;
	u_int16_t value;
};

typedef struct {
       pthread_t id;
       u_int8_t  stop;
       pthread_mutex_t finished;
} THREAD;

#define PTHREAD_JOIN(x) (pthread_mutex_lock(&(x)->finished))

int8_t  thread_create(pthread_t *, void *, void *);
int8_t  thread_destroy_cancel(pthread_t);
int8_t  thread_destroy(THREAD *);
void    thread_error(char *, int8_t);
void    thread_libnet_error(char *, libnet_t *);
int8_t  thread_create_condsem(struct condsem *);
void    thread_delete_condsem(struct condsem *);
int8_t  thread_wait_cond(struct condsem *);
int8_t  thread_wait_cond_timed(struct condsem *, struct timeval *);
int8_t  thread_signal_cond(struct condsem *);
int8_t  thread_send_broadcast(struct condsem *, int8_t);
void   *thread_calloc_r(size_t);
void    thread_free_r(void *);
int     thread_usleep(unsigned long);

/* Extern functions...*/
/*extern void write_log( u_int16_t mode, char *msg, ... );*/

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
