/* dlist.h
 * Definitions for dynamic lists
 * taken from http://www.vorlesungen.uos.de/informatik/cc02/src/dlist/dlist.h
 *
 * $Id: dlist.h 43 2007-04-27 11:07:17Z slay $ 
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

#ifndef _DLIST_H_
#define _DLIST_H_

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef SOLARIS
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t  u_int8_t;
#endif
        
struct dlist {
    void         *data;
    struct dlist *next;
    struct dlist *prev;
};

typedef struct dlist dlist_t;

struct list {
   dlist_t *list;
   int8_t (*cmp)(void *, void *);
   pthread_mutex_t mutex;
};

typedef struct list list_t;

void*
dlist_data(dlist_t *list);

dlist_t*
dlist_next(dlist_t* list, dlist_t* p);

dlist_t*
dlist_prev(dlist_t* list, dlist_t* p);

dlist_t*
dlist_append(dlist_t *list, const void *data);

dlist_t*
dlist_prepend(dlist_t *list, const void *data);

dlist_t*
dlist_remove(dlist_t *list, const void *data);

dlist_t*
dlist_delete(dlist_t *list);

u_int32_t
dlist_length(dlist_t *list);

dlist_t*
dlist_last(dlist_t *list);

void
dlist_foreach(dlist_t *list,
              void (*func) (void *data, void *user), void *user);

dlist_t*
dlist_find(dlist_t *list, const void *data);

dlist_t*
dlist_search(dlist_t *list,
             int8_t (*cmp) (void *data, void *pattern), void *pattern);

extern void write_log( u_int16_t mode, char *msg, ... );
#endif
