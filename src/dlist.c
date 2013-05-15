/* dlist.c
 * Dynamic lists implementation (double linked)
 * taken from http://www.vorlesungen.uos.de/informatik/cc02/src/dlist/dlist.c
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
"$Id: dlist.c 43 2007-04-27 11:07:17Z slay $";
#endif

#include "config.h"

#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "dlist.h"

void *
dlist_data(dlist_t *list)
{
   return list ? list->data : NULL;
}

dlist_t*
dlist_next(dlist_t* list, dlist_t* p)
{
    return (list && p && p->next != list) ? p->next : NULL;
}

dlist_t*
dlist_prev(dlist_t* list, dlist_t* p)
{
    return (list && p && p != list) ? p->prev : NULL;
}

static inline dlist_t*
dlist_new(const void *data)
{
    dlist_t *p;

    p = malloc(sizeof(dlist_t));
    if (! p) {
        exit(EXIT_FAILURE);
    }
    p->data = (void *) data;
    p->next = p->prev = p;
    return p;
}

dlist_t*
dlist_prepend(dlist_t *list, const void *data)
{
    dlist_t *p;

    p = dlist_new(data);
    if (! list) {
        return p;
    } 
    p->prev = list->prev, list->prev->next = p;
    p->next = list, list->prev = p;
    return p;
}

dlist_t*
dlist_append(dlist_t *list, const void *data)
{
    dlist_t *p;

    p = dlist_new(data);
    if (! list) {
        return p;
    } 
    p->prev = list->prev, list->prev->next = p;
    p->next = list, list->prev = p;
    return list;
}

dlist_t*
dlist_remove(dlist_t *list, const void *data)
{
    dlist_t *p, *q;

    for (p = list; p; ) {
        if (p->data == data) {
            if (p->next == p && p->prev == p) {
                free(p);
                list = p = NULL;
            } else {
                q = p;
                p->prev->next = p->next;
                p->next->prev = p->prev;
                p = dlist_next(list, p->prev);
                if (q == list) list = p;
                free(q);
            }
        } else {
            p = dlist_next(list, p);
        }
    }
    return list;
}

dlist_t*
dlist_delete(dlist_t *list)
{
    dlist_t *p, *q;

    for (p = list; p; ) {
        q = p, p = dlist_next(list, p), free(q);
    }
    return NULL;
}

u_int32_t
dlist_length(dlist_t *list)
{
    dlist_t *p;
    u_int32_t l = 0;

    for (p = list; p; p = dlist_next(list, p)) l++;
    return l;
}

dlist_t*
dlist_last(dlist_t *list)
{
    return (list ? list->prev : NULL); 
}

void
dlist_foreach(dlist_t *list,
              void (*func) (void *data, void *user), void *user)
{
    dlist_t *p;

    if (func) {
        for (p = list; p; p = dlist_next(list, p)) {
            func((p)->data, user);
        }
    }
}

dlist_t*
dlist_find(dlist_t *list, const void *data)
{
    dlist_t *p;
    
    for (p = list; p; p = dlist_next(list, p)) {
        if (p->data == data) {
            return p;
        }
    }
    return NULL;
}

dlist_t*
dlist_search(dlist_t *list,
             int8_t (*cmp) (void *data, void *pattern), void *pattern)
{
    dlist_t *p;

    if (cmp) {
        for (p = list; p; p = dlist_next(list, p)) {
            if (cmp(p->data, pattern) == 0) {
                return p;
            }
        }
    }
    return NULL;
}
