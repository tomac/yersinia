/* md5_sum.c
 * Wrapper function for MD5
 *
 * Yersinia
 * By David Barroso <tomac@yersinia.net> and Alfredo Andres <aandreswork@hotmail.com>
 * Copyright 2005-2017 Alfredo Andres and David Barroso
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "md5-sum.h"

void
md5_sum(const u_int8_t *stuff, size_t len, u_char *digest)
{
   struct MD5Context context;

   MD5Init(&context);
   MD5Update(&context, stuff, (unsigned) len);
   MD5Final(digest, &context);
}
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=120: */
