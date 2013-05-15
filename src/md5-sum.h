/* md5_sum.h
 * Definitions for MD5 wrapper function
 *
 * $Id: md5-sum.h 43 2007-04-27 11:07:17Z slay $  
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

#ifndef _MD5_SUM_H
#define _MD5_SUM_H

#include "md5.h"

void md5_sum(const u_int8_t *, size_t, u_char *);

#endif

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
