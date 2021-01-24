/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2010-2011, 2019 Rami Lehti,
 *               Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _AIDE_H_INCLUDED
#define _AIDE_H_INCLUDED

#include "config.h"
#include "types.h"
#include "db_config.h"
#include <stdlib.h>
#include <unistd.h>
#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifndef __APPLE__
#include "error.h"
#endif /* __APPLE__ */

#ifndef TEMP_FAILURE_RETRY
/* Evaluate EXPRESSION, and repeat as long as it returns -1 with errno'
   set to EINTR.  */

# define TEMP_FAILURE_RETRY(expression) \
   (__extension__                                                              \
     ({ long int __result;                                                     \
        do __result = (long int) (expression);                                 \
        while (__result == -1L && errno == EINTR);                             \
        __result; }))
#endif

#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif

#ifdef strtoimax
# define HAVE_STRTOIMAX
#endif

#ifndef __NetBSD__
#ifndef _POSIX_C_SOURCE
/* For _POSIX_THREAD_SEMANTICS _REENTRANT */
#define _POSIX_C_SOURCE 199506L
#endif /* _POSIX_C_SOURCE */
#endif /* __NetBSD__ */


#define ARGUMENT_SIZE 65536

/* This is a structure that has all configuration info */
extern db_config* conf;

#endif

