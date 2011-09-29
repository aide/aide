/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2004-2006,2010,2011 Rami Lehti, Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
 * $Header$
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "report.h"

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

#if !defined HAVE_VSNPRINTF || !defined HAVE_C99_VSNPRINTF
#define vsnprintf rsync_vsnprintf
int vsnprintf(char *str, size_t count, const char *fmt, va_list args);
#endif

#if !defined HAVE_SNPRINTF || !defined HAVE_C99_VSNPRINTF
#define snprintf rsync_snprintf
int snprintf(char *str,size_t count,const char *fmt,...);
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

#if defined HAVE_OFF64_TYPE && SIZEOF_OFF64_T == SIZEOF_LONG_LONG || !defined HAVE_OFF64_TYPE && SIZEOF_OFF_T == SIZEOF_LONG_LONG
# ifdef HAVE_STRTOLL
#  define AIDE_STRTOLL_FUNC strtoll
# else
#  ifdef HAVE_STRTOIMAX
#   define AIDE_STRTOLL_FUNC strtoimax
#  else
#   define AIDE_STRTOLL_FUNC strtol
#  endif
# endif
#else
# define AIDE_STRTOLL_FUNC strtol
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

