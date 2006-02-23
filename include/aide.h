/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti, Pablo Virolainen
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
#define AIDEVERSION VERSION
#include "report.h"
#include "db_config.h"
#include <stdlib.h>
#include <unistd.h>
#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif

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

#ifdef HAVE_SNPRINTF
#if !defined(HAVE_C99_SNPRINTF) || !defined(HAVE_C99_VSNPRINTF)
#define PREFER_PORTABLE_SNPRINTF
#endif
#endif

#ifdef HAVE_VSNPRINTF
#ifndef HAVE_SNPRINTF
#define HAVE_SNPRINTF
#define PREFER_PORTABLE_SNPRINTF
#endif
#endif

#define SNPRINTF_LONGLONG_SUPPORT

#include "snprintf.h"

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

#if AIDE_OFF_TYPE == off64_t
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

void print_version(void);

void usage(int);

int read_param(int argc,char**argv);



#endif

