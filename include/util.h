/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2013, 2020-2023 Rami Lehti, Pablo Virolainen,
 *               Richard van den Berg, Hannes von Haugwitz
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

#ifndef _UTIL_H_INCLUDED
#define _UTIL_H_INCLUDED
#include "config.h"
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdarg.h>
#include "url.h"

#define HEXD2ASC(x) (((x) < 10) ? ((x) + '0') : ((x) - 10 + 'A'))

#define ASC2HEXD(x) (((x) >= '0' && (x) <= '9') ?               \
                     ((x) - '0') : (toupper(x) - 'A' + 10))

#define ISXDIGIT(x) isxdigit ((unsigned char)(x))

#define CLEANDUP(x) (contains_unsafe (x) ? encode_string (x) : strdup (x))

#ifndef HAVE_STRICMP
#  define stricmp(a,b)   strcasecmp( (a), (b) )
#endif

#ifndef HAVE_BYTE
typedef uint8_t byte;
#endif

void stderr_msg(const char*, ...);
void vstderr_prefix_line(const char*, const char*, va_list);
void stderr_set_line_erasure(bool);

const char* btoa(bool);

void* checked_malloc(size_t);
void* checked_calloc(size_t, size_t);
void* checked_strdup(const char *);
void* checked_strndup(const char *, size_t);
void* checked_realloc(void *, size_t);

int cmpurl(url_t*, url_t*);

int contains_unsafe(const char*);

void decode_string(char*);

char* encode_string(const char*);

char* perm_to_char(mode_t perm);

char *expand_tilde(char * path);

char* pipe2string(int);

#ifndef HAVE_STRNSTR
char* strnstr(char* haystack,char* needle,int n);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen);
#endif

#ifdef HAVE_SYSLOG
int syslog_facility_lookup(char *);
#endif

#endif
