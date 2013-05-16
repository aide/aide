/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2013 Rami Lehti, Pablo Virolainen, Richard
 * van den Berg, Hannes von Haugwitz
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

#ifndef _UTIL_H_INCLUDED
#define _UTIL_H_INCLUDED
#include <string.h>
#include <sys/types.h>
#include "db_config.h"

#define HEXD2ASC(x) (((x) < 10) ? ((x) + '0') : ((x) - 10 + 'A'))

#define ASC2HEXD(x) (((x) >= '0' && (x) <= '9') ?               \
                     ((x) - '0') : (toupper(x) - 'A' + 10))

#define ISXDIGIT(x) isxdigit ((unsigned char)(x))

#define CLEANDUP(x) (contains_unsafe (x) ? encode_string (x) : strdup (x))

#ifndef HAVE_STRICMP
#  define stricmp(a,b)   strcasecmp( (a), (b) )
#endif

int cmpurl(url_t*, url_t*);

url_t* parse_url(char*);

int contains_unsafe(const char*);

void decode_string(char*);

char* encode_string(const char*);

char* perm_to_char(mode_t perm);

void sig_handler(int signal);

void init_sighandler(void);

char *expand_tilde(char * path);

#ifndef HAVE_STRNSTR
char* strnstr(char* haystack,char* needle,int n);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen);
#endif

int syslog_facility_lookup(char *);

#endif
