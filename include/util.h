/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2013, 2020-2025 Rami Lehti, Pablo Virolainen,
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
#include <time.h>
#include "url.h"

#define HEXD2ASC(x) (((x) < 10) ? ((x) + '0') : ((x) - 10 + 'A'))

#define ASC2HEXD(x) (((x) >= '0' && (x) <= '9') ?               \
                     ((x) - '0') : (toupper(x) - 'A' + 10))

#define ISXDIGIT(x) isxdigit ((unsigned char)(x))

#ifndef HAVE_STRICMP
#  define stricmp(a,b)   strcasecmp( (a), (b) )
#endif

#ifndef HAVE_BYTE
typedef uint8_t byte;
#endif

#define COLOR_L_BLACK  "\x1B[0;30m"
#define COLOR_L_RED    "\x1B[0;31m"
#define COLOR_L_GREEN  "\x1B[0;32m"
#define COLOR_L_ORANGE "\x1B[0;33m"
#define COLOR_L_BLUE   "\x1B[0;34m"
#define COLOR_L_PURPLE "\x1B[0;35m"
#define COLOR_L_CYAN   "\x1B[0;36m"
#define COLOR_L_GRAY   "\x1B[0;37m"

#define COLOR_B_GRAY   "\x1B[1;30m"
#define COLOR_B_RED    "\x1B[1;31m"
#define COLOR_B_GREEN  "\x1B[1;32m"
#define COLOR_B_YELLOW "\x1B[1;33m"
#define COLOR_B_BLUE   "\x1B[1;34m"
#define COLOR_B_PURPLE "\x1B[1;35m"
#define COLOR_B_CYAN   "\x1B[1;36m"
#define COLOR_B_WHITE  "\x1B[1;37m"

#define COLOR_RESET    "\x1B[0m"

void stderr_msg(const char* format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 1, 2)))
#endif
;
void vstderr_prefix_line(const char*, const char*, va_list)
#ifdef __GNUC__
    __attribute__ ((format (printf, 1, 0)))
#endif
;
void stderr_set_line_erasure(bool);
void stderr_multi_lines(char* *, int);

const char* btoa(bool);

void* checked_malloc(size_t);
void* checked_calloc(size_t, size_t);
void* checked_strdup(const char *);
void* checked_strndup(const char *, size_t);
void* checked_realloc(void *, size_t);

int cmpurl(url_t*, url_t*);

int contains_unsafe(const char*);

char *strnesc(const char *, size_t);
char *stresc(const char *);

void decode_string(char*);

char* encode_string(const char*);

int  print_path(char *, const char *, const char*, int);
char *get_progress_bar_string(const char *, const char *, long unsigned, long unsigned, int, int);

char* perm_to_char(mode_t perm);

char *expand_tilde(char * path);

char* byte_to_base16(const byte*, size_t);

char* pipe2string(int);

char* get_time_string(const time_t *);

void mask_sig(const char*);

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
