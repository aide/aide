/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2020, 2022, 2023 Hannes von Haugwitz
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

#ifndef _LOG_H_INCLUDED
#define  _LOG_H_INCLUDED

#include "config.h"
#include <stdbool.h>

/* log levels */
typedef enum { /* preserve order */
    LOG_LEVEL_UNSET = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_NOTICE = 3,
    LOG_LEVEL_INFO = 4,
    LOG_LEVEL_RULE = 5,
    LOG_LEVEL_COMPARE = 6,
    LOG_LEVEL_CONFIG = 7,
    LOG_LEVEL_DEBUG = 8,
    LOG_LEVEL_THREAD = 9,
    LOG_LEVEL_TRACE = 10,
} LOG_LEVEL;

#ifdef WITH_PTHREAD
void log_init();
#endif

bool is_log_level_unset();

void set_log_level(LOG_LEVEL);

const char * get_log_level_name(LOG_LEVEL);

LOG_LEVEL get_log_level_from_string(char*);

LOG_LEVEL toogle_log_level(LOG_LEVEL);

void log_msg(LOG_LEVEL, const char* ,...);

void stderr_msg(const char* ,...);

#define LOG_CONFIG_FORMAT_LINE(log_level, format, ...) \
    if (linebuf) { \
        log_msg(log_level,"%s:%d: " format " (line: '%s')", filename, linenumber, __VA_ARGS__, linebuf); \
    } else { \
        log_msg(log_level,"%s: " format, filename, __VA_ARGS__); \
    }

#define LOG_CONFIG_FORMAT_LINE_PREFIX(log_level, format, ...) \
    if (rule_prefix) { \
        log_msg(log_level,"%s:%d: " format " (line: '%s', prefix: '%s')", filename, linenumber, __VA_ARGS__, linebuf, rule_prefix); \
    } else { \
        log_msg(log_level,"%s:%d: " format " (line: '%s')", filename, linenumber, __VA_ARGS__, linebuf); \
    }

#endif
