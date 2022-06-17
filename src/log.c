/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2020,2022 Hannes von Haugwitz
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

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "log.h"
#include "util.h"

LOG_LEVEL prev_log_level = LOG_LEVEL_UNSET;
LOG_LEVEL log_level = LOG_LEVEL_UNSET;

typedef struct log_cache {
    LOG_LEVEL level;
    char *message;
} log_cache;

log_cache *cached_lines = NULL;
int ncachedlines = 0;

struct log_level {
    LOG_LEVEL log_level;
    const char *name;
    const char *log_string;
};

static struct log_level log_level_array[] = {
    { LOG_LEVEL_ERROR,         "error",         "  ERROR" },
    { LOG_LEVEL_WARNING,       "warning",       "WARNING" },
    { LOG_LEVEL_NOTICE,        "notice",        " NOTICE" },
    { LOG_LEVEL_INFO,          "info",          "   INFO" },
    { LOG_LEVEL_RULE,          "rule",          "   RULE" },
    { LOG_LEVEL_CONFIG,        "config",        " CONFIG" },
    { LOG_LEVEL_DEBUG,         "debug",         "  DEBUG" },
    { LOG_LEVEL_TRACE,         "trace",         "  TRACE" },
    { 0,                       NULL,            NULL      },
};

static void cache_line(LOG_LEVEL, const char*, va_list)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 0)));
#endif
;
static void cache_line(LOG_LEVEL level, const char* format, va_list ap) {
    int n;

    cached_lines = checked_realloc(cached_lines, (ncachedlines+1) * sizeof(log_cache)); /* freed in log_cached_lines() */

    cached_lines[ncachedlines].level = level;
    cached_lines[ncachedlines].message = NULL;

    va_list aq;
    va_copy(aq, ap);
    n = vsnprintf(NULL, 0, format, aq) + 1;
    va_end(aq);

    cached_lines[ncachedlines].message = checked_malloc(n * sizeof(char)); /* freed in log_cached_lines() */
    vsnprintf(cached_lines[ncachedlines].message, n, format, ap);
    ncachedlines++;
}

const char * get_log_level_name(LOG_LEVEL level) {
    return level?log_level_array[level-1].name:NULL;
}

static void log_cached_lines(void) {
    for(int i = 0; i < ncachedlines; ++i) {
        log_msg(cached_lines[i].level, "%s", cached_lines[i].message);
        free(cached_lines[i].message);
    }
    ncachedlines = 0;
    free(cached_lines);
}

static void vlog_msg(LOG_LEVEL, const char*, va_list)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 0)));
#endif
;
static void vlog_msg(LOG_LEVEL level,const char* format, va_list ap) {
    FILE* url = stderr;

    if (level == LOG_LEVEL_ERROR || level <= log_level) {
        fprintf(url, "%s: ", log_level_array[level-1].log_string );
        vfprintf(url, format, ap);
        fprintf(url, "\n");
    } else if (log_level == LOG_LEVEL_UNSET) {
        cache_line(level, format, ap);
    }
}

bool is_log_level_unset() {
    return log_level == LOG_LEVEL_UNSET;
}

LOG_LEVEL get_log_level_from_string(char* val) {
    struct log_level *level;

    for (level = log_level_array; level->log_level != 0; level++) {
        if (strcmp(val, level->name) == 0) {
            return level->log_level;
        }
    }

    return LOG_LEVEL_UNSET;
}

void set_log_level(LOG_LEVEL level) {
    log_level = level;
    if (ncachedlines && level != LOG_LEVEL_UNSET) {
        log_cached_lines();
    }
}

LOG_LEVEL toogle_log_level(LOG_LEVEL level) {
    if (prev_log_level != LOG_LEVEL_UNSET && log_level != level) {
        set_log_level(level);
    } else if (log_level != level || prev_log_level != LOG_LEVEL_UNSET) {
        if (prev_log_level == LOG_LEVEL_UNSET) {
            prev_log_level = log_level;
            set_log_level(level);
        } else {
            set_log_level(prev_log_level);
            prev_log_level = LOG_LEVEL_UNSET;
        }
    }
    return log_level;
}

void log_msg(LOG_LEVEL, const char*, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)));
#endif
;
void log_msg(LOG_LEVEL level, const char* format, ...) {
    va_list argp;
    va_start(argp, format);
    vlog_msg(level, format, argp);
    va_end(argp);
}
