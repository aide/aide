/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2020,2022,2023,2025 Hannes von Haugwitz
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

#include "config.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "log.h"
#include "errorcodes.h"
#include "util.h"

LOG_LEVEL prev_log_level = LOG_LEVEL_UNSET;
LOG_LEVEL log_level = LOG_LEVEL_UNSET;

typedef struct log_cache {
    LOG_LEVEL level;
    char *message;
} log_cache;

log_cache *cached_lines = NULL;
int ncachedlines = 0;

int colored_log = -1;

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

struct log_level {
    LOG_LEVEL log_level;
    const char *name;
    const char *log_string;
    const char *colored_log_string;
};

static struct log_level log_level_array[] = {
    { LOG_LEVEL_ERROR,         "error",         "  ERROR", COLOR_B_RED    "  ERROR" COLOR_RESET },
    { LOG_LEVEL_WARNING,       "warning",       "WARNING", COLOR_B_YELLOW "WARNING" COLOR_RESET },
    { LOG_LEVEL_NOTICE,        "notice",        " NOTICE", COLOR_L_ORANGE " NOTICE" COLOR_RESET },
    { LOG_LEVEL_INFO,          "info",          "   INFO", COLOR_L_GREEN  "   INFO" COLOR_RESET },
    { LOG_LEVEL_COMPARE,       "compare",       "COMPARE", COLOR_B_BLUE   "COMPARE" COLOR_RESET },
    { LOG_LEVEL_RULE,          "rule",          "   RULE", COLOR_L_BLUE   "   RULE" COLOR_RESET },
    { LOG_LEVEL_CONFIG,        "config",        " CONFIG", COLOR_L_CYAN   " CONFIG" COLOR_RESET },
    { LOG_LEVEL_DEBUG,         "debug",         "  DEBUG", COLOR_B_PURPLE "  DEBUG" COLOR_RESET },
    { LOG_LEVEL_LIMIT,         "limit",         "  LIMIT", COLOR_L_GRAY   "  LIMIT" COLOR_RESET },
    { LOG_LEVEL_THREAD,        "thread",        " THREAD", COLOR_B_CYAN   " THREAD" COLOR_RESET },
    { LOG_LEVEL_TRACE,         "trace",         "  TRACE", COLOR_L_PURPLE "  TRACE" COLOR_RESET },
    { 0,                       NULL,            NULL     , NULL      },
};

static const char* get_log_string(LOG_LEVEL level) {
    if (colored_log) {
        return log_level_array[level-1].colored_log_string;
    } else {
        return log_level_array[level-1].log_string;
    }
}

static void cache_line(LOG_LEVEL, const char*, va_list)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 0)))
#endif
;
static void cache_line(LOG_LEVEL level, const char* format, va_list ap) {
    int n;

    cached_lines = realloc(cached_lines, (ncachedlines+1) * sizeof(log_cache)); /* freed in log_cached_lines() */
    if (cached_lines == NULL) {
        stderr_msg("%s: realloc: failed to allocate memory\n", get_log_string(LOG_LEVEL_ERROR));
        exit(MEMORY_ALLOCATION_FAILURE);
    }

    cached_lines[ncachedlines].level = level;
    cached_lines[ncachedlines].message = NULL;

    va_list aq;
    va_copy(aq, ap);
    n = vsnprintf(NULL, 0, format, aq) + 1;
    va_end(aq);

    int size = n * sizeof(char);
    cached_lines[ncachedlines].message = malloc(size); /* freed in log_cached_lines() */
    if (cached_lines[ncachedlines].message == NULL) {
        stderr_msg("%s: malloc: failed to allocate %d bytes of memory\n", get_log_string(LOG_LEVEL_ERROR), size);
        exit(MEMORY_ALLOCATION_FAILURE);
    }

    vsnprintf(cached_lines[ncachedlines].message, n, format, ap);
    ncachedlines++;
}

const char * get_log_level_name(LOG_LEVEL level) {
    return level?log_level_array[level-1].name:NULL;
}

static void log_cached_lines(void) {
    pthread_mutex_lock(&log_mutex);
    for(int i = 0; i < ncachedlines; ++i) {
        LOG_LEVEL level = cached_lines[i].level;
        if (level == LOG_LEVEL_ERROR || level <= log_level) {
            stderr_msg("%s: %s\n", get_log_string(level), cached_lines[i].message);
        }
        free(cached_lines[i].message);
    }
    ncachedlines = 0;
    free(cached_lines);
    pthread_mutex_unlock(&log_mutex);
}

static void vlog_msg(LOG_LEVEL, const char*, va_list)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 0)))
#endif
;
static void vlog_msg(LOG_LEVEL level,const char* format, va_list ap) {
    if (level != LOG_LEVEL_ERROR && (log_level == LOG_LEVEL_UNSET || colored_log < 0)) {
    pthread_mutex_lock(&log_mutex);
        cache_line(level, format, ap);
    pthread_mutex_unlock(&log_mutex);
    } else if (level == LOG_LEVEL_ERROR || level <= log_level) {
        vstderr_prefix_line(get_log_string(level), format, ap);
    }
}

bool is_log_level_unset(void) {
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

void set_colored_log(bool color) {
    colored_log = color;
    if (ncachedlines && log_level != LOG_LEVEL_UNSET) {
        log_cached_lines();
    }
}

void set_log_level(LOG_LEVEL level) {
    log_level = level;
    if (colored_log >= 0 && ncachedlines && log_level != LOG_LEVEL_UNSET) {
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

void log_msg(LOG_LEVEL level, const char* format, ...) {
    va_list argp;
    va_start(argp, format);
    vlog_msg(level, format, argp);
    va_end(argp);
}
