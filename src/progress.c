/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2023-2025 Hannes von Haugwitz
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
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "aide.h"
#include "progress.h"
#include "log.h"
#include "errorcodes.h"
#include "util.h"

#define BILLION  1000000000L

pthread_t progress_updater_thread = 0LU;
pthread_mutex_t progress_update_mutex = PTHREAD_MUTEX_INITIALIZER;

static progress_state  state = PROGRESS_NONE;
static struct timespec time_start;
static long unsigned num_entries = 0;
static long unsigned num_skipped = 0LU;
static char* path = NULL;

static char *get_state_string(progress_state s) {
    switch (s) {
        case PROGRESS_OLDDB:
            return "read old db";
        case PROGRESS_NEWDB:
            return "read new db";
        case PROGRESS_DISK:
            return "scan file system";
        case PROGRESS_WRITEDB:
            return "write db";
        case PROGRESS_CONFIG:
            return "parse config";
        case PROGRESS_SKIPPED:
        case PROGRESS_CLEAR:
        case PROGRESS_NONE:
            return NULL;
    }
    return NULL;
}

static void * progress_updater( __attribute__((unused)) void *arg) {
    const char *whoami = "(progress)";
    log_msg(LOG_LEVEL_THREAD, "%10s: initialized progress_updater thread", whoami);

    mask_sig(whoami);

    bool _continue = true;
    while (_continue) {
        pthread_mutex_lock(&progress_update_mutex);
        time_t now = time(NULL);
        int elapsed = (unsigned long) now - (unsigned long) conf->start_time;
        char *progress_bar = NULL;
        switch (state) {
            case PROGRESS_CONFIG:
            case PROGRESS_NEWDB:
            case PROGRESS_SKIPPED:
            case PROGRESS_DISK:
            case PROGRESS_WRITEDB:
            case PROGRESS_OLDDB:
                progress_bar = get_progress_bar_string(get_state_string(state), path, num_entries, num_skipped, elapsed, conf->progress);
                stderr_msg("%s\r", progress_bar);
                free(progress_bar);
                progress_bar = NULL;
                break;
            case PROGRESS_CLEAR:
                _continue = false;
                break;
            case PROGRESS_NONE:
                /* do nothing */
                ;;

        }
        pthread_mutex_unlock(&progress_update_mutex);
        usleep(100000);
    }
    return (void *) pthread_self();
}

static void update_state(progress_state new_state) {
        LOG_LEVEL log_level = LOG_LEVEL_INFO;

        struct timespec time_now;
        clock_gettime( CLOCK_REALTIME, &time_now);

        double elapsed = (time_now.tv_sec - time_start.tv_sec) + (time_now.tv_nsec - time_start.tv_nsec)/(double)BILLION;

        long elapsed_minutes = (long)floor(elapsed)/60;
        double elapsed_seconds = elapsed - elapsed_minutes*60;

        unsigned long performance = (num_entries+num_skipped)/elapsed;
        char * entries_string = num_entries == 1 ? "entry" : "entries";

        char *skipped_str = NULL;
        if (num_skipped) {
            const char *skipped_format = " (%lu skipped)";
            int n = snprintf(NULL, 0, skipped_format, num_skipped);
            skipped_str = checked_malloc(n+1);
            snprintf(skipped_str, n+1, skipped_format, num_skipped);
        }
        switch (state) {
            case PROGRESS_OLDDB:
                log_msg(log_level, "read %lu %s%s [%lu entries/s] from %s in %ldm %.4lfs", num_entries, entries_string, skipped_str?skipped_str:"", performance, (conf->database_in.url)->raw, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_NEWDB:
                log_msg(log_level, "read %lu %s%s [%lu entries/s] from %s in %ldm %.4lfs", num_entries, entries_string, skipped_str?skipped_str:"", performance, (conf->database_new.url)->raw, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_DISK:
                log_msg(log_level, "read %lu %s [%lu entries/s] from file system in %ldm %.4lfs", num_entries, entries_string, performance, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_CONFIG:
                log_msg(log_level, "parsed %lu config %s [%lu files/s] in %ldm %.4lfs", num_entries, num_entries == 1 ? "file" : "files", performance, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_WRITEDB:
                log_msg(log_level, "wrote %lu %s [%lu entries/s] to %s in %ldm %.4lfs", num_entries, entries_string, performance, (conf->database_out.url)->raw, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_SKIPPED:
            case PROGRESS_CLEAR:
            case PROGRESS_NONE:
                /* no logging */
                break;
        }
        if (skipped_str) {
            free(skipped_str);
            skipped_str = NULL;
        }
        time_start = time_now;
        state = new_state;
}

bool progress_start(void) {
    struct winsize winsize;

    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &winsize) == -1) {
        conf->progress = 80;
    } else {
        conf->progress = winsize.ws_col;
    }
    if (pthread_create(&progress_updater_thread, NULL, &progress_updater, NULL) != 0) {
        log_msg(LOG_LEVEL_WARNING, "failed to start progress_updater thread (disable progress bar)");
        return false;
    }
    stderr_set_line_erasure(true);
    return true;
}

void progress_stop(void) {
    pthread_mutex_lock(&progress_update_mutex);
    update_state(PROGRESS_CLEAR);
    stderr_set_line_erasure(false);
    pthread_mutex_unlock(&progress_update_mutex);
    if (progress_updater_thread) {
        if (pthread_join(progress_updater_thread, NULL) != 0) {
            log_msg(LOG_LEVEL_ERROR, "failed to join progress_updater thread");
            exit(THREAD_ERROR);
        }
        log_msg(LOG_LEVEL_THREAD, "%10s: progress_updater thread finished", "(main)");
    }
}

void progress_status(progress_state new_state, const char* data) {
    pthread_mutex_lock(&progress_update_mutex);
    switch (new_state) {
        case PROGRESS_CONFIG:
        case PROGRESS_OLDDB:
        case PROGRESS_NEWDB:
        case PROGRESS_DISK:
        case PROGRESS_WRITEDB:
            if (state == new_state) {
                num_entries++;
            } else {
                update_state(new_state);
                num_entries = 0LU;
                num_skipped = 0LU;
            }
            free(path);
            path = NULL;
            if (data) {
                path = checked_strdup(data);
            }
            break;
        case PROGRESS_SKIPPED:
            num_skipped++;
            break;
        case PROGRESS_CLEAR:
        case PROGRESS_NONE:
            update_state(new_state);
            break;
    }
    pthread_mutex_unlock(&progress_update_mutex);
}
