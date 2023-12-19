/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2023 Hannes von Haugwitz
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
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "aide.h"
#include "progress.h"
#include "log.h"
#include "errorcodes.h"
#include "util.h"

#define BILLION  1000000000L;

pthread_t progress_updater_thread = 0LU;
pthread_mutex_t progress_update_mutex = PTHREAD_MUTEX_INITIALIZER;

static progress_state  state = PROGRESS_NONE;
static struct timespec time_start;
static long unsigned num_entries = 0;
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
        case PROGRESS_CLEAR:
        case PROGRESS_NONE:
            return NULL;
    }
    return NULL;
}

#define PROGRESS_FORMAT "[%02d:%02d] %s> %lu files, last: "

static void * progress_updater( __attribute__((unused)) void *arg) {
    const char *whoami = "(progress)";
    log_msg(LOG_LEVEL_THREAD, "%10s: initialized progress_updater thread", whoami);

    mask_sig(whoami);

    bool _continue = true;
    while (_continue) {
        pthread_mutex_lock(&progress_update_mutex);
        time_t now = time(NULL);
        int elapsed = (unsigned long) now - (unsigned long) conf->start_time;
        switch (state) {
            case PROGRESS_CONFIG:
            case PROGRESS_NEWDB:
            case PROGRESS_DISK:
            case PROGRESS_WRITEDB:
            case PROGRESS_OLDDB:
                if (conf->progress < 42) {
                    stderr_msg("terminal too small\r");
                } else {
                    if (path) {
                        size_t base_len = snprintf(NULL, 0, PROGRESS_FORMAT, elapsed/60, elapsed%60, get_state_string(state), num_entries);
                        long left = conf->progress-base_len;

                        char *ellipsis = "/...";
                        int ellipsis_len = 0;

                        char *suffix_path = path;
                        int prefix_len = 0;
                        if ((long) strlen(path) > left) {
                            char *first_slash = strchr(path+1, '/');
                            if (first_slash == NULL) {
                                first_slash = path;
                            }
                            ellipsis_len = strlen(ellipsis);
                            prefix_len = first_slash-path;
                            left -= prefix_len+ellipsis_len;

                            suffix_path = first_slash+1;

                            while ((long) strlen(suffix_path) > left) {
                                char *slash = strchr(suffix_path+1, '/');
                                if (slash) {
                                    suffix_path = slash;
                                } else {
                                    break;
                                }
                            }
                        }
                        if (left > 8) {
                            long suffix_len = strlen(suffix_path);
                            long suffix_start = left<suffix_len ? suffix_len-left : 0;
                            stderr_msg(PROGRESS_FORMAT "%.*s%.*s%s\r", elapsed/60, elapsed%60, get_state_string(state), num_entries, prefix_len, path, ellipsis_len, ellipsis, &suffix_path[suffix_start]);
                        } else {
                            stderr_msg("[%02d:%02d] %s> %lu files\r", elapsed/60, elapsed%60, get_state_string(state), num_entries);
                        }
                    } else {
                        stderr_msg("[%02d:%02d] %s> preparing\r", elapsed/60, elapsed%60, get_state_string(state));
                    }
                }
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

        long elapsed = time_now.tv_sec - time_start.tv_sec;
        long elapsed_minutes = elapsed/60;
        double elapsed_seconds = elapsed%60 + (double)( time_now.tv_nsec - time_start.tv_nsec ) / (double)BILLION;

        switch (state) {
            case PROGRESS_OLDDB:
                log_msg(log_level, "read %lu entries [%lu entries/s] from %s:%s in %ldm %.4lfs", num_entries, elapsed?num_entries/elapsed:num_entries, get_url_type_string((conf->database_in.url)->type), (conf->database_in.url)->value, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_NEWDB:
                log_msg(log_level, "read %lu entries [%lu entries/s] from %s:%s in %ldm %.4lfs", num_entries, elapsed?num_entries/elapsed:num_entries, get_url_type_string((conf->database_new.url)->type), (conf->database_new.url)->value, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_DISK:
                log_msg(log_level, "read %lu entries [%lu entries/s] from file system in %ldm %.4lfs", num_entries, elapsed?num_entries/elapsed:num_entries, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_CONFIG:
                log_msg(log_level, "parsed %lu config files [%lu files/s] in %ldm %.4lfs", num_entries, elapsed?num_entries/elapsed:num_entries, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_WRITEDB:
                log_msg(log_level, "wrote %lu entries [%lu entries/s] to %s:%s in %ldm %.4lfs", num_entries, elapsed?num_entries/elapsed:num_entries, get_url_type_string((conf->database_out.url)->type), (conf->database_out.url)->value, elapsed_minutes, elapsed_seconds);
                break;
            case PROGRESS_CLEAR:
            case PROGRESS_NONE:
                /* no logging */
                break;
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
            }
            free(path);
            path = NULL;
            if (data) {
                path = checked_strdup(data);
            }
            break;
        case PROGRESS_CLEAR:
        case PROGRESS_NONE:
            update_state(new_state);
            break;
    }
    pthread_mutex_unlock(&progress_update_mutex);
}
