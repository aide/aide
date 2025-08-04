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
#include <signal.h>
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

typedef struct progress_worker_status {
    progress_worker_state state;
    char * data;
    int percentage;
} progress_worker_status;

static progress_worker_status *worker_status = NULL;
static bool progress_worker_status_enabled = false;

static char* *lines = NULL;

static char *get_worker_state_string(progress_worker_state s) {
    switch (s) {
        case progress_worker_state_idle:
            return "idle";
        case progress_worker_state_processing:
            return "processing";
    }
    return NULL;
}

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

static void progress_sig_handler(int signum) {
    struct winsize winsize;
    switch(signum){
        case SIGWINCH :
            if(ioctl(STDERR_FILENO, TIOCGWINSZ, &winsize) == -1) {
                conf->progress = 80;
                progress_worker_status_enabled = false;
            } else {
                conf->progress = winsize.ws_col;
                progress_worker_status_enabled = (winsize.ws_row > (conf->num_workers + 10));
            }
        break;
    }
}

static void * progress_updater( __attribute__((unused)) void *arg) {
    const char *whoami = "(progress)";
    log_msg(LOG_LEVEL_THREAD, "%10s: initialized progress_updater thread", whoami);

    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);

    if(pthread_sigmask(SIG_BLOCK, &set, NULL)) {
        log_msg(LOG_LEVEL_ERROR, "%10s: pthread_sigmask failed to set mask of blocked signals", whoami);
        exit(THREAD_ERROR);
    }

    log_msg(LOG_LEVEL_DEBUG, "%10s: initialize signal handler for SIGWINCH", whoami);
    signal(SIGWINCH, progress_sig_handler);

    bool _continue = true;

    while (_continue) {
        pthread_mutex_lock(&progress_update_mutex);
        int width = conf->progress;
        time_t now = time(NULL);
        int elapsed = (unsigned long) now - (unsigned long) conf->start_time;
        int num_of_lines = 1;
        switch (state) {
            case PROGRESS_DISK:
                if (progress_worker_status_enabled && worker_status) {
                    for (long i = 0 ; i < conf->num_workers; ++i) {
                        int n = 0;
                        int left = width;
                        lines[i+1] = checked_malloc(left + 1);
                        n += snprintf(lines[i+1], left, "worker #%0*ld> %10s", 2, i+1,
                                get_worker_state_string(worker_status[i].state)
                                );
                        left = width - n;
                        if (worker_status[i].data && left > 12) {
                            n += print_path(&(lines[i+1])[n], worker_status[i].data, " ", left);
                            left = width - n;;
                            if (worker_status[i].percentage > 0 && left >= 7) {
                                snprintf(&(lines[i+1])[n], left, " (%2d%%)", worker_status[i].percentage);
                            }
                        }
                        num_of_lines++;
                    }
                }
                /* fall through */
            case PROGRESS_CONFIG:
            case PROGRESS_NEWDB:
            case PROGRESS_SKIPPED:
            case PROGRESS_WRITEDB:
            case PROGRESS_OLDDB:
                lines[0] = get_progress_bar_string(get_state_string(state), path, num_entries, num_skipped, elapsed, width);
                stderr_multi_lines(lines, num_of_lines);
                for (int i = 0 ; i < num_of_lines; ++i) {
                    free(lines[i]);
                    lines[i] = NULL;
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

void progress_worker_state_init(void) {
    struct winsize winsize;
    pthread_mutex_lock(&progress_update_mutex);
    progress_worker_status_enabled = false;
    if (lines && conf->progress >= 0 && conf->num_workers > 0) {
        lines = checked_realloc(lines, (conf->num_workers + 1) * sizeof(char*));
        worker_status = checked_malloc(conf->num_workers * sizeof(progress_worker_status));
        for (int i = 0 ; i < conf->num_workers ; ++i) {
            worker_status[i].state = progress_worker_state_idle;
            worker_status[i].data = NULL;
            worker_status[i].percentage = 0;
        }
        if(ioctl(STDERR_FILENO, TIOCGWINSZ, &winsize) != -1) {
            progress_worker_status_enabled = (winsize.ws_row > (conf->num_workers + 10));
        }
    }
    pthread_mutex_unlock(&progress_update_mutex);
}

bool progress_start(void) {
    struct winsize winsize;

    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &winsize) == -1) {
        conf->progress = 80;
    } else {
        conf->progress = winsize.ws_col;
    }
    lines = checked_malloc(1 * sizeof(char*));
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
    free(lines);
    if (conf->num_workers) {
        free(worker_status);
    }
}

void update_progress_status(progress_state new_state, const char* data) {
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

void update_progress_worker_progress(int index, int percentage) {
    pthread_mutex_lock(&progress_update_mutex);
    if (worker_status) {
        worker_status[index-1].percentage = percentage;
    }
    pthread_mutex_unlock(&progress_update_mutex);
}

void update_progress_worker_status(int index, progress_worker_state new_state, void* data) {
    pthread_mutex_lock(&progress_update_mutex);
    if (worker_status) {
        switch (new_state) {
            case progress_worker_state_processing:
                if (data) {
                    free(worker_status[index-1].data);
                    worker_status[index-1].data = checked_strdup(data);
                }
                break;
            case progress_worker_state_idle:
                free(worker_status[index-1].data);
                worker_status[index-1].data = NULL;
                break;
        }
        worker_status[index-1].state = new_state;
    }
    pthread_mutex_unlock(&progress_update_mutex);
}
