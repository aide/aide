/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2011, 2016-2017, 2019-2024 Rami Lehti,
 *               Pablo Virolainen, Mike Markley, Richard van den Berg,
 *               Hannes von Haugwitz
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
#include "aide.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include "db_config.h"
#include "log.h"
#include "rx_rule.h"
#include "seltree.h"
#include "gen_list.h"
#include "db.h"
#include "db_line.h"
#include "db_disk.h"
#include "util.h"
#include "queue.h"
#include "errorcodes.h"

#include <pthread.h>

static int get_file_status(char *filename, struct stat *fs) {
    int sres = 0;
    sres = lstat(filename,fs);
    if(sres == -1){
        char* er = strerror(errno);
        if (er == NULL) {
            log_msg(LOG_LEVEL_WARNING, "get_file_status: lstat() failed for %s. strerror() failed with %i", filename, errno);
        } else {
            log_msg(LOG_LEVEL_WARNING, "get_file_status: lstat() failed for %s: %s", filename, er);
        }
    }
    return sres;
}

queue_ts_t *queue_worker_files = NULL;
queue_ts_t *queue_database_entries = NULL;

pthread_t wait_for_workers_thread = 0;

pthread_t *file_attributes_threads = 0;

const char *whoami_main = "(main)";

static char *name_construct (const char *dirpath, const char *filename) {
    int dirpath_len = strlen (dirpath);
    int len = dirpath_len + strlen(filename) + (dirpath[dirpath_len-1] != '/'?1:0) + 1;
    char *ret = checked_malloc(len);
    snprintf(ret, len, "%s%s%s", dirpath, dirpath[dirpath_len-1] != '/'?"/":"", filename);
    log_msg(LOG_LEVEL_TRACE,"name_construct: dir: '%s' (%p) + filename: '%s' (%p): '%s' (%p)", dirpath, (void*) dirpath, filename, (void*) filename, ret, (void*) ret);
    return ret;
}

typedef struct scan_dir_entry {
    char *filename;
    DB_ATTR_TYPE attr;
    struct stat fs;
} scan_dir_entry;

typedef struct database_entry {
    db_line *line;
    struct stat fs;
} database_entry;

static void handle_matched_file(char *entry_full_path, DB_ATTR_TYPE attr, struct stat fs) {
    char *filename = checked_strdup(entry_full_path); /* not te be freed, reused as fullname in db_line */;
    if (conf->num_workers) {
        scan_dir_entry *data;
        data = checked_malloc(sizeof(scan_dir_entry)); /* freed in file_attrs_worker */
        data->filename = filename;
        data->attr = attr;
        data->fs = fs;
        log_msg(LOG_LEVEL_THREAD, "%10s: scan_dir: add entry %p to list of worker files (filename: '%s' (%p))", whoami_main,  (void*) data, data->filename, (void*) data->filename);
        queue_ts_enqueue(queue_worker_files, data, whoami_main);
    } else {
        db_line *line = get_file_attrs(filename, attr, &fs);
        add_file_to_tree(conf->tree, line, DB_NEW|DB_DISK, NULL, &fs);
    }
}

void scan_dir(char *root_path, bool dry_run) {
    char* full_path;
    struct stat fs;

    log_msg(LOG_LEVEL_DEBUG,"scan_dir: process root directory '%s' (fullpath: '%s')", &root_path[conf->root_prefix_length], root_path);
    if (!get_file_status(root_path, &fs)) {
        match_t path_match = check_rxtree (&root_path[conf->root_prefix_length], conf->tree, get_restriction_from_perm(fs.st_mode), "disk", false);
        if (dry_run) {
            print_match(&root_path[conf->root_prefix_length], path_match, get_restriction_from_perm(fs.st_mode));
        }
        if (!dry_run && path_match.result&(RESULT_EQUAL_MATCH|RESULT_SELECTIVE_MATCH)) {
            handle_matched_file(root_path, path_match.rule->attr, fs);
        }
        if (path_match.result & (RESULT_NO_RULE_MATCH|RESULT_NON_RECURSIVE_NEGATIVE_MATCH|RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH)) {
            return;
        }
    }

    queue_ts_t *stack = queue_init(NULL);
    log_msg(LOG_LEVEL_TRACE, "initialized scan stack queue %p", (void*) stack);

    queue_enqueue(stack, checked_strdup(root_path)); /* freed below */

    while((full_path = queue_dequeue(stack)) != NULL) {
        DIR *dir;
        char *file_path = &full_path[conf->root_prefix_length];
        log_msg(LOG_LEVEL_DEBUG,"scan_dir: process directory '%s' (fullpath: '%s')", file_path, full_path);
        if((dir = opendir(full_path)) == NULL) {
            log_msg(LOG_LEVEL_WARNING,"opendir() failed for '%s' (fullpath: '%s'): %s", file_path, full_path, strerror(errno));
        } else {
            struct dirent *entp;
            while ((entp = readdir(dir)) != NULL) {
                LOG_LEVEL log_level = LOG_LEVEL_TRACE;
                if (strcmp(entp->d_name, ".") != 0 && strcmp(entp->d_name, "..") != 0) {
                    char *entry_full_path = name_construct(full_path, entp->d_name);
                    bool free_entry_full_path = true;
                    log_msg(log_level, "scan_dir: process child directory '%s' (fullpath: '%s')", &entry_full_path[conf->root_prefix_length], entry_full_path);
                    if (!get_file_status(entry_full_path, &fs)) {
                        match_t path_match = check_rxtree (&entry_full_path[conf->root_prefix_length], conf->tree, get_restriction_from_perm(fs.st_mode), "disk", false);
                        switch (path_match.result) {
                            case RESULT_SELECTIVE_MATCH:
                            case RESULT_EQUAL_MATCH:
                                if (S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: selective/equal match)", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                                if (!dry_run) {
                                    handle_matched_file(entry_full_path, path_match.rule->attr, fs);
                                }
                                break;
                            case RESULT_PARTIAL_MATCH:
                                if (S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: partial match)", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                                break;
                            case RESULT_RECURSIVE_NEGATIVE_MATCH:
                                if (S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: recursive negative match)", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                                break;
                            case RESULT_PARTIAL_LIMIT_MATCH:
                                if(S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: partial limit match)", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                                break;
                            case RESULT_NON_RECURSIVE_NEGATIVE_MATCH:
                                if(S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: do NOT add child directory '%s' to scan stack (reason: non-recursive negative match)", &entry_full_path[conf->root_prefix_length]);
                                }
                                break;
                            case RESULT_NEGATIVE_PARENT_MATCH:
                            case RESULT_NO_RULE_MATCH:
                            case RESULT_NO_LIMIT_MATCH:
                            case RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH:
                                break;
                        }
                        if (dry_run) {
                            print_match(&entry_full_path[conf->root_prefix_length], path_match, get_restriction_from_perm(fs.st_mode));
                        }
                    }
                    if (free_entry_full_path) {
                        free(entry_full_path);
                    }
                }
            }
            closedir(dir);
        }
        free(full_path);
        full_path = NULL;
    }
    if (conf->num_workers && !dry_run) {
        queue_ts_release(queue_worker_files, whoami_main);
    }
    queue_free(stack);
}

static void * add2tree( __attribute__((unused)) void *arg) {
    const char *whoami = "(add2tree)";

    mask_sig(whoami);

    log_msg(LOG_LEVEL_THREAD, "%10s: wait for database entries", whoami);
    database_entry *data;
    while ((data = queue_ts_dequeue_wait(queue_database_entries, whoami)) != NULL) {
        log_msg(LOG_LEVEL_THREAD, "%10s: got line '%s'", whoami, (data->line)->filename);
        add_file_to_tree(conf->tree, data->line, DB_NEW|DB_DISK, NULL, &data->fs);
        free(data);
    }
    queue_ts_free(queue_database_entries);
    log_msg(LOG_LEVEL_TRACE, "%10s: finished (queue empty)", whoami);

    return (void *) pthread_self();
}

void db_scan_disk(bool dry_run) {
    char* full_path=checked_malloc((conf->root_prefix_length+2)*sizeof(char));
    strncpy(full_path, conf->root_prefix, conf->root_prefix_length+1);
    strcat (full_path, "/");

    pthread_t add2tree_thread = 0;

    if (!dry_run && conf->num_workers) {
        if (pthread_create(&add2tree_thread, NULL, &add2tree, NULL) != 0) {
            log_msg(LOG_LEVEL_ERROR, "failed to start add2tree thread");
            exit(THREAD_ERROR);
        }
    }

    scan_dir(full_path, dry_run);

    if (!dry_run && conf->num_workers) {
        if (pthread_join(add2tree_thread, NULL) != 0) {
            log_msg(LOG_LEVEL_ERROR, "failed to join add2tree thread");
            exit(THREAD_ERROR);
        }
    }

    free(full_path);
}

static void * file_attrs_worker( __attribute__((unused)) void *arg) {
    long worker_index = (long) arg;
    char whoami[32];
    snprintf(whoami, 32, "(work-%03li)", worker_index );

    mask_sig(whoami);

    log_msg(LOG_LEVEL_THREAD, "%10s: file_attrs_worker: initialized worker thread #%ld", whoami, worker_index);

    while (1) {
        log_msg(LOG_LEVEL_THREAD, "%10s: file_attrs_worker: check/wait for files", whoami);
        scan_dir_entry *data = queue_ts_dequeue_wait(queue_worker_files, whoami);
        if (data) {
            log_msg(LOG_LEVEL_THREAD, "%10s: file_attrs_workers: got entry %p from list of files (filename: '%s' (%p))", whoami, (void*) data, data->filename, (void*) data->filename);

            db_line *line = get_file_attrs (data->filename, data->attr, &data->fs);
            database_entry *db_data;
            db_data = checked_malloc(sizeof(database_entry)); /* freed in db_scan_disk */
            db_data->line = line;
            db_data->fs = data->fs;
            log_msg(LOG_LEVEL_THREAD, "%10s: file_attrs_worker: add entry %p to list of database entries (filename: '%s')", whoami, (void*) line, line->filename);
            queue_ts_enqueue(queue_database_entries, db_data, whoami);

            free(data);
        } else {
            log_msg(LOG_LEVEL_THREAD, "%10s: file_attrs_worker: queue empty, exit thread", whoami);
            break;
        }
    }

    return (void *) pthread_self();
}

static void * wait_for_workers( __attribute__((unused)) void *arg) {
    const char *whoami = "(wait)";

    mask_sig(whoami);

    log_msg(LOG_LEVEL_THREAD, "%10s: wait for file_attrs_worker threads to be finished", whoami);
    for (int i = 0 ; i < conf->num_workers ; ++i) {
        if (pthread_join(file_attributes_threads[i], NULL) != 0) {
            log_msg(LOG_LEVEL_WARNING, "failed to join file attributes thread #%d", i);
        }
        log_msg(LOG_LEVEL_THREAD, "%10s: file_attrs_worker thread #%d finished", whoami, i);
    }
    free(file_attributes_threads);
    queue_ts_release(queue_database_entries, whoami);
    queue_ts_free(queue_worker_files);
    return (void *) pthread_self();
}

int db_disk_start_threads(void) {
    queue_database_entries = queue_ts_init(NULL); /* freed in add2tree */
    log_msg(LOG_LEVEL_THREAD, "%10s: initialized database entries queue %p", whoami_main, (void*) queue_database_entries);
    queue_worker_files = queue_ts_init(NULL); /* freed in wait_for_workers */
    log_msg(LOG_LEVEL_THREAD, "%10s: initialized worker files queue %p", whoami_main, (void*) queue_worker_files);

    file_attributes_threads = checked_malloc(conf->num_workers * sizeof(pthread_t)); /* freed in wait_for_workers */

    for (int i = 0 ; i < conf->num_workers ; ++i) {
        if (pthread_create(&file_attributes_threads[i], NULL, &file_attrs_worker, (void *) (i+1L)) != 0) {
            log_msg(LOG_LEVEL_ERROR, "failed to start file attributes worker thread #%d", i+1);
            return RETFAIL;
        }
    }
    if (pthread_create(&wait_for_workers_thread, NULL, &wait_for_workers, NULL) != 0) {
        log_msg(LOG_LEVEL_ERROR, "failed to start wait_for_workers thread");
        return RETFAIL;
    }
    return RETOK;
}

int db_disk_finish_threads(void) {
    if (pthread_join(wait_for_workers_thread, NULL) != 0) {
        log_msg(LOG_LEVEL_ERROR, "failed to join wait_for_workers thread");
        return RETFAIL;
    }
    log_msg(LOG_LEVEL_THREAD, "%10s: wait_for_workers thread finished", whoami_main);
    return RETOK;
}
