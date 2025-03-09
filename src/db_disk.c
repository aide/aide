/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2011, 2016-2017, 2019-2025 Rami Lehti,
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef HAVE_FSTYPE
#include <sys/vfs.h>
#endif
#include <unistd.h>
#include "aide.h"
#include "attributes.h"
#include "db.h"
#include "db_config.h"
#include "db_disk.h"
#include "db_line.h"
#include "errorcodes.h"
#include "gen_list.h"
#include "log.h"
#include "queue.h"
#include "rx_rule.h"
#include "seltree_struct.h"
#include "util.h"

queue_ts_t *queue_worker_entries = NULL;

struct worker_args {
    long worker_index;
    bool dry_run;
};

typedef struct worker_thread {
    pthread_t thread;
    struct worker_args args;
} worker_thread;

static char *name_construct (const char *dirpath, const char *filename) {
    int dirpath_len = strlen (dirpath);
    int len = dirpath_len + strlen(filename) + (dirpath[dirpath_len-1] != '/'?1:0) + 1;
    char *ret = checked_malloc(len);
    snprintf(ret, len, "%s%s%s", dirpath, dirpath[dirpath_len-1] != '/'?"/":"", filename);
    log_msg(LOG_LEVEL_TRACE,"name_construct: dir: '%s' (%p) + filename: '%s' (%p): '%s' (%p)", dirpath, (void*) dirpath, filename, (void*) filename, ret, (void*) ret);
    return ret;
}

static void process_path(char *path, bool dry_run, const char *whoami) {
    db_line *line = NULL;

    log_msg(LOG_LEVEL_DEBUG, "process '%s' (fullpath: '%s')", &path[conf->root_prefix_length], path);

    int fd = -1;
    int errno_read = 0;
#ifdef O_NOATIME
    if ((fd = open(path, O_NOFOLLOW | O_RDONLY | O_NOATIME | O_NONBLOCK)) == -1) {
        log_msg(LOG_LEVEL_DEBUG, "%s> open() with O_NOATIME flag failed: %s (retrying without O_NOATIME)", path, strerror(errno));
#endif
        fd = open(path, O_NOFOLLOW | O_RDONLY | O_NONBLOCK);
#ifdef O_NOATIME
    }
#endif
    struct stat stat;
#ifdef HAVE_FSTYPE
        struct statfs statfs;
#endif
    if (fd == -1) {
#ifdef O_PATH
        log_msg(LOG_LEVEL_DEBUG, "%s> open() with O_RDONLY flag failed: %s (retrying with O_PATH)", path, strerror(errno));
        errno_read = errno;
        fd = open(path, O_NOFOLLOW | O_PATH);
    }
    if (fd == -1) {
        log_msg(LOG_LEVEL_WARNING, "open() failed for '%s': %s (skipping)", path, strerror(errno));
    } else {
        if (fstat(fd, &stat) == -1) {
            log_msg(LOG_LEVEL_WARNING, "fstat() failed for %s: %s", path, strerror(errno));
        }
#else
        log_msg(LOG_LEVEL_DEBUG, "%s> open() with O_RDONLY flag failed: %s (falling back to lstat())", path, strerror(errno));
        errno_read = errno;
    }
    if(lstat(path, &stat) == -1) {
        log_msg(LOG_LEVEL_WARNING, "lstat() failed for '%s': %s (skipping)", path, strerror(errno));
    } else {
#endif
        file_t file = {
            .name = &path[conf->root_prefix_length],
            .type = get_f_type_from_perm(stat.st_mode),
#ifdef HAVE_FSTYPE
            .fs_type = 0UL,
#endif
        };
#ifdef HAVE_FSTYPE
        if (fstatfs(fd, &statfs) == -1) {
            log_msg(LOG_LEVEL_WARNING, "fstatfs() failed for %s: %s", path, strerror(errno));
        } else {
            file.fs_type = statfs.f_type;
        }
#endif

        match_t path_match = check_rxtree(file, conf->tree, "disk", false);
        if (S_ISDIR(stat.st_mode)) {
            DIR *dir = NULL;
            switch (path_match.result) {
                case RESULT_SELECTIVE_MATCH:
                case RESULT_EQUAL_MATCH:
                case RESULT_PARTIAL_MATCH:
                case RESULT_RECURSIVE_NEGATIVE_MATCH:
                case RESULT_PARTIAL_LIMIT_MATCH:
                    log_msg(LOG_LEVEL_DEBUG, "read directory contents of '%s' (reason: %s)", path, get_match_result_desc(path_match.result));
                    int dupfd = dup(fd);
                    if (dupfd == -1) {
                        log_msg(LOG_LEVEL_WARNING, "'%s': failed to duplicate file descriptor: %s", path, strerror(errno));
                    } else {
                        if ((dir = fdopendir(dupfd)) == NULL) {
                            log_msg(LOG_LEVEL_WARNING, "failed to open directory '%s' for reading directory contents: %s (skipping recursion)", path,
                                    strerror(errno == EBADF && errno_read ? errno_read : errno));
                        } else {
                            const struct dirent *entp = NULL;
                            while ((entp = readdir(dir)) != NULL) {
                                if (strcmp(entp->d_name, ".") != 0 && strcmp(entp->d_name, "..") != 0) {
                                    char *entry_full_path = name_construct(path, entp->d_name);
                                    log_msg(LOG_LEVEL_THREAD,
                                            "%10s: add entry %p to queue of worker entries (filename: '%s')", whoami,
                                            (void *)entry_full_path, entry_full_path);
                                    queue_ts_enqueue(queue_worker_entries, entry_full_path, whoami);
                                }
                            }
                            if (closedir(dir) < 0) {
                                log_msg(LOG_LEVEL_WARNING, "closedir() failed for '%s': %s", path, strerror(errno));
                            }
                        }
                    }
                    break;
                case RESULT_NON_RECURSIVE_NEGATIVE_MATCH:
                case RESULT_NEGATIVE_PARENT_MATCH:
                case RESULT_NO_RULE_MATCH:
                case RESULT_NO_LIMIT_MATCH:
                case RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH:
                    log_msg(LOG_LEVEL_DEBUG, "do NOT read directory contents of '%s' (reason: %s)", path, get_match_result_desc(path_match.result));
                    break;
            }
        }
        if (dry_run) {
            print_match(file, path_match);
        } else {
            if (path_match.result & RESULT_SELECTIVE_MATCH || path_match.result & RESULT_EQUAL_MATCH) {

                DB_ATTR_TYPE attrs = path_match.rule->attr;
                char *attrs_str = NULL;

                /* disable unsupported attributes */
                DB_ATTR_TYPE attrs_to_disable;
                LOG_LEVEL log_level_unavailable = LOG_LEVEL_DEBUG;
                if (!S_ISREG(stat.st_mode)) {
                    /* hashsum attributes */
                    attrs_to_disable = attrs & get_hashes(false);
                    if (attrs_to_disable) {
                        attrs_str = diff_attributes(0, attrs_to_disable);
                        log_msg(log_level_unavailable, "%s> disabling hashsum attribute(s) for non-regular file: %s)",
                                path, attrs_str);
                        free(attrs_str);
                        attrs &= ~attrs_to_disable;
                    }
#ifdef WITH_CAPABILITIES
                    /* capability attribute */
                    attrs_to_disable = attrs & ATTR(attr_capabilities);
                    if (attrs_to_disable) {
                        log_msg(log_level_unavailable, "%s> disabling capability attribute for non-regular file", path);
                        attrs &= ~attrs_to_disable;
                    }
#endif
                }
                if (!S_ISLNK(stat.st_mode)) {
                    /* linkname attribute */
                    attrs_to_disable = attrs & ATTR(attr_linkname);
                    if (attrs_to_disable) {
                        log_msg(log_level_unavailable, "%s> disabling linkname attribute for non-symlink file", path);
                        attrs &= ~attrs_to_disable;
                    }
                }
#ifdef WITH_E2FSATTRS
                if (!(S_ISDIR(stat.st_mode) || S_ISREG(stat.st_mode))) {
                    /* e2fsattrs attribute */
                    attrs_to_disable = attrs & ATTR(attr_e2fsattrs);
                    if (attrs_to_disable) {
                        log_msg(log_level_unavailable,
                                "%s> disabling e2fsattrs attribute for non-directory/non-regular file", path);
                        attrs &= ~attrs_to_disable;
                    }
                }
#endif
                if (errno_read
#ifdef O_PATH
                        && errno_read != ELOOP
#endif
                   ) {
                    /* disable attributes requiring read permissions */
                    attrs_to_disable = attrs & (get_hashes(false)
#ifdef WITH_E2FSATTRS
                            | ATTR(attr_e2fsattrs)
#endif
                    );
                    if (attrs_to_disable) {
                        attrs_str = diff_attributes(0, attrs_to_disable);
                        log_msg(
                                LOG_LEVEL_WARNING,
                                "failed to open '%s' for reading: %s (disabling attributes requiring read permissions: %s)",
                                path, strerror(errno_read), attrs_str);
                        free(attrs_str);
                        attrs &= ~attrs_to_disable;
                    }
                }

                DB_ATTR_TYPE transition_hashsums = 0LL;
                if (conf->action & DO_COMPARE && attrs & get_hashes(false)) {
                    const seltree *node = get_seltree_node(conf->tree, &path[conf->root_prefix_length]);
                    if (node && node->old_data) {
                        transition_hashsums = get_transition_hashsums(
                                (node->old_data)->filename, (node->old_data)->attr, &path[conf->root_prefix_length], attrs);
                    }
                }

                disk_entry entry = {
                    .filename = checked_strdup(path),
                    .fs = stat,
#ifdef HAVE_FSTYPE
                    .fs_type = file.fs_type,
#endif
                    .fd = fd,
                };

                attrs_str = diff_attributes(0, attrs);
                log_msg(LOG_LEVEL_DEBUG, "%s> requested attributes: %s", entry.filename, attrs_str);
                free(attrs_str);

                line = get_file_attrs(&entry, attrs, transition_hashsums);

                /* attr_filename is always needed/returned but never requested */
                DB_ATTR_TYPE returned_attr = (~ATTR(attr_filename) & line->attr);
                attrs_str = diff_attributes(0, returned_attr);
                log_msg(LOG_LEVEL_DEBUG, "%s> returned attributes: %llu (%s)", entry.filename, returned_attr, attrs_str);
                free(attrs_str);
                if (returned_attr ^ attrs) {
                    attrs_str = diff_attributes(attrs, returned_attr);
                    log_msg(LOG_LEVEL_DEBUG, "%s> requested (%llu) and returned (%llu) attributes are not equal: %s", entry.filename, attrs, returned_attr, attrs_str);
                    free(attrs_str);
                }

                add_file_to_tree(conf->tree, line, DB_NEW | DB_DISK, NULL, &entry);
            }
        }
#ifndef O_PATH
        if (fd != -1) {
#endif
            if (close(fd) < 0) {
                log_msg(LOG_LEVEL_WARNING, "close() failed for '%s': %s", path, strerror(errno));
            }
#ifndef O_PATH
        }
#endif
    }
}

static void process_disk_entries(bool dry_run, const char *whoami) {
    while (1) {
        log_msg(LOG_LEVEL_THREAD, "%10s: process_disk_entries: wait for entries", whoami);
        char *data = queue_ts_dequeue_wait(queue_worker_entries, whoami);
        if (data) {
            log_msg(LOG_LEVEL_THREAD, "%10s: process_disk_entries: got entry %p from queue of worker entries (path: '%s' )", whoami, (void*) data, data);
            process_path(data, dry_run, whoami);
            free(data);
        } else {
            log_msg(LOG_LEVEL_THREAD, "%10s: process_disk_entries: queue empty", whoami);
            break;
        }
    }
}

static void * worker(void *arg) {
    struct worker_args args = *(struct worker_args *)arg;
    char whoami[32];
    snprintf(whoami, 32, "(work-%03li)", args.worker_index);

    mask_sig(whoami);

    queue_ts_register(queue_worker_entries, whoami);

    log_msg(LOG_LEVEL_THREAD, "%10s: worker: initialized worker thread #%ld", whoami, args.worker_index);

    process_disk_entries(args.dry_run, whoami);

    log_msg(LOG_LEVEL_THREAD, "%10s: worker: exit thread", whoami);
    return (void *) pthread_self();
}

void db_scan_disk(bool dry_run) {
    const char *whoami_main = "(main)";

    char* full_path=checked_malloc((conf->root_prefix_length+2)*sizeof(char)); /* freed in process_disk_entries() */
    strncpy(full_path, conf->root_prefix, conf->root_prefix_length+1);
    strcat (full_path, "/");

    if (dry_run || conf->num_workers == 0) {
        queue_worker_entries = queue_ts_init(); /* freed below */
        queue_ts_enqueue(queue_worker_entries, full_path, whoami_main);
        queue_ts_release(queue_worker_entries, whoami_main);

        process_disk_entries(dry_run, whoami_main);

        queue_ts_free(queue_worker_entries);
    } else {
        queue_worker_entries = queue_ts_init(); /* freed below */
        log_msg(LOG_LEVEL_THREAD, "initialized worker entries queue %p", (void*) queue_worker_entries);

        worker_thread *worker_threads = checked_malloc(conf->num_workers * sizeof(worker_thread)); /* freed below */

        for (int i = 0 ; i < conf->num_workers ; ++i) {
            worker_threads[i].args.worker_index = i + 1L;
            worker_threads[i].args.dry_run = dry_run;
            if (pthread_create(&worker_threads[i].thread, NULL, &worker, (void *) &worker_threads[i].args) != 0) {
                log_msg(LOG_LEVEL_ERROR, "failed to start file attributes worker thread #%d", i+1);
                exit(THREAD_ERROR);
            }
        }

        queue_ts_enqueue(queue_worker_entries, full_path, whoami_main);
        queue_ts_release(queue_worker_entries, whoami_main);

        log_msg(LOG_LEVEL_THREAD, "wait for worker threads to be finished");
        for (int i = 0 ; i < conf->num_workers ; ++i) {
            if (pthread_join(worker_threads[i].thread, NULL) != 0) {
                log_msg(LOG_LEVEL_WARNING, "failed to join file attributes thread #%d", i);
            }
            log_msg(LOG_LEVEL_THREAD, "worker thread #%d finished", i);
        }
        free(worker_threads);
        queue_ts_free(queue_worker_entries);
    }
}
