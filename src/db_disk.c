/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2011, 2016-2017, 2019-2022 Rami Lehti,
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
#include "seltree_struct.h"
#include "seltree.h"
#include "gen_list.h"
#include "db.h"
#include "db_line.h"
#include "db_disk.h"
#include "util.h"
#include "queue.h"


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

static char *name_construct (const char *dirpath, const char *filename) {
    int dirpath_len = strlen (dirpath);
    int len = dirpath_len + strlen(filename) + (dirpath[dirpath_len-1] != '/'?1:0) + 1;
    char *ret = checked_malloc(len);
    snprintf(ret, len, "%s%s%s", dirpath, dirpath[dirpath_len-1] != '/'?"/":"", filename);
    log_msg(LOG_LEVEL_TRACE,"name_construct: dir: '%s' (%p) + filename: '%s' (%p): '%s' (%p)", dirpath, dirpath, filename, filename, ret, ret);
    return ret;
}

static void handle_matched_file(char *entry_full_path, DB_ATTR_TYPE attr, struct stat fs) {
    char *filename = checked_strdup(entry_full_path); /* not te be freed, reused as fullname in db_line */;
    db_line *line = get_file_attrs(filename, attr, &fs);
    add_file_to_tree(conf->tree, line, DB_NEW, NULL);
}

void scan_dir(char *root_path, bool dry_run) {
    char* full_path;
    rx_rule *rule = NULL;
    seltree *node = NULL;
    struct stat fs;

    log_msg(LOG_LEVEL_DEBUG,"scan_dir: process root directory '%s' (fullpath: '%s')", &root_path[conf->root_prefix_length], root_path);
    if (!get_file_status(root_path, &fs)) {
        match_result match = check_rxtree (&root_path[conf->root_prefix_length], conf->tree, &rule, get_restriction_from_perm(fs.st_mode));
        if (dry_run) {
            print_match(&root_path[conf->root_prefix_length], rule, match, get_restriction_from_perm(fs.st_mode));
        }
        if (!dry_run && match&(RESULT_EQUAL_MATCH|RESULT_SELECTIVE_MATCH)) {
            handle_matched_file(root_path, rule->attr, fs);
        }
    }

    queue_ts_t *stack = queue_init((int (*)(const void *, const void *)) strcmp);
    log_msg(LOG_LEVEL_TRACE, "initialized (sorted) scan stack queue %p", stack);

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
                    log_msg(log_level, "scan_dir: process child directory '%s' (fullpath: '%s'", &entry_full_path[conf->root_prefix_length], entry_full_path);
                    if (!get_file_status(entry_full_path, &fs)) {
                        rule = NULL;
                        node = NULL;
                        match_result match = check_rxtree (&entry_full_path[conf->root_prefix_length], conf->tree, &rule, get_restriction_from_perm(fs.st_mode));
                        switch (match) {
                            case RESULT_SELECTIVE_MATCH:
                                if (S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: selective match)", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                            // fall through
                            case RESULT_EQUAL_MATCH:
                                if (!dry_run) {
                                    handle_matched_file(entry_full_path, rule->attr, fs);
                                }
                                break;
                            case RESULT_PARTIAL_MATCH:
                                if (S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: partial match)", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                                break;
                            case RESULT_NO_MATCH:
                                node = get_seltree_node(conf->tree, &entry_full_path[conf->root_prefix_length]);
                                if(S_ISDIR(fs.st_mode) && node) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: existing tree node '%s' (%p))", &entry_full_path[conf->root_prefix_length], node->path, node);
                                    free_entry_full_path = false;
                                    queue_enqueue(stack, entry_full_path);
                                }
                                break;
                            case RESULT_PARTIAL_LIMIT_MATCH:
                                if(S_ISDIR(fs.st_mode)) {
                                    log_msg(log_level, "scan_dir: add child directory '%s' to scan stack (reason: partial limit match", &entry_full_path[conf->root_prefix_length]);
                                    queue_enqueue(stack, entry_full_path);
                                    free_entry_full_path = false;
                                }
                                break;
                            case RESULT_NO_LIMIT_MATCH:
                                break;
                        }
                        if (dry_run) {
                            print_match(&entry_full_path[conf->root_prefix_length], rule, match, get_restriction_from_perm(fs.st_mode));
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
    queue_free(stack);
}

void db_scan_disk(bool dry_run) {
    char* full_path=checked_malloc((conf->root_prefix_length+2)*sizeof(char));
    strncpy(full_path, conf->root_prefix, conf->root_prefix_length+1);
    strcat (full_path, "/");

    scan_dir(full_path, dry_run);

    free(full_path);
}

