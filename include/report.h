/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2010, 2019-2023 Rami Lehti, Pablo Virolainen,
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

#ifndef _REPORT_H_INCLUDED
#define _REPORT_H_INCLUDED
#include <stdbool.h>
#include <stdio.h>
#include "attributes.h"
#include "seltree.h"
#include "config.h"
#include "conf_ast.h"
#include "log.h"
#include "url.h"
#include "db_line.h"

/* report level */
typedef enum { /* preserve order */
    REPORT_LEVEL_MINIMAL = 1,
    REPORT_LEVEL_SUMMARY = 2,
    REPORT_LEVEL_DATABASE_ATTRIBUTES = 3,
    REPORT_LEVEL_LIST_ENTRIES = 4,
    REPORT_LEVEL_CHANGED_ATTRIBUTES = 5,
    REPORT_LEVEL_ADDED_REMOVED_ATTRIBUTES = 6,
    REPORT_LEVEL_ADDED_REMOVED_ENTRIES = 7,
} REPORT_LEVEL;

/* report format */
typedef enum {
    REPORT_FORMAT_PLAIN = 1,
    REPORT_FORMAT_JSON = 2,
} REPORT_FORMAT;

bool init_report_urls();

bool add_report_url(url_t* url, int, char*, char*);

REPORT_LEVEL get_report_level(char *);
REPORT_FORMAT get_report_format(char *);

void log_report_urls(LOG_LEVEL);

/*
 * gen_report()
 * Generate report based on the given node
 */
int gen_report(seltree* node);

typedef struct report_options {
    REPORT_LEVEL level;
    REPORT_FORMAT format;
} report_options;

extern report_options default_report_options;

typedef struct diff_attrs_entry {
    char* entry;
    DB_ATTR_TYPE old_attrs;
    DB_ATTR_TYPE new_attrs;
} diff_attrs_entry;

typedef struct report_t {
    url_t* url;
    FILE* fd;

    REPORT_LEVEL level;
    REPORT_FORMAT format;

    int detailed_init;
    int base16;
    int quiet;
    int summarize_changes;
    int grouped;
    bool append;

#ifdef WITH_E2FSATTRS
    long ignore_e2fsattrs;
#endif

    DB_ATTR_TYPE ignore_added_attrs;
    DB_ATTR_TYPE ignore_removed_attrs;
    DB_ATTR_TYPE ignore_changed_attrs;
    DB_ATTR_TYPE force_attrs;

    long ntotal;
    long nadd, nrem, nchg;

    diff_attrs_entry *diff_attrs_entries;
    int num_diff_attrs_entries;

    int linenumber;
    char* filename;
    char* linebuf;

} report_t;

void report_printf(report_t*, const char*, ...);

typedef struct report_format_module {
    void (*print_report_config_options)(report_t*);
    void (*print_report_databases)(report_t*);
    void (*print_report_details)(report_t*, seltree*);
    void (*print_report_diff_attrs_entries)(report_t*);
    void (*print_report_endtime_runtime)(report_t*, const char*, long);
    void (*print_report_entries)(report_t*, seltree*, const int);
    void (*print_report_footer)(report_t*);
    void (*print_report_header)(report_t*);
    void (*print_report_new_database_written)(report_t*);
    void (*print_report_outline)(report_t*);
    void (*print_report_report_options)(report_t*);
    void (*print_report_starttime_version)(report_t*, const char*, const char*);
    void (*print_report_summary)(report_t*);
} report_format_module;

char* get_file_type_string(mode_t);
char* get_summarize_changes_string(report_t*, seltree*);
char* get_summary_string(report_t*);
const char* get_report_level_string(REPORT_LEVEL);
int get_attribute_values(DB_ATTR_TYPE, db_line*,char* **, report_t* );
void print_databases_attrs(report_t *, void (*)(report_t *, db_line*));
void print_dbline_attrs(report_t *, db_line*, db_line*, DB_ATTR_TYPE, void (*)(report_t *, db_line*, db_line*, ATTRIBUTE));
void print_report_config_options(report_t *, void (*)(report_t *, config_option, const char*));
void print_report_details(report_t *, seltree*, void (*)(report_t *, db_line*, db_line*, DB_ATTR_TYPE));
void print_report_entries(report_t*, seltree*, const int, void (*)(report_t*, char*, int, seltree*));
void print_report_report_options(report_t *, void (*)(report_t *, config_option, const char*));

#endif
