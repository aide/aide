/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2022,2023 Hannes von Haugwitz
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

#include <stdlib.h>
#include "config.h"
#include "aide.h"
#include "attributes.h"
#include "conf_ast.h"
#include "db.h"
#include "db_config.h"
#include "db_line.h"
#include "report.h"
#include "seltree.h"
#include "stdbool.h"
#include "url.h"

#define JSON_FMT_ARRAY_BEGIN "%*c\"%s\": [\n"
#define JSON_FMT_ARRAY_ELEMENT_INNER "%*c\"%s\",\n"
#define JSON_FMT_ARRAY_ELEMENT_LAST "%*c\"%s\"\n"
#define JSON_FMT_ARRAY_ELEMENT_PLAIN "%*c\"%s\""
#define JSON_FMT_ARRAY_END "%*c],\n"
#define JSON_FMT_ARRAY_END_PLAIN "%*c]"
#define JSON_FMT_LONG "%*c\"%s\": %ld,\n"
#define JSON_FMT_LONG_LAST "%*c\"%s\": %ld\n"
#define JSON_FMT_OBJECT_BEGIN "%*c\"%s\": {\n"
#define JSON_FMT_OBJECT_END "%*c},\n"
#define JSON_FMT_OBJECT_END_PLAIN "%*c}"
#define JSON_FMT_STRING_COMMA "%*c\"%s\": \"%s\",\n"
#define JSON_FMT_STRING_LAST "%*c\"%s\": \"%s\"\n"
#define JSON_FMT_STRING_PLAIN "%*c\"%s\": \"%s\""

bool line_first = true;
bool database_first = true;
bool databases_first = true;
bool details_first = true;
bool attributes_first = true;

static int _escape_json_string(const char *src, char *escaped_string) {
    size_t i;
    int n = 0;

    for (i = 0; i < strlen(src); ++i) {
        if (src[i] == '\\') {
            if (escaped_string) { escaped_string[n] = '\\'; }
            n++;
        }
        if (escaped_string) { escaped_string[n] = src[i]; }
        n++;
    }
    if (escaped_string) { escaped_string[n] = '\0'; }
    n++;

    return n;
}

static char *_get_escaped_json_string(const char *src) {
    char *str = NULL;
    int n = _escape_json_string(src, str);
    str = checked_malloc(n);
    _escape_json_string(src, str);
    return str;
}

static void _print_config_option(report_t *report, config_option option, const char* value) {
    char *escaped_value = _get_escaped_json_string(value);
    report_printf(report, JSON_FMT_STRING_COMMA, 2, ' ', config_options[option].config_name, escaped_value);
    free(escaped_value);
}

static char* _get_value_format(ATTRIBUTE attribute) {
    switch(attribute) {
        case attr_uid:
        case attr_gid:
        case attr_size:
        case attr_sizeg:
        case attr_inode:
        case attr_bcount:
        case attr_linkcount:
            return "%*c\"%s\": %s";
        default:
            return "%*c\"%s\": \"%s\"";
    }
}

static void print_line_json(report_t* report, char* filename, int node_checked, seltree* node) {
    if (line_first) { line_first=false; }
    else { report_printf(report,",\n"); }

    char *escacped_filename = _get_escaped_json_string(filename);

    if(report->summarize_changes) {
        char* summary = get_summarize_changes_string(report, node);
        report_printf(report, JSON_FMT_STRING_PLAIN, 4, ' ', escacped_filename, summary);
        free(summary); summary=NULL;
    } else if (!report->grouped) {
        char* change_type;
        if (node_checked&NODE_ADDED) {
            change_type = "added";
        } else if (node_checked&NODE_REMOVED) {
            change_type = "removed";
        } else {
            change_type = "changed";
        }
        report_printf(report, JSON_FMT_STRING_PLAIN, 4, ' ', escacped_filename, change_type);
    } else {
        report_printf(report, JSON_FMT_ARRAY_ELEMENT_PLAIN, 4, ' ', escacped_filename);
    }
    free(escacped_filename);
}

static void _print_attribute_value(report_t *report, const char* name, ATTRIBUTE attribute, char **value, int num, int ident) {
    if (num) {
        if (num > 1) {
            report_printf(report, JSON_FMT_ARRAY_BEGIN, ident, ' ', name);
            for (int i = 0 ; i < num ; i++) {
                char *escaped_value = _get_escaped_json_string(value[i]);
                report_printf(report, i+1<num?JSON_FMT_ARRAY_ELEMENT_INNER:JSON_FMT_ARRAY_ELEMENT_LAST, ident+2, ' ', escaped_value);
                free(escaped_value);
            }
            report_printf(report, JSON_FMT_ARRAY_END_PLAIN, ident, ' ');
        } else {
            char *escaped_value = _get_escaped_json_string(value[0]);
            report_printf(report, _get_value_format(attribute), ident, ' ', name, escaped_value);
            free(escaped_value);
        }
    }
}

static void _print_attribute(report_t *report, db_line* oline, db_line* nline, ATTRIBUTE attribute) {
    char **ovalue = NULL;
    char **nvalue = NULL;
    int onumber, nnumber, i;

    if (attributes_first) { attributes_first=false; }
    else { report_printf(report,",\n"); }

    DB_ATTR_TYPE attr = ATTR(attribute);

    const char* json_name = attributes[attribute].field_name;
    report_printf(report, JSON_FMT_OBJECT_BEGIN, 6, ' ', json_name);

    onumber=get_attribute_values(attr, oline, &ovalue, report);
    nnumber=get_attribute_values(attr, nline, &nvalue, report);

    _print_attribute_value(report, "old", attribute, ovalue, onumber, 8);
    for(i=0; i < onumber; ++i) { free(ovalue[i]); ovalue[i]=NULL; } free(ovalue); ovalue=NULL;

    if (onumber && nnumber) { report_printf(report,",\n"); }

    _print_attribute_value(report, "new", attribute, nvalue, nnumber, 8);
    for(i=0; i < nnumber; ++i) { free(nvalue[i]); nvalue[i]=NULL; } free(nvalue); nvalue=NULL;

    report_printf(report,"\n");
    report_printf(report, JSON_FMT_OBJECT_END_PLAIN, 6, ' ');
}

static void _print_database_attribute(report_t *report, db_line* oline, __attribute__((unused)) db_line* nline, ATTRIBUTE attribute) {
    char **value;
    int num, i;

    if (database_first) { database_first=false; }
    else { report_printf(report,",\n"); }

    DB_ATTR_TYPE attr = ATTR(attribute);

    const char* json_name = attributes[attribute].field_name;

    num=get_attribute_values(attr, oline, &value, report);

    _print_attribute_value(report, json_name, attribute, value, num, 6);
    for(i=0; i < num; ++i) { free(value[i]); value[i]=NULL; } free(value); value=NULL;
}

static void _print_database_attributes(report_t *report, db_line* db) {
    if (databases_first) { databases_first=false; }
    else { report_printf(report,",\n"); }

    char *escacped_filename = _get_escaped_json_string(db->filename);

    database_first = true;
    report_printf(report, JSON_FMT_OBJECT_BEGIN, 4, ' ', escacped_filename);
    print_dbline_attrs(report, db, NULL, db->attr, _print_database_attribute);
    report_printf(report,"\n");
    report_printf(report, JSON_FMT_OBJECT_END_PLAIN, 4, ' ');
    free(escacped_filename);
}

static void _print_report_dbline_attributes(report_t *report, db_line* oline, db_line* nline, DB_ATTR_TYPE report_attrs) {
    if  (report_attrs)  {
        if (details_first) { details_first=false; }
        else { report_printf(report,",\n"); }

        char *escacped_filename = _get_escaped_json_string((nline==NULL?oline:nline)->filename);
        report_printf(report, JSON_FMT_OBJECT_BEGIN, 4, ' ', escacped_filename);
        attributes_first = true;
        print_dbline_attrs(report, oline, nline, report_attrs, _print_attribute);
        report_printf(report,"\n");
        report_printf(report, JSON_FMT_OBJECT_END_PLAIN, 4, ' ');
        free(escacped_filename);
    }
}

static void print_report_header_json(report_t *report) {
    report_printf(report, "{\n");
}
static void print_report_footer_json(report_t *report) {
    report_printf(report, "}\n");
}
static void print_report_outline_json(report_t *report) {
    report_printf(report, report->level >= REPORT_LEVEL_SUMMARY?JSON_FMT_STRING_COMMA:JSON_FMT_STRING_LAST , 2, ' ', "outline", get_summary_string(report));
}
static void print_report_starttime_version_json(report_t *report, const char* start_time, const char* aide_version) {
    report_printf(report, JSON_FMT_STRING_COMMA, 2, ' ', "start_time", start_time);
    report_printf(report, JSON_FMT_STRING_COMMA, 2, ' ', "aide_version", aide_version);
}
static void print_report_endtime_runtime_json(report_t* report, const char* end_time, long run_time) {
    report_printf(report, JSON_FMT_STRING_COMMA, 2, ' ', "end_time", end_time);
    report_printf(report, JSON_FMT_LONG_LAST, 2, ' ', "run_time_seconds", run_time);
}

static void print_report_config_options_json(report_t *report) {
    print_report_config_options(report, _print_config_option);
}

static void print_report_report_options_json(report_t *report) {
    print_report_report_options(report, _print_config_option);
}

static void print_report_summary_json(report_t *report) {
    report_printf(report, JSON_FMT_OBJECT_BEGIN, 2, ' ', "number_of_entries");
    if (conf->action&(DO_COMPARE|DO_DIFF) && (report->nadd||report->nrem||report->nchg)) {
        report_printf(report, JSON_FMT_LONG, 4, ' ', "total", report->ntotal);
        report_printf(report, JSON_FMT_LONG, 4, ' ', "added", report->nadd);
        report_printf(report, JSON_FMT_LONG, 4, ' ', "removed", report->nrem);
        report_printf(report, JSON_FMT_LONG_LAST, 4, ' ', "changed", report->nchg);
    } else {
        report_printf(report, JSON_FMT_LONG_LAST, 4, ' ', "total", report->ntotal);
    }
    report_printf(report, JSON_FMT_OBJECT_END, 2, ' ');
}

static void print_report_new_database_written_json(report_t *report) {
    report_printf(report, JSON_FMT_STRING_COMMA, 2, ' ', "new_database", conf->database_out.url->value);
}

static void print_report_details_json(report_t *report, seltree* node) {
    details_first = true;
    report_printf(report, JSON_FMT_OBJECT_BEGIN, 2, ' ', "details");
    print_report_details(report, node, _print_report_dbline_attributes);
    report_printf(report,"\n");
    report_printf(report, JSON_FMT_OBJECT_END, 2, ' ');
}

static void print_report_databases_json(report_t *report) {
    databases_first = true;
    report_printf(report, JSON_FMT_OBJECT_BEGIN, 2, ' ', "databases");
    print_databases_attrs(report, _print_database_attributes);
    report_printf(report,"\n");
    report_printf(report, JSON_FMT_OBJECT_END, 2, ' ');
}

static void print_report_entries_json(report_t *report, seltree* node, const int filter) {
    line_first = true;
    switch (filter) {
        case NODE_ADDED:
            report_printf(report, report->summarize_changes||!report->grouped?JSON_FMT_OBJECT_BEGIN:JSON_FMT_ARRAY_BEGIN, 2, ' ', "added");
            break;
        case NODE_REMOVED:
            report_printf(report, report->summarize_changes||!report->grouped?JSON_FMT_OBJECT_BEGIN:JSON_FMT_ARRAY_BEGIN, 2, ' ', "removed");
            break;
        case NODE_CHANGED:
            report_printf(report, report->summarize_changes||!report->grouped?JSON_FMT_OBJECT_BEGIN:JSON_FMT_ARRAY_BEGIN, 2, ' ', "changed");
            break;
        default:
            report_printf(report, report->summarize_changes||!report->grouped?JSON_FMT_OBJECT_BEGIN:JSON_FMT_ARRAY_BEGIN, 2, ' ', "entries");
            break;
    }
    print_report_entries(report, node, filter, print_line_json);
    report_printf(report,"\n");
    report_printf(report, report->summarize_changes||!report->grouped?JSON_FMT_OBJECT_END:JSON_FMT_ARRAY_END, 2, ' ');
}

static void print_report_diff_attrs_entries_json(report_t *report) {
    if (report->num_diff_attrs_entries) {
        report_printf(report, JSON_FMT_OBJECT_BEGIN, 2, ' ', "different_attributes");
        for(int i = 0; i < report->num_diff_attrs_entries; ++i) {
            char *str = NULL;
            report_printf(report, i+1<report->num_diff_attrs_entries?JSON_FMT_STRING_COMMA:JSON_FMT_STRING_LAST , 4, ' ',
                    report->diff_attrs_entries[i].entry,
                    str= diff_attributes(report->diff_attrs_entries[i].old_attrs, report->diff_attrs_entries[i].new_attrs));
            free(str);
        }
        report->num_diff_attrs_entries = 0;
        free(report->diff_attrs_entries);
        report_printf(report, JSON_FMT_OBJECT_END, 2, ' ');
    }
}

report_format_module report_module_json = {
    .print_report_config_options = print_report_config_options_json,
    .print_report_databases = print_report_databases_json,
    .print_report_details = print_report_details_json,
    .print_report_diff_attrs_entries = print_report_diff_attrs_entries_json,
    .print_report_endtime_runtime = print_report_endtime_runtime_json,
    .print_report_entries = print_report_entries_json,
    .print_report_footer = print_report_footer_json,
    .print_report_header = print_report_header_json,
    .print_report_new_database_written = print_report_new_database_written_json,
    .print_report_outline = print_report_outline_json,
    .print_report_report_options = print_report_report_options_json,
    .print_report_starttime_version = print_report_starttime_version_json,
    .print_report_summary = print_report_summary_json,
};
