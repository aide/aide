/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2022-2026 Hannes von Haugwitz
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
#include "report_json.h"

#define NDJSON_FMT_LINE_START "{ \"type\": \"%s\","
#define NDJSON_FMT_LINE_END " }\n"
#define NDJSON_FMT_ARRAY_BEGIN "%*c\"%s\": ["
#define NDJSON_FMT_ARRAY_ELEMENT_INNER "%*c\"%s\","
#define NDJSON_FMT_ARRAY_ELEMENT_LAST "%*c\"%s\""
#define NDJSON_FMT_ARRAY_END_PLAIN "%*c]"
#define NDJSON_FMT_LONG "%*c\"%s\": %ld,"
#define NDJSON_FMT_LONG_LAST "%*c\"%s\": %ld"
#define NDJSON_FMT_OBJECT_BEGIN "%*c\"%s\": {"
#define NDJSON_FMT_OBJECT_END_PLAIN "%*c}"
#define NDJSON_FMT_STRING_COMMA "%*c\"%s\": \"%s\","
#define NDJSON_FMT_STRING_LAST "%*c\"%s\": \"%s\""
#define NDJSON_FMT_STRING_PLAIN "%*c\"%s\": \"%s\""

bool ndjson_database_first = true;
bool ndjson_databases_first = true;
bool ndjson_attributes_first = true;
bool ndjson_config_first = true;

static void _print_config_option(report_t *report, config_option option, const char* value) {
    if (ndjson_config_first) {
        ndjson_config_first=false;
        report_printf(report, NDJSON_FMT_LINE_START, "config");
    } else {
        report_printf(report,",");
    }

    char *escaped_value = get_escaped_json_string(value);
    report_printf(report, NDJSON_FMT_STRING_PLAIN, 0, ' ', config_options[option].config_name, escaped_value);
    free(escaped_value);
}

static void print_line_ndjson(report_t* report, char* filename, int node_checked, seltree* node) {
    char *escaped_filename = get_escaped_json_string(filename);

    char *change_type, *change;
    if (node_checked&NODE_ADDED) {
        change_type = "addition";
        change = "added";
    } else if (node_checked&NODE_REMOVED) {
        change_type = "removal";
        change = "removed";
    } else {
        change_type = "change";
        change = "changed";
    }
    report_printf(report, NDJSON_FMT_LINE_START, change_type);
    if(report->summarize_changes) {
        char* summary = get_summarize_changes_string(report, node);
        report_printf(report, NDJSON_FMT_STRING_PLAIN, 0, ' ', escaped_filename, summary);
        free(summary); summary=NULL;
    } else {
        report_printf(report, NDJSON_FMT_STRING_PLAIN, 0, ' ', escaped_filename, change);
    }
    report_printf(report, NDJSON_FMT_LINE_END);
    free(escaped_filename);
}

static void _print_attribute_value(report_t *report, const char* name, ATTRIBUTE attribute, char **value, int num, int ident) {
    if (num) {
        if (num > 1) {
            report_printf(report, NDJSON_FMT_ARRAY_BEGIN, ident, ' ', name);
            for (int i = 0 ; i < num ; i++) {
                char *escaped_value = get_escaped_json_string(value[i]);
                report_printf(report, i+1<num?NDJSON_FMT_ARRAY_ELEMENT_INNER:NDJSON_FMT_ARRAY_ELEMENT_LAST, 0, ' ', escaped_value);
                free(escaped_value);
            }
            report_printf(report, NDJSON_FMT_ARRAY_END_PLAIN, ident, ' ');
        } else {
            char *escaped_value = get_escaped_json_string(value[0]);
            report_printf(report, get_value_format_json(attribute), ident, ' ', name, escaped_value);
            free(escaped_value);
        }
    }
}

static void _print_attribute(report_t *report, db_line* oline, db_line* nline, ATTRIBUTE attribute) {
    char **ovalue = NULL;
    char **nvalue = NULL;
    int onumber, nnumber, i;

    if (ndjson_attributes_first) { ndjson_attributes_first=false; }
    else { report_printf(report,","); }

    DB_ATTR_TYPE attr = ATTR(attribute);

    const char* json_name = attributes[attribute].field_name;
    report_printf(report, NDJSON_FMT_OBJECT_BEGIN, 0, ' ', json_name);

    onumber=get_attribute_values(attr, oline, &ovalue, report);
    nnumber=get_attribute_values(attr, nline, &nvalue, report);

    _print_attribute_value(report, "old", attribute, ovalue, onumber, 0);
    for(i=0; i < onumber; ++i) { free(ovalue[i]); ovalue[i]=NULL; } free(ovalue); ovalue=NULL;

    if (onumber && nnumber) { report_printf(report,","); }

    _print_attribute_value(report, "new", attribute, nvalue, nnumber, 0);
    for(i=0; i < nnumber; ++i) { free(nvalue[i]); nvalue[i]=NULL; } free(nvalue); nvalue=NULL;

    report_printf(report, NDJSON_FMT_OBJECT_END_PLAIN, 0, ' ');
}

static void _print_database_attribute(report_t *report, db_line* oline, __attribute__((unused)) db_line* nline, ATTRIBUTE attribute) {
    char **value;
    int num, i;

    if (ndjson_database_first) { ndjson_database_first=false; }
    else { report_printf(report,","); }

    DB_ATTR_TYPE attr = ATTR(attribute);

    const char* json_name = attributes[attribute].field_name;

    num=get_attribute_values(attr, oline, &value, report);

    _print_attribute_value(report, json_name, attribute, value, num, 0);
    for(i=0; i < num; ++i) { free(value[i]); value[i]=NULL; } free(value); value=NULL;
}

static void _print_database_attributes(report_t *report, db_line* db) {
    if (ndjson_databases_first) { ndjson_databases_first=false; }
    else { report_printf(report,","); }

    char *escaped_filename = get_escaped_json_string(db->filename);

    ndjson_database_first = true;
    report_printf(report, NDJSON_FMT_OBJECT_BEGIN, 0, ' ', escaped_filename);
    print_dbline_attrs(report, db, NULL, db->attr, _print_database_attribute);
    report_printf(report, NDJSON_FMT_OBJECT_END_PLAIN, 0, ' ');
    free(escaped_filename);
}

static void _print_report_dbline_attributes(report_t *report, db_line* oline, db_line* nline, DB_ATTR_TYPE report_attrs) {
    if  (report_attrs)  {
        report_printf(report, NDJSON_FMT_LINE_START, "details");
        char *escaped_filename = get_escaped_json_string((nline==NULL?oline:nline)->filename);
        report_printf(report, NDJSON_FMT_OBJECT_BEGIN, 0, ' ', escaped_filename);
        ndjson_attributes_first = true;
        print_dbline_attrs(report, oline, nline, report_attrs, _print_attribute);
        report_printf(report, NDJSON_FMT_OBJECT_END_PLAIN, 0, ' ');
        report_printf(report, NDJSON_FMT_LINE_END);
        free(escaped_filename);
    }
}

static void print_report_outline_ndjson(report_t *report) {
    report_printf(report, NDJSON_FMT_LINE_START, "outline");
    report_printf(report, NDJSON_FMT_STRING_LAST , 0, ' ', "outline", get_summary_string(report));
    report_printf(report, NDJSON_FMT_LINE_END);
}
static void print_report_starttime_version_ndjson(report_t *report, const char* start_time, const char* aide_version) {
    report_printf(report, NDJSON_FMT_LINE_START, "startup");
    report_printf(report, NDJSON_FMT_STRING_COMMA, 0, ' ', "start_time", start_time);
    report_printf(report, NDJSON_FMT_STRING_LAST, 0, ' ', "aide_version", aide_version);
    report_printf(report, NDJSON_FMT_LINE_END);
}
static void print_report_endtime_runtime_ndjson(report_t* report, const char* end_time, long run_time) {
    report_printf(report, NDJSON_FMT_LINE_START, "shutdown");
    report_printf(report, NDJSON_FMT_STRING_COMMA, 0, ' ', "end_time", end_time);
    report_printf(report, NDJSON_FMT_LONG_LAST, 0, ' ', "run_time_seconds", run_time);
    report_printf(report, NDJSON_FMT_LINE_END);
}

static void print_report_config_options_ndjson(report_t *report) {
    ndjson_config_first = true;
    print_report_config_options(report, _print_config_option);
    if (!ndjson_config_first && report->level < REPORT_LEVEL_LIST_ENTRIES) {
        report_printf(report, NDJSON_FMT_LINE_END);
    }
}

static void print_report_report_options_ndjson(report_t *report) {
    print_report_report_options(report, _print_config_option);
    if(!ndjson_config_first) {
        report_printf(report, NDJSON_FMT_LINE_END);
    }
}

static void print_report_summary_ndjson(report_t *report) {
    report_printf(report, NDJSON_FMT_LINE_START, "number_of_entries");
    if (conf->action&(DO_COMPARE|DO_DIFF) && (report->nadd||report->nrem||report->nchg)) {
        report_printf(report, NDJSON_FMT_LONG, 0, ' ', "total", report->ntotal);
        report_printf(report, NDJSON_FMT_LONG, 0, ' ', "added", report->nadd);
        report_printf(report, NDJSON_FMT_LONG, 0, ' ', "removed", report->nrem);
        report_printf(report, NDJSON_FMT_LONG_LAST, 0, ' ', "changed", report->nchg);
    } else {
        report_printf(report, NDJSON_FMT_LONG_LAST, 0, ' ', "total", report->ntotal);
    }
    report_printf(report, NDJSON_FMT_LINE_END);
}

static void print_report_new_database_written_ndjson(report_t *report) {
    report_printf(report, NDJSON_FMT_LINE_START, "new_database");
    report_printf(report, NDJSON_FMT_STRING_PLAIN, 0, ' ', "new_database", conf->database_out.url->type == url_file ? conf->database_out.url->value : conf->database_out.url->raw);
    report_printf(report, NDJSON_FMT_LINE_END);
}

static void print_report_details_ndjson(report_t *report, seltree* node) {
    print_report_details(report, node, _print_report_dbline_attributes);
}

static void print_report_databases_ndjson(report_t *report) {
    ndjson_databases_first = true;
    report_printf(report, NDJSON_FMT_LINE_START, "databases");
    print_databases_attrs(report, _print_database_attributes);
    report_printf(report, NDJSON_FMT_LINE_END);
}

static void print_report_entries_ndjson(report_t *report, seltree* node, const int filter) {
    print_report_entries(report, node, filter, print_line_ndjson);
}

static void print_report_diff_attrs_entries_ndjson(report_t *report) {
    if (report->num_diff_attrs_entries) {
        report_printf(report, NDJSON_FMT_LINE_START, "different_attributes");
        for(int i = 0; i < report->num_diff_attrs_entries; ++i) {
            char *escaped_filename = get_escaped_json_string(report->diff_attrs_entries[i].entry);
            char *attrs = diff_attributes(report->diff_attrs_entries[i].old_attrs, report->diff_attrs_entries[i].new_attrs);
            report_printf(report, i + 1 < report->num_diff_attrs_entries ? NDJSON_FMT_STRING_COMMA : NDJSON_FMT_STRING_LAST, 0, ' ',
                    escaped_filename, attrs);
            free(escaped_filename);
            free(attrs);
        }
        report->num_diff_attrs_entries = 0;
        free(report->diff_attrs_entries);
        report_printf(report, NDJSON_FMT_LINE_END);
    }
}

report_format_module report_module_ndjson = {
    .print_report_config_options = print_report_config_options_ndjson,
    .print_report_databases = print_report_databases_ndjson,
    .print_report_details = print_report_details_ndjson,
    .print_report_diff_attrs_entries = print_report_diff_attrs_entries_ndjson,
    .print_report_endtime_runtime = print_report_endtime_runtime_ndjson,
    .print_report_entries = print_report_entries_ndjson,
    .print_report_footer = NULL,
    .print_report_header = NULL,
    .print_report_new_database_written = print_report_new_database_written_ndjson,
    .print_report_outline = print_report_outline_ndjson,
    .print_report_report_options = print_report_report_options_ndjson,
    .print_report_starttime_version = print_report_starttime_version_ndjson,
    .print_report_summary = print_report_summary_ndjson,
};
