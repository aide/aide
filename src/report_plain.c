/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010, 2011, 2013, 2015-2016, 2018-2023 Rami Lehti,
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
#include "locale-aide.h"

const int width_details = 80;

#define PLAIN_REPORT_HEADLINE_FMT "\n\n---------------------------------------------------\n%s:\n---------------------------------------------------\n"

bool first = true;

static void print_report_dbline_attributes_plain(report_t *, db_line*, db_line*, DB_ATTR_TYPE);

static char* _get_not_grouped_list_string(report_t *report) {
    if (report->nadd && report->nrem && report->nchg) { return _("Added, removed and changed entries"); }
    else if (report->nadd && report->nrem) { return _("Added and removed entries"); }
    else if (report->nadd && report->nchg) { return _("Added and changed entries"); }
    else if (report->nrem && report->nchg) { return _("Removed and changed entries"); }
    else if (report->nadd) { return _("Added entries"); }
    else if (report->nrem) { return _("Removed entries"); }
    else { return _("Changed entries"); }
}

static void _print_config_option(report_t *report, config_option option, const char* value) {
    if (first) { first=false; }
    else { report_printf(report," | "); }
    report_printf(report, "%s: %s", config_options[option].report_string, value);
}

static void _print_report_option(report_t *report, config_option option, const char* value) {
    report_printf(report, "%s: %s\n", config_options[option].report_string, value);
}

static void _print_attribute(report_t *report, db_line* oline, db_line* nline, ATTRIBUTE attribute) {
    char **ovalue = NULL;
    char **nvalue = NULL;
    int onumber, nnumber, i, c;
    int p = (width_details-(4 + MAX_WIDTH_DETAILS_STRING))/2;

    DB_ATTR_TYPE attr = ATTR(attribute);
    const char* name = attributes[attribute].details_string;

    onumber=get_attribute_values(attr, oline, &ovalue, report);
    nnumber=get_attribute_values(attr, nline, &nvalue, report);

    i = 0;
    while (i<onumber || i<nnumber) {
        int olen = i<onumber?strlen(ovalue[i]):0;
        int nlen = i<nnumber?strlen(nvalue[i]):0;
        int k = 0;
        while (olen-p*k >= 0 || nlen-p*k >= 0) {
            c = k*(p-1);
            if (!onumber) {
                report_printf(report," %-*s%c %-*c  %.*s\n", MAX_WIDTH_DETAILS_STRING, (i+k)?"":name, (i+k)?' ':':', p, ' ', p-1, nlen-c>0?&nvalue[i][c]:"");
            } else if (!nnumber) {
                report_printf(report," %-*s%c %.*s\n", MAX_WIDTH_DETAILS_STRING, (i+k)?"":name, (i+k)?' ':':', p-1, olen-c>0?&ovalue[i][c]:"");
            } else {
                report_printf(report," %-*s%c %-*.*s| %.*s\n", MAX_WIDTH_DETAILS_STRING, (i+k)?"":name, (i+k)?' ':':', p, p-1, olen-c>0?&ovalue[i][c]:"", p-1, nlen-c>0?&nvalue[i][c]:"");
            }
            k++;
        }
        ++i;
    }
    for(i=0; i < onumber; ++i) { free(ovalue[i]); ovalue[i]=NULL; } free(ovalue); ovalue=NULL;
    for(i=0; i < nnumber; ++i) { free(nvalue[i]); nvalue[i]=NULL; } free(nvalue); nvalue=NULL;
}

static void _print_database_attributes(report_t *report, db_line* db) {
    print_report_dbline_attributes_plain(report, db, NULL, db->attr);
}

static void print_report_outline_plain(report_t *report) {
    report_printf(report, "%s\n", get_summary_string(report));
}

static void print_report_new_database_written_plain(report_t *report) {
    report_printf(report,_("New AIDE database written to %s\n"),conf->database_out.url->value);
}

static void print_report_config_options_plain(report_t *report) {
    first = true;
    print_report_config_options(report, _print_config_option);
    if (!first) { report_printf(report, "\n"); }
}

static void print_report_report_options_plain(report_t *report) {
    print_report_report_options(report, _print_report_option);
}

static void print_report_starttime_version_plain(report_t *report, const char* start_time, const char* aide_version) {
    report_printf(report, _("Start timestamp: %s (AIDE %s)\n"), start_time, aide_version);
}

static void print_report_endtime_runtime_plain(report_t* report, const char* end_time, long run_time) {
    report_printf(report, _("\n\nEnd timestamp: %s (run time: %ldm %lds)\n"), end_time, run_time/60, run_time%60);
}

static void print_report_summary_plain(report_t *report) {
    if(conf->action&(DO_COMPARE|DO_DIFF) && (report->nadd||report->nrem||report->nchg)) {
        report_printf(report,_("\nSummary:\n  Total number of entries:\t%li\n  Added entries:\t\t%li\n"
                    "  Removed entries:\t\t%li\n  Changed entries:\t\t%li"), report->ntotal, report->nadd, report->nrem, report->nchg);
    } else {
        report_printf(report, _("\nNumber of entries:\t%li"), report->ntotal);
    }
}

static void print_line_plain(report_t* report, char* filename, int node_checked, seltree* node) {
    if(report->summarize_changes) {
        char* summary = get_summarize_changes_string(report, node);
        report_printf(report, "\n%s: %s", summary, filename);
        free(summary); summary=NULL;
    } else {
        if (node_checked&NODE_ADDED) {
            report_printf(report, _("\nadded: %s"), filename);
        } else if (node_checked&NODE_REMOVED) {
            report_printf(report, _("\nremoved: %s"), filename);
        } else if (node_checked&NODE_CHANGED) {
            report_printf(report, _("\nchanged: %s"), filename);
        }
    }
}

static void print_report_dbline_attributes_plain(report_t *report, db_line* oline, db_line* nline, DB_ATTR_TYPE report_attrs) {
    if  (report_attrs)  {
        char *file_type = get_file_type_string((nline==NULL?oline:nline)->perm);
        report_printf(report, "\n");
        if (file_type) {
            report_printf(report, "%s: ", file_type);
        }
        report_printf(report, "%s\n", (nline==NULL?oline:nline)->filename);

        print_dbline_attrs(report, oline, nline, report_attrs, _print_attribute);
    }
}

static void print_report_databases_plain(report_t *report) {
    report_printf(report, PLAIN_REPORT_HEADLINE_FMT,_("The attributes of the (uncompressed) database(s)"));
    print_databases_attrs(report, _print_database_attributes);
}

static void print_report_entries_plain(report_t *report, seltree* node, const int filter) {
    switch (filter) {
        case NODE_ADDED:
            report_printf(report, PLAIN_REPORT_HEADLINE_FMT,_("Added entries"));
            break;
        case NODE_REMOVED:
            report_printf(report, PLAIN_REPORT_HEADLINE_FMT,_("Removed entries"));
            break;
        case NODE_CHANGED:
            report_printf(report, PLAIN_REPORT_HEADLINE_FMT,_("Changed entries"));
            break;
        default:
            report_printf(report, PLAIN_REPORT_HEADLINE_FMT, _get_not_grouped_list_string(report));
            break;
    }
    print_report_entries(report, node, filter, print_line_plain);
}

static void print_report_details_plain(report_t *report, seltree* node) {
    report_printf(report, PLAIN_REPORT_HEADLINE_FMT,_("Detailed information about changes"));
    print_report_details(report, node, print_report_dbline_attributes_plain);
}

static void print_report_diff_attrs_entries_plain(report_t *report) {
    for(int i = 0; i < report->num_diff_attrs_entries; ++i) {
        char *str = NULL;
        report_printf(report, "Entry %s in databases has different attributes: %s\n",
                report->diff_attrs_entries[i].entry,
                str= diff_attributes(report->diff_attrs_entries[i].old_attrs, report->diff_attrs_entries[i].new_attrs));
        free(str);
    }
    report->num_diff_attrs_entries = 0;
    free(report->diff_attrs_entries);
}

report_format_module report_module_plain = {
    .print_report_config_options = print_report_config_options_plain,
    .print_report_databases = print_report_databases_plain,
    .print_report_details = print_report_details_plain,
    .print_report_diff_attrs_entries = print_report_diff_attrs_entries_plain,
    .print_report_endtime_runtime = print_report_endtime_runtime_plain,
    .print_report_entries = print_report_entries_plain,
    .print_report_footer = NULL,
    .print_report_header = NULL,
    .print_report_new_database_written = print_report_new_database_written_plain,
    .print_report_outline = print_report_outline_plain,
    .print_report_report_options = print_report_report_options_plain,
    .print_report_starttime_version = print_report_starttime_version_plain,
    .print_report_summary = print_report_summary_plain,
};
