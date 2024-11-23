/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2007, 2010-2013, 2015-2016, 2018-2024 Rami Lehti,
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
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef WITH_AUDIT
#include <libaudit.h>
#include <unistd.h>
#endif
#ifdef WITH_E2FSATTRS
#include "e2fsattrs.h"
#endif
#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include "hashsum.h"
#include "log.h"
#include "rx_rule.h"
#include "seltree_struct.h"

#include "attributes.h"
#include "base64.h"
#include "conf_ast.h"
#include "db_config.h"
#include "list.h"
#include "url.h"
#include "db.h"
#include "db_line.h"
#include "be.h"
#include "util.h"
#include "report.h"
#include "report_plain.h"
#include "report_json.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/


/*************/
/* construction area for report lines */

#ifdef WITH_AUDIT
long nadd, nrem, nchg = 0;
#endif
int added_entries_reported, removed_entries_reported, changed_entries_reported = 0;


const ATTRIBUTE report_attrs_order[] = {
    attr_ftype,
    attr_linkname,
    attr_size,
    attr_bcount,
    attr_perm,
    attr_uid,
    attr_gid,
    attr_atime,
    attr_mtime,
    attr_ctime,
    attr_inode,
    attr_linkcount,
    attr_allhashsums,
#ifdef WITH_ACL
   attr_acl,
#endif
#ifdef WITH_XATTR
   attr_xattrs,
#endif
#ifdef WITH_SELINUX
   attr_selinux,
#endif
#ifdef WITH_E2FSATTRS
   attr_e2fsattrs,
#endif
#ifdef WITH_CAPABILITIES
   attr_capabilities,
#endif
};

int report_attrs_order_length = sizeof(report_attrs_order)/sizeof(ATTRIBUTE);

static DB_ATTR_TYPE get_attrs(ATTRIBUTE attr) {
    switch(attr) {
        case attr_allhashsums: return get_hashes(true);
        case attr_size: return ATTR(attr_size)|ATTR(attr_sizeg);
        default: return ATTR(attr);
    }
}

report_options default_report_options = {
    .format = REPORT_FORMAT_PLAIN,
    .level  = REPORT_LEVEL_CHANGED_ATTRIBUTES,
};

struct report_level {
    REPORT_LEVEL report_level;
    const char *name;
};

static struct report_level report_level_array[] = {
 { REPORT_LEVEL_MINIMAL, "minimal" },
 { REPORT_LEVEL_SUMMARY, "summary" },
 { REPORT_LEVEL_DATABASE_ATTRIBUTES, "database_attributes" },
 { REPORT_LEVEL_LIST_ENTRIES, "list_entries" },
 { REPORT_LEVEL_CHANGED_ATTRIBUTES, "changed_attributes" },
 { REPORT_LEVEL_ADDED_REMOVED_ATTRIBUTES, "added_removed_attributes" },
 { REPORT_LEVEL_ADDED_REMOVED_ENTRIES, "added_removed_entries" },
 { 0, NULL }
};

struct report_format {
    REPORT_FORMAT report_format;
    const char *name;
};

static struct report_format report_format_array[] = {
 { REPORT_FORMAT_PLAIN, "plain" },
 { REPORT_FORMAT_JSON, "json" },
 { 0, NULL }
};

#ifdef WITH_XATTR
static size_t xstrnspn(const char *s1, size_t len, const char *srch)
{
  const char *os1 = s1;

  while (len-- && strchr(srch, *s1))
    ++s1;

  return (s1 - os1);
}

#define PRINTABLE_XATTR_VALS                    \
    "0123456789"                                \
    "abcdefghijklmnopqrstuvwxyz"                \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"                \
    ".-_:;,[]{}<>()!@#$%^&*|\\/?~"

static int xattrs2array(xattrs_type* xattrs, char* **values) {
    int n = 0;
    if (xattrs==NULL) { n=1; }
    else { n=1+xattrs->num; }
    *values = checked_malloc(n * sizeof(char*));
    (*values)[0]=checked_malloc((6+floor(log10(n)))*sizeof(char));
    snprintf((*values)[0], 6+floor(log10(n)), "num=%d", n-1);
    if (n>1) {
        size_t num = 0;
        int width, length;
        width = log10(xattrs->num); /* make them the same width */
        while (num++ < xattrs->num) {
            char *val = NULL;
            size_t len = 0;
            val = (char *)xattrs->ents[num - 1].val;
            len = xstrnspn(val, xattrs->ents[num - 1].vsz, PRINTABLE_XATTR_VALS);
            if ((len ==  xattrs->ents[num - 1].vsz) || ((len == (xattrs->ents[num - 1].vsz - 1)) && !val[len])) {
                length = 8 + width + strlen(xattrs->ents[num - 1].key) + strlen(val);
                (*values)[num]=checked_malloc(length *sizeof(char));
                snprintf((*values)[num], length , "[%.*zd] %s = %s", width, num, xattrs->ents[num - 1].key, val);
            } else {
                val = encode_base64(xattrs->ents[num - 1].val, xattrs->ents[num - 1].vsz);
                length = 10 + width + strlen(xattrs->ents[num - 1].key) + strlen(val);
                (*values)[num]=checked_malloc( length  *sizeof(char));
                snprintf((*values)[num], length , "[%.*zd] %s <=> %s", width, num, xattrs->ents[num - 1].key, val);
                free(val);
            }
        }
    }
    return n;
}
#endif

#ifdef WITH_ACL
static int acl2array(acl_type* acl, char* **values) {
    int n = 0;
#ifdef WITH_POSIX_ACL
#define easy_posix_acl(x,y) \
        if (acl->x) { \
            i = k = 0; \
            while (acl->x[i]) { \
                if (acl->x[i]=='\n') { \
                    (*values)[j]=checked_malloc(4+(i-k)*sizeof(char)); \
                    snprintf((*values)[j], 4+(i-k), "%c: %s", y, &acl->x[k]); \
                    j++; \
                    k=i+1; \
                } \
                i++; \
            } \
        }
    if (acl->acl_a || acl->acl_d) {
        int j, k, i;
        if (acl->acl_a) { i = 0; while (acl->acl_a[i]) { if (acl->acl_a[i++]=='\n') { n++; } } }
        if (acl->acl_d) { i = 0; while (acl->acl_d[i]) { if (acl->acl_d[i++]=='\n') { n++; } } }
        *values = checked_malloc(n * sizeof(char*));
        j = 0;
        easy_posix_acl(acl_a, 'A')
        easy_posix_acl(acl_d, 'D')
    }
#endif
    return n;
}
#endif

char* get_file_type_string(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return _("File");
        case S_IFDIR: return _("Directory");
#ifdef S_IFIFO
        case S_IFIFO: return _("FIFO");
#endif
        case S_IFLNK: return _("Link");
        case S_IFBLK: return _("Block device");
        case S_IFCHR: return _("Character device");
#ifdef S_IFSOCK
        case S_IFSOCK: return _("Socket");
#endif
#ifdef S_IFDOOR
        case S_IFDOOR: return _("Door");
#endif
#ifdef S_IFPORT
        case S_IFPORT: return _("Port");
#endif
        case 0: return NULL;
        default: return _("Unknown file type");
    }
}

static int cmp_url(url_t* url1,url_t* url2){
  return ((url1->type==url2->type)&&(strcmp(url1->value,url2->value)==0));
}

const char* get_report_level_string(REPORT_LEVEL report_level) {
    return report_level_array[report_level-1].name;
}

REPORT_LEVEL get_report_level(char *str) {
    struct report_level *level;

    for (level = report_level_array; level->report_level != 0; level++) {
        if (strcmp(str, level->name) == 0) {
            return level->report_level;
        }
    }
    return 0;
}

static const char* get_report_format_string(REPORT_FORMAT report_format) {
    return report_format_array[report_format-1].name;
}

REPORT_FORMAT get_report_format(char *str) {
    struct report_format *level;

    for (level = report_format_array; level->report_format != 0; level++) {
        if (strcmp(str, level->name) == 0) {
            return level->report_format;
        }
    }
    return 0;
}

static void report_vprintf(report_t*, const char *, va_list)
#ifdef __GNUC__
        __attribute__ ((format (printf, 2, 0)))
#endif
;

static void report_vprintf(report_t* r, const char *format, va_list ap) {
    int retval;

if (!r->quiet || (r->nadd || r->nchg || r->nrem)) {
    switch ((r->url)->type) {
#ifdef HAVE_SYSLOG
        case url_syslog: {
#ifdef HAVE_VSYSLOG
            vsyslog(AIDE_SYSLOG_PRIORITY,format,ap);
#else
            char buf[1024];
            vsnprintf(buf,1024,format,ap);
            syslog(AIDE_SYSLOG_PRIORITY,"%s",buf);
#endif
            break;
        }
#endif
        default : {
    retval=vfprintf(r->fd, format, ap);
    if(retval==0) {
        log_msg(LOG_LEVEL_ERROR, "unable to write to '%s", (r->url)->value);
    }
            break;
        }
    }

}

}

void report_printf(report_t* r, const char* error_msg, ...) {
    va_list ap;

    va_start(ap, error_msg);
    report_vprintf(r, error_msg, ap);
    va_end(ap);

}

static int compare_report_t_by_report_level(const void *n1, const void *n2)
{
    const report_t *x1 = n1;
    const report_t *x2 = n2;
    return x2->level - x1->level;
}

void log_report_urls(LOG_LEVEL log_level) {
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;

        log_msg(log_level, " %s%s%s (%p)", get_url_type_string((r->url)->type), (r->url)->value?":":"", (r->url)->value?(r->url)->value:"", (void*) r);

        log_msg(log_level, "   level: %s | format: %s | base16: %s | append: %s | quiet: %s | detailed_init: %s | summarize_changes: %s | grouped: %s", get_report_level_string(r->level), get_report_format_string(r->format), btoa(r->base16), btoa(r->append), btoa(r->quiet), btoa(r->detailed_init), btoa(r->summarize_changes), btoa(r->grouped));
        char *str;
        log_msg(log_level, "   ignore_added_attrs: '%s'", str = diff_attributes(0, r->ignore_added_attrs));
        free(str);
        log_msg(log_level, "   ignore_removed_attrs: '%s'", str = diff_attributes(0, r->ignore_removed_attrs));
        free(str);
        log_msg(log_level, "   ignore_changed_attrs: '%s'", str = diff_attributes(0, r->ignore_changed_attrs));
        free(str);
        log_msg(log_level, "   force_attrs: '%s'", str = diff_attributes(0, r->force_attrs));
        free(str);
#ifdef WITH_E2FSATTRS
        log_msg(log_level, "   ignore_e2fsattrs: '%s'", str = get_e2fsattrs_string(r->ignore_e2fsattrs, true, 0));
        free(str);
#endif
    }
}

void print_report_config_options(report_t *report, void (*print_config_option)(report_t *, config_option, const char*)) {
    if(conf->config_version) {
        print_config_option(report, CONFIG_VERSION, conf->config_version);
    }
    if (conf->limit != NULL) {
        print_config_option(report, LIMIT_CMDLINE_OPTION, conf->limit);
    }
    if (conf->action&(DO_INIT|DO_COMPARE) && conf->root_prefix_length > 0) {
        print_config_option(report, ROOT_PREFIX_OPTION, conf->root_prefix);
    }
    if (report->level != default_report_options.level) {
        print_config_option(report, REPORT_LEVEL_OPTION, get_report_level_string(report->level));
    }
}

void print_report_report_options(report_t *report, void (*print_config_option)(report_t *, config_option, const char*)) {
    char *str;
    if (report->ignore_added_attrs) {
        print_config_option(report, REPORT_IGNORE_ADDED_ATTRS_OPTION, str = diff_attributes(0, report->ignore_added_attrs));
        free(str);
    }
    if (report->ignore_removed_attrs) {
        print_config_option(report, REPORT_IGNORE_REMOVED_ATTRS_OPTION, str = diff_attributes(0, report->ignore_removed_attrs));
        free(str);
    }
    if (report->ignore_changed_attrs) {
        print_config_option(report, REPORT_IGNORE_CHANGED_ATTRS_OPTION, str = diff_attributes(0, report->ignore_changed_attrs));
        free(str);
    }
    if (report->force_attrs && report->level >= REPORT_LEVEL_CHANGED_ATTRIBUTES) {
        print_config_option(report, REPORT_FORCE_ATTRS_OPTION, str = diff_attributes(0, report->force_attrs));
        free(str);
    }
#ifdef WITH_E2FSATTRS
    if (report->ignore_e2fsattrs) {
        print_config_option(report, REPORT_IGNORE_E2FSATTRS_OPTION, str = get_e2fsattrs_string(report->ignore_e2fsattrs, true, 0) );
        free(str);
    }
#endif

}

char* get_summary_string(report_t* report) {
    if(conf->action&(DO_COMPARE|DO_DIFF)) {
        if (report->nadd||report->nrem||report->nchg) {
            if (conf->action&DO_COMPARE) {
                return _("AIDE found differences between database and filesystem!!");
            } else {
                return _("AIDE found differences between the two databases!!");
            }
        } else {
            if (conf->action&DO_COMPARE) {
                return _("AIDE found NO differences between database and filesystem. Looks okay!!");
            } else {
                return _("AIDE found NO differences between the two databases. Looks okay!!");
            }
        }
    } else {
        return _("AIDE successfully initialized database.");
    }
}

bool add_report_url(url_t* url, int linenumber, char* filename, char* linebuf) {
    list* report_urls=NULL;

    if(url==NULL) {
        return false;
    } else if (url->type==url_stdin) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "unsupported report URL-type: '%s'", get_url_type_string(url->type))
        return false;
    }

    for(report_urls=conf->report_urls; report_urls ; report_urls=report_urls->next) {
        if (cmp_url((url_t*) report_urls->data, url)) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, "report_url '%s' already defined (ignoring) ",url->value)
            return true;
        }
    }


    report_t* r = checked_malloc(sizeof(report_t));
    r->url = url;
    r->fd = NULL;
    r->level = conf->report_level;
    r->format = conf->report_format;

    r->detailed_init = conf->report_detailed_init;
    r->base16 = conf->report_base16;
    r->quiet = conf->report_quiet;
    r->append = conf->report_append;
    r->summarize_changes = conf->report_summarize_changes;
    r->grouped = conf->report_grouped;

    r->ignore_added_attrs = conf->report_ignore_added_attrs;
    r->ignore_removed_attrs = conf->report_ignore_removed_attrs;
    r->ignore_changed_attrs = conf->report_ignore_changed_attrs;
    r->force_attrs = conf->report_force_attrs;

    r->ntotal = 0;
    r->nadd = 0;
    r->nrem = 0;
    r->nchg = 0;

    r->diff_attrs_entries = NULL;
    r->num_diff_attrs_entries = 0;

    r->linenumber = linenumber;
    r->filename = filename;
    r->linebuf = linebuf?checked_strdup(linebuf):NULL;

#ifdef WITH_E2FSATTRS
    r->ignore_e2fsattrs = conf->report_ignore_e2fsattrs;
#endif

    log_msg(LOG_LEVEL_DEBUG, _("add report_url (%p): url(: %s:%s, level: %d"), (void*) r, get_url_type_string((r->url)->type), (r->url)->value, r->level);
    conf->report_urls=list_sorted_insert(conf->report_urls, (void*) r, compare_report_t_by_report_level);
    return true;

}

bool init_report_urls(void) {
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;
    switch (r->url->type) {
#ifdef HAVE_SYSLOG
        int sfac;
        case url_syslog: {
            sfac=syslog_facility_lookup(r->url->value);
            openlog(AIDE_IDENT,AIDE_LOGOPT, sfac);
            break;
        }
#endif
        default : {
            r->fd=be_init(r->url, false, false, r->append, r->linenumber, r->filename, r->linebuf, NULL);
            if(r->fd==NULL) {
                return false;
            }
            break;
        }
    }

    }
    return true;
}

static int attributes2array(ATTRIBUTE attrs, char* **values) {
    *values = NULL;

    int n = 0;
    for (ATTRIBUTE i = 0; i < num_attrs; ++i) {
        if (attributes[i].db_name && (1LLU<<i)&attrs) {
            n++;
        }
    }

    *values = checked_malloc(n * sizeof(char*));
    n = 0;
    for (ATTRIBUTE i = 0; i < num_attrs; ++i) {
        if (attributes[i].db_name && (1LLU<<i)&attrs) {
            size_t len = strlen(attributes[i].db_name)+1;
            (*values)[n] = checked_malloc(len * sizeof(char));
            snprintf((*values)[n], len, "%s", attributes[i].db_name);
            n++;
        }
    }
    return n;
}

int get_attribute_values(DB_ATTR_TYPE attr, db_line* line,
        char* **values, report_t *r) {

#define easy_string(s) \
l = strlen(s)+1; \
*values[0] = checked_malloc(l * sizeof (char)); \
snprintf(*values[0], l, "%s",s);

#define easy_number(a,b,c) \
} else if (a&attr) { \
    l = 2+floor(line->b?log10(line->b):0); \
    *values[0] = checked_malloc(l * sizeof (char)); \
    snprintf(*values[0], l, c,line->b);

#define easy_time(a,b) \
} else if (a&attr) { \
    *values[0] = get_time_string(&(line->b)); \

    if (line!=NULL && attr&get_hashes(true)) {
        for (int i = 0 ; i < num_hashes ; ++i) {
            if (ATTR(hashsums[i].attribute)&attr) {
                if (line->hashsums[i]) {
                    *values = checked_malloc(1 * sizeof (char*));
                    if (r==NULL || r->base16) {
                        *values[0] = byte_to_base16(line->hashsums[i], hashsums[i].length);
                    } else {
                        *values[0] = encode_base64(line->hashsums[i], hashsums[i].length);
                    }
                    return 1;
                } else {
                    return 0;
                }
            }
        }
    }

    if (ATTR(attr_attr)&attr) {
        return attributes2array(line->attr, values);
    } else
    if (line==NULL || !(line->attr&attr)) {
        *values = NULL;
        return 0;
#ifdef WITH_ACL
    } else if (ATTR(attr_acl)&attr) {
        return acl2array(line->acl, values);
#endif
#ifdef WITH_XATTR
    } else if (ATTR(attr_xattrs)&attr) {
        return xattrs2array(line->xattrs, values);
#endif
    } else {
        int l;
        *values = checked_malloc(1 * sizeof (char*));
        if (ATTR(attr_ftype)&attr) {
            easy_string(get_file_type_string(line->perm))
        } else if (ATTR(attr_linkname)&attr) {
            easy_string(line->linkname)
        easy_number((ATTR(attr_size)|ATTR(attr_sizeg)),size,"%lli")
        } else if (ATTR(attr_perm)&attr) {
            *values[0] = perm_to_char(line->perm);
        easy_time(ATTR(attr_atime),atime)
        easy_time(ATTR(attr_mtime),mtime)
        easy_time(ATTR(attr_ctime),ctime)
        easy_number(ATTR(attr_bcount),bcount,"%lli")
        easy_number(ATTR(attr_uid),uid,"%li")
        easy_number(ATTR(attr_gid),gid,"%li")
        easy_number(ATTR(attr_inode),inode,"%li")
        easy_number(ATTR(attr_linkcount),nlink,"%li")
#ifdef WITH_SELINUX
        } else if (ATTR(attr_selinux)&attr) {
            easy_string(line->cntx)
#endif
#ifdef WITH_E2FSATTRS
        } else if (ATTR(attr_e2fsattrs)&attr) {
            *values[0]=get_e2fsattrs_string(line->e2fsattrs, false, r?r->ignore_e2fsattrs:0L);
#endif
#ifdef WITH_CAPABILITIES
        } else if (ATTR(attr_capabilities)&attr) {
            easy_string(line->capabilities)
#endif
        } else {
            easy_string("unknown attribute")
        }
        return 1;
    }
}

char* get_summarize_changes_string(report_t* report, seltree* node) {
        int i;
        char* summary = checked_malloc ((report_attrs_order_length+1) * sizeof (char));
        if (node->checked&(NODE_ADDED|NODE_REMOVED)) {
            summary[0]=get_f_type_char_from_perm(((node->checked&NODE_REMOVED)?node->old_data:node->new_data)->perm);
            for(i=1;i<report_attrs_order_length;i++){
                summary[i]=(node->checked&NODE_ADDED)?'+':'-';
            }
        } else if (node->checked&NODE_CHANGED) {
            for(i=0;i<report_attrs_order_length;i++) {
                char c, u, a, d, g, s;
                DB_ATTR_TYPE attrs = get_attrs(report_attrs_order[i]);
                c = attributes[report_attrs_order[i]].summary_char;
                d = '-'; a = '+'; g = ':'; u = '.'; s = ' ';
                switch (i) {
                    case 0:
                        summary[i]=get_f_type_char_from_perm((node->new_data)->perm);
                        continue;
                    case 2:
                        if (attrs&(node->changed_attrs&(~(report->ignore_removed_attrs))) && (node->old_data)->size > (node->new_data)->size) {
                            c = '<';
                        }
                        u = '=';
                        break;
                }
                if (attrs&node->changed_attrs&(report->force_attrs|(~(report->ignore_changed_attrs)))) {
                    summary[i]=c;
                } else if (attrs&((node->old_data)->attr&~((node->new_data)->attr)&(report->force_attrs|~(report->ignore_removed_attrs)))) {
                    summary[i]=d;
                } else if (attrs&~((node->old_data)->attr)&(node->new_data)->attr&(report->force_attrs|~(report->ignore_added_attrs))) {
                    summary[i]=a;
                } else if (attrs& (
                             (((node->old_data)->attr&~((node->new_data)->attr)&report->ignore_removed_attrs))|
                            (~((node->old_data)->attr)&(node->new_data)->attr&report->ignore_added_attrs)|
                             (((node->old_data)->attr&(node->new_data)->attr)&report->ignore_changed_attrs)
                            ) ) {
                    summary[i]=g;
                } else if (attrs&((node->old_data)->attr&(node->new_data)->attr)) {
                    summary[i]=u;
                } else {
                    summary[i]=s;
                }
            }
        }
        summary[report_attrs_order_length]='\0';
    return summary;
}



static DB_ATTR_TYPE get_report_attributes(seltree* node, report_t *report) {
    db_line* oline = node->old_data;
    db_line* nline = node->new_data;
    DB_ATTR_TYPE attrs = node->changed_attrs;

    DB_ATTR_TYPE report_attrs, changed_attrs;

    changed_attrs = ~(report->ignore_changed_attrs)&(attrs
#ifdef WITH_E2FSATTRS
            & (~ATTR(attr_e2fsattrs) | ( (attrs&ATTR(attr_e2fsattrs) && oline != NULL && nline != NULL && ~(report->ignore_e2fsattrs)&(oline->e2fsattrs^nline->e2fsattrs)) ? ATTR(attr_e2fsattrs) : 0 ) )
#endif
            );

    report_attrs = 0LL;
    report_attrs |= changed_attrs;

    if (report->level >= REPORT_LEVEL_ADDED_REMOVED_ATTRIBUTES && oline&&nline) {
        report_attrs |= ~(oline->attr)&nline->attr&~(report->ignore_added_attrs); /* added attributes */
        report_attrs |= oline->attr&~(nline->attr)&~(report->ignore_removed_attrs); /* removed attributes */
    }
    report_attrs |= report_attrs?report->force_attrs:0; /* forced attributes */

    return report_attrs;
}

static void terse_report(seltree* node) {
    list* l = NULL;

    pthread_mutex_lock(&node->mutex);
    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;

    if ((node->checked&(DB_OLD|DB_NEW)) != 0) {
        r->ntotal += ((node->checked&DB_NEW) != 0);
        if (!(node->checked&DB_OLD)){
            /* File is in new db but not old. (ADDED) */
            /* unless it was moved in */
            if ( (conf->action&DO_INIT && r->detailed_init) || (conf->action&(DO_COMPARE|DO_DIFF) && !((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) ) {
#ifdef WITH_AUDIT
                nadd++;
#endif
                r->nadd++;
                node->checked|=NODE_ADDED;
            }
        } else if (!(node->checked&DB_NEW)){
            /* File is in old db but not new. (REMOVED) */
            /* unless it was moved out */
            if (!((node->checked&NODE_ALLOW_RM)||(node->checked&NODE_MOVED_OUT))) {
#ifdef WITH_AUDIT
                nrem++;
#endif
                r->nrem++;
                node->checked|=NODE_REMOVED;
            }
        } else if ((node->old_data!=NULL)&&(node->new_data!=NULL)){
            /* File is in both db's and the data is still there. (CHANGED) */
            if (!(node->checked&(NODE_MOVED_IN|NODE_MOVED_OUT))){
                if (r->level >= REPORT_LEVEL_LIST_ENTRIES
                  && ((node->old_data->attr&~(r->ignore_removed_attrs))^(node->new_data->attr&~(r->ignore_added_attrs)))&((node->old_data->attr)^(node->new_data->attr)) ) {
                    r->diff_attrs_entries = checked_realloc(r->diff_attrs_entries, (r->num_diff_attrs_entries+1) * sizeof(diff_attrs_entry));
                    r->diff_attrs_entries[r->num_diff_attrs_entries].entry = node->old_data->filename;
                    r->diff_attrs_entries[r->num_diff_attrs_entries].old_attrs = node->old_data->attr&~(r->ignore_removed_attrs);
                    r->diff_attrs_entries[r->num_diff_attrs_entries].new_attrs = node->new_data->attr&~(r->ignore_added_attrs);
                    r->num_diff_attrs_entries++;
                }
                DB_ATTR_TYPE changed_attrs = (node->changed_attrs)&~(r->ignore_changed_attrs);
                if (changed_attrs
#ifdef WITH_E2FSATTRS
                    &~ATTR(attr_e2fsattrs) || (changed_attrs&ATTR(attr_e2fsattrs) && ~(r->ignore_e2fsattrs)&(node->old_data->e2fsattrs^node->new_data->e2fsattrs))
#endif
                ) {
                    r->nchg++;
                    node->checked|=NODE_CHANGED;
                }
#ifdef WITH_AUDIT
                nchg++;
#endif
            }else if (!((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) {
#ifdef WITH_AUDIT
                nadd++;
#endif
                r->nadd++;
                node->checked|=NODE_ADDED;
            }else if (!((node->checked&NODE_ALLOW_RM)||(node->checked&NODE_MOVED_OUT))) {
#ifdef WITH_AUDIT
                nrem++;
#endif
                r->nrem++;
                node->checked|=NODE_REMOVED;
            }
        }
    }

        added_entries_reported |= r->nadd != 0;
        removed_entries_reported |= r->nrem != 0;
        changed_entries_reported |= r->nchg != 0;
    }

    for(tree_node *x = tree_walk_first(node->children); x != NULL ; x = tree_walk_next(x)) {
        terse_report(tree_get_data(x));
    }
    pthread_mutex_unlock(&node->mutex);
}

void print_report_entries(report_t *report, seltree* node, const int node_status, void (*print_line)(report_t*, char*, int, seltree*)) {

    pthread_mutex_lock(&node->mutex);
    if (node->checked&node_status)  {
            if (!(node->changed_attrs) || ~(report->ignore_changed_attrs)&(node->changed_attrs
#ifdef WITH_E2FSATTRS
                & (~ATTR(attr_e2fsattrs) | (node->changed_attrs&ATTR(attr_e2fsattrs) && ~(report->ignore_e2fsattrs)&(node->old_data->e2fsattrs^node->new_data->e2fsattrs)?ATTR(attr_e2fsattrs):0))
#endif
            )) {
        print_line(report, ((node->checked&NODE_REMOVED)?node->old_data:node->new_data)->filename, node->checked, node);
            }

    }
    for(tree_node *x = tree_walk_first(node->children); x != NULL ; x = tree_walk_next(x)) {
        print_report_entries(report, tree_get_data(x), node_status, print_line);
    }
    pthread_mutex_unlock(&node->mutex);
}

void print_dbline_attrs(report_t * report, db_line* oline, db_line* nline, DB_ATTR_TYPE report_attrs, void (*print_attribute)(report_t *, db_line*, db_line*, ATTRIBUTE)) {
    for (int j=0; j < report_attrs_order_length; ++j) {
        switch(report_attrs_order[j]) {
            case attr_allhashsums:
                for (int i = 0 ; i < num_hashes ; ++i) {
                    if (ATTR(hashsums[i].attribute)&report_attrs) { print_attribute(report, oline, nline, hashsums[i].attribute); }
                }
                break;
            case attr_size:
                if (ATTR(attr_size)&report_attrs) { print_attribute(report, oline, nline, attr_size); }
                if (ATTR(attr_sizeg)&report_attrs) { print_attribute(report, oline, nline, attr_sizeg); }
                break;
            default:
                if (ATTR(report_attrs_order[j])&report_attrs) { print_attribute(report, oline, nline, report_attrs_order[j]); }
                break;
        }
    }
}


void print_databases_attrs(report_t *report, void (*print_database_attributes)(report_t *, db_line*)) {
    if (conf->database_in.db_line) {
        print_database_attributes(report, conf->database_in.db_line);
    }
    if (conf->database_out.db_line) {
        print_database_attributes(report, conf->database_out.db_line);
    }
    if (conf->database_new.db_line) {
        print_database_attributes(report, conf->database_new.db_line);
    }
}

void print_report_details(report_t *report, seltree* node, void (*print_attributes)(report_t *, db_line*, db_line*, DB_ATTR_TYPE)) {
    pthread_mutex_lock(&node->mutex);
    if (node->checked&NODE_CHANGED) {
        print_attributes(report, node->old_data, node->new_data, get_report_attributes(node, report));
    }
    if (report->level >= REPORT_LEVEL_ADDED_REMOVED_ENTRIES) {
        if (node->checked&NODE_ADDED) {
            print_attributes(report, NULL, node->new_data, (node->new_data)->attr&~(report->ignore_added_attrs));
        }
        if (node->checked&NODE_REMOVED) {
            print_attributes(report, node->old_data, NULL, (node->old_data)->attr&~(report->ignore_removed_attrs));
        }
    }
    for(tree_node *x = tree_walk_first(node->children); x != NULL ; x = tree_walk_next(x)) {
        print_report_details(report, tree_get_data(x), print_attributes);
    }
    pthread_mutex_unlock(&node->mutex);
}

#ifdef WITH_AUDIT
  /* Something changed, send audit anomaly message */
void send_audit_report()
{
  if(nadd!=0||nrem!=0||nchg!=0){
    int fd=audit_open();
    if (fd>=0){
       char msg[64];

       snprintf(msg, sizeof(msg), "added=%ld removed=%ld changed=%ld", 
                nadd, nrem, nchg);

       if (audit_log_user_message(fd, AUDIT_ANOM_RBAC_INTEGRITY_FAIL,
                                  msg, NULL, NULL, NULL, 0)<=0)
#ifdef HAVE_SYSLOG
          syslog(LOG_ERR, "Failed sending audit message:%s", msg);
#else
          ;
#endif
       close(fd);
    }
  }
}
#endif /* WITH_AUDIT */


static void print_report(report_t * report, seltree * node, report_format_module module) {
    if (module.print_report_header) {
        module.print_report_header(report);
    }

    module.print_report_diff_attrs_entries(report);

    if (report->level >= REPORT_LEVEL_SUMMARY) {
        char *time = get_time_string(&(conf->start_time));
        module.print_report_starttime_version(report, time, conf->aide_version);
        free(time); time=NULL;
    }

    module.print_report_outline(report);

    if (report->level >= REPORT_LEVEL_SUMMARY) {
        if(conf->action&DO_INIT) {
            module.print_report_new_database_written(report);
        }
        module.print_report_config_options(report);
    }

    if (report->level >= REPORT_LEVEL_LIST_ENTRIES) {
        module.print_report_report_options(report);
    }

    if (report->level >= REPORT_LEVEL_SUMMARY) {
        module.print_report_summary(report);
    }

    if (conf->action&(DO_COMPARE|DO_DIFF) || (conf->action&DO_INIT && report->detailed_init)) {
        if (report->level >= REPORT_LEVEL_LIST_ENTRIES) {
            if (report->grouped) {
                if (report->nadd) {
                    module.print_report_entries(report, node, NODE_ADDED);
                }
                if (report->nrem) {
                    module.print_report_entries(report, node, NODE_REMOVED);
                }
                if (report->nchg) {
                    module.print_report_entries(report, node, NODE_CHANGED);
                }
            } else {
                if (report->nadd || report->nrem || report->nchg) {
                    module.print_report_entries(report, node, NODE_ADDED|NODE_REMOVED|NODE_CHANGED);
                }
            }
        }
        if ( (report->nchg && report->level >= REPORT_LEVEL_CHANGED_ATTRIBUTES) || ( (report->nadd || report->nrem) && report->level >= REPORT_LEVEL_ADDED_REMOVED_ENTRIES) ) {
            module.print_report_details(report, node);
        }
    }

    if (report->level >= REPORT_LEVEL_DATABASE_ATTRIBUTES) {
        if (conf->database_in.db_line || conf->database_out.db_line || conf->database_new.db_line) {

            module.print_report_databases(report);
        }
    }

    if (report->level >= REPORT_LEVEL_SUMMARY) {
        char *time = get_time_string(&(conf->end_time));
        long run_time = (long) difftime(conf->end_time, conf->start_time);
        module.print_report_endtime_runtime(report, time, run_time);
        free(time); time=NULL;
    }
    if (module.print_report_footer) {
        module.print_report_footer(report);
    }
}

int gen_report(seltree* node) {
    list* report_list = NULL;

    terse_report(node);

#ifdef WITH_AUDIT
    send_audit_report();
#endif

    for (report_list=conf->report_urls; report_list; report_list=report_list->next) {
        report_t* report = report_list->data;
        switch(report->format) {
            case REPORT_FORMAT_PLAIN:
                print_report(report, node, report_module_plain);
                break;
            case REPORT_FORMAT_JSON: ;
                print_report(report, node, report_module_json);
                break;
        }
    }

    return conf->action&(DO_COMPARE|DO_DIFF) ? (added_entries_reported)*1+(removed_entries_reported!=0)*2+(changed_entries_reported!=0)*4 : 0;
}

// vi: ts=8 sw=8
