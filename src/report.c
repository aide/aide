/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2007,2010-2013,2015,2016,2018-2020 Rami Lehti,
 * Pablo Virolainen, Richard van den Berg, Mike Markley, Hannes von Haugwitz
 * $Id$
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "aide.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#ifdef WITH_AUDIT
#include <libaudit.h>
#endif
#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif

#include "attributes.h"
#include "base64.h"
#include "db_config.h"
#include "gen_list.h"
#include "list.h"
#include "db.h"
#include "be.h"
#include "util.h"
#include "commandconf.h"
#include "gen_list.h"
#include "report.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#include "md.h"

/*************/
/* construction area for report lines */

const int width_details = 80;

const char time_format[] = "%Y-%m-%d %H:%M:%S %z";
const int time_string_len = 26;

#ifdef WITH_AUDIT
long nadd, nrem, nchg = 0;
#endif
int added_entries_reported, removed_entries_reported, changed_entries_reported = 0;

const char* report_top_format = "\n\n---------------------------------------------------\n%s:\n---------------------------------------------------\n";

const DB_ATTR_TYPE summary_attributes[] = { DB_FTYPE, DB_LINKNAME, DB_SIZE|DB_SIZEG, DB_BCOUNT, DB_PERM, DB_UID, DB_GID, DB_ATIME, DB_MTIME, DB_CTIME, DB_INODE, DB_LNKCOUNT, DB_HASHES
#ifdef WITH_ACL
        , DB_ACL
#endif
#ifdef WITH_XATTR
        , DB_XATTRS
#endif
#ifdef WITH_SELINUX
        , DB_SELINUX
#endif
#ifdef WITH_E2FSATTRS
        , DB_E2FSATTRS
#endif
#ifdef WITH_CAPABILITIES
        , DB_CAPABILITIES
#endif
};

const char summary_char[] = { '!' ,'l', '>', 'b', 'p', 'u', 'g', 'a', 'm', 'c', 'i', 'n', 'D'
#ifdef WITH_ACL
    , 'A'
#endif
#ifdef WITH_XATTR
    , 'X'
#endif
#ifdef WITH_SELINUX
    , 'S'
#endif
#ifdef WITH_E2FSATTRS
    , 'E'
#endif
#ifdef WITH_CAPABILITIES
    , 'C'
#endif
};

const DB_ATTR_TYPE details_attributes[] = { DB_FTYPE, DB_LINKNAME, DB_SIZE, DB_SIZEG, DB_BCOUNT, DB_PERM, DB_UID, DB_GID, DB_ATIME, DB_MTIME, DB_CTIME, DB_INODE, DB_LNKCOUNT, DB_MD5, DB_SHA1, DB_RMD160, DB_TIGER, DB_SHA256, DB_SHA512
    , DB_CRC32, DB_HAVAL, DB_GOST, DB_CRC32B, DB_WHIRLPOOL
#ifdef WITH_ACL
        , DB_ACL
#endif
#ifdef WITH_XATTR
        , DB_XATTRS
#endif
#ifdef WITH_SELINUX
        , DB_SELINUX
#endif
#ifdef WITH_E2FSATTRS
        , DB_E2FSATTRS
#endif
#ifdef WITH_CAPABILITIES
        , DB_CAPABILITIES
#endif
};

const char* details_string[] = { _("File type") , _("Lname"), _("Size"), _("Size (>)"), _("Bcount"), _("Perm"), _("Uid"), _("Gid"), _("Atime"), _("Mtime"), _("Ctime"), _("Inode"), _("Linkcount"), _("MD5"), _("SHA1"), _("RMD160"), _("TIGER"), _("SHA256"), _("SHA512")
    , _("CRC32"), _("HAVAL"), _("GOST"), _("CRC32B"), _("WHIRLPOOL")
#ifdef WITH_ACL
    , _("ACL")
#endif
#ifdef WITH_XATTR
    , _("XAttrs")
#endif
#ifdef WITH_SELINUX
    , _("SELinux")
#endif
#ifdef WITH_E2FSATTRS
    , _("E2FSAttrs")
#endif
#ifdef WITH_CAPABILITIES
    , _("Caps")
#endif
};

#ifdef WITH_E2FSATTRS
    /* flag->character mappings taken from lib/e2p/pf.c (git commit c46b57b)
     * date: 2015-05-10
     * sources: git://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git
     *
     * on update see also do_e2fsattrs in commandconf.c
     */
    unsigned long flag_bits[] = { EXT2_SECRM_FL, EXT2_UNRM_FL, EXT2_SYNC_FL, EXT2_DIRSYNC_FL, EXT2_IMMUTABLE_FL,
        EXT2_APPEND_FL, EXT2_NODUMP_FL, EXT2_NOATIME_FL, EXT2_COMPR_FL, EXT2_COMPRBLK_FL,
        EXT2_DIRTY_FL, EXT2_NOCOMPR_FL,
#ifdef EXT2_ECOMPR_FL
        EXT2_ECOMPR_FL,
#else
        EXT4_ENCRYPT_FL,
#endif
        EXT3_JOURNAL_DATA_FL, EXT2_INDEX_FL,
        EXT2_NOTAIL_FL, EXT2_TOPDIR_FL
#ifdef EXT4_EXTENTS_FL
        , EXT4_EXTENTS_FL
#endif
#ifdef EXT4_HUGE_FILE_FL
        , EXT4_HUGE_FILE_FL
#endif
#ifdef FS_NOCOW_FL
    , FS_NOCOW_FL
#endif
#ifdef EXT4_INLINE_DATA_FL
    , EXT4_INLINE_DATA_FL
#endif

    };
    char flag_char[] = { 's', 'u', 'S', 'D', 'i', 'a', 'd', 'A', 'c', 'B', 'Z', 'X', 'E', 'j', 'I', 't', 'T'
#ifdef EXT4_EXTENTS_FL
    , 'e'
#endif
#ifdef EXT4_HUGE_FILE_FL
    , 'h'
#endif
#ifdef FS_NOCOW_FL
    , 'C'
#endif
#ifdef EXT4_INLINE_DATA_FL
    , 'N'
#endif
    };
/*************/
#endif

typedef struct report_t {
    url_t* url;
    FILE* fd;

    REPORT_LEVEL level;

    int detailed_init;
    int base16;
    int quiet;
    int summarize_changes;
    int grouped;

#ifdef WITH_E2FSATTRS
    long ignore_e2fsattrs;
#endif

    DB_ATTR_TYPE ignore_added_attrs;
    DB_ATTR_TYPE ignore_removed_attrs;
    DB_ATTR_TYPE ignore_changed_attrs;
    DB_ATTR_TYPE force_attrs;

    long ntotal;
    long nadd, nrem, nchg;

} report_t;

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

static char get_file_type_char(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return 'f';
        case S_IFDIR: return 'd';
#ifdef S_IFIFO
        case S_IFIFO: return 'p';
#endif
        case S_IFLNK: return 'l';
        case S_IFBLK: return 'b';
        case S_IFCHR: return 'c';
#ifdef S_IFSOCK
        case S_IFSOCK: return 's';
#endif
#ifdef S_IFDOOR
        case S_IFDOOR: return 'D';
#endif
#ifdef S_IFPORT
        case S_IFPORT: return 'P';
#endif
        default: return '?';
    }
}



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
    *values = malloc(n * sizeof(char*));
    (*values)[0]=malloc((6+floor(log10(n)))*sizeof(char));
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
                (*values)[num]=malloc(length *sizeof(char));
                snprintf((*values)[num], length , "[%.*zd] %s = %s", width, num, xattrs->ents[num - 1].key, val);
            } else {
                val = encode_base64(xattrs->ents[num - 1].val, xattrs->ents[num - 1].vsz);
                length = 10 + width + strlen(xattrs->ents[num - 1].key) + strlen(val);
                (*values)[num]=malloc( length  *sizeof(char));
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
                    (*values)[j]=malloc(4+(i-k)*sizeof(char)); \
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
        *values = malloc(n * sizeof(char*));
        j = 0;
        easy_posix_acl(acl_a, 'A')
        easy_posix_acl(acl_d, 'D')
    }
#endif
#ifdef WITH_SUN_ACL
/* FIXME: readd sun acl support */
#endif
    return n;
}
#endif

#ifdef WITH_E2FSATTRS
static char* e2fsattrs2string(unsigned long flags, int flags_only, unsigned long ignore_e2fsattrs) {
    int length = sizeof(flag_bits)/sizeof(long);
    char* string = malloc ((length+1) * sizeof (char));
    int j = 0;
    for (int i = 0 ; i < length ; i++) {
        if (!flags_only && flag_bits[i]&ignore_e2fsattrs) {
            string[j++]=':';
        } else if (flag_bits[i] & flags) {
            string[j++]=flag_char[i];
        } else if (!flags_only) {
            string[j++]='-';
        }
    }
    string[j] = '\0';
    return string;
}
#endif

static char* get_file_type_string(mode_t mode) {
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

static const char* get_report_level_string(REPORT_LEVEL report_level) {
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

static void report_vprintf(report_t* r, const char *format, va_list ap) {
    int retval;

if (!r->quiet || (r->nadd || r->nchg || r->nrem)) {
    switch ((r->url)->type) {
#ifdef HAVE_SYSLOG
        case url_syslog: {
#ifdef HAVE_VSYSLOG
            vsyslog(SYSLOG_PRIORITY,format,ap);
#else
            char buf[1024];
            vsnprintf(buf,1024,format,ap);
            syslog(SYSLOG_PRIORITY,"%s",buf);
#endif
            break;
        }
#endif
        default : {
    retval=vfprintf(r->fd, format, ap);
    if(retval==0) {
        error(0, "unable to write to '%s", (r->url)->value);
    }
            break;
        }
    }

}

}

static void report_printf(report_t* r, const char* error_msg, ...) {
    va_list ap;

    va_start(ap, error_msg);
    report_vprintf(r, error_msg, ap);
    va_end(ap);

}

static void report(REPORT_LEVEL report_level, const char* error_msg, ...) {
    va_list ap;
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;
        if (report_level <= r->level) {
            va_start(ap, error_msg);
            report_vprintf(r, error_msg, ap);
            va_end(ap);
        } else {
            break; /* list sorted by report_level */
        }
    }
}

static int compare_report_t_by_report_level(const void *n1, const void *n2)
{
    const report_t *x1 = n1;
    const report_t *x2 = n2;
    return x2->level - x1->level;
}

int add_report_url(url_t* url) {
    list* report_urls=NULL;
    FILE* fh=NULL;

    for(report_urls=conf->report_urls; report_urls ; report_urls=report_urls->next) {
        if (cmp_url((url_t*) report_urls->data, url)) {
            error(1, _("report_url '%s' already defined, ignoring") ,url->value);
            return RETOK;
        }
    }

    switch (url->type) {
#ifdef HAVE_SYSLOG
        int sfac;
        case url_syslog: {
            sfac=syslog_facility_lookup(url->value);
            openlog(AIDE_IDENT,AIDE_LOGOPT, sfac);
            break;
        }
#endif
        default : {
            fh=be_init(0,url,0);
            if(fh==NULL) {
                return false;
            }
            break;
        }
    }

    report_t* r = malloc(sizeof(report_t));
    r->url = url;
    r->fd = fh;
    r->level = conf->report_level;

    r->detailed_init = conf->report_detailed_init;
    r->base16 = conf->report_base16;
    r->quiet = conf->report_quiet;
    r->summarize_changes = conf->summarize_changes;
    r->grouped = conf->grouped;

    r->ignore_added_attrs = conf->report_ignore_added_attrs;
    r->ignore_removed_attrs = conf->report_ignore_removed_attrs;
    r->ignore_changed_attrs = conf->report_ignore_changed_attrs;
    r->force_attrs = conf->report_force_attrs;

    r->ntotal = 0;
    r->nadd = 0;
    r->nrem = 0;
    r->nchg = 0;

#ifdef WITH_E2FSATTRS
    r->ignore_e2fsattrs = conf->report_ignore_e2fsattrs;
#endif

    conf->report_urls=list_sorted_insert(conf->report_urls, (void*) r, compare_report_t_by_report_level);
    return RETOK;

}

static char* byte_to_base16(byte* src, size_t ssize) {
    char* str = malloc((2*ssize+1) * sizeof (char));
    size_t i;
    for(i=0; i < ssize; ++i) {
        snprintf(&str[2*i], 3, "%02x", src[i]);
    }
    return str;
}

static int get_attribute_values(DB_ATTR_TYPE attr, db_line* line,
        char* **values, report_t* r) {

#define easy_string(s) \
l = strlen(s)+1; \
*values[0] = malloc(l * sizeof (char)); \
snprintf(*values[0], l, "%s",s);

#define easy_md(a,b,c) \
} else if (a&attr) { \
    if (r->base16) { \
        *values[0] = byte_to_base16(line->b, c); \
    } else { \
        *values[0] = encode_base64(line->b, c); \
    }

#define easy_number(a,b,c) \
} else if (a&attr) { \
    l = 2+floor(line->b?log10(line->b):0); \
    *values[0] = malloc(l * sizeof (char)); \
    snprintf(*values[0], l, c,line->b);

#define easy_time(a,b) \
} else if (a&attr) { \
    *values[0] = malloc(time_string_len * sizeof (char));  \
    strftime(*values[0], time_string_len, time_format, localtime(&(line->b)));

    if (line==NULL || !(line->attr&attr)) {
        *values = NULL;
        return 0;
#ifdef WITH_ACL
    } else if (DB_ACL&attr) {
        return acl2array(line->acl, values);
#endif
#ifdef WITH_XATTR
    } else if (DB_XATTRS&attr) {
        return xattrs2array(line->xattrs, values);
#endif
    } else {
        int l;
        *values = malloc(1 * sizeof (char*));
        if (DB_FTYPE&attr) {
            easy_string(get_file_type_string(line->perm))
        } else if (DB_LINKNAME&attr) {
            easy_string(line->linkname)
        easy_number((DB_SIZE|DB_SIZEG),size,"%lli")
        } else if (DB_PERM&attr) {
            *values[0] = perm_to_char(line->perm);
        easy_time(DB_ATIME,atime)
        easy_time(DB_MTIME,mtime)
        easy_time(DB_CTIME,ctime)
        easy_number(DB_BCOUNT,bcount,"%lli")
        easy_number(DB_UID,uid,"%li")
        easy_number(DB_GID,gid,"%li")
        easy_number(DB_INODE,inode,"%li")
        easy_number(DB_LNKCOUNT,nlink,"%li")
        easy_md(DB_MD5,md5,HASH_MD5_LEN)
        easy_md(DB_SHA1,sha1,HASH_SHA1_LEN)
        easy_md(DB_RMD160,rmd160,HASH_RMD160_LEN)
        easy_md(DB_TIGER,tiger,HASH_TIGER_LEN)
        easy_md(DB_SHA256,sha256,HASH_SHA256_LEN)
        easy_md(DB_SHA512,sha512,HASH_SHA512_LEN)
        easy_md(DB_CRC32,crc32,HASH_CRC32_LEN)
        easy_md(DB_HAVAL,haval,HASH_HAVAL256_LEN)
        easy_md(DB_GOST,gost,HASH_GOST_LEN)
        easy_md(DB_CRC32B,crc32b,HASH_CRC32B_LEN)
        easy_md(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN)
#ifdef WITH_SELINUX
        } else if (DB_SELINUX&attr) {
            easy_string(line->cntx)
#endif
#ifdef WITH_E2FSATTRS
        } else if (DB_E2FSATTRS&attr) {
            *values[0]=e2fsattrs2string(line->e2fsattrs, 0, r->ignore_e2fsattrs);
#endif
#ifdef WITH_CAPABILITIES
        } else if (DB_CAPABILITIES&attr) {
            easy_string(line->capabilities)
#endif
        } else {
            easy_string("unknown attribute")
        }
        return 1;
    }
}

static void print_line(seltree* node, const int grouped, const int node_status) {
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;

if ((!(conf->action&DO_INIT) || r->detailed_init)
   && (r->grouped == grouped && node->checked&node_status) ) {

        if (r->level >= REPORT_LEVEL_LIST_ENTRIES) {
            if (!(node->changed_attrs) || ~(r->ignore_changed_attrs)&(node->changed_attrs
#ifdef WITH_E2FSATTRS
                & (~DB_E2FSATTRS | (node->changed_attrs&DB_E2FSATTRS && ~(r->ignore_e2fsattrs)&(node->old_data->e2fsattrs^node->new_data->e2fsattrs)?DB_E2FSATTRS:0))
#endif
            )) {

    if(r->summarize_changes) {
        int i;
        int length = sizeof(summary_attributes)/sizeof(DB_ATTR_TYPE);
        char* summary = malloc ((length+1) * sizeof (char));
        if (node->checked&(NODE_ADDED|NODE_REMOVED)) {
            summary[0]=get_file_type_char(((node->checked&NODE_REMOVED)?node->old_data:node->new_data)->perm);
            for(i=1;i<length;i++){
                summary[i]=(node->checked&NODE_ADDED)?'+':'-';
            }
        } else if (node->checked&NODE_CHANGED) {
            for(i=0;i<length;i++) {
                char c, u, a, d, g, s;
                c = summary_char[i];
                d = '-'; a = '+'; g = ':'; u = '.'; s = ' ';
                switch (i) {
                    case 0:
                        summary[i]=get_file_type_char((node->new_data)->perm);
                        continue;
                    case 2:
                        if (summary_attributes[i]&(node->changed_attrs&(~(r->ignore_removed_attrs))) && (node->old_data)->size > (node->new_data)->size) {
                            c = '<';
                        }
                        u = '=';
                        break;
                }
                if (summary_attributes[i]&node->changed_attrs&(r->force_attrs|(~(r->ignore_changed_attrs)))) {
                    summary[i]=c;
                } else if (summary_attributes[i]&((node->old_data)->attr&~((node->new_data)->attr)&(r->force_attrs|~(r->ignore_removed_attrs)))) {
                    summary[i]=d;
                } else if (summary_attributes[i]&~((node->old_data)->attr)&(node->new_data)->attr&(r->force_attrs|~(r->ignore_added_attrs))) {
                    summary[i]=a;
                } else if (summary_attributes[i]& (
                             (((node->old_data)->attr&~((node->new_data)->attr)&r->ignore_removed_attrs))|
                            (~((node->old_data)->attr)&(node->new_data)->attr&r->ignore_added_attrs)|
                             (((node->old_data)->attr&(node->new_data)->attr)&r->ignore_changed_attrs)
                            ) ) {
                    summary[i]=g;
                } else if (summary_attributes[i]&((node->old_data)->attr&(node->new_data)->attr)) {
                    summary[i]=u;
                } else {
                    summary[i]=s;
                }
            }
        }
        summary[length]='\0';
        report_printf(r, "\n%s: %s", summary, ((node->checked&NODE_REMOVED)?node->old_data:node->new_data)->filename);
        free(summary); summary=NULL;
    } else {
        if (node->checked&NODE_ADDED) {
            report_printf(r,_("\nadded: %s"),(node->new_data)->filename);
        } else if (node->checked&NODE_REMOVED) {
            report_printf(r,_("\nremoved: %s"),(node->old_data)->filename);
        } else if (node->checked&NODE_CHANGED) {
            report_printf(r,_("\nchanged: %s"),(node->new_data)->filename);
        }
    }
            }
        } else {
            break; /* list sorted by report_level */
        }
}
    }
}

static void print_dbline_attributes(REPORT_LEVEL report_level, db_line* oline, db_line* nline, DB_ATTR_TYPE attrs, bool force) {
    char **ovalue, **nvalue;
    int onumber, nnumber, olen, nlen, i, j, k, c;
    int length = sizeof(details_attributes)/sizeof(DB_ATTR_TYPE);
    int p = (width_details-(width_details%2?13:14))/2;


    DB_ATTR_TYPE report_attrs, added_attrs, removed_attrs, changed_attrs, forced_attrs;
    list* l = NULL;

    char *file_type = get_file_type_string((nline==NULL?oline:nline)->perm);

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;

        if ( !(conf->action&DO_INIT) || r->detailed_init || force) {

        added_attrs = oline&&nline?(~(oline->attr)&nline->attr&~(r->ignore_added_attrs)):0;
        removed_attrs = oline&&nline?(oline->attr&~(nline->attr)&~(r->ignore_removed_attrs)):0;

        changed_attrs = ~(r->ignore_changed_attrs)&(attrs
#ifdef WITH_E2FSATTRS
        & (~DB_E2FSATTRS | (attrs&DB_E2FSATTRS && ~(r->ignore_e2fsattrs)&(oline->e2fsattrs^nline->e2fsattrs)?DB_E2FSATTRS:0))
#endif
);
        forced_attrs = (oline && nline)?r->force_attrs:attrs;

        report_attrs=changed_attrs?forced_attrs|changed_attrs:0;

        if  (r->level >= report_level && changed_attrs)  {
            report_printf(r, "\n");
            if (file_type) {
                report_printf(r, "%s: ", file_type);
            }
            report_printf(r, "%s\n", (nline==NULL?oline:nline)->filename);
        }

    for (j=0; j < length; ++j) {
        if ( (details_attributes[j]&report_attrs && r->level >= report_level)
          || (report_attrs && details_attributes[j]&(added_attrs|removed_attrs) && r->level >= REPORT_LEVEL_ADDED_REMOVED_ATTRIBUTES) ) {
            onumber=get_attribute_values(details_attributes[j], oline, &ovalue, r);
            nnumber=get_attribute_values(details_attributes[j], nline, &nvalue, r);

            i = 0;
            while (i<onumber || i<nnumber) {
                olen = i<onumber?strlen(ovalue[i]):0;
                nlen = i<nnumber?strlen(nvalue[i]):0;
                k = 0;
                while (olen-p*k >= 0 || nlen-p*k >= 0) {
                    c = k*(p-1);
                    if (!onumber) {
                        report_printf(r," %s%-9s%c %-*c  %.*s\n", width_details%2?"":" ", (i+k)?"":details_string[j], (i+k)?' ':':', p, ' ', p-1, nlen-c>0?&nvalue[i][c]:"");
                    } else if (!nnumber) {
                        report_printf(r," %s%-9s%c %.*s\n", width_details%2?"":" ", (i+k)?"":details_string[j], (i+k)?' ':':', p-1, olen-c>0?&ovalue[i][c]:"");
                    } else {
                        report_printf(r," %s%-9s%c %-*.*s| %.*s\n", width_details%2?"":" ", (i+k)?"":details_string[j], (i+k)?' ':':', p, p-1, olen-c>0?&ovalue[i][c]:"", p-1, nlen-c>0?&nvalue[i][c]:"");
                    }
                    k++;
                }
                ++i;
            }
            for(i=0; i < onumber; ++i) { free(ovalue[i]); ovalue[i]=NULL; } free(ovalue); ovalue=NULL;
            for(i=0; i < nnumber; ++i) { free(nvalue[i]); nvalue[i]=NULL; } free(nvalue); nvalue=NULL;
        }
    }
    }
    }

}

static void print_attributes_added_node(REPORT_LEVEL report_level, db_line* line) {
    print_dbline_attributes(report_level, NULL, line, line->attr, false);
}

static void print_attributes_removed_node(REPORT_LEVEL report_level, db_line* line) {
    print_dbline_attributes(report_level, line, NULL, line->attr, false);
}

static void terse_report(seltree* node) {
    list* n = NULL;
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;

    if ((node->checked&(DB_OLD|DB_NEW)) != 0) {
        r->ntotal += ((node->checked&DB_NEW) != 0);
        if (!(node->checked&DB_OLD)){
            /* File is in new db but not old. (ADDED) */
            /* unless it was moved in */
            if (conf->action&DO_INIT?r->detailed_init:!((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) {
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
                  && (node->old_data->attr&~(r->ignore_removed_attrs))^(node->new_data->attr&~(r->ignore_added_attrs)) ) {
                    char *str = NULL;
                    report_printf(r, "Entry %s in databases has different attributes: %s\n",
                            node->old_data->filename,str= diff_attributes(node->old_data->attr&~(r->ignore_removed_attrs),node->new_data->attr&~(r->ignore_added_attrs)));
                    free(str);
                }
                DB_ATTR_TYPE changed_attrs = (node->changed_attrs)&~(r->ignore_changed_attrs);
                if (changed_attrs
#ifdef WITH_E2FSATTRS
                    &~DB_E2FSATTRS || (changed_attrs&DB_E2FSATTRS && ~(r->ignore_e2fsattrs)&(node->old_data->e2fsattrs^node->new_data->e2fsattrs))
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
    for (n=node->childs;n;n=n->next) {
        terse_report((seltree*)n->data);
    }
}

static void print_report_list(seltree* node, const int grouped, const int node_status) {
    list* r=NULL;

    print_line(node, grouped, node_status);
    for(r=node->childs;r;r=r->next){
        print_report_list((seltree*)r->data, grouped, node_status);
    }
}

static void print_report_details(seltree* node) {
    list* r=NULL;
    if (node->checked&NODE_CHANGED) {
        print_dbline_attributes(REPORT_LEVEL_CHANGED_ATTRIBUTES, node->old_data, node->new_data, node->changed_attrs, false);
    }
    if (node->checked&NODE_ADDED) { print_attributes_added_node(REPORT_LEVEL_ADDED_REMOVED_ENTRIES, node->new_data); }
    if (node->checked&NODE_REMOVED) { print_attributes_removed_node(REPORT_LEVEL_ADDED_REMOVED_ENTRIES, node->old_data); }
    for(r=node->childs;r;r=r->next){
        print_report_details((seltree*)r->data);
    }
}

static void print_report_summary_line(REPORT_LEVEL report_level) {
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;
        if (r->level >= report_level) {
            report_printf(r, _(" found %sdifferences between %s%s!!\n"), (r->nadd||r->nrem||r->nchg)?"":"NO ", conf->action&DO_COMPARE?_("database and filesystem"):_("the two databases"), (r->nadd||r->nrem||r->nchg)?"":_(". Looks okay"));
        }
    }
}

static void print_report_header() {
    char *time;

    time = malloc(time_string_len * sizeof (char));
    strftime(time, time_string_len, time_format, localtime(&(conf->start_time)));
    report(REPORT_LEVEL_SUMMARY,_("Start timestamp: %s (AIDE " AIDEVERSION ")\n"), time);
    free(time); time=NULL;

    report(REPORT_LEVEL_MINIMAL,_("AIDE"));
    if(conf->action&(DO_COMPARE|DO_DIFF)) {
        print_report_summary_line(REPORT_LEVEL_MINIMAL);
        if(conf->action&(DO_INIT)) {
            report(REPORT_LEVEL_SUMMARY,_("New AIDE database written to %s\n"),conf->db_out_url->value);
        }
    } else {
        report(REPORT_LEVEL_MINIMAL,_(" initialized database at %s\n"),conf->db_out_url->value);
    }

    if(conf->config_version) {
        report(REPORT_LEVEL_SUMMARY,_("Config version used: %s\n"),conf->config_version);
    }

    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;

        if (r->level >= REPORT_LEVEL_SUMMARY) {
            int first = 1;
            if (conf->limit != NULL) {
                report_printf(r, _("Limit: %s"), conf->limit);
                first = 0;
            }

            if (conf->action&(DO_INIT|DO_COMPARE) && conf->root_prefix_length > 0) {
                if (first) { first=0; }
                else { report_printf(r," | "); }
                report_printf(r, _("Root prefix: %s"),conf->root_prefix);
            }

            if (r->level != REPORT_LEVEL_CHANGED_ATTRIBUTES) {
                if (first) { first=0; }
                else { report_printf(r," | "); }
                report_printf(r, _("Report level: %s"), get_report_level_string(r->level));
            }

            if (!first) { report_printf(r, "\n"); }
        }

            char *str;
            if (r->level >= REPORT_LEVEL_LIST_ENTRIES) {
                if (r->ignore_added_attrs) {
                    report_printf(r, _("Ignored added attributes: %s\n"), str = diff_attributes(0, r->ignore_added_attrs));
                    free(str);
                }
                if (r->ignore_removed_attrs) {
                    report_printf(r, _("Ignored removed attributes: %s\n"), str = diff_attributes(0, r->ignore_removed_attrs));
                    free(str);
                }
                if (r->ignore_changed_attrs) {
                    report_printf(r, _("Ignored changed attributes: %s\n"), str = diff_attributes(0, r->ignore_changed_attrs));
                    free(str);
                }
            }
            if (r->force_attrs && r->level >= REPORT_LEVEL_CHANGED_ATTRIBUTES) {
                report_printf(r, _("Forced attributes: %s\n"), str = diff_attributes(0, r->force_attrs));
                free(str);
            }

#ifdef WITH_E2FSATTRS
            if (r->level >= REPORT_LEVEL_LIST_ENTRIES && r->ignore_e2fsattrs) {
                report_printf(r,_("Ignored e2fs attributes: %s\n"), str = e2fsattrs2string(r->ignore_e2fsattrs, 1, 0) );
                free(str);
            }
#endif
            if (r->level >= REPORT_LEVEL_SUMMARY) {
                if(conf->action&(DO_COMPARE|DO_DIFF) && (r->nadd||r->nrem||r->nchg)) {
                    report_printf(r,_("\nSummary:\n  Total number of entries:\t%li\n  Added entries:\t\t%li\n"
                                "  Removed entries:\t\t%li\n  Changed entries:\t\t%li"), r->ntotal, r->nadd, r->nrem, r->nchg);
                } else {
                    report_printf(r, _("\nNumber of entries:\t%li"), r->ntotal);
                }
            }
    }
}

static void print_report_databases() {
    if (conf->line_db_in || conf->line_db_out) {
        report(REPORT_LEVEL_DATABASE_ATTRIBUTES,(char*)report_top_format,_("The attributes of the (uncompressed) database(s)"));
        if (conf->line_db_in) {
            print_attributes_removed_node(REPORT_LEVEL_DATABASE_ATTRIBUTES, conf->line_db_in);
        }
        if (conf->line_db_out) {
            print_dbline_attributes(REPORT_LEVEL_DATABASE_ATTRIBUTES, conf->line_db_out, NULL, (conf->line_db_out)->attr, true);
        }
    }
}

static void print_report_footer()
{
  char *time = malloc(time_string_len * sizeof (char));
  int run_time = (int) difftime(conf->end_time, conf->start_time);

  strftime(time, time_string_len, time_format, localtime(&(conf->end_time)));
  report(REPORT_LEVEL_SUMMARY,_("\n\nEnd timestamp: %s (run time: %dm %ds)\n"), time, run_time/60, run_time%60);
  free(time); time=NULL;
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

static void print_list_header(const int node_status) {
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;
        if (r->level >= REPORT_LEVEL_LIST_ENTRIES) {
            if (!r->grouped && node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED) && r->nadd && r->nrem && r->nchg) { report_printf(r,(char*)report_top_format,_("Added, removed and changed entries")); }
            else if (!r->grouped && node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED) && r->nadd && r->nrem) { report_printf(r,(char*)report_top_format,_("Added and removed entries")); }
            else if (!r->grouped && node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED) && r->nadd && r->nchg) { report_printf(r,(char*)report_top_format,_("Added and changed entries")); }
            else if (!r->grouped && node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED) && r->nrem && r->nchg) { report_printf(r,(char*)report_top_format,_("Removed and changed entries")); }
            else if (( (r->grouped && node_status == NODE_ADDED) || (!r->grouped && node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED)) ) && r->nadd) { report_printf(r,(char*)report_top_format,_("Added entries")); }
            else if (( (r->grouped && node_status == NODE_REMOVED) || (!r->grouped && node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED)) ) && r->nrem) { report_printf(r,(char*)report_top_format,_("Removed entries")); }
            else if (node_status == (NODE_ADDED|NODE_REMOVED|NODE_CHANGED) && r->nchg) { report_printf(r,(char*)report_top_format,_("Changed entries")); }
        } else {
            break; /* list sorted by report_level */
        }
    }
}

static void print_detailed_header() {
    list* l = NULL;

    for (l=conf->report_urls; l; l=l->next) {
        report_t* r = l->data;
        if ( (r->nchg && r->level >= REPORT_LEVEL_CHANGED_ATTRIBUTES) || ( (r->nadd || r->nrem) && r->level >= REPORT_LEVEL_ADDED_REMOVED_ENTRIES) ) {
            report_printf(r, (char*)report_top_format,_("Detailed information about changes"));
        }
    }
}

int gen_report(seltree* node) {

    terse_report(node);
#ifdef WITH_AUDIT
    send_audit_report();
#endif
    print_report_header();
    print_list_header(NODE_ADDED);
    print_report_list(node, 1, NODE_ADDED);
    print_list_header(NODE_REMOVED);
    print_report_list(node, 1, NODE_REMOVED);
    print_list_header(NODE_ADDED|NODE_REMOVED|NODE_CHANGED);
    print_report_list(node, 1, NODE_CHANGED);
    print_report_list(node, 0, NODE_ADDED|NODE_REMOVED|NODE_CHANGED);
    print_detailed_header();
    print_report_details(node);
    print_report_databases();
    conf->end_time=time(&(conf->end_time));
    print_report_footer();

    return conf->action&(DO_COMPARE|DO_DIFF) ? (added_entries_reported)*1+(removed_entries_reported!=0)*2+(changed_entries_reported!=0)*4 : 0;
}

const char* aide_key_9=CONFHMACKEY_09;
const char* db_key_9=DBHMACKEY_09;

// vi: ts=8 sw=8
