/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2007,2010 Rami Lehti, Pablo Virolainen, Richard van
 * den Berg, Mike Markley, Hannes von Haugwitz
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
#include <sys/stat.h>
#include <math.h>
#ifdef WITH_AUDIT
#include <libaudit.h>
#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif
#endif

#include "base64.h"
#include "report.h"
#include "db_config.h"
#include "gnu_regex.h"
#include "gen_list.h"
#include "list.h"
#include "db.h"
#include "util.h"
#include "commandconf.h"
#include "gen_list.h"
#include "compare_db.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#include "md.h"

/*************/
/* construction area for report lines */

int width_details = 80;

char time_format[] = "%Y-%m-%d %H:%M:%S";
int time_string_len = 20;

const char* report_top_format = "\n---------------------------------------------------\n%s:\n---------------------------------------------------\n\n";

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
};

const char summary_char[] = { '!' ,'l', '>', 'b', 'p', 'u', 'g', 'a', 'm', 'c', 'i', 'n', 'C'
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
};

const DB_ATTR_TYPE details_attributes[] = { DB_FTYPE, DB_LINKNAME, DB_SIZE, DB_SIZEG, DB_BCOUNT, DB_PERM, DB_UID, DB_GID, DB_ATIME, DB_MTIME, DB_CTIME, DB_INODE, DB_LNKCOUNT, DB_MD5, DB_SHA1, DB_RMD160, DB_TIGER, DB_SHA256, DB_SHA512
#ifdef WITH_MHASH
    , DB_CRC32, DB_HAVAL, DB_GOST, DB_CRC32B, DB_WHIRLPOOL
#endif
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
};

const char* details_string[] = { _("File type") , _("Lname"), _("Size"), _("Size (>)"), _("Bcount"), _("Perm"), _("Uid"), _("Gid"), _("Atime"), _("Mtime"), _("Ctime"), _("Inode"), _("Linkcount"), _("MD5"), _("SHA1"), _("RMD160"), _("TIGER"), _("SHA256"), _("SHA512")
#ifdef WITH_MHASH
    , _("CRC32"), _("HAVAL"), _("GOST"), _("CRC32B"), _("WHIRLPOOL")
#endif
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
};

#ifdef WITH_E2FSATTRS
    /* flag->character mappings defined in lib/e2p/pf.c (part of e2fsprogs-1.41.12 sources) */
    unsigned long flag_bits[] = { EXT2_SECRM_FL, EXT2_UNRM_FL, EXT2_SYNC_FL, EXT2_DIRSYNC_FL, EXT2_IMMUTABLE_FL,
        EXT2_APPEND_FL, EXT2_NODUMP_FL, EXT2_NOATIME_FL, EXT2_COMPR_FL, EXT2_COMPRBLK_FL,
        EXT2_DIRTY_FL, EXT2_NOCOMPR_FL, EXT2_ECOMPR_FL, EXT3_JOURNAL_DATA_FL, EXT2_INDEX_FL,
        EXT2_NOTAIL_FL, EXT2_TOPDIR_FL, EXT4_EXTENTS_FL, EXT4_HUGE_FILE_FL};
    char flag_char[] = "suSDiadAcBZXEjItTeh";
#endif
/*************/

static DB_ATTR_TYPE get_ignorelist() {
    DB_ATTR_TYPE ignorelist = get_groupval("ignore_list");
    return ignorelist==DB_ATTR_UNDEF?0:ignorelist;
}

static DB_ATTR_TYPE get_report_attributes() {
    DB_ATTR_TYPE forced_attrs = get_groupval("report_attributes");
    return forced_attrs==DB_ATTR_UNDEF?0:forced_attrs;
}

static char get_file_type_char(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return 'f';
        case S_IFDIR: return 'd';
#ifdef S_IFIFO
        case S_IFIFO: return 'F';
#endif
        case S_IFLNK: return 'L';
        case S_IFBLK: return 'B';
        case S_IFCHR: return 'D';
#ifdef S_IFSOCK
        case S_IFSOCK: return 's';
#endif
#ifdef S_IFDOOR
        case S_IFDOOR: return '|';
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
static char* e2fsattrs2string(unsigned long flags) {
    char* string = malloc (20 * sizeof (char));
    int i;
    for (i = 0 ; i < 19 ; i++) {
        if (flag_bits[i] & flags) {
            string[i]=flag_char[i];
        } else {
            string[i]='-';
        }
    }
    string[19] = '\0';
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
        default: return _("Unknown file type");
    }
}

static int get_attribute_values(DB_ATTR_TYPE attr, db_line* line,
        char* **values) {

#define easy_string(s) \
l = strlen(s)+1; \
*values[0] = malloc(l * sizeof (char)); \
snprintf(*values[0], l, "%s",s);

#define easy_md(a,b,c) \
} else if (a&attr) { \
    *values[0] = encode_base64(line->b, c);

#define easy_number(a,b,c) \
} else if (a&attr) { \
    l = 2+floor(line->b?log10(line->b):0); \
    *values[0] = malloc(l * sizeof (char)); \
    snprintf(*values[0], l, c,line->b);

#define easy_time(a,b) \
} else if (a&attr) { \
    *values[0] = malloc(time_string_len * sizeof (char));  \
    strftime(*values[0], time_string_len, time_format, localtime(&(line->b)));

    int l;
    if (line==NULL || !(line->attr&attr)) {
        *values = malloc(1 * sizeof (char*));
        easy_string("")
        return 1;
#ifdef WITH_ACL
    } else if (DB_ACL&attr) {
        return acl2array(line->acl, &*values);
#endif
#ifdef WITH_XATTR
    } else if (DB_XATTRS&attr) {
        return xattrs2array(line->xattrs, &*values);
#endif
    } else {
        *values = malloc(1 * sizeof (char*));
        if (DB_FTYPE&attr) {
            easy_string(get_file_type_string(line->perm))
        } else if (DB_LINKNAME&attr) {
            easy_string(line->linkname)
        easy_number((DB_SIZE|DB_SIZEG),size,"%llu")
        } else if (DB_PERM&attr) {
            *values[0] = perm_to_char(line->perm);
        easy_time(DB_ATIME,atime)
        easy_time(DB_MTIME,mtime)
        easy_time(DB_CTIME,ctime)
        easy_number(DB_BCOUNT,bcount,"%i")
        easy_number(DB_UID,uid,"%i")
        easy_number(DB_GID,gid,"%i")
        easy_number(DB_INODE,inode,"%i")
        easy_number(DB_LNKCOUNT,nlink,"%i")
        easy_md(DB_MD5,md5,HASH_MD5_LEN)
        easy_md(DB_SHA1,sha1,HASH_SHA1_LEN)
        easy_md(DB_RMD160,rmd160,HASH_RMD160_LEN)
        easy_md(DB_TIGER,tiger,HASH_TIGER_LEN)
        easy_md(DB_SHA256,sha256,HASH_SHA256_LEN)
        easy_md(DB_SHA512,sha512,HASH_SHA512_LEN)
#ifdef WITH_MHASH
        easy_md(DB_CRC32,crc32,HASH_CRC32_LEN)
        easy_md(DB_HAVAL,haval,HASH_HAVAL256_LEN)
        easy_md(DB_GOST,gost,HASH_GOST_LEN)
        easy_md(DB_CRC32B,crc32b,HASH_CRC32B_LEN)
        easy_md(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN)
#endif
#ifdef WITH_SELINUX
        } else if (DB_SELINUX&attr) {
            easy_string(line->cntx)
#endif
#ifdef WITH_E2FSATTRS
        } else if (DB_E2FSATTRS&attr) {
            *values[0]=e2fsattrs2string(line->e2fsattrs);
#endif
        } else {
            easy_string("unknown attribute")
        }
        return 1;
    }
}

static void print_line(seltree* node, DB_ATTR_TYPE ignored_attrs) {
    if(conf->summarize_changes==1) {
        int i;
        int length = sizeof(summary_attributes)/sizeof(DB_ATTR_TYPE);
        char* summary = malloc ((length+1) * sizeof (char));
        if (node->checked&(NODE_ADDED|NODE_REMOVED)) {
            summary[0]=get_file_type_char((node->checked&NODE_REMOVED?node->old_data:node->new_data)->perm);
            for(i=1;i<length;i++){
                summary[i]=node->checked&NODE_ADDED?'+':'-';
            }
        } else if (node->checked&NODE_CHANGED) {
            char c, u, a, r, g, s;
            for(i=0;i<length;i++) {
                c = summary_char[i];
                r = '-'; a = '+'; g = ':'; u = '.'; s = ' ';
                switch (i) {
                    case 0:
                        r = a = u = g = s = get_file_type_char((node->new_data)->perm);
                        break;
                    case 2:
                        if (summary_attributes[i]&(node->changed_attrs&(~ignored_attrs)) && (node->old_data)->size > (node->new_data)->size) {
                            c = '<';
                        }
                        u = '=';
                        break;
                }
                if (summary_attributes[i]&node->changed_attrs&(~ignored_attrs)) {
                    summary[i]=c;
                } else if (summary_attributes[i]&((node->old_data)->attr&~((node->new_data)->attr))) {
                    summary[i]=r;
                } else if (summary_attributes[i]&~((node->old_data)->attr)&(node->new_data)->attr) {
                    summary[i]=a;
                } else if (summary_attributes[i]&(((node->old_data)->attr&(node->new_data)->attr)&ignored_attrs)) {
                    summary[i]=g;
                } else if (summary_attributes[i]&((node->old_data)->attr&(node->new_data)->attr)) {
                    summary[i]=u;
                } else {
                    summary[i]=s;
                }
            }
        }
        summary[length]='\0';
        error(2,"%s: %s\n", summary, (node->checked&NODE_REMOVED?node->old_data:node->new_data)->filename);
        free(summary); summary=NULL;
    } else {
        if (node->checked&NODE_ADDED) {
            error(2,"added: %s\n",(node->new_data)->filename);
        } else if (node->checked&NODE_REMOVED) {
            error(2,"removed: %s\n",(node->old_data)->filename);
        } else if (node->checked&NODE_CHANGED) {
            error(2,"changed: %s\n",(node->new_data)->filename);
        }
    }
}

static void print_dbline_attributes(db_line* oline, db_line* nline, DB_ATTR_TYPE
        changed_attrs, DB_ATTR_TYPE ignored_attrs, DB_ATTR_TYPE report_attrs) {
    char **ovalue, **nvalue;
    int onumber, nnumber, olen, nlen, i, j, k, c;
    int length = sizeof(details_attributes)/sizeof(DB_ATTR_TYPE);
    int p = (width_details-(width_details%2?13:14))/2;
    DB_ATTR_TYPE attrs;
    error(2,"\n%s: %s\n",get_file_type_string((nline==NULL?oline:nline)->perm),(nline==NULL?oline:nline)->filename);
    attrs=(~(ignored_attrs))&(report_attrs|changed_attrs)&((oline==NULL?0:oline->attr)|(nline==NULL?0:nline->attr));
    for (j=0; j < length; ++j) {
        if (details_attributes[j]&attrs) {
            onumber=get_attribute_values(details_attributes[j], oline, &ovalue);
            nnumber=get_attribute_values(details_attributes[j], nline, &nvalue);
            i = 0;
            while (i<onumber || i<nnumber) {
                olen = i<onumber?strlen(ovalue[i]):0;
                nlen = i<nnumber?strlen(nvalue[i]):0;
                k = 0;
                while (olen-p*k >= 0 || nlen-p*k >= 0) {
                    c = k*(p-1);
                    if (oline==NULL || !(oline->attr&details_attributes[j]) ) {
                        error(2," %s%-9s%c %-*c  %.*s\n", width_details%2?"":" ", i+k?"":details_string[j], i+k?' ':':', p, ' ', p-1, nlen-p*k>0?&nvalue[i][c]:"");
                    } else if (nline==NULL || !(nline->attr&details_attributes[j])) {
                        error(2," %s%-9s%c %.*s\n", width_details%2?"":" ", i+k?"":details_string[j], i+k?' ':':', p-1, olen-p*k>0?&ovalue[i][c]:"");
                    } else {
                        error(2," %s%-9s%c %-*.*s| %.*s\n", width_details%2?"":" ", i+k?"":details_string[j], i+k?' ':':', p, p-1, olen-p*k>0?&ovalue[i][c]:"", p-1, nlen-p*k>0?&nvalue[i][c]:"");
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

static void print_attributes_added_node(db_line* line, DB_ATTR_TYPE ignored_attrs) {
    print_dbline_attributes(NULL, line, line->attr, ignored_attrs ,0);
}

static void print_attributes_removed_node(db_line* line, DB_ATTR_TYPE ignored_attrs) {
    print_dbline_attributes(line, NULL, line->attr, ignored_attrs ,0);
}

void print_report_header(int nfil,int nadd,int nrem,int nchg)
{
  char *time;
  if(conf->action&DO_COMPARE)
    error(0,_("AIDE " AIDEVERSION " found differences between database and filesystem!!\n"));

  if(conf->action&DO_DIFF)
    error(0,_("AIDE " AIDEVERSION " found differences between the two databases!!\n"));
  if(conf->config_version)
    error(2,_("Config version used: %s\n"),conf->config_version);

  time = malloc(time_string_len * sizeof (char));
  strftime(time, time_string_len, time_format, localtime(&(conf->start_time)));
  error(2,_("Start timestamp: %s\n"), time);
  free(time); time=NULL;
  error(0,_("\nSummary:\n  Total number of entries:\t%i\n  Added entries:\t\t%i\n"
	    "  Removed entries:\t\t%i\n  Changed entries:\t\t%i\n\n"),nfil,nadd,nrem,nchg);
  
}

void print_report_footer(struct tm* st)
{
  char *time = malloc(time_string_len * sizeof (char));
  strftime(time, time_string_len, time_format, st);
  error(2,_("\nEnd timestamp: %s\n"), time);
  free(time); time=NULL;
}

#ifdef WITH_AUDIT
  /* Something changed, send audit anomaly message */
void send_audit_report(long nadd, long nrem, long nchg)
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

long report_tree(seltree* node,int stage, long* status)
{
  list* r=NULL;
  DB_ATTR_TYPE ignorelist=0;
  DB_ATTR_TYPE forced_attrs=0;
  int top=0;

  ignorelist=get_ignorelist();
  forced_attrs=get_report_attributes();
  
  if(status[0]){
    status[0]=0;
    top=1;
  }


  /* First check the tree for changes and do a bit of painting, 
     then we print the terse report one changetype at a time
     and then we do the detailed listing for changed nodes
  */
  if(stage==0){
    /* If this node has been touched checked !=0 
       If checked == 0 there is nothing to report
    */
    if(node->checked!=0){
      status[1]++;
      if((node->checked&DB_OLD)&&(node->checked&DB_NEW)&&
	 (node->old_data==NULL)&&(node->new_data==NULL)){
	/* Node was added to twice and discovered to be not changed*/
      }else if(!(node->checked&DB_OLD)&&(node->checked&DB_NEW)){
	/* File is in new db but not old. (ADDED) */
	/* unless it was moved in */
	if (!((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) {
	  status[2]++;
	  node->checked|=NODE_ADDED;
	}
      }else if((node->checked&DB_OLD)&&!(node->checked&DB_NEW)){
	/* File is in old db but not new. (REMOVED) */
	/* unless it was moved out */
	if (!((node->checked&NODE_ALLOW_RM)||(node->checked&NODE_MOVED_OUT))) {
	  status[3]++;
	  node->checked|=NODE_REMOVED;
	}
      }else if((node->checked&DB_OLD)&&(node->checked&DB_NEW)&&
	       (node->old_data!=NULL)&&(node->new_data!=NULL)){
	/* File is in both db's and the data is still there. (CHANGED) */
	if(!(node->checked&(NODE_MOVED_IN|NODE_MOVED_OUT))){
	  status[4]++;
	  node->checked|=NODE_CHANGED;
	}else if (!((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) {
	  status[2]++;
	  node->checked|=NODE_ADDED;
	}else if (!((node->checked&NODE_ALLOW_RM)||(node->checked&NODE_MOVED_OUT))) {
	  status[3]++;
	  node->checked|=NODE_REMOVED;
	}
      }
    }
  }

  if((stage==1)&&status[2]){
    if(top){
        error(2,(char*)report_top_format,_("Added entries"));
    }
    if(node->checked&NODE_ADDED){ print_line(node, ignorelist); }
  }

  if((stage==2)&&status[3]){
    if(top){
        error(2,(char*)report_top_format,_("Removed entries"));
    }
    if(node->checked&NODE_REMOVED){ print_line(node, ignorelist); }
  }

  if((stage==3)&&status[4]){
    if(top){
            error(2,(char*)report_top_format,_("Changed entries"));
    }
    if(node->checked&NODE_CHANGED){ print_line(node, ignorelist); }
  }

  if((stage==4)&&(conf->verbose_level>=5)&&status[4]){
    if(top){
            error(2,(char*)report_top_format,_("Detailed information about changes"));
    }
    if (node->checked&NODE_CHANGED) {
        print_dbline_attributes(node->old_data, node->new_data, node->changed_attrs, ignorelist, (conf->verbose_level>=6?(((node->old_data)->attr)^((node->new_data)->attr)):0)|forced_attrs);
    } else if ((conf->verbose_level>=6)) {
        if (node->checked&NODE_ADDED) { print_attributes_added_node(node->new_data, ignorelist); }
        if (node->checked&NODE_REMOVED) { print_attributes_removed_node(node->old_data, ignorelist); }
    }
  }

  if((stage==5)&&(status[2]||status[3]||status[4])) {
    if(top){
        if (status[2]&&status[3]&&status[4]) { error(2,(char*)report_top_format,_("Added, removed and changed entries")); }
        else if (status[2]&&status[3]) { error(2,(char*)report_top_format,_("Added and removed entries")); }
        else if (status[2]&&status[4]) { error(2,(char*)report_top_format,_("Added and changed entries")); }
        else if (status[3]&&status[4]) { error(2,(char*)report_top_format,_("Removed and changed entries")); }
        else if (status[2]) { error(2,(char*)report_top_format,_("Added entries")); }
        else if (status[3]) { error(2,(char*)report_top_format,_("Removed entries")); }
        else if (status[4]) { error(2,(char*)report_top_format,_("Changed entries")); }
    }
    if(node->checked) { print_line(node, ignorelist); }
  }

  /* All stage dependent things done for this node. Let's check children */
  for(r=node->childs;r;r=r->next){
    report_tree((seltree*)r->data,stage,status);
  }

  if(top&&(stage==0)&&((status[2]+status[3]+status[4])>0)){
#ifdef WITH_AUDIT
    send_audit_report(status[2],status[3],status[4]);
#endif
    print_report_header(status[1],status[2],status[3],status[4]);
  }
  
  return (status[2]+status[3]+status[4]);
}

const char* aide_key_9=CONFHMACKEY_09;
const char* db_key_9=DBHMACKEY_09;

// vi: ts=8 sw=8
