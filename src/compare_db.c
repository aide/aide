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
/* contruction area for report lines */
const int old_col  = 12;   
const int new_col  = 40;   

const int part_len = 33; /* usable length of line[] for most purposes */
const int long_part_len = 129; /* length of line[] for link names and selinux contexts */
char      oline[129];
char      nline[129];
const char* entry_format=        " %-9s: %-33s, %s\n";
const char* entry_format_justnew=" %-9s: %-33c  %s\n";

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

const DB_ATTR_TYPE summary_char[] = { '!' ,'l', '>', 'b', 'p', 'u', 'g', 'a', 'm', 'c', 'i', 'n', 'C'
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

#ifdef WITH_POSIX_ACL
int compare_acl(acl_type* a1,acl_type* a2)
{
  if (a1==NULL && a2==NULL) {
    return RETOK;
  }
  if (a1==NULL || a2==NULL) {
    return RETFAIL;
  }

  if (!a1->acl_a != !a2->acl_a) {
    return RETFAIL;
  }
  if (!a1->acl_d != !a2->acl_d) {
    return RETFAIL;
  }

  if (a1->acl_a && strcmp(a1->acl_a, a2->acl_a))
    return RETFAIL;
  if (a1->acl_d && strcmp(a1->acl_d, a2->acl_d))
    return RETFAIL;

  return RETOK;
}
#endif

#ifdef WITH_SUN_ACL
static int compare_single_acl(aclent_t* a1,aclent_t* a2) {
  if (a1->a_type!=a2->a_type ||
      a1->a_id!=a2->a_id ||
      a1->a_perm!=a2->a_perm) {
    return RETFAIL;
  }
  return RETOK;
}

int compare_acl(acl_type* a1,acl_type* a2) {

  int i;
  if (a1==NULL && a2==NULL) {
    return RETOK;
  }
  if (a1==NULL || a2==NULL) {
    return RETFAIL;
  }

  if (a1->entries!=a2->entries) {
    return RETFAIL;
  }
  /* Sort em up. */
  aclsort(a1->entries,0,a1->acl);
  aclsort(a2->entries,0,a2->acl);
  for(i=0;i<a1->entries;i++){
    if (compare_single_acl(a1->acl+i,a2->acl+i)==RETFAIL) {
      return RETFAIL;
    }
  }
  return RETOK;
}
#endif

static int cmp_xattr_node(const void *c1, const void *c2)
{
  const xattr_node *x1 = c1;
  const xattr_node *x2 = c2;

  return (strcmp(x1->key, x2->key));
}

int compare_xattrs(xattrs_type* x1,xattrs_type* x2)
{
  size_t num = 0;

  if (x1 && (x1->num == 0)) x1 = NULL;
  if (x2 && (x2->num == 0)) x2 = NULL;

  if (x1==NULL && x2==NULL) {
    return RETOK;
  }
  if (x1==NULL || x2==NULL) {
    return RETFAIL;
  }

  if (x1->num != x2->num) {
    return RETFAIL;
  }

  qsort(x1->ents, x1->num, sizeof(xattr_node), cmp_xattr_node);
  qsort(x2->ents, x2->num, sizeof(xattr_node), cmp_xattr_node);
  
  while (num++ < x1->num)
  {
    const char *x1key = NULL;
    const byte *x1val = NULL;
    size_t x1vsz = 0;
    const char *x2key = NULL;
    const byte *x2val = NULL;
    size_t x2vsz = 0;
    
    x1key = x1->ents[num - 1].key;
    x1val = x1->ents[num - 1].val;
    x1vsz = x1->ents[num - 1].vsz;

    x2key = x2->ents[num - 1].key;
    x2val = x2->ents[num - 1].val;
    x2vsz = x2->ents[num - 1].vsz;

    if (strcmp(x1key, x2key) ||
        x1vsz != x2vsz ||
        memcmp(x1val, x2val, x1vsz))
      return RETFAIL;
  }
  
  return RETOK;
}

static int bytecmp(byte *b1, byte *b2, size_t len)
{
  return strncmp((char *)b1, (char *)b2, len);
}

char get_file_type_char(mode_t mode) {
    if (S_ISREG(mode)) return 'f';
    else if(S_ISDIR(mode)) return 'd';
#ifdef S_ISFIFO
    else if (S_ISFIFO(mode)) return 'F';
#endif
    else if (S_ISLNK(mode)) return 'L';
    else if (S_ISBLK(mode)) return 'B';
    else if (S_ISCHR(mode)) return 'D';
#ifdef S_ISSOCK
    else if (S_ISSOCK(mode)) return 's';
#endif
#ifdef S_ISDOOR
    else if (S_ISDOOR(mode)) return '|';
#endif
    else return '?';
}

void print_str_changes(char*old,char*new,const char *name, DB_ATTR_TYPE force)
{
  int mode = 0;
  if(old==NULL){
    if(new!=NULL){
       snprintf(oline,long_part_len,"<NULL>");
       snprintf(nline,long_part_len,"%s",new);
       mode = 1;
    }
  } else if(new==NULL){
       snprintf(oline,long_part_len,"%s",old);
       snprintf(nline,long_part_len,"<NULL>");
       mode = 1;
   } else if(strcmp(old,new)!=0){
        snprintf(oline,long_part_len,"%s",old);
        snprintf(nline,long_part_len,"%s",new);
        mode = 1;
  } else if (force) {
      snprintf(nline,long_part_len,"%s",new);
      mode = 2;
  }
   if(mode == 1) {
     error(2,(char*)entry_format,name,oline,nline);
   } else if (mode == 2) {
    error(2,(char*)entry_format_justnew,name,' ',nline);
   }
   return;
}

#ifdef WITH_ACL
void print_single_acl(acl_type* acl)
{
  if (acl==NULL) {
    error(2,"<NULL>\n");
  } else {
#ifdef WITH_POSIX_ACL
    if (!acl->acl_a)
      error(2,"A: <NONE>\n                  ");
    else
      error(2,"A:\n----\n%s----\n                  ",acl->acl_a);
    if (!acl->acl_d)
      error(2,"D: <NONE>\n");
    else
      error(2,"D:\n----\n%s----\n",acl->acl_d);
#endif
#ifdef WITH_SUN_ACL
    aclt=acltotext(acl->acl,acl->entries);
    if (aclt==NULL) {
      error(2,"ERROR\n");
    } else {
      error(2,"%s ,\n",aclt);
      free(aclt);
    }
#endif
  }
}

void print_acl_changes(acl_type* old,acl_type* new, DB_ATTR_TYPE force) {
  
  if (compare_acl(old,new)==RETFAIL) {
    error(2," ACL      : old = ");
    print_single_acl(old);
    error(2,"            new = ");
    print_single_acl(new);
  } else if (old!=NULL && new!=NULL && force) {
      error(2," ACL      :       ");
      print_single_acl(new);
  }
}
#endif

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

void print_single_xattrs(xattrs_type* xattrs)
{
  if (xattrs==NULL) {
    error(2,"num=0\n");
  } else {
    size_t num = 0;
    int width = 0;
    
    error(2,"num=%lu\n", (unsigned long)xattrs->num);

    width = log10(xattrs->num); /* make them the same width */
    
    while (num++ < xattrs->num)
    {
      char *val = NULL;
      size_t len = 0;
      
      val = (char *)xattrs->ents[num - 1].val;

      len = xstrnspn(val, xattrs->ents[num - 1].vsz, PRINTABLE_XATTR_VALS);
      
      if ((len ==  xattrs->ents[num - 1].vsz) ||
          ((len == (xattrs->ents[num - 1].vsz - 1)) && !val[len]))
        error(2,"             [%.*zd] %s = %s\n", width, num,
              xattrs->ents[num - 1].key, val);
      else        
      {
        val = encode_base64(xattrs->ents[num - 1].val,
                            xattrs->ents[num - 1].vsz);
        error(2,"             [%.*zd] %s <=> %s\n", width, num,
              xattrs->ents[num - 1].key, val);
        free(val);
      }
      
    }
  }
}

void print_xattrs_changes(xattrs_type* old,xattrs_type* new,
        DB_ATTR_TYPE force) {
  
  if (compare_xattrs(old,new)==RETFAIL) {
    error(2," XAttrs   : old = ");
    print_single_xattrs(old);
    error(2,"            new = ");
    print_single_xattrs(new);
  } else if (force) {
      error(2," XAttrs   : ");
      print_single_xattrs(new);
  }
  
}

#ifdef WITH_E2FSATTRS
char* e2fsattrs2string(unsigned long flags) {
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

void print_md_changes(byte*old,byte*new,int len,char* name, DB_ATTR_TYPE force)
{
    int mode = 0;
    if (old!=NULL && new!=NULL) {
        if(bytecmp(old,new,len)!=0) {
            snprintf(oline,part_len,"%s",encode_base64(old,len));
            snprintf(nline,part_len,"%s",encode_base64(new,len));
            mode = 1;
        } else if (force) {
            snprintf(nline,part_len,"%s",encode_base64(new,len));
            mode = 2;
        }
    } else if (old==NULL && new!=NULL) {
        snprintf(oline,part_len,"<NONE>");
        snprintf(nline,part_len,"%s",encode_base64(new,len));
        mode = 1;
    } else if (old!=NULL && new==NULL) {
        snprintf(oline,part_len,"%s",encode_base64(old,len));
        snprintf(nline,part_len,"<NONE>");
        mode = 1;
    }
    if (mode == 1) {
        error(2,(char*)entry_format,name,oline,nline);
    } else if (mode == 2) {
        error(2,(char*)entry_format_justnew,name,' ',nline);
    }
    return;
}

int is_time_null(struct tm *ot)
{
    /* 1970-01-01 01:00:00 is year null */
    return (ot->tm_year==70 && ot->tm_mon == 0 && ot->tm_mday == 1
            && ot->tm_hour == 1 &&  ot->tm_min == 0 && ot->tm_sec == 0);
}

void print_time_changes(const char* name, time_t old_time, time_t new_time,int justnew)
{
  struct tm otm;
  struct tm *ot = &otm;
  struct tm *tmp = localtime(&old_time);
  struct tm *nt;
  
  /* lib stores last tm call in static storage */
  ot->tm_year = tmp->tm_year; ot->tm_mon = tmp->tm_mon;
  ot->tm_mday = tmp->tm_mday;  ot->tm_hour = tmp->tm_hour;
  ot->tm_min = tmp->tm_min; ot->tm_sec = tmp->tm_sec;
  
  nt = localtime(&(new_time));
  if (!justnew) {
    if( is_time_null(ot) ) {
      snprintf(oline,part_len,"<NONE>");
    } else {
      snprintf(oline,part_len,
	       "%.4u-%.2u-%.2u %.2u:%.2u:%.2u",
	       ot->tm_year+1900, ot->tm_mon+1, ot->tm_mday,
	       ot->tm_hour, ot->tm_min, ot->tm_sec);
    }
  }
  if( is_time_null(nt) ) {
    snprintf(nline,part_len,"<NONE>");
  } else {
    snprintf(nline,part_len,
	     "%.4u-%.2u-%.2u %.2u:%.2u:%.2u",
	     nt->tm_year+1900, nt->tm_mon+1, nt->tm_mday,
	     nt->tm_hour, nt->tm_min, nt->tm_sec);
  }
  if (justnew) {
    error(2,(char*)entry_format_justnew,name,' ',nline);
  } else {
    error(2,(char*)entry_format,name,oline,nline); 
  }
}

void print_int_changes(const char* name, int old, int new, int justnew)
{
  if (!justnew) {
    snprintf(oline,part_len,"%i",old);
  }
  snprintf(nline,part_len,"%i",new);
  if (justnew) {
    error(2,(char*)entry_format_justnew,name,' ',nline);
  } else {
    error(2,(char*)entry_format,name,oline,nline);
  }
}
void print_long_changes(const char* name, AIDE_OFF_TYPE old, AIDE_OFF_TYPE new, int justnew)
{
#if SIZEOF_OFF64_T == SIZEOF_LONG_LONG
  if (!justnew) {
    snprintf(oline,part_len,"%llu",(long long unsigned)old);
  }
  snprintf(nline,part_len,"%llu",(long long unsigned)new);
#else
  if (!justnew) {
    snprintf(oline,part_len,"%lu",old);
  }
  snprintf(nline,part_len,"%lu",new);
#endif
  if (justnew) {
    error(2,(char*)entry_format_justnew,name,' ',nline);
  } else {
    error(2,(char*)entry_format,name,oline,nline);
  }
}

void print_string_changes(const char* name, const char* old, const char* new, int justnew)
{
  if (!justnew) {
    snprintf(oline,part_len,"%s",old);
  }
  snprintf(nline,part_len,"%s",new);
  if (justnew) {
    error(2,(char*)entry_format_justnew,name,' ',nline);
  } else {
    error(2,(char*)entry_format,name,oline,nline); 
  }
}

char* get_file_type_string(mode_t mode) {
    switch (get_file_type_char(mode)) {
        case 'f': return "File";
        case 'd': return "Directory";
        case 'F': return "FIFO";
        case 'L': return "Link";
        case 'B': return "Block device";
        case 'D': return "Character device";
        case 's': return "Socket";
        case '|': return "Door";
        default: return "Unknown file type";
    }
}


int str_has_changed(char*old,char*new)
{
    return (((old!=NULL && new!=NULL) &&
                strcmp(old,new)!=0 ) &&
            (old!=NULL || new!=NULL));
}

int md_has_changed(byte*old,byte*new,int len)
{
    error(255,"Debug, md_has_changed %p %p\n",old,new);
    return (((old!=NULL && new!=NULL) &&
                (bytecmp(old,new,len)!=0)) || 
            ((old!=NULL && new==NULL) || 
             (old==NULL && new!=NULL)));
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

void print_dbline_changes(db_line* old,db_line* new,
                          DB_ATTR_TYPE ignorelist,DB_ATTR_TYPE forced_attrs)
{
  char* tmp=NULL;
  char* tmp2=NULL;
  
  /*
    Force just entries, that exists.
  */
  forced_attrs&=new->attr;
  
  error(2,"\n%s: %s\n",get_file_type_string(new->perm),new->filename);

  if ((!(DB_FTYPE&ignorelist)) && (((DB_FTYPE&old->attr && DB_FTYPE&new->attr) && get_file_type_char(old->perm)!=get_file_type_char(new->perm)) || DB_FTYPE&forced_attrs)) {
          print_string_changes("File type", get_file_type_string(old->perm),get_file_type_string(new->perm), get_file_type_char(old->perm)==get_file_type_char(new->perm));
  }

  if(!(DB_LINKNAME&ignorelist)){
    print_str_changes(old->linkname,new->linkname, "Lname", DB_LINKNAME&forced_attrs);
  }

  if (((!(DB_SIZEG&ignorelist)) && (((DB_SIZEG&old->attr && DB_SIZEG&new->attr)  && old->size>new->size) || DB_SIZEG&forced_attrs))
     || ((!(DB_SIZE&ignorelist)) && (((DB_SIZE&old->attr && DB_SIZE&new->attr) && old->size!=new->size) || DB_SIZE&forced_attrs)) ) {
          print_long_changes("Size", old->size,new->size,old->size==new->size);
  }

  if (!(DB_BCOUNT&ignorelist)) {
    if(old->bcount!=new->bcount ||(DB_BCOUNT&forced_attrs) ){
      print_int_changes("Bcount", old->bcount,new->bcount,old->bcount==new->bcount);
    }
  }
  if (!(DB_PERM&ignorelist)) {
    if((DB_PERM&old->attr && DB_PERM&new->attr && old->perm!=new->perm) || DB_PERM&forced_attrs){
      tmp=perm_to_char(old->perm);
      tmp2=perm_to_char(new->perm);
      print_string_changes("Perm", tmp,tmp2,old->perm==new->perm);
      free(tmp);
      free(tmp2);
      tmp=NULL;
      tmp2=NULL;
    }
  }
  
  if (!(DB_UID&ignorelist)) {
    if(old->uid!=new->uid||DB_UID&forced_attrs){
      print_int_changes("Uid", old->uid,new->uid,old->uid==new->uid);
    }
  }
  
  if (!(DB_GID&ignorelist)) {
    if(old->gid!=new->gid||DB_GID&forced_attrs){
      print_int_changes("Gid", old->gid,new->gid,old->gid==new->gid);
    }
  }
  
  if (!(DB_ATIME&ignorelist)) {
    if(old->atime!=new->atime||DB_ATIME&forced_attrs){
      print_time_changes("Atime", old->atime, new->atime,old->atime==new->atime);
    }
  }
  
  if (!(DB_MTIME&ignorelist)) {
    if(old->mtime!=new->mtime||DB_MTIME&forced_attrs){
      print_time_changes("Mtime", old->mtime, new->mtime,old->mtime==new->mtime);
    }
  }
  
  if (!(DB_CTIME&ignorelist)) {
    if(old->ctime!=new->ctime||DB_CTIME&forced_attrs){
      print_time_changes("Ctime", old->ctime, new->ctime,old->ctime==new->ctime);
    }
  }

  if (!(DB_INODE&ignorelist)) {
    if(((DB_INODE&old->attr && (DB_INODE&new->attr)) && old->inode!=new->inode) ||DB_INODE&forced_attrs){
      print_int_changes("Inode", old->inode,new->inode,old->inode==new->inode);
    }
  }
  if (!(DB_LNKCOUNT&ignorelist)) {
    if(old->nlink!=new->nlink||DB_LNKCOUNT&forced_attrs){
      print_int_changes("Linkcount", old->nlink,new->nlink,old->nlink==new->nlink);
    }
  }

  if (!(DB_MD5&ignorelist)) {  
    print_md_changes(old->md5,new->md5,
		     HASH_MD5_LEN,
		     "MD5", DB_MD5&forced_attrs);
  }
  
  if (!(DB_SHA1&ignorelist)) {
      print_md_changes(old->sha1,new->sha1,
		       HASH_SHA1_LEN,
		       "SHA1", DB_SHA1&forced_attrs);
  }

  if (!(DB_RMD160&ignorelist)) {
    print_md_changes(old->rmd160,new->rmd160,
		     HASH_RMD160_LEN,
		     "RMD160", DB_RMD160&forced_attrs);
  }
  
  if (!(DB_TIGER&ignorelist)) {
    print_md_changes(old->tiger,new->tiger,
		     HASH_TIGER_LEN,
		     "TIGER", DB_TIGER&forced_attrs);
  }
  
  if (!(DB_SHA256&ignorelist)) {
      print_md_changes(old->sha256,new->sha256,
		       HASH_SHA256_LEN,
		       "SHA256", DB_SHA256&forced_attrs);
  }

  if (!(DB_SHA512&ignorelist)) {
      print_md_changes(old->sha512,new->sha512,
		       HASH_SHA512_LEN,
		       "SHA512", DB_SHA512&forced_attrs);
  }

#ifdef WITH_MHASH
  if (!(DB_CRC32&ignorelist)) {
    print_md_changes(old->crc32,new->crc32,
		     HASH_CRC32_LEN,
		     "CRC32", DB_CRC32&forced_attrs);
  }
  
  if (!(DB_HAVAL&ignorelist)) {
    print_md_changes(old->haval,new->haval,
		     HASH_HAVAL256_LEN,
		     "HAVAL", DB_HAVAL&forced_attrs);
  }
  
  if (!(DB_GOST&ignorelist)) {
    print_md_changes(old->gost,new->gost,
		     HASH_GOST_LEN,
		     "GOST", DB_GOST&forced_attrs);
  }
  
  if (!(DB_CRC32B&ignorelist)) {
    print_md_changes(old->crc32b,new->crc32b,
		     HASH_CRC32B_LEN,
		     "CRC32B", DB_CRC32B&forced_attrs);
  }

  if (!(DB_WHIRLPOOL&ignorelist)) {
      print_md_changes(old->whirlpool,new->whirlpool,
		       HASH_WHIRLPOOL_LEN,
		       "WHIRLPOOL", DB_WHIRLPOOL&forced_attrs);
  }
#endif                   

#ifdef WITH_ACL
  if (!(DB_ACL&ignorelist)) {
    print_acl_changes(old->acl,new->acl, DB_ACL&forced_attrs);
  }
#endif
  if (!(DB_XATTRS&ignorelist)) {
    print_xattrs_changes(old->xattrs,new->xattrs, DB_XATTRS&forced_attrs);
  }
  if (!(DB_SELINUX&ignorelist)) {
    print_str_changes(old->cntx,new->cntx, "SELinux", DB_SELINUX&forced_attrs);
  }
  
#ifdef WITH_E2FSATTRS
  if ( !(DB_E2FSATTRS&ignorelist) ) {
      if(old->e2fsattrs!=new->e2fsattrs || DB_E2FSATTRS&forced_attrs ) {
          tmp=e2fsattrs2string(old->e2fsattrs);
          tmp2=e2fsattrs2string(new->e2fsattrs);
          print_string_changes("E2FSAttrs", tmp, tmp2, old->e2fsattrs==new->e2fsattrs);
          free(tmp); free(tmp2);
          tmp=NULL; tmp2=NULL;
      }
  }
#endif

  return;
}

void print_report_header(int nfil,int nadd,int nrem,int nchg)
{
  struct tm* st=localtime(&(conf->start_time));
  if(conf->action&DO_COMPARE)
    error(0,_("AIDE " AIDEVERSION " found differences between database and filesystem!!\n"));

  if(conf->action&DO_DIFF)
    error(0,_("AIDE " AIDEVERSION " found differences between the two databases!!\n"));
  if(conf->config_version)
    error(2,_("Config version used: %s\n"),conf->config_version);

  error(2,_("Start timestamp: %.4u-%.2u-%.2u %.2u:%.2u:%.2u\n"),
	st->tm_year+1900, st->tm_mon+1, st->tm_mday,
	st->tm_hour, st->tm_min, st->tm_sec);
  error(0,_("\nSummary:\n  Total number of entries:\t%i\n  Added entries:\t\t%i\n"
	    "  Removed entries:\t\t%i\n  Changed entries:\t\t%i\n\n"),nfil,nadd,nrem,nchg);
  
}

void print_report_footer(struct tm* st)
{
    error(2,_("\nEnd timestamp: %.4u-%.2u-%.2u %.2u:%.2u:%.2u\n"),
	  st->tm_year+1900, st->tm_mon+1, st->tm_mday,
	  st->tm_hour, st->tm_min, st->tm_sec);
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
    if(node->checked&NODE_CHANGED){
      DB_ATTR_TYPE localignorelist=(node->old_data->attr ^ node->new_data->attr)|ignorelist;
      print_dbline_changes(node->old_data,node->new_data,localignorelist,forced_attrs);
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
