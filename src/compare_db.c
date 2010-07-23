/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006 Rami Lehti, Pablo Virolainen, Richard van den Berg
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
#ifdef WITH_E2FSATTRS
    /* flag->character mappings defined in lib/e2p/pf.c (part of e2fsprogs-1.41.12 sources) */
    unsigned long flag_bits[] = { EXT2_SECRM_FL, EXT2_UNRM_FL, EXT2_SYNC_FL, EXT2_DIRSYNC_FL, EXT2_IMMUTABLE_FL,
        EXT2_APPEND_FL, EXT2_NODUMP_FL, EXT2_NOATIME_FL, EXT2_COMPR_FL, EXT2_COMPRBLK_FL,
        EXT2_DIRTY_FL, EXT2_NOCOMPR_FL, EXT2_ECOMPR_FL, EXT3_JOURNAL_DATA_FL, EXT2_INDEX_FL,
        EXT2_NOTAIL_FL, EXT2_TOPDIR_FL, EXT4_EXTENTS_FL, EXT4_HUGE_FILE_FL};
    char flag_char[] = "suSDiadAcBZXEjItTeh";
#endif
/* The initial length of summary string, the final length depends on
 * compile options */
int summary_len = 13;
/*************/

static DB_ATTR_TYPE get_ignorelist() {
  DB_ATTR_TYPE ignorelist;
  ignorelist=get_groupval("ignore_list");

  if (ignorelist==-1) {
    ignorelist=0;
  }

  return ignorelist;
}

static DB_ATTR_TYPE get_report_attributes() {
  DB_ATTR_TYPE forced_attrs;
  
  forced_attrs=get_groupval("report_attributes");
  if (forced_attrs==-1) {
    forced_attrs=0;
  }

  return forced_attrs;
}

list* find_line_match(db_line* line,list* l)
{
  list*r=NULL;

  /* Filename cannot be NULL. Or if it is NULL then we have done something 
     completly wrong. So we don't check if filename if null. db_line:s
     sould also be non null
  */
  
  for(r=l;r;r=r->next){
    if(strcmp(line->filename,((db_line*)r->data)->filename)==0){
      return r;
    }
  }
  if(l!=NULL){
    for(r=l->prev;r;r=r->prev){
      if(strcmp(line->filename,((db_line*)r->data)->filename)==0){
	return r;
      }
    }
  }

  return NULL;
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

int compare_md_entries(byte* e1,byte* e2,int len)
{

  error(255,"Debug, compare_md_entries %p %p\n",e1,e2);

  if(e1!=NULL && e2!=NULL){
    if(bytecmp(e1,e2,len)!=0){
      return RETFAIL;
    }else{
      return RETOK;
    }
  } else {
    /* At least the other is NULL */
    if(e1==NULL && e2==NULL){
      return RETOK;
    }else{
      return RETFAIL;
    }
  }
  return RETFAIL;
}

static int compare_str(const char *s1, const char *s2)
{
  if(s1==NULL){
    if(s2!=NULL){
      return RETFAIL;
    }
  }else if(s2==NULL){
    return RETFAIL;
  }else if (strcmp(s1,s2)!=0){
    return RETFAIL;
  }

  return RETOK;
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


/*
  We assume
  - no null parameters
  - same filename
  - something else?
  - ignorelist kertoo mitä ei saa vertailla
*/

DB_ATTR_TYPE compare_dbline(db_line* l1,db_line* l2,DB_ATTR_TYPE ignorelist)
{

#define easy_compare(a,b) \
  if (!(a&ignorelist)) {\
    if(l1->b!=l2->b){\
      ret|=a;\
    }\
  }

#define easy_md_compare(a,b,c) \
  if (!(a&ignorelist)) {  \
    if(compare_md_entries(l1->b,l2->b,\
			  c)==RETFAIL){ \
      ret|=a; \
    } \
  }
  
  DB_ATTR_TYPE ret=0;
  
  if (!(DB_FTYPE&ignorelist)) {
      if ((DB_FTYPE&l1->attr && DB_FTYPE&l2->attr) && get_file_type_char(l1->perm)!=get_file_type_char(l2->perm)) {
	    ret|=DB_FTYPE;
      }
  }

  if (!(DB_LINKNAME&ignorelist)) {
    if(compare_str(l1->linkname, l2->linkname)){
	ret|=DB_LINKNAME;
    }
  }

  if (!(DB_SIZEG&ignorelist)) {
      if ((DB_SIZEG&l1->attr && (DB_SIZEG&l2->attr))  && l1->size>l2->size){
          ret|=DB_SIZEG;
      }
  }

  if (!(DB_SIZE&ignorelist)) {
      if ((DB_SIZE&l1->attr && DB_SIZE&l2->attr) && l1->size!=l2->size){
          ret|=DB_SIZE;
      }
  }
  
  easy_compare(DB_BCOUNT,bcount);
  
  if (!(DB_PERM&ignorelist)) {
    if (DB_PERM&l1->attr && DB_PERM&l2->attr && l1->perm!=l2->perm) {
      ret|=DB_PERM;
    }
  } else {
    error(0,"Ignoring permissions\n");
  }
  
  easy_compare(DB_UID,uid);
  easy_compare(DB_GID,gid);
  easy_compare(DB_ATIME,atime);
  easy_compare(DB_MTIME,mtime);
  easy_compare(DB_CTIME,ctime);

  if (!(DB_INODE&ignorelist)) {
      if ((DB_INODE&l1->attr && DB_INODE&l2->attr) && (l1->inode!=l2->inode)){
          ret|=DB_INODE;
      }
  }
  easy_compare(DB_LNKCOUNT,nlink);

  easy_md_compare(DB_MD5,md5,HASH_MD5_LEN);
  
  error(255,"Debug, %s, %p %p %llx %llx\n",
        l1->filename,l1->md5,l2->md5,ret&DB_MD5,ignorelist);
  
  easy_md_compare(DB_SHA1,sha1,HASH_SHA1_LEN);
  easy_md_compare(DB_RMD160,rmd160,HASH_RMD160_LEN);
  easy_md_compare(DB_TIGER,tiger,HASH_TIGER_LEN);
  
  easy_md_compare(DB_SHA256,sha256,HASH_SHA256_LEN);
  easy_md_compare(DB_SHA512,sha512,HASH_SHA512_LEN);
  
#ifdef WITH_MHASH
  easy_md_compare(DB_CRC32,crc32,HASH_CRC32_LEN);
  easy_md_compare(DB_HAVAL,haval,HASH_HAVAL256_LEN);
  easy_md_compare(DB_GOST,gost,HASH_GOST_LEN);
  easy_md_compare(DB_CRC32B,crc32b,HASH_CRC32B_LEN);
  easy_md_compare(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN);
#endif

#ifdef WITH_ACL
  if (!(DB_ACL&ignorelist)) {
    if(compare_acl(l1->acl,l2->acl)) {
      ret|=DB_ACL;
    }
  }
#endif
  if (!(DB_XATTRS&ignorelist)) {
    if(compare_xattrs(l1->xattrs,l2->xattrs)) {
      ret|=DB_XATTRS;
    }
  }
#ifdef WITH_E2FSATTRS
  easy_compare(DB_E2FSATTRS,e2fsattrs);
#endif
  if (!(DB_SELINUX&ignorelist)) {
    if(compare_str(l1->cntx,l2->cntx)) {
      ret|=DB_SELINUX;
    }
  }
  return ret;
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
        error(2,"  [%.*zd] %s = %s\n", width, num,
              xattrs->ents[num - 1].key, val);
      else        
      {
        val = encode_base64(xattrs->ents[num - 1].val,
                            xattrs->ents[num - 1].vsz);
        error(2,"  [%.*zd] %s <=> %s\n", width, num,
              xattrs->ents[num - 1].key, val);
        free(val);
      }
      
    }
  }
}

void print_xattrs_changes(xattrs_type* old,xattrs_type* new) {
  
  if (compare_xattrs(old,new)==RETFAIL) {
    error(2,"XAttrs: old = ");
    print_single_xattrs(old);
    error(2,"        new = ");
    print_single_xattrs(new);
  }
  
}

#ifdef WITH_E2FSATTRS
char* e2fsattrs2char(unsigned long flags) {
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

void print_simple_line(db_line* data, char* s, char c) {
    char* tmp=NULL;
    int i=0;
    int length = summary_len-1;
    /* The length depends on compile options */
#ifdef WITH_ACL
    length++;
#endif
#ifdef WITH_XATTR
    length++;
#endif
#ifdef WITH_SELINUX
    length++;
#endif
#ifdef WITH_E2FSATTRS
    length++;
#endif
    if(conf->summarize_changes==1) {
        tmp=(char*)malloc(sizeof(char)*(length+1));
        for(i=0;i<length;i++){ tmp[i]=c; }
        tmp[length]='\0';
        error(2,"%c%s: %s\n",get_file_type_char(data->perm) , tmp, data->filename);
        free(tmp); tmp=NULL;
    } else {
        error(2,"%s: %s\n", s, data->filename);
    }
}

void print_added_line(db_line* data) {
    print_simple_line(data, "added", '+');
}

void print_removed_line(db_line* data) {
    print_simple_line(data, "removed", '-');
}

int str_has_changed(char*old,char*new)
{
    return (((old!=NULL && new!=NULL) &&
                strcmp(old,new)!=0 ) &&
            (old!=NULL || new!=NULL));
}

int md_has_changed(byte*old,byte*new,int len)
{
    return (((old!=NULL && new!=NULL) &&
                (bytecmp(old,new,len)!=0)) || 
            ((old!=NULL && new==NULL) || 
             (old==NULL && new!=NULL)));
}

char get_size_char(DB_ATTR_TYPE ignorelist, db_line* old, db_line* new) {
    if (DB_SIZE&old->attr || DB_SIZEG&old->attr) {
        if ((DB_SIZE&old->attr && DB_SIZE&new->attr) || (DB_SIZEG&old->attr && DB_SIZEG&new->attr)) {
            if (((DB_SIZE&old->attr && DB_SIZE&new->attr) && DB_SIZE&ignorelist) || 
                    ((DB_SIZEG&old->attr && DB_SIZEG&new->attr) && DB_SIZEG&ignorelist)) {
                return ':';
            } else if (old->size < new->size) {
                return '>';
            } else if (old->size > new->size) {
                return '<';
            } else {
                return '=';
            }
        } else {
            return '-';
        }
    } else if ((!(DB_SIZE&old->attr) && DB_SIZE&new->attr) || (!(DB_SIZEG&old->attr) && DB_SIZEG&new->attr) ) {
        return '+';
    } else {
        return ' ';
    }
}

void print_changed_line(db_line* old,db_line* new, DB_ATTR_TYPE ignorelist) {

#define easy_compare_char(a,b,c,d) \
    if (a&old->attr) { \
        if (a&new->attr) { \
            if (a&ignorelist) { \
                summary[d]=':'; \
            } else if (b) { \
                summary[d]=c; \
            } else { \
                summary[d]='.'; \
            } \
        } else { \
            summary[d]='-'; \
        } \
    } else if (a&new->attr) { \
        summary[d]='+'; \
    } else { \
        summary[d]=' '; \
    }

#define easy_char(a,b,c,d) \
    if (a&old->attr) { \
        if (a&new->attr) { \
            if (a&ignorelist) { \
                summary[d]=':'; \
            } else if (old->b!=new->b) { \
                summary[d]=c; \
            } else { \
                summary[d]='.'; \
            } \
        } else { \
            summary[d]='-'; \
        } \
    } else if (a&new->attr) { \
        summary[d]='+'; \
    } else { \
        summary[d]=' '; \
    }

    if(conf->summarize_changes==1) {
        int offset = 0;
        int length = summary_len;
        /* The length depends on compile options */
#ifdef WITH_ACL
        length++;
#endif
#ifdef WITH_XATTR
        length++;
#endif
#ifdef WITH_SELINUX
        length++;
#endif
#ifdef WITH_E2FSATTRS
        length++;
#endif
        char* summary = malloc ((length+1) * sizeof (char));
        summary[0]= ((!(DB_FTYPE&ignorelist)) &&
                (((DB_FTYPE&old->attr && DB_FTYPE&new->attr) &&
                  get_file_type_char(old->perm)!=get_file_type_char(new->perm)))) ? '!' : get_file_type_char(new->perm);
        easy_compare_char(DB_LINKNAME,str_has_changed(old->linkname,new->linkname),'l',1);
        summary[2]=get_size_char(ignorelist, old, new);
        easy_char(DB_BCOUNT,bcount,'b',3);
        easy_char(DB_PERM,perm,'p',4);
        easy_char(DB_UID,uid,'u',5);
        easy_char(DB_GID,gid,'g',6);
        easy_char(DB_ATIME,atime,'a',7);
        easy_char(DB_MTIME,mtime,'m',8);
        easy_char(DB_CTIME,ctime,'c',9);
        easy_char(DB_INODE,inode,'i',10);
        easy_char(DB_LNKCOUNT,nlink,'n',11);
        if (
                ((DB_MD5&old->attr && DB_MD5&new->attr) && md_has_changed(old->md5,new->md5,HASH_MD5_LEN) && !(DB_MD5&ignorelist)) ||
                ((DB_SHA1&old->attr &&  DB_SHA1&new->attr) && md_has_changed(old->sha1,new->sha1,HASH_SHA1_LEN) && !(DB_SHA1&ignorelist)) ||
                ((DB_RMD160&old->attr && DB_RMD160&new->attr) && md_has_changed(old->rmd160,new->rmd160,HASH_RMD160_LEN) && !(DB_RMD160&ignorelist)) ||
                ((DB_TIGER&old->attr && DB_TIGER&new->attr) && md_has_changed(old->tiger,new->tiger,HASH_TIGER_LEN) && !(DB_TIGER&ignorelist)) ||
                ((DB_SHA256&old->attr && DB_SHA256&new->attr) && md_has_changed(old->sha256,new->sha256,HASH_SHA256_LEN) && !(DB_SHA256&ignorelist)) ||
                ((DB_SHA512&old->attr && DB_SHA512&new->attr) && md_has_changed(old->sha512,new->sha512,HASH_SHA512_LEN) && !(DB_SHA512&ignorelist)) 
#ifdef WITH_MHASH
                || ((DB_CRC32&old->attr && DB_CRC32&new->attr) && md_has_changed(old->crc32,new->crc32,HASH_CRC32_LEN) && !(DB_CRC32&ignorelist)) ||
                ((DB_HAVAL&old->attr && DB_HAVAL&new->attr) && md_has_changed(old->haval,new->haval,HASH_HAVAL256_LEN) && !(DB_HAVAL&ignorelist)) ||
                ((DB_GOST&old->attr && DB_GOST&new->attr) && md_has_changed(old->gost,new->gost,HASH_GOST_LEN) && !(DB_GOST&ignorelist)) ||
                ((DB_CRC32B&old->attr && DB_CRC32B&new->attr) && md_has_changed(old->crc32b,new->crc32b,HASH_CRC32B_LEN) && !(DB_CRC32B&ignorelist)) ||
                ((DB_WHIRLPOOL&old->attr && DB_WHIRLPOOL&new->attr) && md_has_changed(old->whirlpool,new->whirlpool,HASH_WHIRLPOOL_LEN && !(DB_WHIRLPOOL&ignorelist)))
#endif        
           ) {
            summary[12]='C';
        } else if (
                ((DB_MD5&old->attr) && !(DB_MD5&new->attr)) ||
                ((DB_SHA1&old->attr) &&  !(DB_SHA1&new->attr)) ||
                ((DB_RMD160&old->attr) && !(DB_RMD160&new->attr)) ||
                ((DB_TIGER&old->attr) && !(DB_TIGER&new->attr)) ||
                ((DB_SHA256&old->attr) && !(DB_SHA256&new->attr)) ||
                ((DB_SHA512&old->attr) && !(DB_SHA512&new->attr))
#ifdef WITH_MHASH
                || ((DB_CRC32&old->attr) && !(DB_CRC32&new->attr)) ||
                ((DB_HAVAL&old->attr) && !(DB_HAVAL&new->attr)) ||
                ((DB_GOST&old->attr) && !(DB_GOST&new->attr)) ||
                ((DB_CRC32B&old->attr) && !(DB_CRC32B&new->attr)) ||
                ((DB_WHIRLPOOL&old->attr) && !(DB_WHIRLPOOL&new->attr))
#endif        
                ) {
            summary[12]='-';
        } else if (
                (!(DB_MD5&old->attr) && (DB_MD5&new->attr)) ||
                (!(DB_SHA1&old->attr) &&  (DB_SHA1&new->attr)) ||
                (!(DB_RMD160&old->attr) && (DB_RMD160&new->attr)) ||
                (!(DB_TIGER&old->attr) && (DB_TIGER&new->attr)) ||
                (!(DB_SHA256&old->attr) && (DB_SHA256&new->attr)) ||
                (!(DB_SHA512&old->attr) && (DB_SHA512&new->attr))
#ifdef WITH_MHASH
                || (!(DB_CRC32&old->attr) && (DB_CRC32&new->attr)) ||
                (!(DB_HAVAL&old->attr) && (DB_HAVAL&new->attr)) ||
                (!(DB_GOST&old->attr) && (DB_GOST&new->attr)) ||
                (!(DB_CRC32B&old->attr) && (DB_CRC32B&new->attr)) ||
                (!(DB_WHIRLPOOL&old->attr) && (DB_WHIRLPOOL&new->attr))
#endif        
                ) {
            summary[12]='+';
        } else if (
                ((DB_MD5&old->attr && DB_MD5&new->attr) && DB_MD5&ignorelist) ||
                ((DB_SHA1&old->attr &&  DB_SHA1&new->attr) && DB_SHA1&ignorelist) ||
                ((DB_RMD160&old->attr && DB_RMD160&new->attr) && DB_RMD160&ignorelist) ||
                ((DB_TIGER&old->attr && DB_TIGER&new->attr) && DB_TIGER&ignorelist) ||
                ((DB_SHA256&old->attr && DB_SHA256&new->attr) && DB_SHA256&ignorelist) ||
                ((DB_SHA512&old->attr && DB_SHA512&new->attr) && DB_SHA512&ignorelist)
#ifdef WITH_MHASH
                || ((DB_CRC32&old->attr && DB_CRC32&new->attr) && DB_CRC32&ignorelist) ||
                ((DB_HAVAL&old->attr && DB_HAVAL&new->attr) && DB_HAVAL&ignorelist) ||
                ((DB_GOST&old->attr && DB_GOST&new->attr) && DB_GOST&ignorelist) ||
                ((DB_CRC32B&old->attr && DB_CRC32B&new->attr) && DB_CRC32B&ignorelist) ||
                ((DB_WHIRLPOOL&old->attr && DB_WHIRLPOOL&new->attr) && DB_WHIRLPOOL&ignorelist)
#endif        
                ) {
            summary[12]=':';
        } else if (
                (DB_MD5&old->attr && DB_MD5&new->attr) ||
                (DB_SHA1&old->attr &&  DB_SHA1&new->attr) ||
                (DB_RMD160&old->attr && DB_RMD160&new->attr) ||
                (DB_TIGER&old->attr && DB_TIGER&new->attr) ||
                (DB_SHA256&old->attr && DB_SHA256&new->attr) ||
                (DB_SHA512&old->attr && DB_SHA512&new->attr)
#ifdef WITH_MHASH
                || (DB_CRC32&old->attr && DB_CRC32&new->attr) ||
                (DB_HAVAL&old->attr && DB_HAVAL&new->attr) ||
                (DB_GOST&old->attr && DB_GOST&new->attr) ||
                (DB_CRC32B&old->attr && DB_CRC32B&new->attr) ||
                (DB_WHIRLPOOL&old->attr && DB_WHIRLPOOL&new->attr)
#endif        
                ) {
            summary[12]='.';
        } else {
            summary[12]=' ';
        }

#ifdef WITH_ACL
        easy_compare_char(DB_ACL,compare_acl(old->acl,new->acl)==RETFAIL,'A',summary_len+offset++);
#endif
#ifdef WITH_XATTR
        easy_compare_char(DB_XATTRS,compare_xattrs(old->xattrs,new->xattrs)==RETFAIL,'X',summary_len+offset++);
#endif
#ifdef WITH_SELINUX
        easy_compare_char(DB_SELINUX,str_has_changed(old->cntx,new->cntx),'S',summary_len+offset++);
#endif
#ifdef WITH_E2FSATTRS
        easy_char(DB_E2FSATTRS,e2fsattrs,'E',summary_len+offset++);
#endif
        summary[summary_len+offset]='\0';
        error(2,"%s: %s\n",summary, new->filename);
        free(summary);
        summary=NULL;
    } else {
        error(2,"changed: %s\n",new->filename);
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
    print_xattrs_changes(old->xattrs,new->xattrs);
  }
  if (!(DB_SELINUX&ignorelist)) {
    print_str_changes(old->cntx,new->cntx, "SELinux", DB_SELINUX&forced_attrs);
  }
  
#ifdef WITH_E2FSATTRS
  if ( !(DB_E2FSATTRS&ignorelist) ) {
      if(old->e2fsattrs!=new->e2fsattrs || DB_E2FSATTRS&forced_attrs ) {
          tmp=e2fsattrs2char(old->e2fsattrs);
          tmp2=e2fsattrs2char(new->e2fsattrs);
          print_string_changes("E2FSAttrs", tmp, tmp2, old->e2fsattrs==new->e2fsattrs);
          free(tmp); free(tmp2);
          tmp=NULL; tmp2=NULL;
      }
  }
#endif

  return;
}

void init_rxlst(list* rxlst)
{
    list*    r         = NULL;
    rx_rule* rxrultmp  = NULL;
    regex_t* rxtmp     = NULL;


  for(r=rxlst;r;r=r->next){
    char* data=NULL;
    /* We have to add '^' to the first charaster of string... 
     *
     */
    
    data=(char*)malloc(strlen(((rx_rule*)r->data)->rx)+1+1);
    
    if (data==NULL){
      error(0,_("Not enough memory for regexpr compile... exiting..\n"));
      exit(EXIT_FAILURE);
    }
    
    strcpy(data+1,((rx_rule*)r->data)->rx);
    
    data[0]='^';
    
    rxrultmp=((rx_rule*)r->data);
    rxrultmp->conf_lineno=-1;
    rxtmp=(regex_t*)malloc(sizeof(regex_t));
    if( regcomp(rxtmp,data,REG_EXTENDED|REG_NOSUB)){
      error(0,_("Error in selective regexp: %s\n"),((rx_rule*)r->data)->rx);
      free(data);
    }else {
      rxrultmp->conf_lineno=((rx_rule*)r)->conf_lineno;
      free(rxrultmp->rx);
      rxrultmp->rx=data;
      rxrultmp->crx=rxtmp;
    }
    
  }

}

void eat_files_indir(list* flist,char* dirname,long* filcount)
{
  size_t len;

  *filcount=0;
  len=strlen(dirname);

  while (flist){
    if((strncmp(dirname,((db_line*)flist->data)->filename,len)==0)
       && ((((db_line*)flist->data)->filename)[len]=='/')){
      free_db_line((db_line*)flist->data);
      free(flist->data);
      flist=list_delete_item(flist);
      (*filcount)++;
    }
    flist=flist->next;
  }
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
  error(0,_("\nSummary:\n  Total number of files:\t%i\n  Added files:\t\t\t%i\n"
	    "  Removed files:\t\t%i\n  Changed files:\t\t%i\n\n"),nfil,nadd,nrem,nchg);
  
}

void print_report_footer(struct tm* st)
{
    error(2,_("\nEnd timestamp: %.4u-%.2u-%.2u %.2u:%.2u:%.2u\n"),
	  st->tm_year+1900, st->tm_mon+1, st->tm_mday,
	  st->tm_hour, st->tm_min, st->tm_sec);
}

void compare_db(list* new,db_config* dbconf)
{
  db_line* old=NULL;
  list* l=new;
  list* r=NULL;
  list* removed=NULL;
  list* changednew=NULL;
  list* changedold=NULL;
  list* added=NULL;
  long nrem=0;
  long nchg=0;
  long nadd=0;
  long nfil=0;
  long filesindir=0;
  DB_ATTR_TYPE tempignore=0;
  int initdbwarningprinted=0;

  DB_ATTR_TYPE ignorelist;
  DB_ATTR_TYPE forced_attrs;

  error(200,_("compare_db()\n"));


  /* With this we avoid unnecessary checking of removed files. */
  if(dbconf->action&DO_INIT){
    initdbwarningprinted=1;
  } else {
    /* We have to init the rxlsts since they are copied and then 
       initialized in gen_list.c */
    init_rxlst(dbconf->selrxlst);
    init_rxlst(dbconf->equrxlst);
    init_rxlst(dbconf->negrxlst);
  }
  
  /* We have a way to ignore some changes... */ 
  
  ignorelist=get_ignorelist();
  
  forced_attrs=get_report_attributes();

  if (forced_attrs==DB_ATTR_UNDEF) {
    forced_attrs=0;
  }

  for(old=db_readline(DB_OLD);old;old=db_readline(DB_OLD)){
    nfil++;
    r=find_line_match(old,l);
    if(r==NULL){
      /* The WARNING is only printed once */
      /* FIXME There should be a check for this in changed part also */
      /* This part should also be rethinked */
      if(!initdbwarningprinted &&
	 (check_list_for_match(dbconf->selrxlst,old->filename,&tempignore) ||
	  check_list_for_match(dbconf->equrxlst,old->filename,&tempignore)) &&
	 !check_list_for_match(dbconf->negrxlst,old->filename,&tempignore)){
	if(!(dbconf->action&DO_INIT)){
	  error(2,_("WARNING: Old db contains one or more entries that shouldn\'t be there, run --init or --update\n"));
	}
	initdbwarningprinted=1;
      }
      removed=list_append(removed,(void*)old);
      nrem++;
    }else {
      DB_ATTR_TYPE localignorelist=old->attr ^ ((db_line*)r->data)->attr;
      
      if ((localignorelist&(~(DB_NEWFILE|DB_RMFILE)))!=0) {
	error(2,"Entry %s in databases has different attributes: %llx %llx\n",
              old->filename,old->attr,((db_line*)r->data)->attr);
      }
      
      localignorelist|=ignorelist;
      
      if(compare_dbline(old,(db_line*)r->data,localignorelist)!=0){
	changednew=list_append(changednew,r->data);
	changedold=list_append(changedold,(void*)old);
	r->data=NULL;
	l=list_delete_item(r);
	nchg++;
      }else {
	/* This line was ok */
	/*
	  Cannot free, check why.
	  It's because db_disk needs it for going back
	  to it's parent.
	*/
	
	l=list_delete_item(r);
      }
    }
    
  }
  /* Now we have checked the old database and removed the lines *
   * that have matched. */
  if(l!=NULL){
    added=l->header->head;
  }else {
    added=NULL;
  }
  
  for(l=added;l;l=l->next){
    nadd++;
  }

  if(nadd!=0||nrem!=0||nchg!=0){
    print_report_header(nfil,nadd,nrem,nchg);

    if(nadd!=0){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Added files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=added;r;r=r->next){
       print_added_line((db_line*)r->data);
	if(dbconf->verbose_level<20){
	  if(S_ISDIR(((db_line*)r->data)->perm)){
	    eat_files_indir(r->next,((db_line*)r->data)->filename,&filesindir);
	    if(filesindir>0){
	      error(2,
		    _("added: THERE WERE ALSO %li "
		    "FILES ADDED UNDER THIS DIRECTORY\n")
		    ,filesindir);
	    }
	  }
	}
      }
    }
    

    if(nrem!=0){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Removed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=removed;r;r=r->next){
       print_removed_line((db_line*)r->data);
      }
    }

    if(nchg!=0){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Changed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=changedold,l=changednew;r;r=r->next,l=l->next){
	print_changed_line((db_line*)r->data,
			     (db_line*)l->data,ignorelist);
      }
    }

    if((dbconf->verbose_level>=5)&&(nchg!=0)){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Detailed information about changes:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=changedold,l=changednew;r;r=r->next,l=l->next){
	DB_ATTR_TYPE localignorelist=((db_line*)l->data)->attr^((db_line*)r->data)->attr;
	localignorelist|=ignorelist;
	print_dbline_changes((db_line*)r->data,
			     (db_line*)l->data,localignorelist,forced_attrs);
      }
    }
    dbconf->end_time=time(&(dbconf->end_time));
    print_report_footer(localtime(&(dbconf->end_time)));
  }
}

  /* Something changed, send audit anomaly message */
void send_audit_report(long nadd, long nrem, long nchg)
{
#ifdef WITH_AUDIT
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
#endif /* WITH_AUDIT */
}

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
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Added files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_ADDED){
      print_added_line(node->new_data);
    }
  }

  if((stage==2)&&status[3]){
    if(top){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Removed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_REMOVED){
      print_removed_line(node->old_data);
    }
  }

  if((stage==3)&&status[4]){
    if(top){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Changed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_CHANGED){
      print_changed_line(node->old_data,node->new_data,ignorelist);
    }
  }

  if((stage==4)&&(conf->verbose_level>=5)&&status[4]){
    if(top){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Detailed information about changes:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_CHANGED){
      DB_ATTR_TYPE localignorelist=(node->old_data->attr ^ node->new_data->attr)|ignorelist;
      print_dbline_changes(node->old_data,node->new_data,localignorelist,forced_attrs);
    }
  }

  /* All stage dependent things done for this node. Let's check children */
  for(r=node->childs;r;r=r->next){
    report_tree((seltree*)r->data,stage,status);
  }

  if(top&&(stage==0)&&((status[2]+status[3]+status[4])>0)){
    send_audit_report(status[2],status[3],status[4]);
    print_report_header(status[1],status[2],status[3],status[4]);
  }
  
  return (status[2]+status[3]+status[4]);
}

const char* aide_key_9=CONFHMACKEY_09;
const char* db_key_9=DBHMACKEY_09;

// vi: ts=8 sw=8
