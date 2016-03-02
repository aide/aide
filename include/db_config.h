/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2004-2006,2010-2013,2015,2016 Rami Lehti, Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
 * $Header$
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
 
#ifndef _DB_CONFIG_H_INCLUDED
#define _DB_CONFIG_H_INCLUDED
#include "aide.h"
#include "types.h"
#include <unistd.h>
#include <stdio.h>
#include <pcre.h>

#define E2O(n) (1<<n)

#include "list.h"

#ifdef WITH_SUN_ACL /* First try to implement support for sun acl. */
/*#define WITH_ACL    If we use sun acl then we have acl :) */
/* Warning! if acl in database is corrupted then
   this will break down. See and fix db.c */

#ifndef WITH_ACL
# error "No ACL support ... but Sun ACL support."
#endif

#include <sys/acl.h>
typedef struct acl_type{
  int entries;
  aclent_t* acl;
} acl_type;

#endif

#ifdef WITH_POSIX_ACL /* POSIX acl works for Sun ACL, AIUI but anyway... */
#include <sys/acl.h>
#ifndef WITH_ACL
# error "No ACL support ... but POSIX ACL support."
#endif
#endif

typedef struct acl_type {
 char *acl_a; /* ACCESS */
 char *acl_d; /* DEFAULT, directories only */
} acl_type;

#ifdef WITH_XATTR /* Do generic user Xattrs. */
#include <sys/xattr.h>
#include <attr/xattr.h>
#endif

typedef struct xattr_node 
{
 char *key;
 byte *val;
 size_t vsz;
} xattr_node;

typedef struct xattrs_type
{
  size_t num;
  size_t sz;
  struct xattr_node *ents;
} xattrs_type;

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#ifndef ENOATTR
# define ENOATTR ENODATA 
#endif
#endif

#ifdef WITH_E2FSATTRS
#include <e2p/e2p.h>
#endif

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#define RETOK 0
#define RETFAIL -1

#define DO_INIT     (1<<0)
#define DO_COMPARE  (1<<1)
#define DO_DIFF     (1<<2)

#include "url.h"

/*
typedef enum {
  url_file, url_stdout, url_stdin, url_stderr, url_fd, url_http,
  url_sql, url_syslog, url_database, url_multiplexer , url_unknown
} URL_TYPE;
*/
/*
  typedef struct url_t {*/
  /* Everything before the first ':' */
/*
  URL_TYPE type;
  char* value;
} url_t;
*/

typedef enum { 
   db_filename=0, 		/* "name",   */ 
   db_linkname, 		/* "lname",   */
   db_perm, 			/* "perm",    */
   db_uid, 			/* "uid",     */
   db_gid,			/* "gid",     */
   db_size, 			/* "size",    */
   db_atime, 			/* "atime",   */
   db_ctime, 			/* "ctime",   */
   db_mtime, 			/* "mtime",   */
   db_inode,			/* "inode",   */
   db_bcount, 			/* "bcount",  */
   db_lnkcount, 		/* "lcount",  */
   db_md5, 			/* "md5",     */
   db_sha1, 			/* "sha1",    */
   db_rmd160,			/* "rmd160",  */
   db_tiger, 			/* "tiger",   */
   db_crc32, 			/* "crc32",   */
   db_haval,			/* "haval",   */
   db_gost, 			/* "gost",    */
   db_crc32b, 			/* "crc32b",  */
   db_attr,                     /* attributes */
   db_acl,                      /* access control list */
   db_bsize,                    /* "bsize"    */
   db_rdev,                     /* "rdev"     */
   db_dev,                      /* "dev"      */
   db_checkmask,                /* "checkmask"*/
   db_allownewfile,		/* "allownewfile */
   db_allowrmfile,		/* "allowrmfile" */
   db_sha256, 			/* "sha256",  */
   db_sha512, 			/* "sha512",  */
   db_whirlpool,		/* "whirlpool",  */
   db_selinux, 			/* "selinux",  */
   db_xattrs, 			/* "xattrs",  */
   db_e2fsattrs,        /* "e2fsattrs"     */
   db_unknown } DB_FIELD; 	/* "unknown"  */

/* db_unknown must be last because it is used to determine size of
   DB_FILED */

/* FIXME: THIS IS A HACK, sometimes we use AIDE_OFF_TYPE instead
 * because that's what internal functions take. This bitmap needs to die. */
#define DB_ATTR_TYPE unsigned long long
#define DB_ATTR_UNDEF ((DB_ATTR_TYPE) -1)

/* WE need this for rx_rules since enums are not orrable (horrible) */
#define DB_FILENAME (1LLU<<0)	/* "name",   */ 
#define DB_LINKNAME (1LLU<<1)	/* "lname",   */
#define DB_PERM     (1LLU<<2)	/* "perm",    */
#define DB_UID      (1LLU<<3)	/* "uid",     */
#define DB_GID      (1LLU<<4)	/* "gid",     */
#define DB_SIZE     (1LLU<<5)	/* "size",    */
#define DB_ATIME    (1LLU<<6)	/* "atime",   */
#define DB_CTIME    (1LLU<<7)	/* "ctime",   */
#define DB_MTIME    (1LLU<<8)	/* "mtime",   */
#define DB_INODE    (1LLU<<9)	/* "inode",   */
#define DB_BCOUNT   (1LLU<<10)	/* "bcount",  */
#define DB_LNKCOUNT (1LLU<<11)	/* "lcount",  */
#define DB_MD5      (1LLU<<12)	/* "md5",     */
#define DB_SHA1     (1LLU<<13)	/* "sha1",    */
#define DB_RMD160   (1LLU<<14)	/* "rmd160",  */
#define DB_TIGER    (1LLU<<15)	/* "tiger",   */
/*
  We want to matk these newertheless we have a 
  hash-functon or not.
 */

#define DB_CRC32    (1LLU<<16)	/* "crc32",   */
#define DB_HAVAL    (1LLU<<17)	/* "haval",   */
#define DB_GOST     (1LLU<<18)	/* "gost",    */
#define DB_CRC32B   (1LLU<<19)	/* "crc32b",  */
// #define DB_ATTR    (1LLU<<20)     /* "attr"    */
#define DB_ACL      (1LLU<<21)  /* "acl"      */
#define DB_BSIZE    (1LLU<<22)  /* "bsize"    */
#define DB_RDEV     (1LLU<<23)  /* "rdev"     */
#define DB_DEV      (1LLU<<24)  /* "dev"      */

#define DB_CHECKMASK  (1LLU<<25) /* "checkmask"*/
#define DB_SIZEG      (1LLU<<26) /* "unknown"  */
#define DB_CHECKINODE (1LLU<<27) /* "checkinode"*/
#define DB_NEWFILE    (1LLU<<28) /* "allow new file" */
#define DB_RMFILE     (1LLU<<29) /* "allot rm file" */
#define DB_SHA256     (1LLU<<30) /* "sha256",  */
#define DB_SHA512     (1LLU<<31) /* "sha512",  */
#define DB_SELINUX    (1LLU<<32) /* "selinux", */
#define DB_XATTRS     (1LLU<<33) /* "xattrs",  */
#define DB_WHIRLPOOL  (1LLU<<34) /* "whirlpool",  */
#define DB_FTYPE      (1LLU<<35) /* "file type",  */
#define DB_E2FSATTRS  (1LLU<<36) /* "ext2 file system attributes"  */

#define DB_HASHES    (DB_MD5|DB_SHA1|DB_RMD160|DB_TIGER|DB_CRC32|DB_HAVAL| \
		      DB_GOST|DB_CRC32B|DB_SHA256|DB_SHA512|DB_WHIRLPOOL)

extern const char* db_names[db_unknown+1];
extern const int db_value[db_unknown+1];

/* db_namealias && db_aliasvalue are here to support earlier database 
 * names that are no longer used. */
#define db_alias_size 1
extern const char* db_namealias[db_alias_size];
extern const int db_aliasvalue[db_alias_size];

/* TIMEBUFSIZE should be exactly ceil(sizeof(time_t)*8*ln(2)/ln(10))
 * Now it is ceil(sizeof(time_t)*2.5)
 * And of course we add one for end of string char
 */

#define TIMEBUFSIZE (((sizeof(time_t)*5+1)>>1)+1)


/*
  New db_config
  Not used yet, maybe someday.
*/

/*  typedef struct _db_config { */
/*    url_t* url; */
/*    config* conf; */
/*    int inout; */
/*    int (*init)(url*,int,config*); */
/*    char** (*readline)(_db_config*); */
/*    int (*writeline)(_db_config*,db_line* line); */
/*    int (*close)(_db_config*); */
/*    int db_size; */
/*    DB_FIELD* db_order; */
/*    void* local; */  
/*  }_db_config ; */


#include "seltree.h"

typedef struct db_line {
  byte* md5;
  byte* sha1;
  byte* rmd160;
  byte* tiger;

  byte* sha256;
  byte* sha512;

  byte* crc32; /* MHASH only */
  byte* haval;
  byte* gost;
  byte* crc32b;
  byte* whirlpool;

  acl_type* acl;
  /* Something here.. */

  mode_t perm;
  mode_t perm_o; /* Permission for tree traverse */
  uid_t uid;
  gid_t gid;
  time_t atime;
  time_t ctime;
  time_t mtime;
  AIDE_INO_TYPE inode;
  nlink_t nlink;

  AIDE_OFF_TYPE size;
  AIDE_OFF_TYPE size_o; /* ... */
  AIDE_BLKCNT_TYPE bcount;
  char* filename;
  char* fullpath;
  char* linkname;

  char *cntx;

  xattrs_type* xattrs;

  unsigned long e2fsattrs;

  /* Attributes .... */
  DB_ATTR_TYPE attr;

} db_line;

typedef struct db_config {
  
  url_t* db_in_url;
  FILE* db_in;
  
  url_t* db_new_url;
  FILE* db_new;
  
  url_t* db_out_url;
  FILE* db_out;
  
  int config_check;

  struct md_container *mdc_in;
  struct md_container *mdc_out;

  struct db_line *line_db_in;
  struct db_line *line_db_out;

  DB_ATTR_TYPE db_attrs;

#ifdef WITH_ZLIB
  gzFile db_gzin;
  gzFile db_gznew;
  gzFile db_gzout;
  /* Is dbout gzipped or not */
  int gzip_dbout;
  
#endif

  int db_in_size;
  DB_FIELD* db_in_order;
  
  int db_new_size;
  DB_FIELD* db_new_order;

  int db_out_size;
  DB_FIELD* db_out_order;
  
  char* config_file;
  char* config_version;

 
  int do_dbnewmd;
  int do_dboldmd; 
#ifdef WITH_MHASH
  int do_configmd;
  MHASH confmd;
  hashid confhmactype;
  char* old_confmdstr;

  hashid dbhmactype;
  MHASH dbnewmd;
  MHASH dboldmd;
#endif
  char* old_dbnewmdstr;
  char* old_dboldmdstr;


  /* The following three a lists of rx_rule*s */
  list* selrxlst;
  list* equrxlst;
  list* negrxlst;

  int verbose_level;
  int database_add_metadata;
  int report_detailed_init;
  int report_base16;
  int report_quiet;
  int use_initial_errorsto;

#ifdef WITH_E2FSATTRS
  unsigned long report_ignore_e2fsattrs;
#endif

  url_t* initial_report_url;
  FILE* initial_report_fd;
  
  /* report_url is a list of url_t*s */
  list* report_url;

  /* report_fd is a list of FILE*s */
  list* report_fd;

  /* Report syslog */
  
  int report_syslog;
  int report_db;
  
  /* defsyms is a list of symba*s */
  list* defsyms;
  /* so is groupsyms */
  list* groupsyms;

  /* What are we supposed to do */
  int action;

  /* Should we catch errors from mmapping */
  int catch_mmap;

  time_t start_time;
  time_t end_time;

  int symlinks_found;
  DB_ATTR_TYPE attr;

#ifdef WITH_ACL  
  int no_acl_on_symlinks;
#endif
  int warn_dead_symlinks;

  int grouped;

  int summarize_changes;

  char* root_prefix;
  int root_prefix_length;

  char* limit;
  pcre* limit_crx;

  struct seltree* tree;

} db_config;

#ifdef WITH_PSQL
#include "libpq-fe.h"

typedef struct psql_data{
  PGconn* conn;
  char* table;
  PGresult *res;
  int des[db_unknown];
  int curread;
  int maxread;
} psql_data;

#endif

#endif
