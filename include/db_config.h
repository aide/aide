/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti, Pablo Virolainen
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
#include <unistd.h>
#include <stdio.h>

#define E2O(n) (1<<n)

#include "config.h"
#include "types.h"
#include "list.h"
#include "seltree.h"

#ifdef WITH_SUN_ACL /* First try to implement support for sun acl. */
/*#define WITH_ACL    If we use sun acl then we have acl :) */
/* Warning! if acl in database is corrupted then
   this will break down. See and fix db.c */

#include <sys/acl.h>
typedef struct acl_type{
  int entries;
  aclent_t* acl;
} acl_type;

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
   db_unknown } DB_FIELD; 	/* "unknown"  */

/* db_unknown must be last because it is used to determine size of
   DB_FILED */

/* WE need this for rx_rules since enums are not orrable (horrible) */
#define DB_FILENAME (1<<0)	/* "name",   */ 
#define DB_LINKNAME (1<<1)	/* "lname",   */
#define DB_PERM     (1<<2)	/* "perm",    */
#define DB_UID      (1<<3)	/* "uid",     */
#define DB_GID      (1<<4)	/* "gid",     */
#define DB_SIZE     (1<<5)	/* "size",    */
#define DB_ATIME    (1<<6)	/* "atime",   */
#define DB_CTIME    (1<<7)	/* "ctime",   */
#define DB_MTIME    (1<<8)	/* "mtime",   */
#define DB_INODE    (1<<9)	/* "inode",   */
#define DB_BCOUNT   (1<<10)	/* "bcount",  */
#define DB_LNKCOUNT (1<<11)	/* "lcount",  */
#define DB_MD5      (1<<12)	/* "md5",     */
#define DB_SHA1     (1<<13)	/* "sha1",    */
#define DB_RMD160   (1<<14)	/* "rmd160",  */
#define DB_TIGER    (1<<15)	/* "tiger",   */
/*
  We want to matk these newertheless we have a 
  hash-functon or not.
 */

#define DB_CRC32    (1<<16)	/* "crc32",   */
#define DB_HAVAL    (1<<17)	/* "haval",   */
#define DB_GOST     (1<<18)	/* "gost",    */
#define DB_CRC32B   (1<<19)	/* "crc32b",  */
#define DB_ACL      (1<<20)     /* "acl"      */
#define DB_BSIZE    (1<<21)     /* "bsize"    */
#define DB_RDEV     (1<<22)     /* "rdev"     */
#define DB_DEV      (1<<23)     /* "dev"      */

#define DB_CHECKMASK (1<<24)    /* "checkmask"*/
#define DB_SIZEG     (1<<25)	/* "unknown"  */
#define DB_CHECKINODE (1<<26) /* "checkinode"*/


#define DB_HASHES    (DB_MD5|DB_SHA1|DB_RMD160|DB_TIGER|DB_CRC32|DB_HAVAL| \
		      DB_GOST|DB_CRC32B)

const static char* db_names[] = {
   "name", 
   "lname", 
   "perm", 
   "uid", 
   "gid", 
   "size", 
   "atime", 
   "ctime",
   "mtime", 
   "inode", 
   "bcount", 
   "lcount", 
   "md5", 
   "sha1", 
   "rmd160", 
   "tiger",
   "crc32", 
   "haval",
   "gost",
   "crc32b",
   "attr",
   "acl",
   "bsize",
   "rdev",
   "dev",
   "checkmask",
   "unknown" } ; 

const static int db_value[] = { 
   db_filename, 	/* "name",   */ 
   db_linkname, 	/* "lname",   */
   db_perm, 		/* "perm",    */
   db_uid, 		/* "uid",     */
   db_gid,		/* "gid",     */
   db_size, 		/* "size",    */
   db_atime, 		/* "atime",   */
   db_ctime, 		/* "ctime",   */
   db_mtime, 		/* "mtime",   */
   db_inode,		/* "inode",   */
   db_bcount, 		/* "bcount",  */
   db_lnkcount, 	/* "lcount",  */
   db_md5, 		/* "md5",     */
   db_sha1, 		/* "sha1",    */
   db_rmd160,		/* "rmd160",  */
   db_tiger, 		/* "tiger",   */
   db_crc32, 		/* "crc32",   */
   db_haval,		/* "haval",   */
   db_gost, 		/* "gost",    */
   db_crc32b, 		/* "crc32b",  */
   db_attr,             /* attributes */
   db_acl,              /* "acl"      */
   db_bsize,            /* "bsize"    */
   db_rdev,             /* "rdev"     */
   db_dev,              /* "dev"      */
   db_checkmask,	/* "checkmask" */
   db_unknown };	/* "unknown"  */

/* db_namealias && db_aliasvalue are here to support earlier database 
 * names that are no longer used. */

const static char* db_namealias[] = {
  "count" } ;

const static int db_aliasvalue[] = {
  db_lnkcount } ;       /* "count",  */

const static int db_alias_size=1;

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



typedef struct db_config {
  
  url_t* db_in_url;
  FILE* db_in;
  
  url_t* db_new_url;
  FILE* db_new;
  
  url_t* db_out_url;
  FILE* db_out;
  
  int config_check;

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

#ifdef WITH_MHASH
  int do_configmd;
  MHASH confmd;
  hashid confhmactype;
  char* old_confmdstr;

  int do_dbnewmd;
  int do_dboldmd;
  hashid dbhmactype;
  MHASH dbnewmd;
  MHASH dboldmd;
  char* old_dbnewmdstr;
  char* old_dboldmdstr;
#endif


  /* The following three a lists of rx_rule*s */
  list* selrxlst;
  list* equrxlst;
  list* negrxlst;

  int verbose_level;
  int use_initial_errorsto;

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
  int attr;

#ifdef WITH_ACL  
  int no_acl_on_symlinks;
#endif
  int warn_dead_symlinks;
  
  struct seltree* tree;

} db_config;

typedef struct db_line {
  byte* md5;
  byte* sha1;
  byte* rmd160;
  byte* tiger;
  byte* crc32;
  byte* haval;
  byte* gost;
  byte* crc32b;

#ifdef WITH_ACL
  acl_type* acl;
  /* Something here.. */
#endif

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
  char* linkname;

  /* Attributes .... */
  int attr;
  
} db_line;

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
