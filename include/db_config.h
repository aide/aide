/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2004-2006,2010-2013,2015,2016,2019,2020 Rami Lehti,
 * Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
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
#include "attributes.h"
#include "types.h"
#include <unistd.h>
#include <stdio.h>
#include <pcre.h>

#define E2O(n) (1<<n)

#include "list.h"
#include "report.h"

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
#include <attr/attributes.h>
#ifndef ENOATTR
# define ENOATTR ENODATA
#endif
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

#ifdef WITH_CAPABILITIES
#include <sys/capability.h>
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
   db_allownewfile,		/* "allownewfile  */
   db_allowrmfile,		/* "allowrmfile"  */
   db_sha256, 			/* "sha256",      */
   db_sha512, 			/* "sha512",      */
   db_whirlpool,		/* "whirlpool",   */
   db_selinux, 			/* "selinux",     */
   db_xattrs, 			/* "xattrs",      */
   db_e2fsattrs,                /* "e2fsattrs"    */
   db_capabilities,             /* "capabilities" */
   db_unknown } DB_FIELD; 	/* "unknown"  */

/* db_unknown must be last because it is used to determine size of
   DB_FILED */

#define DB_HASHES    (DB_MD5|DB_SHA1|DB_RMD160|DB_TIGER|DB_CRC32|DB_HAVAL| \
		      DB_GOST|DB_CRC32B|DB_SHA256|DB_SHA512|DB_WHIRLPOOL)

extern const char* db_names[db_unknown+1];
extern const int db_value[db_unknown+1];

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
  long uid; /* uid_t */
  long gid; /* gid_t */
  time_t atime;
  time_t ctime;
  time_t mtime;
  long inode; /* ino_t */
  long nlink; /* nlink_t */

  long long size; /* off_t */
  long long bcount; /* blkcnt_t */
  char* filename;
  char* fullpath;
  char* linkname;

  char *cntx;

  xattrs_type* xattrs;

  unsigned long e2fsattrs;

  char* capabilities;

  /* Attributes .... */
  DB_ATTR_TYPE attr;

} db_line;

typedef struct db_config {
  
  url_t* db_in_url;
  void* db_in;
  
  url_t* db_new_url;
  void* db_new;
  
  url_t* db_out_url;
  void* db_out;
  
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

  int verbose_level;
  int database_add_metadata;
  int report_detailed_init;
  int report_base16;
  int report_quiet;

  DB_ATTR_TYPE report_ignore_added_attrs;
  DB_ATTR_TYPE report_ignore_removed_attrs;
  DB_ATTR_TYPE report_ignore_changed_attrs;
  DB_ATTR_TYPE report_force_attrs;

#ifdef WITH_E2FSATTRS
  unsigned long report_ignore_e2fsattrs;
#endif

  list* report_urls;
  REPORT_LEVEL report_level;

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

#endif
