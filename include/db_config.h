/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2010-2013, 2015-2016, 2019-2022
 *               Rami Lehti, Pablo Virolainen, Richard van den Berg,
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
 
#ifndef _DB_CONFIG_H_INCLUDED
#define _DB_CONFIG_H_INCLUDED

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include "config.h"
#ifdef WITH_ZLIB
#include <zlib.h>
#endif
#include "attributes.h"
#include "hashsum.h"
#include "db_line.h"
#include "list.h"
#include "report.h"
#include "rx_rule.h"
#include "util.h"
#include "url.h"


#define E2O(n) (1<<n)

#define RETOK 0
#define RETFAIL -1

#define DO_INIT     (1<<0)
#define DO_COMPARE  (1<<1)
#define DO_DIFF     (1<<2)
#define DO_DRY_RUN  (1<<3)

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

typedef struct database {
    url_t* url;

    char *filename;
    int linenumber;
    char *linebuf;

    void *fp;
#ifdef WITH_ZLIB
    gzFile gzp;
#endif

    long lineno;
    ATTRIBUTE* fields;
    int num_fields;
    void *buffer_state;
    struct md_container *mdc;
    struct db_line *db_line;

} database;

typedef struct db_config {
  char *hostname;

  database database_in;
  database database_out;
  database database_new;

  DB_ATTR_TYPE db_attrs;

#ifdef WITH_ZLIB
  /* Is dbout gzipped or not */
  int gzip_dbout;
  
#endif

  DB_ATTR_TYPE db_out_attrs;

  char *check_path;
  RESTRICTION_TYPE check_file_type;
  
  char* config_file;
  char* config_version;
  bool config_check_warn_unrestricted_rules;

  int database_add_metadata;
  int report_detailed_init;
  int report_base16;
  int report_quiet;
  bool report_append;

  DB_ATTR_TYPE report_ignore_added_attrs;
  DB_ATTR_TYPE report_ignore_removed_attrs;
  DB_ATTR_TYPE report_ignore_changed_attrs;
  DB_ATTR_TYPE report_force_attrs;

#ifdef WITH_E2FSATTRS
  unsigned long report_ignore_e2fsattrs;
#endif

  list* report_urls;
  REPORT_LEVEL report_level;
  REPORT_FORMAT report_format;

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

  int report_grouped;

  int report_summarize_changes;

  char* root_prefix;
  int root_prefix_length;

  char* limit;
  pcre2_code* limit_crx;
  pcre2_match_data* limit_md;

  struct seltree* tree;

} db_config;

#endif
