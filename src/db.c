/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2011, 2013, 2019-2021 Rami Lehti,
 *               Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
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
 
#include "aide.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "db.h"
#include "db_lex.h"
#include "db_file.h"
#include "db_disk.h"
#include "md.h"

#ifdef WITH_CURL
#include "fopen.h"
#endif

#include "db_config.h"
#include "log.h"
#include "be.h"

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#include "base64.h"
#include "util.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

db_line* db_char2line(char**, database*);

static long readoct(char* s, database* db, char* field_name){
  long i;
  char* e;
  i=strtol(s,&e,8);
  if (e[0]!='\0') {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, could not read '%s' from database: strtol (base: 8) failed for '%s', field_name, s)
  }
  return i;
}

static long readlong(char* s, database* db, char* field_name){
  long i;
  char* e;
  i=strtol(s,&e,10);
  if (e[0]!='\0') {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, could not read '%s' from database: strtol failed for '%s', field_name, s)
  }
  return i;
}

static long long readlonglong(char* s, database* db, char* field_name){
  long long int i;
  char* e;
  i=strtoll(s,&e,10);
  if (e[0]!='\0') {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, could not read '%s' from database: strtoll failed for '%s', field_name, s)
  }
  return i;
}

static struct md_container *init_db_attrs(url_t *u) {
    struct md_container *mdc = NULL;
    if (conf->db_attrs) {
        switch (u->type) {
            case url_stdin:
            case url_stdout:
            case url_stderr:
            case url_fd:
            case url_file:
            case url_http:
            case url_https:
            case url_ftp: {
                mdc = checked_malloc(sizeof(struct md_container)); /* freed in close_db_attrs */
                mdc->todo_attr = conf->db_attrs;

                int length = snprintf(NULL, 0, "%s:%s", get_url_type_string(u->type), u->value) + 1;
                char *str = checked_malloc(length * sizeof(char));
                snprintf(str, length, "%s:%s", get_url_type_string(u->type), u->value);
                init_md(mdc, str);
                free(str);

                break;
            }
            /* unsupported database types */
            case url_syslog: {
                /* do nothing */
                break;
            }
        }
    }
    return mdc;
}

static db_line *close_db_attrs (database *db) {
    db_line *line = NULL;
    if (db->mdc != NULL) {
        close_md(db->mdc);
        line = checked_malloc(sizeof(struct db_line));
        line->filename = (db->url)->value;
        line->perm = 0;
        line->attr = conf->db_attrs;
        md2line(db->mdc, line);
        free(db->mdc);
    }
    return line;
}

int db_init(database* db, bool readonly, bool gzip) {
  void* fp = NULL;
  
  log_msg(LOG_LEVEL_TRACE,"db_init(): arguments: db=%p, gzip=%s", db, btoa(gzip));
  
    db->mdc = init_db_attrs(db->url);
    fp=be_init(readonly, db->url, gzip, false, db->linenumber, db->filename, db->linebuf);
    if(fp==NULL) {
      return RETFAIL;
    } else {
#ifdef WITH_ZLIB
        if (gzip) {
            db->gzp = fp;
        } else {
#endif
            db->fp = fp;
#ifdef WITH_ZLIB
        }
#endif
    return RETOK;
    }
}

db_line* db_readline(database* db){
  db_line* s=NULL;

  if (db->fp != NULL) {
      char** ss=db_readline_file(db);
      if (ss!=NULL){
          s=db_char2line(ss,db);

          for(int i=0;i<db->num_fields;i++){
              if(db->fields[i]!=attr_unknown &&
                      ss[db->fields[i]]!=NULL){
                  free(ss[db->fields[i]]);
                  ss[db->fields[i]]=NULL;
              }
          }
          free(ss);
      }
  }
  
  return s;
  
}

byte* base64tobyte(char* src,int len,size_t *ret_len)
{
  if(strcmp(src,"0")!=0){
    return decode_base64(src,len,ret_len);
  }
  return NULL;
}

static char *db_readchar(char *s)
{
  if (s == NULL)
    return (NULL);
  
  if (s[0] == '0')
  {
    if (s[1] == '\0')
      return (NULL);
    
    if (s[1] == '-')
      return (checked_strdup(""));

    if (s[1] == '0')
    {
      memmove(s, s+1, strlen(s+1)+1);
      // Hope this removes core
      // dumping in some environments. Has something to do with
      // memory (de)allocation.
    }
  }

  decode_string(s);

  return checked_strdup(s);
}


#define CHAR2HASH(hash) \
case attr_ ##hash : { \
    line->hashsums[hash_ ##hash]=base64tobyte(ss[db->fields[i]], \
        strlen(ss[db->fields[i]]), NULL); \
  break; \
}

db_line* db_char2line(char** ss, database* db){

  db_line* line=(db_line*)checked_malloc(sizeof(db_line)*1);

  line->perm=0;
  line->uid=0;
  line->gid=0;
  line->atime=0;
  line->ctime=0;
  line->mtime=0;
  line->inode=0;
  line->nlink=0;
  line->bcount=0;
  line->size=0;
  line->filename=NULL;
  line->fullpath=NULL;
  line->linkname=NULL;
  line->acl=NULL;
  line->xattrs=NULL;
  line->e2fsattrs=0;
  line->cntx=NULL;
  line->capabilities=NULL;

  for (int i = 0 ; i < num_hashes ; ++i) {
      line->hashsums[i]=NULL;
  }

  
  line->attr=conf->attr; /* attributes from @@dbspec */

  for(int i=0;i<db->num_fields;i++){

    log_msg(LOG_LEVEL_TRACE, "db_char2line(): %d[%d]: '%s' (%p)", db->lineno, i, ss[i], ss[i]);

    switch (db->fields[i]) {
    case attr_filename : {
      if(ss[db->fields[i]]!=NULL){
	decode_string(ss[db->fields[i]]);
	line->fullpath=checked_strdup(ss[db->fields[i]]);
	line->filename=line->fullpath;
      } else {
        log_msg(LOG_LEVEL_ERROR, "db_char2line(): error while reading database");
	exit(EXIT_FAILURE);
      }
      break;
    }
    case attr_linkname : {
      line->linkname = db_readchar(ss[db->fields[i]]);
      break;
    }
    case attr_mtime : {
      line->mtime=base64totime_t(ss[db->fields[i]], db, "mtime");
      break;
    }
    case attr_bcount : {
      line->bcount=readlonglong(ss[db->fields[i]], db, "bcount");
      break;
    }
    case attr_atime : {
      line->atime=base64totime_t(ss[db->fields[i]], db, "atime");
      break;
    }
    case attr_ctime : {
      line->ctime=base64totime_t(ss[db->fields[i]], db, "ctime");
      break;
    }
    case attr_inode : {
      line->inode=readlong(ss[db->fields[i]], db, "inode");
      break;
    }

    case attr_uid : {
      line->uid=readlong(ss[db->fields[i]], db, "uid");
      break;
    }
    case attr_gid : {
      line->gid=readlong(ss[db->fields[i]], db, "gid");
      break;
    }
    case attr_size : {
      line->size=readlonglong(ss[db->fields[i]], db, "size");
      break;
    }
    CHAR2HASH(md5)
    CHAR2HASH(sha256)
    CHAR2HASH(sha512)
    CHAR2HASH(sha1)
    CHAR2HASH(rmd160)
    CHAR2HASH(tiger)
    CHAR2HASH(crc32)
    CHAR2HASH(crc32b)
    CHAR2HASH(haval)
    CHAR2HASH(whirlpool)
    CHAR2HASH(gostr3411_94)
    CHAR2HASH(stribog256)
    CHAR2HASH(stribog512)
    case attr_acl : {
#ifdef WITH_POSIX_ACL
      char *tval = NULL;
      
      tval = strtok(ss[db->fields[i]], ",");

      line->acl = NULL;

      if (tval[0] == '0')
        line->acl = NULL;
      else if (!strcmp(tval, "POSIX"))
      {
        line->acl = checked_malloc(sizeof(acl_type));
        line->acl->acl_a = NULL;
        line->acl->acl_d = NULL;
        
        tval = strtok(NULL, ",");
        line->acl->acl_a = (char *)base64tobyte(tval, strlen(tval), NULL);
        tval = strtok(NULL, ",");
        line->acl->acl_d = (char *)base64tobyte(tval, strlen(tval), NULL);
      }
      /* else, it's broken... */
#endif
      break;
    }
      case attr_xattrs : {
        size_t num = 0;
        char *tval = NULL;
        
        tval = strtok(ss[db->fields[i]], ",");
        num = readlong(tval,  db, "xattrs");
        if (num)
        {
          line->xattrs = checked_malloc(sizeof(xattrs_type));
          line->xattrs->ents = checked_calloc(sizeof(xattr_node), num);
          line->xattrs->sz  = num;
          line->xattrs->num = num;
          num = 0;
          while (num < line->xattrs->num)
          {
            byte  *val = NULL;
            size_t vsz = 0;
            
            tval = strtok(NULL, ",");
            line->xattrs->ents[num].key = db_readchar(checked_strdup(tval));
            tval = strtok(NULL, ",");
            val = base64tobyte(tval, strlen(tval), &vsz);
            line->xattrs->ents[num].val = val;
            line->xattrs->ents[num].vsz = vsz;

            ++num;
          }
        }
        break;
      }

      case attr_selinux : {
        byte  *val = NULL;
        
        val = base64tobyte(ss[db->fields[i]], strlen(ss[db->fields[i]]),NULL);
        line->cntx = (char *)val;
        break;
      }
      
    case attr_perm : {
      line->perm=readoct(ss[db->fields[i]], db, "permissions");
      break;
    }
    
    case attr_linkcount : {
      line->nlink=readlong(ss[db->fields[i]], db, "nlink");
      break;
    }

    case attr_attr : {
      line->attr=readlonglong(ss[db->fields[i]], db, "attr");
      break;
    }
    
    case attr_e2fsattrs : {
      line->e2fsattrs=readlong(ss[db->fields[i]], db, "e2fsattrs");
      break;
    }

    case attr_capabilities : {
      byte  *val = NULL;

      val = base64tobyte(ss[db->fields[i]], strlen(ss[db->fields[i]]),NULL);
      line->capabilities = (char *)val;
      break;
    }
    case attr_bsize :
    case attr_sizeg :
    case attr_rdev :
    case attr_dev :
    case attr_ftype :
    case attr_checkinode :
    case attr_allhashsums :
    case attr_allownewfile :
    case attr_allowrmfile : {
      /*  no db field */
      break;
    }
    case attr_unknown : {
      /* Unknown fields are ignored. */
      break;
    }
    
    }
    
  }

  return line;
}

time_t base64totime_t(char* s, database* db, const char* field_name){
  
  if(strcmp(s,"0")==0){
      return 0;
  }
  byte* b=decode_base64(s,strlen(s),NULL);
  char* endp;
  
  if (b==NULL) {
    
    /* Should we print error here? */
    
    return 0;
  } else {
    time_t t = strtol((char *)b,&endp,10);
    
    if (endp[0]!='\0') {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, could not read '%s' from database: strtoll failed for '%s' (base64 encoded value: '%s'), field_name, b, s)
      free(b);
      return 0;
    }
    log_msg(LOG_LEVEL_DEBUG, "base64totime_t: converted '%s': '%s' to %lld (base64 encoded value '%s')", field_name, b, (long long) t, s);
    free(b);
    return t;
  }
  
  
}


int db_writespec(db_config* dbconf)
{
    if(
#ifdef WITH_ZLIB
       (dbconf->gzip_dbout && dbconf->database_out.gzp) ||
#endif
       (dbconf->database_out.fp!=NULL)){
      if(db_writespec_file(dbconf)==RETOK){
	return RETOK;
      }
    }
  return RETFAIL;
}

int db_writeline(db_line* line,db_config* dbconf){

  if (line==NULL||dbconf==NULL) return RETOK;
  
    if (
#ifdef WITH_ZLIB
       (dbconf->gzip_dbout && dbconf->database_out.gzp) ||
#endif
       (dbconf->database_out.fp!=NULL)) {
      if (db_writeline_file(line,dbconf,dbconf->database_out.url)==RETOK) {
	return RETOK;
      }
    }
  return RETFAIL;
}

void db_close() {
  if (conf->database_out.url) {
  switch (conf->database_out.url->type) {
  case url_stdin:
  case url_stdout:
  case url_stderr:
  case url_fd:
  case url_file: {
    if (
#ifdef WITH_ZLIB
       (conf->gzip_dbout && conf->database_out.gzp) ||
#endif
       (conf->database_out.fp!=NULL)) {
        db_close_file(conf);
    }
    break;
  }
  case url_http:
  case url_https:
  case url_ftp:
    {
#ifdef WITH_CURL
        if (conf->database_out.fp!=NULL) {
            url_fclose(conf->database_out.fp);
        }
#endif /* WITH CURL */
      break;
    }
  /* unsupported database types */
  case url_syslog: {
    /* do nothing */
    break;
  }
  }
  }
  conf->database_in.db_line = close_db_attrs(&conf->database_in);
  conf->database_out.db_line = close_db_attrs(&conf->database_out);
  conf->database_new.db_line = close_db_attrs(&conf->database_new);
}

void free_db_line(db_line* dl)
{
  if (dl==NULL) {
    return;
  }
  
#define checked_free(x) do { free(x); x=NULL; } while (0)

  for (int i = 0 ; i < num_hashes ; ++i) {
      checked_free(dl->hashsums[i]);
  }

  dl->filename=NULL;
  checked_free(dl->fullpath);
  checked_free(dl->linkname);
  
  if (dl->acl)
  {
#ifdef WITH_ACL
    free(dl->acl->acl_a);
    free(dl->acl->acl_d);
#endif
  }
  checked_free(dl->acl);
  
  if (dl->xattrs)
    free(dl->xattrs->ents);
  checked_free(dl->xattrs);
  checked_free(dl->cntx);
}
