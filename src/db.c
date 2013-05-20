/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2010,2011,2013 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg, Hannes von Haugwitz
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
 
#include "aide.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "db.h"
#include "db_file.h"
#include "db_disk.h"
#include "md.h"

#ifdef WITH_PSQL
#include "db_sql.h"
#endif

#include "db_config.h"
#include "report.h"
#include "be.h"

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#include "base64.h"
#include "util.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

db_line* db_char2line(char** ss,int db);
long readint(char* s,char* err);
AIDE_OFF_TYPE readlong(char* s,char* err);
long readoct(char* s,char* err);
time_t base64totime_t(char*);

const char* db_names[db_unknown+1] = {
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
   "allownewfiles",
   "allowrmfiles",
   "sha256",
   "sha512",
   "whirlpool",
   "selinux",
   "xattrs",
   "e2fsattrs",
   "unknown"} ;

const int db_value[db_unknown+1] = {
   db_filename,         /* "name",   */
   db_linkname,         /* "lname",   */
   db_perm,             /* "perm",    */
   db_uid,              /* "uid",     */
   db_gid,              /* "gid",     */
   db_size,             /* "size",    */
   db_atime,            /* "atime",   */
   db_ctime,            /* "ctime",   */
   db_mtime,            /* "mtime",   */
   db_inode,            /* "inode",   */
   db_bcount,           /* "bcount",  */
   db_lnkcount,         /* "lcount",  */
   db_md5,              /* "md5",     */
   db_sha1,             /* "sha1",    */
   db_rmd160,           /* "rmd160",  */
   db_tiger,            /* "tiger",   */
   db_crc32,            /* "crc32",   */
   db_haval,            /* "haval",   */
   db_gost,             /* "gost",    */
   db_crc32b,           /* "crc32b",  */
   db_attr,             /* attributes */
   db_acl,              /* "acl"      */
   db_bsize,            /* "bsize"    */
   db_rdev,             /* "rdev"     */
   db_dev,              /* "dev"      */
   db_checkmask,        /* "checkmask" */
   db_allownewfile,     /* "allownewfile" */
   db_allowrmfile,      /* "allowrmfile" */
   db_sha256,           /* "sha256",  */
   db_sha512,           /* "sha512",  */
   db_whirlpool,        /* "whirlpool", */
   db_selinux,          /* "selinux", */
   db_xattrs,           /* "xattrs",  */
   db_e2fsattrs,        /* "e2fsattrs",  */
   db_unknown };        /* "unknown"  */

const char* db_namealias[db_alias_size] = {
  "count" } ;

const int db_aliasvalue[db_alias_size] = {
  db_lnkcount } ;       /* "count",  */

static struct md_container *init_db_attrs(URL_TYPE type) {
    struct md_container *mdc = NULL;
    if (conf->db_attrs) {
        switch (type) {
            case url_stdout:
            case url_stderr:
            case url_fd:
            case url_file:
            #ifdef WITH_CURL
            case url_http:
            case url_https:
            case url_ftp:
            #endif /* WITH CURL */
                mdc = malloc(sizeof(struct md_container)); /* freed in close_db_attrs */
                mdc->todo_attr = conf->db_attrs;
                init_md(mdc);
                break;
            #ifdef WITH_PSQL
            case url_sql:
                break;
            #endif /* WITH_PSQL */
            default :
                error(200,_("init_db_attrs(): Unknown url type.\n"));
        }
    }
    return mdc;
}

static db_line *close_db_attrs (struct md_container *mdc, char *url_value) {
    db_line *line = NULL;
    if (mdc != NULL) {
        close_md(mdc);
        line = malloc(sizeof(struct db_line));
        line->filename = url_value;
        line->perm = 0;
        line->attr = conf->db_attrs;
        md2line(mdc, line);
        free(mdc);
    }
    return line;
}

int db_init(int db)
{
  void* rv=NULL;
  
  error(200,"db_init %i\n",db);
  
  switch(db) {

  case DB_DISK: {
    /*
      Should we actually do something here?
     */
    return db_disk_init();
  }


  case DB_OLD: {
    conf->mdc_in = init_db_attrs((conf->db_in_url)->type);
    rv=be_init(1,conf->db_in_url,0);
    if(rv==NULL) {
      error(200,_("db_in is null\n"));      
      return RETFAIL;
    }
    conf->db_in=rv;
    error(200,_("db_in is nonnull\n"));
    return RETOK;
  }
  case DB_WRITE: {    
#ifdef WITH_ZLIB
    conf->mdc_out = init_db_attrs((conf->db_out_url)->type);
    if(conf->gzip_dbout){
       rv=be_init(0,conf->db_out_url,conf->gzip_dbout);
       conf->db_gzout=rv;
    }
    else{
#endif
      rv=be_init(0,conf->db_out_url,0);
      conf->db_out=rv;
#ifdef WITH_ZLIB
    }
#endif
    
    if(rv==NULL){
      error(200,_("db_out is null\n"));
      return RETFAIL;
    }
    error(200,_("db_out is nonnull %s\n"),conf->db_out_url->value);
    return RETOK;
  }
  case DB_NEW: {
    conf->mdc_out = init_db_attrs((conf->db_new_url)->type);
    rv=be_init(1,conf->db_new_url,0);
    if(rv==NULL) {
      error(200,_("db_new is null\n"));      
      return RETFAIL;
    }
    conf->db_new=rv;
    error(200,_("db_new is nonnull\n"));
    return RETOK;
  }
  }
  return RETFAIL;
}

db_line* db_readline(int db){
  db_line* s=NULL;
  int i=0;
  url_t* db_url=NULL;
  FILE** db_filep=NULL;
  int* db_osize=0;
  DB_FIELD** db_order=NULL;

  switch (db) {
  case DB_DISK: {
    /*
      Nothing else to be done?
     */
    s=db_readline_disk();
    return s;
  }
  
  case DB_OLD: {
    db_url=conf->db_in_url;
    db_filep=&(conf->db_in);
    db_osize=&(conf->db_in_size);
    db_order=&(conf->db_in_order);
    break;
  }
  case DB_NEW: {
    db_url=conf->db_new_url;
    db_filep=&(conf->db_new);
    db_osize=&(conf->db_new_size);
    db_order=&(conf->db_new_order);
    break;
  }
  }

  switch (db_url->type) {
#ifdef WITH_CURL
  case url_http:
  case url_https:
  case url_ftp:
#endif /* WITH CURL */
  case url_stdin:
  case url_fd:
  case url_file: {
    /* Should set errno */
    /* Please FIXME */
    if ((*db_filep)!=NULL) {
      char** ss=db_readline_file(db);
      if (ss!=NULL){
	s=db_char2line(ss,db);

	for(i=0;i<*db_osize;i++){
	  if((*db_order)[i]!=db_unknown && 
	     ss[(*db_order)[i]]!=NULL){
	    free(ss[(*db_order)[i]]);
	    ss[(*db_order)[i]]=NULL;
	  }
	}
	free(ss);
	
      }
    }
    
    break;
  }


#ifdef WITH_PSQL
  case url_sql: {
    error(255,"db_sql readline...");
    s=db_readline_sql(db, conf);
    
    break;
  }
#endif
  default : {
    error(0,_("db_readline():Url-type backend not implemented\n"));
    return NULL;
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
      return (strdup(""));

    if (s[1] == '0')
    {
      memmove(s, s+1, strlen(s+1)+1);
      // Hope this removes core
      // dumping in some environments. Has something to do with
      // memory (de)allocation.
    }
  }

  decode_string(s);

  return strdup(s);
}

#define WARN_ONCE(x) case db_ ## x : {                                  \
      static int warn_once_ ## x = 0;                                   \
      if (! warn_once_ ## x )                                           \
        error(0,_("Hash %s uses MHASH, which is not enabled.\n"),       \
              #x );                                                     \
      warn_once_ ## x = 1;                                              \
    } break

db_line* db_char2line(char** ss,int db){

  int i;
  db_line* line=(db_line*)malloc(sizeof(db_line)*1);
  int* db_osize=0;
  DB_FIELD** db_order=NULL;

  switch (db) {
  case DB_OLD: {
    db_osize=&(conf->db_in_size);
    db_order=&(conf->db_in_order);
    break;
  }
  case DB_NEW: {
    db_osize=&(conf->db_new_size);
    db_order=&(conf->db_new_order);
    break;
  }
  }


  line->md5=NULL;
  line->sha1=NULL;
  line->rmd160=NULL;
  line->tiger=NULL;

  line->crc32=NULL; /* MHASH stuff.. */
  line->crc32b=NULL;
  line->haval=NULL;
  line->gost=NULL;
  line->whirlpool=NULL;
  
  line->sha256=NULL;
  line->sha512=NULL;
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
  
  line->attr=conf->attr; /* attributes from @@dbspec */

  for(i=0;i<*db_osize;i++){
    switch ((*db_order)[i]) {
    case db_filename : {
      if(ss[(*db_order)[i]]!=NULL){
	decode_string(ss[(*db_order)[i]]);
	line->fullpath=strdup(ss[(*db_order)[i]]);
	line->filename=line->fullpath;
      } else {
	error(0,"db_char2line():Error while reading database\n");
	exit(EXIT_FAILURE);
      }
      break;
    }
    case db_linkname : {
      line->linkname = db_readchar(ss[(*db_order)[i]]);
      break;
    }
    case db_mtime : {
      line->mtime=base64totime_t(ss[(*db_order)[i]]);
      break;
    }
    case db_bcount : {
      line->bcount=readint(ss[(*db_order)[i]],"bcount");
      break;
    }
    case db_atime : {
      line->atime=base64totime_t(ss[(*db_order)[i]]);
      break;
    }
    case db_ctime : {
      line->ctime=base64totime_t(ss[(*db_order)[i]]);
      break;
    }
    case db_inode : {
      line->inode=readint(ss[(*db_order)[i]],"inode");
      break;
    }

    case db_uid : {
      line->uid=readint(ss[(*db_order)[i]],"uid");
      break;
    }
    case db_gid : {
      line->gid=readint(ss[(*db_order)[i]],"gid");
      break;
    }
    case db_size : {
      line->size=readlong(ss[(*db_order)[i]],"size");
      break;
    }
    case db_md5 : {
      line->md5=base64tobyte(ss[(*db_order)[i]],
			     strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_sha1 : {
      line->sha1=base64tobyte(ss[(*db_order)[i]],
			      strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_rmd160 : {
      line->rmd160=base64tobyte(ss[(*db_order)[i]],
				strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_tiger : {
      line->tiger=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_crc32 : {
      line->crc32=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_haval : {
      line->haval=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
#ifdef WITH_MHASH
    case db_gost : {
      line->gost=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_crc32b : {
      line->crc32b=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_whirlpool : {
      line->whirlpool=base64tobyte(ss[(*db_order)[i]],
                                   strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
#else
      WARN_ONCE(gost);
      WARN_ONCE(crc32b);
      WARN_ONCE(whirlpool);
#endif
    case db_sha256 : {
      line->sha256=base64tobyte(ss[(*db_order)[i]],
                                strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
    case db_sha512 : {
      line->sha512=base64tobyte(ss[(*db_order)[i]],
                                strlen(ss[(*db_order)[i]]), NULL);
      break;
    }
#ifdef WITH_SUN_ACL
    case db_acl : {
      char* endp,*pos;
      int entries,lc;
      line->acl=NULL;
      
      entries=strtol(ss[(*db_order)[i]],&endp,10);
      if (endp==ss[(*db_order)[i]]) {
 	/* Something went wrong */
	break;
      }
      pos=endp+1; /* Warning! if acl in database is corrupted then
		     this will break down. */
      
      line->acl=malloc(sizeof(acl_type));
      line->acl->entries=entries;
      line->acl->acl=malloc(sizeof(aclent_t)*entries);
      for (lc=0;lc<entries;lc++) {
	line->acl->acl[lc].a_type=strtol(pos,&endp,10);
	pos=endp+1;
	line->acl->acl[lc].a_id=strtol(pos,&endp,10);
	pos=endp+1;
	line->acl->acl[lc].a_perm=strtol(pos,&endp,10);
	pos=endp+1;
      }
      break;
    }
#endif
#ifdef WITH_POSIX_ACL
    case db_acl : {
      char *tval = NULL;
      
      tval = strtok(ss[(*db_order)[i]], ",");

      line->acl = NULL;

      if (tval[0] == '0')
        line->acl = NULL;
      else if (!strcmp(tval, "POSIX"))
      {
        line->acl = malloc(sizeof(acl_type));        
        line->acl->acl_a = NULL;
        line->acl->acl_d = NULL;
        
        tval = strtok(NULL, ",");
        line->acl->acl_a = (char *)base64tobyte(tval, strlen(tval), NULL);
        tval = strtok(NULL, ",");
        line->acl->acl_d = (char *)base64tobyte(tval, strlen(tval), NULL);
      }
      /* else, it's broken... */
      break;
    }
#endif
      case db_xattrs : {
        size_t num = 0;
        char *tval = NULL;
        
        tval = strtok(ss[(*db_order)[i]], ",");
        num = readlong(tval, "xattrs");
        if (num)
        {
          line->xattrs = malloc(sizeof(xattrs_type));
          line->xattrs->ents = calloc(sizeof(xattr_node), num);
          line->xattrs->sz  = num;
          line->xattrs->num = num;
          num = 0;
          while (num < line->xattrs->num)
          {
            byte  *val = NULL;
            size_t vsz = 0;
            
            tval = strtok(NULL, ",");
            line->xattrs->ents[num].key = db_readchar(strdup(tval));
            tval = strtok(NULL, ",");
            val = base64tobyte(tval, strlen(tval), &vsz);
            line->xattrs->ents[num].val = val;
            line->xattrs->ents[num].vsz = vsz;

            ++num;
          }
        }
        break;
      }

      case db_selinux : {
        byte  *val = NULL;
        
        val = base64tobyte(ss[(*db_order)[i]], strlen(ss[(*db_order)[i]]),NULL);
        line->cntx = (char *)val;
        break;
      }
      
    case db_perm : {
      line->perm=readoct(ss[(*db_order)[i]],"permissions");
      break;
    }
    
    case db_lnkcount : {
      line->nlink=readint(ss[(*db_order)[i]],"nlink");
      break;
    }

    case db_attr : {
      line->attr=readlong(ss[(*db_order)[i]],"attr");
      break;
    }
    
    case db_e2fsattrs : {
      line->e2fsattrs=readlong(ss[(*db_order)[i]],"e2fsattrs");
      break;
    }

    case db_unknown : {
      /* Unknown fields are ignored. */
      break;
    }
    
    default : {
      error(0,_("Not implemented in db_char2line %i \n"),(*db_order)[i]);
      return NULL;
    }
    
    }
    
  }

  return line;
}

time_t base64totime_t(char* s){
  
  byte* b=decode_base64(s,strlen(s),NULL);
  char* endp;
  
  if (b==NULL||strcmp(s,"0")==0) {
    
    /* Should we print error here? */
    free(b);
    
    return 0;
  } else {
    time_t t = strtol((char *)b,&endp,10);
    
    if (endp[0]!='\0') {
      error(0,"Error converting base64\n");
      free(b);
      return 0;
    }
    free(b);
    return t;
  }
  
  
}

long readint(char* s,char* err){
  long i;
  char* e;
  i=strtol(s,&e,10);
  if (e[0]!='\0') {
    error(0,_("Could not read %s from database"),err);
  }
  return i;
}

AIDE_OFF_TYPE readlong(char* s,char* err){
  AIDE_OFF_TYPE i;
  char* e;
  i=AIDE_STRTOLL_FUNC(s,&e,10);
  if (e[0]!='\0') {
    error(0,_("Could not read %s from database"),err);
  }
  return i;
}

long readoct(char* s,char* err){
  long i;
  char* e;
  i=strtol(s,&e,8);
  if (e[0]!='\0') {
    error(0,_("Could not read %s from database. String %s \n"),err,s);
  }
  return i;
}


int db_writespec(db_config* dbconf)
{
  switch (dbconf->db_out_url->type) {
  case url_stdout:
  case url_stderr:
  case url_fd:
  case url_file: {
    if(
#ifdef WITH_ZLIB
       (dbconf->gzip_dbout && dbconf->db_gzout) ||
#endif
       (dbconf->db_out!=NULL)){
      if(db_writespec_file(dbconf)==RETOK){
	return RETOK;
      }
    }
    break;
  }
#ifdef WITH_CURL
  case url_http:
  case url_https:
  case url_ftp:
    {
      
      break;
    }
#endif /* WITH CURL */
#ifdef WITH_PSQL
  case url_sql: {
    if(dbconf->db_out!=NULL){
      if(db_writespec_sql(dbconf)==RETOK){
	return RETOK;
      }
    }
    break;
  }
#endif
  default:{
    error(0,_("Unknown output in db out.\n"));    
    return RETFAIL;
  }
  }
  return RETFAIL;
}

int db_writeline(db_line* line,db_config* dbconf){

  if (line==NULL||dbconf==NULL) return RETOK;
  
  switch (dbconf->db_out_url->type) {
#ifdef WITH_CURL
  case url_http:
  case url_https:
  case url_ftp:
#endif /* WITH CURL */
  case url_stdout:
  case url_stderr:
  case url_fd:
  case url_file: {
    if (
#ifdef WITH_ZLIB
       (dbconf->gzip_dbout && dbconf->db_gzout) ||
#endif
       (dbconf->db_out!=NULL)) {
      if (db_writeline_file(line,dbconf,dbconf->db_out_url)==RETOK) {
	return RETOK;
      }
    }
    return RETFAIL;
    break;
  }
#ifdef WITH_PSQL
  case url_sql: {
    if (dbconf->db_out!=NULL) {
      if (db_writeline_sql(line,dbconf)==RETOK) {
	return RETOK;
      }
    }
    return RETFAIL;
    break;
  }
#endif
  default : {
    error(0,_("Unknown output in db out.\n"));    
    return RETFAIL;
  } 
  }
  return RETFAIL;
}

void db_close() {
  switch (conf->db_out_url->type) {
  case url_stdout:
  case url_stderr:
  case url_fd:
  case url_file: {
    if (
#ifdef WITH_ZLIB
       (conf->gzip_dbout && conf->db_gzout) ||
#endif
       (conf->db_out!=NULL)) {
        db_close_file(conf);
    }
    break;
  }
#ifdef WITH_CURL
  case url_http:
  case url_https:
  case url_ftp:
    {
        if (conf->db_out!=NULL) {
            url_fclose(conf->db_out);
        }
      break;
    }
#endif /* WITH CURL */
#ifdef WITH_PSQL
  case url_sql: {
    if (conf->db_out!=NULL) {
      db_close_sql(conf->db_out);
    }
    break;
  }
#endif
  default : {
    error(0,_("db_close():Unknown output in db out.\n"));    
  } 
  }
  conf->line_db_in = close_db_attrs(conf->mdc_in, (conf->db_in_url)->value);
  conf->line_db_out = close_db_attrs(conf->mdc_out, (conf->action&DO_DIFF
          ? conf->db_new_url : conf->db_out_url)->value);
}

void free_db_line(db_line* dl)
{
  if (dl==NULL) {
    return;
  }
  
#define checked_free(x) do { free(x); x=NULL; } while (0)

  checked_free(dl->md5);
  checked_free(dl->sha1);
  checked_free(dl->rmd160);
  checked_free(dl->tiger);
  dl->filename=NULL;
  checked_free(dl->fullpath);
  checked_free(dl->linkname);
  
#ifdef WITH_MHASH
  checked_free(dl->crc32);
  checked_free(dl->crc32b);
  checked_free(dl->gost);
  checked_free(dl->haval);
#endif
  
  checked_free(dl->sha256);
  checked_free(dl->sha512);
  checked_free(dl->whirlpool);

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
const char* aide_key_5=CONFHMACKEY_05;
const char* db_key_5=DBHMACKEY_05;
