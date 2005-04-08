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
 
#include "aide.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "db.h"
#include "db_file.h"
#include "db_disk.h"

#ifdef WITH_PSQL
#include "db_sql.h"
#endif

#include "db_config.h"
#include "report.h"
#include "be.h"

/*
#include <gcrypt.h>
*/
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
AIDE_SIZE_TYPE readlong(char* s,char* err);
long readoct(char* s,char* err);

time_t base64totime_t(char*);
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
    s=db_readline_disk(db);
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

byte* base64tobyte(char* src,int len)
{
  if(strcmp(src,"0")!=0){
    return decode_base64(src,len);
  }
  return NULL;
}

db_line* db_char2line(char** ss,int db){

  int i;
  db_line* line=(db_line*)malloc(sizeof(db_line)*1);
  url_t* db_url=NULL;
  FILE** db_filep=NULL;
  int* db_osize=0;
  DB_FIELD** db_order=NULL;

  switch (db) {
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


  line->md5=NULL;
  line->sha1=NULL;
  line->rmd160=NULL;
  line->tiger=NULL;
#ifdef WITH_MHASH
  line->crc32=NULL;
  line->crc32b=NULL;
  line->haval=NULL;
  line->gost=NULL;
#endif
#ifdef WITH_ACL
  line->acl=0;
#endif
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
  line->linkname=NULL;
  
  line->attr=conf->attr; /* attributes from @@dbspec */

  for(i=0;i<*db_osize;i++){
    switch ((*db_order)[i]) {
    case db_filename : {
      if(ss[(*db_order)[i]]!=NULL){
	decode_string(ss[(*db_order)[i]]);
	line->filename=strdup(ss[(*db_order)[i]]);
      } else {
	error(0,"db_char2line():Error while reading database\n");
	abort();
      }
      break;
    }
    case db_linkname : {
      char *s = ss[(*db_order)[i]];
      if(ss[(*db_order)[i]]!=NULL){
	if(ss[(*db_order)[i]][0]=='0'){
	  if(ss[(*db_order)[i]][1]=='\0'){
	    line->linkname=NULL;
	    break;
	  }else if(ss[(*db_order)[i]][1]=='-'){
	    line->linkname=strdup("");
	    break;
	  }else if(ss[(*db_order)[i]][1]=='0'){
	    memmove(s,s+1,strlen(s+1)+1); 
	    // Hope this removes core
	    // dumping in some environments. Has something to do with
	    // memory (de)allocation.
	  }
	}
	decode_string(s);
	line->linkname=strdup(s);
      } else {
	error(0,_("db_char2line():Error while reading database\n"));
	abort();
      }
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
			     strlen(ss[(*db_order)[i]]));
      break;
    }
    case db_sha1 : {
      line->sha1=base64tobyte(ss[(*db_order)[i]],
			      strlen(ss[(*db_order)[i]]));
      break;
    }
    case db_rmd160 : {
      line->rmd160=base64tobyte(ss[(*db_order)[i]],
				strlen(ss[(*db_order)[i]]));
      break;
    }
    case db_tiger : {
      line->tiger=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]));
      break;
    }
#ifdef WITH_MHASH
    case db_crc32 : {
      line->crc32=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]));
      break;
    }
    case db_gost : {
      line->gost=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]));
      break;
    }
    case db_haval : {
      line->haval=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]));
      break;
    }
    case db_crc32b : {
      line->crc32b=base64tobyte(ss[(*db_order)[i]],
			       strlen(ss[(*db_order)[i]]));
      break;
    }
#endif
#ifdef WITH_ACL
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
    case db_perm : {
      line->perm=readoct(ss[(*db_order)[i]],"permissions");
      break;
    }
    
    case db_lnkcount : {
      line->nlink=readint(ss[(*db_order)[i]],"nlink");
      break;
    }

    case db_attr : {
      line->attr=readint(ss[(*db_order)[i]],"attr");
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
  
  byte* b=decode_base64(s,strlen(s));
  char* endp;
  
  if (b==NULL||strcmp(s,"0")==0) {
    
    /* Should we print error here? */
    free(b);
    
    return 0;
  } else {
    time_t t = strtol(b,&endp,10);
    
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

AIDE_SIZE_TYPE readlong(char* s,char* err){
  AIDE_SIZE_TYPE i;
  char* e;
  i=AIDE_STRTOULL_FUNC(s,&e,10);
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


int db_writespec(db_config* conf)
{
  switch (conf->db_out_url->type) {
  case url_stdout:
  case url_stderr:
  case url_fd:
  case url_file: {
    if(
#ifdef WITH_ZLIB
       (conf->gzip_dbout && conf->db_gzout) ||
#endif
       (conf->db_out!=NULL)){
      if(db_writespec_file(conf)==RETOK){
	return RETOK;
      }
    }
    break;
  }
#ifdef WITH_PSQL
  case url_sql: {
    if(conf->db_out!=NULL){
      if(db_writespec_sql(conf)==RETOK){
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

int db_writeline(db_line* line,db_config* conf){

  if (line==NULL||conf==NULL) return RETOK;
  
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
      if (db_writeline_file(line,conf)==RETOK) {
	return RETOK;
      }
    }
    return RETFAIL;
    break;
  }
#ifdef WITH_PSQL
  case url_sql: {
    if (conf->db_out!=NULL) {
      if (db_writeline_sql(line,conf)==RETOK) {
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

int db_close(db_config* conf)
{
  if (conf==NULL) return RETOK;
  
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
      if (db_close_file(conf)==RETOK) {
	return RETOK;
      }
    }
    return RETFAIL;
    break;
  }
#ifdef WITH_PSQL
  case url_sql: {
    if (conf->db_out!=NULL) {
      if (db_close_sql(conf->db_out)==RETOK) {
	return RETOK;
      } else {
	return RETFAIL;
      }
    }
    return RETOK;
    break;
  }
#endif
  default : {
    error(0,_("db_close():Unknown output in db out.\n"));    
    return RETFAIL;
  } 
  }
  return RETFAIL;
}

void free_db_line(db_line* dl)
{
  if (dl==NULL) {
    return;
  }
  
#define checked_free(x) if(x!=NULL) { free(x); x=NULL; }

  checked_free(dl->md5);
  checked_free(dl->sha1);
  checked_free(dl->rmd160);
  checked_free(dl->tiger);
  checked_free(dl->filename);
  checked_free(dl->linkname);
  
  checked_free(dl->crc32);
  checked_free(dl->crc32b);
  checked_free(dl->gost);
  checked_free(dl->haval);
}
const char* aide_key_5=CONFHMACKEY_05;
const char* db_key_5=DBHMACKEY_05;
