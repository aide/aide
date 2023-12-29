/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2007, 2010-2013, 2016, 2018-2023 Rami Lehti,
 *               Pablo Virolainen, Mike Markley, Richard van den Berg,
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

#include "config.h"
#include "aide.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include "db_config.h"
#include "hashsum.h"
#include "log.h"
#include "url.h"

#include "attributes.h"

#include <errno.h>

#include "base64.h"
#include "db_line.h"
#include "db_lex.h"
#include "db_file.h"
#include "util.h"
#include "errorcodes.h"

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#define BUFSIZE 16384

#include "md.h"


int dofflush(void)
{

  int retval;
#ifdef WITH_ZLIB
  if(conf->gzip_dbout){
    /* Should not flush using gzip, it degrades compression */
    retval=Z_OK;
  }else {
#endif
    retval=fflush(conf->database_out.fp);
#ifdef WITH_ZLIB
  }
#endif

  return retval;
}

int dofprintf(const char*, ...)
#ifdef __GNUC__
        __attribute__ ((format (printf, 1, 2)))
#endif
;
int dofprintf( const char* s,...)
{
  char buf[3];
  int retval;
  char* temp=NULL;
  va_list ap;
  
  va_start(ap,s);
  retval=vsnprintf(buf,3,s,ap);
  va_end(ap);
  
  temp=(char*)checked_malloc(retval+2);

  va_start(ap,s);
  retval=vsnprintf(temp,retval+1,s,ap);
  va_end(ap);
  
  if ((conf->database_out).mdc) {
      update_md((conf->database_out).mdc,temp ,retval);
  }

#ifdef WITH_ZLIB
  if(conf->gzip_dbout){
    retval=gzwrite((conf->database_out).gzp,temp,retval);
  }else{
#endif
    /* writing is ok with fwrite with curl.. */
    retval=fwrite(temp,1,retval,conf->database_out.fp);
#ifdef WITH_ZLIB
  }
#endif
  free(temp);

  return retval;
}



static int db_file_read_spec(database* db){
  int i=0;

  DB_ATTR_TYPE seen_attrs = 0LLU;

  db->fields = checked_malloc(1*sizeof(ATTRIBUTE));
  
  while ((i=db_scan())!=TNEWLINE){
    LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "db_file_read_spec(): db_scan() returned token=%d", i);

    switch (i) {
      
    case TSTRING : {
      ATTRIBUTE l;
      db->fields = checked_realloc(db->fields, (db->num_fields+1)*sizeof(ATTRIBUTE));
      db->fields[db->num_fields]=attr_unknown;
      for (l=0;l<num_attrs;l++){
          if (attributes[l].db_name && strcmp(attributes[l].db_name,dbtext)==0) {
              if (ATTR(l)&seen_attrs) {
                  LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "@@dbspec: skip redefined field '%s' at position %i", dbtext, db->num_fields)
                  db->fields[db->num_fields]=attr_unknown;
              } else {
                  db->fields[db->num_fields]=l;
                  seen_attrs |= ATTR(l);
                  LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "@@dpspec: define field '%s' at position %i", dbtext, db->num_fields)
              }
              db->num_fields++;
              break;
          }
      }

      if(l==attr_unknown){
          LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "@@dbspec: skip unknown field '%s' at position %i", dbtext, db->num_fields);
          db->fields[db->num_fields]=attr_unknown;
          db->num_fields++;
      }
      break;
    }

    default : {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_ERROR, "unexpected token while reading dbspec: '%s'", dbtext);
      return RETFAIL;
    }
    }
  }

  /* Lets generate attr from db_order if database does not have attr */
  conf->attr=DB_ATTR_UNDEF;

  for (i=0;i<db->num_fields;i++) {
    if (db->fields[i] == attr_attr) {
      conf->attr=1;
    }
  }
  if (conf->attr==DB_ATTR_UNDEF) {
    conf->attr=0;
    for(i=0;i<db->num_fields;i++) {
      conf->attr|=1LL<<db->fields[i];
    }
    char *str;
    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "missing attr field, generated attr field from dbspec: %s (comparison may be incorrect)", str = diff_database_attributes(0, conf->attr))
    free(str);
  }
  return RETOK;
}

DB_TOKEN skip_line(database* db) {
    DB_TOKEN token;
    do {
        token = db_scan();
        LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "db_readline_file(): db_scan() returned a=%d", token);
        LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "skip_line(): skip '%s'", token==TNEWLINE?"\n":dbtext)
    } while(token != TNEWLINE && token != TEOF);
    return token;
}

char** db_readline_file(database* db) {
  log_msg(LOG_LEVEL_TRACE, "db_readline_file(): arguments db=%p", (void*) db);
  char** s=NULL;
  
  int i=0;
  int a=0;
  DB_TOKEN token;
  bool found_enddb = false;;

  do {
  token = db_scan();
  LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "db_readline_file(): db_scan() returned token=%d", token);
  if (db->fields) {
    switch (token) {
        case TUNKNOWN: {
          LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "unknown token '%s' found inside database (skip line)", dbtext)
          skip_line(db);
          break;
        }
        case TDBSPEC:
        case TBEGIN_DB: {
          LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "additional '%s' found inside database (skip line)", dbtext)
          skip_line(db);
          break;
        }
        case TEND_DB: {
          LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "%s", "'@@end_db' found")
          found_enddb = true;
          break;
        }
        case TEOF:
        case TNEWLINE: {
            if (s) {
                if (i<db->num_fields-1) {
                    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "cutoff database line '%s' found (field '%s' (position: %d) is missing) (skip line)", s[0], attributes[db->fields[i+1]].db_name, i+1);
                    for(a=0;a<i;a++){
                        free(s[db->fields[a]]);
                        s[db->fields[a]] = NULL;
                    }
                    free(s);
                    s = NULL;
                } else {
                    return s;
                }
            }
            if (found_enddb) {
                LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "%s", "stop reading database")
                return s;
            } else if (token == TEOF) {
                LOG_DB_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "missing '@@end_db' in database")
                exit(DATABASE_ERROR);
            }
            break;
        }
        case TSTRING: {
            if (!found_enddb) {
            if (s) {
                if (++i<db->num_fields) {
                    if (db->fields[i] != attr_unknown) {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "'%s' set field '%s' (position %d): '%s'", s[0], attributes[db->fields[i]].db_name, i, dbtext);
                        s[db->fields[i]] = checked_strdup(dbtext);
                    } else {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "skip unknown/redefined field at position: %d: '%s'", i, dbtext);
                    }
                } else {
                    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "expected newline or end of file (skip found string '%s')", dbtext);
                }
            } else {
                if (*dbtext != '/') {
                    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "invalid path found: '%s' (skip line)", dbtext);
                    skip_line(db);
                } else {
                    i = 0;
                    s = checked_malloc(sizeof(char*)*num_attrs);
                    for(ATTRIBUTE j=0; j<num_attrs; j++){
                        s[j]=NULL;
                    }
                    s[i] = checked_strdup(dbtext);
                    LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "'%s' set field '%s' (position %d): '%s'", s[0], attributes[db->fields[i]].db_name, i, dbtext);
                }
            }
            } else {
                LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "expected newline or end of file (skip found string '%s')", dbtext)
            }
            break;
        }
    }
  } else {
      if (token == TEOF) {
          /* allow empty database */
          LOG_DB_FORMAT_LINE(LOG_LEVEL_INFO, "%s", "db_readline_file(): empty database file");
          return s;
      }
      while (token != TBEGIN_DB) {
          if (token == TEOF) {
              LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "%s", "db_readline_file(): '@@begin_db' NOT found (stop reading database)");
              return s;
          }
          LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "db_readline_file(): skip '%s'", dbtext);
          token = db_scan();
          LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "db_readline_file(): db_scan() returned token=%d", token);
      }
      LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "%s", "'@@begin_db' found")
      token = db_scan();
      LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "db_readline_file(): db_scan() returned token=%d", token);
      if (token != TNEWLINE) {
              LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "%s", "db_readline_file(): missing newline after '@@begin_db' (stop reading database)");
              return s;

      } else {
          token = db_scan();
          LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, "db_readline_file(): db_scan() returned token=%d", token);
          if (token != TDBSPEC) {
              LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "db_readline_file(): unexpected token '%s'%c expected '@@db_spec' (stop reading database)", dbtext, 'c');
              return s;
          } else {
              LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "%s", "'@@dbspec' found")
              if (db_file_read_spec(db)!=0) {
                  /* something went wrong */
                  return s;
              }
          }
      }
  }
  } while (token != TEOF);

  return s;
  
}

int db_writechar(char* s,FILE* file,int i)
{
  char* r=NULL;
  int retval=0;

  (void)file;
  
  if(i) {
    dofprintf(" ");
  }

  if(s==NULL){
    retval=dofprintf("0");
    return retval;
  }
  if(s[0]=='\0'){
    retval=dofprintf("0-");
    return retval;
  }
  if(s[0]=='0'){
    retval=dofprintf("00");
    if(retval<0){
      return retval;
    }
    s++;
  }
  
  if (!i && s[0]=='#') {
    dofprintf("# ");
    r=CLEANDUP(s+1);
  } else {
    r=CLEANDUP(s);
  }
  
  retval=dofprintf("%s",r);
  free(r);
  return retval;
}

static int db_writelong(long i,FILE* file,int a)
{
  (void)file;
  
  if(a) {
    dofprintf(" ");
  }
  
  return dofprintf("%li",i);
  
}

static int db_writelonglong(long long i,FILE* file,int a)
{
  (void)file;
  
  if(a) {
    dofprintf(" ");
  }
  
  return dofprintf("%lli",i);
  
}


int db_write_attr(DB_ATTR_TYPE i,FILE* file,int a)
{
    (void)file;
    if(a) {
        dofprintf(" ");
    }
    return dofprintf("%llu", i);
}

int db_write_byte_base64(byte*data,size_t len,FILE* file,int i,
                         DB_ATTR_TYPE th, DB_ATTR_TYPE attr )
{
  char* tmpstr=NULL;
  
  (void)file;  
  if (data && !len)
    len = strlen((const char *)data);
  
  if (data!=NULL&&th&attr) {
    tmpstr=encode_base64(data,len);
  } else {
    tmpstr=NULL;
  }
  if(i){
    dofprintf(" ");
  }

  if(tmpstr){
    int retval=dofprintf("%s", tmpstr);
    free(tmpstr);
    return retval;
  }else {
    return dofprintf("0");
  }
  return 0;

}

int db_write_time_base64(time_t i,FILE* file,int a)
{
  static char* ptr=NULL;
  char* tmpstr=NULL;
  int retval=0;

  (void)file;
  
  if(a){
    dofprintf(" ");
  }

  if(i==0){
    retval=dofprintf("0");
    return retval;
  }


  int len = sizeof(char)*TIMEBUFSIZE;
  ptr=(char*)checked_malloc(len);

  memset((void*)ptr,0,len);

  snprintf(ptr, len, "%li",i);


  tmpstr=encode_base64((byte *)ptr,strlen(ptr));
  retval=dofprintf("%s", tmpstr);
  free(tmpstr);
  free(ptr);

  return retval;

}

int db_writeoct(long i, FILE* file,int a)
{
  (void)file;
  
  if(a) {
    dofprintf(" ");
  }
  
  return dofprintf("%lo",i);
  
}

int db_writespec_file(db_config* dbconf)
{
  int retval=1;
  struct tm* st;
  time_t tim=time(&tim);
  st=localtime(&tim);

  retval=dofprintf("@@begin_db\n");
  if(retval==0){
    return RETFAIL;
  }

  if(dbconf->database_add_metadata) {
      retval=dofprintf(
             "# This file was generated by Aide, version %s\n"
             "# Time of generation was %.4u-%.2u-%.2u %.2u:%.2u:%.2u\n",
             conf->aide_version,
             st->tm_year+1900, st->tm_mon+1, st->tm_mday,
             st->tm_hour, st->tm_min, st->tm_sec
             );
      if(retval==0){
        return RETFAIL;
      }
  }
  if(dbconf->config_version){
    retval=dofprintf(
		     "# The config version used to generate this file was:\n"
		     "# %s\n", dbconf->config_version);
    if(retval==0){
      return RETFAIL;
    }
  }
  retval=dofprintf("@@db_spec ");
  if(retval==0){
    return RETFAIL;
  }
  for (ATTRIBUTE i = 0 ; i < num_attrs ; ++i) {
      if (attributes[i].db_name && attributes[i].attr&conf->db_out_attrs) {
          retval=dofprintf("%s ", attributes[i].db_name);
          if(retval==0){
              return RETFAIL;
          }
      }
  }
  retval=dofprintf("\n");
  if(retval==0){
    return RETFAIL;
  }
  return RETOK;
}

#ifdef WITH_ACL
int db_writeacl(acl_type* acl,FILE* file,int a)
{
#ifdef WITH_POSIX_ACL
  if(a) {
    dofprintf(" ");
  }
  
  if (acl==NULL) {
    dofprintf("0");
  } else {    
    dofprintf("POSIX"); /* This is _very_ incompatible */

    dofprintf(",");
    if (acl->acl_a)
      db_write_byte_base64((byte*)acl->acl_a, 0, file,0,1,1);
    else
      dofprintf("0");
    dofprintf(",");
    if (acl->acl_d)
      db_write_byte_base64((byte*)acl->acl_d, 0, file,0,1,1);
    else
      dofprintf("0");
  }
#endif
  return RETOK;
}
#endif


#define WRITE_HASHSUM(x) \
case attr_ ##x : { \
    db_write_byte_base64(line->hashsums[hash_ ##x], \
        hashsums[hash_ ##x].length, \
        dbconf->database_out.fp, i, \
        ATTR(attr_ ##x), line->attr); \
    break; \
}

int db_writeline_file(db_line* line,db_config* dbconf, url_t* url){

  (void)url;

  for (ATTRIBUTE i = 0 ; i < num_attrs ; ++i) {
    if (attributes[i].db_name && ATTR(i)&conf->db_out_attrs) {
    switch (i) {
    case attr_filename : {
      db_writechar(line->filename,dbconf->database_out.fp,i);
      break;
    }
    case attr_linkname : {
      db_writechar(line->linkname,dbconf->database_out.fp,i);
      break;
    }
    case attr_bcount : {
      db_writelonglong(line->bcount,dbconf->database_out.fp,i);
      break;
    }

    case attr_mtime : {
      db_write_time_base64(line->mtime,dbconf->database_out.fp,i);
      break;
    }
    case attr_atime : {
      db_write_time_base64(line->atime,dbconf->database_out.fp,i);
      break;
    }
    case attr_ctime : {
      db_write_time_base64(line->ctime,dbconf->database_out.fp,i);
      break;
    }
    case attr_inode : {
      db_writelong(line->inode,dbconf->database_out.fp,i);
      break;
    }
    case attr_linkcount : {
      db_writelong(line->nlink,dbconf->database_out.fp,i);
      break;
    }
    case attr_uid : {
      db_writelong(line->uid,dbconf->database_out.fp,i);
      break;
    }
    case attr_gid : {
      db_writelong(line->gid,dbconf->database_out.fp,i);
      break;
    }
    case attr_size : {
      db_writelonglong(line->size,dbconf->database_out.fp,i);
      break;
    }
    case attr_perm : {
      db_writeoct(line->perm,dbconf->database_out.fp,i);
      break;
    }
    WRITE_HASHSUM(md5)
    WRITE_HASHSUM(sha1)
    WRITE_HASHSUM(rmd160)
    WRITE_HASHSUM(tiger)
    WRITE_HASHSUM(crc32)
    WRITE_HASHSUM(crc32b)
    WRITE_HASHSUM(haval)
    WRITE_HASHSUM(gostr3411_94)
    WRITE_HASHSUM(stribog256)
    WRITE_HASHSUM(stribog512)
    WRITE_HASHSUM(sha256)
    WRITE_HASHSUM(sha512)
    WRITE_HASHSUM(whirlpool)
    case attr_attr : {
      db_write_attr(line->attr, dbconf->database_out.fp,i);
      break;
    }
#ifdef WITH_ACL
    case attr_acl : {
      db_writeacl(line->acl,dbconf->database_out.fp,i);
      break;
    }
#endif
#ifdef WITH_XATTR
    case attr_xattrs : {
        xattr_node *xattr = NULL;
        size_t num = 0;
        
        if (!line->xattrs)
        {
          db_writelong(0, dbconf->database_out.fp, i);
          break;
        }
        
        db_writelong(line->xattrs->num, dbconf->database_out.fp, i);
        
        xattr = line->xattrs->ents;
        while (num < line->xattrs->num)
        {
          dofprintf(",");
          db_writechar(xattr->key, dbconf->database_out.fp, 0);
          dofprintf(",");
          db_write_byte_base64(xattr->val, xattr->vsz, dbconf->database_out.fp, 0, 1, 1);
          
          ++xattr;
          ++num;
        }
      break;
    }
#endif
    case attr_selinux : {
	db_write_byte_base64((byte*)line->cntx, 0, dbconf->database_out.fp, i, 1, 1);
      break;
    }
#ifdef WITH_E2FSATTRS
    case attr_e2fsattrs : {
      db_writelong(line->e2fsattrs,dbconf->database_out.fp,i);
      break;
    }
#endif
#ifdef WITH_CAPABILITIES
    case attr_capabilities : {
      db_write_byte_base64((byte*)line->capabilities, 0, dbconf->database_out.fp, i, 1, 1);
      break;
    }
#endif
    default : {
      log_msg(LOG_LEVEL_ERROR,"not implemented in db_writeline_file %i", i);
      return RETFAIL;
    }
    
    }
    
  }

  }

  dofprintf("\n");
  /* Can't use fflush because of zlib.*/
  dofflush();

  return RETOK;
}

int db_close_file(db_config* dbconf){
  
  if(dbconf->database_out.fp
#ifdef WITH_ZLIB
     || dbconf->database_out.gzp
#endif
     ){
      dofprintf("@@end_db\n");
  }

#ifdef WITH_ZLIB
  if(dbconf->gzip_dbout){
    if(gzclose(dbconf->database_out.gzp)){
      log_msg(LOG_LEVEL_ERROR,"unable to gzclose database '%s:%s': %s", get_url_type_string((dbconf->database_out.url)->type), (dbconf->database_out.url)->value, strerror(errno));
      return RETFAIL;
    }
    dbconf->database_out.gzp = NULL;
  }else {
#endif
    if(fclose(dbconf->database_out.fp)){
      log_msg(LOG_LEVEL_ERROR,"unable to close database '%s:%s': %s", get_url_type_string((dbconf->database_out.url)->type), (dbconf->database_out.url)->value, strerror(errno));
      return RETFAIL;
    }
    dbconf->database_out.fp = NULL;
#ifdef WITH_ZLIB
  }
#endif

  return RETOK;
}
// vi: ts=8 sw=8
