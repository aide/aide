/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 2000-2002,2004-2006,2011 Rami Lehti, Pablo Virolainen,
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
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#ifdef WITH_PSQL
 
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <gcrypt.h>
#include "base64.h"
#include "db.h"

#include "db_sql.h"
#include "db_config.h"
#include "libpq-fe.h"
#include "report.h"

#ifdef WITH_MHASH
#include <mhash.h>
#endif

char* db_get_sql(db_line*,db_config*);

int _db_check_result(PGconn *conn, PGresult *res, char *query) 
{
  int status = 0;
  int ret = RETOK;


  if (!res || ( (PQresultStatus(res) != PGRES_COMMAND_OK) &&
                (PQresultStatus(res) != PGRES_TUPLES_OK) )){
    ret = RETFAIL;
    if (res!=NULL) {
        error(0,"Sql error %s while doing %s\n", PQerrorMessage(conn), query);
    } else {
        error(0,"Sql error while doing %s.\n",query);
    }
  } else {
    error(255,"Sql went ok.\n");
    status = 1;
  }
 
  return status;
}

int db_writespec_sql(db_config* conf){
  PGresult *res;
  int i;
  int table_exists;
  char* s;
  int ret = RETOK;

  s = (char*) malloc(sizeof(char)*1024); /* Hope 1023 bytes is
					    enough for string...
					    390 + length of table
					    name should be enough.
					 */
  /* We have to ensure that the database table not exist */

  /* check if the table exists already */
  sprintf(s, "SELECT * FROM pg_class WHERE relname = '%s'", 
             ((psql_data*)conf->db_out)->table);
  res = PQexec(((psql_data*)conf->db_out)->conn, s);
  if ( _db_check_result(((psql_data*)conf->db_out)->conn, res, s) == 0 ) {
    ret = RETFAIL;
  }
  table_exists = PQntuples(res) == 1 ? 1 : 0;
  PQclear(res);

  *s = '\0';  /* reset query string */

  if (table_exists == 0) {
    /* we need to create the table */
    
    s = strcat(s, "CREATE TABLE ");

    s = strcat(s, ((psql_data*)conf->db_out)->table);
    s = strcat(s, "(");
  
    for (i=0;i<conf->db_out_size;i++) {
      if (i!=0) {
        s = strcat(s, ",");
      }
      s = strcat(s, db_names[conf->db_out_order[i]]);
      s = strcat(s, " ");
      s = strcat(s, db_sql_types[conf->db_out_order[i]]);
    }
    s = strcat(s,");");

    error(255,"SQL:%s\n",s);
    
    res = PQexec(((psql_data*)conf->db_out)->conn,s);

    if (_db_check_result(((psql_data*)conf->db_out)->conn, res, s) == 0) {
      ret = RETFAIL;
    }
  
    PQclear(res);  
  }

  free(s); /* Just say no to memoryleaks. */
  
  return ret;
  
  /* FIXME!! No error checkin may be broken. Fix malloc also */ 
}

int db_writeline_sql(db_line* line,db_config* conf){

  PGresult *res;
  int i;
  int ret=RETOK;
  char* s=db_get_sql(line,conf) ;
  
  if (s==NULL) {
    return RETFAIL;
  }
  
  error(255,"SQL:%s",s);
  
  res = PQexec(((psql_data*)conf->db_out)->conn,s);
  if ( _db_check_result(((psql_data*)conf->db_out)->conn, res, s) == 0 ) {
    ret = RETFAIL;
  }
  PQclear(res);
  
  free(s);
  
  return ret;
}

void db_readline_sql_int(int* d,int db,int i, db_config* conf) 
{
  FILE** db_filep=NULL;

  switch (db) {
  case DB_OLD: {
    db_filep=&(conf->db_in);
    break;
  }
  case DB_NEW: {
    db_filep=&(conf->db_new);
    break;
  }
  }

  if (((psql_data*)(*db_filep))->des[i]!=-1) {
    *d=(int)PQgetvalue(((psql_data*)(*db_filep))->res, 
		       ((psql_data*)(*db_filep))->curread,
		       ((psql_data*)(*db_filep))->des[i]);
  } else {
    *d=0;
  }
  error(254,"sql_readline_sql_int %s got %i\n",db_names[i],*d);

}

void db_readline_sql_char(void** d,int db,const int i, db_config* conf) 
{
  
  volatile int cr,des;
  psql_data* data;
  FILE** db_filep=NULL;

  switch (db) {
  case DB_OLD: {
    db_filep=&(conf->db_in);
    break;
  }
  case DB_NEW: {
    db_filep=&(conf->db_new);
    break;
  }
  }

  data=((psql_data*)(*db_filep));
  
  cr=data->curread;
  des=data->des[i];
  if (des!=-1) {
    volatile char* s=NULL;
    
    s = (char*)PQgetvalue(data->res,cr,des);
    if (s!=NULL) {
      *d=(void*)strdup((char*)s);
    } else {
      *d=NULL;
    }
    error(254,"sql_readline_sql_char %i,%i %s got %s\n",cr,des,db_names[i],*d);
  } else {
    *d=NULL;
    error(254,"sql_readline_sql_char %i,%i %s got NULL\n",cr,des,db_names[i]);
  }
  
}

void db_readline_sql_byte(void** d,int db,int i, db_config* conf) {
  
  db_readline_sql_char(d,db,i, conf);
  
  if (*d!=NULL) {
    *((byte*)d)=base64tobyte(*d,strlen(*d));
  }
  
}

void db_readline_sql_time(void** d,int db,int i, db_config* conf) {
  
  db_readline_sql_char(d,db,i, conf);
  
  if (*d!=NULL) {
    *((time_t*)d)=base64totime_t(*d);
  }
  
}

db_line* db_readline_sql(int db, db_config* conf) {
  
  volatile db_line* rline;
  int i;
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

  
  if (((psql_data*)(*db_filep))->curread>=
      ((psql_data*)(*db_filep))->maxread) {
    error(255,"Everything read from SQL\n");
    return NULL;
  }
  rline=(db_line*)malloc(1*sizeof(db_line));
  
  db_readline_sql_byte((void*)&(rline->md5),db,(int)db_md5, conf);
  db_readline_sql_byte((void*)&(rline->sha1),db,db_sha1, conf);
  db_readline_sql_byte((void*)&(rline->rmd160),db,db_rmd160, conf);
  db_readline_sql_byte((void*)&(rline->tiger),db,db_tiger, conf);
#ifdef WITH_MHASH
  db_readline_sql_byte((void*)&(rline->crc32),db,db_crc32, conf);
  db_readline_sql_byte((void*)&(rline->haval),db,db_haval, conf);
  db_readline_sql_byte((void*)&(rline->gost),db,db_gost, conf);
#endif
  db_readline_sql_char((void*)&(rline->fullpath),db,db_filename, conf);
  rline->filename=rline->fullpath;
  db_readline_sql_char((void*)&(rline->linkname),db,db_linkname, conf);
  
  db_readline_sql_int((void*)&(rline->perm),db,db_perm, conf);
  db_readline_sql_int((void*)&(rline->uid),db,db_uid, conf);
  db_readline_sql_int((void*)&(rline->gid),db,db_gid, conf);
  db_readline_sql_int((void*)&(rline->inode),db,db_inode, conf);
  db_readline_sql_int((void*)&(rline->nlink),db,db_lnkcount, conf);
  
  db_readline_sql_int((void*)&(rline->size),db,*db_osize, conf);
  db_readline_sql_int((void*)&(rline->bcount),db,db_bcount, conf);
  db_readline_sql_int((void*)&(rline->attr),db,db_attr, conf);
  
  db_readline_sql_time((void*)&(rline->atime),db,db_atime, conf);
  db_readline_sql_time((void*)&(rline->ctime),db,db_ctime, conf);
  db_readline_sql_time((void*)&(rline->mtime),db,db_mtime, conf);
#ifdef WITH_ACL
  rline->acl=NULL;
#endif
  ((psql_data*)(*db_filep))->curread++;
  
  error(255,"filename %s\n",rline->filename);
  
  return rline;
}


void sql_writeint(int data,char *s,int i){
  char t[10];
  t[0]=0;
  if (i!=0) {
    s = strcat(s,",");
  }
  sprintf(t,"%i",data);
  
  strcat(s,t);
  
}

void sql_writeoct(int data,char *s,int i){
  char t[10];
  t[0]=0;
  if (i!=0) {
    s = strcat(s,",");
  }
  sprintf(t,"%lo",data);
  
  strcat(s,t);
  
}

void sql_write_time_base64(time_t data,char* s,int i){
  static char* ptr=NULL;
  char* tmpstr=NULL;
  int retval=0;
  
  if(i!=0){
    strcat(s,",");
  }
  
  if(data==0){
    strcat(s,"''");
    return;
  }


  ptr=(char*)malloc(sizeof(char)*TIMEBUFSIZE);
  if (ptr==NULL) {
    error(0,"\nCannot allocate memory..\n");
    abort();
  }
  
  memset((void*)ptr,0,sizeof(char)*TIMEBUFSIZE);

  sprintf(ptr,"%li",data);


  tmpstr=encode_base64(ptr,strlen(ptr));
  strcat(s,"'");
  strcat(s,tmpstr);
  strcat(s,"'");

  free(tmpstr);
  free(ptr);
  
  return;
  
}

void sql_write_byte_base64(byte*data,size_t len,char* s,int i )
{
  char* tmpstr=NULL;
  int retval=0;
  
  tmpstr=encode_base64(data,len);
  if(i){
    strcat(s,",");
  }
  
  strcat(s,"'");
  
  if(tmpstr){
    strcat(s,tmpstr);
    free(tmpstr);
  }else {
    /* Do nothing.. */
  }
  
  strcat(s,"'");
  return;
}


char* db_get_sql(db_line* line,db_config* conf){
  
  int i;
  char* s=(char*) malloc(sizeof(char)*10240); /* FIXME .. */

  if (s==NULL) {
    error(0,"\nCannot allocate memory..\n");
    abort();
  }
  
  s[0]=0;

  /* Insertion was hardcoded into aide-table, now we will use the
     provided name from the configfile */
  
  s = strcat(s,"INSERT INTO ");
  s = strcat(s, ((psql_data*)conf->db_out)->table);
  s = strcat(s," values(");
  
  for(i=0;i<conf->db_out_size;i++){
    switch (conf->db_out_order[i]) {
    case db_filename : {
      char* tmp;
      if ( i!=0 ) {
	s = strcat(s,",");
      }
      strcat(s,"'");
      tmp=encode_string(line->filename);
      s = strcat(s,tmp);
      free(tmp);
      strcat(s,"'");
      break;
    }
    case db_linkname : {
      if ( i!=0 ) {
	s = strcat(s,",");
      }
      strcat(s,"'");
      if (line->linkname != NULL) {
	char* tmp;
	tmp=encode_string(line->linkname);
	s = strcat(s,tmp);
	free(tmp);
      }
      strcat(s,"'");
      break;
    }  
    case db_attr : {
      sql_writeint(line->attr,s,i);
      break;
    }
    case db_bcount : {
      sql_writeint(line->bcount,s,i);
      break;
    }
    
    case db_mtime : {
      sql_write_time_base64(line->mtime,s,i);
      break;
    }
    case db_atime : {
      sql_write_time_base64(line->atime,s,i);
      break;
    }
    case db_ctime : {
      sql_write_time_base64(line->ctime,s,i);
      break;
    }
    case db_inode : {
      sql_writeint(line->inode,s,i);
      break;
    }
    case db_lnkcount : {
      sql_writeint(line->nlink,s,i);
      break;
    }
    case db_uid : {
      sql_writeint(line->uid,s,i);
      break;
    }
    case db_gid : {
      sql_writeint(line->gid,s,i);
      break;
    }
    case db_size : {
      sql_writeint(line->size,s,i);
      break;
    }
    case db_md5 : {
      sql_write_byte_base64(line->md5,
			   gcry_md_get_algo_dlen(GCRY_MD_MD5),s,i);
      break;
    }
    case db_sha1 : {
      sql_write_byte_base64(line->sha1,
			   gcry_md_get_algo_dlen(GCRY_MD_SHA1),s,i);
      break;
    }
    case db_rmd160 : {
      sql_write_byte_base64(line->rmd160,
			   gcry_md_get_algo_dlen(GCRY_MD_RMD160),
			   s,i);
      break;
    }
    case db_tiger : {
      sql_write_byte_base64(line->tiger,
			   gcry_md_get_algo_dlen(GCRY_MD_TIGER),
			   s,i);
      break;
    }
    case db_perm : {
      sql_writeoct(line->perm,s,i);
      break;
    }
#ifdef WITH_MHASH
    case db_crc32 : {
      sql_write_byte_base64(line->crc32,
			   mhash_get_block_size(MHASH_CRC32),
			   s,i);
      break;
    }
    case db_crc32b : {
      sql_write_byte_base64(line->crc32b,
			   mhash_get_block_size(MHASH_CRC32B),
			   s,i);
      break;
    }
    case db_haval : {
      sql_write_byte_base64(line->haval,
			   mhash_get_block_size(MHASH_HAVAL256),
			   s,i);
      break;
    }
    case db_gost : {
      sql_write_byte_base64(line->gost ,
			   mhash_get_block_size(MHASH_GOST),
			   s,i);
      break;
    }
#endif
    case db_acl : {
      error(0,"TODO db_acl write to db_sql.c");
      /* TODO */
      break;
    }
    case db_xattrs : {
      error(0,"TODO db_xattrs write to db_sql.c");
      /* TODO */
      break;
    }
    case db_checkmask : {
      sql_writeoct(line->attr,s,i);
      break;
    }
    default : {
      error(0,"Not implemented in sql_writeline_file %i\n",
	    conf->db_out_order[i]);
      return NULL;
    }
    
    }
    
  }

  strcat(s,");");

  return s;
}

int db_close_sql(void* db){
  
  PQexec(((psql_data*)db)->conn,"commit");
  
  PQfinish(((psql_data*)db)->conn);

  return RETOK;
  
}

#endif
