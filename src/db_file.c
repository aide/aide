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
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <errno.h>

#include "types.h"
#include "base64.h"
#include "db_file.h"
#include "conf_yacc.h"
#include "util.h"
#include "db_sql.h" /* typedefs */
#include "commandconf.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#define BUFSIZE 16384

#include "md.h"

#ifdef WITH_ZLIB
#define ZBUFSIZE 16384


/* FIXME get rid of this */
void handle_gzipped_input(int out,gzFile* gzp){

  int nread=0;
  int err=0;
  int* buf=malloc(ZBUFSIZE);
  buf[0]='\0';
  error(200,"handle_gzipped_input(),%d\n",out);
  while(!gzeof(*gzp)){
    if((nread=gzread(*gzp,buf,ZBUFSIZE))<0){
      error(0,_("gzread() failed:gzerr=%s!\n"),gzerror(*gzp,&err));
      exit(1);
    } else {
      /* gzread returns 0 even if uncompressed bytes were read*/
      if(nread==0){
	write(out, buf,strlen((char*)buf));
      } else {
	write(out, buf,nread);
      }
      error(240,"nread=%d,strlen(buf)=%d,errno=%s,gzerr=%s\n",
	    nread,strlen((char*)buf),strerror(errno),
	    gzerror(*gzp,&err));
      buf[0]='\0';
    }
  }
  close(out);
  error(240,"handle_gzipped_input() exiting\n");
  exit(0);
  /* NOT REACHED */
  return;
}
#endif


int dofflush(void)
{

  int retval;
#ifdef WITH_ZLIB
  if(conf->gzip_dbout){
    /* Should not flush using gzip, it degrades compression */
    retval=Z_OK;
  }else {
#endif
    retval=fflush(conf->db_out); 
#ifdef WITH_ZLIB
  }
#endif

  return retval;
}

int dofprintf( const char* s,...)
{
  char buf[3];
  int retval;
  char* temp=NULL;
  va_list ap;
  
  va_start(ap,s);
  retval=vsnprintf(buf,3,s,ap);
  va_end(ap);
  
  temp=(char*)malloc(retval+2);
  if(temp==NULL){
    error(0,"Unable to alloc %i bytes\n",retval+2);
    return -1;
  }  
  va_start(ap,s);
  retval=vsnprintf(temp,retval+1,s,ap);
  va_end(ap);
  
#ifdef WITH_MHASH
  if(conf->do_dbnewmd)
    mhash(conf->dbnewmd,(void*)temp,retval);
#endif

#ifdef WITH_ZLIB
  if(conf->gzip_dbout){
    retval=gzwrite(conf->db_gzout,temp,retval);
  }else{
#endif
    va_start(ap,s);
    retval=vfprintf(conf->db_out,s,ap);
    va_end(ap);
#ifdef WITH_ZLIB
  }
#endif
  free(temp);

  return retval;
}



int db_file_read_spec(int db){
  
  int i=0;
  int* db_osize=0;
  DB_FIELD** db_order=NULL;
  FILE** db_filep=NULL;
  url_t* db_url=NULL;
#ifdef WITH_ZLIB
  gzFile* db_gzp=NULL;
#endif

  switch (db) {
  case DB_OLD: {
    db_osize=&(conf->db_in_size);
    db_order=&(conf->db_in_order);
    db_filep=&(conf->db_in);
    db_url=conf->db_in_url;
    db_lineno=&db_in_lineno;
#ifdef WITH_ZLIB
    db_gzp=&(conf->db_gzin);
#endif
    break;
  }
  case DB_NEW: {
    db_osize=&(conf->db_new_size);
    db_order=&(conf->db_new_order);
    db_filep=&(conf->db_new);
    db_url=conf->db_new_url;
    db_lineno=&db_new_lineno;
#ifdef WITH_ZLIB
    db_gzp=&(conf->db_gznew);
#endif
    break;
  }
  }

  *db_order=(DB_FIELD*) malloc(1*sizeof(DB_FIELD));
  
  while ((i=db_scan())!=TNEWLINE){
    switch (i) {
      
    case TID : {
      int l;
      

      /* Yes... we do not check if realloc returns nonnull */

      *db_order=(DB_FIELD*)
	realloc((void*)*db_order,
		((*db_osize)+1)*sizeof(DB_FIELD));
      
      if(*db_order==NULL){
	return RETFAIL;
      }
      
      (*db_order)[*db_osize]=db_unknown;
      
      for (l=0;l<db_unknown;l++){
	
	if (strcmp(db_names[l],dbtext)==0) {
	  
	  if (check_db_order(*db_order, *db_osize,
			     db_value[l])==RETFAIL) {
	    error(0,"Field %s redefined in @@dbspec\n",dbtext);
	    (*db_order)[*db_osize]=db_unknown;
	  } else {
	    (*db_order)[*db_osize]=db_value[l];
	  }
	  (*db_osize)++;
	  break;
	}
      }
      for (l=0;l<db_alias_size;l++){
	
	if (strcmp(db_namealias[l],dbtext)==0) {
	  
	  if (check_db_order(*db_order, *db_osize,
			     db_aliasvalue[l])==RETFAIL) {
	    error(0,"Field %s redefined in @@dbspec\n",dbtext);
	    (*db_order)[*db_osize]=db_unknown;
	  } else {
	    (*db_order)[*db_osize]=db_aliasvalue[l];
	  }
	  (*db_osize)++;
	  break;
	}
      }
      if(l==db_unknown){
	error(0,"Unknown field %s in database\n",dbtext);
	(*db_osize)++;
      }
      break;
    }
    
    case TDBSPEC : {
      error(0,"Only one @@dbspec in input database.\n");
      return RETFAIL;
      break;
    }
    
    default : {
      error(0,"Aide internal error while reading input database.\n");
      return RETFAIL;
    }
    }
  }

  /* Lets generate attr from db_order if database does not have attr */
  conf->attr=-1;

  for (i=0;i<*db_osize;i++) {
    if ((*db_order)[i]==db_attr) {
      conf->attr=1;
    }
  }
  if (conf->attr==-1) {
    conf->attr=0;
    error(0,"Database does not have attr field.\nComparation may be incorrect\nGenerating attr-field from dbspec\nIt might be a good Idea to regenerate databases. Sorry.\n");
    for(i=0;i<conf->db_in_size;i++) {
      conf->attr|=1<<(*db_order)[i];
    }
  }
  return RETOK;
}

char** db_readline_file(int db){
  
  char** s=NULL;
  
  int i=0;
  int r;
  int a=0;
  int token=0;
  int gotbegin_db=0;
  int gotend_db=0;
  int* domd=NULL;
  MHASH* md=NULL;
  char** oldmdstr=NULL;
  int* db_osize=0;
  DB_FIELD** db_order=NULL;
  FILE** db_filep=NULL;
  url_t* db_url=NULL;
#ifdef WITH_ZLIB
  gzFile* db_gzp=NULL;
#endif

  switch (db) {
  case DB_OLD: {
    md=&(conf->dboldmd);
    domd=&(conf->do_dboldmd);
    oldmdstr=&(conf->old_dboldmdstr);
    db_osize=&(conf->db_in_size);
    db_order=&(conf->db_in_order);
    db_filep=&(conf->db_in);
    db_url=conf->db_in_url;
    db_lineno=&db_in_lineno;
#ifdef WITH_ZLIB
    db_gzp=&(conf->db_gzin);
#endif
    break;
  }
  case DB_NEW: {
    md=&(conf->dbnewmd);
    domd=&(conf->do_dbnewmd);
    oldmdstr=&(conf->old_dbnewmdstr);
    db_osize=&(conf->db_new_size);
    db_order=&(conf->db_new_order);
    db_filep=&(conf->db_new);
    db_url=conf->db_new_url;
    db_lineno=&db_new_lineno;
#ifdef WITH_ZLIB
    db_gzp=&(conf->db_gznew);
#endif
    break;
  }
  }
  
  if (*db_osize==0) {
    db_buff(db,*db_filep);
    
    token=db_scan();
    while((token!=TDBSPEC)){

      switch(token){
      case TUNKNOWN: {
	continue;
	break;
      }
      case TBEGIN_DB: {
	token=db_scan();
	gotbegin_db=1;
	continue;
	break;
      }
      case TNEWLINE: {
	if(gotbegin_db){
	  *domd=1;
	  token=db_scan();
	  continue;
	}else {
	  token=TEOF;
	  break;
	}
      }
      case TGZIPHEADER: {
	error(0,"Gzipheader found inside uncompressed db!\n");
	return NULL;
	break;
      }
      default: {
	/* If it is anything else we quit */
	/* Missing dbspec */
	token=TEOF;
	break;
      }
      }
      if(token==TEOF){
	break;
      }

      token=db_scan();
    }

    if(FORCEDBMD&&!gotbegin_db){
      error(0,"Database %i does not have checksum!\n");
      return NULL;
    }

    if (token!=TDBSPEC) {
      /*
       * error.. must be a @@dbspec line
       */
      
      switch (db_url->type) {
      case url_file : {
	error(0,"File database must have one db_spec specification\n");
	break;
      }

      case url_stdin : {
	error(0,"Pipe database must have one db_spec specification\n");
	break;
      }

      case url_fd: {
	error(0,"FD database must have one db_spec specification\n");
	break;
      }

      default : {
	error(0,"db_readline_file():Unknown or unsupported db in type.\n");
	
	break;
      }
      
      }
      return s;
    }
    
    /*
     * Here we read da spec
     */
    
    if (db_file_read_spec(db)!=0) {
      /* somethin went wrong */
      return s;
    }
    
  }else {
    /* We need to switch the buffer cleanly*/
    db_buff(db,NULL);
  }

  s=(char**)malloc(sizeof(char*)*db_unknown);

  /* We NEED this to avoid Bus errors on Suns */
  for(i=0;i<db_unknown;i++){
    s[i]=NULL;
  }
  
  for(i=0;i<*db_osize;i++){
    switch (r=db_scan()) {
      
    case TDBSPEC : {
      
      error(0,"Database file can have only one db_spec.\nTrying to continue on line %i\n",*db_lineno);      
      break;
    }
    case TNAME : {
      if ((*db_order)[i]!=db_unknown) {
	s[*db_order[i]]=(char*)strdup(dbtext);
      }
      break;
    }
    
    case TID : {
      if ((*db_order)[i]!=db_unknown) {
	s[(*db_order)[i]]=(char*)strdup(dbtext);
      }
      break;
    }
    
    case TNEWLINE : {
      
      if (i==0) {
	i--;
	break;
      }
      if(gotend_db){
	return NULL;
      }
      /*  */

      error(0,"Not enough parameters in db:%i. Trying to continue.\n",
	    *db_lineno);
      for(a=0;a<i;a++){
	free(s[(*db_order)[a]]);
	s[(*db_order)[a]]=NULL;
      }
      i=0;
      break;

    }

    case TBEGIN_DB : {
      error(0,_("Corrupt db. Found @@begin_db inside db. Please check\n"));
      return NULL;
      break;
    }

    case TEND_DB : {
      gotend_db=1;
      token=db_scan();
      if(token!=TSTRING){
	error(0,_("Corrupt db. Checksum garbled\n"));
	abort();
      } else {
	if(*md){
	  byte* dig=NULL;
	  char* digstr=NULL;
	  
	  *oldmdstr=strdup(dbtext);
	  
	  mhash(*md,NULL,0);
	  dig=(byte*)
	    malloc(sizeof(byte)*mhash_get_block_size(conf->dbhmactype));
	  mhash_deinit(*md,(void*)dig);
	  digstr=encode_base64(dig,mhash_get_block_size(conf->dbhmactype));
	  if(strncmp(digstr,*oldmdstr,strlen(digstr))!=0){
	    error(0,_("Db checksum mismatch for db:%i\n"),db);
	    abort();
	  }
	}else {
	  error(0,"@@end_db found without @@begin_db in db:%i\n",db);
	  abort();
	}
      }
      token=db_scan();
      if(token!=TNEWLINE){
	error(0,_("Corrupt db. Checksum garbled\n"));
	abort();
      }	
      break;
    }

    case TEND_DBNOMD : {
      gotend_db=1;
      break;
    }

    case TEOF : {
      if(gotend_db){
	return NULL;
      }	
      /* This can be the first token on a line */
      if(i>0){
	error(0,"Not enough parameters in db:%i\n",*db_lineno);
      };
      for(a=0;a<i;a++){
	free(s[(*db_order)[a]]);
      }
      free(s);
      return NULL;
      break;
    }
    case TERROR : {
      error(0,"There was an error in the database file on line:%i.\n",*db_lineno);
      break;
    }
    
    default : {
      
      error(0,"Not implemented in db_readline_file %i\n\"%s\"",r,dbtext);
      
      free(s);
      s=NULL;
      i=*db_osize;
      break;
    }
    }
    
  }
  

  /*
   * If we don't get newline after reading all sells we print an error
   */
  a=db_scan();

  if (a!=TNEWLINE&&a!=TEOF) {
    error(0,"Newline expected in database. Readin until end of line\n");
    do {
      
      error(0,"Skipped value %s\n",dbtext);
      
      /*
       * Null statement
       */ 
      a=db_scan();
    }while(a!=TNEWLINE&&a!=TEOF);
    
  }
  
  return s;
  
}

int db_writechar(char* s,FILE* file,int i)
{
  char* r=NULL;
  int retval=0;

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

int db_writeint(long i,FILE* file,int a)
{
  if(a) {
    dofprintf(" ");
  }
  
  return dofprintf("%li",i);
  
}
int db_writelong(unsigned long long i,FILE* file,int a)
{
  if(a) {
    dofprintf(" ");
  }
  
  return dofprintf("%lli",i);
  
}

int db_write_byte_base64(byte*data,size_t len,FILE* file,int i,int th,
			 int attr )
{
  char* tmpstr=NULL;
  int retval=0;
  
  
  if (data!=NULL&&th&attr) {
    tmpstr=encode_base64(data,len);
  } else {
    tmpstr=NULL;
  }
  if(i){
    dofprintf(" ");
  }

  if(tmpstr){
    retval=dofprintf(tmpstr);
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

  if(a){
    dofprintf(" ");
  }

  if(i==0){
    retval=dofprintf("0");
    return retval;
  }


  ptr=(char*)malloc(sizeof(char)*TIMEBUFSIZE);
  if (ptr==NULL) {
    error(0,"\nCannot allocate memory.\n");
    abort();
  }
  memset((void*)ptr,0,sizeof(char)*TIMEBUFSIZE);

  sprintf(ptr,"%li",i);


  tmpstr=encode_base64(ptr,strlen(ptr));
  retval=dofprintf(tmpstr);
  free(tmpstr);
  free(ptr);

  return retval;

}

int db_writeoct(long i, FILE* file,int a)
{
  if(a) {
    dofprintf(" ");
  }
  
  return dofprintf("%lo",i);
  
}

int db_writespec_file(db_config* conf)
{
  int i=0;
  int j=0;
  int retval=1;
  void*key=NULL;
  int keylen=0;
  struct tm* st;
  time_t tim=time(&tim);
  st=localtime(&tim);

  retval=dofprintf("@@begin_db\n");
  if(retval==0){
    return RETFAIL;
  }

#ifdef WITH_MHASH
  /* From hereon everything must MD'd before write to db */
  if((key=get_db_key())!=NULL){
    keylen=get_db_key_len();
    conf->do_dbnewmd=1;
    if( (conf->dbnewmd=
	 mhash_hmac_init(conf->dbhmactype,
			 key,
			 keylen,
			 mhash_get_hash_pblock(conf->dbhmactype)))==
	MHASH_FAILED){
      error(0, "mhash_hmac_init() failed for db write. Aborting\n");
      abort();
    }
  }
  
  
#endif

  retval=dofprintf(
		 "# This file was generated by Aide, version %s\n"
		 "# Time of generation was %.4u-%.2u-%.2u %.2u:%.2u:%.2u\n",
		 AIDEVERSION,
		 st->tm_year+1900, st->tm_mon+1, st->tm_mday,
		 st->tm_hour, st->tm_min, st->tm_sec
		 );
  if(retval==0){
    return RETFAIL;
  }
  if(conf->config_version){
    retval=dofprintf(
		     "# The config version used to generate this file was:\n"
		     "# %s\n", conf->config_version);
    if(retval==0){
      return RETFAIL;
    }
  }
  retval=dofprintf("@@db_spec ");
  if(retval==0){
    return RETFAIL;
  }
  for(i=0;i<conf->db_out_size;i++){
    for(j=0;j<db_unknown;j++){
      if(db_value[j]==conf->db_out_order[i]){
	retval=dofprintf("%s ",db_names[j]);
	if(retval==0){
	  return RETFAIL;
	}
	break;
      }
    }
  }
  retval=dofprintf("\n");
  if(retval==0){
    return RETFAIL;
  }
  return RETOK;
}

#ifdef WITH_SUN_ACL
int db_writeacl(acl_type* acl,FILE* file,int a){
  int i;

  if(a) {
    dofprintf(" ");
  }
  
  if (acl==NULL) {
    dofprintf("0");
  } else {
    
    dofprintf("%i",acl->entries);
    
    for (i=0;i<acl->entries;i++) {
      dofprintf(",%i,%i,%i", acl->acl[i].a_type, acl->acl[i].a_id,
	      acl->acl[i].a_perm);
    }
  }
  return RETOK;
}
#endif

int db_writeline_file(db_line* line,db_config* conf){
  int i;

  for(i=0;i<conf->db_out_size;i++){
    switch (conf->db_out_order[i]) {
    case db_filename : {
      db_writechar(line->filename,conf->db_out,i);
      break;
    }
    case db_linkname : {
      db_writechar(line->linkname,conf->db_out,i);
      break;
    }
    case db_bcount : {
      db_writeint(line->bcount,conf->db_out,i);
      break;
    }

    case db_mtime : {
      db_write_time_base64(line->mtime,conf->db_out,i);
      break;
    }
    case db_atime : {
      db_write_time_base64(line->atime,conf->db_out,i);
      break;
    }
    case db_ctime : {
      db_write_time_base64(line->ctime,conf->db_out,i);
      break;
    }
    case db_inode : {
      db_writeint(line->inode,conf->db_out,i);
      break;
    }
    case db_lnkcount : {
      db_writeint(line->nlink,conf->db_out,i);
      break;
    }
    case db_uid : {
      db_writeint(line->uid,conf->db_out,i);
      break;
    }
    case db_gid : {
      db_writeint(line->gid,conf->db_out,i);
      break;
    }
    case db_size : {
      db_writelong(line->size,conf->db_out,i);
      break;
    }
    case db_md5 : {
      db_write_byte_base64(line->md5,
			   HASH_MD5_LEN,
			   conf->db_out,i,
			   DB_MD5,line->attr);
	
      break;
    }
    case db_sha1 : {
      db_write_byte_base64(line->sha1,
			   HASH_SHA1_LEN,
			   conf->db_out,i,
			   DB_SHA1,line->attr);

      break;
    }
    case db_rmd160 : {
      db_write_byte_base64(line->rmd160,
			   HASH_RMD160_LEN,
			   conf->db_out,i,
			   DB_RMD160,line->attr);
      break;
    }
    case db_tiger : {
      db_write_byte_base64(line->tiger,
			   HASH_TIGER_LEN,
			   conf->db_out,i,
			   DB_TIGER,line->attr);
      break;
    }
    case db_perm : {
      db_writeoct(line->perm,conf->db_out,i);
      break;
    }
    case db_crc32 : {
      db_write_byte_base64(line->crc32,
			   HASH_CRC32_LEN,
			   conf->db_out,i,
			   DB_CRC32,line->attr);
      break;
    }
    case db_crc32b : {
      db_write_byte_base64(line->crc32b,
			   HASH_CRC32B_LEN,
			   conf->db_out,i,
			   DB_CRC32B,line->attr);
      break;
    }
    case db_haval : {
      db_write_byte_base64(line->haval,
			   HASH_HAVAL256_LEN,
			   conf->db_out,i,
			   DB_HAVAL,line->attr);
      break;
    }
    case db_gost : {
      db_write_byte_base64(line->gost ,
			   HASH_GOST_LEN,
			   conf->db_out,i,
			   DB_GOST,line->attr);
      break;
    }
    case db_attr : {
      db_writeint(line->attr,
		  conf->db_out,i);
      break;
    }
#ifdef WITH_ACL
    case db_acl : {
      db_writeacl(line->acl,conf->db_out,i);
      break;
    }
#endif
    case db_checkmask : {
      db_writeoct(line->attr,conf->db_out,i);
      break;
    }
    default : {
      error(0,"Not implemented in db_writeline_file %i\n",
	    conf->db_out_order[i]);
      return RETFAIL;
    }
    
    }
    
  }

  dofprintf("\n");
  /* Can't use fflush because of zlib.*/
  dofflush();

  return RETOK;
}

int db_close_file(db_config* conf){
  
#ifdef WITH_MHASH
  byte* dig=NULL;
  char* digstr=NULL;

  if(conf->db_out
#ifdef WITH_ZLIB
     || conf->db_gzout
#endif
     ){

    /* Let's write @@end_db <checksum> */
    if (conf->dbnewmd!=NULL) {
      mhash(conf->dbnewmd, NULL ,0);
      dig=(byte*)malloc(sizeof(byte)*mhash_get_block_size(conf->dbhmactype));
      mhash_deinit(conf->dbnewmd,(void*)dig);
      digstr=encode_base64(dig,mhash_get_block_size(conf->dbhmactype));
      conf->do_dbnewmd=0;
      dofprintf("@@end_db %s\n",digstr);
      free(dig);
      free(digstr);
    } else {
      dofprintf("@@end_db\n");
    }
  }
#endif

#ifndef WITH_ZLIB
  if(fclose(conf->db_out)){
    error(0,"Unable to close database:%s\n",strerror(errno));
    return RETFAIL;
  }
#else
  if(conf->gzip_dbout){
    if(gzclose(conf->db_gzout)){
      error(0,"Unable to close gzdatabase:%s\n",strerror(errno));
      return RETFAIL;
    }
  }else {
    if(fclose(conf->db_out)){
      error(0,"Unable to close database:%s\n",strerror(errno));
      return RETFAIL;
    }
  }
#endif

  return RETOK;
}
/*
const char* aide_key_11=CONFHMACKEY_11;
*/
