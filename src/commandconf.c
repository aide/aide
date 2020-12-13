/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2010,2011,2013,2015,2016,2019,2020 Rami Lehti, Pablo
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

#include "aide.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>

#include "commandconf.h"
#include "conf_lex.h"
#include "conf_yacc.h"
#include "db.h"
#include "db_config.h"
#include "gen_list.h"
#include "symboltable.h"
#include "md.h"
#include "util.h"
#include "base64.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/
#ifdef WITH_CURL
#include "fopen.h"
#endif

#define BUFSIZE 4096
#define ZBUFSIZE 16384

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

int commandconf(const char mode,const char* line)
{
  static char* before=NULL;
  static char* config=NULL;
  static char* after=NULL;
  char* all=NULL;
  char* tmp=NULL;
  int l=0;

  switch(mode){
  case 'B':{
    if(before==NULL){
      before=strdup(line);
    }
    else {
      tmp=(char*)malloc(sizeof(char)
			*(strlen(before)+strlen(line)+2));
      tmp[0]='\0';
      strcat(tmp,before);
      strcat(tmp,"\n");
      strcat(tmp,line);
      free(before);
      before=tmp;
    }
    break;
  }
  case 'C':{
    config=strdup(line);
    break;
  }
  case 'A':{
    if(after==NULL){
      after=strdup(line);
    }
    else {
      tmp=(char*)malloc(sizeof(char)
			*(strlen(after)+strlen(line)+2));
      strcpy(tmp,after);
      strcat(tmp,"\n");
      strcat(tmp,line);
      free(after);
      after=tmp;
    }
    break;
  }
  case 'D': {
    /* Let's do it */
    int rv=-1;

    config = expand_tilde(config);
    if (config!=NULL && strcmp(config,"-")==0) {
      error(255,_("Config from stdin\n"));
      rv=0;
    } else {
      
      rv=access(config,R_OK);
      if(rv==-1){
	error(0,_("Cannot access config file: %s: %s\n"),config,strerror(errno));
      }
    }
    
    if(before==NULL&&after==NULL&&
       (config==NULL||strcmp(config,"")==0||rv==-1)){
      error(0,_("No config defined\n"));
      return RETFAIL;
    }
    if(before!=NULL) {
      l+=strlen(before);
    }
    if(config!=NULL) {
      l+=strlen(config);
    }
    if(after!=NULL) {
      l+=strlen(after);
    }
    l+=strlen("@@include \n\n\n")+1;
    
    all=(char*)malloc(sizeof(char)*l);

    memset(all,0,l);
    if(before!=NULL){
      strcat(all,before);
      strcat(all,"\n");
    }
    strcat(all,"@@include ");
    strcat(all,config);
    strcat(all,"\n");
    if(after!=NULL){
      strcat(all,after);
      strcat(all,"\n");
    }
    
    error(200,"commandconf():%s\n",all);
    
    conf_scan_string(all);
    
    if(confparse()){
      free(all);
      return RETFAIL;
    }
    free(all);
    
    break;
  }
  default: {
    error(0,_("Illegal argument %c to commmandconf()\n"),mode);
    break;
  }
  }
  return RETOK;
}

int conf_input_wrapper(char* buf, int max_size, FILE* in)
{
  int retval=0;

  /* FIXME Add support for gzipped config. :) */
#ifdef WITH_MHASH
  int c=0;
  /* Read a character at a time until we are doing md */
  if(conf->do_configmd){
    retval=fread(buf,1,max_size,in);
  }else {
    c=fgetc(in);
    retval= (c==EOF) ? 0 : (buf[0] = c,1);
  }
#else
  retval=fread(buf,1,max_size,in);
#endif 

#ifdef WITH_MHASH    
  char* tmp=NULL;
  void* key=NULL;
  int keylen=0;
  if(conf->do_configmd||conf->config_check){
    if(((conf->do_configmd==1)&&conf->config_check)||!conf->confmd){
      if(conf->do_configmd==1){
	conf->do_configmd+=1;
      }
      if((key=get_conf_key())!=NULL){
	keylen=get_conf_key_len();
	
	if( (conf->confmd=
	     mhash_hmac_init(conf->confhmactype,
			     key,
			     keylen,
			     mhash_get_hash_pblock(conf->confhmactype)))==
	    MHASH_FAILED){
	  error(0, "mhash_hmac_init() failed for %i for config check. Aborting\n",
		conf->confhmactype);
	  exit(EXIT_FAILURE);
	}
      } else {
	conf->do_configmd=0;
	return retval;
      }
    }
    /* FIXME This does not handle the case that @@end_config is on 
       buffer boundary. */
    if((tmp=strnstr(buf,"@@end_config",retval))!=NULL){
      /* We have end of config don't feed the last line to mhash */
      mhash(conf->confmd,(void*)buf,tmp-buf);
    } else {
      mhash(conf->confmd,(void*)buf,retval);
    }
  }
#endif
  return retval;
}

int db_input_wrapper(char* buf, int max_size, int db)
{
  int retval=0;
  int c=0;
  int err=0;
  int* domd=NULL;
#ifdef WITH_CURL
  url_t* db_url=NULL;
#endif
#ifdef WITH_MHASH
  char* tmp=NULL;
  MHASH* md=NULL;
  void* key=NULL;
  int keylen;
#endif
  FILE* db_filep=NULL;
#ifdef WITH_ZLIB
  gzFile* db_gzp=NULL;
#endif
  struct md_container *mdc;
  switch(db) {
  case DB_OLD: {
#ifdef WITH_CURL
    db_url=conf->db_in_url;
#endif
    
    domd=&(conf->do_dboldmd);
#ifdef WITH_MHASH
    md=&(conf->dboldmd);
#endif
    
    db_filep=conf->db_in;
    
#ifdef WITH_ZLIB
    db_gzp=&(conf->db_gzin);
#endif
    break;
  }
  case DB_NEW: {
#ifdef WITH_CURL
    db_url=conf->db_new_url;
#endif
    
    domd=&(conf->do_dbnewmd);
#ifdef WITH_MHASH
    md=&(conf->dbnewmd);
#endif
    
    db_filep=conf->db_new;
    
#ifdef WITH_ZLIB
    db_gzp=&(conf->db_gznew);
#endif
    break;
  }
  }

#ifdef WITH_CURL
  switch (db_url->type) {
  case url_http:
  case url_https:
  case url_ftp: {
    retval=url_fread(buf,1,max_size,(URL_FILE *)db_filep);
    if ((mdc = (db == DB_OLD ? conf->mdc_in : conf->mdc_out))) {
        update_md(mdc, buf, retval);
    }
    break;
  } 
  default:
#endif /* WITH CURL */


  /* Read a character at a time until we are doing md */
#ifdef WITH_ZLIB
  if((*db_gzp==NULL)&&(*domd)){
    retval=fread(buf,1,max_size,db_filep);
  }
  if((*db_gzp!=NULL)&&(*domd)){
    if(gzeof(*db_gzp)){
      retval=0;
      buf[0]='\0';
    }else {
      if((retval=gzread(*db_gzp,buf,max_size))<0){
	error(0,_("gzread() failed: gzerr=%s!\n"),gzerror(*db_gzp,&err));
	retval=0;
	buf[0]='\0';
      } else {
	/* gzread returns 0 even if uncompressed bytes were read*/
	error(240,"nread=%d,strlen(buf)=%lu,errno=%s,gzerr=%s\n",
              retval,(unsigned long)strnlen((char*)buf, max_size),
              strerror(errno),gzerror(*db_gzp,&err));
	if(retval==0){
	  retval=strnlen((char*)buf, max_size);
	}
      }
    }
  }
  if((*db_gzp!=NULL)&&!(*domd)){
    c=gzgetc(*db_gzp);
    retval= (c==EOF) ? 0 : (buf[0] = c,1);
  }
  if((*db_gzp==NULL)&&!(*domd)){
    c=fgetc(db_filep);
    if(c==(unsigned char)'\037'){
      c=fgetc(db_filep);
      if(c==(unsigned char)'\213'){
	/* We got gzip header. */
	error(255,"Got Gzip header. Handling..\n");
	lseek(fileno(db_filep),0L,SEEK_SET);
	*db_gzp=gzdopen(fileno(db_filep),"rb");
	c=gzgetc(*db_gzp);
	error(255,"First character after gzip header is: %c(%#X)\n",c,c);
  if(c==-1) {
    int xx;
	  error(0,"Error reading gzipped file: %s\n",gzerror(*db_gzp,&xx));
    exit(EXIT_FAILURE);
  }
      }else {
	/* False alarm */
	ungetc(c,db_filep);
      }
    }
    retval= (c==EOF) ? 0 : (buf[0] = c,1);
  }

#else /* WITH_ZLIB */
#ifdef WITH_MHASH
  if(*domd){
    retval=fread(buf,1,max_size,db_filep);
  }else {
    c=fgetc(db_filep);
    retval= (c==EOF) ? 0 : (buf[0] = c,1);
  }
#else /* WITH_MHASH */
  retval=fread(buf,1,max_size,db_filep);
#endif /* WITH_MHASH */ 
#endif /* WITH_ZLIB */

  if ((mdc = (db == DB_OLD ? conf->mdc_in : conf->mdc_out))) {
      update_md(mdc, buf, retval);
  }

#ifdef WITH_MHASH    
  if(*domd){
    if(!*md){
      if((key=get_db_key())!=NULL){
	keylen=get_db_key_len();
	
	if( (*md=
	     mhash_hmac_init(conf->dbhmactype,
			     key,
			     keylen,
			     mhash_get_hash_pblock(conf->dbhmactype)))==
	    MHASH_FAILED){
	  error(0, "mhash_hmac_init() failed for db check. Aborting\n");
	  exit(EXIT_FAILURE);
	}
      } else {
	*domd=0;
      }
    }
    /* FIXME This does not handle the case that @@end_config is on 
       buffer boundary. */
    if (*domd!=0) {
      if((tmp=strnstr(buf,"@@end_db",retval))!=NULL){
	/* We have end of db don't feed the last line to mhash */
	mhash(*md,(void*)buf,tmp-buf);
	/* We don't want to come here again after the *md has been deinited 
	   by db_readline_file() */
	*domd=0;
      } else {
	mhash(*md,(void*)buf,retval);
      }
    }
  }
#endif

#ifdef WITH_CURL
  }
#endif /* WITH CURL */
  return retval;
}

char* get_variable_value(char* var)
{
  list* r=NULL;
  
  if((r=list_find(var,conf->defsyms))){
    return (((symba*)r->data)->value);
  };

  return NULL;
}

void putbackvariable(char* var)
{
  char* a=NULL;
  
  char* v=strdup(var);
  
  char* subst_begin=strstr(v,"@@{");
  char* subst_end=strstr(subst_begin,"}");
  
  char* tmp=(char*)malloc((subst_end-subst_begin)+1);
  
  tmp = strncpy(tmp,subst_begin+3,subst_end-subst_begin-3);
  
  tmp[subst_end-subst_begin-3]='\0';
  
  conf_put_token(subst_end+1);
  
  if((a=get_variable_value(tmp))!=NULL){
    conf_put_token(a);
  }
  else {
    
    error(230,_("Variable %s not defined\n"),tmp);

    /*
     * We can use nondefined variable
     */ 
  }
  
  subst_begin[0]='\0';
  
  conf_put_token(v);
  conf_put_token("\n");
  free(v);
  free(tmp);

}

void do_define(char* name, char* value)
{
  symba* s=NULL;
  list* l=NULL;

  if(!(l=list_find(name,conf->defsyms))){
    s=(symba*)malloc(sizeof(symba));
    s->name=name;
    s->value=value;
    conf->defsyms=list_append(conf->defsyms,(void*)s);
  }
  else {
    free(((symba*)l->data)->value);
    ((symba*)l->data)->value=NULL;
    ((symba*)l->data)->value=value;
  }
}

void do_undefine(char* name)
{
  list*r=NULL;

  if((r=list_find(name,conf->defsyms))){
    free(((symba*)r->data)->value);
    free((symba*)r->data);
    r->data=NULL;
    conf->defsyms=list_delete_item(r);
  }
}

int handle_endif(int doit,int allow_else){
  
  if(doit){
    int count=1;
    error(230,_("\nEating until @@endif\n"));
    do {
      int i = conflex();
      switch (i) {
      case TIFDEF : {
	count++;
	break;
      }
      case TIFNDEF : {
	count++;
	break;
      }
      case TENDIF : {
	count--;
	break;
      }

      case TIFHOST : {
	count++;
	break;
      }

      case TIFNHOST : {
	count++;
	break;
      }
      
      case TELSE : {
	
	if (count==1) {
	  /*
	   * We have done enough 
	   */ 
	  if (allow_else) {
	    return 0;
	  }
	  else {
	    conferror("Ambiguous else");
	    return -1;
	  }
	}
	
	break;
      }
      
      case 0 : {
	conferror("@@endif or @@else expected");
	return -1;
	count=0;
      }
      
      default : {
	/*
 	 * empty default
	 */
      }
      }
      
      
    } while (count!=0);
    
    conf_put_token("\n@@endif\n");
    error(230,"\nEating done\n");
  }
  
  return 0;
  
}

int do_ifxdef(int mode,char* name)
{
  int doit;
  doit=mode;

  if((list_find(name,conf->defsyms))){
    doit=1-doit;
  }
  
  return (handle_endif(doit,1));

}

int do_ifxhost(int mode,char* name)
{
  int doit;
  char* s=NULL;
  char *p;
  doit=mode;
  s=(char*)malloc(sizeof(char)*MAXHOSTNAMELEN+1);
  if (s == NULL) {
    error(0,_("Couldn't malloc hostname buffer"));
  }
  s[MAXHOSTNAMELEN] = '\0';

  if(gethostname(s,MAXHOSTNAMELEN)==-1){
    error(0,_("Couldn't get hostname %s"),name);
    free(s);
    return -1;
  }  
  /* strip off everything past the . */
  p = strchr(s, '.');
  if (p != NULL) {
    *p = '\0';
  }
  if(strcmp(name,s)==0) {
    doit=1-doit;
  }
  free(s);
  return (handle_endif(doit,1));
}

bool add_rx_rule_to_tree(char* rx, RESTRICTION_TYPE restriction, DB_ATTR_TYPE attr, int type, seltree *tree) {

    rx_rule* r=NULL;

    bool retval = false;

    char *path = NULL;

    const char* pcre_error;
    int         pcre_erroffset;

    if ((r = add_rx_to_tree(rx, restriction, type, tree, path, &pcre_error, &pcre_erroffset)) == NULL) {
        error(0,_("Error in regexp '%s' at %i: %s\n"),rx, pcre_erroffset, pcre_error);
        retval = false;
    }else {
        r->attr=attr;
        conf->db_out_attrs |= attr;

        if (attr&ATTR(attr_checkinode) && attr&ATTR(attr_ctime)) {
            error(20,"Rule at line %li has c and I flags enabled at the same time. If same inode is found, flag c is ignored\n",conf_lineno);
        }

        retval = true;
    }
    return retval;
}

void do_groupdef(char* group,DB_ATTR_TYPE value)
{
  list* r=NULL;
  symba* s=NULL;

  if((r=list_find(group,conf->groupsyms))){
      error(2, "Warning: group '%s' is redefined\n", group);
      ((symba*)r->data)->ival=value;
      return;
  }
  /* This is a new group */
  s=(symba*)malloc(sizeof(symba));
  s->name=group;
  s->ival=value;
  conf->groupsyms=list_append(conf->groupsyms,(void*)s);
}

DB_ATTR_TYPE get_groupval(char* group)
{
  list* r=NULL;

  if((r=list_find(group,conf->groupsyms))){
    return (((symba*)r->data)->ival);
  }
  return -1;
}

void do_dbdef(int dbtype,char* val)
{
  url_t* u=NULL;
  url_t** conf_db_url;

  error(255,"do_dbdef (%i) called with (%s)\n",dbtype,val);

  switch(dbtype) {
  case DB_OLD: {
    conf_db_url=&(conf->db_in_url);
    break;
  }
  case DB_WRITE: {
    conf_db_url=&(conf->db_out_url);
    break;
  }
  case DB_NEW: {
    conf_db_url=&(conf->db_new_url);
    break;
  }
  default : {
    error(0,"Invalid call of do_dbdef\n");
    return;
  }
  }

  if(*conf_db_url==NULL){
    u=parse_url(val);
    /* FIXME Check the URL if you add support for databases that cannot be 
     * both input and output urls */
    switch (dbtype) {
    case DB_OLD:
    case DB_NEW:{
      if(u==NULL||u->type==url_unknown||u->type==url_stdout
	 ||u->type==url_stderr) {
	error(0,_("Unsupported input URL-type:%s\n"),val);
      }
      else {
	*conf_db_url=u;
      }
      break;
    }
    case DB_WRITE: {
      if(u==NULL||u->type==url_unknown||u->type==url_stdin){
	error(0,_("Unsupported output URL-type:%s\n"),val);
      }
      else{
	conf->db_out_url=u;
	error(200,_("Output database set to \"%s\" \"%s\"\n"),val,u->value);
      }
      break;
    }
    }
  }
  free(val);
}

void do_repurldef(char* val)
{
  url_t* u=NULL;

  
  u=parse_url(val);

  if(u==NULL||u->type==url_unknown||u->type==url_stdin){
    error(0,_("Unsupported output URL-type:%s\n"),val);
  } else {
    add_report_url(u);
  }

}

void do_reportlevel(char* val) {
  REPORT_LEVEL report_level=0;

  report_level = get_report_level(val);
  if (report_level) {
      conf->report_level = report_level;
  } else {
      error(0, _("Ignoring unknown report level: %s\n"),val);
  }
  
}

void do_verbdef(char* val)
{
  char* err=NULL;
  long a=0;
  
  a=strtol(val,&err,10);
  if(*err!='\0' || a>255 || a<0 || errno==ERANGE){
    error(0, _("Illegal verbosity level:%s\n"),val);
    error(10,_("Using previous value:%i\n"),conf->verbose_level);
    return;
  }    
  else {
    if(conf->verbose_level==-1){
      conf->verbose_level=a;
    }else {
      error(210,_("Verbosity already defined to %i\n"),conf->verbose_level);
    }
  }
}

void do_rootprefix(char* val) {
    if (conf->root_prefix_length == 0) {
        conf->root_prefix=val;
        conf->root_prefix_length=strlen(conf->root_prefix);
        if (conf->root_prefix_length && conf->root_prefix[conf->root_prefix_length-1] == '/') {
            conf->root_prefix[--conf->root_prefix_length] = '\0';
            error(200,_("Removed trailing '/' from root prefix \n"));
        }
        error(200,_("Root prefix set to '%s'\n"), conf->root_prefix);
    } else {
        error(200,_("Root prefix already set to '%s'\n"), conf->root_prefix);
    }
}

#ifdef WITH_E2FSATTRS
#define easy_e2fsattrs_case(c,f) \
case c: { \
    conf->report_ignore_e2fsattrs|=f; \
    break; \
}

void do_report_ignore_e2fsattrs(char* val) {
    conf->report_ignore_e2fsattrs = 0UL;
    while (*val) {
        switch(*val){
            /* source for mappings see report.c */
            easy_e2fsattrs_case('s',EXT2_SECRM_FL)
            easy_e2fsattrs_case('u',EXT2_UNRM_FL)
            easy_e2fsattrs_case('S',EXT2_SYNC_FL)
            easy_e2fsattrs_case('D',EXT2_DIRSYNC_FL)
            easy_e2fsattrs_case('i',EXT2_IMMUTABLE_FL)
            easy_e2fsattrs_case('a',EXT2_APPEND_FL)
            easy_e2fsattrs_case('d',EXT2_NODUMP_FL)
            easy_e2fsattrs_case('A',EXT2_NOATIME_FL)
            easy_e2fsattrs_case('c',EXT2_COMPR_FL)
            easy_e2fsattrs_case('B',EXT2_COMPRBLK_FL)
            easy_e2fsattrs_case('Z',EXT2_DIRTY_FL)
            easy_e2fsattrs_case('X',EXT2_NOCOMPR_FL)
#ifdef EXT2_ECOMPR_FL
            easy_e2fsattrs_case('E',EXT2_ECOMPR_FL)
#else
            easy_e2fsattrs_case('E',EXT4_ENCRYPT_FL)
#endif
            easy_e2fsattrs_case('j',EXT3_JOURNAL_DATA_FL)
            easy_e2fsattrs_case('I',EXT2_INDEX_FL)
            easy_e2fsattrs_case('t',EXT2_NOTAIL_FL)
            easy_e2fsattrs_case('T',EXT2_TOPDIR_FL)
#ifdef EXT4_EXTENTS_FL
            easy_e2fsattrs_case('e',EXT4_EXTENTS_FL)
#endif
#ifdef EXT4_HUGE_FILE_FL
            easy_e2fsattrs_case('h',EXT4_HUGE_FILE_FL)
#endif
#ifdef FS_NOCOW_FL
            easy_e2fsattrs_case('C',FS_NOCOW_FL)
#endif
#ifdef EXT4_INLINE_DATA_FL
            easy_e2fsattrs_case('N',EXT4_INLINE_DATA_FL)
#endif
            case '0': {
                 break;
            }
            default: {
                 error(0,_("Ignore invalid ext2 file attribute: '%c'\n"),*val);
                 break;
            }
        }
        val++;
    }
}
#endif

const char* aide_key_7=CONFHMACKEY_07;
const char* db_key_7=DBHMACKEY_07;

void* get_conf_key(void) {
  void* r;
  char* m=(char*)malloc(strlen(aide_key_1)+
			strlen(aide_key_2)+
			strlen(aide_key_3)+
			strlen(aide_key_4)+
			strlen(aide_key_5)+
			strlen(aide_key_6)+
			strlen(aide_key_7)+
			strlen(aide_key_8)+
			strlen(aide_key_9)+
			strlen(aide_key_0)+1);
  m[0]=0;
  strcat(m,aide_key_0);
  strcat(m,aide_key_1);
  strcat(m,aide_key_2);
  strcat(m,aide_key_3);
  strcat(m,aide_key_4);
  strcat(m,aide_key_5);
  strcat(m,aide_key_6);
  strcat(m,aide_key_7);
  strcat(m,aide_key_8);
  strcat(m,aide_key_9);
  
  r=decode_base64(m,strlen(m),NULL);

  memset(m,0,strlen(m));
  free(m);
  return r;
}

size_t get_conf_key_len(void) {
  size_t len=0;
  char* m=(char*)malloc(strlen(aide_key_1)+
			strlen(aide_key_2)+
			strlen(aide_key_3)+
			strlen(aide_key_4)+
			strlen(aide_key_5)+
			strlen(aide_key_6)+
			strlen(aide_key_7)+
			strlen(aide_key_8)+
			strlen(aide_key_9)+
			strlen(aide_key_0)+1);
  m[0]=0;
  strcat(m,aide_key_0);
  strcat(m,aide_key_1);
  strcat(m,aide_key_2);
  strcat(m,aide_key_3);
  strcat(m,aide_key_4);
  strcat(m,aide_key_5);
  strcat(m,aide_key_6);
  strcat(m,aide_key_7);
  strcat(m,aide_key_8);
  strcat(m,aide_key_9);
  
  len=length_base64(m,strlen(m));

  memset(m,0,strlen(m));
  free(m);
  return len;
}

void* get_db_key(void) {
  void* r;
  char* m=(char*)malloc(strlen(db_key_1)+
			strlen(db_key_2)+
			strlen(db_key_3)+
			strlen(db_key_4)+
			strlen(db_key_5)+
			strlen(db_key_6)+
			strlen(db_key_7)+
			strlen(db_key_8)+
			strlen(db_key_9)+
			strlen(db_key_0)+1);
  m[0]=0;
  strcat(m,db_key_0);
  strcat(m,db_key_1);
  strcat(m,db_key_2);
  strcat(m,db_key_3);
  strcat(m,db_key_4);
  strcat(m,db_key_5);
  strcat(m,db_key_6);
  strcat(m,db_key_7);
  strcat(m,db_key_8);
  strcat(m,db_key_9);
  
  r=decode_base64(m,strlen(m),NULL);
  
  memset(m,0,strlen(m));
  free(m);
  return r;
}

size_t get_db_key_len(void) {
  size_t len=0;
  char* m=(char*)malloc(strlen(db_key_1)+
			strlen(db_key_2)+
			strlen(db_key_3)+
			strlen(db_key_4)+
			strlen(db_key_5)+
			strlen(db_key_6)+
			strlen(db_key_7)+
			strlen(db_key_8)+
			strlen(db_key_9)+
			strlen(db_key_0)+1);
  m[0]=0;
  strcat(m,db_key_0);
  strcat(m,db_key_1);
  strcat(m,db_key_2);
  strcat(m,db_key_3);
  strcat(m,db_key_4);
  strcat(m,db_key_5);
  strcat(m,db_key_6);
  strcat(m,db_key_7);
  strcat(m,db_key_8);
  strcat(m,db_key_9);
  
  len=length_base64(m,strlen(m));
  
  memset(m,0,strlen(m));
  free(m);
  return len;
}
