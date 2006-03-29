/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006 Rami Lehti, Pablo Virolainen, Richard van den Berg
 * $Id$
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "base64.h"
#include "report.h"
#include "db_config.h"
#include "gnu_regex.h"
#include "gen_list.h"
#include "list.h"
#include "db.h"
#include "util.h"
#include "commandconf.h"
#include "gen_list.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#include "md.h"

/*************/
/* contruction area for report lines */
const int old_col  = 12;   
const int new_col  = 40;   

const int part_len = 40; /* usable length of line[] */
char      oline[40];
char      nline[40];
const char* entry_format="  %-9s: %-34s, %-34s\n";
/*************/



list* find_line_match(db_line* line,list* l)
{
  list*r=NULL;

  /* Filename cannot be NULL. Or if it is NULL then we have done something 
     completly wrong. So we don't check if filename if null. db_line:s
     sould also be non null
  */
  
  for(r=l;r;r=r->next){
    if(strcmp(line->filename,((db_line*)r->data)->filename)==0){
      return r;
    }
  }
  if(l!=NULL){
    for(r=l->prev;r;r=r->prev){
      if(strcmp(line->filename,((db_line*)r->data)->filename)==0){
	return r;
      }
    }
  }

  return NULL;
}

#ifdef WITH_ACL
int compare_single_acl(aclent_t* a1,aclent_t* a2) {
  if (a1->a_type!=a2->a_type ||
      a1->a_id!=a2->a_id ||
      a1->a_perm!=a2->a_perm) {
    return RETFAIL;
  }
  return RETOK;
}

int compare_acl(acl_type* a1,acl_type* a2) {

  int i;
  if (a1==NULL && a2==NULL) {
    return RETOK;
  }
  if (a1==NULL || a2==NULL) {
    return RETFAIL;
  }

  if (a1->entries!=a2->entries) {
    return RETFAIL;
  }
  /* Sort em up. */
  aclsort(a1->entries,0,a1->acl);
  aclsort(a2->entries,0,a2->acl);
  for(i=0;i<a1->entries;i++){
    if (compare_single_acl(a1->acl+i,a2->acl+i)==RETFAIL) {
      return RETFAIL;
    }
  }
  return RETOK;
}
#endif

int compare_md_entries(byte* e1,byte* e2,int len)
{

  error(255,"Debug, compare_md_entries %p %p\n",e1,e2);

  if(e1!=NULL && e2!=NULL){
    if(strncmp(e1,e2,len)!=0){
      return RETFAIL;
    }else{
      return RETOK;
    }
  } else {
    /* At least the other is NULL */
    if(e1==NULL && e2==NULL){
      return RETOK;
    }else{
      return RETFAIL;
    }
  }
  return RETFAIL;
}


/*
  We assume
  - no null parameters
  - same filename
  - something else?
  - ignorelist kertoo mitä ei saa vertailla
*/

int compare_dbline(db_line* l1,db_line* l2,int ignorelist)
{

#define easy_compare(a,b) \
  if (!(a&ignorelist)) {\
    if(l1->b!=l2->b){\
      ret|=a;\
    }\
  }

#define easy_md_compare(a,b,c) \
  if (!(a&ignorelist)) {  \
    if(compare_md_entries(l1->b,l2->b,\
			  c)==RETFAIL){ \
      ret|=a; \
    } \
  }
  
  
  int ret=0;
  
  if (!(DB_LINKNAME&ignorelist)) {
    if(l1->linkname==NULL){
      if(l2->linkname!=NULL){
	ret|=DB_LINKNAME;
	//return RETFAIL;
      }
    }else if(l2->linkname==NULL){
	ret|=DB_LINKNAME;
	//return RETFAIL;
    }else if(strcmp(l1->linkname,l2->linkname)!=0){
	ret|=DB_LINKNAME;
	//return RETFAIL;
    }
  }
    
  if (!(DB_SIZEG&ignorelist)) {
    if ( (DB_SIZEG&l2->attr) && !(DB_SIZE&l2->attr) ){
      if(l1->size>l2->size){
	ret|=DB_SIZEG;
	//return RETFAIL;
      }
    } else {
      if(l1->size!=l2->size){
	ret|=DB_SIZEG;
	//return RETFAIL;
      }
    }
  }
  
  easy_compare(DB_BCOUNT,bcount);
  
  if (!(DB_PERM&ignorelist)) {
    if(l1->perm!=l2->perm){
      ret|=DB_PERM;
      //return RETFAIL;
    }
  } else {
    error(0,"Ignoring permissions\n");
  }
  
  easy_compare(DB_UID,uid);
  easy_compare(DB_GID,gid);
  easy_compare(DB_ATIME,atime);
  easy_compare(DB_MTIME,mtime);
  easy_compare(DB_CTIME,ctime);


  easy_compare(DB_INODE,inode);
  easy_compare(DB_LNKCOUNT,nlink);

  easy_md_compare(DB_MD5,md5,HASH_MD5_LEN);
  
  error(255,"Debug, %s, %p %p %i %i\n",l1->filename,l1->md5,l2->md5,ret&DB_MD5,ignorelist);
  
  easy_md_compare(DB_SHA1,sha1,HASH_SHA1_LEN);
  easy_md_compare(DB_RMD160,rmd160,HASH_RMD160_LEN);
  easy_md_compare(DB_TIGER,tiger,HASH_TIGER_LEN);
  
#ifdef WITH_MHASH
  easy_md_compare(DB_CRC32,crc32,HASH_CRC32_LEN);
  easy_md_compare(DB_HAVAL,haval,HASH_HAVAL256_LEN);
  easy_md_compare(DB_GOST,gost,HASH_GOST_LEN);
  easy_md_compare(DB_CRC32B,crc32b,HASH_CRC32B_LEN);
#endif

#ifdef WITH_ACL
  if (!(DB_ACL&ignorelist)) {
    if(compare_acl(l1->acl,l2->acl)) {
      ret|=DB_ACL;
    }
  }
#endif
  return ret;
}

void print_lname_changes(char*old,char*new)
{
  int ok = 0;

  if(old==NULL){
    if(new!=NULL){
       snprintf(oline,part_len,"<NULL>");
       snprintf(nline,part_len,"%s",new);
       ok = 1;
    }
  } else if(new==NULL){
       snprintf(oline,part_len,"%s",old);
       snprintf(nline,part_len,"<NULL>");
       ok = 1;
   } else if(strcmp(old,new)!=0){
        snprintf(oline,part_len,"%s",old);
        snprintf(nline,part_len,"%s",new);
        ok = 1;
  }
   if(ok)
     error(2,(char*)entry_format,"Lname",oline,nline);

   return;
}

#ifdef WITH_ACL
void print_single_acl(acl_type* acl){
  char* aclt;
  
  if (acl==NULL) {
    error(2,"<NULL>");
  } else {
    
    aclt=acltotext(acl->acl,acl->entries);
    if (aclt==NULL) {
      error(2,"ERROR");
    } else {
      error(2,"%s ,",aclt);
      free(aclt);
    }
  }
}

void print_acl_changes(acl_type* old,acl_type* new) {
  
  if (compare_acl(old,new)==RETFAIL) {
    error(2,"Acl: old = ");
    print_single_acl(old);
    error(2,"\n     new = ");
    print_single_acl(new);
  }
  
}
#endif

void print_md_changes(byte*old,byte*new,int len,char* name)
{
  int ok = 0;
  if(old!=NULL && new!=NULL){
    if(strncmp(old,new,len)!=0){
      snprintf(oline,part_len,"%s",encode_base64(old,len));
      snprintf(nline,part_len,"%s",encode_base64(new,len));
      ok = 1;
    }
  } else {
    if(old == NULL && new == NULL){
      return;
    }
    if(old==NULL){
      snprintf(oline,part_len,"NA");
    } else {
      snprintf(oline,part_len,"%s",encode_base64(old,len));
      ok = 1;
    }
    /* OLD one */
    if(new==NULL){
      snprintf(nline,part_len,"NA");
    }else {
      snprintf(nline,part_len,"%s",encode_base64(new,len));
      ok = 1;
    }
  }
  if(ok)
    error(2,(char*)entry_format,name,oline,nline);
  
  return;
}

int is_time_null(struct tm *ot)
{
    /* 1970-01-01 01:00:00 is year null */
    return (ot->tm_year==70 && ot->tm_mon == 0 && ot->tm_mday == 1
            && ot->tm_hour == 1 &&  ot->tm_min == 0 && ot->tm_sec == 0);
}

void print_time_changes(const char* name, time_t old_time, time_t new_time)
{
  struct tm otm;
  struct tm *ot = &otm;
  struct tm *tmp = localtime(&old_time);
  struct tm *nt;
  
  /* lib stores last tm call in static storage */
  ot->tm_year = tmp->tm_year; ot->tm_mon = tmp->tm_mon;
  ot->tm_mday = tmp->tm_mday;  ot->tm_hour = tmp->tm_hour;
  ot->tm_min = tmp->tm_min; ot->tm_sec = tmp->tm_sec;
  
  nt = localtime(&(new_time));
  
  if( is_time_null(ot) )
    snprintf(oline,part_len,"NA");
  else
    snprintf(oline,part_len,
	     "%0.4u-%0.2u-%0.2u %0.2u:%0.2u:%0.2u",
	     ot->tm_year+1900, ot->tm_mon+1, ot->tm_mday,
	     ot->tm_hour, ot->tm_min, ot->tm_sec);
  if( is_time_null(nt) )
    snprintf(nline,part_len,"NA");
  else
    snprintf(nline,part_len,
	     "%0.4u-%0.2u-%0.2u %0.2u:%0.2u:%0.2u",
	     nt->tm_year+1900, nt->tm_mon+1, nt->tm_mday,
	     nt->tm_hour, nt->tm_min, nt->tm_sec);
  error(2,(char*)entry_format,name,oline,nline); 
}

void print_int_changes(
        const char* name,
        int old,
        int new
        )
{
  snprintf(oline,part_len,"%i",old);
  snprintf(nline,part_len,"%i",new);
  error(2,(char*)entry_format,name,oline,nline); 
}
void print_long_changes(
        const char* name,
        AIDE_OFF_TYPE old,
        AIDE_OFF_TYPE new
        )
{
#if AIDE_OFF_TYPE == off64_t
  snprintf(oline,part_len,"%llu",old);
  snprintf(nline,part_len,"%llu",new);
#else
  snprintf(oline,part_len,"%lu",old);
  snprintf(nline,part_len,"%lu",new);
#endif
  error(2,(char*)entry_format,name,oline,nline);  
}

void print_string_changes(
        const char* name,
        const char* old,
        const char* new
        )
{
  snprintf(oline,part_len,"%s",old);
  snprintf(nline,part_len,"%s",new);
  error(2,(char*)entry_format,name,oline,nline); 
}


void print_dbline_changes(db_line* old,db_line* new,int ignorelist)
{
  char* tmp=NULL;
  char* tmp2=NULL;
  

  if(S_ISDIR(new->perm_o)){
    error(2,"\nDirectory: %s\n",old->filename);
  }else {
    error(2,"\nFile: %s\n",old->filename);
  }
  
  if(!(DB_LINKNAME&ignorelist)){
    print_lname_changes(old->linkname,new->linkname);
  }
  if (!(DB_SIZE&ignorelist)) {
    if(old->size!=new->size){
      print_long_changes("Size", old->size,new->size);
    }
  }

  if (!(DB_BCOUNT&ignorelist)) {
    if(old->bcount!=new->bcount){
      print_int_changes("Bcount", old->bcount,new->bcount);
    }
  }
  if (!(DB_PERM&ignorelist)) {
    if(old->perm!=new->perm){
      tmp=perm_to_char(old->perm);
      tmp2=perm_to_char(new->perm);
      print_string_changes("Permissions", tmp,tmp2);
      free(tmp);
      free(tmp2);
      tmp=NULL;
      tmp2=NULL;
    }
  }
  
  if (!(DB_UID&ignorelist)) {
    if(old->uid!=new->uid){
      print_int_changes("Uid", old->uid,new->uid);
    }
  }
  
  if (!(DB_GID&ignorelist)) {
    if(old->gid!=new->gid){
      print_int_changes("Gid", old->gid,new->gid);
    }
  }
  
  if (!(DB_ATIME&ignorelist)) {
    if(old->atime!=new->atime){
      print_time_changes("Atime", old->atime, new->atime);
    }
  }
  
  if (!(DB_MTIME&ignorelist)) {
    if(old->mtime!=new->mtime){
      print_time_changes("Mtime", old->mtime, new->mtime);
    }
  }
  
  if (!(DB_CTIME&ignorelist)) {
    if(old->ctime!=new->ctime){
      print_time_changes("Ctime", old->ctime, new->ctime);
    }
  }

  if (!(DB_INODE&ignorelist)) {
    if(old->inode!=new->inode){
      print_int_changes("Inode", old->inode,new->inode);
    }
  }
  if (!(DB_LNKCOUNT&ignorelist)) {
    if(old->nlink!=new->nlink){
      print_int_changes("Linkcount", old->nlink,new->nlink);
    }
  }

  if (!(DB_MD5&ignorelist)) {  
    print_md_changes(old->md5,new->md5,
		     HASH_MD5_LEN,
		     "MD5");
  }
  
  if (!(DB_SHA1&ignorelist)) {
      print_md_changes(old->sha1,new->sha1,
		       HASH_SHA1_LEN,
		       "SHA1");
  }

  if (!(DB_RMD160&ignorelist)) {
    print_md_changes(old->rmd160,new->rmd160,
		     HASH_RMD160_LEN,
		     "RMD160");
  }
  
  if (!(DB_TIGER&ignorelist)) {
    print_md_changes(old->tiger,new->tiger,
		     HASH_TIGER_LEN,
		     "TIGER");
  }
  
#ifdef WITH_MHASH
  if (!(DB_CRC32&ignorelist)) {
    print_md_changes(old->crc32,new->crc32,
		     HASH_CRC32_LEN,
		     "CRC32");
  }
  
  if (!(DB_HAVAL&ignorelist)) {
    print_md_changes(old->haval,new->haval,
		     HASH_HAVAL256_LEN,
		     "HAVAL");
  }
  
  if (!(DB_GOST&ignorelist)) {
    print_md_changes(old->gost,new->gost,
		     HASH_GOST_LEN,
		     "GOST");
  }
  
  if (!(DB_CRC32B&ignorelist)) {
    print_md_changes(old->crc32b,new->crc32b,
		     HASH_CRC32B_LEN,
		     "CRC32B");
  }
#endif                   

#ifdef WITH_ACL
  if (!(DB_ACL&ignorelist)) {
    print_acl_changes(old->acl,new->acl);
  }
#endif
  
  return;
}

void init_rxlst(list* rxlst)
{
    list*    r         = NULL;
    rx_rule* rxrultmp  = NULL;
    regex_t* rxtmp     = NULL;


  for(r=rxlst;r;r=r->next){
    char* data=NULL;
    /* We have to add '^' to the first charaster of string... 
     *
     */
    
    data=(char*)malloc(strlen(((rx_rule*)r->data)->rx)+1+1);
    
    if (data==NULL){
      error(0,_("Not enough memory for regexpr compile... exiting..\n"));
      abort();
    }
    
    strcpy(data+1,((rx_rule*)r->data)->rx);
    
    data[0]='^';
    
    rxrultmp=((rx_rule*)r->data);
    rxrultmp->conf_lineno=-1;
    rxtmp=(regex_t*)malloc(sizeof(regex_t));
    if( regcomp(rxtmp,data,REG_EXTENDED|REG_NOSUB)){
      error(0,_("Error in selective regexp:%s"),((rx_rule*)r->data)->rx);
      free(data);
    }else {
      rxrultmp->conf_lineno=((rx_rule*)r)->conf_lineno;
      free(rxrultmp->rx);
      rxrultmp->rx=data;
      rxrultmp->crx=rxtmp;
    }
    
  }

}

void eat_files_indir(list* flist,char* dirname,long* filcount)
{
  size_t len;

  *filcount=0;
  len=strlen(dirname);

  while (flist){
    if((strncmp(dirname,((db_line*)flist->data)->filename,len)==0)
       && ((((db_line*)flist->data)->filename)[len]=='/')){
      free_db_line((db_line*)flist->data);
      free(flist->data);
      flist=list_delete_item(flist);
      (*filcount)++;
    }
    flist=flist->next;
  }
}

void print_report_header(int nfil,int nadd,int nrem,int nchg)
{
  struct tm* st=localtime(&(conf->start_time));
  if(conf->action&DO_COMPARE)
    error(0,_("AIDE found differences between database and filesystem!!\n"));

  if(conf->action&DO_DIFF)
    error(0,_("AIDE found differences between the two databases!!\n"));
  if(conf->config_version)
    error(2,_("Config version used: %s\n"),conf->config_version);

  error(2,_("Start timestamp: %0.4u-%0.2u-%0.2u %0.2u:%0.2u:%0.2u\n"),
	st->tm_year+1900, st->tm_mon+1, st->tm_mday,
	st->tm_hour, st->tm_min, st->tm_sec);
  error(0,_("\nSummary:\n  Total number of files:\t%i\n  Added files:\t\t\t%i\n"
	    "  Removed files:\t\t%i\n  Changed files:\t\t%i\n\n"),nfil,nadd,nrem,nchg);
  
}

void print_report_footer(struct tm* st)
{
    error(2,_("\nEnd timestamp: %0.4u-%0.2u-%0.2u %0.2u:%0.2u:%0.2u\n"),
	  st->tm_year+1900, st->tm_mon+1, st->tm_mday,
	  st->tm_hour, st->tm_min, st->tm_sec);
}

void compare_db(list* new,db_config* conf)
{
  db_line* old=NULL;
  list* l=new;
  list* r=NULL;
  list* removed=NULL;
  list* changednew=NULL;
  list* changedold=NULL;
  list* added=NULL;
  long nrem=0;
  long nchg=0;
  long nadd=0;
  long nfil=0;
  long filesindir=0;
  int tempignore=0;
  int initdbwarningprinted=0;

  int ignorelist;

  error(200,_("compare_db()\n"));


  /* With this we avoid unnecessary checking of removed files. */
  if(conf->action&DO_INIT){
    initdbwarningprinted=1;
  } else {
    /* We have to init the rxlsts since they are copied and then 
       initialized in gen_list.c */
    init_rxlst(conf->selrxlst);
    init_rxlst(conf->equrxlst);
    init_rxlst(conf->negrxlst);
  }
  
  /* We have a way to ignore some changes... */ 
  
  ignorelist=get_groupval("ignore_list");
  
  if (ignorelist==-1) {
    ignorelist=0;
  }

  for(old=db_readline(DB_OLD);old;old=db_readline(DB_OLD)){
    nfil++;
    r=find_line_match(old,l);
    if(r==NULL){
      /* The WARNING is only printed once */
      /* FIXME There should be a check for this in changed part also */
      /* This part should also be rethinked */
      if(!initdbwarningprinted &&
	 (check_list_for_match(conf->selrxlst,old->filename,&tempignore) ||
	  check_list_for_match(conf->equrxlst,old->filename,&tempignore)) &&
	 !check_list_for_match(conf->negrxlst,old->filename,&tempignore)){
	if(!(conf->action&DO_INIT)){
	  error(2,_("WARNING: Old db contains a file that shouldn\'t be there, run --init or --update\n"));
	}
	initdbwarningprinted=1;
      }
      removed=list_append(removed,(void*)old);
      nrem++;
    }else {
      int localignorelist=old->attr ^ ((db_line*)r->data)->attr;
      
      if ((localignorelist&(~(DB_NEWFILE|DB_RMFILE)))!=0) {
	error(2,"File %s in databases has different attributes, %i,%i\n",old->filename,old->attr,((db_line*)r->data)->attr);
      }
      
      localignorelist|=ignorelist;
      
      if(compare_dbline(old,(db_line*)r->data,localignorelist)!=0){
	changednew=list_append(changednew,r->data);
	changedold=list_append(changedold,(void*)old);
	r->data=NULL;
	l=list_delete_item(r);
	nchg++;
      }else {
	/* This line was ok */
	/*
	  Cannot free, chech why.
	  It's because db_disk needs it for going back
	  to it's parent.
	  
	  free_db_line(old);
	  free(old);
	  free_db_line((db_line*)r->data);
	  free((db_line*)r->data);
	*/
	
	l=list_delete_item(r);
      }
    }
    
  }
  /* Now we have checked the old database and removed the lines *
   * that have matched. */
  if(l!=NULL){
    added=l->header->head;
  }else {
    added=NULL;
  }
  
  for(l=added;l;l=l->next){
    nadd++;
  }


  if(nadd!=0||nrem!=0||nchg!=0){
    print_report_header(nfil,nadd,nrem,nchg);

    if(nadd!=0){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Added files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=added;r;r=r->next){
	error(2,"added: %s\n",((db_line*)r->data)->filename);
	if(conf->verbose_level<20){
	  if(S_ISDIR(((db_line*)r->data)->perm)){
	    /*	    
		    free_db_line((db_line*)r->data);
		    free(r->data);
		    r=list_delete_item(r);
	    */
	    eat_files_indir(r->next,((db_line*)r->data)->filename,&filesindir);
	    if(filesindir>0){
	      error(2,
		    _("added: THERE WERE ALSO %li "
		    "FILES ADDED UNDER THIS DIRECTORY\n")
		    ,filesindir);
	    }
	  }
	}
      }
    }
    

    if(nrem!=0){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Removed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=removed;r;r=r->next){
	error(2,"removed: %s\n",((db_line*)r->data)->filename);
      }
    }

    if(nchg!=0){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Changed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=changedold;r;r=r->next){
	error(2,"changed: %s\n",((db_line*)r->data)->filename);
      }
    }

    if((conf->verbose_level>=5)&&(nchg!=0)){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Detailed information about changes:\n"));
      error(2,_("---------------------------------------------------\n\n"));
      for(r=changedold,l=changednew;r;r=r->next,l=l->next){
	int localignorelist=((db_line*)l->data)->attr^((db_line*)r->data)->attr;
	localignorelist|=ignorelist;
	print_dbline_changes((db_line*)r->data,
			     (db_line*)l->data,localignorelist);
      }
    }
    conf->end_time=time(&(conf->end_time));
    print_report_footer(localtime(&(conf->end_time)));
  }
}

long report_tree(seltree* node,int stage, int* stat)
{
  list* r=NULL;
  int ignorelist=0;
  int top=0;

  ignorelist=get_groupval("ignore_list");
  
  if (ignorelist==-1) {
    ignorelist=0;
  }
  
  if(stat[0]){
    stat[0]=0;
    top=1;
  }


  /* First check the tree for changes and do a bit of painting, 
     then we print the terse report one changetype at a time
     and then we do the detailed listing for changed nodes
  */
  if(stage==0){
    /* If this node has been touched checked !=0 
       If checked == 0 there is nothing to report
    */
    if(node->checked!=0){
      stat[1]++;
      if((node->checked&DB_OLD)&&(node->checked&DB_NEW)&&
	 (node->old_data==NULL)&&(node->new_data==NULL)){
	/* Node was added to twice and discovered to be not changed*/
      }else if(!(node->checked&DB_OLD)&&(node->checked&DB_NEW)){
	/* File is in new db but not old. (ADDED) */
	/* unless it was moved in */
	if (!((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) {
	  stat[2]++;
	  node->checked|=NODE_ADDED;
	}
      }else if((node->checked&DB_OLD)&&!(node->checked&DB_NEW)){
	/* File is in old db but not new. (REMOVED) */
	/* unless it was moved out */
	if (!((node->checked&NODE_ALLOW_RM)||(node->checked&NODE_MOVED_OUT))) {
	  stat[3]++;
	  node->checked|=NODE_REMOVED;
	}
      }else if((node->checked&DB_OLD)&&(node->checked&DB_NEW)&&
	       (node->old_data!=NULL)&&(node->new_data!=NULL)){
	/* File is in both db's and the data is still there. (CHANGED) */
	if(!(node->checked&(NODE_MOVED_IN|NODE_MOVED_OUT))){
	  stat[4]++;
	  node->checked|=NODE_CHANGED;
	}else if (!((node->checked&NODE_ALLOW_NEW)||(node->checked&NODE_MOVED_IN))) {
	  stat[2]++;
	  node->checked|=NODE_ADDED;
	}else if (!((node->checked&NODE_ALLOW_RM)||(node->checked&NODE_MOVED_OUT))) {
	  stat[3]++;
	  node->checked|=NODE_REMOVED;
	}
      }
    }
  }

  if((stage==1)&&stat[2]){
    if(top){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Added files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_ADDED){
      error(2,_("added: %s\n"),node->new_data->filename);
    }
  }

  if((stage==2)&&stat[3]){
    if(top){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Removed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_REMOVED){
      error(2,_("removed: %s\n"),node->old_data->filename);
    }
  }

  if((stage==3)&&stat[4]){
    if(top){
      error(2,_("\n---------------------------------------------------\n"));
      error(2,_("Changed files:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_CHANGED){
      error(2,_("changed: %s\n"),node->new_data->filename);
    }
  }

  if((stage==4)&&(conf->verbose_level>=5)&&stat[4]){
    if(top){
      error(2,_("\n--------------------------------------------------\n"));
      error(2,_("Detailed information about changes:\n"));
      error(2,_("---------------------------------------------------\n\n"));
    }
    if(node->checked&NODE_CHANGED){
      print_dbline_changes(node->old_data,node->new_data,ignorelist);
    }
  }

  /* All stage dependent things done for this node. Let's check children */
  for(r=node->childs;r;r=r->next){
    report_tree((seltree*)r->data,stage,stat);
  }

  if(top&&(stage==0)&&((stat[2]+stat[3]+stat[4])>0)){
    print_report_header(stat[1],stat[2],stat[3],stat[4]);
  }
  
  return (stat[2]+stat[3]+stat[4]);
}

const char* aide_key_9=CONFHMACKEY_09;
const char* db_key_9=DBHMACKEY_09;

// vi: ts=8 sw=8
