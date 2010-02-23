/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti,Pablo Virolainen
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
	       
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

#include "report.h"
#include "gnu_regex.h"
#include "list.h"
#include "gen_list.h"
#include "seltree.h"
#include "db.h"
#include "db_config.h"
#include "compare_db.h"
#include "commandconf.h"
#include "report.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#define CLOCK_SKEW 5

#ifdef WITH_MHASH
#include <mhash.h>
#endif
#include "md.h"
#include "do_md.h"

void hsymlnk(db_line* line);
void fs2db_line(struct AIDE_STAT_TYPE* fs,db_line* line);
void calc_md(struct AIDE_STAT_TYPE* old_fs,db_line* line);
void no_hash(db_line* line);

char* strrxtok(char* rx)
{
  char*p=NULL;
  size_t i=0;

  /* The following code assumes that the first character is a slash */
  size_t lastslash=1;

  p=strdup(rx);
  p[0]='/';

  for(i=1;i<strlen(p);i++){
    switch(p[i])
      {
      case '/':
	lastslash=i;
	break;
      case '(':
      case '^':
      case '$':
      case '*':
      case '[':
	i=strlen(p);
	break;
      case '\\':
	strcpy(p+i,p+i+1);
	i++;
	break;
      default:
	break;
      }
  }

  p[lastslash]='\0';

  return p;
}

char* strlastslash(char*str)
{
  char* p=NULL;
  size_t lastslash=1;
  size_t i=0;

  for(i=1;i<strlen(str);i++){
    if(str[i]=='/'){
      lastslash=i;
    }
  }
  
  p=(char*)malloc(sizeof(char)*lastslash+1);
  strncpy(p,str,lastslash);
  p[lastslash]='\0';

  return p;
}

char* strgetndirname(char* path,int depth)
{
  char* r=NULL;
  char* tmp=NULL;
  int i=0;

  for(r=path;;r+=1){
    if(*r=='/')
      i++;
    if(*r=='\0')
      break;
    if(i==depth)
      break;
  }
  /* If we ran out string return the whole string */
  if(!(*r))
    return strdup(path);

  tmp=strdup(path);

  tmp[r-path]='\0';

  return tmp;
}

int treedepth(seltree* node)
{
  seltree* r=NULL;
  int depth=0;

  for(r=node;r;r=r->parent)
    depth++;
  
  return depth;
}

/* This function returns a node with the same inode value as the 'file' */
/* The only place it is used is in add_file_to_tree() function */
static seltree* get_seltree_inode(seltree* tree, db_line* file, int db)
{
  seltree* node=NULL;
  list* r=NULL;
  char* tmp=NULL;

  if(tree==NULL){
    return NULL;
  }

  /* found the match */
  if((db == DB_NEW &&
      tree->new_data != NULL &&
      file->inode == tree->new_data->inode) ||
     (db == DB_OLD &&
      tree->old_data != NULL &&
      file->inode == tree->old_data->inode)) {
    return tree;
  }

  /* tmp is the directory of the file->filename */
  tmp=strgetndirname(file->filename,treedepth(tree)+1);
  for(r=tree->childs;r;r=r->next){
    /* We are interested only in files with the same regexp specification */
    if(strlen(tmp) == strlen(file->filename) ||
       strncmp(((seltree*)r->data)->path,tmp,strlen(tmp)+1)==0){
      node=get_seltree_inode((seltree*)r->data,file,db);
      if(node!=NULL){
	break;
      }
    }
  }
  free(tmp);
  return node;
}

seltree* get_seltree_node(seltree* tree,char* path)
{
  seltree* node=NULL;
  list* r=NULL;
  char* tmp=NULL;

  if(tree==NULL){
    return NULL;
  }

  if(strncmp(path,tree->path,strlen(path)+1)==0){
    return tree;
  }
  else{
    tmp=strgetndirname(path,treedepth(tree)+1);
    for(r=tree->childs;r;r=r->next){
      if(strncmp(((seltree*)r->data)->path,tmp,strlen(tmp)+1)==0){
	node=get_seltree_node((seltree*)r->data,path);
	if(node!=NULL){
	  /* Don't leak memory */
	  free(tmp);
	  return node;
	}
      }
    }
    free(tmp);
  }
  return NULL;
}

void copy_rule_ref(seltree* node, rx_rule* r)
{
    if( r!=NULL ){
        node->conf_lineno = r->conf_lineno;  
        node->rx=strdup(r->rx);
    } else {
        node->conf_lineno = -1;
        node->rx=NULL;
    }
}

seltree* new_seltree_node(
        seltree* tree,
        char*path,
        int isrx,
        rx_rule* r)
{
  seltree* node=NULL;
  seltree* parent=NULL;
  char* tmprxtok = NULL;

  node=(seltree*)malloc(sizeof(seltree));
  node->childs=NULL;
  node->path=strdup(path);
  node->sel_rx_lst=NULL;
  node->neg_rx_lst=NULL;
  node->equ_rx_lst=NULL;
  node->checked=0;
  node->attr=0;
  node->new_data=NULL;
  node->old_data=NULL;

  copy_rule_ref(node,r);

  if(tree!=NULL){
    tmprxtok = strrxtok(path);
    if(isrx){
      parent=get_seltree_node(tree,tmprxtok);
    }else {
      char* dirn=strlastslash(path);
      parent=get_seltree_node(tree,dirn);
      free(dirn);
    }      
    if(parent==NULL){
      if(isrx){
	parent=new_seltree_node(tree,tmprxtok,isrx,r);
      }else {
        char* dirn=strlastslash(path);
        parent=new_seltree_node(tree,dirn,isrx,r);
        free(dirn);
      }
    }
    free(tmprxtok);
    parent->childs=list_append(parent->childs,(void*)node);
    node->parent=parent;
  }else {
    node->parent=NULL;
  }
  return node;
}

void gen_seltree(list* rxlist,seltree* tree,char type)
{
  regex_t*     rxtmp   = NULL;
  seltree*     curnode = NULL;
  list*        r       = NULL;
  char*        rxtok   = NULL;
  rx_rule*     rxc     = NULL;

  for(r=rxlist;r;r=r->next){
    char* data;
    rx_rule* curr_rule = (rx_rule*)r->data;
    
    
    rxtok=strrxtok(curr_rule->rx);
    curnode=get_seltree_node(tree,rxtok);

    if(curnode==NULL){
      curnode=new_seltree_node(tree,rxtok,1,curr_rule);
    }

    error(240,"Handling %s with %c \"%s\" with node \"%s\"\n",rxtok,type,curr_rule->rx,curnode->path);
	
    
    /* We have to add '^' to the first character of string... 
     */

    data=(char*)malloc(strlen(curr_rule->rx)+1+1);

    if (data==NULL){
      error(0,_("Not enough memory for regexpr compile... exiting..\n"));
      abort();
    }
    
    /* FIX ME! (returnvalue) */
    
    strcpy(data+1,curr_rule->rx);
    
    data[0]='^';
    
    rxtmp=(regex_t*)malloc(sizeof(regex_t));
    if( regcomp(rxtmp,data,REG_EXTENDED|REG_NOSUB)){
      error(0,_("Error in selective regexp:%s"),curr_rule->rx);
      free(data);
    }else{
      /* replace regexp text with regexp compiled */
      rxc=(rx_rule*)malloc(sizeof(rx_rule));
      rxc->rx=data;
      /* and copy the rest */
      rxc->crx=rxtmp;
      rxc->attr=curr_rule->attr;
      rxc->conf_lineno=curr_rule->conf_lineno;

      switch (type){
      case 's':{
	curnode->sel_rx_lst=list_append(curnode->sel_rx_lst,(void*)rxc);
	break;
      }
      case 'n':{
	curnode->neg_rx_lst=list_append(curnode->neg_rx_lst,(void*)rxc);
	break;
      }
      case 'e':{
	curnode->equ_rx_lst=list_append(curnode->equ_rx_lst,(void*)rxc);
	break;
      }
      }
    }
    /* Data should not be free'ed because it's in rxc struct
     * and freeing is done if error occour.
     */
      free(rxtok);
  }
}

static xattrs_type *xattr_new(void)
{
  xattrs_type *ret = NULL;

  ret = malloc(sizeof(xattrs_type));
  ret->num = 0;
  ret->sz  = 2;
  ret->ents = malloc(sizeof(xattr_node) * ret->sz);

  return (ret);
}

static void *xzmemdup(const void *ptr, size_t len)
{ /* always keeps a 0 at the end... */
  void *ret = NULL;

  ret = malloc(len+1);
  memcpy(ret, ptr, len);
  ((char*)ret)[len] = 0;
  
  return (ret);
}

static void xattr_add(xattrs_type *xattrs,
                      const char *key, const char *val, size_t vsz)
{
  if (xattrs->num >= xattrs->sz)
  {
    xattrs->sz <<= 1;
    xattrs->ents = realloc(xattrs->ents, sizeof(xattr_node) * xattrs->sz);
  }

  xattrs->ents[xattrs->num].key = strdup(key);
  xattrs->ents[xattrs->num].val = xzmemdup(val, vsz);
  xattrs->ents[xattrs->num].vsz = vsz;

  xattrs->num += 1;
}

/* should be in do_md ? */
static void xattrs2line(db_line *line)
{ /* get all generic user xattrs. */
#ifdef WITH_XATTR
  xattrs_type *xattrs = NULL;
  static ssize_t xsz = 1024;
  static char *xatrs = NULL;
  ssize_t xret = -1;

  if (!(DB_XATTRS&line->attr))
    return;
  
  /* assume memory allocs work, like rest of AIDE code... */
  if (!xatrs) xatrs = malloc(xsz);
  
  while (((xret = llistxattr(line->filename, xatrs, xsz)) == -1) &&
         (errno == ERANGE))
  {
    xsz <<= 1;
    xatrs = realloc(xatrs, xsz);
  }

  if ((xret == -1) && (errno == ENOSYS))
  { /* do nothing */ }
  else if (xret == -1)
    error(0, "listxattrs failed for %s:%m\n", line->filename);
  else if (xret)
  {
    const char *attr = xatrs;
    static ssize_t asz = 1024;
    static char *val = NULL;

    if (!val) val = malloc(asz);
    
    xattrs = xattr_new();
  
    while (xret > 0)
    {
      size_t len = strlen(attr);
      ssize_t aret = 0;
      
      if (strncmp(attr, "user.", strlen("user.")) &&
          strncmp(attr, "root.", strlen("root.")))
        goto next_attr; /* only store normal xattrs, and SELinux */
      
      while (((aret = getxattr(line->filename, attr, val, asz)) == -1) &&
             (errno == ERANGE))
      {
        asz <<= 1;
        val = realloc (val, asz);
      }
      
      if (aret != -1)
        xattr_add(xattrs, attr, val, aret);
      else if (errno != ENOATTR)
        error(0, "getxattr failed for %s:%m\n", line->filename);
      
     next_attr:
      attr += len + 1;
      xret -= len + 1;
    }
  }

  line->xattrs = xattrs;
#endif
}

/* should be in do_md ? */
static void selinux2line(db_line *line)
{
#ifdef WITH_SELINUX
  char *cntx = NULL;

  if (!(DB_SELINUX&line->attr))
    return;

  if (lgetfilecon_raw(line->filename, &cntx) == -1)
  {
    error(0, "lgetfilecon_raw failed for %s:%m\n", line->filename);
    return;
  }

  line->cntx = strdup(cntx);
  
  freecon(cntx);
#endif
}

list* add_file_to_list(list* listp,char*filename,DB_ATTR_TYPE attr,int* addok)
{
  db_line* fil=NULL;
  time_t cur_time;
  struct AIDE_STAT_TYPE fs;
  int sres=0;
  
  error(220, _("Adding %s to filelist\n"),filename);
  
  fil=(db_line*)malloc(sizeof(db_line));
  fil->attr=attr|DB_FILENAME|DB_LINKNAME;
  fil->filename=(char*)malloc(sizeof(char)*strlen(filename)+1);
  strncpy(fil->filename,filename,strlen(filename));
  fil->filename[strlen(filename)]='\0';
  /* We want to use lstat here instead of stat since we want *
   * symlinks stats not the file that it points to. */
  sres=AIDE_LSTAT_FUNC(fil->filename,&fs);
  if(sres==-1){
    char* er=strerror(errno);
    if (er==NULL) {
      error(0,"lstat() failed for %s. strerror failed for %i\n",fil->filename,errno);
    } else {
      error(0,"lstat() failed for %s:%s\n",fil->filename,strerror(errno));
    }
    free(fil->filename);
    free(fil);
    *addok=RETFAIL;
    return listp;
  } 
  if(!(fil->attr&DB_RDEV))
    fs.st_rdev=0;
  
  cur_time=time(NULL);

  if (cur_time==(time_t)-1) {
    char* er=strerror(errno);
    if (er==NULL) {
      error(0,_("Can not get current time. strerror failed for %i\n"),errno);
    } else {
      error(0,_("Can not get current time with reason %s\n"),er);
    }
  } else {
    
    if(fs.st_atime>cur_time){
      error(CLOCK_SKEW,_("%s atime in future\n"),fil->filename);
    }
    if(fs.st_mtime>cur_time){
      error(CLOCK_SKEW,_("%s mtime in future\n"),fil->filename);
    }
    if(fs.st_ctime>cur_time){
      error(CLOCK_SKEW,_("%s ctime in future\n"),fil->filename);
    }
  }
  
  fil->perm_o=fs.st_mode;
  fil->size_o=fs.st_size;

  if((S_ISLNK(fs.st_mode))){
    char* lnktmp=NULL;
    char* lnkbuf=NULL;
    int len=0;
    
#ifdef WITH_ACL   
    if(conf->no_acl_on_symlinks!=1) {
      fil->attr&=(~DB_ACL);
    }
#endif
    
    if(conf->warn_dead_symlinks==1) {
      struct AIDE_STAT_TYPE tmp_fs;
      sres=AIDE_STAT_FUNC(fil->filename,&tmp_fs);
      if (sres!=0) {
	error(4,"Dead symlink detected at %s\n",fil->filename);
      }
      if(!(fil->attr&DB_RDEV))
	fs.st_rdev=0;
    }
    
    if(conf->symlinks_found==0){
      int it=0;
      DB_FIELD dbtmp;
      DB_FIELD dbtmp2;
      dbtmp=conf->db_out_order[1];
      conf->db_out_order[1]=db_linkname;
      for(it=2;it<conf->db_out_size;it++){
	dbtmp2=conf->db_out_order[it];
	conf->db_out_order[it]=dbtmp;
	dbtmp=dbtmp2;
      }
      conf->db_out_order[conf->db_out_size++]=dbtmp;
      conf->symlinks_found=1;
    }

    lnktmp=(char*)malloc(_POSIX_PATH_MAX+1);
    if(lnktmp==NULL){
      error(0,_("malloc failed in add_file_to_list()\n"));
      abort();
    }
 
    len=readlink(fil->filename,lnktmp,_POSIX_PATH_MAX+1);
    if(len == -1){
      error(0,"readlink failed in add_file_to_list(): %d,%s\n"
	    ,errno,strerror(errno));
      free(lnktmp);
      free(fil->filename);
      free(fil);
      *addok=RETFAIL;
      return listp;
    }
    lnkbuf=(char*)malloc(len+1);
    if(lnkbuf==NULL){
      error(0,_("malloc failed in add_file_to_list()\n"));
      abort();
    }

    strncpy(lnkbuf,lnktmp,len);
    lnkbuf[len]='\0';
    fil->linkname=lnkbuf;
    free(lnktmp);
    fil->attr|=DB_LINKNAME;
  }else {
    fil->linkname=NULL;
    /* Just remove linkname availability bit from this entry */
    fil->attr&=(~DB_LINKNAME); 
  }

  
  if(DB_INODE&fil->attr||DB_CHECKINODE&fil->attr){
    fil->inode=fs.st_ino;
  } else {
    fil->inode=0;
  }

  if(DB_UID&fil->attr) {
    fil->uid=fs.st_uid;
  }else {
    fil->uid=0;
  }

  if(DB_GID&fil->attr){
    fil->gid=fs.st_gid;
  }else{
    fil->gid=0;
  }

  fil->perm=fs.st_mode;

  if(DB_SIZE&fil->attr||DB_SIZEG&fil->attr){
    fil->size=fs.st_size;
  }else{
    fil->size=0;
  }
  
  if(DB_LNKCOUNT&fil->attr){
    fil->nlink=fs.st_nlink;
  }else {
    fil->nlink=0;
  }

  if(DB_MTIME&fil->attr){
    fil->mtime=fs.st_mtime;
  }else{
    fil->mtime=0;
  }

  if(DB_CTIME&fil->attr){
    fil->ctime=fs.st_ctime;
  }else{
    fil->ctime=0;
  }
  
  if(DB_ATIME&fil->attr){
    fil->atime=fs.st_atime;
  }else{
    fil->atime=0;
  }

  if(DB_BCOUNT&fil->attr){
    fil->bcount=fs.st_blocks;
  } else {
    fil->bcount=0;
  }

  
  if(S_ISDIR(fs.st_mode)||S_ISCHR(fs.st_mode)
     ||S_ISBLK(fs.st_mode)||S_ISFIFO(fs.st_mode)
     ||S_ISLNK(fs.st_mode)||S_ISSOCK(fs.st_mode)){
    
    fil->attr&=(~DB_MD5)&(~DB_SHA1)&(~DB_SHA256)&(~DB_SHA512)&(~DB_RMD160)&(~DB_TIGER)&(~DB_CRC32)&(~DB_HAVAL);
    
    fil->md5=NULL;
    fil->sha1=NULL;
    fil->sha256=NULL;
    fil->sha512=NULL;
    fil->tiger=NULL;
    fil->rmd160=NULL;
    fil->haval=NULL;
    fil->crc32=NULL;
#ifdef WITH_MHASH

    fil->attr&=(~DB_CRC32B)&(~DB_GOST)&(~DB_WHIRLPOOL);

    fil->crc32b=NULL;
    fil->gost=NULL;
    fil->whirlpool=NULL;
#endif
  }else {
    /* 1 if needs to be set
     * 0 otherwise */
    fil->md5=DB_MD5&fil->attr?(byte*)"":NULL;
    fil->sha1=DB_SHA1&fil->attr?(byte*)"":NULL;
    fil->tiger=DB_TIGER&fil->attr?(byte*)"":NULL;
    fil->rmd160=DB_RMD160&fil->attr?(byte*)"":NULL;
    fil->crc32=DB_CRC32&fil->attr?(byte*)"":NULL;
    fil->haval=DB_HAVAL&fil->attr?(byte*)"":NULL;
#ifdef WITH_MHASH
    fil->crc32b=DB_CRC32B&fil->attr?(byte*)"":NULL;
    fil->gost=DB_GOST&fil->attr?(byte*)"":NULL;
    fil->whirlpool=DB_WHIRLPOOL&fil->attr?(byte*)"":NULL;
#endif
  }

  xattrs2line(fil); /* NOTE ... this is a lie, code never gets here */
  
  listp=list_append(listp,(void*)fil);

  *addok=RETOK;
  return listp;
}

int check_list_for_match(list* rxrlist,char* text,DB_ATTR_TYPE* attr)
{
  list* r=NULL;
  int retval=1;
  for(r=rxrlist;r;r=r->next){
    if((retval=regexec((regex_t*)((rx_rule*)r->data)->crx,text,0,0,0))==0){
      *attr=((rx_rule*)r->data)->attr;
        error(231,"\"%s\" matches rule from line #%ld: %s\n",text,((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
      break;
    } else {
	error(232,"\"%s\" doesn't match rule from line #%ld: %s\n",text,((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
    }
  }
  return retval;
}

/* 
 * Function check_node_for_match()
 * calls itself recursively to go to the top and then back down.
 * uses check_list_for_match()
 * returns:
 * 0,  if a negative rule was matched 
 * 1,  if a selective rule was matched
 * 2,  if a equals rule was matched
 * retval if no rule was matched.
 * retval&3 if no rule was matched and first in the recursion
 * to keep state revat is orred with:
 * 4,  matched deeper on equ rule
 * 8,  matched deeper on sel rule
 *16,  this is a recursed call
 */    

int check_node_for_match(seltree*node,char*text,int retval,DB_ATTR_TYPE* attr)
{
  int top=0;
  
  if(node==NULL){
    return retval;
  }
  
  /* if this call is not recursive we check the equals list and we set top *
   * and retval so we know following calls are recursive */
  if(!(retval&16)){
    top=1;
    retval|=16;

    if(!check_list_for_match(node->equ_rx_lst,text,attr)){
      retval|=2|4;
    }
  }
  /* We'll use retval to pass information on whether to recurse 
   * the dir or not */


  /* If 4 and 8 are not set, we will check for matches */
  if(!(retval&(4|8))){
    if(!check_list_for_match(node->sel_rx_lst,text,attr))
      retval|=1|8;
  }

  /* Now let's check the ancestors */
  retval=check_node_for_match(node->parent,text,retval,attr);


  /* Negative regexps are the strongest so they are checked last */
  /* If this file is to be added */
  if(retval){
    if(!check_list_for_match(node->neg_rx_lst,text,attr)){
      retval=0;
    }
  }
  /* Now we discard the info whether a match was made or not *
   * and just return 0,1 or 2 */
  if(top){
    retval&=3;
  }
  return retval;
}

list* traverse_tree(seltree* tree,list* file_lst,DB_ATTR_TYPE attr)
{
  list* r=NULL;
  seltree* a=NULL;
  DIR* dirh=NULL;
  struct AIDE_DIRENT_TYPE* entp=NULL;
  struct AIDE_DIRENT_TYPE** resp=NULL;
  int rdres=0;
  int addfile=0;
  char* fullname=NULL;
  int e=0;
  DB_ATTR_TYPE matchattr=attr;
#  ifndef HAVE_READDIR_R
  long td=-1;
#  endif
  int addok=RETOK;

  /* Root is special and it must be checked on it's own. */
  if( tree->path[0]=='/' && tree->path[1]=='\0' ){
    addfile=check_node_for_match(tree,"/",0,&matchattr);
    if(addfile){
      error(240,"%s match=%d\n",fullname, addfile);
      file_lst=add_file_to_list(file_lst,"/",matchattr,&addok);
    }
  }

  if(!(dirh=opendir(tree->path))){
    error(3,"traverse_tree():%s: %s\n", strerror(errno),tree->path);
    return file_lst;
  }
  
#  ifdef HAVE_READDIR_R
  resp=(struct AIDE_DIRENT_TYPE**)
    malloc(sizeof(struct AIDE_DIRENT_TYPE)+_POSIX_PATH_MAX);
  entp=(struct AIDE_DIRENT_TYPE*)
    malloc(sizeof(struct AIDE_DIRENT_TYPE)+_POSIX_PATH_MAX);
  
  for(rdres=AIDE_READDIR_R_FUNC(dirh,entp,resp);
      (rdres==0&&(*resp)!=NULL);
      rdres=AIDE_READDIR_R_FUNC(dirh,entp,resp)){
#  else
#   ifdef HAVE_READDIR
  for(entp=AIDE_READDIR_FUNC(dirh);
      (entp!=NULL&&td!=telldir(dirh));
      entp=AIDE_READDIR_FUNC(dirh)){
    td=telldir(dirh);
#   else
#    error AIDE needs readdir or readdir_r
#   endif
#  endif

    if(strncmp(entp->d_name,".",1)==0){
      if(strncmp(entp->d_name,".",strlen(entp->d_name))==0)
	continue;
      if(strncmp(entp->d_name,"..",strlen(entp->d_name))==0)
	continue;
    }
    /* Construct fully qualified pathname for the file in question */
    fullname=(char*)
      malloc(sizeof(char)*(strlen(entp->d_name)+strlen(tree->path)+2));
    strncpy(fullname,tree->path,strlen(tree->path));
    if(strncmp(tree->path,"/",strlen(tree->path))!=0){
      strncpy(fullname+strlen(tree->path),"/",1);
      e=1;
    }else {
      e=0;
    }
    strncpy(fullname+strlen(tree->path)+e,entp->d_name,strlen(entp->d_name));
    fullname[(strlen(tree->path)+e+strlen(entp->d_name))]='\0';
    error(230,_("Checking %s for match\n"),fullname);
    if(attr){ /* This dir and all its subs are added by default */
      addfile=1;
      
      addfile=check_node_for_match(tree,fullname,addfile,&matchattr);
      
      if(addfile){
        error(240,"%s match=%d\n",fullname, addfile); 

	file_lst=add_file_to_list(file_lst,fullname,matchattr,&addok);
	if( !(addfile&2) && addok!=RETFAIL){
	  if(S_ISDIR(((db_line*)file_lst->header->tail->data)->perm_o)){
	    a=get_seltree_node(tree,
			       ((db_line*)file_lst->header->tail->data)
			       ->filename);
	    if(a==NULL){
	      a=new_seltree_node(tree,
				 ((db_line*)file_lst->header->tail->data)
				 ->filename,0,NULL);
	    }
	    file_lst=traverse_tree(a,file_lst,attr);
	  }
	}
      } else {
	error(230,_("File %s does not match\n"),fullname);
      }
    } else{ /* This dir is not added by default */
      addfile=0;
      
      addfile=check_node_for_match(tree,fullname,addfile,&matchattr);
      
      if(addfile){
        error(240,"%s match=%d\n",fullname, addfile); 
	file_lst=add_file_to_list(file_lst,fullname,matchattr,&addok);
	if(addfile!=2 && addok!=RETFAIL){
	  if(S_ISDIR(((db_line*)file_lst->header->tail->data)->perm_o)){
	    a=get_seltree_node(tree,
			       ((db_line*)file_lst->header->tail->data)
			       ->filename);
	    if(a==NULL){
	      a=new_seltree_node(tree,
				 ((db_line*)file_lst->header->tail->data)
				 ->filename,0,NULL);
	    }
	    file_lst=traverse_tree(a,file_lst,matchattr); 
	  }
	}
      } else {
	error(230,_("File %s does not match\n"),fullname);
      }
      
    }
    free(fullname);
  }

  if(closedir(dirh)==-1){
    error(0,"Closedir() failed for %s\n",tree->path);
  };
  
#  ifdef HAVE_READDIR_R
  free(resp);
  free(entp);
#  endif
  
  /* All childs are not necessarily checked yet */
  if(tree->childs!=NULL){
    for(r=tree->childs;r;r=r->next){
      if(!(((seltree*)r->data)->checked)) {
	file_lst=traverse_tree((seltree*)r->data,file_lst,attr);
      }
    }
  }
  tree->checked=1;
  
  return file_lst;
}

void print_tree(seltree* tree) {
  
  list* r;
  rx_rule* rxc;
  error(245,"tree: \"%s\"\n",tree->path);

  for(r=tree->sel_rx_lst;r!=NULL;r=r->next) {
	rxc=r->data;
	error(246,"%li\t%s\n",rxc->conf_lineno,rxc->rx);
  }
  for(r=tree->equ_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        error(246,"%li=\t%s\n",rxc->conf_lineno,rxc->rx);
  }
  
  for(r=tree->neg_rx_lst;r!=NULL;r=r->next) {
	  rxc=r->data;
	  error(246,"%li!\t%s\n",rxc->conf_lineno,rxc->rx);
  }
  
  for(r=tree->childs;r!=NULL;r=r->next) {
	print_tree(r->data);
  }
}

seltree* gen_tree(list* prxlist,list* nrxlist,list* erxlist)
{
  seltree* tree=NULL;

  tree=new_seltree_node(NULL,"/",0,NULL);

  gen_seltree(prxlist,tree,'s');
  gen_seltree(nrxlist,tree,'n');
  gen_seltree(erxlist,tree,'e');

  print_tree(tree);

  return tree;
}

list* gen_list(list* prxlist,list* nrxlist,list* erxlist)
{
  list* r=NULL;
  seltree* tree=NULL;
  
  tree=gen_tree(prxlist,nrxlist,erxlist);
  
  if(tree==NULL){
    return NULL;
  }
  
  
  r=traverse_tree(tree,NULL,0);
  
  return r;
}

/*
 * strip_dbline()
 * strips given dbline
 */
void strip_dbline(db_line* line,DB_ATTR_TYPE attr)
{
#define checked_free(x) do { free(x); x=NULL; } while (0)

  /* filename is always needed, hence it is never stripped */
  if(!(attr&DB_LINKNAME)){
    checked_free(line->linkname);
  }
  /* permissions are always needed for summarize_changes, hence it is never stripped */
  if(!(attr&DB_UID)){
    line->uid=0;
  }
  if(!(attr&DB_GID)){
    line->gid=0;
  }
  if(!(attr&DB_ATIME)){
    line->atime=0;
  }
  if(!(attr&DB_CTIME)){
    line->ctime=0;
  }
  if(!(attr&DB_MTIME)){
    line->mtime=0;
  }
  if(!(attr&DB_INODE)){
    line->inode=0;
  }
  if(!(attr&DB_LNKCOUNT)){
    line->nlink=0;
  }
  if(!(attr&DB_SIZE)&&!(attr&DB_SIZEG)){
    line->size=0;
  }
  if(!(attr&DB_BCOUNT)){
    line->bcount=0;
  }

  if(!(attr&DB_MD5)){
    checked_free(line->md5);
  }
  if(!(attr&DB_SHA1)){
    checked_free(line->sha1);
  }
  if(!(attr&DB_RMD160)){
    checked_free(line->rmd160);
  }
  if(!(attr&DB_TIGER)){
    checked_free(line->tiger);
  }
  if(!(attr&DB_HAVAL)){
    checked_free(line->haval);
  }
  if(!(attr&DB_CRC32)){
    checked_free(line->crc32);
  }
#ifdef WITH_MHASH
  if(!(attr&DB_CRC32B)){
    checked_free(line->crc32b);
  }
  if(!(attr&DB_GOST)){
    checked_free(line->gost);
  }
  if(!(attr&DB_WHIRLPOOL)){
    checked_free(line->whirlpool);
  }
#endif
  if(!(attr&DB_SHA256)){
    checked_free(line->sha256);
  }
  if(!(attr&DB_SHA512)){
    checked_free(line->sha512);
  }
#ifdef WITH_ACL
  if(!(attr&DB_ACL)){
    if (line->acl)
    {
      free(line->acl->acl_a);
      free(line->acl->acl_d);
    }
    checked_free(line->acl);
  }
#endif
#ifdef WITH_XATTR
  if(!(attr&DB_XATTRS)){
    if (line->xattrs)
      free(line->xattrs->ents);
    checked_free(line->xattrs);
  }
#endif
#ifdef WITH_SELINUX
  if(!(attr&DB_SELINUX)){
    checked_free(line->cntx);
  }
#endif
}

/*
 * add_file_to_tree
 * db = which db this file belongs to
 * status = what to do with this node
 * attr attributes to add 
 */
void add_file_to_tree(seltree* tree,db_line* file,int db,int status,
                      DB_ATTR_TYPE attr)
{
  seltree* node=NULL;
  DB_ATTR_TYPE localignorelist=0;
  DB_ATTR_TYPE ignorelist=0;

  node=get_seltree_node(tree,file->filename);

  if(!node){
    node=new_seltree_node(tree,file->filename,0,NULL);
  }
  
  if(file==NULL){
    error(0, "add_file_to_tree was called with NULL db_line\n");
  }

  /* add note to this node which db has modified it */
  node->checked|=db;

  /* add note whether to add this node's children */
  if(S_ISDIR(file->perm)&&status==NODE_ADD_CHILDREN){
    node->checked|=NODE_ADD_CHILDREN;
  }

  node->attr=attr;

  strip_dbline(file,attr);

  switch (db) {
  case DB_OLD: {
    node->old_data=file;
    break;
  }
  case DB_NEW: {
    node->new_data=file;
    break;
  }
  }
  /* We have a way to ignore some changes... */

  ignorelist=get_groupval("ignore_list");

  if (ignorelist==DB_ATTR_UNDEF) {
    ignorelist=0;
  }

  if((node->checked&DB_OLD)&&(node->checked&DB_NEW)){
    localignorelist=(node->new_data->attr^node->old_data->attr);
    if (localignorelist!=0) {
      error(2,"File %s in databases has different attributes, %llx,%llx\n",
            node->old_data->filename,node->old_data->attr,node->new_data->attr);
    }
    
    localignorelist|=ignorelist;

    /* Free the data if same else leave as is for report_tree */
    if(compare_dbline(node->old_data,node->new_data,localignorelist)==RETOK){
      /* FIXME this messes up the tree on SunOS. Don't know why. Fix
	 needed badly otherwise we leak memory like hell. */

      free_db_line(node->old_data);
      free(node->old_data);
      free_db_line(node->new_data);
      free(node->new_data);
      
      node->old_data=NULL;
      node->new_data=NULL;      
      node->checked-=(DB_OLD + DB_NEW); /* mark old and new files as released */          
    }
  }

  /* Do verification if file was moved only if we are asked for it.
   * old and new data are NULL only if file present in both DBs
   * and has not been changed.
   */
  if( (node->old_data!=NULL || node->new_data!=NULL) &&
    (file->attr & DB_CHECKINODE)) {
    /* Check if file was moved (same inode, different name in the other DB)*/
    db_line *oldData;
    db_line *newData;
    seltree* moved_node;

    moved_node=get_seltree_inode(tree,file,db==DB_OLD?DB_NEW:DB_OLD);
    if(!(moved_node == NULL || moved_node == node)) {
        /* There's mo match for inode or it matches the node with the same name.
         * In first case we don't have a match to compare with.
         * In the second - we already compared those files. */
      if(db == DB_NEW) {
        newData = node->new_data;
        oldData = moved_node->old_data;
      } else {
        newData = moved_node->new_data;
        oldData = node->old_data;
      }

      localignorelist=(oldData->attr^newData->attr)&(~(DB_NEWFILE|DB_RMFILE));

      if (localignorelist!=0) {
        error(5,"File \"%s\" \"%s\" in databases has different attributes (here3), %llx,%llx\n",
  	    newData->filename,oldData->filename,oldData->attr,newData->attr);
      }
    
      localignorelist|=ignorelist|DB_CTIME;

      /* Free the data if same else leave as is for report_tree */
      if(compare_dbline(oldData, newData, localignorelist)==RETOK){
        node->checked |= db==DB_NEW ? NODE_MOVED_IN : NODE_MOVED_OUT;
        moved_node->checked |= db==DB_NEW ? NODE_MOVED_OUT : NODE_MOVED_IN;
      }
    }
  }
  if( (db == DB_NEW) &&
      (node->new_data!=NULL) &&
      (file->attr & DB_NEWFILE) ){
	 node->checked|=NODE_ALLOW_NEW;
  }
  if( (db == DB_OLD) &&
      (node->old_data!=NULL) &&
      (file->attr & DB_RMFILE) ){
	  node->checked|=NODE_ALLOW_RM;
  }
}

int check_rxtree(char* filename,seltree* tree,DB_ATTR_TYPE* attr)
{
  int retval=0;
  char * tmp=NULL;
  char * parentname=NULL;
  seltree* pnode=NULL;

  parentname=strdup(filename);
  tmp=strrchr(parentname,'/');
  if(tmp!=parentname){
    *tmp='\0';
  }else {
    
    if(parentname[1]!='\0'){
      /* we are in the root dir */
      parentname[1]='\0';
    }
  }
  pnode=get_seltree_node(tree,parentname);

  if(pnode&&(pnode->checked&NODE_ADD_CHILDREN)){
    *attr=pnode->attr;
    retval=check_node_for_match(pnode,filename,1,attr);
  }else{
    *attr=0;
    retval=check_node_for_match(pnode,filename,0,attr);
  }
    
  free(parentname);

  return retval;
}

db_line* get_file_attrs(char* filename,DB_ATTR_TYPE attr)
{
  struct AIDE_STAT_TYPE fs;
  int sres=0;
  db_line* line=NULL;
  time_t cur_time;
  
  sres=AIDE_LSTAT_FUNC(filename,&fs);  
  if(sres==-1){
    char* er=strerror(errno);
    if (er==NULL) {
      error(0,"lstat() failed for %s. strerror failed for %i\n",filename,errno);
    } else {
      error(0,"lstat() failed for %s:%s\n",filename,strerror(errno));
    }
    return NULL;
  } 
  if(!(attr&DB_RDEV))
    fs.st_rdev=0;
  /*
    Get current time for future time notification.
   */
  cur_time=time(NULL);
  
  if (cur_time==(time_t)-1) {
    char* er=strerror(errno);
    if (er==NULL) {
      error(0,_("Can not get current time. strerror failed for %i\n"),errno);
    } else {
      error(0,_("Can not get current time with reason %s\n"),er);
    }
  } else {
    
    if(fs.st_atime>cur_time){
      error(CLOCK_SKEW,_("%s atime in future\n"),filename);
    }
    if(fs.st_mtime>cur_time){
      error(CLOCK_SKEW,_("%s mtime in future\n"),filename);
    }
    if(fs.st_ctime>cur_time){
      error(CLOCK_SKEW,_("%s ctime in future\n"),filename);
    }
  }
  
  /*
    Malloc if we have something to store..
  */
  
  line=(db_line*)malloc(sizeof(db_line));
  
  memset(line,0,sizeof(db_line));
  
  /*
    We want filename
  */

  line->attr=attr|DB_FILENAME;
  
  /*
    Just copy some needed fields.
  */
  
  line->filename=filename;
  line->perm_o=fs.st_mode;
  line->size_o=fs.st_size;
  line->linkname=NULL;

  /*
    Handle symbolic link
  */
  
  hsymlnk(line);
  
  /*
    Set normal part
  */
  
  fs2db_line(&fs,line);
  
  /*
    ACL stuff
  */
  acl2line(line);

  xattrs2line(line);

  selinux2line(line);

  if (attr&DB_HASHES && S_ISREG(fs.st_mode)) {
    calc_md(&fs,line);
  } else {
    /*
      We cannot calculate hash for nonfile.
      Mark it to attr.
    */
    no_hash(line);
  }
  
  return line;
}

void populate_tree(seltree* tree)
{
  /* FIXME this function could really use threads */
  int i=0;
  int add=0;
  db_line* old=NULL;
  db_line* new=NULL;
  int initdbwarningprinted=0;
  DB_ATTR_TYPE ignorelist=0;
  DB_ATTR_TYPE attr=0;
  seltree* node=NULL;
  
  /* With this we avoid unnecessary checking of removed files. */
  if(conf->action&DO_INIT){
    initdbwarningprinted=1;
  }
  
  /* We have a way to ignore some changes... */ 
  
  ignorelist=get_groupval("ignore_list");

  if (ignorelist==DB_ATTR_UNDEF) {
    ignorelist=0;
  }
  
  do{
    /* We add 100 files every turn from both inputs 
       if the other input is disk it is added one dir at a time until
       100 files have been added  
    */
    if((conf->action&DO_COMPARE)||(conf->action&DO_DIFF)){
      i=0;
      for(old=db_readline(DB_OLD);i<100&&old;){
	/* This is needed because check_rxtree assumes there is a parent
	   for the node for old->filename */
	if((node=get_seltree_node(tree,old->filename))==NULL){
	  node=new_seltree_node(tree,old->filename,0,NULL);
	}
	if((add=check_rxtree(old->filename,tree,&attr))>0){
	  add_file_to_tree(tree,old,DB_OLD,0,attr);
	  i++;
	}else{
          free_db_line(old);
          free(old);
          old=NULL;
          if(!initdbwarningprinted){
	    error(3,_("WARNING: Old db contains a file that shouldn\'t be there, run --init or --update\n"));
	    initdbwarningprinted=1;
	  }
	}
	if(i<100){
	  old=db_readline(DB_OLD);
	}
      }
    }
    if(conf->action&DO_DIFF){
      i=0;
      for(new=db_readline(DB_NEW);i<100&&new;){
	/* FIXME add support config checking at this stage 
	   config check = add only those files that match config rxs
	   make this configurable
	   Only configurability is not implemented.
	*/
	/* This is needed because check_rxtree assumes there is a parent
	   for the node for old->filename */
	if((node=get_seltree_node(tree,new->filename))==NULL){
	  node=new_seltree_node(tree,new->filename,0,NULL);
	}
	if((add=check_rxtree(new->filename,tree,&attr))>0){
	  add_file_to_tree(tree,new,DB_NEW,0,attr);
	  i++;
	} else {
          free_db_line(new);
          free(new);
          new=NULL;
	}
	if(i<100){
	  new=db_readline(DB_NEW);
	}
      }
    }
    
    if((conf->action&DO_INIT)||(conf->action&DO_COMPARE)){
      /* FIXME  */
      new=NULL;
      i=0;
      for(new=db_readline(DB_DISK);i<100&&new;){
	/* Write to db only if needed */
	if(conf->action&DO_INIT){
	  db_writeline(new,conf);
	}
	/* Populate tree only if it is needed later */
	if(conf->action&DO_COMPARE){
	  if((add=check_rxtree(new->filename,tree,&attr))>0){
	    add_file_to_tree(tree,new,DB_NEW,0,attr);
	    i++;
	  }
	}
	if((conf->action&DO_INIT)&&!(conf->action&DO_COMPARE)){
	  free_db_line(new);
          free(new);
          new=NULL;
	}
	if(i<100){
	  new=db_readline(DB_DISK);
	}
      }

    }
  }while(old || new);
}

void hsymlnk(db_line* line) {
  
  if((S_ISLNK(line->perm_o))){
    int len=0;
#ifdef WITH_ACL   
    if(conf->no_acl_on_symlinks!=1) {
      line->attr&=(~DB_ACL);
    }
#endif   
    
    if(conf->warn_dead_symlinks==1) {
      struct AIDE_STAT_TYPE fs;
      int sres;
      sres=AIDE_STAT_FUNC(line->filename,&fs);
      if (sres!=0 && sres!=EACCES) {
	error(4,"Dead symlink detected at %s\n",line->filename);
      }
      if(!(line->attr&DB_RDEV))
	fs.st_rdev=0;
    }
    /*
      Is this valid?? 
      No, We should do this elsewhere.
    */
    line->linkname=(char*)malloc(_POSIX_PATH_MAX+1);
    if(line->linkname==NULL){
      error(0,_("malloc failed in add_file_to_list()\n"));
      abort();
    }
    
    /*
      Remember to nullify the buffer, because man page says
      
      readlink  places the contents of the symbolic link path in
      the buffer buf, which has size bufsiz.  readlink does  not
      append  a NUL character to buf.  It will truncate the con-
      tents (to a length of  bufsiz  characters),  in  case  the
      buffer is too small to hold all of the contents.
      
    */
    memset(line->linkname,0,_POSIX_PATH_MAX+1);
    
    len=readlink(line->filename,line->linkname,_POSIX_PATH_MAX+1);
    
    /*
     * We use realloc :)
     */
    line->linkname=realloc(line->linkname,len+1);
  } else {
      line->attr&=(~DB_LINKNAME);
  }
  
}
// vi: ts=8 sw=2
