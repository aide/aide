/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2009-2012,2015,2016 Rami Lehti,Pablo Virolainen,
 * Mike Markley, Richard van den Berg, Hannes von Haugwitz
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
#include <pcre.h>

#include "report.h"
#include "list.h"
#include "gen_list.h"
#include "seltree.h"
#include "db.h"
#include "db_config.h"
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

static DB_ATTR_TYPE get_special_report_group(char* group) {
    DB_ATTR_TYPE attr = get_groupval(group);
    return attr==DB_ATTR_UNDEF?0:attr;
}

static int bytecmp(byte *b1, byte *b2, size_t len) {
  return strncmp((char *)b1, (char *)b2, len);
}

static int has_str_changed(char* old,char* new) {
    return (((old!=NULL && new!=NULL) &&
                strcmp(old,new)!=0 ) ||
            ((old!=NULL && new==NULL) ||
             (old==NULL && new!=NULL)));
}

static int has_md_changed(byte* old,byte* new,int len) {
    error(255,"Debug, has_md_changed %p %p\n",old,new);
    return (((old!=NULL && new!=NULL) &&
                (bytecmp(old,new,len)!=0)) ||
            ((old!=NULL && new==NULL) ||
             (old==NULL && new!=NULL)));
}

#ifdef WITH_ACL
#ifdef WITH_SUN_ACL
static int compare_single_acl(aclent_t* a1,aclent_t* a2) {
  if (a1->a_type!=a2->a_type ||
      a1->a_id!=a2->a_id ||
      a1->a_perm!=a2->a_perm) {
    return RETFAIL;
  }
  return RETOK;
}
#endif
static int has_acl_changed(acl_type* old, acl_type* new) {
#ifdef WITH_SUN_ACL
    int i;
#endif
    if (old==NULL && new==NULL) {
        return RETOK;
    }
    if (old==NULL || new==NULL) {
        return RETFAIL;
    }
#ifdef WITH_POSIX_ACL
    if ((!old->acl_a != !new->acl_a)
            || (!old->acl_d != !new->acl_d)
            || (old->acl_a && strcmp(old->acl_a, new->acl_a))
            || (old->acl_d && strcmp(old->acl_d, new->acl_d))){
        return RETFAIL;
    }
#endif
#ifdef WITH_SUN_ACL
    if (old->entries!=new->entries) {
        return RETFAIL;
    }
    /* Sort em up. */
    aclsort(old->entries,0,old->acl);
    aclsort(new->entries,0,new->acl);
    for(i=0;i<old->entries;i++){
        if (compare_single_acl(old->acl+i,new->acl+i)==RETFAIL) {
            return RETFAIL;
        }
    }
#endif
    return RETOK;
}
#endif

#ifdef WITH_XATTR
static int cmp_xattr_node(const void *c1, const void *c2)
{
  const xattr_node *x1 = c1;
  const xattr_node *x2 = c2;

  return (strcmp(x1->key, x2->key));
}
static int have_xattrs_changed(xattrs_type* x1,xattrs_type* x2) {
  size_t num = 0;

  if (x1 && (x1->num == 0)) x1 = NULL;
  if (x2 && (x2->num == 0)) x2 = NULL;

  if (x1==NULL && x2==NULL) {
    return RETOK;
  }
  if (x1==NULL || x2==NULL) {
    return RETFAIL;
  }

  if (x1->num != x2->num) {
    return RETFAIL;
  }

  qsort(x1->ents, x1->num, sizeof(xattr_node), cmp_xattr_node);
  qsort(x2->ents, x2->num, sizeof(xattr_node), cmp_xattr_node);

  while (num++ < x1->num) {
    const char *x1key = NULL;
    const byte *x1val = NULL;
    size_t x1vsz = 0;
    const char *x2key = NULL;
    const byte *x2val = NULL;
    size_t x2vsz = 0;

    x1key = x1->ents[num - 1].key;
    x1val = x1->ents[num - 1].val;
    x1vsz = x1->ents[num - 1].vsz;

    x2key = x2->ents[num - 1].key;
    x2val = x2->ents[num - 1].val;
    x2vsz = x2->ents[num - 1].vsz;

    if (strcmp(x1key, x2key) ||
        x1vsz != x2vsz ||
        memcmp(x1val, x2val, x1vsz))
      return RETFAIL;
  }

  return RETOK;
}
#endif

#ifdef WITH_E2FSATTRS
static int has_e2fsattrs_changed(unsigned long old, unsigned long new) {
    return (~(conf->report_ignore_e2fsattrs)&(old^new));
}
#endif

/*
 * Returns the changed attributes for two database lines.
 *
 * Attributes are only compared if they exist in both database lines.
*/
static DB_ATTR_TYPE get_changed_attributes(db_line* l1,db_line* l2) {

#define easy_compare(a,b) \
    if((a&l1->attr && (a&l2->attr)) && l1->b!=l2->b){\
        ret|=a;\
    }

#define easy_md_compare(a,b,c) \
    if((a&l1->attr && (a&l2->attr)) && has_md_changed(l1->b,l2->b, c)){ \
        ret|=a; \
    }

#define easy_function_compare(a,b,c) \
    if((a&l1->attr && (a&l2->attr)) && c(l1->b,l2->b)){ \
        ret|=a; \
    }

    DB_ATTR_TYPE ret=0;

    if ((DB_FTYPE&l1->attr && DB_FTYPE&l2->attr) && (l1->perm&S_IFMT)!=(l2->perm&S_IFMT)) { ret|=DB_FTYPE; }
    easy_function_compare(DB_LINKNAME,linkname,has_str_changed);
    if ((DB_SIZEG&l1->attr && DB_SIZEG&l2->attr) && l1->size>l2->size){ ret|=DB_SIZEG; }
    easy_compare(DB_SIZE,size);
    easy_compare(DB_BCOUNT,bcount);
    easy_compare(DB_PERM,perm);
    easy_compare(DB_UID,uid);
    easy_compare(DB_GID,gid);
    easy_compare(DB_ATIME,atime);
    easy_compare(DB_MTIME,mtime);
    easy_compare(DB_CTIME,ctime);
    easy_compare(DB_INODE,inode);
    easy_compare(DB_LNKCOUNT,nlink);

    easy_md_compare(DB_MD5,md5,HASH_MD5_LEN);
    easy_md_compare(DB_SHA1,sha1,HASH_SHA1_LEN);
    easy_md_compare(DB_RMD160,rmd160,HASH_RMD160_LEN);
    easy_md_compare(DB_TIGER,tiger,HASH_TIGER_LEN);
    easy_md_compare(DB_SHA256,sha256,HASH_SHA256_LEN);
    easy_md_compare(DB_SHA512,sha512,HASH_SHA512_LEN);

#ifdef WITH_MHASH
    easy_md_compare(DB_CRC32,crc32,HASH_CRC32_LEN);
    easy_md_compare(DB_HAVAL,haval,HASH_HAVAL256_LEN);
    easy_md_compare(DB_GOST,gost,HASH_GOST_LEN);
    easy_md_compare(DB_CRC32B,crc32b,HASH_CRC32B_LEN);
    easy_md_compare(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN);
#endif

#ifdef WITH_ACL
    easy_function_compare(DB_ACL,acl,has_acl_changed);
#endif
#ifdef WITH_XATTR
    easy_function_compare(DB_XATTRS,xattrs,have_xattrs_changed);
#endif
#ifdef WITH_SELINUX
    easy_function_compare(DB_SELINUX,cntx,has_str_changed);
#endif
#ifdef WITH_E2FSATTRS
    easy_function_compare(DB_E2FSATTRS,e2fsattrs,has_e2fsattrs_changed);
#endif
    error(255,"Debug, changed attributes for entry %s [%llx %llx]: %llx\n", l1->filename,l1->attr,l2->attr,ret);
    return ret;
}

int compare_node_by_path(const void *n1, const void *n2)
{
    const seltree *x1 = n1;
    const seltree *x2 = n2;
    return strcmp(x1->path, x2->path);
}

char* strrxtok(char* rx)
{
  char*p=NULL;
  char*t=NULL;
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
	t=strdup(p);
	strcpy(p+i,t+i+1);
	free(t);
	t=NULL;
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
    parent->childs=list_sorted_insert(parent->childs,(void*)node, compare_node_by_path);
    node->parent=parent;
  }else {
    node->parent=NULL;
  }
  return node;
}

void gen_seltree(list* rxlist,seltree* tree,char type)
{
  pcre*        rxtmp = NULL;
  const char*  pcre_error;
  int          pcre_erroffset;

  seltree*     curnode = NULL;
  list*        r       = NULL;
  char*        rxtok   = NULL;
  rx_rule*     rxc     = NULL;

  for(r=rxlist;r;r=r->next){
    rx_rule* curr_rule = (rx_rule*)r->data;
    
    
    rxtok=strrxtok(curr_rule->rx);
    curnode=get_seltree_node(tree,rxtok);

    if(curnode==NULL){
      curnode=new_seltree_node(tree,rxtok,1,curr_rule);
    }

    error(240,"Handling %s with %c \"%s\" with node \"%s\"\n",rxtok,type,curr_rule->rx,curnode->path);

    if((rxtmp=pcre_compile(curr_rule->rx, PCRE_ANCHORED, &pcre_error, &pcre_erroffset, NULL)) == NULL) {
      error(0,_("Error in regexp '%s' at %i: %s\n"),curr_rule->rx, pcre_erroffset, pcre_error);
    }else{
      /* replace regexp text with regexp compiled */
      rxc=(rx_rule*)malloc(sizeof(rx_rule));
      /* and copy the rest */
      rxc->rx=curr_rule->rx;
      rxc->crx=rxtmp;
      rxc->attr=curr_rule->attr;
      rxc->conf_lineno=curr_rule->conf_lineno;
      rxc->restriction=curr_rule->restriction;

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

static RESTRICTION_TYPE get_file_type(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return RESTRICTION_FT_REG;
        case S_IFDIR: return RESTRICTION_FT_DIR;
#ifdef S_IFIFO
        case S_IFIFO: return RESTRICTION_FT_FIFO;
#endif
        case S_IFLNK: return RESTRICTION_FT_LNK;
        case S_IFBLK: return RESTRICTION_FT_BLK;
        case S_IFCHR: return RESTRICTION_FT_CHR;
#ifdef S_IFSOCK
        case S_IFSOCK: return RESTRICTION_FT_SOCK;
#endif
#ifdef S_IFDOOR
        case S_IFDOOR: return RESTRICTION_FT_DOOR;
#endif
#ifdef S_IFDOOR
        case S_IFPORT: return RESTRICTION_FT_PORT;
#endif
        default: return RESTRICTION_NULL;
    }
}

static int check_list_for_match(list* rxrlist,char* text,DB_ATTR_TYPE* attr, RESTRICTION_TYPE file_type)
{
  list* r=NULL;
  int retval=1;
  int pcre_retval;
  pcre_extra *pcre_extra = NULL;
  for(r=rxrlist;r;r=r->next){
      pcre_retval=pcre_exec((pcre*)((rx_rule*)r->data)->crx, pcre_extra, text, strlen(text), 0, PCRE_PARTIAL_SOFT, NULL, 0);
      if (pcre_retval >= 0) {
              error(231,"\"%s\" matches (pcre_exec return value: %i) rule from line #%ld: %s\n",text, pcre_retval, ((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
          if (!((rx_rule*)r->data)->restriction || file_type&((rx_rule*)r->data)->restriction) {
              *attr=((rx_rule*)r->data)->attr;
              error(231,"\"%s\" matches restriction (%u) for rule from line #%ld: %s\n",text, ((rx_rule*)r->data)->restriction, ((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
              return 0;
          } else {
              error(232,"\"%s\" doesn't match restriction (%u) for rule from line #%ld: %s\n",text, ((rx_rule*)r->data)->restriction, ((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
              retval=-1;
          }
      } else if (pcre_retval == PCRE_ERROR_PARTIAL) {
          error(232,"\"%s\" PARTIAL matches (pcre_exec return value: %i) rule from line #%ld: %s\n",text, pcre_retval, ((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
          retval=-1;
      } else {
          error(232,"\"%s\" doesn't match (pcre_exec return value: %i) rule from line #%ld: %s\n",text, pcre_retval,((rx_rule*)r->data)->conf_lineno,((rx_rule*)r->data)->rx);
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

static int check_node_for_match(seltree*node,char*text, mode_t perm, int retval,DB_ATTR_TYPE* attr)
{
  int top=0;
  RESTRICTION_TYPE file_type;
  
  if(node==NULL){
    return retval;
  }
  
   file_type = get_file_type(perm);

  /* if this call is not recursive we check the equals list and we set top *
   * and retval so we know following calls are recursive */
  if(!(retval&16)){
    top=1;
    retval|=16;

      switch (check_list_for_match(node->equ_rx_lst, text, attr, file_type)) {
          case 0: {
              error(220, "check_node_for_match: equal match for '%s'\n", text);
              retval|=2|4;
              break;
          }
          case -1: {
           if(S_ISDIR(perm) && get_seltree_node(node,text)==NULL) {
               error(220, "check_node_for_match: creating new seltree node for '%s'\n", text);
               new_seltree_node(node,text,0,NULL);
           }
           break;
          }
    }
  }
  /* We'll use retval to pass information on whether to recurse 
   * the dir or not */


  /* If 4 and 8 are not set, we will check for matches */
  if(!(retval&(4|8))){
      switch (check_list_for_match(node->sel_rx_lst, text, attr, file_type)) {
          case 0: {
              error(220, "check_node_for_match: selective match for '%s'\n", text);
              retval|=1|8;
              break;
          }
          case -1: {
           if(S_ISDIR(perm) && get_seltree_node(node,text)==NULL) {
               error(220, "check_node_for_match: creating new seltree node for '%s'\n", text);
               new_seltree_node(node,text,0,NULL);
           }
           break;
          }
      }
  }

  /* Now let's check the ancestors */
  retval=check_node_for_match(node->parent,text, perm, retval,attr);


  /* Negative regexps are the strongest so they are checked last */
  /* If this file is to be added */
  if(retval){
    if(!check_list_for_match(node->neg_rx_lst, text, attr, file_type)){
      error(220, "check_node_for_match: negative match for '%s'\n", text);
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

void print_tree(seltree* tree) {
  
  list* r;
  rx_rule* rxc;
  error(220,"tree: \"%s\"\n",tree->path);

  for(r=tree->sel_rx_lst;r!=NULL;r=r->next) {
	rxc=r->data;
	error(220,"%li\t%s\n",rxc->conf_lineno,rxc->rx);
  }
  for(r=tree->equ_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        error(220,"%li=\t%s\n",rxc->conf_lineno,rxc->rx);
  }
  
  for(r=tree->neg_rx_lst;r!=NULL;r=r->next) {
	  rxc=r->data;
	  error(220,"%li!\t%s\n",rxc->conf_lineno,rxc->rx);
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

/*
 * strip_dbline()
 * strips given dbline
 */
void strip_dbline(db_line* line)
{
#define checked_free(x) do { free(x); x=NULL; } while (0)

    DB_ATTR_TYPE attr = line->attr;

  /* filename is always needed, hence it is never stripped */
  if(!(attr&DB_LINKNAME)){
    checked_free(line->linkname);
  }
  /* permissions are always needed for file type detection, hence they are
   * never stripped */
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
  /* inode is always needed for ignoring changed filename, hence it is
   * never stripped */
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
  /* e2fsattrs is stripped within e2fsattrs2line in do_md */
}

/*
 * add_file_to_tree
 * db = which db this file belongs to
 * attr attributes to add
 */
static void add_file_to_tree(seltree* tree,db_line* file,int db,
                      DB_ATTR_TYPE attr)
{
  seltree* node=NULL;
  DB_ATTR_TYPE localignorelist=0;
  DB_ATTR_TYPE ignored_added_attrs, ignored_removed_attrs, ignored_changed_attrs;

  node=get_seltree_node(tree,file->filename);

  if(!node){
    node=new_seltree_node(tree,file->filename,0,NULL);
  }
  
  if(file==NULL){
    error(0, "add_file_to_tree was called with NULL db_line\n");
  }

  /* add note to this node which db has modified it */
  node->checked|=db;

  node->attr=attr;

  strip_dbline(file);

  switch (db) {
  case DB_OLD: {
    node->old_data=file;
    break;
  }
  case DB_NEW: {
    node->new_data=file;
    break;
  }
  case DB_OLD|DB_NEW: {
    node->new_data=file;
    if(conf->action&DO_INIT) {
        node->checked|=NODE_FREE;
    } else {
        free_db_line(node->new_data);
        free(node->new_data);
        node->new_data=NULL;
    }
    return;
  }
  }
  /* We have a way to ignore some changes... */
  ignored_added_attrs = get_special_report_group("report_ignore_added_attrs");
  ignored_removed_attrs = get_special_report_group("report_ignore_removed_attrs");
  ignored_changed_attrs = get_special_report_group("report_ignore_changed_attrs");

  if((node->checked&DB_OLD)&&(node->checked&DB_NEW)){
      if (((node->old_data)->attr&~((node->new_data)->attr)&~(ignored_removed_attrs))|(~((node->old_data)->attr)&(node->new_data)->attr&~(ignored_added_attrs))) {
      error(2,"Entry %s in databases has different attributes: %llx %llx\n",
            node->old_data->filename,node->old_data->attr,node->new_data->attr);
    }

    node->changed_attrs=get_changed_attributes(node->old_data,node->new_data);
    /* Free the data if same else leave as is for report_tree */
    if((~(ignored_changed_attrs)&node->changed_attrs)==RETOK){
      /* FIXME this messes up the tree on SunOS. Don't know why. Fix
	 needed badly otherwise we leak memory like hell. */

      node->changed_attrs=0;

      free_db_line(node->old_data);
      free(node->old_data);
      node->old_data=NULL;

      /* Free new data if not needed for write_tree */
      if(conf->action&DO_INIT) {
          node->checked|=NODE_FREE;
      } else {
          free_db_line(node->new_data);
          free(node->new_data);
          node->new_data=NULL;
      }
      return;
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

      localignorelist=(oldData->attr^newData->attr)&(~(DB_NEWFILE|DB_RMFILE|DB_CHECKINODE));

      if (localignorelist!=0) {
         error(220,"Ignoring moved entry (\"%s\" [%llx] => \"%s\" [%llx]) due to different attributes: %llx\n",
                 oldData->filename, oldData->attr, newData->filename, newData->attr, localignorelist);
     } else {
         /* Free the data if same else leave as is for report_tree */
         if ((get_changed_attributes(oldData, newData)&~(ignored_changed_attrs|DB_CTIME)) == RETOK) {
             node->checked |= db==DB_NEW ? NODE_MOVED_IN : NODE_MOVED_OUT;
             moved_node->checked |= db==DB_NEW ? NODE_MOVED_OUT : NODE_MOVED_IN;
             error(220,_("Entry was moved: %s [%llx] => %s [%llx]\n"),
                     oldData->filename , oldData->attr, newData->filename, newData->attr);
         } else {
             error(220,"Ignoring moved entry (\"%s\" => \"%s\") because the entries mismatch\n",
                     oldData->filename, newData->filename);
         }
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

int check_rxtree(char* filename,seltree* tree,DB_ATTR_TYPE* attr, mode_t perm)
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

  if(conf->limit!=NULL) {
      retval=pcre_exec(conf->limit_crx, NULL, filename, strlen(filename), 0, PCRE_PARTIAL_SOFT, NULL, 0);
      if (retval >= 0) {
          error(220, "check_rxtree: %s does match limit: %s\n", filename, conf->limit);
      } else if (retval == PCRE_ERROR_PARTIAL) {
          error(220, "check_rxtree: %s does PARTIAL match limit: %s\n", filename, conf->limit);
          if(S_ISDIR(perm) && get_seltree_node(tree,filename)==NULL){
              error(220, "check_rxtree: creating new seltree node for '%s'\n", filename);
              new_seltree_node(tree,filename,0,NULL);
          }
          return -1;
      } else {
          error(220, "check_rxtree: %s does NOT match limit: %s\n", filename, conf->limit);
          return -2;
      }
  }

  pnode=get_seltree_node(tree,parentname);

  *attr=0;
  retval=check_node_for_match(pnode,filename, perm, 0,attr);
    
  free(parentname);

  return retval;
}

db_line* get_file_attrs(char* filename,DB_ATTR_TYPE attr, struct AIDE_STAT_TYPE *fs)
{
  db_line* line=NULL;
  time_t cur_time;

  if(!(attr&DB_RDEV))
    fs->st_rdev=0;
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
    
    if(fs->st_atime>cur_time){
      error(CLOCK_SKEW,_("%s atime in future\n"),filename);
    }
    if(fs->st_mtime>cur_time){
      error(CLOCK_SKEW,_("%s mtime in future\n"),filename);
    }
    if(fs->st_ctime>cur_time){
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
  
  line->fullpath=filename;
  line->filename=&filename[conf->root_prefix_length];
  line->perm_o=fs->st_mode;
  line->size_o=fs->st_size;
  line->linkname=NULL;

  /*
    Handle symbolic link
  */
  
  hsymlnk(line);
  
  /*
    Set normal part
  */
  
  fs2db_line(fs,line);
  
  /*
    ACL stuff
  */

#ifdef WITH_ACL
  acl2line(line);
#endif

#ifdef WITH_XATTR
  xattrs2line(line);
#endif

#ifdef WITH_SELINUX
  selinux2line(line);
#endif

#ifdef WITH_E2FSATTRS
    e2fsattrs2line(line);
#endif

  if (attr&DB_HASHES && S_ISREG(fs->st_mode)) {
    calc_md(fs,line);
  } else {
    /*
      We cannot calculate hash for nonfile.
      Mark it to attr.
    */
    no_hash(line);
  }
  
  return line;
}

static void write_tree(seltree* node) {
    list* r=NULL;
    if (node->checked&DB_NEW) {
        db_writeline(node->new_data,conf);
        if (node->checked&NODE_FREE) {
            free_db_line(node->new_data);
            free(node->new_data);
            node->new_data=NULL;
        }
    }
    for (r=node->childs;r;r=r->next) {
        write_tree((seltree*)r->data);
    }
}

void populate_tree(seltree* tree)
{
  /* FIXME this function could really use threads */
  int add=0;
  db_line* old=NULL;
  db_line* new=NULL;
  int initdbwarningprinted=0;
  DB_ATTR_TYPE attr=0;
  seltree* node=NULL;
  
  /* With this we avoid unnecessary checking of removed files. */
  if(conf->action&DO_INIT){
    initdbwarningprinted=1;
  }
  
    if(conf->action&DO_DIFF){
      while((new=db_readline(DB_NEW)) != NULL){
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
	if((add=check_rxtree(new->filename,tree,&attr, new->perm))>0){
	  add_file_to_tree(tree,new,DB_NEW,attr);
	} else {
          free_db_line(new);
          free(new);
          new=NULL;
	}
      }
    }
    
    if((conf->action&DO_INIT)||(conf->action&DO_COMPARE)){
      /* FIXME  */
      new=NULL;
      while((new=db_readline(DB_DISK)) != NULL) {
	    add_file_to_tree(tree,new,DB_NEW,attr);
      }
    }
    if((conf->action&DO_COMPARE)||(conf->action&DO_DIFF)){
            while((old=db_readline(DB_OLD)) != NULL) {
                /* This is needed because check_rxtree assumes there is a parent
                   for the node for old->filename */
                if((node=get_seltree_node(tree,old->filename))==NULL){
                    node=new_seltree_node(tree,old->filename,0,NULL);
                }
                add=check_rxtree(old->filename,tree,&attr, old->perm);
                if(add > 0) {
                    add_file_to_tree(tree,old,DB_OLD,attr);
                } else if (conf->limit!=NULL && add < 0) {
                    add_file_to_tree(tree,old,DB_OLD|DB_NEW,attr);
                }else{
                    free_db_line(old);
                    free(old);
                    old=NULL;
                    if(!initdbwarningprinted){
                        error(3,_("WARNING: Old db contains a entry that shouldn\'t be there, run --init or --update\n"));
                        initdbwarningprinted=1;
                    }
                }
            }
    }
    if(conf->action&DO_INIT) {
        write_tree(tree);
    }
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
      sres=AIDE_STAT_FUNC(line->fullpath,&fs);
      if (sres!=0 && sres!=EACCES) {
	error(4,"Dead symlink detected at %s\n",line->fullpath);
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
      error(0,_("malloc failed in hsymlnk()\n"));
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
    
    len=readlink(line->fullpath,line->linkname,_POSIX_PATH_MAX+1);
    
    /*
     * We use realloc :)
     */
    line->linkname=realloc(line->linkname,len+1);
  } else {
      line->attr&=(~DB_LINKNAME);
  }
  
}
// vi: ts=8 sw=2
