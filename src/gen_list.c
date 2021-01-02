/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2009-2012,2015,2016,2019-2021 Rami Lehti,
 * Pablo Virolainen, Mike Markley, Richard van den Berg, Hannes von Haugwitz
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

#include "attributes.h"
#include "list.h"
#include "gen_list.h"
#include "seltree.h"
#include "db.h"
#include "db_config.h"
#include "db_disk.h"
#include "db_lex.h"
#include "commandconf.h"
#include "log.h"
#include "util.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#ifdef WITH_MHASH
#include <mhash.h>
#endif
#include "md.h"
#include "do_md.h"

void hsymlnk(db_line* line);
void fs2db_line(struct stat* fs,db_line* line);
void calc_md(struct stat* old_fs,db_line* line);
void no_hash(db_line* line);

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
    log_msg(LOG_LEVEL_TRACE," has_md_changed %p %p",old,new);
    return (((old!=NULL && new!=NULL) &&
                (bytecmp(old,new,len)!=0)) ||
            ((old!=NULL && new==NULL) ||
             (old==NULL && new!=NULL)));
}

#ifdef WITH_ACL
static int has_acl_changed(acl_type* old, acl_type* new) {
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
    return (old^new);
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

#define easy_function_compare(a,b,c) \
    if((a&l1->attr && (a&l2->attr)) && c(l1->b,l2->b)){ \
        ret|=a; \
    }

    DB_ATTR_TYPE ret=0;

    if ((ATTR(attr_ftype)&l1->attr && ATTR(attr_ftype)&l2->attr) && (l1->perm&S_IFMT)!=(l2->perm&S_IFMT)) { ret|=ATTR(attr_ftype); }
    easy_function_compare(ATTR(attr_linkname),linkname,has_str_changed);
    if ((ATTR(attr_sizeg)&l1->attr && ATTR(attr_sizeg)&l2->attr) && l1->size>l2->size){ ret|=ATTR(attr_sizeg); }
    easy_compare(ATTR(attr_size),size);
    easy_compare(ATTR(attr_bcount),bcount);
    easy_compare(ATTR(attr_perm),perm);
    easy_compare(ATTR(attr_uid),uid);
    easy_compare(ATTR(attr_gid),gid);
    easy_compare(ATTR(attr_atime),atime);
    easy_compare(ATTR(attr_mtime),mtime);
    easy_compare(ATTR(attr_ctime),ctime);
    easy_compare(ATTR(attr_inode),inode);
    easy_compare(ATTR(attr_linkcount),nlink);

  for (int i = 0 ; i < num_hashes ; ++i) {
    DB_ATTR_TYPE attr = ATTR(hashsums[i].attribute);
    if((attr&l1->attr && (attr&l2->attr)) && has_md_changed(l1->hashsums[i],l2->hashsums[i], hashsums[i].length)){
        ret|=attr;
    }
  }

#ifdef WITH_ACL
    easy_function_compare(ATTR(attr_acl),acl,has_acl_changed);
#endif
#ifdef WITH_XATTR
    easy_function_compare(ATTR(attr_xattrs),xattrs,have_xattrs_changed);
#endif
#ifdef WITH_SELINUX
    easy_function_compare(ATTR(attr_selinux),cntx,has_str_changed);
#endif
#ifdef WITH_E2FSATTRS
    easy_function_compare(ATTR(attr_e2fsattrs),e2fsattrs,has_e2fsattrs_changed);
#endif
#ifdef WITH_CAPABILITIES
    easy_function_compare(ATTR(attr_capabilities),capabilities,has_str_changed);
#endif

    return ret;
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






/*
 * strip_dbline()
 * strips given dbline
 */
void strip_dbline(db_line* line)
{
#define checked_free(x) do { free(x); x=NULL; } while (0)

    DB_ATTR_TYPE attr = line->attr;

  /* filename is always needed, hence it is never stripped */
  if(!(attr&ATTR(attr_linkname))){
    checked_free(line->linkname);
  }
  /* permissions are always needed for file type detection, hence they are
   * never stripped */
  if(!(attr&ATTR(attr_uid))){
    line->uid=0;
  }
  if(!(attr&ATTR(attr_gid))){
    line->gid=0;
  }
  if(!(attr&ATTR(attr_atime))){
    line->atime=0;
  }
  if(!(attr&ATTR(attr_ctime))){
    line->ctime=0;
  }
  if(!(attr&ATTR(attr_mtime))){
    line->mtime=0;
  }
  /* inode is always needed for ignoring changed filename, hence it is
   * never stripped */
  if(!(attr&ATTR(attr_linkcount))){
    line->nlink=0;
  }
  if(!(attr&ATTR(attr_size))&&!(attr&ATTR(attr_sizeg))){
    line->size=0;
  }
  if(!(attr&ATTR(attr_bcount))){
    line->bcount=0;
  }

  for (int i = 0 ; i < num_hashes ; ++i) {
      if(!(attr&ATTR(hashsums[i].attribute))){
          checked_free(line->hashsums[i]);
      }
  }

#ifdef WITH_ACL
  if(!(attr&ATTR(attr_acl))){
    if (line->acl)
    {
      free(line->acl->acl_a);
      free(line->acl->acl_d);
    }
    checked_free(line->acl);
  }
#endif
#ifdef WITH_XATTR
  if(!(attr&ATTR(attr_xattrs))){
    if (line->xattrs)
      free(line->xattrs->ents);
    checked_free(line->xattrs);
  }
#endif
#ifdef WITH_SELINUX
  if(!(attr&ATTR(attr_selinux))){
    checked_free(line->cntx);
  }
#endif
#ifdef WITH_CAPABILITIES
  if(!(attr&ATTR(attr_capabilities))){
    checked_free(line->capabilities);
  }
#endif
  /* e2fsattrs is stripped within e2fsattrs2line in do_md */
}

/*
 * add_file_to_tree
 * db = which db this file belongs to
 */
static void add_file_to_tree(seltree* tree,db_line* file,int db)
{
  seltree* node=NULL;

  node=get_seltree_node(tree,file->filename);

  if(!node){
    node=new_seltree_node(tree,file->filename,0,NULL);
    log_msg(LOG_LEVEL_DEBUG, "added new node '%s' (%p) for '%s' (reason: new entry)", node->path, node, file->filename);
  }

  /* add note to this node which db has modified it */
  node->checked|=db;

  strip_dbline(file);

  switch (db) {
  case DB_OLD: {
    log_msg(LOG_LEVEL_DEBUG, "add old entry '%s' (%c) to node '%s' (%p) as old data", file->filename, get_file_type_char(file->perm), node->path, node);
    node->old_data=file;
    break;
  }
  case DB_NEW: {
    log_msg(LOG_LEVEL_DEBUG, "add new entry '%s' (%c) to node '%s' (%p) as new data", file->filename, get_file_type_char(file->perm), node->path, node);
    node->new_data=file;
    break;
  }
  case DB_OLD|DB_NEW: {
    node->new_data=file;
    if(conf->action&DO_INIT) {
        node->checked|=NODE_FREE;
        log_msg(LOG_LEVEL_DEBUG, "add old entry '%s' (%c) to node (%p) as new data (entry does not match limit but keep it for database_out)", file->filename, get_file_type_char(file->perm), node);
    } else {
        log_msg(LOG_LEVEL_DEBUG, "drop old entry '%s' (entry does not match limit)", file->filename);
        free_db_line(node->new_data);
        free(node->new_data);
        node->new_data=NULL;
    }
    return;
  }
  }

  if((node->checked&DB_OLD)&&(node->checked&DB_NEW)){
    node->changed_attrs=get_changed_attributes(node->old_data,node->new_data);
    char *str;
    str = node->changed_attrs?diff_attributes(0, node->changed_attrs):NULL;
    log_msg(LOG_LEVEL_DEBUG,"changed attributes for entry '%s': %s", (node->old_data)->filename, str?str:"(none)");
    free(str);
    /* Free the data if same else leave as is for report_tree */
    if(node->changed_attrs==RETOK){
      log_msg(LOG_LEVEL_DEBUG, "free old data (node '%s' is unchanged)", node->path);
      node->changed_attrs=0;

      free_db_line(node->old_data);
      free(node->old_data);
      node->old_data=NULL;

      /* Free new data if not needed for write_tree */
      if(conf->action&DO_INIT) {
          log_msg(LOG_LEVEL_DEBUG, "keep new data (node '%s' is unchanged, but keep it for database_out)", node->path);
          node->checked|=NODE_FREE;
      } else {
          log_msg(LOG_LEVEL_DEBUG, "free new data (node '%s' is unchanged)", node->path);
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
    (file->attr & ATTR(attr_checkinode))) {
    log_msg(LOG_LEVEL_DEBUG, "'%s' has check inode group set, checking for moved file", file->filename);
    /* Check if file was moved (same inode, different name in the other DB)*/
    db_line *oldData;
    db_line *newData;
    seltree* moved_node;

    moved_node=get_seltree_inode(tree,file,db==DB_OLD?DB_NEW:DB_OLD);
    if(!(moved_node == NULL || moved_node == node)) {
      if(db == DB_NEW) {
        newData = node->new_data;
        oldData = moved_node->old_data;
        log_msg(LOG_LEVEL_DEBUG, "checking old data of node '%s' with new data of '%s'", moved_node->path, node->path);
      } else {
        newData = moved_node->new_data;
        oldData = node->old_data;
        log_msg(LOG_LEVEL_DEBUG, "checking old data of node '%s' with new data of '%s'", node->path, moved_node->path);
      }

      DB_ATTR_TYPE move_attr = ATTR(attr_allownewfile)|ATTR(attr_allowrmfile)|ATTR(attr_checkinode);

      if((oldData->attr^newData->attr)&(~move_attr)) {
         char *str;
         log_msg(LOG_LEVEL_DEBUG, "ignoring moved entry ('%s' => '%s') due to different attributes: %s",
                 oldData->filename, newData->filename, str = diff_attributes(oldData->attr&(~move_attr), newData->attr&(~move_attr)));
         free(str);
     } else {
         /* Free the data if same else leave as is for report_tree */
         DB_ATTR_TYPE changed_attr_moved_file = get_changed_attributes(oldData, newData);
         if ((changed_attr_moved_file&~(ATTR(attr_ctime))) == RETOK) {
             node->checked |= db==DB_NEW ? NODE_MOVED_IN : NODE_MOVED_OUT;
             moved_node->checked |= db==DB_NEW ? NODE_MOVED_OUT : NODE_MOVED_IN;
             if (changed_attr_moved_file & (ATTR(attr_ctime))) {
                log_msg(LOG_LEVEL_DEBUG,_("  ctime is ignored, due to filename change: '%s' => '%s'"), oldData->filename, newData->filename);
             }
             log_msg(LOG_LEVEL_DEBUG,_("  entry has been moved: '%s' => '%s'"), oldData->filename, newData->filename);
         } else {
             log_msg(LOG_LEVEL_DEBUG,"  ignoring moved entry ('%s' => '%s') because the entries mismatch\n",
                     oldData->filename, newData->filename);
         }
      }
    } else {
        /* There's mo match for inode or it matches the node with the same name.
         * In first case we don't have a match to compare with.
         * In the second - we already compared those files. */
        log_msg(LOG_LEVEL_DEBUG, "no moved file found for '%s'", file->filename);
    }
  }
  if( (db == DB_NEW) &&
      (node->new_data!=NULL) &&
      (file->attr & ATTR(attr_allownewfile)) ){
	 node->checked|=NODE_ALLOW_NEW;
     log_msg(LOG_LEVEL_DEBUG,_(" mark node '%s' as NODE_ALLOW_NEW (reason: entry '%s' has ANF attribute set)"), node->path, file->filename);
  }
  if( (db == DB_OLD) &&
      (node->old_data!=NULL) &&
      (file->attr & ATTR(attr_allowrmfile)) ){
	  node->checked|=NODE_ALLOW_RM;
     log_msg(LOG_LEVEL_DEBUG,_(" mark node '%s' as NODE_ALLOW_RM (reason: entry '%s' has ARF attribute set)"), node->path, file->filename);
  }
}

int check_rxtree(char* filename,seltree* tree,DB_ATTR_TYPE* attr, mode_t perm)
{
  log_msg(LOG_LEVEL_RULE, "\u252c process '%s' (filetype: %c)", filename, get_file_type_char(perm));
  int retval=0;

  if(conf->limit!=NULL) {
      retval=pcre_exec(conf->limit_crx, NULL, filename, strlen(filename), 0, PCRE_PARTIAL_SOFT, NULL, 0);
      if (retval >= 0) {
          log_msg(LOG_LEVEL_DEBUG, "\u2502 '%s' does match limit '%s'", filename, conf->limit);
      } else if (retval == PCRE_ERROR_PARTIAL) {
          if(S_ISDIR(perm) && get_seltree_node(tree,filename)==NULL){
              seltree* node = new_seltree_node(tree,filename,0,NULL);
              log_msg(LOG_LEVEL_DEBUG, "added new node '%s' (%p) for '%s' (reason: partial limit match)", node->path, node, filename);
          }
          log_msg(LOG_LEVEL_RULE, "\u2534 skip '%s' (reason: partial limit match, limit: '%s')", filename, conf->limit);
          return -1;
      } else {
          log_msg(LOG_LEVEL_RULE, "\u2534 skip '%s' (reason: no limit match, limit '%s')", filename, conf->limit);
          return -2;
      }
  }

  *attr=0;
  return check_seltree(tree, filename, get_file_type(perm), attr);
}

db_line* get_file_attrs(char* filename,DB_ATTR_TYPE attr, struct stat *fs)
{
  db_line* line=NULL;
  time_t cur_time;

  char *str;
  log_msg(LOG_LEVEL_DEBUG, " requested attributes: %s", str = diff_attributes(0, attr));
  free(str);

  if(!(attr&ATTR(attr_rdev))) {
    fs->st_rdev=0;
  }
  /*
    Get current time for future time notification.
   */
  cur_time=time(NULL);
  
  if (cur_time==(time_t)-1) {
    log_msg(LOG_LEVEL_WARNING, "can't get current time: %s", strerror(errno));
  } else {
    
    if(fs->st_atime>cur_time){
      log_msg(LOG_LEVEL_NOTICE,_("%s atime in future"),filename);
    }
    if(fs->st_mtime>cur_time){
      log_msg(LOG_LEVEL_NOTICE,_("%s mtime in future"),filename);
    }
    if(fs->st_ctime>cur_time){
      log_msg(LOG_LEVEL_NOTICE,_("%s ctime in future"),filename);
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

  line->attr=attr|ATTR(attr_filename);

  /*
    Just copy some needed fields.
  */
  
  line->fullpath=filename;
  line->filename=&filename[conf->root_prefix_length];
  line->perm_o=fs->st_mode;
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

#ifdef WITH_CAPABILITIES
    capabilities2line(line);
#endif

  if (line->attr&get_hashes(true) && S_ISREG(fs->st_mode)) {
    calc_md(fs,line);
  } else {
    /*
      We cannot calculate hash for nonfile.
      Mark it to attr.
    */
    no_hash(line);
  }

  log_msg(LOG_LEVEL_DEBUG, " returned attributes: %llu (%s)", line->attr, str = diff_attributes(0, line->attr));
  free(str);
      if (~attr|line->attr) {
          log_msg(LOG_LEVEL_DEBUG, " requested and returned attributes are not equal: %s", str = diff_attributes(attr, line->attr));
          free(str);
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
  
  /* With this we avoid unnecessary checking of removed files. */
  if(conf->action&DO_INIT){
    initdbwarningprinted=1;
  }
  
    if(conf->action&DO_DIFF){
        log_msg(LOG_LEVEL_INFO, "read new entries from database: %s:%s", get_url_type_string((conf->database_new.url)->type), (conf->database_new.url)->value);
      db_lex_buffer(&(conf->database_new));
      while((new=db_readline(&(conf->database_new))) != NULL){
	if((add=check_rxtree(new->filename,tree,&attr, new->perm))>0){
	  add_file_to_tree(tree,new,DB_NEW);
	} else {
          free_db_line(new);
          free(new);
          new=NULL;
	}
      }
      db_lex_delete_buffer(&(conf->database_new));
    }
    
    if((conf->action&DO_INIT)||(conf->action&DO_COMPARE)){
      /* FIXME  */
      new=NULL;
      log_msg(LOG_LEVEL_INFO, "read new entries from disk (root: '%s', limit: '%s')", conf->root_prefix, conf->limit?conf->limit:"(none)");
      while((new=db_readline_disk()) != NULL) {
	    add_file_to_tree(tree,new,DB_NEW);
      }
    }
    if((conf->action&DO_COMPARE)||(conf->action&DO_DIFF)){
        log_msg(LOG_LEVEL_INFO, "read old entries from database: %s:%s", get_url_type_string((conf->database_in.url)->type), (conf->database_in.url)->value);
        db_lex_buffer(&(conf->database_in));
            while((old=db_readline(&(conf->database_in))) != NULL) {
                add=check_rxtree(old->filename,tree,&attr, old->perm);
                if(add > 0) {
                    add_file_to_tree(tree,old,DB_OLD);
                } else if (conf->limit!=NULL && add < 0) {
                    add_file_to_tree(tree,old,DB_OLD|DB_NEW);
                }else{
                    if(!initdbwarningprinted){
                        log_msg(LOG_LEVEL_WARNING, _("%s:%s: old database entry '%s' has no matching rule, run --init or --update (this warning is only shown once)"), get_url_type_string((conf->database_in.url)->type), (conf->database_in.url)->value, old->filename);
                        initdbwarningprinted=1;
                    }
                    free_db_line(old);
                    free(old);
                    old=NULL;
                }
            }
            db_lex_delete_buffer(&(conf->database_in));
    }
    if(conf->action&DO_INIT) {
        log_msg(LOG_LEVEL_INFO, "write new entries to database: %s:%s", get_url_type_string((conf->database_out.url)->type), (conf->database_out.url)->value);
        write_tree(tree);
    }
}

void hsymlnk(db_line* line) {
  
  if((S_ISLNK(line->perm_o))){
    int len=0;
#ifdef WITH_ACL   
    if(conf->no_acl_on_symlinks!=1) {
      line->attr&=(~ATTR(attr_acl));
    }
#endif   
    
    if(conf->warn_dead_symlinks==1) {
      struct stat fs;
      int sres;
      sres=stat(line->fullpath,&fs);
      if (sres!=0 && sres!=EACCES) {
	log_msg(LOG_LEVEL_WARNING,"Dead symlink detected at %s",line->fullpath);
      }
      if(!(line->attr&ATTR(attr_rdev))) {
	fs.st_rdev=0;
      }
    }
    /*
      Is this valid?? 
      No, We should do this elsewhere.
    */
    line->linkname=(char*)malloc(_POSIX_PATH_MAX+1);
    if(line->linkname==NULL){
      log_msg(LOG_LEVEL_ERROR,_("malloc failed in hsymlnk()"));
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
      line->attr&=(~ATTR(attr_linkname));
  }
  
}
// vi: ts=8 sw=2
