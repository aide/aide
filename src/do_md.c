/* aide, Advanced Intrusion Detection Environment
 * vi: ts=8 sw=8
 *
 * Copyright (C) 1999,2000,2001,2002,2005 Rami Lehti, Pablo Virolainen
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

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "md.h"

#include "db_config.h"
#include "do_md.h"
#include "report.h"
#include "list.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/


/* This define should be somewhere else */
#define READ_BLOCK_SIZE 16777216

#ifdef WITH_MHASH
#include <mhash.h>
#endif /* WITH_MHASH */

/* Redhat 5.0 needs this */
#ifdef HAVE_MMAP
#ifndef MAP_FAILED
#define MAP_FAILED  (-1)
#endif /* MAP_FAILED */
#define MMAP_BLOCK_SIZE 16777216
#endif /* HAVE_MMAP */

/*
#include <gcrypt.h>
*/
void md_init_fail(const char* s,db_line* db,byte** hash,DB_ATTR_TYPE i) {
  error(0,"Message digest %s initialise failed\nDisabling %s for file %s\n",s,s,db->filename);
  db->attr=db->attr&(~i);
  (*hash)=0;
}

void free_hashes(db_line* dl){

#define free_hash(a) dl->a=NULL

  free_hash(md5);
  free_hash(sha1);
  free_hash(rmd160);
  free_hash(tiger);
#ifdef WITH_MHASH
  free_hash(crc32);
  free_hash(haval);
  free_hash(gost);
  free_hash(crc32b);  
#endif
  free_hash(sha256);
  free_hash(sha512);
}

int stat_cmp(struct AIDE_STAT_TYPE* f1,struct AIDE_STAT_TYPE* f2) {
  if (f1==NULL || f2==NULL) {
    return RETFAIL;
  }
#define stat_cmp_helper(n,n2) ((f1->n!=f2->n)*n2)

  return (stat_cmp_helper(st_ino,DB_INODE)|
	  stat_cmp_helper(st_mode,DB_PERM)|
	  stat_cmp_helper(st_nlink,DB_LNKCOUNT)|
	  stat_cmp_helper(st_size,DB_SIZE)|
	  stat_cmp_helper(st_mtime,DB_MTIME)|
	  stat_cmp_helper(st_ctime,DB_CTIME)|
	  stat_cmp_helper(st_blocks,DB_BCOUNT)|
	  stat_cmp_helper(st_blksize,DB_BSIZE)|
	  stat_cmp_helper(st_rdev,DB_RDEV)|
	  stat_cmp_helper(st_gid,DB_GID)|
	  stat_cmp_helper(st_uid,DB_UID)|
	  stat_cmp_helper(st_dev,DB_DEV));
}


void no_hash(db_line* line);

void calc_md(struct AIDE_STAT_TYPE* old_fs,db_line* line) {
  /*
    We stat after opening just to make sure that the file
    from we are about to calculate the hash is the correct one,
    and we don't read from a pipe :)
   */
  struct AIDE_STAT_TYPE fs;
  int sres=0;
  int stat_diff,filedes;

  error(255,"calc_md called\n");
#ifdef _PARAMETER_CHECK_
  if (line==NULL) {
    abort();
  }
#endif  

#ifdef HAVE_O_NOATIME
  filedes=open(line->filename,O_RDONLY|O_NOATIME);
  if(filedes==-1)
#endif
    filedes=open(line->filename,O_RDONLY);

  if (filedes==-1) {
    char* er=strerror(errno);
    if (er!=NULL) {
      error(3,"do_md(): open() for %s failed: %s\n",
	    line->filename,er);
    } else {
      error(3,"do_md(): open() for %s failed: %i\n",
	    line->filename,errno);
    }
    /*
      Nop. Cannot cal hashes. Mark it.
     */
    no_hash(line);
    return;
  }
  
  sres=AIDE_FSTAT_FUNC(filedes,&fs);
  if(!(line->attr&DB_RDEV))
	  fs.st_rdev=0;
  
#ifdef HAVE_POSIX_FADVICE
  if (posix_fadvise(filedes,0,fs.st_size,POSIX_FADV_NOREUSE)!=0) {
	error(255,"posix_fadvise error %s\n",strerror(errno));
  } else {
	error(255,"posix_fadvise(%i,0,%i,POSIX_FADV_NOREUSE) ok\n",filedes,fs.st_size);
  }
#endif
  if ((stat_diff=stat_cmp(&fs,old_fs))==RETOK) {
    /*
      Now we have a 'valid' filehandle to read from a file.
     */
    off_t r_size=0;
    off_t size=0;
    char* buf;

    struct md_container mdc;
    
    mdc.todo_attr=line->attr;
    
    if (init_md(&mdc)==RETOK) {
#ifdef HAVE_MMAP
      off_t curpos=0;

      r_size=fs.st_size;
      /* in mmap branch r_size is used as size remaining */
      while(r_size>0){
	if(r_size<MMAP_BLOCK_SIZE){
#ifdef __hpux
	  buf = mmap(0,r_size,PROT_READ,MAP_PRIVATE,filedes,curpos);
#else
	  buf = mmap(0,r_size,PROT_READ,MAP_SHARED,filedes,curpos);
#endif
	  curpos+=r_size;
	  size=r_size;
	  r_size=0;
	}else {
#ifdef __hpux
	  buf = mmap(0,MMAP_BLOCK_SIZE,PROT_READ,MAP_PRIVATE,filedes,curpos);
#else
	  buf = mmap(0,MMAP_BLOCK_SIZE,PROT_READ,MAP_SHARED,filedes,curpos);
#endif
	  curpos+=MMAP_BLOCK_SIZE;
	  size=MMAP_BLOCK_SIZE;
	  r_size-=MMAP_BLOCK_SIZE;
	}
	if ( buf == MAP_FAILED ) {
	  error(0,"error mmap'ing %s: %s\n", line->filename,strerror(errno));
	  close(filedes);
	  close_md(&mdc);
	  return;
	}
	conf->catch_mmap=1;
	if (update_md(&mdc,buf,size)!=RETOK) {
	  error(0,"Message digest failed during update\n");
	  close_md(&mdc);
	  munmap(buf,size);
	  return;
	}
	munmap(buf,size);
	conf->catch_mmap=0;
      }
#else /* not HAVE_MMAP */
      buf=malloc(READ_BLOCK_SIZE);
#if READ_BLOCK_SIZE>SSIZE_MAX
#error "READ_BLOCK_SIZE" is too large. Max value is SSIZE_MAX, and current is READ_BLOCK_SIZE
#endif
      while ((size=TEMP_FAILURE_RETRY(read(filedes,buf,READ_BLOCK_SIZE)))>0) {
	if (update_md(&mdc,buf,size)!=RETOK) {
	  error(0,"Message digest failed during update\n");
	  close_md(&mdc);
	  return;
	}
	r_size+=size;
      }
      free(buf);
#endif /* HAVE_MMAP else branch */    
      close_md(&mdc);
      md2line(&mdc,line);
      
    } else {
      error(3,"Message digest initialization failed.\n");
      no_hash(line);
      close(filedes);
      return;
    }
  } else {
    unsigned i;
    /*
      Something just wasn't correct, so no hash calculated.
    */
    
    error(5,"File %s was changed so that hash cannot be calculated for it\n"
	  ,line->filename);

    for(i=0;i<db_unknown;i++) {
      if (((1<<i)&stat_diff)!=0) {
	error(5,"Attribute %s has been changed\n",db_names[i]);
      }
    }
    
    no_hash(line);
    close(filedes);
    return;
  }
  close(filedes);
  return;
}

void fs2db_line(struct AIDE_STAT_TYPE* fs,db_line* line) {
  
  if(DB_INODE&line->attr||DB_CHECKINODE&line->attr){
    line->inode=fs->st_ino;
  } else {
    line->inode=0;
  }

  if(DB_UID&line->attr) {
    line->uid=fs->st_uid;
  }else {
    line->uid=0;
  }

  if(DB_GID&line->attr){
    line->gid=fs->st_gid;
  }else{
    line->gid=0;
  }

  if(DB_PERM&line->attr){
    line->perm=fs->st_mode;
  }else{
    line->perm=0;
  }

  if(DB_SIZE&line->attr||DB_SIZEG&line->attr){
    line->size=fs->st_size;
  }else{
    line->size=0;
  }
  
  if(DB_LNKCOUNT&line->attr){
    line->nlink=fs->st_nlink;
  }else {
    line->nlink=0;
  }

  if(DB_MTIME&line->attr){
    line->mtime=fs->st_mtime;
  }else{
    line->mtime=0;
  }

  if(DB_CTIME&line->attr){
    line->ctime=fs->st_ctime;
  }else{
    line->ctime=0;
  }
  
  if(DB_ATIME&line->attr){
    line->atime=fs->st_atime;
  }else{
    line->atime=0;
  }

  if(DB_BCOUNT&line->attr){
    line->bcount=fs->st_blocks;
  } else {
    line->bcount=0;
  }
  
}

void acl2line(db_line* line) {
  acl_type *ret = NULL;
  
#ifdef WITH_POSIX_ACL
  if(DB_ACL&line->attr) {
    acl_t acl_a;
    acl_t acl_d;
    char *tmp = NULL;

    acl_a = acl_get_file(line->filename, ACL_TYPE_ACCESS);
    acl_d = acl_get_file(line->filename, ACL_TYPE_DEFAULT);
    if ((acl_a == NULL) && (errno == ENOTSUP))
      return;
    if (acl_a == NULL)
      error(0, "Tried to read access ACL on %s but failed with: %m\n",
            line->filename);
    if ((acl_d == NULL) && (errno != EACCES)) /* ignore DEFAULT on files */
    {
      acl_free(acl_a);
      error(0, "Tried to read default ACL on %s but failed with: %m\n",
            line->filename);
    }

    /* assume memory allocs work, like rest of AIDE code... */
    ret = malloc(sizeof(acl_type));

    /* use tmp, so free() can be called instead of acl_free() */
    tmp = acl_to_text(acl_a, NULL);
    if (!tmp || !*tmp)
      ret->acl_a = NULL;
    else
      ret->acl_a = strdup(tmp);
    acl_free(tmp);

    if (!acl_d)
      ret->acl_d = NULL;
    else
    {
      tmp = acl_to_text(acl_d, NULL);
      if (!tmp || !*tmp)
        ret->acl_d = NULL;
      else
        ret->acl_d = strdup(tmp);
      acl_free(tmp);
    }

    acl_free(acl_a);
    acl_free(acl_d);
  }
  line->acl = ret;
#endif  
#ifdef WITH_SUN_ACL
  if(DB_ACL&line->attr) { /* There might be a bug here. */
    int res;
    line->acl=malloc(sizeof(acl_type));
    line->acl->entries=acl(line->filename,GETACLCNT,0,NULL);
    if (line->acl->entries==-1) {
      char* er=strerror(errno);
      line->acl->entries=0;
      if (er==NULL) {
	error(0,"ACL query failed for %s. strerror failed for %i\n",line->filename,errno);
      } else {
	error(0,"ACL query failed for %s:%s\n",line->filename,er);
      }
    } else {
      line->acl->acl=malloc(sizeof(aclent_t)*line->acl->entries);
      res=acl(line->filename,GETACL,line->acl->entries,line->acl->acl);
      if (res==-1) {
	error(0,"ACL error %s\n",strerror(errno));
      } else {
	if (res!=line->acl->entries) {
	  error(0,"Tried to read %i acl but got %i\n",line->acl->entries,res);
	}
      }
    }
  }else{
    line->acl=NULL;
  }
#endif
}

void no_hash(db_line* line) {
  line->attr&=~DB_HASHES;
}

