/* Aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2005,2006,2010 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg
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
#include <stdlib.h>
#include "md.h"
#include "report.h"
#include <string.h>
#ifdef WITH_MHASH
#include <mhash.h>
#endif
#define HASH_HAVAL_LEN HASH_HAVAL256_LEN


/*
  It might be a good idea to construct a table, where these values are
  stored. Only a speed issue.
*/

DB_ATTR_TYPE hash_gcrypt2attr(int i) {
  DB_ATTR_TYPE r=0;
#ifdef WITH_GCRYPT
  switch (i) {
  case GCRY_MD_MD5: {
    r=DB_MD5;
    break;
  }
  case GCRY_MD_SHA1: {
    r=DB_SHA1;
    break;
  }
  case GCRY_MD_RMD160: {
    r=DB_RMD160;
    break;
  }
  case GCRY_MD_TIGER: {
    r=DB_TIGER;
    break;
  }
  case GCRY_MD_HAVAL: {
    r=DB_HAVAL;
    break;
  }
  case GCRY_MD_SHA256: {
    r=DB_SHA256;
    break;
  }
  case GCRY_MD_SHA512: {
    r=DB_SHA512;
    break;
  }
  case GCRY_MD_CRC32: {
    r=DB_CRC32;
    break;
  }
  default:
    break;
  }
#endif
  return r;
}

DB_ATTR_TYPE hash_mhash2attr(int i) {
  DB_ATTR_TYPE r=0;
#ifdef WITH_MHASH
  switch (i) {
  case MHASH_CRC32: {
    r=DB_CRC32;
    break;
  }
  case MHASH_MD5: {
    r=DB_MD5;
    break;
  }
  case MHASH_SHA1: {
    r=DB_SHA1;
    break;
  }
  case MHASH_HAVAL: {   
    r=DB_HAVAL;
    break;
  }
  case MHASH_RMD160: {
    r=DB_RMD160;
    break;
  }
  case MHASH_TIGER: {
    r=DB_TIGER;
    break;
  }
  case MHASH_GOST: {
    r=DB_GOST;
    break;
  }
  case MHASH_CRC32B: {
    r=DB_CRC32B;
    break;
  }
  case MHASH_HAVAL224: {
    break;
  }
  case MHASH_HAVAL192: {
    break;
  }
  case MHASH_HAVAL160: {
    break;
  }
  case MHASH_HAVAL128: {
    break;
  }
  case MHASH_TIGER128: {
    break;
  }
  case MHASH_TIGER160: {
    break;
  }
  case MHASH_MD4: {
    break;
  }
  case MHASH_SHA256: {
    r=DB_SHA256;
    break;
  }
  case MHASH_SHA512: {
    r=DB_SHA512;
    break;
  }
#ifdef HAVE_MHASH_WHIRLPOOL		 
  case MHASH_WHIRLPOOL: {
    r=DB_WHIRLPOOL;
    break;
  }
#endif
  case MHASH_ADLER32: {
    break;
  }
  default:
    break;
  }
#endif
  return r;
}

/*
  Initialise md_container according it's todo_attr field
 */

int init_md(struct md_container* md) {
  
  int i;
  /*    First we check the parameter..   */
#ifdef _PARAMETER_CHECK_
  if (md==NULL) {
    return RETFAIL;  
  }
#endif
  error(255,"init_md called\n");
  /*
    We don't have calculator for this yet :)
  */
  md->calc_attr=0;
#ifdef WITH_MHASH
  error(255,"Mhash library initialization\n");
  for(i=0;i<=HASH_MHASH_COUNT;i++) {
    if (((hash_mhash2attr(i)&HASH_USE_MHASH)&md->todo_attr)!=0) {
      DB_ATTR_TYPE h=hash_mhash2attr(i);
      error(255,"inserting %llu\n",h);
      md->mhash_mdh[i]=mhash_init(i);
      if (md->mhash_mdh[i]!=MHASH_FAILED) {
				md->calc_attr|=h;
      } else {
	/*
	  Oops.. 
	  We just don't calculate this.
	 */

				md->todo_attr&=~h;
      }

    } else {
      md->mhash_mdh[i]=MHASH_FAILED;      
    }
  }
#endif 
#ifdef WITH_GCRYPT
  error(255,"Gcrypt library initialization\n");
  	if(!gcry_check_version(GCRYPT_VERSION)) {
		error(0,"libgcrypt version mismatch\n");
		exit(VERSION_MISMATCH_ERROR);
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if(gcry_md_open(&md->mdh,0,0)!=GPG_ERR_NO_ERROR){
		error(0,"gcrypt_md_open failed\n");
		exit(IO_ERROR);
	}
  for(i=0;i<=HASH_GCRYPT_COUNT;i++) {
    if (((hash_gcrypt2attr(i)&HASH_USE_GCRYPT)&md->todo_attr)!=0) {
      DB_ATTR_TYPE h=hash_gcrypt2attr(i);
      error(255,"inserting %llu\n",h);
			if(gcry_md_enable(md->mdh,i)==GPG_ERR_NO_ERROR){
				md->calc_attr|=h;
			} else {
				error(0,"gcry_md_enable %i failed",i);
				md->todo_attr&=~h;
			}
		}
	}
#endif
  return RETOK;
}

/*
  update :)
  Just call this when you have more data.
 */

int update_md(struct md_container* md,void* data,ssize_t size) {
  int i;
    
  error(255,"update_md called\n");

#ifdef _PARAMETER_CHECK_
  if (md==NULL||data==NULL) {
    return RETFAIL;
  }
#endif

#ifdef WITH_MHASH
  
  for(i=0;i<=HASH_MHASH_COUNT;i++) {
    if (md->mhash_mdh[i]!=MHASH_FAILED) {
      mhash (md->mhash_mdh[i], data, size);
    }
  }
  
#endif /* WITH_MHASH */
#ifdef WITH_GCRYPT
	gcry_md_write(md->mdh, data, size);
#endif
  return RETOK;
}

/*
  close.. Does some magic.
  After this calling update_db is not a good idea.
*/

int close_md(struct md_container* md) {
  int i;
#ifdef _PARAMETER_CHECK_
  if (md==NULL) {
    return RETFAIL;
  }
#endif
  error(255,"close_md called \n");
#ifdef WITH_MHASH
  for(i=0;i<=HASH_MHASH_COUNT;i++) {
    if (md->mhash_mdh[i]!=MHASH_FAILED) {
      mhash (md->mhash_mdh[i], NULL, 0);
    }  
  }
#endif /* WITH_MHASH */
#ifdef WITH_GCRYPT
  gcry_md_final(md->mdh); 
  /* Let's flush the buffers */

#define get_libgcrypt_hash(a,b,c,d) \
  if(md->calc_attr&a&HASH_USE_GCRYPT){\
		error(255,"Getting hash %i\n",b);\
    memcpy(md->c,gcry_md_read(md->mdh,b),d);\
  }

  get_libgcrypt_hash(DB_MD5,GCRY_MD_MD5,md5,HASH_MD5_LEN);
  get_libgcrypt_hash(DB_SHA1,GCRY_MD_SHA1,sha1,HASH_SHA1_LEN);
  get_libgcrypt_hash(DB_TIGER,GCRY_MD_TIGER,tiger,HASH_TIGER_LEN);
  get_libgcrypt_hash(DB_RMD160,GCRY_MD_RMD160,rmd160,HASH_RMD160_LEN);
  get_libgcrypt_hash(DB_SHA256,GCRY_MD_SHA256,sha256,HASH_SHA256_LEN);
  get_libgcrypt_hash(DB_SHA512,GCRY_MD_SHA512,sha512,HASH_SHA512_LEN);
  get_libgcrypt_hash(DB_CRC32,GCRY_MD_CRC32,crc32,HASH_CRC32_LEN);
  
  /*.    There might be more hashes in the library. Add those here..   */
  
  gcry_md_reset(md->mdh);
#endif  

#ifdef WITH_MHASH
#define get_mhash_hash(b,c) \
  if(md->mhash_mdh[b]!=MHASH_FAILED){ \
    mhash_deinit(md->mhash_mdh[b],(void*)md->c); \
  }
  
  get_mhash_hash(MHASH_MD5,md5);
  get_mhash_hash(MHASH_SHA1,sha1);
  get_mhash_hash(MHASH_TIGER,tiger);
  get_mhash_hash(MHASH_RMD160,rmd160);
  get_mhash_hash(MHASH_CRC32,crc32);
  get_mhash_hash(MHASH_HAVAL,haval);
  get_mhash_hash(MHASH_GOST,gost);
  get_mhash_hash(MHASH_CRC32B,crc32b);
  get_mhash_hash(MHASH_SHA256,sha256);
  get_mhash_hash(MHASH_SHA512,sha512);
#ifdef HAVE_MHASH_WHIRLPOOL
  get_mhash_hash(MHASH_WHIRLPOOL,whirlpool);
#endif
  
  /*
    There might be more hashes in the library we want to use.
    Add those here..
  */
  
#endif
  return RETOK;
}

/*
  Writes md_container to db_line.
 */

void md2line(struct md_container* md,struct db_line* line) {
  
  error(255,"md2line \n");
  
#ifdef _PARAMETER_CHECK_
  if (md==NULL||line==NULL) {
    return RETFAIL;
  }
#endif

#define copyhash(a,b,c)        \
  if (line->attr&a) {          \
    error(255,"Line has %llu\n",a); \
    if (md->calc_attr&a) {     \
      error(255,"copying %llu\n",a); \
      line->b=(byte*)malloc(c);       \
      memcpy(line->b,md->b,c); \
    } else {                   \
      line->attr&=~a;          \
    }                          \
  }
  
  
  copyhash(DB_MD5,md5,HASH_MD5_LEN);
  copyhash(DB_SHA1,sha1,HASH_SHA1_LEN);
  copyhash(DB_RMD160,rmd160,HASH_RMD160_LEN);
  copyhash(DB_TIGER,tiger,HASH_TIGER_LEN);
  copyhash(DB_CRC32,crc32,HASH_CRC32_LEN);
  copyhash(DB_HAVAL,haval,HASH_HAVAL_LEN);
  copyhash(DB_GOST,gost,HASH_GOST_LEN);
  copyhash(DB_CRC32B,crc32b,HASH_CRC32B_LEN);

  copyhash(DB_SHA256,sha256,HASH_SHA256_LEN);
  copyhash(DB_SHA512,sha512,HASH_SHA512_LEN);
  copyhash(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN);
}
