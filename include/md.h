/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 2000-2002,2005,2006 Rami Lehti,Pablo Virolainen,
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


#ifndef _MD_H_INCLUDED
#define _MD_H_INCLUDED

#include "aide.h"

/*
  This should come from configure-script.
 */

#include "db_config.h"

#ifdef WITH_MHASH
#include <mhash.h>

#ifdef HAVE_MHASH_WHIRLPOOL
# define HASH_MHASH_COUNT MHASH_WHIRLPOOL /* WHIRLPOOL == 22 on 2006-10-11 */
#else
# define HASH_MHASH_COUNT MHASH_RIPEMD320
#endif
#define MHASH_RMD160 MHASH_RIPEMD160
#define MHASH_HAVAL MHASH_HAVAL256
#endif

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#define HASH_GCRYPT_COUNT GCRY_MD_CRC32
#ifndef WITH_MHASH
#define HASH_USE_GCRYPT (DB_MD5|DB_SHA1|DB_RMD160|DB_TIGER|DB_CRC32|\
                         DB_HAVAL|DB_CRC32|DB_SHA256|DB_SHA512)
#endif
#endif

/*
  Lengths. Hope I got there right :)
 */

#define HASH_MD5_LEN 16
#define HASH_SHA1_LEN 20
#define HASH_RMD160_LEN 20
#define HASH_TIGER_LEN 24
#define HASH_GOST_LEN 32
#define HASH_HAVAL224_LEN 28
#define HASH_HAVAL192_LEN 24
#define HASH_HAVAL160_LEN 20
#define HASH_HAVAL128_LEN 16
#define HASH_HAVAL256_LEN 32
#define HASH_TIGER128_LEN 16
#define HASH_TIGER160_LEN 20
#define HASH_MD4_LEN 16
#define HASH_SHA256_LEN 32
#define HASH_SHA512_LEN 64
#define HASH_WHIRLPOOL_LEN 64
#define HASH_ADLER32_LEN 4
#define HASH_CRC32B_LEN 4
#define HASH_CRC32_LEN 4


/*
  What we use from what library?
 */

#ifdef WITH_MHASH
#define HASH_USE_MHASH (DB_MD5|DB_SHA1|DB_RMD160|DB_TIGER|DB_CRC32|\
                        DB_HAVAL|DB_GOST|DB_CRC32|\
                        DB_SHA256|DB_SHA512|DB_WHIRLPOOL)

#define HASH_USE_GCRYPT (0)
#endif


/*
  This struct hold's internal data needed for md-calls.

 */

typedef struct md_container {
  /*
    final hashes. There might be more these than AIDE currently supports,
    but that should be an easy task.
  */
  char crc32[HASH_CRC32_LEN];
  char md5[HASH_MD5_LEN];
  char sha1[HASH_SHA1_LEN];
  char haval[HASH_HAVAL256_LEN];
  char rmd160[HASH_RMD160_LEN];
  char tiger[HASH_TIGER_LEN];
  char gost[HASH_GOST_LEN];
  char crc32b[HASH_CRC32B_LEN];
  char haval224[HASH_HAVAL224_LEN];
  char haval192[HASH_HAVAL192_LEN];
  char haval160[HASH_HAVAL160_LEN];
  char haval128[HASH_HAVAL128_LEN];
  char tiger128[HASH_TIGER128_LEN];
  char tiger160[HASH_TIGER160_LEN];
  char md4[HASH_MD4_LEN];
  char sha256[HASH_SHA256_LEN];
  char sha512[HASH_SHA512_LEN];
  char adler32[HASH_ADLER32_LEN];
  char whirlpool[HASH_WHIRLPOOL_LEN];
  

  /* 
     Attr which are to be calculated.
  */
  DB_ATTR_TYPE calc_attr; 
  /*
    Attr which are not (yet) to be calculated.
    After init hold's hashes which are not calculated :)
  */
  DB_ATTR_TYPE todo_attr;

  /*
    Variables needed to cope with the library.
   */
#ifdef WITH_MHASH
  MHASH mhash_mdh[HASH_MHASH_COUNT+1];
#endif

#ifdef WITH_GCRYPT
  gcry_md_hd_t mdh;
#endif


} md_container;

int init_md(struct md_container*);
int update_md(struct md_container*,void*,ssize_t);
int close_md(struct md_container*);
void md2line(struct md_container*,struct db_line*);


#endif /*_MD_H_INCLUDED*/
