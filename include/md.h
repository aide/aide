/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2000-2002, 2005-2006, 2020, 2022, 2024 Rami Lehti,
 *               Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _MD_H_INCLUDED
#define _MD_H_INCLUDED

#include "config.h"
#ifdef WITH_NETTLE
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>
#include <nettle/ripemd160.h>
#include <nettle/gosthash94.h>
#include <nettle/streebog.h>
#endif
#ifdef WITH_GCRYPT
#include <gcrypt.h>
#endif
#include <sys/types.h>
#include "attributes.h"
#include "hashsum.h"
#include "util.h"
struct db_line;

/*
  This struct hold's internal data needed for md-calls.

 */

typedef struct md_container {
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
#ifdef WITH_NETTLE
      union {
          struct md5_ctx md5;
          struct sha1_ctx sha1;
          struct sha256_ctx sha256;
          struct sha512_ctx sha512;
          struct ripemd160_ctx ripemd160;
          struct gosthash94_ctx gosthash94;
          struct streebog256_ctx streebog256;
          struct streebog512_ctx streebog512;
          struct sha512_256_ctx sha512_256;
          struct sha3_512_ctx sha3_256;
          struct sha3_256_ctx sha3_512;
      } ctx[num_hashes];
#endif

#ifdef WITH_GCRYPT
  gcry_md_hd_t mdh;
#endif

} md_container;

typedef struct md_hashsums {
  unsigned char hashsums[num_hashes][HASHSUM_MAX_LENGTH];
  DB_ATTR_TYPE attrs;
} md_hashsums;

int init_md(struct md_container*, const char*);
int update_md(struct md_container*,void*,ssize_t);
int close_md(struct md_container*, md_hashsums *, const char*);
void hashsums2line(md_hashsums*, struct db_line*);

DB_ATTR_TYPE copy_hashsums(char *, md_hashsums *, byte* (*)[num_hashes]);

#endif /*_MD_H_INCLUDED*/
