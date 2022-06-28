/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2000-2002, 2005-2006, 2020, 2022 Rami Lehti, Pablo Virolainen,
 *               Richard van den Berg, Hannes von Haugwitz
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
#ifdef WITH_MHASH
#include <mhash.h>
#endif
#ifdef WITH_GCRYPT
#include <gcrypt.h>
#endif
#include <sys/types.h>
#include "attributes.h"
#include "hashsum.h"
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
#ifdef WITH_MHASH
  MHASH mhash_mdh[num_hashes];
#endif

#ifdef WITH_GCRYPT
  gcry_md_hd_t mdh;
#endif

} md_container;

typedef struct md_hashsums {
  char hashsums[num_hashes][HASHSUM_MAX_LENGTH];
  DB_ATTR_TYPE attrs;
} md_hashsums;

int init_md(struct md_container*, const char*);
int update_md(struct md_container*,void*,ssize_t);
int close_md(struct md_container*, md_hashsums *);
void hashsums2line(md_hashsums*, struct db_line*);

#endif /*_MD_H_INCLUDED*/
