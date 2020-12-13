/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 2000-2002,2005,2006,2020 Rami Lehti,Pablo Virolainen,
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

#include "db_config.h"
#include "hashsum.h"

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#endif

/*
  This struct hold's internal data needed for md-calls.

 */

typedef struct md_container {
  char hashsums[num_hashes][64];

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

int init_md(struct md_container*);
int update_md(struct md_container*,void*,ssize_t);
int close_md(struct md_container*);
void md2line(struct md_container*,struct db_line*);

#endif /*_MD_H_INCLUDED*/
