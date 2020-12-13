/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002,2004,2006,2019,2020 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg, Hannes von Haugwitz
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

#ifndef _ATTRIBUTES_H_INCLUDED
#define _ATTRIBUTES_H_INCLUDED

#define DB_ATTR_TYPE unsigned long long
#define DB_ATTR_UNDEF ((DB_ATTR_TYPE) -1)

#define ATTR(attribute) (1LLU<<attribute)

typedef enum {
   attr_filename=0,
   attr_linkname,
   attr_perm,
   attr_uid,
   attr_gid,
   attr_size,
   attr_atime,
   attr_ctime,
   attr_mtime,
   attr_inode,
   attr_bcount,
   attr_linkcount,
   attr_md5,
   attr_sha1,
   attr_rmd160,
   attr_tiger,
   attr_crc32,
   attr_haval,
   attr_gostr3411_94,
   attr_crc32b,
   attr_attr,
   attr_acl,
   attr_bsize,
   attr_rdev,
   attr_dev,
   attr_allhashsums,
   attr_sizeg,
   attr_checkinode,
   attr_allownewfile,
   attr_allowrmfile,
   attr_sha256,
   attr_sha512,
   attr_selinux,
   attr_xattrs,
   attr_whirlpool,
   attr_ftype,
   attr_e2fsattrs,
   attr_capabilities,
   attr_unknown
} ATTRIBUTE;

typedef struct {
    DB_ATTR_TYPE attr;
    char *config_name;
    char *details_string;
    char *db_name;
    char summary_char;
} attributes_t;

#define MAX_WIDTH_DETAILS_STRING 10

extern attributes_t attributes[];
extern DB_ATTR_TYPE num_attrs;

/* memory for the returned string is obtained with malloc(3), and should be freed with free(3). */
char *diff_attributes(DB_ATTR_TYPE, DB_ATTR_TYPE);
#endif
