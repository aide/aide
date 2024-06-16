/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2010, 2013, 2019-2022,2024
 *               Rami Lehti, Pablo Virolainen, Richard van den Berg,
 *               Hannes von Haugwitz
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

#ifndef _DB_LINE_H_INCLUDED
#define _DB_LINE_H_INCLUDED

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include "config.h"
#include "attributes.h"
#include "hashsum.h"
#include "util.h"

#ifdef WITH_POSIX_ACL
typedef struct acl_type {
 char *acl_a; /* ACCESS */
 char *acl_d; /* DEFAULT, directories only */
} acl_type;
#endif

#ifdef WITH_XATTR
typedef struct xattr_node
{
 char *key;
 byte *val;
 size_t vsz;
} xattr_node;

typedef struct xattrs_type
{
  size_t num;
  size_t sz;
  struct xattr_node *ents;
} xattrs_type;
#endif

typedef struct db_line {
  byte* hashsums[num_hashes];

#ifdef WITH_POSIX_ACL
  acl_type* acl;
#endif

  mode_t perm;
  mode_t perm_o; /* Permission for tree traverse */
  long uid; /* uid_t */
  long gid; /* gid_t */
  time_t atime;
  time_t ctime;
  time_t mtime;
  long inode; /* ino_t */
  long nlink; /* nlink_t */

  long long size; /* off_t */
  long long bcount; /* blkcnt_t */
  char* filename;
  char* fullpath;
  char* linkname;

  char *cntx;

#ifdef WITH_XATTR
  xattrs_type* xattrs;
#endif

  unsigned long e2fsattrs;

  char* capabilities;

  /* Attributes .... */
  DB_ATTR_TYPE attr;

} db_line;

#endif
