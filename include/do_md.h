/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002,2006,2010-2011,2019,2022,2023,2025 Rami Lehti, Pablo
 *               Virolainen, Richard van den Berg, Hannes von Haugwitz
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

#ifndef _DO_MD_H_INCLUDED
#define _DO_MD_H_INCLUDED

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "db_disk.h"
#include "list.h"
#include "db_config.h"
#include "md.h"

list* do_md(list* file_lst,db_config* conf);
md_hashsums calc_hashsums(disk_entry *, DB_ATTR_TYPE, ssize_t, bool);

#ifdef WITH_ACL
void acl2line(db_line* line, int);
#endif

#ifdef WITH_XATTR
void xattrs2line(db_line *line, int);
#endif

#ifdef WITH_SELINUX
void selinux2line(db_line *line, int);
#endif

#ifdef WITH_E2FSATTRS
void e2fsattrs2line(db_line* line, int);
#endif

#ifdef WITH_CAPABILITIES
void capabilities2line(db_line* line, int);
#endif

#endif /* _DO_MD_H_INCLUDED */
