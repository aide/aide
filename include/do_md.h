/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2010,2011 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg, Hannes von Haugwitz
 * 
 * $Header$
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
 
#ifndef _DO_MD_H_INCLUDED
#define _DO_MD_H_INCLUDED
#ifdef WITH_MHASH
#include "mhash.h"
#endif

#include "list.h"
#include "db_config.h"

#define BUFSIZE 16384

list* do_md(list* file_lst,db_config* conf);

#ifdef WITH_ACL
void acl2line(db_line* line);
#endif

#ifdef WITH_XATTR
void xattrs2line(db_line *line);
#endif

#ifdef WITH_SELINUX
void selinux2line(db_line *line);
#endif

#ifdef WITH_E2FSATTRS
void e2fsattrs2line(db_line* line);
#endif

#endif /* _DO_MD_H_INCLUDED */
