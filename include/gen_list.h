/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2010,2016,2019,2020,2021 Rami Lehti,Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
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

#ifndef _GEN_LIST_H_INCLUDED
#define _GEN_LIST_H_INCLUDED
#include <pcre.h>
#include "seltree.h"
#include "list.h"

/* DB_FOO are anded together to form rx_rule's attr */

int compare_node_by_path(const void *n1, const void *n2);

/* 
 * populate_tree()
 * Populate tree with data from disk and db 
 * Also do comparing while adding to the tree
 */
void populate_tree(seltree* tree);

#define NO_LIMIT_MATCH -2
#define PARTIAL_LIMIT_MATCH -1
#define NO_MATCH 0
#define SELECTIVE_MATCH 1
#define EQUAL_MATCH 2

int check_rxtree(char*,seltree*, rx_rule* *, RESTRICTION_TYPE);

db_line* get_file_attrs(char* filename,DB_ATTR_TYPE attr, struct stat *fs);

#endif /*_GEN_LIST_H_INCLUDED*/
