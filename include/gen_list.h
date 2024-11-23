/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2010-2011, 2016, 2019-2024 Rami Lehti,
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

#ifndef _GEN_LIST_H_INCLUDED
#define _GEN_LIST_H_INCLUDED
#include <stdbool.h>
#include "attributes.h"
#include "rx_rule.h"
#include "db_config.h"
#include "file.h"
#include "seltree.h"
#include "db_disk.h"

struct stat;

/* DB_FOO are anded together to form rx_rule's attr */

/* 
 * populate_tree()
 * Populate tree with data from disk and db 
 * Also do comparing while adding to the tree
 */
void populate_tree(seltree*);

void write_tree(seltree*);

match_t check_rxtree(file_t, seltree*, char *, bool);
match_result check_limit(char*, bool);

struct db_line* get_file_attrs(disk_entry *);
void add_file_to_tree(seltree*, db_line*, int, const database *, struct stat *);

void print_match(file_t, match_t);
#endif /*_GEN_LIST_H_INCLUDED*/
