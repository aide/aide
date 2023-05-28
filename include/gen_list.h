/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2010-2011, 2016, 2019-2023 Rami Lehti,
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
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "attributes.h"
#include "rx_rule.h"
#include "seltree.h"
struct stat;

/* DB_FOO are anded together to form rx_rule's attr */

/* 
 * populate_tree()
 * Populate tree with data from disk and db 
 * Also do comparing while adding to the tree
 */
void populate_tree(seltree*);

void write_tree(seltree*);

typedef enum match_result {
    RESULT_NO_MATCH = 0,
    RESULT_SELECTIVE_MATCH = 2,
    RESULT_EQUAL_MATCH = 4,
    RESULT_PARTIAL_MATCH = 16,
    RESULT_NO_LIMIT_MATCH = 32,
    RESULT_PARTIAL_LIMIT_MATCH = 64,
} match_result;

match_result check_rxtree(char*,seltree*, rx_rule* *, RESTRICTION_TYPE, char *);

struct db_line* get_file_attrs(char*,DB_ATTR_TYPE, struct stat *);
void add_file_to_tree(seltree*, db_line*, int, const database *, struct stat *);

void print_match(char*, rx_rule*, match_result, RESTRICTION_TYPE);
#endif /*_GEN_LIST_H_INCLUDED*/
