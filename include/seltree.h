/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2010,2020 Rami Lehti,Pablo Virolainen, Hannes von
 * Haugwitz
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

#ifndef _SELTREE_H_INCLUDED
#define _SELTREE_H_INCLUDED
#include "attributes.h"
#include "seltree_struct.h"
#include "rx_rule.h"

#define AIDE_NEGATIVE_RULE -1
#define AIDE_EQUAL_RULE 0
#define AIDE_SELECTIVE_RULE 1

seltree* init_tree();

seltree* new_seltree_node(seltree*, char*, int, rx_rule*);

seltree* get_seltree_node(seltree* ,char*);

rx_rule * add_rx_to_tree(char *, RESTRICTION_TYPE, int, seltree *, char *, const char **, int *);

int check_seltree(seltree *, char *, RESTRICTION_TYPE, DB_ATTR_TYPE *);

int treedepth(seltree *);

void print_tree(seltree *);

char* strgetndirname(char* ,int);
#endif /* _SELTREE_H_INCLUDED*/
