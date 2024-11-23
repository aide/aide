/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2010, 2020-2024 Rami Lehti, Pablo Virolainen,
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

#ifndef _SELTREE_H_INCLUDED
#define _SELTREE_H_INCLUDED
#include "log.h"
#include "file.h"
#include "rx_rule.h"

typedef struct seltree seltree;

seltree* init_tree(void);

seltree* get_seltree_node(seltree* ,char*);
seltree* get_or_create_seltree_node(seltree*, char *);

rx_rule * add_rx_to_tree(char *, rx_restriction_t, AIDE_RULE_TYPE, seltree *, int, char *, char *, char **);

match_t check_seltree(seltree *, file_t, bool);

void log_tree(LOG_LEVEL, seltree *, int);
bool is_tree_empty(seltree *);
#endif /* _SELTREE_H_INCLUDED*/
