/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2023 Hannes von Haugwitz
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

#ifndef TREE_H_INCLUDED
#define TREE_H_INCLUDED

typedef struct tree_node tree_node;

typedef int (*tree_cmp_f)(const void*, const void*);

tree_node *tree_insert(tree_node *, void *, void *, tree_cmp_f);
void *tree_search(tree_node *, void *, tree_cmp_f);

tree_node *tree_walk_first(tree_node *);
tree_node *tree_walk_next(tree_node *);

void *tree_get_data(tree_node *n);

#endif
