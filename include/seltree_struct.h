/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2010, 2020, 2023, 2025 Rami Lehti, Pablo Virolainen,
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

#ifndef _SELTREE_STRUCT_H_INCLUDED
#define _SELTREE_STRUCT_H_INCLUDED
#include <pthread.h>
#include "attributes.h"
#include "list.h"
#include "tree.h"

struct seltree {

  pthread_rwlock_t rwlock;

  list* sel_rx_lst;
  list* neg_rx_lst;
  list* equ_rx_lst;

  struct seltree* parent;

  tree_node *children;

  char* path;
  int checked;

  struct db_line* new_data;
  struct db_line* old_data;

  DB_ATTR_TYPE changed_attrs;

};
#endif /* _SELTREE_STRUCT_H_INCLUDED */
