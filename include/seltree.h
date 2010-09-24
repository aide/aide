/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2010 Rami Lehti,Pablo Virolainen, Hannes von
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
struct seltree;
#include "db_config.h"
#include "list.h"


/* seltree structure
 * lists have regex_t* in them
 * checked is whether or not the node has been checked yet and status
 * when added  
 * path is the path of the node
 * parent is the parent, NULL if root
 * childs is list of seltree*:s
 * new_data is this nodes new attributes (read from disk or db in --compare)
 * old_data is this nodes old attributes (read from db)
 * attr attributes to add for this node and possibly for its children
 * changed_attrs changed attributes between new_data and old_data
 */

typedef struct seltree {
  list* sel_rx_lst;
  list* neg_rx_lst;
  list* equ_rx_lst;
  list* childs;
  struct seltree* parent;

  char* path;
  int checked;

  long      conf_lineno;
  char*     rx;    

  DB_ATTR_TYPE attr;

  struct db_line* new_data;
  struct db_line* old_data;

  DB_ATTR_TYPE changed_attrs;

} seltree;

#endif /* _SELTREE_H_INCLUDED*/
