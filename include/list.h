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

#ifndef _LIST_H_INCLUDED
#define _LIST_H_INCLUDED

typedef struct list {
  struct list* next;
  struct list* prev;

  struct list_header* header;

  /*
  struct list* head;
  struct list* tail;
  */

  void* data;
} list;

typedef struct list_header{
  
  struct list* head;
  struct list* tail;
  
}list_header;

list* list_sorted_insert(list* listp, void* data, int (*compare) (const void*, const void*));

list* list_append(list* listp,void*data);

/*

list* new_list_item(void*);

*/

list* list_delete_item(list* item);

#endif /* _DB_LIST_H_INCLUDED */


