/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti,Pablo Virolainen
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

#ifndef _DB_LIST_H_INCLUDED
#define _DB_LIST_H_INCLUDED
typedef struct db_list{
  dbline* data
  db_list* next
  db_list* prev
  db_list* head
  db_list* tail
} db_list

/* Only the head knows for sure where the tail is */
static db_list* db_list_head=NULL;

void db_list_append(db_list*item);

#endif /* _DB_LIST_H_INCLUDED */


