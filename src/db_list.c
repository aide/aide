/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002,2022 Rami Lehti, Pablo Virolainen,
 *                              Hannes von Haugwitz
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

#include "db_list.h"

void db_list_append(db_list*item)
{
  db_list* tmp_listp=NULL;
  item->next=NULL;
  item->prev=NULL;
  item->head=NULL;
  
  if(db_list_head==NULL){
    db_list_head=item;
    db_list_head->next=NULL;
    db_list_head->prev=NULL;
    db_list_head->head=db_list_head;
    db_list_head->tail=db_list_head;
    return;
  }
  else {
    tmp_listp=db_list_head->tail;
    tmp_listp->next=item;
    tmp_listp->tail=item;
    item->head=db_list_head;
    item->tail=db_list_head;
    db_list_head->tail=item;
    return;
  }
}

