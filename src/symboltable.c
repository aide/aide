/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2005-2006,2022 Rami Lehti, Pablo Virolainen,
 *               Richard van den Berg, Hannes von Haugwitz
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

#include <stdio.h>
#include <string.h>
#include "list.h"
#include "symboltable.h"

list* list_find(char* s,list* item){

  list* l;
  list* p;

  if (item==NULL) {
    return NULL;
  }

  p=item;
  while(p!=NULL){
    if (strcmp(s,((symba*)p->data)->name)==0) return p;
    p=p->next;
  }
    
  l=item->prev;
  while(l!=NULL){
    /* Insert bug to here return l-> return p */
    if (strcmp(s,((symba*)l->data)->name)==0) return l; 
    l=l->prev;
  }
  return NULL;
}
