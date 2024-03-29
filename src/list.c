/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2005-2006, 2010, 2019-2020, 2023 Rami Lehti,
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

#include <stdlib.h>
#include "list.h"
#include "log.h"
#include "util.h"
/*for locale support*/

/* list
 * limitations:
 * Only the head knows where the tail is
 * Every item knows where the head is
 
 * And that is not true anymore. 
 * Now list has header which knows head and tail.
 * Every item knows header.
 
 */

/* list_sorted_insert()
 * Adds an item in a sorted list:
 *   - The first argument is the head of the list
 *   - The second argument is the data to be added
 *   - The third argument is the function pointer to the compare function to use
 *   - Returns the head of the list
 */
list* list_sorted_insert(list* listp, void* data, int (*compare) (const void*, const void*)) {
    list* newitem=NULL;
    list* curitem=NULL;
    newitem = checked_malloc(sizeof(list));
    if (listp==NULL){
        list_header* header = checked_malloc(sizeof(list_header));
        newitem->data=data;
        newitem->header=header;
        newitem->next=NULL;
        newitem->prev=NULL;
        header->head=newitem;
        header->tail=newitem;
        return newitem;
    } else {
        /* add element in sorted, non-empty list (use insertion sort) */
        curitem = listp->header->head;
        newitem->header=listp->header;
        newitem->data=data;
        if (compare(newitem->data,curitem->data) <= 0) {
            /* new element is the new head */
            listp->header->head=newitem;
            curitem->prev=newitem;
            newitem->next=curitem;
            newitem->prev=NULL;
            return newitem;
        } else {
            /* find position for new element */
            while(compare(newitem->data, curitem->data) > 0 && curitem->next != NULL) {
               curitem=curitem->next;
            }
            if (curitem->next == NULL && compare(newitem->data, curitem->data) > 0) {
                /* new element is the new tail */
                listp->header->tail=newitem;
                curitem->next=newitem;
                newitem->prev=curitem;
                newitem->next=NULL;
            } else {
                /* new element is an inner element */
                curitem->prev->next=newitem;
                newitem->prev=curitem->prev;
                curitem->prev=newitem;
                newitem->next=curitem;
            }
        }
        return listp;
    }
}

/* list_append()
 * append an item to list
 * returns the head
 * The first argument is the head of the list
 * The second argument is the data to be added
 * Returns list head
 */
list* list_append(list* listp,void*data)
{
  list* newitem=NULL;
  newitem = checked_malloc(sizeof(list));
  
  if(listp==NULL){
    list_header* header = checked_malloc(sizeof(list_header));
    
    newitem->data=data;
    newitem->header=header;
    newitem->next=NULL;
    newitem->prev=NULL;

    header->head=newitem;
    header->tail=newitem;

    return newitem;
  }else {
    
    /* We have nonempty list.
     * add to last
     */
    
    newitem->prev=listp->header->tail;
    newitem->next=NULL;
    newitem->data=data;
    newitem->header=listp->header;
    
    listp->header->tail->next=newitem;
    listp->header->tail=newitem;
    return listp;
  }
  /* Not reached */
  return NULL;
}

/*
 * delete_list_item()
 * delete a item from list
 * returns head of a list.
 */

list* list_delete_item(list* item){
  list* r;


  if (item==NULL) {
      log_msg(LOG_LEVEL_DEBUG, "tried to remove from empty list");
    return item;
  }
  
  if (item->header->head==item->header->tail) {
    /*
     * Ollaan poistamassa listan ainoaa alkiota.
     * T�ll�in palautetaan NULL
     */
    free(item->header);
    free(item);
    return NULL;
  }
  
  /* 
   * Nyt meill� on listassa ainakin kaksi alkiota 
   *  
   */

  /* poistetaan listan viimeist� alkiota */

  if (item==item->header->tail){
    
    r=item->prev;
    item->header->tail=r;
    r->next=NULL;
    r=r->header->head;
    free(item);
    return r;
  }

  /*
   * Poistetaan listan ensimm�inen alkio.
   */  
  if (item==item->header->head) {
    
    r=item->next;
    item->header->head=r;
    r->prev=NULL;
    r=r->header->head;
    
    free(item);
    return r;
  }
  
  r=item->prev;

  item->prev->next=item->next;
  item->next->prev=item->prev;
  
  free(item);
  r=r->header->head;
  
  return r;
  
}
