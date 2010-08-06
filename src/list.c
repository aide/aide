/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2005,2006,2010 Rami Lehti,Pablo Virolainen,
 * Richard van den Berg, Hannes von Haugwitz
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

#include "aide.h"
#include <stdlib.h>
#include "list.h"
#include "report.h"
/*for locale support*/
#include "locale-aide.h"
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
    newitem=(list*)malloc(sizeof(list));
    if (newitem==NULL) {
        error(0,"Not enough memory to add a new item to list.\n");
        exit(EXIT_FAILURE);
    }
    if (listp==NULL){
        list_header* header=(list_header*)malloc(sizeof(list_header));
        if (header==NULL){
            error(0,"Not enough memory for list header allocation\n");
            exit(EXIT_FAILURE);
        }
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


/* 
 * Some way to handle mallocs failure would be nice.
 */

list* list_append(list* listp,void*data)
{
  list* newitem=NULL;
  newitem=(list*)malloc(sizeof(list));

  if (newitem==NULL) {
    error(0,"Not enough memory to add a new item to list.\n");
    exit(EXIT_FAILURE);
  }
  
  if(listp==NULL){
    list_header* header=(list_header*)malloc(sizeof(list_header));
    
    if (header==NULL){
      error(0,"Not enough memory for list header allocation\n");
      exit(EXIT_FAILURE);
    }
    
    newitem->data=data;
    newitem->header=header;
    newitem->next=NULL;
    newitem->prev=NULL;

    header->head=newitem;
    header->tail=newitem;

    return newitem;
  }else {
    
    /* We have nonempthy list.
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
    error(200,"Tried to remove from empthy list\n");
    return item;
  }
  
  if (item->header->head==item->header->tail) {
    /*
     * Ollaan poistamassa listan ainoaa alkiota.
     * Tällöin palautetaan NULL
     */
    free(item->header);
    free(item);
    return NULL;
  }
  
  /* 
   * Nyt meillä on listassa ainakin kaksi alkiota 
   *  
   */

  /* poistetaan listan viimeistä alkiota */

  if (item==item->header->tail){
    
    r=item->prev;
    item->header->tail=r;
    r->next=NULL;
    r=r->header->head;
    free(item);
    return r;
  }

  /*
   * Poistetaan listan ensimmäinen alkio.
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
