/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006,2009-2011,2015,2016,2019,2020 Rami Lehti,
 * Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
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

#include <stdlib.h>
#include <string.h>

#include "seltree.h"
#include "error.h"

#define PARTIAL_RULE_MATCH       (-1)
#define NO_RULE_MATCH            (0)
#define RESTRICTED_RULE_MATCH    (1)
#define RULE_MATCH               (2)


void print_tree(seltree* tree) {

  list* r;
  rx_rule* rxc;
  error(220,"tree: \"%s\"\n",tree->path);

  for(r=tree->sel_rx_lst;r!=NULL;r=r->next) {
       rxc=r->data;
       error(220,"\t%s\n",rxc->rx);
  }
  for(r=tree->equ_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        error(220,"=\t%s\n",rxc->rx);
  }

  for(r=tree->neg_rx_lst;r!=NULL;r=r->next) {
         rxc=r->data;
         error(220,"!\t%s\n",rxc->rx);
  }

  for(r=tree->childs;r!=NULL;r=r->next) {
       print_tree(r->data);
  }
}

/*
 * strrxtok()
 * return a pointer to a copy of the non-regexp path part of the argument
 */
static char* strrxtok(char* rx)
{
  char*p=NULL;
  char*t=NULL;
  size_t i=0;

  /* The following code assumes that the first character is a slash */
  size_t lastslash=1;

  p=strdup(rx);
  p[0]='/';

  for(i=1;i<strlen(p);i++){
    switch(p[i])
      {
      case '/':
	lastslash=i;
	break;
      case '(':
      case '^':
      case '$':
      case '?':
      case '*':
      case '[':
	i=strlen(p);
	break;
      case '\\':
	t=strdup(p);
	strcpy(p+i,t+i+1);
	free(t);
	t=NULL;
	break;
      default:
	break;
      }
  }

  p[lastslash]='\0';

  return p;
}

static char* strlastslash(char*str)
{
  char* p=NULL;
  size_t lastslash=1;
  size_t i=0;

  for(i=1;i<strlen(str);i++){
    if(str[i]=='/'){
      lastslash=i;
    }
  }

  p=(char*)malloc(sizeof(char)*lastslash+1);
  strncpy(p,str,lastslash);
  p[lastslash]='\0';

  return p;
}

char* strgetndirname(char* path,int depth)
{
  char* r=NULL;
  char* tmp=NULL;
  int i=0;

  for(r=path;;r+=1){
    if(*r=='/')
      i++;
    if(*r=='\0')
      break;
    if(i==depth)
      break;
  }
  /* If we ran out string return the whole string */
  if(!(*r))
    return strdup(path);

  tmp=strdup(path);

  tmp[r-path]='\0';

  return tmp;
}

int treedepth(seltree* node)
{
  seltree* r=NULL;
  int depth=0;

  for(r=node;r;r=r->parent)
    depth++;

  return depth;
}

int compare_node_by_path(const void *n1, const void *n2)
{
    const seltree *x1 = n1;
    const seltree *x2 = n2;
    return strcmp(x1->path, x2->path);
}

seltree* get_seltree_node(seltree* tree,char* path)
{
  seltree* node=NULL;
  list* r=NULL;
  char* tmp=NULL;

  if(tree==NULL){
    return NULL;
  }

  if(strncmp(path,tree->path,strlen(path)+1)==0){
    return tree;
  }
  else{
    tmp=strgetndirname(path,treedepth(tree)+1);
    for(r=tree->childs;r;r=r->next){
      if(strncmp(((seltree*)r->data)->path,tmp,strlen(tmp)+1)==0){
	node=get_seltree_node((seltree*)r->data,path);
	if(node!=NULL){
	  /* Don't leak memory */
	  free(tmp);
	  return node;
	}
      }
    }
    free(tmp);
  }
  return NULL;
}


seltree* new_seltree_node(
        seltree* tree,
        char*path,
        int isrx,
        rx_rule* r)
{
  seltree* node=NULL;
  seltree* parent=NULL;
  char* tmprxtok = NULL;

  node=(seltree*)malloc(sizeof(seltree));
  node->childs=NULL;
  node->path=strdup(path);
  node->sel_rx_lst=NULL;
  node->neg_rx_lst=NULL;
  node->equ_rx_lst=NULL;
  node->checked=0;
  node->attr=0;
  node->new_data=NULL;
  node->old_data=NULL;

  if(tree!=NULL){
    tmprxtok = strrxtok(path);
    if(isrx){
      parent=get_seltree_node(tree,tmprxtok);
    }else {
      char* dirn=strlastslash(path);
      parent=get_seltree_node(tree,dirn);
      free(dirn);
    }
    if(parent==NULL){
      if(isrx){
	parent=new_seltree_node(tree,tmprxtok,isrx,r);
      }else {
        char* dirn=strlastslash(path);
        parent=new_seltree_node(tree,dirn,isrx,r);
        free(dirn);
      }
    }
    free(tmprxtok);
    parent->childs=list_sorted_insert(parent->childs,(void*)node, compare_node_by_path);
    node->parent=parent;
  }else {
    node->parent=NULL;
  }
  return node;
}

seltree *init_tree() {
    return new_seltree_node(NULL,"/",0,NULL);
}

rx_rule * add_rx_to_tree(char * rx, RESTRICTION_TYPE restriction, int rule_type, seltree *tree, char *node_path, const char **pcre_error, int *pcre_erroffset) {
    rx_rule* r = NULL;
    seltree *curnode = NULL;
    char *rxtok = NULL;

    r=(rx_rule*)malloc(sizeof(rx_rule));

    r->rx=rx;
    r->restriction = restriction;

    if((r->crx=pcre_compile(r->rx, PCRE_ANCHORED, pcre_error, pcre_erroffset, NULL)) == NULL) {
        free(r);
        return NULL;
    } else {
        rxtok=strrxtok(r->rx);
        curnode=get_seltree_node(tree,rxtok);

        if(curnode == NULL){
            curnode=new_seltree_node(tree,rxtok,1,r);
        }
        if (node_path) {
            node_path = curnode->path;
        }
        switch (rule_type){
            case AIDE_NEGATIVE_RULE:{
                curnode->neg_rx_lst=list_append(curnode->neg_rx_lst,(void*)r);
                break;
            }
            case AIDE_EQUAL_RULE:{
                curnode->equ_rx_lst=list_append(curnode->equ_rx_lst,(void*)r);
                break;
            }
            case AIDE_SELECTIVE_RULE:{
                curnode->sel_rx_lst=list_append(curnode->sel_rx_lst,(void*)r);
                break;
            }
        }
        free(rxtok);
    }
    return r;
}

static int check_list_for_match(list* rxrlist,char* text,DB_ATTR_TYPE* attr, RESTRICTION_TYPE file_type)
{
  list* r=NULL;
  int retval=NO_RULE_MATCH;
  int pcre_retval;
  pcre_extra *pcre_extra = NULL;
  for(r=rxrlist;r;r=r->next){
      rx_rule *rx = (rx_rule*)r->data;
      pcre_retval=pcre_exec((pcre*)rx->crx, pcre_extra, text, strlen(text), 0, PCRE_PARTIAL_SOFT, NULL, 0);
      if (pcre_retval >= 0) {
          if (!rx->restriction || file_type&rx->restriction) {
              if (retval != RULE_MATCH && retval != RESTRICTED_RULE_MATCH) { /* no match before */
                  *attr=rx->attr;
                  retval = rx->restriction?RESTRICTED_RULE_MATCH:RULE_MATCH;
                  break;
              }
          } else {
              retval=PARTIAL_RULE_MATCH;
          }
      } else if (pcre_retval == PCRE_ERROR_PARTIAL) {
          retval=PARTIAL_RULE_MATCH;
      }
  }
  return retval;
}

/*
 * Function check_node_for_match()
 * calls itself recursively to go to the top and then back down.
 * uses check_list_for_match()
 * returns:
 * 0,  if a negative rule was matched
 * 1,  if a selective rule was matched
 * 2,  if a equals rule was matched
 * retval if no rule was matched.
 * retval&3 if no rule was matched and first in the recursion
 * to keep state revat is orred with:
 * 4,  matched deeper on equ rule
 * 8,  matched deeper on sel rule
 *16,  this is a recursed call
 */
static int check_node_for_match(seltree *node, char *text, RESTRICTION_TYPE file_type, int retval, DB_ATTR_TYPE *attr, int depth)
{
  int top=0;

  if(node==NULL){
      return retval;
  }

  /* if this call is not recursive we check the equals list and we set top *
   * and retval so we know following calls are recursive */
  if(!(retval&16)){
      top=1;
      retval|=16;

      if (node->equ_rx_lst) {
          switch (check_list_for_match(node->equ_rx_lst, text, attr, file_type)) {
              case RESTRICTED_RULE_MATCH:
              case RULE_MATCH: {
                          retval|=2|4;
                          break;
                      }
              case PARTIAL_RULE_MATCH: {
                           if(file_type&RESTRICTION_FT_DIR && get_seltree_node(node,text)==NULL) {
                               new_seltree_node(node,text,0,NULL);
                           }
                           break;
                       }
          }
      }
  }
  /* We'll use retval to pass information on whether to recurse
   * the dir or not */

  /* If 4 and 8 are not set, we will check for matches */
  if(!(retval&(4|8))){
      if (node->sel_rx_lst) {
          switch (check_list_for_match(node->sel_rx_lst, text, attr, file_type)) {
              case RESTRICTED_RULE_MATCH:
              case RULE_MATCH: {
                          retval|=1|8;
                          break;
                      }
              case PARTIAL_RULE_MATCH: {
                           if(file_type&RESTRICTION_FT_DIR && get_seltree_node(node,text)==NULL) {
                               new_seltree_node(node,text,0,NULL);
                           }
                           break;
                       }
          }
      }
  }

  /* Now let's check the ancestors */
  retval=check_node_for_match(node->parent, text, file_type, retval,attr, depth+2);

  /* Negative regexps are the strongest so they are checked last */
  /* If this file is to be added */
  if(retval){
      if (node->neg_rx_lst) {
          switch (check_list_for_match(node->neg_rx_lst, text, attr, file_type)) {
              case RESTRICTED_RULE_MATCH: {
                  if(file_type&RESTRICTION_FT_DIR && get_seltree_node(node,text)==NULL) {
                      new_seltree_node(node,text,0,NULL);
                  }

              }
              // fall through
              case RULE_MATCH: {
                  retval=0;
                  break;
              }
          }
      } else {
      }
  }
  /* Now we discard the info whether a match was made or not *
   * and just return 0,1 or 2 */
  if(top){
      retval&=3;
  }
  return retval;
}

int check_seltree(seltree *tree, char *filename, RESTRICTION_TYPE file_type, DB_ATTR_TYPE *attr) {
  char * tmp=NULL;
  char * parentname=NULL;
  seltree* pnode=NULL;
  int retval = 0;

  parentname=strdup(filename);
  tmp=strrchr(parentname,'/');
  if(tmp!=parentname){
    *tmp='\0';
  }else {

    if(parentname[1]!='\0'){
      /* we are in the root dir */
      parentname[1]='\0';
    }
  }

  pnode=get_seltree_node(tree,parentname);
  free(parentname);

  retval = check_node_for_match(pnode, filename, file_type, 0,attr, 0);
  if (retval) {
    if(get_seltree_node(tree,filename)==NULL) {
        new_seltree_node(tree,filename,0,NULL);
    }
  }
  return retval;
}
