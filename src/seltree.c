/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2009-2011, 2015-2016, 2019-2022 Rami Lehti,
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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "attributes.h"
#include "list.h"
#include "log.h"
#include "rx_rule.h"
#include "seltree.h"
#include "seltree_struct.h"
#include "util.h"

#define PARTIAL_RULE_MATCH       (-1)
#define NO_RULE_MATCH            (0)
#define RESTRICTED_RULE_MATCH    (1)
#define RULE_MATCH               (2)

void log_tree(LOG_LEVEL log_level, seltree* tree, int depth) {

    list* r;
    rx_rule* rxc;

    log_msg(log_level, "%-*s %s:", depth, depth?"\u251d":"\u250c", tree->path, tree);

    char *attr_str, *rs_str;

    for(r=tree->equ_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        log_msg(log_level, "%-*s  '=%s %s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", rxc->rx, rs_str = get_restriction_string(rxc->restriction), attr_str = diff_attributes(0, rxc->attr), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
        free(rs_str);
        free(attr_str);
    }
    for(r=tree->sel_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        log_msg(log_level, "%-*s  '%s %s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", rxc->rx, rs_str = get_restriction_string(rxc->restriction), attr_str = diff_attributes(0, rxc->attr), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
        free(rs_str);
        free(attr_str);
    }
    for(r=tree->neg_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        log_msg(log_level, "%-*s  '!%s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", rxc->rx, rs_str = get_restriction_string(rxc->restriction), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
        free(rs_str);
    }

    for(r=tree->childs;r!=NULL;r=r->next) {
        log_tree(log_level, r->data, depth+2);
    }
    if (depth == 0) {
        log_msg(log_level, "%s", "\u2514");
    }
}

/*
 * strrxtok()
 * return a pointer to a copy of the non-regexp path part of the argument
 */
static char* strrxtok(char* rx)
{
  char*p=NULL;
  size_t i=0;

  /* The following code assumes that the first character is a slash */
  size_t lastslash=1;

  p=checked_strdup(rx);
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
        for (int j = i; p[j]; j++) {
            p[j] = p[j+1];
        }
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

  p=(char*)checked_malloc(sizeof(char)*lastslash+1);
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
    return checked_strdup(path);

  tmp=checked_strdup(path);

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

  node=(seltree*)checked_malloc(sizeof(seltree));
  node->childs=NULL;
  node->path=checked_strdup(path);
  node->sel_rx_lst=NULL;
  node->neg_rx_lst=NULL;
  node->equ_rx_lst=NULL;
  node->checked=0;
  node->new_data=NULL;
  node->old_data=NULL;
  node->changed_attrs = 0;

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
  log_msg(LOG_LEVEL_DEBUG, "new node '%s' (%p, parent: %p)", node->path, node, node->parent);
  return node;
}

seltree *init_tree() {
    seltree* node = new_seltree_node(NULL,"/",0,NULL);
    log_msg(LOG_LEVEL_DEBUG, "added new node '%s' (%p) for '%s' (reason: root node)", node->path, node, "/");
    return node;
}

rx_rule * add_rx_to_tree(char * rx, RESTRICTION_TYPE restriction, int rule_type, seltree *tree, int linenumber, char* filename, char* linebuf) {
    rx_rule* r = NULL;
    seltree *curnode = NULL;
    char *rxtok = NULL;

    r=(rx_rule*)checked_malloc(sizeof(rx_rule));

    r->rx=rx;
    r->restriction = restriction;

    r->config_filename = NULL;
    r->config_line = NULL;
    r->config_linenumber = -1;
    r->attr = 0;

    int pcre2_errorcode;
    PCRE2_SIZE pcre2_erroffset;

    if((r->crx=pcre2_compile((PCRE2_SPTR) r->rx, PCRE2_ZERO_TERMINATED, PCRE2_UTF|PCRE2_ANCHORED, &pcre2_errorcode, &pcre2_erroffset, NULL)) == NULL) {
        PCRE2_UCHAR pcre2_error[128];
        pcre2_get_error_message(pcre2_errorcode, pcre2_error, 128);
        log_msg(LOG_LEVEL_ERROR, "%s:%d:%i: error in rule '%s': %s (line: '%s')", filename, linenumber, pcre2_erroffset, rx, pcre2_error, linebuf);
        free(r);
        return NULL;
    } else {
        r->md = pcre2_match_data_create_from_pattern(r->crx, NULL);
        if (r->md == NULL) {
            log_msg(LOG_LEVEL_ERROR, "pcre2_match_data_create_from_pattern: failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        int pcre2_jit = pcre2_jit_compile(r->crx, PCRE2_JIT_PARTIAL_SOFT);
        if (pcre2_jit < 0) {
            PCRE2_UCHAR pcre2_error[128];
            pcre2_get_error_message(pcre2_jit, pcre2_error, 128);
            log_msg(LOG_LEVEL_NOTICE, "JIT compilation for regex '%s' failed: %s (fall back to interpreted matching)", r->rx, pcre2_error);
        } else {
            log_msg(LOG_LEVEL_DEBUG, "JIT compilation for regex '%s' successful", r->rx);
        }

        rxtok=strrxtok(r->rx);
        curnode=get_seltree_node(tree,rxtok);

        for(size_t i=1;i < strlen(rxtok); ++i){
            if (rxtok[i] == '/' && rxtok[i-1] == '/') {
                log_msg(LOG_LEVEL_ERROR, "%s:%d:1: error in rule '%s': invalid double slash (line: '%s')", filename, linenumber, rx, linebuf);
                free(r);
                return NULL;
            }
        }

        if(curnode == NULL){
            curnode=new_seltree_node(tree,rxtok,1,r);
            log_msg(LOG_LEVEL_DEBUG, "added new node '%s' (%p) for '%s' (reason: new rule '%s')", curnode->path, curnode, rxtok, r->rx);
        }
        r->node = curnode;
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

#define LOG_MATCH(log_level, border, format, ...) \
    log_msg(log_level, "%s %*c'%s' " #format " of %s (%s:%d: '%s%s%s')", border, depth+2, ' ', text, __VA_ARGS__, get_rule_type_long_string(rule_type), rx->config_filename, rx->config_linenumber, rx->config_line, rx->prefix?"', prefix: '":"", rx->prefix?rx->prefix:"");

static int check_list_for_match(list* rxrlist,char* text, rx_rule* *rule, RESTRICTION_TYPE file_type, int rule_type, int depth, bool unrestricted_only)
{
  list* r=NULL;
  int retval=NO_RULE_MATCH;
  int pcre_retval;
  char *rs_str = NULL;
  for(r=rxrlist;r;r=r->next){
      rx_rule *rx = (rx_rule*)r->data;

      if (!(unrestricted_only && rx->restriction)) {

      pcre_retval = pcre2_match(rx->crx, (PCRE2_SPTR) text, PCRE2_ZERO_TERMINATED, 0, PCRE2_PARTIAL_SOFT, rx->md, NULL);
      if (pcre_retval >= 0) {
          if (!rx->restriction || file_type&rx->restriction) {
                  *rule = rx;
                  retval = rx->restriction?RESTRICTED_RULE_MATCH:RULE_MATCH;
                  LOG_MATCH(LOG_LEVEL_RULE, "\u251d", matches regex '%s' and restriction '%s', rx->rx, rs_str = get_restriction_string(rx->restriction))
                  free(rs_str);
                  break;
          } else {
              LOG_MATCH(LOG_LEVEL_RULE, "\u2502", does not match restriction '%s', rs_str = get_restriction_string(rx->restriction))
              free(rs_str);
              retval=PARTIAL_RULE_MATCH;
          }
      } else if (pcre_retval == PCRE2_ERROR_PARTIAL) {
          LOG_MATCH(LOG_LEVEL_RULE, "\u2502", partially matches regex '%s', rx->rx)
          retval=PARTIAL_RULE_MATCH;
      } else {
          LOG_MATCH(LOG_LEVEL_RULE, "\u2502", does not match regex '%s', rx->rx)
      }

      } else {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cskip restricted '%s' rule as requested (%s:%d: '%s')", depth+2, ' ', rs_str = get_restriction_string(rx->restriction), rx->config_filename, rx->config_linenumber, rx->config_line);
          free(rs_str);
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
 *32,  top-level call
 */
static int check_node_for_match(seltree *node, char *text, RESTRICTION_TYPE file_type, int retval, rx_rule* *rule, int depth)
{

  if(node==NULL){
      return retval;
  }

  if (node->equ_rx_lst || node->sel_rx_lst || node->neg_rx_lst) {

  /* if this call is not recursive we check the equals list and we set top *
   * and retval so we know following calls are recursive */
  if(!(retval&16)){
      retval|=16;

      if (node->equ_rx_lst) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check equal list", depth, ' ', node->path);
          switch (check_list_for_match(node->equ_rx_lst, text, rule, file_type, AIDE_EQUAL_RULE, depth, false)) {
              case RESTRICTED_RULE_MATCH:
              case RULE_MATCH: {
                          log_msg(LOG_LEVEL_RULE, "\u2502 %*cequal match for '%s' (node: '%s')", depth, ' ', text, node->path);
                          retval|=2|4;
                          break;
                      }
              case PARTIAL_RULE_MATCH: {
                           if(file_type&FT_DIR && get_seltree_node(node,text)==NULL) {
                               seltree *new_node = new_seltree_node(node,text,0,NULL);
                               log_msg(LOG_LEVEL_DEBUG, "added new node '%s' (%p) for '%s' (reason: partial equal match for directory)", new_node->path, new_node, text);
                           }
                           break;
                       }
          }
      } else {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': skip equal list (reason: list is empty)", depth, ' ', node->path);
      }
  } else {
      log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s' skip equal list (reason: not on top level)", depth, ' ', node->path);
  }
  /* We'll use retval to pass information on whether to recurse
   * the dir or not */

  /* If 4 and 8 are not set, we will check for matches */
  if(!(retval&(4|8))){
      if (node->sel_rx_lst) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check selective list", depth, ' ', node->path);
          switch (check_list_for_match(node->sel_rx_lst, text, rule, file_type, AIDE_SELECTIVE_RULE, depth, false)) {
              case RESTRICTED_RULE_MATCH:
              case RULE_MATCH: {
                          log_msg(LOG_LEVEL_RULE, "\u2502 %*cselective match for '%s' (node: '%s')", depth, ' ', text, node->path);
                          retval|=1|8;
                          break;
                      }
              case PARTIAL_RULE_MATCH: {
                           if(file_type&FT_DIR && get_seltree_node(node,text)==NULL) {
                               seltree *new_node = new_seltree_node(node,text,0,NULL);
                               log_msg(LOG_LEVEL_DEBUG, "added new node '%s', (%p) for '%s' (reason: partial selective match for directory)", new_node->path, new_node, text);
                           }
                           break;
                       }
          }
      } else {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': skip selective list (reason: list is empty)", depth, ' ', node->path);
      }
  } else {
      log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': skip selective list (reason: previous positive match)", depth, ' ', node->path);
  }

  /* Now let's check the ancestors */
  retval=check_node_for_match(node->parent, text, file_type, retval&~32, rule, depth+2);

  /* Negative regexps are the strongest so they are checked last */
  /* If this file is to be added */
  if(retval&(1|2)){
      if (node->neg_rx_lst) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check negative list (reason: previous positive match)", depth, ' ', node->path);

          char* parentname=checked_strdup(text);
          do {
              char *tmp=strrchr(parentname,'/');
              if(tmp != parentname){
                  *tmp='\0';
              } else {
                  parentname[1]='\0';
              }
              if (strcmp(parentname,node->path) > 0) {
                  log_msg(LOG_LEVEL_RULE, "\u2502 %*ccheck parent directory '%s' (unrestricted rules only)", depth+2, ' ', parentname);
                  if (check_list_for_match(node->neg_rx_lst, parentname, rule, FT_DIR, AIDE_NEGATIVE_RULE, depth+4, true) == RULE_MATCH) {
                      log_msg(LOG_LEVEL_RULE, "\u2502 %*cnegative match for parent directory '%s'", depth, ' ', parentname);
                      retval=0;;
                      break;
                  }
              }
          } while (strcmp(parentname,node->path) > 0);
          free(parentname);

          if (retval) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*ccheck file '%s'", depth+2, ' ', text);
          switch (check_list_for_match(node->neg_rx_lst, text, rule, file_type, AIDE_NEGATIVE_RULE, depth+2, false)) {
              case RESTRICTED_RULE_MATCH: {
                  if(file_type&FT_DIR && get_seltree_node(node,text)==NULL) {
                      seltree *new_node = new_seltree_node(node,text,0,NULL);
                      log_msg(LOG_LEVEL_DEBUG, "added new node '%s' (%p) for '%s' (reason: restricted negative match for directory)", new_node->path, new_node, text);
                  }

              }
              // fall through
              case RULE_MATCH: {
                  log_msg(LOG_LEVEL_RULE, "\u2502 %*cnegative match for '%s' (node: '%s')", depth, ' ', text, node->path);
                  retval=0;
                  break;
              }
          }
          } else {
            log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': skip checking file '%s' (reason: negative match for a parent directory)", depth, ' ', node->path, text);
          }
      } else {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': skip negative list (reason: list is empty)", depth, ' ', node->path);
      }
  } else {
      log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': skip negative list (reason: no previous positive match)", depth, ' ', node->path);
  }

  } else {
    log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cskip node '%s' (reason: no regex rules)", depth, ' ', node->path);
    retval = check_node_for_match(node->parent, text, file_type, (retval|16)&~32, rule, depth);
  }

  /* Now we discard the info whether a match was made or not *
   * and just return 0,1 or 2 */
  if(!(retval&32)){
      retval&=3;
  }
  return retval;
}

int check_seltree(seltree *tree, char *filename, RESTRICTION_TYPE file_type, rx_rule* *rule) {
  log_msg(LOG_LEVEL_RULE, "\u2502 check '%s'", filename);
  char * tmp=NULL;
  char * parentname=NULL;
  seltree* pnode=NULL;
  int retval = 0;

  parentname=checked_strdup(filename);

  do {

  tmp=strrchr(parentname,'/');
  if(tmp!=parentname){
    *tmp='\0';
  }else {
      /* we are in the root dir */
      parentname[1]='\0';
  }

  pnode=get_seltree_node(tree,parentname);
  if (pnode == NULL) {
    retval |= 16;
  }

  } while (pnode == NULL);

  log_msg(LOG_LEVEL_DEBUG, "got parent node '%s' (%p) for parentname '%s'", pnode->path, pnode, parentname);

  free(parentname);

  retval = check_node_for_match(pnode, filename, file_type, retval|32 ,rule, 0);

  if (retval) {
    char *str;
    log_msg(LOG_LEVEL_RULE, "\u2534 ADD '%s' to the tree (attr: '%s')", filename, str = diff_attributes(0, (*rule)->attr));
    free(str);

    if(get_seltree_node(tree,filename)==NULL) {
        seltree *new_node = new_seltree_node(tree,filename,0,NULL);
        log_msg(LOG_LEVEL_DEBUG, "added new node '%s', (%p) for '%s' (reason: full match)", new_node->path, new_node, filename);
    }
  } else {
    log_msg(LOG_LEVEL_RULE, "\u2534 do NOT add '%s' to the tree", filename);
  }
  return retval;
}
