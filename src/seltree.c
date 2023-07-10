/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2009-2011, 2015-2016, 2019-2023 Rami Lehti,
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
#include <pthread.h>
#include "attributes.h"
#include "list.h"
#include "log.h"
#include <string.h>
#include "rx_rule.h"
#include "seltree.h"
#include "seltree_struct.h"
#include "util.h"
#include "errorcodes.h"

#define NO_RULE_MATCH               0
#define NEGATIVE_RULE_MATCH     (1<<0)
#define SELECtIVE_RULE_MATCH    (1<<1)
#define EQUAL_RULE_MATCH        (1<<2)
#define RESTRICTED_RULE_MATCH   (1<<3)
#define PARTIAL_RULE_MATCH      (1<<4)
#define RULE_MATCH              (EQUAL_RULE_MATCH|SELECtIVE_RULE_MATCH)

#define DEEP_EQUAL_MATCH        (1<<5)
#define DEEP_SELECTIVE_MATCH    (1<<6)
#define RECURSED_CALL           (1<<7)
#define TOP_LEVEL_CALL          (1<<8)

void log_tree(LOG_LEVEL log_level, seltree* node, int depth) {

    list* r;
    rx_rule* rxc;

    pthread_mutex_lock(&node->mutex);

    log_msg(log_level, "%-*s %s:", depth, depth?"\u251d":"\u250c", node->path, node);

    char *attr_str, *rs_str;

    for(r=node->equ_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        log_msg(log_level, "%-*s  '=%s %s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", rxc->rx, rs_str = get_restriction_string(rxc->restriction), attr_str = diff_attributes(0, rxc->attr), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
        free(rs_str);
        free(attr_str);
    }
    for(r=node->sel_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        log_msg(log_level, "%-*s  '%s %s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", rxc->rx, rs_str = get_restriction_string(rxc->restriction), attr_str = diff_attributes(0, rxc->attr), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
        free(rs_str);
        free(attr_str);
    }
    for(r=node->neg_rx_lst;r!=NULL;r=r->next) {
        rxc=r->data;
        log_msg(log_level, "%-*s  '!%s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", rxc->rx, rs_str = get_restriction_string(rxc->restriction), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
        free(rs_str);
    }

    for(tree_node *n = tree_walk_first(node->children); n != NULL ; n = tree_walk_next(n)) {
        log_tree(log_level, tree_get_data(n), depth+2);
    }

    pthread_mutex_unlock(&node->mutex);

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


static seltree *create_seltree_node(char *path, seltree *parent) {
    seltree *node = checked_malloc(sizeof(seltree)); /* not to be freed */

    node->path = checked_strdup(path); /* not to be freed */
    node->parent = parent;

    pthread_mutex_init(&node->mutex, NULL);

    node->sel_rx_lst = NULL;
    node->neg_rx_lst = NULL;
    node->equ_rx_lst = NULL;

    node->children = NULL;

    node->checked = 0;
    node->new_data = NULL;
    node->old_data = NULL;
    node->changed_attrs = 0;

    return node;
}

static seltree *_insert_new_node(char *path, seltree *parent) {
    seltree *node = create_seltree_node(path, parent);
    pthread_mutex_lock(&parent->mutex);
    parent ->children = tree_insert(parent->children, strrchr(node->path,'/'), (void*)node, (tree_cmp_f) strcmp);
    pthread_mutex_unlock(&parent->mutex);
    return node;
}

static seltree* _get_seltree_node(seltree* node, char *path, bool create) {
    LOG_LEVEL log_level = LOG_LEVEL_TRACE;
    seltree *parent = NULL;
    char *tmp = checked_strdup(path);
    if (node && strcmp(node->path, path) != 0) {
        char *next_dir = path;;
        do {
            parent = node;
            next_dir = strchr(&next_dir[1], '/');
            if (next_dir) { tmp[next_dir-path] = '\0'; }
            pthread_mutex_lock(&parent->mutex);
            node = tree_search(parent->children, strrchr(tmp,'/'), (tree_cmp_f) strcmp);
            pthread_mutex_unlock(&parent->mutex);
            if (next_dir) { tmp[next_dir-path] = '/'; }
        } while (node != NULL && next_dir);
        if (create && node == NULL) {
            while (next_dir) {
                tmp[next_dir-path] = '\0';
                node = _insert_new_node(tmp, parent);
                log_msg(log_level, "_get_seltree_node(): %s> created new inner node '%s' (%p) (parent: %p)", path, tmp, node, parent);
                parent = node;
                tmp[next_dir-path] = '/';
                next_dir = strchr(&next_dir[1], '/');
            }
            node = _insert_new_node(path, parent);
            log_msg(LOG_LEVEL_DEBUG, "created new leaf node '%s' (%p) (parent: %p)", path, node, parent);
        }
    }
    free(tmp);
    if (node == NULL) {
        log_msg(log_level, "_get_seltree_node(): %s> return NULL (node == NULL)", path);
    } else {
        log_msg(log_level, "_get_seltree_node(): %s> return node: '%s' (%o)", path, node->path, node);
    }
    return node;
}

seltree* get_or_create_seltree_node(seltree* node, char *path) {
    return _get_seltree_node(node, path, true);
}

seltree* get_seltree_node(seltree* node, char *path) {
    return _get_seltree_node(node, path, false);
}

seltree *init_tree(void) {
    seltree *node = create_seltree_node("/", NULL);
    log_msg(LOG_LEVEL_DEBUG, "created root node '%s' (%p)", node->path, node);
    return node;
}

bool is_tree_empty(seltree *node) {
    pthread_mutex_lock(&node->mutex);
    bool is_empty = (node->children == NULL
          && node->equ_rx_lst == NULL
          && node->sel_rx_lst == NULL
          && node->neg_rx_lst == NULL
        );
    pthread_mutex_unlock(&node->mutex);
    return is_empty;
}

rx_rule * add_rx_to_tree(char * rx, RESTRICTION_TYPE restriction, int rule_type, seltree *tree, int linenumber, char* filename, char* linebuf, char **node_path) {
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
            exit(MEMORY_ALLOCATION_FAILURE);
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

        for(size_t i=1;i < strlen(rxtok); ++i){
            if (rxtok[i] == '/' && rxtok[i-1] == '/') {
                log_msg(LOG_LEVEL_ERROR, "%s:%d:1: error in rule '%s': invalid double slash (line: '%s')", filename, linenumber, rx, linebuf);
                free(r);
                return NULL;
            }
        }

        curnode = get_or_create_seltree_node(tree, rxtok);

        pthread_mutex_lock(&curnode->mutex);
        *node_path = curnode->path;
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
        pthread_mutex_unlock(&curnode->mutex);
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

  pthread_mutex_lock(&node->mutex);

  if (node->equ_rx_lst || node->sel_rx_lst || node->neg_rx_lst) {

  /* if this call is not recursive we check the equals list and we set top *
   * and retval so we know following calls are recursive */
  if(!(retval&RECURSED_CALL)){
      retval|=RECURSED_CALL;

      if (node->equ_rx_lst) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check equal list", depth, ' ', node->path);
          switch (check_list_for_match(node->equ_rx_lst, text, rule, file_type, AIDE_EQUAL_RULE, depth, false)) {
              case RESTRICTED_RULE_MATCH:
              case RULE_MATCH: {
                          log_msg(LOG_LEVEL_RULE, "\u2502 %*cequal match for '%s' (node: '%s')", depth, ' ', text, node->path);
                          retval|=EQUAL_RULE_MATCH|DEEP_EQUAL_MATCH;
                          break;
                      }
              case PARTIAL_RULE_MATCH: {
                           retval|=PARTIAL_RULE_MATCH;
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

  /* If we have no deep matches, we will check for matches */
  if(!(retval&(DEEP_EQUAL_MATCH|DEEP_SELECTIVE_MATCH))){
      if (node->sel_rx_lst) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check selective list", depth, ' ', node->path);
          switch (check_list_for_match(node->sel_rx_lst, text, rule, file_type, AIDE_SELECTIVE_RULE, depth, false)) {
              case RESTRICTED_RULE_MATCH:
              case RULE_MATCH: {
                          log_msg(LOG_LEVEL_RULE, "\u2502 %*cselective match for '%s' (node: '%s')", depth, ' ', text, node->path);
                          retval|=SELECtIVE_RULE_MATCH|DEEP_SELECTIVE_MATCH;
                          break;
                      }
              case PARTIAL_RULE_MATCH: {
                           retval|=PARTIAL_RULE_MATCH;
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
  retval=check_node_for_match(node->parent, text, file_type, retval&~TOP_LEVEL_CALL, rule, depth+2);

  /* Negative regexps are the strongest so they are checked last */
  /* If this file is to be added */
  if(retval&(SELECtIVE_RULE_MATCH|EQUAL_RULE_MATCH)){
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
                      retval=NEGATIVE_RULE_MATCH;
                      break;
                  }
              }
          } while (strcmp(parentname,node->path) > 0);
          free(parentname);

          if (retval != NEGATIVE_RULE_MATCH) {
          log_msg(LOG_LEVEL_RULE, "\u2502 %*ccheck file '%s'", depth+2, ' ', text);
          switch (check_list_for_match(node->neg_rx_lst, text, rule, file_type, AIDE_NEGATIVE_RULE, depth+2, false)) {
              case RESTRICTED_RULE_MATCH: {
                  retval=PARTIAL_RULE_MATCH;
                  break;
              }
              case RULE_MATCH: {
                  log_msg(LOG_LEVEL_RULE, "\u2502 %*cnegative match for '%s' (node: '%s')", depth, ' ', text, node->path);
                  retval=NEGATIVE_RULE_MATCH;
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
    retval = check_node_for_match(node->parent, text, file_type, (retval|RECURSED_CALL)&~TOP_LEVEL_CALL, rule, depth);
  }

  /* Now we discard the info whether a match was made or not *
   * and just return 0,1 or 2 */
  if(!(retval&TOP_LEVEL_CALL)){
      if (retval&(EQUAL_RULE_MATCH|SELECtIVE_RULE_MATCH)) {
        retval&=(EQUAL_RULE_MATCH|SELECtIVE_RULE_MATCH);
      } else {
        retval&=PARTIAL_RULE_MATCH;
      }
  }
  pthread_mutex_unlock(&node->mutex);
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

  log_msg(LOG_LEVEL_TRACE, "\u2502 search for parent node '%s' (tree: '%s' (%p))", parentname, tree->path, tree);
  pnode=get_seltree_node(tree,parentname);
  if (pnode == NULL) {
    retval |= RECURSED_CALL;
  }

  } while (pnode == NULL);

  log_msg(LOG_LEVEL_DEBUG, "\u2502 got parent node '%s' (%p) for parentname '%s'", pnode->path, pnode, parentname);

  free(parentname);

  retval = check_node_for_match(pnode, filename, file_type, retval|TOP_LEVEL_CALL ,rule, 0);

  if (retval&(SELECtIVE_RULE_MATCH|EQUAL_RULE_MATCH)) {
    get_or_create_seltree_node(tree, filename);

    char *str;
    log_msg(LOG_LEVEL_RULE, "\u2534 ADD '%s' (attr: '%s')", filename, str = diff_attributes(0, (*rule)->attr));
    free(str);
  } else {
    log_msg(LOG_LEVEL_RULE, "\u2534 do NOT add '%s'", filename);
  }
  log_msg(LOG_LEVEL_TRACE, "check_seltree: return %d for '%s'", retval, filename);
  return retval;
}
