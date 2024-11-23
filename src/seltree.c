/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2009-2011, 2015-2016, 2019-2024 Rami Lehti,
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

#include "file.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "attributes.h"
#include "list.h"
#include "log.h"
#include <string.h>
#include "rx_rule.h"
#include "seltree.h"
#include "seltree_struct.h"
#include "util.h"
#include "errorcodes.h"
#include "db.h"

void log_tree(LOG_LEVEL log_level, seltree* node, int depth) {

    list* r;
    rx_rule* rxc;

    pthread_mutex_lock(&node->mutex);

    log_msg(log_level, "%-*s %s:", depth, depth?"\u251d":"\u250c", node->path);

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
        log_msg(log_level, "%-*s  '%s%s %s' (%s:%d: '%s%s%s')", depth+2, "\u2502", get_rule_type_char(rxc->type), rxc->rx, rs_str = get_restriction_string(rxc->restriction), rxc->config_filename, rxc->config_linenumber, rxc->config_line, rxc->prefix?"', prefix: '":"", rxc->prefix?rxc->prefix:"");
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

    pthread_mutexattr_t attr;
    pthread_mutexattr_init (&attr);
    pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&node->mutex, &attr);

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
    pthread_mutex_lock(&node->mutex);
    log_msg(log_level, "_get_seltree_node(): %s> node: '%s' (%p), create: %s", path, node->path, (void*) node, btoa(create));
    pthread_mutex_unlock(&node->mutex);
    seltree *parent = NULL;
    char *tmp = checked_strdup(path);
    if (node && strcmp(node->path, path) != 0) {
        char *next_dir = path;;
        do {
            parent = node;
            next_dir = strchr(&next_dir[1], '/');
            if (next_dir) { tmp[next_dir-path] = '\0'; }
            pthread_mutex_lock(&parent->mutex);
            log_msg(log_level, "_get_seltree_node(): %s> search for child node '%s' (parent: '%s' (%p))", path, strrchr(tmp,'/'), parent->path, (void*) parent);
            node = tree_search(parent->children, strrchr(tmp,'/'), (tree_cmp_f) strcmp);
            pthread_mutex_unlock(&parent->mutex);
            if (next_dir) { tmp[next_dir-path] = '/'; }
        } while (node != NULL && next_dir);
        if (create && node == NULL) {
            while (next_dir) {
                tmp[next_dir-path] = '\0';
                node = _insert_new_node(tmp, parent);
                log_msg(log_level, "_get_seltree_node(): %s> created new inner node '%s' (%p) (parent: %p)", path, tmp, (void*) node, (void*) parent);
                parent = node;
                tmp[next_dir-path] = '/';
                next_dir = strchr(&next_dir[1], '/');
            }
            node = _insert_new_node(path, parent);
            log_msg(LOG_LEVEL_TRACE, "created new leaf node '%s' (%p) (parent: %p)", path, (void*) node, (void*) parent);
        }
    }
    free(tmp);
    if (node == NULL) {
        log_msg(log_level, "_get_seltree_node(): %s> return NULL (node == NULL)", path);
    } else {
        pthread_mutex_lock(&node->mutex);
        log_msg(log_level, "_get_seltree_node(): %s> return node: '%s' (%p)", path, node->path, (void*) node);
        pthread_mutex_unlock(&node->mutex);
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
    log_msg(LOG_LEVEL_DEBUG, "created root node '%s' (%p)", node->path, (void*) node);
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

rx_rule * add_rx_to_tree(char * rx, rx_restriction_t restriction, AIDE_RULE_TYPE rule_type, seltree *tree, int linenumber, char* filename, char* linebuf, char **node_path) {
    rx_rule* r = NULL;
    seltree *curnode = NULL;
    char *rxtok = NULL;

    r=(rx_rule*)checked_malloc(sizeof(rx_rule));

    r->rx=rx;
    r->type = rule_type;
    r->restriction = restriction;

    r->config_linenumber = linenumber;
    r->config_filename = filename;
    r->config_line = checked_strdup(linebuf);
    r->prefix = NULL;
    r->attr = 0;

    int pcre2_errorcode;
    PCRE2_SIZE pcre2_erroffset;

    if((r->crx=pcre2_compile((PCRE2_SPTR) r->rx, PCRE2_ZERO_TERMINATED, PCRE2_UTF|PCRE2_ANCHORED, &pcre2_errorcode, &pcre2_erroffset, NULL)) == NULL) {
        PCRE2_UCHAR pcre2_error[128];
        pcre2_get_error_message(pcre2_errorcode, pcre2_error, 128);
        log_msg(LOG_LEVEL_ERROR, "%s:%d:%zu: error in rule '%s': %s (line: '%s')", filename, linenumber, pcre2_erroffset, rx, pcre2_error, linebuf);
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
            case AIDE_RECURSIVE_NEGATIVE_RULE:
            case AIDE_NON_RECURSIVE_NEGATIVE_RULE:{
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

        while (curnode) {
            pthread_mutex_t *mutex = &curnode->mutex;
            pthread_mutex_lock(mutex);
            if(curnode->checked&NODE_HAS_SUB_RULES) {
                curnode = NULL;;
            } else {
                log_msg(LOG_LEVEL_DEBUG, "set NODE_HAS_SUB_RULES for node '%s' (%p)", curnode->path, (void*) curnode);
                curnode->checked |= NODE_HAS_SUB_RULES;
                curnode = curnode->parent;
            }
            pthread_mutex_unlock(mutex);
        }
    }
    return r;
}

#define LOG_MATCH(log_level, border, format, ...) \
    log_msg(log_level, "%s %*c'%s' " #format " of %s (%s:%d: '%s%s%s')", border, depth, ' ', file.name, __VA_ARGS__, get_rule_type_long_string(rx->type), rx->config_filename, rx->config_linenumber, rx->config_line, rx->prefix?"', prefix: '":"", rx->prefix?rx->prefix:"");

static int check_list_for_match(list* rxrlist, file_t file, rx_rule* *rule, int depth)
{
  list* r=NULL;
  int retval=RESULT_NO_RULE_MATCH;
  int pcre_retval;
  char *rs_str = NULL;
  for(r=rxrlist;r;r=r->next){
      rx_rule *rx = (rx_rule*)r->data;

      pcre_retval = pcre2_match(rx->crx, (PCRE2_SPTR) file.name, PCRE2_ZERO_TERMINATED, 0, PCRE2_PARTIAL_SOFT, rx->md, NULL);
      if (pcre_retval >= 0) { /* matching regex */
          if (!rx->restriction.f_type || file.type&rx->restriction.f_type) { /* no file type restriction OR matching file type */
                  *rule = rx;
                  LOG_MATCH(LOG_LEVEL_RULE, "\u251d", matches regex '%s' and restriction '%s', rx->rx, rs_str = get_restriction_string(rx->restriction))
                  free(rs_str);
                  switch(rx->type) {
                      case AIDE_SELECTIVE_RULE:
                          retval = RESULT_SELECTIVE_MATCH;
                          break;
                      case AIDE_EQUAL_RULE:
                          retval = RESULT_EQUAL_MATCH;
                          break;
                      case AIDE_RECURSIVE_NEGATIVE_RULE:
                          retval = RESULT_RECURSIVE_NEGATIVE_MATCH;
                          break;
                      case AIDE_NON_RECURSIVE_NEGATIVE_RULE:
                          retval = RESULT_NON_RECURSIVE_NEGATIVE_MATCH;
                          break;
                  }
                  break;
          } else { /* file type restriction does not match */
              LOG_MATCH(LOG_LEVEL_DEBUG, "\u2502", does not match file type of rule restriction '%s', rs_str = get_restriction_string(rx->restriction))
              free(rs_str);
              retval=RESULT_PARTIAL_MATCH;
          }
      } else if (pcre_retval == PCRE2_ERROR_PARTIAL) { /* partial match of regex */
          LOG_MATCH(LOG_LEVEL_DEBUG, "\u2502", partially matches regex '%s', rx->rx)
          retval=RESULT_PARTIAL_MATCH;
      } else { /* regex does not match */
          LOG_MATCH(LOG_LEVEL_DEBUG, "\u2502", does not match regex '%s', rx->rx)
          /* RESULT_NO_RULE_MATCH */
      }
  }
  return retval;
}

static match_result _get_default_match_result(const seltree *node, int depth) {
    if (node->checked&NODE_HAS_SUB_RULES) {
        log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cdirectory node '%s' (%p) has NODE_HAS_SUB_RULES set (set default match result to RESULT_PARTIAL_MATCH)", depth, ' ', node->path, (void*) node);
        return RESULT_PARTIAL_MATCH;
    }
    log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cdirectory node '%s' (%p) has NODE_HAS_SUB_RULES NOT set (keep default match result at RESULT_NO_RULE_MATCH)", depth, ' ', node->path, (void*) node);
    return RESULT_NO_RULE_MATCH;
}

static match_t check_node_for_match(seltree *pnode, file_t file) {

    match_t match = { RESULT_NO_RULE_MATCH, NULL, 0 };
    match_result result;
    int depth = 1;

    char *last_slash = strrchr(file.name,'/');
    int parent_length = (last_slash != file.name?last_slash-file.name:0);

    pthread_mutex_lock(&pnode->mutex);
    log_msg(LOG_LEVEL_TRACE, "\u2502 check_node_for_match: pnode: '%s' (%p), filename: '%s', file_type: %c", pnode->path, (void*) pnode, file.name, get_f_type_char_from_f_type(file.type));
    if (strncmp(pnode->path, file.name, parent_length) == 0) {

        if (file.type == FT_DIR) {
            if (strcmp(pnode->path, file.name) == 0) {
                match.result = _get_default_match_result(pnode, depth);
            } else {
                seltree * child_node = tree_search(pnode->children, last_slash, (tree_cmp_f) strcmp);
                if (child_node) {
                    pthread_mutex_lock(&child_node->mutex);
                    match.result = _get_default_match_result(child_node, depth);
                    pthread_mutex_unlock(&child_node->mutex);
                } else {
                    log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cno node for directory '%s' exists (keep default match result at RESULT_NO_RULE_MATCH)", depth, ' ', file.name);
                }
            }
        }

        if (pnode->equ_rx_lst) {
            log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check equal list", depth, ' ', pnode->path);
            result = check_list_for_match(pnode->equ_rx_lst, file, &match.rule, depth+2);
            if (result == RESULT_EQUAL_MATCH || result == RESULT_PARTIAL_MATCH) {
                match.result = result;
            }
        } else {
            log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip equal list (reason: list is empty)", depth, ' ', pnode->path);
        }
    } else {
        log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s' skip equal list (reason: not on top level)", depth, ' ', pnode->path);
    }
    pthread_mutex_unlock(&pnode->mutex);

    /* seltree* stack for negative rules */
    int i = 0;
    seltree * p = pnode;
    while (p) {
        pthread_mutex_t *mutex = &p->mutex;
        pthread_mutex_lock(mutex);
        p = p->parent;
        i++;
        pthread_mutex_unlock(mutex);
    }
    seltree* *nodes = checked_malloc(sizeof(seltree*)*i);

    i = 0;
    seltree *next_parent = NULL;;
    /* check selective rules down -> top */
    do {
        pthread_mutex_lock(&pnode->mutex);
        if (pnode->sel_rx_lst || pnode->neg_rx_lst) {
            nodes[i++] = pnode;

            if (match.result != RESULT_EQUAL_MATCH && match.result != RESULT_SELECTIVE_MATCH) {
                if (pnode->sel_rx_lst) {
                    log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check selective list", depth, ' ', pnode->path);
                    result = check_list_for_match(pnode->sel_rx_lst, file, &match.rule, depth+2);
                    if (result == RESULT_SELECTIVE_MATCH || result == RESULT_PARTIAL_MATCH) {
                        match.result = result;
                    }
                } else {
                    log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip selective list (reason: list is empty)", depth, ' ', pnode->path);
                }
            } else {
                log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip selective list (reason: previous positive match)", depth, ' ', pnode->path);
            }
            depth++;
        } else {
            log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip selective and negative list (reason: lists are empty)", depth, ' ', pnode->path);
        }
        next_parent = pnode->parent;
        pthread_mutex_unlock(&pnode->mutex);
    } while ((pnode = next_parent));

    /* check negative rules top -> down */
    while (--i >=0) {
        pnode = nodes[i];
        depth--;
        pthread_mutex_lock(&pnode->mutex);
        if (match.result == RESULT_EQUAL_MATCH || match.result == RESULT_SELECTIVE_MATCH || match.result == RESULT_PARTIAL_MATCH) {
            if (pnode->neg_rx_lst) {
                log_msg(LOG_LEVEL_RULE, "\u2502 %*cnode: '%s': check negative list (reason: previous positive/partial match)", depth, ' ', pnode->path);
                result = check_list_for_match(pnode->neg_rx_lst, file, &match.rule, depth+2);
                if ((match.result != RESULT_PARTIAL_MATCH && result == RESULT_RECURSIVE_NEGATIVE_MATCH) || result == RESULT_NON_RECURSIVE_NEGATIVE_MATCH) {
                    match.result = result;
                }
            } else {
                log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip negative list (reason: list is empty)", depth, ' ', pnode->path);
            }
        } else if (match.result == RESULT_NON_RECURSIVE_NEGATIVE_MATCH || match.result == RESULT_RECURSIVE_NEGATIVE_MATCH) {
            log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip negative list (reason: previous negative match)", depth, ' ', pnode->path);
        } else {
            log_msg(LOG_LEVEL_DEBUG, "\u2502 %*cnode: '%s': skip negative list (reason: no previous positive/partial match)", depth, ' ', pnode->path);
        }
        pthread_mutex_unlock(&pnode->mutex);
    }
    free(nodes);
    log_msg(LOG_LEVEL_TRACE, "\u2502 check_node_for_match: match result %s (%d) for '%s'", get_match_result_string(match.result), match.result, file.name);
    return match;
}

static seltree *_cache_parent_result(char *parent, seltree* node, seltree *pnode, int flag) {
    if (!node) {
        node = _insert_new_node(parent, pnode);
    }
    pthread_mutex_lock(&node->mutex);
    node->checked |= flag;
    pthread_mutex_unlock(&node->mutex);
    return node;
}

match_t check_seltree(seltree *tree, file_t file, bool check_parent_dirs) {
    seltree* pnode=NULL;
    match_t match = { RESULT_NO_RULE_MATCH, NULL, 0 };
    bool parent_negative_match = false;

    const char *next_dir = file.name;
    char *parent = checked_strdup(file.name); /* freed below */
    pnode = tree;
    seltree *node = tree;

    log_msg(LOG_LEVEL_TRACE, "\u2502 search for parent node for '%s'  (tree: '%s' (%p))", file.name, tree->path, (void*) tree);

    if (strcmp(file.name, "/") == 0) { check_parent_dirs = false; } /* do not check parent directories for '/' */

    char *relative_child_path = parent;
    while ((next_dir = strchr(next_dir, '/'))) {
        int parent_length = next_dir-file.name;
        int relative_child_path_start = parent_length;
        if (next_dir == file.name) { /* handle "/" directory */
            parent_length = 1;
            relative_child_path_start = 0;
        }
        parent[parent_length] = '\0';

        if (node && relative_child_path_start) {
            node = get_seltree_node(pnode, relative_child_path);
            if (node) {
                pthread_mutex_lock(&node->mutex);
                log_msg(LOG_LEVEL_TRACE, "\u2502 got %s (%p) for '%s'", node->path, (void*) node, relative_child_path);
                pthread_mutex_unlock(&node->mutex);
                pnode = node;
            }
        }

        if (check_parent_dirs) {
            pthread_mutex_lock(&pnode->mutex);
            if (pnode == node && pnode->checked&NODE_PARENT_POSTIVE_MATCH) {
                log_msg(LOG_LEVEL_DEBUG, "\u2502 (cache) positive match for parent directory '%s' (node: '%s' (%p))", parent, pnode->path, (void*) pnode);
            } else if (pnode == node && pnode->checked&NODE_PARENT_NEGATIVE_MATCH) {
                log_msg(LOG_LEVEL_RULE, "\u2502 (cache) negative match for parent directory '%s' (node: '%s' (%p))", parent, pnode->path, (void*) pnode);
                match.result = RESULT_NEGATIVE_PARENT_MATCH;
                match.length = parent_length;
                parent_negative_match = true;
            } else if (pnode == node && pnode->checked&NODE_PARENT_NO_RULE_MATCH) {
                log_msg(LOG_LEVEL_RULE, "\u2502 (cache) no rule match for parent directory '%s' (node: '%s' (%p))", parent, pnode->path, (void*) pnode);
                match.result = RESULT_NO_RULE_MATCH;
                parent_negative_match = true;
            } else {
                log_msg(LOG_LEVEL_RULE, "\u2502 check parent directory '%s' for no-recurse match (node: '%s' (%p))", parent, pnode->path, (void*) pnode);
                match = check_node_for_match(pnode, (file_t) { .name = parent, .type = FT_DIR,
                    });
                if (match.result == RESULT_NON_RECURSIVE_NEGATIVE_MATCH) {
                    match.result = RESULT_NEGATIVE_PARENT_MATCH;
                    match.length = parent_length;
                    parent_negative_match = true;
                    node = _cache_parent_result(parent, node, pnode, NODE_PARENT_NEGATIVE_MATCH);
                    pthread_mutex_lock(&node->mutex);
                    log_msg(LOG_LEVEL_DEBUG, "\u2502 cache non-recursive negative match of parent directory '%s' (node: '%s' (%p))", parent, node->path, (void*) node);
                    pthread_mutex_unlock(&node->mutex);
                } else if(match.result == RESULT_NO_RULE_MATCH) {
                    parent_negative_match = true;
                    node = _cache_parent_result(parent, node, pnode, NODE_PARENT_NO_RULE_MATCH);
                    pthread_mutex_lock(&node->mutex);
                    log_msg(LOG_LEVEL_DEBUG, "\u2502 cache no rule match of parent directory '%s' (node: '%s' (%p))", parent, node->path, (void*) node);
                    pthread_mutex_unlock(&node->mutex);
                } else {
                    node = _cache_parent_result(parent, node, pnode, NODE_PARENT_POSTIVE_MATCH);
                    pthread_mutex_lock(&node->mutex);
                    log_msg(LOG_LEVEL_DEBUG, "\u2502 cache positive match of parent directory '%s' (node: '%s' (%p))", parent, node->path, (void*) node);
                    pthread_mutex_unlock(&node->mutex);
                }
                if (!parent_negative_match) {
                    log_msg(LOG_LEVEL_RULE, "\u2502 no no-recurse match found for parent directory '%s'", parent);
                }
            }
            pthread_mutex_unlock(&pnode->mutex);
            if (parent_negative_match) {
                break;
            }
        }

        parent[parent_length] = file.name[parent_length];
        relative_child_path = &parent[relative_child_path_start];
        next_dir += 1;
    }
    pthread_mutex_lock(&pnode->mutex);
    log_msg(LOG_LEVEL_TRACE, "\u2502 got parent node '%s' (%p) for parent name '%s'", pnode->path, (void*) pnode, parent);
    pthread_mutex_unlock(&pnode->mutex);
    free(parent);
    if (!parent_negative_match) {
        log_msg(LOG_LEVEL_RULE, "\u2502 check '%s' (filetype: %c)", file.name, get_f_type_char_from_f_type(file.type));
        match = check_node_for_match(pnode, file);
    }

    log_msg(LOG_LEVEL_DEBUG, "\u2502 check_selree: match result %s (%d) for '%s'", get_match_result_string(match.result), match.result, file.name);
    return match;
}
