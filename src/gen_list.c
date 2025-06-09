/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2009-2012, 2015-2016, 2019-2025 Rami Lehti,
 *               Pablo Virolainen, Mike Markley, Richard van den Berg,
 *               Hannes von Haugwitz
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

#include "config.h"
#include "aide.h"
#include "file.h"
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "attributes.h"
#include "hashsum.h"
#include "seltree_struct.h"
#include "rx_rule.h"
#include "url.h"
#include "gen_list.h"
#include "md.h"
#include "db.h"
#include "db_line.h"
#include "db_config.h"
#include "db_disk.h"
#include "do_md.h"
#include "log.h"
#include "progress.h"
#include "util.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

void hsymlnk(db_line* line);
void fs2db_line(struct stat* fs,db_line* line);

LOG_LEVEL compare_log_level = LOG_LEVEL_COMPARE;

static int bytecmp(byte *b1, byte *b2, size_t len) {
  return strncmp((char *)b1, (char *)b2, len);
}

static int has_str_changed(char* old,char* new) {
    return (((old!=NULL && new!=NULL) &&
                strcmp(old,new)!=0 ) ||
            ((old!=NULL && new==NULL) ||
             (old==NULL && new!=NULL)));
}

#ifdef WITH_ACL
static int has_acl_changed(const acl_type* old, const acl_type* new) {
    if (old==NULL && new==NULL) {
        return RETOK;
    }
    if (old==NULL || new==NULL) {
        return RETFAIL;
    }
#ifdef WITH_POSIX_ACL
    if ((!old->acl_a != !new->acl_a)
            || (!old->acl_d != !new->acl_d)
            || (old->acl_a && strcmp(old->acl_a, new->acl_a))
            || (old->acl_d && strcmp(old->acl_d, new->acl_d))){
        return RETFAIL;
    }
#endif
    return RETOK;
}
#endif

#ifdef WITH_XATTR
static int cmp_xattr_node(const void *c1, const void *c2)
{
  const xattr_node *x1 = c1;
  const xattr_node *x2 = c2;

  return (strcmp(x1->key, x2->key));
}
static int have_xattrs_changed(xattrs_type* x1,xattrs_type* x2) {
  size_t num = 0;

  if (x1 && (x1->num == 0)) x1 = NULL;
  if (x2 && (x2->num == 0)) x2 = NULL;

  if (x1==NULL && x2==NULL) {
    return RETOK;
  }
  if (x1==NULL || x2==NULL) {
    return RETFAIL;
  }

  if (x1->num != x2->num) {
    return RETFAIL;
  }

  qsort(x1->ents, x1->num, sizeof(xattr_node), cmp_xattr_node);
  qsort(x2->ents, x2->num, sizeof(xattr_node), cmp_xattr_node);

  while (num++ < x1->num) {
    const char *x1key = NULL;
    const byte *x1val = NULL;
    size_t x1vsz = 0;
    const char *x2key = NULL;
    const byte *x2val = NULL;
    size_t x2vsz = 0;

    x1key = x1->ents[num - 1].key;
    x1val = x1->ents[num - 1].val;
    x1vsz = x1->ents[num - 1].vsz;

    x2key = x2->ents[num - 1].key;
    x2val = x2->ents[num - 1].val;
    x2vsz = x2->ents[num - 1].vsz;

    if (strcmp(x1key, x2key) ||
        x1vsz != x2vsz ||
        memcmp(x1val, x2val, x1vsz))
      return RETFAIL;
  }

  return RETOK;
}
#endif

#ifdef WITH_E2FSATTRS
static int has_e2fsattrs_changed(unsigned long old, unsigned long new) {
    return (old^new);
}
#endif

static DB_ATTR_TYPE get_changed_hashsums(byte** old_hashsums, byte** new_hashsums, db_line* old, db_line* new, const char* whoami) {
    DB_ATTR_TYPE changed_hashsums = 0;
    bool no_hashsums_compared = true;
    for (int i = 0 ; i < num_hashes ; ++i) {
        DB_ATTR_TYPE attr = ATTR(hashsums[i].attribute);
        if (old_hashsums[i] || new_hashsums[i]) {
            if (old_hashsums[i] && new_hashsums[i]) {
                no_hashsums_compared = false;
                bool hash_has_changed = (bytecmp(old_hashsums[i], new_hashsums[i], hashsums[i].length) != 0);
                LOG_WHOAMI(LOG_LEVEL_TRACE,"│ %s hashsum %s changed (old: %p, new: %p)", attributes[hashsums[i].attribute].db_name, hash_has_changed?"has":"has NOT", (void*) old_hashsums[i], (void*) new_hashsums[i]);
                if(hash_has_changed) {
                    changed_hashsums|=attr;
                }
            } else {
                LOG_WHOAMI(LOG_LEVEL_TRACE,"│ %s hashsum comparison skipped (old: %p, new: %p)", attributes[hashsums[i].attribute].db_name, (void*) old_hashsums[i], (void*) new_hashsums[i]);
            }
        }
    }
    if (no_hashsums_compared) {
        log_msg(LOG_LEVEL_WARNING,"cannot compare hashsums of old:'%s' and new:'%s' (no common hashsum(s) available)", old->filename, new->filename);
    }
    return changed_hashsums;
}

/*
 * Returns the changed attributes for two database lines.
 *
 * Attributes are only compared if they exist in both database lines.
*/
static DB_ATTR_TYPE get_changed_attributes(db_line* l1,db_line* l2, DB_ATTR_TYPE ignore_attrs, disk_entry *entry, bool compare_hashsums, const char* whoami) {

#define easy_growing_compare(a,b) \
    if(((a&l1->attr) && (a&l2->attr))) { \
        if (l1->attr&ATTR(attr_growing)) { \
            if (l1->b < l2->b) { \
                LOG_WHOAMI(compare_log_level, "│ ignore growing " #b " change of old:'%s' and new:'%s'", l1->filename, l2->filename); \
            } else if (l1->b > l2->b) { \
                ret|=a; \
            } \
        } else if (l1->b != l2->b) { \
            ret|=a; \
        } \
    }

#define easy_compare(a,b) \
    if((a&l1->attr && (a&l2->attr)) && l1->b!=l2->b){\
        ret|=a;\
    }

#define easy_function_compare(a,b,c) \
    if((a&l1->attr && (a&l2->attr)) && c(l1->b,l2->b)){ \
        ret|=a; \
    }

    DB_ATTR_TYPE ret=0;

    if (l1->attr&ATTR(attr_growing)) {
        LOG_WHOAMI(compare_log_level, "│ old:'%s' has growing attribute set, ignore growing changes", l1->filename);
    }

    if ((ATTR(attr_ftype)&l1->attr && ATTR(attr_ftype)&l2->attr) && (l1->perm&S_IFMT)!=(l2->perm&S_IFMT)) { ret|=ATTR(attr_ftype); }
    easy_function_compare(ATTR(attr_linkname),linkname,has_str_changed);
    if ((ATTR(attr_sizeg)&l1->attr && ATTR(attr_sizeg)&l2->attr) && l1->size>l2->size){ ret|=ATTR(attr_sizeg); }
    easy_growing_compare(ATTR(attr_size),size);
    easy_growing_compare(ATTR(attr_bcount),bcount);
    easy_compare(ATTR(attr_perm),perm);
    easy_compare(ATTR(attr_uid),uid);
    easy_compare(ATTR(attr_gid),gid);
    easy_growing_compare(ATTR(attr_atime),atime);
    easy_growing_compare(ATTR(attr_mtime),mtime);
    easy_growing_compare(ATTR(attr_ctime),ctime);
    easy_compare(ATTR(attr_inode),inode);
    easy_compare(ATTR(attr_linkcount),nlink);

#ifdef HAVE_FSTYPE
    easy_compare(ATTR(attr_fs_type), fs_type);
#endif

    DB_ATTR_TYPE all_hashsums = get_hashes(true);
    if (compare_hashsums && l1->attr&all_hashsums && l2->attr&all_hashsums) {
        LOG_WHOAMI(LOG_LEVEL_TRACE, "│ compare hashsums of old:'%s' and new:'%s'", l1->filename, l2->filename);
        DB_ATTR_TYPE changed_hashsums = get_changed_hashsums(l1->hashsums, l2->hashsums, l1, l2, whoami);
        if (changed_hashsums) {
            char *str;
            str = diff_attributes(0,changed_hashsums);
            LOG_WHOAMI(compare_log_level, "│ old:'%s' and new:'%s' have CHANGED hashsum(s): %s", l1->filename, l2->filename, str);
            free(str);
            if (l1->attr&ATTR(attr_growing)) {
                if (conf->action&DO_COMPARE) {
                    if(l1->size < l2->size) {
                        if (l1->size) {
                            LOG_WHOAMI(compare_log_level, "┝ old:'%s' has growing attribute set, check for growing hashsums", l1->filename);
                            LOG_WHOAMI(compare_log_level, "│ compare hashsums of old:'%s' and new:'%s' (limited to old size %lld)", l1->filename, l2->filename, l1->size);
                            DB_ATTR_TYPE transition_hashsums = get_transition_hashsums(l1->filename, l1->attr, l2->filename, l2->attr);
                            md_hashsums hs = calc_hashsums(entry, l2->attr|transition_hashsums, l1->size, false, 0, whoami);

                            byte* new_hashsums[num_hashes];
                            copy_hashsums(l2->fullpath, &hs, &new_hashsums, whoami);

                            DB_ATTR_TYPE new_changed = get_changed_hashsums(l1->hashsums, new_hashsums, l1, l2, whoami);

                            for (int i = 0 ; i < num_hashes ; ++i) {
                                free(new_hashsums[i]);
                            }

                            if (new_changed) {
                                str = diff_attributes(0,new_changed);
                                LOG_WHOAMI(compare_log_level, "│ keep hashsums as CHANGED (hashsums of new:'%s' limited to old size %lld have been changed: %s)", l2->filename, l1->size, str);
                                free(str);
                            } else {
                                LOG_WHOAMI(compare_log_level, "│ set hashsums as UNCHANGED (hashsums of new:'%s' limited to old size %lld have NOT been changed)", l2->filename, l1->size);
                                changed_hashsums = 0;
                            }
                        } else {
                            LOG_WHOAMI(compare_log_level, "│ old:'%s' has growing attribute set, but skip hashsums calculation (file was empty before)", l1->filename);
                            LOG_WHOAMI(compare_log_level, "%s", "│ set hashsums as UNCHANGED (old size equals zero)");
                            changed_hashsums = 0;
                        }
                    } else {
                        LOG_WHOAMI(compare_log_level, "┝ old:'%s' has growing attribute set, but skip hashsum calculation (old size is greater than or equal to new size)", l1->filename);
                    }
                } else {
                    LOG_WHOAMI(compare_log_level, "┝ old:'%s' has growing attribute set, but skip hashsum calculation (NOT supported in dataase compare mode)", l1->filename);
                }
            }
        } else {
            LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ old:'%s' and new:'%s' have NO changed hashsum(s)", l1->filename, l2->filename);
        }
        ret |= changed_hashsums;
    }

#ifdef WITH_ACL
    easy_function_compare(ATTR(attr_acl),acl,has_acl_changed);
#endif
#ifdef WITH_XATTR
    easy_function_compare(ATTR(attr_xattrs),xattrs,have_xattrs_changed);
#endif
#ifdef WITH_SELINUX
    easy_function_compare(ATTR(attr_selinux),cntx,has_str_changed);
#endif
#ifdef WITH_E2FSATTRS
    easy_function_compare(ATTR(attr_e2fsattrs),e2fsattrs,has_e2fsattrs_changed);
#endif
#ifdef WITH_CAPABILITIES
    easy_function_compare(ATTR(attr_capabilities),capabilities,has_str_changed);
#endif

    char *str;
    if (ignore_attrs) {
        str = diff_attributes(0, ignore_attrs);
        LOG_WHOAMI(compare_log_level, "│ attribute changes to ignore: %s", str);
        free(str);
    }
    DB_ATTR_TYPE ignored_attributes = ret&ignore_attrs;
    char *ignored_attrs_str = ignored_attributes?diff_attributes(0, ignored_attributes):NULL;
    ret &= ~ignore_attrs;
    if (ret) {
        str = diff_attributes(0, ret);
        LOG_WHOAMI(compare_log_level, "│ old:'%s' and new:'%s' have CHANGED attributes: %s (ignored attributes: %s)", l1->filename, l2->filename, str, ignored_attrs_str?ignored_attrs_str:"<none>");
        free(str);
    } else {
        LOG_WHOAMI(compare_log_level, "│ old:'%s' and new:'%s' have NO changed attributes (ignored attributes: %s)", l1->filename, l2->filename, ignored_attrs_str?ignored_attrs_str:"<none>");
    }
    free(ignored_attrs_str);
    return ret;
}

static DB_ATTR_TYPE get_different_attributes(db_line* l1, db_line* l2, DB_ATTR_TYPE ignore_attrs, const char *whoami) {
    DB_ATTR_TYPE ret = l1->attr^l2->attr;
    char *str;
    if (ignore_attrs) {
        str = diff_attributes(0, ignore_attrs);
        LOG_WHOAMI(compare_log_level, "│ attribute differences to ignore: %s", str);
        free(str);
    }
    DB_ATTR_TYPE ignored_attributes = ret&ignore_attrs;
    char *ignored_attrs_str = ignored_attributes?diff_attributes(0, ignored_attributes):NULL;
    ret &= ~ignore_attrs;
    if (ret) {
        str = diff_attributes(l1->attr&~ignore_attrs, l2->attr&~ignore_attrs);
        LOG_WHOAMI(compare_log_level, "│ old:'%s' and new:'%s' have different attributes: %s (ignored attributes: %s)", l1->filename, l2->filename, str, ignored_attrs_str?ignored_attrs_str:"<none>");
        free(str);
    } else {
        LOG_WHOAMI(compare_log_level, "│ old:'%s' and new:'%s' have NO different attributes (ignored attributes: %s)", l1->filename, l2->filename, ignored_attrs_str?ignored_attrs_str:"<none>");
    }
    free(ignored_attrs_str);
    return ret;
}

#ifdef HAVE_FSTYPE
#define PRINT_RULE_MATCH(format, c, ...) \
    if (file.fs_type) { \
        fs_type_str = get_fs_type_string_from_magic(file.fs_type); \
        fprintf(stdout, "[%c] %c=%s:%s: " format "\n", c, file_type, fs_type_str, file.name, __VA_ARGS__); \
        free(fs_type_str); \
    } else { \
        fprintf(stdout, "[%c] %c:%s: " format "\n", c, file_type, file.name, __VA_ARGS__); \
    }
#else
#define PRINT_RULE_MATCH(format, c, ...) \
    fprintf(stdout, "[%c] %c:%s: " format "\n", c, file_type, file.name, __VA_ARGS__);
#endif

void print_match(file_t file, match_t match) {
    char * str;
    char* attr_str;
    char file_type = get_f_type_char_from_f_type(file.type);
#ifdef HAVE_FSTYPE
    char *fs_type_str = NULL;
#endif
    rx_rule *rule = match.rule;
    switch (match.result) {
        case RESULT_SELECTIVE_MATCH:
        case RESULT_EQUAL_MATCH:
            str = get_restriction_string(rule->restriction);
            attr_str = diff_attributes(0, rule->attr);
            PRINT_RULE_MATCH("%s: '%s%s %s %s' (%s:%d: '%s%s%s')", 'x', get_rule_type_long_string(rule->type), get_rule_type_char(rule->type), rule->rx, str, attr_str, rule->config_filename, rule->config_linenumber, rule->config_line, rule->prefix?"', prefix: '":"", rule->prefix?rule->prefix:"")
            free(attr_str);
            free(str);
            break;
        case RESULT_RECURSIVE_NEGATIVE_MATCH:
        case RESULT_NON_RECURSIVE_NEGATIVE_MATCH:
            str = get_restriction_string(rule->restriction);
            PRINT_RULE_MATCH("%s: '%s%s %s' (%s:%d: '%s%s%s')", ' ', get_rule_type_long_string(rule->type), get_rule_type_char(rule->type), rule->rx, str, rule->config_filename, rule->config_linenumber, rule->config_line, rule->prefix?"', prefix: '":"", rule->prefix?rule->prefix:"")
            free(str);
            break;
        case RESULT_NEGATIVE_PARENT_MATCH:
            str = get_restriction_string(rule->restriction);
            PRINT_RULE_MATCH("parent directory '%.*s' matches %s: '%s%s %s' (%s:%d: '%s%s%s')", ' ', match.length, file.name, get_rule_type_long_string(rule->type), get_rule_type_char(rule->type), rule->rx, str, rule->config_filename, rule->config_linenumber, rule->config_line, rule->prefix?"', prefix: '":"", rule->prefix?rule->prefix:"")
            free(str);
            break;
        case RESULT_PARTIAL_MATCH:
        case RESULT_NO_RULE_MATCH:
            PRINT_RULE_MATCH("%s", ' ', "no matching rule")
            break;
        case RESULT_PARTIAL_LIMIT_MATCH:
            PRINT_RULE_MATCH("parital limit match (limit '%s')", ' ', conf->limit);
            break;
        case RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH:
            if (rule) {
                str = get_restriction_string(rule->restriction);
                PRINT_RULE_MATCH("partial limit match (limit '%s') but %s: '%s%s %s' (%s:%d: '%s%s%s')", ' ', conf->limit, get_rule_type_long_string(rule->type), get_rule_type_char(rule->type), rule->rx, str, rule->config_filename, rule->config_linenumber, rule->config_line, rule->prefix?"', prefix: '":"", rule->prefix?rule->prefix:"")
                free(str);
            } else {
                PRINT_RULE_MATCH("partial limit match (limit '%s') but no matching rule", ' ', conf->limit)
            }
            break;
        case RESULT_NO_LIMIT_MATCH:
            PRINT_RULE_MATCH("outside of limit '%s'", ' ', conf->limit);
            break;
    }
}

/*
 * add_file_to_tree
 */
void add_file_to_tree(seltree* tree,db_line* file,int db_flags, const database *db, disk_entry *entry, const char *whoami)
{
  LOG_WHOAMI(LOG_LEVEL_TRACE, "add_file_to_tree: '%s'", file->filename);
  seltree* node=NULL;

  node = get_or_create_seltree_node(tree,file->filename);

  pthread_rwlock_rdlock(&node->rwlock);
  int node_flags = node->checked&db_flags;
  pthread_rwlock_unlock(&node->rwlock);
  if (db && node_flags) {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "duplicate database entry found for '%s' (skip line)", file->filename)
      free_db_line(file);
      free(file);
  } else {
    pthread_rwlock_wrlock(&node->rwlock);

  /* add note to this node which db has modified it */
  node->checked|=db_flags;

  LOG_LEVEL add_entry_log_level = LOG_LEVEL_DEBUG;

  switch (db_flags) {
  case DB_OLD: {
    update_progress_status(PROGRESS_OLDDB, file->filename);
    LOG_WHOAMI(add_entry_log_level, "add old database entry '%s' (%c) to node '%s' (%p) as old data", file->filename, get_f_type_char_from_perm(file->perm), node->path, (void*) node);
    node->old_data=file;
    break;
  }
  case DB_NEW|DB_DISK: {
    update_progress_status(PROGRESS_DISK, file->filename);
    LOG_WHOAMI(add_entry_log_level, "add disk entry '%s' (%c) to node '%s' (%p) as new data", file->filename, get_f_type_char_from_perm(file->perm), node->path, (void*) node);
    node->new_data=file;
    break;
  }
  case DB_NEW: {
    update_progress_status(PROGRESS_NEWDB, file->filename);
    LOG_WHOAMI(add_entry_log_level, "add new database entry '%s' (%c) to node '%s' (%p) as new data", file->filename, get_f_type_char_from_perm(file->perm), node->path, (void*) node);
    node->new_data=file;
    break;
  }
  case DB_OLD|DB_NEW: {
    update_progress_status(PROGRESS_SKIPPED, NULL);
    node->new_data=file;
    node->checked|=NODE_FREE;
    LOG_WHOAMI(LOG_LEVEL_LIMIT, "add old database entry '%s' (%c) to node (%p) as new data (entry does not match limit but keep it for database_out)", file->filename, get_f_type_char_from_perm(file->perm), (void*) node);
    pthread_rwlock_unlock(&node->rwlock);
    return;
  }
  }
  pthread_rwlock_unlock(&node->rwlock);

    if (conf->action&(DO_COMPARE|DO_DIFF)) {
      if (!(db_flags&DB_OLD)) {
        pthread_rwlock_rdlock(&node->rwlock);
        LOG_WHOAMI(compare_log_level, "┬ handle '%s' from %s", node->path, db_flags==DB_OLD ? "old database": (db_flags==DB_NEW ? "new database": "disk"));
        pthread_rwlock_unlock(&node->rwlock);
      }

    pthread_rwlock_wrlock(&node->rwlock);
        if((node->checked&DB_OLD)&&(node->checked&DB_NEW)){
    LOG_WHOAMI(compare_log_level, "┝ compare attributes of '%s'", node->path);
    get_different_attributes(node->old_data,node->new_data, 0, whoami);
    node->changed_attrs=get_changed_attributes(node->old_data,node->new_data, 0, entry, true, whoami);
    /* Free the data if same else leave as is for report_tree */
    if(node->changed_attrs==RETOK && !((node->old_data)->attr^(node->new_data)->attr)) {
      LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ free old data (node '%s' is unchanged)", node->path);
      node->changed_attrs=0;

      free_db_line(node->old_data);
      free(node->old_data);
      node->old_data=NULL;

      /* Free new data if not needed for write_tree */
      if(conf->action&DO_INIT) {
          LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ keep new data (node '%s' is unchanged, but keep it for database_out)", node->path);
          node->checked|=NODE_FREE;
      } else {
          LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ free new data (node '%s' is unchanged)", node->path);
          free_db_line(node->new_data);
          free(node->new_data);
          node->new_data=NULL;
      }
      LOG_WHOAMI(compare_log_level, "┴ finished '%s'", node->path);
      pthread_rwlock_unlock(&node->rwlock);
      return;
    }
  } else if(node->checked&DB_NEW) {
      LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ '%s' is new (no old data exists)", node->path);
  }
  pthread_rwlock_unlock(&node->rwlock);

  DB_ATTR_TYPE default_move_ignored_attr = ATTR(attr_allownewfile)|ATTR(attr_allowrmfile)|ATTR(attr_checkinode)|ATTR(attr_compressed)|ATTR(attr_growing);
  if (db_flags&DB_NEW) {
      pthread_rwlock_rdlock(&node->rwlock);
      db_line *new_file = node->new_data;
      pthread_rwlock_unlock(&node->rwlock);
      if (new_file->attr&ATTR(attr_compressed)) {
          DB_ATTR_TYPE available_hashsums = get_hashes(false);
          if (new_file->attr&available_hashsums) {
              if (conf->action&DO_COMPARE) {
                  LOG_WHOAMI(compare_log_level, "┝ '%s' has compressed attribute set, calculate uncompressed hashsums", new_file->filename);

                  seltree *moved_node = NULL;

                  md_hashsums hs = calc_hashsums(entry, new_file->attr, -1, true, 0, whoami);
                  if (hs.attrs) {
                      byte* new_hashsums[num_hashes];
                      copy_hashsums(new_file->fullpath, &hs, &new_hashsums, whoami);
                      LOG_WHOAMI(compare_log_level, "│ search for original file with uncompressed hashsums of new:'%s'", new_file->filename);

                      pthread_rwlock_rdlock(&(node->parent)->rwlock);
                      for(tree_node *x = tree_walk_first((node->parent)->children); x != NULL ; x = tree_walk_next(x)) {
                          moved_node = tree_get_data(x);
                          if (moved_node != node) {
                              pthread_rwlock_rdlock(&moved_node->rwlock);
                              if (moved_node->old_data) {
                                  if ((new_file->attr&(moved_node->old_data)->attr)&available_hashsums) {
                                      LOG_WHOAMI(LOG_LEVEL_TRACE, "│ compare hashsums of old:'%s' with uncompressed hashsums of new:'%s'", (moved_node->old_data)->filename, new_file->filename);
                                      DB_ATTR_TYPE uncompressed_changed = get_changed_hashsums((moved_node->old_data)->hashsums, new_hashsums, (moved_node->old_data), new_file, whoami);
                                      if (uncompressed_changed) {
                                          char *str = diff_attributes(0,uncompressed_changed);
                                          LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ hashsums of old:'%s' and uncompressed hashsums of new:'%s' have been CHANGED: %s)", (moved_node->old_data)->filename, new_file->filename, str);
                                          free(str);
                                      } else {
                                          LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ hashsums of old:'%s' and uncompressed hashsums of new:'%s' have NOT been changed)", (moved_node->old_data)->filename, new_file->filename);
                                          pthread_rwlock_unlock(&moved_node->rwlock);
                                          break;
                                      }
                                  } else {
                                      char *old_hashsums_str = diff_attributes(0,(moved_node->old_data)->attr&available_hashsums);
                                      char *new_hashsums_str = diff_attributes(0,new_file->attr&available_hashsums);
                                      LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ skip old:'%s' (no common hashsums with new:'%s', old hashsum(s): %s, new hashsum(s): %s)", (moved_node->old_data)->filename, new_file->filename, old_hashsums_str, new_hashsums_str);
                                      free(old_hashsums_str);
                                      free(new_hashsums_str);
                                  }
                              }
                              pthread_rwlock_unlock(&moved_node->rwlock);
                          }
                          moved_node = NULL;
                      }
                      pthread_rwlock_unlock(&(node->parent)->rwlock);

                      for (int i = 0 ; i < num_hashes ; ++i) {
                          free(new_hashsums[i]);
                      }
                      if (moved_node) {
                          pthread_rwlock_wrlock(&moved_node->rwlock);
                          pthread_rwlock_wrlock(&node->rwlock);
                          if (!(moved_node->checked&NODE_MOVED_OUT)) {
                          LOG_WHOAMI(compare_log_level, "│ found old:'%s' with same common hashsum(s) as uncompressed file new:'%s'", (moved_node->old_data)->filename, new_file->filename);
                          LOG_WHOAMI(compare_log_level, "│ compare attributes of original file old:'%s' and compressed file new:'%s'", (moved_node->old_data)->filename, new_file->filename);

                          DB_ATTR_TYPE compressed_ignored_attr = default_move_ignored_attr | get_hashsums_to_ignore((moved_node->old_data)->filename, (moved_node->old_data)->attr, new_file->filename, new_file->attr);
                          if (get_different_attributes(moved_node->old_data, new_file, compressed_ignored_attr, whoami)) {
                              LOG_WHOAMI(compare_log_level, "│ ignore old:'%s' as original file of compressed file new:'%s' (due to different attributes)", (moved_node->old_data)->filename, new_file->filename);
                          } else if (get_changed_attributes((moved_node->old_data), new_file, ATTR(attr_ctime)|ATTR(attr_size)|ATTR(attr_bcount)|ATTR(attr_inode), entry, false, whoami) == RETOK) {
                              node->checked |= NODE_MOVED_IN;
                              moved_node->checked |= NODE_MOVED_OUT;
                              LOG_WHOAMI(compare_log_level,_("│ accept old:'%s' as original file of compressed file new:'%s'"), (moved_node->old_data)->filename, new_file->filename);
                              LOG_WHOAMI(compare_log_level, "┴ finished '%s'", node->path);
                              pthread_rwlock_unlock(&node->rwlock);
                              pthread_rwlock_unlock(&moved_node->rwlock);
                              return;
                          } else {
                              LOG_WHOAMI(compare_log_level,"│ ignore '%s' as original file of compressed file '%s' (due to changed attributes)", (moved_node->old_data)->filename, new_file->filename);
                          }
                          } else {
                              LOG_WHOAMI(compare_log_level, "│ '%s' has been already moved out", (moved_node->old_data)->filename);
                          }
                          pthread_rwlock_unlock(&node->rwlock);
                          pthread_rwlock_unlock(&moved_node->rwlock);
                      } else {
                          LOG_WHOAMI(compare_log_level, "│ NO original file with same hashsum(s) found for compressed file new:'%s'", new_file->filename);
                      }
                  } else {
                      LOG_WHOAMI(compare_log_level, "│ calculation of uncompressed hashsums for comprressed file new:'%s' FAILED", new_file->filename);
                  }
              } else {
                  LOG_WHOAMI(compare_log_level, "┝ new:'%s' has compressed attribute set, but skip hashsum calculation (NOT supported in dataase compare mode)", new_file->filename);
              }
          } else {
              LOG_WHOAMI(compare_log_level, "┝ new:'%s' has compressed attribute set, but skip hashsum calculation (file has no hashsums set)", new_file->filename);
          }
      }
  }

  if (node->parent != NULL) { /* root (/) has no parent */
      if (db_flags&DB_OLD) {
          pthread_rwlock_wrlock(&(node->parent)->rwlock);
          if(file->attr & ATTR(attr_checkinode)) {
              LOG_WHOAMI(compare_log_level, "'%s' (inode: %li) has check inode attribute set, set NODE_CHECK_INODE_CHILD for parent '%s'", file->filename, file->inode, (node->parent)->path);
              (node->parent)->checked |= NODE_CHECK_INODE;
          }
          pthread_rwlock_unlock(&(node->parent)->rwlock);
      } else {
            pthread_rwlock_rdlock(&node->rwlock);
            db_line *new_file = node->new_data;
            pthread_rwlock_unlock(&node->rwlock);

            pthread_rwlock_rdlock(&(node->parent)->rwlock);
          if( (node->parent)->checked&NODE_CHECK_INODE && new_file != NULL ) {
              LOG_WHOAMI(compare_log_level, "┝ parent directory (%s) of '%s' (inode: %li) has entries with check inode attribute set, search for source file with same inode", (node->parent)->path, new_file->filename, new_file->inode);
              seltree* moved_node = NULL;
              for(tree_node *x = tree_walk_first((node->parent)->children); x != NULL ; x = tree_walk_next(x)) {
                  moved_node = tree_get_data(x);
                  if (moved_node != node) {
                      pthread_rwlock_rdlock(&moved_node->rwlock);
                      if (moved_node->old_data != NULL && (moved_node->old_data)->attr & ATTR(attr_checkinode)) {
                          if ((moved_node->old_data)->inode == new_file->inode) {
                              pthread_rwlock_unlock(&moved_node->rwlock);
                              break;
                          } else {
                              LOG_WHOAMI(LOG_LEVEL_DEBUG, "│ '%s' has check inode attribute set but different inode", (moved_node->old_data)->filename);
                          }
                      }
                      pthread_rwlock_unlock(&moved_node->rwlock);
                  }
                  moved_node = NULL;
              }
             if(moved_node != NULL) {
                 pthread_rwlock_wrlock(&moved_node->rwlock);
                 pthread_rwlock_wrlock(&node->rwlock);
                  db_line *newData = new_file;
                  db_line *oldData = moved_node->old_data;
                if (!(moved_node->checked&NODE_MOVED_OUT)) {
                  LOG_WHOAMI(compare_log_level, "│ found old:'%s' with check inode attribute set and same inode as file new:'%s'", oldData->filename, newData->filename);
                  LOG_WHOAMI(compare_log_level, "│ compare attributes of source file old:'%s' and target file new:'%s'", oldData->filename, newData->filename);
                  DB_ATTR_TYPE move_ignored_attr = default_move_ignored_attr | get_hashsums_to_ignore(oldData->filename, oldData->attr, newData->filename, newData->attr);
                  if (get_different_attributes(oldData, newData, move_ignored_attr, whoami)) {
                      LOG_WHOAMI(compare_log_level, "│ ignore old:'%s' as source file of target file new:'%s' (due to different attributes)", oldData->filename, newData->filename);
                  } else if (get_changed_attributes(oldData, newData, ATTR(attr_ctime), entry, true, whoami) == RETOK) {
                      node->checked |= NODE_MOVED_IN;
                      moved_node->checked |= NODE_MOVED_OUT;
                      LOG_WHOAMI(compare_log_level, "│ accept old:'%s' as source file of target file new:'%s'", oldData->filename, newData->filename);
                      LOG_WHOAMI(compare_log_level, "┴ finished '%s'", node->path);
                      pthread_rwlock_unlock(&node->rwlock);
                      pthread_rwlock_unlock(&moved_node->rwlock);
                      pthread_rwlock_unlock(&(node->parent)->rwlock);
                      return;
                  } else {
                      LOG_WHOAMI(compare_log_level, "│ ignore old:'%s' as source file of target file new:'%s' (due to changed attributes)", oldData->filename, newData->filename);
                  }
                } else {
                      LOG_WHOAMI(compare_log_level, "│ '%s' has been already moved out", oldData->filename);
                }
                pthread_rwlock_unlock(&node->rwlock);
                pthread_rwlock_unlock(&moved_node->rwlock);
              } else {
                  LOG_WHOAMI(compare_log_level, "│ no source file found for target file '%s'", new_file->filename);
              }
          }
          pthread_rwlock_unlock(&(node->parent)->rwlock);
      }
  }

  pthread_rwlock_wrlock(&node->rwlock);
  if( (db_flags&DB_NEW) &&
      (node->new_data!=NULL) &&
      (file->attr & ATTR(attr_allownewfile)) ){
	 node->checked|=NODE_ALLOW_NEW;
     LOG_WHOAMI(compare_log_level,_("│ '%s' has ANF attribute set, ignore addition of entry in the report"), file->filename);
  }
  if( (db_flags&DB_OLD) &&
      (node->old_data!=NULL) &&
      (file->attr & ATTR(attr_allowrmfile)) ){
	  node->checked|=NODE_ALLOW_RM;
      LOG_WHOAMI(compare_log_level,_("'%s' has ARF attribute set, ignore removal of entry in the report"), file->filename);
  }
      if (!(db_flags&DB_OLD)) {
          LOG_WHOAMI(compare_log_level,"┴ finished '%s'", node->path);
      }
      pthread_rwlock_unlock(&node->rwlock);
    }
  }
}

match_result check_limit(char* filename, bool log_partial_match, const char *whoami) {
    if(conf->limit!=NULL) {
        int match=pcre2_match(conf->limit_crx, (PCRE2_SPTR) filename, PCRE2_ZERO_TERMINATED, 0, PCRE2_PARTIAL_SOFT, conf->limit_md, NULL);
        if (match >= 0) {
            LOG_WHOAMI(LOG_LEVEL_TRACE, "'%s' does match limit '%s'", filename, conf->limit);
            return 0;
        } else if (match == PCRE2_ERROR_PARTIAL) {
            if (log_partial_match) {
                LOG_WHOAMI(LOG_LEVEL_LIMIT, "skip '%s' (reason: partial limit match, limit: '%s')", filename, conf->limit);
            }
            return RESULT_PARTIAL_LIMIT_MATCH;
        } else {
            LOG_WHOAMI(LOG_LEVEL_LIMIT, "skip '%s' (reason: no limit match, limit '%s')", filename, conf->limit);
            return RESULT_NO_LIMIT_MATCH;
        }
    }
    return 0;
}

match_t check_rxtree(file_t file, seltree* tree, char* source, bool check_parent_dirs, const char *whoami) {
  match_result limit_result = check_limit(file.name, !(file.type&FT_DIR), whoami);
  match_t match;
  if (limit_result) {
      if (limit_result == RESULT_PARTIAL_LIMIT_MATCH && file.type&FT_DIR) {
        LOG_WHOAMI(LOG_LEVEL_RULE, "\u252c partial limit match (limit: '%s') for directory '%s', check for no-recurse match", conf->limit, file.name);
        match = check_seltree(tree, file, check_parent_dirs, whoami);
        if (match.result == RESULT_NON_RECURSIVE_NEGATIVE_MATCH || match.result == RESULT_NO_RULE_MATCH) {
            match.result = RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH;
            LOG_WHOAMI(LOG_LEVEL_RULE, "\u2534 no-recurse match for '%s', stop directory processing", file.name);
            LOG_WHOAMI(LOG_LEVEL_TRACE, "check_rxtree: match result %s (%d) for '%s'", get_match_result_string(match.result), match.result, file.name);
            return match;
        } else {
            LOG_WHOAMI(LOG_LEVEL_RULE, "\u2534 no no-recurse match for '%s'", file.name);
        }
      }
      match = (match_t) { limit_result, NULL, 0 };
      LOG_WHOAMI(LOG_LEVEL_TRACE, "check_rxtree: match result %s (%d) for '%s'", get_match_result_string(match.result), match.result, file.name);
      return match;
  }

#ifdef HAVE_FSTYPE
  char * fs_type_str = get_fs_type_string_from_magic(file.fs_type);
  LOG_WHOAMI(LOG_LEVEL_RULE, "\u252c process '%s' from %s (filetype: %c, file system type: %s)", file.name, source, get_f_type_char_from_f_type(file.type), fs_type_str);
  free(fs_type_str);
#else
  LOG_WHOAMI(LOG_LEVEL_RULE, "\u252c process '%s' from %s (filetype: %c)", file.name, source, get_f_type_char_from_f_type(file.type));
#endif
  match = check_seltree(tree, file, check_parent_dirs, whoami);
  if (match.result == RESULT_SELECTIVE_MATCH || match.result == RESULT_EQUAL_MATCH) {
      char *str;
      LOG_WHOAMI(LOG_LEVEL_RULE, "\u2534 ADD '%s' (attr: '%s')", file.name, str = diff_attributes(0, match.rule->attr));
      free(str);
  } else {
      LOG_WHOAMI(LOG_LEVEL_RULE, "\u2534 do NOT add '%s'", file.name);
  }
  LOG_WHOAMI(LOG_LEVEL_TRACE, "check_rxtree: match result %s (%d) for '%s'", get_match_result_string(match.result), match.result, file.name);
  return match;
}

db_line* get_file_attrs(disk_entry *file, DB_ATTR_TYPE attrs, DB_ATTR_TYPE extra_hashsums, int worker_index, const char *whoami) {
  LOG_WHOAMI(LOG_LEVEL_DEBUG, "get file attributes '%s' (fullpath: '%s')", &file->filename[conf->root_prefix_length], file->filename);
  db_line* line=NULL;
  time_t cur_time;

  if(!(attrs&ATTR(attr_rdev))) {
    (file->fs).st_rdev=0;
  }
  /*
    Get current time for future time notification.
   */
  cur_time=time(NULL);
  
  if (cur_time==(time_t)-1) {
    log_msg(LOG_LEVEL_WARNING, "can't get current time: %s", strerror(errno));
  } else {
    
    if(file->fs.st_atime>cur_time){
      log_msg(LOG_LEVEL_NOTICE,_("%s atime in future"),file->filename);
    }
    if(file->fs.st_mtime>cur_time){
      log_msg(LOG_LEVEL_NOTICE,_("%s mtime in future"),file->filename);
    }
    if(file->fs.st_ctime>cur_time){
      log_msg(LOG_LEVEL_NOTICE,_("%s ctime in future"),file->filename);
    }
  }

  line = checked_calloc(1, sizeof(db_line));

  /*
    We want filename
  */

  line->attr=attrs|ATTR(attr_filename);

  /*
    Just copy some needed fields.
  */
  
  line->fullpath = checked_strdup(file->filename);
  line->filename=&line->fullpath[conf->root_prefix_length];
  line->perm_o=file->fs.st_mode;
  line->linkname=NULL;

#ifdef HAVE_FSTYPE
  if(ATTR(attr_fs_type)&line->attr) {
      line->fs_type = file->fs_type;
  } else {
      line->fs_type = 0;
  }
#endif

  /*
    Handle symbolic link
  */
  
  hsymlnk(line);
  
  /*
    Set normal part
  */
  
  fs2db_line(&file->fs, line);
  
  /*
    ACL stuff
  */

#ifdef WITH_ACL
  acl2line(line, file->fd, whoami);
#endif

#ifdef WITH_XATTR
  xattrs2line(line, file->fd, whoami);
#endif

#ifdef WITH_SELINUX
  selinux2line(line, file->fd, whoami);
#endif

#ifdef WITH_E2FSATTRS
    e2fsattrs2line(line, file->fd, whoami);
#endif

#ifdef WITH_CAPABILITIES
    capabilities2line(line, file->fd, whoami);
#endif

  DB_ATTR_TYPE all_hashsums = get_hashes(true);
  if (line->attr&all_hashsums) {
    md_hashsums hs = calc_hashsums(file, line->attr|extra_hashsums, -1, false, worker_index, whoami);
    if (hs.attrs) {
        hashsums2line(&hs,line, whoami);
    } else {
        line->attr&=~all_hashsums;
    }
  }

  return line;
}

void write_tree(seltree* node) {
    pthread_rwlock_rdlock(&node->rwlock);
    if (node->checked&DB_NEW) {
        update_progress_status(PROGRESS_WRITEDB, (node->new_data)->filename);
        db_writeline(node->new_data,conf);
        if (node->checked&NODE_FREE) {
            free_db_line(node->new_data);
            free(node->new_data);
            node->new_data=NULL;
        }
    }
    for(tree_node *n = tree_walk_first(node->children); n != NULL ; n = tree_walk_next(n)) {
        write_tree(tree_get_data(n));
    }
    pthread_rwlock_unlock(&node->rwlock);
}

void populate_tree(seltree* tree) {
    db_entry_t entry;
    if((conf->action&DO_COMPARE)||(conf->action&DO_DIFF)){
        update_progress_status(PROGRESS_OLDDB, NULL);
        log_msg(LOG_LEVEL_INFO, "read old entries from database: %s", (conf->database_in.url)->raw);
            while((entry = db_readline(&(conf->database_in), conf->action&DO_INIT)).line != NULL) {
                if (entry.limit) {
                    add_file_to_tree(tree,entry.line,DB_OLD|DB_NEW, &(conf->database_in), NULL, NULL);
                } else {
                    add_file_to_tree(tree,entry.line,DB_OLD, &(conf->database_in), NULL, NULL);
                }
            }
    }
    if(conf->action&DO_DIFF){
        update_progress_status(PROGRESS_NEWDB, NULL);
        log_msg(LOG_LEVEL_INFO, "read new entries from database: %s", (conf->database_new.url)->raw);
      while((entry = db_readline(&(conf->database_new), false)).line != NULL){
          add_file_to_tree(tree,entry.line,DB_NEW, &(conf->database_new), NULL, NULL);
      }
    }

    if((conf->action&DO_INIT)||(conf->action&DO_COMPARE)){
      update_progress_status(PROGRESS_DISK, NULL);
      log_msg(LOG_LEVEL_INFO, "read new entries from disk (limit: '%s', root prefix: '%s')", conf->limit?conf->limit:"(none)", conf->root_prefix);

      db_scan_disk(false);
    }
}

void hsymlnk(db_line* line) {
  
  line->linkname = NULL;
  if (line->attr&ATTR(attr_linkname)) {
  if((S_ISLNK(line->perm_o))){
    int len=0;
#ifdef WITH_ACL   
    if(conf->no_acl_on_symlinks!=1) {
      line->attr&=(~ATTR(attr_acl));
    }
#endif   
    
    if(conf->warn_dead_symlinks==1) {
      struct stat fs;
      int sres;
      sres=stat(line->fullpath,&fs);
      if (sres!=0 && sres!=EACCES) {
	log_msg(LOG_LEVEL_WARNING,"Dead symlink detected at %s",line->fullpath);
      }
      if(!(line->attr&ATTR(attr_rdev))) {
	fs.st_rdev=0;
      }
    }
    /*
      Is this valid?? 
      No, We should do this elsewhere.
    */
    line->linkname=(char*)checked_malloc(_POSIX_PATH_MAX+1);
    
    /*
      Remember to nullify the buffer, because man page says
      
      readlink  places the contents of the symbolic link path in
      the buffer buf, which has size bufsiz.  readlink does  not
      append  a NUL character to buf.  It will truncate the con-
      tents (to a length of  bufsiz  characters),  in  case  the
      buffer is too small to hold all of the contents.
      
    */
    memset(line->linkname,0,_POSIX_PATH_MAX+1);
    
    len=readlink(line->fullpath,line->linkname,_POSIX_PATH_MAX+1);
    if (len < 0) {
        log_msg(LOG_LEVEL_WARNING, "readlink() failed for '%s': %s", line->fullpath, strerror(errno));
        line->attr&=(~ATTR(attr_linkname));
        free(line->linkname);
        line->linkname = NULL;
    } else {
        line->linkname=checked_realloc(line->linkname,len+1);
    }
  } else {
      line->attr&=(~ATTR(attr_linkname));
  }
  }
  
}
// vi: ts=8 sw=2
