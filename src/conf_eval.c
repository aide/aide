/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2019-2021 Hannes von Haugwitz
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

#include "conf_eval.h"
#include "conf_yacc.h"
#include "conf_lex.h"

#include "log.h"
#include "errorcodes.h"
#include "db.h"
#include "rx_rule.h"
#include "util.h"

#include "commandconf.h"

#include "symboltable.h"

#include <stddef.h>
#include <unistd.h>

LOG_LEVEL eval_log_level = LOG_LEVEL_DEBUG;

bool log_level_set_in_config = false;

#define BOOL_CONFIG_OPTION_CASE(id, option) \
    case id: \
        b = string_expression_to_bool(statement.e, linenumber, filename, linebuf); \
        conf->option = b; \
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set '%s' to '%s', #option, btoa(conf->option)) \
        break;

#define ATTRIBUTE_CONFIG_OPTION_CASE(id, option) \
    case id: \
        attr = eval_attribute_expression(statement.a, linenumber, filename, linebuf); \
        conf->option=attr; \
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set '%s' to '%s', #option, str = diff_attributes(0, attr) ) \
        free(str); \
        break;

#define DATABASE_CONFIG_OPTION_CASE(id, dbtype) \
    case id: \
        str =  eval_string_expression(statement.e, linenumber, filename, linebuf); \
        if (!do_dbdef(dbtype, str, linenumber, filename, linebuf)) { \
            exit(INVALID_CONFIGURELINE_ERROR); \
        } \
        free(str); \
        break;

static char* eval_string_expression(struct string_expression* expression, int linenumber, char *filename, char* linebuf) {
    char *str = NULL, *right, *left;
    int length = 0;
    list *entry;
    switch (expression->op) {
        case STR_OP_STR:
            str = checked_strdup(expression->str);
            break;
        case STR_OP_VARIABLE:
            entry = NULL;
            if ((entry = list_find(expression->str, conf->defsyms))) {
                str = checked_strdup(((symba*)entry->data)->value);
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, variable substitution: replace '@@%c%s%c' with '%s', '{', expression->str, '}', str)
            } else if (strcmp(expression->str, "HOSTNAME") == 0 && conf->hostname) {
                str = checked_strdup(conf->hostname);
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, variable substitution: replace '@@%c%s%c' with '%s', '{', expression->str, '}', str)
            } else {
                str = checked_strdup("");
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, variable substitution: variable '%s' not defined (use empty string), expression->str)
            }
            break;
        case STR_OP_CONCAT:
            left = eval_string_expression(expression->left, linenumber, filename, linebuf);
            right = eval_string_expression(expression->right, linenumber, filename, linebuf);
            length = strlen(left)+strlen(right);
            str = checked_malloc(length+1);
            strncpy(str, left, length+1);
            strncat(str, right, length-strlen(left)+1);
            log_msg(eval_log_level, "eval(%p): string concat '%s' + '%s' evaluates to %s", expression, left, right, str);
            free(left);
            free(right);
            break;
    }
    return str;
}

static bool string_expression_to_bool(string_expression *e, int linenumber, char *filename, char* linebuf) {
    bool b = false;
    char *str = eval_string_expression(e, linenumber, filename, linebuf);
    if (strcmp(str, "true") == 0 || strcmp(str, "yes") == 0) {
        b = true;
    } else if (strcmp(str, "false") != 0 && strcmp(str, "no") != 0) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, unrecognized bool value: '%s' (expecting %s), str, "'true', 'yes','false' or 'no'")
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    free(str);
    return b;
}

static DB_ATTR_TYPE eval_attribute_expression(struct attribute_expression* expression, int linenumber, char *filename, char* linebuf) {
    DB_ATTR_TYPE attr = 0, attr_r;

    if (expression != NULL) {
        if (expression->left) {
            attr = eval_attribute_expression(expression->left, linenumber, filename, linebuf);
        }

        attr_r = get_groupval(expression->right);
        if(attr_r ==  DB_ATTR_UNDEF) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, group '%s' is not defined, expression->right)
                exit(INVALID_CONFIGURELINE_ERROR);
        }
        log_msg(eval_log_level, "eval(%p): attribute group '%s' evaluates to %llu", expression, expression->right, attr_r);
        switch (expression->op) {
            case ATTR_OP_GROUP:
                attr = attr_r;
                break;
            case ATTR_OP_PLUS:
                attr |= attr_r;
                break;
            case ATTR_OP_MINUS:
                attr &= (~attr_r);
                break;
        }
        log_msg(eval_log_level, "eval(%p): attribute expression (op: %d, left: %p, right: '%s') evaluates to %llu", expression, expression->op, expression->left, expression->right, attr);
    } else {
        log_msg(eval_log_level, "eval(%p): attribute expression is NULL and evaluates to %llu", expression, attr);
    }
    return attr;
}

static void set_database_attr_option(DB_ATTR_TYPE attr, int linenumber, char *filename, char* linebuf) {
        char *str;

        DB_ATTR_TYPE hashes = get_hashes(true);
        if (attr&(~hashes)) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, invalid attribute(s): %s, str = diff_attributes(0, attr&(~hashes)));
            free(str);
            exit(INVALID_CONFIGURELINE_ERROR);
        }
        DB_ATTR_TYPE unsupported_hashes = attr&(get_hashes(true)&~get_hashes(false));
        if (unsupported_hashes) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, ignoring unsupported hash algorithm(s): %s, str = diff_attributes(0, unsupported_hashes));
            free(str);
            attr &= ~unsupported_hashes;
        }
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set 'database_attrs' option to: %s, str = diff_attributes(0, attr));
        free(str);
        conf->db_attrs = attr;
}

static void eval_config_statement(config_option_statement statement, int linenumber, char *filename, char* linebuf) {
    char *str;
    bool b;
    DB_ATTR_TYPE attr;
    switch (statement.option) {
        ATTRIBUTE_CONFIG_OPTION_CASE(REPORT_IGNORE_ADDED_ATTRS_OPTION, report_ignore_added_attrs)
        ATTRIBUTE_CONFIG_OPTION_CASE(REPORT_IGNORE_REMOVED_ATTRS_OPTION, report_ignore_removed_attrs)
        ATTRIBUTE_CONFIG_OPTION_CASE(REPORT_IGNORE_CHANGED_ATTRS_OPTION, report_ignore_changed_attrs)
        ATTRIBUTE_CONFIG_OPTION_CASE(REPORT_FORCE_ATTRS_OPTION, report_force_attrs)
        case REPORT_URL_OPTION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            if (!do_repurldef(str, linenumber, filename, linebuf)) {
                exit(INVALID_CONFIGURELINE_ERROR);
            }
            free(str);
            break;
        case ROOT_PREFIX_OPTION:
            /* not to be freed, reused in do_rootprefix */
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            do_rootprefix(str, linenumber, filename, linebuf);
            break;
        DATABASE_CONFIG_OPTION_CASE(DATABASE_IN_OPTION, DB_TYPE_IN)
        DATABASE_CONFIG_OPTION_CASE(DATABASE_OUT_OPTION, DB_TYPE_OUT)
        DATABASE_CONFIG_OPTION_CASE(DATABASE_NEW_OPTION, DB_TYPE_NEW)
        case DATABASE_ATTRIBUTES_OPTION:
            set_database_attr_option(
                    eval_attribute_expression(statement.a, linenumber, filename, linebuf),
                    linenumber, filename, linebuf);
            break;
        case DATABASE_GZIP_OPTION:
#ifdef WITH_ZLIB
            b = string_expression_to_bool(statement.e, linenumber, filename, linebuf);
            conf->gzip_dbout=b;
#else
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, %s, "gzip support not compiled in, recompile AIDE with '--with-zlib'")
                exit(INVALID_CONFIGURELINE_ERROR);
#endif
            break;
        BOOL_CONFIG_OPTION_CASE(DATABASE_ADD_METADATA_OPTION, database_add_metadata)
        case ACL_NO_SYMLINK_FOLLOW_OPTION:
#ifdef WITH_ACL
            b = string_expression_to_bool(statement.e, linenumber, filename, linebuf);
            conf->no_acl_on_symlinks=b;
#else
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, %s, "acl support not compiled in, recompile AIDE with '--with-posix-acl'")
            exit(INVALID_CONFIGURELINE_ERROR);
#endif
            break;
        case REPORT_IGNORE_E2FSATTRS_OPTION:
#ifdef WITH_E2FSATTRS
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            do_report_ignore_e2fsattrs(str, linenumber, filename, linebuf);
            free(str);
#else
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, %s, "e2fsattrs support not compiled in, recompile AIDE with '--with-e2fsattrs'")
            exit(INVALID_CONFIGURELINE_ERROR);
#endif
            break;
        BOOL_CONFIG_OPTION_CASE(REPORT_BASE16_OPTION, report_base16)
        BOOL_CONFIG_OPTION_CASE(REPORT_DETAILED_INIT_OPTION, report_detailed_init)
        BOOL_CONFIG_OPTION_CASE(REPORT_GROUPED_OPTION, report_grouped)
        BOOL_CONFIG_OPTION_CASE(REPORT_QUIET_OPTION, report_quiet)
        BOOL_CONFIG_OPTION_CASE(REPORT_APPEND_OPTION, report_append)
        BOOL_CONFIG_OPTION_CASE(REPORT_SUMMARIZE_CHANGES_OPTION, report_summarize_changes)
        BOOL_CONFIG_OPTION_CASE(WARN_DEAD_SYMLINKS_OPTION, warn_dead_symlinks)
        case REPORT_LEVEL_OPTION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            if(!do_reportlevel(str, linenumber, filename, linebuf)) {
                exit(INVALID_CONFIGURELINE_ERROR);
            }
            free(str);
            break;
        case LOG_LEVEL_OPTION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            LOG_LEVEL level = get_log_level_from_string(str);
            if (level == LOG_LEVEL_UNSET) {
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, invalid log level: '%s', str);
                exit(INVALID_CONFIGURELINE_ERROR);
            } else {
                if (is_log_level_unset() || ( conf->action&DO_DRY_RUN && !log_level_set_in_config )) {
                    if (!(conf->action&DO_DRY_RUN)) {
                        set_log_level(level);
                    } else {
                        log_level_set_in_config = true;
                    }
                    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set 'log_level' option to '%s', str)
                } else {
                    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, 'log_level' option already set (ignore new value '%s'), str)
                }
            }
            free(str);
            break;
        case CONFIG_VERSION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            conf->config_version = str;
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set 'config_version' option to '%s', str)
            break;
        case VERBOSE_OPTION:
            log_msg(LOG_LEVEL_ERROR, "%s:%d: 'verbose' option is no longer supported, use 'log_level' and 'report_level' options instead (see man aide.conf for details) (line: '%s')", conf_filename, conf_linenumber, conf_linebuf);
            exit(INVALID_CONFIGURELINE_ERROR);
            break;
    }
}

static bool eval_bool_expression(struct bool_expression* expression, int linenumber, char *filename, char* linebuf) {
    bool result = false, left;
    char * str;

    switch (expression->op) {
        case BOOL_OP_DEFINED:
            str = eval_string_expression(expression->expr, linenumber, filename, linebuf);
            result = list_find(str, conf->defsyms) != NULL;
            log_msg(eval_log_level, "eval(%p): bool defined '%s': %s", expression, str, btoa(result));
            free(str);
            break;
        case BOOL_OP_HOSTNAME:
            str = eval_string_expression(expression->expr, linenumber, filename, linebuf);
            if (conf->hostname) {
                result = strcmp(str, conf->hostname) == 0;
            } else {
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, hostname not avaiable%c ifhost and ifnhost always evaluate to 'false', ',')
            }
            log_msg(eval_log_level, "eval(%p): bool hostname '%s' (hostname: '%s'): %s", expression, str, conf->hostname, btoa(result));
            free(str);
            break;
        case BOOL_OP_NOT:
            left = eval_bool_expression(expression->left, linenumber, filename, linebuf);
            result = !left;
            log_msg(eval_log_level, "eval(%p): bool !%s: %s", expression, btoa(left), btoa(result));
            break;
    }
    return result;
}

static void eval_group_statement(group_statement statement, int linenumber, char *filename, char* linebuf) {
         DB_ATTR_TYPE attr, prev_attr;
         char *str, *str2;
         attr = eval_attribute_expression(statement.expr, linenumber, filename, linebuf);
         if ((prev_attr = do_groupdef(statement.name, attr))) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, redefine group '%s' with value '%s' (previous value: '%s'), statement.name, str = diff_attributes(0, attr), str2 = diff_attributes(0, prev_attr))
            free(str2);
         } else {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, define group '%s' with value '%s', statement.name, str = diff_attributes(0, attr))
         }
         free(str);
}

static bool evaL_if_condition(if_condition* c) {
    log_msg(eval_log_level, "eval(%p): if condition", c);
    bool cond_result = eval_bool_expression(c->expression, c->linenumber, c->filename, c->linebuf);
    log_msg(LOG_LEVEL_CONFIG,"%s:%d: if condition results to '%s' (line: '%s')", c->filename, c->linenumber, btoa(cond_result), c->linebuf);
    return cond_result;
}

static void eval_if_statement(if_statement statement, int linenumber, char *filename, char* linebuf) {
    bool condition = evaL_if_condition(statement.condition);

    if (condition) {
        log_msg(eval_log_level, "eval(%p): if branch", statement.if_branch);
        if (statement.if_branch) {
            eval_config(statement.if_branch);
        }
    } else {
        log_msg(eval_log_level, "eval(%p): else branch", statement.else_branch);
        if (statement.else_branch) {
            eval_config(statement.else_branch);
        }
    }
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, %s, "endif")
}

static void eval_define_statement(define_statement statement, int linenumber, char *filename, char* linebuf) {
    do_define(statement.name,
            /* not to be freed, reused in do_define */
            statement.value?eval_string_expression(statement.value, linenumber, filename, linebuf):NULL,
            linenumber, filename, linebuf);
}

static void eval_undefine_statement(undefine_statement statement, int linenumber, char *filename, char* linebuf) {
    do_undefine(statement.name, linenumber, filename, linebuf);
}

static void eval_include_statement(include_statement statement, int linenumber, char *filename, char* linebuf) {
    char* path = eval_string_expression(statement.path, linenumber, filename, linebuf);
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, include '%s', path)
    conf_lex_file(path);
    ast* config_ast = NULL;
    if(confparse(&config_ast)){
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    conf_lex_delete_buffer();
    free(path);
    eval_config(config_ast);
    deep_free(config_ast);
}

static RESTRICTION_TYPE eval_restriction_expression(restriction_expression *expression, int linenumber, char *filename, char* linebuf) {
    RESTRICTION_TYPE rs = FT_NULL, rs_r;

    if (expression) {
        rs_r = (strlen(expression->right) == 1)?get_restriction_from_char(*(expression->right)):FT_NULL;
        log_msg(eval_log_level, "eval(%p): restriction file type '%s' evaluates to %d", expression, expression->right, rs_r);
        if (rs_r == FT_NULL) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, invalid restriction '%s', expression->right)
            exit(INVALID_CONFIGURELINE_ERROR);
        }
        if (expression->left == NULL) {
            rs = rs_r;
        } else {
            rs = eval_restriction_expression(expression->left, linenumber, filename, linebuf) | rs_r;
        }

    } else {
        log_msg(eval_log_level, "eval(%p): restriction is NULL, returning %d", expression, rs);
    }
    return rs;
}

static void eval_rule_statement(rule_statement statement, int linenumber, char *filename, char* linebuf) {
    if(!add_rx_rule_to_tree(
            /* not to be freed, reused in add_rx_rule_to_tree */
            eval_string_expression(statement.path, linenumber, filename, linebuf),
            eval_restriction_expression(statement.restriction, linenumber, filename, linebuf),
            eval_attribute_expression(statement.attributes, linenumber, filename, linebuf),
            statement.type,
            conf->tree,
            linenumber, filename, linebuf)) {
        exit(INVALID_CONFIGURELINE_ERROR);
    }
}

void eval_config(ast* config_ast) {
    ast* node = NULL;
    for(node = config_ast; node != NULL; node = node->next) {
        log_msg(eval_log_level, "eval(%p): ast node (next: %p)", node, node->next);
        switch (node->type) {
            case config_option_type:
                eval_config_statement(node->statement._config, node->linenumber, node->filename, node->linebuf);
                break;
            case include_statement_type:
                eval_include_statement(node->statement._include, node->linenumber, node->filename, node->linebuf);
                break;
            case if_statement_type:
                eval_if_statement(node->statement._if, node->linenumber, node->filename, node->linebuf);
                break;
            case define_statement_type:
                eval_define_statement(node->statement._define, node->linenumber, node->filename, node->linebuf);
                break;
            case undefine_statement_type:
                eval_undefine_statement(node->statement._undefine, node->linenumber, node->filename, node->linebuf);
                break;
            case group_statement_type:
                eval_group_statement(node->statement._group, node->linenumber, node->filename, node->linebuf);
                break;
            case rule_statement_type:
                eval_rule_statement(node->statement._rule, node->linenumber, node->filename, node->linebuf);
                break;
        }
    }
}
