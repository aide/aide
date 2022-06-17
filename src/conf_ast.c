/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2019-2022 Hannes von Haugwitz
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
#include <stdbool.h>

#include "conf_ast.h"
#include "conf_lex.h"
#include "log.h"
#include "rx_rule.h"
#include "util.h"

LOG_LEVEL ast_log_level = LOG_LEVEL_DEBUG;

config_option_t config_options[] = {
    { ACL_NO_SYMLINK_FOLLOW_OPTION,             "acl_no_symlink_follow",        NULL },
    { DATABASE_ADD_METADATA_OPTION,             NULL,                           NULL },
    { DATABASE_ATTRIBUTES_OPTION,               NULL,                           NULL },
    { DATABASE_GZIP_OPTION,                     NULL,                           NULL },
    { DATABASE_IN_OPTION,                       NULL,                           NULL },
    { DATABASE_OUT_OPTION,                      NULL,                           NULL },
    { DATABASE_NEW_OPTION,                      NULL,                           NULL },
    { LOG_LEVEL_OPTION,                         NULL,                           NULL },
    { REPORT_BASE16_OPTION,                     NULL,                           NULL },
    { REPORT_DETAILED_INIT_OPTION,              NULL,                           NULL },
    { REPORT_FORCE_ATTRS_OPTION,                "report_force_attrs",           "Forced attributes" },
    { REPORT_GROUPED_OPTION,                    NULL,                           NULL },
    { REPORT_IGNORE_ADDED_ATTRS_OPTION,         "report_ignore_added_attrs",    "Ignored added attributes" },
    { REPORT_IGNORE_REMOVED_ATTRS_OPTION,       "report_ignore_removed_attrs",  "Ignored removed attributes" },
    { REPORT_IGNORE_CHANGED_ATTRS_OPTION,       "report_ignore_changed_attrs",  "Ignored changed attributes" },
    { REPORT_IGNORE_E2FSATTRS_OPTION,           "report_ignore_e2fsattrs",      "Ignored e2fs attributes" },
    { REPORT_LEVEL_OPTION,                      "report_level",                 "Report level" },
    { REPORT_QUIET_OPTION,                      NULL,                           NULL },
    { REPORT_APPEND_OPTION,                     NULL,                           NULL },
    { REPORT_SUMMARIZE_CHANGES_OPTION,          NULL,                           NULL },
    { REPORT_URL_OPTION,                        NULL,                           NULL },
    { ROOT_PREFIX_OPTION,                       "root_prefix",                  "Root prefix" },
    { WARN_DEAD_SYMLINKS_OPTION,                NULL,                           NULL },
    { VERBOSE_OPTION,                           NULL,                           NULL },
    { CONFIG_VERSION,                           "config_version",               "Config version used" },
    { CONFIG_CHECK_WARN_UNRESTRICTED_RULES,     NULL,                           NULL },
    { REPORT_FORMAT_OPTION,                     NULL,                           NULL },
    { LIMIT_CMDLINE_OPTION,                     "limit",                        "Limit" },
};

static ast* new_ast_node() {
    ast* a = checked_malloc(sizeof(ast));

    a->linenumber = conf_linenumber;
    a->filename = conf_filename;
    a->linebuf = conf_linebuf;
    a->next = NULL;

    return a;
}

ast* new_string_option_statement(config_option option, string_expression* value) {
      ast* a = new_ast_node();

      a->type = config_option_type;
      a->statement._config.option = option;
      a->statement._config.a = NULL;
      a->statement._config.e = value;
      log_msg(ast_log_level, "ast: new string option statement (%p): option: %d, value: %p", a, option, value);
      return a;
}

ast* new_attribute_option_statement(config_option option, attribute_expression* value) {
      ast* a = new_ast_node();

      a->type = config_option_type;
      a->statement._config.option = option;
      a->statement._config.a = value;
      a->statement._config.e = NULL;
      log_msg(ast_log_level, "ast: new attribute option statement (%p): option: %d, value: %p", a, option, value);
      return a;
}

ast* new_include_statement(string_expression* path, string_expression* rx, bool execute, string_expression* prefix) {
      ast* a = new_ast_node();

      a->type = include_statement_type;
      a->statement._include.path = path;
      a->statement._include.rx = rx;
      a->statement._include.execute = execute;
      a->statement._include.prefix = prefix;

      log_msg(ast_log_level, "ast: new include statement (%p): path: %p, rx: %p, execute: %s, prefix: %p", a, path, rx, btoa(execute), prefix);
      return a;
}

ast* new_x_include_setenv_statement(char *variable, string_expression *value) {
      ast* a = new_ast_node();

      a->type = x_include_setenv_statement_type;
      a->statement._x_include_setenv.variable = variable;
      a->statement._x_include_setenv.value = value;
      log_msg(ast_log_level, "ast: new x_include_setenv statement (%p): variable: '%s', value: %p", a, variable, value);
      return a;
}

ast* new_define_statement(char *name, string_expression *value) {
      ast* a = new_ast_node();

      a->type = define_statement_type;
      a->statement._define.name = name;
      a->statement._define.value = value;
      log_msg(ast_log_level, "ast: new define statement (%p): name: '%s', value: %p", a, name, value);
      return a;
}

ast* new_undefine_statement(char *name) {
      ast* a = new_ast_node();

      a->type = undefine_statement_type;
      a->statement._undefine.name = name;
      log_msg(ast_log_level, "ast: new undefine statement (%p): name: '%s'", a, name);
      return a;
}

ast* new_group_statement(char* name, attribute_expression* expr) {
      ast* a = new_ast_node();

      a->type = group_statement_type;
      a->statement._group.name = name;
      a->statement._group.expr = expr;
      log_msg(ast_log_level, "ast: new group statement (%p): name: '%s', expr: %p", a, name, expr);
      return a;
}

bool_expression* new_string_bool_expression(bool_operator op, string_expression* expr) {
    bool_expression* e = checked_malloc(sizeof(bool_expression));
    e->op = op;
    e->expr = expr;
    e->left = NULL;
    e->right = NULL;
    log_msg(ast_log_level, "ast: new bool expression (%p): op: %d, expr: %p", e, op, expr);
    return e;
}

bool_expression* new_bool_expression(bool_operator op, bool_expression* left, bool_expression* right) {
    bool_expression* e = checked_malloc(sizeof(bool_expression));
    e->op = op;
    e->expr = NULL;
    e->left = left;
    e->right = right;
    log_msg(ast_log_level, "ast: new bool expression (%p): op: %d, left: %p, right: %p", e, op, left, right);
    return e;
}

if_condition* new_if_condition(bool_expression* expression) {
    if_condition* c = checked_malloc(sizeof(if_condition));

    c->linenumber = conf_linenumber;
    c->filename = conf_filename;
    c->linebuf = conf_linebuf;

    c->expression = expression;

    log_msg(ast_log_level, "ast: if condition (%p): expression: %p", c,  expression);
    return c;
}

attribute_expression* new_attribute_expression(attribute_operator op, attribute_expression* left, char* right) {
    attribute_expression* e = checked_malloc(sizeof(attribute_expression));
    e->op = op;
    e->left = left;
    e->right = right;
    log_msg(ast_log_level, "ast: new attribute expression (%p): op: %d, left: %p, right: '%s'", e, op, left, right);
    return e;
}

restriction_expression* new_restriction_expression(restriction_expression* left, char* right) {
    restriction_expression* e = checked_malloc(sizeof(restriction_expression));
    e->right = right;
    e->left = left;
    log_msg(ast_log_level, "ast: new restriction expression (%p): left: %p, right: '%s'", e, left, right);
    return e;
}

ast* new_if_statement(struct if_condition* condition, struct ast* if_branch, struct ast* else_branch) {
      ast* e = new_ast_node();

      e->type = if_statement_type;
      e->statement._if.condition = condition;
      e->statement._if.if_branch = if_branch;
      e->statement._if.else_branch = else_branch;
      log_msg(ast_log_level, "ast: new if statement (%p): condition: %p, if_branch: %p, else_branch: %p", e, condition, if_branch, else_branch);
      return e;
}

ast* new_rule_statement(AIDE_RULE_TYPE rule_type, string_expression* path, restriction_expression* restriction, attribute_expression* attrs) {
      ast* e = new_ast_node();

      e->type = rule_statement_type;
      e->statement._rule.type = rule_type;
      e->statement._rule.path = path;
      e->statement._rule.restriction = restriction;
      e->statement._rule.attributes = attrs;
      log_msg(ast_log_level, "ast: new rule statement (%p): type: %s, path: %p, restriction: %p, attributes: %p", e, get_rule_type_long_string(rule_type), path, restriction, attrs);
      return e;
}

string_expression* new_string(char *str) {
    string_expression* e = checked_malloc(sizeof(string_expression));

    e->op = STR_OP_STR;
    e->str = str;
    e->left = NULL;
    e->right = NULL;
    log_msg(ast_log_level, "ast: new string (%p): str: '%s'", e, str);
    return e;
}
string_expression* new_variable(char *name) {
    string_expression* e = checked_malloc(sizeof(string_expression));

    e->op = STR_OP_VARIABLE;
    e->str = name;
    e->left = NULL;
    e->right = NULL;
    log_msg(ast_log_level, "ast: new variable (%p): name: '%s'", e, name);
    return e;
}
string_expression* new_string_concat(string_expression* left, string_expression* right) {
    string_expression* e = checked_malloc(sizeof(string_expression));
    e->op = STR_OP_CONCAT;
    e->str = NULL;
    e->left = left;
    e->right = right;
    log_msg(ast_log_level, "ast: new string concat (%p): left: %p, right: %p", e, left, right);
    return e;
}

void free_string(char * s) {
    if (s == NULL) {
        return;
    }
    log_msg(ast_log_level, "ast: free string %p", s);
    free(s);
}

void free_attribute_expression(attribute_expression *a) {
    if (a == NULL) {
        return;
    }
    free_attribute_expression(a->left);
    free_string(a->right);
    log_msg(ast_log_level, "ast: free attribute expression %p", a);
    free(a);
}

void free_string_expression(string_expression *s) {
    if (s == NULL) {
        return;
    }
    free_string_expression(s->left);
    free_string_expression(s->right);
    free_string(s->str);
    log_msg(ast_log_level, "ast: free string expression %p", s);
    free(s);
}

void free_bool_expression(bool_expression *b) {
    if (b == NULL) {
        return;
    }
    free_string_expression(b->expr);
    free_bool_expression(b->left);
    free_bool_expression(b->right);
    log_msg(ast_log_level, "ast: free bool expression %p", b);
    free(b);
}

void free_if_condition(if_condition *c) {
    free_bool_expression(c->expression);
    free_string(c->linebuf);
    log_msg(ast_log_level, "ast: free if condition %p", c);
    free(c);
}

void free_restriction_expression(restriction_expression *r) {
    if (r == NULL) {
        return;
    }
    free_restriction_expression(r->left);
    free_string(r->right);
    log_msg(ast_log_level, "ast: free restriction expression %p", r);
    free(r);
}

void deep_free(ast* config_ast) {
    if (config_ast == NULL) {
        return;
    }
    ast* node = NULL;
    for(node = config_ast; node != NULL; ) {
        switch (node->type) {
            case config_option_type:
                free_attribute_expression(node->statement._config.a);
                free_string_expression(node->statement._config.e);
                break;
            case define_statement_type:
                free_string_expression(node->statement._define.value);
                free_string(node->statement._define.name);
                break;
            case group_statement_type:
                free_attribute_expression(node->statement._group.expr);
                free_string(node->statement._group.name);
                break;
            case if_statement_type:
                free_if_condition(node->statement._if.condition);
                deep_free(node->statement._if.if_branch);
                deep_free(node->statement._if.else_branch);
                break;
            case include_statement_type:
                free_string_expression(node->statement._include.path);
                free_string_expression(node->statement._include.rx);
                free_string_expression(node->statement._include.prefix);
                break;
            case x_include_setenv_statement_type:
                free_string_expression(node->statement._x_include_setenv.value);
                free_string(node->statement._x_include_setenv.variable);
                break;
            case rule_statement_type:
                free_string_expression(node->statement._rule.path);
                free_restriction_expression(node->statement._rule.restriction);
                free_attribute_expression(node->statement._rule.attributes);
                break;
            case undefine_statement_type:
                free_string(node->statement._define.name);
                break;
        }
        free(node->linebuf);
        ast* to_be_freed = node;
        node = node->next;
        log_msg(ast_log_level, "ast: free ast node %p (next: %p)", to_be_freed, node);
        free(to_be_freed);
    }
}
