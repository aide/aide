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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CONF_AST_H_INCLUDED
#define  _CONF_AST_H_INCLUDED

#include <stdbool.h>
#include "rx_rule.h"

typedef enum config_option {
    ACL_NO_SYMLINK_FOLLOW_OPTION,
    DATABASE_ADD_METADATA_OPTION,
    DATABASE_ATTRIBUTES_OPTION,
    DATABASE_GZIP_OPTION,
    DATABASE_IN_OPTION,
    DATABASE_OUT_OPTION,
    DATABASE_NEW_OPTION,
    LOG_LEVEL_OPTION,
    REPORT_BASE16_OPTION,
    REPORT_DETAILED_INIT_OPTION,
    REPORT_FORCE_ATTRS_OPTION,
    REPORT_GROUPED_OPTION,
    REPORT_IGNORE_ADDED_ATTRS_OPTION,
    REPORT_IGNORE_REMOVED_ATTRS_OPTION,
    REPORT_IGNORE_CHANGED_ATTRS_OPTION,
    REPORT_IGNORE_E2FSATTRS_OPTION,
    REPORT_LEVEL_OPTION,
    REPORT_QUIET_OPTION,
    REPORT_APPEND_OPTION,
    REPORT_SUMMARIZE_CHANGES_OPTION,
    REPORT_URL_OPTION,
    ROOT_PREFIX_OPTION,
    WARN_DEAD_SYMLINKS_OPTION,
    VERBOSE_OPTION,
    CONFIG_VERSION,
    CONFIG_CHECK_WARN_UNRESTRICTED_RULES,
    REPORT_FORMAT_OPTION,
    LIMIT_CMDLINE_OPTION,
    ROOT_PREFIX_CMDLINE_OPTION,
} config_option;

typedef struct {
    config_option option;
    char *config_name;
    char *report_string;
} config_option_t;

extern config_option_t config_options[];

typedef enum attribute_operator {
        ATTR_OP_PLUS = 0,
        ATTR_OP_MINUS,
        ATTR_OP_GROUP,
} attribute_operator;

typedef struct attribute_expression {
    attribute_operator op;

    struct attribute_expression* left;
    char* right;
} attribute_expression;

typedef enum string_operator {
        STR_OP_STR,
        STR_OP_VARIABLE,
        STR_OP_CONCAT,
} string_operator;
typedef struct string_expression {
    string_operator op;

    char* str;
    struct string_expression* left;
    struct string_expression* right;
} string_expression;

typedef struct config_option_statement {
    config_option option;
    attribute_expression *a;
    string_expression* e;
} config_option_statement;

typedef enum bool_operator {
        BOOL_OP_NOT,
        BOOL_OP_DEFINED,
        BOOL_OP_HOSTNAME,
        BOOL_OP_EXISTS,
} bool_operator;

typedef struct bool_expression {
    bool_operator op;

    string_expression* expr;
    struct bool_expression* left;
    struct bool_expression* right;
} bool_expression;

typedef struct if_condition {
    bool_expression* expression;

    int linenumber;
    char *filename;
    char* linebuf;
} if_condition;

typedef struct if_statement {
    struct if_condition* condition;

    struct ast* if_branch;
    struct ast* else_branch;
} if_statement;

typedef struct define_statement {
    char *name;
    string_expression *value;
} define_statement;

typedef struct include_statement {
    string_expression *path;
    string_expression *rx;
    bool execute;
} include_statement;

typedef struct x_include_setenv_statement {
    char *variable;
    string_expression *value;
} x_include_setenv_statement;

typedef struct undefine_statement {
    char *name;
} undefine_statement;

typedef struct group_statement {
    char *name;
    attribute_expression *expr;
} group_statement;

typedef struct restriction_expression {
    char* right;
    struct restriction_expression* left;
} restriction_expression;

typedef struct rule_statement {
    AIDE_RULE_TYPE type;

    string_expression *path;
    restriction_expression *restriction;
    attribute_expression *attributes;
} rule_statement;

typedef struct ast {
    enum {
        config_option_type,

        include_statement_type,
        x_include_setenv_statement_type,
        define_statement_type,
        undefine_statement_type,

        group_statement_type,

        if_statement_type,

        rule_statement_type,
    } type;

    union {
        config_option_statement _config;
        include_statement _include;
        x_include_setenv_statement _x_include_setenv;
        define_statement _define;
        undefine_statement _undefine;
        group_statement _group;
        if_statement _if;
        rule_statement _rule;
    } statement;

    int linenumber;
    char *filename;
    char* linebuf;

    struct ast* next;
} ast;

string_expression* new_string(char*);
string_expression* new_variable(char*);
string_expression* new_string_concat(string_expression*, string_expression*);

ast* new_string_option_statement(config_option, string_expression*);
ast* new_attribute_option_statement(config_option, attribute_expression*);

ast* new_define_statement(char*, string_expression*);
ast* new_undefine_statement(char*);

ast* new_group_statement(char*, attribute_expression*);

ast* new_include_statement(string_expression*, string_expression*, bool);
ast* new_x_include_setenv_statement(char*, string_expression*);

ast* new_if_statement(struct if_condition*, struct ast*, struct ast*);

ast* new_rule_statement(AIDE_RULE_TYPE, string_expression*, restriction_expression*, attribute_expression*);

if_condition* new_if_condition(struct bool_expression*);

bool_expression* new_string_bool_expression(bool_operator, string_expression*);
bool_expression* new_bool_expression(bool_operator, bool_expression*, bool_expression*);

attribute_expression* new_attribute_expression(attribute_operator, attribute_expression*, char*);
restriction_expression* new_restriction_expression(restriction_expression*, char*);

void deep_free(ast*);

#endif
