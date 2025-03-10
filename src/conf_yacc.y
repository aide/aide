%code requires {
#include "conf_ast.h"
}
%{

/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2013, 2015-2016, 2019-2025 Rami Lehti,
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
#include "attributes.h"
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "rx_rule.h"
#include "conf_lex.h"

DB_ATTR_TYPE retval=0;

#include "conf_ast.h"
extern int conflex(void);
void conferror(ast**, const char *);

%}
%union {
  char* s;

  config_option option;

  bool_operator operator;

  ast* ast;

  if_condition* if_cond;
  bool_expression* bool_expr;
  attribute_expression* attr_expr;
  restriction_expression* rs_expr;
  ft_restriction_expression* ft_rs_expr;
  string_expression* string_expr;
}

%token TDEFINE "@@define"
%token TUNDEFINE "@@undef"
%token TIFDEF "@@ifdef"
%token TIFNDEF "@@ifndef"
%token TIFNHOST "@@ifnhost"
%token TIFHOST "@@ifhost"
%token TIF "@@if"
%token TBOOLNOT "not"
%token <operator> TBOOLFUNC "boolean function"
%token <operator> TBOOLOP "boolean operator"
%token TELSE "@@else"
%token TENDIF "@@endif"
%token TINCLUDE "@@include"
%token TXINCLUDE "@@x_include"
%token TSETENV "@@x_include_setenv"
%token <s> TGROUP "group name"
%token <s> TSTRING "string"
%token <s> TEXPR "group"
%token <s> TVARIABLE "variable name"

%token TSPACE "whitespace"
%token TNEWLINE "new line"

/* File rule */

%token <s> TSELRXRULE "regular rule"
%token <s> TEQURXRULE "equals rule"
%token <s> TRECNEGRXRULE "recursive negative rule"
%token <s> TNONRECNEGRXRULE "non-recursive negative rule"

%token <option> CONFIGOPTION "configuration option"

%type <ast> statements statement config_statement include_statement x_include_setenv_statement if_statement define_statement undefine_statement group_statement rule_statement

%type <if_cond> if_condition
%type <bool_expr> bool_expression
%type <attr_expr> attribute_expression
%type <rs_expr> restriction_expression
%type <ft_rs_expr> ft_restriction_expression
%type <string_expr> string_expression string_fragment

%start config

%parse-param {ast** config_ast}
%define parse.error verbose

%%

config : %empty  /* empty input */
       | statements { *config_ast = $1; }

statements : statement TNEWLINE statements {
               ast *temp = $1;
               temp->next = $3;
               $$ = $1; }
               | statement TNEWLINE { $$ = $1; }
               | statement { $$ = $1; }

statement: config_statement
         | include_statement
         | x_include_setenv_statement
         | if_statement
         | define_statement | undefine_statement
         | group_statement
         | rule_statement

attribute_expression: attribute_expression '+' TEXPR { $$ = new_attribute_expression(ATTR_OP_PLUS, $1, $3); }
                    | attribute_expression '-' TEXPR { $$ = new_attribute_expression(ATTR_OP_MINUS, $1, $3); }
                    | TEXPR { $$ = new_attribute_expression(ATTR_OP_GROUP, NULL, $1); }

ft_restriction_expression: ft_restriction_expression ',' TEXPR { $$ = new_ft_restriction_expression($1, $3); }
                      | TEXPR { $$ = new_ft_restriction_expression(NULL, $1); }

restriction_expression: ft_restriction_expression '=' TEXPR { $$ = new_restriction_expression($1, $3); }
                      | '=' TEXPR { $$ = new_restriction_expression(NULL, $2); }
                      | ft_restriction_expression { $$ = new_restriction_expression($1, NULL); }
                      | '0' { $$ = new_restriction_expression(NULL, NULL); }

define_statement: TDEFINE TVARIABLE { $$ = new_define_statement($2, NULL); }
                | TDEFINE TVARIABLE string_expression { $$ = new_define_statement($2, $3); }

string_expression: string_fragment string_expression { $$ = new_string_concat($1, $2); }
                 | string_fragment { $$ = $1; }
string_fragment: TSTRING { $$ = new_string($1); }
               | TVARIABLE { $$ = new_variable($1); }

undefine_statement: TUNDEFINE TVARIABLE { $$ = new_undefine_statement($2); }

config_statement: CONFIGOPTION '=' string_expression { $$ = new_string_option_statement($1, $3); }
                | CONFIGOPTION '=' attribute_expression { $$ = new_attribute_option_statement($1, $3); }

group_statement: TGROUP '=' attribute_expression { $$ = new_group_statement($1, $3); }

include_statement: TINCLUDE TSPACE string_expression { $$ = new_include_statement($3, NULL, false, NULL); }
                 | TINCLUDE TSPACE string_expression TSPACE string_expression { $$ = new_include_statement($3, $5, false, NULL); }
                 | TINCLUDE TSPACE string_expression TSPACE string_expression TSPACE string_expression{ $$ = new_include_statement($3, $5, false, $7); }
                 | TXINCLUDE TSPACE string_expression { $$ = new_include_statement($3, NULL, true, NULL); }
                 | TXINCLUDE TSPACE string_expression TSPACE string_expression { $$ = new_include_statement($3, $5, true, NULL); }
                 | TXINCLUDE TSPACE string_expression TSPACE string_expression TSPACE string_expression { $$ = new_include_statement($3, $5, true, $7); }

x_include_setenv_statement: TSETENV TVARIABLE string_expression { $$ = new_x_include_setenv_statement($2, $3); }

if_statement: if_condition TNEWLINE statements TENDIF { $$ = new_if_statement($1, $3, NULL); }
            | if_condition TNEWLINE statements TELSE TNEWLINE statements TENDIF { $$ = new_if_statement($1, $3, $6); }

if_condition: TIFDEF string_expression { $$=new_if_condition(new_string_bool_expression(BOOL_OP_DEFINED, $2, NULL)); }
            | TIFNDEF string_expression { $$=new_if_condition(new_bool_expression(BOOL_OP_NOT, new_string_bool_expression(BOOL_OP_DEFINED, $2, NULL), NULL)); }
            | TIFHOST string_expression { $$=new_if_condition(new_string_bool_expression(BOOL_OP_HOSTNAME, $2, NULL)); }
            | TIFNHOST string_expression { $$=new_if_condition(new_bool_expression(BOOL_OP_NOT, new_string_bool_expression(BOOL_OP_HOSTNAME, $2, NULL), NULL)); }
            | TIF bool_expression { $$=new_if_condition($2); }

bool_expression: TBOOLNOT bool_expression { $$ = new_bool_expression(BOOL_OP_NOT, $2, NULL); }
               | TBOOLFUNC string_expression { $$ = new_string_bool_expression($1, $2, NULL); }
               | string_expression TBOOLOP string_expression { $$ = new_string_bool_expression($2, $1, $3); }

rule_statement: TSELRXRULE string_expression attribute_expression { $$ = new_rule_statement(AIDE_SELECTIVE_RULE, $2, NULL, $3); }
              | TEQURXRULE string_expression attribute_expression { $$ = new_rule_statement(AIDE_EQUAL_RULE, $2, NULL, $3); }
              | TRECNEGRXRULE string_expression { $$ = new_rule_statement(AIDE_RECURSIVE_NEGATIVE_RULE, $2, NULL, NULL); }
              | TNONRECNEGRXRULE string_expression { $$ = new_rule_statement(AIDE_NON_RECURSIVE_NEGATIVE_RULE, $2, NULL, NULL); }
              | TSELRXRULE string_expression restriction_expression attribute_expression { $$ = new_rule_statement(AIDE_SELECTIVE_RULE, $2, $3, $4); }
              | TEQURXRULE string_expression restriction_expression attribute_expression { $$ = new_rule_statement(AIDE_EQUAL_RULE, $2, $3, $4); }
              | TRECNEGRXRULE string_expression restriction_expression { $$ = new_rule_statement(AIDE_RECURSIVE_NEGATIVE_RULE, $2, $3, NULL); }
              | TNONRECNEGRXRULE string_expression restriction_expression { $$ = new_rule_statement(AIDE_NON_RECURSIVE_NEGATIVE_RULE, $2, $3, NULL); }
              | TRECNEGRXRULE string_expression restriction_expression attribute_expression {
                log_msg(LOG_LEVEL_ERROR, "%s:%d: recursive negative rule must not have an attribute expression (line: '%s')", conf_filename, conf_linenumber, conf_linebuf);
                YYABORT;
              }
              | TNONRECNEGRXRULE string_expression restriction_expression attribute_expression {
                log_msg(LOG_LEVEL_ERROR, "%s:%d: non-recursive negative rule must not have an attribute expression (line: '%s')", conf_filename, conf_linenumber, conf_linebuf);
                YYABORT;
              }

%%

void conferror(
    ast** config_ast  __attribute__((unused)),
    const char *msg){
  log_msg(LOG_LEVEL_ERROR, "%s:%d: %s (line: '%s')", conf_filename, conf_linenumber, msg, conf_linebuf);
}
