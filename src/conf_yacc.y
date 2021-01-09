%code requires {
#include "conf_ast.h"
}
%{

/*
 * Copyright (C) 1999-2006,2010-2013,2015,2016,2019-2021 Rami Lehti, Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
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
#include "attributes.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include "list.h"
#include "conf_lex.h"
#include "gen_list.h"
#include "db.h"
#include "db_config.h"
#include "symboltable.h"
#include "util.h"
#include "commandconf.h"

#include "seltree.h"

DB_ATTR_TYPE retval=0;

#include "conf_ast.h"
extern int conflex();
void conferror(ast**, const char *);

%}
%union {
  char* s;

  config_option option;

  ast* ast;

  if_condition* if_cond;
  attribute_expression* attr_expr;
  restriction_expression* rs_expr;
  string_expression* string_expr;
}

%token TDEFINE
%token TUNDEFINE
%token TIFDEF
%token TIFNDEF
%token TIFNHOST
%token TIFHOST
%token TELSE
%token TENDIF
%token TINCLUDE
%token <s> TGROUP
%token <s> TSTRING
%token <s> TEXPR
%token <s> TVARIABLE

%token TSPACE
%token TNEWLINE

/* File rule */

%token <s> TSELRXRULE
%token <s> TEQURXRULE
%token <s> TNEGRXRULE

%token <option> CONFIGOPTION

%type <ast> statements statement config_statement include_statement if_statement define_statement undefine_statement group_statement rule_statement

%type <if_cond> if_condition
%type <attr_expr> attribute_expression
%type <rs_expr> restriction_expression
%type <string_expr> string_expression string_fragment

%start config

%parse-param {ast** config_ast}

%%

config : %empty  /* empty input */
       | statements { *config_ast = $1; }

statements : statement TNEWLINE statements {
               ast *temp = $1;
               temp->next = $3;
               $$ = $1; }
               | statement TNEWLINE { $$ = $1; }
               | statement {
                    log_msg(LOG_LEVEL_ERROR, "%s:%d: syntax error: unexpected token or end of file, expected newline (line: '%s')", conf_filename, conf_linenumber, conf_linebuf);
                    YYABORT;
               }

statement: config_statement
         | include_statement
         | if_statement
         | define_statement | undefine_statement
         | group_statement
         | rule_statement

attribute_expression: attribute_expression '+' TEXPR { $$ = new_attribute_expression(ATTR_OP_PLUS, $1, $3); }
                    | attribute_expression '-' TEXPR { $$ = new_attribute_expression(ATTR_OP_MINUS, $1, $3); }
                    | TEXPR { $$ = new_attribute_expression(ATTR_OP_GROUP, NULL, $1); }

restriction_expression: restriction_expression ',' TEXPR { $$ = new_restriction_expression($1, $3); }
                      | TEXPR { $$ = new_restriction_expression(NULL, $1); }

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

include_statement: TINCLUDE TSPACE string_expression { $$ = new_include_statement($3, NULL); }
                 | TINCLUDE TSPACE string_expression TSPACE string_expression { $$ = new_include_statement($3, $5); }

if_statement: if_condition TNEWLINE statements TENDIF { $$ = new_if_statement($1, $3, NULL); }
            | if_condition TNEWLINE statements TELSE TNEWLINE statements TENDIF { $$ = new_if_statement($1, $3, $6); }

if_condition: TIFDEF string_expression { $$=new_if_condition(new_string_bool_expression(BOOL_OP_DEFINED, $2)); }
            | TIFNDEF string_expression { $$=new_if_condition(new_bool_expression(BOOL_OP_NOT, new_string_bool_expression(BOOL_OP_DEFINED, $2), NULL)); }
            | TIFHOST string_expression { $$=new_if_condition(new_string_bool_expression(BOOL_OP_HOSTNAME, $2)); }
            | TIFNHOST string_expression { $$=new_if_condition(new_bool_expression(BOOL_OP_NOT, new_string_bool_expression(BOOL_OP_HOSTNAME, $2), NULL)); }

rule_statement: TSELRXRULE string_expression attribute_expression { $$ = new_rule_statement(AIDE_SELECTIVE_RULE, $2, NULL, $3); }
              | TEQURXRULE string_expression attribute_expression { $$ = new_rule_statement(AIDE_EQUAL_RULE, $2, NULL, $3); }
              | TNEGRXRULE string_expression { $$ = new_rule_statement(AIDE_NEGATIVE_RULE, $2, NULL, NULL); }
              | TSELRXRULE string_expression restriction_expression attribute_expression { $$ = new_rule_statement(AIDE_SELECTIVE_RULE, $2, $3, $4); }
              | TEQURXRULE string_expression restriction_expression attribute_expression { $$ = new_rule_statement(AIDE_EQUAL_RULE, $2, $3, $4); }
              | TNEGRXRULE string_expression restriction_expression { $$ = new_rule_statement(AIDE_NEGATIVE_RULE, $2, $3, NULL); }

%%

void conferror(
    ast** config_ast  __attribute__((unused)),
    const char *msg){
  log_msg(LOG_LEVEL_ERROR, "%s:%d: %s (line: '%s')", conf_filename, conf_linenumber, msg, conf_linebuf);
}
