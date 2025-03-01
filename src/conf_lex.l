C	[^\r\n\t ]

L	[a-zA-Zˆ‰¸ﬂÂ÷ƒ‹≈0-9_%]
G	[a-zA-Z0-9]
V	[a-zA-Z_]+[a-zA-Z0-9_]*
E	[\ ]*"="[\ ]*

%{

#define YYDEBUG 1

/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2010-2013, 2015-2016, 2019-2025
 *               Rami Lehti, Pablo Virolainen, Richard van den Berg,
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

#include "util.h"
#include "conf_yacc.h"
#include "errorcodes.h"
#include "commandconf.h"
#include "log.h"
#include "progress.h"

#include "conf_ast.h"

#define LOG_LEX_TOKEN(log_level, token, text) \
    log_msg(log_level, "%s:%d: \u2502 " #token " (text: '%s')", conf_filename, conf_linenumber, text);

#define LOG_CONFIG_LINE(log_level, msg) \
     log_msg(log_level, "%s:%d: %s (line: '%s')", conf_filename, conf_linenumber, msg, conf_linebuf);

#define DEPRECATION_NOTICE(deprecated_option, new_option) \
     log_msg(LOG_LEVEL_NOTICE, "%s:%d: Using '%s' is DEPRECATED and will be removed in the release after next. Update your config and use '%s' instead (line: '%s')", conf_filename, conf_linenumber, deprecated_option, new_option ,conf_linebuf);
#define DEPRECATION_WARNING(deprecated_option, new_option) \
     log_msg(LOG_LEVEL_WARNING, "%s:%d: Using '%s' is DEPRECATED and will be removed in the next release.. Update your config and use '%s' instead (line: '%s')", conf_filename, conf_linenumber, deprecated_option, new_option ,conf_linebuf);

int conf_linenumber = 0;
char *conf_filename;
char *conf_linebuf;

LOG_LEVEL lex_log_level = LOG_LEVEL_DEBUG;

#define YY_INPUT(buf,result,max_size) \
        if( ((result=conf_input_wrapper(buf,max_size,confin)) == 0) \
            && ferror(yyin) ) \
          YY_FATAL_ERROR( "input in flex scanner failed" );

%}

%option noinput nounput

%x CONFIG DEFSTMT ENVVAR EXPR EXPREQUHUNT PATH STRING STRINGS STRINGEQHUNT STRINGHUNT CONDITION

%%
<INITIAL><<EOF>> {
            log_msg(lex_log_level,"%s: - <end of file>", conf_filename);
            return (0);
           }
<INITIAL>^[\t\ ]*"#"[^\r\n]*\r?\n {
            conf_linebuf = checked_strndup(conftext, confleng-1);
            ++conf_linenumber;
            LOG_CONFIG_LINE(lex_log_level, "- skip comment line")
            free(conf_linebuf);
           }
<INITIAL>^[\t\ ]*\r?\n {
            conf_linebuf = "";
            ++conf_linenumber;
            LOG_CONFIG_LINE(lex_log_level, "- skip empty line")
           }
<INITIAL>^[^\n\r]* {
            conf_linebuf = checked_strndup(conftext, confleng);
            ++conf_linenumber;
            log_msg(lex_log_level,"%s:%d: \u252c '%s'", conf_filename, conf_linenumber, conf_linebuf);
            yyless(0);
            BEGIN(CONFIG);
           }
<CONFIG>"#"[^\r\n]* { /* inline comment */
  LOG_LEX_TOKEN(lex_log_level, skip inline comment, conftext)
 }

<CONFIG>"=/" {
  LOG_LEX_TOKEN(lex_log_level, TEQURXRULE, "=")
  yyless(strchr(conftext,'/')-conftext);
  BEGIN(PATH);
  return (TEQURXRULE);
}

<CONFIG>"/" {
  LOG_LEX_TOKEN(lex_log_level, TSELRXRULE, "")
  yyless(strchr(conftext,'/')-conftext);
  BEGIN(PATH);
  return (TSELRXRULE);
}

<CONFIG>"!/" {
  LOG_LEX_TOKEN(lex_log_level, TRECNEGRXRULE, "!")
  yyless(strchr(conftext,'/')-conftext);
  BEGIN(PATH);
  return (TRECNEGRXRULE);
}

<CONFIG>"-/" {
  LOG_LEX_TOKEN(lex_log_level, TNONRECNEGRXRULE, "-")
  yyless(strchr(conftext,'/')-conftext);
  BEGIN(PATH);
  return (TNONRECNEGRXRULE);
}

<EXPREQUHUNT>{E} {
  LOG_LEX_TOKEN(lex_log_level, '=', conftext)
  BEGIN(EXPR);
  return('=');
}

<EXPR>0 { /* no restriction */
  LOG_LEX_TOKEN(lex_log_level, '0', conftext)
  return ('0');
}

<EXPR>({L}|">")+ {
  LOG_LEX_TOKEN(lex_log_level, TEXPR, conftext)
  conflval.s=checked_strdup(conftext);
  return (TEXPR);
}

<EXPR>\+ { /* attribute operator */
  LOG_LEX_TOKEN(lex_log_level, '+', conftext)
  return ('+');
}

<EXPR>\- { /* attribute operator */
  LOG_LEX_TOKEN(lex_log_level, '-', conftext)
  return ('-');
}

<EXPR>, { /* restriction seperator */
  LOG_LEX_TOKEN(lex_log_level, ',', conftext)
  return (',');
}

<EXPR>= { /* restriction file system type separator */
  LOG_LEX_TOKEN(lex_log_level, '=', conftext)
  return ('=');
}

<DEFSTMT>({L})+ {
  LOG_LEX_TOKEN(lex_log_level, TVARIABLE, conftext)
  conflval.s=checked_strdup(conftext);
  BEGIN(STRINGHUNT);
  return (TVARIABLE);
}

<CONFIG>"\@\@define" {
  LOG_LEX_TOKEN(lex_log_level, TDEFINE, conftext)
  BEGIN DEFSTMT;
  return (TDEFINE);
}

<CONFIG>"\@\@undef" {
  LOG_LEX_TOKEN(lex_log_level, TUNDEFINE, conftext)
  BEGIN DEFSTMT;
  return (TUNDEFINE);
}

<CONFIG>"\@\@if" {
  LOG_LEX_TOKEN(lex_log_level, TIF, conftext)
  BEGIN(CONDITION);
  return (TIF);
}

<CONDITION>"not" {
  LOG_LEX_TOKEN(lex_log_level, TBOOLNOT, conftext)
  return (TBOOLNOT);
}

<CONDITION>"defined" {
  LOG_LEX_TOKEN(lex_log_level, TBOOLFUNC (BOOL_OP_DEFINED), conftext)
  conflval.operator = BOOL_OP_DEFINED;
  BEGIN(STRINGHUNT);
  return (TBOOLFUNC);
}

<CONDITION>"hostname" {
  LOG_LEX_TOKEN(lex_log_level, TBOOLFUNC (BOOL_OP_HOSTNAME), conftext)
  conflval.operator = BOOL_OP_HOSTNAME;
  BEGIN(STRINGHUNT);
  return (TBOOLFUNC);
}

<CONDITION>"exists" {
  LOG_LEX_TOKEN(lex_log_level, TBOOLFUNC (BOOL_OP_EXISTS), conftext)
  conflval.operator = BOOL_OP_EXISTS;
  BEGIN(STRINGHUNT);
  return (TBOOLFUNC);
}

<CONFIG>"\@\@ifdef" {
  DEPRECATION_WARNING("@@ifdef", "@@if defined")
  LOG_LEX_TOKEN(lex_log_level, TIFDEF, conftext)
  BEGIN(STRINGHUNT);
  return (TIFDEF);
}

<CONFIG>"\@\@ifndef" {
  DEPRECATION_WARNING("@@ifndef", "@@if not defined")
  LOG_LEX_TOKEN(lex_log_level, TIFNDEF, conftext)
  BEGIN(STRINGHUNT);
  return (TIFNDEF);
}

<CONFIG>"\@\@else" {
  LOG_LEX_TOKEN(lex_log_level, TELSE, conftext)
  BEGIN CONFIG;
  return (TELSE);
}

<CONFIG>"\@\@endif" {
  LOG_LEX_TOKEN(lex_log_level, TENDIF, conftext)
  BEGIN CONFIG;
  return (TENDIF);
}

<CONFIG>"\@\@ifhost" {
  DEPRECATION_WARNING("@@ifhost", "@@if hostname")
  LOG_LEX_TOKEN(lex_log_level, TIFHOST, conftext)
  BEGIN(STRINGHUNT);
  return (TIFHOST);
}

<CONFIG>"\@\@ifnhost" {
  DEPRECATION_WARNING("@@ifnhost", "@@if not hostname")
  LOG_LEX_TOKEN(lex_log_level, TIFNHOST, conftext)
  BEGIN(STRINGHUNT);
  return (TIFNHOST);
}

<CONFIG>"\@\@include" {
  LOG_LEX_TOKEN(lex_log_level, TINCLUDE, conftext)
  BEGIN(STRINGS);
  return (TINCLUDE);
}

<CONFIG>"\@\@x_include" {
  LOG_LEX_TOKEN(lex_log_level, TXINCLUDE, conftext)
  BEGIN(STRINGS);
  return (TXINCLUDE);
}

<CONFIG>"\@\@x_include_setenv" {
  LOG_LEX_TOKEN(lex_log_level, TSETENV, conftext)
  BEGIN ENVVAR;
  return (TSETENV);
}

<ENVVAR>({V})+ {
  LOG_LEX_TOKEN(lex_log_level, TVARIABLE, conftext)
  conflval.s=checked_strdup(conftext);
  BEGIN(STRINGHUNT);
  return (TVARIABLE);
}

<CONFIG,DEFSTMT,ENVVAR,EXPR,CONDITION>[\t\ ]+ {
    LOG_LEX_TOKEN(LOG_LEVEL_DEBUG, skip tab(s)/whitespace(s), conftext)
}

<CONFIG>"database_in" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (DATABASE_IN_OPTION), conftext)
  conflval.option = DATABASE_IN_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"database_out" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (DATABASE_OUT_OPTION), conftext)
  conflval.option = DATABASE_OUT_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"database_new" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (DATABASE_NEW_OPTION), conftext)
  conflval.option = DATABASE_NEW_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"database_attrs" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (DATABASE_ATTRIBUTES_OPTION), conftext)
  conflval.option = DATABASE_ATTRIBUTES_OPTION;
  BEGIN (EXPREQUHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"warn_dead_symlinks" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (WARN_DEAD_SYMLINKS_OPTION), conftext)
  conflval.option = WARN_DEAD_SYMLINKS_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_grouped" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_GROUPED_OPTION), conftext)
  conflval.option = REPORT_GROUPED_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_summarize_changes" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_SUMMARIZE_CHANGES_OPTION), conftext)
  conflval.option = REPORT_SUMMARIZE_CHANGES_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}
<CONFIG>"acl_no_symlink_follow" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (ACL_NO_SYMLINK_FOLLOW_OPTION), conftext)
  conflval.option = ACL_NO_SYMLINK_FOLLOW_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_format" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_FORMAT_OPTION), conftext)
  conflval.option = REPORT_FORMAT_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_level" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_LEVEL_OPTION), conftext)
  conflval.option = REPORT_LEVEL_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_ignore_added_attrs" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_IGNORE_ADDED_ATTRS_OPTION), conftext)
  conflval.option = REPORT_IGNORE_ADDED_ATTRS_OPTION;
  BEGIN (EXPREQUHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_ignore_removed_attrs" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_IGNORE_REMOVED_ATTRS_OPTION), conftext)
  conflval.option = REPORT_IGNORE_REMOVED_ATTRS_OPTION;
  BEGIN (EXPREQUHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_ignore_changed_attrs" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_IGNORE_CHANGED_ATTRS_OPTION), conftext)
  conflval.option = REPORT_IGNORE_CHANGED_ATTRS_OPTION;
  BEGIN (EXPREQUHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_force_attrs" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_FORCE_ATTRS_OPTION), conftext)
  conflval.option = REPORT_FORCE_ATTRS_OPTION;
  BEGIN (EXPREQUHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"log_level" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (LOG_LEVEL_OPTION), conftext)
  conflval.option = LOG_LEVEL_OPTION;
  BEGIN(STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"database_add_metadata" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (DATABASE_ADD_METADATA_OPTION), conftext)
  conflval.option = DATABASE_ADD_METADATA_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_url" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_URL_OPTION), conftext)
  conflval.option = REPORT_URL_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_detailed_init" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_DETAILED_INIT_OPTION), conftext)
  conflval.option = REPORT_DETAILED_INIT_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_base16" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_BASE16_OPTION), conftext)
  conflval.option = REPORT_BASE16_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_quiet" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_QUIET_OPTION), conftext)
  conflval.option = REPORT_QUIET_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_append" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_APPEND_OPTION), conftext)
  conflval.option = REPORT_APPEND_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"report_ignore_e2fsattrs" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (REPORT_IGNORE_E2FSATTRS_OPTION), conftext)
  conflval.option = REPORT_IGNORE_E2FSATTRS_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"gzip_dbout" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (DATABASE_GZIP_OPTION), conftext)
  conflval.option = DATABASE_GZIP_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"root_prefix" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (ROOT_PREFIX_OPTION), conftext)
  conflval.option = ROOT_PREFIX_OPTION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"config_version" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (CONFIG_VERSION), conftext)
  conflval.option = CONFIG_VERSION;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"config_check_warn_unrestricted_rules" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (CONFIG_CHECK_WARN_UNRESTRICTED_RULES), conftext)
  conflval.option = CONFIG_CHECK_WARN_UNRESTRICTED_RULES;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>"num_workers" {
  LOG_LEX_TOKEN(lex_log_level, CONFIGOPTION (NUM_WORKERS), conftext)
  conflval.option = NUM_WORKERS;
  BEGIN (STRINGEQHUNT);
  return (CONFIGOPTION);
}

<CONFIG>[a-z]+(_[a-z]+)+ {
  log_msg(LOG_LEVEL_ERROR,"%s:%d: unknown config option: '%s' (line: '%s')", conf_filename, conf_linenumber, conftext, conf_linebuf);
  exit(INVALID_CONFIGURELINE_ERROR);
}

<CONFIG>({G})+ { /* group definition */
  conflval.s=checked_strdup(conftext);
  LOG_LEX_TOKEN(lex_log_level, TGROUP, conftext)
  BEGIN(EXPREQUHUNT);
  return (TGROUP);
}

<CONFIG>({L})+ { /* group definition, deprecated group names */
  log_msg(LOG_LEVEL_WARNING, "%s:%d: special characters in group names are DEPRECATED. Update your config and only use alphanumeric characters (A-Za-z0-9) (line: '%s')", conf_filename, conf_linenumber, conf_linebuf); \
  conflval.s=checked_strdup(conftext);
  LOG_LEX_TOKEN(lex_log_level, TGROUP, conftext)
  BEGIN(EXPREQUHUNT);
  return (TGROUP);
}

<STRINGEQHUNT>{E} {
  LOG_LEX_TOKEN(lex_log_level, '=', conftext)
  BEGIN(STRING);
  return('=');
}

<STRINGS,STRING,PATH>"@@{"({L}+)"}" {
  size_t length = strlen(conftext)-4;
  conflval.s=checked_malloc(length+1);
  strncpy(conflval.s, conftext+3, length);
  conflval.s[length] = '\0';
  LOG_LEX_TOKEN(lex_log_level, TVARIABLE, conflval.s)
  return (TVARIABLE);
}

<STRINGS,STRING,PATH>[^@\\ \t\r\n]+ {
  LOG_LEX_TOKEN(lex_log_level, TSTRING, conftext)
  conflval.s=checked_strdup(conftext);
  return (TSTRING);
}

<STRINGS,STRING,PATH>\\[\\@ ] {
  LOG_LEX_TOKEN(lex_log_level, (escaped) TSTRING, conftext)
  conflval.s=checked_strdup(conftext+1);
  return (TSTRING);
}

<STRINGS,STRING,PATH>[\\@] {
  LOG_LEX_TOKEN(lex_log_level, (single-character) TSTRING, conftext)
  conflval.s=checked_strdup(conftext);
  return (TSTRING);
}

<STRINGS>[\ \t]+ {
  LOG_LEX_TOKEN(lex_log_level, TSPACE, conftext)
  return (TSPACE);
}

<STRING>[\ \t]+ {
  LOG_LEX_TOKEN(LOG_LEVEL_DEBUG, skip tab(s)/whitespace(s), conftext)
  BEGIN(CONFIG);
}

<PATH>[\ \t]+ {
  LOG_LEX_TOKEN(LOG_LEVEL_DEBUG, skip tab(s)/whitespace(s), conftext)
  BEGIN(EXPR);
}

<STRINGHUNT>[\ \t]+ {
  LOG_LEX_TOKEN(LOG_LEVEL_DEBUG, skip tab(s)/whitespace(s), conftext)
  BEGIN(STRING);
}

<STRINGHUNT>[^\ \t\r\n] {
  LOG_LEX_TOKEN(LOG_LEVEL_DEBUG, found string -> unput, conftext)
  yyless(0);
  BEGIN(STRING);
}

<CONFIG,DEFSTMT,ENVVAR,EXPR,EXPREQUHUNT,PATH,STRINGS,STRING,STRINGEQHUNT,STRINGHUNT>\r?\n {
  log_msg(lex_log_level,"%s:%d: \u2534 TNEWLINE (text: '%s')", conf_filename, conf_linenumber, strlen(conftext) == 2?"\\r\\n":"\\n");
  BEGIN 0;
  return (TNEWLINE);
}

<*><<EOF>> {
  log_msg(lex_log_level,"%s:%d: \u2534 <end of file>", conf_filename, conf_linenumber);
  log_msg(LOG_LEVEL_NOTICE,"%s:%d: missing new line at end of file (line: '%s')", conf_filename, conf_linenumber, conf_linebuf);
  return (0);
}

<*>. {
     char *unexpected_character = conftext;
     switch (*conftext) {
         case '\r': unexpected_character = "\\r"; break;
     };
     log_msg(LOG_LEVEL_ERROR,"%s:%d: unexpected character: '%s' (line: '%s')", conf_filename, conf_linenumber, unexpected_character, conf_linebuf);
     exit(INVALID_CONFIGURELINE_ERROR);
}

%%

int confwrap(void){
  return 1;
}

void conf_lex_string(const char * name, const char *string) {
    log_msg(LOG_LEVEL_DEBUG, "parse: '%s'", name);
    conf_linenumber = 0;
    conf_filename = checked_strdup(name); /* not to be freed, needed for logging */
    progress_status(PROGRESS_CONFIG, conf_filename);
    conf_scan_string(string);
}

void conf_lex_file(const char * config) {
    log_msg(LOG_LEVEL_DEBUG, "parse: '%s'", config);
    conf_linenumber = 0;

    if (strcmp(config,"-") == 0) {
        conf_filename = checked_strdup("(stdin)"); /* not to be freed, needed for logging */
        confin = stdin;
    } else {
        conf_filename = checked_strdup(config);  /* not to be freed, needed for logging */
        progress_status(PROGRESS_CONFIG, conf_filename);
        char *expanded_config = expand_tilde(checked_strdup(config));
        confin = fopen( expanded_config, "r" );
        if (!confin) {
            log_msg(LOG_LEVEL_ERROR,"cannot open config file '%s': %s", config, strerror(errno));
            exit(IO_ERROR);
        }
        free(expanded_config);
        expanded_config=NULL;
    }
    conf_switch_to_buffer(conf_create_buffer( confin, YY_BUF_SIZE ));
    BEGIN 0;
}

void conf_lex_delete_buffer(void) {
    conf_delete_buffer( YY_CURRENT_BUFFER );
}
