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

#include "config.h"
#include "aide.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "attributes.h"
#include "conf_ast.h"
#include "db_config.h"
#include "hashsum.h"
#include "list.h"
#include "report.h"

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

#include <stdlib.h>
#include <stddef.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

LOG_LEVEL eval_log_level = LOG_LEVEL_DEBUG;

bool log_level_set_in_config = false;

list* x_include_environment = NULL;

#define BOOL_CONFIG_OPTION_CASE(id, option) \
    case id: \
        b = string_expression_to_bool(statement.e, linenumber, filename, linebuf); \
        conf->option = b; \
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "set '%s' to '%s'", #option, btoa(conf->option)) \
        break;

#define ATTRIBUTE_CONFIG_OPTION_CASE(id, option) \
    case id: \
        attr = eval_attribute_expression(statement.a, linenumber, filename, linebuf); \
        conf->option=attr; \
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "set '%s' to '%s'", #option, str = diff_attributes(0, attr) ) \
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
                str = checked_strdup(((symba*)entry->data)->value?((symba*)entry->data)->value:"");
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "variable substitution: replace '@@%c%s%c' with '%s'", '{', expression->str, '}', str)
            } else if (strcmp(expression->str, "HOSTNAME") == 0 && conf->hostname) {
                str = checked_strdup(conf->hostname);
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "variable substitution: replace '@@%c%s%c' with '%s'", '{', expression->str, '}', str)
            } else {
                str = checked_strdup("");
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "variable substitution: variable '%s' not defined (use empty string)", expression->str)
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
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "unrecognized bool value: '%s' (expecting %s)", str, "'true', 'yes','false' or 'no'")
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
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "group '%s' is not defined", expression->right)
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
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "invalid attribute(s): %s", str = diff_attributes(0, attr&(~hashes)));
            free(str);
            exit(INVALID_CONFIGURELINE_ERROR);
        }
        DB_ATTR_TYPE unsupported_hashes = attr&(get_hashes(true)&~get_hashes(false));
        if (unsupported_hashes) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, "ignoring unsupported hash algorithm(s): %s", str = diff_attributes(0, unsupported_hashes));
            free(str);
            attr &= ~unsupported_hashes;
        }
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "set 'database_attrs' option to: %s", str = diff_attributes(0, attr));
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
            if(do_rootprefix(str, linenumber, filename, linebuf) == false) {
                free(str);
            }
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
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "gzip support not compiled in, recompile AIDE with '--with-zlib'")
                exit(INVALID_CONFIGURELINE_ERROR);
#endif
            break;
        BOOL_CONFIG_OPTION_CASE(DATABASE_ADD_METADATA_OPTION, database_add_metadata)
        case ACL_NO_SYMLINK_FOLLOW_OPTION:
#ifdef WITH_ACL
            b = string_expression_to_bool(statement.e, linenumber, filename, linebuf);
            conf->no_acl_on_symlinks=b;
#else
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "acl support not compiled in, recompile AIDE with '--with-posix-acl'")
            exit(INVALID_CONFIGURELINE_ERROR);
#endif
            break;
        case REPORT_IGNORE_E2FSATTRS_OPTION:
#ifdef WITH_E2FSATTRS
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            do_report_ignore_e2fsattrs(str, linenumber, filename, linebuf);
            free(str);
#else
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "e2fsattrs support not compiled in, recompile AIDE with '--with-e2fsattrs'")
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
        BOOL_CONFIG_OPTION_CASE(CONFIG_CHECK_WARN_UNRESTRICTED_RULES, config_check_warn_unrestricted_rules)
        case REPORT_LEVEL_OPTION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            if(!do_reportlevel(str, linenumber, filename, linebuf)) {
                exit(INVALID_CONFIGURELINE_ERROR);
            }
            free(str);
            break;
        case REPORT_FORMAT_OPTION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            REPORT_FORMAT report_format = get_report_format(str);
            if (report_format) {
                conf->report_format = report_format;
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "set 'report_format' option to '%s' (raw: %d)", str, report_format)
            } else {
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "invalid report format: '%s'", str);
                exit(INVALID_CONFIGURELINE_ERROR);
            }
            free(str);
            break;
        case LOG_LEVEL_OPTION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            LOG_LEVEL level = get_log_level_from_string(str);
            if (level == LOG_LEVEL_UNSET) {
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "invalid log level: '%s'", str);
                exit(INVALID_CONFIGURELINE_ERROR);
            } else {
                if (is_log_level_unset() || ( conf->action&DO_DRY_RUN && !log_level_set_in_config )) {
                    if (!(conf->action&DO_DRY_RUN)) {
                        set_log_level(level);
                    } else {
                        log_level_set_in_config = true;
                    }
                    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "set 'log_level' option to '%s'", str)
                } else {
                    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, "'log_level' option already set (ignore new value '%s')", str)
                }
            }
            free(str);
            break;
        case CONFIG_VERSION:
            str = eval_string_expression(statement.e, linenumber, filename, linebuf);
            conf->config_version = str;
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "set 'config_version' option to '%s'", str)
            break;
        case VERBOSE_OPTION:
            log_msg(LOG_LEVEL_ERROR, "%s:%d: 'verbose' option is no longer supported, use 'log_level' and 'report_level' options instead (see man aide.conf for details) (line: '%s')", conf_filename, conf_linenumber, conf_linebuf);
            exit(INVALID_CONFIGURELINE_ERROR);
            break;
        case LIMIT_CMDLINE_OPTION:
            /* command-line options are ignored here */
            break;
    }
}

static bool eval_bool_expression(struct bool_expression* expression, int linenumber, char *filename, char* linebuf) {
    bool result = false, left;
    char * str;

    switch (expression->op) {
        case BOOL_OP_EXISTS:
            str = eval_string_expression(expression->expr, linenumber, filename, linebuf);

            int retval = access(str, F_OK);
            result = retval == 0;
            log_msg(LOG_LEVEL_DEBUG, "access('%s', F_OK) returns %d: (%s)", str, retval, strerror(errno));
            log_msg(eval_log_level, "eval(%p): bool exists '%s': %s", expression, str, btoa(result));
            free(str);
            break;
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
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, "%s", "hostname not available; ifhost and ifnhost always evaluate to 'false'")
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
         char *str;
         attr = eval_attribute_expression(statement.expr, linenumber, filename, linebuf);
         if ((prev_attr = do_groupdef(statement.name, attr))) {
            char *str2;
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, "redefine group '%s' with value '%s' (previous value: '%s')", statement.name, str = diff_attributes(0, attr), str2 = diff_attributes(0, prev_attr))
            free(str2);
         } else {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "define group '%s' with value '%s'", statement.name, str = diff_attributes(0, attr))
         }
         free(str);
}

static bool evaL_if_condition(if_condition* c) {
    log_msg(eval_log_level, "eval(%p): if condition", c);
    bool cond_result = eval_bool_expression(c->expression, c->linenumber, c->filename, c->linebuf);
    log_msg(LOG_LEVEL_CONFIG,"%s:%d: if condition results to '%s' (line: '%s')", c->filename, c->linenumber, btoa(cond_result), c->linebuf);
    return cond_result;
}

static void eval_if_statement(if_statement statement, int include_depth, char* rule_prefix, int linenumber, char *filename, char* linebuf) {
    bool condition = evaL_if_condition(statement.condition);

    if (condition) {
        log_msg(eval_log_level, "eval(%p): if branch", statement.if_branch);
        if (statement.if_branch) {
            eval_config(statement.if_branch, include_depth, rule_prefix);
        }
    } else {
        log_msg(eval_log_level, "eval(%p): else branch", statement.else_branch);
        if (statement.else_branch) {
            eval_config(statement.else_branch, include_depth, rule_prefix);
        }
    }
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "%s", "endif")
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

static int dirfilter(const struct dirent *d) {
    return (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0);
}

static void eval_x_include_setenv_statement(x_include_setenv_statement statement, int linenumber, char *filename, char* linebuf) {
    symba* s=NULL;
    list* l=NULL;

    char* value = eval_string_expression(statement.value, linenumber, filename, linebuf);

    if(!(l=list_find(statement.variable,x_include_environment))) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, "add '%s' with value '%s' to @@x_include environment", statement.variable, value)
        s=(symba*)checked_malloc(sizeof(symba));
        s->name=checked_strdup(statement.variable);
        s->value=value;
        x_include_environment=list_append(x_include_environment,(void*)s);
    } else {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, "overwrite '%s' variable with value '%s' in @@x_include environment (previous value: '%s')", statement.variable, value, ((symba*)l->data)->value)
        free(((symba*)l->data)->value);
        ((symba*)l->data)->value=NULL;
        ((symba*)l->data)->value=value;
    }
}

static void include_file(const char* file, bool execute, int include_depth, char* rule_prefix) {
    if (execute) {
        int p_stdout[2];
        int p_stderr[2];
        pid_t pid;

        if (pipe(p_stdout)==-1) {
            log_msg(LOG_LEVEL_ERROR, "%s: pipe stdout failed: %s", file, strerror(errno));
            exit(EXEC_ERROR);
        }
        if (pipe(p_stderr)==-1) {
            log_msg(LOG_LEVEL_ERROR, "%s: pipe stderr failed: %s", file, strerror(errno));
            exit(EXEC_ERROR);
        }
        if ((pid = fork()) == -1) {
            log_msg(LOG_LEVEL_ERROR, "%s: fork failed: %s", file, strerror(errno));
            exit(EXEC_ERROR);
        }

        if(pid == 0) {
            /* child */
            close(p_stdout[0]);
            dup2 (p_stdout[1], STDOUT_FILENO);
            close(p_stdout[1]);
            close(p_stderr[0]);
            dup2 (p_stderr[1], STDERR_FILENO);
            close(p_stderr[1]);

            list *entry;
            for(entry = x_include_environment ; entry != NULL; entry = entry->next) {
                char* name = ((symba*)entry->data)->name;
                char* value = ((symba*)entry->data)->value;
                if (setenv(name, value, 0) < 0) {
                    fprintf(stderr, "aide: @@x_include: setenv for '%s' failed: %s\n", name, strerror(errno));
                    exit(EXEC_ERROR);
                }
            }

            execl(file, file, (char*) NULL);
            log_msg(LOG_LEVEL_ERROR, "%s: execl failed: %s", file, strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            /* parent */
            close(p_stdout[1]);
            close(p_stderr[1]);

            char* config_str = pipe2string(p_stdout[0]);

            char* child_stderr = pipe2string(p_stderr[0]);

            int wstatus;
            waitpid(pid, &wstatus, 0);
            if (child_stderr || !WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
                char* newline;
                while (child_stderr && *child_stderr != '\0') {
                    newline = strchr(child_stderr, '\n');
                    if (newline != NULL) {
                        log_msg(LOG_LEVEL_ERROR, "%s: stderr> %.*s", file, newline-child_stderr, child_stderr);
                        child_stderr = newline+1;
                    } else {
                        log_msg(LOG_LEVEL_ERROR, "%s: stderr> %s", file, child_stderr);
                        break;
                    }
                }
                log_msg(LOG_LEVEL_ERROR, "%s: execution failed (exit status: %d)", file, WEXITSTATUS(wstatus));
                exit(EXEC_ERROR);
            }

            if (config_str) {
                ast* config_ast = NULL;
                int len = (strlen(file) + 10) * sizeof(char);
                char * source_name = checked_malloc(len);
                snprintf(source_name, len, "%s (stdout)", file);
                conf_lex_string(source_name, config_str);
                if(confparse(&config_ast)){
                    exit(INVALID_CONFIGURELINE_ERROR);
                }
                conf_lex_delete_buffer();
                free(source_name);
                eval_config(config_ast, include_depth, rule_prefix);
                deep_free(config_ast);
            }
            free(config_str);
        }
    } else {
    ast* config_ast = NULL;
    conf_lex_file(file);
    if(confparse(&config_ast)){
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    conf_lex_delete_buffer();
    eval_config(config_ast, include_depth, rule_prefix);
    deep_free(config_ast);
    }
}

void check_permissions(const char* path, struct stat *st, int linenumber, char *filename, char* linebuf) {
    if (st->st_uid != geteuid() || (st->st_mode & 002) != 0 || (st->st_mode & 020) != 0) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'@@x_include': bad ownership or modes for '%s' (please ensure it is neither group- nor world-writable and owned by the current user)", path)
        exit(INVALID_CONFIGURELINE_ERROR);
    }
}

static void include_directory(const char* dir, const char* rx, bool execute, char* new_rule_prefix, int include_depth, char* rule_prefix, int linenumber, char *filename, char* linebuf) {
    LOG_CONFIG_FORMAT_LINE_PREFIX(LOG_LEVEL_CONFIG, "include directory '%s' (regex: '%s', execute: %s , prefix: '%s', depth: %d)", dir, rx, btoa(execute), new_rule_prefix?new_rule_prefix:"", include_depth)

    struct dirent **namelist;
    int n;

    int pcre2_errorcode;
    PCRE2_SIZE pcre2_erroffset;
    pcre2_code* crx;

    if((crx = pcre2_compile((PCRE2_SPTR) rx, PCRE2_ZERO_TERMINATED, PCRE2_UTF, &pcre2_errorcode, &pcre2_erroffset, NULL)) == NULL) {
        PCRE2_UCHAR pcre2_error[128];
        pcre2_get_error_message(pcre2_errorcode, pcre2_error, 128);
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'%s': error in regular expression '%s' at %i: %s", execute?"@@x_include":"@@include", rx, pcre2_erroffset, pcre2_error)
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(crx, NULL);
    if (match_data == NULL) {
        log_msg(LOG_LEVEL_ERROR, "pcre2_match_data_create_from_pattern: failed to allocate memory");
        exit(MEMORY_ALLOCATION_FAILURE);
    }

    struct stat fs;

    if (execute) {
        if (stat(dir,&fs) == -1) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'@@x_include': stat for '%s' failed: %s", dir, strerror(errno))
            exit(INVALID_CONFIGURELINE_ERROR);
        }
        check_permissions(dir, &fs, linenumber, filename, linebuf);
    }

    n = scandir(dir, &namelist, dirfilter, alphasort);
    if (n == -1) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'%s': failed to open directory '%s': %s", execute?"@@x_include":"@@include", dir, strerror(errno))
        exit(INVALID_CONFIGURELINE_ERROR);
    }

    if (new_rule_prefix && *new_rule_prefix != '/') {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'%s': invalid rule prefix '%s': unexpected first character '%c', expected '/'", execute?"@@x_include":"@@include", new_rule_prefix, *new_rule_prefix)
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    /* not to be freed, reused in add_rx_rule_to_tree */
    char* nested_rule_prefix = NULL;
    if (rule_prefix && new_rule_prefix) {
        int length = strlen(rule_prefix)+strlen(new_rule_prefix);
        nested_rule_prefix = checked_malloc(length+1);
        strncpy(nested_rule_prefix, rule_prefix, length+1);
        strncat(nested_rule_prefix, new_rule_prefix, length-strlen(rule_prefix)+1);
        log_msg(LOG_LEVEL_DEBUG, "concatenate current prefix '%s' and new prefix '%s': '%s'", rule_prefix, new_rule_prefix, nested_rule_prefix);
        free(new_rule_prefix);
    } else if (rule_prefix) {
        nested_rule_prefix = rule_prefix;
    } else if (new_rule_prefix) {
        nested_rule_prefix = new_rule_prefix;
    }

    int dir_len = strlen(dir);
    for (int i = 0 ; i < n ; ++i) {

        int len = (dir_len+strlen(namelist[i]->d_name)+2)*sizeof(char);
        char * filepath = checked_malloc(len);
        snprintf(filepath, len, "%s/%s", dir, namelist[i]->d_name);
        if (stat(filepath,&fs) == -1) {
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'%s': stat for '%s' failed: %s", execute?"@@x_include":"@@include", filepath, strerror(errno))
            exit(INVALID_CONFIGURELINE_ERROR);
        }
        if (S_ISREG(fs.st_mode)) {
            int match=pcre2_match(crx, (PCRE2_SPTR) namelist[i]->d_name, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
            if(match < 0) {
                log_msg(LOG_LEVEL_DEBUG,"%s: skip '%s' (reason: file name does not match regex '%s')", dir, namelist[i]->d_name, rx);
            } else {
                int exec = execute && S_IXUSR&fs.st_mode;
                if (exec) {
                    check_permissions(filepath, &fs, linenumber, filename, linebuf);
                }
                log_msg(LOG_LEVEL_CONFIG,"%s: %s '%s'", dir, exec?"execute":"include", namelist[i]->d_name);
                include_file(filepath, exec, include_depth, nested_rule_prefix);
            }
        } else {
            log_msg(LOG_LEVEL_DEBUG,"%s: skip '%s' (reason: file is not a regular file)", dir, namelist[i]->d_name);
        }

        free(filepath);
        free(namelist[i]);
    }
    free(namelist);
    pcre2_match_data_free(match_data);
    pcre2_code_free(crx);
}

static void eval_include_statement(include_statement statement, int include_depth, char* rule_prefix, int linenumber, char *filename, char* linebuf) {
    if (include_depth >= 16) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "include files are nested too deeply")
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    char* path = eval_string_expression(statement.path, linenumber, filename, linebuf);
    char* rx = statement.rx?eval_string_expression(statement.rx, linenumber, filename, linebuf):NULL;

    if (rx) {
        char* new_rule_prefix = NULL;
        if (statement.prefix) {
            new_rule_prefix = eval_string_expression(statement.prefix, linenumber, filename, linebuf);
            int prefix_length = strlen(new_rule_prefix);
            if (prefix_length && new_rule_prefix[prefix_length-1] == '/') {
                new_rule_prefix[prefix_length-1] = '\0';
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, "%s: removed trailing '/' from prefix: '%s'", statement.execute?"@@x_include":"@@include", new_rule_prefix);
            }
        }
        include_directory(path, rx, statement.execute, new_rule_prefix, include_depth, rule_prefix, linenumber, filename, linebuf);
        free(rx);
    } else {
    struct stat fs;
    if (lstat(path,&fs) == -1) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'@@include': lstat for '%s' failed: %s", path, strerror(errno))
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    if (S_ISREG(fs.st_mode)) {
        LOG_CONFIG_FORMAT_LINE_PREFIX(LOG_LEVEL_CONFIG, "include file '%s' (depth: %d)", path, include_depth)
        include_file(path, statement.execute && S_IXUSR&fs.st_mode, include_depth, rule_prefix);
    } else {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "'@@include': '%s' is not a regular file", path);
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    }
}

static RESTRICTION_TYPE eval_restriction_expression(restriction_expression *expression, int linenumber, char *filename, char* linebuf) {
    RESTRICTION_TYPE rs = FT_NULL, rs_r;

    if (expression) {
        char *unrestricted = "0";
        if (strncmp(expression->right, unrestricted, strlen(unrestricted)) == 0) {
            rs_r = FT_NULL;
            log_msg(eval_log_level, "eval(%p): restriction '%s', evaluates to %d", expression, unrestricted, rs);
        } else {
            rs_r = (strlen(expression->right) == 1)?get_restriction_from_char(*(expression->right)):FT_NULL;
            log_msg(eval_log_level, "eval(%p): restriction file type '%s' evaluates to %d", expression, expression->right, rs_r);
            if (rs_r == FT_NULL) {
                LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "invalid restriction '%s'", expression->right)
                    exit(INVALID_CONFIGURELINE_ERROR);
            }
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

static void eval_rule_statement(rule_statement statement, char* rule_prefix, int linenumber, char *filename, char* linebuf) {
    char *rx = eval_string_expression(statement.path, linenumber, filename, linebuf);
     if (conf->action&DO_DRY_RUN && conf->config_check_warn_unrestricted_rules && !statement.restriction) {
         LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, "%s '%s' is unrestricted", get_rule_type_long_string(statement.type), rx)
     }
    if(!add_rx_rule_to_tree(
            rx,
            rule_prefix,
            eval_restriction_expression(statement.restriction, linenumber, filename, linebuf),
            eval_attribute_expression(statement.attributes, linenumber, filename, linebuf),
            statement.type,
            conf->tree,
            linenumber, filename, linebuf)) {
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    free(rx);
}

void eval_config(ast* config_ast, int include_depth, char *rule_prefix) {
    ast* node = NULL;
    for(node = config_ast; node != NULL; node = node->next) {
        log_msg(eval_log_level, "eval(%p): ast node (next: %p)", node, node->next);
        switch (node->type) {
            case config_option_type:
                eval_config_statement(node->statement._config, node->linenumber, node->filename, node->linebuf);
                break;
            case include_statement_type:
                eval_include_statement(node->statement._include, include_depth+1, rule_prefix, node->linenumber, node->filename, node->linebuf);
                break;
            case x_include_setenv_statement_type:
                eval_x_include_setenv_statement(node->statement._x_include_setenv, node->linenumber, node->filename, node->linebuf);
                break;
            case if_statement_type:
                eval_if_statement(node->statement._if, include_depth, rule_prefix, node->linenumber, node->filename, node->linebuf);
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
                eval_rule_statement(node->statement._rule, rule_prefix, node->linenumber, node->filename, node->linebuf);
                break;
        }
    }
}
