/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2011, 2013, 2015-2016, 2019-2021 Rami Lehti,
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

#include "aide.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>

#include "commandconf.h"
#include "conf_lex.h"
#include "log.h"
#include "conf_yacc.h"
#include "db.h"
#include "db_config.h"
#include "report.h"
#include "gen_list.h"
#include "symboltable.h"
#include "md.h"
#include "util.h"
#include "base64.h"
#include "conf_eval.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/
#ifdef WITH_CURL
#include "fopen.h"
#endif
#ifdef WITH_E2FSATTRS
#include "e2fsattrs.h"
#endif

#define BUFSIZE 4096
#define ZBUFSIZE 16384

url_t* parse_url(char* val, int linenumber, char* filename, char* linebuf)
{
  url_t* u=NULL;
  char* r=NULL;
  char* val_copy=NULL;
  int i=0;

  u=checked_malloc(sizeof(url_t));

  /* We don't want to modify the original hence strdup(val) */
  val_copy=checked_strdup(val);
  for(r=val_copy;r[0]!=':'&&r[0]!='\0';r++);

  if(r[0]!='\0'){
    r[0]='\0';
    r++;
  }

  u->type = get_url_type(val_copy);
  if (u->type) {
  switch (u->type) {
  case url_file : {
    if(r[0]=='/'&&(r+1)[0]=='/'&&(r+2)[0]=='/'){
      u->value=checked_strdup(r+2);
      break;
    }
    if(r[0]=='/'&&(r+1)[0]=='/'&&(r+2)[0]!='/'){
      char* t=r+2;
      r+=2;
      for(i=0;r[0]!='/'&&r[0]!='\0';r++,i++);
      if(r[0]=='\0'){
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, invalid file-URL '%s': no path after hostname, val)
    free(val_copy);
    free(u);
    return NULL;
      }
      if( (strcmp(t,"localhost") != 0) && !( conf->hostname && strcmp(t,conf->hostname)==0)){
          LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, invalid file-URL '%s': cannot use hostname other than 'localhost' or '%s', val, conf->hostname);
          free(u);
          free(val_copy);
          return NULL;
      }
      u->value=checked_strdup(r);
      r[0]='\0';

      break;
    }
    u->value=checked_strdup(r);
    break;
  }
  case url_ftp :
  case url_https :
  case url_http : {
#ifdef WITH_CURL
    u->value=checked_strdup(val);
#else
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, %s, "http, https and ftp URL support not compiled in, recompile AIDE with '--with-curl'")
    free(val_copy);
    free(u);
    return NULL;
#endif /* WITH CURL */
    break;
  }
  case url_fd:
  case url_stdin:
  case url_stdout:
  case url_stderr: {
    u->value=checked_strdup(r);
    break;
  }
  case url_syslog : {
#ifdef HAVE_SYSLOG
    u->value=checked_strdup(r);
#else
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, %s, "syslog url support not compiled in, recompile AIDE with syslog support")
    free(val_copy);
    free(u);
    return NULL;
#endif
    break;
  }
  }
  } else {
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, unknown URL-type: '%s', val_copy);
    free(u);
    return NULL;
  }

  free(val_copy);

  return u;
}

int parse_config(char *before, char *config, char* after) {
    if(before==NULL && after==NULL && (config==NULL||strcmp(config,"")==0)){
      log_msg(LOG_LEVEL_ERROR,_("missing configuration (use '--config' '--before' or '--after' command line parameter)"));
      return RETFAIL;
    }

    ast* config_ast = NULL;
    if (before) {
        conf_lex_string("(--before)", before);
        if(confparse(&config_ast)){
          return RETFAIL;
        }
        conf_lex_delete_buffer();
        eval_config(config_ast, 0);
        deep_free(config_ast);
        config_ast = NULL;
    }
    if (config) {
        conf_lex_file(config);
        if(confparse(&config_ast)){
          return RETFAIL;
        }
        conf_lex_delete_buffer();
        eval_config(config_ast, 0);
        deep_free(config_ast);
        config_ast = NULL;
    }
    if (after) {
        conf_lex_string("(--after)", after);
        if(confparse(&config_ast)){
          return RETFAIL;
        }
        conf_lex_delete_buffer();
        eval_config(config_ast, 0);
        deep_free(config_ast);
        config_ast = NULL;
    }
  return RETOK;
}

int conf_input_wrapper(char* buf, int max_size, FILE* in)
{
  int retval=0;

  /* FIXME Add support for gzipped config. :) */
  retval=fread(buf,1,max_size,in);

  return retval;
}

int db_input_wrapper(char* buf, int max_size, database* db)
{
  log_msg(LOG_LEVEL_TRACE,"db_input_wrapper(): parameters: buf=%p, max_size=%d, db=%p)", buf, max_size, db);
  int retval=0;
#ifdef WITH_ZLIB
  int c=0;
#endif

#ifdef WITH_CURL
  switch ((db->url)->type) {
  case url_http:
  case url_https:
  case url_ftp: {
    retval=url_fread(buf,1,max_size,(URL_FILE *)db->fp);
    if (db->mdc) {
        update_md(db->mdc, buf, retval);
    }
    break;
  } 
  default:
#endif /* WITH CURL */

#ifdef WITH_ZLIB
  if (db->gzp!=NULL) {
    c=gzgetc(db->gzp);
    retval= (c==EOF) ? 0 : (buf[0] = c,1);
  }
  if (db->gzp==NULL) {
    c=fgetc(db->fp);
    if(c==(unsigned char)'\037'){
      c=fgetc(db->fp);
      if(c==(unsigned char)'\213'){
    log_msg(LOG_LEVEL_DEBUG,"db_input_wrapper(): handle gzip header");
    lseek(fileno(db->fp),0L,SEEK_SET);
    db->gzp=gzdopen(fileno(db->fp),"rb");
    c=gzgetc(db->gzp);
    log_msg(LOG_LEVEL_DEBUG, "db_input_wrapper(): first character after gzip header is: %c(%#X)\n",c,c);
  if(c==-1) {
    int xx;
      log_msg(LOG_LEVEL_ERROR,"reading gzipped file failed: %s", gzerror(db->gzp,&xx));
    exit(EXIT_FAILURE);
  }
      }else {
       /* False alarm */
       ungetc(c,db->fp);
      }
    }
    retval= (c==EOF) ? 0 : (buf[0] = c,1);
  }

#else /* WITH_ZLIB */
  retval=fread(buf,1,max_size,db->fp);
#endif /* WITH_ZLIB */

  if (db->mdc) {
      update_md(db->mdc, buf, retval);
  }


#ifdef WITH_CURL
  }
#endif /* WITH CURL */
  log_msg(LOG_LEVEL_TRACE,"db_input_wrapper(): return value: %d", retval);
  return retval;
}

void do_define(char* name, char* value, int linenumber, char* filename, char* linebuf)
{
  symba* s=NULL;
  list* l=NULL;

  if(!(l=list_find(name,conf->defsyms))){
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, define '%s' with value '%s', name, value)
    s=(symba*)checked_malloc(sizeof(symba));
    s->name=checked_strdup(name);
    s->value=value;
    conf->defsyms=list_append(conf->defsyms,(void*)s);
  }
  else {
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, redefine '%s' with value '%s' (previous value: '%s'), name, value, ((symba*)l->data)->value)
    free(((symba*)l->data)->value);
    ((symba*)l->data)->value=NULL;
    ((symba*)l->data)->value=value;
  }
}

void do_undefine(char* name, int linenumber, char* filename, char* linebuf)
{
  list*r=NULL;

  if((r=list_find(name,conf->defsyms))){
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, undefine '%s' (value: '%s'), name, ((symba*)r->data)->value)
    free(((symba*)r->data)->name);
    free(((symba*)r->data)->value);
    free((symba*)r->data);
    r->data=NULL;
    conf->defsyms=list_delete_item(r);
  } else {
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, variable '%s' to be undefined not found, name);
  }
}

bool add_rx_rule_to_tree(char* rx, RESTRICTION_TYPE restriction, DB_ATTR_TYPE attr, int type, seltree *tree, int linenumber, char* filename, char* linebuf) {

    rx_rule* r=NULL;

    bool retval = false;

    char *attr_str = NULL;
    char *rs_str = NULL;

    if ((r = add_rx_to_tree(rx, restriction, type, tree, linenumber, filename, linebuf)) == NULL) {
        retval = false;
    }else {
        r->config_linenumber = linenumber;
        r->config_filename = filename;
        r->config_line = checked_strdup(linebuf);

        DB_ATTR_TYPE unsupported_hashes = attr&(get_hashes(true)&~get_hashes(false));
        if (unsupported_hashes) {
            char *str;
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, ignoring unsupported hash algorithm(s): %s, str = diff_attributes(0, unsupported_hashes));
            free(str);
            attr &= ~unsupported_hashes;
        }

        r->attr=attr;
        conf->db_out_attrs |= attr;

        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, add %s '%s%s %s %s' to node '%s', get_rule_type_long_string(type), get_rule_type_char(type), r->rx, rs_str = get_restriction_string(r->restriction), attr_str = diff_attributes(0, r->attr),  (r->node)->path)
        free(rs_str);
        free(attr_str);

        retval = true;
    }
    return retval;
}

DB_ATTR_TYPE do_groupdef(char* group,DB_ATTR_TYPE value)
{
  log_msg(LOG_LEVEL_DEBUG, "define attribute group '%s' with value %llu", group, value);
  list* r=NULL;
  symba* s=NULL;

  if((r=list_find(group,conf->groupsyms))){
      DB_ATTR_TYPE prev_value = ((symba*)r->data)->ival;
      ((symba*)r->data)->ival=value;
      return prev_value;
  }
  /* This is a new group */
  s=checked_malloc(sizeof(symba));
  s->name=checked_strdup(group);
  s->ival=value;
  conf->groupsyms=list_append(conf->groupsyms,(void*)s);
  return 0;
}

DB_ATTR_TYPE get_groupval(char* group)
{
  list* r=NULL;

  if((r=list_find(group,conf->groupsyms))){
    return (((symba*)r->data)->ival);
  }
  return DB_ATTR_UNDEF;
}

bool do_dbdef(DB_TYPE dbtype ,char* val, int linenumber, char* filename, char* linebuf)
{
  url_t* u=NULL;
  database *db = NULL;
  char *db_option_name = NULL;

  switch(dbtype) {
  case DB_TYPE_IN: {
    db_option_name = "database_in";
    db = &(conf->database_in);
    break;
  }
  case DB_TYPE_OUT: {
    db_option_name = "database_out";
    db = &(conf->database_out);
    break;
  }
  case DB_TYPE_NEW: {
    db_option_name = "database_new";
    db = &(conf->database_new);
    break;
  }
  }

  if(db->url == NULL){
    if ((u=parse_url(val, linenumber, filename, linebuf)) != NULL) {
    /* FIXME Check the URL if you add support for databases that cannot be 
     * both input and output urls */
    switch (dbtype) {
    case DB_TYPE_IN:
    case DB_TYPE_NEW:{
      switch (u->type) {
          case url_stdout:
          case url_stderr:
          case url_syslog: {
              LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, '%s': unsupported URL-type: '%s', db_option_name, get_url_type_string(u->type))
              return false;
          }
          case url_stdin:
          case url_ftp:
          case url_http:
          case url_https:
          case url_fd:
          case url_file:
                break;
        }
        break;
    }
    case DB_TYPE_OUT: {
      switch (u->type) {
          case url_stdin:
          case url_stderr:
          case url_syslog: {
              LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, '%s': unsupported URL-type: '%s', db_option_name, get_url_type_string(u->type))
              return false;
          }
          case url_stdout:
          case url_ftp:
          case url_http:
          case url_https:
          case url_fd:
          case url_file:
                break;
        }
        break;
    }
    }
    db->url = u;
    db->linenumber = linenumber;
    db->filename = filename;
    db->linebuf = linebuf?checked_strdup(linebuf):NULL;
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set '%s' option to '%s:%s', db_option_name, get_url_type_string(u->type), u->value)
    } else {
        return false;
    }
  } else {
    LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, '%s' option already set to '%s:%s' (ignore new value '%s'), db_option_name, get_url_type_string((db->url)->type), (db->url)->value, val);
  }
  return true;
}

bool do_repurldef(char* val, int linenumber, char* filename, char* linebuf) {
    url_t* u = parse_url(val, linenumber, filename, linebuf);
    if (add_report_url(u, linenumber, filename, linebuf)) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set 'report_url' to '%s%s%s', get_url_type_string(u->type), u->value?":":"", u->value?u->value:"")
            return true;
    }
    return false;
}

bool do_reportlevel(char* val, int linenumber, char* filename, char* linebuf) {
  REPORT_LEVEL report_level=0;

  report_level = get_report_level(val);
  if (report_level) {
      conf->report_level = report_level;
      LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set 'report_level' option to '%s' (raw: %d), val, report_level)
      return true;
  } else {
      LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, invalid report level: '%s', val);
      return false;
  }
}

void do_rootprefix(char* val, int linenumber, char* filename, char* linebuf) {
    if (conf->root_prefix == NULL) {
        conf->root_prefix=val;
        conf->root_prefix_length=strlen(conf->root_prefix);
        if (conf->root_prefix_length && conf->root_prefix[conf->root_prefix_length-1] == '/') {
            conf->root_prefix[--conf->root_prefix_length] = '\0';
            log_msg(LOG_LEVEL_NOTICE, "%s:%d: removed trailing '/' from root prefix", filename, linenumber);
        }
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_CONFIG, set 'root_prefix' option to '%s', conf->root_prefix)
    } else {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, 'root_prefix' option already set to '%s' (ignore new value '%s'), conf->root_prefix, val);
        free(val);
    }
}

#ifdef WITH_E2FSATTRS
void do_report_ignore_e2fsattrs(char* val, int linenumber, char* filename, char* linebuf) {
    conf->report_ignore_e2fsattrs = 0UL;
    if (strcmp(val, "0") != 0) {
        while (*val) {
            unsigned long flag = e2fsattrs_get_flag(*val);
            if (flag) {
                conf->report_ignore_e2fsattrs |= flag;
            } else {
                 LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, ignore invalid ext2 file attribute: '%c', *val)
            }
            val++;
        }
    }
}
#endif
