SC	[\\'"netbgr\ @#]
C	[a-zA-Z0-9ˆ‰¸ﬂÂ÷ƒ‹≈_\\=$%£@&/!\^\~;:.,\?\{\}\(\)\[\]\<\>\-\+\*\|\'\`]

E	[\ ]*"="[\ ]*

L	[a-zA-Zˆ‰¸ﬂÂ÷ƒ‹≈0-9_%]
D	[0-9]

PC	\\[^\n]

EX      [" "\t]*

%{

#define YYDEBUG 1

/*
 * Copyright (C) 1999-2002,2004-2006,2010-2013,2015,2016 Rami Lehti, Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
 * $Header$
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
#include <string.h>
#include "gen_list.h"
#include "conf_yacc.h"
#include "list.h"
#include "symboltable.h"
#include "commandconf.h"

void includehandler(void) ;
void conf_put_token(const char*);

int firstnotempty(char* s);

typedef struct conf_buffer_type {
  char* buff;
  char* pos;
} conf_buffer_type;

list* l_symt=NULL;
list* conf_buffer=NULL;
int condition=0;
int varbol=0;

long conf_lineno=1;
int newlinelastinconfig=0;

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr = 0;

#define YY_INPUT(buf,result,max_size) \
        if( ((result=conf_input_wrapper(buf,max_size,yyin)) == 0) \
            && ferror(yyin) ) \
          YY_FATAL_ERROR( "input in flex scanner failed" );

int var_in_conflval=0;

%}

%Start A EXPR DEFSTMT DEFSTMT2 IFDEFSTMT INCLUDE EXPREQUHUNT VARSUB CONFVALHUNT IFHOSTSTMT E2FSATTRS

%%

"#"[^\n]* {
 }


^[^\n]*"\@\@\{"({L}+)"}"[^\n]* {
  
  putbackvariable(conftext);

  error(230,"%li:Variable substitution\n",conf_lineno+1);
  
}



^[\ \t]*"=/"({C}|{PC})* {
  conflval.s=strdup(conftext+1+firstnotempty(conftext));
  BEGIN(EXPR);
  return (TEQURXRULE);
}

^[\ \t]*"/"({C}|{PC})* {
  conflval.s=strdup(conftext+firstnotempty(conftext));
  error(230,"%li:Selrule\n",conf_lineno);
  BEGIN(EXPR);
  return (TSELRXRULE );
}

^[\ \t]*"!/"({C}|{PC})* {  
  conflval.s=strdup(conftext+1+firstnotempty(conftext));
  error(230,"%li:Negrule\n",conf_lineno);
  return (TNEGRXRULE );
}

^[\ \t]*({L})+ {
  conflval.s=strdup(conftext+firstnotempty(conftext));
  error(230,"%li:Equrule\n",conf_lineno);
  BEGIN(EXPREQUHUNT);
  return (TSTRING);
}

<EXPREQUHUNT>[\ \t]*"="[\ \t]* {
  BEGIN(EXPR);
  return('=');
}

<EXPR>, {
  return (',');
}

<EXPR>[\ \t]*({L}|{D}|">")+ {
  conflval.s=strdup(conftext+firstnotempty(conftext));
  return (TSTRING);
}

<EXPR>[\ \t]*\n {
  conf_lineno++;
  return (TNEWLINE);
  BEGIN 0;
}

<EXPR>\+ {
  return ('+');
}

<EXPR>\- {
  return ('-');
}

<DEFSTMT>({L})+ {
  error(230," %s",conftext);
  conflval.s=strdup(conftext);
  BEGIN (DEFSTMT2);
  return (TSTRING);
}

<DEFSTMT2>({C})+ {
  error(230," %s",conftext);
  conflval.s=strdup(conftext);
  return (TSTRING);
}

<DEFSTMT2>[\ \t]*"\n" { 
  error(230,"\n");
  conf_lineno++;
  BEGIN 0;
  return (TNEWLINE);
}

^[\ \t]*"\@\@define" {
  error(230,"%li:@@define",conf_lineno);
  BEGIN DEFSTMT;
  return (TDEFINE);
}

^[\ \t]*"\@\@undef" {
  error(230,"%li:@@undef",conf_lineno);
  BEGIN IFDEFSTMT;
  return (TUNDEF);
}


^[\ \t]*"\@\@ifndef" {
  error(230,"%li:@@ifndef",conf_lineno);
  BEGIN IFDEFSTMT;
  return (TIFNDEF);
}

^[\ \t]*"\@\@ifdef" {
  error(230,"%li:@@ifdef",conf_lineno);
  BEGIN IFDEFSTMT;
  return (TIFDEF);
}

^[\ \t]*"\@\@else" {
  error(230,"%li:@@else\n",conf_lineno);
  BEGIN 0;
  return (TELSE);
}

^[\ \t]*"\@\@endif" {
  error(230,"%li:@@endif\n",conf_lineno);
  BEGIN 0;
  return (TENDIF);
}

^"\@\@begin_db" {
  error(230,"%li:@@begin_db",conf_lineno);
  BEGIN 0;
  return (TBEGIN_DB);
}

<IFDEFSTMT>({L})+ {
  error(230," %s\n",conftext);
  conflval.s=strdup(conftext);
  BEGIN 0;
  return (TSTRING);
}

^[\ \t]*"\@\@ifhost" {
  error(230,"%li:@@ifhost",conf_lineno);
  BEGIN IFHOSTSTMT;
  return (TIFHOST);
}

^[\ \t]*"\@\@ifnhost" {
  error(230,"%li:@@ifnhost",conf_lineno);
  BEGIN IFHOSTSTMT;
  return (TIFNHOST);
}

<IFHOSTSTMT>({L}|"-")+ {
  error(230," %s\n",conftext);
  conflval.s=strdup(conftext);
  BEGIN 0;
  return (TSTRING);
}

^[\ \t]*"\@\@db_spec" {
  conf_put_token("\n@@db_spec");
  error(230,"%li:@@db_spec",conf_lineno);
  return (TDBSPEC);
}

^[\ \t]*"\@\@begin_config" {
  error(230,"%li:@@begin_config",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TBEGIN_CONFIG);
}

^[\ \t]*"\@\@end_config" {
  return (TEND_CONFIG);
}

^[\ \t]*"\@\@include" {
  BEGIN INCLUDE;
}

<INCLUDE>[^ \t\n]+ {
  includehandler();
  BEGIN 0;
  error(230,"%li:@@include\n",conf_lineno);
  return (TNEWLINE);
}

<<EOF>> {
        if (yy_hold_char=='\n'){
            newlinelastinconfig=1;
        }else {
            newlinelastinconfig=0;
        }
        if ( --include_stack_ptr < 0 )
            {
            yyterminate();
            }

        else
            {

            if (confin != stdin ) {
              fclose(confin);
              }

            conf_delete_buffer( YY_CURRENT_BUFFER );
            conf_switch_to_buffer(
                 include_stack[include_stack_ptr] );
            }
}


[\t\ ]+ {}

"\n" { 
  conf_lineno++;
  BEGIN 0;
  return (TNEWLINE);
 }

^[\t\ ]*"database"{E} {
  error(230,"%li:database =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TDATABASE);
} 

^[\t\ ]*"database_out"{E}  {
  error(230,"%li:database_out =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TDATABASE_OUT);
}

^[\t\ ]*"database_new"{E}  {
  error(230,"%li:database_new =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TDATABASE_NEW);
}

^[\t\ ]*"database_attrs"{E} {
  error(230,"%li:database_attrs =\n",conf_lineno);
  BEGIN EXPR;
  return (TDATABASE_ATTRS);
}

^[\t\ ]*"warn_dead_symlinks"{E} {
  error(230,"%li:warn_dead_symlinks =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TWARNDEADSYMLINKS);
}

^[\t\ ]*"grouped"{E} {
  error(230,"%li:grouped =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TGROUPED);
}

^[\t\ ]*"summarize_changes"{E} {
  error(230,"%li:summarize_changes =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TSUMMARIZECHANGES);
}

^[\t\ ]*"acl_no_symlink_follow"{E} {
  error(230,"%li:acl_no_symlink_follow =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TACLNOSYMLINKFOLLOW);
}


^[\t\ ]*"verbose"{E} {
  error(230,"%li:verbose =\n",conf_lineno);
  return (TVERBOSE);  
}

^[\t\ ]*"database_add_metadata"{E} {
  error(230,"%li:database_add_metadata =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TDATABASEADDMETADATA);
}

^[\t\ ]*"report_url"{E} {
  error(230,"%li:report_url =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TREPORT_URL);  
}

^[\t\ ]*"report_detailed_init"{E} {
  error(230,"%li:report_detailed_init =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TREPORTDETAILEDINIT);
}

^[\t\ ]*"report_base16"{E} {
  error(230,"%li:report_base16 =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TREPORTBASE16);
}

^[\t\ ]*"report_quiet"{E} {
  error(230,"%li:report_quiet =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TREPORTQUIET);
}

^[\t\ ]*"report_ignore_e2fsattrs"{E} {
  error(230,"%li:report_ignore_e2fsattrs =\n",conf_lineno);
  BEGIN E2FSATTRS;
  return (TREPORTIGNOREE2FSATTRS);
}

<E2FSATTRS>([A-Za-z]+|"0") {
  conflval.s=strdup(conftext);
  BEGIN 0;
  return (TSTRING);
}

^[\t\ ]*"gzip_dbout"{E} {
  error(230,"%li:gzip_dbout =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TGZIPDBOUT);
}

^[\t\ ]*"root_prefix"{E}  {
  error(230,"%li:root_prefix =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TROOT_PREFIX);
}

^[\t\ ]*"recstop"{E} {
  error(230,"%li:recstop =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TRECSTOP);
}

^[\ \t]*"config_version"{E} {
  error(230,"%li:config_version =\n",conf_lineno);
  BEGIN CONFVALHUNT;
  return (TCONFIG_VERSION);
}

<CONFVALHUNT>("yes"|"true") {
  BEGIN 0;
  return (TTRUE);
}

<CONFVALHUNT>("no"|"false") {
  BEGIN 0;
  return (TFALSE);
}

<CONFVALHUNT>({C})+ {
  conflval.s=strdup(conftext);
  BEGIN 0;
  return (TSTRING);
}


({L})+ {
  conflval.s=strdup(conftext);
  return (TSTRING);
}


[^\n] { return(conftext[0]); }


%%

int confwrap(void){
  return 1;
}

void conf_put_token(const char* s){

  int i=0;

  for(i=strlen(s)-1;i>=0;i--){
       unput(s[i]);
       if(s[i]=='\n'){
          conf_lineno--;
       }
  }
  
}

int firstnotempty(char* s){
  
  int i=0;

  if (s==NULL) {
    return i;
  }


  while( s[i]==' ' || s[i]=='\t') {
    i++;
  }

  return i;

}

const char* aide_key_4=CONFHMACKEY_04;
const char* db_key_4=DBHMACKEY_04;

void includehandler(void) { 
  /* got the include file name */
  if ( include_stack_ptr >= MAX_INCLUDE_DEPTH )
    {
      error( 0, "Config includes nested too deeply\n" );
      exit( 1 );
    }

  if (strcmp(conftext,"-")==0) {
      confin = stdin;
    } else {
      confin = fopen( conftext, "r" );
    }
  if ( ! confin ) {
    error(0,"Cannot open config file %s\n",conftext);
    exit(IO_ERROR);
  } else {
    include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;
    conf_switch_to_buffer(conf_create_buffer( confin, YY_BUF_SIZE ) );
  }
  
}

