%{ 

/*	
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti, Pablo Virolainen
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include "list.h"
#include "gen_list.h"
#include "db.h"
#include "db_config.h"
#include "symboltable.h"
#include "commandconf.h"
#include "aide.h"

int retval=0;
extern int conflex();
void conferror(const char*);

extern char* conftext;
extern long conf_lineno;


%}
%union {
  char* s;
  int i;
}


%start lines


%token TDEFINE
%token TUNDEF
%token TIFDEF
%token TIFNDEF
%token TIFNHOST
%token TIFHOST
%token TELSE
%token TENDIF
%token TINCLUDE
%token TBEGIN_CONFIG
%token TEND_CONFIG
%token TBEGIN_DB
%token TEND_DB
%token TEND_DBNOMD
%token TID
%token <s> TSTRING
%token '='

%token TACLNOSYMLINKFOLLOW
%token TWARNDEADSYMLINKS
%token TNEWLINE
%token TVERBOSE
%token TCONFIG_FILE
%token TDATABASE
%token TDATABASE_OUT
%token TDATABASE_NEW
%token TREPORT_URL
%token TGZIPDBOUT
%token TUMASK
%token TTRUE
%token TFALSE

%token TRECSTOP
%token TCONFIG_VERSION

/* File rule */

%token <s> TSELRXRULE
%token <s> TEQURXRULE
%token <s> TNEGRXRULE

/* expr alkiot */

%token <i> TRIGHTS
%token <i> TUSER
%token <i> TGROUP
%token <i> TINODE
%token <i> TLINKCOUNT
%token <i> TSIZE
%token <i> TGROWINGSIZE
%token <i> TATIME
%token <i> TCTIME
%token <i> TMTIME

/* hash funktions */

%token <i> TTIGER
%token <i> TSHA1
%token <i> TRMD160
%token <i> TMD2
%token <i> TMD4
%token <i> TMD5

/* predefs */

%token <i> TL
%token <i> TR

/* For db_lex */
%token TGZIPHEADER
%token TDBSPEC
%token TUNKNOWN
%token TNAME
%token TERROR
%token TEOF

%type  <i> expr
%type  <i> hash
%type  <i> primary other

%left '+' '-'

%%

lines : | line lines;

line : rule | equrule | negrule | definestmt | undefstmt
       | ifdefstmt | ifndefstmt | ifhoststmt | ifnhoststmt
       | groupdef | db_in | db_out | db_new | verbose | config_version 
       | report | gzipdbout | recursion_stopper | warn_dead_symlinks
       | acl_no_symlink_follow | beginconfigstmt | endconfigstmt
       | TEOF {
            newlinelastinconfig=1;
	    YYACCEPT;
          }
       | TNEWLINE 
       | TDBSPEC {
          error(220,"Got @@dbspec.Stopping\n");
	  YYACCEPT;
          }
       | TBEGIN_DB {
	  error(220,"Got @@begin_db. Stopping\n");
	  YYACCEPT;
          }
       | TEND_DB {
	  conferror("Error while reading configuration");
          }
       | error {
	  conferror("Error while reading configuration");
	  YYABORT;
          } ;

rule : TSELRXRULE expr newlineoreof
{ conf->selrxlst=append_rxlist($1,$2,conf->selrxlst); } ;

equrule : TEQURXRULE expr newlineoreof
{ conf->equrxlst=append_rxlist($1,$2,conf->equrxlst); } ;

negrule : TNEGRXRULE newlineoreof
{ conf->negrxlst=append_rxlist($1,0,conf->negrxlst); } |
          TNEGRXRULE expr newlineoreof 
{ conf->negrxlst=append_rxlist($1,0,conf->negrxlst); };

newlineoreof : TNEWLINE |
          TEOF {
            newlinelastinconfig=0;
	    YYACCEPT;
          } ;

expr :  expr '+' expr { $$ =$1  | $3 ; } |
        expr '-' expr { $$ =$1  & (~$3 ); } |
	primary { $$ =$1 ;} ;

primary : hash { $$ =$1 ; } |
	  other { $$ =$1 ; } |
	  TSTRING { if((retval=get_groupval($1))>=0) {
	    $$=retval;
	  }
	  else {
	    conferror("Error in expression");
	    YYABORT;
	  }
	  } ;

other : TRIGHTS { $$ =$1 ;} | TUSER {$$ =$1 ;} 
        | TGROUP {$$ =$1 ;} | TINODE {$$ =$1 ;}
        | TLINKCOUNT {$$ =$1 ;} | TSIZE {$$ =$1 ;} 
	| TGROWINGSIZE {$$ =$1 ;} | TATIME {$$ =$1 ;} 
        | TCTIME {$$ =$1 ;} | TMTIME {$$ =$1 ;} | TL {$$ = $1;}
        | TR {$$ = $1;} ;

hash : TTIGER { $$ =$1 ;} | TSHA1 { $$ =$1 ;} | TRMD160 { $$ =$1 ;}
	| TMD5 {$$ =$1 ;} ;

definestmt : TDEFINE TSTRING TSTRING { do_define($2,$3); };

undefstmt : TUNDEF TSTRING { do_undefine($2); } ;

ifdefstmt : TIFDEF TSTRING { 
  if(do_ifxdef(1,$2)==-1){
    error(0,"ifdef error\n");
    YYABORT; 
  };
 } ifstmtlist ;

ifndefstmt : TIFNDEF TSTRING { 
  if(do_ifxdef(0,$2)==-1){
    error(0,"ifndef error\n");
    YYABORT; 
  };
 } ifstmtlist { error(220,"Ifndef statement ended\n");}  ;

ifhoststmt : TIFHOST TSTRING { 
  if(do_ifxhost(1,$2)==-1){
    error(0,"ifhost error\n");
    YYABORT;
  };
 } ifstmtlist ;

ifnhoststmt : TIFNHOST TSTRING { 
  if(do_ifxhost(0,$2)==-1){
    error(0,"ifnhost error\n");
    YYABORT; 
  };
 } ifstmtlist ;

ifstmtlist : lines TENDIF { error(220,"Endif stmt matched\n");} |
             lines TELSE lines TENDIF {error(220,"Endifelse stmt matched");} ;

groupdef : TSTRING '=' expr { do_groupdef($1,$3); } ;

db_in : TDATABASE TSTRING { do_dbdef(DB_OLD,$2); };

db_out : TDATABASE_OUT TSTRING { do_dbdef(DB_WRITE,$2); };

db_new : TDATABASE_NEW TSTRING { do_dbdef(DB_NEW,$2); };

verbose : TVERBOSE TSTRING { do_verbdef($2); };

report : TREPORT_URL TSTRING { do_repurldef($2); } ;

beginconfigstmt : TBEGIN_CONFIG TSTRING {
  conf->do_configmd=1;
  conf->old_confmdstr=strdup($2);
} ;

endconfigstmt : TEND_CONFIG {
  YYACCEPT;
} ;

acl_no_symlink_follow : TACLNOSYMLINKFOLLOW TTRUE { 
#ifdef WITH_ACL
  conf->no_acl_on_symlinks=1;
#else
  error(0,"ACL-support not compiled in.\n");
#endif
} ;

acl_no_symlink_follow : TACLNOSYMLINKFOLLOW TFALSE { 
#ifdef WITH_ACL
  conf->no_acl_on_symlinks=0;
#else
  error(0,"ACL-support not compiled in.\n");
#endif
} ;

warn_dead_symlinks : TWARNDEADSYMLINKS TTRUE {
  conf->warn_dead_symlinks=1;
} ;

warn_dead_symlinks : TWARNDEADSYMLINKS TFALSE {
  conf->warn_dead_symlinks=0;
} ;

gzipdbout : TGZIPDBOUT TTRUE { 
#ifdef WITH_ZLIB
conf->gzip_dbout=1; 
#else 
 error(0,"Gzip-support not compiled in.\n");
#endif
} |
            TGZIPDBOUT TFALSE { 
#ifdef WITH_ZLIB
conf->gzip_dbout=0; 
#endif
} ;

recursion_stopper : TRECSTOP TSTRING {
  /* FIXME implement me */  
  
} ;

config_version : TCONFIG_VERSION TSTRING {
  conf->config_version=strdup($2);
} ;

%%


void conferror(const char *msg){
  error(0,"%i:%s:%s\n",conf_lineno,msg,conftext);

}

const char* aide_key_1=CONFHMACKEY_01;
const char* db_key_1=DBHMACKEY_01;

