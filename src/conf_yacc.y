%{ 

/*	
 * Copyright (C) 1999-2006,2010-2013,2015,2016 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg, Hannes von Haugwitz
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
#include "util.h"
#include "commandconf.h"

DB_ATTR_TYPE retval=0;
extern int conflex();
void conferror(const char*);

extern char *conftext;
extern long conf_lineno;


%}
%union {
  char* s;
  DB_ATTR_TYPE i;
  RESTRICTION_TYPE r;
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
%token TGROUPED
%token TSUMMARIZECHANGES
%token TNEWLINE
%token TVERBOSE
%token TDATABASEADDMETADATA
%token TREPORTDETAILEDINIT
%token TREPORTBASE16
%token TREPORTQUIET
%token TREPORTIGNOREE2FSATTRS
%token TCONFIG_FILE
%token TDATABASE
%token TDATABASE_OUT
%token TDATABASE_NEW
%token TDATABASE_ATTRS
%token TREPORT_URL
%token TGZIPDBOUT
%token TROOT_PREFIX
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
%token <i> TFTYPE
%token <i> TSIZE
%token <i> TGROWINGSIZE
%token <i> TATIME
%token <i> TCTIME
%token <i> TMTIME
%token <i> TACL
%token <i> TXATTRS
%token <i> TSELINUX
%token <i> TE2FSATTRS

/* hash funktions */

%token <i> TTIGER
%token <i> TSHA1
%token <i> TRMD160
%token <i> TMD2
%token <i> TMD4
%token <i> TMD5
%token <i> TSHA256
%token <i> TSHA512
%token <i> TWHIRLPOOL

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

%type  <r> restriction
%type  <i> expr
%type  <i> hash
%type  <i> primary other

%left '+' '-'

%%

lines : lines line | ;

line : rule | equrule | negrule | definestmt | undefstmt
       | ifdefstmt | ifndefstmt | ifhoststmt | ifnhoststmt
       | groupdef | db_in | db_out | db_new | db_attrs | verbose | report_detailed_init | config_version
       | database_add_metadata | report | gzipdbout | root_prefix | report_base16 | report_quiet
       | report_ignore_e2fsattrs | recursion_stopper | warn_dead_symlinks | grouped
       | summarize_changes | acl_no_symlink_follow | beginconfigstmt | endconfigstmt
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
{ decode_string($1); conf->selrxlst=append_rxlist($1,$2,conf->selrxlst, RESTRICTION_NULL); } ;

equrule : TEQURXRULE expr newlineoreof
{ decode_string($1); conf->equrxlst=append_rxlist($1,$2,conf->equrxlst, RESTRICTION_NULL); } ;

negrule : TNEGRXRULE newlineoreof
{ decode_string($1); conf->negrxlst=append_rxlist($1,0,conf->negrxlst, RESTRICTION_NULL); };

rule : TSELRXRULE restriction expr newlineoreof
{ decode_string($1); conf->selrxlst=append_rxlist($1,$3,conf->selrxlst, $2); } ;

equrule : TEQURXRULE restriction expr newlineoreof
{ decode_string($1); conf->equrxlst=append_rxlist($1,$3,conf->equrxlst, $2); } ;

negrule : TNEGRXRULE restriction newlineoreof
{ decode_string($1); conf->negrxlst=append_rxlist($1,0,conf->negrxlst, $2); };

newlineoreof : TNEWLINE |
          TEOF {
            newlinelastinconfig=0;
	    YYACCEPT;
          } ;

restriction : restriction ',' restriction { $$ =$1  | $3 ; }
    | TSTRING {
       if((retval=get_restrictionval($1)) != RESTRICTION_NULL) {
            $$=retval;
       } else {
            conf_lineno++;
            conferror("Error in restriction");
            YYABORT;
       }
    };

expr :  expr '+' expr { $$ =$1  | $3 ; } |
        expr '-' expr { $$ =$1  & (~$3 ); } |
	primary { $$ =$1 ;} ;

primary : hash { $$ =$1 ; } |
	  other { $$ =$1 ; } |
	  TSTRING { if((retval=get_groupval($1)) != DB_ATTR_UNDEF) {
	    $$=retval;
	  }
	  else {
		  conf_lineno++; // Hack
	    conferror("Error in expression");
	    YYABORT;
	  }
	  } ;

other : TRIGHTS { $$ =$1 ;} | TUSER {$$ =$1 ;} 
        | TGROUP {$$ =$1 ;} | TINODE {$$ =$1 ;}
        | TLINKCOUNT {$$ =$1 ;} | TFTYPE {$$ =$1 ;} | TSIZE {$$ =$1 ;}
	| TGROWINGSIZE {$$ =$1 ;} | TATIME {$$ =$1 ;} 
        | TCTIME {$$ =$1 ;} | TMTIME {$$ =$1 ;} | TL {$$ = $1;}
        | TR {$$ = $1;} | TACL {$$ =$1 ;} | TXATTRS {$$ =$1 ;}
        | TSELINUX {$$ =$1 ;} | TE2FSATTRS {$$ =$1 ;};

hash : TTIGER { $$ =$1 ;} | TSHA1 { $$ =$1 ;} | TRMD160 { $$ =$1 ;}
	| TMD5 {$$ =$1 ;} | TSHA256 { $$ =$1 ;} | TSHA512 { $$ =$1 ;}
        | TWHIRLPOOL { $$ =$1 ;};

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
             lines TELSE lines TENDIF {error(220,"Endifelse stmt matched\n");} ;

groupdef : TSTRING '=' expr { do_groupdef($1,$3); } ;

db_in : TDATABASE TSTRING { do_dbdef(DB_OLD,$2); };

db_out : TDATABASE_OUT TSTRING { do_dbdef(DB_WRITE,$2); };

db_new : TDATABASE_NEW TSTRING { do_dbdef(DB_NEW,$2); };

verbose : TVERBOSE TSTRING { do_verbdef($2); };

report : TREPORT_URL TSTRING { do_repurldef($2); } ;

db_attrs : TDATABASE_ATTRS expr {
  DB_ATTR_TYPE attr;
  if((attr = $2&(~DB_HASHES))){
    error(0, "%li: invalid attribute(s) in database_attrs: %llx\n", conf_lineno-1, attr);
    YYABORT;
  }
  conf->db_attrs=$2;
} ;

beginconfigstmt : TBEGIN_CONFIG TSTRING {
#ifdef WITH_MHASH
  conf->do_configmd=1;
  conf->old_confmdstr=strdup($2);
#endif
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

database_add_metadata : TDATABASEADDMETADATA TTRUE {
  conf->database_add_metadata=1;
} ;

database_add_metadata : TDATABASEADDMETADATA TFALSE {
  conf->database_add_metadata=0;
} ;

report_detailed_init : TREPORTDETAILEDINIT TTRUE {
  conf->report_detailed_init=1;
} ;

report_detailed_init : TREPORTDETAILEDINIT TFALSE {
  conf->report_detailed_init=0;
} ;

report_ignore_e2fsattrs : TREPORTIGNOREE2FSATTRS TSTRING {
#ifdef WITH_E2FSATTRS
  do_report_ignore_e2fsattrs($2);
#else
  error(0,"e2fsattrs-support not compiled in.\n");
#endif
} ;

report_base16 : TREPORTBASE16 TTRUE {
  conf->report_base16=1;
} ;

report_base16 : TREPORTBASE16 TFALSE {
  conf->report_base16=0;
} ;

report_quiet : TREPORTQUIET TTRUE {
  conf->report_quiet=1;
} ;

report_quiet : TREPORTQUIET TFALSE {
  conf->report_quiet=0;
} ;

grouped : TGROUPED TTRUE {
  conf->grouped=1;
} ;

root_prefix : TROOT_PREFIX TSTRING { do_rootprefix($2); };

grouped : TGROUPED TFALSE {
  conf->grouped=0;
} ;

summarize_changes : TSUMMARIZECHANGES TTRUE {
  conf->summarize_changes=1;
} ;

summarize_changes : TSUMMARIZECHANGES TFALSE {
  conf->summarize_changes=0;
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
  error(0,"%li:%s:%s\n",conf_lineno-1,msg,conftext);

}

const char* aide_key_1=CONFHMACKEY_01;
const char* db_key_1=DBHMACKEY_01;

