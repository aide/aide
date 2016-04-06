C	[%!$&\'\(\)\*\+,\-./0-9;=?A-Za-z_]
L	[a-zA-Zˆ‰Â÷ƒ≈0-9_]

%{

/*
C	[a-zA-Z0-9ˆ‰Â÷ƒ≈\\\*=$%£&/!\^\~;:.,\?\{\}\(\)\[\]\<\>\-\+\*\|\'\`]
*/
/*
"\ "\\*=$%£&/!\^~;:.,?\{\}\(\)\[\]\<\>-+*\|\'\`]
typedef union {
	char* s;
	}  YYSTYPE;
extern YYSTYPE yylval;


"/"({C}|{PC})+ {
  return (TNAME);
}

*/

/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2005,2010,2013,2016 Rami Lehti,Pablo Virolainen,
 * Richard van den Berg, Hannes von Haugwitz
 * $Header$
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#define YY_DECL int db_scan(void)


#define YYDEBUG 1

#include "aide.h"
#include "gen_list.h"
#include "conf_yacc.h"
#include <string.h>
#include "report.h"
#include "commandconf.h"

/* We need to define these here since we cannot include db.h*/
#define DB_OLD       (1<<0)
#define DB_WRITE     (1<<1)
#define DB_NEW       (1<<2)
#define NODE_ADDED   (1<<4)
#define NODE_REMOVED (1<<5)
#define NODE_CHANGED (1<<6)

long db_in_lineno=1;
long db_new_lineno=1;
long* db_lineno=&db_in_lineno;
YY_BUFFER_STATE db_stack[2];

int db_at_hand=0;

#define YY_INPUT(buf,result,max_size) \
        if( ((result=db_input_wrapper(buf,max_size,db_at_hand)) == 0) \
            && ferror(yyin) ) \
          YY_FATAL_ERROR( "input in flex scanner failed" );



%}

%option nounput

%Start MDVALHUNT

%%

^"\037\213" {
  return (TGZIPHEADER);
}

"@@db_spec" {
  return (TDBSPEC);
}

^"@@begin_db" {
  return (TBEGIN_DB);
}

^"@@end_db " {
  BEGIN MDVALHUNT;
  return (TEND_DB);
}

<MDVALHUNT>({C})+ {
  BEGIN 0;
  return (TSTRING);
}

^"@@end_db" {
  return (TEND_DBNOMD);
}

"@@"({L}+) {
  return (TUNKNOWN);
}

"#"[^\n]*"\n" {
  (*db_lineno)++;
}

({C})+ {

 error(230," %s \n",yytext);

 return (TID);
}

[" "\t] {}

"\n" {
 (*db_lineno)++;
 return (TNEWLINE);
}

[^\n] {
 return (TERROR);
}

<<EOF>> {
	return (TEOF);
	}
	

%%

int dbwrap(){
  return 1;
}

void db_buff(int db, FILE* f)
{
  int stack_pointer=0;

  switch(db) {
  case DB_OLD: {
    stack_pointer=0;
    db_at_hand=DB_OLD;
    break;
  }
  case DB_NEW: {
    stack_pointer=1;
    db_at_hand=DB_NEW;
    break;
  }    
  }
  
  if(f!=NULL){
    db_stack[stack_pointer]=yy_create_buffer( f, YY_BUF_SIZE );
  }  
  yy_switch_to_buffer(db_stack[stack_pointer]);

}
