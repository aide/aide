C	[^\n\t ]

%{

/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2002,2005,2010,2013,2016,2019-2021 Rami Lehti,Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
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
#include <string.h>
#include "log.h"
#include "commandconf.h"
#include "db_lex.h"

#include "db.h"

database* db;

LOG_LEVEL db_lex_log_level = LOG_LEVEL_DEBUG;

#define LOG_AND_RETURN(token) \
    LOG_DB_FORMAT_LINE(db_lex_log_level, db_lex: %s: '%s', #token, dbtext) \
    return (token);

#define YY_INPUT(buf,result,max_size) \
        if( ((result=db_input_wrapper(buf, max_size, db)) == 0) \
            && ferror(dbin) ) \
          YY_FATAL_ERROR( "input in flex scanner failed" );

%}

%option noinput
%option nounput

%x DB

%%
<INITIAL>"#"[^\n]*"\n" {
            (db->lineno)++;
            LOG_DB_FORMAT_LINE(db_lex_log_level, db_lex: skip comment line: '%.*s', strlen(dbtext)-1, dbtext)
           }
<INITIAL>^"\n" {
            (db->lineno)++;
            LOG_DB_FORMAT_LINE(db_lex_log_level, %s, "db_lex: skip empty line")
           }
<INITIAL>^[^\n]*"\n" {
            (db->lineno)++;
            LOG_DB_FORMAT_LINE(db_lex_log_level, db_lex: parse '%.*s', strlen(dbtext)-1, dbtext)
            yyless(0);
            BEGIN(DB);
           }

<DB>^"@@db_spec" {
    LOG_AND_RETURN(TDBSPEC)
}

<DB>^"@@begin_db" {
    LOG_AND_RETURN(TBEGIN_DB)
}


<DB>^"@@end_db" {
    LOG_AND_RETURN(TEND_DB)
}

<DB>^"@@"({C}+) {
    LOG_AND_RETURN(TUNKNOWN)
}

<DB>"#"[^\n]* { /* inline comment */
    LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, db_lex: skip inline comment: '%s', dbtext)
}

<DB>^"/"({C})* {
    LOG_AND_RETURN(TPATH)
}

<DB>({C})+ {
    LOG_AND_RETURN(TSTRING)
}

<DB>[ \t] {
    LOG_DB_FORMAT_LINE(LOG_LEVEL_TRACE, db_lex: skip tab/whitespace: '%s', dbtext)
}

<DB>"\n" {
  LOG_DB_FORMAT_LINE(db_lex_log_level, db_lex: TNEWLINE: '\n', NULL)
  BEGIN 0;
  return (TNEWLINE);
}

<*><<EOF>> {
    LOG_DB_FORMAT_LINE(db_lex_log_level, db_lex: TEOF: '<<EOF>>', NULL)
    return (TEOF);
}

<*>. {
    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, skip unexpected character: '%c', *dbtext)
}

%%

int dbwrap(){
  return 1;
}

void db_lex_buffer(database* _database)
{
  db = _database;

  if (db->fp != NULL) {
    db->buffer_state = db_create_buffer(db->fp, YY_BUF_SIZE );
  }
  db_switch_to_buffer(db->buffer_state);
}

void db_lex_delete_buffer(database* _database) {
    db_delete_buffer(_database->buffer_state );
}
