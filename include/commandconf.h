/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2011,2015,2016 Rami Lehti, Pablo Virolainen,
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

#ifndef _COMMANDCONF_H_INCLUDED
#define _COMMANDCONF_H_INCLUDED
#include "list.h"
#include "gen_list.h"
#include "db_config.h"

extern long conf_lineno;
extern int newlinelastinconfig;

int commandconf(const char mode,const char* line);

int conf_input_wrapper(char* buf, int max_size, FILE* in);
int db_input_wrapper(char* buf, int max_size, int db);

list* append_rxlist(char*,DB_ATTR_TYPE,list*, RESTRICTION_TYPE);

void do_define(char*,char*);

void do_undefine(char*);

int do_ifxdef(int,char*);

int do_ifxhost(int,char*);

void do_groupdef(char*,DB_ATTR_TYPE);

RESTRICTION_TYPE get_restrictionval(char*);

DB_ATTR_TYPE get_groupval(char*);

void putbackvariable(char*);

int handle_endif(int doit,int allow_else);

void do_dbdef(int, char*);

void do_verbdef(char*);

void do_replevdef(char*);

void do_repurldef(char*);

void do_rootprefix(char*);

void do_report_ignore_e2fsattrs(char*);

int check_db_order(DB_FIELD*,int, DB_FIELD);

void* get_db_key(void);
void* get_conf_key(void);
size_t get_db_key_len(void);
size_t get_conf_key_len(void);



extern const char* aide_key_1;
extern const char* aide_key_2;
extern const char* aide_key_3;
extern const char* aide_key_4;
extern const char* aide_key_5;
extern const char* aide_key_6;
extern const char* aide_key_7;
extern const char* aide_key_8;
extern const char* aide_key_9;
extern const char* aide_key_0;

extern const char* db_key_1;
extern const char* db_key_2;
extern const char* db_key_3;
extern const char* db_key_4;
extern const char* db_key_5;
extern const char* db_key_6;
extern const char* db_key_7;
extern const char* db_key_8;
extern const char* db_key_9;
extern const char* db_key_0;


#endif
