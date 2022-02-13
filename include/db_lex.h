/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2020-2022 Rami Lehti, Pablo Virolainen,
 *               Richard van den Berg, Hannes von Haugwitz
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

#ifndef _DB_LEX_H_INCLUDED_
#define _DB_LEX_H_INCLUDED_

#include "db_config.h"

extern char* dbtext;

void db_lex_buffer(database*);
void db_lex_delete_buffer(database*);
int db_scan(void);

typedef enum {
    TBEGIN_DB = 1,
    TEND_DB,
    TSTRING,
    TDBSPEC,
    TUNKNOWN,
    TNEWLINE,
    TEOF,
} DB_TOKEN;

#define LOG_DB_FORMAT_LINE(log_level, format, ...) \
    log_msg(log_level, "%s:%s:%li: " format , get_url_type_string((db->url)->type), (db->url)->value, db->lineno, __VA_ARGS__);

#endif
