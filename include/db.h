/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2005, 2013, 2016, 2020, 2022 Rami Lehti,
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

#ifndef _DB_H_INCLUDED
#define _DB_H_INCLUDED

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "db_config.h"
#include "util.h"

typedef enum {
    DB_TYPE_IN,
    DB_TYPE_OUT,
    DB_TYPE_NEW,
} DB_TYPE;

byte* base64tobyte(char*, int, size_t *);
time_t base64totime_t(char*, database*, const char*);

int db_init(database*, bool, bool);

db_line* db_readline(database*);

int db_writespec(db_config*);

int db_writeline(db_line*,db_config*);

void db_close();

void free_db_line(db_line* dl);

#define DB_OLD            (1<<0)
#define DB_WRITE          (1<<1)
#define DB_NEW            (1<<2)
#define NODE_ADDED        (1<<4)
#define NODE_REMOVED      (1<<5)
#define NODE_CHANGED      (1<<6)
#define NODE_FREE         (1<<7)
#define DB_DISK           (1<<8)

#define NODE_MOVED_OUT    (1<<11)
#define NODE_MOVED_IN     (1<<12)
#define NODE_ALLOW_NEW    (1<<13)
#define NODE_ALLOW_RM	  (1<<14)

#endif
