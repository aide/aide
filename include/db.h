/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti, Pablo Virolainen
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

#ifndef _DB_H_INCLUDED
#define _DB_H_INCLUDED

#include <stdio.h>
#include "db_config.h"

int db_init(int);

db_line* db_readline(int);

int db_writespec(db_config*);

int db_writeline(db_line*,db_config*);

int db_close(db_config*);

void free_db_line(db_line* dl);

extern const char* db_names[];
extern const int db_value[];

#define DB_OLD            (1<<0)
#define DB_WRITE          (1<<1)
#define DB_NEW            (1<<2)
#define NODE_ADDED        (1<<4)
#define NODE_REMOVED      (1<<5)
#define NODE_CHANGED      (1<<6)
#define NODE_ADD_CHILDREN (1<<7)
#define DB_DISK           (1<<8)

#define NODE_TRAVERSE     (1<<9)
#define NODE_CHECKED      (1<<10)


#endif
