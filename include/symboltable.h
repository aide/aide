/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006 Rami Lehti,Pablo Virolainen, Richard van
 * den Berg
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

#ifndef _SYMBOLTABLE_H_INCLUDED
#define _SYMBOLTABLE_H_INCLUDED

#include "list.h"

typedef struct symba {
  char* name;
  char* value;
  DB_ATTR_TYPE ival;

} symba;


list* list_find(char* s,list* item);

#endif

