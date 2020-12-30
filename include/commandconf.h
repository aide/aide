/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2011,2015,2016,2020 Rami Lehti, Pablo Virolainen,
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
#include "rx_rule.h"
#include "list.h"
#include <stdio.h>
#include <stdbool.h>
#include "db_config.h"
#include "db.h"

int parse_config(char *, char *, char *);

int conf_input_wrapper(char* buf, int max_size, FILE* in);
int db_input_wrapper(char*, int, database*);

bool add_rx_rule_to_tree(char*, RESTRICTION_TYPE, DB_ATTR_TYPE, int, seltree*, int, char*, char*);

void do_define(char*,char*, int, char*, char*);

void do_undefine(char*, int, char*, char*);

DB_ATTR_TYPE do_groupdef(char*,DB_ATTR_TYPE);

DB_ATTR_TYPE get_groupval(char*);

bool do_dbdef(DB_TYPE, char*, int, char*, char*);

bool do_reportlevel(char *, int, char*, char*);

void do_replevdef(char*);

bool do_repurldef(char*, int, char*, char*);

void do_rootprefix(char*, int, char*, char*);

void do_report_ignore_e2fsattrs(char*, int, char*, char*);
#endif
