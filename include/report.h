/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2010,2020 Rami Lehti, Pablo Virolainen,
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

#ifndef _REPORT_H_INCLUDED
#define _REPORT_H_INCLUDED
#include "list.h"
#include "log.h"
#include "url.h"
#include "seltree.h"

/* report level */
typedef enum { /* preserve order */
    REPORT_LEVEL_MINIMAL = 1,
    REPORT_LEVEL_SUMMARY = 2,
    REPORT_LEVEL_DATABASE_ATTRIBUTES = 3,
    REPORT_LEVEL_LIST_ENTRIES = 4,
    REPORT_LEVEL_CHANGED_ATTRIBUTES = 5,
    REPORT_LEVEL_ADDED_REMOVED_ATTRIBUTES = 6,
    REPORT_LEVEL_ADDED_REMOVED_ENTRIES = 7,
} REPORT_LEVEL;

bool add_report_url(url_t* url, int, char*, char*);

REPORT_LEVEL get_report_level(char *);

void log_report_urls(LOG_LEVEL);

/*
 * gen_report()
 * Generate report based on the given node
 */
int gen_report(seltree* node);

#endif
