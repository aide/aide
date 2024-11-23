/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2016, 2020-2024 Rami Lehti, Pablo Virolainen,
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

#ifndef _RX_RULE_H_INCLUDED
#define  _RX_RULE_H_INCLUDED

#include "config.h"
#include "file.h"
#include <sys/stat.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "attributes.h"

typedef struct rx_restriction_t {
   FT_TYPE f_type;
} rx_restriction_t;

typedef enum {
    AIDE_RECURSIVE_NEGATIVE_RULE=0,
    AIDE_NON_RECURSIVE_NEGATIVE_RULE=1,
    AIDE_SELECTIVE_RULE=2,
    AIDE_EQUAL_RULE=3,
} AIDE_RULE_TYPE;

typedef struct rx_rule {
  char* rx; /* Regular expression in text form */
  pcre2_code* crx; /* Compiled regexp */
  pcre2_match_data *md;
  AIDE_RULE_TYPE type;
  DB_ATTR_TYPE attr; /* Which attributes to save */
  char *config_filename;
  int config_linenumber;
  char *config_line;
  char *prefix;
  rx_restriction_t restriction;
} rx_rule;

typedef enum match_result {
    RESULT_NO_RULE_MATCH                   =     0,
    RESULT_RECURSIVE_NEGATIVE_MATCH        = (1<<0),
    RESULT_NON_RECURSIVE_NEGATIVE_MATCH    = (1<<1),
    RESULT_SELECTIVE_MATCH                 = (1<<2),
    RESULT_EQUAL_MATCH                     = (1<<3),
    RESULT_PARTIAL_MATCH                   = (1<<4),
    RESULT_NO_LIMIT_MATCH                  = (1<<5),
    RESULT_PARTIAL_LIMIT_MATCH             = (1<<6),
    RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH = (1<<7),
    RESULT_NEGATIVE_PARENT_MATCH           = (1<<8),
} match_result;

typedef struct match_t {
    match_result result;
    rx_rule* rule;
    int length;
} match_t;

char* get_rule_type_long_string(AIDE_RULE_TYPE);
char* get_rule_type_char(AIDE_RULE_TYPE);

/* memory for the returned string is obtained with malloc(3), and should be freed with free(3). */
char *get_restriction_string(rx_restriction_t);

char *get_match_result_string(match_result);
#endif /* RX_RULE_H_INCLUDED */
