/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2006, 2016, 2020-2023 Rami Lehti, Pablo Virolainen,
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

#include <sys/stat.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "attributes.h"
#include "seltree_struct.h"

#define RESTRICTION_TYPE unsigned int
#define FT_REG   (1U<<0) /* file */
#define FT_DIR   (1U<<1) /* dir */
#define FT_FIFO  (1U<<2) /* fifo */
#define FT_LNK   (1U<<3) /* link */
#define FT_BLK   (1U<<4) /* block device */
#define FT_CHR   (1U<<5) /* char device */
#define FT_SOCK  (1U<<6) /* socket */
#define FT_DOOR  (1U<<7) /* door */
#define FT_PORT  (1U<<8) /* port */
#define FT_NULL  0U

typedef struct rx_rule {
  char* rx; /* Regular expression in text form */
  pcre2_code* crx; /* Compiled regexp */
  pcre2_match_data *md;
  DB_ATTR_TYPE attr; /* Which attributes to save */
  seltree *node;
  char *config_filename;
  int config_linenumber;
  char *config_line;
  char *prefix;
  RESTRICTION_TYPE restriction;
} rx_rule;

RESTRICTION_TYPE get_restriction_from_char(char);
RESTRICTION_TYPE get_restriction_from_perm(mode_t);
char get_file_type_char_from_perm(mode_t);
char get_restriction_char(RESTRICTION_TYPE);

typedef enum {
    AIDE_NEGATIVE_RULE=0,
    AIDE_SELECTIVE_RULE=1,
    AIDE_EQUAL_RULE=2,
} AIDE_RULE_TYPE;

char* get_rule_type_long_string(AIDE_RULE_TYPE);
char* get_rule_type_char(AIDE_RULE_TYPE);

/* memory for the returned string is obtained with malloc(3), and should be freed with free(3). */
char *get_restriction_string(RESTRICTION_TYPE);

#endif /* RX_RULE_H_INCLUDED */
