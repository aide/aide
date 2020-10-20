/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002,2006,2016,2020 Rami Lehti,Pablo Virolainen, Richard
 * van den Berg, Hannes von Haugwitz
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

#ifndef _RX_RULE_H_INCLUDED
#define  _RX_RULE_H_INCLUDED

#include "attributes.h"
#include "seltree_struct.h"
#include <sys/stat.h>
#include <pcre.h>

#define RESTRICTION_TYPE unsigned int
#define RESTRICTION_FT_REG   (1U<<0) /* file */
#define RESTRICTION_FT_DIR   (1U<<1) /* dir */
#define RESTRICTION_FT_FIFO  (1U<<2) /* fifo */
#define RESTRICTION_FT_LNK   (1U<<3) /* link */
#define RESTRICTION_FT_BLK   (1U<<4) /* block device */
#define RESTRICTION_FT_CHR   (1U<<5) /* char device */
#define RESTRICTION_FT_SOCK  (1U<<6) /* socket */
#define RESTRICTION_FT_DOOR  (1U<<7) /* door */
#define RESTRICTION_FT_PORT  (1U<<8) /* port */
#define RESTRICTION_NULL 0U

typedef struct rx_rule {
  char* rx; /* Regular expression in text form */
  pcre* crx; /* Compiled regexp */
  DB_ATTR_TYPE attr; /* Which attributes to save */
  seltree *node;
  RESTRICTION_TYPE restriction;
} rx_rule;

RESTRICTION_TYPE get_restrictionval(char*);

RESTRICTION_TYPE get_file_type(mode_t mode);
#endif /* RX_RULE_H_INCLUDED */
