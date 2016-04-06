/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006,2010,2016 Rami Lehti,Pablo Virolainen,
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

#ifndef _GEN_LIST_H_INCLUDED
#define _GEN_LIST_H_INCLUDED
#include <pcre.h>
#include "seltree.h"
#include "list.h"

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

/* DB_FOO are anded together to form rx_rule's attr */

typedef struct rx_rule {
  char* rx; /* Regular expression in text form */
  pcre* crx; /* Compiled regexp */
  DB_ATTR_TYPE attr; /* Which attributes to save */
  long  conf_lineno; /* line no. of rule definition*/
  RESTRICTION_TYPE restriction;
} rx_rule;

int compare_node_by_path(const void *n1, const void *n2);

/* 
 * gen_tree()
 * Generates the file tree
 * from rx_rule's
 */
seltree* gen_tree(list* prxlist,list* nrxlist,list* erxlist);

/* 
 * populate_tree()
 * Populate tree with data from disk and db 
 * Also do comparing while adding to the tree
 */
void populate_tree(seltree* tree);

/*
 * strrxtok()
 * return a pointer to a copy of the non-regexp path part of the argument
 */

char* strrxtok(char*);

int check_rxtree(char* filename,seltree* tree, DB_ATTR_TYPE* attr, mode_t perm);

db_line* get_file_attrs(char* filename,DB_ATTR_TYPE attr, struct AIDE_STAT_TYPE *fs);

seltree* get_seltree_node(seltree* tree,char* path);

#endif /*_GEN_LIST_H_INCLUDED*/
