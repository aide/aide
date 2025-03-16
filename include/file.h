/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2016,2020,2021,2024,2025 Hannes von Haugwitz
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

#ifndef _FILE_H_INCLUDED
#define _FILE_H_INCLUDED

#include "config.h"
#include <sys/stat.h>
#include <limits.h>

#define FT_TYPE unsigned int
#define FT_NULL  0U

#define FT_REG   (1U<<0) /* file */
#define FT_DIR   (1U<<1) /* dir */
#define FT_FIFO  (1U<<2) /* fifo */
#define FT_LNK   (1U<<3) /* link */
#define FT_BLK   (1U<<4) /* block device */
#define FT_CHR   (1U<<5) /* char device */
#define FT_SOCK  (1U<<6) /* socket */
#define FT_DOOR  (1U<<7) /* door */
#define FT_PORT  (1U<<8) /* port */

char get_f_type_char_from_f_type(FT_TYPE);
char *get_f_type_string_from_f_type(FT_TYPE);
char get_f_type_char_from_perm(mode_t);
char *get_f_type_string_from_perm(mode_t);
FT_TYPE get_f_type_from_char(char);
FT_TYPE get_f_type_from_perm(mode_t);

#ifdef HAVE_FSTYPE
#define FS_TYPE unsigned long

typedef struct {
    char *str;
    unsigned int magic;
} filesystem_t;

FS_TYPE get_fs_type_from_string(const char *);
int generate_fs_type_string(FS_TYPE, char*);
char * get_fs_type_string_from_magic(FS_TYPE);

extern filesystem_t filesystems[];
extern int num_filesystems;
#endif

typedef struct file_t {
    char* name;
    FT_TYPE type;
#ifdef HAVE_FSTYPE
    FS_TYPE fs_type;
#endif
} file_t;

#endif
