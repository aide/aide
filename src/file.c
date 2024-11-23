/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2016,2020,2021,2024 Hannes von Haugwitz
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

#include "config.h"
#include "file.h"

#include <limits.h>

typedef struct {
    char c;
    FT_TYPE r;
    mode_t ft;
} f_type_t;

static f_type_t filetypes[] = {
    { 'f', FT_REG, S_IFREG },
    { 'd', FT_DIR, S_IFDIR },
#ifdef S_IFIFO
    { 'p', FT_FIFO, S_IFIFO },
#endif
    { 'l', FT_LNK, S_IFLNK },
    { 'b', FT_BLK, S_IFBLK },
    { 'c', FT_CHR, S_IFCHR },
#ifdef S_IFSOCK
    { 's', FT_SOCK, S_IFSOCK },
#endif
#ifdef S_IFDOOR
    { 'D', FT_DOOR, S_IFDOOR },
#endif
#ifdef S_IFPORT
    { 'P', FT_PORT, S_IFPORT },
#endif
};

static int num_filetypes = sizeof(filetypes)/sizeof(f_type_t);

char get_f_type_char_from_f_type(FT_TYPE r) {
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (r == filetypes[i].r) {
            return filetypes[i].c;
        }
    }
    return '?';
}

char get_f_type_char_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (ft == filetypes[i].ft) {
            return filetypes[i].c;
        }
    }
    return '?';
}

FT_TYPE get_f_type_from_char(char c) {
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (c == filetypes[i].c) {
            return filetypes[i].r;
        }
    }
    return FT_NULL;
}

FT_TYPE get_f_type_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (ft == filetypes[i].ft) {
            return filetypes[i].r;
        }
    }
    return FT_NULL;
}
