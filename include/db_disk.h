/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2011, 2021-2025 Rami Lehti, Pablo Virolainen,
 *               Hannes von Haugwitz
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

#ifndef _DB_DISK_H_INCLUDED
#define _DB_DISK_H_INCLUDED

#include "attributes.h"
#include "config.h"
#ifdef HAVE_FSTYPE
#include "file.h"
#endif
#include <sys/stat.h>
#include <stdbool.h>

typedef struct disk_entry {
    char *filename;
    struct stat fs;
#ifdef HAVE_FSTYPE
    FS_TYPE fs_type;
#endif
    int fd;
    DB_ATTR_TYPE attrs;
} disk_entry;

void db_scan_disk(bool);
#endif
