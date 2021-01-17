/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2020 Hannes von Haugwitz
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

#ifndef _HASHSUM_H_INCLUDED
#define _HASHSUM_H_INCLUDED

#include "attributes.h"
#include <stdbool.h>

typedef struct {
    ATTRIBUTE attribute;
    int length;
} hashsum_t;

typedef enum {
    hash_md5=0,
    hash_sha1,
    hash_sha256,
    hash_sha512,
    hash_rmd160,
    hash_tiger,
    hash_crc32,
    hash_crc32b,
    hash_haval,
    hash_whirlpool,
    hash_gostr3411_94,
    hash_stribog256,
    hash_stribog512,
    num_hashes,
} HASHSUM;

extern hashsum_t hashsums[];

extern int algorithms[];

DB_ATTR_TYPE get_hashes(bool);

#endif /* _HASHSUM_H_INCLUDED */
