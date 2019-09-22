/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2015,2016,2019 Hannes von Haugwitz
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "attributes.h"

static const char* attrs_string[] = { "filename", "l", "p", "u", "g", "s", "a", "c", "m", "i", "b", "n",
                               "md5", "sha1", "rmd160", "tiger", "crc32", "haval", "gost", "crc32b",
                               "attr", "acl", "bsize", "rdev", "dev", "checkmask", "S", "I", "ANF",
                               "ARF", "sha256", "sha512", "selinux", "xattrs", "whirlpool", "ftype",
                               "e2fsattrs", "caps" };

char* report_attrs(DB_ATTR_TYPE attrs) {
    char* str;
    int j = 1;
    int num_attrs = sizeof(attrs_string)/sizeof(char*);
    for (int i = 0; i < num_attrs; ++i) {
        if ((1LLU<<i)&attrs) {
            j += strlen(attrs_string[i])+1;
        }
    }
    str = malloc(j * sizeof (char));
    j=0;
    for (int i = 0; i < num_attrs; ++i) {
        if ((1LLU<<i)&attrs) {
            if (j) { str[j++] = '+'; }
            j += sprintf(&str[j], "%s", attrs_string[i]);
        }
    }
    str[j] = '\0';
    return str;
}
