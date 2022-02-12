/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2015,2016,2019-2022 Hannes von Haugwitz
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

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "util.h"

#include "attributes.h"

attributes_t attributes[] = {
    { ATTR(attr_filename),       NULL,           NULL,          "name",         '\0'  },
    { ATTR(attr_linkname),       "l",            "Lname",       "lname",        'l'   },
    { ATTR(attr_perm),           "p",            "Perm",        "perm",         'p'   },
    { ATTR(attr_uid),            "u",            "Uid",         "uid",          'u'   },
    { ATTR(attr_gid),            "g",            "Gid",         "gid",          'g'   },
    { ATTR(attr_size),           "s",            "Size",        "size",         '>'   },
    { ATTR(attr_atime),          "a",            "Atime",       "atime",        'a'   },
    { ATTR(attr_ctime),          "c",            "Ctime",       "ctime",        'c'   },
    { ATTR(attr_mtime),          "m",            "Mtime" ,      "mtime",        'm'   },
    { ATTR(attr_inode),          "i",            "Inode",       "inode",        'i'   },
    { ATTR(attr_bcount),         "b",            "Bcount",      "bcount",       'b'   },
    { ATTR(attr_linkcount),      "n",            "Linkcount",   "lcount",       'n'   },
    { ATTR(attr_md5),            "md5",          "MD5",         "md5",          '\0'  },
    { ATTR(attr_sha1),           "sha1",         "SHA1",        "sha1",         '\0'  },
    { ATTR(attr_rmd160),         "rmd160",       "RMD160",      "rmd160",       '\0'  },
    { ATTR(attr_tiger),          "tiger",        "TIGER",       "tiger",        '\0'  },
    { ATTR(attr_crc32),          "crc32",        "CRC32",       "crc32",        '\0'  },
    { ATTR(attr_haval),          "haval",        "HAVAL",       "haval",        '\0'  },
    { ATTR(attr_gostr3411_94),   "gost",         "GOST",        "gost",         '\0'  },
    { ATTR(attr_crc32b),         "crc32b",       "CRC32B",      "crc32b",       '\0'  },
    { ATTR(attr_attr),           NULL,           NULL ,         "attr",         '\0'  },
    { ATTR(attr_acl),            "acl",          "ACL",         "acl",          'A'   },
    { ATTR(attr_bsize),          NULL,           NULL,          NULL,           '\0'  },
    { ATTR(attr_rdev),           NULL,           NULL ,         NULL,           '\0'  },
    { ATTR(attr_dev),            NULL,           NULL ,         NULL,           '\0'  },
    { ATTR(attr_allhashsums),    NULL,           NULL,          NULL,           'H'   }, /* "H" is also default compound group for all compiled in hashsums */
    { ATTR(attr_sizeg),          "S",            "Size (>)",    NULL,           '\0'  },
    { ATTR(attr_checkinode),     "I",            NULL,          NULL,           '\0'  },
    { ATTR(attr_allownewfile),   "ANF",          NULL,          NULL,           '\0'  },
    { ATTR(attr_allowrmfile),    "ARF",          NULL,          NULL,           '\0'  },
    { ATTR(attr_sha256),         "sha256",       "SHA256",      "sha256",       '\0'  },
    { ATTR(attr_sha512),         "sha512",       "SHA512",      "sha512",       '\0'  },
    { ATTR(attr_selinux),        "selinux",      "SELinux",     "selinux",      'S'   },
    { ATTR(attr_xattrs),         "xattrs",       "XAttrs",      "xattrs",       'X'   },
    { ATTR(attr_whirlpool),      "whirlpool",    "WHIRLPOOL",   "whirlpool",    '\0'  },
    { ATTR(attr_ftype),          "ftype",        "File type",   NULL,           '!'   },
    { ATTR(attr_e2fsattrs),      "e2fsattrs",    "E2FSAttrs",   "e2fsattrs",    'E'   },
    { ATTR(attr_capabilities),   "caps",         "Caps",        "capabilities", 'C'   },
    { ATTR(attr_stribog256),     "stribog256",   "STRIBOG256" ,  "stribog256",  '\0'  },
    { ATTR(attr_stribog512),     "stribog512",   "STRIBOG512" ,  "stribog512",  '\0'  },
};

DB_ATTR_TYPE num_attrs = sizeof(attributes)/sizeof(attributes_t);

static int get_diff_attrs_string(DB_ATTR_TYPE a, DB_ATTR_TYPE b, char *str, bool db) {
    int n = 0;
    for (ATTRIBUTE i = 0; i < num_attrs; ++i) {
        if (db?attributes[i].db_name:attributes[i].config_name) {
            if (((1LLU<<i)&a) ^ ((1LLU<<i)&b)) {
                if (n || a != 0) {
                    if (str) { str[n] = ((1LLU<<i)&b)?'+':'-'; }
                    n++;
                }
                if (str) { sprintf(&str[n], "%s", db?attributes[i].db_name:attributes[i].config_name); }
                n += strlen(db?attributes[i].db_name:attributes[i].config_name);
            }
        }
    }
    if (str) { str[n] = '\0'; }
    n++;
    return n;
}

char *diff_attributes(DB_ATTR_TYPE a, DB_ATTR_TYPE b) {
    char *str = NULL;
    int n = get_diff_attrs_string(a, b, str, false);
    str = checked_malloc(n);
    get_diff_attrs_string(a, b, str, false);
    return str;
}

char *diff_database_attributes(DB_ATTR_TYPE a, DB_ATTR_TYPE b) {
    char *str = NULL;
    int n = get_diff_attrs_string(a, b, str, true);
    str = checked_malloc(n);
    get_diff_attrs_string(a, b, str, true);
    return str;
}
