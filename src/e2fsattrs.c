/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2010, 2012, 2015-2016, 2020-2021 Hannes von Haugwitz
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

#include "e2fsattrs.h"
#include "util.h"

typedef struct {
    unsigned long f;
    char c;
} e2fsattrs_t;

/* flag->character mappings taken from lib/e2p/pf.c (git commit 32fda1e)
 * date: 2021-04-24
 * sources: git://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git
 */
static e2fsattrs_t e2fsattrs_flags[] = {
    { EXT2_SECRM_FL, 's' },
    { EXT2_UNRM_FL, 'u' },
    { EXT2_SYNC_FL, 'S' },
    { EXT2_DIRSYNC_FL, 'D' },
    { EXT2_IMMUTABLE_FL, 'i' },
    { EXT2_APPEND_FL, 'a' },
    { EXT2_NODUMP_FL, 'd' },
    { EXT2_NOATIME_FL, 'A' },
    { EXT2_COMPR_FL, 'c' },
    { EXT4_ENCRYPT_FL, 'E' },
    { EXT3_JOURNAL_DATA_FL, 'j' },
    { EXT2_INDEX_FL, 'I' },
    { EXT2_NOTAIL_FL, 't' },
    { EXT2_TOPDIR_FL, 'T' },
#ifdef EXT4_EXTENTS_FL
    { EXT4_EXTENTS_FL, 'e' },
#endif
#ifdef FS_NOCOW_FL
    { FS_NOCOW_FL, 'C' },
#endif
#ifdef FS_DAX_FL
    { FS_DAX_FL, 'x' },
#endif
#ifdef EXT4_CASEFOLD_FL
    { EXT4_CASEFOLD_FL, 'F' },
#endif
#ifdef EXT4_INLINE_DATA_FL
    { EXT4_INLINE_DATA_FL, 'N' },
#endif
#ifdef EXT4_PROJINHERIT_FL
    { EXT4_PROJINHERIT_FL, 'P' },
#endif
#ifdef EXT4_VERITY_FL
    { EXT4_VERITY_FL, 'V' },
#endif
#ifdef EXT2_NOCOMPR_FL
    { EXT2_NOCOMPR_FL, 'm' },
#endif
};

unsigned long num_flags = sizeof(e2fsattrs_flags)/sizeof(e2fsattrs_t);

unsigned long e2fsattrs_get_flag(char c) {
    for (unsigned long i = 0 ; i < num_flags ; ++i) {
        if (e2fsattrs_flags[i].c == c ) {
            return e2fsattrs_flags[i].f;
        }
    }
    return 0;
}

char* get_e2fsattrs_string(unsigned long flags, bool flags_only, unsigned long ignore_e2fsattrs) {
    char* string = checked_malloc ((num_flags+1) * sizeof (char));
    int j = 0;
    for (unsigned long i = 0 ; i < num_flags ; i++) {
        if (!flags_only && e2fsattrs_flags[i].f&ignore_e2fsattrs) {
            string[j++]=':';
        } else if (e2fsattrs_flags[i].f & flags) {
            string[j++]=e2fsattrs_flags[i].c;
        } else if (!flags_only) {
            string[j++]='-';
        }
    }
    string[j] = '\0';
    return string;
}
