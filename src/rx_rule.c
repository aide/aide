/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2016, 2020-2022,2024 Hannes von Haugwitz
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

#include <string.h>
#include <sys/stat.h>

#include "rx_rule.h"
#include "util.h"

typedef struct {
    char c;
    RESTRICTION_TYPE r;
    mode_t ft;
} restriction_t;

static restriction_t rs[] = {
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

static int num_restrictions = sizeof(rs)/sizeof(restriction_t);

RESTRICTION_TYPE get_restriction_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_restrictions; ++i) {
        if (ft == rs[i].ft) {
            return rs[i].r;
        }
    }
    return FT_NULL;
}

char get_file_type_char_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_restrictions; ++i) {
        if (ft == rs[i].ft) {
            return rs[i].c;
        }
    }
    return '?';
}

RESTRICTION_TYPE get_restriction_from_char(char c) {
    for (int i = 0 ; i < num_restrictions; ++i) {
        if (c == rs[i].c) {
            return rs[i].r;
        }
    }
    return FT_NULL;
}

char get_restriction_char(RESTRICTION_TYPE r) {
    for (int i = 0 ; i < num_restrictions; ++i) {
        if (r == rs[i].r) {
            return rs[i].c;
        }
    }
    return '?';
}

static int generate_restriction_string(RESTRICTION_TYPE r, char *str) {
    int n = 0;
    if (r == FT_NULL) {
        char *no_restriction_string = "(none)";
        size_t length = strlen(no_restriction_string);
        if (str) { strncpy(str, no_restriction_string, length+1); }
        n = length + 1;
    } else {
        for (int i = 0; i < num_restrictions; ++i) {
            if (rs[i].r&r) {
                if (n) {
                    if (str) { str[n] = ','; }
                    n++;
                }
                if (str) { str[n] = rs[i].c; }
                n ++;
            }
        }
        if (str) { str[n] = '\0'; }
        n++;
    }
    return n;
}

char *get_restriction_string(RESTRICTION_TYPE r) {
    char *str = NULL;
    int n = generate_restriction_string(r, str);
    str = checked_malloc(n);
    generate_restriction_string(r, str);
    return str;
}

char* get_rule_type_long_string(AIDE_RULE_TYPE rule_type) {
    switch (rule_type) {
        case AIDE_SELECTIVE_RULE: return "selective rule";
        case AIDE_EQUAL_RULE: return "equal rule";
        case AIDE_RECURSIVE_NEGATIVE_RULE: return "recursive negative rule";
        case AIDE_NON_RECURSIVE_NEGATIVE_RULE: return "non-recursive negative rule";
    }
    return NULL;
}

char* get_rule_type_char(AIDE_RULE_TYPE rule_type) {
    switch (rule_type) {
        case AIDE_SELECTIVE_RULE: return "";
        case AIDE_EQUAL_RULE: return "=";
        case AIDE_RECURSIVE_NEGATIVE_RULE: return "!";
        case AIDE_NON_RECURSIVE_NEGATIVE_RULE: return "-";
    }
    return NULL;
}

char *get_match_result_string(match_result match) {
    switch(match) {
        case RESULT_NO_RULE_MATCH:
            return "RESULT_NO_RULE_MATCH";
        case RESULT_RECURSIVE_NEGATIVE_MATCH:
            return "RESULT_RECURSIVE_NEGATIVE_MATCH";
        case RESULT_NON_RECURSIVE_NEGATIVE_MATCH:
            return "RESULT_NON_RECURSIVE_NEGATIVE_MATCH";
        case RESULT_EQUAL_MATCH:
            return "RESULT_EQUAL_MATCH";
        case RESULT_SELECTIVE_MATCH:
            return "RESULT_SELECTIVE_MATCH";
        case RESULT_PARTIAL_MATCH:
            return "RESULT_PARTIAL_MATCH";
        case RESULT_NO_LIMIT_MATCH:
            return "RESULT_NO_LIMIT_MATCH";
        case RESULT_PARTIAL_LIMIT_MATCH:
            return "RESULT_PARTIAL_LIMIT_MATCH";
        case RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH:
            return "RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH";
        case RESULT_NEGATIVE_PARENT_MATCH:
            return "RESULT_NEGATIVE_PARENT_MATCH";
    }
    return "unknown match result";
}
