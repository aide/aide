/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2016, 2020-2022,2024,2025 Hannes von Haugwitz
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
#include <stdio.h>

#include "file.h"
#include "rx_rule.h"
#include "util.h"

static int generate_restriction_string(rx_restriction_t r, char *str) {
    int n = 0;
    if (r.f_type == FT_NULL
#ifdef HAVE_FSTYPE
        && r.fs_type == 0
#endif
            ) {
        const char *no_restriction_string = "(none)";
        size_t length = strlen(no_restriction_string);
        if (str) { sprintf(&str[n], "%s", no_restriction_string); }
        n = length+1;
    } else {
        FT_TYPE f_types = r.f_type;
        unsigned int i = 0;
        while (f_types) {
            FT_TYPE t = (1U<<i);
            if (f_types&t) {
                if (n) {
                    if (str) { str[n] = ','; }
                    n++;
                }
                if (str) { str[n] = get_f_type_char_from_f_type(t); }
                n++;
            }
            i++;
            f_types &= ~t;
        }
#ifdef HAVE_FSTYPE
        if (r.fs_type != 0) {
            if (str) { str[n] = '='; }
            n++;
            size_t length = generate_fs_type_string(r.fs_type, NULL);
            if (str) { generate_fs_type_string(r.fs_type, &str[n]); }
            n += length;
        }
#endif
        if (str) { str[n] = '\0'; }
        n++;
    }
    return n;
}

char *get_restriction_string(rx_restriction_t r) {
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

char *get_match_result_desc(match_result match) {
    switch(match) {
        case RESULT_NO_RULE_MATCH:
            return "no rule match";
        case RESULT_RECURSIVE_NEGATIVE_MATCH:
            return "recursive negative match";
        case RESULT_NON_RECURSIVE_NEGATIVE_MATCH:
            return "non-recursive negative match";
        case RESULT_EQUAL_MATCH:
            return "equal match";
        case RESULT_SELECTIVE_MATCH:
            return "selective match";
        case RESULT_PARTIAL_MATCH:
            return "partial match";
        case RESULT_NO_LIMIT_MATCH:
            return "no limit match";
        case RESULT_PARTIAL_LIMIT_MATCH:
            return "partial limit match";
        case RESULT_PART_LIMIT_AND_NO_RECURSE_MATCH:
            return "partial limit match but non-recursive negative match";
        case RESULT_NEGATIVE_PARENT_MATCH:
            return "negative parent match";
    }
    return "unknown match result";
}
