/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2016,2020 Hannes von Haugwitz
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

#include <string.h>

#include "rx_rule.h"

static const char restriction_char[] = { 'f', 'd', 'p', 'l', 'b', 'c', 's', 'D', 'P'};

static int num_restrictions = sizeof(restriction_char)/sizeof(char);

RESTRICTION_TYPE get_file_type(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return RESTRICTION_FT_REG;
        case S_IFDIR: return RESTRICTION_FT_DIR;
#ifdef S_IFIFO
        case S_IFIFO: return RESTRICTION_FT_FIFO;
#endif
        case S_IFLNK: return RESTRICTION_FT_LNK;
        case S_IFBLK: return RESTRICTION_FT_BLK;
        case S_IFCHR: return RESTRICTION_FT_CHR;
#ifdef S_IFSOCK
        case S_IFSOCK: return RESTRICTION_FT_SOCK;
#endif
#ifdef S_IFDOOR
        case S_IFDOOR: return RESTRICTION_FT_DOOR;
#endif
#ifdef S_IFDOOR
        case S_IFPORT: return RESTRICTION_FT_PORT;
#endif
        default: return RESTRICTION_NULL;
    }
}

RESTRICTION_TYPE get_restrictionval(char* ch) {
    if (strcmp(ch, "f") == 0) { return RESTRICTION_FT_REG; }
    else if (strcmp(ch, "d") == 0) { return RESTRICTION_FT_DIR; }
    else if (strcmp(ch, "p") == 0) { return RESTRICTION_FT_FIFO; }
    else if (strcmp(ch, "l") == 0) { return RESTRICTION_FT_LNK; }
    else if (strcmp(ch, "b") == 0) { return RESTRICTION_FT_BLK; }
    else if (strcmp(ch, "c") == 0) { return RESTRICTION_FT_CHR; }
    else if (strcmp(ch, "s") == 0) { return RESTRICTION_FT_SOCK; }
    else if (strcmp(ch, "D") == 0) { return RESTRICTION_FT_DOOR; }
    else if (strcmp(ch, "P") == 0) { return RESTRICTION_FT_PORT; }
    else { return RESTRICTION_NULL; }
}

static int generate_restriction_string(RESTRICTION_TYPE rs, char *str) {
    int n = 0;
    if (rs == RESTRICTION_NULL) {
        char *no_restriction_string = "(none)";
        size_t length = strlen(no_restriction_string);
        if (str) { strncpy(str, no_restriction_string, length+1); }
        n = length + 1;
    } else {
        for (int i = 0; i < num_restrictions; ++i) {
            if ((1LLU<<i)&rs) {
                if (n) {
                    if (str) { str[n] = ','; }
                    n++;
                }
                if (str) { str[n] = restriction_char[i]; }
                n ++;
            }
        }
        if (str) { str[n] = '\0'; }
        n++;
    }
    return n;
}

char *get_restriction_string(RESTRICTION_TYPE rs) {
    char *str = NULL;
    int n = generate_restriction_string(rs, str);
    str = malloc(n);
    generate_restriction_string(rs, str);
    return str;
}

char* get_rule_type_long_string(AIDE_RULE_TYPE rule_type) {
    switch (rule_type) {
        case AIDE_SELECTIVE_RULE: return "selective rule";
        case AIDE_EQUAL_RULE: return "equal rule";
        case AIDE_NEGATIVE_RULE: return "negative rule";
    }
    return NULL;
}

char* get_rule_type_char(AIDE_RULE_TYPE rule_type) {
    switch (rule_type) {
        case AIDE_SELECTIVE_RULE: return "";
        case AIDE_EQUAL_RULE: return "=";
        case AIDE_NEGATIVE_RULE: return "!";
    }
    return NULL;
}
