/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2019 Hannes von Haugwitz
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

#include <check.h>
#include <stdlib.h>

#include "attributes.h"

typedef struct {
    DB_ATTR_TYPE a;
    DB_ATTR_TYPE b;
    const char *expected_string;
} diff_attributes_t;

static diff_attributes_t diff_attributes_tests[] = {
    { 0, 0, "" },
    { 0, DB_FILENAME, "filename" },
    { 0, DB_LINKNAME, "l" },
    { 0, DB_PERM, "p" },
    { 0, DB_UID, "u" },
    { 0, DB_GID, "g" },
    { 0, DB_SIZE, "s" },
    { 0, DB_ATIME, "a" },
    { 0, DB_CTIME, "c" },
    { 0, DB_MTIME, "m" },
    { 0, DB_INODE, "i" },
    { 0, DB_BCOUNT, "b" },
    { 0, DB_LNKCOUNT, "n" },
    { 0, DB_MD5, "md5" },
    { 0, DB_SHA1, "sha1" },
    { 0, DB_RMD160, "rmd160" },
    { 0, DB_TIGER, "tiger" },
    { 0, DB_CRC32, "crc32" },
    { 0, DB_HAVAL, "haval" },
    { 0, DB_GOST, "gost" },
    { 0, DB_CRC32B, "crc32b" },
    { 0, DB_ATTR, "attr" },
    { 0, DB_ACL, "acl" },
    { 0, DB_BSIZE, "bsize" },
    { 0, DB_RDEV, "rdev" },
    { 0, DB_DEV, "dev" },
    { 0, DB_CHECKMASK, "checkmask" },
    { 0, DB_SIZEG, "S" },
    { 0, DB_CHECKINODE, "I" },
    { 0, DB_NEWFILE , "ANF" },
    { 0, DB_RMFILE, "ARF" },
    { 0, DB_SHA256, "sha256" },
    { 0, DB_SHA512, "sha512" },
    { 0, DB_SELINUX, "selinux" },
    { 0, DB_XATTRS, "xattrs" },
    { 0, DB_WHIRLPOOL, "whirlpool" },
    { 0, DB_FTYPE, "ftype" },
    { 0, DB_E2FSATTRS, "e2fsattrs" },
    { 0, DB_CAPABILITIES, "caps" },

    { 0, DB_LINKNAME|DB_PERM, "l+p" },
    { 0, DB_CTIME|DB_FTYPE, "c+ftype" },
    { 0, DB_LINKNAME|DB_PERM|DB_UID|DB_GID|DB_SIZE|DB_BCOUNT|DB_LNKCOUNT|DB_SHA256|DB_TIGER|DB_HAVAL|DB_SHA512|DB_FTYPE, "l+p+u+g+s+b+n+tiger+haval+sha256+sha512+ftype" },

    { DB_LINKNAME, 0 , "-l" },
    { DB_LINKNAME, DB_LINKNAME , "" },
    { DB_LINKNAME, DB_LINKNAME|DB_PERM , "+p" },
    { DB_LINKNAME|DB_PERM, DB_LINKNAME , "-p" },
    { DB_PERM|DB_MTIME, DB_PERM|DB_UID|DB_GID|DB_SIZE|DB_BCOUNT|DB_LNKCOUNT, "+u+g+s-m+b+n" },
};

static int num_diff_attributes_tests = sizeof diff_attributes_tests / sizeof(diff_attributes_t);

START_TEST (test_diff_attributes) {
    char *str = diff_attributes(diff_attributes_tests[_i].a, diff_attributes_tests[_i].b);
    ck_assert_msg(strcmp(diff_attributes_tests[_i].expected_string, str) == 0, "diff_attributes: %llu %llu: string returned '%s' != '%s'", diff_attributes_tests[_i].a, diff_attributes_tests[_i].b, str, diff_attributes_tests[_i].expected_string);
    free(str);
}
END_TEST

Suite *make_attributes_suite(void) {

    Suite *s = suite_create ("attributes");

    TCase *tc_diff_attributes = tcase_create ("diff_attributes");

    tcase_add_loop_test (tc_diff_attributes, test_diff_attributes, 0, num_diff_attributes_tests);

    suite_add_tcase (s, tc_diff_attributes);

    return s;
}
