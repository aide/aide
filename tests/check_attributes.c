/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2019-2020 Hannes von Haugwitz
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
    /* { 0, ATTR(attr_filename), "filename" }, */
    { 0, ATTR(attr_linkname), "l" },
    { 0, ATTR(attr_perm), "p" },
    { 0, ATTR(attr_uid), "u" },
    { 0, ATTR(attr_gid), "g" },
    { 0, ATTR(attr_size), "s" },
    { 0, ATTR(attr_atime), "a" },
    { 0, ATTR(attr_ctime), "c" },
    { 0, ATTR(attr_mtime), "m" },
    { 0, ATTR(attr_inode), "i" },
    { 0, ATTR(attr_bcount), "b" },
    { 0, ATTR(attr_linkcount), "n" },
    { 0, ATTR(attr_md5), "md5" },
    { 0, ATTR(attr_sha1), "sha1" },
    { 0, ATTR(attr_rmd160), "rmd160" },
    { 0, ATTR(attr_tiger), "tiger" },
    { 0, ATTR(attr_crc32), "crc32" },
    { 0, ATTR(attr_haval), "haval" },
    { 0, ATTR(attr_gostr3411_94), "gost" },
    { 0, ATTR(attr_crc32b), "crc32b" },
    /* { 0, ATTR(attr_attr), "attr" }, */
    { 0, ATTR(attr_acl), "acl" },
    /* { 0, ATTR(attr_bsize), "bsize" }, */
    /* { 0, ATTR(attr_rdev), "rdev" }, */
    /* { 0, ATTR(attr_dev), "dev" }, */
    /* { 0, ATTR(attr_allhashsums), "H" }, */
    { 0, ATTR(attr_sizeg), "S" },
    { 0, ATTR(attr_checkinode), "I" },
    { 0, ATTR(attr_allownewfile) , "ANF" },
    { 0, ATTR(attr_allowrmfile), "ARF" },
    { 0, ATTR(attr_sha256), "sha256" },
    { 0, ATTR(attr_sha512), "sha512" },
    { 0, ATTR(attr_selinux), "selinux" },
    { 0, ATTR(attr_xattrs), "xattrs" },
    { 0, ATTR(attr_whirlpool), "whirlpool" },
    { 0, ATTR(attr_ftype), "ftype" },
    { 0, ATTR(attr_e2fsattrs), "e2fsattrs" },
    { 0, ATTR(attr_capabilities), "caps" },

    { 0, ATTR(attr_linkname)|ATTR(attr_perm), "l+p" },
    { 0, ATTR(attr_ctime)|ATTR(attr_ftype), "c+ftype" },
    { 0, ATTR(attr_linkname)|ATTR(attr_perm)|ATTR(attr_uid)|ATTR(attr_gid)|ATTR(attr_size)|ATTR(attr_bcount)|ATTR(attr_linkcount)|ATTR(attr_sha256)|ATTR(attr_tiger)|ATTR(attr_haval)|ATTR(attr_sha512)|ATTR(attr_ftype), "l+p+u+g+s+b+n+tiger+haval+sha256+sha512+ftype" },

    { ATTR(attr_linkname), 0 , "-l" },
    { ATTR(attr_linkname), ATTR(attr_linkname) , "" },
    { ATTR(attr_linkname), ATTR(attr_linkname)|ATTR(attr_perm) , "+p" },
    { ATTR(attr_linkname)|ATTR(attr_perm), ATTR(attr_linkname) , "-p" },
    { ATTR(attr_perm)|ATTR(attr_mtime), ATTR(attr_perm)|ATTR(attr_uid)|ATTR(attr_gid)|ATTR(attr_size)|ATTR(attr_bcount)|ATTR(attr_linkcount), "+u+g+s-m+b+n" },
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
