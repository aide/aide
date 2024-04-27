/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2024 Hannes von Haugwitz
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
#include <string.h>

#include "base64.h"

typedef struct {
    char* orig;
    char* base64;
} base64_t;

static base64_t base64_tests[] = {
    { "A", "QQ==" },
    { "AA", "QUE=" },
    { "AAA", "QUFB" },
    { "AAAA", "QUFBQQ==" },
    { "AAAAA", "QUFBQUE=" },
    { "AAAAAA", "QUFBQUFB" },
    { "AAAAAAA", "QUFBQUFBQQ==" },
    { "AAAAAAA", "QUFBQUFBQQ==" },
};

static int num_base64_tests = sizeof base64_tests / sizeof(base64_t);

START_TEST (test_base64) {
    size_t orig_length = strlen(base64_tests[_i].orig);
    char *base64 = encode_base64((byte *) base64_tests[_i].orig, orig_length);
    ck_assert_msg(strcmp(base64_tests[_i].base64, base64) == 0, "\n"
            "encode_base64('%s', %zu ):\n"
            "string returned '%s'\n"
            "       expected '%s'",
            base64_tests[_i].orig, orig_length, base64, base64_tests[_i].base64);

    size_t orig_length_pointer;
    size_t base64_length = strlen(base64);
    byte *orig = decode_base64(base64, base64_length, &orig_length_pointer);
    ck_assert_msg(strcmp(base64_tests[_i].orig, (char *) orig) == 0, "\n"
            "padded decode_base64('%s', %zu ):\n"
            "string returned '%s'\n"
            "       expected '%s'",
            base64, base64_length, orig, base64_tests[_i].orig);

    ck_assert_msg(orig_length_pointer == orig_length, "padded decode_base64(' %s', %zu) returned length %zu (expected: %zu)", base64, base64_length, orig_length_pointer, orig_length);

    free(orig);
    free(base64);
}
END_TEST

Suite *make_base64_suite(void) {

    Suite *s = suite_create ("base64");

    TCase *tc_base64 = tcase_create ("base64");

    tcase_add_loop_test (tc_base64, test_base64, 0, num_base64_tests);

    suite_add_tcase (s, tc_base64);

    return s;
}
