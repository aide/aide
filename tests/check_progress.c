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

#include "util.h"

typedef struct {
    char * path;
    long unsigned entries;
    long unsigned skipped;
    int length;
    const char *expected_string;
} progress_test_t;

static progress_test_t progress_tests[] = {
    { NULL, 0, 0, 50, "[00:01] scan file system> 0 files" },
    { NULL, 0, 0, 40, "[00:01] scan file system> 0 files" },
    { NULL, 0, 0, 33, "[00:01] scan file system> 0 files" },
    { NULL, 0, 0, 30, "[00:01] scan file system> 0 fi" },
    { NULL, 0, 0, 20, "[00:01] scan file sy" },
    { NULL, 0, 0, 10, "[00:01] sc" },
    { NULL, 0, 0,  5, "[00:0" },
    { NULL, 0, 0,  1, "[" },

    { NULL, 0, 1230, 60, "[00:01] scan file system> 0 files (1230 skipped)" },
    { NULL, 0, 1230, 50, "[00:01] scan file system> 0 files (1230 skipped)" },
    { NULL, 0, 1230, 48, "[00:01] scan file system> 0 files (1230 skipped)" },
    { NULL, 0, 1230, 40, "[00:01] scan file system> 0 files (1230 " },
    { NULL, 0, 1230, 30, "[00:01] scan file system> 0 fi" },
    { NULL, 0, 1230, 20, "[00:01] scan file sy" },
    { NULL, 0, 1230, 10, "[00:01] sc" },
    { NULL, 0, 1230,  5, "[00:0" },
    { NULL, 0, 1230,  1, "[" },

    { "/etc/fstab", 1, 0, 60, "[00:01] scan file system> 1 file, last /etc/fstab" },
    { "/etc/fstab", 1, 0, 50, "[00:01] scan file system> 1 file, last /etc/fstab" },
    { "/etc/fstab", 1, 0, 49, "[00:01] scan file system> 1 file, last /etc/fstab" },
    { "/etc/fstab", 1, 0, 43, "[00:01] scan file system> 1 file, last /etc" },
    { "/etc/fstab", 1, 0, 40, "[00:01] scan file system> 1 file, last /" },
    { "/etc/fstab", 1, 0, 30, "[00:01] scan file system> 1 fi" },
    { "/etc/fstab", 1, 0, 20, "[00:01] scan file sy" },
    { "/etc/fstab", 1, 0, 10, "[00:01] sc" },
    { "/etc/fstab", 1, 0,  5, "[00:0" },
    { "/etc/fstab", 1, 0,  1, "[" },

    { "/", 3100, 12310, 70, "[00:01] scan file system> 3100 files (12310 skipped), last /" },
    { "/", 3100, 12310, 60, "[00:01] scan file system> 3100 files (12310 skipped), last /" },
    { "/", 3100, 12310, 50, "[00:01] scan file system> 3100 files (12310 skippe" },
    { "/", 3100, 12310, 40, "[00:01] scan file system> 3100 files (12" },
    { "/", 3100, 12310, 30, "[00:01] scan file system> 3100" },
    { "/", 3100, 12310, 20, "[00:01] scan file sy" },
    { "/", 3100, 12310, 10, "[00:01] sc" },
    { "/", 3100, 12310,  5, "[00:0" },
    { "/", 3100, 12310,  1, "[" },

    { "/system", 3100, 12310, 80, "[00:01] scan file system> 3100 files (12310 skipped), last /system" },
    { "/system", 3100, 12310, 70, "[00:01] scan file system> 3100 files (12310 skipped), last /system" },
    { "/system", 3100, 12310, 66, "[00:01] scan file system> 3100 files (12310 skipped), last /system" },
    { "/system", 3100, 12310, 63, "[00:01] scan file system> 3100 files (12310 skipped), last /sys" },
    { "/system", 3100, 12310, 60, "[00:01] scan file system> 3100 files (12310 skipped), last /" },
    { "/system", 3100, 12310, 50, "[00:01] scan file system> 3100 files (12310 skippe" },
    { "/system", 3100, 12310, 40, "[00:01] scan file system> 3100 files (12" },
    { "/system", 3100, 12310, 30, "[00:01] scan file system> 3100" },
    { "/system", 3100, 12310, 20, "[00:01] scan file sy" },
    { "/system", 3100, 12310, 10, "[00:01] sc" },
    { "/system", 3100, 12310,  5, "[00:0" },
    { "/system", 3100, 12310,  1, "[" },

    { "/etc/fstab", 100, 10, 80, "[00:01] scan file system> 100 files (10 skipped), last /etc/fstab" },
    { "/etc/fstab", 100, 10, 70, "[00:01] scan file system> 100 files (10 skipped), last /etc/fstab" },
    { "/etc/fstab", 100, 10, 65, "[00:01] scan file system> 100 files (10 skipped), last /etc/fstab" },
    { "/etc/fstab", 100, 10, 60, "[00:01] scan file system> 100 files (10 skipped), last /etc/" },
    { "/etc/fstab", 100, 10, 50, "[00:01] scan file system> 100 files (10 skipped), " },
    { "/etc/fstab", 100, 10, 40, "[00:01] scan file system> 100 files (10 " },
    { "/etc/fstab", 100, 10, 30, "[00:01] scan file system> 100 " },
    { "/etc/fstab", 100, 10, 20, "[00:01] scan file sy" },
    { "/etc/fstab", 100, 10, 10, "[00:01] sc" },
    { "/etc/fstab", 100, 10,  5, "[00:0" },
    { "/etc/fstab", 100, 10,  1, "[" },

    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230, 130, "[00:01] scan file system> 6393 files (230 skipped), last /usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230, 129, "[00:01] scan file system> 6393 files (230 skipped), last /usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230, 120, "[00:01] scan file system> 6393 files (230 skipped), last /usr/.../device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230, 110, "[00:01] scan file system> 6393 files (230 skipped), last /usr/.../libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230, 100, "[00:01] scan file system> 6393 files (230 skipped), last /usr/.../libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  90, "[00:01] scan file system> 6393 files (230 skipped), last /usr/.../libdevmapper-event-lvm2m" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  80, "[00:01] scan file system> 6393 files (230 skipped), last /usr/.../libdevmapper-e" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  70, "[00:01] scan file system> 6393 files (230 skipped), last /usr/.../libd" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  60, "[00:01] scan file system> 6393 files (230 skipped), last /us" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  50, "[00:01] scan file system> 6393 files (230 skipped)" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  40, "[00:01] scan file system> 6393 files (23" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  30, "[00:01] scan file system> 6393" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  20, "[00:01] scan file sy" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,  10, "[00:01] sc" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,   5, "[00:0" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 6393, 230,   1, "[" },

    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0, 120, "[00:01] scan file system> 1 file, last /usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0, 111, "[00:01] scan file system> 1 file, last /usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0, 110, "[00:01] scan file system> 1 file, last /usr/.../device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0, 100, "[00:01] scan file system> 1 file, last /usr/.../device-mapper/libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  90, "[00:01] scan file system> 1 file, last /usr/.../libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  80, "[00:01] scan file system> 1 file, last /usr/.../libdevmapper-event-lvm2mirror.so" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  70, "[00:01] scan file system> 1 file, last /usr/.../libdevmapper-event-lvm" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  60, "[00:01] scan file system> 1 file, last /usr/.../libdevmapper" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  50, "[00:01] scan file system> 1 file, last /usr/.../li" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  40, "[00:01] scan file system> 1 file, last /" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  30, "[00:01] scan file system> 1 fi" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  20, "[00:01] scan file sy" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,  10, "[00:01] sc" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,   5, "[00:0" },
    { "/usr/lib/x86_64-linux-gnu/device-mapper/libdevmapper-event-lvm2mirror.so", 1, 0,   1, "[" },
};

static int num_diff_progress_tests = sizeof progress_tests / sizeof(progress_test_t);

START_TEST (get_progress_bar_string_test) {
    char *str = get_progress_bar_string("scan file system", progress_tests[_i].path, progress_tests[_i].entries, progress_tests[_i].skipped, 1, progress_tests[_i].length);
    ck_assert_msg(strcmp(progress_tests[_i].expected_string, str) == 0, "\n"
            "get_progress_bar_string(path: '%s', entries: %lu, skipped: %lu, length: %d):\n"
            "  string returned '%s'\n"
            "         expected '%s'", progress_tests[_i].path, progress_tests[_i].entries, progress_tests[_i].skipped, progress_tests[_i].length, str, progress_tests[_i].expected_string);
    free(str);
}
END_TEST

Suite *make_progress_suite(void) {

    Suite *s = suite_create ("progress");

    TCase *tc_get_progress_bar_string = tcase_create ("get_progress_bar_string");

    tcase_add_loop_test (tc_get_progress_bar_string, get_progress_bar_string_test, 0, num_diff_progress_tests);

    suite_add_tcase (s, tc_get_progress_bar_string);

    return s;
}
