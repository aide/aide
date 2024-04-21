/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2019,2024 Hannes von Haugwitz
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

#include <stdlib.h>

#include "check_aide.h"

int main (void) {
    int number_failed;
    SRunner *sr;

    sr = srunner_create (make_attributes_suite());
    srunner_add_suite(sr, make_seltree_suite());

    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);

    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
