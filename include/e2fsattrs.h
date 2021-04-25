/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2021 Hannes von Haugwitz
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

#ifndef _E2FSATTRS_H_INCLUDED
#define _E2FSATTRS_H_INCLUDED

#include <stdbool.h>
#include <e2p/e2p.h>

unsigned long e2fsattrs_get_flag(char);

/* memory for the returned string is obtained with malloc(3), and should be freed with free(3). */
char* get_e2fsattrs_string(unsigned long, bool, unsigned long);

#endif
