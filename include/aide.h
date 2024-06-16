/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2010-2011, 2019, 2022, 2024 Rami Lehti,
 *               Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
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

#ifndef _AIDE_H_INCLUDED
#define _AIDE_H_INCLUDED

#include "config.h"
#include "db_config.h"

#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif

#ifdef strtoimax
# define HAVE_STRTOIMAX
#endif

#define ARGUMENT_SIZE 65536

/* This is a structure that has all configuration info */
extern db_config* conf;

#endif

