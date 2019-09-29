/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2010 Rami Lehti, Pablo Virolainen, Richard
 * van den Berg
 * $Header$
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

#ifndef _ERROR_H_INCLUDED
#define  _ERROR_H_INCLUDED

#include <stdio.h>
#include <stdarg.h>
#include "db_config.h"
#include "url.h"

/* Exitcodes */
#define ERROR_WRITING_ERROR 14
#define INVALID_ARGUMENT_ERROR 15
#define UNIMPLEMENTED_FUNCTION_ERROR 16
#define INVALID_CONFIGURELINE_ERROR 17
#define IO_ERROR 18
#define VERSION_MISMATCH_ERROR 19

/* Errorcodes */
#define HASH_ALGO_ERROR 30

void error(int errorlevel, char* error_msg,...)
#ifdef __GNUC__
        __attribute__ ((format (printf, 2, 3)));
#else
 ;
#endif

int error_init(url_t*,int);

void write_error_stderr(int errorlevel, char*error_msg,va_list ap);


#endif
