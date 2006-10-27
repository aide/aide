/*
**
** Copyright (C) 1994 Swedish University Network (SUNET)
** Modified by Rami Lehti (C) 1999
** $Header$
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITTNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
**
**                                        Martin.Wendel@udac.uu.se
**                                        Torbjorn.Wictorin@udac.uu.se
**
**                                        UDAC	
**                                        P.O. Box 174
**                                        S-751 04 Uppsala
**                                        Sweden
**
*/

#ifndef _BASE64_H_INCLUDED
#define _BASE64_H_INCLUDED
#include <sys/types.h>
#include <assert.h>
#include "types.h"

#define B64_BUF 16384
#define FAIL -1
#define SKIP -2


char* encode_base64(byte* src,size_t ssize);

byte* decode_base64(char* src,size_t ssize,size_t *);

/* Returns decoded length */
size_t length_base64(char* src,size_t ssize);

#endif /* _BASE64_H_INCLUDED */
