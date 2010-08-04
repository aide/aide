/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006 Rami Lehti, Pablo Virolainen, Richard
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

#ifndef _CONF_LEX_H_INCLUDED_
#define _CONF_LEX_H_INCLUDED_

void conf_put_token(const char* s);

extern int conferror(const char*);

extern int conflex(void);

extern int confparse(void);

extern void* conf_scan_string(char*);

#endif
