/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2019,2020 Rami Lehti, Pablo Virolainen, Mike
 * Markley, Richard van den Berg, Hannes von Haugwitz
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

#include "aide.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "error.h"

void error(int errorlevel,char* error_msg,...)
{
  va_list ap;

  if(conf->verbose_level==-1){
    if(5<errorlevel){
      return;
    }
  }else{ 
    if(conf->verbose_level<errorlevel){
      return;
    }
  }  

  FILE* url = stderr;

  va_start(ap, error_msg);
  vfprintf(url, error_msg,ap);
  va_end(ap);

  return;
}

const char* aide_key_0=CONFHMACKEY_00;
const char* db_key_0=DBHMACKEY_00;
