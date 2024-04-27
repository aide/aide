/*
**
** Copyright (C) 1994 Swedish University Network (SUNET)
** Modified by Rami Lehti (C) 1999
** Modified by Richard van den Berg (C) 2005,2006
** Modified by Hannes von Haugwitz (C) 2018,2020-2022,2024
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "base64.h"
#include "util.h"
#include "log.h"

char tob64[] = 
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



int fromb64[] = {
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, SKIP, SKIP, FAIL, FAIL, SKIP, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  

SKIP, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, 0x3e, FAIL, FAIL, FAIL, 0x3f,
0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,  
0x3c, 0x3d, FAIL, FAIL, FAIL, SKIP, FAIL, FAIL,

FAIL, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  
0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,  
0x17, 0x18, 0x19, FAIL, FAIL, FAIL, FAIL, FAIL,

FAIL, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,  
0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,  
0x31, 0x32, 0x33, FAIL, FAIL, FAIL, FAIL, FAIL,

FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL,  
FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL, FAIL
};

/* Returns NULL on error */
char* encode_base64(byte* src,size_t ssize)
{
  char* outbuf;
  int pos;
  int i, l, left;
  unsigned long triple;
  byte *inb;
  
  /* Exit on empty input */
  if (!ssize||src==NULL){
    log_msg(LOG_LEVEL_DEBUG,"encode base64: empty string");
    return NULL;
  }

  /* length of encoded base64 string (padded) */
  size_t length = sizeof(char)* ((ssize + 2) / 3) * 4;
  outbuf = (char *)checked_malloc(length + 1);
  
  /* Initialize working pointers */
  inb = src;
  i = 0;
  triple = 0;
  pos = 0;
  left = ssize;
  log_msg(LOG_LEVEL_TRACE, "encode base64:, data length: %d", left);
  /*
   * Process entire inbuf.
   */
  while (left != 0)
    {
      i++;
      left--;
      
      triple = (triple <<8) | *inb;
      if (i == 3 || left == 0)
	{
	  switch (i) 
	    {
	    case 1:
	      triple = triple<<4;
	      break;
	    case 2:
	      triple = triple<<2;
	      break;
	    default:
	      break;
	    }
	  for (l = i; l >= 0; l--){
	    /* register */ 
	    int rr; 
	    rr = 0x3f & (triple>>(6*l)); 
	    assert (rr < 64); 
	    outbuf[pos]=tob64[rr];
	    pos++;
	      }
	  if (left == 0)
	    switch(i)
	      {
	      case 2:
		outbuf[pos]='=';
		pos++;
		break;
	      case 1:
		outbuf[pos]='=';
		pos++;
		outbuf[pos]='=';
		pos++;
		break;
	      default:
		break;
	      }
	  triple = 0;
	  i = 0;
	  }
      inb++;
  }
  
  outbuf[pos]='\0';

  return outbuf;
}

byte* decode_base64(char* src,size_t ssize, size_t *ret_len)
{
  byte* outbuf;
  char* inb;
  int i;
  int l;
  int left;
  int pos;
  unsigned long triple;

  /* Exit on empty input */
  if (!ssize||src==NULL) {
    log_msg(LOG_LEVEL_DEBUG, "decode base64: empty string");
    return NULL;
  }

  /* exit on unpadded input */
  if (ssize % 4) {
    log_msg(LOG_LEVEL_WARNING, "decode_base64: '%s' has invalid length (missing padding characters?)", src);
    return NULL;
  }

  /* calculate length of decoded string, substract padding chars if any (ssize is >= 4) */
  size_t length = sizeof(byte) * ((ssize / 4) * 3)- (src[ssize-1] == '=') - (src[ssize-2] == '=');

  /* Initialize working pointers */
  inb = src;
  outbuf = (byte *)checked_malloc(length + 1);

  l = 0;
  triple = 0;
  pos=0;
  left = ssize;
  /*
   * Process entire inbuf.
   */
  while (left != 0)
    {
      left--;
      i = fromb64[(unsigned char)*inb];
      switch(i)
	{
	case FAIL:
	  log_msg(LOG_LEVEL_WARNING, "decode_base64: illegal character: '%c' in '%s'", *inb, src);
	  free(outbuf);
	  return NULL;
	  break;
	case SKIP:
	  break;
	default:
	  triple = triple<<6 | (0x3f & i);
	  l++;
	  break;
	}
      if (l == 4 || left == 0)
	{
	  switch(l)
	    {
	    case 2:
	      triple = triple>>4;
	      break;
	    case 3:
	      triple = triple>>2;
	      break;
	    default:
	      break;
	    }
	  for (l  -= 2; l >= 0; l--)
	    {
	      outbuf[pos]=( 0xff & (triple>>(l*8)));
	      pos++;
	    }
	  triple = 0;
	  l = 0;
	}
      inb++;
    }
  
  outbuf[pos]='\0';

  if (ret_len) *ret_len = pos;
  
  return outbuf;
}
