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

#include "aide.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "base64.h"
#include "report.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

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
/* FIXME Possible buffer overflow on outputs larger than B64_BUF */
char* encode_base64(byte* src,size_t ssize)
{
  char* outbuf;
  char* retbuf;
  int pos;
  int i, l, left;
  unsigned long triple;
  byte *inb;
  
  error(235, "encode base64");
  /* Exit on empty input */
  if (!ssize||src==NULL){
    error(240,"\n");
    return NULL;
  }
  outbuf = (char *)malloc(sizeof(char)*B64_BUF);
  
  /* Initialize working pointers */
  inb = src;
  i = 0;
  triple = 0;
  pos = 0;
  left = ssize;
  error(235, ", data length: %d\n", left);
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
  
  /* outbuf is not completely used so we use retbuf */
  retbuf=(char*)malloc(sizeof(char)*(pos+1));
  memcpy(retbuf,outbuf,pos);
  retbuf[pos]='\0';
  free(outbuf);

  return retbuf;
}

/* FIXME Possible buffer overflow on outputs larger than B64_BUF */
byte* decode_base64(char* src,size_t ssize, size_t *ret_len)
{
  byte* outbuf;
  byte* retbuf;
  char* inb;
  int i;
  int l;
  int left;
  int pos;
  unsigned long triple;

  error(235, "decode base64\n");
  /* Exit on empty input */
  if (!ssize||src==NULL)
    return NULL;


  /* Initialize working pointers */
  inb = src;
  outbuf = (byte *)malloc(sizeof(byte)*B64_BUF);

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
	  error(3, "decode_base64: Illegal character: %c\n", *inb);
	  error(230, "decode_base64: Illegal line:\n%s\n", src);
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
  
  retbuf=(byte*)malloc(sizeof(byte)*(pos+1));
  memcpy(retbuf,outbuf,pos);
  retbuf[pos]='\0';
  
  free(outbuf);

  if (ret_len) *ret_len = pos;
  
  return retbuf;
}

size_t length_base64(char* src,size_t ssize)
{
  char* inb;
  int i;
  int l;
  int left;
  size_t pos;
  unsigned long triple;

  error(235, "decode base64\n");
  /* Exit on empty input */
  if (!ssize||src==NULL)
    return 0;



  /* Initialize working pointers */
  inb = src;

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
	  error(3, "length_base64: Illegal character: %c\n", *inb);
	  error(230, "length_base64: Illegal line:\n%s\n", src);
	  return 0; 
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
	      pos++;
	    }
	  triple = 0;
	  l = 0;
	}
      inb++;
    }
  
  return pos;
}

