/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2003,2005,2006,2010,2011,2013,2019,2020 Rami Lehti, Pablo
 * Virolainen, Richard van den Berg, Hannes von Haugwitz
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
#include <unistd.h>
#include <errno.h>
#include "db_config.h"
#include "db_file.h"
#include "error.h"
#include "util.h"
#ifdef WITH_CURL
#include "fopen.h"
#endif
#include "be.h"

/*for locale support*/
#include "locale-aide.h"
/*for locale support*/


void* be_init(int inout,url_t* u,int iszipped)
{
  FILE* fh=NULL;
  long a=0;
  char* err=NULL;
  int fd;
#if HAVE_FCNTL && HAVE_FTRUNCATE
  struct flock fl;
#endif

  if (u==NULL) {
    return NULL;
  }

  switch (u->type) {
  case url_file : {
    u->value = expand_tilde(u->value);
    error(200,_("Opening file \"%s\" for %s\n"),u->value,inout?"r":"w+");
#if HAVE_FCNTL && HAVE_FTRUNCATE
    fd=open(u->value,inout?O_RDONLY:O_CREAT|O_RDWR,0666);
#else
    fd=open(u->value,inout?O_RDONLY:O_CREAT|O_RDWR|O_TRUNC,0666);
#endif
    error(255,"Opened file \"%s\" with fd=%i\n",u->value,fd);
    if(fd==-1) {
      error(0,_("Couldn't open file %s for %s"),u->value,
	    inout?"reading\n":"writing\n");
      return NULL;
    }
#if HAVE_FCNTL && HAVE_FTRUNCATE
    if(!inout) {
     if (strncmp(u->value, "/dev/null", strlen("/dev/null"))) {
      fl.l_type = F_WRLCK;
      fl.l_whence = SEEK_SET;
      fl.l_start = 0;
      fl.l_len = 0;
      if (fcntl(fd, F_SETLK, &fl) == -1) {
	if (fcntl(fd, F_SETLK, &fl) == -1)
	  error(0,_("File %s is locked by another process.\n"),u->value);
	else
	  error(0,_("Cannot get lock for file %s"),u->value);
	return NULL;
      }
      if(ftruncate(fd,0)==-1)
	error(0,_("Error truncating file %s"),u->value);

     }
    }
#endif
#ifdef WITH_ZLIB
    if(iszipped && !inout){
      gzFile gzfh = gzdopen(fd,"wb9");
      if(gzfh==NULL){
	error(0,_("Couldn't open file %s for %s"),u->value,
	      inout?"reading\n":"writing\n");
      }
    return gzfh;
    }
    else{
#endif
      fh=fdopen(fd,inout?"r":"w+");
      if(fh==NULL){
	error(0,_("Couldn't open file %s for %s"),u->value,
	      inout?"reading\n":"writing\n");
      }
    return fh;
#ifdef WITH_ZLIB
    }
#endif
    }
  case url_stdout : {
#ifdef WITH_ZLIB
    if(iszipped){
      return gzdopen(fileno(stdout),"wb");
    }
    else{
#endif
    return stdout;
#ifdef WITH_ZLIB
    }
#endif
  }
  case url_stdin : {
#ifdef WITH_ZLIB
    if(iszipped){
      return gzdopen(fileno(stdin),"r");
    }
    else{
#endif
      return stdin;
#ifdef WITH_ZLIB
    }
#endif
  }
  case url_stderr : {
#ifdef WITH_ZLIB
    if(iszipped){
      return gzdopen(fileno(stderr),"wb");
    }
    else{
#endif
      return stderr;
#ifdef WITH_ZLIB
    }
#endif
  }
  case url_fd : {
    a=strtol(u->value,&err,10);
    if(*err!='\0'||errno==ERANGE){
      error(0,"Illegal file descriptor value:%s\n",u->value);
    }
#ifdef WITH_ZLIB
    if(iszipped && !inout){
      gzFile gzfh = gzdopen(a,"w");
      if(fh==NULL){
	error(0,"Couldn't reopen file descriptor %li\n",a);
      }
      return gzfh;
    }
    else{
#endif
      fh=fdopen(a,inout?"r":"w");
      if(fh==NULL){
	error(0,"Couldn't reopen file descriptor %li\n",a);
      }
      return fh;
#ifdef WITH_ZLIB
    }
#endif
  }
#ifdef WITH_CURL
  case url_http:
  case url_https:
  case url_ftp:
    {
      error(200,_("Opening curl \"%s\" for %s\n"),u->value,inout?"r":"w+");
      if (iszipped) {
	return NULL;
      }
      return url_fopen(u->value,inout?"r":"w+");
    }
#endif /* WITH CURL */
  default:{
    error(0,"Unsupported backend: %i", u->type);
    return NULL;
  }    
  }
  /* Not reached */
  return NULL;

}

const char* aide_key_8=CONFHMACKEY_08;
const char* db_key_8=DBHMACKEY_08;
