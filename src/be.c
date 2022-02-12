/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2003, 2005-2006, 2010-2011, 2013, 2019-2022 Rami Lehti,
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

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#ifdef HAVE_FCNTL
#include <fcntl.h>
#endif
#include <unistd.h>
#include <errno.h>
#ifdef WITH_ZLIB
#include <zlib.h>
#endif
#include "log.h"
#include "util.h"
#include "errorcodes.h"
#ifdef WITH_CURL
#include "fopen.h"
#endif
#include "be.h"
#include "url.h"

/*for locale support*/
#include "locale-aide.h"
/*for locale support*/


void* be_init(bool readonly, url_t* u, bool iszipped, bool append, int linenumber, char* filename, char* linebuf) {
  FILE* fh=NULL;
  long a=0;
  char* err=NULL;
  int fd;
#if HAVE_FCNTL && HAVE_FTRUNCATE
  struct flock fl;
#endif

  switch (u->type) {
  case url_file : {
    u->value = expand_tilde(u->value);
    log_msg(LOG_LEVEL_DEBUG, "open (%s, gzip: %s, append: %s ) file '%s'", readonly?"read-only":"read/write", btoa(iszipped), btoa(append), u->value);
#if HAVE_FCNTL && HAVE_FTRUNCATE
    fd=open(u->value,readonly?O_RDONLY:O_CREAT|O_RDWR|(append?O_APPEND:0),0666);
#else
    fd=open(u->value,readonly?O_RDONLY:O_CREAT|O_RDWR|(append?O_APPEND:O_TRUNC),0666);
#endif
    if(fd==-1) {
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, open (%s) failed for file '%s': %s, readonly?"read-only":"read/write", u->value, strerror(errno));
      return NULL;
    } else {
        log_msg(LOG_LEVEL_DEBUG, "opened file '%s' with fd=%i",u->value,fd);
    }
#if HAVE_FCNTL && HAVE_FTRUNCATE
    if(!readonly) {
     if (strncmp(u->value, "/dev/null", strlen("/dev/null"))) {
      fl.l_type = F_WRLCK;
      fl.l_whence = SEEK_SET;
      fl.l_start = 0;
      fl.l_len = 0;
      log_msg(LOG_LEVEL_DEBUG, "try to get lock for file '%s'", u->value);
      if (fcntl(fd, F_SETLK, &fl) == -1) {
          log_msg(LOG_LEVEL_ERROR, "cannot get lock for file '%s': %s", u->value, strerror(errno));
          exit(LOCK_ERROR);
      } else {
          log_msg(LOG_LEVEL_DEBUG, "successfully got lock for file '%s'", u->value);
      }
      if (!append) {
          if(ftruncate(fd,0)==-1) {
              log_msg(LOG_LEVEL_ERROR,_("ftruncate failed for file %s: %s"),u->value, strerror(errno));
              return NULL;
          } else {
              log_msg(LOG_LEVEL_DEBUG, "successfully truncated file '%s' to size 0", u->value);
          }
     }
        } else {
          log_msg(LOG_LEVEL_DEBUG, "skip lock for '/dev/null'");
     }
    }
#endif
#ifdef WITH_ZLIB
    if(iszipped && !readonly){
      gzFile gzfh = gzdopen(fd,"wb9");
      if(gzfh==NULL){
        log_msg(LOG_LEVEL_ERROR, _("gzdopen (%s) failed for file %s"), readonly?"read-only":"read/write", u->value);
      }
    return gzfh;
    }
    else{
#endif
      fh=fdopen(fd,readonly?"r":"w+");
      if(fh==NULL){
          log_msg(LOG_LEVEL_ERROR, _("fdopen (%s) failed for file '%s': %s"), readonly?"read-only":"read/write", u->value, strerror(errno));
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
      log_msg(LOG_LEVEL_ERROR,"illegal file descriptor value:%s",u->value);
    }
#ifdef WITH_ZLIB
    if(iszipped && !readonly){
      gzFile gzfh = gzdopen(a,"w");
      if(fh==NULL){
	log_msg(LOG_LEVEL_ERROR,"couldn't reopen file descriptor %li",a);
      }
      return gzfh;
    }
    else{
#endif
      fh=fdopen(a,readonly?"r":"w");
      if(fh==NULL){
	log_msg(LOG_LEVEL_ERROR,"couldn't reopen file descriptor %li",a);
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
      log_msg(LOG_LEVEL_DEBUG,_("opening curl '%s' for %s"),u->value,readonly?"r":"w+");
      if (iszipped) {
	return NULL;
      }
      return url_fopen(u->value,readonly?"r":"w+");
    }
#endif /* WITH CURL */
  default:{
    log_msg(LOG_LEVEL_ERROR, "unsupported backend: %i", u->type);
    return NULL;
  }    
  }
  /* Not reached */
  return NULL;

}
