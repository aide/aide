/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2004-2006,2010,2011,2013,2016,2019-2021 Rami Lehti,
 * Pablo Virolainen, Mike Markley, Richard van den Berg, Hannes von Haugwitz
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <syslog.h>
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/


#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#include "log.h"
#include "db_config.h"
#include "util.h"

#define URL_UNSAFE " <>\"#%{}|\\^~[]`@:\033'"
#define ISPRINT(c) (isascii(c) && isprint(c))

const char* btoa(bool b) {
    return b?"true":"false";
}

void* checked_malloc(size_t size) {
    void * p = malloc(size);
    if (p == NULL) {
        log_msg(LOG_LEVEL_ERROR, "malloc: failed to allocate %d bytes of memory", size);
        exit(EXIT_FAILURE);
    }
    return p;
}
void* checked_strdup(const char *s) {
    void * p = strdup(s);
    if (p == NULL) {
        log_msg(LOG_LEVEL_ERROR, "strdup: failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    return p;
}

int cmpurl(url_t* u1,url_t* u2)
{
  if(u1->type!= u2->type){
    return RETFAIL;
  };
  if(strcmp(u1->value,u2->value)!=0){
    return RETFAIL;
  }

  return RETOK;
};

/* Returns 1 if the string contains unsafe characters, 0 otherwise.  */
int contains_unsafe (const char *s)
{
  for (; *s; s++)
    if (strchr (URL_UNSAFE,(int) *s)||!ISPRINT((int)*s))
      return 1;
  return 0;
}
 
/* Decodes the forms %xy in a URL to the character the hexadecimal
   code of which is xy.  xy are hexadecimal digits from
   [0123456789ABCDEF] (case-insensitive).  If x or y are not
   hex-digits or `%' precedes `\0', the sequence is inserted
   literally.  */
 
void decode_string (char* s)
{
  char *p = s;
 
  for (; *s; s++, p++)
    {
      if (*s != '%')
        *p = *s;
      else
        {
          /* Do nothing if at the end of the string, or if the chars
             are not hex-digits.  */
          if (!*(s + 1) || !*(s + 2)
              || !(ISXDIGIT (*(s + 1)) && ISXDIGIT (*(s + 2))))
            {
              *p = *s;
              continue;
            }
          *p = (ASC2HEXD (*(s + 1)) << 4) + ASC2HEXD (*(s + 2));
          s += 2;
        }
    }
  *p = '\0';
}
 
/* Encodes the unsafe characters (listed in URL_UNSAFE) in a given
   string, returning a malloc-ed %XX encoded string.  */
char* encode_string (const char* s)
{
  const char *b;
  char *p, *res;
  int i;
 
  b = s;
  for (i = 0; *s; s++, i++){
    if (strchr (URL_UNSAFE,(int) *s)||!ISPRINT((int)*s)){
      i += 2; /* Two more characters (hex digits) */
    }
  }

  res = (char *)malloc (i + 1);
  s = b;
  for (p = res; *s; s++){
    if (strchr (URL_UNSAFE, *s)||!ISPRINT((int)*s))
      {
        const unsigned char c = *s;
        *p++ = '%';
        *p++ = HEXD2ASC (c >> 4);
        *p++ = HEXD2ASC (c & 0xf);
      }
    else {
      *p++ = *s;
    }
  }
  *p = '\0';
  return res;
}

char* perm_to_char(mode_t perm)
{
  char*pc=NULL;
  int i=0;
  
  pc=(char*)malloc(sizeof(char)*11);
  for(i=0;i<10;i++){
    pc[i]='-';
  }
  pc[10]='\0';

  if(S_ISDIR(perm))
    pc[0]='d';
#ifdef S_ISFIFO
  if(S_ISFIFO(perm))
    pc[0]='p';
#endif
  if(S_ISLNK(perm))
    pc[0]='l';
  if(S_ISBLK(perm))
    pc[0]='b';
  if(S_ISCHR(perm))
    pc[0]='c';
#ifdef S_ISDOOR
  if(S_ISDOOR(perm))
    pc[0]='|';
#endif
#ifdef S_ISSOCK
  if(S_ISSOCK(perm))
    pc[0]='s';
#endif
  
  if((S_IRUSR&perm)==S_IRUSR){
    pc[1]='r';
  }
  if((S_IWUSR&perm)==S_IWUSR){
    pc[2]='w';
  }
  if((S_IXUSR&perm)==S_IXUSR){
    pc[3]='x';
  }
  if((S_IRGRP&perm)==S_IRGRP){
    pc[4]='r';
  }
  if((S_IWGRP&perm)==S_IWGRP){
    pc[5]='w';
  }
  if((S_IXGRP&perm)==S_IXGRP){
    pc[6]='x';
  }
  if((S_IROTH&perm)==S_IROTH){
    pc[7]='r';
  }
  if((S_IWOTH&perm)==S_IWOTH){
    pc[8]='w';
  }
  if((S_IXOTH&perm)==S_IXOTH){
    pc[9]='x';
  }

  if((S_ISUID&perm)==S_ISUID){
    if((S_IXUSR&perm)==S_IXUSR){
      pc[3]='s';
    } else {
      pc[3]='S';
    }
  }
  if((S_ISGID&perm)==S_ISGID){
    if((S_IXGRP&perm)==S_IXGRP){
      pc[6]='s';
    } else {
      pc[6]='l';
    }
  }
#if defined (S_ISVTX) && defined (S_IXOTH)
  if((S_ISVTX&perm)==S_ISVTX){
    if((S_IXOTH&perm)==S_IXOTH){
      pc[9]='t';
    } else {
      pc[9]='T';
    }
  }
#endif

  log_msg(LOG_LEVEL_TRACE, "perm_to_char: %i -> %s",perm,pc);

  return pc;
}

char *expand_tilde(char *path) {
    char *homedir = NULL;
    char *full = NULL;
    size_t path_len, homedir_len, full_len;

    if (path != NULL) {
        if (path[0] == '~') {
            if((homedir=getenv("HOME")) != NULL) {
                path_len = strlen(path+sizeof(char));
                homedir_len = strlen(homedir);
                full_len = homedir_len+path_len;
                full = malloc(sizeof(char) * (full_len+1));
                strcpy(full, homedir);
                strcat(full+homedir_len, path+sizeof(char));
                log_msg(LOG_LEVEL_DEBUG, "expanded '~' in '%s' to '%s'", path, full);
                free(path);
                /* Don't free(homedir); because it is not safe on some platforms */
                path = full;
            } else {
                log_msg(LOG_LEVEL_WARNING, _("Variable name 'HOME' not found in environment. '~' cannot be expanded"));
            }
        } else if (path[0] == '\\' && path[1] == '~') {
            path += sizeof(char);
        }
    }
    return path;
}

/* Like strstr but only do search for maximum of n chars.
   haystack does not have to be NULL terminated
   needle has to be NULL terminated. NULL in needle is not used in compare.
   NULLs in haystack are ignored.
*/
#ifndef HAVE_STRNSTR
char* strnstr(char* haystack,char* needle,int n)
{
  char* h=haystack;
  char* s=needle;
  int slen=strlen(s);
  int i=0;

  for(i=0;i<n;i++){
    /* If terminating NULL is reached in needle string
       then we have a match */
    if(*s=='\0'){
      return &haystack[i-slen];
    }
    if(*s==*h){
      s++;
    }else{
      s=needle;
    }
    h++;
  }
  /* Handle the special case that we are at the end of haystack 
     and match is right at the end 
  */
  if(*s=='\0'){
    return &haystack[i-slen];
  }
  
  /* If we get this far no match was found so we return NULL */
  return NULL;
}
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen)
{
	size_t l;
	l=strlen(s);
	if(l>maxlen)
		return maxlen;
	return l;
}
#endif

/* Lookup syslog facilities by name */
int syslog_facility_lookup(char *s)
{
	if(!s || strlen(s)<1)
		return(AIDE_SYSLOG_FACILITY);
#ifdef LOG_KERN
	if(strcasecmp(s,"LOG_KERN")==0)
		return(LOG_KERN);
#endif
#ifdef LOG_USER
	if(strcasecmp(s,"LOG_USER")==0)
		return(LOG_USER);
#endif
#ifdef LOG_MAIL
	if(strcasecmp(s,"LOG_MAIL")==0)
		return(LOG_MAIL);
#endif
#ifdef LOG_DAEMON
	if(strcasecmp(s,"LOG_DAEMON")==0)
		return(LOG_DAEMON);
#endif
#ifdef LOG_AUTH
	if(strcasecmp(s,"LOG_AUTH")==0)
		return(LOG_AUTH);
#endif
#ifdef LOG_SYSLOG
	if(strcasecmp(s,"LOG_SYSLOG")==0)
		return(LOG_SYSLOG);
#endif
#ifdef LOG_LPR
	if(strcasecmp(s,"LOG_LPR")==0)
		return(LOG_LPR);
#endif
#ifdef LOG_NEWS
	if(strcasecmp(s,"LOG_NEWS")==0)
		return(LOG_NEWS);
#endif
#ifdef LOG_UUCP
	if(strcasecmp(s,"LOG_UUCP")==0)
		return(LOG_UUCP);
#endif
#ifdef LOG_CRON
	if(strcasecmp(s,"LOG_CRON")==0)
		return(LOG_CRON);
#endif
#ifdef LOG_LOCAL0
	if(strcasecmp(s,"LOG_LOCAL0")==0)
		return(LOG_LOCAL0);
#endif
#ifdef LOG_LOCAL1
	if(strcasecmp(s,"LOG_LOCAL1")==0)
		return(LOG_LOCAL1);
#endif
#ifdef LOG_LOCAL2
	if(strcasecmp(s,"LOG_LOCAL2")==0)
		return(LOG_LOCAL2);
#endif
#ifdef LOG_LOCAL3
	if(strcasecmp(s,"LOG_LOCAL3")==0)
		return(LOG_LOCAL3);
#endif
#ifdef LOG_LOCAL4
	if(strcasecmp(s,"LOG_LOCAL4")==0)
		return(LOG_LOCAL4);
#endif
#ifdef LOG_LOCAL5
	if(strcasecmp(s,"LOG_LOCAL5")==0)
		return(LOG_LOCAL5);
#endif
#ifdef LOG_LOCAL6
	if(strcasecmp(s,"LOG_LOCAL6")==0)
		return(LOG_LOCAL6);
#endif
#ifdef LOG_LOCAL7
	if(strcasecmp(s,"LOG_LOCAL7")==0)
		return(LOG_LOCAL7);
#endif

	log_msg(LOG_LEVEL_WARNING, "Syslog facility \"%s\" is unknown, using default",s);
	return(AIDE_SYSLOG_FACILITY);
}
