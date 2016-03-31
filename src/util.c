/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2004-2006,2010,2011,2013,2016 Rami Lehti, Pablo
 * Virolainen, Mike Markley, Richard van den Berg, Hannes von Haugwitz
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>
#include <syslog.h>
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/


#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#include "report.h"
#include "db_config.h"
#include "util.h"

#define URL_UNSAFE " <>\"#%{}|\\^~[]`@:\033'"
#define ISPRINT(c) (isascii(c) && isprint(c))

static const char* url_name[] = { 
  "file", "stdin", "stdout", "stderr", "fd", "sql", "syslog", "database", "https", "http", "ftp" };

static const int url_value[] = {
  url_file, url_stdin, url_stdout,url_stderr,url_fd, url_sql, url_syslog, url_database, url_https, url_http, url_ftp };

const int url_ntypes=sizeof(url_value)/sizeof(URL_TYPE);

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

url_t* parse_url(char* val)
{
  url_t* u=NULL;
  char* r=NULL;
  char* val_copy=NULL;
  int i=0;

  if(val==NULL){
    return NULL;
  }
  
  u=(url_t*)malloc(sizeof(url_t));
  
  /* We don't want to modify the original hence strdup(val) */
  val_copy=strdup(val);
  for(r=val_copy;r[0]!=':'&&r[0]!='\0';r++);
  
  if(r[0]!='\0'){
    r[0]='\0';
    r++;
  }
  u->type=url_unknown;
  for(i=0;i<url_ntypes;i++){
    if(strcmp(val_copy,url_name[i])==0){
      u->type=url_value[i];
      break;
    }
  }
  
  switch (u->type) {
  case url_file : {
    if(r[0]=='/'&&(r+1)[0]=='/'&&(r+2)[0]=='/'){
      u->value=strdup(r+2);
      break;
    }
    if(r[0]=='/'&&(r+1)[0]=='/'&&(r+2)[0]!='/'){
      char*hostname=(char*)malloc(sizeof(char)*MAXHOSTNAMELEN);
      char* t=r+2;
      r+=2;
      for(i=0;r[0]!='/'&&r[0]!='\0';r++,i++);
      if(r[0]=='\0'){
	error(0,"Invalid file-URL,no path after hostname: file:%s\n",t);
	return NULL;
      }
      u->value=strdup(r);
      r[0]='\0';
      if(gethostname(hostname,MAXHOSTNAMELEN)==-1){
    strncpy(hostname,"localhost", 10);
      }
      if( (strcmp(t,"localhost")==0)||(strcmp(t,hostname)==0)){
	free(hostname);
	break;
      } else {
	error(0,"Invalid file-URL, cannot use hostname other than localhost or %s: file:%s\n",hostname,u->value);
	free(hostname);
	return NULL;
      }
      free(hostname);
      break;
    }
    u->value=strdup(r);
    
    break;
  }
  case url_https :
  case url_http :
  case url_ftp : {
    u->value=strdup(val);
    break;
  }
  case url_unknown : {
    error(0,"Unknown URL-type:%s\n",val_copy);
    break;
  }
  default : {
    u->value=strdup(r);
    break;
  }
  }

  free(val_copy);

  return u;
}

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

  error(240,"perm_to_char(): %i -> %s\n",perm,pc);

  return pc;
}

void init_sighandler()
{
  signal(SIGBUS,sig_handler);
  signal(SIGTERM,sig_handler);
  signal(SIGUSR1,sig_handler);
  signal(SIGUSR2,sig_handler);
  signal(SIGHUP,sig_handler);

  return;
}

void sig_handler(int signum)
{
  switch(signum){
  case SIGBUS  : 
  case SIGSEGV :{
    error(200,"Caught SIGBUS/SIGSEGV\n");
    if(conf->catch_mmap==1){
      error(4,"Caught SIGBUS/SEGV while mmapping. File was truncated while aide was running?\n");
      conf->catch_mmap=0;
    } else {
      error(0,"Caught SIGBUS/SEGV. Exiting\n");
      exit(EXIT_FAILURE);
    }
    break;
  }
  case SIGHUP : {
    error(4,"Caught SIGHUP\n");
    break;
  }
  case SIGTERM : {
    error(4,"Caught SIGTERM\nUse SIGKILL to terminate\n");
    break;
  }
  case SIGUSR1 : {
    error(4,"Setting output to debug level according to signal\n");
    conf->verbose_level=220;
    break;
  }
  case SIGUSR2 : {
    error(4,"Setting output to normal level according to signal\n");
    conf->verbose_level=5;
    break;
  }
  }
  error(220,"Caught signal %d\n",signum);
  init_sighandler();

  return;
}

char *expand_tilde(char *path) {
    char *homedir, *full;
    size_t path_len, homedir_len, full_len;

    if (path != NULL) {
        if (path[0] == '~') {
            if((homedir=getenv("HOME")) != NULL) {
                path_len = strlen(path+sizeof(char));
                homedir_len = strlen(homedir);
                full_len = homedir_len+path_len;
                full = malloc(sizeof(char) * (full_len+1));
                strncpy(full, homedir, homedir_len);
                strncpy(full+homedir_len, path+sizeof(char), path_len);
                full[full_len] = '\0';
                free(path);
                /* Don't free(homedir); because it is not safe on some platforms */
                path = full;
            } else {
                error(3, _("Variable name 'HOME' not found in environment. '~' cannot be expanded\n"));
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

	error(0,"Syslog facility \"%s\" is unknown, using default\n",s);
	return(AIDE_SYSLOG_FACILITY);
}

/* We need these dummy stubs to fool the linker into believing that
   we do not need them at link time */

void* dlopen(char*filename,int flag)
{
  return NULL;
}

void* dlsym(void*handle,char*symbol)
{
  return NULL;
}

void* dlclose(void*handle)
{
  return NULL;
}

const char* dlerror(void)
{
  return NULL;
}

const char* aide_key_2=CONFHMACKEY_02;
const char* db_key_2=DBHMACKEY_02;
