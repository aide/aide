/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006 Rami Lehti, Pablo Virolainen, Mike
 * Markley, Richard van den Berg
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

#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif

#include "error.h"
#include "list.h"
#include "be.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/
#include "util.h"

int cmp_url(url_t* url1,url_t* url2){
  
  return ((url1->type==url2->type)&&(strcmp(url1->value,url2->value)==0));
  
}

int error_init(url_t* url,int initial)
{
  list* r=NULL;
  FILE* fh=NULL;
	int   sfac;
  
  if(initial==1){
    if (url->type==url_syslog) {
      conf->report_syslog++;
#ifdef HAVE_SYSLOG
      conf->initial_report_url=url;
      conf->initial_report_fd=NULL;
      sfac=syslog_facility_lookup(url->value);
      openlog(AIDE_IDENT,AIDE_LOGOPT, sfac);
      
      return RETOK;
#endif
#ifndef HAVE_SYSLOG
      error(0,_("This binary has no syslog support\n"));
      exit(INVALID_ARGUMENT_ERROR);
#endif
    }
    fh=be_init(0,url,0);
    if(fh!=NULL){
      conf->initial_report_fd=fh;
      conf->initial_report_url=url;
      return RETOK;
    }
    error(0,_("Cannot open %s for writing\n"),url->value);
    exit(INVALID_ARGUMENT_ERROR);
  }
  
  if(conf->verbose_level>=200){
    error(5,_("WARNING: Debug output enabled\n"));
  }

  for(r=conf->report_url;r;r=r->next){
    
    if (cmp_url((url_t*)r->data,url)) {
      
      error(5,_("WARNING: Already have report output %s\n"),url->value);
      return RETOK;
    }
    
  }


  if (url->type==url_syslog) {
    conf->report_syslog++;
#ifdef HAVE_SYSLOG
    /* If you add support for facility changing in config 
       consider multiple calls of openlog.
       This openlog MUST NOT mess up initial errorsto openlog.
       RvdB 22/1/2006: the 2 openlog calls where the same before my
       change, and they are still the same, I assume I did not brake anything
    */
    sfac=syslog_facility_lookup(url->value);
    if(conf->report_syslog<2)
      openlog(AIDE_IDENT,AIDE_LOGOPT, sfac);

    return RETOK;
#endif
#ifndef HAVE_SYSLOG
    error(0,_("This binary has no syslog support\n"));
    return RETFAIL;
#endif
  }
  
  fh=be_init(0,url,0);
  if(fh!=NULL) {
    conf->report_fd=list_append(conf->report_fd,(void*)fh);
    conf->report_url=list_append(conf->report_url,(void*)url);
    return RETOK;
  }
  
  error(0,_("Cannot open %s for writing\n"),url->value);

  return RETFAIL;

}

void error(int errorlevel,char* error_msg,...)
{
  va_list ap;
  int retval=0;
  list* r=NULL;

  if(conf->verbose_level==-1){
    if(5<errorlevel){
      return;
    }
  }else{ 
    if(conf->verbose_level<errorlevel){
      return;
    }
  }  
  

  if(conf->use_initial_errorsto){
    /* We are still using the initial errorsto */
    va_start(ap, error_msg);
    if(conf->initial_report_url==NULL){
      /* Error called before error_init(url,1) 
	 This most likely means that parsing compiled in initial
	 report url failed.
       */
      vfprintf(stderr,error_msg,ap);
      va_end(ap);
      fprintf(stderr,
	      "Initial report url broken. Reconfigure and recompile.\n");
      exit(INVALID_ARGUMENT_ERROR);
    }
#ifdef HAVE_SYSLOG
    if(conf->initial_report_url->type==url_syslog){
#ifdef HAVE_VSYSLOG
      vsyslog(SYSLOG_PRIORITY,error_msg,ap);
#else
			char buf[1024];
			vsnprintf(buf,1024,error_msg,ap);
			syslog(SYSLOG_PRIORITY,"%s",buf);
#endif
      va_end(ap);
      return;
    }
#endif
    vfprintf(conf->initial_report_fd,error_msg,ap);
    va_end(ap);
    return;
  }

#ifdef HAVE_SYSLOG
  if (conf->report_syslog!=0) {
#ifdef HAVE_VSYSLOG
    va_start(ap,error_msg);
    vsyslog(SYSLOG_PRIORITY,error_msg,ap);
    va_end(ap);
#else
		char buf[1024];
    va_start(ap,error_msg);
		vsnprintf(buf,1024,error_msg,ap);
    va_end(ap);
		syslog(SYSLOG_PRIORITY,"%s",buf);
#endif
  }
#endif

  for(r=conf->report_fd;r;r=r->next){
    va_start(ap, error_msg);
    retval=vfprintf((FILE*)r->data, error_msg,ap);
    va_end(ap);
    if(retval==0){
      va_start(ap, error_msg);
      retval=vfprintf((FILE*)r->data, error_msg,ap);
      va_end(ap);
      if(retval==0){
	exit(ERROR_WRITING_ERROR);
      }
    } 
  }

  return;
}

const char* aide_key_0=CONFHMACKEY_00;
const char* db_key_0=DBHMACKEY_00;
