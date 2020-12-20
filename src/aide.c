/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2010-2013,2015,2016,2019,2020 Rami Lehti, Pablo
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "md.h"
#include "commandconf.h"
#include "report.h"
#include "db_config.h"
#include "db_file.h"
#include "do_md.h"
#include "error.h"
#include "gen_list.h"
#include "getopt.h"
#include "list.h"
#include "util.h"
#include "base64.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/
db_config* conf;

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

static void usage(int exitvalue)
{
  fprintf(stderr, 
	  _("Aide " AIDEVERSION" \n\n"
	    "Usage: aide [options] command\n\n"
	    "Commands:\n"
	    "  -i, --init\t\tInitialize the database\n"
	    "  -C, --check\t\tCheck the database\n"
	    "  -u, --update\t\tCheck and update the database non-interactively\n"
	    "  -E, --compare\t\tCompare two databases\n\n"
	    "Miscellaneous:\n"
	    "  -D, --config-check\tTest the configuration file\n"
	    "  -v, --version\t\tShow version of AIDE and compilation options\n"
	    "  -h, --help\t\tShow this help message\n\n"
	    "Options:\n"
	    "  -c [cfgfile]\t--config=[cfgfile]\tGet config options from [cfgfile]\n"
	    "  -l [REGEX]\t--limit=[REGEX]\t\tLimit command to entries matching [REGEX]\n"
	    "  -B \"OPTION\"\t--before=\"OPTION\"\tBefore configuration file is read define OPTION\n"
	    "  -A \"OPTION\"\t--after=\"OPTION\"\tAfter configuration file is read define OPTION\n"
	    "  -V[level]\t--verbose=[level]\tSet debug message level to [level]\n"
	    "\n")
	  );
  
  exit(exitvalue);
}

static void print_version(void)
{
  fprintf(stderr,
	  "Aide " AIDEVERSION "\n\n"
	  "Compiled with the following options:\n\n" AIDECOMPILEOPTIONS "\n");
  exit(0);
}

static int read_param(int argc,char**argv)
{
  int option = -1;
  char* err=NULL;
  int i=0;
  

  static struct option options[] =
  {
    { "help", no_argument, NULL, 'h' },
    { "verbose", optional_argument, NULL, 'V'},
    { "version", no_argument, NULL, 'v'},
    { "config", required_argument, NULL, 'c'},
    { "before", required_argument, NULL, 'B'},
    { "after", required_argument, NULL, 'A'},
    { "report", no_argument, NULL, 'r'},
    { "init", no_argument, NULL, 'i'},
    { "check", no_argument, NULL, 'C'},
    { "update", no_argument, NULL, 'u'},
    { "config-check", no_argument, NULL, 'D'},
    { "limit", required_argument, NULL, 'l'},
    { "compare", no_argument, NULL, 'E'},
    { NULL,0,NULL,0 }
  };

  while(1){
    option = getopt_long(argc, argv, "hV::vc:l:B:A:riCuDE", options, &i);
    if(option==-1)
      break;
    switch(option)
      {
      case 'h':{
	usage(0);
	break;
      }
      case 'v':{
	print_version();
	break;
      }
      case 'V':{
	if(optarg!=NULL){
	  conf->verbose_level=strtol(optarg,&err,10);
	  if(*err!='\0' || conf->verbose_level>255 || conf->verbose_level<0 || 
	     errno==ERANGE){
	    error(0, _("Illegal verbosity level:%s\n"),optarg);
	    exit(INVALID_ARGUMENT_ERROR);
	  }
	  error(230,_("Setting verbosity to %s\n"),optarg);
	}else{
	  conf->verbose_level=20;
	}
	break;
      }
      case 'c':{
	if(optarg!=NULL){
	  conf->config_file=optarg;
	}else{
	  error(0,_("No config-file name given!\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	}
	break;
      }
      case 'B': {
	if (optarg!=NULL) {
	  int errorno=commandconf('B',optarg);
	  if (errorno!=0){
	    error(0,_("Configuration error in before statement:%s\n"),optarg);
	    exit(INVALID_CONFIGURELINE_ERROR);
	  }
	} else {
	  error(0,_("-B must have a parameter\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	}
	break;
      }
      case 'A': {
	if (optarg!=NULL) {
	  int errorno=commandconf('A',optarg);
	  if (errorno!=0){
	    error(0,_("Configuration error in after statement:%s\n"),optarg);
	    exit(INVALID_CONFIGURELINE_ERROR);
	  }
	} else {
	  error(0,_("-A must have a parameter\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	}
	break;
      }
      case 'l': {
            if (optarg!=NULL) {
                const char* pcre_error;
                int pcre_erroffset;
                conf->limit=malloc(strlen(optarg)+1);
                strcpy(conf->limit,optarg);
                if((conf->limit_crx=pcre_compile(conf->limit, PCRE_ANCHORED, &pcre_error, &pcre_erroffset, NULL)) == NULL) {
                    error(0,_("Error in limit regexp '%s' at %i: %s\n"), conf->limit, pcre_erroffset, pcre_error);
                    exit(INVALID_ARGUMENT_ERROR);
                }
                error(200,_("Limit set to '%s'\n"), conf->limit);
            } else {
                error(0,_("-l must have an argument\n"));
                exit(INVALID_ARGUMENT_ERROR);
            }
            break;
      }
      case 'r': {
       error(0,_("option '%s' is no longer supported, use 'report_url' config option (see man 5 aide.conf for details)\n"), argv[optind-1]);
       exit(INVALID_ARGUMENT_ERROR);
       break;
      }
      case 'i': {
	if(conf->action==0){
	  conf->action=DO_INIT;
	}else {
	  error(0,
		_("Cannot have multiple commands on a single commandline.\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	};
	break;
      }
      case 'C': {
	if(conf->action==0){
	  conf->action=DO_COMPARE;
	}else {
	  error(0,
		_("Cannot have multiple commands on a single commandline.\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	};
	break;
      }
      case 'u': {
	if(conf->action==0){
	  conf->action=DO_INIT|DO_COMPARE;
	}else {
	  error(0,
		_("Cannot have multiple commands on a single commandline.\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	};
	break;
      }
      case 'E': {
	if(conf->action==0){
	  conf->action=DO_DIFF;
	}else {
	  error(0,
		_("Cannot have multiple commands on a single commandline.\n"));
	  exit(INVALID_ARGUMENT_ERROR);
	};
	break;
      }
      case 'D': {
	conf->config_check=1;
	break;
      }
      default:
	error(0,_("Unknown option given. Exiting\n"));
	  exit(INVALID_ARGUMENT_ERROR);
      }
  }

  if(optind<argc){
    error(0,_("Extra parameters given\n"));
    exit(INVALID_ARGUMENT_ERROR);
  }
  return RETOK;
}

static void setdefaults_before_config()
{
  char* s=(char*)malloc(sizeof(char)*MAXHOSTNAMELEN+1);
  DB_ATTR_TYPE X;

  /*
    Set up the hostname
  */
  conf=(db_config*)malloc(sizeof(db_config));
  conf->defsyms=NULL;
  
  if (gethostname(s,MAXHOSTNAMELEN)==-1) {
    error(0,_("Couldn't get hostname"));
    free(s);
  } else {
    s=(char*)realloc((void*)s,strlen(s)+1);
    do_define("HOSTNAME",s);
  }
  
  /* Setting some defaults */
  conf->tree=init_tree();
  conf->config_check=0;
  conf->verbose_level=-1;
  conf->database_add_metadata=1;
  conf->report_detailed_init=0;
  conf->report_base16=0;
  conf->report_quiet=0;
  conf->report_ignore_added_attrs = 0;
  conf->report_ignore_removed_attrs = 0;
  conf->report_ignore_changed_attrs = 0;
  conf->report_force_attrs = 0;
#ifdef WITH_E2FSATTRS
  conf->report_ignore_e2fsattrs = 0UL;
#endif

  conf->report_urls=NULL;
  conf->report_level=REPORT_LEVEL_CHANGED_ATTRIBUTES;

  conf->config_file=CONFIG_FILE;
  conf->config_version=NULL;
  
#ifdef WITH_ACL
  conf->no_acl_on_symlinks=0; /* zero means don't do ACLs on symlinks */
#endif
  conf->db_out_attrs = ATTR(attr_filename)|ATTR(attr_attr)|ATTR(attr_perm)|ATTR(attr_inode);

  conf->symlinks_found=0;
  conf->db_in_size=0;
  conf->db_in_order=NULL;
  conf->db_in_url=NULL;
  conf->db_in=NULL;
  conf->db_new_size=0;
  conf->db_new_order=NULL;
  conf->db_new_url=NULL;
  conf->db_new=NULL;
  conf->db_out_url=NULL;
  conf->db_out=NULL;

  conf->mdc_in=NULL;
  conf->mdc_out=NULL;

  conf->line_db_in=NULL;
  conf->line_db_out=NULL;

  conf->db_attrs = get_hashes();
  
#ifdef WITH_ZLIB
  conf->db_gzin=0;
  conf->db_gznew=0;
  conf->gzip_dbout=0;
  conf->db_gzout=0;
#endif

  conf->action=0;
  conf->catch_mmap=0;

  conf->warn_dead_symlinks=0;

  conf->grouped=1;

  conf->summarize_changes=1;

  conf->root_prefix="";
  conf->root_prefix_length=0;

  conf->limit=NULL;
  conf->limit_crx=NULL;

  conf->groupsyms=NULL;

  conf->start_time=time(&(conf->start_time));

  for (ATTRIBUTE i = 0 ; i < num_attrs ; ++i) {
      if (attributes[i].config_name) {
          do_groupdef(attributes[i].config_name, attributes[i].attr);
      }
  }

  X=0LLU;
#ifdef WITH_ACL
  X|=ATTR(attr_acl);
#endif
#ifdef WITH_SELINUX
  X|=ATTR(attr_selinux);
#endif
#ifdef WITH_XATTR
  X|=ATTR(attr_xattrs);
#endif
#ifdef WITH_E2FSATTRS
  X|=ATTR(attr_e2fsattrs);
#endif
#ifdef WITH_CAPABILITIES
  X|=ATTR(attr_capabilities);
#endif

  DB_ATTR_TYPE common_attrs = ATTR(attr_perm)|ATTR(attr_ftype)|ATTR(attr_inode)|ATTR(attr_linkcount)|ATTR(attr_uid)|ATTR(attr_gid);

  do_groupdef("R",common_attrs|ATTR(attr_size)|ATTR(attr_linkname)|ATTR(attr_mtime)|ATTR(attr_ctime)
#if defined(WITH_MHASH) || defined(WITH_GCRYPT)
          |ATTR(attr_md5)
#endif
          |X);
  do_groupdef("L",common_attrs|ATTR(attr_linkname)|X);
  do_groupdef(">",common_attrs|ATTR(attr_sizeg)|ATTR(attr_linkname)|X);
  do_groupdef("X",X);
  do_groupdef("E",0);

}

static void setdefaults_after_config()
{
  if(conf->db_in_url==NULL){
    url_t* u=NULL;
    u=(url_t*)malloc(sizeof(url_t));
    u->type=url_file;
    u->value=DEFAULT_DB;
    conf->db_in_url=u;
  }
  if(conf->db_out_url==NULL){
    url_t* u=NULL;
    u=(url_t*)malloc(sizeof(url_t));
    u->type=url_file;
    u->value=DEFAULT_DB_OUT;
    conf->db_out_url=u;
  }

  if(conf->report_urls==NULL){
    url_t* u = malloc(sizeof(url_t)); /* not to be freed, needed for reporting */
    u->type=url_stdout;
    u->value=NULL;
    add_report_url(u);
  }

  if(conf->action==0){
    conf->action=DO_COMPARE;
  }
  if(conf->verbose_level==-1){
    conf->verbose_level=5;
  }
}


int main(int argc,char**argv)
{
  int errorno=0;

#ifdef USE_LOCALE
  setlocale(LC_ALL,"");
  bindtextdomain(PACKAGE,LOCALEDIR);
  textdomain(PACKAGE);
#endif
  umask(0177);
  init_sighandler();

  setdefaults_before_config();

  if(read_param(argc,argv)==RETFAIL){
    error(0, _("Invalid argument\n") );
    exit(INVALID_ARGUMENT_ERROR);
  }
  
  errorno=commandconf('C',conf->config_file);

  errorno=commandconf('D',"");
  if (errorno==RETFAIL){
    error(0,_("Configuration error\n"));
    exit(INVALID_CONFIGURELINE_ERROR);
  }

  setdefaults_after_config();
  
  print_tree(conf->tree);
  
  
  /* Let's do some sanity checks for the config */
  if(cmpurl(conf->db_in_url,conf->db_out_url)==RETOK){
    error(4,_("WARNING:Input and output database urls are the same.\n"));
    if((conf->action&DO_INIT)&&(conf->action&DO_COMPARE)){
      error(0,_("Input and output database urls cannot be the same "
	    "when doing database update\n"));
      exit(INVALID_ARGUMENT_ERROR);
    }
    if(conf->action&DO_DIFF){
      error(0,_("Both input databases cannot be the same "
		"when doing database compare\n"));
      exit(INVALID_ARGUMENT_ERROR);
    }
  };
  if((conf->action&DO_DIFF)&&(!(conf->db_new_url)||!(conf->db_in_url))){
    error(0,_("Must have both input databases defined for "
	      "database compare.\n"));
    exit(INVALID_ARGUMENT_ERROR);
  }
  if (conf->action&(DO_INIT|DO_COMPARE) && conf->root_prefix_length > 0) {
      DIR *dir;
      if((dir = opendir(conf->root_prefix)) != NULL) {
          closedir(dir);
      } else {
          char* er=strerror(errno);
          if (er!=NULL) {
              error(0,"opendir() for root prefix %s failed: %s\n", conf->root_prefix,er);
          } else {
              error(0,"opendir() for root prefix %s failed: %i\n", conf->root_prefix,errno);
          }
          exit(INVALID_ARGUMENT_ERROR);
      }
  }
  if (!conf->config_check) {
    if(conf->action&DO_INIT){
      if(db_init(DB_WRITE)==RETFAIL) {
	exit(IO_ERROR);
      }
      if(db_writespec(conf)==RETFAIL){
	error(0,_("Error while writing database. Exiting..\n"));
	exit(IO_ERROR);
      }
    }
    if((conf->action&DO_INIT)||(conf->action&DO_COMPARE)){
      if(db_init(DB_DISK)==RETFAIL)
	exit(IO_ERROR);
    }
    if((conf->action&DO_COMPARE)||(conf->action&DO_DIFF)){
      if(db_init(DB_OLD)==RETFAIL)
	exit(IO_ERROR);
    }
    if(conf->action&DO_DIFF){
      if(db_init(DB_NEW)==RETFAIL)
	exit(IO_ERROR);
    }
      
    populate_tree(conf->tree);
    db_close();
    
    exit(gen_report(conf->tree));
    
  }
  return RETOK;
}
// vi: ts=8 sw=8
