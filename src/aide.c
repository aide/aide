/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999,2000,2001,2002 Rami Lehti, Pablo Virolainen
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
#include <time.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "md.h"
#include "commandconf.h"
#include "compare_db.h"
#include "db_config.h"
#include "db_file.h"
#include "do_md.h"
#include "report.h"
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

void usage(int exitvalue)
{
  fprintf(stderr, 
	  _("Aide,\n"
	    "Usage: aide <options> command\n"
	    "\n"
	    "Commands:\n"
	    "-i\n--init\n\tInitialize the database\n"
	    "-C\n--check\n\tCheck the database\n"
	    "-u\n--update\n\t"
	    "Check and update the database non-interactively.\n"
	    "--compare\n\tCompare two databases\n"
	    "-v\n--version\n\t"
	    "Show version of AIDE and compilation options.\n"
	    "-h\n--help\n\tShow this help message\n"
	    "Options:\n"
	    "-c config_file\n--config=config_file\n\t"
	    "Get config options from config_file.\n"
	    "-B \"config_stuff\"\n--before=\"config_stuff\"\n\t"
	    "Before config_file is read use these options.\n"
	    "-A \"config_stuff\"\n--after=\"config_stuff\"\n\t"
	    "After config_file is read use these options.\n"
	    "-r reporter\n--report=reporter\n\t"
	    "Where report output is written to.\n"
	    "-Vverbosity_level\n--verbose=verbosity_level\n\t"
	    "Level of debug messages.\n"
	    "--config-check just read config-file\n"
	    "\n")
	  );
  
  exit(exitvalue);
}

void print_version(void)
{
  fprintf(stderr,
	  "Aide, version " AIDEVERSION "\n"
	  "Compiled with the following options\n" AIDECOMPILEOPTIONS "\n");
  exit(0);
}

int read_param(int argc,char**argv)
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
    { "report", required_argument, NULL, 'r'},
    { "init", no_argument, NULL, 'i'},
    { "check", no_argument, NULL, 'C'},
    { "update", no_argument, NULL, 'u'},
    { "config-check", no_argument, NULL, 'D'},
    { "compare", no_argument, NULL, 'E'},
    { NULL }
  };

  while(1){
    option = getopt_long(argc, argv, "hV::vc:B:A:r:iCuDE", options, &i);
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

      case 'r': {
	if(optarg!=NULL) {
	  do_repurldef(optarg);
	}else {
	  error(0,_("-r must have an argument\n"));
	}
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

void setdefaults_before_config()
{
  char* urlstr=INITIALERRORSTO;
  url_t* u=NULL;
  char* s=(char*)malloc(sizeof(char)*MAXHOSTNAMELEN+1);

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
  conf->report_db=0;  
  conf->tree=NULL;
  conf->config_check=0;
  conf->verbose_level=-1;
  conf->use_initial_errorsto=1;
  conf->report_url=NULL;
  conf->report_fd=NULL;
  conf->report_syslog=0;
  conf->report_db=0;

  u=parse_url(urlstr);
  error_init(u,1);

  conf->config_file=CONFIG_FILE;
#ifdef WITH_MHASH
  conf->do_configmd=0;
  conf->confmd=NULL;
  conf->confhmactype=CONFIGHMACTYPE;
  conf->old_confmdstr=NULL;
  conf->do_dbnewmd=0;
  conf->do_dboldmd=0;
  conf->dbhmactype=DBHMACTYPE;
  conf->old_dbnewmdstr=NULL;
  conf->old_dboldmdstr=NULL;
  conf->dbnewmd=NULL;
  conf->dboldmd=NULL;
#endif
  conf->db_out_order=(DB_FIELD*)malloc(sizeof(DB_FIELD)*db_unknown);
  conf->db_out_size=1;
  conf->db_out_order[0]=db_filename;
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
#ifdef WITH_ZLIB
  conf->db_gzin=0;
  conf->db_gznew=0;
  conf->gzip_dbout=0;
#endif

  conf->action=0;
  conf->catch_mmap=0;

  conf->warn_dead_symlinks=0;

  conf->selrxlst=NULL;
  conf->equrxlst=NULL;
  conf->negrxlst=NULL;

  conf->groupsyms=NULL;

  conf->start_time=time(&(conf->start_time));

  
  do_groupdef("p",DB_PERM);
  do_groupdef("i",DB_INODE);
  do_groupdef("I",DB_CHECKINODE);
  do_groupdef("n",DB_LNKCOUNT);
  do_groupdef("u",DB_UID);
  do_groupdef("g",DB_GID);
  do_groupdef("s",DB_SIZE);
  do_groupdef("S",DB_SIZEG);
  do_groupdef("b",DB_BCOUNT);
  do_groupdef("m",DB_MTIME);
  do_groupdef("c",DB_CTIME);
  do_groupdef("a",DB_ATIME);
  do_groupdef("md5",DB_MD5);
  do_groupdef("tiger",DB_TIGER);
  do_groupdef("sha1",DB_SHA1);
  do_groupdef("rmd160",DB_RMD160);
#ifdef WITH_ACL
  do_groupdef("acl",DB_ACL);
#endif
#ifdef WITH_MHASH
  do_groupdef("crc32",DB_CRC32);
  /*
    crc32b is same than crc32
    do_groupdef("crc32b",DB_CRC32B);
  */
  do_groupdef("haval",DB_HAVAL);
  do_groupdef("gost",DB_GOST);
#endif

  do_groupdef("R",DB_PERM|DB_INODE|DB_LNKCOUNT|DB_UID|DB_GID|DB_SIZE|
	      DB_MTIME|DB_CTIME|DB_MD5);
  do_groupdef("L",DB_PERM|DB_INODE|DB_LNKCOUNT|DB_UID|DB_GID);
  do_groupdef(">",DB_PERM|DB_INODE|DB_LNKCOUNT|DB_UID|DB_GID|DB_SIZEG);
  do_groupdef("E",0);
  
  
}

void setdefaults_after_config()
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
  if(conf->report_url==NULL){
    url_t* u=NULL;

    /* Don't free this one because conf->report_url needs it */
    u=(url_t*)malloc(sizeof(url_t));
    u->type=url_stdout;
    u->value="";
    error_init(u,0);
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
  byte* dig=NULL;
  char* digstr=NULL;

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
  
  /*
    This won't actualy work, because conf->tree is not constructed.
    Now we construct it. And we have THE tree.
   */
  
  conf->tree=gen_tree(conf->selrxlst,conf->negrxlst,conf->equrxlst);
  
  
  /*
    Just for debugging purposes..
   */
  /*
  db_disk_init();
  {
    int i=0;
    db_line* l=db_readline_disk();
    printf("Entering to readloop\n");
    while (l!=NULL) {
      i++;
      printf("%i:%s\n",i,l->filename);
      l=db_readline_disk();
    }
    printf("Readloop ended\n");
    exit(0);
  }  
  */  
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
#ifdef WITH_MHASH
  if(conf->config_check&&FORCECONFIGMD){
    error(0,"Can't give config checksum when compiled with --enable-forced_configmd\n");
    exit(INVALID_ARGUMENT_ERROR);
  }
  
  if((conf->do_configmd||conf->config_check)&& conf->confmd!=0){
    /* The patch automatically adds a newline so will also have to add it. */
    if(newlinelastinconfig==0){
      mhash(conf->confmd,"\n",1);
    };
    mhash(conf->confmd, NULL,0);
    dig=(byte*)malloc(sizeof(byte)*mhash_get_block_size(conf->confhmactype));
    mhash_deinit(conf->confmd,(void*)dig);
    digstr=encode_base64(dig,mhash_get_block_size(conf->confhmactype));

    if(!conf->config_check||FORCECONFIGMD){
      if(strncmp(digstr,conf->old_confmdstr,strlen(digstr))!=0){
	/* FIXME Don't use error and add configurability */
	error(0,_("Config checksum mismatch\n"));
	exit(INVALID_ARGUMENT_ERROR);
      }
    }
  } else {
    if(FORCECONFIGMD){
      error(0,_("Config checksum not found. Exiting..\n"));
      exit(INVALID_ARGUMENT_ERROR);
    }
  }
#endif
  conf->use_initial_errorsto=0;
  if (!conf->config_check) {
  
    long totalchanges=0;
    long stat[5]={1,0,0,0,0};
    if(conf->action&DO_INIT){
      if(db_init(DB_WRITE)==RETFAIL) {
	exit(IO_ERROR);
      }
      /* FIXME db_out_order info should be taken from tree/config */ 
      /* update_db_out_order(-1); OOPS. It was allready done by append_rxlist
	 :) */
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

    /* First terse report */
    totalchanges=report_tree(conf->tree,0,stat);
    if(totalchanges>0){
      stat[0]=1;
      report_tree(conf->tree,1,stat);
      stat[0]=1;
      report_tree(conf->tree,2,stat);
      stat[0]=1;
      report_tree(conf->tree,3,stat);
      /* Then detailed list of changes */
      stat[0]=1;
      report_tree(conf->tree,4,stat);
    } else {
      if (conf->verbose_level >= 5) {
        printf("\nAIDE, version " AIDEVERSION "\n\n");
        if(conf->action&DO_COMPARE) {
          printf("### All files match AIDE database. Looks okay!\n\n");
        }
        if(conf->action&DO_INIT) {
	  if(conf->action&DO_COMPARE)
            printf("### New AIDE database written to %s\n\n",conf->db_out_url->value);
	  else
            printf("### AIDE database at %s initialized.\n\n",conf->db_out_url->value);
        }
      }
    }
    db_close(conf);
    
    exit(RETOK);
      
  }else {
#ifdef WITH_MHASH
    if(conf->confmd){
      error(0,"Config checked. Use the following to patch your config file.\n");
      error(0,"0a1\n");
      if(newlinelastinconfig==1){
	error(0,"> @@begin_config %s\n%ia%i\n> @@end_config\n",digstr,conf_lineno-1,conf_lineno+1);
      }else {
	error(0,"> @@begin_config %s\n%ia%i\n> @@end_config\n",digstr,conf_lineno,conf_lineno+2);
      }
      free(dig);
      free(digstr);
    }
#endif
  }
  return RETOK;
}
const char* aide_key_3=CONFHMACKEY_03;
const char* db_key_3=DBHMACKEY_03;

