/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2013, 2015-2017, 2019-2023 Rami Lehti,
 *               Pablo Virolainen, Mike Markley, Richard van den Berg,
 *               Hannes von Haugwitz
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

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "attributes.h"
#include "hashsum.h"
#include "rx_rule.h"
#include "url.h"
#include "commandconf.h"
#include "report.h"
#include "db_config.h"
#include "db_disk.h"
#include "db.h"
#include "log.h"
#include "progress.h"
#include "seltree.h"
#include "errorcodes.h"
#include "gen_list.h"
#include "getopt.h"
#include "util.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/
db_config* conf;
char* before = NULL;
char* after = NULL;

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#define NEED_LIBGCRYPT_VERSION "1.8.0"
#endif

static void usage(int exitvalue)
{
  fprintf(stdout,
	  _("AIDE %s \n\n"
	    "Usage: aide [options] command\n\n"
	    "Commands:\n"
	    "  -i, --init\t\tInitialize the database\n"
	    "  -n, --dry-init\tTraverse the file system and match each file against rule tree\n"
	    "  -C, --check\t\tCheck the database\n"
	    "  -u, --update\t\tCheck and update the database non-interactively\n"
	    "  -E, --compare\t\tCompare two databases\n\n"
	    "Miscellaneous:\n"
	    "  -D,\t\t\t--config-check\t\t\tTest the configuration file\n"
	    "  -p FILE_TYPE:PATH\t--path-check=FILE_TYPE:PATH\tMatch file type and path against rule tree\n"
	    "  -v,\t\t\t--version\t\t\tShow version of AIDE and compilation options\n"
	    "  -h,\t\t\t--help\t\t\t\tShow this help message\n\n"
	    "Options:\n"
	    "  -c CFGFILE\t--config=CFGFILE\tGet config options from CFGFILE\n"
	    "  -l REGEX\t--limit=REGEX\t\tLimit command to entries matching REGEX\n"
	    "  -B \"OPTION\"\t--before=\"OPTION\"\tBefore configuration file is read define OPTION\n"
	    "  -A \"OPTION\"\t--after=\"OPTION\"\tAfter configuration file is read define OPTION\n"
	    "  -L LEVEL\t--log-level=LEVEL\tSet log message level to LEVEL\n"
	    "  -W WORKERS\t--workers=WORKERS\tNumber of simultaneous workers (threads) for file attribute processing (i.a. hashsum calculation)\n"
	    "  \t\t--no-progress\t\tTurn progress off explicitly\n"
	    ), conf->aide_version
	  );
  
  exit(exitvalue);
}

static void sig_handler(int);

static void init_sighandler()
{
  log_msg(LOG_LEVEL_DEBUG, "initialize signal handler for SIGTERM, SIGUSR1 and SIGHUP");
  signal(SIGTERM,sig_handler);
  signal(SIGUSR1,sig_handler);
  signal(SIGHUP,sig_handler);

  return;
}

static void init_crypto_lib() {
/* libmhash does not need to be initialized */
#ifdef WITH_GCRYPT
  if(!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
      log_msg(LOG_LEVEL_ERROR, "libgcrypt is too old (need %s, have %s)", NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
      exit(VERSION_MISMATCH_ERROR);
  }
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
}

static void sig_handler(int signum)
{
    struct winsize winsize;
    char *str;
    switch(signum){
        case SIGHUP :
          str = "Caught SIGHUP. Ignoring\n";
          (void) !write(STDERR_FILENO ,str, strlen(str));
          break;
        case SIGTERM :
           str = "Caught SIGTERM. Use SIGKILL to terminate\n";
           (void) !write(STDERR_FILENO ,str, strlen(str));
           break;
        case SIGUSR1 :
           str = "Caught SIGUSR1, toggle debug level\n";
           (void) !write(STDERR_FILENO ,str, strlen(str));
           toogle_log_level(LOG_LEVEL_DEBUG);
           break;
        case SIGWINCH :
           if(ioctl(STDERR_FILENO, TIOCGWINSZ, &winsize) == -1) {
            conf->progress = 80;
           } else {
               conf->progress = winsize.ws_col;
           }
        break;
    }
}

#define EXTRA_ATTR(attribute) fprintf(stdout, "%s: %s\n", attributes[attribute].config_name, extra_attributes&ATTR(attribute)?"yes":"no");

static void print_version(void)
{
  fprintf(stdout, "AIDE %s\n\n", conf->aide_version );
  fprintf(stdout, "Compile-time options:\n%s\n", AIDECOMPILEOPTIONS);
  fprintf(stdout, "Default config values:\n");
  fprintf(stdout, "config file: %s\n", conf->config_file?conf->config_file:"<none>");
#ifdef DEFAULT_DB
  fprintf(stdout, "database_in: %s\n", DEFAULT_DB);
#else
  fprintf(stdout, "database_in: <none>\n");
#endif
#ifdef DEFAULT_DB_OUT
  fprintf(stdout, "database_out: %s\n", DEFAULT_DB_OUT),
#else
  fprintf(stdout, "database_out: <none>\n"),
#endif

  fprintf(stdout, "\nAvailable compiled-in attributes:\n");
  DB_ATTR_TYPE extra_attributes = get_groupval("X");
  EXTRA_ATTR(attr_acl)
  EXTRA_ATTR(attr_xattrs)
  EXTRA_ATTR(attr_selinux)
  EXTRA_ATTR(attr_e2fsattrs)
  EXTRA_ATTR(attr_capabilities)

  fprintf(stdout, "\nAvailable hashsum attributes:\n");
  DB_ATTR_TYPE available_hashsums = get_hashes(false);
  for (int i = 0; i < num_hashes; ++i) {
      fprintf(stdout, "%s: %s\n", attributes[hashsums[i].attribute].config_name, ATTR(hashsums[i].attribute)&available_hashsums?"yes":"no");
  }

  fprintf(stdout, "\nDefault compound groups:\n");
  char* predefined_groups[] = { "R", "L", ">", "H", "X" };
  for (unsigned long i = 0 ; i < sizeof(predefined_groups)/sizeof(char*); ++i) {
      char* str;
      fprintf(stdout, "%s: %s\n", predefined_groups[i], str = diff_attributes(0, get_groupval(predefined_groups[i])));
      free(str);
  }

  exit(0);
}

static char *append_line_to_config(char *config, char *line) {
    size_t line_length = strlen(line);
    if (config == NULL) {
        int len = (line_length + 2)*sizeof(char);
        config = checked_malloc(len);
        snprintf(config, len, "%s\n", line);
    } else {
        int len = (strlen(config) + line_length + 2) * sizeof(char);
        char *tmp = checked_malloc(len);
        snprintf(tmp, len, "%s%s\n", config, line);
        free(config);
        config=tmp;
    }
    return config;
}

#define INVALID_ARGUMENT(option, format, ...) \
        fprintf(stderr, "%s: (%s): " #format "\n", argv[0], option, __VA_ARGS__); \
        exit(INVALID_ARGUMENT_ERROR);

#define ACTION_CASE(longopt, option, _action, desc) \
      case option: { \
            if(conf->action==0){ \
                conf->action=_action; \
                log_msg(LOG_LEVEL_INFO,"(%s): %s command", longopt, desc); \
            } else { \
                INVALID_ARGUMENT(longopt, %s, "cannot have multiple commands on a single commandline") \
            } \
            break; \
        }

static void read_param(int argc,char**argv)
{
  int i=0;

  enum cmdline_args {
      ARG_NO_PROGRESS = 1,
  };

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
    { "dry-init", no_argument, NULL, 'n'},
    { "check", no_argument, NULL, 'C'},
    { "update", no_argument, NULL, 'u'},
    { "config-check", no_argument, NULL, 'D'},
    { "path-check", required_argument, NULL, 'p'},
    { "limit", required_argument, NULL, 'l'},
    { "log-level", required_argument, NULL, 'L'},
    { "workers", required_argument, NULL, 'W'},
    { "no-progress", no_argument, NULL, ARG_NO_PROGRESS},
    { "compare", no_argument, NULL, 'E'},
    { NULL,0,NULL,0 }
  };

  while(1){
    int option = getopt_long(argc, argv, "hL:V::vc:l:p:B:A:W:riCuDEn", options, &i);
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
        INVALID_ARGUMENT("--verbose", %s, "option no longer supported, use 'log_level' and 'report_level' options instead (see man aide.conf for details)")
      }
      case 'c':{
	  conf->config_file=optarg;
      log_msg(LOG_LEVEL_INFO,_("(--config): set config file to '%s'"), conf->config_file);
	break;
      }
      case 'B': {
        before = append_line_to_config(before, optarg);
        log_msg(LOG_LEVEL_INFO,_("(--before): append '%s' to before config"), optarg);
	break;
      }
      case 'A': {
        after = append_line_to_config(after, optarg);
        log_msg(LOG_LEVEL_INFO,_("(--after): append '%s' to after config"), optarg);
	break;
      }
      case 'l': {
                int pcre2_errorcode;
                PCRE2_SIZE pcre2_erroffset;
                int len = (strlen(optarg)+1) * sizeof(char);
                conf->limit=checked_malloc(len);
                strncpy(conf->limit, optarg, len);
                if((conf->limit_crx=pcre2_compile((PCRE2_SPTR) conf->limit, PCRE2_ZERO_TERMINATED, PCRE2_UTF|PCRE2_ANCHORED, &pcre2_errorcode, &pcre2_erroffset, NULL)) == NULL) {
                    PCRE2_UCHAR pcre2_error[128];
                    pcre2_get_error_message(pcre2_errorcode, pcre2_error, 128);
                    INVALID_ARGUMENT("--limit", error in regular expression '%s' at %zu: %s, conf->limit, pcre2_erroffset, pcre2_error)

                }
                conf->limit_md = pcre2_match_data_create_from_pattern(conf->limit_crx, NULL);
                if (conf->limit_md == NULL) {
                    log_msg(LOG_LEVEL_ERROR, "pcre2_match_data_create_from_pattern: failed to allocate memory");
                    exit(MEMORY_ALLOCATION_FAILURE);
                }

                int pcre2_jit = pcre2_jit_compile(conf->limit_crx, PCRE2_JIT_PARTIAL_SOFT);
                if (pcre2_jit < 0) {
                    PCRE2_UCHAR pcre2_error[128];
                    pcre2_get_error_message(pcre2_jit, pcre2_error, 128);
                    log_msg(LOG_LEVEL_NOTICE, "JIT compilation for limit '%s' failed: %s (fall back to interpreted matching)", conf->limit, pcre2_error);
                } else {
                    log_msg(LOG_LEVEL_DEBUG, "JIT compilation for limit '%s' successful", conf->limit);
                }

                log_msg(LOG_LEVEL_INFO,_("(--limit): set limit to '%s'"), conf->limit);
            break;
      }
      case 'L':{
            LOG_LEVEL level = get_log_level_from_string(optarg);
            if (level == LOG_LEVEL_UNSET) {
                INVALID_ARGUMENT("--log-level", invalid log level '%s' (see man aide.conf for details), optarg)
            } else {
                set_log_level(level);
                log_msg(LOG_LEVEL_INFO,"(--log-level): set log level to '%s'", optarg);
            }
           break;
               }
      case 'W':{
           long num_workers = do_num_workers(optarg);
           if (num_workers < 0) {
               INVALID_ARGUMENT("--workers", invalid number of workers '%s', optarg)
           }
           conf->num_workers = num_workers;
           log_msg(LOG_LEVEL_INFO,"(--workers): set number of workers to %ld (argument value: '%s')", conf->num_workers, optarg);
           break;
      }
      case ARG_NO_PROGRESS:{
           conf->progress = -1;
           log_msg(LOG_LEVEL_INFO,"(--no-progress): disable progress bar");
           break;
      }
      case 'p':{
            if(conf->action==0){
                conf->action=DO_DRY_RUN;
                log_msg(LOG_LEVEL_INFO,"(--path-check): path check command");

                if (strlen(optarg) >= 3 && optarg[1] == ':') {
                    RESTRICTION_TYPE file_type = get_restriction_from_char(*optarg);
                    if (file_type == FT_NULL) {
                        INVALID_ARGUMENT("--path-check", invalid file type '%c' (see man aide for details), *optarg)
                    } else {
                        conf->check_file_type = file_type;
                        if (optarg[2] != '/') {
                            INVALID_ARGUMENT("--path-check", '%s' needs to be an absolute path, optarg+2)
                        } else {
                            conf->check_path = checked_strdup(optarg+2);
                            log_msg(LOG_LEVEL_INFO,"(--path-check): set path to '%s' (filetype: %c)", optarg+2, get_restriction_char(conf->check_file_type));
                        }
                    }
                } else {
                    INVALID_ARGUMENT("--path-check", %s, "missing file type or path (see man aide for details)")
                }

            } else {
                INVALID_ARGUMENT("--path-check", %s, "cannot have multiple commands on a single commandline")
            }
            break;
      }
      case 'r': {
       INVALID_ARGUMENT("--report", %s, "option no longer supported, use 'report_url' config option instead (see man aide.conf for detail)")
      }
      ACTION_CASE("--init", 'i', DO_INIT, "database init")
      ACTION_CASE("--dry-init", 'n', DO_INIT|DO_DRY_RUN, "dry init")
      ACTION_CASE("--check", 'C', DO_COMPARE, "database check")
      ACTION_CASE("--update", 'u', DO_INIT|DO_COMPARE, "database update")
      ACTION_CASE("--compare", 'E', DO_DIFF, "database compare")
      ACTION_CASE("--config-check", 'D', DO_DRY_RUN, "config check")
      default: /* '?' */
	  exit(INVALID_ARGUMENT_ERROR);
      }
  }

  if(optind<argc){
    fprintf(stderr, "%s: extra parameter: '%s'\n", argv[0], argv[optind]);
    exit(INVALID_ARGUMENT_ERROR);
  }
}

static void setdefaults_before_config()
{
  DB_ATTR_TYPE X;

  conf=(db_config*)checked_malloc(sizeof(db_config));
  conf->defsyms=NULL;

  /* Setting some defaults */

  log_msg(LOG_LEVEL_INFO, "initialize rule tree");
  conf->tree=init_tree();
  conf->database_add_metadata=1;
  conf->report_detailed_init=0;
  conf->report_base16=0;
  conf->report_quiet=0;
  conf->report_append=false;
  conf->report_ignore_added_attrs = 0;
  conf->report_ignore_removed_attrs = 0;
  conf->report_ignore_changed_attrs = 0;
  conf->report_force_attrs = 0;
#ifdef WITH_E2FSATTRS
  conf->report_ignore_e2fsattrs = 0UL;
#endif

  conf->check_path=NULL;
  conf->check_file_type = FT_REG;

  conf->report_urls=NULL;
  conf->report_level=default_report_options.level;
  conf->report_format=default_report_options.format;

  conf->config_file=
#ifdef CONFIG_FILE
          CONFIG_FILE
#else
      NULL
#endif
      ;
  conf->config_version=NULL;
  conf->aide_version = AIDEVERSION;
  conf->config_check_warn_unrestricted_rules = false;
  
#ifdef WITH_ACL
  conf->no_acl_on_symlinks=0; /* zero means don't do ACLs on symlinks */
#endif
  conf->db_out_attrs = ATTR(attr_filename)|ATTR(attr_attr)|ATTR(attr_perm)|ATTR(attr_inode);

  conf->symlinks_found=0;

  conf->database_in.url = NULL;
  conf->database_in.filename=NULL;
  conf->database_in.linenumber=0;
  conf->database_in.linebuf=NULL;
  conf->database_in.fp=NULL;
#ifdef WITH_ZLIB
  conf->database_in.gzp = NULL;
#endif
  conf->database_in.lineno = 0;
  conf->database_in.fields = NULL;
  conf->database_in.num_fields = 0;
  conf->database_in.buffer_state = NULL;
  conf->database_in.mdc = NULL;
  conf->database_in.db_line = NULL;

  conf->database_out.url = NULL;
  conf->database_out.filename=NULL;
  conf->database_out.linenumber=0;
  conf->database_out.linebuf=NULL;
  conf->database_out.fp=NULL;
#ifdef WITH_ZLIB
  conf->database_out.gzp = NULL;
#endif
  conf->database_out.lineno = 0;
  conf->database_out.fields = NULL;
  conf->database_out.num_fields = 0;
  conf->database_out.buffer_state = NULL;
  conf->database_out.mdc = NULL;
  conf->database_out.db_line = NULL;

  conf->database_new.url = NULL;
  conf->database_new.filename=NULL;
  conf->database_new.linenumber=0;
  conf->database_new.linebuf=NULL;
  conf->database_new.fp=NULL;
#ifdef WITH_ZLIB
  conf->database_new.gzp = NULL;
#endif
  conf->database_new.lineno = 0;
  conf->database_new.fields = NULL;
  conf->database_new.num_fields = 0;
  conf->database_new.buffer_state = NULL;
  conf->database_new.mdc = NULL;
  conf->database_new.db_line = NULL;

  conf->db_attrs = get_hashes(false);
  
#ifdef WITH_ZLIB
  conf->gzip_dbout=0;
#endif

  conf->action=0;

  conf->num_workers = -1;

  conf->warn_dead_symlinks=0;

  conf->report_grouped=1;

  conf->report_summarize_changes=1;

  conf->root_prefix=NULL;
  conf->root_prefix_length=0;

  conf->limit=NULL;
  conf->limit_crx=NULL;

  conf->groupsyms=NULL;

  conf->start_time=time(NULL);

  conf->progress = 0;

  log_msg(LOG_LEVEL_INFO, "define default attribute definitions");

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

  DB_ATTR_TYPE GROUP_R_HASHES=0LLU;
#ifdef WITH_MHASH
  GROUP_R_HASHES=ATTR(attr_md5);
#endif
#ifdef WITH_GCRYPT
  if (gcry_fips_mode_active()) {
    char* str;
    log_msg(LOG_LEVEL_NOTICE, "libgcrypt is running in FIPS mode, the following hash(es) are not available: %s", str = diff_attributes(0, ATTR(attr_md5)));
    free(str);
  } else {
    GROUP_R_HASHES = ATTR(attr_md5);
  }
#endif

  log_msg(LOG_LEVEL_INFO, "define default groups definitions");
  do_groupdef("R",common_attrs|ATTR(attr_size)|ATTR(attr_linkname)|ATTR(attr_mtime)|ATTR(attr_ctime)|GROUP_R_HASHES|X);
  do_groupdef("L",common_attrs|ATTR(attr_linkname)|X);
  do_groupdef(">",common_attrs|ATTR(attr_size)|ATTR(attr_growing)|ATTR(attr_linkname)|X);
  do_groupdef("H",get_hashes(false));
  do_groupdef("X",X);
  do_groupdef("E",0);

}

static void setdefaults_after_config()
{
  int linenumber=1;

#ifdef DEFAULT_DB
  if(conf->database_in.url==NULL){
    do_dbdef(DB_TYPE_IN, DEFAULT_DB, linenumber++, "(default)",  NULL);
  }
#endif
#ifdef DEFAULT_DB_OUT
  if(conf->database_out.url==NULL){
    do_dbdef(DB_TYPE_OUT, DEFAULT_DB_OUT, linenumber++, "(default)",  NULL);
  }
#endif

  if(conf->root_prefix==NULL){
    do_rootprefix("" , linenumber++, "(default)",  NULL);
  }

  if(conf->report_urls==NULL){
    do_repurldef("stdout" , linenumber++, "(default)",  NULL);
  }

  if(conf->action==0){
    conf->action=DO_COMPARE;
  }

  if(conf->num_workers < 0) {
      conf->num_workers = 1;
      log_msg(LOG_LEVEL_CONFIG, "(default): set 'num_workers' option to %lu", conf->num_workers);
  }

  if (is_log_level_unset()) {
          set_log_level(LOG_LEVEL_WARNING);
  };
}

int main(int argc,char**argv)
{
  int errorno=0;

  log_init();

#ifdef WITH_LOCALE
  setlocale(LC_ALL,"");
  bindtextdomain(PACKAGE,LOCALEDIR);
  textdomain(PACKAGE);
#endif
  umask(0177);
  init_sighandler();
  init_crypto_lib();

  setdefaults_before_config();

  log_msg(LOG_LEVEL_INFO, "read command line parameters");
  read_param(argc,argv);

  if (!(conf->action&DO_DRY_RUN)) {
      if (conf->progress >= 0) {
          if (isatty(STDERR_FILENO)) {
              log_msg(LOG_LEVEL_DEBUG, "enable progress bar (stderr refers to a terminal)");
              if (progress_start()) {
                  log_msg(LOG_LEVEL_DEBUG, "initialize signal handler for SIGWINCH");
                  signal(SIGWINCH,sig_handler);
              }
          } else {
              log_msg(LOG_LEVEL_DEBUG, "isatty() failed for 'STDERR_FILENO': %s", strerror(errno));
              log_msg(LOG_LEVEL_INFO, "disable progress bar (stderr does not refer to a terminal)");
          }
      }
  }

  /* get hostname */
  conf->hostname = checked_malloc(sizeof(char) * MAXHOSTNAMELEN + 1);
  if (gethostname(conf->hostname,MAXHOSTNAMELEN) == -1) {
      log_msg(LOG_LEVEL_WARNING,"gethostname failed: %s", strerror(errno));
      free(conf->hostname);
      conf->hostname = NULL;
  } else {
      log_msg(LOG_LEVEL_DEBUG, "hostname: '%s'", conf->hostname);
  }

  log_msg(LOG_LEVEL_INFO, "parse configuration");
  progress_status(PROGRESS_CONFIG, NULL);
  errorno=parse_config(before, conf->config_file, after);
  if (errorno==RETFAIL){
    exit(INVALID_CONFIGURELINE_ERROR);
  }
  free (before);
  free (after);

  setdefaults_after_config();

  log_msg(LOG_LEVEL_CONFIG, "report_urls:");
  log_report_urls(LOG_LEVEL_CONFIG);

  log_msg(LOG_LEVEL_RULE, "rule tree:");
  log_tree(LOG_LEVEL_RULE, conf->tree, 0);

  if (conf->action&DO_INIT && is_tree_empty(conf->tree)) {
      log_msg(LOG_LEVEL_WARNING, "rule tree is empty, no files will be added to the database");
  }

  if (conf->check_path) {
      rx_rule* rule = NULL;
      match_result match = check_rxtree(conf->check_path, conf->tree, &rule, conf->check_file_type, "disk (path-check)");
      print_match(conf->check_path, rule, match, conf->check_file_type);
      switch (match) {
          case RESULT_PARTIAL_LIMIT_MATCH:
          case RESULT_NO_LIMIT_MATCH:
              exit(2);
          case RESULT_EQUAL_MATCH:
          case RESULT_SELECTIVE_MATCH:
              exit(0);
          case RESULT_NO_MATCH:
          case RESULT_PARTIAL_MATCH:
              exit(1);
      }
  }

  /* Let's do some sanity checks for the config */
  if (conf->action&(DO_DIFF|DO_COMPARE) && !(conf->database_in.url)) {
    log_msg(LOG_LEVEL_ERROR,_("missing 'database_in', config option is required"));
    exit(INVALID_ARGUMENT_ERROR);
  }
  if (!(conf->action&DO_DRY_RUN) && conf->action&DO_INIT && !(conf->database_out.url)) {
    log_msg(LOG_LEVEL_ERROR,_("missing 'database_out', config option is required"));
    exit(INVALID_ARGUMENT_ERROR);
  }
  if(conf->database_in.url && conf->database_out.url && cmpurl(conf->database_in.url,conf->database_out.url)==RETOK){
      log_msg(LOG_LEVEL_NOTICE, "input and output database URLs are the same: '%s'", (conf->database_in.url)->value);
    if((conf->action&DO_INIT)&&(conf->action&DO_COMPARE)){
      log_msg(LOG_LEVEL_ERROR,_("input and output database urls cannot be the same "
	    "when doing database update"));
      exit(INVALID_ARGUMENT_ERROR);
    }
    if(conf->action&DO_DIFF){
      log_msg(LOG_LEVEL_ERROR,_("both input databases cannot be the same "
		"when doing database compare"));
      exit(INVALID_ARGUMENT_ERROR);
    }
  };
  if((conf->action&DO_DIFF)&&(!(conf->database_new.url)||!(conf->database_in.url))){
    log_msg(LOG_LEVEL_ERROR,_("must have both input databases defined for "
	      "database compare"));
    exit(INVALID_ARGUMENT_ERROR);
  }

  /* ensure size attribute is added to db_out_attrs if sizeg or growing attribute is set */
  if (conf->db_out_attrs & ATTR(attr_sizeg) || conf->db_out_attrs & ATTR(attr_growing)) {
        conf->db_out_attrs |=ATTR(attr_size);
  }

  if (conf->action&DO_INIT && conf->action&DO_DRY_RUN) {
      log_msg(LOG_LEVEL_INFO, "scan file system (dry-run)");
      db_scan_disk(true);
      exit (0);
  }

  if (!(conf->action&DO_DRY_RUN)) {

  if (!init_report_urls()) {
      exit(INVALID_CONFIGURELINE_ERROR);
  }

  if (conf->action&(DO_INIT|DO_COMPARE) && conf->root_prefix_length > 0) {
      DIR *dir;
      if((dir = opendir(conf->root_prefix)) != NULL) {
          closedir(dir);
      } else {
          log_msg(LOG_LEVEL_ERROR,"opendir() for root_prefix %s failed: %s", conf->root_prefix, strerror(errno));
          exit(INVALID_CONFIGURELINE_ERROR);
      }
  }
    if(conf->action&DO_INIT){
      if(db_init(&(conf->database_out), false,
#ifdef WITH_ZLIB
        conf->gzip_dbout
#else
        false
#endif
       ) == RETFAIL) {
	exit(IO_ERROR);
      }
      if(db_writespec(conf)==RETFAIL){
	log_msg(LOG_LEVEL_ERROR,_("Error while writing database. Exiting.."));
	exit(IO_ERROR);
      }
    }
    if((conf->action&DO_COMPARE)||(conf->action&DO_DIFF)){
      if(db_init(&(conf->database_in), true, false)==RETFAIL)
	exit(IO_ERROR);
    }
    if(conf->action&DO_DIFF){
      if(db_init(&(conf->database_new), true, false)==RETFAIL)
	exit(IO_ERROR);
    }

    if((conf->action&DO_INIT || conf->action&DO_COMPARE) && conf->num_workers){
      if(db_disk_start_threads()==RETFAIL)
          exit(THREAD_ERROR);
    }

    populate_tree(conf->tree);

    if((conf->action&DO_INIT || conf->action&DO_COMPARE) && conf->num_workers){
      if(db_disk_finish_threads() == RETFAIL)
          exit(THREAD_ERROR);
    }

    if(conf->action&DO_INIT) {
        progress_status(PROGRESS_WRITEDB, NULL);
        log_msg(LOG_LEVEL_INFO, "write new entries to database: %s:%s", get_url_type_string((conf->database_out.url)->type), (conf->database_out.url)->value);
        write_tree(conf->tree);
    }
    progress_stop();

    db_close();

    conf->end_time=time(NULL);

    log_msg(LOG_LEVEL_INFO, "generate reports");

    int exitcode = gen_report(conf->tree);

    log_msg(LOG_LEVEL_INFO, "exit AIDE with exit code '%d'", exitcode);

    exit(exitcode);
  }
  return RETOK;
}
// vi: ts=8 sw=8
