/* The name and version of this software distribution. These
 * originates from AM_INIT_AUTOMAKE in the configure.in file. */
#define PACKAGE "configure-generated"
#define VERSION "configure-generated"
 
/* Define if zlib should be used */
#undef WITH_ZLIB

/* Define if mhash should be used */
#undef WITH_MHASH

/* Define if gcrypt should be used */
#undef WITH_GCRYPT
 
/* Define if PostgrsSQL should used */
#undef WITH_PSQL
 
/* Define if zlib.h is present */
#undef HAVE_ZLIB_H

/* syslog() available? */
#undef HAVE_SYSLOG

/* Define if LOCALE support should be used */
#undef USE_LOCALE

/* Localedir to use */
#undef LOCALEDIR

/* Defined if we use bundled regexps */
#undef REGEX

/* Default configuration file */
#define CONFIG_FILE "./aide.conf" 
#define DEFAULT_DB "./aide.db"
#define DEFAULT_DB_OUT "./aide.db.new"

#undef HAVE_BYTE_TYPEDEF
#undef HAVE_USHORT_TYPEDEF
#undef HAVE_ULONG_TYPEDEF
#undef HAVE_U16_TYPEDEF
#undef HAVE_U32_TYPEDEF

#undef BIG_ENDIAN_HOST
#undef LITTLE_ENDIAN_HOST

/* AIDE compile options */
#undef AIDECOMPILEOPTIONS

#undef HAVE_readdir
#undef HAVE_readdir_r
#undef HAVE_mmap
#undef HAVE_stricmp
#undef HAVE_ustat
#undef ACLLIB

/* Defines for LSTAT */
#define AIDE_LSTAT_FUNC lstat
#define AIDE_FSTAT_FUNC fstat
#define AIDE_STAT_FUNC stat
#define AIDE_STAT_TYPE stat
#define AIDE_INO_TYPE ino_t
#define AIDE_OFF_TYPE off_t
#define AIDE_BLKCNT_TYPE blkcnt_t

/* Defines for READDIR64 */
#define AIDE_READDIR_FUNC readdir
#define AIDE_READDIR_R_FUNC readdir_r
#define AIDE_DIRENT_TYPE dirent


/* Define if you want to try ACL on solaris */
#undef WITH_SUN_ACL
#undef WITH_ACL

#define AIDE_SYSLOG_FACILITY LOG_LOCAL0
#define AIDE_IDENT "aide"
#define AIDE_LOGOPT LOG_CONS
#define SYSLOG_PRIORITY LOG_NOTICE

#define CONFIGHMACTYPE MHASH_MD5

#define CONFHMACKEY_00 ""
#define CONFHMACKEY_01 ""
#define CONFHMACKEY_02 ""
#define CONFHMACKEY_03 ""
#define CONFHMACKEY_04 ""
#define CONFHMACKEY_05 ""
#define CONFHMACKEY_06 ""
#define CONFHMACKEY_07 ""
#define CONFHMACKEY_08 ""
#define CONFHMACKEY_09 ""

#define DBHMACTYPE MHASH_MD5

#define DBHMACKEY_00 ""
#define DBHMACKEY_01 ""
#define DBHMACKEY_02 ""
#define DBHMACKEY_03 ""
#define DBHMACKEY_04 ""
#define DBHMACKEY_05 ""
#define DBHMACKEY_06 ""
#define DBHMACKEY_07 ""
#define DBHMACKEY_08 ""
#define DBHMACKEY_09 ""

#undef FORCECONFIGMD
#undef FORCEDBMD

#define INITIALERRORSTO "stderr"
