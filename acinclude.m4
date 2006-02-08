dnl Local aide macros

dnl AIDE_LINK_FILES( SRC, DEST )
dnl same as AC_LINK_FILES, but collect the files to link in
dnl some special variables and do the link
dnl when AIDE_DO_LINK_FILES is called
dnl This is a workaround for AC_LINK_FILES, because it does not work
dnl correct when using a caching scheme
dnl
define(AIDE_LINK_FILES,
  [ if test "x$wk_link_files_src" = "x"; then
        wk_link_files_src="$1"
        wk_link_files_dst="$2"
    else
        wk_link_files_src="$wk_link_files_src $1"
        wk_link_files_dst="$wk_link_files_dst $2"
    fi
  ])

define(AIDE_DO_LINK_FILES,
  [ AC_LINK_FILES( $wk_link_files_src, $wk_link_files_dst )
  ])

dnl AIDE_MSG_PRINT(STRING)
dnl print a message
dnl
define(AIDE_MSG_PRINT,
  [ echo $ac_n "$1"" $ac_c" 1>&AC_FD_MSG
  ])

AC_DEFUN([AIDE_CHECK_READDIR_R_ARGS],[
# Check definition of readdir_r
AC_CACHE_CHECK(args to readdir_r, aide_cv_readdir_r,
AC_TRY_LINK(
[#ifndef SCO
#define _REENTRANT
#endif
#define _POSIX_PTHREAD_SEMANTICS
#include <pthread.h>
#include <dirent.h>],
[ int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result);
readdir_r((DIR *) NULL, (struct dirent *) NULL, (struct dirent **) NULL); ],
aide_cv_readdir_r=POSIX, aide_cv_readdir_r=other))
if test "$aide_cv_readdir_r" = "POSIX"
then
	AC_DEFINE(HAVE_READDIR_R,1,[Define to 1 if you have the `readdir_r' function.])
fi
])

