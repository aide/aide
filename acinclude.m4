dnl Local aide macros

dnl AIDE_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN(AIDE_CHECK_TYPEDEF,
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(aide_cv_typedef_$1,
    [AC_TRY_COMPILE([#include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], aide_cv_typedef_$1=yes, aide_cv_typedef_$1=no )])
    AC_MSG_RESULT($aide_cv_typedef_$1)
    if test "$aide_cv_typedef_$1" = yes; then
          AC_DEFINE($2)
    fi
  ])

dnl AIDE_CHECK_ENDIAN
dnl define either LITTLE_ENDIAN_HOST or BIG_ENDIAN_HOST
dnl
define(AIDE_CHECK_ENDIAN,
  [ if test "$cross_compiling" = yes; then
        AC_MSG_WARN(cross compiling; assuming little endianess)
    fi
    AC_MSG_CHECKING(endianess)
    AC_CACHE_VAL(aide_cv_c_endian,
      [ aide_cv_c_endian=unknown
        # See if sys/param.h defines the BYTE_ORDER macro.
        AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/param.h>], [
        #if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
         bogus endian macros
        #endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
        AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/param.h>], [
        #if BYTE_ORDER != BIG_ENDIAN
         not big endian
        #endif], aide_cv_c_endian=big, aide_cv_c_endian=little)])
        if test "$aide_cv_c_endian" = unknown; then
            AC_TRY_RUN([main () {
              /* Are we little or big endian?  From Harbison&Steele.  */
              union
              {
                long l;
                char c[sizeof (long)];
              } u;
              u.l = 1;
              exit (u.c[sizeof (long) - 1] == 1);
              }],
              aide_cv_c_endian=little,
              aide_cv_c_endian=big,
              aide_cv_c_endian=little
            )
        fi
      ])
    AC_MSG_RESULT([$aide_cv_c_endian])
    if test "$aide_cv_c_endian" = little; then
      AC_DEFINE(LITTLE_ENDIAN_HOST)
    else
      AC_DEFINE(BIG_ENDIAN_HOST)
    fi
  ])

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

