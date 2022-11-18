AC_DEFUN([AIDE_PKG_CHECK_MODULES],
[
   if test "$aide_static_choice" = "yes"; then
       PKG_CHECK_MODULES_STATIC($2, [$3], [], [AC_MSG_ERROR([$3 not found by pkg-config - Try --without-$1 or add directory containing $3.pc to PKG_CONFIG_PATH environment variable])])
    else
       PKG_CHECK_MODULES($2, [$3], [], [AC_MSG_ERROR([$3 not found by pkg-config - Try --without-$1 or add directory containing $3.pc to PKG_CONFIG_PATH environment variable])])
    fi
    AC_DEFINE(WITH_$2,1,[Define to 1 if $3 is available])
])

AC_DEFUN([AIDE_PKG_CHECK_MODULES_OPTIONAL],
[
    AS_IF([test x"$with_$1" != xno], [
   if test "$aide_static_choice" = "yes"; then
       PKG_CHECK_MODULES_STATIC($2, [$3], [
            with_$1=yes
       ], [
           AS_IF([test x"$with_$1" = xyes], [
               AC_MSG_ERROR([$3 not found by pkg-config - Try to add directory containing $3.pc to PKG_CONFIG_PATH environment variable])
           ])
           with_$1=no
       ])
    else
       PKG_CHECK_MODULES($2, [$3], [
            with_$1=yes
       ], [
           AS_IF([test x"$with_$1" = xyes], [
               AC_MSG_ERROR([$3 not found by pkg-config - Try to add directory containing $3.pc to PKG_CONFIG_PATH environment variable])
           ])
           with_$1=no
       ])
    fi
    AS_IF([test x"$with_$1" = xyes], [
        AC_DEFINE(WITH_$2,1,[Define to 1 if $3 is available])
    ])
    ])
])

AC_DEFUN([AIDE_PKG_CHECK],
[
    AC_MSG_CHECKING(for $2)
    AC_ARG_WITH([$1], AS_HELP_STRING([--with-$1], [use $2 (default: $3)]), [with_$5=$withval], [with_$5=$3])

    AS_IF([test x"$with_$5" = xyes], [
           AC_MSG_RESULT(yes)
           AIDE_PKG_CHECK_MODULES($1, $4, $5)
           if test -n $6; then
              aideextragroups="${aideextragroups}+$6"
           fi
    ],[
        AC_MSG_RESULT(no)
    ])
    compoptionstring="${compoptionstring}use $2: $with_$5\\n"
    AM_CONDITIONAL(HAVE_$4, [test "x$$4_LIBS" != "x"])
])

AC_DEFUN([AIDE_PKG_CHECK_MANDATORY],
[
   if test "$aide_static_choice" = "yes"; then
       PKG_CHECK_MODULES_STATIC($2, [$3], [], [AC_MSG_ERROR([$3 not found by pkg-config - Try to add directory containing $3.pc to PKG_CONFIG_PATH environment variable])])
    else
       PKG_CHECK_MODULES($2, [$3], [], [AC_MSG_ERROR([$3 not found by pkg-config - Try to add directory containing $3.pc to PKG_CONFIG_PATH environment variable])])
    fi
    compoptionstring="${compoptionstring}use $1: mandatory\\n"
])

AC_DEFUN([AIDE_PKG_CHECK_HEADERS],
[
    AC_MSG_CHECKING(for $1)
    AC_ARG_WITH([$1], AS_HELP_STRING([--with-$1], [$2 (default: $3)]), [with_$1=$withval], [with_$1=$3])
    AC_MSG_RESULT([$with_$1])
    AS_IF([test x"$with_$1" != xno], [
    AC_CHECK_HEADERS($5, [
            AS_IF([test x"$3" != xno], [
                AC_DEFINE(WITH_$4,1,[Define to 1 if $1 is available])
                with_$1="yes"
            ])
        ], [
            AS_IF([test x"$3" = xyes], [
                AC_MSG_ERROR([headers $5 for $1 not found])
            ])
        ])
    ])
    compoptionstring="${compoptionstring}use $2: $with_$1\\n"
    AM_CONDITIONAL(HAVE_$4, [test "x$with_$1" = "xyes"])
])

AC_DEFUN([AIDE_COMPILE_TIME_OPTION],
[
    AC_MSG_CHECKING(for $3)
    AC_ARG_WITH([$1], AS_HELP_STRING([--with-$2], [$3 (default: $4)]), [with_$1=$withval], [with_$1=$4])
    AC_MSG_RESULT([$with_$1])
    compoptionstring="${compoptionstring}$3: $with_$1\\n"
])
