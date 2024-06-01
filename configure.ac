AC_PREREQ([2.69])

m4_include([version.m4])

dnl Initialize autoconf/automake
AC_INIT([aide],[AIDE_VERSION])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.10 -Wall -Werror silent-rules subdir-objects serial-tests])

AC_DEFINE_UNQUOTED(AIDEVERSION, "AIDE_VERSION")
AH_TEMPLATE([AIDEVERSION], [package version])

dnl The name of the configure h-file.
AC_CONFIG_HEADERS(include/config.h)

dnl Checks for programs.
AC_PROG_CC
if test "x$ac_cv_prog_cc_c99" = xno; then
    AC_MSG_ERROR([AIDE needs a C99 compatible compiler])
fi

AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_YACC
if test "x${YACC}" != "xbison -y"; then
        echo "AIDE requires GNU bison"
        exit 5
fi

AC_PROG_LEX(noyywrap)
if test "x${LEX}" != "xflex"; then
        echo "AIDE requires GNU flex"
        exit 5
fi
AC_CHECK_PROGS(LD, ld)

AC_PATH_TOOL([PKG_CONFIG], [pkg-config], [no])
AM_PROG_CC_C_O

AC_SYS_LARGEFILE

dnl AC_ARG_PROGRAM

AC_ARG_WITH(extra-includes,
	AS_HELP_STRING([--with-extra-includes],[Specify additional paths with -I to find headerfiles]),
	[CPPFLAGS="$CPPFLAGS $withval"]
)
AC_ARG_WITH(extra-libs,
	AS_HELP_STRING([--with-extra-libs],[Specify additional paths with -L to find libraries]),
	[LDFLAGS="$LDFLAGS $withval"]
)
AC_ARG_WITH(extra-link-libs,
	AS_HELP_STRING([--with-extra-link-libs],[Specify additional libraries to link]),
	[LIBS="$LIBS $withval"]
)

dnl Do the right thing for glibc...
AIDE_DEFS="-D_GNU_SOURCE"

dnl This is borrowed from libtool
    
if test $ac_cv_c_compiler_gnu = yes; then
    LD_STATIC_FLAG='-static'

    case "$host_os" in
    beos* | irix5* | irix6* | osf3* | osf4* | osf5*)
	# PIC is the default for these OSes.
	;;
    aix*)
	# Below there is a dirty hack to force normal static linking with -ldl
	# The problem is because libdl dynamically linked with both libc and
	# libC (AIX C++ library), which obviously doesn't included in libraries
	# list by gcc. This cause undefined symbols with -static flags.
	# This hack allows C programs to be linked with "-static -ldl", but
	# we not sure about C++ programs.
	LD_STATIC_FLAG="$LD_STATIC_FLAG ${wl}-lC"
	;;
    cygwin* | mingw* | os2*)
	# We can build DLLs from non-PIC.
	;;
    amigaos*)
	# FIXME: we need at least 68020 code to build shared libraries, but
	# adding the `-m68020' flag to GCC prevents building anything better,
	# like `-m68040'.
	## pic_flag='-m68020 -resident32 -malways-restore-a4'
	;;
    sysv4*MP*)
	## if test -d /usr/nec; then
	## pic_flag=-Kconform_pic
	## fi
	;;
    *)
	## pic_flag='-fPIC'
	;;
    esac
else
    # PORTME Check for PIC flags for the system compiler.
    case "$host_os" in
    aix3* | aix4*)
	# All AIX code is PIC.
	LD_STATIC_FLAG='-bnso -bI:/lib/syscalls.exp'
	;;
	
    hpux9* | hpux10* | hpux11*)
	# Is there a better LD_STATIC_FLAG that works with the bundled CC?
	## wl='-Wl,'
	LD_STATIC_FLAG="${wl}-a ${wl}archive"
	## pic_flag='+Z'
	;;
	
    irix5* | irix6*)
	## wl='-Wl,'
	LD_STATIC_FLAG='-non_shared'
	# PIC (with -KPIC) is the default.
	;;
	
    cygwin* | mingw* | os2*)
	# We can build DLLs from non-PIC.
	;;
	
    osf3* | osf4* | osf5*)
	# All OSF/1 code is PIC.
	## wl='-Wl,'
	LD_STATIC_FLAG='-non_shared'
	;;
	
    sco3.2v5*)
	## pic_flag='-Kpic'
	LD_STATIC_FLAG='-dn'
	## special_shlib_compile_flags='-belf'
	;;
	
    solaris*)
	## pic_flag='-KPIC'
	LD_STATIC_FLAG='-Bstatic'
	## wl='-Wl,'
	;;
	
    sunos4*)
	## pic_flag='-PIC'
	LD_STATIC_FLAG='-Bstatic'
	## wl='-Qoption ld '
	;;
	
    sysv4 | sysv4.2uw2* | sysv4.3* | sysv5*)
	## pic_flag='-KPIC'
	LD_STATIC_FLAG='-Bstatic'
	## wl='-Wl,'
	;;
	
    uts4*)
	## pic_flag='-pic'
	LD_STATIC_FLAG='-Bstatic'
	;;
    sysv4*MP*)
	if test -d /usr/nec ;then
	## pic_flag='-Kconform_pic'
	LD_STATIC_FLAG='-Bstatic'
	fi
	;;
    *)
	## can_build_shared=no
	;;
    esac
fi

# Check whether static linking has explicitly been enabled
AC_ARG_ENABLE(static,[  --enable-static         enable static linking (might increase the security of aide, see README for details)], [aide_static_choice=$enableval], [aide_static_choice=no])

dnl Borrowed from dbus
cc_supports_flag() {
  AC_MSG_CHECKING(whether $CC supports "$@")
  Cfile=/tmp/foo${$}
  touch ${Cfile}.c
  $CC -c "$@" ${Cfile}.c -o ${Cfile}.o >/dev/null 2>&1
  rc=$?
  rm -f ${Cfile}.c ${Cfile}.o
  case $rc in
    0) AC_MSG_RESULT(yes);;
    *) AC_MSG_RESULT(no);;
  esac
  return $rc
}

dnl Borrowed from dbus
ld_supports_flag() {
  AC_MSG_CHECKING([whether $LD supports "$@"])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
    int one(void) { return 1; }
    int two(void) { return 2; }
  ], [ two(); ] ) ] , [_ac_ld_flag_supported=yes], [_ac_ld_flag_supported=no])

  if test "$_ac_ld_flag_supported" = "yes"; then
    rm -f conftest.c
    touch conftest.c
    if $CC -c conftest.c; then
      ld_out=`$LD $@ -o conftest conftest.o 2>&1`
      ld_ret=$?
      if test $ld_ret -ne 0 ; then
        _ac_ld_flag_supported=no
      elif echo "$ld_out" | egrep 'option ignored|^usage:|unrecognized option|illegal option' >/dev/null ; then
        _ac_ld_flag_supported=no
      fi
    fi
    rm -f conftest.c conftest.o conftest
  fi

  AC_MSG_RESULT($_ac_ld_flag_supported)
  if test "$_ac_ld_flag_supported" = "yes" ; then
    return 0
  else
    return 1
  fi
}

if test "$aide_static_choice" != "yes"; then
  LD_STATIC_FLAG=""
  EXTRA_LDFLAGS=""
  EXTRA_CFLAGS=""
  if test x$CC = "xgcc"; then
    if ld_supports_flag -z,relro; then
      EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,-z,relro"
    fi
    if ld_supports_flag -z,now; then
      EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,-z,now"
    fi
    if cc_supports_flag -fPIE -DPIE; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -fPIE -DPIE"
      EXTRA_LDFLAGS="$EXTRA_LDFLAGS -pie"
    fi
    dnl Check for some optional warnings
    if cc_supports_flag -Wundef; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wundef"
    fi
    if cc_supports_flag -Wmissing-format-attribute; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wmissing-format-attribute"
    fi
    if cc_supports_flag -Wshadow; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wshadow"
    fi
    if cc_supports_flag -Wlogical-op; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wlogical-op"
    fi
  fi
fi

dnl This macro is new in autoconf-2.13
AC_SEARCH_LIBS(syslog, bsd socket inet, [AC_DEFINE(HAVE_SYSLOG,1,[syslog available?])])
AC_CHECK_FUNCS(vsyslog)

AC_C_BIGENDIAN([AC_DEFINE(BIG_ENDIAN_HOST,1,[big endian])], [AC_DEFINE(LITTLE_ENDIAN_HOST,1,[little endian])])

AC_CHECK_TYPES([byte, ushort, ulong, u16, u32, u64])

AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)
AC_CHECK_SIZEOF(unsigned long long, 8)

AC_CHECK_SIZEOF(int)

AC_CHECK_SIZEOF(long long)

AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(ino_t)
AC_CHECK_SIZEOF(nlink_t)
AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(blkcnt_t)

AC_CHECK_FUNCS(strtoll strtoimax readdir)
AC_CHECK_FUNCS(stricmp strnstr strnlen)

AC_CHECK_FUNCS(fcntl ftruncate posix_fadvise asprintf snprintf \
	vasprintf vsnprintf va_copy __va_copy)

AC_CHECK_FUNCS(sigabbrev_np)
AC_CHECK_HEADERS(sys/prctl.h)

# Linux has the O_NOATIME flag, sometimes
AC_CACHE_CHECK([for open/O_NOATIME], db_cv_open_o_noatime, [
echo "test for working open/O_NOATIME" > __o_noatime_file
AC_RUN_IFELSE([AC_LANG_SOURCE([
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif
int main(void) {
int c, fd = open("__o_noatime_file", O_RDONLY | O_NOATIME, 0);
exit ((!O_NOATIME) || (fd == -1) || (read(fd, &c, 1) != 1));
} ]) ], [db_cv_open_o_noatime=yes], [db_cv_open_o_noatime=no],
AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <fcntl.h>
#include <sys/types.h
#include <sys/stat.h>>
#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif
], [ open("__o_noatime_file", O_RDONLY | O_NOATIME, 0);
]) ], [db_cv_open_o_noatime=yes], [db_cv_open_o_noatime=no]))
rm -f __o_noatime_file])
if test "$db_cv_open_o_noatime" = yes; then
	AC_DEFINE(HAVE_O_NOATIME)
	AH_TEMPLATE(HAVE_O_NOATIME, [Define to 1 if you have the O_NOATIME flag.])
fi

AC_CHECK_HEADERS(syslog.h inttypes.h fcntl.h ctype.h)

AIDE_PKG_CHECK_MANDATORY(pcre2, PCRE2, libpcre2-8)

AX_PTHREAD(compoptionstring="${compoptionstring}use pthread: mandatory\\n", [AC_MSG_ERROR([AIDE requires pthread])])

AIDE_PKG_CHECK(zlib, zlib compression, yes, ZLIB, zlib)

AIDE_PKG_CHECK([posix-acl], POSIX ACLs, no, POSIX_ACL, libacl, acl)
if test "x$with_libacl" = xyes; then
    AC_DEFINE(WITH_ACL, 1, [use ACL])
fi

AIDE_PKG_CHECK(selinux, SELinux, no, SELINUX, libselinux, selinux)

AIDE_PKG_CHECK(xattr, xattr, no, XATTR, libattr, xattrs)

AIDE_PKG_CHECK(capabilities, POSIX 1003.1e capabilities, no, CAPABILITIES, libcap, caps)

AIDE_PKG_CHECK(e2fsattrs, e2fsattrs, no, E2FSATTRS, e2p, e2fsattrs)

AIDE_PKG_CHECK(curl, cURL, no, CURL, libcurl)

AC_MSG_CHECKING(for Mhash)
AC_ARG_WITH([mhash], AS_HELP_STRING([--with-mhash], [use Mhash (default: check)]), [with_mhash=$withval], [with_mhash=check])
AC_MSG_RESULT([$with_mhash])

AC_MSG_CHECKING(for GnuTLS)
AC_ARG_WITH([gnutls], AS_HELP_STRING([--with-gnutls], [use GnuTLS library (default: check)]), [with_gnutls=$withval], [with_gnutls=check])
AC_MSG_RESULT([$with_gnutls])

AC_MSG_CHECKING(for GNU crypto library)
AC_ARG_WITH([gcrypt], AS_HELP_STRING([--with-gcrypt], [use GNU crypto library (default: check)]), [with_gcrypt=$withval], [with_gcrypt=check])
AC_MSG_RESULT([$with_gcrypt])

AIDE_PKG_CHECK_MODULES_OPTIONAL(mhash, MHASH, mhash)
AS_IF([test x"$with_mhash" = xyes], [
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
        [[#include <mhash.h>
        int i=MHASH_WHIRLPOOL;
        ]]
    )],AC_DEFINE(HAVE_MHASH_WHIRLPOOL,1,[mhash has whirlpool]))
    AS_IF([test x"$with_gcrypt" = xcheck], [
    with_gcrypt=no
    with_gnutls=no
    ])
])
AIDE_PKG_CHECK_MODULES_OPTIONAL(gcrypt, GCRYPT, libgcrypt)
AIDE_PKG_CHECK_MODULES_OPTIONAL(gnutls, GNUTLS, gnutls)
AS_IF([test x"$with_mhash" != xno && test x"$with_gcrypt" != xno], [
    AC_MSG_ERROR([Using gcrypt together with mhash makes no sense. To disable mhash use --without-mhash])
])
AS_IF([test x"$with_mhash" != xno && test x"$with_gnutls" != xno], [
    AC_MSG_ERROR([Using gnutls together with mhash makes no sense. To disable mhash use --without-mhash])
])
AS_IF([test x"$with_gcrypt" != xno && test x"$with_gnutls" != xno], [
    AC_MSG_ERROR([Using gnutls together with gcrypt makes no sense. To disable gcrypt use --without-gcrypt])
])
AS_IF([test x"$with_mhash" = xno && test x"$with_gcrypt" = xno && test x"$with_gnutls" == xno], [
    AC_MSG_ERROR([AIDE requires mhash, gnutls or libcrypt for hashsum calculation])
])
compoptionstring="${compoptionstring}use Mhash: $with_mhash\\n"
AM_CONDITIONAL(HAVE_MHASH, [test "x$MHASH_LIBS" != "x"])
compoptionstring="${compoptionstring}use GNU crypto library: $with_gcrypt\\n"
AM_CONDITIONAL(HAVE_GCRYPT, [test "x$GCRYPT_LIBS" != "x"])
compoptionstring="${compoptionstring}use GnuTLS: $with_gnutls\\n"
AM_CONDITIONAL(HAVE_GNUTLS, [test "x$GNUTLS_LIBS" != "x"])

AIDE_PKG_CHECK(audit, Linux Auditing Framework, no, AUDIT, audit)

AIDE_PKG_CHECK_HEADERS(locale, locale, no, LOCALE, [libintl.h])
if test "x$with_locale" = xyes; then
    AC_DEFINE_UNQUOTED(LOCALEDIR,"$prefix/lib/locale",[Localedir to use])
fi

AIDE_COMPILE_TIME_OPTION(syslog_ident, syslog-ident, syslog ident, "aide")
AC_DEFINE_UNQUOTED(AIDE_IDENT, "$with_syslog_ident", [syslog ident])

AIDE_COMPILE_TIME_OPTION(syslog_logopt, syslog-logopt, syslog logopt, LOG_CONS)
AC_DEFINE_UNQUOTED(AIDE_LOGOPT, $with_syslog_logopt, [syslog logopt])

AIDE_COMPILE_TIME_OPTION(syslog_priority, syslog-priority, syslog priority, LOG_NOTICE)
AC_DEFINE_UNQUOTED(AIDE_SYSLOG_PRIORITY, $with_syslog_priority, [syslog priority])

AIDE_COMPILE_TIME_OPTION(syslog_facility, syslog-facility, default syslog facility, LOG_LOCAL0)
AC_DEFINE_UNQUOTED(AIDE_SYSLOG_FACILITY, $with_syslog_facility, [syslog facility])

PKG_CHECK_MODULES(CHECK, [check >= 0.9.4], , [AC_MSG_RESULT([Check not found (testing via 'make check' disabled)])])
AM_CONDITIONAL(HAVE_CHECK, [test "x$CHECK_LIBS" != "x"])

AC_ARG_WITH([config_file],
	AS_HELP_STRING([--with-config-file=config-file],[specify default config file (use --without-config-file to disable default config file)]),
    [with_config_file=$withval],[with_config_file=yes])

if test "$with_config_file" != "no"; then
    if test "$with_config_file" != "yes"; then
        config_file=$with_config_file
    else
        if test "x$sysconfdir" != x'${prefix}/etc'; then
            config_file=`eval echo "$sysconfdir/aide.conf"`
        elif test "x$prefix" != xNONE; then
            config_file="$prefix/etc/aide.conf"
        else
            config_file="$ac_default_prefix/etc/aide.conf"
        fi
    fi
    AC_DEFINE_UNQUOTED(CONFIG_FILE,"$config_file",[Location of configuration file])
fi

AC_ARG_ENABLE([default_db],
	AS_HELP_STRING([--disable-default-db],[do not set default values for database_in and database_out config options]),
    [enable_default_db=$enableval],[enable_default_db=yes])

if test "$enable_default_db" = "yes"; then

if test "x$sysconfdir" != x'${prefix}/etc'; then
	evalled_sysconfdir=`eval echo "$sysconfdir"`
	default_db="$evalled_sysconfdir/aide.db"
	default_db_out="$evalled_sysconfdir/aide.db.new"
elif test "x$prefix" != xNONE; then
	default_db="$prefix/etc/aide.db"
	default_db_out="$prefix/etc/aide.db.new"
else
	default_db="$ac_default_prefix/etc/aide.db"
	default_db_out="$ac_default_prefix/etc/aide.db.new"
fi

AC_DEFINE_UNQUOTED(DEFAULT_DB,"file:$default_db",[Default location of signature database])
AC_DEFINE_UNQUOTED(DEFAULT_DB_OUT,"file:$default_db_out",[Default output location for newly-generated signature database])

fi

extrasub="s&@AIDEVERSION@&$PACKAGE_VERSION&;t t"

AC_DEFINE_UNQUOTED(AIDECOMPILEOPTIONS, "${compoptionstring}",[Compile-time options displayed in -v output])

dnl Add in the optional compiler features
LDFLAGS="$LDFLAGS $LD_STATIC_FLAG $EXTRA_LDFLAGS"
CFLAGS="$CFLAGS $EXTRA_CFLAGS"

AC_SUBST(AIDE_DEFS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
