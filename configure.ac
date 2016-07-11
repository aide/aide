m4_include([version.m4])

dnl Initialize autoconf/automake
AC_INIT(aide, AIDE_VERSION)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.10 -Wall -Werror silent-rules subdir-objects])

AC_DEFINE_UNQUOTED(AIDEVERSION, "AIDE_VERSION")
AH_TEMPLATE([AIDEVERSION], [package version])

dnl The name of the configure h-file.
AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC_C99
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_YACC
if test "x${YACC}" != "xbison -y"; then
        echo "AIDE requires GNU bison"
        exit 5
fi

AC_PROG_LEX
if test "x${LEX}" != "xflex"; then
        echo "AIDE requires GNU flex"
        exit 5
fi
AC_CHECK_PROGS(LD, ld)

AC_PATH_PROG(PKG_CONFIG, pkg-config, "")
AM_PROG_CC_C_O

dnl AC_ARG_PROGRAM

AC_ARG_WITH(extra-includes,
	AC_HELP_STRING([--with-extra-includes],
		[Specify additional paths with -I to find headerfiles]),
	[CPPFLAGS="$CPPFLAGS $withval"]
)
AC_ARG_WITH(extra-libs,
	AC_HELP_STRING([--with-extra-libs],
		[Specify additional paths with -L to find libraries]),
	[LDFLAGS="$LDFLAGS $withval"]
)
AC_ARG_WITH(extra-link-libs,
	AC_HELP_STRING([--with-extra-link-libs],
		[Specify additional libraries to link]),
	[LIBS="$LIBS $withval"]
)

dnl Do the right thing for glibc...
AIDE_DEFS="-D_GNU_SOURCE"

dnl This is borrowed from libtool
    
if test $ac_cv_prog_gcc = yes; then
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

# Check whether static linking has explicitly been disabled
AC_ARG_ENABLE(static,[  --disable-static        Disable static linking (lowers the security of aide)], [aide_static_choice=$enableval], [aide_static_choice=yes])

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
  AC_TRY_LINK([
    int one(void) { return 1; }
    int two(void) { return 2; }
  ], [ two(); ] , [_ac_ld_flag_supported=yes], [_ac_ld_flag_supported=no])

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
AC_CHECK_SIZEOF(long long, 8)
AC_CHECK_SIZEOF(unsigned long long, 8)
AC_C_LONG_DOUBLE

AC_HEADER_STDC
AC_CHECK_FUNCS(strtoll strtoimax readdir)
AIDE_CHECK_READDIR_R_ARGS
AC_CHECK_FUNCS(stricmp strnstr strnlen)

AC_ARG_WITH([mmap],
	[AC_HELP_STRING([--with-mmap],
		[use mmap @<:@default=check@:>@])],
	[],
	[with_mmap=check]
)

AS_IF([test "x$with_mmap" != xno],
	[AC_CHECK_FUNCS(mmap)]
	compoptionstring="${compoptionstring}WITH_MMAP\\n"
)

AC_CHECK_FUNCS(fcntl ftruncate posix_fadvise asprintf snprintf \
	vasprintf vsnprintf va_copy __va_copy)

AC_CACHE_CHECK(for ISO C99 compliant snprintf,ac_cv_func_snprintf_c99,
	[AC_TRY_RUN([
#include <stdio.h>

int main()
{
	char buf[] = {0, 0, 0, 0};

	snprintf(buf, 3, "ABC");
	exit ((buf[2] != 0) || (snprintf(NULL, 0, "%d", 100) != 3));
}],ac_cv_func_snprintf_c99=yes,ac_cv_func_snprintf_c99=no,ac_cv_func_snprintf_c99=no)])
if test $ac_cv_func_snprintf_c99 = yes; then
	AC_DEFINE(HAVE_C99_SNPRINTF,1,[snprintf is ISO C99 compliant])
fi
AC_CACHE_CHECK(for ISO C99 compliant vsnprintf,ac_cv_func_vsnprintf_c99,
	[AC_TRY_RUN([
#include <stdio.h>
#include <stdarg.h>

int doit(char *buf, int len, const char *s, ...)
{
	va_list ap;
	int r;

	va_start(ap, s);
	r = vsnprintf(buf, len, s, ap);
	va_end(ap);

	return r;
}

int main()
{
	char buf[] = {0, 0, 0, 0};

	doit(buf, 3, "ABC");
	exit ((buf[2] != 0) || (doit(NULL, 0, "%d", 100) != 3));
}],ac_cv_func_vsnprintf_c99=yes,ac_cv_func_vsnprintf_c99=no,ac_cv_func_vsnprintf_c99=no)])
if test $ac_cv_func_vsnprintf_c99 = yes; then
	AC_DEFINE(HAVE_C99_VSNPRINTF,1,[vsnprintf is ISO C99 compliant])
fi

# Linux has the O_NOATIME flag, sometimes
AC_CACHE_CHECK([for open/O_NOATIME], db_cv_open_o_noatime, [
echo "test for working open/O_NOATIME" > __o_noatime_file
AC_TRY_RUN([
#include <sys/types.h>
#include <fcntl.h>
#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif
main() {
int c, fd = open("__o_noatime_file", O_RDONLY | O_NOATIME, 0);
exit ((!O_NOATIME) || (fd == -1) || (read(fd, &c, 1) != 1));
}], [db_cv_open_o_noatime=yes], [db_cv_open_o_noatime=no],
AC_TRY_LINK([
#include <sys/types.h>   
#include <fcntl.h>
#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif], [
	open("__o_noatime_file", O_RDONLY | O_NOATIME, 0);
], [db_cv_open_o_noatime=yes], [db_cv_open_o_noatime=no]))
rm -f __o_noatime_file])
if test "$db_cv_open_o_noatime" = yes; then
	AC_DEFINE(HAVE_O_NOATIME)
	AH_TEMPLATE(HAVE_O_NOATIME, [Define to 1 if you have the O_NOATIME flag.])
fi

AC_CHECK_HEADERS(syslog.h inttypes.h fcntl.h ctype.h)

PCRELIB="-lpcre"
if test "$aide_static_choice" == "yes"; then
    PCRELIB="$PCRELIB -pthread"
fi
AC_CHECK_LIB(pcre, pcre_exec, [
    compoptionstring="${compoptionstring}WITH_PCRE\\n"
    ], [AC_MSG_ERROR([You don't have pcre library properly installed.])]
    )
AC_SUBST(PCRELIB)

AC_ARG_WITH([locale],
	[AC_HELP_STRING([--with-locale],
		[use locale stuff])],
	[],
	[with_locale=no]
)

AS_IF([test "x$with_locale" != xno],
	[AC_CHECK_HEADERS(libintl.h,
		[AC_DEFINE(USE_LOCALE,1,[Define if LOCALE support should be used])
		AIDE_USE_LOCALE=""
		compoptionstring="${compoptionstring}WITH_LOCALE\\n"
dnl        	AC_DEFINE_UNQUOTED(LOCALEDIR,"$prefix/lib/locale",[Localedir to use])],
	)]
)

AC_SUBST(AIDE_USE_LOCALE)

AC_ARG_WITH([syslog_ident],
	AC_HELP_STRING([--with-syslog-ident],
	[syslog ident]),
  	[AC_DEFINE_UNQUOTED(AIDE_IDENT,"$withval",[syslog ident])]
		compoptionstring="${compoptionstring}AIDE_IDENT=${withval}\\n",
  	[AC_DEFINE_UNQUOTED(AIDE_IDENT,"aide",[syslog ident])]
)

AC_ARG_WITH([syslog_facility],
	AC_HELP_STRING([--with-syslog-facility],
		[Specify syslog facility, see man syslog for options]),
	[AC_DEFINE_UNQUOTED(AIDE_SYSLOG_FACILITY,$withval,[syslog facility])]
	compoptionstring="${compoptionstring}AIDE_SYSLOG_FACILITY=${withval}\\n",
	[AC_DEFINE_UNQUOTED(AIDE_SYSLOG_FACILITY,LOG_LOCAL0,[syslog facility])]
)

AC_ARG_WITH([syslog_logopt],
	AC_HELP_STRING([--with-syslog-logopt],
		[Specify syslog logopt, see man syslog for options]),
	[AC_DEFINE_UNQUOTED(AIDE_LOGOPT,$withval,[syslog logopt])],
	[AC_DEFINE_UNQUOTED(AIDE_LOGOPT,LOG_CONS,[syslog logopt])]
)

AC_ARG_WITH([syslog_priority],
	AC_HELP_STRING([--with-syslog-priority],
		[Specify syslog priority, see man syslog for options]),
	[AC_DEFINE_UNQUOTED(SYSLOG_PRIORITY,$withval,[syslog priority])]
	compoptionstring="${compoptionstring}SYSLOG_PRIORITY=${withval}\\n",
	[AC_DEFINE_UNQUOTED(SYSLOG_PRIORITY,LOG_NOTICE,[syslog priority])]
)


AC_ARG_WITH([zlib],
	AC_HELP_STRING([--with-zlib],
		[use zlib compression]),
	,
	[with_zlib=yes]
)

AC_ARG_WITH([curl],
	AC_HELP_STRING([--with-curl],
		[use curl for http,https and ftp backends]),
		,
	[with_curl=no]
)

AC_MSG_CHECKING(for sun-acl-support)
AC_ARG_WITH([sun-acl],
	[AC_HELP_STRING([--with-sun-acl],
		[use ACL on solaris (no checking)])],
	[],
	[with_sun_acl=no]
)

AS_IF([test "x$with_sun_acl" != xno],
	[AC_DEFINE(WITH_SUN_ACL,1,[use ACL on Solaris])
	AC_DEFINE(WITH_ACL,1,[use ACL])
	ACLLIB="-lsec"
	compoptionstring="${compoptionstring}WITH_SUN_ACL\\n"
	aideextragroups="${aideextragroups}+acl"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_MSG_CHECKING(for posix-acl-support)
AC_ARG_WITH([posix-acl],
	[AC_HELP_STRING([--with-posix-acl],
		[use POSIX ACLs (no checking)])],
	[],
	[with_posix_acl_support=no]
)

AS_IF([test "x$with_posix_acl_support" != xno],
	[AC_DEFINE(WITH_POSIX_ACL,1,[use POSIX ACLs])
	AC_DEFINE(WITH_ACL,1,[use ACL])
	ACLLIB="-lacl"
	compoptionstring="${compoptionstring}WITH_POSIX_ACL\\n"
	aideextragroups="${aideextragroups}+acl"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(ACLLIB)

AC_MSG_CHECKING(for selinux-support)
AC_ARG_WITH([selinux],
	[AC_HELP_STRING([--with-selinux],
		[use SELinux (no checking)])],
	[with_selinux_support="$withval"],
	[with_selinux_support=no]
)

AS_IF([test "x$with_selinux_support" != xno],
    AC_DEFINE(WITH_SELINUX,1,[use SELinux])
    [AC_MSG_RESULT(yes)
    if test -n "$PKG_CONFIG" && $PKG_CONFIG --exists libselinux; then
        if test "$aide_static_choice" == "yes"; then
            SELINUXLIB=$(${PKG_CONFIG} --libs libselinux --static)
        else
            SELINUXLIB=$(${PKG_CONFIG} --libs libselinux)
        fi
    else
    SELINUXLIB="-lselinux"
    if test "$aide_static_choice" == "yes"; then
        saveLIBS=$LIBS
        LIBS="-static $SELINUXLIB"
        AC_SEARCH_LIBS([lgetfilecon_raw], [], [], [SELINUXLIB="$SELINUXLIB -lpthread"])
        LIBS=$saveLIBS
    fi
    fi
	compoptionstring="${compoptionstring}WITH_SELINUX\\n"
	aideextragroups="${aideextragroups}+selinux"
    ],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(SELINUXLIB)


AC_MSG_CHECKING(for prelink-support)
AC_ARG_WITH([prelink], 
            [AC_HELP_STRING([--with-prelink],[use prelink (no checking)])],
            [case $with_prelink in 
		yes) AC_DEFINE_UNQUOTED(PRELINK_PATH, "/usr/sbin/prelink", [path to prelink])
		     AC_DEFINE(WITH_PRELINK,1,[use prelink])
		     ELFLIB="-lelf"
		     compoptionstring="${compoptionstring}WITH_PRELINK\\n"
		     AC_MSG_RESULT([/usr/sbin/prelink])
		     ;;
		no)  AC_MSG_RESULT(no)
		     ;;
		*)   AC_DEFINE_UNQUOTED(PRELINK_PATH, "$with_prelink", [path to prelink])
		     AC_DEFINE(WITH_PRELINK,1,[use prelink])
		     ELFLIB="-lelf"
		     compoptionstring="${compoptionstring}WITH_PRELINK\\n"
		     AC_MSG_RESULT([$with_prelink])
		     ;;
	     esac],
	    [with_prelink=no
			AC_MSG_RESULT(no)
			]
)
AC_SUBST(ELFLIB)

AC_MSG_CHECKING(for xattr-support)
AC_ARG_WITH([xattr],
	[AC_HELP_STRING([--with-xattr],
		[use xattr (no checking)])],
	[with_xattr_support="$withval"],
	[with_xattr_support=no]
)
	
AS_IF([test "x$with_xattr_support" != xno],
	[AC_DEFINE(WITH_XATTR,1,[use xattr])
	ATTRLIB=-lattr
	compoptionstring="${compoptionstring}WITH_XATTR\\n"
	aideextragroups="${aideextragroups}+xattrs"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(ATTRLIB)

AC_MSG_CHECKING(for e2fsattrs-support)
AC_ARG_WITH([e2fsattrs],
	[AC_HELP_STRING([--with-e2fsattrs],
		[use e2fsattrs (no checking)])],
	[with_e2fsattrs_support="$withval"],
	[with_e2fsattrs_support=no]
)

AS_IF([test "x$with_e2fsattrs_support" != xno],
	[AC_DEFINE(WITH_E2FSATTRS,1,[use e2fsattrs])
	E2FSATTRSLIB=-le2p
	compoptionstring="${compoptionstring}WITH_E2FSATTRS\\n"
	aideextragroups="${aideextragroups}+e2fsattrs"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(E2FSATTRSLIB)

# Check whether LFS has explicitly been disabled
AC_ARG_ENABLE(lfs,[  --disable-lfs           Disable large file support on 32-bit platforms], [aide_lfs_choice=$enableval], [aide_lfs_choice=yes])

if test "$aide_lfs_choice" = "yes"; then
# This looks weird because Linux defines lstat64 and then screws it up
AC_CHECK_FUNC(lstat64,
    [AC_CHECK_FUNC(stat64,
	AIDE_DEFS="$AIDE_DEFS -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
	AIDE_LSTAT_FUNC="lstat64"
	compoptionstring="${compoptionstring}WITH_LSTAT64\\n"
	AIDE_STAT_FUNC="stat64"
	AIDE_FSTAT_FUNC="fstat64"
	AIDE_STAT_TYPE="stat64"
	AIDE_OFF_TYPE="off64_t"
	AC_DEFINE(HAVE_OFF64_T,1,[have off64_t])
	AIDE_BLKCNT_TYPE="blkcnt64_t"
	[AC_CHECK_FUNC(readdir64,
		AIDE_READDIR_FUNC="readdir64"
		compoptionstring="${compoptionstring}WITH_READDIR64\\n",
		AIDE_READDIR_FUNC="readdir")]
	[AC_CHECK_FUNC(readdir64_r,
		AIDE_READDIR_R_FUNC="readdir64_r",
		AIDE_READDIR_R_FUNC="readdir_r")],
	AIDE_LSTAT_FUNC="lstat"
	AIDE_STAT_FUNC="stat"
	AIDE_FSTAT_FUNC="fstat"
	AIDE_STAT_TYPE="stat"
	AIDE_OFF_TYPE="off_t"
	AIDE_BLKCNT_TYPE="blkcnt_t"
	AIDE_READDIR_FUNC="readdir"
	AIDE_READDIR_R_FUNC="readdir_r"
	compoptionstring="${compoptionstring}WITH_LSTAT\\n"
	compoptionstring="${compoptionstring}WITH_READDIR\\n"
)],
	[AIDE_LSTAT_FUNC="lstat"
	AIDE_STAT_FUNC="stat"
	AIDE_FSTAT_FUNC="fstat"
	AIDE_STAT_TYPE="stat"
	AIDE_OFF_TYPE="off_t"
	AIDE_BLKCNT_TYPE="blkcnt_t"
	AIDE_READDIR_FUNC="readdir"
	AIDE_READDIR_R_FUNC="readdir_r"
	compoptionstring="${compoptionstring}WITH_LSTAT\\n"
	compoptionstring="${compoptionstring}WITH_READDIR\\n"]
)

saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $AIDE_DEFS"
AC_CACHE_CHECK([for LFS ino_t],ac_cv_ino_type,[
AC_TRY_RUN([
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
main() { struct stat64 st; ino64_t s; if (sizeof(ino_t) == sizeof(ino64_t)) exit(1); exit((lstat64("/dev/null", &st)==0)?0:1); }],
ac_cv_ino_type=ino64_t,ac_cv_ino_type=ino_t,ac_cv_ino_type=cross)])
AIDE_INO_TYPE=$ac_cv_ino_type

AC_CACHE_CHECK([for LFS dirent],ac_cv_dirent_type,[
AC_TRY_COMPILE([
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>],
[struct dirent64 de;],
ac_cv_dirent_type=dirent64,ac_cv_dirent_type=dirent)])
AIDE_DIRENT_TYPE=$ac_cv_dirent_type
else
	AIDE_LSTAT_FUNC="lstat"
	AIDE_STAT_FUNC="stat"
	AIDE_FSTAT_FUNC="fstat"
	AIDE_STAT_TYPE="stat"
	AIDE_OFF_TYPE="off_t"
	AIDE_BLKCNT_TYPE="blkcnt_t"
	AIDE_READDIR_FUNC="readdir"
	AIDE_READDIR_R_FUNC="readdir_r"
	compoptionstring="${compoptionstring}WITH_LSTAT\\n"
	compoptionstring="${compoptionstring}WITH_READDIR\\n"
	AIDE_INO_TYPE=ino_t
	AIDE_DIRENT_TYPE=dirent
fi
AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(off64_t)
CFLAGS="$saved_CFLAGS"

AC_DEFINE_UNQUOTED(AIDE_LSTAT_FUNC,$AIDE_LSTAT_FUNC,[lstat])
AC_DEFINE_UNQUOTED(AIDE_STAT_FUNC,$AIDE_STAT_FUNC,[stat])
AC_DEFINE_UNQUOTED(AIDE_FSTAT_FUNC,$AIDE_FSTAT_FUNC,[fstat])
AC_DEFINE_UNQUOTED(AIDE_STAT_TYPE,$AIDE_STAT_TYPE,[stat type])
AC_DEFINE_UNQUOTED(AIDE_INO_TYPE,$AIDE_INO_TYPE,[ino_t])
AC_DEFINE_UNQUOTED(AIDE_OFF_TYPE,$AIDE_OFF_TYPE,[off_t])
AC_DEFINE_UNQUOTED(AIDE_BLKCNT_TYPE,$AIDE_BLKCNT_TYPE,[blkcnt_t])
AC_DEFINE_UNQUOTED(AIDE_READDIR_FUNC,$AIDE_READDIR_FUNC,[readdir])
AC_DEFINE_UNQUOTED(AIDE_READDIR_R_FUNC,$AIDE_READDIR_R_FUNC,[readdir_r])
AC_DEFINE_UNQUOTED(AIDE_DIRENT_TYPE,$AIDE_DIRENT_TYPE,[dirent])

AC_ARG_WITH([config_file],
	AC_HELP_STRING([--with-config-file=config-file],
		[use config-file as the default config file]),
	[config_file=$withval],
	[if test "x$sysconfdir" != x'${prefix}/etc'; then
	   config_file=`eval echo "$sysconfdir/aide.conf"`
	elif test "x$prefix" != xNONE; then
	   config_file="$prefix/etc/aide.conf"
	else
	   config_file="$ac_default_prefix/etc/aide.conf"
	fi]
)

AC_DEFINE_UNQUOTED(CONFIG_FILE,"$config_file",[Location of configuration file])

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

AC_DEFINE_UNQUOTED(DEFAULT_DB,"$default_db",[Default location of signature database])
AC_DEFINE_UNQUOTED(DEFAULT_DB_OUT,"$default_db_out",[Default output location for newly-generated signature database])

dnl Do the library tests with the static flag
LDFLAGS="$LDFLAGS $LD_STATIC_FLAG"
if test x$with_zlib = xyes; then
  AC_CHECK_HEADERS(zlib.h,[],
 	[AC_MSG_ERROR([You don't have zlib properly installed. Install it or try --without-zlib.])])
  save_LDFLAGS=$LDFLAGS
  AC_CHECK_LIB(z, deflate,[],
 	  [AC_MSG_ERROR([You don't have zlib properly installed. Install it or try --without-zlib.])]
  )
  AC_DEFINE(WITH_ZLIB,1,[use zlib])
  compoptionstring="${compoptionstring}WITH_ZLIB\\n"
fi

if test x$with_curl = xyes; then
	AC_PATH_PROG(curlconfig, "curl-config")
	if test "_$curlconfig" != _ ; then
		CURL_CFLAGS=`$curlconfig --cflags`
		CURL_LIBS=`$curlconfig --libs`
	else
		AC_MSG_ERROR([You don't have curl properly installed. Install it or try --without-curl.])
	fi
  AC_CHECK_HEADERS(curl/curl.h,,
 	[AC_MSG_ERROR([You don't have curl properly installed. Install it or try --without-curl.])])
  CFLAGS="$CFLAGS $CURL_CFLAGS"
  LDFLAGS="$LDFLAGS $CURL_LIBS"
  AC_CHECK_LIB(curl,curl_easy_init,havecurl=yes,
 	[AC_MSG_ERROR([You don't have curl properly installed. Install it or try --without-curl.])]
)
  AC_DEFINE(WITH_CURL,1,[use curl])
	compoptionstring="${compoptionstring}WITH_CURL\\n"
fi
AM_CONDITIONAL(USE_CURL, test x$havecurl = xyes)

AC_ARG_WITH(mhash,
	AC_HELP_STRING([--with-mhash],
		[use libmhash, needed for hmacs @<:@default=check@:>@]),
	[],
	[with_mhash=check]
)

AS_IF([test "x$with_mhash" != xno],
	AC_CHECK_LIB([mhash],[mhash_get_block_size],
		[CRYPTLIB="${CRYPTLIB} -lmhash"
		compoptionstring="${compoptionstring}WITH_MHASH\\n"
		with_mhash=yes
		aideextragroups="${aideextragroups}+whirlpool"
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[[#include <mhash.h>
		int i=MHASH_WHIRLPOOL;
		]])],AC_DEFINE(HAVE_MHASH_WHIRLPOOL,1,[mhash has whirlpool]))
		AC_DEFINE(WITH_MHASH,1,[use mhash library])],
		[AC_MSG_WARN(No mhash means no hmac.)]
	)
)

AC_ARG_WITH([gcrypt],
	[AC_HELP_STRING([--with-gcrypt],
		[use gcrypt library])],
		[],
		[if test "x$with_mhash" != xyes; then
			with_gcrypt=check
		else
			with_gcrypt=no
		fi]
)

AS_IF([test "x$with_gcrypt" != xno],
	[AC_DEFINE(WITH_GCRYPT,1,[use gcrypt library])
	if test "x$with_mhash" = xyes; then
		AC_MSG_ERROR([Using gcrypt together with mhash makes no sense. To disable mhash use --without-mhash])
	fi
	AC_CHECK_LIB([gpg-error], [gpg_strerror],
		[saveLIBS="$LIBS"
		LIBS="$LIBS -lgpg-error"
		AC_CHECK_LIB([gcrypt], [gcry_md_hash_buffer],[],
			AC_MSG_ERROR([Aide requires mhash or libcrypt to be installed with static libraries.])
		)
		LIBS="$saveLIBS"],
		[AC_MSG_ERROR([You need to have libgpg-error.a installed to use libgcrypt.])]
	)
	CRYPTLIB="${CRYPTLIB} -lgcrypt -lgpg-error"
	with_gcrypt=yes
	compoptionstring="${compoptionstring}WITH_GCRYPT\\n"],
	[with_gcrypt=no]
)

AC_SUBST(CRYPTLIB)

AC_ARG_WITH([confighmactype],
	AC_HELP_STRING([--with-confighmactype=TYPE],
		[Hash type to use for checking config. Valid values are md5, sha1, sha256 and sha512.]),
	[if test "x$withval" = "xmd5" ;then
	   CONFIGHMACTYPE="MHASH_MD5"
	else if test "x$withval" = "xsha1" ;then
	      CONFIGHMACTYPE="MHASH_SHA1"
	else if test "x$withval" = "xsha256" ;then
	      CONFIGHMACTYPE="MHASH_SHA256"
	else if test "x$withval" = "xsha512" ;then
	      CONFIGHMACTYPE="MHASH_SHA512"
        else 
	   echo "Valid parameters for --with-confighmactype are md5, sha1, sha256 and sha512"
	   exit 1
	fi
	fi
	fi
	fi
	AC_DEFINE_UNQUOTED(CONFIGHMACTYPE,$CONFIGHMACTYPE,[hash type for config file check])],
	[
	AC_DEFINE_UNQUOTED(CONFIGHMACTYPE,MHASH_MD5,[hash type for config file check])]
,
)

AC_ARG_WITH([confighmackey],
	AC_HELP_STRING([--with-confighmackey=KEY HMAC],
		[hash key to use for checking config. Must be a base64 encoded byte stream. Maximum string length is 31 chars.]),
	[if test "x$withval" = "x" ; then
	   echo "--with-confighmackey requires a value"
	   exit 5
	fi
	key00=`echo $withval|cut -c1-3`
	key01=`echo $withval|cut -c4-6`
	key02=`echo $withval|cut -c7-9`
	key03=`echo $withval|cut -c10-12`
	key04=`echo $withval|cut -c13-15`
	key05=`echo $withval|cut -c16-18`
	key06=`echo $withval|cut -c19-21`
	key07=`echo $withval|cut -c22-24`
	key08=`echo $withval|cut -c25-28`
	key09=`echo $withval|cut -c29-31`

	AC_DEFINE_UNQUOTED(CONFHMACKEY_00,"$key00",[HMAC key 00])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_01,"$key01",[HMAC key 01])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_02,"$key02",[HMAC key 02])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_03,"$key03",[HMAC key 03])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_04,"$key04",[HMAC key 04])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_05,"$key05",[HMAC key 05])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_06,"$key06",[HMAC key 06])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_07,"$key07",[HMAC key 07])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_08,"$key08",[HMAC key 08])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_09,"$key09",[HMAC key 09])],
	[
	AC_DEFINE_UNQUOTED(CONFHMACKEY_00,"$key00",[HMAC key 00])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_01,"$key01",[HMAC key 01])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_02,"$key02",[HMAC key 02])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_03,"$key03",[HMAC key 03])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_04,"$key04",[HMAC key 04])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_05,"$key05",[HMAC key 05])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_06,"$key06",[HMAC key 06])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_07,"$key07",[HMAC key 07])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_08,"$key08",[HMAC key 08])
	AC_DEFINE_UNQUOTED(CONFHMACKEY_09,"$key09",[HMAC key 09])]
)


AC_ARG_WITH([dbhmactype],
	AC_HELP_STRING([--with-dbhmactype=TYPE],
		[Hash type to use for checking db. Valid values are md5 and sha1.]),
	[if test "x$withval" = "xmd5" ;then
	   DBHMACTYPE="MHASH_MD5"
	else if test "x$withval" = "xsha1" ;then
	      DBHMACTYPE="MHASH_SHA1"
	else if test "x$withval" = "xsha256" ;then
	      CONFIGHMACTYPE="MHASH_SHA256"
	else if test "x$withval" = "xsha512" ;then
	      CONFIGHMACTYPE="MHASH_SHA512"
        else 
	      echo "Valid parameters for --with-dbhmactype are md5, sha1, sha256 and sha512"
	      exit 1
	fi
	fi
	fi
	fi
	AC_DEFINE_UNQUOTED(DBHMACTYPE,$DBHMACTYPE,[hash type for checking db])],
	[
	AC_DEFINE_UNQUOTED(DBHMACTYPE,MHASH_MD5,[hash type for checking db])]
)

AC_ARG_WITH([dbhmackey],
	AC_HELP_STRING([--with-dbhmackey=KEY HMAC],
		[hash key to use for checking db. Must be a base64 encoded byte stream. Maximum string lentgth is 31 chars.]),
	[if test "x$withval" = "x" ; then
	   echo "--with-dbhmackey requires a value"
	   exit 5
	fi
	key00=`echo $withval|cut -c1-3`
	key01=`echo $withval|cut -c4-6`
	key02=`echo $withval|cut -c7-9`
	key03=`echo $withval|cut -c10-12`
	key04=`echo $withval|cut -c13-15`
	key05=`echo $withval|cut -c16-18`
	key06=`echo $withval|cut -c19-21`
	key07=`echo $withval|cut -c22-24`
	key08=`echo $withval|cut -c25-28`
	key09=`echo $withval|cut -c29-31`

	AC_DEFINE_UNQUOTED(DBHMACKEY_00,"$key00",[DB HMAC key 00])
	AC_DEFINE_UNQUOTED(DBHMACKEY_01,"$key01",[DB HMAC key 01])
	AC_DEFINE_UNQUOTED(DBHMACKEY_02,"$key02",[DB HMAC key 02])
	AC_DEFINE_UNQUOTED(DBHMACKEY_03,"$key03",[DB HMAC key 03])
	AC_DEFINE_UNQUOTED(DBHMACKEY_04,"$key04",[DB HMAC key 04])
	AC_DEFINE_UNQUOTED(DBHMACKEY_05,"$key05",[DB HMAC key 05])
	AC_DEFINE_UNQUOTED(DBHMACKEY_06,"$key06",[DB HMAC key 06])
	AC_DEFINE_UNQUOTED(DBHMACKEY_07,"$key07",[DB HMAC key 07])
	AC_DEFINE_UNQUOTED(DBHMACKEY_08,"$key08",[DB HMAC key 08])
	AC_DEFINE_UNQUOTED(DBHMACKEY_09,"$key09",[DB HMAC key 09])],
	[
	AC_DEFINE_UNQUOTED(DBHMACKEY_00,"$key00",[DB HMAC key 00])
	AC_DEFINE_UNQUOTED(DBHMACKEY_01,"$key01",[DB HMAC key 01])
	AC_DEFINE_UNQUOTED(DBHMACKEY_02,"$key02",[DB HMAC key 02])
	AC_DEFINE_UNQUOTED(DBHMACKEY_03,"$key03",[DB HMAC key 03])
	AC_DEFINE_UNQUOTED(DBHMACKEY_04,"$key04",[DB HMAC key 04])
	AC_DEFINE_UNQUOTED(DBHMACKEY_05,"$key05",[DB HMAC key 05])
	AC_DEFINE_UNQUOTED(DBHMACKEY_06,"$key06",[DB HMAC key 06])
	AC_DEFINE_UNQUOTED(DBHMACKEY_07,"$key07",[DB HMAC key 07])
	AC_DEFINE_UNQUOTED(DBHMACKEY_08,"$key08",[DB HMAC key 08])
	AC_DEFINE_UNQUOTED(DBHMACKEY_09,"$key09",[DB HMAC key 09])]
)

AC_ARG_ENABLE(forced_configmd,
	AC_HELP_STRING([--enable-forced-configmd],
		[Forces the config to have checksum. Also disables --config-check]),
	[AC_DEFINE(FORCECONFIGMD,1,[force config checksum])],
	[AC_DEFINE(FORCECONFIGMD,0,[don't force config checksum])]
)

AC_ARG_ENABLE(forced_dbmd,
	AC_HELP_STRING([--enable-forced-dbmd],
		[Forces the file/pipe database's to have checksum. This will be the default in the next release.]),
	AC_DEFINE(FORCEDBMD,1,[force database checksum]),
	AC_DEFINE(FORCEDBMD,0,[don't force database checksum])
)

AC_ARG_WITH(initial_errors_to,
	AC_HELP_STRING([--with-initial-errors-to=URL],
		[Where errors should go while checking config. Default is stderr.]),
	AC_DEFINE_UNQUOTED(INITIALERRORSTO,"$withval",[send errors here])
	compoptionstring="${compoptionstring}INITIALERRORSTO=${withval}\\n",
	AC_DEFINE_UNQUOTED(INITIALERRORSTO,"stderr",[send errors to stderr])
)

AC_MSG_CHECKING(for PostgresSQL support)
AC_ARG_WITH([psql],
	[AC_HELP_STRING([--with-psql],
		[use postgresql library for storing databases])],
	[],
	[with_psql=no]
)

AS_IF([test "x$with_psql" != xno],
	AC_DEFINE(WITH_PSQL,1,[postgresql support])
	AC_CHECK_LIB(pq,PQclear,[],
		with_psql=no
		AC_MSG_RESULT([not found])
  	)
	PSQLLIB="-lpq"
	compoptionstring="${compoptionstring}WITH_PSQL\\n"
	AC_MSG_RESULT(yes),
	PSQLLIB=""
	[with_psql=no]
	AC_MSG_RESULT([no])
)

AC_SUBST(PSQLLIB)

# Check for Linux auditing API
#
AC_ARG_WITH([audit],
	[AC_HELP_STRING([--with-audit],
		[use audit library])],
	[],
	[with_audit=no]
)

AS_IF([test "x$with_audit" != xno],
	[AC_DEFINE(WITH_AUDIT,1,[use audit library])
	AC_CHECK_HEADER(libaudit.h,,
		AC_MSG_ERROR(You don't have libaudit properly installed. Install it if you need it.)
	)
	AUDITLIB="-laudit"
	if test "$aide_static_choice" == "yes"; then
		saveLIBS=$LIBS
		LIBS="-static $AUDITLIB"
		AC_CHECK_LIB([audit], [audit_log_user_message], [], [
			LIBS="$LIBS -lcap-ng"
			AC_CHECK_LIB([cap-ng], [audit_log_user_message], [AUDITLIB="$AUDITLIB -lcap-ng"],
			AC_MSG_ERROR([You don't have libaudit properly installed. Install it or try --without-audit.])
			, [])
		], [])
		LIBS=$saveLIBS
	fi
	compoptionstring="${compoptionstring}WITH_AUDIT\\n"],
	[with_audit=no]
)
AC_SUBST(AUDITLIB)

extrasub="s&@aideextragroups@&$aideextragroups&;t t
s&@AIDEVERSION@&$PACKAGE_VERSION&;t t"

AIDE_DO_LINK_FILES

compoptionstring="${compoptionstring}CONFIG_FILE = \\\"${config_file}\\\"\\n"

AC_DEFINE_UNQUOTED(AIDECOMPILEOPTIONS, "${compoptionstring}",[Compile-time options displayed in -v output])

dnl Add in the optional compiler features
LDFLAGS="$LDFLAGS $EXTRA_LDFLAGS"
CFLAGS="$CFLAGS $EXTRA_CFLAGS"

AC_SUBST(AIDE_DEFS)
AC_OUTPUT(Makefile doc/aide.conf doc/aide.1 doc/aide.conf.5 aide.spec)

